//! The NTFS USN change journal: record parsing and catch-up planning.
//!
//! This is the Windows counterpart of the Linux baseline rescan — the
//! **durable** half of FIM's two detectors. `ReadDirectoryChangesW` sees
//! changes as they happen and, like inotify, sees nothing that happened while
//! the sensor was down and drops events when its buffer overflows. The USN
//! journal is written by the filesystem itself and survives both, so it can
//! answer "what changed between the USN I last processed and now".
//!
//! # What the journal does and does not tell you
//!
//! It records **that** a file changed and **why** — a reason bitmask — never
//! what it changed *to*. So it is a way to find the files worth hashing, not a
//! substitute for hashing them. A sensor that trusted the journal alone would
//! report that `/etc/passwd`'s Windows equivalent was written without knowing
//! whether the contents differ from the baseline, which is the difference
//! between an alert and an alert with evidence.
//!
//! # Why the parsing is here, in a safe crate, and not next to the FFI
//!
//! `FSCTL_READ_USN_JOURNAL` hands back a raw byte buffer containing a run of
//! variable-length records, each declaring its own length and the offset of its
//! own filename. That is precisely the input class this project keeps in-tree
//! and fuzzes rather than parsing behind an FFI boundary a fuzzer cannot see
//! into — the same reasoning that made the `.pcap` *reader* first-party while
//! the capture *backend* is libpcap (CLAUDE.md §10).
//!
//! So everything in this module is pure `&[u8]` parsing with no Windows
//! dependency at all. It compiles and its tests run on any OS, which is the
//! only reason its behaviour could be established at all before meeting a real
//! journal.
//!
//! # Status: layout constants are unvalidated against a real journal
//!
//! The field offsets below come from the documented `USN_RECORD_V2`/`V3`
//! layouts, not from bytes off an NTFS volume — no Windows machine has been
//! available. **The safety properties are established** (totality, bounds,
//! termination, rejection of incoherent records) and fuzzed; **the constants
//! are not.** They are written so that a wrong one fails loudly rather than
//! silently mis-reading: every record is checked for internal coherence, and
//! the filename is located by the record's *own* declared offset rather than by
//! an assumed position. First contact with a real volume must confirm the
//! version numbers and header sizes; see `packaging/windows/PORT-PLAN.md`.

use cybersentinel_common::event::FileChange;

/// Smallest `USN_RECORD_V2`: the header up to and including `FileNameOffset`.
const V2_HEADER: usize = 60;
/// Smallest `USN_RECORD_V3`, whose file references are 128-bit.
const V3_HEADER: usize = 76;
/// `FSCTL_READ_USN_JOURNAL` prefixes the record run with the next USN to read.
const NEXT_USN_PREFIX: usize = 8;
/// `USN_JOURNAL_DATA_V0`, the prefix every later version shares.
const JOURNAL_DATA_V0: usize = 56;
/// Longest filename kept, in characters. NTFS caps a component at 255.
const MAX_NAME_CHARS: usize = 255;

// Reason flags, from `winioctl.h`.
/// File data was overwritten.
pub const USN_REASON_DATA_OVERWRITE: u32 = 0x0000_0001;
/// File data was extended.
pub const USN_REASON_DATA_EXTEND: u32 = 0x0000_0002;
/// File data was truncated.
pub const USN_REASON_DATA_TRUNCATION: u32 = 0x0000_0004;
/// A named data stream was overwritten.
pub const USN_REASON_NAMED_DATA_OVERWRITE: u32 = 0x0000_0010;
/// A named data stream was extended.
pub const USN_REASON_NAMED_DATA_EXTEND: u32 = 0x0000_0020;
/// A named data stream was truncated.
pub const USN_REASON_NAMED_DATA_TRUNCATION: u32 = 0x0000_0040;
/// The file was created.
pub const USN_REASON_FILE_CREATE: u32 = 0x0000_0100;
/// The file was deleted.
pub const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;
/// Extended attributes changed.
pub const USN_REASON_EA_CHANGE: u32 = 0x0000_0400;
/// The security descriptor changed — the ACL, which is detection signal.
pub const USN_REASON_SECURITY_CHANGE: u32 = 0x0000_0800;
/// The record carries the name the file had before a rename.
pub const USN_REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
/// The record carries the name the file has after a rename.
pub const USN_REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;
/// The indexable state changed.
pub const USN_REASON_INDEXABLE_CHANGE: u32 = 0x0000_4000;
/// Timestamps or attributes changed.
pub const USN_REASON_BASIC_INFO_CHANGE: u32 = 0x0000_8000;
/// A hard link was added or removed.
pub const USN_REASON_HARD_LINK_CHANGE: u32 = 0x0001_0000;
/// Compression state changed.
pub const USN_REASON_COMPRESSION_CHANGE: u32 = 0x0002_0000;
/// Encryption state changed.
pub const USN_REASON_ENCRYPTION_CHANGE: u32 = 0x0004_0000;
/// The object id changed.
pub const USN_REASON_OBJECT_ID_CHANGE: u32 = 0x0008_0000;
/// A reparse point changed — junctions and symlinks.
pub const USN_REASON_REPARSE_POINT_CHANGE: u32 = 0x0010_0000;
/// A named stream was added, removed, or renamed.
pub const USN_REASON_STREAM_CHANGE: u32 = 0x0020_0000;
/// The change was part of a transaction.
pub const USN_REASON_TRANSACTED_CHANGE: u32 = 0x0040_0000;
/// Integrity state changed (ReFS).
pub const USN_REASON_INTEGRITY_CHANGE: u32 = 0x0080_0000;
/// The final record for a file handle that has been closed.
pub const USN_REASON_CLOSE: u32 = 0x8000_0000;

/// `FILE_ATTRIBUTE_DIRECTORY`.
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

/// One change the filesystem recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnRecord {
    /// This record's position in the journal. The next read resumes past it.
    pub usn: i64,
    /// The file's NTFS reference number. 64-bit records are widened, so one
    /// field serves both layouts.
    pub file_reference: u128,
    /// The containing directory's reference number.
    ///
    /// The journal records **names, not paths**: resolving this to a full path
    /// needs `OpenFileById`, which is the FFI layer's job, not this one's.
    pub parent_reference: u128,
    /// Windows `FILETIME` — 100ns ticks since 1601-01-01 UTC.
    pub timestamp: i64,
    /// Why the record was written. A bitmask; several reasons can be set.
    pub reason: u32,
    /// `FILE_ATTRIBUTE_*` bits at the time of the change.
    pub attributes: u32,
    /// The file's name, without its directory.
    pub file_name: String,
    /// Which record layout this came from.
    pub version: (u16, u16),
}

impl UsnRecord {
    /// Whether the record describes a directory rather than a file.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    /// The change this record implies, in CyberSentinel's terms.
    ///
    /// Reasons are a bitmask and more than one is usually set — a single write
    /// typically produces `DATA_EXTEND | DATA_OVERWRITE | CLOSE`. The order
    /// here is by consequence, not by bit position: a file that was created and
    /// then written within one journal record is a creation, and one that was
    /// deleted is a deletion whatever else happened to it first.
    ///
    /// Returns `None` for records that carry no change worth an event —
    /// a bare `CLOSE`, or reasons outside the set below. Silence here is
    /// deliberate: an event per handle close would bury the changes.
    #[must_use]
    pub fn change(&self) -> Option<FileChange> {
        const CONTENT: u32 = USN_REASON_DATA_OVERWRITE
            | USN_REASON_DATA_EXTEND
            | USN_REASON_DATA_TRUNCATION
            | USN_REASON_NAMED_DATA_OVERWRITE
            | USN_REASON_NAMED_DATA_EXTEND
            | USN_REASON_NAMED_DATA_TRUNCATION
            | USN_REASON_STREAM_CHANGE;
        // Attribute-ish changes. SECURITY_CHANGE is in here and is worth
        // saying out loud: an ACL edit changes who can read a file without
        // changing a byte of it, so it must not be filtered out as noise.
        const ATTRIBUTES: u32 = USN_REASON_BASIC_INFO_CHANGE
            | USN_REASON_SECURITY_CHANGE
            | USN_REASON_EA_CHANGE
            | USN_REASON_COMPRESSION_CHANGE
            | USN_REASON_ENCRYPTION_CHANGE
            | USN_REASON_OBJECT_ID_CHANGE
            | USN_REASON_REPARSE_POINT_CHANGE
            | USN_REASON_HARD_LINK_CHANGE
            | USN_REASON_INDEXABLE_CHANGE
            | USN_REASON_INTEGRITY_CHANGE;

        if self.reason & USN_REASON_FILE_DELETE != 0 {
            return Some(FileChange::Deleted);
        }
        if self.reason & USN_REASON_FILE_CREATE != 0 {
            return Some(FileChange::Created);
        }
        if self.reason & (USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME) != 0 {
            return Some(FileChange::Renamed);
        }
        if self.reason & CONTENT != 0 {
            return Some(FileChange::Modified);
        }
        if self.reason & ATTRIBUTES != 0 {
            return Some(FileChange::AttributesChanged);
        }
        None
    }
}

/// Why a record could not be read.
///
/// Every variant is a *rejection*, never a guess. A record whose declared
/// offsets do not cohere is skipped and counted rather than parsed from an
/// assumed layout — which is also what makes a mistaken constant in this file
/// show up as a pile of rejections instead of silently wrong events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RecordError {
    /// Fewer bytes than the smallest possible record.
    #[error("record is {len} bytes, shorter than any USN record header")]
    TooShort {
        /// How many bytes there were.
        len: usize,
    },
    /// A record layout this build does not know.
    ///
    /// Refused rather than approximated: guessing at an unknown layout would
    /// produce filenames read from the wrong offset, which is worse than a
    /// counted gap.
    #[error("unsupported USN record version {major}.{minor}")]
    UnsupportedVersion {
        /// Major version from the record.
        major: u16,
        /// Minor version from the record.
        minor: u16,
    },
    /// `RecordLength` disagrees with the bytes available.
    #[error("record declares {declared} bytes, {available} available")]
    LengthMismatch {
        /// What the record claimed.
        declared: usize,
        /// What there was.
        available: usize,
    },
    /// The filename does not lie inside the record.
    #[error("filename at offset {offset} length {len} does not fit in a {record} byte record")]
    NameOutOfBounds {
        /// Declared offset.
        offset: usize,
        /// Declared length in bytes.
        len: usize,
        /// The record's own declared length.
        record: usize,
    },
    /// A UTF-16 filename with an odd byte length cannot be one.
    #[error("filename length {len} is not a whole number of UTF-16 code units")]
    OddNameLength {
        /// Declared length in bytes.
        len: usize,
    },
}

/// Read a little-endian integer, or `None` if it does not fit.
macro_rules! read_int {
    ($ty:ty, $bytes:expr, $at:expr) => {{
        const WIDTH: usize = std::mem::size_of::<$ty>();
        $bytes
            .get($at..$at + WIDTH)
            .and_then(|slice| <[u8; WIDTH]>::try_from(slice).ok())
            .map(<$ty>::from_le_bytes)
    }};
}

/// Parse one record from the start of `bytes`.
///
/// `bytes` may be longer than the record; only `RecordLength` bytes are read.
pub fn parse_record(bytes: &[u8]) -> Result<UsnRecord, RecordError> {
    let declared =
        read_int!(u32, bytes, 0).ok_or(RecordError::TooShort { len: bytes.len() })? as usize;
    let major = read_int!(u16, bytes, 4).ok_or(RecordError::TooShort { len: bytes.len() })?;
    let minor = read_int!(u16, bytes, 6).ok_or(RecordError::TooShort { len: bytes.len() })?;

    let header = match major {
        2 => V2_HEADER,
        3 => V3_HEADER,
        _ => return Err(RecordError::UnsupportedVersion { major, minor }),
    };

    // The record must be at least its own header and no longer than what we
    // hold. Both directions matter: too short and the fields below are not
    // there, too long and we would read into the next record.
    if declared < header || declared > bytes.len() {
        return Err(RecordError::LengthMismatch {
            declared,
            available: bytes.len(),
        });
    }
    let record = &bytes[..declared];

    let (file_reference, parent_reference, rest) = if major == 2 {
        (
            u128::from(read_int!(u64, record, 8).ok_or(RecordError::TooShort { len: declared })?),
            u128::from(read_int!(u64, record, 16).ok_or(RecordError::TooShort { len: declared })?),
            24,
        )
    } else {
        (
            read_int!(u128, record, 8).ok_or(RecordError::TooShort { len: declared })?,
            read_int!(u128, record, 24).ok_or(RecordError::TooShort { len: declared })?,
            40,
        )
    };

    let usn = read_int!(i64, record, rest).ok_or(RecordError::TooShort { len: declared })?;
    let timestamp =
        read_int!(i64, record, rest + 8).ok_or(RecordError::TooShort { len: declared })?;
    let reason =
        read_int!(u32, record, rest + 16).ok_or(RecordError::TooShort { len: declared })?;
    // SourceInfo at +20 and SecurityId at +24 are read past, deliberately:
    // neither is used, and naming them here would imply they were.
    let attributes =
        read_int!(u32, record, rest + 28).ok_or(RecordError::TooShort { len: declared })?;
    let name_len =
        read_int!(u16, record, rest + 32).ok_or(RecordError::TooShort { len: declared })? as usize;
    let name_offset =
        read_int!(u16, record, rest + 34).ok_or(RecordError::TooShort { len: declared })? as usize;

    if name_len % 2 != 0 {
        return Err(RecordError::OddNameLength { len: name_len });
    }
    // The record locates its own filename, and the bounds are checked against
    // the record's declared length rather than the buffer's: a name that
    // "fits" only by running into the next record is not this record's name.
    let end = name_offset
        .checked_add(name_len)
        .ok_or(RecordError::NameOutOfBounds {
            offset: name_offset,
            len: name_len,
            record: declared,
        })?;
    if name_offset < header || end > declared {
        return Err(RecordError::NameOutOfBounds {
            offset: name_offset,
            len: name_len,
            record: declared,
        });
    }

    Ok(UsnRecord {
        usn,
        file_reference,
        parent_reference,
        timestamp,
        reason,
        attributes,
        file_name: decode_name(&record[name_offset..end]),
        version: (major, minor),
    })
}

/// Decode a UTF-16LE filename into something safe to put in an event.
///
/// Unpaired surrogates become the replacement character rather than an error:
/// NTFS permits names that are not valid UTF-16, and refusing to name a file
/// would mean not reporting a change to it. Control characters are stripped for
/// the same reason they are everywhere else in this crate — event logs get read
/// in terminals.
fn decode_name(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .chars()
        .take(MAX_NAME_CHARS)
        .map(|character| {
            if character.is_control() {
                '.'
            } else {
                character
            }
        })
        .collect()
}

/// What a whole `FSCTL_READ_USN_JOURNAL` response contained.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadResponse {
    /// The USN to resume from on the next read.
    pub next_usn: i64,
    /// The records that parsed.
    pub records: Vec<UsnRecord>,
    /// Records rejected as malformed.
    ///
    /// **A coverage hole, not a statistic.** Every rejection is a filesystem
    /// change the sensor did not see, and a non-zero count most likely means a
    /// layout constant in this file is wrong rather than that NTFS emitted a
    /// bad record.
    pub rejected: u64,
}

/// Parse a `FSCTL_READ_USN_JOURNAL` output buffer.
///
/// The buffer is a `USN` (the next USN to read from) followed by a run of
/// variable-length records. Iteration stops at the first record that cannot be
/// stepped over — a zero or absurd `RecordLength` — because continuing would
/// mean guessing where the next record starts. Records that parse before that
/// point are kept: partial progress through a buffer is still progress, and the
/// next read resumes from `next_usn` regardless.
#[must_use]
pub fn parse_read_response(buffer: &[u8]) -> ReadResponse {
    let Some(next_usn) = read_int!(i64, buffer, 0) else {
        return ReadResponse::default();
    };

    let mut response = ReadResponse {
        next_usn,
        ..ReadResponse::default()
    };

    let mut offset = NEXT_USN_PREFIX;
    while offset < buffer.len() {
        let remaining = &buffer[offset..];
        let Some(declared) = read_int!(u32, remaining, 0).map(|len| len as usize) else {
            response.rejected += 1;
            break;
        };
        // A record length that could not belong to a real record is not a
        // step, it is a guess. Zero would loop for ever; anything below the
        // smallest possible header, or past the end of the buffer, would land
        // mid-record and turn one bad length into a run of fabricated
        // rejections — resynchronising on nonsense. The run is unreadable from
        // here: stop and count it.
        //
        // Found by fuzzing: a 30-byte buffer with a declared length of 10
        // produced three rejections by stepping through itself.
        if declared < V2_HEADER || declared > remaining.len() {
            response.rejected += 1;
            break;
        }

        match parse_record(&remaining[..declared]) {
            Ok(record) => response.records.push(record),
            // A record that is individually malformed but whose length is
            // usable is skipped: the run can still be walked.
            Err(_) => response.rejected += 1,
        }
        offset += declared;
    }

    response
}

// ---------------------------------------------------------------------------
// journal identity and catch-up
// ---------------------------------------------------------------------------

/// The volume's journal, from `FSCTL_QUERY_USN_JOURNAL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalData {
    /// Identifies this journal instance. **Changes when the journal is
    /// deleted and recreated**, which is what makes a stored USN meaningless.
    pub journal_id: u64,
    /// The oldest USN still in the journal.
    pub first_usn: i64,
    /// The USN the next record will be written at.
    pub next_usn: i64,
    /// The oldest USN that can still be read.
    pub lowest_valid_usn: i64,
    /// The USN at which the journal will be reset.
    pub max_usn: i64,
}

/// Parse `USN_JOURNAL_DATA`.
///
/// Only the `V0` prefix is read, which every later version shares, so a `V1` or
/// `V2` buffer parses fine and the extra fields are ignored rather than
/// mis-read.
#[must_use]
pub fn parse_journal_data(bytes: &[u8]) -> Option<JournalData> {
    if bytes.len() < JOURNAL_DATA_V0 {
        return None;
    }
    Some(JournalData {
        journal_id: read_int!(u64, bytes, 0)?,
        first_usn: read_int!(i64, bytes, 8)?,
        next_usn: read_int!(i64, bytes, 16)?,
        lowest_valid_usn: read_int!(i64, bytes, 24)?,
        max_usn: read_int!(i64, bytes, 32)?,
    })
}

/// What to do when the sensor starts and wants to know what it missed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatchUp {
    /// Read the journal from this USN. Everything since is recoverable.
    Resume(i64),
    /// The journal cannot answer. Fall back to a full baseline rescan, and
    /// **say why** — this is the expensive path and an operator seeing it
    /// repeatedly has a journal sized too small for the sensor's downtime.
    FullRescan(RescanReason),
}

/// Why the journal could not be resumed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RescanReason {
    /// Nothing was stored — a first run.
    NoStoredPosition,
    /// The journal was deleted and recreated, so the stored USN refers to a
    /// journal that no longer exists. A stored USN from a different journal is
    /// not merely stale, it is meaningless: the same number names a different
    /// change.
    JournalReplaced,
    /// The journal wrapped past the stored position while the sensor was down.
    /// The records in between are gone.
    RecordsAgedOut,
    /// The stored position is ahead of the journal's next USN, which should be
    /// impossible — a restored volume snapshot, or a corrupt store.
    PositionFromTheFuture,
}

/// Decide how to catch up, given what was stored and what the volume says now.
///
/// Pure logic, deliberately: this is the decision that determines whether
/// changes made while the sensor was down are found or missed, and it is worth
/// being able to test every branch of it without a filesystem.
///
/// **Fails toward the rescan.** Every uncertain case returns [`CatchUp::FullRescan`],
/// because the expensive-but-complete answer is the right way to be wrong when
/// the alternative is silently skipping a range of changes.
#[must_use]
pub fn plan_catch_up(stored: Option<(u64, i64)>, current: &JournalData) -> CatchUp {
    let Some((stored_journal, stored_usn)) = stored else {
        return CatchUp::FullRescan(RescanReason::NoStoredPosition);
    };
    if stored_journal != current.journal_id {
        return CatchUp::FullRescan(RescanReason::JournalReplaced);
    }
    if stored_usn > current.next_usn {
        return CatchUp::FullRescan(RescanReason::PositionFromTheFuture);
    }
    // `lowest_valid_usn` is the oldest readable position. Anything before it
    // has been overwritten as the journal wrapped.
    if stored_usn < current.lowest_valid_usn || stored_usn < current.first_usn {
        return CatchUp::FullRescan(RescanReason::RecordsAgedOut);
    }
    CatchUp::Resume(stored_usn)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `USN_RECORD_V2` the way the documented layout says one looks.
    ///
    /// The tests are only as right as this builder, which is the honest limit
    /// of what can be established without a Windows volume: they pin the
    /// parser's *behaviour* — bounds, totality, rejection of incoherent input —
    /// and they pin it against this file's understanding of the layout, not
    /// against NTFS.
    fn v2_record(usn: i64, reason: u32, attributes: u32, name: &str) -> Vec<u8> {
        let name_utf16: Vec<u8> = name
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let len = V2_HEADER + name_utf16.len();
        // Records are 8-byte aligned in the buffer.
        let padded = len.div_ceil(8) * 8;

        let mut record = vec![0_u8; padded];
        record[0..4].copy_from_slice(&(padded as u32).to_le_bytes());
        record[4..6].copy_from_slice(&2_u16.to_le_bytes());
        record[6..8].copy_from_slice(&0_u16.to_le_bytes());
        record[8..16].copy_from_slice(&0x1234_5678_u64.to_le_bytes());
        record[16..24].copy_from_slice(&0x8765_4321_u64.to_le_bytes());
        record[24..32].copy_from_slice(&usn.to_le_bytes());
        record[32..40].copy_from_slice(&132_000_000_000_000_000_i64.to_le_bytes());
        record[40..44].copy_from_slice(&reason.to_le_bytes());
        record[44..48].copy_from_slice(&0_u32.to_le_bytes()); // SourceInfo
        record[48..52].copy_from_slice(&0_u32.to_le_bytes()); // SecurityId
        record[52..56].copy_from_slice(&attributes.to_le_bytes());
        record[56..58].copy_from_slice(&(name_utf16.len() as u16).to_le_bytes());
        record[58..60].copy_from_slice(&(V2_HEADER as u16).to_le_bytes());
        record[V2_HEADER..V2_HEADER + name_utf16.len()].copy_from_slice(&name_utf16);
        record
    }

    fn v3_record(usn: i64, reason: u32, name: &str) -> Vec<u8> {
        let name_utf16: Vec<u8> = name
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let len = V3_HEADER + name_utf16.len();
        let padded = len.div_ceil(8) * 8;

        let mut record = vec![0_u8; padded];
        record[0..4].copy_from_slice(&(padded as u32).to_le_bytes());
        record[4..6].copy_from_slice(&3_u16.to_le_bytes());
        record[6..8].copy_from_slice(&0_u16.to_le_bytes());
        record[8..24].copy_from_slice(&1_u128.to_le_bytes());
        record[24..40].copy_from_slice(&2_u128.to_le_bytes());
        record[40..48].copy_from_slice(&usn.to_le_bytes());
        record[48..56].copy_from_slice(&0_i64.to_le_bytes());
        record[56..60].copy_from_slice(&reason.to_le_bytes());
        record[60..64].copy_from_slice(&0_u32.to_le_bytes());
        record[64..68].copy_from_slice(&0_u32.to_le_bytes());
        record[68..72].copy_from_slice(&0_u32.to_le_bytes());
        record[72..74].copy_from_slice(&(name_utf16.len() as u16).to_le_bytes());
        record[74..76].copy_from_slice(&(V3_HEADER as u16).to_le_bytes());
        record[V3_HEADER..V3_HEADER + name_utf16.len()].copy_from_slice(&name_utf16);
        record
    }

    fn response(records: &[Vec<u8>], next_usn: i64) -> Vec<u8> {
        let mut buffer = next_usn.to_le_bytes().to_vec();
        for record in records {
            buffer.extend_from_slice(record);
        }
        buffer
    }

    // -----------------------------------------------------------------------
    // parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parses_a_v2_record() {
        let bytes = v2_record(4_096, USN_REASON_DATA_OVERWRITE, 0, "passwords.txt");
        let record = parse_record(&bytes).expect("a record");

        assert_eq!(record.usn, 4_096);
        assert_eq!(record.file_name, "passwords.txt");
        assert_eq!(record.reason, USN_REASON_DATA_OVERWRITE);
        assert_eq!(record.version, (2, 0));
        assert_eq!(record.file_reference, 0x1234_5678);
        assert!(!record.is_directory());
    }

    #[test]
    fn parses_a_v3_record_with_a_128_bit_reference() {
        let bytes = v3_record(9_000, USN_REASON_FILE_CREATE, "new.dll");
        let record = parse_record(&bytes).expect("a record");

        assert_eq!(record.usn, 9_000);
        assert_eq!(record.file_name, "new.dll");
        assert_eq!(record.version, (3, 0));
        assert_eq!(record.file_reference, 1);
        assert_eq!(record.parent_reference, 2);
    }

    #[test]
    fn a_directory_attribute_is_read() {
        let bytes = v2_record(1, USN_REASON_FILE_CREATE, FILE_ATTRIBUTE_DIRECTORY, "sub");
        assert!(parse_record(&bytes).expect("a record").is_directory());
    }

    #[test]
    fn parses_a_non_ascii_name() {
        let bytes = v2_record(1, USN_REASON_DATA_EXTEND, 0, "café-Ω-日本語.log");
        assert_eq!(
            parse_record(&bytes).expect("a record").file_name,
            "café-Ω-日本語.log"
        );
    }

    #[test]
    fn a_walk_of_several_records_finds_them_all() {
        let buffer = response(
            &[
                v2_record(10, USN_REASON_FILE_CREATE, 0, "a.txt"),
                v2_record(20, USN_REASON_DATA_OVERWRITE, 0, "b.txt"),
                v2_record(30, USN_REASON_FILE_DELETE, 0, "c.txt"),
            ],
            40,
        );
        let parsed = parse_read_response(&buffer);

        assert_eq!(parsed.next_usn, 40);
        assert_eq!(parsed.rejected, 0);
        let names: Vec<_> = parsed
            .records
            .iter()
            .map(|record| record.file_name.as_str())
            .collect();
        assert_eq!(names, ["a.txt", "b.txt", "c.txt"]);
    }

    #[test]
    fn mixed_record_versions_in_one_buffer_are_both_read() {
        let buffer = response(
            &[
                v2_record(10, USN_REASON_FILE_CREATE, 0, "old.txt"),
                v3_record(20, USN_REASON_FILE_CREATE, "new.txt"),
            ],
            30,
        );
        let parsed = parse_read_response(&buffer);
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.records[0].version, (2, 0));
        assert_eq!(parsed.records[1].version, (3, 0));
    }

    // -----------------------------------------------------------------------
    // rejection rather than guessing
    // -----------------------------------------------------------------------

    #[test]
    fn an_unknown_version_is_refused_not_approximated() {
        let mut bytes = v2_record(1, USN_REASON_FILE_CREATE, 0, "x.txt");
        bytes[4..6].copy_from_slice(&9_u16.to_le_bytes());
        assert_eq!(
            parse_record(&bytes),
            Err(RecordError::UnsupportedVersion { major: 9, minor: 0 }),
            "guessing at an unknown layout would read a filename from the wrong offset"
        );
    }

    #[test]
    fn a_filename_pointing_outside_the_record_is_refused() {
        let mut bytes = v2_record(1, USN_REASON_FILE_CREATE, 0, "x.txt");
        // Claim the name is far past the end.
        bytes[58..60].copy_from_slice(&60_000_u16.to_le_bytes());
        assert!(matches!(
            parse_record(&bytes),
            Err(RecordError::NameOutOfBounds { .. })
        ));
    }

    #[test]
    fn a_filename_running_past_the_record_end_is_refused() {
        let mut bytes = v2_record(1, USN_REASON_FILE_CREATE, 0, "x.txt");
        // A length that would run into whatever follows this record.
        bytes[56..58].copy_from_slice(&4_000_u16.to_le_bytes());
        assert!(matches!(
            parse_record(&bytes),
            Err(RecordError::NameOutOfBounds { .. })
        ));
    }

    #[test]
    fn a_filename_inside_the_header_is_refused() {
        let mut bytes = v2_record(1, USN_REASON_FILE_CREATE, 0, "x.txt");
        // Offset 8 is inside the header: the "name" would overlap the fields.
        bytes[58..60].copy_from_slice(&8_u16.to_le_bytes());
        assert!(matches!(
            parse_record(&bytes),
            Err(RecordError::NameOutOfBounds { .. })
        ));
    }

    #[test]
    fn an_odd_length_utf16_name_is_refused() {
        let mut bytes = v2_record(1, USN_REASON_FILE_CREATE, 0, "x.txt");
        bytes[56..58].copy_from_slice(&7_u16.to_le_bytes());
        assert_eq!(
            parse_record(&bytes),
            Err(RecordError::OddNameLength { len: 7 })
        );
    }

    #[test]
    fn a_record_shorter_than_its_own_header_is_refused() {
        let mut bytes = v2_record(1, USN_REASON_FILE_CREATE, 0, "x.txt");
        bytes[0..4].copy_from_slice(&16_u32.to_le_bytes());
        assert!(matches!(
            parse_record(&bytes),
            Err(RecordError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn a_record_claiming_more_bytes_than_exist_is_refused() {
        let mut bytes = v2_record(1, USN_REASON_FILE_CREATE, 0, "x.txt");
        bytes[0..4].copy_from_slice(&100_000_u32.to_le_bytes());
        assert!(matches!(
            parse_record(&bytes),
            Err(RecordError::LengthMismatch { .. })
        ));
    }

    /// The property that stops a malformed buffer becoming an infinite loop.
    /// Found by the fuzzer. A declared length too small to be a record is not
    /// a usable step: following it lands mid-record and turns one bad length
    /// into a run of fabricated rejections.
    #[test]
    fn a_length_too_small_to_be_a_record_stops_the_walk_once() {
        let mut buffer = 7_i64.to_le_bytes().to_vec();
        // Three "records" each claiming to be 10 bytes long.
        for _ in 0..3 {
            let mut stub = vec![0_u8; 10];
            stub[0..4].copy_from_slice(&10_u32.to_le_bytes());
            buffer.extend_from_slice(&stub);
        }

        let parsed = parse_read_response(&buffer);
        assert!(parsed.records.is_empty());
        assert_eq!(
            parsed.rejected, 1,
            "one unreadable run is one hole, not one per bogus length"
        );
        assert_eq!(parsed.next_usn, 7);
    }

    #[test]
    fn a_zero_length_record_terminates_the_walk_instead_of_looping() {
        let mut buffer = 100_i64.to_le_bytes().to_vec();
        buffer.extend_from_slice(&[0_u8; 64]); // RecordLength == 0
        let parsed = parse_read_response(&buffer);
        assert!(parsed.records.is_empty());
        assert_eq!(parsed.rejected, 1);
        assert_eq!(parsed.next_usn, 100);
    }

    #[test]
    fn a_truncated_buffer_keeps_what_parsed_and_counts_the_rest() {
        let mut buffer = response(
            &[
                v2_record(10, USN_REASON_FILE_CREATE, 0, "kept.txt"),
                v2_record(20, USN_REASON_FILE_CREATE, 0, "lost.txt"),
            ],
            30,
        );
        buffer.truncate(buffer.len() - 20);

        let parsed = parse_read_response(&buffer);
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].file_name, "kept.txt");
        assert_eq!(
            parsed.rejected, 1,
            "the change we could not read is a hole, and must be counted"
        );
    }

    #[test]
    fn a_malformed_record_between_good_ones_does_not_stop_the_walk() {
        let mut bad = v2_record(20, USN_REASON_FILE_CREATE, 0, "bad.txt");
        bad[4..6].copy_from_slice(&9_u16.to_le_bytes()); // unknown version
        let buffer = response(
            &[
                v2_record(10, USN_REASON_FILE_CREATE, 0, "one.txt"),
                bad,
                v2_record(30, USN_REASON_FILE_CREATE, 0, "two.txt"),
            ],
            40,
        );

        let parsed = parse_read_response(&buffer);
        assert_eq!(parsed.rejected, 1);
        let names: Vec<_> = parsed
            .records
            .iter()
            .map(|record| record.file_name.as_str())
            .collect();
        assert_eq!(
            names,
            ["one.txt", "two.txt"],
            "a usable RecordLength lets the walk step over a bad record"
        );
    }

    #[test]
    fn an_empty_or_tiny_buffer_is_not_an_error() {
        assert_eq!(parse_read_response(&[]).records.len(), 0);
        assert_eq!(parse_read_response(&[0; 4]).records.len(), 0);
        assert_eq!(parse_read_response(&[0; 8]).next_usn, 0);
    }

    #[test]
    fn control_characters_in_a_name_are_stripped() {
        let bytes = v2_record(1, USN_REASON_FILE_CREATE, 0, "ev\u{1b}[31mil.txt");
        let record = parse_record(&bytes).expect("a record");
        assert!(!record.file_name.contains('\u{1b}'));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // Totality, the way every other parser in this workspace is checked.
        for seed in 0_u8..=255 {
            let noise: Vec<u8> = (0..256)
                .map(|index| seed.wrapping_mul(index as u8))
                .collect();
            let _ = parse_read_response(&noise);
            let _ = parse_record(&noise);
            let _ = parse_journal_data(&noise);
        }
    }

    // -----------------------------------------------------------------------
    // reason -> change
    // -----------------------------------------------------------------------

    #[test]
    fn a_write_is_a_modification() {
        let bytes = v2_record(
            1,
            USN_REASON_DATA_EXTEND | USN_REASON_DATA_OVERWRITE | USN_REASON_CLOSE,
            0,
            "a.txt",
        );
        assert_eq!(
            parse_record(&bytes).expect("a record").change(),
            Some(FileChange::Modified)
        );
    }

    #[test]
    fn a_deletion_outranks_whatever_else_happened_first() {
        // One record often carries a whole handle's history. A file written and
        // then deleted is a deletion; reporting it as a modification would
        // describe a file that is no longer there.
        let bytes = v2_record(
            1,
            USN_REASON_DATA_OVERWRITE | USN_REASON_FILE_DELETE | USN_REASON_CLOSE,
            0,
            "a.txt",
        );
        assert_eq!(
            parse_record(&bytes).expect("a record").change(),
            Some(FileChange::Deleted)
        );
    }

    #[test]
    fn a_creation_outranks_the_write_that_followed_it() {
        let bytes = v2_record(
            1,
            USN_REASON_FILE_CREATE | USN_REASON_DATA_EXTEND | USN_REASON_CLOSE,
            0,
            "a.txt",
        );
        assert_eq!(
            parse_record(&bytes).expect("a record").change(),
            Some(FileChange::Created)
        );
    }

    /// An ACL edit changes who can read a file without changing a byte of it.
    /// Filtering it out as noise would lose one of the better host signals.
    #[test]
    fn a_security_descriptor_change_is_reported() {
        let bytes = v2_record(1, USN_REASON_SECURITY_CHANGE | USN_REASON_CLOSE, 0, "a.txt");
        assert_eq!(
            parse_record(&bytes).expect("a record").change(),
            Some(FileChange::AttributesChanged)
        );
    }

    #[test]
    fn both_halves_of_a_rename_are_renames() {
        for reason in [USN_REASON_RENAME_OLD_NAME, USN_REASON_RENAME_NEW_NAME] {
            let bytes = v2_record(1, reason | USN_REASON_CLOSE, 0, "a.txt");
            assert_eq!(
                parse_record(&bytes).expect("a record").change(),
                Some(FileChange::Renamed)
            );
        }
    }

    #[test]
    fn a_bare_close_is_not_a_change() {
        let bytes = v2_record(1, USN_REASON_CLOSE, 0, "a.txt");
        assert_eq!(
            parse_record(&bytes).expect("a record").change(),
            None,
            "an event per handle close would bury the changes"
        );
    }

    // -----------------------------------------------------------------------
    // catch-up
    // -----------------------------------------------------------------------

    fn journal(id: u64, first: i64, next: i64) -> JournalData {
        JournalData {
            journal_id: id,
            first_usn: first,
            next_usn: next,
            lowest_valid_usn: first,
            max_usn: 1 << 40,
        }
    }

    #[test]
    fn a_stored_position_inside_the_journal_resumes() {
        let current = journal(7, 1_000, 9_000);
        assert_eq!(
            plan_catch_up(Some((7, 5_000)), &current),
            CatchUp::Resume(5_000)
        );
    }

    #[test]
    fn a_first_run_rescans() {
        assert_eq!(
            plan_catch_up(None, &journal(7, 0, 100)),
            CatchUp::FullRescan(RescanReason::NoStoredPosition)
        );
    }

    /// The same USN in a different journal names a different change. Resuming
    /// from it would skip everything since the journal was recreated while
    /// looking like it had caught up.
    #[test]
    fn a_recreated_journal_forces_a_rescan() {
        assert_eq!(
            plan_catch_up(Some((7, 5_000)), &journal(8, 0, 9_000)),
            CatchUp::FullRescan(RescanReason::JournalReplaced)
        );
    }

    #[test]
    fn a_position_the_journal_has_wrapped_past_forces_a_rescan() {
        // The sensor was down long enough that its position aged out.
        let current = journal(7, 6_000, 9_000);
        assert_eq!(
            plan_catch_up(Some((7, 5_000)), &current),
            CatchUp::FullRescan(RescanReason::RecordsAgedOut)
        );
    }

    #[test]
    fn a_position_ahead_of_the_journal_forces_a_rescan() {
        // A restored snapshot, or a corrupt store. Either way the stored
        // position cannot be trusted.
        assert_eq!(
            plan_catch_up(Some((7, 50_000)), &journal(7, 0, 9_000)),
            CatchUp::FullRescan(RescanReason::PositionFromTheFuture)
        );
    }

    #[test]
    fn the_boundary_positions_resume_rather_than_rescan() {
        // Exactly at the oldest readable record, and exactly at the newest, are
        // both valid: an off-by-one here would either rescan needlessly on
        // every start or skip the oldest record.
        let current = journal(7, 1_000, 9_000);
        assert_eq!(
            plan_catch_up(Some((7, 1_000)), &current),
            CatchUp::Resume(1_000)
        );
        assert_eq!(
            plan_catch_up(Some((7, 9_000)), &current),
            CatchUp::Resume(9_000)
        );
    }

    #[test]
    fn parses_journal_data() {
        let mut bytes = vec![0_u8; JOURNAL_DATA_V0];
        bytes[0..8].copy_from_slice(&42_u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&100_i64.to_le_bytes());
        bytes[16..24].copy_from_slice(&900_i64.to_le_bytes());
        bytes[24..32].copy_from_slice(&150_i64.to_le_bytes());
        bytes[32..40].copy_from_slice(&(1_i64 << 40).to_le_bytes());

        let data = parse_journal_data(&bytes).expect("journal data");
        assert_eq!(data.journal_id, 42);
        assert_eq!(data.first_usn, 100);
        assert_eq!(data.next_usn, 900);
        assert_eq!(data.lowest_valid_usn, 150);
    }

    #[test]
    fn a_short_journal_data_buffer_is_refused() {
        assert!(parse_journal_data(&[0; 40]).is_none());
    }

    #[test]
    fn a_longer_journal_data_buffer_parses_its_v0_prefix() {
        // V1 and V2 append fields; the prefix is unchanged, so a newer buffer
        // must not be refused.
        let mut bytes = vec![0_u8; JOURNAL_DATA_V0 + 24];
        bytes[0..8].copy_from_slice(&5_u64.to_le_bytes());
        assert_eq!(parse_journal_data(&bytes).expect("data").journal_id, 5);
    }
}
