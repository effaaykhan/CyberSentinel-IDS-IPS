//! Reading `.pcap` savefiles.
//!
//! An in-tree reader for the classic libpcap savefile format: a 24-byte file
//! header, then per-record a 16-byte prefix (timestamp, captured length, wire
//! length) followed by the frame.
//!
//! # This parses attacker-supplied input
//!
//! A savefile is data, and data given to an analyst is data an attacker may
//! have shaped. Every length in this format is attacker controlled, so:
//!
//! * a record claiming more than [`MAX_FRAME_LEN`] bytes is **rejected before
//!   anything is allocated**;
//! * a record that runs off the end of the file ends the replay and is
//!   reported, rather than being silently dropped;
//! * the reader is fuzzed (`fuzz/fuzz_targets/pcap_reader.rs`).
//!
//! # Truncated files are reported, not hidden
//!
//! A capture cut short — `tcpdump` killed mid-write, a full disk — is common
//! and legitimate. It ends the replay cleanly, but [`PcapReplay::is_truncated`]
//! says so and the reader logs a warning. Quietly treating a partial record as
//! end-of-file would let an analyst believe they had seen the whole capture.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    CaptureCounters, CaptureError, Captured, LinkType, PacketSource, RawPacket, Result,
    MAX_FRAME_LEN,
};

/// Byte length of the savefile header.
const FILE_HEADER_LEN: usize = 24;
/// Byte length of a per-record prefix.
const RECORD_HEADER_LEN: usize = 16;

/// Savefile magic numbers.
const MAGIC_MICROS: u32 = 0xa1b2_c3d4;
const MAGIC_MICROS_SWAPPED: u32 = 0xd4c3_b2a1;
const MAGIC_NANOS: u32 = 0xa1b2_3c4d;
const MAGIC_NANOS_SWAPPED: u32 = 0x4d3c_b2a1;
/// pcapng's Section Header Block type, recognised only to give a better error.
const MAGIC_PCAPNG: u32 = 0x0a0d_0d0a;

/// The parsed savefile header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHeader {
    /// Format major version.
    pub version_major: u16,
    /// Format minor version.
    pub version_minor: u16,
    /// Snap length the capture was taken with.
    pub snaplen: u32,
    /// Link-layer encapsulation.
    pub link_type: LinkType,
    /// Whether record timestamps are nanoseconds rather than microseconds.
    pub nanosecond_timestamps: bool,
    /// Whether the file's byte order is the opposite of ours.
    pub byte_swapped: bool,
}

/// Replays frames from a `.pcap` savefile.
///
/// Needs no privileges and no system library, which is what makes the whole
/// decode path testable in CI on every OS.
#[derive(Debug)]
pub struct PcapReplay<R = File> {
    reader: BufReader<R>,
    name: String,
    header: FileHeader,
    /// Reused between records so replay does not allocate per packet.
    buffer: Vec<u8>,
    frame_len: usize,
    original_len: usize,
    timestamp: SystemTime,
    counters: CaptureCounters,
    offset: u64,
    truncated: bool,
    finished: bool,
}

impl PcapReplay<File> {
    /// Open a savefile.
    ///
    /// # Errors
    /// [`CaptureError::Io`] if the file cannot be read, [`CaptureError::NotPcap`]
    /// if it is not a savefile, and [`CaptureError::UnsupportedLinkType`] if its
    /// encapsulation is not Ethernet.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path: PathBuf = path.as_ref().to_path_buf();
        let file = File::open(&path).map_err(|source| CaptureError::io(&path, source))?;
        Self::from_reader(file, path.display().to_string())
    }
}

impl<R: Read> PcapReplay<R> {
    /// Read the savefile header from `reader` and prepare to replay.
    ///
    /// # Errors
    /// As [`PcapReplay::open`].
    pub fn from_reader(reader: R, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let mut reader = BufReader::new(reader);

        let mut raw = [0u8; FILE_HEADER_LEN];
        let read = fill(&mut reader, &mut raw, &name)?;
        if read < FILE_HEADER_LEN {
            return Err(CaptureError::NotPcap {
                path: PathBuf::from(&name),
                reason: format!("file header is {read} bytes, expected {FILE_HEADER_LEN}"),
            });
        }

        let header = parse_file_header(&raw, &name)?;
        if header.link_type != LinkType::Ethernet {
            return Err(CaptureError::UnsupportedLinkType {
                link_type: header.link_type.as_raw(),
                source_name: name,
            });
        }

        Ok(Self {
            reader,
            name,
            header,
            buffer: Vec::new(),
            frame_len: 0,
            original_len: 0,
            timestamp: UNIX_EPOCH,
            counters: CaptureCounters::default(),
            offset: FILE_HEADER_LEN as u64,
            truncated: false,
            finished: false,
        })
    }

    /// The savefile header.
    #[must_use]
    pub fn header(&self) -> FileHeader {
        self.header
    }

    /// Whether the file ended in the middle of a record.
    ///
    /// The replay is still usable — every complete record before the tear was
    /// delivered — but the capture is incomplete and the caller should say so.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Read one record into the reusable buffer.
    ///
    /// Returns `false` at end of file.
    fn read_record(&mut self) -> Result<bool> {
        let mut raw = [0u8; RECORD_HEADER_LEN];
        let read = fill(&mut self.reader, &mut raw, &self.name)?;
        if read == 0 {
            return Ok(false);
        }
        if read < RECORD_HEADER_LEN {
            tracing::warn!(
                file = %self.name,
                offset = self.offset,
                "pcap file ends in the middle of a record header; the capture is incomplete"
            );
            self.truncated = true;
            return Ok(false);
        }

        let seconds = self.header.u32_at(&raw, 0);
        let fraction = self.header.u32_at(&raw, 4);
        let captured_len = self.header.u32_at(&raw, 8);
        let wire_len = self.header.u32_at(&raw, 12);

        // Reject before allocating: this length came from the file.
        if captured_len as usize > MAX_FRAME_LEN {
            return Err(CaptureError::RecordTooLarge {
                offset: self.offset,
                claimed: captured_len,
            });
        }
        self.offset += RECORD_HEADER_LEN as u64;

        let captured_len = captured_len as usize;
        self.buffer.clear();
        self.buffer.resize(captured_len, 0);
        let read = fill(&mut self.reader, &mut self.buffer, &self.name)?;
        if read < captured_len {
            tracing::warn!(
                file = %self.name,
                offset = self.offset,
                expected = captured_len,
                got = read,
                "pcap file ends in the middle of a frame; the capture is incomplete"
            );
            self.truncated = true;
            return Ok(false);
        }
        self.offset += captured_len as u64;

        let nanos = if self.header.nanosecond_timestamps {
            fraction
        } else {
            // A microsecond field over 1_000_000 is out of spec; the
            // multiplication is saturating so a bogus value cannot overflow
            // into a wildly wrong instant.
            fraction.saturating_mul(1_000)
        };
        self.timestamp = UNIX_EPOCH
            + Duration::new(u64::from(seconds), 0)
            + Duration::from_nanos(u64::from(nanos));

        self.frame_len = captured_len;
        // A wire length below the captured length is nonsense; trust the bytes
        // we actually have, so nothing downstream believes the frame was
        // snapped when it was not.
        self.original_len = (wire_len as usize).max(captured_len);
        Ok(true)
    }
}

impl<R: Read> PacketSource for PcapReplay<R> {
    fn next_packet(&mut self) -> Result<Captured<'_>> {
        if self.finished {
            return Ok(Captured::End);
        }
        if !self.read_record()? {
            self.finished = true;
            return Ok(Captured::End);
        }

        self.counters.packets += 1;
        self.counters.bytes += self.frame_len as u64;

        Ok(Captured::Frame(RawPacket {
            timestamp: self.timestamp,
            interface: &self.name,
            data: &self.buffer[..self.frame_len],
            original_len: self.original_len,
        }))
    }

    fn counters(&mut self) -> CaptureCounters {
        // A savefile drops nothing: every record it holds is delivered.
        self.counters
    }

    fn link_type(&self) -> LinkType {
        self.header.link_type
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl FileHeader {
    /// Read a `u32` at `offset`, honouring the file's byte order.
    fn u32_at(&self, bytes: &[u8; RECORD_HEADER_LEN], offset: usize) -> u32 {
        let word = [
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ];
        if self.byte_swapped {
            u32::from_be_bytes(word)
        } else {
            u32::from_le_bytes(word)
        }
    }
}

fn parse_file_header(raw: &[u8; FILE_HEADER_LEN], name: &str) -> Result<FileHeader> {
    let magic_le = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);

    let (byte_swapped, nanosecond_timestamps) = match magic_le {
        MAGIC_MICROS => (false, false),
        MAGIC_NANOS => (false, true),
        MAGIC_MICROS_SWAPPED => (true, false),
        MAGIC_NANOS_SWAPPED => (true, true),
        _ => {
            let magic_be = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let reason = if magic_be == MAGIC_PCAPNG || magic_le == MAGIC_PCAPNG {
                "this is a pcapng file; convert it with `editcap -F pcap` first".to_string()
            } else {
                format!("unrecognised magic number {magic_le:#010x}")
            };
            return Err(CaptureError::NotPcap {
                path: PathBuf::from(name),
                reason,
            });
        }
    };

    let u16_at = |offset: usize| {
        let word = [raw[offset], raw[offset + 1]];
        if byte_swapped {
            u16::from_be_bytes(word)
        } else {
            u16::from_le_bytes(word)
        }
    };
    let u32_at = |offset: usize| {
        let word = [
            raw[offset],
            raw[offset + 1],
            raw[offset + 2],
            raw[offset + 3],
        ];
        if byte_swapped {
            u32::from_be_bytes(word)
        } else {
            u32::from_le_bytes(word)
        }
    };

    Ok(FileHeader {
        version_major: u16_at(4),
        version_minor: u16_at(6),
        // bytes 8..16 are the (long obsolete) timezone and sigfigs fields
        snaplen: u32_at(16),
        link_type: LinkType::from_raw(u32_at(20)),
        nanosecond_timestamps,
        byte_swapped,
    })
}

/// Read until `buf` is full or the reader is exhausted.
///
/// Returns how many bytes were read, so the caller can tell a clean end of file
/// (`0`) from a torn record (`0 < n < buf.len()`). `Read::read_exact` collapses
/// those two into one error.
fn fill<R: Read>(reader: &mut R, buf: &mut [u8], name: &str) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(source) => return Err(CaptureError::io(name, source)),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal savefile writer, for building inputs in memory.
    #[derive(Debug, Default)]
    struct PcapBuilder {
        records: Vec<u8>,
        link_type: u32,
        nanosecond: bool,
        big_endian: bool,
    }

    impl PcapBuilder {
        fn new() -> Self {
            Self {
                link_type: 1,
                ..Self::default()
            }
        }

        fn frame(mut self, seconds: u32, fraction: u32, wire_len: u32, data: &[u8]) -> Self {
            let captured = u32::try_from(data.len()).unwrap();
            for value in [seconds, fraction, captured, wire_len] {
                self.push_u32(value);
            }
            self.records.extend_from_slice(data);
            self
        }

        /// A record header whose captured length is a lie.
        fn raw_record(mut self, captured_len: u32, data: &[u8]) -> Self {
            for value in [0, 0, captured_len, captured_len] {
                self.push_u32(value);
            }
            self.records.extend_from_slice(data);
            self
        }

        fn push_u32(&mut self, value: u32) {
            if self.big_endian {
                self.records.extend_from_slice(&value.to_be_bytes());
            } else {
                self.records.extend_from_slice(&value.to_le_bytes());
            }
        }

        fn build(&self) -> Vec<u8> {
            let magic: u32 = match (self.nanosecond, self.big_endian) {
                (false, false) => MAGIC_MICROS,
                (true, false) => MAGIC_NANOS,
                // A big-endian file carries the same magic bytes on the wire;
                // written big-endian they read as the swapped constant.
                (false, true) => MAGIC_MICROS,
                (true, true) => MAGIC_NANOS,
            };
            let mut out = Vec::new();
            let push = |value: u32, out: &mut Vec<u8>| {
                if self.big_endian {
                    out.extend_from_slice(&value.to_be_bytes());
                } else {
                    out.extend_from_slice(&value.to_le_bytes());
                }
            };
            push(magic, &mut out);
            push(0x0004_0002, &mut out); // version 2.4, as two u16s
            push(0, &mut out); // thiszone
            push(0, &mut out); // sigfigs
            push(65_535, &mut out); // snaplen
            push(self.link_type, &mut out);
            out.extend_from_slice(&self.records);
            out
        }
    }

    fn replay(bytes: Vec<u8>) -> Result<PcapReplay<std::io::Cursor<Vec<u8>>>> {
        PcapReplay::from_reader(std::io::Cursor::new(bytes), "test.pcap")
    }

    fn collect(source: &mut impl PacketSource) -> Vec<(SystemTime, Vec<u8>, usize)> {
        let mut out = Vec::new();
        loop {
            match source.next_packet().expect("replay should not fail") {
                Captured::Frame(frame) => {
                    out.push((frame.timestamp, frame.data.to_vec(), frame.original_len));
                }
                Captured::Idle => continue,
                Captured::End => break,
            }
        }
        out
    }

    #[test]
    fn replays_records_in_order_with_their_timestamps() {
        let bytes = PcapBuilder::new()
            .frame(1_000, 500_000, 4, b"aaaa")
            .frame(1_001, 0, 2, b"bb")
            .build();
        let mut source = replay(bytes).unwrap();

        let frames = collect(&mut source);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].1, b"aaaa");
        assert_eq!(frames[1].1, b"bb");
        assert_eq!(
            frames[0].0,
            UNIX_EPOCH + Duration::from_micros(1_000_500_000)
        );
        assert_eq!(frames[1].0, UNIX_EPOCH + Duration::from_secs(1_001));

        let counters = source.counters();
        assert_eq!(counters.packets, 2);
        assert_eq!(counters.bytes, 6);
        assert_eq!(counters.drops, 0, "a savefile drops nothing");
        assert!(!source.is_truncated());
    }

    #[test]
    fn end_is_sticky() {
        let mut source = replay(PcapBuilder::new().frame(0, 0, 1, b"a").build()).unwrap();
        assert!(matches!(source.next_packet().unwrap(), Captured::Frame(_)));
        assert!(matches!(source.next_packet().unwrap(), Captured::End));
        assert!(matches!(source.next_packet().unwrap(), Captured::End));
    }

    #[test]
    fn reads_nanosecond_timestamps() {
        let bytes = PcapBuilder {
            nanosecond: true,
            ..PcapBuilder::new()
        }
        .frame(5, 123_456_789, 1, b"x")
        .build();
        let mut source = replay(bytes).unwrap();
        let frames = collect(&mut source);
        assert_eq!(
            frames[0].0,
            UNIX_EPOCH + Duration::from_secs(5) + Duration::from_nanos(123_456_789)
        );
    }

    #[test]
    fn reads_a_byte_swapped_file() {
        let bytes = PcapBuilder {
            big_endian: true,
            ..PcapBuilder::new()
        }
        .frame(7, 0, 3, b"xyz")
        .build();
        let mut source = replay(bytes).unwrap();
        assert!(source.header().byte_swapped);
        let frames = collect(&mut source);
        assert_eq!(frames[0].1, b"xyz");
        assert_eq!(frames[0].0, UNIX_EPOCH + Duration::from_secs(7));
    }

    #[test]
    fn a_snapped_frame_keeps_its_wire_length() {
        let bytes = PcapBuilder::new()
            .frame(0, 0, 1_514, b"only-64-bytes")
            .build();
        let mut source = replay(bytes).unwrap();
        let frames = collect(&mut source);
        assert_eq!(frames[0].1.len(), 13);
        assert_eq!(
            frames[0].2, 1_514,
            "the decoder needs the wire length to spot snapping"
        );
    }

    #[test]
    fn a_wire_length_below_the_captured_length_is_corrected() {
        // Nonsense, and it would make the decoder think a complete frame was
        // snapped — which suppresses genuine length-mismatch anomalies.
        let bytes = PcapBuilder::new().frame(0, 0, 2, b"ten-bytes!").build();
        let mut source = replay(bytes).unwrap();
        let frames = collect(&mut source);
        assert_eq!(frames[0].2, 10);
    }

    #[test]
    fn rejects_a_file_that_is_not_pcap() {
        let error = replay(b"not a pcap file at all!!".to_vec()).unwrap_err();
        assert!(matches!(error, CaptureError::NotPcap { .. }), "{error}");
    }

    #[test]
    fn names_pcapng_specifically() {
        let mut bytes = MAGIC_PCAPNG.to_be_bytes().to_vec();
        bytes.resize(FILE_HEADER_LEN, 0);
        let error = replay(bytes).unwrap_err();
        assert!(error.to_string().contains("pcapng"), "{error}");
        assert!(
            error.to_string().contains("editcap"),
            "the error should say what to do: {error}"
        );
    }

    #[test]
    fn rejects_an_empty_or_short_file() {
        assert!(replay(Vec::new()).is_err());
        assert!(replay(vec![0xd4, 0xc3, 0xb2, 0xa1]).is_err());
    }

    #[test]
    fn rejects_an_unsupported_link_type() {
        let bytes = PcapBuilder {
            link_type: 113, // LINUX_SLL
            ..PcapBuilder::new()
        }
        .build();
        let error = replay(bytes).unwrap_err();
        assert!(
            matches!(
                error,
                CaptureError::UnsupportedLinkType { link_type: 113, .. }
            ),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_record_larger_than_any_frame_may_be() {
        // The length is a lie and the file holds nothing like that many bytes.
        // It must be refused before it is believed, not allocated first.
        let bytes = PcapBuilder::new().raw_record(u32::MAX, b"tiny").build();
        let mut source = replay(bytes).unwrap();
        let error = source.next_packet().unwrap_err();
        assert!(
            matches!(
                error,
                CaptureError::RecordTooLarge {
                    claimed: u32::MAX,
                    ..
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn a_file_torn_mid_header_is_reported_and_ends_the_replay() {
        let mut bytes = PcapBuilder::new().frame(0, 0, 1, b"a").build();
        bytes.extend_from_slice(&[0u8; 5]); // half a record header
        let mut source = replay(bytes).unwrap();

        let frames = collect(&mut source);
        assert_eq!(frames.len(), 1, "the complete record is still delivered");
        assert!(
            source.is_truncated(),
            "the tear must be visible to the caller"
        );
    }

    #[test]
    fn a_file_torn_mid_frame_is_reported_and_ends_the_replay() {
        let bytes = PcapBuilder::new().raw_record(64, b"only-13-bytes").build();
        let mut source = replay(bytes).unwrap();

        assert_eq!(collect(&mut source).len(), 0);
        assert!(source.is_truncated());
    }

    #[test]
    fn a_zero_length_frame_is_delivered_rather_than_ending_the_file() {
        let bytes = PcapBuilder::new()
            .frame(0, 0, 0, b"")
            .frame(1, 0, 1, b"z")
            .build();
        let mut source = replay(bytes).unwrap();
        let frames = collect(&mut source);
        assert_eq!(
            frames.len(),
            2,
            "an empty record must not look like end of file"
        );
        assert!(frames[0].1.is_empty());
    }

    #[test]
    fn an_out_of_spec_microsecond_field_does_not_overflow() {
        let bytes = PcapBuilder::new().frame(0, u32::MAX, 1, b"x").build();
        let mut source = replay(bytes).unwrap();
        let frames = collect(&mut source);
        assert_eq!(
            frames.len(),
            1,
            "a bogus timestamp must not stop the replay"
        );
    }

    #[test]
    fn arbitrary_truncations_of_a_valid_file_never_panic() {
        let bytes = PcapBuilder::new()
            .frame(1, 2, 4, b"aaaa")
            .frame(3, 4, 8, b"bbbbbbbb")
            .build();
        for end in 0..=bytes.len() {
            if let Ok(mut source) = replay(bytes[..end].to_vec()) {
                while let Ok(Captured::Frame(_) | Captured::Idle) = source.next_packet() {}
            }
        }
    }
}
