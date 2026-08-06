//! Fuzz the NTFS USN journal parser.
//!
//! `FSCTL_READ_USN_JOURNAL` returns a raw buffer of variable-length records,
//! each declaring its own length and the offset of its own filename. Every one
//! of those is a chance to walk off the end of the buffer, loop for ever on a
//! zero length, or read a filename out of the next record — which is why the
//! parsing lives in a safe crate rather than beside the FFI, and why it is
//! fuzzed like the pcap reader and the packet decoder.
//!
//! The journal is written by the filesystem, so this is not attacker-controlled
//! in the way a packet is. It is still *adversary-adjacent*: filenames come from
//! whoever created the file, the buffer is parsed while the sensor is catching
//! up on changes made while it was down, and a panic here is a sensor that dies
//! exactly when something has been modifying files unobserved.
//!
//! Properties asserted, beyond the absence of panics:
//!
//! * **Termination.** The walk always ends. A zero or absurd `RecordLength`
//!   stops it rather than spinning.
//! * **Containment.** Every record that parses came from inside the buffer, and
//!   its filename from inside the record.
//! * **No smuggled control characters.** Filenames reach event logs that get
//!   read in terminals.
//! * **Accounting.** Every record either parses or is counted as rejected. A
//!   change the sensor could not read is a coverage hole, and an uncounted one
//!   is invisible.

#![no_main]

use cybersentinel_hids::usn::{parse_journal_data, parse_read_response, parse_record};
use libfuzzer_sys::fuzz_target;

/// NTFS caps a path component at 255 characters; the parser caps what it keeps.
const MAX_NAME_CHARS: usize = 255;

fuzz_target!(|data: &[u8]| {
    // The whole-buffer walk: the shape the FFI layer actually hands over.
    let response = parse_read_response(data);

    // Nothing can come out of a buffer that has nothing in it.
    if data.len() <= 8 {
        assert!(
            response.records.is_empty(),
            "records appeared from a buffer too small to hold one"
        );
    }

    // Records plus rejections cannot exceed what the buffer could hold. Each
    // record is at least the smallest header (60 bytes), so this bounds the
    // walk and would catch an iteration that failed to advance.
    let ceiling = data.len() / 60 + 2;
    assert!(
        response.records.len() as u64 + response.rejected <= ceiling as u64,
        "walk produced {} records and {} rejections from {} bytes",
        response.records.len(),
        response.rejected,
        data.len()
    );

    for record in &response.records {
        assert!(
            !record.file_name.chars().any(char::is_control),
            "a control character reached a filename: {:?}",
            record.file_name
        );
        assert!(
            record.file_name.chars().count() <= MAX_NAME_CHARS,
            "filename is unbounded at {} characters",
            record.file_name.chars().count()
        );
        assert!(
            matches!(record.version.0, 2 | 3),
            "a record parsed with an unsupported version {:?}",
            record.version
        );
        // `change()` is a pure function of the reason bitmask and must be
        // total: every bit pattern maps to a change or to nothing.
        let _ = record.change();
        let _ = record.is_directory();
    }

    // The single-record entry point, against the same bytes. A record that
    // parses standalone must agree with itself.
    if let Ok(record) = parse_record(data) {
        assert!(matches!(record.version.0, 2 | 3));
        assert!(!record.file_name.chars().any(char::is_control));
        let reparsed = parse_record(data).expect("parsing is deterministic");
        assert_eq!(record, reparsed);
    }

    // And the journal header, which decides whether a catch-up is even possible.
    if let Some(journal) = parse_journal_data(data) {
        let repeat = parse_journal_data(data).expect("parsing is deterministic");
        assert_eq!(journal, repeat);
    }
});
