//! Fuzz the pcap savefile reader, and the decoder behind it.
//!
//! A savefile is attacker-supplied input: every length in the format is
//! attacker controlled, and an analyst opening a capture someone sent them is
//! exactly the situation this has to survive. Reading savefiles in-tree rather
//! than through libpcap is what makes this target possible at all — an FFI
//! boundary would be opaque to the fuzzer.
//!
//! This drives the real Phase 1 path: file → records → decoder, so a
//! disagreement between the two layers about a length shows up here.

#![no_main]

use cybersentinel_capture::{Captured, PacketSource, PcapReplay};
use libfuzzer_sys::fuzz_target;

/// Stop after this many records so a small input that describes a huge number
/// of tiny frames cannot make one case run forever.
const MAX_RECORDS: usize = 4_096;

fuzz_target!(|data: &[u8]| {
    let Ok(mut source) = PcapReplay::from_reader(std::io::Cursor::new(data.to_vec()), "fuzz.pcap")
    else {
        // A rejected file is a correct outcome, not a failure.
        return;
    };

    let mut records = 0usize;
    let mut decoded_bytes = 0u64;

    while records < MAX_RECORDS {
        match source.next_packet() {
            Ok(Captured::Frame(frame)) => {
                records += 1;

                // The reader must never hand out a frame longer than the cap
                // it promises to enforce.
                assert!(frame.data.len() <= cybersentinel_capture::MAX_FRAME_LEN);
                // A wire length below the captured length would make the
                // decoder treat a complete frame as snapped, which silently
                // suppresses genuine length-mismatch anomalies.
                assert!(
                    frame.original_len >= frame.data.len(),
                    "wire length {} below captured length {}",
                    frame.original_len,
                    frame.data.len()
                );

                let decoded = cybersentinel_decode::decode(frame.data, frame.original_len);
                assert!(decoded.payload.end <= frame.data.len());
                decoded_bytes += decoded.payload_len() as u64;
            }
            Ok(Captured::Idle) => {}
            // Both are correct outcomes for a malformed file.
            Ok(Captured::End) | Err(_) => break,
        }
    }

    let counters = source.counters();
    assert_eq!(counters.drops, 0, "a savefile drops nothing");
    assert!(decoded_bytes <= counters.bytes);
});
