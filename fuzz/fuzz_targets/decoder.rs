//! Fuzz the L2–L4 decoder.
//!
//! The decoder is the first thing in the sensor to touch a packet an attacker
//! wrote, so guide §6 makes this target non-negotiable: *a crash here is a
//! vulnerability in the security tool.*
//!
//! The properties asserted are stronger than "did not panic". A decoder that
//! returns a payload range pointing outside the frame, or that claims a
//! 5-tuple it never read, would corrupt everything downstream of it without
//! ever crashing.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first two bytes choose a wire length, so the fuzzer can explore the
    // snapped-frame paths as well as whole frames. `original_len` is
    // attacker-influenced on some capture backends, so it gets fuzzed too.
    let (original_len, frame) = match data.split_at_checked(2) {
        Some((prefix, rest)) => (
            usize::from(u16::from_le_bytes([prefix[0], prefix[1]])),
            rest,
        ),
        None => (data.len(), data),
    };

    let decoded = cybersentinel_decode::decode(frame, original_len);

    // The payload range must always be a valid, non-inverted slice of the
    // frame: everything downstream indexes with it.
    assert!(
        decoded.payload.start <= decoded.payload.end,
        "inverted payload range {:?}",
        decoded.payload
    );
    assert!(
        decoded.payload.end <= frame.len(),
        "payload range {:?} escapes a {}-byte frame",
        decoded.payload,
        frame.len()
    );
    assert_eq!(decoded.payload_bytes().len(), decoded.payload_len());

    // A transport layer without a network layer would be a 5-tuple built from
    // addresses that were never parsed.
    if decoded.transport.is_some() {
        assert!(decoded.network.is_some(), "transport decoded with no network layer");
    }
    assert_eq!(decoded.five_tuple().is_some(), decoded.network.is_some());

    // Anomaly storage is capped, so one crafted frame cannot allocate without
    // limit or flood the event pipeline.
    assert!(decoded.anomalies.len() <= cybersentinel_decode::AnomalySet::CAP);

    // Counters must accept anything the decoder produced.
    let mut counters = cybersentinel_decode::DecodeCounters::default();
    counters.record(&decoded);
    assert_eq!(counters.packets, 1);
});
