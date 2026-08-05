//! Fuzz the HTTP request parser.
//!
//! It reads a reassembled attacker-controlled byte stream and decides what the
//! server will see. A crash is a vulnerability; a parser that grows without
//! bound is a denial of service; and a URI buffer that is not canonical is a
//! rule matching the wrong request — all three silent.

#![no_main]

use cybersentinel_applayer::HttpParser;
use cybersentinel_reassembly::normalize::NormalizeOptions;
use libfuzzer_sys::fuzz_target;

const MAX_HEAD: usize = 4_096;

fuzz_target!(|data: &[u8]| {
    let (control, rest) = match data.split_first() {
        Some((control, rest)) => (*control, rest),
        None => (0, &[][..]),
    };
    let options = NormalizeOptions {
        decode_rounds: usize::from(control & 0b11),
        collapse_path: control & 0b100 != 0,
        backslash_is_separator: control & 0b1000 != 0,
    };

    let mut parser = HttpParser::new(MAX_HEAD);
    // Feed in chunks, so the incremental path is exercised rather than only
    // the one-shot one: a request split across deliveries is the normal case.
    for chunk in rest.chunks(17.max(1)) {
        for request in parser.push(chunk, &options) {
            // A parsed request must be self-consistent.
            assert!(!request.method.is_empty(), "a parsed request always has a method");
            assert!(!request.raw_uri.is_empty(), "a parsed request always has a target");
            assert!(
                request.method.iter().all(u8::is_ascii_alphabetic),
                "a method that is not a token should not have parsed"
            );
            // Normalization never grows its input, so neither does the URI.
            assert!(
                request.uri.len() <= request.raw_uri.len(),
                "the normalized URI grew from {} to {} bytes",
                request.raw_uri.len(),
                request.uri.len()
            );
            if options.collapse_path {
                let path_end = request
                    .uri
                    .iter()
                    .position(|byte| *byte == b'?')
                    .unwrap_or(request.uri.len());
                for segment in request.uri[..path_end].split(|byte| *byte == b'/') {
                    assert_ne!(segment, b"..", "a traversal survived into the URI buffer");
                }
            }
        }
        // The cap is what stops a client that never terminates its head from
        // costing more than one that does.
        assert!(
            parser.buffered() <= MAX_HEAD + 17,
            "buffered {} bytes against a {MAX_HEAD} cap",
            parser.buffered()
        );
    }
});
