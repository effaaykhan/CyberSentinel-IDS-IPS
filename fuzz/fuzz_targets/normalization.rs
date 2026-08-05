//! Fuzz the normalization primitives.
//!
//! Normalization decides what a rule is matched *against*. A bug here does not
//! crash anything — it quietly makes the sensor look at a different request
//! than the server is serving, which is the failure mode this phase exists to
//! prevent. So the properties asserted are semantic, not just "did not panic".

#![no_main]

use cybersentinel_reassembly::normalize::{
    collapse_path, normalize_path, percent_decode, percent_decode_repeatedly, NormalizeOptions,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First byte selects the options, so one corpus explores every combination.
    let (control, input) = match data.split_first() {
        Some((control, rest)) => (*control, rest),
        None => (0, &[][..]),
    };
    let options = NormalizeOptions {
        decode_rounds: usize::from(control & 0b11),
        collapse_path: control & 0b100 != 0,
        backslash_is_separator: control & 0b1000 != 0,
    };

    // --- decoding ---------------------------------------------------------
    let (decoded, _) = percent_decode(input);
    assert!(
        decoded.len() <= input.len(),
        "percent decoding grew {} bytes into {}",
        input.len(),
        decoded.len()
    );

    let repeated = percent_decode_repeatedly(input, options.decode_rounds);
    assert!(repeated.bytes.len() <= input.len());
    assert!(repeated.rounds_applied <= options.decode_rounds);

    // --- collapsing -------------------------------------------------------
    let (collapsed, _) = collapse_path(input, options.backslash_is_separator);
    assert!(
        collapsed.len() <= input.len(),
        "collapsing grew its input"
    );

    // A collapsed path is fully resolved: no `.`, no `..`, no empty interior
    // segment can remain, or a rule would still have to consider spellings the
    // server has already resolved away.
    let parts: Vec<&[u8]> = collapsed.split(|byte| *byte == b'/').collect();
    for (index, part) in parts.iter().enumerate() {
        assert_ne!(*part, b".", "a self-reference survived collapsing");
        assert_ne!(*part, b"..", "a traversal survived collapsing");
        if part.is_empty() {
            assert!(
                index == 0 || index == parts.len() - 1,
                "an interior empty segment survived collapsing: {collapsed:?}"
            );
        }
    }

    // Collapsing is idempotent: normalizing something already normalized must
    // not change it again, or the canonical form would not be canonical.
    let (twice, _) = collapse_path(&collapsed, options.backslash_is_separator);
    assert_eq!(twice, collapsed, "collapsing is not idempotent");

    // --- the composition --------------------------------------------------
    let normalized = normalize_path(input, &options);
    assert!(normalized.bytes.len() <= input.len());

    // Flags must describe what actually happened.
    if normalized.flags.double_encoded {
        assert!(
            normalized.rounds_applied >= 2,
            "double encoding cannot be reported without a second pass"
        );
    }
    if options.decode_rounds == 0 {
        assert_eq!(normalized.rounds_applied, 0);
        assert!(!normalized.flags.double_encoded);
    }
});
