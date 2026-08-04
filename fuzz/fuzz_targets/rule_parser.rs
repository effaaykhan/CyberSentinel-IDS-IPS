//! Fuzz a single rule through the parser.
//!
//! The property under test is totality: for **any** input the parser returns a
//! `Rule` or a `ParseError`, and never panics, hangs, or overflows the stack.
//! Rules are operator-supplied and, over time, may be shared between
//! organisations — a crash here is a vulnerability in the security tool
//! (guide §6).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(rule) = cybersentinel_rules::parse_rule(text) {
        // A rule that parsed must be self-consistent: these are the invariants
        // the loader and, from Phase 3, the engine rely on.
        assert!(!rule.msg.is_empty(), "a parsed rule always has a msg");
        assert!(rule.rev >= 1, "rev defaults to at least 1");
        assert_eq!(
            rule.is_evaluable(),
            rule.unsupported_options.is_empty(),
            "evaluability is exactly the absence of unsupported options"
        );

        let mut seen = std::collections::HashSet::new();
        for option in &rule.unsupported_options {
            assert!(seen.insert(option), "unsupported options are deduplicated");
        }
    }
});
