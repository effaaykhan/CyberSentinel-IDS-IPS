//! Fuzz a whole rule *file* through the loader.
//!
//! Covers what the single-rule target cannot: comment stripping, line
//! continuation, BOM handling, duplicate-SID detection, and the report
//! accounting. The invariant is that every logical line is accounted for —
//! loaded or skipped, never silently dropped, because a silently dropped rule
//! is a detection gap nobody is told about.

#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let mut set = cybersentinel_rules::RuleSet::new();
    let mut report = cybersentinel_rules::LoadReport::default();
    set.load_text(text, Path::new("fuzz.rules"), &mut report);

    assert_eq!(set.len(), report.loaded, "the ruleset and the report must agree");
    assert!(report.evaluable <= report.loaded);
    assert_eq!(report.evaluable + report.non_evaluable(), report.loaded);
    assert_eq!(set.evaluable().count(), report.evaluable);

    // SIDs are unique: a duplicate must have been skipped, not overwritten.
    let mut sids = std::collections::HashSet::new();
    for rule in set.rules() {
        assert!(sids.insert(rule.sid), "duplicate sid {} survived the load", rule.sid);
        assert!(rule.origin.is_some(), "the loader stamps every rule with its origin");
    }
});
