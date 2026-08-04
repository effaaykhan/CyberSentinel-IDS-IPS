//! Loader behaviour against the shared rule fixtures in `tests/fixtures/rules`.
//!
//! The unit tests in `src/loader.rs` cover each outcome in isolation; this
//! checks that a realistic file mixing all of them produces the report an
//! operator would act on.

use std::path::PathBuf;

use cybersentinel_rules::RuleSet;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/rules")
        .join(name)
}

#[test]
fn mixed_fixture_loads_the_good_rules_and_accounts_for_the_rest() {
    let (set, report) = RuleSet::load_files(&[fixture("mixed.rules")]);

    assert_eq!(report.files.len(), 1);
    assert_eq!(report.loaded, 4, "{}", report.summary());
    assert_eq!(report.evaluable, 2, "{}", report.summary());
    assert_eq!(report.non_evaluable(), 2, "{}", report.summary());
    assert_eq!(set.len(), 4);

    // Every skip names a reason and a line, so the log points at the problem.
    assert_eq!(report.skipped.len(), 5, "{:#?}", report.skipped);
    for skipped in &report.skipped {
        assert!(!skipped.reason.is_empty());
        assert!(skipped.line > 0, "{skipped:?}");
    }

    let reasons: Vec<&str> = report.skipped.iter().map(|s| s.reason.as_str()).collect();
    assert!(reasons.iter().any(|r| r.contains("option block")), "{reasons:?}");
    assert!(reasons.iter().any(|r| r.contains("'sid'")), "{reasons:?}");
    assert!(reasons.iter().any(|r| r.contains("unknown option")), "{reasons:?}");
    assert!(reasons.iter().any(|r| r.contains("detection-only")), "{reasons:?}");
    assert!(reasons.iter().any(|r| r.contains("duplicate sid 900001")), "{reasons:?}");
}

#[test]
fn the_first_definition_of_a_duplicated_sid_wins() {
    let (set, _) = RuleSet::load_files(&[fixture("mixed.rules")]);
    assert_eq!(set.get(900_001).unwrap().msg, "FIXTURE header only");
}

#[test]
fn continuation_lines_produce_one_rule() {
    let (set, _) = RuleSet::load_files(&[fixture("mixed.rules")]);
    let rule = set.get(900_011).expect("the continued rule should load");
    assert_eq!(rule.msg, "FIXTURE continuation joined across lines");
    assert_eq!(rule.rev, 3);
}

#[test]
fn only_evaluable_rules_are_offered_to_the_engine() {
    let (set, _) = RuleSet::load_files(&[fixture("mixed.rules")]);
    let sids: Vec<u32> = set.evaluable().map(|rule| rule.sid).collect();
    assert_eq!(sids, vec![900_001, 900_002]);
}

/// The default ruleset ships with the product; it must parse cleanly, or every
/// install starts with a broken load report.
#[test]
fn the_shipped_default_ruleset_parses() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/cybersentinel.rules");
    let (set, report) = RuleSet::load_files(&[path]);

    assert!(report.skipped.is_empty(), "shipped rules must parse: {:#?}", report.skipped);
    assert!(!set.is_empty());
    for rule in set.rules() {
        assert!(!rule.msg.is_empty());
        assert!(rule.origin.is_some());
        // The SID convention from guide §3.1.
        assert!(rule.sid >= 100_000, "sid {} is below the network range", rule.sid);
    }
}
