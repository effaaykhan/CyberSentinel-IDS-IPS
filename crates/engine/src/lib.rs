//! The detection engine (**Phase 3**).
//!
//! Rule grouping by header, an `aho-corasick` multi-pattern scan over
//! `fast_pattern` content, then full evaluation of the surviving candidates
//! (content modifiers, `pcre`, `flow`, `flowbits`, sticky buffers, `byte_test`,
//! thresholds) — ending in a CyberSentinel `alert` event.
//!
//! Phase 0 defines the counters the engine reports and the verdict it returns.

/// Result of evaluating one unit of input against the ruleset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verdict {
    /// Nothing matched.
    #[default]
    NoMatch,
    /// At least one rule matched; alerts have been emitted.
    Matched,
}

/// Counters the engine contributes to `stats` events.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EngineCounters {
    /// Units of input evaluated.
    pub evaluated: u64,
    /// Candidates surfaced by the multi-pattern scan.
    pub mpm_candidates: u64,
    /// Alerts raised.
    pub alerts: u64,
    /// Alerts suppressed by `threshold` / `detection_filter`.
    pub thresholded: u64,
}
