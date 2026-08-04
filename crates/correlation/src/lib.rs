//! Local correlation and deduplication (**Phase 4, deepened in Phase 7**).
//!
//! Joins host and network alerts by host, flow, and time so one incident
//! surfaces once rather than as a scatter of alerts. Any anomaly scoring added
//! later stays a separate, alert-only path — the base-rate fallacy makes
//! anomaly scores a poor primary detector (guide §7, Phase 7).

/// How aggressively to collapse repeated alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum DedupeMode {
    /// Emit every alert.
    Off,
    /// Collapse identical alerts within a time window.
    #[default]
    Window,
}
