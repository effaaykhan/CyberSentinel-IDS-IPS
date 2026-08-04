//! IP defragmentation, TCP stream reassembly, and normalization (**Phase 2**).
//!
//! This is the evasion-resistance core (guide §7, Phase 2). Two properties
//! decide whether the whole sensor works:
//!
//! * **Normalize before matching, with a target-based overlap policy.** An
//!   attacker who can make the sensor and the destination host disagree about
//!   what the byte stream contains can walk past every rule silently.
//! * **Bounded state.** Per-flow and global caps plus timeouts, so an attacker
//!   cannot exhaust memory by opening flows or sending fragments that never
//!   complete (guide §6).
//!
//! Phase 0 fixed the limit vocabulary so the caps are a first-class, reviewable
//! part of the design rather than constants discovered later. Phase 1 adds
//! [`flow`], the bounded flow table those limits first apply to and the state
//! Phase 2's stream reassembly is keyed on.

pub mod flow;

pub use flow::{EndReason, EndedFlow, Endpoint, Flow, FlowCounters, FlowId, FlowKey, FlowTable};

use std::time::Duration;

/// How to resolve overlapping TCP segments or IP fragments that disagree.
///
/// The correct choice depends on the *destination* operating system, which is
/// why this is per-target policy rather than a global switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OverlapPolicy {
    /// First data received wins (Linux, most BSDs).
    #[default]
    First,
    /// Last data received wins (older Windows).
    Last,
}

/// Hard caps on reassembly state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum concurrently tracked flows.
    pub max_flows: usize,
    /// Maximum buffered bytes per flow direction.
    pub max_bytes_per_flow: usize,
    /// Maximum buffered bytes across all flows.
    pub max_bytes_total: usize,
    /// Maximum concurrent in-progress IP fragment reassemblies.
    pub max_fragment_sets: usize,
    /// Idle time after which a flow is evicted.
    pub flow_timeout: Duration,
    /// Time after which an incomplete fragment set is discarded.
    pub fragment_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_flows: 65_536,
            max_bytes_per_flow: 1 << 20,
            max_bytes_total: 512 << 20,
            max_fragment_sets: 4_096,
            flow_timeout: Duration::from_secs(300),
            fragment_timeout: Duration::from_secs(60),
        }
    }
}
