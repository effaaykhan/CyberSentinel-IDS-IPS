//! What each host event source is doing, and whether it is doing anything.
//!
//! # The problem this exists to solve
//!
//! A sensor reporting nothing looks exactly the same whether the host is quiet
//! or the thing that watches it is broken. On Linux that was handled with
//! counters — `watch_failures`, `auth_unparsed`, `inotify_overflows` — one per
//! failure mode, each added when its failure mode was understood.
//!
//! Porting to a second OS makes that approach come apart. The *ways* a source
//! fails are per-platform: an exhausted `max_user_watches` has no Windows
//! equivalent, a disabled audit policy has no Linux one. What does not change
//! is the question an operator asks — *is this source working?* — so that is
//! what gets reported, uniformly, and the platform-specific reason goes in a
//! detail string.
//!
//! It also closes a hole that exists **today**, before any Windows code is
//! written. Build the sensor for Windows right now and it starts, reports
//! `hids.enabled: true`, tries to read `/proc` (which is not there), tries to
//! spawn `journalctl` (which is not there), and emits zeroes — a host sensor
//! that is not monitoring the host, saying nothing about it. Every source below
//! that has no implementation for the target platform now reports
//! [`SourceState::Unsupported`] instead.
//!
//! # Silence that is provably wrong
//!
//! Some sources cannot legitimately report nothing, and those are worth
//! checking rather than counting. A process table always contains at least the
//! sensor's own process, so a sweep that finds **only itself** is not watching
//! a quiet host — it is blind, and something has restricted its view. That is
//! exactly the shape of the `ProtectProc=invisible` failure the Linux packaging
//! pass found by testing: service healthy, capture fine, FIM fine, process
//! monitoring silently reporting nothing at all.

use cybersentinel_common::event::{SourceState, SourceStatus};
use std::collections::BTreeMap;

/// Names are stable: a consumer alarms on them.
pub mod names {
    /// Real-time file change notification.
    pub const FIM_REALTIME: &str = "fim.realtime";
    /// The periodic baseline comparison.
    pub const FIM_BASELINE: &str = "fim.baseline";
    /// Structured authentication records.
    pub const AUTH_STRUCTURED: &str = "auth.structured";
    /// Authentication records from text log files.
    pub const AUTH_FILES: &str = "auth.files";
    /// Process creation and exit.
    pub const PROCESS_TABLE: &str = "process.table";
    /// Listening sockets.
    pub const PROCESS_SOCKETS: &str = "process.sockets";
}

/// The set of sources and what each is doing.
#[derive(Debug, Default)]
pub struct SourceRegistry {
    entries: BTreeMap<String, SourceStatus>,
}

impl SourceRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a source's state, replacing whatever was there.
    pub fn set(&mut self, name: &str, state: SourceState, detail: impl Into<String>) {
        let records = self.entries.get(name).map_or(0, |entry| entry.records);
        self.entries.insert(
            name.to_string(),
            SourceStatus {
                name: name.to_string(),
                state,
                detail: detail.into(),
                records,
            },
        );
    }

    /// Declare a source working.
    pub fn active(&mut self, name: &str) {
        self.set(name, SourceState::Active, String::new());
    }

    /// Declare a source absent on this host, with the reason.
    pub fn unavailable(&mut self, name: &str, detail: impl Into<String>) {
        self.set(name, SourceState::Unavailable, detail);
    }

    /// Declare a source not implemented for this platform.
    pub fn unsupported(&mut self, name: &str, detail: impl Into<String>) {
        self.set(name, SourceState::Unsupported, detail);
    }

    /// Declare a source working with reduced coverage.
    pub fn degraded(&mut self, name: &str, detail: impl Into<String>) {
        self.set(name, SourceState::Degraded, detail);
    }

    /// Count records a source produced.
    ///
    /// Recorded even for a source in a hole state: a source that is degraded
    /// but still producing is a different situation from one producing nothing.
    pub fn produced(&mut self, name: &str, count: u64) {
        self.entries
            .entry(name.to_string())
            .or_insert_with(|| SourceStatus {
                name: name.to_string(),
                ..SourceStatus::default()
            })
            .records += count;
    }

    /// The state of one source, if it has been declared.
    #[must_use]
    pub fn state(&self, name: &str) -> Option<SourceState> {
        self.entries.get(name).map(|entry| entry.state)
    }

    /// Every source, in stable name order.
    #[must_use]
    pub fn snapshot(&self) -> Vec<SourceStatus> {
        self.entries.values().cloned().collect()
    }

    /// The sources that are not fully working.
    #[must_use]
    pub fn holes(&self) -> Vec<&SourceStatus> {
        self.entries
            .values()
            .filter(|entry| entry.state.is_hole())
            .collect()
    }

    /// Log every hole once, at startup.
    ///
    /// Deliberately one line per hole rather than a summary count: an operator
    /// needs to know *which* coverage they do not have.
    pub fn log_holes(&self) {
        for hole in self.holes() {
            tracing::warn!(
                source = hole.name,
                state = hole.state.as_str(),
                detail = hole.detail,
                "host event source is not fully working: this is a coverage hole"
            );
        }
    }
}

/// Which sources have no implementation on a given OS, and why.
///
/// A **pure function of the OS name** rather than a pile of `cfg` blocks, so
/// the Windows and macOS answers can be tested from a Linux machine. Gating
/// this on `cfg!` would have made the one thing worth checking — that a
/// platform without backends says so rather than reporting zeroes — checkable
/// only by running on that platform, which is exactly the circularity this
/// project keeps trying to avoid.
///
/// The details name the phase that fills each gap, because "unsupported" with
/// no horizon reads like a bug rather than a plan.
#[must_use]
pub fn platform_gaps(os: &str) -> Vec<(&'static str, &'static str)> {
    match os {
        // Linux implements every source (Phase 4).
        "linux" => Vec::new(),
        "windows" => vec![
            (
                names::AUTH_STRUCTURED,
                "Windows Event Log (4624/4625) arrives in Phase 5; journald is Linux-only",
            ),
            (
                names::PROCESS_TABLE,
                "ETW process monitoring arrives in Phase 5; /proc is Linux-only",
            ),
            (
                names::PROCESS_SOCKETS,
                "GetExtendedTcpTable arrives in Phase 5; /proc/net/tcp is Linux-only",
            ),
        ],
        "macos" => vec![
            (
                names::AUTH_STRUCTURED,
                "the macOS unified log and OpenBSM arrive in Phase 6; journald is Linux-only",
            ),
            (
                names::PROCESS_TABLE,
                "macOS process monitoring arrives in Phase 6; /proc is Linux-only",
            ),
            (
                names::PROCESS_SOCKETS,
                "macOS socket enumeration arrives in Phase 6; /proc/net/tcp is Linux-only",
            ),
        ],
        // An OS nobody has ported to is entirely unsupported, and saying so is
        // better than pretending the Linux backends will work.
        _ => vec![
            (names::AUTH_STRUCTURED, "no host backend for this platform"),
            (names::PROCESS_TABLE, "no host backend for this platform"),
            (names::PROCESS_SOCKETS, "no host backend for this platform"),
        ],
    }
}

/// Declare this platform's gaps into a registry.
///
/// Called at startup before anything else registers, so a backend that *does*
/// exist overwrites its entry. Whatever still says `unsupported` genuinely is.
pub fn declare_platform_gaps(registry: &mut SourceRegistry) {
    for (name, detail) in platform_gaps(std::env::consts::OS) {
        registry.unsupported(name, detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hole_is_reported_with_its_reason() {
        let mut registry = SourceRegistry::new();
        registry.active(names::FIM_REALTIME);
        registry.unavailable(names::AUTH_STRUCTURED, "journalctl is not installed");

        let holes = registry.holes();
        assert_eq!(holes.len(), 1);
        assert_eq!(holes[0].name, names::AUTH_STRUCTURED);
        assert!(
            !holes[0].detail.is_empty(),
            "a hole without a reason is not actionable"
        );
    }

    #[test]
    fn an_active_source_is_not_a_hole() {
        let mut registry = SourceRegistry::new();
        registry.active(names::PROCESS_TABLE);
        assert!(registry.holes().is_empty());
        assert_eq!(
            registry.state(names::PROCESS_TABLE),
            Some(SourceState::Active)
        );
    }

    #[test]
    fn record_counts_survive_a_state_change() {
        // A source that degrades has still produced what it produced; losing
        // the count would hide how much coverage there was before it broke.
        let mut registry = SourceRegistry::new();
        registry.active(names::AUTH_FILES);
        registry.produced(names::AUTH_FILES, 7);
        registry.degraded(names::AUTH_FILES, "one of two files disappeared");

        let snapshot = registry.snapshot();
        let entry = snapshot
            .iter()
            .find(|entry| entry.name == names::AUTH_FILES)
            .expect("the source is listed");
        assert_eq!(entry.records, 7);
        assert_eq!(entry.state, SourceState::Degraded);
    }

    #[test]
    fn the_snapshot_is_in_stable_order() {
        let mut registry = SourceRegistry::new();
        registry.active(names::PROCESS_TABLE);
        registry.active(names::AUTH_FILES);
        registry.active(names::FIM_BASELINE);

        let names: Vec<_> = registry
            .snapshot()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "consumers diff these; order must not churn");
    }

    /// The point of the whole module, and the reason `platform_gaps` takes the
    /// OS as an argument: **this is checkable from Linux.** Build the sensor
    /// for Windows today and it starts, tries to read a `/proc` that is not
    /// there, tries to spawn a `journalctl` that is not there, and emits
    /// zeroes — a host sensor not monitoring the host and saying nothing about
    /// it. Every such source must announce itself instead.
    #[test]
    fn a_platform_without_backends_says_so_rather_than_reporting_zeroes() {
        for os in ["windows", "macos", "freebsd"] {
            let gaps = platform_gaps(os);
            assert!(
                !gaps.is_empty(),
                "{os} has no host backends but declares no gaps: it would look quiet"
            );
            for (name, detail) in gaps {
                assert!(
                    !detail.is_empty(),
                    "{os}/{name} says unsupported without saying why"
                );
            }
        }
    }

    #[test]
    fn windows_and_macos_gaps_name_the_phase_that_fills_them() {
        for (os, phase) in [("windows", "Phase 5"), ("macos", "Phase 6")] {
            for (name, detail) in platform_gaps(os) {
                assert!(
                    detail.contains(phase),
                    "{os}/{name} does not say when it stops being a gap: {detail:?}"
                );
            }
        }
    }

    #[test]
    fn linux_declares_no_gaps_because_it_implements_them_all() {
        assert!(platform_gaps("linux").is_empty());
    }

    #[test]
    fn declaring_gaps_marks_them_unsupported_in_the_registry() {
        let mut registry = SourceRegistry::new();
        declare_platform_gaps(&mut registry);
        for hole in registry.holes() {
            assert_eq!(hole.state, SourceState::Unsupported);
        }
        // On the host this runs on, the registry agrees with the pure function.
        assert_eq!(
            registry.holes().len(),
            platform_gaps(std::env::consts::OS).len()
        );
    }

    #[test]
    fn a_later_declaration_overwrites_an_earlier_one() {
        // A backend that *does* exist must be able to overwrite the gap
        // declaration, or the gap list would be permanently wrong.
        let mut registry = SourceRegistry::new();
        registry.unsupported(names::PROCESS_TABLE, "not on this platform");
        registry.active(names::PROCESS_TABLE);
        assert!(registry.holes().is_empty());
    }
}
