//! Authentication and system log monitoring (**Phase 4**).
//!
//! Linux reads auditd and journald; Windows reads ETW and the Windows Event Log
//! (plus Sysmon where present); macOS reads unified logging and OpenBSM. Each
//! backend normalizes into the same host event vocabulary.

/// Normalized authentication outcome, independent of the source log format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthOutcome {
    /// Authentication succeeded.
    Success,
    /// Authentication failed.
    Failure,
}
