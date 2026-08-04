//! Host-based detection (**Phase 4** on Linux, **5**/**6** on Windows/macOS).
//!
//! Three sensors, all emitting into the same CyberSentinel event pipeline the
//! network side uses, so host and network alerts correlate natively:
//!
//! * [`fim`] — file integrity monitoring via `notify` (inotify / FSEvents /
//!   `ReadDirectoryChangesW`).
//! * [`logs`] — authentication and system logs (auditd + journald · ETW +
//!   Windows Event Log · unified logging + OpenBSM).
//! * [`process`] — process creation and listening sockets.
//!
//! Host rules use the same `.rules` file format as network rules, with
//! host-event match keywords and SIDs at or above [`HOST_RULE_SID_BASE`]
//! (guide §3.1).

pub mod fim;
pub mod logs;
pub mod platform;
pub mod process;

/// Host rules occupy SIDs at or above this value, keeping them out of the
/// network rule space.
pub const HOST_RULE_SID_BASE: u32 = 1_000_000;
