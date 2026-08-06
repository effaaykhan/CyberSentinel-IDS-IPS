//! Host-based detection (**Phase 4** on Linux, **5**/**6** on Windows/macOS).
//!
//! Three sensors, all emitting into the same CyberSentinel event pipeline the
//! network side uses, so host and network alerts correlate natively:
//!
//! * [`fim`] — file integrity monitoring via `notify` (inotify / FSEvents /
//!   `ReadDirectoryChangesW`), backed by a SQLite baseline and a periodic
//!   rescan.
//! * [`logs`] — authentication logs (journald and syslog files now; auditd,
//!   the Windows Event Log, and macOS unified logging later).
//! * [`process`] — process creation and listening sockets, from `/proc`.
//!
//! [`sensor::HostSensor`] drives all three from one polled call, so the CLI's
//! run loop services host monitoring the same way it services packet capture.
//!
//! Host rules use the same `.rules` file format as network rules, with
//! host-event match keywords and SIDs at or above [`HOST_RULE_SID_BASE`]
//! (guide §3.1).
//!
//! # Privileges
//!
//! Unlike the network side — which needs `CAP_NET_RAW` and nothing else — the
//! HIDS reads and hashes files it does not own and reads other users' `/proc`
//! entries. The capability set it needs, and the reason for each, is documented
//! in `CLAUDE.md` for the packaging pass to wire into the service unit.

pub mod fim;
pub mod logs;
pub mod platform;
pub mod process;
pub mod sensor;
pub mod sources;

/// Host rules occupy SIDs at or above this value, keeping them out of the
/// network rule space.
pub const HOST_RULE_SID_BASE: u32 = 1_000_000;

/// Something a host sensor could not do.
///
/// Deliberately small. Nearly everything that goes wrong while monitoring a
/// host — an unreadable file, a process that exited mid-read, a log that does
/// not exist yet — is *ordinary*, and is counted rather than raised. What
/// reaches this type is a failure that leaves a whole sensor unable to work.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HostError {
    /// The baseline store could not be opened or used.
    #[error("file integrity baseline: {detail}")]
    Baseline {
        /// What failed.
        detail: String,
    },
    /// The real-time watcher could not be established.
    ///
    /// Not fatal to FIM as a whole: the periodic rescan still runs, which is
    /// precisely the case the baseline exists for.
    #[error("file watcher: {detail}")]
    Watcher {
        /// What failed.
        detail: String,
    },
}
