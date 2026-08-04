//! Dropping privileges once the capture handle is open.
//!
//! Guide §6: *least privilege — open the capture socket, then drop privileges.*
//!
//! Opening a live capture needs `CAP_NET_RAW` (and `CAP_NET_ADMIN` for a
//! promiscuous-mode or BPF-filtered capture). **Nothing after that does.** Once
//! libpcap holds the socket, the capabilities are pure attack surface: a flaw
//! in the decoder, the reassembler, or a rule parser is worth far less to an
//! attacker in a process that cannot open new sockets or read arbitrary files.
//!
//! # What this does and does not achieve
//!
//! Dropping capabilities is not the same as dropping *root*. A process running
//! as uid 0 with an empty capability set can still be granted capabilities back
//! by the kernel on `execve`, and root-owned file access is governed by more
//! than capabilities. Real privilege separation means running as a non-root
//! user with only the ambient capabilities needed — which is exactly what the
//! shipped systemd unit does (`DynamicUser=yes` plus
//! `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`).
//!
//! So [`drop_after_capture_open`] reports what it actually managed, and the
//! caller is expected to warn loudly when the sensor is still running as root.

/// What privilege dropping achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivilegeReport {
    /// Real user id of the process.
    pub uid: u32,
    /// Whether the capability sets were cleared.
    pub capabilities_dropped: bool,
    /// Whether the process is still uid 0.
    pub running_as_root: bool,
    /// Whether this platform supports capability dropping at all.
    pub supported: bool,
}

impl PrivilegeReport {
    /// Whether the operator should be warned that the sensor holds more
    /// privilege than it needs.
    #[must_use]
    pub fn is_overprivileged(&self) -> bool {
        self.running_as_root
    }
}

/// The process's real user id.
///
/// Read from `/proc/self` rather than `getuid(2)` so no `unsafe` and no `libc`
/// dependency is needed. Falls back to 0 (assume root, warn) if `/proc` is not
/// mounted, which is the safe direction to be wrong in.
#[cfg(unix)]
#[must_use]
pub fn current_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata("/proc/self")
        .map(|metadata| metadata.uid())
        .unwrap_or(0)
}

/// The process's real user id. Always 0 on platforms without one.
#[cfg(not(unix))]
#[must_use]
pub fn current_uid() -> u32 {
    0
}

/// Clear every capability set now that the capture handle is open.
///
/// Never fails the sensor: a failure to drop is logged and reported, because a
/// monitoring tool that refuses to monitor is not the safer outcome. The caller
/// is responsible for making the residual privilege visible.
#[cfg(target_os = "linux")]
pub fn drop_after_capture_open() -> PrivilegeReport {
    use caps::CapSet;

    let uid = current_uid();
    let mut dropped = true;

    // Ambient first: the kernel requires it to be a subset of the permitted and
    // inheritable sets, so clearing those first would fail.
    for set in [
        CapSet::Ambient,
        CapSet::Inheritable,
        CapSet::Effective,
        // Permitted last, and irreversibly: once it is empty nothing can raise
        // a capability back into the effective set.
        CapSet::Permitted,
    ] {
        if let Err(error) = caps::clear(None, set) {
            // A container may not expose the ambient set at all; that is not
            // worth alarming on by itself.
            if matches!(set, CapSet::Ambient) {
                tracing::debug!(?set, %error, "capability set not available");
            } else {
                tracing::warn!(?set, %error, "could not clear capability set");
                dropped = false;
            }
        }
    }

    if dropped {
        tracing::info!("capabilities dropped: the sensor can no longer open capture handles");
    }

    PrivilegeReport {
        uid,
        capabilities_dropped: dropped,
        running_as_root: uid == 0,
        supported: true,
    }
}

/// Clear privileges. A no-op where the platform has no capability model.
#[cfg(not(target_os = "linux"))]
pub fn drop_after_capture_open() -> PrivilegeReport {
    let uid = current_uid();
    tracing::debug!("no capability model on this platform; privileges left unchanged");
    PrivilegeReport {
        uid,
        capabilities_dropped: false,
        running_as_root: uid == 0,
        supported: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_flags_root_as_overprivileged() {
        let report = PrivilegeReport {
            uid: 0,
            capabilities_dropped: true,
            running_as_root: true,
            supported: true,
        };
        assert!(report.is_overprivileged());

        let report = PrivilegeReport {
            uid: 1_000,
            running_as_root: false,
            ..report
        };
        assert!(!report.is_overprivileged());
    }

    /// Deliberately does **not** call `drop_after_capture_open`: it is
    /// irreversible, and running it here would strip the capabilities of the
    /// whole test binary and break any test that runs after it.
    #[test]
    fn current_uid_is_readable() {
        let _ = current_uid();
    }
}
