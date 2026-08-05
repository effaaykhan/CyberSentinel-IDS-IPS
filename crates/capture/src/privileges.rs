//! Dropping privileges once the capture handle is open.
//!
//! Guide §6: *least privilege — open the capture socket, then drop privileges.*
//!
//! Opening a live capture needs `CAP_NET_RAW` (and `CAP_NET_ADMIN` for a
//! promiscuous-mode or BPF-filtered capture). **Nothing on the network path
//! does after that.** Once libpcap holds the socket, those capabilities are
//! pure attack surface: a flaw in the decoder, the reassembler, or a rule
//! parser is worth far less to an attacker in a process that cannot open new
//! sockets or read arbitrary files.
//!
//! # Host monitoring changes the picture
//!
//! The HIDS is not a one-shot open followed by a lifetime of parsing. It has to
//! keep reading and hashing files it does not own — `/etc/shadow` is mode 0640
//! `root:shadow`, and a FIM baseline that cannot read it is a FIM baseline that
//! silently omits the one file most worth watching. So when host monitoring is
//! enabled the sensor **retains** `CAP_DAC_READ_SEARCH` rather than dropping
//! it, and drops everything else. See [`drop_after_capture_open_retaining`],
//! and `CLAUDE.md` for the full set and the reasoning behind each one.
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
    /// How many capabilities were deliberately kept.
    pub retained: usize,
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
    drop_after_capture_open_retaining(&[])
}

/// Drop every capability except the ones named, now that the handle is open.
///
/// `retain` is the set the sensor genuinely still needs — in practice
/// `CAP_DAC_READ_SEARCH` when file integrity monitoring or log reading is on,
/// and nothing at all otherwise.
///
/// Never fails the sensor: a failure to drop is logged and reported, because a
/// monitoring tool that refuses to monitor is not the safer outcome. The caller
/// is responsible for making the residual privilege visible.
///
/// # Why the retained set goes into *four* capability sets
///
/// Permitted and Effective are what this process needs to read a file it does
/// not own. Inheritable and Ambient are what a **child** process needs — and
/// the sensor does exec one: `journalctl`, to follow the journal. Without the
/// ambient bit, a non-root sensor would hold `CAP_DAC_READ_SEARCH` itself and
/// then spawn a `journalctl` that cannot read `/var/log/journal`, which would
/// look exactly like a host with no authentication activity.
#[cfg(target_os = "linux")]
pub fn drop_after_capture_open_retaining(retain: &[caps::Capability]) -> PrivilegeReport {
    use caps::{CapSet, CapsHashSet};

    let uid = current_uid();
    let mut dropped = true;

    // Only keep what we actually hold. Asking for a capability the process was
    // never granted would fail the whole operation and leave everything in
    // place, which is the opposite of what this function is for.
    let held = caps::read(None, CapSet::Permitted).unwrap_or_default();
    let keep: CapsHashSet = retain
        .iter()
        .copied()
        .filter(|capability| held.contains(capability))
        .collect();

    for capability in retain {
        if !keep.contains(capability) {
            tracing::debug!(
                ?capability,
                "not held, so not retained; the feature that needs it will report its own gap"
            );
        }
    }

    // Ambient first: the kernel requires it to stay a subset of permitted and
    // inheritable, so narrowing those first would fail.
    for set in [CapSet::Ambient, CapSet::Inheritable, CapSet::Effective] {
        if let Err(error) = caps::set(None, set, &keep) {
            // A container may not expose the ambient set at all; that is not
            // worth alarming on by itself.
            if matches!(set, CapSet::Ambient) {
                tracing::debug!(?set, %error, "capability set not available");
            } else {
                tracing::warn!(?set, %error, "could not narrow capability set");
                dropped = false;
            }
        }
    }
    // Permitted last, and irreversibly: once a capability leaves it, nothing
    // can raise that capability back into the effective set.
    if let Err(error) = caps::set(None, CapSet::Permitted, &keep) {
        tracing::warn!(%error, "could not narrow the permitted capability set");
        dropped = false;
    }

    if dropped {
        if keep.is_empty() {
            tracing::info!("capabilities dropped: the sensor can no longer open capture handles");
        } else {
            tracing::info!(
                retained = ?keep,
                "capabilities narrowed to what host monitoring needs"
            );
        }
    }

    PrivilegeReport {
        uid,
        capabilities_dropped: dropped,
        running_as_root: uid == 0,
        supported: true,
        retained: keep.len(),
    }
}

/// Clear privileges. A no-op where the platform has no capability model.
#[cfg(not(target_os = "linux"))]
pub fn drop_after_capture_open() -> PrivilegeReport {
    drop_after_capture_open_retaining(&[])
}

/// Clear privileges. A no-op where the platform has no capability model.
#[cfg(not(target_os = "linux"))]
pub fn drop_after_capture_open_retaining(_retain: &[Capability]) -> PrivilegeReport {
    let uid = current_uid();
    tracing::debug!("no capability model on this platform; privileges left unchanged");
    PrivilegeReport {
        uid,
        capabilities_dropped: false,
        running_as_root: uid == 0,
        supported: false,
        retained: 0,
    }
}

/// The capability a host sensor needs kept.
///
/// Re-exported so the CLI does not have to depend on `caps` directly, and so
/// there is exactly one place naming it.
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Capability {
    /// Bypass file read and directory search permission checks.
    CapDacReadSearch,
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
            retained: 0,
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
