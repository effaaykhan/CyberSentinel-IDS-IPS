//! Per-OS backends for the host sensors.
//!
//! The modules below are gated on the target OS so a build only ever compiles
//! the backend it can use. They are empty in Phase 0.

/// Linux backends: inotify/fanotify, auditd, journald, `/proc` (**Phase 4**).
#[cfg(target_os = "linux")]
pub mod linux {}

/// Windows backends: `ReadDirectoryChangesW`/USN, ETW, Event Log (**Phase 5**).
#[cfg(target_os = "windows")]
pub mod windows {}

/// macOS backends: FSEvents, unified logging, OpenBSM (**Phase 6**).
#[cfg(target_os = "macos")]
pub mod macos {}
