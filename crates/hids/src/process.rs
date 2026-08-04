//! Process and listening-socket monitoring (**Phase 4**).
//!
//! Linux reads `/proc`; Windows uses ETW; macOS uses the unified log, with
//! Endpoint Security a possible later upgrade (it needs an Apple entitlement, a
//! System Extension, and notarization — guide §4).

/// A process lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcessChange {
    /// A process started.
    Started,
    /// A process exited.
    Exited,
    /// A process began listening on a socket.
    Listening,
}
