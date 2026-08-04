//! File integrity monitoring (**Phase 4**).
//!
//! Real-time via `notify`, which maps to inotify on Linux, FSEvents on macOS,
//! and `ReadDirectoryChangesW` on Windows.

/// The kind of change observed on a watched path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileChange {
    /// A new path appeared.
    Created,
    /// Contents changed.
    Modified,
    /// Ownership, mode, or timestamps changed.
    AttributesChanged,
    /// The path was removed.
    Deleted,
    /// The path was renamed.
    Renamed,
}

impl FileChange {
    /// Stable identifier used in event JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Modified => "modified",
            Self::AttributesChanged => "attributes_changed",
            Self::Deleted => "deleted",
            Self::Renamed => "renamed",
        }
    }
}
