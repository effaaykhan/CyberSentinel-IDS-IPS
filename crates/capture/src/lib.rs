//! Packet capture (**Phase 1**).
//!
//! Everything upstream of the decoder sits behind [`PacketSource`], with two
//! implementations:
//!
//! * [`replay::PcapReplay`] — reads a `.pcap` savefile. Pure Rust, no
//!   privileges, no system library. This is what the tests and CI run, on every
//!   OS.
//! * [`live::LiveCapture`] — libpcap on Linux and macOS (Npcap on Windows in
//!   Phase 5). Needs privileges to open, and none to keep running; see
//!   [`privileges`].
//!
//! # Why the file reader is not libpcap
//!
//! Live capture uses the `pcap` crate, which keeps all the `unsafe` inside the
//! dependency so our crates stay `forbid(unsafe_code)`. Reading a *savefile* is
//! different: the format is a 24-byte header and a 16-byte record prefix, and
//! implementing it in-tree buys two things worth more than the shared code.
//!
//! First, the entire decode path becomes testable on any machine with no
//! libpcap at all — including the Windows CI runner, which would otherwise need
//! the Npcap SDK installed just to replay a file.
//!
//! Second, a savefile is **attacker-supplied input**. Anything that parses
//! attacker-supplied input belongs under the same bounds-checking and fuzzing
//! discipline as the rest of the pipeline, rather than behind an FFI boundary
//! our fuzzers cannot see into.
//!
//! # Drop counters are load-bearing
//!
//! Dropped packets are silent coverage holes (guide §9). [`CaptureCounters`]
//! carries kernel and interface drops from the first backend onward, and they
//! surface in every `stats` event.

pub mod privileges;
pub mod replay;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod live;

use std::path::PathBuf;
use std::time::SystemTime;

pub use replay::PcapReplay;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use live::{LiveCapture, LiveOptions};

/// Convenience alias for capture operations.
pub type Result<T> = std::result::Result<T, CaptureError>;

/// The largest single frame any backend will accept.
///
/// Matches libpcap's `MAXIMUM_SNAPLEN`. A savefile record claiming more than
/// this is rejected rather than allocated — the length field is attacker
/// controlled.
pub const MAX_FRAME_LEN: usize = 262_144;

/// Link-layer encapsulation of a capture source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// `LINKTYPE_ETHERNET` (1). The only encapsulation the Phase 1 decoder
    /// understands.
    Ethernet,
    /// Anything else, kept so the error message can name it.
    Other(u32),
}

impl LinkType {
    /// Build from a pcap link-type number.
    #[must_use]
    pub fn from_raw(value: u32) -> Self {
        match value {
            1 => Self::Ethernet,
            other => Self::Other(other),
        }
    }

    /// The pcap link-type number.
    #[must_use]
    pub fn as_raw(self) -> u32 {
        match self {
            Self::Ethernet => 1,
            Self::Other(other) => other,
        }
    }
}

/// Why capture failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaptureError {
    /// An I/O operation against a named path failed.
    #[error("i/o error on {path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The file is not a pcap savefile.
    #[error("{path} is not a pcap savefile: {reason}")]
    NotPcap {
        /// The offending file.
        path: PathBuf,
        /// What was wrong.
        reason: String,
    },

    /// The savefile or interface uses an encapsulation the decoder cannot read.
    #[error("unsupported link type {link_type} ({source_name}): only Ethernet (1) is supported in Phase 1")]
    UnsupportedLinkType {
        /// The link-type number.
        link_type: u32,
        /// Which file or interface it came from.
        source_name: String,
    },

    /// A record header claims more bytes than any frame may hold.
    #[error("pcap record at offset {offset} claims {claimed} bytes, above the {MAX_FRAME_LEN} byte limit")]
    RecordTooLarge {
        /// Byte offset of the record header.
        offset: u64,
        /// The claimed capture length.
        claimed: u32,
    },

    /// The capture backend failed.
    #[error("capture backend error: {0}")]
    Backend(String),

    /// No live-capture backend exists for this platform yet.
    #[error("live capture is not available on this platform yet")]
    NoLiveBackend,
}

impl CaptureError {
    /// Attach a path to a bare [`std::io::Error`].
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// One captured frame, borrowed from the backend's buffer.
#[derive(Debug, Clone, Copy)]
pub struct RawPacket<'a> {
    /// Capture timestamp, from the kernel for live capture and from the record
    /// header when replaying.
    pub timestamp: SystemTime,
    /// Interface or file the frame came from.
    pub interface: &'a str,
    /// Frame bytes, clipped to the snap length.
    pub data: &'a [u8],
    /// Length on the wire before clipping. Greater than `data.len()` means the
    /// frame was snapped.
    pub original_len: usize,
}

/// What a poll of a [`PacketSource`] produced.
///
/// The three-way answer matters: a live source that has simply seen no traffic
/// for a moment is **not** finished, and the run loop needs the difference so it
/// can check for a shutdown signal instead of blocking forever.
#[derive(Debug)]
pub enum Captured<'a> {
    /// A frame.
    Frame(RawPacket<'a>),
    /// Nothing arrived within the backend's poll timeout. Try again.
    Idle,
    /// The source is finished: end of file, or a closed handle.
    End,
}

/// Counters every backend maintains.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureCounters {
    /// Frames delivered to the pipeline.
    pub packets: u64,
    /// Bytes delivered to the pipeline.
    pub bytes: u64,
    /// Frames the kernel dropped because our buffer was full. **A non-zero
    /// value means traffic went unexamined.**
    pub drops: u64,
    /// Frames the interface dropped before the kernel saw them.
    pub interface_drops: u64,
}

impl CaptureCounters {
    /// Drops as a fraction of everything that was offered to us.
    ///
    /// Returns 0.0 when nothing has been seen yet.
    #[must_use]
    pub fn drop_rate(&self) -> f64 {
        let offered = self.packets + self.drops + self.interface_drops;
        if offered == 0 {
            return 0.0;
        }
        (self.drops + self.interface_drops) as f64 / offered as f64
    }
}

/// A source of frames.
pub trait PacketSource {
    /// Poll for the next frame.
    ///
    /// # Errors
    /// Backend-specific capture or parse failures.
    fn next_packet(&mut self) -> Result<Captured<'_>>;

    /// Current counters, including kernel-side drops.
    ///
    /// Takes `&mut self` because querying drop counters is a call into the
    /// capture handle, not a field read.
    fn counters(&mut self) -> CaptureCounters;

    /// Link-layer encapsulation of this source.
    fn link_type(&self) -> LinkType;

    /// A human-readable name for logs and events.
    fn name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_rate_is_zero_before_anything_is_seen() {
        assert!((CaptureCounters::default().drop_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn drop_rate_counts_dropped_traffic_against_everything_offered() {
        let counters = CaptureCounters {
            packets: 75,
            bytes: 0,
            drops: 20,
            interface_drops: 5,
        };
        assert!((counters.drop_rate() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn link_types_round_trip() {
        assert_eq!(LinkType::from_raw(1), LinkType::Ethernet);
        assert_eq!(LinkType::Ethernet.as_raw(), 1);
        assert_eq!(LinkType::from_raw(113), LinkType::Other(113));
        assert_eq!(LinkType::Other(113).as_raw(), 113);
    }
}
