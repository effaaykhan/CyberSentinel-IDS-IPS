//! Packet capture (**Phase 1**).
//!
//! Owns the [`PacketSource`] abstraction and its per-OS backends: AF_PACKET on
//! Linux, Npcap on Windows, BPF on macOS (guide §2). Phase 0 defines only the
//! shape, so downstream crates can be written against a stable interface before
//! any backend exists.
//!
//! Two obligations this crate must honour when it is implemented:
//!
//! * **Drop counters.** Dropped packets are silent coverage holes (guide §9);
//!   [`CaptureCounters::drops`] feeds the `stats` event from the first backend
//!   onward.
//! * **Least privilege.** Open the capture handle, then drop privileges
//!   (guide §6).

use std::time::SystemTime;

/// One captured frame, borrowed from the capture backend's buffer.
#[derive(Debug, Clone, Copy)]
pub struct RawPacket<'a> {
    /// Kernel-supplied capture timestamp.
    pub timestamp: SystemTime,
    /// Interface the frame arrived on.
    pub interface: &'a str,
    /// Frame bytes, truncated to the configured snap length.
    pub data: &'a [u8],
    /// Length on the wire before snap-length truncation. Greater than
    /// `data.len()` means the frame was clipped.
    pub original_len: usize,
}

/// Counters every backend maintains.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureCounters {
    /// Frames delivered to the pipeline.
    pub packets: u64,
    /// Bytes delivered to the pipeline.
    pub bytes: u64,
    /// Frames the kernel or capture library discarded before we saw them.
    pub drops: u64,
}

/// A source of frames.
///
/// Implemented per OS in Phase 1, and by a PCAP replay source used by the test
/// fixtures.
pub trait PacketSource {
    /// Block until the next frame is available.
    ///
    /// `Ok(None)` means the source is exhausted (end of a PCAP file, or a
    /// closed handle).
    ///
    /// # Errors
    /// Backend-specific capture failures.
    fn next_packet(&mut self) -> std::io::Result<Option<RawPacket<'_>>>;

    /// Current counters, including kernel-side drops.
    fn counters(&self) -> CaptureCounters;
}
