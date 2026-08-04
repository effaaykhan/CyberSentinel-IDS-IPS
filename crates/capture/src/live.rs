//! Live capture through libpcap (**Phase 1**, Linux and macOS).
//!
//! The `pcap` crate wraps libpcap, which keeps all the `unsafe` inside the
//! dependency so every first-party crate stays `forbid(unsafe_code)`. Windows
//! gets its Npcap-backed equivalent in Phase 5.
//!
//! # Privileges
//!
//! Opening the handle needs `CAP_NET_RAW`, and `CAP_NET_ADMIN` for promiscuous
//! mode or a kernel-side BPF filter. Nothing after the open does, so
//! [`LiveCapture::open`] is expected to be followed immediately by
//! [`crate::privileges::drop_after_capture_open`].
//!
//! # Drops
//!
//! [`LiveCapture::counters`] queries libpcap for kernel and interface drop
//! counts on every call. Dropped packets are traffic that went unexamined —
//! a coverage hole, and the reason these counters reach `stats` events from
//! this phase onward rather than later (guide §9).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{CaptureCounters, CaptureError, Captured, LinkType, PacketSource, RawPacket, Result};

/// How to open a live capture.
#[derive(Debug, Clone)]
pub struct LiveOptions {
    /// Interface name. `None` asks libpcap for the default.
    pub interface: Option<String>,
    /// Bytes to capture per frame.
    pub snaplen: u32,
    /// Whether to put the interface in promiscuous mode.
    pub promiscuous: bool,
    /// Optional BPF filter, applied in the kernel.
    pub bpf_filter: Option<String>,
    /// How long a poll waits before reporting [`Captured::Idle`].
    ///
    /// This is what bounds shutdown latency on a quiet link: the run loop can
    /// only notice a stop signal between polls.
    pub poll_timeout_ms: i32,
    /// Kernel capture buffer size. Larger absorbs longer bursts and is the
    /// first thing to raise when drops appear.
    pub buffer_size_bytes: Option<i32>,
}

impl Default for LiveOptions {
    fn default() -> Self {
        Self {
            interface: None,
            snaplen: 65_535,
            promiscuous: true,
            bpf_filter: None,
            poll_timeout_ms: 250,
            buffer_size_bytes: None,
        }
    }
}

/// A live capture handle.
pub struct LiveCapture {
    handle: pcap::Capture<pcap::Active>,
    name: String,
    link_type: LinkType,
    delivered_packets: u64,
    delivered_bytes: u64,
}

// `pcap::Capture` is not `Debug`, so this is written out rather than derived —
// the workspace warns on missing `Debug` impls, and a capture handle that
// cannot be printed in a log line is a nuisance during incident work.
impl std::fmt::Debug for LiveCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveCapture")
            .field("interface", &self.name)
            .field("link_type", &self.link_type)
            .field("packets", &self.delivered_packets)
            .field("bytes", &self.delivered_bytes)
            .finish_non_exhaustive()
    }
}

impl LiveCapture {
    /// Open a live capture.
    ///
    /// # Errors
    /// [`CaptureError::Backend`] if the device cannot be found or opened —
    /// most often a missing `CAP_NET_RAW` — and
    /// [`CaptureError::UnsupportedLinkType`] if the interface is not Ethernet.
    pub fn open(options: &LiveOptions) -> Result<Self> {
        let device = select_device(options.interface.as_deref())?;
        let name = device.name.clone();

        let mut builder = pcap::Capture::from_device(device)
            .map_err(|error| CaptureError::Backend(format!("selecting a capture device: {error}")))?
            .promisc(options.promiscuous)
            .snaplen(i32::try_from(options.snaplen).unwrap_or(i32::MAX))
            .timeout(options.poll_timeout_ms)
            // Without immediate mode libpcap batches frames until its buffer
            // fills, which on a quiet link delays detection by an unbounded
            // amount. An IDS wants the packet now.
            .immediate_mode(true);

        if let Some(bytes) = options.buffer_size_bytes {
            builder = builder.buffer_size(bytes);
        }

        let mut handle = builder.open().map_err(|error| {
            CaptureError::Backend(format!(
                "opening {name}: {error} \
                 (live capture needs CAP_NET_RAW; try running under the shipped systemd unit)"
            ))
        })?;

        if let Some(filter) = &options.bpf_filter {
            handle.filter(filter, true).map_err(|error| {
                CaptureError::Backend(format!("BPF filter {filter:?}: {error}"))
            })?;
        }

        let raw_link_type = handle.get_datalink().0;
        let link_type = LinkType::from_raw(u32::try_from(raw_link_type).unwrap_or(u32::MAX));
        if link_type != LinkType::Ethernet {
            return Err(CaptureError::UnsupportedLinkType {
                link_type: link_type.as_raw(),
                source_name: name,
            });
        }

        tracing::info!(
            interface = %name,
            snaplen = options.snaplen,
            promiscuous = options.promiscuous,
            filter = options.bpf_filter.as_deref().unwrap_or(""),
            "live capture open"
        );

        Ok(Self {
            handle,
            name,
            link_type,
            delivered_packets: 0,
            delivered_bytes: 0,
        })
    }
}

fn select_device(interface: Option<&str>) -> Result<pcap::Device> {
    match interface {
        Some(wanted) => {
            let devices = pcap::Device::list().map_err(|error| {
                CaptureError::Backend(format!("listing capture devices: {error}"))
            })?;
            devices
                .iter()
                .find(|device| device.name == wanted)
                .cloned()
                .ok_or_else(|| {
                    let available = devices
                        .iter()
                        .map(|device| device.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    CaptureError::Backend(format!(
                        "no capture device named {wanted:?}; available: {available}"
                    ))
                })
        }
        None => pcap::Device::lookup()
            .map_err(|error| CaptureError::Backend(format!("finding a default device: {error}")))?
            .ok_or_else(|| {
                CaptureError::Backend("no capture device is available on this host".to_string())
            }),
    }
}

/// Convert a `timeval` to a [`SystemTime`], tolerating out-of-range values.
///
/// Generic over the field types because `timeval` is `i64`/`i64` on Linux but
/// `i64`/`i32` on macOS: a fixed signature would need a cast that is redundant
/// on one platform and required on the other. A corrupt or pre-epoch value must
/// not panic a running sensor, so both fields are clamped rather than trusted.
fn timeval_to_system_time(seconds: impl Into<i64>, microseconds: impl Into<i64>) -> SystemTime {
    let (seconds, microseconds) = (seconds.into(), microseconds.into());
    let Ok(seconds) = u64::try_from(seconds) else {
        return UNIX_EPOCH;
    };
    let microseconds = microseconds.clamp(0, 999_999) as u64;
    UNIX_EPOCH + Duration::from_secs(seconds) + Duration::from_micros(microseconds)
}

impl PacketSource for LiveCapture {
    fn next_packet(&mut self) -> Result<Captured<'_>> {
        match self.handle.next_packet() {
            Ok(packet) => {
                let timestamp =
                    timeval_to_system_time(packet.header.ts.tv_sec, packet.header.ts.tv_usec);
                self.delivered_packets += 1;
                self.delivered_bytes += packet.data.len() as u64;
                Ok(Captured::Frame(RawPacket {
                    timestamp,
                    interface: &self.name,
                    data: packet.data,
                    original_len: packet.header.len as usize,
                }))
            }
            // A quiet link, not a finished one. The run loop uses this to check
            // for a shutdown signal.
            Err(pcap::Error::TimeoutExpired) => Ok(Captured::Idle),
            Err(pcap::Error::NoMorePackets) => Ok(Captured::End),
            Err(error) => Err(CaptureError::Backend(error.to_string())),
        }
    }

    fn counters(&mut self) -> CaptureCounters {
        // Ask libpcap for the kernel's view every time: drops accumulate in the
        // kernel, not here, and a stale drop count is worse than none.
        let (drops, interface_drops) = match self.handle.stats() {
            Ok(stats) => (u64::from(stats.dropped), u64::from(stats.if_dropped)),
            Err(error) => {
                tracing::warn!(%error, "could not read capture drop counters");
                (0, 0)
            }
        };

        CaptureCounters {
            packets: self.delivered_packets,
            bytes: self.delivered_bytes,
            drops,
            interface_drops,
        }
    }

    fn link_type(&self) -> LinkType {
        self.link_type
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_are_sane_for_an_ids() {
        let options = LiveOptions::default();
        assert_eq!(options.snaplen, 65_535, "an IDS wants the whole packet");
        assert!(options.promiscuous);
        assert!(
            options.poll_timeout_ms > 0,
            "a zero timeout would block shutdown on a quiet link"
        );
    }

    #[test]
    fn timevals_convert_and_never_panic() {
        assert_eq!(
            timeval_to_system_time(1_000, 500_000),
            UNIX_EPOCH + Duration::from_micros(1_000_500_000)
        );
        // Pre-epoch and out-of-range values clamp rather than panicking.
        assert_eq!(timeval_to_system_time(-1, 0), UNIX_EPOCH);
        assert_eq!(timeval_to_system_time(0, -5), UNIX_EPOCH);
        assert_eq!(
            timeval_to_system_time(0, i64::MAX),
            UNIX_EPOCH + Duration::from_micros(999_999)
        );
        assert!(timeval_to_system_time(i64::MAX, i64::MAX)
            .duration_since(UNIX_EPOCH)
            .is_ok());
    }

    /// Opening a live capture needs privileges, so CI cannot exercise it. This
    /// at least proves the device-selection error path is reachable and says
    /// something useful.
    #[test]
    fn a_missing_device_is_reported_by_name() {
        let error = select_device(Some("definitely-not-an-interface")).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("definitely-not-an-interface"), "{message}");
    }
}
