//! The decoder-anomaly vocabulary.
//!
//! A malformed packet is **detection signal**, not a parse failure to swallow.
//! Overlapping and impossible header lengths are a classic way to make a sensor
//! and its protected host disagree about what a packet contains, so every
//! structural problem the decoder finds is named, counted, and emitted.
//!
//! Two things this vocabulary deliberately does *not* include:
//!
//! * **Unsupported EtherTypes** (ARP, LLDP, ...). Those are normal traffic the
//!   decoder has no opinion about. Reporting them as anomalies would bury the
//!   real ones in noise; they are counted in [`crate::DecodeCounters`] instead.
//! * **Snap-length truncation.** A frame clipped by the capture snap length is
//!   expected, and is distinguished from a frame whose header lies about its
//!   own length — see [`AnomalyKind::LengthMismatch`].

use std::fmt;

/// Which layer the decoder was reading when it found a problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Layer {
    /// Ethernet II framing.
    Ethernet,
    /// An 802.1Q / 802.1ad VLAN tag.
    Vlan,
    /// IPv4.
    Ipv4,
    /// IPv6, including its extension header chain.
    Ipv6,
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP or ICMPv6.
    Icmp,
}

impl Layer {
    /// Stable identifier used in event JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ethernet => "ethernet",
            Self::Vlan => "vlan",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What was structurally wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AnomalyKind {
    /// The frame ended in the middle of a header.
    TruncatedHeader,
    /// A length field claims more bytes than the frame contains, and the frame
    /// was **not** clipped by the snap length — so the header is lying.
    LengthMismatch,
    /// A length field holds a structurally impossible value: an IPv4 IHL below
    /// 5, a TCP data offset below 5, a UDP length below 8, or an IPv4 total
    /// length shorter than its own header.
    ImpossibleLength,
    /// The IP version nibble is neither 4 nor 6.
    UnknownIpVersion,
    /// The IPv4 header checksum does not verify.
    BadIpv4Checksum,
    /// More stacked headers than the decoder will follow — VLAN tags beyond
    /// QinQ, or an IPv6 extension chain past its limit. Unbounded nesting is a
    /// denial-of-service vector, so the decoder stops and says so.
    TooManyLayers,
    /// A zero-length frame.
    EmptyFrame,
}

impl AnomalyKind {
    /// Stable identifier used in event JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TruncatedHeader => "truncated_header",
            Self::LengthMismatch => "length_mismatch",
            Self::ImpossibleLength => "impossible_length",
            Self::UnknownIpVersion => "unknown_ip_version",
            Self::BadIpv4Checksum => "bad_ipv4_checksum",
            Self::TooManyLayers => "too_many_layers",
            Self::EmptyFrame => "empty_frame",
        }
    }
}

impl fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One anomaly: what was wrong, and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Anomaly {
    /// What was wrong.
    pub kind: AnomalyKind,
    /// The layer being decoded when it was found.
    pub layer: Layer,
}

impl Anomaly {
    /// Build an anomaly.
    #[must_use]
    pub fn new(layer: Layer, kind: AnomalyKind) -> Self {
        Self { kind, layer }
    }
}

impl fmt::Display for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.layer, self.kind)
    }
}

/// The anomalies found in one frame.
///
/// **Capped.** A crafted frame — a long VLAN or extension-header chain — could
/// otherwise make one packet allocate without limit and flood the event
/// pipeline. Past the cap, anomalies are counted but not stored, and
/// [`AnomalySet::overflowed`] says so.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnomalySet {
    found: Vec<Anomaly>,
    overflowed: bool,
}

impl AnomalySet {
    /// Most anomalies stored per frame.
    pub const CAP: usize = 8;

    /// Record an anomaly, ignoring exact duplicates.
    pub fn push(&mut self, anomaly: Anomaly) {
        if self.found.contains(&anomaly) {
            return;
        }
        if self.found.len() >= Self::CAP {
            self.overflowed = true;
            return;
        }
        self.found.push(anomaly);
    }

    /// The stored anomalies, in the order they were found.
    #[must_use]
    pub fn as_slice(&self) -> &[Anomaly] {
        &self.found
    }

    /// Whether any anomaly was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.found.is_empty()
    }

    /// How many anomalies are stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.found.len()
    }

    /// Whether anomalies were discarded because the cap was reached.
    #[must_use]
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Whether a given anomaly was recorded.
    #[must_use]
    pub fn contains(&self, layer: Layer, kind: AnomalyKind) -> bool {
        self.found.contains(&Anomaly::new(layer, kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_are_ignored() {
        let mut set = AnomalySet::default();
        set.push(Anomaly::new(Layer::Ipv4, AnomalyKind::TruncatedHeader));
        set.push(Anomaly::new(Layer::Ipv4, AnomalyKind::TruncatedHeader));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn the_same_kind_at_a_different_layer_is_a_different_anomaly() {
        let mut set = AnomalySet::default();
        set.push(Anomaly::new(Layer::Ipv4, AnomalyKind::TruncatedHeader));
        set.push(Anomaly::new(Layer::Tcp, AnomalyKind::TruncatedHeader));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn storage_is_capped_and_the_overflow_is_reported() {
        let mut set = AnomalySet::default();
        let kinds = [
            AnomalyKind::TruncatedHeader,
            AnomalyKind::LengthMismatch,
            AnomalyKind::ImpossibleLength,
            AnomalyKind::UnknownIpVersion,
            AnomalyKind::BadIpv4Checksum,
            AnomalyKind::TooManyLayers,
            AnomalyKind::EmptyFrame,
        ];
        // Enough distinct (layer, kind) pairs to exceed the cap.
        for layer in [Layer::Ethernet, Layer::Vlan, Layer::Ipv4] {
            for kind in kinds {
                set.push(Anomaly::new(layer, kind));
            }
        }
        assert_eq!(set.len(), AnomalySet::CAP);
        assert!(set.overflowed());
    }

    #[test]
    fn identifiers_are_stable() {
        assert_eq!(
            Anomaly::new(Layer::Ipv4, AnomalyKind::TruncatedHeader).to_string(),
            "ipv4.truncated_header"
        );
    }
}
