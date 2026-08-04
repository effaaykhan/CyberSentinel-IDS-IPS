//! L2–L4 packet decoding (**Phase 1**).
//!
//! Wraps `etherparse` to turn a captured frame into a 5-tuple plus payload, and
//! to report **decoder anomalies** — malformed headers, impossible lengths,
//! truncated packets — as events in their own right. Anomalies are detection
//! signal, not just parse failures: they are how a number of evasion attempts
//! announce themselves.
//!
//! Phase 0 defines the anomaly vocabulary; the decoder itself lands in Phase 1,
//! together with a `cargo-fuzz` target (guide §6: a crash in the decoder is a
//! vulnerability in the security tool).

/// A structural problem found while decoding a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeAnomaly {
    /// The frame ended in the middle of a header.
    TruncatedHeader,
    /// A header length field disagrees with the bytes actually present.
    LengthMismatch,
    /// The IP version field is not 4 or 6.
    UnknownIpVersion,
    /// An IPv4 header checksum did not verify.
    BadIpv4Checksum,
    /// More encapsulation layers than the decoder will follow.
    TooManyLayers,
}

impl DecodeAnomaly {
    /// Stable identifier used in event JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TruncatedHeader => "truncated_header",
            Self::LengthMismatch => "length_mismatch",
            Self::UnknownIpVersion => "unknown_ip_version",
            Self::BadIpv4Checksum => "bad_ipv4_checksum",
            Self::TooManyLayers => "too_many_layers",
        }
    }
}
