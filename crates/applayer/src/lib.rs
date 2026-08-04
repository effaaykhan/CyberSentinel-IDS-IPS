//! Application-layer parsers (**Phase 3+**).
//!
//! HTTP first, then DNS, then TLS (guide §1). These parsers fill the sticky
//! buffers (`http.uri`, `http.header`, `http.user_agent`, ...) that rule
//! options match against, so app-layer coverage is what gates rule coverage.

/// Application protocols the sensor can parse, or intends to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AppProto {
    /// Not yet identified.
    #[default]
    Unknown,
    /// HTTP/1.x. Phase 3.
    Http,
    /// DNS. Phase 8.
    Dns,
    /// TLS handshake metadata. Phase 8.
    Tls,
}

impl AppProto {
    /// Stable identifier used in event JSON and rule headers.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Http => "http",
            Self::Dns => "dns",
            Self::Tls => "tls",
        }
    }
}
