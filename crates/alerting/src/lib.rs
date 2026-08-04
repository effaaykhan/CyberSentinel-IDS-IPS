//! Alert delivery to external systems (**Phase 7**).
//!
//! CyberSentinel is standalone: it ships no console. It forwards events to
//! whatever the operator already runs — a file, syslog, or a webhook (guide
//! §3). The on-disk event log in `cybersentinel-storage` is the primary sink;
//! this crate covers the push-based ones.

/// Where alerts are pushed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Destination {
    /// Local syslog.
    Syslog,
    /// HTTP POST of newline-delimited JSON to a URL.
    Webhook(String),
}

/// A delivery channel for serialized events.
pub trait Delivery: Send {
    /// Short name for logs.
    fn name(&self) -> &str;

    /// Deliver one newline-terminated JSON line.
    ///
    /// Delivery runs on the event-writer thread and may block; the queue in
    /// `cybersentinel-common::eventlog` keeps that away from the fast path.
    ///
    /// # Errors
    /// Any transport failure. Failures are counted and logged, never fatal.
    fn deliver(&mut self, line: &[u8]) -> std::io::Result<()>;
}
