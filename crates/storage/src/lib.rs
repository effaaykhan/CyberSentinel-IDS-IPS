//! Local storage for a standalone sensor.
//!
//! Phase 0 provides the two event-log sinks the sensor writes to: stdout and an
//! append-only newline-delimited JSON file. The flow store (SQLite) and the
//! PCAP ring buffer described in guide §3 arrive with the phases that produce
//! their data.
//!
//! Both sinks run on the event-writer thread, never on the fast path, so they
//! are free to block.

pub mod sinks;

pub use sinks::{FileEventSink, StdoutEventSink};
