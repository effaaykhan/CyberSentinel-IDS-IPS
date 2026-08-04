//! Shared foundations for the CyberSentinel sensor.
//!
//! This crate owns the three things every other crate depends on:
//!
//! * [`event`] — the **CyberSentinel event JSON** schema. One schema for host and
//!   network events alike (guide §3.1); newline-delimited JSON on the wire.
//! * [`config`] — the `config.yaml` loader.
//! * [`eventlog`] — the **decoupled logging pipeline**: a bounded queue feeding a
//!   dedicated writer thread, so the detection fast path never blocks on I/O
//!   (guide §6).
//!
//! Nothing here does packet capture, decoding, or detection; those live in the
//! per-stage crates and are built in later phases.

pub mod config;
pub mod error;
pub mod event;
pub mod eventlog;
pub mod sensor;
pub mod time;

pub use error::{Error, Result};
pub use event::{Event, EventKind, Payload, SensorInfo};
pub use eventlog::{EventEmitter, EventPipeline, EventSink, PipelineCounters, PipelineSnapshot};
pub use time::Timestamp;

/// Version of the sensor, taken from the crate metadata at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
