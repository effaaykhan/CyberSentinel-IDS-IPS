//! The decoupled event-logging pipeline.
//!
//! Guide §6: *decouple logging from the fast path — never block on I/O.* The
//! producing side (capture, decode, detection, host sensors) calls
//! [`EventEmitter::emit`], which does a **non-blocking** push onto a bounded
//! queue and returns. A single dedicated writer thread owns all the sinks and
//! does the serialization and the I/O.
//!
//! Two consequences, both deliberate:
//!
//! * **A slow or wedged sink can never stall event production.** It can only
//!   fill the queue.
//! * **A full queue drops events**, counted in [`PipelineCounters::dropped`]
//!   and reported in every `stats` event. A non-zero drop count is a coverage
//!   hole, not a cosmetic problem, and must be alarmed on.
//!
//! The queue is [`std::sync::mpsc::sync_channel`]: a bounded MPSC whose
//! `try_send` never blocks and never allocates on the producer side. The guide
//! calls for a "lock-free queue"; std's channel has been backed by the
//! crossbeam algorithm since Rust 1.67, so this is that queue without the extra
//! dependency. If a future phase needs multi-consumer or work-stealing
//! semantics, `crossbeam-channel` is a drop-in replacement.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::event::{Event, Payload, SensorInfo};
use crate::time::Timestamp;

/// A destination for serialized events.
///
/// Implementations run **only** on the writer thread, so they may block; that
/// is the whole point of the queue in front of them.
pub trait EventSink: Send {
    /// Short name used in log messages and error reporting.
    fn name(&self) -> &str;

    /// Write one newline-terminated JSON line.
    ///
    /// # Errors
    /// Any I/O failure. The pipeline counts the error, logs it, and keeps
    /// running — one broken sink must not take the sensor down.
    fn write_line(&mut self, line: &[u8]) -> io::Result<()>;

    /// Flush buffered data.
    ///
    /// Called whenever the queue drains and once at shutdown.
    ///
    /// # Errors
    /// Any I/O failure.
    fn flush(&mut self) -> io::Result<()>;
}

/// Live counters for the pipeline.
#[derive(Debug, Default)]
pub struct PipelineCounters {
    emitted: AtomicU64,
    dropped: AtomicU64,
    written: AtomicU64,
    write_errors: AtomicU64,
    queued: AtomicU64,
    capacity: u64,
}

/// An immutable read of [`PipelineCounters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineSnapshot {
    /// Events accepted onto the queue plus events dropped.
    pub emitted: u64,
    /// Events discarded because the queue was full.
    pub dropped: u64,
    /// Events written to at least one sink.
    pub written: u64,
    /// Sink write failures.
    pub write_errors: u64,
    /// Events currently queued.
    pub queued: u64,
    /// Queue capacity.
    pub capacity: u64,
}

impl PipelineCounters {
    /// Read all counters.
    #[must_use]
    pub fn snapshot(&self) -> PipelineSnapshot {
        PipelineSnapshot {
            emitted: self.emitted.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            queued: self.queued.load(Ordering::Relaxed),
            capacity: self.capacity,
        }
    }
}

/// Messages carried on the queue.
enum Message {
    /// An event to write.
    Event(Box<Event>),
    /// Stop after draining everything queued ahead of this message.
    Shutdown,
}

/// The bounded queue plus its writer thread.
#[derive(Debug)]
pub struct EventPipeline {
    tx: SyncSender<Message>,
    counters: Arc<PipelineCounters>,
    /// `Mutex<Option<..>>` so [`EventPipeline::shutdown`] can join from `&self`
    /// while the pipeline is shared behind an `Arc`. Never touched by `emit`.
    writer: Mutex<Option<JoinHandle<()>>>,
}

impl EventPipeline {
    /// Start the writer thread over `sinks` with a queue of `capacity` events.
    ///
    /// `capacity` is clamped to at least 1.
    #[must_use]
    pub fn spawn(sinks: Vec<Box<dyn EventSink>>, capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let (tx, rx) = sync_channel::<Message>(capacity);
        let counters = Arc::new(PipelineCounters {
            capacity: capacity as u64,
            ..PipelineCounters::default()
        });

        let writer_counters = Arc::clone(&counters);
        let writer = std::thread::Builder::new()
            .name("cybersentinel-eventlog".into())
            .spawn(move || writer_loop(&rx, sinks, &writer_counters))
            .expect("failed to spawn the event-writer thread");

        Self {
            tx,
            counters,
            writer: Mutex::new(Some(writer)),
        }
    }

    /// Counters for `stats` reporting.
    #[must_use]
    pub fn counters(&self) -> &Arc<PipelineCounters> {
        &self.counters
    }

    /// Queue an event without blocking.
    ///
    /// Returns `false` if the queue was full and the event was dropped. This
    /// call performs no I/O and never waits on a sink.
    pub fn emit(&self, event: Event) -> bool {
        self.counters.emitted.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(Message::Event(Box::new(event))) {
            Ok(()) => {
                self.counters.queued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(_)) => {
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                // The writer thread is gone (shut down, or it panicked).
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Drain the queue, flush every sink, and stop the writer thread.
    ///
    /// Blocking, unlike [`EventPipeline::emit`] — call it from the shutdown
    /// path only. Safe to call more than once.
    pub fn shutdown(&self) {
        // Blocking send: shutdown queues behind whatever is still pending, so
        // nothing already accepted is thrown away.
        let _ = self.tx.send(Message::Shutdown);
        if let Some(handle) = self.writer.lock().ok().and_then(|mut w| w.take()) {
            if handle.join().is_err() {
                tracing::error!("event-writer thread panicked");
            }
        }
    }
}

impl Drop for EventPipeline {
    fn drop(&mut self) {
        // `shutdown` is idempotent; this covers the path where a caller forgets.
        self.shutdown();
    }
}

fn writer_loop(
    rx: &Receiver<Message>,
    mut sinks: Vec<Box<dyn EventSink>>,
    counters: &PipelineCounters,
) {
    loop {
        // Drain what is queued, then flush once and park. Flushing on the
        // drain edge keeps the syscall count down without delaying events
        // during a lull.
        let message = match rx.try_recv() {
            Ok(message) => message,
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                flush_all(&mut sinks, counters);
                match rx.recv() {
                    Ok(message) => message,
                    Err(_) => break,
                }
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
        };

        match message {
            Message::Event(event) => {
                counters.queued.fetch_sub(1, Ordering::Relaxed);
                write_event(&event, &mut sinks, counters);
            }
            Message::Shutdown => break,
        }
    }

    // Drain anything queued behind the shutdown marker before going away.
    while let Ok(Message::Event(event)) = rx.try_recv() {
        counters.queued.fetch_sub(1, Ordering::Relaxed);
        write_event(&event, &mut sinks, counters);
    }
    flush_all(&mut sinks, counters);
}

fn write_event(event: &Event, sinks: &mut [Box<dyn EventSink>], counters: &PipelineCounters) {
    // Serialize once, fan out to every sink.
    let line = match event.to_ndjson() {
        Ok(line) => line,
        Err(error) => {
            counters.write_errors.fetch_add(1, Ordering::Relaxed);
            tracing::error!(%error, "failed to serialize event");
            return;
        }
    };

    let mut any_written = false;
    for sink in sinks.iter_mut() {
        match sink.write_line(&line) {
            Ok(()) => any_written = true,
            Err(error) => {
                counters.write_errors.fetch_add(1, Ordering::Relaxed);
                tracing::error!(sink = sink.name(), %error, "event sink write failed");
            }
        }
    }
    if any_written {
        counters.written.fetch_add(1, Ordering::Relaxed);
    }
}

fn flush_all(sinks: &mut [Box<dyn EventSink>], counters: &PipelineCounters) {
    for sink in sinks.iter_mut() {
        if let Err(error) = sink.flush() {
            counters.write_errors.fetch_add(1, Ordering::Relaxed);
            tracing::error!(sink = sink.name(), %error, "event sink flush failed");
        }
    }
}

/// Stamps events with the sensor identity and the current time, then hands them
/// to an [`EventPipeline`].
///
/// Cheap to clone and shareable across threads; this is what producing code
/// holds.
#[derive(Debug, Clone)]
pub struct EventEmitter {
    sensor: SensorInfo,
    pipeline: Arc<EventPipeline>,
}

impl EventEmitter {
    /// Bind a sensor identity to a pipeline.
    #[must_use]
    pub fn new(sensor: SensorInfo, pipeline: Arc<EventPipeline>) -> Self {
        Self { sensor, pipeline }
    }

    /// The sensor identity stamped onto every event.
    #[must_use]
    pub fn sensor(&self) -> &SensorInfo {
        &self.sensor
    }

    /// The underlying pipeline.
    #[must_use]
    pub fn pipeline(&self) -> &Arc<EventPipeline> {
        &self.pipeline
    }

    /// Stamp `payload` with the current time and queue it.
    ///
    /// Returns `false` if the event was dropped because the queue was full.
    pub fn emit(&self, payload: Payload) -> bool {
        self.emit_event(Event::new(Timestamp::now(), self.sensor.clone(), payload))
    }

    /// Queue an already-built event.
    ///
    /// Returns `false` if the event was dropped because the queue was full.
    pub fn emit_event(&self, event: Event) -> bool {
        self.pipeline.emit(event)
    }

    /// Build an event with this emitter's sensor identity and the current time,
    /// for callers that need to attach a flow id or 5-tuple before emitting.
    #[must_use]
    pub fn build(&self, payload: Payload) -> Event {
        self.build_at(Timestamp::now(), payload)
    }

    /// Build an event stamped with a specific time.
    ///
    /// Packet-derived events use the **capture** timestamp, not the moment the
    /// sensor processed the packet.
    #[must_use]
    pub fn build_at(&self, timestamp: Timestamp, payload: Payload) -> Event {
        Event::new(timestamp, self.sensor.clone(), payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Payload, StatsEvent};
    use std::sync::mpsc::channel;
    use std::time::{Duration, Instant};

    fn sensor() -> SensorInfo {
        SensorInfo {
            name: "test-host".into(),
            id: "test-id".into(),
            version: "0.1.0".into(),
        }
    }

    fn event(uptime: u64) -> Event {
        Event::new(
            Timestamp::now(),
            sensor(),
            Payload::stats(StatsEvent {
                uptime_secs: uptime,
                ..StatsEvent::default()
            }),
        )
    }

    /// Collects lines into a shared buffer.
    #[derive(Clone)]
    struct MemorySink(Arc<Mutex<Vec<String>>>);

    impl EventSink for MemorySink {
        fn name(&self) -> &str {
            "memory"
        }
        fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
            self.0
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(line).into_owned());
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Parks the writer thread inside `write_line` until it is released.
    /// Signals `entered` once, so a test can know the writer is wedged.
    struct BlockingSink {
        entered: SyncSender<()>,
        release: Receiver<()>,
        blocked_once: bool,
    }

    impl EventSink for BlockingSink {
        fn name(&self) -> &str {
            "blocking"
        }
        fn write_line(&mut self, _line: &[u8]) -> io::Result<()> {
            if !self.blocked_once {
                self.blocked_once = true;
                let _ = self.entered.try_send(());
                let _ = self.release.recv();
            }
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Always fails, to prove one bad sink does not stop the pipeline.
    struct FailingSink;

    impl EventSink for FailingSink {
        fn name(&self) -> &str {
            "failing"
        }
        fn write_line(&mut self, _line: &[u8]) -> io::Result<()> {
            Err(io::Error::other("nope"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("nope"))
        }
    }

    #[test]
    fn writes_events_to_sinks_in_order() {
        let store = Arc::new(Mutex::new(Vec::new()));
        let pipeline = EventPipeline::spawn(vec![Box::new(MemorySink(Arc::clone(&store)))], 64);
        for i in 0..10 {
            assert!(pipeline.emit(event(i)));
        }
        pipeline.shutdown();

        let lines = store.lock().unwrap();
        assert_eq!(lines.len(), 10);
        for (i, line) in lines.iter().enumerate() {
            assert!(
                line.ends_with('\n'),
                "sinks receive newline-terminated lines"
            );
            let json: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(json["stats"]["uptime_secs"], i);
        }
        assert_eq!(pipeline.counters().snapshot().written, 10);
    }

    #[test]
    fn fans_out_to_every_sink() {
        let a = Arc::new(Mutex::new(Vec::new()));
        let b = Arc::new(Mutex::new(Vec::new()));
        let pipeline = EventPipeline::spawn(
            vec![
                Box::new(MemorySink(Arc::clone(&a))),
                Box::new(MemorySink(Arc::clone(&b))),
            ],
            16,
        );
        pipeline.emit(event(1));
        pipeline.shutdown();
        assert_eq!(a.lock().unwrap().len(), 1);
        assert_eq!(b.lock().unwrap().len(), 1);
    }

    /// The Phase 0 acceptance criterion: *a slow or blocked sink does not stall
    /// event production.*
    ///
    /// The assertion is structural rather than timing-based. With the writer
    /// parked inside the sink, the queue is the only thing absorbing events:
    /// exactly `capacity` more emits succeed, and every emit past that returns
    /// `false` immediately instead of waiting on the sink.
    #[test]
    fn a_blocked_sink_never_stalls_the_producer() {
        const CAPACITY: usize = 8;
        let (entered_tx, entered_rx) = sync_channel(1);
        let (release_tx, release_rx) = channel();

        let pipeline = EventPipeline::spawn(
            vec![Box::new(BlockingSink {
                entered: entered_tx,
                release: release_rx,
                blocked_once: false,
            })],
            CAPACITY,
        );

        // Wedge the writer inside the sink.
        assert!(pipeline.emit(event(0)));
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("writer should reach the sink");

        // The queue is now empty and the writer cannot drain it. Fill it, then
        // keep going well past capacity.
        let start = Instant::now();
        let mut accepted = 0;
        let mut refused = 0;
        for i in 1..=(CAPACITY as u64 * 4) {
            if pipeline.emit(event(i)) {
                accepted += 1;
            } else {
                refused += 1;
            }
        }
        let elapsed = start.elapsed();

        assert_eq!(
            accepted, CAPACITY,
            "the queue should absorb exactly its capacity"
        );
        assert_eq!(
            refused,
            CAPACITY * 3,
            "everything past capacity must be dropped, not queued"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "producing must not wait on the wedged sink (took {elapsed:?})"
        );

        let snapshot = pipeline.counters().snapshot();
        assert_eq!(snapshot.dropped, (CAPACITY * 3) as u64);
        assert_eq!(snapshot.queued, CAPACITY as u64);

        release_tx.send(()).unwrap();
        pipeline.shutdown();
    }

    #[test]
    fn queued_events_survive_shutdown() {
        let store = Arc::new(Mutex::new(Vec::new()));
        let pipeline = EventPipeline::spawn(vec![Box::new(MemorySink(Arc::clone(&store)))], 256);
        for i in 0..200 {
            pipeline.emit(event(i));
        }
        pipeline.shutdown();
        assert_eq!(
            store.lock().unwrap().len(),
            200,
            "shutdown must drain the queue"
        );
    }

    #[test]
    fn a_failing_sink_is_counted_and_survived() {
        let store = Arc::new(Mutex::new(Vec::new()));
        let pipeline = EventPipeline::spawn(
            vec![
                Box::new(FailingSink),
                Box::new(MemorySink(Arc::clone(&store))),
            ],
            16,
        );
        pipeline.emit(event(1));
        pipeline.emit(event(2));
        pipeline.shutdown();

        assert_eq!(
            store.lock().unwrap().len(),
            2,
            "the healthy sink still gets every event"
        );
        let snapshot = pipeline.counters().snapshot();
        assert_eq!(snapshot.written, 2);
        assert!(snapshot.write_errors >= 2);
    }

    #[test]
    fn shutdown_is_idempotent() {
        let pipeline = EventPipeline::spawn(vec![], 4);
        pipeline.shutdown();
        pipeline.shutdown();
    }

    #[test]
    fn emitter_stamps_sensor_and_timestamp() {
        let store = Arc::new(Mutex::new(Vec::new()));
        let pipeline = Arc::new(EventPipeline::spawn(
            vec![Box::new(MemorySink(Arc::clone(&store)))],
            16,
        ));
        let emitter = EventEmitter::new(sensor(), Arc::clone(&pipeline));
        assert!(emitter.emit(Payload::stats(StatsEvent::default())));
        pipeline.shutdown();

        let lines = store.lock().unwrap();
        let json: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(json["sensor"]["name"], "test-host");
        assert!(json["timestamp"].as_str().unwrap().ends_with('Z'));
    }
}
