//! The `run` subcommand: the sensor's main loop.

use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use cybersentinel_common::config::Config;
use cybersentinel_common::event::{
    CaptureStats, EngineStats, EventStats, Payload, RuleStats, StatsEvent,
};
use cybersentinel_common::eventlog::{EventEmitter, EventPipeline, EventSink};
use cybersentinel_common::sensor;
use cybersentinel_rules::{LoadReport, RuleSet};
use cybersentinel_storage::{FileEventSink, StdoutEventSink};

/// Arguments to `cybersentinel run`.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Path to config.yaml.
    #[arg(short, long, value_name = "PATH")]
    pub config: PathBuf,

    /// Emit a single stats event and exit, instead of running until signalled.
    ///
    /// Exercises the whole startup path — config, rules, sensor identity, the
    /// event pipeline, and both sinks — which makes it the smoke test CI runs
    /// on every OS.
    #[arg(long)]
    pub once: bool,

    /// Override logging.level from the config file.
    #[arg(long, value_name = "LEVEL")]
    pub log_level: Option<String>,
}

/// Load everything, then emit `stats` until signalled.
///
/// # Errors
/// Startup failures only: an unreadable or invalid config, an unopenable output
/// file, or an unwritable data directory. Once running, individual failures are
/// logged and survived rather than propagated — a sensor that exits on the
/// first bad write stops being a sensor.
pub fn run(args: &RunArgs) -> Result<()> {
    // Config comes first: it carries the log level. Failures here surface
    // through `main`, which prints to stderr.
    let config = Config::load(&args.config)
        .with_context(|| format!("loading config {}", args.config.display()))?;

    init_tracing(args.log_level.as_deref(), &config.logging.level)?;

    tracing::info!(
        version = cybersentinel_common::VERSION,
        config = %args.config.display(),
        "starting CyberSentinel sensor (detection-only)"
    );
    for warning in config.warnings() {
        tracing::warn!("{warning}");
    }

    let sensor_info = sensor::resolve(&config).context("resolving the sensor identity")?;
    tracing::info!(
        sensor = %sensor_info.name,
        sensor_id = %sensor_info.id,
        "sensor identity resolved"
    );

    let sinks = build_sinks(&config)?;
    let pipeline = Arc::new(EventPipeline::spawn(sinks, config.logging.queue_capacity));
    let emitter = EventEmitter::new(sensor_info, Arc::clone(&pipeline));

    let (_rules, report) = RuleSet::load_files(&config.rules.files);

    let result = main_loop(args, &config, &emitter, &report);

    // Always drain and flush, even if the loop failed: queued alerts are
    // evidence.
    pipeline.shutdown();
    tracing::info!("sensor stopped");
    result
}

fn main_loop(
    args: &RunArgs,
    config: &Config,
    emitter: &EventEmitter,
    report: &LoadReport,
) -> Result<()> {
    let started = Instant::now();
    let shutdown = install_signal_handler()?;

    // A stats event at t=0 doubles as a startup heartbeat: a consumer sees the
    // sensor is alive without waiting a full interval.
    emit_stats(emitter, report, started);

    if args.once {
        return Ok(());
    }

    if !config.stats.enabled {
        tracing::info!("stats events are disabled; running until signalled");
        let _ = shutdown.recv();
        return Ok(());
    }

    let interval = Duration::from_secs(config.stats.interval_secs);
    loop {
        match shutdown.recv_timeout(interval) {
            Err(RecvTimeoutError::Timeout) => emit_stats(emitter, report, started),
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                tracing::info!("shutdown signal received");
                // A final stats event records where the counters ended up —
                // in particular whether anything was dropped.
                emit_stats(emitter, report, started);
                return Ok(());
            }
        }
    }
}

fn emit_stats(emitter: &EventEmitter, report: &LoadReport, started: Instant) {
    let pipeline = emitter.pipeline().counters().snapshot();

    let stats = StatsEvent {
        uptime_secs: started.elapsed().as_secs(),
        events: EventStats {
            emitted: pipeline.emitted,
            dropped: pipeline.dropped,
            written: pipeline.written,
            write_errors: pipeline.write_errors,
            queued: pipeline.queued,
            queue_capacity: pipeline.capacity,
        },
        rules: RuleStats {
            loaded: report.loaded as u64,
            skipped: report.skipped.len() as u64,
            with_unsupported_options: report.non_evaluable() as u64,
        },
        // Zero and disabled until the phases that produce them land, rather
        // than absent: an operator reading `"enabled": false` learns something,
        // whereas a missing section reads like a bug.
        capture: CaptureStats::default(),
        engine: EngineStats::default(),
    };

    if !emitter.emit(Payload::stats(stats)) {
        tracing::warn!("stats event dropped: the event queue is full");
    }
}

fn build_sinks(config: &Config) -> Result<Vec<Box<dyn EventSink>>> {
    let mut sinks: Vec<Box<dyn EventSink>> = Vec::new();

    if config.outputs.stdout.enabled {
        sinks.push(Box::new(StdoutEventSink::new()));
    }
    if config.outputs.file.enabled {
        let path = &config.outputs.file.path;
        let sink = FileEventSink::open(path)
            .with_context(|| format!("opening event log {}", path.display()))?;
        tracing::info!(path = %path.display(), "writing events to file");
        sinks.push(Box::new(sink));
    }
    // syslog and webhook delivery land in Phase 7; `Config::warnings` already
    // told the operator if they enabled one.

    Ok(sinks)
}

/// Wire SIGINT/SIGTERM (Ctrl-C / service stop) to a channel.
///
/// A channel rather than a flag so the main loop can wait on the shutdown
/// signal and the stats interval at once, and stop promptly instead of at the
/// end of the current interval — systemd and Windows service control both
/// expect a timely exit.
fn install_signal_handler() -> Result<Receiver<()>> {
    let (tx, rx) = sync_channel(1);
    ctrlc::set_handler(move || {
        // Non-blocking: the handler must not block, and one notification is
        // enough. A second Ctrl-C while shutting down is intentionally ignored.
        let _ = tx.try_send(());
    })
    .context("installing the shutdown signal handler")?;
    Ok(rx)
}

fn init_tracing(override_level: Option<&str>, config_level: &str) -> Result<()> {
    use tracing_subscriber::EnvFilter;

    // Precedence: --log-level, then RUST_LOG, then logging.level from the config.
    let filter = match override_level {
        Some(level) => EnvFilter::new(level),
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(config_level)),
    };

    tracing_subscriber::fmt()
        // Diagnostics on stderr keep stdout a pure newline-delimited event
        // stream that can be piped straight into a consumer.
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .try_init()
        .map_err(|error| anyhow::anyhow!("installing the log subscriber: {error}"))
}
