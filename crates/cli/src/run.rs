//! The `run` subcommand: the sensor's main loop.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use cybersentinel_capture::{Captured, PacketSource, PcapReplay};
use cybersentinel_common::config::Config;
use cybersentinel_common::event::{
    CaptureStats, DecodeStats, EngineStats, EventStats, FlowStats, Payload, ReassemblyStats,
    RuleStats, StatsEvent,
};
use cybersentinel_common::eventlog::{EventEmitter, EventPipeline, EventSink};
use cybersentinel_common::sensor;
use cybersentinel_engine::CompileLimits;
use cybersentinel_engine::{CompileReport, Engine, EngineLimits, VarTable};
use cybersentinel_rules::{LoadReport, RuleSet};
use cybersentinel_storage::{FileEventSink, StdoutEventSink};

use crate::pipeline::{PacketPipeline, PipelineOptions, PipelineSnapshot, SharedSnapshot};

/// How often the packet loop republishes counters for the stats thread.
const PUBLISH_EVERY_PACKETS: u64 = 1_024;

/// Granularity of the stats thread's sleep, and so the worst-case delay between
/// a shutdown signal and the sensor acting on it.
const SHUTDOWN_POLL: Duration = Duration::from_millis(100);

/// How long the packet loop waits after an empty poll.
///
/// Live capture handles are non-blocking, so an idle link would otherwise spin
/// a core. One millisecond costs at most 1ms of extra detection latency on the
/// next packet — and only when the link was idle, which is when latency matters
/// least — while keeping shutdown responsive and counters fresh.
const IDLE_POLL: Duration = Duration::from_millis(1);

/// Arguments to `cybersentinel run`.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Path to config.yaml.
    #[arg(short, long, value_name = "PATH")]
    pub config: PathBuf,

    /// Replay a .pcap capture file instead of capturing live, then exit.
    ///
    /// Needs no privileges and no libpcap, so this is how the whole pipeline is
    /// exercised in tests and CI.
    #[arg(long, value_name = "PATH", conflicts_with = "once")]
    pub replay: Option<PathBuf>,

    /// Emit a single stats event and exit, without capturing.
    ///
    /// Exercises the startup path — config, rules, sensor identity, the event
    /// pipeline, and both sinks — which makes it a cheap per-OS smoke test.
    #[arg(long)]
    pub once: bool,

    /// Override logging.level from the config file.
    #[arg(long, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Refuse to start if any rule fails to load or compile.
    ///
    /// Off by default: a sensor that will not start because one rule is broken
    /// is a sensor that is not watching anything. Use this in CI and
    /// pre-deployment checks, where failing loudly is the point.
    #[arg(long)]
    pub strict: bool,

    /// Write reassembled TCP stream content into this directory.
    ///
    /// A debugging aid, off unless asked for. Reassembled streams are bulk
    /// payload — credentials, personal data, whatever the traffic carried — so
    /// putting them on disk has to be a deliberate choice. Alert-triggered
    /// evidence capture is a later phase and is a different thing.
    #[arg(long, value_name = "DIR")]
    pub dump_streams: Option<PathBuf>,
}

/// Where frames come from.
enum Source {
    /// A capture file.
    Replay(Box<PcapReplay>),
    /// A live interface.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Live(Box<cybersentinel_capture::LiveCapture>),
    /// Nothing: the sensor runs as a heartbeat only.
    None,
}

impl Source {
    fn as_packet_source(&mut self) -> Option<&mut dyn PacketSource> {
        match self {
            Self::Replay(source) => Some(source.as_mut()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Live(source) => Some(source.as_mut()),
            Self::None => None,
        }
    }

    fn name(&self) -> String {
        match self {
            Self::Replay(source) => source.name().to_string(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::Live(source) => source.name().to_string(),
            Self::None => String::new(),
        }
    }
}

/// Load everything, then capture until the source or the operator stops us.
///
/// # Errors
/// Startup failures only: an unreadable or invalid config, an unopenable
/// capture source or output file, or an unwritable data directory. Once
/// running, individual failures are logged and survived rather than propagated
/// — a sensor that exits on the first bad write stops being a sensor.
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

    if let Some(directory) = &args.dump_streams {
        std::fs::create_dir_all(directory).with_context(|| {
            format!("creating the stream dump directory {}", directory.display())
        })?;
        tracing::warn!(
            path = %directory.display(),
            "--dump-streams is on: reassembled payload will be written to disk in the clear. \
             This is captured traffic and should be treated as personal data."
        );
    }

    let sensor_info = sensor::resolve(&config).context("resolving the sensor identity")?;
    tracing::info!(
        sensor = %sensor_info.name,
        sensor_id = %sensor_info.id,
        "sensor identity resolved"
    );

    // ---------------------------------------------------------------------
    // Least privilege (guide §6).
    //
    // Order matters here, and it is the reason capture is opened before the
    // event pipeline exists. Linux capabilities are per-*thread*: a thread
    // keeps whatever it had when it was spawned. So the handle is opened and
    // the capabilities dropped while this is still a single-threaded process,
    // and every thread created afterwards inherits the dropped set.
    // ---------------------------------------------------------------------
    let mut source = open_source(args, &config)?;
    if matches!(source, Source::None) {
        tracing::info!("no capture source configured; running as a heartbeat only");
    } else {
        drop_privileges();
    }

    let sinks = build_sinks(&config)?;
    let event_log = Arc::new(EventPipeline::spawn(sinks, config.logging.queue_capacity));
    let emitter = EventEmitter::new(sensor_info, Arc::clone(&event_log));

    let (rules, report) = RuleSet::load_files(&config.rules.files);
    let (engine, compile_report) = build_engine(&config, &rules);
    log_coverage(&report, &compile_report);

    if args.strict {
        let problems = report.skipped.len() + compile_report.failed.len();
        if problems > 0 {
            event_log.shutdown();
            anyhow::bail!(
                "--strict: {problems} rule(s) failed to load or compile; \
                 run `cybersentinel validate-rules` for the detail"
            );
        }
    }

    let result = main_loop(
        args,
        &config,
        &emitter,
        &report,
        &compile_report,
        engine,
        &mut source,
    );

    // Always drain and flush, even if the run failed: queued events are
    // evidence.
    event_log.shutdown();
    tracing::info!("sensor stopped");
    result
}

fn open_source(args: &RunArgs, config: &Config) -> Result<Source> {
    if let Some(path) = &args.replay {
        let replay = PcapReplay::open(path)
            .with_context(|| format!("opening capture file {}", path.display()))?;
        tracing::info!(
            file = %path.display(),
            snaplen = replay.header().snaplen,
            "replaying capture file"
        );
        return Ok(Source::Replay(Box::new(replay)));
    }

    if !config.capture.enabled {
        return Ok(Source::None);
    }

    open_live(config)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_live(config: &Config) -> Result<Source> {
    use cybersentinel_capture::{LiveCapture, LiveOptions};

    let options = LiveOptions {
        interface: config.capture.interfaces.first().cloned(),
        snaplen: config.capture.snaplen,
        promiscuous: config.capture.promiscuous,
        bpf_filter: config.capture.bpf_filter.clone(),
        buffer_size_bytes: config.capture.buffer_size_bytes,
        ..LiveOptions::default()
    };

    let capture = LiveCapture::open(&options).context("opening live capture")?;
    Ok(Source::Live(Box::new(capture)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_live(_config: &Config) -> Result<Source> {
    anyhow::bail!(
        "capture.enabled is true, but live capture is not implemented on this platform yet \
         (Windows support lands in Phase 5). Use --replay to analyse a capture file."
    )
}

/// Drop capture privileges now that the handle is open.
///
/// Deliberately non-fatal: a monitoring tool that refuses to monitor is not the
/// safer outcome. The residual privilege is made loud instead.
fn drop_privileges() {
    let report = cybersentinel_capture::privileges::drop_after_capture_open();
    if report.is_overprivileged() {
        tracing::warn!(
            uid = report.uid,
            capabilities_dropped = report.capabilities_dropped,
            "running as root: capabilities were dropped, but uid 0 remains. Run under the \
             shipped systemd unit, which uses DynamicUser with only CAP_NET_RAW and \
             CAP_NET_ADMIN as ambient capabilities."
        );
    } else if report.supported && report.capabilities_dropped {
        tracing::info!(uid = report.uid, "capture privileges dropped");
    }
}

/// Compile the loaded rules into an engine.
pub fn build_engine(config: &Config, rules: &RuleSet) -> (Engine, CompileReport) {
    let vars = VarTable::new(
        config.vars.address_groups.clone(),
        config.vars.port_groups.clone(),
    );
    let limits = EngineLimits {
        compile: CompileLimits {
            regex_size_limit: config.detect.regex_size_limit,
            regex_dfa_size_limit: config.detect.regex_dfa_size_limit,
        },
        max_flow_states: config.detect.max_flow_states,
        max_flowbits_per_flow: config.detect.max_flowbits_per_flow,
        inspection_window: config.detect.inspection_window,
        max_threshold_entries: config.detect.max_threshold_entries,
    };
    Engine::new(rules.rules().iter(), &vars, limits)
}

/// Report rule coverage at startup, in buckets an operator can act on.
///
/// The distinction matters: "not implemented yet" is the project's problem,
/// "failed to compile" is the rule author's, and "skipped" means the file has a
/// line in it that is not a rule at all. Collapsing them into one number would
/// hide whichever one someone needs to fix.
fn log_coverage(load: &LoadReport, compile: &CompileReport) {
    tracing::info!(
        loaded = load.loaded,
        armed = compile.compiled,
        awaiting_support = compile.not_evaluable,
        failed_to_compile = compile.failed.len(),
        skipped = load.skipped.len(),
        "rule coverage"
    );

    for failure in &compile.failed {
        tracing::warn!(
            sid = failure.sid,
            rule = %failure.origin,
            reason = %failure.reason,
            "rule failed to compile and is NOT running"
        );
    }

    if compile.without_prefilter > 0 {
        tracing::debug!(
            count = compile.without_prefilter,
            "rule(s) have no pre-filter pattern and are evaluated on every packet"
        );
    }
    if compile.compiled == 0 {
        tracing::warn!("no rules are armed: the sensor will see traffic but detect nothing");
    }
}

#[allow(clippy::too_many_arguments)]
fn main_loop(
    args: &RunArgs,
    config: &Config,
    emitter: &EventEmitter,
    report: &LoadReport,
    compile_report: &CompileReport,
    engine: Engine,
    source: &mut Source,
) -> Result<()> {
    let started = Instant::now();
    let shutdown = install_signal_handler()?;
    // Seed the shared snapshot with what is already known, so the startup
    // heartbeat reports the real flow-table capacity rather than zero.
    let snapshot: SharedSnapshot = Arc::new(Mutex::new(PipelineSnapshot {
        source: source.name(),
        flow_capacity: config.flow.max_flows as u64,
        ..PipelineSnapshot::default()
    }));

    // A stats event at t=0 doubles as a startup heartbeat: a consumer sees the
    // sensor is alive without waiting a full interval.
    emit_stats(emitter, report, started, &snapshot);

    if args.once {
        return Ok(());
    }

    if source.as_packet_source().is_none() {
        return heartbeat_only(config, emitter, report, started, &snapshot, &shutdown);
    }
    let _ = compile_report;

    // Stats run on their own thread so a busy packet loop cannot delay them,
    // and so a quiet link still produces a heartbeat.
    let stats_thread = spawn_stats_thread(config, emitter, report, started, &snapshot, &shutdown);

    let outcome = run_packet_loop(
        config,
        emitter,
        source,
        &snapshot,
        &shutdown,
        args.dump_streams.as_ref(),
        engine,
        compile_report,
    );

    // Stop the stats thread and emit one final stats event with the closing
    // counters — in particular whether anything was dropped.
    shutdown.store(true, Ordering::Relaxed);
    if let Some(handle) = stats_thread {
        let _ = handle.join();
    }
    emit_stats(emitter, report, started, &snapshot);

    outcome
}

/// The packet loop. Runs on the main thread, which is the thread that opened
/// the capture handle and dropped privileges.
#[allow(clippy::too_many_arguments)]
fn run_packet_loop(
    config: &Config,
    emitter: &EventEmitter,
    source: &mut Source,
    snapshot: &SharedSnapshot,
    shutdown: &Arc<AtomicBool>,
    dump_streams: Option<&PathBuf>,
    engine: Engine,
    compile_report: &CompileReport,
) -> Result<()> {
    let mut pipeline = PacketPipeline::new(
        emitter.clone(),
        config,
        PipelineOptions {
            emit_anomaly_events: config.decode.emit_anomaly_events,
            emit_flow_events: config.flow.emit_events,
            dump_streams_to: dump_streams.cloned(),
        },
        source.name(),
    );
    if config.detect.enabled {
        pipeline.arm(engine, compile_report);
    }

    let Some(packets) = source.as_packet_source() else {
        return Ok(());
    };

    let mut seen = 0u64;
    let mut error = None;

    while !shutdown.load(Ordering::Relaxed) {
        match packets.next_packet() {
            Ok(Captured::Frame(frame)) => {
                pipeline.on_packet(&frame);
                seen += 1;
                if seen % PUBLISH_EVERY_PACKETS == 0 {
                    let counters = packets.counters();
                    pipeline.publish(snapshot, counters);
                }
            }
            // A quiet link, not a finished one: republish counters (drops
            // accumulate whether or not we are being handed packets), then wait
            // a moment so an idle link does not spin a core, and go round again
            // so the shutdown check runs.
            Ok(Captured::Idle) => {
                let counters = packets.counters();
                pipeline.publish(snapshot, counters);
                std::thread::sleep(IDLE_POLL);
            }
            Ok(Captured::End) => break,
            Err(source_error) => {
                tracing::error!(error = %source_error, "capture failed");
                error = Some(source_error);
                break;
            }
        }
    }

    // End every open flow so nothing is lost at the end of a capture.
    pipeline.flush();
    let counters = packets.counters();
    pipeline.publish(snapshot, counters);

    if counters.drops > 0 || counters.interface_drops > 0 {
        tracing::warn!(
            drops = counters.drops,
            interface_drops = counters.interface_drops,
            drop_rate = counters.drop_rate(),
            "packets were dropped before the sensor saw them: this is a coverage hole, \
             not a performance statistic. Raise capture.buffer-size-bytes."
        );
    }

    if let Source::Replay(replay) = source {
        if replay.is_truncated() {
            tracing::warn!(
                "the capture file ended mid-record: the analysis covers only part of it"
            );
            if let Ok(mut guard) = snapshot.lock() {
                guard.capture_truncated = true;
            }
        }
    }

    match error {
        Some(error) => Err(anyhow::Error::new(error).context("packet capture")),
        None => Ok(()),
    }
}

/// The no-capture path: emit `stats` on an interval until signalled.
fn heartbeat_only(
    config: &Config,
    emitter: &EventEmitter,
    report: &LoadReport,
    started: Instant,
    snapshot: &SharedSnapshot,
    shutdown: &Arc<AtomicBool>,
) -> Result<()> {
    if !config.stats.enabled {
        tracing::info!("stats events are disabled; running until signalled");
        while !shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(SHUTDOWN_POLL);
        }
        return Ok(());
    }

    let interval = Duration::from_secs(config.stats.interval_secs);
    while !sleep_until(interval, shutdown) {
        emit_stats(emitter, report, started, snapshot);
    }
    tracing::info!("shutdown signal received");
    emit_stats(emitter, report, started, snapshot);
    Ok(())
}

fn spawn_stats_thread(
    config: &Config,
    emitter: &EventEmitter,
    report: &LoadReport,
    started: Instant,
    snapshot: &SharedSnapshot,
    shutdown: &Arc<AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    if !config.stats.enabled {
        return None;
    }

    let interval = Duration::from_secs(config.stats.interval_secs);
    let emitter = emitter.clone();
    let report = report.clone();
    let snapshot = Arc::clone(snapshot);
    let shutdown = Arc::clone(shutdown);

    std::thread::Builder::new()
        .name("cybersentinel-stats".into())
        .spawn(move || {
            while !sleep_until(interval, &shutdown) {
                emit_stats(&emitter, &report, started, &snapshot);
            }
        })
        .map_err(|error| tracing::error!(%error, "could not start the stats thread"))
        .ok()
}

/// Sleep for `interval`, waking early if shutdown is signalled.
///
/// Returns `true` if it woke because of shutdown.
fn sleep_until(interval: Duration, shutdown: &AtomicBool) -> bool {
    let deadline = Instant::now() + interval;
    while Instant::now() < deadline {
        if shutdown.load(Ordering::Relaxed) {
            return true;
        }
        std::thread::sleep(SHUTDOWN_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
    shutdown.load(Ordering::Relaxed)
}

fn emit_stats(
    emitter: &EventEmitter,
    report: &LoadReport,
    started: Instant,
    snapshot: &SharedSnapshot,
) {
    let queue = emitter.pipeline().counters().snapshot();
    let pipeline = snapshot
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let capturing = !pipeline.source.is_empty();

    let stats = StatsEvent {
        uptime_secs: started.elapsed().as_secs(),
        events: EventStats {
            emitted: queue.emitted,
            dropped: queue.dropped,
            written: queue.written,
            write_errors: queue.write_errors,
            queued: queue.queued,
            queue_capacity: queue.capacity,
        },
        rules: RuleStats {
            loaded: report.loaded as u64,
            skipped: report.skipped.len() as u64,
            with_unsupported_options: report.non_evaluable() as u64,
        },
        capture: CaptureStats {
            enabled: capturing,
            source: capturing.then(|| pipeline.source.clone()),
            packets: pipeline.capture.packets,
            bytes: pipeline.capture.bytes,
            drops: pipeline.capture.drops,
            interface_drops: pipeline.capture.interface_drops,
            drop_rate: pipeline.capture.drop_rate(),
        },
        decode: DecodeStats {
            enabled: capturing,
            packets: pipeline.decode.packets,
            ipv4: pipeline.decode.ipv4,
            ipv6: pipeline.decode.ipv6,
            tcp: pipeline.decode.tcp,
            udp: pipeline.decode.udp,
            icmp: pipeline.decode.icmp,
            non_ip: pipeline.decode.non_ip,
            fragments: pipeline.decode.fragments,
            snapped: pipeline.decode.snapped,
            anomalous: pipeline.decode.anomalous,
            anomalies: pipeline.decode.anomalies,
        },
        flows: FlowStats {
            enabled: capturing,
            active: pipeline.active_flows,
            created: pipeline.flows.created,
            closed: pipeline.flows.closed,
            timed_out: pipeline.flows.timed_out,
            evicted: pipeline.flows.evicted,
            capacity: pipeline.flow_capacity,
        },
        reassembly: ReassemblyStats {
            enabled: capturing,
            fragments: pipeline.defrag.fragments,
            datagrams_reassembled: pipeline.defrag.completed,
            fragment_sets_active: pipeline.active_fragment_sets,
            fragment_timeouts: pipeline.defrag.timed_out,
            fragment_evictions: pipeline.defrag.evicted,
            fragment_conflicts: pipeline.defrag.conflicting_overlaps,
            stream_bytes_buffered: pipeline.stream_bytes_buffered,
            stream_bytes_delivered: pipeline.streams.bytes_delivered,
            stream_conflicts: pipeline.streams.conflicting_overlaps,
            stream_out_of_window: pipeline.streams.out_of_window,
            stream_after_fin: pipeline.streams.after_fin,
            stream_flushed_unacked: pipeline.streams.flushed_unacked,
            stream_dropped_incomplete: pipeline.streams.dropped_incomplete,
            resets_ignored: pipeline.flows.resets_ignored,
        },
        engine: EngineStats {
            enabled: capturing && pipeline.rules_armed > 0,
            rules_armed: pipeline.rules_armed,
            rules_awaiting_support: pipeline.rules_awaiting_support,
            rules_failed: pipeline.rules_failed,
            rules_without_prefilter: pipeline.rules_without_prefilter,
            inspections: pipeline.engine.inspections,
            bytes_inspected: pipeline.engine.bytes_inspected,
            candidates: pipeline.engine.candidates,
            matches: pipeline.engine.matches,
            alerts: pipeline.engine.alerts,
            thresholded: pipeline.engine.thresholded,
            silent: pipeline.engine.silent,
            flow_states: pipeline.engine.flow_states,
            flow_states_evicted: pipeline.engine.flow_states_evicted,
            inspection_bytes_dropped: pipeline.engine.inspection_bytes_dropped,
        },
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

/// Wire SIGINT/SIGTERM (Ctrl-C / service stop) to a flag.
///
/// A flag rather than a channel because two threads watch it — the packet loop
/// and the stats thread — and both must stop promptly. systemd and Windows
/// service control both expect a timely exit.
fn install_signal_handler() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    let handler_flag = Arc::clone(&flag);
    ctrlc::set_handler(move || {
        // Signal handlers must not block or allocate; a relaxed store is all
        // this needs. A second Ctrl-C during shutdown is intentionally ignored.
        handler_flag.store(true, Ordering::Relaxed);
    })
    .context("installing the shutdown signal handler")?;
    Ok(flag)
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
