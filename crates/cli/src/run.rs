//! The `run` subcommand: the sensor's main loop.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use cybersentinel_capture::{CaptureCounters, Captured, PacketSource, PcapReplay};
use cybersentinel_common::config::Config;
use cybersentinel_common::event::{
    CaptureStats, DecodeStats, EngineStats, EventStats, FlowStats, Payload, ReassemblyStats,
    RuleStats, StatsEvent,
};
use cybersentinel_common::eventlog::{EventEmitter, EventPipeline, EventSink};
use cybersentinel_common::sensor;
use cybersentinel_correlation::{CorrelationSettings, Correlator};
use cybersentinel_engine::CompileLimits;
use cybersentinel_engine::{CompileReport, Engine, EngineLimits, VarTable};
use cybersentinel_hids::fim::FimSettings;
use cybersentinel_hids::process::ScanLimits;
use cybersentinel_hids::sensor::{HostSensor, HostSettings};
use cybersentinel_prevent::{FailMode, Mode, Prevention, PreventionSettings};
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

/// How long the host-only loop waits between polls.
///
/// Longer than [`IDLE_POLL`] because host events are not packets: there is no
/// per-microsecond arrival to keep up with, and a sensor that spins a core on
/// an idle host is a sensor an operator uninstalls.
const HOST_POLL: Duration = Duration::from_millis(200);

/// How long shutdown waits for the host sensors to hand over what they found.
const HOST_DRAIN: Duration = Duration::from_secs(5);

/// The one capability host monitoring keeps.
///
/// `CAP_DAC_READ_SEARCH` bypasses file-read and directory-search permission
/// checks, which is exactly what hashing `/etc/shadow` and reading
/// `/var/log/secure` need — and nothing more. Notably **not**
/// `CAP_SYS_PTRACE`: attributing a listening socket to another user's process
/// would need it, and the price is the ability to ptrace anything on the box.
/// A sensor holding that is a sensor worth compromising.
#[cfg(target_os = "linux")]
const HOST_READ_CAPABILITY: caps::Capability = caps::Capability::CAP_DAC_READ_SEARCH;
#[cfg(not(target_os = "linux"))]
const HOST_READ_CAPABILITY: cybersentinel_capture::privileges::Capability =
    cybersentinel_capture::privileges::Capability::CapDacReadSearch;

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

    // The netfilter queue is bound here, next to the capture handle and for
    // exactly the same reason: it needs CAP_NET_ADMIN, and the whole point of
    // the drop below is that nothing afterwards has it. Binding it later —
    // which is where it naturally wanted to live, beside the rest of the
    // prevention setup — meant `bind` returned EPERM on a correctly configured
    // system and the sensor degraded to detect-only. Loudly, but still.
    let queue = bind_verdict_queue(&config);

    if matches!(source, Source::None) && queue.is_none() {
        tracing::info!("no capture source configured; running as a heartbeat only");
    } else {
        drop_privileges(&config);
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
        queue,
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
/// The network path needs nothing after the handle exists, so it keeps nothing.
/// Host monitoring is different: it goes on reading and hashing files it does
/// not own for as long as it runs, so `CAP_DAC_READ_SEARCH` is **retained**
/// when it is enabled. That is the smallest set that lets FIM hash
/// `/etc/shadow` and the log reader follow `/var/log/secure`; everything else
/// still goes. `CLAUDE.md` documents the full set and the reasoning.
///
/// Deliberately non-fatal: a monitoring tool that refuses to monitor is not the
/// safer outcome. The residual privilege is made loud instead.
fn drop_privileges(config: &Config) {
    let mut retain = Vec::new();
    if config.hids.enabled {
        retain.push(HOST_READ_CAPABILITY);
    }
    // Inline prevention needs CAP_NET_ADMIN for the process's whole life, not
    // just to bind the queue. Setting a verdict is a netlink *send*, and that
    // send is privileged: without the capability the kernel refuses it and
    // reports the refusal asynchronously, so the next `recv` returns EPERM and
    // the verdict path stops. Binding early is necessary and not sufficient.
    //
    // Measured, not reasoned about: with the capability dropped, the sensor
    // judged exactly one packet, the thread exited, the kernel fell back to the
    // fail mode, and nothing said the sensor had stopped enforcing.
    #[cfg(target_os = "linux")]
    if config.prevent.enabled {
        retain.push(caps::Capability::CAP_NET_ADMIN);
    }

    let report = if retain.is_empty() {
        cybersentinel_capture::privileges::drop_after_capture_open()
    } else {
        cybersentinel_capture::privileges::drop_after_capture_open_retaining(&retain)
    };

    if report.is_overprivileged() {
        tracing::warn!(
            uid = report.uid,
            capabilities_dropped = report.capabilities_dropped,
            retained = report.retained,
            "running as root: capabilities were narrowed, but uid 0 remains. Run under the \
             shipped systemd unit, which uses a dedicated user with only the ambient \
             capabilities documented in CLAUDE.md."
        );
    } else if report.supported && report.capabilities_dropped {
        tracing::info!(
            uid = report.uid,
            retained = report.retained,
            "capture privileges dropped"
        );
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
        normalize: cybersentinel_reassembly::normalize::NormalizeOptions {
            decode_rounds: config.normalize.decode_rounds,
            collapse_path: config.normalize.collapse_path,
            backslash_is_separator: config.normalize.backslash_is_separator,
        },
        ..EngineLimits::default()
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

/// Translate the `hids` config section into sensor settings.
///
/// Returns `None` when host monitoring is switched off entirely, so the caller
/// never starts a sensor that would do nothing.
fn host_settings(config: &Config) -> Option<HostSettings> {
    if !config.hids.enabled {
        return None;
    }
    let fim = config.hids.fim.enabled.then(|| FimSettings {
        paths: config.hids.fim.paths.clone(),
        baseline_path: Some(config.hids.fim.baseline.clone()),
        rescan_interval: Duration::from_secs(config.hids.fim.rescan_interval_secs),
        max_file_bytes: config.hids.fim.max_file_bytes,
        max_depth: config.hids.fim.max_depth,
        max_entries: config.hids.fim.max_entries,
    });

    let settings = HostSettings {
        fim,
        auth_files: if config.hids.auth.enabled {
            config.hids.auth.files.clone()
        } else {
            Vec::new()
        },
        journald: config.hids.auth.enabled && config.hids.auth.journald,
        proc_root: config.hids.process.proc_root.clone(),
        process_monitoring: config.hids.process.enabled,
        process_interval: Duration::from_secs(config.hids.process.interval_secs),
        process_limits: ScanLimits {
            max_processes: config.hids.process.max_processes,
            max_sockets: config.hids.process.max_sockets,
        },
    };

    // Every sensor off is the same as host monitoring off, and starting one
    // would advertise coverage that does not exist.
    let anything_enabled = settings.fim.is_some()
        || !settings.auth_files.is_empty()
        || settings.journald
        || settings.process_monitoring;
    anything_enabled.then_some(settings)
}

/// Build inline prevention from the config, and start the verdict path.
///
/// Returns the shared store so the detection path can record verdicts into it.
/// `None` means prevention is switched off entirely, which is the default and
/// leaves the sensor behaving exactly as an IDS.
///
/// The nftables rule is **logged, not applied**. Taking a machine's traffic
/// into userspace is not something a sensor should do to an operator by
/// surprise on first start, and an inline rule installed wrongly is an outage.
fn start_prevention(config: &Config) -> Option<Arc<Mutex<Prevention>>> {
    if !config.prevent.enabled {
        return None;
    }

    let mode = if config.prevent.mode == "prevent" {
        Mode::Prevent
    } else {
        Mode::Detect
    };
    let fail_mode = if config.prevent.fail_mode == "closed" {
        FailMode::Closed
    } else {
        FailMode::Open
    };
    let allow_list: Vec<_> = config
        .prevent
        .allow_list
        .iter()
        .filter_map(|entry| entry.parse().ok())
        .collect();

    let prevention = Arc::new(Mutex::new(Prevention::new(PreventionSettings {
        mode,
        fail_mode,
        allow_list,
        source_block: Duration::from_secs(config.prevent.source_block_secs),
        max_blocked_flows: config.prevent.max_blocked_flows,
        max_blocked_sources: config.prevent.max_blocked_sources,
    })));

    // Both of these are load-bearing and easy to get wrong by hand, so the
    // sensor says exactly what it expects rather than leaving an operator to
    // infer it. A `fail-mode: open` config with a rule that lacks `bypass` is
    // fail-closed in practice, and nobody finds that out until an outage.
    tracing::warn!(
        mode = mode.as_str(),
        fail_mode = fail_mode.as_str(),
        queue = config.prevent.queue,
        allow_list = config.prevent.allow_list.len(),
        "inline prevention is enabled"
    );
    if mode == Mode::Prevent {
        tracing::warn!(
            "ARMED: matching traffic will be DROPPED. Set prevent.mode to `detect` to disarm."
        );
    } else {
        tracing::info!("prevention is in detect mode: rules that ask to block will only alert");
    }
    tracing::info!(
        "the queueing rule this sensor expects (apply it yourself; it is not applied for you):\n{}",
        cybersentinel_prevent::nft::queue_rule(config.prevent.queue, fail_mode)
    );

    Some(prevention)
}

/// Bind the netfilter queue, while the process still has `CAP_NET_ADMIN`.
///
/// Called beside `open_source` and before `drop_privileges`, which is the only
/// place it can go: capabilities are dropped once, early, while the process is
/// single-threaded, and everything after that runs without them.
#[cfg(target_os = "linux")]
fn bind_verdict_queue(config: &Config) -> Option<cybersentinel_prevent::queue::KernelQueue> {
    use cybersentinel_prevent::queue::KernelQueue;

    if !config.prevent.enabled {
        return None;
    }
    match KernelQueue::bind(config.prevent.queue) {
        Ok(mut queue) => {
            if let Err(error) =
                queue.set_queue_length(config.prevent.queue, config.prevent.queue_length)
            {
                tracing::warn!(%error, "could not set the queue length; the kernel default applies");
            }
            Some(queue)
        }
        Err(error) => {
            // Not fatal. Detection continues; what is lost is enforcement, and
            // it is lost loudly rather than by a sensor that looks armed.
            tracing::error!(
                %error,
                queue = config.prevent.queue,
                "could not bind the netfilter queue; the sensor will DETECT BUT NOT PREVENT \
                 (CAP_NET_ADMIN is required, and the queue must not already be bound)"
            );
            None
        }
    }
}

/// Bind the netfilter queue. Linux-only.
#[cfg(not(target_os = "linux"))]
fn bind_verdict_queue(_config: &Config) -> Option<()> {
    None
}

/// Run the verdict path on its own thread.
///
/// Its own thread because it must answer the kernel promptly and cannot be
/// behind a packet-capture poll or a FIM scan. It holds the lock only for the
/// duration of a hash lookup.
#[cfg(target_os = "linux")]
fn spawn_verdict_thread(
    mut queue: cybersentinel_prevent::queue::KernelQueue,
    prevention: Arc<Mutex<Prevention>>,
    shutdown: Arc<AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    use cybersentinel_prevent::queue::{judge, VerdictSource};

    let queue_number = 0_u16;
    std::thread::Builder::new()
        .name("cybersentinel-verdict".to_string())
        .spawn(move || {
            tracing::info!(queue = queue_number, "verdict path running");
            while !shutdown.load(Ordering::Relaxed) {
                let Some(packet) = queue.next_packet() else {
                    break;
                };
                let decision = {
                    let Ok(mut store) = prevention.lock() else {
                        break;
                    };
                    judge(&mut store, &packet, std::time::Instant::now())
                };
                queue.resolve(packet, decision);
            }
            // A stopped verdict path means the kernel's fail mode is now
            // deciding for every packet on this queue. That is a change in what
            // the machine does to traffic, so it is an error, not an info line.
            match queue.fatal.take() {
                Some(error) => tracing::error!(
                    %error,
                    retries = queue.retries,
                    "the verdict path STOPPED: the kernel's fail mode now applies to every packet"
                ),
                None => tracing::info!(
                    retries = queue.retries,
                    "verdict path stopped; the kernel now applies the configured fail mode"
                ),
            }
        })
        .ok()
}

/// Attach host monitoring to the pipeline, if it is configured.
///
/// A host sensor that cannot start is reported and skipped rather than fatal:
/// the network half of the sensor still works, and half a sensor beats none.
fn attach_host_monitoring(config: &Config, pipeline: &mut PacketPipeline) {
    let Some(settings) = host_settings(config) else {
        tracing::info!("host monitoring is disabled");
        return;
    };

    let correlator = config.correlation.enabled.then(|| {
        Correlator::new(CorrelationSettings {
            window: Duration::from_secs(config.correlation.window_secs),
            cooldown: Duration::from_secs(config.correlation.cooldown_secs),
            max_hosts: config.correlation.max_hosts,
            max_per_host: config.correlation.max_per_host,
        })
    });

    match HostSensor::start(settings) {
        Ok(sensor) => {
            let stats = sensor.stats();
            tracing::info!(
                watched_paths = stats.watched_paths,
                watch_failures = stats.watch_failures,
                baseline_entries = stats.baseline_entries,
                correlation = correlator.is_some(),
                "host monitoring started"
            );
            if stats.watch_failures > 0 {
                tracing::warn!(
                    watch_failures = stats.watch_failures,
                    "some paths could not be watched in real time; they are covered by the \
                     periodic baseline rescan only"
                );
            }
            pipeline.attach_host(sensor, correlator);
        }
        Err(error) => tracing::error!(
            error = %error,
            "host monitoring could not start; the network sensor continues without it"
        ),
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
    #[cfg(target_os = "linux")] queue: Option<cybersentinel_prevent::queue::KernelQueue>,
    #[cfg(not(target_os = "linux"))] queue: Option<()>,
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

    // The pipeline is built here rather than inside the packet loop because
    // host monitoring runs whether or not there is a capture source: a
    // HIDS-only install is a supported deployment, not a degraded one.
    let mut pipeline = PacketPipeline::new(
        emitter.clone(),
        config,
        PipelineOptions {
            emit_anomaly_events: config.decode.emit_anomaly_events,
            emit_flow_events: config.flow.emit_events,
            dump_streams_to: args.dump_streams.clone(),
        },
        source.name(),
    );
    if config.detect.enabled {
        pipeline.arm(engine, compile_report);
    }
    attach_host_monitoring(config, &mut pipeline);

    // Inline prevention, if it is configured. The verdict thread runs whether
    // or not there is a capture source: a machine can be inline without the
    // sensor also sniffing it.
    let prevention = start_prevention(config);
    #[cfg(target_os = "linux")]
    let verdict_thread = match (queue, prevention.as_ref()) {
        (Some(queue), Some(store)) => {
            spawn_verdict_thread(queue, Arc::clone(store), Arc::clone(&shutdown))
        }
        _ => None,
    };
    #[cfg(not(target_os = "linux"))]
    let _ = queue;
    if let Some(store) = prevention.as_ref() {
        pipeline.arm_prevention(Arc::clone(store));
    }

    // Publish before the first stats event so the startup heartbeat reports the
    // real baseline and watch counts rather than zeroes.
    pipeline.publish(&snapshot, CaptureCounters::default());

    // A stats event at t=0 doubles as a startup heartbeat: a consumer sees the
    // sensor is alive without waiting a full interval.
    emit_stats(emitter, report, started, &snapshot);

    if args.once {
        return Ok(());
    }

    // Stats run on their own thread so a busy packet loop cannot delay them,
    // and so a quiet link still produces a heartbeat.
    let stats_thread = spawn_stats_thread(config, emitter, report, started, &snapshot, &shutdown);

    let mut outcome = if source.as_packet_source().is_some() {
        run_packet_loop(source, &snapshot, &shutdown, &mut pipeline)
    } else {
        host_only_loop(&snapshot, &shutdown, &mut pipeline)
    };

    // A capture file ending is not a reason to stop enforcing. The verdict
    // path is still bound to the kernel's queue and still holding traffic;
    // exiting here would hand every packet to the fail mode because a replay
    // finished. Keep going until signalled, the same as any other inline run.
    #[cfg(target_os = "linux")]
    let enforcing = verdict_thread.is_some();
    #[cfg(not(target_os = "linux"))]
    let enforcing = false;
    // Only when a queue is actually being served. `prevent.enabled` with no
    // bound queue enforces nothing, and a `--replay` run that never exits
    // because of a config flag would be a surprise with no upside.
    if outcome.is_ok() && enforcing && !shutdown.load(Ordering::Relaxed) {
        tracing::info!(
            "the capture source is finished, but prevention is active: \
             staying up to keep enforcing"
        );
        outcome = host_only_loop(&snapshot, &shutdown, &mut pipeline);
    }

    // Stop the stats thread and emit one final stats event with the closing
    // counters — in particular whether anything was dropped.
    shutdown.store(true, Ordering::Relaxed);
    #[cfg(target_os = "linux")]
    if verdict_thread.is_some() {
        // Deliberately not joined. The verdict thread blocks in `recv` waiting
        // for a packet that may never come on a quiet link, and holding
        // shutdown open for it would make the sensor look wedged. Letting the
        // process exit hands the queue back to the kernel, which then applies
        // the configured fail mode — which is exactly the intended behaviour.
        tracing::info!("leaving the verdict path to the kernel's fail mode");
    }
    if let Some(handle) = stats_thread {
        let _ = handle.join();
    }
    emit_stats(emitter, report, started, &snapshot);

    outcome
}

/// The host-only loop: no capture source, but a host to watch.
///
/// A sensor installed for FIM and authentication monitoring alone is a normal
/// deployment — a database server with no span port still wants to know when
/// `/etc/shadow` changes — so this path is a first-class loop rather than the
/// old bare heartbeat.
fn host_only_loop(
    snapshot: &SharedSnapshot,
    shutdown: &Arc<AtomicBool>,
    pipeline: &mut PacketPipeline,
) -> Result<()> {
    if !pipeline.has_host() {
        tracing::info!("no capture source and no host monitoring: running as a heartbeat only");
    }
    while !shutdown.load(Ordering::Relaxed) {
        pipeline.service_host();
        pipeline.publish(snapshot, CaptureCounters::default());
        std::thread::sleep(HOST_POLL);
    }
    pipeline.drain_host(HOST_DRAIN);
    pipeline.publish(snapshot, CaptureCounters::default());
    tracing::info!("shutdown signal received");
    Ok(())
}

/// The packet loop. Runs on the main thread, which is the thread that opened
/// the capture handle and dropped privileges.
fn run_packet_loop(
    source: &mut Source,
    snapshot: &SharedSnapshot,
    shutdown: &Arc<AtomicBool>,
    pipeline: &mut PacketPipeline,
) -> Result<()> {
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
                    // A saturated link must not starve host monitoring, so it
                    // is serviced on the same cadence as counter publication.
                    pipeline.service_host();
                    let counters = packets.counters();
                    pipeline.publish(snapshot, counters);
                }
            }
            // A quiet link, not a finished one: republish counters (drops
            // accumulate whether or not we are being handed packets), then wait
            // a moment so an idle link does not spin a core, and go round again
            // so the shutdown check runs.
            Ok(Captured::Idle) => {
                // A quiet link is exactly when the host sensors get serviced:
                // no packet is waiting, so nothing is delayed by doing it here.
                pipeline.service_host();
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

    // End every open flow so nothing is lost at the end of a capture, and give
    // the host sensors the same courtesy.
    pipeline.flush();
    pipeline.drain_host(HOST_DRAIN);
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
        hids: pipeline.hids.clone(),
        prevent: pipeline.prevent.clone(),
        correlation: pipeline.correlation.clone(),
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
