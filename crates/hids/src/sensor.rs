//! The host sensor runtime: one polled call driving FIM, auth logs, and
//! process monitoring.
//!
//! The network side is driven by packets arriving. The host side has no such
//! clock — file changes arrive on a channel, log lines arrive when a service
//! writes one, and process monitoring is a sweep on a timer. [`HostSensor`]
//! reconciles that into a single non-blocking [`HostSensor::poll`] the CLI's
//! run loop calls alongside the capture poll, so there is one shutdown path,
//! one stats snapshot, and one place where host events enter the pipeline.
//!
//! # FIM runs on its own thread, and that is not an optimisation
//!
//! Establishing a baseline over `/etc` and `/usr/bin` means hashing tens of
//! thousands of files. Doing that on the caller's thread would stall packet
//! capture for as long as it takes — dropping traffic, on a sensor whose whole
//! job is not to miss things — and would make startup appear to hang. So
//! [`FimWorker`] owns the baseline and the watcher on a dedicated thread and
//! hands finished events back over a bounded channel. The poll then costs one
//! `try_recv` whether the baseline is idle or mid-scan.
//!
//! Auth logs and `/proc` stay inline: both are bounded, fast reads, and neither
//! can take longer than the poll interval.
//!
//! # inotify overflow is a first-class event, not an error
//!
//! The kernel's inotify queue is bounded. Fill it faster than we drain it and
//! it drops events and raises `IN_Q_OVERFLOW` — which `notify` surfaces as an
//! event carrying [`notify::event::Flag::Rescan`]. An attacker who wants a file
//! change to go unnoticed only has to touch enough other files first.
//!
//! So overflow is handled three ways at once, and it is the combination that
//! matters:
//!
//! 1. It **forces an immediate rescan**, so the change that was dropped is
//!    still found by comparing hashes against the baseline.
//! 2. It is **reported** — the batch carries the overflow count so the caller
//!    emits it as its own event, and the gap is visible in the event stream
//!    rather than inferred from an absence.
//! 3. It is **counted** in [`HidsStats::inotify_overflows`], so a host that
//!    overflows repeatedly shows up as a coverage problem.
//!
//! A silently missed change must never be indistinguishable from an unchanged
//! filesystem.

use crate::fim::{self, FimSettings};
use crate::logs::{self, Tailer};
use crate::process::{self, ScanLimits};
use crate::sources::{self, names, SourceRegistry};
use crate::HostError;
use cybersentinel_common::event::{AuthEvent, FimDetection, FimEvent, HidsStats, ProcessEvent};
use notify::{RecursiveMode, Watcher as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How many pending notifications, log lines, and updates are held before
/// dropping.
///
/// Bounded like every other queue in the sensor: back-pressure that blocks the
/// watcher thread would be worse than a counted drop, and unbounded growth
/// would be worse than both.
const CHANNEL_DEPTH: usize = 4_096;
/// Most real-time notifications turned into events in one worker tick.
///
/// Keeps a burst of file activity from monopolising the worker; the rest is
/// picked up on the next tick, or by the rescan.
const MAX_NOTIFICATIONS_PER_TICK: usize = 512;
/// Most log lines parsed in one poll.
const MAX_LOG_LINES_PER_POLL: usize = 1_024;
/// How long the FIM worker waits between ticks.
const FIM_TICK: Duration = Duration::from_millis(100);
/// Default gap between `/proc` sweeps.
pub const DEFAULT_PROCESS_INTERVAL: Duration = Duration::from_secs(5);

/// What the host sensors should do.
#[derive(Debug, Clone)]
pub struct HostSettings {
    /// File integrity monitoring, or `None` to leave it off.
    pub fim: Option<FimSettings>,
    /// Authentication log files to follow.
    pub auth_files: Vec<PathBuf>,
    /// Whether to read journald, via `journalctl`.
    pub journald: bool,
    /// Where `/proc` is. Overridable so the whole module is testable.
    pub proc_root: PathBuf,
    /// Whether to sweep processes at all.
    pub process_monitoring: bool,
    /// Gap between `/proc` sweeps.
    pub process_interval: Duration,
    /// Bounds on a `/proc` sweep.
    pub process_limits: ScanLimits,
}

impl Default for HostSettings {
    fn default() -> Self {
        Self {
            fim: None,
            auth_files: Vec::new(),
            journald: false,
            proc_root: PathBuf::from("/proc"),
            process_monitoring: false,
            process_interval: DEFAULT_PROCESS_INTERVAL,
            process_limits: ScanLimits::default(),
        }
    }
}

/// Everything one poll produced.
#[derive(Debug, Default)]
pub struct HostBatch {
    /// File changes, real-time and rescan alike.
    pub fim: Vec<FimEvent>,
    /// Authentication records.
    pub auth: Vec<AuthEvent>,
    /// Process starts and new listening sockets.
    pub process: Vec<ProcessEvent>,
    /// Queue overflows seen this poll, each of which forced a rescan.
    ///
    /// Reported separately from the events it produced, because "we lost
    /// events here" is itself the finding.
    pub overflows: u64,
}

impl HostBatch {
    /// Whether the poll found anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fim.is_empty() && self.auth.is_empty() && self.process.is_empty()
    }
}

// ---------------------------------------------------------------------------
// the FIM worker
// ---------------------------------------------------------------------------

/// What FIM has done so far.
#[derive(Debug, Clone, Copy, Default)]
pub struct FimCounters {
    /// Paths successfully watched in real time.
    pub watched_paths: u64,
    /// Watches that could not be established, or that were lost.
    pub watch_failures: u64,
    /// Changes the kernel reported as they happened.
    pub realtime: u64,
    /// Changes found by the baseline comparison.
    pub rescan: u64,
    /// Queue overflows seen.
    pub overflows: u64,
    /// Rescans completed.
    pub rescans: u64,
    /// Files in the baseline.
    pub baseline_entries: u64,
}

/// One tick's worth of FIM findings.
#[derive(Debug, Default)]
pub struct FimUpdate {
    /// The changes found.
    pub events: Vec<FimEvent>,
    /// Overflows seen this tick.
    pub overflows: u64,
    /// Counters as of this tick.
    pub counters: FimCounters,
}

/// Owns the baseline and the real-time watcher.
///
/// Public so its behaviour — particularly the overflow path — can be exercised
/// directly. Inducing a real `IN_Q_OVERFLOW` in a test would mean outrunning
/// the kernel's queue, which is neither reliable nor fast.
#[allow(missing_debug_implementations)] // `notify::Watcher` is not `Debug`.
pub struct FimWorker {
    monitor: fim::Monitor,
    /// Kept alive for as long as we want notifications; dropping it stops them.
    _watcher: Option<Box<dyn notify::Watcher + Send>>,
    notifications: Option<Receiver<notify::Result<notify::Event>>>,
    rescan_interval: Duration,
    next_rescan: Option<Instant>,
    /// Cleared when the sensor is shutting down, so a long scan can be
    /// abandoned rather than held to.
    running: Arc<AtomicBool>,
    /// Set when a gap is detected, cleared when the forced rescan runs.
    ///
    /// Held on the worker rather than passed along the call stack so that an
    /// overflow noticed at any point is guaranteed to reach a rescan, even if
    /// the tick that noticed it is interrupted.
    overflow_pending: bool,
    counters: FimCounters,
}

impl FimWorker {
    /// Open the baseline and attach the watcher.
    ///
    /// Deliberately does **no** scanning: the first [`Self::tick`] does that,
    /// on whatever thread the worker is running on.
    pub fn start(settings: &FimSettings) -> Result<Self, HostError> {
        // Resolve the roots ONCE, and use the result for both the baseline and
        // the watcher. They must agree about what is being monitored: the
        // walker will not follow a symlinked root and `notify` will, and that
        // disagreement makes every file under such a root flip between
        // `created` and `deleted` for ever. See `fim::resolve_roots`.
        let (paths, collapsed) = fim::resolve_roots(&settings.paths);
        for (asked, kept) in &collapsed {
            tracing::info!(
                configured = %asked.display(),
                monitored = %kept.display(),
                "two configured paths name the same directory; monitoring it once"
            );
        }
        let settings = &FimSettings {
            paths,
            ..settings.clone()
        };

        let baseline = fim::Baseline::open(settings.baseline_path.as_deref())?;
        let mut worker = Self {
            monitor: fim::Monitor::new(settings.clone(), baseline),
            _watcher: None,
            notifications: None,
            rescan_interval: settings.rescan_interval,
            // `None` means "scan on the first tick". That first scan is what
            // catches changes made while the sensor was down, by comparing
            // against what was stored last time rather than against whatever
            // the watcher happens to see from now on.
            next_rescan: None,
            running: Arc::new(AtomicBool::new(true)),
            overflow_pending: false,
            counters: FimCounters::default(),
        };
        worker.install_watcher(settings);
        Ok(worker)
    }

    /// The counters so far.
    #[must_use]
    pub fn counters(&self) -> FimCounters {
        self.counters
    }

    /// The flag that keeps a scan going. Clearing it abandons the current one.
    #[must_use]
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Attach the real-time watcher, counting rather than failing on the paths
    /// it cannot take.
    fn install_watcher(&mut self, settings: &FimSettings) {
        let (sender, receiver) = std::sync::mpsc::sync_channel(CHANNEL_DEPTH);
        let forwarder = move |event| {
            // A full channel means we are behind. Dropping is the right answer
            // — blocking here would stall the watcher thread and make the
            // kernel queue overflow, which is strictly worse — and the rescan
            // is the backstop that makes the drop recoverable.
            let _ = SyncSender::try_send(&sender, event);
        };

        let mut watcher = match notify::recommended_watcher(forwarder) {
            Ok(watcher) => watcher,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "real-time file watching unavailable; the periodic rescan still runs"
                );
                self.counters.watch_failures += 1;
                return;
            }
        };

        for path in &settings.paths {
            match watcher.watch(path, RecursiveMode::Recursive) {
                Ok(()) => self.counters.watched_paths += 1,
                Err(error) => {
                    // The usual causes are a missing path or an exhausted
                    // `max_user_watches`. Neither is fatal, and both must be
                    // visible: an unwatched path is a coverage gap, not a clean
                    // bill of health.
                    tracing::warn!(
                        path = %path.display(),
                        error = %error,
                        "could not watch path; it is covered by the periodic rescan only"
                    );
                    self.counters.watch_failures += 1;
                }
            }
        }

        self._watcher = Some(Box::new(watcher));
        self.notifications = Some(receiver);
    }

    /// Do one round of FIM work.
    pub fn tick(&mut self, now: Instant) -> FimUpdate {
        let mut update = FimUpdate::default();

        for _ in 0..MAX_NOTIFICATIONS_PER_TICK {
            let Some(receiver) = self.notifications.as_ref() else {
                break;
            };
            match receiver.try_recv() {
                Ok(notification) => {
                    let (events, _) = self.handle_notification(notification);
                    update.events.extend(events);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // The watcher thread is gone. Rescans continue, but the
                    // loss of real-time coverage must not be silent.
                    tracing::warn!("file watcher stopped; falling back to periodic rescan only");
                    self.counters.watch_failures += 1;
                    // Losing the watcher is losing real-time coverage, so it
                    // gets the same treatment as an overflow: rescan now.
                    self.overflow_pending = true;
                    self.notifications = None;
                    self._watcher = None;
                    break;
                }
            }
        }

        let forced = std::mem::take(&mut self.overflow_pending);
        let due = self.next_rescan.is_none_or(|next| now >= next);
        if forced || due {
            update.events.extend(self.rescan());
            self.next_rescan = Some(now + self.rescan_interval);
        }
        if forced {
            update.overflows += 1;
        }

        update.counters = self.counters;
        update
    }

    /// Turn one notification into events, and say whether it was an overflow.
    pub fn handle_notification(
        &mut self,
        notification: notify::Result<notify::Event>,
    ) -> (Vec<FimEvent>, bool) {
        let event = match notification {
            Ok(event) => event,
            Err(error) => {
                // notify reports queue overflow as an error on some backends
                // and as a rescan flag on others. Both must reach the same
                // handler, or the platform decides whether we notice.
                tracing::warn!(error = %error, "file watcher error");
                self.counters.watch_failures += 1;
                self.overflow_pending = true;
                return (Vec::new(), true);
            }
        };

        if event.need_rescan() {
            tracing::warn!(
                "file watch queue overflowed; changes were dropped — forcing a baseline rescan"
            );
            self.counters.overflows += 1;
            self.overflow_pending = true;
            return (Vec::new(), true);
        }

        // Whatever the notification claims happened, the baseline decides. A
        // notification is a hint about *where* to look, never about *what*
        // changed — the hashes settle that.
        let mut events = Vec::new();
        for path in &event.paths {
            match self.monitor.recheck(path) {
                Ok(Some(event)) => events.push(event),
                Ok(None) => {}
                Err(error) => tracing::warn!(error = %error, "rechecking a changed path"),
            }
        }
        self.counters.realtime += events.len() as u64;
        (events, false)
    }

    /// Run a baseline comparison now, abandoning it if asked to stop.
    pub fn rescan(&mut self) -> Vec<FimEvent> {
        let running = Arc::clone(&self.running);
        let mut should_continue = move || running.load(Ordering::Relaxed);
        match self
            .monitor
            .rescan_until(FimDetection::BaselineRescan, &mut should_continue)
        {
            Ok(outcome) => {
                self.counters.rescans += 1;
                self.counters.rescan += outcome.events.len() as u64;
                self.counters.baseline_entries = self.monitor.baseline().len().unwrap_or(0);
                outcome.events
            }
            Err(error) => {
                tracing::error!(error = %error, "baseline rescan failed");
                Vec::new()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// the sensor
// ---------------------------------------------------------------------------

/// The polled host runtime.
pub struct HostSensor {
    settings: HostSettings,
    /// Findings from the FIM worker thread.
    fim_updates: Option<Receiver<FimUpdate>>,
    fim_thread: Option<std::thread::JoinHandle<()>>,
    fim_shutdown: Arc<AtomicBool>,
    /// Cleared on shutdown to abandon an in-flight baseline scan.
    fim_running: Arc<AtomicBool>,
    fim_counters: FimCounters,
    tailers: Vec<Tailer>,
    journal: Option<JournalReader>,
    processes: Option<process::Watcher>,
    next_sweep: Instant,
    /// What each source is doing, and whether it is doing anything.
    sources: SourceRegistry,
    stats: HidsStats,
}

impl std::fmt::Debug for HostSensor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostSensor")
            .field("settings", &self.settings)
            .field("fim", &self.fim_thread.is_some())
            .field("tailers", &self.tailers.len())
            .field("journald", &self.journal.is_some())
            .field("process_monitoring", &self.processes.is_some())
            .field("stats", &self.stats)
            .finish()
    }
}

impl HostSensor {
    /// Start the host sensors.
    ///
    /// A sensor that cannot fully start is still started. If the real-time
    /// watcher fails — `max_user_watches` exhausted, a path that does not
    /// exist — FIM continues with the periodic rescan alone and the failure is
    /// counted in [`HidsStats::watch_failures`]. Refusing to run because one of
    /// three sensors is degraded would trade partial visibility for none.
    ///
    /// Returns as soon as the watcher is attached. The baseline scan happens on
    /// the FIM thread, so a sensor watching `/usr/bin` starts immediately
    /// rather than after several thousand files have been hashed.
    pub fn start(settings: HostSettings) -> Result<Self, HostError> {
        let mut sensor = Self {
            fim_updates: None,
            fim_thread: None,
            fim_shutdown: Arc::new(AtomicBool::new(false)),
            fim_running: Arc::new(AtomicBool::new(true)),
            fim_counters: FimCounters::default(),
            tailers: settings.auth_files.iter().map(Tailer::new).collect(),
            journal: None,
            // Linux-only, and gated rather than left to fail quietly. The
            // `/proc` reader is ordinary file I/O, so on Windows it would
            // construct happily, find nothing, and report zero events — while
            // the source registry said "unsupported". Two answers to the same
            // question is worse than one wrong one.
            processes: (cfg!(target_os = "linux") && settings.process_monitoring).then(|| {
                process::Watcher::new(settings.proc_root.clone(), settings.process_limits)
            }),
            next_sweep: Instant::now(),
            sources: SourceRegistry::new(),
            stats: HidsStats {
                enabled: true,
                ..HidsStats::default()
            },
            settings,
        };

        // Declare this platform's gaps first, so a backend that exists can
        // overwrite its entry below. Whatever is left saying `unsupported` is
        // genuinely unsupported — and says so, rather than reporting zeroes.
        sources::declare_platform_gaps(&mut sensor.sources);

        if let Some(fim_settings) = sensor.settings.fim.clone() {
            sensor.spawn_fim(&fim_settings)?;
        }

        // journald is Linux. Attempting it elsewhere would replace the
        // registry's accurate "the Event Log backend arrives in Phase 5" with a
        // misleading "journalctl could not be spawned" — both are holes, but
        // only one tells an operator what is actually going on.
        if sensor.settings.journald && cfg!(target_os = "linux") {
            match JournalReader::spawn() {
                Ok(reader) => {
                    sensor.sources.active(names::AUTH_STRUCTURED);
                    sensor.journal = Some(reader);
                }
                Err(detail) => {
                    // A hole, not a warning to move past: authentication
                    // activity on this host is now only as visible as the
                    // configured log files make it.
                    sensor
                        .sources
                        .unavailable(names::AUTH_STRUCTURED, format!("journalctl: {detail}"));
                    sensor.journal = None;
                }
            }
        }

        sensor.declare_auth_files();
        sensor.sources.log_holes();
        sensor.stats.sources = sensor.sources.snapshot();

        Ok(sensor)
    }

    /// Say whether the configured authentication log files exist.
    ///
    /// A file that is not there is not an error — a service may simply not have
    /// logged yet — but *none* of them being there means this source will never
    /// produce anything, which an operator should hear about rather than infer
    /// from a permanent zero.
    fn declare_auth_files(&mut self) {
        if self.tailers.is_empty() {
            return;
        }
        let present: Vec<_> = self
            .tailers
            .iter()
            .filter(|tailer| tailer.path().exists())
            .map(|tailer| tailer.path().display().to_string())
            .collect();

        if present.is_empty() {
            let configured: Vec<_> = self
                .tailers
                .iter()
                .map(|tailer| tailer.path().display().to_string())
                .collect();
            self.sources.unavailable(
                names::AUTH_FILES,
                format!(
                    "none of the configured files exist: {}",
                    configured.join(", ")
                ),
            );
        } else if present.len() < self.tailers.len() {
            self.sources.degraded(
                names::AUTH_FILES,
                format!(
                    "{} of {} configured files exist",
                    present.len(),
                    self.tailers.len()
                ),
            );
        } else {
            self.sources.active(names::AUTH_FILES);
        }
    }

    /// Put the FIM worker on its own thread.
    fn spawn_fim(&mut self, settings: &FimSettings) -> Result<(), HostError> {
        // Opening the baseline happens here, on the caller's thread, so a
        // broken store is a startup error rather than a silent thread death.
        let mut worker = FimWorker::start(settings)?;
        self.fim_counters = worker.counters();
        // Shutting the sensor down must abandon an in-flight scan, not wait
        // for it: hashing `/usr/bin` takes longer than a service manager's
        // patience.
        self.fim_running = worker.running_flag();

        let (sender, receiver) = std::sync::mpsc::sync_channel(CHANNEL_DEPTH);
        let shutdown = Arc::clone(&self.fim_shutdown);
        let handle = std::thread::Builder::new()
            .name("cybersentinel-fim".to_string())
            .spawn(move || {
                while !shutdown.load(Ordering::Relaxed) {
                    let update = worker.tick(Instant::now());
                    // Always send: even an empty update carries counters, which
                    // is how the baseline-entry count reaches `stats`.
                    if sender.try_send(update).is_err() {
                        // The receiver is gone, or is not draining. Either way
                        // there is nothing useful to do but carry on watching.
                    }
                    std::thread::sleep(FIM_TICK);
                }
            })
            .map_err(|error| HostError::Watcher {
                detail: error.to_string(),
            })?;

        self.fim_updates = Some(receiver);
        self.fim_thread = Some(handle);
        // The watches are already established — `FimWorker::start` attaches
        // them on this thread — so say so now. The caller logs `stats()` as
        // soon as `start()` returns, and a zero there would misreport a
        // working sensor as a blind one.
        self.publish_fim_counters();
        Ok(())
    }

    /// The counters so far.
    #[must_use]
    pub fn stats(&self) -> &HidsStats {
        &self.stats
    }

    /// Service every sensor once. Never blocks.
    pub fn poll(&mut self) -> HostBatch {
        self.poll_at(Instant::now())
    }

    /// [`Self::poll`] with an injected clock, so timer behaviour is testable.
    pub fn poll_at(&mut self, now: Instant) -> HostBatch {
        let mut batch = HostBatch::default();
        self.drain_fim(&mut batch);
        self.poll_logs(&mut batch);
        if self.processes.is_some() && now >= self.next_sweep {
            self.sweep_processes(&mut batch);
            self.next_sweep = now + self.settings.process_interval;
        }
        self.stats.sources = self.sources.snapshot();
        batch
    }

    /// Collect whatever the FIM thread has finished.
    fn drain_fim(&mut self, batch: &mut HostBatch) {
        let Some(receiver) = self.fim_updates.as_ref() else {
            return;
        };
        loop {
            match receiver.try_recv() {
                Ok(update) => {
                    batch.events_from(update, &mut self.fim_counters);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    tracing::error!("the file integrity thread stopped");
                    self.fim_updates = None;
                    break;
                }
            }
        }
        // FIM's two detectors are two sources, and they fail independently:
        // watches can all fail while the baseline still works, which is a
        // partial hole, not an outage.
        if self.settings.fim.is_some() {
            if self.fim_counters.watched_paths == 0 && self.fim_counters.watch_failures > 0 {
                self.sources.unavailable(
                    names::FIM_REALTIME,
                    "no path could be watched in real time; only the periodic rescan sees changes",
                );
            } else if self.fim_counters.watch_failures > 0 {
                self.sources.degraded(
                    names::FIM_REALTIME,
                    format!(
                        "{} path(s) could not be watched; those are covered by the rescan only",
                        self.fim_counters.watch_failures
                    ),
                );
            } else if self.fim_counters.watched_paths > 0 {
                self.sources.active(names::FIM_REALTIME);
            }

            if self.fim_counters.rescans > 0 && self.fim_counters.baseline_entries == 0 {
                // A completed scan that hashed nothing means the configured
                // paths matched no files. The sensor is watching an empty set
                // and would report nothing for ever.
                self.sources.unavailable(
                    names::FIM_BASELINE,
                    "a scan completed but the baseline is empty: hids.fim.paths matched no files",
                );
            } else if self.fim_counters.rescans > 0 {
                self.sources.active(names::FIM_BASELINE);
            }
            self.sources.produced(names::FIM_REALTIME, 0);
        }

        self.publish_fim_counters();
    }

    /// Copy the FIM counters into the reported stats.
    ///
    /// Called from `drain_fim` on every poll, and once from `spawn_fim` so the
    /// numbers are true the moment [`HostSensor::start`] returns rather than
    /// only after the first poll.
    ///
    /// That gap was visible in the field. Watches are established
    /// synchronously in `FimWorker::start`, so `fim_counters` is already
    /// correct when `spawn_fim` captures it — but `stats` was refreshed only
    /// here, and the caller logs `stats()` immediately after starting. A
    /// healthy sensor watching five paths therefore announced
    /// `watched_paths=0 watch_failures=0`, which reads as "watching nothing"
    /// and is the exact shape of the coverage hole this project tells
    /// operators to look for. Reporting a false hole trains people to ignore
    /// the real ones.
    fn publish_fim_counters(&mut self) {
        self.stats.watched_paths = self.fim_counters.watched_paths;
        self.stats.watch_failures = self.fim_counters.watch_failures;
        self.stats.fim_realtime = self.fim_counters.realtime;
        self.stats.fim_rescan = self.fim_counters.rescan;
        self.stats.inotify_overflows = self.fim_counters.overflows;
        self.stats.rescans = self.fim_counters.rescans;
        self.stats.baseline_entries = self.fim_counters.baseline_entries;
    }

    /// Read whatever the log sources have produced.
    fn poll_logs(&mut self, batch: &mut HostBatch) {
        let mut budget = MAX_LOG_LINES_PER_POLL;

        for index in 0..self.tailers.len() {
            if budget == 0 {
                break;
            }
            let (source, lines) = {
                let tailer = &mut self.tailers[index];
                let source = format!("file:{}", tailer.path().display());
                match tailer.read_new_lines() {
                    Ok(lines) => (source, lines),
                    Err(error) => {
                        tracing::warn!(error = %error, source, "reading authentication log");
                        continue;
                    }
                }
            };
            for line in lines.into_iter().take(budget) {
                budget = budget.saturating_sub(1);
                self.stats.auth_records += 1;
                match logs::parse_syslog_line(&line, &source) {
                    Some(parsed) => {
                        if !parsed.event.suspicious.is_empty() {
                            self.stats.auth_suspicious += 1;
                        }
                        batch.auth.push(parsed.event);
                    }
                    // Most log lines are not about authentication. Counting
                    // them is how a parser that has stopped understanding a
                    // format becomes visible instead of just quiet.
                    None => self.stats.auth_unparsed += 1,
                }
            }
        }

        if let Some(journal) = self.journal.as_mut() {
            for line in journal.drain(budget) {
                self.stats.auth_records += 1;
                match logs::parse_journal_record(&line, "journald") {
                    Some(parsed) => {
                        if !parsed.event.suspicious.is_empty() {
                            self.stats.auth_suspicious += 1;
                        }
                        batch.auth.push(parsed.event);
                    }
                    None => self.stats.auth_unparsed += 1,
                }
            }
        }
    }

    /// Take one `/proc` sweep.
    fn sweep_processes(&mut self, batch: &mut HostBatch) {
        let Some(watcher) = self.processes.as_mut() else {
            return;
        };
        let outcome = watcher.sweep();

        // **Silence that is provably wrong.** A process table always contains
        // at least this process, so a sweep seeing one entry or none is not
        // watching a quiet machine — its view has been restricted. That is the
        // exact shape of the `ProtectProc=invisible` failure the packaging pass
        // found by testing: service healthy, capture fine, FIM fine, process
        // monitoring reporting nothing at all and looking no different from a
        // host where nothing started.
        if outcome.processes_seen <= 1 {
            self.sources.unavailable(
                names::PROCESS_TABLE,
                format!(
                    "a sweep of {} saw {} process(es); a process table always contains this one, \
                     so the view is restricted (ProtectProc/hidepid?), not quiet",
                    self.settings.proc_root.display(),
                    outcome.processes_seen
                ),
            );
        } else {
            self.sources.active(names::PROCESS_TABLE);
        }

        // Sockets are read from a different file with different permissions, so
        // they can fail while the process table works — `ProcSubset=pid` does
        // exactly that. Zero listening sockets is possible on a real host
        // though, so this cannot be a hard failure: it is reported as degraded
        // only when the table itself is readable and the socket file is not.
        match watcher.sockets_readable() {
            true => self.sources.active(names::PROCESS_SOCKETS),
            false => self.sources.unavailable(
                names::PROCESS_SOCKETS,
                format!(
                    "no socket table under {}: listening sockets are invisible (ProcSubset=pid?)",
                    self.settings.proc_root.display()
                ),
            ),
        }

        self.sources
            .produced(names::PROCESS_TABLE, outcome.events.len() as u64);
        self.stats.process_events += outcome.events.len() as u64;
        batch.process.extend(outcome.events);
    }
}

impl HostBatch {
    /// Fold one FIM update in, updating the running counters.
    fn events_from(&mut self, update: FimUpdate, counters: &mut FimCounters) {
        self.fim.extend(update.events);
        self.overflows += update.overflows;
        *counters = update.counters;
    }
}

impl Drop for HostSensor {
    fn drop(&mut self) {
        self.fim_shutdown.store(true, Ordering::Relaxed);
        self.fim_running.store(false, Ordering::Relaxed);
        // Dropping the receiver first would leave the worker sending into a
        // closed channel for up to one tick, which is harmless; joining keeps
        // the baseline's SQLite handle from outliving the sensor.
        if let Some(handle) = self.fim_thread.take() {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// journald
// ---------------------------------------------------------------------------

/// Reads journald by following `journalctl -o json`.
///
/// Deliberately a subprocess rather than a link against `libsystemd`. Linking
/// would make the binary depend on a library whose presence and version vary
/// across distributions, and the sensor's promise is a standalone install with
/// no prerequisites. A subprocess that is absent simply means this source is
/// unavailable and the configured log files carry the load — which is exactly
/// what happens on a host without systemd.
#[derive(Debug)]
struct JournalReader {
    child: std::process::Child,
    lines: Receiver<String>,
}

impl JournalReader {
    /// Start following the journal's authentication facilities.
    fn spawn() -> Result<Self, String> {
        use std::process::{Command, Stdio};

        // Facilities 4 (auth) and 10 (authpriv) are where login decisions are
        // recorded. Following everything would mean parsing the whole system
        // log to find them.
        let mut child = Command::new("journalctl")
            .args([
                "--output=json",
                "--follow",
                "--lines=0",
                "SYSLOG_FACILITY=4",
                "+",
                "SYSLOG_FACILITY=10",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| error.to_string())?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "journalctl produced no stdout".to_string())?;

        let (sender, lines) = std::sync::mpsc::sync_channel(CHANNEL_DEPTH);
        std::thread::Builder::new()
            .name("cybersentinel-journal".to_string())
            .spawn(move || {
                use std::io::BufRead as _;
                let reader = std::io::BufReader::new(stdout);
                for line in reader.lines() {
                    let Ok(line) = line else { break };
                    // Bounded, and a drop on a full channel: same reasoning as
                    // the file watcher. Falling behind must not turn into
                    // unbounded memory.
                    let _ = sender.try_send(line);
                }
            })
            .map_err(|error| error.to_string())?;

        Ok(Self { child, lines })
    }

    /// Take up to `budget` pending records.
    fn drain(&mut self, budget: usize) -> Vec<String> {
        let mut out = Vec::new();
        for _ in 0..budget {
            match self.lines.try_recv() {
                Ok(line) => out.push(line),
                Err(_) => break,
            }
        }
        out
    }
}

impl Drop for JournalReader {
    fn drop(&mut self) {
        // `journalctl --follow` never exits on its own.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cybersentinel_common::event::FileChange;
    use notify::event::{EventKind, Flag};
    use std::fs;
    use std::io::Write as _;

    fn write(path: &std::path::Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        let mut file = fs::File::create(path).expect("create");
        file.write_all(contents.as_bytes()).expect("write");
    }

    fn fim_settings(root: &std::path::Path) -> FimSettings {
        FimSettings {
            paths: vec![root.to_path_buf()],
            ..FimSettings::default()
        }
    }

    /// Wait for a condition the FIM thread will eventually satisfy.
    ///
    /// The worker runs on its own clock, so tests wait on the outcome rather
    /// than on a fixed sleep.
    fn poll_until(
        sensor: &mut HostSensor,
        mut done: impl FnMut(&HostBatch) -> bool,
    ) -> Option<HostBatch> {
        for _ in 0..200 {
            let batch = sensor.poll();
            if done(&batch) {
                return Some(batch);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    // -----------------------------------------------------------------------
    // the overflow contract
    // -----------------------------------------------------------------------

    /// **inotify-overflow-isn't-silent.**
    ///
    /// The kernel dropped events. The sensor must not carry on as though the
    /// filesystem were unchanged: it rescans, it reports, and it counts.
    #[test]
    fn a_queue_overflow_forces_a_rescan_and_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("passwd");
        write(&target, "root:x:0:0");

        let mut worker = FimWorker::start(&fim_settings(dir.path())).expect("worker");
        worker.tick(Instant::now()); // establishes the baseline

        // A change the watcher never told us about, because the queue
        // overflowed and the kernel dropped the notification.
        write(&target, "root:x:0:0\nbackdoor:x:0:0");

        let overflow = notify::Event::new(EventKind::Other).set_flag(Flag::Rescan);
        let (events, forced) = worker.handle_notification(Ok(overflow));
        assert!(events.is_empty(), "the overflow itself carries no paths");
        assert!(forced, "and it must force a rescan");
        assert_eq!(
            worker.counters().overflows,
            1,
            "a dropped-event window must be counted, not swallowed"
        );

        // The next tick runs the forced rescan, which finds what was dropped
        // and reports the overflow alongside it.
        let update = worker.tick(Instant::now());
        assert_eq!(
            update.overflows, 1,
            "the gap must be reported, not just recovered from"
        );
        assert!(
            update
                .events
                .iter()
                .any(|event| event.change == FileChange::Modified
                    && event.path == target.to_string_lossy()),
            "the change the overflow hid must still surface"
        );
    }

    /// A watcher error is treated as a possible gap too, rather than being
    /// logged and forgotten.
    #[test]
    fn a_watcher_error_also_forces_a_rescan() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(&dir.path().join("a"), "x");
        let mut worker = FimWorker::start(&fim_settings(dir.path())).expect("worker");

        let (_, forced) = worker.handle_notification(Err(notify::Error::generic("backend died")));
        assert!(forced);
        assert_eq!(worker.counters().watch_failures, 1);
    }

    /// **real-time-missed-it → periodic-rescan-caught-it**, through the worker.
    #[test]
    fn a_change_made_while_the_sensor_was_down_is_found_on_the_first_tick() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path().join("baseline.db");
        let watched = dir.path().join("etc");
        let target = watched.join("sudoers");
        write(&target, "root ALL=(ALL) ALL");

        let settings = FimSettings {
            paths: vec![watched],
            baseline_path: Some(store),
            ..FimSettings::default()
        };

        // First run establishes the baseline, then goes away.
        {
            let mut worker = FimWorker::start(&settings).expect("worker");
            assert!(
                worker.tick(Instant::now()).events.is_empty(),
                "establishing a baseline is not a wall of alerts"
            );
        }

        // Nothing is watching.
        write(
            &target,
            "root ALL=(ALL) ALL\nattacker ALL=(ALL) NOPASSWD: ALL",
        );

        let mut worker = FimWorker::start(&settings).expect("worker");
        let update = worker.tick(Instant::now());

        assert_eq!(update.events.len(), 1, "the offline change must surface");
        assert_eq!(update.events[0].change, FileChange::Modified);
        assert_eq!(
            update.events[0].detected_by,
            FimDetection::BaselineRescan,
            "and it must be labelled as found by rescan, not claimed as real-time"
        );
    }

    #[test]
    fn the_first_tick_does_not_rescan_again_immediately() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(&dir.path().join("a"), "x");
        let mut worker = FimWorker::start(&FimSettings {
            rescan_interval: Duration::from_secs(3_600),
            ..fim_settings(dir.path())
        })
        .expect("worker");

        let start = Instant::now();
        worker.tick(start);
        worker.tick(start);
        assert_eq!(
            worker.counters().rescans,
            1,
            "the rescan interval must be honoured after the first scan"
        );
    }

    #[test]
    fn an_unwatchable_path_is_counted_not_fatal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let worker = FimWorker::start(&FimSettings {
            paths: vec![dir.path().join("does-not-exist")],
            ..FimSettings::default()
        })
        .expect("a degraded worker still starts");
        assert_eq!(worker.counters().watch_failures, 1);
        assert_eq!(worker.counters().watched_paths, 0);
    }

    // -----------------------------------------------------------------------
    // the sensor
    // -----------------------------------------------------------------------

    /// Starting must not block on hashing. A baseline over `/usr/bin` takes
    /// seconds to minutes; paying that on the caller's thread would stall
    /// packet capture and look like a hang.
    #[test]
    fn starting_does_not_wait_for_the_baseline_scan() {
        let dir = tempfile::tempdir().expect("tempdir");
        for index in 0..200 {
            write(&dir.path().join(format!("file{index}")), &"x".repeat(4_096));
        }

        let before = Instant::now();
        let sensor = HostSensor::start(HostSettings {
            fim: Some(fim_settings(dir.path())),
            ..HostSettings::default()
        })
        .expect("sensor");
        let elapsed = before.elapsed();
        drop(sensor);

        assert!(
            elapsed < Duration::from_secs(2),
            "start took {elapsed:?}; the scan belongs on the FIM thread"
        );
    }

    /// The startup log line reads `stats()` the instant `start()` returns, so
    /// the watch counts have to be true by then.
    ///
    /// They were not: watches are established synchronously, but `stats` was
    /// only refreshed on the first poll, so a healthy sensor announced
    /// `watched_paths=0 watch_failures=0` — indistinguishable from watching
    /// nothing, which is the coverage hole operators are told to look for.
    ///
    /// Polling before the assertion would pass against the broken code and pin
    /// nothing. Not polling is the whole test.
    #[test]
    fn starting_reports_the_watches_it_established() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(&dir.path().join("passwd"), "root:x:0:0");

        let sensor = HostSensor::start(HostSettings {
            fim: Some(fim_settings(dir.path())),
            ..HostSettings::default()
        })
        .expect("sensor");

        assert_eq!(
            sensor.stats().watched_paths,
            1,
            "one configured path was watched; start() must say so before any poll"
        );
        assert_eq!(sensor.stats().watch_failures, 0);
    }

    #[test]
    fn a_change_reaches_the_caller_through_the_worker_thread() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("passwd");
        write(&target, "root:x:0:0");

        let mut sensor = HostSensor::start(HostSettings {
            fim: Some(FimSettings {
                rescan_interval: Duration::from_millis(50),
                ..fim_settings(dir.path())
            }),
            ..HostSettings::default()
        })
        .expect("sensor");

        // Wait for the baseline to be established before changing anything,
        // or the change would simply be part of the starting position.
        for _ in 0..200 {
            sensor.poll();
            if sensor.stats().rescans >= 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(sensor.stats().rescans >= 1, "the baseline never settled");
        write(&target, "root:x:0:0\nbackdoor:x:0:0");

        let batch = poll_until(&mut sensor, |batch| !batch.fim.is_empty())
            .expect("the change must reach the caller");
        assert!(batch
            .fim
            .iter()
            .any(|event| event.change == FileChange::Modified));
    }

    #[test]
    fn authentication_lines_are_read_from_a_followed_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("auth.log");
        write(&log, "");

        let mut sensor = HostSensor::start(HostSettings {
            auth_files: vec![log.clone()],
            ..HostSettings::default()
        })
        .expect("sensor");
        sensor.poll();

        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .expect("open");
        writeln!(
            file,
            "Jan  2 03:04:05 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 1 ssh2"
        )
        .expect("write");
        writeln!(file, "Jan  2 03:04:06 web01 cron[9]: unrelated chatter").expect("write");

        let batch = sensor.poll();
        assert_eq!(batch.auth.len(), 1);
        assert_eq!(batch.auth[0].user.as_deref(), Some("admin"));
        assert_eq!(sensor.stats().auth_records, 2);
        assert_eq!(
            sensor.stats().auth_unparsed,
            1,
            "lines we did not understand are counted, so a broken parser is visible"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_sweeps_respect_their_interval() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A minimal fake /proc: one process, no sockets.
        write(
            &dir.path().join("1/stat"),
            "1 (init) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 5 0 0",
        );

        let mut sensor = HostSensor::start(HostSettings {
            proc_root: dir.path().to_path_buf(),
            process_monitoring: true,
            process_interval: Duration::from_secs(60),
            ..HostSettings::default()
        })
        .expect("sensor");

        let start = Instant::now();
        sensor.poll_at(start); // establishes

        write(
            &dir.path().join("999/stat"),
            "999 (nc) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 9 0 0",
        );
        assert!(
            sensor.poll_at(start).process.is_empty(),
            "the interval has not elapsed"
        );
        let batch = sensor.poll_at(start + Duration::from_secs(61));
        assert_eq!(batch.process.len(), 1);
        assert_eq!(batch.process[0].name, "nc");
    }

    // -----------------------------------------------------------------------
    // silence that is provably wrong
    // -----------------------------------------------------------------------

    /// The `ProtectProc=invisible` failure, reproduced without systemd.
    ///
    /// The packaging pass found it by measurement: service healthy, capture
    /// working, FIM working, and process monitoring reporting nothing at all —
    /// indistinguishable from a host where nothing started. A process table
    /// always contains the sensor's own process, so seeing one entry is proof
    /// the view is restricted rather than the host being quiet.
    // `/proc` process monitoring is Linux-only — `HostSensor::start` gates the
    // watcher on it, so on any other platform `processes` is `None` and no
    // sweep happens. These four tests assert what a sweep *found*, so they are
    // Linux-only too.
    //
    // They were not, and CI's first run on real Windows and macOS runners
    // failed all four. The cross-compile guard could not have caught it: it
    // compiles the tests, it never runs them. Gating the runtime without
    // gating the tests that exercise it is a gap only a real runner shows.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_sweep_that_can_only_see_itself_reports_a_hole() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A /proc containing exactly one process: what hidepid leaves behind.
        write(
            &dir.path().join("1/stat"),
            "1 (cybersentinel) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 5 0 0",
        );
        write(&dir.path().join("net/tcp"), "  sl  local_address\n");

        let mut sensor = HostSensor::start(HostSettings {
            proc_root: dir.path().to_path_buf(),
            process_monitoring: true,
            ..HostSettings::default()
        })
        .expect("sensor");
        sensor.poll();

        let status = sensor
            .stats()
            .sources
            .iter()
            .find(|source| source.name == names::PROCESS_TABLE)
            .expect("the process source is listed");
        assert_eq!(
            status.state,
            cybersentinel_common::event::SourceState::Unavailable,
            "one visible process is a blinded sensor, not a quiet host"
        );
        assert!(
            status.detail.contains("restricted"),
            "the report must say what is wrong: {:?}",
            status.detail
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_sweep_that_sees_a_real_table_is_active() {
        let dir = tempfile::tempdir().expect("tempdir");
        for pid in 1..=5 {
            write(
                &dir.path().join(format!("{pid}/stat")),
                &format!("{pid} (proc) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {pid} 0 0"),
            );
        }
        write(&dir.path().join("net/tcp"), "  sl  local_address\n");

        let mut sensor = HostSensor::start(HostSettings {
            proc_root: dir.path().to_path_buf(),
            process_monitoring: true,
            ..HostSettings::default()
        })
        .expect("sensor");
        sensor.poll();

        let sources = &sensor.stats().sources;
        let table = sources
            .iter()
            .find(|source| source.name == names::PROCESS_TABLE)
            .expect("listed");
        assert_eq!(
            table.state,
            cybersentinel_common::event::SourceState::Active
        );
    }

    /// The `ProcSubset=pid` failure: the process table is readable, the socket
    /// table is not, and listening-socket detection stops with nothing to show.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_missing_socket_table_reports_a_hole_of_its_own() {
        let dir = tempfile::tempdir().expect("tempdir");
        for pid in 1..=4 {
            write(
                &dir.path().join(format!("{pid}/stat")),
                &format!("{pid} (proc) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {pid} 0 0"),
            );
        }
        // No net/tcp at all — what ProcSubset=pid leaves behind.

        let mut sensor = HostSensor::start(HostSettings {
            proc_root: dir.path().to_path_buf(),
            process_monitoring: true,
            ..HostSettings::default()
        })
        .expect("sensor");
        sensor.poll();

        let sources = &sensor.stats().sources;
        let table = sources
            .iter()
            .find(|source| source.name == names::PROCESS_TABLE)
            .expect("listed");
        let sockets = sources
            .iter()
            .find(|source| source.name == names::PROCESS_SOCKETS)
            .expect("listed");

        assert_eq!(
            table.state,
            cybersentinel_common::event::SourceState::Active,
            "the process table is fine; only the socket half broke"
        );
        assert_eq!(
            sockets.state,
            cybersentinel_common::event::SourceState::Unavailable,
            "an unreadable socket table is a hole, not zero sockets"
        );
    }

    #[test]
    fn auth_files_that_do_not_exist_are_a_reported_hole() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sensor = HostSensor::start(HostSettings {
            auth_files: vec![
                dir.path().join("nope.log"),
                dir.path().join("also-nope.log"),
            ],
            ..HostSettings::default()
        })
        .expect("sensor");

        let status = sensor
            .stats()
            .sources
            .iter()
            .find(|source| source.name == names::AUTH_FILES)
            .expect("listed");
        assert_eq!(
            status.state,
            cybersentinel_common::event::SourceState::Unavailable,
            "a source that can never produce anything must say so"
        );
        assert!(status.detail.contains("none of the configured files exist"));
    }

    #[test]
    fn some_auth_files_missing_is_degraded_not_dead() {
        let dir = tempfile::tempdir().expect("tempdir");
        let present = dir.path().join("auth.log");
        write(&present, "");

        let sensor = HostSensor::start(HostSettings {
            auth_files: vec![present, dir.path().join("secure")],
            ..HostSettings::default()
        })
        .expect("sensor");

        let status = sensor
            .stats()
            .sources
            .iter()
            .find(|source| source.name == names::AUTH_FILES)
            .expect("listed");
        assert_eq!(
            status.state,
            cybersentinel_common::event::SourceState::Degraded
        );
    }

    /// FIM watching a path set that matches nothing would report zero for ever
    /// and look like a filesystem nobody touched.
    #[test]
    fn a_baseline_that_matched_no_files_is_a_reported_hole() {
        let dir = tempfile::tempdir().expect("tempdir");
        let empty = dir.path().join("empty-dir");
        fs::create_dir_all(&empty).expect("mkdir");

        let mut sensor = HostSensor::start(HostSettings {
            fim: Some(FimSettings {
                paths: vec![empty],
                ..FimSettings::default()
            }),
            ..HostSettings::default()
        })
        .expect("sensor");

        for _ in 0..200 {
            sensor.poll();
            if sensor.stats().rescans >= 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        sensor.poll();

        let status = sensor
            .stats()
            .sources
            .iter()
            .find(|source| source.name == names::FIM_BASELINE)
            .expect("listed");
        assert_eq!(
            status.state,
            cybersentinel_common::event::SourceState::Unavailable,
            "a completed scan with an empty baseline means the paths matched nothing"
        );
    }

    #[test]
    fn a_sensor_with_nothing_enabled_is_valid_and_quiet() {
        let mut sensor = HostSensor::start(HostSettings::default()).expect("sensor");
        assert!(sensor.poll().is_empty());
        assert_eq!(sensor.stats().watched_paths, 0);
    }
}
