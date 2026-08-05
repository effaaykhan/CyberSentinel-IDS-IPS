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
//! 2. It is **reported** as its own decoder-anomaly-style event, so the gap is
//!    visible in the event stream rather than inferred from an absence.
//! 3. It is **counted** in [`HidsStats::inotify_overflows`], so a host that
//!    overflows repeatedly shows up as a coverage problem.
//!
//! A silently missed change must never be indistinguishable from an unchanged
//! filesystem.

use crate::fim::{self, FimSettings};
use crate::logs::{self, Tailer};
use crate::process::{self, ScanLimits};
use crate::HostError;
use cybersentinel_common::event::{AuthEvent, FimDetection, FimEvent, HidsStats, ProcessEvent};
use notify::{RecursiveMode, Watcher as _};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError};
use std::time::{Duration, Instant};

/// How many pending notifications and log lines are held before dropping.
///
/// Bounded like every other queue in the sensor: back-pressure that blocks the
/// watcher thread would be worse than a counted drop, and unbounded growth
/// would be worse than both.
const CHANNEL_DEPTH: usize = 4_096;
/// Most real-time notifications turned into events in one poll.
///
/// Keeps a burst of file activity from monopolising the run loop; the rest is
/// picked up on the next poll, or by the rescan.
const MAX_NOTIFICATIONS_PER_POLL: usize = 512;
/// Most log lines parsed in one poll.
const MAX_LOG_LINES_PER_POLL: usize = 1_024;
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

    fn absorb(&mut self, other: HostBatch) {
        self.fim.extend(other.fim);
        self.auth.extend(other.auth);
        self.process.extend(other.process);
        self.overflows += other.overflows;
    }
}

/// The polled host runtime.
pub struct HostSensor {
    settings: HostSettings,
    /// `None` when FIM is off or the baseline could not be opened.
    fim: Option<fim::Monitor>,
    /// Kept alive for as long as we want notifications; dropping it stops them.
    watcher: Option<Box<dyn notify::Watcher + Send>>,
    notifications: Option<Receiver<notify::Result<notify::Event>>>,
    tailers: Vec<Tailer>,
    journal: Option<JournalReader>,
    processes: Option<process::Watcher>,
    /// Findings from the startup rescan, handed out on the first poll.
    startup_findings: Vec<FimEvent>,
    next_rescan: Instant,
    next_sweep: Instant,
    stats: HidsStats,
}

impl std::fmt::Debug for HostSensor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `notify::Watcher` is not `Debug`, so the interesting state is
        // summarised rather than derived.
        formatter
            .debug_struct("HostSensor")
            .field("settings", &self.settings)
            .field("watching", &self.watcher.is_some())
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
    pub fn start(settings: HostSettings) -> Result<Self, HostError> {
        let now = Instant::now();
        let rescan_interval = settings
            .fim
            .as_ref()
            .map_or(fim::DEFAULT_RESCAN_INTERVAL, |fim| fim.rescan_interval);

        let mut sensor = Self {
            fim: None,
            watcher: None,
            notifications: None,
            tailers: settings.auth_files.iter().map(Tailer::new).collect(),
            journal: None,
            startup_findings: Vec::new(),
            processes: settings.process_monitoring.then(|| {
                process::Watcher::new(settings.proc_root.clone(), settings.process_limits)
            }),
            next_rescan: now + rescan_interval,
            next_sweep: now,
            stats: HidsStats {
                enabled: true,
                ..HidsStats::default()
            },
            settings,
        };

        if let Some(fim_settings) = sensor.settings.fim.clone() {
            let baseline = fim::Baseline::open(fim_settings.baseline_path.as_deref())?;
            let mut monitor = fim::Monitor::new(fim_settings.clone(), baseline);

            // Establish (or refresh) the baseline before watching. Doing it in
            // this order is what catches changes made while the sensor was
            // down: the first comparison happens against what we stored last
            // time, not against what we are about to see.
            let outcome = monitor.rescan(FimDetection::BaselineRescan)?;
            sensor.stats.rescans += 1;
            sensor.stats.baseline_entries = monitor.baseline().len().unwrap_or(0);
            sensor.startup_findings = outcome.events;

            sensor.fim = Some(monitor);
            sensor.install_watcher(&fim_settings);
        }

        if sensor.settings.journald {
            match JournalReader::spawn() {
                Ok(reader) => sensor.journal = Some(reader),
                Err(detail) => {
                    tracing::warn!(
                        detail,
                        "journald unavailable; continuing with configured log files"
                    );
                }
            }
        }

        Ok(sensor)
    }

    /// Attach the real-time watcher, counting rather than failing on the paths
    /// it cannot take.
    fn install_watcher(&mut self, settings: &FimSettings) {
        let (sender, receiver) = std::sync::mpsc::sync_channel(CHANNEL_DEPTH);
        let forwarder = move |event| {
            // A full channel means we are behind. Dropping is the right answer —
            // blocking here would stall the watcher thread and make the kernel
            // queue overflow, which is strictly worse — and the rescan is the
            // backstop that makes the drop recoverable.
            let _ = SyncSender::try_send(&sender, event);
        };

        let mut watcher = match notify::recommended_watcher(forwarder) {
            Ok(watcher) => watcher,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "real-time file watching unavailable; the periodic rescan still runs"
                );
                self.stats.watch_failures += 1;
                return;
            }
        };

        for path in &settings.paths {
            match watcher.watch(path, RecursiveMode::Recursive) {
                Ok(()) => self.stats.watched_paths += 1,
                Err(error) => {
                    // The usual causes are a missing path or an exhausted
                    // `max_user_watches`. Neither is fatal, and both must be
                    // visible: an unwatched path is a coverage gap, not a
                    // clean bill of health.
                    tracing::warn!(
                        path = %path.display(),
                        error = %error,
                        "could not watch path; it is covered by the periodic rescan only"
                    );
                    self.stats.watch_failures += 1;
                }
            }
        }

        self.watcher = Some(Box::new(watcher));
        self.notifications = Some(receiver);
    }

    /// Hand out the startup rescan's findings.
    ///
    /// Held rather than returned from [`Self::start`] so callers have exactly
    /// one place that consumes host events.
    fn take_startup_findings(&mut self) -> Vec<FimEvent> {
        std::mem::take(&mut self.startup_findings)
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
        let mut batch = HostBatch {
            fim: self.take_startup_findings(),
            ..HostBatch::default()
        };
        self.stats.fim_rescan += batch.fim.len() as u64;

        batch.absorb(self.poll_notifications());
        if now >= self.next_rescan {
            batch.absorb(self.run_rescan(FimDetection::BaselineRescan));
            self.next_rescan = now
                + self
                    .settings
                    .fim
                    .as_ref()
                    .map_or(fim::DEFAULT_RESCAN_INTERVAL, |fim| fim.rescan_interval);
        }
        batch.absorb(self.poll_logs());
        if self.processes.is_some() && now >= self.next_sweep {
            batch.absorb(self.sweep_processes());
            self.next_sweep = now + self.settings.process_interval;
        }

        batch
    }

    /// Drain pending real-time notifications.
    fn poll_notifications(&mut self) -> HostBatch {
        let mut batch = HostBatch::default();
        let mut overflowed = false;

        for _ in 0..MAX_NOTIFICATIONS_PER_POLL {
            let Some(receiver) = self.notifications.as_ref() else {
                break;
            };
            match receiver.try_recv() {
                Ok(notification) => {
                    let (events, overflow) = self.handle_notification(notification);
                    batch.fim.extend(events);
                    overflowed |= overflow;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // The watcher thread is gone. Rescans continue, but the
                    // loss of real-time coverage must not be silent.
                    tracing::warn!("file watcher stopped; falling back to periodic rescan only");
                    self.stats.watch_failures += 1;
                    self.notifications = None;
                    self.watcher = None;
                    break;
                }
            }
        }

        if overflowed {
            // Point 1 of the overflow contract: find what was dropped.
            batch.absorb(self.run_rescan(FimDetection::BaselineRescan));
            batch.overflows += 1;
        }
        batch
    }

    /// Turn one notification into events, and say whether it was an overflow.
    ///
    /// Split out so the overflow path can be exercised directly: inducing a
    /// real `IN_Q_OVERFLOW` in a test would need to outrun the kernel's queue,
    /// which is neither reliable nor fast.
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
                self.stats.watch_failures += 1;
                return (Vec::new(), true);
            }
        };

        if event.need_rescan() {
            // Point 2: report the gap. The count is the report; the caller
            // turns it into an event so it appears in the stream.
            tracing::warn!(
                "file watch queue overflowed; changes were dropped — forcing a baseline rescan"
            );
            self.stats.inotify_overflows += 1;
            return (Vec::new(), true);
        }

        let Some(monitor) = self.fim.as_mut() else {
            return (Vec::new(), false);
        };

        // Whatever the notification claims happened, the baseline decides. A
        // notification is a hint about *where* to look, never about *what*
        // changed — the hashes settle that.
        let mut events = Vec::new();
        for path in &event.paths {
            match monitor.recheck(path) {
                Ok(Some(event)) => events.push(event),
                Ok(None) => {}
                Err(error) => tracing::warn!(error = %error, "rechecking a changed path"),
            }
        }
        self.stats.fim_realtime += events.len() as u64;
        (events, false)
    }

    /// Run a baseline rescan now.
    fn run_rescan(&mut self, detected_by: FimDetection) -> HostBatch {
        let Some(monitor) = self.fim.as_mut() else {
            return HostBatch::default();
        };
        match monitor.rescan(detected_by) {
            Ok(outcome) => {
                self.stats.rescans += 1;
                self.stats.fim_rescan += outcome.events.len() as u64;
                self.stats.baseline_entries = monitor.baseline().len().unwrap_or(0);
                HostBatch {
                    fim: outcome.events,
                    ..HostBatch::default()
                }
            }
            Err(error) => {
                tracing::error!(error = %error, "baseline rescan failed");
                HostBatch::default()
            }
        }
    }

    /// Read whatever the log sources have produced.
    fn poll_logs(&mut self) -> HostBatch {
        let mut batch = HostBatch::default();
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

        batch
    }

    /// Take one `/proc` sweep.
    fn sweep_processes(&mut self) -> HostBatch {
        let Some(watcher) = self.processes.as_mut() else {
            return HostBatch::default();
        };
        let outcome = watcher.sweep();
        self.stats.process_events += outcome.events.len() as u64;
        HostBatch {
            process: outcome.events,
            ..HostBatch::default()
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
/// what happens on a non-systemd host.
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
                    if sender.try_send(line).is_err() {
                        continue;
                    }
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

    fn fim_settings(root: &std::path::Path) -> HostSettings {
        HostSettings {
            fim: Some(FimSettings {
                paths: vec![root.to_path_buf()],
                ..FimSettings::default()
            }),
            ..HostSettings::default()
        }
    }

    /// **inotify-overflow-isn't-silent.**
    ///
    /// The kernel dropped events. The sensor must not carry on as though the
    /// filesystem were unchanged: it rescans, it reports, and it counts.
    #[test]
    fn a_queue_overflow_forces_a_rescan_and_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("passwd");
        write(&target, "root:x:0:0");

        let mut sensor = HostSensor::start(fim_settings(dir.path())).expect("sensor");
        sensor.poll(); // consume the startup baseline

        // A change the watcher never told us about, because the queue overflowed.
        write(&target, "root:x:0:0\nbackdoor:x:0:0");

        let overflow = notify::Event::new(EventKind::Other).set_flag(Flag::Rescan);
        let (events, forced) = sensor.handle_notification(Ok(overflow));

        assert!(events.is_empty(), "the overflow itself carries no paths");
        assert!(forced, "and it must force a rescan");
        assert_eq!(
            sensor.stats().inotify_overflows,
            1,
            "a dropped-event window must be counted, not swallowed"
        );

        // The rescan the overflow forced finds the change the kernel dropped.
        let found = sensor.run_rescan(FimDetection::BaselineRescan);
        assert!(
            found
                .fim
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
        let mut sensor = HostSensor::start(fim_settings(dir.path())).expect("sensor");

        let (_, forced) = sensor.handle_notification(Err(notify::Error::generic("backend died")));
        assert!(forced);
        assert_eq!(sensor.stats().watch_failures, 1);
    }

    /// **real-time-missed-it → periodic-rescan-caught-it**, end to end through
    /// the sensor rather than through the FIM monitor alone.
    #[test]
    fn a_change_made_before_startup_is_reported_on_the_first_poll() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path().join("baseline.db");
        let watched = dir.path().join("etc");
        let target = watched.join("sudoers");
        write(&target, "root ALL=(ALL) ALL");

        let settings = HostSettings {
            fim: Some(FimSettings {
                paths: vec![watched],
                baseline_path: Some(store),
                ..FimSettings::default()
            }),
            ..HostSettings::default()
        };

        // First run establishes the baseline, then goes away.
        drop(HostSensor::start(settings.clone()).expect("sensor"));

        // Nothing is watching.
        write(
            &target,
            "root ALL=(ALL) ALL\nattacker ALL=(ALL) NOPASSWD: ALL",
        );

        let mut sensor = HostSensor::start(settings).expect("sensor");
        let batch = sensor.poll();

        assert_eq!(batch.fim.len(), 1, "the offline change must surface");
        assert_eq!(batch.fim[0].change, FileChange::Modified);
        assert_eq!(batch.fim[0].detected_by, FimDetection::BaselineRescan);
        assert!(sensor.stats().rescans >= 1);
    }

    #[test]
    fn a_first_start_reports_nothing_and_establishes_the_baseline() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(&dir.path().join("a"), "x");
        write(&dir.path().join("b"), "y");

        let mut sensor = HostSensor::start(fim_settings(dir.path())).expect("sensor");
        assert!(sensor.poll().is_empty());
        assert_eq!(sensor.stats().baseline_entries, 2);
    }

    #[test]
    fn an_unwatchable_path_is_counted_not_fatal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let settings = HostSettings {
            fim: Some(FimSettings {
                paths: vec![dir.path().join("does-not-exist")],
                ..FimSettings::default()
            }),
            ..HostSettings::default()
        };
        let sensor = HostSensor::start(settings).expect("a degraded sensor still starts");
        assert_eq!(sensor.stats().watch_failures, 1);
        assert_eq!(sensor.stats().watched_paths, 0);
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

    #[test]
    fn a_sensor_with_nothing_enabled_is_valid_and_quiet() {
        let mut sensor = HostSensor::start(HostSettings::default()).expect("sensor");
        assert!(sensor.poll().is_empty());
        assert_eq!(sensor.stats().watched_paths, 0);
    }
}
