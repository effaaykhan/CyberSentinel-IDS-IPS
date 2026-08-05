//! File integrity monitoring.
//!
//! # Two detectors, because one is not enough
//!
//! Real-time watching (inotify, via `notify`) reports changes as they happen,
//! but it has three failure modes that all look identical from the outside —
//! like a filesystem nobody touched:
//!
//! 1. **The sensor was not running.** Anything changed while it was down is
//!    invisible to a watcher that only ever sees future events.
//! 2. **The queue overflowed.** inotify has a bounded per-instance queue. Fill
//!    it faster than the sensor drains it and the kernel drops events and sets
//!    `IN_Q_OVERFLOW`. That is trivially attacker-inducible: touch a lot of
//!    files, then change the one that matters.
//! 3. **The watch was never established.** `max_user_watches` is finite, and a
//!    path that could not be watched is a path with no coverage.
//!
//! So real-time watching is paired with a **periodic baseline rescan**: hashes
//! of every watched file live in SQLite, and on a timer the tree is walked and
//! compared. The rescan is the backstop that makes the three failures above
//! recoverable rather than silent. Overflow additionally triggers an
//! *immediate* rescan and is reported as its own event — a dropped change must
//! never be indistinguishable from no change.
//!
//! # Bounded on purpose
//!
//! Watching the whole filesystem would exhaust `max_user_watches` and hurt the
//! machine we are supposed to be protecting. FIM is scoped to a configured set
//! of critical paths, and within that: bounded depth, bounded entry count,
//! bounded file size for hashing, and no symlink traversal. Every bound that
//! bites is *counted and reported*, because unreported truncation is the same
//! bug as a silently dropped event.

use crate::HostError;
use cybersentinel_common::event::{FileChange, FimDetection, FimEvent};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Files larger than this are recorded by metadata only, never hashed.
///
/// Hashing an arbitrarily large file inside the monitoring loop is a
/// denial-of-service whose size the attacker chooses.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1_024 * 1_024;
/// Deepest directory nesting walked below a configured root.
pub const DEFAULT_MAX_DEPTH: usize = 16;
/// Most files tracked across all configured roots.
pub const DEFAULT_MAX_ENTRIES: usize = 50_000;
/// Default gap between baseline rescans.
pub const DEFAULT_RESCAN_INTERVAL: Duration = Duration::from_secs(3_600);
/// Read buffer for hashing.
const HASH_CHUNK: usize = 64 * 1_024;

/// What to watch and how hard to try.
#[derive(Debug, Clone)]
pub struct FimSettings {
    /// Roots to monitor. Files are watched directly; directories recursively.
    pub paths: Vec<PathBuf>,
    /// Where the baseline lives. `None` keeps it in memory — useful for tests,
    /// and it means a rescan still works when the on-disk store cannot be
    /// opened, just without surviving a restart.
    pub baseline_path: Option<PathBuf>,
    /// Gap between periodic rescans.
    pub rescan_interval: Duration,
    /// Largest file hashed.
    pub max_file_bytes: u64,
    /// Deepest nesting walked.
    pub max_depth: usize,
    /// Most files tracked.
    pub max_entries: usize,
}

impl Default for FimSettings {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            baseline_path: None,
            rescan_interval: DEFAULT_RESCAN_INTERVAL,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

/// What the baseline remembers about one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    /// Content hash, absent for files too large to hash or unreadable.
    pub sha256: Option<String>,
    /// Size in bytes.
    pub size: u64,
    /// Unix mode.
    pub mode: u32,
    /// Owning user.
    pub uid: u32,
    /// Owning group.
    pub gid: u32,
}

/// Read a file's current state.
///
/// Returns `Ok(None)` when the path is not a regular file we should track — a
/// directory, a symlink, a device node. Symlinks are deliberately not followed:
/// a symlink swapped under a watched path must not make us hash, and report on,
/// something outside the monitored set.
pub fn inspect(path: &Path, max_file_bytes: u64) -> Result<Option<FileRecord>, std::io::Error> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() {
        return Ok(None);
    }

    let size = metadata.len();
    let sha256 = if size <= max_file_bytes {
        hash_file(path).ok()
    } else {
        None
    };

    Ok(Some(FileRecord {
        sha256,
        size,
        mode: file_mode(&metadata),
        uid: file_uid(&metadata),
        gid: file_gid(&metadata),
    }))
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    metadata.mode()
}
#[cfg(unix)]
fn file_uid(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    metadata.uid()
}
#[cfg(unix)]
fn file_gid(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    metadata.gid()
}
#[cfg(not(unix))]
fn file_mode(_metadata: &fs::Metadata) -> u32 {
    0
}
#[cfg(not(unix))]
fn file_uid(_metadata: &fs::Metadata) -> u32 {
    0
}
#[cfg(not(unix))]
fn file_gid(_metadata: &fs::Metadata) -> u32 {
    0
}

/// SHA-256 a file in bounded chunks.
fn hash_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_CHUNK];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

// ---------------------------------------------------------------------------
// baseline
// ---------------------------------------------------------------------------

/// The persistent record of what the watched files looked like.
///
/// SQLite rather than a flat file because a rescan needs prefix lookups over
/// tens of thousands of paths, and because a half-written flat file after a
/// crash is a baseline that quietly lies.
#[derive(Debug)]
pub struct Baseline {
    connection: Connection,
}

impl Baseline {
    /// Open (or create) the baseline at `path`, or in memory when `None`.
    pub fn open(path: Option<&Path>) -> Result<Self, HostError> {
        let connection = match path {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|error| HostError::Baseline {
                        detail: format!("creating {}: {error}", parent.display()),
                    })?;
                }
                Connection::open(path)
            }
            None => Connection::open_in_memory(),
        }
        .map_err(|error| HostError::Baseline {
            detail: error.to_string(),
        })?;

        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE IF NOT EXISTS baseline (
                     path  TEXT PRIMARY KEY,
                     hash  TEXT,
                     size  INTEGER NOT NULL,
                     mode  INTEGER NOT NULL,
                     uid   INTEGER NOT NULL,
                     gid   INTEGER NOT NULL
                 );",
            )
            .map_err(|error| HostError::Baseline {
                detail: error.to_string(),
            })?;

        Ok(Self { connection })
    }

    /// Look up one path.
    pub fn get(&self, path: &str) -> Result<Option<FileRecord>, HostError> {
        self.connection
            .query_row(
                "SELECT hash, size, mode, uid, gid FROM baseline WHERE path = ?1",
                [path],
                |row| {
                    Ok(FileRecord {
                        sha256: row.get(0)?,
                        size: row.get::<_, i64>(1)?.unsigned_abs(),
                        mode: row.get(2)?,
                        uid: row.get(3)?,
                        gid: row.get(4)?,
                    })
                },
            )
            .map(Some)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(HostError::Baseline {
                    detail: other.to_string(),
                }),
            })
    }

    /// Record the current state of one path.
    pub fn put(&self, path: &str, record: &FileRecord) -> Result<(), HostError> {
        self.connection
            .execute(
                "INSERT INTO baseline (path, hash, size, mode, uid, gid)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(path) DO UPDATE SET
                     hash = excluded.hash, size = excluded.size,
                     mode = excluded.mode, uid = excluded.uid, gid = excluded.gid",
                rusqlite::params![
                    path,
                    record.sha256,
                    i64::try_from(record.size).unwrap_or(i64::MAX),
                    record.mode,
                    record.uid,
                    record.gid
                ],
            )
            .map(|_| ())
            .map_err(|error| HostError::Baseline {
                detail: error.to_string(),
            })
    }

    /// Forget one path.
    pub fn remove(&self, path: &str) -> Result<(), HostError> {
        self.connection
            .execute("DELETE FROM baseline WHERE path = ?1", [path])
            .map(|_| ())
            .map_err(|error| HostError::Baseline {
                detail: error.to_string(),
            })
    }

    /// Every path the baseline knows that starts with `prefix`.
    ///
    /// Used to find deletions: a path in the baseline that the walk did not
    /// reach is a path that is gone.
    pub fn paths_under(&self, prefix: &str) -> Result<Vec<String>, HostError> {
        // LIKE with an escaped prefix — a configured path containing `%` or `_`
        // must not turn into a wildcard that sweeps in unrelated entries.
        let pattern = format!(
            "{}%",
            prefix
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        let mut statement = self
            .connection
            .prepare("SELECT path FROM baseline WHERE path LIKE ?1 ESCAPE '\\'")
            .map_err(|error| HostError::Baseline {
                detail: error.to_string(),
            })?;
        let rows = statement
            .query_map([pattern], |row| row.get::<_, String>(0))
            .map_err(|error| HostError::Baseline {
                detail: error.to_string(),
            })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| HostError::Baseline {
                detail: error.to_string(),
            })
    }

    /// How many files the baseline is tracking.
    pub fn len(&self) -> Result<u64, HostError> {
        self.connection
            .query_row("SELECT COUNT(*) FROM baseline", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(i64::unsigned_abs)
            .map_err(|error| HostError::Baseline {
                detail: error.to_string(),
            })
    }

    /// Whether the baseline has never been populated.
    pub fn is_empty(&self) -> Result<bool, HostError> {
        Ok(self.len()? == 0)
    }
}

// ---------------------------------------------------------------------------
// walking and rescanning
// ---------------------------------------------------------------------------

/// What a walk hit, beyond the files it found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalkLimits {
    /// Entries skipped because [`FimSettings::max_entries`] was reached.
    pub over_entry_limit: u64,
    /// Directories not descended into because of [`FimSettings::max_depth`].
    pub over_depth_limit: u64,
    /// Paths that could not be read.
    pub unreadable: u64,
    /// Symlinks not followed.
    pub symlinks_skipped: u64,
    /// The scan was asked to stop before it finished.
    pub abandoned: bool,
}

impl WalkLimits {
    /// Whether anything was left out.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.abandoned
            || self.over_entry_limit > 0
            || self.over_depth_limit > 0
            || self.unreadable > 0
    }
}

/// Collect the regular files under a set of roots, bounded.
///
/// Returns paths in sorted order so a rescan is deterministic and so tests can
/// assert on it. Symlinks are counted and skipped rather than followed —
/// following them would let a symlink planted inside a watched directory pull
/// the whole filesystem into the monitored set.
#[must_use]
pub fn walk(roots: &[PathBuf], settings: &FimSettings) -> (Vec<PathBuf>, WalkLimits) {
    let mut found = BTreeSet::new();
    let mut limits = WalkLimits::default();

    for root in roots {
        let mut stack = vec![(root.clone(), 0_usize)];
        while let Some((path, depth)) = stack.pop() {
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                limits.unreadable += 1;
                continue;
            };

            if metadata.is_symlink() {
                limits.symlinks_skipped += 1;
                continue;
            }

            if metadata.is_file() {
                if found.len() >= settings.max_entries {
                    limits.over_entry_limit += 1;
                    continue;
                }
                found.insert(path);
                continue;
            }

            if !metadata.is_dir() {
                continue;
            }
            if depth >= settings.max_depth {
                limits.over_depth_limit += 1;
                continue;
            }
            let Ok(entries) = fs::read_dir(&path) else {
                limits.unreadable += 1;
                continue;
            };
            for entry in entries {
                match entry {
                    Ok(entry) => stack.push((entry.path(), depth + 1)),
                    Err(_) => limits.unreadable += 1,
                }
            }
        }
    }

    (found.into_iter().collect(), limits)
}

/// What a rescan produced.
#[derive(Debug, Default)]
pub struct RescanOutcome {
    /// The differences found, ready to emit.
    pub events: Vec<FimEvent>,
    /// Files compared.
    pub files_seen: u64,
    /// What the walk had to leave out.
    pub limits: WalkLimits,
}

/// The baseline comparator.
///
/// Deliberately separate from the watcher: this half needs no kernel support,
/// which is what lets it be tested exhaustively and what lets it run on a
/// machine where real-time watching failed entirely.
#[derive(Debug)]
pub struct Monitor {
    settings: FimSettings,
    baseline: Baseline,
}

impl Monitor {
    /// Build a monitor over an open baseline.
    #[must_use]
    pub fn new(settings: FimSettings, baseline: Baseline) -> Self {
        Self { settings, baseline }
    }

    /// The configuration in force.
    #[must_use]
    pub fn settings(&self) -> &FimSettings {
        &self.settings
    }

    /// The baseline store.
    #[must_use]
    pub fn baseline(&self) -> &Baseline {
        &self.baseline
    }

    /// Walk the configured roots and report every difference from the baseline.
    ///
    /// `detected_by` distinguishes the scheduled sweep from the one an overflow
    /// forced, because an analyst reading a change found by rescan needs to
    /// know real-time watching missed it.
    ///
    /// The **first** scan of an empty baseline establishes it and reports
    /// nothing. Every file on the box is not a thousand alerts; it is the
    /// starting position.
    pub fn rescan(&mut self, detected_by: FimDetection) -> Result<RescanOutcome, HostError> {
        self.rescan_until(detected_by, &mut || true)
    }

    /// [`Self::rescan`], abandoned as soon as `should_continue` says stop.
    ///
    /// A first scan of `/etc` and `/usr/bin` hashes tens of thousands of files
    /// and takes real time. Without a way to abandon it, shutdown would have to
    /// wait for it to finish — a sensor that ignores SIGTERM for a minute is a
    /// sensor a service manager kills, and an operator distrusts.
    ///
    /// An abandoned scan is treated exactly like one that hit a bound: partial
    /// results, `limits.truncated()` set, and therefore no deletions inferred.
    /// What was recorded still lands in the baseline, so the next run resumes
    /// from a better starting point rather than from nothing.
    pub fn rescan_until(
        &mut self,
        detected_by: FimDetection,
        should_continue: &mut dyn FnMut() -> bool,
    ) -> Result<RescanOutcome, HostError> {
        let establishing = self.baseline.is_empty()?;
        let (paths, limits) = walk(&self.settings.paths, &self.settings);
        let mut outcome = RescanOutcome {
            limits,
            ..RescanOutcome::default()
        };

        let mut seen = BTreeSet::new();
        for path in paths {
            if !should_continue() {
                // Abandoned, not finished. Saying so is what stops the
                // deletion pass below from reading "we stopped looking" as
                // "everything else is gone".
                outcome.limits.abandoned = true;
                return Ok(outcome);
            }
            let key = path.to_string_lossy().into_owned();
            seen.insert(key.clone());
            outcome.files_seen += 1;

            let current = match inspect(&path, self.settings.max_file_bytes) {
                Ok(Some(record)) => record,
                Ok(None) => continue,
                Err(_) => {
                    outcome.limits.unreadable += 1;
                    continue;
                }
            };
            let previous = self.baseline.get(&key)?;
            self.baseline.put(&key, &current)?;

            if establishing {
                continue;
            }
            if let Some(event) = difference(&key, previous.as_ref(), &current, detected_by) {
                outcome.events.push(event);
            }
        }

        // Anything the baseline knows about under a watched root that the walk
        // did not reach has been deleted. Skipped when the walk was truncated:
        // a bound that bit means "we did not look", not "it is gone", and
        // reporting mass deletions there would be a lie an attacker can induce.
        if !establishing && !outcome.limits.truncated() {
            for root in self.settings.paths.clone() {
                let prefix = root.to_string_lossy().into_owned();
                for known in self.baseline.paths_under(&prefix)? {
                    if seen.contains(&known) {
                        continue;
                    }
                    let previous = self.baseline.get(&known)?;
                    self.baseline.remove(&known)?;
                    outcome.events.push(FimEvent {
                        path: known,
                        change: FileChange::Deleted,
                        detected_by,
                        size: None,
                        sha256: None,
                        previous_sha256: previous.and_then(|record| record.sha256),
                        mode: None,
                        uid: None,
                        gid: None,
                    });
                }
            }
        }

        Ok(outcome)
    }

    /// Re-check a single path, as a real-time notification asks us to.
    ///
    /// Real-time events say *something happened here*; this is what turns that
    /// into *what actually changed*, with hashes, by comparing against the
    /// baseline rather than trusting the notification's own idea of the change.
    /// A rename that produced identical bytes is not a modification, and a
    /// notification for an unchanged file produces no event at all.
    pub fn recheck(&mut self, path: &Path) -> Result<Option<FimEvent>, HostError> {
        if !self.is_watched(path) {
            return Ok(None);
        }
        let key = path.to_string_lossy().into_owned();
        let previous = self.baseline.get(&key)?;

        match inspect(path, self.settings.max_file_bytes) {
            Ok(Some(current)) => {
                self.baseline.put(&key, &current)?;
                Ok(difference(
                    &key,
                    previous.as_ref(),
                    &current,
                    FimDetection::RealTime,
                ))
            }
            Ok(None) => {
                // Gone, or never a regular file. Only the former is an event,
                // and only if we had it.
                let Some(previous) = previous else {
                    return Ok(None);
                };
                self.baseline.remove(&key)?;
                Ok(Some(FimEvent {
                    path: key,
                    change: FileChange::Deleted,
                    detected_by: FimDetection::RealTime,
                    size: None,
                    sha256: None,
                    previous_sha256: previous.sha256,
                    mode: None,
                    uid: None,
                    gid: None,
                }))
            }
            Err(_) => Ok(None),
        }
    }

    /// Whether a path falls under a configured root.
    ///
    /// The watcher is set on directories, so it reports paths we never asked
    /// about; this keeps the monitored set to what was configured.
    #[must_use]
    pub fn is_watched(&self, path: &Path) -> bool {
        self.settings
            .paths
            .iter()
            .any(|root| path == root || path.starts_with(root))
    }

    /// Loosen the entry bound. Test-only, to exercise truncation handling.
    #[cfg(test)]
    fn set_max_entries(&mut self, max_entries: usize) {
        self.settings.max_entries = max_entries;
    }
}

/// Compare a file against its baseline entry.
///
/// Content changes outrank attribute changes: if the bytes moved, that is the
/// finding, and the mode change that came with it is detail. Both hashes are
/// carried on the event so an analyst can tell a real edit from a `touch`.
fn difference(
    path: &str,
    previous: Option<&FileRecord>,
    current: &FileRecord,
    detected_by: FimDetection,
) -> Option<FimEvent> {
    let event = |change: FileChange, previous_sha256: Option<String>| FimEvent {
        path: path.to_string(),
        change,
        detected_by,
        size: Some(current.size),
        sha256: current.sha256.clone(),
        previous_sha256,
        mode: Some(current.mode),
        uid: Some(current.uid),
        gid: Some(current.gid),
    };

    let Some(previous) = previous else {
        return Some(event(FileChange::Created, None));
    };

    // An unhashable file (too large, unreadable) falls back to size — a coarse
    // signal, but better than none, and the absent hash says which it was.
    let content_changed = match (&previous.sha256, &current.sha256) {
        (Some(before), Some(after)) => before != after,
        _ => previous.size != current.size,
    };
    if content_changed {
        return Some(event(FileChange::Modified, previous.sha256.clone()));
    }

    if previous.mode != current.mode || previous.uid != current.uid || previous.gid != current.gid {
        return Some(event(
            FileChange::AttributesChanged,
            previous.sha256.clone(),
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn settings(root: &Path) -> FimSettings {
        FimSettings {
            paths: vec![root.to_path_buf()],
            ..FimSettings::default()
        }
    }

    fn monitor(root: &Path) -> Monitor {
        Monitor::new(
            settings(root),
            Baseline::open(None).expect("in-memory baseline"),
        )
    }

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        let mut file = File::create(path).expect("create");
        file.write_all(contents.as_bytes()).expect("write");
    }

    #[test]
    fn the_first_scan_establishes_rather_than_alerts() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(&dir.path().join("passwd"), "root:x:0:0");
        write(&dir.path().join("shadow"), "root:!:0");

        let mut monitor = monitor(dir.path());
        let outcome = monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        assert!(
            outcome.events.is_empty(),
            "establishing the baseline is not two thousand alerts"
        );
        assert_eq!(outcome.files_seen, 2);
        assert_eq!(monitor.baseline().len().expect("len"), 2);
    }

    #[test]
    fn a_content_change_is_a_modification_with_both_hashes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("sudoers");
        write(&target, "root ALL=(ALL) ALL");

        let mut monitor = monitor(dir.path());
        monitor.rescan(FimDetection::BaselineRescan).expect("scan");
        let before = monitor
            .baseline()
            .get(&target.to_string_lossy())
            .expect("get")
            .and_then(|record| record.sha256);

        write(
            &target,
            "root ALL=(ALL) ALL\nattacker ALL=(ALL) NOPASSWD: ALL",
        );
        let outcome = monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        assert_eq!(outcome.events.len(), 1);
        let event = &outcome.events[0];
        assert_eq!(event.change, FileChange::Modified);
        assert_eq!(event.previous_sha256, before);
        assert_ne!(event.sha256, before);
        assert!(event.sha256.is_some());
    }

    #[test]
    fn a_new_file_is_a_creation_and_a_removed_one_a_deletion() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(&dir.path().join("keep"), "a");
        write(&dir.path().join("goes"), "b");

        let mut monitor = monitor(dir.path());
        monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        fs::remove_file(dir.path().join("goes")).expect("remove");
        write(&dir.path().join("appears"), "c");
        let outcome = monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        let changes: Vec<_> = outcome
            .events
            .iter()
            .map(|event| (event.change, event.path.clone()))
            .collect();
        assert!(changes.contains(&(
            FileChange::Created,
            dir.path().join("appears").to_string_lossy().into_owned()
        )));
        assert!(changes.contains(&(
            FileChange::Deleted,
            dir.path().join("goes").to_string_lossy().into_owned()
        )));
        assert_eq!(changes.len(), 2, "the untouched file is not an event");
    }

    #[test]
    fn a_deletion_carries_the_hash_of_what_was_lost() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("audit.rules");
        write(&target, "-w /etc/passwd -p wa");

        let mut monitor = monitor(dir.path());
        monitor.rescan(FimDetection::BaselineRescan).expect("scan");
        fs::remove_file(&target).expect("remove");
        let outcome = monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        assert_eq!(outcome.events.len(), 1);
        assert_eq!(outcome.events[0].change, FileChange::Deleted);
        assert!(
            outcome.events[0].previous_sha256.is_some(),
            "what the file used to be is the only evidence left"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_mode_change_alone_is_an_attribute_change() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("script.sh");
        write(&target, "#!/bin/sh\n");

        let mut monitor = monitor(dir.path());
        monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        fs::set_permissions(&target, fs::Permissions::from_mode(0o4_755)).expect("chmod");
        let outcome = monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        assert_eq!(outcome.events.len(), 1);
        let event = &outcome.events[0];
        assert_eq!(event.change, FileChange::AttributesChanged);
        assert_eq!(
            event.sha256, event.previous_sha256,
            "same bytes: the hashes prove the content did not move"
        );
        assert_eq!(event.mode.map(|mode| mode & 0o7_777), Some(0o4_755));
    }

    #[test]
    fn an_unchanged_tree_produces_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(&dir.path().join("a"), "x");
        let mut monitor = monitor(dir.path());
        monitor.rescan(FimDetection::BaselineRescan).expect("scan");
        for _ in 0..3 {
            let outcome = monitor.rescan(FimDetection::BaselineRescan).expect("scan");
            assert!(outcome.events.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // the adversarial cases
    // -----------------------------------------------------------------------

    /// **real-time-missed-it → periodic-rescan-caught-it.**
    ///
    /// The whole reason the baseline exists. A change made with no watcher
    /// running — sensor down, watch never established, events dropped — is
    /// still found, and the event says so.
    #[test]
    fn a_change_made_while_nothing_was_watching_is_caught_by_the_rescan() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path().join("state/baseline.db");
        let watched = dir.path().join("etc");
        write(&watched.join("passwd"), "root:x:0:0:root:/root:/bin/bash");

        let config = FimSettings {
            paths: vec![watched.clone()],
            baseline_path: Some(store.clone()),
            ..FimSettings::default()
        };

        // First run: the sensor establishes the baseline, then stops.
        {
            let mut monitor = Monitor::new(
                config.clone(),
                Baseline::open(Some(&store)).expect("baseline"),
            );
            monitor.rescan(FimDetection::BaselineRescan).expect("scan");
        }

        // Sensor is down. Nobody is watching. The file changes.
        write(
            &watched.join("passwd"),
            "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/sh",
        );

        // Second run: a fresh process, a fresh watcher that saw nothing.
        let mut monitor = Monitor::new(config, Baseline::open(Some(&store)).expect("baseline"));
        let outcome = monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        assert_eq!(outcome.events.len(), 1, "the offline change must surface");
        let event = &outcome.events[0];
        assert_eq!(event.change, FileChange::Modified);
        assert_eq!(
            event.detected_by,
            FimDetection::BaselineRescan,
            "and it must be labelled as found by rescan, not claimed as real-time"
        );
        assert!(event.previous_sha256.is_some() && event.sha256 != event.previous_sha256);
    }

    #[test]
    fn the_baseline_survives_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path().join("baseline.db");
        write(&dir.path().join("watched/a"), "one");
        let config = FimSettings {
            paths: vec![dir.path().join("watched")],
            baseline_path: Some(store.clone()),
            ..FimSettings::default()
        };

        {
            let mut monitor =
                Monitor::new(config.clone(), Baseline::open(Some(&store)).expect("open"));
            monitor.rescan(FimDetection::BaselineRescan).expect("scan");
        }
        let reopened = Baseline::open(Some(&store)).expect("reopen");
        assert_eq!(reopened.len().expect("len"), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_not_followed_out_of_the_watched_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("outside");
        write(&outside.join("secret"), "not ours to watch");
        let watched = dir.path().join("watched");
        fs::create_dir_all(&watched).expect("mkdir");
        std::os::unix::fs::symlink(&outside, watched.join("link")).expect("symlink");

        let config = FimSettings {
            paths: vec![watched],
            ..FimSettings::default()
        };
        let (paths, limits) = walk(&config.paths, &config);
        assert!(paths.is_empty(), "a symlink must not widen the scope");
        assert_eq!(limits.symlinks_skipped, 1);
    }

    #[test]
    fn the_entry_limit_is_enforced_and_counted() {
        let dir = tempfile::tempdir().expect("tempdir");
        for index in 0..20 {
            write(&dir.path().join(format!("file{index}")), "x");
        }
        let config = FimSettings {
            paths: vec![dir.path().to_path_buf()],
            max_entries: 5,
            ..FimSettings::default()
        };
        let (paths, limits) = walk(&config.paths, &config);
        assert_eq!(paths.len(), 5);
        assert!(limits.over_entry_limit > 0, "truncation must be visible");
        assert!(limits.truncated());
    }

    #[test]
    fn the_depth_limit_is_enforced_and_counted() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(&dir.path().join("a/b/c/d/deep"), "x");
        let config = FimSettings {
            paths: vec![dir.path().to_path_buf()],
            max_depth: 2,
            ..FimSettings::default()
        };
        let (paths, limits) = walk(&config.paths, &config);
        assert!(paths.is_empty());
        assert!(limits.over_depth_limit > 0);
    }

    /// A truncated walk must not be read as mass deletion. Otherwise an
    /// attacker who can make the walk hit its bound gets to bury a real change
    /// under thousands of fabricated ones.
    /// Shutdown must not have to wait for a scan of `/usr/bin` to finish.
    #[test]
    fn a_scan_can_be_abandoned_partway_and_says_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        for index in 0..50 {
            write(&dir.path().join(format!("file{index}")), "x");
        }
        let mut monitor = monitor(dir.path());

        let mut remaining = 5;
        let outcome = monitor
            .rescan_until(FimDetection::BaselineRescan, &mut || {
                remaining -= 1;
                remaining > 0
            })
            .expect("scan");

        assert!(outcome.limits.abandoned);
        assert!(outcome.limits.truncated());
        assert!(outcome.files_seen < 50, "it stopped early, as asked");
        assert!(
            monitor.baseline().len().expect("len") > 0,
            "what it did record still counts: the next run starts further along"
        );
    }

    /// An abandoned scan must not read as mass deletion, for the same reason a
    /// bounded one must not: we stopped looking, the files did not vanish.
    #[test]
    fn an_abandoned_scan_does_not_report_deletions() {
        let dir = tempfile::tempdir().expect("tempdir");
        for index in 0..20 {
            write(&dir.path().join(format!("file{index}")), "x");
        }
        let mut monitor = monitor(dir.path());
        monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        let mut remaining = 3;
        let outcome = monitor
            .rescan_until(FimDetection::BaselineRescan, &mut || {
                remaining -= 1;
                remaining > 0
            })
            .expect("scan");
        assert!(outcome
            .events
            .iter()
            .all(|event| event.change != FileChange::Deleted));
    }

    #[test]
    fn a_truncated_walk_does_not_report_deletions() {
        let dir = tempfile::tempdir().expect("tempdir");
        for index in 0..10 {
            write(&dir.path().join(format!("file{index}")), "x");
        }
        let mut monitor = monitor(dir.path());
        monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        monitor.set_max_entries(3);
        let outcome = monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        assert!(
            !outcome
                .events
                .iter()
                .any(|event| event.change == FileChange::Deleted),
            "hitting a bound means we did not look, not that the files are gone"
        );
        assert!(outcome.limits.truncated());
    }

    #[test]
    fn an_oversized_file_is_tracked_by_size_without_hashing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("big");
        write(&target, "aaaaaaaaaa");

        let config = FimSettings {
            paths: vec![dir.path().to_path_buf()],
            max_file_bytes: 4,
            ..FimSettings::default()
        };
        let mut monitor = Monitor::new(config, Baseline::open(None).expect("baseline"));
        monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        // Unhashable files fall back to size, so a same-length edit is genuinely
        // missed — the absent hash on the event is what says so.
        write(&target, "bbbbbbbbbbbb");
        let outcome = monitor.rescan(FimDetection::BaselineRescan).expect("scan");
        assert_eq!(outcome.events.len(), 1);
        assert_eq!(outcome.events[0].change, FileChange::Modified);
        assert!(outcome.events[0].sha256.is_none());
    }

    #[test]
    fn a_path_that_does_not_exist_is_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = FimSettings {
            paths: vec![dir.path().join("nope"), dir.path().join("also/nope")],
            ..FimSettings::default()
        };
        let mut monitor = Monitor::new(config, Baseline::open(None).expect("baseline"));
        let outcome = monitor.rescan(FimDetection::BaselineRescan).expect("scan");
        assert!(outcome.events.is_empty());
        assert!(outcome.limits.unreadable > 0);
    }

    #[test]
    fn a_prefix_lookup_does_not_treat_configured_paths_as_wildcards() {
        let baseline = Baseline::open(None).expect("baseline");
        let record = FileRecord {
            sha256: None,
            size: 0,
            mode: 0,
            uid: 0,
            gid: 0,
        };
        baseline.put("/etc/my_app/conf", &record).expect("put");
        baseline.put("/etc/myXapp/conf", &record).expect("put");

        let found = baseline.paths_under("/etc/my_app").expect("query");
        assert_eq!(
            found,
            vec!["/etc/my_app/conf".to_string()],
            "`_` in a configured path is a literal, not a LIKE wildcard"
        );
    }

    // -----------------------------------------------------------------------
    // real-time recheck
    // -----------------------------------------------------------------------

    #[test]
    fn a_recheck_outside_the_watched_set_is_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let watched = dir.path().join("watched");
        fs::create_dir_all(&watched).expect("mkdir");
        let mut monitor = Monitor::new(
            FimSettings {
                paths: vec![watched],
                ..FimSettings::default()
            },
            Baseline::open(None).expect("baseline"),
        );
        write(&dir.path().join("elsewhere"), "x");
        assert!(monitor
            .recheck(&dir.path().join("elsewhere"))
            .expect("recheck")
            .is_none());
    }

    #[test]
    fn a_recheck_of_an_unchanged_file_produces_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("a");
        write(&target, "x");
        let mut monitor = monitor(dir.path());
        monitor.rescan(FimDetection::BaselineRescan).expect("scan");
        assert!(monitor.recheck(&target).expect("recheck").is_none());
    }

    #[test]
    fn a_recheck_reports_a_change_as_real_time() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("a");
        write(&target, "x");
        let mut monitor = monitor(dir.path());
        monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        write(&target, "y");
        let event = monitor
            .recheck(&target)
            .expect("recheck")
            .expect("an event");
        assert_eq!(event.change, FileChange::Modified);
        assert_eq!(event.detected_by, FimDetection::RealTime);
    }

    #[test]
    fn a_recheck_after_deletion_reports_a_deletion_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("a");
        write(&target, "x");
        let mut monitor = monitor(dir.path());
        monitor.rescan(FimDetection::BaselineRescan).expect("scan");

        fs::remove_file(&target).expect("remove");
        let event = monitor
            .recheck(&target)
            .expect("recheck")
            .expect("an event");
        assert_eq!(event.change, FileChange::Deleted);
        assert!(
            monitor.recheck(&target).expect("recheck").is_none(),
            "a second notification for the same deletion is not a second deletion"
        );
    }
}
