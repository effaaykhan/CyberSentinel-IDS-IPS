//! Process and listening-socket monitoring.
//!
//! Reads `/proc` rather than hooking anything. That is a deliberate trade: a
//! poller misses processes that start and exit between sweeps, where an
//! audit-subsystem or eBPF hook would not. In exchange it needs no kernel
//! module, no `CAP_BPF`, no auditd configuration, and it cannot wedge the
//! machine — and the sensor's promise is that installing it never makes the
//! host worse. Phase 7 can add an audit-backed source alongside this one.
//!
//! Two things are reported, both from the same sweep:
//!
//! * **New processes** — a pid appearing that the previous sweep did not have.
//!   Compared by `(pid, start-time)`, not pid alone, so a recycled pid reads as
//!   a new process rather than the old one continuing.
//! * **New listening sockets** — a `LISTEN`-state entry in `/proc/net/tcp*`
//!   whose local address the previous sweep did not have. That is the signal
//!   that matters for a backdoor: something on this host is now accepting
//!   connections that was not before.
//!
//! Every reader is parameterised on the `/proc` root so the whole module is
//! testable against a fixture tree, with no privileges and no real processes.
//!
//! Windows (ETW) and macOS (unified log, possibly Endpoint Security) arrive in
//! Phases 5 and 6 behind the same [`Watcher`] shape.

use cybersentinel_common::event::{ProcessChange, ProcessEvent};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

/// Most processes tracked. Beyond this the sweep stops and reports truncation
/// rather than growing without bound on a fork-bombed host.
pub const DEFAULT_MAX_PROCESSES: usize = 16_384;
/// Most listening sockets tracked.
pub const DEFAULT_MAX_SOCKETS: usize = 8_192;
/// Longest command line kept on an event.
const MAX_COMMAND_LINE: usize = 4_096;

/// Identity of a running process.
///
/// The start time is part of the identity because pids are recycled. Without
/// it, a short-lived process exiting and its pid being reused looks like
/// nothing happened at all.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProcessKey {
    /// Process id.
    pub pid: u32,
    /// Start time in kernel clock ticks since boot, from `/proc/<pid>/stat`.
    pub start_time: u64,
}

/// What a sweep found about one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Identity.
    pub key: ProcessKey,
    /// Executable name.
    pub name: String,
    /// Resolved path to the executable, where the link could be read.
    pub executable: Option<String>,
    /// Command line, NUL-separated in `/proc`, joined and truncated here.
    pub command_line: Option<String>,
    /// Real user id.
    pub uid: Option<u32>,
    /// Parent pid.
    pub parent_pid: Option<u32>,
}

/// A socket in `LISTEN` state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ListeningSocket {
    /// Where it is listening.
    pub address: SocketAddr,
    /// Owning socket inode, used to attribute it to a process.
    pub inode: u64,
}

/// One sweep of `/proc`.
#[derive(Debug, Default)]
pub struct Snapshot {
    /// Live processes by identity.
    pub processes: BTreeMap<ProcessKey, ProcessInfo>,
    /// Listening sockets by local address.
    pub listening: BTreeMap<SocketAddr, ListeningSocket>,
    /// Entries dropped because a bound was reached.
    pub truncated: u64,
    /// Entries that could not be read — usually a process that exited
    /// mid-sweep, which is normal and not an error.
    pub unreadable: u64,
}

/// Bounds for a sweep.
#[derive(Debug, Clone, Copy)]
pub struct ScanLimits {
    /// Most processes tracked.
    pub max_processes: usize,
    /// Most sockets tracked.
    pub max_sockets: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_processes: DEFAULT_MAX_PROCESSES,
            max_sockets: DEFAULT_MAX_SOCKETS,
        }
    }
}

/// Take one sweep of a `/proc` tree.
#[must_use]
pub fn snapshot(proc_root: &Path, limits: ScanLimits) -> Snapshot {
    let mut snapshot = Snapshot::default();

    let Ok(entries) = fs::read_dir(proc_root) else {
        snapshot.unreadable += 1;
        return snapshot;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue; // not a pid directory
        };
        if snapshot.processes.len() >= limits.max_processes {
            snapshot.truncated += 1;
            continue;
        }
        match read_process(&entry.path(), pid) {
            Some(info) => {
                snapshot.processes.insert(info.key.clone(), info);
            }
            None => snapshot.unreadable += 1,
        }
    }

    // Only TCP LISTEN is reported. UDP has no listen state, and a bound UDP
    // socket is far more often ordinary than interesting.
    for (file, is_v6) in [("net/tcp", false), ("net/tcp6", true)] {
        let Ok(text) = fs::read_to_string(proc_root.join(file)) else {
            continue;
        };
        for socket in parse_net_table(&text, is_v6) {
            if snapshot.listening.len() >= limits.max_sockets {
                snapshot.truncated += 1;
                break;
            }
            snapshot.listening.insert(socket.address, socket);
        }
    }

    snapshot
}

/// Read one `/proc/<pid>` directory.
fn read_process(dir: &Path, pid: u32) -> Option<ProcessInfo> {
    // `/proc/<pid>/stat` is the one file readable for another user's process,
    // and it carries the start time our identity needs.
    let stat = fs::read_to_string(dir.join("stat")).ok()?;
    let (name, parent_pid, start_time) = parse_stat(&stat)?;

    let executable = fs::read_link(dir.join("exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned());

    let command_line = fs::read(dir.join("cmdline")).ok().and_then(|raw| {
        let joined = String::from_utf8_lossy(&raw)
            .split('\0')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if joined.is_empty() {
            None
        } else {
            Some(sanitise(&joined, MAX_COMMAND_LINE))
        }
    });

    let uid = fs::read_to_string(dir.join("status"))
        .ok()
        .and_then(|status| parse_status_uid(&status));

    Some(ProcessInfo {
        key: ProcessKey { pid, start_time },
        name,
        executable,
        command_line,
        uid,
        parent_pid,
    })
}

/// Strip control characters and bound the length.
///
/// A process name and command line are attacker-chosen strings that end up in
/// an event log somebody will `cat`. Same reasoning as the log parser.
fn sanitise(text: &str, limit: usize) -> String {
    text.chars()
        .take(limit)
        .map(|character| {
            if character.is_control() {
                '.'
            } else {
                character
            }
        })
        .collect()
}

/// Parse `/proc/<pid>/stat` into `(comm, ppid, starttime)`.
///
/// The `comm` field is parenthesised **and may itself contain spaces and
/// parentheses** — a process can call itself `foo) R 1 1 1`. Splitting on
/// whitespace from the left is therefore wrong, and is a real way for a process
/// to misreport its own parent. Fields are located from the **last** `)`,
/// which is unambiguous.
#[must_use]
pub fn parse_stat(stat: &str) -> Option<(String, Option<u32>, u64)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close < open {
        return None;
    }
    let name = sanitise(stat.get(open + 1..close)?, 128);

    // After `) ` come state, ppid, pgrp, session, ... with starttime the 22nd
    // field overall, i.e. index 19 in this remainder.
    let rest: Vec<&str> = stat.get(close + 1..)?.split_whitespace().collect();
    let parent_pid = rest.get(1).and_then(|field| field.parse::<u32>().ok());
    let start_time = rest.get(19).and_then(|field| field.parse::<u64>().ok())?;

    Some((name, parent_pid, start_time))
}

/// Pull the real uid out of `/proc/<pid>/status`.
#[must_use]
pub fn parse_status_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|field| field.parse().ok())
}

/// Parse `/proc/net/tcp` or `/proc/net/tcp6`, returning only `LISTEN` entries.
///
/// Format is whitespace-separated hex fields:
/// `sl local rem st tx:rx tr:when retrnsmt uid timeout inode`.
/// State `0A` is `TCP_LISTEN`.
#[must_use]
pub fn parse_net_table(text: &str, is_v6: bool) -> Vec<ListeningSocket> {
    let mut sockets = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(local), Some(state)) = (fields.get(1), fields.get(3)) else {
            continue;
        };
        if !state.eq_ignore_ascii_case("0A") {
            continue;
        }
        let Some(address) = parse_hex_address(local, is_v6) else {
            continue;
        };
        let inode = fields
            .get(9)
            .and_then(|field| field.parse::<u64>().ok())
            .unwrap_or(0);
        sockets.push(ListeningSocket { address, inode });
    }
    sockets
}

/// Decode a `HEXADDR:HEXPORT` field.
///
/// The kernel writes the address in host byte order per 32-bit word, which is
/// why each word is read as an integer and re-emitted little-endian.
fn parse_hex_address(field: &str, is_v6: bool) -> Option<SocketAddr> {
    let (address, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;

    if is_v6 {
        if address.len() != 32 {
            return None;
        }
        let mut octets = [0_u8; 16];
        for (index, chunk) in address.as_bytes().chunks(8).enumerate() {
            let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
            octets[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
    } else {
        if address.len() != 8 {
            return None;
        }
        let word = u32::from_str_radix(address, 16).ok()?;
        let [a, b, c, d] = word.to_le_bytes();
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port))
    }
}

/// Compares consecutive sweeps and reports what is new.
#[derive(Debug)]
pub struct Watcher {
    proc_root: PathBuf,
    limits: ScanLimits,
    known_processes: BTreeSet<ProcessKey>,
    known_listening: BTreeSet<SocketAddr>,
    established: bool,
}

/// What a sweep concluded.
#[derive(Debug, Default)]
pub struct SweepOutcome {
    /// New processes and newly listening sockets.
    pub events: Vec<ProcessEvent>,
    /// Entries dropped because a bound was reached.
    pub truncated: u64,
    /// How many processes the sweep could see at all.
    ///
    /// Not a statistic: it is how the caller tells "quiet host" from "blinded
    /// sensor". A process table always contains at least this process, so a
    /// sweep that sees one or none is not watching a machine where nothing
    /// happened — something has restricted its view of `/proc`.
    pub processes_seen: usize,
    /// How many listening sockets the sweep could see.
    pub sockets_seen: usize,
}

impl Watcher {
    /// Watch a `/proc` tree.
    #[must_use]
    pub fn new(proc_root: impl Into<PathBuf>, limits: ScanLimits) -> Self {
        Self {
            proc_root: proc_root.into(),
            limits,
            known_processes: BTreeSet::new(),
            known_listening: BTreeSet::new(),
            established: false,
        }
    }

    /// Take a sweep and report what changed since the last one.
    ///
    /// The first sweep establishes the picture and reports nothing — every
    /// process already running at startup is not a detection.
    pub fn sweep(&mut self) -> SweepOutcome {
        let snapshot = snapshot(&self.proc_root, self.limits);
        let mut outcome = SweepOutcome {
            truncated: snapshot.truncated,
            processes_seen: snapshot.processes.len(),
            sockets_seen: snapshot.listening.len(),
            ..SweepOutcome::default()
        };

        if self.established {
            for (key, info) in &snapshot.processes {
                if self.known_processes.contains(key) {
                    continue;
                }
                outcome.events.push(ProcessEvent {
                    change: ProcessChange::Started,
                    pid: info.key.pid,
                    name: info.name.clone(),
                    executable: info.executable.clone(),
                    command_line: info.command_line.clone(),
                    uid: info.uid,
                    parent_pid: info.parent_pid,
                });
            }

            for (address, socket) in &snapshot.listening {
                if self.known_listening.contains(address) {
                    continue;
                }
                // Attribute the socket to a process where we can. The inode
                // link needs `/proc/<pid>/fd`, which is root-only; when that is
                // unavailable the event still reports the socket, because "this
                // host started listening on 4444" is the finding and "we do not
                // know which process" is a detail.
                let owner = self.owner_of(&snapshot, socket.inode);
                outcome.events.push(ProcessEvent {
                    change: ProcessChange::Listening,
                    pid: owner.as_ref().map_or(0, |info| info.key.pid),
                    name: owner
                        .as_ref()
                        .map_or_else(|| "unknown".to_string(), |info| info.name.clone()),
                    executable: owner.as_ref().and_then(|info| info.executable.clone()),
                    command_line: Some(format!("listening on {address}")),
                    uid: owner.as_ref().and_then(|info| info.uid),
                    parent_pid: owner.as_ref().and_then(|info| info.parent_pid),
                });
            }
        }

        self.known_processes = snapshot.processes.keys().cloned().collect();
        self.known_listening = snapshot.listening.keys().copied().collect();
        self.established = true;
        outcome
    }

    /// Whether the socket table can be read at all.
    ///
    /// Separate from "are there any listening sockets", which can legitimately
    /// be zero. `/proc/net/tcp` exists on every Linux with a network stack, so
    /// its *absence* means something has hidden it — `ProcSubset=pid` does
    /// exactly this — and listening-socket detection is then off with nothing
    /// to show for it.
    #[must_use]
    pub fn sockets_readable(&self) -> bool {
        ["net/tcp", "net/tcp6"]
            .iter()
            .any(|file| self.proc_root.join(file).exists())
    }

    /// Find the process holding a socket inode, by scanning `/proc/<pid>/fd`.
    fn owner_of(&self, snapshot: &Snapshot, inode: u64) -> Option<ProcessInfo> {
        if inode == 0 {
            return None;
        }
        let needle = format!("socket:[{inode}]");
        for info in snapshot.processes.values() {
            let fd_dir = self.proc_root.join(info.key.pid.to_string()).join("fd");
            let Ok(entries) = fs::read_dir(&fd_dir) else {
                continue;
            };
            for entry in entries.flatten() {
                if fs::read_link(entry.path())
                    .is_ok_and(|target| target.to_string_lossy() == needle)
                {
                    return Some(info.clone());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        let mut file = fs::File::create(path).expect("create");
        file.write_all(contents.as_bytes()).expect("write");
    }

    /// Lay down a fake `/proc/<pid>` with the fields the reader needs.
    fn fake_process(root: &Path, pid: u32, name: &str, ppid: u32, start: u64, cmdline: &str) {
        let dir = root.join(pid.to_string());
        let mut stat = format!("{pid} ({name}) S {ppid}");
        // pgrp, session, tty, tpgid, flags, fault and time counters — up to
        // starttime at index 19 of the post-`)` remainder.
        for _ in 2..19 {
            stat.push_str(" 0");
        }
        stat.push_str(&format!(" {start} 0 0"));
        write(&dir.join("stat"), &stat);
        write(
            &dir.join("status"),
            "Name:\tx\nUid:\t1000\t1000\t1000\t1000\n",
        );
        write(&dir.join("cmdline"), &cmdline.replace(' ', "\0"));
    }

    #[test]
    fn parses_a_stat_line() {
        let (name, ppid, start) =
            parse_stat("42 (nginx) S 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 987654 0 0")
                .expect("parsed");
        assert_eq!(name, "nginx");
        assert_eq!(ppid, Some(1));
        assert_eq!(start, 987_654);
    }

    /// A process can name itself anything, including something that looks like
    /// the rest of the line. Locating fields from the last `)` is what stops a
    /// process from misreporting its own parent.
    #[test]
    fn a_process_cannot_forge_its_parent_through_its_name() {
        let honest = "42 (nginx) S 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0";
        let lying =
            "42 (evil) S 9999 0 0 0 0 0 0 0) S 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0";

        let (_, honest_ppid, _) = parse_stat(honest).expect("parsed");
        let (name, lying_ppid, start) = parse_stat(lying).expect("parsed");

        assert_eq!(honest_ppid, Some(1));
        assert_eq!(
            name, "evil) S 9999 0 0 0 0 0 0 0",
            "everything up to the last paren is the name, not a field"
        );
        assert_eq!(lying_ppid, Some(1), "the real ppid, not the embedded 9999");
        assert_eq!(start, 500);
    }

    #[test]
    fn control_characters_in_a_process_name_are_stripped() {
        let (name, _, _) =
            parse_stat("1 (ni\u{1b}[31mgx) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 7 0 0")
                .expect("parsed");
        assert!(!name.contains('\u{1b}'));
    }

    #[test]
    fn malformed_stat_lines_are_refused_not_fatal() {
        for line in ["", "1", "1 (x", "1 x) S 1", "1 (x) S", "()", ")("] {
            let _ = parse_stat(line);
        }
        assert!(
            parse_stat("1 (x) S 1").is_none(),
            "no starttime, no identity"
        );
    }

    #[test]
    fn parses_a_listening_tcp_entry() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
                     0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000    0 45678 1 0000 100 0\n   \
                     1: 0100007F:0016 0200007F:C1B4 01 00000000:00000000 00:00000000 00000000     0    0 45679 1 0000 100 0\n";
        let sockets = parse_net_table(table, false);
        assert_eq!(sockets.len(), 1, "only LISTEN entries");
        assert_eq!(sockets[0].address.to_string(), "127.0.0.1:8080");
        assert_eq!(sockets[0].inode, 45_678);
    }

    #[test]
    fn parses_a_listening_tcp6_entry() {
        let table = "  sl  local_address remote_address st\n   \
                     0: 00000000000000000000000000000000:115C 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 90210 1 0 100 0\n";
        let sockets = parse_net_table(table, true);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].address.port(), 4_444);
        assert!(sockets[0].address.ip().is_unspecified());
    }

    #[test]
    fn garbage_net_tables_yield_nothing_rather_than_panicking() {
        for table in ["", "header only", "x y z\n:::: 0A", "0: ZZZZ:ZZ x 0A", "0:"] {
            assert!(parse_net_table(table, false).is_empty());
            assert!(parse_net_table(table, true).is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // sweeps
    // -----------------------------------------------------------------------

    #[test]
    fn the_first_sweep_establishes_and_reports_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        fake_process(dir.path(), 1, "systemd", 0, 10, "/sbin/init");
        fake_process(dir.path(), 2, "sshd", 1, 20, "/usr/sbin/sshd -D");

        let mut watcher = Watcher::new(dir.path(), ScanLimits::default());
        assert!(
            watcher.sweep().events.is_empty(),
            "everything already running at startup is not a detection"
        );
    }

    #[test]
    fn a_new_process_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        fake_process(dir.path(), 1, "systemd", 0, 10, "/sbin/init");
        let mut watcher = Watcher::new(dir.path(), ScanLimits::default());
        watcher.sweep();

        fake_process(dir.path(), 1337, "nc", 1, 99, "nc -lvnp 4444 -e /bin/sh");
        let outcome = watcher.sweep();

        assert_eq!(outcome.events.len(), 1);
        let event = &outcome.events[0];
        assert_eq!(event.change, ProcessChange::Started);
        assert_eq!(event.pid, 1_337);
        assert_eq!(event.name, "nc");
        assert_eq!(
            event.command_line.as_deref(),
            Some("nc -lvnp 4444 -e /bin/sh")
        );
        assert_eq!(event.uid, Some(1_000));
        assert_eq!(event.parent_pid, Some(1));
    }

    #[test]
    fn an_unchanged_process_list_produces_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        fake_process(dir.path(), 1, "systemd", 0, 10, "/sbin/init");
        let mut watcher = Watcher::new(dir.path(), ScanLimits::default());
        watcher.sweep();
        for _ in 0..3 {
            assert!(watcher.sweep().events.is_empty());
        }
    }

    /// pids are recycled. Identity is `(pid, start-time)` so the reuse reads as
    /// a new process rather than as the old one quietly continuing.
    #[test]
    fn a_recycled_pid_is_a_new_process() {
        let dir = tempfile::tempdir().expect("tempdir");
        fake_process(dir.path(), 500, "sleep", 1, 100, "sleep 1");
        let mut watcher = Watcher::new(dir.path(), ScanLimits::default());
        watcher.sweep();

        fs::remove_dir_all(dir.path().join("500")).expect("remove");
        fake_process(dir.path(), 500, "bash", 1, 200, "bash -i");
        let outcome = watcher.sweep();

        assert_eq!(outcome.events.len(), 1);
        assert_eq!(outcome.events[0].name, "bash");
    }

    #[test]
    fn a_new_listening_socket_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        fake_process(dir.path(), 1, "systemd", 0, 10, "/sbin/init");
        write(&dir.path().join("net/tcp"), "  sl  local_address\n");

        let mut watcher = Watcher::new(dir.path(), ScanLimits::default());
        watcher.sweep();

        write(
            &dir.path().join("net/tcp"),
            "  sl  local_address rem_address st\n   \
             0: 00000000:115C 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 4242 1 0 100 0\n",
        );
        let outcome = watcher.sweep();

        assert_eq!(outcome.events.len(), 1);
        let event = &outcome.events[0];
        assert_eq!(event.change, ProcessChange::Listening);
        assert_eq!(
            event.command_line.as_deref(),
            Some("listening on 0.0.0.0:4444")
        );
    }

    #[test]
    fn a_socket_that_was_already_listening_is_not_reported_again() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            &dir.path().join("net/tcp"),
            "  sl  local_address rem_address st\n   \
             0: 00000000:0016 00000000:0000 0A 0 0 0 0 0 7 1 0 100 0\n",
        );
        let mut watcher = Watcher::new(dir.path(), ScanLimits::default());
        watcher.sweep();
        assert!(
            watcher.sweep().events.is_empty(),
            "sshd already listening is not a finding every sweep"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_listening_socket_is_attributed_to_its_process_when_fd_is_readable() {
        let dir = tempfile::tempdir().expect("tempdir");
        fake_process(dir.path(), 77, "backdoor", 1, 5, "./backdoor");
        write(&dir.path().join("net/tcp"), "  sl\n");
        let mut watcher = Watcher::new(dir.path(), ScanLimits::default());
        watcher.sweep();

        let fd_dir = dir.path().join("77/fd");
        fs::create_dir_all(&fd_dir).expect("mkdir");
        std::os::unix::fs::symlink("socket:[4242]", fd_dir.join("3")).expect("symlink");
        write(
            &dir.path().join("net/tcp"),
            "  sl  local_address rem_address st\n   \
             0: 00000000:115C 00000000:0000 0A 0 0 0 0 0 4242 1 0 100 0\n",
        );

        let outcome = watcher.sweep();
        assert_eq!(outcome.events.len(), 1);
        assert_eq!(outcome.events[0].name, "backdoor");
        assert_eq!(outcome.events[0].pid, 77);
    }

    #[test]
    fn an_unattributable_socket_is_still_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        write(&dir.path().join("net/tcp"), "  sl\n");
        let mut watcher = Watcher::new(dir.path(), ScanLimits::default());
        watcher.sweep();
        write(
            &dir.path().join("net/tcp"),
            "  sl  local_address rem_address st\n   \
             0: 00000000:115C 00000000:0000 0A 0 0 0 0 0 999999 1 0 100 0\n",
        );

        let outcome = watcher.sweep();
        assert_eq!(outcome.events.len(), 1);
        assert_eq!(
            outcome.events[0].name, "unknown",
            "not knowing the owner is no reason to hide the socket"
        );
    }

    #[test]
    fn the_process_limit_is_enforced_and_counted() {
        let dir = tempfile::tempdir().expect("tempdir");
        for pid in 1..=20 {
            fake_process(dir.path(), pid, "x", 1, u64::from(pid), "x");
        }
        let mut watcher = Watcher::new(
            dir.path(),
            ScanLimits {
                max_processes: 5,
                ..ScanLimits::default()
            },
        );
        assert!(
            watcher.sweep().truncated > 0,
            "a fork bomb must not be unbounded"
        );
    }

    #[test]
    fn a_missing_proc_tree_is_survivable() {
        let mut watcher = Watcher::new("/nonexistent/proc", ScanLimits::default());
        assert!(watcher.sweep().events.is_empty());
    }
}
