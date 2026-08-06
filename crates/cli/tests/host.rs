//! End-to-end tests for host-based detection **on Linux**.
//!
//! Gated to Linux as a whole rather than test by test. Parts of it would run
//! elsewhere — the FIM path is `notify`, which is cross-platform, and the
//! syslog parser is pure text — but the suite as written asserts Linux
//! backends: a `/proc` tree, `/proc/net/tcp`, and syslog-shaped auth records.
//! Letting the portable half run on Windows would report coverage for a
//! platform whose host backends do not exist yet, which is the opposite of
//! what this file is for. The Windows equivalent arrives with those backends.
#![cfg(target_os = "linux")]

//!
//! These are the Phase 4 acceptance criteria, driven through the real binary:
//! a watched file changes, a login fails repeatedly, a socket starts listening
//! — and each produces the host alert it should. Plus the two that matter most,
//! because they are what separates a sensor from a thing that reports what it
//! happened to be looking at:
//!
//! * a change made while nothing was watching is still found, and
//! * a host event and a network alert on the same host become one incident.
//!
//! Everything the sensor reads is under a scratch directory — the watched
//! paths, the authentication log, and `/proc` — so the tests need no
//! privileges, do not touch the machine they run on, and do not depend on what
//! happens to be installed.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

/// Scratch directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cybersentinel-host-{tag}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("creating the scratch directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn yaml(&self, name: &str) -> String {
        self.0.join(name).display().to_string().replace('\\', "/")
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("creating a parent directory");
        }
        std::fs::write(&path, contents).expect("writing a scratch file");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Host rules covering the three sensors.
const HOST_RULES: &str = r#"
alert ip any any -> any any (msg:"TEST FIM watched file changed"; \
    file.path:"WATCHED"; file.change:"modified,created"; \
    classtype:policy-violation; sid:1000101; rev:1;)

alert ip any any -> any any (msg:"TEST AUTH failed login burst"; \
    auth.outcome:"failure"; \
    threshold:type threshold, track by_src, count 3, seconds 60; \
    classtype:attempted-admin; sid:1000102; rev:1;)

alert ip any any -> any any (msg:"TEST PROCESS new listening socket"; \
    process.change:"listening"; \
    classtype:policy-violation; sid:1000103; rev:1;)
"#;

/// A minimal fake `/proc/<pid>` with the fields the reader needs.
fn fake_process(root: &Path, pid: u32, name: &str, start: u64) {
    let mut stat = format!("{pid} ({name}) S 1");
    for _ in 2..19 {
        stat.push_str(" 0");
    }
    stat.push_str(&format!(" {start} 0 0"));
    let dir = root.join(pid.to_string());
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(dir.join("stat"), stat).expect("write stat");
    std::fs::write(dir.join("status"), "Uid:\t1000\t1000\t1000\t1000\n").expect("write status");
    std::fs::write(dir.join("cmdline"), format!("./{name}\0")).expect("write cmdline");
}

/// A `/proc/net/tcp` table with one `LISTEN` entry on port 4444.
const LISTENING_ON_4444: &str = "  sl  local_address rem_address st\n   \
     0: 00000000:115C 00000000:0000 0A 0 0 0 0 0 4242 1 0 100 0\n";

/// Rewrite a capture's timestamps into the present.
///
/// Events carry the time the *packet* was captured, deliberately — replaying
/// last week's traffic must produce events dated last week. That is right, and
/// it means a committed fixture from months ago can never fall inside the
/// correlation window alongside a host event happening now. So correlating the
/// two end to end needs a capture that is recent, which is what this makes.
///
/// Little-endian pcap: a 24-byte global header, then per record
/// `ts_sec, ts_usec, incl_len, orig_len` followed by the frame.
fn restamp_pcap(source: &Path, destination: &Path) {
    let bytes = std::fs::read(source).expect("reading the fixture capture");
    assert!(bytes.len() > 24, "a capture has a global header");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs();

    let mut out = bytes[..24].to_vec();
    let mut offset = 24;
    while offset + 16 <= bytes.len() {
        let read32 = |at: usize| -> u32 {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let incl_len = read32(offset + 8) as usize;
        if offset + 16 + incl_len > bytes.len() {
            break; // a torn record: stop rather than invent one
        }
        out.extend_from_slice(&u32::try_from(now).unwrap_or(u32::MAX).to_le_bytes());
        out.extend_from_slice(&read32(offset + 4).to_le_bytes());
        out.extend_from_slice(&bytes[offset + 8..offset + 16 + incl_len]);
        offset += 16 + incl_len;
    }
    std::fs::write(destination, out).expect("writing the restamped capture");
}

/// Config common to these tests: everything scoped to the scratch directory.
fn config(scratch: &Scratch, extra: &str) -> PathBuf {
    let watched = scratch.yaml("watched");
    let rules = HOST_RULES.replace("WATCHED", &watched);
    scratch.write("host.rules", &rules);

    let text = format!(
        r#"
paths:
  data-dir: "{data}"
  log-dir: "{logs}"
rules:
  directory: "{dir}"
  files:
    - host.rules
hids:
  fim:
    paths:
      - "{watched}"
    baseline: "{baseline}"
    rescan-interval-secs: 1
  auth:
    journald: false
    files:
      - "{auth}"
  process:
    proc-root: "{proc}"
    interval-secs: 1
outputs:
  stdout:
    enabled: false
  file:
    enabled: true
    path: events.json
logging:
  level: warn
  queue-capacity: 256
stats:
  enabled: true
  interval-secs: 1
{extra}
"#,
        data = scratch.yaml("data"),
        logs = scratch.yaml("logs"),
        dir = scratch.path().display().to_string().replace('\\', "/"),
        baseline = scratch.yaml("data/baseline.db"),
        auth = scratch.yaml("auth.log"),
        proc = scratch.yaml("proc"),
    );
    scratch.write("config.yaml", &text)
}

/// Run the sensor for a moment, then stop it and return the events.
///
/// The sensor has no capture source here, so it runs the host-only loop until
/// signalled — which is exactly the shape of a FIM-and-auth-only install.
fn run_briefly(config: &Path, seconds: u64) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .arg("run")
        .arg("--config")
        .arg(config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("starting the sensor");

    std::thread::sleep(std::time::Duration::from_secs(seconds));
    stop(&mut child);

    let events_path = config
        .parent()
        .expect("a parent directory")
        .join("logs/events.json");
    read_events(&events_path)
}

/// Ask the sensor to shut down the way a service manager would.
fn stop(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // SIGTERM, so the shutdown path under test is the real one rather than
        // a kill that would tell us nothing about whether it drains cleanly.
        let pid = i32::try_from(child.id()).expect("a plausible pid");
        // SAFETY-free: `kill(1)` rather than libc, because this workspace
        // forbids unsafe code and a test is no place to make an exception.
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status();
    }
    for _ in 0..100 {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn read_events(path: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("every event line is JSON"))
        .collect()
}

/// The bodies of every event of one type.
///
/// Event JSON is an envelope plus a body nested under the event type, so this
/// hands back the bodies — which is what the assertions are about.
fn of_type<'a>(events: &'a [Value], event_type: &str) -> Vec<&'a Value> {
    events
        .iter()
        .filter(|event| event["event_type"] == event_type)
        .map(|event| &event[event_type])
        .collect()
}

fn has_sid(events: &[Value], sid: u64) -> bool {
    of_type(events, "alert")
        .iter()
        .any(|body| body["sid"] == sid)
}

// ---------------------------------------------------------------------------

/// A watched file changes; the FIM rule fires.
#[test]
fn a_watched_file_change_produces_a_host_alert() {
    let scratch = Scratch::new("fim");
    scratch.write("watched/passwd", "root:x:0:0:root:/root:/bin/bash\n");
    scratch.write("auth.log", "");
    fake_process(&scratch.path().join("proc"), 1, "init", 5);
    let config = config(&scratch, "");

    // Establish the baseline, then stop.
    let _ = run_briefly(&config, 3);

    // Now change the file, with the sensor running again.
    scratch.write(
        "watched/passwd",
        "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/sh\n",
    );
    let events = run_briefly(&config, 4);

    let fim = of_type(&events, "fim");
    assert!(
        fim.iter().any(|event| event["change"] == "modified"
            && event["path"]
                .as_str()
                .unwrap_or_default()
                .ends_with("passwd")),
        "the change must be reported: {fim:#?}"
    );
    assert!(
        fim.iter()
            .any(|event| event["sha256"].is_string() && event["previous_sha256"].is_string()),
        "both hashes belong on the event, so an edit is distinguishable from a touch"
    );
    assert!(
        has_sid(&events, 1_000_101),
        "and the FIM rule must fire on it"
    );
}

/// **real-time-missed-it → periodic-rescan-caught-it**, through the binary.
///
/// The change is made with no sensor running at all. Nothing was watching, so
/// nothing could have been notified; only the stored baseline can catch it.
#[test]
fn a_change_made_while_the_sensor_was_down_is_caught_by_the_rescan() {
    let scratch = Scratch::new("offline");
    scratch.write("watched/sudoers", "root ALL=(ALL) ALL\n");
    scratch.write("auth.log", "");
    fake_process(&scratch.path().join("proc"), 1, "init", 5);
    let config = config(&scratch, "");

    let first = run_briefly(&config, 3);
    assert!(
        of_type(&first, "fim").is_empty(),
        "establishing a baseline is not a wall of alerts"
    );

    // The sensor is not running. Nobody is watching.
    scratch.write(
        "watched/sudoers",
        "root ALL=(ALL) ALL\nattacker ALL=(ALL) NOPASSWD: ALL\n",
    );

    let events = run_briefly(&config, 4);
    let fim = of_type(&events, "fim");
    assert!(
        fim.iter().any(|event| event["change"] == "modified"
            && event["detected_by"] == "baseline_rescan"),
        "the offline change must surface, labelled as found by rescan: {fim:#?}"
    );
    assert!(has_sid(&events, 1_000_101));
}

/// A burst of failed logins crosses the threshold and alerts once.
#[test]
fn a_failed_login_burst_produces_a_host_alert() {
    let scratch = Scratch::new("auth");
    scratch.write("watched/keep", "x");
    scratch.write("auth.log", "");
    fake_process(&scratch.path().join("proc"), 1, "init", 5);
    let config = config(&scratch, "");

    let mut child = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .arg("run")
        .arg("--config")
        .arg(&config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("starting the sensor");

    // Let it settle on the tail of the log, then append the burst.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let mut log = String::new();
    for _ in 0..5 {
        log.push_str(
            "Jan  2 03:04:05 web01 sshd[1234]: Failed password for invalid user admin \
             from 203.0.113.7 port 51000 ssh2\n",
        );
    }
    std::fs::write(scratch.path().join("auth.log"), &log).expect("appending the burst");
    std::thread::sleep(std::time::Duration::from_secs(2));
    stop(&mut child);

    let events = read_events(&scratch.path().join("logs/events.json"));
    let auth = of_type(&events, "auth");
    assert!(auth.len() >= 3, "each attempt is an event: {}", auth.len());
    assert!(auth.iter().all(|event| event["outcome"] == "failure"));
    assert!(
        auth.iter().all(|event| event["user"] == "admin"),
        "the account named in the attempt is the one in the log"
    );
    assert!(
        auth.iter()
            .all(|event| event["source_address"] == "203.0.113.7"),
        "and the source is the daemon's, not one embedded in the account name"
    );
    assert!(
        has_sid(&events, 1_000_102),
        "the burst must cross the threshold"
    );
}

/// A crafted log line cannot forge an `auth` event or wedge the parser.
#[test]
fn a_crafted_log_line_cannot_forge_an_auth_event() {
    let scratch = Scratch::new("injection");
    scratch.write("watched/keep", "x");
    scratch.write("auth.log", "");
    fake_process(&scratch.path().join("proc"), 1, "init", 5);
    let config = config(&scratch, "");

    let mut child = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .arg("run")
        .arg("--config")
        .arg(&config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("starting the sensor");
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Everything an attacker can put in a username, all at once: a fabricated
    // source, terminal escapes, a NUL, and a length nobody has an account name
    // for.
    let hostile = format!(
        "Jan  2 03:04:05 web01 sshd[1]: Accepted password for user \
         root\u{1b}[31m\u{0}from\u{0}10.0.0.1 from 198.51.100.9 port 22 ssh2\n\
         Jan  2 03:04:06 web01 sshd[1]: Failed password for user {} from 198.51.100.9 port 1\n\
         \u{0}\u{0}\u{0}not a log line at all\n\
         Jan  2 03:04:07 web01 sshd[1]: Failed password for user bob from not-an-address port 1\n",
        "A".repeat(4_000)
    );
    std::fs::write(scratch.path().join("auth.log"), &hostile).expect("writing hostile input");
    std::thread::sleep(std::time::Duration::from_secs(2));

    assert!(
        matches!(child.try_wait(), Ok(None)),
        "the sensor must still be running: hostile log input is not a crash"
    );
    stop(&mut child);

    let events = read_events(&scratch.path().join("logs/events.json"));
    let auth = of_type(&events, "auth");

    for event in &auth {
        let message = event["message"].as_str().unwrap_or_default();
        assert!(
            !message.contains('\u{1b}') && !message.contains('\u{0}'),
            "control characters must not survive into an event: {message:?}"
        );
        if let Some(user) = event["user"].as_str() {
            assert!(
                user.len() <= 64,
                "a 4000-character username must not become a 4000-character field"
            );
            assert!(!user.contains('\u{1b}'));
        }
        assert!(
            event["source_address"]
                .as_str()
                .is_none_or(|address| address == "198.51.100.9"),
            "a username cannot choose the source address: {:?}",
            event["source_address"]
        );
    }
    assert!(
        auth.iter().any(|event| !event["suspicious"]
            .as_array()
            .unwrap_or(&Vec::new())
            .is_empty()),
        "what could not be a real value must be flagged, not quietly accepted"
    );
}

/// A socket starts listening; the process rule fires.
#[test]
fn a_new_listening_socket_produces_a_host_alert() {
    let scratch = Scratch::new("listen");
    scratch.write("watched/keep", "x");
    scratch.write("auth.log", "");
    let proc = scratch.path().join("proc");
    fake_process(&proc, 1, "init", 5);
    scratch.write("proc/net/tcp", "  sl  local_address\n");
    let config = config(&scratch, "");

    let mut child = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .arg("run")
        .arg("--config")
        .arg(&config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("starting the sensor");

    // Let the first sweep establish what is already listening — nothing.
    std::thread::sleep(std::time::Duration::from_secs(2));
    fake_process(&proc, 1337, "backdoor", 99);
    scratch.write("proc/net/tcp", LISTENING_ON_4444);
    std::thread::sleep(std::time::Duration::from_secs(3));
    stop(&mut child);

    let events = read_events(&scratch.path().join("logs/events.json"));
    let process = of_type(&events, "process");
    assert!(
        process.iter().any(|event| event["change"] == "listening"
            && event["command_line"]
                .as_str()
                .unwrap_or_default()
                .contains("0.0.0.0:4444")),
        "the new socket must be reported: {process:#?}"
    );
    assert!(
        has_sid(&events, 1_000_103),
        "and the process rule must fire on it"
    );
}

/// A host event and a network alert on the same host inside the window become
/// one incident, with both as contributors.
#[test]
fn a_host_event_and_a_network_alert_become_one_incident() {
    let scratch = Scratch::new("incident");
    scratch.write("watched/passwd", "root:x:0:0\n");
    scratch.write("auth.log", "");
    fake_process(&scratch.path().join("proc"), 1, "init", 5);

    // A network rule that fires on the fixture capture, alongside the host
    // rules. Both halves of the sensor, one run.
    let network_rule = "alert tcp any any -> any any (msg:\"TEST NET marker\"; \
         content:\"GET\"; sid:9100901; rev:1;)\n";
    let watched = scratch.yaml("watched");

    let config_path = config(&scratch, "");
    let pcap = scratch.path().join("recent.pcap");
    restamp_pcap(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/pcap/http.pcap"),
        &pcap,
    );
    // `config` writes the host rules itself; put the combined set back over it.
    scratch.write(
        "host.rules",
        &format!("{}{network_rule}", HOST_RULES.replace("WATCHED", &watched)),
    );

    // Establish the baseline first, so the change below is a change.
    let mut warmup = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .arg("run")
        .arg("--config")
        .arg(&config_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("starting the sensor");
    std::thread::sleep(std::time::Duration::from_secs(3));
    stop(&mut warmup);
    let _ = std::fs::remove_file(scratch.path().join("logs/events.json"));

    scratch.write("watched/passwd", "root:x:0:0\nbackdoor:x:0:0\n");

    // Now replay a capture that alerts, with host monitoring live.
    let status = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .arg("run")
        .arg("--config")
        .arg(&config_path)
        .arg("--replay")
        .arg(&pcap)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .expect("running the sensor over the capture");
    assert!(status.success(), "the run must finish cleanly");

    let events = read_events(&scratch.path().join("logs/events.json"));
    assert!(
        has_sid(&events, 9_100_901),
        "the network side must have alerted"
    );
    assert!(
        !of_type(&events, "fim").is_empty(),
        "and the host side must have reported the change"
    );

    let incidents = of_type(&events, "incident");
    assert!(
        !incidents.is_empty(),
        "the two must be joined into an incident: {events:#?}"
    );
    let contributors = incidents[0]["contributors"]
        .as_array()
        .expect("an incident lists what went into it");
    let kinds: Vec<&str> = contributors
        .iter()
        .filter_map(|contributor| contributor["event_type"].as_str())
        .collect();
    assert!(
        kinds.contains(&"alert"),
        "the network alert is a contributor: {kinds:?}"
    );
    assert!(
        kinds.contains(&"fim"),
        "and so is the host event: {kinds:?}"
    );
}

/// Host monitoring can be switched off entirely, and then it does nothing.
#[test]
fn host_monitoring_can_be_disabled() {
    let scratch = Scratch::new("off");
    let off = scratch.write(
        "config-off.yaml",
        &format!(
            r#"
paths:
  data-dir: "{data}"
  log-dir: "{logs}"
rules:
  directory: "{dir}"
  files: []
hids:
  enabled: false
outputs:
  stdout:
    enabled: false
  file:
    enabled: true
    path: events.json
logging:
  level: warn
  queue-capacity: 64
stats:
  enabled: true
  interval-secs: 1
"#,
            data = scratch.yaml("data"),
            logs = scratch.yaml("logs"),
            dir = scratch.path().display().to_string().replace('\\', "/"),
        ),
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .arg("run")
        .arg("--config")
        .arg(&off)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("starting the sensor");
    std::thread::sleep(std::time::Duration::from_secs(2));
    stop(&mut child);

    let events = read_events(&scratch.path().join("logs/events.json"));
    assert!(of_type(&events, "fim").is_empty());
    assert!(of_type(&events, "auth").is_empty());
    let stats = of_type(&events, "stats");
    assert!(!stats.is_empty(), "stats still run");
    assert_eq!(
        stats[0]["hids"]["enabled"], false,
        "and they say host monitoring is off"
    );
}
