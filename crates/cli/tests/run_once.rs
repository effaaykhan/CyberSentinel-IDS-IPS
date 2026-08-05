//! End-to-end acceptance tests for `cybersentinel run`.
//!
//! These drive the real binary on the real filesystem, which is what the Phase 0
//! acceptance criteria are actually about: the sensor starts on this OS, loads
//! its config and rules, skips and logs what it cannot parse, and writes
//! well-formed CyberSentinel event JSON to both sinks.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// Scratch directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cybersentinel-e2e-{tag}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("creating the scratch directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Write a file and return its path, using forward slashes in YAML so the
    /// same test source works on Windows.
    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("writing a fixture file");
        path
    }

    fn yaml_path(&self, name: &str) -> String {
        self.0.join(name).display().to_string().replace('\\', "/")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const RULES: &str = r#"
# One rule of each outcome, so the load report is non-trivial.
alert tcp any any -> any any (msg:"E2E header only"; sid:900001;)
alert http any any -> any any (msg:"E2E awaiting support"; content:"x"; endswith; sid:900002;)
alert tcp any any -> any any (msg:"E2E missing sid";)
not a rule at all
"#;

fn config_yaml(scratch: &Scratch) -> String {
    format!(
        r#"
paths:
  data-dir: "{data}"
  log-dir: "{logs}"
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
rules:
  directory: "{dir}"
  files:
    - test.rules
hids:
  # These tests exercise the network path. Host monitoring is switched off so
  # they neither hash the machine's real /etc nor depend on what is in it.
  enabled: false
outputs:
  stdout:
    enabled: true
  file:
    enabled: true
    path: events.json
logging:
  level: info
  queue-capacity: 64
stats:
  enabled: true
  interval-secs: 1
"#,
        data = scratch.yaml_path("data"),
        logs = scratch.yaml_path("logs"),
        dir = scratch.path().display().to_string().replace('\\', "/"),
    )
}

fn run_once(scratch: &Scratch) -> std::process::Output {
    scratch.write("test.rules", RULES);
    let config = scratch.write("config.yaml", &config_yaml(scratch));

    Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .args(["run", "--config"])
        .arg(&config)
        .arg("--once")
        .output()
        .expect("running the cybersentinel binary")
}

/// `timestamp` must be UTC with sub-second precision — guide §6.
fn assert_timestamp_shape(timestamp: &str) {
    assert_eq!(
        timestamp.len(),
        27,
        "expected YYYY-MM-DDThh:mm:ss.ffffffZ, got {timestamp:?}"
    );
    assert!(
        timestamp.ends_with('Z'),
        "timestamps must be UTC: {timestamp:?}"
    );
    let (date, time) = timestamp.split_once('T').expect("missing the T separator");
    assert_eq!(date.len(), 10, "{timestamp:?}");
    let fraction = time
        .split_once('.')
        .expect("missing sub-second precision")
        .1;
    assert_eq!(
        fraction.len(),
        7,
        "expected 6 fractional digits and Z: {timestamp:?}"
    );
    assert!(
        fraction[..6].chars().all(|c| c.is_ascii_digit()),
        "{timestamp:?}"
    );
}

#[test]
fn run_once_emits_one_well_formed_stats_event_to_stdout() {
    let scratch = Scratch::new("stdout");
    let output = run_once(&scratch);
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "expected exactly one event, got:\n{stdout}");

    let event: serde_json::Value = serde_json::from_str(lines[0]).expect("stdout must be JSON");
    assert_eq!(event["event_type"], "stats");
    assert_timestamp_shape(
        event["timestamp"]
            .as_str()
            .expect("timestamp must be a string"),
    );

    // The sensor envelope.
    assert!(!event["sensor"]["name"].as_str().unwrap().is_empty());
    assert!(!event["sensor"]["id"].as_str().unwrap().is_empty());
    assert_eq!(event["sensor"]["version"], env!("CARGO_PKG_VERSION"));

    // The stats body: two rules loaded, two skipped, one of the loaded pair
    // awaiting engine support.
    let stats = &event["stats"];
    assert_eq!(stats["rules"]["loaded"], 2, "{stats}");
    assert_eq!(stats["rules"]["skipped"], 2, "{stats}");
    assert_eq!(stats["rules"]["with_unsupported_options"], 1, "{stats}");
    assert_eq!(stats["events"]["dropped"], 0, "{stats}");
    assert_eq!(stats["events"]["queue_capacity"], 64, "{stats}");
    assert_eq!(
        stats["capture"]["enabled"], false,
        "capture lands in Phase 1"
    );
    assert_eq!(
        stats["engine"]["enabled"], false,
        "detection lands in Phase 3"
    );
}

#[test]
fn the_same_event_reaches_the_file_sink() {
    let scratch = Scratch::new("file");
    let output = run_once(&scratch);
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let events = scratch.path().join("logs").join("events.json");
    let contents = std::fs::read_to_string(&events)
        .unwrap_or_else(|e| panic!("reading {}: {e}", events.display()));

    assert!(
        contents.ends_with('\n'),
        "the file sink must write newline-delimited JSON"
    );
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 1);

    let from_file: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let from_stdout: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap();
    assert_eq!(
        from_file, from_stdout,
        "both sinks must receive the identical event"
    );
}

#[test]
fn unparseable_rules_are_skipped_and_logged_with_a_reason() {
    let scratch = Scratch::new("skiplog");
    let output = run_once(&scratch);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("skipping unparseable rule"),
        "stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("test.rules:5"),
        "the log must name file and line:\n{stderr}"
    );
    assert!(
        stderr.contains("test.rules:6"),
        "the log must name file and line:\n{stderr}"
    );
    assert!(stderr.contains("2 rule(s) loaded"), "stderr:\n{stderr}");
    assert!(
        stderr.contains("cannot evaluate yet and will not fire"),
        "operators must be told which rules are inert:\n{stderr}"
    );
}

#[test]
fn diagnostics_never_contaminate_the_event_stream() {
    let scratch = Scratch::new("streams");
    let output = run_once(&scratch);

    // Every stdout line must parse as JSON: a consumer piping stdout into a
    // parser must never meet a log line.
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.trim().is_empty() {
            continue;
        }
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|e| panic!("non-JSON on stdout: {line:?} ({e})"));
    }
    assert!(
        !String::from_utf8_lossy(&output.stderr).is_empty(),
        "diagnostics go to stderr"
    );
}

#[test]
fn the_sensor_id_persists_across_runs() {
    let scratch = Scratch::new("identity");

    let first = run_once(&scratch);
    let second = run_once(&scratch);
    assert!(first.status.success() && second.status.success());

    let id_of = |output: &std::process::Output| -> String {
        let event: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&output.stdout).trim()).unwrap();
        event["sensor"]["id"].as_str().unwrap().to_string()
    };
    assert_eq!(
        id_of(&first),
        id_of(&second),
        "the sensor id must be stable across restarts"
    );
    assert!(scratch.path().join("data").join("sensor-id").exists());
}

#[test]
fn a_missing_config_fails_with_a_clear_message_not_a_panic() {
    let output = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .args(["run", "--config", "definitely/not/here.yaml", "--once"])
        .output()
        .expect("running the binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("definitely/not/here.yaml"),
        "stderr:\n{stderr}"
    );
    assert!(!stderr.contains("panicked"), "stderr:\n{stderr}");
}

#[test]
fn an_invalid_config_is_rejected_before_the_sensor_starts() {
    let scratch = Scratch::new("badconfig");
    let config = scratch.write("config.yaml", "outputs:\n  file:\n    enabeld: false\n");

    let output = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .args(["run", "--config"])
        .arg(&config)
        .arg("--once")
        .output()
        .expect("running the binary");

    assert!(
        !output.status.success(),
        "a typo in the config must not start a half-configured sensor"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("enabeld"),
        "the error must name the offending key:\n{stderr}"
    );
    assert!(output.stdout.is_empty(), "no events should be emitted");
}

#[test]
fn version_is_reported() {
    let output = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .arg("--version")
        .output()
        .expect("running the binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "got: {stdout}");
}
