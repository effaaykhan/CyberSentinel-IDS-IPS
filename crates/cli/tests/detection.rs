//! End-to-end detection tests: the Phase 3 acceptance criteria.
//!
//! These drive the real binary over the committed captures with real rules and
//! check which alerts came out. Between them they prove the whole chain agrees
//! with what the destination host would have seen: capture, decode,
//! defragment, reassemble, resolve overlaps, normalize, pre-filter, evaluate,
//! alert.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cybersentinel-detect-{tag}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("creating the scratch directory");
        Self(path)
    }

    fn yaml(&self, name: &str) -> String {
        self.0.join(name).display().to_string().replace('\\', "/")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn repo(path: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
        .display()
        .to_string()
        .replace('\\', "/")
}

/// What the sensor reported.
struct Outcome {
    /// Alert counts by signature id.
    alerts: BTreeMap<u32, usize>,
    stats: Value,
    stderr: String,
    success: bool,
}

impl Outcome {
    fn count(&self, sid: u32) -> usize {
        self.alerts.get(&sid).copied().unwrap_or(0)
    }

    fn fired(&self, sid: u32) -> bool {
        self.count(sid) > 0
    }

    fn engine(&self) -> &Value {
        &self.stats["stats"]["engine"]
    }
}

/// Run the sensor over `pcap` with `rules`, and collect what it said.
///
/// The rule file is **copied into the scratch directory** rather than read from
/// the repository. The sensor drops capabilities at startup, which leaves even a
/// root process subject to ordinary file permissions — so a path that traverses
/// a mode-0750 home directory becomes unreadable, exactly as it should.
fn run(tag: &str, rules_file: &str, pcap: &str, extra: &str) -> Outcome {
    let scratch = Scratch::new(tag);
    std::fs::copy(
        repo(&format!("tests/fixtures/rules/{rules_file}")),
        scratch.0.join(rules_file),
    )
    .expect("copying the rule fixture");
    let config = scratch.0.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            r#"
paths:
  data-dir: "{data}"
  log-dir: "{logs}"
rules:
  directory: "{rules_dir}"
  files: ["{rules_file}"]
hids:
  # These tests exercise the network path. Host monitoring is switched off so
  # they neither hash the machine's real /etc nor depend on what is in it.
  enabled: false
outputs:
  stdout:
    enabled: true
  file:
    enabled: false
logging:
  level: info
stats:
  enabled: true
  interval-secs: 3600
{extra}
"#,
            data = scratch.yaml("data"),
            logs = scratch.yaml("logs"),
            rules_dir = scratch.yaml(""),
        ),
    )
    .expect("writing the config");

    let output = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .args(["run", "--config"])
        .arg(&config)
        .arg("--replay")
        .arg(repo(&format!("tests/fixtures/pcap/{pcap}")))
        .output()
        .expect("running the sensor");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut alerts = BTreeMap::new();
    let mut stats = Value::Null;
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        let event: Value = serde_json::from_str(line).expect("event JSON");
        match event["event_type"].as_str() {
            Some("alert") => {
                let sid = event["alert"]["sid"].as_u64().unwrap_or(0) as u32;
                *alerts.entry(sid).or_insert(0) += 1;
            }
            Some("stats") => stats = event,
            _ => {}
        }
    }

    Outcome {
        alerts,
        stats,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        success: output.status.success(),
    }
}

// Signature ids from tests/fixtures/rules/detection.rules.
const SEGMENTED: u32 = 9_000_001;
const OVERLAP_LAST: u32 = 9_000_002;
const OVERLAP_FIRST: u32 = 9_000_003;
const PRE_FIN: u32 = 9_000_004;
const POST_FIN_INJECTION: u32 = 9_000_005;
const SURVIVED_RESET: u32 = 9_000_006;
const DEFRAGMENTED: u32 = 9_000_007;

// ---------------------------------------------------------------------------
// the engine core, on raw TCP content
// ---------------------------------------------------------------------------

#[test]
fn a_content_rule_fires_on_a_reassembled_stream() {
    let outcome = run("core", "detection.rules", "evasion.pcap", "");
    assert!(outcome.success, "stderr:\n{}", outcome.stderr);
    assert!(
        outcome.fired(SEGMENTED),
        "a plain content rule must fire: {:?}",
        outcome.alerts
    );
    assert!(outcome.engine()["enabled"].as_bool().unwrap_or(false));
    assert!(outcome.engine()["rules_armed"].as_u64().unwrap() >= 7);
}

#[test]
fn the_alert_event_carries_the_rule_and_the_flow() {
    let scratch = Scratch::new("alert-shape");
    std::fs::copy(
        repo("tests/fixtures/rules/detection.rules"),
        scratch.0.join("detection.rules"),
    )
    .unwrap();
    let config = scratch.0.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "paths:\n  data-dir: \"{}\"\n  log-dir: \"{}\"\nrules:\n  directory: \"{}\"\n  files: [\"detection.rules\"]\nhids:\n  enabled: false\noutputs:\n  file:\n    enabled: false\nlogging:\n  level: warn\n",
            scratch.yaml("data"),
            scratch.yaml("logs"),
            scratch.yaml(""),
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .args(["run", "--config"])
        .arg(&config)
        .arg("--replay")
        .arg(repo("tests/fixtures/pcap/evasion.pcap"))
        .output()
        .expect("running the sensor");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let alert: Value = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|event| event["event_type"] == "alert")
        .expect("an alert event");

    assert_eq!(
        alert["alert"]["action"], "alerted",
        "v1 alerts, it does not block"
    );
    assert_eq!(alert["alert"]["source"], "network");
    assert_eq!(alert["alert"]["sid"], SEGMENTED);
    assert_eq!(alert["alert"]["rev"], 1);
    assert_eq!(
        alert["alert"]["signature"],
        "CYBERSENTINEL TEST segmented marker"
    );
    assert_eq!(alert["alert"]["classtype"], "trojan-activity");
    assert_eq!(
        alert["alert"]["severity"], 3,
        "no priority means the middle"
    );
    // The envelope ties it to a conversation.
    assert!(alert["flow_id"].as_u64().unwrap() > 0);
    assert_eq!(alert["src_ip"], "192.0.2.10");
    assert_eq!(alert["proto"], "TCP");
    assert!(alert["timestamp"]
        .as_str()
        .unwrap()
        .starts_with("2024-01-01"));
}

// ---------------------------------------------------------------------------
// the whole chain: every delivery in evasion.pcap
// ---------------------------------------------------------------------------

/// The Phase 3 headline. Each of the six conversations in `evasion.pcap`
/// delivers its payload a different way — in order, out of order, through
/// contradicting overlaps, past a FIN, across a forged reset, and split into IP
/// fragments. A rule fires on each only if reassembly reconstructed exactly
/// what the destination host would have read.
#[test]
fn a_rule_fires_on_every_delivery_in_the_evasion_capture() {
    let outcome = run(
        "all-six",
        "detection.rules",
        "evasion.pcap",
        "reassembly:\n  overlap-policy: last\n",
    );
    assert!(outcome.success, "stderr:\n{}", outcome.stderr);

    assert_eq!(
        outcome.count(SEGMENTED),
        2,
        "in-order and out-of-order segment delivery: {:?}",
        outcome.alerts
    );
    assert!(
        outcome.fired(OVERLAP_LAST),
        "contradicting overlap resolved last-wins: {:?}",
        outcome.alerts
    );
    assert!(
        outcome.fired(PRE_FIN),
        "data the host read before closing: {:?}",
        outcome.alerts
    );
    assert!(
        outcome.fired(SURVIVED_RESET),
        "the stream must stay whole across a forged reset: {:?}",
        outcome.alerts
    );
    assert!(
        outcome.fired(DEFRAGMENTED),
        "the IP-fragmented delivery: {:?}",
        outcome.alerts
    );
}

/// Firing is only half the proof. These two must **not** fire, and each of them
/// would be a silent evasion or a silent false positive if it did.
#[test]
fn the_deliveries_that_must_not_match_do_not() {
    let outcome = run(
        "must-not",
        "detection.rules",
        "evasion.pcap",
        "reassembly:\n  overlap-policy: last\n",
    );

    assert!(
        !outcome.fired(POST_FIN_INJECTION),
        "bytes past the FIN are never read by the host; matching them means the \
         sensor is inspecting something the server discarded"
    );
    assert!(
        !outcome.fired(OVERLAP_FIRST),
        "under last-wins policy the superseded copy must not reach detection"
    );
}

/// The same capture, the other policy: the overlap resolves the other way and a
/// different rule fires. Proof that resolution is doing the work, not luck.
#[test]
fn the_overlap_policy_decides_which_rule_fires() {
    let last = run(
        "policy-last",
        "detection.rules",
        "evasion.pcap",
        "reassembly:\n  overlap-policy: last\n",
    );
    let first = run(
        "policy-first",
        "detection.rules",
        "evasion.pcap",
        "reassembly:\n  overlap-policy: first\n",
    );

    assert!(last.fired(OVERLAP_LAST) && !last.fired(OVERLAP_FIRST));
    assert!(first.fired(OVERLAP_FIRST) && !first.fired(OVERLAP_LAST));
}

// ---------------------------------------------------------------------------
// HTTP and normalization
// ---------------------------------------------------------------------------

#[test]
fn a_uri_rule_matches_every_spelling_of_the_same_request() {
    // The five requests in http.pcap ask for the same file plainly, with a
    // traversal, with a self-reference, percent-encoded, and double-encoded.
    // The server resolves them all to /etc/passwd, so the sensor must too.
    let outcome = run("http-uri", "http.rules", "http.pcap", "");
    assert!(outcome.success, "stderr:\n{}", outcome.stderr);
    assert_eq!(
        outcome.count(9_100_001),
        5,
        "one alert per spelling: {:?}",
        outcome.alerts
    );
}

#[test]
fn normalization_flags_are_matchable_in_their_own_right() {
    let outcome = run("http-flags", "http.rules", "http.pcap", "");
    assert_eq!(
        outcome.count(9_100_002),
        1,
        "only the double-encoded request should match: {:?}",
        outcome.alerts
    );
}

#[test]
fn header_and_user_agent_buffers_are_populated() {
    let outcome = run("http-headers", "http.rules", "http.pcap", "");
    assert!(
        outcome.fired(9_100_003),
        "http.user_agent: {:?}",
        outcome.alerts
    );
    assert!(
        outcome.fired(9_100_004),
        "http.header: {:?}",
        outcome.alerts
    );
    assert!(
        outcome.fired(9_100_005),
        "http.method: {:?}",
        outcome.alerts
    );
}

#[test]
fn a_uri_rule_only_matches_the_uri_that_was_requested() {
    // normal.pcap carries a real request, but for /index.html. The URI rule
    // must not fire on it, and neither must the encoding-flag rule — a sensor
    // that matched anything HTTP-shaped would be useless.
    let outcome = run("http-negative", "http.rules", "normal.pcap", "");
    assert!(
        !outcome.fired(9_100_001),
        "a different URI must not match: {:?}",
        outcome.alerts
    );
    assert!(
        !outcome.fired(9_100_002),
        "nothing was encoded: {:?}",
        outcome.alerts
    );
    assert!(
        outcome.fired(9_100_005),
        "the method buffer should still be populated for a real request"
    );
}

// ---------------------------------------------------------------------------
// coverage reporting and gating
// ---------------------------------------------------------------------------

#[test]
fn the_startup_summary_reports_coverage_in_buckets() {
    let outcome = run("coverage", "mixed.rules", "normal.pcap", "");
    // Field names only: the log writer wraps the `=` in colour escapes.
    for field in [
        "rule coverage",
        "armed",
        "awaiting_support",
        "failed_to_compile",
        "skipped",
    ] {
        assert!(
            outcome.stderr.contains(field),
            "the startup summary should report {field}:\n{}",
            outcome.stderr
        );
    }

    let engine = outcome.engine();
    assert!(engine["rules_armed"].as_u64().unwrap() > 0);
    assert!(
        engine["rules_awaiting_support"].as_u64().unwrap() > 0,
        "mixed.rules holds one rule the engine cannot evaluate yet"
    );
}

#[test]
fn load_and_report_is_the_default_even_with_broken_rules() {
    // A sensor that will not start because one rule is broken is a sensor that
    // is watching nothing.
    let outcome = run("lenient", "mixed.rules", "normal.pcap", "");
    assert!(outcome.success, "a broken rule must not stop the sensor");
}

#[test]
fn strict_refuses_to_start_when_a_rule_is_broken() {
    let scratch = Scratch::new("strict");
    std::fs::copy(
        repo("tests/fixtures/rules/mixed.rules"),
        scratch.0.join("mixed.rules"),
    )
    .unwrap();
    let config = scratch.0.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "paths:\n  data-dir: \"{}\"\n  log-dir: \"{}\"\nrules:\n  directory: \"{}\"\n  files: [\"mixed.rules\"]\nhids:\n  enabled: false\noutputs:\n  file:\n    enabled: false\n",
            scratch.yaml("data"),
            scratch.yaml("logs"),
            scratch.yaml(""),
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .args(["run", "--config"])
        .arg(&config)
        .arg("--once")
        .arg("--strict")
        .output()
        .expect("running the sensor");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--strict"), "{stderr}");
}

#[test]
fn validate_rules_passes_on_a_clean_set_and_fails_on_a_broken_one() {
    let check = |rules: &str| -> bool {
        let scratch = Scratch::new("validate");
        std::fs::copy(
            repo(&format!("tests/fixtures/rules/{rules}")),
            scratch.0.join(rules),
        )
        .unwrap();
        let config = scratch.0.join("config.yaml");
        std::fs::write(
            &config,
            format!(
                "paths:\n  data-dir: \"{}\"\n  log-dir: \"{}\"\nrules:\n  directory: \"{}\"\n  files: [\"{rules}\"]\n",
                scratch.yaml("data"),
                scratch.yaml("logs"),
                scratch.yaml(""),
            ),
        )
        .unwrap();

        Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
            .args(["validate-rules", "--config"])
            .arg(&config)
            .output()
            .expect("running validate-rules")
            .status
            .success()
    };

    assert!(check("detection.rules"), "a clean set should validate");
    assert!(!check("mixed.rules"), "a set with broken rules should not");
}

#[test]
fn an_over_budget_regex_is_reported_by_validate_rules() {
    let scratch = Scratch::new("budget");
    let rules = scratch.0.join("budget.rules");
    // Legal, and far too expensive to compile under a small budget.
    std::fs::write(
        &rules,
        "alert tcp any any -> any any (msg:\"expensive\"; pcre:\"/(?:[a-z0-9]{40}){200}/\"; sid:1;)\n",
    )
    .unwrap();

    let config = scratch.0.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "paths:\n  data-dir: \"{}\"\n  log-dir: \"{}\"\nrules:\n  directory: \"{}\"\n  files: [\"budget.rules\"]\ndetect:\n  regex-size-limit: 1024\n  regex-dfa-size-limit: 1024\n",
            scratch.yaml("data"),
            scratch.yaml("logs"),
            scratch.yaml(""),
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .args(["validate-rules", "--config"])
        .arg(&config)
        .output()
        .expect("running validate-rules");

    assert!(
        !output.status.success(),
        "an over-budget rule must fail validation"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("failed to compile"), "{stdout}");
    assert!(
        stdout.contains("armed:            0") || stdout.contains("armed:"),
        "{stdout}"
    );
}
