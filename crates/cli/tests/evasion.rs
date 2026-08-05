//! End-to-end evasion tests: the Phase 2 acceptance criteria.
//!
//! `evasion.pcap` carries the same marker string delivered six different ways,
//! each designed to make a sensor and a host disagree about what was sent. This
//! drives the real binary over it and checks what the reassembler actually
//! produced — using `--dump-streams`, which exists precisely so these
//! properties can be asserted end to end rather than only at unit level.

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
            "cybersentinel-evasion-{tag}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("creating the scratch directory");
        Self(path)
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

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/pcap/evasion.pcap")
}

/// What the sensor made of the capture.
struct Outcome {
    /// One entry per reassembled client-to-server stream.
    streams: Vec<String>,
    /// The closing `stats` event.
    stats: Value,
}

impl Outcome {
    fn has_stream(&self, text: &str) -> bool {
        self.streams.iter().any(|stream| stream == text)
    }

    fn any_stream_contains(&self, text: &str) -> bool {
        self.streams.iter().any(|stream| stream.contains(text))
    }

    fn reassembly(&self) -> &Value {
        &self.stats["stats"]["reassembly"]
    }
}

/// Replay the evasion fixture with the given extra reassembly config.
fn replay(tag: &str, reassembly: &str) -> Outcome {
    let scratch = Scratch::new(tag);
    let dumps = scratch.0.join("streams");
    let config_path = scratch.0.join("config.yaml");

    std::fs::write(
        &config_path,
        format!(
            r#"
paths:
  data-dir: "{data}"
  log-dir: "{logs}"
rules:
  files: []
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
  level: warn
stats:
  enabled: true
  interval-secs: 3600
reassembly:
{reassembly}
"#,
            data = scratch.yaml_path("data"),
            logs = scratch.yaml_path("logs"),
        ),
    )
    .expect("writing the config");

    let output = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .args(["run", "--config"])
        .arg(&config_path)
        .arg("--replay")
        .arg(fixture())
        .arg("--dump-streams")
        .arg(&dumps)
        .output()
        .expect("running the sensor");

    assert!(
        output.status.success(),
        "sensor failed\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut streams = Vec::new();
    for entry in std::fs::read_dir(&dumps).expect("reading the dump directory") {
        let path = entry.expect("a directory entry").path();
        if path.to_string_lossy().ends_with("-to-server.bin") {
            let bytes = std::fs::read(&path).expect("reading a stream dump");
            streams.push(String::from_utf8_lossy(&bytes).into_owned());
        }
    }
    streams.sort();

    let stats = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("event JSON"))
        .rfind(|event| event["event_type"] == "stats")
        .expect("a closing stats event");

    Outcome { streams, stats }
}

const MARKER: &str = "ATTACK-PAYLOAD-MARKER";
const FRAGMENTED_MARKER: &str = "FRAGMENTED-ATTACK-MARKER";

// ---------------------------------------------------------------------------
// splitting
// ---------------------------------------------------------------------------

#[test]
fn a_string_split_across_tcp_segments_reassembles() {
    let outcome = replay("segments", "  overlap-policy: first\n");
    assert!(
        outcome.has_stream(MARKER),
        "the split marker should reassemble whole: {:#?}",
        outcome.streams
    );
}

#[test]
fn the_same_string_reassembles_when_the_segments_arrive_out_of_order() {
    // Two conversations in the fixture carry it — one in order, one shuffled.
    // Both must produce the identical stream.
    let outcome = replay("out-of-order", "  overlap-policy: first\n");
    let matching = outcome
        .streams
        .iter()
        .filter(|stream| stream.as_str() == MARKER)
        .count();
    assert_eq!(
        matching, 2,
        "in-order and out-of-order delivery must agree: {:#?}",
        outcome.streams
    );
}

#[test]
fn a_string_split_across_ip_fragments_reassembles() {
    let outcome = replay("fragments", "  overlap-policy: first\n");
    assert!(
        outcome.has_stream(FRAGMENTED_MARKER),
        "the fragmented marker should reassemble whole: {:#?}",
        outcome.streams
    );
    assert_eq!(outcome.reassembly()["datagrams_reassembled"], 1);
    assert_eq!(outcome.reassembly()["fragments"], 3);
}

// ---------------------------------------------------------------------------
// overlap policy — the same capture, two answers
// ---------------------------------------------------------------------------

#[test]
fn contradicting_segments_resolve_to_the_first_copy_under_first_policy() {
    let outcome = replay("policy-first", "  overlap-policy: first\n");
    assert!(
        outcome.has_stream("XXXXXXXX-TAIL"),
        "first-wins should keep the original bytes: {:#?}",
        outcome.streams
    );
    assert!(
        !outcome.any_stream_contains("ATTACKED"),
        "the contradicting copy must not appear: {:#?}",
        outcome.streams
    );
    assert!(
        outcome.reassembly()["stream_conflicts"].as_u64().unwrap() > 0,
        "the disagreement must be counted, not silently resolved"
    );
}

#[test]
fn contradicting_segments_resolve_to_the_last_copy_under_last_policy() {
    let outcome = replay("policy-last", "  overlap-policy: last\n");
    assert!(
        outcome.has_stream("ATTACKED-TAIL"),
        "last-wins should take the newer bytes: {:#?}",
        outcome.streams
    );
    assert!(
        !outcome.any_stream_contains("XXXXXXXX"),
        "the superseded copy must not appear: {:#?}",
        outcome.streams
    );
}

/// The headline property of the phase: the same bytes on the wire produce
/// different reassembled streams depending on what the operator says the
/// destination host is.
#[test]
fn a_per_host_override_changes_what_the_sensor_sees() {
    let default_policy = replay("host-default", "  overlap-policy: first\n");
    let overridden = replay(
        "host-override",
        "  overlap-policy: first\n  host-policies:\n    - network: 198.51.100.20/32\n      policy: last\n",
    );

    assert!(default_policy.has_stream("XXXXXXXX-TAIL"));
    assert!(
        overridden.has_stream("ATTACKED-TAIL"),
        "the override for the destination host should apply: {:#?}",
        overridden.streams
    );
}

#[test]
fn an_override_for_a_different_host_does_not_apply() {
    let outcome = replay(
        "host-miss",
        "  overlap-policy: first\n  host-policies:\n    - network: 10.0.0.0/8\n      policy: last\n",
    );
    assert!(
        outcome.has_stream("XXXXXXXX-TAIL"),
        "a policy for another network must not change this one: {:#?}",
        outcome.streams
    );
}

// ---------------------------------------------------------------------------
// injection and teardown ambiguity
// ---------------------------------------------------------------------------

#[test]
fn data_past_the_fin_never_reaches_the_stream() {
    // The host has closed that direction. Bytes the sensor accepts but the host
    // ignores are an insertion attack: they corrupt what detection matches on.
    let outcome = replay("past-fin", "  overlap-policy: first\n");
    assert!(
        outcome.has_stream("GOOD"),
        "the pre-FIN data should still be delivered: {:#?}",
        outcome.streams
    );
    assert!(
        !outcome.any_stream_contains("EVIL"),
        "data past the FIN must not enter the stream: {:#?}",
        outcome.streams
    );
    assert!(outcome.reassembly()["stream_after_fin"].as_u64().unwrap() > 0);
}

#[test]
fn a_forged_reset_does_not_stop_the_sensor_watching() {
    // The RST-evasion case. If the sensor believes a blind reset, it stops
    // following a connection the host keeps serving — and everything after it
    // is invisible.
    let outcome = replay("forged-reset", "  overlap-policy: first\n");
    assert!(
        outcome.has_stream("BEFORE-AFTER-RESET"),
        "traffic after a forged reset must stay in the same flow: {:#?}",
        outcome.streams
    );
    assert_eq!(
        outcome.reassembly()["resets_ignored"],
        1,
        "the ignored reset must be visible in stats"
    );
}

#[test]
fn a_first_fragment_too_small_to_hold_the_transport_header_is_flagged() {
    // RFC 1858's tiny-fragment attack: split the TCP header itself across
    // fragments so a device that reads only the first one cannot see the
    // flags or ports. The fixture's first fragment carries 16 bytes of a
    // 20-byte header, and the decoder says so — while reassembly still puts
    // the datagram back together.
    let outcome = replay("tiny-fragment", "  overlap-policy: first\n");
    assert_eq!(
        outcome.stats["stats"]["decode"]["anomalous"], 1,
        "the truncated first fragment should be reported: {}",
        outcome.stats["stats"]["decode"]
    );
    assert!(
        outcome.has_stream(FRAGMENTED_MARKER),
        "and the datagram should still reassemble: {:#?}",
        outcome.streams
    );
}

// ---------------------------------------------------------------------------
// the dump itself
// ---------------------------------------------------------------------------

#[test]
fn stream_dumping_is_off_unless_asked_for() {
    // Reassembled payload is captured traffic. It must never reach disk because
    // someone left a default on.
    let scratch = Scratch::new("nodump");
    let config_path = scratch.0.join("config.yaml");
    std::fs::write(
        &config_path,
        format!(
            "paths:\n  data-dir: \"{}\"\n  log-dir: \"{}\"\nrules:\n  files: []\nhids:\n  enabled: false\noutputs:\n  file:\n    enabled: false\nlogging:\n  level: warn\n",
            scratch.yaml_path("data"),
            scratch.yaml_path("logs"),
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .args(["run", "--config"])
        .arg(&config_path)
        .arg("--replay")
        .arg(fixture())
        .output()
        .expect("running the sensor");

    assert!(output.status.success());
    let written: Vec<_> = std::fs::read_dir(&scratch.0)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".bin"))
        .collect();
    assert!(
        written.is_empty(),
        "no payload should be on disk: {written:?}"
    );
}

#[test]
fn enabling_the_dump_warns_that_payload_is_being_written() {
    let scratch = Scratch::new("warns");
    let dumps = scratch.0.join("streams");
    let config_path = scratch.0.join("config.yaml");
    std::fs::write(
        &config_path,
        format!(
            "paths:\n  data-dir: \"{}\"\n  log-dir: \"{}\"\nrules:\n  files: []\nhids:\n  enabled: false\noutputs:\n  file:\n    enabled: false\n",
            scratch.yaml_path("data"),
            scratch.yaml_path("logs"),
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .args(["run", "--config"])
        .arg(&config_path)
        .arg("--replay")
        .arg(fixture())
        .arg("--dump-streams")
        .arg(&dumps)
        .output()
        .expect("running the sensor");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("personal data"),
        "the operator must be told what they just turned on:\n{stderr}"
    );
}
