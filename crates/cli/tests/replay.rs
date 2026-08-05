//! End-to-end tests for `cybersentinel run --replay`.
//!
//! These are the Phase 1 acceptance criteria, driven through the real binary
//! against the committed pcap fixtures: replaying a capture yields correct flow
//! metadata, malformed packets yield anomaly events rather than crashes or
//! silence, and the whole pipeline runs with no privileges and no libpcap.

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
            "cybersentinel-replay-{tag}-{}-{unique}",
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

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/pcap")
        .join(name)
}

/// Run the sensor over a fixture and return the events it emitted.
fn replay(tag: &str, pcap: &Path, extra_config: &str) -> Vec<Value> {
    let scratch = Scratch::new(tag);
    let config_path = scratch.0.join("config.yaml");
    std::fs::write(
        &config_path,
        format!(
            r#"
paths:
  data-dir: "{data}"
  log-dir: "{logs}"
rules:
  directory: "{dir}"
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
{extra_config}
"#,
            data = scratch.yaml_path("data"),
            logs = scratch.yaml_path("logs"),
            dir = scratch.0.display().to_string().replace('\\', "/"),
        ),
    )
    .expect("writing the config");

    let output = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .args(["run", "--config"])
        .arg(&config_path)
        .arg("--replay")
        .arg(pcap)
        .output()
        .expect("running the sensor");

    assert!(
        output.status.success(),
        "sensor failed\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|e| panic!("non-JSON line {line:?}: {e}"))
        })
        .collect()
}

fn of_type<'a>(events: &'a [Value], kind: &str) -> Vec<&'a Value> {
    events
        .iter()
        .filter(|event| event["event_type"] == kind)
        .collect()
}

/// The last stats event, which carries the closing counters.
fn final_stats(events: &[Value]) -> &Value {
    of_type(events, "stats").pop().expect("a stats event")
}

// ---------------------------------------------------------------------------
// decoded flow metadata
// ---------------------------------------------------------------------------

#[test]
fn replaying_a_capture_yields_correct_flow_metadata() {
    let events = replay("normal", &fixture("normal.pcap"), "");
    let flows = of_type(&events, "flow");

    assert_eq!(
        flows.len(),
        5,
        "the fixture holds five conversations: {events:#?}"
    );

    let http = flows
        .iter()
        .find(|flow| flow["dest_port"] == 80)
        .expect("the HTTP conversation");
    assert_eq!(http["src_ip"], "192.0.2.10");
    assert_eq!(http["src_port"], 51_000);
    assert_eq!(http["dest_ip"], "198.51.100.20");
    assert_eq!(http["proto"], "TCP");
    assert_eq!(
        http["flow"]["reason"], "closed",
        "the fixture tears the connection down"
    );
    assert_eq!(http["flow"]["packets_to_server"], 4);
    assert_eq!(http["flow"]["packets_to_client"], 3);
    assert_eq!(http["flow"]["tcp_flags"], "FSPA");
    assert_eq!(http["flow"]["duration_ms"], 600);
    // Byte counts are whole frames, so they must exceed the payload alone.
    assert!(http["flow"]["bytes_to_server"].as_u64().unwrap() > 200);
    assert!(http["flow_id"].as_u64().unwrap() > 0);
}

#[test]
fn udp_icmp_ipv6_and_vlan_flows_are_all_decoded() {
    let events = replay("protocols", &fixture("normal.pcap"), "");
    let flows = of_type(&events, "flow");

    let dns = flows
        .iter()
        .find(|flow| flow["proto"] == "UDP")
        .expect("the DNS exchange");
    assert_eq!(dns["dest_port"], 53);
    assert_eq!(dns["flow"]["packets_to_server"], 1);
    assert_eq!(dns["flow"]["packets_to_client"], 1);

    let icmp = flows
        .iter()
        .find(|flow| flow["proto"] == "ICMP")
        .expect("the ping");
    assert!(icmp.get("src_port").is_none(), "ICMP has no ports: {icmp}");
    assert!(icmp["flow"].get("tcp_flags").is_none());

    let v6 = flows
        .iter()
        .find(|flow| flow["src_ip"] == "2001:db8::10")
        .expect("the IPv6 flow");
    assert_eq!(v6["dest_ip"], "2001:db8::20");
    assert_eq!(v6["dest_port"], 443);

    let vlan = flows
        .iter()
        .find(|flow| flow["dest_port"] == 8080)
        .expect("the VLAN-tagged flow");
    assert_eq!(vlan["proto"], "TCP");
    assert_eq!(vlan["flow"]["reason"], "sensor_stopped");
}

#[test]
fn decode_counters_classify_the_whole_capture() {
    let events = replay("counters", &fixture("normal.pcap"), "");
    let stats = final_stats(&events);

    let capture = &stats["stats"]["capture"];
    assert_eq!(capture["enabled"], true);
    assert_eq!(capture["packets"], 14);
    assert_eq!(capture["drops"], 0, "a savefile drops nothing");
    assert_eq!(capture["drop_rate"], 0.0);
    assert!(capture["source"].as_str().unwrap().ends_with("normal.pcap"));

    let decode = &stats["stats"]["decode"];
    assert_eq!(decode["enabled"], true);
    assert_eq!(decode["packets"], 14);
    assert_eq!(decode["ipv4"], 12);
    assert_eq!(decode["ipv6"], 1);
    assert_eq!(decode["tcp"], 9);
    assert_eq!(decode["udp"], 2);
    assert_eq!(decode["icmp"], 2);
    assert_eq!(decode["non_ip"], 1, "the ARP frame");
    assert_eq!(decode["anomalous"], 0, "the normal fixture is well-formed");

    let flows = &stats["stats"]["flows"];
    assert_eq!(flows["created"], 5);
    assert_eq!(flows["closed"], 1);
    assert_eq!(flows["evicted"], 0);
    assert_eq!(
        flows["active"], 0,
        "every flow is flushed at end of capture"
    );
    assert_eq!(flows["capacity"], 65_536);
}

#[test]
fn event_timestamps_come_from_the_capture_not_the_clock() {
    // The fixture is stamped 2024-01-01. Events dated "now" would be useless
    // for correlating a replayed capture against anything else.
    let events = replay("timestamps", &fixture("normal.pcap"), "");
    for flow in of_type(&events, "flow") {
        let timestamp = flow["timestamp"].as_str().unwrap();
        assert!(timestamp.starts_with("2024-01-01"), "got {timestamp}");
    }
}

#[test]
fn replaying_the_same_capture_twice_produces_the_same_flow_ids() {
    let ids = |tag: &str| -> Vec<u64> {
        let events = replay(tag, &fixture("normal.pcap"), "");
        let mut ids: Vec<u64> = of_type(&events, "flow")
            .iter()
            .map(|flow| flow["flow_id"].as_u64().unwrap())
            .collect();
        ids.sort_unstable();
        ids
    };
    assert_eq!(
        ids("stable-a"),
        ids("stable-b"),
        "flow ids must be reproducible"
    );
}

// ---------------------------------------------------------------------------
// anomalies
// ---------------------------------------------------------------------------

#[test]
fn malformed_packets_produce_anomaly_events_rather_than_crashes() {
    let events = replay("malformed", &fixture("malformed.pcap"), "");
    let anomalies = of_type(&events, "anomaly");

    assert_eq!(
        anomalies.len(),
        14,
        "every frame in the fixture is malformed, and each produces exactly one event"
    );

    let seen: Vec<String> = anomalies
        .iter()
        .flat_map(|event| event["anomaly"]["anomalies"].as_array().unwrap())
        .map(|record| {
            format!(
                "{}.{}",
                record["layer"].as_str().unwrap(),
                record["kind"].as_str().unwrap()
            )
        })
        .collect();

    for expected in [
        "ethernet.empty_frame",
        "ethernet.truncated_header",
        "ipv4.unknown_ip_version",
        "ipv4.impossible_length",
        "ipv4.length_mismatch",
        "ipv4.bad_ipv4_checksum",
        "tcp.impossible_length",
        "tcp.truncated_header",
        "udp.impossible_length",
        "udp.length_mismatch",
        "vlan.too_many_layers",
        "ipv6.truncated_header",
    ] {
        assert!(
            seen.contains(&expected.to_string()),
            "missing {expected} in {seen:?}"
        );
    }
}

#[test]
fn an_anomalous_packet_is_still_attributed_to_a_host() {
    let events = replay("attribution", &fixture("malformed.pcap"), "");
    let attributed = of_type(&events, "anomaly")
        .into_iter()
        .filter(|event| event.get("src_ip").is_some())
        .count();
    assert!(
        attributed >= 6,
        "packets whose layer 3 survived should keep their addresses; only {attributed} did"
    );
}

#[test]
fn anomaly_counters_reach_the_stats_event() {
    let events = replay("anomaly-counters", &fixture("malformed.pcap"), "");
    let decode = &final_stats(&events)["stats"]["decode"];
    assert_eq!(decode["packets"], 14);
    assert_eq!(decode["anomalous"], 14);
    assert!(decode["anomalies"].as_u64().unwrap() >= 14);
}

#[test]
fn anomaly_events_can_be_silenced_without_losing_the_counters() {
    let events = replay(
        "quiet",
        &fixture("malformed.pcap"),
        "decode:\n  emit-anomaly-events: false\n",
    );
    assert!(of_type(&events, "anomaly").is_empty());
    assert_eq!(final_stats(&events)["stats"]["decode"]["anomalous"], 14);
}

#[test]
fn flow_events_can_be_silenced_without_losing_the_counters() {
    let events = replay(
        "no-flows",
        &fixture("normal.pcap"),
        "flow:\n  emit-events: false\n",
    );
    assert!(of_type(&events, "flow").is_empty());
    assert_eq!(final_stats(&events)["stats"]["flows"]["created"], 5);
}

// ---------------------------------------------------------------------------
// bounded state
// ---------------------------------------------------------------------------

#[test]
fn a_tiny_flow_table_evicts_and_says_so() {
    // The bound is what stops an attacker growing sensor memory by opening
    // flows. With room for one, the five-conversation fixture must evict.
    let events = replay(
        "bounded",
        &fixture("normal.pcap"),
        "flow:\n  max-flows: 1\n",
    );
    let stats = final_stats(&events);

    assert_eq!(stats["stats"]["flows"]["capacity"], 1);
    assert!(
        stats["stats"]["flows"]["evicted"].as_u64().unwrap() > 0,
        "evictions must be counted: {stats}"
    );
    assert!(
        of_type(&events, "flow")
            .iter()
            .any(|flow| flow["flow"]["reason"] == "evicted"),
        "an evicted flow is still reported — it is a coverage hole, not a silent drop"
    );
}

// ---------------------------------------------------------------------------
// failure modes
// ---------------------------------------------------------------------------

#[test]
fn a_missing_capture_file_fails_with_a_clear_message() {
    let scratch = Scratch::new("missing");
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
        .args(["--replay", "definitely/not/here.pcap"])
        .output()
        .expect("running the sensor");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("definitely/not/here.pcap"),
        "stderr:\n{stderr}"
    );
    assert!(!stderr.contains("panicked"), "stderr:\n{stderr}");
}

#[test]
fn a_file_that_is_not_a_capture_is_rejected() {
    let scratch = Scratch::new("notpcap");
    let junk = scratch.0.join("junk.pcap");
    std::fs::write(&junk, b"this is not a capture file, it is just some text").unwrap();

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
        .arg(&junk)
        .output()
        .expect("running the sensor");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not a pcap"), "stderr:\n{stderr}");
}

#[test]
fn replay_and_once_are_mutually_exclusive() {
    let output = Command::new(env!("CARGO_BIN_EXE_cybersentinel"))
        .args([
            "run",
            "--config",
            "config/config.yaml",
            "--once",
            "--replay",
            "x.pcap",
        ])
        .output()
        .expect("running the sensor");
    assert!(
        !output.status.success(),
        "asking for both modes at once should be an error"
    );
}
