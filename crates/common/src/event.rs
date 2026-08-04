//! The CyberSentinel event JSON schema.
//!
//! One schema covers host and network events (guide §3.1). Every event is a
//! single JSON object on one line (newline-delimited JSON) with a common
//! envelope:
//!
//! ```text
//! {"timestamp":"2026-08-04T16:47:12.123456Z","event_type":"stats",
//!  "sensor":{...},"flow_id":123,"src_ip":...,"stats":{...}}
//! ```
//!
//! The envelope carries `timestamp`, `event_type`, `sensor`, an optional
//! `flow_id`, and the 5-tuple where one applies. The type-specific body is
//! flattened in under a key matching `event_type`, so `"event_type":"stats"`
//! always pairs with a `"stats"` object.
//!
//! Phase 0 defines two bodies: [`StatsEvent`] (emitted by the running sensor)
//! and [`AlertEvent`] (the shape the detection engine will fill in from Phase 3).
//! Further bodies — `flow`, `http`, `dns`, `tls`, `fim`, `auth`, `process` —
//! are added as their producing phases land.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::time::Timestamp;

/// Identity of the sensor that produced an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorInfo {
    /// Host name of the machine the sensor runs on.
    pub name: String,
    /// Stable per-install UUID, persisted under the data directory.
    pub id: String,
    /// Sensor version.
    pub version: String,
}

/// Transport / network protocol of an event's 5-tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Internet Control Message Protocol (v4 or v6).
    Icmp,
    /// Any other IP protocol number.
    Ip,
}

/// The network 5-tuple attached to network-derived events.
///
/// Ports are absent for protocols that have none (ICMP, bare IP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetTuple {
    /// Source address.
    pub src_ip: IpAddr,
    /// Source port, where the protocol has one.
    pub src_port: Option<u16>,
    /// Destination address.
    pub dest_ip: IpAddr,
    /// Destination port, where the protocol has one.
    pub dest_port: Option<u16>,
    /// Protocol.
    pub proto: Protocol,
}

/// Discriminant for the event body, mirrored into the `event_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A rule matched.
    Alert,
    /// Periodic sensor health and counters.
    Stats,
}

impl EventKind {
    /// The wire string for this kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Stats => "stats",
        }
    }
}

/// The type-specific body of an event.
///
/// Serializes as a single key matching [`EventKind`], flattened into the event
/// envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Payload {
    /// A rule matched. See [`AlertEvent`].
    Alert(Box<AlertEvent>),
    /// Periodic counters. See [`StatsEvent`].
    Stats(Box<StatsEvent>),
}

impl Payload {
    /// Which [`EventKind`] this body corresponds to.
    #[must_use]
    pub fn kind(&self) -> EventKind {
        match self {
            Self::Alert(_) => EventKind::Alert,
            Self::Stats(_) => EventKind::Stats,
        }
    }

    /// Wrap a [`StatsEvent`].
    #[must_use]
    pub fn stats(stats: StatsEvent) -> Self {
        Self::Stats(Box::new(stats))
    }

    /// Wrap an [`AlertEvent`].
    #[must_use]
    pub fn alert(alert: AlertEvent) -> Self {
        Self::Alert(Box::new(alert))
    }
}

/// A single CyberSentinel event.
///
/// Build these with [`Event::new`] so `event_type` can never disagree with the
/// body; the 5-tuple and flow id are attached with the builder methods.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// When the event occurred, UTC with microsecond precision.
    pub timestamp: Timestamp,
    /// Body discriminant; always equals `payload.kind()`.
    pub event_type: EventKind,
    /// Identity of the emitting sensor.
    pub sensor: SensorInfo,
    /// Flow this event belongs to, for correlating host and network events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<u64>,
    /// Source address of the 5-tuple, when one applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<IpAddr>,
    /// Source port of the 5-tuple, when one applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    /// Destination address of the 5-tuple, when one applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest_ip: Option<IpAddr>,
    /// Destination port of the 5-tuple, when one applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest_port: Option<u16>,
    /// Protocol of the 5-tuple, when one applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<Protocol>,
    /// The type-specific body.
    #[serde(flatten)]
    pub payload: Payload,
}

impl Event {
    /// Build an event, stamping `event_type` from the body.
    #[must_use]
    pub fn new(timestamp: Timestamp, sensor: SensorInfo, payload: Payload) -> Self {
        Self {
            timestamp,
            event_type: payload.kind(),
            sensor,
            flow_id: None,
            src_ip: None,
            src_port: None,
            dest_ip: None,
            dest_port: None,
            proto: None,
            payload,
        }
    }

    /// Attach a flow id.
    #[must_use]
    pub fn with_flow_id(mut self, flow_id: u64) -> Self {
        self.flow_id = Some(flow_id);
        self
    }

    /// Attach a 5-tuple.
    #[must_use]
    pub fn with_net(mut self, net: NetTuple) -> Self {
        self.src_ip = Some(net.src_ip);
        self.src_port = net.src_port;
        self.dest_ip = Some(net.dest_ip);
        self.dest_port = net.dest_port;
        self.proto = Some(net.proto);
        self
    }

    /// Serialize to a newline-terminated JSON line.
    ///
    /// # Errors
    /// Returns [`crate::Error::Serialize`] if the event cannot be represented as
    /// JSON.
    pub fn to_ndjson(&self) -> crate::Result<Vec<u8>> {
        let mut buf = serde_json::to_vec(self)?;
        buf.push(b'\n');
        Ok(buf)
    }
}

// ---------------------------------------------------------------------------
// alert
// ---------------------------------------------------------------------------

/// What the sensor did about a match.
///
/// Guide §6 requires every alert to record the action taken. v1 is
/// detection-only, so `Alerted` is the only variant; prevention actions would
/// extend this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertAction {
    /// The event was recorded; traffic was not altered.
    Alerted,
}

/// Which sensor half produced an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSource {
    /// Network detection (NIDS).
    Network,
    /// Host detection (HIDS).
    Host,
}

/// Body of an `alert` event.
///
/// Populated by the detection engine from Phase 3; defined here in Phase 0 so
/// the schema and its consumers exist before the engine does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertEvent {
    /// Action taken. Always [`AlertAction::Alerted`] in v1.
    pub action: AlertAction,
    /// Whether the match came from the network or host side.
    pub source: AlertSource,
    /// Signature id of the matching rule.
    pub sid: u32,
    /// Revision of the matching rule.
    pub rev: u32,
    /// The rule's `msg`.
    pub signature: String,
    /// The rule's `classtype`, if it declared one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classtype: Option<String>,
    /// Severity, 1 (most severe) to 4.
    pub severity: u8,
    /// The rule's `metadata` key/value pairs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Vec<String>>,
}

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

/// Body of a `stats` event: periodic sensor health.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsEvent {
    /// Seconds since the sensor started.
    pub uptime_secs: u64,
    /// Event-pipeline counters.
    pub events: EventStats,
    /// Rule-loading counters from the most recent load.
    pub rules: RuleStats,
    /// Packet-capture counters.
    pub capture: CaptureStats,
    /// Detection-engine counters.
    pub engine: EngineStats,
}

/// Counters for the decoupled event pipeline.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventStats {
    /// Events handed to the pipeline.
    pub emitted: u64,
    /// Events dropped because the queue was full. **Non-zero means the sink
    /// could not keep up and events were lost** — this is a coverage hole.
    pub dropped: u64,
    /// Events successfully written to at least one sink.
    pub written: u64,
    /// Sink write failures.
    pub write_errors: u64,
    /// Events currently queued.
    pub queued: u64,
    /// Queue capacity.
    pub queue_capacity: u64,
}

/// Counters describing the loaded ruleset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleStats {
    /// Rules loaded successfully.
    pub loaded: u64,
    /// Rules skipped because they could not be parsed or are unsupported.
    pub skipped: u64,
    /// Loaded rules carrying at least one option this build cannot yet evaluate.
    pub with_unsupported_options: u64,
}

/// Counters for packet capture.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureStats {
    /// Whether capture is running. `false` until Phase 1 lands, which is why
    /// the counters below read zero.
    pub enabled: bool,
    /// Packets received.
    pub packets: u64,
    /// Bytes received.
    pub bytes: u64,
    /// Packets dropped by the kernel or capture library. **Drops are silent
    /// coverage holes** (guide §9).
    pub drops: u64,
}

/// Counters for the detection engine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStats {
    /// Whether detection is running. `false` until Phase 3 lands.
    pub enabled: bool,
    /// Alerts raised.
    pub alerts: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Timestamp;
    use serde_json::Value;

    fn sensor() -> SensorInfo {
        SensorInfo {
            name: "test-host".into(),
            id: "8f1a0d4e-0000-4000-8000-000000000001".into(),
            version: "0.1.0".into(),
        }
    }

    fn stats_event() -> Event {
        Event::new(
            Timestamp::now(),
            sensor(),
            Payload::stats(StatsEvent::default()),
        )
    }

    #[test]
    fn event_type_mirrors_the_payload() {
        assert_eq!(stats_event().event_type, EventKind::Stats);
        let alert = Event::new(
            Timestamp::now(),
            sensor(),
            Payload::alert(AlertEvent {
                action: AlertAction::Alerted,
                source: AlertSource::Network,
                sid: 1_000_001,
                rev: 1,
                signature: "test".into(),
                classtype: None,
                severity: 3,
                metadata: BTreeMap::new(),
            }),
        );
        assert_eq!(alert.event_type, EventKind::Alert);
    }

    #[test]
    fn stats_body_is_flattened_under_its_kind() {
        let json: Value = serde_json::from_slice(&stats_event().to_ndjson().unwrap()).unwrap();
        assert_eq!(json["event_type"], "stats");
        assert!(
            json["stats"].is_object(),
            "stats body must be flattened in: {json}"
        );
        assert_eq!(json["stats"]["uptime_secs"], 0);
        assert!(json["timestamp"].as_str().unwrap().ends_with('Z'));
        assert_eq!(json["sensor"]["name"], "test-host");
    }

    #[test]
    fn ndjson_is_exactly_one_line() {
        let line = stats_event().to_ndjson().unwrap();
        assert_eq!(line.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(*line.last().unwrap(), b'\n');
    }

    #[test]
    fn absent_five_tuple_fields_are_omitted() {
        let json: Value = serde_json::from_slice(&stats_event().to_ndjson().unwrap()).unwrap();
        for field in [
            "flow_id",
            "src_ip",
            "src_port",
            "dest_ip",
            "dest_port",
            "proto",
        ] {
            assert!(
                json.get(field).is_none(),
                "{field} should be omitted when unset"
            );
        }
    }

    #[test]
    fn five_tuple_is_emitted_at_the_top_level() {
        let event = stats_event().with_flow_id(42).with_net(NetTuple {
            src_ip: "192.0.2.1".parse().unwrap(),
            src_port: Some(1234),
            dest_ip: "198.51.100.7".parse().unwrap(),
            dest_port: Some(80),
            proto: Protocol::Tcp,
        });
        let json: Value = serde_json::from_slice(&event.to_ndjson().unwrap()).unwrap();
        assert_eq!(json["flow_id"], 42);
        assert_eq!(json["src_ip"], "192.0.2.1");
        assert_eq!(json["src_port"], 1234);
        assert_eq!(json["dest_ip"], "198.51.100.7");
        assert_eq!(json["dest_port"], 80);
        assert_eq!(json["proto"], "TCP");
    }

    #[test]
    fn icmp_tuple_omits_ports() {
        let event = stats_event().with_net(NetTuple {
            src_ip: "192.0.2.1".parse().unwrap(),
            src_port: None,
            dest_ip: "198.51.100.7".parse().unwrap(),
            dest_port: None,
            proto: Protocol::Icmp,
        });
        let json: Value = serde_json::from_slice(&event.to_ndjson().unwrap()).unwrap();
        assert_eq!(json["proto"], "ICMP");
        assert!(json.get("src_port").is_none());
    }

    #[test]
    fn round_trips_through_json() {
        let event = stats_event().with_flow_id(7);
        let back: Event = serde_json::from_slice(&event.to_ndjson().unwrap()).unwrap();
        assert_eq!(back, event);
    }
}
