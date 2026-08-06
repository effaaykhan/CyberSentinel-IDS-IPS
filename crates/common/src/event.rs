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
    /// A structural problem was found while decoding a packet.
    Anomaly,
    /// A flow ended.
    Flow,
    /// A watched file changed.
    Fim,
    /// An authentication attempt was observed.
    Auth,
    /// A process started, exited, or began listening.
    Process,
    /// Several events on one host were judged to be one incident.
    Incident,
    /// Periodic sensor health and counters.
    Stats,
}

impl EventKind {
    /// The wire string for this kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Anomaly => "anomaly",
            Self::Flow => "flow",
            Self::Fim => "fim",
            Self::Auth => "auth",
            Self::Process => "process",
            Self::Incident => "incident",
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
    /// A malformed packet. See [`AnomalyEvent`].
    Anomaly(Box<AnomalyEvent>),
    /// A flow ended. See [`FlowEvent`].
    Flow(Box<FlowEvent>),
    /// A watched file changed. See [`FimEvent`].
    Fim(Box<FimEvent>),
    /// An authentication attempt. See [`AuthEvent`].
    Auth(Box<AuthEvent>),
    /// A process event. See [`ProcessEvent`].
    Process(Box<ProcessEvent>),
    /// Correlated events. See [`IncidentEvent`].
    Incident(Box<IncidentEvent>),
    /// Periodic counters. See [`StatsEvent`].
    Stats(Box<StatsEvent>),
}

impl Payload {
    /// Which [`EventKind`] this body corresponds to.
    #[must_use]
    pub fn kind(&self) -> EventKind {
        match self {
            Self::Alert(_) => EventKind::Alert,
            Self::Anomaly(_) => EventKind::Anomaly,
            Self::Flow(_) => EventKind::Flow,
            Self::Fim(_) => EventKind::Fim,
            Self::Auth(_) => EventKind::Auth,
            Self::Process(_) => EventKind::Process,
            Self::Incident(_) => EventKind::Incident,
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

    /// Wrap an [`AnomalyEvent`].
    #[must_use]
    pub fn anomaly(anomaly: AnomalyEvent) -> Self {
        Self::Anomaly(Box::new(anomaly))
    }

    /// Wrap a [`FlowEvent`].
    #[must_use]
    pub fn flow(flow: FlowEvent) -> Self {
        Self::Flow(Box::new(flow))
    }

    /// Wrap a [`FimEvent`].
    #[must_use]
    pub fn fim(fim: FimEvent) -> Self {
        Self::Fim(Box::new(fim))
    }

    /// Wrap an [`AuthEvent`].
    #[must_use]
    pub fn auth(auth: AuthEvent) -> Self {
        Self::Auth(Box::new(auth))
    }

    /// Wrap a [`ProcessEvent`].
    #[must_use]
    pub fn process(process: ProcessEvent) -> Self {
        Self::Process(Box::new(process))
    }

    /// Wrap an [`IncidentEvent`].
    #[must_use]
    pub fn incident(incident: IncidentEvent) -> Self {
        Self::Incident(Box::new(incident))
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
    /// The event was recorded **and** the traffic was acted on: the flow was
    /// terminated and its source blocked from this point on.
    ///
    /// Deliberately not read as "no byte of this attack reached the target".
    /// Matching needs reassembly, so the packets that carried the signature
    /// have already been forwarded by the time a rule can match on them. What
    /// `blocked` promises is that the rest of the flow and subsequent
    /// connections from that source are dropped — see `crates/prevent`.
    Blocked,
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
// anomaly
// ---------------------------------------------------------------------------

/// One structural problem found in a packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnomalyRecord {
    /// Layer being decoded, e.g. `ipv4`.
    pub layer: String,
    /// What was wrong, e.g. `length_mismatch`.
    pub kind: String,
}

/// Body of an `anomaly` event: a packet that is malformed at the wire level.
///
/// **One event per packet, not per anomaly.** A single crafted frame can be
/// wrong in several ways at once, and emitting an event for each would let one
/// packet multiply into an event flood — the pipeline's cost per packet has to
/// stay bounded.
///
/// Whatever the decoder did manage to read is still in the envelope, so an
/// anomalous packet remains attributable to a host and a flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnomalyEvent {
    /// Everything wrong with this packet.
    pub anomalies: Vec<AnomalyRecord>,
    /// Interface or capture file the packet came from.
    pub interface: String,
    /// Bytes actually captured.
    pub captured_len: u32,
    /// Length on the wire before snap-length clipping.
    pub packet_len: u32,
    /// Whether more anomalies were found than the per-packet cap allows.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub anomalies_truncated: bool,
}

// ---------------------------------------------------------------------------
// flow
// ---------------------------------------------------------------------------

/// Why a flow ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowEndReason {
    /// TCP teardown was observed: FIN in both directions, or a RST.
    Closed,
    /// The flow went idle past the configured timeout.
    TimedOut,
    /// The flow table hit its cap and this flow was evicted to make room.
    ///
    /// **Evictions are a coverage signal**: the sensor stopped tracking a
    /// conversation that was still live.
    Evicted,
    /// The sensor shut down, or a capture file ended, while the flow was open.
    SensorStopped,
}

/// Body of a `flow` event, emitted when a flow ends.
///
/// The envelope carries the `flow_id` and the 5-tuple, oriented so that `src_*`
/// is whichever endpoint sent the first packet. "To server" therefore means
/// "in the direction the flow was opened in".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowEvent {
    /// Why the flow ended.
    pub reason: FlowEndReason,
    /// First packet seen.
    pub start: Timestamp,
    /// Last packet seen.
    pub end: Timestamp,
    /// Milliseconds between the first and last packet.
    pub duration_ms: u64,
    /// Packets from the initiator.
    pub packets_to_server: u64,
    /// Bytes from the initiator.
    pub bytes_to_server: u64,
    /// Packets towards the initiator.
    pub packets_to_client: u64,
    /// Bytes towards the initiator.
    pub bytes_to_client: u64,
    /// Union of the TCP flags seen on the flow, e.g. `SAPF`. Absent for
    /// protocols without them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_flags: Option<String>,
}

// ---------------------------------------------------------------------------
// host events
// ---------------------------------------------------------------------------

/// What happened to a watched file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChange {
    /// The path appeared.
    Created,
    /// Contents changed.
    Modified,
    /// Ownership, mode, or timestamps changed.
    AttributesChanged,
    /// The path was removed.
    Deleted,
    /// The path was renamed.
    Renamed,
}

impl FileChange {
    /// Stable identifier used in event JSON and rules.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Modified => "modified",
            Self::AttributesChanged => "attributes_changed",
            Self::Deleted => "deleted",
            Self::Renamed => "renamed",
        }
    }
}

/// How a file change came to the sensor's attention.
///
/// The distinction matters operationally: a change found by the rescan is one
/// real-time watching **did not see**, which is either a gap in coverage or a
/// change made while the sensor was down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FimDetection {
    /// Reported by the kernel as it happened.
    RealTime,
    /// Found by comparing against the stored baseline.
    BaselineRescan,
}

impl FimDetection {
    /// Stable identifier used in event JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RealTime => "real_time",
            Self::BaselineRescan => "baseline_rescan",
        }
    }
}

/// Body of a `fim` event: a watched file changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FimEvent {
    /// The path that changed.
    pub path: String,
    /// What happened to it.
    pub change: FileChange,
    /// Whether the kernel told us or the rescan found it.
    pub detected_by: FimDetection,
    /// Size after the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Content hash after the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Content hash before it, where a baseline existed.
    ///
    /// Both hashes present and equal means the metadata moved but the bytes did
    /// not — a touch, not an edit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_sha256: Option<String>,
    /// Unix mode after the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// Owning user id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Owning group id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
}

/// Whether an authentication attempt succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthOutcome {
    /// The attempt succeeded.
    Success,
    /// The attempt failed.
    Failure,
}

impl AuthOutcome {
    /// Stable identifier used in event JSON and rules.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Body of an `auth` event: an authentication attempt.
///
/// The fields come from log text an attacker may partly control — a username is
/// whatever was typed at a login prompt. [`AuthEvent::suspicious`] records what
/// the parser refused to take at face value, so a forged-looking record is
/// visible rather than quietly trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthEvent {
    /// Success or failure.
    pub outcome: AuthOutcome,
    /// The account named in the attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// The service that reported it — `sshd`, `sudo`, ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Where the attempt came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address: Option<IpAddr>,
    /// Source port, where the log recorded one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    /// The log line, sanitised for transport.
    pub message: String,
    /// Where the record came from — `journald`, or a file path.
    pub log_source: String,
    /// What looked wrong about the record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suspicious: Vec<String>,
}

/// What a process did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessChange {
    /// A process appeared.
    Started,
    /// A process went away.
    Exited,
    /// A process began listening on a socket.
    Listening,
}

impl ProcessChange {
    /// Stable identifier used in event JSON and rules.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Exited => "exited",
            Self::Listening => "listening",
        }
    }
}

/// Body of a `process` event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEvent {
    /// What happened.
    pub change: ProcessChange,
    /// Process id.
    pub pid: u32,
    /// Executable name.
    pub name: String,
    /// Full path to the executable, where it could be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// The command line, truncated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// Owning user id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Parent process id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
}

/// One event that contributed to an incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentContributor {
    /// The contributing event's type.
    pub event_type: EventKind,
    /// Signature id, for contributors that were alerts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<u32>,
    /// A one-line description.
    pub summary: String,
    /// When it happened.
    pub timestamp: Timestamp,
}

/// Body of an `incident` event: several observations judged to be one thing.
///
/// The point of running host and network detection in one sensor: a file change
/// and a network alert on the same host inside a short window are usually one
/// story, and an analyst should be shown it as one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentEvent {
    /// Why these events were grouped.
    pub reason: String,
    /// Highest severity among the contributors.
    pub severity: u8,
    /// Earliest contributing event.
    pub first_seen: Timestamp,
    /// Latest contributing event.
    pub last_seen: Timestamp,
    /// What went into it, in time order.
    pub contributors: Vec<IncidentContributor>,
}

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

/// Body of a `stats` event: periodic sensor health.
///
/// Not `Eq`: `capture.drop_rate` is a float.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StatsEvent {
    /// Seconds since the sensor started.
    pub uptime_secs: u64,
    /// Event-pipeline counters.
    pub events: EventStats,
    /// Rule-loading counters from the most recent load.
    pub rules: RuleStats,
    /// Packet-capture counters.
    pub capture: CaptureStats,
    /// Packet-decoding counters.
    pub decode: DecodeStats,
    /// Flow-table counters.
    pub flows: FlowStats,
    /// Defragmentation and stream-reassembly counters.
    pub reassembly: ReassemblyStats,
    /// Detection-engine counters.
    pub engine: EngineStats,
    /// Host-monitoring counters.
    pub hids: HidsStats,
    /// Correlation counters.
    pub correlation: CorrelationStats,
    /// Inline prevention counters.
    pub prevent: PreventStats,
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
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CaptureStats {
    /// Whether capture is running.
    pub enabled: bool,
    /// The interface or capture file frames are coming from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Packets received.
    pub packets: u64,
    /// Bytes received.
    pub bytes: u64,
    /// Packets the kernel dropped because our buffer was full. **Drops are
    /// silent coverage holes** (guide §9): traffic arrived and was never
    /// examined. Raise the capture buffer size when this is non-zero.
    pub drops: u64,
    /// Packets the interface or its driver dropped before the kernel saw them.
    pub interface_drops: u64,
    /// Dropped packets as a fraction of everything offered to the sensor.
    pub drop_rate: f64,
}

/// Counters for packet decoding.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodeStats {
    /// Whether decoding is running.
    pub enabled: bool,
    /// Frames decoded.
    pub packets: u64,
    /// Frames carrying IPv4.
    pub ipv4: u64,
    /// Frames carrying IPv6.
    pub ipv6: u64,
    /// TCP segments.
    pub tcp: u64,
    /// UDP datagrams.
    pub udp: u64,
    /// ICMP and ICMPv6 messages.
    pub icmp: u64,
    /// Frames with no IP layer — ARP and friends. Ordinary traffic.
    pub non_ip: u64,
    /// IP fragments seen. Reassembled from Phase 2.
    pub fragments: u64,
    /// Frames clipped by the capture snap length.
    pub snapped: u64,
    /// Frames with at least one anomaly.
    pub anomalous: u64,
    /// Anomalies recorded across all frames.
    pub anomalies: u64,
}

/// Counters for the flow table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowStats {
    /// Whether flow tracking is running.
    pub enabled: bool,
    /// Flows currently tracked.
    pub active: u64,
    /// Flows created since start.
    pub created: u64,
    /// Flows ended by an observed TCP teardown.
    pub closed: u64,
    /// Flows ended by the idle timeout.
    pub timed_out: u64,
    /// Flows evicted because the table was full. **Non-zero means the sensor
    /// stopped following conversations that were still live** — raise
    /// `max_flows`, or find out what is opening so many.
    pub evicted: u64,
    /// Maximum flows the table will hold.
    pub capacity: u64,
}

/// Counters for IP defragmentation and TCP stream reassembly.
///
/// The `conflict` counters are the ones to alarm on: they mean two copies of
/// the same bytes arrived **disagreeing**, and the sensor had to break the tie
/// with the configured overlap policy. That is either a badly broken stack or
/// somebody trying to show the sensor and the host different things.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReassemblyStats {
    /// Whether reassembly is running.
    pub enabled: bool,
    /// IP fragments seen.
    pub fragments: u64,
    /// Datagrams fully reassembled from fragments.
    pub datagrams_reassembled: u64,
    /// Fragment reassemblies in progress.
    pub fragment_sets_active: u64,
    /// Incomplete datagrams discarded on timeout.
    pub fragment_timeouts: u64,
    /// Incomplete datagrams evicted under memory pressure. **A coverage
    /// signal** — an attack may have been inside one.
    pub fragment_evictions: u64,
    /// Fragment bytes that arrived twice and disagreed.
    pub fragment_conflicts: u64,
    /// Bytes currently held in TCP reassembly buffers.
    pub stream_bytes_buffered: u64,
    /// Stream bytes handed to detection.
    pub stream_bytes_delivered: u64,
    /// Stream bytes that arrived twice and disagreed.
    pub stream_conflicts: u64,
    /// Stream bytes addressed outside any plausible receive window.
    pub stream_out_of_window: u64,
    /// Stream bytes offered after a FIN closed that direction.
    pub stream_after_fin: u64,
    /// Stream bytes delivered without an acknowledgement, because the buffer
    /// filled. Expected on a one-way tap; unexpected otherwise.
    pub stream_flushed_unacked: u64,
    /// Buffered stream bytes dropped because a flow ended with a hole in it.
    pub stream_dropped_incomplete: u64,
    /// Resets ignored as ones the destination would not have acted on.
    ///
    /// Non-zero means somebody sent a reset the sensor judged forged — a
    /// broken middlebox, or an attempt to stop the sensor watching a live
    /// connection.
    pub resets_ignored: u64,
}

/// Whether a host event source is actually working.
///
/// A sensor that reports nothing looks identical whether the host is quiet or
/// the source that watches it is broken. On Linux that distinction was made by
/// counters; porting to another OS makes it structural, because the ways a
/// source can fail differ per platform while "we are not seeing this any more"
/// does not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    /// Running. It may legitimately have nothing to report.
    #[default]
    Active,
    /// Running with less coverage than it should have. **A partial hole.**
    Degraded,
    /// Configured, but could not start on this host — a missing binary, a
    /// permission, a disabled audit policy. **A hole.**
    Unavailable,
    /// Not implemented for this platform yet. **A hole**, and an expected one,
    /// but an operator reading a quiet sensor still needs to be told.
    Unsupported,
}

impl SourceState {
    /// The wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
        }
    }

    /// Whether this state means coverage is missing.
    #[must_use]
    pub fn is_hole(self) -> bool {
        !matches!(self, Self::Active)
    }
}

/// One host event source and what it is doing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceStatus {
    /// Stable identifier — `fim.realtime`, `auth.journald`, `process.table`.
    pub name: String,
    /// Whether it is working.
    pub state: SourceState,
    /// Why, in one line. Always set when the state is not `active`, because
    /// "unavailable" without a reason is not actionable.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// How much this source has produced since start.
    pub records: u64,
}

/// Counters for inline prevention.
///
/// `mode` and `fail_mode` are strings rather than counters on purpose: an
/// operator reading a `stats` event needs to know whether this sensor is
/// currently able to drop anything at all, and inferring that from a zero
/// drop count is exactly the ambiguity the rest of this schema avoids.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreventStats {
    /// Whether inline prevention is running at all.
    pub enabled: bool,
    /// `detect` or `prevent`. **The arming state.**
    pub mode: String,
    /// `open` or `closed` — what the kernel does when the sensor is not
    /// answering. Enforced by the queueing rule, not by the sensor.
    pub fail_mode: String,
    /// Packets the verdict path judged.
    pub packets_judged: u64,
    /// Packets dropped.
    pub packets_dropped: u64,
    /// Packets that passed because an endpoint is on the allow-list.
    pub allow_listed_passes: u64,
    /// Block verdicts refused because an endpoint is on the allow-list.
    ///
    /// Non-zero means a rule is matching traffic an operator has declared
    /// must never be blocked — worth knowing, in both directions.
    pub allow_listed_blocks_refused: u64,
    /// Flows condemned by a rule.
    pub flows_blocked: u64,
    /// Sources added to the block set.
    pub sources_blocked: u64,
    /// Flows currently carrying a block verdict.
    pub blocked_flows_active: u64,
    /// Sources currently blocked.
    pub blocked_sources_active: u64,
    /// Flow verdicts that lapsed.
    pub flow_verdicts_expired: u64,
    /// Source blocks that lapsed.
    pub source_blocks_expired: u64,
    /// Block verdicts that could not be recorded because state was full.
    ///
    /// **A coverage hole**: a rule asked for traffic to be dropped and it was
    /// not.
    pub blocks_dropped_at_capacity: u64,
    /// Packets the kernel disposed of by the fail mode rather than asking.
    pub fail_mode_packets: u64,
    /// Total verdict latency in microseconds, for an average.
    pub verdict_latency_us_total: u64,
    /// Worst verdict latency seen, in microseconds. Every microsecond here is
    /// added to every packet on the path.
    pub verdict_latency_us_max: u64,
    /// Verdicts that took longer than a millisecond.
    ///
    /// A count rather than a percentile because the shape that matters is not
    /// the median — which is a hash lookup — but the tail, and a tail that is
    /// growing is a queue about to back up.
    pub verdict_latency_over_1ms: u64,
    /// Verdicts that took longer than ten milliseconds.
    pub verdict_latency_over_10ms: u64,
    /// Packets the kernel had queued for us at the last reading.
    ///
    /// The depth grows before anything is dropped, so this is the early
    /// warning that `fail_mode_packets` is the confirmation of.
    pub queue_depth: u64,
    /// The deepest the queue has been seen.
    pub queue_depth_max: u64,
    /// Packets the **kernel** discarded before the sensor could judge them —
    /// a full queue, or a netlink buffer that could not take them.
    ///
    /// **A coverage hole, and the one the sensor cannot see from the inside**:
    /// from the verdict loop, packets that never arrived are indistinguishable
    /// from a quiet link. Read from
    /// `/proc/net/netfilter/nfnetlink_queue`.
    pub queue_unjudged: u64,
}

/// Counters for host monitoring.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HidsStats {
    /// Whether host monitoring is running.
    pub enabled: bool,
    /// Paths currently watched in real time.
    pub watched_paths: u64,
    /// Watches that could not be established. **A coverage hole**: changes to
    /// those paths are only caught by the rescan.
    pub watch_failures: u64,
    /// File changes reported by the kernel as they happened.
    pub fim_realtime: u64,
    /// File changes found by comparing against the baseline.
    ///
    /// Non-zero means real-time watching did not see them — because the sensor
    /// was down, or because the kernel queue overflowed.
    pub fim_rescan: u64,
    /// Times the kernel's event queue overflowed.
    ///
    /// **Every overflow is an unknown number of missed changes.** Each one
    /// forces an immediate rescan and is reported.
    pub inotify_overflows: u64,
    /// Baseline rescans completed.
    pub rescans: u64,
    /// Files in the baseline.
    pub baseline_entries: u64,
    /// Authentication records parsed.
    pub auth_records: u64,
    /// Log lines that could not be parsed into a record.
    pub auth_unparsed: u64,
    /// Auth records carrying something the parser would not take at face value.
    pub auth_suspicious: u64,
    /// Process events emitted.
    pub process_events: u64,
    /// Host alerts raised.
    pub host_alerts: u64,
    /// Every event source and whether it is actually working.
    ///
    /// The point of listing sources that are **not** working is that they are
    /// otherwise indistinguishable from a quiet host. A consumer should alarm
    /// on any entry whose state is not `active`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<SourceStatus>,
}

/// Counters for host/network correlation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationStats {
    /// Whether correlation is running.
    pub enabled: bool,
    /// Observations offered for correlation.
    pub observations: u64,
    /// Incidents emitted.
    pub incidents: u64,
    /// Observations dropped because the window was full.
    pub dropped: u64,
}

/// Counters for the detection engine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStats {
    /// Whether detection is running.
    pub enabled: bool,
    /// Rules armed and matching.
    pub rules_armed: u64,
    /// Rules loaded but awaiting engine support for a keyword.
    pub rules_awaiting_support: u64,
    /// Rules that failed to compile. **Not running**, and someone wrote them.
    pub rules_failed: u64,
    /// Rules with no usable pre-filter pattern, evaluated on every packet.
    pub rules_without_prefilter: u64,
    /// Buffers inspected.
    pub inspections: u64,
    /// Bytes inspected.
    pub bytes_inspected: u64,
    /// Rules the pre-filter put forward for full evaluation.
    pub candidates: u64,
    /// Rules that fully matched.
    pub matches: u64,
    /// Alerts raised.
    pub alerts: u64,
    /// Matches suppressed by a `threshold`.
    pub thresholded: u64,
    /// Matches that raised no alert because of `flowbits:noalert`.
    pub silent: u64,
    /// Flows carrying detection state.
    pub flow_states: u64,
    /// Detection states evicted under the cap. **A coverage signal.**
    pub flow_states_evicted: u64,
    /// Stream bytes that fell out of an inspection window before matching.
    pub inspection_bytes_dropped: u64,
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

    fn tuple() -> NetTuple {
        NetTuple {
            src_ip: "192.0.2.1".parse().unwrap(),
            src_port: Some(51_000),
            dest_ip: "198.51.100.7".parse().unwrap(),
            dest_port: Some(80),
            proto: Protocol::Tcp,
        }
    }

    #[test]
    fn an_anomaly_event_carries_every_problem_with_one_packet() {
        let event = Event::new(
            Timestamp::now(),
            sensor(),
            Payload::anomaly(AnomalyEvent {
                anomalies: vec![
                    AnomalyRecord {
                        layer: "ipv4".into(),
                        kind: "length_mismatch".into(),
                    },
                    AnomalyRecord {
                        layer: "tcp".into(),
                        kind: "impossible_length".into(),
                    },
                ],
                interface: "eth0".into(),
                captured_len: 64,
                packet_len: 1_514,
                anomalies_truncated: false,
            }),
        )
        .with_net(tuple());

        let json: Value = serde_json::from_slice(&event.to_ndjson().unwrap()).unwrap();
        assert_eq!(json["event_type"], "anomaly");
        assert_eq!(json["anomaly"]["anomalies"].as_array().unwrap().len(), 2);
        assert_eq!(json["anomaly"]["anomalies"][0]["layer"], "ipv4");
        assert_eq!(json["anomaly"]["packet_len"], 1_514);
        // Still attributable to a host even though the packet was malformed.
        assert_eq!(json["src_ip"], "192.0.2.1");
        assert!(
            json["anomaly"].get("anomalies_truncated").is_none(),
            "a false flag should not clutter every event"
        );
    }

    #[test]
    fn a_flow_event_reports_both_directions() {
        let start = Timestamp::now();
        let event = Event::new(
            start,
            sensor(),
            Payload::flow(FlowEvent {
                reason: FlowEndReason::Closed,
                start,
                end: start,
                duration_ms: 1_234,
                packets_to_server: 5,
                bytes_to_server: 600,
                packets_to_client: 4,
                bytes_to_client: 4_000,
                tcp_flags: Some("SAPF".into()),
            }),
        )
        .with_flow_id(99)
        .with_net(tuple());

        let json: Value = serde_json::from_slice(&event.to_ndjson().unwrap()).unwrap();
        assert_eq!(json["event_type"], "flow");
        assert_eq!(json["flow_id"], 99);
        assert_eq!(json["flow"]["reason"], "closed");
        assert_eq!(json["flow"]["packets_to_server"], 5);
        assert_eq!(json["flow"]["bytes_to_client"], 4_000);
        assert_eq!(json["flow"]["tcp_flags"], "SAPF");
    }

    #[test]
    fn every_event_kind_matches_its_body_key() {
        // The invariant the whole schema rests on: `event_type` names the key
        // the body is under, so a consumer can dispatch on one field.
        let bodies = [
            Payload::stats(StatsEvent::default()),
            Payload::anomaly(AnomalyEvent {
                anomalies: Vec::new(),
                interface: "eth0".into(),
                captured_len: 0,
                packet_len: 0,
                anomalies_truncated: true,
            }),
            Payload::flow(FlowEvent {
                reason: FlowEndReason::TimedOut,
                start: Timestamp::now(),
                end: Timestamp::now(),
                duration_ms: 0,
                packets_to_server: 0,
                bytes_to_server: 0,
                packets_to_client: 0,
                bytes_to_client: 0,
                tcp_flags: None,
            }),
            Payload::alert(AlertEvent {
                action: AlertAction::Alerted,
                source: AlertSource::Network,
                sid: 1,
                rev: 1,
                signature: "s".into(),
                classtype: None,
                severity: 3,
                metadata: BTreeMap::new(),
            }),
        ];

        for body in bodies {
            let kind = body.kind();
            let event = Event::new(Timestamp::now(), sensor(), body);
            let json: Value = serde_json::from_slice(&event.to_ndjson().unwrap()).unwrap();
            assert_eq!(json["event_type"], kind.as_str());
            assert!(
                json.get(kind.as_str()).is_some_and(Value::is_object),
                "{} body must be flattened under its own key: {json}",
                kind.as_str()
            );
        }
    }

    #[test]
    fn stats_reports_the_new_pipeline_sections() {
        let json: Value = serde_json::from_slice(&stats_event().to_ndjson().unwrap()).unwrap();
        for section in ["events", "rules", "capture", "decode", "flows", "engine"] {
            assert!(
                json["stats"][section].is_object(),
                "missing stats.{section}: {json}"
            );
        }
        assert_eq!(json["stats"]["capture"]["drop_rate"], 0.0);
    }
}
