//! The packet pipeline: capture → decode → flow tracking → events.
//!
//! This is the join between the per-stage crates. It owns the flow table and
//! the decode counters, runs on the capture thread, and is the only place that
//! turns a decoded packet into CyberSentinel events.
//!
//! # Threading
//!
//! One instance per capture source, on that source's thread. It publishes a
//! [`PipelineSnapshot`] into a shared slot every so often so the stats thread
//! can report counters without touching pipeline state. Events go out through
//! the [`EventEmitter`], which is already non-blocking by construction.
//!
//! # Event volume is bounded per packet
//!
//! A packet produces at most one `anomaly` event, no matter how many things are
//! wrong with it, plus whatever `flow` events its arrival happened to expire.
//! That ceiling matters: an attacker choosing what to send should not be able
//! to choose how many events the sensor emits per packet.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use cybersentinel_capture::{CaptureCounters, RawPacket};
use cybersentinel_common::config::Config;
use cybersentinel_common::event::{
    AlertAction, AlertEvent, AlertSource, AnomalyEvent, AnomalyRecord, FlowEndReason, FlowEvent,
    NetTuple, Payload, Protocol,
};
use cybersentinel_common::eventlog::EventEmitter;
use cybersentinel_common::Timestamp;
use cybersentinel_decode::{DecodeCounters, Decoded, Network, Transport};
use cybersentinel_engine::{AlertRecord, Engine, EngineCounters};
use cybersentinel_reassembly::defrag::{DefragCounters, Defragmenter, FragmentView, Reassembled};
use cybersentinel_reassembly::flow::{
    EndReason, EndedFlow, FlowCounters, FlowTable, PacketSummary,
};
use cybersentinel_reassembly::policy::PolicyResolver;
use cybersentinel_reassembly::stream::{StreamCounters, StreamReady, TcpSegment};
use cybersentinel_reassembly::Limits;

/// A read of the pipeline's counters, published for the stats thread.
#[derive(Debug, Clone, Default)]
pub struct PipelineSnapshot {
    /// Where frames are coming from.
    pub source: String,
    /// Capture-side counters, including kernel drops.
    pub capture: CaptureCounters,
    /// Decode-side counters.
    pub decode: DecodeCounters,
    /// Flow-table counters.
    pub flows: FlowCounters,
    /// Flows currently tracked.
    pub active_flows: u64,
    /// Flow-table capacity.
    pub flow_capacity: u64,
    /// IP defragmentation counters.
    pub defrag: DefragCounters,
    /// Fragment reassemblies in progress.
    pub active_fragment_sets: u64,
    /// TCP stream reassembly counters.
    pub streams: StreamCounters,
    /// Bytes held in stream reassembly buffers.
    pub stream_bytes_buffered: u64,
    /// Detection-engine counters.
    pub engine: EngineCounters,
    /// Rules armed and matching.
    pub rules_armed: u64,
    /// Rules loaded but awaiting engine support.
    pub rules_awaiting_support: u64,
    /// Rules that failed to compile.
    pub rules_failed: u64,
    /// Rules with no usable pre-filter pattern.
    pub rules_without_prefilter: u64,
    /// Whether a replayed capture file was torn.
    pub capture_truncated: bool,
}

/// Shared slot the capture thread publishes into.
pub type SharedSnapshot = Arc<Mutex<PipelineSnapshot>>;

/// What the pipeline emits.
#[derive(Debug, Clone)]
pub struct PipelineOptions {
    /// Emit an `anomaly` event per malformed packet.
    pub emit_anomaly_events: bool,
    /// Emit a `flow` event when a flow ends.
    pub emit_flow_events: bool,
    /// Write reassembled stream content to this directory.
    ///
    /// **Off unless explicitly asked for, and a debugging aid only.**
    /// Reassembled streams are bulk payload — credentials, personal data,
    /// whatever the traffic carried — so writing them to disk is a decision an
    /// operator has to make deliberately. Alert-triggered evidence capture is a
    /// later phase and is a different thing entirely.
    pub dump_streams_to: Option<PathBuf>,
}

/// Decode, defragment, reassemble, and flow-track packets, emitting events.
#[derive(Debug)]
pub struct PacketPipeline {
    emitter: EventEmitter,
    flows: FlowTable,
    defrag: Defragmenter,
    policy: PolicyResolver,
    decode: DecodeCounters,
    /// Reused across packets so delivery costs no allocation.
    ready: StreamReady,
    stream_bytes_delivered: u64,
    /// The detection engine, once rules are armed.
    engine: Option<Engine>,
    /// Reused across packets so alerting costs no allocation.
    alerts: Vec<AlertRecord>,
    rules_armed: u64,
    rules_awaiting_support: u64,
    rules_failed: u64,
    rules_without_prefilter: u64,
    options: PipelineOptions,
    source: String,
}

impl PacketPipeline {
    /// Build a pipeline from the loaded config.
    #[must_use]
    pub fn new(
        emitter: EventEmitter,
        config: &Config,
        options: PipelineOptions,
        source: impl Into<String>,
    ) -> Self {
        let limits = Limits {
            max_flows: config.flow.max_flows,
            flow_timeout: std::time::Duration::from_secs(config.flow.timeout_secs),
            max_fragment_sets: config.reassembly.max_fragment_sets,
            fragment_timeout: std::time::Duration::from_secs(
                config.reassembly.fragment_timeout_secs,
            ),
            ..Limits::default()
        };
        Self {
            emitter,
            flows: FlowTable::with_reassembly(limits, config.reassembly.clone()),
            defrag: Defragmenter::new(&config.reassembly),
            policy: PolicyResolver::from_config(&config.reassembly),
            decode: DecodeCounters::default(),
            ready: StreamReady::default(),
            stream_bytes_delivered: 0,
            engine: None,
            alerts: Vec::new(),
            rules_armed: 0,
            rules_awaiting_support: 0,
            rules_failed: 0,
            rules_without_prefilter: 0,
            options,
            source: source.into(),
        }
    }

    /// Arm the detection engine.
    pub fn arm(&mut self, engine: Engine, report: &cybersentinel_engine::CompileReport) {
        self.rules_armed = report.compiled as u64;
        self.rules_awaiting_support = report.not_evaluable as u64;
        self.rules_failed = report.failed.len() as u64;
        self.rules_without_prefilter = report.without_prefilter as u64;
        self.engine = Some(engine);
    }

    /// Decode one captured frame and emit whatever it warrants.
    pub fn on_packet(&mut self, packet: &RawPacket<'_>) {
        let decoded = cybersentinel_decode::decode(packet.data, packet.original_len);
        self.decode.record(&decoded);

        let flow_id = self.track(&decoded, packet.timestamp);

        if self.options.emit_anomaly_events && !decoded.anomalies.is_empty() {
            self.emit_anomaly(packet, &decoded, flow_id);
        }

        self.drain_ended_flows();
    }

    /// Attribute a packet to a flow, reassembling on the way.
    fn track(&mut self, decoded: &Decoded<'_>, timestamp: SystemTime) -> Option<u64> {
        let network = decoded.network.as_ref()?;

        if network.is_fragment() {
            // A fragment is counted against its flow, but its transport header
            // is deliberately *not* fed to stream reassembly: the reassembled
            // datagram carries it, and doing both would double-count the bytes
            // and corrupt the stream.
            let flow_id = self.observe(&PacketSummary {
                protocol: network.protocol(),
                source: (network.source(), 0),
                destination: (network.destination(), 0),
                timestamp,
                frame_len: decoded.frame.len(),
                payload: decoded.payload_bytes(),
                tcp: None,
            });

            if let Some(reassembled) = self.defragment(network, decoded, timestamp) {
                self.on_reassembled(&reassembled, timestamp);
            }
            return Some(flow_id);
        }

        Some(
            self.observe(&PacketSummary {
                protocol: network.protocol(),
                source: (
                    network.source(),
                    decoded
                        .transport
                        .as_ref()
                        .and_then(Transport::source_port)
                        .unwrap_or(0),
                ),
                destination: (
                    network.destination(),
                    decoded
                        .transport
                        .as_ref()
                        .and_then(Transport::destination_port)
                        .unwrap_or(0),
                ),
                timestamp,
                frame_len: decoded.frame.len(),
                payload: decoded.payload_bytes(),
                tcp: tcp_segment(decoded.transport.as_ref(), decoded.payload_bytes()),
            }),
        )
    }

    /// Offer a fragment to the defragmenter.
    fn defragment(
        &mut self,
        network: &Network,
        decoded: &Decoded<'_>,
        timestamp: SystemTime,
    ) -> Option<Reassembled> {
        let (identification, offset, more_fragments) = match network {
            Network::Ipv4(ip) => (
                u32::from(ip.identification),
                ip.fragment_offset,
                ip.more_fragments,
            ),
            Network::Ipv6(ip) => (ip.identification, ip.fragment_offset, ip.more_fragments),
        };

        // Overlaps are resolved the way the *destination* stack would.
        let policy = self.policy.for_destination(network.destination());

        self.defrag.push(
            &FragmentView {
                source: network.source(),
                destination: network.destination(),
                identification,
                protocol: network.protocol(),
                offset,
                more_fragments,
                // The IP payload, not the transport payload: the first
                // fragment's transport header is part of what is being
                // reassembled.
                payload: decoded.network_payload_bytes(),
            },
            timestamp,
            policy,
        )
    }

    /// Feed a datagram that has just been reassembled back into the pipeline.
    fn on_reassembled(&mut self, reassembled: &Reassembled, timestamp: SystemTime) {
        let decoded =
            cybersentinel_decode::decode_transport_bytes(&reassembled.data, reassembled.protocol);

        self.observe(&PacketSummary {
            protocol: reassembled.protocol,
            source: (
                reassembled.source,
                decoded
                    .transport
                    .as_ref()
                    .and_then(Transport::source_port)
                    .unwrap_or(0),
            ),
            destination: (
                reassembled.destination,
                decoded
                    .transport
                    .as_ref()
                    .and_then(Transport::destination_port)
                    .unwrap_or(0),
            ),
            timestamp,
            // The datagram's own length, not a frame length: it never was one
            // frame.
            frame_len: reassembled.data.len(),
            payload: decoded.payload_bytes(),
            tcp: tcp_segment(decoded.transport.as_ref(), decoded.payload_bytes()),
        });
    }

    /// Hand a packet to the flow table and consume whatever it delivered.
    fn observe(&mut self, packet: &PacketSummary<'_>) -> u64 {
        self.ready.clear();

        // Bound the borrows: the policy resolver, the flow table and the
        // delivery buffer are three disjoint fields of `self`.
        let policy = &self.policy;
        let resolve = |address: IpAddr| policy.for_destination(address);
        let observed = self.flows.observe(packet, &resolve, &mut self.ready);
        let flow_id = observed.flow_id.get();

        // Orient the tuple from the flow's initiator, so "to server" means the
        // same thing to the engine as it does to the flow table.
        let packet_tuple = summary_tuple(packet);
        let oriented = if observed.to_server {
            packet_tuple
        } else {
            reverse(packet_tuple)
        };

        // A datagram protocol has no stream, so its payload is inspected as it
        // stands. TCP payload reaches detection only through reassembly.
        if packet.tcp.is_none() && !packet.payload.is_empty() {
            let payload = packet.payload.to_vec();
            self.inspect_packet(
                flow_id,
                packet_tuple,
                observed.to_server,
                &payload,
                packet.timestamp,
            );
        }

        self.consume_ready(flow_id, oriented, packet.timestamp);
        flow_id
    }

    fn inspect_packet(
        &mut self,
        flow_id: u64,
        tuple: NetTuple,
        to_server: bool,
        payload: &[u8],
        timestamp: SystemTime,
    ) {
        let Some(engine) = &mut self.engine else {
            return;
        };
        self.alerts.clear();
        engine.inspect_packet(
            flow_id,
            tuple,
            to_server,
            payload,
            timestamp,
            &mut self.alerts,
        );
        self.emit_alerts(flow_id, tuple, timestamp);
    }

    fn emit_alerts(&self, flow_id: u64, tuple: NetTuple, timestamp: SystemTime) {
        for record in &self.alerts {
            let body = AlertEvent {
                action: AlertAction::Alerted,
                source: AlertSource::Network,
                sid: record.sid,
                rev: record.rev,
                signature: record.signature.clone(),
                classtype: record.classtype.clone(),
                severity: record.severity,
                metadata: record.metadata.clone(),
            };
            let event = self
                .emitter
                .build_at(to_timestamp(timestamp), Payload::alert(body))
                .with_flow_id(flow_id)
                .with_net(tuple);
            self.emitter.emit_event(event);
        }
    }

    /// Account for — and optionally dump — bytes that reassembly delivered.
    ///
    /// From Phase 3 this is where the detection engine is handed the stream.
    fn consume_ready(&mut self, flow_id: u64, oriented: NetTuple, timestamp: SystemTime) {
        if self.ready.is_empty() {
            return;
        }
        self.stream_bytes_delivered += self.ready.len() as u64;

        if let Some(directory) = &self.options.dump_streams_to {
            dump_stream(directory, flow_id, true, &self.ready.to_server);
            dump_stream(directory, flow_id, false, &self.ready.to_client);
        }

        // Take the delivery so the engine and the emitter can both be borrowed.
        let to_server = std::mem::take(&mut self.ready.to_server);
        let to_client = std::mem::take(&mut self.ready.to_client);

        for (bytes, is_to_server) in [(&to_server, true), (&to_client, false)] {
            if bytes.is_empty() {
                continue;
            }
            let tuple = if is_to_server {
                oriented
            } else {
                reverse(oriented)
            };
            if let Some(engine) = &mut self.engine {
                self.alerts.clear();
                engine.inspect_stream(
                    flow_id,
                    tuple,
                    is_to_server,
                    bytes,
                    timestamp,
                    &mut self.alerts,
                );
                self.emit_alerts(flow_id, tuple, timestamp);
            }
        }

        self.ready.to_server = to_server;
        self.ready.to_client = to_client;
    }

    fn emit_anomaly(&self, packet: &RawPacket<'_>, decoded: &Decoded<'_>, flow_id: Option<u64>) {
        let anomalies = decoded
            .anomalies
            .as_slice()
            .iter()
            .map(|anomaly| AnomalyRecord {
                layer: anomaly.layer.as_str().to_string(),
                kind: anomaly.kind.as_str().to_string(),
            })
            .collect();

        let body = AnomalyEvent {
            anomalies,
            interface: packet.interface.to_string(),
            captured_len: u32::try_from(packet.data.len()).unwrap_or(u32::MAX),
            packet_len: u32::try_from(packet.original_len).unwrap_or(u32::MAX),
            anomalies_truncated: decoded.anomalies.overflowed(),
        };

        let mut event = self
            .emitter
            .build_at(to_timestamp(packet.timestamp), Payload::anomaly(body));
        if let Some(flow_id) = flow_id {
            event = event.with_flow_id(flow_id);
        }
        // Whatever the decoder managed to read is still worth reporting: an
        // anomalous packet the analyst cannot attribute to a host is much less
        // use than one they can.
        if let Some(tuple) = decoded.five_tuple() {
            event = event.with_net(tuple);
        }
        self.emitter.emit_event(event);
    }

    /// Emit an event for every flow that has ended since the last call.
    fn drain_ended_flows(&mut self) {
        if self.flows.ended_mut().is_empty() {
            return;
        }
        self.take_final_deliveries();
        if !self.options.emit_flow_events {
            self.flows.ended_mut().clear();
            return;
        }

        // Take the batch so the emitter can be used without holding a borrow of
        // the flow table.
        let ended: Vec<EndedFlow> = self.flows.ended_mut().drain(..).collect();
        for entry in ended {
            self.emit_flow(&entry);
        }
    }

    /// Deliver and account for the tail of every flow that has ended.
    fn take_final_deliveries(&mut self) {
        let tails: Vec<(u64, StreamReady)> = self
            .flows
            .ended_mut()
            .iter_mut()
            .map(|ended| (ended.flow.id.get(), std::mem::take(&mut ended.final_ready)))
            .filter(|(_, ready)| !ready.is_empty())
            .collect();

        for (flow_id, ready) in tails {
            self.stream_bytes_delivered += ready.len() as u64;
            if let Some(directory) = &self.options.dump_streams_to {
                dump_stream(directory, flow_id, true, &ready.to_server);
                dump_stream(directory, flow_id, false, &ready.to_client);
            }
        }

        // The flows are about to be reported and dropped, so their detection
        // state goes with them.
        let ended: Vec<u64> = self
            .flows
            .ended_mut()
            .iter()
            .map(|ended| ended.flow.id.get())
            .collect();
        if let Some(engine) = &mut self.engine {
            for flow_id in ended {
                engine.on_flow_end(flow_id);
            }
        }
    }

    fn emit_flow(&self, ended: &EndedFlow) {
        let flow = &ended.flow;
        let (initiator, responder) = flow.oriented_tuple();

        let body = FlowEvent {
            reason: match ended.reason {
                EndReason::Closed => FlowEndReason::Closed,
                EndReason::TimedOut => FlowEndReason::TimedOut,
                EndReason::Evicted => FlowEndReason::Evicted,
                EndReason::SensorStopped => FlowEndReason::SensorStopped,
            },
            start: to_timestamp(flow.start),
            end: to_timestamp(flow.last_seen),
            duration_ms: u64::try_from(flow.duration().as_millis()).unwrap_or(u64::MAX),
            packets_to_server: flow.to_server.packets,
            bytes_to_server: flow.to_server.bytes,
            packets_to_client: flow.to_client.packets,
            bytes_to_client: flow.to_client.bytes,
            tcp_flags: flow.tcp_flags_string(),
        };

        // A flow event is stamped with when the flow *ended*, so events stay in
        // chronological order in the log.
        let event = self
            .emitter
            .build_at(to_timestamp(flow.last_seen), Payload::flow(body))
            .with_flow_id(flow.id.get())
            .with_net(NetTuple {
                src_ip: initiator.0,
                src_port: port_or_none(initiator.1),
                dest_ip: responder.0,
                dest_port: port_or_none(responder.1),
                proto: protocol_from_number(flow.key.protocol),
            });
        self.emitter.emit_event(event);
    }

    /// End every open flow, for shutdown or end of capture.
    pub fn flush(&mut self) {
        self.flows.flush();
        self.drain_ended_flows();
    }

    /// Publish counters for the stats thread.
    pub fn publish(&mut self, slot: &SharedSnapshot, capture: CaptureCounters) {
        let mut streams = self.flows.stream_counters();
        streams.bytes_delivered = self.stream_bytes_delivered;
        let snapshot = PipelineSnapshot {
            source: self.source.clone(),
            capture,
            decode: self.decode,
            flows: self.flows.counters(),
            active_flows: self.flows.len() as u64,
            flow_capacity: self.flows.capacity() as u64,
            defrag: self.defrag.counters(),
            active_fragment_sets: self.defrag.active_sets() as u64,
            streams,
            stream_bytes_buffered: self.flows.buffered_bytes() as u64,
            engine: self
                .engine
                .as_ref()
                .map(Engine::counters)
                .unwrap_or_default(),
            rules_armed: self.rules_armed,
            rules_awaiting_support: self.rules_awaiting_support,
            rules_failed: self.rules_failed,
            rules_without_prefilter: self.rules_without_prefilter,
            capture_truncated: false,
        };
        if let Ok(mut guard) = slot.lock() {
            let truncated = guard.capture_truncated;
            *guard = snapshot;
            guard.capture_truncated = truncated;
        }
    }
}

/// The 5-tuple a packet summary describes.
fn summary_tuple(packet: &PacketSummary<'_>) -> NetTuple {
    NetTuple {
        src_ip: packet.source.0,
        src_port: port_or_none(packet.source.1),
        dest_ip: packet.destination.0,
        dest_port: port_or_none(packet.destination.1),
        proto: protocol_from_number(packet.protocol),
    }
}

/// The same tuple seen from the other end.
fn reverse(tuple: NetTuple) -> NetTuple {
    NetTuple {
        src_ip: tuple.dest_ip,
        src_port: tuple.dest_port,
        dest_ip: tuple.src_ip,
        dest_port: tuple.src_port,
        proto: tuple.proto,
    }
}

/// Build a reassembly segment from a decoded TCP header.
fn tcp_segment<'a>(transport: Option<&Transport>, payload: &'a [u8]) -> Option<TcpSegment<'a>> {
    match transport {
        Some(Transport::Tcp(tcp)) => Some(TcpSegment {
            sequence: tcp.sequence_number,
            acknowledgment: tcp.acknowledgment_number,
            flags: tcp.flags.bits(),
            payload,
        }),
        _ => None,
    }
}

/// Append reassembled stream content to a per-flow file.
///
/// Debugging only. Opens per write rather than holding descriptors, because an
/// unbounded map of open files would be its own denial of service — and this
/// path is not meant to be fast, it is meant to be rare.
fn dump_stream(directory: &std::path::Path, flow_id: u64, to_server: bool, bytes: &[u8]) {
    use std::io::Write;

    if bytes.is_empty() {
        return;
    }
    let direction = if to_server { "to-server" } else { "to-client" };
    let path = directory.join(format!("{flow_id}-{direction}.bin"));

    let result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(bytes));
    if let Err(error) = result {
        tracing::warn!(path = %path.display(), %error, "could not write the stream dump");
    }
}

/// Ports are reported as absent rather than zero for protocols without them.
fn port_or_none(port: u16) -> Option<u16> {
    (port != 0).then_some(port)
}

fn protocol_from_number(protocol: u8) -> Protocol {
    match protocol {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        1 | 58 => Protocol::Icmp,
        _ => Protocol::Ip,
    }
}

/// Events carry the **packet's** capture time, not the moment the sensor
/// processed it.
fn to_timestamp(time: SystemTime) -> Timestamp {
    Timestamp::from_system_time(time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cybersentinel_common::event::SensorInfo;
    use cybersentinel_common::eventlog::{EventPipeline, EventSink};
    use std::io;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    #[derive(Clone)]
    struct MemorySink(Arc<StdMutex<Vec<String>>>);

    impl EventSink for MemorySink {
        fn name(&self) -> &str {
            "memory"
        }
        fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
            self.0
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(line).into_owned());
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Harness {
        pipeline: PacketPipeline,
        events: Arc<StdMutex<Vec<String>>>,
        log: Arc<EventPipeline>,
    }

    impl Harness {
        fn new(options: PipelineOptions) -> Self {
            let events = Arc::new(StdMutex::new(Vec::new()));
            let log = Arc::new(EventPipeline::spawn(
                vec![Box::new(MemorySink(Arc::clone(&events)))],
                1_024,
            ));
            let emitter = EventEmitter::new(
                SensorInfo {
                    name: "test".into(),
                    id: "test".into(),
                    version: "0.1.0".into(),
                },
                Arc::clone(&log),
            );
            let mut config = Config::default();
            config.flow.max_flows = 128;
            config.flow.timeout_secs = 60;
            Self {
                pipeline: PacketPipeline::new(emitter, &config, options, "test.pcap"),
                events,
                log,
            }
        }

        fn feed(&mut self, frame: &[u8], seconds: u64) {
            self.pipeline.on_packet(&RawPacket {
                timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
                interface: "test.pcap",
                data: frame,
                original_len: frame.len(),
            });
        }

        fn finish(mut self) -> Vec<serde_json::Value> {
            self.pipeline.flush();
            self.log.shutdown();
            self.events
                .lock()
                .unwrap()
                .iter()
                .map(|line| serde_json::from_str(line).expect("events must be JSON"))
                .collect()
        }
    }

    fn default_options() -> PipelineOptions {
        PipelineOptions {
            emit_anomaly_events: true,
            emit_flow_events: true,
            dump_streams_to: None,
        }
    }

    /// Ethernet + IPv4 + TCP, built by hand so the test owns every byte.
    fn tcp_frame(
        src_port: u16,
        dst_port: u16,
        flags: u8,
        payload: &[u8],
        reverse: bool,
    ) -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp.extend_from_slice(payload);

        let (source, destination) = if reverse {
            ([198, 51, 100, 7], [192, 0, 2, 1])
        } else {
            ([192, 0, 2, 1], [198, 51, 100, 7])
        };

        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        let total = u16::try_from(20 + tcp.len()).unwrap();
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&source);
        ip[16..20].copy_from_slice(&destination);
        let checksum = ipv4_checksum(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        ip.extend_from_slice(&tcp);

        let mut frame = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00];
        frame.extend_from_slice(&ip);
        frame
    }

    fn ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in header.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    const SYN: u8 = 0b0000_0010;
    const FIN: u8 = 0b0000_0001;
    const ACK: u8 = 0b0001_0000;

    #[test]
    fn a_completed_tcp_conversation_produces_one_flow_event() {
        let mut harness = Harness::new(default_options());
        harness.feed(&tcp_frame(51_000, 80, SYN, b"", false), 10);
        harness.feed(&tcp_frame(80, 51_000, SYN | ACK, b"", true), 11);
        harness.feed(&tcp_frame(51_000, 80, ACK, b"GET /", false), 12);
        harness.feed(&tcp_frame(80, 51_000, ACK, b"HTTP/1.1 200", true), 13);
        harness.feed(&tcp_frame(51_000, 80, FIN | ACK, b"", false), 14);
        harness.feed(&tcp_frame(80, 51_000, FIN | ACK, b"", true), 15);

        let events = harness.finish();
        let flows: Vec<_> = events
            .iter()
            .filter(|event| event["event_type"] == "flow")
            .collect();
        assert_eq!(
            flows.len(),
            1,
            "one conversation, one flow record: {events:#?}"
        );

        let flow = flows[0];
        assert_eq!(flow["flow"]["reason"], "closed");
        assert_eq!(flow["src_ip"], "192.0.2.1", "the initiator is the source");
        assert_eq!(flow["src_port"], 51_000);
        assert_eq!(flow["dest_ip"], "198.51.100.7");
        assert_eq!(flow["dest_port"], 80);
        assert_eq!(flow["proto"], "TCP");
        assert_eq!(flow["flow"]["packets_to_server"], 3);
        assert_eq!(flow["flow"]["packets_to_client"], 3);
        assert_eq!(flow["flow"]["tcp_flags"], "FSA");
        assert_eq!(flow["flow"]["duration_ms"], 5_000);
        assert!(flow["flow_id"].as_u64().unwrap() > 0);
    }

    #[test]
    fn event_timestamps_come_from_the_packet_not_the_wall_clock() {
        // Replaying an old capture must produce events dated when the traffic
        // happened, or nothing downstream can correlate them.
        let mut harness = Harness::new(default_options());
        harness.feed(&tcp_frame(1, 2, SYN, b"", false), 1_000_000_000);
        let events = harness.finish();

        let flow = events
            .iter()
            .find(|event| event["event_type"] == "flow")
            .expect("a flow event");
        assert!(
            flow["timestamp"]
                .as_str()
                .unwrap()
                .starts_with("2001-09-09"),
            "got {}",
            flow["timestamp"]
        );
    }

    #[test]
    fn an_open_flow_is_reported_when_the_capture_ends() {
        let mut harness = Harness::new(default_options());
        harness.feed(&tcp_frame(51_000, 80, SYN, b"", false), 10);

        let events = harness.finish();
        let flow = events
            .iter()
            .find(|event| event["event_type"] == "flow")
            .expect("an unfinished flow must still be reported");
        assert_eq!(flow["flow"]["reason"], "sensor_stopped");
    }

    #[test]
    fn a_malformed_packet_produces_one_anomaly_event_however_wrong_it_is() {
        let mut harness = Harness::new(default_options());
        // Break the IPv4 checksum and the TCP data offset at once.
        let mut frame = tcp_frame(51_000, 80, SYN, b"", false);
        frame[24] ^= 0xff; // checksum byte
        frame[46] = 0; // TCP data offset nibble
        harness.feed(&frame, 10);

        let events = harness.finish();
        let anomalies: Vec<_> = events
            .iter()
            .filter(|event| event["event_type"] == "anomaly")
            .collect();
        assert_eq!(
            anomalies.len(),
            1,
            "one packet, one anomaly event: {events:#?}"
        );

        let anomaly = anomalies[0];
        assert!(
            anomaly["anomaly"]["anomalies"].as_array().unwrap().len() >= 2,
            "both problems belong in the one event: {anomaly}"
        );
        // Layer 3 survived, so the packet is still attributable.
        assert_eq!(anomaly["src_ip"], "192.0.2.1");
        assert!(anomaly["flow_id"].as_u64().is_some());
        assert_eq!(anomaly["anomaly"]["interface"], "test.pcap");
    }

    #[test]
    fn anomaly_events_can_be_turned_off_without_losing_the_counters() {
        let mut harness = Harness::new(PipelineOptions {
            emit_anomaly_events: false,
            ..default_options()
        });
        let mut frame = tcp_frame(51_000, 80, SYN, b"", false);
        frame[24] ^= 0xff;
        harness.feed(&frame, 10);

        assert_eq!(harness.pipeline.decode.anomalous, 1);
        let events = harness.finish();
        assert!(events.iter().all(|event| event["event_type"] != "anomaly"));
    }

    #[test]
    fn flow_events_can_be_turned_off() {
        let mut harness = Harness::new(PipelineOptions {
            emit_flow_events: false,
            ..default_options()
        });
        harness.feed(&tcp_frame(51_000, 80, SYN, b"", false), 10);
        let events = harness.finish();
        assert!(events.iter().all(|event| event["event_type"] != "flow"));
    }

    #[test]
    fn a_non_ip_frame_is_counted_but_starts_no_flow() {
        let mut harness = Harness::new(default_options());
        let mut arp = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x06];
        arp.extend_from_slice(&[0u8; 28]);
        harness.feed(&arp, 10);

        assert_eq!(harness.pipeline.decode.non_ip, 1);
        let events = harness.finish();
        assert!(
            events.is_empty(),
            "ARP is neither a flow nor an anomaly: {events:#?}"
        );
    }

    #[test]
    fn icmp_flows_are_tracked_without_ports() {
        let mut harness = Harness::new(default_options());
        let mut icmp = vec![8u8, 0, 0, 0, 0, 1, 0, 1];
        icmp.extend_from_slice(b"ping");

        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        let total = u16::try_from(20 + icmp.len()).unwrap();
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[8] = 64;
        ip[9] = 1;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[198, 51, 100, 7]);
        let checksum = ipv4_checksum(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        ip.extend_from_slice(&icmp);

        let mut frame = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00];
        frame.extend_from_slice(&ip);
        harness.feed(&frame, 10);

        let events = harness.finish();
        let flow = events
            .iter()
            .find(|event| event["event_type"] == "flow")
            .expect("ICMP is still a conversation between two hosts");
        assert_eq!(flow["proto"], "ICMP");
        assert!(flow.get("src_port").is_none(), "ICMP has no ports: {flow}");
        assert!(flow["flow"].get("tcp_flags").is_none());
    }

    #[test]
    fn counters_are_published_for_the_stats_thread() {
        let mut harness = Harness::new(default_options());
        harness.feed(&tcp_frame(51_000, 80, SYN, b"", false), 10);

        let slot: SharedSnapshot = Arc::new(Mutex::new(PipelineSnapshot::default()));
        harness.pipeline.publish(
            &slot,
            CaptureCounters {
                packets: 1,
                bytes: 74,
                drops: 3,
                interface_drops: 1,
            },
        );

        let snapshot = slot.lock().unwrap().clone();
        assert_eq!(snapshot.capture.drops, 3);
        assert_eq!(snapshot.decode.tcp, 1);
        assert_eq!(snapshot.active_flows, 1);
        assert_eq!(snapshot.flow_capacity, 128);
        assert_eq!(snapshot.source, "test.pcap");
    }
}
