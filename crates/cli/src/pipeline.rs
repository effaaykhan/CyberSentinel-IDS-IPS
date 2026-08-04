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

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use cybersentinel_capture::{CaptureCounters, RawPacket};
use cybersentinel_common::event::{
    AnomalyEvent, AnomalyRecord, FlowEndReason, FlowEvent, NetTuple, Payload, Protocol,
};
use cybersentinel_common::eventlog::EventEmitter;
use cybersentinel_common::Timestamp;
use cybersentinel_decode::{DecodeCounters, Decoded, Transport};
use cybersentinel_reassembly::flow::{EndReason, EndedFlow, Endpoint, FlowCounters, FlowTable};

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
    /// Whether a replayed capture file was torn.
    pub capture_truncated: bool,
}

/// Shared slot the capture thread publishes into.
pub type SharedSnapshot = Arc<Mutex<PipelineSnapshot>>;

/// What the pipeline emits.
#[derive(Debug, Clone, Copy)]
pub struct PipelineOptions {
    /// Emit an `anomaly` event per malformed packet.
    pub emit_anomaly_events: bool,
    /// Emit a `flow` event when a flow ends.
    pub emit_flow_events: bool,
}

/// Decode and flow-track packets, emitting events.
#[derive(Debug)]
pub struct PacketPipeline {
    emitter: EventEmitter,
    flows: FlowTable,
    decode: DecodeCounters,
    options: PipelineOptions,
    source: String,
}

impl PacketPipeline {
    /// Build a pipeline writing into `emitter`.
    #[must_use]
    pub fn new(
        emitter: EventEmitter,
        flows: FlowTable,
        options: PipelineOptions,
        source: impl Into<String>,
    ) -> Self {
        Self {
            emitter,
            flows,
            decode: DecodeCounters::default(),
            options,
            source: source.into(),
        }
    }

    /// Decode one captured frame and emit whatever it warrants.
    pub fn on_packet(&mut self, packet: &RawPacket<'_>) {
        let decoded = cybersentinel_decode::decode(packet.data, packet.original_len);
        self.decode.record(&decoded);

        let flow_id = self.track_flow(&decoded, packet.timestamp);

        if self.options.emit_anomaly_events && !decoded.anomalies.is_empty() {
            self.emit_anomaly(packet, &decoded, flow_id);
        }

        self.drain_ended_flows();
    }

    /// Attribute a packet to a flow, returning the flow id if it has one.
    ///
    /// ICMP and bare-IP packets have no ports; they are tracked with port 0 so
    /// they still correlate as conversations between two hosts.
    fn track_flow(&mut self, decoded: &Decoded<'_>, timestamp: SystemTime) -> Option<u64> {
        let network = decoded.network.as_ref()?;

        let source: Endpoint = (
            network.source(),
            decoded
                .transport
                .as_ref()
                .and_then(Transport::source_port)
                .unwrap_or(0),
        );
        let destination: Endpoint = (
            network.destination(),
            decoded
                .transport
                .as_ref()
                .and_then(Transport::destination_port)
                .unwrap_or(0),
        );

        let tcp_flags = match &decoded.transport {
            Some(Transport::Tcp(tcp)) => Some(tcp.flags.bits()),
            _ => None,
        };

        let observed = self.flows.observe(
            network.protocol(),
            source,
            destination,
            timestamp,
            decoded.frame.len(),
            tcp_flags,
        );
        Some(observed.flow_id.get())
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
        let snapshot = PipelineSnapshot {
            source: self.source.clone(),
            capture,
            decode: self.decode,
            flows: self.flows.counters(),
            active_flows: self.flows.len() as u64,
            flow_capacity: self.flows.capacity() as u64,
            capture_truncated: false,
        };
        if let Ok(mut guard) = slot.lock() {
            let truncated = guard.capture_truncated;
            *guard = snapshot;
            guard.capture_truncated = truncated;
        }
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
    use cybersentinel_reassembly::Limits;
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
            let flows = FlowTable::new(Limits {
                max_flows: 128,
                flow_timeout: Duration::from_secs(60),
                ..Limits::default()
            });
            Self {
                pipeline: PacketPipeline::new(emitter, flows, options, "test.pcap"),
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
            emit_flow_events: true,
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
            emit_anomaly_events: true,
            emit_flow_events: false,
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
