//! Flow tracking (**Phase 1**), the state Phase 2's reassembly is built on.
//!
//! A flow is one conversation, keyed on the 5-tuple with the two endpoints in a
//! canonical order so both directions land on the same entry. Every packet is
//! attributed to a flow and a direction, which is what gives every event a
//! `flow_id` and lets host and network events correlate later.
//!
//! # Bounded, because an attacker chooses how many flows exist
//!
//! Guide §6: *bound all reassembly and flow state with per-flow and global caps
//! plus timeouts.* Opening flows is free for an attacker and expensive for a
//! sensor — a SYN flood from spoofed sources creates a new entry per packet.
//! So the table has a hard cap ([`Limits::max_flows`]) and an idle timeout, and
//! it can never grow past the cap regardless of traffic.
//!
//! When the cap is hit, the oldest flows are evicted and **reported as
//! evictions**, not silently forgotten. An eviction means the sensor stopped
//! following a conversation that was still live; that is a coverage hole and it
//! belongs in `stats` where someone will see it.
//!
//! # Cost
//!
//! Per packet the table does one hash lookup. Timeout sweeps are amortised: a
//! sweep runs at most once per [`FlowTable::SWEEP_INTERVAL`] of capture time,
//! and eviction removes a batch rather than one entry per insert, so no single
//! packet pays for a full scan more than once in a while.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use cybersentinel_common::config::{OverlapPolicy, ReassemblyConfig};

use crate::stream::{flags, StreamCounters, StreamPair, StreamReady, TcpSegment};
use crate::Limits;

/// A flow identifier.
///
/// Derived from the canonical key and the flow's start time, so it is stable
/// for the life of the flow, reproducible across replays of the same capture,
/// and unlikely to collide with a flow from a previous run of the sensor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowId(u64);

impl FlowId {
    /// The identifier as it appears in event JSON.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for FlowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One endpoint of a flow.
pub type Endpoint = (IpAddr, u16);

/// The canonical key for a conversation.
///
/// The two endpoints are stored in sorted order so a packet in either direction
/// produces the same key. Which endpoint *opened* the conversation is kept
/// separately, in [`Flow::initiator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// IP protocol number.
    pub protocol: u8,
    /// The lower-sorting endpoint.
    pub first: Endpoint,
    /// The higher-sorting endpoint.
    pub second: Endpoint,
}

impl FlowKey {
    /// Build a canonical key from a directional pair of endpoints.
    #[must_use]
    pub fn new(protocol: u8, source: Endpoint, destination: Endpoint) -> Self {
        if source <= destination {
            Self {
                protocol,
                first: source,
                second: destination,
            }
        } else {
            Self {
                protocol,
                first: destination,
                second: source,
            }
        }
    }
}

/// Per-direction counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectionCounters {
    /// Packets seen.
    pub packets: u64,
    /// Bytes seen, counting whole frames.
    pub bytes: u64,
}

/// A tracked conversation.
///
/// Deliberately **not** `Clone`: a flow owns its reassembly buffers, and a
/// stray clone would duplicate up to the per-flow byte cap. Flows are moved out
/// of the table when they end, never copied out of it.
#[derive(Debug)]
pub struct Flow {
    /// Stable identifier.
    pub id: FlowId,
    /// Canonical key.
    pub key: FlowKey,
    /// The endpoint that sent the first packet. Defines "to server".
    pub initiator: Endpoint,
    /// First packet seen.
    pub start: SystemTime,
    /// Most recent packet seen.
    pub last_seen: SystemTime,
    /// Counters in the direction the flow was opened in.
    pub to_server: DirectionCounters,
    /// Counters in the reverse direction.
    pub to_client: DirectionCounters,
    /// Union of every TCP flag byte seen on the flow.
    pub tcp_flags_seen: u8,
    /// Whether a FIN has been seen from the initiator.
    fin_from_initiator: bool,
    /// Whether a FIN has been seen from the responder.
    fin_from_responder: bool,
    /// Whether a RST the destination would have acted on has been seen.
    saw_reset: bool,
    /// TCP reassembly state. `None` for anything that is not TCP.
    streams: Option<StreamPair>,
}

impl Flow {
    /// The endpoint that did not open the conversation.
    #[must_use]
    pub fn responder(&self) -> Endpoint {
        if self.initiator == self.key.first {
            self.key.second
        } else {
            self.key.first
        }
    }

    /// The 5-tuple oriented from the initiator, as events report it.
    #[must_use]
    pub fn oriented_tuple(&self) -> (Endpoint, Endpoint) {
        (self.initiator, self.responder())
    }

    /// How long the flow lasted.
    #[must_use]
    pub fn duration(&self) -> Duration {
        self.last_seen
            .duration_since(self.start)
            .unwrap_or_default()
    }

    /// Whether TCP teardown has been observed in both directions, or a reset.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.saw_reset || (self.fin_from_initiator && self.fin_from_responder)
    }

    /// Reassembly counters for this flow, if it is TCP.
    #[must_use]
    pub fn stream_counters(&self) -> Option<StreamCounters> {
        self.streams.as_ref().map(StreamPair::counters)
    }

    /// Bytes this flow currently holds awaiting reassembly.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.streams.as_ref().map_or(0, StreamPair::buffered_bytes)
    }

    /// The union of TCP flags, in the conventional short form.
    #[must_use]
    pub fn tcp_flags_string(&self) -> Option<String> {
        if self.key.protocol != TCP_PROTOCOL {
            return None;
        }
        let mut out = String::new();
        for (bit, letter) in [
            (0, 'F'),
            (1, 'S'),
            (2, 'R'),
            (3, 'P'),
            (4, 'A'),
            (5, 'U'),
            (6, 'E'),
            (7, 'C'),
        ] {
            if self.tcp_flags_seen & (1 << bit) != 0 {
                out.push(letter);
            }
        }
        Some(out)
    }
}

/// Why a flow left the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// TCP teardown was observed.
    Closed,
    /// The flow went idle past the timeout.
    TimedOut,
    /// Evicted to make room under the cap.
    Evicted,
    /// The sensor stopped, or the capture ended, while the flow was open.
    SensorStopped,
}

/// A flow that has left the table and is ready to be reported.
#[derive(Debug)]
pub struct EndedFlow {
    /// The flow as it was.
    pub flow: Flow,
    /// Why it ended.
    pub reason: EndReason,
    /// Stream bytes that became deliverable as the flow ended.
    ///
    /// The tail of a conversation still has to be matched against, so what was
    /// contiguous at the end is delivered rather than dropped with the flow.
    pub final_ready: StreamReady,
}

/// What a packet did to the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observed {
    /// The flow the packet belongs to.
    pub flow_id: FlowId,
    /// Whether the packet travelled in the direction the flow was opened in.
    pub to_server: bool,
    /// Whether this packet created the flow.
    pub is_new: bool,
}

/// Running totals for the table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowCounters {
    /// Flows created.
    pub created: u64,
    /// Flows ended by observed teardown.
    pub closed: u64,
    /// Flows ended by the idle timeout.
    pub timed_out: u64,
    /// Flows evicted under memory pressure. **A coverage signal.**
    pub evicted: u64,
    /// Resets ignored because the destination would not have acted on them.
    ///
    /// Non-zero means somebody sent a reset the sensor decided was forged —
    /// either a broken middlebox or an attempt to make the sensor stop watching
    /// a live connection.
    pub resets_ignored: u64,
}

const TCP_PROTOCOL: u8 = 6;

/// The IP protocol number for TCP.
/// Everything the flow table needs to know about one packet.
#[derive(Debug, Clone, Copy)]
pub struct PacketSummary<'a> {
    /// IP protocol number.
    pub protocol: u8,
    /// Source endpoint.
    pub source: Endpoint,
    /// Destination endpoint.
    pub destination: Endpoint,
    /// Capture timestamp.
    pub timestamp: SystemTime,
    /// Whole captured frame length, for flow byte counts.
    pub frame_len: usize,
    /// The TCP segment, for protocols that have one.
    pub tcp: Option<TcpSegment<'a>>,
}

/// A bounded table of live flows.
#[derive(Debug)]
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    limits: Limits,
    reassembly: ReassemblyConfig,
    /// Running total of bytes held in reassembly buffers, maintained
    /// incrementally so the global cap costs nothing per packet.
    stream_bytes: usize,
    counters: FlowCounters,
    /// Flows that have ended and not yet been reported.
    ended: Vec<EndedFlow>,
    /// Capture-time of the last timeout sweep.
    last_sweep: Option<SystemTime>,
}

impl FlowTable {
    /// Minimum capture time between timeout sweeps.
    ///
    /// Sweeping is O(flows); doing it per packet would make a busy link pay for
    /// the whole table on every frame.
    pub const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

    /// Fraction of the table evicted at once when the cap is reached.
    ///
    /// Evicting a batch amortises the scan: one scan serves many subsequent
    /// inserts, instead of a full scan per insert while the table sits full.
    const EVICTION_BATCH_FRACTION: usize = 10;

    /// Build a table under `limits`.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self::with_reassembly(limits, ReassemblyConfig::default())
    }

    /// Build a table with explicit reassembly limits.
    #[must_use]
    pub fn with_reassembly(limits: Limits, reassembly: ReassemblyConfig) -> Self {
        Self {
            flows: HashMap::new(),
            limits,
            reassembly,
            stream_bytes: 0,
            counters: FlowCounters::default(),
            ended: Vec::new(),
            last_sweep: None,
        }
    }

    /// Flows currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Maximum flows the table will hold.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.limits.max_flows
    }

    /// Running totals.
    #[must_use]
    pub fn counters(&self) -> FlowCounters {
        self.counters
    }

    /// Flows that have ended and not yet been reported.
    ///
    /// The caller drains this after `observe`, `sweep`, or `flush` and emits an
    /// event for each.
    pub fn ended_mut(&mut self) -> &mut Vec<EndedFlow> {
        &mut self.ended
    }

    /// Attribute a packet to a flow.
    ///
    /// `frame_len` is the whole captured frame, so flow byte counts describe
    /// link-layer volume. `tcp_flags` is the raw flag byte for TCP and `None`
    /// otherwise.
    pub fn observe(
        &mut self,
        packet: &PacketSummary<'_>,
        policy: &dyn Fn(IpAddr) -> OverlapPolicy,
        ready: &mut StreamReady,
    ) -> Observed {
        self.maybe_sweep(packet.timestamp);

        let key = FlowKey::new(packet.protocol, packet.source, packet.destination);
        let is_new = !self.flows.contains_key(&key);
        if is_new {
            self.make_room(packet.timestamp);
        }

        let counters = &mut self.counters;
        let reassembly = &self.reassembly;
        let flow = self.flows.entry(key).or_insert_with(|| {
            counters.created += 1;
            Flow {
                id: FlowId(derive_flow_id(&key, packet.timestamp)),
                key,
                initiator: packet.source,
                start: packet.timestamp,
                last_seen: packet.timestamp,
                to_server: DirectionCounters::default(),
                to_client: DirectionCounters::default(),
                tcp_flags_seen: 0,
                fin_from_initiator: false,
                fin_from_responder: false,
                saw_reset: false,
                streams: (packet.protocol == TCP_PROTOCOL).then(|| StreamPair::new(reassembly)),
            }
        });

        let to_server = packet.source == flow.initiator;
        let direction = if to_server {
            &mut flow.to_server
        } else {
            &mut flow.to_client
        };
        direction.packets += 1;
        direction.bytes += packet.frame_len as u64;

        // Capture timestamps are not guaranteed monotonic (multiple queues, a
        // stepped clock), so never let `last_seen` go backwards — a flow that
        // appears to end before it started would produce nonsense durations.
        if packet.timestamp > flow.last_seen {
            flow.last_seen = packet.timestamp;
        }

        let buffered_before = flow.buffered_bytes();

        if let Some(segment) = &packet.tcp {
            flow.tcp_flags_seen |= segment.flags;

            if segment.has(flags::FIN) {
                if to_server {
                    flow.fin_from_initiator = true;
                } else {
                    flow.fin_from_responder = true;
                }
            }

            // Each direction is resolved by the policy of the host *receiving*
            // it — two stacks, two answers. Resolved before borrowing the
            // stream pair, which needs the flow mutably.
            let policy_to_server = policy(flow.responder().0);
            let policy_to_client = policy(flow.initiator.0);

            if let Some(streams) = &mut flow.streams {
                streams.push(
                    to_server,
                    segment,
                    policy_to_server,
                    policy_to_client,
                    ready,
                );

                // A reset only ends the connection if the destination would
                // have acted on it. Believing a forged one stops the sensor
                // watching a live conversation, which is the whole point of the
                // technique.
                if segment.has(flags::RST) {
                    if streams.rst_should_close(to_server, segment.sequence) {
                        flow.saw_reset = true;
                    } else {
                        self.counters.resets_ignored += 1;
                    }
                }
            } else if segment.has(flags::RST) {
                flow.saw_reset = true;
            }
        }

        let buffered_after = flow.buffered_bytes();
        self.stream_bytes = self.stream_bytes + buffered_after - buffered_before;

        let observed = Observed {
            flow_id: flow.id,
            to_server,
            is_new,
        };

        if flow.is_closed() {
            if let Some(flow) = self.flows.remove(&key) {
                self.counters.closed += 1;
                self.end_flow(flow, EndReason::Closed);
            }
        }

        observed
    }

    /// Move a flow out of the table, flushing whatever it can still deliver.
    fn end_flow(&mut self, mut flow: Flow, reason: EndReason) {
        // Read the byte total *before* flushing: flushing empties the buffers,
        // so measuring afterwards would always subtract zero and the global
        // counter would ratchet upwards for ever.
        let released = flow.buffered_bytes();
        let mut final_ready = StreamReady::default();
        if let Some(streams) = &mut flow.streams {
            streams.flush(&mut final_ready);
        }
        self.stream_bytes = self.stream_bytes.saturating_sub(released);
        self.ended.push(EndedFlow {
            flow,
            reason,
            final_ready,
        });
    }

    /// Expire flows idle past the timeout, if a sweep is due.
    fn maybe_sweep(&mut self, now: SystemTime) {
        let due = match self.last_sweep {
            None => true,
            Some(last) => now
                .duration_since(last)
                .is_ok_and(|elapsed| elapsed >= Self::SWEEP_INTERVAL),
        };
        if due {
            self.sweep(now);
        }
    }

    /// Expire every flow idle past [`Limits::flow_timeout`].
    pub fn sweep(&mut self, now: SystemTime) {
        self.last_sweep = Some(now);
        let timeout = self.limits.flow_timeout;

        // Collect then remove, rather than `retain` with a clone: a flow owns
        // its reassembly buffers and copying them out would double the memory
        // this whole design exists to bound.
        let expired: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, flow)| now.duration_since(flow.last_seen).unwrap_or_default() >= timeout)
            .map(|(key, _)| *key)
            .collect();

        for key in expired {
            if let Some(flow) = self.flows.remove(&key) {
                self.counters.timed_out += 1;
                self.end_flow(flow, EndReason::TimedOut);
            }
        }
    }

    /// Make space for one more flow, evicting a batch if the table is full.
    fn make_room(&mut self, now: SystemTime) {
        if self.within_limits() {
            return;
        }

        // A timeout sweep may free everything needed without losing a live flow.
        self.sweep(now);
        if self.within_limits() {
            return;
        }

        // Still full: evict the least recently seen. This is where the sensor
        // starts losing visibility, so it is counted and surfaced.
        let batch = (self.limits.max_flows / Self::EVICTION_BATCH_FRACTION).max(1);
        let mut by_age: Vec<(SystemTime, FlowKey)> = self
            .flows
            .iter()
            .map(|(key, flow)| (flow.last_seen, *key))
            .collect();
        by_age.sort_unstable_by_key(|(last_seen, _)| *last_seen);

        for (_, key) in by_age.into_iter().take(batch) {
            if let Some(flow) = self.flows.remove(&key) {
                self.counters.evicted += 1;
                self.end_flow(flow, EndReason::Evicted);
            }
        }

        tracing::warn!(
            evicted = batch,
            flows = self.flows.len(),
            capacity = self.limits.max_flows,
            stream_bytes = self.stream_bytes,
            "flow table is full; evicting live flows — visibility is being lost"
        );
    }

    /// Whether the table is inside both its flow count and byte budgets.
    ///
    /// Two separate ceilings: an attacker can exhaust either a few flows each
    /// holding a lot, or many flows each holding a little.
    fn within_limits(&self) -> bool {
        self.flows.len() < self.limits.max_flows
            && self.stream_bytes < self.reassembly.max_stream_bytes_total
    }

    /// End every remaining flow, for shutdown or end of capture.
    pub fn flush(&mut self) {
        let flows: Vec<Flow> = self.flows.drain().map(|(_, flow)| flow).collect();
        for flow in flows {
            self.end_flow(flow, EndReason::SensorStopped);
        }
    }

    /// Bytes held across every flow's reassembly buffers.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.stream_bytes
    }
}

/// Derive a flow id from the canonical key and start time.
///
/// FNV-1a with a fixed basis, deliberately not `DefaultHasher`: that is seeded
/// randomly per process, which would make replaying the same capture twice
/// produce different flow ids and break every test that compares them.
fn derive_flow_id(key: &FlowKey, start: SystemTime) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET_BASIS;
    let mut mix = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(PRIME);
        }
    };

    mix(&[key.protocol]);
    for (address, port) in [key.first, key.second] {
        match address {
            IpAddr::V4(v4) => mix(&v4.octets()),
            IpAddr::V6(v6) => mix(&v6.octets()),
        }
        mix(&port.to_be_bytes());
    }
    let nanos = start
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    mix(&nanos.to_be_bytes());

    // Zero is reserved as "no flow" in the event schema.
    if hash == 0 {
        1
    } else {
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Phase 1's call shape, kept for the tests that predate stream
    /// reassembly: a control packet with no payload.
    fn observe(
        table: &mut FlowTable,
        protocol: u8,
        source: Endpoint,
        destination: Endpoint,
        timestamp: SystemTime,
        frame_len: usize,
        tcp_flags: Option<u8>,
    ) -> Observed {
        observe_segment(
            table,
            protocol,
            source,
            destination,
            timestamp,
            frame_len,
            tcp_flags.map(|flags| TcpSegment {
                sequence: 0,
                acknowledgment: 0,
                flags,
                payload: b"",
            }),
        )
    }

    fn observe_segment(
        table: &mut FlowTable,
        protocol: u8,
        source: Endpoint,
        destination: Endpoint,
        timestamp: SystemTime,
        frame_len: usize,
        tcp: Option<TcpSegment<'_>>,
    ) -> Observed {
        let mut ready = StreamReady::default();
        table.observe(
            &PacketSummary {
                protocol,
                source,
                destination,
                timestamp,
                frame_len,
                tcp,
            },
            &|_| OverlapPolicy::First,
            &mut ready,
        )
    }

    const TCP: u8 = 6;
    const UDP: u8 = 17;
    const SYN: u8 = 0b0000_0010;
    const FIN: u8 = 0b0000_0001;
    const ACK: u8 = 0b0001_0000;
    const RST: u8 = 0b0000_0100;

    fn endpoint(last_octet: u8, port: u16) -> Endpoint {
        (IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet)), port)
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn table(max_flows: usize, timeout_secs: u64) -> FlowTable {
        FlowTable::new(Limits {
            max_flows,
            flow_timeout: Duration::from_secs(timeout_secs),
            ..Limits::default()
        })
    }

    #[test]
    fn both_directions_map_to_one_flow() {
        let mut table = table(100, 300);
        let client = endpoint(1, 51_000);
        let server = endpoint(2, 80);

        let first = observe(&mut table, TCP, client, server, at(0), 74, Some(SYN));
        let reply = observe(&mut table, TCP, server, client, at(1), 74, Some(SYN | ACK));

        assert_eq!(
            first.flow_id, reply.flow_id,
            "a reply belongs to the same flow"
        );
        assert!(first.is_new);
        assert!(!reply.is_new);
        assert!(
            first.to_server,
            "the opener defines the to-server direction"
        );
        assert!(!reply.to_server);
        assert_eq!(table.len(), 1);
        assert_eq!(table.counters().created, 1);
    }

    #[test]
    fn a_different_port_is_a_different_flow() {
        let mut table = table(100, 300);
        let a = observe(
            &mut table,
            TCP,
            endpoint(1, 51_000),
            endpoint(2, 80),
            at(0),
            74,
            None,
        );
        let b = observe(
            &mut table,
            TCP,
            endpoint(1, 51_001),
            endpoint(2, 80),
            at(0),
            74,
            None,
        );
        assert_ne!(a.flow_id, b.flow_id);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn the_same_ports_on_a_different_protocol_are_different_flows() {
        let mut table = table(100, 300);
        let tcp = observe(
            &mut table,
            TCP,
            endpoint(1, 5_000),
            endpoint(2, 53),
            at(0),
            74,
            None,
        );
        let udp = observe(
            &mut table,
            UDP,
            endpoint(1, 5_000),
            endpoint(2, 53),
            at(0),
            74,
            None,
        );
        assert_ne!(tcp.flow_id, udp.flow_id);
    }

    #[test]
    fn counters_are_kept_per_direction() {
        let mut table = table(100, 300);
        let client = endpoint(1, 51_000);
        let server = endpoint(2, 80);

        observe(&mut table, TCP, client, server, at(0), 100, None);
        observe(&mut table, TCP, client, server, at(1), 200, None);
        observe(&mut table, TCP, server, client, at(2), 1_500, None);
        table.flush();

        let ended = &table.ended_mut()[0];
        assert_eq!(ended.flow.to_server.packets, 2);
        assert_eq!(ended.flow.to_server.bytes, 300);
        assert_eq!(ended.flow.to_client.packets, 1);
        assert_eq!(ended.flow.to_client.bytes, 1_500);
        assert_eq!(ended.reason, EndReason::SensorStopped);
    }

    #[test]
    fn a_tcp_teardown_closes_the_flow() {
        let mut table = table(100, 300);
        let client = endpoint(1, 51_000);
        let server = endpoint(2, 80);

        observe(&mut table, TCP, client, server, at(0), 74, Some(SYN));
        observe(&mut table, TCP, server, client, at(1), 74, Some(SYN | ACK));
        observe(&mut table, TCP, client, server, at(2), 74, Some(FIN | ACK));
        assert_eq!(table.len(), 1, "one FIN is not a teardown");

        observe(&mut table, TCP, server, client, at(3), 74, Some(FIN | ACK));
        assert_eq!(table.len(), 0, "FIN in both directions ends the flow");

        let ended = table.ended_mut();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].reason, EndReason::Closed);
        assert_eq!(ended[0].flow.tcp_flags_string().as_deref(), Some("FSA"));
        assert_eq!(table.counters().closed, 1);
    }

    #[test]
    fn an_in_window_reset_closes_the_flow() {
        let mut table = table(100, 300);
        let client = endpoint(1, 51_000);
        let server = endpoint(2, 80);

        // A full handshake, so both sequence spaces are anchored and a reset
        // can be judged against them.
        observe_segment(
            &mut table,
            TCP,
            client,
            server,
            at(0),
            74,
            Some(TcpSegment {
                sequence: 1_000,
                acknowledgment: 0,
                flags: SYN,
                payload: b"",
            }),
        );
        observe_segment(
            &mut table,
            TCP,
            server,
            client,
            at(1),
            74,
            Some(TcpSegment {
                sequence: 5_000,
                acknowledgment: 1_001,
                flags: SYN | ACK,
                payload: b"",
            }),
        );
        observe_segment(
            &mut table,
            TCP,
            server,
            client,
            at(2),
            74,
            Some(TcpSegment {
                sequence: 5_001,
                acknowledgment: 1_001,
                flags: RST,
                payload: b"",
            }),
        );

        assert_eq!(
            table.len(),
            0,
            "a reset the host would act on ends the flow"
        );
        assert_eq!(table.ended_mut()[0].reason, EndReason::Closed);
    }

    /// The RST-evasion case: a blind reset with a guessed sequence number must
    /// not make the sensor stop watching a connection the host keeps serving.
    #[test]
    fn an_out_of_window_reset_does_not_close_the_flow() {
        let mut table = table(100, 300);
        let client = endpoint(1, 51_000);
        let server = endpoint(2, 80);

        observe_segment(
            &mut table,
            TCP,
            client,
            server,
            at(0),
            74,
            Some(TcpSegment {
                sequence: 1_000,
                acknowledgment: 0,
                flags: SYN,
                payload: b"",
            }),
        );
        observe_segment(
            &mut table,
            TCP,
            server,
            client,
            at(1),
            74,
            Some(TcpSegment {
                sequence: 5_000,
                acknowledgment: 1_001,
                flags: SYN | ACK,
                payload: b"",
            }),
        );
        observe_segment(
            &mut table,
            TCP,
            server,
            client,
            at(2),
            74,
            Some(TcpSegment {
                sequence: 5_000_000,
                acknowledgment: 0,
                flags: RST,
                payload: b"",
            }),
        );

        assert_eq!(table.len(), 1, "the flow is still live and still watched");
        assert_eq!(table.counters().resets_ignored, 1);
    }

    #[test]
    fn udp_flows_report_no_tcp_flags() {
        let mut table = table(100, 300);
        observe(
            &mut table,
            UDP,
            endpoint(1, 5_000),
            endpoint(2, 53),
            at(0),
            74,
            None,
        );
        table.flush();
        assert!(table.ended_mut()[0].flow.tcp_flags_string().is_none());
    }

    #[test]
    fn idle_flows_time_out() {
        let mut table = table(100, 60);
        observe(
            &mut table,
            TCP,
            endpoint(1, 1),
            endpoint(2, 2),
            at(0),
            74,
            None,
        );

        table.sweep(at(30));
        assert_eq!(table.len(), 1, "still within the timeout");

        table.sweep(at(61));
        assert_eq!(table.len(), 0);
        assert_eq!(table.ended_mut()[0].reason, EndReason::TimedOut);
        assert_eq!(table.counters().timed_out, 1);
    }

    #[test]
    fn a_busy_flow_is_not_timed_out() {
        let mut table = table(100, 60);
        for second in 0..200 {
            observe(
                &mut table,
                TCP,
                endpoint(1, 1),
                endpoint(2, 2),
                at(second),
                74,
                None,
            );
        }
        assert_eq!(table.len(), 1, "traffic keeps the flow alive across sweeps");
        assert_eq!(table.counters().timed_out, 0);
    }

    /// The DoS property: an attacker who opens flows without limit must not be
    /// able to grow the table without limit.
    #[test]
    fn the_table_never_exceeds_its_cap() {
        const CAP: usize = 64;
        let mut table = table(CAP, 3_600);

        for i in 0..10_000u32 {
            let source = (IpAddr::V4(Ipv4Addr::from(i.to_be_bytes())), 1_234);
            observe(
                &mut table,
                TCP,
                source,
                endpoint(2, 80),
                at(0),
                74,
                Some(SYN),
            );
            assert!(
                table.len() <= CAP,
                "table grew to {} past the cap",
                table.len()
            );
            table.ended_mut().clear();
        }

        assert!(
            table.counters().evicted > 0,
            "evictions must be counted, not silent"
        );
    }

    #[test]
    fn eviction_takes_the_least_recently_seen_flow_first() {
        let mut table = table(10, 3_600);

        // Ten flows, each last seen at a distinct time.
        for i in 0..10u8 {
            observe(
                &mut table,
                TCP,
                endpoint(i, 1_000),
                endpoint(200, 80),
                at(u64::from(i)),
                74,
                None,
            );
        }
        table.ended_mut().clear();

        // Refresh the oldest so it is no longer the eviction candidate.
        observe(
            &mut table,
            TCP,
            endpoint(0, 1_000),
            endpoint(200, 80),
            at(100),
            74,
            None,
        );
        table.ended_mut().clear();

        // One more flow forces an eviction batch.
        observe(
            &mut table,
            TCP,
            endpoint(99, 1_000),
            endpoint(200, 80),
            at(101),
            74,
            None,
        );

        let evicted: Vec<Endpoint> = table
            .ended_mut()
            .iter()
            .filter(|ended| ended.reason == EndReason::Evicted)
            .map(|ended| ended.flow.initiator)
            .collect();
        assert!(!evicted.is_empty());
        assert!(
            !evicted.contains(&endpoint(0, 1_000)),
            "the recently refreshed flow should not be the one evicted: {evicted:?}"
        );
        assert!(evicted.contains(&endpoint(1, 1_000)), "{evicted:?}");
    }

    #[test]
    fn timeouts_are_preferred_over_evicting_live_flows() {
        let mut table = table(4, 60);
        for i in 0..4u8 {
            observe(
                &mut table,
                TCP,
                endpoint(i, 1_000),
                endpoint(200, 80),
                at(0),
                74,
                None,
            );
        }
        table.ended_mut().clear();

        // Long after the timeout, a new flow arrives. The four idle flows
        // should be swept, not evicted: eviction is the lossy path.
        observe(
            &mut table,
            TCP,
            endpoint(50, 1_000),
            endpoint(200, 80),
            at(1_000),
            74,
            None,
        );

        assert_eq!(table.counters().timed_out, 4);
        assert_eq!(
            table.counters().evicted,
            0,
            "sweeping should have freed enough room"
        );
    }

    #[test]
    fn flush_ends_every_remaining_flow() {
        let mut table = table(100, 300);
        for i in 0..5u8 {
            observe(
                &mut table,
                TCP,
                endpoint(i, 1_000),
                endpoint(200, 80),
                at(0),
                74,
                None,
            );
        }
        table.flush();

        assert!(table.is_empty());
        assert_eq!(table.ended_mut().len(), 5);
        assert!(table
            .ended_mut()
            .iter()
            .all(|ended| ended.reason == EndReason::SensorStopped));
    }

    #[test]
    fn flow_ids_are_reproducible_across_runs() {
        // Two independent tables fed the same capture must agree, or replaying
        // the same file twice would produce incomparable events.
        let mut first = table(100, 300);
        let mut second = table(100, 300);
        let a = observe(
            &mut first,
            TCP,
            endpoint(1, 51_000),
            endpoint(2, 80),
            at(1_700),
            74,
            None,
        );
        let b = observe(
            &mut second,
            TCP,
            endpoint(1, 51_000),
            endpoint(2, 80),
            at(1_700),
            74,
            None,
        );
        assert_eq!(a.flow_id, b.flow_id);
        assert_ne!(a.flow_id.get(), 0, "zero is reserved for 'no flow'");
    }

    #[test]
    fn flows_starting_at_different_times_get_different_ids() {
        let mut table = table(100, 300);
        let a = observe(
            &mut table,
            TCP,
            endpoint(1, 51_000),
            endpoint(2, 80),
            at(1_000),
            74,
            Some(RST),
        );
        table.ended_mut().clear();
        let b = observe(
            &mut table,
            TCP,
            endpoint(1, 51_000),
            endpoint(2, 80),
            at(2_000),
            74,
            None,
        );
        assert_ne!(
            a.flow_id, b.flow_id,
            "a reused 5-tuple is a new conversation"
        );
    }

    #[test]
    fn the_oriented_tuple_puts_the_initiator_first() {
        let mut table = table(100, 300);
        // Deliberately open from the higher-sorting endpoint, so the canonical
        // key order and the initiator disagree.
        observe(
            &mut table,
            TCP,
            endpoint(9, 51_000),
            endpoint(1, 80),
            at(0),
            74,
            None,
        );
        table.flush();

        let (initiator, responder) = table.ended_mut()[0].flow.oriented_tuple();
        assert_eq!(initiator, endpoint(9, 51_000));
        assert_eq!(responder, endpoint(1, 80));
    }

    /// Reassembly reaching the caller through the table, which is how the
    /// pipeline will consume it.
    #[test]
    fn stream_bytes_surface_through_the_flow_table() {
        let mut table = table(100, 300);
        let client = endpoint(1, 51_000);
        let server = endpoint(2, 80);
        let mut ready = StreamReady::default();
        let mut delivered = Vec::new();

        let send = |table: &mut FlowTable,
                    source,
                    destination,
                    segment,
                    ready: &mut StreamReady,
                    delivered: &mut Vec<u8>| {
            ready.clear();
            table.observe(
                &PacketSummary {
                    protocol: TCP,
                    source,
                    destination,
                    timestamp: at(0),
                    frame_len: 74,
                    tcp: Some(segment),
                },
                &|_| OverlapPolicy::First,
                ready,
            );
            delivered.extend_from_slice(&ready.to_server);
        };

        send(
            &mut table,
            client,
            server,
            TcpSegment {
                sequence: 1_000,
                acknowledgment: 0,
                flags: SYN,
                payload: b"",
            },
            &mut ready,
            &mut delivered,
        );
        send(
            &mut table,
            server,
            client,
            TcpSegment {
                sequence: 5_000,
                acknowledgment: 1_001,
                flags: SYN | ACK,
                payload: b"",
            },
            &mut ready,
            &mut delivered,
        );
        send(
            &mut table,
            client,
            server,
            TcpSegment {
                sequence: 1_001,
                acknowledgment: 5_001,
                flags: ACK,
                payload: b"GET /etc",
            },
            &mut ready,
            &mut delivered,
        );
        send(
            &mut table,
            client,
            server,
            TcpSegment {
                sequence: 1_009,
                acknowledgment: 5_001,
                flags: ACK,
                payload: b"/passwd",
            },
            &mut ready,
            &mut delivered,
        );
        // The server acknowledges, settling the request.
        send(
            &mut table,
            server,
            client,
            TcpSegment {
                sequence: 5_001,
                acknowledgment: 1_016,
                flags: ACK,
                payload: b"",
            },
            &mut ready,
            &mut delivered,
        );

        assert_eq!(delivered, b"GET /etc/passwd");
    }

    #[test]
    fn a_flow_ending_delivers_whatever_was_still_contiguous() {
        let mut table = table(100, 300);
        let client = endpoint(1, 51_000);
        let server = endpoint(2, 80);
        let mut ready = StreamReady::default();

        for segment in [
            TcpSegment {
                sequence: 1_000,
                acknowledgment: 0,
                flags: SYN,
                payload: b"",
            },
            TcpSegment {
                sequence: 1_001,
                acknowledgment: 0,
                flags: ACK,
                payload: b"unacked tail",
            },
        ] {
            table.observe(
                &PacketSummary {
                    protocol: TCP,
                    source: client,
                    destination: server,
                    timestamp: at(0),
                    frame_len: 74,
                    tcp: Some(segment),
                },
                &|_| OverlapPolicy::First,
                &mut ready,
            );
        }
        assert!(ready.is_empty(), "nothing has acknowledged it yet");

        table.flush();
        assert_eq!(
            table.ended_mut()[0].final_ready.to_server,
            b"unacked tail",
            "the tail of a conversation still has to be matched against"
        );
    }

    /// The second ceiling: many flows each holding a little.
    #[test]
    fn the_global_stream_byte_cap_forces_eviction() {
        let mut table = FlowTable::with_reassembly(
            Limits {
                max_flows: 10_000,
                flow_timeout: Duration::from_secs(3_600),
                ..Limits::default()
            },
            ReassemblyConfig {
                max_stream_bytes_per_flow: 4_096,
                max_stream_bytes_total: 32_768,
                delivery_flush_bytes: 4_096,
                ..ReassemblyConfig::default()
            },
        );
        let mut ready = StreamReady::default();
        let payload = [b'A'; 1_024];

        for index in 0..200u16 {
            let client = (
                IpAddr::V4(Ipv4Addr::new(10, 0, (index >> 8) as u8, index as u8)),
                4_000,
            );
            let server = endpoint(200, 80);
            for segment in [
                TcpSegment {
                    sequence: 1_000,
                    acknowledgment: 0,
                    flags: SYN,
                    payload: b"",
                },
                // Offset 1 leaves a hole at the front, so nothing can ever be
                // delivered and the bytes just accumulate.
                TcpSegment {
                    sequence: 1_002,
                    acknowledgment: 0,
                    flags: ACK,
                    payload: &payload,
                },
            ] {
                table.observe(
                    &PacketSummary {
                        protocol: TCP,
                        source: client,
                        destination: server,
                        timestamp: at(0),
                        frame_len: 1_100,
                        tcp: Some(segment),
                    },
                    &|_| OverlapPolicy::First,
                    &mut ready,
                );
            }
            table.ended_mut().clear();
            assert!(
                table.buffered_bytes() <= 32_768 + 1_024,
                "held {} bytes against a 32768 cap",
                table.buffered_bytes()
            );
        }
        assert!(table.counters().evicted > 0, "evictions must be counted");
    }

    #[test]
    fn a_backwards_timestamp_does_not_produce_a_negative_duration() {
        let mut table = table(100, 300);
        observe(
            &mut table,
            TCP,
            endpoint(1, 1),
            endpoint(2, 2),
            at(100),
            74,
            None,
        );
        observe(
            &mut table,
            TCP,
            endpoint(1, 1),
            endpoint(2, 2),
            at(50),
            74,
            None,
        );
        table.flush();
        assert_eq!(table.ended_mut()[0].flow.duration(), Duration::ZERO);
    }
}
