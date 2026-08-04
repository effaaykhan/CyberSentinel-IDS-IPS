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
#[derive(Debug, Clone)]
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
    /// Whether a RST has been seen.
    saw_reset: bool,
}

impl Flow {
    /// The 5-tuple oriented from the initiator, as events report it.
    #[must_use]
    pub fn oriented_tuple(&self) -> (Endpoint, Endpoint) {
        let responder = if self.initiator == self.key.first {
            self.key.second
        } else {
            self.key.first
        };
        (self.initiator, responder)
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
#[derive(Debug, Clone)]
pub struct EndedFlow {
    /// The flow as it was.
    pub flow: Flow,
    /// Why it ended.
    pub reason: EndReason,
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
}

const TCP_PROTOCOL: u8 = 6;

/// A bounded table of live flows.
#[derive(Debug)]
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    limits: Limits,
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
        Self {
            flows: HashMap::new(),
            limits,
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
        protocol: u8,
        source: Endpoint,
        destination: Endpoint,
        timestamp: SystemTime,
        frame_len: usize,
        tcp_flags: Option<u8>,
    ) -> Observed {
        self.maybe_sweep(timestamp);

        let key = FlowKey::new(protocol, source, destination);
        let is_new = !self.flows.contains_key(&key);
        if is_new {
            self.make_room(timestamp);
        }

        let counters = &mut self.counters;
        let flow = self.flows.entry(key).or_insert_with(|| {
            counters.created += 1;
            Flow {
                id: FlowId(derive_flow_id(&key, timestamp)),
                key,
                initiator: source,
                start: timestamp,
                last_seen: timestamp,
                to_server: DirectionCounters::default(),
                to_client: DirectionCounters::default(),
                tcp_flags_seen: 0,
                fin_from_initiator: false,
                fin_from_responder: false,
                saw_reset: false,
            }
        });

        let to_server = source == flow.initiator;
        let direction = if to_server {
            &mut flow.to_server
        } else {
            &mut flow.to_client
        };
        direction.packets += 1;
        direction.bytes += frame_len as u64;

        // Capture timestamps are not guaranteed monotonic (multiple queues, a
        // stepped clock), so never let `last_seen` go backwards — a flow that
        // appears to end before it started would produce nonsense durations.
        if timestamp > flow.last_seen {
            flow.last_seen = timestamp;
        }

        if let Some(flags) = tcp_flags {
            flow.tcp_flags_seen |= flags;
            const FIN: u8 = 0b0000_0001;
            const RST: u8 = 0b0000_0100;
            if flags & FIN != 0 {
                if to_server {
                    flow.fin_from_initiator = true;
                } else {
                    flow.fin_from_responder = true;
                }
            }
            if flags & RST != 0 {
                flow.saw_reset = true;
            }
        }

        let observed = Observed {
            flow_id: flow.id,
            to_server,
            is_new,
        };

        if flow.is_closed() {
            if let Some(flow) = self.flows.remove(&key) {
                self.counters.closed += 1;
                self.ended.push(EndedFlow {
                    flow,
                    reason: EndReason::Closed,
                });
            }
        }

        observed
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
        let ended = &mut self.ended;
        let counters = &mut self.counters;

        self.flows.retain(|_, flow| {
            let idle = now.duration_since(flow.last_seen).unwrap_or_default();
            if idle < timeout {
                return true;
            }
            counters.timed_out += 1;
            ended.push(EndedFlow {
                flow: flow.clone(),
                reason: EndReason::TimedOut,
            });
            false
        });
    }

    /// Make space for one more flow, evicting a batch if the table is full.
    fn make_room(&mut self, now: SystemTime) {
        if self.flows.len() < self.limits.max_flows {
            return;
        }

        // A timeout sweep may free everything needed without losing a live flow.
        self.sweep(now);
        if self.flows.len() < self.limits.max_flows {
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
                self.ended.push(EndedFlow {
                    flow,
                    reason: EndReason::Evicted,
                });
            }
        }

        tracing::warn!(
            evicted = batch,
            capacity = self.limits.max_flows,
            "flow table is full; evicting live flows — visibility is being lost"
        );
    }

    /// End every remaining flow, for shutdown or end of capture.
    pub fn flush(&mut self) {
        for (_, flow) in self.flows.drain() {
            self.ended.push(EndedFlow {
                flow,
                reason: EndReason::SensorStopped,
            });
        }
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

        let first = table.observe(TCP, client, server, at(0), 74, Some(SYN));
        let reply = table.observe(TCP, server, client, at(1), 74, Some(SYN | ACK));

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
        let a = table.observe(TCP, endpoint(1, 51_000), endpoint(2, 80), at(0), 74, None);
        let b = table.observe(TCP, endpoint(1, 51_001), endpoint(2, 80), at(0), 74, None);
        assert_ne!(a.flow_id, b.flow_id);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn the_same_ports_on_a_different_protocol_are_different_flows() {
        let mut table = table(100, 300);
        let tcp = table.observe(TCP, endpoint(1, 5_000), endpoint(2, 53), at(0), 74, None);
        let udp = table.observe(UDP, endpoint(1, 5_000), endpoint(2, 53), at(0), 74, None);
        assert_ne!(tcp.flow_id, udp.flow_id);
    }

    #[test]
    fn counters_are_kept_per_direction() {
        let mut table = table(100, 300);
        let client = endpoint(1, 51_000);
        let server = endpoint(2, 80);

        table.observe(TCP, client, server, at(0), 100, None);
        table.observe(TCP, client, server, at(1), 200, None);
        table.observe(TCP, server, client, at(2), 1_500, None);
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

        table.observe(TCP, client, server, at(0), 74, Some(SYN));
        table.observe(TCP, server, client, at(1), 74, Some(SYN | ACK));
        table.observe(TCP, client, server, at(2), 74, Some(FIN | ACK));
        assert_eq!(table.len(), 1, "one FIN is not a teardown");

        table.observe(TCP, server, client, at(3), 74, Some(FIN | ACK));
        assert_eq!(table.len(), 0, "FIN in both directions ends the flow");

        let ended = table.ended_mut();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].reason, EndReason::Closed);
        assert_eq!(ended[0].flow.tcp_flags_string().as_deref(), Some("FSA"));
        assert_eq!(table.counters().closed, 1);
    }

    #[test]
    fn a_reset_closes_the_flow_immediately() {
        let mut table = table(100, 300);
        table.observe(
            TCP,
            endpoint(1, 51_000),
            endpoint(2, 80),
            at(0),
            74,
            Some(SYN),
        );
        table.observe(
            TCP,
            endpoint(2, 80),
            endpoint(1, 51_000),
            at(1),
            74,
            Some(RST),
        );
        assert_eq!(table.len(), 0);
        assert_eq!(table.ended_mut()[0].reason, EndReason::Closed);
    }

    #[test]
    fn udp_flows_report_no_tcp_flags() {
        let mut table = table(100, 300);
        table.observe(UDP, endpoint(1, 5_000), endpoint(2, 53), at(0), 74, None);
        table.flush();
        assert!(table.ended_mut()[0].flow.tcp_flags_string().is_none());
    }

    #[test]
    fn idle_flows_time_out() {
        let mut table = table(100, 60);
        table.observe(TCP, endpoint(1, 1), endpoint(2, 2), at(0), 74, None);

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
            table.observe(TCP, endpoint(1, 1), endpoint(2, 2), at(second), 74, None);
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
            table.observe(TCP, source, endpoint(2, 80), at(0), 74, Some(SYN));
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
            table.observe(
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
        table.observe(
            TCP,
            endpoint(0, 1_000),
            endpoint(200, 80),
            at(100),
            74,
            None,
        );
        table.ended_mut().clear();

        // One more flow forces an eviction batch.
        table.observe(
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
            table.observe(TCP, endpoint(i, 1_000), endpoint(200, 80), at(0), 74, None);
        }
        table.ended_mut().clear();

        // Long after the timeout, a new flow arrives. The four idle flows
        // should be swept, not evicted: eviction is the lossy path.
        table.observe(
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
            table.observe(TCP, endpoint(i, 1_000), endpoint(200, 80), at(0), 74, None);
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
        let a = first.observe(
            TCP,
            endpoint(1, 51_000),
            endpoint(2, 80),
            at(1_700),
            74,
            None,
        );
        let b = second.observe(
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
        let a = table.observe(
            TCP,
            endpoint(1, 51_000),
            endpoint(2, 80),
            at(1_000),
            74,
            Some(RST),
        );
        table.ended_mut().clear();
        let b = table.observe(
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
        table.observe(TCP, endpoint(9, 51_000), endpoint(1, 80), at(0), 74, None);
        table.flush();

        let (initiator, responder) = table.ended_mut()[0].flow.oriented_tuple();
        assert_eq!(initiator, endpoint(9, 51_000));
        assert_eq!(responder, endpoint(1, 80));
    }

    #[test]
    fn a_backwards_timestamp_does_not_produce_a_negative_duration() {
        let mut table = table(100, 300);
        table.observe(TCP, endpoint(1, 1), endpoint(2, 2), at(100), 74, None);
        table.observe(TCP, endpoint(1, 1), endpoint(2, 2), at(50), 74, None);
        table.flush();
        assert_eq!(table.ended_mut()[0].flow.duration(), Duration::ZERO);
    }
}
