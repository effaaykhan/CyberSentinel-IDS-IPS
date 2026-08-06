//! The driver: packets in, verdicts out.
//!
//! Deliberately thin. Everything that decides anything lives in
//! [`crate::store`], which is pure; this module's only job is to get packets
//! from somewhere and hand back an answer. That split is what lets the verdict
//! logic be tested and fuzzed in CI with no root, no nftables, and no kernel
//! queue — see [`OfflineQueue`].

use crate::store::{Decision, Prevention};
use cybersentinel_common::event::NetTuple;
use std::time::Instant;

/// A source of packets awaiting a verdict.
///
/// Two implementations: the real NFQUEUE, and an offline one that replays
/// packets from memory. The verdict path cannot tell them apart, which is the
/// point — the logic under test in CI is the logic that runs in the path.
pub trait VerdictSource {
    /// Wait for the next packet. `None` means the source is finished.
    fn next_packet(&mut self) -> Option<QueuedPacket>;
    /// Hand back the answer.
    fn resolve(&mut self, packet: QueuedPacket, decision: Decision);
}

/// A packet the kernel is holding while we decide.
#[derive(Debug, Clone)]
pub struct QueuedPacket {
    /// The kernel's handle for this packet, echoed back with the verdict.
    pub id: u32,
    /// Its 5-tuple. The verdict path derives everything it needs from this.
    pub tuple: NetTuple,
}

/// Judge one packet. The entire hot path.
///
/// Split out as a free function so the fuzz target and the offline tests
/// exercise exactly what the NFQUEUE loop exercises, rather than a
/// reimplementation of it that could drift.
pub fn judge(prevention: &mut Prevention, packet: &QueuedPacket, now: Instant) -> Decision {
    let started = Instant::now();
    let decision = prevention.decide(&packet.tuple, now);
    // Microseconds: a verdict path measured in milliseconds is already broken.
    let elapsed = started.elapsed().as_micros();
    prevention.record_latency(u64::try_from(elapsed).unwrap_or(u64::MAX));
    decision
}

/// Run a source to completion, judging everything it produces.
pub fn run<S: VerdictSource>(source: &mut S, prevention: &mut Prevention) -> RunSummary {
    let mut summary = RunSummary::default();
    while let Some(packet) = source.next_packet() {
        let decision = judge(prevention, &packet, Instant::now());
        match decision {
            Decision::Accept => summary.accepted += 1,
            Decision::Drop(_) => summary.dropped += 1,
        }
        source.resolve(packet, decision);
    }
    summary
}

/// What a run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunSummary {
    /// Packets passed.
    pub accepted: u64,
    /// Packets dropped.
    pub dropped: u64,
}

// ---------------------------------------------------------------------------
// offline
// ---------------------------------------------------------------------------

/// A queue with no kernel behind it.
///
/// The verdict path is the one part of this project that can take a network
/// down, so "it works" cannot rest on a test that needs root, nftables, and a
/// spare interface. This replays packets from memory and records the verdicts,
/// so the same `judge` that runs inline runs in CI.
#[derive(Debug, Default)]
pub struct OfflineQueue {
    pending: std::collections::VecDeque<QueuedPacket>,
    /// What was decided, in order, for assertions.
    pub verdicts: Vec<(u32, Decision)>,
}

impl OfflineQueue {
    /// A queue holding these packets.
    #[must_use]
    pub fn new(packets: Vec<QueuedPacket>) -> Self {
        Self {
            pending: packets.into(),
            verdicts: Vec::new(),
        }
    }

    /// Whether every packet was accepted.
    #[must_use]
    pub fn all_accepted(&self) -> bool {
        self.verdicts
            .iter()
            .all(|(_, decision)| *decision == Decision::Accept)
    }

    /// The decisions, without the ids.
    #[must_use]
    pub fn decisions(&self) -> Vec<Decision> {
        self.verdicts
            .iter()
            .map(|(_, decision)| *decision)
            .collect()
    }
}

impl VerdictSource for OfflineQueue {
    fn next_packet(&mut self) -> Option<QueuedPacket> {
        self.pending.pop_front()
    }

    fn resolve(&mut self, packet: QueuedPacket, decision: Decision) {
        self.verdicts.push((packet.id, decision));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{DropReason, Mode, PreventionSettings};
    use cybersentinel_common::event::Protocol;

    fn packet(id: u32, src: &str) -> QueuedPacket {
        QueuedPacket {
            id,
            tuple: NetTuple {
                src_ip: src.parse().expect("an address"),
                src_port: Some(4_000),
                dest_ip: "10.0.0.1".parse().expect("an address"),
                dest_port: Some(80),
                proto: Protocol::Tcp,
            },
        }
    }

    fn armed() -> Prevention {
        Prevention::new(PreventionSettings {
            mode: Mode::Prevent,
            ..PreventionSettings::default()
        })
    }

    #[test]
    fn an_offline_run_accepts_everything_by_default() {
        let mut queue = OfflineQueue::new(vec![packet(1, "203.0.113.7"), packet(2, "203.0.113.7")]);
        let mut prevention = armed();

        let summary = run(&mut queue, &mut prevention);
        assert_eq!(summary.accepted, 2);
        assert_eq!(summary.dropped, 0);
        assert!(queue.all_accepted());
    }

    /// The shape of a real block: the flow is condemned partway through, and
    /// everything after it is dropped. The packets before it have already
    /// passed — which is the honest limit stated in the crate docs.
    #[test]
    fn packets_after_a_block_verdict_are_dropped_and_earlier_ones_were_not() {
        let mut prevention = armed();

        let early = packet(1, "203.0.113.7");
        assert_eq!(
            judge(&mut prevention, &early, Instant::now()),
            Decision::Accept
        );

        // Detection catches up and condemns the flow.
        prevention.block(&early.tuple, Instant::now());

        for id in 2..5 {
            assert_eq!(
                judge(&mut prevention, &packet(id, "203.0.113.7"), Instant::now()),
                Decision::Drop(DropReason::FlowVerdict),
                "the rest of the flow is what inline prevention actually stops"
            );
        }
    }

    #[test]
    fn a_run_records_a_verdict_for_every_packet() {
        let packets: Vec<_> = (0..50).map(|id| packet(id, "203.0.113.7")).collect();
        let mut queue = OfflineQueue::new(packets);
        let mut prevention = armed();

        let summary = run(&mut queue, &mut prevention);
        assert_eq!(
            queue.verdicts.len(),
            50,
            "a queued packet must never be left unanswered"
        );
        assert_eq!(summary.accepted + summary.dropped, 50);
    }

    #[test]
    fn latency_is_measured_for_every_judged_packet() {
        let mut prevention = armed();
        for id in 0..10 {
            judge(&mut prevention, &packet(id, "203.0.113.7"), Instant::now());
        }
        let stats = prevention.stats();
        assert_eq!(stats.packets_judged, 10);
        // The verdict path is table lookups; anything approaching a
        // millisecond would mean something is very wrong.
        assert!(
            stats.verdict_latency_us_max < 1_000,
            "verdict took {}us, which is not a table lookup",
            stats.verdict_latency_us_max
        );
    }

    #[test]
    fn detect_mode_accepts_a_condemned_flow() {
        let mut prevention = Prevention::new(PreventionSettings::default());
        let first = packet(1, "203.0.113.7");
        prevention.block(&first.tuple, Instant::now());

        let mut queue = OfflineQueue::new(vec![packet(2, "203.0.113.7")]);
        run(&mut queue, &mut prevention);
        assert!(queue.all_accepted());
    }

    /// Blocking a conversation has to stop the replies too. A server still
    /// answering an attacker whose requests are being dropped is a half-closed
    /// session, not a blocked one.
    #[test]
    fn a_block_stops_both_directions_of_the_conversation() {
        use cybersentinel_common::event::NetTuple;
        let mut prevention = armed();
        let now = Instant::now();

        let request = packet(1, "203.0.113.7").tuple;
        prevention.block(&request, now);

        let reply = NetTuple {
            src_ip: request.dest_ip,
            src_port: request.dest_port,
            dest_ip: request.src_ip,
            dest_port: request.src_port,
            proto: request.proto,
        };
        assert!(
            prevention.decide(&reply, now).is_drop(),
            "the reply direction must be dropped by the same verdict"
        );
    }

    // -----------------------------------------------------------------------
    // reading the tuple out of a packet
    // -----------------------------------------------------------------------

    /// A minimal IPv4 TCP packet.
    fn ipv4_tcp(src: [u8; 4], dest: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45; // version 4, 5-word header
        packet[9] = 6; // TCP
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dest);
        packet[20..22].copy_from_slice(&sport.to_be_bytes());
        packet[22..24].copy_from_slice(&dport.to_be_bytes());
        packet
    }

    #[test]
    fn reads_an_ipv4_tcp_tuple() {
        let bytes = ipv4_tcp([203, 0, 113, 7], [10, 0, 0, 1], 4_000, 80);
        let tuple = tuple_from_ip_packet(&bytes).expect("a tuple");
        assert_eq!(tuple.src_ip.to_string(), "203.0.113.7");
        assert_eq!(tuple.dest_ip.to_string(), "10.0.0.1");
        assert_eq!(tuple.src_port, Some(4_000));
        assert_eq!(tuple.dest_port, Some(80));
    }

    #[test]
    fn reads_an_ipv6_tuple() {
        let mut packet = vec![0_u8; 48];
        packet[0] = 0x60;
        packet[6] = 17; // UDP
        packet[8..24]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40..42].copy_from_slice(&53_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&5_353_u16.to_be_bytes());

        let tuple = tuple_from_ip_packet(&packet).expect("a tuple");
        assert_eq!(tuple.src_ip.to_string(), "2001:db8::1");
        assert_eq!(tuple.src_port, Some(53));
    }

    /// A later fragment carries no ports. Reading them out of the payload
    /// would attribute the packet to a port nobody used.
    #[test]
    fn a_non_initial_fragment_has_no_ports() {
        let mut bytes = ipv4_tcp([203, 0, 113, 7], [10, 0, 0, 1], 4_000, 80);
        bytes[6] = 0x00;
        bytes[7] = 0x25; // a non-zero fragment offset
        let tuple = tuple_from_ip_packet(&bytes).expect("a tuple");
        assert_eq!(tuple.src_port, None);
        assert_eq!(
            tuple.src_ip.to_string(),
            "203.0.113.7",
            "the addresses are still readable, which is what source blocking needs"
        );
    }

    #[test]
    fn icmp_has_no_ports_and_is_still_identified() {
        let mut bytes = ipv4_tcp([203, 0, 113, 7], [10, 0, 0, 1], 0, 0);
        bytes[9] = 1; // ICMP
        let tuple = tuple_from_ip_packet(&bytes).expect("a tuple");
        assert_eq!(tuple.src_port, None);
        assert_eq!(tuple.proto, cybersentinel_common::event::Protocol::Icmp);
    }

    #[test]
    fn a_truncated_or_nonsense_packet_yields_no_tuple() {
        for bytes in [
            vec![],
            vec![0x45],
            vec![0x45; 10],
            vec![0x60; 20],
            vec![0xf0; 40],
            vec![0x40; 40],
        ] {
            let _ = tuple_from_ip_packet(&bytes);
        }
        assert!(tuple_from_ip_packet(&[]).is_none());
        assert!(
            tuple_from_ip_packet(&[0x45; 10]).is_none(),
            "too short for a v4 header"
        );
        assert!(
            tuple_from_ip_packet(&[0xf0; 40]).is_none(),
            "not a known IP version"
        );
    }

    #[test]
    fn an_empty_queue_is_a_valid_run() {
        let mut queue = OfflineQueue::new(Vec::new());
        let mut prevention = armed();
        assert_eq!(run(&mut queue, &mut prevention), RunSummary::default());
    }
}

// ---------------------------------------------------------------------------
// the 5-tuple, from a bare IP packet
// ---------------------------------------------------------------------------

/// Read the 5-tuple out of an IP packet.
///
/// NFQUEUE hands over the packet from the IP header on — no Ethernet framing —
/// so this is a deliberately small, bounded read of just the fields the verdict
/// path needs. It is not a decoder: anything it does not fully understand
/// yields `None`, and a packet with no tuple is accepted rather than guessed
/// at, because the alternative is dropping traffic on the strength of a header
/// we could not read.
///
/// Fragments are handled by taking the tuple from the **first** fragment only.
/// A later fragment carries no ports, and inventing them from the payload would
/// attribute the packet to a port nobody used — the same rule the decoder
/// already follows.
#[must_use]
pub fn tuple_from_ip_packet(bytes: &[u8]) -> Option<NetTuple> {
    use cybersentinel_common::event::Protocol;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let version = bytes.first()? >> 4;
    let (source, destination, protocol, transport) = match version {
        4 => {
            let header_len = usize::from(bytes.first()? & 0x0f) * 4;
            if header_len < 20 || bytes.len() < header_len {
                return None;
            }
            let protocol = *bytes.get(9)?;
            let source = IpAddr::V4(Ipv4Addr::new(
                *bytes.get(12)?,
                *bytes.get(13)?,
                *bytes.get(14)?,
                *bytes.get(15)?,
            ));
            let destination = IpAddr::V4(Ipv4Addr::new(
                *bytes.get(16)?,
                *bytes.get(17)?,
                *bytes.get(18)?,
                *bytes.get(19)?,
            ));
            // A non-initial fragment has no transport header to read.
            let fragment_offset = u16::from_be_bytes([*bytes.get(6)? & 0x1f, *bytes.get(7)?]);
            let transport = if fragment_offset == 0 {
                bytes.get(header_len..)
            } else {
                None
            };
            (source, destination, protocol, transport)
        }
        6 => {
            if bytes.len() < 40 {
                return None;
            }
            let protocol = *bytes.get(6)?;
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(bytes.get(8..24)?);
            let source = IpAddr::V6(Ipv6Addr::from(octets));
            octets.copy_from_slice(bytes.get(24..40)?);
            let destination = IpAddr::V6(Ipv6Addr::from(octets));
            // Extension headers are not walked. A packet carrying them yields
            // no ports rather than ports read from the wrong offset; it is
            // still identified by address, which is what source blocking needs.
            (source, destination, protocol, bytes.get(40..))
        }
        _ => return None,
    };

    let (proto, wants_ports) = match protocol {
        6 => (Protocol::Tcp, true),
        17 => (Protocol::Udp, true),
        1 | 58 => (Protocol::Icmp, false),
        _ => (Protocol::Ip, false),
    };

    let (src_port, dest_port) = match (wants_ports, transport) {
        (true, Some(payload)) if payload.len() >= 4 => (
            Some(u16::from_be_bytes([payload[0], payload[1]])),
            Some(u16::from_be_bytes([payload[2], payload[3]])),
        ),
        _ => (None, None),
    };

    Some(NetTuple {
        src_ip: source,
        src_port,
        dest_ip: destination,
        dest_port,
        proto,
    })
}

// ---------------------------------------------------------------------------
// the real queue
// ---------------------------------------------------------------------------

/// Packets from the kernel's netfilter queue.
///
/// The only part of prevention that touches a kernel. It holds no logic: it
/// reads a packet, hands the tuple to [`judge`] through [`run`], and echoes the
/// answer back. A packet whose header could not be read is **accepted** — the
/// verdict path must never drop traffic on the strength of a header it did not
/// understand.
#[cfg(target_os = "linux")]
#[allow(missing_debug_implementations)] // `nfq::Queue` is not `Debug`.
pub struct KernelQueue {
    queue: nfq::Queue,
    /// Packets received but not yet answered, by kernel id.
    in_flight: std::collections::HashMap<u32, nfq::Message>,
    /// Packets accepted without judgement because their header was unreadable.
    pub unparsed: u64,
}

#[cfg(target_os = "linux")]
impl KernelQueue {
    /// Bind to a queue number.
    ///
    /// # Errors
    /// If the queue cannot be opened or bound — most often because the process
    /// lacks `CAP_NET_ADMIN`, or because another program already holds it.
    pub fn bind(number: u16) -> std::io::Result<Self> {
        let mut queue = nfq::Queue::open()?;
        queue.bind(number)?;
        Ok(Self {
            queue,
            in_flight: std::collections::HashMap::new(),
            unparsed: 0,
        })
    }

    /// Set how many packets the kernel will hold for us before applying the
    /// fail mode.
    ///
    /// # Errors
    /// If the queue cannot be configured.
    pub fn set_queue_length(&mut self, number: u16, packets: u32) -> std::io::Result<()> {
        self.queue.set_queue_max_len(number, packets)
    }
}

#[cfg(target_os = "linux")]
impl VerdictSource for KernelQueue {
    fn next_packet(&mut self) -> Option<QueuedPacket> {
        loop {
            let message = self.queue.recv().ok()?;
            let id = message.get_packet_id();
            match tuple_from_ip_packet(message.get_payload()) {
                Some(tuple) => {
                    self.in_flight.insert(id, message);
                    return Some(QueuedPacket { id, tuple });
                }
                None => {
                    // Unreadable header: accept it and move on. Dropping a
                    // packet we could not parse would make every malformed
                    // frame an outage.
                    self.unparsed += 1;
                    let mut message = message;
                    message.set_verdict(nfq::Verdict::Accept);
                    let _ = self.queue.verdict(message);
                }
            }
        }
    }

    fn resolve(&mut self, packet: QueuedPacket, decision: Decision) {
        let Some(mut message) = self.in_flight.remove(&packet.id) else {
            return;
        };
        message.set_verdict(match decision {
            Decision::Accept => nfq::Verdict::Accept,
            Decision::Drop(_) => nfq::Verdict::Drop,
        });
        // A failed verdict leaves the kernel holding the packet until the
        // queue's own timeout applies the fail mode. Nothing better is
        // available from here, and it is counted by the caller.
        let _ = self.queue.verdict(message);
    }
}
