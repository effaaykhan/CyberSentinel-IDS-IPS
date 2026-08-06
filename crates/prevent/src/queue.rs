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
    /// The flow it belongs to, as the detection path numbers flows.
    pub flow_id: u64,
    /// Its 5-tuple.
    pub tuple: NetTuple,
}

/// Judge one packet. The entire hot path.
///
/// Split out as a free function so the fuzz target and the offline tests
/// exercise exactly what the NFQUEUE loop exercises, rather than a
/// reimplementation of it that could drift.
pub fn judge(prevention: &mut Prevention, packet: &QueuedPacket, now: Instant) -> Decision {
    let started = Instant::now();
    let decision = prevention.decide(packet.flow_id, &packet.tuple, now);
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

    fn packet(id: u32, flow_id: u64, src: &str) -> QueuedPacket {
        QueuedPacket {
            id,
            flow_id,
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
        let mut queue = OfflineQueue::new(vec![
            packet(1, 10, "203.0.113.7"),
            packet(2, 10, "203.0.113.7"),
        ]);
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

        let early = packet(1, 10, "203.0.113.7");
        assert_eq!(
            judge(&mut prevention, &early, Instant::now()),
            Decision::Accept
        );

        // Detection catches up and condemns the flow.
        prevention.block(10, &early.tuple, Instant::now());

        for id in 2..5 {
            assert_eq!(
                judge(
                    &mut prevention,
                    &packet(id, 10, "203.0.113.7"),
                    Instant::now()
                ),
                Decision::Drop(DropReason::FlowVerdict),
                "the rest of the flow is what inline prevention actually stops"
            );
        }
    }

    #[test]
    fn a_run_records_a_verdict_for_every_packet() {
        let packets: Vec<_> = (0..50)
            .map(|id| packet(id, u64::from(id), "203.0.113.7"))
            .collect();
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
            judge(
                &mut prevention,
                &packet(id, 1, "203.0.113.7"),
                Instant::now(),
            );
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
        let first = packet(1, 10, "203.0.113.7");
        prevention.block(10, &first.tuple, Instant::now());

        let mut queue = OfflineQueue::new(vec![packet(2, 10, "203.0.113.7")]);
        run(&mut queue, &mut prevention);
        assert!(queue.all_accepted());
    }

    #[test]
    fn an_empty_queue_is_a_valid_run() {
        let mut queue = OfflineQueue::new(Vec::new());
        let mut prevention = armed();
        assert_eq!(run(&mut queue, &mut prevention), RunSummary::default());
    }
}
