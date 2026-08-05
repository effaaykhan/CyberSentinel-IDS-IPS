//! IP defragmentation.
//!
//! Fragmentation is the oldest evasion technique there is: split an attack
//! across fragments and a sensor that does not reassemble sees only harmless
//! pieces. Send the pieces out of order, overlapping, or with contradictory
//! contents and a sensor that reassembles *differently from the destination*
//! sees something the destination never will.
//!
//! So this does three things, and all three matter:
//!
//! * reassemble out-of-order fragments into the original datagram;
//! * resolve overlapping fragments by the destination's configured
//!   [`OverlapPolicy`], and **count the ones that disagreed**;
//! * hold no more state than it is allowed to, because the attacker chooses how
//!   many incomplete datagrams exist and how long they stay incomplete.
//!
//! A datagram whose fragments never all arrive is discarded on timeout. That is
//! not a failure — it is the only correct outcome, and the alternative is
//! pinning memory on the attacker's say-so.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use cybersentinel_common::config::{OverlapPolicy, ReassemblyConfig};

use crate::range_buffer::RangeBuffer;

/// Largest datagram that can be reassembled.
///
/// IPv4's total-length field is 16 bits, so nothing legitimate exceeds this.
/// A fragment claiming to extend past it is the "oversized datagram" attack and
/// is refused rather than allocated for.
pub const MAX_DATAGRAM_LEN: u64 = 65_535;

/// Maximum holes tracked per datagram, so a scatter of tiny fragments cannot
/// cost unbounded bookkeeping.
const MAX_HOLES_PER_DATAGRAM: usize = 128;

/// How often, in capture time, to sweep for expired fragment sets.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// One fragment handed to the defragmenter.
#[derive(Debug, Clone, Copy)]
pub struct FragmentView<'a> {
    /// Source address.
    pub source: IpAddr,
    /// Destination address — whose policy decides overlaps.
    pub destination: IpAddr,
    /// Fragment identification from the IP header.
    pub identification: u32,
    /// Protocol carried by the reassembled datagram.
    pub protocol: u8,
    /// Fragment offset, in 8-byte units as it appears on the wire.
    pub offset: u16,
    /// Whether more fragments follow.
    pub more_fragments: bool,
    /// This fragment's payload.
    pub payload: &'a [u8],
}

/// Identifies one datagram being reassembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FragmentKey {
    source: IpAddr,
    destination: IpAddr,
    identification: u32,
    protocol: u8,
}

/// A completed datagram.
#[derive(Debug, Clone)]
pub struct Reassembled {
    /// Source address.
    pub source: IpAddr,
    /// Destination address.
    pub destination: IpAddr,
    /// Protocol of the transport header now at offset zero of `data`.
    pub protocol: u8,
    /// The reassembled payload: everything after the IP header.
    pub data: Vec<u8>,
    /// How many fragments went into it.
    pub fragments: u32,
    /// Bytes where two fragments disagreed. Non-zero means the reassembly was
    /// ambiguous and the configured policy had to break the tie.
    pub conflicting_bytes: u64,
}

/// Running totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DefragCounters {
    /// Fragments seen.
    pub fragments: u64,
    /// Datagrams fully reassembled.
    pub completed: u64,
    /// Reassemblies started.
    pub started: u64,
    /// Incomplete datagrams discarded on timeout.
    pub timed_out: u64,
    /// Incomplete datagrams evicted under memory pressure. **A coverage
    /// signal**: an attack may have been in one of them.
    pub evicted: u64,
    /// Fragment bytes that landed on already-covered offsets.
    pub overlaps: u64,
    /// Of those, bytes that **disagreed** with what was already there.
    pub conflicting_overlaps: u64,
    /// Fragments refused for claiming to extend past the maximum datagram size.
    pub oversized: u64,
    /// Fragment bytes refused by a per-datagram cap.
    pub refused_bytes: u64,
    /// Fragments that broke the 8-byte alignment rule for non-final fragments.
    pub misaligned: u64,
}

#[derive(Debug)]
struct FragmentSet {
    buffer: RangeBuffer,
    first_seen: SystemTime,
    last_seen: SystemTime,
    /// Known once the final fragment (more-fragments clear) arrives.
    total_len: Option<u64>,
    fragments: u32,
    conflicting_bytes: u64,
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
}

/// Reassembles IP fragments, under a hard bound.
#[derive(Debug)]
pub struct Defragmenter {
    sets: HashMap<FragmentKey, FragmentSet>,
    max_sets: usize,
    max_bytes_total: usize,
    timeout: Duration,
    counters: DefragCounters,
    last_sweep: Option<SystemTime>,
}

impl Defragmenter {
    /// Build a defragmenter from a config section.
    #[must_use]
    pub fn new(config: &ReassemblyConfig) -> Self {
        Self {
            sets: HashMap::new(),
            max_sets: config.max_fragment_sets.max(1),
            max_bytes_total: config.max_fragment_bytes_total.max(1),
            timeout: Duration::from_secs(config.fragment_timeout_secs.max(1)),
            counters: DefragCounters::default(),
            last_sweep: None,
        }
    }

    /// Running totals.
    #[must_use]
    pub fn counters(&self) -> DefragCounters {
        self.counters
    }

    /// Datagrams currently part-assembled.
    #[must_use]
    pub fn active_sets(&self) -> usize {
        self.sets.len()
    }

    /// Bytes currently held across all part-assembled datagrams.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.sets
            .values()
            .map(|set| set.buffer.buffered_bytes())
            .sum()
    }

    /// Maximum datagrams that can be part-assembled at once.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.max_sets
    }

    /// Offer a fragment. Returns the datagram once the last piece arrives.
    pub fn push(
        &mut self,
        fragment: &FragmentView<'_>,
        now: SystemTime,
        policy: OverlapPolicy,
    ) -> Option<Reassembled> {
        self.counters.fragments += 1;
        self.maybe_sweep(now);

        let offset = u64::from(fragment.offset) * 8;
        let end = offset.saturating_add(fragment.payload.len() as u64);

        // A datagram cannot exceed 65535 bytes. A fragment claiming otherwise
        // is not a real datagram being split, it is an attempt to make the
        // sensor allocate for one.
        if end > MAX_DATAGRAM_LEN {
            self.counters.oversized += 1;
            return None;
        }

        // Every fragment but the last must be a multiple of 8 bytes. Stacks
        // disagree about what to do with one that is not, which makes it an
        // ambiguity worth counting.
        if fragment.more_fragments
            && !fragment.payload.is_empty()
            && fragment.payload.len() % 8 != 0
        {
            self.counters.misaligned += 1;
        }

        let key = FragmentKey {
            source: fragment.source,
            destination: fragment.destination,
            identification: fragment.identification,
            protocol: fragment.protocol,
        };

        if !self.sets.contains_key(&key) {
            self.make_room(now);
            self.counters.started += 1;
            self.sets.insert(
                key,
                FragmentSet {
                    buffer: RangeBuffer::new(0, MAX_DATAGRAM_LEN as usize, MAX_HOLES_PER_DATAGRAM),
                    first_seen: now,
                    last_seen: now,
                    total_len: None,
                    fragments: 0,
                    conflicting_bytes: 0,
                    source: fragment.source,
                    destination: fragment.destination,
                    protocol: fragment.protocol,
                },
            );
        }

        let set = self.sets.get_mut(&key)?;
        set.fragments += 1;
        if now > set.last_seen {
            set.last_seen = now;
        }

        let outcome = set.buffer.write(offset, fragment.payload, policy);
        self.counters.overlaps += outcome.overlapped;
        self.counters.conflicting_overlaps += outcome.conflicting;
        self.counters.refused_bytes += outcome.refused;
        set.conflicting_bytes += outcome.conflicting;

        if !fragment.more_fragments {
            // The final fragment fixes the datagram's length. A second,
            // contradicting "final" fragment is an evasion attempt; the first
            // claim is kept, matching the policy of not letting later data
            // rewrite an earlier decision.
            set.total_len.get_or_insert(end);
        }

        let complete = set
            .total_len
            .is_some_and(|total| set.buffer.contiguous_end() >= total);
        if !complete {
            return None;
        }

        let mut set = self.sets.remove(&key)?;
        let total = set.total_len.unwrap_or_default();
        let mut data = Vec::with_capacity(total as usize);
        set.buffer.drain_contiguous_upto(total, &mut data);

        self.counters.completed += 1;
        Some(Reassembled {
            source: set.source,
            destination: set.destination,
            protocol: set.protocol,
            data,
            fragments: set.fragments,
            conflicting_bytes: set.conflicting_bytes,
        })
    }

    fn maybe_sweep(&mut self, now: SystemTime) {
        let due = match self.last_sweep {
            None => true,
            Some(last) => now
                .duration_since(last)
                .is_ok_and(|elapsed| elapsed >= SWEEP_INTERVAL),
        };
        if due {
            self.sweep(now);
        }
    }

    /// Discard fragment sets that have been incomplete for too long.
    pub fn sweep(&mut self, now: SystemTime) {
        self.last_sweep = Some(now);
        let timeout = self.timeout;
        let before = self.sets.len();
        self.sets.retain(|_, set| {
            let idle = now.duration_since(set.last_seen).unwrap_or_default();
            idle < timeout
        });
        self.counters.timed_out += (before - self.sets.len()) as u64;
    }

    /// Make room for one more datagram.
    fn make_room(&mut self, now: SystemTime) {
        if self.sets.len() < self.max_sets && self.buffered_bytes() < self.max_bytes_total {
            return;
        }

        // Timeouts first: dropping something already dead costs no visibility.
        self.sweep(now);
        if self.sets.len() < self.max_sets && self.buffered_bytes() < self.max_bytes_total {
            return;
        }

        // Still over: evict the oldest. This is where a fragment flood starts
        // costing coverage, so it is counted rather than absorbed quietly.
        let batch = (self.max_sets / 10).max(1);
        let mut by_age: Vec<(SystemTime, FragmentKey)> = self
            .sets
            .iter()
            .map(|(key, set)| (set.first_seen, *key))
            .collect();
        by_age.sort_unstable_by_key(|(first_seen, _)| *first_seen);

        for (_, key) in by_age.into_iter().take(batch) {
            if self.sets.remove(&key).is_some() {
                self.counters.evicted += 1;
            }
        }

        tracing::warn!(
            evicted = batch,
            capacity = self.max_sets,
            "IP fragment table full; discarding partly assembled datagrams — \
             an attack could be inside one of them"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use OverlapPolicy::{First, Last};

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn config() -> ReassemblyConfig {
        ReassemblyConfig {
            max_fragment_sets: 16,
            max_fragment_bytes_total: 1 << 20,
            fragment_timeout_secs: 30,
            ..ReassemblyConfig::default()
        }
    }

    fn fragment<'a>(
        identification: u32,
        offset: u16,
        more: bool,
        payload: &'a [u8],
    ) -> FragmentView<'a> {
        FragmentView {
            source: ip("192.0.2.1"),
            destination: ip("198.51.100.1"),
            identification,
            protocol: 17,
            offset,
            more_fragments: more,
            payload,
        }
    }

    #[test]
    fn reassembles_fragments_arriving_in_order() {
        let mut defrag = Defragmenter::new(&config());
        assert!(defrag
            .push(&fragment(1, 0, true, b"ATTACK--"), at(0), First)
            .is_none());
        let done = defrag
            .push(&fragment(1, 1, false, b"STRING"), at(0), First)
            .expect("the last fragment completes the datagram");

        assert_eq!(done.data, b"ATTACK--STRING");
        assert_eq!(done.fragments, 2);
        assert_eq!(defrag.active_sets(), 0, "a completed set is released");
        assert_eq!(defrag.counters().completed, 1);
    }

    #[test]
    fn reassembles_fragments_arriving_out_of_order() {
        // Offsets are in 8-byte units, so every fragment but the last carries a
        // multiple of 8 bytes — as the wire format requires.
        let mut defrag = Defragmenter::new(&config());
        // The final fragment first: the length is known before the middle.
        assert!(defrag
            .push(&fragment(2, 2, false, b"G"), at(0), First)
            .is_none());
        assert!(defrag
            .push(&fragment(2, 1, true, b"RT-STRIN"), at(0), First)
            .is_none());
        let done = defrag
            .push(&fragment(2, 0, true, b"ATTACKPA"), at(0), First)
            .expect("the datagram completes when the hole fills");

        assert_eq!(done.data, b"ATTACKPART-STRING");
    }

    #[test]
    fn a_string_split_across_many_fragments_reassembles_whole() {
        let message: Vec<u8> = (0..64u8).flat_map(|i| [b'A' + (i % 26), b'-']).collect();
        let mut defrag = Defragmenter::new(&config());

        let chunk = 8;
        let chunks: Vec<&[u8]> = message.chunks(chunk).collect();
        let mut done = None;
        // Reverse order, to prove ordering is irrelevant.
        for (index, piece) in chunks.iter().enumerate().rev() {
            let last = index == chunks.len() - 1;
            let result = defrag.push(
                &fragment(3, (index * chunk / 8) as u16, !last, piece),
                at(0),
                First,
            );
            if result.is_some() {
                done = result;
            }
        }
        assert_eq!(done.expect("completed").data, message);
    }

    #[test]
    fn different_identifications_are_different_datagrams() {
        let mut defrag = Defragmenter::new(&config());
        defrag.push(&fragment(10, 0, true, b"AAAAAAAA"), at(0), First);
        defrag.push(&fragment(11, 0, true, b"BBBBBBBB"), at(0), First);
        assert_eq!(defrag.active_sets(), 2);

        let first = defrag
            .push(&fragment(10, 1, false, b"aaa"), at(0), First)
            .unwrap();
        assert_eq!(first.data, b"AAAAAAAAaaa");
        assert_eq!(defrag.active_sets(), 1);
    }

    // -----------------------------------------------------------------------
    // overlap policy
    // -----------------------------------------------------------------------

    #[test]
    fn overlapping_fragments_that_disagree_resolve_by_policy() {
        for (policy, expected) in [(First, &b"AAAAAAAAxx"[..]), (Last, &b"AAAAAAAABB"[..])] {
            let mut defrag = Defragmenter::new(&config());
            defrag.push(&fragment(1, 0, true, b"AAAAAAAA"), at(0), policy);
            defrag.push(&fragment(1, 1, true, b"xxxxxxxx"), at(0), policy);
            // Re-sends offset 8 with different content, then completes.
            defrag.push(&fragment(1, 1, true, b"BBxxxxxx"), at(0), policy);
            let done = defrag
                .push(&fragment(1, 2, false, b""), at(0), policy)
                .expect("completed");

            assert_eq!(&done.data[..10], expected, "policy {policy:?}");
            assert!(
                done.conflicting_bytes > 0,
                "the disagreement must be visible"
            );
        }
    }

    #[test]
    fn an_identical_retransmitted_fragment_is_not_a_conflict() {
        let mut defrag = Defragmenter::new(&config());
        defrag.push(&fragment(1, 0, true, b"AAAAAAAA"), at(0), First);
        defrag.push(&fragment(1, 0, true, b"AAAAAAAA"), at(0), First);
        let done = defrag
            .push(&fragment(1, 1, false, b"end"), at(0), First)
            .unwrap();

        assert_eq!(done.data, b"AAAAAAAAend");
        assert_eq!(done.conflicting_bytes, 0);
        assert!(
            defrag.counters().overlaps > 0,
            "the overlap is still counted"
        );
    }

    #[test]
    fn a_second_contradicting_final_fragment_does_not_rewrite_the_length() {
        let mut defrag = Defragmenter::new(&config());
        defrag.push(&fragment(1, 0, true, b"AAAAAAAA"), at(0), First);
        // Claims the datagram ends at 11 bytes.
        let done = defrag.push(&fragment(1, 1, false, b"end"), at(0), First);
        assert_eq!(done.expect("completed").data, b"AAAAAAAAend");
    }

    // -----------------------------------------------------------------------
    // malformed and hostile input
    // -----------------------------------------------------------------------

    #[test]
    fn an_oversized_datagram_is_refused_not_allocated() {
        let mut defrag = Defragmenter::new(&config());
        // Offset 8190 * 8 = 65520, plus 64 bytes, is past the 65535 limit.
        let result = defrag.push(&fragment(1, 8_190, false, &[0u8; 64]), at(0), First);
        assert!(result.is_none());
        assert_eq!(defrag.counters().oversized, 1);
        assert_eq!(
            defrag.active_sets(),
            0,
            "nothing should have been allocated"
        );
    }

    #[test]
    fn a_misaligned_non_final_fragment_is_counted() {
        let mut defrag = Defragmenter::new(&config());
        // 5 bytes with more-fragments set violates the 8-byte rule.
        defrag.push(&fragment(1, 0, true, b"AAAAA"), at(0), First);
        assert_eq!(defrag.counters().misaligned, 1);
    }

    #[test]
    fn a_datagram_that_never_completes_is_dropped_on_timeout() {
        let mut defrag = Defragmenter::new(&config());
        defrag.push(&fragment(1, 0, true, b"AAAAAAAA"), at(0), First);
        assert_eq!(defrag.active_sets(), 1);

        defrag.sweep(at(10));
        assert_eq!(defrag.active_sets(), 1, "still inside the timeout");

        defrag.sweep(at(31));
        assert_eq!(defrag.active_sets(), 0);
        assert_eq!(defrag.counters().timed_out, 1);
    }

    /// The DoS property: an attacker sending first-fragments that never
    /// complete must not grow sensor memory without limit.
    #[test]
    fn a_fragment_flood_cannot_exceed_the_set_cap() {
        let mut defrag = Defragmenter::new(&ReassemblyConfig {
            max_fragment_sets: 32,
            fragment_timeout_secs: 3_600,
            ..config()
        });

        for identification in 0..10_000u32 {
            defrag.push(
                &fragment(identification, 0, true, &[0u8; 512]),
                at(0),
                First,
            );
            assert!(
                defrag.active_sets() <= 32,
                "grew to {} sets",
                defrag.active_sets()
            );
        }
        assert!(defrag.counters().evicted > 0, "evictions must be counted");
    }

    #[test]
    fn a_flood_of_holes_within_one_datagram_stays_bounded() {
        // One identification, fragments at scattered offsets that never
        // complete: bounded by the per-datagram hole cap.
        let mut defrag = Defragmenter::new(&config());
        for offset in (0..8_000u16).step_by(2) {
            defrag.push(&fragment(1, offset, true, b"AAAAAAAA"), at(0), First);
        }
        assert_eq!(defrag.active_sets(), 1);
        assert!(
            defrag.buffered_bytes() <= MAX_DATAGRAM_LEN as usize,
            "one datagram held {} bytes",
            defrag.buffered_bytes()
        );
        assert!(defrag.counters().refused_bytes > 0);
    }

    #[test]
    fn the_total_byte_cap_forces_eviction() {
        let mut defrag = Defragmenter::new(&ReassemblyConfig {
            max_fragment_sets: 10_000,
            max_fragment_bytes_total: 8_192,
            fragment_timeout_secs: 3_600,
            ..config()
        });
        for identification in 0..64u32 {
            defrag.push(
                &fragment(identification, 0, true, &[0u8; 1_024]),
                at(0),
                First,
            );
        }
        assert!(
            defrag.buffered_bytes() <= 8_192 * 2,
            "held {} bytes against an 8192 cap",
            defrag.buffered_bytes()
        );
        assert!(defrag.counters().evicted > 0);
    }

    #[test]
    fn an_empty_fragment_does_not_break_anything() {
        let mut defrag = Defragmenter::new(&config());
        assert!(defrag
            .push(&fragment(1, 0, true, b""), at(0), First)
            .is_none());
        let done = defrag.push(&fragment(1, 0, false, b"only"), at(0), First);
        assert_eq!(done.expect("completed").data, b"only");
    }

    #[test]
    fn a_single_unfragmented_looking_piece_completes_immediately() {
        let mut defrag = Defragmenter::new(&config());
        let done = defrag
            .push(&fragment(1, 0, false, b"whole datagram"), at(0), First)
            .expect("a lone final fragment is a complete datagram");
        assert_eq!(done.data, b"whole datagram");
        assert_eq!(done.fragments, 1);
    }
}
