//! Fuzz IP defragmentation and TCP stream reassembly.
//!
//! Reassembly decides what the detection engine will see. Guide §6 names it the
//! evasion-resistance core, and its two failure modes are both silent:
//! reassembling *differently from the destination host*, and holding more state
//! than it is allowed to.
//!
//! So this asserts more than absence of panics:
//!
//! * **bounds** — the buffers an attacker fills must stay inside their caps,
//!   whatever order and whatever offsets the fragments and segments use;
//! * **a first-wins oracle** — under [`OverlapPolicy::First`], any byte
//!   delivered at a given offset must equal the *first* byte ever written
//!   there. The oracle is a plain map built independently of the reassembler,
//!   so a bug in the overlap logic cannot hide behind the same bug in the check.

#![no_main]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};

use cybersentinel_common::config::{OverlapPolicy, ReassemblyConfig};
use cybersentinel_reassembly::defrag::{Defragmenter, FragmentView, MAX_DATAGRAM_LEN};
use cybersentinel_reassembly::range_buffer::RangeBuffer;
use cybersentinel_reassembly::stream::{StreamPair, StreamReady, TcpSegment};
use libfuzzer_sys::fuzz_target;

/// Reads structured values out of the fuzzer's byte string.
struct Input<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Input<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn exhausted(&self) -> bool {
        self.position >= self.data.len()
    }

    fn byte(&mut self) -> u8 {
        let value = self.data.get(self.position).copied().unwrap_or(0);
        self.position += 1;
        value
    }

    fn u16(&mut self) -> u16 {
        u16::from(self.byte()) << 8 | u16::from(self.byte())
    }

    fn u32(&mut self) -> u32 {
        u32::from(self.u16()) << 16 | u32::from(self.u16())
    }

    /// Up to `max` bytes of payload.
    fn slice(&mut self, max: usize) -> &'a [u8] {
        let want = usize::from(self.byte()).min(max);
        let start = self.position.min(self.data.len());
        let end = (start + want).min(self.data.len());
        self.position = end;
        &self.data[start..end]
    }
}

const BYTE_LIMIT: usize = 4_096;
const RANGE_LIMIT: usize = 32;

fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    match input.byte() % 3 {
        0 => fuzz_range_buffer(&mut input),
        1 => fuzz_defragmenter(&mut input),
        _ => fuzz_stream(&mut input),
    }
});

/// The shared primitive, with a first-wins oracle.
fn fuzz_range_buffer(input: &mut Input<'_>) {
    let mut buffer = RangeBuffer::new(0, BYTE_LIMIT, RANGE_LIMIT);
    let mut oracle: BTreeMap<u64, u8> = BTreeMap::new();
    let mut delivered_upto = 0u64;
    let mut delivered = Vec::new();

    while !input.exhausted() {
        match input.byte() % 4 {
            0..=2 => {
                let offset = u64::from(input.u16());
                let payload = input.slice(128);
                let outcome = buffer.write(offset, payload, OverlapPolicy::First);

                // Mirror only what the buffer said it stored, at the offsets it
                // said it stored them: first write to an offset wins.
                if outcome.accepted > 0 {
                    for (index, byte) in payload.iter().enumerate() {
                        let at = offset + index as u64;
                        if at >= delivered_upto && at < delivered_upto + BYTE_LIMIT as u64 {
                            oracle.entry(at).or_insert(*byte);
                        }
                    }
                }
            }
            _ => {
                let before = delivered.len();
                buffer.drain_contiguous(&mut delivered);
                for (index, byte) in delivered[before..].iter().enumerate() {
                    let at = delivered_upto + index as u64;
                    if let Some(expected) = oracle.get(&at) {
                        assert_eq!(
                            byte, expected,
                            "byte at offset {at} was delivered as {byte} but first written as {expected}"
                        );
                    }
                }
                delivered_upto += (delivered.len() - before) as u64;
            }
        }

        assert!(
            buffer.buffered_bytes() <= BYTE_LIMIT,
            "buffered {} bytes against a {BYTE_LIMIT} cap",
            buffer.buffered_bytes()
        );
        assert!(
            buffer.range_count() <= RANGE_LIMIT,
            "tracked {} ranges against a {RANGE_LIMIT} cap",
            buffer.range_count()
        );
        assert!(buffer.contiguous_end() >= buffer.base());
        assert!(buffer.covered_end() >= buffer.base());
    }
}

fn fuzz_defragmenter(input: &mut Input<'_>) {
    let config = ReassemblyConfig {
        max_fragment_sets: 8,
        max_fragment_bytes_total: 1 << 16,
        fragment_timeout_secs: 30,
        ..ReassemblyConfig::default()
    };
    let mut defrag = Defragmenter::new(&config);
    let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let destination = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let mut clock = 0u64;

    while !input.exhausted() {
        let control = input.byte();
        let policy = if control & 1 == 0 {
            OverlapPolicy::First
        } else {
            OverlapPolicy::Last
        };
        clock += u64::from(control >> 6);

        let fragment = FragmentView {
            source,
            destination,
            identification: u32::from(input.byte() % 4),
            protocol: 17,
            offset: input.u16() % 512,
            more_fragments: control & 2 != 0,
            payload: input.slice(256),
        };

        if let Some(done) = defrag.push(
            &fragment,
            SystemTime::UNIX_EPOCH + Duration::from_secs(clock),
            policy,
        ) {
            assert!(
                done.data.len() as u64 <= MAX_DATAGRAM_LEN,
                "a reassembled datagram exceeded the maximum"
            );
        }

        assert!(
            defrag.active_sets() <= defrag.capacity(),
            "{} fragment sets against a {} cap",
            defrag.active_sets(),
            defrag.capacity()
        );
        assert!(
            defrag.buffered_bytes() <= defrag.capacity() * MAX_DATAGRAM_LEN as usize,
            "fragment buffers grew past what the set cap allows"
        );
    }
}

fn fuzz_stream(input: &mut Input<'_>) {
    let per_flow = 2_048;
    let config = ReassemblyConfig {
        max_stream_bytes_per_flow: per_flow,
        max_stream_bytes_total: 1 << 20,
        delivery_flush_bytes: 512,
        ..ReassemblyConfig::default()
    };
    let mut pair = StreamPair::new(&config);
    let mut ready = StreamReady::default();

    // First-wins oracle, keyed on sequence number rather than stream offset so
    // it needs no knowledge of how the reassembler anchors its window.
    let mut oracle: BTreeMap<u32, u8> = BTreeMap::new();
    let mut to_server_delivered = 0usize;
    let mut to_client_delivered = 0usize;

    let base_sequence = input.u32();

    while !input.exhausted() {
        let control = input.byte();
        let to_server = control & 1 == 0;
        // Sequences stay near the base so segments land in the window often
        // enough to exercise the interesting paths.
        let sequence = base_sequence.wrapping_add(u32::from(input.u16()) % 4_096);
        let payload = input.slice(128);

        if to_server {
            for (index, byte) in payload.iter().enumerate() {
                oracle
                    .entry(sequence.wrapping_add(index as u32))
                    .or_insert(*byte);
            }
        }

        ready.clear();
        pair.push(
            to_server,
            &TcpSegment {
                sequence,
                acknowledgment: input.u32(),
                flags: control >> 1,
                payload,
            },
            OverlapPolicy::First,
            OverlapPolicy::First,
            &mut ready,
        );

        to_server_delivered += ready.to_server.len();
        to_client_delivered += ready.to_client.len();

        assert!(
            pair.buffered_bytes() <= per_flow * 2,
            "buffered {} bytes across two directions against a {per_flow} per-direction cap",
            pair.buffered_bytes()
        );

        let counters = pair.counters();
        assert!(
            counters.bytes_delivered as usize >= to_server_delivered + to_client_delivered,
            "delivered byte counter disagrees with the bytes handed back"
        );
        assert!(
            counters.conflicting_overlaps <= counters.overlaps,
            "conflicting overlaps cannot exceed overlaps"
        );
    }

    ready.clear();
    pair.flush(&mut ready);
    assert_eq!(
        pair.buffered_bytes(),
        0,
        "flushing must release every buffered byte"
    );
}
