//! A bounded byte buffer addressed by absolute offset, with overlap policy.
//!
//! Both halves of reassembly need the same thing: accept byte ranges that
//! arrive out of order, possibly overlapping and possibly *disagreeing*, decide
//! which copy wins, and hand back the contiguous prefix once it is complete.
//! IP defragmentation addresses it by fragment offset; TCP stream reassembly
//! addresses it by sequence number. One implementation serves both, which means
//! one place to get the overlap rules right and one thing to fuzz.
//!
//! # Overlap is the evasion surface
//!
//! When two copies of the same byte range arrive with **different contents**,
//! the sensor must resolve them the way the destination host will. Getting it
//! wrong is silent: the sensor scans one payload while the host executes
//! another. So [`WriteOutcome::conflicting`] counts bytes that actually
//! disagreed — not merely bytes that arrived twice — because a plain
//! retransmission is normal and a *contradicting* one is not.
//!
//! # Bounded twice over
//!
//! An attacker chooses the offsets, so both the bytes held and the number of
//! holes are capped. The byte cap alone is not enough: a flood of one-byte
//! segments at alternating offsets would hold few bytes but an unbounded number
//! of gap descriptors, which is the same denial of service wearing a different
//! hat.

use cybersentinel_common::config::OverlapPolicy;
use std::ops::Range;

/// What a write did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriteOutcome {
    /// Bytes written into space that was not covered before.
    pub accepted: u64,
    /// Bytes that landed on already-covered space, agreeing or not.
    pub overlapped: u64,
    /// Of the overlapping bytes, how many **disagreed** with what was there.
    ///
    /// Non-zero means two copies of the same offset carried different data.
    /// That is either a badly broken stack or somebody trying to show the
    /// sensor and the host different things.
    pub conflicting: u64,
    /// Bytes that overwrote existing data because the policy is
    /// [`OverlapPolicy::Last`].
    pub replaced: u64,
    /// Bytes refused because the buffer is at its byte or range cap.
    pub refused: u64,
    /// Bytes addressed below the window, i.e. already delivered and gone.
    pub before_window: u64,
}

impl WriteOutcome {
    /// Whether anything was refused or dropped rather than stored.
    #[must_use]
    pub fn lost_data(&self) -> bool {
        self.refused > 0
    }
}

/// A bounded buffer of byte ranges at absolute offsets.
#[derive(Debug)]
pub struct RangeBuffer {
    /// Absolute offset of `data[0]`. Everything below this has been consumed.
    base: u64,
    data: Vec<u8>,
    /// Sorted, disjoint, non-touching absolute ranges that hold real data.
    covered: Vec<Range<u64>>,
    byte_limit: usize,
    range_limit: usize,
}

impl RangeBuffer {
    /// Create a buffer whose window starts at `base`.
    ///
    /// `byte_limit` caps stored bytes; `range_limit` caps the number of
    /// disjoint covered ranges, which is what stops a flood of scattered
    /// one-byte writes from costing unbounded bookkeeping.
    #[must_use]
    pub fn new(base: u64, byte_limit: usize, range_limit: usize) -> Self {
        Self {
            base,
            data: Vec::new(),
            covered: Vec::new(),
            byte_limit: byte_limit.max(1),
            range_limit: range_limit.max(1),
        }
    }

    /// Absolute offset of the start of the window.
    #[must_use]
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Bytes currently held.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.covered
            .iter()
            .map(|range| (range.end - range.start) as usize)
            .sum()
    }

    /// Number of disjoint covered ranges — one more than the number of holes.
    #[must_use]
    pub fn range_count(&self) -> usize {
        self.covered.len()
    }

    /// Whether nothing is buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.covered.is_empty()
    }

    /// The end of the contiguous run starting at [`RangeBuffer::base`].
    ///
    /// Equal to `base` when the very next byte is missing.
    #[must_use]
    pub fn contiguous_end(&self) -> u64 {
        match self.covered.first() {
            Some(first) if first.start == self.base => first.end,
            _ => self.base,
        }
    }

    /// Highest offset any stored byte reaches.
    #[must_use]
    pub fn covered_end(&self) -> u64 {
        self.covered.last().map_or(self.base, |range| range.end)
    }

    /// Write `bytes` at absolute `offset`, resolving overlaps by `policy`.
    pub fn write(&mut self, offset: u64, bytes: &[u8], policy: OverlapPolicy) -> WriteOutcome {
        let mut outcome = WriteOutcome::default();
        if bytes.is_empty() {
            return outcome;
        }

        let end = offset.saturating_add(bytes.len() as u64);

        // Entirely behind the window: these bytes have already been delivered
        // and cannot be revised. Counted, not stored.
        if end <= self.base {
            outcome.before_window = bytes.len() as u64;
            return outcome;
        }

        // Partially behind: trim the consumed prefix.
        let (offset, bytes) = if offset < self.base {
            let skip = (self.base - offset) as usize;
            outcome.before_window = skip as u64;
            (self.base, &bytes[skip..])
        } else {
            (offset, bytes)
        };

        // Past the byte cap: refuse the tail rather than growing.
        let window_end = self.base.saturating_add(self.byte_limit as u64);
        if offset >= window_end {
            outcome.refused = bytes.len() as u64;
            return outcome;
        }
        // Saturating throughout: the offset comes off the wire, so a sequence
        // number near the top of the range must clamp rather than wrap into a
        // small number and land somewhere it was never addressed to.
        let bytes = if offset.saturating_add(bytes.len() as u64) > window_end {
            let keep = (window_end - offset) as usize;
            outcome.refused = (bytes.len() - keep) as u64;
            &bytes[..keep]
        } else {
            bytes
        };
        if bytes.is_empty() {
            return outcome;
        }
        let end = offset.saturating_add(bytes.len() as u64);

        // Range cap: a write that cannot merge with anything would add a new
        // descriptor. Refuse it rather than track unbounded holes.
        if self.covered.len() >= self.range_limit && !self.touches_existing(offset, end) {
            outcome.refused += bytes.len() as u64;
            return outcome;
        }

        let needed = (end - self.base) as usize;
        if self.data.len() < needed {
            self.data.resize(needed, 0);
        }

        // Walk the write range, alternating between covered and uncovered
        // stretches, so policy is applied exactly where data already exists.
        let mut cursor = offset;
        for existing in self.covered.clone() {
            if existing.end <= cursor {
                continue;
            }
            if existing.start >= end {
                break;
            }
            // Uncovered gap before this range.
            if cursor < existing.start {
                let gap_end = existing.start.min(end);
                self.copy_in(cursor, gap_end, offset, bytes);
                outcome.accepted += gap_end - cursor;
                cursor = gap_end;
            }
            // Overlapping stretch.
            let overlap_end = existing.end.min(end);
            if cursor < overlap_end {
                let differing = self.count_differing(cursor, overlap_end, offset, bytes);
                outcome.overlapped += overlap_end - cursor;
                outcome.conflicting += differing;
                if policy == OverlapPolicy::Last {
                    self.copy_in(cursor, overlap_end, offset, bytes);
                    outcome.replaced += differing;
                }
                cursor = overlap_end;
            }
        }
        if cursor < end {
            self.copy_in(cursor, end, offset, bytes);
            outcome.accepted += end - cursor;
        }

        self.mark_covered(offset, end);
        outcome
    }

    /// Copy `[from, to)` of the write into the buffer.
    fn copy_in(&mut self, from: u64, to: u64, write_offset: u64, bytes: &[u8]) {
        let source_start = (from - write_offset) as usize;
        let source_end = (to - write_offset) as usize;
        let target_start = (from - self.base) as usize;
        let target_end = (to - self.base) as usize;
        self.data[target_start..target_end].copy_from_slice(&bytes[source_start..source_end]);
    }

    /// How many bytes of `[from, to)` differ between the buffer and the write.
    fn count_differing(&self, from: u64, to: u64, write_offset: u64, bytes: &[u8]) -> u64 {
        let source_start = (from - write_offset) as usize;
        let source_end = (to - write_offset) as usize;
        let target_start = (from - self.base) as usize;
        let target_end = (to - self.base) as usize;
        self.data[target_start..target_end]
            .iter()
            .zip(&bytes[source_start..source_end])
            .filter(|(existing, incoming)| existing != incoming)
            .count() as u64
    }

    /// Whether `[start, end)` touches or overlaps any covered range.
    fn touches_existing(&self, start: u64, end: u64) -> bool {
        self.covered
            .iter()
            .any(|range| range.end >= start && range.start <= end)
    }

    /// Insert `[start, end)` into the coverage list, merging neighbours.
    fn mark_covered(&mut self, start: u64, end: u64) {
        let mut merged = Range { start, end };
        let mut out = Vec::with_capacity(self.covered.len() + 1);
        let mut inserted = false;

        for range in self.covered.drain(..) {
            if range.end < merged.start {
                out.push(range);
            } else if range.start > merged.end {
                if !inserted {
                    out.push(merged.clone());
                    inserted = true;
                }
                out.push(range);
            } else {
                // Touching or overlapping: absorb.
                merged.start = merged.start.min(range.start);
                merged.end = merged.end.max(range.end);
            }
        }
        if !inserted {
            out.push(merged);
        }
        self.covered = out;
    }

    /// Move the contiguous prefix, up to `limit`, into `out`.
    ///
    /// Returns how many bytes moved. The window advances past them, so they can
    /// never be revised afterwards — which is exactly why the caller decides
    /// *when* data is settled enough to take.
    pub fn drain_contiguous_upto(&mut self, limit: u64, out: &mut Vec<u8>) -> usize {
        let end = self.contiguous_end().min(limit);
        if end <= self.base {
            return 0;
        }
        let count = (end - self.base) as usize;
        out.extend_from_slice(&self.data[..count]);
        self.consume(count);
        count
    }

    /// Move the whole contiguous prefix into `out`.
    pub fn drain_contiguous(&mut self, out: &mut Vec<u8>) -> usize {
        self.drain_contiguous_upto(u64::MAX, out)
    }

    /// Drop `count` bytes from the front of the window.
    fn consume(&mut self, count: usize) {
        self.data.drain(..count);
        self.base += count as u64;
        self.covered.retain_mut(|range| {
            range.start = range.start.max(self.base);
            range.end > self.base
        });
    }

    /// Discard everything and restart the window at `base`.
    pub fn reset(&mut self, base: u64) {
        self.data.clear();
        self.covered.clear();
        self.base = base;
    }

    /// A view of the contiguous prefix without consuming it.
    #[must_use]
    pub fn peek_contiguous(&self) -> &[u8] {
        let count = (self.contiguous_end() - self.base) as usize;
        &self.data[..count.min(self.data.len())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use OverlapPolicy::{First, Last};

    fn buffer() -> RangeBuffer {
        RangeBuffer::new(0, 4_096, 64)
    }

    fn drained(buffer: &mut RangeBuffer) -> Vec<u8> {
        let mut out = Vec::new();
        buffer.drain_contiguous(&mut out);
        out
    }

    #[test]
    fn writes_in_order_and_delivers_contiguously() {
        let mut buffer = buffer();
        buffer.write(0, b"ATTACK", First);
        buffer.write(6, b"STRING", First);
        assert_eq!(buffer.contiguous_end(), 12);
        assert_eq!(drained(&mut buffer), b"ATTACKSTRING");
        assert!(buffer.is_empty());
        assert_eq!(buffer.base(), 12);
    }

    #[test]
    fn out_of_order_writes_are_held_until_the_gap_fills() {
        let mut buffer = buffer();
        buffer.write(6, b"STRING", First);
        assert_eq!(buffer.contiguous_end(), 0, "a leading hole blocks delivery");
        assert_eq!(drained(&mut buffer), b"");

        buffer.write(0, b"ATTACK", First);
        assert_eq!(drained(&mut buffer), b"ATTACKSTRING");
    }

    #[test]
    fn a_write_spanning_a_hole_fills_it() {
        let mut buffer = buffer();
        buffer.write(0, b"AAAA", First);
        buffer.write(8, b"CCCC", First);
        assert_eq!(buffer.range_count(), 2);

        let outcome = buffer.write(4, b"BBBB", First);
        assert_eq!(outcome.accepted, 4);
        assert_eq!(buffer.range_count(), 1, "the ranges should merge");
        assert_eq!(drained(&mut buffer), b"AAAABBBBCCCC");
    }

    // -----------------------------------------------------------------------
    // overlap policy — the evasion surface
    // -----------------------------------------------------------------------

    #[test]
    fn first_policy_keeps_the_original_bytes() {
        let mut buffer = buffer();
        buffer.write(0, b"AAAA", First);
        let outcome = buffer.write(0, b"BBBB", First);

        assert_eq!(outcome.overlapped, 4);
        assert_eq!(outcome.conflicting, 4);
        assert_eq!(outcome.replaced, 0);
        assert_eq!(outcome.accepted, 0);
        assert_eq!(drained(&mut buffer), b"AAAA");
    }

    #[test]
    fn last_policy_takes_the_new_bytes() {
        let mut buffer = buffer();
        buffer.write(0, b"AAAA", Last);
        let outcome = buffer.write(0, b"BBBB", Last);

        assert_eq!(outcome.overlapped, 4);
        assert_eq!(outcome.conflicting, 4);
        assert_eq!(outcome.replaced, 4);
        assert_eq!(drained(&mut buffer), b"BBBB");
    }

    #[test]
    fn an_identical_retransmission_is_overlap_but_not_conflict() {
        // Ordinary retransmission must not look like an evasion attempt.
        let mut buffer = buffer();
        buffer.write(0, b"HELLO", First);
        let outcome = buffer.write(0, b"HELLO", First);

        assert_eq!(outcome.overlapped, 5);
        assert_eq!(outcome.conflicting, 0, "same bytes twice is not a conflict");
    }

    #[test]
    fn a_partial_overlap_splits_into_kept_and_new() {
        let mut buffer = buffer();
        buffer.write(0, b"AAAA", First);
        // Covers 2..8: two bytes overlap, four are new.
        let outcome = buffer.write(2, b"XXBBBB", First);

        assert_eq!(outcome.overlapped, 2);
        assert_eq!(outcome.conflicting, 2);
        assert_eq!(outcome.accepted, 4);
        assert_eq!(drained(&mut buffer), b"AAAABBBB");
    }

    #[test]
    fn a_partial_overlap_under_last_replaces_only_the_overlap() {
        let mut buffer = buffer();
        buffer.write(0, b"AAAA", Last);
        buffer.write(2, b"XXBBBB", Last);
        assert_eq!(drained(&mut buffer), b"AAXXBBBB");
    }

    #[test]
    fn a_write_covering_several_existing_ranges_resolves_each() {
        let mut buffer = buffer();
        buffer.write(0, b"AA", Last);
        buffer.write(4, b"CC", Last);
        // Spans covered, gap, covered.
        let outcome = buffer.write(0, b"111111", Last);

        assert_eq!(outcome.overlapped, 4);
        assert_eq!(outcome.accepted, 2, "only the gap was new");
        assert_eq!(drained(&mut buffer), b"111111");
    }

    #[test]
    fn the_same_write_under_first_keeps_every_original_stretch() {
        let mut buffer = buffer();
        buffer.write(0, b"AA", First);
        buffer.write(4, b"CC", First);
        buffer.write(0, b"111111", First);
        assert_eq!(drained(&mut buffer), b"AA11CC");
    }

    // -----------------------------------------------------------------------
    // window edges
    // -----------------------------------------------------------------------

    #[test]
    fn data_behind_the_window_is_counted_and_dropped() {
        let mut buffer = buffer();
        buffer.write(0, b"AAAA", First);
        drained(&mut buffer);
        assert_eq!(buffer.base(), 4);

        let outcome = buffer.write(0, b"BBBB", Last);
        assert_eq!(outcome.before_window, 4);
        assert_eq!(outcome.accepted, 0);
        assert!(buffer.is_empty(), "delivered bytes cannot be revised");
    }

    #[test]
    fn a_write_straddling_the_window_edge_keeps_only_the_new_part() {
        let mut buffer = buffer();
        buffer.write(0, b"AAAA", First);
        drained(&mut buffer);

        let outcome = buffer.write(2, b"XXBBBB", First);
        assert_eq!(outcome.before_window, 2);
        assert_eq!(outcome.accepted, 4);
        assert_eq!(drained(&mut buffer), b"BBBB");
    }

    #[test]
    fn delivery_can_be_limited_to_settled_data() {
        // The caller decides how far to deliver; the rest stays revisable.
        let mut buffer = buffer();
        buffer.write(0, b"ATTACKSTRING", First);

        let mut out = Vec::new();
        assert_eq!(buffer.drain_contiguous_upto(6, &mut out), 6);
        assert_eq!(out, b"ATTACK");
        assert_eq!(buffer.base(), 6);

        // The undelivered remainder can still be overwritten.
        buffer.write(6, b"ZZZZZZ", Last);
        assert_eq!(drained(&mut buffer), b"ZZZZZZ");
    }

    // -----------------------------------------------------------------------
    // bounds — an attacker chooses the offsets
    // -----------------------------------------------------------------------

    #[test]
    fn the_byte_cap_refuses_rather_than_grows() {
        let mut buffer = RangeBuffer::new(0, 16, 64);
        let outcome = buffer.write(0, &[b'x'; 64], First);
        assert_eq!(outcome.accepted, 16);
        assert_eq!(outcome.refused, 48);
        assert!(outcome.lost_data());
        assert_eq!(buffer.buffered_bytes(), 16);
    }

    #[test]
    fn a_write_entirely_past_the_byte_cap_is_refused_whole() {
        let mut buffer = RangeBuffer::new(0, 16, 64);
        let outcome = buffer.write(1_000_000, b"far away", First);
        assert_eq!(outcome.refused, 8);
        assert!(buffer.is_empty());
    }

    #[test]
    fn a_flood_of_scattered_writes_cannot_grow_the_range_list() {
        // Few bytes, unbounded holes: the byte cap alone would not stop this.
        let mut buffer = RangeBuffer::new(0, 1 << 20, 32);
        let mut refused = 0;
        for i in 0..10_000u64 {
            let outcome = buffer.write(i * 4, b"x", First);
            refused += outcome.refused;
            assert!(
                buffer.range_count() <= 32,
                "range list grew to {}",
                buffer.range_count()
            );
        }
        assert!(refused > 0, "the cap must be visible to the caller");
    }

    #[test]
    fn filling_holes_frees_range_descriptors_again() {
        let mut buffer = RangeBuffer::new(0, 1 << 20, 4);
        for i in 0..4u64 {
            buffer.write(i * 2, b"a", First);
        }
        assert_eq!(buffer.range_count(), 4);
        assert_eq!(buffer.write(9, b"b", First).refused, 1, "at the cap");

        // Filling the gaps merges the ranges and makes room again.
        for i in 0..4u64 {
            buffer.write(i * 2 + 1, b"b", First);
        }
        assert_eq!(buffer.range_count(), 1);
        assert_eq!(buffer.write(9, b"c", First).accepted, 1);
    }

    #[test]
    fn offsets_near_the_integer_limit_do_not_overflow() {
        let mut buffer = RangeBuffer::new(u64::MAX - 8, 4_096, 64);
        let outcome = buffer.write(u64::MAX - 4, b"abcdefgh", First);
        // Whatever it decides, it must not panic and must stay consistent.
        assert!(outcome.accepted + outcome.refused + outcome.before_window <= 8);
        assert!(buffer.covered_end() >= buffer.base());
    }

    #[test]
    fn an_empty_write_does_nothing() {
        let mut buffer = buffer();
        assert_eq!(buffer.write(0, b"", First), WriteOutcome::default());
        assert!(buffer.is_empty());
    }

    #[test]
    fn reset_clears_everything() {
        let mut buffer = buffer();
        buffer.write(0, b"data", First);
        buffer.reset(100);
        assert!(buffer.is_empty());
        assert_eq!(buffer.base(), 100);
        assert_eq!(buffer.contiguous_end(), 100);
    }

    #[test]
    fn peek_does_not_consume() {
        let mut buffer = buffer();
        buffer.write(0, b"peek", First);
        assert_eq!(buffer.peek_contiguous(), b"peek");
        assert_eq!(buffer.peek_contiguous(), b"peek");
        assert_eq!(drained(&mut buffer), b"peek");
    }

    /// Whatever order the pieces arrive in, the delivered stream is the same.
    #[test]
    fn delivery_is_independent_of_arrival_order() {
        const CHUNK: usize = 8;
        let message = b"the quick brown fox jumps over the lazy dog";
        let chunks = message.len().div_ceil(CHUNK);
        let orders: [&[usize]; 4] = [
            &[0, 1, 2, 3, 4, 5],
            &[5, 4, 3, 2, 1, 0],
            &[2, 0, 4, 1, 5, 3],
            &[1, 3, 0, 5, 2, 4],
        ];
        for order in orders {
            assert_eq!(
                order.len(),
                chunks,
                "the order must cover the whole message"
            );
            let mut buffer = buffer();
            for &index in order {
                let start = index * CHUNK;
                let end = (start + CHUNK).min(message.len());
                buffer.write(start as u64, &message[start..end], First);
            }
            assert_eq!(drained(&mut buffer), message, "order {order:?}");
        }
    }
}
