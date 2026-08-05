//! TCP stream reassembly.
//!
//! Turning segments back into the byte stream the receiving application will
//! see. Everything here exists because the sensor and the destination host must
//! agree about what that stream contains; wherever they can be made to
//! disagree, an attack passes unseen.
//!
//! # Delivery is gated on acknowledgement
//!
//! Reassembled bytes are held until the **peer acknowledges them**, and only
//! then handed downstream.
//!
//! That is not caution for its own sake — it is what makes overlap policy mean
//! anything. A retransmission carrying different data always arrives before the
//! ACK for that range, so at the moment the sensor must choose, it still holds
//! both copies and can apply the destination's policy. A reassembler that
//! delivered bytes the instant they were contiguous could never implement
//! [`OverlapPolicy::Last`]: the first copy would already be gone.
//!
//! The fallback matters too. On a path where the reverse direction is not
//! visible — asymmetric routing, a one-way tap — no ACK ever arrives, so data
//! is flushed once `delivery_flush_bytes` has accumulated. Without it the
//! sensor would quietly stop matching on exactly the networks that are hardest
//! to monitor.
//!
//! # Where the ambiguities are resolved, and why each way round
//!
//! | Case | Behaviour | Why |
//! |---|---|---|
//! | Data on the SYN | Accepted, counted | TCP Fast Open makes it real traffic. Ignoring data a host may act on is a hole; the counter makes it visible either way |
//! | Data past the FIN | Rejected, counted | The host has closed that direction and will not act on it. Accepting it lets an attacker feed the sensor bytes the host never sees |
//! | Data filling a gap *before* the FIN | Accepted | An ordinary retransmission of something missing, not an injection |
//! | Out-of-window RST | **Ignored**, counted | Honouring a forged RST stops the sensor watching a live connection. Ignoring a real one only means a dead flow waits for its timeout — a much cheaper mistake |
//! | In-window RST | Tears down | What the host will do |
//! | Retransmission of already-delivered data | Dropped, counted | It cannot be un-delivered. Counted because a *contradicting* one is an attempt at exactly that |

use cybersentinel_common::config::{OverlapPolicy, ReassemblyConfig};

use crate::range_buffer::RangeBuffer;

/// TCP flag bits, in wire order.
pub mod flags {
    /// FIN.
    pub const FIN: u8 = 0b0000_0001;
    /// SYN.
    pub const SYN: u8 = 0b0000_0010;
    /// RST.
    pub const RST: u8 = 0b0000_0100;
    /// ACK.
    pub const ACK: u8 = 0b0001_0000;
}

/// Maximum holes tracked per direction.
const MAX_HOLES_PER_STREAM: usize = 256;

/// How far past what we have seen a reset's sequence number may be and still be
/// believed.
///
/// One un-scaled TCP receive window. The point is to tolerate the sensor having
/// missed up to a window of data while refusing a blind guess: an attacker who
/// cannot see the connection has to hit a 64 KiB target in a 4 GiB space.
/// Sizing this off the reassembly buffer instead — which is megabytes — would
/// hand them a target thousands of times larger.
const RST_SEQUENCE_SLACK: u64 = 65_535;

/// One TCP segment offered to the reassembler.
#[derive(Debug, Clone, Copy)]
pub struct TcpSegment<'a> {
    /// Sequence number of the first payload byte.
    pub sequence: u32,
    /// Acknowledgement number; meaningful only with [`flags::ACK`] set.
    pub acknowledgment: u32,
    /// Control flags.
    pub flags: u8,
    /// Segment payload.
    pub payload: &'a [u8],
}

impl TcpSegment<'_> {
    /// Whether a flag is set.
    #[must_use]
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// Bytes that became deliverable, per direction.
#[derive(Debug, Default)]
pub struct StreamReady {
    /// Newly delivered bytes travelling towards the responder.
    pub to_server: Vec<u8>,
    /// Newly delivered bytes travelling towards the initiator.
    pub to_client: Vec<u8>,
}

impl StreamReady {
    /// Forget the previous packet's output, keeping the allocations.
    pub fn clear(&mut self) {
        self.to_server.clear();
        self.to_client.clear();
    }

    /// Whether anything was delivered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.to_server.is_empty() && self.to_client.is_empty()
    }

    /// Total bytes delivered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.to_server.len() + self.to_client.len()
    }
}

/// Running totals for one direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamCounters {
    /// Segments carrying payload.
    pub segments: u64,
    /// Payload bytes stored.
    pub bytes_accepted: u64,
    /// Payload bytes handed downstream.
    pub bytes_delivered: u64,
    /// Bytes landing on already-buffered offsets.
    pub overlaps: u64,
    /// Of those, bytes that **disagreed**. The evasion signal.
    pub conflicting_overlaps: u64,
    /// Bytes refused by the per-direction byte or hole cap.
    pub refused_bytes: u64,
    /// Bytes addressed far beyond the buffer — outside any plausible window.
    pub out_of_window: u64,
    /// Bytes retransmitting data already delivered, which cannot be revised.
    pub before_window: u64,
    /// Bytes offered after the FIN, which the host will not act on.
    pub after_fin: u64,
    /// Bytes carried on a SYN.
    pub syn_data: u64,
    /// Deliveries forced by the flush threshold rather than by an ACK.
    pub flushed_unacked: u64,
    /// Buffered bytes discarded because the flow ended with a hole in it.
    pub dropped_incomplete: u64,
}

impl StreamCounters {
    /// Fold another set of counters into this one.
    pub fn merge(&mut self, other: Self) {
        self.segments += other.segments;
        self.bytes_accepted += other.bytes_accepted;
        self.bytes_delivered += other.bytes_delivered;
        self.overlaps += other.overlaps;
        self.conflicting_overlaps += other.conflicting_overlaps;
        self.refused_bytes += other.refused_bytes;
        self.out_of_window += other.out_of_window;
        self.before_window += other.before_window;
        self.after_fin += other.after_fin;
        self.syn_data += other.syn_data;
        self.flushed_unacked += other.flushed_unacked;
        self.dropped_incomplete += other.dropped_incomplete;
    }
}

/// One direction of a TCP conversation.
#[derive(Debug)]
struct Stream {
    /// Wire sequence number corresponding to `buffer.base()`.
    base_sequence: u32,
    /// Whether the sequence space has been anchored yet.
    established: bool,
    buffer: RangeBuffer,
    /// Highest absolute offset the peer has acknowledged.
    acknowledged_upto: u64,
    /// Absolute offset one past the last byte, once a FIN has been seen.
    fin_at: Option<u64>,
    byte_limit: usize,
    flush_bytes: usize,
    counters: StreamCounters,
}

impl Stream {
    fn new(byte_limit: usize, flush_bytes: usize) -> Self {
        Self {
            base_sequence: 0,
            established: false,
            buffer: RangeBuffer::new(0, byte_limit, MAX_HOLES_PER_STREAM),
            acknowledged_upto: 0,
            fin_at: None,
            byte_limit,
            flush_bytes,
            counters: StreamCounters::default(),
        }
    }

    /// Map a wire sequence number onto this stream's absolute offset space.
    ///
    /// Signed arithmetic on the wrapping difference, which is how TCP sequence
    /// comparison is defined: it stays correct across the 32-bit wrap, and a
    /// sequence behind the window yields a negative delta rather than an
    /// enormous positive one.
    fn absolute(&self, sequence: u32) -> i64 {
        let delta = sequence.wrapping_sub(self.base_sequence) as i32;
        self.buffer.base() as i64 + i64::from(delta)
    }

    /// Anchor the sequence space, if this segment can.
    fn establish(&mut self, segment: &TcpSegment<'_>) {
        if self.established {
            return;
        }
        if segment.has(flags::SYN) {
            // The SYN itself consumes one sequence number, so data starts one
            // past it.
            self.base_sequence = segment.sequence.wrapping_add(1);
            self.established = true;
        } else if !segment.payload.is_empty() {
            // Joined mid-conversation: take the first data we see as the start.
            self.base_sequence = segment.sequence;
            self.established = true;
        }
    }

    fn push(&mut self, segment: &TcpSegment<'_>, policy: OverlapPolicy) {
        self.establish(segment);
        if !self.established {
            return;
        }

        if !segment.payload.is_empty() {
            self.counters.segments += 1;
        }

        // Data riding on a SYN starts after the SYN's own sequence number.
        let sequence = if segment.has(flags::SYN) {
            if !segment.payload.is_empty() {
                self.counters.syn_data += segment.payload.len() as u64;
            }
            segment.sequence.wrapping_add(1)
        } else {
            segment.sequence
        };

        if !segment.payload.is_empty() {
            self.store(sequence, segment.payload, policy);
        }

        if segment.has(flags::FIN) {
            let fin_offset = self
                .absolute(sequence)
                .max(0)
                .saturating_add(segment.payload.len() as i64);
            let fin_at = fin_offset as u64;
            // Keep the earliest FIN: a later, higher one would let an attacker
            // reopen a direction the host has already closed.
            self.fin_at = Some(self.fin_at.map_or(fin_at, |existing| existing.min(fin_at)));
        }
    }

    fn store(&mut self, sequence: u32, payload: &[u8], policy: OverlapPolicy) {
        let offset = self.absolute(sequence);

        // Entirely behind the delivery point: already handed downstream and
        // beyond revision.
        if offset + payload.len() as i64 <= self.buffer.base() as i64 {
            self.counters.before_window += payload.len() as u64;
            return;
        }

        // Absurdly far ahead: outside any window the receiver could have
        // advertised, so the host will drop it too.
        let window_end = self.buffer.base() + self.byte_limit as u64;
        if offset < 0 || offset as u64 >= window_end {
            self.counters.out_of_window += payload.len() as u64;
            return;
        }
        let offset = offset as u64;

        // Past a FIN this direction already sent. The host has closed and will
        // not act on these bytes; accepting them would let an attacker write
        // into the sensor's view of a stream the host has stopped reading.
        if let Some(fin_at) = self.fin_at {
            if offset >= fin_at {
                self.counters.after_fin += payload.len() as u64;
                return;
            }
        }

        let outcome = self.buffer.write(offset, payload, policy);
        self.counters.bytes_accepted += outcome.accepted;
        self.counters.overlaps += outcome.overlapped;
        self.counters.conflicting_overlaps += outcome.conflicting;
        self.counters.refused_bytes += outcome.refused;
        self.counters.before_window += outcome.before_window;
    }

    /// Note that the peer has acknowledged everything below `acknowledgment`.
    fn acknowledge(&mut self, acknowledgment: u32) {
        if !self.established {
            return;
        }
        let offset = self.absolute(acknowledgment);
        if offset > 0 {
            self.acknowledged_upto = self.acknowledged_upto.max(offset as u64);
        }
    }

    /// Move settled bytes into `out`.
    fn deliver(&mut self, out: &mut Vec<u8>, force: bool) {
        let contiguous = self.buffer.contiguous_end();
        let available = contiguous.saturating_sub(self.buffer.base());

        let limit = if force {
            contiguous
        } else if available >= self.flush_bytes as u64 {
            // No ACK in sight and the buffer is filling. Deliver rather than
            // stall matching on a one-way path.
            self.counters.flushed_unacked += available;
            contiguous
        } else {
            self.acknowledged_upto.min(contiguous)
        };

        let before = out.len();
        self.buffer.drain_contiguous_upto(limit, out);
        let moved = (out.len() - before) as u64;
        self.counters.bytes_delivered += moved;

        // Advance the sequence anchor with the window so the signed mapping
        // stays centred and keeps working across the 32-bit wrap.
        self.base_sequence = self.base_sequence.wrapping_add(moved as u32);
    }

    /// Whether a RST at this sequence is one the host would act on.
    ///
    /// Deliberately generous about what counts as in-window and strict about
    /// what does not: ignoring a genuine RST costs a flow entry until its
    /// timeout, while honouring a forged one stops the sensor watching a live
    /// connection.
    fn rst_is_in_window(&self, sequence: u32) -> bool {
        if !self.established {
            return false;
        }
        let offset = self.absolute(sequence);
        offset >= 0 && (offset as u64) <= self.buffer.covered_end() + RST_SEQUENCE_SLACK
    }

    fn discard(&mut self) {
        self.counters.dropped_incomplete += self.buffer.buffered_bytes() as u64;
        let base = self.buffer.base();
        self.buffer.reset(base);
    }

    fn buffered_bytes(&self) -> usize {
        self.buffer.buffered_bytes()
    }
}

/// Both directions of one TCP conversation.
#[derive(Debug)]
pub struct StreamPair {
    to_server: Stream,
    to_client: Stream,
}

impl StreamPair {
    /// Build a pair sized by the configured per-flow limits.
    #[must_use]
    pub fn new(config: &ReassemblyConfig) -> Self {
        let byte_limit = config.max_stream_bytes_per_flow.max(1);
        let flush = config.delivery_flush_bytes.clamp(1, byte_limit);
        Self {
            to_server: Stream::new(byte_limit, flush),
            to_client: Stream::new(byte_limit, flush),
        }
    }

    /// Offer a segment.
    ///
    /// `policy_to_server` is the policy of the *responder* — the host receiving
    /// data sent towards the server — and `policy_to_client` that of the
    /// initiator. Two stacks, two policies.
    ///
    /// Newly settled bytes are appended to `ready`, which may gain data in
    /// **either** direction: an ACK travelling one way is what settles data
    /// travelling the other.
    pub fn push(
        &mut self,
        to_server: bool,
        segment: &TcpSegment<'_>,
        policy_to_server: OverlapPolicy,
        policy_to_client: OverlapPolicy,
        ready: &mut StreamReady,
    ) {
        if to_server {
            self.to_server.push(segment, policy_to_server);
            if segment.has(flags::ACK) {
                self.to_client.acknowledge(segment.acknowledgment);
            }
        } else {
            self.to_client.push(segment, policy_to_client);
            if segment.has(flags::ACK) {
                self.to_server.acknowledge(segment.acknowledgment);
            }
        }

        self.to_server.deliver(&mut ready.to_server, false);
        self.to_client.deliver(&mut ready.to_client, false);
    }

    /// Whether a RST in the given direction should tear the connection down.
    #[must_use]
    pub fn rst_should_close(&self, to_server: bool, sequence: u32) -> bool {
        let stream = if to_server {
            &self.to_server
        } else {
            &self.to_client
        };
        stream.rst_is_in_window(sequence)
    }

    /// Deliver everything still contiguous, for a flow that is ending.
    pub fn flush(&mut self, ready: &mut StreamReady) {
        self.to_server.deliver(&mut ready.to_server, true);
        self.to_client.deliver(&mut ready.to_client, true);
        self.to_server.discard();
        self.to_client.discard();
    }

    /// Bytes currently buffered across both directions.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.to_server.buffered_bytes() + self.to_client.buffered_bytes()
    }

    /// Combined counters for both directions.
    #[must_use]
    pub fn counters(&self) -> StreamCounters {
        let mut combined = self.to_server.counters;
        combined.merge(self.to_client.counters);
        combined
    }

    /// Counters for one direction.
    #[must_use]
    pub fn direction_counters(&self, to_server: bool) -> StreamCounters {
        if to_server {
            self.to_server.counters
        } else {
            self.to_client.counters
        }
    }
}

#[cfg(test)]
mod tests {
    use super::flags::{ACK, FIN, RST, SYN};
    use super::*;
    use OverlapPolicy::{First, Last};

    const CLIENT_ISN: u32 = 1_000;
    const SERVER_ISN: u32 = 5_000;

    fn config() -> ReassemblyConfig {
        ReassemblyConfig {
            max_stream_bytes_per_flow: 4_096,
            max_stream_bytes_total: 1 << 20,
            delivery_flush_bytes: 4_096,
            ..ReassemblyConfig::default()
        }
    }

    /// A harness that drives one conversation and accumulates what was
    /// delivered in each direction.
    struct Conversation {
        pair: StreamPair,
        ready: StreamReady,
        server_stream: Vec<u8>,
        client_stream: Vec<u8>,
        policy: OverlapPolicy,
    }

    impl Conversation {
        fn new(policy: OverlapPolicy) -> Self {
            Self::with_config(policy, &config())
        }

        fn with_config(policy: OverlapPolicy, config: &ReassemblyConfig) -> Self {
            Self {
                pair: StreamPair::new(config),
                ready: StreamReady::default(),
                server_stream: Vec::new(),
                client_stream: Vec::new(),
                policy,
            }
        }

        fn send(&mut self, to_server: bool, segment: TcpSegment<'_>) {
            self.ready.clear();
            self.pair.push(
                to_server,
                &segment,
                self.policy,
                self.policy,
                &mut self.ready,
            );
            self.server_stream.extend_from_slice(&self.ready.to_server);
            self.client_stream.extend_from_slice(&self.ready.to_client);
        }

        /// Client data at `offset` bytes into the client's stream.
        fn client(&mut self, offset: u32, payload: &[u8]) {
            self.send(
                true,
                TcpSegment {
                    sequence: CLIENT_ISN.wrapping_add(1).wrapping_add(offset),
                    acknowledgment: SERVER_ISN.wrapping_add(1),
                    flags: ACK,
                    payload,
                },
            );
        }

        /// Server data at `offset` bytes into the server's stream.
        fn server(&mut self, offset: u32, payload: &[u8]) {
            self.send(
                false,
                TcpSegment {
                    sequence: SERVER_ISN.wrapping_add(1).wrapping_add(offset),
                    acknowledgment: CLIENT_ISN.wrapping_add(1),
                    flags: ACK,
                    payload,
                },
            );
        }

        /// The client acknowledges `bytes` of server data.
        fn client_acks(&mut self, bytes: u32) {
            self.send(
                true,
                TcpSegment {
                    sequence: CLIENT_ISN.wrapping_add(1),
                    acknowledgment: SERVER_ISN.wrapping_add(1).wrapping_add(bytes),
                    flags: ACK,
                    payload: b"",
                },
            );
        }

        /// The server acknowledges `bytes` of client data.
        fn server_acks(&mut self, bytes: u32) {
            self.send(
                false,
                TcpSegment {
                    sequence: SERVER_ISN.wrapping_add(1),
                    acknowledgment: CLIENT_ISN.wrapping_add(1).wrapping_add(bytes),
                    flags: ACK,
                    payload: b"",
                },
            );
        }

        fn handshake(&mut self) {
            self.send(
                true,
                TcpSegment {
                    sequence: CLIENT_ISN,
                    acknowledgment: 0,
                    flags: SYN,
                    payload: b"",
                },
            );
            self.send(
                false,
                TcpSegment {
                    sequence: SERVER_ISN,
                    acknowledgment: CLIENT_ISN.wrapping_add(1),
                    flags: SYN | ACK,
                    payload: b"",
                },
            );
        }

        fn flush(&mut self) {
            self.ready.clear();
            self.pair.flush(&mut self.ready);
            self.server_stream.extend_from_slice(&self.ready.to_server);
            self.client_stream.extend_from_slice(&self.ready.to_client);
        }
    }

    // -----------------------------------------------------------------------
    // the core property: an attack split across segments comes back whole
    // -----------------------------------------------------------------------

    #[test]
    fn a_string_split_across_segments_reassembles_contiguously() {
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(0, b"GET /cgi-bin/");
        conversation.client(13, b"phf?Qalias=x%");
        conversation.client(26, b"0a/bin/cat%20/etc/passwd");
        conversation.server_acks(50);

        assert_eq!(
            conversation.server_stream,
            b"GET /cgi-bin/phf?Qalias=x%0a/bin/cat%20/etc/passwd"
        );
    }

    #[test]
    fn segments_arriving_out_of_order_still_reassemble_in_order() {
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(26, b"0a/bin/cat%20/etc/passwd");
        conversation.client(0, b"GET /cgi-bin/");
        assert!(
            conversation.server_stream.is_empty(),
            "a hole in the middle must block delivery"
        );

        conversation.client(13, b"phf?Qalias=x%");
        conversation.server_acks(50);
        assert_eq!(
            conversation.server_stream,
            b"GET /cgi-bin/phf?Qalias=x%0a/bin/cat%20/etc/passwd"
        );
    }

    #[test]
    fn both_directions_are_reassembled_independently() {
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(0, b"GET / HTTP/1.1\r\n\r\n");
        conversation.server(0, b"HTTP/1.1 200 OK\r\n");
        conversation.server(17, b"\r\nbody");
        // Each side acknowledges the other, settling both streams.
        conversation.server_acks(18);
        conversation.client_acks(23);

        assert_eq!(conversation.server_stream, b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(conversation.client_stream, b"HTTP/1.1 200 OK\r\n\r\nbody");
    }

    #[test]
    fn a_stream_joined_mid_conversation_still_reassembles() {
        // No handshake: the sensor started after the connection did.
        let mut conversation = Conversation::new(First);
        conversation.client(0, b"continuing ");
        conversation.client(11, b"mid-stream");
        conversation.server_acks(21);
        assert_eq!(conversation.server_stream, b"continuing mid-stream");
    }

    // -----------------------------------------------------------------------
    // acknowledgement gating — what makes overlap policy possible
    // -----------------------------------------------------------------------

    #[test]
    fn data_is_held_until_the_peer_acknowledges_it() {
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(0, b"unacknowledged");
        assert!(
            conversation.server_stream.is_empty(),
            "un-acknowledged data must stay revisable"
        );

        conversation.server_acks(14);
        assert_eq!(conversation.server_stream, b"unacknowledged");
    }

    #[test]
    fn a_partial_acknowledgement_delivers_only_what_was_acknowledged() {
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(0, b"ABCDEFGHIJ");
        conversation.server_acks(4);
        assert_eq!(conversation.server_stream, b"ABCD");

        conversation.server_acks(10);
        assert_eq!(conversation.server_stream, b"ABCDEFGHIJ");
    }

    #[test]
    fn un_acknowledged_data_is_flushed_once_it_piles_up() {
        // A one-way tap never sees ACKs. Matching must not stall for ever.
        let config = ReassemblyConfig {
            delivery_flush_bytes: 16,
            max_stream_bytes_per_flow: 4_096,
            ..config()
        };
        let mut conversation = Conversation::with_config(First, &config);
        conversation.client(0, b"0123456789");
        assert!(conversation.server_stream.is_empty(), "below the threshold");

        conversation.client(10, b"abcdef");
        assert_eq!(
            conversation.server_stream, b"0123456789abcdef",
            "at the threshold, deliver rather than stall"
        );
        assert!(conversation.pair.counters().flushed_unacked > 0);
    }

    // -----------------------------------------------------------------------
    // overlap policy
    // -----------------------------------------------------------------------

    #[test]
    fn a_contradicting_retransmission_resolves_by_policy() {
        for (policy, expected) in [(First, &b"AAAAA"[..]), (Last, &b"BBBBB"[..])] {
            let mut conversation = Conversation::new(policy);
            conversation.handshake();
            // Both copies arrive before the ACK, so the policy still has both.
            conversation.client(0, b"AAAAA");
            conversation.client(0, b"BBBBB");
            conversation.server_acks(5);

            assert_eq!(conversation.server_stream, expected, "policy {policy:?}");
            assert!(
                conversation.pair.counters().conflicting_overlaps > 0,
                "the disagreement must be counted"
            );
        }
    }

    #[test]
    fn a_partially_overlapping_segment_resolves_by_policy() {
        for (policy, expected) in [(First, &b"AAAAAAAAyyyy"[..]), (Last, &b"AAAAxxxxyyyy"[..])] {
            let mut conversation = Conversation::new(policy);
            conversation.handshake();
            conversation.client(0, b"AAAAAAAA");
            conversation.client(4, b"xxxxyyyy");
            conversation.server_acks(12);
            assert_eq!(conversation.server_stream, expected, "policy {policy:?}");
        }
    }

    #[test]
    fn an_identical_retransmission_is_not_a_conflict() {
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(0, b"HELLO");
        conversation.client(0, b"HELLO");
        conversation.server_acks(5);

        assert_eq!(conversation.server_stream, b"HELLO");
        assert_eq!(conversation.pair.counters().conflicting_overlaps, 0);
        assert!(conversation.pair.counters().overlaps > 0);
    }

    #[test]
    fn data_already_delivered_cannot_be_rewritten() {
        // The honest limit of the design, pinned so it cannot regress silently.
        let mut conversation = Conversation::new(Last);
        conversation.handshake();
        conversation.client(0, b"AAAAA");
        conversation.server_acks(5);
        assert_eq!(conversation.server_stream, b"AAAAA");

        conversation.client(0, b"BBBBB");
        assert_eq!(
            conversation.server_stream, b"AAAAA",
            "delivered bytes are gone; the retransmission is counted, not applied"
        );
        assert!(conversation.pair.counters().before_window >= 5);
    }

    // -----------------------------------------------------------------------
    // window edges
    // -----------------------------------------------------------------------

    #[test]
    fn data_far_beyond_the_window_is_refused() {
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.send(
            true,
            TcpSegment {
                sequence: CLIENT_ISN.wrapping_add(1).wrapping_add(1_000_000),
                acknowledgment: SERVER_ISN.wrapping_add(1),
                flags: ACK,
                payload: b"far future",
            },
        );
        assert!(conversation.pair.counters().out_of_window > 0);
        assert_eq!(conversation.pair.buffered_bytes(), 0);
    }

    #[test]
    fn data_before_the_window_is_counted_and_dropped() {
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(0, b"delivered");
        conversation.server_acks(9);

        // Re-send the same range, now behind the delivery point.
        conversation.client(0, b"delivered");
        assert_eq!(conversation.server_stream, b"delivered");
        assert!(conversation.pair.counters().before_window > 0);
    }

    #[test]
    fn a_sequence_number_wrap_is_handled() {
        // Start just below the 32-bit boundary so the stream wraps mid-flight.
        let mut pair = StreamPair::new(&config());
        let mut ready = StreamReady::default();
        let isn = u32::MAX - 4;

        pair.push(
            true,
            &TcpSegment {
                sequence: isn,
                acknowledgment: 0,
                flags: SYN,
                payload: b"",
            },
            First,
            First,
            &mut ready,
        );
        // Data spans the wrap: first four bytes before it, four after.
        pair.push(
            true,
            &TcpSegment {
                sequence: isn.wrapping_add(1),
                acknowledgment: 0,
                flags: ACK,
                payload: b"WRAPPING",
            },
            First,
            First,
            &mut ready,
        );
        ready.clear();
        pair.push(
            false,
            &TcpSegment {
                sequence: 1,
                acknowledgment: isn.wrapping_add(9),
                flags: ACK,
                payload: b"",
            },
            First,
            First,
            &mut ready,
        );
        assert_eq!(
            ready.to_server, b"WRAPPING",
            "the 32-bit wrap must not lose data"
        );
    }

    // -----------------------------------------------------------------------
    // SYN, FIN, RST
    // -----------------------------------------------------------------------

    #[test]
    fn data_on_the_syn_is_accepted_and_counted() {
        let mut conversation = Conversation::new(First);
        conversation.send(
            true,
            TcpSegment {
                sequence: CLIENT_ISN,
                acknowledgment: 0,
                flags: SYN,
                payload: b"fastopen",
            },
        );
        conversation.server_acks(8);
        assert_eq!(conversation.server_stream, b"fastopen");
        assert_eq!(conversation.pair.counters().syn_data, 8);
    }

    #[test]
    fn data_past_the_fin_is_rejected() {
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(0, b"request");
        conversation.send(
            true,
            TcpSegment {
                sequence: CLIENT_ISN.wrapping_add(1).wrapping_add(7),
                acknowledgment: SERVER_ISN.wrapping_add(1),
                flags: FIN | ACK,
                payload: b"",
            },
        );
        // The host has closed this direction; it will never read these bytes.
        conversation.client(7, b"INJECTED");
        conversation.server_acks(7);

        assert_eq!(conversation.server_stream, b"request");
        assert_eq!(conversation.pair.counters().after_fin, 8);
    }

    #[test]
    fn data_filling_a_gap_before_the_fin_is_still_accepted() {
        // A retransmission of something genuinely missing is not an injection.
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(4, b"DEF");
        conversation.send(
            true,
            TcpSegment {
                sequence: CLIENT_ISN.wrapping_add(1).wrapping_add(7),
                acknowledgment: SERVER_ISN.wrapping_add(1),
                flags: FIN | ACK,
                payload: b"",
            },
        );
        conversation.client(0, b"ABCD");
        conversation.server_acks(7);

        assert_eq!(conversation.server_stream, b"ABCDDEF");
        assert_eq!(conversation.pair.counters().after_fin, 0);
    }

    #[test]
    fn an_in_window_reset_tears_the_connection_down() {
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(0, b"data");

        let sequence = CLIENT_ISN.wrapping_add(1).wrapping_add(4);
        assert!(
            conversation.pair.rst_should_close(true, sequence),
            "a reset at the expected sequence is real"
        );
    }

    #[test]
    fn an_out_of_window_reset_does_not_tear_the_connection_down() {
        // The RST-evasion case. A blind attacker guesses a sequence number; if
        // the sensor believes it, the sensor stops watching a live connection
        // while the host carries on.
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(0, b"data");

        let forged = CLIENT_ISN.wrapping_add(500_000);
        assert!(
            !conversation.pair.rst_should_close(true, forged),
            "a reset far outside the window must be ignored"
        );
    }

    #[test]
    fn a_reset_on_an_unestablished_stream_is_ignored() {
        let pair = StreamPair::new(&config());
        assert!(!pair.rst_should_close(true, 12_345));
    }

    #[test]
    fn the_reset_flag_itself_is_not_what_decides() {
        // Sanity: the decision is about the sequence number, not the flag.
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(0, b"data");
        conversation.send(
            true,
            TcpSegment {
                sequence: CLIENT_ISN.wrapping_add(500_000),
                acknowledgment: 0,
                flags: RST,
                payload: b"",
            },
        );
        assert!(!conversation
            .pair
            .rst_should_close(true, CLIENT_ISN.wrapping_add(500_000)));
    }

    // -----------------------------------------------------------------------
    // bounds
    // -----------------------------------------------------------------------

    /// The DoS property: out-of-order segments that never complete must not
    /// grow the buffer without limit.
    #[test]
    fn an_out_of_order_flood_cannot_exceed_the_per_flow_cap() {
        let config = ReassemblyConfig {
            max_stream_bytes_per_flow: 2_048,
            delivery_flush_bytes: 2_048,
            ..config()
        };
        let mut conversation = Conversation::with_config(First, &config);
        conversation.handshake();

        // Never send offset 0, so nothing is ever contiguous and nothing can be
        // delivered — the worst case for a reassembler.
        for index in 1..10_000u32 {
            conversation.client(index * 4, b"AAAA");
            assert!(
                conversation.pair.buffered_bytes() <= 2_048,
                "buffered {} bytes against a 2048 cap",
                conversation.pair.buffered_bytes()
            );
        }
        assert!(
            conversation.pair.counters().refused_bytes > 0
                || conversation.pair.counters().out_of_window > 0,
            "the cap must be visible in the counters"
        );
        assert!(conversation.server_stream.is_empty());
    }

    #[test]
    fn a_flood_of_one_byte_holes_stays_bounded() {
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        for index in 1..5_000u32 {
            conversation.client(index * 2, b"A");
        }
        assert!(conversation.pair.buffered_bytes() <= 4_096);
    }

    #[test]
    fn flushing_delivers_what_is_contiguous_and_drops_the_rest() {
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(0, b"delivered");
        conversation.client(100, b"orphaned");

        conversation.flush();
        assert_eq!(
            conversation.server_stream, b"delivered",
            "the contiguous prefix is still worth having"
        );
        assert!(conversation.pair.counters().dropped_incomplete > 0);
        assert_eq!(conversation.pair.buffered_bytes(), 0);
    }

    #[test]
    fn an_empty_segment_carries_no_data_and_breaks_nothing() {
        let mut conversation = Conversation::new(First);
        conversation.handshake();
        conversation.client(0, b"");
        conversation.server_acks(0);
        assert!(conversation.server_stream.is_empty());
        assert_eq!(conversation.pair.counters().segments, 0);
    }
}
