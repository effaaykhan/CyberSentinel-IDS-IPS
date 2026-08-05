//! Evaluating a candidate rule against one unit of inspected data.
//!
//! The pre-filter says a rule is *worth* looking at; this decides whether it
//! actually matches. Options are walked in written order because several are
//! positional: `distance` and `within` are measured from the end of the
//! previous match, and `byte_jump` moves the cursor the options after it read
//! from.
//!
//! # Fail closed, everywhere
//!
//! Anything this code cannot answer means **no match**. A buffer the HTTP
//! parser has not filled, a `byte_test` reading past the end — each returns
//! "did not match" rather than "matched anyway". Compilation refuses an option
//! variant it does not understand, so one cannot reach here unhandled.
//! The alternative is a rule that fires on traffic nobody wrote it for, which
//! is how an analyst learns to ignore alerts.
//!
//! # Side effects wait for the verdict
//!
//! `flowbits:set` must only take effect if the whole rule matched. They are
//! collected during evaluation and returned to the caller, who applies them
//! once the verdict is in — otherwise a rule that matched half way would leave
//! state behind that changes what later rules do.

use std::collections::BTreeSet;

use cybersentinel_common::event::NetTuple;
use cybersentinel_reassembly::normalize::NormalizationFlags;
use cybersentinel_rules::{
    Buffer, ByteJump, ByteTest, ContentMatch, Endian, FlowBitsOp, FlowMatch, NormalizationCondition,
};

use crate::compile::{CompiledOption, CompiledRule};

/// Number of distinct buffers, for the per-buffer cursor array.
const BUFFER_COUNT: usize = 6;

fn buffer_index(buffer: Buffer) -> usize {
    match buffer {
        Buffer::Payload => 0,
        Buffer::HttpUri => 1,
        Buffer::HttpHeader => 2,
        Buffer::HttpUserAgent => 3,
        Buffer::HttpMethod => 4,
        Buffer::HttpHost => 5,
    }
}

/// The data a rule is matched against.
#[derive(Debug, Clone, Copy, Default)]
pub struct Buffers<'a> {
    /// Packet payload, or reassembled stream.
    pub payload: &'a [u8],
    /// Normalized request URI.
    pub http_uri: Option<&'a [u8]>,
    /// Raw header block.
    pub http_header: Option<&'a [u8]>,
    /// `User-Agent` value.
    pub http_user_agent: Option<&'a [u8]>,
    /// Request method.
    pub http_method: Option<&'a [u8]>,
    /// `Host` value.
    pub http_host: Option<&'a [u8]>,
    /// What normalization had to do to produce the URI.
    pub normalization: NormalizationFlags,
}

impl<'a> Buffers<'a> {
    /// The bytes of a buffer, or `None` if it was never filled.
    ///
    /// An absent buffer is not an empty one: a rule on `http.uri` must not
    /// match non-HTTP traffic just because there is no URI to contradict it.
    #[must_use]
    pub fn get(&self, buffer: Buffer) -> Option<&'a [u8]> {
        match buffer {
            Buffer::Payload => Some(self.payload),
            Buffer::HttpUri => self.http_uri,
            Buffer::HttpHeader => self.http_header,
            Buffer::HttpUserAgent => self.http_user_agent,
            Buffer::HttpMethod => self.http_method,
            Buffer::HttpHost => self.http_host,
        }
    }
}

/// Everything about the packet or stream chunk being inspected.
#[derive(Debug, Clone, Copy)]
pub struct MatchInput<'a> {
    /// The 5-tuple, oriented as the data travelled.
    pub tuple: NetTuple,
    /// Whether the connection is established.
    pub established: bool,
    /// Whether the data is travelling towards the responder.
    pub to_server: bool,
    /// The buffers.
    pub buffers: Buffers<'a>,
}

/// Flowbits set on one flow.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowBits {
    bits: BTreeSet<String>,
}

impl FlowBits {
    /// Whether a bit is set.
    #[must_use]
    pub fn is_set(&self, name: &str) -> bool {
        self.bits.contains(name)
    }

    /// How many bits are set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Whether no bits are set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// Apply a side effect.
    ///
    /// `limit` caps how many distinct bits one flow may hold: bit names come
    /// from rules, but *how many* get set is driven by traffic, and unbounded
    /// per-flow state is the thing this project keeps refusing to have.
    pub fn apply(&mut self, op: &FlowBitsOp, limit: usize) {
        match op {
            FlowBitsOp::Set(name) => {
                if self.bits.len() < limit || self.bits.contains(name) {
                    self.bits.insert(name.clone());
                }
            }
            FlowBitsOp::Unset(name) => {
                self.bits.remove(name);
            }
            FlowBitsOp::Toggle(name) => {
                if self.bits.contains(name) {
                    self.bits.remove(name);
                } else if self.bits.len() < limit {
                    self.bits.insert(name.clone());
                }
            }
            FlowBitsOp::IsSet(_) | FlowBitsOp::IsNotSet(_) | FlowBitsOp::NoAlert => {}
        }
    }
}

/// What a successful match wants done afterwards.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchOutcome {
    /// Flowbit operations to apply now that the rule has matched.
    pub side_effects: Vec<FlowBitsOp>,
}

/// Evaluate one rule.
///
/// Returns `None` if it did not match.
#[must_use]
pub fn evaluate(
    rule: &CompiledRule,
    input: &MatchInput<'_>,
    bits: &FlowBits,
) -> Option<MatchOutcome> {
    if !rule.header.matches(&input.tuple) {
        return None;
    }

    let mut cursors = [0usize; BUFFER_COUNT];
    let mut current = Buffer::Payload;
    let mut side_effects = Vec::new();

    for option in &rule.options {
        match option {
            CompiledOption::Content(content) => {
                current = content.buffer;
                let haystack = input.buffers.get(content.buffer)?;
                let cursor = &mut cursors[buffer_index(content.buffer)];
                if !match_content(content, haystack, cursor) {
                    return None;
                }
            }
            CompiledOption::Pcre {
                matcher,
                buffer,
                negated,
                relative,
            } => {
                current = *buffer;
                let haystack = input.buffers.get(*buffer)?;
                let cursor = &mut cursors[buffer_index(*buffer)];
                let start = if *relative {
                    (*cursor).min(haystack.len())
                } else {
                    0
                };
                // The remainder is *sliced* rather than searched from an
                // offset, so `^` in a relative expression anchors where the
                // previous match ended — which is what `R` is asking for.
                // `regex` has no look-behind, so nothing is lost by cutting.
                let found = matcher.find(&haystack[start..]);
                match (found, negated) {
                    (Some(found), false) => *cursor = start + found.end(),
                    (None, true) => {}
                    _ => return None,
                }
            }
            CompiledOption::Flow(flow) => {
                if !match_flow(*flow, input) {
                    return None;
                }
            }
            CompiledOption::FlowBits(op) => match op {
                FlowBitsOp::IsSet(name) => {
                    if !bits.is_set(name) {
                        return None;
                    }
                }
                FlowBitsOp::IsNotSet(name) => {
                    if bits.is_set(name) {
                        return None;
                    }
                }
                other => side_effects.push(other.clone()),
            },
            CompiledOption::ByteTest(test) => {
                let haystack = input.buffers.get(current)?;
                let cursor = cursors[buffer_index(current)];
                if !match_byte_test(*test, haystack, cursor) {
                    return None;
                }
            }
            CompiledOption::ByteJump(jump) => {
                let haystack = input.buffers.get(current)?;
                let cursor = &mut cursors[buffer_index(current)];
                if !apply_byte_jump(*jump, haystack, cursor) {
                    return None;
                }
            }
            CompiledOption::Dsize(dsize) => {
                let haystack = input.buffers.get(current)?;
                if !dsize.matches(haystack.len()) {
                    return None;
                }
            }
            CompiledOption::Normalized(condition) => {
                if !normalization_matches(*condition, input.buffers.normalization) {
                    return None;
                }
            }
        }
    }

    Some(MatchOutcome { side_effects })
}

fn match_flow(flow: FlowMatch, input: &MatchInput<'_>) -> bool {
    if let Some(established) = flow.established {
        if established != input.established {
            return false;
        }
    }
    if let Some(to_server) = flow.to_server {
        if to_server != input.to_server {
            return false;
        }
    }
    true
}

/// Search for a content pattern, honouring its modifiers.
///
/// Returns whether the condition held; on a positive match the cursor advances
/// to the end of the match so the next relative option measures from there.
fn match_content(content: &ContentMatch, haystack: &[u8], cursor: &mut usize) -> bool {
    let length = haystack.len();

    // Relative matches measure from the previous match's end; absolute ones
    // from the start of the buffer.
    let base = if content.is_relative() { *cursor } else { 0 };
    let start = i64::from(content.distance.unwrap_or(0))
        .saturating_add(if content.is_relative() {
            base as i64
        } else {
            i64::from(content.offset.unwrap_or(0))
        })
        .max(0) as usize;

    let mut end = length;
    if let Some(within) = content.within {
        end = end.min(base.saturating_add(within as usize));
    }
    if let Some(depth) = content.depth {
        end = end.min(start.saturating_add(depth as usize));
    }
    let start = start.min(length);
    let end = end.min(length).max(start);

    let found = find(&haystack[start..end], &content.pattern, content.nocase);

    match (found, content.negated) {
        (Some(position), false) => {
            *cursor = start + position + content.pattern.len();
            true
        }
        // A negated match leaves the cursor alone: there is no match to measure
        // the next `distance` from.
        (None, true) => true,
        _ => false,
    }
}

/// Find `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8], nocase: bool) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    if nocase {
        haystack.windows(needle.len()).position(|window| {
            window
                .iter()
                .zip(needle)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        })
    } else {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }
}

/// Read `bytes` big- or little-endian at `position`.
fn read_number(haystack: &[u8], position: usize, bytes: u8, endian: Endian) -> Option<u64> {
    let width = usize::from(bytes);
    let slice = haystack.get(position..position.checked_add(width)?)?;
    let mut value = 0u64;
    match endian {
        Endian::Big => {
            for byte in slice {
                value = (value << 8) | u64::from(*byte);
            }
        }
        Endian::Little => {
            for byte in slice.iter().rev() {
                value = (value << 8) | u64::from(*byte);
            }
        }
    }
    Some(value)
}

fn resolve_position(base: usize, offset: i32, relative: bool) -> Option<usize> {
    let start = if relative { base as i64 } else { 0 };
    let position = start.checked_add(i64::from(offset))?;
    usize::try_from(position).ok()
}

fn match_byte_test(test: ByteTest, haystack: &[u8], cursor: usize) -> bool {
    let Some(position) = resolve_position(cursor, test.offset, test.relative) else {
        return false;
    };
    // Reading past the end is not a match; it is a rule looking at data that is
    // not there.
    let Some(value) = read_number(haystack, position, test.bytes, test.endian) else {
        return false;
    };
    let result = test.op.apply(value, test.value);
    result != test.negated
}

fn apply_byte_jump(jump: ByteJump, haystack: &[u8], cursor: &mut usize) -> bool {
    let Some(position) = resolve_position(*cursor, jump.offset, jump.relative) else {
        return false;
    };
    let Some(value) = read_number(haystack, position, jump.bytes, jump.endian) else {
        return false;
    };

    let jumped = value
        .checked_mul(u64::from(jump.multiplier))
        .and_then(|scaled| scaled.checked_add(position as u64 + u64::from(jump.bytes)))
        .and_then(|destination| {
            let with_post = destination as i64 + i64::from(jump.post_offset);
            u64::try_from(with_post).ok()
        });

    // A jump landing outside the buffer is a failed match, not a wrapped
    // cursor pointing at unrelated bytes.
    match jumped {
        Some(destination) if destination <= haystack.len() as u64 => {
            *cursor = destination as usize;
            true
        }
        _ => false,
    }
}

fn normalization_matches(condition: NormalizationCondition, flags: NormalizationFlags) -> bool {
    match condition {
        NormalizationCondition::PercentEncoded => flags.percent_encoded,
        NormalizationCondition::DoubleEncoded => flags.double_encoded,
        NormalizationCondition::InvalidEscape => flags.invalid_escape,
        NormalizationCondition::NullByte => flags.null_byte,
        NormalizationCondition::Traversal => flags.traversal,
        NormalizationCondition::AboveRoot => flags.above_root,
        NormalizationCondition::SelfReference => flags.self_reference,
        NormalizationCondition::EmptySegment => flags.empty_segment,
        NormalizationCondition::Backslash => flags.backslash,
        NormalizationCondition::DecodeLimitReached => flags.decode_limit_reached,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::{CompileLimits, CompiledRuleset};
    use crate::vars::VarTable;
    use cybersentinel_common::event::Protocol;
    use cybersentinel_rules::parse_rule;
    use std::collections::BTreeMap;

    fn compile(text: &str) -> CompiledRuleset {
        let rule = parse_rule(text).expect("the rule should parse");
        let (ruleset, report) = CompiledRuleset::compile(
            std::iter::once(&rule),
            &VarTable::new(BTreeMap::new(), BTreeMap::new()),
            CompileLimits::default(),
        );
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert_eq!(report.compiled, 1, "{}", report.summary());
        ruleset
    }

    fn tuple() -> NetTuple {
        NetTuple {
            src_ip: "192.0.2.1".parse().unwrap(),
            src_port: Some(51_000),
            dest_ip: "198.51.100.1".parse().unwrap(),
            dest_port: Some(80),
            proto: Protocol::Tcp,
        }
    }

    fn input<'a>(payload: &'a [u8]) -> MatchInput<'a> {
        MatchInput {
            tuple: tuple(),
            established: true,
            to_server: true,
            buffers: Buffers {
                payload,
                ..Buffers::default()
            },
        }
    }

    fn matches(text: &str, payload: &[u8]) -> bool {
        let ruleset = compile(text);
        evaluate(&ruleset.rules()[0], &input(payload), &FlowBits::default()).is_some()
    }

    // -----------------------------------------------------------------------
    // content
    // -----------------------------------------------------------------------

    #[test]
    fn a_content_rule_matches_the_payload_that_contains_it() {
        let rule = r#"alert tcp any any -> any any (msg:"m"; content:"evil"; sid:1;)"#;
        assert!(matches(rule, b"something evil here"));
        assert!(!matches(rule, b"nothing to see"));
    }

    #[test]
    fn nocase_matches_either_case() {
        let rule = r#"alert tcp any any -> any any (msg:"m"; content:"SELECT"; nocase; sid:1;)"#;
        assert!(matches(rule, b"union select 1"));
        assert!(!matches(
            r#"alert tcp any any -> any any (msg:"m"; content:"SELECT"; sid:1;)"#,
            b"union select 1"
        ));
    }

    #[test]
    fn offset_and_depth_bound_where_a_match_counts() {
        let rule =
            r#"alert tcp any any -> any any (msg:"m"; content:"GET"; offset:0; depth:3; sid:1;)"#;
        assert!(matches(rule, b"GET /index.html"));
        assert!(
            !matches(rule, b"xxGET /index.html"),
            "the pattern is past the depth window"
        );
    }

    #[test]
    fn distance_and_within_are_measured_from_the_previous_match() {
        let rule = r#"alert tcp any any -> any any (msg:"m"; content:"AA"; content:"BB"; distance:2; within:4; sid:1;)"#;
        assert!(matches(rule, b"AAxxBB"));
        assert!(!matches(rule, b"AABB"), "BB is closer than distance:2");
        assert!(
            !matches(rule, b"AAxxxxxxxxBB"),
            "BB is further away than within:4"
        );
    }

    #[test]
    fn a_negated_content_matches_when_the_pattern_is_absent() {
        let rule =
            r#"alert tcp any any -> any any (msg:"m"; content:"login"; content:!"admin"; sid:1;)"#;
        assert!(matches(rule, b"login as guest"));
        assert!(!matches(rule, b"login as admin"));
    }

    #[test]
    fn a_hex_pattern_matches_raw_bytes() {
        let rule = r#"alert tcp any any -> any any (msg:"m"; content:"GET|20|/|0d0a|"; sid:1;)"#;
        assert!(matches(rule, b"GET /\r\n"));
        assert!(!matches(rule, b"GET /\n"));
    }

    // -----------------------------------------------------------------------
    // other conditions
    // -----------------------------------------------------------------------

    #[test]
    fn pcre_matches_and_can_be_relative() {
        assert!(matches(
            r#"alert tcp any any -> any any (msg:"m"; pcre:"/id=\d+/"; sid:1;)"#,
            b"?id=1234"
        ));
        assert!(matches(
            r#"alert tcp any any -> any any (msg:"m"; content:"user="; pcre:"/^\w+/R"; sid:1;)"#,
            b"user=admin"
        ));
    }

    #[test]
    fn flow_conditions_are_honoured() {
        let ruleset = compile(
            r#"alert tcp any any -> any any (msg:"m"; flow:established,to_client; content:"x"; sid:1;)"#,
        );
        let mut context = input(b"x");
        assert!(evaluate(&ruleset.rules()[0], &context, &FlowBits::default()).is_none());
        context.to_server = false;
        assert!(evaluate(&ruleset.rules()[0], &context, &FlowBits::default()).is_some());
    }

    #[test]
    fn dsize_tests_the_buffer_length() {
        assert!(matches(
            r#"alert tcp any any -> any any (msg:"m"; dsize:>4; sid:1;)"#,
            b"12345"
        ));
        assert!(!matches(
            r#"alert tcp any any -> any any (msg:"m"; dsize:>4; sid:1;)"#,
            b"1234"
        ));
    }

    #[test]
    fn byte_test_reads_and_compares() {
        // Two big-endian bytes at offset 0 are 0x0100 = 256.
        assert!(matches(
            r#"alert tcp any any -> any any (msg:"m"; byte_test:2,=,256,0; sid:1;)"#,
            &[0x01, 0x00, 0xff]
        ));
        assert!(matches(
            r#"alert tcp any any -> any any (msg:"m"; byte_test:2,=,1,0,little; sid:1;)"#,
            &[0x01, 0x00, 0xff]
        ));
        assert!(!matches(
            r#"alert tcp any any -> any any (msg:"m"; byte_test:2,=,256,0; sid:1;)"#,
            &[0x02, 0x00]
        ));
    }

    #[test]
    fn byte_test_reading_past_the_end_does_not_match() {
        assert!(!matches(
            r#"alert tcp any any -> any any (msg:"m"; byte_test:4,=,1,100; sid:1;)"#,
            b"short"
        ));
    }

    #[test]
    fn byte_jump_moves_the_cursor_for_what_follows() {
        // One byte at offset 0 holds 3; jump past it and the 3 bytes it counts,
        // landing on "END".
        assert!(matches(
            r#"alert tcp any any -> any any (msg:"m"; byte_jump:1,0; content:"END"; sid:1;)"#,
            &[0x03, b'x', b'y', b'z', b'E', b'N', b'D']
        ));
    }

    #[test]
    fn a_byte_jump_past_the_buffer_does_not_match() {
        assert!(!matches(
            r#"alert tcp any any -> any any (msg:"m"; byte_jump:1,0; content:"END"; sid:1;)"#,
            &[0xff, b'x']
        ));
    }

    #[test]
    fn flowbits_conditions_read_the_flow_state() {
        let ruleset = compile(
            r#"alert tcp any any -> any any (msg:"m"; flowbits:isset,seen; content:"x"; sid:1;)"#,
        );
        let mut bits = FlowBits::default();
        assert!(evaluate(&ruleset.rules()[0], &input(b"x"), &bits).is_none());

        bits.apply(&FlowBitsOp::Set("seen".into()), 32);
        assert!(evaluate(&ruleset.rules()[0], &input(b"x"), &bits).is_some());
    }

    #[test]
    fn flowbits_side_effects_are_returned_rather_than_applied() {
        // They must only take effect if the whole rule matched.
        let ruleset = compile(
            r#"alert tcp any any -> any any (msg:"m"; content:"login"; flowbits:set,seen; sid:1;)"#,
        );
        assert!(evaluate(
            &ruleset.rules()[0],
            &input(b"nothing"),
            &FlowBits::default()
        )
        .is_none());

        let outcome = evaluate(&ruleset.rules()[0], &input(b"login"), &FlowBits::default())
            .expect("should match");
        assert_eq!(outcome.side_effects.len(), 1);
    }

    #[test]
    fn the_flowbit_count_per_flow_is_bounded() {
        // Bit names come from rules, but how many get set is driven by traffic.
        let mut bits = FlowBits::default();
        for index in 0..1_000 {
            bits.apply(&FlowBitsOp::Set(format!("bit{index}")), 8);
        }
        assert_eq!(bits.len(), 8);
    }

    // -----------------------------------------------------------------------
    // failing closed
    // -----------------------------------------------------------------------

    #[test]
    fn a_rule_on_an_unfilled_buffer_does_not_match() {
        // No HTTP parser has run, so there is no URI. The rule must not match
        // just because there is nothing to contradict it.
        let ruleset = compile(
            r#"alert http any any -> any any (msg:"m"; http.uri; content:"/admin"; sid:1;)"#,
        );
        assert!(evaluate(&ruleset.rules()[0], &input(b"/admin"), &FlowBits::default()).is_none());
    }

    #[test]
    fn a_header_that_does_not_select_the_traffic_stops_evaluation() {
        let ruleset = compile(r#"alert tcp any any -> any 443 (msg:"m"; content:"evil"; sid:1;)"#);
        assert!(evaluate(&ruleset.rules()[0], &input(b"evil"), &FlowBits::default()).is_none());
    }

    #[test]
    fn normalization_conditions_read_the_flags() {
        let ruleset = compile(
            r#"alert http any any -> any any (msg:"m"; http.uri; content:"/a"; normalized:double_encoded; sid:1;)"#,
        );
        let uri = b"/a";
        let mut context = input(b"");
        context.buffers.http_uri = Some(uri);
        assert!(evaluate(&ruleset.rules()[0], &context, &FlowBits::default()).is_none());

        context.buffers.normalization.double_encoded = true;
        assert!(evaluate(&ruleset.rules()[0], &context, &FlowBits::default()).is_some());
    }

    #[test]
    fn every_condition_must_hold_for_the_rule_to_match() {
        let rule = r#"alert tcp any any -> any any (msg:"m"; content:"a"; content:"b"; dsize:>100; sid:1;)"#;
        assert!(!matches(rule, b"ab"), "dsize is not satisfied");
    }
}
