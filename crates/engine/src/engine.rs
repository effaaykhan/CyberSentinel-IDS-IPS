//! The detection engine: state, rate limiting, and alerts.
//!
//! Ties the pre-filter and the evaluator to the per-flow state a ruleset needs
//! — flowbits, and an inspection buffer so a pattern split across two stream
//! deliveries is still found.
//!
//! # Bounded, like everything else an attacker drives
//!
//! Flow states, flowbits per flow, inspection bytes per direction, and
//! threshold counters all have caps. The number of flows, the number of bits a
//! rule sets, and how much data arrives before a match are all chosen by
//! whoever is sending traffic.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime};

use cybersentinel_common::event::NetTuple;
use cybersentinel_rules::{Buffer, Rule, ThresholdKind, Track};

use crate::compile::{CompileLimits, CompileReport, CompiledRuleset};
use crate::eval::{evaluate, Buffers, FlowBits, MatchInput};
use crate::vars::VarTable;

/// Engine limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineLimits {
    /// Regex compilation budgets.
    pub compile: CompileLimits,
    /// Flows that may carry detection state at once.
    pub max_flow_states: usize,
    /// Flowbits one flow may hold.
    pub max_flowbits_per_flow: usize,
    /// Bytes of reassembled stream kept per direction for matching.
    ///
    /// A pattern cannot be found if it never sits in the window whole, so this
    /// is the longest content match that can ever fire on a stream.
    pub inspection_window: usize,
    /// Threshold counters held at once.
    pub max_threshold_entries: usize,
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            compile: CompileLimits::default(),
            max_flow_states: 65_536,
            max_flowbits_per_flow: 64,
            inspection_window: 64 << 10,
            max_threshold_entries: 65_536,
        }
    }
}

/// An alert the engine decided to raise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertRecord {
    /// Signature id.
    pub sid: u32,
    /// Revision.
    pub rev: u32,
    /// The rule's `msg`.
    pub signature: String,
    /// The rule's `classtype`.
    pub classtype: Option<String>,
    /// Severity, from `priority`.
    pub severity: u8,
    /// The rule's metadata.
    pub metadata: BTreeMap<String, Vec<String>>,
}

/// Running totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EngineCounters {
    /// Buffers inspected.
    pub inspections: u64,
    /// Bytes inspected.
    pub bytes_inspected: u64,
    /// Rules the pre-filter put forward.
    pub candidates: u64,
    /// Rules that fully matched.
    pub matches: u64,
    /// Alerts raised.
    pub alerts: u64,
    /// Matches suppressed by a `threshold`.
    pub thresholded: u64,
    /// Matches that raised no alert because of `flowbits:noalert`.
    pub silent: u64,
    /// Flows carrying detection state.
    pub flow_states: u64,
    /// Flow states evicted under the cap. **A coverage signal**: flowbits and
    /// stream context for those flows are gone.
    pub flow_states_evicted: u64,
    /// Stream bytes dropped from the front of an inspection window.
    pub inspection_bytes_dropped: u64,
}

/// A bounded, sliding view of one direction's reassembled stream.
///
/// Detection needs a pattern to be contiguous. Deliveries are not: a signature
/// can straddle two of them. So bytes accumulate here, and only the new region
/// — plus an overlap as long as the longest pattern — is re-scanned, which
/// keeps the work linear in the traffic rather than quadratic.
#[derive(Debug, Default)]
struct InspectionBuffer {
    data: Vec<u8>,
    /// How much of `data` has already been scanned.
    scanned: usize,
}

impl InspectionBuffer {
    /// Append and return the region that still needs scanning.
    fn append(&mut self, bytes: &[u8], overlap: usize, window: usize) -> (usize, u64) {
        self.data.extend_from_slice(bytes);

        let mut dropped = 0u64;
        if self.data.len() > window {
            let excess = self.data.len() - window;
            self.data.drain(..excess);
            self.scanned = self.scanned.saturating_sub(excess);
            dropped = excess as u64;
        }

        let start = self.scanned.saturating_sub(overlap);
        self.scanned = self.data.len();
        (start, dropped)
    }
}

/// Detection state for one flow.
#[derive(Debug)]
struct FlowState {
    bits: FlowBits,
    to_server: InspectionBuffer,
    to_client: InspectionBuffer,
    last_seen: SystemTime,
}

impl Default for FlowState {
    fn default() -> Self {
        Self {
            bits: FlowBits::default(),
            to_server: InspectionBuffer::default(),
            to_client: InspectionBuffer::default(),
            last_seen: SystemTime::UNIX_EPOCH,
        }
    }
}

/// One threshold counter.
#[derive(Debug, Clone, Copy)]
struct ThresholdEntry {
    count: u32,
    window_start: SystemTime,
}

/// The engine.
#[derive(Debug)]
pub struct Engine {
    ruleset: CompiledRuleset,
    limits: EngineLimits,
    states: HashMap<u64, FlowState>,
    thresholds: HashMap<(u32, String), ThresholdEntry>,
    counters: EngineCounters,
    /// Longest pattern in the ruleset, for the re-scan overlap.
    longest_pattern: usize,
}

impl Engine {
    /// Compile a ruleset and build an engine around it.
    #[must_use]
    pub fn new<'a>(
        rules: impl IntoIterator<Item = &'a Rule>,
        vars: &VarTable,
        limits: EngineLimits,
    ) -> (Self, CompileReport) {
        let (ruleset, report) = CompiledRuleset::compile(rules, vars, limits.compile);
        let longest_pattern = ruleset
            .rules()
            .iter()
            .flat_map(|rule| rule.options.iter())
            .filter_map(|option| match option {
                crate::compile::CompiledOption::Content(content) => Some(content.pattern.len()),
                _ => None,
            })
            .max()
            .unwrap_or(0);

        (
            Self {
                ruleset,
                limits,
                states: HashMap::new(),
                thresholds: HashMap::new(),
                counters: EngineCounters::default(),
                longest_pattern,
            },
            report,
        )
    }

    /// The compiled ruleset.
    #[must_use]
    pub fn ruleset(&self) -> &CompiledRuleset {
        &self.ruleset
    }

    /// Running totals.
    #[must_use]
    pub fn counters(&self) -> EngineCounters {
        let mut counters = self.counters;
        counters.flow_states = self.states.len() as u64;
        counters
    }

    /// Whether any armed rule needs the HTTP parser.
    #[must_use]
    pub fn needs_http(&self) -> bool {
        self.ruleset.needs_http()
    }

    /// Inspect a self-contained payload — a UDP datagram, an ICMP message, or a
    /// reassembled IP datagram.
    ///
    /// No stream context, so nothing accumulates.
    pub fn inspect_packet(
        &mut self,
        flow_id: u64,
        tuple: NetTuple,
        to_server: bool,
        payload: &[u8],
        timestamp: SystemTime,
        alerts: &mut Vec<AlertRecord>,
    ) {
        let buffers = Buffers {
            payload,
            ..Buffers::default()
        };
        self.inspect(
            flow_id,
            tuple,
            to_server,
            false,
            buffers,
            Buffer::Payload,
            timestamp,
            alerts,
        );
    }

    /// Inspect newly delivered stream bytes for a flow.
    ///
    /// The bytes are appended to that direction's window and only the new
    /// region — plus an overlap — is scanned.
    pub fn inspect_stream(
        &mut self,
        flow_id: u64,
        tuple: NetTuple,
        to_server: bool,
        delivered: &[u8],
        timestamp: SystemTime,
        alerts: &mut Vec<AlertRecord>,
    ) {
        if delivered.is_empty() {
            return;
        }
        self.make_room(timestamp);

        let overlap = self.longest_pattern.saturating_sub(1);
        let window = self.limits.inspection_window;

        let state = self.states.entry(flow_id).or_default();
        state.last_seen = timestamp;
        let buffer = if to_server {
            &mut state.to_server
        } else {
            &mut state.to_client
        };
        let (start, dropped) = buffer.append(delivered, overlap, window);
        self.counters.inspection_bytes_dropped += dropped;

        // Copy the region out so the ruleset and state can both be borrowed.
        // Bounded by the inspection window, and only the new part is taken.
        let region: Vec<u8> = buffer.data[start..].to_vec();

        let buffers = Buffers {
            payload: &region,
            ..Buffers::default()
        };
        self.inspect(
            flow_id,
            tuple,
            to_server,
            true,
            buffers,
            Buffer::Payload,
            timestamp,
            alerts,
        );
    }

    /// Inspect a set of buffers directly. Used by the app-layer parser once it
    /// has a complete transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn inspect(
        &mut self,
        flow_id: u64,
        tuple: NetTuple,
        to_server: bool,
        established: bool,
        buffers: Buffers<'_>,
        prefilter_buffer: Buffer,
        timestamp: SystemTime,
        alerts: &mut Vec<AlertRecord>,
    ) {
        let haystack = buffers.get(prefilter_buffer).unwrap_or(&[]);
        self.counters.inspections += 1;
        self.counters.bytes_inspected += haystack.len() as u64;

        let mut candidates = Vec::new();
        self.ruleset
            .candidates(prefilter_buffer, haystack, &mut candidates);
        self.counters.candidates += candidates.len() as u64;
        if candidates.is_empty() {
            return;
        }

        let input = MatchInput {
            tuple,
            established,
            to_server,
            buffers,
        };

        // The flow's bits are read during evaluation and written after, so a
        // rule cannot see its own side effects.
        let bits = self
            .states
            .get(&flow_id)
            .map(|state| state.bits.clone())
            .unwrap_or_default();
        let mut pending = Vec::new();

        for index in candidates {
            // Everything needed from the rule is taken here, so the borrow of
            // the ruleset ends before the engine is touched mutably.
            let Some(rule) = self.ruleset.rule(index) else {
                continue;
            };
            let Some(outcome) = evaluate(rule, &input, &bits) else {
                continue;
            };
            let sid = rule.sid;
            let threshold = rule.threshold;
            let no_alert = rule.no_alert;
            let record = AlertRecord {
                sid: rule.sid,
                rev: rule.rev,
                signature: rule.msg.clone(),
                classtype: rule.classtype.clone(),
                severity: rule.severity,
                metadata: rule.metadata.clone(),
            };

            self.counters.matches += 1;
            pending.extend(outcome.side_effects);

            if no_alert {
                self.counters.silent += 1;
                continue;
            }
            if !self.threshold_allows(sid, threshold, &tuple, timestamp) {
                self.counters.thresholded += 1;
                continue;
            }
            self.counters.alerts += 1;
            alerts.push(record);
        }

        if !pending.is_empty() {
            self.make_room(timestamp);
            let limit = self.limits.max_flowbits_per_flow;
            let state = self.states.entry(flow_id).or_default();
            state.last_seen = timestamp;
            for op in &pending {
                state.bits.apply(op, limit);
            }
        }
    }

    /// Whether a rule's threshold lets this match alert.
    fn threshold_allows(
        &mut self,
        sid: u32,
        threshold: Option<cybersentinel_rules::Threshold>,
        tuple: &NetTuple,
        now: SystemTime,
    ) -> bool {
        let Some(threshold) = threshold else {
            return true;
        };
        let key = match threshold.track {
            Track::BySource => tuple.src_ip.to_string(),
            Track::ByDestination => tuple.dest_ip.to_string(),
            Track::ByRule => String::new(),
        };

        // Bounded: the key can be an address, and addresses are chosen by
        // whoever is sending. A full table drops the counter rather than the
        // alert — alerting too often is a lesser failure than not at all.
        if self.thresholds.len() >= self.limits.max_threshold_entries
            && !self.thresholds.contains_key(&(sid, key.clone()))
        {
            return true;
        }

        let window = Duration::from_secs(u64::from(threshold.seconds));
        let entry = self.thresholds.entry((sid, key)).or_insert(ThresholdEntry {
            count: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start).unwrap_or_default() >= window {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count += 1;

        match threshold.kind {
            // Alert on every `count`th event.
            ThresholdKind::Threshold => entry.count % threshold.count == 0,
            // Alert at most `count` times per window.
            ThresholdKind::Limit => entry.count <= threshold.count,
            // Alert once, on the `count`th, and not again this window.
            ThresholdKind::Both => entry.count == threshold.count,
        }
    }

    /// Drop the detection state for a flow that has ended.
    pub fn on_flow_end(&mut self, flow_id: u64) {
        self.states.remove(&flow_id);
    }

    /// Keep the state table inside its cap.
    fn make_room(&mut self, now: SystemTime) {
        if self.states.len() < self.limits.max_flow_states {
            return;
        }
        // Evict the least recently used tenth. Losing a flow's state means
        // losing its flowbits and its stream window, so it is counted.
        let batch = (self.limits.max_flow_states / 10).max(1);
        let mut by_age: Vec<(SystemTime, u64)> = self
            .states
            .iter()
            .map(|(id, state)| (state.last_seen, *id))
            .collect();
        by_age.sort_unstable_by_key(|(seen, _)| *seen);

        for (_, id) in by_age.into_iter().take(batch) {
            if self.states.remove(&id).is_some() {
                self.counters.flow_states_evicted += 1;
            }
        }
        tracing::warn!(
            evicted = batch,
            capacity = self.limits.max_flow_states,
            "detection state table full; flowbits and stream context are being lost"
        );
        let _ = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cybersentinel_common::event::Protocol;
    use cybersentinel_rules::parse_rule;

    fn engine(texts: &[&str]) -> Engine {
        let rules: Vec<Rule> = texts
            .iter()
            .map(|text| parse_rule(text).expect("the rule should parse"))
            .collect();
        let (engine, report) = Engine::new(
            rules.iter(),
            &VarTable::new(BTreeMap::new(), BTreeMap::new()),
            EngineLimits::default(),
        );
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        engine
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

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn a_content_rule_alerts_on_a_matching_payload() {
        let mut engine = engine(&[
            r#"alert tcp any any -> any any (msg:"CYBERSENTINEL TEST marker"; content:"ATTACK"; classtype:trojan-activity; priority:2; sid:1234; rev:5;)"#,
        ]);
        let mut alerts = Vec::new();
        engine.inspect_packet(1, tuple(), true, b"an ATTACK payload", at(0), &mut alerts);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].sid, 1_234);
        assert_eq!(alerts[0].rev, 5);
        assert_eq!(alerts[0].signature, "CYBERSENTINEL TEST marker");
        assert_eq!(alerts[0].classtype.as_deref(), Some("trojan-activity"));
        assert_eq!(alerts[0].severity, 2);
        assert_eq!(engine.counters().alerts, 1);
    }

    #[test]
    fn a_non_matching_payload_raises_nothing() {
        let mut engine =
            engine(&[r#"alert tcp any any -> any any (msg:"m"; content:"ATTACK"; sid:1;)"#]);
        let mut alerts = Vec::new();
        engine.inspect_packet(1, tuple(), true, b"ordinary traffic", at(0), &mut alerts);
        assert!(alerts.is_empty());
    }

    /// The property Phase 2 exists for, seen from the engine's side.
    #[test]
    fn a_pattern_split_across_two_deliveries_is_still_found() {
        let mut engine =
            engine(&[r#"alert tcp any any -> any any (msg:"m"; content:"ATTACKSTRING"; sid:1;)"#]);
        let mut alerts = Vec::new();

        engine.inspect_stream(1, tuple(), true, b"junk ATTACK", at(0), &mut alerts);
        assert!(alerts.is_empty(), "not yet complete");

        engine.inspect_stream(1, tuple(), true, b"STRING more", at(1), &mut alerts);
        assert_eq!(alerts.len(), 1, "the overlap must carry the prefix across");
    }

    #[test]
    fn the_inspection_window_is_bounded() {
        let rules = [parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; content:"never-appears"; sid:1;)"#,
        )
        .unwrap()];
        let (mut engine, _) = Engine::new(
            rules.iter(),
            &VarTable::new(BTreeMap::new(), BTreeMap::new()),
            EngineLimits {
                inspection_window: 4_096,
                ..EngineLimits::default()
            },
        );

        let mut alerts = Vec::new();
        for index in 0..1_000u64 {
            engine.inspect_stream(1, tuple(), true, &[b'x'; 512], at(index), &mut alerts);
        }
        assert!(engine.counters().inspection_bytes_dropped > 0);
        assert!(alerts.is_empty());
    }

    #[test]
    fn flowbits_carry_state_between_inspections() {
        let mut engine = engine(&[
            r#"alert tcp any any -> any any (msg:"login"; content:"LOGIN"; flowbits:set,in; flowbits:noalert; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"after login"; flowbits:isset,in; content:"SECRET"; sid:2;)"#,
        ]);
        let mut alerts = Vec::new();

        engine.inspect_packet(7, tuple(), true, b"SECRET first", at(0), &mut alerts);
        assert!(alerts.is_empty(), "the bit is not set yet");

        engine.inspect_packet(7, tuple(), true, b"LOGIN ok", at(1), &mut alerts);
        assert!(alerts.is_empty(), "the setter does not alert");

        engine.inspect_packet(7, tuple(), true, b"SECRET now", at(2), &mut alerts);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].sid, 2);
    }

    #[test]
    fn flowbits_are_kept_per_flow() {
        let mut engine = engine(&[
            r#"alert tcp any any -> any any (msg:"set"; content:"LOGIN"; flowbits:set,in; flowbits:noalert; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"use"; flowbits:isset,in; content:"SECRET"; sid:2;)"#,
        ]);
        let mut alerts = Vec::new();
        engine.inspect_packet(1, tuple(), true, b"LOGIN", at(0), &mut alerts);
        engine.inspect_packet(2, tuple(), true, b"SECRET", at(1), &mut alerts);
        assert!(alerts.is_empty(), "another flow's bit must not apply");
    }

    #[test]
    fn a_flow_ending_releases_its_state() {
        let mut engine = engine(&[
            r#"alert tcp any any -> any any (msg:"m"; content:"x"; flowbits:set,b; sid:1;)"#,
        ]);
        let mut alerts = Vec::new();
        engine.inspect_packet(1, tuple(), true, b"x", at(0), &mut alerts);
        assert_eq!(engine.counters().flow_states, 1);

        engine.on_flow_end(1);
        assert_eq!(engine.counters().flow_states, 0);
    }

    #[test]
    fn the_flow_state_table_is_bounded() {
        let rules = [parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; content:"x"; flowbits:set,b; sid:1;)"#,
        )
        .unwrap()];
        let (mut engine, _) = Engine::new(
            rules.iter(),
            &VarTable::new(BTreeMap::new(), BTreeMap::new()),
            EngineLimits {
                max_flow_states: 32,
                ..EngineLimits::default()
            },
        );

        let mut alerts = Vec::new();
        for flow in 0..1_000u64 {
            engine.inspect_packet(flow, tuple(), true, b"x", at(flow), &mut alerts);
            assert!(engine.counters().flow_states <= 32);
        }
        assert!(engine.counters().flow_states_evicted > 0);
    }

    // -----------------------------------------------------------------------
    // thresholds
    // -----------------------------------------------------------------------

    #[test]
    fn a_threshold_alerts_once_per_count() {
        let mut engine = engine(&[
            r#"alert tcp any any -> any any (msg:"m"; content:"x"; threshold:type threshold, track by_src, count 3, seconds 60; sid:1;)"#,
        ]);
        let mut alerts = Vec::new();
        for index in 0..7u64 {
            engine.inspect_packet(1, tuple(), true, b"x", at(index), &mut alerts);
        }
        assert_eq!(alerts.len(), 2, "one alert per three matches");
        assert_eq!(engine.counters().thresholded, 5);
    }

    #[test]
    fn a_limit_threshold_caps_alerts_per_window() {
        let mut engine = engine(&[
            r#"alert tcp any any -> any any (msg:"m"; content:"x"; threshold:type limit, track by_src, count 2, seconds 60; sid:1;)"#,
        ]);
        let mut alerts = Vec::new();
        for index in 0..10u64 {
            engine.inspect_packet(1, tuple(), true, b"x", at(index), &mut alerts);
        }
        assert_eq!(alerts.len(), 2);

        // A new window starts and the allowance returns.
        alerts.clear();
        engine.inspect_packet(1, tuple(), true, b"x", at(100), &mut alerts);
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn thresholds_are_tracked_per_source() {
        let mut engine = engine(&[
            r#"alert tcp any any -> any any (msg:"m"; content:"x"; threshold:type limit, track by_src, count 1, seconds 60; sid:1;)"#,
        ]);
        let mut alerts = Vec::new();
        let mut second = tuple();
        second.src_ip = "192.0.2.99".parse().unwrap();

        engine.inspect_packet(1, tuple(), true, b"x", at(0), &mut alerts);
        engine.inspect_packet(1, tuple(), true, b"x", at(1), &mut alerts);
        engine.inspect_packet(2, second, true, b"x", at(2), &mut alerts);

        assert_eq!(alerts.len(), 2, "each source gets its own allowance");
    }
}
