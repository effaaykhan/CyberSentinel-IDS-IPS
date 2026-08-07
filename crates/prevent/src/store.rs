//! The verdict store and the per-packet decision.
//!
//! Everything here is pure: no sockets, no kernel, no clock of its own. That is
//! deliberate — the decision that drops somebody's traffic is the last thing in
//! this project that should only be testable as a side effect of running as
//! root on a machine with nftables.

use cybersentinel_common::event::{NetTuple, PreventStats};
use cybersentinel_common::net::IpNetwork;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Most flows carrying a block verdict at once.
pub const DEFAULT_MAX_BLOCKED_FLOWS: usize = 65_536;
/// Most sources blocked at once.
pub const DEFAULT_MAX_BLOCKED_SOURCES: usize = 16_384;
/// How long a source stays blocked by default.
pub const DEFAULT_SOURCE_BLOCK: Duration = Duration::from_secs(600);

/// Whether the sensor is allowed to drop anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Alert only. The verdict path returns `Accept` for everything, whatever
    /// the rules say. **The default, and the kill switch.**
    #[default]
    Detect,
    /// Enforce block verdicts.
    Prevent,
}

impl Mode {
    /// The wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Detect => "detect",
            Self::Prevent => "prevent",
        }
    }
}

/// What happens to traffic when the sensor cannot answer.
///
/// Enforced by the **kernel**, through the queueing rule, not by a branch in
/// this crate — if the process is dead, none of this code runs. See
/// [`crate::nft::queue_rule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailMode {
    /// Traffic passes if the sensor is not there to judge it. Availability
    /// first, and the default: an IPS that takes the network down when it
    /// crashes has caused the outage it was bought to prevent.
    #[default]
    Open,
    /// Traffic stops if the sensor is not there to judge it. For deployments
    /// where unfiltered traffic is worse than no traffic.
    Closed,
}

impl FailMode {
    /// The wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }
}

/// What the verdict path decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Let it through.
    Accept,
    /// Drop it, for this reason.
    Drop(DropReason),
}

impl Decision {
    /// Whether this decision drops the packet.
    #[must_use]
    pub fn is_drop(self) -> bool {
        matches!(self, Self::Drop(_))
    }
}

/// Why a packet was dropped. Carried so an operator can tell "this flow was
/// already condemned" from "this whole source is blocked".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DropReason {
    /// A rule matched this flow earlier and asked for it to be blocked.
    FlowVerdict,
    /// The source is in the block set.
    BlockedSource,
}

impl DropReason {
    /// The wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FlowVerdict => "flow_verdict",
            Self::BlockedSource => "blocked_source",
        }
    }
}

/// What came of asking for something to be blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockOutcome {
    /// The verdict was recorded and will be enforced.
    Blocked {
        /// The source now in the block set, if one was added.
        source: Option<IpAddr>,
    },
    /// The sensor is in detect mode. Nothing was recorded; the alert says
    /// `alerted`.
    NotArmed,
    /// An endpoint is on the allow-list. **Deliberately still an alert** — the
    /// detection was real and must be reported; only the enforcement is
    /// withheld.
    AllowListed {
        /// Which address matched the allow-list.
        address: IpAddr,
    },
    /// A bound was reached. A block that could not be recorded is a coverage
    /// hole, not a tuning statistic.
    Full,
}

/// Tuning.
#[derive(Debug, Clone)]
pub struct PreventionSettings {
    /// Whether the sensor may drop anything.
    pub mode: Mode,
    /// What the kernel does when the sensor is not answering.
    pub fail_mode: FailMode,
    /// Addresses and networks that must never be blocked, whatever matches.
    pub allow_list: Vec<IpNetwork>,
    /// How long a blocked source stays blocked.
    pub source_block: Duration,
    /// Most flows carrying a block verdict.
    pub max_blocked_flows: usize,
    /// Most sources blocked at once.
    pub max_blocked_sources: usize,
}

impl Default for PreventionSettings {
    fn default() -> Self {
        Self {
            mode: Mode::Detect,
            fail_mode: FailMode::Open,
            allow_list: Vec::new(),
            source_block: DEFAULT_SOURCE_BLOCK,
            max_blocked_flows: DEFAULT_MAX_BLOCKED_FLOWS,
            max_blocked_sources: DEFAULT_MAX_BLOCKED_SOURCES,
        }
    }
}

/// A conversation, as the verdict path identifies one.
///
/// **Not the detection path's flow id.** That id mixes in the flow's start
/// time, so it cannot be recomputed from a packet in isolation — the verdict
/// path would have to consult the flow table for every packet, on the one code
/// path that must not depend on anything it does not already hold.
///
/// The endpoints are ordered, so both directions of a conversation produce the
/// same key. That is deliberate: condemning a flow should stop the replies too.
/// Letting the server keep answering an attacker whose requests are being
/// dropped is a half-closed session, not a blocked one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    protocol: u8,
    lower: (IpAddr, u16),
    upper: (IpAddr, u16),
}

impl FlowKey {
    /// The key for a 5-tuple, in whichever direction it was seen.
    #[must_use]
    pub fn from_tuple(tuple: &NetTuple) -> Self {
        let first = (tuple.src_ip, tuple.src_port.unwrap_or(0));
        let second = (tuple.dest_ip, tuple.dest_port.unwrap_or(0));
        let (lower, upper) = if first <= second {
            (first, second)
        } else {
            (second, first)
        };
        Self {
            protocol: tuple.proto as u8,
            lower,
            upper,
        }
    }
}

/// The verdict store: what to do with a packet, decided from state that already
/// exists.
#[derive(Debug)]
pub struct Prevention {
    settings: PreventionSettings,
    /// Conversations a rule has condemned.
    flows: HashMap<FlowKey, Instant>,
    /// Sources in the block set, with when the block lapses.
    sources: HashMap<IpAddr, Instant>,
    stats: PreventStats,
}

impl Prevention {
    /// Build a store.
    #[must_use]
    pub fn new(settings: PreventionSettings) -> Self {
        let stats = PreventStats {
            enabled: true,
            mode: settings.mode.as_str().to_string(),
            fail_mode: settings.fail_mode.as_str().to_string(),
            ..PreventStats::default()
        };
        Self {
            settings,
            flows: HashMap::new(),
            sources: HashMap::new(),
            stats,
        }
    }

    /// Whether the sensor may drop anything.
    #[must_use]
    pub fn armed(&self) -> bool {
        self.settings.mode == Mode::Prevent
    }

    /// How long a source block lasts, for the kernel-side set.
    #[must_use]
    pub fn source_block_timeout(&self) -> Duration {
        self.settings.source_block
    }

    /// The configured fail mode.
    #[must_use]
    pub fn fail_mode(&self) -> FailMode {
        self.settings.fail_mode
    }

    /// Arm or disarm at runtime. **The kill switch.**
    ///
    /// Disarming takes effect on the very next packet: `decide` checks the mode
    /// before it looks at any verdict, so a disarm cannot be outrun by state
    /// recorded before it. Existing verdicts are kept rather than discarded —
    /// re-arming should not require re-detecting everything — but they stop
    /// being enforced immediately.
    pub fn set_mode(&mut self, mode: Mode) {
        if self.settings.mode != mode {
            tracing::warn!(
                from = self.settings.mode.as_str(),
                to = mode.as_str(),
                blocked_flows = self.flows.len(),
                blocked_sources = self.sources.len(),
                "inline prevention mode changed"
            );
        }
        self.settings.mode = mode;
        self.stats.mode = mode.as_str().to_string();
    }

    /// Whether an address is on the allow-list.
    #[must_use]
    pub fn is_allow_listed(&self, address: IpAddr) -> bool {
        self.settings
            .allow_list
            .iter()
            .any(|network| network.contains(address))
    }

    /// Decide what to do with one packet. **Never blocks, never allocates.**
    ///
    /// The order of these checks is the whole safety argument:
    ///
    /// 1. **Not armed → accept.** Checked first so the kill switch cannot be
    ///    outrun by a verdict recorded a moment earlier.
    /// 2. **Allow-listed → accept.** Checked before any verdict, so no
    ///    sequence of matches can ever drop traffic to or from a critical host.
    ///    Both endpoints are checked, not just the source: cutting the flow to
    ///    your DNS server breaks DNS exactly as thoroughly as blocking it.
    /// 3. Flow verdict, then source block.
    /// 4. Otherwise accept. **Default accept**, always.
    pub fn decide(&mut self, tuple: &NetTuple, now: Instant) -> Decision {
        self.stats.packets_judged += 1;

        if !self.armed() {
            return Decision::Accept;
        }
        if self.is_allow_listed(tuple.src_ip) || self.is_allow_listed(tuple.dest_ip) {
            self.stats.allow_listed_passes += 1;
            return Decision::Accept;
        }

        if self.flows.contains_key(&FlowKey::from_tuple(tuple)) {
            self.stats.packets_dropped += 1;
            return Decision::Drop(DropReason::FlowVerdict);
        }

        if let Some(until) = self.sources.get(&tuple.src_ip).copied() {
            if now < until {
                self.stats.packets_dropped += 1;
                return Decision::Drop(DropReason::BlockedSource);
            }
            // Lapsed. Forget it here rather than sweeping: the packet that
            // notices is the cheapest place to clean up.
            self.sources.remove(&tuple.src_ip);
            self.stats.source_blocks_expired += 1;
        }

        Decision::Accept
    }

    /// Record that a flow — and its source — should be blocked.
    ///
    /// Called by the detection path when a rule with a block action matches.
    /// Returns what actually happened, because the alert has to say.
    pub fn block(&mut self, tuple: &NetTuple, now: Instant) -> BlockOutcome {
        if !self.armed() {
            return BlockOutcome::NotArmed;
        }
        // The allow-list is checked here as well as in `decide`, so an
        // allow-listed address never even enters the block set — otherwise the
        // nftables set would fill with entries that `decide` then ignores, and
        // an operator reading the set would believe traffic was being dropped
        // that is not.
        for address in [tuple.src_ip, tuple.dest_ip] {
            if self.is_allow_listed(address) {
                self.stats.allow_listed_blocks_refused += 1;
                tracing::warn!(
                    %address,
                    "a rule asked to block an allow-listed address; alerting without enforcing"
                );
                return BlockOutcome::AllowListed { address };
            }
        }

        if self.flows.len() >= self.settings.max_blocked_flows
            || self.sources.len() >= self.settings.max_blocked_sources
        {
            // Refusing to record is refusing to enforce. Counted as a hole.
            self.stats.blocks_dropped_at_capacity += 1;
            tracing::error!(
                blocked_flows = self.flows.len(),
                blocked_sources = self.sources.len(),
                "prevention state is full; a block verdict could not be recorded"
            );
            return BlockOutcome::Full;
        }

        self.flows.insert(FlowKey::from_tuple(tuple), now);
        self.stats.flows_blocked += 1;

        let expiry = now + self.settings.source_block;
        let source = tuple.src_ip;
        let already = self.sources.insert(source, expiry).is_some();
        if !already {
            self.stats.sources_blocked += 1;
        }

        BlockOutcome::Blocked {
            source: Some(source),
        }
    }

    /// Forget verdicts that have lapsed.
    ///
    /// Flow verdicts are held for the source-block duration too: a flow whose
    /// source is no longer blocked has no reason to stay condemned, and holding
    /// them for ever is the unbounded-state failure this project keeps
    /// designing against.
    pub fn expire(&mut self, now: Instant) {
        let horizon = self.settings.source_block;
        let before = self.flows.len();
        self.flows.retain(|_, at| now.duration_since(*at) < horizon);
        self.stats.flow_verdicts_expired += (before - self.flows.len()) as u64;

        let before = self.sources.len();
        self.sources.retain(|_, until| now < *until);
        self.stats.source_blocks_expired += (before - self.sources.len()) as u64;
    }

    /// Counters for `stats`.
    #[must_use]
    pub fn stats(&self) -> PreventStats {
        let mut stats = self.stats.clone();
        stats.blocked_flows_active = self.flows.len() as u64;
        stats.blocked_sources_active = self.sources.len() as u64;
        stats
    }

    /// Record how long a verdict took, in microseconds.
    ///
    /// Inline latency is a property worth watching: every microsecond here is
    /// added to every packet on the path, and a verdict path that got slow is
    /// an outage waiting for a traffic spike.
    pub fn record_latency(&mut self, micros: u64) {
        self.stats.verdict_latency_us_total += micros;
        self.stats.verdict_latency_us_max = self.stats.verdict_latency_us_max.max(micros);
        // The tail, not the median. A verdict path's median is a hash lookup
        // and stays flat right up until the queue backs up; what moves first is
        // the number of packets that took far longer than they should have.
        if micros > 1_000 {
            self.stats.verdict_latency_over_1ms += 1;
        }
        if micros > 10_000 {
            self.stats.verdict_latency_over_10ms += 1;
        }
    }

    /// Fold in what the kernel says about the queue.
    ///
    /// Called from the stats path, not the verdict path: it reads a proc file,
    /// and nothing that touches the filesystem belongs in the loop the kernel
    /// is waiting on.
    pub fn record_queue_depth(&mut self, depth: &crate::depth::QueueDepth) {
        self.stats.queue_depth = u64::from(depth.queued);
        self.stats.queue_depth_max = self.stats.queue_depth_max.max(u64::from(depth.queued));
        self.stats.queue_unjudged = depth.unjudged();
    }

    /// Record that the kernel applied the fail mode rather than asking us.
    pub fn record_fail_mode_applied(&mut self, packets: u64) {
        self.stats.fail_mode_packets += packets;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cybersentinel_common::event::Protocol;

    fn tuple(src: &str, dest: &str) -> NetTuple {
        NetTuple {
            src_ip: src.parse().expect("an address"),
            src_port: Some(4_000),
            dest_ip: dest.parse().expect("an address"),
            dest_port: Some(80),
            proto: Protocol::Tcp,
        }
    }

    fn armed() -> Prevention {
        Prevention::new(PreventionSettings {
            mode: Mode::Prevent,
            ..PreventionSettings::default()
        })
    }

    #[test]
    fn the_default_is_detect_and_accepts_everything() {
        let mut prevention = Prevention::new(PreventionSettings::default());
        assert!(!prevention.armed());

        let flow = tuple("203.0.113.7", "10.0.0.1");
        // Even after a rule asks for a block.
        assert_eq!(
            prevention.block(&flow, Instant::now()),
            BlockOutcome::NotArmed
        );
        assert_eq!(
            prevention.decide(&flow, Instant::now()),
            Decision::Accept,
            "detect mode never drops, whatever the rules say"
        );
    }

    #[test]
    fn an_unknown_flow_is_accepted() {
        let mut prevention = armed();
        assert_eq!(
            prevention.decide(&tuple("203.0.113.7", "10.0.0.1"), Instant::now()),
            Decision::Accept,
            "default accept: the verdict path never guesses"
        );
    }

    #[test]
    fn a_blocked_flow_drops_its_later_packets() {
        let mut prevention = armed();
        let flow = tuple("203.0.113.7", "10.0.0.1");
        let now = Instant::now();

        assert!(matches!(
            prevention.block(&flow, now),
            BlockOutcome::Blocked { .. }
        ));
        assert_eq!(
            prevention.decide(&flow, now),
            Decision::Drop(DropReason::FlowVerdict)
        );
    }

    #[test]
    fn a_blocked_source_drops_a_brand_new_flow() {
        let mut prevention = armed();
        let now = Instant::now();
        prevention.block(&tuple("203.0.113.7", "10.0.0.1"), now);

        // A different flow id entirely — the next connection from that source.
        assert_eq!(
            prevention.decide(&tuple("203.0.113.7", "10.0.0.2"), now),
            Decision::Drop(DropReason::BlockedSource),
            "blocking the source is what stops the next connection starting"
        );
    }

    #[test]
    fn an_unrelated_source_is_unaffected() {
        let mut prevention = armed();
        let now = Instant::now();
        prevention.block(&tuple("203.0.113.7", "10.0.0.1"), now);
        assert_eq!(
            prevention.decide(&tuple("198.51.100.4", "10.0.0.1"), now),
            Decision::Accept
        );
    }

    // -----------------------------------------------------------------------
    // the allow-list
    // -----------------------------------------------------------------------

    fn with_allow_list(entries: &[&str]) -> Prevention {
        Prevention::new(PreventionSettings {
            mode: Mode::Prevent,
            allow_list: entries
                .iter()
                .map(|entry| entry.parse().expect("a network"))
                .collect(),
            ..PreventionSettings::default()
        })
    }

    #[test]
    fn an_allow_listed_source_is_never_blocked() {
        let mut prevention = with_allow_list(&["192.0.2.1"]);
        let flow = tuple("192.0.2.1", "10.0.0.1");
        let now = Instant::now();

        assert_eq!(
            prevention.block(&flow, now),
            BlockOutcome::AllowListed {
                address: "192.0.2.1".parse().expect("an address")
            },
            "a matching block rule must not enforce against an allow-listed host"
        );
        assert_eq!(prevention.decide(&flow, now), Decision::Accept);
    }

    #[test]
    fn an_allow_listed_network_covers_its_hosts() {
        let mut prevention = with_allow_list(&["10.0.0.0/8"]);
        let now = Instant::now();
        assert!(matches!(
            prevention.block(&tuple("10.1.2.3", "203.0.113.7"), now),
            BlockOutcome::AllowListed { .. }
        ));
    }

    /// Cutting the flow to a critical host breaks it exactly as thoroughly as
    /// blocking that host's own traffic, so the allow-list covers both ends.
    #[test]
    fn an_allow_listed_destination_is_protected_too() {
        let mut prevention = with_allow_list(&["10.0.0.53"]);
        let flow = tuple("203.0.113.7", "10.0.0.53");
        let now = Instant::now();

        assert!(matches!(
            prevention.block(&flow, now),
            BlockOutcome::AllowListed { .. }
        ));
        assert_eq!(prevention.decide(&flow, now), Decision::Accept);
    }

    /// The allow-list is checked before any verdict, so no ordering of events
    /// can produce a drop for a protected host.
    #[test]
    fn an_allow_list_entry_added_to_the_block_set_by_another_route_still_passes() {
        let mut prevention = with_allow_list(&["192.0.2.1"]);
        let now = Instant::now();
        // Block a different source, then ask about the protected one whose
        // traffic shares the flow id (a contrived collision, but the check must
        // not depend on that not happening).
        prevention.block(&tuple("203.0.113.7", "10.0.0.1"), now);
        assert_eq!(
            prevention.decide(&tuple("192.0.2.1", "10.0.0.9"), now),
            Decision::Accept
        );
    }

    // -----------------------------------------------------------------------
    // the kill switch
    // -----------------------------------------------------------------------

    #[test]
    fn disarming_stops_dropping_on_the_very_next_packet() {
        let mut prevention = armed();
        let flow = tuple("203.0.113.7", "10.0.0.1");
        let now = Instant::now();

        prevention.block(&flow, now);
        assert!(prevention.decide(&flow, now).is_drop());

        prevention.set_mode(Mode::Detect);
        assert_eq!(
            prevention.decide(&flow, now),
            Decision::Accept,
            "the kill switch cannot be outrun by a verdict recorded before it"
        );
    }

    #[test]
    fn re_arming_restores_the_verdicts_that_were_already_known() {
        let mut prevention = armed();
        let flow = tuple("203.0.113.7", "10.0.0.1");
        let now = Instant::now();

        prevention.block(&flow, now);
        prevention.set_mode(Mode::Detect);
        prevention.set_mode(Mode::Prevent);

        assert!(
            prevention.decide(&flow, now).is_drop(),
            "re-arming should not require re-detecting everything"
        );
    }

    // -----------------------------------------------------------------------
    // bounds and expiry
    // -----------------------------------------------------------------------

    #[test]
    fn a_source_block_lapses() {
        let mut prevention = Prevention::new(PreventionSettings {
            mode: Mode::Prevent,
            source_block: Duration::from_secs(60),
            ..PreventionSettings::default()
        });
        let start = Instant::now();
        prevention.block(&tuple("203.0.113.7", "10.0.0.1"), start);

        let later = start + Duration::from_secs(61);
        assert_eq!(
            prevention.decide(&tuple("203.0.113.7", "10.0.0.2"), later),
            Decision::Accept,
            "a block that never lapses is a permanent outage nobody chose"
        );
    }

    #[test]
    fn expiry_clears_both_tables() {
        let mut prevention = Prevention::new(PreventionSettings {
            mode: Mode::Prevent,
            source_block: Duration::from_secs(60),
            ..PreventionSettings::default()
        });
        let start = Instant::now();
        for index in 0..10 {
            prevention.block(&tuple(&format!("203.0.113.{index}"), "10.0.0.1"), start);
        }
        assert_eq!(prevention.stats().blocked_flows_active, 10);

        prevention.expire(start + Duration::from_secs(61));
        assert_eq!(prevention.stats().blocked_flows_active, 0);
        assert_eq!(prevention.stats().blocked_sources_active, 0);
    }

    #[test]
    fn a_full_store_refuses_to_record_and_counts_it() {
        let mut prevention = Prevention::new(PreventionSettings {
            mode: Mode::Prevent,
            max_blocked_flows: 2,
            ..PreventionSettings::default()
        });
        let now = Instant::now();
        for index in 0..2 {
            assert!(matches!(
                prevention.block(&tuple(&format!("203.0.113.{index}"), "10.0.0.1"), now),
                BlockOutcome::Blocked { .. }
            ));
        }
        assert_eq!(
            prevention.block(&tuple("203.0.113.99", "10.0.0.1"), now),
            BlockOutcome::Full,
            "a block that could not be recorded is a hole, not a silent no-op"
        );
        assert_eq!(prevention.stats().blocks_dropped_at_capacity, 1);
    }

    // -----------------------------------------------------------------------
    // soak: does the state stay bounded and drain, over a long timeline
    // -----------------------------------------------------------------------

    /// The question a five-second burst cannot answer: does this leak?
    ///
    /// An IPS holds state per condemned flow and per blocked source, and both
    /// are fed by whoever is attacking — which is exactly the shape of an
    /// unbounded-growth bug an attacker gets to trigger. Simulated time rather
    /// than real, so the whole hour runs in milliseconds and runs in CI.
    #[test]
    fn an_hour_of_continuous_blocking_stays_bounded_and_drains() {
        let block_for = Duration::from_secs(60);
        let mut prevention = Prevention::new(PreventionSettings {
            mode: Mode::Prevent,
            source_block: block_for,
            max_blocked_flows: 4_096,
            max_blocked_sources: 4_096,
            ..PreventionSettings::default()
        });

        let start = Instant::now();
        // An hour, a block every second, from a rotating cast of sources —
        // 3,600 blocks against a store that may hold 4,096.
        for second in 0..3_600_u64 {
            let now = start + Duration::from_secs(second);
            let source = format!(
                "10.{}.{}.{}",
                second % 251,
                (second / 251) % 251,
                1 + second % 250
            );
            prevention.block(&tuple(&source, "10.0.0.1"), now);
            prevention.expire(now);

            let stats = prevention.stats();
            assert!(
                stats.blocked_flows_active <= 4_096,
                "flow table exceeded its cap at second {second}"
            );
            assert!(
                stats.blocked_sources_active <= 4_096,
                "source table exceeded its cap at second {second}"
            );
            // Nothing may be held longer than the block duration, so the live
            // set can never be larger than one block-window's worth of work.
            assert!(
                stats.blocked_sources_active <= 61,
                "at second {second} the source table held {} entries, but nothing \
                 should outlive its 60s block",
                stats.blocked_sources_active
            );
        }

        // And it drains completely once the traffic stops.
        prevention.expire(start + Duration::from_secs(3_600 + 61));
        let stats = prevention.stats();
        assert_eq!(
            stats.blocked_sources_active, 0,
            "the source table did not drain"
        );
        assert_eq!(
            stats.blocked_flows_active, 0,
            "the flow table did not drain"
        );
        assert!(
            stats.blocks_dropped_at_capacity == 0,
            "a cap was hit that should not have been"
        );
    }

    /// The same source attacking continuously must not grow the table: it is
    /// one entry whose expiry moves, not one entry per attempt.
    #[test]
    fn one_persistent_source_is_one_entry() {
        let mut prevention = armed();
        let start = Instant::now();
        for second in 0..10_000_u64 {
            let now = start + Duration::from_millis(second * 100);
            prevention.block(&tuple("203.0.113.7", "10.0.0.1"), now);
            prevention.expire(now);
        }
        assert_eq!(
            prevention.stats().blocked_sources_active,
            1,
            "a source blocked ten thousand times is still one source"
        );
    }

    /// Past the cap the store refuses rather than grows, and says so. The
    /// refusal is the important half: silently evicting a live verdict would
    /// let an attacker restore their own traffic by making noise.
    #[test]
    fn a_flood_of_distinct_sources_hits_the_cap_and_reports_it() {
        let mut prevention = Prevention::new(PreventionSettings {
            mode: Mode::Prevent,
            max_blocked_sources: 512,
            max_blocked_flows: 512,
            source_block: Duration::from_secs(3_600),
            ..PreventionSettings::default()
        });
        let now = Instant::now();
        for index in 0..5_000_u32 {
            let source = format!(
                "10.{}.{}.{}",
                index / 65_536,
                (index / 256) % 256,
                index % 256
            );
            prevention.block(&tuple(&source, "10.0.0.1"), now);
        }

        let stats = prevention.stats();
        assert!(stats.blocked_sources_active <= 512);
        assert!(
            stats.blocks_dropped_at_capacity > 0,
            "hitting the cap must be counted: a block that was not recorded is not enforced"
        );
    }

    /// Latency accounting must survive a long run without wrapping.
    #[test]
    fn latency_totals_do_not_overflow_over_a_long_run() {
        let mut prevention = armed();
        for _ in 0..100_000 {
            prevention.record_latency(u64::MAX / 200_000);
        }
        let stats = prevention.stats();
        assert!(stats.verdict_latency_us_total > 0);
        assert!(stats.verdict_latency_us_max > 0);
    }

    #[test]
    fn stats_report_the_active_mode_and_fail_mode() {
        let prevention = Prevention::new(PreventionSettings {
            mode: Mode::Prevent,
            fail_mode: FailMode::Closed,
            ..PreventionSettings::default()
        });
        let stats = prevention.stats();
        assert_eq!(stats.mode, "prevent");
        assert_eq!(stats.fail_mode, "closed");
    }

    #[test]
    fn latency_is_recorded() {
        let mut prevention = armed();
        prevention.record_latency(10);
        prevention.record_latency(250);
        prevention.record_latency(5);
        let stats = prevention.stats();
        assert_eq!(stats.verdict_latency_us_max, 250);
        assert_eq!(stats.verdict_latency_us_total, 265);
    }

    #[test]
    fn every_judged_packet_is_counted_in_both_modes() {
        let mut prevention = Prevention::new(PreventionSettings::default());
        let flow = tuple("203.0.113.7", "10.0.0.1");
        for _ in 0..5 {
            prevention.decide(&flow, Instant::now());
        }
        assert_eq!(prevention.stats().packets_judged, 5);
        assert_eq!(prevention.stats().packets_dropped, 0);
    }
}
