//! Local correlation and deduplication (**Phase 4, deepened in Phase 7**).
//!
//! CyberSentinel watches a host two ways at once, and the two halves see
//! different sides of the same event. A web shell dropped through an upload is
//! a network alert on the request *and* a FIM event on the file that appeared.
//! A brute-force that succeeds is an auth event *and* the outbound connection
//! the session then makes. Reported separately, each is a line in a log that
//! somebody has to join by hand. Reported together, it is one incident with the
//! evidence attached.
//!
//! Any anomaly scoring added later stays a separate, alert-only path — the
//! base-rate fallacy makes anomaly scores a poor primary detector (guide §7,
//! Phase 7).
//!
//! # What "together" means here
//!
//! Two conditions, both required:
//!
//! * **Same host.** Correlation is local — this sensor's host — so the join key
//!   is the host name stamped on every event. Nothing here tries to correlate
//!   across machines; that is a fleet-level problem and belongs somewhere with
//!   a fleet-level view.
//! * **Within the window.** Events separated by an hour are not evidence of
//!   each other. The window is configurable and short by default.
//!
//! And one more thing that matters more than either: **the contributors must
//! span both domains.** Two network alerts are not an incident, they are two
//! network alerts, and deduplication is what that calls for. What makes an
//! incident worth raising above its parts is that host-side and network-side
//! evidence agree — the combination a single noisy rule cannot produce on its
//! own.
//!
//! # Bounded, like everything else
//!
//! The observation window is capped in both directions: a maximum number of
//! hosts and a maximum number of observations per host. Anyone who can generate
//! events — which is to say any attacker — must not be able to grow this table
//! without limit. Drops are counted, never silent.

use cybersentinel_common::event::{
    CorrelationStats, EventKind, IncidentContributor, IncidentEvent,
};
use cybersentinel_common::time::Timestamp;
use std::collections::BTreeMap;
use std::time::Duration;

/// Default window within which events are treated as related.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(120);
/// Default cap on hosts tracked at once.
pub const DEFAULT_MAX_HOSTS: usize = 1_024;
/// Default cap on observations retained per host.
pub const DEFAULT_MAX_PER_HOST: usize = 256;
/// Default quiet period after an incident before the same host raises another.
pub const DEFAULT_COOLDOWN: Duration = Duration::from_secs(300);

/// How aggressively to collapse repeated alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum DedupeMode {
    /// Emit every alert.
    Off,
    /// Collapse identical alerts within a time window.
    #[default]
    Window,
}

/// Which half of the sensor an observation came from.
///
/// The distinction is the whole point: an incident requires both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Domain {
    /// Packets — alerts, anomalies, flows.
    Network,
    /// The host — file changes, authentication, processes.
    Host,
}

impl Domain {
    /// Which domain an event kind belongs to, if either.
    ///
    /// `Alert` maps to the network side because that is where most alerts come
    /// from. Alerts raised by *host* rules are offered as [`Self::Host`]
    /// explicitly by the caller, which knows the SID and therefore knows which
    /// engine produced them — better than guessing from the event type here.
    #[must_use]
    pub fn of(kind: EventKind) -> Option<Self> {
        match kind {
            EventKind::Alert | EventKind::Anomaly | EventKind::Flow => Some(Self::Network),
            EventKind::Fim | EventKind::Auth | EventKind::Process => Some(Self::Host),
            // An incident must not feed itself back in, and stats are not
            // evidence of anything.
            EventKind::Incident | EventKind::Stats => None,
        }
    }
}

/// One thing worth correlating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The host it happened on.
    pub host: String,
    /// When.
    pub timestamp: Timestamp,
    /// Which half of the sensor saw it.
    pub domain: Domain,
    /// The event type, carried through to the incident's contributor list.
    pub event_type: EventKind,
    /// Signature id, for observations that were alerts.
    pub sid: Option<u32>,
    /// Severity, used to rank the incident.
    pub severity: u8,
    /// A one-line description for the incident summary.
    pub summary: String,
}

/// Tuning.
#[derive(Debug, Clone, Copy)]
pub struct CorrelationSettings {
    /// How far apart two events can be and still be one incident.
    pub window: Duration,
    /// Most hosts tracked at once.
    pub max_hosts: usize,
    /// Most observations retained per host.
    pub max_per_host: usize,
    /// Quiet period after an incident on a host.
    pub cooldown: Duration,
}

impl Default for CorrelationSettings {
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            max_hosts: DEFAULT_MAX_HOSTS,
            max_per_host: DEFAULT_MAX_PER_HOST,
            cooldown: DEFAULT_COOLDOWN,
        }
    }
}

/// The correlator.
#[derive(Debug)]
pub struct Correlator {
    settings: CorrelationSettings,
    /// Recent observations per host.
    windows: BTreeMap<String, Vec<Observation>>,
    /// When each host last produced an incident, for the cooldown.
    last_incident: BTreeMap<String, Timestamp>,
    stats: CorrelationStats,
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new(CorrelationSettings::default())
    }
}

impl Correlator {
    /// Build a correlator.
    #[must_use]
    pub fn new(settings: CorrelationSettings) -> Self {
        Self {
            settings,
            windows: BTreeMap::new(),
            last_incident: BTreeMap::new(),
            stats: CorrelationStats {
                enabled: true,
                ..CorrelationStats::default()
            },
        }
    }

    /// The counters so far.
    #[must_use]
    pub fn stats(&self) -> &CorrelationStats {
        &self.stats
    }

    /// Offer an observation, and get back an incident if this one completed a
    /// cross-domain pairing.
    ///
    /// Returns at most one incident per call. The observation is retained
    /// either way, because the *next* one may be what completes the picture.
    pub fn observe(&mut self, observation: Observation) -> Option<IncidentEvent> {
        self.stats.observations += 1;

        // Trim first, so a host that has been quiet for an hour does not
        // correlate against evidence from an hour ago.
        self.expire(observation.timestamp);

        if !self.windows.contains_key(&observation.host)
            && self.windows.len() >= self.settings.max_hosts
        {
            // A bound that bites is a coverage gap, and it is counted as one.
            self.stats.dropped += 1;
            return None;
        }

        let window = self.windows.entry(observation.host.clone()).or_default();
        if window.len() >= self.settings.max_per_host {
            // Drop the oldest rather than refuse the newest: the most recent
            // evidence is the most likely to be part of what is happening now.
            window.remove(0);
            self.stats.dropped += 1;
        }
        window.push(observation.clone());

        self.try_correlate(&observation)
    }

    /// Drop observations that have fallen out of the window.
    fn expire(&mut self, now: Timestamp) {
        let window = self.settings.window;
        self.windows.retain(|_, observations| {
            observations.retain(|observation| within(observation.timestamp, now, window));
            !observations.is_empty()
        });
        let cooldown = self.settings.cooldown;
        self.last_incident
            .retain(|_, when| within(*when, now, cooldown));
    }

    /// Look for a cross-domain pairing that includes the newest observation.
    fn try_correlate(&mut self, trigger: &Observation) -> Option<IncidentEvent> {
        if let Some(previous) = self.last_incident.get(&trigger.host) {
            if within(*previous, trigger.timestamp, self.settings.cooldown) {
                // Already raised for this host recently. Repeating it would
                // turn one incident into a stream of them, which is the noise
                // correlation exists to remove.
                return None;
            }
        }

        let window = self.windows.get(&trigger.host)?;
        let opposite = match trigger.domain {
            Domain::Network => Domain::Host,
            Domain::Host => Domain::Network,
        };
        // The pairing must genuinely span both halves of the sensor. Two
        // network alerts agreeing with each other is not corroboration.
        if !window
            .iter()
            .any(|observation| observation.domain == opposite)
        {
            return None;
        }

        let mut contributors: Vec<&Observation> = window.iter().collect();
        contributors.sort_by_key(|observation| observation.timestamp);

        let first_seen = contributors.first()?.timestamp;
        let last_seen = contributors.last()?.timestamp;
        // Severity is lowest-number-is-worst throughout CyberSentinel, so the
        // incident inherits its most severe contributor.
        let severity = contributors
            .iter()
            .map(|observation| observation.severity)
            .min()
            .unwrap_or(3);

        let incident = IncidentEvent {
            reason: describe(&contributors),
            severity,
            first_seen,
            last_seen,
            contributors: contributors
                .iter()
                .map(|observation| IncidentContributor {
                    event_type: observation.event_type,
                    sid: observation.sid,
                    summary: observation.summary.clone(),
                    timestamp: observation.timestamp,
                })
                .collect(),
        };

        self.stats.incidents += 1;
        self.last_incident
            .insert(trigger.host.clone(), trigger.timestamp);
        Some(incident)
    }
}

/// Whether `earlier` is within `window` of `now`.
///
/// Absolute difference, not signed: a live host sensor and a replayed capture
/// can interleave imperfectly, and treating a one-second reordering as "an hour
/// apart" would break correlation for no good reason.
fn within(earlier: Timestamp, now: Timestamp, window: Duration) -> bool {
    let difference = now.as_offset_date_time() - earlier.as_offset_date_time();
    difference.abs().unsigned_abs() <= window
}

/// One line saying why these events were grouped.
fn describe(contributors: &[&Observation]) -> String {
    let host_side = contributors
        .iter()
        .filter(|observation| observation.domain == Domain::Host)
        .count();
    let network_side = contributors.len() - host_side;
    format!(
        "{network_side} network and {host_side} host observations on the same host within the correlation window"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_offset_date_time(
            OffsetDateTime::from_unix_timestamp(1_700_000_000 + seconds).expect("a valid time"),
        )
    }

    fn network(host: &str, seconds: i64, sid: u32) -> Observation {
        Observation {
            host: host.to_string(),
            timestamp: at(seconds),
            domain: Domain::Network,
            event_type: EventKind::Alert,
            sid: Some(sid),
            severity: 2,
            summary: format!("network alert {sid}"),
        }
    }

    fn host_fim(host: &str, seconds: i64, path: &str) -> Observation {
        Observation {
            host: host.to_string(),
            timestamp: at(seconds),
            domain: Domain::Host,
            event_type: EventKind::Fim,
            sid: None,
            severity: 3,
            summary: format!("file changed: {path}"),
        }
    }

    /// The acceptance case: a file change and a network alert on the same host,
    /// close together, are one incident rather than two lines in a log.
    #[test]
    fn a_host_event_and_a_network_alert_correlate_into_one_incident() {
        let mut correlator = Correlator::default();

        assert!(
            correlator
                .observe(host_fim("web01", 0, "/var/www/upload.php"))
                .is_none(),
            "one half is not an incident yet"
        );

        let incident = correlator
            .observe(network("web01", 5, 9_000_001))
            .expect("the pairing completes the incident");

        assert_eq!(incident.contributors.len(), 2);
        assert_eq!(incident.first_seen, at(0));
        assert_eq!(incident.last_seen, at(5));
        assert_eq!(
            incident.severity, 2,
            "the incident inherits its most severe contributor"
        );
        assert!(incident
            .contributors
            .iter()
            .any(|contributor| contributor.event_type == EventKind::Fim));
        assert!(incident
            .contributors
            .iter()
            .any(|contributor| contributor.sid == Some(9_000_001)));
        assert_eq!(correlator.stats().incidents, 1);
    }

    #[test]
    fn it_correlates_in_either_order() {
        let mut correlator = Correlator::default();
        assert!(correlator.observe(network("web01", 0, 1)).is_none());
        assert!(correlator
            .observe(host_fim("web01", 3, "/etc/passwd"))
            .is_some());
    }

    #[test]
    fn contributors_are_listed_in_time_order() {
        let mut correlator = Correlator::default();
        correlator.observe(host_fim("web01", 10, "/a"));
        correlator.observe(host_fim("web01", 2, "/b"));
        let incident = correlator
            .observe(network("web01", 20, 7))
            .expect("incident");

        let times: Vec<_> = incident
            .contributors
            .iter()
            .map(|contributor| contributor.timestamp)
            .collect();
        let mut sorted = times.clone();
        sorted.sort_unstable();
        assert_eq!(times, sorted);
    }

    // -----------------------------------------------------------------------
    // what must *not* correlate
    // -----------------------------------------------------------------------

    #[test]
    fn events_on_different_hosts_are_not_one_incident() {
        let mut correlator = Correlator::default();
        correlator.observe(host_fim("web01", 0, "/etc/passwd"));
        assert!(
            correlator.observe(network("db02", 5, 1)).is_none(),
            "correlation joins on host; two machines are two stories"
        );
    }

    #[test]
    fn events_outside_the_window_are_not_one_incident() {
        let mut correlator = Correlator::new(CorrelationSettings {
            window: Duration::from_secs(60),
            ..CorrelationSettings::default()
        });
        correlator.observe(host_fim("web01", 0, "/etc/passwd"));
        assert!(
            correlator.observe(network("web01", 3_600, 1)).is_none(),
            "an hour apart is not evidence of each other"
        );
    }

    /// Two alerts from the same half of the sensor are repetition, not
    /// corroboration. Raising an incident for them would launder one noisy rule
    /// into something that looks like agreement between independent detectors.
    #[test]
    fn two_network_alerts_alone_are_not_an_incident() {
        let mut correlator = Correlator::default();
        correlator.observe(network("web01", 0, 1));
        assert!(correlator.observe(network("web01", 1, 2)).is_none());
        assert_eq!(correlator.stats().incidents, 0);
    }

    #[test]
    fn two_host_events_alone_are_not_an_incident() {
        let mut correlator = Correlator::default();
        correlator.observe(host_fim("web01", 0, "/a"));
        assert!(correlator.observe(host_fim("web01", 1, "/b")).is_none());
    }

    #[test]
    fn a_correlated_host_stays_quiet_for_the_cooldown() {
        let mut correlator = Correlator::default();
        correlator.observe(host_fim("web01", 0, "/a"));
        assert!(correlator.observe(network("web01", 1, 1)).is_some());

        // More of the same activity is the same incident, not a new one.
        assert!(correlator.observe(host_fim("web01", 2, "/b")).is_none());
        assert!(correlator.observe(network("web01", 3, 2)).is_none());
        assert_eq!(correlator.stats().incidents, 1);
    }

    #[test]
    fn the_cooldown_expires() {
        let mut correlator = Correlator::new(CorrelationSettings {
            window: Duration::from_secs(60),
            cooldown: Duration::from_secs(60),
            ..CorrelationSettings::default()
        });
        correlator.observe(host_fim("web01", 0, "/a"));
        assert!(correlator.observe(network("web01", 1, 1)).is_some());

        correlator.observe(host_fim("web01", 1_000, "/b"));
        assert!(correlator.observe(network("web01", 1_001, 2)).is_some());
        assert_eq!(correlator.stats().incidents, 2);
    }

    // -----------------------------------------------------------------------
    // bounds
    // -----------------------------------------------------------------------

    #[test]
    fn the_host_table_is_bounded_and_drops_are_counted() {
        let mut correlator = Correlator::new(CorrelationSettings {
            max_hosts: 2,
            ..CorrelationSettings::default()
        });
        for index in 0..10 {
            correlator.observe(host_fim(&format!("host{index}"), 0, "/a"));
        }
        assert!(correlator.stats().dropped > 0);
    }

    #[test]
    fn the_per_host_window_is_bounded() {
        let mut correlator = Correlator::new(CorrelationSettings {
            max_per_host: 4,
            ..CorrelationSettings::default()
        });
        for index in 0..20 {
            correlator.observe(host_fim("web01", i64::from(index), "/a"));
        }
        // The newest evidence survives; the oldest is what gives way.
        let incident = correlator
            .observe(network("web01", 20, 1))
            .expect("incident");
        assert!(incident.contributors.len() <= 5);
        assert!(correlator.stats().dropped > 0);
    }

    #[test]
    fn expired_observations_do_not_accumulate() {
        let mut correlator = Correlator::new(CorrelationSettings {
            window: Duration::from_secs(10),
            ..CorrelationSettings::default()
        });
        for index in 0..100 {
            correlator.observe(host_fim("web01", i64::from(index) * 60, "/a"));
        }
        assert_eq!(
            correlator.windows.get("web01").map(Vec::len),
            Some(1),
            "each observation is a minute past the last; none should survive"
        );
    }

    #[test]
    fn events_that_are_slightly_out_of_order_still_correlate() {
        let mut correlator = Correlator::default();
        correlator.observe(network("web01", 10, 1));
        assert!(correlator.observe(host_fim("web01", 8, "/a")).is_some());
    }

    #[test]
    fn domains_are_assigned_to_every_event_kind() {
        assert_eq!(Domain::of(EventKind::Alert), Some(Domain::Network));
        assert_eq!(Domain::of(EventKind::Fim), Some(Domain::Host));
        assert_eq!(Domain::of(EventKind::Auth), Some(Domain::Host));
        assert_eq!(Domain::of(EventKind::Process), Some(Domain::Host));
        assert_eq!(
            Domain::of(EventKind::Incident),
            None,
            "an incident must not feed itself back in"
        );
        assert_eq!(Domain::of(EventKind::Stats), None);
    }
}
