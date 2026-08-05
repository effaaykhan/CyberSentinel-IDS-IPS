//! Resolving the overlap policy for a destination host.
//!
//! Overlap policy is **configured, never guessed**. OS fingerprinting to infer
//! a stack's reassembly behaviour is itself evadable — an attacker who can
//! influence the fingerprint can choose the policy the sensor uses, which is
//! worse than having no policy at all. An operator who knows their network
//! states what is on it, and a wrong entry is at least a wrong entry someone
//! can find and correct.
//!
//! Lookups are by **destination**: the host that will act on the bytes is the
//! one whose reassembly rules matter. For a TCP stream that means the receiver
//! of that direction, so the two halves of a connection can resolve overlaps
//! differently — which is correct, because they are two different stacks.

use std::net::IpAddr;

use cybersentinel_common::config::{HostPolicy, OverlapPolicy, ReassemblyConfig};
use cybersentinel_common::IpNetwork;

/// Resolves an overlap policy for a destination address.
///
/// Longest prefix wins, so a `/32` beats a `/24` however the file was ordered.
#[derive(Debug, Clone, Default)]
pub struct PolicyResolver {
    default_policy: OverlapPolicy,
    /// Sorted by descending prefix length, so the first match is the most
    /// specific one.
    entries: Vec<(IpNetwork, OverlapPolicy)>,
}

impl PolicyResolver {
    /// Build a resolver from the configured default and overrides.
    #[must_use]
    pub fn new(default_policy: OverlapPolicy, overrides: &[HostPolicy]) -> Self {
        let mut entries: Vec<(IpNetwork, OverlapPolicy)> = overrides
            .iter()
            .map(|entry| (entry.network, entry.policy))
            .collect();
        entries.sort_by_key(|(network, _)| std::cmp::Reverse(network.prefix_len()));
        Self {
            default_policy,
            entries,
        }
    }

    /// Build a resolver from a config section.
    #[must_use]
    pub fn from_config(config: &ReassemblyConfig) -> Self {
        Self::new(config.overlap_policy, &config.host_policies)
    }

    /// The policy for data destined for `address`.
    #[must_use]
    pub fn for_destination(&self, address: IpAddr) -> OverlapPolicy {
        self.entries
            .iter()
            .find(|(network, _)| network.contains(address))
            .map_or(self.default_policy, |(_, policy)| *policy)
    }

    /// The policy used where no override matches.
    #[must_use]
    pub fn default_policy(&self) -> OverlapPolicy {
        self.default_policy
    }

    /// How many overrides are configured.
    #[must_use]
    pub fn override_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use OverlapPolicy::{First, Last};

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn entry(network: &str, policy: OverlapPolicy) -> HostPolicy {
        HostPolicy {
            network: network.parse().unwrap(),
            policy,
        }
    }

    #[test]
    fn falls_back_to_the_default_when_nothing_matches() {
        let resolver = PolicyResolver::new(First, &[entry("10.0.0.0/8", Last)]);
        assert_eq!(resolver.for_destination(ip("192.0.2.1")), First);
        assert_eq!(resolver.for_destination(ip("10.1.2.3")), Last);
    }

    #[test]
    fn the_longest_prefix_wins_regardless_of_file_order() {
        // The specific host is listed last, and must still win.
        let resolver = PolicyResolver::new(
            First,
            &[entry("10.0.0.0/8", First), entry("10.1.2.3/32", Last)],
        );
        assert_eq!(resolver.for_destination(ip("10.1.2.3")), Last);
        assert_eq!(resolver.for_destination(ip("10.1.2.4")), First);

        // ... and the same the other way round.
        let resolver = PolicyResolver::new(
            First,
            &[entry("10.1.2.3/32", Last), entry("10.0.0.0/8", First)],
        );
        assert_eq!(resolver.for_destination(ip("10.1.2.3")), Last);
    }

    #[test]
    fn a_bare_address_is_a_host_override() {
        let resolver = PolicyResolver::new(First, &[entry("192.0.2.10", Last)]);
        assert_eq!(resolver.for_destination(ip("192.0.2.10")), Last);
        assert_eq!(resolver.for_destination(ip("192.0.2.11")), First);
    }

    #[test]
    fn ipv6_overrides_work_and_do_not_affect_ipv4() {
        let resolver = PolicyResolver::new(First, &[entry("2001:db8::/32", Last)]);
        assert_eq!(resolver.for_destination(ip("2001:db8::5")), Last);
        assert_eq!(resolver.for_destination(ip("10.0.0.1")), First);
    }

    #[test]
    fn a_zero_prefix_override_covers_its_whole_family() {
        let resolver = PolicyResolver::new(First, &[entry("0.0.0.0/0", Last)]);
        assert_eq!(resolver.for_destination(ip("8.8.8.8")), Last);
        assert_eq!(
            resolver.for_destination(ip("2001:db8::1")),
            First,
            "an IPv4 catch-all must not swallow IPv6"
        );
    }

    #[test]
    fn an_empty_table_is_just_the_default() {
        let resolver = PolicyResolver::new(Last, &[]);
        assert_eq!(resolver.override_count(), 0);
        assert_eq!(resolver.for_destination(ip("1.1.1.1")), Last);
        assert_eq!(resolver.default_policy(), Last);
    }

    #[test]
    fn builds_from_a_config_section() {
        let config = ReassemblyConfig {
            overlap_policy: Last,
            host_policies: vec![entry("172.16.0.0/12", First)],
            ..ReassemblyConfig::default()
        };
        let resolver = PolicyResolver::from_config(&config);
        assert_eq!(resolver.for_destination(ip("172.16.5.5")), First);
        assert_eq!(resolver.for_destination(ip("8.8.8.8")), Last);
    }
}
