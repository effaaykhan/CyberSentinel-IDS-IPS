//! Network address ranges.
//!
//! A small CIDR type, used by the reassembly host-policy table and, from
//! Phase 3, by rule-header address matching. Written in-tree rather than taken
//! from a crate because it is forty lines of arithmetic, and because both of
//! those callers are parsing operator- or rule-supplied text — which is exactly
//! the input this project fuzzes rather than delegates.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// An IP address range in CIDR form.
///
/// A bare address (`192.0.2.1`, `2001:db8::1`) is accepted and treated as a
/// single-host network — `/32` or `/128`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNetwork {
    address: IpAddr,
    prefix_len: u8,
}

/// Why a CIDR string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IpNetworkParseError {
    /// The address part is not an IP address.
    #[error("{0:?} is not an IP address")]
    BadAddress(String),
    /// The prefix length is not a number.
    #[error("{0:?} is not a prefix length")]
    BadPrefix(String),
    /// The prefix length exceeds the address family's width.
    #[error("prefix length {prefix_len} exceeds {max} for this address family")]
    PrefixTooLong {
        /// The prefix length given.
        prefix_len: u8,
        /// The maximum for this family.
        max: u8,
    },
}

impl IpNetwork {
    /// Build a network, masking off any host bits.
    ///
    /// # Errors
    /// [`IpNetworkParseError::PrefixTooLong`] if `prefix_len` is wider than the
    /// address family allows.
    pub fn new(address: IpAddr, prefix_len: u8) -> Result<Self, IpNetworkParseError> {
        let max = Self::max_prefix_len(&address);
        if prefix_len > max {
            return Err(IpNetworkParseError::PrefixTooLong { prefix_len, max });
        }
        Ok(Self {
            // Canonicalise so that 10.1.2.3/8 and 10.0.0.0/8 compare equal:
            // an operator writing the former means the latter.
            address: mask(address, prefix_len),
            prefix_len,
        })
    }

    /// A network matching a single address.
    #[must_use]
    pub fn host(address: IpAddr) -> Self {
        Self {
            prefix_len: Self::max_prefix_len(&address),
            address,
        }
    }

    fn max_prefix_len(address: &IpAddr) -> u8 {
        match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    /// The network address, with host bits cleared.
    #[must_use]
    pub fn address(&self) -> IpAddr {
        self.address
    }

    /// The prefix length in bits.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Whether `address` falls inside this network.
    ///
    /// An IPv4 address never matches an IPv6 network or vice versa; the two
    /// families are kept strictly separate rather than mapped onto each other,
    /// so `::ffff:10.0.0.1` does not quietly match `10.0.0.0/8`.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                masked_v4(candidate, self.prefix_len) == network
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                masked_v6(candidate, self.prefix_len) == network
            }
            _ => false,
        }
    }
}

fn mask(address: IpAddr, prefix_len: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => IpAddr::V4(masked_v4(v4, prefix_len)),
        IpAddr::V6(v6) => IpAddr::V6(masked_v6(v6, prefix_len)),
    }
}

fn masked_v4(address: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    // A shift of 32 is undefined, so the all-bits case is handled separately.
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    };
    Ipv4Addr::from(u32::from(address) & mask)
}

fn masked_v6(address: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    };
    Ipv6Addr::from(u128::from(address) & mask)
}

impl FromStr for IpNetwork {
    type Err = IpNetworkParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let Some((address, prefix)) = text.split_once('/') else {
            let address: IpAddr = text
                .parse()
                .map_err(|_| IpNetworkParseError::BadAddress(text.to_string()))?;
            return Ok(Self::host(address));
        };

        let address: IpAddr = address
            .parse()
            .map_err(|_| IpNetworkParseError::BadAddress(address.to_string()))?;
        let prefix_len: u8 = prefix
            .parse()
            .map_err(|_| IpNetworkParseError::BadPrefix(prefix.to_string()))?;
        Self::new(address, prefix_len)
    }
}

impl fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

impl Serialize for IpNetwork {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for IpNetwork {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn network(text: &str) -> IpNetwork {
        text.parse().unwrap()
    }

    #[test]
    fn parses_ipv4_networks() {
        let net = network("10.0.0.0/8");
        assert_eq!(net.prefix_len(), 8);
        assert!(net.contains(ip("10.1.2.3")));
        assert!(!net.contains(ip("11.0.0.1")));
    }

    #[test]
    fn parses_ipv6_networks() {
        let net = network("2001:db8::/32");
        assert!(net.contains(ip("2001:db8::1")));
        assert!(net.contains(ip("2001:db8:ffff::1")));
        assert!(!net.contains(ip("2001:db9::1")));
    }

    #[test]
    fn a_bare_address_is_a_single_host() {
        let net = network("192.0.2.7");
        assert_eq!(net.prefix_len(), 32);
        assert!(net.contains(ip("192.0.2.7")));
        assert!(!net.contains(ip("192.0.2.8")));

        assert_eq!(network("2001:db8::1").prefix_len(), 128);
    }

    #[test]
    fn host_bits_are_masked_off_so_equivalent_networks_compare_equal() {
        assert_eq!(network("10.1.2.3/8"), network("10.0.0.0/8"));
        assert_eq!(network("10.1.2.3/8").to_string(), "10.0.0.0/8");
    }

    #[test]
    fn the_zero_prefix_matches_everything_in_its_family() {
        let all_v4 = network("0.0.0.0/0");
        assert!(all_v4.contains(ip("1.2.3.4")));
        assert!(all_v4.contains(ip("255.255.255.255")));
        assert!(!all_v4.contains(ip("::1")), "families do not cross");

        assert!(network("::/0").contains(ip("2001:db8::1")));
    }

    #[test]
    fn the_full_prefix_matches_only_itself() {
        let host = network("192.0.2.1/32");
        assert!(host.contains(ip("192.0.2.1")));
        assert!(!host.contains(ip("192.0.2.2")));
        assert!(network("::1/128").contains(ip("::1")));
    }

    #[test]
    fn address_families_never_cross() {
        // ::ffff:10.0.0.1 is a v4-mapped v6 address. Matching it against an
        // IPv4 network would let an operator's policy apply somewhere they did
        // not intend.
        assert!(!network("10.0.0.0/8").contains(ip("::ffff:10.0.0.1")));
        assert!(!network("::/0").contains(ip("10.0.0.1")));
    }

    #[test]
    fn malformed_input_is_rejected_with_a_reason() {
        assert!(matches!(
            "not-an-ip".parse::<IpNetwork>(),
            Err(IpNetworkParseError::BadAddress(_))
        ));
        assert!(matches!(
            "10.0.0.0/x".parse::<IpNetwork>(),
            Err(IpNetworkParseError::BadPrefix(_))
        ));
        assert!(matches!(
            "10.0.0.0/33".parse::<IpNetwork>(),
            Err(IpNetworkParseError::PrefixTooLong { .. })
        ));
        assert!(matches!(
            "2001:db8::/129".parse::<IpNetwork>(),
            Err(IpNetworkParseError::PrefixTooLong { .. })
        ));
        assert!("".parse::<IpNetwork>().is_err());
        assert!("/8".parse::<IpNetwork>().is_err());
    }

    #[test]
    fn round_trips_through_yaml() {
        let net = network("172.16.0.0/12");
        let yaml = serde_yaml::to_string(&net).unwrap();
        assert_eq!(yaml.trim(), "172.16.0.0/12");
        assert_eq!(serde_yaml::from_str::<IpNetwork>(&yaml).unwrap(), net);
    }

    #[test]
    fn a_bad_network_in_yaml_is_a_load_error() {
        assert!(serde_yaml::from_str::<IpNetwork>("10.0.0.0/99").is_err());
    }
}
