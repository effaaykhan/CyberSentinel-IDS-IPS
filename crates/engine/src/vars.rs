//! Resolving rule-header variables into address and port sets.
//!
//! A rule header says `$EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS`. Turning
//! that into something a packet can be tested against needs the variables from
//! `config.yaml`, which may themselves reference other variables
//! (`EXTERNAL_NET: "!$HOME_NET"`).
//!
//! # Wrong here is silent
//!
//! An address set that is too broad makes a rule fire on traffic it was never
//! meant to see; one that is too narrow makes it fire on nothing at all, and
//! nobody notices a rule that never matches. So resolution **fails loudly**
//! rather than guessing: an undefined variable, a reference cycle, or a
//! negation this code cannot represent exactly is an error that skips the rule
//! and is reported, not an approximation.

use std::collections::BTreeMap;

use cybersentinel_common::event::{NetTuple, Protocol as WireProtocol};
use cybersentinel_common::IpNetwork;
use cybersentinel_rules::{AddressSpec, AddressValue, Direction, PortSpec, PortValue, Protocol};
use std::net::IpAddr;

/// How deep variable references may nest before it is treated as a cycle.
const MAX_VAR_DEPTH: usize = 16;

/// Why a header could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VarError {
    /// A `$NAME` the config does not define.
    #[error("undefined variable ${0}")]
    Undefined(String),
    /// Variables reference each other in a loop, or nest too deeply.
    #[error("variable ${0} nests too deeply — check for a reference cycle")]
    TooDeep(String),
    /// A list or literal could not be parsed.
    #[error("{0}")]
    Malformed(String),
    /// A negation this representation cannot express exactly.
    ///
    /// Rather than approximate it — and match the wrong traffic without saying
    /// so — the rule is refused.
    #[error("cannot negate {0}: mixing inclusions and exclusions under a `!` is not supported")]
    UnsupportedNegation(String),
}

/// A resolved set of addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressSet {
    /// Matches every address.
    pub any: bool,
    /// Networks that match.
    pub include: Vec<IpNetwork>,
    /// Networks that do not, whatever else says.
    pub exclude: Vec<IpNetwork>,
}

impl AddressSet {
    /// Whether `address` is in the set.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        if self.exclude.iter().any(|network| network.contains(address)) {
            return false;
        }
        self.any || self.include.iter().any(|network| network.contains(address))
    }

    fn everything() -> Self {
        Self {
            any: true,
            ..Self::default()
        }
    }

    /// Invert the set.
    ///
    /// # Errors
    /// [`VarError::UnsupportedNegation`] where the result cannot be expressed
    /// exactly — negating a set that already mixes inclusions and exclusions.
    fn negate(self, description: &str) -> Result<Self, VarError> {
        match (self.any, self.include.is_empty(), self.exclude.is_empty()) {
            // !any -> nothing
            (true, true, true) => Ok(Self::default()),
            // !(any except E) -> E
            (true, true, false) => Ok(Self {
                any: false,
                include: self.exclude,
                exclude: Vec::new(),
            }),
            // !(I) -> any except I
            (false, false, true) => Ok(Self {
                any: true,
                include: Vec::new(),
                exclude: self.include,
            }),
            // !nothing -> any
            (false, true, true) => Ok(Self::everything()),
            _ => Err(VarError::UnsupportedNegation(description.to_string())),
        }
    }
}

/// A resolved set of ports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortSet {
    /// Matches every port.
    pub any: bool,
    /// Inclusive ranges that match.
    pub include: Vec<(u16, u16)>,
    /// Inclusive ranges that do not.
    pub exclude: Vec<(u16, u16)>,
}

impl PortSet {
    /// Whether `port` is in the set.
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        if self
            .exclude
            .iter()
            .any(|(low, high)| port >= *low && port <= *high)
        {
            return false;
        }
        self.any
            || self
                .include
                .iter()
                .any(|(low, high)| port >= *low && port <= *high)
    }

    fn everything() -> Self {
        Self {
            any: true,
            ..Self::default()
        }
    }

    fn negate(self, description: &str) -> Result<Self, VarError> {
        match (self.any, self.include.is_empty(), self.exclude.is_empty()) {
            (true, true, true) => Ok(Self::default()),
            (true, true, false) => Ok(Self {
                any: false,
                include: self.exclude,
                exclude: Vec::new(),
            }),
            (false, false, true) => Ok(Self {
                any: true,
                include: Vec::new(),
                exclude: self.include,
            }),
            (false, true, true) => Ok(Self::everything()),
            _ => Err(VarError::UnsupportedNegation(description.to_string())),
        }
    }
}

/// The variables a ruleset may reference.
#[derive(Debug, Clone, Default)]
pub struct VarTable {
    addresses: BTreeMap<String, String>,
    ports: BTreeMap<String, String>,
}

impl VarTable {
    /// Build from the config's `vars` section.
    #[must_use]
    pub fn new(addresses: BTreeMap<String, String>, ports: BTreeMap<String, String>) -> Self {
        Self { addresses, ports }
    }

    /// Resolve a rule header's address field.
    ///
    /// # Errors
    /// Any [`VarError`].
    pub fn resolve_addresses(&self, spec: &AddressSpec) -> Result<AddressSet, VarError> {
        let set = self.address_value(&spec.value, 0)?;
        if spec.negated {
            set.negate(&format!("{:?}", spec.value))
        } else {
            Ok(set)
        }
    }

    /// Resolve a rule header's port field.
    ///
    /// # Errors
    /// Any [`VarError`].
    pub fn resolve_ports(&self, spec: &PortSpec) -> Result<PortSet, VarError> {
        let set = self.port_value(&spec.value, 0)?;
        if spec.negated {
            set.negate(&format!("{:?}", spec.value))
        } else {
            Ok(set)
        }
    }

    fn address_value(&self, value: &AddressValue, depth: usize) -> Result<AddressSet, VarError> {
        match value {
            AddressValue::Any => Ok(AddressSet::everything()),
            AddressValue::Literal(text) => Ok(AddressSet {
                any: false,
                include: vec![text
                    .parse()
                    .map_err(|error| VarError::Malformed(format!("{text}: {error}")))?],
                exclude: Vec::new(),
            }),
            AddressValue::Var(name) => {
                if depth >= MAX_VAR_DEPTH {
                    return Err(VarError::TooDeep(name.clone()));
                }
                let text = self
                    .addresses
                    .get(name)
                    .ok_or_else(|| VarError::Undefined(name.clone()))?;
                self.address_expression(text, depth + 1)
            }
            AddressValue::List(text) => self.address_expression(text, depth),
        }
    }

    /// Resolve an expression as written in the config: `[a,!b]`, `!$X`, `$X`,
    /// `any`, or a literal.
    fn address_expression(&self, text: &str, depth: usize) -> Result<AddressSet, VarError> {
        let text = text.trim();
        if let Some(rest) = text.strip_prefix('!') {
            return self.address_expression(rest, depth)?.negate(rest.trim());
        }
        if let Some(inner) = strip_brackets(text) {
            let mut combined = AddressSet::default();
            for element in split_top_level(inner) {
                let part = self.address_expression(element, depth)?;
                combined.any |= part.any;
                combined.include.extend(part.include);
                combined.exclude.extend(part.exclude);
            }
            return Ok(combined);
        }
        if text.eq_ignore_ascii_case("any") {
            return Ok(AddressSet::everything());
        }
        if let Some(name) = text.strip_prefix('$') {
            return self.address_value(&AddressValue::Var(name.to_string()), depth);
        }
        Ok(AddressSet {
            any: false,
            include: vec![text
                .parse()
                .map_err(|error| VarError::Malformed(format!("{text}: {error}")))?],
            exclude: Vec::new(),
        })
    }

    fn port_value(&self, value: &PortValue, depth: usize) -> Result<PortSet, VarError> {
        match value {
            PortValue::Any => Ok(PortSet::everything()),
            PortValue::Single(port) => Ok(PortSet {
                any: false,
                include: vec![(*port, *port)],
                exclude: Vec::new(),
            }),
            PortValue::Range(low, high) => Ok(PortSet {
                any: false,
                include: vec![(low.unwrap_or(0), high.unwrap_or(u16::MAX))],
                exclude: Vec::new(),
            }),
            PortValue::Var(name) => {
                if depth >= MAX_VAR_DEPTH {
                    return Err(VarError::TooDeep(name.clone()));
                }
                let text = self
                    .ports
                    .get(name)
                    .ok_or_else(|| VarError::Undefined(name.clone()))?;
                self.port_expression(text, depth + 1)
            }
            PortValue::List(text) => self.port_expression(text, depth),
        }
    }

    fn port_expression(&self, text: &str, depth: usize) -> Result<PortSet, VarError> {
        let text = text.trim();
        if let Some(rest) = text.strip_prefix('!') {
            return self.port_expression(rest, depth)?.negate(rest.trim());
        }
        if let Some(inner) = strip_brackets(text) {
            let mut combined = PortSet::default();
            for element in split_top_level(inner) {
                let part = self.port_expression(element, depth)?;
                combined.any |= part.any;
                combined.include.extend(part.include);
                combined.exclude.extend(part.exclude);
            }
            return Ok(combined);
        }
        if text.eq_ignore_ascii_case("any") {
            return Ok(PortSet::everything());
        }
        if let Some(name) = text.strip_prefix('$') {
            return self.port_value(&PortValue::Var(name.to_string()), depth);
        }
        if let Some((low, high)) = text.split_once(':') {
            let low = parse_port(low, 0)?;
            let high = parse_port(high, u16::MAX)?;
            return Ok(PortSet {
                any: false,
                include: vec![(low, high)],
                exclude: Vec::new(),
            });
        }
        let port = parse_port(text, 0)?;
        Ok(PortSet {
            any: false,
            include: vec![(port, port)],
            exclude: Vec::new(),
        })
    }
}

fn parse_port(text: &str, empty_default: u16) -> Result<u16, VarError> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(empty_default);
    }
    text.parse()
        .map_err(|_| VarError::Malformed(format!("{text:?} is not a port")))
}

fn strip_brackets(text: &str) -> Option<&str> {
    text.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
}

/// Split on commas that are not inside nested brackets.
fn split_top_level(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (index, character) in text.char_indices() {
        match character {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&text[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
        .into_iter()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect()
}

/// A rule header resolved into something a packet can be tested against.
#[derive(Debug, Clone)]
pub struct CompiledHeader {
    /// Protocol the rule selects.
    pub protocol: Protocol,
    /// Source addresses.
    pub source: AddressSet,
    /// Source ports.
    pub source_ports: PortSet,
    /// Destination addresses.
    pub destination: AddressSet,
    /// Destination ports.
    pub destination_ports: PortSet,
    /// Whether the rule matches traffic in either direction.
    pub bidirectional: bool,
}

impl CompiledHeader {
    /// Resolve a parsed header.
    ///
    /// # Errors
    /// Any [`VarError`] from the address or port fields.
    pub fn resolve(
        header: &cybersentinel_rules::RuleHeader,
        vars: &VarTable,
    ) -> Result<Self, VarError> {
        Ok(Self {
            protocol: header.protocol,
            source: vars.resolve_addresses(&header.source)?,
            source_ports: vars.resolve_ports(&header.source_port)?,
            destination: vars.resolve_addresses(&header.destination)?,
            destination_ports: vars.resolve_ports(&header.destination_port)?,
            bidirectional: header.direction == Direction::Bidirectional,
        })
    }

    /// Whether this header selects the given 5-tuple.
    #[must_use]
    pub fn matches(&self, tuple: &NetTuple) -> bool {
        if !self.protocol_matches(tuple.proto) {
            return false;
        }
        if self.one_way(tuple.src_ip, tuple.src_port, tuple.dest_ip, tuple.dest_port) {
            return true;
        }
        self.bidirectional
            && self.one_way(tuple.dest_ip, tuple.dest_port, tuple.src_ip, tuple.src_port)
    }

    fn one_way(
        &self,
        source: IpAddr,
        source_port: Option<u16>,
        destination: IpAddr,
        destination_port: Option<u16>,
    ) -> bool {
        self.source.contains(source)
            && self.destination.contains(destination)
            // A protocol with no ports satisfies any port clause: `icmp any any`
            // must match, and a rule naming a port for ICMP would never have
            // made sense anyway.
            && source_port.is_none_or(|port| self.source_ports.contains(port))
            && destination_port.is_none_or(|port| self.destination_ports.contains(port))
    }

    fn protocol_matches(&self, wire: WireProtocol) -> bool {
        match self.protocol {
            Protocol::Ip => true,
            Protocol::Tcp => wire == WireProtocol::Tcp,
            Protocol::Udp => wire == WireProtocol::Udp,
            Protocol::Icmp => wire == WireProtocol::Icmp,
            // App-layer protocols ride on TCP; that the traffic really is HTTP
            // is decided by the parser filling the buffers, not by the header.
            Protocol::Http | Protocol::Tls => wire == WireProtocol::Tcp,
            Protocol::Dns => matches!(wire, WireProtocol::Udp | WireProtocol::Tcp),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cybersentinel_rules::parse_rule;

    fn vars() -> VarTable {
        VarTable::new(
            [
                ("HOME_NET".into(), "[192.168.0.0/16,10.0.0.0/8]".into()),
                ("EXTERNAL_NET".into(), "!$HOME_NET".into()),
                ("SERVERS".into(), "$HOME_NET".into()),
                ("LOOP".into(), "$LOOP".into()),
            ]
            .into_iter()
            .collect(),
            [
                ("HTTP_PORTS".into(), "[80,8080,8000:8100]".into()),
                ("NOT_SSH".into(), "!22".into()),
            ]
            .into_iter()
            .collect(),
        )
    }

    fn header(text: &str) -> CompiledHeader {
        let rule = parse_rule(text).expect("the rule should parse");
        CompiledHeader::resolve(&rule.header, &vars()).expect("the header should resolve")
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn tuple(src: &str, sport: u16, dst: &str, dport: u16) -> NetTuple {
        NetTuple {
            src_ip: ip(src),
            src_port: Some(sport),
            dest_ip: ip(dst),
            dest_port: Some(dport),
            proto: WireProtocol::Tcp,
        }
    }

    #[test]
    fn resolves_a_list_variable() {
        let set = vars()
            .resolve_addresses(&AddressSpec {
                negated: false,
                value: AddressValue::Var("HOME_NET".into()),
            })
            .unwrap();
        assert!(set.contains(ip("192.168.1.1")));
        assert!(set.contains(ip("10.5.5.5")));
        assert!(!set.contains(ip("8.8.8.8")));
    }

    #[test]
    fn resolves_a_negated_variable_reference() {
        // EXTERNAL_NET is "!$HOME_NET": everything except home.
        let set = vars()
            .resolve_addresses(&AddressSpec {
                negated: false,
                value: AddressValue::Var("EXTERNAL_NET".into()),
            })
            .unwrap();
        assert!(set.contains(ip("8.8.8.8")));
        assert!(!set.contains(ip("192.168.1.1")));
    }

    #[test]
    fn resolves_variables_that_reference_variables() {
        let set = vars()
            .resolve_addresses(&AddressSpec {
                negated: false,
                value: AddressValue::Var("SERVERS".into()),
            })
            .unwrap();
        assert!(set.contains(ip("10.0.0.1")));
    }

    #[test]
    fn a_reference_cycle_is_an_error_not_a_hang() {
        let error = vars()
            .resolve_addresses(&AddressSpec {
                negated: false,
                value: AddressValue::Var("LOOP".into()),
            })
            .unwrap_err();
        assert!(matches!(error, VarError::TooDeep(_)), "{error}");
    }

    #[test]
    fn an_undefined_variable_is_an_error_not_an_empty_set() {
        // An empty set would make the rule match nothing, silently.
        let error = vars()
            .resolve_addresses(&AddressSpec {
                negated: false,
                value: AddressValue::Var("NOT_DEFINED".into()),
            })
            .unwrap_err();
        assert!(matches!(error, VarError::Undefined(_)), "{error}");
    }

    #[test]
    fn resolves_port_lists_and_ranges() {
        let set = vars()
            .resolve_ports(&PortSpec {
                negated: false,
                value: PortValue::Var("HTTP_PORTS".into()),
            })
            .unwrap();
        assert!(set.contains(80));
        assert!(set.contains(8_080));
        assert!(set.contains(8_050));
        assert!(!set.contains(443));
    }

    #[test]
    fn resolves_negated_ports() {
        let set = vars()
            .resolve_ports(&PortSpec {
                negated: false,
                value: PortValue::Var("NOT_SSH".into()),
            })
            .unwrap();
        assert!(set.contains(80));
        assert!(!set.contains(22));
    }

    #[test]
    fn a_negation_that_cannot_be_expressed_exactly_is_refused() {
        // `![10.0.0.0/8,!10.1.0.0/16]` mixes inclusion and exclusion under a
        // negation. Approximating it would match the wrong traffic without
        // saying so, so it is an error.
        let table = VarTable::new(
            [("MIXED".into(), "![10.0.0.0/8,!10.1.0.0/16]".into())]
                .into_iter()
                .collect(),
            BTreeMap::new(),
        );
        let error = table
            .resolve_addresses(&AddressSpec {
                negated: false,
                value: AddressValue::Var("MIXED".into()),
            })
            .unwrap_err();
        assert!(matches!(error, VarError::UnsupportedNegation(_)), "{error}");
    }

    // -----------------------------------------------------------------------
    // header matching
    // -----------------------------------------------------------------------

    #[test]
    fn a_header_selects_the_traffic_it_names() {
        let compiled =
            header(r#"alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"m"; sid:1;)"#);
        assert!(compiled.matches(&tuple("8.8.8.8", 51_000, "192.168.1.5", 80)));
        assert!(!compiled.matches(&tuple("8.8.8.8", 51_000, "192.168.1.5", 443)));
        assert!(
            !compiled.matches(&tuple("192.168.1.5", 51_000, "192.168.1.6", 80)),
            "internal traffic is not EXTERNAL_NET"
        );
    }

    #[test]
    fn a_one_way_header_does_not_match_the_reply() {
        let compiled = header(r#"alert tcp any any -> any 80 (msg:"m"; sid:1;)"#);
        assert!(compiled.matches(&tuple("1.1.1.1", 5_000, "2.2.2.2", 80)));
        assert!(!compiled.matches(&tuple("2.2.2.2", 80, "1.1.1.1", 5_000)));
    }

    #[test]
    fn a_bidirectional_header_matches_both_ways() {
        let compiled = header(r#"alert tcp any any <> any 80 (msg:"m"; sid:1;)"#);
        assert!(compiled.matches(&tuple("1.1.1.1", 5_000, "2.2.2.2", 80)));
        assert!(compiled.matches(&tuple("2.2.2.2", 80, "1.1.1.1", 5_000)));
    }

    #[test]
    fn the_protocol_must_agree() {
        let tcp = header(r#"alert tcp any any -> any any (msg:"m"; sid:1;)"#);
        let mut udp_tuple = tuple("1.1.1.1", 1, "2.2.2.2", 2);
        udp_tuple.proto = WireProtocol::Udp;
        assert!(!tcp.matches(&udp_tuple));

        let ip_rule = header(r#"alert ip any any -> any any (msg:"m"; sid:1;)"#);
        assert!(ip_rule.matches(&udp_tuple), "ip matches any protocol");

        let http = header(r#"alert http any any -> any any (msg:"m"; sid:1;)"#);
        assert!(
            http.matches(&tuple("1.1.1.1", 1, "2.2.2.2", 80)),
            "http rides on TCP; the parser decides whether it really is HTTP"
        );
    }

    #[test]
    fn a_protocol_without_ports_still_matches_a_port_clause() {
        let icmp = header(r#"alert icmp any any -> any any (msg:"m"; sid:1;)"#);
        let tuple = NetTuple {
            src_ip: ip("1.1.1.1"),
            src_port: None,
            dest_ip: ip("2.2.2.2"),
            dest_port: None,
            proto: WireProtocol::Icmp,
        };
        assert!(icmp.matches(&tuple));
    }
}
