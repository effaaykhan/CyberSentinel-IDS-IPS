//! The `.rules` text parser.
//!
//! Hand-written rather than built on a combinator library: the grammar is small
//! and mostly context-free splitting, and a hand-written scanner keeps the
//! failure modes explicit and easy to fuzz. `nom` remains an option if Phase 3's
//! option grammar grows past what this stays readable at.
//!
//! The parser is total: every input either yields a [`Rule`] or a [`ParseError`]
//! naming what was wrong. It never panics, never recurses, and does a single
//! left-to-right pass, so its cost is linear in the input length.

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::model::{
    Action, AddressSpec, AddressValue, Direction, MetadataEntry, PortSpec, PortValue, Protocol,
    Rule, RuleHeader,
};

/// Option keywords this format defines but this build cannot yet evaluate.
///
/// A rule using one of these still loads — flagged, and reported as
/// non-evaluable. Anything *not* listed here and not handled below is treated
/// as a typo and the rule is skipped. Keywords move out of this list as their
/// implementing phase lands.
pub const RECOGNISED_UNIMPLEMENTED_OPTIONS: &[&str] = &[
    // Content matching (Phase 3)
    "content",
    "nocase",
    "offset",
    "depth",
    "distance",
    "within",
    "fast_pattern",
    "startswith",
    "endswith",
    // Flow state (Phase 3)
    "flow",
    "flowbits",
    // Expressions (Phase 3)
    "pcre",
    "byte_test",
    "byte_jump",
    "dsize",
    // Rate limiting (Phase 3)
    "threshold",
    "detection_filter",
    // Sticky buffers (Phase 3)
    "http.uri",
    "http.header",
    "http.user_agent",
    "http.method",
    "http.host",
    // Non-matching annotations (Phase 3)
    "reference",
    "priority",
    "gid",
    "target",
    // Host-rule keywords (Phase 4)
    "file.path",
    "file.change",
    "auth.outcome",
    "auth.user",
    "process.name",
];

/// Why a rule could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The line held no rule text.
    #[error("empty rule")]
    Empty,

    /// No `(` was found after the header.
    #[error("missing option block: expected '(' after the rule header")]
    MissingOptionBlock,

    /// The option block was not closed.
    #[error("unterminated option block: expected a closing ')'")]
    UnterminatedOptionBlock,

    /// A quoted value ran to the end of the rule.
    #[error("unterminated quoted string")]
    UnterminatedString,

    /// The header did not have exactly seven whitespace-separated fields.
    #[error(
        "rule header must have 7 fields \
         (action protocol src-addr src-port direction dst-addr dst-port), found {found}"
    )]
    HeaderFieldCount {
        /// How many fields were present.
        found: usize,
    },

    /// The action was not a recognised keyword.
    #[error("unknown action {0:?}: expected alert, pass, drop, or reject")]
    UnknownAction(String),

    /// The action was recognised but is a prevention action.
    #[error("action {0:?} is not supported: CyberSentinel v1 is detection-only (IDS)")]
    PreventionAction(String),

    /// The protocol was not recognised.
    #[error("unknown protocol {0:?}: expected ip, tcp, udp, icmp, http, dns, or tls")]
    UnknownProtocol(String),

    /// The direction token was neither `->` nor `<>`.
    #[error("invalid direction {0:?}: expected '->' or '<>'")]
    InvalidDirection(String),

    /// An address field was malformed.
    #[error("invalid address {value:?}: {reason}")]
    InvalidAddress {
        /// The offending text.
        value: String,
        /// What was wrong with it.
        reason: String,
    },

    /// A port field was malformed.
    #[error("invalid port {value:?}: {reason}")]
    InvalidPort {
        /// The offending text.
        value: String,
        /// What was wrong with it.
        reason: String,
    },

    /// An option that needs a value had none.
    #[error("option {0:?} requires a value")]
    MissingOptionValue(String),

    /// An option's value was not of the expected form.
    #[error("invalid value for option {option:?}: {reason}")]
    InvalidOptionValue {
        /// The option keyword.
        option: String,
        /// What was wrong with the value.
        reason: String,
    },

    /// An option keyword is not part of the CyberSentinel rule format.
    #[error("unknown option {0:?}")]
    UnknownOption(String),

    /// An option that may appear at most once appeared twice.
    #[error("duplicate option {0:?}")]
    DuplicateOption(String),

    /// `sid` is mandatory: without it an alert cannot be attributed to a rule.
    #[error("missing required option 'sid'")]
    MissingSid,

    /// `msg` is mandatory: an alert with no description is not actionable.
    #[error("missing required option 'msg'")]
    MissingMsg,
}

/// Parse one rule.
///
/// `text` must be a single rule with any line continuations already joined; see
/// [`crate::loader`] for reading whole files.
///
/// # Errors
/// A [`ParseError`] describing the first problem found.
pub fn parse_rule(text: &str) -> Result<Rule, ParseError> {
    let raw = text.trim();
    if raw.is_empty() {
        return Err(ParseError::Empty);
    }

    let open = raw.find('(').ok_or(ParseError::MissingOptionBlock)?;
    let close = raw.rfind(')').ok_or(ParseError::UnterminatedOptionBlock)?;
    if close < open {
        return Err(ParseError::UnterminatedOptionBlock);
    }

    let header = parse_header(&raw[..open])?;
    let options = parse_options(&raw[open + 1..close])?;

    build_rule(header, options, raw)
}

// ---------------------------------------------------------------------------
// header
// ---------------------------------------------------------------------------

fn parse_header(text: &str) -> Result<RuleHeader, ParseError> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    if fields.len() != 7 {
        return Err(ParseError::HeaderFieldCount {
            found: fields.len(),
        });
    }

    Ok(RuleHeader {
        action: parse_action(fields[0])?,
        protocol: parse_protocol(fields[1])?,
        source: parse_address(fields[2])?,
        source_port: parse_port(fields[3])?,
        direction: parse_direction(fields[4])?,
        destination: parse_address(fields[5])?,
        destination_port: parse_port(fields[6])?,
    })
}

fn parse_action(text: &str) -> Result<Action, ParseError> {
    match text.to_ascii_lowercase().as_str() {
        "alert" => Ok(Action::Alert),
        "pass" => Ok(Action::Pass),
        "drop" | "reject" | "rejectsrc" | "rejectdst" | "rejectboth" => {
            Err(ParseError::PreventionAction(text.to_string()))
        }
        _ => Err(ParseError::UnknownAction(text.to_string())),
    }
}

fn parse_protocol(text: &str) -> Result<Protocol, ParseError> {
    match text.to_ascii_lowercase().as_str() {
        "ip" => Ok(Protocol::Ip),
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "icmp" => Ok(Protocol::Icmp),
        "http" => Ok(Protocol::Http),
        "dns" => Ok(Protocol::Dns),
        "tls" => Ok(Protocol::Tls),
        _ => Err(ParseError::UnknownProtocol(text.to_string())),
    }
}

fn parse_direction(text: &str) -> Result<Direction, ParseError> {
    match text {
        "->" => Ok(Direction::ToDestination),
        "<>" => Ok(Direction::Bidirectional),
        // `<-` is deliberately rejected: a reversed arrow reads as a valid rule
        // but would silently invert the header's meaning.
        _ => Err(ParseError::InvalidDirection(text.to_string())),
    }
}

/// Split a leading `!` off a header field.
fn split_negation(text: &str) -> (bool, &str) {
    match text.strip_prefix('!') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, text),
    }
}

fn parse_address(text: &str) -> Result<AddressSpec, ParseError> {
    let invalid = |reason: &str| ParseError::InvalidAddress {
        value: text.to_string(),
        reason: reason.to_string(),
    };

    let (negated, body) = split_negation(text);
    if body.is_empty() {
        return Err(invalid("empty address"));
    }

    let value = if body.eq_ignore_ascii_case("any") {
        AddressValue::Any
    } else if let Some(name) = body.strip_prefix('$') {
        validate_var_name(name).map_err(|reason| invalid(&reason))?;
        AddressValue::Var(name.to_string())
    } else if body.starts_with('[') {
        if !body.ends_with(']') {
            return Err(invalid("address list is missing its closing ']'"));
        }
        if body.len() == 2 {
            return Err(invalid("empty address list"));
        }
        AddressValue::List(body.to_string())
    } else {
        validate_address_literal(body).map_err(|reason| invalid(&reason))?;
        AddressValue::Literal(body.to_string())
    };

    Ok(AddressSpec { negated, value })
}

fn validate_address_literal(text: &str) -> Result<(), String> {
    let (addr, prefix) = match text.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (text, None),
    };

    let addr: IpAddr = addr
        .parse()
        .map_err(|_| format!("{addr:?} is not an IP address"))?;

    if let Some(prefix) = prefix {
        let bits: u8 = prefix
            .parse()
            .map_err(|_| format!("{prefix:?} is not a prefix length"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(format!(
                "prefix length {bits} exceeds {max} for this address family"
            ));
        }
    }
    Ok(())
}

fn parse_port(text: &str) -> Result<PortSpec, ParseError> {
    let invalid = |reason: &str| ParseError::InvalidPort {
        value: text.to_string(),
        reason: reason.to_string(),
    };

    let (negated, body) = split_negation(text);
    if body.is_empty() {
        return Err(invalid("empty port"));
    }

    let value = if body.eq_ignore_ascii_case("any") {
        PortValue::Any
    } else if let Some(name) = body.strip_prefix('$') {
        validate_var_name(name).map_err(|reason| invalid(&reason))?;
        PortValue::Var(name.to_string())
    } else if body.starts_with('[') {
        if !body.ends_with(']') {
            return Err(invalid("port list is missing its closing ']'"));
        }
        if body.len() == 2 {
            return Err(invalid("empty port list"));
        }
        PortValue::List(body.to_string())
    } else if let Some((low, high)) = body.split_once(':') {
        let low = parse_optional_port(low).map_err(|reason| invalid(&reason))?;
        let high = parse_optional_port(high).map_err(|reason| invalid(&reason))?;
        if let (Some(low), Some(high)) = (low, high) {
            if low > high {
                return Err(invalid("range start is greater than range end"));
            }
        }
        PortValue::Range(low, high)
    } else {
        PortValue::Single(
            body.parse()
                .map_err(|_| invalid("not a port number in 0..=65535"))?,
        )
    };

    Ok(PortSpec { negated, value })
}

fn parse_optional_port(text: &str) -> Result<Option<u16>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    text.parse()
        .map(Some)
        .map_err(|_| format!("{text:?} is not a port number in 0..=65535"))
}

fn validate_var_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("'$' must be followed by a variable name".to_string());
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!(
            "variable name {name:?} must be alphanumeric or underscore"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// options
// ---------------------------------------------------------------------------

/// One `name` or `name:value` option, with the value already unquoted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawOption {
    name: String,
    value: Option<String>,
}

/// Split an option block into options.
///
/// Semicolons inside quotes, and semicolons escaped with a backslash, do not
/// terminate an option — this is the one place where a naive `split(';')` would
/// silently truncate a rule and change what it matches.
fn split_option_list(body: &str) -> Result<Vec<String>, ParseError> {
    let mut options = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = body.chars();

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                // Keep the escape intact; `unescape` resolves it later.
                current.push('\\');
                match chars.next() {
                    Some(escaped) => current.push(escaped),
                    None => return Err(ParseError::UnterminatedString),
                }
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push('"');
            }
            ';' if !in_quotes => {
                options.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }

    if in_quotes {
        return Err(ParseError::UnterminatedString);
    }
    // Trailing text after the last `;` — a rule whose final option omitted its
    // terminator.
    if !current.trim().is_empty() {
        options.push(current);
    }
    Ok(options)
}

fn parse_options(body: &str) -> Result<Vec<RawOption>, ParseError> {
    let mut options = Vec::new();

    for chunk in split_option_list(body)? {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            continue;
        }

        let (name, value) = match split_name_value(chunk) {
            Some((name, value)) => (name, Some(unescape(value.trim())?)),
            None => (chunk, None),
        };

        options.push(RawOption {
            name: name.trim().to_ascii_lowercase(),
            value,
        });
    }

    Ok(options)
}

/// Split `name:value` at the first colon that is outside quotes.
///
/// Sticky-buffer keywords such as `http.uri` contain no colon, and values such
/// as `pcre:"/a:b/"` do — so the split must respect quoting.
fn split_name_value(chunk: &str) -> Option<(&str, &str)> {
    let mut in_quotes = false;
    let mut escaped = false;
    for (index, c) in chunk.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => in_quotes = !in_quotes,
            ':' if !in_quotes => return Some((&chunk[..index], &chunk[index + 1..])),
            _ => {}
        }
    }
    None
}

/// Strip surrounding quotes if present and resolve backslash escapes.
fn unescape(value: &str) -> Result<String, ParseError> {
    let inner = if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        &value[1..value.len() - 1]
    } else if value.starts_with('"') {
        return Err(ParseError::UnterminatedString);
    } else {
        value
    };

    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            // The three characters that are structural in this format.
            Some('"') => out.push('"'),
            Some(';') => out.push(';'),
            Some('\\') => out.push('\\'),
            // Anything else keeps its backslash: rule authors write regexes and
            // byte patterns here, and rewriting `\d` to `d` would corrupt them.
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => return Err(ParseError::UnterminatedString),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// assembly
// ---------------------------------------------------------------------------

/// Fold the parsed options into a [`Rule`], separating the ones Phase 0
/// interprets from the ones it only recognises.
fn build_rule(header: RuleHeader, options: Vec<RawOption>, raw: &str) -> Result<Rule, ParseError> {
    let mut sid = None;
    let mut rev = None;
    let mut msg = None;
    let mut classtype = None;
    let mut metadata = Vec::new();
    let mut unsupported: Vec<String> = Vec::new();
    let mut seen_unsupported = BTreeSet::new();

    for option in options {
        let RawOption { name, value } = option;
        match name.as_str() {
            "sid" => {
                reject_duplicate(&sid, "sid")?;
                sid = Some(parse_u32_option(&name, value.as_deref())?);
            }
            "rev" => {
                reject_duplicate(&rev, "rev")?;
                rev = Some(parse_u32_option(&name, value.as_deref())?);
            }
            "msg" => {
                reject_duplicate(&msg, "msg")?;
                let text = require_value(&name, value)?;
                if text.trim().is_empty() {
                    return Err(ParseError::InvalidOptionValue {
                        option: name,
                        reason: "msg must not be empty".to_string(),
                    });
                }
                msg = Some(text);
            }
            "classtype" => {
                reject_duplicate(&classtype, "classtype")?;
                classtype = Some(require_value(&name, value)?);
            }
            "metadata" => {
                metadata.extend(parse_metadata(&require_value(&name, value)?));
            }
            other if RECOGNISED_UNIMPLEMENTED_OPTIONS.contains(&other) => {
                if seen_unsupported.insert(other.to_string()) {
                    unsupported.push(other.to_string());
                }
            }
            other => return Err(ParseError::UnknownOption(other.to_string())),
        }
    }

    Ok(Rule {
        header,
        sid: sid.ok_or(ParseError::MissingSid)?,
        rev: rev.unwrap_or(1),
        msg: msg.ok_or(ParseError::MissingMsg)?,
        classtype,
        metadata,
        unsupported_options: unsupported,
        raw: raw.to_string(),
        origin: None,
    })
}

fn reject_duplicate<T>(slot: &Option<T>, name: &str) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError::DuplicateOption(name.to_string()));
    }
    Ok(())
}

fn require_value(name: &str, value: Option<String>) -> Result<String, ParseError> {
    value.ok_or_else(|| ParseError::MissingOptionValue(name.to_string()))
}

fn parse_u32_option(name: &str, value: Option<&str>) -> Result<u32, ParseError> {
    let value = value.ok_or_else(|| ParseError::MissingOptionValue(name.to_string()))?;
    value
        .trim()
        .parse()
        .map_err(|_| ParseError::InvalidOptionValue {
            option: name.to_string(),
            reason: format!("{:?} is not a number in 0..=4294967295", value.trim()),
        })
}

/// Parse `metadata:key value, key2 value2`.
fn parse_metadata(value: &str) -> Vec<MetadataEntry> {
    value
        .split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            let (key, value) = match entry.split_once(char::is_whitespace) {
                Some((key, value)) => (key, value.trim()),
                None => (entry, ""),
            };
            Some(MetadataEntry {
                key: key.to_string(),
                value: value.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"alert tcp any any -> any any (msg:"minimal"; sid:1;)"#;

    #[test]
    fn parses_a_minimal_rule() {
        let rule = parse_rule(MINIMAL).unwrap();
        assert_eq!(rule.header.action, Action::Alert);
        assert_eq!(rule.header.protocol, Protocol::Tcp);
        assert_eq!(rule.header.direction, Direction::ToDestination);
        assert_eq!(rule.sid, 1);
        assert_eq!(rule.rev, 1, "rev defaults to 1");
        assert_eq!(rule.msg, "minimal");
        assert!(rule.classtype.is_none());
        assert!(rule.is_evaluable());
    }

    #[test]
    fn parses_a_full_header() {
        let rule = parse_rule(
            r#"alert http !$EXTERNAL_NET [80,8080] <> 192.0.2.0/24 !1024: (msg:"m"; sid:2;)"#,
        )
        .unwrap();
        let header = rule.header;
        assert_eq!(header.protocol, Protocol::Http);
        assert!(header.source.negated);
        assert_eq!(
            header.source.value,
            AddressValue::Var("EXTERNAL_NET".into())
        );
        assert_eq!(
            header.source_port.value,
            PortValue::List("[80,8080]".into())
        );
        assert_eq!(header.direction, Direction::Bidirectional);
        assert_eq!(
            header.destination.value,
            AddressValue::Literal("192.0.2.0/24".into())
        );
        assert!(header.destination_port.negated);
        assert_eq!(
            header.destination_port.value,
            PortValue::Range(Some(1024), None)
        );
    }

    #[test]
    fn parses_metadata_classtype_and_rev() {
        let rule = parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; classtype:trojan-activity; metadata:phase 3, confidence medium, flag; sid:3; rev:7;)"#,
        )
        .unwrap();
        assert_eq!(rule.rev, 7);
        assert_eq!(rule.classtype.as_deref(), Some("trojan-activity"));
        assert_eq!(
            rule.metadata,
            vec![
                MetadataEntry {
                    key: "phase".into(),
                    value: "3".into()
                },
                MetadataEntry {
                    key: "confidence".into(),
                    value: "medium".into()
                },
                MetadataEntry {
                    key: "flag".into(),
                    value: String::new()
                },
            ]
        );
    }

    #[test]
    fn a_semicolon_inside_a_quoted_value_does_not_end_the_option() {
        let rule = parse_rule(r#"alert tcp any any -> any any (msg:"a; b; c"; sid:4;)"#).unwrap();
        assert_eq!(rule.msg, "a; b; c");
    }

    #[test]
    fn escapes_are_resolved_in_values() {
        let rule =
            parse_rule(r#"alert tcp any any -> any any (msg:"quote \" semi \; slash \\"; sid:5;)"#)
                .unwrap();
        assert_eq!(rule.msg, r#"quote " semi ; slash \"#);
    }

    #[test]
    fn regex_escapes_are_left_alone() {
        // `\d` must survive into Phase 3's regex compiler unchanged.
        let rule =
            parse_rule(r#"alert tcp any any -> any any (msg:"m"; pcre:"/\d+/"; sid:6;)"#).unwrap();
        assert_eq!(rule.unsupported_options, vec!["pcre".to_string()]);
        assert!(rule.raw.contains(r"\d+"));
    }

    #[test]
    fn a_valueless_option_is_accepted() {
        let rule = parse_rule(
            r#"alert http any any -> any any (msg:"m"; http.uri; content:"x"; nocase; sid:7;)"#,
        )
        .unwrap();
        assert_eq!(
            rule.unsupported_options,
            vec!["http.uri", "content", "nocase"]
        );
        assert!(
            !rule.is_evaluable(),
            "match conditions are not implemented yet"
        );
    }

    #[test]
    fn repeated_unsupported_options_are_listed_once() {
        let rule = parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; content:"a"; content:"b"; sid:8;)"#,
        )
        .unwrap();
        assert_eq!(rule.unsupported_options, vec!["content".to_string()]);
    }

    #[test]
    fn a_missing_final_semicolon_is_tolerated() {
        let rule = parse_rule(r#"alert tcp any any -> any any (msg:"m"; sid:9)"#).unwrap();
        assert_eq!(rule.sid, 9);
    }

    #[test]
    fn prevention_actions_are_rejected_not_downgraded() {
        for action in ["drop", "reject"] {
            let text = MINIMAL.replace("alert", action);
            assert!(
                matches!(parse_rule(&text), Err(ParseError::PreventionAction(_))),
                "{action} must be rejected: v1 cannot block"
            );
        }
    }

    #[test]
    fn a_reversed_arrow_is_rejected() {
        let text = MINIMAL.replace("->", "<-");
        assert!(matches!(
            parse_rule(&text),
            Err(ParseError::InvalidDirection(_))
        ));
    }

    #[test]
    fn a_typo_in_an_option_keyword_is_an_error() {
        // Loading this while ignoring `contnet` would leave a header-only rule
        // matching every packet on the port.
        let text = r#"alert tcp any any -> any any (msg:"m"; contnet:"evil"; sid:10;)"#;
        assert_eq!(
            parse_rule(text),
            Err(ParseError::UnknownOption("contnet".into()))
        );
    }

    #[test]
    fn sid_and_msg_are_required() {
        assert_eq!(
            parse_rule(r#"alert tcp any any -> any any (msg:"m";)"#),
            Err(ParseError::MissingSid)
        );
        assert_eq!(
            parse_rule(r#"alert tcp any any -> any any (sid:1;)"#),
            Err(ParseError::MissingMsg)
        );
    }

    #[test]
    fn duplicate_single_valued_options_are_rejected() {
        let text = r#"alert tcp any any -> any any (msg:"a"; msg:"b"; sid:1;)"#;
        assert_eq!(
            parse_rule(text),
            Err(ParseError::DuplicateOption("msg".into()))
        );
    }

    #[test]
    fn malformed_structure_is_reported_precisely() {
        assert_eq!(parse_rule(""), Err(ParseError::Empty));
        assert_eq!(
            parse_rule("alert tcp any any -> any any"),
            Err(ParseError::MissingOptionBlock)
        );
        assert_eq!(
            parse_rule(r#"alert tcp any any -> any any (msg:"m"; sid:1;"#),
            Err(ParseError::UnterminatedOptionBlock)
        );
        assert_eq!(
            parse_rule(r#"alert tcp any any -> any any (msg:"unterminated; sid:1;)"#),
            Err(ParseError::UnterminatedString)
        );
        assert_eq!(
            parse_rule(r#"alert tcp any -> any any (msg:"m"; sid:1;)"#),
            Err(ParseError::HeaderFieldCount { found: 6 })
        );
    }

    #[test]
    fn malformed_addresses_and_ports_are_rejected() {
        let cases = [
            r#"alert tcp 999.1.1.1 any -> any any (msg:"m"; sid:1;)"#,
            r#"alert tcp 10.0.0.0/33 any -> any any (msg:"m"; sid:1;)"#,
            r#"alert tcp [10.0.0.1,10.0.0.2 any -> any any (msg:"m"; sid:1;)"#,
            r#"alert tcp $ any -> any any (msg:"m"; sid:1;)"#,
            r#"alert tcp any 70000 -> any any (msg:"m"; sid:1;)"#,
            r#"alert tcp any 200:100 -> any any (msg:"m"; sid:1;)"#,
            r#"alert tcp any http -> any any (msg:"m"; sid:1;)"#,
        ];
        for case in cases {
            assert!(
                parse_rule(case).is_err(),
                "should have been rejected: {case}"
            );
        }
    }

    #[test]
    fn ipv6_literals_and_prefixes_work() {
        let rule =
            parse_rule(r#"alert tcp 2001:db8::/32 any -> ::1 any (msg:"m"; sid:1;)"#).unwrap();
        assert_eq!(
            rule.header.source.value,
            AddressValue::Literal("2001:db8::/32".into())
        );
        assert_eq!(
            rule.header.destination.value,
            AddressValue::Literal("::1".into())
        );
    }

    #[test]
    fn keywords_are_case_insensitive_but_values_are_not() {
        let rule = parse_rule(r#"ALERT TCP any any -> any any (MSG:"KeepCase"; SID:1;)"#).unwrap();
        assert_eq!(rule.header.action, Action::Alert);
        assert_eq!(rule.msg, "KeepCase");
    }

    #[test]
    fn host_rules_are_recognised_by_sid_range() {
        let network = parse_rule(MINIMAL).unwrap();
        assert!(!network.is_host_rule());
        let host = parse_rule(r#"alert ip any any -> any any (msg:"m"; sid:1000001;)"#).unwrap();
        assert!(host.is_host_rule());
    }

    /// The parser sees operator-supplied and, over time, third-party rule
    /// content. It must be total on every input, not just well-formed ones.
    #[test]
    fn never_panics_on_hostile_input() {
        let cases = [
            "(",
            ")",
            "()",
            ")(",
            "\\",
            "alert",
            "alert tcp any any -> any any (",
            "alert tcp any any -> any any ()",
            r#"alert tcp any any -> any any (";)"#,
            r#"alert tcp any any -> any any (msg:")"#,
            "alert tcp any any -> any any (:::;;;)",
            "alert tcp any any -> any any (sid:99999999999999999999;)",
            "\u{0}\u{1}\u{2}",
            "alert tcp any any -> any any (msg:\"\u{1F600}\"; sid:1;)",
            "alert tcp any any -> any any (msg:\"m\"; sid:1;)\u{0}",
            "→ ← ↔",
        ];
        for case in cases {
            let _ = parse_rule(case);
        }
        // Deeply nested and very long inputs must stay linear, not recursive.
        let _ = parse_rule(&"(".repeat(10_000));
        let _ = parse_rule(&format!(
            r#"alert tcp any any -> any any (msg:"{}"; sid:1;)"#,
            "a".repeat(100_000)
        ));
    }

    #[test]
    fn a_multibyte_value_is_not_split_mid_character() {
        let rule =
            parse_rule("alert tcp any any -> any any (msg:\"héllo → wörld\"; sid:1;)").unwrap();
        assert_eq!(rule.msg, "héllo → wörld");
    }
}
