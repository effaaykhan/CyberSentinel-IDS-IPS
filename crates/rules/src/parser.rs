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
use crate::options::{
    Buffer, ByteJump, ByteTest, ContentMatch, DsizeMatch, Endian, FlowBitsOp, FlowMatch, HostField,
    HostFieldMatch, HostMatcher, NormalizationCondition, NumericOp, PcreMatch, RuleOption,
    Threshold, ThresholdKind, Track,
};

/// Option keywords this format defines but this build cannot yet evaluate.
///
/// A rule using one of these still loads — flagged, and reported as
/// non-evaluable. Anything *not* listed here and not handled below is treated
/// as a typo and the rule is skipped. Keywords move out of this list as their
/// implementing phase lands.
pub const RECOGNISED_UNIMPLEMENTED_OPTIONS: &[&str] = &[
    // Content matching not yet implemented (Phase 8)
    "endswith",
    // Rate limiting (Phase 8)
    "detection_filter",
    // Annotations with no effect on matching (Phase 8)
    "target",
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
    /// The value was prefixed with `!`, as in `content:!"evil"`.
    negated: bool,
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

        let (name, raw_value) = match split_name_value(chunk) {
            Some((name, value)) => (name, Some(value.trim())),
            None => (chunk, None),
        };

        // Negation is stripped before unquoting so `content:!"evil"` reads as a
        // negated `evil` rather than as a value that happens to start with `!`.
        let (negated, raw_value) = match raw_value {
            Some(value) => match value.strip_prefix('!') {
                Some(rest) => (true, Some(rest.trim())),
                None => (false, Some(value)),
            },
            None => (false, None),
        };

        options.push(RawOption {
            name: name.trim().to_ascii_lowercase(),
            value: raw_value.map(unescape).transpose()?,
            negated,
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

/// Fold the parsed options into a [`Rule`], separating the ones this build
/// interprets from the ones it only recognises.
fn build_rule(header: RuleHeader, options: Vec<RawOption>, raw: &str) -> Result<Rule, ParseError> {
    let mut sid = None;
    let mut rev = None;
    let mut msg = None;
    let mut classtype = None;
    let mut priority = None;
    let mut gid = None;
    let mut threshold = None;
    let mut metadata = Vec::new();
    let mut references = Vec::new();
    let mut matches: Vec<RuleOption> = Vec::new();
    let mut unsupported: Vec<String> = Vec::new();
    let mut seen_unsupported = BTreeSet::new();
    let mut no_alert = false;

    // A sticky-buffer keyword applies to everything after it until the next
    // one, which is what lets a single rule look at the URI and then the
    // headers.
    let mut buffer = Buffer::Payload;

    for option in options {
        let RawOption {
            name,
            value,
            negated,
        } = option;

        match name.as_str() {
            // --- metadata -------------------------------------------------
            "sid" => {
                reject_duplicate(&sid, "sid")?;
                sid = Some(parse_u32_option(&name, value.as_deref())?);
            }
            "rev" => {
                reject_duplicate(&rev, "rev")?;
                rev = Some(parse_u32_option(&name, value.as_deref())?);
            }
            "gid" => {
                reject_duplicate(&gid, "gid")?;
                gid = Some(parse_u32_option(&name, value.as_deref())?);
            }
            "priority" => {
                reject_duplicate(&priority, "priority")?;
                let level = parse_u32_option(&name, value.as_deref())?;
                if !(1..=255).contains(&level) {
                    return Err(invalid(&name, "priority must be between 1 and 255"));
                }
                priority = Some(level as u8);
            }
            "msg" => {
                reject_duplicate(&msg, "msg")?;
                let text = require_value(&name, value)?;
                if text.trim().is_empty() {
                    return Err(invalid(&name, "msg must not be empty"));
                }
                msg = Some(text);
            }
            "classtype" => {
                reject_duplicate(&classtype, "classtype")?;
                classtype = Some(require_value(&name, value)?);
            }
            "metadata" => metadata.extend(parse_metadata(&require_value(&name, value)?)),
            "reference" => references.push(require_value(&name, value)?),

            // --- sticky buffers -------------------------------------------
            keyword if Buffer::from_keyword(keyword).is_some() => {
                if value.is_some() {
                    return Err(invalid(&name, "a sticky-buffer keyword takes no value"));
                }
                buffer = Buffer::from_keyword(keyword).unwrap_or_default();
            }

            // --- matching --------------------------------------------------
            "content" => {
                let pattern = parse_content_pattern(&require_value(&name, value)?)
                    .map_err(|reason| invalid(&name, &reason))?;
                if pattern.is_empty() {
                    return Err(invalid(&name, "content must not be empty"));
                }
                let mut content = ContentMatch::new(pattern);
                content.buffer = buffer;
                content.negated = negated;
                matches.push(RuleOption::Content(content));
            }
            "nocase" | "fast_pattern" | "startswith" | "offset" | "depth" | "distance"
            | "within" => {
                apply_content_modifier(&mut matches, &name, value.as_deref())?;
            }
            "pcre" => {
                let mut pcre = parse_pcre(&require_value(&name, value)?)
                    .map_err(|reason| invalid(&name, &reason))?;
                pcre.buffer = buffer;
                pcre.negated = negated;
                matches.push(RuleOption::Pcre(pcre));
            }
            "flow" => matches.push(RuleOption::Flow(
                parse_flow(&require_value(&name, value)?).map_err(|r| invalid(&name, &r))?,
            )),
            "flowbits" => {
                let op = parse_flowbits(&require_value(&name, value)?)
                    .map_err(|reason| invalid(&name, &reason))?;
                if matches!(op, FlowBitsOp::NoAlert) {
                    no_alert = true;
                } else {
                    matches.push(RuleOption::FlowBits(op));
                }
            }
            "byte_test" => matches.push(RuleOption::ByteTest(
                parse_byte_test(&require_value(&name, value)?).map_err(|r| invalid(&name, &r))?,
            )),
            "byte_jump" => matches.push(RuleOption::ByteJump(
                parse_byte_jump(&require_value(&name, value)?).map_err(|r| invalid(&name, &r))?,
            )),
            "dsize" => matches.push(RuleOption::Dsize(
                parse_dsize(&require_value(&name, value)?).map_err(|r| invalid(&name, &r))?,
            )),
            "normalized" => {
                let text = require_value(&name, value)?;
                let condition = NormalizationCondition::parse(&text)
                    .ok_or_else(|| invalid(&name, &format!("unknown condition {text:?}")))?;
                matches.push(RuleOption::Normalized(condition));
            }
            "threshold" => {
                reject_duplicate(&threshold, "threshold")?;
                threshold = Some(
                    parse_threshold(&require_value(&name, value)?)
                        .map_err(|reason| invalid(&name, &reason))?,
                );
            }

            // --- host events ----------------------------------------------
            keyword if HostField::from_keyword(keyword).is_some() => {
                let field = HostField::from_keyword(keyword)
                    .ok_or_else(|| invalid(&name, "unknown host field"))?;
                let values = parse_host_values(&require_value(&name, value)?)
                    .map_err(|reason| invalid(&name, &reason))?;
                matches.push(RuleOption::Host(HostFieldMatch {
                    field,
                    matcher: HostMatcher::AnyOf {
                        values,
                        kind: field.default_match_kind(),
                        nocase: false,
                    },
                    negated,
                }));
            }
            keyword
                if keyword
                    .strip_suffix(".pcre")
                    .and_then(HostField::from_keyword)
                    .is_some() =>
            {
                let field = keyword
                    .strip_suffix(".pcre")
                    .and_then(HostField::from_keyword)
                    .ok_or_else(|| invalid(&name, "unknown host field"))?;
                let expression = require_value(&name, value)?;
                if expression.trim().is_empty() {
                    return Err(invalid(&name, "empty expression"));
                }
                matches.push(RuleOption::Host(HostFieldMatch {
                    field,
                    matcher: HostMatcher::Regex(expression),
                    negated,
                }));
            }

            // --- recognised, not yet implemented ---------------------------
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
        gid,
        priority,
        msg: msg.ok_or(ParseError::MissingMsg)?,
        classtype,
        metadata,
        references,
        options: matches,
        threshold,
        no_alert,
        unsupported_options: unsupported,
        raw: raw.to_string(),
        origin: None,
    })
}

/// Split a host keyword's comma-separated alternatives.
///
/// Whitespace around each is trimmed and empties dropped, so
/// `file.path:"/etc/passwd, /etc/shadow"` reads the way it looks.
fn parse_host_values(text: &str) -> Result<Vec<String>, String> {
    let values: Vec<String> = text
        .split(',')
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    if values.is_empty() {
        return Err("needs at least one value".to_string());
    }
    Ok(values)
}

fn invalid(option: &str, reason: &str) -> ParseError {
    ParseError::InvalidOptionValue {
        option: option.to_string(),
        reason: reason.to_string(),
    }
}

/// Apply a modifier to the most recent `content`.
///
/// Modifiers are separate options that attach backwards, so one arriving with
/// no content in front of it is a rule that does not mean what its author
/// thought — an error, not something to ignore.
fn apply_content_modifier(
    matches: &mut [RuleOption],
    name: &str,
    value: Option<&str>,
) -> Result<(), ParseError> {
    let Some(RuleOption::Content(content)) = matches.last_mut() else {
        return Err(invalid(name, "no preceding content for this modifier"));
    };

    let number = |what: &str| -> Result<i64, ParseError> {
        value
            .ok_or_else(|| ParseError::MissingOptionValue(name.to_string()))?
            .trim()
            .parse::<i64>()
            .map_err(|_| invalid(name, &format!("{what} must be a number")))
    };

    match name {
        "nocase" => content.nocase = true,
        "fast_pattern" => content.fast_pattern = true,
        "startswith" => {
            // Exactly "at the very start": offset 0, and no further than the
            // pattern's own length.
            content.offset = Some(0);
            content.depth = Some(u32::try_from(content.pattern.len()).unwrap_or(u32::MAX));
        }
        "offset" => content.offset = Some(u32::try_from(number("offset")?).unwrap_or(0)),
        "depth" => content.depth = Some(u32::try_from(number("depth")?).unwrap_or(0)),
        "distance" => content.distance = Some(i32::try_from(number("distance")?).unwrap_or(0)),
        "within" => content.within = Some(u32::try_from(number("within")?).unwrap_or(0)),
        other => return Err(ParseError::UnknownOption(other.to_string())),
    }
    Ok(())
}

/// Parse a content pattern, resolving `|48 54 54 50|` hex sections.
///
/// Binary protocols need bytes that cannot be written literally, and a rule
/// author writing `|0d 0a|` means CRLF rather than those six characters.
fn parse_content_pattern(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len());
    let mut in_hex = false;
    let mut nibbles = String::new();

    for character in text.chars() {
        if character == '|' {
            if in_hex && !nibbles.is_empty() {
                return Err("a hex section ended mid-byte".to_string());
            }
            in_hex = !in_hex;
            continue;
        }
        if !in_hex {
            // Non-ASCII in a content pattern is almost always a mistake — a
            // smart quote pasted from a document — and silently encoding it as
            // UTF-8 would produce a pattern that never matches.
            if !character.is_ascii() {
                return Err(format!(
                    "non-ASCII character {character:?} in a pattern; use a |hex| section"
                ));
            }
            out.push(character as u8);
            continue;
        }
        if character.is_ascii_whitespace() {
            continue;
        }
        if !character.is_ascii_hexdigit() {
            return Err(format!("{character:?} is not a hex digit"));
        }
        nibbles.push(character);
        if nibbles.len() == 2 {
            let byte = u8::from_str_radix(&nibbles, 16).map_err(|error| error.to_string())?;
            out.push(byte);
            nibbles.clear();
        }
    }

    if in_hex {
        return Err("unterminated hex section".to_string());
    }
    Ok(out)
}

/// Parse `/expression/flags`.
fn parse_pcre(text: &str) -> Result<PcreMatch, String> {
    let text = text.trim();
    let body = text
        .strip_prefix('/')
        .ok_or_else(|| "a pcre must be delimited with /".to_string())?;
    let close = body
        .rfind('/')
        .ok_or_else(|| "a pcre must be delimited with /".to_string())?;
    let (source, flags) = body.split_at(close);
    if source.is_empty() {
        return Err("empty expression".to_string());
    }

    let mut pcre = PcreMatch {
        source: source.to_string(),
        buffer: Buffer::Payload,
        negated: false,
        case_insensitive: false,
        dot_matches_newline: false,
        multi_line: false,
        relative: false,
    };
    for flag in flags.trim_start_matches('/').chars() {
        match flag {
            'i' => pcre.case_insensitive = true,
            's' => pcre.dot_matches_newline = true,
            'm' => pcre.multi_line = true,
            'R' => pcre.relative = true,
            other => return Err(format!("unknown pcre flag {other:?}")),
        }
    }
    Ok(pcre)
}

fn parse_flow(text: &str) -> Result<FlowMatch, String> {
    let mut flow = FlowMatch::default();
    for part in text.split(',') {
        match part.trim() {
            "established" => flow.established = Some(true),
            "not_established" | "stateless" => flow.established = Some(false),
            "to_server" | "from_client" => flow.to_server = Some(true),
            "to_client" | "from_server" => flow.to_server = Some(false),
            other => return Err(format!("unknown flow option {other:?}")),
        }
    }
    Ok(flow)
}

fn parse_flowbits(text: &str) -> Result<FlowBitsOp, String> {
    let mut parts = text.splitn(2, ',');
    let command = parts.next().unwrap_or("").trim();
    let name = parts.next().map(str::trim).unwrap_or("");

    let named = |op: fn(String) -> FlowBitsOp| -> Result<FlowBitsOp, String> {
        if name.is_empty() {
            return Err(format!("flowbits:{command} needs a bit name"));
        }
        Ok(op(name.to_string()))
    };

    match command {
        "set" => named(FlowBitsOp::Set),
        "unset" => named(FlowBitsOp::Unset),
        "toggle" => named(FlowBitsOp::Toggle),
        "isset" => named(FlowBitsOp::IsSet),
        "isnotset" => named(FlowBitsOp::IsNotSet),
        "noalert" => Ok(FlowBitsOp::NoAlert),
        other => Err(format!("unknown flowbits command {other:?}")),
    }
}

fn parse_byte_test(text: &str) -> Result<ByteTest, String> {
    let parts: Vec<&str> = text.split(',').map(str::trim).collect();
    if parts.len() < 4 {
        return Err("byte_test needs at least bytes, operator, value, offset".to_string());
    }

    let bytes: u8 = parts[0].parse().map_err(|_| "bytes must be a number")?;
    if !(1..=8).contains(&bytes) {
        return Err("byte_test can read between 1 and 8 bytes".to_string());
    }
    let (operator, negated) = match parts[1].strip_prefix('!') {
        Some(rest) => (rest.trim(), true),
        None => (parts[1], false),
    };
    let op = NumericOp::parse(operator).ok_or_else(|| format!("unknown operator {operator:?}"))?;
    let value: u64 = parts[2].parse().map_err(|_| "value must be a number")?;
    let offset: i32 = parts[3].parse().map_err(|_| "offset must be a number")?;

    let mut test = ByteTest {
        bytes,
        op,
        value,
        offset,
        relative: false,
        endian: Endian::Big,
        negated,
    };
    for modifier in &parts[4..] {
        match *modifier {
            "relative" => test.relative = true,
            "big" => test.endian = Endian::Big,
            "little" => test.endian = Endian::Little,
            "" => {}
            other => return Err(format!("unsupported byte_test modifier {other:?}")),
        }
    }
    Ok(test)
}

fn parse_byte_jump(text: &str) -> Result<ByteJump, String> {
    let parts: Vec<&str> = text.split(',').map(str::trim).collect();
    if parts.len() < 2 {
        return Err("byte_jump needs at least bytes and offset".to_string());
    }

    let bytes: u8 = parts[0].parse().map_err(|_| "bytes must be a number")?;
    if !(1..=8).contains(&bytes) {
        return Err("byte_jump can read between 1 and 8 bytes".to_string());
    }
    let offset: i32 = parts[1].parse().map_err(|_| "offset must be a number")?;

    let mut jump = ByteJump {
        bytes,
        offset,
        relative: false,
        multiplier: 1,
        endian: Endian::Big,
        post_offset: 0,
    };
    let mut index = 2;
    while index < parts.len() {
        match parts[index] {
            "relative" => jump.relative = true,
            "big" => jump.endian = Endian::Big,
            "little" => jump.endian = Endian::Little,
            "" => {}
            other => {
                let mut words = other.split_whitespace();
                match (words.next(), words.next()) {
                    (Some("multiplier"), Some(value)) => {
                        jump.multiplier =
                            value.parse().map_err(|_| "multiplier must be a number")?;
                    }
                    (Some("post_offset"), Some(value)) => {
                        jump.post_offset =
                            value.parse().map_err(|_| "post_offset must be a number")?;
                    }
                    _ => return Err(format!("unsupported byte_jump modifier {other:?}")),
                }
            }
        }
        index += 1;
    }
    Ok(jump)
}

fn parse_dsize(text: &str) -> Result<DsizeMatch, String> {
    let text = text.trim();
    if let Some((low, high)) = text.split_once("<>") {
        return Ok(DsizeMatch {
            op: NumericOp::Greater,
            value: low
                .trim()
                .parse()
                .map_err(|_| "dsize bounds must be numbers")?,
            upper: Some(
                high.trim()
                    .parse()
                    .map_err(|_| "dsize bounds must be numbers")?,
            ),
        });
    }

    let split = text
        .find(|c: char| c.is_ascii_digit())
        .ok_or_else(|| "dsize needs a number".to_string())?;
    let (operator, value) = text.split_at(split);
    let op = if operator.trim().is_empty() {
        NumericOp::Equal
    } else {
        NumericOp::parse(operator).ok_or_else(|| format!("unknown operator {operator:?}"))?
    };
    Ok(DsizeMatch {
        op,
        value: value.trim().parse().map_err(|_| "dsize must be a number")?,
        upper: None,
    })
}

fn parse_threshold(text: &str) -> Result<Threshold, String> {
    let mut kind = None;
    let mut track = None;
    let mut count = None;
    let mut seconds = None;

    for part in text.split(',') {
        let mut words = part.split_whitespace();
        match (words.next(), words.next()) {
            (Some("type"), Some(value)) => {
                kind = Some(match value {
                    "threshold" => ThresholdKind::Threshold,
                    "limit" => ThresholdKind::Limit,
                    "both" => ThresholdKind::Both,
                    other => return Err(format!("unknown threshold type {other:?}")),
                });
            }
            (Some("track"), Some(value)) => {
                track = Some(match value {
                    "by_src" => Track::BySource,
                    "by_dst" => Track::ByDestination,
                    "by_rule" => Track::ByRule,
                    other => return Err(format!("unknown threshold track {other:?}")),
                });
            }
            (Some("count"), Some(value)) => {
                count = Some(value.parse().map_err(|_| "count must be a number")?);
            }
            (Some("seconds"), Some(value)) => {
                seconds = Some(value.parse().map_err(|_| "seconds must be a number")?);
            }
            (Some(""), _) | (None, _) => {}
            (Some(other), _) => return Err(format!("unknown threshold field {other:?}")),
        }
    }

    let count = count.ok_or("threshold needs a count")?;
    if count == 0 {
        return Err("threshold count must be at least 1".to_string());
    }
    Ok(Threshold {
        kind: kind.ok_or("threshold needs a type")?,
        track: track.ok_or("threshold needs a track")?,
        count,
        seconds: seconds.ok_or("threshold needs a seconds window")?,
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
        .map_err(|_| invalid(name, &format!("{:?} is not a number", value.trim())))
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
    use crate::options::{DsizeMatch, FlowMatch};

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
    fn regex_escapes_reach_the_expression_unchanged() {
        let rule =
            parse_rule(r#"alert tcp any any -> any any (msg:"m"; pcre:"/\d+/i"; sid:6;)"#).unwrap();
        let Some(RuleOption::Pcre(pcre)) = rule.options.first() else {
            panic!("expected a pcre option, got {:?}", rule.options);
        };
        assert_eq!(pcre.source, r"\d+");
        assert!(pcre.case_insensitive);
        assert!(rule.is_evaluable());
    }

    #[test]
    fn a_sticky_buffer_applies_to_the_matches_that_follow_it() {
        let rule = parse_rule(
            r#"alert http any any -> any any (msg:"m"; http.uri; content:"x"; nocase; content:"y"; http.header; content:"z"; sid:7;)"#,
        )
        .unwrap();
        assert!(rule.is_evaluable());

        let buffers: Vec<Buffer> = rule.options.iter().filter_map(RuleOption::buffer).collect();
        assert_eq!(
            buffers,
            vec![Buffer::HttpUri, Buffer::HttpUri, Buffer::HttpHeader],
            "the buffer persists until another keyword changes it"
        );

        let Some(RuleOption::Content(first)) = rule.options.first() else {
            panic!("expected content");
        };
        assert!(first.nocase, "nocase attaches to the content before it");
        assert!(rule.needs_http());
    }

    #[test]
    fn repeated_unsupported_options_are_listed_once() {
        let rule = parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; content:"a"; endswith; content:"b"; endswith; sid:8;)"#,
        )
        .unwrap();
        assert_eq!(rule.unsupported_options, vec!["endswith".to_string()]);
        assert!(!rule.is_evaluable());
    }

    // -----------------------------------------------------------------------
    // match conditions
    // -----------------------------------------------------------------------

    #[test]
    fn parses_content_with_its_modifiers() {
        let rule = parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; content:"GET"; offset:0; depth:3; content:"HTTP"; distance:1; within:20; fast_pattern; sid:1;)"#,
        )
        .unwrap();

        let Some(RuleOption::Content(first)) = rule.options.first() else {
            panic!("expected content");
        };
        assert_eq!(first.pattern, b"GET");
        assert_eq!(first.offset, Some(0));
        assert_eq!(first.depth, Some(3));
        assert!(!first.is_relative());

        let Some(RuleOption::Content(second)) = rule.options.get(1) else {
            panic!("expected a second content");
        };
        assert_eq!(second.distance, Some(1));
        assert_eq!(second.within, Some(20));
        assert!(second.is_relative());
        assert!(second.fast_pattern);
    }

    #[test]
    fn parses_hex_sections_in_content() {
        let rule = parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; content:"GET|20 2f|HTTP|0d0a|"; sid:1;)"#,
        )
        .unwrap();
        let Some(RuleOption::Content(content)) = rule.options.first() else {
            panic!("expected content");
        };
        assert_eq!(content.pattern, b"GET /HTTP\r\n");
    }

    #[test]
    fn rejects_malformed_hex_sections() {
        for text in [
            r#"alert tcp any any -> any any (msg:"m"; content:"|41"; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"m"; content:"|4|"; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"m"; content:"|zz|"; sid:1;)"#,
        ] {
            assert!(
                parse_rule(text).is_err(),
                "should have been rejected: {text}"
            );
        }
    }

    #[test]
    fn a_negated_content_is_recognised_as_such() {
        let rule =
            parse_rule(r#"alert tcp any any -> any any (msg:"m"; content:!"benign"; sid:1;)"#)
                .unwrap();
        let Some(RuleOption::Content(content)) = rule.options.first() else {
            panic!("expected content");
        };
        assert!(content.negated);
        assert_eq!(content.pattern, b"benign");
        assert!(!content.usable_as_fast_pattern());
    }

    #[test]
    fn startswith_anchors_the_pattern_to_the_start() {
        let rule = parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; content:"GET"; startswith; sid:1;)"#,
        )
        .unwrap();
        let Some(RuleOption::Content(content)) = rule.options.first() else {
            panic!("expected content");
        };
        assert_eq!(content.offset, Some(0));
        assert_eq!(content.depth, Some(3));
    }

    #[test]
    fn a_modifier_with_no_content_before_it_is_an_error() {
        // Silently ignoring it would leave a rule that does not mean what its
        // author wrote.
        let error =
            parse_rule(r#"alert tcp any any -> any any (msg:"m"; nocase; sid:1;)"#).unwrap_err();
        assert!(
            error.to_string().contains("no preceding content"),
            "{error}"
        );
    }

    #[test]
    fn parses_flow_and_flowbits() {
        let rule = parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; flow:established,to_server; flowbits:isset,logged_in; flowbits:set,seen; sid:1;)"#,
        )
        .unwrap();
        assert!(matches!(
            rule.options.first(),
            Some(RuleOption::Flow(FlowMatch {
                established: Some(true),
                to_server: Some(true)
            }))
        ));
        assert!(matches!(
            rule.options.get(1),
            Some(RuleOption::FlowBits(FlowBitsOp::IsSet(_)))
        ));
    }

    #[test]
    fn flowbits_noalert_marks_the_rule_rather_than_adding_a_condition() {
        let rule = parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; flowbits:set,seen; flowbits:noalert; sid:1;)"#,
        )
        .unwrap();
        assert!(rule.no_alert);
        assert_eq!(rule.options.len(), 1, "noalert is not a match condition");
    }

    #[test]
    fn parses_byte_test_and_byte_jump() {
        let rule = parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; byte_test:2,>,1000,0,relative,little; byte_jump:4,0,relative,multiplier 2,post_offset -4; sid:1;)"#,
        )
        .unwrap();

        let Some(RuleOption::ByteTest(test)) = rule.options.first() else {
            panic!("expected byte_test");
        };
        assert_eq!(test.bytes, 2);
        assert_eq!(test.op, NumericOp::Greater);
        assert_eq!(test.value, 1_000);
        assert!(test.relative);
        assert_eq!(test.endian, Endian::Little);

        let Some(RuleOption::ByteJump(jump)) = rule.options.get(1) else {
            panic!("expected byte_jump");
        };
        assert_eq!(jump.multiplier, 2);
        assert_eq!(jump.post_offset, -4);
        assert!(jump.relative);
    }

    #[test]
    fn parses_dsize_comparisons_and_ranges() {
        let single =
            parse_rule(r#"alert udp any any -> any any (msg:"m"; dsize:>200; sid:1;)"#).unwrap();
        assert!(matches!(
            single.options.first(),
            Some(RuleOption::Dsize(DsizeMatch {
                op: NumericOp::Greater,
                value: 200,
                upper: None
            }))
        ));

        let range = parse_rule(r#"alert udp any any -> any any (msg:"m"; dsize:100<>200; sid:1;)"#)
            .unwrap();
        let Some(RuleOption::Dsize(dsize)) = range.options.first() else {
            panic!("expected dsize");
        };
        assert_eq!(dsize.upper, Some(200));
    }

    #[test]
    fn parses_threshold() {
        let rule = parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; threshold:type threshold, track by_src, count 20, seconds 60; sid:1;)"#,
        )
        .unwrap();
        let threshold = rule.threshold.expect("a threshold");
        assert_eq!(threshold.kind, ThresholdKind::Threshold);
        assert_eq!(threshold.track, Track::BySource);
        assert_eq!(threshold.count, 20);
        assert_eq!(threshold.seconds, 60);
    }

    #[test]
    fn an_incomplete_threshold_is_rejected() {
        // Half a threshold would silently rate-limit differently from what the
        // author wrote.
        for text in [
            r#"alert tcp any any -> any any (msg:"m"; threshold:type threshold, count 5; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"m"; threshold:track by_src, count 5, seconds 60; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"m"; threshold:type threshold, track by_src, count 0, seconds 60; sid:1;)"#,
        ] {
            assert!(
                parse_rule(text).is_err(),
                "should have been rejected: {text}"
            );
        }
    }

    #[test]
    fn parses_normalization_conditions() {
        let rule = parse_rule(
            r#"alert http any any -> any any (msg:"m"; http.uri; normalized:double_encoded; sid:1;)"#,
        )
        .unwrap();
        assert!(matches!(
            rule.options.last(),
            Some(RuleOption::Normalized(
                NormalizationCondition::DoubleEncoded
            ))
        ));
    }

    #[test]
    fn priority_becomes_the_alert_severity() {
        let rule =
            parse_rule(r#"alert tcp any any -> any any (msg:"m"; priority:1; sid:1;)"#).unwrap();
        assert_eq!(rule.severity(), 1);

        let default = parse_rule(r#"alert tcp any any -> any any (msg:"m"; sid:1;)"#).unwrap();
        assert_eq!(
            default.severity(),
            3,
            "an author who says nothing gets the middle"
        );
    }

    #[test]
    fn malformed_option_values_are_rejected_with_a_reason() {
        for text in [
            r#"alert tcp any any -> any any (msg:"m"; flow:sideways; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"m"; flowbits:frobnicate,x; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"m"; flowbits:set; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"m"; pcre:"no-delimiters"; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"m"; pcre:"/x/q"; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"m"; byte_test:99,>,1,0; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"m"; byte_test:2,nonsense,1,0; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"m"; dsize:abc; sid:1;)"#,
            r#"alert http any any -> any any (msg:"m"; normalized:nonsense; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"m"; http.uri:value; sid:1;)"#,
        ] {
            assert!(
                parse_rule(text).is_err(),
                "should have been rejected: {text}"
            );
        }
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
