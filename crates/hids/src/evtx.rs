//! Windows Security log logon events (4624 / 4625) → [`AuthEvent`].
//!
//! The Windows counterpart of [`crate::logs`], and a much better one. Syslog
//! forces a guess: sshd writes `for invalid user bob` when the account does not
//! exist and `for bob` when it does, so someone logging in as the literal
//! string `invalid user root` produces a line nobody can disambiguate — the
//! limitation `crate::logs` documents rather than hides. Here the account is a
//! **field**. There is nothing to disambiguate.
//!
//! # What this parses, and what it does not
//!
//! `EvtRender` hands back an XML rendering of an event. This module parses that
//! rendering; obtaining it is the FFI layer's job. Splitting it this way is
//! what makes the mapping testable at all without Windows, and it keeps the
//! parsing of attacker-influenced text out of the crate that has to be
//! `unsafe`.
//!
//! # The field is structured; its contents are still hostile
//!
//! `TargetUserName` is whatever somebody typed at a logon prompt, including at
//! an RDP prompt exposed to the internet. Being a field rather than free text
//! removes the *ambiguity*, not the *hostility*: the value still reaches an
//! event log that gets read in a terminal, still has no length limit of its
//! own, and — if the renderer ever failed to escape it — could carry markup
//! that looks like more fields.
//!
//! So the same discipline as the syslog parser applies, plus two checks that
//! only make sense here:
//!
//! * a value that still contains markup after entity decoding is **flagged**,
//!   because a correctly rendered event cannot produce one;
//! * a field that appears **more than once** is refused outright, not resolved.
//!   A second occurrence is either a renderer bug or an injection, and because
//!   `TargetUserName` is rendered *before* `IpAddress`, taking the first would
//!   hand an attacker a forged source address. No field beats a forged one.

use cybersentinel_common::event::{AuthEvent, AuthOutcome};
use std::net::IpAddr;

/// Successful logon.
pub const EVENT_ID_LOGON_SUCCESS: u32 = 4_624;
/// Failed logon.
pub const EVENT_ID_LOGON_FAILURE: u32 = 4_625;
/// Explicit-credential logon (`runas`, lateral movement).
pub const EVENT_ID_EXPLICIT_CREDENTIALS: u32 = 4_648;

/// Longest field value kept, in characters.
const MAX_FIELD_CHARS: usize = 256;
/// Longest rendered event considered at all.
pub const MAX_EVENT_BYTES: usize = 64 * 1_024;

/// How the logon was attempted.
///
/// Worth carrying because it changes what an event means: a type 3 or type 10
/// failure from a routable address is somebody trying the door, while a type 5
/// failure is usually a service account with a stale password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogonType {
    /// 2 — at the keyboard.
    Interactive,
    /// 3 — from the network, e.g. SMB.
    Network,
    /// 4 — a scheduled task.
    Batch,
    /// 5 — a service starting.
    Service,
    /// 7 — a workstation unlock.
    Unlock,
    /// 8 — network logon with a cleartext password.
    NetworkCleartext,
    /// 9 — `runas /netonly`.
    NewCredentials,
    /// 10 — RDP.
    RemoteInteractive,
    /// 11 — cached credentials.
    CachedInteractive,
    /// Anything else, kept as its number rather than dropped.
    Other(u32),
}

impl LogonType {
    /// Map the numeric field.
    #[must_use]
    pub fn from_code(code: u32) -> Self {
        match code {
            2 => Self::Interactive,
            3 => Self::Network,
            4 => Self::Batch,
            5 => Self::Service,
            7 => Self::Unlock,
            8 => Self::NetworkCleartext,
            9 => Self::NewCredentials,
            10 => Self::RemoteInteractive,
            11 => Self::CachedInteractive,
            other => Self::Other(other),
        }
    }

    /// A short name for the event message.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Network => "network",
            Self::Batch => "batch",
            Self::Service => "service",
            Self::Unlock => "unlock",
            Self::NetworkCleartext => "network-cleartext",
            Self::NewCredentials => "new-credentials",
            Self::RemoteInteractive => "remote-interactive",
            Self::CachedInteractive => "cached-interactive",
            Self::Other(_) => "other",
        }
    }

    /// Whether the logon came over the network rather than from the console.
    ///
    /// This is the distinction that makes a failed-logon burst interesting: a
    /// thousand console failures is somebody at the keyboard, a thousand
    /// network failures is somebody with a password list.
    #[must_use]
    pub fn is_remote(self) -> bool {
        matches!(
            self,
            Self::Network | Self::NetworkCleartext | Self::RemoteInteractive
        )
    }
}

/// A parsed logon event, before the sensor stamps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLogon {
    /// The normalized event.
    pub event: AuthEvent,
    /// How the logon was attempted.
    pub logon_type: Option<LogonType>,
    /// The Windows event id it came from.
    pub event_id: u32,
}

/// Take at most `limit` characters, replacing control characters.
///
/// Characters, not bytes: slicing a UTF-8 string by byte offset panics on a
/// multi-byte boundary, and these values are attacker-chosen. The syslog
/// parser learned that one the hard way.
fn sanitise(text: &str, limit: usize) -> (String, bool) {
    let mut changed = false;
    let mut out = String::new();
    for character in text.chars() {
        if out.chars().count() >= limit {
            changed = true;
            break;
        }
        if character.is_control() {
            out.push('.');
            changed = true;
        } else {
            out.push(character);
        }
    }
    (out, changed)
}

/// Decode the five XML entities `EvtRender` produces.
///
/// Deliberately not a general entity decoder: numeric character references are
/// left alone rather than expanded, because expanding them is how a decoder
/// turns `&#60;` into markup that a later stage then trusts.
fn decode_entities(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        // Ampersand last: doing it first would let `&amp;lt;` become `<`.
        .replace("&amp;", "&")
}

/// Every `<Data Name="…">…</Data>` value for one name, in document order.
///
/// Returns all occurrences rather than the first, so the caller can notice a
/// duplicate. A correctly rendered event has exactly one of each.
fn data_fields<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let opening = format!("<Data Name=\"{name}\">");
    let mut values = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&opening) {
        let after = &rest[start + opening.len()..];
        match after.find("</Data>") {
            Some(end) => {
                values.push(&after[..end]);
                rest = &after[end..];
            }
            // An unterminated field is not a value. Stop rather than guess
            // where it ended.
            None => break,
        }
    }
    values
}

/// Read the event id out of the `System` section.
#[must_use]
pub fn event_id(xml: &str) -> Option<u32> {
    let start = xml.find("<EventID")?;
    let after = &xml[start..];
    let open = after.find('>')? + 1;
    let close = after.find("</EventID>")?;
    if close <= open {
        return None;
    }
    after[open..close].trim().parse().ok()
}

/// Pull one field, decode it, and note anything that should not be there.
///
/// **A field that appears more than once is not used at all.** A correctly
/// rendered event has exactly one of each, so a duplicate means either the
/// renderer is broken or an unescaped value has injected markup — and in the
/// second case the attacker chooses where their injection lands. Taking the
/// first occurrence is no defence: `TargetUserName` is rendered *before*
/// `IpAddress`, so a username carrying `</Data><Data Name="IpAddress">…` puts
/// the forged address first. Refusing the field entirely is the only answer
/// that does not hand an attacker a field they did not own, and it matches how
/// the rest of the engine behaves — fail closed on anything unanswerable.
///
/// The cost is a missing field on a suspicious event, which is much cheaper
/// than a forged one: a rule matching on the source address simply does not
/// match, instead of matching a value the attacker picked.
fn field(xml: &str, name: &str, suspicious: &mut Vec<String>) -> Option<String> {
    let occurrences = data_fields(xml, name);
    if occurrences.len() > 1 {
        suspicious.push(format!(
            "field {name} appears {} times; refusing it rather than choosing one",
            occurrences.len()
        ));
        return None;
    }
    let raw = occurrences.first()?;
    let decoded = decode_entities(raw);

    if decoded.contains('<') || decoded.contains('>') {
        // A correctly rendered event cannot produce this: the renderer escapes
        // markup. Recorded anyway — hiding the attempt would be worse — but
        // marked so nothing downstream treats it as an ordinary value.
        suspicious.push(format!("field {name} contains markup after decoding"));
    }

    let (clean, changed) = sanitise(&decoded, MAX_FIELD_CHARS);
    if changed {
        suspicious.push(format!(
            "field {name} was truncated or held control characters"
        ));
    }
    if clean.is_empty() {
        return None;
    }
    Some(clean)
}

/// Windows writes `-` for "no value" in several fields.
fn meaningful(value: Option<String>) -> Option<String> {
    value.filter(|text| text != "-" && !text.is_empty())
}

/// Parse a rendered Security-log event into an [`AuthEvent`].
///
/// Returns `None` for events that are not logon decisions. Inventing an auth
/// event from an unrelated record would be worse than ignoring it.
#[must_use]
pub fn parse_logon_event(xml: &str) -> Option<ParsedLogon> {
    if xml.len() > MAX_EVENT_BYTES {
        return None;
    }
    let id = event_id(xml)?;
    let outcome = match id {
        EVENT_ID_LOGON_SUCCESS | EVENT_ID_EXPLICIT_CREDENTIALS => AuthOutcome::Success,
        EVENT_ID_LOGON_FAILURE => AuthOutcome::Failure,
        _ => return None,
    };

    let mut suspicious = Vec::new();

    // `TargetUserName` is the account somebody tried to log in *as*. Where the
    // event has both, `SubjectUserName` is the account that initiated the
    // attempt — a different question, and not the one an auth event answers.
    let user = meaningful(field(xml, "TargetUserName", &mut suspicious));
    let domain = meaningful(field(xml, "TargetDomainName", &mut suspicious));
    let workstation = meaningful(field(xml, "WorkstationName", &mut suspicious));

    let logon_type = meaningful(field(xml, "LogonType", &mut suspicious))
        .and_then(|code| code.parse::<u32>().ok())
        .map(LogonType::from_code);

    // The address must parse as an address. A field saying `-`, `LOCAL`, or a
    // hostname yields no address rather than a made-up one — same rule as the
    // syslog parser, and the reason a username full of markup cannot invent a
    // source.
    let raw_address = meaningful(field(xml, "IpAddress", &mut suspicious));
    let source_address = match raw_address.as_deref() {
        Some(text) => match text.parse::<IpAddr>() {
            Ok(address) => Some(address),
            Err(_) => {
                // `LOCAL` and `-` are ordinary for console logons; anything
                // else claiming to be an address and failing to parse is worth
                // flagging.
                if !matches!(text, "LOCAL" | "127.0.0.1" | "::1") {
                    suspicious.push(format!(
                        "IpAddress {:?} is not an address",
                        text.chars().take(48).collect::<String>()
                    ));
                }
                None
            }
        },
        None => None,
    };
    let source_port = meaningful(field(xml, "IpPort", &mut suspicious))
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0);

    // A one-line summary in the shape the rest of the pipeline expects. Built
    // from the parsed fields rather than from the event's own rendered message,
    // which is localised and would make rules locale-dependent.
    let mut message = format!(
        "{} logon (event {id})",
        match outcome {
            AuthOutcome::Success => "successful",
            AuthOutcome::Failure => "failed",
        }
    );
    if let Some(kind) = logon_type {
        message.push_str(&format!(", type {}", kind.as_str()));
    }
    if let Some(account) = &user {
        let qualified = match &domain {
            Some(domain) => format!("{domain}\\{account}"),
            None => account.clone(),
        };
        message.push_str(&format!(", account {qualified}"));
    }
    if let Some(host) = &workstation {
        message.push_str(&format!(", from workstation {host}"));
    }
    if id == EVENT_ID_LOGON_FAILURE {
        if let Some(status) = meaningful(field(xml, "Status", &mut suspicious)) {
            message.push_str(&format!(", status {status}"));
        }
    }

    Some(ParsedLogon {
        event: AuthEvent {
            outcome,
            user,
            // The service that reported it. Windows logon events come from the
            // Security channel via LSA, and the logon process is the closest
            // analogue to sshd/sudo.
            service: meaningful(field(xml, "LogonProcessName", &mut suspicious))
                .or_else(|| Some("Security".to_string())),
            source_address,
            source_port,
            message,
            log_source: "windows-security".to_string(),
            suspicious,
        },
        logon_type,
        event_id: id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rendered 4625 the way `EvtRender` produces one, trimmed to the fields
    /// this module reads.
    fn failure_event(user: &str, address: &str, logon_type: u32) -> String {
        format!(
            r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Computer>WEB01</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">-</Data>
    <Data Name="TargetUserName">{user}</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="SubStatus">0xc0000064</Data>
    <Data Name="LogonType">{logon_type}</Data>
    <Data Name="LogonProcessName">NtLmSsp</Data>
    <Data Name="WorkstationName">ATTACKER-PC</Data>
    <Data Name="IpAddress">{address}</Data>
    <Data Name="IpPort">50331</Data>
  </EventData>
</Event>"#
        )
    }

    fn success_event(user: &str, address: &str) -> String {
        format!(
            r#"<Event><System><EventID>4624</EventID></System>
  <EventData>
    <Data Name="TargetUserName">{user}</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="LogonProcessName">User32</Data>
    <Data Name="IpAddress">{address}</Data>
    <Data Name="IpPort">3389</Data>
  </EventData></Event>"#
        )
    }

    #[test]
    fn parses_a_failed_logon() {
        let parsed =
            parse_logon_event(&failure_event("admin", "203.0.113.7", 3)).expect("a record");

        assert_eq!(parsed.event_id, 4_625);
        assert_eq!(parsed.event.outcome, AuthOutcome::Failure);
        assert_eq!(parsed.event.user.as_deref(), Some("admin"));
        assert_eq!(
            parsed
                .event
                .source_address
                .map(|a| a.to_string())
                .as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(parsed.event.source_port, Some(50_331));
        assert_eq!(parsed.logon_type, Some(LogonType::Network));
        assert_eq!(parsed.event.log_source, "windows-security");
        assert!(parsed.event.suspicious.is_empty());
    }

    #[test]
    fn parses_a_successful_rdp_logon() {
        let parsed = parse_logon_event(&success_event("deploy", "10.0.0.5")).expect("a record");
        assert_eq!(parsed.event.outcome, AuthOutcome::Success);
        assert_eq!(parsed.logon_type, Some(LogonType::RemoteInteractive));
        assert!(parsed.logon_type.expect("a type").is_remote());
    }

    /// The whole point of preferring the Event Log over syslog: the account is
    /// a field, so the `for invalid user bob` ambiguity cannot arise.
    #[test]
    fn a_username_that_reads_like_syslog_text_is_still_just_the_username() {
        let parsed = parse_logon_event(&failure_event("invalid user root", "203.0.113.7", 3))
            .expect("a record");
        assert_eq!(
            parsed.event.user.as_deref(),
            Some("invalid user root"),
            "the field says what the account was; there is nothing to disambiguate"
        );
        assert_eq!(
            parsed
                .event
                .source_address
                .map(|a| a.to_string())
                .as_deref(),
            Some("203.0.113.7")
        );
    }

    #[test]
    fn an_event_that_is_not_a_logon_decision_is_ignored() {
        let xml = r#"<Event><System><EventID>4634</EventID></System>
            <EventData><Data Name="TargetUserName">bob</Data></EventData></Event>"#;
        assert!(
            parse_logon_event(xml).is_none(),
            "inventing an auth event from a logoff would be worse than ignoring it"
        );
    }

    #[test]
    fn events_without_an_id_are_ignored() {
        for xml in [
            "",
            "<Event/>",
            "<Event><System></System></Event>",
            "<EventID>",
        ] {
            assert!(parse_logon_event(xml).is_none(), "{xml:?}");
        }
    }

    // -----------------------------------------------------------------------
    // the field is structured; its contents are still hostile
    // -----------------------------------------------------------------------

    /// The Windows analogue of the syslog injection test, and the one that
    /// shaped the design. If the renderer ever failed to escape a username, a
    /// crafted one would look like more fields — and because `TargetUserName`
    /// is rendered *before* `IpAddress`, the forged address comes first. Taking
    /// the first occurrence would hand the attacker the field. The parser
    /// refuses a duplicated field outright instead.
    #[test]
    fn a_username_containing_markup_cannot_fabricate_a_source_address() {
        let hostile = r#"bob</Data><Data Name="IpAddress">198.51.100.9</Data><Data Name="X">"#;
        let parsed =
            parse_logon_event(&failure_event(hostile, "203.0.113.7", 3)).expect("a record");

        assert_eq!(
            parsed.event.source_address, None,
            "an ambiguous field must not be used at all: no address beats a forged one"
        );
        assert!(
            parsed
                .event
                .suspicious
                .iter()
                .any(|note| note.contains("refusing it")),
            "and the attempt must be flagged: {:?}",
            parsed.event.suspicious
        );
        assert_eq!(
            parsed.event.outcome,
            AuthOutcome::Failure,
            "the logon attempt itself is still recorded"
        );
    }

    /// The same injection aimed at a field rendered *after* the username: the
    /// answer must not depend on which way round they happen to be.
    #[test]
    fn injection_is_refused_whichever_order_the_fields_are_in() {
        let hostile = r#"x</Data><Data Name="TargetUserName">administrator</Data><Data Name="Y">"#;
        let parsed =
            parse_logon_event(&failure_event(hostile, "203.0.113.7", 3)).expect("a record");
        assert_eq!(
            parsed.event.user, None,
            "a duplicated account field is refused, not resolved"
        );
        assert!(parsed
            .event
            .suspicious
            .iter()
            .any(|note| note.contains("refusing it")));
    }

    #[test]
    fn escaped_markup_in_a_username_is_decoded_and_flagged() {
        // What a correctly-behaving renderer produces for the same input.
        let escaped = "bob&lt;script&gt;";
        let parsed =
            parse_logon_event(&failure_event(escaped, "203.0.113.7", 3)).expect("a record");

        assert_eq!(parsed.event.user.as_deref(), Some("bob<script>"));
        assert!(
            parsed
                .event
                .suspicious
                .iter()
                .any(|note| note.contains("markup")),
            "a decoded value containing markup is not something a real account produces"
        );
    }

    #[test]
    fn double_escaped_entities_are_not_over_decoded() {
        // `&amp;lt;` is the literal text `&lt;`, not `<`. Decoding ampersands
        // first would turn it into markup.
        let parsed =
            parse_logon_event(&failure_event("a&amp;lt;b", "203.0.113.7", 3)).expect("a record");
        assert_eq!(parsed.event.user.as_deref(), Some("a&lt;b"));
    }

    #[test]
    fn control_characters_never_reach_an_event() {
        let parsed = parse_logon_event(&failure_event("ro\u{1b}[31mot", "203.0.113.7", 3))
            .expect("a record");
        assert!(!parsed
            .event
            .user
            .as_deref()
            .unwrap_or_default()
            .contains('\u{1b}'));
        assert!(!parsed.event.message.contains('\u{1b}'));
        assert!(!parsed.event.suspicious.is_empty());
    }

    #[test]
    fn field_values_are_bounded_in_characters_not_bytes() {
        // A long name ending in a multi-byte character: byte-slicing would
        // panic on the boundary.
        let name = format!("{}é", "a".repeat(MAX_FIELD_CHARS));
        let parsed = parse_logon_event(&failure_event(&name, "203.0.113.7", 3)).expect("a record");
        assert!(
            parsed
                .event
                .user
                .as_deref()
                .unwrap_or_default()
                .chars()
                .count()
                <= MAX_FIELD_CHARS
        );
    }

    #[test]
    fn an_absurdly_long_event_is_refused_outright() {
        let huge = failure_event(&"x".repeat(MAX_EVENT_BYTES), "10.0.0.1", 3);
        assert!(parse_logon_event(&huge).is_none());
    }

    #[test]
    fn a_non_address_in_the_address_field_yields_no_address() {
        let parsed =
            parse_logon_event(&failure_event("bob", "not-an-address", 3)).expect("a record");
        assert!(
            parsed.event.source_address.is_none(),
            "a claim is not an address"
        );
        assert!(parsed
            .event
            .suspicious
            .iter()
            .any(|note| note.contains("not an address")));
    }

    /// Console logons legitimately have no address. Flagging those would train
    /// an operator to ignore the flag.
    #[test]
    fn a_console_logon_without_an_address_is_not_suspicious() {
        for placeholder in ["-", "LOCAL", "127.0.0.1", "::1"] {
            let parsed =
                parse_logon_event(&failure_event("bob", placeholder, 2)).expect("a record");
            assert!(
                parsed.event.suspicious.is_empty(),
                "{placeholder:?} produced {:?}",
                parsed.event.suspicious
            );
        }
    }

    #[test]
    fn an_unterminated_field_is_not_a_value() {
        let xml = r#"<Event><System><EventID>4625</EventID></System>
            <EventData><Data Name="TargetUserName">bob"#;
        let parsed = parse_logon_event(xml).expect("a record");
        assert!(
            parsed.event.user.is_none(),
            "guessing where an unterminated field ended is guessing"
        );
    }

    #[test]
    fn logon_types_map_and_remote_ones_are_distinguished() {
        assert_eq!(LogonType::from_code(2), LogonType::Interactive);
        assert_eq!(LogonType::from_code(10), LogonType::RemoteInteractive);
        assert_eq!(LogonType::from_code(99), LogonType::Other(99));

        assert!(LogonType::from_code(3).is_remote());
        assert!(LogonType::from_code(10).is_remote());
        assert!(
            !LogonType::from_code(5).is_remote(),
            "a service logon failure is a stale password, not somebody at the door"
        );
        assert!(!LogonType::from_code(2).is_remote());
    }

    #[test]
    fn arbitrary_input_never_panics() {
        let inputs = [
            "",
            "<",
            "<Event",
            "<EventID></EventID>",
            "<EventID>4625</EventID>",
            "<Data Name=\"TargetUserName\">",
            &"<Data Name=\"a\">b</Data>".repeat(1_000),
            &"&amp;".repeat(10_000),
        ];
        for input in inputs {
            let _ = parse_logon_event(input);
            let _ = event_id(input);
        }
    }
}
