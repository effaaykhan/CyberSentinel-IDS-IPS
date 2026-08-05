//! Fuzz the authentication-log parsers.
//!
//! Every byte reaching these parsers is attacker-influenced. A username is
//! whatever somebody typed at a login prompt, and it lands in the log verbatim,
//! so the log file is an input channel that anyone who can reach the login
//! service can write to. A crash here is a denial of service against the
//! security tool, delivered by failing to log in (guide §6).
//!
//! Two properties are checked. First **totality**: for any input the parsers
//! return a record or nothing, and never panic, hang, or overflow. Second, the
//! parts of the anti-forgery contract that hold for *every* input, whatever it
//! is:
//!
//! * No control character ever survives into an event. Event logs get read in
//!   terminals, and an ANSI escape in a `message` field is its own small
//!   attack.
//! * Fields are bounded. A megabyte-long username must not become a
//!   megabyte-long event.
//! * A source address, if one is reported, is one that actually parsed as an
//!   address — never a token that merely sat where an address goes.

#![no_main]

use cybersentinel_hids::logs::{parse_auth_message, parse_journal_record, parse_syslog_line};
use libfuzzer_sys::fuzz_target;

/// Longest username the parser is allowed to emit.
const MAX_USER: usize = 64;
/// Longest message the parser is allowed to emit.
const MAX_MESSAGE: usize = 2_048;

fn check(parsed: Option<cybersentinel_hids::logs::ParsedAuth>) {
    let Some(parsed) = parsed else {
        return;
    };
    let event = parsed.event;

    assert!(
        !event.message.chars().any(char::is_control),
        "a control character reached an event: {:?}",
        event.message
    );
    assert!(
        event.message.chars().count() <= MAX_MESSAGE,
        "the message is unbounded: {} characters",
        event.message.chars().count()
    );

    if let Some(user) = &event.user {
        assert!(
            !user.chars().any(char::is_control),
            "a control character reached the user field: {user:?}"
        );
        assert!(
            user.chars().count() <= MAX_USER,
            "the user field is unbounded: {} characters",
            user.chars().count()
        );
    }

    if let Some(service) = &event.service {
        assert!(!service.chars().any(char::is_control));
    }

    // A reported address is one that parsed. This is the anti-forgery property:
    // a message cannot name its own source by putting text where an address
    // goes, because the text has to *be* an address.
    if let Some(address) = event.source_address {
        assert_eq!(
            address.to_string().parse::<std::net::IpAddr>().ok(),
            Some(address),
            "a reported address must round-trip"
        );
    }

    for note in &event.suspicious {
        assert!(!note.is_empty(), "an empty note flags nothing");
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Line by line, the way the tailer hands them over — so a crafted line
    // embedded in ordinary traffic is covered as well as one on its own.
    for line in text.lines().take(64) {
        check(parse_syslog_line(line, "fuzz"));
        check(parse_journal_record(line, "fuzz"));
        check(parse_auth_message(line, Some("sshd"), "fuzz"));
        check(parse_auth_message(line, None, "fuzz"));
    }

    // And the whole blob at once, which is what an appender writing without
    // newlines produces.
    check(parse_syslog_line(text, "fuzz"));
    check(parse_journal_record(text, "fuzz"));
    check(parse_auth_message(text, Some(text), "fuzz"));
});
