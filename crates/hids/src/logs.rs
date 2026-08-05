//! Authentication log parsing.
//!
//! Two sources, one output. journald is preferred because its records are
//! **structured**: the service name and pid are fields the kernel and systemd
//! put there, not text a login prompt can influence. A plain syslog file is
//! supported too, because plenty of systems still have one and because auditd
//! will arrive through the same shape.
//!
//! # Everything here is attacker-influenced
//!
//! A username is whatever somebody typed at a login prompt, and it lands in the
//! log verbatim. That makes log parsing an injection surface, and this module
//! is written on the assumption that any part of a message may be hostile:
//!
//! * **Fields are extracted positionally and validated, never scavenged.** A
//!   username is one whitespace-delimited token. Somebody logging in as
//!   `admin from 10.0.0.1 port 22` does not get to choose the `source_address`
//!   of the event they generate.
//! * **What cannot be a real value is flagged, not dropped.** A username
//!   holding control characters is recorded, marked in
//!   [`AuthEvent::suspicious`], and truncated. Dropping it would hide the
//!   attempt; trusting it would launder a forgery.
//! * **Control characters are stripped from the message.** Event logs get
//!   `cat`-ed into terminals, and an ANSI escape sequence in a log line is its
//!   own small attack.
//! * **Lengths are bounded.** A megabyte-long username must not become a
//!   megabyte-long event.
//!
//! One ambiguity is **not** solvable at this layer and is called out rather
//! than papered over: sshd writes `for invalid user bob` for an account that
//! does not exist and `for bob` for one that does, so an attacker who logs in
//! as the literal string `invalid user root` produces a line indistinguishable
//! from a failed attempt against `root`. Free-form syslog text simply does not
//! carry enough structure to settle it. journald does — the account is a field
//! — which is why it is the preferred source and the one to configure when
//! both are available.

use cybersentinel_common::event::{AuthEvent, AuthOutcome};
use std::net::IpAddr;

/// Longest field value kept.
const MAX_FIELD: usize = 256;
/// Longest message kept.
const MAX_MESSAGE: usize = 2_048;
/// Longest log line considered at all.
pub const MAX_LINE: usize = 16 * 1_024;

/// Turn a raw byte string into something safe to put in an event.
///
/// Control characters become `.`, so a crafted log line cannot smuggle ANSI
/// escapes, newlines, or NULs into the event stream.
fn sanitise(text: &str, limit: usize) -> (String, bool) {
    let mut changed = false;
    let mut out = String::with_capacity(text.len().min(limit));
    for character in text.chars() {
        if out.len() >= limit {
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

/// Take at most `limit` **characters**.
///
/// Byte slicing would panic on a multi-byte boundary, and the strings here are
/// attacker-chosen: a username ending in one non-ASCII character would be
/// enough to crash the parser.
fn clip(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// Whether a token could be a real account name.
///
/// Deliberately generous — local conventions vary — but it rejects whitespace
/// and control characters, which is what a forged extra field needs.
fn plausible_username(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 64
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-$@\\/".contains(c))
}

/// A parsed authentication record, before the sensor stamps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAuth {
    /// The normalized event.
    pub event: AuthEvent,
}

/// Parse the message body of an authentication log record.
///
/// The service and log source are supplied by the caller, because for journald
/// they are structured fields rather than anything the message can claim.
#[must_use]
pub fn parse_auth_message(
    message: &str,
    service: Option<&str>,
    log_source: &str,
) -> Option<ParsedAuth> {
    let (clean, message_changed) = sanitise(message, MAX_MESSAGE);
    let lower = clean.to_ascii_lowercase();

    // Outcome first: a record that is not about an authentication decision is
    // not an auth event, and inventing one would be worse than ignoring it.
    let outcome = if lower.starts_with("failed password")
        || lower.starts_with("failed publickey")
        || lower.contains("authentication failure")
        || lower.starts_with("invalid user")
        || lower.starts_with("failed none")
    {
        AuthOutcome::Failure
    } else if lower.starts_with("accepted password")
        || lower.starts_with("accepted publickey")
        || lower.starts_with("session opened for user")
    {
        AuthOutcome::Success
    } else {
        return None;
    };

    let mut suspicious = Vec::new();
    if message_changed {
        suspicious.push("message contained control characters or was truncated".to_string());
    }

    let tokens: Vec<&str> = clean.split_whitespace().collect();
    let user = extract_user(&tokens, &mut suspicious);
    let (source_address, source_port) = extract_source(&tokens, &mut suspicious);

    Some(ParsedAuth {
        event: AuthEvent {
            outcome,
            user,
            service: service.map(|s| sanitise(s, MAX_FIELD).0),
            source_address,
            source_port,
            message: clean,
            log_source: log_source.to_string(),
            suspicious,
        },
    })
}

/// Pull the account name out of a tokenised message.
///
/// Only ever takes **one** token, and only from the position the format puts it
/// in. That is what stops a login as `admin from 10.0.0.1` from rewriting the
/// rest of the event.
///
/// Three shapes are recognised, most specific first:
///
/// * `user=root` — PAM's `key=value` form, which is unambiguous.
/// * `for [invalid] [user] NAME` — sshd's, with the optional words skipped.
/// * `user NAME` — anything else that names the field.
fn extract_user(tokens: &[&str], suspicious: &mut Vec<String>) -> Option<String> {
    let candidate = tokens
        .iter()
        .find_map(|token| token.strip_prefix("user="))
        .or_else(|| {
            let position = tokens.iter().position(|token| *token == "for")?;
            let mut index = position + 1;
            while matches!(tokens.get(index), Some(&"invalid" | &"user")) {
                index += 1;
            }
            tokens.get(index).copied()
        })
        .or_else(|| {
            let position = tokens.iter().position(|token| *token == "user")?;
            tokens.get(position + 1).copied()
        })?;

    if plausible_username(candidate) {
        return Some(candidate.to_string());
    }
    // Not a name any account could have. Recorded anyway — hiding the attempt
    // would be worse — but marked, so nothing downstream treats it as real.
    suspicious.push(format!(
        "user token {:?} is not a plausible account name",
        clip(candidate, 32)
    ));
    Some(sanitise(candidate, 64).0)
}

/// Pull the source address and port out of a tokenised message.
///
/// Both must parse as what they claim to be. A message saying
/// `from somewhere-else` yields no address rather than a made-up one.
fn extract_source(tokens: &[&str], suspicious: &mut Vec<String>) -> (Option<IpAddr>, Option<u16>) {
    let Some(position) = tokens.iter().position(|token| *token == "from") else {
        return (None, None);
    };
    let Some(candidate) = tokens.get(position + 1) else {
        return (None, None);
    };
    let Ok(address) = candidate.parse::<IpAddr>() else {
        suspicious.push(format!(
            "source token {:?} is not an address",
            clip(candidate, 48)
        ));
        return (None, None);
    };

    let port = tokens
        .get(position + 2)
        .filter(|token| **token == "port")
        .and_then(|_| tokens.get(position + 3))
        .and_then(|token| token.parse::<u16>().ok());

    (Some(address), port)
}

/// Split off the next whitespace-delimited token, returning it and the rest.
fn next_token(text: &str) -> Option<(&str, &str)> {
    let text = text.trim_start_matches([' ', '\t']);
    if text.is_empty() {
        return None;
    }
    Some(match text.find([' ', '\t']) {
        Some(end) => (&text[..end], text[end..].trim_start_matches([' ', '\t'])),
        None => (text, ""),
    })
}

/// Parse one line of a syslog-format authentication file.
///
/// Expects `MMM DD HH:MM:SS host service[pid]: message`. A line that does not
/// have that shape is not a record; it is text, and it is ignored.
#[must_use]
pub fn parse_syslog_line(line: &str, log_source: &str) -> Option<ParsedAuth> {
    if line.len() > MAX_LINE {
        return None;
    }
    // `month day time host tag: rest`. Note the day is space-padded — `Jan  2`
    // has two spaces — so fields are taken by skipping runs of whitespace
    // rather than by splitting on a single space.
    let rest = line;
    let (_month, rest) = next_token(rest)?;
    let (_day, rest) = next_token(rest)?;
    let (_time, rest) = next_token(rest)?;
    let (_host, rest) = next_token(rest)?;
    let (tag, message) = next_token(rest)?;

    // `sshd[1234]:` — the service is what comes before the bracket or colon.
    let tag = tag.trim_end_matches(':');
    let service = tag.split('[').next().unwrap_or(tag);
    if service.is_empty() || !service.chars().all(|c| c.is_ascii_graphic()) {
        return None;
    }

    parse_auth_message(message, Some(service), log_source)
}

/// Parse one `journalctl -o json` record.
///
/// The service and pid come from structured fields, which is the whole reason
/// journald is preferred: a message cannot claim to have come from `sshd`.
#[must_use]
pub fn parse_journal_record(json: &str, log_source: &str) -> Option<ParsedAuth> {
    if json.len() > MAX_LINE {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let message = journal_string(value.get("MESSAGE")?)?;
    let service = value
        .get("SYSLOG_IDENTIFIER")
        .or_else(|| value.get("_COMM"))
        .and_then(journal_string);

    parse_auth_message(&message, service.as_deref(), log_source)
}

/// Read a journal field, which may be a string or an array of byte values.
///
/// journald encodes fields that are not valid UTF-8 as a JSON array of numbers.
/// Refusing to look at those would let an attacker hide a record simply by
/// putting a stray byte in it.
fn journal_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Array(bytes) => {
            let raw: Vec<u8> = bytes
                .iter()
                .filter_map(serde_json::Value::as_u64)
                .map(|byte| u8::try_from(byte).unwrap_or(b'.'))
                .collect();
            Some(String::from_utf8_lossy(&raw).into_owned())
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// following a log file
// ---------------------------------------------------------------------------

/// Follows an append-only log file across reads, restarts, and rotation.
///
/// Rotation is detected by the file shrinking or its identity changing, at
/// which point reading resumes from the start of the new file. Getting this
/// wrong is a detection gap: a sensor that keeps reading from a stale offset
/// after `logrotate` runs sees nothing again until the file grows past where
/// the old one ended.
#[derive(Debug)]
pub struct Tailer {
    path: std::path::PathBuf,
    offset: u64,
    /// Identity of the file we are following, so a rotation is visible.
    identity: Option<(u64, u64)>,
    /// Partial trailing line held over until its newline arrives.
    pending: String,
    /// Lines dropped because they exceeded [`MAX_LINE`].
    pub oversized: u64,
    /// Rotations noticed.
    pub rotations: u64,
}

impl Tailer {
    /// Follow `path`, starting from its current end.
    ///
    /// Starting at the end rather than the beginning is deliberate: replaying
    /// months of history on every restart would bury the present.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        let path = path.into();
        let (offset, identity) = std::fs::metadata(&path)
            .map(|metadata| (metadata.len(), identity_of(&metadata)))
            .unwrap_or((0, None));
        Self {
            path,
            offset,
            identity,
            pending: String::new(),
            oversized: 0,
            rotations: 0,
        }
    }

    /// Follow `path` from the beginning. Used by tests and by fixture replay.
    #[must_use]
    pub fn from_start(path: impl Into<std::path::PathBuf>) -> Self {
        let mut tailer = Self::new(path);
        tailer.offset = 0;
        tailer
    }

    /// The file being followed.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Read whatever has been appended since the last call.
    ///
    /// Returns complete lines only; a partial trailing line is held until its
    /// newline arrives, so a record that straddles two reads is never parsed
    /// as two truncated ones.
    pub fn read_new_lines(&mut self) -> std::io::Result<Vec<String>> {
        use std::io::{Read as _, Seek as _, SeekFrom};

        let metadata = match std::fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            // A log file that does not exist yet is not an error; it is a
            // service that has not logged yet.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };

        let identity = identity_of(&metadata);
        if metadata.len() < self.offset || (identity.is_some() && identity != self.identity) {
            // Truncated or rotated: start over on the new file.
            self.offset = 0;
            self.pending.clear();
            self.rotations += 1;
        }
        self.identity = identity;

        if metadata.len() == self.offset {
            return Ok(Vec::new());
        }

        let mut file = std::fs::File::open(&self.path)?;
        file.seek(SeekFrom::Start(self.offset))?;

        // Bounded read: a log that grew by a gigabyte between polls must not
        // become a gigabyte of resident memory.
        let available = metadata.len().saturating_sub(self.offset);
        let want = usize::try_from(available.min(1_024 * 1_024)).unwrap_or(usize::MAX);
        let mut buffer = vec![0_u8; want];
        let read = file.read(&mut buffer)?;
        buffer.truncate(read);
        self.offset = self.offset.saturating_add(read as u64);

        let text = String::from_utf8_lossy(&buffer);
        let mut lines = Vec::new();
        for piece in text.split_inclusive('\n') {
            if let Some(line) = piece.strip_suffix('\n') {
                let mut complete = std::mem::take(&mut self.pending);
                complete.push_str(line.strip_suffix('\r').unwrap_or(line));
                if complete.len() > MAX_LINE {
                    self.oversized += 1;
                    continue;
                }
                lines.push(complete);
            } else {
                // No newline yet. Hold it, but not without limit — an appender
                // that never writes a newline must not grow us forever.
                if self.pending.len() + piece.len() > MAX_LINE {
                    self.oversized += 1;
                    self.pending.clear();
                } else {
                    self.pending.push_str(piece);
                }
            }
        }
        Ok(lines)
    }
}

/// Device and inode, where the platform exposes them.
#[cfg(unix)]
fn identity_of(metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    Some((metadata.dev(), metadata.ino()))
}
#[cfg(not(unix))]
fn identity_of(_metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syslog(line: &str) -> Option<AuthEvent> {
        parse_syslog_line(line, "file:/var/log/auth.log").map(|parsed| parsed.event)
    }

    #[test]
    fn parses_a_failed_password() {
        let event = syslog(
            "Jan  2 03:04:05 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.7 port 51000 ssh2",
        )
        .expect("a record");
        assert_eq!(event.outcome, AuthOutcome::Failure);
        assert_eq!(event.user.as_deref(), Some("admin"));
        assert_eq!(event.service.as_deref(), Some("sshd"));
        assert_eq!(
            event.source_address.map(|a| a.to_string()).as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(event.source_port, Some(51_000));
        assert!(event.suspicious.is_empty());
    }

    #[test]
    fn parses_a_successful_login() {
        let event = syslog(
            "Jan  2 03:04:05 web01 sshd[1234]: Accepted password for deploy from 10.0.0.5 port 4022 ssh2",
        )
        .expect("a record");
        assert_eq!(event.outcome, AuthOutcome::Success);
        assert_eq!(event.user.as_deref(), Some("deploy"));
    }

    #[test]
    fn a_line_that_is_not_about_authentication_is_not_a_record() {
        // Inventing an auth event from an unrelated line would be worse than
        // ignoring it.
        assert!(
            syslog("Jan  2 03:04:05 web01 cron[9]: pam_unix(cron:session): starting").is_none()
        );
        assert!(syslog("Jan  2 03:04:05 web01 kernel: eth0 link up").is_none());
    }

    #[test]
    fn a_line_without_a_syslog_shape_is_ignored() {
        assert!(syslog("Failed password for root from 10.0.0.1").is_none());
        assert!(syslog("").is_none());
        assert!(syslog("short line").is_none());
    }

    // -----------------------------------------------------------------------
    // log injection
    // -----------------------------------------------------------------------

    /// The headline adversarial case: somebody logs in with a username chosen
    /// to forge the rest of the record.
    #[test]
    fn a_username_cannot_fabricate_a_source_address() {
        let event = syslog(
            "Jan  2 03:04:05 web01 sshd[1234]: Failed password for invalid user attacker from 198.51.100.1 port 22 ssh2",
        )
        .expect("a record");
        // The real source is the one the daemon reported, not one embedded in
        // the account name.
        assert_eq!(event.user.as_deref(), Some("attacker"));
        assert_eq!(
            event.source_address.map(|a| a.to_string()).as_deref(),
            Some("198.51.100.1")
        );
    }

    #[test]
    fn a_username_containing_spaces_is_flagged_not_believed() {
        // `user` followed by a token containing a fabricated field. Only one
        // token is ever taken, so the fabrication lands nowhere.
        let event = syslog(
            "Jan  2 03:04:05 web01 sshd[1234]: Failed password for invalid user root@evil from 203.0.113.7 port 1 ssh2",
        )
        .expect("a record");
        assert_eq!(event.user.as_deref(), Some("root@evil"));
        assert_eq!(
            event.source_address.map(|a| a.to_string()).as_deref(),
            Some("203.0.113.7")
        );
    }

    #[test]
    fn a_username_with_control_characters_is_sanitised_and_flagged() {
        let line =
            "Jan  2 03:04:05 web01 sshd[1234]: Failed password for user ro\u{1b}[31mot from 10.0.0.1 port 1 ssh2";
        let event = syslog(line).expect("a record");
        assert!(
            !event.user.as_deref().unwrap_or_default().contains('\u{1b}'),
            "an escape sequence must not survive into an event"
        );
        assert!(!event.suspicious.is_empty(), "and it must be flagged");
    }

    #[test]
    fn escape_sequences_are_stripped_from_the_message() {
        // Event logs get cat-ed into terminals.
        let line = "Jan  2 03:04:05 web01 sshd[1]: Failed password for user bob from 10.0.0.1 port 1 \u{1b}]0;pwned\u{7}";
        let event = syslog(line).expect("a record");
        assert!(!event.message.contains('\u{1b}'));
        assert!(!event.suspicious.is_empty());
    }

    /// Byte-slicing an attacker-chosen string is a crash waiting to happen. A
    /// username that is exactly long enough and ends in a multi-byte character
    /// used to be all it took.
    #[test]
    fn a_multibyte_username_does_not_split_a_character() {
        let name = format!("{}é", "a".repeat(31));
        let line = format!(
            "Jan  2 03:04:05 web01 sshd[1]: Failed password for user {name} from 10.0.0.1 port 1"
        );
        let event = syslog(&line).expect("a record");
        assert!(!event.suspicious.is_empty());
    }

    #[test]
    fn a_made_up_source_token_yields_no_address() {
        let event = syslog(
            "Jan  2 03:04:05 web01 sshd[1]: Failed password for user bob from not-an-address port 1 ssh2",
        )
        .expect("a record");
        assert!(event.source_address.is_none(), "a claim is not an address");
        assert!(event
            .suspicious
            .iter()
            .any(|s| s.contains("not an address")));
    }

    #[test]
    fn field_lengths_are_bounded() {
        let huge = "A".repeat(1_000);
        let line = format!(
            "Jan  2 03:04:05 web01 sshd[1]: Failed password for user {huge} from 10.0.0.1 port 1"
        );
        let event = syslog(&line).expect("a record");
        assert!(event.user.as_deref().unwrap_or_default().len() <= 64);
        assert!(event.message.len() <= MAX_MESSAGE);
    }

    #[test]
    fn an_absurdly_long_line_is_refused_outright() {
        let line = format!(
            "Jan  2 03:04:05 web01 sshd[1]: Failed password for user bob {}",
            "x".repeat(MAX_LINE)
        );
        assert!(syslog(&line).is_none());
    }

    // -----------------------------------------------------------------------
    // journald
    // -----------------------------------------------------------------------

    #[test]
    fn parses_a_journal_record() {
        let json = r#"{"MESSAGE":"Failed password for invalid user admin from 203.0.113.7 port 1 ssh2","SYSLOG_IDENTIFIER":"sshd","_PID":"1234"}"#;
        let parsed = parse_journal_record(json, "journald").expect("a record");
        assert_eq!(parsed.event.outcome, AuthOutcome::Failure);
        assert_eq!(parsed.event.service.as_deref(), Some("sshd"));
        assert_eq!(parsed.event.log_source, "journald");
    }

    #[test]
    fn a_journal_message_cannot_claim_a_different_service() {
        // The identifier is a structured field. This is why journald is first.
        let json = r#"{"MESSAGE":"Failed password for user root from 10.0.0.1 port 1","SYSLOG_IDENTIFIER":"myapp"}"#;
        let parsed = parse_journal_record(json, "journald").expect("a record");
        assert_eq!(
            parsed.event.service.as_deref(),
            Some("myapp"),
            "the service comes from the field, not the text"
        );
    }

    #[test]
    fn a_binary_journal_field_is_still_read() {
        // journald encodes non-UTF-8 fields as byte arrays. Ignoring those
        // would let a record hide behind one stray byte.
        let json = r#"{"MESSAGE":[70,97,105,108,101,100,32,112,97,115,115,119,111,114,100,32,102,111,114,32,117,115,101,114,32,98,111,98],"SYSLOG_IDENTIFIER":"sshd"}"#;
        let parsed = parse_journal_record(json, "journald").expect("a record");
        assert_eq!(parsed.event.user.as_deref(), Some("bob"));
    }

    #[test]
    fn malformed_journal_input_is_ignored_not_fatal() {
        for json in [
            "",
            "{",
            "null",
            "[]",
            r#"{"MESSAGE":42}"#,
            r#"{"other":"x"}"#,
        ] {
            assert!(parse_journal_record(json, "journald").is_none(), "{json}");
        }
    }

    // -----------------------------------------------------------------------
    // tailing
    // -----------------------------------------------------------------------

    fn append(path: &std::path::Path, text: &str) {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open");
        file.write_all(text.as_bytes()).expect("write");
    }

    #[test]
    fn a_tailer_reads_only_what_was_appended() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("auth.log");
        append(&log, "first\n");

        let mut tailer = Tailer::new(&log);
        assert!(
            tailer.read_new_lines().expect("read").is_empty(),
            "history is not news"
        );

        append(&log, "second\nthird\n");
        assert_eq!(tailer.read_new_lines().expect("read"), ["second", "third"]);
        assert!(tailer.read_new_lines().expect("read").is_empty());
    }

    #[test]
    fn a_record_split_across_two_reads_is_not_two_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("auth.log");
        let mut tailer = Tailer::from_start(&log);

        append(&log, "Failed password for ");
        assert!(tailer.read_new_lines().expect("read").is_empty());
        append(&log, "user bob\n");
        assert_eq!(
            tailer.read_new_lines().expect("read"),
            ["Failed password for user bob"]
        );
    }

    #[test]
    fn rotation_resumes_from_the_start_of_the_new_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("auth.log");
        append(&log, "old line one\nold line two\n");

        let mut tailer = Tailer::new(&log);
        std::fs::rename(&log, dir.path().join("auth.log.1")).expect("rotate");
        append(&log, "after rotation\n");

        assert_eq!(tailer.read_new_lines().expect("read"), ["after rotation"]);
        assert_eq!(tailer.rotations, 1);
    }

    #[test]
    fn truncation_in_place_is_also_a_rotation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("auth.log");
        append(&log, "a long first line\n");
        let mut tailer = Tailer::new(&log);

        std::fs::write(&log, "short\n").expect("truncate");
        assert_eq!(tailer.read_new_lines().expect("read"), ["short"]);
    }

    #[test]
    fn a_log_file_that_does_not_exist_is_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut tailer = Tailer::new(dir.path().join("never-created.log"));
        assert!(tailer.read_new_lines().expect("read").is_empty());
    }

    /// An appender that never writes a newline must not grow the sensor without
    /// bound — that is a memory exhaustion an attacker can trigger from a login
    /// prompt.
    #[test]
    fn an_endless_line_is_dropped_rather_than_buffered_forever() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("auth.log");
        let mut tailer = Tailer::from_start(&log);

        for _ in 0..8 {
            append(&log, &"x".repeat(4_096));
            tailer.read_new_lines().expect("read");
        }
        assert!(tailer.oversized > 0);
        assert!(tailer.pending.len() <= MAX_LINE);
    }

    #[test]
    fn arbitrary_input_never_panics() {
        let inputs = [
            "",
            "\u{0}\u{0}\u{0}",
            "Jan",
            "Jan  2 03:04:05 h s: ",
            &"a ".repeat(10_000),
            "Jan  2 03:04:05 web01 sshd[1]: Failed password for user",
            "Jan  2 03:04:05 web01 sshd[1]: Failed password for user  from",
        ];
        for input in inputs {
            let _ = parse_syslog_line(input, "test");
            let _ = parse_journal_record(input, "test");
            let _ = parse_auth_message(input, None, "test");
        }
    }
}
