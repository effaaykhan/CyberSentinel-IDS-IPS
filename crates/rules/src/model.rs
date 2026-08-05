//! The rule model produced by the parser.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::options::{Buffer, HostEventKind, RuleOption, Threshold};

/// What a rule does when it matches.
///
/// v1 is detection-only, so `drop` and `reject` are rejected at parse time
/// rather than silently downgraded to an alert — an operator who writes a
/// blocking rule must be told it will not block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Emit an `alert` event.
    Alert,
    /// Stop evaluating this input; emit nothing.
    Pass,
}

impl Action {
    /// Stable identifier used in rule text and event JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Pass => "pass",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The protocol a rule header selects on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP (v4 or v6).
    Icmp,
    /// Any IP protocol.
    Ip,
    /// HTTP, via the app-layer parser (Phase 3).
    Http,
    /// DNS, via the app-layer parser (Phase 8).
    Dns,
    /// TLS, via the app-layer parser (Phase 8).
    Tls,
}

impl Protocol {
    /// Stable identifier used in rule text.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Ip => "ip",
            Self::Http => "http",
            Self::Dns => "dns",
            Self::Tls => "tls",
        }
    }

    /// Whether matching this protocol needs an app-layer parser.
    #[must_use]
    pub fn is_app_layer(self) -> bool {
        matches!(self, Self::Http | Self::Dns | Self::Tls)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which way traffic must flow for the header to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// `->`: source to destination only.
    ToDestination,
    /// `<>`: either direction.
    Bidirectional,
}

impl Direction {
    /// Stable identifier used in rule text.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToDestination => "->",
            Self::Bidirectional => "<>",
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The address half of a header field, with its negation flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressSpec {
    /// Whether the field was prefixed with `!`.
    pub negated: bool,
    /// The address expression.
    pub value: AddressValue,
}

/// An address expression.
///
/// Lists and variables are kept as written. Resolving them into concrete
/// address sets needs `vars.address-groups` from `config.yaml` and is Phase 3
/// work; Phase 0 validates only the syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressValue {
    /// `any`.
    Any,
    /// `$NAME`, resolved from `vars.address-groups`.
    Var(String),
    /// A bracketed list, e.g. `[10.0.0.0/8,!10.1.0.0/16]`, kept verbatim.
    List(String),
    /// A single address or CIDR, validated at parse time.
    Literal(String),
}

/// The port half of a header field, with its negation flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    /// Whether the field was prefixed with `!`.
    pub negated: bool,
    /// The port expression.
    pub value: PortValue,
}

/// A port expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortValue {
    /// `any`.
    Any,
    /// `$NAME`, resolved from `vars.port-groups`.
    Var(String),
    /// A bracketed list, e.g. `[80,443]`, kept verbatim.
    List(String),
    /// A single port.
    Single(u16),
    /// An inclusive range. `None` on either side means open-ended: `:1024` is
    /// `0..=1024` and `1024:` is `1024..=65535`.
    Range(Option<u16>, Option<u16>),
}

/// The parsed rule header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHeader {
    /// Action taken on a match.
    pub action: Action,
    /// Protocol selector.
    pub protocol: Protocol,
    /// Source addresses.
    pub source: AddressSpec,
    /// Source ports.
    pub source_port: PortSpec,
    /// Direction.
    pub direction: Direction,
    /// Destination addresses.
    pub destination: AddressSpec,
    /// Destination ports.
    pub destination_port: PortSpec,
}

/// One `metadata:` key/value pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataEntry {
    /// Key — the first whitespace-separated token.
    pub key: String,
    /// Value — everything after the key, or empty if there was nothing.
    pub value: String,
}

/// Where a rule came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleOrigin {
    /// File the rule was read from.
    pub file: PathBuf,
    /// 1-based line number the rule started on.
    pub line: usize,
}

impl RuleOrigin {
    /// Build an origin.
    #[must_use]
    pub fn new(file: impl AsRef<Path>, line: usize) -> Self {
        Self {
            file: file.as_ref().to_path_buf(),
            line,
        }
    }
}

impl fmt::Display for RuleOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file.display(), self.line)
    }
}

/// A successfully parsed rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The header.
    pub header: RuleHeader,
    /// Signature id. Unique across the loaded ruleset.
    pub sid: u32,
    /// Revision. Defaults to 1 when the rule omits `rev`.
    pub rev: u32,
    /// Generator id, if the rule declared one.
    pub gid: Option<u32>,
    /// Priority, 1 (most urgent) to 255. Becomes the alert's severity.
    pub priority: Option<u8>,
    /// Human-readable description from `msg`.
    pub msg: String,
    /// `classtype`, if declared.
    pub classtype: Option<String>,
    /// `metadata` entries, in the order they appeared.
    pub metadata: Vec<MetadataEntry>,
    /// `reference` entries, for the analyst rather than the engine.
    pub references: Vec<String>,
    /// Match conditions, in the order they were written.
    ///
    /// Order is load-bearing: `distance` and `within` are measured from the
    /// previous match, and `byte_jump` moves the cursor the options after it
    /// read from.
    pub options: Vec<RuleOption>,
    /// Rate limiting, if the rule declared any.
    pub threshold: Option<Threshold>,
    /// The rule tracks state without alerting (`flowbits:noalert`).
    pub no_alert: bool,
    /// Option keywords this build recognises but cannot yet evaluate, in the
    /// order they appeared and without duplicates.
    ///
    /// A non-empty list means the rule is inert — see [`Rule::is_evaluable`].
    pub unsupported_options: Vec<String>,
    /// The rule text as written, with line continuations joined.
    pub raw: String,
    /// Where the rule came from. Set by the loader.
    pub origin: Option<RuleOrigin>,
}

impl Rule {
    /// Whether this build can evaluate the rule in full.
    ///
    /// `false` means at least one match condition is unimplemented, so the
    /// engine must not evaluate the rule at all: honouring the header while
    /// ignoring the conditions would broaden the signature rather than narrow
    /// it.
    #[must_use]
    pub fn is_evaluable(&self) -> bool {
        self.unsupported_options.is_empty()
    }

    /// Severity for the alert this rule raises.
    ///
    /// Defaults to 3 — "worth looking at" — when the rule says nothing, so an
    /// author who does not think about priority does not get the loudest one.
    #[must_use]
    pub fn severity(&self) -> u8 {
        self.priority.unwrap_or(3)
    }

    /// Every buffer this rule inspects.
    #[must_use]
    pub fn buffers(&self) -> Vec<Buffer> {
        let mut buffers: Vec<Buffer> = self.options.iter().filter_map(RuleOption::buffer).collect();
        buffers.sort_unstable();
        buffers.dedup();
        buffers
    }

    /// The host event kind this rule matches, if it is a host rule.
    ///
    /// `None` means it is a network rule. A rule naming fields from two
    /// different kinds could never match a single record, so that is an error
    /// the loader reports rather than an armed rule that never fires.
    ///
    /// # Errors
    /// The two kinds that conflicted.
    pub fn host_event_kind(&self) -> Result<Option<HostEventKind>, (HostEventKind, HostEventKind)> {
        let mut found: Option<HostEventKind> = None;
        for kind in self.options.iter().filter_map(RuleOption::host_event_kind) {
            match found {
                Some(existing) if existing != kind => return Err((existing, kind)),
                _ => found = Some(kind),
            }
        }
        Ok(found)
    }

    /// Whether this rule matches host events rather than network traffic.
    #[must_use]
    pub fn is_host_rule_by_options(&self) -> bool {
        self.options.iter().any(|o| o.host_event_kind().is_some())
    }

    /// Whether matching this rule needs the HTTP parser.
    #[must_use]
    pub fn needs_http(&self) -> bool {
        self.header.protocol.is_app_layer() || self.buffers().iter().any(|b| b.is_http())
    }

    /// Whether this is a host rule, by the SID convention (guide §3.1).
    #[must_use]
    pub fn is_host_rule(&self) -> bool {
        self.sid >= 1_000_000
    }

    /// `file:line` if the origin is known, otherwise `<inline>`.
    #[must_use]
    pub fn location(&self) -> String {
        self.origin
            .as_ref()
            .map_or_else(|| "<inline>".to_string(), ToString::to_string)
    }
}
