//! The CyberSentinel `.rules` format: model, parser, and loader.
//!
//! # Format
//!
//! One rule per line — a header, then a parenthesised, semicolon-separated
//! option list:
//!
//! ```text
//! alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
//!     msg:"CYBERSENTINEL WEB traversal attempt in URI"; \
//!     flow:established,to_server; http.uri; content:"../"; nocase; \
//!     classtype:web-application-attack; \
//!     metadata:phase 3, confidence medium; \
//!     sid:2000101; rev:1;)
//! ```
//!
//! Blank lines and `#` comments are ignored, and a trailing `\` continues a
//! rule onto the next line.
//!
//! # What Phase 0 parses
//!
//! This is the **parser stub** called for in Phase 0. It fully parses:
//!
//! * the header — action, protocol, source/destination addresses and ports,
//!   and direction, including `$VARIABLE` references and negation;
//! * the metadata options — `sid`, `rev`, `msg`, `classtype`, `metadata`.
//!
//! Match conditions (`content`, `pcre`, `flow`, sticky buffers, ...) are
//! recognised by name but **not** interpreted; they land in
//! [`Rule::unsupported_options`] in Phase 3.
//!
//! # Two failure modes, deliberately distinguished
//!
//! * **Unparseable** — a malformed header, a missing `sid`, an unknown option
//!   keyword. The rule is *skipped* and logged with a file, line, and reason
//!   (guide §6: never fail the whole load on one bad rule). An unknown keyword
//!   counts here on purpose: a typo like `contnet:"x"` would otherwise silently
//!   produce a rule that matches far more traffic than its author intended.
//!
//! * **Parseable but not yet evaluable** — every option is a keyword this
//!   format defines, but at least one is not implemented in this build. The
//!   rule loads, is counted, and reports [`Rule::is_evaluable`] as `false`.
//!
//! **The engine must only ever evaluate rules where [`Rule::is_evaluable`] is
//! `true`.** Evaluating a rule while ignoring the conditions it cannot handle
//! would turn a narrow signature into a broad one — a false-positive flood at
//! best, and a misleading alert at worst.

pub mod loader;
pub mod model;
pub mod options;
pub mod parser;

pub use loader::{LoadReport, RuleSet, SkippedRule};
pub use model::{
    Action, AddressSpec, AddressValue, Direction, MetadataEntry, PortSpec, PortValue, Protocol,
    Rule, RuleHeader, RuleOrigin,
};
pub use options::{
    Buffer, ByteJump, ByteTest, ContentMatch, DsizeMatch, Endian, FlowBitsOp, FlowMatch,
    NormalizationCondition, NumericOp, PcreMatch, RuleOption, Threshold, ThresholdKind, Track,
};
pub use parser::{parse_rule, ParseError};
