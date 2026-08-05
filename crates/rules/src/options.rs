//! The match conditions a rule can carry.
//!
//! Phase 0 recognised these keywords by name and refused to evaluate them.
//! Phase 3 gives them a typed model, which is what turns
//! [`crate::Rule::is_evaluable`] true for the supported subset.
//!
//! Options are kept **in the order they were written**, because several of them
//! are positional: `distance` and `within` are measured from where the previous
//! `content` matched, and `byte_jump` moves the cursor the options after it
//! read from. A set would lose the rule's meaning.

use std::fmt;

/// Which buffer a match applies to.
///
/// A sticky-buffer keyword (`http.uri`) sets the buffer for every match option
/// that follows it, until another one changes it. That is what lets one rule
/// look at the URI and the headers in turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Buffer {
    /// The packet payload, or the reassembled stream for TCP.
    #[default]
    Payload,
    /// The normalized request URI.
    HttpUri,
    /// The raw header block.
    HttpHeader,
    /// The `User-Agent` header value.
    HttpUserAgent,
    /// The request method.
    HttpMethod,
    /// The `Host` header value.
    HttpHost,
}

impl Buffer {
    /// The keyword that selects this buffer.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Payload => "payload",
            Self::HttpUri => "http.uri",
            Self::HttpHeader => "http.header",
            Self::HttpUserAgent => "http.user_agent",
            Self::HttpMethod => "http.method",
            Self::HttpHost => "http.host",
        }
    }

    /// Parse a sticky-buffer keyword.
    #[must_use]
    pub fn from_keyword(keyword: &str) -> Option<Self> {
        match keyword {
            "http.uri" => Some(Self::HttpUri),
            "http.header" => Some(Self::HttpHeader),
            "http.user_agent" => Some(Self::HttpUserAgent),
            "http.method" => Some(Self::HttpMethod),
            "http.host" => Some(Self::HttpHost),
            _ => None,
        }
    }

    /// Whether matching this buffer needs the HTTP parser.
    #[must_use]
    pub fn is_http(self) -> bool {
        self != Self::Payload
    }
}

impl fmt::Display for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A `content` match and its modifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMatch {
    /// The bytes to look for.
    pub pattern: Vec<u8>,
    /// Buffer to search.
    pub buffer: Buffer,
    /// Match must **not** be present.
    pub negated: bool,
    /// Case-insensitive.
    pub nocase: bool,
    /// Absolute: start searching this many bytes in.
    pub offset: Option<u32>,
    /// Absolute: search no further than this many bytes from the start.
    pub depth: Option<u32>,
    /// Relative: start this many bytes past the end of the previous match.
    pub distance: Option<i32>,
    /// Relative: match within this many bytes of the previous match's end.
    pub within: Option<u32>,
    /// Use this pattern for the multi-pattern pre-filter.
    pub fast_pattern: bool,
}

impl ContentMatch {
    /// A bare content match on the payload.
    #[must_use]
    pub fn new(pattern: Vec<u8>) -> Self {
        Self {
            pattern,
            buffer: Buffer::Payload,
            negated: false,
            nocase: false,
            offset: None,
            depth: None,
            distance: None,
            within: None,
            fast_pattern: false,
        }
    }

    /// Whether this match is positioned relative to the previous one.
    #[must_use]
    pub fn is_relative(&self) -> bool {
        self.distance.is_some() || self.within.is_some()
    }

    /// Whether this pattern may be used as a pre-filter.
    ///
    /// A negated match cannot: the pre-filter finds packets that *contain* the
    /// pattern, and a rule requiring its absence would then never be
    /// considered for the packets it should fire on.
    #[must_use]
    pub fn usable_as_fast_pattern(&self) -> bool {
        !self.negated && !self.pattern.is_empty()
    }
}

/// A `pcre` match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcreMatch {
    /// The expression source, without delimiters.
    pub source: String,
    /// Buffer to search.
    pub buffer: Buffer,
    /// Match must **not** be present.
    pub negated: bool,
    /// `i` — case-insensitive.
    pub case_insensitive: bool,
    /// `s` — `.` matches newline.
    pub dot_matches_newline: bool,
    /// `m` — `^`/`$` match at line boundaries.
    pub multi_line: bool,
    /// `R` — start from the end of the previous match.
    pub relative: bool,
}

/// Which direction and connection state a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlowMatch {
    /// `established` / `not_established`.
    pub established: Option<bool>,
    /// `to_server` / `to_client`.
    pub to_server: Option<bool>,
}

/// A `flowbits` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowBitsOp {
    /// Set a bit on the flow.
    Set(String),
    /// Clear a bit.
    Unset(String),
    /// Flip a bit.
    Toggle(String),
    /// Match only if the bit is set.
    IsSet(String),
    /// Match only if the bit is clear.
    IsNotSet(String),
    /// Track state without alerting. Used by rules that only set bits.
    NoAlert,
}

impl FlowBitsOp {
    /// Whether this operation is a condition rather than a side effect.
    #[must_use]
    pub fn is_condition(&self) -> bool {
        matches!(self, Self::IsSet(_) | Self::IsNotSet(_))
    }
}

/// A numeric comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericOp {
    /// `=`
    Equal,
    /// `!=`
    NotEqual,
    /// `<`
    Less,
    /// `<=`
    LessOrEqual,
    /// `>`
    Greater,
    /// `>=`
    GreaterOrEqual,
    /// `&` — bitwise AND is non-zero.
    BitAnd,
    /// `^` — bitwise XOR is non-zero.
    BitXor,
}

impl NumericOp {
    /// Apply the comparison.
    #[must_use]
    pub fn apply(self, left: u64, right: u64) -> bool {
        match self {
            Self::Equal => left == right,
            Self::NotEqual => left != right,
            Self::Less => left < right,
            Self::LessOrEqual => left <= right,
            Self::Greater => left > right,
            Self::GreaterOrEqual => left >= right,
            Self::BitAnd => left & right != 0,
            Self::BitXor => left ^ right != 0,
        }
    }

    /// Parse an operator token.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "=" | "==" => Some(Self::Equal),
            "!=" | "!" => Some(Self::NotEqual),
            "<" => Some(Self::Less),
            "<=" => Some(Self::LessOrEqual),
            ">" => Some(Self::Greater),
            ">=" => Some(Self::GreaterOrEqual),
            "&" => Some(Self::BitAnd),
            "^" => Some(Self::BitXor),
            _ => None,
        }
    }
}

/// Byte order for `byte_test` and `byte_jump`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Endian {
    /// Network byte order.
    #[default]
    Big,
    /// Host-of-some-other-machine byte order.
    Little,
}

/// A `byte_test`: read N bytes and compare them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteTest {
    /// How many bytes to read, 1 to 8.
    pub bytes: u8,
    /// Comparison to apply.
    pub op: NumericOp,
    /// Value to compare against.
    pub value: u64,
    /// Where to read from.
    pub offset: i32,
    /// Whether `offset` is relative to the previous match.
    pub relative: bool,
    /// Byte order.
    pub endian: Endian,
    /// Invert the result.
    pub negated: bool,
}

/// A `byte_jump`: read N bytes and move the match cursor by that much.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteJump {
    /// How many bytes to read, 1 to 8.
    pub bytes: u8,
    /// Where to read from.
    pub offset: i32,
    /// Whether `offset` is relative to the previous match.
    pub relative: bool,
    /// Multiply the value read by this.
    pub multiplier: u32,
    /// Byte order.
    pub endian: Endian,
    /// Added to the destination after jumping.
    pub post_offset: i32,
}

/// A `dsize` match on the inspected buffer's length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DsizeMatch {
    /// Comparison, or the lower bound of a range.
    pub op: NumericOp,
    /// Value, or the lower bound of a range.
    pub value: u32,
    /// Upper bound, for `dsize:100<>200`.
    pub upper: Option<u32>,
}

impl DsizeMatch {
    /// Whether a buffer of `length` bytes satisfies this.
    #[must_use]
    pub fn matches(&self, length: usize) -> bool {
        let length = length as u64;
        match self.upper {
            Some(upper) => length > u64::from(self.value) && length < u64::from(upper),
            None => self.op.apply(length, u64::from(self.value)),
        }
    }
}

/// What a `threshold` counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdKind {
    /// Alert once per `count` events in the window.
    Threshold,
    /// Alert at most `count` times in the window.
    Limit,
    /// Both: alert on the `count`th, then not again in the window.
    Both,
}

/// What a `threshold` counts against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Track {
    /// One counter per source address.
    BySource,
    /// One counter per destination address.
    ByDestination,
    /// One counter for the whole rule.
    ByRule,
}

/// A `threshold` clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    /// How the count is applied.
    pub kind: ThresholdKind,
    /// What the count is kept per.
    pub track: Track,
    /// Event count.
    pub count: u32,
    /// Window length in seconds.
    pub seconds: u32,
}

/// A condition on what normalization had to do.
///
/// These are computed anyway while canonicalising a URI, and each of them is
/// unusual enough to be worth matching on directly: a request that arrives
/// double-encoded is suspicious whatever it decodes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NormalizationCondition {
    /// The input was percent-encoded.
    PercentEncoded,
    /// A second decoding pass changed the result.
    DoubleEncoded,
    /// A `%` did not begin a valid escape.
    InvalidEscape,
    /// Decoding produced a NUL byte.
    NullByte,
    /// A `..` segment was resolved.
    Traversal,
    /// A `..` tried to walk above the root.
    AboveRoot,
    /// A `.` segment was dropped.
    SelfReference,
    /// A `//` was collapsed.
    EmptySegment,
    /// A backslash was treated as a separator.
    Backslash,
    /// Decoding stopped at the round limit with escapes still present.
    DecodeLimitReached,
}

impl NormalizationCondition {
    /// The keyword that selects this condition.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PercentEncoded => "percent_encoded",
            Self::DoubleEncoded => "double_encoded",
            Self::InvalidEscape => "invalid_escape",
            Self::NullByte => "null_byte",
            Self::Traversal => "traversal",
            Self::AboveRoot => "above_root",
            Self::SelfReference => "self_reference",
            Self::EmptySegment => "empty_segment",
            Self::Backslash => "backslash",
            Self::DecodeLimitReached => "decode_limit_reached",
        }
    }

    /// Parse the value of a `normalized:` option.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::PercentEncoded,
            Self::DoubleEncoded,
            Self::InvalidEscape,
            Self::NullByte,
            Self::Traversal,
            Self::AboveRoot,
            Self::SelfReference,
            Self::EmptySegment,
            Self::Backslash,
            Self::DecodeLimitReached,
        ]
        .into_iter()
        .find(|condition| condition.as_str() == text.trim())
    }
}

/// One match condition from a rule, in the order it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleOption {
    /// A byte pattern.
    Content(ContentMatch),
    /// A regular expression.
    Pcre(PcreMatch),
    /// A flow-state requirement.
    Flow(FlowMatch),
    /// A flowbit condition or side effect.
    FlowBits(FlowBitsOp),
    /// A numeric test on bytes in the buffer.
    ByteTest(ByteTest),
    /// A cursor move driven by bytes in the buffer.
    ByteJump(ByteJump),
    /// A length test on the buffer.
    Dsize(DsizeMatch),
    /// A condition on what normalization found.
    Normalized(NormalizationCondition),
}

impl RuleOption {
    /// The buffer this option inspects, where that is meaningful.
    #[must_use]
    pub fn buffer(&self) -> Option<Buffer> {
        match self {
            Self::Content(content) => Some(content.buffer),
            Self::Pcre(pcre) => Some(pcre.buffer),
            _ => None,
        }
    }

    /// Whether this option only has an effect and cannot fail to match.
    #[must_use]
    pub fn is_side_effect(&self) -> bool {
        matches!(
            self,
            Self::FlowBits(FlowBitsOp::Set(_) | FlowBitsOp::Unset(_) | FlowBitsOp::Toggle(_))
                | Self::ByteJump(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_operators_apply_as_written() {
        assert!(NumericOp::Greater.apply(5, 3));
        assert!(!NumericOp::Greater.apply(3, 5));
        assert!(NumericOp::BitAnd.apply(0b1010, 0b0010));
        assert!(!NumericOp::BitAnd.apply(0b1010, 0b0101));
        assert_eq!(NumericOp::parse(">="), Some(NumericOp::GreaterOrEqual));
        assert_eq!(NumericOp::parse("nonsense"), None);
    }

    #[test]
    fn dsize_handles_both_comparisons_and_ranges() {
        let greater = DsizeMatch {
            op: NumericOp::Greater,
            value: 200,
            upper: None,
        };
        assert!(greater.matches(201));
        assert!(!greater.matches(200));

        let range = DsizeMatch {
            op: NumericOp::Greater,
            value: 100,
            upper: Some(200),
        };
        assert!(range.matches(150));
        assert!(!range.matches(100));
        assert!(!range.matches(200));
    }

    #[test]
    fn sticky_buffer_keywords_round_trip() {
        for buffer in [
            Buffer::HttpUri,
            Buffer::HttpHeader,
            Buffer::HttpUserAgent,
            Buffer::HttpMethod,
            Buffer::HttpHost,
        ] {
            assert_eq!(Buffer::from_keyword(buffer.as_str()), Some(buffer));
            assert!(buffer.is_http());
        }
        assert!(!Buffer::Payload.is_http());
        assert_eq!(Buffer::from_keyword("http.nonsense"), None);
    }

    #[test]
    fn a_negated_content_cannot_be_a_fast_pattern() {
        // The pre-filter selects packets that CONTAIN the pattern. A rule that
        // requires its absence would never be considered for the packets it is
        // supposed to fire on.
        let mut content = ContentMatch::new(b"evil".to_vec());
        assert!(content.usable_as_fast_pattern());
        content.negated = true;
        assert!(!content.usable_as_fast_pattern());
    }

    #[test]
    fn normalization_conditions_round_trip() {
        assert_eq!(
            NormalizationCondition::parse("double_encoded"),
            Some(NormalizationCondition::DoubleEncoded)
        );
        assert_eq!(NormalizationCondition::parse("nope"), None);
    }
}
