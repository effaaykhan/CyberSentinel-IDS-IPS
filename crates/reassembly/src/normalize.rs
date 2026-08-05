//! Normalization primitives.
//!
//! Guide §6: *normalize before matching.* A rule that looks for `/etc/passwd`
//! has to match traffic that spells it `/etc/./passwd`, `/foo/../etc/passwd`,
//! `%2fetc%2fpasswd`, or `%252fetc%252fpasswd` — because the server at the far
//! end will resolve all of those to the same file, and a sensor that does not
//! is looking at a different request than the one being served.
//!
//! These are **pure functions over bytes**. There is deliberately no HTTP here:
//! finding the URI inside a request is the app-layer parser's job (Phase 3),
//! and keeping the two apart means this half can be exhaustively tested and
//! fuzzed on its own.
//!
//! # Order matters, and it is a target-behaviour decision
//!
//! Decoding happens **before** path collapsing. `%2e%2e%2f` has to become `../`
//! before traversal can be resolved, which is the entire point of the
//! technique. This mirrors servers that percent-decode the path and then
//! resolve it — the common case, and the reading that keeps an attack visible.
//!
//! A server configured the other way (Apache's `AllowEncodedSlashes off`, which
//! rejects an encoded slash outright) would never serve such a request at all,
//! so normalizing it here costs a possible false positive, not a false
//! negative. Between the two, an IDS should take the false positive.
//!
//! # Nothing here can grow its input
//!
//! Decoding turns three bytes into one and collapsing only ever removes
//! segments, so output length is bounded by input length. There is no expansion
//! step an attacker could use to amplify a small packet into a large
//! allocation — the one thing a normalizer must never have.

/// What normalization had to do, and what it found.
///
/// These are **detection signal in their own right**. A request that arrives
/// double-encoded, or that walks above the document root, is unusual in a way
/// worth alerting on even when the resolved path turns out to be harmless — so
/// from Phase 3 these become matchable rule conditions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NormalizationFlags {
    /// The input contained at least one valid `%XX` escape.
    pub percent_encoded: bool,
    /// A second decoding pass changed the result: the input was **double
    /// encoded**, e.g. `%252e` for `.`.
    pub double_encoded: bool,
    /// A `%` was present that did not begin a valid escape.
    pub invalid_escape: bool,
    /// Decoding produced a NUL byte.
    pub null_byte: bool,
    /// A `..` segment was resolved.
    pub traversal: bool,
    /// A `..` segment tried to walk above the root.
    pub above_root: bool,
    /// A `.` segment was dropped.
    pub self_reference: bool,
    /// An empty segment (`//`) was collapsed.
    pub empty_segment: bool,
    /// A backslash was treated as a separator.
    pub backslash: bool,
    /// Decoding stopped at the round limit with escapes still present.
    pub decode_limit_reached: bool,
}

impl NormalizationFlags {
    /// Whether anything at all had to be normalized.
    #[must_use]
    pub fn any(&self) -> bool {
        *self != Self::default()
    }

    fn merge(&mut self, other: Self) {
        self.percent_encoded |= other.percent_encoded;
        self.double_encoded |= other.double_encoded;
        self.invalid_escape |= other.invalid_escape;
        self.null_byte |= other.null_byte;
        self.traversal |= other.traversal;
        self.above_root |= other.above_root;
        self.self_reference |= other.self_reference;
        self.empty_segment |= other.empty_segment;
        self.backslash |= other.backslash;
        self.decode_limit_reached |= other.decode_limit_reached;
    }
}

/// How to normalize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizeOptions {
    /// Maximum percent-decoding passes.
    ///
    /// Two catches ordinary double encoding. It is capped rather than repeated
    /// to a fixed point because an input can always be encoded one level deeper
    /// than any limit, and unbounded work per packet is a denial of service.
    /// When the limit is hit with escapes still present,
    /// [`NormalizationFlags::decode_limit_reached`] says so.
    pub decode_rounds: usize,
    /// Resolve `.` and `..` segments.
    pub collapse_path: bool,
    /// Treat `\` as a path separator, as Windows-hosted servers do.
    pub backslash_is_separator: bool,
}

impl Default for NormalizeOptions {
    fn default() -> Self {
        Self {
            decode_rounds: 2,
            collapse_path: true,
            backslash_is_separator: false,
        }
    }
}

/// The result of normalizing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    /// The canonical bytes.
    pub bytes: Vec<u8>,
    /// How many decoding passes actually changed something.
    pub rounds_applied: usize,
    /// What was found on the way.
    pub flags: NormalizationFlags,
}

/// Decode `%XX` escapes once.
///
/// An escape that is not two hex digits is **left exactly as written** rather
/// than guessed at or dropped: a sensor that silently rewrites malformed input
/// is inventing a request nobody sent.
#[must_use]
pub fn percent_decode(input: &[u8]) -> (Vec<u8>, NormalizationFlags) {
    let mut out = Vec::with_capacity(input.len());
    let mut flags = NormalizationFlags::default();
    let mut index = 0;

    while index < input.len() {
        if input[index] != b'%' {
            out.push(input[index]);
            index += 1;
            continue;
        }
        match (
            input.get(index + 1).and_then(hex_value),
            input.get(index + 2).and_then(hex_value),
        ) {
            (Some(high), Some(low)) => {
                let byte = (high << 4) | low;
                if byte == 0 {
                    flags.null_byte = true;
                }
                out.push(byte);
                flags.percent_encoded = true;
                index += 3;
            }
            _ => {
                flags.invalid_escape = true;
                out.push(b'%');
                index += 1;
            }
        }
    }

    (out, flags)
}

fn hex_value(byte: &u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode `%XX` escapes repeatedly, up to `rounds` passes.
///
/// Stops early once a pass changes nothing.
#[must_use]
pub fn percent_decode_repeatedly(input: &[u8], rounds: usize) -> Normalized {
    let mut flags = NormalizationFlags::default();
    let mut current = input.to_vec();
    let mut applied = 0;

    for round in 0..rounds {
        let (decoded, round_flags) = percent_decode(&current);
        if decoded == current {
            break;
        }
        flags.merge(round_flags);
        if round > 0 {
            // A pass after the first changed something, so at least one escape
            // was itself encoded.
            flags.double_encoded = true;
        }
        current = decoded;
        applied = round + 1;
    }

    // Escapes still present after the last permitted pass: an attacker can
    // always add one more layer, so say we stopped rather than pretend we
    // finished.
    if applied == rounds && rounds > 0 {
        let (probe, _) = percent_decode(&current);
        if probe != current {
            flags.decode_limit_reached = true;
        }
    }

    Normalized {
        bytes: current,
        rounds_applied: applied,
        flags,
    }
}

/// Resolve `.`, `..`, and empty segments in a path.
///
/// Absolute-ness and any trailing separator are preserved, because `/a/b` and
/// `/a/b/` are different requests to most servers.
#[must_use]
pub fn collapse_path(input: &[u8], backslash_is_separator: bool) -> (Vec<u8>, NormalizationFlags) {
    let mut flags = NormalizationFlags::default();

    let normalized_separators: Vec<u8> = if backslash_is_separator {
        input
            .iter()
            .map(|byte| {
                if *byte == b'\\' {
                    flags.backslash = true;
                    b'/'
                } else {
                    *byte
                }
            })
            .collect()
    } else {
        input.to_vec()
    };

    if normalized_separators.is_empty() {
        return (Vec::new(), flags);
    }

    let absolute = normalized_separators[0] == b'/';
    let parts: Vec<&[u8]> = normalized_separators.split(|byte| *byte == b'/').collect();

    // A `//` shows up as an empty part that is neither the leading nor the
    // trailing one — those two are just the separators at each end.
    flags.empty_segment = parts
        .iter()
        .enumerate()
        .any(|(index, part)| part.is_empty() && index != 0 && index != parts.len() - 1);

    // The result names a directory — and so keeps a trailing separator — when
    // the *last* part is a separator, `.`, or `..`. Anything earlier in the
    // path says nothing about how it ends.
    let trailing = matches!(parts.last(), Some(&b"" | &b"." | &b".."));

    let mut segments: Vec<&[u8]> = Vec::new();
    for part in &parts {
        match *part {
            b"" => {}
            b"." => flags.self_reference = true,
            b".." => {
                flags.traversal = true;
                if segments.pop().is_none() {
                    // Walked above the root. Servers clamp here; so do we, and
                    // we remember that it was tried.
                    flags.above_root = true;
                }
            }
            other => segments.push(other),
        }
    }

    let mut out = Vec::with_capacity(normalized_separators.len());
    if absolute {
        out.push(b'/');
    }
    for (index, segment) in segments.iter().enumerate() {
        if index > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(segment);
    }
    // Never invent a leading separator for a relative path that resolved away
    // to nothing: `..` must not become `/`.
    if trailing && !out.is_empty() && !out.ends_with(b"/") {
        out.push(b'/');
    }

    (out, flags)
}

/// Decode and then collapse — the canonical form a rule should match against.
#[must_use]
pub fn normalize_path(input: &[u8], options: &NormalizeOptions) -> Normalized {
    let mut decoded = percent_decode_repeatedly(input, options.decode_rounds);
    if !options.collapse_path {
        return decoded;
    }

    let (collapsed, flags) = collapse_path(&decoded.bytes, options.backslash_is_separator);
    decoded.flags.merge(flags);
    decoded.bytes = collapsed;
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize(input: &str) -> Normalized {
        normalize_path(input.as_bytes(), &NormalizeOptions::default())
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    // -----------------------------------------------------------------------
    // percent decoding
    // -----------------------------------------------------------------------

    #[test]
    fn decodes_valid_escapes_in_either_case() {
        let (out, flags) = percent_decode(b"%2Fetc%2fpasswd");
        assert_eq!(text(&out), "/etc/passwd");
        assert!(flags.percent_encoded);
        assert!(!flags.invalid_escape);
    }

    #[test]
    fn leaves_malformed_escapes_exactly_as_written() {
        for input in ["%", "%2", "%zz", "%2z", "100%", "%%41"] {
            let (out, flags) = percent_decode(input.as_bytes());
            assert!(
                flags.invalid_escape,
                "{input} should flag an invalid escape"
            );
            assert!(
                out.len() <= input.len(),
                "decoding must never grow its input: {input}"
            );
        }
        // Specifically: the stray % survives, it is not dropped or guessed at.
        assert_eq!(text(&percent_decode(b"a%zz").0), "a%zz");
        assert_eq!(text(&percent_decode(b"%%41").0), "%A");
    }

    #[test]
    fn a_decoded_null_byte_is_flagged() {
        let (out, flags) = percent_decode(b"/etc/passwd%00.jpg");
        assert!(flags.null_byte);
        assert_eq!(out[11], 0);
    }

    #[test]
    fn decoding_stops_when_a_pass_changes_nothing() {
        let result = percent_decode_repeatedly(b"/plain/path", 4);
        assert_eq!(result.rounds_applied, 0);
        assert!(!result.flags.double_encoded);
    }

    #[test]
    fn double_encoding_needs_and_gets_a_second_pass() {
        // %252e is `%2e` once decoded, and `.` twice decoded.
        let once = percent_decode_repeatedly(b"%252e%252e%252f", 1);
        assert_eq!(text(&once.bytes), "%2e%2e%2f");
        assert!(!once.flags.double_encoded);
        assert!(once.flags.decode_limit_reached, "one pass was not enough");

        let twice = percent_decode_repeatedly(b"%252e%252e%252f", 2);
        assert_eq!(text(&twice.bytes), "../");
        assert!(twice.flags.double_encoded);
        assert!(!twice.flags.decode_limit_reached);
    }

    #[test]
    fn the_round_limit_is_reported_rather_than_silently_hit() {
        // Triple encoded, with only two rounds allowed.
        let result = percent_decode_repeatedly(b"%25252e", 2);
        assert!(result.flags.decode_limit_reached);
        assert_eq!(text(&result.bytes), "%2e");
    }

    #[test]
    fn decoding_can_be_turned_off_entirely() {
        let result = percent_decode_repeatedly(b"%2e%2e%2f", 0);
        assert_eq!(text(&result.bytes), "%2e%2e%2f");
        assert_eq!(result.rounds_applied, 0);
    }

    // -----------------------------------------------------------------------
    // path collapsing
    // -----------------------------------------------------------------------

    #[test]
    fn collapses_self_references_and_traversal() {
        assert_eq!(text(&collapse_path(b"/a/./b", false).0), "/a/b");
        assert_eq!(text(&collapse_path(b"/a/b/../c", false).0), "/a/c");
        assert_eq!(text(&collapse_path(b"/a/b/../../c", false).0), "/c");
        assert_eq!(
            text(&collapse_path(b"/foo/../etc/passwd", false).0),
            "/etc/passwd"
        );
    }

    #[test]
    fn collapses_repeated_separators() {
        let (out, flags) = collapse_path(b"/a//b///c", false);
        assert_eq!(text(&out), "/a/b/c");
        assert!(flags.empty_segment);
    }

    #[test]
    fn preserves_absoluteness_and_trailing_separators() {
        assert_eq!(text(&collapse_path(b"/a/b/", false).0), "/a/b/");
        assert_eq!(text(&collapse_path(b"a/b", false).0), "a/b");
        assert_eq!(text(&collapse_path(b"/", false).0), "/");
        assert_eq!(text(&collapse_path(b"", false).0), "");
        // `.` and `..` name directories, so the result keeps its separator.
        assert_eq!(text(&collapse_path(b"/a/b/.", false).0), "/a/b/");
        assert_eq!(text(&collapse_path(b"/a/b/..", false).0), "/a/");
    }

    #[test]
    fn walking_above_the_root_is_clamped_and_flagged() {
        let (out, flags) = collapse_path(b"/../../../etc/passwd", false);
        assert_eq!(text(&out), "/etc/passwd");
        assert!(flags.above_root, "escaping the root is worth knowing about");
        assert!(flags.traversal);
    }

    #[test]
    fn backslashes_are_separators_only_when_asked() {
        let (kept, flags) = collapse_path(br"/a\..\b", false);
        assert_eq!(
            text(&kept),
            r"/a\..\b",
            "a backslash is an ordinary byte by default"
        );
        assert!(!flags.backslash);

        let (collapsed, flags) = collapse_path(br"/a\..\b", true);
        assert_eq!(text(&collapsed), "/b");
        assert!(flags.backslash);
    }

    #[test]
    fn an_ordinary_path_is_left_alone_and_flags_nothing() {
        let (out, flags) = collapse_path(b"/index.html", false);
        assert_eq!(text(&out), "/index.html");
        assert!(
            !flags.any(),
            "a clean path should raise no flags: {flags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // the composition — this is what an attacker actually sends
    // -----------------------------------------------------------------------

    #[test]
    fn every_spelling_of_the_same_request_normalizes_alike() {
        // A rule looking for /etc/passwd must match all of these, because the
        // server resolves all of them to the same file.
        let spellings = [
            "/etc/passwd",
            "/etc/./passwd",
            "/foo/../etc/passwd",
            "/etc//passwd",
            "/%65tc/passwd",
            "%2fetc%2fpasswd",
            "/etc/%2e/passwd",
            "/%252e%252e%252fetc/passwd",
            "/a/b/../../etc/passwd",
        ];
        for spelling in spellings {
            assert_eq!(
                text(&normalize(spelling).bytes),
                "/etc/passwd",
                "{spelling} did not normalize to /etc/passwd"
            );
        }
    }

    #[test]
    fn encoded_traversal_is_resolved_because_decoding_happens_first() {
        // The whole point: %2e%2e%2f must become ../ before it can be resolved.
        let result = normalize("/var/www/%2e%2e/%2e%2e/etc/passwd");
        assert_eq!(text(&result.bytes), "/etc/passwd");
        assert!(result.flags.percent_encoded);
        assert!(result.flags.traversal);
    }

    #[test]
    fn double_encoded_traversal_is_resolved_and_flagged() {
        let result = normalize("/var/%252e%252e/%252e%252e/etc/passwd");
        assert_eq!(text(&result.bytes), "/etc/passwd");
        assert!(
            result.flags.double_encoded,
            "double encoding is itself signal"
        );
    }

    #[test]
    fn windows_style_traversal_normalizes_when_the_target_is_windows() {
        let options = NormalizeOptions {
            backslash_is_separator: true,
            ..NormalizeOptions::default()
        };
        let result = normalize_path(br"/scripts/..%5c..%5cwinnt/system32/cmd.exe", &options);
        assert_eq!(text(&result.bytes), "/winnt/system32/cmd.exe");
        assert!(result.flags.backslash);
    }

    #[test]
    fn normalization_never_grows_its_input() {
        // The one property a normalizer must have: no amplification.
        let inputs: [&[u8]; 8] = [
            b"",
            b"/",
            b"%",
            b"%%%%%%%%",
            b"/a/b/c",
            b"%2e%2e%2f%2e%2e%2f",
            b"////////////",
            b"/../../../../..",
        ];
        for input in inputs {
            let result = normalize_path(input, &NormalizeOptions::default());
            assert!(
                result.bytes.len() <= input.len(),
                "{:?} grew from {} to {} bytes",
                text(input),
                input.len(),
                result.bytes.len()
            );
        }
    }

    #[test]
    fn collapsing_can_be_disabled_leaving_only_decoding() {
        let options = NormalizeOptions {
            collapse_path: false,
            ..NormalizeOptions::default()
        };
        let result = normalize_path(b"/a/%2e%2e/b", &options);
        assert_eq!(text(&result.bytes), "/a/../b");
    }

    #[test]
    fn arbitrary_bytes_normalize_without_panicking() {
        let inputs: [&[u8]; 9] = [
            &[],
            &[0xff; 64],
            &[0x00; 16],
            b"%00%00%00",
            b"/../%",
            b"\\\\\\\\",
            b"..",
            b"../",
            &[b'%'; 256],
        ];
        for input in inputs {
            for backslash in [false, true] {
                for rounds in [0, 1, 2, 8] {
                    let options = NormalizeOptions {
                        decode_rounds: rounds,
                        collapse_path: true,
                        backslash_is_separator: backslash,
                    };
                    let result = normalize_path(input, &options);
                    assert!(result.bytes.len() <= input.len());
                }
            }
        }
    }
}
