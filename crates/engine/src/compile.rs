//! Turning parsed rules into something that can be matched quickly.
//!
//! Two things happen here. Headers and regexes are **resolved and compiled
//! once**, at load, so no packet ever pays for parsing a variable or building a
//! DFA. And every rule's `fast_pattern` goes into a shared **Aho-Corasick
//! automaton** per buffer, so one pass over the payload tells us which of
//! thousands of rules are even worth evaluating.
//!
//! # Why a pre-filter at all
//!
//! Evaluating every rule against every packet is quadratic in the wrong things.
//! The pre-filter finds, in a single scan, the small set of rules whose most
//! distinctive pattern is present; only those get the expensive treatment. A
//! rule with no usable pattern cannot be pre-filtered and is evaluated every
//! time — which is why `fast_pattern` selection matters and why a rule with
//! only negated content is a cost to be aware of.
//!
//! # A rule that fails to compile is skipped and reported
//!
//! Not silently dropped, and not fatal. Guide §6: never fail the whole load on
//! one bad rule. But an operator has to be able to see that a rule they wrote
//! is not running, which is what [`CompileReport`] is for.

use std::collections::BTreeMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use cybersentinel_rules::{
    Buffer, ByteJump, ByteTest, ContentMatch, DsizeMatch, FlowBitsOp, FlowMatch,
    NormalizationCondition, Rule, RuleOption, Threshold,
};
use regex::bytes::{Regex, RegexBuilder};

use crate::vars::{CompiledHeader, VarError, VarTable};

/// Limits applied while compiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompileLimits {
    /// Byte budget for a compiled regex program.
    pub regex_size_limit: usize,
    /// Byte budget for a regex's lazy DFA cache.
    pub regex_dfa_size_limit: usize,
}

impl Default for CompileLimits {
    fn default() -> Self {
        Self {
            regex_size_limit: 1 << 20,
            regex_dfa_size_limit: 1 << 20,
        }
    }
}

/// Why a rule could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CompileError {
    /// A header variable could not be resolved.
    #[error("header: {0}")]
    Header(#[from] VarError),
    /// A regex would not compile, or exceeded its budget.
    #[error("pcre {expression:?}: {reason}")]
    Regex {
        /// The expression that failed.
        expression: String,
        /// What went wrong.
        reason: String,
    },
    /// The rule uses a keyword this build cannot evaluate.
    #[error("uses options this build cannot evaluate: {0}")]
    NotEvaluable(String),
}

/// A rule that did not compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileFailure {
    /// Signature id.
    pub sid: u32,
    /// Where the rule came from.
    pub origin: String,
    /// Why it failed.
    pub reason: String,
}

/// What happened during compilation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompileReport {
    /// Rules now running.
    pub compiled: usize,
    /// Rules skipped because they use unimplemented keywords.
    pub not_evaluable: usize,
    /// Rules that failed to compile, with reasons.
    pub failed: Vec<CompileFailure>,
    /// Rules with no usable pre-filter pattern, evaluated on every packet.
    pub without_prefilter: usize,
}

impl CompileReport {
    /// A one-line summary for logs.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} rule(s) armed, {} awaiting engine support, {} failed to compile, \
             {} without a pre-filter pattern",
            self.compiled,
            self.not_evaluable,
            self.failed.len(),
            self.without_prefilter
        )
    }
}

/// A match condition with anything expensive already built.
#[derive(Debug)]
#[non_exhaustive]
pub enum CompiledOption {
    /// A byte pattern.
    Content(ContentMatch),
    /// A compiled regular expression.
    Pcre {
        /// The compiled matcher.
        matcher: Box<Regex>,
        /// Buffer to search.
        buffer: Buffer,
        /// Match must not be present.
        negated: bool,
        /// Search from the end of the previous match.
        relative: bool,
    },
    /// A flow-state requirement.
    Flow(FlowMatch),
    /// A flowbit condition or side effect.
    FlowBits(FlowBitsOp),
    /// A numeric test on buffer bytes.
    ByteTest(ByteTest),
    /// A cursor move driven by buffer bytes.
    ByteJump(ByteJump),
    /// A length test.
    Dsize(DsizeMatch),
    /// A condition on what normalization found.
    Normalized(NormalizationCondition),
}

/// A rule ready to be matched.
#[derive(Debug)]
pub struct CompiledRule {
    /// Signature id.
    pub sid: u32,
    /// Revision.
    pub rev: u32,
    /// Description.
    pub msg: String,
    /// Classification.
    pub classtype: Option<String>,
    /// Severity, from `priority`.
    pub severity: u8,
    /// Metadata, grouped by key.
    pub metadata: BTreeMap<String, Vec<String>>,
    /// Resolved header.
    pub header: CompiledHeader,
    /// Match conditions, in written order.
    pub options: Vec<CompiledOption>,
    /// Rate limiting.
    pub threshold: Option<Threshold>,
    /// Track state without alerting.
    pub no_alert: bool,
    /// Whether matching needs the HTTP parser.
    pub needs_http: bool,
    /// Where the rule came from, for messages.
    pub origin: String,
}

/// Patterns gathered per (buffer, case-sensitivity), with the rule each
/// belongs to, before the automata are built.
type PatternsByBuffer = BTreeMap<(Buffer, bool), (Vec<Vec<u8>>, Vec<usize>)>;

/// One buffer's pre-filter automata.
#[derive(Debug, Default)]
struct Prefilter {
    /// Case-sensitive patterns, and the rule each belongs to.
    sensitive: Option<(AhoCorasick, Vec<usize>)>,
    /// Case-insensitive patterns.
    insensitive: Option<(AhoCorasick, Vec<usize>)>,
}

impl Prefilter {
    fn candidates(&self, haystack: &[u8], out: &mut Vec<usize>) {
        for (automaton, owners) in [&self.sensitive, &self.insensitive].into_iter().flatten() {
            for found in automaton.find_overlapping_iter(haystack) {
                if let Some(rule) = owners.get(found.pattern().as_usize()) {
                    out.push(*rule);
                }
            }
        }
    }
}

/// Every rule, compiled, with its pre-filters.
#[derive(Debug, Default)]
pub struct CompiledRuleset {
    rules: Vec<CompiledRule>,
    prefilters: BTreeMap<Buffer, Prefilter>,
    /// Rules with no usable pre-filter pattern. Evaluated for every packet
    /// their header selects, which is why the count is reported.
    always: Vec<usize>,
    buffers: Vec<Buffer>,
}

impl CompiledRuleset {
    /// Compile a set of parsed rules.
    ///
    /// Never fails as a whole: rules that cannot be compiled are collected in
    /// the report and left out.
    #[must_use]
    pub fn compile<'a>(
        rules: impl IntoIterator<Item = &'a Rule>,
        vars: &VarTable,
        limits: CompileLimits,
    ) -> (Self, CompileReport) {
        let mut report = CompileReport::default();
        let mut compiled = Vec::new();
        // Patterns gathered per (buffer, case-sensitivity) before the automata
        // are built, since Aho-Corasick wants all of them at once.
        let mut patterns: PatternsByBuffer = BTreeMap::new();
        let mut always = Vec::new();

        for rule in rules {
            if !rule.is_evaluable() {
                report.not_evaluable += 1;
                continue;
            }
            match compile_rule(rule, vars, limits) {
                Ok(entry) => {
                    let index = compiled.len();
                    match select_fast_pattern(rule) {
                        Some((buffer, pattern, nocase)) => {
                            let slot = patterns.entry((buffer, nocase)).or_default();
                            slot.0.push(pattern);
                            slot.1.push(index);
                        }
                        None => {
                            report.without_prefilter += 1;
                            always.push(index);
                        }
                    }
                    compiled.push(entry);
                }
                Err(error) => report.failed.push(CompileFailure {
                    sid: rule.sid,
                    origin: rule.location(),
                    reason: error.to_string(),
                }),
            }
        }

        let mut prefilters: BTreeMap<Buffer, Prefilter> = BTreeMap::new();
        for ((buffer, nocase), (needles, owners)) in patterns {
            let automaton = AhoCorasickBuilder::new()
                .ascii_case_insensitive(nocase)
                .match_kind(MatchKind::Standard)
                .build(&needles);
            let Ok(automaton) = automaton else {
                // Building cannot realistically fail for a non-empty pattern
                // set, but a silent loss of the pre-filter would turn into a
                // silent loss of detection, so the rules fall back to always.
                tracing::error!(
                    buffer = buffer.as_str(),
                    "could not build the pre-filter; those rules will be evaluated on every packet"
                );
                always.extend(owners);
                continue;
            };
            let entry = prefilters.entry(buffer).or_default();
            if nocase {
                entry.insensitive = Some((automaton, owners));
            } else {
                entry.sensitive = Some((automaton, owners));
            }
        }

        report.compiled = compiled.len();
        let mut buffers: Vec<Buffer> = prefilters.keys().copied().collect();
        for rule in &compiled {
            for option in &rule.options {
                if let Some(buffer) = compiled_option_buffer(option) {
                    buffers.push(buffer);
                }
            }
        }
        buffers.sort_unstable();
        buffers.dedup();

        (
            Self {
                rules: compiled,
                prefilters,
                always,
                buffers,
            },
            report,
        )
    }

    /// Every compiled rule.
    #[must_use]
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// How many rules are armed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether nothing is armed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether any armed rule needs the HTTP parser.
    #[must_use]
    pub fn needs_http(&self) -> bool {
        self.buffers.iter().any(|buffer| buffer.is_http())
            || self.rules.iter().any(|rule| rule.needs_http)
    }

    /// Rules worth evaluating for the given buffer contents.
    ///
    /// `out` is cleared and filled with rule indices; duplicates are removed so
    /// a rule whose pattern appears twice is only evaluated once.
    pub fn candidates(&self, buffer: Buffer, haystack: &[u8], out: &mut Vec<usize>) {
        self.candidates_in(&[(buffer, haystack)], out);
    }

    /// Rules worth evaluating across several buffers at once.
    ///
    /// One HTTP transaction fills the URI, the headers and more, and a rule's
    /// fast pattern may sit in any of them. Scanning each and taking the union
    /// means every rule is found — and, because the result is deduplicated,
    /// each is still evaluated exactly once.
    pub fn candidates_in(&self, buffers: &[(Buffer, &[u8])], out: &mut Vec<usize>) {
        out.clear();
        for (buffer, haystack) in buffers {
            if let Some(prefilter) = self.prefilters.get(buffer) {
                prefilter.candidates(haystack, out);
            }
        }
        out.extend_from_slice(&self.always);
        out.sort_unstable();
        out.dedup();
    }

    /// A rule by index.
    #[must_use]
    pub fn rule(&self, index: usize) -> Option<&CompiledRule> {
        self.rules.get(index)
    }
}

fn compiled_option_buffer(option: &CompiledOption) -> Option<Buffer> {
    match option {
        CompiledOption::Content(content) => Some(content.buffer),
        CompiledOption::Pcre { buffer, .. } => Some(*buffer),
        _ => None,
    }
}

fn compile_rule(
    rule: &Rule,
    vars: &VarTable,
    limits: CompileLimits,
) -> Result<CompiledRule, CompileError> {
    if !rule.is_evaluable() {
        return Err(CompileError::NotEvaluable(
            rule.unsupported_options.join(", "),
        ));
    }

    let header = CompiledHeader::resolve(&rule.header, vars)?;
    let mut options = Vec::with_capacity(rule.options.len());

    for option in &rule.options {
        options.push(match option {
            RuleOption::Content(content) => CompiledOption::Content(content.clone()),
            RuleOption::Pcre(pcre) => {
                let matcher = RegexBuilder::new(&pcre.source)
                    .case_insensitive(pcre.case_insensitive)
                    .dot_matches_new_line(pcre.dot_matches_newline)
                    .multi_line(pcre.multi_line)
                    // The budget is about compile time and memory, not match
                    // time: `regex` already guarantees linear matching. An
                    // expression that needs more than this is refused rather
                    // than allowed to cost megabytes per rule.
                    .size_limit(limits.regex_size_limit)
                    .dfa_size_limit(limits.regex_dfa_size_limit)
                    .build()
                    .map_err(|error| CompileError::Regex {
                        expression: pcre.source.clone(),
                        reason: error.to_string(),
                    })?;
                CompiledOption::Pcre {
                    matcher: Box::new(matcher),
                    buffer: pcre.buffer,
                    negated: pcre.negated,
                    relative: pcre.relative,
                }
            }
            RuleOption::Flow(flow) => CompiledOption::Flow(*flow),
            RuleOption::FlowBits(op) => CompiledOption::FlowBits(op.clone()),
            RuleOption::ByteTest(test) => CompiledOption::ByteTest(*test),
            RuleOption::ByteJump(jump) => CompiledOption::ByteJump(*jump),
            RuleOption::Dsize(dsize) => CompiledOption::Dsize(*dsize),
            RuleOption::Normalized(condition) => CompiledOption::Normalized(*condition),
            // `RuleOption` is non-exhaustive, so a variant added later lands
            // here. Failing closed is the only safe answer: compiling the rule
            // while dropping a condition would widen the signature silently.
            other => {
                return Err(CompileError::NotEvaluable(format!(
                    "the engine does not handle {other:?} yet"
                )))
            }
        });
    }

    let mut metadata: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in &rule.metadata {
        metadata
            .entry(entry.key.clone())
            .or_default()
            .push(entry.value.clone());
    }

    Ok(CompiledRule {
        sid: rule.sid,
        rev: rule.rev,
        msg: rule.msg.clone(),
        classtype: rule.classtype.clone(),
        severity: rule.severity(),
        metadata,
        header,
        options,
        threshold: rule.threshold,
        no_alert: rule.no_alert,
        needs_http: rule.needs_http(),
        origin: rule.location(),
    })
}

/// Choose the pattern a rule is pre-filtered on.
///
/// An explicit `fast_pattern` wins. Otherwise the **longest** usable pattern,
/// because a longer needle appears in less traffic and so rejects more rules
/// per scan — the whole point of the pre-filter.
fn select_fast_pattern(rule: &Rule) -> Option<(Buffer, Vec<u8>, bool)> {
    let contents: Vec<&ContentMatch> = rule
        .options
        .iter()
        .filter_map(|option| match option {
            RuleOption::Content(content) if content.usable_as_fast_pattern() => Some(content),
            _ => None,
        })
        .collect();

    let chosen = contents
        .iter()
        .find(|content| content.fast_pattern)
        .or_else(|| contents.iter().max_by_key(|content| content.pattern.len()))?;

    Some((chosen.buffer, chosen.pattern.clone(), chosen.nocase))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cybersentinel_rules::parse_rule;

    fn vars() -> VarTable {
        VarTable::new(BTreeMap::new(), BTreeMap::new())
    }

    fn compile(texts: &[&str]) -> (CompiledRuleset, CompileReport) {
        let rules: Vec<Rule> = texts
            .iter()
            .map(|text| parse_rule(text).expect("the rule should parse"))
            .collect();
        CompiledRuleset::compile(rules.iter(), &vars(), CompileLimits::default())
    }

    #[test]
    fn compiles_a_simple_content_rule() {
        let (ruleset, report) =
            compile(&[r#"alert tcp any any -> any any (msg:"m"; content:"evil"; sid:1;)"#]);
        assert_eq!(report.compiled, 1);
        assert!(report.failed.is_empty());
        assert_eq!(report.without_prefilter, 0);
        assert_eq!(ruleset.len(), 1);
        assert_eq!(ruleset.rules()[0].sid, 1);
    }

    #[test]
    fn the_prefilter_selects_only_rules_whose_pattern_is_present() {
        let (ruleset, _) = compile(&[
            r#"alert tcp any any -> any any (msg:"a"; content:"alpha"; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"b"; content:"beta"; sid:2;)"#,
        ]);

        let mut candidates = Vec::new();
        ruleset.candidates(Buffer::Payload, b"nothing here", &mut candidates);
        assert!(candidates.is_empty());

        ruleset.candidates(Buffer::Payload, b"xxx alpha xxx", &mut candidates);
        assert_eq!(candidates.len(), 1);
        assert_eq!(ruleset.rule(candidates[0]).unwrap().sid, 1);

        ruleset.candidates(Buffer::Payload, b"alpha and beta", &mut candidates);
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn a_repeated_pattern_yields_the_rule_once() {
        let (ruleset, _) =
            compile(&[r#"alert tcp any any -> any any (msg:"a"; content:"ab"; sid:1;)"#]);
        let mut candidates = Vec::new();
        ruleset.candidates(Buffer::Payload, b"ababababab", &mut candidates);
        assert_eq!(candidates.len(), 1, "evaluate each rule once per buffer");
    }

    #[test]
    fn case_insensitive_patterns_match_either_case() {
        let (ruleset, _) = compile(&[
            r#"alert tcp any any -> any any (msg:"a"; content:"SELECT"; nocase; sid:1;)"#,
        ]);
        let mut candidates = Vec::new();
        ruleset.candidates(Buffer::Payload, b"union select 1", &mut candidates);
        assert_eq!(candidates.len(), 1);
    }

    #[test]
    fn the_longest_pattern_is_chosen_unless_one_is_marked() {
        let rule = parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; content:"ab"; content:"a-much-longer-one"; sid:1;)"#,
        )
        .unwrap();
        let (buffer, pattern, _) = select_fast_pattern(&rule).expect("a pattern");
        assert_eq!(pattern, b"a-much-longer-one");
        assert_eq!(buffer, Buffer::Payload);

        let marked = parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; content:"ab"; fast_pattern; content:"a-much-longer-one"; sid:1;)"#,
        )
        .unwrap();
        assert_eq!(select_fast_pattern(&marked).unwrap().1, b"ab");
    }

    #[test]
    fn a_rule_with_no_usable_pattern_is_always_a_candidate() {
        // It cannot be pre-filtered, so it costs something on every packet —
        // which is why the report counts them.
        let (ruleset, report) =
            compile(&[r#"alert tcp any any -> any any (msg:"m"; dsize:>100; sid:1;)"#]);
        assert_eq!(report.without_prefilter, 1);

        let mut candidates = Vec::new();
        ruleset.candidates(Buffer::Payload, b"anything at all", &mut candidates);
        assert_eq!(candidates.len(), 1);
    }

    #[test]
    fn a_rule_with_only_negated_content_cannot_be_prefiltered() {
        let (_, report) =
            compile(&[r#"alert tcp any any -> any any (msg:"m"; content:!"benign"; sid:1;)"#]);
        assert_eq!(report.without_prefilter, 1);
    }

    #[test]
    fn patterns_are_kept_per_buffer() {
        let (ruleset, _) = compile(&[
            r#"alert http any any -> any any (msg:"u"; http.uri; content:"/admin"; sid:1;)"#,
            r#"alert tcp any any -> any any (msg:"p"; content:"/admin"; sid:2;)"#,
        ]);

        let mut candidates = Vec::new();
        ruleset.candidates(Buffer::HttpUri, b"GET /admin", &mut candidates);
        assert_eq!(ruleset.rule(candidates[0]).unwrap().sid, 1);

        ruleset.candidates(Buffer::Payload, b"GET /admin", &mut candidates);
        assert_eq!(ruleset.rule(candidates[0]).unwrap().sid, 2);
    }

    // -----------------------------------------------------------------------
    // failure handling
    // -----------------------------------------------------------------------

    #[test]
    fn an_over_budget_regex_is_refused_rather_than_accepted() {
        // Linear-time matching does not make compilation free. A pathological
        // expression can cost megabytes of program, and a rule nobody can
        // afford to load must not load.
        let huge = format!("(?:{}){{200}}", "[a-z0-9]{40}");
        let text = format!(r#"alert tcp any any -> any any (msg:"m"; pcre:"/{huge}/"; sid:1;)"#);
        let rules = [parse_rule(&text).expect("the rule parses")];
        let (ruleset, report) = CompiledRuleset::compile(
            rules.iter(),
            &vars(),
            CompileLimits {
                regex_size_limit: 1 << 10,
                regex_dfa_size_limit: 1 << 10,
            },
        );

        assert_eq!(report.compiled, 0);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].sid, 1);
        assert!(
            report.failed[0].reason.contains("pcre"),
            "{:?}",
            report.failed[0]
        );
        assert!(ruleset.is_empty());
    }

    #[test]
    fn the_same_regex_compiles_under_a_generous_budget() {
        let text = r#"alert tcp any any -> any any (msg:"m"; pcre:"/[a-z]{1,20}/"; sid:1;)"#;
        let rules = [parse_rule(text).unwrap()];
        let (_, report) = CompiledRuleset::compile(rules.iter(), &vars(), CompileLimits::default());
        assert_eq!(report.compiled, 1, "{:?}", report.failed);
    }

    #[test]
    fn an_invalid_regex_is_reported_not_fatal() {
        let rules = [
            parse_rule(r#"alert tcp any any -> any any (msg:"bad"; pcre:"/[unclosed/"; sid:1;)"#)
                .unwrap(),
            parse_rule(r#"alert tcp any any -> any any (msg:"good"; content:"x"; sid:2;)"#)
                .unwrap(),
        ];
        let (ruleset, report) =
            CompiledRuleset::compile(rules.iter(), &vars(), CompileLimits::default());
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.compiled, 1, "one bad rule must not stop the others");
        assert_eq!(ruleset.rules()[0].sid, 2);
    }

    #[test]
    fn an_unresolvable_header_is_reported_not_fatal() {
        let rules =
            [
                parse_rule(r#"alert tcp $NOPE any -> any any (msg:"m"; content:"x"; sid:1;)"#)
                    .unwrap(),
            ];
        let (_, report) = CompiledRuleset::compile(rules.iter(), &vars(), CompileLimits::default());
        assert_eq!(report.failed.len(), 1);
        assert!(
            report.failed[0].reason.contains("NOPE"),
            "{:?}",
            report.failed[0]
        );
    }

    #[test]
    fn non_evaluable_rules_are_counted_separately_from_failures() {
        // "Not implemented yet" and "your rule is broken" are different things
        // and an operator needs to tell them apart.
        let rules = [parse_rule(
            r#"alert tcp any any -> any any (msg:"m"; content:"x"; endswith; sid:1;)"#,
        )
        .unwrap()];
        let (_, report) = CompiledRuleset::compile(rules.iter(), &vars(), CompileLimits::default());
        assert_eq!(report.not_evaluable, 1);
        assert!(report.failed.is_empty());
        assert_eq!(report.compiled, 0);
    }
}
