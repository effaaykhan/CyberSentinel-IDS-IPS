//! Reading `.rules` files into a [`RuleSet`].
//!
//! Guide §6: *graceful rule loading — skip and log unsupported rules; never
//! fail the whole load on one bad rule.* A single malformed line must not take
//! a sensor's entire detection capability offline, so every failure is recorded
//! with its file, line, and reason, and loading continues.
//!
//! A missing rule *file*, by contrast, is reported as a skip against that file
//! rather than silently ignored — an operator who mistypes a path should not
//! discover it by noticing they have no alerts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::model::{Rule, RuleOrigin};
use crate::parser::parse_rule;

/// A rule that did not make it into the ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRule {
    /// File the rule came from.
    pub file: PathBuf,
    /// 1-based line the rule started on, or 0 if the whole file failed.
    pub line: usize,
    /// Why it was skipped.
    pub reason: String,
    /// The offending text, truncated for logging.
    pub raw: String,
}

/// What happened during a load.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadReport {
    /// Files that were read successfully.
    pub files: Vec<PathBuf>,
    /// Rules parsed successfully.
    pub loaded: usize,
    /// Of those, how many this build can actually evaluate.
    pub evaluable: usize,
    /// Rules that could not be parsed, or were rejected as duplicates.
    pub skipped: Vec<SkippedRule>,
    /// Recognised-but-unimplemented option keywords, and how many rules used
    /// each. This is the coverage gap, quantified.
    pub unsupported_options: BTreeMap<String, usize>,
}

impl LoadReport {
    /// Rules parsed but not evaluable by this build.
    #[must_use]
    pub fn non_evaluable(&self) -> usize {
        self.loaded - self.evaluable
    }

    /// A one-line summary for logs and `stats`.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} rule(s) loaded from {} file(s): {} evaluable, {} awaiting engine support, {} skipped",
            self.loaded,
            self.files.len(),
            self.evaluable,
            self.non_evaluable(),
            self.skipped.len(),
        )
    }
}

/// The loaded rules.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    by_sid: BTreeMap<u32, usize>,
}

impl RuleSet {
    /// An empty ruleset.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every loaded rule, in load order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Number of loaded rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the ruleset is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Look a rule up by signature id.
    #[must_use]
    pub fn get(&self, sid: u32) -> Option<&Rule> {
        self.by_sid
            .get(&sid)
            .and_then(|index| self.rules.get(*index))
    }

    /// Rules this build can evaluate.
    ///
    /// **The engine must iterate this, not [`RuleSet::rules`].**
    pub fn evaluable(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|rule| rule.is_evaluable())
    }

    /// Load every file in `paths`, in order.
    ///
    /// Never fails: unreadable files and unparseable rules land in
    /// [`LoadReport::skipped`].
    #[must_use]
    pub fn load_files<P: AsRef<Path>>(paths: &[P]) -> (Self, LoadReport) {
        let mut set = Self::new();
        let mut report = LoadReport::default();

        for path in paths {
            let path = path.as_ref();
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    report.files.push(path.to_path_buf());
                    set.load_text(&text, path, &mut report);
                }
                Err(error) => {
                    let reason = format!("could not read rule file: {error}");
                    tracing::error!(file = %path.display(), %error, "could not read rule file");
                    report.skipped.push(SkippedRule {
                        file: path.to_path_buf(),
                        line: 0,
                        reason,
                        raw: String::new(),
                    });
                }
            }
        }

        set.log_report(&report);
        (set, report)
    }

    /// Load rules from a string, attributing them to `file`.
    pub fn load_text(&mut self, text: &str, file: &Path, report: &mut LoadReport) {
        for (line, raw) in logical_lines(text) {
            let origin = RuleOrigin::new(file, line);
            match parse_rule(&raw) {
                Ok(mut rule) => {
                    if let Some(existing) = self.by_sid.get(&rule.sid) {
                        let previous = self.rules[*existing].location();
                        let reason =
                            format!("duplicate sid {} (already defined at {previous})", rule.sid);
                        tracing::warn!(rule = %origin, %reason, "skipping rule");
                        report.skipped.push(SkippedRule {
                            file: file.to_path_buf(),
                            line,
                            reason,
                            raw: truncate(&raw),
                        });
                        continue;
                    }

                    for option in &rule.unsupported_options {
                        *report
                            .unsupported_options
                            .entry(option.clone())
                            .or_insert(0) += 1;
                    }
                    report.loaded += 1;
                    if rule.is_evaluable() {
                        report.evaluable += 1;
                    } else {
                        tracing::debug!(
                            rule = %origin,
                            sid = rule.sid,
                            options = ?rule.unsupported_options,
                            "rule loaded but not evaluable by this build"
                        );
                    }

                    rule.origin = Some(origin);
                    self.by_sid.insert(rule.sid, self.rules.len());
                    self.rules.push(rule);
                }
                Err(error) => {
                    tracing::warn!(rule = %origin, %error, "skipping unparseable rule");
                    report.skipped.push(SkippedRule {
                        file: file.to_path_buf(),
                        line,
                        reason: error.to_string(),
                        raw: truncate(&raw),
                    });
                }
            }
        }
    }

    fn log_report(&self, report: &LoadReport) {
        tracing::info!("{}", report.summary());
        if !report.unsupported_options.is_empty() {
            let breakdown = report
                .unsupported_options
                .iter()
                .map(|(option, count)| format!("{option}={count}"))
                .collect::<Vec<_>>()
                .join(" ");
            tracing::warn!(
                "{} rule(s) use options this build cannot evaluate yet and will not fire: {breakdown}",
                report.non_evaluable(),
            );
        }
        if !report.skipped.is_empty() {
            tracing::warn!(
                "{} rule(s) skipped; see the warnings above",
                report.skipped.len()
            );
        }
    }
}

/// Yield `(starting line number, rule text)` for each rule in a file.
///
/// Strips comments and blank lines, and joins continuation lines — a line whose
/// last non-whitespace character is `\` continues onto the next.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut buffer = String::new();
    let mut start_line = 0usize;

    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        // A BOM on the first line would otherwise become part of the action.
        let line = if number == 1 {
            line.trim_start_matches('\u{feff}')
        } else {
            line
        };
        let trimmed = line.trim();

        if buffer.is_empty() {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            start_line = number;
        }

        match trimmed.strip_suffix('\\') {
            Some(head) => {
                buffer.push_str(head.trim_end());
                buffer.push(' ');
            }
            None => {
                buffer.push_str(trimmed);
                out.push((start_line, std::mem::take(&mut buffer)));
            }
        }
    }

    // A file ending on a continuation line: keep what we have so the parser can
    // report a real error rather than dropping the rule silently.
    if !buffer.trim().is_empty() {
        out.push((start_line, buffer));
    }
    out
}

/// Cap rule text kept for logging, so one enormous line cannot flood the log.
fn truncate(text: &str) -> String {
    const LIMIT: usize = 256;
    if text.len() <= LIMIT {
        return text.to_string();
    }
    let mut end = LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(text: &str) -> (RuleSet, LoadReport) {
        let mut set = RuleSet::new();
        let mut report = LoadReport::default();
        set.load_text(text, Path::new("test.rules"), &mut report);
        report.files.push(PathBuf::from("test.rules"));
        (set, report)
    }

    #[test]
    fn loads_rules_and_skips_comments_and_blanks() {
        let (set, report) = load(
            r#"
# a comment

alert tcp any any -> any any (msg:"one"; sid:1;)

  # indented comment
alert udp any any -> any any (msg:"two"; sid:2;)
"#,
        );
        assert_eq!(set.len(), 2);
        assert_eq!(report.loaded, 2);
        assert_eq!(report.evaluable, 2);
        assert!(report.skipped.is_empty());
    }

    #[test]
    fn records_the_origin_line_of_each_rule() {
        let (set, _) = load("\n\nalert tcp any any -> any any (msg:\"m\"; sid:1;)\n");
        let origin = set.get(1).unwrap().origin.as_ref().unwrap();
        assert_eq!(origin.line, 3);
        assert_eq!(origin.file, PathBuf::from("test.rules"));
    }

    #[test]
    fn joins_continuation_lines_and_reports_the_first_line() {
        let (set, report) =
            load("alert tcp any any -> any any ( \\\n    msg:\"joined\"; \\\n    sid:42;)\n");
        assert_eq!(report.loaded, 1);
        let rule = set.get(42).unwrap();
        assert_eq!(rule.msg, "joined");
        assert_eq!(rule.origin.as_ref().unwrap().line, 1);
    }

    #[test]
    fn one_bad_rule_does_not_stop_the_load() {
        let (set, report) = load(
            r#"alert tcp any any -> any any (msg:"good one"; sid:1;)
this is not a rule at all
alert tcp any any -> any any (msg:"no sid";)
alert tcp any any -> any any (msg:"good two"; sid:2;)
"#,
        );
        assert_eq!(set.len(), 2, "the good rules must still load");
        assert_eq!(report.skipped.len(), 2);
        assert_eq!(report.skipped[0].line, 2);
        assert_eq!(report.skipped[1].line, 3);
        assert!(report.skipped[1].reason.contains("sid"));
        assert!(report.skipped[0].raw.contains("not a rule"));
    }

    #[test]
    fn duplicate_sids_are_skipped_with_a_pointer_to_the_original() {
        let (set, report) = load(
            r#"alert tcp any any -> any any (msg:"first"; sid:7;)
alert udp any any -> any any (msg:"second"; sid:7;)
"#,
        );
        assert_eq!(set.len(), 1);
        assert_eq!(set.get(7).unwrap().msg, "first");
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].reason.contains("duplicate sid 7"));
        assert!(report.skipped[0].reason.contains("test.rules:1"));
    }

    #[test]
    fn counts_unsupported_options_per_keyword() {
        let (_, report) = load(
            r#"alert tcp any any -> any any (msg:"a"; content:"x"; endswith; sid:1;)
alert tcp any any -> any any (msg:"b"; content:"y"; endswith; detection_filter:x; sid:2;)
alert tcp any any -> any any (msg:"c"; content:"z"; sid:3;)
"#,
        );
        assert_eq!(report.loaded, 3);
        assert_eq!(report.evaluable, 1);
        assert_eq!(report.non_evaluable(), 2);
        assert_eq!(report.unsupported_options["endswith"], 2);
        assert_eq!(report.unsupported_options["detection_filter"], 1);
    }

    #[test]
    fn evaluable_iterator_excludes_inert_rules() {
        let (set, _) = load(
            r#"alert tcp any any -> any any (msg:"inert"; content:"x"; endswith; sid:1;)
alert tcp any any -> any any (msg:"live"; content:"y"; sid:2;)
"#,
        );
        let live: Vec<u32> = set.evaluable().map(|rule| rule.sid).collect();
        assert_eq!(
            live,
            vec![2],
            "a rule with unevaluated conditions must never be evaluated"
        );
    }

    #[test]
    fn a_missing_file_is_reported_not_ignored() {
        let missing = std::env::temp_dir().join("cybersentinel-definitely-absent.rules");
        let (set, report) = RuleSet::load_files(&[missing]);
        assert!(set.is_empty());
        assert!(report.files.is_empty());
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].line, 0);
        assert!(report.skipped[0].reason.contains("could not read"));
    }

    #[test]
    fn a_trailing_continuation_is_surfaced_as_a_parse_error() {
        let (set, report) = load("alert tcp any any -> any any (msg:\"m\"; sid:1;) \\\n");
        assert!(set.is_empty() || set.len() == 1);
        // Either way it must be accounted for, never silently dropped.
        assert_eq!(report.loaded + report.skipped.len(), 1);
    }

    #[test]
    fn a_leading_byte_order_mark_is_stripped() {
        let (set, report) = load("\u{feff}alert tcp any any -> any any (msg:\"m\"; sid:1;)\n");
        assert!(
            report.skipped.is_empty(),
            "BOM should not break the first rule"
        );
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn oversized_rule_text_is_truncated_in_the_report() {
        let long = format!(
            "alert tcp any any -> any any (msg:\"{}\";)",
            "x".repeat(5_000)
        );
        let (_, report) = load(&long);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].raw.chars().count() <= 257);
    }

    #[test]
    fn summary_reports_every_bucket() {
        let (_, report) = load(
            r#"alert tcp any any -> any any (msg:"a"; sid:1;)
alert tcp any any -> any any (msg:"b"; content:"x"; endswith; sid:2;)
garbage
"#,
        );
        let summary = report.summary();
        assert!(summary.contains("2 rule(s) loaded"), "{summary}");
        assert!(summary.contains("1 evaluable"), "{summary}");
        assert!(summary.contains("1 awaiting engine support"), "{summary}");
        assert!(summary.contains("1 skipped"), "{summary}");
    }
}
