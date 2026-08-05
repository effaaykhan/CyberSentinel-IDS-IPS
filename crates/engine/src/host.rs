//! Host-rule compilation and evaluation.
//!
//! Host events are **records with named fields**, not byte streams. A file
//! change has a path and a kind; an authentication attempt has a user and an
//! outcome. Matching those is a direct comparison against named values, so this
//! is a direct evaluator rather than the packet path's header grouping and
//! multi-pattern scan.
//!
//! That is a deliberate difference, not an omission. The Aho-Corasick
//! pre-filter earns its keep when thousands of rules must be narrowed against
//! megabytes of payload per second. Host events arrive at human rates and carry
//! a handful of short fields; selecting candidates by **event kind** is all the
//! narrowing they need, and a pre-filter would cost more than it saved.
//!
//! Everything else is shared with the network side: the rule model and loader,
//! thresholds, flowbits, and the `alert` pipeline.

use std::collections::BTreeMap;

use cybersentinel_common::event::{AuthEvent, FimEvent, ProcessEvent};
use cybersentinel_rules::{
    FlowBitsOp, HostEventKind, HostField, HostMatchKind, HostMatcher, Rule, RuleOption, Threshold,
};
use regex::Regex;

use crate::compile::{CompileError, CompileFailure, CompileLimits, CompileReport};
use crate::eval::{FlowBits, MatchOutcome};

/// One host event being matched.
#[derive(Debug, Clone, Copy)]
pub enum HostObservation<'a> {
    /// A watched file changed.
    Fim(&'a FimEvent),
    /// An authentication attempt.
    Auth(&'a AuthEvent),
    /// A process event.
    Process(&'a ProcessEvent),
}

impl HostObservation<'_> {
    /// Which kind of record this is.
    #[must_use]
    pub fn kind(&self) -> HostEventKind {
        match self {
            Self::Fim(_) => HostEventKind::Fim,
            Self::Auth(_) => HostEventKind::Auth,
            Self::Process(_) => HostEventKind::Process,
        }
    }

    /// The value of a named field, if this record has one.
    ///
    /// A field the record does not carry returns `None`, and a condition on it
    /// therefore fails — the same fail-closed rule the packet evaluator uses.
    #[must_use]
    pub fn field(&self, field: HostField) -> Option<String> {
        match (self, field) {
            (Self::Fim(fim), HostField::FilePath) => Some(fim.path.clone()),
            (Self::Fim(fim), HostField::FileChange) => Some(fim.change.as_str().to_string()),
            (Self::Auth(auth), HostField::AuthOutcome) => Some(auth.outcome.as_str().to_string()),
            (Self::Auth(auth), HostField::AuthUser) => auth.user.clone(),
            (Self::Auth(auth), HostField::AuthService) => auth.service.clone(),
            (Self::Auth(auth), HostField::AuthSource) => {
                auth.source_address.map(|address| address.to_string())
            }
            (Self::Process(process), HostField::ProcessName) => Some(process.name.clone()),
            (Self::Process(process), HostField::ProcessChange) => {
                Some(process.change.as_str().to_string())
            }
            (Self::Process(process), HostField::ProcessCommandLine) => process.command_line.clone(),
            _ => None,
        }
    }

    /// What a `track by_src` threshold counts against.
    ///
    /// The natural "who did this" for each kind: the address an attempt came
    /// from, the file that changed, the process that ran. Without it, a burst
    /// of failed logins from one address and from a thousand would look the
    /// same to a threshold.
    #[must_use]
    pub fn subject(&self) -> String {
        match self {
            Self::Fim(fim) => fim.path.clone(),
            Self::Auth(auth) => auth
                .source_address
                .map(|address| address.to_string())
                .or_else(|| auth.user.clone())
                .unwrap_or_default(),
            Self::Process(process) => process.name.clone(),
        }
    }

    /// A one-line description, for incident summaries.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Fim(fim) => format!("{} {}", fim.change.as_str(), fim.path),
            Self::Auth(auth) => format!(
                "{} for {}",
                auth.outcome.as_str(),
                auth.user.as_deref().unwrap_or("(unknown user)")
            ),
            Self::Process(process) => {
                format!(
                    "{} {} (pid {})",
                    process.change.as_str(),
                    process.name,
                    process.pid
                )
            }
        }
    }
}

/// A compiled way of matching one field.
#[derive(Debug)]
enum CompiledMatcher {
    AnyOf {
        values: Vec<String>,
        kind: HostMatchKind,
        nocase: bool,
    },
    Regex(Box<Regex>),
}

impl CompiledMatcher {
    fn matches(&self, value: &str) -> bool {
        match self {
            Self::AnyOf {
                values,
                kind,
                nocase,
            } => values.iter().any(|candidate| {
                let (value, candidate) = if *nocase {
                    (value.to_ascii_lowercase(), candidate.to_ascii_lowercase())
                } else {
                    (value.to_string(), candidate.clone())
                };
                match kind {
                    HostMatchKind::Exact => value == candidate,
                    HostMatchKind::Prefix => value.starts_with(&candidate),
                    HostMatchKind::Contains => value.contains(&candidate),
                }
            }),
            Self::Regex(regex) => regex.is_match(value),
        }
    }
}

/// One compiled condition.
#[derive(Debug)]
enum CompiledCondition {
    Field {
        field: HostField,
        negated: bool,
        matcher: CompiledMatcher,
    },
    BitIsSet(String),
    BitIsNotSet(String),
    BitEffect(FlowBitsOp),
}

/// A host rule ready to be matched.
#[derive(Debug)]
pub struct CompiledHostRule {
    /// Signature id.
    pub sid: u32,
    /// Revision.
    pub rev: u32,
    /// Description.
    pub msg: String,
    /// Classification.
    pub classtype: Option<String>,
    /// Severity.
    pub severity: u8,
    /// Metadata, grouped by key.
    pub metadata: BTreeMap<String, Vec<String>>,
    /// The event kind this rule applies to.
    pub kind: HostEventKind,
    /// Rate limiting.
    pub threshold: Option<Threshold>,
    /// Track state without alerting.
    pub no_alert: bool,
    /// Where the rule came from.
    pub origin: String,
    conditions: Vec<CompiledCondition>,
}

/// Host rules, indexed by the event kind they apply to.
#[derive(Debug, Default)]
pub struct HostRuleset {
    rules: Vec<CompiledHostRule>,
    /// Candidate selection: the only narrowing host events need.
    by_kind: BTreeMap<HostEventKind, Vec<usize>>,
}

impl HostRuleset {
    /// Compile host rules.
    ///
    /// Never fails as a whole; failures land in the report.
    #[must_use]
    pub fn compile<'a>(
        rules: impl IntoIterator<Item = &'a Rule>,
        limits: CompileLimits,
    ) -> (Self, CompileReport) {
        let mut report = CompileReport::default();
        let mut compiled = Vec::new();
        let mut by_kind: BTreeMap<HostEventKind, Vec<usize>> = BTreeMap::new();

        for rule in rules {
            if !rule.is_evaluable() {
                report.not_evaluable += 1;
                continue;
            }
            match compile_host_rule(rule, limits) {
                Ok(entry) => {
                    by_kind.entry(entry.kind).or_default().push(compiled.len());
                    compiled.push(entry);
                }
                Err(error) => report.failed.push(CompileFailure {
                    sid: rule.sid,
                    origin: rule.location(),
                    reason: error.to_string(),
                }),
            }
        }

        report.compiled = compiled.len();
        (
            Self {
                rules: compiled,
                by_kind,
            },
            report,
        )
    }

    /// Every compiled host rule.
    #[must_use]
    pub fn rules(&self) -> &[CompiledHostRule] {
        &self.rules
    }

    /// How many host rules are armed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether none are armed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The rules that could match this kind of record.
    #[must_use]
    pub fn candidates(&self, kind: HostEventKind) -> &[usize] {
        self.by_kind.get(&kind).map_or(&[], Vec::as_slice)
    }

    /// A rule by index.
    #[must_use]
    pub fn rule(&self, index: usize) -> Option<&CompiledHostRule> {
        self.rules.get(index)
    }
}

fn compile_host_rule(rule: &Rule, limits: CompileLimits) -> Result<CompiledHostRule, CompileError> {
    let kind = match rule.host_event_kind() {
        Ok(Some(kind)) => kind,
        Ok(None) => {
            return Err(CompileError::NotEvaluable(
                "no host field conditions".to_string(),
            ))
        }
        // A rule naming fields from two kinds can never match one record. Armed
        // and permanently silent is the worst outcome, so it is refused.
        Err((first, second)) => {
            return Err(CompileError::NotEvaluable(format!(
                "mixes {} and {} fields, so it could never match one event",
                first.as_str(),
                second.as_str()
            )))
        }
    };

    let mut conditions = Vec::new();
    for option in &rule.options {
        match option {
            RuleOption::Host(host) => {
                let matcher = match &host.matcher {
                    HostMatcher::AnyOf {
                        values,
                        kind,
                        nocase,
                    } => CompiledMatcher::AnyOf {
                        values: values.clone(),
                        kind: *kind,
                        nocase: *nocase,
                    },
                    HostMatcher::Regex(source) => {
                        let regex = regex::RegexBuilder::new(source)
                            .size_limit(limits.regex_size_limit)
                            .dfa_size_limit(limits.regex_dfa_size_limit)
                            .build()
                            .map_err(|error| CompileError::Regex {
                                expression: source.clone(),
                                reason: error.to_string(),
                            })?;
                        CompiledMatcher::Regex(Box::new(regex))
                    }
                };
                conditions.push(CompiledCondition::Field {
                    field: host.field,
                    negated: host.negated,
                    matcher,
                });
            }
            RuleOption::FlowBits(FlowBitsOp::IsSet(name)) => {
                conditions.push(CompiledCondition::BitIsSet(name.clone()));
            }
            RuleOption::FlowBits(FlowBitsOp::IsNotSet(name)) => {
                conditions.push(CompiledCondition::BitIsNotSet(name.clone()));
            }
            RuleOption::FlowBits(op) => {
                conditions.push(CompiledCondition::BitEffect(op.clone()));
            }
            // Anything the host evaluator cannot answer is refused rather than
            // dropped: a condition silently ignored widens the rule.
            other => {
                return Err(CompileError::NotEvaluable(format!(
                    "{other:?} is not a host condition"
                )))
            }
        }
    }

    let mut metadata: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in &rule.metadata {
        metadata
            .entry(entry.key.clone())
            .or_default()
            .push(entry.value.clone());
    }

    Ok(CompiledHostRule {
        sid: rule.sid,
        rev: rule.rev,
        msg: rule.msg.clone(),
        classtype: rule.classtype.clone(),
        severity: rule.severity(),
        metadata,
        kind,
        threshold: rule.threshold,
        no_alert: rule.no_alert,
        origin: rule.location(),
        conditions,
    })
}

/// Evaluate one host rule against one record.
///
/// Returns `None` if it did not match. Side effects are returned rather than
/// applied, exactly as on the packet side, so a rule that matched half way
/// leaves nothing behind.
#[must_use]
pub fn evaluate_host(
    rule: &CompiledHostRule,
    observation: &HostObservation<'_>,
    bits: &FlowBits,
) -> Option<MatchOutcome> {
    if rule.kind != observation.kind() {
        return None;
    }

    let mut side_effects = Vec::new();
    for condition in &rule.conditions {
        match condition {
            CompiledCondition::Field {
                field,
                negated,
                matcher,
            } => {
                // A record without the field cannot satisfy a positive
                // condition, and cannot contradict a negated one either — an
                // absent value is not evidence.
                let value = observation.field(*field)?;
                if matcher.matches(&value) == *negated {
                    return None;
                }
            }
            CompiledCondition::BitIsSet(name) => {
                if !bits.is_set(name) {
                    return None;
                }
            }
            CompiledCondition::BitIsNotSet(name) => {
                if bits.is_set(name) {
                    return None;
                }
            }
            CompiledCondition::BitEffect(op) => side_effects.push(op.clone()),
        }
    }

    Some(MatchOutcome { side_effects })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cybersentinel_common::event::{AuthOutcome, FileChange, FimDetection, ProcessChange};
    use cybersentinel_rules::parse_rule;

    fn compile(texts: &[&str]) -> (HostRuleset, CompileReport) {
        let rules: Vec<Rule> = texts
            .iter()
            .map(|text| parse_rule(text).expect("the rule should parse"))
            .collect();
        HostRuleset::compile(rules.iter(), CompileLimits::default())
    }

    fn fim(path: &str, change: FileChange) -> FimEvent {
        FimEvent {
            path: path.to_string(),
            change,
            detected_by: FimDetection::RealTime,
            size: None,
            sha256: None,
            previous_sha256: None,
            mode: None,
            uid: None,
            gid: None,
        }
    }

    fn auth(outcome: AuthOutcome, user: Option<&str>, source: Option<&str>) -> AuthEvent {
        AuthEvent {
            outcome,
            user: user.map(str::to_string),
            service: Some("sshd".into()),
            source_address: source.map(|s| s.parse().unwrap()),
            source_port: None,
            message: "test".into(),
            log_source: "test".into(),
            suspicious: Vec::new(),
        }
    }

    fn process(name: &str, change: ProcessChange) -> ProcessEvent {
        ProcessEvent {
            change,
            pid: 42,
            name: name.to_string(),
            executable: Some(format!("/usr/bin/{name}")),
            command_line: Some(format!("{name} -l -p 4444")),
            uid: Some(0),
            parent_pid: Some(1),
        }
    }

    fn matches(rule_text: &str, observation: HostObservation<'_>) -> bool {
        let (ruleset, report) = compile(&[rule_text]);
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert_eq!(ruleset.len(), 1, "{}", report.summary());
        evaluate_host(&ruleset.rules()[0], &observation, &FlowBits::default()).is_some()
    }

    // -----------------------------------------------------------------------
    // file integrity
    // -----------------------------------------------------------------------

    #[test]
    fn a_file_path_condition_matches_by_prefix() {
        // An operator writing a directory means everything under it.
        let rule = r#"alert ip any any -> any any (msg:"m"; file.path:"/usr/bin"; sid:1000001;)"#;
        assert!(matches(
            rule,
            HostObservation::Fim(&fim("/usr/bin/sudo", FileChange::Modified))
        ));
        assert!(!matches(
            rule,
            HostObservation::Fim(&fim("/home/x", FileChange::Modified))
        ));
    }

    #[test]
    fn a_file_change_condition_matches_any_listed_kind() {
        let rule = r#"alert ip any any -> any any (msg:"m"; file.path:"/etc"; file.change:"modified,created"; sid:1000001;)"#;
        assert!(matches(
            rule,
            HostObservation::Fim(&fim("/etc/passwd", FileChange::Modified))
        ));
        assert!(matches(
            rule,
            HostObservation::Fim(&fim("/etc/passwd", FileChange::Created))
        ));
        assert!(!matches(
            rule,
            HostObservation::Fim(&fim("/etc/passwd", FileChange::Deleted))
        ));
    }

    #[test]
    fn several_paths_can_be_listed() {
        let rule = r#"alert ip any any -> any any (msg:"m"; file.path:"/etc/passwd,/etc/shadow,/etc/sudoers"; sid:1000001;)"#;
        assert!(matches(
            rule,
            HostObservation::Fim(&fim("/etc/shadow", FileChange::Modified))
        ));
        assert!(!matches(
            rule,
            HostObservation::Fim(&fim("/etc/hosts", FileChange::Modified))
        ));
    }

    #[test]
    fn a_negated_condition_matches_when_it_does_not_hold() {
        let rule = r#"alert ip any any -> any any (msg:"m"; file.path:"/etc"; file.change:!"attributes_changed"; sid:1000001;)"#;
        assert!(matches(
            rule,
            HostObservation::Fim(&fim("/etc/x", FileChange::Modified))
        ));
        assert!(!matches(
            rule,
            HostObservation::Fim(&fim("/etc/x", FileChange::AttributesChanged))
        ));
    }

    // -----------------------------------------------------------------------
    // authentication
    // -----------------------------------------------------------------------

    #[test]
    fn an_auth_outcome_condition_matches_exactly() {
        let rule = r#"alert ip any any -> any any (msg:"m"; auth.outcome:"failure"; sid:1000010;)"#;
        assert!(matches(
            rule,
            HostObservation::Auth(&auth(AuthOutcome::Failure, Some("root"), None))
        ));
        assert!(!matches(
            rule,
            HostObservation::Auth(&auth(AuthOutcome::Success, Some("root"), None))
        ));
    }

    #[test]
    fn an_auth_user_condition_is_exact_not_a_substring() {
        // Matching `root` inside `chroot` would be a surprise nobody wrote.
        let rule = r#"alert ip any any -> any any (msg:"m"; auth.user:"root"; sid:1000010;)"#;
        assert!(matches(
            rule,
            HostObservation::Auth(&auth(AuthOutcome::Failure, Some("root"), None))
        ));
        assert!(!matches(
            rule,
            HostObservation::Auth(&auth(AuthOutcome::Failure, Some("chroot"), None))
        ));
    }

    #[test]
    fn a_regex_condition_matches_a_field() {
        let rule =
            r#"alert ip any any -> any any (msg:"m"; auth.user.pcre:"^svc_[a-z]+$"; sid:1000010;)"#;
        assert!(matches(
            rule,
            HostObservation::Auth(&auth(AuthOutcome::Failure, Some("svc_backup"), None))
        ));
        assert!(!matches(
            rule,
            HostObservation::Auth(&auth(AuthOutcome::Failure, Some("svc_1"), None))
        ));
    }

    #[test]
    fn a_missing_field_fails_the_condition_rather_than_passing_it() {
        let rule = r#"alert ip any any -> any any (msg:"m"; auth.source:"10.0.0.1"; sid:1000010;)"#;
        assert!(!matches(
            rule,
            HostObservation::Auth(&auth(AuthOutcome::Failure, Some("root"), None))
        ));
    }

    // -----------------------------------------------------------------------
    // processes
    // -----------------------------------------------------------------------

    #[test]
    fn a_process_rule_matches_a_new_listener() {
        let rule = r#"alert ip any any -> any any (msg:"m"; process.change:"listening"; process.name:"nc"; sid:1000020;)"#;
        assert!(matches(
            rule,
            HostObservation::Process(&process("nc", ProcessChange::Listening))
        ));
        assert!(!matches(
            rule,
            HostObservation::Process(&process("nc", ProcessChange::Started))
        ));
    }

    #[test]
    fn a_command_line_condition_matches_a_substring() {
        let rule =
            r#"alert ip any any -> any any (msg:"m"; process.cmdline:"-l -p"; sid:1000020;)"#;
        assert!(matches(
            rule,
            HostObservation::Process(&process("nc", ProcessChange::Started))
        ));
    }

    // -----------------------------------------------------------------------
    // selection and compilation
    // -----------------------------------------------------------------------

    #[test]
    fn candidates_are_selected_by_event_kind() {
        let (ruleset, _) = compile(&[
            r#"alert ip any any -> any any (msg:"f"; file.path:"/etc"; sid:1000001;)"#,
            r#"alert ip any any -> any any (msg:"a"; auth.outcome:"failure"; sid:1000002;)"#,
            r#"alert ip any any -> any any (msg:"p"; process.name:"nc"; sid:1000003;)"#,
        ]);
        assert_eq!(ruleset.candidates(HostEventKind::Fim).len(), 1);
        assert_eq!(ruleset.candidates(HostEventKind::Auth).len(), 1);
        assert_eq!(ruleset.candidates(HostEventKind::Process).len(), 1);

        let index = ruleset.candidates(HostEventKind::Auth)[0];
        assert_eq!(ruleset.rule(index).unwrap().sid, 1_000_002);
    }

    #[test]
    fn a_rule_mixing_event_kinds_is_refused() {
        // It could never match one record, and armed-and-silent is the worst
        // outcome a rule can have.
        let (ruleset, report) = compile(&[
            r#"alert ip any any -> any any (msg:"m"; file.path:"/etc"; auth.outcome:"failure"; sid:1000001;)"#,
        ]);
        assert!(ruleset.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert!(
            report.failed[0].reason.contains("could never match"),
            "{:?}",
            report.failed[0]
        );
    }

    #[test]
    fn a_network_condition_in_a_host_rule_is_refused() {
        let (_, report) = compile(&[
            r#"alert ip any any -> any any (msg:"m"; file.path:"/etc"; content:"x"; sid:1000001;)"#,
        ]);
        assert_eq!(report.failed.len(), 1);
        assert!(
            report.failed[0].reason.contains("not a host condition"),
            "{:?}",
            report.failed[0]
        );
    }

    #[test]
    fn flowbits_conditions_work_on_host_rules_too() {
        let (ruleset, _) = compile(&[
            r#"alert ip any any -> any any (msg:"m"; auth.outcome:"failure"; flowbits:isset,breached; sid:1000010;)"#,
        ]);
        let event = auth(AuthOutcome::Failure, Some("root"), None);
        let observation = HostObservation::Auth(&event);

        let mut bits = FlowBits::default();
        assert!(evaluate_host(&ruleset.rules()[0], &observation, &bits).is_none());
        bits.apply(&FlowBitsOp::Set("breached".into()), 8);
        assert!(evaluate_host(&ruleset.rules()[0], &observation, &bits).is_some());
    }

    #[test]
    fn the_threshold_subject_identifies_who_did_it() {
        let event = auth(AuthOutcome::Failure, Some("root"), Some("203.0.113.9"));
        assert_eq!(HostObservation::Auth(&event).subject(), "203.0.113.9");

        let event = fim("/etc/passwd", FileChange::Modified);
        assert_eq!(HostObservation::Fim(&event).subject(), "/etc/passwd");
    }
}
