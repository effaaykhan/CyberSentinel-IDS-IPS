//! The `validate-rules` subcommand.
//!
//! The running sensor deliberately loads what it can and reports the rest: a
//! sensor that refuses to start because one rule is broken is a sensor that is
//! watching nothing, which is the worse failure.
//!
//! That leaves a gap, though — nobody notices a warning in a log they do not
//! read. This closes it. `validate-rules` does the same load and the same
//! compilation, prints everything it found, and **exits non-zero if anything is
//! wrong**, so a CI or pre-deployment pipeline can gate on rule quality without
//! making production fragile.

use std::path::PathBuf;

use anyhow::{Context, Result};
use cybersentinel_common::config::Config;
use cybersentinel_rules::RuleSet;

/// Arguments to `cybersentinel validate-rules`.
#[derive(Debug, clap::Args)]
pub struct ValidateArgs {
    /// Path to config.yaml.
    #[arg(short, long, value_name = "PATH")]
    pub config: PathBuf,

    /// Print every rule that loaded, not only the problems.
    #[arg(long)]
    pub verbose: bool,
}

/// Load, compile, and report.
///
/// # Errors
/// If the config cannot be read, or any rule failed to load or compile.
pub fn validate(args: &ValidateArgs) -> Result<()> {
    let config = Config::load(&args.config)
        .with_context(|| format!("loading config {}", args.config.display()))?;

    let (rules, load) = RuleSet::load_files(&config.rules.files);
    let (engine, compile) = crate::run::build_engine(&config, &rules);

    println!("files:              {}", load.files.len());
    println!("rules loaded:       {}", load.loaded);
    println!("  armed:            {}", compile.compiled);
    println!("  awaiting support: {}", compile.not_evaluable);
    println!("  failed to compile:{}", compile.failed.len());
    println!("skipped:            {}", load.skipped.len());
    println!("no pre-filter:      {}", compile.without_prefilter);
    println!("needs HTTP parser:  {}", engine.needs_http());

    if !load.skipped.is_empty() {
        println!("\nskipped:");
        for skipped in &load.skipped {
            println!(
                "  {}:{} — {}",
                skipped.file.display(),
                skipped.line,
                skipped.reason
            );
        }
    }

    if !compile.failed.is_empty() {
        println!("\nfailed to compile:");
        for failure in &compile.failed {
            println!(
                "  sid {} at {} — {}",
                failure.sid, failure.origin, failure.reason
            );
        }
    }

    if compile.not_evaluable > 0 {
        println!(
            "\n{} rule(s) use keywords this build cannot evaluate yet. They load and are \
             counted, but they will not fire.",
            compile.not_evaluable
        );
    }

    if args.verbose {
        println!("\narmed rules:");
        for rule in engine.ruleset().rules() {
            println!("  sid {} [{}] {}", rule.sid, rule.origin, rule.msg);
        }
    }

    let problems = load.skipped.len() + compile.failed.len();
    if problems > 0 {
        anyhow::bail!("{problems} rule problem(s) found");
    }

    println!("\nOK — {} rule(s) armed, no problems.", compile.compiled);
    Ok(())
}
