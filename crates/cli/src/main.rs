//! The `cybersentinel` sensor binary.
//!
//! One standalone process per host. Phase 0 wires the foundations end to end —
//! config, rules, the event pipeline, and periodic `stats` events — so every
//! later phase plugs a stage into a pipeline that already exists and is already
//! observable.

mod pipeline;
mod run;

use clap::{Parser, Subcommand};

/// CyberSentinel-IPS — standalone host- and network-based intrusion detection.
#[derive(Debug, Parser)]
#[command(
    name = "cybersentinel",
    version,
    about,
    long_about = "CyberSentinel-IPS is a standalone intrusion detection sensor: host-based \
                  (file integrity, auth/log, process) and network-based monitoring in one \
                  self-contained binary, with no external prerequisites and no central server.\n\n\
                  Detection-only: it alerts, it does not block."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the sensor.
    Run(run::RunArgs),
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Run(args) => run::run(&args),
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // Diagnostics go to stderr; stdout is reserved for event JSON.
            eprintln!("cybersentinel: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_requires_a_config() {
        assert!(Cli::try_parse_from(["cybersentinel", "run"]).is_err());
        assert!(
            Cli::try_parse_from(["cybersentinel", "run", "--config", "config/config.yaml"]).is_ok()
        );
    }

    #[test]
    fn version_is_reported() {
        let rendered = Cli::command().render_version();
        assert!(
            rendered.contains(env!("CARGO_PKG_VERSION")),
            "got: {rendered}"
        );
    }
}
