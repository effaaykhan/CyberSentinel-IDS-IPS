//! The `config.yaml` loader.
//!
//! CyberSentinel's own configuration format (not a third-party engine's). Every
//! section has defaults, so a minimal file is valid; unknown keys are a hard
//! error, because a typo that silently disables an output or a sensor is a
//! failure mode this tool cannot afford.
//!
//! # Path resolution
//!
//! Relative paths are resolved against the process working directory, with two
//! conveniences:
//!
//! * `outputs.file.path`, if relative, is joined to `paths.log-dir`.
//! * each entry in `rules.files`, if relative, is joined to `rules.directory`.
//!
//! [`Config::load`] applies both, so everything downstream of the loader sees
//! resolved paths.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Top-level `config.yaml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct Config {
    /// Sensor identity.
    pub sensor: SensorConfig,
    /// Filesystem locations the sensor owns.
    pub paths: PathsConfig,
    /// Address and port variables referenced by rules (`$HOME_NET`, ...).
    pub vars: VarsConfig,
    /// Packet capture. Inert until Phase 1.
    pub capture: CaptureConfig,
    /// Which `.rules` files to load.
    pub rules: RulesConfig,
    /// Where events go.
    pub outputs: OutputsConfig,
    /// Diagnostic logging (distinct from event output).
    pub logging: LoggingConfig,
    /// Periodic `stats` events.
    pub stats: StatsConfig,
    /// Path this config was loaded from. Not part of the file format.
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
    /// Guard making [`Config::resolve_paths`] idempotent. Not part of the file
    /// format.
    #[serde(skip)]
    paths_resolved: bool,
}

/// Sensor identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct SensorConfig {
    /// Sensor name. `None` means "use the host name".
    pub name: Option<String>,
}

/// Filesystem locations the sensor owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct PathsConfig {
    /// Persistent state: the sensor id, and later the flow store and PCAP ring.
    pub data_dir: PathBuf,
    /// Event and diagnostic logs.
    pub log_dir: PathBuf,
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("data"),
            log_dir: PathBuf::from("logs"),
        }
    }
}

/// Address and port variables referenced by rule headers.
///
/// Values are kept as written; resolving them into address/port sets is Phase 3
/// work, alongside the rest of rule-header evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct VarsConfig {
    /// `$HOME_NET`, `$EXTERNAL_NET`, ...
    pub address_groups: BTreeMap<String, String>,
    /// `$HTTP_PORTS`, ...
    pub port_groups: BTreeMap<String, String>,
}

/// Packet capture settings. Read but unused until Phase 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct CaptureConfig {
    /// Enable network capture. Off by default: Phase 0 has no capture backend.
    pub enabled: bool,
    /// Interfaces to capture from. Empty means "pick the default route's".
    pub interfaces: Vec<String>,
    /// Bytes captured per packet.
    pub snaplen: u32,
    /// Put the interface in promiscuous mode.
    pub promiscuous: bool,
    /// Optional BPF filter applied at the capture socket.
    pub bpf_filter: Option<String>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interfaces: Vec::new(),
            snaplen: 65_535,
            promiscuous: true,
            bpf_filter: None,
        }
    }
}

/// Which `.rules` files to load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct RulesConfig {
    /// Base directory for relative entries in [`RulesConfig::files`].
    pub directory: PathBuf,
    /// Rule files, in load order.
    pub files: Vec<PathBuf>,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("rules"),
            files: vec![PathBuf::from("cybersentinel.rules")],
        }
    }
}

/// Event outputs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct OutputsConfig {
    /// Newline-delimited JSON on stdout.
    pub stdout: StdoutOutputConfig,
    /// Newline-delimited JSON to a file.
    pub file: FileOutputConfig,
    /// Syslog delivery. Phase 7.
    pub syslog: SyslogOutputConfig,
    /// Webhook delivery. Phase 7.
    pub webhook: WebhookOutputConfig,
}

/// Stdout event output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct StdoutOutputConfig {
    /// Enable the sink.
    pub enabled: bool,
}

impl Default for StdoutOutputConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// File event output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct FileOutputConfig {
    /// Enable the sink.
    pub enabled: bool,
    /// Destination file. Relative paths are joined to `paths.log-dir`.
    pub path: PathBuf,
}

impl Default for FileOutputConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: PathBuf::from("events.json"),
        }
    }
}

/// Syslog delivery. Accepted but inert until Phase 7.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct SyslogOutputConfig {
    /// Enable the sink.
    pub enabled: bool,
}

/// Webhook delivery. Accepted but inert until Phase 7.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct WebhookOutputConfig {
    /// Enable the sink.
    pub enabled: bool,
    /// Destination URL.
    pub url: Option<String>,
}

/// Diagnostic logging — the sensor talking about itself, not detection output.
///
/// Diagnostics go to stderr so stdout stays pure newline-delimited event JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// `error`, `warn`, `info`, `debug`, or `trace`.
    pub level: String,
    /// Depth of the event queue in front of the writer thread. Deeper absorbs
    /// longer sink stalls at the cost of memory; overflow drops events.
    pub queue_capacity: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            queue_capacity: 8_192,
        }
    }
}

/// Periodic `stats` events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct StatsConfig {
    /// Emit `stats` events.
    pub enabled: bool,
    /// Seconds between `stats` events.
    pub interval_secs: u64,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
        }
    }
}

impl Config {
    /// Read and parse a `config.yaml`, then resolve its relative paths.
    ///
    /// # Errors
    /// Returns [`Error::Io`] if the file cannot be read, [`Error::ConfigParse`]
    /// on malformed YAML or an unknown key, and [`Error::ConfigInvalid`] if a
    /// value is unusable.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| Error::io(path, source))?;
        let mut config = Self::from_yaml(&text).map_err(|source| Error::ConfigParse {
            path: path.to_path_buf(),
            source,
        })?;
        config.source_path = Some(path.to_path_buf());
        config.resolve_paths();
        config.check()?;
        Ok(config)
    }

    /// Parse a config from a YAML string, without path resolution.
    ///
    /// # Errors
    /// Any YAML or schema error.
    pub fn from_yaml(text: &str) -> std::result::Result<Self, serde_yaml::Error> {
        // An empty file is a valid config: every section defaults.
        if text.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_yaml::from_str(text)
    }

    /// Apply the documented relative-path rules in place.
    ///
    /// Idempotent: calling it again after [`Config::load`] will not stack path
    /// prefixes.
    pub fn resolve_paths(&mut self) {
        if std::mem::replace(&mut self.paths_resolved, true) {
            return;
        }
        if self.outputs.file.path.is_relative() {
            self.outputs.file.path = self.paths.log_dir.join(&self.outputs.file.path);
        }
        let directory = self.rules.directory.clone();
        for file in &mut self.rules.files {
            if file.is_relative() {
                *file = directory.join(&*file);
            }
        }
    }

    /// Reject values the sensor cannot act on.
    ///
    /// # Errors
    /// [`Error::ConfigInvalid`] with a message naming the offending key.
    pub fn check(&self) -> Result<()> {
        if self.logging.queue_capacity == 0 {
            return Err(Error::ConfigInvalid(
                "logging.queue-capacity must be at least 1".into(),
            ));
        }
        if self.stats.enabled && self.stats.interval_secs == 0 {
            return Err(Error::ConfigInvalid(
                "stats.interval-secs must be at least 1 when stats are enabled".into(),
            ));
        }
        if self.outputs.file.enabled && self.outputs.file.path.as_os_str().is_empty() {
            return Err(Error::ConfigInvalid(
                "outputs.file.path must be set when outputs.file.enabled is true".into(),
            ));
        }
        if self.outputs.webhook.enabled && self.outputs.webhook.url.is_none() {
            return Err(Error::ConfigInvalid(
                "outputs.webhook.url must be set when outputs.webhook.enabled is true".into(),
            ));
        }
        if self.capture.snaplen == 0 {
            return Err(Error::ConfigInvalid(
                "capture.snaplen must be at least 1".into(),
            ));
        }
        match self.logging.level.to_ascii_lowercase().as_str() {
            "error" | "warn" | "info" | "debug" | "trace" => {}
            other => {
                return Err(Error::ConfigInvalid(format!(
                    "logging.level must be one of error|warn|info|debug|trace, got {other:?}"
                )))
            }
        }
        Ok(())
    }

    /// Non-fatal problems worth telling the operator about.
    ///
    /// A sensor that starts up with no output, or with no rules, is running
    /// blind — but that is the operator's call, not a reason to refuse to start.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if !self.outputs.stdout.enabled
            && !self.outputs.file.enabled
            && !self.outputs.syslog.enabled
            && !self.outputs.webhook.enabled
        {
            warnings.push("no outputs are enabled: events will be produced and discarded".into());
        }
        if self.rules.files.is_empty() {
            warnings.push("rules.files is empty: no detection rules will be loaded".into());
        }
        if !self.vars.address_groups.contains_key("HOME_NET") {
            warnings.push(
                "vars.address-groups has no HOME_NET: rules referencing $HOME_NET will not load"
                    .into(),
            );
        }
        if self.outputs.syslog.enabled {
            warnings.push("outputs.syslog is enabled but not implemented until Phase 7".into());
        }
        if self.outputs.webhook.enabled {
            warnings.push("outputs.webhook is enabled but not implemented until Phase 7".into());
        }
        if self.capture.enabled {
            warnings.push("capture.enabled is true but packet capture lands in Phase 1".into());
        }
        warnings
    }

    /// Path of the persisted sensor id file.
    #[must_use]
    pub fn sensor_id_path(&self) -> PathBuf {
        self.paths.data_dir.join("sensor-id")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_config_is_all_defaults() {
        assert_eq!(Config::from_yaml("").unwrap(), Config::default());
        assert_eq!(Config::from_yaml("   \n\n").unwrap(), Config::default());
    }

    #[test]
    fn parses_a_full_config() {
        let yaml = r#"
sensor:
  name: edge-01
paths:
  data-dir: /var/lib/cybersentinel
  log-dir: /var/log/cybersentinel
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
capture:
  enabled: false
  interfaces: [eth0]
  snaplen: 1600
  promiscuous: false
  bpf-filter: "not port 22"
rules:
  directory: /etc/cybersentinel/rules
  files: [cybersentinel.rules, local.rules]
outputs:
  stdout:
    enabled: false
  file:
    enabled: true
    path: events.json
logging:
  level: debug
  queue-capacity: 1024
stats:
  enabled: true
  interval-secs: 5
"#;
        let mut config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.sensor.name.as_deref(), Some("edge-01"));
        assert_eq!(config.capture.snaplen, 1600);
        assert_eq!(config.capture.bpf_filter.as_deref(), Some("not port 22"));
        assert_eq!(
            config.vars.address_groups["HOME_NET"],
            "[192.168.0.0/16,10.0.0.0/8]"
        );
        assert_eq!(config.logging.queue_capacity, 1024);
        assert!(!config.outputs.stdout.enabled);

        config.resolve_paths();
        assert_eq!(
            config.outputs.file.path,
            PathBuf::from("/var/log/cybersentinel/events.json")
        );
        assert_eq!(
            config.rules.files,
            vec![
                PathBuf::from("/etc/cybersentinel/rules/cybersentinel.rules"),
                PathBuf::from("/etc/cybersentinel/rules/local.rules"),
            ]
        );
    }

    #[test]
    fn a_partial_config_keeps_defaults_for_the_rest() {
        let config = Config::from_yaml("stats:\n  interval-secs: 1\n").unwrap();
        assert_eq!(config.stats.interval_secs, 1);
        assert!(config.stats.enabled);
        assert_eq!(config.logging.queue_capacity, 8_192);
    }

    #[test]
    fn a_misspelled_key_is_an_error_not_a_silent_default() {
        // `enabled` misspelled must not silently leave the output on.
        let error = Config::from_yaml("outputs:\n  file:\n    enabeld: false\n").unwrap_err();
        assert!(error.to_string().contains("enabeld"), "got: {error}");
        // ... and neither must a misspelled section.
        assert!(Config::from_yaml("outputz:\n  stdout:\n    enabled: true\n").is_err());
    }

    #[test]
    fn absolute_output_paths_are_left_alone() {
        let mut config = Config::default();
        let absolute = if cfg!(windows) {
            PathBuf::from(r"C:\logs\events.json")
        } else {
            PathBuf::from("/logs/events.json")
        };
        config.outputs.file.path = absolute.clone();
        config.resolve_paths();
        assert_eq!(config.outputs.file.path, absolute);
    }

    #[test]
    fn resolve_paths_is_idempotent() {
        let mut config = Config::default();
        config.resolve_paths();
        let once = config.clone();
        assert_eq!(config.outputs.file.path, PathBuf::from("logs/events.json"));
        config.resolve_paths();
        assert_eq!(config, once, "resolving twice must not stack path prefixes");
    }

    #[test]
    fn check_rejects_unusable_values() {
        let mut config = Config::default();
        config.logging.queue_capacity = 0;
        assert!(config.check().is_err());

        let mut config = Config::default();
        config.stats.interval_secs = 0;
        assert!(config.check().is_err());

        let mut config = Config::default();
        config.logging.level = "chatty".into();
        assert!(config.check().is_err());

        let mut config = Config::default();
        config.outputs.webhook.enabled = true;
        assert!(config.check().is_err());

        assert!(Config::default().check().is_ok());
    }

    #[test]
    fn warns_when_the_sensor_would_run_blind() {
        let mut config = Config::default();
        config.outputs.stdout.enabled = false;
        config.outputs.file.enabled = false;
        let warnings = config.warnings();
        assert!(
            warnings.iter().any(|w| w.contains("no outputs")),
            "got: {warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("HOME_NET")),
            "got: {warnings:?}"
        );
    }

    #[test]
    fn relative_rule_files_are_joined_to_the_rules_directory() {
        let mut config = Config::default();
        config.rules.directory = PathBuf::from("rules");
        config.rules.files = vec![PathBuf::from("a.rules")];
        config.resolve_paths();
        assert_eq!(config.rules.files, vec![PathBuf::from("rules/a.rules")]);
    }
}
