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
use crate::net::IpNetwork;

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
    /// Packet capture.
    pub capture: CaptureConfig,
    /// Packet decoding.
    pub decode: DecodeConfig,
    /// Flow tracking.
    pub flow: FlowConfig,
    /// IP defragmentation and TCP stream reassembly.
    pub reassembly: ReassemblyConfig,
    /// URI and path normalization.
    pub normalize: NormalizeConfig,
    /// The detection engine.
    pub detect: DetectConfig,
    /// Which `.rules` files to load.
    pub rules: RulesConfig,
    /// Host-based monitoring: FIM, authentication logs, processes.
    pub hids: HidsConfig,
    /// Joining host and network evidence into incidents.
    pub correlation: CorrelationConfig,
    /// Inline prevention. **Off by default.**
    pub prevent: PreventConfig,
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

/// Packet capture settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct CaptureConfig {
    /// Enable live network capture.
    ///
    /// Off by default: a sensor should start capturing because someone chose
    /// to, and live capture needs privileges that a first run may not have.
    /// `cybersentinel run --replay <file>` needs neither.
    pub enabled: bool,
    /// Interfaces to capture from. Empty means "ask libpcap for the default".
    ///
    /// Phase 1 captures from one interface; further entries are ignored with a
    /// warning until multi-interface capture lands.
    pub interfaces: Vec<String>,
    /// Bytes captured per packet. 65535 keeps whole packets, which is what
    /// content matching needs.
    pub snaplen: u32,
    /// Put the interface in promiscuous mode.
    pub promiscuous: bool,
    /// Optional BPF filter applied in the kernel, before the sensor sees
    /// anything. **Traffic excluded here is invisible to detection.**
    pub bpf_filter: Option<String>,
    /// Kernel capture buffer size in bytes. `null` uses libpcap's default.
    ///
    /// The first thing to raise when `stats.capture.drops` is non-zero.
    pub buffer_size_bytes: Option<i32>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interfaces: Vec::new(),
            snaplen: 65_535,
            promiscuous: true,
            bpf_filter: None,
            buffer_size_bytes: None,
        }
    }
}

/// Packet decoding settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct DecodeConfig {
    /// Emit an `anomaly` event for each malformed packet.
    ///
    /// Malformed packets are detection signal, so this defaults on. On a link
    /// with a chatty broken device it can be loud; turning it off keeps the
    /// counters in `stats.decode` either way.
    pub emit_anomaly_events: bool,
}

impl Default for DecodeConfig {
    fn default() -> Self {
        Self {
            emit_anomaly_events: true,
        }
    }
}

/// Flow-tracking settings.
///
/// These are the bounds on flow state (guide §6). They are configuration rather
/// than constants because the right ceiling depends on the link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct FlowConfig {
    /// Maximum concurrently tracked flows.
    ///
    /// A hard cap: past it, live flows are evicted and counted in
    /// `stats.flows.evicted`. Sized so an attacker opening flows cannot grow
    /// sensor memory without limit.
    pub max_flows: usize,
    /// Seconds of idleness after which a flow is considered over.
    pub timeout_secs: u64,
    /// Emit a `flow` event when a flow ends.
    ///
    /// One event per conversation is a lot of volume on a busy link. It
    /// defaults on because flow records are Phase 1's primary output; turn it
    /// off to keep only alerts and stats.
    pub emit_events: bool,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            max_flows: 65_536,
            timeout_secs: 300,
            emit_events: true,
        }
    }
}

/// How to resolve overlapping TCP segments or IP fragments whose data
/// **disagrees**.
///
/// This is the evasion-resistance decision (guide §6). When two copies of the
/// same byte range arrive with different contents, the sensor has to pick one —
/// and it must pick the same one the *destination host* will, or an attacker
/// can put one payload in front of the sensor and a different one in front of
/// the host.
///
/// The policy is **configured, not detected**: OS fingerprinting to guess a
/// stack's behaviour is itself evadable, and a wrong guess fails silently. An
/// operator who knows their network states what is on it.
///
/// Extensible on purpose — OS-family policies (`bsd`, `solaris`, ...) are the
/// obvious next entries, and adding one must not be a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum OverlapPolicy {
    /// The data received **first** wins. Linux and most BSDs.
    #[default]
    First,
    /// The data received **last** wins. Older Windows stacks.
    Last,
}

impl OverlapPolicy {
    /// Stable identifier used in config and logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Last => "last",
        }
    }
}

impl std::fmt::Display for OverlapPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An overlap-policy override for one network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HostPolicy {
    /// The network this applies to, in CIDR form. A bare address is one host.
    pub network: IpNetwork,
    /// The policy to use for hosts in it.
    pub policy: OverlapPolicy,
}

/// IP defragmentation and TCP stream reassembly.
///
/// Everything here is either an evasion-resistance decision or a hard bound on
/// state. Both matter more than they look: get the first wrong and attacks pass
/// silently, get the second wrong and the sensor is a memory-exhaustion target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct ReassemblyConfig {
    /// Policy for hosts with no more specific entry in
    /// [`ReassemblyConfig::host_policies`].
    pub overlap_policy: OverlapPolicy,

    /// Per-network overrides, matched against the **destination** of the data —
    /// the host whose stack decides what the bytes mean.
    ///
    /// Longest prefix wins, so a `/32` beats a `/24` regardless of order in the
    /// file. Overlapping entries of the same length are a config error rather
    /// than a silent first-wins.
    pub host_policies: Vec<HostPolicy>,

    /// Maximum concurrent in-progress IP fragment reassemblies.
    pub max_fragment_sets: usize,
    /// Maximum bytes held across all in-progress fragment reassemblies.
    pub max_fragment_bytes_total: usize,
    /// Seconds after which an incomplete fragment set is discarded.
    ///
    /// A datagram whose fragments never all arrive is either a broken path or
    /// an attempt to pin memory; either way it must not be held forever.
    pub fragment_timeout_secs: u64,

    /// Maximum bytes buffered per flow direction awaiting reassembly.
    pub max_stream_bytes_per_flow: usize,
    /// Maximum bytes buffered across every flow direction.
    pub max_stream_bytes_total: usize,

    /// Deliver un-acknowledged data once this many bytes have buffered.
    ///
    /// Reassembled bytes are normally held until the peer acknowledges them,
    /// which is what makes overlap policy meaningful: a retransmission that
    /// contradicts earlier data always arrives before the ACK, so the policy
    /// still has both copies to choose between. On a path where the reverse
    /// direction is not visible — asymmetric routing, a one-way tap — no ACK
    /// ever arrives, so this is the fallback that keeps matching working.
    pub delivery_flush_bytes: usize,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            overlap_policy: OverlapPolicy::First,
            host_policies: Vec::new(),
            max_fragment_sets: 4_096,
            max_fragment_bytes_total: 32 << 20,
            fragment_timeout_secs: 60,
            max_stream_bytes_per_flow: 1 << 20,
            max_stream_bytes_total: 256 << 20,
            delivery_flush_bytes: 64 << 10,
        }
    }
}

impl ReassemblyConfig {
    /// Reject values the reassembler cannot act on.
    ///
    /// # Errors
    /// [`Error::ConfigInvalid`] naming the offending key.
    pub fn check(&self) -> Result<()> {
        if self.max_fragment_sets == 0 {
            return Err(Error::ConfigInvalid(
                "reassembly.max-fragment-sets must be at least 1".into(),
            ));
        }
        if self.fragment_timeout_secs == 0 {
            return Err(Error::ConfigInvalid(
                "reassembly.fragment-timeout-secs must be at least 1".into(),
            ));
        }
        if self.max_stream_bytes_per_flow == 0 {
            return Err(Error::ConfigInvalid(
                "reassembly.max-stream-bytes-per-flow must be at least 1".into(),
            ));
        }
        if self.max_stream_bytes_total < self.max_stream_bytes_per_flow {
            return Err(Error::ConfigInvalid(
                "reassembly.max-stream-bytes-total must be at least \
                 reassembly.max-stream-bytes-per-flow, or no single flow could ever \
                 reach its own limit"
                    .into(),
            ));
        }
        if self.delivery_flush_bytes == 0 {
            return Err(Error::ConfigInvalid(
                "reassembly.delivery-flush-bytes must be at least 1".into(),
            ));
        }
        if self.delivery_flush_bytes > self.max_stream_bytes_per_flow {
            return Err(Error::ConfigInvalid(
                "reassembly.delivery-flush-bytes must not exceed \
                 reassembly.max-stream-bytes-per-flow, or the per-flow cap would be hit \
                 before un-acknowledged data was ever flushed"
                    .into(),
            ));
        }

        // Two entries for the same network are ambiguous, and picking one
        // silently would leave an operator believing the other applied.
        let mut seen = std::collections::BTreeSet::new();
        for entry in &self.host_policies {
            if !seen.insert(entry.network.to_string()) {
                return Err(Error::ConfigInvalid(format!(
                    "reassembly.host-policies lists {} more than once",
                    entry.network
                )));
            }
        }
        Ok(())
    }
}

/// URI and path normalization.
///
/// These are target-behaviour decisions, like the overlap policy: they say what
/// the *server* will make of a request, and a sensor that reads it differently
/// is looking at something the server never saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct NormalizeConfig {
    /// Percent-decoding passes.
    ///
    /// Two catches ordinary double encoding. Capped rather than repeated to a
    /// fixed point, because an input can always be encoded one level deeper
    /// than any limit and unbounded work per request is a denial of service.
    pub decode_rounds: usize,
    /// Resolve `.` and `..` segments.
    pub collapse_path: bool,
    /// Treat `\` as a path separator, as Windows-hosted servers do.
    pub backslash_is_separator: bool,
}

impl Default for NormalizeConfig {
    fn default() -> Self {
        Self {
            decode_rounds: 2,
            collapse_path: true,
            backslash_is_separator: false,
        }
    }
}

/// The detection engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct DetectConfig {
    /// Run detection at all. Off means rules load and report but never fire.
    pub enabled: bool,
    /// Byte budget for one compiled regex program.
    ///
    /// Linear-time matching does not make *compilation* free. A rule whose
    /// `pcre` needs more than this is refused at load and reported, rather
    /// than costing megabytes per rule.
    pub regex_size_limit: usize,
    /// Byte budget for one regex's lazy DFA cache.
    pub regex_dfa_size_limit: usize,
    /// Flows that may carry detection state at once.
    pub max_flow_states: usize,
    /// Flowbits one flow may hold.
    pub max_flowbits_per_flow: usize,
    /// Reassembled bytes kept per direction for matching.
    ///
    /// The longest content match that can ever fire on a stream: a pattern that
    /// never sits in the window whole cannot be found.
    pub inspection_window: usize,
    /// Threshold counters held at once.
    pub max_threshold_entries: usize,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            regex_size_limit: 1 << 20,
            regex_dfa_size_limit: 1 << 20,
            max_flow_states: 65_536,
            max_flowbits_per_flow: 64,
            inspection_window: 64 << 10,
            max_threshold_entries: 65_536,
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

/// Inline prevention.
///
/// Every default here is the safe one: prevention off, and fail-open if it is
/// ever switched on. Turning a detection sensor into something that drops
/// traffic is a decision an operator makes deliberately, and the shape of this
/// section is meant to make it hard to do by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct PreventConfig {
    /// Run the verdict path at all.
    pub enabled: bool,
    /// `detect` or `prevent`. **The arming control**, and the kill switch.
    ///
    /// `detect` is the default and behaves exactly like the IDS: rules with a
    /// `drop` action still alert, and nothing is ever dropped.
    pub mode: String,
    /// What the **kernel** does when the sensor is not answering: `open` or
    /// `closed`.
    ///
    /// Not a branch in the sensor — if the process is dead, none of its code
    /// runs. This value decides whether the generated nftables rule carries
    /// `bypass`, and the sensor logs the rule it expects at startup.
    pub fail_mode: String,
    /// The netfilter queue number to bind.
    pub queue: u16,
    /// How many packets the kernel holds for us before applying the fail mode.
    pub queue_length: u32,
    /// Addresses and networks that must **never** be blocked, whatever
    /// matches: gateways, DNS resolvers, the management network, the host you
    /// administer this box from.
    ///
    /// Checked before any verdict and on **both** endpoints, because cutting
    /// the flow to a critical host breaks it exactly as thoroughly as blocking
    /// that host's own traffic.
    pub allow_list: Vec<String>,
    /// How long a blocked source stays blocked, in seconds.
    pub source_block_secs: u64,
    /// Most flows carrying a block verdict at once.
    pub max_blocked_flows: usize,
    /// Most sources blocked at once.
    pub max_blocked_sources: usize,
}

impl Default for PreventConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "detect".to_string(),
            fail_mode: "open".to_string(),
            queue: 0,
            queue_length: 1_024,
            allow_list: Vec::new(),
            source_block_secs: 600,
            max_blocked_flows: 65_536,
            max_blocked_sources: 16_384,
        }
    }
}

/// Host-based monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct HidsConfig {
    /// Run host monitoring at all.
    pub enabled: bool,
    /// File integrity monitoring.
    pub fim: FimConfig,
    /// Authentication log sources.
    pub auth: AuthConfig,
    /// Process and listening-socket monitoring.
    pub process: ProcessConfig,
}

impl Default for HidsConfig {
    fn default() -> Self {
        Self {
            // On by default: a host sensor that ships switched off is a host
            // sensor nobody turns on.
            enabled: true,
            fim: FimConfig::default(),
            auth: AuthConfig::default(),
            process: ProcessConfig::default(),
        }
    }
}

/// File integrity monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct FimConfig {
    /// Watch files at all.
    pub enabled: bool,
    /// The critical paths to monitor.
    ///
    /// Deliberately a short list rather than the whole filesystem: every
    /// watched directory consumes one of the kernel's finite
    /// `max_user_watches`, and a sensor that exhausts them degrades the host it
    /// is supposed to protect.
    pub paths: Vec<PathBuf>,
    /// Where the hash baseline lives, relative to [`PathsConfig::data_dir`].
    pub baseline: PathBuf,
    /// Seconds between baseline rescans.
    ///
    /// The rescan is what catches changes made while the sensor was down and
    /// changes lost to a queue overflow, so this is a **detection-latency**
    /// setting, not a performance knob.
    pub rescan_interval_secs: u64,
    /// Largest file hashed. Bigger files are tracked by size and metadata.
    pub max_file_bytes: u64,
    /// Deepest directory nesting walked below a configured path.
    pub max_depth: usize,
    /// Most files tracked across all configured paths.
    pub max_entries: usize,
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // The files that decide who can log in and what runs as root.
            paths: vec![
                PathBuf::from("/etc"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/sbin"),
                PathBuf::from("/bin"),
                PathBuf::from("/sbin"),
            ],
            baseline: PathBuf::from("fim-baseline.db"),
            rescan_interval_secs: 3_600,
            max_file_bytes: 64 * 1_024 * 1_024,
            max_depth: 16,
            max_entries: 50_000,
        }
    }
}

/// Authentication log sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Read authentication records at all.
    pub enabled: bool,
    /// Follow journald, via `journalctl`.
    ///
    /// Preferred over a log file: journald records carry the service as a
    /// structured field, so a message cannot claim to have come from `sshd`.
    pub journald: bool,
    /// Syslog-format files to follow, for hosts without journald.
    pub files: Vec<PathBuf>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            journald: true,
            // Debian and RHEL name it differently; a file that is not there is
            // not an error, so listing both is the portable default.
            files: vec![
                PathBuf::from("/var/log/auth.log"),
                PathBuf::from("/var/log/secure"),
            ],
        }
    }
}

/// Process and listening-socket monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct ProcessConfig {
    /// Sweep `/proc` at all.
    pub enabled: bool,
    /// Where `/proc` is mounted.
    ///
    /// Configurable because a sensor in a container is often given the host's
    /// `/proc` at another path, and because it makes the whole reader testable
    /// against a fixture tree.
    pub proc_root: PathBuf,
    /// Seconds between sweeps.
    ///
    /// A poller cannot see a process that starts and exits between sweeps.
    /// Shorter is more thorough and more expensive; this is the trade.
    pub interval_secs: u64,
    /// Most processes tracked in one sweep.
    pub max_processes: usize,
    /// Most listening sockets tracked in one sweep.
    pub max_sockets: usize,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proc_root: PathBuf::from("/proc"),
            interval_secs: 5,
            max_processes: 16_384,
            max_sockets: 8_192,
        }
    }
}

/// Joining host and network evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct CorrelationConfig {
    /// Emit `incident` events.
    pub enabled: bool,
    /// How far apart two events can be and still be one incident.
    pub window_secs: u64,
    /// Quiet period after an incident on a host, so sustained activity is one
    /// incident rather than a stream of them.
    pub cooldown_secs: u64,
    /// Most hosts tracked at once.
    pub max_hosts: usize,
    /// Most observations retained per host.
    pub max_per_host: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_secs: 120,
            cooldown_secs: 300,
            max_hosts: 1_024,
            max_per_host: 256,
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
        if self.hids.fim.baseline.is_relative() {
            self.hids.fim.baseline = self.paths.data_dir.join(&self.hids.fim.baseline);
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
        if self.flow.max_flows == 0 {
            return Err(Error::ConfigInvalid(
                "flow.max-flows must be at least 1".into(),
            ));
        }
        if self.flow.timeout_secs == 0 {
            return Err(Error::ConfigInvalid(
                "flow.timeout-secs must be at least 1".into(),
            ));
        }
        self.reassembly.check()?;
        // A zero rescan interval would mean a rescan on every poll: the sensor
        // would spend its life hashing and never service anything else.
        if self.hids.fim.enabled && self.hids.fim.rescan_interval_secs == 0 {
            return Err(Error::ConfigInvalid(
                "hids.fim.rescan-interval-secs must be at least 1 when FIM is enabled".into(),
            ));
        }
        if self.hids.fim.enabled && self.hids.fim.max_entries == 0 {
            return Err(Error::ConfigInvalid(
                "hids.fim.max-entries must be at least 1 when FIM is enabled".into(),
            ));
        }
        if self.hids.process.enabled && self.hids.process.interval_secs == 0 {
            return Err(Error::ConfigInvalid(
                "hids.process.interval-secs must be at least 1 when process monitoring is enabled"
                    .into(),
            ));
        }
        // Prevention's values are checked strictly: a typo in the mode is the
        // difference between a sensor that drops traffic and one that does
        // not, and defaulting a misspelling to either answer would be wrong.
        if !matches!(self.prevent.mode.as_str(), "detect" | "prevent") {
            return Err(Error::ConfigInvalid(format!(
                "prevent.mode must be `detect` or `prevent`, not {:?}",
                self.prevent.mode
            )));
        }
        if !matches!(self.prevent.fail_mode.as_str(), "open" | "closed") {
            return Err(Error::ConfigInvalid(format!(
                "prevent.fail-mode must be `open` or `closed`, not {:?}",
                self.prevent.fail_mode
            )));
        }
        for entry in &self.prevent.allow_list {
            if entry.parse::<IpNetwork>().is_err() {
                return Err(Error::ConfigInvalid(format!(
                    "prevent.allow-list entry {entry:?} is not an address or network"
                )));
            }
        }
        if self.prevent.enabled && self.prevent.source_block_secs == 0 {
            return Err(Error::ConfigInvalid(
                "prevent.source-block-secs must be at least 1: a zero-length block blocks nothing"
                    .into(),
            ));
        }

        // A zero window correlates nothing, which is a silently disabled
        // feature rather than a configured one.
        if self.correlation.enabled && self.correlation.window_secs == 0 {
            return Err(Error::ConfigInvalid(
                "correlation.window-secs must be at least 1 when correlation is enabled".into(),
            ));
        }
        if self.detect.inspection_window == 0 {
            return Err(Error::ConfigInvalid(
                "detect.inspection-window must be at least 1".into(),
            ));
        }
        if self.detect.max_flow_states == 0 {
            return Err(Error::ConfigInvalid(
                "detect.max-flow-states must be at least 1".into(),
            ));
        }
        if self.normalize.decode_rounds > 8 {
            return Err(Error::ConfigInvalid(
                "normalize.decode-rounds above 8 is a denial of service, not a setting".into(),
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
        if self.capture.snaplen < 1_518 {
            warnings.push(format!(
                "capture.snaplen is {}: packets will be clipped, and content past the \
                 snap length cannot be matched",
                self.capture.snaplen
            ));
        }
        if self.capture.bpf_filter.is_some() {
            warnings.push(
                "capture.bpf-filter is set: traffic it excludes is invisible to detection".into(),
            );
        }
        if !self.detect.enabled {
            warnings.push(
                "detect.enabled is false: rules will load and report, but nothing will fire".into(),
            );
        }
        if self.capture.interfaces.len() > 1 {
            warnings.push(format!(
                "capture.interfaces lists {} interfaces; this build captures from the first only",
                self.capture.interfaces.len()
            ));
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
