//! The nftables side: the queueing rule, and the block set.
//!
//! # Fail-open is a property of the rule, not of this program
//!
//! The tempting model is an error branch somewhere in the verdict path that
//! returns `Accept` when things go wrong. That model is wrong in the case that
//! matters most: if the sensor process has died, **none of its code runs**, and
//! nothing it might have decided is relevant. The kernel disposes of the queued
//! packet on its own, and what it does is decided by how the queueing rule was
//! written:
//!
//! | Rule | No listener bound | Queue full |
//! |---|---|---|
//! | `queue num 0` | packets **dropped** | packets **dropped** |
//! | `queue num 0 bypass` | packets **accepted** | packets **accepted** |
//!
//! Measured on a live host, not inferred from documentation: with no listener,
//! a plain `queue` rule gave 100% packet loss and the same rule with `bypass`
//! passed everything.
//!
//! So [`queue_rule`] generates the rule that matches the configured fail mode,
//! and the sensor logs which one is active at startup. The failure this guards
//! against is an operator configuring `fail_mode: open`, writing the rule by
//! hand without `bypass`, and discovering during an outage that their IPS is
//! fail-closed.
//!
//! # Why shelling out to `nft`
//!
//! Managing the set through netlink directly would be faster and would avoid a
//! subprocess. It would also mean hand-rolling nftables netlink messages, which
//! is a great deal of attack surface for an operation that happens once per
//! blocked source rather than once per packet. `nft` is present wherever
//! nftables is, its arguments here are fully constructed by this code with no
//! operator string interpolated, and a missing binary degrades to "the set is
//! not updated", which is reported rather than silent.

use crate::store::FailMode;
use std::net::IpAddr;
use std::time::Duration;

/// The table the sensor owns. Its own, so removing it cannot disturb anything
/// else an operator has configured.
pub const TABLE: &str = "cybersentinel";
/// The set of blocked sources.
pub const BLOCKED_SET_V4: &str = "blocked_v4";
/// The set of blocked sources, v6.
pub const BLOCKED_SET_V6: &str = "blocked_v6";

/// The `queue` statement for a fail mode.
///
/// This is the whole of the fail-open mechanism, and it is three words long.
#[must_use]
pub fn queue_statement(queue: u16, fail_mode: FailMode) -> String {
    match fail_mode {
        // `bypass` tells the kernel to accept rather than drop when no
        // userspace program is listening, or when the queue is full.
        FailMode::Open => format!("queue num {queue} bypass"),
        FailMode::Closed => format!("queue num {queue}"),
    }
}

/// A complete, copy-pasteable ruleset for the configured mode.
///
/// Emitted into the log at startup rather than applied automatically. Taking a
/// machine's traffic into userspace is not something a sensor should do to an
/// operator by surprise on first start — and an inline rule installed wrongly
/// is an outage, so the operator gets to read it first.
#[must_use]
pub fn queue_rule(queue: u16, fail_mode: FailMode) -> String {
    let statement = queue_statement(queue, fail_mode);
    format!(
        "table inet {TABLE} {{\n  \
           set {BLOCKED_SET_V4} {{ type ipv4_addr; flags timeout; }}\n  \
           set {BLOCKED_SET_V6} {{ type ipv6_addr; flags timeout; }}\n  \
           chain forward {{\n    \
             type filter hook forward priority 0; policy accept;\n    \
             ip saddr @{BLOCKED_SET_V4} drop\n    \
             ip6 saddr @{BLOCKED_SET_V6} drop\n    \
             {statement}\n  \
           }}\n\
         }}"
    )
}

/// What happened when the block set was updated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetOutcome {
    /// The address is now in the kernel's set.
    Added,
    /// `nft` is not available. The in-process verdict store still drops the
    /// traffic; what is lost is the cheap kernel-side drop for *new*
    /// connections, so this is a degradation rather than a failure.
    Unavailable(String),
    /// `nft` ran and refused.
    Failed(String),
}

/// The `nft` arguments for adding one address to the block set.
///
/// Split out from running it so the command can be asserted in a test without
/// a kernel: the risk in shelling out is not that the command fails, it is that
/// it silently does something other than intended.
#[must_use]
pub fn add_element_args(address: IpAddr, timeout: Duration) -> Vec<String> {
    let (set, literal) = match address {
        IpAddr::V4(v4) => (BLOCKED_SET_V4, v4.to_string()),
        IpAddr::V6(v6) => (BLOCKED_SET_V6, v6.to_string()),
    };
    vec![
        "add".to_string(),
        "element".to_string(),
        "inet".to_string(),
        TABLE.to_string(),
        set.to_string(),
        // The address is rendered from a parsed `IpAddr`, never from operator
        // or attacker text, so there is nothing here that could carry shell
        // syntax — and `nft` is executed directly rather than through a shell
        // in any case.
        format!("{{ {literal} timeout {}s }}", timeout.as_secs()),
    ]
}

/// Add an address to the kernel's block set.
#[cfg(target_os = "linux")]
#[must_use]
pub fn add_blocked_source(address: IpAddr, timeout: Duration) -> SetOutcome {
    let args = add_element_args(address, timeout);
    match std::process::Command::new("nft").args(&args).output() {
        Ok(output) if output.status.success() => SetOutcome::Added,
        Ok(output) => {
            SetOutcome::Failed(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
        Err(error) => SetOutcome::Unavailable(error.to_string()),
    }
}

/// Add an address to the kernel's block set. Not available off Linux.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn add_blocked_source(_address: IpAddr, _timeout: Duration) -> SetOutcome {
    SetOutcome::Unavailable("nftables is Linux-only".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three words the whole fail-open promise rests on.
    #[test]
    fn fail_open_puts_bypass_in_the_rule_and_fail_closed_does_not() {
        assert_eq!(queue_statement(0, FailMode::Open), "queue num 0 bypass");
        assert_eq!(queue_statement(0, FailMode::Closed), "queue num 0");
    }

    #[test]
    fn the_generated_ruleset_matches_the_fail_mode() {
        let open = queue_rule(3, FailMode::Open);
        assert!(open.contains("queue num 3 bypass"));

        let closed = queue_rule(3, FailMode::Closed);
        assert!(closed.contains("queue num 3"));
        assert!(
            !closed.contains("bypass"),
            "a fail-closed ruleset containing bypass would be fail-open in practice"
        );
    }

    /// The kernel-side drop has to come *before* the queue statement, or every
    /// packet from an already-blocked source takes a trip through userspace.
    #[test]
    fn the_block_set_is_checked_before_packets_are_queued() {
        let rule = queue_rule(0, FailMode::Open);
        let set_drop = rule.find("@blocked_v4").expect("the set is used");
        let queue = rule.find("queue num").expect("the queue statement");
        assert!(
            set_drop < queue,
            "a blocked source should be dropped by the kernel, not queued to userspace"
        );
    }

    #[test]
    fn the_ruleset_declares_both_address_families() {
        let rule = queue_rule(0, FailMode::Open);
        assert!(rule.contains("type ipv4_addr"));
        assert!(rule.contains("type ipv6_addr"));
        assert!(
            rule.contains("flags timeout"),
            "a set without timeouts would block sources for ever"
        );
    }

    #[test]
    fn adding_a_v4_address_targets_the_v4_set() {
        let args = add_element_args(
            "203.0.113.7".parse().expect("an address"),
            Duration::from_secs(600),
        );
        assert_eq!(args[4], BLOCKED_SET_V4);
        assert!(args[5].contains("203.0.113.7"));
        assert!(args[5].contains("timeout 600s"));
    }

    #[test]
    fn adding_a_v6_address_targets_the_v6_set() {
        let args = add_element_args(
            "2001:db8::1".parse().expect("an address"),
            Duration::from_secs(60),
        );
        assert_eq!(args[4], BLOCKED_SET_V6);
        assert!(args[5].contains("2001:db8::1"));
    }

    /// Every argument is built from a parsed `IpAddr`, so there is no operator
    /// or attacker text in the command at all.
    #[test]
    fn the_command_contains_nothing_but_the_address_and_the_timeout() {
        let args = add_element_args(
            "203.0.113.7".parse().expect("an address"),
            Duration::from_secs(1),
        );
        assert_eq!(args[..5], ["add", "element", "inet", TABLE, BLOCKED_SET_V4]);
        assert_eq!(args.len(), 6);
    }
}
