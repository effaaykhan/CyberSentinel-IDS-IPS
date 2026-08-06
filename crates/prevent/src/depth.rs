//! What the kernel thinks of our queue.
//!
//! The sensor's own counters can only describe packets it *saw*. The number
//! that matters most under load is the one it never sees: packets the kernel
//! dropped because our queue was full and we were not draining it fast enough.
//! From inside the verdict loop that is indistinguishable from a quiet link —
//! the same ambiguity this project keeps designing against, one layer down.
//!
//! `/proc/net/netfilter/nfnetlink_queue` has it. One line per bound queue:
//!
//! ```text
//!   queue_num  peer_portid  queue_total  copy_mode  copy_range  queue_dropped  user_dropped  id_sequence  1
//!      17         12345          3           2        65535          0             0            4271      1
//! ```
//!
//! * `queue_total` — packets queued **right now**. The instantaneous depth, and
//!   the thing that grows before anything is dropped.
//! * `queue_dropped` — packets the kernel discarded because the queue was full.
//!   **This is the fail-mode path being taken.** With `bypass` they were
//!   accepted unexamined; without it they were dropped. Either way the sensor
//!   did not judge them, and either way it is a coverage hole.
//! * `user_dropped` — packets discarded because userspace could not be handed
//!   them: a netlink send buffer that filled, most often. Same consequence.
//!
//! Reading a proc file per stats interval is not on the fast path and costs
//! nothing that matters; not reading it means an operator finds out about a
//! saturated queue from a packet capture on some other machine.

/// One queue's counters, as the kernel reports them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueDepth {
    /// The queue this describes.
    pub queue_num: u16,
    /// Packets queued at this instant.
    pub queued: u32,
    /// Packets the kernel dropped because the queue was full.
    pub queue_dropped: u32,
    /// Packets dropped because they could not be delivered to userspace.
    pub user_dropped: u32,
    /// The kernel's running packet id, useful only for spotting a rebind.
    pub id_sequence: u32,
}

impl QueueDepth {
    /// Packets that never reached a verdict, for whatever reason.
    ///
    /// Both causes have the same consequence — the sensor did not judge the
    /// packet and the fail mode decided instead — so they are added rather than
    /// left for a reader to combine.
    #[must_use]
    pub fn unjudged(&self) -> u64 {
        u64::from(self.queue_dropped) + u64::from(self.user_dropped)
    }
}

/// Parse `/proc/net/netfilter/nfnetlink_queue`, returning the line for `queue`.
///
/// Total, like every other parser here: any input yields a value or nothing.
/// The file is kernel-generated, but a sensor that panicked on an unexpected
/// column count would be a sensor taken down by a kernel upgrade.
#[must_use]
pub fn parse(text: &str, queue: u16) -> Option<QueueDepth> {
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Nine columns today. Accepting "at least the ones we read" means a
        // kernel that adds a column does not take the reading away.
        if fields.len() < 7 {
            continue;
        }
        let Ok(queue_num) = fields[0].parse::<u16>() else {
            continue;
        };
        if queue_num != queue {
            continue;
        }
        return Some(QueueDepth {
            queue_num,
            queued: fields[2].parse().unwrap_or(0),
            queue_dropped: fields[5].parse().unwrap_or(0),
            user_dropped: fields[6].parse().unwrap_or(0),
            id_sequence: fields.get(7).and_then(|f| f.parse().ok()).unwrap_or(0),
        });
    }
    None
}

/// Read the counters for one queue from the running kernel.
#[cfg(target_os = "linux")]
#[must_use]
pub fn read(queue: u16) -> Option<QueueDepth> {
    let text = std::fs::read_to_string("/proc/net/netfilter/nfnetlink_queue").ok()?;
    parse(&text, queue)
}

/// Read the counters for one queue. Not available off Linux.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn read(_queue: u16) -> Option<QueueDepth> {
    None
}

// ---------------------------------------------------------------------------
// the netlink receive buffer
// ---------------------------------------------------------------------------

/// A netlink receive buffer below this is worth mentioning, not refusing.
///
/// The history is worth keeping, because the first diagnosis was wrong.
///
/// Measured on loopback with `iperf3`: copying **whole packets** to userspace
/// left 3,566 of ~283,000 packets `user_dropped` — never judged, and under
/// fail-open forwarded unexamined. The queue never went deeper than five of
/// 1024, so `queue-length` was never the constraint. Raising this buffer to
/// 8 MB took it to zero, which looked like the answer.
///
/// It was not the *cause*. Copying only the headers — which is all the verdict
/// path reads — takes it to zero at the **stock 208 KB buffer**, because the
/// bytes crossing netlink drop by three orders of magnitude. See
/// [`crate::queue::KernelQueue::set_header_only`].
///
/// So this stays as defence in depth: a bigger buffer absorbs bursts the copy
/// reduction does not, and a host running close to the edge is worth telling.
/// It is a warning, never a refusal to start.
pub const MIN_NETLINK_RECV_BUFFER: u64 = 4 * 1_024 * 1_024;

/// What the host's netlink receive buffer is set to.
///
/// `nfq` does not expose the socket, so this cannot be set from inside the
/// process — it is a host tuning value, and all the sensor can do is read it
/// and say whether it is big enough.
#[cfg(target_os = "linux")]
#[must_use]
pub fn netlink_recv_buffer() -> Option<u64> {
    std::fs::read_to_string("/proc/sys/net/core/rmem_default")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// What the host's netlink receive buffer is set to. Linux-only.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn netlink_recv_buffer() -> Option<u64> {
    None
}

/// Whether the buffer is large enough to judge every packet under load.
#[must_use]
pub fn buffer_is_adequate(bytes: u64) -> bool {
    bytes >= MIN_NETLINK_RECV_BUFFER
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "   17  12345     3 2 65535     0     0     4271  1\n\
                          \x20  18  12346  1024 2 65535   512    17    99999  1\n";

    #[test]
    fn reads_the_line_for_the_requested_queue() {
        let depth = parse(SAMPLE, 17).expect("queue 17");
        assert_eq!(depth.queued, 3);
        assert_eq!(depth.queue_dropped, 0);
        assert_eq!(depth.unjudged(), 0);
    }

    #[test]
    fn a_saturated_queue_reports_what_never_reached_a_verdict() {
        let depth = parse(SAMPLE, 18).expect("queue 18");
        assert_eq!(depth.queued, 1_024);
        assert_eq!(depth.queue_dropped, 512);
        assert_eq!(depth.user_dropped, 17);
        assert_eq!(
            depth.unjudged(),
            529,
            "both causes mean the fail mode decided instead of the sensor"
        );
    }

    #[test]
    fn an_unbound_queue_is_absent_rather_than_zero() {
        assert!(
            parse(SAMPLE, 99).is_none(),
            "reporting zeroes for a queue nobody bound would look like a healthy queue"
        );
        assert!(parse("", 17).is_none());
    }

    #[test]
    fn malformed_input_never_panics() {
        for text in [
            "",
            "garbage",
            "17",
            "17 1 2",
            "x y z a b c d e f",
            "17 1 2 3 4 5 6 7 8 9 10 11",
            &"9".repeat(10_000),
        ] {
            let _ = parse(text, 17);
        }
    }

    #[test]
    fn the_kernel_default_is_not_big_enough_for_inline_prevention() {
        // 208 KB is what a stock Linux ships with, and it left 1.3% of packets
        // unjudged under load. The constant exists so that is a startup error
        // rather than something an operator reads off a throughput graph.
        assert!(!buffer_is_adequate(212_992));
        assert!(buffer_is_adequate(8 * 1_024 * 1_024));
    }

    /// A kernel that adds a column must not take the reading away.
    #[test]
    fn extra_columns_are_tolerated() {
        let future = "17  12345  7 2 65535  1  2  4271  1  99  extra";
        let depth = parse(future, 17).expect("still readable");
        assert_eq!(depth.queued, 7);
        assert_eq!(depth.unjudged(), 3);
    }
}
