//! Inline prevention: turning detection into dropped packets.
//!
//! This is the crate that makes CyberSentinel an IPS rather than an IDS, and
//! the whole of it hangs on one design point.
//!
//! # The verdict path and the detection path are two different jobs
//!
//! Detection is **ACK-gated**. Reassembly holds bytes until the peer
//! acknowledges them, because that is the only way a target-based overlap
//! policy can be applied at all: a contradicting retransmission always arrives
//! before the ACK, so at the moment the sensor must choose which copy is real,
//! it still holds both. That costs about a round trip.
//!
//! Inline, a round trip is not available. NFQUEUE hands over a packet and the
//! kernel waits; holding it for an RTT while reassembly catches up would stall
//! the very connection under inspection, and a queue full of stalled packets is
//! an outage. So the two jobs are kept apart:
//!
//! * The **verdict path** — this crate — answers immediately, per packet, from
//!   state that already exists. It never reassembles, never matches, never
//!   waits. Default `Accept`.
//! * The **detection path** — everything already built — runs on its existing
//!   ACK-gated timeline, unchanged. When a rule with a block action matches, it
//!   *records a verdict*, which the verdict path then enforces on every later
//!   packet.
//!
//! # What that honestly buys, and what it does not
//!
//! Because matching needs reassembly, **the first packets carrying a brand-new
//! signature may pass before the match completes.** What inline prevention here
//! reliably does is drop the *rest of that flow* and every *subsequent
//! connection from the flagged source*.
//!
//! That is not a weakness of this implementation; it is inherent to any
//! reassembly-based IPS, and any product claiming otherwise is either not
//! reassembling or not telling you. The consequences are worth being blunt
//! about:
//!
//! * A single-packet exploit that fits entirely in the first segment **will
//!   land**. The session is then killed and the source blocked, which limits
//!   the follow-up but does not undo the first packet.
//! * An attack spread across several segments is cut mid-stream, which for
//!   most exploit deliveries means it fails.
//!
//! So `blocked` in an alert means *"the flow was terminated and the source
//! blocked from this point"* — not *"no byte of this attack reached the
//! target"*. The event schema says so, and so does CLAUDE.md.
//!
//! # Fail-open is not a code path
//!
//! The obvious reading of "fail open" is an error branch that returns `Accept`.
//! That is not where it lives. If the sensor process dies, no code of ours
//! runs at all — the **kernel** decides, based on how the queueing rule was
//! written. `queue num N` with no listener **drops**; `queue num N bypass`
//! accepts. Measured on a live host, not inferred.
//!
//! So the fail mode is a property of the nftables rule, and this crate's job is
//! to generate the rule that matches the configured mode and to refuse to let
//! the two disagree. See [`nft::queue_rule`].

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub mod nft;
pub mod queue;
pub mod store;

pub use store::{
    BlockOutcome, Decision, DropReason, FailMode, Mode, Prevention, PreventionSettings,
};
