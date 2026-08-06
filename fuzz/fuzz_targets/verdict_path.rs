//! Fuzz the inline verdict path: arbitrary packet bytes → a verdict.
//!
//! This is the one code path in the project that can take a network down. It
//! runs on every packet, in-path, with the kernel waiting; a panic here is not
//! a crashed sensor but a stalled queue, and past the queue's bound that means
//! the fail mode applies to production traffic.
//!
//! The bytes are whatever arrived on the wire, so they are attacker-controlled
//! in the strongest sense available. Properties asserted:
//!
//! * **Totality.** Any bytes produce a tuple or nothing, never a panic.
//! * **Default accept.** With nothing blocked, nothing is ever dropped —
//!   whatever the packet looks like.
//! * **Detect mode never drops.** The kill switch holds against arbitrary
//!   input, which is the property an operator relies on when they disarm.
//! * **The allow-list is absolute.** A packet whose source or destination is
//!   allow-listed is accepted, no matter what has been blocked.

#![no_main]

use cybersentinel_prevent::queue::{judge, tuple_from_ip_packet, QueuedPacket};
use cybersentinel_prevent::{Decision, Mode, Prevention, PreventionSettings};
use libfuzzer_sys::fuzz_target;
use std::time::Instant;

fuzz_target!(|data: &[u8]| {
    // Totality: the parser sees the raw bytes first.
    let Some(tuple) = tuple_from_ip_packet(data) else {
        return;
    };
    let packet = QueuedPacket { id: 1, tuple };
    let now = Instant::now();

    // 1. An empty store accepts everything.
    let mut empty = Prevention::new(PreventionSettings {
        mode: Mode::Prevent,
        ..PreventionSettings::default()
    });
    assert_eq!(
        judge(&mut empty, &packet, now),
        Decision::Accept,
        "an armed sensor with nothing blocked dropped a packet"
    );

    // 2. Detect mode never drops, even with this very flow condemned.
    let mut disarmed = Prevention::new(PreventionSettings::default());
    disarmed.block(&packet.tuple, now);
    assert_eq!(
        judge(&mut disarmed, &packet, now),
        Decision::Accept,
        "detect mode dropped a packet: the kill switch does not hold"
    );

    // 3. Armed and condemned: this must drop, or `block` did nothing.
    let mut armed = Prevention::new(PreventionSettings {
        mode: Mode::Prevent,
        ..PreventionSettings::default()
    });
    if matches!(
        armed.block(&packet.tuple, now),
        cybersentinel_prevent::BlockOutcome::Blocked { .. }
    ) {
        assert!(
            judge(&mut armed, &packet, now).is_drop(),
            "a condemned flow was not dropped"
        );
    }

    // 4. The allow-list wins over any verdict, for either endpoint.
    for address in [packet.tuple.src_ip, packet.tuple.dest_ip] {
        let mut allowed = Prevention::new(PreventionSettings {
            mode: Mode::Prevent,
            allow_list: vec![cybersentinel_common::net::IpNetwork::host(address)],
            ..PreventionSettings::default()
        });
        allowed.block(&packet.tuple, now);
        assert_eq!(
            judge(&mut allowed, &packet, now),
            Decision::Accept,
            "an allow-listed endpoint was dropped"
        );
    }
});
