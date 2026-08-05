//! Fuzz the `/proc` readers.
//!
//! `/proc/<pid>/stat` and `/proc/net/tcp` are kernel-formatted, which sounds
//! safe until you notice that one of the fields in `stat` is the process's own
//! name — chosen by the process, allowed to contain spaces and parentheses, and
//! therefore able to look exactly like the rest of the line. A process that
//! wants to misreport its parent only has to name itself after one.
//!
//! So the properties here are totality plus the field-locating contract:
//!
//! * Any input yields a parse or nothing, never a panic.
//! * A parsed process name carries no control characters and is bounded.
//! * A listening socket's address round-trips, so nothing is reported that did
//!   not actually decode as an address and a port.

#![no_main]

use cybersentinel_hids::process::{parse_net_table, parse_stat, parse_status_uid};
use libfuzzer_sys::fuzz_target;

/// Longest process name the reader is allowed to emit.
const MAX_NAME: usize = 128;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Some((name, parent_pid, start_time)) = parse_stat(text) {
        assert!(
            !name.chars().any(char::is_control),
            "a control character reached a process name: {name:?}"
        );
        assert!(
            name.chars().count() <= MAX_NAME,
            "the process name is unbounded: {} characters",
            name.chars().count()
        );
        // Both are read as unsigned integers, so nothing further to assert
        // beyond that they decoded at all.
        let _ = parent_pid;
        let _ = start_time;
    }

    let _ = parse_status_uid(text);

    for is_v6 in [false, true] {
        for socket in parse_net_table(text, is_v6) {
            assert_eq!(
                socket.address.to_string().parse().ok(),
                Some(socket.address),
                "a reported socket address must round-trip"
            );
            assert_eq!(
                socket.address.is_ipv6(),
                is_v6,
                "a v4 table must not yield v6 addresses, or the reverse"
            );
        }
    }
});
