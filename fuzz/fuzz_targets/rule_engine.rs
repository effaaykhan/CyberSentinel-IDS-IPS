//! Fuzz the whole rule path: parse, compile, evaluate.
//!
//! Rules are operator-supplied and, over time, shared between organisations, so
//! everything from the text to the compiled matcher eats input somebody else
//! wrote. The payload it is matched against is attacker-supplied outright.
//!
//! The property is that no rule text and no payload can crash the engine, and
//! that a rule which compiled is one the evaluator can answer for.

#![no_main]

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use cybersentinel_common::event::{NetTuple, Protocol};
use cybersentinel_engine::{CompileLimits, Engine, EngineLimits, VarTable};
use cybersentinel_rules::parse_rule;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The input is split at the first NUL: rule text, then the payload it is
    // matched against. That lets the fuzzer explore both halves at once.
    let (rule_text, payload) = match data.iter().position(|byte| *byte == 0) {
        Some(split) => (&data[..split], &data[split + 1..]),
        None => (data, &[][..]),
    };
    let Ok(rule_text) = std::str::from_utf8(rule_text) else {
        return;
    };
    let Ok(rule) = parse_rule(rule_text) else {
        // A rejected rule is a correct outcome.
        return;
    };

    let vars = VarTable::new(
        [
            ("HOME_NET".to_string(), "[10.0.0.0/8,192.168.0.0/16]".to_string()),
            ("EXTERNAL_NET".to_string(), "!$HOME_NET".to_string()),
        ]
        .into_iter()
        .collect(),
        [("HTTP_PORTS".to_string(), "[80,8080]".to_string())]
            .into_iter()
            .collect(),
    );

    let (mut engine, report) = Engine::new(
        std::iter::once(&rule),
        &vars,
        EngineLimits {
            compile: CompileLimits {
                regex_size_limit: 64 << 10,
                regex_dfa_size_limit: 64 << 10,
            },
            max_flow_states: 8,
            max_flowbits_per_flow: 4,
            inspection_window: 4_096,
            max_threshold_entries: 8,
            ..EngineLimits::default()
        },
    );

    // Compilation is all-or-nothing per rule, and a rule that is not evaluable
    // must never be armed.
    assert!(report.compiled <= 1);
    assert_eq!(report.compiled, engine.ruleset().len());
    if !rule.is_evaluable() {
        assert_eq!(report.compiled, 0, "a non-evaluable rule was armed");
    }
    if report.compiled == 0 {
        return;
    }

    let tuple = NetTuple {
        src_ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
        src_port: Some(51_000),
        dest_ip: "203.0.113.5".parse::<IpAddr>().unwrap(),
        dest_port: Some(80),
        proto: Protocol::Tcp,
    };
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

    let mut alerts = Vec::new();
    engine.inspect_packet(1, tuple, true, payload, now, &mut alerts);

    // Feed the same bytes as a stream, in pieces, so the inspection window and
    // the HTTP path are exercised too.
    for chunk in payload.chunks(13.max(1)) {
        engine.inspect_stream(1, tuple, true, chunk, now, &mut alerts);
    }

    let counters = engine.counters();
    assert!(counters.alerts <= counters.matches, "alerted more often than matched");
    assert!(counters.flow_states <= 8, "the state table exceeded its cap");
    for alert in &alerts {
        assert_eq!(alert.sid, rule.sid);
        assert!(!alert.signature.is_empty());
    }

    engine.on_flow_end(1);
    assert_eq!(engine.counters().flow_states, 0);
});
