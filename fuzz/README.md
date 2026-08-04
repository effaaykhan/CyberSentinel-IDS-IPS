# Fuzzing

Guide §6 makes this non-negotiable: CyberSentinel hand-builds every parser in
the pipeline, and each one eats attacker-controlled input. **A crash in a parser
is a vulnerability in the security tool**, not a cosmetic bug.

## Running

```sh
cargo install cargo-fuzz
rustup toolchain install nightly          # libFuzzer needs -Z sanitizer

cd fuzz                                   # rust-toolchain.toml here selects nightly
cargo fuzz list
cargo fuzz run rule_parser -- -max_total_time=300
cargo fuzz run rule_file   -- -max_total_time=300
```

Run these from **inside `fuzz/`**. The workspace root pins stable, and
`fuzz/rust-toolchain.toml` overrides that for this directory; running
`cargo fuzz` from the repo root instead fails with *"the option `Z` is only
accepted on the nightly compiler"*.

Corpora and crash artifacts land in `corpus/` and `artifacts/`, both ignored by
git. A reproducer is replayed with:

```sh
cargo fuzz run rule_parser artifacts/rule_parser/crash-<hash>
```

## Targets

| Target | Covers | Phase |
|---|---|---|
| `rule_parser` | one rule through `parse_rule` — totality and rule invariants | 0 (live) |
| `rule_file` | a whole file through `RuleSet::load_text` — every line accounted for | 0 (live) |
| `decoder` | L2–L4 decode of arbitrary frames, at arbitrary claimed wire lengths | 1 (live) |
| `pcap_reader` | a whole savefile: file → records → decoder | 1 (live) |
| `reassembler` | IP defragmentation and TCP stream reassembly | 2 |
| `applayer_http` | HTTP request/response parsing and URI normalization | 3 |

`pcap_reader` is the reason savefile parsing lives in-tree rather than behind
libpcap: an FFI boundary would be opaque to the fuzzer, and every length in that
format is attacker controlled.

The later targets are added by the phase that introduces the code they cover;
each phase's acceptance criteria include "the fuzz target runs clean".

## What the targets assert

They check more than "did not crash". Each one asserts the invariants the rest
of the system relies on:

* a parsed rule is self-consistent, and evaluability is exactly the absence of
  unsupported options;
* every logical line of a rule file is either loaded or reported as skipped;
* the decoder's payload range is always a valid, non-inverted slice of the
  frame, and a transport layer never appears without a network layer;
* the savefile reader never hands out a frame longer than its own cap, nor a
  wire length below the captured length — which would make the decoder treat a
  complete frame as snapped and silently suppress real length-mismatch
  anomalies.

A fuzzer that only checks for panics would miss every one of those, and each is
a way to lose detection coverage without anything appearing to go wrong.
