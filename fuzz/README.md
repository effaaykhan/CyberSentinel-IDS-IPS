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
| `decoder` | `etherparse`-based L2–L4 decode of raw frames | 1 |
| `reassembler` | IP defragmentation and TCP stream reassembly | 2 |
| `applayer_http` | HTTP request/response parsing and URI normalization | 3 |

The later targets are added by the phase that introduces the code they cover;
each phase's acceptance criteria include "the fuzz target runs clean".

## What the targets assert

They check more than "did not crash". Each one asserts the invariants the rest
of the system relies on — that a parsed rule is self-consistent, that evaluability
is exactly the absence of unsupported options, that every logical line is either
loaded or reported as skipped. A fuzzer that only checks for panics will not
catch a parser that silently drops a rule, which is the failure mode that
actually costs detection coverage.
