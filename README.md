# CyberSentinel-IPS

A **standalone intrusion detection sensor** for Windows, Linux, and macOS. One
installed binary per host does both **host-based** (file integrity,
authentication and system logs, processes) and **network-based** monitoring,
with **no external prerequisites** and **no central server** to run.

* **Detection-only.** It alerts; it does not block. The rule parser rejects
  `drop` and `reject` outright rather than quietly downgrading them, so a
  blocking rule is never mistaken for one that works.
* **Its own engine.** The detection pipeline is built from scratch in Rust — no
  third-party detection engine is bundled or wrapped.
* **Its own formats.** CyberSentinel `.rules` for detection content,
  `config.yaml` for configuration, CyberSentinel event JSON for output.
* **Standalone.** Each install is self-sufficient. It can forward events to a
  SIEM you already run (file, syslog, or webhook); it ships no console of its
  own.

Architecture, decisions, and the phase plan: **[`CLAUDE.md`](CLAUDE.md)**.
The design document it implements:
[`cybersentinel-implementation-guide-v4.md`](cybersentinel-implementation-guide-v4.md).

---

## Status: Phase 0 complete

Foundations, scaffolding, and the packaging pipeline. **The sensor does not yet
detect anything** — packet capture lands in Phase 1 and the detection engine in
Phase 3. What works today:

* the Cargo workspace and every crate in the layout, as compiling stubs where a
  phase has not reached them;
* the `config.yaml` loader;
* the `.rules` parser — headers and metadata in full, match conditions
  recognised but not yet evaluated — with graceful skip-and-log;
* the CyberSentinel event JSON schema and emitter;
* the decoupled event pipeline, with a test proving a blocked sink cannot stall
  event production;
* `cybersentinel run`, emitting periodic `stats` events to stdout and a file;
* matrix CI on Linux, Windows, and macOS that also builds, installs, and runs an
  installable Linux `.deb`.

---

## Try it

```sh
cargo build --workspace
cargo run -p cybersentinel -- run --config config/config.yaml --once
```

```
INFO starting CyberSentinel sensor (detection-only) version="0.1.0" config=config/config.yaml
INFO sensor identity resolved sensor=edge-01 sensor_id=aec73f3f-…
INFO writing events to file path=logs/events.json
INFO 9 rule(s) loaded from 1 file(s): 0 evaluable, 9 awaiting engine support, 0 skipped
WARN 9 rule(s) use options this build cannot evaluate yet and will not fire: content=4 flow=5 …
{"timestamp":"2026-08-04T11:42:25.974770Z","event_type":"stats","sensor":{…},"stats":{…}}
```

Diagnostics go to **stderr**; **stdout** is a pure newline-delimited event
stream you can pipe straight into a consumer:

```sh
cargo run -q -p cybersentinel -- run --config config/config.yaml 2>/dev/null | jq .
```

That load report is the honest one: the shipped rules all use match conditions
the engine cannot evaluate until Phase 3, so they load, are counted, and **do
not fire**. A rule is never evaluated with its conditions ignored — that would
widen the signature instead of narrowing it.

Drop `--once` to run until Ctrl-C.

## Install (Linux)

```sh
cargo install cargo-deb
cargo build --release -p cybersentinel
cargo deb -p cybersentinel --no-build
sudo dpkg --install target/debian/cybersentinel_*.deb

sudoedit /etc/cybersentinel/config.yaml
sudo systemctl start cybersentinel
```

The unit is enabled but not started by the package: review the installed config
first. See [`packaging/linux/README.md`](packaging/linux/README.md).

---

## Layout

| Path | What |
|---|---|
| `crates/common` | event schema, config loader, event pipeline, sensor identity |
| `crates/rules` | `.rules` parser, rule model, loader |
| `crates/cli` | the `cybersentinel` binary |
| `crates/{capture,decode,reassembly,applayer,engine,hids,correlation,storage,alerting}` | one crate per pipeline stage |
| `rules/` | the default ruleset |
| `config/` | `config.yaml` for running from the repo |
| `packaging/` | per-OS installers |
| `fuzz/` | `cargo-fuzz` targets |

---

## Contributing

Read [`CLAUDE.md`](CLAUDE.md) first — in particular §4, the conventions that are
not negotiable. The short version: never block the fast path on I/O, no
`unsafe`, parsers must be total and fuzzed, bound all state, and one bad rule
must never take the ruleset down.

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Licence

Apache-2.0.
