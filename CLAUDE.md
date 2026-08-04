# CLAUDE.md — CyberSentinel-IPS

Working notes for anyone (human or agent) changing this repository. The
architectural source of truth is **`cybersentinel-implementation-guide-v4.md`**;
this file records what was actually built, the decisions taken along the way,
and where they diverge from the guide.

---

## 0. Read this first: the guide file is v3 content under a v4 name

`cybersentinel-implementation-guide-v4.md` carries the v4 filename but holds the
**v3 document**. Its text specifies Suricata-format rules, a `suricata.yaml`
config subset, EVE JSON output, and a curated ET Open ruleset snapshot.

**The v4 brief supersedes all of that.** CyberSentinel owns its formats:

| Guide (v3 text) | CyberSentinel v4 — what is built |
|---|---|
| Suricata-format `.rules` | **CyberSentinel `.rules`** — our own format |
| `suricata.yaml` subset | **`config.yaml`** — our own schema |
| EVE JSON | **CyberSentinel event JSON** |
| Curated ET Open subset, licensing to verify | **We author all detection content**; no third-party ruleset, no ruleset licence to clear |

Everything else in the guide — the pipeline stages, the crate layout (§3.2), the
cross-cutting principles (§6), the phase plan (§7) — is followed as written.
Where this file says "guide §N", that part still applies.

The rule *syntax* deliberately resembles the Suricata family, because that
grammar is what IDS practitioners already read fluently. The parser, the
semantics, and the content are ours.

---

## 1. What this is

A **standalone intrusion detection sensor**. One installed binary per host doing
both **host-based** (file integrity, auth/log, process) and **network-based**
monitoring, shipped as a native installer per OS with **no external
prerequisites** and **no central server**. It can forward events to a SIEM the
operator already runs; it ships no console of its own.

**Detection-only (IDS) in v1.** It alerts; it does not block. This is enforced in
code, not just documented: the rule parser *rejects* `drop` and `reject` actions
rather than silently downgrading them to alerts, so an operator who writes a
blocking rule is told it will not block.

The detection engine is **built from scratch**. Nothing third-party does the
detecting.

---

## 2. Where things live

```
crates/
  common/        event schema, config.yaml loader, decoupled event pipeline, sensor identity
  capture/       Capture trait + per-OS backends            (Phase 1)
  decode/        etherparse L2–L4 decode, decoder anomalies (Phase 1)
  reassembly/    IP defrag, TCP reassembly, normalization   (Phase 2)
  applayer/      HTTP → DNS → TLS parsers, sticky buffers   (Phase 3, 8)
  rules/         .rules parser + rule model + loader        (parser stub live)
  engine/        rule grouping, aho-corasick MPM, evaluation(Phase 3)
  hids/          fim/ logs/ process/ platform/{linux,windows,macos}  (Phase 4–6)
  correlation/   dedupe, host↔network correlation           (Phase 4, 7)
  storage/       event sinks (live), flow store, PCAP ring
  alerting/      syslog / webhook delivery                  (Phase 7)
  cli/           the `cybersentinel` binary
rules/           the default ruleset we author
config/          config.yaml for running from the repo
packaging/       linux (live) · windows · macos · third_party
fuzz/            cargo-fuzz targets
tests/fixtures/  shared fixtures (rule files now; pcaps from Phase 1)
```

Crates that a phase has not reached yet are **compiling stubs**: they carry the
types and traits their stage will expose, with a doc comment naming the phase.
They contain no `todo!()`, so the workspace always builds and the interfaces can
be argued about before the implementation exists.

---

## 3. The pipeline

```
capture → decode → IP-defrag + TCP-reassembly + normalization → rule-group
        → multi-pattern scan (aho-corasick) → full evaluation → event alert
```

plus host sensors (FIM, logs, process) emitting into the *same* event pipeline,
which is what makes host and network alerts correlate natively rather than by
post-hoc log joining.

**Phase 0 built the ends, not the middle**: config and rule loading at the front,
the event schema and output path at the back. Every later phase drops a stage
into a pipeline that already exists and is already observable.

---

## 4. Conventions that are not negotiable

These come from guide §6 and from what this tool is. Changing one is a design
decision, not a refactor.

### Never block the fast path on I/O
Producers call `EventEmitter::emit`, which pushes onto a bounded queue and
returns. One writer thread owns all sinks and does the serialization and the
I/O. A wedged sink can fill the queue; it can never stall detection.

The overflow behaviour is **drop and count**, surfaced as
`stats.events.dropped`. A non-zero drop count is a **coverage hole** — events
that happened and were never recorded — and must be alarmed on, not treated as a
tuning metric.

### No `unsafe`
`unsafe_code = "forbid"` at the workspace root. This code parses hostile input at
every stage; memory safety is the reason the language was chosen. A crate that
genuinely needs `unsafe` (a capture backend, plausibly) must opt out explicitly
and document why.

### Parsers must be total
Every parser returns a value or a typed error for **any** input, including
malformed, adversarial, and enormous. No panics, no unbounded recursion. Guide
§6: *a crash here is a vulnerability in your security tool.* Each parser gets a
`cargo-fuzz` target in the phase that introduces it, and the fuzz targets assert
invariants, not just absence of panics.

### Bound all state
Reassembly and flow tracking get per-flow and global caps plus timeouts
(`cybersentinel-reassembly::Limits`). An attacker must not be able to exhaust
memory by opening flows or sending fragments that never complete.

### Normalize before matching, with a target-based overlap policy
The evasion-resistance core. If the sensor and the destination host disagree
about what a byte stream contains, an attacker walks past every rule silently.

### UTC timestamps, sub-second, on everything
`Timestamp` renders exactly `YYYY-MM-DDThh:mm:ss.ffffffZ` and is *stored* at
microsecond resolution, so an event written and read back compares equal. Clock
accuracy is assumed to come from NTP; detecting and reporting skew is not
implemented (see §9).

### Always record the action taken
Every alert carries `action`. In v1 it is always `alerted`, and that is worth
stating explicitly rather than implying.

### Fail one rule, not the whole load
A malformed rule is skipped and logged with file, line, and reason. It never
takes the rest of the ruleset down. Likewise a broken sink is counted and
survived, never fatal.

### Diagnostics on stderr, events on stdout
`stdout` is a pure newline-delimited event stream that can be piped straight into
a consumer. Everything the sensor says *about itself* goes to stderr.

### Captured data is PII
Traffic and host activity are personal data. Access control and retention are
part of packaging, not an afterthought — the Linux package ships a logrotate
policy for exactly this reason.

---

## 5. The CyberSentinel event JSON schema

One schema for host and network. Newline-delimited JSON, one object per line.

```json
{"timestamp":"2026-08-04T11:42:25.974770Z",
 "event_type":"stats",
 "sensor":{"name":"edge-01","id":"<uuid>","version":"0.1.0"},
 "flow_id":12345,
 "src_ip":"192.0.2.1","src_port":51000,
 "dest_ip":"198.51.100.7","dest_port":80,"proto":"TCP",
 "stats":{...}}
```

* The envelope is `timestamp`, `event_type`, `sensor`, an optional `flow_id`, and
  the 5-tuple where one applies. Absent fields are omitted, not null.
* The body is flattened in under a key **equal to** `event_type`. `Event::new`
  derives `event_type` from the body, so the two cannot disagree.
* `sensor.id` is a UUIDv4 generated on first run and persisted under
  `paths.data-dir`, so events stay correlatable across restarts, renames, and
  address changes.

Bodies defined so far: **`stats`** (live) and **`alert`** (defined, filled in
from Phase 3). `flow`, `http`, `dns`, `tls`, `fim`, `auth`, and `process` arrive
with the phases that produce them.

`stats` reports `capture.enabled` and `engine.enabled` as `false` with zeroed
counters rather than omitting the sections — an operator reading `"enabled":
false` learns something, whereas a missing section reads like a bug.

---

## 6. The CyberSentinel rule format

```
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS ( \
    msg:"CYBERSENTINEL WEB directory traversal sequence in URI"; \
    flow:established,to_server; http.uri; content:"../"; nocase; \
    classtype:web-application-attack; \
    metadata:phase 3, confidence high; \
    sid:100001; rev:1;)
```

Header: `action protocol src-addr src-port direction dst-addr dst-port`.
Options: `;`-separated, `"`-quoted values, `\` escapes for `"` `;` `\`. Comments
are `#`; a trailing `\` continues a rule.

**SID convention:** `100000–999999` network rules, `1000000+` host rules.

### The target language subset (Phase 3)

Headers with variables · `content` + `nocase`/`offset`/`depth`/`distance`/`within`
· `fast_pattern` · `flow` · `flowbits` · `pcre` · `byte_test`/`byte_jump` ·
`dsize` · `threshold`/`detection_filter` · sticky buffers `http.uri`/
`http.header`/`http.user_agent` · metadata (`sid`/`rev`/`msg`/`classtype`/
`metadata`).

App-layer order: **HTTP first** (unlocks the most rules), then DNS, then TLS.

### What Phase 0's parser actually does

Fully parses the header and the metadata options (`sid`, `rev`, `msg`,
`classtype`, `metadata`). Match conditions are recognised by keyword but not
interpreted.

It distinguishes **two** failure modes, and the distinction matters:

* **Unparseable** → the rule is **skipped** and logged with file, line, reason.
  This includes an *unknown option keyword*, on purpose: a typo like
  `contnet:"x"` would otherwise silently produce a header-only rule matching
  every packet on the port.
* **Parseable but not evaluable** → every keyword is real, but at least one is
  unimplemented in this build. The rule **loads**, is counted, and reports
  `is_evaluable() == false`.

> **The engine must only ever evaluate rules where `is_evaluable()` is true** —
> iterate `RuleSet::evaluable()`, never `RuleSet::rules()`. Honouring a header
> while ignoring the conditions it was written with *widens* a signature instead
> of narrowing it.

Since every realistic rule uses `content` or similar, today's honest load report
against the shipped ruleset is *"9 loaded, 0 evaluable, 9 awaiting engine
support"*. That is the coverage gap, quantified — exactly what guide §1 says to
expect from a native engine, made visible rather than hidden.

---

## 7. Configuration

`config.yaml`. Every section defaults, so a minimal file is valid, but **unknown
keys are a hard error** — a typo that silently disables an output or a sensor is
a failure mode this tool cannot afford.

Relative paths resolve against the working directory, with two conveniences:
`outputs.file.path` joins to `paths.log-dir`, and each `rules.files` entry joins
to `rules.directory`.

Two shipped configs: `config/config.yaml` (repo-relative, for development) and
`packaging/linux/config.yaml` (absolute system paths, installed to
`/etc/cybersentinel/`).

---

## 8. Packaging

Guide §5 treats packaging as a core workstream, and each OS phase ends in a
signed, installable artifact. See `packaging/README.md` for the full matrix.

| Target | Artifact | Status |
|---|---|---|
| Linux `.deb` (cargo-deb, systemd) | built and installed in CI | **live** |
| Linux `.rpm` / AppImage / musl static | — | Phase 4 |
| Windows `.msi`/`.exe`, Service, Authenticode, bundled Npcap | scaffolding | Phase 5 |
| macOS `.pkg`/`.dmg`, launchd, Developer ID + notarization | scaffolding | Phase 6 |

Two things are flagged early because they have lead time and cost: **code
signing** on Windows and macOS, and the **Npcap redistribution licence**
(`packaging/third_party/README.md`) — Npcap is not open source, and bundling it
in a distributed product generally needs a commercial licence.

---

## 9. Decisions taken, with their reasoning

Recorded so they can be revisited deliberately.

| Decision | Why | Revisit if |
|---|---|---|
| Hand-written rule parser, not `nom` | Small grammar, explicit failure modes, easy to fuzz, one fewer dependency | Phase 3's option grammar stops being readable |
| `std::sync::mpsc::sync_channel` for the event queue | Bounded, `try_send` never blocks, and std's channel *is* the crossbeam algorithm since Rust 1.67 — zero dependency | A phase needs multi-consumer or work-stealing; `crossbeam-channel` drops straight in |
| Unknown option keyword → skip the rule | A typo must not silently broaden a signature | Never |
| Rules with unimplemented options load but are inert | Makes the coverage gap visible and countable instead of hiding it | Never |
| `stats` reports disabled subsystems explicitly | `"enabled": false` informs; a missing section reads as a bug | Never |
| `deny_unknown_fields` on the whole config | A misspelled key silently disabling a sensor is worse than a startup failure | Never |
| systemd `DynamicUser=yes` | No `useradd` in a maintainer script, no orphaned account after removal | Something needs a stable uid |
| First-party GitHub Actions only | A third-party action runs with access to a security tool's build | Never, without a good reason |
| `tracing` + `tracing-subscriber` for diagnostics | Ecosystem standard, structured fields, level filtering | — |
| `ctrlc` with `termination` | SIGTERM from systemd/launchd must shut down as cleanly as Ctrl-C | — |
| **`serde_yaml` (0.9)** | The guide names it | **Open — see below** |

### Open questions for the next phases

1. **`serde_yaml` is unmaintained.** Version 0.9.34 is published as
   `0.9.34+deprecated`; the crate was archived by its author. It works and only
   ever parses a local, trusted config file, but "unmaintained YAML parser" in a
   security tool deserves a deliberate answer. Options: keep it, move to a
   maintained fork (`serde_yaml_ng`), or move to `saphyr`. **Not changed
   unilaterally — the guide names `serde_yaml`.**
2. **`regex` vs `pcre2`** for `pcre:` (guide §2 flags the tradeoff). `regex` has
   linear-time guarantees, which matters when rule content may come from
   elsewhere; `pcre2` has the features some rules assume. Needs deciding before
   Phase 3, not during it.
3. **WiX vs Inno** for the Windows installer — see
   `packaging/windows/README.md`.
4. **Clock skew.** Guide §6 says "UTC + NTP". Timestamps are UTC; nothing checks
   whether the host clock is actually synchronized. A sensor with a wrong clock
   produces evidence that will not correlate. Worth a `stats` field.
5. **Npcap licensing** must be resolved before Phase 5 ships.

---

## 10. Phase plan and acceptance criteria

From guide §7. Each "done" is an acceptance test.

### Phase 0 — Foundations, scaffolding, packaging pipeline ✅
Workspace and layout · `CLAUDE.md` · `config.yaml` loader · `.rules` parser stub
· event schema and emitter · decoupled logging · runnable binary emitting `stats`
· matrix CI producing an installable Linux package.

**Done when:** builds and tests pass on all three OSes · `cybersentinel run`
runs on all three · config and rules load, skipping and logging what they cannot
parse · well-formed `stats` events reach stdout and a file · a blocked sink
provably does not stall production · CI outputs an installable `.deb`.

### Phase 1 — Capture + decode (Linux)
`Capture` trait + AF_PACKET backend · `etherparse` decoder for Eth/IP/TCP/UDP/ICMP
· 5-tuple extraction · decoder-anomaly events · packet and drop counters into
`stats`.

**Done when:** replaying a pcap yields correct flow metadata and anomaly events
for malformed packets, and the decoder fuzz target runs clean.

### Phase 2 — Reassembly + normalization
IP defragmentation · TCP stream reassembly with bounded state, timeouts, and a
target-based overlap policy · HTTP normalization. The evasion-resistance core.

**Done when:** an attack string split across segments or fragments reassembles
correctly · overlapping-segment and encoded-URI cases resolve correctly · the
reassembler fuzz target runs clean · state is provably bounded.

### Phase 3 — Native rule engine → **NIDS milestone**
Full `.rules` parsing of the §6 subset · rule grouping by header ·
`aho-corasick` MPM on `fast_pattern` · full evaluation · HTTP app-layer parser
feeding sticky buffers · verdict → `alert` event.

**Done when:** a known signature in replayed traffic produces a correct alert ·
the loader reports supported vs. skipped · the rule-parser fuzz target runs
clean.

### Phase 4 — HIDS core (Linux) → **first MVP**
FIM via `notify` · auditd/journald · process monitoring · host rules · local
host↔network correlation.

**Done when:** a watched-file change, a failed-login burst, and a new listener
each produce a host alert unified with network alerts. **MVP: an installable
standalone Linux sensor doing NIDS + HIDS.**

### Phase 5 — Windows port + installer
Npcap capture (bundled) · FIM via `ReadDirectoryChangesW`/USN · ETW/Event Log ·
Windows Service · `.msi`/`.exe` · Authenticode.

### Phase 6 — macOS port + installer
BPF capture · FSEvents · unified log/OpenBSM · launchd · universal binary ·
`.pkg`/`.dmg` · Developer ID + notarization.

### Phase 7 — Correlation, analytics, delivery
Richer correlation, dedupe, severity · optional anomaly scoring as a **separate,
alert-only** path (respect the base-rate fallacy) · syslog/webhook delivery.

### Phase 8 — Hardening, evasion testing, performance
Broad fuzzing · an adversarial suite (fragmented, overlapping, encoded, low-and-slow)
· drop-rate monitoring under load · state-exhaustion resistance · DNS and TLS
coverage · service self-protection · secure auto-update.

**Out of scope for v1:** inline prevention (NFQUEUE/WFP/NetworkExtension plus
driver and extension signing) and any central console. The architecture leaves
room for both.

---

## 11. Working on this

```sh
cargo build --workspace
cargo test  --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings

# Run from the repo root; state lands in ./data and ./logs.
cargo run -p cybersentinel -- run --config config/config.yaml
cargo run -p cybersentinel -- run --config config/config.yaml --once   # one event, then exit

# Fuzzing — from inside fuzz/, whose rust-toolchain.toml selects nightly
cd fuzz && cargo fuzz run rule_parser -- -max_total_time=60
```

**Write the test first where practical.** The decoupled-pipeline test
(`eventlog::tests::a_blocked_sink_never_stalls_the_producer`) is the model: it
asserts the property *structurally* — with the writer parked inside a sink,
exactly `capacity` further emits succeed and the rest are refused immediately —
rather than by timing, which would be flaky.

Keep commits small and reviewable. Flag anything in the guide that proves
impractical rather than diverging from it silently.
