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
  capture/       PacketSource: pcap replay (live) + libpcap live capture
  decode/        L2–L4 decode, decoder anomalies            (live)
  reassembly/    flow table, IP defrag, TCP reassembly, normalization (live)
  applayer/      HTTP request parser + sticky buffers (live) · DNS, TLS (Phase 8)
  rules/         .rules parser, rule model, loader          (live)
  engine/        var resolution, compilation, MPM, evaluation, alerts (live)
  hids/          fim/ logs/ process/ platform/{linux,windows,macos}  (Phase 4–6)
  correlation/   dedupe, host↔network correlation           (Phase 4, 7)
  storage/       event sinks (live), flow store, PCAP ring
  alerting/      syslog / webhook delivery                  (Phase 7)
  cli/           the `cybersentinel` binary
rules/           the default ruleset we author
config/          config.yaml for running from the repo
packaging/       linux (live) · windows · macos · third_party
fuzz/            cargo-fuzz targets
tests/fixtures/  shared fixtures: rule files, and pcaps with their generator
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

**Phase 0 built the ends**: config and rule loading at the front, the event
schema and output path at the back. **Phase 1 filled in capture, decode, and
flow tracking**. **Phase 2 added defragmentation, stream reassembly, and
normalization**, so packets became the byte stream a server would actually see.
**Phase 3 added the detection engine and the HTTP parser**: the pipeline is now
complete end to end for the network side, and rules fire.

### Capture sources

`PacketSource` has two implementations and answers three ways — `Frame`, `Idle`,
`End`. `Idle` matters: a live source that has seen no traffic for a moment is not
a finished one, and the run loop needs the difference to notice a shutdown
signal on a quiet link.

* **`PcapReplay`** reads `.pcap` savefiles, in-tree, in pure Rust. No
  privileges, no libpcap, works on every OS. This is what the tests and CI run.
* **`LiveCapture`** uses the `pcap` crate (libpcap), target-gated to Linux and
  macOS. Windows gets Npcap in Phase 5.

**Live capture needs libpcap at runtime** — present by default on Linux and
macOS, bundled as Npcap on Windows from Phase 5. Replay needs nothing. See
`crates/capture/README.md`.

### Reassembly, and why it decides whether any of this works

Guide §7 calls Phase 2 the evasion-resistance core, and it is: an attacker who
can make the sensor and the destination host disagree about what the byte
stream contains walks past every rule silently, with no error anywhere.

**Overlap policy is configured, never fingerprinted.** When two copies of the
same bytes arrive *disagreeing*, the sensor picks one — and it must pick what
the destination host will. Guessing the stack from its packets is itself
evadable: an attacker who can influence the fingerprint gets to choose the
policy the sensor uses, which is worse than having none.

```yaml
reassembly:
  overlap-policy: first        # first | last — the default
  host-policies:               # per-DESTINATION overrides, longest prefix wins
    - network: 10.1.0.0/16     # a bare address means a single host
      policy: last
```

`first` matches Linux and most BSDs; `last` matches older Windows stacks. The
enum is `#[non_exhaustive]`, so OS-family policies can be added without breaking
anything. Lookups are by **destination**, so the two halves of a connection can
resolve overlaps differently — they are two different stacks.

**Delivery is gated on acknowledgement.** Reassembled bytes are held until the
peer ACKs them. That is what makes overlap policy mean anything: a
contradicting retransmission always arrives before the ACK, so at the moment the
sensor must choose it still holds both copies. A reassembler that delivered
bytes as soon as they were contiguous could not implement `last` at all. Where
no ACK is visible — asymmetric routing, a one-way tap — `delivery-flush-bytes`
releases the data anyway, so matching does not stall on exactly the networks
hardest to monitor.

Once delivered, data cannot be revised. A retransmission contradicting
already-delivered bytes is counted, not applied; there is a test pinning that
limit so it cannot regress into silence.

**The ambiguities, and which way each is resolved:**

| Case | Behaviour | Why |
|---|---|---|
| Data on the SYN | Accepted, counted | TCP Fast Open makes it real traffic |
| Data past the FIN | Rejected, counted | The host has closed that direction; accepting it lets an attacker write into the sensor's view of a stream the host has stopped reading |
| Data filling a gap *before* the FIN | Accepted | An ordinary retransmission, not an injection |
| **Out-of-window RST** | **Ignored**, counted | Honouring a forged reset stops the sensor watching a live connection. Ignoring a real one only costs a flow entry until its timeout — a far cheaper mistake. The window is one un-scaled receive window (64 KiB), not the reassembly buffer |
| In-window RST | Tears down | What the host will do |
| Fragment too small to hold the transport header | Reassembled, and flagged | RFC 1858's tiny-fragment attack |

**Normalization runs decode-then-collapse.** `%2e%2e%2f` has to become `../`
before traversal can be resolved — that ordering *is* the technique. Decoding is
capped at `decode_rounds` passes, because an input can always be encoded one
level deeper than any limit; when the cap is hit with escapes still present, the
result says so. Nothing in normalization can grow its input.

The flags normalization returns — double-encoded, above-root, null byte, invalid
escape — are **detection signal in their own right** and become matchable rule
conditions in Phase 3.

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
Reassembly and flow tracking get per-flow and global caps plus timeouts. An
attacker must not be able to exhaust memory by opening flows or sending
fragments that never complete. Past `flow.max-flows` the table sweeps timeouts,
then evicts least-recently-seen, and **counts the evictions** — an eviction
means the sensor stopped following a live conversation, which is a coverage
hole, not a memory statistic.

**Bound the bookkeeping, not just the bytes.** A flood of one-byte writes at
alternating offsets holds few bytes but an unbounded number of gap descriptors,
which is the same denial of service wearing a different hat. `RangeBuffer` caps
both, and the caps have tests that drive floods at them.

**Two ceilings, always.** An attacker can exhaust either a few flows each
holding a lot or many flows each holding a little, so there is a per-flow cap
*and* a global one.

### Bound the events one packet can cause
A packet produces at most one `anomaly` event however many things are wrong with
it. An attacker chooses what to send; they must not thereby choose how many
events the sensor emits per packet.

### Report coverage holes as coverage holes
Kernel drops, flow evictions, snapped frames, and a torn capture file are all
places where traffic existed and the sensor did not see it. Each has a counter
in `stats` and a log line that says what it means. Silence here is the failure
mode that matters most: a sensor that sees nothing looks identical to a quiet
network.

### Normalize before matching, with a target-based overlap policy
The evasion-resistance core. If the sensor and the destination host disagree
about what a byte stream contains, an attacker walks past every rule silently.

### UTC timestamps, sub-second, on everything
`Timestamp` renders exactly `YYYY-MM-DDThh:mm:ss.ffffffZ` and is *stored* at
microsecond resolution, so an event written and read back compares equal. Clock
accuracy is assumed to come from NTP; detecting and reporting skew is not
implemented (see §9).

**Packet-derived events carry the capture timestamp, not the processing time.**
Replaying a capture from last week must produce events dated last week, or
nothing downstream can correlate them with anything else.

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

Bodies defined so far:

| Body | Status | What it says |
|---|---|---|
| `stats` | live | periodic sensor health: event queue, rules, capture, decode, flows, engine |
| `flow` | live | a conversation ended — per-direction packets and bytes, TCP flags, and why it ended (`closed`, `timed_out`, `evicted`, `sensor_stopped`) |
| `anomaly` | live | a packet was malformed at the wire level — every problem with it, in one event |
| `alert` | defined | a rule matched. Filled in from Phase 3 |

`http`, `dns`, `tls`, `fim`, `auth`, and `process` arrive with the phases that
produce them.

`stats` reports `engine.enabled` as `false` with zeroed counters rather than
omitting the section — an operator reading `"enabled": false` learns something,
whereas a missing section reads like a bug.

A `flow` event's 5-tuple is **oriented from the initiator**, so `src_*` is
whoever sent the first packet and "to server" means "in the direction the
conversation was opened in".

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

The sections that matter operationally:

| Key | Why it matters |
|---|---|
| `capture.enabled` | off by default — live capture needs privileges, and a sensor should start capturing because someone chose to |
| `capture.bpf-filter` | applied in the kernel: **traffic it excludes is invisible to detection** |
| `capture.snaplen` | content past the snap length cannot be matched |
| `capture.buffer-size-bytes` | the first thing to raise when `stats.capture.drops` goes non-zero |
| `flow.max-flows` | the hard bound on flow state; past it, live flows are evicted and counted |
| `flow.emit-events` / `decode.emit-anomaly-events` | event volume. Turning either off keeps the counters in `stats` |
| `hids.fim.paths` | **the whole scope of file integrity monitoring.** Deliberately a short list: every watched directory consumes one of the kernel's finite `max_user_watches`, and a sensor that exhausts them degrades the host it exists to protect |
| `hids.fim.rescan-interval-secs` | detection *latency*, not a performance knob: the rescan is what catches changes made while the sensor was down and changes lost to a queue overflow |
| `hids.fim.max-file-bytes` | files above it are tracked by size and metadata only. A same-length edit to one is genuinely missed, and the absent `sha256` on the event is what says so |
| `hids.auth.journald` | prefer it over a log file. journald records carry the service as a *structured field*, so a message cannot claim to have come from `sshd` |
| `hids.process.interval-secs` | a poller cannot see a process that starts and exits between sweeps. Shorter is more thorough and more expensive |
| `hids.process.proc-root` | where `/proc` is. Configurable for containers given the host's `/proc` at another path |
| `correlation.window-secs` | how far apart two events can be and still be one incident |
| `correlation.cooldown-secs` | the quiet period after an incident, so sustained activity is one incident rather than a stream of them |

---

## 8. Privileges: what the sensor keeps, and why

The network path follows the classic pattern: open the capture socket, then
drop everything. Once libpcap holds the handle, `CAP_NET_RAW` is pure attack
surface — a flaw in the decoder or a rule parser is worth far less in a process
that cannot open sockets.

**Host monitoring breaks that pattern**, and the packaging pass has to account
for it. The HIDS is not a one-shot open followed by a lifetime of parsing: it
goes on reading and hashing files it does not own for as long as it runs. A
baseline that cannot read `/etc/shadow` — mode 0640, `root:shadow` — is a
baseline that silently omits the file most worth watching, and "silently omits"
is the failure mode this whole project is built to avoid.

### The set

| Capability | Needed by | Kept? | Why |
|---|---|---|---|
| `CAP_NET_RAW` | opening the live capture handle | **dropped after open** | Nothing on the packet path needs it once libpcap holds the socket. |
| `CAP_NET_ADMIN` | promiscuous mode, kernel BPF filter | **dropped after open** | Same. |
| `CAP_DAC_READ_SEARCH` | FIM hashing, reading `/var/log/secure` and `/var/log/audit/`, `journalctl` reading `/var/log/journal` | **retained while `hids.enabled`** | Bypasses file-read and directory-search checks, and nothing else. The smallest capability that makes FIM and log reading actually cover what they claim to. |
| `CAP_SYS_PTRACE` | `/proc/<pid>/exe` and `/proc/<pid>/fd` for **other users'** processes — i.e. attributing a listening socket to the process holding it | **never granted** | It permits ptracing any process on the box, which is full compromise. The socket is still reported; the owning process shows as `unknown`. Losing an attribution is worth far more than handing an attacker that capability. |
| `CAP_AUDIT_READ` | reading the kernel audit netlink socket directly | **not used** | Phase 4 reads auditd's log *file*, which `CAP_DAC_READ_SEARCH` already covers. Revisit only if a netlink reader is added. |

`CAP_DAC_READ_SEARCH` is placed in the **permitted, effective, inheritable and
ambient** sets. The first two are for this process. The last two are for the
one child it execs: `journalctl`. Without the ambient bit, a non-root sensor
would hold the capability itself and then spawn a `journalctl` that cannot read
the journal — which looks exactly like a host with no authentication activity.

### For the packaging pass

The systemd unit needs, at minimum:

```ini
[Service]
User=cybersentinel
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
```

`CAP_NET_RAW` and `CAP_NET_ADMIN` are in the ambient set because the process
needs them at startup and drops them itself; the bounding set is what stops
anything raising them back. Drop the two `NET` capabilities entirely on a
HIDS-only install, and drop `CAP_DAC_READ_SEARCH` on a NIDS-only one — the
sensor works with either half missing, and says so in `stats`.

Running as **root** is supported and warned about loudly. Dropping capabilities
is not the same as dropping root: uid 0 is still uid 0. Prefer a dedicated
user with ambient capabilities.

---

## 9. Packaging

Guide §5 treats packaging as a core workstream, and each OS phase ends in a
signed, installable artifact. See `packaging/README.md` for the full matrix.

| Target | Artifact | Status |
|---|---|---|
| Linux `.deb` (cargo-deb, systemd) | built and installed in CI | **live** |
| Linux `.rpm` / AppImage / musl static | — | next: the packaging pass after Phase 4 |
| Windows `.msi`/`.exe`, Service, Authenticode, bundled Npcap | scaffolding | Phase 5 |
| macOS `.pkg`/`.dmg`, launchd, Developer ID + notarization | scaffolding | Phase 6 |

Two things are flagged early because they have lead time and cost: **code
signing** on Windows and macOS, and the **Npcap redistribution licence**
(`packaging/third_party/README.md`) — Npcap is not open source, and bundling it
in a distributed product generally needs a commercial licence.

---

## 10. Decisions taken, with their reasoning

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
| **Live capture via the `pcap` crate** | Keeps all `unsafe` inside the dependency so first-party crates stay `forbid(unsafe_code)`; one API across three OSes | Profiling shows the FFI cost matters — then add an AF_PACKET backend behind `PacketSource`, in an isolated audited-`unsafe` module |
| **Reading `.pcap` *files* in-tree, not through libpcap** | Makes the whole decode path testable with no libpcap anywhere, including on the Windows runner; and a savefile is attacker-supplied input, which belongs under our own bounds-checking and fuzzing rather than behind an FFI boundary the fuzzer cannot see into | Never — this is the cheaper half of the format |
| Snap-length truncation is not a decoder anomaly | A clipped frame is expected; a header that overruns a *complete* frame is not. Conflating them buries real anomalies under noise | Never |
| An unsupported EtherType is not an anomaly | ARP and LLDP are ordinary traffic; they are counted, not alerted on | Never |
| A non-initial IP fragment gets no transport header | Its bytes are payload; reading ports out of them attributes the packet to a port nobody used | Never |
| Flow ids from FNV-1a, not `DefaultHasher` | `DefaultHasher` is randomly seeded per process, so replaying one capture twice would produce incomparable events | Never |
| One `anomaly` event per packet, not per anomaly | Bounds the events an attacker can cause per packet | Never |
| Variable resolution fails loudly | An address set silently too broad fires on traffic nobody meant; too narrow and it fires on nothing and nobody notices | Never |
| `![a,!b]` is refused, not approximated | An approximate address set matches the wrong traffic without saying so | Only with an exact representation |
| Regex budget applied at **compile** time | Linear-time matching does not make compilation free; a pathological expression costs megabytes of program | — |
| A rule over budget is skipped, not accepted | A rule nobody can afford to load must not load | Never |
| Evaluation fails closed on anything unanswerable | A rule firing on traffic nobody wrote it for is how analysts learn to ignore alerts | Never |
| A negated content is never a fast pattern | The pre-filter selects packets that *contain* the pattern; a rule needing its absence would never be considered | Never |
| Longest pattern chosen when none is marked | A longer needle appears in less traffic, so it rejects more rules per scan | — |
| Normalization runs on the URI **path** only | `..` inside a query parameter is not a traversal | — |
| A bare-LF request terminator is accepted | Lenient servers answer them; insisting on CRLF would miss requests somebody served | — |
| **Overlap policy configured, not fingerprinted** | A fingerprint an attacker can influence lets them choose the sensor's policy | Never |
| **Delivery gated on the peer's ACK** | It is the only way `last` policy can be implemented at all; the choice must still be open when it is made | If a phase needs lower matching latency than an RTT — then the trade has to be made explicitly |
| Reassembled content is never an event | It is bulk payload and PII; alert-triggered evidence capture is a different, later thing | Never |
| `--dump-streams` exists but is off by default | The end-to-end evasion properties have to be assertable somehow, and it is a debugging aid an operator opts into | Never make it a default |
| Normalization decodes before collapsing | `%2e%2e%2f` must become `../` before traversal resolves; a server rejecting encoded slashes would not serve the request anyway, so the cost is a false positive not a false negative | Never |
| RST accepted only within 64 KiB of what we have seen | Sizing the window off the reassembly buffer would give a blind attacker a target thousands of times larger | Never |
| `tracing` + `tracing-subscriber` for diagnostics | Ecosystem standard, structured fields, level filtering | — |
| `ctrlc` with `termination` | SIGTERM from systemd/launchd must shut down as cleanly as Ctrl-C | — |
| **`serde_yaml` (0.9)** | The guide names it | **Open — see below** |

### Open questions for the next phases

1. **`endswith`, `detection_filter`, and `%uXXXX` remain unimplemented.**
   Recognised and reported, never silently ignored. `%uXXXX` in particular is a
   real IIS-era evasion that needs a UTF-16 decision.
2. **HTTP responses and bodies are not parsed.** Request heads only, which is
   what the `http.*` buffers need; response inspection follows with the rules
   that want it.
3. **`serde_yaml` is unmaintained.** Version 0.9.34 is published as
   `0.9.34+deprecated`; the crate was archived by its author. It works and only
   ever parses a local, trusted config file, but "unmaintained YAML parser" in a
   security tool deserves a deliberate answer. Options: keep it, move to a
   maintained fork (`serde_yaml_ng`), or move to `saphyr`. **Not changed
   unilaterally — the guide names `serde_yaml`.**
4. **`regex` vs `pcre2`** — **decided and shipped: `regex`**, for its
   linear-time guarantee. The rule model has no PCRE-only features, and `pcre`
   flags are limited to `i`, `s`, `m`, and `R`.
3. **WiX vs Inno** for the Windows installer — see
   `packaging/windows/README.md`.
4. **Clock skew.** Guide §6 says "UTC + NTP". Timestamps are UTC; nothing checks
   whether the host clock is actually synchronized. A sensor with a wrong clock
   produces evidence that will not correlate. Worth a `stats` field.
5. **Npcap licensing** must be resolved before Phase 5 ships.
6. **Multi-interface capture.** One interface per sensor today; further entries
   in `capture.interfaces` are ignored with a warning. A thread per interface is
   the obvious shape, but flow-table sharing across them needs thought.
7. **Link types.** Only Ethernet is decoded. `LINUX_SLL` (113) — what capturing
   on the `any` device produces — is the likely next one.
8. **`%uXXXX` escapes are not decoded.** IIS accepted them, and they are a real
   evasion vector. Implementing it needs careful UTF-16 handling and a decision
   about which targets do it, so it is deliberately absent rather than
   half-present. Phase 3 or 8.
9. **Normalization options are not yet in `config.yaml`.** `NormalizeOptions`
   has code defaults; exposing `decode-rounds` and `backslash-is-separator` per
   target belongs with the HTTP parser that actually calls them (Phase 3).
10. **Privilege dropping is per-thread on Linux.** The sensor opens the capture
   handle and drops capabilities while still single-threaded, so every thread
   spawned afterwards inherits the dropped set. That ordering is load-bearing:
   `run()` opens capture *before* building the event pipeline for exactly this
   reason. Dropping capabilities is still not the same as dropping root — real
   separation comes from the systemd unit's `DynamicUser`.

---

## 11. Phase plan and acceptance criteria

From guide §7. Each "done" is an acceptance test.

### Phase 0 — Foundations, scaffolding, packaging pipeline ✅
Workspace and layout · `CLAUDE.md` · `config.yaml` loader · `.rules` parser stub
· event schema and emitter · decoupled logging · runnable binary emitting `stats`
· matrix CI producing an installable Linux package.

**Done when:** builds and tests pass on all three OSes · `cybersentinel run`
runs on all three · config and rules load, skipping and logging what they cannot
parse · well-formed `stats` events reach stdout and a file · a blocked sink
provably does not stall production · CI outputs an installable `.deb`.

### Phase 1 — Capture + decode ✅
`PacketSource` with a libpcap live backend and an in-tree pcap replay source ·
`etherparse`-driven decoder for Eth/VLAN/IPv4/IPv6/TCP/UDP/ICMP · 5-tuple and
payload range · decoder-anomaly events · bounded flow table and `flow` events ·
real capture, decode, and flow counters including kernel drops · capability
dropping after the handle is open · decoder and pcap-reader fuzz targets.

**Done when:** replaying a pcap yields correct flow metadata and anomaly events
for malformed packets, and the decoder fuzz target runs clean.

### Phase 2 — Reassembly + normalization ✅
IP defragmentation with a bounded, timed-out fragment table · TCP stream
reassembly keyed on the flow table, with ACK-gated delivery · target-based
overlap policy at both levels, from config with per-host overrides ·
normalization primitives (percent-decode, double-decode, path collapse) ·
`reassembler` and `normalization` fuzz targets · an adversarial pcap fixture
covering split, out-of-order, contradicting-overlap, past-FIN, forged-RST, and
tiny-fragment cases.

**Done when:** an attack string split across segments or fragments reassembles
correctly · overlapping-segment and encoded-URI cases resolve correctly · the
reassembler fuzz target runs clean · state is provably bounded.

### Phase 3 — Native rule engine ✅ → **NIDS milestone**
Full `.rules` parsing of the §6 subset · rule grouping by header ·
`aho-corasick` MPM on `fast_pattern` · full evaluation · HTTP app-layer parser
locating the URI and feeding sticky buffers through the Phase 2 normalization
primitives · verdict → `alert` event. The engine consumes the reassembled
stream that `StreamReady` already delivers.

**Done when:** a known signature in replayed traffic produces a correct alert ·
the loader reports supported vs. skipped · the rule-parser fuzz target runs
clean.

### How detection is put together

Rules are **compiled once** at load: headers resolved from `vars`, regexes built
under a size budget. Every rule's `fast_pattern` goes into a shared
Aho-Corasick automaton **per buffer**, so one scan finds the few rules worth
evaluating. Rules with no usable pattern — header-only, or only negated content
— cannot be pre-filtered and are evaluated on every packet, which is why the
count is reported.

Evaluation walks options in written order with a per-buffer cursor, and **fails
closed everywhere**: an unfilled buffer, a `byte_test` reading past the end, a
`byte_jump` landing outside the buffer all mean *no match*. A rule on `http.uri`
must not match non-HTTP traffic just because there is no URI to contradict it.

`flowbits` side effects are collected during evaluation and applied only once
the whole rule matched, so a partial match leaves no state behind.

Stream matching uses a bounded **inspection window** per direction: patterns
must be contiguous but deliveries are not, so bytes accumulate and only the new
region plus an overlap as long as the longest pattern is re-scanned. `detect.
inspection-window` is therefore the longest content match that can ever fire on
a stream.

### `/proc` polling rather than an audit or eBPF hook

A poller misses processes that start and exit between sweeps, where a hook would
not. In exchange it needs no kernel module, no `CAP_BPF`, no auditd
configuration, and it cannot wedge the machine. Installing a sensor must never
make the host worse; an audit-backed source can be added alongside in Phase 7.

### journald read through `journalctl`, not `libsystemd`

Linking would tie the binary to a library whose presence and version vary across
distributions, against a promise of a standalone install with no prerequisites.
A missing subprocess simply means that source is unavailable and the configured
log files carry the load — which is what happens on a host without systemd
anyway.

### Correlation joins on the timestamp the event carries

For a replay that is *capture* time, deliberately (§4). It follows that
replaying a months-old capture will not correlate with host events happening
now, and that is correct rather than a bug to widen the window around.

### Rule coverage is reported in four buckets

`armed` / `awaiting support` / `failed to compile` / `skipped`. They are
different problems belonging to different people — the project's, the rule
author's, and whoever edited the file. Collapsing them into one number hides
whichever one someone needs to fix.

**Load-and-report is the default**: a sensor that will not start because one
rule is broken is a sensor watching nothing. `--strict` and `cybersentinel
validate-rules` fail loudly instead, for CI and pre-deploy gates.

### Phase 4 — HIDS core (Linux) ✅ → **first MVP**
FIM via `notify` with a SQLite baseline · journald and syslog authentication
logs · `/proc` process and listening-socket monitoring · host rules on the same
engine · local host↔network correlation.

**Done when:** a watched-file change, a failed-login burst, and a new listener
each produce a host alert unified with network alerts. `crates/cli/tests/host.rs`
drives every one of those through the real binary, plus the two that matter
most: a change made while nothing was watching, and a host event and a network
alert becoming one incident.

Still outstanding for the **MVP**: the packaging pass — `.rpm`, a musl static
build, and a systemd unit wiring the capabilities in §8.

### How host detection is put together

**Host rules share the engine's foundations, not its packet pre-filter.** They
reuse the rule model, the loader, the value-matching primitives, thresholds,
flowbits and the alert pipeline. What they do *not* reuse is header grouping and
aho-corasick — that is a packet-scale optimisation, and a host produces a
handful of events a second, not a million packets. `engine::host` selects
candidate rules by event kind and runs the primitives against named fields.

**FIM has two detectors because one is not enough.** Real-time watching has
three failure modes that all look identical from outside — like a filesystem
nobody touched: the sensor was not running, the kernel queue overflowed, or the
watch was never established. The periodic baseline rescan is what makes all
three recoverable. Overflow additionally forces an immediate rescan, is counted,
and is emitted as its own event.

**FIM runs on its own thread.** Hashing `/etc` and `/usr/bin` takes real time;
doing it on the capture thread would drop traffic and make startup look like a
hang. Scans are abandonable so shutdown does not wait for one, and an abandoned
scan reports itself as truncated — so it is never mistaken for mass deletion.

**Log parsing assumes every field is hostile**, because a username is whatever
somebody typed at a login prompt. Fields are extracted positionally and
validated rather than scavenged; a login as `admin from 10.0.0.1` does not get
to pick its own `source_address`. Control characters never reach an event, and
what cannot be a real value is flagged rather than dropped.

**Correlation requires both domains.** Two network alerts agreeing with each
other is repetition, not corroboration; raising an incident for it would launder
one noisy rule into something resembling independent agreement.

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

## 12. Working on this

```sh
cargo build --workspace
cargo test  --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings

# Run from the repo root; state lands in ./data and ./logs.
cargo run -p cybersentinel -- run --config config/config.yaml
cargo run -p cybersentinel -- run --config config/config.yaml --once   # one event, then exit

# Analyse a capture file. No privileges, no libpcap, works on any OS.
cargo run -p cybersentinel -- run --config config/config.yaml \
    --replay tests/fixtures/pcap/normal.pcap

# Live capture needs libpcap headers to build and CAP_NET_RAW to run.
sudo apt-get install libpcap-dev
python3 tests/fixtures/pcap/generate.py       # regenerate the pcap fixtures

# Analyse the adversarial capture, dumping what reassembly produced.
# --dump-streams writes captured payload to disk; it is off by default.
cargo run -p cybersentinel -- run --config config/config.yaml \
    --replay tests/fixtures/pcap/evasion.pcap --dump-streams /tmp/streams

# Fuzzing — run from INSIDE fuzz/, whose rust-toolchain.toml selects nightly.
# `cargo fuzz` resolves the toolchain from the working directory, so running it
# from the repo root picks up the root pin (stable) and fails.
cd fuzz && cargo fuzz run reassembler -- -max_total_time=60
```

**Write the test first where practical.** The decoupled-pipeline test
(`eventlog::tests::a_blocked_sink_never_stalls_the_producer`) is the model: it
asserts the property *structurally* — with the writer parked inside a sink,
exactly `capacity` further emits succeed and the rest are refused immediately —
rather than by timing, which would be flaky.

Keep commits small and reviewable. Flag anything in the guide that proves
impractical rather than diverging from it silently.
