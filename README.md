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

## Status: Phase 4 complete — both halves of the sensor

**The sensor detects on the host and on the wire, and joins the two.** Rules
written in CyberSentinel's own format are compiled and matched against
reassembled network traffic *and* against file changes, authentication records,
and process activity — and when both halves see the same thing, it is reported
as one incident rather than two log lines.

**The Linux MVP is complete**: a `.deb` and an `.rpm`, a hardened systemd
service, and a check that verifies the privilege model on the installed sensor
rather than asserting it in a document.

What works today:

* **Packet capture** — live via libpcap (Linux, macOS), or replaying a `.pcap`
  file with no privileges and no system library at all;
* **L2–L4 decoding** — Ethernet, VLAN and QinQ, IPv4, IPv6 with extension
  headers, TCP, UDP, ICMP — to a 5-tuple and a zero-copy payload range;
* **decoder anomalies** as first-class events: malformed packets are detection
  signal, not parse failures to swallow;
* **IP defragmentation and TCP stream reassembly**, with a **target-based
  overlap policy** so the sensor resolves contradictory data the way the
  destination host will — and counts the times they disagreed;
* **normalization primitives** — percent-decoding, double-decoding, path
  collapse — so `/foo/../etc/passwd` and `%252e%252e%252fetc/passwd` are the
  same request;
* **flow tracking** with hard caps and idle timeouts, emitting `flow` events;
* **real counters** — kernel drops, decode classification, flow evictions,
  reassembly conflicts, ignored resets — in every `stats` event;
* **a detection engine** — rules compiled once, an Aho-Corasick pre-filter over
  every rule's fast pattern, then full evaluation of `content` and its
  modifiers, `pcre`, `flow`, `flowbits`, `byte_test`, `byte_jump`, `dsize` and
  `threshold`;
* **an HTTP parser** filling the `http.uri`, `http.header`, `http.user_agent`,
  `http.method` and `http.host` sticky buffers — with the URI **normalized**, so
  one rule matches every spelling of the same request;
* **file integrity monitoring** — real-time inotify watching over a configured
  set of critical paths, paired with a **periodic baseline rescan** whose hashes
  live in SQLite. The rescan is not a nicety: watching alone misses everything
  changed while the sensor was down, everything the kernel dropped on queue
  overflow, and everything under a path whose watch could not be established —
  and all three look exactly like a filesystem nobody touched. Queue overflow
  forces an immediate rescan, is counted, and is **reported**;
* **authentication log monitoring** — journald (preferred, because its records
  carry the service as a structured field) and syslog files, parsed on the
  assumption that every field is hostile, because a username is whatever
  somebody typed at a login prompt;
* **process and listening-socket monitoring** from `/proc`, where a new listener
  appearing is the signal that matters;
* **host rules** in the same `.rules` files, on the same engine, matching
  `file.path`, `file.change`, `auth.outcome`, `auth.user`, `process.name` and
  more — with the same thresholds and the same alert pipeline;
* **host↔network correlation** — a file change and a network alert on the same
  host inside the window become one `incident` with both as contributors. An
  incident requires evidence from *both* halves: two network alerts agreeing
  with each other is repetition, not corroboration;
* `cybersentinel validate-rules`, which exits non-zero on a broken or
  over-budget rule so a pipeline can gate on rule quality;
* matrix CI on Linux, Windows, and macOS that replays the fixtures, runs the
  evasion suite under both overlap policies, fuzzes every parser, and builds,
  installs, and runs a Linux `.deb`.

---

## Try it

Analyse a capture file — no privileges, no libpcap, any OS:

```sh
cargo build --workspace
cargo run -p cybersentinel -- run --config config/config.yaml \
    --replay tests/fixtures/pcap/normal.pcap
```

```
{"timestamp":"2024-01-01T00:00:00.600000Z","event_type":"flow","flow_id":17613525333215950991,
 "src_ip":"192.0.2.10","src_port":51000,"dest_ip":"198.51.100.20","dest_port":80,"proto":"TCP",
 "flow":{"reason":"closed","duration_ms":600,"packets_to_server":4,"bytes_to_server":267,
         "packets_to_client":3,"bytes_to_client":202,"tcp_flags":"FSPA"}}
```

Malformed traffic is reported rather than silently dropped:

```sh
cargo run -p cybersentinel -- run --config config/config.yaml \
    --replay tests/fixtures/pcap/malformed.pcap
```

```
{"event_type":"anomaly","src_ip":"192.0.2.10","dest_ip":"198.51.100.20",
 "anomaly":{"anomalies":[{"layer":"ipv4","kind":"length_mismatch"}],
            "interface":"…/malformed.pcap","captured_len":61,"packet_len":61}}
```

## Evasion resistance

An attacker who can make the sensor and the destination host disagree about what
was sent walks past every rule — silently. So overlapping data that
**contradicts** itself is resolved the way the *destination* will resolve it,
and that is configured rather than guessed:

```yaml
reassembly:
  overlap-policy: first        # first (Linux, BSD) | last (older Windows)
  host-policies:               # per-destination overrides, longest prefix wins
    - network: 10.1.0.0/16
      policy: last
```

The same capture, read two ways:

```sh
cargo run -p cybersentinel -- run --config config/config.yaml \
    --replay tests/fixtures/pcap/evasion.pcap --dump-streams /tmp/streams
```

| Policy | What the reassembled stream says |
|---|---|
| `first` | `XXXXXXXX-TAIL` |
| `last` | `ATTACKED-TAIL` |

Those are the same bytes on the wire. Which one the server acts on depends on
its TCP stack, which is why the sensor has to be told.

`--dump-streams` writes reassembled payload to disk and is **off by default** —
it is a debugging aid, and reassembled traffic is personal data.

Or start it as a sensor:

```sh
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

Drop `--once` to run until Ctrl-C.

## Host monitoring

Host monitoring is on by default and needs no capture source: a sensor doing
file integrity and authentication monitoring alone is a normal install, not a
degraded one. `hids.fim.paths` in `config.yaml` is the whole scope — keep it
short, because every watched directory consumes one of the kernel's finite
`max_user_watches`, and a sensor that exhausts them degrades the host it exists
to protect.

Reading and hashing files it does not own — `/etc/shadow` is mode 0640 — means
the sensor **retains** `CAP_DAC_READ_SEARCH` where the network path drops
everything. The full capability set, and why each entry is or is not in it, is
in [`CLAUDE.md`](CLAUDE.md) §8. Notably absent: `CAP_SYS_PTRACE`. It would let
the sensor attribute a listening socket to another user's process, and it would
also let it ptrace anything on the box; the socket is reported either way, with
the owner shown as `unknown`.

## Live capture

Live capture links against **libpcap** (present by default on Linux and macOS;
Npcap on Windows from Phase 5) and needs `CAP_NET_RAW` to open the handle —
which the sensor drops immediately afterwards. Replaying a `.pcap` file needs
neither. See [`crates/capture/README.md`](crates/capture/README.md).

```sh
sudo apt-get install libpcap-dev     # to build
```

Then set `capture.enabled: true` in `config.yaml`.

## Install (Linux)

```sh
sudo dpkg --install cybersentinel_*.deb     # Debian, Ubuntu
sudo dnf install  cybersentinel-*.rpm       # RHEL, Fedora, SUSE

sudoedit /etc/cybersentinel/config.yaml
sudo systemctl start cybersentinel
```

The unit is enabled but not started by the package: review the installed config
first. A sensor should begin watching because you decided it should.

**Supported distributions: glibc 2.28 and newer** — RHEL/Rocky/Alma 8+,
Debian 10+, Ubuntu 20.04+, SLES 15 SP2+. Both packages come from one binary
that still links libpcap, so live capture works everywhere; see
[`packaging/linux/README.md`](packaging/linux/README.md) for why that is not a
static build.

To build them yourself:

```sh
cargo install cargo-deb cargo-generate-rpm cargo-zigbuild
sh packaging/linux/build-packages.sh
```

### Verifying the install

```sh
sudo sh /usr/share/doc/cybersentinel/verify-install.sh
```

A privilege model nobody checks is a privilege model nobody knows is wrong, so
the checks ship with the package. They assert, against the running service,
that it runs as a dedicated unprivileged user, that it holds **exactly**
`CAP_DAC_READ_SEARCH` at steady state, that live capture still works anyway —
and that `/etc/shadow` is hashed into the file-integrity baseline, which is the
whole reason that one capability is kept.

---

## Layout

| Path | What |
|---|---|
| `crates/common` | event schema, config loader, event pipeline, sensor identity |
| `crates/capture` | `PacketSource`: libpcap live capture and in-tree pcap replay |
| `crates/decode` | L2–L4 decoding and decoder anomalies |
| `crates/reassembly` | IP defragmentation, ACK-gated TCP reassembly, normalization |
| `crates/rules` | `.rules` parser, rule model, loader |
| `crates/applayer` | the HTTP parser and its sticky buffers |
| `crates/engine` | rule compilation, the packet path, and the direct host evaluator |
| `crates/hids` | file integrity, authentication logs, `/proc` monitoring |
| `crates/correlation` | joining host and network evidence into incidents |
| `crates/storage` | stdout and file event sinks |
| `crates/cli` | the `cybersentinel` binary |
| `crates/alerting` | later delivery stages, as a compiling stub |
| `rules/` | the default ruleset |
| `config/` | `config.yaml` for running from the repo |
| `packaging/` | per-OS installers |
| `fuzz/` | `cargo-fuzz` targets |
| `tests/fixtures/` | rule and pcap fixtures, with the generator that builds them |

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
