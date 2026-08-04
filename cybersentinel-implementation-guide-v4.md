# CyberSentinel-IPS — Implementation Guide (v3: native engine, Suricata format, standalone IDS)

A **fully standalone**, locally-installed **HIDS + NIDS** sensor for **Windows, Linux, and macOS**,
shipped as **self-contained native installers**, powered by a **native detection engine built from
scratch in Rust** that consumes **Suricata-format rules and configuration** and emits **EVE JSON**.
**Detection-only (IDS) for v1**; prevention is a documented future extension. Built with Claude Code.

> Decisions locked from the planning questions:
> - **Native engine**, not bundled Suricata — but rules/config are **Suricata format** and output is EVE JSON.
> - **Detect-only (IDS) first** — no inline prevention, drivers, or extension-signing in v1.
> - **Fully standalone per host** — no central server; each install is self-sufficient (can forward
>   to an existing SIEM).

---

## 1. Scope & the honest reality of a native engine
You are building the classic IDS pipeline yourself:

`capture → decode → IP-defrag + TCP-reassembly + normalization → rule-group → multi-pattern scan → full evaluation → EVE alert`

plus host sensors (FIM, log/auth, process) — all in one standalone, installable, signed binary per OS.

**Set expectations up front:** a native engine that runs *all* of ET Open is a long-term goal, not a
milestone. **Rule coverage is gated by keyword and app-layer coverage.** Implement a practical subset
first and have the rule loader **skip and log** rules it can't yet evaluate; grow coverage over time.

**Initial rule-language subset (Phase 3):** headers (action/proto/src/dst/direction with variables);
`content` + `nocase`/`offset`/`depth`/`distance`/`within`; `fast_pattern`; `flow`; `flowbits`;
`pcre`; `byte_test`/`byte_jump`; `dsize`; `threshold`/`detection_filter`; sticky buffers
`http.uri`/`http.header`/`http.user_agent`; and metadata (`sid`/`rev`/`classtype`/`msg`/`metadata`).
**App-layer order:** HTTP first (unlocks the most rules), then DNS, then TLS.

Why this is tractable in Rust: `aho-corasick` is your multi-pattern matcher, `etherparse` is your safe
decoder, `notify` is cross-platform FIM, `regex`/`pcre2` are your rule regexes, `serde_*` handle
YAML/JSON. You implement the reassembler, normalizer, rule parser, and evaluation logic; the riskiest
primitives are provided.

---

## 2. Technology stack

| Concern | Choice | Notes |
|---|---|---|
| **Language** | **Rust** (Cargo workspace; static binary via musl on Linux) | your code parses hostile input at every stage — safety is decisive here |
| **Packet capture** | `pcap` / `pnet` behind a `Capture` trait | Linux AF_PACKET · Windows **Npcap** (bundle installer) · macOS BPF |
| **Decode (L2–L4)** | **`etherparse`** | safe Eth/IP/TCP/UDP/ICMP parsing; extract 5-tuple; emit decoder anomalies |
| **Reassembly + normalization** | **custom** (bounded state + timeouts) | IP defrag, TCP stream reassembly with target-based overlap policy, HTTP normalization first |
| **Multi-pattern matcher** | **`aho-corasick`** | the `fast_pattern` MPM — single-pass scan of all patterns |
| **Rule regex** | **`regex`** (safe subset) or **`pcre2`** (full PCRE for ET Open compat) | tradeoff: pick `pcre2` where rules need PCRE-only features |
| **Rule parser** | **`nom`** or hand-written | parses Suricata `.rules` syntax into a rule model |
| **App-layer parsers** | custom: HTTP → DNS → TLS | feed sticky buffers; gate rule coverage |
| **Config** | **`serde_yaml`** for a `suricata.yaml` subset | |
| **Output** | **EVE JSON** (`serde_json`), extended with host events | one schema, host + network |
| **Flow state** | `dashmap`/custom, keyed on 5-tuple, **bounded** | |
| **HIDS FIM** | **`notify`** (inotify / FSEvents / ReadDirectoryChangesW) | cross-platform, real-time |
| **Local storage** | SQLite + on-disk EVE log + PCAP ring | self-sufficient per host |
| **Alert delivery** | file / syslog / webhook | standalone; can feed an existing SIEM — no central server we build |
| **Service** | `windows-service` · systemd unit · launchd plist | |
| **Packaging / fuzzing** | `cargo-deb`, WiX/Inno, pkgbuild; **`cargo-fuzz`** | see §5–6 |

---

## 3. Architecture (standalone sensor)
One installed binary per host, self-contained, containing:
- **Capture** (trait + per-OS backend) → **Decode** (etherparse) → **Reassembly/Normalization**
  (custom, bounded) → **Detection engine** (rule model + `aho-corasick` MPM + full evaluation +
  flow/flowbits/thresholds) → **EVE alert**.
- **App-layer parsers** (HTTP → DNS → TLS) feeding sticky buffers to the engine.
- **Host sensors** — FIM (`notify`), log/auth (auditd/journald · ETW/Event Log · unified log/OpenBSM),
  process monitoring — emitting EVE host events into the same pipeline.
- **Correlation** — local dedupe + host/network correlation by host/flow/time; optional local anomaly
  scoring (alert-only).
- **Local storage** — EVE log, flow store (SQLite), PCAP ring.
- **Alert delivery** — file/syslog/webhook to whatever you already run.
- **Local control** — CLI + config only. No central console (standalone by design).

### 3.1 Suricata-format strategy
- **Network rules:** your parser reads genuine Suricata `.rules` (curated ET Open subset) + a
  `suricata.yaml` subset + `threshold.config`. Unsupported rules are skipped and logged.
- **Host rules:** a **Suricata-compatible convention** (same file format, `sid`/`rev`/`classtype`/
  `metadata`, SID ≥ 1,000,000, thresholds) with host-event match keywords, evaluated by the host
  rule engine.
- **Output:** **EVE JSON everywhere** (`alert`, `flow`, `http`, `dns`, `tls`, `fim`, `auth`,
  `process`, `stats`).

### 3.2 Repository layout (Rust workspace)
```
cybersentinel-IPS/
  CLAUDE.md
  cybersentinel-implementation-guide-v3.md
  Cargo.toml                      # workspace
  crates/
    common/                       # EVE schema, config (suricata.yaml) loader, logging, types
    capture/                      # Capture trait + AF_PACKET / pcap / Npcap / BPF backends
    decode/                       # etherparse-based decoder: L2–L4, 5-tuple, decoder anomalies
    reassembly/                   # IP defrag + TCP reassembly + normalization (HTTP first)
    applayer/                     # HTTP → DNS → TLS parsers feeding sticky buffers
    rules/                        # Suricata .rules parser + rule model
    engine/                       # rule grouping + aho-corasick MPM + full eval + flow/flowbits/thresholds
    hids/
      fim/  logs/  process/
      platform/{linux,windows,macos}/
    correlation/                  # dedupe, correlate, optional anomaly scoring
    storage/                      # eve sink, flow store (sqlite), pcap ring
    alerting/                     # file / syslog / webhook delivery
    cli/                          # `cybersentinel` standalone sensor binary
  rules/                          # Suricata .rules (curated ET Open subset) + host-rule convention
  config/                         # suricata.yaml, cybersentinel.yaml, threshold.config
  packaging/
    windows/   (WiX / Inno)       # .msi/.exe + Windows Service + Authenticode signing
    linux/     (cargo-deb / fpm)  # .deb/.rpm/AppImage + systemd unit
    macos/     (pkgbuild / dmg)   # .pkg/.dmg + launchd + Developer ID + notarization
    third_party/                  # Npcap installer (Windows), ET Open snapshot
  fuzz/                           # cargo-fuzz targets: decoder, reassembler, rule parser
  tests/                          # pcap fixtures, integration, adversarial/evasion
  .github/workflows/              # matrix CI: build + test + package + sign per OS
```

---

## 4. Host visibility per OS (full, real-time)
- **Linux:** FIM via `notify` (inotify)/fanotify; auth/log via **auditd** + **journald**; processes
  via `/proc`. **systemd** service.
- **Windows:** FIM via `notify` (ReadDirectoryChangesW) / **USN journal**; events via **ETW** +
  **Windows Event Log** (+ **Sysmon** if present). **Windows Service**.
- **macOS:** FIM via `notify` (**FSEvents**); events via **unified logging** + **OpenBSM**. **launchd**
  daemon. (Deep process/network host events via **Endpoint Security** are a future option requiring an
  Apple entitlement + System Extension + notarization.)

Host detections map into EVE host event types and flow through the same pipeline as network alerts.

---

## 5. Packaging, signing & distribution (core workstream)
Each OS phase ends in a signed, installable artifact.
- **Windows:** build the `.exe`; wrap in **.msi (WiX)** or **.exe (Inno/NSIS)**; register a **Windows
  Service**; **Authenticode sign** (OV/EV cert aids SmartScreen); **bundle the Npcap installer**
  (confirm its license); auto-update + uninstaller.
- **Linux:** **static** binary (musl); **.deb** (`cargo-deb`) + **.rpm** (`fpm`) + AppImage/tarball;
  **systemd** unit; optional apt/yum repo.
- **macOS:** **universal** binary (arm64 + x86_64 via `lipo`); **.pkg**/**.dmg**; **launchd** daemon;
  **Developer ID sign + notarize + staple**.
- **Cross-cutting:** embed default rules/config; code-sign on every OS; single self-contained binary;
  auto-update; service auto-start; documented uninstall. macOS may need BPF-device permissions at
  install; Windows needs Npcap present (bundle it).

**Licensing to verify:** Npcap (custom license) for Windows capture, and the ET Open ruleset's
redistribution terms if you ship a snapshot. (No Suricata binary is bundled in this design.)

---

## 6. Cross-cutting engineering principles (parser security is paramount here)
Because the engine is hand-built and eats hostile input at every stage:
- **Fuzz the decoder, reassembler, and rule parser** with `cargo-fuzz` — non-negotiable; a crash here
  is a vulnerability in your security tool.
- **Bound all reassembly/flow state** with per-flow + global caps and timeouts (DoS resistance).
- **Normalize before matching; target-based overlap policy** (this is the evasion-resistance core we
  discussed — get it right or attacks slip past silently).
- **Decouple logging from the fast path** (lock-free queue → writer; never block on I/O).
- **UTC + NTP timestamps** on every event; **always record the action taken** (`alerted`).
- **Least privilege:** open the capture socket, then drop privileges.
- **Graceful rule loading:** skip + log unsupported rules; never fail the whole load on one bad rule.
- **Treat captured data as PII** (access control, retention). **Self-protect** the installed service.

---

## 7. Phase-by-phase plan (engine built incrementally)
Each "Done" doubles as an acceptance test. Test each stage against pcap fixtures.

### Phase 0 — Foundations, scaffolding & packaging pipeline
Cargo workspace + layout (§3.2); `CLAUDE.md`; **config loader** (`suricata.yaml` subset via serde) +
`.rules` **parser stub**; **shared EVE JSON schema + emitter**; decoupled logging; runnable
`cybersentinel` binary emitting `stats` EVE events; **matrix CI (Linux/Windows/macOS) that builds,
tests, and produces at least one installable artifact** (Linux `.deb` via `cargo-deb`).
**Done:** binary runs on all three OSes; emits valid `stats` EVE JSON; CI builds all targets + outputs
an installable Linux package.

### Phase 1 — Capture + Decode (Linux)
`Capture` trait + AF_PACKET backend; **`etherparse` decoder** for Eth/IP/TCP/UDP/ICMP; 5-tuple
extraction; **decoder anomaly events**; flow/packet metadata → EVE.
**Done:** replaying a pcap yields correct decoded flow metadata + decoder-anomaly events for malformed
packets; a fuzz target on the decoder runs clean.

### Phase 2 — Reassembly + Normalization
**IP defragmentation**, **TCP stream reassembly** (bounded state, timeouts, target-based overlap
policy), and **HTTP normalization** (URI canonicalization). This is the evasion-resistance core.
**Done:** an attack string split across TCP segments / fragments is reassembled into the correct
stream; overlapping-segment and encoded-URI test cases resolve correctly; reassembler fuzz target
runs clean; state is provably bounded.

### Phase 3 — Native rule engine (Suricata format) → **NIDS milestone**
Suricata **`.rules` parser** (subset in §1) + `suricata.yaml` loader; **rule grouping by header**;
**`aho-corasick` multi-pattern matcher** (`fast_pattern`); **full evaluation** (content modifiers,
`pcre`, `flow`, `flowbits`, sticky buffers, `byte_test`, `threshold`); verdict → EVE `alert`. Load a
curated **ET Open subset**; skip + log unsupported rules. HTTP app-layer parser feeds `http.*` buffers.
**Done:** a known signature in replayed traffic produces a correct EVE alert; the rule loader reports
supported vs. skipped rules; rule-parser fuzz target runs clean. **You now have a working native NIDS
on Linux consuming Suricata-format rules.**

### Phase 4 — HIDS core (Linux) → **first MVP**
Native **FIM** (`notify`), **auditd/journald** auth & log monitoring, process monitoring; **host rules**
in the Suricata-compatible convention; EVE host events; local correlation of host + network.
**Done:** watched-file change / failed-login burst / new listener each produce a host alert unified
with network alerts. **MVP = installable standalone Linux sensor: native engine, NIDS + HIDS,
Suricata-format rules.**

### Phase 5 — Windows port + `.msi`/`.exe` installer
Npcap capture (bundled); FIM via ReadDirectoryChangesW/USN; ETW/Event Log; **Windows Service**;
package **.msi/.exe**; **Authenticode signing**.
**Done:** signed Windows installer runs NIDS + HIDS as a service, at parity with Linux.

### Phase 6 — macOS port + `.pkg`/`.dmg` installer
BPF capture; FIM via FSEvents; unified log/OpenBSM; **launchd** daemon; universal binary; **.pkg/.dmg**
with **Developer ID signing + notarization**.
**Done:** notarized macOS installer runs NIDS + HIDS as a daemon, at parity with the others.

### Phase 7 — Correlation, analytics & alert delivery (deepened)
Richer correlation/dedupe/severity; optional **anomaly scoring** as a separate, alert-only path
(respect the base-rate fallacy); alert delivery to file/syslog/webhook for your existing SIEM.
**Done:** a network exploit attempt + a host file change on the same host surface as one incident and
are delivered to your chosen sink.

### Phase 8 — Hardening, evasion testing, performance
Broad **`cargo-fuzz`** coverage (decoder, reassembler, app-layer, rule parser); **adversarial/evasion
suite** (fragmented/overlapping/encoded/low-and-slow — verify reassembly holds); perf under load with
**drop-rate monitoring**; state-exhaustion resistance; grow rule/app-layer coverage (DNS, TLS); service
self-protection; secure auto-update.
**Done:** low measured drop rate under target load; evasion suite doesn't bypass detection; fuzzing
finds no crashes; expanded ET Open coverage.

> **Future (out of scope for v1):** inline prevention (NFQUEUE/WFP/NetworkExtension + driver/extension
> signing) and, if ever needed, an optional central console. The architecture leaves room for both.

---

## 8. MVP & sequencing
**MVP:** installable **standalone Linux** sensor — Phases 0 → 1 → 2 → 3 → 4 — with the native engine
(Suricata-format rules) doing NIDS + HIDS and unified EVE alerts. Then Windows (5), macOS (6), deepen
correlation/delivery (7), harden + grow coverage (8). Ship the Linux MVP before porting.

---

## 9. Risks & honest caveats
- **Native engine scope:** full ET Open coverage is a long tail gated by keyword + app-layer support;
  ship a subset and grow it. This is the single biggest effort in the project.
- **Parser security:** a hand-built engine is only as safe as its parsers — fuzz relentlessly.
- **Evasion resistance rides on reassembly/normalization** — the hardest correctness problem here.
- **Code-signing gates:** Windows Authenticode, macOS Developer ID + notarization — budget time/cost.
- **Licensing:** Npcap (Windows capture) and any bundled ET Open snapshot — verify redistribution.
- **Performance:** dropped packets = silent coverage holes; monitor drop counters from Phase 1.
- **Build vs. adopt:** Suricata already does all this superbly; building your own is justified for
  learning, control, or a specific unmet need.

---


