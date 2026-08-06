# Phase 5 — the Windows port, and what has to be true before it starts

Written from a Linux machine with no Windows host and no CI remote, which is
why this is a plan and a set of decisions rather than an implementation. It
records what was settled, what was built because it could be verified here, and
what is deliberately not written yet.

## Status

The **platform-independent half** of the Windows port is written, tested, and
fuzzed: the USN journal parser and catch-up planner (`crates/hids/src/usn.rs`)
and the Security-log logon parser (`crates/hids/src/evtx.rs`). Both are pure
`&[u8]`/`&str` parsing with no Windows dependency, which is why their behaviour
could be established at all from a Linux machine.

The **FFI half** — actually calling `FSCTL_READ_USN_JOURNAL`,
`ReadDirectoryChangesW`, `EvtQuery`/`EvtRender`, ETW, `GetExtendedTcpTable` —
is not, and neither is the service, the installer, or signing. Those need a
Windows machine and a CI remote.

## Why the FFI half is not in the tree

The phase's own sequencing puts *"CI green on the Windows runner first"* at step
1, ahead of every platform feature, and says why: everything below it would
otherwise be built on assumptions. That step needs a remote this repository does
not have — no git remote, no `gh`, no credentials — and the machine building it
has no Windows host, no WSL, and no wine.

Writing `ReadDirectoryChangesW`, USN journal parsing, ETW session setup, and
`GetExtendedTcpTable` blind would produce a few thousand lines that compile at
best under mingw, that no one has run, and that would look finished. For code
whose failure mode is *silently not detecting things*, that is worse than an
empty directory: an empty directory does not get trusted.

So this phase delivered the parts that could be **proven** from here, listed
below, and stopped.

## Decisions settled (do not re-litigate)

### Npcap: detect and prompt, do not bundle

Recorded in `../third_party/README.md`. The consequence is that the Windows
*network* half has one external prerequisite, which is now stated in CLAUDE.md
§1 and the README instead of promised away. The Windows *host* half has none.

**Requirement this creates:** a sensor whose capture backend is unavailable
must report it as an unavailable source, not run quietly with a packet counter
at zero. The mechanism exists — see below.

### `unsafe_code = "forbid"` cannot hold literally, and the property it protects can

Every function in `windows`/`windows-sys` is an `unsafe fn`. CLAUDE.md §4 now
carries the decision: one opted-out backend crate that does **FFI only**, with
no parsing inside it, handing `&[u8]` to safe, fuzzed parsers outside. The
acceptance criterion should be restated as *"no first-party crate parses input
under `unsafe`"*, which is the property that was ever worth having.

### The source model, not a counter per failure mode

Phase 4 reported host coverage with one counter per failure mode —
`watch_failures`, `inotify_overflows`. That does not survive a second OS: an
exhausted `max_user_watches` has no Windows equivalent, a disabled audit policy
has no Linux one. `crates/hids/src/sources.rs` replaces it with a uniform
question — *is this source working?* — and a platform-specific reason string.

## Built and verified in this phase

| What | Verified how |
|---|---|
| Every host source reports `active`/`degraded`/`unavailable`/`unsupported` with a reason, in `stats.hids.sources` | end to end, on a running sensor |
| A platform with no backends says so instead of reporting zeroes | `platform_gaps` is a pure function of the OS name, so the **Windows and macOS answers are asserted from Linux** |
| A process sweep that can only see itself is reported as blinded, not quiet | test, confirmed to fail without the check |
| An unreadable socket table is reported separately from "no sockets" | test |
| Auth log files that do not exist are a reported hole | test |
| A FIM baseline that matched no files is a reported hole | test |
| The workspace, tests included, cross-compiles for Windows | `cargo build --workspace --tests --target x86_64-pc-windows-gnu`, and now in CI |
| The `/proc` reader and journald no longer run on Windows and contradict the registry | test + cross-compile |
| USN record parsing: bounds, totality, termination, rejection of incoherent records | 35 tests + a fuzz target, 4.2M executions clean |
| USN catch-up planning: resume vs. full rescan, including journal replacement and wrap | tests over every branch |
| Security-log 4624/4625 → `AuthEvent`, including field-injection refusal | 17 tests |

### Two things the tests changed

Both were caught by writing the test before believing the code:

* **The USN walk resynchronised on nonsense.** It stepped forward by any
  declared record length, including lengths too small to be a record, which
  landed mid-record and turned one bad length into a run of fabricated
  rejections. The fuzzer found it in seconds. The walk now stops at the first
  length that cannot belong to a real record and counts one hole.
* **"First occurrence wins" was no defence against field injection.** If the
  event renderer ever failed to escape a username, a crafted one looks like
  more fields — and `TargetUserName` is rendered *before* `IpAddress`, so the
  forged address comes first. A duplicated field is now refused outright: no
  source address beats an attacker-chosen one.

## Then, in this order

### 1. Windows CI green — the gate for everything else

`.github/workflows/ci.yml` already builds and tests on `windows-latest` with
bundled SQLite as its own named step. It has never run. The specific risk is
**rusqlite's bundled SQLite under MSVC**: it is known to compile here under
gcc, mingw-w64, and zig cc, so the gap is one toolchain, not the whole
question. If MSVC fights it, the fallback is a pure-Rust baseline store — the
baseline needs key/value lookup by path, prefix scans, and a count, which
`redb` or a sorted indexed file covers. Raise it as a decision; do not work
around it quietly.

### 2. Npcap capture behind `PacketSource`

The trait already has two implementations and the run loop already handles
`Frame`/`Idle`/`End`. Windows adds a third. `PcapReplay` is pure Rust and
already works there, so the replay tests are the parity check: a Windows
sensor should produce byte-identical events replaying the same fixture.
**That is the cheapest possible NIDS-parity proof and it needs no NIC.**

### 3. Host backends behind the source model

Each one registers itself in the `SourceRegistry` and overwrites the
`unsupported` entry `platform_gaps` put there. If a backend cannot start, it
sets `unavailable` with the reason — a disabled audit policy, a missing
privilege — and the sensor keeps running with the rest.

* **FIM real-time:** `ReadDirectoryChangesW`. It has the same overflow failure
  as inotify (`ERROR_NOTIFY_ENUM_DIR`); handle it the same way — force a
  rescan, count it, emit it. The Linux code already does this behind
  `FimWorker::handle_notification`, and `notify` covers Windows, so the first
  question is whether `notify`'s Windows backend surfaces overflow at all. If
  it does not, that is a coverage hole and must be found now, not after
  shipping.
* **FIM catch-up:** the USN journal. **The parsing and the catch-up decision
  are written** — `crates/hids/src/usn.rs`. What remains is the FFI:
  `FSCTL_QUERY_USN_JOURNAL` into `parse_journal_data`, `plan_catch_up` to
  decide resume-or-rescan, `FSCTL_READ_USN_JOURNAL` into
  `parse_read_response`, and `OpenFileById` to turn a parent reference into a
  path. Then hash the files it names — the journal says *that* a file changed,
  never *what to*, so content integrity still comes from hashing.

  **Confirm the layout constants on first contact.** They come from the
  documented `USN_RECORD_V2`/`V3` layouts, not from bytes off an NTFS volume.
  A wrong one shows up as a non-zero `rejected` count rather than as wrong
  events, which is the failure mode that was designed for — but it is still a
  failure, so check `rejected` is zero against a real journal before trusting
  anything downstream of it.
* **Auth:** Event Log 4624/4625. **The mapping is written** —
  `crates/hids/src/evtx.rs` turns a rendered event into an `AuthEvent`. What
  remains is `EvtQuery`/`EvtSubscribe` plus `EvtRender` to produce the XML it
  parses. Structured, so the `for invalid user` ambiguity documented in
  `crates/hids/README.md` does not arise — the account is a field. Note that
  4688 process auditing is **off by default**, which is why process events come
  from ETW instead; if a deployment wants 4688 anyway, its absence must be
  reported rather than looking like a host where nothing ran.
* **Process:** ETW Kernel-Process provider. **Sockets:**
  `GetExtendedTcpTable`. Both keep the `Watcher` shape: a sweep or a stream,
  producing the same `ProcessEvent`s the engine already matches on.

### 4. Service, installer, and a `verify-install` that proves the privilege model

The Linux analogue is `../linux/verify-install.sh`, and the discipline transfers
exactly: assert the model against the **running service**, not the package.

* runs as a **low-privilege service account**, not SYSTEM;
* holds **only** the expected token privileges — `SeBackupPrivilege` is the
  counterpart of `CAP_DAC_READ_SEARCH`, and the check should be *exactly* that
  set, the way the Linux one asserts `CapEff == 0x4`;
* **live capture works** through Npcap, which is what proves the privilege
  reduction did not cost the capability it was reduced around;
* it can read an **ACL-denied test file** and produce a **hash** — test for the
  hash, not the tracked row. The Linux pass proved why: without the capability,
  `/etc/shadow` was still *in* the baseline, with `hash = NULL`, so a
  same-length edit would have been missed and nothing looked wrong. Use a
  purpose-made ACL-denied file, never the SAM or any credential store;
* the service is **registered and survives a reboot** — test the behaviour.
  The Linux pass found a package that shipped a unit nobody enabled, invisible
  to every check that looked at package contents rather than at what happened.

### 5. Service hardening by measurement

The Linux pass found two sandbox settings that left the service healthy and
silently blinded a detector. The Windows equivalents exist. Add each setting
one at a time and re-verify capture, FIM, process, and sockets after each. The
source registry now makes this cheap: a blinded source says so in `stats`
instead of reporting zero.

### 6. Authenticode

Procurement, not code. EV gives immediate SmartScreen reputation; OV earns it.
Signing runs in CI once the remote exists.

## What would tell you this plan is wrong

The plan assumes `notify` surfaces `ReadDirectoryChangesW` overflow, that ETW
can be consumed without a driver, and that the USN layout constants written
from documentation match reality. Each is checkable in an hour on a Windows
machine and none is checkable here. Check them before building on them.
