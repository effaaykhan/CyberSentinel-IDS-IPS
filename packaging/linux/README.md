# Linux packaging

**Status: live.** CI builds a `.deb` and an `.rpm` on every run, installs the
`.deb`, starts the service, and verifies the capability model against the
running process.

## Building

```sh
cargo install cargo-deb cargo-generate-rpm cargo-zigbuild
# plus zig 0.13+ on PATH: https://ziglang.org/download/
sh packaging/linux/build-packages.sh
```

That produces both formats from one binary:

```
target/debian/cybersentinel_0.1.0-1_amd64.deb
target/x86_64-unknown-linux-gnu/generate-rpm/cybersentinel-0.1.0-1.x86_64.rpm
```

Package metadata lives in `crates/cli/Cargo.toml`, under
`[package.metadata.deb]` and `[package.metadata.generate-rpm]`.

## Portability: the glibc baseline

**Minimum: glibc 2.28.** That covers RHEL/Rocky/Alma 8+, Debian 10+,
Ubuntu 20.04+, and SLES 15 SP2+ — everything still in support.

This is not what you get for free. A binary built the ordinary way records the
glibc symbol versions of the machine that built it; on Ubuntu 24.04 that is
`GLIBC_2.39`, and the package then installs on Ubuntu 24.04 and refuses
everywhere older. `cargo-zigbuild` hands the link step to zig, which ships stub
definitions for every glibc version and can be told to emit references no newer
than a chosen one.

The result is still an **ordinary dynamically linked binary that links
libpcap**, so live capture works in full. That is the whole reason this is not
a static musl build: musl cannot link libpcap, and a sensor that cannot capture
is not the sensor. (A HIDS-only static variant, or `dlopen`-ing libpcap at
runtime, are possible future options — neither is this one.)

`build-packages.sh` checks both invariants rather than trusting them:

* the highest `GLIBC_*` symbol in the binary is within the baseline, and
* the binary still has a `NEEDED` entry for libpcap.

A dependency bump that quietly raised either would otherwise go unnoticed until
somebody's install failed.

### Declared dependencies

| Package | Depends |
|---|---|
| `.deb` | `libc6 (>= 2.28), libpcap0.8` |
| `.rpm` | `libpcap.so.0.8()(64bit)`, plus per-symbol `libc.so.6(GLIBC_*)` requires derived from the ELF |

The `.deb`'s dependencies are **declared, not derived**, and the reason is
worth knowing. At glibc 2.28 libpthread and libdl were still separate
libraries, so the pinned binary has `NEEDED` entries for `libpthread.so.0` and
`libdl.so.2`. Building on a modern host, `dpkg-shlibdeps` maps those sonames to
the merged `libc6` that provides them as stubs and concludes `libc6 (>= 2.34)`
— a portability build defeated by its own packaging metadata. RPM derives
per-symbol-version requires straight from the ELF and gets 2.28 right on its
own, so it is left to do that.

`libpcap0.8` rather than `libpcap0.8t64`: Ubuntu 24.04 renamed the package for
the time64 transition but declares `Provides: libpcap0.8`, so the old name
resolves everywhere.

## What the packages install

| Path | Source | Notes |
|---|---|---|
| `/usr/bin/cybersentinel` | the built binary | the sensor |
| `/etc/cybersentinel/config.yaml` | `packaging/linux/config.yaml` | conffile — survives upgrades |
| `/etc/cybersentinel/rules/cybersentinel.rules` | `rules/cybersentinel.rules` | conffile |
| `/usr/lib/systemd/system/cybersentinel.service` | `cybersentinel.service` | registered by the generated maintainer scripts |
| `/etc/logrotate.d/cybersentinel` | `logrotate` | event logs are PII; rotate and expire them |
| `/usr/share/doc/cybersentinel/verify-install.sh` | `verify-install.sh` | the §8 checks, runnable on your own machine |
| `/var/lib/cybersentinel` | — | systemd `StateDirectory`; holds the sensor id and the FIM baseline |
| `/var/log/cybersentinel` | — | systemd `LogsDirectory` |

The unit is **enabled but not started**: review
`/etc/cybersentinel/config.yaml`, then `systemctl start cybersentinel`. A
sensor should begin watching because an operator decided it should, not because
a package manager did.

### `maintainer-scripts` is load-bearing

`[package.metadata.deb]` points `maintainer-scripts` at an almost-empty
directory, and that is not decoration. cargo-deb's `generate_scripts` returns
early when the key is unset, so `systemd-units` on its own installs the unit
file and generates **nothing** to register it — no `daemon-reload`, no
`enable`. The package looks correct in `dpkg-deb --contents`, and the sensor
silently fails to come back after a reboot. It shipped that way from Phase 0
until an install-and-check step caught it.

The RPM's equivalents are the `rpm-*.sh` scriptlets, named directly from
`[package.metadata.generate-rpm]`.

## Verifying an install

```sh
sudo sh /usr/share/doc/cybersentinel/verify-install.sh
```

CLAUDE.md §8 makes four claims about privilege. A document cannot be wrong in a
way anyone notices, so this script makes them falsifiable, against a running
service:

1. the service runs as a dedicated unprivileged user;
2. at steady state it holds **exactly** `CAP_DAC_READ_SEARCH` — `CAP_NET_RAW`
   and `CAP_NET_ADMIN` were used to open the capture handle and then dropped,
   permitted set included, so they cannot be regained;
3. **live capture still works**, which is the point of dropping them after the
   open rather than never taking them. Proving the drop without proving capture
   would be proving the sensor is safely useless;
4. `/etc/shadow` is hashed into the FIM baseline — the thing
   `CAP_DAC_READ_SEARCH` was retained for.

It exits non-zero on the first failure, so it can gate a deployment. It also
waits — bounded — for a fresh stats event and for the first baseline scan,
rather than sleeping a fixed interval: a check that fails on a healthy sensor
gets ignored, which ends in the same place as no check at all.

### What it catches, demonstrated

Removing `CAP_DAC_READ_SEARCH` from the unit while leaving capture working is
the subtle failure, and it is worth seeing what it actually looks like. The
sensor starts. Capture runs. The baseline fills up. `/etc/shadow` is *in* it —
with `hash = NULL`, tracked by metadata alone, so a same-length edit to it
would be missed entirely and nothing would appear wrong.

That is the whole argument for the capability in one row of a table, and it is
why the check tests for a hash rather than for the file's presence.

## Service design

`cybersentinel.service` uses `DynamicUser=yes`, so systemd allocates and owns
the service account: no `useradd` in a maintainer script, no orphaned account
after removal.

The capability set is **temporal**. `CAP_NET_RAW` and `CAP_NET_ADMIN` are
needed once, to open the capture socket, and the sensor drops them itself
immediately afterwards. `CAP_DAC_READ_SEARCH` is needed for the process's whole
life, because host monitoring goes on reading and hashing files it does not
own. So the ambient set grants all three at launch and steady state is only the
last one.

Beyond that, the usual `Protect*`/`Restrict*` set, plus
`SystemCallFilter=@system-service` and
`RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_PACKET`.

Every directive was added **one at a time** and re-verified against a running
sensor — live capture, the FIM baseline, real-time file events, `/proc` sweeps,
listening-socket detection, and the `journalctl` child. Two plausible ones
failed and are named in the unit with the reason rather than quietly omitted:

* **`ProtectProc=invisible`** — the service starts, capture works, FIM works,
  and process monitoring reports nothing at all, because the only process it
  can still see is its own.
* **`ProcSubset=pid`** — hides `/proc/net/tcp`, so listening-socket detection
  stops. A new backdoor listening on a port is the host signal that matters
  most.

Both are the failure mode this project exists to avoid: a detection feature
switched off without anything failing. That is why the sandbox was built by
measurement rather than by copying a hardening checklist.

`AF_INET`/`AF_INET6` are deliberately absent until the Phase 7 webhook sink
needs them — with a check that shows it does.

## Inline prevention: measure before you arm

`sudo sh packaging/linux/measure-prevention.sh` puts real traffic through a
real queue and reports what the sensor costs. Measured on this project's
development host — 8 cores, loopback, ~283,000 packets:

| | value |
|---|---|
| mean verdict latency | **31 µs** |
| worst | 5.3 ms |
| verdicts over 10 ms | **0** |
| peak queue depth | 52 of 1024 |
| packets never judged | **0** |

Latency was never the problem. What the measurement found was **1.3% of
packets never reaching a verdict at all**, and the first diagnosis of it was
wrong — which is worth recording, because the wrong fix looked like it worked.

An `iperf3` run left **3,566 of ~283,000 packets `user_dropped`**: discarded
between the kernel and the sensor. The queue never went deeper than five of
1024, so `queue-length` was never the constraint. Raising
`net.core.rmem_default` from 208 KB to 8 MB took it to zero, which looked like
the answer.

It was not the cause. NFQUEUE copies the **whole packet** to userspace by
default, and the verdict path reads at most 64 bytes of it — an IP header and
two ports. Copying headers only takes the count to **zero at the stock 208 KB
buffer**, because the bytes crossing netlink fall by three orders of magnitude.
The sensor now sets a 128-byte copy range at bind time.

The trade is visible and worth knowing: packets that used to be dropped are now
queued and judged, so peak depth went from 5 to 52 and worst-case latency from
1 ms to 5 ms. Complete coverage costs tail latency.

**Watch `stats.prevent.queue_unjudged`.** It is the count of packets the kernel
disposed of before the sensor could judge them — forwarded **unexamined** under
fail-open, **dropped** under fail-closed — and the sensor cannot see them from
the inside, which is why it reads them back out of
`/proc/net/netfilter/nfnetlink_queue`. A rising value is the only warning you
get. `sysctl -w net.core.rmem_default=8388608` buys extra headroom for bursts
on top of the copy reduction.

### Soak: does it drift?

`sudo sh packaging/linux/soak-prevention.sh 180` answers the different question
a burst cannot — whether anything *grows*. An IPS holds state per condemned
flow and per blocked source, and both are fed by whoever is attacking, which is
the shape of a leak an attacker gets to trigger.

180 seconds, 4,200,000 packets judged (~23k pps sustained):

| | |
|---|---|
| mean latency, first tenth of the run | 11.8 µs |
| mean latency, last tenth | **11.7 µs** |
| worst | 4.9 ms |
| verdicts over 10 ms | **0** |
| peak queue depth | 1 |
| packets never judged | **0** |
| RSS, start → end | 7048 → 7060 kB |

The early-versus-late comparison is the point: a cumulative mean would average a
slow climb away against the first quiet minute, so the script recomputes the
mean per interval and compares the ends. Flat latency, flat memory, nothing
unjudged.

**What this soak does not cover:** nothing matched, so the verdict *store* was
empty throughout — it measures the path, not state growth under sustained
blocking. That is covered deterministically instead, by
`an_hour_of_continuous_blocking_stays_bounded_and_drains` in
`crates/prevent`, which runs a simulated hour of blocking and asserts the
tables stay bounded, never hold anything past its expiry, and drain to zero.
Simulated time, so it runs in milliseconds and runs in CI.

**What loopback cannot tell you.** No NIC, no driver, no interrupt path, and a
higher packet rate than most links. It stresses the verdict path harder than a
real segment and says nothing about behaviour behind a saturated interface.
Re-run this on the real path before arming.

## Still to do

* **arm64.** The build pins `x86_64-unknown-linux-gnu`; `aarch64` needs the
  same treatment and a runner to test on.
* **Package signing.** Both packages are unsigned. A repository, a signing key,
  and a key-rotation story are their own piece of work.
* **An apt/dnf repository**, if distribution beyond direct downloads is wanted.

## Uninstall

```sh
sudo apt-get remove cybersentinel     # keeps /etc/cybersentinel
sudo apt-get purge  cybersentinel     # removes it too
sudo dnf remove cybersentinel
```

Event logs under `/var/log/cybersentinel` are deliberately left in place: they
are evidence, and removing a package should not destroy an audit trail.
