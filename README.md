# CyberSentinel-IPS

A **standalone intrusion detection and prevention sensor**. One installed
binary per host does both **host-based** monitoring (file integrity,
authentication logs, processes) and **network-based** monitoring, with no
central server to run and no agent framework to deploy.

* **Its own engine.** The detection pipeline is written from scratch in Rust —
  no third-party detection engine is bundled or wrapped.
* **Its own formats.** CyberSentinel `.rules` for detection content,
  `config.yaml` for configuration, newline-delimited JSON for output.
* **Standalone.** Each install is self-sufficient. It can forward events to a
  SIEM you already run; it ships no console of its own.
* **Detection by default, prevention when you arm it.** Out of the box it
  alerts and never touches traffic. Inline blocking is a config change you make
  deliberately, with a kill switch — see [Inline prevention](#inline-prevention-ips-mode).

---

## Platform support

| | Network monitoring | Host monitoring | Inline prevention |
|---|---|---|---|
| **Linux** | yes | yes | yes (NFQUEUE) |
| **Windows** | — | — | — |
| **macOS** | — | — | — |

Linux is complete and is what this guide covers. The sensor builds and its
tests pass on Windows and macOS, but the platform backends for those aren't
written yet — a build there reports each event source as `unsupported` rather
than quietly reporting nothing.

**Supported distributions: glibc 2.28 and newer** — RHEL/Rocky/Alma 8+,
Debian 10+, Ubuntu 20.04+, SLES 15 SP2+.

---

## Install

```sh
sudo dpkg --install cybersentinel_0.2.1-1_amd64.deb     # Debian, Ubuntu
sudo dnf install cybersentinel-0.2.1-1.x86_64.rpm       # RHEL, Fedora, SUSE
```

Both packages pull in **libpcap** as a dependency; live capture needs it.

The service is **enabled but not started**. That's deliberate — review the
config before the sensor begins watching:

```sh
sudo systemctl start cybersentinel-ips
```

### What gets installed

| Path | What |
|---|---|
| `/usr/bin/cybersentinel` | the sensor |
| `/etc/cybersentinel/config.yaml` | configuration (survives upgrades) |
| `/etc/cybersentinel/rules/cybersentinel.rules` | the default ruleset (survives upgrades) |
| `/usr/lib/systemd/system/cybersentinel-ips.service` | the service unit |
| `/etc/logrotate.d/cybersentinel` | log rotation — event logs are personal data |
| `/usr/share/doc/cybersentinel/verify-install.sh` | privilege-model checks |
| `/var/lib/cybersentinel` | sensor id and the file-integrity baseline |
| `/var/log/cybersentinel` | event log |

---

## Configuration

Everything lives in `/etc/cybersentinel/config.yaml`. Every section has
defaults, so a minimal file is valid — but **an unknown key is a hard error**,
because a typo that silently disables a sensor is worse than a failed start.

Check a config before restarting into it:

```sh
sudo cybersentinel validate-rules --config /etc/cybersentinel/config.yaml
```

### Network monitoring

Off by default: capture needs privileges, and a sensor should start watching
because someone chose it.

```yaml
capture:
  enabled: true
  interfaces: [eth0]        # one interface per sensor
  snaplen: 65535            # content past this cannot be matched
  bpf-filter: null          # applied in the kernel — what it excludes is invisible
  buffer-size-bytes: null   # raise this first if stats.capture.drops goes non-zero
```

### Host monitoring

```yaml
hids:
  enabled: true

  fim:
    enabled: true
    paths:                  # the ENTIRE scope of file integrity monitoring
      - /etc
      - /usr/bin
      - /usr/sbin
      - /bin
      - /sbin
    rescan-interval-secs: 3600
    max-file-bytes: 67108864

  auth:
    enabled: true
    journald: true          # preferred: the service name is a structured field
    files:
      - /var/log/auth.log
      - /var/log/secure

  process:
    enabled: true
    interval-secs: 5
```

Three of these are worth understanding rather than just setting:

* **`fim.paths` is the whole scope.** Keep it short. Every watched directory
  consumes one of the kernel's finite `max_user_watches`, and a sensor that
  exhausts them degrades the machine it exists to protect.
* **`fim.rescan-interval-secs` is detection latency, not a performance knob.**
  The rescan is what catches changes made while the sensor was down, and
  changes the kernel dropped when its watch queue overflowed. Raising it widens
  the window in which a change goes unnoticed.
* **`fim.max-file-bytes`** — larger files are tracked by size and metadata
  only. A same-length edit to one is genuinely missed, and the absent `sha256`
  on the event is what tells you so.

### Correlation

Joins host and network evidence into a single `incident` when both halves see
the same thing:

```yaml
correlation:
  enabled: true
  window-secs: 120          # how far apart two events can be and still be one incident
  cooldown-secs: 300        # so sustained activity is one incident, not a stream
```

### Output

```yaml
outputs:
  stdout:
    enabled: false          # under systemd this would duplicate into the journal
  file:
    enabled: true
    path: events.json       # -> /var/log/cybersentinel/events.json
```

Events go to **stdout**; diagnostics go to **stderr** and the journal. That
separation means stdout is a clean stream you can pipe straight into a
consumer.

---

## Inline prevention (IPS mode)

Off by default. Turning it on puts the sensor **in the path of your traffic**.

```yaml
prevent:
  enabled: false
  mode: detect              # `detect` or `prevent` — THE ARMING CONTROL
  fail-mode: open           # what the KERNEL does if the sensor stops answering
  queue: 0
  allow-list: []            # never blocked, whatever matches
  source-block-secs: 600
```

Four things to know before arming:

**`mode` is the kill switch.** In `detect`, rules with a `drop` action still
alert and nothing is ever dropped — identical behaviour to the IDS. Switching
to `detect` disarms on the very next packet.

**`fail-mode` is enforced by the kernel, not the sensor.** If the process dies,
none of its code runs, so the behaviour is decided by the nftables rule:
`queue num N bypass` accepts when nothing is listening, `queue num N` drops.
The sensor **logs the rule it expects and does not apply it for you** — an
inline rule installed wrongly is an outage.

**The allow-list is absolute and covers both endpoints.** Put your gateway, DNS
resolvers, and the host you administer this box from in it. Cutting the flow
*to* a critical host breaks it exactly as thoroughly as blocking that host.

**What `blocked` means.** Matching requires stream reassembly, so the first
packets carrying a brand-new signature may pass before the match completes.
What inline prevention reliably does is drop the **rest of that flow** and
**every subsequent connection from the flagged source**. A single-packet
exploit that fits in the first segment will land; the session is then killed
and the source blocked. That is inherent to any reassembly-based IPS.

Before arming on a live segment, measure it:

```sh
sudo sh /usr/share/doc/cybersentinel/measure-prevention.sh   # latency and queue depth
sudo sh /usr/share/doc/cybersentinel/soak-prevention.sh 300  # drift over time
```

Watch **`stats.prevent.queue_unjudged`** in production. It counts packets the
kernel disposed of before the sensor could judge them — forwarded unexamined
under fail-open, dropped under fail-closed — and it's the only warning you get.

---

## Verifying an install

```sh
sudo sh /usr/share/doc/cybersentinel/verify-install.sh
```

This asserts, against the **running service**, that it runs as a dedicated
unprivileged user, holds exactly the capability it needs and nothing more, that
live capture still works anyway, and that a root-owned file like `/etc/shadow`
is genuinely hashed into the baseline. It exits non-zero on the first failure,
so it can gate a deployment.

---

## Reading events

One JSON object per line, one schema for host and network alike.

```sh
sudo tail -f /var/log/cybersentinel/events.json | jq -c 'select(.event_type=="alert")'
sudo journalctl -u cybersentinel-ips -f      # diagnostics, separate from events
```

Event types: `alert`, `anomaly`, `flow`, `fim`, `auth`, `process`, `incident`,
`stats`.

**`stats` is worth watching, not skipping.** It reports coverage holes as
holes: `capture.drops` (traffic the kernel discarded before the sensor saw it),
`flows.evicted`, `hids.inotify_overflows`, and `hids.sources` — where every
event source reports `active` / `degraded` / `unavailable` / `unsupported` with
a reason. A source that isn't working is otherwise indistinguishable from a
quiet host.

### Testing that it detects

Scope FIM to a small directory first — the default watches several thousand
files, and the first baseline has to hash all of them.

```sh
sudo mkdir -p /opt/cs-test && echo 'root:x:0:0' | sudo tee /opt/cs-test/passwd
# set hids.fim.paths to [/opt/cs-test], then:
sudo systemctl restart cybersentinel-ips
```

**Wait for the baseline before changing anything** — the first scan establishes
the starting position, so anything already changed becomes part of it:

```sh
sudo grep -o '"baseline_entries":[0-9]*' /var/log/cybersentinel/events.json | tail -1
```

Once it's non-zero, make a change whose *content* actually differs, and watch:

```sh
echo 'attacker:x:0:0::/root:/bin/bash' | sudo tee -a /opt/cs-test/passwd
sudo tail -f /var/log/cybersentinel/events.json | grep --line-buffered '"fim"'
```

To reset between tests:

```sh
sudo systemctl stop cybersentinel-ips
sudo rm -rf /var/lib/cybersentinel/* /var/log/cybersentinel/*
sudo systemctl start cybersentinel-ips
```

---

## Uninstall

```sh
sudo systemctl stop cybersentinel-ips
sudo apt-get remove cybersentinel      # keeps /etc/cybersentinel
sudo apt-get purge  cybersentinel      # removes configuration too
sudo dnf remove cybersentinel
```

**Event logs under `/var/log/cybersentinel` are deliberately left in place.**
They are evidence, and removing a package should not destroy an audit trail.
Delete them by hand when you're satisfied you no longer need them:

```sh
sudo rm -rf /var/log/cybersentinel /var/lib/cybersentinel
```

---

## Building from source

```sh
sudo apt-get install libpcap-dev
cargo build --release -p cybersentinel
```

To build the distributable packages, pinned to glibc 2.28 so one binary covers
every supported distribution:

```sh
cargo install cargo-deb cargo-generate-rpm cargo-zigbuild
# plus zig 0.13+ on PATH: https://ziglang.org/download/
sh packaging/linux/build-packages.sh
```

Analysing a capture file needs no privileges, no libpcap, and no install:

```sh
cybersentinel run --config config/config.yaml --replay capture.pcap
```

---

## Licence

Apache-2.0.
