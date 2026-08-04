# Linux packaging

**Status: live.** CI builds a `.deb` on every run — this is the Phase 0
acceptance criterion "CI outputs at least one installable Linux package".

## Building

```sh
cargo install cargo-deb
cargo build --release -p cybersentinel
cargo deb -p cybersentinel --no-build
# -> target/debian/cybersentinel_0.1.0-1_amd64.deb
```

The package metadata lives in `crates/cli/Cargo.toml` under
`[package.metadata.deb]`.

## What the package installs

| Path | Source | Notes |
|---|---|---|
| `/usr/bin/cybersentinel` | `target/release/cybersentinel` | the sensor |
| `/etc/cybersentinel/config.yaml` | `packaging/linux/config.yaml` | conffile — survives upgrades |
| `/etc/cybersentinel/rules/cybersentinel.rules` | `rules/cybersentinel.rules` | conffile |
| `/usr/lib/systemd/system/cybersentinel.service` | `cybersentinel.service` | registered by `cargo-deb`'s generated maintainer scripts |
| `/etc/logrotate.d/cybersentinel` | `logrotate` | event logs are PII; rotate and expire them |
| `/var/lib/cybersentinel` | — | created by systemd `StateDirectory` |
| `/var/log/cybersentinel` | — | created by systemd `LogsDirectory` |

The unit is **enabled but not started**: review `/etc/cybersentinel/config.yaml`,
then `systemctl start cybersentinel`.

## Service design

`cybersentinel.service` uses `DynamicUser=yes`, so systemd allocates and owns the
service account. The package needs no `useradd` in a maintainer script and leaves
no orphaned account behind on removal.

From Phase 1, packet capture needs `CAP_NET_RAW` and `CAP_NET_ADMIN`. These are
granted as ambient capabilities rather than by running as root; the sensor opens
the capture socket and then drops what it no longer needs (guide §6). Everything
else is locked down — `ProtectSystem=strict`, `MemoryDenyWriteExecute`, a
capability bounding set — because the sensor is itself a target.

## Still to do

* **`.rpm` and AppImage** via `fpm` (Phase 4), so the MVP is installable beyond
  Debian derivatives.
* **A musl static build** (guide §2) so one artifact runs across distributions
  regardless of glibc version. The current build is dynamically linked against
  the builder's glibc.
* **An apt repository**, if distribution beyond direct `.deb` downloads is wanted.

## Uninstall

```sh
sudo apt-get remove cybersentinel     # keeps /etc/cybersentinel
sudo apt-get purge  cybersentinel     # removes it too
```

Event logs under `/var/log/cybersentinel` are deliberately left in place: they
are evidence, and removing a package should not destroy an audit trail.
