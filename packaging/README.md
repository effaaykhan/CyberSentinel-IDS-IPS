# Packaging

Guide §5 treats packaging as a core workstream, not an afterthought: *each OS
phase ends in a signed, installable artifact*. Linux is done — both formats
build in CI, install, and are verified on a running service. The Windows and
macOS directories hold the scaffolding their phases fill in.

| Target | Artifact | Toolchain | Service | Signing | Phase |
|---|---|---|---|---|---|
| Linux | `.deb` | `cargo-deb` | systemd | — | **live** |
| Linux | `.rpm` | `cargo-generate-rpm` | systemd | — | **live** |
| Windows | `.msi` / `.exe` | WiX or Inno | Windows Service | Authenticode | 5 |
| macOS | `.pkg` / `.dmg` | `pkgbuild` / `productbuild` | launchd | Developer ID + notarization | 6 |

Both Linux formats are built from **one** glibc-2.28-pinned binary that still
links libpcap, so one artifact covers every supported distro without giving up
live capture. See `linux/README.md` for why that is not a static musl build.

AppImage is not planned: it solves a desktop-application problem, and a sensor
is a system service that wants a service manager, a conffile, and a package
database entry.

## What every package must do

* Install a **single self-contained binary** — no runtime, no interpreter, no
  external prerequisite. (Windows is the one exception: packet capture needs
  Npcap, which is why its installer is bundled — see `third_party/`.)
* Install a default `config.yaml` and ruleset as **conffiles**, so an operator's
  edits survive an upgrade.
* Register the **service**, enabled but **not started**: a sensor should start
  once its operator has reviewed the installed configuration.
* Run with **least privilege** — and remember the set is *temporal*. Capture
  needs a raw socket once, at startup; host monitoring needs to read files it
  does not own for its whole life. So the sensor takes both, drops the capture
  capabilities after the open, and keeps only `CAP_DAC_READ_SEARCH`
  (CLAUDE.md §8).
* **Ship the check, not just the claim.** A privilege model nobody verifies is
  a privilege model nobody knows is wrong. `linux/verify-install.sh` asserts it
  against a running service and is installed alongside the binary; CI runs it.
* **Self-protect**: an attacker who can rewrite the rules or delete the event log
  has blinded the sensor. Package the config, rules, and binary read-only to the
  service account.
* Treat the event log as **PII** and ship a retention policy alongside it.
* Document **uninstall**.

## Signing

Code signing gates release, and both gates cost money and lead time (guide §9):

* **Windows** — Authenticode. An OV certificate signs; an EV certificate also
  buys immediate SmartScreen reputation.
* **macOS** — a Developer ID Application certificate, plus notarization and
  stapling, or Gatekeeper blocks the installer outright.

Neither is wired up yet, and neither are the Linux packages: `.deb` and `.rpm`
signing wants a repository and a key-rotation story of its own. CI produces
**unsigned** artifacts, which are fine for testing and are not fit to
distribute.

## A note on bundled SQLite

The FIM baseline is a SQLite database, built through `rusqlite`'s `bundled`
feature — SQLite's C sources compiled into the binary, so there is no
`libsqlite3` prerequisite on the target. That is the one part of the build that
is not Rust, and it compiles with a different toolchain on each OS (cc, clang,
MSVC), so CI gives it a named step per platform rather than burying it in the
workspace build.

If it ever becomes a portability problem — most plausibly on the Windows or
macOS runners — the alternative is a pure-Rust store. The baseline needs
key/value lookup by path, prefix scans, and a count; that is not much SQL, and
`redb` or a sorted flat file with an index would cover it. Raise it as a
decision rather than working around it quietly.
