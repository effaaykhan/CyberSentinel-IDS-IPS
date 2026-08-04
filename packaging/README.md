# Packaging

Guide §5 treats packaging as a core workstream, not an afterthought: *each OS
phase ends in a signed, installable artifact*. Phase 0 proves the pipeline by
building a real Linux `.deb` in CI; the Windows and macOS directories hold the
scaffolding their phases fill in.

| Target | Artifact | Toolchain | Service | Signing | Phase |
|---|---|---|---|---|---|
| Linux | `.deb` | `cargo-deb` | systemd | — | **0 (live)** |
| Linux | `.rpm`, AppImage | `fpm` | systemd | — | 4 |
| Windows | `.msi` / `.exe` | WiX or Inno | Windows Service | Authenticode | 5 |
| macOS | `.pkg` / `.dmg` | `pkgbuild` / `productbuild` | launchd | Developer ID + notarization | 6 |

## What every package must do

* Install a **single self-contained binary** — no runtime, no interpreter, no
  external prerequisite. (Windows is the one exception: packet capture needs
  Npcap, which is why its installer is bundled — see `third_party/`.)
* Install a default `config.yaml` and ruleset as **conffiles**, so an operator's
  edits survive an upgrade.
* Register the **service**, enabled but **not started**: a sensor should start
  once its operator has reviewed the installed configuration.
* Run with **least privilege** — capture needs a raw socket, and nothing else
  does, so the socket is opened and privileges dropped (guide §6).
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

Neither is wired up yet. CI produces **unsigned** artifacts, which are fine for
testing and are not fit to distribute.
