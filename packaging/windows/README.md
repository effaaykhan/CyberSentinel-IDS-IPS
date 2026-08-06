# Windows packaging

**Status: scaffolding (Phase 5).** Nothing here is built by CI yet. CI compiles
and tests the sensor on `windows-latest` and cross-compiles it for Windows from
the Linux runner, so the code stays portable in the meantime.

**Read `PORT-PLAN.md` first.** It records what Phase 5 settled, what it built,
and why no Windows platform code is in the tree yet.

## Planned shape

1. `cargo build --release` → `cybersentinel.exe`.
2. Wrap in an **MSI (WiX)** or an **EXE (Inno Setup)**. `cybersentinel.wxs` is a
   WiX v4 skeleton; the toolchain choice is still open — see below.
3. Register a **Windows Service** (`windows-service` crate) with automatic start.
4. **Detect Npcap and prompt** — do **not** bundle it. Npcap's licence
   restricts redistribution, and bundling generally needs a commercial OEM
   licence; detect-and-prompt has no procurement dependency. The cost is that
   the Windows NIDS has one external prerequisite, which is now stated rather
   than promised away. See `../third_party/`.
5. **Authenticode sign** the binary and the installer.

## Open decision: WiX vs Inno

Not settled, and worth settling before Phase 5 starts rather than during it.

| | WiX | Inno Setup |
|---|---|---|
| Output | `.msi` | `.exe` |
| Enterprise deployment | Native — Group Policy, Intune, `msiexec /qn` | Needs wrapping |
| Bundling Npcap | Burn bundle (extra moving part) | Straightforward |
| Learning curve | Steep (declarative XML) | Gentle (Pascal-ish script) |
| Upgrade/patch story | Strong | Adequate |

An IDS is enterprise-deployed software, which argues for **WiX/MSI**. That is
the assumption `cybersentinel.wxs` is written against, but it is not a decision
that has been made.

## Service considerations

* **Least privilege.** Npcap can be installed in "restrict to Administrators"
  mode; the service account needs access to the driver but should not otherwise
  be `LocalSystem` if that can be avoided.
* **Self-protection.** ACL the install directory and the rules so the service
  account cannot rewrite its own detection content.
* **Uninstall** must remove the service, and must state clearly whether it also
  removes Npcap — other software may depend on it, so the default should be to
  leave it.

## Signing

Authenticode, via `signtool`. An OV certificate signs; an EV certificate also
carries immediate SmartScreen reputation, which matters for a downloaded
security tool. Certificate acquisition has lead time — start it before Phase 5,
not during (guide §9).
