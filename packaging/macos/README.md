# macOS packaging

**Status: scaffolding (Phase 6).** Nothing here is built by CI yet; CI does
compile and test the sensor on `macos-latest`, so the code stays portable.

## Planned shape

1. Build for both architectures and merge into a **universal binary**:
   ```sh
   cargo build --release --target aarch64-apple-darwin
   cargo build --release --target x86_64-apple-darwin
   lipo -create -output cybersentinel \
       target/aarch64-apple-darwin/release/cybersentinel \
       target/x86_64-apple-darwin/release/cybersentinel
   ```
2. `pkgbuild` + `productbuild` → `.pkg`, optionally wrapped in a `.dmg`.
3. Install the **launchd** daemon (`com.cybersentinel.sensor.plist`).
4. **Sign with a Developer ID Application certificate, notarize, and staple.**

## Two things that will bite

**BPF device permissions.** Packet capture reads `/dev/bpf*`, which is
root-owned. The options are a privileged helper, a postinstall script that
adjusts the device permissions, or running the daemon as root — and none of them
is free. Deciding this is part of Phase 6, not something to discover during it.

**Notarization is not optional.** Without a Developer ID signature plus
notarization and stapling, Gatekeeper blocks the installer on any machine that
did not build it. This costs a paid Apple Developer account and adds a
network round trip to every release (guide §9).

## Endpoint Security is deliberately out of scope

Deep process and network host events would come from Apple's Endpoint Security
framework, which requires a restricted entitlement, a System Extension, and
notarization of that extension (guide §4). Phase 6 uses FSEvents, unified
logging, and OpenBSM instead — less depth, no entitlement application.

## Uninstall

`.pkg` has no built-in uninstaller, so ship a script that unloads the launchd
daemon and removes the binary, config, and rules. As on Linux, leave the event
log: it is evidence.
