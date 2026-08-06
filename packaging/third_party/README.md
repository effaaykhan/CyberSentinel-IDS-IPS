# Third-party payloads

Empty by design. Nothing is vendored here yet, and each entry below needs a
licensing answer *before* it is.

## Npcap (Windows packet capture) — Phase 5

Windows has no built-in packet-capture interface, so the Windows NIDS depends
on Npcap.

**Npcap is not open source.** It ships under a custom licence that restricts
redistribution; bundling its installer in a distributed product generally
requires a commercial OEM licence from the Nmap Project. Nothing here should be
treated as legal advice — read the licence that ships with the version you
intend to use, and get the OEM question answered by someone qualified before
distributing anything.

### Decision: detect and prompt. Do not bundle.

The installer **detects** Npcap and, if it is absent, tells the operator what
to install and why. It does not carry the Npcap installer.

That is the option with no procurement dependency and no licence risk, and it
can be revisited: if the product is later distributed with Npcap bundled, the
OEM licence has to be obtained first, and this file is where that change gets
recorded.

### What it costs, stated plainly

It breaks the "**no external prerequisites**" promise in CLAUDE.md §1 — for the
**network half, on Windows, only**. The honest statement of the product is now:

* **HIDS on Windows: no prerequisites.** File integrity, authentication, and
  process monitoring need nothing installed.
* **NIDS on Windows: needs Npcap.** One prerequisite, detected at install and
  named in the installer rather than discovered at 3am.
* **Linux and macOS: unchanged.** libpcap is present by default on both and is
  a package dependency, not a bundled payload.

### The requirement that follows

A Windows sensor whose capture backend is unavailable must **say so**, in the
same way every other missing source now does — `capture` reports unavailable
with "Npcap is not installed" rather than running happily and seeing no
traffic. An operator who skipped the prompt must not have to infer that from a
packet counter stuck at zero. See `crates/hids/src/sources.rs` for the shape
this takes on the host side.

## Detection content

There is none to vendor. CyberSentinel authors its own rules in its own format
(`rules/cybersentinel.rules`), so there is no third-party ruleset to
redistribute and no ruleset licence to clear.

If importing an external ruleset is ever considered, its redistribution terms
have to be checked first, and a compatibility layer would be needed — our rule
format is our own, not another engine's.
