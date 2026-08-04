# Third-party payloads

Empty by design. Nothing is vendored here yet, and each entry below needs a
licensing answer *before* it is.

## Npcap (Windows packet capture) — Phase 5

Windows has no built-in packet-capture interface, so Phase 5 depends on Npcap,
and the product's "no external prerequisites" promise means bundling its
installer rather than telling operators to fetch it.

**Npcap is not open source.** It ships under a custom licence that restricts
redistribution; bundling it in a distributed product generally requires a
commercial OEM licence from the Nmap Project. **This must be resolved before
Phase 5 ships, not after.** The alternatives, if it cannot be:

* Detect Npcap at install time and direct the operator to install it — honest,
  but it breaks the no-prerequisites promise.
* Use a different capture path on Windows, at a meaningful cost in coverage and
  compatibility.

## Detection content

There is none to vendor. CyberSentinel authors its own rules in its own format
(`rules/cybersentinel.rules`), so there is no third-party ruleset to
redistribute and no ruleset licence to clear.

If importing an external ruleset is ever considered, its redistribution terms
have to be checked first, and a compatibility layer would be needed — our rule
format is our own, not another engine's.
