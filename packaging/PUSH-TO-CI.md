# Getting the matrix onto a remote

The workflow in `.github/workflows/ci.yml` has never run on a remote. This
repository has no git remote, no `gh` CLI, and no credentials, so the agent
building it cannot push — and will not invent a way to. This file is the
handover.

## What still needs a remote to prove

Everything below is verified locally on Linux and is the reason the remaining
gaps are narrow, not the reason they are closed:

| Claim | Verified locally? | Needs a runner? |
|---|---|---|
| `.deb` + `.rpm` build, contents, dependencies | yes | no |
| glibc 2.28 ceiling, libpcap still linked | yes | no |
| install → service starts → §8 capability model holds | yes, on a real systemd host | no |
| bundled SQLite compiles with **gcc** | yes | no |
| bundled SQLite compiles with **mingw-w64** (cross) | yes | no |
| bundled SQLite compiles with **zig cc** | yes | no |
| bundled SQLite compiles with **MSVC** | **no** | **windows-latest** |
| bundled SQLite compiles with **Apple clang** | **no** | **macos-latest** |
| workspace builds and tests on Windows | cross-compile check only | **windows-latest** |
| workspace builds and tests on macOS | **no** — never verified, any phase | **macos-latest** |

The two SQLite rows are the substantive risk. `rusqlite`'s `bundled` feature
compiles SQLite's C sources, and MSVC and Apple clang are the two toolchains
nothing here has exercised. If either fails, the fallback is a pure-Rust store
for the FIM baseline — the baseline needs key/value lookup by path, prefix
scans, and a count, which `redb` or a sorted indexed file would cover. That is
a decision to raise, not a workaround to apply quietly; see
`packaging/README.md`.

## Doing it

```sh
# 1. Create the remote. Any host with GitHub Actions runners works.
gh repo create <owner>/cybersentinel-IPS --private --source=. --remote=origin
# ... or, without gh:
git remote add origin git@github.com:<owner>/cybersentinel-IPS.git

# 2. Push. The workflow triggers on push to main and on pull requests.
git push -u origin main

# 3. Watch it.
gh run watch
```

Nothing in the workflow needs a secret. It uses first-party actions only
(`actions/checkout`, `actions/cache`, `actions/upload-artifact`), because a
third-party action runs with access to a security tool's build.

## What the matrix does

| Job | Runner | What it proves |
|---|---|---|
| `test` | ubuntu, windows, macos | fmt, clippy `-D warnings`, build, test, **bundled SQLite as its own step**, FIM baseline round-trip, sensor runs with the shipped config, pcap fixtures replay |
| `package-linux` | ubuntu | both packages build from the pinned binary, contents and dependencies checked, `.deb` installed, service started, `verify-install.sh` run against it |
| `fuzz` | ubuntu | a short run of each of the ten fuzz targets |

`package-linux` starting the service and running `verify-install.sh` is the
step that matters most: it is what makes CLAUDE.md §8 falsifiable on every
commit instead of once, by hand, on one machine.

## If the runner cannot capture

`verify-install.sh` needs to see at least one packet to pass its capture check.
GitHub runners have a working NIC and outbound network, and the job pings
through the default route's interface, so this should hold. If a future runner
is network-isolated, the honest fix is to make the check skip **loudly** — with
a message saying capture was not verified — rather than to pass quietly. A
capture check that silently does nothing is worse than no check, because it
reads as coverage.
