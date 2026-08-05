# cybersentinel-hids

Host-based detection: file integrity, authentication logs, and process
monitoring. Linux in Phase 4; Windows and macOS behind the same shapes in
Phases 5 and 6.

## Runtime requirements

| What | Needs | If it is missing |
|---|---|---|
| File integrity | `CAP_DAC_READ_SEARCH` to read and hash files the sensor does not own | Unreadable files are counted in `stats.hids` and omitted from the baseline. A FIM baseline that silently omits `/etc/shadow` is worse than one that says it could not read it, so the count is not optional. |
| inotify watches | one of the kernel's `max_user_watches` per watched directory | Watches that could not be established are counted in `watch_failures`; those paths are covered by the periodic rescan only. |
| journald | the `journalctl` binary, and read access to `/var/log/journal` | The source is skipped with a warning and the configured log files carry the load — which is what happens on a host without systemd. |
| Auth log files | read access, usually `CAP_DAC_READ_SEARCH` | A file that is not there is not an error; it is a service that has not logged yet. |
| `/proc` | nothing beyond a mounted `/proc` for names, pids, and command lines | `/proc/<pid>/exe` and `/proc/<pid>/fd` for **other users'** processes need `CAP_SYS_PTRACE`, which the sensor deliberately does not take. A listening socket it cannot attribute is still reported, with the owner shown as `unknown`. |

No kernel module, no eBPF, no auditd configuration. Installing the sensor must
never make the host worse.

`CLAUDE.md` §8 documents the full capability set and the reasoning behind each
entry.

## Why FIM has two detectors

Real-time watching has three failure modes, and from the outside all three look
identical — like a filesystem nobody touched:

1. **The sensor was not running.** A watcher only ever sees the future.
2. **The queue overflowed.** inotify's queue is bounded, and filling it is
   trivially attacker-inducible: touch a lot of files, then change the one that
   matters.
3. **The watch was never established.** `max_user_watches` is finite.

So watching is paired with a periodic **baseline rescan**: SHA-256 of every
watched file in SQLite, compared on a timer. Overflow additionally forces an
immediate rescan and is emitted as its own event, because a silently missed
change must never be indistinguishable from no change.

The baseline runs on its own thread. Hashing `/etc` and `/usr/bin` takes real
time, and paying it on the capture thread would drop traffic. Scans are
abandonable so shutdown does not wait for one — and an abandoned scan reports
itself as truncated, so it is never mistaken for mass deletion.

## Why log parsing is written defensively

A username is whatever somebody typed at a login prompt, and it lands in the log
verbatim. That makes the authentication log an input channel that anyone who
can reach the login service can write to.

* Fields are extracted **positionally and validated**, never scavenged. A login
  as `admin from 10.0.0.1 port 22` does not get to choose the `source_address`
  of the event it generates.
* Control characters never reach an event. Event logs get read in terminals.
* Lengths are bounded, in characters rather than bytes — a username ending in
  one multi-byte character is not a crash.
* What cannot be a real value is **flagged**, not dropped. Dropping it would
  hide the attempt; trusting it would launder a forgery.

One ambiguity is not solvable here and is documented rather than papered over:
sshd writes `for invalid user bob` for an account that does not exist and
`for bob` for one that does, so an attacker logging in as the literal string
`invalid user root` produces an indistinguishable line. journald carries the
account as a structured field, which is why it is the preferred source.

Both parsers have `cargo-fuzz` targets: `auth_log` and `proc_reader`.
