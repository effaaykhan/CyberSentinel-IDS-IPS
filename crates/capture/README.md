# cybersentinel-capture

Frame sources for the sensor, behind one `PacketSource` trait.

| Source | Backend | Privileges | Platforms |
|---|---|---|---|
| `PcapReplay` | in-tree `.pcap` reader | none | all |
| `LiveCapture` | libpcap via the `pcap` crate | `CAP_NET_RAW` to open | Linux, macOS |
| *Npcap* | Phase 5 | Administrator | Windows |

## Runtime dependency: libpcap

**Live capture links against libpcap.** Replaying a `.pcap` file does not — that
reader is implemented in this crate, so `cargo test`, CI, and any offline
analysis need no system library at all.

| Platform | What is needed | Usually present? |
|---|---|---|
| Linux | `libpcap0.8` at runtime, `libpcap-dev` to build | Yes at runtime; the `.deb` declares the dependency automatically |
| macOS | system libpcap | Yes, shipped with the OS |
| Windows | **Npcap** (Phase 5) | **No** — the installer will bundle it, licence permitting |

Building this crate on Linux needs the headers:

```sh
sudo apt-get install libpcap-dev      # Debian/Ubuntu
sudo dnf install libpcap-devel        # Fedora/RHEL
```

The Npcap licence is not an open-source licence and its redistribution has to be
settled before Phase 5 ships — see `packaging/third_party/README.md`.

## Why the savefile reader is not libpcap

libpcap can read savefiles perfectly well. Doing it in-tree buys two things:

1. **The whole decode path is testable everywhere.** The Windows CI runner would
   otherwise need the Npcap SDK installed purely to replay a file, and every
   contributor would need libpcap headers to run `cargo test`.
2. **A savefile is attacker-supplied input.** Every length in the format is
   attacker controlled. Parsing it in-tree puts it under the same
   bounds-checking and fuzzing discipline as the rest of the pipeline, rather
   than behind an FFI boundary the fuzzer cannot see into. `fuzz/fuzz_targets/
   pcap_reader.rs` covers it.

Live capture still goes through the `pcap` crate exactly as intended: it keeps
all the `unsafe` inside the dependency so every first-party crate stays
`forbid(unsafe_code)`.

## Privileges

`LiveCapture::open` needs `CAP_NET_RAW`, plus `CAP_NET_ADMIN` for promiscuous
mode or a kernel-side BPF filter. **Nothing after the open needs either.** So the
sensor opens the handle and then calls `privileges::drop_after_capture_open`,
which clears every capability set — ambient, inheritable, effective, and finally
permitted, irreversibly.

Dropping capabilities is not the same as dropping root, and the report says
which one you got. Real separation comes from running as a non-root user with
only the ambient capabilities needed, which is what the shipped systemd unit
arranges (`DynamicUser=yes` plus `AmbientCapabilities=CAP_NET_RAW
CAP_NET_ADMIN`). Running the sensor as root works, and it logs a warning saying
you should not.

## Drop counters

`CaptureCounters` carries `drops` (kernel buffer full) and `interface_drops`
(dropped by the NIC or driver), queried from libpcap on every read. **A non-zero
drop count means traffic went unexamined** — a silent coverage hole, which is
why these reach `stats` events from this phase rather than a later one. When
they appear, raise `LiveOptions::buffer_size_bytes` first.

## Link types

Phase 1 decodes Ethernet (`LINKTYPE_ETHERNET`, 1) only. Any other encapsulation
is rejected at open time with the link-type number in the message, rather than
being fed to a decoder that would misread every frame. `LINUX_SLL` (113), which
is what capturing on the `any` device produces, is a likely early addition.
