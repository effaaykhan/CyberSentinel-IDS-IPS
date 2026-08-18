#!/bin/sh
# Build the portable Linux packages: one binary, two package formats.
#
#     sh packaging/linux/build-packages.sh
#
# Produces
#   target/debian/cybersentinel_<version>_amd64.deb
#   target/x86_64-unknown-linux-gnu/generate-rpm/cybersentinel-<version>.x86_64.rpm
#
# # Why this is not just `cargo build --release`
#
# A binary built the ordinary way on a current distro records the glibc symbol
# versions of the machine that built it. Ours came out needing GLIBC_2.39 —
# which means the package installs on Ubuntu 24.04 and refuses on RHEL 8,
# Debian 11, and Ubuntu 20.04, all of which are still in support and are
# exactly the machines somebody wants a sensor on.
#
# `cargo-zigbuild` fixes that by handing the link step to zig, which ships the
# glibc stub definitions for every version and can be told to emit references
# no newer than a chosen one. The result is an ordinary dynamically linked
# binary — it still links libpcap, so **live capture works in full**. That is
# the whole reason this is not a static musl build: a sensor that cannot
# capture is not the sensor.
#
# # Requirements
#
#   cargo install cargo-zigbuild cargo-deb cargo-generate-rpm
#   plus zig 0.13+ on PATH (https://ziglang.org/download/, or `pip install ziglang`)
#   plus libpcap headers to link against: apt-get install libpcap-dev

set -eu

# RHEL 8, Debian 10, Ubuntu 20.04, SLES 15 SP2. Older than this and the
# distro is out of support; newer and the package stops reaching machines
# people still run. Raise it deliberately, not by accident.
GLIBC_BASELINE=2.28
TARGET=x86_64-unknown-linux-gnu

command -v zig >/dev/null 2>&1 || {
    echo "zig is not on PATH; cargo-zigbuild needs it to pin the glibc baseline" >&2
    exit 1
}

echo "==> building against glibc $GLIBC_BASELINE"
cargo zigbuild --release -p cybersentinel --target "$TARGET.$GLIBC_BASELINE"

BINARY="target/$TARGET/release/cybersentinel"

# The check that makes the pinning real. Without it, a dependency bump that
# pulls in a newer symbol would silently narrow the supported distros again,
# and nobody would find out until an install failed.
echo "==> verifying the glibc ceiling"
HIGHEST=$(objdump -T "$BINARY" | grep -oE 'GLIBC_[0-9.]+' | sed 's/GLIBC_//' | sort -V | tail -1)
if [ "$(printf '%s\n%s\n' "$GLIBC_BASELINE" "$HIGHEST" | sort -V | tail -1)" != "$GLIBC_BASELINE" ]; then
    echo "FAIL: needs GLIBC_$HIGHEST, above the $GLIBC_BASELINE baseline" >&2
    exit 1
fi
echo "    highest glibc symbol: $HIGHEST (baseline $GLIBC_BASELINE)"

# And the check that the point of the exercise survived: a portable binary that
# dropped libpcap would be portable and half-blind.
objdump -p "$BINARY" | grep -q 'NEEDED.*libpcap' || {
    echo "FAIL: the binary does not link libpcap; live capture would be unavailable" >&2
    exit 1
}
echo "    links libpcap: live capture available"

# Clear previously built packages before producing new ones.
#
# Neither cargo-deb nor cargo-generate-rpm removes the output of an earlier
# version, and CI caches `target/`, so a version bump leaves the OLD package
# sitting beside the new one. The release upload globs this directory, which is
# how a stale 0.1.0 RPM ended up attached to the v0.1.1 artifact — a release
# where "the RPM" could have been the wrong package entirely.
#
# Removing only our own package files, not the directories, so nothing else in
# target/ is disturbed.
find target -name 'cybersentinel*.deb' -o -name 'cybersentinel*.rpm' \
    | while read -r stale; do rm -f "$stale"; done

echo "==> .deb"
cargo deb -p cybersentinel --no-build --target "$TARGET"

echo "==> .rpm"
cargo generate-rpm -p crates/cli --target "$TARGET"

echo
echo "Built:"
find target -name 'cybersentinel*.deb' -o -name 'cybersentinel*.rpm' | sed 's/^/  /'

# Every package here must be the version just built. If a stale one survives,
# say so loudly rather than letting a release ship it.
VERSION=$(cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "cybersentinel"))')
UNEXPECTED=$(find target -name 'cybersentinel*.deb' -o -name 'cybersentinel*.rpm' \
    | grep -v -- "-\?_\?${VERSION}" || true)
if [ -n "$UNEXPECTED" ]; then
    echo "a package from another version survived the build:" >&2
    echo "$UNEXPECTED" | sed 's/^/  /' >&2
    exit 1
fi
