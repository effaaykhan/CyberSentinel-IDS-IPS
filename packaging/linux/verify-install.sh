#!/bin/sh
# Verify an installed CyberSentinel sensor against the capability model in
# CLAUDE.md §8.
#
# §8 is a set of claims about what the sensor holds and what that buys it. A
# document cannot be wrong in a way anyone notices; a check can. This script is
# what makes the claims falsifiable:
#
#   1. the service runs as a dedicated unprivileged user, not root;
#   2. at steady state it holds ONLY CAP_DAC_READ_SEARCH — CAP_NET_RAW and
#      CAP_NET_ADMIN were needed to open the capture handle and have been
#      dropped;
#   3. live capture still works, which is the point of dropping them *after*
#      the open rather than never taking them;
#   4. /etc/shadow is hashed into the FIM baseline, which is what
#      CAP_DAC_READ_SEARCH was retained for. A baseline that silently omits the
#      file most worth watching is the failure this whole project is built to
#      avoid.
#
# Run as root on a host where the package is installed:
#
#     sh /usr/share/doc/cybersentinel/verify-install.sh
#
# Exits non-zero on the first failed check, so it can gate a deployment.

set -eu

UNIT=cybersentinel.service
CONFIG=/etc/cybersentinel/config.yaml
STATE=/var/lib/cybersentinel
BASELINE="$STATE/fim-baseline.db"
LOGS=/var/log/cybersentinel

pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1" >&2; exit 1; }
info() { printf '        %s\n' "$1"; }

require_root() {
    [ "$(id -u)" = 0 ] || fail "run this as root: it reads /proc/<pid>/status and /etc/shadow"
}

# --------------------------------------------------------------------------
# 1. the service is running, and not as root
# --------------------------------------------------------------------------
check_service() {
    printf '\n1. service\n'
    systemctl is-active --quiet "$UNIT" || fail "$UNIT is not active"
    pass "$UNIT is active"

    PID=$(systemctl show -p MainPID --value "$UNIT")
    [ -n "$PID" ] && [ "$PID" != 0 ] || fail "no main pid"
    pass "main pid $PID"

    UID_=$(awk '/^Uid:/ {print $2}' "/proc/$PID/status")
    USER_=$(id -nu "$UID_" 2>/dev/null || echo "uid $UID_")
    [ "$UID_" != 0 ] || fail "running as root (uid 0). DynamicUser or User= is not taking effect."
    pass "running as $USER_ (uid $UID_), not root"
}

# --------------------------------------------------------------------------
# 2. steady-state capabilities
# --------------------------------------------------------------------------
#
# CapEff is a hex bitmask. CAP_DAC_READ_SEARCH is bit 2, so the only value that
# passes is exactly 0x4: anything more means something was not dropped, and
# anything less means FIM cannot read what it was installed to read.
CAP_DAC_READ_SEARCH_MASK=4

# How long to wait for the first FIM baseline to reach /etc/shadow.
BASELINE_WAIT_SECS=300

check_capabilities() {
    printf '\n2. steady-state capabilities\n'
    PID=$(systemctl show -p MainPID --value "$UNIT")

    EFF=$(awk '/^CapEff:/ {print $2}' "/proc/$PID/status")
    PRM=$(awk '/^CapPrm:/ {print $2}' "/proc/$PID/status")
    EFF_DEC=$(printf '%d' "0x$EFF")
    PRM_DEC=$(printf '%d' "0x$PRM")

    info "CapEff=$EFF CapPrm=$PRM"

    [ "$EFF_DEC" = "$CAP_DAC_READ_SEARCH_MASK" ] || {
        info "decoded: $(capsh --decode="0x$EFF" 2>/dev/null || echo '(capsh unavailable)')"
        fail "effective capabilities are not exactly CAP_DAC_READ_SEARCH"
    }
    pass "effective set is exactly CAP_DAC_READ_SEARCH"

    [ "$PRM_DEC" = "$CAP_DAC_READ_SEARCH_MASK" ] || {
        info "decoded: $(capsh --decode="0x$PRM" 2>/dev/null || echo '(capsh unavailable)')"
        fail "permitted capabilities are not exactly CAP_DAC_READ_SEARCH — something can be raised back"
    }
    pass "permitted set is exactly CAP_DAC_READ_SEARCH (CAP_NET_RAW cannot be regained)"
}

# --------------------------------------------------------------------------
# 3. live capture still works
# --------------------------------------------------------------------------
#
# The whole point of dropping CAP_NET_RAW *after* opening the handle is that
# capture keeps working without it. Proving the drop without proving capture
# would be proving the sensor is safely useless.
# How long to wait for a stats event carrying capture counters. Comfortably
# more than the default `stats.interval-secs` of 60.
CAPTURE_WAIT_SECS=90

# Put something on the wire the sensor is watching. Pinging loopback while the
# sensor captures on eth0 proves nothing and would fail a working install.
generate_traffic() {
    case "$IFACE" in
        lo|"") ping -c 4 -i 0.2 127.0.0.1 >/dev/null 2>&1 || true ;;
        *)     ping -c 4 -i 0.2 -I "$IFACE" 8.8.8.8 >/dev/null 2>&1 ||
               ping -c 4 -i 0.2 -I "$IFACE" 1.1.1.1 >/dev/null 2>&1 ||
               # No route out. Broadcast ARP on the segment instead: it needs
               # no reachable host, and the sensor sees it either way.
               arping -c 3 -I "$IFACE" -b 255.255.255.255 >/dev/null 2>&1 || true ;;
    esac
}

check_capture() {
    printf '\n3. live capture\n'

    if ! grep -qE '^[[:space:]]*enabled:[[:space:]]*true' "$CONFIG" 2>/dev/null ||
       ! sed -n '/^capture:/,/^[a-z]/p' "$CONFIG" | grep -qE 'enabled:[[:space:]]*true'; then
        info "capture.enabled is false in $CONFIG — skipping"
        info "set it and name an interface to include this check"
        return 0
    fi

    EVENTS="$LOGS/events.json"
    [ -f "$EVENTS" ] || fail "no event log at $EVENTS"

    # Give the sensor something to see — on the interface it is actually
    # watching. Pinging loopback while the sensor captures on eth0 proves
    # nothing, and would fail this check on a working install.
    # Scoped to the capture block: `source` also appears on alerts (network or
    # host) and `log_source` on auth records, and picking one of those up gives
    # an interface name that does not exist.
    IFACE=$(grep -o '"capture":{[^}]*}' "$EVENTS" | tail -1 |
            grep -o '"source":"[^"]*"' | cut -d'"' -f4)
    info "capturing on ${IFACE:-unknown}"
    generate_traffic
    BEFORE=$(wc -c < "$EVENTS")

    # Wait for a *fresh* stats event rather than sleeping a fixed interval.
    # Capture counters only reach the event log when one is emitted, and
    # `stats.interval-secs` defaults to 60 — so a fixed sleep reads the startup
    # event, sees zero packets, and fails a perfectly healthy sensor. A check
    # that cries wolf gets ignored, which is the same end state as no check.
    STATS_BEFORE=$(grep -c '"event_type":"stats"' "$EVENTS" || true)
    DEADLINE=$(( $(date +%s) + CAPTURE_WAIT_SECS ))
    SEEN=""
    while [ "$(date +%s)" -lt "$DEADLINE" ]; do
        NOW_COUNT=$(grep -c '"event_type":"stats"' "$EVENTS" || true)
        if [ "$NOW_COUNT" -gt "$STATS_BEFORE" ]; then
            SEEN=$(grep -o '"capture":{[^}]*}' "$EVENTS" | tail -1 |
                   grep -o '"packets":[0-9]*' | cut -d: -f2)
            [ "${SEEN:-0}" -gt 0 ] && break
            # A fresh event reporting zero: keep the link busy and try again,
            # in case the ping landed between two stats windows.
            generate_traffic
        fi
        sleep 2
    done

    [ -n "${SEEN:-}" ] || fail "no fresh capture counters within ${CAPTURE_WAIT_SECS}s (is the sensor emitting stats?)"
    [ "$SEEN" -gt 0 ] || fail "capture is enabled but no packets were seen: the handle was opened, then broken"
    pass "capture is live: $SEEN packet(s) seen"

    AFTER=$(wc -c < "$EVENTS")
    [ "$AFTER" -ge "$BEFORE" ] || fail "the event log shrank"
    pass "events are still being written"
}

# --------------------------------------------------------------------------
# 4. /etc/shadow is in the baseline, with a hash
# --------------------------------------------------------------------------
#
# This is the check CAP_DAC_READ_SEARCH exists for. /etc/shadow is mode 0640
# root:shadow; an unprivileged process without the capability cannot read it,
# and FIM would record it by metadata alone — or not at all. A row with a hash
# is proof the capability is doing its job.
check_shadow() {
    printf '\n4. /etc/shadow in the FIM baseline\n'

    if ! sed -n '/^hids:/,$p' "$CONFIG" | grep -q '/etc'; then
        info "/etc is not in hids.fim.paths — skipping"
        return 0
    fi
    # The first baseline hashes every watched file, which on a default install
    # is /etc plus four binary directories — tens of thousands of files. Wait
    # for it, bounded, rather than failing a sensor that is simply still
    # working: same reasoning as the capture check.
    DEADLINE=$(( $(date +%s) + BASELINE_WAIT_SECS ))
    ROW=""
    while [ "$(date +%s)" -lt "$DEADLINE" ]; do
        if [ -f "$BASELINE" ]; then
            ROW=$(sqlite_query "SELECT hash FROM baseline WHERE path = '/etc/shadow';")
            [ -n "$ROW" ] && break
        fi
        sleep 3
    done

    [ -f "$BASELINE" ] || fail "no FIM baseline at $BASELINE after ${BASELINE_WAIT_SECS}s"
    [ -n "$ROW" ] || fail "/etc/shadow is not in the baseline after ${BASELINE_WAIT_SECS}s: FIM cannot see the file most worth watching"
    pass "/etc/shadow is tracked"

    case "$ROW" in
        [0-9a-f]*) : ;;
        *) fail "/etc/shadow has no content hash: it was tracked by metadata only, so a same-length edit would be missed" ;;
    esac
    pass "and it has a content hash — CAP_DAC_READ_SEARCH is doing its job"

    EXPECTED=$(sha256sum /etc/shadow | cut -d' ' -f1)
    [ "$ROW" = "$EXPECTED" ] || {
        info "baseline: $ROW"
        info "actual:   $EXPECTED"
        info "(a mismatch is fine if the file changed since the last scan)"
    }
    [ "$ROW" = "$EXPECTED" ] && pass "the hash matches the file on disk"

    COUNT=$(sqlite_query "SELECT COUNT(*) FROM baseline;")
    info "baseline holds $COUNT file(s)"
    [ "${COUNT:-0}" -gt 1 ] || fail "the baseline has almost nothing in it"
}

# Read one value out of the baseline, using whichever SQLite is to hand.
sqlite_query() {
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "file:$BASELINE?mode=ro" "$1" 2>/dev/null || true
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "$BASELINE" "$1" <<'EOF' 2>/dev/null || true
import sqlite3, sys
connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
row = connection.execute(sys.argv[2]).fetchone()
print("" if row is None or row[0] is None else row[0])
EOF
    else
        fail "neither sqlite3 nor python3 is available to read the baseline"
    fi
}

# --------------------------------------------------------------------------

printf 'CyberSentinel installed-sensor verification\n'
printf '(the checks behind CLAUDE.md §8)\n'
require_root
check_service
check_capabilities
check_capture
check_shadow
printf '\nAll checks passed.\n'
