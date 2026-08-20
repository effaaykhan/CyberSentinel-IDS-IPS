#!/bin/sh
# Remove CyberSentinel-IPS from a host, completely.
#
#   sudo sh uninstall.sh              # asks before destroying the event log
#   sudo sh uninstall.sh --yes        # no prompts, for automation
#   sudo sh uninstall.sh --keep-logs  # remove everything except the event log
#
# What "completely" covers: the service, the package, the binary, the config,
# the ruleset, the sensor identity, the FIM baseline, the log rotation policy,
# and the event log. Both the current `cybersentinel-ips` service and the
# pre-0.2.0 `cybersentinel` one, so a host that was never upgraded is cleaned
# up too.
#
# What it deliberately does NOT touch: any nftables rule an operator added to
# feed the sensor's verdict queue. See the warning near the end — removing the
# sensor while such a rule is still installed can take a network down, and
# guessing which rules are ours would be worse than saying so.

set -eu

ASSUME_YES=0
KEEP_LOGS=0
for arg in "$@"; do
    case "$arg" in
        -y|--yes)   ASSUME_YES=1 ;;
        --keep-logs) KEEP_LOGS=1 ;;
        -h|--help)  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done

# `sh` reads a script incrementally, so a copy running from the package's own
# doc directory would be deleted out from under itself when the package goes.
# Re-exec from a private copy first; it is unlinked immediately, which is safe
# once the interpreter holds the descriptor.
case "$0" in
    /usr/share/doc/cybersentinel/*)
        COPY=$(mktemp) || { echo "could not stage a copy of this script" >&2; exit 1; }
        cat "$0" > "$COPY"
        exec sh "$COPY" "$@"
        ;;
esac
[ "${0#/tmp/}" = "$0" ] || rm -f "$0" 2>/dev/null || :

[ "$(id -u)" = 0 ] || { echo "run as root: this removes system files" >&2; exit 1; }

UNITS="cybersentinel-ips cybersentinel"
STATE=/var/lib/cybersentinel
LOGS=/var/log/cybersentinel
CONF=/etc/cybersentinel

removed_any=0
note() { echo "  $1"; }

echo "CyberSentinel-IPS uninstall"
echo

# ---------------------------------------------------------------------------
# 1. What is actually here
# ---------------------------------------------------------------------------
echo "Found:"
for unit in $UNITS; do
    if systemctl list-unit-files "$unit.service" >/dev/null 2>&1 \
       && systemctl cat "$unit.service" >/dev/null 2>&1; then
        note "service $unit.service ($(systemctl is-active "$unit" 2>/dev/null || echo inactive))"
        removed_any=1
    fi
done
if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W cybersentinel >/dev/null 2>&1; then
    note "package cybersentinel $(dpkg-query -W -f='${Version}' cybersentinel 2>/dev/null)  (dpkg)"
    removed_any=1
fi
if command -v rpm >/dev/null 2>&1 && rpm -q cybersentinel >/dev/null 2>&1; then
    note "package $(rpm -q cybersentinel)  (rpm)"
    removed_any=1
fi
for dir in "$CONF" "$STATE" "$LOGS"; do
    [ -d "$dir" ] && { note "directory $dir ($(du -sh "$dir" 2>/dev/null | cut -f1))"; removed_any=1; }
done
[ -x /usr/bin/cybersentinel ] && { note "binary /usr/bin/cybersentinel"; removed_any=1; }

if [ "$removed_any" = 0 ]; then
    echo "  nothing — CyberSentinel-IPS is not installed here."
    exit 0
fi

# ---------------------------------------------------------------------------
# 2. Confirm, because the event log is evidence
# ---------------------------------------------------------------------------
echo
if [ "$KEEP_LOGS" = 1 ]; then
    echo "The event log at $LOGS will be KEPT."
else
    echo "The event log at $LOGS WILL BE DELETED."
    echo "It is a record of what this host saw. If it might be needed for an"
    echo "investigation, copy it elsewhere first, or re-run with --keep-logs."
fi
if [ "$ASSUME_YES" = 0 ]; then
    printf 'Continue? [y/N] '
    read -r reply || reply=n
    case "$reply" in [yY]|[yY][eE][sS]) ;; *) echo "aborted; nothing was changed."; exit 1 ;; esac
fi
echo

# ---------------------------------------------------------------------------
# 3. Stop the service before removing what it is using
# ---------------------------------------------------------------------------
echo "Stopping:"
for unit in $UNITS; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        systemctl stop "$unit" >/dev/null 2>&1 || :
        note "stopped $unit"
    fi
    if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        systemctl disable "$unit" >/dev/null 2>&1 || :
        note "disabled $unit"
    fi
done

# ---------------------------------------------------------------------------
# 4. The package
# ---------------------------------------------------------------------------
echo "Removing the package:"
if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W cybersentinel >/dev/null 2>&1; then
    # purge, not remove: `remove` leaves the conffiles behind by design, and
    # this script is the one place where that is not what was asked for.
    DEBIAN_FRONTEND=noninteractive dpkg --purge cybersentinel >/dev/null 2>&1 \
        || dpkg --purge --force-all cybersentinel >/dev/null 2>&1 || :
    note "purged the .deb"
elif command -v rpm >/dev/null 2>&1 && rpm -q cybersentinel >/dev/null 2>&1; then
    rpm -e cybersentinel >/dev/null 2>&1 || :
    note "removed the .rpm"
else
    note "no package registered (installed by hand?)"
fi

# ---------------------------------------------------------------------------
# 5. Whatever the package manager does not own
# ---------------------------------------------------------------------------
echo "Removing files:"
for unit in $UNITS; do
    for path in "/usr/lib/systemd/system/$unit.service" "/lib/systemd/system/$unit.service" \
                "/etc/systemd/system/$unit.service" \
                "/etc/systemd/system/multi-user.target.wants/$unit.service"; do
        [ -e "$path" ] || [ -L "$path" ] || continue
        rm -f "$path"
        note "removed $path"
    done
done
systemctl daemon-reload >/dev/null 2>&1 || :

for path in /usr/bin/cybersentinel /etc/logrotate.d/cybersentinel /usr/share/doc/cybersentinel; do
    [ -e "$path" ] || continue
    rm -rf "$path"
    note "removed $path"
done

for dir in "$CONF" "$STATE"; do
    [ -d "$dir" ] || continue
    rm -rf "$dir"
    note "removed $dir"
done

if [ "$KEEP_LOGS" = 1 ]; then
    [ -d "$LOGS" ] && note "kept $LOGS (--keep-logs)"
else
    [ -d "$LOGS" ] && { rm -rf "$LOGS"; note "removed $LOGS"; }
fi

# ---------------------------------------------------------------------------
# 6. The one thing this script must not silently leave broken
# ---------------------------------------------------------------------------
if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q 'queue num'; then
    echo
    echo "WARNING: this host still has an nftables rule feeding a verdict queue:"
    nft list ruleset 2>/dev/null | grep 'queue num' | sed 's/^/    /'
    echo
    echo "  Nothing is listening on that queue any more. A rule WITHOUT \`bypass\`"
    echo "  fails CLOSED: the kernel drops every packet it matches, which on a"
    echo "  forwarding host is an outage. Remove the rule, or add \`bypass\`."
    echo
    echo "  These rules are not removed automatically because the sensor never"
    echo "  installed them — guessing which of your firewall rules are ours"
    echo "  would be a worse mistake than telling you they are there."
fi

echo
echo "Done. CyberSentinel-IPS has been removed."
