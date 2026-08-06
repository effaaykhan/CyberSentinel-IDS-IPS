#!/bin/sh
# Measure what inline prevention costs, before anyone arms it on a live segment.
#
#   sudo sh packaging/linux/measure-prevention.sh [sensor-binary]
#
# Two numbers decide whether an IPS is safe to put in a path:
#
#   verdict latency  — how long the kernel holds each packet because of us.
#                      Added to every packet, so it is the sensor's tax on the
#                      link even when nothing matches.
#   queue depth      — how many packets are waiting. This grows *before*
#                      anything is dropped, which makes it the early warning;
#                      `queue_unjudged` is the confirmation that it was too
#                      late. From inside the verdict loop, packets the kernel
#                      dropped are indistinguishable from a quiet link, which
#                      is why the reading comes from
#                      /proc/net/netfilter/nfnetlink_queue and not from us.
#
# Everything runs on loopback in its own nftables table, so it cannot disturb
# the machine's real networking. Loopback is also the honest limitation: it has
# no NIC, no driver, and a far higher packet rate than most links, so it
# stresses the verdict path harder than a real segment while telling you
# nothing about how the sensor behaves behind a saturated interface.

set -eu

SENSOR="${1:-./target/release/cybersentinel}"
TABLE=cybersentinel_measure
QUEUE=23
WORK=$(mktemp -d)
SAMPLES="$WORK/depth.tsv"

cleanup() {
    kill "${SENSOR_PID:-0}" "${LOAD_PID:-0}" 2>/dev/null || true
    nft delete table inet "$TABLE" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

[ "$(id -u)" = 0 ] || { echo "run as root: this binds a netfilter queue" >&2; exit 1; }
[ -x "$SENSOR" ] || { echo "no sensor binary at $SENSOR" >&2; exit 1; }

cat > "$WORK/config.yaml" <<EOF
paths: {data-dir: "$WORK/data", log-dir: "$WORK/logs"}
rules: {directory: "$WORK", files: []}
hids: {enabled: false}
capture: {enabled: false}
prevent:
  enabled: true
  mode: prevent
  fail-mode: open
  queue: $QUEUE
  queue-length: 1024
outputs: {stdout: {enabled: true}, file: {enabled: false}}
logging: {level: info, queue-capacity: 4096}
stats: {enabled: true, interval-secs: 1}
EOF

# Queue everything on loopback. `bypass` so a saturated queue accepts rather
# than drops — the fail-open default, and the one where an overrun shows up as
# unjudged packets rather than as an outage.
nft delete table inet "$TABLE" 2>/dev/null || true
nft add table inet "$TABLE"
nft add chain inet "$TABLE" out '{ type filter hook output priority 0; }'
nft add rule inet "$TABLE" out ip daddr 127.0.0.7 queue num "$QUEUE" bypass

printf 'CyberSentinel inline prevention — load measurement\n'
printf '  queue %s, loopback, fail-open\n\n' "$QUEUE"

"$SENSOR" run --config "$WORK/config.yaml" >"$WORK/events.json" 2>"$WORK/err.log" &
SENSOR_PID=$!
for _ in $(seq 1 40); do
    grep -q "verdict path running" "$WORK/err.log" 2>/dev/null && break
    sleep 0.25
done
grep -q "verdict path running" "$WORK/err.log" || {
    echo "the verdict path never bound:" >&2
    tail -3 "$WORK/err.log" >&2
    exit 1
}

# Sample the kernel's view while the load runs. The sensor publishes its own
# depth reading once a second; this samples far faster, because a queue that
# backs up and drains between two stats events would otherwise be invisible.
sample_depth() {
    trap - EXIT INT TERM
    while :; do
        awk -v q="$QUEUE" '$1 == q { print $3, $6, $7 }' \
            /proc/net/netfilter/nfnetlink_queue 2>/dev/null >> "$SAMPLES" || true
        sleep 0.05
    done
}

run_load() {
    label=$1
    shift
    : > "$SAMPLES"
    printf '  %-22s' "$label"
    sample_depth & SAMPLER=$!
    "$@" >/dev/null 2>&1 || true
    sleep 0.5
    kill "$SAMPLER" 2>/dev/null || true
    wait "$SAMPLER" 2>/dev/null || true

    awk '
        { if ($1 > maxq) maxq = $1; qd = $2; ud = $3; n++ }
        END {
            if (n == 0) { print "no samples"; exit }
            printf "peak depth %5d   kernel-dropped %6d   user-dropped %6d\n", maxq, qd, ud
        }
    ' "$SAMPLES"
}

printf 'Load\n'
# Flood ping: the highest packet rate available without extra tooling. Each
# echo-request is one queued packet, so this is a pure verdict-path stress.
run_load "flood ping 10k" ping -f -c 10000 -W 1 127.0.0.7
run_load "flood ping 50k" ping -f -c 50000 -W 1 127.0.0.7

if command -v iperf3 >/dev/null 2>&1; then
    iperf3 -s -B 127.0.0.7 -1 >/dev/null 2>&1 &
    IPERF_PID=$!
    sleep 0.5
    run_load "iperf3 tcp 5s" iperf3 -c 127.0.0.7 -t 5 -P 4
    kill "$IPERF_PID" 2>/dev/null || true
fi

sleep 1.5
kill "$SENSOR_PID" 2>/dev/null || true
wait "$SENSOR_PID" 2>/dev/null || true

printf '\nSensor'"'"'s own view (final stats event)\n'
python3 - "$WORK/events.json" <<'EOF'
import json, sys
last = None
for line in open(sys.argv[1]):
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if event.get("event_type") == "stats":
        last = event["stats"]["prevent"]
if not last:
    print("  no stats events"); raise SystemExit(1)

judged = last["packets_judged"]
total = last["verdict_latency_us_total"]
mean = (total / judged) if judged else 0
print(f"  packets judged      {judged}")
print(f"  mean latency        {mean:.1f} us")
print(f"  worst latency       {last['verdict_latency_us_max']} us")
print(f"  over 1ms / 10ms     {last['verdict_latency_over_1ms']} / {last['verdict_latency_over_10ms']}")
print(f"  peak queue depth    {last['queue_depth_max']}")
print(f"  never judged        {last['queue_unjudged']}  <- kernel dropped these before we saw them")
EOF
