#!/bin/sh
# Soak the verdict path: does it drift?
#
#   sudo sh packaging/linux/soak-prevention.sh [seconds] [sensor-binary]
#
# measure-prevention.sh answers "what does a verdict cost". This answers the
# different question a five-second burst cannot: **does anything grow that
# should not**, over minutes rather than moments. An IPS holds state per
# condemned flow and per blocked source, and both are fed by whoever is
# attacking — the shape of a leak an attacker gets to trigger.
#
# What it watches, sampled once a second from the sensor's own `stats` events
# and from `/proc`:
#
#   RSS              — the process's memory. Flat is the only acceptable shape.
#   queue_unjudged   — packets that never reached a verdict. Must stay at zero;
#                      a rising value means the fail mode is deciding.
#   mean latency     — recomputed per interval, not cumulative, so a slow drift
#                      upward is visible rather than averaged away by the first
#                      quiet minute.
#   queue depth      — the early warning that precedes unjudged packets.
#
# Loopback, its own nftables table, cleaned up on exit.

set -eu

SECONDS_TO_RUN="${1:-180}"
SENSOR="${2:-./target/release/cybersentinel}"
TABLE=cybersentinel_soak
QUEUE=29
TARGET=127.0.0.11
WORK=$(mktemp -d)

cleanup() {
    trap - EXIT INT TERM
    kill "${LOAD_PID:-0}" "${SENSOR_PID:-0}" 2>/dev/null || true
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
  # Short, so expiry is exercised many times within the soak rather than never.
  source-block-secs: 20
outputs: {stdout: {enabled: true}, file: {enabled: false}}
logging: {level: info, queue-capacity: 4096}
stats: {enabled: true, interval-secs: 1}
EOF

nft delete table inet "$TABLE" 2>/dev/null || true
nft add table inet "$TABLE"
nft add chain inet "$TABLE" out '{ type filter hook output priority 0; }'
nft add rule inet "$TABLE" out ip daddr "$TARGET" queue num "$QUEUE" bypass

printf 'CyberSentinel verdict-path soak — %s seconds\n\n' "$SECONDS_TO_RUN"

"$SENSOR" run --config "$WORK/config.yaml" >"$WORK/events.json" 2>"$WORK/err.log" &
SENSOR_PID=$!
for _ in $(seq 1 40); do
    grep -q "verdict path running" "$WORK/err.log" 2>/dev/null && break
    sleep 0.25
done
grep -q "verdict path running" "$WORK/err.log" || {
    echo "the verdict path never bound:" >&2; tail -3 "$WORK/err.log" >&2; exit 1
}

# Continuous load for the whole soak.
( while :; do ping -f -c 20000 -W 1 "$TARGET" >/dev/null 2>&1 || sleep 0.1; done ) &
LOAD_PID=$!

# Sample RSS alongside the sensor's own counters: the sensor cannot report its
# own leak, and a flat counter with a growing heap is the failure this is for.
: > "$WORK/rss.tsv"
( while :; do
    awk '/^VmRSS:/ {print $2}' "/proc/$SENSOR_PID/status" 2>/dev/null >> "$WORK/rss.tsv" || true
    sleep 1
  done ) &
RSS_PID=$!

sleep "$SECONDS_TO_RUN"
kill "$LOAD_PID" "$RSS_PID" 2>/dev/null || true
sleep 2
kill "$SENSOR_PID" 2>/dev/null || true
wait "$SENSOR_PID" 2>/dev/null || true

python3 - "$WORK/events.json" "$WORK/rss.tsv" <<'EOF'
import json, sys

samples = []
for line in open(sys.argv[1]):
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if event.get("event_type") == "stats":
        samples.append(event["stats"]["prevent"])
if len(samples) < 5:
    print("  too few stats events to judge drift"); raise SystemExit(1)

def interval_mean(a, b):
    packets = b["packets_judged"] - a["packets_judged"]
    micros = b["verdict_latency_us_total"] - a["verdict_latency_us_total"]
    return (micros / packets) if packets else 0.0

# Compare the first tenth of the run against the last tenth. A cumulative mean
# hides a slow climb; this does not.
span = max(2, len(samples) // 10)
early = [interval_mean(samples[i], samples[i + 1]) for i in range(span)]
late = [interval_mean(samples[-span + i - 1], samples[-span + i]) for i in range(1, span)]
early_mean = sum(early) / len(early)
late_mean = sum(late) / len(late) if late else 0.0

final = samples[-1]
judged = final["packets_judged"]
print(f"  packets judged        {judged}")
print(f"  mean latency early    {early_mean:.1f} us")
print(f"  mean latency late     {late_mean:.1f} us")
print(f"  worst latency         {final['verdict_latency_us_max']} us")
print(f"  over 1ms / 10ms       {final['verdict_latency_over_1ms']} / {final['verdict_latency_over_10ms']}")
print(f"  peak queue depth      {final['queue_depth_max']}")
print(f"  never judged          {final['queue_unjudged']}")
print(f"  blocked flows active  {final['blocked_flows_active']}")
print(f"  blocked sources activ {final['blocked_sources_active']}")

rss = [int(v) for v in open(sys.argv[2]).read().split()]
if rss:
    print(f"  RSS first / last      {rss[0]} / {rss[-1]} kB  (peak {max(rss)})")

problems = []
if final["queue_unjudged"] > 0:
    problems.append(f"{final['queue_unjudged']} packets never reached a verdict")
if late_mean > early_mean * 3 and late_mean > 50:
    problems.append(f"latency drifted from {early_mean:.1f}us to {late_mean:.1f}us")
if rss and max(rss) > rss[0] * 2 and max(rss) - rss[0] > 20_000:
    problems.append(f"RSS grew from {rss[0]} to {max(rss)} kB")

print()
if problems:
    for problem in problems:
        print(f"  PROBLEM  {problem}")
    raise SystemExit(1)
print("  no drift: latency flat, memory flat, every packet judged.")
EOF
