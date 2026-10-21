#!/usr/bin/env bash
# End-to-end check of the live defender with REAL packets and a REAL firewall, no second laptop needed.
#
# It builds a tiny virtual network inside this machine (a bridge plus two network namespaces: one
# plays the attacker, one plays the phone), runs the live defender on the bridge, lets the "phone"
# check in, has the "attacker" port-scan the box, and verifies that:
#   1. the scan is detected and the source is blocked by a real iptables rule,
#   2. the scanner's connections now time out (the block really works),
#   3. the phone keeps getting replies throughout (no collateral damage),
#   4. the block expires on its own, and
#   5. when the defender stops, every rule it added is gone.
#
# Usage (from ~/iot-defense, needs root for namespaces and iptables):
#   sudo bash scripts/live_selftest.sh
set -u

if [ "$(id -u)" -ne 0 ]; then echo "run with sudo: sudo bash scripts/live_selftest.sh"; exit 2; fi
cd "$(dirname "$0")/.." || exit 2
PY=".venv/bin/python3"
BR=iotbr0; BOX=10.77.0.1; ATK=10.77.0.2; PHN=10.77.0.3
STATE=/tmp/selftest_state.json; LOG=/tmp/selftest_defender.log; PHONE_LOG=/tmp/selftest_phone.log
TTL=25
FAILS=0

say()  { printf '\n== %s\n' "$*"; }
ok()   { printf '   PASS  %s\n' "$*"; }
bad()  { printf '   FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

cleanup() {
  [ -n "${DEF_PID:-}" ] && kill -INT "$DEF_PID" 2>/dev/null && wait "$DEF_PID" 2>/dev/null
  [ -n "${PHONE_PID:-}" ] && kill "$PHONE_PID" 2>/dev/null
  ip netns del iotatk 2>/dev/null; ip netns del iotphn 2>/dev/null
  ip link del v-atk 2>/dev/null; ip link del v-phn 2>/dev/null; ip link del $BR 2>/dev/null
  PYTHONPATH=src $PY -m iot_defense.live.defender restore --iface $BR --box-ip $BOX >/dev/null 2>&1
}
trap cleanup EXIT
cleanup  # start from a clean slate

say "Building a virtual network: bridge $BR ($BOX) with an attacker ($ATK) and a phone ($PHN)"
ip link add $BR type bridge && ip addr add $BOX/24 dev $BR && ip link set $BR up || { echo "could not create the bridge"; exit 2; }
for pair in "atk iotatk $ATK" "phn iotphn $PHN"; do
  set -- $pair
  ip netns add "$2"
  ip link add "v-$1" type veth peer name "p-$1"
  ip link set "v-$1" master $BR && ip link set "v-$1" up
  ip link set "p-$1" netns "$2"
  ip netns exec "$2" ip addr add "$3/24" dev "p-$1"
  ip netns exec "$2" ip link set "p-$1" up
  ip netns exec "$2" ip link set lo up
done

say "Starting the live defender (blocks last ${TTL}s)"
PYTHONPATH=src $PY -m iot_defense.live.defender run --iface $BR --box-ip $BOX --ttl $TTL --state $STATE --port 8080 >"$LOG" 2>&1 &
DEF_PID=$!
for _ in $(seq 1 90); do
  ip netns exec iotphn $PY -c "import urllib.request;urllib.request.urlopen('http://$BOX:8080/ping',timeout=1)" 2>/dev/null && break
  sleep 1
done
kill -0 "$DEF_PID" 2>/dev/null || { echo "defender did not start; log:"; cat "$LOG"; exit 2; }
ok "defender is up and the protected page answers"

say "The phone starts checking in every 2 seconds (keep-alive, like the real page)"
: >"$PHONE_LOG"
ip netns exec iotphn $PY - >"$PHONE_LOG" 2>&1 <<EOF &
import http.client, time
conn = http.client.HTTPConnection("$BOX", 8080, timeout=1.5)
while True:
    try:
        conn.request("GET", "/ping"); conn.getresponse().read(); print("OK", time.time(), flush=True)
    except Exception as exc:
        print("FAIL", time.time(), flush=True)
        conn = http.client.HTTPConnection("$BOX", 8080, timeout=1.5)
    time.sleep(2)
EOF
PHONE_PID=$!
sleep 8
[ "$(grep -c '^OK' "$PHONE_LOG")" -ge 3 ] && ok "phone is being served ($(grep -c '^OK' "$PHONE_LOG") replies)" || bad "phone is not being served"
[ "$(grep -c '^FAIL' "$PHONE_LOG")" -eq 0 ] && ok "no missed replies before the attack" || bad "phone missed replies before any attack"

scan() {  # scan(first_port, last_port, per_port_timeout) -> "refused=N timeout=N open=N seconds"
  ip netns exec iotatk $PY - "$@" <<'PYEOF'
import socket, sys, time
first, last, wait = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
refused = timeout = opened = 0
t0 = time.time()
for port in range(first, last + 1):
    s = socket.socket(); s.settimeout(wait)
    try:
        s.connect(("10.77.0.1", port)); opened += 1
    except ConnectionRefusedError:
        refused += 1
    except OSError:
        timeout += 1
    finally:
        s.close()
print(f"refused={refused} timeout={timeout} open={opened} seconds={time.time() - t0:.1f}")
PYEOF
}

say "ATTACK: the attacker port-scans ports 1-400 of the box"
BEFORE=$(scan 1 400 0.3)
echo "   scan result: $BEFORE"
echo "$BEFORE" | grep -qE "refused=(3[0-9][0-9]|400)" && ok "before the block the box answers every closed port with a refusal" || bad "unexpected scan result before the block"

say "Waiting for detect -> decide -> respond (up to 30 s)"
START=$(date +%s)
for _ in $(seq 1 60); do
  iptables -S IOTDEF 2>/dev/null | grep -q "iotdef:block:$ATK" && break
  sleep 0.5
done
ELAPSED=$(( $(date +%s) - START ))
echo "   block appeared ${ELAPSED} s after the scan"
[ "$ELAPSED" -le 10 ] && ok "the response came within 10 s of the scan" || bad "the response took ${ELAPSED} s (too slow: the scan would be over)"
if iptables -S IOTDEF 2>/dev/null | grep -q "iotdef:block:$ATK"; then ok "a real iptables DROP rule for $ATK is installed"; else bad "no block rule for $ATK"; fi
iptables -S IOTDEF 2>/dev/null | grep -q "iotdef:block:$PHN" && bad "the phone was blocked" || ok "the phone was NOT blocked"

AFTER=$(scan 1000 1015 0.4)
echo "   scan result after the block: $AFTER"
echo "$AFTER" | grep -qE "timeout=1[0-6]" && ok "after the block the scanner's connections time out (dropped)" || bad "scanner still gets answers after the block"

say "Checking what the dashboard would show"
sleep 2
$PY - <<EOF
import json, sys
s = json.load(open("$STATE"))
checks = [
    ("attack identified as a port scan", s.get("attack_mode") == "reconnaissance"),
    ("an action was selected by the arbiter or a policy", bool(s.get("selected_decision"))),
    ("the selected action was BLOCK_SOURCE", (s.get("selected_decision") or {}).get("action") == "BLOCK_SOURCE"),
    ("the response succeeded", (s.get("response_result") or {}).get("status") == "success"),
    ("the firewall counter shows dropped packets", any(b.get("packets_dropped", 0) > 0 for b in s["live"]["blocks"])),
    ("the phone is listed as a trusted normal user", "$PHN" in s["live"]["trusted"]),
]
for name, passed in checks:
    print(("   PASS  " if passed else "   FAIL  ") + name)
sys.exit(0 if all(p for _, p in checks) else 1)
EOF
[ $? -eq 0 ] || FAILS=$((FAILS + 1))

say "Phone during and after the attack"
MISSED=$(grep -c '^FAIL' "$PHONE_LOG"); [ "$MISSED" -eq 0 ] && ok "the phone never missed a reply" || bad "the phone missed $MISSED replies"

say "Waiting for the block to expire (${TTL}s)"
sleep $((TTL + 6))
iptables -S IOTDEF 2>/dev/null | grep -q "iotdef:block:$ATK" && bad "the block did not expire" || ok "the block expired and its rule was removed"
AGAIN=$(scan 2000 2015 0.3)
echo "   scan result after expiry: $AGAIN"
echo "$AGAIN" | grep -q "refused=1[0-6]" && ok "the attacker's address is allowed again" || bad "traffic from the attacker is still dropped"

say "Stopping the defender: every rule it added must disappear"
kill -INT "$DEF_PID" 2>/dev/null; wait "$DEF_PID" 2>/dev/null; DEF_PID=""
iptables -S 2>/dev/null | grep -q "IOTDEF" && bad "IOTDEF rules or hook still present" || ok "no IOTDEF chain or hook remains"

echo
if [ "$FAILS" -eq 0 ]; then echo "SELF-TEST PASSED: the live defender detected, blocked, protected the phone, expired the block and cleaned up."; exit 0; fi
echo "SELF-TEST FAILED ($FAILS problem(s)). Defender log: $LOG; phone log: $PHONE_LOG"; exit 1
