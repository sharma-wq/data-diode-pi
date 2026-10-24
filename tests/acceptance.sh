#!/usr/bin/env bash
# tests/acceptance.sh — invariant smoke tests for the data diode.
# Run on an installed Pi:  sudo tests/acceptance.sh
set -uo pipefail

PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
ck()  { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

CTL=/usr/local/sbin/diode-controller.py
CFG=/etc/diode/diode.conf
NFTFILE=/etc/nftables-diode.conf
HMACKEY=/etc/diode/hmac.key

echo "== prerequisite checks =="
ck "controller present"                 "[ -x $CTL ]"
ck "config present"                     "[ -f $CFG ]"
ck "hmac key present"                   "[ -f $HMACKEY ]"
ck "hmac key mode 0600"                 "[ \"\$(stat -c %a $HMACKEY 2>/dev/null)\" = '600' ]"
ck "hmac key owned by root"             "[ \"\$(stat -c %U $HMACKEY 2>/dev/null)\" = 'root' ]"
ck "nftables base ruleset present"      "[ -f $NFTFILE ]"
ck "no shell=True in controller"        "! grep -q 'shell=True' $CTL"

echo
echo "== AC-1: at most one ETH UP =="
up=$(ip -br link | awk '$2=="UP" && $1 ~ /^eth/ {print $1}')
if [ "$(echo "$up" | wc -w)" -le 1 ]; then
    ok "one-eth-up (current: ${up:-none})"
else
    bad "one-eth-up (both up: $up)"
fi

echo
echo "== AC-3: firewall at rest =="
if nft list table inet diode >/dev/null 2>&1; then
    rules=$(nft -a list chain inet diode input 2>/dev/null \
            | grep -c "ct state new counter accept" || true)
    if [ "${rules:-0}" -eq 0 ]; then
        ok "no-app-accept-at-rest"
    else
        bad "no-app-accept-at-rest ($rules rules)"
    fi
    pol_in=$(nft  list chain inet diode input  2>/dev/null \
             | grep -o 'policy [a-z]*' | awk '{print $2}')
    pol_out=$(nft list chain inet diode output 2>/dev/null \
             | grep -o 'policy [a-z]*' | awk '{print $2}')
    pol_fw=$(nft  list chain inet diode forward 2>/dev/null \
             | grep -o 'policy [a-z]*' | awk '{print $2}')
    ck "input policy drop"   "[ \"$pol_in\"  = drop ]"
    ck "output policy drop"  "[ \"$pol_out\" = drop ]"
    ck "forward policy drop" "[ \"$pol_fw\"  = drop ]"
else
    bad "table inet diode not loaded"
fi

echo
echo "== AC-4: SIGTERM brings links down =="
if [ -x "$CTL" ] && [ -f "$CFG" ]; then
    "$CTL" --config "$CFG" --once >/dev/null 2>&1 &
    pid=$!
    sleep 2
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    up=$(ip -br link | awk '$2=="UP" && $1 ~ /^eth/ {print}' | wc -l)
    ck "sigterm-links-down" "[ \"$up\" -eq 0 ]"
else
    bad "sigterm-links-down (prereq missing)"
fi

echo
echo "== AC-2: insecure URL rejected by fetch worker =="
if [ -x "$CTL" ]; then
    if "$CTL" --fetch-worker --url "http://insecure.example/x" \
              --dest /tmp/diode-test.bin --ca /etc/ssl/certs/ca-certificates.crt \
              --timeout 5 --max-bytes 1000 --max-redirects 1 \
              >/dev/null 2>&1; then
        bad "http-url-rejected (fetch unexpectedly succeeded)"
    else
        ok "http-url-rejected"
    fi
else
    bad "http-url-rejected (controller missing)"
fi

echo
echo "== Summary: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ]