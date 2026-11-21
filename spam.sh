#!/usr/bin/env bash
# Copyright (c) 2026 Aldianokto
# Distributed under the Apache License, see the accompanying
# file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.
#
# Spam script for mainnet: send a fixed amount to a fixed address every N
# milliseconds by calling the local node through its CLI. The network
# defaults to mainnet; pass -testnet or -regtest explicitly to override.
#
# Usage:
#   ./spam.sh [interval_ms] [amount_xepc] [destination] [count] [network_flag] [datadir]
#
# Defaults:
#   interval_ms   = 1000
#   amount_xepc   = 0.01
#   destination   = XJFAMNgAY6X1sNFL8yowSrJ5b7VuPvRSdU
#   count         = 0   (0 means run forever)
#   network_flag  = ""  (empty string means mainnet)
#   datadir       = ""  (empty string means use the compiled-in default)
#
# Examples:
#   ./spam.sh 1000
#   ./spam.sh 500 0.01 XJFAMNgAY6X1sNFL8yowSrJ5b7VuPvRSdU 100
#   ./spam.sh 1000 0.01 XJFAMNgAY6X1sNFL8yowSrJ5b7VuPvRSdU 0 "" /root/.xepay-b

set -u

INTERVAL_MS="${1:-1000}"
AMOUNT_XEPC="${2:-0.01}"
DESTINATION="${3:-XJFAMNgAY6X1sNFL8yowSrJ5b7VuPvRSdU}"
COUNT="${4:-0}"
NETWORK_FLAG="${5:-}"
DATADIR="${6:-}"

XEPAY_BIN="./xepay"

if [ ! -x "$XEPAY_BIN" ]; then
    echo "error: $XEPAY_BIN not found or not executable. Run ./build.sh first."
    exit 1
fi

if ! [[ "$INTERVAL_MS" =~ ^[0-9]+$ ]]; then
    echo "error: interval_ms must be a non-negative integer"
    exit 1
fi

if ! [[ "$COUNT" =~ ^[0-9]+$ ]]; then
    echo "error: count must be a non-negative integer"
    exit 1
fi

if [ -n "$DATADIR" ]; then
    export XEPC_DATADIR="$DATADIR"
fi

INTERVAL_SEC=$(awk "BEGIN { printf \"%.3f\", $INTERVAL_MS / 1000 }")

# Build the argument list. An empty NETWORK_FLAG means mainnet, which is
# the compiled-in default, so the flag is omitted entirely.
if [ -n "$NETWORK_FLAG" ]; then
    NET_ARG=("$NETWORK_FLAG")
else
    NET_ARG=()
fi

echo "[spam] network     : ${NETWORK_FLAG:-mainnet (default)}"
echo "[spam] datadir     : ${DATADIR:-<compiled-in default>}"
echo "[spam] destination : $DESTINATION"
echo "[spam] amount      : $AMOUNT_XEPC XEPC"
echo "[spam] interval    : ${INTERVAL_MS} ms"
if [ "$COUNT" -eq 0 ]; then
    echo "[spam] count       : infinite (Ctrl+C to stop)"
else
    echo "[spam] count       : $COUNT"
fi
echo

SENT=0
FAILED=0
START_TS=$(date +%s)

while :; do
    if [ "$COUNT" -ne 0 ] && [ "$SENT" -ge "$COUNT" ]; then
        break
    fi

    OUT=$("$XEPAY_BIN" "${NET_ARG[@]}" sendtoaddress "$AMOUNT_XEPC" "$DESTINATION" 2>&1)
    RC=$?

    if [ $RC -eq 0 ] && echo "$OUT" | grep -q '"txid"'; then
        TXID=$(echo "$OUT" | grep -o '"txid"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | sed 's/.*"\([^"]*\)"$/\1/')
        SENT=$((SENT + 1))
        echo "[spam] #$SENT txid=$TXID"
    else
        FAILED=$((FAILED + 1))
        echo "[spam] failed (rc=$RC): $OUT"
    fi

    sleep "$INTERVAL_SEC"
done

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))
if [ "$ELAPSED" -eq 0 ]; then ELAPSED=1; fi
RATE=$(awk "BEGIN { printf \"%.2f\", $SENT / $ELAPSED }")

echo
echo "[spam] done: sent=$SENT failed=$FAILED elapsed=${ELAPSED}s rate=${RATE} tx/s"
