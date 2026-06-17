#!/bin/bash
# End-to-end smoke test for the cloudflared sidecar.
# Usage: ./smoke_test.sh
#
# Spawns the sidecar with a fake cloudflared, then drives it over stdin
# JSON-RPC to exercise init -> start -> get_state -> get_logs -> stop.

set -euo pipefail

SIDECAR=/tmp/sidecar
MOCK=/tmp/mock-cloudflared

# 1) ping / init
echo '> ping'
echo '{"jsonrpc":"2.0","method":"ping","id":1}' | timeout 3 $SIDECAR | head -1

# 2) init with fake binary + short timeout
echo ''
echo '> init'
echo '{"jsonrpc":"2.0","method":"init","params":{"name":"smoke","mode":"quick","origin_url":"http://127.0.0.1:3000","binary_path":"'"$MOCK"'","start_timeout_seconds":2000000000},"id":2}' | timeout 3 $SIDECAR | head -2

# 3) start the fake cloudflared — it will emit "registered tunnel connection"
echo ''
echo '> start'
(
  echo '{"jsonrpc":"2.0","method":"init","params":{"name":"smoke","mode":"quick","origin_url":"http://127.0.0.1:3000","binary_path":"'"$MOCK"'","start_timeout_seconds":3000000000},"id":1}'
  sleep 1
  echo '{"jsonrpc":"2.0","method":"start","id":2}'
  sleep 2
  echo '{"jsonrpc":"2.0","method":"get_state","id":3}'
  sleep 1
  echo '{"jsonrpc":"2.0","method":"get_logs","params":{"n":10},"id":4}'
  sleep 1
  echo '{"jsonrpc":"2.0","method":"stop","id":5}'
) | timeout 10 $SIDECAR

echo ''
echo "--- smoke test done ---"
