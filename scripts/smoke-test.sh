#!/usr/bin/env bash
#
# Local end-to-end smoke test for the MHS edge gateway under Viceroy.
#
# Builds the Compute wasm, starts a mock MHS backend (there is no public MHS
# spec to integrate against yet — see scripts/mock_mhs_backend.py), starts
# Viceroy, and drives the server over real HTTP with JSON-RPC: tools/list,
# a happy-path proxied tools/call, a Range-limit safety denial, an
# Allowed-limit safety denial, and central schema validation.
#
# Requirements:
#   - viceroy >= 0.20 on PATH (cargo install --locked viceroy), pinned to the
#     fastly = "=0.13.0" crate ABI it was verified against locally
#   - cargo with the wasm32-wasip1 target, plus curl, jq, python3
#
# Usage:
#   scripts/smoke-test.sh              # build + run
#   SKIP_BUILD=1 scripts/smoke-test.sh # reuse bin/main.wasm
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ADDR="127.0.0.1:7686"
URL="http://${ADDR}/"
MOCK_PORT="8899"
export SECRET_MRTR_AEAD_KEY_1="0123456789abcdef0123456789abcdef"

PASS=0
FAIL=0
VICEROY_PID=""
MOCK_PID=""

cleanup() {
  [ -n "$VICEROY_PID" ] && kill "$VICEROY_PID" 2>/dev/null
  [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null
}
trap cleanup EXIT

note()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
fail()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }

assert_eq() {
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (got '$2', want '$3')"; fi
}

rpc() { curl -s -X POST "$URL" -H 'Content-Type: application/json' -d "$1"; }

META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}'

# --- Build -------------------------------------------------------------
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  note "Building gateway-server (wasm32-wasip1)…"
  cargo build --release --target wasm32-wasip1 --package gateway-server || exit 1
  mkdir -p bin
  cp target/wasm32-wasip1/release/gateway-server.wasm bin/main.wasm
fi
[ -f bin/main.wasm ] || { echo "bin/main.wasm missing (run without SKIP_BUILD)"; exit 1; }

mkdir -p data
printf '{}\n' > data/kv_tasks.json
printf '{}\n' > data/kv_jwks.json
printf '{}\n' > data/kv_idem.json
printf '{}\n' > data/kv_device_limits.json

# --- Start the mock MHS backend -----------------------------------------
note "Starting mock MHS backend on ${MOCK_PORT}…"
python3 scripts/mock_mhs_backend.py "$MOCK_PORT" >/tmp/mhs-mock-smoke.log 2>&1 &
MOCK_PID=$!
sleep 0.3
kill -0 "$MOCK_PID" 2>/dev/null || { echo "mock backend failed to start:"; cat /tmp/mhs-mock-smoke.log; exit 1; }

# --- Start Viceroy -------------------------------------------------------
note "Starting Viceroy on ${ADDR} (demo config, auth disabled)…"
viceroy --addr "$ADDR" -C fastly.demo.toml bin/main.wasm >/tmp/mhs-gateway-viceroy.log 2>&1 &
VICEROY_PID=$!

ready=0
for _ in $(seq 1 40); do
  if curl -s -o /dev/null "$URL" -X POST -H 'Content-Type: application/json' -d '{}' 2>/dev/null; then
    ready=1; break
  fi
  kill -0 "$VICEROY_PID" 2>/dev/null || { echo "Viceroy exited early:"; tail -20 /tmp/mhs-gateway-viceroy.log; exit 1; }
  sleep 0.25
done
[ "$ready" = 1 ] || { echo "Viceroy did not become ready"; tail -20 /tmp/mhs-gateway-viceroy.log; exit 1; }

# --- 1. tools/list -------------------------------------------------------
note "tools/list"
RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{$META}}")
TOOLS=$(echo "$RES" | jq -r '[.result.tools[].name]|sort|join(",")')
assert_eq "lists move_joint, set_temperature" "$TOOLS" "move_joint,set_temperature"

# --- 2. happy path: proxies to the mock MHS driver -----------------------
note "tools/call set_temperature (within limits -> proxied)"
RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"set_temperature\",\"arguments\":{\"celsius\":37},$META}}")
assert_eq "completes, not an error" "$(echo "$RES" | jq -r '.result.isError')" "false"
BACKEND_TOOL=$(echo "$RES" | jq -r '.result.content[0].text' | jq -r '.received.tool')
assert_eq "mock driver received the tool name" "$BACKEND_TOOL" "set_temperature"

# --- 3. safety policy: Range limit denial --------------------------------
note "tools/call set_temperature (out of range -> safety denial)"
RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"set_temperature\",\"arguments\":{\"celsius\":999},$META}}")
assert_eq "is a tool-execution error" "$(echo "$RES" | jq -r '.result.isError')" "true"
TEXT=$(echo "$RES" | jq -r '.result.content[0].text')
case "$TEXT" in *celsius*) pass "denial names the violated field" ;; *) fail "denial should name 'celsius', got: $TEXT" ;; esac

# --- 4. safety policy: Allowed (enum) limit denial -----------------------
note "tools/call move_joint (bad axis -> safety denial)"
RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"move_joint\",\"arguments\":{\"axis\":\"w\",\"angle_degrees\":10},$META}}")
assert_eq "is a tool-execution error" "$(echo "$RES" | jq -r '.result.isError')" "true"

# --- 5. central schema validation (inherited from mcp-core, unmodified) --
note "tools/call set_temperature (missing required field -> -32602)"
RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"set_temperature\",\"arguments\":{},$META}}")
assert_eq "rejected before the handler runs" "$(echo "$RES" | jq -r '.error.code')" "-32602"

# --- 6. unsupported protocol version (inherited, unmodified) -------------
note "unsupported protocol version -> -32022"
RES=$(rpc '{"jsonrpc":"2.0","id":6,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1999-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}')
assert_eq "rejects old protocol version" "$(echo "$RES" | jq -r '.error.code')" "-32022"

# --- Known local-only gap (documented, not a failure) --------------------
note "Rate limiting: NOT exercised as a pass/fail check here"
echo "  Viceroy's ERL (RateCounter/Penaltybox) host calls do not appear to enforce"
echo "  limits locally (calls past max_calls_per_window still succeed) — the same"
echo "  category of gap edge-mcp's own README documents for local Viceroy testing"
echo "  (CPU meter, KV consistency, cache-purge propagation). Validate on a real"
echo "  Fastly service before relying on it."

note "Smoke test: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
