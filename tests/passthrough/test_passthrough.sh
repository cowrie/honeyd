#!/bin/bash
# ABOUTME: Integration test for honeyd passthrough/proxy configuration
# ABOUTME: Verifies that honeyd correctly proxies traffic to real local services

set -e

HONEYD_BIN="${HONEYD_BIN:-/usr/local/bin/honeyd}"
# Support both in-container and local paths
if [ -f "/src/honeyd/config.passthrough" ]; then
    CONFIG_FILE="${CONFIG_FILE:-/src/honeyd/config.passthrough}"
else
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/../../config.passthrough}"
fi

# Network configuration
HONEYD_VIRTUAL_IP="192.0.2.100"
HONEYD_HOST_IP="192.0.2.1"
TEST_NETWORK="192.0.2.0/24"
TEST_SERVICE_PORT="8888"

# Unique namespace name
NS_TEST="hd_proxy_$$"

# Track test results
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ -n "$HONEYD_PID" ]; then
        kill "$HONEYD_PID" 2>/dev/null || true
        wait "$HONEYD_PID" 2>/dev/null || true
    fi
    if [ -n "$SERVICE_PID" ]; then
        kill "$SERVICE_PID" 2>/dev/null || true
    fi
    ip netns delete "$NS_TEST" 2>/dev/null || true
}

trap cleanup EXIT

run_test() {
    local name="$1"
    local cmd="$2"
    TESTS_RUN=$((TESTS_RUN + 1))

    echo -n "  $name... "
    if eval "$cmd" > /dev/null 2>&1; then
        echo "PASS"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo "FAIL"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

ns_exec() {
    ip netns exec "$NS_TEST" "$@"
}

echo "=== Honeyd Passthrough Proxy Test ==="
echo ""

# Verify honeyd binary exists
if [ ! -x "$HONEYD_BIN" ]; then
    echo "ERROR: honeyd binary not found at $HONEYD_BIN"
    exit 1
fi
echo "[Setup] Binary exists: OK"

# Create a temporary config with the test IP
TEMP_CONFIG=$(mktemp)
sed "s/192.168.1.100/$HONEYD_VIRTUAL_IP/g" "$CONFIG_FILE" > "$TEMP_CONFIG"
echo "[Setup] Config prepared: OK"

# Verify config syntax
if ! "$HONEYD_BIN" --verify-config -f "$TEMP_CONFIG" "$TEST_NETWORK" 2>/dev/null; then
    echo "ERROR: Configuration file validation failed"
    cat "$TEMP_CONFIG"
    rm -f "$TEMP_CONFIG"
    exit 1
fi
echo "[Setup] Config valid: OK"

# Create network namespace
ip netns add "$NS_TEST"
ns_exec ip link set lo up
ns_exec ip addr add "$HONEYD_HOST_IP/32" dev lo
ns_exec ip route add "$TEST_NETWORK" dev lo
echo "[Setup] Network namespace created: OK"

# Start a simple test service on localhost (in the namespace)
# This uses nc to listen and echo a response
ns_exec sh -c "while true; do echo 'PROXY_TEST_RESPONSE' | nc -l -p $TEST_SERVICE_PORT -q 1 2>/dev/null || true; done" &
SERVICE_PID=$!
sleep 1
echo "[Setup] Test service started on port $TEST_SERVICE_PORT: OK"

# Start honeyd with the passthrough config
ns_exec "$HONEYD_BIN" -d -f "$TEMP_CONFIG" -i lo "$TEST_NETWORK" 2>&1 &
HONEYD_PID=$!
sleep 2

if ! kill -0 "$HONEYD_PID" 2>/dev/null; then
    echo "ERROR: honeyd failed to start"
    rm -f "$TEMP_CONFIG"
    exit 1
fi
echo "[Setup] Honeyd started (PID $HONEYD_PID): OK"
echo ""

# === ICMP Tests ===
echo "[ICMP Tests]"
run_test "Ping virtual host" "ns_exec ping -c 1 -W 2 $HONEYD_VIRTUAL_IP"
echo ""

# === TCP Proxy Tests ===
echo "[TCP Proxy Tests]"

# Test that connecting to the honeyd IP on the test port proxies to localhost
TESTS_RUN=$((TESTS_RUN + 1))
echo -n "  TCP proxy to local service... "
RESPONSE=$(ns_exec sh -c "echo 'test' | nc -w 2 $HONEYD_VIRTUAL_IP $TEST_SERVICE_PORT" 2>/dev/null || true)
if echo "$RESPONSE" | grep -q "PROXY_TEST_RESPONSE"; then
    echo "PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "FAIL (got: '$RESPONSE')"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# === UDP Tests ===
echo "[UDP Tests]"
# UDP proxy is harder to test without a specific UDP service
# Just verify the port accepts packets (no ICMP unreachable)
run_test "UDP port accepts packets" "ns_exec sh -c 'echo test | nc -u -w 1 $HONEYD_VIRTUAL_IP 53'"
echo ""

# === OS Fingerprint Test ===
echo "[OS Fingerprint Tests]"
echo "  Running nmap OS detection..."
TESTS_RUN=$((TESTS_RUN + 1))
NMAP_OUTPUT=$(ns_exec nmap -O --osscan-guess "$HONEYD_VIRTUAL_IP" 2>&1 || true)
echo "$NMAP_OUTPUT" | sed 's/^/    /'
echo ""
echo -n "  Result: "
if echo "$NMAP_OUTPUT" | grep -qi "cisco"; then
    echo "PASS (detected Cisco)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "FAIL (Cisco not detected)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Cleanup temp config
rm -f "$TEMP_CONFIG"

# === Summary ===
echo "========================================="
echo "Tests run: $TESTS_RUN"
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
echo "========================================="

if [ $TESTS_FAILED -eq 0 ]; then
    echo "=== ALL PASSTHROUGH TESTS PASSED ==="
    exit 0
else
    echo "=== PASSTHROUGH TESTS FAILED ==="
    exit 1
fi
