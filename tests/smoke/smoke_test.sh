#!/bin/bash
# ABOUTME: Smoke test for honeyd - verifies ICMP, TCP, UDP, OS fingerprinting, and webserver
# ABOUTME: Uses single network namespace with loopback for isolation

set -e

# Use installed honeyd by default (has access to data files)
HONEYD_BIN="${HONEYD_BIN:-/usr/local/bin/honeyd}"
CONFIG_FILE="${CONFIG_FILE:-/src/honeyd/tests/smoke/test.conf}"

# Network configuration
HONEYD_VIRTUAL_IP="192.0.2.100"
HONEYD_HOST_IP="192.0.2.1"
TEST_NETWORK="192.0.2.0/24"
WEBSERVER_PORT="8080"

# Unique names using PID to allow parallel runs
NS_TEST="hd_test_$$"

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
    ip netns delete "$NS_TEST" 2>/dev/null || true
}

trap cleanup EXIT

# Run a test and track result
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

# Run a test expecting failure
run_test_expect_fail() {
    local name="$1"
    local cmd="$2"
    TESTS_RUN=$((TESTS_RUN + 1))

    echo -n "  $name... "
    if eval "$cmd" > /dev/null 2>&1; then
        echo "FAIL (expected failure but succeeded)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    else
        echo "PASS (correctly rejected)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi
}

# Helper to run commands in namespace
ns_exec() {
    ip netns exec "$NS_TEST" "$@"
}

echo "=== Honeyd Smoke Test ==="
echo ""

# Verify honeyd binary exists
if [ ! -x "$HONEYD_BIN" ]; then
    echo "ERROR: honeyd binary not found at $HONEYD_BIN"
    exit 1
fi
echo "[Setup] Binary exists: OK"

# Verify config syntax
if ! "$HONEYD_BIN" --verify-config -f "$CONFIG_FILE" "$TEST_NETWORK" 2>/dev/null; then
    echo "ERROR: Configuration file validation failed"
    exit 1
fi
echo "[Setup] Config valid: OK"

# Create network namespace
ip netns add "$NS_TEST"
ns_exec ip link set lo up
ns_exec ip addr add 192.0.2.1/32 dev lo
ns_exec ip route add "$TEST_NETWORK" dev lo
echo "[Setup] Network namespace created: OK"

# Start honeyd in the namespace with webserver enabled
ns_exec "$HONEYD_BIN" -d -f "$CONFIG_FILE" -i lo \
    --webserver-address="$HONEYD_HOST_IP" \
    --webserver-port="$WEBSERVER_PORT" \
    "$TEST_NETWORK" 2>&1 &
HONEYD_PID=$!
sleep 2

if ! kill -0 "$HONEYD_PID" 2>/dev/null; then
    echo "ERROR: honeyd failed to start"
    exit 1
fi
echo "[Setup] Honeyd started (PID $HONEYD_PID): OK"
echo ""

# === ICMP Tests ===
echo "[ICMP Tests]"
run_test "Ping virtual host" "ns_exec ping -c 1 -W 2 $HONEYD_VIRTUAL_IP"
echo ""

# === TCP Tests ===
echo "[TCP Tests]"
run_test "Connect to open port 22" "ns_exec nc -z -w 2 $HONEYD_VIRTUAL_IP 22"
run_test "Connect to open port 80" "ns_exec nc -z -w 2 $HONEYD_VIRTUAL_IP 80"
run_test_expect_fail "Connect to closed port 23" "ns_exec nc -z -w 2 $HONEYD_VIRTUAL_IP 23"
run_test_expect_fail "Connect to filtered port 443" "ns_exec nc -z -w 1 $HONEYD_VIRTUAL_IP 443"
echo ""


# === UDP Tests ===
echo "[UDP Tests]"
# UDP is harder to test definitively - we check that we don't get ICMP unreachable
run_test "UDP port 53 accepts packets" "ns_exec sh -c 'echo test | nc -u -w 1 $HONEYD_VIRTUAL_IP 53'"
echo ""

# === Webserver Tests ===
echo "[Webserver Tests]"
run_test "Webserver responds to HTTP GET" "ns_exec curl -s -o /dev/null -w '%{http_code}' http://$HONEYD_HOST_IP:$WEBSERVER_PORT/ | grep -q '200\\|404'"
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

# === Summary ===
echo "========================================="
echo "Tests run: $TESTS_RUN"
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
echo "========================================="

if [ $TESTS_FAILED -eq 0 ]; then
    echo "=== ALL SMOKE TESTS PASSED ==="
    exit 0
else
    echo "=== SMOKE TESTS FAILED ==="
    exit 1
fi
