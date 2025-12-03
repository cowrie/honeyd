#!/bin/bash
# ABOUTME: Smoke test for honeyd - verifies basic ICMP echo response
# ABOUTME: Uses single network namespace with loopback for isolation

set -e

# Use installed honeyd by default (has access to data files)
HONEYD_BIN="${HONEYD_BIN:-/usr/local/bin/honeyd}"
CONFIG_FILE="${CONFIG_FILE:-/src/honeyd/tests/smoke/test.conf}"

# Network configuration
# We use a single namespace with loopback - same approach as regression tests
# This avoids ARP complexity since loopback is L3-only

HONEYD_VIRTUAL_IP="192.0.2.100"
TEST_NETWORK="192.0.2.0/24"

# Unique names using PID to allow parallel runs
NS_TEST="hd_test_$$"

cleanup() {
    echo "Cleaning up..."
    # Kill honeyd if running
    if [ -n "$HONEYD_PID" ]; then
        kill "$HONEYD_PID" 2>/dev/null || true
        wait "$HONEYD_PID" 2>/dev/null || true
    fi
    # Delete namespace
    ip netns delete "$NS_TEST" 2>/dev/null || true
}

trap cleanup EXIT

echo "=== Honeyd Smoke Test (Network Namespace Isolated) ==="

# Verify honeyd binary exists
if [ ! -x "$HONEYD_BIN" ]; then
    echo "ERROR: honeyd binary not found at $HONEYD_BIN"
    exit 1
fi
echo "1. Binary exists: OK"

# Verify config syntax
if ! "$HONEYD_BIN" --verify-config -f "$CONFIG_FILE" "$TEST_NETWORK" 2>/dev/null; then
    echo "ERROR: Configuration file validation failed"
    exit 1
fi
echo "2. Config valid: OK"

# Create network namespace
ip netns add "$NS_TEST"
echo "3. Network namespace created: OK"

# Configure namespace:
# - Bring up loopback
# - Add route to test network via loopback (packets go nowhere but honeyd captures them)
ip netns exec "$NS_TEST" ip link set lo up
ip netns exec "$NS_TEST" ip route add "$TEST_NETWORK" dev lo

echo "4. Network configured: OK"

# Start honeyd in the namespace on loopback
ip netns exec "$NS_TEST" "$HONEYD_BIN" -d -f "$CONFIG_FILE" -i lo "$TEST_NETWORK" 2>&1 &
HONEYD_PID=$!

# Give honeyd time to start and set up pcap
sleep 2

# Verify honeyd is running
if ! kill -0 "$HONEYD_PID" 2>/dev/null; then
    echo "ERROR: honeyd failed to start"
    wait "$HONEYD_PID" 2>/dev/null || true
    exit 1
fi
echo "5. Honeyd started (PID $HONEYD_PID): OK"

# Run the actual test: ping from same namespace to honeyd's virtual IP
echo "6. Testing ping to $HONEYD_VIRTUAL_IP..."

if ip netns exec "$NS_TEST" ping -c 3 -W 2 "$HONEYD_VIRTUAL_IP"; then
    PING_RESULT=0
else
    PING_RESULT=$?
fi

echo ""
if [ $PING_RESULT -eq 0 ]; then
    echo "=== SMOKE TEST PASSED ==="
    exit 0
else
    echo "=== SMOKE TEST FAILED ==="
    echo "Ping to virtual host $HONEYD_VIRTUAL_IP failed (exit code: $PING_RESULT)"
    exit 1
fi
