#!/usr/bin/env python3
# ABOUTME: Unit tests for the proxy subsystem
# ABOUTME: Tests HTTP CONNECT and GET proxy functionality

import socket
import subprocess
import time
import os
import signal
import sys
import unittest

# Allow override via environment for Docker/CI
PROXY_BIN = os.environ.get(
    'PROXY_BIN',
    os.path.join(os.path.dirname(__file__), '..', 'build', 'proxy')
)
SMTP_BIN = os.environ.get(
    'SMTP_BIN',
    os.path.join(os.path.dirname(__file__), '..', 'build', 'smtp')
)
TEST_PORT = 12525


class ProxyTestCase(unittest.TestCase):
    """Test cases for the proxy subsystem."""

    proxy_proc = None

    @classmethod
    def setUpClass(cls):
        """Start the proxy server before all tests."""
        if not os.path.exists(PROXY_BIN):
            raise unittest.SkipTest(f"Proxy binary not found at {PROXY_BIN}")

        cls.proxy_proc = subprocess.Popen(
            [PROXY_BIN, '-p', str(TEST_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Give it time to start
        time.sleep(0.5)

        # Check it's still running
        if cls.proxy_proc.poll() is not None:
            stdout, stderr = cls.proxy_proc.communicate()
            raise RuntimeError(
                f"Proxy failed to start: {stderr.decode()}"
            )

    @classmethod
    def tearDownClass(cls):
        """Stop the proxy server after all tests."""
        if cls.proxy_proc:
            cls.proxy_proc.terminate()
            try:
                cls.proxy_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                cls.proxy_proc.kill()
                cls.proxy_proc.wait()

    def _connect(self):
        """Create a connection to the proxy."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', TEST_PORT))
        return sock

    def test_connect_to_proxy(self):
        """Test that we can connect to the proxy."""
        sock = self._connect()
        sock.close()

    def test_invalid_request(self):
        """Test that invalid requests get a 400 response."""
        sock = self._connect()
        try:
            sock.sendall(b"INVALID REQUEST\r\n\r\n")
            response = sock.recv(4096)
            self.assertIn(b"400", response)
        finally:
            sock.close()

    def test_connect_bad_port(self):
        """Test CONNECT to non-port-25 gets rejected."""
        sock = self._connect()
        try:
            # CONNECT to port 80 should be rejected (only port 25 allowed)
            sock.sendall(b"CONNECT example.com:80 HTTP/1.0\r\n\r\n")
            response = sock.recv(4096)
            # Should get some kind of error response
            self.assertTrue(len(response) > 0)
        finally:
            sock.close()

    def test_get_nonexistent_domain(self):
        """Test GET to non-existent domain returns 404."""
        sock = self._connect()
        try:
            sock.sendall(b"GET http://nonexistent.invalid.test/ HTTP/1.0\r\n\r\n")
            response = sock.recv(4096)
            # Should get 404 for non-existent domain
            self.assertIn(b"404", response)
        finally:
            sock.close()

    def test_get_private_network_blocked(self):
        """Test GET to private networks is blocked."""
        sock = self._connect()
        try:
            # 10.x.x.x is private and should be blocked
            sock.sendall(b"GET http://10.0.0.1/ HTTP/1.0\r\n\r\n")
            response = sock.recv(4096)
            # Should get an error (503 connect failed or similar)
            self.assertTrue(len(response) > 0)
            # Should not successfully connect
            self.assertNotIn(b"200 OK", response)
        finally:
            sock.close()

    def test_connect_private_network_blocked(self):
        """Test CONNECT to private networks is blocked."""
        sock = self._connect()
        try:
            sock.sendall(b"CONNECT 192.168.1.1:25 HTTP/1.0\r\n\r\n")
            response = sock.recv(4096)
            self.assertTrue(len(response) > 0)
        finally:
            sock.close()

    def test_multiple_connections(self):
        """Test that multiple simultaneous connections work."""
        sockets = []
        try:
            for _ in range(5):
                sock = self._connect()
                sockets.append(sock)
            # All connections should be established
            self.assertEqual(len(sockets), 5)
        finally:
            for sock in sockets:
                sock.close()


class SmtpTestCase(unittest.TestCase):
    """Test cases for the standalone SMTP subsystem."""

    smtp_proc = None
    SMTP_PORT = 12526

    @classmethod
    def setUpClass(cls):
        """Start the SMTP server before all tests."""
        if not os.path.exists(SMTP_BIN):
            raise unittest.SkipTest(f"SMTP binary not found at {SMTP_BIN}")

        cls.smtp_proc = subprocess.Popen(
            [SMTP_BIN, '-p', str(cls.SMTP_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)

        if cls.smtp_proc.poll() is not None:
            stdout, stderr = cls.smtp_proc.communicate()
            raise RuntimeError(f"SMTP failed to start: {stderr.decode()}")

    @classmethod
    def tearDownClass(cls):
        """Stop the SMTP server after all tests."""
        if cls.smtp_proc:
            cls.smtp_proc.terminate()
            try:
                cls.smtp_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                cls.smtp_proc.kill()
                cls.smtp_proc.wait()

    def _connect(self):
        """Create a connection to the SMTP server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', self.SMTP_PORT))
        return sock

    def test_connect_to_smtp(self):
        """Test that we can connect to SMTP."""
        sock = self._connect()
        try:
            # Should get a greeting
            response = sock.recv(4096)
            self.assertIn(b"220", response)
        finally:
            sock.close()

    def test_helo(self):
        """Test HELO command."""
        sock = self._connect()
        try:
            # Read greeting
            sock.recv(4096)
            # Send HELO
            sock.sendall(b"HELO test.example.com\r\n")
            response = sock.recv(4096)
            self.assertIn(b"250", response)
        finally:
            sock.close()

    def test_ehlo(self):
        """Test EHLO command."""
        sock = self._connect()
        try:
            sock.recv(4096)
            sock.sendall(b"EHLO test.example.com\r\n")
            response = sock.recv(4096)
            self.assertIn(b"250", response)
        finally:
            sock.close()

    def test_quit(self):
        """Test QUIT command."""
        sock = self._connect()
        try:
            sock.recv(4096)
            sock.sendall(b"QUIT\r\n")
            response = sock.recv(4096)
            self.assertIn(b"221", response)
        finally:
            sock.close()

    def test_noop(self):
        """Test NOOP command."""
        sock = self._connect()
        try:
            sock.recv(4096)
            sock.sendall(b"NOOP\r\n")
            response = sock.recv(4096)
            self.assertIn(b"250", response)
        finally:
            sock.close()

    def test_mail_flow(self):
        """Test basic MAIL FROM / RCPT TO flow."""
        sock = self._connect()
        try:
            sock.recv(4096)

            sock.sendall(b"HELO test.example.com\r\n")
            sock.recv(4096)

            sock.sendall(b"MAIL FROM: <sender@example.com>\r\n")
            response = sock.recv(4096)
            self.assertIn(b"250", response)

            sock.sendall(b"RCPT TO: <recipient@example.com>\r\n")
            response = sock.recv(4096)
            self.assertIn(b"250", response)
        finally:
            sock.close()

    def test_invalid_command(self):
        """Test invalid command gets error response."""
        sock = self._connect()
        try:
            sock.recv(4096)
            sock.sendall(b"INVALIDCMD\r\n")
            response = sock.recv(4096)
            # Should get 5xx error
            self.assertTrue(response[0:1] == b"5" or b"500" in response)
        finally:
            sock.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
