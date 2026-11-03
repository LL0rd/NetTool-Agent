import contextlib
import http.client
import io
import json
from pathlib import Path
import ssl
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from nettool_agent import dhcp
from nettool_agent.__main__ import load_token, make_tls, parser
from nettool_agent.server import APIError, AgentHTTPServer, AgentService

TOKEN = "a" * 64


def fake_probe(interface, timeout):
    return {"schemaVersion": 1, "source": "nettool-agent", "capturedAt": "2026-10-31T12:00:00.000Z", "interface": interface, "offers": [], "limitations": ["Test fixture; no packets were sent."]}


class ServiceTests(unittest.TestCase):
    def test_auth_requires_exact_secret_and_bearer_scheme(self):
        service = AgentService("eth-test", TOKEN)
        self.assertTrue(service.authorized("Bearer " + TOKEN))
        self.assertTrue(service.authorized("bearer " + TOKEN))
        for header in ("", TOKEN, "Basic " + TOKEN, "Bearer wrong", "Bearer " + TOKEN + " ", "Bearer ä"):
            self.assertFalse(service.authorized(header))

    def test_auth_uses_constant_time_comparison(self):
        service = AgentService("eth-test", TOKEN)
        with patch("nettool_agent.server.hmac.compare_digest", return_value=True) as compare:
            self.assertTrue(service.authorized("Bearer " + TOKEN))
        compare.assert_called_once_with(TOKEN.encode(), TOKEN.encode())

    def test_rate_limit_and_retry_after(self):
        now = [100.0]
        probe = Mock(side_effect=fake_probe)
        service = AgentService("eth-test", TOKEN, probe=probe, clock=lambda: now[0])
        service.discover(3)
        now[0] += 1.2
        with self.assertRaises(APIError) as failure:
            service.discover(3)
        self.assertEqual(failure.exception.status, 429)
        self.assertEqual(failure.exception.retry_after, 59)
        now[0] = 160
        service.discover(3)
        self.assertEqual(probe.call_count, 2)

    def test_failed_attempt_is_rate_limited_too(self):
        service = AgentService("eth-test", TOKEN, probe=Mock(side_effect=dhcp.CapabilityError("UDP port 68 is busy.")))
        with self.assertRaises(APIError) as failure:
            service.discover(3)
        self.assertEqual(failure.exception.status, 503)
        self.assertEqual(failure.exception.code, "capability_unavailable")
        with self.assertRaises(APIError) as limited:
            service.discover(3)
        self.assertEqual(limited.exception.status, 429)

    def test_only_one_probe_runs_at_a_time(self):
        started, release = threading.Event(), threading.Event()

        def blocking(interface, timeout):
            started.set()
            release.wait(2)
            return fake_probe(interface, timeout)

        service = AgentService("eth-test", TOKEN, probe=blocking)
        thread = threading.Thread(target=service.discover, args=(3,))
        thread.start()
        try:
            self.assertTrue(started.wait(1))
            with self.assertRaises(APIError) as failure:
                service.discover(3)
            self.assertEqual(failure.exception.code, "probe_in_progress")
        finally:
            release.set()
            thread.join(2)

    @patch("nettool_agent.dhcp.check_capability")
    def test_health_never_runs_a_probe(self, capability):
        probe = Mock()
        service = AgentService("eth-test", TOKEN, probe=probe)
        result = service.health()
        self.assertEqual(result["capabilities"], ["dhcp-discover"])
        self.assertEqual(result["interface"], "eth-test")
        capability.side_effect = dhcp.CapabilityError("Interface missing.")
        self.assertEqual(service.health()["capabilities"], [])
        probe.assert_not_called()

    def test_weak_token_and_short_cooldown_rejected(self):
        for token in ("", "short", "a " * 32, "ä" * 64, "a" * 513):
            with self.assertRaises(ValueError):
                AgentService("eth-test", token)
        with self.assertRaises(ValueError):
            AgentService("eth-test", TOKEN, cooldown_seconds=1)


class HTTPTests(unittest.TestCase):
    """Loopback HTTP only; DHCP is always replaced with a fixture."""

    @classmethod
    def setUpClass(cls):
        cls.probe = Mock(side_effect=fake_probe)
        cls.service = AgentService("eth-test", TOKEN, probe=cls.probe)
        cls.server = AgentHTTPServer(("127.0.0.1", 0), cls.service)
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.01})
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(2)
        cls.server.server_close()

    def setUp(self):
        self.service._next_probe = 0
        self.probe.reset_mock(side_effect=True)
        self.probe.side_effect = fake_probe

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        try:
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), json.loads(response.read())
        finally:
            connection.close()

    def authorized_headers(self):
        return {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"}

    @patch("nettool_agent.dhcp.check_capability")
    def test_health_requires_auth_and_reports_interface(self, _capability):
        status, _, result = self.request("GET", "/v1/health", headers=self.authorized_headers())
        self.assertEqual(status, 200)
        self.assertEqual(result["capabilities"], ["dhcp-discover"])
        self.assertEqual(result["interface"], "eth-test")
        self.probe.assert_not_called()

    def test_unauthorized_calls_never_run_probe_or_log_secret(self):
        logs = io.StringIO()
        with contextlib.redirect_stderr(logs):
            for path, method in (("/v1/health", "GET"), ("/v1/dhcp/discover", "POST")):
                status, headers, result = self.request(method, path, b"{}", {"Authorization": "Bearer wrong"})
                self.assertEqual(status, 401)
                self.assertEqual(result["error"]["code"], "unauthorized")
                self.assertEqual(headers["WWW-Authenticate"], "Bearer")
        self.assertEqual(logs.getvalue(), "")
        self.probe.assert_not_called()

    def test_discovery_response_and_rate_limit(self):
        status, headers, result = self.request("POST", "/v1/dhcp/discover", b'{"timeoutSeconds":2}', self.authorized_headers())
        self.assertEqual(status, 200)
        self.assertEqual(result, fake_probe("eth-test", 2))
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.probe.assert_called_once_with("eth-test", 2)
        status, headers, result = self.request("POST", "/v1/dhcp/discover", b"{}", self.authorized_headers())
        self.assertEqual(status, 429)
        self.assertGreater(int(headers["Retry-After"]), 0)
        self.assertEqual(result["error"]["code"], "rate_limited")

    def test_body_limit_rejects_before_probe(self):
        status, _, result = self.request("POST", "/v1/dhcp/discover", b" " * 1025, self.authorized_headers())
        self.assertEqual(status, 413)
        self.assertEqual(result["error"]["code"], "body_too_large")
        self.probe.assert_not_called()

    def test_invalid_json_options_and_timeout_rejected(self):
        for raw in (b"{", b"[]", b'{"interface":"other"}', b'{"timeoutSeconds":true}', b'{"timeoutSeconds":0}', b'{"timeoutSeconds":6}', b'{"timeoutSeconds":2,"timeoutSeconds":3}'):
            with self.subTest(raw=raw):
                status, _, _ = self.request("POST", "/v1/dhcp/discover", raw, self.authorized_headers())
                self.assertEqual(status, 400)
        self.probe.assert_not_called()

    def test_content_type_and_chunking_rejected(self):
        headers = self.authorized_headers()
        headers["Content-Type"] = "text/plain"
        self.assertEqual(self.request("POST", "/v1/dhcp/discover", b"{}", headers)[0], 415)
        headers = self.authorized_headers()
        headers["Transfer-Encoding"] = "chunked"
        self.assertEqual(self.request("POST", "/v1/dhcp/discover", b"0\r\n\r\n", headers)[0], 400)
        self.probe.assert_not_called()

    def test_duplicate_authorization_rejected(self):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        try:
            connection.putrequest("GET", "/v1/health")
            connection.putheader("Authorization", "Bearer " + TOKEN)
            connection.putheader("Authorization", "Bearer " + TOKEN)
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
        finally:
            connection.close()

    def test_capability_failure_is_not_an_empty_success(self):
        self.probe.side_effect = dhcp.CapabilityError("UDP port 68 is already in use.")
        status, _, result = self.request("POST", "/v1/dhcp/discover", b"{}", self.authorized_headers())
        self.assertEqual(status, 503)
        self.assertEqual(result["error"]["code"], "capability_unavailable")
        self.assertNotIn("offers", result)

    def test_query_and_method_are_not_probe_aliases(self):
        self.assertEqual(self.request("GET", "/v1/dhcp/discover", headers=self.authorized_headers())[0], 405)
        self.assertEqual(self.request("POST", "/v1/dhcp/discover?x=1", b"{}", self.authorized_headers())[0], 404)
        self.probe.assert_not_called()


class ConfigurationTests(unittest.TestCase):
    def test_loopback_default_and_tls_required_for_lan(self):
        defaults = parser().parse_args(["--interface", "eth0"])
        self.assertEqual(defaults.bind, "127.0.0.1")
        self.assertIsNone(make_tls(defaults))
        for address in ("0.0.0.0", "192.0.2.1", "::"):
            args = parser().parse_args(["--interface", "eth0", "--bind", address])
            with self.assertRaisesRegex(ValueError, "requires"):
                make_tls(args)
            # Also enforce this at the server layer, before binding any socket.
            with self.assertRaises(ValueError):
                AgentHTTPServer((address, 8742), AgentService("eth0", TOKEN))

    def test_partial_tls_config_rejected(self):
        args = parser().parse_args(["--interface", "eth0", "--cert", "test.pem"])
        with self.assertRaisesRegex(ValueError, "both"):
            make_tls(args)

    def test_tls_has_modern_minimum_and_loads_chain(self):
        args = parser().parse_args(["--interface", "eth0", "--bind", "192.0.2.1", "--cert", "test.pem", "--key", "key.pem"])
        with patch("nettool_agent.__main__.ssl.SSLContext") as constructor:
            context = make_tls(args)
            constructor.assert_called_once_with(ssl.PROTOCOL_TLS_SERVER)
            self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
            context.load_cert_chain.assert_called_once_with(Path("test.pem"), Path("key.pem"))

    def test_token_file_or_environment_and_no_secret_in_error(self):
        with patch.dict("os.environ", {"NETTOOL_AGENT_TOKEN": TOKEN}):
            self.assertEqual(load_token(None), TOKEN)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text(TOKEN + "\n", encoding="ascii")
            self.assertEqual(load_token(path), TOKEN)
            path.write_bytes(b"\xffsecret")
            with self.assertRaisesRegex(ValueError, "ASCII") as failure:
                load_token(path)
            self.assertNotIn("secret", str(failure.exception))


if __name__ == "__main__":
    unittest.main()
