"""Authenticated, bounded local HTTP API for the optional LAN agent."""

from __future__ import annotations

import hmac
import ipaddress
import json
import math
import socket
import ssl
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import urlsplit, parse_qs

from . import dhcp

MAX_BODY_BYTES = 1024
REQUEST_TIMEOUT_SECONDS = 5


class APIError(Exception):
    def __init__(self, status: int, code: str, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.retry_after = retry_after


class AgentService:
    def __init__(
        self,
        interface: str,
        token: str,
        *,
        cooldown_seconds: int = 60,
        probe: Callable = dhcp.discover,
        clock: Callable[[], float] = time.monotonic,
        engine=None,
    ):
        dhcp.validate_interface(interface)
        if not 32 <= len(token) <= 512 or not token.isascii() or not all(33 <= ord(c) <= 126 for c in token):
            raise ValueError("Bearer token must contain 32–512 printable ASCII characters without spaces.")
        if type(cooldown_seconds) is not int or cooldown_seconds < 30:
            raise ValueError("The discovery cooldown must be at least 30 seconds.")
        self.engine = engine
        self.interface = interface
        self._token = token.encode("ascii")
        self.cooldown_seconds = cooldown_seconds
        self._probe = probe
        self._clock = clock
        self._lock = threading.Lock()
        self._next_probe = 0.0

    def authorized(self, authorization: str) -> bool:
        scheme, separator, credential = authorization.partition(" ")
        # compare_digest compares the secret even when the scheme is incorrect.
        matches = hmac.compare_digest(credential.encode("utf-8"), self._token)
        return bool(matches and separator and scheme.lower() == "bearer")

    def health(self) -> dict:
        limitations = [
            "Health checks interface presence only; port 68 permissions, availability and broadcast delivery are checked during a requested probe.",
            *dhcp.LIMITATIONS,
        ]
        capabilities = ["dhcp-discover"]
        try:
            dhcp.check_capability(self.interface)
        except dhcp.CapabilityError as exc:
            capabilities = []
            limitations.insert(0, str(exc))
        return {
            "schemaVersion": 1,
            "source": "nettool-agent",
            "capturedAt": dhcp.timestamp(),
            "interface": self.interface,
            "capabilities": capabilities + (["schedules", "history", "tcp", "http", "dns", "ping", "iperf", "ssdp", "wol", "ipv6-observe", "openwrt", "dhcp"] if self.engine else []),
            "limitations": limitations,
        }

    def discover(self, timeout_seconds: int) -> dict:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 5:
            raise APIError(400, "invalid_request", "timeoutSeconds must be an integer from 1 through 5.")
        if not self._lock.acquire(blocking=False):
            raise APIError(409, "probe_in_progress", "One DHCP probe is already running.")
        try:
            now = self._clock()
            if now < self._next_probe:
                raise APIError(429, "rate_limited", "Wait before starting another DHCP probe.", math.ceil(self._next_probe - now))
            # Count failed attempts as well; errors must not enable a tight retry loop.
            self._next_probe = now + self.cooldown_seconds
            try:
                if self.engine:
                    try:return self.engine.run_dhcp_probe(lambda:self._probe(self.interface,timeout_seconds),self.cooldown_seconds)
                    except RuntimeError as exc:raise APIError(429,'rate_limited',str(exc),60) from exc
                return self._probe(self.interface, timeout_seconds)
            except dhcp.CapabilityError as exc:
                raise APIError(503, "capability_unavailable", str(exc)) from exc
        finally:
            self._lock.release()


class AgentHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 8
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], service: AgentService, tls_context: ssl.SSLContext | None = None):
        address_ip = ipaddress.ip_address(address[0])
        if not address_ip.is_loopback and tls_context is None:
            raise ValueError("Binding beyond loopback requires --cert and --key for HTTPS.")
        self.address_family = socket.AF_INET6 if address_ip.version == 6 else socket.AF_INET
        self.service = service
        self.tls_context = tls_context
        self._connections = threading.BoundedSemaphore(8)
        super().__init__(address, AgentHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(REQUEST_TIMEOUT_SECONDS)
        if self.tls_context is not None:
            try:
                connection = self.tls_context.wrap_socket(connection, server_side=True)
            except (OSError, ssl.SSLError):
                connection.close()
                raise
        return connection, address

    def process_request(self, request, client_address):
        if not self._connections.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connections.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connections.release()

    def handle_error(self, request, client_address):
        # No raw request, header or secret is written to console logs.
        pass


class AgentHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NetToolAgent"
    sys_version = ""

    def log_message(self, format, *args):
        pass

    def _send_json(self, status: int, value: dict, headers: dict | None = None) -> None:
        payload = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _send_failure(self, error: APIError) -> None:
        headers = {}
        if error.status == 401:
            headers["WWW-Authenticate"] = "Bearer"
        if error.retry_after is not None:
            headers["Retry-After"] = str(error.retry_after)
        self._send_json(error.status, {
            "schemaVersion": 1,
            "source": "nettool-agent",
            "error": {"code": error.code, "message": error.message},
        }, headers)

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler otherwise generates HTML and echoes request fragments.
        self._send_failure(APIError(code, "invalid_request", HTTPStatus(code).phrase))

    def handle_expect_100(self):
        self._send_failure(APIError(417, "expectation_failed", "Expect: 100-continue is not supported."))
        return False

    def _authenticate(self) -> None:
        values = self.headers.get_all("Authorization", [])
        if len(values) != 1 or not self.server.service.authorized(values[0]):
            raise APIError(401, "unauthorized", "A valid Bearer token is required.")

    def _body(self, allowed=None, maximum=MAX_BODY_BYTES) -> dict:
        if self.headers.get_all("Transfer-Encoding"):
            raise APIError(400, "invalid_request", "Transfer-Encoding is not supported.")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1:
            raise APIError(411, "length_required", "Provide one Content-Length header.")
        if not lengths[0].isascii() or not lengths[0].isdigit():
            raise APIError(400, "invalid_request", "Invalid Content-Length.")
        # Check the character count before int conversion to bound arbitrarily large input.
        if len(lengths[0]) > 6 or int(lengths[0]) > maximum:
            raise APIError(413, "body_too_large", f"The JSON body limit is {maximum} bytes.")
        length = int(lengths[0])
        content_types = self.headers.get_all("Content-Type", [])
        if len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json":
            raise APIError(415, "unsupported_media_type", "Use Content-Type: application/json.")
        try:
            deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
            raw = bytearray()
            while len(raw) < length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                self.connection.settimeout(remaining)
                chunk = self.rfile.read1(length - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
        except (TimeoutError, OSError) as exc:
            raise APIError(408, "request_timeout", "The request body did not arrive in time.") from exc
        if len(raw) != length:
            raise APIError(400, "invalid_request", "The request body was incomplete.")
        try:
            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("Duplicate JSON key.")
                    result[key] = value
                return result
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise APIError(400, "invalid_json", "Provide a JSON object.") from exc
        if allowed is not None:
            if not isinstance(value, dict) or set(value) - allowed:
                raise APIError(400, "invalid_request", "Unexpected request fields.")
            return value
        if not isinstance(value, dict) or set(value) - {"timeoutSeconds"}:
            raise APIError(400, "invalid_request", "Only timeoutSeconds is accepted; the interface is configured on the agent.")
        timeout = value.get("timeoutSeconds", 3)
        if type(timeout) is not int or not 1 <= timeout <= 5:
            raise APIError(400, "invalid_request", "timeoutSeconds must be an integer from 1 through 5.")
        return value

    def _dispatch(self) -> None:
        try:
            self._authenticate()
            if self.command == "GET" and self.path == "/v1/health":
                self._send_json(200, self.server.service.health())
            elif self.command == "POST" and self.path == "/v1/dhcp/discover":
                body = self._body()
                self._send_json(200, self.server.service.discover(body.get("timeoutSeconds", 3)))
            elif self.server.service.engine and self.path.split("?",1)[0] in ("/v1/status", "/v1/checks", "/v1/checks/run", "/v1/history"):
                self._engine_dispatch()
            elif self.path in ("/v1/health", "/v1/dhcp/discover"):
                raise APIError(405, "method_not_allowed", "Use GET for health and POST for discovery.")
            else:
                raise APIError(404, "not_found", "Unknown API endpoint.")
        except APIError as exc:
            self._send_failure(exc)
        except (ConnectionError, TimeoutError):
            self.close_connection = True
        except Exception:
            self._send_failure(APIError(500, "internal_error", "The agent could not complete the request."))

    def _engine_dispatch(self):
        engine = self.server.service.engine
        parsed = urlsplit(self.path)
        try:
            if self.command == "GET" and parsed.path in ("/v1/status", "/v1/checks") and not parsed.query:
                result = engine.status()
            elif self.command == "GET" and parsed.path == "/v1/history":
                query = parse_qs(parsed.query, strict_parsing=True)
                if set(query)-{"limit","after"} or any(len(v)!=1 for v in query.values()):
                    raise ValueError("Use limit and optional after sequence only.")
                result = engine.history(int(query.get("limit",["100"])[0]), int(query["after"][0]) if "after" in query else None)
            elif self.command == "POST" and self.path == "/v1/checks":
                body = self._body({"checks","expectedChecks"},131072)
                result = engine.set_checks(body.get("checks"),body.get("expectedChecks"))
            elif self.command == "POST" and self.path == "/v1/checks/run":
                body = self._body({"id"})
                result = engine.run(body.get("id"))
            elif self.command == "DELETE" and self.path == "/v1/history":
                result = engine.delete_history()
            else:
                raise APIError(405,"method_not_allowed","Unsupported method for this endpoint.")
            self._send_json(200,result)
        except ValueError as exc:
            raise APIError(400,"invalid_request",str(exc)) from exc
        except RuntimeError as exc:
            raise APIError(409,"busy",str(exc)) from exc

    do_GET = _dispatch
    do_POST = _dispatch
    do_HEAD = _dispatch
    do_PUT = _dispatch
    do_PATCH = _dispatch
    do_DELETE = _dispatch
    do_OPTIONS = _dispatch
