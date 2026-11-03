"""Run with python3 -m nettool_agent --interface enp3s0 --token-file ..."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import ssl
import sys

from . import dhcp
from .server import AgentHTTPServer, AgentService
from .engine import Engine
from .monitor import Relay


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description="Customer-operated NetTool LAN diagnostics and local monitoring agent.")
    cli.add_argument("--interface", required=True, help="Explicit Linux LAN interface; never auto-selected")
    cli.add_argument("--bind", default="127.0.0.1", help="Literal listen IP (default: 127.0.0.1); LAN binding requires TLS")
    cli.add_argument("--port", type=int, default=8742)
    cli.add_argument("--token-file", type=Path, help="File containing a random token; otherwise NETTOOL_AGENT_TOKEN is required")
    cli.add_argument("--cert", type=Path, help="PEM TLS certificate chain trusted by the client")
    cli.add_argument("--key", type=Path, help="PEM TLS private key")
    cli.add_argument("--cooldown", type=int, default=60, help="Seconds between discovery starts, minimum 30 (default: 60)")
    cli.add_argument("--config", type=Path, help="Protected JSON configuration for checks, read-only routers and optional Monitor")
    cli.add_argument("--data-dir", type=Path, default=Path("./nettool-data"), help="Persistent local history and schedule directory")
    return cli


def load_token(path: Path | None) -> str:
    if path is None:
        token = os.environ.get("NETTOOL_AGENT_TOKEN", "")
        if not token:
            raise ValueError("Set NETTOOL_AGENT_TOKEN or supply --token-file.")
        return token
    try:
        # Bound reads even if accidentally pointed at a large file.
        with path.open("rb") as stream:
            raw = stream.read(514)
    except OSError as exc:
        raise ValueError("Unable to read the configured token file.") from exc
    try:
        token = raw.decode("ascii").rstrip("\r\n")
    except UnicodeError as exc:
        raise ValueError("The token file must contain an ASCII token.") from exc
    if len(raw) == 514 or not token:
        raise ValueError("The token file is empty or too large.")
    return token


def make_tls(args: argparse.Namespace) -> ssl.SSLContext | None:
    address = ipaddress.ip_address(args.bind)
    if bool(args.cert) != bool(args.key):
        raise ValueError("Supply both --cert and --key.")
    if not address.is_loopback and not args.cert:
        raise ValueError("Binding beyond loopback requires --cert and --key for HTTPS.")
    if not args.cert:
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(args.cert, args.key)
    except (OSError, ssl.SSLError) as exc:
        raise ValueError("Unable to load the TLS certificate and private key.") from exc
    return context


def main(argv: list[str] | None = None) -> int:
    cli = parser()
    args = cli.parse_args(argv)
    try:
        dhcp.check_capability(args.interface)
        if not 1 <= args.port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        config = {}
        if args.config:
            if args.config.stat().st_size > 65536: raise ValueError("Config exceeds 64 KiB.")
            config = json.loads(args.config.read_text())
            if not isinstance(config,dict): raise ValueError("Config must be an object.")
        engine = Engine(args.data_dir, args.interface, config)
        service = AgentService(args.interface, load_token(args.token_file), cooldown_seconds=args.cooldown, engine=engine)
        context = make_tls(args)
        server = AgentHTTPServer((args.bind, args.port), service, context)
    except (ValueError, dhcp.CapabilityError, OSError) as exc:
        # Messages from our validation contain no secrets. Do not dump a traceback.
        cli.error(str(exc))
        return 2
    protocol = "https" if context else "http"
    print(f"NetTool agent listening on {protocol}://{args.bind}:{args.port}; interface {args.interface}. Only explicitly enabled schedules run automatically.", flush=True)
    engine.start()
    relay = Relay(engine)
    relay.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        relay.close()
        engine.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
