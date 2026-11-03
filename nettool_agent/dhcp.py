"""Bounded DHCPDISCOVER / DHCPOFFER exchange; never requests an offered lease."""

from __future__ import annotations

import errno
import ipaddress
import re
import secrets
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from typing import Callable

COOKIE = b"\x63\x82\x53\x63"
CLIENT_MAC = bytes.fromhex("024e54000001")
CLIENT_MAC_TEXT = ":".join(f"{byte:02x}" for byte in CLIENT_MAC)
MAX_PACKET_SIZE = 4096
MAX_RECEIVED_PACKETS = 128
MAX_OFFERS = 16
LIMITATIONS = (
    "One DHCPDISCOVER from the selected agent interface; only matching DHCPOFFER replies are recorded.",
    "No DHCPREQUEST is sent, no lease is acquired, and the iPhone's lease is not measured.",
    "No observed offer does not prove that no DHCP server exists; VLANs, relays, filtering and timing limit visibility.",
    "A fixed synthetic DHCP identity is used; servers may temporarily reserve an offered address.",
    "This probe records DHCPv4 offers only; separate agent checks provide scheduled observations and passive IPv6 evidence.",
)


class CapabilityError(Exception):
    """The host cannot perform this probe; never a synthetic zero-result scan."""


class PacketError(ValueError):
    """A packet is unrelated or cannot be safely decoded as this probe's offer."""


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def validate_interface(interface: str) -> None:
    # Linux IFNAMSIZ includes the terminating NUL. No arbitrary ioctl/device strings.
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
        raise ValueError("Interface must be an explicit Linux interface name (1–15 ASCII characters).")
    if interface == "lo":
        raise ValueError("Choose a LAN interface, not loopback.")


def check_capability(interface: str) -> None:
    validate_interface(interface)
    if not sys.platform.startswith("linux") or not hasattr(socket, "SO_BINDTODEVICE"):
        raise CapabilityError("DHCP discovery requires Linux with SO_BINDTODEVICE support.")
    try:
        socket.if_nametoindex(interface)
    except OSError as exc:
        raise CapabilityError("The configured Linux interface is not available.") from exc


def build_discover(xid: int) -> bytes:
    header = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1, 1, 6, 0, xid, 0, 0x8000,
        bytes(4), bytes(4), bytes(4), bytes(4),
        CLIENT_MAC.ljust(16, b"\0"), bytes(64), bytes(128),
    )
    requested = bytes([1, 3, 6, 15, 28, 51, 54, 58, 59, 119, 121])
    options = (
        b"\x35\x01\x01"  # DHCP message type: DISCOVER, never REQUEST.
        + b"\x3d\x07\x01" + CLIENT_MAC
        + bytes([55, len(requested)]) + requested
    )
    name = b"nettool-probe"
    options += bytes([12, len(name)]) + name + b"\x39\x02\x05\xdc\xff"
    return (header + COOKIE + options).ljust(300, b"\0")


def _read_options(data: bytes, options: dict[int, bytes]) -> None:
    cursor = 0
    while cursor < len(data):
        code = data[cursor]
        cursor += 1
        if code == 0:
            continue
        if code == 255:
            return
        if cursor >= len(data):
            raise PacketError("Missing DHCP option length.")
        size = data[cursor]
        cursor += 1
        if cursor + size > len(data):
            raise PacketError("Truncated DHCP option.")
        # Repeated option fragments are concatenated in wire order (RFC 3396).
        options[code] = options.get(code, b"") + data[cursor:cursor + size]
        cursor += size
    raise PacketError("Missing DHCP end option.")


def _addresses(value: bytes, single: bool = False) -> str:
    if not value or len(value) % 4 or (single and len(value) != 4):
        raise PacketError("Invalid IPv4 option length.")
    return ", ".join(str(ipaddress.IPv4Address(value[pos:pos + 4])) for pos in range(0, len(value), 4))


def _seconds(value: bytes) -> int:
    if len(value) != 4:
        raise PacketError("Invalid DHCP time option length.")
    return int.from_bytes(value, "big")


def _decode_option(code: int, value: bytes) -> str:
    if code in (1, 28, 50, 54):
        return _addresses(value, single=True)
    if code in (3, 6, 42):
        return _addresses(value)
    if code in (51, 58, 59):
        return str(_seconds(value))
    if code in (12, 15, 60):
        return "".join(chr(byte) if 32 <= byte <= 126 else f"\\x{byte:02x}" for byte in value)
    if code == 53:
        if value != b"\x02":
            raise PacketError("Not a DHCPOFFER.")
        return "DHCPOFFER"
    if code == 52:
        if len(value) != 1 or value[0] not in (1, 2, 3):
            raise PacketError("Invalid option overload.")
        return str(value[0])
    # Preserve unimplemented / vendor-specific encodings faithfully, including 119/121.
    return "0x" + value.hex()


def parse_offer(packet: bytes, xid: int, response_ms: float) -> dict:
    if len(packet) < 240 or len(packet) > MAX_PACKET_SIZE:
        raise PacketError("Invalid BOOTP packet length.")
    if packet[:3] != b"\x02\x01\x06":
        raise PacketError("Not an Ethernet BOOTREPLY.")
    if struct.unpack_from("!I", packet, 4)[0] != xid:
        raise PacketError("Different DHCP transaction.")
    if packet[28:34] != CLIENT_MAC or packet[236:240] != COOKIE:
        raise PacketError("Different client or invalid DHCP cookie.")
    options: dict[int, bytes] = {}
    _read_options(packet[240:], options)
    overload = options.get(52, b"\0")
    if len(overload) != 1 or overload[0] not in (0, 1, 2, 3):
        raise PacketError("Invalid option overload.")
    if overload[0] & 1:
        _read_options(packet[108:236], options)
    if overload[0] & 2:
        _read_options(packet[44:108], options)
    if options.get(53) != b"\x02" or 54 not in options:
        raise PacketError("Offer lacks message type or server identifier.")
    offered = ipaddress.IPv4Address(packet[16:20])
    server = ipaddress.IPv4Address(options[54]) if len(options[54]) == 4 else None
    if offered.is_unspecified or offered.is_multicast or int(offered) == 0xffffffff:
        raise PacketError("Offer has no valid offered address.")
    if server is None or server.is_unspecified or server.is_multicast or int(server) == 0xffffffff:
        raise PacketError("Offer has no valid server identifier.")
    decoded = {str(code): _decode_option(code, value) for code, value in sorted(options.items())}
    result = {
        "serverIdentifier": str(server),
        "offeredAddress": str(offered),
        "clientMAC": CLIENT_MAC_TEXT,
        "responseMS": round(response_ms, 3),
        "options": decoded,
    }
    if 51 in options:
        result["leaseSeconds"] = _seconds(options[51])
    return result


def _socket_error(exc: OSError) -> CapabilityError:
    if exc.errno == errno.EADDRINUSE:
        return CapabilityError("UDP client port 68 is already in use. The agent will not share or replace the host DHCP client.")
    if exc.errno in (errno.EACCES, errno.EPERM):
        return CapabilityError("Insufficient permission for interface binding or UDP port 68; check Linux NET_RAW and NET_BIND_SERVICE capabilities.")
    if exc.errno in (errno.ENODEV, errno.ENETDOWN, errno.ENETUNREACH, errno.EADDRNOTAVAIL):
        return CapabilityError("The configured interface cannot send or receive this IPv4 broadcast; check link and IPv4 configuration.")
    return CapabilityError("The host could not complete the DHCP socket operation.")


def discover(
    interface: str,
    timeout_seconds: int = 3,
    *,
    socket_factory: Callable = socket.socket,
    clock: Callable[[], float] = time.monotonic,
) -> dict:
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 5:
        raise ValueError("timeoutSeconds must be an integer from 1 through 5.")
    check_capability(interface)
    captured_at = timestamp()
    xid = secrets.randbits(32)
    offers = []
    seen = set()
    limitations = list(LIMITATIONS)
    try:
        with socket_factory(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as connection:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode("ascii") + b"\0")
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # Deliberately no SO_REUSEADDR/SO_REUSEPORT: respect an existing DHCP client.
            connection.bind(("0.0.0.0", 68))
            connection.settimeout(timeout_seconds)
            started = clock()
            connection.sendto(build_discover(xid), ("255.255.255.255", 67))
            deadline = started + timeout_seconds
            for _ in range(MAX_RECEIVED_PACKETS):
                remaining = deadline - clock()
                if remaining <= 0:
                    break
                connection.settimeout(remaining)
                try:
                    packet, sender = connection.recvfrom(MAX_PACKET_SIZE + 1)
                except socket.timeout:
                    break
                if sender[1] != 67:
                    continue
                try:
                    offer = parse_offer(packet, xid, (clock() - started) * 1000)
                except PacketError:
                    continue
                identity = (offer["serverIdentifier"], offer["offeredAddress"], tuple(offer["options"].items()))
                if identity not in seen:
                    offers.append(offer)
                    seen.add(identity)
                if len(offers) == MAX_OFFERS:
                    limitations.append("The limit of 16 distinct offers was reached; further replies were not collected.")
                    break
            else:
                limitations.append("The receive budget of 128 packets was reached; collection ended early.")
    except OSError as exc:
        raise _socket_error(exc) from exc
    return {
        "schemaVersion": 1,
        "source": "nettool-agent",
        "capturedAt": captured_at,
        "interface": interface,
        "offers": offers,
        "limitations": limitations,
    }
