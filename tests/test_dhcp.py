import errno
import random
import socket
import struct
import unittest
from unittest.mock import Mock, patch

from nettool_agent import dhcp

XID = 0x12345678


def option(code, value):
    return bytes([code, len(value)]) + value


def offer_packet(extra=b"", *, message_type=2, server=b"\xc0\xa8\x01\x01", lease=True):
    packet = bytearray(dhcp.build_discover(XID)[:240])
    packet[0] = 2
    packet[16:20] = b"\xc0\xa8\x01\x64"
    packet += option(53, bytes([message_type]))
    if server is not None:
        packet += option(54, server)
    if lease:
        packet += option(51, struct.pack("!I", 3600))
    packet += extra + b"\xff"
    return bytes(packet)


class PacketTests(unittest.TestCase):
    def test_discover_is_one_synthetic_broadcast_client(self):
        packet = dhcp.build_discover(XID)
        self.assertEqual(len(packet), 300)
        self.assertEqual(packet[:3], b"\x01\x01\x06")
        self.assertEqual(struct.unpack_from("!I", packet, 4)[0], XID)
        self.assertEqual(struct.unpack_from("!H", packet, 10)[0], 0x8000)
        self.assertEqual(packet[28:34], dhcp.CLIENT_MAC)
        self.assertTrue(dhcp.CLIENT_MAC[0] & 2)
        self.assertFalse(dhcp.CLIENT_MAC[0] & 1)
        options = {}
        dhcp._read_options(packet[240:], options)
        self.assertEqual(options[53], b"\x01")
        self.assertEqual(options[61], b"\x01" + dhcp.CLIENT_MAC)
        self.assertNotIn(50, options)
        self.assertNotIn(54, options)

    def test_real_offer_fields_and_options(self):
        packet = offer_packet(
            option(1, b"\xff\xff\xff\x00")
            + option(3, b"\xc0\xa8\x01\x01")
            + option(6, bytes([1, 1, 1, 1, 8, 8, 8, 8]))
            + option(15, b"example.test")
            + option(58, struct.pack("!I", 1800))
            + option(224, b"\x01\x02")
        )
        result = dhcp.parse_offer(packet, XID, 12.34567)
        self.assertEqual(result["serverIdentifier"], "192.168.1.1")
        self.assertEqual(result["offeredAddress"], "192.168.1.100")
        self.assertEqual(result["clientMAC"], "02:4e:54:00:00:01")
        self.assertEqual(result["leaseSeconds"], 3600)
        self.assertEqual(result["responseMS"], 12.346)
        self.assertEqual(result["options"]["6"], "1.1.1.1, 8.8.8.8")
        self.assertEqual(result["options"]["224"], "0x0102")
        self.assertEqual(result["options"]["58"], "1800")

    def test_absent_lease_is_not_invented(self):
        result = dhcp.parse_offer(offer_packet(lease=False), XID, 1)
        self.assertNotIn("leaseSeconds", result)

    def test_infinite_lease_keeps_rfc_value(self):
        packet = offer_packet(option(51, b"\xff" * 4), lease=False)
        self.assertEqual(dhcp.parse_offer(packet, XID, 1)["leaseSeconds"], 4294967295)

    def test_wrong_identity_header_and_cookie_rejected(self):
        for offset in (0, 1, 2, 4, 28, 236):
            with self.subTest(offset=offset):
                packet = bytearray(offer_packet())
                packet[offset] ^= 1
                with self.assertRaises(dhcp.PacketError):
                    dhcp.parse_offer(bytes(packet), XID, 1)

    def test_non_offer_or_missing_server_rejected(self):
        for packet in (offer_packet(message_type=5), offer_packet(server=None), offer_packet(server=b"\x01")):
            with self.subTest(packet=packet[-20:]):
                with self.assertRaises(dhcp.PacketError):
                    dhcp.parse_offer(packet, XID, 1)

    def test_unspecified_offered_address_rejected(self):
        packet = bytearray(offer_packet())
        packet[16:20] = bytes(4)
        with self.assertRaises(dhcp.PacketError):
            dhcp.parse_offer(bytes(packet), XID, 1)

    def test_malformed_tlv_and_fixed_length_options_rejected(self):
        packets = [offer_packet()[:-1], offer_packet()[:-1] + b"\x06", offer_packet()[:-1] + b"\x06\x08\x01\xff"]
        packets += [offer_packet(option(code, b"\x01")) for code in (1, 3, 6, 58)]
        packets += [offer_packet(option(51, b"\x01"), lease=False), offer_packet(option(52, b"\x04"))]
        for packet in packets:
            with self.subTest(packet=packet[-20:]):
                with self.assertRaises(dhcp.PacketError):
                    dhcp.parse_offer(packet, XID, 1)

    def test_duplicate_scalar_message_type_rejected(self):
        with self.assertRaises(dhcp.PacketError):
            dhcp.parse_offer(offer_packet(option(53, b"\x02")), XID, 1)

    def test_option_overload_and_fragment_order(self):
        packet = bytearray(offer_packet(option(52, b"\x03") + option(15, b"start.")))
        packet[108:236] = (option(15, b"file.") + b"\xff").ljust(128, b"\0")
        packet[44:108] = (option(15, b"sname") + b"\xff").ljust(64, b"\0")
        self.assertEqual(dhcp.parse_offer(bytes(packet), XID, 1)["options"]["15"], "start.file.sname")

    def test_control_bytes_in_text_are_escaped(self):
        packet = offer_packet(option(15, b"a\n\x00\xff"))
        self.assertEqual(dhcp.parse_offer(packet, XID, 1)["options"]["15"], "a\\x0a\\x00\\xff")

    def test_truncated_packets_never_raise_unexpected_errors(self):
        packet = offer_packet(option(15, b"example.test"))
        for size in range(len(packet)):
            with self.assertRaises(dhcp.PacketError):
                dhcp.parse_offer(packet[:size], XID, 1)
        with self.assertRaises(dhcp.PacketError):
            dhcp.parse_offer(packet.ljust(dhcp.MAX_PACKET_SIZE + 1, b"\0"), XID, 1)

    def test_malformed_option_fuzz_is_bounded(self):
        rng = random.Random(42)
        header = offer_packet()[:240]
        for _ in range(300):
            packet = header + rng.randbytes(rng.randrange(0, 500))
            try:
                dhcp.parse_offer(packet, XID, 1)
            except dhcp.PacketError:
                pass


class ProbeTests(unittest.TestCase):
    def setUp(self):
        # Parser / fake-socket tests also run on a macOS development host.
        binding = patch.object(socket, "SO_BINDTODEVICE", 25, create=True)
        binding.start()
        self.addCleanup(binding.stop)

    def connection(self):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        return connection

    @patch("nettool_agent.dhcp.check_capability")
    @patch("nettool_agent.dhcp.secrets.randbits", return_value=XID)
    def test_one_send_matching_replies_only_and_socket_cleanup(self, _random, _capability):
        connection = self.connection()
        connection.recvfrom.side_effect = [
            (offer_packet(), ("192.168.1.1", 123)),
            (b"malformed", ("192.168.1.1", 67)),
            (offer_packet(), ("192.168.1.1", 67)),
            (offer_packet(), ("192.168.1.1", 67)),
            socket.timeout(),
        ]
        result = dhcp.discover("eth-test", socket_factory=Mock(return_value=connection))
        self.assertEqual(len(result["offers"]), 1)
        self.assertEqual(result["source"], "nettool-agent")
        self.assertEqual(result["interface"], "eth-test")
        self.assertEqual(result["schemaVersion"], 1)
        connection.sendto.assert_called_once_with(dhcp.build_discover(XID), ("255.255.255.255", 67))
        connection.bind.assert_called_once_with(("0.0.0.0", 68))
        connection.setsockopt.assert_any_call(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth-test\0")
        connection.__exit__.assert_called_once()
        self.assertFalse(any(call.args[1] in (socket.SO_REUSEADDR, socket.SO_REUSEPORT) for call in connection.setsockopt.call_args_list))

    @patch("nettool_agent.dhcp.check_capability")
    def test_no_replies_are_an_observation_not_a_socket_error(self, _capability):
        connection = self.connection()
        connection.recvfrom.side_effect = socket.timeout()
        result = dhcp.discover("eth-test", socket_factory=Mock(return_value=connection))
        self.assertEqual(result["offers"], [])
        self.assertTrue(any("does not prove" in item for item in result["limitations"]))

    @patch("nettool_agent.dhcp.check_capability")
    def test_port_in_use_is_capability_error_and_socket_is_closed(self, _capability):
        connection = self.connection()
        connection.bind.side_effect = OSError(errno.EADDRINUSE, "address in use")
        with self.assertRaisesRegex(dhcp.CapabilityError, "port 68"):
            dhcp.discover("eth-test", socket_factory=Mock(return_value=connection))
        connection.sendto.assert_not_called()
        connection.__exit__.assert_called_once()

    @patch("nettool_agent.dhcp.check_capability")
    def test_permission_error_is_capability_error(self, _capability):
        with self.assertRaisesRegex(dhcp.CapabilityError, "permission"):
            dhcp.discover("eth-test", socket_factory=Mock(side_effect=PermissionError(errno.EPERM, "denied")))

    @patch("nettool_agent.dhcp.check_capability")
    def test_receive_flood_has_packet_budget(self, _capability):
        connection = self.connection()
        connection.recvfrom.return_value = (b"wrong", ("192.168.1.1", 67))
        result = dhcp.discover("eth-test", socket_factory=Mock(return_value=connection))
        self.assertEqual(connection.recvfrom.call_count, 128)
        self.assertTrue(any("128" in item for item in result["limitations"]))

    def test_bad_timeouts_cannot_start_a_probe(self):
        for timeout in (0, 6, True, 1.5):
            factory = Mock()
            with self.assertRaises(ValueError):
                dhcp.discover("eth-test", timeout, socket_factory=factory)
            factory.assert_not_called()

    def test_explicit_interface_required(self):
        for name in ("", "lo", "../eth0", "eth0\0bad", "a" * 16):
            with self.assertRaises(ValueError):
                dhcp.validate_interface(name)


if __name__ == "__main__":
    unittest.main()
