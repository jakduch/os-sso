#!/usr/bin/env python3
"""Management-socket failures must not be acknowledged as successful revocations."""
import importlib.util
import socket
import unittest
from pathlib import Path
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / 'src/opnsense/scripts/OPNsense/SSO/vpn_kill.py'
SPEC = importlib.util.spec_from_file_location('vpn_kill', SOURCE)
VPN_KILL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VPN_KILL)


class KillResultTest(unittest.TestCase):
    def response(self, value):
        connection = mock.MagicMock()
        connection.recv.side_effect = [b'greeting\n', value]
        return connection

    def test_timeout_is_unacknowledged(self):
        with mock.patch.object(VPN_KILL.socket, 'socket', side_effect=socket.timeout):
            self.assertIsNone(VPN_KILL.kill_on('/fixture.sock', 'alice'))

    def test_unknown_management_error_is_unacknowledged(self):
        connection = self.response(b'ERROR: management unavailable\n')
        with mock.patch.object(VPN_KILL.socket, 'socket') as factory:
            factory.return_value.__enter__.return_value = connection
            self.assertIsNone(VPN_KILL.kill_on('/fixture.sock', 'alice'))

    def test_absent_client_is_already_revoked(self):
        connection = self.response(b'ERROR: common name alice not found\n')
        with mock.patch.object(VPN_KILL.socket, 'socket') as factory:
            factory.return_value.__enter__.return_value = connection
            self.assertEqual(0, VPN_KILL.kill_on('/fixture.sock', 'alice'))

    def test_digits_in_common_name_do_not_inflate_kill_count(self):
        connection = self.response(b"SUCCESS: common name 'alice123' found, 1 client(s) killed\n")
        with mock.patch.object(VPN_KILL.socket, 'socket') as factory:
            factory.return_value.__enter__.return_value = connection
            self.assertEqual(1, VPN_KILL.kill_on('/fixture.sock', 'alice123'))


if __name__ == '__main__':
    unittest.main()
