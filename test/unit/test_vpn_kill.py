#!/usr/bin/env python3
"""Revoke the actual VPN identity using complete management responses."""
import importlib.util
import socket
import unittest
from pathlib import Path
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / 'src/opnsense/scripts/OPNsense/SSO/vpn_kill.py'
SPEC = importlib.util.spec_from_file_location('vpn_kill', SOURCE)
VPN_KILL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VPN_KILL)
HEADER = 'HEADER\tCLIENT_LIST\tCommon Name\tUsername\tClient ID\n'
SUCCESS = b'SUCCESS: client-kill command succeeded\n'


def status(*rows):
    return (HEADER + ''.join('CLIENT_LIST\t%s\t%s\t%s\n' % row for row in rows) + 'END\n').encode()


class KillResultTest(unittest.TestCase):
    def call(self, username, *chunks):
        connection = mock.MagicMock()
        connection.recv.side_effect = [b'>INFO:OpenVPN management\n', *chunks, b'']
        with mock.patch.object(VPN_KILL.socket, 'socket') as factory:
            factory.return_value.__enter__.return_value = connection
            result = VPN_KILL.kill_on('/fixture.sock', username)
        return result, [call.args[0] for call in connection.sendall.call_args_list]

    def test_timeout_is_unacknowledged(self):
        with mock.patch.object(VPN_KILL.socket, 'socket', side_effect=socket.timeout):
            self.assertIsNone(VPN_KILL.kill_on('/fixture.sock', 'alice'))

    def test_uses_username_when_certificate_name_differs(self):
        result, commands = self.call('alice', status(('device-42', 'alice', '17')), SUCCESS)
        self.assertEqual(1, result)
        self.assertEqual([b'status 3\n', b'client-kill 17\n'], commands)

    def test_does_not_kill_another_user_with_matching_certificate_name(self):
        result, commands = self.call('alice', status(('alice', 'bob', '18')))
        self.assertEqual(0, result)
        self.assertEqual([b'status 3\n'], commands)

    def test_username_with_spaces_is_not_truncated(self):
        result, commands = self.call('Alice Smith', status(('device', 'Alice Smith', '19')), SUCCESS)
        self.assertEqual(1, result)
        self.assertEqual(b'client-kill 19\n', commands[-1])

    def test_absent_client_is_already_revoked(self):
        self.assertEqual(0, self.call('alice', status())[0])

    def test_all_matching_tunnels_are_killed(self):
        result, commands = self.call('alice', status(('a', 'alice', '2'), ('b', 'alice', '1')), SUCCESS, SUCCESS)
        self.assertEqual(2, result)
        self.assertEqual([b'status 3\n', b'client-kill 1\n', b'client-kill 2\n'], commands)

    def test_fragmented_status_and_acknowledgement(self):
        response = status(('device', 'alice', '123')) + SUCCESS
        chunks = [response[index:index + 7] for index in range(0, len(response), 7)]
        self.assertEqual(1, self.call('alice', *chunks)[0])

    def test_missing_status_end_is_not_success(self):
        self.assertIsNone(self.call('alice', status()[:-4])[0])

    def test_unknown_management_error_is_unacknowledged(self):
        self.assertIsNone(self.call('alice', b'ERROR: management unavailable\n')[0])

    def test_failed_disconnect_is_unacknowledged(self):
        self.assertIsNone(self.call('alice', status(('d', 'alice', '3')), b'ERROR: client-kill command failed\n')[0])

    def test_missing_username_column_is_not_success(self):
        self.assertIsNone(self.call('alice', b'HEADER\tCLIENT_LIST\tCommon Name\tClient ID\nEND\n')[0])

    def test_injected_client_id_is_not_sent(self):
        result, commands = self.call('alice', status(('d', 'alice', '3; signal SIGTERM')))
        self.assertIsNone(result)
        self.assertEqual([b'status 3\n'], commands)

    def test_trailing_newline_in_username_is_rejected(self):
        result, commands = self.call('alice\n', status())
        self.assertIsNone(result)
        self.assertEqual([], commands)

    def test_asynchronous_notifications_are_not_acknowledgements(self):
        result, _ = self.call('alice', status(('d', 'alice', '4')), b'>LOG:example SUCCESS\n', SUCCESS)
        self.assertEqual(1, result)

    def test_oversized_response_is_not_success(self):
        with mock.patch.object(VPN_KILL, 'MAX_RESPONSE', 64):
            self.assertIsNone(self.call('alice', b'x' * 65)[0])


if __name__ == '__main__':
    unittest.main()
