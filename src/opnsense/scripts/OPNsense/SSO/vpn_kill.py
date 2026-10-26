#!/usr/local/bin/python3
"""
    Copyright (C) 2026 Maxime Wewer
    SPDX-License-Identifier: BSD-2-Clause

    Disconnect OpenVPN clients by the username supplied at authentication.

    The certificate common name can differ from that username. Resolve the exact
    Username column in status 3, then disconnect numeric client IDs. No client
    supplied text is interpolated into a management command.
"""
import glob
import json
import re
import socket
import sys
import time

SOCKET_GLOB = '/var/etc/openvpn/*.sock'
TIMEOUT = 3
MAX_RESPONSE = 8 * 1024 * 1024


class ManagementReader:
    """Read complete lines with one time and size budget per connection."""
    def __init__(self, connection):
        self.connection = connection
        self.buffer = b''
        self.remaining = MAX_RESPONSE
        self.deadline = time.monotonic() + TIMEOUT

    def line(self):
        while b'\n' not in self.buffer:
            remaining_time = self.deadline - time.monotonic()
            if remaining_time <= 0:
                raise TimeoutError('management response deadline exceeded')
            self.connection.settimeout(remaining_time)
            data = self.connection.recv(min(4096, self.remaining + 1))
            if not data or len(data) > self.remaining:
                raise ValueError('incomplete or oversized management response')
            self.remaining -= len(data)
            self.buffer += data
        line, self.buffer = self.buffer.split(b'\n', 1)
        return line.rstrip(b'\r').decode('utf-8', errors='strict')


def client_ids(reader, username):
    """Require a complete status response and the identity columns we depend on."""
    header = None
    clients = set()
    while True:
        line = reader.line()
        if line == 'END':
            if header is None:
                raise ValueError('missing client status header')
            return sorted(clients, key=int)
        if line.startswith('>'):
            continue  # asynchronous management notifications
        row = line.split('\t')
        if row[:2] == ['HEADER', 'CLIENT_LIST']:
            if header is not None:
                raise ValueError('duplicate client status header')
            header = row[1:]
            if header.count('Username') != 1 or header.count('Client ID') != 1:
                raise ValueError('missing client identity columns')
        elif row[0] == 'CLIENT_LIST':
            if header is None or len(row) != len(header):
                raise ValueError('malformed client status row')
            client = dict(zip(header, row))
            if client['Username'] == username:
                if re.fullmatch(r'[0-9]+', client['Client ID']) is None:
                    raise ValueError('invalid client ID')
                clients.add(client['Client ID'])
        elif line.startswith('ERROR:'):
            raise ValueError('management status failed')


def kill_on(socket_path, username):
    """Return the acknowledged disconnect count, or None when it must be retried."""
    if re.fullmatch(r'[A-Za-z0-9._@ -]{1,64}', username) is None:
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect(socket_path)
            reader = ManagementReader(sock)
            if not reader.line().startswith('>INFO:'):
                return None
            sock.sendall(b'status 3\n')
            clients = client_ids(reader, username)
            killed = 0
            for client in clients:
                sock.sendall(('client-kill %s\n' % client).encode('ascii'))
                while True:
                    answer = reader.line()
                    if not answer.startswith('>'):
                        break
                if answer != 'SUCCESS: client-kill command succeeded':
                    return None
                killed += 1
            return killed
    except (OSError, ValueError, UnicodeError):
        return None


def main():
    name = sys.argv[1] if len(sys.argv) == 2 else ''
    if re.fullmatch(r'[A-Za-z0-9._@ -]{1,64}', name) is None:
        print(json.dumps({'status': 'invalid username', 'killed': 0}))
        return 1
    killed = 0
    failures = 0
    sockets = sorted(glob.glob(SOCKET_GLOB))
    for path in sockets:
        result = kill_on(path, name)
        if result is None:
            failures += 1
        else:
            killed += result
    print(json.dumps({'status': 'error' if failures else 'ok', 'killed': killed,
                      'instances': len(sockets), 'failures': failures}))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
