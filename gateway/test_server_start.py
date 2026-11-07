"""Runs server.py's real main() as a process, with a directory configured and the sign-up policy on.

A start failure there (a live deploy met one: the policy wrapper hid master_public) must fail here. No network, no helper run.
Needs a POSIX host with `cryptography`; it skips elsewhere."""
import http.client
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import unittest

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: F401
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

HERE = Path(__file__).resolve().parent
PIN = 'd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737'
OTHER = 'a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0'
SECRET = 'fixture-bridge-secret-'+'x'*32


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@unittest.skipUnless(os.name == 'posix' and HAVE_CRYPTOGRAPHY, 'needs a POSIX host with cryptography')
class Start(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.d = Path(tmp.name)
        token = self.d/'enrollment.token'
        token.write_text('ab'*32)
        token.chmod(0o600)
        self.port = free_port()
        self.env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'PYTHONDONTWRITEBYTECODE': '1',
                    'HALO_GATEWAY_BINARY': '/bin/true', 'HALO_GATEWAY_PORT': str(self.port), 'HALO_BRIDGE_SECRET': SECRET,
                    'HALO_DIRECTORY_HOST': 'directory.example.invalid', 'HALO_DIRECTORY_IPV4': '8.8.4.4', 'HALO_DIRECTORY_VERIFY_KEY': PIN,
                    'HALO_ENROLLMENT_URL': 'http://127.0.0.1:1', 'HALO_ENROLLMENT_TOKEN_FILE': str(token), 'HALO_ENROLLMENT_MASTER_KEY': 'ed25519:'+PIN,
                    'HALO_PUBLIC_ENROLL_STATE': str(self.d/'state.json'), 'HALO_PUBLIC_ENROLL_REVOKED': str(self.d/'revoked.txt')}

    def start(self, **change):
        env = {**self.env, **change}
        env = {k: v for k, v in env.items() if v is not None}
        process = subprocess.Popen([sys.executable, str(HERE/'server.py')], env=env, cwd=HERE, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: (process.poll() is None and process.kill(), process.communicate()))
        return process

    def lines_until_listening(self, process):
        lines = []
        for line in process.stdout:
            lines.append(line)
            if 'gateway listening' in line:
                return lines
        process.wait(10)
        self.fail('gateway did not start: '+''.join(lines)+process.stderr.read()[-800:])

    def config(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        connection.request('POST', '/api/device-enrollment/config', headers={
            'X-Halo-Bridge-Key': SECRET, 'X-Halo-Session': 'a'*64, 'X-Halo-Session-Expires': '9999999999999'})
        reply = connection.getresponse()
        body = reply.read()
        connection.close()
        return reply.status, body

    def test_policy_on_starts_serves_config_and_stops_clean(self):
        process = self.start()
        self.lines_until_listening(process)
        status, body = self.config()
        self.assertEqual(status, 200, body)
        self.assertIn(PIN.encode(), body)
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(10), 0)

    def test_without_policy_files_it_starts_with_sign_up_off(self):
        process = self.start(HALO_PUBLIC_ENROLL_STATE=None)
        lines = self.lines_until_listening(process)
        self.assertTrue(any('public enrollment off' in line for line in lines), lines)
        self.assertEqual(self.config()[0], 503)

    def test_a_master_key_that_differs_from_the_pin_refuses_to_start(self):
        process = self.start(HALO_ENROLLMENT_MASTER_KEY='ed25519:'+OTHER)
        self.assertNotEqual(process.wait(10), 0)
        self.assertIn('enrollment master must match', process.stderr.read())


if __name__ == '__main__':
    unittest.main()
