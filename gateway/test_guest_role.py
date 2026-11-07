"""Guest role: signed catalog tuples only, real helper and sockets. Fails closed."""
import asyncio
import os
import re
import socket
import struct
import subprocess
import time
import unittest
from unittest.mock import patch

from directory_catalog import control_snapshot
from server import GatewayServer, now_ms
from test_catalog import PUBLIC, signed_catalog
from test_gateway import Guest, udp, udp_payload

ADDRESS = subprocess.check_output(['hostname', '-I'], text=True).split()[0]
DIRECTORY = ('directory.fixture.invalid', '192.0.2.1')


def refused(guest):
    guest.p.stdin.close()
    guest.p.wait(3)
    return int(re.search(rb'refused=(\d+)', guest.p.stderr.read())[1])


class HelperGuestMode(unittest.TestCase):
    def setUp(self):
        self.endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.endpoint.bind((ADDRESS, 0))
        self.endpoint.settimeout(.25)
        self.port = self.endpoint.getsockname()[1]
        self.addCleanup(self.endpoint.close)

    def guest(self):
        guest = Guest('guest', 1, port=1, directory=DIRECTORY, control=True)
        self.addCleanup(lambda: (guest.p.kill(), guest.p.wait()))
        guest.arp()
        return guest

    def test_requires_control_and_directory(self):
        for kwargs in (dict(directory=DIRECTORY), dict(control=True)):
            with self.assertRaises(RuntimeError):
                Guest('guest', 1, port=1, **kwargs)

    def test_only_listed_ip_and_port(self):
        guest = self.guest()
        os.write(guest.control, control_snapshot(1, [(ADDRESS, self.port, int(time.time())+30)]))
        time.sleep(.03)
        guest.send(udp(guest.addr, ADDRESS, 5151, self.port, b'listed'))
        self.assertEqual(self.endpoint.recvfrom(64)[0], b'listed')
        bad = [('8.8.4.4', self.port, 5151), ('192.168.77.77', self.port, 5151),  # unlisted, LAN
               (ADDRESS, self.port+1 if self.port < 65535 else self.port-1, 5151),  # right IP, wrong port
               (guest.router, self.port, 5151), (guest.router, 5150, 5151),  # gateway itself
               ('127.0.0.1', self.port, 5151), (ADDRESS, self.port, 4000)]  # loopback, wrong source port
        for host, port, source in bad:
            guest.send(udp(guest.addr, host, source, port, b'refused'))
        with self.assertRaises(socket.timeout):
            self.endpoint.recvfrom(64)
        time.sleep(.05)
        self.assertEqual(refused(guest), len(bad))

    def test_expired_and_revoked_rows_stop_flows(self):
        guest = self.guest()
        os.write(guest.control, control_snapshot(1, [(ADDRESS, self.port, int(time.time())+2)]))
        time.sleep(.03)
        guest.send(udp(guest.addr, ADDRESS, 5151, self.port, b'live'))
        self.assertEqual(self.endpoint.recvfrom(64)[0], b'live')
        time.sleep(2.2)
        guest.send(udp(guest.addr, ADDRESS, 5151, self.port, b'expired'))
        with self.assertRaises(socket.timeout):
            self.endpoint.recvfrom(64)
        os.write(guest.control, control_snapshot(2, [(ADDRESS, self.port, int(time.time())+30)]))
        time.sleep(.03)
        guest.send(udp(guest.addr, ADDRESS, 5151, self.port, b'relisted'))
        self.assertEqual(self.endpoint.recvfrom(64)[0], b'relisted')
        os.write(guest.control, control_snapshot(3, []))
        time.sleep(.03)
        guest.send(udp(guest.addr, ADDRESS, 5151, self.port, b'revoked'))
        with self.assertRaises(socket.timeout):
            self.endpoint.recvfrom(64)


class EstablishedFlows(HelperGuestMode):
    def opened(self):
        guest = self.guest()
        os.write(guest.control, control_snapshot(1, [(ADDRESS, self.port, int(time.time())+30)]))
        time.sleep(.03)
        guest.send(udp(guest.addr, ADDRESS, 5151, self.port, b'open'))
        peer = self.endpoint.recvfrom(64)[1]
        return guest, peer

    def reply(self, guest, peer):
        self.endpoint.sendto(b'pong', peer)
        return udp_payload(guest.recv(lambda f: f[12:14] == b'\x08\x00' and f[23] == 17))

    def test_row_removed_mid_flow_keeps_flow_but_refuses_new(self):
        guest, peer = self.opened()
        self.assertEqual(self.reply(guest, peer), b'pong')
        other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        other.bind((ADDRESS, 0))
        other.settimeout(.25)
        self.addCleanup(other.close)
        os.write(guest.control, control_snapshot(2, []))
        time.sleep(.03)
        guest.send(udp(guest.addr, ADDRESS, 5151, self.port, b'still'))
        self.assertEqual(self.endpoint.recvfrom(64)[0], b'still')
        self.assertEqual(self.reply(guest, peer), b'pong')
        guest.send(udp(guest.addr, ADDRESS, 5151, other.getsockname()[1], b'new'))
        with self.assertRaises(socket.timeout):
            other.recvfrom(64)

    def test_no_reply_means_not_established(self):
        guest = self.guest()
        os.write(guest.control, control_snapshot(1, [(ADDRESS, self.port, int(time.time())+30)]))
        time.sleep(.03)
        guest.send(udp(guest.addr, ADDRESS, 5151, self.port, b'open'))
        self.endpoint.recvfrom(64)
        os.write(guest.control, control_snapshot(2, []))
        time.sleep(.03)
        guest.send(udp(guest.addr, ADDRESS, 5151, self.port, b'refused'))
        with self.assertRaises(socket.timeout):
            self.endpoint.recvfrom(64)

    def test_idle_flow_expires(self):
        guest, peer = self.opened()
        self.reply(guest, peer)
        os.write(guest.control, control_snapshot(2, []))
        time.sleep(20.2)
        guest.send(udp(guest.addr, ADDRESS, 5151, self.port, b'idle'))
        with self.assertRaises(socket.timeout):
            self.endpoint.recvfrom(64)


class RelayEgress(unittest.TestCase):
    def test_only_browser_host_reaches_relay_hello_and_only_there(self):
        endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        endpoint.bind((ADDRESS, 0))
        endpoint.settimeout(.25)
        self.addCleanup(endpoint.close)
        port = endpoint.getsockname()[1]
        os.environ['HALO_GATEWAY_RELAY'] = f'{ADDRESS}:{port}'
        self.addCleanup(os.environ.pop, 'HALO_GATEWAY_RELAY')
        host = Guest('host', 1, port=25151)
        self.addCleanup(lambda: (host.p.kill(), host.p.wait()))
        host.arp()
        host.send(udp(host.addr, ADDRESS, 5150, port, b'hello'))
        self.assertEqual(endpoint.recvfrom(64)[0], b'hello')
        host.send(udp(host.addr, ADDRESS, 5151, port, b'wrong source'))
        host.send(udp(host.addr, ADDRESS, 5150, port+1 if port < 65535 else port-1, b'wrong port'))
        with self.assertRaises(socket.timeout):
            endpoint.recvfrom(64)
        guest = Guest('guest', 2, port=1, directory=DIRECTORY, control=True)
        self.addCleanup(lambda: (guest.p.kill(), guest.p.wait()))
        guest.arp()
        guest.send(udp(guest.addr, ADDRESS, 5150, port, b'guest refused'))
        with self.assertRaises(socket.timeout):
            endpoint.recvfrom(64)


class ServerRoles(unittest.IsolatedAsyncioTestCase):
    def server(self, **kwargs):
        return GatewayServer(os.environ['HALO_GATEWAY_BINARY'], 'x'*40, **kwargs)

    def directory(self, **kwargs):
        return self.server(directory_host=DIRECTORY[0], directory_ip=DIRECTORY[1], directory_verify_key=PUBLIC,
                           directory_private_lan_cidrs=[ADDRESS+'/32'], **kwargs)

    async def test_guest_needs_no_host_and_room_still_works(self):
        fetch = patch('server.fetch_catalog_async', side_effect=OSError())
        with fetch:
            server = self.directory()
            try:
                guest = await server.create('a'*64, now_ms()+60000, 'join')
                self.assertEqual(guest.mode, 'guest')
                self.assertIsNone(guest.public()['joinEndpoint'])
                with self.assertRaises(ValueError):
                    await server.create('a'*64, now_ms()+60000, 'host')
                host = await server.create('b'*64, now_ms()+60000, 'host')
                self.assertEqual((host.mode, guest.index != host.index), ('host', True))
                await server.close_lease(host)
                self.assertFalse(guest.closing)
            finally:
                await server.shutdown()

    async def test_room_defaults_and_refusals(self):
        server = self.server()
        try:
            with self.assertRaisesRegex(ValueError, 'guest_unavailable'):
                await server.create('a'*64, now_ms()+60000, 'join')
            self.assertEqual((await server.create('a'*64, now_ms()+60000)).mode, 'host')
            with self.assertRaisesRegex(ValueError, 'host_taken'):
                await server.create('b'*64, now_ms()+60000, 'host')
            self.assertEqual((await server.create('b'*64, now_ms()+60000, 'join')).mode, 'peer')
        finally:
            await server.shutdown()

    async def test_relay_lets_hosts_share_a_gateway(self):
        server = self.directory()
        try:
            with patch.dict(os.environ, {'HALO_GATEWAY_RELAY': '192.0.2.9:5400'}), patch('server.MAX_LEASES', 8):
                first = await server.create('a'*64, now_ms()+60000, 'host')
                second = await server.create('b'*64, now_ms()+60000, 'host')
                self.assertEqual((first.mode, second.mode), ('host', 'host'))
                self.assertNotEqual(first.index, second.index)
                self.assertEqual((await server.create('c'*64, now_ms()+60000, 'join')).mode, 'guest')
                self.assertEqual((await server.create('d'*64, now_ms()+60000)).mode, 'guest')
        finally:
            await server.shutdown()

    async def test_bad_signature_clears_guest_access(self):
        endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        endpoint.bind((ADDRESS, 0))
        endpoint.setblocking(False)
        port = endpoint.getsockname()[1]
        body, headers = signed_catalog(ADDRESS, port)
        server = self.directory()
        loop = asyncio.get_running_loop()
        try:
            with patch('server.fetch_catalog_async', return_value=(body, headers)):
                lease = await server.create('a'*64, now_ms()+60000, 'join')
                for _ in range(100):
                    if server.catalog:
                        break
                    await asyncio.sleep(.01)
                await asyncio.sleep(.03)
                frame = udp('10.77.1.15', ADDRESS, 5151, port, b'signed')
                lease.process.stdin.write(struct.pack('!H', len(frame))+frame)
                await lease.process.stdin.drain()
                self.assertEqual((await asyncio.wait_for(loop.sock_recvfrom(endpoint, 64), 1))[0], b'signed')
            with patch('server.fetch_catalog_async', return_value=(body+b' ', headers)):
                await server.refresh_catalog_once()
            self.assertFalse(server.catalog)
            await asyncio.sleep(.03)
            lease.process.stdin.write(struct.pack('!H', len(frame))+frame)
            await lease.process.stdin.drain()
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(loop.sock_recvfrom(endpoint, 64), .2)
        finally:
            await server.shutdown()
            endpoint.close()

    async def test_normal_close_reports_no_helper_failure(self):
        with patch('server.fetch_catalog_async', side_effect=OSError()):
            server = self.directory()
            lease = await server.create('a'*64, now_ms()+60000, 'join')
            await server.close_lease(lease, 'delete')
            for _ in range(40):
                if server.counter_rows:
                    break
                await asyncio.sleep(.05)
            await server.shutdown()
        self.assertEqual(server.counter_rows[-1]['helper']['failed'], 0)

    async def test_fetch_failure_keeps_verified_rows(self):
        body, headers = signed_catalog(ADDRESS, 6000)
        server = self.directory()
        with patch('server.fetch_catalog_async', return_value=(body, headers)):
            await server.refresh_catalog_once()
        rows = list(server.catalog)
        self.assertTrue(rows)
        for error in (OSError(), ValueError('catalog_fetch_failed'), asyncio.TimeoutError()):
            with patch('server.fetch_catalog_async', side_effect=error):
                await server.refresh_catalog_once()
            self.assertEqual(server.catalog, rows)
        with patch('server.fetch_catalog_async', return_value=(body+b' ', headers)):
            await server.refresh_catalog_once()
        self.assertEqual(server.catalog, [])

    async def test_test_destination_off_by_default_guest_only_and_validated(self):
        with patch('server.fetch_catalog_async', side_effect=OSError()):
            off = self.directory()
            self.assertIsNone(off.test_destination)
            self.assertEqual(off.endpoints_for(type('L', (), dict(mode='guest')), []), [])
            for bad in ('127.0.0.1:5150', '10.77.1.2:5150', '169.254.1.1:5150', '192.168.1.5:80', 'nonsense'):
                with self.assertRaises(ValueError):
                    self.directory(test_destination=bad)
            with self.assertRaises(ValueError):
                self.server(test_destination='192.168.1.5:5150')
            on = self.directory(test_destination='192.168.1.5:5150')
            guest = await on.create('a'*64, now_ms()+60000, 'join')
            try:
                self.assertTrue(guest.test_destination_active)
                self.assertEqual(on.endpoints_for(guest, [])[0][:2], ('192.168.1.5', 5150))
                self.assertEqual(on.endpoints_for(type('L', (), dict(mode='host')), []), [])
            finally:
                await on.shutdown()


if __name__ == '__main__':
    unittest.main()
