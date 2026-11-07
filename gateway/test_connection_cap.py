"""S2-7: a live WebSocket does not hold an HTTP slot, so a full room can still renew. No native helper."""
import asyncio
import unittest

import server
from server import GatewayServer

SECRET = 'k'*32
SESSION = 'a'*64
LEASE = 'L'*43
FAR = server.now_ms()+3_600_000


class Writer:
    def __init__(self):
        self.data = b''
        self.closed = False

    def write(self, data):
        self.data += data

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


class Row:
    session = SESSION
    expires = FAR

    def public(self):
        return {'lease': 'row'}


def request(method, extra=''):
    text = (f'{method} {server.PREFIX}/{LEASE} HTTP/1.1\r\nx-halo-bridge-key: {SECRET}\r\nx-halo-session: {SESSION}\r\n'
            f'x-halo-session-expires: {FAR}\r\n{extra}\r\n')
    reader = asyncio.StreamReader()
    reader.feed_data(text.encode())
    return reader


class Cap(unittest.IsolatedAsyncioTestCase):
    def gateway(self):
        g = GatewayServer.__new__(GatewayServer)
        g.secret, g.connections, g.enrollment = SECRET, 0, None
        g.leases = {LEASE: Row()}
        g.renew = lambda lease, expiry: lease
        self.release = asyncio.Event()

        async def socket(reader, writer, lease, headers):
            await self.release.wait()
        g.websocket = socket
        return g

    async def test_sixteen_sockets_leave_renew_working(self):
        g = self.gateway()
        sockets = [asyncio.create_task(g.handle(request('GET', 'upgrade: websocket\r\n'), Writer())) for _ in range(16)]
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertEqual(g.connections, 0)
        writer = Writer()
        await g.handle(request('POST'), writer)
        self.assertTrue(writer.data.startswith(b'HTTP/1.1 200 '), writer.data)
        self.assertEqual(g.connections, 0)
        self.release.set()
        await asyncio.gather(*sockets)
        self.assertEqual(g.connections, 0)

    async def test_http_cap_still_holds(self):
        g = self.gateway()
        g.connections = 16
        writer = Writer()
        await g.handle(request('POST'), writer)
        self.assertEqual(writer.data, b'')
        self.assertTrue(writer.closed)
        self.assertEqual(g.connections, 16)

    async def test_failed_request_gives_its_slot_back(self):
        g = self.gateway()
        reader = asyncio.StreamReader()
        reader.feed_data(b'bad\r\n\r\n')
        await g.handle(reader, Writer())
        self.assertEqual(g.connections, 0)


if __name__ == '__main__':
    unittest.main()
