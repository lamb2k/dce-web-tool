"""Per-client lease cap and rate, without the native helper."""
import asyncio
import unittest
from unittest.mock import patch

import server
from server import ClientLimit, GatewayServer


class Row:
    def __init__(self, client, session='s'):
        self.client, self.session, self.mode = client, session, 'peer'


def gateway():
    g = GatewayServer.__new__(GatewayServer)
    g.leases, g.client_rates, g.lock = {}, {}, asyncio.Lock()
    return g


class Limits(unittest.TestCase):
    def test_held_leases_are_capped_per_client(self):
        g = gateway()
        g.leases = {str(n): Row('a') for n in range(server.LEASES_PER_CLIENT)}
        self.assertFalse(g.client_allowed('a'))
        self.assertTrue(g.client_allowed('b'))

    def test_new_leases_a_minute_are_capped(self):
        g = gateway()
        clock = [1000.0]
        with patch.object(server.time, 'monotonic', lambda: clock[0]):
            for _ in range(server.LEASE_RATE):
                self.assertTrue(g.client_allowed('a'))
            self.assertFalse(g.client_allowed('a'))
            clock[0] += 61
            self.assertTrue(g.client_allowed('a'))

    def test_rate_table_is_bounded(self):
        g = gateway()
        with patch.object(server, 'CLIENT_RATES', 2):
            self.assertTrue(g.client_allowed('a'))
            self.assertTrue(g.client_allowed('b'))
            self.assertFalse(g.client_allowed('c'))

    def test_create_refuses_a_client_at_its_cap_before_the_room_check(self):
        g = gateway()
        g.leases = {str(n): Row('a', f's{n}') for n in range(server.LEASES_PER_CLIENT)}

        async def run():
            await g.create('new-session', 0, None, 'a')
        with self.assertRaises(ClientLimit):
            asyncio.run(run())

    def test_a_session_keeps_its_lease_at_the_cap(self):
        g = gateway()
        row = Row('a', 'mine')
        row.mode = 'peer'
        g.leases = {'1': row, '2': Row('a', 'other')}

        async def run():
            return await g.create('mine', 0, None, 'a')
        self.assertIs(asyncio.run(run()), row)


if __name__ == '__main__':
    unittest.main()
