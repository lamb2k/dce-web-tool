"""Deterministic idle/control/lifecycle tests; no core, Ethernet or live service."""
import asyncio
import base64
import unittest
from types import SimpleNamespace
from server import GatewayServer, Lease, HEARTBEAT_SECONDS, MAX_LEASE_SECONDS

class Writer:
    def __init__(self, reader=None):
        self.transport=self; self.reader=reader; self.writes=[]; self.closed=False; self.fail=False; self.stall=False
    def set_write_buffer_limits(self, **kwargs): pass
    def write(self, data):
        self.writes.append(data)
        if data==b'\x89\x00' and self.reader:
            self.reader.feed_data(b'\x8a\x80abcd')
    async def drain(self):
        if self.writes[-1:]==[b'\x89\x00']:
            if self.fail: raise ConnectionError('fixture')
            if self.stall: await asyncio.Future()
    def close(self):
        self.closed=True
        if self.reader and not self.reader.at_eof(): self.reader.feed_eof()

class HeartbeatTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server=GatewayServer('unused', 'x'*32)
        self.reader=asyncio.StreamReader(); self.stdout=asyncio.StreamReader()
        self.writer=Writer(self.reader); self.stdin=Writer()
        async def done(): return 0
        process=SimpleNamespace(stdin=self.stdin,stdout=self.stdout,wait=done)
        self.lease=Lease('a'*43,'b'*64,600000,0,'native',5150,process)
        self.server.leases[self.lease.token]=self.lease
        self.clock=0; self.ticks=asyncio.Queue(); self.heartbeat_task=None; self.delays=[]
        original=self.server.heartbeat
        async def sleeper(delay):
            self.delays.append(delay); await self.ticks.get()
        async def heartbeat(lease,send):
            self.heartbeat_task=asyncio.current_task()
            await original(lease,send,sleep=sleeper,clock=lambda:self.clock)
        self.server.heartbeat=heartbeat
        headers={'sec-websocket-key':base64.b64encode(b'0123456789abcdef').decode(),'sec-websocket-version':'13','connection':'upgrade'}
        self.task=asyncio.create_task(self.server.websocket(self.reader,self.writer,self.lease,headers))
        await self.flush()
    async def flush(self):
        for _ in range(40): await asyncio.sleep(0)
    async def tick(self,seconds):
        self.clock=seconds*1000; self.ticks.put_nowait(None); await self.flush()
    async def asyncTearDown(self):
        self.task.cancel(); await asyncio.gather(self.task,return_exceptions=True)
        await self.server.shutdown()
        self.assertTrue(self.heartbeat_task.done())
        self.assertFalse(self.server.leases)
    async def test_idle135_ping_pong_only_unchanged_expiry(self):
        self.assertEqual(HEARTBEAT_SECONDS,25); self.assertEqual(MAX_LEASE_SECONDS,600)
        self.assertEqual(self.lease.heartbeat_pings,0)
        for second in (25,50,75,100,125): await self.tick(second)
        self.clock=135000; await self.flush()
        self.assertFalse(self.task.done()); self.assertEqual(self.lease.expires,600000)
        self.assertEqual(self.lease.heartbeat_pings,5); self.assertEqual(self.lease.heartbeat_pongs,5)
        self.assertEqual(self.writer.writes[1:],[b'\x89\x00']*5); self.assertEqual(self.stdin.writes,[])
        self.assertEqual(self.delays,[25]*6)
    async def test_expiry_no_ping_or_extension(self):
        await self.tick(600); await asyncio.wait_for(self.task,1)
        self.assertEqual(self.lease.heartbeat_pings,0); self.assertEqual(self.lease.expires,600000)
    async def test_browser_close_cancels_heartbeat(self):
        self.reader.feed_data(b'\x88\x80abcd'); await asyncio.wait_for(self.task,1)
        self.assertIn(b'\x88\x00',self.writer.writes)
    async def test_helper_eof_cancels_heartbeat(self):
        self.stdout.feed_eof(); await asyncio.wait_for(self.task,1)
    async def test_ping_send_error_cancels_siblings(self):
        self.writer.fail=True; await self.tick(25); await asyncio.wait_for(self.task,1)
        self.assertEqual(self.lease.heartbeat_pings,0)
    async def test_ping_drain_deadline_cancels_siblings(self):
        self.writer.stall=True; await self.tick(25); await asyncio.wait_for(self.task,2)
        self.assertEqual(self.lease.heartbeat_pings,0)
    async def test_shutdown_cancels_heartbeat(self):
        await self.server.shutdown(); await asyncio.wait_for(self.task,1)
    async def test_unsolicited_pong_counter_bounded(self):
        self.reader.feed_data(b'\x8a\x80abcd'*30); await self.flush()
        self.assertEqual(self.lease.heartbeat_pongs,24)
    async def test_cancellation_cancels_all_children(self):
        self.task.cancel(); await asyncio.gather(self.task,return_exceptions=True)
        self.assertTrue(self.heartbeat_task.done())
    async def test_stall_does_not_create_catchup_burst(self):
        await self.tick(135); self.assertEqual(self.lease.heartbeat_pings,1)
        self.assertEqual(self.delays,[25,25])
