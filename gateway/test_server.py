"""Loopback API and raw WebSocket tests against real native helper."""
import asyncio
import base64
import json
import os
import struct
import unittest
import socket
import subprocess
from unittest.mock import patch

from server import GatewayServer, now_ms
from test_gateway import MAC, ip
from test_gateway import udp
from test_catalog import PUBLIC, signed_catalog
from directory_catalog import fetch_catalog_async


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.secret='private-test-key-'+'x'*32
        self.server=GatewayServer(os.environ['HALO_GATEWAY_BINARY'],self.secret)
        self.listener=await asyncio.start_server(self.server.handle,'127.0.0.1',0,limit=8192)
        self.port=self.listener.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.listener.close();await self.listener.wait_closed();await self.server.shutdown()

    def headers(self,session='a'*64,secret=None,expiry=None):
        return {'Host':'localhost','X-Halo-Session':session,
                'X-Halo-Bridge-Key':secret or self.secret,
                'X-Halo-Session-Expires':str(expiry or now_ms()+60000)}

    async def request(self,method,path='/api/guest-network',session='a'*64,secret=None,body=b'',expiry=None):
        r,w=await asyncio.open_connection('127.0.0.1',self.port)
        headers=self.headers(session,secret,expiry)
        headers['Content-Length']=str(len(body))
        w.write((f'{method} {path} HTTP/1.1\r\n'+''.join(f'{k}: {v}\r\n' for k,v in headers.items())+'\r\n').encode()+body)
        await w.drain();raw=await asyncio.wait_for(r.read(),3)
        w.close();await w.wait_closed()
        head,data=raw.split(b'\r\n\r\n',1)
        return int(head.split(b' ')[1]),json.loads(data) if data else None

    async def test_lease_cap_per_client_from_the_worker_tag(self):
        async def post(session,client):
            r,w=await asyncio.open_connection('127.0.0.1',self.port)
            headers=self.headers(session);headers['Content-Length']='0';headers['X-Halo-Client']=client
            w.write(('POST /api/guest-network HTTP/1.1\r\n'+''.join(f'{k}: {v}\r\n' for k,v in headers.items())+'\r\n').encode())
            await w.drain();raw=await asyncio.wait_for(r.read(),3);w.close();await w.wait_closed()
            return int(raw.split(b' ')[1])
        self.assertEqual(await post('1'*64,'a'*32),201)
        self.assertEqual(await post('2'*64,'a'*32),201)
        self.assertEqual(await post('3'*64,'a'*32),429)
        self.assertEqual(await post('4'*64,'b'*32),201)
        self.assertEqual(await post('5'*64,'not hex'),400)

    async def websocket(self,lease):
        r,w=await asyncio.open_connection('127.0.0.1',self.port)
        headers=self.headers()
        headers.update({'Connection':'Upgrade','Upgrade':'websocket','Sec-WebSocket-Version':'13',
                        'Sec-WebSocket-Key':base64.b64encode(b'0123456789abcdef').decode()})
        w.write((f'GET {lease["websocketPath"]} HTTP/1.1\r\n'+''.join(f'{k}: {v}\r\n' for k,v in headers.items())+'\r\n').encode())
        await w.drain();head=await r.readuntil(b'\r\n\r\n');self.assertIn(b'101 Switching',head)
        return r,w

    async def test_auth_ownership_limit_and_cleanup(self):
        self.assertEqual((await self.request('POST',secret='wrong'))[0],403)
        self.assertEqual((await self.request('POST',expiry=now_ms()-1))[0],403)
        self.assertEqual((await self.request('POST',body=b'{"host":"127.0.0.1"}'))[0],400)
        status,a=await self.request('POST');self.assertEqual(status,201)
        self.assertEqual(a['mode'],'dce');self.assertEqual(a['role'],'host');self.assertEqual(len(a['lease']),43)
        status,b=await self.request('POST',session='b'*64);self.assertEqual(status,201)
        self.assertEqual(b['role'],'peer');self.assertEqual(b['joinEndpoint']['host'],b['routerIPv4'])
        with patch('server.MAX_LEASES',2):self.assertEqual((await self.request('POST',session='c'*64))[0],409)
        self.assertEqual((await self.request('GET',a['websocketPath'],session='b'*64))[0],404)
        self.assertEqual((await self.request('DELETE',a['websocketPath']))[0],204)
        self.assertEqual((await self.request('GET',b['websocketPath'],session='b'*64))[0],404)
        self.assertFalse(self.server.leases)

    async def test_default_limit_fits_four_consoles(self):
        for mark in 'abcd':self.assertEqual((await self.request('POST',session=mark*64))[0],201)
        self.assertEqual((await self.request('POST',session='e'*64))[0],409)

    async def test_websocket_actual_arp_and_disconnect_cleanup(self):
        _,lease=await self.request('POST');r,w=await self.websocket(lease)
        frame=b'\xff'*6+MAC+b'\x08\x06'+struct.pack('!HHBBH',1,0x800,6,4,1)+MAC+ip(lease['guestIPv4'])+b'\0'*6+ip(lease['routerIPv4'])
        mask=b'abcd';payload=bytes(v^mask[i%4] for i,v in enumerate(frame))
        w.write(bytes([0x82,0x80|len(frame)])+mask+payload);await w.drain()
        a,b=await asyncio.wait_for(r.readexactly(2),2);self.assertEqual(a,0x82)
        n=b if b<126 else struct.unpack('!H',await r.readexactly(2))[0]
        answer=await r.readexactly(n);self.assertEqual(answer[12:14],b'\x08\x06');self.assertEqual(answer[28:32],ip(lease['routerIPv4']))
        w.close();await w.wait_closed();await asyncio.sleep(.1)
        self.assertFalse(self.server.leases)

    async def test_renewal_extends_past_grant_then_expires_with_counters(self):
        with patch('server.MAX_LEASE_SECONDS',2):
            status,lease=await self.request('POST',expiry=now_ms()+30000)
            self.assertEqual(status,201)
            r,w=await self.websocket(lease)
            first=lease['expiresAt']
            for _ in range(3):
                await asyncio.sleep(1)
                status,lease=await self.request('POST',lease['websocketPath'],expiry=now_ms()+30000)
                self.assertEqual(status,200)
            self.assertGreater(lease['expiresAt'],first)
            status,_=await self.request('POST',lease['websocketPath'],session='b'*64)
            self.assertEqual(status,404)
            await asyncio.sleep(3.2)
        for _ in range(40):
            if self.server.counter_rows:break
            await asyncio.sleep(.1)
        row=self.server.counter_rows[-1]
        self.assertEqual(row['close_reason'],'expiry');self.assertEqual(row['renewals'],3)
        self.assertEqual(row['connections'],1);self.assertGreater(row['connected_ms'],4000)
        self.assertNotIn('session',row);self.assertNotIn(lease['lease'],json.dumps(row))
        w.close()

    async def test_renewal_never_passes_session_or_helper_end(self):
        expiry=now_ms()+5000
        _,lease=await self.request('POST',expiry=expiry)
        _,again=await self.request('POST',lease['websocketPath'],expiry=now_ms()+999999)
        self.assertLessEqual(again['expiresAt'],expiry)

    async def test_disconnect_releases_lease_so_later_delete_is_404(self):
        _,lease=await self.request('POST')
        r,w=await self.websocket(lease)
        w.close();await w.wait_closed()
        for _ in range(40):
            if not self.server.leases:break
            await asyncio.sleep(.1)
        self.assertEqual(self.server.leases,{})
        self.assertEqual((await self.request('DELETE',lease['websocketPath']))[0],404)
        for _ in range(40):
            if self.server.counter_rows:break
            await asyncio.sleep(.1)
        row=self.server.counter_rows[-1]
        self.assertEqual(row['close_reason'],'client_disconnect')
        self.assertEqual(row['helper']['failed'],0)

    async def test_unmasked_frame_closes_lease(self):
        _,lease=await self.request('POST');r,w=await self.websocket(lease)
        w.write(b'\x82\x0e'+b'x'*14);await w.drain()
        self.assertEqual(await asyncio.wait_for(r.read(),2),b'')
        w.close();await w.wait_closed();self.assertFalse(self.server.leases)

    async def test_expiry_kills_helper(self):
        _,lease=await self.request('POST',expiry=now_ms()+2100)
        await asyncio.sleep(2.2)
        self.assertFalse(self.server.leases)
        self.assertEqual((await self.request('GET',lease['websocketPath']))[0],404)

    async def test_directory_configuration_requires_separate_complete_pin(self):
        with self.assertRaises(ValueError):
            GatewayServer(os.environ['HALO_GATEWAY_BINARY'],self.secret,
                          directory_host='directory.fixture.invalid',directory_ip='192.0.2.1')
        with self.assertRaises(ValueError):
            GatewayServer(os.environ['HALO_GATEWAY_BINARY'],self.secret,
                          directory_host='bad/host',directory_ip='192.0.2.1',directory_verify_key='1'*64)
        configured=GatewayServer(os.environ['HALO_GATEWAY_BINARY'],self.secret,
            directory_host='directory.fixture.invalid',directory_ip='192.0.2.1',directory_verify_key='1'*64)
        self.assertEqual(configured.directory,('directory.fixture.invalid','192.0.2.1','1'*64))

    async def test_signed_catalog_parent_to_private_pipe_to_real_udp(self):
        address=subprocess.check_output(['hostname','-I'],text=True).split()[0]
        endpoint=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        endpoint.bind((address,0));endpoint.setblocking(False);port=endpoint.getsockname()[1]
        configured=GatewayServer(os.environ['HALO_GATEWAY_BINARY'],self.secret,
            directory_host='directory.fixture.invalid',directory_ip=address,directory_verify_key=PUBLIC,
            directory_private_lan_cidrs=[address+'/32'])
        body,headers=signed_catalog(address,port)
        try:
            with patch('server.fetch_catalog_async',return_value=(body,headers)):
                lease=await configured.create('a'*64,now_ms()+60000)
                for _ in range(100):
                    if configured.catalog:break
                    await asyncio.sleep(.01)
                self.assertTrue(configured.catalog)
                await asyncio.sleep(.03)
                frame=udp('10.77.1.15',address,5151,port,b'signed-admitted')
                lease.process.stdin.write(struct.pack('!H',len(frame))+frame)
                await lease.process.stdin.drain()
                data,_=await asyncio.wait_for(asyncio.get_running_loop().sock_recvfrom(endpoint,2048),1)
                self.assertEqual(data,b'signed-admitted')
            with patch('server.fetch_catalog_async',return_value=(body+b' ',headers)):
                await configured.refresh_catalog_once()
            self.assertFalse(configured.catalog)
            await asyncio.sleep(.03)
            lease.process.stdin.write(struct.pack('!H',len(frame))+frame);await lease.process.stdin.drain()
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.get_running_loop().sock_recvfrom(endpoint,2048),.15)
        finally:
            await configured.shutdown();endpoint.close()

    async def test_fixed_private_interface_host_mapping_and_metadata(self):
        address=subprocess.check_output(['hostname','-I'],text=True).split()[0]
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
            probe.bind((address,0));port=probe.getsockname()[1]
        configured=GatewayServer(os.environ['HALO_GATEWAY_BINARY'],self.secret,
                                 game_host=(address,port,address,port))
        try:
            host=await configured.create('a'*64,now_ms()+60000)
            peer=await configured.create('b'*64,now_ms()+60000)
            self.assertEqual(host.public()['advertisedEndpoint'],{'host':address,'port':port})
            self.assertEqual(peer.public()['joinEndpoint'],{'host':address,'port':port})
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as conflict:
                with self.assertRaises(OSError):conflict.bind((address,port))
        finally:await configured.shutdown()
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as released:released.bind((address,port))
        with self.assertRaises(ValueError):
            GatewayServer(os.environ['HALO_GATEWAY_BINARY'],self.secret,game_host=('127.0.0.1',port,address,port))

    async def test_catalog_fetch_cancellation_reaps_actual_child(self):
        address=subprocess.check_output(['hostname','-I'],text=True).split()[0]
        connected=asyncio.Event();closed=asyncio.Event();children=[]
        async def stalled_tls(reader,writer):
            connected.set()
            try:await reader.read()
            finally:writer.close();closed.set()
        listener=await asyncio.start_server(stalled_tls,address,443)
        original=asyncio.create_subprocess_exec
        async def capture(*args,**kwargs):
            child=await original(*args,**kwargs);children.append(child);return child
        try:
            with patch('directory_catalog.asyncio.create_subprocess_exec',side_effect=capture):
                task=asyncio.create_task(fetch_catalog_async('directory.fixture.invalid',address))
                await asyncio.wait_for(connected.wait(),2)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):await task
                self.assertEqual(len(children),1);self.assertIsNotNone(children[0].returncode)
                await asyncio.wait_for(closed.wait(),2)
        finally:listener.close();await listener.wait_closed()


if __name__=='__main__':unittest.main()
