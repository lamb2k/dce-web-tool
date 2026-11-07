import asyncio
import unittest
from directory_proxy import DirectoryIngress,RESPONSE_LIMIT

class DirectoryIngressTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.calls=[];self.slow=False;self.reply=b' exact signed body\n'
        async def backend(reader,writer):
            try:
                raw=await reader.readuntil(b'\r\n\r\n')
                lines=raw.decode().split('\r\n');headers=dict(line.split(': ',1) for line in lines[1:-2])
                body=await reader.readexactly(int(headers['Content-Length']))
                self.calls.append((lines[0],headers,body))
                if self.slow:await reader.read();return
                writer.write(b'HTTP/1.0 200 OK\r\nSignature: ed25519=exact\r\nSignature-Key: aaaaaaaaaaaaaaaa\r\nSignature-Time: 123\r\nContent-Length: '+str(len(self.reply)).encode()+b'\r\n\r\n'+self.reply)
                await writer.drain()
            finally:writer.close();await writer.wait_closed()
        self.backend=await asyncio.start_server(backend,'127.0.0.1',0)
        self.ingress=DirectoryIngress('d'*64,self.backend.sockets[0].getsockname()[1])
        self.listener=await asyncio.start_server(self.ingress.handle,'127.0.0.1',0,limit=8192)
        self.port=self.listener.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.listener.close();self.backend.close()
        await self.listener.wait_closed();await self.backend.wait_closed()

    async def test_list_nonce_passes(self):
        for query in ('?nonce='+'ab'*16,'?limit=1&nonce='+'ab'*16):
            await self.request('/v1/dce/servers'+query)
            self.assertEqual(self.calls[-1][0],f'GET /v1/dce/servers{query} HTTP/1.0')

    async def request(self,path='/v1/dce/servers?limit=16',method='GET',body=b'',key=None,extra=''):
        reader,writer=await asyncio.open_connection('127.0.0.1',self.port)
        key='d'*64 if key is None else key
        raw=f'{method} {path} HTTP/1.1\r\nHost: fixture\r\nX-Halo-Directory-Key: {key}\r\nContent-Length: {len(body)}\r\n{extra}\r\n'.encode()+body
        writer.write(raw);await writer.drain()
        result=await asyncio.wait_for(reader.read(),7)
        writer.close();await writer.wait_closed()
        head,data=result.split(b'\r\n\r\n',1)
        return int(head.split()[1]),head,data

    async def test_exact_bytes_query_and_fresh_headers(self):
        status,head,data=await self.request();self.assertEqual(status,200);self.assertEqual(data,self.reply)
        self.assertIn(b'Signature: ed25519=exact',head)
        self.assertEqual(self.calls[-1][0],'GET /v1/dce/servers?limit=16 HTTP/1.0')
        body=b' {"name":"fixture"}\n'
        status,_,_=await self.request('/v1/dce/servers/'+'a'*16,'PUT',body,extra='Authorization: OpenCE-Ed25519 exact\r\nCookie: forbidden\r\nX-Forwarded-For: spoof\r\n')
        self.assertEqual(status,200);line,headers,actual=self.calls[-1]
        self.assertEqual(actual,body);self.assertEqual(headers['Authorization'],'OpenCE-Ed25519 exact')
        self.assertNotIn('Cookie',headers);self.assertNotIn('X-Forwarded-For',headers);self.assertNotIn('X-Halo-Directory-Key',headers)

    async def test_auth_route_query_duplicates_and_bounds(self):
        for kwargs,status in [({'key':'wrong'},403),({'path':'/v1/dce/enrollment/challenge'},404),
            ({'path':'/v1/dce/servers?limit=016'},404),
            ({'path':'/v1/dce/servers?nonce=short'},404),({'path':'/v1/dce/servers?nonce='+'A'*32},404),({'method':'POST'},405),
            ({'extra':'Content-Length: 0\r\n'},400),({'extra':'Transfer-Encoding: chunked\r\n'},400),
            ({'path':'/v1/dce/servers/'+'a'*16,'method':'PUT'},401)]:
            self.assertEqual((await self.request(**kwargs))[0],status)
        self.assertFalse(self.calls)
        self.reply=b'x'*(RESPONSE_LIMIT+1)
        self.assertEqual((await self.request())[0],502)

    async def test_total_backend_deadline_and_slot_release(self):
        self.slow=True
        start=asyncio.get_running_loop().time()
        self.assertEqual((await self.request())[0],502)
        self.assertLess(asyncio.get_running_loop().time()-start,6)
        await asyncio.sleep(.01);self.assertEqual(self.ingress.active,0)

    async def test_handler_cancellation_releases_slot(self):
        reader=asyncio.StreamReader()
        class Writer:
            closed=False
            def close(self):self.closed=True
            async def wait_closed(self):pass
        writer=Writer();task=asyncio.create_task(self.ingress.handle(reader,writer))
        await asyncio.sleep(0);self.assertEqual(self.ingress.active,1)
        task.cancel();await asyncio.gather(task,return_exceptions=True)
        self.assertEqual(self.ingress.active,0);self.assertTrue(writer.closed)

if __name__=='__main__':unittest.main()
