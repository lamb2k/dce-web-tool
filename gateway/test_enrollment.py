"""Public proof/session/quota fixtures; all identities here are synthetic."""
import asyncio
import base64
import json
import os
from pathlib import Path
import time
import unittest
import socket
import subprocess
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from enrollment import EnrollmentRelay,EnrollmentError,key_id,proof_bytes
from enrollment import operator_request
from server import GatewayServer

DEVICE=Ed25519PrivateKey.from_private_bytes(bytes.fromhex('22'*32))
PUBLIC='ed25519:'+DEVICE.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
MASTER='ed25519:d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737'
TOKEN='ab'*32
SESSION='a'*64


class FakeOperator:
    def __init__(self):self.calls=[];self.approved=set();self.cached={}
    async def __call__(self,url,token,action,session,body,master):
        self.calls.append((action,session,body));now=int(time.time())
        assert token==TOKEN and master==MASTER
        if action=='challenge':
            return dict(protocol=1,masterKeyId=key_id(MASTER),keyId=key_id(body['publicKey']),publicKey=body['publicKey'],
                        challenge=f'{len(self.calls):032x}',expires=now+60,serverTime=now,sessionBinding=session)
        lookup=(session,body['challenge'],body['signature'])
        if lookup not in self.cached:
            self.cached[lookup]=dict(ok=True,masterKeyId=key_id(MASTER),keyId=key_id(body['publicKey']),
                publicKey=body['publicKey'],approved=True,created=body['publicKey'] not in self.approved,serverTime=now)
            self.approved.add(body['publicKey'])
        return {**self.cached[lookup],'serverTime':now}


class EnrollmentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.operator=FakeOperator()
        self.relay=EnrollmentRelay('http://127.0.0.1:18097',TOKEN,MASTER,self.operator)
        self.expiry=int(time.time()*1000)+600000

    async def challenge(self,session=SESSION):
        return await self.relay.handle('challenge',session,self.expiry,{'publicKey':PUBLIC})

    def registration(self,value):
        return dict(publicKey=PUBLIC,challenge=value['challenge'],signature=base64.b64encode(DEVICE.sign(proof_bytes(value))).decode())

    async def test_golden_go_canonical_and_signature(self):
        vector=json.loads(Path(__file__).with_name('enrollment-vector.json').read_text())
        challenge=json.loads(vector['challenge_response']['body'])
        self.assertEqual(proof_bytes(challenge),bytes.fromhex(vector['canonical_hex']))
        self.assertEqual(proof_bytes(challenge).decode(),vector['canonical_utf8'])
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(vector['host_public'][8:])).verify(
            base64.b64decode(vector['signature']),proof_bytes(challenge))

    async def test_config_proof_idempotent_registration_and_same_key_new_session(self):
        config=await self.relay.handle('config',SESSION,self.expiry,None)
        self.assertEqual(config['masterPublicKey'],MASTER);self.assertFalse(self.operator.calls)
        challenge=await self.challenge();body=self.registration(challenge)
        first=await self.relay.handle('register',SESSION,self.expiry,body)
        second=await self.relay.handle('register',SESSION,self.expiry,body)
        self.assertTrue(first['approved']);self.assertTrue(first['created']);self.assertEqual(first,second)
        other=await self.challenge('b'*64)
        resumed=await self.relay.handle('register','b'*64,self.expiry,self.registration(other))
        self.assertFalse(resumed['created']);self.assertEqual(len(self.operator.approved),1)

    async def test_private_fields_wrong_proof_session_and_expiry_refused(self):
        with self.assertRaises(EnrollmentError):
            await self.relay.handle('challenge',SESSION,self.expiry,{'publicKey':PUBLIC,'seed':'forbidden'})
        self.assertFalse(self.operator.calls)
        value=await self.challenge();body=self.registration(value)
        for session,request in [('b'*64,body),(SESSION,{**body,'signature':base64.b64encode(bytes(64)).decode()})]:
            with self.assertRaises(EnrollmentError) as caught:await self.relay.handle('register',session,self.expiry,request)
            self.assertEqual(caught.exception.status,403)
        self.assertEqual(len(self.operator.calls),1)
        self.relay.pending[SESSION]['deadline']=time.monotonic()-1
        with self.assertRaises(EnrollmentError):await self.relay.handle('register',SESSION,self.expiry,body)

    async def test_quotas_and_pending_capacity(self):
        for _ in range(5):await self.challenge()
        with self.assertRaises(EnrollmentError) as caught:await self.challenge()
        self.assertEqual(caught.exception.status,429)
        for i in range(31):await self.challenge(f'{i:064x}')
        self.assertEqual(len(self.relay.pending),32)
        with self.assertRaises(EnrollmentError):await self.challenge('f'*64)
        self.assertEqual(len(self.relay.pending),32)

    async def test_backend_concurrency_and_cancel_release_reservations(self):
        entered=asyncio.Event();hold=asyncio.Event()
        async def waiting(*args):entered.set();await hold.wait()
        self.relay.requester=waiting
        first=asyncio.create_task(self.challenge('1'*64));await entered.wait()
        second=asyncio.create_task(self.challenge('2'*64));await asyncio.sleep(.01)
        with self.assertRaises(EnrollmentError) as caught:await self.challenge('3'*64)
        self.assertEqual(caught.exception.status,429);self.assertEqual(len(self.relay.pending),2)
        first.cancel();second.cancel();await asyncio.gather(first,second,return_exceptions=True)
        self.assertEqual(self.relay.inflight,0);self.assertFalse(self.relay.pending)

    async def test_private_endpoint_configuration(self):
        for url in ('http://example.com:18097','http://192.168.1.1:18097','http://127.0.0.1:18097/path',
                    'http://user:pass@127.0.0.1:18097','http://127.0.0.1:18097/?target=x'):
            with self.assertRaises(ValueError):EnrollmentRelay(url,TOKEN,MASTER)

    async def test_authenticated_gateway_routes_and_disabled_default(self):
        bridge='b'*64
        server=GatewayServer(os.environ['HALO_GATEWAY_BINARY'],bridge,enrollment=self.relay)
        listener=await asyncio.start_server(server.handle,'127.0.0.1',0,limit=8192)
        port=listener.sockets[0].getsockname()[1]
        async def request(action,body=None):
            payload=b'' if body is None else json.dumps(body).encode()
            reader,writer=await asyncio.open_connection('127.0.0.1',port)
            headers=f'POST /api/device-enrollment/{action} HTTP/1.1\r\nHost: localhost\r\nX-Halo-Bridge-Key: {bridge}\r\nX-Halo-Session: {SESSION}\r\nX-Halo-Session-Expires: {self.expiry}\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n'
            writer.write(headers.encode()+payload);await writer.drain()
            raw=await asyncio.wait_for(reader.read(),3);writer.close();await writer.wait_closed()
            head,data=raw.split(b'\r\n\r\n',1)
            return int(head.split()[1]),json.loads(data)
        try:
            code,config=await request('config');self.assertEqual(code,200);self.assertEqual(config['masterPublicKey'],MASTER)
            code,value=await request('challenge',{'publicKey':PUBLIC});self.assertEqual(code,200)
            code,result=await request('register',self.registration(value));self.assertEqual(code,200);self.assertTrue(result['approved'])
            self.assertEqual((await request('challenge',{'publicKey':PUBLIC,'privateKey':'blocked'}))[0],400)
            server.enrollment=None
            self.assertEqual((await request('config'))[0],503)
        finally:listener.close();await listener.wait_closed();await server.shutdown()


@unittest.skipUnless(os.environ.get('HALO_ENROLLMENT_TEST_BINARY'),'isolated Go binary required')
class RealOperatorTests(unittest.IsolatedAsyncioTestCase):
    async def test_signed_go_approval_retry_and_wrong_pin(self):
        # Explicit synthetic identities only; temporary loopback service and state.
        with tempfile.TemporaryDirectory(prefix='halo-enrollment-fixture-') as directory:
            root=Path(directory)
            for name,value in [('master','11'*32),('token',TOKEN),('approvals','[]')]:
                (root/name).write_text(value);(root/name).chmod(0o600)
            with socket.socket() as port_socket:
                port_socket.bind(('127.0.0.1',0));port=port_socket.getsockname()[1]
            process=subprocess.Popen([os.environ['HALO_ENROLLMENT_TEST_BINARY'],'--key',str(root/'master'),
                '--db',str(root/'nonces.db'),'--approvals',str(root/'approvals'),'--listen','127.0.0.1:0',
                '--udp-listen','127.0.0.1:0','--allow-loopback','--enrollment-listen',f'127.0.0.1:{port}',
                '--enrollment-token-file',str(root/'token')],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    if process.poll() is not None:self.fail(process.stderr.read().decode())
                    try:
                        reader,writer=await asyncio.open_connection('127.0.0.1',port)
                        writer.close();await writer.wait_closed();break
                    except OSError:await asyncio.sleep(.05)
                else:self.fail('operator startup timeout')
                url=f'http://127.0.0.1:{port}'
                relay=EnrollmentRelay(url,TOKEN,MASTER)
                expiry=int(time.time()*1000)+600000
                value=await relay.handle('challenge',SESSION,expiry,{'publicKey':PUBLIC})
                body=dict(publicKey=PUBLIC,challenge=value['challenge'],signature=base64.b64encode(DEVICE.sign(proof_bytes(value))).decode())
                first=await relay.handle('register',SESSION,expiry,body)
                again=await relay.handle('register',SESSION,expiry,body)
                self.assertTrue(first['created']);self.assertEqual(first['keyId'],again['keyId'])
                self.assertEqual(json.loads((root/'approvals').read_text()),[{'public_key':PUBLIC}])
                new=await relay.handle('challenge','b'*64,expiry,{'publicKey':PUBLIC})
                body=dict(publicKey=PUBLIC,challenge=new['challenge'],signature=base64.b64encode(DEVICE.sign(proof_bytes(new))).decode())
                self.assertFalse((await relay.handle('register','b'*64,expiry,body))['created'])
                with self.assertRaises(EnrollmentError) as caught:
                    await operator_request(url,TOKEN,'challenge','c'*64,{'publicKey':PUBLIC},PUBLIC)
                self.assertEqual(caught.exception.status,502)
                with self.assertRaises(EnrollmentError) as caught:
                    await operator_request(url,'cd'*32,'challenge','d'*64,{'publicKey':PUBLIC},MASTER)
                self.assertEqual(caught.exception.status,503) # Backend auth failure is not browser proof failure.
            finally:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait()
                process.stderr.close()


if __name__=='__main__':unittest.main()
