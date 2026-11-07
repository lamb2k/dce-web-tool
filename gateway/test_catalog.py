"""Official Ed25519 verification plus real private-control Ethernet admission."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import unittest
import fcntl

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from directory_catalog import CatalogVerifier,control_snapshot
from test_gateway import Guest,udp,udp_payload

# Public deterministic test identity, never production provisioning.
KEY=Ed25519PrivateKey.from_private_bytes(bytes.fromhex('33'*32))
PUBLIC=KEY.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
KEY_ID=hashlib.sha256(bytes.fromhex(PUBLIC)).hexdigest()[:16]


def signed_catalog(address='8.8.4.4',port=5150,now=None):
    now=int(time.time()) if now is None else now
    keyid,instance='11'*8,'22'*8
    row=dict(id=hashlib.sha256((keyid+instance).encode()).hexdigest()[:16],key_id=keyid,instance=instance,
             protocol=1,family='dce-net',network_version=4,build=1,map=0,map_crc=2,mode=0,score=15,
             players=1,capacity=2,name='Fixture',sequence=1,time=now,game_port=port,
             endpoint=dict(ip=address,port=port),updated=now,expires=now+90,reachable=True)
    data=dict(protocol=1,family='dce-net',network_version=4,master=dict(key_id=KEY_ID,time=now),
              ttl=90,truncated=False,servers=[row])
    return sign(data,now)


def sign(data,now):
    body=json.dumps(data,separators=(',',':')).encode()
    return body,{'Signature':'ed25519='+base64.b64encode(KEY.sign(body)).decode(),
                 'Signature-Key':KEY_ID,'Signature-Time':str(now)}


class CatalogTests(unittest.TestCase):
    def test_go_signed_vector_and_block_loopback(self):
        vector=json.loads(Path(__file__).with_name('directory-vector.json').read_text())
        verifier=CatalogVerifier(vector['master_public'].removeprefix('ed25519:'))
        body=vector['list_response']['body'].encode();headers=vector['list_response']['headers']
        self.assertEqual(verifier.signed_body(body,headers,vector['time'])['family'],'dce-net')
        with self.assertRaisesRegex(ValueError,'blocked_endpoint'):
            verifier.verify(body,headers,vector['time'])

    def test_signature_identity_freshness_and_endpoint_refusals(self):
        now=int(time.time());verifier=CatalogVerifier(PUBLIC);body,headers=signed_catalog(now=now)
        self.assertEqual(verifier.verify(body,headers,now),[('8.8.4.4',5150,now+90)])
        self.assertEqual(verifier.verify(*signed_catalog(port=1024,now=now),now),[('8.8.4.4',1024,now+90)])
        with self.assertRaises(ValueError):verifier.verify(*signed_catalog(port=1023,now=now),now)
        for altered,head in ((body+b' ',headers),(body,{**headers,'Signature-Key':'00'*8}),
                             (body,{**headers,'Signature-Time':str(now-31)})):
            with self.assertRaises(ValueError):verifier.verify(altered,head,now)
        for address in ('127.0.0.1','169.254.169.254','10.77.1.2','192.0.2.1','224.0.0.1','192.168.1.2'):
            with self.assertRaises(ValueError):verifier.verify(*signed_catalog(address,now=now),now)
        for change in ({'family':'opence'},{'expires':now+91},{'reachable':False},{'game_port':22}):
            data=json.loads(body);data['servers'][0].update(change)
            with self.assertRaises(ValueError):verifier.verify(*sign(data,now),now)
        data=json.loads(body);data['servers']*=33
        with self.assertRaises(ValueError):verifier.verify(*sign(data,now),now)
        private=CatalogVerifier(PUBLIC,['192.168.1.0/24'])
        self.assertEqual(private.verify(*signed_catalog('192.168.1.2',now=now),now)[0][0],'192.168.1.2')
        for scope in ('0.0.0.0/0','127.0.0.0/8','169.254.0.0/16'):
            with self.assertRaises(ValueError):CatalogVerifier(PUBLIC,[scope])

    def test_real_control_admission_revoke_expiry_and_reply_filter(self):
        address=subprocess.check_output(['hostname','-I'],text=True).split()[0]
        endpoint=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        endpoint.bind((address,0));endpoint.settimeout(.15);port=endpoint.getsockname()[1]
        g=Guest(control=True)
        try:
            g.arp();g.send(udp(g.addr,address,5151,port,b'blocked'))
            with self.assertRaises(socket.timeout):endpoint.recvfrom(2048)
            os.write(g.control,control_snapshot(1,[(address,port,int(time.time())+2)]))
            time.sleep(.03)
            g.send(udp(g.addr,address,5151,port,b'admitted'))
            payload,peer=endpoint.recvfrom(2048);self.assertEqual(payload,b'admitted')
            os.write(g.control,control_snapshot(2,[]));time.sleep(.03)
            g.send(udp(g.addr,address,5151,port,b'revoked'))
            with self.assertRaises(socket.timeout):endpoint.recvfrom(2048)
            endpoint.sendto(b'late-reply',peer)
            with self.assertRaises(TimeoutError):g.recv(lambda f:f[12:14]==b'\x08\x00' and f[23]==17,timeout=.15)
            os.write(g.control,control_snapshot(3,[(address,port,int(time.time())+1)]));time.sleep(1.1)
            g.send(udp(g.addr,address,5151,port,b'expired'))
            with self.assertRaises(socket.timeout):endpoint.recvfrom(2048)
        finally:
            log=g.close();endpoint.close()
        self.assertIn('dropped=1',log)

    def test_control_not_ethernet_and_control_eof_closes(self):
        g=Guest(control=True)
        try:
            # A control message encoded as browser Ethernet cannot update ACL.
            payload=control_snapshot(1,[('8.8.4.4',5150,int(time.time())+30)])
            g.send(payload)
            g.arp()
            os.close(g.control);g.control=-1
            g.p.wait(timeout=2);self.assertEqual(g.p.returncode,4)
        finally:g.close()

    def test_control_replay_oversize_and_host_alias_rejected(self):
        now=int(time.time())
        for messages in ((control_snapshot(1,[]),control_snapshot(1,[])),
                         (b'\x01\x07',),
                         (control_snapshot(1,[('127.0.0.1',22,now+30)]),)):
            g=Guest(control=True)
            try:
                for message in messages:os.write(g.control,message)
                g.p.wait(timeout=2);self.assertEqual(g.p.returncode,4)
            finally:g.close()

    def test_row_removal_keeps_replies_of_established_flow(self):
        address=subprocess.check_output(['hostname','-I'],text=True).split()[0]
        endpoint=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);endpoint.bind((address,0))
        endpoint.settimeout(1);port=endpoint.getsockname()[1];g=Guest(control=True)
        try:
            fcntl.fcntl(g.p.stdout.fileno(),fcntl.F_SETPIPE_SZ,4096)
            g.arp();os.write(g.control,control_snapshot(1,[(address,port,int(time.time())+30)]));time.sleep(.03)
            g.send(udp(g.addr,address,5151,port,b'open-flow'));_,peer=endpoint.recvfrom(2048)
            size=1400
            for _ in range(100):endpoint.sendto(b'x'*size,peer)
            time.sleep(.15)
            os.write(g.control,control_snapshot(2,[]));time.sleep(.1)
            received=0
            while True:
                try:
                    g.recv(lambda f:f[12:14]==b'\x08\x00' and f[23]==17,timeout=.15);received+=1
                except TimeoutError:break
            # Bytes already emitted before revocation cannot be recalled; queued
            # helper frames must not be delivered after pipe space becomes free.
            capacity=fcntl.fcntl(g.p.stdout.fileno(),fcntl.F_GETPIPE_SZ)
            self.assertGreater(received,0)
            self.assertGreater(received,capacity//(size+14+20+8+2))
        finally:g.close();endpoint.close()


if __name__=='__main__':unittest.main()
