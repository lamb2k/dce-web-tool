"""Fixed DNS and TLS SNI gate fixtures; no remote directory contacted."""
import time
import socket
import struct
import subprocess
import unittest

from test_gateway import Guest, checksum, ip, packet, tcp, udp, udp_payload

HOST='directory.fixture.invalid'
ADDRESS=subprocess.check_output(['hostname','-I'],text=True).split()[0]


def dns_query(host=HOST,flags=0x100):
    name=b''.join(bytes([len(label)])+label.encode() for label in host.split('.'))+b'\0'
    return struct.pack('!HHHHHH',0x1234,flags,1,0,0,0)+name+struct.pack('!HH',1,1)


def client_hello(host=HOST):
    name=host.encode();sni=struct.pack('!H',len(name)+3)+b'\0'+struct.pack('!H',len(name))+name
    extensions=struct.pack('!HH',0,len(sni))+sni
    body=b'\x03\x03'+bytes(32)+b'\0'+b'\0\x02\x00\x2f'+b'\x01\0'+struct.pack('!H',len(extensions))+extensions
    hello=b'\x01'+len(body).to_bytes(3,'big')+body
    return b'\x16\x03\x01'+struct.pack('!H',len(hello))+hello


class DirectoryTests(unittest.TestCase):
    def test_exact_dns_and_refusals(self):
        g=Guest(directory=(HOST,ADDRESS))
        try:
            g.arp();dns='10.77.1.3'
            g.send(udp(g.addr,dns,12001,53,dns_query()))
            f=g.recv(lambda f:f[12:14]==b'\x08\x00' and f[23]==17)
            answer=udp_payload(f)
            self.assertEqual(f[26:30],ip(dns));self.assertEqual(answer[:2],b'\x12\x34')
            self.assertEqual(answer[-4:],ip(ADDRESS));self.assertEqual(answer[6:8],b'\0\x01')
            self.assertTrue(checksum(f[14:34])==0)
            for query in (dns_query('unapproved.invalid'),dns_query(flags=0x8100),
                          dns_query()+b'\0',dns_query()[:12]+b'\xc0\x0c\0\x01\0\x01'):
                g.send(udp(g.addr,dns,12001,53,query))
            g.send(udp(g.addr,'8.8.8.8',12001,53,dns_query()))
            # Wait for all input without introducing an outbound DNS socket.
            g.arp()
        finally:
            log=g.close()
        self.assertIn('refused=5',log)

    def connect(self,g,listener,port=52001):
        g.arp();g.send(tcp(g.addr,ADDRESS,port,443,100,0,2))
        conn,_=listener.accept();conn.settimeout(.2)
        syn=g.recv(lambda f:f[12:14]==b'\x08\x00' and f[23]==6 and f[47]&0x12==0x12)
        ack=struct.unpack('!I',syn[38:42])[0]+1
        return conn,ack

    def listener(self):
        s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        # Bind fixture only to this WSL private interface, never wildcard/public.
        s.bind((ADDRESS,443));s.listen();s.settimeout(2)
        return s

    def test_split_clienthello_held_until_matching_sni(self):
        listener=self.listener();g=Guest(directory=(HOST,ADDRESS))
        try:
            conn,ack=self.connect(g,listener);hello=client_hello();split=30
            g.send(tcp(g.addr,ADDRESS,52001,443,101,ack,0x18,hello[:split]))
            with self.assertRaises(socket.timeout):conn.recv(1024)
            g.send(tcp(g.addr,ADDRESS,52001,443,101+split,ack,0x18,hello[split:]))
            conn.settimeout(2);data=conn.recv(4096)
            while len(data)<len(hello):data+=conn.recv(4096)
            self.assertEqual(data,hello)
            conn.sendall(b'fixture-return')
            g.recv(lambda f:f[12:14]==b'\x08\x00' and f[23]==6 and b'fixture-return' in f)
            conn.close()
        finally:g.close();listener.close()

    def test_wrong_sni_plaintext_and_invalid_ack_cannot_open_gate(self):
        listener=self.listener()
        try:
            for invalid in (client_hello('unapproved.invalid'),b'GET / HTTP/1.1\r\n\r\n'):
                g=Guest(directory=(HOST,ADDRESS))
                try:
                    conn,ack=self.connect(g,listener)
                    g.send(tcp(g.addr,ADDRESS,52001,443,101,ack,0x18,invalid))
                    with self.assertRaises(socket.timeout):conn.recv(4096)
                    conn.close()
                finally:g.close()
            g=Guest(directory=(HOST,ADDRESS))
            try:
                conn,ack=self.connect(g,listener)
                g.send(tcp(g.addr,ADDRESS,52001,443,101,ack+100,0x18,client_hello()))
                g.send(tcp(g.addr,ADDRESS,52001,443,101,ack,0x18,client_hello('unapproved.invalid')))
                with self.assertRaises(socket.timeout):conn.recv(4096)
                conn.close()
            finally:g.close()
        finally:listener.close()

    def test_admitted_flow_survives_a_long_crypto_pause(self):
        # Join stall: ClientKeyExchange after 30+ s of SH-4 crypto was refused for good.
        listener=self.listener();g=Guest(directory=(HOST,ADDRESS),seconds=120)
        try:
            conn,ack=self.connect(g,listener);hello=client_hello();conn.settimeout(2)
            g.send(tcp(g.addr,ADDRESS,52001,443,101,ack,0x18,hello))
            data=b''
            while len(data)<len(hello):data+=conn.recv(4096)
            time.sleep(31)
            key_exchange=bytes.fromhex('160303004610')+bytes(120)
            g.send(tcp(g.addr,ADDRESS,52001,443,101+len(hello),ack,0x18,key_exchange))
            data=b''
            while len(data)<len(key_exchange):data+=conn.recv(4096)
            self.assertEqual(data,key_exchange)
            # A quiet admitted flow gives up its slot when the table is full; new joins are never locked out.
            time.sleep(31)
            for port in range(53000,53008):
                g.send(tcp(g.addr,ADDRESS,port,443,100,0,2))
                accepted,_=listener.accept();accepted.close()
            conn.close()
        finally:log=g.close();listener.close()
        self.assertIn('refused=0',log)


if __name__=='__main__':unittest.main()
