"""Real libslirp Ethernet fixtures. No emulator, game, WAN or privileged interface."""
import os
import select
import socket
import struct
import subprocess
import time
import unittest

BIN = os.environ['HALO_GATEWAY_BINARY']
MAC = bytes.fromhex('0c0a0f0e0000')
ip = socket.inet_aton
u16 = lambda b: struct.unpack('!H', b)[0]
udp_payload = lambda f: f[42:34+u16(f[38:40])]


def checksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 65535) + (s >> 16)
    return (~s) & 65535


def packet(src, dst, proto, data, mac=MAC, frag=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(data), 1, frag, 64, proto, 0, ip(src), ip(dst))
    h = h[:10] + struct.pack('!H', checksum(h)) + h[12:]
    return b'\xff'*6 + mac + b'\x08\x00' + h + data


def udp(src, dst, sport, dport, data=b'fixture', **kw):
    return packet(src, dst, 17, struct.pack('!HHHH', sport, dport, len(data)+8, 0)+data, **kw)


def tcp(src, dst, sport, dport, seq, ack, flags, data=b''):
    h = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 32768, 0, 0)+data
    pseudo = ip(src)+ip(dst)+struct.pack('!BBH', 0, 6, len(h))
    h = h[:16]+struct.pack('!H', checksum(pseudo+h))+h[18:]
    return packet(src, dst, 6, h)


class Guest:
    def __init__(self, mode='peer', lease=1, dest=None, port=25150, seconds=30, directory=None, control=False,host_bind=None):
        self.addr, self.router = f'10.77.{lease}.15', f'10.77.{lease}.2'
        args=[BIN, mode, str(lease), dest or self.router, str(port), str(seconds)]
        if directory:
            args.extend(directory)
        self.control=-1;read_fd=-1;env=os.environ.copy()
        if host_bind:env['HALO_GATEWAY_HOST_BIND_IP']=host_bind
        if control:
            read_fd,self.control=os.pipe();env['HALO_GATEWAY_CONTROL_FD']=str(read_fd)
        try:
            self.p = subprocess.Popen(args,stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env=env,pass_fds=(read_fd,) if read_fd>=0 else ())
        finally:
            if read_fd>=0:os.close(read_fd)
        self.buf = b''
        line = self.p.stderr.readline()
        if not line.startswith(b'READY'):
            self.p.wait()
            raise RuntimeError(line)

    def send(self, b):
        self.p.stdin.write(struct.pack('!H', len(b))+b)
        self.p.stdin.flush()

    def recv(self, predicate=lambda f: True, timeout=2):
        until = time.monotonic()+timeout
        while time.monotonic() < until:
            if len(self.buf) >= 2 and len(self.buf) >= 2+u16(self.buf[:2]):
                n = u16(self.buf[:2]); f, self.buf = self.buf[2:n+2], self.buf[n+2:]
                if f[12:14] == b'\x08\x06' and u16(f[20:22]) == 1:
                    # Reply to stack ARP query; still return frame to ARP fixtures.
                    self.send(f[6:12]+MAC+b'\x08\x06'+struct.pack('!HHBBH',1,0x800,6,4,2)+
                              MAC+ip(self.addr)+f[22:28]+f[28:32])
                if predicate(f):
                    return f
                continue
            ready, _, _ = select.select([self.p.stdout], [], [], max(0, until-time.monotonic()))
            if ready:
                chunk = os.read(self.p.stdout.fileno(), 65536)
                if not chunk:
                    raise RuntimeError('helper exited')
                self.buf += chunk
        raise TimeoutError('no matching Ethernet frame')

    def arp(self):
        self.send(b'\xff'*6+MAC+b'\x08\x06'+struct.pack('!HHBBH',1,0x800,6,4,1)+
                  MAC+ip(self.addr)+b'\0'*6+ip(self.router))
        return self.recv(lambda f: f[12:14]==b'\x08\x06' and u16(f[20:22])==2)

    def close(self):
        if not self.p.stdin.closed:
            self.p.stdin.close()
        self.p.wait(timeout=3)
        if self.control>=0:os.close(self.control);self.control=-1
        log = self.p.stderr.read().decode()
        print(log.strip())
        self.p.stdout.close(); self.p.stderr.close()
        return log


class GatewayTests(unittest.TestCase):
    def test_arp_and_dhcp(self):
        g=Guest()
        try:
            self.assertEqual(g.arp()[28:32],ip(g.router))
            boot=bytearray(240)
            boot[:4]=bytes([1,1,6,0]); boot[4:8]=b'ABCD'; boot[28:34]=MAC
            boot[236:240]=bytes([99,130,83,99])
            boot+=bytes([53,1,1,255])
            g.send(udp('0.0.0.0','255.255.255.255',68,67,boot))
            f=g.recv(lambda f:f[12:14]==b'\x08\x00' and f[23]==17 and u16(f[36:38])==68)
            self.assertEqual(f[58:62],ip(g.addr))
        finally:g.close()

    def test_two_stack_udp_host_reply_and_cleanup(self):
        probe=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);probe.bind(('127.0.0.1',0))
        port=probe.getsockname()[1];probe.close()
        a=Guest('host',1,port=port);b=Guest('peer',2,port=port)
        try:
            a.arp();b.arp()
            b.send(udp(b.addr,b.router,5151,port,b'peer-to-host'))
            f=a.recv(lambda f:f[12:14]==b'\x08\x00' and f[23]==17)
            self.assertEqual(udp_payload(f),b'peer-to-host')
            a.send(udp(a.addr,socket.inet_ntoa(f[26:30]),5150,u16(f[34:36]),b'host-reply'))
            answer=b.recv(lambda f:f[12:14]==b'\x08\x00' and f[23]==17)
            self.assertEqual(udp_payload(answer),b'host-reply')
        finally:a.close();b.close()
        check=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        check.bind(('127.0.0.1',port));check.close()

    def test_native_tcp_udp_same_explicit_endpoint(self):
        # Bind only this machine's actual private interface, selected by operator fixture.
        address=subprocess.check_output(['hostname','-I'],text=True).split()[0]
        listener=socket.socket();listener.bind((address,0));listener.listen();listener.settimeout(2)
        port=listener.getsockname()[1]
        datagram=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);datagram.bind((address,port));datagram.settimeout(2)
        g=Guest('native',3,address,port)
        try:
            g.arp();g.send(udp(g.addr,address,5151,port,b'native-udp'))
            data,peer=datagram.recvfrom(2048);self.assertEqual(data,b'native-udp')
            datagram.sendto(b'udp-reply',peer)
            self.assertEqual(udp_payload(g.recv(lambda f:f[12:14]==b'\x08\x00' and f[23]==17)),b'udp-reply')
            g.send(tcp(g.addr,address,5152,port,100,0,2))
            conn,_=listener.accept();conn.settimeout(2)
            syn=g.recv(lambda f:f[12:14]==b'\x08\x00' and f[23]==6 and f[47]&0x12==0x12)
            server_seq=struct.unpack('!I',syn[38:42])[0]
            g.send(tcp(g.addr,address,5152,port,101,server_seq+1,0x18,b'native-tcp'))
            self.assertEqual(conn.recv(2048),b'native-tcp')
            conn.sendall(b'tcp-reply')
            reply=g.recv(lambda f:f[12:14]==b'\x08\x00' and f[23]==6 and b'tcp-reply' in f)
            self.assertIn(b'tcp-reply',reply);conn.close()
        finally:g.close();listener.close();datagram.close()

    def test_fixed_interface_host_forward_roundtrip(self):
        address=subprocess.check_output(['hostname','-I'],text=True).split()[0]
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
            probe.bind((address,0));port=probe.getsockname()[1]
        a=Guest('host',1,port=port,host_bind=address);b=Guest('peer',2,address,port)
        try:
            a.arp();b.arp();b.send(udp(b.addr,address,5151,port,b'fixed-host'))
            f=a.recv(lambda f:f[12:14]==b'\x08\x00' and f[23]==17)
            self.assertEqual(udp_payload(f),b'fixed-host')
            a.send(udp(a.addr,socket.inet_ntoa(f[26:30]),5150,u16(f[34:36]),b'fixed-reply'))
            self.assertEqual(udp_payload(b.recv(lambda f:f[12:14]==b'\x08\x00' and f[23]==17)),b'fixed-reply')
        finally:a.close();b.close()

    def test_refusals(self):
        g=Guest()
        for f in [udp(g.addr,'127.0.0.1',5151,22),udp(g.addr,g.router,5151,22),
                  udp('10.77.1.99',g.router,5151,25150),udp(g.addr,g.router,5151,25150,mac=b'\0'*6),
                  udp(g.addr,g.router,5151,25150,frag=0x2000),
                  tcp(g.addr,g.router,5152,25150,1,0,2),b'\xff'*6+MAC+b'\x86\xdd'+b'\0'*40]:
            g.send(f)
        time.sleep(.1)
        log=g.close();self.assertIn('refused=7',log);self.assertIn('accepted=0',log)

    def test_malformed_ipc_and_lease_expiry(self):
        g=Guest();g.p.stdin.write(b'\xff\xff');g.p.stdin.flush()
        g.p.wait(timeout=2);self.assertEqual(g.p.returncode,4);g.close()
        g=Guest(seconds=1);g.p.wait(timeout=2);self.assertEqual(g.p.returncode,0);g.close()


if __name__=='__main__':unittest.main()
