"""Loopback-only authenticated lease/WS adapter. TLS and tester auth live upstream.

No arbitrary destination request API. Configure one private two-browser room OR
one numeric native-game endpoint in the trusted launcher environment.
"""
import asyncio
import base64
import collections
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import struct
import time
from dataclasses import dataclass
from directory_catalog import CatalogVerifier, control_snapshot, fetch_catalog_async, strict_object
from enrollment_policy import EnrollmentPolicy, GuardedEnrollment
from enrollment import EnrollmentRelay, EnrollmentError

PREFIX = '/api/guest-network'
MAX_FRAME = 1514
MAX_HTTP = 8192
MAX_LEASE_SECONDS = 600
MAX_LEASES = int(os.environ.get('HALO_GATEWAY_MAX_LEASES','4'))
if not 2<=MAX_LEASES<=250:
    raise ValueError('HALO_GATEWAY_MAX_LEASES must be 2..250')
LEASES_PER_CLIENT = int(os.environ.get('HALO_GATEWAY_LEASES_PER_CLIENT','2'))
LEASE_RATE = int(os.environ.get('HALO_GATEWAY_LEASE_RATE','10'))  # New leases per client per minute.
if LEASES_PER_CLIENT<1 or LEASE_RATE<1:
    raise ValueError('lease limits must be positive')
CLIENT_RATES = 4096
HEARTBEAT_SECONDS = 25
HELPER_CAP_SECONDS = 3600  # gateway.c refuses more; a renewed lease cannot outlive its helper.
COUNTER_ROWS = 64
COUNTER_FILE_BYTES = 64*1024
# Sanitized close codes. First cause survives cleanup. No addresses, identities or payloads.
CLOSE_REASONS = {'none':0,'client_close':1,'client_disconnect':2,'helper_exit':3,'expiry':4,
                 'delete':5,'protocol_error':6,'send_timeout':7,'shutdown':8,'control_failure':9,'host_closed':10}


def now_ms():
    return int(time.time()*1000)


def unmask(raw,mask):
    # One big-int XOR in C. A per-byte Python loop on full frames at the frame cap would stall every other lease on this event loop (S3-23).
    n=len(raw)
    repeated=(mask*(n//4+1))[:n]
    return (int.from_bytes(raw,'little')^int.from_bytes(repeated,'little')).to_bytes(n,'little')


class ClientLimit(Exception):
    pass


@dataclass
class Lease:
    token: str
    session: str
    expires: int
    index: int
    mode: str
    port: int
    process: object
    socket: object = None
    heartbeat_pings: int = 0
    heartbeat_pongs: int = 0
    consumed: bool = False
    closing: bool = False
    native_host: str = None
    client: str = None
    control_fd: int = -1
    control_generation: int = 0
    advertised_endpoint: object = None
    helper_end: int = 0
    session_expires: int = 0
    ordinal: int = 0
    created_ms: int = 0
    opened_ms: int = 0
    closed_ms: int = 0
    close_reason: str = 'none'
    renewals: int = 0
    browser_frames: int = 0
    browser_bytes: int = 0
    helper_frames: int = 0
    helper_bytes: int = 0
    helper_stop: object = None
    test_destination_active: bool = False

    def counters(self):
        # Fixed numeric/enum fields only: this row may leave the machine.
        return dict(schema=1,lease=self.ordinal,role=self.mode,connections=1 if self.opened_ms else 0,
                    open_after_ms=self.opened_ms-self.created_ms if self.opened_ms else None,
                    connected_ms=self.closed_ms-self.opened_ms if self.opened_ms else 0,
                    lifetime_ms=self.closed_ms-self.created_ms,closed_ms=self.closed_ms,
                    close_reason=self.close_reason,close_code=CLOSE_REASONS[self.close_reason],
                    to_gateway_frames=self.browser_frames,to_gateway_bytes=self.browser_bytes,
                    to_browser_frames=self.helper_frames,to_browser_bytes=self.helper_bytes,
                    heartbeat_pings=self.heartbeat_pings,heartbeat_pongs=self.heartbeat_pongs,
                    renewals=self.renewals,test_destination=self.test_destination_active,helper=self.helper_stop)

    def public(self):
        router = f'10.77.{self.index}.2'
        return dict(lease=self.token, expiresAt=self.expires, guestIPv4=f'10.77.{self.index}.15',
                    routerIPv4=router, netmask='255.255.255.0', mode='native' if self.mode=='native' else 'dce',
                    role=self.mode,
                    advertisedEndpoint=self.advertised_endpoint,
                    joinEndpoint=(dict(host=self.native_host or router, port=self.port)
                                  if self.mode in ('peer','native') else None),
                    websocketPath=f'{PREFIX}/{self.token}')


class GatewayServer:
    def __init__(self, binary, secret, mode='room', native_host=None, native_port=5150,
                 directory_host=None, directory_ip=None, directory_verify_key=None,
                 directory_private_lan_cidrs=(),game_host=None,enrollment=None,test_destination=None):
        if len(secret) < 32:
            raise ValueError('bridge secret must contain at least 32 characters')
        if mode not in ('room', 'native'):
            raise ValueError('mode must be room or native')
        if mode == 'native':
            addr = ipaddress.IPv4Address(native_host)
            if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
                raise ValueError('native endpoint must be explicit unicast')
        self.binary, self.secret, self.mode = binary, secret, mode
        self.native_host, self.native_port = native_host, native_port
        self.game_host=None
        if game_host:
            if mode!='room' or len(game_host)!=4 or any(value is None for value in game_host):
                raise ValueError('host_mapping_requires_all_four_pins_in_room_mode')
            bind_ip,bind_port,advertised_ip,advertised_port=game_host
            for value in (bind_ip,advertised_ip):
                address=ipaddress.IPv4Address(value)
                if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved or address in ipaddress.IPv4Network('10.77.0.0/16'):
                    raise ValueError('host_mapping_requires_unicast_non_guest_addresses')
            bind_port=int(bind_port);advertised_port=int(advertised_port)
            if not 1<=bind_port<=65535 or not 1<=advertised_port<=65535:
                raise ValueError('invalid_host_mapping_port')
            self.game_host=(bind_ip,bind_port,advertised_ip,advertised_port)
        self.directory = None
        if any((directory_host,directory_ip,directory_verify_key)):
            if (not directory_host or len(directory_host)>253 or
                not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+',directory_host) or
                any(len(label)>63 for label in directory_host.split('.')) or
                not directory_verify_key or not re.fullmatch('[0-9a-f]{64}',directory_verify_key)):
                raise ValueError('directory requires fixed hostname, IPv4 and separate pinned public key')
            addr=ipaddress.IPv4Address(directory_ip)
            if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified or addr in ipaddress.IPv4Network('10.77.0.0/16'):
                raise ValueError('directory IPv4 must be explicit unicast outside guest network')
            # Public signing key is a configuration pin, verified by the guest client;
            # forwarding encrypted TLS does not verify signed application responses.
            self.directory=(directory_host,str(addr),directory_verify_key)
        self.verifier=CatalogVerifier(directory_verify_key,directory_private_lan_cidrs) if self.directory else None
        self.enrollment=enrollment
        if enrollment and self.directory and enrollment.master_public[8:]!=directory_verify_key:
            raise ValueError('enrollment master must match configured DCE directory master')
        self.test_destination=None
        if test_destination:
            # Launcher environment only. No request or browser field reaches this.
            if not self.directory:
                raise ValueError('test_destination_requires_directory')
            host,_,port=test_destination.partition(':')
            address=ipaddress.IPv4Address(host);port=int(port)
            if (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or
                address.is_reserved or address in ipaddress.IPv4Network('10.77.0.0/16') or not 1024<=port<=65535):
                raise ValueError('invalid_test_destination')
            self.test_destination=(str(address),port)
        self.catalog=[]
        self.catalog_time=0
        self.catalog_task=None
        self.leases = {}
        self.client_rates = {}
        self.lock = asyncio.Lock()
        self.tasks = set()
        self.connections = 0
        self.ordinal = 0
        self.counter_rows = collections.deque(maxlen=COUNTER_ROWS)
        self.counter_file = os.environ.get('HALO_GATEWAY_COUNTERS_FILE')

    def record_counters(self, lease):
        row=lease.counters()
        self.counter_rows.append(row)
        if not self.counter_file:
            return
        # Observability never breaks networking. Bounded: current file plus one rotated copy.
        try:
            if os.path.exists(self.counter_file) and os.path.getsize(self.counter_file)>=COUNTER_FILE_BYTES:
                os.replace(self.counter_file,self.counter_file+'.1')
            with open(self.counter_file,'a',encoding='ascii') as out:
                out.write(json.dumps(row,separators=(',',':'))+'\n')
        except OSError:
            pass

    def task(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    async def close_lease(self, lease, reason='none'):
        if lease.close_reason=='none':
            lease.close_reason=reason
        if lease.closing:
            return
        lease.closing = True
        lease.closed_ms = now_ms()
        self.leases.pop(lease.token, None)
        if lease.mode == 'host':
            for other in list(self.leases.values()):
                if other.mode == 'peer':
                    await self.close_lease(other,'host_closed')
        if lease.socket:
            lease.socket.close()
        process = lease.process
        if process.stdin:
            process.stdin.close()
        # Stdin first: control EOF is a helper failure, a normal close must not report one.
        try:
            await asyncio.wait_for(process.wait(), 2)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
        if lease.control_fd>=0:
            os.close(lease.control_fd)
            lease.control_fd=-1

    def endpoints_for(self,lease,endpoints):
        if self.test_destination and lease.mode=='guest' and self.test_destination not in [(h,p) for h,p,_ in endpoints]:
            return [*endpoints,(*self.test_destination,int(time.time())+90)]
        return endpoints

    async def update_catalog(self,endpoints):
        self.catalog=endpoints
        for lease in list(self.leases.values()):
            if lease.control_fd<0 or lease.closing:
                continue
            try:
                lease.control_generation+=1
                message=control_snapshot(lease.control_generation,self.endpoints_for(lease,endpoints))
                if os.write(lease.control_fd,message)!=len(message):
                    raise OSError('incomplete_control_write')
            except (OSError,ValueError):
                await self.close_lease(lease,'control_failure')

    async def refresh_catalog_once(self):
        try:
            body,headers=await fetch_catalog_async(*self.directory[:2])
        except (OSError,ValueError,asyncio.TimeoutError):
            # No answer is not a verdict: verified rows stand until their signed expiry.
            return
        try:
            endpoints=self.verifier.verify(body,headers)
            stamp=int(headers['Signature-Time'])
            if stamp<self.catalog_time:
                raise ValueError('catalog_time_rollback')
            self.catalog_time=stamp
            await self.update_catalog(endpoints)
        except (OSError,ValueError,asyncio.TimeoutError):
            await self.update_catalog([])

    async def refresh_catalog(self):
        try:
            while self.leases:
                await self.refresh_catalog_once()
                await asyncio.sleep(10)
        finally:
            self.catalog_task=None

    async def watch(self, lease):
        # Helper stderr contains metadata counters only. Never forward auth/packets.
        async def read_log():
            while line:=await lease.process.stderr.readline():
                match=re.match(rb'STOP accepted=(\d+) refused=(\d+) sent=(\d+) dropped=(\d+) maxrss_kib=(\d+) failed=(\d+)',line)
                if match:
                    lease.helper_stop=dict(zip(('accepted','refused','sent','dropped','maxrss_kib','failed'),map(int,match.groups())))
        log = asyncio.create_task(read_log())
        reason='helper_exit'
        try:
            # Renewal moves lease.expires; re-read it rather than trust the first deadline.
            while True:
                try:
                    await asyncio.wait_for(asyncio.shield(lease.process.wait()), max(.001,(lease.expires-now_ms())/1000))
                    break
                except asyncio.TimeoutError:
                    if now_ms()>=lease.expires:
                        reason='expiry'
                        break
        finally:
            await self.close_lease(lease,reason)
            await log
            self.record_counters(lease)

    def renew(self, lease, session_expiry):
        # A fresh grant of the same bounded TTL; never past session or helper lifetime.
        target=min(now_ms()+MAX_LEASE_SECONDS*1000,session_expiry,lease.helper_end)
        if target>lease.expires:
            lease.expires=target
            lease.renewals=min(1000,lease.renewals+1)
        return lease

    def client_allowed(self, client):
        """Per client: leases held and new leases a minute. The tag comes from the Worker; absent, the session stands in."""
        if sum(lease.client==client for lease in self.leases.values())>=LEASES_PER_CLIENT:
            return False
        now=time.monotonic()
        times=self.client_rates.get(client)
        if times is None:
            if len(self.client_rates)>=CLIENT_RATES:
                self.client_rates={k:v for k,v in self.client_rates.items() if v and v[-1]>now-60}
                if len(self.client_rates)>=CLIENT_RATES:
                    return False
            times=self.client_rates[client]=collections.deque()
        while times and times[0]<=now-60:
            times.popleft()
        if len(times)>=LEASE_RATE:
            return False
        times.append(now)
        return True

    async def create(self, session, expiry, role=None, client=None):
        async with self.lock:
            for lease in self.leases.values():
                if lease.session == session:
                    if (role=='host')!=(lease.mode=='host') and role is not None:
                        raise ValueError('role_conflict')
                    return lease
            client=client or session
            if not self.client_allowed(client):
                raise ClientLimit('client_limit')
            if len(self.leases) >= MAX_LEASES:
                raise ValueError('room_full')
            used={lease.index for lease in self.leases.values()}
            index = next(i for i in range(1,251) if i not in used)
            hosted=any(lease.mode=='host' for lease in self.leases.values())
            relayed=bool(self.directory and os.environ.get('HALO_GATEWAY_RELAY'))
            if self.mode=='native':
                mode='native'
            elif role=='host':
                # Through the relay a host needs no shared address, so hosts do not collide.
                if hosted and not relayed:
                    raise ValueError('host_taken')
                mode='host'
            elif role=='join':
                # A room's host is reachable as before; otherwise only signed catalog hosts.
                if not hosted and not self.directory:
                    raise ValueError('guest_unavailable')
                mode='peer' if hosted and not relayed else 'guest'
            else:
                mode='host' if not self.leases else 'guest' if relayed else 'peer'
            if mode == 'host':
                # Bind is checked again by libslirp; a race fails lease creation.
                if self.game_host:
                    port=self.game_host[1]
                else:
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                        probe.bind(('127.0.0.1',0)); port = probe.getsockname()[1]
            elif mode == 'peer':
                host = next((l for l in self.leases.values() if l.mode == 'host'), None)
                if not host:
                    raise ValueError('host_unavailable')
                port = host.port
            elif mode == 'guest':
                port = 1  # Helper refuses all but catalog tuples; this is never a destination.
            else:
                port = self.native_port
            dest = self.native_host if mode == 'native' else f'10.77.{index}.2'
            if mode=='peer' and self.game_host:
                dest=self.game_host[0]
            created=now_ms()
            lease_expiry=min(expiry,created+MAX_LEASE_SECONDS*1000)
            helper_end=min(expiry,created+HELPER_CAP_SECONDS*1000)
            if mode=='peer':
                lease_expiry=min(lease_expiry,host.expires)
                helper_end=min(helper_end,host.helper_end)
            ttl = max(1,(helper_end-created)//1000)
            args=[self.binary,mode,str(index),dest,str(port),str(ttl)]
            if self.directory:
                args.extend(self.directory[:2])
            control_read,control_write=(-1,-1)
            child_env={'LANG':'C','PATH':'/usr/bin:/bin'}
            if mode=='host' and self.game_host:
                child_env['HALO_GATEWAY_HOST_BIND_IP']=self.game_host[0]
            if self.directory:
                control_read,control_write=os.pipe()
                os.set_blocking(control_write,False)
                child_env['HALO_GATEWAY_CONTROL_FD']=str(control_read)
            if os.environ.get('HALO_GATEWAY_ROUTE_ALLOW'):
                child_env['HALO_GATEWAY_ROUTE_ALLOW']=os.environ['HALO_GATEWAY_ROUTE_ALLOW']
            if os.environ.get('HALO_GATEWAY_RELAY'):
                child_env['HALO_GATEWAY_RELAY']=os.environ['HALO_GATEWAY_RELAY']
            try:
                process = await asyncio.create_subprocess_exec(*args,
                    stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,
                    limit=24*1024, env=child_env,pass_fds=(control_read,) if control_read>=0 else ())
            except BaseException:
                if control_write>=0:
                    os.close(control_write)
                raise
            finally:
                if control_read>=0:
                    os.close(control_read)
            try:
                line = await asyncio.wait_for(process.stderr.readline(),2)
                if not line.startswith(b'READY '):
                    raise ValueError('helper_unavailable')
            except BaseException:
                if control_write>=0:
                    os.close(control_write)
                if process.returncode is None:
                    process.kill()
                await process.wait()
                raise
            lease = Lease(secrets.token_urlsafe(32),session,lease_expiry,index,mode,port,process)
            lease.helper_end=helper_end
            lease.test_destination_active=bool(self.test_destination and mode=='guest')
            if lease.test_destination_active:
                print(f'TEST DESTINATION ACTIVE lease={self.ordinal+1}',flush=True)
            self.ordinal+=1
            lease.ordinal=self.ordinal
            lease.created_ms=created
            lease.native_host = self.native_host
            lease.client = client
            if mode=='host' and self.game_host:
                lease.advertised_endpoint=dict(host=self.game_host[2],port=self.game_host[3])
            if mode=='peer' and self.game_host:
                # Peer joins directly to this host interface, not loopback alias.
                lease.native_host=self.game_host[0]
            lease.control_fd=control_write
            self.leases[lease.token] = lease
            if self.directory:
                lease.control_generation=1
                try:
                    message=control_snapshot(1,self.endpoints_for(lease,self.catalog))
                    if os.write(control_write,message)!=len(message):
                        raise OSError('incomplete_control_write')
                except (OSError,ValueError):
                    await self.close_lease(lease,'control_failure')
                    raise ValueError('control_unavailable')
                if self.catalog_task is None:
                    self.catalog_task=self.task(self.refresh_catalog())
            self.task(self.watch(lease))
            return lease

    async def response(self, writer, status, value):
        data = b'' if status.startswith('204 ') else json.dumps(value,separators=(',',':')).encode()
        writer.write(f'HTTP/1.1 {status}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {len(data)}\r\n\r\n'.encode()+data)
        await asyncio.wait_for(writer.drain(),1)

    async def heartbeat(self, lease, send, *, sleep=asyncio.sleep, clock=now_ms):
        # RFC6455 control traffic only: never inject Ethernet or extend a lease.
        while not lease.closing:
            await sleep(HEARTBEAT_SECONDS)
            if lease.closing or clock() >= lease.expires:
                return
            await send(b'', 9)
            lease.heartbeat_pings = min(24, lease.heartbeat_pings + 1)

    async def websocket(self, reader, writer, lease, headers):
        key = headers.get('sec-websocket-key','')
        try:
            if len(base64.b64decode(key,validate=True)) != 16:
                raise ValueError()
        except ValueError:
            await self.response(writer,'400 Bad Request',{'error':'bad_websocket'})
            return
        if (headers.get('sec-websocket-version') != '13' or
            'upgrade' not in [p.strip().lower() for p in headers.get('connection','').split(',')] or
            lease.consumed or lease.closing):
            await self.response(writer,'409 Conflict',{'error':'bridge_unavailable'})
            return
        lease.consumed = True
        lease.socket = writer
        lease.opened_ms = now_ms()
        accept = base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        writer.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+b'\r\n\r\n')
        await writer.drain()
        writer.transport.set_write_buffer_limits(high=48*1024,low=16*1024)
        lease.process.stdin.transport.set_write_buffer_limits(high=48*1024,low=16*1024)
        send_lock = asyncio.Lock()

        async def ws_send(payload,opcode=2):
            async with send_lock:
                n=len(payload)
                head=bytes([0x80|opcode,n]) if n<126 else bytes([0x80|opcode,126])+struct.pack('!H',n)
                writer.write(head+payload)
                await asyncio.wait_for(writer.drain(),1)

        async def from_browser():
            epoch=time.monotonic(); count=0
            while not lease.closing:
                a,b=await reader.readexactly(2)
                opcode=a&15; n=b&127
                if a&0x70 or not a&0x80 or not b&0x80 or opcode not in (2,8,9,10) or n==127:
                    raise ValueError('invalid_ws_frame')
                if n==126:
                    n=struct.unpack('!H',await asyncio.wait_for(reader.readexactly(2),1))[0]
                    if n<126:
                        raise ValueError('noncanonical_ws_length')
                if n>MAX_FRAME or (opcode!=2 and n>125) or (opcode==2 and n<14):
                    raise ValueError('invalid_ws_size')
                mask=await asyncio.wait_for(reader.readexactly(4),1)
                raw=await asyncio.wait_for(reader.readexactly(n),1)
                payload=unmask(raw,mask)
                now=time.monotonic()
                if now-epoch>=1:
                    epoch,count=now,0
                count+=1
                if count>1000:
                    raise ValueError('rate_limit')
                if opcode==8:
                    if n==1:
                        raise ValueError('bad_close')
                    await ws_send(b'',8)
                    return
                if opcode==9:
                    await ws_send(payload,10)
                elif opcode==10:
                    # Bounded received-control counter, not proof of a matching Ping.
                    lease.heartbeat_pongs = min(24, lease.heartbeat_pongs + 1)
                elif opcode==2:
                    if payload[12:14] not in (b'\x08\x00',b'\x08\x06'):
                        raise ValueError('unsupported_ethernet')
                    lease.browser_frames+=1
                    lease.browser_bytes+=n
                    lease.process.stdin.write(struct.pack('!H',n)+payload)
                    await asyncio.wait_for(lease.process.stdin.drain(),1)

        async def to_browser():
            while not lease.closing:
                prefix=await lease.process.stdout.readexactly(2)
                n=struct.unpack('!H',prefix)[0]
                if not 14<=n<=MAX_FRAME:
                    raise ValueError('invalid_helper_frame')
                payload=await asyncio.wait_for(lease.process.stdout.readexactly(n),1)
                lease.helper_frames+=1
                lease.helper_bytes+=n
                await ws_send(payload)

        tasks=[asyncio.create_task(from_browser()),asyncio.create_task(to_browser()),
               asyncio.create_task(self.heartbeat(lease, ws_send))]
        try:
            done,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
            reason=self.ws_close_reason(tasks,done)
        except BaseException:
            reason='shutdown'
            raise
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
            await self.close_lease(lease,reason)

    @staticmethod
    def ws_close_reason(tasks,done):
        for index,task in enumerate(tasks):
            if task not in done or task.cancelled():
                continue
            error=task.exception()
            if error is None:
                return 'client_close' if index==0 else 'expiry'
            if isinstance(error,asyncio.TimeoutError):
                return 'send_timeout'
            if isinstance(error,ValueError):
                return 'protocol_error'
            return ('client_disconnect','helper_exit','send_timeout')[index]
        return 'none'

    async def handle(self, reader, writer):
        if self.connections>=16:
            writer.close()
            return
        self.connections+=1
        # This cap is for HTTP requests. A live socket leaves it at the upgrade: lease.consumed and MAX_LEASES already bound those,
        # and a full room must still renew (S2-7).
        counted=True
        try:
            raw=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),3)
            if len(raw)>MAX_HTTP:
                raise ValueError('header_too_large')
            lines=raw.decode('ascii').split('\r\n')
            method,path,version=lines[0].split(' ')
            headers={}
            for line in lines[1:]:
                if not line:
                    continue
                name,value=line.split(':',1);name=name.lower()
                if name in headers or not re.fullmatch(r'[a-z0-9-]+',name):
                    raise ValueError('invalid_header')
                headers[name]=value.strip()
            session=headers.get('x-halo-session','')
            if (not hmac.compare_digest(headers.get('x-halo-bridge-key',''),self.secret) or
                not re.fullmatch('[0-9a-f]{64}',session)):
                await self.response(writer,'403 Forbidden',{'error':'forbidden'});return
            expiry=int(headers.get('x-halo-session-expires','0'))
            if expiry<=now_ms()+1000:
                await self.response(writer,'403 Forbidden',{'error':'session_expired'});return
            if version!='HTTP/1.1' or headers.get('transfer-encoding'):
                raise ValueError('unsupported_http_framing')
            enrollment=re.fullmatch(r'/api/device-enrollment/(config|challenge|register)',path)
            if enrollment:
                if method!='POST' or headers.get('upgrade'):
                    await self.response(writer,'405 Method Not Allowed',{'error':'method'});return
                if self.enrollment is None:
                    await self.response(writer,'503 Service Unavailable',{'error':'enrollment_unavailable'});return
                length=headers.get('content-length','0')
                if not re.fullmatch('[0-9]{1,3}',length) or int(length)>512:
                    raise ValueError('invalid_enrollment_size')
                action=enrollment[1]
                raw=await asyncio.wait_for(reader.readexactly(int(length)),1)
                body=None
                if action=='config':
                    if raw:raise ValueError('empty_body_required')
                else:
                    if headers.get('content-type','').split(';')[0].strip().lower()!='application/json':
                        raise ValueError('json_required')
                    body=json.loads(raw.decode('utf-8'),object_pairs_hook=strict_object)
                client=headers.get('x-halo-client')
                if client is not None and not re.fullmatch('[0-9a-f]{32}',client):
                    raise ValueError('invalid_client')
                operation=asyncio.create_task(self.enrollment.handle(action,session,expiry,body,client=client))
                disconnected=asyncio.create_task(reader.read(1))
                try:
                    done,_=await asyncio.wait((operation,disconnected),return_when=asyncio.FIRST_COMPLETED)
                    if disconnected in done:
                        return
                    try:
                        value=operation.result()
                        await self.response(writer,'200 OK',value)
                    except EnrollmentError as exc:
                        reasons={400:'Bad Request',403:'Forbidden',409:'Conflict',429:'Too Many Requests',
                                 502:'Bad Gateway',503:'Service Unavailable',504:'Gateway Timeout'}
                        await self.response(writer,f'{exc.status} {reasons[exc.status]}',{'error':'enrollment_refused'})
                finally:
                    operation.cancel();disconnected.cancel()
                    await asyncio.gather(operation,disconnected,return_exceptions=True)
                return
            if headers.get('content-length','0')!='0':
                raise ValueError('empty_body_required')
            if path==PREFIX and method=='POST':
                try:
                    role=headers.get('x-halo-guest-role')
                    if role not in (None,'host','join'):
                        raise ValueError('invalid_role')
                    client=headers.get('x-halo-client')
                    if client is not None and not re.fullmatch('[0-9a-f]{32}',client):
                        raise ValueError('invalid_role')
                    lease=await self.create(session,expiry,role,client)
                except ClientLimit as exc:
                    await self.response(writer,'429 Too Many Requests',{'error':str(exc)});return
                except ValueError as exc:
                    if str(exc)=='invalid_role':
                        raise
                    await self.response(writer,'409 Conflict',{'error':str(exc)});return
                await self.response(writer,'201 Created',lease.public());return
            match=re.fullmatch(re.escape(PREFIX)+r'/([A-Za-z0-9_-]{43})',path)
            lease=self.leases.get(match[1]) if match else None
            if not lease or lease.session!=session or lease.expires<=now_ms():
                await self.response(writer,'404 Not Found',{'error':'lease_unavailable'});return
            if method=='DELETE':
                await self.close_lease(lease,'delete')
                await self.response(writer,'204 No Content',None)
            elif method=='POST' and not headers.get('upgrade'):
                await self.response(writer,'200 OK',self.renew(lease,expiry).public())
            elif method=='GET' and headers.get('upgrade','').lower()=='websocket':
                self.connections-=1;counted=False
                await self.websocket(reader,writer,lease,headers)
            elif method=='GET':
                await self.response(writer,'200 OK',lease.public())
            else:
                await self.response(writer,'405 Method Not Allowed',{'error':'method'})
        except (ValueError,UnicodeError,asyncio.LimitOverrunError):
            try:
                await self.response(writer,'400 Bad Request',{'error':'bad_request'})
            except (ConnectionError,asyncio.TimeoutError):
                pass
        except (ConnectionError,asyncio.IncompleteReadError,asyncio.TimeoutError):
            pass
        finally:
            if counted:
                self.connections-=1
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def shutdown(self):
        for lease in list(self.leases.values()):
            await self.close_lease(lease,'shutdown')
        if self.catalog_task:
            self.catalog_task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks,return_exceptions=True)


async def main():
    host_fields=tuple(os.environ.get(key) for key in ('HALO_GAME_BIND_IPV4','HALO_GAME_BIND_PORT',
                                                      'HALO_GAME_ADVERTISED_IPV4','HALO_GAME_ADVERTISED_PORT'))
    enrollment_fields=tuple(os.environ.get(key) for key in ('HALO_ENROLLMENT_URL','HALO_ENROLLMENT_TOKEN_FILE','HALO_ENROLLMENT_MASTER_KEY'))
    enrollment=None
    if any(enrollment_fields):
        if not all(enrollment_fields):raise ValueError('all private enrollment settings required')
        url,token_path,master=enrollment_fields
        if os.stat(token_path).st_mode&0o077:raise ValueError('operator token file must be mode0600')
        with open(token_path,encoding='ascii') as token_file:token=token_file.read(130).strip()
        # An anonymous browser is not an operator: its keys go in the small public pool unless the launcher says so.
        enrollment_class=os.environ.get('HALO_ENROLLMENT_CLASS','public')
        # Browser sessions are free in public mode, 20 a minute per address: the operator's small tables would fill (S3-26).
        size=dict(sessions=1024,pending=256) if enrollment_class=='public' else {}
        enrollment=EnrollmentRelay(url,token,master,enrollment_class=enrollment_class,**size)
        if enrollment_class=='public':
            # Same refused list, caps and day total as public_enroll.py. No policy files, no public route: the page reports online setup as unavailable.
            state,revoked=os.environ.get('HALO_PUBLIC_ENROLL_STATE'),os.environ.get('HALO_PUBLIC_ENROLL_REVOKED')
            if state and revoked:
                enrollment=GuardedEnrollment(enrollment,EnrollmentPolicy(state,revoked,int(os.environ.get('HALO_PUBLIC_ENROLL_DAILY','100'))))
            else:
                enrollment=None
                print('public enrollment off: HALO_PUBLIC_ENROLL_STATE and HALO_PUBLIC_ENROLL_REVOKED not set',flush=True)
    server=GatewayServer(os.environ['HALO_GATEWAY_BINARY'],os.environ['HALO_BRIDGE_SECRET'],
        os.environ.get('HALO_GATEWAY_MODE','room'),os.environ.get('HALO_NATIVE_HOST'),
        int(os.environ.get('HALO_NATIVE_PORT','5150')),os.environ.get('HALO_DIRECTORY_HOST'),
        os.environ.get('HALO_DIRECTORY_IPV4'),os.environ.get('HALO_DIRECTORY_VERIFY_KEY'),
        tuple(filter(None,os.environ.get('HALO_DIRECTORY_PRIVATE_LAN_CIDRS','').split(','))),
        host_fields if any(host_fields) else None,enrollment,os.environ.get('HALO_GATEWAY_TEST_DESTINATION'))
    if server.test_destination:
        print('TEST DESTINATION ACTIVE: guest leases may reach one operator-set host',flush=True)
    listener=await asyncio.start_server(server.handle,'127.0.0.1',int(os.environ.get('HALO_GATEWAY_PORT','18106')),
                                       limit=MAX_HTTP,backlog=8)
    print('gateway listening on loopback; private proxy authentication required',flush=True)
    stop=asyncio.Event()
    loop=asyncio.get_running_loop()
    for sig in (signal.SIGTERM,signal.SIGINT):
        loop.add_signal_handler(sig,stop.set)
    try:
        async with listener:
            await stop.wait()
    finally:
        await server.shutdown()


if __name__=='__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
