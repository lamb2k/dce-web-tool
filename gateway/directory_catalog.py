"""Bounded master-signed DCE catalogue admission; never trusts browser targets."""
import base64
import asyncio
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import struct
import time
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BODY_MAX=32768
ENTRY_MAX=32
TTL_MAX=90
RFC1918=tuple(map(ipaddress.IPv4Network,('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')))
GUEST_NETWORK=ipaddress.IPv4Network('10.77.0.0/16')


def strict_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError('duplicate_json_key')
        result[key]=value
    return result


def integer(value,low,high):
    return type(value) is int and low<=value<=high


class CatalogVerifier:
    def __init__(self,public_hex,private_lan_cidrs=()):
        if not re.fullmatch('[0-9a-f]{64}',public_hex):
            raise ValueError('invalid_master_key')
        raw=bytes.fromhex(public_hex)
        self.key=Ed25519PublicKey.from_public_bytes(raw)
        self.key_id=hashlib.sha256(raw).hexdigest()[:16]
        self.private=[]
        for value in private_lan_cidrs:
            network=ipaddress.IPv4Network(value,strict=True)
            if not any(network.subnet_of(scope) for scope in RFC1918):
                raise ValueError('private_scope_must_be_RFC1918')
            self.private.append(network)
        if len(self.private)>4:
            raise ValueError('too_many_private_scopes')

    def signed_body(self,body,headers,now=None):
        now=int(time.time()) if now is None else now
        if not isinstance(body,bytes) or len(body)>BODY_MAX:
            raise ValueError('oversized_catalog')
        headers={k.lower():v for k,v in headers.items()}
        stamp=headers.get('signature-time','')
        signature=headers.get('signature','')
        if (headers.get('signature-key')!=self.key_id or not re.fullmatch('[0-9]{1,12}',stamp) or
            abs(int(stamp)-now)>30 or not signature.startswith('ed25519=')):
            raise ValueError('invalid_catalog_identity_or_time')
        try:
            sig=base64.b64decode(signature[8:],validate=True)
            if len(sig)!=64:
                raise ValueError('invalid_signature_length')
            self.key.verify(sig,body)
        except (InvalidSignature,ValueError) as exc:
            raise ValueError('invalid_catalog_signature') from exc
        data=json.loads(body.decode('utf-8'),object_pairs_hook=strict_object)
        if (not isinstance(data,dict) or data.get('protocol')!=1 or type(data.get('protocol')) is not int or
            data.get('family')!='dce-net' or data.get('network_version')!=4 or
            type(data.get('network_version')) is not int or data.get('ttl')!=90 or
            type(data.get('ttl')) is not int or type(data.get('truncated')) is not bool or
            not isinstance(data.get('master'),dict) or data['master'].get('key_id')!=self.key_id or
            type(data['master'].get('time')) is not int or data['master']['time']!=int(stamp) or
            not isinstance(data.get('servers'),list) or len(data['servers'])>ENTRY_MAX):
            raise ValueError('invalid_catalog_schema')
        return data

    def address_allowed(self,address):
        return (not address.is_multicast and not address.is_reserved and not address.is_loopback and
                not address.is_link_local and not address.is_unspecified and address not in GUEST_NETWORK and
                (address.is_global or any(address in scope for scope in self.private)))

    def verify(self,body,headers,now=None):
        now=int(time.time()) if now is None else now
        data=self.signed_body(body,headers,now)
        endpoints={};ids=set()
        for row in data['servers']:
            if not isinstance(row,dict):
                raise ValueError('invalid_entry')
            for field in ('id','key_id','instance'):
                if not isinstance(row.get(field),str) or not re.fullmatch('[0-9a-f]{16}',row[field]):
                    raise ValueError('invalid_entry_identity')
            if row['id'] in ids or row['id']!=hashlib.sha256((row['key_id']+row['instance']).encode()).hexdigest()[:16]:
                raise ValueError('invalid_entry_id')
            ids.add(row['id'])
            if (row.get('protocol')!=1 or type(row.get('protocol')) is not int or row.get('family')!='dce-net' or
                row.get('network_version')!=4 or type(row.get('network_version')) is not int or
                row.get('reachable') is not True or not isinstance(row.get('endpoint'),dict) or
                not integer(row.get('updated'),0,data['master']['time']) or
                not integer(row.get('expires'),0,data['master']['time']+TTL_MAX) or
                row['expires']!=row['updated']+TTL_MAX):
                raise ValueError('invalid_entry_protocol_or_expiry')
            for field,low,high in (('build',0,2**32-1),('map_crc',0,2**32-1),('map',0,255),
                                   ('sequence',1,2**32-1),('game_port',1024,65535),('players',1,2)):
                if not integer(row.get(field),low,high):
                    raise ValueError('invalid_entry_bounds')
            if (type(row.get('mode')) is not int or row['mode'] not in (0,1) or
                type(row.get('score')) is not int or row['score'] not in (10,15,25,50) or
                type(row.get('capacity')) is not int or row['capacity']!=2 or
                not isinstance(row.get('name'),str) or not re.fullmatch('[\x20-\x7e]{1,32}',row['name']) or
                row['name']!=row['name'].strip() or not integer(row.get('time'),0,2**53-1)):
                raise ValueError('invalid_entry_metadata')
            endpoint=row['endpoint'];port=endpoint.get('port')
            if not integer(port,1024,65535) or port!=row['game_port']:
                raise ValueError('invalid_endpoint_port')
            try:
                address=ipaddress.IPv4Address(endpoint.get('ip'))
            except (ipaddress.AddressValueError,TypeError) as exc:
                raise ValueError('invalid_endpoint_address') from exc
            if str(address)!=endpoint.get('ip') or not self.address_allowed(address):
                raise ValueError('blocked_endpoint')
            if row['expires']<=now:
                continue
            key=(str(address),port)
            endpoints[key]=min(endpoints.get(key,row['expires']),row['expires'])
        return [(host,port,expiry) for (host,port),expiry in sorted(endpoints.items())]


def fetch_catalog(host,pinned_ip,context=None):
    """Certificate verified for hostname; TCP connects only operator-pinned IPv4."""
    connection=http.client.HTTPSConnection(host,443,timeout=4,context=context or ssl.create_default_context())
    connection._create_connection=lambda _address,timeout,source_address=None: socket.create_connection(
        (pinned_ip,443),timeout,source_address)
    try:
        connection.request('GET','/v1/dce/servers?limit=32',headers={'Accept':'application/json',
                           'Accept-Encoding':'identity','Connection':'close'})
        response=connection.getresponse()
        if response.status!=200 or response.getheader('Content-Encoding','identity')!='identity':
            raise ValueError('catalog_http_refused')
        if response.getheader('Content-Length') and int(response.getheader('Content-Length'))>BODY_MAX:
            raise ValueError('oversized_catalog')
        headers={}
        for field in ('Signature','Signature-Key','Signature-Time'):
            values=response.headers.get_all(field,[])
            maximum={'Signature':96,'Signature-Key':16,'Signature-Time':12}[field]
            if len(values)!=1 or len(values[0])>maximum:
                raise ValueError('ambiguous_signature_header')
            headers[field]=values[0]
        body=response.read(BODY_MAX+1)
        if len(body)>BODY_MAX:
            raise ValueError('oversized_catalog')
        return body,headers
    except http.client.HTTPException as exc:
        raise ValueError('invalid_catalog_http') from exc
    finally:
        connection.close()


def control_snapshot(generation,endpoints,now=None):
    now=time.time() if now is None else now
    if not integer(generation,1,2**32-1) or len(endpoints)>ENTRY_MAX:
        raise ValueError('invalid_control_snapshot')
    entries=[]
    for host,port,expiry in endpoints:
        ttl=int(min(TTL_MAX,expiry-now))
        if ttl<=0:
            continue
        entries.append(socket.inet_aton(host)+struct.pack('!HH',port,ttl))
    data=bytes([1,len(entries)])+struct.pack('!I',generation)+b''.join(entries)
    return struct.pack('!H',len(data))+data


async def fetch_catalog_async(host,pinned_ip):
    """Killable subprocess: slow-drip TLS/HTTP cannot leave abandoned threads."""
    process=await asyncio.create_subprocess_exec(sys.executable,__file__,host,pinned_ip,
        stdin=asyncio.subprocess.DEVNULL,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL,
        env={'LANG':'C','PATH':'/usr/bin:/bin'},limit=24*1024)
    try:
        output,_=await asyncio.wait_for(process.communicate(),5)
        if process.returncode or len(output)>48*1024:
            raise ValueError('catalog_fetch_failed')
        value=json.loads(output.decode('utf-8'),object_pairs_hook=strict_object)
        body=base64.b64decode(value['body'],validate=True)
        if len(body)>BODY_MAX or not isinstance(value['headers'],dict):
            raise ValueError('catalog_fetch_failed')
        return body,value['headers']
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


if __name__=='__main__':
    import resource
    resource.setrlimit(resource.RLIMIT_AS,(96*1024*1024,96*1024*1024))
    resource.setrlimit(resource.RLIMIT_NOFILE,(32,32))
    try:
        if len(sys.argv)!=3:
            raise ValueError('arguments')
        fetched,proof=fetch_catalog(sys.argv[1],sys.argv[2])
        print(json.dumps({'body':base64.b64encode(fetched).decode(),'headers':proof},separators=(',',':')))
    except Exception:
        sys.exit(1)
