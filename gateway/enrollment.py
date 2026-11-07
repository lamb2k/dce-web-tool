"""Disabled-by-default public-key enrollment through one private operator API."""
import asyncio
import base64
from collections import deque
import functools
import hashlib
import http.client
import ipaddress
import json
import os
import re
import ssl
import sys
import time
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from directory_catalog import strict_object

DOMAIN='DCE-Device-Enrollment-v1'
PUBLIC_RE=re.compile(r'ed25519:[0-9a-f]{64}')
LIMITS={'config':30,'challenge':5,'register':10}


class EnrollmentError(Exception):
    def __init__(self,status):
        self.status=status


def key_id(public):
    return hashlib.sha256(bytes.fromhex(public[8:])).hexdigest()[:16]


def proof_bytes(challenge):
    return '\n'.join((DOMAIN,challenge['masterKeyId'],challenge['publicKey'],challenge['challenge'],
                      str(challenge['expires']),challenge['sessionBinding'])).encode('utf-8')


def valid_public(value):
    return isinstance(value,str) and PUBLIC_RE.fullmatch(value) is not None


def exact(value,keys):
    return isinstance(value,dict) and set(value)==set(keys)


def integer(value):
    return type(value) is int


def backend_url(value):
    parts=urlsplit(value)
    try:
        address=ipaddress.ip_address(parts.hostname or '')
        port=parts.port
    except ValueError as exc:
        raise ValueError('enrollment endpoint must be literal loopback') from exc
    if (parts.scheme not in ('http','https') or not address.is_loopback or not port or
        parts.username or parts.password or parts.path not in ('','/') or parts.query or parts.fragment):
        raise ValueError('enrollment endpoint must be private loopback origin')
    return parts


async def operator_request(url,token,action,session,body,master_public,enrollment_class='operator'):
    """One killable process; operator credential only in its private environment."""
    payload=json.dumps(body,separators=(',',':')).encode()
    if len(payload)>512 or action not in ('challenge','register'):
        raise EnrollmentError(400)
    try:
        process=await asyncio.create_subprocess_exec(sys.executable,__file__,url,action,session,
            stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL,
            env={'PATH':'/usr/bin:/bin','LANG':'C','HALO_ENROLLMENT_OPERATOR_TOKEN':token,
                 'HALO_ENROLLMENT_CLASS':enrollment_class},limit=4096)
    except OSError as exc:
        raise EnrollmentError(503) from exc
    try:
        output,_=await asyncio.wait_for(process.communicate(payload),5)
        if process.returncode or len(output)>4096:
            raise EnrollmentError(503)
        wrapper=json.loads(output.decode('utf-8'),object_pairs_hook=strict_object)
        if wrapper['status']!=200:
            raise EnrollmentError(wrapper['status'] if wrapper['status'] in (400,403,409,429) else 503)
        raw=base64.b64decode(wrapper['body'],validate=True)
        if len(raw)>2048:
            raise EnrollmentError(502)
        headers=wrapper['headers'];stamp=headers['Signature-Time']
        if (headers['Signature-Key']!=key_id(master_public) or not re.fullmatch('[0-9]{1,12}',stamp) or
            abs(int(stamp)-time.time())>300 or not headers['Signature'].startswith('ed25519=')):
            raise EnrollmentError(502)
        sig=base64.b64decode(headers['Signature'][8:],validate=True)
        if len(sig)!=64:raise EnrollmentError(502)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(master_public[8:])).verify(sig,raw)
        value=json.loads(raw.decode('utf-8'),object_pairs_hook=strict_object)
        if not isinstance(value,dict) or type(value.get('serverTime')) is not int or value['serverTime']!=int(stamp):
            raise EnrollmentError(502)
        return value
    except asyncio.TimeoutError as exc:
        raise EnrollmentError(504) from exc
    except (ValueError,KeyError,TypeError,InvalidSignature) as exc:
        raise EnrollmentError(502) from exc
    finally:
        if process.returncode is None:
            process.kill();await process.wait()


class EnrollmentRelay:
    def __init__(self,url,token,master_public,requester=operator_request,enrollment_class='operator',sessions=64,pending=32):
        backend_url(url)
        if enrollment_class not in ('operator','public'):
            raise ValueError('enrollment class is operator or public')
        if enrollment_class!='operator':
            requester=functools.partial(requester,enrollment_class=enrollment_class)
        if not re.fullmatch('[0-9a-f]{64,128}',token or '') or len(token)%2:
            raise ValueError('operator token requires 32..64 random bytes encoded as lowercase hex')
        if not valid_public(master_public):
            raise ValueError('separate enrollment master public key required')
        self.url,self.token,self.master_public=url,token,master_public
        self.master_id=key_id(master_public)
        self.requester=requester
        self.rates={};self.pending={};self.busy=set();self.inflight=0
        self.max_sessions,self.max_pending=sessions,pending

    def cleanup(self,now):
        for session,value in list(self.pending.items()):
            if value['deadline']<=now and session not in self.busy:
                del self.pending[session]
        for session,value in list(self.rates.items()):
            if value['seen']+60<=now and session not in self.pending and session not in self.busy:
                del self.rates[session]

    def rate(self,session,action,now):
        self.cleanup(now)
        if session not in self.rates:
            if len(self.rates)>=self.max_sessions:raise EnrollmentError(429)
            self.rates[session]={'seen':now,**{name:deque() for name in LIMITS}}
        value=self.rates[session];value['seen']=now;times=value[action]
        while times and times[0]<=now-60:times.popleft()
        if len(times)>=LIMITS[action]:raise EnrollmentError(429)
        times.append(now)

    def configuration(self):
        return dict(protocol=1,configured=True,masterPublicKey=self.master_public,masterKeyId=self.master_id,
                    proofDomain=DOMAIN,challengeTtl=60)

    def challenge(self,value,public,session,session_expiry):
        fields=('protocol','masterKeyId','keyId','publicKey','challenge','expires','serverTime','sessionBinding')
        if (not exact(value,fields) or type(value['protocol']) is not int or value['protocol']!=1 or
            value['masterKeyId']!=self.master_id or value['keyId']!=key_id(public) or value['publicKey']!=public or
            not isinstance(value['challenge'],str) or not re.fullmatch('[0-9a-f]{32}',value['challenge']) or
            not integer(value['expires']) or not integer(value['serverTime']) or
            abs(value['serverTime']-time.time())>300 or not value['serverTime']<value['expires']<=value['serverTime']+60 or
            value['expires']*1000>session_expiry or value['sessionBinding']!=session):
            raise EnrollmentError(502)
        return value

    async def handle(self,action,session,session_expiry,body,client=None):
        if action not in LIMITS or not re.fullmatch('[0-9a-f]{64}',session):raise EnrollmentError(400)
        now=time.monotonic();self.rate(session,action,now)
        if action=='config':
            if body is not None:raise EnrollmentError(400)
            return self.configuration()
        fields=('publicKey',) if action=='challenge' else ('publicKey','challenge','signature')
        if not exact(body,fields) or not valid_public(body['publicKey']):raise EnrollmentError(400)
        if session in self.busy:raise EnrollmentError(409)
        if self.inflight>=2:raise EnrollmentError(429)
        public=body['publicKey']
        reserved=False
        if action=='challenge':
            if session_expiry<time.time()*1000+65000:raise EnrollmentError(403)
            if session not in self.pending and len(self.pending)>=self.max_pending:raise EnrollmentError(429)
            if session not in self.pending:
                self.pending[session]={'value':None,'deadline':now+6}
                reserved=True
        else:
            pending=self.pending.get(session)
            if (not pending or pending['deadline']<=now or pending['value']['publicKey']!=public or
                body['challenge']!=pending['value']['challenge']):raise EnrollmentError(403)
            try:
                if not isinstance(body['signature'],str) or len(body['signature'])!=88:
                    raise ValueError('signature')
                signature=base64.b64decode(body['signature'],validate=True)
                if len(signature)!=64 or base64.b64encode(signature).decode()!=body['signature']:
                    raise ValueError('signature')
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(public[8:])).verify(signature,proof_bytes(pending['value']))
            except (ValueError,InvalidSignature) as exc:
                raise EnrollmentError(403) from exc
        self.busy.add(session);self.inflight+=1
        try:
            value=await self.requester(self.url,self.token,action,session,body,self.master_public)
            if action=='challenge':
                value=self.challenge(value,public,session,session_expiry)
                self.pending[session]={'value':value,'deadline':time.monotonic()+min(60,value['expires']-value['serverTime'])}
                return value
            fields=('ok','masterKeyId','keyId','publicKey','approved','created','serverTime')
            if (not exact(value,fields) or value['ok'] is not True or value['approved'] is not True or
                value['masterKeyId']!=self.master_id or value['keyId']!=key_id(public) or value['publicKey']!=public or
                type(value['created']) is not bool or not integer(value['serverTime']) or abs(value['serverTime']-time.time())>300):
                raise EnrollmentError(502)
            # Retain original challenge until its deadline for identical lost-response retries.
            return value
        finally:
            self.inflight-=1;self.busy.discard(session)
            if reserved and self.pending.get(session,{}).get('value') is None:
                self.pending.pop(session,None)


def fetch_operator(url,action,session,body,token,enrollment_class='operator'):
    parts=backend_url(url)
    cls=http.client.HTTPSConnection if parts.scheme=='https' else http.client.HTTPConnection
    kwargs={'timeout':4}
    if parts.scheme=='https':kwargs['context']=ssl.create_default_context()
    connection=cls(parts.hostname,parts.port,**kwargs)
    try:
        connection.request('POST','/v1/dce/enrollment/'+action,body=body,headers={
            'Authorization':'Bearer '+token,'X-DCE-Enrollment-Session':session,'X-DCE-Enrollment-Class':enrollment_class,
            'Content-Type':'application/json','Accept':'application/json','Accept-Encoding':'identity','Connection':'close'})
        response=connection.getresponse()
        if response.getheader('Content-Encoding','identity')!='identity':raise ValueError('encoding')
        if response.getheader('Content-Length') and int(response.getheader('Content-Length'))>2048:raise ValueError('size')
        result=response.read(2049)
        if len(result)>2048:raise ValueError('size')
        headers={}
        if response.status==200:
            for name,maximum in (('Signature',96),('Signature-Key',16),('Signature-Time',12)):
                values=response.headers.get_all(name,[])
                if len(values)!=1 or len(values[0])>maximum:raise ValueError('signature_header')
                headers[name]=values[0]
        return {'status':response.status,'body':base64.b64encode(result).decode(),'headers':headers}
    finally:connection.close()


if __name__=='__main__':
    import resource
    resource.setrlimit(resource.RLIMIT_AS,(96*1024*1024,96*1024*1024))
    resource.setrlimit(resource.RLIMIT_NOFILE,(32,32))
    try:
        if len(sys.argv)!=4 or sys.argv[2] not in ('challenge','register') or not re.fullmatch('[0-9a-f]{64}',sys.argv[3]):
            raise ValueError('arguments')
        body=sys.stdin.buffer.read(513)
        if len(body)>512:raise ValueError('size')
        token=os.environ['HALO_ENROLLMENT_OPERATOR_TOKEN']
        print(json.dumps(fetch_operator(sys.argv[1],sys.argv[2],sys.argv[3],body,token,os.environ.get('HALO_ENROLLMENT_CLASS','operator')),separators=(',',':')))
    except Exception:
        sys.exit(1)
