"""Dedicated authenticated loopback ingress; never route this to enrollment."""
import asyncio
import hmac
import os
import re

RESPONSE_LIMIT=65*1024
PATH=re.compile(r'/v1/dce/servers(?:\?(?:limit=(?:[1-9]|[1-5][0-9]|6[0-4])(?:&nonce=[0-9a-f]{32})?|nonce=[0-9a-f]{32}))?')
ITEM=re.compile(r'/v1/dce/servers/[0-9a-f]{16}(?:/join)?')
CLIENT=re.compile(r'[0-9a-f:.]{2,45}')

class DirectoryIngress:
    def __init__(self,key,backend_port=18117):
        if not re.fullmatch(r'[!-~]{32,256}',key):raise ValueError('dedicated key required')
        self.key=key;self.backend_port=backend_port;self.active=0
        self.trust_client=os.environ.get('HALO_DIRECTORY_TRUST_CLIENT')=='1'

    async def forward(self,method,path,headers,body):
        reader,writer=await asyncio.open_connection('127.0.0.1',self.backend_port,limit=8192)
        try:
            fresh={'Host':'127.0.0.1','Accept':'application/json','Accept-Encoding':'identity','Connection':'close','Content-Length':str(len(body))}
            if method!='GET':fresh['Authorization']=headers['authorization']
            # Believed only after the dedicated key check; never passed through unvalidated.
            client=headers.get('x-halo-client-ip','')
            if self.trust_client and CLIENT.fullmatch(client):
                fresh['X-Forwarded-For']=client;fresh['X-Forwarded-Proto']='https'
            if method=='PUT':fresh['Content-Type']='application/json'
            request=f'{method} {path} HTTP/1.0\r\n'+''.join(f'{name}: {value}\r\n' for name,value in fresh.items())
            writer.write(request.encode('ascii')+b'\r\n'+body);await writer.drain()
            raw=await reader.readuntil(b'\r\n\r\n')
            if len(raw)>8192:raise ValueError('headers')
            lines=raw.decode('ascii').split('\r\n');status=int(lines[0].split(' ')[1]);response={}
            if status not in (200,201,202,204,400,401,403,404,405,409,413,429,500,503):raise ValueError('status')
            for line in lines[1:-2]:
                name,value=line.split(':',1);name=name.lower()
                if name in response:raise ValueError('duplicate')
                response[name]=value.strip()
            if 'transfer-encoding' in response or response.get('content-encoding','identity')!='identity':raise ValueError('encoding')
            data=bytearray()
            while True:
                part=await reader.read(min(4096,RESPONSE_LIMIT+1-len(data)))
                if not part:break
                data.extend(part)
                if len(data)>RESPONSE_LIMIT:raise ValueError('size')
            if 'content-length' in response and int(response['content-length'])!=len(data):raise ValueError('length')
            outgoing={}
            for name,maximum in [('Signature',96),('Signature-Key',16),('Signature-Time',12),('Retry-After',12)]:
                value=response.get(name.lower())
                if value is not None:
                    if len(value)>maximum or '\r' in value or '\n' in value:raise ValueError('header')
                    outgoing[name]=value
            return status,outgoing,bytes(data)
        finally:
            writer.close()
            try:await writer.wait_closed()
            except OSError:pass

    async def handle(self,reader,writer):
        if self.active>=16:
            writer.close();await writer.wait_closed();return
        self.active+=1
        try:await self.request(reader,writer)
        finally:
            self.active-=1;writer.close()
            try:await writer.wait_closed()
            except OSError:pass

    async def request(self,reader,writer):
        status=400;outgoing={};data=b'request refused'
        try:
            raw=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),3)
            if len(raw)>8192:raise ValueError('headers')
            lines=raw.decode('ascii').split('\r\n');method,path,version=lines[0].split(' ')
            if version!='HTTP/1.1':raise ValueError('version')
            headers={}
            for line in lines[1:-2]:
                name,value=line.split(':',1);name=name.lower()
                if not re.fullmatch('[a-z0-9-]+',name) or name in headers:raise ValueError('header')
                headers[name]=value.strip()
            if not hmac.compare_digest(headers.get('x-halo-directory-key',''),self.key):
                status=403;raise ValueError('auth')
            if 'transfer-encoding' in headers or 'content-encoding' in headers or 'upgrade' in headers:raise ValueError('framing')
            is_list=PATH.fullmatch(path) is not None
            if not is_list and not ITEM.fullmatch(path):status=404;raise ValueError('route')
            if not (method=='GET' if is_list else method in ('PUT','DELETE')):status=405;raise ValueError('method')
            if method!='GET' and not (headers.get('authorization','').startswith('OpenCE-Ed25519 ') and len(headers['authorization'])<=512):
                status=401;raise ValueError('signature')
            length=headers.get('content-length','0')
            if not re.fullmatch('0|[1-9][0-9]{0,3}',length):raise ValueError('length')
            length=int(length)
            if length>(2048 if method=='PUT' else 0):status=413;raise ValueError('body')
            body=await asyncio.wait_for(reader.readexactly(length),3)
            try:status,outgoing,data=await asyncio.wait_for(self.forward(method,path,headers,body),5)
            except (OSError,ValueError,UnicodeError,asyncio.TimeoutError,asyncio.IncompleteReadError,asyncio.LimitOverrunError):status=502;data=b'upstream unavailable'
        except (ValueError,UnicodeError,asyncio.TimeoutError,asyncio.IncompleteReadError,asyncio.LimitOverrunError):pass
        try:
            response=f'HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {len(data)}\r\n'
            response+=''.join(f'{key}: {value}\r\n' for key,value in outgoing.items())
            writer.write(response.encode()+b'\r\n'+data);await asyncio.wait_for(writer.drain(),2)
        except (OSError,asyncio.TimeoutError):pass

async def main():
    path=os.environ['HALO_DIRECTORY_INGRESS_KEY_FILE']
    if os.stat(path).st_mode&0o077:raise ValueError('key file must be0600')
    with open(path,encoding='ascii') as file:key=file.read(257).strip()
    ingress=DirectoryIngress(key)
    listener=await asyncio.start_server(ingress.handle,'127.0.0.1',18119,limit=8192,backlog=8)
    async with listener:await listener.serve_forever()

if __name__=='__main__':asyncio.run(main())
