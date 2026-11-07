import test from 'node:test';
import assert from 'node:assert/strict';
import {proxyDirectory,DIRECTORY_RESPONSE_LIMIT} from '../directory-proxy.mjs';
import worker from '../worker.mjs';
const env={DIRECTORY_UPSTREAM_URL:'https://private.invalid',DIRECTORY_UPSTREAM_KEY:'d'.repeat(64)};
const base='https://halo.invalid/v1/dce/servers',id='a'.repeat(16);
const signed='OpenCE-Ed25519 keyid=test, ts=1, nonce=test, sig=test';
test('exact list query and signed PUT bytes survive; untrusted headers stripped',async()=>{
 const bytes=' {"name":"x", "sequence":1}\n';
 for(const [url,method,body] of [[base+'?limit=16','GET',undefined],[base+'?nonce='+'ab'.repeat(16),'GET',undefined],[base+'?limit=1&nonce='+'ab'.repeat(16),'GET',undefined],[base+'/'+id,'PUT',bytes],[base+'/'+id,'DELETE',undefined]]){
  const response=await proxyDirectory(new Request(url,{method,body,headers:{Authorization:signed,Cookie:'secret','X-Forwarded-For':'spoof','X-Halo-Directory-Key':'spoof'}}),env,async(target,init)=>{
   assert.equal(new URL(target).pathname+new URL(target).search,new URL(url).pathname+new URL(url).search);
   assert.equal(init.method,method);assert.equal(init.redirect,'manual');assert.equal(init.headers.get('Cookie'),null);
   assert.equal(init.headers.get('X-Forwarded-For'),null);assert.equal(init.headers.get('X-Halo-Directory-Key'),env.DIRECTORY_UPSTREAM_KEY);
   assert.equal(init.headers.get('Authorization'),method==='GET'?null:signed);
   if(body)assert.equal(new TextDecoder().decode(init.body),body);
   return new Response(' signed bytes\n',{headers:{Signature:'ed25519=exact','Signature-Key':id,'Signature-Time':'123','Set-Cookie':'never','Location':'never'}});
  });
  assert.equal(await response.text(),' signed bytes\n');assert.equal(response.headers.get('Signature'),'ed25519=exact');
  assert.equal(response.headers.get('Set-Cookie'),null);assert.equal(response.headers.get('Location'),null);
 }
});
test('exact route, query, auth and dedicated config fail closed',async()=>{
 const never=()=>assert.fail('unexpected upstream');
 for(const [url,method,status] of [[base+'/../enrollment/challenge','GET',404],[base+'?limit=016','GET',400],[base+'?nonce=short','GET',400],[base+'?nonce='+'A'.repeat(32),'GET',400],[base+'?limit=16&limit=16','GET',400],[base+'/'+id+'?limit=1','PUT',400],[base+'/AAAAAAAAAAAAAAAA','PUT',404],[base,'POST',405]])
  assert.equal((await proxyDirectory(new Request(url,{method}),env,never)).status,status);
 assert.equal((await proxyDirectory(new Request(base+'/'+id,{method:'PUT'}),env,never)).status,401);
 for(const bad of [{},{...env,DIRECTORY_UPSTREAM_URL:'http://private.invalid'},{...env,GUEST_GATEWAY_KEY:env.DIRECTORY_UPSTREAM_KEY}])
  assert.equal((await proxyDirectory(new Request(base),bad,never)).status,503);
 assert.equal((await worker.fetch(new Request(base+'?limit=16'),{})).status,503); // routes before tester-cookie configuration
 assert.equal((await worker.fetch(new Request('https://halo.invalid/v1/dce/enrollment/challenge'),{})).status,404);
});
test('body/response bounds, redirects and abort fail closed',async()=>{
 assert.equal((await proxyDirectory(new Request(base+'/'+id,{method:'PUT',headers:{Authorization:signed},body:'x'.repeat(2049)}),env,()=>assert.fail())).status,413);
 for(const response of [new Response(null,{status:302,headers:{Location:'https://evil.invalid'}}),new Response('x'.repeat(DIRECTORY_RESPONSE_LIMIT+1))])
  assert.equal((await proxyDirectory(new Request(base),env,async()=>response)).status,502);
 const control=new AbortController();control.abort();
 assert.equal((await proxyDirectory(new Request(base,{signal:control.signal}),env,async(_,init)=>{assert.ok(init.signal.aborted);throw Error('aborted')})).status,504);
 const abort=new AbortController();const pending=proxyDirectory(new Request(base,{signal:abort.signal}),env,async()=>new Response(new ReadableStream({start(){}})));
 abort.abort();assert.equal((await pending).status,504);
});
test('Go maximum typed catalogue fits conservative bound with HTML escaped name',()=>{
 const max32=4294967295,max64=-9223372036854775808;
 const entry={id,key_id:id,protocol:1,family:'dce-net',network_version:3,build:max32,map:255,map_crc:max32,mode:1,score:50,players:2,capacity:2,name:'<'.repeat(32),sequence:max32,time:max64,instance:id,game_port:65535,endpoint:{ip:'255.255.255.255',port:65535},updated:max64,expires:max64,reachable:true};
 const encode=v=>JSON.stringify(v).replaceAll('<','\\u003c');
 assert.ok(encode(entry).length<1024);
 const catalogue={protocol:1,family:'dce-net',network_version:3,master:{key_id:id,time:max64},ttl:90,truncated:false,servers:Array(64).fill(entry)};
 assert.ok(encode(catalogue).length<DIRECTORY_RESPONSE_LIMIT);
});

test("edge client address is forwarded and join route is accepted", async () => {
 const headers = { Authorization: "OpenCE-Ed25519 x", "CF-Connecting-IP": "203.0.113.5" };
 let seen;
 const key = "d".repeat(40);
 const response = await proxyDirectory(new Request("https://t.invalid/v1/dce/servers/" + "a".repeat(16) + "/join", { method: "PUT", headers }),
   { DIRECTORY_UPSTREAM_URL: "https://up.invalid", DIRECTORY_UPSTREAM_KEY: key, GUEST_GATEWAY_KEY: "g".repeat(40) },
   async (url, init) => { seen = init.headers.get("X-Halo-Client-IP"); return new Response("{}", { status: 200 }); });
 assert.equal(response.status, 200); assert.equal(seen, "203.0.113.5");
});
