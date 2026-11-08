import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker.mjs';
const origin = 'https://test.invalid';
const username = 'test-team', password = 'fixture-password-only-not-deployed';
function env(){const puts=[];return {puts,TEST_USERNAME:username,TEST_PASSWORD:password,ASSETS:{async fetch(r){return new Response(new URL(r.url).pathname);}},
 TEST_FILES:{async put(k,v,o){puts.push({k,v:new TextDecoder().decode(v),o});},async get(){return null},async head(){return null}}};}
const req=(p,init={})=>new Request(origin+p,init);
async function session(e){const r=await worker.fetch(req('/signin',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:JSON.stringify({username,password})}),e);return r.headers.get('Set-Cookie').split(';')[0];}
let ip=0;const post=(c,body,h={})=>req('/diag',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json',Cookie:c,'CF-Connecting-IP':'203.0.113.'+(++ip%250),...h},body});
test('/diag stores a JSON report under diag/ with nothing added',async()=>{
 const e=env(),c=await session(e),body=JSON.stringify({end:'failed',build:'v0.55-b15-web-diag'});
 const r=await worker.fetch(post(c,body),e);assert.equal(r.status,201);
 assert.equal(e.puts.length,1);assert.match(e.puts[0].k,/^diag\/\d{4}-\d\d-\d\dT[\d-]+Z-[0-9a-f]{8}\.json$/);
 assert.equal(e.puts[0].v,body);assert.ok(!JSON.stringify(e.puts[0]).includes('203.0.113.'));
});
test('/diag refuses non-JSON, oversize, no session, cross-origin, GET',async()=>{
 const e=env(),c=await session(e);
 assert.equal((await worker.fetch(post(c,'not json'),e)).status,400);
 assert.equal((await worker.fetch(post(c,'[1]'),e)).status,400);
 assert.equal((await worker.fetch(post(c,'{}',{'Content-Type':'text/plain'}),e)).status,415);
 assert.equal((await worker.fetch(post(c,JSON.stringify({x:'y'.repeat(9000)})),e)).status,413);
 assert.equal((await worker.fetch(post('',"{}"),e)).status,401);
 assert.equal((await worker.fetch(post(c,'{}',{Origin:'https://elsewhere.invalid'}),e)).status,403);
 assert.equal((await worker.fetch(req('/diag',{headers:{Cookie:c}}),e)).status,405);
 assert.equal(e.puts.length,0);
});
test('/diag is rate limited and reports are not served from /files',async()=>{
 const e=env(),c=await session(e),h={'CF-Connecting-IP':'198.51.100.7'};
 const codes=[];for(let i=0;i<5;i++)codes.push((await worker.fetch(post(c,'{"a":1}',h),e)).status);
 assert.deepEqual(codes,[201,201,201,429,429]);
 let n=0;const bound={...e,DIAG_LIMIT:{async limit(){return {success:n++<1}}}};
 assert.equal((await worker.fetch(post(c,'{"a":1}',{'CF-Connecting-IP':'192.0.2.1'}),bound)).status,201);
 assert.equal((await worker.fetch(post(c,'{"a":1}',{'CF-Connecting-IP':'192.0.2.1'}),bound)).status,429);
 assert.equal((await worker.fetch(req('/files/diag/x.json',{headers:{Cookie:c}}),e)).status,404);
});
