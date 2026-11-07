import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker.mjs';
import { readFile } from 'node:fs/promises';
const origin = 'https://test.invalid';
const username = 'test-team', password = 'fixture-password-only-not-deployed';
function env(){return {TEST_USERNAME:username,TEST_PASSWORD:password,ASSETS:{async fetch(r){assert.equal(r.headers.get('Cookie'),null);assert.equal(r.headers.get('Authorization'),null);return new Response(new URL(r.url).pathname);}}};}
const request = (path, init={})=>new Request(origin+path,init);
const sign = (value={},headers={})=>request('/signin',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json',...headers},body:JSON.stringify({username,password,...value})});
const cookie = response=>response.headers.get('Set-Cookie').split(';')[0];

test('login assets public, application and files still protected',async()=>{
 const e=env();
 for(const p of ['/signin','/signin.html','/signin.mjs','/signin.css'])assert.equal((await worker.fetch(request(p),e)).status,200);
 const nav=await worker.fetch(request('/',{headers:{Accept:'text/html'}}),e);assert.equal(nav.status,302);assert.equal(nav.headers.get('Location'),'/signin');
 for(const p of ['/app.mjs','/runtime-frame.html','/files/image.cdi','/files/core.wasm'])assert.equal((await worker.fetch(request(p),e)).status,401);
});
test('native form fallback never puts credentials in a URL',async()=>{
 const html=await readFile(new URL('../public/signin.html',import.meta.url),'utf8');
 assert.match(html,/<form\b[^>]*method="post"[^>]*action="\/signin"/);
 const fallback=request('/signin',{method:'POST',headers:{Origin:origin,'Content-Type':'application/x-www-form-urlencoded'},body:'username=fixture&password=fixture'});
 const res=await worker.fetch(fallback,env());assert.equal(res.status,400);assert.equal(res.headers.get('Location'),null);assert.equal(res.headers.get('Set-Cookie'),null);
});
test('same-origin login creates secure HttpOnly session; auth headers never reach assets',async()=>{
 const e=env(), res=await worker.fetch(sign(),e);assert.equal(res.status,200);
 const field=res.headers.get('Set-Cookie');for(const expected of ['HttpOnly','Secure','SameSite=Strict','Max-Age=28800','Path=/'])assert.ok(field.includes(expected));
 assert.ok(!(await res.text()).includes(password));
 const asset=await worker.fetch(request('/app.mjs',{headers:{Cookie:cookie(res)}}),e);assert.equal(asset.status,200);
 assert.equal(asset.headers.get('Vary'),'Authorization, Cookie');
});
test('wrong credentials, cross-origin login and oversized input cannot issue a session',async()=>{
 for(const [req,code] of [[sign({password:'wrong'}),401],[sign({}, {Origin:'https://elsewhere.invalid'}),403],[sign({padding:'x'.repeat(1100)}),400]]){
  const r=await worker.fetch(req,env());assert.equal(r.status,code);assert.equal(r.headers.get('Set-Cookie'),null);
 }
});
test('tampered, expired and credential-rotated sessions rejected',async()=>{
 const e=env(), r=await worker.fetch(sign(),e), c=cookie(r);
 const i=c.length-3, forged=c.slice(0,i)+(c[i]==='A'?'B':'A')+c.slice(i+1);
 assert.equal((await worker.fetch(request('/app.mjs',{headers:{Cookie:forged}}),e)).status,401);
 assert.equal((await worker.fetch(request('/app.mjs',{headers:{Cookie:c}}),{...e,TEST_PASSWORD:password+'rotated'})).status,401);
 const now=Date.now;try{Date.now=()=>now()+28801000;assert.equal((await worker.fetch(request('/app.mjs',{headers:{Cookie:c}}),e)).status,401);}finally{Date.now=now;}
});
test('only authenticated runtime frame allows same-origin embedding',async()=>{
 const e=env(), r=await worker.fetch(sign(),e), headers={Cookie:cookie(r)};
 assert.match((await worker.fetch(request('/runtime-frame.html',{headers}),e)).headers.get('Content-Security-Policy'),/frame-ancestors 'self'/);
 assert.match((await worker.fetch(request('/runtime-frame',{headers}),e)).headers.get('Content-Security-Policy'),/frame-ancestors 'self'/);
 assert.match((await worker.fetch(request('/index.html',{headers}),e)).headers.get('Content-Security-Policy'),/frame-ancestors 'none'/);
 for(const path of ['/runtime-frame.html','/runtime-frame'])assert.match((await worker.fetch(request(path,{headers}),e)).headers.get('Content-Security-Policy'),/script-src 'self' 'wasm-unsafe-eval' blob:;/);
 for(const path of ['/index.html','/signin'])assert.match((await worker.fetch(request(path,{headers}),e)).headers.get('Content-Security-Policy'),/script-src 'self' 'wasm-unsafe-eval';/);
});
test('committed configuration is private; files need a session in public mode',async()=>{
 const text=await readFile(new URL('../wrangler.example.jsonc',import.meta.url),'utf8');
 assert.match(text,/"vars": \{ "PUBLIC_ACCESS": "0" \}/);
 const e={...env(),PUBLIC_ACCESS:'1',TEST_FILES:{async get(){return null},async head(){return null}}};
 assert.equal((await worker.fetch(request('/files/none.cdi'),e)).status,401);
 assert.equal((await worker.fetch(request('/files/none.cdi',{method:'HEAD'}),e)).status,401);
 assert.equal((await worker.fetch(request('/files/none.cdi',{headers:{Cookie:'halo_test_session=forged'}}),e)).status,401);
});
test('new public sessions are limited per client; IPv6 counts by /64',async()=>{
 const e={...env(),PUBLIC_ACCESS:'1'};
 const visit=address=>worker.fetch(request('/',{headers:{Accept:'text/html','CF-Connecting-IP':address}}),e);
 for(let n=0;n<20;n++)assert.equal((await visit(`2001:db8:1:2::${(n+1).toString(16)}`)).status,200);
 const refused=await visit('2001:db8:1:2:ffff::1');assert.equal(refused.status,429);assert.equal(refused.headers.get('Set-Cookie'),null);
 assert.equal((await visit('2001:db8:1:3::1')).status,200);
 assert.equal((await visit('198.51.100.7')).status,200);
 let asked=null;
 const bound={...e,SESSION_LIMIT:{async limit({key}){asked=key;return{success:false};}}};
 assert.equal((await worker.fetch(request('/',{headers:{Accept:'text/html','CF-Connecting-IP':'198.51.100.8'}}),bound)).status,429);assert.equal(asked,'198.51.100.8');
});
test('PUBLIC_ACCESS opens the page, hands out a session, and stays off by default',async()=>{
 const e={...env(),PUBLIC_ACCESS:'1',TEST_FILES:{async get(){return null},async head(){return null}}};
 const nav=await worker.fetch(request('/signin'),e);assert.equal(nav.status,302);assert.equal(nav.headers.get('Location'),'/');
 const page=await worker.fetch(request('/',{headers:{Accept:'text/html'}}),e);assert.equal(page.status,200);
 const field=page.headers.get('Set-Cookie');for(const expected of ['HttpOnly','Secure','SameSite=Strict'])assert.ok(field.includes(expected));
 assert.equal((await worker.fetch(request('/app.mjs'),e)).status,200);assert.equal((await worker.fetch(request('/files/none.cdi',{headers:{Cookie:field.split(';')[0]}}),e)).status,404);
 assert.equal((await worker.fetch(request('/api/guest-network/x'),e)).status,401);
 const again=await worker.fetch(request('/',{headers:{Accept:'text/html',Cookie:field.split(';')[0]}}),e);assert.equal(again.headers.get('Set-Cookie'),null);
 assert.equal((await worker.fetch(request('/files/none.cdi'),{...env(),PUBLIC_ACCESS:'0'})).status,401);
});

test("password guesses are limited per client, and a right password is refused once they run out", async () => {
  const env = { TEST_USERNAME: "tester", TEST_PASSWORD: "p".repeat(20) };
  const basic = (password, ip) => new Request("https://site.invalid/x", { headers: { "CF-Connecting-IP": ip,
    Authorization: "Basic " + btoa("tester:" + password) } });
  const signin = (password, ip) => new Request("https://site.invalid/signin", { method: "POST", headers: { "CF-Connecting-IP": ip,
    Origin: "https://site.invalid", "Content-Type": "application/json" }, body: JSON.stringify({ username: "tester", password }) });
  for (let n = 0; n < 10; n++) assert.equal((await worker.fetch(basic("wrong", "198.51.100.40"), env)).status, 401);
  assert.equal((await worker.fetch(basic("wrong", "198.51.100.40"), env)).status, 429);
  assert.equal((await worker.fetch(basic(env.TEST_PASSWORD, "198.51.100.40"), env)).status, 429);
  assert.equal((await worker.fetch(signin(env.TEST_PASSWORD, "198.51.100.40"), env)).status, 429);
  for (let n = 0; n < 10; n++) assert.equal((await worker.fetch(signin("wrong", "198.51.100.41"), env)).status, 401);
  assert.equal((await worker.fetch(signin(env.TEST_PASSWORD, "198.51.100.41"), env)).status, 429);
  assert.equal((await worker.fetch(signin(env.TEST_PASSWORD, "198.51.100.42"), env)).status, 200);
  // Right passwords do not spend the budget.
  for (let n = 0; n < 12; n++) assert.notEqual((await worker.fetch(basic(env.TEST_PASSWORD, "198.51.100.43"), env)).status, 429);
});

test("the licence page opens without signing in, and pages link to it", async () => {
  const e = env();
  for (const path of ["/licenses.html", "/licenses.mjs", "/LICENSE-GPL-2.0.txt", "/LICENSE-EJS-GPL-3.0.txt"])
    assert.equal((await worker.fetch(request(path), e)).status, 200, path);
  for (const page of ["index.html", "signin.html"])
    assert.match(await readFile(new URL("../public/" + page, import.meta.url), "utf8"), /href="\/licenses\.html">Source and licences</);
  const licences = await readFile(new URL("../public/licenses.html", import.meta.url), "utf8");
  for (const file of ["licenses.html", "licenses.mjs"]) {
    const text = await readFile(new URL("../public/" + file, import.meta.url), "utf8");
    assert.ok(text.includes("github.com/lamb2k/dce-web-tool"), file);
  }
  const pins = JSON.parse(await readFile(new URL("../core-patches/pins.json", import.meta.url), "utf8"));
  for (const commit of [pins.flycast, pins.wasmFoundation, pins.ejsRetroArch]) assert.ok(licences.includes(commit), commit);
});
test("the core is built from source: no prebuilt object is linked by hash", async () => {
  const script = await readFile(new URL("../core-patches/build-network.sh", import.meta.url), "utf8");
  assert.match(script, /emcc [^\n]*flycast_stubs\.c/);
  assert.doesNotMatch(script, /prebuiltSha256/);
  const stubs = await readFile(new URL("../core-patches/flycast_stubs.c", import.meta.url), "utf8");
  for (const symbol of ["fill_short_pathname_representation", "fill_short_pathname_representation_noext", "bm_Reset", "__wrap_glGetString", "__real_glGetString"])
    assert.ok(stubs.includes(symbol), symbol);
});
