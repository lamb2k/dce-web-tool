import test from "node:test";
import assert from "node:assert/strict";
import { proxyGuestNetwork } from "../bridge-proxy.mjs";
import worker from "../worker.mjs";
const base = "https://test.invalid", path = "/api/guest-network", lease = "A".repeat(43);
const session = () => ({ id: "1".repeat(64), expiresAt: Date.now() + 600000 });
const env = () => ({ GUEST_GATEWAY_URL: "https://gateway.invalid", GUEST_GATEWAY_KEY: "server-only-key-".repeat(3) });
const req = (suffix = "", init = {}) => new Request(base + path + suffix, { method: "POST", headers: { Origin: base }, ...init });
const data = () => ({ lease, expiresAt: Date.now() + 300000, guestIPv4: "10.77.1.15", routerIPv4: "10.77.1.2", netmask: "255.255.255.0", mode: "dce", joinEndpoint: null, websocketPath: path + "/" + lease });
const upstream = value => async () => new Response(JSON.stringify(value ?? data()));
test("bridge rejects missing session, bad origin, request body and routes before contacting gateway", async () => {
 const never = async () => assert.fail("Unexpected gateway request");
 for (const [request, identity, code] of [[req(),null,401], [req("",{headers:{Origin:"https://evil.invalid"}}),session(),403],
   [req("",{body:"arbitrary destination"}),session(),400], [req("/bad"),session(),404], [req("",{method:"GET"}),session(),405],
   [req("/"+lease,{method:"GET",headers:{Upgrade:"websocket"}}),session(),403]])
  assert.equal((await proxyGuestNetwork(request,env(),identity,never)).status,code);
});
test("gateway target is configured, TLS protected, never selected by browser", async () => {
 const never = async () => assert.fail("Unexpected gateway request");
 for (const target of [undefined,"http://gateway.invalid","http://127.0.0.1:1234","https://a:b@gateway.invalid","https://gateway.invalid/path","https://gateway.invalid/?secret=1"])
  assert.equal((await proxyGuestNetwork(req(),{...env(),GUEST_GATEWAY_URL:target},session(),never)).status,503);
 const local = new Request("http://127.0.0.1:18105"+path,{method:"POST",headers:{Origin:"http://127.0.0.1:18105"}});
 assert.equal((await proxyGuestNetwork(local,{...env(),GUEST_GATEWAY_URL:"http://127.0.0.1:18096"},session(),upstream())).status,201);
});
test("only trusted identity crosses gateway boundary; returned metadata is stripped", async () => {
 const identity=session(), settings=env();
 const response=await proxyGuestNetwork(req("",{headers:{Origin:base,Cookie:"private-cookie",Authorization:"Basic secret","X-Halo-Session":"spoof","X-Halo-Bridge-Key":"spoof"}}),settings,identity,async(url,init)=>{
  assert.equal(String(url),"https://gateway.invalid"+path);assert.equal(init.redirect,"manual");
  assert.equal(init.headers.get("Cookie"),null);assert.equal(init.headers.get("Authorization"),null);
  assert.equal(init.headers.get("X-Halo-Session"),identity.id);assert.equal(init.headers.get("X-Halo-Bridge-Key"),settings.GUEST_GATEWAY_KEY);
  assert.equal(init.headers.get("X-Halo-Session-Expires"),String(identity.expiresAt));
  return new Response(JSON.stringify({...data(),privateSecret:"must not return"}),{headers:{"Set-Cookie":"backend-cookie"}});
 });
 assert.equal(response.status,201);assert.equal(response.headers.get("Set-Cookie"),null);assert.equal((await response.json()).privateSecret,undefined);
});
test("the client tag reaches the gateway only when well formed", async()=>{
 const seen=[];const capture=async(url,init)=>{seen.push(init.headers.get("X-Halo-Client"));return new Response(JSON.stringify(data()));};
 await proxyGuestNetwork(req(),env(),{...session(),client:"a".repeat(32)},capture);
 await proxyGuestNetwork(req("",{headers:{Origin:base,"X-Halo-Client":"f".repeat(32)}}),env(),{...session(),client:"not hex"},capture);
 assert.deepEqual(seen,["a".repeat(32),null]);
});
test("malformed, oversized, expired and mismatched metadata fail closed", async()=>{
 for(const change of [{lease:"bad"},{expiresAt:Date.now()-1},{expiresAt:Date.now()+7200000},{guestIPv4:"999.1.2.3"},{websocketPath:"https://evil.invalid"},{joinEndpoint:{host:"127.0.0.01",port:5150}},{mode:"invented"}])
  assert.equal((await proxyGuestNetwork(req(),env(),session(),upstream({...data(),...change}))).status,502);
 assert.equal((await proxyGuestNetwork(req("/"+"B".repeat(43),{method:"GET",headers:{}}),env(),session(),upstream())).status,502);
 assert.equal((await proxyGuestNetwork(req(),env(),session(),async()=>new Response("x".repeat(4097)))).status,502);
});
test("backend redirects are not followed and backend errors never echo private text", async()=>{
 const response=await proxyGuestNetwork(req(),env(),session(),async()=>new Response("private backend details",{status:302,headers:{Location:"http://private.invalid"}}));
 assert.equal(response.status,502);assert.equal(response.headers.get("Location"),null);assert.doesNotMatch(await response.text(),/private backend/);
 assert.equal((await proxyGuestNetwork(req(),env(),session(),async()=>{throw Error("private");})).status,503);
});

test("configured advertised endpoint survives only strict DCE host metadata validation", async()=>{
 const endpoint={host:"192.168.1.20",port:25150};
 const response=await proxyGuestNetwork(req(),env(),session(),upstream({...data(),advertisedEndpoint:{...endpoint,secret:"strip"}}));
 assert.equal(response.status,201);assert.deepEqual((await response.json()).advertisedEndpoint,endpoint);
 assert.equal((await (await proxyGuestNetwork(req(),env(),session(),upstream())).json()).advertisedEndpoint,null);
 for(const advertisedEndpoint of [{host:"127.0.0.1",port:5150},{host:"10.77.1.15",port:5150},
   {host:"169.254.169.254",port:80},{host:"224.0.0.1",port:5150},{host:"0.0.0.0",port:5150},
   {host:"192.168.1.20",port:0},{host:"192.168.1.20",port:65536},{host:"192.168.1.20",port:"5150"}])
  assert.equal((await proxyGuestNetwork(req(),env(),session(),upstream({...data(),advertisedEndpoint}))).status,502);
 for(const change of [{mode:"native"},{joinEndpoint:{host:"10.77.1.2",port:25150}}])
  assert.equal((await proxyGuestNetwork(req(),env(),session(),upstream({...data(),...change,advertisedEndpoint:endpoint}))).status,502);
});
test("DELETE and rejected WebSocket upgrade preserve honest state", async()=>{
 assert.equal((await proxyGuestNetwork(req("/"+lease,{method:"DELETE",headers:{Origin:base}}),env(),session(),async()=>new Response(null,{status:204}))).status,204);
 const response=await proxyGuestNetwork(req("/"+lease,{method:"GET",headers:{Origin:base,Upgrade:"websocket"}}),env(),session(),async(url,init)=>{
  assert.equal(init.headers.get("Upgrade"),"websocket");return new Response("not a websocket");
 });assert.equal(response.status,502);
});
test("real worker requires form session for bridge even when Basic auth is valid",async()=>{
 const settings={TEST_USERNAME:"fixture",TEST_PASSWORD:"fixture-password-not-deployed"};
 const basic="Basic "+btoa(settings.TEST_USERNAME+":"+settings.TEST_PASSWORD);
 assert.equal((await worker.fetch(req("",{headers:{Origin:base,Authorization:basic}}),settings)).status,401);
 const login=await worker.fetch(new Request(base+"/signin",{method:"POST",headers:{Origin:base,"Content-Type":"application/json"},body:JSON.stringify({username:settings.TEST_USERNAME,password:settings.TEST_PASSWORD})}),settings);
 const cookie=login.headers.get("Set-Cookie").split(";")[0];
 assert.equal((await worker.fetch(req("",{headers:{Origin:base,Cookie:cookie}}),settings)).status,503);
});

test("renewal POST reaches only that lease and answers 200", async () => {
 let seen;
 const response = await proxyGuestNetwork(req("/" + lease), env(), session(), async (url, init) => { seen = [String(url), init.method]; return new Response(JSON.stringify(data())); });
 assert.equal(response.status, 200); assert.deepEqual(seen, ["https://gateway.invalid" + path + "/" + lease, "POST"]);
});

test("role header: only host or join, only on new lease, forwarded to gateway", async () => {
 const never = async () => assert.fail("Unexpected gateway request");
 const withRole = (suffix, value) => req(suffix, { headers: { Origin: base, "X-Halo-Guest-Role": value } });
 assert.equal((await proxyGuestNetwork(withRole("", "203.0.113.1:5150"), env(), session(), never)).status, 400);
 assert.equal((await proxyGuestNetwork(withRole("/" + lease, "join"), env(), session(), never)).status, 400);
 let seen;
 const response = await proxyGuestNetwork(withRole("", "join"), env(), session(), async (url, init) => { seen = init.headers.get("X-Halo-Guest-Role"); return new Response(JSON.stringify({ ...data(), role: "guest" })); });
 assert.equal(seen, "join"); assert.equal((await response.json()).role, "guest");
});
