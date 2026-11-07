import test from "node:test";
import assert from "node:assert/strict";
import { guestNetwork } from "../public/guest-network.mjs";
const token = "a".repeat(43), path = "/api/guest-network/" + token;
const lease = { lease: token, websocketPath: path, expiresAt: 100000, mode: "dce" };
function setup(fetcher, socketState = "gateway-authenticated") {
  const events = []; let state = "unconfigured", time = 1;
  const network = guestNetwork({}, { origin: "https://test.invalid", fetcher,
    now: () => time, sleep: async ms => { time += ms; }, bridgeFactory: () => ({
      connect(value) { events.push("connect"); assert.equal(value.websocketPath, path); state = socketState; },
      stop() { events.push("stop"); state = "closed"; }, metrics: () => ({ state, txFrames:0, rxFrames:0, txDropped:0, rxDropped:0, queuedBytes:0, txHighWater:0 }),
    }) });
  return { network, events };
}
test("lease is authenticated and prepared before connect, then closed and revoked", async () => {
  const requests = [], {network, events} = setup(async (url, options) => {
    requests.push([url, options.method]); assert.equal(options.credentials,"same-origin"); assert.equal(options.redirect,"error"); assert.equal(options.body,undefined);
    return options.method === "POST" ? Response.json(lease) : new Response(null,{status:204});
  });
  assert.equal(await network.prepare(),true); assert.deepEqual(events,[]);
  assert.equal(await network.activate(),true); assert.equal(network.metrics().guestNetwork,false);
  await network.stop(); assert.deepEqual(events,["connect","stop"]);
  assert.deepEqual(requests,[["/api/guest-network","POST"],[path,"DELETE"]]);
  assert.equal(await network.activate(),false); assert.equal(await network.prepare(),false);
});
test("abort before request creates no lease or connection",async()=>{
  let requests=0;const {network}=setup(async()=>{requests++;throw Error()});
  await network.stop();assert.equal(await network.prepare(),false);assert.equal(await network.activate(),false);assert.equal(requests,0);
});
test("abort during POST revokes an abort-ignoring late response and never connects",async()=>{
  let finish, signal;const requests=[];
  const {network,events}=setup((url,options)=>{requests.push([url,options.method]);if(options.method==='POST'){signal=options.signal;return new Promise(r=>finish=r)}return Promise.resolve(new Response(null,{status:204}));});
  const prepared=network.prepare();await network.stop();assert.equal(signal.aborted,true);
  finish(Response.json(lease));assert.equal(await prepared,false);assert.equal(await network.activate(),false);
  assert.deepEqual(events,['stop']);assert.deepEqual(requests,[['/api/guest-network','POST'],[path,'DELETE']]);
});
test("abort after preparation revokes without socket creation",async()=>{
  const methods=[],{network,events}=setup(async(url,options)=>{methods.push(options.method);return options.method==='POST'?Response.json(lease):new Response(null,{status:204})});
  await network.prepare();await network.stop();assert.equal(await network.activate(),false);assert.deepEqual(events,['stop']);assert.deepEqual(methods,['POST','DELETE']);
});
test("failed or timed out socket closes and revokes with offline fallback",async()=>{
  for(const socketState of ['failed','connecting']){
    const methods=[],{network,events}=setup(async(url,options)=>{methods.push(options.method);return options.method==='POST'?Response.json(lease):new Response(null,{status:204})},socketState);
    await network.prepare();assert.equal(await network.activate(),false);assert.deepEqual(events,['connect','stop']);assert.deepEqual(methods,['POST','DELETE']);assert.equal(network.metrics().state,'unavailable');
  }
});
test("unconfigured gateway and invalid endpoint cannot open a socket",async()=>{
  const offline=setup(async()=>new Response(null,{status:503}));assert.equal(await offline.network.prepare(),false);assert.equal(await offline.network.activate(),false);assert.deepEqual(offline.events,[]);
  const invalid=setup(async()=>Response.json({...lease,websocketPath:'https://elsewhere.invalid/secret'}));assert.equal(await invalid.network.prepare(),false);assert.equal(await invalid.network.activate(),false);assert.deepEqual(invalid.events,[]);
});
test("invalid DCE metadata revokes only its bounded same-origin issued path",async()=>{
  const requests=[],{network}=setup(async(url,options)=>{requests.push([url,options.method]);return options.method==='POST'?Response.json({...lease,mode:'native'}):new Response(null,{status:204})});
  assert.equal(await network.prepare(),false);assert.deepEqual(requests,[['/api/guest-network','POST'],[path,'DELETE']]);
});
test("stop while waiting for socket readiness prevents late activation",async()=>{
  const {network,events}=setup(async(url,options)=>options.method==='POST'?Response.json(lease):new Response(null,{status:204}),'connecting');
  await network.prepare();const activation=network.activate();await network.stop();assert.equal(await activation,false);
  assert.deepEqual(events,['connect','stop']);assert.equal(network.metrics().state,'stopped');
});


test('transport terminal reason remains visible after automatic lease cleanup',async()=>{
 let state='unconfigured',reason=0;const methods=[];
 const network=guestNetwork({}, {origin:'https://test.invalid',now:()=>1,
  fetcher:async(url,options)=>{methods.push(options.method);return options.method==='POST'?Response.json(lease):new Response(null,{status:204})},
  bridgeFactory:()=>({connect(){state='gateway-authenticated'},stop(){state='closed'},metrics:()=>({state,terminalReason:reason,closeCode:1006})})});
 await network.prepare();await network.activate();state='disconnected';reason=5;
 const first=network.metrics();assert.equal(first.terminalReason,5);assert.equal(first.closeCode,1006);
 assert.equal(network.metrics().state,'stopped');assert.equal(network.metrics().terminalReason,5);
 await network.stop();assert.deepEqual(methods,['POST','DELETE']);
});

test("frame enables BBA by the core's actual option name", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../public/runtime-frame.mjs", import.meta.url), "utf8");
  assert.match(source, /reicast_emulate_bba = "enabled"/);
  assert.doesNotMatch(source, /reicast_enable_bba/);
});

test("frame shows VMU 1's LCD in the lower right on every session", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../public/runtime-frame.mjs", import.meta.url), "utf8");
  assert.match(source, /reicast_vmu1_screen_display = "enabled"/);
  assert.match(source, /reicast_vmu1_screen_position = "Lower Right"/);
  assert.match(source, /reicast_vmu1_screen_size_mult = "2x"/);
});

function renewRig(replies) {
  let clock = 1000000, timer = null, extended = 0, state = "gateway-authenticated"; const calls = [];
  const expiry = () => clock + 600000;
  const fetcher = async (url, init) => { calls.push(init.method);
    if (init.method === "DELETE") return new Response(null, { status: 204 });
    if (url === "/api/guest-network") return new Response(JSON.stringify({ lease: "A".repeat(43), websocketPath: "/api/guest-network/" + "A".repeat(43), mode: "dce", expiresAt: expiry() }), { status: 201 });
    const reply = replies.shift();
    if (reply === "fail") return new Response("", { status: 503 });
    return new Response(JSON.stringify({ lease: "A".repeat(43), websocketPath: "/api/guest-network/" + "A".repeat(43), mode: "dce", expiresAt: reply === "same" ? rig.first : expiry() }), { status: 200 });
  };
  const rig = { calls, tick: async ms => { clock += ms; const run = timer; timer = null; await run?.(); }, get extended() { return extended; }, pending: () => timer !== null, setState(v) { state = v; } };
  rig.net = guestNetwork({}, { origin: "https://t.invalid", fetcher, now: () => clock, sleep: async () => {}, setTimer: run => (timer = run, 1), clearTimer: () => { timer = null; },
    bridgeFactory: () => ({ connect() {}, stop() {}, extendLease(v) { extended = v; }, metrics: () => ({ state }) }) });
  rig.first = expiry();
  return rig;
}
test("renews before expiry, stops with session", async () => {
  const rig = renewRig(["ok"]); await rig.net.prepare(); await rig.net.activate();
  await rig.tick(300000);
  assert.equal(rig.net.metrics().renewals, 1); assert.equal(rig.net.metrics().renewState, "renewed"); assert.ok(rig.extended > rig.first);
  assert.ok(rig.pending()); await rig.net.stop(); assert.equal(rig.pending(), false);
});
test("failed renewal is reported and retried; no growth reports final", async () => {
  const rig = renewRig(["fail", "same"]); await rig.net.prepare(); await rig.net.activate();
  await rig.tick(300000);
  assert.equal(rig.net.metrics().renewState, "failed"); assert.equal(rig.net.metrics().renewFailures, 1); assert.ok(rig.pending());
  await rig.tick(15000);
  assert.equal(rig.net.metrics().renewState, "final"); assert.equal(rig.pending(), false);
});
test("lost transport stops renewal", async () => {
  const rig = renewRig([]); await rig.net.prepare(); await rig.net.activate(); rig.setState("disconnected");
  await rig.tick(300000);
  assert.ok(!rig.calls.includes("POST-renew")); assert.equal(rig.calls.at(-1), "DELETE");
});
