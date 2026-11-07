import test from "node:test";
import assert from "node:assert/strict";
import { proxyDeviceEnrollment } from "../enrollment-proxy.mjs";
import worker from "../worker.mjs";

const origin="https://test.invalid", path="/api/device-enrollment/";
const publicKey="ed25519:a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";
const masterPublicKey="ed25519:d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
const session=()=>({id:"a".repeat(64),expiresAt:Date.now()+600000});
const env=()=>({GUEST_GATEWAY_URL:"https://gateway.invalid",GUEST_GATEWAY_KEY:"k".repeat(64)});
const request=(action,body,extra={})=>new Request(origin+path+action,{method:"POST",
  headers:{Origin:origin,"Content-Type":"application/json"},body:body===undefined?undefined:JSON.stringify(body),...extra});
const configuration=()=>({protocol:1,configured:true,masterPublicKey,masterKeyId:"10ba682c8ad13513",
  proofDomain:"DCE-Device-Enrollment-v1",challengeTtl:60});
const challenge=()=>({protocol:1,masterKeyId:"10ba682c8ad13513",keyId:"1325b850c2871916",publicKey,
  challenge:"b".repeat(32),serverTime:Math.floor(Date.now()/1000),expires:Math.floor(Date.now()/1000)+60,sessionBinding:"a".repeat(64)});
const approval=()=>({ok:true,masterKeyId:"10ba682c8ad13513",keyId:"1325b850c2871916",publicKey,
  approved:true,created:false,serverTime:Math.floor(Date.now()/1000)});
const response=value=>async()=>new Response(JSON.stringify(value));
const register=()=>({publicKey,challenge:"b".repeat(32),signature:btoa("x".repeat(64))});

test("enrollment rejects missing form identity, origin, routes and private fields before upstream",async()=>{
 const never=async()=>assert.fail("unexpected upstream");
 for(const [req,identity,status] of [[request("challenge",{publicKey}),null,401],
   [request("challenge",{publicKey},{headers:{Origin:"https://evil.invalid"}}),session(),403],
   [request("challenge",{publicKey,seed:"never send"}),session(),400],
   [request("register",{...register(),privateKey:"never send"}),session(),400],
   [request("challenge",{publicKey},{body:"x".repeat(513)}),session(),400],
   [request("config",{}),session(),400],[request("unknown"),session(),404]])
  assert.equal((await proxyDeviceEnrollment(req,env(),identity,never)).status,status);
});

test("fresh trusted headers and public fields only cross enrollment boundary",async()=>{
 const identity=session();
 const result=await proxyDeviceEnrollment(request("challenge",{publicKey},{headers:{Origin:origin,"Content-Type":"application/json",
   Cookie:"private-cookie",Authorization:"private-auth","X-Halo-Session":"spoof","X-DCE-Enrollment-Session":"spoof"}}),env(),identity,
   async(url,init)=>{
     assert.equal(String(url),"https://gateway.invalid"+path+"challenge");
     assert.equal(init.redirect,"manual");assert.ok(init.signal);
     assert.equal(init.headers.get("Cookie"),null);assert.equal(init.headers.get("Authorization"),null);
     assert.equal(init.headers.get("X-DCE-Enrollment-Session"),null);
     assert.equal(init.headers.get("X-Halo-Session"),identity.id);
     assert.deepEqual(JSON.parse(init.body),{publicKey});
     return new Response(JSON.stringify({...challenge(),privateToken:"strip"}),{headers:{"Set-Cookie":"strip"}});
   });
 assert.equal(result.status,200);assert.equal(result.headers.get("Set-Cookie"),null);
 assert.equal((await result.json()).privateToken,undefined);
});

test("bootstrap and register retain only validated public identity and authenticated time",async()=>{
 const config=await proxyDeviceEnrollment(request("config"),env(),session(),response(configuration()));
 assert.equal(config.status,200);assert.deepEqual(await config.json(),configuration());
 const approved=await proxyDeviceEnrollment(request("register",register()),env(),session(),response(approval()));
 assert.equal(approved.status,200);assert.equal((await approved.json()).created,false);
 for(const [action,body,value] of [["config",undefined,{...configuration(),masterKeyId:"0".repeat(16)}],
   ["challenge",{publicKey},{...challenge(),sessionBinding:"b".repeat(64)}],
   ["challenge",{publicKey},{...challenge(),expires:Math.floor(Date.now()/1000)+61}],
   ["register",register(),{...approval(),keyId:"0".repeat(16)}],
   ["register",register(),{...approval(),masterKeyId:undefined}],
   ["register",register(),{...approval(),serverTime:"unsafe"}]])
  assert.equal((await proxyDeviceEnrollment(request(action,body),env(),session(),response(value))).status,502);
});

test("unconfigured, redirected, oversized and canceled enrollment remains unavailable",async()=>{
 assert.equal((await proxyDeviceEnrollment(request("config"),{},session(),async()=>assert.fail())).status,503);
 assert.equal((await proxyDeviceEnrollment(request("config"),env(),session(),async()=>new Response("secret",{status:302}))).status,502);
 assert.equal((await proxyDeviceEnrollment(request("config"),env(),session(),async()=>new Response("x".repeat(2049)))).status,502);
 const controller=new AbortController();let forwarded;
 const pending=proxyDeviceEnrollment(request("challenge",{publicKey},{signal:controller.signal}),env(),session(),async(_url,init)=>{
   forwarded=init.signal;
   return new Promise((_resolve,reject)=>init.signal.addEventListener("abort",()=>reject(Error("aborted")),{once:true}));
 });
 while(!forwarded)await new Promise(resolve=>setTimeout(resolve,1));
 controller.abort();assert.equal((await pending).status,504);assert.equal(forwarded.aborted,true);
});

test("shared Basic identity cannot enroll a device",async()=>{
 const settings={TEST_USERNAME:"fixture",TEST_PASSWORD:"fixture-password-not-deployed"};
 const result=await worker.fetch(request("config",undefined,{headers:{Origin:origin,
   Authorization:"Basic "+btoa(settings.TEST_USERNAME+":"+settings.TEST_PASSWORD)}}),settings);
 assert.equal(result.status,401);
});

test("client tag reaches the gateway, an invalid one does not",async()=>{
 const headers=[];
 const capture=async(_,init)=>{headers.push(init.headers.get("X-Halo-Client"));return new Response("{}",{status:429});};
 await proxyDeviceEnrollment(request("challenge",{publicKey}),env(),{...session(),client:"1".repeat(32)},capture);
 await proxyDeviceEnrollment(request("challenge",{publicKey}),env(),{...session(),client:"bad"},capture);
 assert.deepEqual(headers,["1".repeat(32),null]);
});
