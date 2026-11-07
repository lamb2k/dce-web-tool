import test from 'node:test';
import assert from 'node:assert/strict';
import {createEthernetBridge} from '../core-patches/adapter/browser-ethernet.mjs';
function fixture(){
 let time=0,wall=100000,gen=1,rx=[];const timers=new Map();let tid=0;
 class Socket {static all=[];constructor(url){this.url=url;this.bufferedAmount=0;this.sent=[];Socket.all.push(this);}send(b){this.sent.push(b);}close(){this.closed=true;}}
 const module={HEAPU8:new Uint8Array(4096),_halo_eth_stop(){++gen;module.haloEthernet.coreStopped();},_halo_eth_configure(){return ++gen;},_halo_eth_rx_buffer(){return 128;},_halo_eth_rx(g,n){rx.push({g,bytes:module.HEAPU8.slice(128,128+n)});return 1;}};
 const bridge=createEthernetBridge(module,{origin:'https://test.invalid',WebSocketClass:Socket,now:()=>time,wallNow:()=>wall,setTimer:f=>{timers.set(++tid,f);return tid;},clearTimer:id=>timers.delete(id)});
 const lease={websocketPath:'/api/guest-network/abcdefghijklmnop',expiresAt:200000};
 const frame=new Uint8Array(1514);frame[12]=8;
 function pump(){const fs=[...timers.values()];timers.clear();for(const f of fs)f();}
 function open(){bridge.connect(lease);const socket=Socket.all.at(-1);socket.onopen();return socket;}
 return {bridge,module,lease,frame,open,pump,Socket,rx,advance:n=>time+=n,expire:()=>wall=200000};
}
test('lease route cannot select other origin/query/fragment or expired lease',()=>{
 const f=fixture();for(const path of ['https://evil.invalid/api/guest-network/abcdefghijklmnop','/api/guest-network/x','/api/guest-network/abcdefghijklmnop?secret=x','/api/guest-network/abcdefghijklmnop#x'])assert.throws(()=>f.bridge.connect({...f.lease,websocketPath:path}));
 assert.throws(()=>f.bridge.connect({...f.lease,expiresAt:100000}));assert.equal(f.Socket.all.length,0);
});
test('owned TX bounded32 and buffered ceiling; stale RX never delivered after stop',()=>{
 const f=fixture(),s=f.open(),g=f.bridge.metrics().generation;s.bufferedAmount=65536;
 for(let i=0;i<32;i++)assert.equal(f.bridge.send(f.frame,g),1);
 assert.equal(f.bridge.send(f.frame,g),0);assert.equal(f.bridge.metrics().queuedBytes,48448);
 f.frame[0]=99;f.pump();assert.equal(s.sent.length,0);s.bufferedAmount=0;f.pump();assert.equal(s.sent.length,32);assert.equal(s.sent[0][0],0);
 const old=s.onmessage;f.bridge.stop();old({data:f.frame.buffer});assert.equal(f.rx.length,0);assert.equal(f.bridge.metrics().queuedBytes,0);
 assert.equal(f.bridge.send(f.frame,g),0);
});
test('RX copied through current heap; core stop disconnects and old generation rejected',()=>{
 const f=fixture(),s=f.open(),g=f.bridge.metrics().generation;f.module.HEAPU8=new Uint8Array(8192);s.onmessage({data:f.frame.buffer});assert.equal(f.rx.length,1);assert.equal(f.rx[0].g,g);
 f.bridge.coreStopped();assert.equal(s.closed,true);assert.equal(f.bridge.metrics().state,'core-stopped');f.open();assert.equal(f.bridge.send(f.frame,g),0);
});
test('queue age, lease expiry, malformed frames and connection timeout fail bounded',()=>{
 let f=fixture(),s=f.open(),g=f.bridge.metrics().generation;s.bufferedAmount=65536;f.bridge.send(f.frame,g);f.advance(1001);f.pump();assert.equal(f.bridge.metrics().queuedFrames,0);assert.equal(f.bridge.metrics().txDropped,1);
 f.expire();f.pump();assert.equal(f.bridge.metrics().state,'expired');assert.ok(s.closed);
 f=fixture();s=f.open();s.onmessage({data:'text forbidden'});assert.equal(f.bridge.metrics().state,'protocol-error');assert.ok(s.closed);
 f=fixture();f.bridge.connect(f.lease);f.advance(10000);f.pump();assert.equal(f.bridge.metrics().state,'expired');
});
test('gateway authenticated never fabricates DHCP or game admission capability',()=>{
 const f=fixture();f.open();assert.equal(f.bridge.metrics().state,'gateway-authenticated');assert.equal(f.bridge.metrics().guestNetwork,false);
});


test('terminal close reason survives cleanup and clears only on new connection',()=>{
 const f=fixture(),s=f.open();s.onclose({code:1006,reason:'must never retain remote text'});
 assert.equal(f.bridge.metrics().terminalReason,5);assert.equal(f.bridge.metrics().closeCode,1006);
 f.bridge.stop();assert.equal(f.bridge.metrics().terminalReason,5);assert.equal(f.bridge.metrics().closeCode,1006);
 assert.ok(!JSON.stringify(f.bridge.metrics()).includes('remote text'));
 f.open();assert.equal(f.bridge.metrics().terminalReason,0);assert.equal(f.bridge.metrics().closeCode,0);
});
test('expiry, connect deadline, protocol and core teardown remain distinguishable after cleanup',()=>{
 for(const [trigger,code] of [[f=>{f.expire();f.pump()},2],[f=>{f.bridge.connect(f.lease);f.advance(10000);f.pump()},3],[f=>f.Socket.all.at(-1).onmessage({data:'private'}),6],[f=>f.bridge.coreStopped(),7]]){
  const f=fixture();f.open();trigger(f);f.bridge.stop();assert.equal(f.bridge.metrics().terminalReason,code);
 }
});
test('invalid close codes are omitted from numeric diagnostics',()=>{
 const f=fixture(),s=f.open();s.onclose({code:'private',reason:'private'});
 assert.equal(f.bridge.metrics().closeCode,0);assert.equal(f.bridge.metrics().terminalReason,5);
});


test('rejected lease retains prior terminal metadata; error cleanup invents no close code',()=>{
 const f=fixture(),s=f.open();s.onclose({code:1006});
 assert.throws(()=>f.bridge.connect({...f.lease,expiresAt:1}));
 assert.equal(f.bridge.metrics().terminalReason,5);assert.equal(f.bridge.metrics().closeCode,1006);
 const next=f.open();next.onerror();assert.equal(f.bridge.metrics().terminalReason,4);assert.equal(f.bridge.metrics().closeCode,0);
 assert.equal(next.onclose,null);f.bridge.stop();assert.equal(f.bridge.metrics().terminalReason,4);
});
test('public and staged Ethernet adapters retain identical executable source',async()=>{
 const {readFile}=await import('node:fs/promises');
 const strip=text=>{const body=text.replace(/^\/\/ SPDX[^\n]*\n/,'');return body.slice(body.indexOf('\n'));};
 assert.equal(strip(await readFile(new URL('../public/browser-ethernet.mjs',import.meta.url),'utf8')),strip(await readFile(new URL('../core-patches/adapter/browser-ethernet.mjs',import.meta.url),'utf8')));
});
