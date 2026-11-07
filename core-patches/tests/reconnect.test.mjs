import test from 'node:test';
import assert from 'node:assert/strict';
import { createEthernetBridge } from '../adapter/browser-ethernet.mjs';
test('reentrant core refusal cannot become gateway-authenticated',()=>{
 let socket,stops=0;
 class Socket {constructor(){socket=this;}close(){this.closed=true;}}
 const module={_halo_eth_configure:()=>0,_halo_eth_stop(){stops++;module.haloEthernet.coreStopped();}};
 const bridge=createEthernetBridge(module,{origin:'https://test.invalid',WebSocketClass:Socket,now:()=>0,wallNow:()=>1,setTimer:()=>1,clearTimer(){}});
 bridge.connect({websocketPath:'/api/guest-network/abcdefghijklmnop',expiresAt:1000});socket.onopen();
 assert.equal(bridge.metrics().state,'failed');assert.equal(bridge.metrics().generation,0);assert.ok(socket.closed);assert.equal(stops,2);
});
