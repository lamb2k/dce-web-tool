// Private staged adapter. Not enabled or shipped by current utility.
const MAX_FRAME=1514, MAX_FRAMES=32, MAX_BYTES=48*1024, MAX_AGE=1000, MAX_BUFFERED=65536;
export function validFrame(bytes) {
  return bytes instanceof Uint8Array && bytes.length>=14 && bytes.length<=MAX_FRAME &&
    bytes[12]===8 && (bytes[13]===0 || bytes[13]===6);
}
export function createEthernetBridge(Module,{origin,WebSocketClass=WebSocket,now=()=>performance.now(),wallNow=()=>Date.now(),setTimer=setTimeout,clearTimer=clearTimeout}={}) {
  let stopping=false, socket=null, generation=0, attempt=0, state='unconfigured', queue=[], queuedBytes=0, timer=null, deadline=0, expires=0;
  // Fixed numeric diagnostics only; never retain server reason text or endpoints.
  // 0 none, 1 stop, 2 lease expiry, 3 connect deadline, 4 failure,
  // 5 disconnect, 6 protocol error, 7 core stop. First terminal cause survives cleanup.
  let terminalReason=0, closeCode=0;
  const reasonCodes={closed:1,expired:2,failed:4,disconnected:5,'protocol-error':6,'core-stopped':7};
  const stats={txDropped:0,rxDropped:0,txHighWater:0,txBytesHighWater:0,rxFrames:0,txFrames:0};
  function clearQueue() {queue=[];queuedBytes=0;}
  function closeTransport(next='closed') {
    if(!terminalReason)terminalReason=reasonCodes[next]??0;
    ++attempt; state=next; generation=0; clearQueue();
    if(timer!==null) clearTimer(timer);timer=null;
    const old=socket;socket=null;if(old) {old.onopen=old.onmessage=old.onclose=old.onerror=null;old.close();}
  }
  function stop(next='closed') {closeTransport(next);stopping=true;try{Module._halo_eth_stop();}finally{stopping=false;}}
  function schedule() {if(timer===null)timer=setTimer(pump,10);}
  function pump() {
    timer=null;if(!socket)return;
    if(wallNow()>=expires || (state==='connecting' && now()>=deadline)){if(!terminalReason)terminalReason=wallNow()>=expires?2:3;stop('expired');return;}
    if(state==='gateway-authenticated') {
      while(queue.length) {
        const entry=queue[0];
        if(entry.generation!==generation || now()-entry.time>MAX_AGE) {queue.shift();queuedBytes-=entry.bytes.length;++stats.txDropped;continue;}
        if(socket.bufferedAmount+entry.bytes.length>MAX_BUFFERED)break;
        queue.shift();queuedBytes-=entry.bytes.length;
        try {socket.send(entry.bytes);++stats.txFrames;}catch {++stats.txDropped;stop('failed');return;}
      }
    }
    schedule();
  }
  function connect(lease) {
    // Lease is authenticated server output; endpoints never come from a game packet.
    const url=new URL(lease?.websocketPath,origin);
    const allowed=new URL(origin);
    if(url.origin!==allowed.origin || !/^\/api\/guest-network\/[A-Za-z0-9_-]{16,128}$/.test(url.pathname) || url.search || url.hash ||
       !Number.isSafeInteger(lease.expiresAt) || lease.expiresAt<=wallNow() || lease.expiresAt-wallNow()>3600000)
      throw new Error('Invalid network lease');
    stop();terminalReason=0;closeCode=0;expires=lease.expiresAt;deadline=now()+10000;state='connecting';const ticket=++attempt;
    url.protocol=allowed.protocol==='https:'?'wss:':'ws:';
    try {socket=new WebSocketClass(url.href);}catch(error){stop('failed');throw error;}
    socket.binaryType='arraybuffer';const current=socket;
    current.onopen=()=>{if(ticket!==attempt)return;generation=Module._halo_eth_configure();if(!generation){stop('failed');return;}state='gateway-authenticated';};
    current.onmessage=event=>{
      if(ticket!==attempt || state!=='gateway-authenticated')return;
      if(wallNow()>=expires){stop('expired');return;}
      if(!(event.data instanceof ArrayBuffer)){++stats.rxDropped;stop('protocol-error');return;}
      const bytes=new Uint8Array(event.data);
      if(!validFrame(bytes)){++stats.rxDropped;stop('protocol-error');return;}
      // Re-read HEAPU8 on every callback; never retain a view across memory growth.
      Module.HEAPU8.set(bytes,Module._halo_eth_rx_buffer());
      if(Module._halo_eth_rx(generation,bytes.length))++stats.rxFrames;else ++stats.rxDropped;
    };
    current.onerror=()=>{if(ticket===attempt)stop('failed');};
    current.onclose=event=>{if(ticket===attempt){closeCode=Number.isInteger(event?.code)&&event.code>=1000&&event.code<=4999?event.code:0;stop('disconnected');}};schedule();
  }
  const bridge={connect,stop,
    extendLease(next){if(Number.isSafeInteger(next)&&next>expires&&next-wallNow()<=3600000)expires=next;},
    coreStopped(){if(!stopping)closeTransport('core-stopped');},
    send(bytes,gen){
      if(state!=='gateway-authenticated'||gen!==generation||wallNow()>=expires||!validFrame(bytes)||queue.length>=MAX_FRAMES||queuedBytes+bytes.length>MAX_BYTES){++stats.txDropped;return 0;}
      const owned=bytes.slice();queue.push({bytes:owned,generation:gen,time:now()});queuedBytes+=owned.length;
      stats.txHighWater=Math.max(stats.txHighWater,queue.length);stats.txBytesHighWater=Math.max(stats.txBytesHighWater,queuedBytes);schedule();return 1;
    },
    metrics(){return {state,terminalReason,closeCode,generation,queuedFrames:queue.length,queuedBytes,...stats,guestNetwork:false};}
  };
  Module.haloEthernet=bridge;return bridge;
}
