import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile } from "node:fs/promises";
const source = (await readFile(new URL("../public/runtime-frame.mjs", import.meta.url), "utf8")).replace(/^import .*;\r?\n/gm, "");
function fixture({ initialFrames = 0, prepare } = {}) {
  const events = [], listeners = {};
  const core = { FS: { mkdirTree() {}, writeFile() {} }, HEAPU8: new Uint8Array(8),
    _halo_vmu_flush: () => 1, _halo_vmu_provisioned() {}, _halo_vmu_rtc_utc: () => 1793800000,
    _get_current_frame_count: () => initialFrames, _simulate_input() {},
    callMain() { events.push("callMain"); }, pauseMainLoop() { events.push("pause"); }, resumeMainLoop() { events.push("resume"); } };
  const network = { async prepare() { events.push("prepare"); if (prepare) await prepare(); return true; }, async activate() { events.push("activate"); return true; },
    async stop() { events.push("network-stop"); }, metrics: () => ({ txFrames:0,rxFrames:0,txDropped:0,rxDropped:0,deviceStarted:false,transportReady:true }) };
  const window = { addEventListener(name, fn) { listeners[name] = fn; }, async EJS_Runtime(options) { assert.equal(options.noInitialRun,true); events.push("factory"); core.callbacks=options.callbacks; return core; } };
  const context = vm.createContext({ window, document: { body:{}, createElement: () => ({}), head:{ append(script) { queueMicrotask(script.onload); } }, getElementById: () => ({}) },
    CORE:{javascript:{path:"/core.js",sha256:"a".repeat(64)}}, AUDIO_LATENCY_MS:64, inputValues:()=>new Int32Array(24),
    guestNetwork:()=>network, btoa:value=>Buffer.from(value,"binary").toString("base64"), setInterval:()=>1, clearInterval() {}, Int32Array, PerformanceObserver:undefined });
  vm.runInContext(source,context);
  return { api:window.haloRuntime, events, listeners };
}
const options = () => ({imageBytes:new Uint8Array([1]),wasmBinary:new Uint8Array([1]),vmuBytes:new Uint8Array(131072),onState(){}});
test("production frame initializes then pauses, activates lease before resuming, and stops transport",async()=>{
  const {api,events}=fixture();await api.boot(options());
  assert.deepEqual(events,["factory","prepare","callMain","pause","activate","resume"]);
  await api.stop();assert.deepEqual(events.slice(-2),["network-stop","pause"]);
});
test("unexpected synchronous guest frames refuse online transport",async()=>{
  const {api,events}=fixture({initialFrames:1});await api.boot(options());
  assert.ok(!events.includes("activate"));assert.deepEqual(events.slice(-2),["network-stop","resume"]);await api.stop();
});
test("pagehide during lease preparation cannot activate or resume a late boot",async()=>{
  let release;const gate=new Promise(resolve=>release=resolve),{api,events,listeners}=fixture({prepare:()=>gate});
  const boot=api.boot(options());while(!events.includes("prepare"))await new Promise(resolve=>setImmediate(resolve));
  listeners.pagehide();release();await assert.rejects(boot,/stopped/);
  assert.ok(!events.includes("activate"));assert.ok(!events.includes("callMain"));assert.ok(!events.includes("resume"));
});
