import test from "node:test";
import assert from "node:assert/strict";
import { inputValues, CORE } from "../public/runtime-config.mjs";
import { boot, fetchPinnedWasm, capabilities } from "../public/runtime-adapter.mjs";
import { report, validateManifest } from "../public/model.mjs";

test("Dreamcast input mapping preserves simultaneous controls and releases all buttons", () => {
  const values = inputValues({ keys: ["Enter", "ArrowUp", "Space", "KeyW"], buttons: [0, 1], axes: [0.5, 0, -0.8, 0] });
  assert.equal(values[3], 1); assert.equal(values[4], 1); assert.equal(values[0], 1); assert.equal(values[8], 1);
  assert.equal(values[16], 16384); assert.equal(values[19], 32767); assert.equal(values[21], 26214);
  assert.deepEqual(inputValues({}), new Int32Array(24));
  assert.ok(inputValues({ axes: [NaN, Infinity, 10, -10] }).every(value => value >= 0 && value <= 32767));
});
test("runtime rejects denied, truncated and oversized private bytes", async () => {
  await assert.rejects(fetchPinnedWasm(async () => new Response("denied", { status: 401 })), /unavailable/);
  await assert.rejects(fetchPinnedWasm(async (path, options) => {
    assert.equal(path, CORE.wasm.path); assert.equal(options.credentials, "same-origin");
    return new Response(new Uint8Array(10));
  }), /verification/);
  await assert.rejects(fetchPinnedWasm(async () => new Response(new Uint8Array(CORE.wasm.bytes + 1))), /exceeds/);
  assert.equal(capabilities.guestNetwork, false);
});
test("diagnostics include only bounded numeric audio/runtime summaries", () => {
  const result = report({ manifest: null, imageVerified: false, runtimeState: "running", connectionState: "unavailable", events: [],
    runtimeMetrics: { frameCount: 42, memoryBytes: 268435456, audioState: "running", audioStarvations: 2, maxAudioGapMs: Infinity, password: "private", target: "private", log: "private" } });
  assert.deepEqual(result.metrics, { frameCount: 42, memoryBytes: 268435456, audioStarvations: 2, audioState: "running" });
  assert.ok(!JSON.stringify(result).includes("private"));
});
test("failed authenticated core load creates no frame or audio context", async () => {
  const saved = { window: globalThis.window, fetch: globalThis.fetch };
  let closed = 0;
  const states = [];
  try {
    globalThis.window = { AudioContext: class { resume() { return Promise.resolve(); } close() { closed++; return Promise.resolve(); } } };
    globalThis.fetch = async () => new Response("denied", { status: 401 });
    await assert.rejects(boot({ canvas: {}, imageBytes: new Uint8Array([1]), onState: state => states.push(state) }), /unavailable/);
    assert.equal(closed, 0); assert.deepEqual(states, ["booting", "failed"]);
  } finally {
    for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete globalThis[key]; else globalThis[key] = value; }
  }
});
test("a dotted basename remains pinned while traversal and URL syntax fail", () => {
  const manifest = { schema:1,status:"ready",build:"example-1.2-test",commit:"abababababababababababababababababababab",
    image:{path:"/files/example-image-1.2-test.cdi",bytes:1234567,sha256:"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"} };
  assert.equal(validateManifest(manifest).image.path, manifest.image.path);
  for (const path of ["/files/../image.cdi", "/files/a..b.cdi", "/files/.hidden.cdi", "/files/folder/image.cdi", "/files/a%2eb.cdi", "/files/a.cdi?secret=x", "https://other.invalid/a.cdi"]) {
    assert.throws(() => validateManifest({...manifest,image:{...manifest.image,path}}));
  }
});
