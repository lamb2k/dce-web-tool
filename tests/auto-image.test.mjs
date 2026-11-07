import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { prepareImage } from "../public/prepare-image.mjs";
const image = new TextEncoder().encode("public synthetic image fixture");
const hash = async bytes => [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(b => b.toString(16).padStart(2, "0")).join("");
const manifest = { schema: 1, status: "ready", build: "fixture-b1", commit: "a".repeat(40), image: { path: "/files/fixture.cdi", bytes: image.length, sha256: await hash(image) } };
function cache() {
  const entries = new Map();
  return { entries, get: async key => entries.get(key), remove: async key => entries.delete(key), put: async (key, bytes) => { entries.clear(); entries.set(key, bytes); } };
}
test("automatic preparation fetches pinned bytes with progress and caches only after verification", async () => {
  const store = cache(), progress = [];
  const bytes = await prepareImage(manifest, { cache: store, onProgress: p => progress.push(p), fetcher: async (path, options) => {
    assert.equal(path, manifest.image.path); assert.equal(options.credentials, "same-origin");
    return new Response(image);
  } });
  assert.deepEqual(bytes, image);
  assert.equal(store.entries.size, 1);
  assert.ok(progress.some(p => p.phase === "downloading" && p.loaded === image.length));
  assert.equal(progress.at(-1).phase, "ready");
});
test("verified cache avoids download; corrupt cache is evicted and refetched", async () => {
  const store = cache(); await store.put(manifest.image.sha256, image);
  assert.deepEqual(await prepareImage(manifest, { cache: store, fetcher: () => assert.fail("cache hit fetched") }), image);
  await store.put(manifest.image.sha256, new Uint8Array(image.length));
  let fetches = 0;
  await prepareImage(manifest, { cache: store, fetcher: async () => { fetches++; assert.equal(store.entries.size, 0); return new Response(image); } });
  assert.equal(fetches, 1); assert.deepEqual(store.entries.get(manifest.image.sha256), image);
});
test("changed hash fetches new build and replaces old cached image", async () => {
  const store = cache(); await store.put(manifest.image.sha256, image);
  const next = new TextEncoder().encode("new synthetic test build");
  const nextManifest = { ...manifest, image: { ...manifest.image, bytes: next.length, sha256: await hash(next) } };
  await prepareImage(nextManifest, { cache: store, fetcher: async () => new Response(next) });
  assert.deepEqual([...store.entries.keys()], [nextManifest.image.sha256]);
});
test("unavailable or full cache does not block verified network image", async () => {
  const broken = { get() { throw new Error("denied"); }, put() { throw new Error("quota"); } };
  assert.deepEqual(await prepareImage(manifest, { cache: broken, fetcher: async () => new Response(image) }), image);
});
test("wrong downloaded hash never becomes ready or enters cache", async () => {
  const store = cache(), progress = [];
  await assert.rejects(prepareImage(manifest, { cache: store, onProgress: p => progress.push(p), fetcher: async () => new Response(new Uint8Array(image.length)) }), /hash/);
  assert.equal(store.entries.size, 0); assert.ok(!progress.some(p => p.phase === "ready"));
});
test("pending manifest never requests image", async () => {
  await assert.rejects(prepareImage({ schema: 1, status: "pending" }, { fetcher: () => assert.fail("pending fetched") }), /No qualified/);
});
test("page prepares image without clicks and enables Play only after verification", async () => {
  const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");
  assert.ok(!html.includes('type="file"')); assert.ok(!html.includes("Load build"));
  const nodes = new Map();
  const node = id => {
    if (!nodes.has(id)) nodes.set(id, { textContent: "", disabled: true, listeners: {}, addEventListener(event, fn) { this.listeners[event] = fn; } });
    return nodes.get(id);
  };
  const saved = Object.fromEntries(["document", "window", "requestAnimationFrame", "fetch"].map(key => [key, globalThis[key]]));
  const requests = [];
  try {
    globalThis.document = { getElementById: node, addEventListener() {} };
    globalThis.window = { addEventListener() {} };
    globalThis.requestAnimationFrame = () => {};
    globalThis.fetch = async path => {
      requests.push(path);
      if (path === "/files/build.json") return Response.json(manifest);
      if (path === manifest.image.path) return new Response(image);
      assert.fail(`unexpected request ${path}`);
    };
    await import(`../public/app.mjs?fixture=${Date.now()}`);
    for (let n = 0; n < 100 && node("status").textContent !== "Ready"; n++) await new Promise(resolve => setTimeout(resolve, 5));
    assert.deepEqual(requests, ["/files/build.json", manifest.image.path]);
    assert.equal(node("status").textContent, "Ready");
    assert.equal(node("play").disabled, false);
    assert.equal(node("download-progress").value, image.length);
    assert.ok(!nodes.has("image")); assert.ok(!nodes.has("load"));
    nodes.clear();
    globalThis.fetch = async path => path === "/files/build.json" ? Response.json(manifest) : new Response(new Uint8Array(image.length));
    await import(`../public/app.mjs?bad-hash=${Date.now()}`);
    for (let n = 0; n < 100 && !node("status").textContent.includes("Build unavailable"); n++) await new Promise(resolve => setTimeout(resolve, 5));
    assert.match(node("status").textContent, /Build unavailable/);
    assert.equal(node("play").disabled, true);
  } finally {
    for (const [key, value] of Object.entries(saved)) { if (value === undefined) delete globalThis[key]; else globalThis[key] = value; }
  }
});
