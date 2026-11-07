import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import worker from "../worker.mjs";
import { validateManifest, verifyImage, matchTarget, report, readBounded } from "../public/model.mjs";
import { capabilities, boot } from "../public/runtime-adapter.mjs";
const username = "test-fixture";
const password = "fixture-only-not-a-deployment-secret";
const auth = `Basic ${btoa(`${username}:${password}`)}`;
const request = (path, options = {}) => new Request(`https://test.invalid${path}`, options);
function environment() {
  let calls = 0;
  return { TEST_USERNAME: username, TEST_PASSWORD: password,
    ASSETS: { async fetch(req) { calls++; assert.equal(req.headers.get("Authorization"), null); return new Response("asset"); } },
    get calls() { return calls; } };
}
test("all routes reject anonymous requests before assets or private files", async () => {
  const env = environment();
  env.TEST_FILES = { get() { assert.fail("private object reached without auth"); } };
  for (const path of ["/", "/index.html", "/app.mjs", "/runtime/core.wasm", "/files/build.json", "/files/image.cdi", "/missing"]) {
    const res = await worker.fetch(request(path), env);
    assert.equal(res.status, 401, path);
    assert.match(res.headers.get("WWW-Authenticate"), /^Basic /);
    assert.equal(res.headers.get("Cache-Control"), "private, no-store");
  }
  assert.equal(env.calls, 0);
});
test("missing, empty and short credentials fail closed even with auth", async () => {
  for (const override of [{ TEST_USERNAME: undefined }, { TEST_PASSWORD: undefined }, { TEST_PASSWORD: "" }, { TEST_PASSWORD: "weak" }]) {
    const env = Object.assign(environment(), override);
    assert.equal((await worker.fetch(request("/", { headers: { Authorization: auth } }), env)).status, 503);
    assert.equal(env.calls, 0);
  }
});
test("bad or malformed credentials rejected", async () => {
  for (const value of ["Basic !", "Bearer no", "Basic " + btoa(username + ":wrong"), "Basic " + btoa("other:" + password)]) {
    const env = environment();
    assert.equal((await worker.fetch(request("/" , { headers: { Authorization: value } }), env)).status, 401);
    assert.equal(env.calls, 0);
  }
});
test("authenticated assets carry isolation and no-store headers", async () => {
  const env = environment();
  const res = await worker.fetch(request("/app.mjs", { headers: { Authorization: auth } }), env);
  assert.equal(res.status, 200); assert.equal(await res.text(), "asset"); assert.equal(env.calls, 1);
  assert.equal(res.headers.get("Cross-Origin-Opener-Policy"), "same-origin");
  assert.equal(res.headers.get("Cross-Origin-Embedder-Policy"), "require-corp");
  assert.equal(res.headers.get("Cache-Control"), "private, no-store");
});
test("public HTTP, write methods and query credentials rejected", async () => {
  const env = environment();
  assert.equal((await worker.fetch(new Request("http://test.invalid/"), env)).status, 403);
  assert.equal((await worker.fetch(request("/", { method: "POST", headers: { Authorization: auth } }), env)).status, 405);
  assert.equal((await worker.fetch(request("/?password=no", { headers: { Authorization: auth } }), env)).status, 400);
  assert.equal(env.calls, 0);
});
test("private files stream after auth; ranges and HEAD retained", async () => {
  const env = environment(); let getCalls = 0, headCalls = 0;
  const object = { size: 8, httpEtag: '"fixture"', writeHttpMetadata() {} };
  env.TEST_FILES = {
    async get(key, options) { getCalls++; assert.equal(key, "image.cdi"); assert.equal(options.range.get("Range"), "bytes=2-4"); return { ...object, body: "abc", range: { offset: 2, length: 3 } }; },
    async head(key) { headCalls++; assert.equal(key, "image.cdi"); return object; }
  };
  const partial = await worker.fetch(request("/files/image.cdi", { headers: { Authorization: auth, Range: "bytes=2-4" } }), env);
  assert.equal(partial.status, 206); assert.equal(partial.headers.get("Content-Range"), "bytes 2-4/8"); assert.equal(await partial.text(), "abc");
  const head = await worker.fetch(request("/files/image.cdi", { method: "HEAD", headers: { Authorization: auth } }), env);
  assert.equal(head.status, 200); assert.equal(head.headers.get("Content-Length"), "8"); assert.equal(await head.text(), "");
  assert.equal(getCalls, 1); assert.equal(headCalls, 1); assert.equal(env.calls, 0);
});
test("private files fail closed when unbound or missing", async () => {
  const env = environment(); const req = request("/files/build.json", { headers: { Authorization: auth } });
  assert.equal((await worker.fetch(req, env)).status, 503);
  env.TEST_FILES = { async get() { return null; } };
  assert.equal((await worker.fetch(req, env)).status, 404);
  assert.equal(env.calls, 0);
});
test("pins.json matches the core patch files", async () => {
  const { readFile } = await import("node:fs/promises");
  const { createHash } = await import("node:crypto");
  const folder = new URL("../core-patches/", import.meta.url);
  const pins = JSON.parse(await readFile(new URL("pins.json", folder), "utf8"));
  for (const section of [pins.patchSha256, pins.adapterSha256])
    for (const [name, sum] of Object.entries(section))
      assert.equal(createHash("sha256").update(await readFile(new URL(name, folder))).digest("hex"), sum, name);
});
test("configuration authenticates every asset and disables alternate preview URLs", async () => {
  const config = JSON.parse(await readFile(new URL("../wrangler.example.jsonc", import.meta.url), "utf8"));
  assert.equal(config.assets.run_worker_first, true);
  assert.equal(config.assets.not_found_handling, "none");
  assert.equal(config.workers_dev, true); assert.equal(config.preview_urls, false);
  assert.deepEqual(config.r2_buckets, [{ binding: "TEST_FILES", bucket_name: "<your-private-bucket>" }]);
});
const image = new TextEncoder().encode("fixture image");
const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", image))].map(b => b.toString(16).padStart(2, "0")).join("");
const manifest = { schema: 1, status: "ready", build: "fixture-b1", commit: "a".repeat(40), image: { bytes: image.length, sha256: digest, path: "/files/fixture.cdi" } };
test("manifest and image are pinned; bad size/hash rejected", async () => {
  assert.equal(await verifyImage(image, validateManifest(manifest)), digest);
  await assert.rejects(verifyImage(new Uint8Array(2), manifest), /size/);
  await assert.rejects(verifyImage(new Uint8Array(image.length), manifest), /hash/);
  for (const path of ["https://elsewhere.invalid/x.cdi", "/files/../x.cdi", "/files/x.cdi?password=no"]) {
    assert.throws(() => validateManifest({ ...manifest, image: { ...manifest.image, path } }));
  }
  assert.throws(() => validateManifest({ ...manifest, image: { ...manifest.image, bytes: 1024 ** 3 } }));
});
test("pending manifest cannot boot or claim network readiness", async () => {
  const pending = validateManifest(JSON.parse(await readFile(new URL("../public/manifest.json", import.meta.url))));
  assert.equal(pending.status, "pending");
  await assert.rejects(verifyImage(image, pending), /No qualified/);
  assert.deepEqual(capabilities, { boot: true, guestNetwork: false, input: true });
  await assert.rejects(boot(), /Verified build required/);
});
test("downloads stop at declared size even when server sends excess bytes", async () => {
  assert.equal(new TextDecoder().decode(await readBounded(new Response("abc"), 3)), "abc");
  let cancelled = false;
  const stream = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(6)); }, cancel() { cancelled = true; } });
  await assert.rejects(readBounded(new Response(stream), 5), /exceeds/);
  assert.equal(cancelled, true);
});
test("diagnostics omit address, credentials, filenames and arbitrary data", () => {
  const data = report({ manifest, imageVerified: true, runtimeState: "unavailable", connectionState: "not-connected", address: "secret-address", events: [{ at: "now", code: "image-verified", password: "secret-password" }] });
  const text = JSON.stringify(data);
  assert.ok(!text.includes("secret")); assert.equal(data.imageSha256, digest);
  assert.equal(report({ manifest, imageVerified: false, events: [] }).imageSha256, null);
  assert.equal(matchTarget(" host.example:5150 "), "host.example:5150");
  assert.throws(() => matchTarget("https://host/?secret=foo"));
});


test('report retains only bounded numeric network terminal metadata',()=>{
 const data=report({events:[],runtimeMetrics:{networkTerminalReason:5,networkCloseCode:1006,networkReason:'private'}});
 assert.equal(data.metrics.networkTerminalReason,5);assert.equal(data.metrics.networkCloseCode,1006);assert.ok(!JSON.stringify(data).includes('private'));
 for(const invalid of [-1,8,1.5,'private'])assert.equal(report({events:[],runtimeMetrics:{networkTerminalReason:invalid}}).metrics.networkTerminalReason,undefined);
 for(const invalid of [-1,999,5000,1006.5,'private'])assert.equal(report({events:[],runtimeMetrics:{networkCloseCode:invalid}}).metrics.networkCloseCode,undefined);
 assert.equal(report({events:[],runtimeMetrics:{networkCloseCode:0}}).metrics.networkCloseCode,0);
});
