// Optional workerd check using an existing Miniflare installation; no remote resource access.
// MINIFLARE_MODULE must name its module entry point as a file URL.
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
if (!process.env.MINIFLARE_MODULE) throw new Error("Set MINIFLARE_MODULE to installed Miniflare entry point");
const { Miniflare, convertV4MiniflareOptions = options => options } = await import(process.env.MINIFLARE_MODULE);
const root = new URL("../", import.meta.url);
const common = {
  modules: true, scriptPath: fileURLToPath(new URL("worker.mjs", root)),
  name: "halo-browser-test", compatibilityDate: process.env.MINIFLARE_DATE ?? "2026-11-04",
  assets: { directory: fileURLToPath(new URL("public", root)), binding: "ASSETS", run_worker_first: true,
    routerConfig: { has_user_worker: true, invoke_user_worker_ahead_of_assets: true } },
  r2Buckets: ["TEST_FILES"]
};
const instance = new Miniflare(convertV4MiniflareOptions({ host: "127.0.0.1", port: 0, r2Persist: false, workers: [{ ...common, bindings: { TEST_USERNAME: "fixture", TEST_PASSWORD: "fixture-not-deployed-password" } }] }));
const unconfigured = new Miniflare(convertV4MiniflareOptions({ host: "127.0.0.1", port: 0, r2Persist: false, workers: [common] }));
try {
  const headers = { Authorization: "Basic " + btoa("fixture:fixture-not-deployed-password") };
  const bucket = await instance.getR2Bucket("TEST_FILES");
  await bucket.put("fixture.cdi", "synthetic-only");
  for (const path of ["/", "/app.mjs", "/runtime-adapter.mjs", "/files/fixture.cdi"]) {
    const anonymous = await instance.dispatchFetch(`https://test.invalid${path}`);
    assert.equal(anonymous.status, 401, `${path}: ${(await anonymous.text()).slice(0, 200)}`);
    assert.equal((await unconfigured.dispatchFetch(`https://test.invalid${path}`, { headers })).status, 503, path);
  }
  const page = await instance.dispatchFetch("https://test.invalid/", { headers });
  assert.equal(page.status, 200); assert.match(await page.text(), /Halo DCE Network Test Tool/);
  const file = await instance.dispatchFetch("https://test.invalid/files/fixture.cdi", { headers });
  assert.equal(file.status, 200); assert.equal(await file.text(), "synthetic-only");
  const range = await instance.dispatchFetch("https://test.invalid/files/fixture.cdi", { headers: { ...headers, Range: "bytes=0-3" } });
  assert.equal(range.status, 206); assert.equal(await range.text(), "synt");
  console.log(`PASS: workerd auth, asset routing, private R2 object and range checks (synthetic only; compatibility ${common.compatibilityDate})`);
} finally { await Promise.all([instance.dispose(), unconfigured.dispose()]); }
