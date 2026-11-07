// Signed game directory transport; no browser cookie and no operator endpoints.
export const DIRECTORY_RESPONSE_LIMIT = 65 * 1024; // Go MaxServers64 * Entry<=1024 + envelope<=1024.
const list = "/v1/dce/servers", item = /^\/v1\/dce\/servers\/[0-9a-f]{16}(?:\/join)?$/;
const answer = (status, text) => new Response(text, { status, headers: {
  "Cache-Control": "no-store", "Content-Type": "text/plain", "X-Content-Type-Options": "nosniff"
} });
async function read(stream, limit, signal) {
  if (!stream) return new Uint8Array();
  const reader = stream.getReader(), output = new Uint8Array(limit); let size = 0;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    for (;;) {
      if (signal.aborted) throw new Error("aborted");
      const { value, done } = await reader.read();
      if (signal.aborted) throw new Error("aborted");
      if (done) return output.subarray(0, size);
      if (size + value.length > limit) { await reader.cancel(); throw new Error("size"); }
      output.set(value, size); size += value.length;
    }
  } finally { signal.removeEventListener("abort", cancel); reader.releaseLock(); }
}
export async function proxyDirectory(request, env, fetcher = fetch) {
  const url = new URL(request.url), isList = url.pathname === list;
  if (!isList && !item.test(url.pathname)) return answer(404, "Not found");
  if (request.headers.has("Upgrade") || !(isList ? request.method === "GET" : ["PUT", "DELETE"].includes(request.method)))
    return answer(405, "Method not allowed");
  if (url.search && !(isList && /^\?(?:limit=([1-9]|[1-5][0-9]|6[0-4])(?:&nonce=[0-9a-f]{32})?|nonce=[0-9a-f]{32})$/.test(url.search))) return answer(400, "Invalid query");
  let upstream;
  try {
    upstream = new URL(env.DIRECTORY_UPSTREAM_URL);
    if (upstream.protocol !== "https:" || upstream.username || upstream.password || upstream.pathname !== "/" || upstream.search || upstream.hash ||
        typeof env.DIRECTORY_UPSTREAM_KEY !== "string" || !/^[\x21-\x7e]{32,256}$/.test(env.DIRECTORY_UPSTREAM_KEY) ||
        env.DIRECTORY_UPSTREAM_KEY === env.GUEST_GATEWAY_KEY) throw new Error("config");
  } catch { return answer(503, "Directory unavailable"); }
  const auth = request.headers.get("Authorization");
  if (!isList && (!auth || auth.length > 512 || !auth.startsWith("OpenCE-Ed25519 "))) return answer(401, "Signed identity required");
  if (request.headers.has("Content-Encoding")) return answer(400, "Encoding refused");
  const controller = new AbortController(), cancel = () => controller.abort();
  request.signal.addEventListener("abort", cancel, { once: true });
  if (request.signal.aborted) cancel();
  const timer = setTimeout(cancel, 7000);
  try {
    let body;
    try { body = await read(request.body, request.method === "PUT" ? 2048 : 0, controller.signal); }
    catch { return answer(controller.signal.aborted ? 504 : 413, "Request refused"); }
    const headers = new Headers({ "X-Halo-Directory-Key": env.DIRECTORY_UPSTREAM_KEY, "Accept": "application/json", "Accept-Encoding": "identity" });
    if (!isList) headers.set("Authorization", auth);
    // Set by Cloudflare at the edge, so a caller cannot choose it.
    const client = request.headers.get("CF-Connecting-IP");
    if (client) headers.set("X-Halo-Client-IP", client);
    if (request.method === "PUT") headers.set("Content-Type", "application/json");
    upstream.pathname = url.pathname; upstream.search = url.search;
    let response;
    try { response = await fetcher(upstream, { method: request.method, headers, body: body.length ? body : undefined, redirect: "manual", signal: controller.signal }); }
    catch { return answer(controller.signal.aborted ? 504 : 503, "Directory unavailable"); }
    if (![200, 201, 202, 204, 400, 401, 403, 404, 405, 409, 413, 429, 500, 503].includes(response.status) ||
        (response.headers.get("Content-Encoding") ?? "identity") !== "identity") {
      await response.body?.cancel(); return answer(502, "Upstream refused");
    }
    let bytes;
    try { bytes = await read(response.body, DIRECTORY_RESPONSE_LIMIT, controller.signal); }
    catch { return answer(controller.signal.aborted ? 504 : 502, "Response refused"); }
    const result = new Headers({ "Cache-Control": "no-store", "Content-Type": "application/json", "X-Content-Type-Options": "nosniff" });
    for (const [name, maximum] of [["Signature", 96], ["Signature-Key", 16], ["Signature-Time", 12], ["Retry-After", 12]]) {
      const value = response.headers.get(name);
      if (value !== null) { if (value.length > maximum) return answer(502, "Response refused"); result.set(name, value); }
    }
    return new Response(response.status === 204 ? null : bytes, { status: response.status, headers: result });
  } finally { clearTimeout(timer); request.signal.removeEventListener("abort", cancel); }
}
