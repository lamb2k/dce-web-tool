// Device public-key enrollment only. Private key/seed/VMU bytes never belong here.
const route = /^\/api\/device-enrollment\/(config|challenge|register)$/;
const publicKey = value => typeof value === "string" && /^ed25519:[0-9a-f]{64}$/.test(value);
const hex = (value, n) => typeof value === "string" && new RegExp(`^[0-9a-f]{${n}}$`).test(value);
const utc = value => Number.isSafeInteger(value) && value >= 1577836800 && value <= 4102444800;
const local = host => ["127.0.0.1", "localhost", "[::1]"].includes(host);
const answer = (status, text) => new Response(text, { status, headers: {
  "Cache-Control": "private, no-store", "Content-Type": "text/plain", "X-Content-Type-Options": "nosniff"
} });
const exact = (value, keys) => value && typeof value === "object" && !Array.isArray(value) &&
  Object.keys(value).sort().join(",") === [...keys].sort().join(",");
const signature = value => {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{86}==$/.test(value)) return false;
  try { return atob(value).length === 64 && btoa(atob(value)) === value; } catch { return false; }
};
async function keyId(publicValue) {
  const raw = Uint8Array.from(publicValue.slice(8).match(/../g), value => parseInt(value, 16));
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", raw))].slice(0, 8)
    .map(value => value.toString(16).padStart(2, "0")).join("");
}

async function bytes(stream, limit, signal) {
  if (!stream) return new Uint8Array();
  const reader = stream.getReader(), output = new Uint8Array(limit); let size = 0;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    for (;;) {
      if (signal.aborted) throw new Error("Canceled");
      const { value, done } = await reader.read();
      if (signal.aborted) throw new Error("Canceled");
      if (done) break;
      if (size + value.length > limit) { await reader.cancel(); throw new Error("Oversized"); }
      output.set(value, size); size += value.length;
    }
    return output.subarray(0, size);
  } finally { signal.removeEventListener("abort", cancel); reader.releaseLock(); }
}

export async function proxyDeviceEnrollment(request, env, session, fetcher = fetch) {
  const url = new URL(request.url), match = route.exec(url.pathname);
  if (!match || url.search) return answer(404, "Not found");
  if (!session || !hex(session.id, 64) || !Number.isSafeInteger(session.expiresAt) || session.expiresAt <= Date.now())
    return answer(401, "Sign in to set up this device");
  if (request.method !== "POST" || request.headers.has("Upgrade")) return answer(405, "Method not allowed");
  if (request.headers.get("Origin") !== url.origin) return answer(403, "Origin refused");
  const action = match[1]; let gateway;
  try {
    gateway = new URL(env.GUEST_GATEWAY_URL);
    if (gateway.username || gateway.password || gateway.search || gateway.hash || gateway.pathname !== "/" ||
        !(gateway.protocol === "https:" || (gateway.protocol === "http:" && local(gateway.hostname) && local(url.hostname))) ||
        typeof env.GUEST_GATEWAY_KEY !== "string" || !/^[\x21-\x7e]{32,256}$/.test(env.GUEST_GATEWAY_KEY))
      throw new Error("Unavailable");
  } catch { return answer(503, "Device setup unavailable"); }
  gateway.pathname = url.pathname;
  const controller = new AbortController(), cancel = () => controller.abort();
  const timer = setTimeout(cancel, 7000);
  request.signal?.addEventListener("abort", cancel, { once: true });
  if (request.signal?.aborted) cancel();
  try {
    let body = null;
    try {
      const raw = await bytes(request.body, 512, controller.signal);
      if (action === "config") {
        if (raw.length) throw new Error("Empty body required");
      } else {
        if (request.headers.get("Content-Type")?.split(";")[0].trim().toLowerCase() !== "application/json")
          throw new Error("JSON required");
        body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
        const fields = action === "challenge" ? ["publicKey"] : ["publicKey", "challenge", "signature"];
        if (!exact(body, fields) || !publicKey(body.publicKey) ||
            (action === "register" && (!hex(body.challenge, 32) || !signature(body.signature))))
          throw new Error("Public enrollment fields only");
      }
    } catch { return answer(controller.signal.aborted ? 504 : 400, "Invalid device setup request"); }
    const headers = new Headers({ "X-Halo-Bridge-Key": env.GUEST_GATEWAY_KEY, "X-Halo-Session": session.id,
      "X-Halo-Session-Expires": String(session.expiresAt), "Content-Type": "application/json" });
    // The gateway counts new identities per client from this tag and never sees the address.
    if (typeof session.client === "string" && /^[0-9a-f]{32}$/.test(session.client)) headers.set("X-Halo-Client", session.client);
    let response;
    try {
      response = await fetcher(gateway, { method: "POST", headers, body: body === null ? undefined : JSON.stringify(body),
        redirect: "manual", signal: controller.signal });
    } catch { return answer(controller.signal.aborted ? 504 : 503, "Device setup service unavailable"); }
    if (response.status !== 200) {
      await response.body?.cancel();
      return answer([400, 403, 409, 429, 503, 504].includes(response.status) ? response.status : 502, "Device setup request refused");
    }
    try {
      const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await bytes(response.body, 2048, controller.signal)));
      let clean;
      if (action === "config") {
        if (value.protocol !== 1 || value.configured !== true || !publicKey(value.masterPublicKey) ||
            !hex(value.masterKeyId, 16) || value.masterKeyId !== await keyId(value.masterPublicKey) ||
            value.proofDomain !== "DCE-Device-Enrollment-v1" || value.challengeTtl !== 60)
          throw new Error("Invalid configuration");
        clean = { protocol: 1, configured: true, masterPublicKey: value.masterPublicKey, masterKeyId: value.masterKeyId,
          proofDomain: value.proofDomain, challengeTtl: 60 };
      } else if (action === "challenge") {
        if (value.protocol !== 1 || !hex(value.masterKeyId, 16) || value.keyId !== await keyId(body.publicKey) || value.publicKey !== body.publicKey ||
            !hex(value.challenge, 32) || !utc(value.serverTime) || !utc(value.expires) || value.expires <= value.serverTime ||
            value.expires > value.serverTime + 60 || value.expires * 1000 > session.expiresAt || value.sessionBinding !== session.id)
          throw new Error("Invalid challenge");
        clean = { protocol: 1, masterKeyId: value.masterKeyId, keyId: value.keyId, publicKey: value.publicKey,
          challenge: value.challenge, expires: value.expires, serverTime: value.serverTime, sessionBinding: value.sessionBinding };
      } else {
        if (value.ok !== true || value.approved !== true || !hex(value.masterKeyId, 16) || value.keyId !== await keyId(body.publicKey) || value.publicKey !== body.publicKey ||
            typeof value.created !== "boolean" || !utc(value.serverTime)) throw new Error("Invalid approval");
        clean = { ok: true, masterKeyId: value.masterKeyId, keyId: value.keyId, publicKey: value.publicKey, approved: true, created: value.created, serverTime: value.serverTime };
      }
      return new Response(JSON.stringify(clean), { status: 200, headers: { "Content-Type": "application/json",
        "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" } });
    } catch { return answer(controller.signal.aborted ? 504 : 502, "Invalid device setup response"); }
  } finally { clearTimeout(timer); request.signal?.removeEventListener("abort", cancel); }
}
