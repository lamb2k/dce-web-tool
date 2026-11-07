// The browser chooses a lease, never a backend address or game destination.
const route = /^\/api\/guest-network(?:\/([A-Za-z0-9_-]{43}))?$/;
const loopback = host => ["127.0.0.1", "localhost", "[::1]"].includes(host);
const answer = (status, text) => new Response(text, { status, headers: {
  "Cache-Control": "private, no-store", "Content-Type": "text/plain", "X-Content-Type-Options": "nosniff"
} });

async function metadata(response) {
  if (!response.body) throw new Error("Missing metadata");
  const reader = response.body.getReader();
  const buffer = new Uint8Array(4096); let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (length + value.length > buffer.length) { await reader.cancel(); throw new Error("Oversized metadata"); }
      buffer.set(value, length); length += value.length;
    }
  } finally { reader.releaseLock(); }
  return JSON.parse(new TextDecoder().decode(buffer.subarray(0, length)));
}
const ipv4 = value => typeof value === "string" && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) &&
  value.split(".").every(part => String(Number(part)) === part && Number(part) <= 255);
const advertisedAddress = value => {
  if (!ipv4(value)) return false;
  const [a, b] = value.split(".").map(Number);
  return a !== 0 && a !== 127 && a < 224 && !(a === 169 && b === 254) && !(a === 10 && b === 77);
};

export async function proxyGuestNetwork(request, env, session, fetcher = fetch) {
  const url = new URL(request.url), match = route.exec(url.pathname);
  if (!match || url.search) return answer(404, "Not found");
  if (!session || !/^[a-f0-9]{64}$/.test(session.id) || !Number.isSafeInteger(session.expiresAt) || session.expiresAt <= Date.now())
    return answer(401, "Sign in to use guest networking");
  const upgrade = request.headers.get("Upgrade")?.toLowerCase() === "websocket";
  const allowed = match[1] ? ["GET", "DELETE", "POST"] : ["POST"];
  if (!allowed.includes(request.method) || (upgrade && (request.method !== "GET" || !match[1])))
    return answer(405, "Method not allowed");
  if ((request.method !== "GET" || upgrade) && request.headers.get("Origin") !== url.origin)
    return answer(403, "Origin refused");
  if (request.headers.has("Origin") && request.headers.get("Origin") !== url.origin)
    return answer(403, "Origin refused");
  if (request.body) {
    const reader = request.body.getReader();
    try { const part = await reader.read(); if (!part.done) { await reader.cancel(); return answer(400, "Body not accepted"); } }
    finally { reader.releaseLock(); }
  }
  let gateway;
  try {
    gateway = new URL(env.GUEST_GATEWAY_URL);
    if (gateway.username || gateway.password || gateway.search || gateway.hash || gateway.pathname !== "/" ||
        !(gateway.protocol === "https:" || (gateway.protocol === "http:" && loopback(gateway.hostname) && loopback(url.hostname))))
      throw new Error("Invalid gateway");
    if (typeof env.GUEST_GATEWAY_KEY !== "string" || !/^[\x21-\x7e]{32,256}$/.test(env.GUEST_GATEWAY_KEY))
      throw new Error("Missing key");
  } catch { return answer(503, "Guest networking unavailable"); }
  gateway.pathname = url.pathname;
  // Construct fresh headers. Browser cookies, Basic credentials and spoofed trust headers never leave this Worker.
  const headers = new Headers({ "X-Halo-Bridge-Key": env.GUEST_GATEWAY_KEY,
    "X-Halo-Session": session.id, "X-Halo-Session-Expires": String(session.expiresAt) });
  if (upgrade) headers.set("Upgrade", "websocket");
  if (typeof session.client === "string" && /^[0-9a-f]{32}$/.test(session.client)) headers.set("X-Halo-Client", session.client);
  const role = request.headers.get("X-Halo-Guest-Role");
  if (role !== null) {
    if (request.method !== "POST" || match[1] || !["host", "join"].includes(role)) return answer(400, "Invalid role");
    headers.set("X-Halo-Guest-Role", role);
  }
  let response;
  try { response = await fetcher(gateway, { method: request.method, headers, redirect: "manual" }); }
  catch { return answer(503, "Guest gateway unavailable"); }
  if (upgrade && response.status === 101 && response.webSocket) {
    // Preserve the actual Workers WebSocket endpoint; wrapping as an ordinary response loses it.
    return new Response(null, { status: 101, webSocket: response.webSocket });
  }
  if (response.status >= 300 || upgrade) {
    await response.body?.cancel();
    return answer([400, 403, 404, 409, 429, 503].includes(response.status) ? response.status : 502, "Guest gateway request refused");
  }
  if (request.method === "DELETE" && response.status === 204) return new Response(null, { status: 204, headers: { "Cache-Control": "private, no-store" } });
  try {
    const data = await metadata(response);
    if (!/^[A-Za-z0-9_-]{43}$/.test(data.lease) || (match[1] && data.lease !== match[1]) ||
        data.websocketPath !== "/api/guest-network/" + data.lease || !Number.isSafeInteger(data.expiresAt) ||
        data.expiresAt <= Date.now() || data.expiresAt > Math.min(session.expiresAt, Date.now() + 3600000) ||
        !ipv4(data.guestIPv4) || !ipv4(data.routerIPv4) || !ipv4(data.netmask) ||
        !["dce", "native"].includes(data.mode) || !["host", "peer", "guest", "native", undefined].includes(data.role) ||
        (data.joinEndpoint !== null && (!ipv4(data.joinEndpoint?.host) || !Number.isInteger(data.joinEndpoint?.port) || data.joinEndpoint.port < 1 || data.joinEndpoint.port > 65535)) ||
        (data.advertisedEndpoint != null && (data.mode !== "dce" || data.joinEndpoint !== null ||
          !advertisedAddress(data.advertisedEndpoint?.host) || !Number.isInteger(data.advertisedEndpoint?.port) ||
          data.advertisedEndpoint.port < 1 || data.advertisedEndpoint.port > 65535)))
      throw new Error("Invalid lease metadata");
    const clean = { lease: data.lease, expiresAt: data.expiresAt, guestIPv4: data.guestIPv4, routerIPv4: data.routerIPv4,
      netmask: data.netmask, mode: data.mode, role: data.role, joinEndpoint: data.joinEndpoint === null ? null : { host: data.joinEndpoint.host, port: data.joinEndpoint.port },
      advertisedEndpoint: data.advertisedEndpoint == null ? null : { host: data.advertisedEndpoint.host, port: data.advertisedEndpoint.port }, websocketPath: data.websocketPath };
    return new Response(JSON.stringify(clean), { status: request.method === "POST" && !match[1] ? 201 : 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" } });
  } catch { return answer(502, "Invalid gateway response"); }
}
