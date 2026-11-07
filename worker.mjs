import { proxyGuestNetwork } from "./bridge-proxy.mjs";
import { proxyDeviceEnrollment } from "./enrollment-proxy.mjs";
import { proxyDirectory } from "./directory-proxy.mjs";
const encoder = new TextEncoder();
const SESSION = "halo_test_session";
const SESSION_SECONDS = 8 * 60 * 60;
const SIGNIN_ASSETS = new Set(["/signin.html", "/signin.css", "/signin.mjs",
  // Reachable without signing in: the GPL source offer is for anyone the page reaches.
  "/licenses", "/licenses.html", "/licenses.mjs", "/source.json", "/LICENSE-GPL-2.0.txt", "/LICENSE-EJS-GPL-3.0.txt"]);
const SESSIONS_PER_MINUTE = 20, SESSION_BUCKETS = 4096;
const sessionBuckets = new Map();

const encode64 = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
function decode64(value) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) return null;
  try { return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "="), c => c.charCodeAt(0)); } catch { return null; }
}
async function sessionKey(env) {
  return crypto.subtle.importKey("raw", encoder.encode(`${env.TEST_USERNAME}:${env.TEST_PASSWORD}`),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
// One client: an IPv4 address, or an IPv6 /64, since one IPv6 customer holds a whole /64.
function clientGroup(request) {
  const address = request.headers.get("CF-Connecting-IP") ?? "";
  if (!address.includes(":")) return address || "local";
  const [head, tail = ""] = address.toLowerCase().split("::");
  const left = head ? head.split(":") : [], right = tail ? tail.split(":") : [];
  const words = address.includes("::") ? [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill("0"), ...right] : left;
  return words.slice(0, 4).map(word => word.replace(/^0+(?=.)/, "")).join(":") + "::/64";
}
// The platform limiter when bound; else one bucket per Worker instance, which still stops a loop from one client.
async function sessionAllowed(request, env, now = Date.now()) {
  const key = clientGroup(request);
  if (env.SESSION_LIMIT?.limit) return (await env.SESSION_LIMIT.limit({ key })).success;
  let bucket = sessionBuckets.get(key);
  if (!bucket || now - bucket.start >= 60000) {
    if (!bucket && sessionBuckets.size >= SESSION_BUCKETS) {
      for (const [old, value] of sessionBuckets) if (now - value.start >= 60000) sessionBuckets.delete(old);
      if (sessionBuckets.size >= SESSION_BUCKETS) return false;
    }
    bucket = { start: now, count: 0 };
    sessionBuckets.set(key, bucket);
  }
  return ++bucket.count <= SESSIONS_PER_MINUTE;
}
// Password guesses, separate from new sessions. Only failures count, so a signed-in tester's page loads are never limited.
const GUESSES_PER_MINUTE = 10;
const guessBuckets = new Map();
function guessBucket(key, now) {
  let bucket = guessBuckets.get(key);
  if (!bucket || now - bucket.start >= 60000) {
    if (!bucket && guessBuckets.size >= SESSION_BUCKETS) {
      for (const [old, value] of guessBuckets) if (now - value.start >= 60000) guessBuckets.delete(old);
      // Full of live rows: every new client shares one row and so one budget, rather than going unlimited.
      if (guessBuckets.size >= SESSION_BUCKETS) key = "overflow";
    }
    bucket = guessBuckets.get(key);
    if (!bucket || now - bucket.start >= 60000) { bucket = { start: now, count: 0 }; guessBuckets.set(key, bucket); }
  }
  return bucket;
}
const guessesLeft = (request, now = Date.now()) => guessBucket(clientGroup(request), now).count < GUESSES_PER_MINUTE;
// The platform limiter, when bound (SIGNIN_LIMIT), holds across Worker instances; a refusal closes this instance's row too.
async function guessFailed(request, env, now = Date.now()) {
  const key = clientGroup(request), bucket = guessBucket(key, now);
  bucket.count++;
  if (env.SIGNIN_LIMIT?.limit && !(await env.SIGNIN_LIMIT.limit({ key })).success) bucket.count = GUESSES_PER_MINUTE;
}
const tooManyGuesses = () => reply("Too many sign-in attempts. Try again in a minute.", 429, { "Retry-After": "60" });
async function sessionValid(request, env) {
  const cookies = request.headers.get("Cookie") ?? "";
  if (cookies.length > 2048) return false;
  const field = cookies.split(";").map(x => x.trim()).find(x => x.startsWith(SESSION + "="));
  if (!field) return false;
  const value = field.slice(SESSION.length + 1);
  const match = /^(1\.([0-9]{1,12})\.[A-Za-z0-9_-]{32})\.([A-Za-z0-9_-]{43})$/.exec(value);
  if (!match) return false;
  const expires = Number(match[2]), now = Math.floor(Date.now() / 1000);
  if (expires <= now || expires > now + SESSION_SECONDS) return false;
  const signature = decode64(match[3]);
  return signature !== null && crypto.subtle.verify("HMAC", await sessionKey(env), signature, encoder.encode(match[1]));
}
async function newSession(env, secureCookie) {
  const nonce = encode64(crypto.getRandomValues(new Uint8Array(24)));
  const payload = `1.${Math.floor(Date.now() / 1000) + SESSION_SECONDS}.${nonce}`;
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", await sessionKey(env), encoder.encode(payload)));
  return `${SESSION}=${payload}.${encode64(signature)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_SECONDS}${secureCookie ? "; Secure" : ""}`;
}
async function loginBody(request) {
  if (!request.headers.get("Content-Type")?.toLowerCase().startsWith("application/json") || !request.body) return null;
  const reader = request.body.getReader();
  const bytes = new Uint8Array(1024); let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (size + value.length > bytes.length) { await reader.cancel(); return null; }
      bytes.set(value, size); size += value.length;
    }
    return JSON.parse(new TextDecoder().decode(bytes.subarray(0, size)));
  } catch { return null; }
  finally { reader.releaseLock(); }
}

// Web Crypto verifies HMAC in constant time, available in Workers and Node tests.
async function credentialMatches(provided, expected) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(expected),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(expected));
  return crypto.subtle.verify("HMAC", key, signature, encoder.encode(provided));
}

function secure(response, runtimeFrame = false) {
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "private, no-store");
  headers.set("Vary", "Authorization, Cookie");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Embedder-Policy", "require-corp");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'" + (runtimeFrame ? " blob:" : "") + "; style-src 'self'; img-src 'self' blob:; media-src 'self' blob:; connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors " + (runtimeFrame ? "'self'" : "'none'") + "; form-action 'self'");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

const reply = (text, status, headers = {}) => secure(new Response(text, { status, headers }));

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // HTTP allowed only for loopback local preview. Never send a login challenge on public HTTP.
    if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) {
      return reply("HTTPS required", 403);
    }
    if (url.pathname.startsWith("/v1/dce/")) return proxyDirectory(request, env);
    if (typeof env.TEST_USERNAME !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(env.TEST_USERNAME) ||
        typeof env.TEST_PASSWORD !== "string" || env.TEST_PASSWORD.length < 16 || env.TEST_PASSWORD.length > 256 ||
        /[^\x20-\x7e]/.test(env.TEST_PASSWORD)) {
      return reply("Tester access not configured", 503);
    }
    if (url.search) return reply("Query parameters not accepted", 400);
    // No password while PUBLIC_ACCESS is 1: the page hands each browser its own session, which guest networking still needs.
    const open = env.PUBLIC_ACCESS === "1";
    if (open && (url.pathname === "/signin" || url.pathname === "/signin.html") && ["GET", "HEAD"].includes(request.method))
      return reply("", 302, { Location: "/" });
    if (url.pathname === "/signin" && request.method === "POST") {
      if (request.headers.get("Origin") !== url.origin) return reply("Origin refused", 403);
      if (!guessesLeft(request)) return tooManyGuesses();
      const body = await loginBody(request);
      if (!body || typeof body.username !== "string" || typeof body.password !== "string" ||
          body.username.length > 64 || body.password.length > 256) return reply("Invalid request", 400);
      if (!await credentialMatches(`${body.username}:${body.password}`, `${env.TEST_USERNAME}:${env.TEST_PASSWORD}`)) {
        await guessFailed(request, env);
        return reply("Sign-in failed", 401);
      }
      return reply("Signed in", 200, { "Set-Cookie": await newSession(env, url.protocol === "https:") });
    }
    if ((url.pathname === "/signin" || SIGNIN_ASSETS.has(url.pathname)) && ["GET", "HEAD"].includes(request.method)) {
      if (!env.ASSETS) return reply("Test page not configured", 503);
      const assetUrl = new URL(request.url);
      if (assetUrl.pathname === "/signin") assetUrl.pathname = "/signin.html";
      // Only these credential-free login assets are public; no private runtime or image.
      return secure(await env.ASSETS.fetch(new Request(assetUrl, { method: request.method })));
    }
    const authorization = request.headers.get("Authorization") ?? "";
    let supplied = "";
    if (authorization.length <= 1024 && /^Basic [A-Za-z0-9+/]+=*$/i.test(authorization)) {
      try { supplied = atob(authorization.slice(6)); } catch { /* Reject malformed input. */ }
    }
    // A valid session passes first, and an exhausted budget refuses before the password is compared, so a right guess then reveals nothing.
    if (!open && supplied && !await sessionValid(request, env) && !guessesLeft(request)) return tooManyGuesses();
    if (!open && !await credentialMatches(supplied, `${env.TEST_USERNAME}:${env.TEST_PASSWORD}`) && !await sessionValid(request, env)) {
      if (supplied) await guessFailed(request, env);
      if (url.pathname === "/" && request.method === "GET" && request.headers.get("Accept")?.includes("text/html"))
        return reply("", 302, { Location: "/signin" });
      return reply("Tester login required", 401, { "WWW-Authenticate": 'Basic realm="Halo test team", charset="UTF-8"' });
    }
    if (url.pathname.startsWith("/api/guest-network") || url.pathname.startsWith("/api/device-enrollment")) {
      // Bridge leases require the per-browser form session, not shared Basic identity.
      if (!await sessionValid(request, env)) return reply("Sign in to use guest networking", 401);
      const field = request.headers.get("Cookie").split(";").map(x => x.trim()).find(x => x.startsWith(SESSION + "="));
      const token = field.slice(SESSION.length + 1);
      const digest = await crypto.subtle.sign("HMAC", await sessionKey(env), encoder.encode("guest-network-session:" + token));
      const id = [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
      const clientDigest = await crypto.subtle.sign("HMAC", await sessionKey(env), encoder.encode("guest-network-client:" + clientGroup(request)));
      // The gateway limits leases per client from this tag and never sees the address.
      const client = [...new Uint8Array(clientDigest)].slice(0, 16).map(byte => byte.toString(16).padStart(2, "0")).join("");
      const identity = { id, expiresAt: Number(token.split(".")[1]) * 1000, client };
      return url.pathname.startsWith("/api/device-enrollment")
        ? proxyDeviceEnrollment(request, env, identity) : proxyGuestNetwork(request, env, identity);
    }
    if (!["GET", "HEAD"].includes(request.method)) return reply("Method not allowed", 405, { Allow: "GET, HEAD" });
    // Private object binding optional. Its bucket must have no public/custom-domain endpoint.
    if (url.pathname.startsWith("/files/")) {
      // Public mode opens the page, not the bucket: files take the session the page hands out.
      if (open && !await sessionValid(request, env)) return reply("Open the page first", 401);
      if (!/^\/files\/[A-Za-z0-9._/-]+$/.test(url.pathname) || url.pathname.includes("..")) return reply("Not found", 404);
      if (!env.TEST_FILES) return reply("Test files not configured", 503);
      const key = url.pathname.slice(7);
      const object = request.method === "HEAD"
        ? await env.TEST_FILES.head(key)
        : await env.TEST_FILES.get(key, request.headers.has("Range") ? { range: request.headers } : {});
      if (!object) return reply("Not found", 404);
      const headers = new Headers();
      object.writeHttpMetadata(headers);
      headers.set("ETag", object.httpEtag);
      headers.set("Accept-Ranges", "bytes");
      headers.set("Content-Type", key.endsWith(".json") ? "application/json" : key.endsWith(".wasm") ? "application/wasm" : key.endsWith(".js") || key.endsWith(".mjs") ? "text/javascript" : "application/octet-stream");
      let status = 200;
      if (request.headers.has("Range") && object.range) {
        const offset = object.range.offset ?? Math.max(0, object.size - object.range.suffix);
        const length = object.range.length ?? object.size - offset;
        headers.set("Content-Range", `bytes ${offset}-${offset + length - 1}/${object.size}`);
        headers.set("Content-Length", String(length));
        status = 206;
      } else headers.set("Content-Length", String(object.size));
      return secure(new Response(request.method === "HEAD" ? null : object.body, { status, headers }));
    }
    if (!env.ASSETS) return reply("Test page not configured", 503);
    // Credentials never forwarded to asset binding, logged or returned in diagnostics.
    const headers = new Headers(request.headers);
    headers.delete("Authorization");
    headers.delete("Cookie");
    // Static Assets may canonicalize .html to its extensionless URL.
    const page = secure(await env.ASSETS.fetch(new Request(request, { headers })),
      url.pathname === "/runtime-frame.html" || url.pathname === "/runtime-frame");
    if (open && (url.pathname === "/" || url.pathname === "/index.html") && !await sessionValid(request, env)) {
      if (!await sessionAllowed(request, env)) return reply("Too many new sessions from this address", 429, { "Retry-After": "60" });
      page.headers.append("Set-Cookie", await newSession(env, url.protocol === "https:"));
    }
    return page;
  }
};
