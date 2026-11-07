import { createEthernetBridge } from "./browser-ethernet.mjs";
import { readBounded } from "./model.mjs";

// One authenticated lease per disposable core. No caller-selected destination.
export function guestNetwork(core, { role = null, origin = location.origin, fetcher = fetch,
  bridgeFactory = createEthernetBridge, now = () => Date.now(), sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  setTimer = (run, ms) => { const id = setTimeout(run, ms); id.unref?.(); return id; }, clearTimer = clearTimeout } = {}) {
  const bridge = bridgeFactory(core, { origin });
  let stopped = false, path = null, lease = null, pending, state = "unconfigured";
  const controller = new AbortController();
  // Renew halfway through a grant. "final" means the server can grant no more time: the
  // session, or the helper's one hour, ends at expiresAt. "failed" means the last attempt failed.
  const RENEW_MARGIN = 300000, RETRY = 15000;
  let renewTimer = null, renewState = "idle", renewals = 0, renewFailures = 0;
  function scheduleRenew(delay) {
    if (renewTimer !== null) clearTimer(renewTimer);
    renewTimer = setTimer(renew, Math.max(RETRY, delay));
  }
  async function renew() {
    renewTimer = null;
    if (stopped || !lease || !path) return;
    if (bridge.metrics().state !== "gateway-authenticated") { void stop(); return; }
    try {
      const response = await fetcher(path, { method: "POST", credentials: "same-origin", redirect: "error", cache: "no-store",
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(5000)]) });
      if (!response.ok) { await response.body?.cancel(); throw new Error("Renewal refused"); }
      const data = validated(JSON.parse(new TextDecoder().decode(await readBounded(response, 4096))));
      if (stopped) return;
      if (data.expiresAt <= lease.expiresAt) { renewState = "final"; return; }
      lease = data; bridge.extendLease?.(data.expiresAt); renewals++; renewState = "renewed";
      scheduleRenew(data.expiresAt - now() - RENEW_MARGIN);
    } catch {
      if (stopped) return;
      renewFailures++; renewState = "failed";
      // The socket lives until the granted expiry; keep trying only inside that window.
      if (lease.expiresAt - now() > RETRY) scheduleRenew(RETRY);
    }
  }
  async function revoke(target) {
    if (!target) return;
    try { const response = await fetcher(target, { method: "DELETE", credentials: "same-origin", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(3000) }); await response.body?.cancel(); }
    catch { /* Server expiry remains the fallback after an unreachable revoke. */ }
  }
  function validated(data) {
    if (!data || typeof data.lease !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(data.lease) || data.websocketPath !== "/api/guest-network/" + data.lease ||
        data.mode !== "dce" || !Number.isSafeInteger(data.expiresAt) || data.expiresAt <= now() || data.expiresAt - now() > 3600000) throw new Error("Guest network lease unavailable");
    return { websocketPath: data.websocketPath, expiresAt: data.expiresAt };
  }
  async function prepare() {
    if (stopped) return false;
    if (pending) return pending;
    state = "preparing";
    pending = (async () => {
      let issuedPath;
      try {
        const response = await fetcher("/api/guest-network", { method: "POST", ...(role ? { headers: { "X-Halo-Guest-Role": role } } : {}), credentials: "same-origin", redirect: "error", cache: "no-store",
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(7000)]) });
        if (!response.ok) { await response.body?.cancel(); return false; }
        const raw = JSON.parse(new TextDecoder().decode(await readBounded(response, 4096)));
        if (typeof raw?.lease === "string" && /^[A-Za-z0-9_-]{43}$/.test(raw.lease) && raw.websocketPath === "/api/guest-network/" + raw.lease) issuedPath = raw.websocketPath;
        const data = validated(raw);
        if (stopped) { await revoke(issuedPath); return false; }
        path = issuedPath; lease = data; state = "prepared"; return true;
      } catch { if (issuedPath) await revoke(issuedPath); return false; }
      finally { if (!lease && !stopped) state = "unavailable"; }
    })();
    return pending;
  }
  async function activate() {
    if (stopped || !lease) return false;
    try {
      bridge.connect(lease); const deadline = now() + 10000;
      for (;;) {
        if (stopped) return false;
        const current = bridge.metrics().state;
        if (current === "gateway-authenticated") { state = current; scheduleRenew(lease.expiresAt - now() - RENEW_MARGIN); return true; }
        if (current !== "connecting" || now() >= deadline) throw new Error("Guest transport unavailable");
        await sleep(25);
      }
    } catch {
      bridge.stop(); const old = path; path = null; lease = null; state = "unavailable"; await revoke(old); return false;
    }
  }
  async function stop() {
    if (stopped) return;
    stopped = true; state = "stopped"; if (renewTimer !== null) clearTimer(renewTimer); renewTimer = null; controller.abort(); bridge.stop();
    const old = path; path = null; lease = null;
    await revoke(old);
    // An abort-ignoring transport that returns a late lease is handled by prepare().
    // Closing the socket already releases the lease server-side, so this DELETE normally answers 404.
  }
  function metrics() {
    const m = bridge.metrics();
    if (state === "gateway-authenticated" && m.state !== "gateway-authenticated") {
      // Core/device teardown or transport loss cannot retain a live server lease.
      void stop();
    }
    return { state: state === "gateway-authenticated" ? m.state : state,
      terminalReason: m.terminalReason ?? 0, closeCode: m.closeCode ?? 0,
      txFrames: m.txFrames, rxFrames: m.rxFrames, txDropped: m.txDropped, rxDropped: m.rxDropped,
      renewState, renewals, renewFailures,
      queuedBytes: m.queuedBytes, txHighWater: m.txHighWater,
      deviceStarted: core._halo_eth_metric?.(7) === 1, transportReady: core._halo_eth_metric?.(8) === 1,
      guestNetwork: false };
  }
  return { prepare, activate, stop, metrics };
}
