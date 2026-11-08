import { CORE } from "./runtime-config.mjs";
import { readBounded } from "./model.mjs";
import { acquireVmu } from "./vmu-store.mjs";
import { enrollDevice } from "./device-enrollment.mjs";
import { vmuCheckpointer } from "./vmu-checkpoint.mjs";
export const capabilities = Object.freeze({ boot: true, guestNetwork: false, input: true });
let pinnedWasm;
export async function fetchPinnedWasm(fetcher = fetch) {
  const response = await fetcher(CORE.wasm.path, { credentials: "same-origin", cache: "no-store", redirect: "error" });
  if (!response.ok) throw new Error("Runtime unavailable");
  const bytes = await readBounded(response, CORE.wasm.bytes);
  const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(value => value.toString(16).padStart(2, "0")).join("");
  if (bytes.byteLength !== CORE.wasm.bytes || hash !== CORE.wasm.sha256) throw new Error("Runtime verification failed");
  return bytes;
}
export async function boot({ canvas: host, imageBytes, manifest, onState = () => {}, onStorage = () => {} } = {}) {
  if (!host || !imageBytes?.byteLength) throw new Error("Verified build required");
  let frame, api, device, stopped = false, snapshotTimer, checkpoint;
  const scheduleSnapshots = () => { snapshotTimer = setInterval(() => { void checkpoint().catch(() => onStorage("save-unavailable")); }, 2000); };
  async function dispose() {
    clearInterval(snapshotTimer);
    try { await api?.stop(); } finally { frame?.remove(); api = null; frame = null; }
  }
  async function start() {
    onState("booting");
    try {
      pinnedWasm ??= fetchPinnedWasm().catch(error => { pinnedWasm = null; throw error; });
      const wasmBinary = await pinnedWasm;
      device ??= await acquireVmu();
      onStorage("preparing");
      let enrollment;
      try { enrollment = await enrollDevice(device.identity, manifest?.directoryMasterPublicKey); }
      catch { enrollment = { available: false }; onStorage("online-unavailable"); }
      const elapsed = enrollment.available ? (performance.now() - enrollment.received) / 1000 : 0;
      const clock = enrollment.available && elapsed >= 0 && elapsed < 30 ? { utc: enrollment.utc, at: enrollment.received, now: () => performance.now() } : null;
      // Exact pinned core verified actual KOS boot UTC in both UTC and America/New_York.
      const vmuBytes = await device.prepare(Math.floor(clock ? clock.utc + elapsed : Date.now() / 1000), Boolean(clock));
      frame = document.createElement("iframe");
      frame.title = "Halo game runtime"; frame.allow = "autoplay; fullscreen"; frame.tabIndex = -1;
      const ready = new Promise((resolve, reject) => {
        frame.addEventListener("load", () => frame.contentWindow?.haloRuntime ? resolve() : reject(new Error("Runtime unavailable")), { once: true });
        frame.addEventListener("error", () => reject(new Error("Runtime unavailable")), { once: true });
      });
      frame.src = "/runtime-frame.html"; host.append(frame); await ready;
      api = frame.contentWindow.haloRuntime;
      await api.boot({ imageBytes, wasmBinary, vmuBytes, clock, onState });
      vmuBytes.fill(0);
      checkpoint = vmuCheckpointer({ snapshot: pause => api.snapshot(pause), resume: () => api?.resume(), persist: bytes => device.checkpoint(bytes), saved: () => onStorage("saved") });
      scheduleSnapshots();
      if (!enrollment.available) onStorage("offline");
    } catch (error) { await dispose(); await device?.close(); device = null; onState("failed"); throw error; }
  }
  await start();
  return {
    setInput(value) { if (!stopped) api?.setInput(value); },
    releaseInput() { api?.releaseInput(); },
    diagnostics() { return api?.diagnostics() ?? {}; },
    matchDiag() { return api?.matchDiag?.() ?? null; },
    networkDiagnostics() { return api?.networkDiagnostics() ?? { state: "unavailable", guestNetwork: false }; },
    async reset() { if (stopped) throw new Error("Runtime stopped"); clearInterval(snapshotTimer); try { await checkpoint(true); } catch (error) { api?.resume(); scheduleSnapshots(); throw error; } await dispose(); await start(); },
    async stop() { stopped = true; clearInterval(snapshotTimer); try { await checkpoint?.(true); } finally { await dispose(); await device?.close(); device = null; onState("stopped"); } },
  };
}
