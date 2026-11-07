import { validateManifest, report, readBounded } from "./model.mjs";
import { prepareImage } from "./prepare-image.mjs";
import { capabilities, boot } from "./runtime-adapter.mjs";
const $ = id => document.getElementById(id);
let manifest, runtime, preparedImage, busy = false, imageVerified = false;
let runtimeState = "unavailable";
let storageState = "preparing";
let connectionState = "unavailable";
const events = [], keys = new Set();
const record = code => { events.push({ at: new Date().toISOString(), code }); if (events.length > 32) events.shift(); };
function refresh() {
  $("play").disabled = !preparedImage || !imageVerified || !capabilities.boot || busy || Boolean(runtime);
  $("reset").disabled = !runtime || busy;
  $("start").disabled = !runtime || busy;
  $("display-placeholder").hidden = Boolean(runtime) || (busy && runtimeState === "booting");
}
function release() { keys.clear(); runtime?.releaseInput(); }
function status(text) { $("status").textContent = text; }
function runningStatus() { return ["offline", "online-unavailable"].includes(storageState) ? "Running · online setup unavailable" : "Running"; }
function runtimeChanged(state) {
  if (!["booting", "running", "stopped", "failed"].includes(state)) return;
  runtimeState = state; record(`runtime-${state}`);
  if (state === "failed") status("Runtime stopped. Reset to retry.");
}
async function readBuild() {
  try {
    let response = await fetch("/files/build.json", { credentials: "same-origin", cache: "no-store", redirect: "error" });
    if ([404, 503].includes(response.status)) response = await fetch("/manifest.json", { credentials: "same-origin", cache: "no-store", redirect: "error" });
    if (!response.ok) throw new Error("Build unavailable");
    manifest = validateManifest(JSON.parse(new TextDecoder().decode(await readBounded(response, 4096))));
    $("build").textContent = manifest.status === "ready" ? manifest.build : "No build selected";
    record("manifest-read");
    if (manifest.status === "ready") {
      busy = true; refresh();
      preparedImage = await prepareImage(manifest, { onProgress: progress => {
        $("download-progress").hidden = false; $("download-progress").max = progress.total; $("download-progress").value = progress.loaded;
        status(progress.phase === "downloading" ? `Preparing build… ${Math.floor(progress.loaded / progress.total * 100)}%` : "Preparing build…");
      } });
      imageVerified = true; record("image-verified"); $("download-progress").hidden = true; status("Ready");
    } else status("Build unavailable");
  } catch { preparedImage = null; imageVerified = false; status("Build unavailable. Reload to retry."); record("prepare-failed"); }
  finally { busy = false; refresh(); }
}
async function play() {
  if (busy || runtime || !preparedImage || !imageVerified || !capabilities.boot) return;
  busy = true; runtimeState = "booting"; status("Starting…"); refresh();
  try {
    runtime = await boot({ canvas: $("game"), imageBytes: preparedImage, manifest, onState: runtimeChanged,
      onStorage: state => { if (state !== "saved") storageState = state; if (state === "save-unavailable") status("VMU save unavailable. Keep this tab open and retry Reset."); } });
    if (runtimeState !== "failed") { status(runningStatus()); $("game").focus(); }
  } catch { status("Runtime unavailable. Try Play again."); record("load-failed"); }
  finally { busy = false; refresh(); }
}
$("play").addEventListener("click", play);
$("reset").addEventListener("click", async () => {
  if (!runtime || busy) return;
  release(); busy = true; status("Resetting…"); refresh();
  try { await runtime.reset(); status(runningStatus()); $("game").focus(); record("runtime-reset"); }
  catch {
    if (runtimeState === "failed") { await runtime.stop().catch(() => {}); runtime = null; status("Runtime unavailable. Try Play again."); }
    else status("Reset could not complete. Keep this tab open and try Reset again.");
    record("reset-failed");
  }
  finally { busy = false; refresh(); }
});
$("fullscreen").addEventListener("click", async () => { try { await $("game").requestFullscreen(); } catch { status("Fullscreen unavailable"); } });
$("game").addEventListener("click", () => $("game").focus());
$("start").addEventListener("pointerdown", event => {
  if (!runtime || busy) return;
  event.preventDefault(); $("game").focus(); keys.add("Enter");
  const up = () => { keys.delete("Enter"); runtime?.setInput({ keys: [...keys] }); window.removeEventListener("pointerup", up); window.removeEventListener("pointercancel", up); };
  window.addEventListener("pointerup", up, { once: true }); window.addEventListener("pointercancel", up, { once: true });
});
$("start").addEventListener("keydown", event => { if (["Enter", "Space"].includes(event.code) && runtime && !busy) { event.preventDefault(); keys.add("Enter"); runtime.setInput({ keys: [...keys] }); } });
$("start").addEventListener("keyup", () => { keys.delete("Enter"); runtime?.setInput({ keys: [...keys] }); });
$("report").addEventListener("click", () => {
  const data = report({ manifest, imageVerified, runtimeState, connectionState, events, runtimeMetrics: runtime?.diagnostics() });
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const link = document.createElement("a"); link.href = url; link.download = "halo-test-report.json"; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
const mapped = new Set(["KeyW", "KeyA", "KeyS", "KeyD", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Space", "Enter", "KeyZ", "KeyX", "KeyC", "KeyV", "KeyE", "KeyQ"]);
$("game").addEventListener("keydown", event => { if (mapped.has(event.code) && runtime && !busy) { event.preventDefault(); keys.add(event.code); runtime.setInput({ keys: [...keys] }); } });
$("game").addEventListener("keyup", event => { keys.delete(event.code); runtime?.setInput({ keys: [...keys] }); });
$("game").addEventListener("blur", release);
window.addEventListener("blur", release); window.addEventListener("gamepaddisconnected", release);
window.addEventListener("pagehide", () => { release(); void runtime?.stop().catch(() => {}); });
document.addEventListener("visibilitychange", () => { if (document.hidden) release(); });
let lastNetworkStatus = 0;
function inputFrame(time = 0) {
  if (time - lastNetworkStatus >= 1000) {
    lastNetworkStatus = time;
    const state = runtime?.networkDiagnostics()?.state;
    connectionState = state === "gateway-authenticated" ? "gateway-authenticated" : "unavailable";
    $("connection").textContent = connectionState === "gateway-authenticated" ? "Gateway connected · guest validation pending" : "Guest networking unavailable";
  }
  if (runtime && !busy && document.activeElement === $("game") && !document.hidden) {
    const pad = [...(navigator.getGamepads?.() ?? [])].find(pad => pad?.connected && pad.mapping === "standard");
    runtime.setInput({ keys: [...keys], buttons: pad ? pad.buttons.slice(0, 17).map(button => Math.max(0, Math.min(1, button.value))) : [], axes: pad ? pad.axes.slice(0, 4).map(axis => Math.max(-1, Math.min(1, axis))) : [] });
  }
  requestAnimationFrame(inputFrame);
}
void readBuild(); requestAnimationFrame(inputFrame);
