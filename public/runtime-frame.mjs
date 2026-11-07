import { CORE, AUDIO_LATENCY_MS, inputValues } from "./runtime-config.mjs";
import { guestNetwork } from "./guest-network.mjs";
let core, timer, observer, stopped = false, previous = new Int32Array(24);
let network, failed = false;
const metrics = { frameCount: 0, memoryBytes: 0, audioState: "unavailable", audioPath: "unavailable", sampleRate: 0,
  workletUnderrunFrames: 0, workletDroppedFrames: 0,
  bufferedMs: 0, audioStarvations: 0, maxAudioGapMs: 0, longTasks: 0, maxLongTaskMs: 0,
  networkTerminalReason: 0, networkCloseCode: 0, networkStartupFrames: 0, networkTxFrames: 0, networkRxFrames: 0, networkTxDropped: 0, networkRxDropped: 0, networkDeviceStarted: 0, networkTransportReady: 0, networkRenewState: 0, networkRenewals: 0, networkRenewFailures: 0 };
let notify = () => {};
function sample() {
  if (!core || stopped) return;
  metrics.frameCount = core._get_current_frame_count();
  metrics.memoryBytes = core.HEAPU8?.byteLength ?? core.wasmExports?.memory?.buffer?.byteLength ?? 0;
  if (network) {
    const m = network.metrics();
    metrics.networkTerminalReason = m.terminalReason; metrics.networkCloseCode = m.closeCode;
    metrics.networkTxFrames = m.txFrames; metrics.networkRxFrames = m.rxFrames;
    metrics.networkTxDropped = m.txDropped; metrics.networkRxDropped = m.rxDropped;
    // 0 idle, 1 renewed, 2 final grant, 3 last renewal failed.
    metrics.networkRenewState = { idle: 0, renewed: 1, final: 2, failed: 3 }[m.renewState] ?? 0;
    metrics.networkRenewals = m.renewals; metrics.networkRenewFailures = m.renewFailures;
    metrics.networkDeviceStarted = Number(m.deviceStarted); metrics.networkTransportReady = Number(m.transportReady);
  }
  const worklet = core._flyAud;
  if (worklet?.ready && !worklet.failed) {
    metrics.audioPath = "worklet"; metrics.audioState = worklet.ctx.state; metrics.sampleRate = worklet.ctx.sampleRate;
    metrics.bufferedMs = Math.round((worklet.stats?.avail ?? 0) / worklet.ctx.sampleRate * 1000);
    metrics.workletUnderrunFrames = worklet.stats?.under ?? 0;
    metrics.workletDroppedFrames = (worklet.stats?.drop ?? 0) + (worklet.drop ?? 0);
    return;
  }
  const context = Object.values(core.AL?.contexts ?? {})[0];
  if (context) {
    metrics.audioPath = "openal"; metrics.audioState = context.audioCtx.state; metrics.sampleRate = context.audioCtx.sampleRate;
    const source = Object.values(context.sources ?? {})[0];
    const end = source?.audioQueue?.reduce((last, item) => Math.max(last, item._startTime + item._duration), 0) ?? 0;
    metrics.bufferedMs = Math.max(0, Math.round((end - context.audioCtx.currentTime) * 1000));
  }
}
function monitorAudio() {
  if (!core.AL?.updateSourceTime) return;
  const original = core.AL.updateSourceTime, episodes = new WeakSet();
  core.AL.updateSourceTime = function(source) {
    if (core._flyAud?.ready && !core._flyAud.failed) return original.call(this, source);
    const end = (source.audioQueue ?? []).reduce((last, item) => Math.max(last, item._startTime + item._duration), 0);
    const gap = source.context.audioCtx.currentTime - end;
    const starved = end > 0 && gap > 0.002 && source.state === 0x1012 &&
      source.context.audioCtx.state === "running" && document.visibilityState === "visible";
    if (starved && !episodes.has(source)) { metrics.audioStarvations++; episodes.add(source); }
    if (!starved) episodes.delete(source);
    if (starved) metrics.maxAudioGapMs = Math.max(metrics.maxAudioGapMs, Math.round(gap * 1000));
    return original.call(this, source);
  };
}
function loadCoreScript() {
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = CORE.javascript.path;
    script.integrity = "sha256-" + btoa(String.fromCharCode(...CORE.javascript.sha256.match(/../g).map(value => parseInt(value, 16))));
    script.crossOrigin = "anonymous";
    script.onload = resolve; script.onerror = () => reject(new Error("Runtime unavailable"));
    document.head.append(script);
  });
}
window.haloRuntime = {
  async boot({ imageBytes, wasmBinary, vmuBytes, clock, onState }) {
    notify = onState; notify("booting");
    // Audio contexts belong to this frame so its narrow worklet CSP applies.
    await loadCoreScript();
    if (stopped) throw new Error("Runtime stopped");
    core = await window.EJS_Runtime({ noInitialRun: true, canvas: document.getElementById("canvas"),
      parent: document.body, wasmBinary, callbacks: {}, print() {}, printErr() {},
      onAbort() { failed = true; void network?.stop(); notify("failed"); }, onExit() { void network?.stop(); if (!stopped) { failed = true; notify("failed"); } } });
    if (stopped || failed) throw new Error("Runtime stopped");
    // #role=host|join on the tester page: the Worker refuses all query strings. Never an address.
    const asked = /^#role=(host|join)$/.exec(window.parent?.location?.hash ?? "");
    network = guestNetwork(core, { role: asked ? asked[1] : null });
    await network.prepare();
    if (stopped || failed) throw new Error("Runtime stopped");
    const FS = core.FS;
    for (const path of ["/home/web_user/.config/retroarch", "/data/saves", "/system/dc"]) FS.mkdirTree(path);
    if (vmuBytes?.length !== 131072 || typeof core._halo_vmu_flush !== "function" || typeof core._halo_vmu_provisioned !== "function") throw new Error("Device storage runtime unavailable");
    FS.writeFile("/system/dc/vmu_save_A1.bin", vmuBytes);
    core._halo_vmu_provisioned();
    if (clock) {
      const elapsed = (clock.now() - clock.at) / 1000;
      if (!Number.isFinite(elapsed) || elapsed < 0 || elapsed > 60 || core._halo_vmu_set_utc(clock.utc + elapsed) !== 1) throw new Error("Verified clock unavailable");
    }
    FS.writeFile("/halo.cdi", imageBytes);
    FS.writeFile("/home/web_user/.config/retroarch/retroarch.cfg", [
      'system_directory = "/system"', 'savefile_directory = "/data/saves"', 'video_driver = "gl"',
      'audio_driver = "openal"', 'video_vsync = true', 'video_smooth = false', 'pause_nonactive = false', `audio_latency = ${AUDIO_LATENCY_MS}`,
    ].join("\n") + "\n");
    const options = 'reicast_hle_bios = "enabled"\nreicast_boot_to_bios = "disabled"\nreicast_threaded_rendering = "disabled"\nreicast_synchronous_rendering = "disabled"\nreicast_internal_resolution = "640x480"\nreicast_mipmapping = "enabled"\nreicast_emulate_bba = "enabled"\nreicast_per_content_vmus = "disabled"\nreicast_vmu1_screen_display = "enabled"\nreicast_vmu1_screen_position = "Lower Right"\nreicast_vmu1_screen_size_mult = "2x"\n';
    core.callbacks.setupCoreSettingFile = path => { FS.mkdirTree(path.slice(0, path.lastIndexOf("/"))); FS.writeFile(path, options); };
    core.callMain(["/halo.cdi"]); core.pauseMainLoop?.();
    metrics.networkStartupFrames = core._get_current_frame_count();
    if (stopped || failed) throw new Error("Runtime stopped");
    // Core initialization may tear down BBA. Connect only after it, before yielding a guest frame.
    if (metrics.networkStartupFrames === 0) await network.activate();
    else await network.stop();
    if (stopped || failed) throw new Error("Runtime stopped");
    core.resumeMainLoop?.(); monitorAudio();
    if (typeof PerformanceObserver === "function") {
      try { observer = new PerformanceObserver(list => { for (const entry of list.getEntries()) { metrics.longTasks++; metrics.maxLongTaskMs = Math.max(metrics.maxLongTaskMs, Math.round(entry.duration)); } }); observer.observe({ type: "longtask", buffered: false }); } catch { /* Optional metric. */ }
    }
    timer = setInterval(sample, 250); sample(); notify("running");
  },
  setInput(input) {
    if (!core || stopped) return;
    const values = inputValues(input);
    values.forEach((value, id) => { if (value !== previous[id]) core._simulate_input(0, id, value); });
    previous = values;
  },
  releaseInput() { this.setInput({}); },
  diagnostics() { sample(); return { ...metrics }; },
  networkDiagnostics() { return network?.metrics() ?? { state: "unavailable", guestNetwork: false }; },
  snapshot(pause = false) {
    if (!core || stopped) throw new Error("VMU unavailable");
    if (pause) core.pauseMainLoop?.();
    if (core._halo_vmu_flush() !== 1) throw new Error("VMU flush failed");
    return core.FS.readFile("/system/dc/vmu_save_A1.bin").slice();
  },
  resume() { if (!stopped) core?.resumeMainLoop?.(); },
  clockUtc() { return core?._halo_vmu_rtc_utc(); },
  async stop() {
    if (stopped) return;
    this.releaseInput(); stopped = true;
    const networkStopped = network?.stop();
    clearInterval(timer); observer?.disconnect(); core?.pauseMainLoop?.();
    await networkStopped;
    if (core?._flyAud) { core._flyAud.node?.disconnect(); core._flyAud.node?.port.close(); core._flyAud.gain?.disconnect(); await core._flyAud.ctx?.close().catch(() => {}); }
    for (const context of Object.values(core?.AL?.contexts ?? {})) { clearInterval(context.interval); await context.audioCtx.close().catch(() => {}); }
    core = null; notify("stopped");
  },
};
window.addEventListener("error", () => { failed = true; void network?.stop(); if (!stopped) notify("failed"); });
window.addEventListener("pagehide", () => { void window.haloRuntime.stop().catch(() => {}); });
