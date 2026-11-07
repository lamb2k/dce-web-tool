export const MAX_IMAGE_BYTES = 128 * 1024 * 1024;
export async function readBounded(response, limit, onProgress = () => {}) {
  if (!response.body) throw new Error("Empty response");
  const reader = response.body.getReader();
  const chunks = []; let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) { await reader.cancel(); throw new Error("Response exceeds selected size"); }
      chunks.push(value);
      onProgress(length);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}
const hash = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
export function validateManifest(value) {
  if (value?.schema !== 1) throw new Error("Unsupported build manifest");
  if (value.status === "pending") return { schema: 1, status: "pending", reason: "Browser build awaiting qualification." };
  if (value.status !== "ready" || !/^[a-zA-Z0-9._-]{1,100}$/.test(value.build ?? "") ||
      !/^[a-f0-9]{40}$/.test(value.commit ?? "") || !hash(value.image?.sha256) ||
      !Number.isSafeInteger(value.image.bytes) || value.image.bytes < 1 || value.image.bytes > MAX_IMAGE_BYTES ||
      !/^\/files\/[a-zA-Z0-9][a-zA-Z0-9._-]*\.(cdi|chd)$/.test(value.image.path ?? "") ||
      value.image.path.includes("..")) throw new Error("Invalid pinned build manifest");
  if (value.directoryMasterPublicKey !== undefined && !/^ed25519:[a-f0-9]{64}$/.test(value.directoryMasterPublicKey)) throw new Error("Invalid directory master pin");
  return { schema: 1, status: "ready", build: value.build, commit: value.commit,
    ...(value.directoryMasterPublicKey ? { directoryMasterPublicKey: value.directoryMasterPublicKey } : {}),
    image: { path: value.image.path, bytes: value.image.bytes, sha256: value.image.sha256 } };
}

export async function verifyImage(bytes, manifest) {
  if (manifest.status !== "ready") throw new Error("No qualified build selected");
  if (bytes.byteLength !== manifest.image.bytes) throw new Error("Image size does not match selected build");
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const actual = [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
  if (actual !== manifest.image.sha256) throw new Error("Image hash does not match selected build");
  return actual;
}

export function matchTarget(text) {
  const target = text.trim();
  if (!target || target.length > 128 || !/^[a-zA-Z0-9.:[\]_-]+$/.test(target)) throw new Error("Enter a match address or invite code");
  return target;
}

export function report({ manifest, imageVerified, runtimeState, connectionState, events, runtimeMetrics = {} }) {
  const metrics = {};
  for (const key of ["frameCount", "memoryBytes", "sampleRate", "bufferedMs", "audioStarvations", "maxAudioGapMs", "workletUnderrunFrames", "workletDroppedFrames", "longTasks", "maxLongTaskMs", "networkStartupFrames", "networkTxFrames", "networkRxFrames", "networkTxDropped", "networkRxDropped", "networkDeviceStarted", "networkTransportReady"]) {
    if (Number.isFinite(runtimeMetrics[key]) && runtimeMetrics[key] >= 0) metrics[key] = Math.round(runtimeMetrics[key]);
  }
  if (Number.isInteger(runtimeMetrics.networkTerminalReason) && runtimeMetrics.networkTerminalReason >= 0 && runtimeMetrics.networkTerminalReason <= 7) metrics.networkTerminalReason = runtimeMetrics.networkTerminalReason;
  if (Number.isInteger(runtimeMetrics.networkCloseCode) && (runtimeMetrics.networkCloseCode === 0 || (runtimeMetrics.networkCloseCode >= 1000 && runtimeMetrics.networkCloseCode <= 4999))) metrics.networkCloseCode = runtimeMetrics.networkCloseCode;
  if (["running", "suspended", "closed", "unavailable"].includes(runtimeMetrics.audioState)) metrics.audioState = runtimeMetrics.audioState;
  if (["worklet", "openal", "unavailable"].includes(runtimeMetrics.audioPath)) metrics.audioPath = runtimeMetrics.audioPath;
  // No address, invite, credentials, input stream, serial dump or local file name.
  return { schema: 1, generatedAt: new Date().toISOString(),
    build: manifest?.status === "ready" ? manifest.build : null,
    commit: manifest?.status === "ready" ? manifest.commit : null,
    imageSha256: imageVerified ? manifest.image.sha256 : null,
    runtimeState, connectionState, metrics, events: events.slice(-32).map(({ at, code }) => ({ at, code })) };
}
