import { validateManifest, verifyImage, readBounded } from "./model.mjs";
import { imageCache } from "./image-cache.mjs";

export async function prepareImage(manifest, { fetcher = fetch, cache = imageCache(), onProgress = () => {} } = {}) {
  manifest = validateManifest(manifest);
  if (manifest.status !== "ready") throw new Error("No qualified build selected");
  const { sha256, bytes: size, path } = manifest.image;
  onProgress({ phase: "checking-cache", loaded: 0, total: size });
  let cached;
  try { cached = await cache.get(sha256); } catch { /* Optional cache. */ }
  if (cached) {
    try {
      await verifyImage(cached, manifest);
      onProgress({ phase: "ready", loaded: size, total: size, cached: true });
      return cached;
    } catch { try { await cache.remove(sha256); } catch {} }
  }
  onProgress({ phase: "downloading", loaded: 0, total: size });
  const response = await fetcher(path, { cache: "no-store", redirect: "error", credentials: "same-origin" });
  if (!response.ok) throw new Error("Test image unavailable. Reload to retry.");
  const length = response.headers.get("Content-Length");
  if (length !== null && Number(length) !== size) throw new Error("Image size does not match selected build");
  const bytes = await readBounded(response, size, loaded => onProgress({ phase: "downloading", loaded, total: size }));
  onProgress({ phase: "verifying", loaded: size, total: size });
  await verifyImage(bytes, manifest);
  try { await cache.put(sha256, bytes); } catch { /* Still usable this session. */ }
  onProgress({ phase: "ready", loaded: size, total: size, cached: false });
  return bytes;
}
