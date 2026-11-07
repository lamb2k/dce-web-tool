import { readBounded } from "./model.mjs";
const pub = value => typeof value === "string" && /^ed25519:[a-f0-9]{64}$/.test(value);
const hex = (value, length) => typeof value === "string" && new RegExp(`^[a-f0-9]{${length}}$`).test(value);
const integer = value => Number.isSafeInteger(value) && value > 0 && value < 0xffffffff;
const fail = () => { throw new Error("Online setup could not be verified"); };
export function enrollmentProof(config, challenge, publicKey) {
  if (challenge?.protocol !== 1 || challenge.masterKeyId !== config.masterKeyId || challenge.publicKey !== publicKey ||
      !hex(challenge.keyId, 16) || !hex(challenge.challenge, 32) || !hex(challenge.sessionBinding, 64) ||
      !integer(challenge.expires) || !integer(challenge.serverTime) || challenge.expires - challenge.serverTime !== 60) fail();
  return ["DCE-Device-Enrollment-v1", config.masterKeyId, publicKey, challenge.challenge, String(challenge.expires), challenge.sessionBinding].join("\n");
}
export async function enrollDevice(identity, masterPin, { fetcher = fetch, now = () => performance.now() } = {}) {
  async function post(route, body) {
    const response = await fetcher("/api/device-enrollment/" + route, { method: "POST", credentials: "same-origin", redirect: "error", cache: "no-store", headers: { "Content-Type": "application/json" }, body: body === undefined ? "" : JSON.stringify(body), signal: AbortSignal.timeout(7000) });
    if (route === "config" && response.status === 503) return null;
    if (!response.ok) fail();
    return JSON.parse(new TextDecoder().decode(await readBounded(response, 2048)));
  }
  const config = await post("config");
  if (!config) return { available: false };
  if (!pub(masterPin) || config.protocol !== 1 || config.configured !== true || config.masterPublicKey !== masterPin ||
      !hex(config.masterKeyId, 16) || config.challengeTtl !== 60 || config.proofDomain !== "DCE-Device-Enrollment-v1") fail();
  const start = now(), challenge = await post("challenge", { publicKey: identity.publicKey });
  const proof = enrollmentProof(config, challenge, identity.publicKey);
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", identity.privateKey, new TextEncoder().encode(proof)));
  const before = now(); if (before - start > 15000 || before < start) fail();
  const result = await post("register", { publicKey: identity.publicKey, challenge: challenge.challenge, signature: btoa(String.fromCharCode(...signature)) });
  const received = now();
  if (result?.ok !== true || result.approved !== true || result.publicKey !== identity.publicKey || result.keyId !== challenge.keyId ||
      result.masterKeyId !== config.masterKeyId || typeof result.created !== "boolean" || !integer(result.serverTime) ||
      result.serverTime < challenge.serverTime || result.serverTime >= challenge.expires || received < before || received - before > 7000) fail();
  // UTC is authenticated by the relay and bounded by this monotonic request interval.
  return { available: true, utc: result.serverTime, received, uncertaintyMs: received - before + 1000 };
}
