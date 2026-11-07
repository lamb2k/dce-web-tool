import { blankVmu, parseVmu, validateOwnedFile, putFile, seedVms, identityVms } from "./vmu.mjs";
const hex = bytes => [...bytes].map(v => v.toString(16).padStart(2, "0")).join("");
const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const pkcs8Prefix = Uint8Array.from([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
const request = req => new Promise((resolve, reject) => { req.onsuccess = () => resolve(req.result); req.onerror = () => reject(new Error("VMU storage unavailable")); });
function complete(tx) { return new Promise((resolve, reject) => { tx.oncomplete = resolve; tx.onabort = tx.onerror = () => reject(new Error("VMU storage commit failed")); }); }
async function openDatabase() {
  const req = indexedDB.open("halo-device-vmu-v1", 1);
  req.onupgradeneeded = () => req.result.createObjectStore("device");
  return request(req);
}
async function read(db, key) { return request(db.transaction("device").objectStore("device").get(key)); }
async function write(db, entries) { const tx = db.transaction("device", "readwrite"), done = complete(tx); for (const [key, value] of entries) tx.objectStore("device").put(value, key); await done; }
async function valid(bytes) { parseVmu(bytes); await validateOwnedFile(bytes, "HALONETR"); await validateOwnedFile(bytes, "HALONETK"); return bytes; }
export async function privateIdentity(bytes) {
  const body = await validateOwnedFile(bytes, "HALONETK"); if (!body) return null;
  const der = new Uint8Array(48); der.set(pkcs8Prefix); der.set(body.subarray(8, 40), 16);
  const privateKey = await crypto.subtle.importKey("pkcs8", der, "Ed25519", false, ["sign"]); der.fill(0);
  const publicBytes = body.slice(40, 72), publicKey = await crypto.subtle.importKey("raw", publicBytes, "Ed25519", false, ["verify"]);
  const message = new TextEncoder().encode("DCE local identity readback");
  const signature = await crypto.subtle.sign("Ed25519", privateKey, message);
  if (!await crypto.subtle.verify("Ed25519", publicKey, signature, message)) throw new Error("VMU identity invalid");
  return { privateKey, publicKey: "ed25519:" + hex(publicBytes) };
}
export async function acquireVmu() {
  if (!navigator.locks?.request) throw new Error("Exclusive VMU storage unavailable");
  let unlock, heldResolve, heldReject;
  const held = new Promise((resolve, reject) => { heldResolve = resolve; heldReject = reject; });
  const lifetime = navigator.locks.request("halo-device-vmu-v1", { mode: "exclusive", ifAvailable: true }, async lock => {
    if (!lock) { heldReject(new Error("Game already open in another tab")); return; }
    heldResolve(); await new Promise(resolve => { unlock = resolve; });
  });
  lifetime.catch(heldReject); await held;
  let db;
  try {
    db = await openDatabase(); let key = await read(db, "key");
    if (!key) {
      // Never replace a lost key while any encrypted state exists.
      if (await read(db, "current") || await read(db, "previous")) throw new Error("VMU encryption key unavailable");
      key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      await write(db, [["key", key]]); key = await read(db, "key");
    }
    if (!key || key.extractable || key.algorithm.name !== "AES-GCM") throw new Error("VMU encryption unavailable");
    const aad = new TextEncoder().encode("HaloDCE VMU snapshot v1");
    async function decrypt(record) {
      if (!record || record.iv?.byteLength !== 12 || record.data?.byteLength !== 131088) throw new Error("VMU snapshot invalid");
      return valid(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: record.iv, additionalData: aad }, key, record.data)));
    }
    let record = await read(db, "current"), bytes;
    if (record) bytes = await decrypt(record); // Corruption is surfaced; never silently roll identity/RNG back.
    else {
      if (await read(db, "previous")) throw new Error("VMU current snapshot unavailable");
      bytes = blankVmu();
    }
    record = Boolean(record);
    let chain = Promise.resolve();
    async function commit(next) {
      await valid(next);
      if (record && same(next, bytes)) return; // Unchanged checkpoints do not churn storage.
      const previous = await read(db, "current"), iv = crypto.getRandomValues(new Uint8Array(12));
      if (previous) await decrypt(previous);
      const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, next);
      await write(db, [...(previous ? [["previous", previous]] : []), ["current", { iv, data }]]);
      const back = await decrypt(await read(db, "current"));
      if (!same(next, back)) throw new Error("VMU readback failed");
      record = true; bytes = back;
    }
    function save(next) { const copy = next.slice(); const result = chain.then(() => commit(copy)); chain = result.catch(() => {}); return result; }
    let identity = await privateIdentity(bytes);
    if (!identity) {
      const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
      const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
      if (der.length !== 48 || !same(der.subarray(0, 16), pkcs8Prefix)) throw new Error("Identity format unsupported");
      const pub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
      const packaged = await identityVms(der.subarray(16), pub); der.fill(0);
      await save(putFile(bytes, "HALONETK", packaged)); packaged.fill(0);
      identity = await privateIdentity(bytes); // Durable, decryptable identity BEFORE enrollment.
    }
    return {
      identity,
      async prepare(utc, trusted = false) {
        const seed = crypto.getRandomValues(new Uint8Array(32));
        try { const file = await seedVms(seed, utc, trusted); const next = putFile(bytes, "HALONETR", file, { replace: true }); file.fill(0); await save(next); return bytes.slice(); }
        finally { seed.fill(0); }
      },
      async checkpoint(next) {
        const incoming = await privateIdentity(next);
        if (!incoming || incoming.publicKey !== identity.publicKey) throw new Error("VMU identity changed");
        return save(next);
      },
      async close() { await chain; db.close(); unlock(); await lifetime; },
    };
  } catch (error) { db?.close(); unlock?.(); await lifetime; throw error; }
}
