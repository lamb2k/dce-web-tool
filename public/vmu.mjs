// Dreamcast VMU filesystem. All writes happen before the emulator starts.
export const VMU_BYTES = 128 * 1024;
const BLOCK = 512, FREE = 0xfffc, END = 0xfffa;
const encoder = new TextEncoder();
const isBytes = bytes => ArrayBuffer.isView(bytes) && Object.prototype.toString.call(bytes) === "[object Uint8Array]";
const fail = () => { throw new Error("VMU storage is invalid"); };
const view = bytes => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
export function blankVmu() {
  const bytes = new Uint8Array(VMU_BYTES), root = bytes.subarray(255 * BLOCK);
  root.set(Uint8Array.from("5555555555555555555555555555555501ffffff6400000000000000000000000000000000000000000000000000000019981127000059040000000000000000ff000000ff00fe000100fd000d000500c8001f00".match(/../g), x => parseInt(x, 16)));
  const fat = view(bytes.subarray(254 * BLOCK));
  for (let i = 0; i < 256; i++) fat.setUint16(i * 2, FREE, true);
  for (let i = 241; i <= 255; i++) fat.setUint16(i * 2, i === 241 || i >= 254 ? END : i - 1, true);
  parseVmu(bytes); return bytes;
}
export function parseVmu(bytes) {
  if (!isBytes(bytes) || bytes.length !== VMU_BYTES) fail();
  const root = view(bytes.subarray(255 * BLOCK));
  if (!bytes.subarray(255 * BLOCK, 255 * BLOCK + 16).every(v => v === 0x55)) fail();
  const fatBlock = root.getUint16(70, true), fatSize = root.getUint16(72, true), dirBlock = root.getUint16(74, true), dirSize = root.getUint16(76, true), users = root.getUint16(80, true);
  // Restrict to the standard 128 KiB format, rather than guessing unfamiliar layouts.
  if (fatBlock !== 254 || fatSize !== 1 || dirBlock !== 253 || dirSize !== 13 || users !== 200) fail();
  const fat = view(bytes.subarray(fatBlock * BLOCK, (fatBlock + 1) * BLOCK));
  for (let i = 241; i < 256; i++) if (fat.getUint16(i * 2, true) !== (i === 241 || i >= 254 ? END : i - 1)) fail();
  const used = new Set(), files = new Map(), empty = [];
  for (let block = dirBlock; block > dirBlock - dirSize; block--) for (let n = 0; n < 16; n++) {
    const offset = block * BLOCK + n * 32, entry = view(bytes.subarray(offset, offset + 32));
    const type = entry.getUint8(0);
    if (!type) { empty.push(offset); continue; }
    if (type !== 0x33 && type !== 0xcc) fail();
    const rawName = bytes.subarray(offset + 4, offset + 16);
    const end = rawName.indexOf(0), nameBytes = end < 0 ? rawName : rawName.subarray(0, end);
    if (!nameBytes.length || !nameBytes.every(v => v >= 32 && v <= 126) || (end >= 0 && !rawName.subarray(end).every(v => !v))) fail();
    const name = String.fromCharCode(...nameBytes);
    if (files.has(name)) fail();
    const count = entry.getUint16(24, true), header = entry.getUint16(26, true);
    if (!count || count > users || header >= count) fail();
    const chain = []; let next = entry.getUint16(2, true);
    for (let i = 0; i < count; i++) {
      if (next >= users || used.has(next)) fail();
      used.add(next); chain.push(next); next = fat.getUint16(next * 2, true);
    }
    if (next !== END) fail();
    files.set(name, { offset, type, chain, header });
  }
  // Orphan allocation is also an in-progress/corrupt transaction, never a checkpoint.
  for (let i = 0; i < users; i++) if (!used.has(i) && fat.getUint16(i * 2, true) !== FREE) fail();
  return { files, empty, fat, users };
}
export function getFile(bytes, name) {
  const file = parseVmu(bytes).files.get(name); if (!file) return null;
  const data = new Uint8Array(file.chain.length * BLOCK);
  file.chain.forEach((block, i) => data.set(bytes.subarray(block * BLOCK, (block + 1) * BLOCK), i * BLOCK));
  return data;
}
export function putFile(bytes, name, data, { replace = false } = {}) {
  if (!/^[A-Z0-9]{1,12}$/.test(name) || !isBytes(data) || data.length > BLOCK) fail();
  const copy = bytes.slice(), fs = parseVmu(copy); let file = fs.files.get(name);
  if (file) { if (!replace || file.type !== 0x33 || file.chain.length !== 1 || file.header !== 0) fail(); }
  else {
    const offset = fs.empty[0]; let block = fs.users - 1;
    while (block >= 0 && fs.fat.getUint16(block * 2, true) !== FREE) block--;
    if (offset === undefined || block < 0) throw new Error("VMU is full");
    copy.fill(0, offset, offset + 32); const entry = view(copy.subarray(offset, offset + 32));
    entry.setUint8(0, 0x33); entry.setUint16(2, block, true); copy.set(encoder.encode(name), offset + 4);
    // Valid cosmetic BCD timestamp, independent of the trusted clock policy.
    copy.set([0x20, 0x00, 0x01, 0x01, 0, 0, 0, 6], offset + 16);
    entry.setUint16(24, 1, true); fs.fat.setUint16(block * 2, END, true);
    file = { chain: [block] };
  }
  const start = file.chain[0] * BLOCK; copy.fill(0, start, start + BLOCK); copy.set(data, start);
  parseVmu(copy); return copy;
}
export function crc16(bytes) {
  let crc = 0; for (const byte of bytes) { crc ^= byte << 8; for (let n = 0; n < 8; n++) crc = ((crc << 1) ^ ((crc & 0x8000) ? 0x1021 : 0)) & 0xffff; } return crc;
}
async function digest(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }
function packageVms(body, short, long) {
  const out = new Uint8Array(128 + body.length), d = view(out);
  out.set(encoder.encode(short.padEnd(16, " "))); out.set(encoder.encode(long.padEnd(32, " ")), 16); out.set(encoder.encode("HaloDCE"), 48);
  d.setUint32(72, body.length, true); out.set(body, 128); d.setUint16(70, crc16(out), true); return out;
}
export async function seedVms(seed, utc, trusted = false) {
  if (seed.length !== 32 || !Number.isSafeInteger(utc) || utc < 0 || utc > 0xffffffff - 30 * 86400) fail();
  const body = new Uint8Array(96), d = view(body); body.set(encoder.encode("DCERN001")); body.set(seed, 8);
  d.setUint32(44, trusted ? 1 : 0, true); d.setUint32(48, utc, true); d.setUint32(52, utc, true); d.setUint32(56, utc + 30 * 86400, true);
  body.set(await digest(body.subarray(0, 64)), 64); return packageVms(body, "Halo network RNG", "Private device network seed");
}
export async function identityVms(seed, publicKey) {
  if (seed.length !== 32 || publicKey.length !== 32) fail();
  const body = new Uint8Array(104); body.set(encoder.encode("DCESIGN1")); body.set(seed, 8); body.set(publicKey, 40); body.set(await digest(body.subarray(0, 72)), 72);
  return packageVms(body, "Halo host key", "Private directory host identity");
}
export async function validateOwnedFile(bytes, name) {
  const raw = getFile(bytes, name); if (!raw) return null;
  const length = name === "HALONETR" ? 96 : name === "HALONETK" ? 104 : 0;
  if (!length || view(raw).getUint16(64, true) || view(raw).getUint16(68, true) || view(raw).getUint32(72, true) !== length) fail();
  const data = raw.slice(0, 128 + length), expected = view(data).getUint16(70, true); view(data).setUint16(70, 0, true);
  if (crc16(data) !== expected) fail();
  const body = raw.slice(128, 128 + length), magic = encoder.encode(length === 96 ? "DCERN001" : "DCESIGN1"), hashAt = length - 32;
  if (!equal(body.subarray(0, 8), magic) || !equal(body.subarray(hashAt), await digest(body.subarray(0, hashAt)))) fail();
  return body;
}
