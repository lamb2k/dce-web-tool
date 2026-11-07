import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile } from "node:fs/promises";
import { blankVmu, parseVmu, getFile, putFile, seedVms, identityVms, validateOwnedFile } from "../public/vmu.mjs";
import { privateIdentity } from "../public/vmu-store.mjs";
import { enrollmentProof, enrollDevice } from "../public/device-enrollment.mjs";
import { vmuCheckpointer } from "../public/vmu-checkpoint.mjs";
test("standard VMU preserves unrelated save and replaces seed in its existing block", async () => {
  let card = putFile(blankVmu(), "SAVE", new Uint8Array([1,2,3]));
  const before = card.slice(), file = await seedVms(new Uint8Array(32).fill(7), 1793800000, false);
  card = putFile(card, "HALONETR", file); const first = parseVmu(card).files.get("HALONETR").chain[0];
  card = putFile(card, "HALONETR", await seedVms(new Uint8Array(32).fill(8), 1793800001, true), { replace: true });
  assert.equal(parseVmu(card).files.get("HALONETR").chain[0], first);
  assert.deepEqual(getFile(card, "SAVE"), getFile(before, "SAVE"));
  assert.equal((await validateOwnedFile(card, "HALONETR"))[8], 8);
  assert.equal(new DataView((await validateOwnedFile(card, "HALONETR")).buffer).getUint32(44, true), 1);
});
test("VMU rejects truncated, root, crosslink, orphan and corrupt package snapshots", async () => {
  const initial = putFile(putFile(blankVmu(), "FIRST", new Uint8Array([1])), "SECOND", new Uint8Array([2]));
  assert.throws(() => parseVmu(initial.subarray(1)));
  const root = initial.slice(); root[255*512] = 0; assert.throws(() => parseVmu(root));
  const crossed = initial.slice(), fs = parseVmu(crossed); new DataView(crossed.buffer).setUint16(fs.files.get("SECOND").offset + 2, fs.files.get("FIRST").chain[0], true); assert.throws(() => parseVmu(crossed));
  const orphan = initial.slice(); new DataView(orphan.buffer).setUint16(254*512, 0xfffa, true); assert.throws(() => parseVmu(orphan));
  const packaged = putFile(initial, "HALONETR", await seedVms(new Uint8Array(32), 1793800000));
  packaged[parseVmu(packaged).files.get("HALONETR").chain[0]*512+140] ^= 1;
  await assert.rejects(validateOwnedFile(packaged, "HALONETR"));
});
test("VMU full failure does not alter card", () => {
  let card = blankVmu(); for (let i = 0; i < 200; i++) card = putFile(card, "F" + i, new Uint8Array([i]));
  const saved = card.slice(); assert.throws(() => putFile(card, "EXTRA", new Uint8Array([1])), /full/); assert.deepEqual(card, saved);
});
test("VMU snapshots from the disposable runtime iframe are accepted", () => {
  const foreign = vm.runInNewContext("new Uint8Array(131072)"); foreign.set(blankVmu());
  assert.equal(parseVmu(foreign).files.size, 0);
  assert.equal(parseVmu(putFile(foreign, "SAVE", vm.runInNewContext("new Uint8Array([1,2,3])"))).files.size, 1);
});
test("identity readback derives matching key and refuses mismatched private/public identity", async () => {
  // Public, deliberately known synthetic fixture; never a provisioned device.
  const seed = new Uint8Array(32).fill(0x22), pub = Uint8Array.from(Buffer.from("a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0", "hex"));
  const card = putFile(blankVmu(), "HALONETK", await identityVms(seed, pub));
  assert.equal((await privateIdentity(card)).publicKey, "ed25519:" + Buffer.from(pub).toString("hex"));
  pub[0] ^= 1; await assert.rejects(privateIdentity(putFile(blankVmu(), "HALONETK", await identityVms(seed, pub))));
});
test("enrollment canonical proof is bounded to identity/master and signed time", async () => {
  const config = { masterKeyId: "10ba682c8ad13513" }, publicKey = "ed25519:a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";
  const challenge = { protocol: 1, masterKeyId: config.masterKeyId, keyId: "1325b850c2871916", publicKey, challenge: "000102030405060708090a0b0c0d0e0f", expires:1793800060, serverTime:1793800000, sessionBinding:"a".repeat(64) };
  assert.equal(enrollmentProof(config, challenge, publicKey), `DCE-Device-Enrollment-v1\n${config.masterKeyId}\n${publicKey}\n${challenge.challenge}\n1793800060\n${"a".repeat(64)}`);
  assert.throws(() => enrollmentProof(config, { ...challenge, expires:1793800061 }, publicKey));
  assert.throws(() => enrollmentProof(config, { ...challenge, masterKeyId:"0".repeat(16) }, publicKey));
  assert.deepEqual(await enrollDevice({}, undefined, { fetcher: async () => new Response(null, { status:503 }) }), { available:false });
  await assert.rejects(enrollDevice({}, undefined, { fetcher: async () => Response.json({ configured:true }) }));
});
test("persistent commit failure surfaces and prevents final reset continuation", async () => {
  let card = putFile(blankVmu(), "HALONETR", await seedVms(new Uint8Array(32), 1793800000));
  card = putFile(card, "HALONETK", await identityVms(new Uint8Array(32), new Uint8Array(32)));
  let saved = 0, attempts = 0, restarted = false;
  const checkpoint = vmuCheckpointer({ snapshot: () => card.slice(), resume() {}, persist: async () => { attempts++; throw new Error("storage fault"); }, saved: () => saved++ });
  await checkpoint(); await assert.rejects(checkpoint(), /storage fault/);
  await assert.rejects((async () => { await checkpoint(true); restarted = true; })(), /storage fault/);
  assert.equal(attempts, 2); assert.equal(saved, 0); assert.equal(restarted, false);
});
test("in-progress FAT snapshot never replaces a valid stored card", async () => {
  const corrupt = blankVmu(); new DataView(corrupt.buffer).setUint16(254*512, 0xfffa, true);
  let now = 0, commits = 0;
  const checkpoint = vmuCheckpointer({ snapshot: () => corrupt, resume() {}, persist: async () => commits++, now: () => now, sleep: async ms => { now += ms; } });
  await checkpoint(); await assert.rejects(checkpoint(true), /still in progress/); assert.equal(commits, 0);
});
test("browser packages match independent game Python provisioner bytes", async () => {
  const oracle = JSON.parse(await readFile(new URL("./fixtures/vmu-packages.json", import.meta.url)));
  const seed = new Uint8Array(32).fill(0x22), pub = Uint8Array.from(Buffer.from(oracle.public, "hex"));
  assert.equal(Buffer.from(await seedVms(seed, 1793800000, true)).toString("hex"), oracle.seed);
  assert.equal(Buffer.from(await identityVms(seed, pub)).toString("hex"), oracle.identity);
});
test("enrollment produces exact independent Go fixture signature without sending seed", async () => {
  const fixture = JSON.parse(await readFile(new URL("./fixtures/enrollment-vectors.json", import.meta.url)));
  const challenge = JSON.parse(fixture.challenge_response.body), registered = JSON.parse(fixture.register_response.body);
  const config = { protocol:1, configured:true, masterPublicKey:fixture.master_public, masterKeyId:challenge.masterKeyId, proofDomain:"DCE-Device-Enrollment-v1", challengeTtl:60 };
  const card = putFile(blankVmu(), "HALONETK", await identityVms(Uint8Array.from(Buffer.from(fixture.host_seed_hex,"hex")), Uint8Array.from(Buffer.from(fixture.host_public.slice(8),"hex"))));
  const identity = await privateIdentity(card); let count = 0;
  const fetcher = async (url, options) => {
    assert.equal(options.credentials, "same-origin"); assert.equal(options.redirect, "error"); count++;
    if (url.endsWith("/config")) { assert.equal(options.body, ""); return Response.json(config); }
    const body = JSON.parse(options.body);
    if (url.endsWith("/challenge")) { assert.deepEqual(body, { publicKey:fixture.host_public }); return Response.json(challenge); }
    assert.deepEqual(body, { publicKey:fixture.host_public, challenge:challenge.challenge, signature:fixture.signature });
    return Response.json(registered);
  };
  let time = 0; const result = await enrollDevice(identity, fixture.master_public, { fetcher, now: () => time += 100 });
  assert.equal(result.available, true); assert.equal(result.utc, registered.serverTime); assert.equal(count, 3);
});
