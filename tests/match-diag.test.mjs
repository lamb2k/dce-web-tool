import test from "node:test";
import assert from "node:assert/strict";
import { findBlock, readBlock, summary } from "../public/match-diag.mjs";
function block(at) {
  const heap = new Uint8Array(4096), v = new DataView(heap.buffer, at, 440), put = (o, s) => heap.set(new TextEncoder().encode(s), at + o);
  [0x4F4C4148, 0x4741494F, 0x5443414D, 0x31564548, 1].forEach((w, i) => v.setUint32(i * 4, w, true));
  v.setUint32(20, 2, true); v.setInt32(32, 96, true); v.setInt32(36, -4, true); v.setUint32(56, 0xe1234567, true); v.setInt32(60, 77, true);
  heap[at + 72] = 2; heap[at + 73] = 252; heap[at + 76] = 7; heap[at + 83] = 7;
  put(88, "failed"); put(120, "opence_world.c"); put(144, "OPENCE_WORLD_CONSTRUCT");
  return heap;
}
test("finds the block and names the failing check, object and transport", () => {
  const heap = block(1024), base = findBlock(new Uint32Array(heap.buffer));
  assert.equal(base, 1024);
  const r = readBlock(heap, base);
  assert.equal(r.seq, 2);
  assert.deepEqual([r.failingCheck.file, r.failingCheck.line, r.failingCheck.check, r.failingCheck.returnCode], ["opence_world.c", 96, "OPENCE_WORLD_CONSTRUCT", -4]);
  assert.deepEqual([r.lastObject.tag, r.lastObject.kind, r.lastObject.id], ["0xe1234567", "weapon", 77]);
  assert.equal(r.world, "OPENCE_WORLD_CONSTRUCT"); assert.equal(r.transport.error, "peer closed"); assert.equal(r.route.failure, "connection lost");
  assert.match(summary(r), /OPENCE_WORLD_CONSTRUCT at opence_world.c:96, return code -4/);
});
test("no magic: nothing found, nothing read", () => {
  const heap = new Uint8Array(4096);
  assert.equal(findBlock(new Uint32Array(heap.buffer)), -1); assert.equal(readBlock(heap, 0), null);
});
import { diagNormal } from '../public/match-diag.mjs';
test('only a decided match or the player leaving, with nothing wrong, is a normal end', () => {
  const ok = { end: 'finished', message: '', failingCheck: { check: '' }, page: { terminalReason: 0 } };
  assert.equal(diagNormal(ok), true);
  assert.equal(diagNormal({ ...ok, end: 'left' }), true);
  assert.equal(diagNormal({ ...ok, page: { terminalReason: 7 } }), true);
  for (const bad of [{ end: 'failed' }, { end: 'ended' }, { end: 'host ended match' }, { end: 'connection failed in lobby' }, { message: 'MULTIPLAYER: connection lost' },
    { failingCheck: { check: 'OPENCE_LOBBY_TRANSPORT' } }, { page: { terminalReason: 3 } }]) assert.equal(diagNormal({ ...ok, ...bad }), false, JSON.stringify(bad));
});
