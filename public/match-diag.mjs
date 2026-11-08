// Diagnostic builds only: reads the match-end block from guest RAM (src/net/match_diag.h, level.c).
// No effect on the core or guest: read only. Layout pinned by a _Static_assert in level.c.
const MAGIC = [0x4F4C4148, 0x4741494F, 0x5443414D, 0x31564548];
const WORLD = { 0: "none", [-1 & 255]: "OPENCE_WORLD_INVALID", [-2 & 255]: "OPENCE_WORLD_CAPACITY", [-3 & 255]: "OPENCE_WORLD_CONTENT", [-4 & 255]: "OPENCE_WORLD_CONSTRUCT", [-5 & 255]: "OPENCE_WORLD_UNSUPPORTED", [-6 & 255]: "OPENCE_WORLD_CLOCK" };
const KIND = ["none", "biped", "weapon", "equipment", "vehicle"];
const LOBBY = ["ok", "data", "network", "transport", "refused"];
const TRANSPORT = ["ok", "argument", "socket", "timeout", "protocol", "session", "stale", "peer closed", "in game"];
const ROUTE_STATE = ["idle", "reaching", "connected", "failed"];
const ROUTE = ["none", "invite refused", "no memory", "no socket", "no signalling broker", "host did not answer", "strict NAT", "connection lost", "host left", "no entropy"];
const PAGE_TRANSPORT = ["none", "stop", "lease expiry", "connect deadline", "failure", "disconnect", "protocol error", "core stop"];
export const pageTransportText = code => PAGE_TRANSPORT[code] ?? String(code);
const name = (table, value) => table[value] ?? String(value);

// Fast scan by 32-bit word: only live RAM holds the magic, it is built at run time.
export function findBlock(heapU32) {
  for (let i = 0, n = heapU32.length - 110; i < n; i += 4) {
    if (heapU32[i] === MAGIC[0] && heapU32[i + 1] === MAGIC[1] && heapU32[i + 2] === MAGIC[2] && heapU32[i + 3] === MAGIC[3] && heapU32[i + 4] === 1) return i * 4;
  }
  return -1;
}
const text = (bytes, at, size) => { let n = 0; while (n < size && bytes[at + n]) n++; return new TextDecoder().decode(bytes.subarray(at, at + n)); };

// Fixed block to a plain report. Returns null unless the block still carries the magic.
export function readBlock(bytes, base) {
  const v = new DataView(bytes.buffer, bytes.byteOffset + base, 440), u = i => v.getUint32(i, true), s = i => v.getInt32(i, true), b = i => v.getUint8(i);
  if (MAGIC.some((word, i) => u(i * 4) !== word)) return null;
  const str = (at, size) => text(bytes, base + at, size);
  return {
    seq: u(20), guestMs: u(24), tick: s(28),
    end: str(88, 32), message: str(312, 128),
    failingCheck: { file: str(120, 24), line: s(32), check: str(144, 48), returnCode: s(36) },
    lastCheck: { file: str(192, 24), line: s(40), check: str(216, 48), returnCode: s(44) },
    lastStep: { line: s(48), check: str(264, 48), returnCode: s(52) }, notes: u(68),
    lastObject: { tag: "0x" + u(56).toString(16).padStart(8, "0"), kind: name(KIND, b(72)), id: s(60), definition: s(64) },
    world: name(WORLD, b(73)),
    lobby: { failure: name(LOBBY, b(74)), phase: b(75), routeOrTransportError: b(81), rejection: b(80), linkError: b(79) },
    transport: { error: name(TRANSPORT, b(76)), phase: b(77), sessionError: b(78) },
    route: { state: name(ROUTE_STATE, b(82)), failure: name(ROUTE, b(83)) },
  };
}
// The on-screen text: what failed, where, with what.
export function summary(r) {
  const c = r.failingCheck;
  return [
    `Match end: ${r.end}${r.message ? " (" + r.message + ")" : ""}`,
    `Failing check: ${c.check || "none recorded"}${c.file ? ` at ${c.file}:${c.line}` : ""}, return code ${c.returnCode}`,
    `Last object: tag ${r.lastObject.tag}, kind ${r.lastObject.kind}, id ${r.lastObject.id}, definition ${r.lastObject.definition}`,
    `Transport: ${r.transport.error}; route ${r.route.state}, ${r.route.failure}; lobby ${r.lobby.failure}; world ${r.world}`,
    r.page ? `Page link: ${r.page.state}, ended by ${pageTransportText(r.page.terminalReason)}, close code ${r.page.closeCode}` : "",
  ].filter(Boolean).join("\n");
}
