import { parseVmu, validateOwnedFile } from "./vmu.mjs";
const equal = (a, b) => a?.length === b?.length && a.every((v, i) => v === b[i]);
export function vmuCheckpointer({ snapshot, resume, persist, saved = () => {}, now = () => performance.now(), sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  let busy = false, previous;
  return async function checkpoint(final = false) {
    if (busy && !final) return;
    while (busy) await sleep(25);
    busy = true;
    try {
      const deadline = now() + (final ? 5000 : 0);
      do {
        let current, valid = false;
        try {
          current = snapshot(final); parseVmu(current);
          if (!await validateOwnedFile(current, "HALONETR") || !await validateOwnedFile(current, "HALONETK")) throw new Error("Device records missing");
          valid = true;
        } catch { previous = null; }
        if (valid) {
          // Commit failures are not a partial guest write: propagate them immediately.
          if (equal(previous, current)) { await persist(current); saved(); return; }
          previous = current;
        }
        if (!final) return;
        resume(); await sleep(250);
      } while (now() < deadline);
      throw new Error("VMU save is still in progress. Try Reset again.");
    } finally { busy = false; if (!final) resume(); }
  };
}
