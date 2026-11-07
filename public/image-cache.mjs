// One verified image per origin. Cache is optional; storage denial never blocks play.
export function imageCache(indexedDB = globalThis.indexedDB) {
  function transaction(mode, operation) {
    return new Promise((resolve, reject) => {
      if (!indexedDB) { reject(new Error("Local cache unavailable")); return; }
      let db, tx, result, settled = false;
      const finish = (error) => {
        if (settled) return;
        settled = true; clearTimeout(timer); db?.close();
        error ? reject(error) : resolve(result);
      };
      const timer = setTimeout(() => { try { tx?.abort(); } catch {} finish(new Error("Local cache timed out")); }, 3000);
      const opening = indexedDB.open("halo-test-image", 1);
      opening.onupgradeneeded = () => opening.result.createObjectStore("images");
      opening.onerror = () => finish(opening.error);
      opening.onblocked = () => finish(new Error("Local cache blocked"));
      opening.onsuccess = () => {
        db = opening.result;
        if (settled) { db.close(); return; }
        try {
          tx = db.transaction("images", mode);
          tx.oncomplete = () => finish();
          tx.onerror = tx.onabort = () => finish(tx.error ?? new Error("Local cache failed"));
          const request = operation(tx.objectStore("images"));
          if (request) request.onsuccess = () => { result = request.result; };
        } catch (error) { finish(error); }
      };
    });
  }
  return {
    get: hash => transaction("readonly", store => store.get(hash)),
    remove: hash => transaction("readwrite", store => store.delete(hash)),
    put: (hash, bytes) => transaction("readwrite", store => {
      store.clear(); // Replace atomically; never accumulate old images.
      return store.put(bytes, hash);
    })
  };
}
