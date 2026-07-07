// Shared pieces of the symmetric engines: a seeded random source (so every lab replays the same way), random
// bytes, block-cipher objects by name, and a runner that drains a generator (slow work is written as a generator
// that yields progress, so a page can run it in slices and the node tests can run it at once).
//   S.Sym.rng(seed) -> () => float in [0, 1);   S.Sym.bytes(rand, n) -> Uint8Array
//   S.Sym.cipher(name, key) -> {name, n, encrypt(block), decrypt(block)}   'aes', 'des', '3des', 'desx', 'present'
//   S.Sym.drain(gen) -> the generator's return value;   S.Sym.slices(gen, ms, onProgress) -> Promise of it
(function (S) {
  'use strict';
  const Y = (S.Sym = S.Sym || {});
  Y.rng = (seed = 1) => {
    let s = seed >>> 0;
    return () => { s = (s + 0x6d2b79f5) >>> 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t ^= t + Math.imul(t ^ (t >>> 7), 61 | t); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  };
  Y.bytes = (rand, n) => { const o = new Uint8Array(n); for (let i = 0; i < n; i++) o[i] = (rand() * 256) | 0; return o; };
  Y.int = (rand, n) => Math.floor(rand() * n);
  Y.cipher = (name, key) => {
    const k = typeof key === 'string' ? S.bytes.fromHex(key) : key;
    switch (String(name).toLowerCase()) {
      case 'aes': return S.AES.cipher(k);
      case 'des': return S.DES.cipher(k);
      case '3des': case 'tdes': return S.TDES.cipher(k);
      case 'desx': return S.DESX.cipher(k.slice(0, 8), k.slice(8, 16), k.slice(16, 24));
      case 'present': return S.PRESENT.cipher(k);
      default: throw new Error('unknown block cipher ' + name);
    }
  };
  Y.drain = (gen) => { for (;;) { const r = gen.next(); if (r.done) return r.value; } };
  /** run a generator in slices of about `ms` milliseconds, yielding to the page between slices */
  Y.slices = (gen, ms = 12, onProgress) => new Promise((resolve, reject) => {
    const tick = () => {
      try {
        const t0 = Date.now();
        for (;;) {
          const r = gen.next();
          if (r.done) { resolve(r.value); return; }
          if (onProgress && r.value) onProgress(r.value);
          if (Date.now() - t0 > ms) break;
        }
        setTimeout(tick, 0);
      } catch (e) { reject(e); }
    };
    tick();
  });
})(globalThis.Sifer = globalThis.Sifer || {});
