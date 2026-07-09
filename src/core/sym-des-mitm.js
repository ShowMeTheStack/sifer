// Double DES and the meet-in-the-middle attack, on keys cut down to a few unknown bits so it runs in a second.
// Each key is a public base key with `bits` unknown key bits (the effective bits of its last bytes, never parity).
// From two known plaintext–ciphertext pairs: encrypt P1 under every K1 and store the middle values; decrypt C1
// under every K2 and look each middle value up; every hit is a candidate, and the second pair weeds out false ones.
//   S.MITM.keyFrom(base8, v, bits) -> the 8-byte key with v in its last effective bits
//   S.MITM.double(block, k1, k2) / undouble(block, k1, k2): double DES
//   S.MITM.setup({seed, bits}) -> {base, k1v, k2v, k1, k2, pairs: [{p, c}]}   a planted secret
//   S.MITM.run({base, bits, pairs}) -> generator; yields {phase, done, total}; returns the result below
//   S.MITM.attack(opts) -> {found: [{k1v, k2v}], candidates, table, work: {mitm, brute}, trace}
(function (S) {
  'use strict';
  const M = (S.MITM = {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const hex = (a) => S.bytes.hex(a);
  /** the unknown bits fill bits 7…1 of the last bytes, from the last byte backwards */
  M.keyFrom = (base, v, bits) => {
    const k = Uint8Array.from(base);
    let left = bits, pos = 7, x = v;
    while (left > 0) {
      const take = Math.min(7, left), mask = ((1 << take) - 1) << 1;
      k[pos] = (k[pos] & ~mask & 0xfe) | ((x & ((1 << take) - 1)) << 1);
      x >>>= take; left -= take; pos--;
    }
    return k;
  };
  M.double = (p, k1, k2) => S.DES.cipher(k2).encrypt(S.DES.cipher(k1).encrypt(p));
  M.undouble = (c, k1, k2) => S.DES.cipher(k1).decrypt(S.DES.cipher(k2).decrypt(c));
  M.setup = ({ seed = 1, bits = 16 } = {}) => {
    const r = S.Sym.rng(seed), base = S.Sym.bytes(r, 8), k1v = S.Sym.int(r, 1 << bits), k2v = S.Sym.int(r, 1 << bits);
    const k1 = M.keyFrom(base, k1v, bits), k2 = M.keyFrom(base, k2v, bits);
    const pairs = [0, 1].map(() => { const p = S.Sym.bytes(r, 8); return { p, c: M.double(p, k1, k2) }; });
    return { base, bits, k1v, k2v, k1, k2, pairs };
  };
  M.run = function* ({ base, bits = 16, pairs }) {
    const N = 1 << bits, [P1, P2] = pairs, trace = [];
    const keysFor = (v) => S.DES.fastKeys(M.keyFrom(base, v, bits));
    trace.push(step('mitm-start', `Two known pairs: ${hex(P1.p)} → ${hex(P1.c)} and ${hex(P2.p)} → ${hex(P2.c)}; each key has ${bits} unknown bits, so 2^${bits} = ${N} values each.`, { bits, N }));
    const table = new Map(), sample = [];
    for (let v = 0; v < N; v++) {
      const m = hex(S.DES.fastBlock(P1.p, keysFor(v), false));
      const list = table.get(m); if (list) list.push(v); else table.set(m, [v]);
      if (v < 4) sample.push({ k1v: v, mid: m });
      if ((v & 4095) === 4095) yield { phase: 'forward', done: v + 1, total: N };
    }
    trace.push(step('mitm-table', `Forward: encrypt P1 under all ${N} values of K1 and store the middle values, e.g. K1 = ${sample.map((s) => `${s.k1v} → ${s.mid}`).join(', ')}.`, { sample, size: table.size }));
    const candidates = [], found = [];
    for (let v = 0; v < N; v++) {
      const ks2 = keysFor(v), m = hex(S.DES.fastBlock(P1.c, ks2, true)), hits = table.get(m);
      if (hits) for (const k1v of hits) {
        const ok = S.bytes.eq(S.DES.fastBlock(S.DES.fastBlock(P2.p, keysFor(k1v), false), ks2, false), P2.c);
        candidates.push({ k1v, k2v: v, mid: m, ok });
        if (ok) found.push({ k1v, k2v: v });
        trace.push(step('mitm-hit', `Backward: K2 = ${v} decrypts C1 to ${m}, which K1 = ${k1v} also reaches; the second pair ${ok ? 'confirms it' : 'rejects it (a false alarm)'}.`, { k1v, k2v: v, mid: m, ok }));
      }
      if ((v & 4095) === 4095) yield { phase: 'backward', done: v + 1, total: N };
    }
    const work = { mitm: 2 * N, brute: N * N, memory: N };
    trace.push(step('mitm-done', `${found.length} key pair${found.length === 1 ? '' : 's'} survive${found.length === 1 ? 's' : ''} out of ${candidates.length} candidate${candidates.length === 1 ? '' : 's'}; the attack cost ${2 * N} DES operations and a table of ${N} entries, against ${N * N} for trying every pair of keys.`, { work, found }));
    return { found, candidates, tableSize: table.size, work, trace };
  };
  M.attack = (opts) => S.Sym.drain(M.run(opts));
})(globalThis.Sifer = globalThis.Sifer || {});
