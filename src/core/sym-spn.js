// A toy substitution–permutation network small enough to break by hand and by program: a 16-bit block, four 4-bit
// S-boxes per round, a bit transposition, four rounds and five 16-bit round keys. Rounds 1–3: key mix, S-boxes,
// permutation; round 4: key mix, S-boxes, a final key mix with K5. Nibble 0 is the leftmost; bit 0 is the leftmost.
//   S.SPN.SBOX, INV_SBOX, PERM (bit i goes to PERM[i])
//   S.SPN.encrypt(p, keys[5]) -> {out, rounds: [{round, u, v, w}], trace}; decrypt(c, keys)
//   S.SPN.keys(seed) -> five random round keys;  S.SPN.fast(keys) -> {enc(p), dec(c)}
//   S.SPN.ddt(sbox) -> 16×16 counts; S.SPN.lat(sbox) -> 16×16 (count − 8)
//   S.SPN.permute(x) / unpermute(x); S.SPN.subs(x, inv) on all four nibbles
//   S.SPN.searchDifferential({maxActive, keep}) -> [{dIn, path: [{u, v, boxes}], dU4, prob, active}] best first
//   S.SPN.searchLinear({keep}) -> [{a, path, bU4, bias, active}] best first
(function (S) {
  'use strict';
  const P = (S.SPN = S.SPN || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  P.SBOX = [0x6, 0xb, 0x5, 0x4, 0x2, 0xe, 0x7, 0xa, 0x9, 0xd, 0xf, 0xc, 0x3, 0x1, 0x0, 0x8];
  P.INV_SBOX = new Array(16); P.SBOX.forEach((v, i) => { P.INV_SBOX[v] = i; });
  /** the transposition: bit j of nibble i goes to bit i of nibble j */
  P.PERM = Array.from({ length: 16 }, (_, b) => 4 * (b % 4) + ((b / 4) | 0));
  const h4 = (x) => x.toString(16).padStart(4, '0');
  P.hex = h4;
  P.bin = (x) => x.toString(2).padStart(16, '0').replace(/(....)(?=.)/g, '$1 ');
  const bit = (x, i) => (x >> (15 - i)) & 1;
  P.permute = (x) => { let y = 0; for (let i = 0; i < 16; i++) if (bit(x, i)) y |= 1 << (15 - P.PERM[i]); return y; };
  P.unpermute = (y) => { let x = 0; for (let i = 0; i < 16; i++) if (bit(y, P.PERM[i])) x |= 1 << (15 - i); return x; };
  P.nib = (x, i) => (x >> (12 - 4 * i)) & 15;
  P.subs = (x, inv) => { const T = inv ? P.INV_SBOX : P.SBOX; let y = 0; for (let i = 0; i < 4; i++) y |= T[P.nib(x, i)] << (12 - 4 * i); return y; };
  P.keys = (seed = 1) => { const r = S.Sym.rng(seed); return [0, 1, 2, 3, 4].map(() => Math.floor(r() * 65536)); };

  P.encrypt = (p, keys) => {
    let x = p & 0xffff;
    const rounds = [], trace = [step('start', `Plaintext ${h4(x)} = ${P.bin(x)}.`, { x })];
    for (let r = 1; r <= 4; r++) {
      const u = x ^ keys[r - 1], v = P.subs(u), w = r < 4 ? P.permute(v) : v ^ keys[4];
      rounds.push({ round: r, u, v, w });
      trace.push(step('round', `Round ${r}: ⊕ K${r} (${h4(keys[r - 1])}) gives U${r} = ${h4(u)}; the S-boxes give V${r} = ${h4(v)}; ${r < 4 ? `the permutation gives W${r} = ${h4(w)}` : `⊕ K5 (${h4(keys[4])}) gives the ciphertext ${h4(w)}`}.`, { round: r, u, v, w }));
      x = w;
    }
    return { out: x, rounds, trace };
  };
  P.decrypt = (c, keys) => {
    let x = (c ^ keys[4]) & 0xffff;
    for (let r = 4; r >= 1; r--) { x = P.subs(x, true) ^ keys[r - 1]; if (r > 1) x = P.unpermute(x); }
    return { out: x };
  };
  /** whole-block tables, for the attacks that need tens of thousands of encryptions */
  P.fast = (keys) => {
    const SB = new Uint16Array(65536), PB = new Uint16Array(65536), IS = new Uint16Array(65536), IP = new Uint16Array(65536);
    for (let x = 0; x < 65536; x++) { SB[x] = P.subs(x); PB[x] = P.permute(x); IS[x] = P.subs(x, true); IP[x] = P.unpermute(x); }
    return {
      enc: (p) => { let x = p; for (let r = 0; r < 3; r++) x = PB[SB[x ^ keys[r]]]; return SB[x ^ keys[3]] ^ keys[4]; },
      dec: (c) => { let x = IS[c ^ keys[4]] ^ keys[3]; for (let r = 2; r >= 0; r--) x = IS[IP[x]] ^ keys[r]; return x; },
    };
  };

  const par = (x) => { let n = 0; while (x) { n ^= x & 1; x >>= 1; } return n; };
  P.parity = par;
  P.ddt = (sb = P.SBOX) => { const t = Array.from({ length: 16 }, () => new Array(16).fill(0)); for (let x = 0; x < 16; x++) for (let d = 0; d < 16; d++) t[d][sb[x] ^ sb[x ^ d]]++; return t; };
  P.lat = (sb = P.SBOX) => { const t = Array.from({ length: 16 }, () => new Array(16).fill(-8)); for (let a = 0; a < 16; a++) for (let b = 0; b < 16; b++) for (let x = 0; x < 16; x++) if (par(a & x) === par(b & sb[x])) t[a][b]++; return t; };
  P.active = (x) => [0, 1, 2, 3].filter((i) => P.nib(x, i));

  /** all ways a 16-bit difference (or mask) can pass the S-layer, with the weight of each, via a per-box table */
  const layerOptions = (x, table, score, cap) => {
    let opts = [{ y: 0, w: 1, boxes: [] }];
    for (let i = 0; i < 4; i++) {
      const a = P.nib(x, i);
      if (!a) continue;
      const next = [];
      for (const o of opts) for (let b = 1; b < 16; b++) { const s = score(table[a][b]); if (s > 0) next.push({ y: o.y | (b << (12 - 4 * i)), w: o.w * s, boxes: o.boxes.concat([{ i, a, b, n: table[a][b] }]) }); }
      next.sort((p, q) => q.w - p.w);
      opts = next.slice(0, cap);
    }
    return opts;
  };
  /** best paths over rounds 1–3 by keeping the best few states after each round (a beam over a Viterbi recursion) */
  const search = (table, score, starts, keep, final) => {
    let beam = starts.map((s) => ({ x0: s, x: s, w: 1, path: [] }));
    for (let r = 1; r <= 3; r++) {
      const best = new Map();
      for (const b of beam) for (const o of layerOptions(b.x, table, score, 24)) {
        const nx = P.permute(o.y), w = b.w * o.w, key = b.x0 + ':' + nx, cur = best.get(key);
        if (!cur || cur.w < w) best.set(key, { x0: b.x0, x: nx, w, path: b.path.concat([{ round: r, u: b.x, v: o.y, boxes: o.boxes }]) });
      }
      beam = [...best.values()].sort((p, q) => q.w - p.w).slice(0, keep);
    }
    return beam.filter((b) => final(b.x));
  };
  const singleBoxStarts = () => { const s = []; for (let i = 0; i < 4; i++) for (let a = 1; a < 16; a++) s.push(a << (12 - 4 * i)); return s; };
  P.searchDifferential = ({ maxActive = 2, keep = 400, starts } = {}) => {
    const D = P.ddt();
    return search(D, (n) => n / 16, starts || singleBoxStarts(), keep, (x) => P.active(x).length <= maxActive)
      .map((b) => ({ dIn: b.x0, path: b.path, dU4: b.x, prob: b.w, active: P.active(b.x),
        say: `ΔP = ${h4(b.x0)} leads to ΔU4 = ${h4(b.x)} with probability ${b.w.toPrecision(3)} (about 1 in ${Math.round(1 / b.w)}), through ${b.path.reduce((n, p) => n + p.boxes.length, 0)} active S-boxes.` }))
      .sort((p, q) => q.prob - p.prob);
  };
  P.searchLinear = ({ maxActive = 2, keep = 400, starts } = {}) => {
    const L = P.lat();
    // weight of a box is |bias| = |n|/16; the piling-up lemma gives 2^(m−1)·∏ bias
    return search(L, (n) => Math.abs(n) / 16, starts || singleBoxStarts(), keep, (x) => P.active(x).length <= maxActive)
      .map((b) => { const m = b.path.reduce((n, p) => n + p.boxes.length, 0), bias = Math.pow(2, m - 1) * b.w;
        return { a: b.x0, path: b.path, bU4: b.x, bias, active: P.active(b.x), boxes: m,
          sign: b.path.reduce((s, p) => s * p.boxes.reduce((t, x) => t * Math.sign(x.n), 1), 1),
          say: `The input mask ${h4(b.x0)} and the mask ${h4(b.x)} on U4 agree with bias ${bias.toPrecision(3)} through ${m} active S-boxes (piling-up: 2^${m - 1} × the product of the box biases).` }; })
      .sort((p, q) => q.bias - p.bias);
  };
})(globalThis.Sifer = globalThis.Sifer || {});
