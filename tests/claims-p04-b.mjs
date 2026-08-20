// Claim checks for part 4, second half: weak keys, exhaustive search, meet-in-the-middle, 3DES, DESX, the toy SPN
// attacks and PRESENT. DES values are checked against node:crypto (single DES as two-key EDE with equal halves),
// the SPN and PRESENT against small implementations written here from the published tables.
import { createCipheriv, createDecipheriv } from 'node:crypto';
import { S } from './claims-lib-p03.mjs';

const hex = (b) => Buffer.from(b).toString('hex');
const fh = (h) => Buffer.from(h, 'hex');
const des = (key, block) => { const c = createCipheriv('des-ede-ecb', Buffer.concat([Buffer.from(key), Buffer.from(key)]), null); c.setAutoPadding(false); return c.update(Buffer.from(block)); };
const undes = (key, block) => { const c = createDecipheriv('des-ede-ecb', Buffer.concat([Buffer.from(key), Buffer.from(key)]), null); c.setAutoPadding(false); return c.update(Buffer.from(block)); };
const ede = (alg, key, block) => { const c = createCipheriv(alg, Buffer.from(key), null); c.setAutoPadding(false); return c.update(Buffer.from(block)); };
const xor = (a, b) => Buffer.from(a.map((v, i) => v ^ b[i]));
const not = (a) => Buffer.from(Array.from(a, (v) => ~v & 255));
const stage = (r, st) => r.frames.find((f) => f.meta.stage === st);
const randHex = (rnd, n) => Array.from({ length: n }, () => Math.floor(rnd() * 256).toString(16).padStart(2, '0')).join('');

// the DES key schedule from the tables, bit by bit
function desSubkeys(key) {
  const bits = []; for (const b of key) for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  const k = S.DES.PC1.map((p) => bits[p - 1]);
  let C = k.slice(0, 28), D = k.slice(28);
  const out = [], h = (a) => a.join('').match(/..../g).map((q) => parseInt(q, 2).toString(16)).join('');
  for (const s of S.DES.SHIFTS) { C = C.slice(s).concat(C.slice(0, s)); D = D.slice(s).concat(D.slice(0, s)); out.push(h(S.DES.PC2.map((p) => C.concat(D)[p - 1]))); }
  return { C0: h(k.slice(0, 28)), D0: h(k.slice(28)), keys: out };
}

// the toy SPN from its tables
const SB = S.SPN.SBOX, ISB = S.SPN.INV_SBOX, PERM = S.SPN.PERM;
const nib = (x, i) => (x >> (12 - 4 * i)) & 15;
const subs = (x, T) => { let y = 0; for (let i = 0; i < 4; i++) y |= T[nib(x, i)] << (12 - 4 * i); return y; };
const perm = (x) => { let y = 0; for (let i = 0; i < 16; i++) if ((x >> (15 - i)) & 1) y |= 1 << (15 - PERM[i]); return y; };
const spnEnc = (p, k) => { let x = p; for (let r = 0; r < 3; r++) x = perm(subs(x ^ k[r], SB)); return subs(x ^ k[3], SB) ^ k[4]; };
const spread = (g, nibs) => { let k = 0; nibs.forEach((n, j) => { k |= ((g >> (4 * (nibs.length - 1 - j))) & 15) << (12 - 4 * n); }); return k; };
const undo = (c, k, nibs) => { let u = 0; for (const n of nibs) u |= ISB[nib(c ^ k, n)] << (12 - 4 * n); return u; };
const par = (x) => { let n = 0; while (x) { n ^= x & 1; x >>= 1; } return n; };
const h4 = (x) => x.toString(16).padStart(4, '0');

// PRESENT-80 from its specification
const PS = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2];
function present(pHex, kHex) {
  let K = BigInt('0x' + kHex), x = BigInt('0x' + pHex);
  const M80 = (1n << 80n) - 1n, rk = [], st = [];
  for (let i = 1; i <= 32; i++) {
    rk.push(K >> 16n);
    K = ((K << 61n) | (K >> 19n)) & M80;
    K = (K & ((1n << 76n) - 1n)) | (BigInt(PS[Number(K >> 76n)]) << 76n);
    K ^= BigInt(i) << 15n;
  }
  for (let r = 0; r < 31; r++) {
    const a = x ^ rk[r]; let s = 0n; for (let i = 0; i < 16; i++) s |= BigInt(PS[Number((a >> BigInt(4 * i)) & 15n)]) << BigInt(4 * i);
    let q = 0n; for (let i = 0; i < 64; i++) if ((s >> BigInt(i)) & 1n) q |= 1n << BigInt(i === 63 ? 63 : (16 * i) % 63);
    st.push({ key: rk[r], added: a, sub: s, perm: q }); x = q;
  }
  return { rk, st, out: x ^ rk[31] };
}
const h16 = (v) => v.toString(16).padStart(16, '0');

export const mods = [
  {
    topic: 'des-weak', allow: ['28', '56', '8', '16', '4', '12', '6'],
    random: (rnd) => ({ key: randHex(rnd, 8), plain: randHex(rnd, 8) }),
    check({ input, r, fail }) {
      const k = fh(input.key), p = fh(input.plain), sk = desSubkeys(k), F = (s) => stage(r, s).facts;
      if (F('pc1').c0 !== sk.C0 || F('pc1').d0 !== sk.D0) fail('C0/D0');
      if (F('keys').distinct !== new Set(sk.keys).size) fail('distinct round keys');
      const c = des(k, p);
      if (F('once').c !== hex(c)) fail('one encryption');
      const k2 = F('keys').partner ? fh(F('keys').partner) : k, cc = des(k2, c);
      if (F('twice').cc !== hex(cc) || F('twice').back !== cc.equals(p)) fail('two encryptions');
      if (F('keys').partner && hex(desSubkeys(k2).keys.slice().reverse().join('')) !== hex(sk.keys.join(''))) fail('the partner key does not reverse the round keys');
      if (F('comp').cc !== hex(des(not(k), not(p))) || F('comp').cc !== hex(not(c))) fail('complementation');
    },
  },
  {
    topic: 'des-search', allow: ['10', '86', '400', '20', '112', '56', '64', '40', '24'],
    check({ input, r, fail }) {
      const bits = +input.bits, space = 2 ** (bits - (input.comp === 'yes' && bits === 56 ? 1 : 0));
      const secs = (t) => { const m = /([\d.,\s]+(?:e\+?\d+)?)(?: × 10\^(\d+))? (seconds|minutes|hours|days|years)/.exec(t); const v = parseFloat(m[1].replace(/\s/g, '')) * (m[2] ? 10 ** +m[2] : 1); return v * { seconds: 1, minutes: 60, hours: 3600, days: 86400, years: 365.25 * 86400 }[m[3]]; };
      for (const f of r.frames.filter((x) => x.meta.stage === 'machine')) {
        const sup = (t) => [...t].map((c) => '⁰¹²³⁴⁵⁶⁷⁸⁹'.indexOf(c)).join('');
        const mm = /^(?:([\d.]+) × )?10([⁰¹²³⁴⁵⁶⁷⁸⁹]+)$/.exec(f.facts.rate), rate = (mm[1] ? +mm[1] : 1) * 10 ** +sup(mm[2]);
        if (Math.abs(rate - f.facts.rv) > 1e-9 * rate) fail(f.facts.year + ': the rate as written');
        const want = space / rate, got = secs(f.facts.full);
        if (Math.abs(got - want) / want > 0.06) fail(f.facts.year + ': ' + f.facts.full + ' for ' + want + ' s');
        if (Math.abs(secs(f.facts.avg) - want / 2) / want > 0.06) fail(f.facts.year + ': the average');
        if (f.meta.day !== (want <= 86400)) fail(f.facts.year + ': the day flag');
      }
      const end = r.frames.find((x) => x.meta.stage === 'end').facts, rows = r.frames.filter((x) => x.meta.stage === 'machine').map((x) => x.facts);
      if (!rows.some((m) => m.year === end.from.year && m.rv === end.from.rv) || !rows.some((m) => m.year === end.to.year && m.rv === end.to.rv)) fail('the growth quotes machines not on the list');
      if (end.ratio !== Math.round(end.to.rv / end.from.rv)) fail('the growth factor');
    },
  },
  {
    topic: 'des-mitm', allow: ['64', '57', '56', '112', '48', '2'],
    random: (rnd) => ({ bits: 4 + Math.floor(rnd() * 5), seed: 1 + Math.floor(rnd() * 900) }), count: 5,
    check({ input, r, fail }) {
      const lab = S.MITM.setup({ seed: input.seed, bits: input.bits }), N = 1 << input.bits;
      const keyFrom = (v) => { const k = Buffer.from(lab.base); let left = input.bits, pos = 7, x = v; while (left > 0) { const t = Math.min(7, left), m = ((1 << t) - 1) << 1; k[pos] = (k[pos] & ~m & 0xfe) | ((x & ((1 << t) - 1)) << 1); x >>>= t; left -= t; pos--; } return k; };
      const [P1, P2] = lab.pairs, hit = stage(r, 'hit').facts;
      if (hex(des(keyFrom(hit.k1), P1.p)) !== hit.m || hex(undes(keyFrom(hit.k2), P1.c)) !== hit.m) fail('the meeting value');
      if (hex(des(keyFrom(hit.k2), des(keyFrom(hit.k1), P1.p))) !== hex(P1.c)) fail('the found keys do not encrypt P1 to C1');
      for (const [v, m] of stage(r, 'back').facts.misses) { if (hex(undes(keyFrom(v), P1.c)) !== m) fail('a backward value'); for (let k1 = 0; k1 < N; k1++) if (hex(des(keyFrom(k1), P1.p)) === m) fail('a "miss" is in the table'); }
      for (const [v, m] of stage(r, 'forward').facts.rows) if (hex(des(keyFrom(v), P1.p)) !== m) fail('a forward value');
      const cf = stage(r, 'confirm').facts, c2 = des(keyFrom(hit.k2), des(keyFrom(hit.k1), P2.p));
      if (cf.c2 !== hex(c2) || cf.ok !== c2.equals(Buffer.from(P2.c))) fail('the second pair');
      if (stage(r, 'end').facts.work !== String(2 * N).replace(/\B(?=(\d{3})+(?!\d))/g, ' ')) fail('the work');
    },
  },
  {
    topic: 'des-3des', allow: ['80', '112', '168', '184', '119', '56', '64', '1', '2', '800', '57', '3'],
    random: (rnd) => ({ variant: ['ede2', 'ede3', 'compat', 'desx'][Math.floor(rnd() * 4)], plain: randHex(rnd, 8), key: randHex(rnd, 24) }),
    check({ input, r, fail }) {
      const p = fh(input.plain), K = fh(input.key), k1 = K.subarray(0, 8), k2 = K.subarray(8, 16), k3 = K.subarray(16, 24);
      let steps;
      if (input.variant === 'desx') { const a = xor(p, k2), b = des(k1, a); steps = [a, b, xor(b, k3)]; }
      else {
        const ks = input.variant === 'ede2' ? [k1, k2, k1] : input.variant === 'ede3' ? [k1, k2, k3] : [k1, k1, k1];
        const a = des(ks[0], p), b = undes(ks[1], a); steps = [a, b, des(ks[2], b)];
        const whole = input.variant === 'ede2' ? ede('des-ede-ecb', K.subarray(0, 16), p) : input.variant === 'ede3' ? ede('des-ede3-ecb', K, p) : des(k1, p);
        if (!whole.equals(steps[2])) fail('EDE against node');
      }
      ['s1', 's2', 's3'].forEach((st, i) => { if (stage(r, st).facts.s !== hex(steps[i])) fail(st); });
      if (stage(r, 'end').facts.out !== hex(steps[2])) fail('the ciphertext');
    },
  },
  {
    topic: 'spn-ddt', allow: ['16', '4', '3', '8', '64', '128'],
    check({ input, r, fail }) {
      const dx = parseInt(input.dx, 16), row = Array(16).fill(0);
      for (let x = 0; x < 16; x++) row[SB[x] ^ SB[x ^ dx]]++;
      if (stage(r, 'row').facts.row !== row.join(' ')) fail('the DDT row');
      if (stage(r, 'pairs').facts.best !== Math.max(...row)) fail('the best count');
      let n4 = 0; for (let a = 1; a < 16; a++) for (let b = 0; b < 16; b++) { let n = 0; for (let x = 0; x < 16; x++) n += (SB[x] ^ SB[x ^ a]) === b; n4 += n === 4; }
      if (stage(r, 'table').facts.n4 !== n4) fail('the count of 4s');
      let prev = null, prob = 1;
      for (const f of r.frames.filter((x) => x.meta.stage === 'round')) {
        const u = parseInt(f.facts.u, 16), v = parseInt(f.facts.v, 16);
        if (prev !== null && perm(prev) !== u) fail('round ' + f.facts.r + ' input is not the permuted output');
        for (const [i, a, b, n] of f.facts.boxes) { let c = 0; for (let x = 0; x < 16; x++) c += (SB[x] ^ SB[x ^ parseInt(a, 16)]) === parseInt(b, 16); if (c !== n || nib(u, i) !== parseInt(a, 16) || nib(v, i) !== parseInt(b, 16)) fail('a box on round ' + f.facts.r); prob *= n / 16; }
        if (f.facts.cum !== Math.round(1 / prob)) fail('the running probability');
        prev = v;
      }
      const end = stage(r, 'end').facts;
      if (parseInt(end.dU4, 16) !== perm(prev) || end.inv !== Math.round(1 / prob)) fail('the end of the characteristic');
    },
  },
  {
    topic: 'spn-diff', allow: ['5', '24'],
    random: (rnd) => ({ char: 'ABCD'[Math.floor(rnd() * 4)], pairs: 200 + Math.floor(rnd() * 2000), key: 1 + Math.floor(rnd() * 900) }), count: 6,
    check({ input, r, fail }) {
      const keys = S.SPN.keys(input.key), ch = S.P04b.char(input.char), nibs = ch.active, G = 1 << (4 * nibs.length);
      const rng = S.Sym.rng(input.key), outside = ~spread(G - 1, nibs) & 0xffff, counts = Array(G).fill(0);
      let used = 0;
      for (let i = 0; i < input.pairs; i++) {
        const p = Math.floor(rng() * 65536), c1 = spnEnc(p, keys), c2 = spnEnc(p ^ ch.dIn, keys);
        if ((c1 ^ c2) & outside) continue;
        used++;
        for (let g = 0; g < G; g++) { const k = spread(g, nibs); if ((undo(c1, k, nibs) ^ undo(c2, k, nibs)) === ch.dU4) counts[g]++; }
      }
      if (stage(r, 'filter').facts.used !== used) fail('pairs kept: ' + used);
      const fl = stage(r, 'filter').facts;
      if (h4(spnEnc(parseInt(fl.p, 16), keys)) !== fl.c1 || h4(spnEnc(parseInt(fl.p, 16) ^ ch.dIn, keys)) !== fl.c2) fail('the sample pair');
      for (const [k, c] of stage(r, 'counts').facts.top) { const g = counts.findIndex((_, j) => h4(spread(j, nibs)) === k); if (counts[g] !== c) fail('the count of ' + k); }
      const right = keys[4] & spread(G - 1, nibs), end = stage(r, 'end').facts;
      if (end.right !== h4(right)) fail('the true key bits');
      if (counts[parseInt(end.guess, 16) ? counts.findIndex((_, j) => h4(spread(j, nibs)) === end.guess) : 0] !== Math.max(...counts)) fail('the top guess');
      const gs = stage(r, 'guess').facts; if (h4(undo(parseInt(fl.c1, 16), parseInt(gs.g, 16), nibs) ^ undo(parseInt(fl.c2, 16), parseInt(gs.g, 16), nibs)) !== gs.d) fail('the peeled difference');
    },
  },
  {
    topic: 'spn-linear', allow: ['8', '16', '3', '4', '10', '1', '2'],
    random: (rnd) => ({ a: '123456789abcdef'[Math.floor(rnd() * 15)], b: '123456789abcdef'[Math.floor(rnd() * 15)], approx: 'ABC'[Math.floor(rnd() * 3)], mode: rnd() < 0.5 ? 'one' : 'several', texts: 500 + Math.floor(rnd() * 3000), key: 1 + Math.floor(rnd() * 900) }), count: 6,
    check({ input, r, fail }) {
      const a = parseInt(input.a, 16), b = parseInt(input.b, 16);
      let n = 0; for (let x = 0; x < 16; x++) n += par(a & x) === par(b & SB[x]);
      const f0 = stage(r, 'pair').facts; if (f0.nAgree !== n || f0.e !== n - 8) fail('the LAT entry');
      const pile = stage(r, 'pile').facts; let prod = 1, m = 0;
      for (const f of r.frames.filter((x) => x.meta.stage === 'round')) for (const [, x, y, e] of f.facts.boxes) { let c = 0; for (let t = 0; t < 16; t++) c += par(parseInt(x, 16) & t) === par(parseInt(y, 16) & SB[t]); if (c - 8 !== e) fail('a LAT entry on the path'); prod *= Math.abs(e) / 16; m++; }
      if (Math.abs(pile.bias - 2 ** (m - 1) * prod) > 1e-12) fail('the piling-up bias');
      if (input.mode === 'one') {
        const keys = S.SPN.keys(input.key), rng = S.Sym.rng(input.key), ap = { a: parseInt(pile.a, 16), b: parseInt(pile.b, 16) }, nibs = S.SPN.active(ap.b), G = 1 << (4 * nibs.length), hold = Array(G).fill(0);
        for (let i = 0; i < input.texts; i++) { const p = Math.floor(rng() * 65536), c = spnEnc(p, keys); for (let g = 0; g < G; g++) if ((par(p & ap.a) ^ par(undo(c, spread(g, nibs), nibs) & ap.b)) === 0) hold[g]++; }
        for (const [k, v] of stage(r, 'count').facts.best) { const g = hold.findIndex((_, j) => h4(spread(j, nibs)) === k); if ((Math.abs(hold[g] - input.texts / 2) / input.texts).toFixed(4) !== v) fail('the bias of ' + k); }
      }
    },
  },
  {
    topic: 'spn-present', allow: ['64', '80', '31', '16', '63', '4', '19', '15', '60', '61', '62'],
    random: (rnd) => ({ plain: randHex(rnd, 8), key: randHex(rnd, 10) }),
    check({ input, r, fail }) {
      const ref = present(input.plain, input.key), R1 = ref.st[0], F = (s) => stage(r, s).facts;
      if (F('addkey').K1 !== h16(R1.key) || F('addkey').added !== h16(R1.added)) fail('round 1 key mix');
      if (F('sbox').sub !== h16(R1.sub) || F('perm').perm !== h16(R1.perm)) fail('round 1 layers');
      if (F('key').K2 !== h16(ref.rk[1])) fail('K2');
      if (F('rounds').s16 !== h16(ref.st[15].perm) || F('end').s31 !== h16(ref.st[30].perm)) fail('the round states');
      if (F('end').k32 !== h16(ref.rk[31]) || F('end').out !== h16(ref.out)) fail('the ciphertext');
      if (F('end').vec && F('end').vec !== h16(ref.out)) fail('the published vector');
    },
  },
];
