// Claim checks for part 4, first half: the Feistel principle and DES end to end. DES is worked out again here by a
// plain, separate implementation from the tables of FIPS 46-3, and every ciphertext is compared with node:crypto
// (two-key 3DES with K1 = K2 is single DES).
import { createCipheriv } from 'node:crypto';
import { S } from './claims-lib-p03.mjs';

const T = S.DES;
const bitsOf = (hex) => [...Buffer.from(hex, 'hex')].flatMap((b) => [7, 6, 5, 4, 3, 2, 1, 0].map((i) => (b >> i) & 1));
const hexOf = (bits) => { let s = ''; for (let i = 0; i < bits.length; i += 4) s += (bits[i] * 8 + bits[i + 1] * 4 + bits[i + 2] * 2 + bits[i + 3]).toString(16); return s; };
const pm = (b, t) => t.map((p) => b[p - 1]);
const rotl = (a, s) => a.slice(s).concat(a.slice(0, s));
const node = (pt, key) => { const c = createCipheriv('des-ede-ecb', Buffer.from(key + key, 'hex'), null); c.setAutoPadding(false); return c.update(Buffer.from(pt, 'hex')).toString('hex'); };
function schedule(key) {
  const k = pm(bitsOf(key), T.PC1); let C = k.slice(0, 28), D = k.slice(28); const out = [];
  for (const s of T.SHIFTS) { C = rotl(C, s); D = rotl(D, s); out.push({ C, D, K: pm(C.concat(D), T.PC2) }); }
  return { C0: k.slice(0, 28), D0: k.slice(28), keys: out };
}
function f(R, K) {
  const E = pm(R, T.E), X = E.map((v, i) => v ^ K[i]), boxes = [], So = [];
  for (let i = 0; i < 8; i++) {
    const b = X.slice(6 * i, 6 * i + 6), row = b[0] * 2 + b[5], col = b[1] * 8 + b[2] * 4 + b[3] * 2 + b[4], v = T.SBOX[i][row * 16 + col];
    boxes.push({ row, col, v, in6: b.join(''), out: v.toString(2).padStart(4, '0') });
    So.push(...[8, 4, 2, 1].map((m) => (v & m ? 1 : 0)));
  }
  return { E, X, boxes, S: So, P: pm(So, T.P) };
}
function des(pt, key, dec) {
  const ks = schedule(key).keys, ip = pm(bitsOf(pt), T.IP), rounds = [];
  let L = ip.slice(0, 32), R = ip.slice(32);
  for (let i = 0; i < 16; i++) { const K = ks[dec ? 15 - i : i].K, ff = f(R, K), nr = L.map((v, j) => v ^ ff.P[j]); rounds.push({ L, R, K, f: ff, newR: nr }); L = R; R = nr; }
  return { ip, rounds, out: hexOf(pm(R.concat(L), T.FP)) };
}
const rhex = (rnd, n) => Array.from({ length: n }, () => Math.floor(rnd() * 256).toString(16).padStart(2, '0')).join('');
const h4 = (v) => v.toString(16).padStart(4, '0');

export const mods = [
  {
    topic: 'des-overview', allow: ['16', '32', '48', '56', '64'],
    random: (rnd) => ({ pt: rhex(rnd, 8), key: rhex(rnd, 8) }),
    check({ input, r, fail }) {
      const d = des(input.pt, input.key);
      if (d.out !== node(input.pt, input.key)) fail('the separate DES disagrees with node:crypto');
      for (const fr of r.frames) {
        const x = fr.facts, st = fr.meta.stage;
        if (st === 'ip' && (x.L0 !== hexOf(d.ip.slice(0, 32)) || x.R0 !== hexOf(d.ip.slice(32)))) fail('L0, R0');
        if (st === 'round') { const q = d.rounds[x.k - 1]; if (x.L !== hexOf(q.L) || x.R !== hexOf(q.R) || x.K !== hexOf(q.K) || x.f !== hexOf(q.f.P) || x.newR !== hexOf(q.newR)) fail('round ' + x.k); }
        if (st === 'fp' && x.out !== d.out) fail('the ciphertext ' + x.out + ', want ' + d.out);
      }
    },
  },
  {
    topic: 'des-ipfp', allow: ['64', '4', '6', '8', '3', '5', '7', '58', '50', '42', '34', '26', '18', '10', '1970'],
    random: (rnd) => ({ pt: rhex(rnd, 8) }),
    check({ input, r, fail }) {
      const b = bitsOf(input.pt), ip = pm(b, T.IP);
      for (const fr of r.frames) {
        const x = fr.facts, st = fr.meta.stage;
        if (st === 'row') {
          const j = x.j - 1, col = [2, 4, 6, 8, 1, 3, 5, 7][j], want = [7, 6, 5, 4, 3, 2, 1, 0].map((row) => b[8 * row + col - 1]).join('');
          if (x.c !== col) fail('row ' + x.j + ' column ' + x.c);
          if (x.byte !== want || want !== ip.slice(8 * j, 8 * j + 8).join('')) fail('row ' + x.j + ' bits');
        }
        if (st === 'split' && (x.L0 !== hexOf(ip.slice(0, 32)) || x.R0 !== hexOf(ip.slice(32)))) fail('the halves');
        if (st === 'fp' && (x.back !== input.pt.toLowerCase() || !x.same)) fail('FP(IP(x))');
      }
    },
  },
  {
    topic: 'des-f', allow: ['32', '48', '16', '6', '4', '8'],
    random: (rnd) => ({ pt: rhex(rnd, 8), key: rhex(rnd, 8), round: 1 + Math.floor(rnd() * 16) }),
    check({ input, r, fail }) {
      const q = des(input.pt, input.key).rounds[input.round - 1];
      for (const fr of r.frames) {
        const x = fr.facts, st = fr.meta.stage;
        if (st === 'start' && (x.R !== hexOf(q.R) || x.K !== hexOf(q.K))) fail('R or K');
        if (st === 'E' && x.E !== hexOf(q.f.E)) fail('E');
        if (st === 'X' && x.X !== hexOf(q.f.X)) fail('X');
        if (st === 'sbox') { const b = q.f.boxes[x.k - 1]; if (b.in6 !== x.in6 || b.row !== x.row || b.col !== x.col || b.v !== x.v || b.out !== x.out) fail('S' + x.k); }
        if (st === 'P' && (x.S !== hexOf(q.f.S) || x.f !== hexOf(q.f.P))) fail('S or P');
        if (st === 'xor' && x.newR !== hexOf(q.newR)) fail('the new half');
      }
    },
  },
  {
    topic: 'des-keys', allow: ['8', '56', '28', '48', '9', '16'],
    random: (rnd) => ({ key: rhex(rnd, 8) }),
    check({ input, r, fail }) {
      const s = schedule(input.key);
      let tot = 0;
      for (const fr of r.frames) {
        const x = fr.facts, st = fr.meta.stage;
        if (st === 'pc1' && (x.C0 !== hexOf(s.C0) || x.D0 !== hexOf(s.D0))) fail('C0, D0');
        if (st === 'round') { const k = s.keys[x.i - 1]; tot += T.SHIFTS[x.i - 1]; if (x.s !== T.SHIFTS[x.i - 1] || x.tot !== tot || x.C !== hexOf(k.C) || x.D !== hexOf(k.D) || x.K !== hexOf(k.K)) fail('round ' + x.i); }
        if (st === 'end' && (x.tot !== 28 || !x.back)) fail('the full turn');
      }
    },
  },
  {
    topic: 'des-decrypt', allow: ['16'],
    random: (rnd) => ({ pt: rhex(rnd, 8), key: rhex(rnd, 8) }),
    check({ input, r, fail }) {
      const e = des(input.pt, input.key), c = node(input.pt, input.key), d = des(c, input.key, true);
      const names = { [hexOf(e.rounds[0].L)]: 'L₀', [hexOf(e.rounds[0].R)]: 'R₀' };
      e.rounds.forEach((q, i) => { names[hexOf(q.newR)] = 'R' + String(i + 1).split('').map((x) => '₀₁₂₃₄₅₆₇₈₉'[x]).join(''); });
      for (const fr of r.frames) {
        const x = fr.facts, st = fr.meta.stage;
        if (st === 'start' && x.C !== c) fail('the ciphertext');
        if (st === 'round') {
          const q = d.rounds[x.i - 1];
          if (x.K !== hexOf(q.K) || x.K !== hexOf(e.rounds[16 - x.i].K)) fail('the key of round ' + x.i);
          if (x.nv !== hexOf(q.newR) || (x.i < 16 && hexOf(e.rounds[0].L) !== hexOf(e.rounds[0].R) && x.nm !== names[x.nv])) fail('round ' + x.i + ' gives ' + x.nv + ' = ' + x.nm);
          const want = x.i < 16 ? e.rounds[15 - x.i - 1] ? hexOf(e.rounds[15 - x.i - 1].newR) : hexOf(e.rounds[0].R) : hexOf(e.rounds[0].L);
          if (x.nv !== want) fail('round ' + x.i + ' should give back ' + want);
        }
        if (st === 'end' && (x.out !== input.pt.toLowerCase() || !x.ok)) fail('the plaintext back');
      }
    },
  },
  {
    topic: 'des-avalanche', allow: ['64', '24', '32'],
    random: (rnd) => ({ pt: rhex(rnd, 8), key: rhex(rnd, 8), what: rnd() < 0.5 ? 'pt' : 'key', bit: 1 + Math.floor(rnd() * 64) }),
    check({ input, r, fail }) {
      const flip = (h, b) => { const x = Buffer.from(h, 'hex'); x[(b - 1) >> 3] ^= 0x80 >> ((b - 1) & 7); return x.toString('hex'); };
      const p2 = input.what === 'pt' ? flip(input.pt, input.bit) : input.pt, k2 = input.what === 'key' ? flip(input.key, input.bit) : input.key;
      const a = des(input.pt, input.key), b = des(p2, k2);
      const st = (d) => [d.ip].concat(d.rounds.map((q) => q.R.concat(q.newR)));
      const sa = st(a), sb = st(b), cnt = sa.map((v, i) => v.reduce((t, x, j) => t + (x ^ sb[i][j]), 0));
      for (const fr of r.frames) {
        const x = fr.facts, s = fr.meta.stage;
        if (s === 'start' && x.d !== cnt[0]) fail('the difference after IP');
        if (s === 'round' && (x.d !== cnt[x.i] || x.prev !== cnt[x.i - 1])) fail('the difference after round ' + x.i);
        if (s === 'end') {
          const c1 = node(input.pt, input.key), c2 = node(p2, k2), cd = bitsOf(c1).reduce((t, v, j) => t + (v ^ bitsOf(c2)[j]), 0);
          if (x.c1 !== c1 || x.c2 !== c2 || x.cd !== cd) fail('the ciphertexts');
          if (x.half !== cnt.findIndex((c) => c >= 24)) fail('the first round with 24 bits');
        }
      }
    },
  },
  {
    topic: 'des-feistel', allow: ['16', '3'],
    random: (rnd) => ({ F: ['sbox', 'addRot', 'xorKey', 'square', 'zero'][Math.floor(rnd() * 5)], pt: rhex(rnd, 4), keys: Array.from({ length: 1 + Math.floor(rnd() * 8) }, () => h4(Math.floor(rnd() * 65536))) }),
    check({ input, r, fail }) {
      const F = input.F === 'square' ? (R, k) => Math.floor(((R ^ k) & 0xffff) ** 2 / 256) & 0xffff : S.Feistel.ROUND_FUNCTIONS[input.F].F;
      const keys = input.keys.map((k) => parseInt(k, 16)), n = keys.length, v = parseInt(input.pt, 16);
      let L = v >>> 16, R = v & 0xffff;
      const L0 = L, R0 = R, made = [];
      for (const fr of r.frames) {
        const x = fr.facts, st = fr.meta.stage;
        if (st === 'enc') { const fv = F(R, keys[x.k - 1], x.k - 1) & 0xffff, nr = L ^ fv; if (x.R !== h4(R) || x.f !== h4(fv) || x.newR !== h4(nr)) fail('encryption round ' + x.k); made.push(nr); L = R; R = nr; }
        if (st === 'out' && x.ct !== h4(R) + h4(L)) fail('the ciphertext');
      }
      let a = R, b = L;
      for (const fr of r.frames) {
        const x = fr.facts;
        if (fr.meta.stage !== 'dec') continue;
        const fv = F(b, keys[n - x.k], 0) & 0xffff, nr = a ^ fv;
        if (x.key !== h4(keys[n - x.k]) || x.v !== h4(nr)) fail('decryption round ' + x.k);
        a = b; b = nr;
      }
      const end = r.frames[r.frames.length - 1].facts;
      if (end.out !== h4(L0) + h4(R0) || !end.ok) fail('the plaintext back');
      if (end.col) { const [p, q, w] = end.col.map((h) => parseInt(h, 16)); if (p === q || (F(p, keys[0], 0) & 0xffff) !== w || (F(q, keys[0], 0) & 0xffff) !== w) fail('the collision of F'); }
      void made;
    },
  },
];
