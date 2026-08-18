import { createCipheriv } from 'node:crypto';
// Claim checks for part 3, first half: the one-time pad, randomness, LFSRs and Berlekamp–Massey.
// Each mod: {topic, allow, random(rnd) -> input values, check({input, r, fail, ok})}; see tests/claims-lib-p03.mjs.

/** s_n = XOR of s_(n−k) over the taps, straight from the definition */
export const recur = (taps, seed, n) => { const s = seed.slice(); while (s.length < n) { let v = 0; for (const k of taps) v ^= s[s.length - k]; s.push(v); } return s.slice(0, n); };
const PRIM = [['4', '3'], ['5', '3'], ['6', '5'], ['7', '6'], ['8', '6', '5', '4'], ['3', '2'], ['5', '4', '3', '2'], ['9', '5'], ['10', '7']];
const randSeed = (rnd, L) => { let s = ''; for (let i = 0; i < L; i++) s += rnd() < 0.5 ? '1' : '0'; return s.includes('1') ? s : '1' + s.slice(1); };

const hx = (a) => Array.from(a, (v) => v.toString(16).padStart(2, '0')).join('');
const asc = (s) => Uint8Array.from(Buffer.from(s, 'latin1'));
const WORDS = ['meet at the gate', 'blue', 'hold the line', 'rain at six', 'go now'];
const CRIBS = [' the ', 'the ', ' and ', 'harbour', 'at ', ' of the ', 'boat', 'north'];

export const mods = [
  {
    topic: 'st-otp-secrecy', allow: ['256'],
    random: (rnd) => { const m = WORDS[Math.floor(rnd() * WORDS.length)]; return { message: m, decoys: WORDS.filter((w) => w !== m).slice(0, 2).join(' / '), seed: 1 + Math.floor(rnd() * 9000) }; },
    check({ S, input, r, fail }) {
      const m = asc(input.message), n = m.length, k = S.Sym.bytes(S.Sym.rng(input.seed), n), c = m.map((v, i) => v ^ k[i]);
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'key' && x.key !== hx(k)) fail('the key');
        if (st === 'cipher' && (x.c !== hx(c) || x.c0 !== hx([c[0]]))) fail('the ciphertext');
        if (st === 'decoy') { const d = asc(x.d), kd = c.map((v, i) => v ^ d[i]); if (x.kd !== hx(kd)) fail('the decoy key'); if (hx(kd.map((v, i) => v ^ c[i])) !== hx(d)) fail('the decoy key does not decrypt'); }
        if (st === 'end' && x.bits !== 8 * n) fail('the key count');
      }
    },
  },
  {
    topic: 'st-two-time',
    random: (rnd) => ({ seed: 1 + Math.floor(rnd() * 999), crib: CRIBS[Math.floor(rnd() * CRIBS.length)] }),
    check({ S, input, r, fail }) {
      const o = S.OTP.setup({ seed: input.seed }), mx = o.m1.map((v, i) => v ^ o.m2[i]), crib = asc(input.crib), txt = (a) => Buffer.from(a).toString('latin1');
      const show = (a) => Array.from(a, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '·')).join('');
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'xor' && x.x0 !== hx([mx[0]])) fail('c1 ⊕ c2 is not m1 ⊕ m2 at byte 0');
        if (st === 'space' && x.sp !== Array.from(mx).filter((v) => v >= 64).length) fail('the count of space bytes');
        if (st === 'crib' && x.other !== show(crib.map((v, j) => v ^ mx[x.pos + j]))) fail('crib at ' + x.pos + ' gives ' + x.other);
        if (st === 'reveal') { if (x.in1 !== (txt(o.m1.slice(x.pos, x.pos + crib.length)) === input.crib)) fail('the crib in m1'); if (x.in2 !== (txt(o.m2.slice(x.pos, x.pos + crib.length)) === input.crib)) fail('the crib in m2'); }
      }
    },
  },
  {
    topic: 'st-lfsr',
    random: (rnd) => { const taps = PRIM[Math.floor(rnd() * PRIM.length)], L = Math.max(...taps.map(Number)); return { taps, seed: randSeed(rnd, L), clocks: 4 + Math.floor(rnd() * 21) }; },
    check({ input, r, fail }) {
      const taps = input.taps.map(Number), L = Math.max(...taps), n = input.clocks, s = recur(taps, input.seed.split('').map(Number), n + L);
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'clock') {
          const i = x.i - 1;
          if (x.out !== s[i]) fail('clock ' + x.i + ': output ' + x.out + ', want ' + s[i]);
          if (x.fb !== s[i + L]) fail('clock ' + x.i + ': feedback ' + x.fb + ', want ' + s[i + L]);
          const want = taps.slice().sort((a, b) => b - a).map((k) => s[i + L - k]);
          if (x.read.join() !== want.join()) fail('clock ' + x.i + ': taps read ' + x.read + ', want ' + want);
          if (!f.say.includes(want.join(' ⊕ ') + ' = ' + s[i + L])) fail('clock ' + x.i + ': the narration does not give the XOR');
        }
        if (st === 'end') { const out = s.slice(0, n).join(''); if (x.out !== out) fail('the output ' + x.out + ', want ' + out); if (x.ones !== out.split('1').length - 1) fail('the count of ones'); }
      }
      if (r.frames.length !== n + 2) fail('expected ' + (n + 2) + ' frames');
    },
  },
  {
    topic: 'st-period', allow: ['4', '6'],
    random: (rnd) => { const L = 3 + Math.floor(rnd() * 4), t = new Set([L]); for (let k = 1; k < L; k++) if (rnd() < 0.4) t.add(k); return { taps: [...t].map(String) }; },
    check({ input, r, fail }) {
      const taps = input.taps.map(Number), L = Math.max(...taps), N = 2 ** L;
      // the cycles, by stepping integers: bit i of v is s(n−L+i)… with v's bit 0 the oldest
      const next = (v) => { let fb = 0; for (const k of taps) fb ^= (v >> (L - k)) & 1; return (v >> 1) | (fb << (L - 1)); };
      const seen = new Set(), lens = [];
      for (let v = 1; v < N; v++) { if (seen.has(v)) continue; let u = v, n = 0; do { seen.add(u); u = next(u); n++; } while (u !== v); lens.push(n); }
      const sorted = lens.slice().sort((a, b) => b - a);
      // primitive: the order of x modulo C(x) is 2^L − 1 (polynomial arithmetic, independent of the register)
      const C = taps.reduce((p, k) => p | (1 << k), 1);
      const mulx = (a) => { a <<= 1; if (a >> L & 1) a ^= C; return a; };
      let a = 1, ord = 0; do { a = mulx(a); ord++; } while (a !== 1 && ord <= N);
      const prim = ord === N - 1;
      let phi = 0; const g = (x, y) => (y ? g(y, x % y) : x); for (let k = 1; k < N; k++) if (g(k, N - 1) === 1) phi++;
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'cycle' && !lens.includes(x.len)) fail('a cycle of ' + x.len);
        if (st === 'end') {
          if (x.prim !== prim) fail('primitive is ' + prim);
          if (x.nPrim !== phi / L) fail('the number of primitive polynomials');
          if (JSON.stringify(x.lens.slice().sort((p, q) => q - p)) !== JSON.stringify(sorted)) fail('the cycle lengths ' + x.lens + ' against ' + sorted);
          if (x.max !== sorted[0]) fail('the longest cycle');
        }
      }
      if (r.frames.filter((f) => f.meta.stage === 'cycle').length !== lens.length) fail('one frame per cycle');
    },
  },
  {
    topic: 'st-galois',
    random: (rnd) => { const taps = PRIM[Math.floor(rnd() * PRIM.length)], L = Math.max(...taps.map(Number)); return L > 8 ? { taps: ['4', '3'], seed: '1001', clocks: 8 } : { taps, seed: randSeed(rnd, L), clocks: 4 + Math.floor(rnd() * 13) }; },
    check({ input, r, fail }) {
      const taps = input.taps.map(Number), L = Math.max(...taps), n = input.clocks, s = recur(taps, input.seed.split('').map(Number), n + L);
      // an independent Galois register: r_j = s_j ⊕ Σ_{k ≤ j} c_k s_(j−k), then r_j ← r_(j+1) ⊕ c_(j+1)·r0
      const c = new Array(L + 1).fill(0); taps.forEach((k) => { c[k] = 1; });
      let g = Array.from({ length: L }, (_, j) => { let v = s[j]; for (let k = 1; k <= j; k++) v ^= c[k] & s[j - k]; return v; });
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'start' && x.gs !== g.slice().reverse().join('')) fail('the Galois start state');
        if (st === 'clock') {
          const i = x.i - 1, out = g[0];
          g = g.map((_, j) => (j + 1 < L ? g[j + 1] : 0) ^ (out & c[j + 1]));
          if (x.out !== s[i] || x.gout !== out || out !== s[i]) fail('clock ' + x.i + ': outputs');
          if (x.fb !== s[i + L]) fail('clock ' + x.i + ': the Fibonacci feedback');
          if (x.gnext !== g.slice().reverse().join('')) fail('clock ' + x.i + ': the Galois state');
        }
        if (st === 'end' && x.out !== s.slice(0, n).join('')) fail('the stream');
      }
    },
  },
  {
    topic: 'st-bm', allow: ['4', '5'],
    random: (rnd) => { const N = 4 + Math.floor(rnd() * 21); let b = ''; for (let i = 0; i < N; i++) b += rnd() < 0.5 ? '1' : '0'; return { bits: b.includes('1') ? b : b.slice(1) + '1' }; },
    check({ input, r, fail }) {
      // Berlekamp–Massey over integers as bit masks, written out again
      const s = input.bits.split('').map(Number);
      let C = 1, B = 1, L = 0, m = -1;
      const P = (p) => { const t = []; for (let k = 0; p >> k; k++) if ((p >> k) & 1) t.push(k); return t.join(','); };
      const want = [];
      for (let n = 0; n < s.length; n++) {
        let d = s[n]; for (let i = 1; i <= L; i++) if ((C >> i) & 1) d ^= s[n - i];
        if (d) { const T = C; C ^= B << (n - m); if (2 * L <= n) { L = n + 1 - L; B = T; m = n; } }
        want.push({ d, C, L });
      }
      const parse = (str) => str.split(' + ').reduce((p, t) => p | (1 << (t === '1' ? 0 : t === 'x' ? 1 : +t.slice(1).replace(/[⁰¹²³⁴⁵⁶⁷⁸⁹]/g, (ch) => '⁰¹²³⁴⁵⁶⁷⁸⁹'.indexOf(ch)))), 0);
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'step') { const w = want[x.n]; if (x.d !== w.d || x.L !== w.L || parse(x.C) !== w.C) fail('bit ' + x.n + ': d ' + x.d + ' L ' + x.L + ' C ' + x.C + ' against ' + w.d + ' ' + w.L + ' ' + P(w.C)); if (x.pred !== (s[x.n] ^ x.d)) fail('bit ' + x.n + ': the prediction'); }
        if (st === 'end') { if (x.L !== L || parse(x.C) !== C) fail('the result'); if (!x.ok) fail('the register does not regenerate the bits'); const t = recur(P(C).split(',').slice(1).map(Number).filter((k) => k <= L), s.slice(0, L), s.length); if (L && t.join('') !== s.join('')) fail('recomputed regeneration'); }
      }
    },
  },
  {
    topic: 'st-rng', allow: ['256', '01', '10', '00', '11'],
    random: (rnd) => ({ seed: 1 + Math.floor(rnd() * 9000), bias: ['0.6', '0.7', '0.8', '0.9'][Math.floor(rnd() * 4)], lcg: ['37,11', '5,3', '101,57', '200,1'][Math.floor(rnd() * 4)] }),
    check({ S, input, r, fail }) {
      const [a, c] = input.lcg.split(',').map(Number), M = 251, xs = [input.seed % M];
      while (xs.length < 12) xs.push((a * xs[xs.length - 1] + c) % M);
      const key = S.Sym.bytes(S.Sym.rng(input.seed * 7919 + 1), 32), iv = Buffer.alloc(16);
      const ks = createCipheriv('chacha20', Buffer.from(key), iv).update(Buffer.alloc(128));
      const sp = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join(' ');
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'lcg' && x.lcg.join() !== xs.join()) fail('the LCG sequence');
        if (st === 'pred') { if (x.ga !== a || x.gc !== c) fail('the solved a, c: ' + x.ga + ', ' + x.gc); if (x.right !== 9) fail('the predictions'); }
        if (st === 'vn' && x.kept > 16) fail('more kept bits than pairs');
        if (st === 'cs' && x.b0 !== sp(ks.subarray(0, 4))) fail('ChaCha20 block 0 against node:crypto');
        if (st === 'cs2' && x.b1 !== sp(ks.subarray(64, 68))) fail('ChaCha20 block 1 against node:crypto');
      }
    },
  },
];
