// Linear feedback shift registers. The connection polynomial C(x) = 1 + c1·x + … + cL·x^L says which earlier bits feed
// the next one: s_n = c1·s_(n−1) ⊕ … ⊕ cL·s_(n−L). Taps are the exponents k with c_k = 1, e.g. [4, 3] for
// 1 + x³ + x⁴. Polynomials are BigInt bit masks (bit k = coefficient of x^k), the convention of S.GF.poly.
//   S.LFSR.poly(taps) -> BigInt;  S.LFSR.str(poly) -> text;  S.LFSR.taps(poly) -> exponents
//   S.LFSR.fibonacci(taps, seed) -> {L, state(), step() -> {out, fb, state, say}, run(n) -> {bits, trace}}
//       seed is [s0 … s(L−1)], the first L output bits; the register shifts them out in order
//   S.LFSR.galois(taps, seed) -> the same interface: one XOR per tap inside the register, the same output sequence
//   S.LFSR.sequence(taps, seed, n) -> n output bits, fast
//   S.LFSR.period(taps[, seed]) -> the period (state space up to about 2^24)
//   S.LFSR.isPrimitive(taps) -> true when the period from any nonzero state is 2^L − 1
//   S.LFSR.berlekampMassey(bits) -> {L, poly, taps, steps: [{n, s, d, C, L, B, m, say}], trace}
(function (S) {
  'use strict';
  const R = (S.LFSR = {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  R.poly = (taps) => taps.reduce((p, k) => p | (1n << BigInt(k)), 1n);
  R.taps = (poly) => { const t = []; for (let k = 1; (poly >> BigInt(k)) > 0n; k++) if ((poly >> BigInt(k)) & 1n) t.push(k); return t.reverse(); };
  R.deg = (poly) => poly.toString(2).length - 1;
  R.str = (poly) => {
    if (S.GF && S.GF.poly) {
      // S.GF.poly writes the highest power first; registers read better from 1 upwards
      return S.GF.poly.str(poly).split(' + ').reverse().join(' + ');
    }
    const t = []; for (let k = 0; (poly >> BigInt(k)) > 0n; k++) if ((poly >> BigInt(k)) & 1n) t.push(k === 0 ? '1' : k === 1 ? 'x' : 'x^' + k); return t.join(' + ');
  };
  const bits = (a) => a.join('');
  const xp = (k) => (k === 0 ? '1' : k === 1 ? 'x' : 'x' + String(k).split('').map((d) => '⁰¹²³⁴⁵⁶⁷⁸⁹'[d]).join(''));

  R.fibonacci = (taps, seed) => {
    const L = Math.max(...taps);
    if (seed.length !== L) throw new Error(`the register needs ${L} seed bits`);
    let st = seed.slice();
    const self = { L, taps, kind: 'fibonacci', state: () => st.slice() };
    self.step = () => {
      // st[0] is the oldest bit (s_(n−L)), st[L−1] the newest; s_n = XOR of st[L − k] over the taps k
      const used = taps.map((k) => st[L - k]), fb = used.reduce((a, b) => a ^ b, 0), out = st[0];
      const before = st.slice();
      st = st.slice(1).concat([fb]);
      return { out, fb, state: st.slice(), before, say: `Output ${out}; the taps ${taps.map(xp).join(', ')} read ${used.join(', ')}, so the new bit is ${used.join(' ⊕ ')} = ${fb}; the register is now ${bits(st)}.` };
    };
    self.run = (n) => { const out = [], trace = []; for (let i = 0; i < n; i++) { const s = self.step(); out.push(s.out); trace.push(step('lfsr', s.say, s)); } return { bits: out, trace }; };
    return self;
  };
  /** Galois form: the register holds the sequence's partial sums; the output bit is fed back into every tap position */
  R.galois = (taps, seed) => {
    const L = Math.max(...taps), c = new Array(L + 1).fill(0);
    taps.forEach((k) => { c[k] = 1; });
    // turn the first L output bits into the Galois state that produces them: r_j = Σ_{i ≥ 0} c_(i+j+1)·s_... solved
    // by running the Fibonacci register's recurrence: r_j = s_j ⊕ Σ_{k=1..j} c_k·s_(j−k)
    let r = seed.map((s, j) => { let v = s; for (let k = 1; k <= j; k++) v ^= c[k] & seed[j - k]; return v; });
    const self = { L, taps, kind: 'galois', state: () => r.slice() };
    self.step = () => {
      const out = r[0], before = r.slice(), next = new Array(L);
      for (let j = 0; j < L; j++) next[j] = (j + 1 < L ? r[j + 1] : 0) ^ (out & c[j + 1]);
      r = next;
      return { out, state: r.slice(), before, say: `Output ${out}; every cell moves one place${out ? `, and the output 1 is XORed into the cells under the taps ${taps.join(', ')}` : ''}: the register is now ${bits(r)}.` };
    };
    self.run = (n) => { const out = [], trace = []; for (let i = 0; i < n; i++) { const s = self.step(); out.push(s.out); trace.push(step('lfsr', s.say, s)); } return { bits: out, trace }; };
    return self;
  };
  /** the output bits alone, without narration: s_n = XOR of s_(n−k) over the taps */
  R.sequence = (taps, seed, n) => {
    const out = seed.slice(0, n);
    for (let i = seed.length; i < n; i++) { let v = 0; for (const k of taps) v ^= out[i - k]; out.push(v); }
    return out;
  };
  R.period = (taps, seed) => {
    const L = Math.max(...taps);
    if (L > 26) throw new Error('too long to walk');
    let st = 0;
    const s0 = seed || Array.from({ length: L }, (_, i) => (i === L - 1 ? 1 : 0));
    s0.forEach((b, i) => { st |= b << i; });
    if (!st) return 1;
    let mask = 0; taps.forEach((k) => { mask |= 1 << (L - k); });
    const start = st;
    for (let n = 1; n <= 2 ** L; n++) {
      let fb = st & mask, p = 0; while (fb) { p ^= fb & 1; fb >>>= 1; }
      st = (st >>> 1) | (p << (L - 1));
      if (st === start) return n;
    }
    return Infinity;
  };
  R.isPrimitive = (taps) => R.period(taps) === 2 ** Math.max(...taps) - 1;

  R.berlekampMassey = (s) => {
    let C = 1n, B = 1n, L = 0, m = -1;
    const steps = [], trace = [], P = (p) => R.str(p);
    for (let n = 0; n < s.length; n++) {
      let d = s[n];
      for (let i = 1; i <= L; i++) if ((C >> BigInt(i)) & 1n) d ^= s[n - i];
      const before = C, Lb = L;
      let say;
      if (d === 0) say = `n = ${n}: s${n} = ${s[n]} and C(x) = ${P(C)} predicts it (discrepancy 0); keep C and L = ${L}.`;
      else {
        const T = C, shift = n - m, Bb = B;
        C ^= B << BigInt(shift);
        if (2 * L <= n) {
          L = n + 1 - L; B = T; m = n;
          say = `n = ${n}: s${n} = ${s[n]}, but C(x) predicts ${s[n] ^ 1} (discrepancy 1); C(x) becomes ${P(before)} + ${xp(shift)}·(${P(Bb)}) = ${P(C)}, and the length grows from ${Lb} to ${L}.`;
        } else say = `n = ${n}: s${n} = ${s[n]}, discrepancy 1; C(x) becomes ${P(before)} + ${xp(shift)}·(${P(Bb)}) = ${P(C)}; the length stays ${L}.`;
      }
      steps.push({ n, s: s[n], d, C, L, B, m, say });
      trace.push(step('bm', say, { n, s: s[n], d, C, L, B, m }));
    }
    trace.push(step('bm-done', `The shortest LFSR that makes these ${s.length} bits has length ${L} and connection polynomial ${P(C)}${s.length >= 2 * L ? ` (unique, since ${s.length} ≥ 2L)` : ''}.`, { L, C }));
    return { L, poly: C, taps: R.taps(C), steps, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
