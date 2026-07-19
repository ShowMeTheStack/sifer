// Scalar multiplication k·P, four ways, each with a per-bit record for drawing and the cost counted: group
// doublings and additions, and the field multiplications (M) and squarings (S) of the Jacobian formulas.
//   S.ECC.naf(k, w = 2) -> signed digits, least significant first (w = 2 is the plain NAF)
//   S.ECC.scalar.ltr(C, k, P)     double-and-add from the top bit down
//   S.ECC.scalar.rtl(C, k, P)     double-and-add from the bottom bit up
//   S.ECC.scalar.ladder(C, k, P)  the Montgomery ladder: one addition and one doubling for every bit
//   S.ECC.scalar.wnaf(C, k, P, w) width-w NAF with odd multiples P, 3P, …, (2^(w−1) − 1)P precomputed
//   each -> {R, doubles, adds, cost: {M, S}, steps: [{i, bit|digit, ops, R, R0?, R1?}], trace}
(function (S) {
  'use strict';
  const E = (S.ECC = S.ECC || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));

  E.naf = (k, w = 2) => {
    k = B(k);
    const W = 1n << BigInt(w), half = W >> 1n, out = [];
    while (k > 0n) {
      let d = 0n;
      if (k & 1n) { d = k % W; if (d >= half) d -= W; k -= d; }
      out.push(Number(d));
      k >>= 1n;
    }
    return out;
  };
  const bitsOf = (k) => k.toString(2);
  const f = (v) => E.fmt(v), fp = (P) => E.fp(P);
  const zero = () => ({ X: 1n, Y: 1n, Z: 0n });
  const finish = (C, name, k, P, J, cnt, doubles, adds, steps, trace) => {
    const R = C.fromJ(J);
    trace.push(step('done', `${name}: ${f(k)}·P = ${fp(R)} after ${doubles} doublings and ${adds} additions (${cnt.M}M + ${cnt.S}S in Jacobian coordinates, then one inversion back to affine).`, { R, doubles, adds, cost: { ...cnt } }));
    return { R, doubles, adds, cost: { M: cnt.M, S: cnt.S }, steps, trace };
  };

  const ltr = (C, k, P) => {
    k = B(k);
    const bits = bitsOf(k), cnt = { M: 0, S: 0, I: 0 }, steps = [], trace = [];
    let J = zero(), doubles = 0, adds = 0;
    trace.push(step('start', `Left-to-right double-and-add on k = ${f(k)} = ${bits.length > 40 ? bits.length + ' bits' : bits + '₂'}: for each bit from the top, double, then add P if the bit is 1.`, { k, bits }));
    for (let j = 0; j < bits.length; j++) {
      const i = bits.length - 1 - j, bit = bits[j] === '1' ? 1 : 0, ops = [];
      if (J.Z !== 0n) { J = C.jdbl(J, cnt); doubles++; ops.push('dbl'); }
      if (bit) { if (J.Z === 0n) J = C.toJ(P); else { J = C.jaddMixed(J, P, cnt); adds++; ops.push('add'); } }
      const R = C.fromJ(J);
      steps.push({ i, bit, ops, R });
      trace.push(step('bit', `Bit ${i} is ${bit}: ${ops.length ? ops.map((o) => (o === 'dbl' ? 'double' : 'add P')).join(', then ') : 'start from P'}; the running point is ${fp(R)}, which is ${f(k >> BigInt(i))}·P.`, { i, bit, ops, R }));
    }
    return finish(C, 'Left to right', k, P, J, cnt, doubles, adds, steps, trace);
  };

  const rtl = (C, k, P) => {
    k = B(k);
    const cnt = { M: 0, S: 0, I: 0 }, steps = [], trace = [], n = E.bitLength(k);
    let J = zero(), Q = C.toJ(P), doubles = 0, adds = 0;
    trace.push(step('start', `Right-to-left double-and-add on k = ${f(k)}: keep Q = 2ⁱ·P, doubling it every step, and add Q into the sum when bit i is 1.`, { k }));
    for (let i = 0; i < n; i++) {
      const bit = Number((k >> BigInt(i)) & 1n), ops = [];
      if (bit) { if (J.Z === 0n) J = Q; else { J = C.jadd(J, Q, cnt); adds++; } ops.push('add'); }
      const R = C.fromJ(J), Qa = C.fromJ(Q);
      if (i < n - 1) { Q = C.jdbl(Q, cnt); doubles++; ops.push('dbl'); }
      steps.push({ i, bit, ops, R, Q: Qa });
      trace.push(step('bit', `Bit ${i} is ${bit}: ${bit ? `add Q = 2^${i}·P = ${fp(Qa)}, so the sum is ${fp(R)}` : `skip Q = ${fp(Qa)}`}${i < n - 1 ? '; then double Q' : ''}.`, { i, bit, ops, R, Q: Qa }));
    }
    return finish(C, 'Right to left', k, P, J, cnt, doubles, adds, steps, trace);
  };

  const ladder = (C, k, P) => {
    k = B(k);
    const bits = bitsOf(k), cnt = { M: 0, S: 0, I: 0 }, steps = [], trace = [];
    let R0 = zero(), R1 = C.toJ(P), doubles = 0, adds = 0;
    trace.push(step('start', `Montgomery ladder on k = ${f(k)}: R0 = O and R1 = P, and R1 − R0 = P always. Each bit does one addition and one doubling, whatever its value, so the timing does not depend on the bits.`, { k, bits }));
    for (let j = 0; j < bits.length; j++) {
      const i = bits.length - 1 - j, bit = bits[j] === '1' ? 1 : 0;
      if (bit) { R0 = C.jadd(R0, R1, cnt); R1 = C.jdbl(R1, cnt); }
      else { R1 = C.jadd(R0, R1, cnt); R0 = C.jdbl(R0, cnt); }
      adds++; doubles++;
      const A0 = C.fromJ(R0), A1 = C.fromJ(R1);
      steps.push({ i, bit, ops: ['add', 'dbl'], R: A0, R0: A0, R1: A1 });
      trace.push(step('bit', `Bit ${i} is ${bit}: ${bit ? 'R0 ← R0 + R1, R1 ← 2·R1' : 'R1 ← R0 + R1, R0 ← 2·R0'}. Now R0 = ${fp(A0)} (${f(k >> BigInt(i))}·P) and R1 = ${fp(A1)}.`, { i, bit, R0: A0, R1: A1 }));
    }
    return finish(C, 'Montgomery ladder', k, P, R0, cnt, doubles, adds, steps, trace);
  };

  const wnaf = (C, k, P, w = 4) => {
    k = B(k);
    const digits = E.naf(k, w), cnt = { M: 0, S: 0, I: 0 }, steps = [], trace = [];
    const m = 1 << (w - 2), T = [C.toJ(P)];
    const P2 = m > 1 ? C.jdbl(C.toJ(P), cnt) : null;
    let doubles = m > 1 ? 1 : 0, adds = 0;
    for (let i = 1; i < m; i++) { T.push(C.jadd(T[i - 1], P2, cnt)); adds++; }
    const Ta = T.map((J) => C.fromJ(J));
    const nz = digits.filter((d) => d).length;
    trace.push(step('start', `Width-${w} NAF of k = ${f(k)}: ${digits.length} signed digits, ${nz} of them nonzero (plain binary has ${bitsOf(k).split('1').length - 1} ones). Precompute ${Ta.map((_, i) => 2 * i + 1 + 'P').join(', ')} for ${m > 1 ? m : 0} group operations.`, { k, digits, table: Ta }));
    let J = zero();
    for (let i = digits.length - 1; i >= 0; i--) {
      const d = digits[i], ops = [];
      if (J.Z !== 0n) { J = C.jdbl(J, cnt); doubles++; ops.push('dbl'); }
      if (d) {
        const Q = d > 0 ? T[(d - 1) >> 1] : C.jneg(T[(-d - 1) >> 1]);
        if (J.Z === 0n) J = Q; else { J = C.jadd(J, Q, cnt); adds++; ops.push(d > 0 ? 'add' : 'sub'); }
      }
      const R = C.fromJ(J);
      steps.push({ i, digit: d, ops, R });
      trace.push(step('digit', `Digit ${i} is ${d}: ${ops.length ? ops.map((o) => (o === 'dbl' ? 'double' : o === 'add' ? `add ${d}P` : `subtract ${-d}P`)).join(', then ') : `start from ${d}P`}; the running point is ${fp(R)}.`, { i, digit: d, ops, R }));
    }
    return finish(C, `Width-${w} NAF`, k, P, J, cnt, doubles, adds, steps, trace);
  };

  E.scalar = { ltr, rtl, ladder, wnaf };
})(globalThis.Sifer = globalThis.Sifer || {});
