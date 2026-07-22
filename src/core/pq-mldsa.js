// A toy lattice signature in the style of ML-DSA (FIPS 204): Fiat–Shamir with aborts over Z_q[X]/(X^n + 1).
// It keeps the ideas — a short secret (s₁, s₂), t = A·s₁ + s₂, a masking vector y, the high bits of A·y, a sparse
// challenge c, the response z = y + c·s₁ and the two rejection tests — and drops the rest (no compression of t, no
// hints, a small ring, simple encodings). It is labelled toy everywhere and is not ML-DSA.
//   S.PQ.ToyDSA.params(o) -> {n, q, k, l, eta, tau, beta, gamma1, gamma2}
//   S.PQ.ToyDSA.keyGen(seed, params) -> {pk: {A, t}, sk: {s1, s2, ...}, trace}
//   S.PQ.ToyDSA.sign(sk, msg, {seed, noAbort}) -> {sig: {c, z}, attempts, trace}
//   S.PQ.ToyDSA.verify(pk, msg, sig) -> {ok, trace}
//   S.PQ.ToyDSA.zSamples(sk, count, {abort}) -> what the responses reveal about s₁ with and without aborts
(function (S) {
  'use strict';
  const P = (S.PQ = S.PQ || {});
  const D = (P.ToyDSA = {});
  const step = (...a) => P.step(...a);
  const enc = (m) => (typeof m === 'string' ? new TextEncoder().encode(m) : m);
  D.params = (o = {}) => {
    const p = Object.assign({ n: 32, q: 8380417, k: 2, l: 2, eta: 2, tau: 8, gamma1: 1 << 10 }, o);
    p.gamma2 = p.gamma2 || (p.q - 1) / 88;
    p.beta = p.tau * p.eta;
    return p;
  };
  const md = (a, q) => ((a % q) + q) % q;
  const cen = (a, q) => { a = md(a, q); return a > (q - 1) / 2 ? a - q : a; };
  const pmul = (a, b, p) => {
    const r = new Array(p.n).fill(0);
    for (let i = 0; i < p.n; i++) if (a[i]) for (let j = 0; j < p.n; j++) { const k = i + j, v = a[i] * b[j]; if (k < p.n) r[k] += v; else r[k - p.n] -= v; }
    return r.map((v) => md(v, p.q));
  };
  const padd = (a, b, q) => a.map((v, i) => md(v + b[i], q));
  const psub = (a, b, q) => a.map((v, i) => md(v - b[i], q));
  const matVec = (A, v, p) => A.map((row) => row.reduce((acc, a, j) => padd(acc, pmul(a, v[j], p), p.q), new Array(p.n).fill(0)));
  const inf = (vec, q) => vec.reduce((m, f) => f.reduce((mm, x) => Math.max(mm, Math.abs(cen(x, q))), m), 0);
  /** r = r₁·2γ₂ + r₀ with r₀ centred, and the corner case r − r₀ = q − 1 folded to r₁ = 0 */
  D.decompose = (r, p) => {
    r = md(r, p.q);
    let r0 = r % (2 * p.gamma2);
    if (r0 > p.gamma2) r0 -= 2 * p.gamma2;
    if (r - r0 === p.q - 1) return [0, r0 - 1];
    return [(r - r0) / (2 * p.gamma2), r0];
  };
  const high = (vec, p) => vec.map((f) => f.map((x) => D.decompose(x, p)[0]));
  const low = (vec, p) => vec.map((f) => f.map((x) => D.decompose(x, p)[1]));
  const matrix = (rho, p) => {
    const x = P.xof(rho, 128);
    return Array.from({ length: p.k }, () => Array.from({ length: p.l }, () => Array.from({ length: p.n }, () => { for (;;) { const b = x.read(3), v = (b[0] | (b[1] << 8) | (b[2] << 16)) & 0x7fffff; if (v < p.q) return v; } })));
  };
  /** a challenge with τ coefficients ±1, from the hash of μ and w₁ */
  const challenge = (mu, w1, p) => {
    const bytes = P.shake256(P.concat(mu, Uint8Array.from(w1.flat())), 64), c = new Array(p.n).fill(0), x = P.xof(bytes, 256);
    let placed = 0;
    while (placed < p.tau) { const b = x.read(2), pos = b[0] % p.n; if (!c[pos]) { c[pos] = b[1] & 1 ? 1 : -1; placed++; } }
    return { c: c.map((v) => md(v, p.q)), tag: bytes.slice(0, 16) };
  };
  const pkBytes = (pk) => P.concat(pk.rho, Uint8Array.from(pk.t.flat().flatMap((v) => [v & 255, (v >> 8) & 255, (v >> 16) & 255])));

  D.keyGen = (seed = 'toy-dsa', params) => {
    const p = params || D.params(), r = P.rng(seed), rho = P.shake256(enc('rho:' + seed), 32);
    const A = matrix(rho, p), small = () => Array.from({ length: p.n }, () => md(r.int(2 * p.eta + 1) - p.eta, p.q));
    const s1 = Array.from({ length: p.l }, small), s2 = Array.from({ length: p.k }, small);
    const t = matVec(A, s1, p).map((f, i) => padd(f, s2[i], p.q));
    const pk = { p, rho, A, t };
    pk.tr = P.shake256(pkBytes(pk), 32);
    const trace = [
      step('dsa-params', `Toy parameters: ring Z_${p.q}[X]/(X^${p.n} + 1), A is ${p.k}×${p.l}, secrets in [−${p.eta}, ${p.eta}], τ = ${p.tau} so β = τη = ${p.beta}, γ₁ = ${p.gamma1}, γ₂ = ${p.gamma2}. A toy, not ML-DSA.`, { params: p }),
      step('dsa-secret', `Short secrets s₁ (${p.l} polynomials) and s₂ (${p.k}), every coefficient in [−${p.eta}, ${p.eta}].`, { s1: s1.map((f) => f.map((x) => cen(x, p.q))), s2: s2.map((f) => f.map((x) => cen(x, p.q))) }),
      step('dsa-public', `t = A·s₁ + s₂: a Module-LWE sample, so t hides s₁.`, { t }),
    ];
    return { pk, sk: { p, A, s1, s2, t, tr: pk.tr }, trace };
  };
  D.sign = (sk, msg, opts = {}) => {
    const p = sk.p, r = P.rng(opts.seed || 3), trace = [], mu = P.shake256(P.concat(sk.tr, enc(msg)), 32);
    for (let attempt = 1; attempt <= 500; attempt++) {
      const y = Array.from({ length: p.l }, () => Array.from({ length: p.n }, () => md(r.int(2 * p.gamma1) - p.gamma1 + 1, p.q)));
      const w = matVec(sk.A, y, p), w1 = high(w, p);
      const { c, tag } = challenge(mu, w1, p);
      const cs1 = sk.s1.map((f) => pmul(c, f, p)), cs2 = sk.s2.map((f) => pmul(c, f, p));
      const z = y.map((f, i) => padd(f, cs1[i], p.q));
      const zn = inf(z, p.q), r0 = inf(low(w.map((f, i) => psub(f, cs2[i], p.q)), p), p.q);
      const okZ = zn < p.gamma1 - p.beta, okR = r0 < p.gamma2 - p.beta;
      const say = `Attempt ${attempt}: mask y in [−${p.gamma1 - 1}, ${p.gamma1}], w₁ = HighBits(A·y), challenge c from H(μ, w₁) with ${p.tau} entries ±1, z = y + c·s₁. ` +
        (okZ ? '' : `‖z‖∞ = ${zn} ≥ γ₁ − β = ${p.gamma1 - p.beta}: z would show where c·s₁ pushed it, abort. `) +
        (okZ && !okR ? `the low bits of w − c·s₂ reach ${r0} ≥ γ₂ − β: abort. ` : '') + (okZ && okR ? `‖z‖∞ = ${zn} < ${p.gamma1 - p.beta}: accept.` : '');
      trace.push(step(okZ && okR ? 'dsa-accept' : 'dsa-abort', say, { attempt, y: y.map((f) => f.map((x) => cen(x, p.q))), z: z.map((f) => f.map((x) => cen(x, p.q))), c: c.map((x) => cen(x, p.q)), zNorm: zn, lowNorm: r0, bound: p.gamma1 - p.beta }));
      if ((okZ && okR) || opts.noAbort) return { sig: { c, tag, z }, attempts: attempt, trace };
    }
    throw new Error('too many aborts');
  };
  D.verify = (pk, msg, sig) => {
    const p = pk.p, mu = P.shake256(P.concat(pk.tr, enc(msg)), 32);
    const Az = matVec(pk.A, sig.z, p), ct = pk.t.map((f) => pmul(sig.c, f, p));
    const w1 = high(Az.map((f, i) => psub(f, ct[i], p.q)), p);
    const { c } = challenge(mu, w1, p), zn = inf(sig.z, p.q);
    const sameC = c.every((v, i) => v === sig.c[i]), ok = sameC && zn < p.gamma1 - p.beta;
    const trace = [
      step('dsa-v-w', 'A·z − c·t = A·y − c·s₂, whose high bits equal w₁ because the signer checked that c·s₂ cannot carry across a boundary.', { w1 }),
      step(ok ? 'dsa-ok' : 'dsa-bad', ok ? `H(μ, w₁) gives the same challenge and ‖z‖∞ = ${zn} is small: accept.` : sameC ? `‖z‖∞ = ${zn} is too large: reject.` : 'The recomputed challenge differs: reject.', { ok, zNorm: zn }),
    ];
    return { ok, trace };
  };
  /**
   * what an observer of many signatures sees in the coefficients of z. Without aborts some z fall outside the range
   * of y itself, and only on the side that c·s₁ pushed them, so each such value leaks the sign of (c·s₁)ᵢ (edge
   * counts them, agree counts the leaks); with aborts z is uniform on a fixed range and nothing sticks out.
   */
  D.zSamples = (sk, count = 400, opts = {}) => {
    const p = sk.p, abort = opts.abort !== false, r = P.rng(opts.seed || 9);
    const bound = p.gamma1 - p.beta, hist = new Map();
    let edge = 0, agree = 0;
    for (let s = 0; s < count; s++) {
      const y = Array.from({ length: p.l }, () => Array.from({ length: p.n }, () => r.int(2 * p.gamma1) - p.gamma1 + 1));
      const c = new Array(p.n).fill(0);
      for (let placed = 0; placed < p.tau;) { const pos = r.int(p.n); if (!c[pos]) { c[pos] = r.int(2) ? 1 : -1; placed++; } }
      const cs1 = sk.s1.map((f) => pmul(c.map((v) => md(v, p.q)), f, p).map((v) => cen(v, p.q)));
      const z = y.map((f, i) => f.map((v, j) => v + cs1[i][j]));
      if (abort && z.some((f) => f.some((v) => Math.abs(v) >= bound))) { s--; continue; }
      z.forEach((f, i) => f.forEach((v, j) => {
        const b = Math.round(v / 64) * 64; hist.set(b, (hist.get(b) || 0) + 1);
        if (v > p.gamma1 || v < -p.gamma1 + 1) { edge++; if (Math.sign(v) === Math.sign(cs1[i][j])) agree++; }
      }));
    }
    return { hist: [...hist.entries()].sort((a, b) => a[0] - b[0]), edge, agree, bound };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
