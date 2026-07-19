// Biased and partly known ECDSA nonces: the hidden number problem. Each signature gives k_i = t_i·d + u_i (mod n)
// with t_i = r_i/s_i and u_i = e_i/s_i. If every k_i is known to lie in a short interval [a_i, a_i + K), the key d
// makes one lattice vector unusually short, and lattice reduction finds it.
//   S.ECC.lll(B[, delta = [99n, 100n]]) -> {B, swaps, trace}     exact integral LLL on BigInt rows
//   S.ECC.hnp.lattice(C, sigs, K) -> {rows, scale}               sigs = [{r, s, e, a?}] with a_i ≤ k_i < a_i + K
//   S.ECC.hnp.attack(C, sigs, K, Q) -> {d, basis, reduced, engine, trace}
//   S.ECC.hnp.twoSig(C, sigs2, K, Q) -> {d, k1, k2, basis, reduced, trace}   the 2-D picture: Lagrange reduction
//   S.ECC.hnp.demo(C, {seed, m, bits, known}) -> {d, Q, sigs, K, result}       plant a key, sign with short nonces
(function (S) {
  'use strict';
  const E = (S.ECC = S.ECC || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const f = (v) => E.fmt(v);
  const abs = (v) => (v < 0n ? -v : v);
  const gcd = (a, b) => { a = abs(a); b = abs(b); while (b) [a, b] = [b, a % b]; return a; };
  // rationals [num, den] with den > 0
  const Q = (n, d = 1n) => { if (d < 0n) { n = -n; d = -d; } const g = gcd(n, d) || 1n; return [n / g, d / g]; };
  const qge = (a, b) => a[0] * b[1] >= b[0] * a[1];
  const qround = (a) => { const [n, d] = a; const fl = (n >= 0n ? n : n - d + 1n) / d, r = Q(n - fl * d, d); return qge(r, [1n, 2n]) ? fl + 1n : fl; };
  const dot = (a, b) => a.reduce((s, v, i) => s + v * b[i], 0n);

  /** integral LLL: all Gram–Schmidt data kept as integers, d_i = Π|b*_j|² (j ≤ i) and λ_kj = d_j·μ_kj */
  E.lll = (B0, delta = [99n, 100n]) => {
    const b = B0.map((r) => r.map(BigInt)), n = b.length, trace = [], [dp, dq] = delta;
    const D = new Array(n + 1).fill(0n), lam = b.map(() => new Array(n).fill(0n));
    D[0] = 1n; D[1] = dot(b[0], b[0]);
    const rnd = (x, y) => { const q2 = 2n * y; let num = 2n * x + y; return num >= 0n ? num / q2 : -((-num + q2 - 1n) / q2); };
    const red = (k, l) => {
      if (2n * abs(lam[k][l]) <= D[l + 1]) return;
      const q = rnd(lam[k][l], D[l + 1]);
      b[k] = b[k].map((x, c) => x - q * b[l][c]);
      lam[k][l] -= q * D[l + 1];
      for (let i = 0; i < l; i++) lam[k][i] -= q * lam[l][i];
    };
    let k = 1, kmax = 0, swaps = 0, guard = 0;
    trace.push(step('lll-start', `Exact LLL with δ = ${dp}/${dq} on ${n} vectors of up to ${Math.max(...b.map((r) => Math.max(...r.map((x) => E.bitLength(abs(x))))))} bits.`, { n }));
    while (k < n && guard++ < 1000000) {
      if (k > kmax) {
        kmax = k;
        for (let j = 0; j <= k; j++) {
          let u = dot(b[k], b[j]);
          for (let i = 0; i < j; i++) u = (D[i + 1] * u - lam[k][i] * lam[j][i]) / D[i];
          if (j < k) lam[k][j] = u; else D[k + 1] = u;
        }
      }
      red(k, k - 1);
      const L = lam[k][k - 1];
      if (dq * D[k + 1] * D[k - 1] < dp * D[k] * D[k] - dq * L * L) {
        [b[k], b[k - 1]] = [b[k - 1], b[k]];
        for (let j = 0; j < k - 1; j++) [lam[k][j], lam[k - 1][j]] = [lam[k - 1][j], lam[k][j]];
        const Bn = (D[k - 1] * D[k + 1] + L * L) / D[k];
        for (let i = k + 1; i <= kmax; i++) {
          const t = lam[i][k];
          lam[i][k] = (D[k + 1] * lam[i][k - 1] - L * t) / D[k];
          lam[i][k - 1] = (Bn * t + L * lam[i][k]) / D[k + 1];
        }
        D[k] = Bn; swaps++;
        k = Math.max(1, k - 1);
      } else {
        for (let l = k - 2; l >= 0; l--) red(k, l);
        k++;
      }
    }
    trace.push(step('lll-done', `Reduced after ${swaps} swaps. The shortest row now has ${Math.min(...b.map((r) => E.bitLength(S.NT.isqrt(dot(r, r)))))} bits.`, { swaps }));
    return { B: b, swaps, trace };
  };

  const coeffs = (C, sigs, K) => sigs.map((g) => {
    const n = C.n, si = E.inv(BigInt(g.s), n);
    return { t: E.mod(BigInt(g.r) * si, n), u: E.mod(BigInt(g.e) * si - BigInt(g.a || 0n) - K / 2n, n) };
  });
  /** rows: n²·e_i; (n·t_1 … n·t_m, K, 0); (n·u_1 … n·u_m, 0, n·K/2). The target (n(k_i − a_i − K/2), d·K, n·K/2) is short. */
  const lattice = (C, sigs, K) => {
    const n = C.n, m = sigs.length, cs = coeffs(C, sigs, K), rows = [];
    for (let i = 0; i < m; i++) { const r = new Array(m + 2).fill(0n); r[i] = n * n; rows.push(r); }
    rows.push([...cs.map((c) => n * c.t), K, 0n]);
    rows.push([...cs.map((c) => n * c.u), 0n, (n * K) / 2n]);
    return { rows, cs };
  };
  const attack = (C, sigs, K, Qp) => {
    K = BigInt(K);
    const n = C.n, m = sigs.length, trace = [], { rows } = lattice(C, sigs, K);
    trace.push(step('equations', `${m} signatures, each nonce known to lie in an interval of width K = 2^${E.bitLength(K) - 1} out of n ≈ 2^${E.bitLength(n)}: k_i − a_i = t_i·d + u_i (mod n) is small for every i at once.`, { m, K }));
    trace.push(step('lattice', `Build the ${m + 2}-dimensional lattice whose rows are n²·e_i, (n·t, K, 0) and (n·u, 0, nK/2). The combination with coefficient d on the t-row, 1 on the u-row and the right multiples of n² is the vector (n(k_i − a_i − K/2), d·K, nK/2): every entry is at most about nK/2, far shorter than a typical vector of a lattice with this volume.`, { rows }));
    const small = n < 1n << 24n && m + 2 <= 8 && S.PQ && S.PQ.Lattice;
    let red, engine;
    if (small) {
      const fl = S.PQ.Lattice.lll(rows.map((r) => r.map(Number)), 0.99);
      red = fl.B.map((r) => r.map((x) => BigInt(Math.round(x)))); engine = 'float';
    }
    const tryRead = (R) => {
      for (const row of R) {
        const last = row[m + 1];
        if (abs(last) !== (n * K) / 2n) continue;
        const sg = last > 0n ? 1n : -1n, x = E.mod(sg * row[m] / K, n);
        if (C.eq(C.mul(x, C.G), Qp)) return x;
      }
      return null;
    };
    let d = red ? tryRead(red) : null;
    let lt = null;
    if (d == null) { lt = E.lll(rows); red = lt.B; engine = 'exact'; d = tryRead(red); }
    trace.push(step('reduce', `${engine === 'float' ? 'LLL (floating point, the numbers are small)' : 'Exact LLL on BigInt rows'} shortens the basis${lt ? ` in ${lt.swaps} swaps` : ''}.`, { engine }));
    trace.push(step(d != null ? 'found' : 'fail', d != null ? `A reduced row ends in ±nK/2; its second-last entry is ±d·K, so d = ${f(d)}, and d·G is the public key.` : 'No reduced row has the expected shape: more signatures (or a stronger bias) are needed.', { d }));
    return { d, basis: rows, reduced: red, engine, trace };
  };

  /** two signatures: eliminate d to get k₁ − T·k₂ ≡ U (mod n), a 2-D closest-vector problem */
  const twoSig = (C, sigs, K, Qp) => {
    K = BigInt(K);
    const n = C.n, [c1, c2] = coeffs(C, sigs, 0n).map((c) => c), trace = [];
    const T = E.mod(c1.t * E.inv(c2.t, n), n), U = E.mod(c1.u - T * c2.u, n);
    trace.push(step('eliminate', `From k₁ = t₁d + u₁ and k₂ = t₂d + u₂: k₁ − T·k₂ ≡ U (mod n) with T = t₁/t₂ = ${f(T)} and U = ${f(U)}. The pairs (k₁, k₂) solving this form a shifted lattice with basis (n, 0), (T, 1).`, { T, U }));
    let b1 = [n, 0n], b2 = [T, 1n];
    const basis = [b1.slice(), b2.slice()];
    for (let it = 0; it < 1000; it++) {
      if (dot(b2, b2) < dot(b1, b1)) [b1, b2] = [b2, b1];
      const num = dot(b1, b2), den = dot(b1, b1), m = qround(Q(num, den));
      if (m === 0n) break;
      b2 = [b2[0] - m * b1[0], b2[1] - m * b1[1]];
    }
    trace.push(step('gauss', `Lagrange reduction gives the short basis (${f(b1[0])}, ${f(b1[1])}), (${f(b2[0])}, ${f(b2[1])}).`, { reduced: [b1, b2] }));
    // CVP by rounding: the target (U, 0) shifted to the centre of the box of small nonces
    const t = [U - K / 2n, -K / 2n], det = b1[0] * b2[1] - b1[1] * b2[0];
    const c1r = qround(Q(t[0] * b2[1] - t[1] * b2[0], det)), c2r = qround(Q(b1[0] * t[1] - b1[1] * t[0], det));
    let best = null;
    for (let i = -2n; i <= 2n && !best; i++) for (let j = -2n; j <= 2n && !best; j++) {
      const v = [c1r + i, c2r + j], w = [v[0] * b1[0] + v[1] * b2[0], v[0] * b1[1] + v[1] * b2[1]];
      const k2 = E.mod(-w[1], n), k1 = E.mod(U + T * k2, n);
      if (k1 < K && k2 < K) {
        const d = E.mod((k1 - c1.u) * E.inv(c1.t, n), n);
        if (!Qp || C.eq(C.mul(d, C.G), Qp)) best = { d, k1, k2 };
      }
    }
    trace.push(step(best ? 'found' : 'fail', best ? `The lattice point nearest the target gives k₁ = ${f(best.k1)} and k₂ = ${f(best.k2)}, both below K = ${f(K)}; then d = (k₁ − u₁)/t₁ = ${f(best.d)}.` : 'No small pair found: the nonces are not short enough for two signatures.', best || {}));
    return { d: best ? best.d : null, k1: best && best.k1, k2: best && best.k2, basis, reduced: [b1, b2], T, U, trace };
  };

  const demo = (C, o = {}) => {
    const old = S.NT.setRandom(S.NT.seededRandom(o.seed || 1));
    try {
      const bits = o.bits, K = 1n << BigInt(bits), m = o.m || 6, { d, Q: Qp } = E.keygen(C), sigs = [];
      for (let i = 0; i < m; i++) {
        const e = S.NT.randBelow(C.n);
        // known: the top bits of k are known (a_i), otherwise they are zero (a_i = 0)
        const top = o.known ? S.NT.randBelow(C.n / K) * K : 0n, k = top + S.NT.randBelow(K);
        if (k === 0n) { i--; continue; }
        const R = C.mul(k, C.G), r = E.mod(R.x, C.n), s = E.mod(E.inv(k, C.n) * (e + r * d), C.n);
        sigs.push({ r, s, e, a: top, k });
      }
      const result = m === 2 ? twoSig(C, sigs, K, Qp) : attack(C, sigs.map(({ r, s, e, a }) => ({ r, s, e, a })), K, Qp);
      return { d, Q: Qp, sigs, K, result };
    } finally { S.NT.setRandom(old); }
  };
  E.hnp = { lattice, attack, twoSig, demo };
})(globalThis.Sifer = globalThis.Sifer || {});
