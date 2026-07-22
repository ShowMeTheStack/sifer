// Lattices for intuition: bases in two (or a few) dimensions, Gram–Schmidt, Lagrange–Gauss reduction, LLL,
// Babai's rounding and nearest-plane methods for the closest vector, and a toy LWE (Regev) bit encryption whose
// noise can be watched and pushed until decryption fails. Basis vectors are rows; entries are small integers.
//   S.PQ.Lattice.gramSchmidt(B) -> {Bs, mu, norms2, trace}
//   S.PQ.Lattice.gauss(B2) -> {B, U, trace}             Lagrange–Gauss, two dimensions
//   S.PQ.Lattice.lll(B, delta = 0.75) -> {B, U, swaps, trace}
//   S.PQ.Lattice.babai(B, t) / nearestPlane(B, t) -> {v, coeffs, dist, trace}
//   S.PQ.Lattice.shortest(B, bound) / closest(B, t, bound) -> exhaustive answers for small lattices
//   S.PQ.Lattice.points(B, box) -> lattice points in a window, for drawing
//   S.PQ.Lattice.goodBad(seed) -> {good, bad, U}          one lattice, two bases
//   S.PQ.LWE.params / keyGen / encrypt / decrypt / failure / noise   (see below)
(function (S) {
  'use strict';
  const P = (S.PQ = S.PQ || {});
  const L = (P.Lattice = {});
  const step = (...a) => P.step(...a);
  const dot = (a, b) => a.reduce((s, v, i) => s + v * b[i], 0);
  const sub = (a, b) => a.map((v, i) => v - b[i]);
  const addv = (a, b) => a.map((v, i) => v + b[i]);
  const scale = (a, k) => a.map((v) => v * k);
  const fmt = (v) => '(' + v.map((x) => (Number.isInteger(x) ? x : +x.toFixed(2))).join(', ') + ')';
  const fmtB = (B) => B.map(fmt).join(', ');
  L.dot = dot; L.norm = (a) => Math.sqrt(dot(a, a)); L.fmt = fmt;
  // round half away from zero would bias; the reduction algorithms use the usual nearest integer
  const rnd = (x) => Math.round(x);

  L.gramSchmidt = (B) => {
    const n = B.length, Bs = [], mu = B.map(() => new Array(n).fill(0)), norms2 = [], trace = [];
    for (let i = 0; i < n; i++) {
      let v = B[i].slice();
      for (let j = 0; j < i; j++) { mu[i][j] = dot(B[i], Bs[j]) / norms2[j]; v = sub(v, scale(Bs[j], mu[i][j])); }
      mu[i][i] = 1;
      Bs.push(v); norms2.push(dot(v, v));
      trace.push(step('gs', i === 0 ? `b*₁ = b₁ = ${fmt(v)}.` : `b*${sub1(i)} = b${sub1(i)} minus its projections on the earlier b*: ${fmt(v)}, length ${Math.sqrt(norms2[i]).toFixed(3)}.`, { i, v, mu: mu[i].slice(0, i) }));
    }
    return { Bs, mu, norms2, trace };
  };
  const sub1 = (i) => String(i + 1).split('').map((d) => '₀₁₂₃₄₅₆₇₈₉'[d]).join('');
  /** |det| of the lattice, the volume of a fundamental cell */
  L.volume = (B) => Math.sqrt(L.gramSchmidt(B).norms2.reduce((a, b) => a * b, 1));
  /** Hadamard ratio (vol / ∏|bᵢ|)^(1/n): 1 for an orthogonal basis, near 0 for a bad one */
  L.hadamard = (B) => Math.pow(L.volume(B) / B.reduce((a, b) => a * L.norm(b), 1), 1 / B.length);
  const ident = (n) => Array.from({ length: n }, (_, i) => Array.from({ length: n }, (_, j) => +(i === j)));

  /** Lagrange–Gauss reduction: subtract the nearest multiple of the shorter vector, swap, repeat */
  L.gauss = (B0) => {
    let [b1, b2] = B0.map((r) => r.slice()), U = ident(2);
    const trace = [step('gauss-start', `Start with b₁ = ${fmt(b1)} (length ${L.norm(b1).toFixed(3)}) and b₂ = ${fmt(b2)} (length ${L.norm(b2).toFixed(3)}).`, { B: [b1.slice(), b2.slice()] })];
    for (let it = 0; it < 1000; it++) {
      if (dot(b2, b2) < dot(b1, b1)) { [b1, b2] = [b2, b1]; U = [U[1], U[0]]; trace.push(step('swap', `Swap so that b₁ is the shorter: b₁ = ${fmt(b1)}, b₂ = ${fmt(b2)}.`, { B: [b1.slice(), b2.slice()] })); }
      const m = rnd(dot(b1, b2) / dot(b1, b1));
      if (m === 0) { trace.push(step('gauss-done', `⟨b₁, b₂⟩/⟨b₁, b₁⟩ rounds to 0, so no multiple of b₁ shortens b₂: the basis is reduced. b₁ = ${fmt(b1)} is a shortest non-zero vector.`, { B: [b1.slice(), b2.slice()] })); break; }
      b2 = sub(b2, scale(b1, m)); U[1] = sub(U[1], scale(U[0], m));
      trace.push(step('reduce', `b₂ ← b₂ − ${m}·b₁ = ${fmt(b2)}, length ${L.norm(b2).toFixed(3)}.`, { m, B: [b1.slice(), b2.slice()] }));
    }
    return { B: [b1, b2], U, trace };
  };

  /** LLL with parameter δ: size-reduce bₖ, then test Lovász's condition and swap if it fails */
  L.lll = (B0, delta = 0.75) => {
    const n = B0.length, B = B0.map((r) => r.slice()), U = ident(n), trace = [];
    let gs = L.gramSchmidt(B), k = 1, swaps = 0, guard = 0;
    trace.push(step('lll-start', `LLL with δ = ${delta} on ${n} vectors: ${fmtB(B)}. Hadamard ratio ${L.hadamard(B).toFixed(3)}.`, { B: B.map((r) => r.slice()) }));
    while (k < n && guard++ < 100000) {
      for (let j = k - 1; j >= 0; j--) {
        const m = rnd(gs.mu[k][j]);
        if (m !== 0) {
          B[k] = sub(B[k], scale(B[j], m)); U[k] = sub(U[k], scale(U[j], m)); gs = L.gramSchmidt(B);
          trace.push(step('size-reduce', `μ${sub1(k)}${sub1(j)} rounds to ${m}: b${sub1(k)} ← b${sub1(k)} − ${m}·b${sub1(j)} = ${fmt(B[k])}.`, { k, j, m, B: B.map((r) => r.slice()) }));
        }
      }
      const lhs = gs.norms2[k], rhs = (delta - gs.mu[k][k - 1] ** 2) * gs.norms2[k - 1];
      if (lhs >= rhs - 1e-9) {
        trace.push(step('lovasz-ok', `Lovász holds at k = ${k + 1}: |b*${sub1(k)}|² = ${lhs.toFixed(2)} ≥ (δ − μ²)|b*${sub1(k - 1)}|² = ${rhs.toFixed(2)}. Move on.`, { k, lhs, rhs }));
        k++;
      } else {
        [B[k], B[k - 1]] = [B[k - 1], B[k]]; [U[k], U[k - 1]] = [U[k - 1], U[k]]; swaps++; gs = L.gramSchmidt(B);
        trace.push(step('lovasz-swap', `Lovász fails at k = ${k + 1} (${lhs.toFixed(2)} < ${rhs.toFixed(2)}): swap b${sub1(k - 1)} and b${sub1(k)} and step back.`, { k, lhs, rhs, B: B.map((r) => r.slice()) }));
        k = Math.max(k - 1, 1);
      }
    }
    trace.push(step('lll-done', `Reduced after ${swaps} swaps: ${fmtB(B)}. Hadamard ratio ${L.hadamard(B).toFixed(3)}; b₁ has length ${L.norm(B[0]).toFixed(3)}.`, { B: B.map((r) => r.slice()), swaps }));
    return { B, U, swaps, trace };
  };
  /** is B LLL-reduced with δ (size-reduced and Lovász at every k)? */
  L.isReduced = (B, delta = 0.75) => {
    const gs = L.gramSchmidt(B);
    for (let i = 1; i < B.length; i++) {
      for (let j = 0; j < i; j++) if (Math.abs(gs.mu[i][j]) > 0.5 + 1e-9) return false;
      if (gs.norms2[i] < (delta - gs.mu[i][i - 1] ** 2) * gs.norms2[i - 1] - 1e-9) return false;
    }
    return true;
  };

  /** solve x·B = t for the real coefficients x (rows of B are the basis) */
  L.coords = (B, t) => {
    const n = B.length, M = B[0].map((_, c) => B.map((r) => r[c]).concat([t[c]]));
    for (let c = 0; c < n; c++) {
      let p = c; for (let r = c + 1; r < n; r++) if (Math.abs(M[r][c]) > Math.abs(M[p][c])) p = r;
      [M[c], M[p]] = [M[p], M[c]];
      for (let r = 0; r < n; r++) if (r !== c) { const f = M[r][c] / M[c][c]; for (let k = c; k <= n; k++) M[r][k] -= f * M[c][k]; }
    }
    return M.map((r, i) => r[n] / r[i]);
  };
  const combo = (B, c) => c.reduce((acc, ci, i) => addv(acc, scale(B[i], ci)), new Array(B[0].length).fill(0));
  /** Babai's rounding: write t in the basis, round each coordinate */
  L.babai = (B, t) => {
    const x = L.coords(B, t), c = x.map(rnd), v = combo(B, c), dist = L.norm(sub(t, v));
    const trace = [
      step('coords', `In this basis t = ${fmt(t)} has coordinates ${fmt(x)}.`, { x }),
      step('round', `Round each coordinate: ${fmt(c)}, giving the lattice point ${fmt(v)} at distance ${dist.toFixed(3)} from t.`, { c, v, dist }),
    ];
    return { v, coeffs: c, real: x, dist, trace };
  };
  /** Babai's nearest plane: peel off one Gram–Schmidt direction at a time, from the last */
  L.nearestPlane = (B, t) => {
    const gs = L.gramSchmidt(B), n = B.length, c = new Array(n).fill(0), trace = [];
    let r = t.slice();
    for (let i = n - 1; i >= 0; i--) {
      c[i] = rnd(dot(r, gs.Bs[i]) / gs.norms2[i]);
      r = sub(r, scale(B[i], c[i]));
      trace.push(step('plane', `Nearest plane along b*${sub1(i)}: take ${c[i]}·b${sub1(i)}; ${fmt(r)} remains.`, { i, c: c[i], r: r.slice() }));
    }
    const v = combo(B, c), dist = L.norm(sub(t, v));
    trace.push(step('plane-done', `The lattice point ${fmt(v)} is at distance ${dist.toFixed(3)} from t.`, { v, dist }));
    return { v, coeffs: c, dist, trace };
  };
  /** every combination with coefficients in [−bound, bound]: exact answers to check the methods against */
  const enumerate = (B, bound, fn) => {
    const n = B.length, c = new Array(n).fill(-bound);
    for (;;) {
      fn(c, combo(B, c));
      let i = 0;
      while (i < n && c[i] === bound) c[i++] = -bound;
      if (i === n) return;
      c[i]++;
    }
  };
  L.shortest = (B, bound = 6) => { let best = null; enumerate(B, bound, (c, v) => { const l = dot(v, v); if (l > 0 && (!best || l < best.len2)) best = { v: v.slice(), c: c.slice(), len2: l }; }); best.len = Math.sqrt(best.len2); return best; };
  L.closest = (B, t, bound = 6) => { let best = null; enumerate(B, bound, (c, v) => { const d = dot(sub(t, v), sub(t, v)); if (!best || d < best.d2) best = { v: v.slice(), c: c.slice(), d2: d }; }); best.dist = Math.sqrt(best.d2); return best; };
  /** lattice points of a 2-D basis inside {x0, x1, y0, y1} */
  L.points = (B, box) => {
    const corners = [[box.x0, box.y0], [box.x1, box.y0], [box.x0, box.y1], [box.x1, box.y1]].map((p) => L.coords(B, p));
    const lo = [0, 1].map((i) => Math.floor(Math.min(...corners.map((c) => c[i])))), hi = [0, 1].map((i) => Math.ceil(Math.max(...corners.map((c) => c[i]))));
    const out = [];
    for (let a = lo[0]; a <= hi[0]; a++) for (let b = lo[1]; b <= hi[1]; b++) {
      const p = combo(B, [a, b]);
      if (p[0] >= box.x0 && p[0] <= box.x1 && p[1] >= box.y0 && p[1] <= box.y1) out.push({ p, c: [a, b] });
    }
    return out;
  };
  /** a nearly orthogonal basis and a long, skewed basis of the same 2-D lattice */
  L.goodBad = (seed = 7) => {
    const r = P.rng(seed);
    const good = [[5 + r.int(3), r.int(3) - 1], [r.int(3) - 1, 4 + r.int(3)]];
    let U = [[1, 0], [0, 1]];
    for (let i = 0; i < 3; i++) {
      const m = 1 + r.int(3);
      U = i % 2 === 0 ? [addv(U[0], scale(U[1], m)), U[1]] : [U[0], addv(U[1], scale(U[0], m))];
    }
    const bad = [combo(good, U[0]), combo(good, U[1])];
    return { good, bad, U, hGood: L.hadamard(good), hBad: L.hadamard(bad) };
  };

  // ---------------------------------------------------------------------------------------------------------
  // Toy LWE (Regev's bit encryption). Public key (A, b = A·s + e) with A an m×n matrix mod q; a bit is encrypted
  // by summing a random subset r of the rows: u = Aᵀr, v = b·r + bit·⌊q/2⌋. Decryption computes v − s·u =
  // bit·⌊q/2⌋ + e·r and rounds; it fails when the accumulated noise e·r passes q/4.
  const W = (P.LWE = {});
  const erf = (x) => {
    const s = Math.sign(x); x = Math.abs(x);
    const t = 1 / (1 + 0.3275911 * x);
    const y = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-x * x);
    return s * y;
  };
  const Phi = (x) => 0.5 * (1 + erf(x / Math.SQRT2));
  W.params = (o = {}) => Object.assign({ n: 8, m: 24, q: 101, noise: { kind: 'uniform', B: 1 } }, o);
  /** the noise distribution as {value: probability} over a finite support */
  W.noise = (params) => {
    const nz = params.noise, d = new Map();
    if (nz.kind === 'uniform') for (let k = -nz.B; k <= nz.B; k++) d.set(k, 1 / (2 * nz.B + 1));
    else {
      const lim = Math.ceil(6 * nz.sigma);
      for (let k = -lim; k <= lim; k++) d.set(k, nz.sigma === 0 ? +(k === 0) : Phi((k + 0.5) / nz.sigma) - Phi((k - 0.5) / nz.sigma));
    }
    return d;
  };
  const sampleNoise = (params, r) => (params.noise.kind === 'uniform' ? r.int(2 * params.noise.B + 1) - params.noise.B : Math.round(params.noise.sigma * r.gauss()));
  W.keyGen = (params, seed = 1) => {
    const { n, m, q } = params, r = P.rng(seed);
    const A = Array.from({ length: m }, () => Array.from({ length: n }, () => r.int(q)));
    const s = Array.from({ length: n }, () => r.int(q));
    const e = Array.from({ length: m }, () => sampleNoise(params, r));
    const b = A.map((row, i) => P.mod(dot(row, s) + e[i], q));
    const desc = params.noise.kind === 'uniform' ? `uniform in [−${params.noise.B}, ${params.noise.B}]` : `a rounded Gaussian with σ = ${params.noise.sigma}`;
    const trace = [
      step('lwe-params', `n = ${n} secret entries, m = ${m} samples, modulus q = ${q}; noise ${desc}.`, { params }),
      step('lwe-A', `A is a random ${m}×${n} matrix mod ${q}, public.`, { A }),
      step('lwe-s', `The secret s = ${fmt(s)}.`, { s }),
      step('lwe-e', `The noise e = ${fmt(e)}: small, and secret.`, { e }),
      step('lwe-b', `b = A·s + e mod ${q} = ${fmt(b)}. Without e, Gaussian elimination would give s at once.`, { b }),
    ];
    return { pk: { A, b, params }, sk: { s, params }, e, trace };
  };
  W.encrypt = (pk, bit, seed = 2) => {
    const { A, b, params } = pk, { m, n, q } = params, r = P.rng(seed);
    const sel = Array.from({ length: m }, () => r.int(2));
    const u = Array.from({ length: n }, (_, j) => P.mod(A.reduce((acc, row, i) => acc + sel[i] * row[j], 0), q));
    const half = Math.floor(q / 2);
    const v = P.mod(dot(sel, b) + bit * half, q);
    const rows = sel.reduce((a, x, i) => (x ? a.concat(i) : a), []);
    const trace = [
      step('lwe-subset', `Choose a random subset of the rows: ${rows.length} of ${m} (rows ${rows.join(', ')}).`, { r: sel }),
      step('lwe-u', `u = the sum of those rows of A = ${fmt(u)}.`, { u }),
      step('lwe-v', `v = the sum of the matching entries of b${bit ? ` plus ⌊q/2⌋ = ${half}` : ''} = ${v}.`, { v, bit }),
    ];
    return { ct: { u, v }, r: sel, trace };
  };
  /** decrypt; if the key's e and the encryption's r are given, the trace also shows the noise e·r */
  W.decrypt = (sk, ct, known) => {
    const { q } = sk.params, half = Math.floor(q / 2);
    const d = P.mod(ct.v - dot(sk.s, ct.u), q), c = P.centre(d, q);
    const bit = Math.abs(c) > q / 4 ? 1 : 0;
    const trace = [step('lwe-dec', `v − s·u = ${d} (mod ${q}), centred ${c}. It is ${bit ? 'nearer ⌊q/2⌋' : 'nearer 0'} (the boundary is q/4 = ${(q / 4).toFixed(2)}), so the bit is ${bit}.`, { d, centred: c, bit, quarter: q / 4 })];
    let noise = null;
    if (known) {
      noise = known.r.reduce((a, x, i) => a + x * known.e[i], 0);
      trace.push(step('lwe-noise', `The noise carried along is e·r = ${noise}; decryption is right exactly while |e·r| stays below q/4 = ${(q / 4).toFixed(2)}${Math.abs(noise) >= q / 4 ? ' — here it does not, so the bit flips' : ''}.`, { noise, half }));
    }
    return { bit, d, centred: c, noise, trace };
  };
  /**
   * the exact chance that decryption fails, over a random key and a random subset: the noise e·r is a sum of m
   * independent terms eᵢrᵢ, so its distribution is the m-fold convolution of one term's.
   * Returns {bit0, bit1, average, worst} with worst = m·max|e|, the bound below which failure is impossible.
   */
  W.failure = (params) => {
    const { m, q } = params, d1 = W.noise(params);
    const term = new Map([[0, 0.5]]);
    for (const [k, p] of d1) term.set(k, (term.get(k) || 0) + 0.5 * p);
    let dist = new Map([[0, 1]]);
    for (let i = 0; i < m; i++) {
      const nd = new Map();
      for (const [a, pa] of dist) for (const [b, pb] of term) { const k = a + b; nd.set(k, (nd.get(k) || 0) + pa * pb); }
      dist = nd;
    }
    const half = Math.floor(q / 2);
    let f0 = 0, f1 = 0;
    for (const [k, p] of dist) {
      if (Math.abs(P.centre(k, q)) > q / 4) f0 += p;
      if (Math.abs(P.centre(k + half, q)) <= q / 4) f1 += p;
    }
    const maxE = Math.max(...[...d1.keys()].map(Math.abs));
    return { bit0: f0, bit1: f1, average: (f0 + f1) / 2, worst: m * maxE, safe: m * maxE < q / 4 - 0.5, dist };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
