// Quantum intuition, by classical simulation of tiny registers. Nothing here is quantum computation: it is the
// arithmetic of amplitudes, done by hand, so that the shapes can be drawn.
//   S.PQ.Quantum.grover({n, marked, iterations?}) -> {N, amps: [[...] per step], success: [...], best, theta, trace}
//   S.PQ.Quantum.shor(N, {a?, seed?}) -> {a, r, Q, probs, y, convergents, factors, trace}
//   S.PQ.Quantum.period(a, N) -> {r, table}
//   S.PQ.Quantum.impact() -> rows of {primitive, classical, quantum, note}
(function (S) {
  'use strict';
  const P = (S.PQ = S.PQ || {});
  const Q = (P.Quantum = {});
  const step = (...a) => P.step(...a);
  const gcd = (a, b) => { while (b) [a, b] = [b, a % b]; return Math.abs(a); };
  const powmod = (b, e, m) => { let r = 1n, B = BigInt(b) % BigInt(m), E = BigInt(e); const M = BigInt(m); while (E > 0n) { if (E & 1n) r = (r * B) % M; B = (B * B) % M; E >>= 1n; } return Number(r); };
  Q.gcd = gcd; Q.powmod = powmod;

  /**
   * Grover's search over N = 2^n items with some marked. Each iteration flips the sign of the marked amplitudes
   * (the oracle) and reflects every amplitude about the mean (the diffusion). After about (π/4)·√(N/M) iterations
   * the marked items hold almost all the probability; one more and it starts to fall again.
   */
  Q.grover = (opts) => {
    const n = opts.n, N = 2 ** n, marked = new Set(opts.marked || [0]), M = marked.size;
    if (n > 16) throw new Error('keep the register to at most 16 qubits');
    const theta = Math.asin(Math.sqrt(M / N)), best = Math.max(0, Math.round(Math.PI / (4 * theta) - 0.5));
    const iterations = opts.iterations != null ? opts.iterations : best;
    let a = new Float64Array(N).fill(1 / Math.sqrt(N));
    const pMarked = (v) => [...marked].reduce((s, i) => s + v[i] * v[i], 0);
    const amps = [Array.from(a)], success = [pMarked(a)], trace = [];
    trace.push(step('grover-start', `${n} qubits hold all ${N} indices at once, each with amplitude 1/√${N} = ${a[0].toFixed(4)}; the chance of measuring a marked one is ${success[0].toFixed(4)}.`, { amps: amps[0], N, M }));
    for (let k = 1; k <= iterations; k++) {
      for (const i of marked) a[i] = -a[i];
      trace.push(step('oracle', `Iteration ${k}: the oracle flips the sign of the ${M === 1 ? 'marked amplitude' : M + ' marked amplitudes'}.`, { k, amps: Array.from(a) }));
      let mean = 0; for (let i = 0; i < N; i++) mean += a[i]; mean /= N;
      for (let i = 0; i < N; i++) a[i] = 2 * mean - a[i];
      amps.push(Array.from(a)); success.push(pMarked(a));
      trace.push(step('diffuse', `Reflect every amplitude about the mean ${mean.toFixed(4)}: marked amplitudes grow to ${a[[...marked][0]].toFixed(4)}; the chance of success is now ${success[k].toFixed(4)} (formula sin²(${2 * k + 1}θ) = ${(Math.sin((2 * k + 1) * theta) ** 2).toFixed(4)}).`, { k, mean, amps: amps[k], success: success[k] }));
    }
    trace.push(step('grover-done', `Best is ${best} iterations, about (π/4)·√(${N}/${M}). A classical search needs about ${((N + 1) / (M + 1)).toFixed(1)} guesses on average: the speed-up is quadratic, not exponential.`, { best, classical: (N + 1) / (M + 1) }));
    return { N, M, theta, best, amps, success, trace };
  };

  /** the period of x ↦ a^x mod N and the first values, by plain computation */
  Q.period = (a, N) => {
    const table = [1];
    let v = 1;
    for (let x = 1; x <= 4 * N; x++) { v = (v * a) % N; if (v === 1) return { r: x, table }; table.push(v); }
    return { r: null, table };
  };
  /** continued-fraction convergents of p/q */
  Q.convergents = (p, q) => {
    const out = [];
    let h0 = 0, h1 = 1, k0 = 1, k1 = 0, a = p, b = q;
    while (b) {
      const t = Math.floor(a / b);
      [h0, h1] = [h1, t * h1 + h0]; [k0, k1] = [k1, t * k1 + k0];
      out.push({ t, p: h1, q: k1 });
      [a, b] = [b, a - t * b];
    }
    return out;
  };
  /**
   * Shor's algorithm for a tiny N. The first register of t qubits (Q = 2^t ≥ N²) is put in superposition, a^x mod
   * N is computed into the second, and the quantum Fourier transform makes the first register peak near multiples
   * of Q/r. A measured y then gives r through the continued fraction of y/Q.
   */
  Q.shor = (N, opts = {}) => {
    const r0 = P.rng(opts.seed || 5), trace = [];
    if (N % 2 === 0) return { factors: [2, N / 2], trace: [step('even', `${N} is even: 2 is a factor, no quantum work needed.`, {})] };
    if (N > 1023) throw new Error('keep N below 1024: the simulation stores every amplitude');
    for (let b = 2; b < 11; b++) { const root = Math.round(N ** (1 / b)); for (const c of [root - 1, root, root + 1]) if (c > 1 && c ** b === N) return { factors: [c, N / c], trace: [step('power', `${N} = ${c}^${b}, a perfect power, found classically.`, {})] }; }
    const t = Math.ceil(Math.log2(N * N)), Qn = 2 ** t;
    for (let attempt = 0; attempt < 20; attempt++) {
      const a = opts.a && attempt === 0 ? opts.a : 2 + r0.int(N - 3);
      trace.push(step('choose', `Attempt ${attempt + 1}: choose a = ${a}.`, { a }));
      const g = gcd(a, N);
      if (g > 1) { trace.push(step('lucky', `gcd(${a}, ${N}) = ${g}: a shares a factor with N, found by luck.`, { g })); return { a, factors: [g, N / g], trace }; }
      const { r, table } = Q.period(a, N);
      trace.push(step('modexp', `The second register holds a^x mod ${N}: ${table.slice(0, 12).join(', ')}${table.length > 12 ? ', …' : ''}. It repeats every ${r} steps; this period is what the quantum part finds.`, { table, r }));
      // P(y) = Σ over the r cosets x₀ of |(1/Q) Σ_j e^{2πi (x₀ + j r) y / Q}|²: a sum of geometric series
      const probs = new Float64Array(Qn);
      for (let y = 0; y < Qn; y++) {
        const phi = (2 * Math.PI * r * y) / Qn, s = Math.sin(phi / 2);
        let p = 0;
        for (let x0 = 0; x0 < r; x0++) {
          const Mx = Math.ceil((Qn - x0) / r);
          p += Math.abs(s) < 1e-12 ? Mx * Mx : (Math.sin((Mx * phi) / 2) / s) ** 2;
        }
        probs[y] = p / (Qn * Qn);
      }
      trace.push(step('qft', `t = ${t} qubits, Q = ${Qn}. After the Fourier transform the first register peaks near multiples of Q/r = ${(Qn / r).toFixed(2)}.`, { Q: Qn, t, probs: Array.from(probs), peaks: Array.from({ length: r }, (_, j) => Math.round((j * Qn) / r)) }));
      let u = r0.next(), y = 0;
      while (y < Qn - 1 && u > probs[y]) u -= probs[y++];
      const cv = Q.convergents(y, Qn).filter((c) => c.q < N);
      trace.push(step('measure', `Measure y = ${y}; y/Q = ${y}/${Qn} ≈ ${(y / Qn).toFixed(5)}. Convergents with denominator below N: ${cv.map((c) => c.p + '/' + c.q).join(', ') || 'none'}.`, { y, convergents: cv }));
      let found = null;
      for (const c of cv) for (let mult = 1; mult * c.q <= N && !found; mult++) if (c.q && powmod(a, mult * c.q, N) === 1) found = mult * c.q;
      if (!found) { trace.push(step('retry', `No denominator is a period of a (y was unlucky); run the circuit again.`, {})); continue; }
      trace.push(step('period', `${a}^${found} ≡ 1 (mod ${N}), so r = ${found}.`, { r: found }));
      if (found % 2) { trace.push(step('odd', `r is odd, so a^(r/2) is not defined; choose another a.`, {})); continue; }
      const h = powmod(a, found / 2, N);
      if (h === N - 1) { trace.push(step('minus-one', `a^(r/2) ≡ −1 (mod ${N}), which gives only trivial factors; choose another a.`, {})); continue; }
      const f1 = gcd(h - 1, N), f2 = gcd(h + 1, N);
      trace.push(step('factor', `a^(r/2) = ${h}; gcd(${h} − 1, ${N}) = ${f1} and gcd(${h} + 1, ${N}) = ${f2}: ${N} = ${f1} × ${N / f1}.`, { h, f1, f2 }));
      return { a, r: found, Q: Qn, t, probs: Array.from(probs), y, convergents: cv, factors: [f1, N / f1], trace };
    }
    return { factors: null, trace };
  };

  /** what the two algorithms do to the usual primitives, in bits of security */
  Q.impact = () => [
    { primitive: 'AES-128', classical: 128, quantum: 64, note: 'Grover halves the exponent of key search; AES-256 keeps 128.' },
    { primitive: 'AES-256', classical: 256, quantum: 128, note: 'Doubling the key length undoes Grover.' },
    { primitive: 'SHA-256 preimage', classical: 256, quantum: 128, note: 'Grover again.' },
    { primitive: 'SHA-256 collision', classical: 128, quantum: 85, note: 'A quantum collision search in theory; its memory cost keeps 128 the practical figure.' },
    { primitive: 'RSA-2048', classical: 112, quantum: 0, note: 'Shor factors in polynomial time.' },
    { primitive: 'ECC P-256', classical: 128, quantum: 0, note: 'Shor solves discrete logarithms in any group, curves included.' },
    { primitive: 'ML-KEM-768', classical: 192, quantum: 192, note: 'No known quantum attack beyond small constant factors (category 3).' },
  ];
})(globalThis.Sifer = globalThis.Sifer || {});
