// The elliptic-curve discrete logarithm on toy curves: given G and Q = k·G, find k. Baby-step giant-step and
// Pollard's rho work on any group and cost about √n; Pohlig–Hellman splits a smooth order into its prime powers;
// Smart's attack solves an anomalous curve (#E = p) at once by lifting to the p-adic numbers. Each returns what a
// picture needs: the tables, the walk with its tail and cycle, the digits, the lifts.
//   S.ECC.dlog.bsgs(C, G, Q, n) -> {k, m, baby: [{j, P}], giant: [{i, P}], hit: {i, j}, ops, trace}
//   S.ECC.dlog.rho(C, G, Q, n, {seed}) -> {k, walk: [{P, a, b, part}], mu, lambda, floydSteps, restarts, trace}
//   S.ECC.dlog.pohligHellman(C, G, Q, n) -> {k, parts: [{q, e, digits, residue}], trace}
//   S.ECC.dlog.smart(C, G, Q) -> {k, psiG, psiQ, lift: {a, b}, trace}      C anomalous: #E(GF(p)) = p
(function (S) {
  'use strict';
  const E = (S.ECC = S.ECC || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const f = (v) => E.fmt(v), fp = (P) => E.fp(P);
  const key = (P) => (P ? P.x + ',' + P.y : 'O');

  const bsgs = (C, G, Q, n) => {
    n = B(n);
    const m = S.NT.isqrt(n - 1n) + 1n, trace = [], baby = [], giant = [], table = new Map();
    trace.push(step('plan', `Write k = i·m + j with m = ⌈√n⌉ = ${m}. Store the baby steps j·G for j < m; then walk Q − i·(m·G) until one lands in the table.`, { m, n }));
    let R = null;
    for (let j = 0n; j < m; j++) { if (!table.has(key(R))) table.set(key(R), j); baby.push({ j, P: R }); R = C.add(R, G); }
    trace.push(step('baby', `${m} baby steps stored: 0·G = O, 1·G = ${fp(G)}, 2·G = ${fp(baby[2] && baby[2].P)}, …`, { count: Number(m) }));
    const mG = C.mul(m, G), step_ = C.neg(mG);
    let Y = Q, ops = Number(m);
    for (let i = 0n; i <= m; i++) {
      giant.push({ i, P: Y });
      if (table.has(key(Y))) {
        const j = table.get(key(Y)), k = E.mod(i * m + j, n);
        trace.push(step('hit', `Giant step ${i}: Q − ${i}·${m}·G = ${fp(Y)} is baby step j = ${j}. So k = ${i}·${m} + ${j} = ${f(k)}.`, { i, j, k }));
        trace.push(step('cost', `${ops} group operations instead of up to ${f(n)} for trying every k.`, { ops }));
        return { k, m, baby, giant, hit: { i, j }, ops, trace };
      }
      Y = C.add(Y, step_); ops++;
    }
    trace.push(step('fail', 'No match: Q is not a multiple of G.', {}));
    return { k: null, m, baby, giant, hit: null, ops, trace };
  };

  /** a three-way walk: the partition of X (by x mod 3) decides X + G, 2X or X + Q, keeping X = a·G + b·Q */
  const rho = (C, G, Q, n, o = {}) => {
    n = B(n);
    const rnd = S.NT.seededRandom(o.seed || 1), old = S.NT.setRandom(rnd), trace = [];
    try {
      const part = (P) => (P ? Number(P.x % 3n) : 0);
      for (let restarts = 0; restarts < 20; restarts++) {
        let a = S.NT.randBelow(n), b = S.NT.randBelow(n), X = C.add(C.mul(a, G), C.mul(b, Q));
        const walk = [], seen = new Map();
        trace.push(step('start', `Start at X₀ = ${a}·G + ${b}·Q = ${fp(X)}. Each step looks at x mod 3: 0 → add G, 1 → double, 2 → add Q, so we always know X = a·G + b·Q.`, { a, b }));
        while (!seen.has(key(X))) {
          seen.set(key(X), walk.length);
          const pt = part(X);
          walk.push({ P: X, a, b, part: pt });
          if (pt === 0) { X = C.add(X, G); a = E.mod(a + 1n, n); }
          else if (pt === 1) { X = C.add(X, X); a = E.mod(2n * a, n); b = E.mod(2n * b, n); }
          else { X = C.add(X, Q); b = E.mod(b + 1n, n); }
        }
        const mu = seen.get(key(X)), lambda = walk.length - mu, first = walk[mu];
        const floydSteps = Math.max(lambda, Math.ceil(mu / lambda) * lambda);
        trace.push(step('collision', `After ${walk.length} steps the walk returns to X_${mu} = ${fp(X)}: a tail of ${mu} points and a cycle of ${lambda}, the shape of the letter ρ. Floyd's tortoise and hare, keeping only two points, meet after ${floydSteps} steps.`, { mu, lambda, floydSteps }));
        const db = E.mod(b - first.b, n);
        trace.push(step('equation', `Two ways to write one point: ${first.a}·G + ${first.b}·Q = ${a}·G + ${b}·Q, so (${first.a} − ${a}) = k·(${b} − ${first.b}) mod ${n}.`, { a1: first.a, b1: first.b, a2: a, b2: b }));
        if (db === 0n) { trace.push(step('restart', 'The b values agree, so the equation says nothing about k: restart from a new random point.', {})); continue; }
        const k = E.mod((first.a - a) * E.inv(db, n), n);
        trace.push(step('solve', `k = (${first.a} − ${a}) · (${b} − ${first.b})⁻¹ mod ${n} = ${f(k)}.`, { k }));
        return { k, walk, mu, lambda, floydSteps, restarts, trace };
      }
      return { k: null, walk: [], trace };
    } finally { S.NT.setRandom(old); }
  };

  const pohligHellman = (C, G, Q, n) => {
    n = B(n);
    const factors = [...S.NT.factor(n)], trace = [], parts = [];
    trace.push(step('factor', `n = ${factors.map(([q, e]) => (e > 1 ? `${q}^${e}` : q)).join(' · ')}: find k modulo each prime power, then glue with the CRT.`, { factors: factors.map(([q, e]) => ({ q, e })) }));
    for (const [q, e] of factors) {
      const G0 = C.mul(n / q, G), digits = [];
      let kq = 0n, qj = 1n;
      for (let j = 0; j < e; j++) {
        const Qj = C.mul(n / (qj * q), C.sub(Q, C.mul(kq, G)));
        let dgt = null, R = null;
        for (let t = 0n; t < q; t++) { if (C.eq(R, Qj)) { dgt = t; break; } R = C.add(R, G0); }
        if (dgt == null) throw new Error('Q is not in the group generated by G');
        digits.push(dgt);
        trace.push(step('digit', `Mod ${q}^${e}, digit ${j}: (n/${q}^${j + 1})·(Q − ${kq}·G) = ${fp(Qj)} = ${dgt}·${fp(G0)}, where ${fp(G0)} = (n/${q})·G has order ${q}.`, { q, j, digit: dgt, Qj, G0 }));
        kq += dgt * qj; qj *= q;
      }
      parts.push({ q, e, digits, residue: kq, modulus: qj });
      trace.push(step('residue', `k ≡ ${kq} (mod ${qj}), from the base-${q} digits ${digits.join(', ')} (least significant first).`, { q, e, residue: kq, modulus: qj }));
    }
    const crt = S.NT.crt(parts.map((x) => x.residue), parts.map((x) => x.modulus));
    trace.push(step('crt', `The CRT combines ${parts.map((x) => `k ≡ ${x.residue} (mod ${x.modulus})`).join(', ')} into k = ${f(crt.x)}. Work: about ${parts.reduce((s, x) => s + x.e * Number(x.q), 0)} small steps instead of ${f(n)}.`, { k: crt.x }));
    return { k: crt.x, parts, crt, trace };
  };

  /** Smart's attack: lift the curve and both points to Z/p², multiply by p, and read off the p-adic elliptic log */
  const smart = (C, G, Q) => {
    const p = C.p, M = p * p, m = (v) => E.mod(v, M), trace = [];
    trace.push(step('anomalous', `#E = p = ${p}: the curve is anomalous. Multiplying by p sends every lifted point into the kernel of reduction, where the logarithm is just a division.`, { p }));
    const addM = (P, R, A) => {
      if (!P) return R; if (!R) return P;
      let l;
      if (E.mod(P.x - R.x, p) === 0n) {
        if (E.mod(P.y - R.y, p) !== 0n) return null;
        l = m((3n * P.x * P.x + A) * E.inv(2n * P.y, M));
      } else l = m((R.y - P.y) * E.inv(R.x - P.x, M));
      const x = m(l * l - P.x - R.x);
      return { x, y: m(l * (P.x - x) - P.y) };
    };
    const psi = (P, A) => {
      let R = null, T = P, k = p - 1n;
      while (k > 0n) { if (k & 1n) R = addM(R, T, A); T = addM(T, T, A); k >>= 1n; }
      const dx = m(P.x - R.x), dy = m(P.y - R.y);
      return E.mod((dx / p) * E.inv(dy, p), p);
    };
    for (let t = 1n; t < 50n; t++) {
      const A = m(C.a + p * t), Bv = m(G.y * G.y - G.x * G.x * G.x - A * G.x);
      const r = m(Q.x * Q.x * Q.x + A * Q.x + Bv), delta = E.mod(((r - Q.y * Q.y) / p) * E.inv(2n * Q.y, p), p);
      const Gh = { x: G.x, y: G.y }, Qh = { x: Q.x, y: m(Q.y + p * delta) };
      const pG = psi(Gh, A), pQ = psi(Qh, A);
      trace.push(step('lift', `Lift to y² = x³ + ${A}x + ${Bv} over Z/${M}: Ĝ = ${fp(Gh)}, Q̂ = ${fp(Qh)} (Hensel's lemma adjusts y of Q).`, { a: A, b: Bv, G: Gh, Q: Qh }));
      trace.push(step('psi', `p·Ĝ and p·Q̂ reduce to O; their p-adic logs (−x/y, divided by p) are ψ(G) = ${pG} and ψ(Q) = ${pQ} (mod ${p}).`, { psiG: pG, psiQ: pQ }));
      if (pG === 0n) { trace.push(step('retry', 'ψ(G) is 0: this lift is the canonical one, which hides the logarithm. Try another lift.', {})); continue; }
      const k = E.mod(pQ * E.inv(pG, p), p);
      trace.push(step('solve', `k = ψ(Q) / ψ(G) mod p = ${k}: one division, no search.`, { k }));
      return { k, psiG: pG, psiQ: pQ, lift: { a: A, b: Bv }, trace };
    }
    return { k: null, trace };
  };

  E.dlog = { bsgs, rho, pohligHellman, smart };
})(globalThis.Sifer = globalThis.Sifer || {});
