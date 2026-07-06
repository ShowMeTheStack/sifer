// Solving the discrete logarithm log_g(h) in a cyclic group, every method traced and working on any group object from
// pk-dlp.js (so a toy group and Z_p* share the code). The baby-step giant-step table, Pollard's rho with Floyd's two
// pointers (the walk's points are returned so a page can draw the ρ shape), Pohlig–Hellman splitting the order into its
// prime-power parts and recombining by CRT, a small index-calculus demonstration over Z_p*, and a small-subgroup
// confinement attack that leaks the static secret of a careless Diffie–Hellman party one prime factor at a time.
//   S.DLP.attack.bsgs(group, h[, {n}]) -> {x, m, babySteps: Map, giantSteps: [...], trace}
//   S.DLP.attack.rho(group, h[, {n}]) -> {x, iterations, tortoise: [...], hare: [...], meeting, trace}
//   S.DLP.attack.pohligHellman(group, h[, {factors}]) -> {x, parts: [{q, e, residue}], crt, trace}
//   S.DLP.attack.indexCalculus(p, g, h[, {bound}]) -> {x, factorBase, relations, logs, trace}
//   S.DLP.attack.smallSubgroup({p, g, staticPub, oracle}) -> {secret, parts, trace}   oracle(point) -> shared^? test
//   S.DLP.labs.<name>(seed[, opts]) -> a planted logarithm and the public data
(function (S) {
  'use strict';
  const N = () => S.NT;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const sh = (v) => N().short(v);
  const D = (S.DLP = S.DLP || {});
  const A = (D.attack = {});
  const L = (D.labs = {});
  const seeded = (seed, fn) => { const old = N().setRandom(N().seededRandom(seed)); try { return fn(); } finally { N().setRandom(old); } };

  /** baby-step giant-step: tabulate g^j for j < m = ⌈√n⌉, then step by g^(−m) until a giant step hits the table */
  A.bsgs = (group, h, opts = {}) => {
    const g = group.generator, n = B(opts.n || group.generatorOrder || group.order);
    const m = N().isqrt(n - 1n) + 1n, trace = [];
    trace.push(step('start', `Solve g^x = ${group.str(h)} in ${group.name}, order n = ${sh(n)}. Write x = i·m + j with m = ⌈√n⌉ = ${sh(m)}; then g^j = h·(g^−m)^i.`, { n, m }));
    const baby = new Map();
    let cur = group.id;
    for (let j = 0n; j < m; j++) { baby.set(group.str(cur), j); cur = group.op(cur, g); }
    trace.push(step('baby', `Baby steps: ${sh(m)} values g^0, g^1, …, g^${sh(m - 1n)} stored in a table.`, { count: m }));
    const factor = group.pow(group.inv(g), m); // g^(−m)
    let gamma = h;
    for (let i = 0n; i < m; i++) {
      const key = group.str(gamma);
      if (baby.has(key)) {
        const j = baby.get(key), x = N().mod(i * m + j, n);
        trace.push(step('match', `Giant step ${sh(i)}: h·(g^−m)^${sh(i)} = ${key} is g^${sh(j)} in the table, so x = ${sh(i)}·${sh(m)} + ${sh(j)} = ${sh(x)}.`, { i, j, x }));
        return { x, m, babySteps: baby, giantSteps: Number(i) + 1, trace };
      }
      gamma = group.op(gamma, factor);
    }
    trace.push(step('fail', 'No giant step matched: h is not a power of g, or n is wrong.'));
    return { x: null, m, babySteps: baby, trace };
  };

  /** Pollard's rho: a pseudo-random walk x_{i+1} = f(x_i) that also tracks the exponents (a, b) with x = g^a·h^b;
   *  Floyd's tortoise and hare meet inside the cycle, giving a·? ≡ b·? and hence the logarithm. */
  A.rho = (group, h, opts = {}) => {
    const g = group.generator, n = B(opts.n || group.generatorOrder || group.order), trace = [];
    const part = (P) => Number(B(group.str(P)) % 3n);
    const f = (P, a, b) => {
      switch (part(P)) {
        case 0: return [group.op(P, h), a, N().mod(b + 1n, n)];
        case 1: return [group.op(P, P), N().mod(2n * a, n), N().mod(2n * b, n)];
        default: return [group.op(P, g), N().mod(a + 1n, n), b];
      }
    };
    trace.push(step('start', `Pollard's rho for g^x = ${group.str(h)}, order ${sh(n)}: a walk whose steps multiply by g, by h, or square, tracking x = g^a·h^b.`, { n }));
    const limit = opts.limit || Number(n < 1000000n ? n : 2000000n);
    const restarts = opts.restarts || 40;
    for (let attempt = 0; attempt <= restarts; attempt++) {
      // start away from the identity (a fixed point of the squaring branch): a0 = 1 + attempt, b0 = attempt
      let a0 = N().mod(1n + BigInt(attempt), n), b0 = N().mod(BigInt(attempt), n);
      let start = group.op(group.pow(g, a0), group.pow(h, b0));
      let [X, a1, b1] = [start, a0, b0], [Y, a2, b2] = [start, a0, b0];
      const tortoise = [{ P: group.str(X), a: a1, b: b1 }], hare = [{ P: group.str(Y), a: a2, b: b2 }];
      for (let i = 1; i <= limit; i++) {
        [X, a1, b1] = f(X, a1, b1);
        [Y, a2, b2] = f(...f(Y, a2, b2));
        if (tortoise.length < 4000) { tortoise.push({ P: group.str(X), a: a1, b: b1 }); hare.push({ P: group.str(Y), a: a2, b: b2 }); }
        if (group.eq(X, Y)) {
          const r = N().mod(b1 - b2, n), base = N().mod(a2 - a1, n);
          if (r !== 0n) {
            const d = N().gcd(r, n);
            if (d === 1n) {
              const x = N().mod(base * N().inv(r, n), n);
              if (group.eq(group.pow(g, x), h)) { trace.push(step('collision', `After ${i} steps the pointers meet at ${group.str(X)}: g^${sh(a1)}·h^${sh(b1)} = g^${sh(a2)}·h^${sh(b2)}, so (b1 − b2)·x ≡ a2 − a1 (mod ${sh(n)}) and x = ${sh(x)}.`, { i, a1, b1, a2, b2 })); return { x, iterations: i, tortoise, hare, meeting: group.str(X), attempts: attempt + 1, trace }; }
            } else if (base % d === 0n) {
              const step0 = N().mod((base / d) * N().inv(r / d, n / d), n / d);
              for (let t = 0n; t < d; t++) { const cand = N().mod(step0 + t * (n / d), n); if (group.eq(group.pow(g, cand), h)) { trace.push(step('collision', `A collision after ${i} steps; gcd(b1 − b2, n) = ${sh(d)} leaves ${sh(d)} candidates, of which x = ${sh(cand)} is the logarithm.`, { i, x: cand })); return { x: cand, iterations: i, tortoise, hare, meeting: group.str(X), attempts: attempt + 1, trace }; } }
            }
          }
          break; // degenerate collision: restart from a fresh starting point
        }
      }
      if (attempt < restarts) trace.push(step('restart', `The walk gave a collision that revealed nothing (or ran its length); restart ${attempt + 1} from a new point.`, { attempt: attempt + 1 }));
    }
    trace.push(step('fail', `No useful collision within ${restarts + 1} attempts.`));
    return { x: null, trace };
  };

  /** Pohlig–Hellman: in a group of order n = Π q^e, find x mod each q^e (digit by digit in base q), then CRT */
  A.pohligHellman = (group, h, opts = {}) => {
    const g = group.generator, n = B(opts.n || group.generatorOrder || group.order);
    const factors = opts.factors ? new Map([...opts.factors].map(([q, e]) => [B(q), e])) : N().factor(n), trace = [];
    trace.push(step('start', `n = ${N().fmtFactors(factors)}. Find x modulo each prime power, then glue the pieces with the Chinese remainder theorem.`, { factors: [...factors] }));
    const parts = [], residues = [], moduli = [];
    for (const [q, e] of factors) {
      const pe = q ** BigInt(e);
      // the order-q subgroup: solve one base-q digit at a time
      const gq = group.pow(g, n / q); // generator of the order-q subgroup
      let x = 0n, gamma = group.id;
      for (let k = 0; k < e; k++) {
        const exp = n / q ** BigInt(k + 1);
        const target = group.pow(group.op(h, group.inv(group.pow(g, x))), exp); // (h·g^−x)^(n/q^{k+1})
        // small discrete log of `target` to base gq, in a group of order q
        let dk = 0n, cur = group.id;
        while (!group.eq(cur, target)) { cur = group.op(cur, gq); dk++; if (dk > q) { dk = null; break; } }
        if (dk == null) { trace.push(step('fail', `No digit found for the prime ${sh(q)}: h is not in ⟨g⟩.`)); return { x: null, trace }; }
        x += dk * q ** BigInt(k);
        trace.push(step('digit', `Prime ${sh(q)}, digit ${k}: the order-${sh(q)} logarithm is ${sh(dk)}, so x ≡ ${sh(x)} (mod ${sh(q ** BigInt(k + 1))}).`, { q, k, digit: dk, x }));
      }
      parts.push({ q, e, residue: x, modulus: pe });
      residues.push(x); moduli.push(pe);
    }
    const crt = N().crt(residues, moduli);
    trace.push(step('crt', `Combining ${parts.map((p) => `x ≡ ${sh(p.residue)} (mod ${sh(p.modulus)})`).join(', ')} gives x = ${sh(crt.x)}.`, { x: crt.x }));
    return { x: crt.x, parts, crt, trace };
  };

  /** a small index calculus over Z_p*: find relations log of small primes, then log_g(h) from one more relation */
  A.indexCalculus = (p, g, h, opts = {}) => {
    p = B(p); g = B(g); h = B(h);
    const n = p - 1n, bound = opts.bound || 29;
    const base = N().SMALL_PRIMES.filter((q) => q <= bound).map(BigInt), trace = [];
    trace.push(step('start', `Index calculus in Z_${sh(p)}*: use the factor base of primes up to ${bound} (${base.map(String).join(', ')}). Collect g^k that factor entirely over it.`, { bound, base }));
    const smooth = (v) => { const exps = new Array(base.length).fill(0n); let m = v; for (let i = 0; i < base.length; i++) { while (m % base[i] === 0n) { m /= base[i]; exps[i]++; } } return m === 1n ? exps : null; };
    const rows = []; // each: {k, exps}
    let need = base.length + (opts.extra || 8), logs = null;
    // gather relations and solve; if the system is rank-deficient, gather a few more rows and try again
    for (let round = 0; round < 12 && !logs; round++, need += Math.max(4, base.length >> 1)) {
      for (let tries = 0; rows.length < need && tries < 500000; tries++) {
        const k = 1n + N().randBelow(n - 1n), e = smooth(N().pow(g, k, p));
        if (e) { rows.push({ k, exps: e }); if (rows.length <= 8) trace.push(step('relation', `g^${sh(k)} ≡ ${base.map((q, i) => (e[i] ? `${q}^${e[i]}` : '')).filter(Boolean).join('·')} (mod ${sh(p)}).`, { k, exps: e })); }
      }
      // solve the linear system for log_g(base[i]) modulo n by Gaussian elimination over Z_n (non-invertible pivots are handled by CRT on the prime-power parts of n)
      logs = solveModLinear(rows.map((r) => r.exps.concat([r.k])), base.length, n);
    }
    if (!logs) { trace.push(step('fail', 'Not enough independent relations; try a larger factor base.')); return { x: null, factorBase: base, relations: rows, trace }; }
    trace.push(step('system', `${rows.length} relations give a solvable system for the logarithms of the ${base.length} factor-base primes.`, { relations: rows.length }));
    base.forEach((q, i) => trace.push(step('log', `log_g(${q}) = ${sh(logs[i])}.`, { q, log: logs[i] })));
    // one more relation involving h: h·g^k smooth
    for (let tries = 0; tries < 200000; tries++) {
      const k = N().randBelow(n), e = smooth((h * N().pow(g, k, p)) % p);
      if (e) {
        let x = N().mod(-k, n);
        for (let i = 0; i < base.length; i++) x = N().mod(x + e[i] * logs[i], n);
        if (N().pow(g, x, p) === N().mod(h, p)) { trace.push(step('solve', `h·g^${sh(k)} is smooth, so log_g(h) = (Σ e_i·log_g(p_i)) − ${sh(k)} = ${sh(x)}.`, { k, x })); return { x, factorBase: base, relations: rows, logs, trace }; }
      }
    }
    trace.push(step('fail', 'Could not relate h to the factor base.'));
    return { x: null, factorBase: base, relations: rows, logs, trace };
  };
  /** Gaussian elimination of an (rows × vars+1) system over Z_n, returning the vars, or null if underdetermined */
  function solveModLinear(aug, vars, n) {
    const pf = N().factor(n);
    // solve modulo each prime power and CRT the variable vectors
    const perPrime = [];
    for (const [q, e] of pf) {
      const pe = q ** BigInt(e);
      const sol = solveModPrimePower(aug, vars, pe, q);
      if (!sol) return null;
      perPrime.push({ pe, sol });
    }
    const out = [];
    for (let v = 0; v < vars; v++) out.push(N().crt(perPrime.map((p) => p.sol[v]), perPrime.map((p) => p.pe)).x);
    return out;
  }
  function solveModPrimePower(aug, vars, pe, q) {
    const M = aug.map((r) => r.map((v) => N().mod(v, pe)));
    const rows = M.length;
    let r = 0;
    const where = new Array(vars).fill(-1);
    for (let c = 0; c < vars && r < rows; c++) {
      // find a pivot whose entry is a unit mod q (hence invertible mod pe)
      let piv = -1;
      for (let i = r; i < rows; i++) if (M[i][c] % q !== 0n) { piv = i; break; }
      if (piv < 0) continue;
      [M[r], M[piv]] = [M[piv], M[r]];
      const inv = N().inv(M[r][c], pe);
      M[r] = M[r].map((v) => N().mod(v * inv, pe));
      for (let i = 0; i < rows; i++) if (i !== r && M[i][c] !== 0n) { const f = M[i][c]; M[i] = M[i].map((v, j) => N().mod(v - f * M[r][j], pe)); }
      where[c] = r; r++;
    }
    const out = new Array(vars).fill(0n);
    for (let c = 0; c < vars; c++) { if (where[c] < 0) return null; out[c] = M[where[c]][vars]; }
    return out;
  }

  /**
   * Small-subgroup confinement: a party reuses a static secret x and computes shared = (received point)^x without
   * checking the point's order. The attacker sends points of small prime order q_i | p − 1; an oracle tells whether a
   * guess for shared^... matches, which reveals x mod q_i. CRT over enough small factors (or a final BSGS for the
   * rest) recovers x. The oracle here is oracle(point, guessExponent) -> boolean: whether point^x equals point^guess.
   */
  A.smallSubgroup = ({ p, g, order, oracle, factors, maxFactor = 100000 }) => {
    p = B(p); g = B(g); const n = B(order || p - 1n), trace = [];
    const pf = factors ? new Map([...factors].map(([q, e]) => [B(q), e])) : N().factor(n);
    trace.push(step('start', `The victim computes point^x with a fixed x and never checks the point. p − 1 = ${N().fmtFactors(pf)}; send points of small prime order and read x modulo each.`, { factors: [...pf] }));
    const residues = [], moduli = [];
    let covered = 1n;
    for (const [q] of pf) {
      if (q > BigInt(maxFactor)) { trace.push(step('skip', `The prime ${sh(q)} is too large to brute force; stop here.`, { q })); break; }
      const elt = N().pow(g, (p - 1n) / q, p); // a point of order q
      let r = -1n;
      for (let t = 0n; t < q; t++) if (oracle(elt, t)) { r = t; break; }
      if (r < 0n) { trace.push(step('skip', `No residue found modulo ${sh(q)}.`, { q })); continue; }
      residues.push(r); moduli.push(q); covered *= q;
      trace.push(step('residue', `A point of order ${sh(q)}: the oracle says point^x = point^${sh(r)}, so x ≡ ${sh(r)} (mod ${sh(q)}).`, { q, residue: r }));
    }
    const crt = N().crt(residues, moduli);
    trace.push(step('crt', `x ≡ ${sh(crt.x)} modulo ${sh(covered)} (the product of the small primes handled).`, { x: crt.x, modulus: covered }));
    return { secret: crt.x, modulus: covered, parts: residues.map((r, i) => ({ q: moduli[i], residue: r })), crt, trace };
  };

  // ---- labs
  L.dlog = (seed, opts = {}) => seeded(seed, () => {
    const bits = opts.bits || 28;
    let p; do { p = N().randomPrime(bits).prime; } while (p < 11n);
    const group = D.groupZp(p), x = group.randomExponent(), h = group.pow(group.generator, x);
    return { secret: { x }, group, public: { h } };
  });
  /** a group whose order is a product of small primes (smooth), for Pohlig–Hellman */
  L.smooth = (seed, opts = {}) => seeded(seed, () => {
    const primes = N().SMALL_PRIMES.filter((q) => q >= 3 && q < (opts.cap || 60));
    let order = 1n, used = [];
    while (order < BigInt(opts.minOrder || 1e7)) { const q = BigInt(primes[Number(N().randBelow(BigInt(primes.length)))]); order *= q; used.push(q); }
    // find a prime p with (p − 1) a multiple of `order`
    let k = 2n, p;
    for (;;) { p = order * k + 1n; if (N().isProbablePrime(p)) break; k++; }
    const group = D.groupZp(p), x = group.randomExponent(), h = group.pow(group.generator, x);
    return { secret: { x }, group, public: { h }, order: p - 1n };
  });
  L.indexCalculus = (seed, opts = {}) => seeded(seed, () => {
    const bits = opts.bits || 24;
    let p; do { p = N().randomPrime(bits).prime; } while (p < 100000n);
    const group = D.groupZp(p), g = group.generator, x = group.randomExponent(), h = group.pow(g, x);
    return { secret: { x }, public: { p, g, h } };
  });
  L.smallSubgroup = (seed, opts = {}) => seeded(seed, () => {
    // build p = 2·q1·q2·…·qk + 1 with distinct small primes, a static secret x
    const small = N().SMALL_PRIMES.filter((q) => q >= 3 && q < (opts.cap || 50));
    for (let attempt = 0; ; attempt++) {
      const chosen = [], seen = new Set();
      let prod = 2n;
      while (chosen.length < (opts.k || 5)) { const q = small[Number(N().randBelow(BigInt(small.length)))]; if (seen.has(q)) continue; seen.add(q); chosen.push(BigInt(q)); prod *= BigInt(q); }
      const p = prod + 1n;
      if (!N().isProbablePrime(p)) continue;
      const g = D.groupZp(p).generator, x = 1n + N().randBelow(p - 2n);
      const oracle = (point, guess) => N().pow(point, x, p) === N().pow(point, guess, p);
      return { secret: { x }, public: { p, g, order: p - 1n, oracle }, factors: N().factor(p - 1n) };
    }
  });
})(globalThis.Sifer = globalThis.Sifer || {});
