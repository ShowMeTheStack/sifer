// Attacks on careless elliptic-curve code, each recovering a planted key:
//  - ECDSA nonce reuse: two signatures with the same k give k, then d, by two divisions;
//  - the invalid-curve attack: a victim who never checks that a point is on its curve computes d·Q on whatever curve
//    Q lies on (the formulas never use b), so points of small order on y² = x³ + ax + b′ leak d mod small primes;
//  - the twist attack on an x-only Montgomery ladder: any u is accepted, and a u on the quadratic twist leaks d
//    modulo the small factors of the twist's order.
//   S.ECC.attacks.nonceReuse(C, sig1, sig2[, Q]) -> {k, d, ok, trace}      sig = {r, s, e} (e the hashed message)
//   S.ECC.attacks.nonceReuseDemo(C, {seed}) -> {d, sigs, result}
//   S.ECC.attacks.invalidCurve(C, d, {seed}) -> {d: recovered, queries: [{b, order, l, Q, residue}], crt, trace}
//   S.ECC.attacks.MONT_TOY = {p: 10037, A: 55}: 4·2549 points, twist of order 9880 = 2³·5·13·19
//   S.ECC.attacks.montLadder(p, A, k, u) -> u of k·P or null for O (x-only; works on the curve and on its twist)
//   S.ECC.attacks.twist(d, {seed}) -> {d, candidates: [d, q − d] (equivalent keys), queries, base, pubU, trace}
(function (S) {
  'use strict';
  const E = (S.ECC = S.ECC || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const f = (v) => E.fmt(v), fp = (P) => E.fp(P);
  const withSeed = (seed, fn) => { const old = S.NT.setRandom(S.NT.seededRandom(seed || 1)); try { return fn(); } finally { S.NT.setRandom(old); } };

  const nonceReuse = (C, s1, s2, Q) => {
    const n = C.n, trace = [];
    const r = BigInt(s1.r);
    if (BigInt(s2.r) !== r) return { k: null, d: null, ok: false, trace: [step('different-r', 'The two signatures have different r, so their nonces differ: this attack does not apply.', {})] };
    trace.push(step('spot', `Both signatures have r = ${f(r)}. Since r is the x-coordinate of k·G, the same k signed both messages.`, { r }));
    trace.push(step('equations', `s₁·k = e₁ + r·d and s₂·k = e₂ + r·d (mod n). Subtract: (s₁ − s₂)·k = e₁ − e₂.`, {}));
    // with low-s normalisation one s may have been negated: try both signs
    for (const sg of [1n, -1n]) {
      const t1 = BigInt(s1.s), t2 = E.mod(sg * BigInt(s2.s), n), ds = E.mod(t1 - t2, n);
      if (ds === 0n) continue;
      const k = E.mod((BigInt(s1.e) - BigInt(s2.e)) * E.inv(ds, n), n);
      const d = E.mod((t1 * k - BigInt(s1.e)) * E.inv(r, n), n);
      const ok = Q ? C.eq(C.mul(d, C.G), Q) : true;
      if (!ok) continue;
      trace.push(step('k', `k = (e₁ − e₂) / (s₁ − ${sg < 0n ? '(−s₂)' : 's₂'}) mod n = ${f(k)}.`, { k }));
      trace.push(step('d', `d = (s₁·k − e₁) / r mod n = ${f(d)}.`, { d }));
      if (Q) trace.push(step('check', `d·G = ${fp(Q)}, the public key: the private key is recovered.`, { ok }));
      return { k, d, ok, trace };
    }
    trace.push(step('fail', 'No consistent key: the signatures do not share a nonce.', {}));
    return { k: null, d: null, ok: false, trace };
  };
  const nonceReuseDemo = (C, o = {}) => withSeed(o.seed, () => {
    const { d, Q } = E.keygen(C), k = 1n + S.NT.randBelow(C.n - 1n);
    const msgs = ['Pay the cafeteria 40 credits', 'Pay the bookshop 75 credits'].map((m) => S.bytes.utf8(m));
    const sigs = msgs.map((m) => { const g = E.ecdsa.sign(C, d, m, { k }); return { r: g.r, s: g.s, e: g.e, msg: m }; });
    return { d, Q, k, sigs, result: nonceReuse(C, sigs[0], sigs[1], Q) };
  });

  /** a point of order exactly q^e on curve D, or null */
  const pointOfOrder = (D, N, q, e) => {
    const qe = q ** BigInt(e), cof = N / qe;
    for (let tries = 0; tries < 200; tries++) {
      const x = S.NT.randBelow(D.p), y = D.sqrt(D.rhs(x));
      if (y == null) continue;
      const P = D.mul(cof, { x, y });
      if (P && D.mul(qe / q, P)) return P;
    }
    return null;
  };

  const invalidCurve = (C, d, o = {}) => withSeed(o.seed, () => {
    d = BigInt(d);
    const trace = [], queries = [], residues = [], moduli = [], used = new Set();
    // the victim: d·Q with formulas that never use b, and a tag over the result so the attacker can test guesses
    const tag = (P) => (P ? P.x * 1000003n + P.y : -1n);
    const victim = (Q) => tag(C.mul(d, Q));
    trace.push(step('victim', `The victim computes d·Q for any Q it is sent and never checks that Q is on y² = x³ + ${C.a}x + ${C.b}. The addition and doubling formulas use a but not b, so for a point on y² = x³ + ${C.a}x + b′ it silently computes on that curve instead.`, {}));
    let M = 1n;
    for (let bp = 1n; bp < C.p && M <= C.n; bp++) {
      if (bp === C.b) continue;
      let D; try { D = E.curve({ p: C.p, a: C.a, b: bp }); } catch { continue; }
      const N = D.count().N;
      for (const [q, e] of S.NT.factor(N)) {
        if (q > 400n || used.has(q)) continue;
        const P = pointOfOrder(D, N, q, 1);
        if (!P) continue;
        used.add(q);
        const t0 = victim(P);
        let res = null, R = null;
        for (let t = 0n; t < q; t++) { if (tag(R) === t0) { res = t; break; } R = D.add(R, P); }
        queries.push({ b: bp, order: N, l: q, Q: P, residue: res });
        residues.push(res); moduli.push(q); M *= q;
        trace.push(step('query', `On y² = x³ + ${C.a}x + ${bp} (${N} points) send Q = ${fp(P)} of order ${q}. The victim's answer matches t·Q for t = ${res}, so d ≡ ${res} (mod ${q}).`, { b: bp, order: N, l: q, Q: P, residue: res }));
        if (M > C.n) break;
      }
    }
    const crt = S.NT.crt(residues, moduli), rec = E.mod(crt.x, M);
    trace.push(step('crt', `${queries.length} queries; the product of the moduli is ${f(M)} > n = ${f(C.n)}, so the CRT gives d = ${f(rec)} outright.`, { d: rec, M }));
    trace.push(step('defence', 'The defence is one line: reject any point that is not on the curve (and, with a cofactor, not in the right subgroup) before multiplying.', {}));
    return { d: rec, queries, crt, trace };
  });

  // ---- x-only Montgomery ladder and the twist attack
  const MONT_TOY = { p: 10037n, A: 55n };
  const montLadder = (p, A, k, u) => {
    const m = (v) => E.mod(v, p), a24 = m((A - 2n) * E.inv(4n, p));
    let x2 = 1n, z2 = 0n, x3 = m(u), z3 = 1n;
    for (let t = E.bitLength(k) - 1; t >= 0; t--) {
      if ((k >> BigInt(t)) & 1n) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
      const Aa = m(x2 + z2), AA = m(Aa * Aa), Bb = m(x2 - z2), BB = m(Bb * Bb), Ee = m(AA - BB);
      const Cc = m(x3 + z3), Dd = m(x3 - z3), DA = m(Dd * Aa), CB = m(Cc * Bb);
      x3 = m((DA + CB) ** 2n); z3 = m(u * (DA - CB) ** 2n); x2 = m(AA * BB); z2 = m(Ee * (AA + a24 * Ee));
      if ((k >> BigInt(t)) & 1n) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    }
    return z2 === 0n ? null : m(x2 * E.inv(z2, p));
  };
  const twist = (d, o = {}) => withSeed(o.seed, () => {
    const { p, A } = MONT_TOY, F = E.forms.make(p, A, 1n), N = F.weier.count().N, q = N / 4n, T = 2n * p + 2n - N;
    d = BigInt(d);
    const trace = [], queries = [];
    const rhs = (u) => E.mod(u * u * u + A * u * u + u, p);
    const onTwist = (u) => S.NT.pow(rhs(u), (p - 1n) / 2n, p) === p - 1n;
    trace.push(step('setup', `The curve v² = u³ + ${A}u² + u over GF(${p}) has ${N} = 4·${q} points, but the victim's ladder only ever sees u. A u for which u³ + Au² + u is not a square lies on the quadratic twist, which has ${T} = ${[...S.NT.factor(T)].map(([a, e]) => (e > 1 ? a + '^' + e : a)).join('·')} points.`, { N, q, T }));
    const victim = (u) => montLadder(p, A, d, u);
    const residues = [], moduli = [];
    for (const [l, e0] of S.NT.factor(T)) {
      let u = null, le = 1n;
      // the l-part of the twist need not be cyclic: take the largest l-power order that a point actually has
      for (let e = e0; e >= 1 && u == null; e--) {
        le = l ** BigInt(e);
        for (let i = 0; i < 300 && u == null; i++) {
          const c = S.NT.randBelow(p);
          if (!onTwist(c)) continue;
          const v = montLadder(p, A, T / l ** BigInt(e0), c);
          if (v == null) continue;
          let ord = 1n, x = v;
          while (x != null) { x = montLadder(p, A, l, x); ord *= l; }
          if (ord >= le) u = montLadder(p, A, ord / le, v);
        }
      }
      if (u == null) continue;
      const ans = victim(u);
      let res = null;
      for (let t = 0n; t <= le / 2n; t++) { if (montLadder(p, A, t, u) === ans) { res = t; break; } }
      queries.push({ u, order: le, residue: res });
      residues.push(res); moduli.push(le);
      trace.push(step('query', `Send u = ${u}, a twist point of order ${le}. The answer is the u of t·P for t = ${res ? "±" + res : 0}, so d ≡ ${res ? "±" + res : 0} (mod ${le}).`, { u, order: le, residue: res }));
    }
    // x-only answers fix each residue only up to sign: try the combinations against the public key
    let B0 = null;
    for (const P of F.mont.points()) { const R = montLadder(p, A, 4n, P.u); if (R != null && montLadder(p, A, q, R) == null) { B0 = R; break; } }
    const pubU = montLadder(p, A, d, B0), M = moduli.reduce((x, y) => x * y, 1n), found = new Set();
    for (let mask = 0; mask < 1 << residues.length; mask++) {
      const rs = residues.map((r, i) => ((mask >> i) & 1 ? E.mod(-r, moduli[i]) : r));
      for (let x = S.NT.crt(rs, moduli).x; x < q; x += M) if (montLadder(p, A, x, B0) === pubU) found.add(x);
    }
    const candidates = [...found].sort((x, y) => (x < y ? -1 : 1));
    trace.push(step('signs', `${1 << residues.length} sign choices, each glued by the CRT modulo ${M}${M < q ? ` and stepped by ${M} up to ${q}` : ''}; those that reproduce the public u = ${pubU} give d ∈ {${candidates.join(', ')}} (mod ${q}). An x-only key cannot tell d from −d, and both give the same shared secrets, so either one is the key.`, { candidates, M }));
    trace.push(step('defence', 'X25519 is safe against this because the twist of Curve25519 also has a large prime factor and the scalar is clamped to a multiple of the cofactor; a toy curve with a smooth twist is not.', {}));
    return { d: candidates[0] ?? null, q, base: B0, pubU, queries, candidates, trace };
  });

  E.attacks = Object.assign(E.attacks || {}, { nonceReuse, nonceReuseDemo, invalidCurve, pointOfOrder, MONT_TOY, montLadder, twist });
})(globalThis.Sifer = globalThis.Sifer || {});
