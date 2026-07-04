// Attacks on RSA, each a lab: a planting function makes a scenario from a seed (so a story can be replayed), and the
// attack works from the public data alone and returns what it recovered with a trace of its reasoning.
//   S.RSA.attack.smallE({n, e, c}) -> {m, k, trace}                     m^e < n (or m^e = c + k·n for a few k): an integer root
//   S.RSA.attack.commonModulus({n, e1, e2, c1, c2}) -> {m, a, b, trace} a·e1 + b·e2 = 1, so m = c1^a·c2^b
//   S.RSA.attack.hastad({e, items: [{n, c}]}) -> {m, x, trace}          CRT then the e-th root
//   S.RSA.attack.wiener({n, e}) -> {d, p, q, rows: [{h, k, phi, ok}], trace}
//   S.RSA.attack.fermat({n[, limit]}) -> {p, q, steps: [{a, b2, square}], trace}
//   S.RSA.attack.sharedPrimes(ns) -> {factors: [{i, p, q} | null], tree: [[…levels]], rems, trace}
//   S.RSA.attack.crtFault({n, e, m, s}) -> {p, q, trace};  crtFaultPair({n, s, sFaulty}) -> {p, q, trace}
//   S.RSA.attack.timingSteps({n, e, samples: [{x, time}], bits}) generator per bit; timing(...) -> {d, ok, bits: [...], trace}
//   S.RSA.labs.<name>(seed[, opts]) -> the planted secret and the public data for each attack above
(function (S) {
  'use strict';
  const N = () => S.NT;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const sh = (v) => N().short(v);
  const R = (S.RSA = S.RSA || {});
  const A = (R.attack = {});
  const L = (R.labs = {});

  /** run fn with the random source seeded, then put the old source back */
  const seeded = (seed, fn) => { const old = N().setRandom(N().seededRandom(seed)); try { return fn(); } finally { N().setRandom(old); } };
  R.seeded = seeded;
  const textNum = (s) => N().fromBytes(new TextEncoder().encode(s));

  A.smallE = ({ n, e, c }, opts = {}) => {
    n = B(n); e = B(e); c = B(c);
    const trace = [step('start', `No padding and e = ${e}: if m^${e} < n, then c is m^${e} itself, with no reduction at all.`, { n, e, c })];
    const maxK = opts.maxK || 1000;
    for (let k = 0n; k <= BigInt(maxK); k++) {
      const r = N().iroot(c + k * n, e);
      if (k < 4n || r.exact) trace.push(step('try', `${k ? `c + ${k}·n` : 'c'} = ${sh(c + k * n)}: its integer ${e}-th root is ${sh(r.root)}${r.exact ? ', exactly' : `, but ${sh(r.root)}^${e} ≠ ${k ? 'it' : 'c'}`}.`, { k, root: r.root, exact: r.exact }));
      if (r.exact && N().pow(r.root, e, n) === c) {
        trace.push(step('done', `m = ${sh(r.root)}: the ${e}-th power wrapped around n ${k} time${k === 1n ? '' : 's'}.`, { m: r.root, k }));
        return { m: r.root, k, trace };
      }
    }
    trace.push(step('fail', `No exact root for k ≤ ${maxK}: the message was long enough that m^${e} wrapped many times.`));
    return { m: null, k: null, trace };
  };
  L.smallE = (seed, opts = {}) => seeded(seed, () => {
    const key = R.keygen(opts.bits || 1024, { e: 3n }), bytes = opts.messageBytes || 40;
    const m = N().randomBits(bytes * 8) | (1n << BigInt(bytes * 8 - 1));
    return { secret: { m }, key, public: { n: key.n, e: 3n, c: N().pow(m, 3n, key.n) } };
  });

  A.commonModulus = ({ n, e1, e2, c1, c2 }) => {
    n = B(n); e1 = B(e1); e2 = B(e2); c1 = B(c1); c2 = B(c2);
    const eg = N().egcd(e1, e2), trace = [step('start', `The same message under the same n with exponents ${sh(e1)} and ${sh(e2)}.`)];
    trace.push(...eg.trace);
    if (eg.g !== 1n) { trace.push(step('fail', `gcd(e1, e2) = ${sh(eg.g)}, not 1: the attack needs coprime exponents.`)); return { m: null, trace }; }
    const { x: a, y: b } = eg;
    const m = (N().pow(c1, a, n) * N().pow(c2, b, n)) % n;
    trace.push(step('combine', `a = ${sh(a)}, b = ${sh(b)}: c1^a·c2^b = m^(a·e1 + b·e2) = m^1 = ${sh(m)} (a negative power uses the inverse mod n).`, { a, b, m }));
    return { m, a, b, trace };
  };
  L.commonModulus = (seed, opts = {}) => seeded(seed, () => {
    const key = R.keygen(opts.bits || 1024), n = key.n, e1 = 65537n;
    let e2 = 3n + 2n * N().randBelow(5000n);
    while (N().gcd(e2, e1) !== 1n || N().gcd(e2, key.phi) !== 1n) e2 += 2n;
    const m = N().randBelow(n);
    return { secret: { m }, public: { n, e1, e2, c1: N().pow(m, e1, n), c2: N().pow(m, e2, n) } };
  });

  A.hastad = ({ e, items }) => {
    e = B(e);
    const trace = [step('start', `The same message went to ${items.length} people, each with e = ${e} and a different modulus.`)];
    if (BigInt(items.length) < e) trace.push(step('warn', `Only ${items.length} ciphertexts for e = ${e}; the root is exact only if m^${e} is below their product.`));
    const crt = N().crt(items.map((it) => B(it.c)), items.map((it) => B(it.n)));
    trace.push(...crt.trace);
    const r = N().iroot(crt.x, e);
    trace.push(step('root', r.exact ? `m^${e} < n1·n2·…, so x = m^${e} exactly, and its integer ${e}-th root is m = ${sh(r.root)}.` : `x is not an exact ${e}-th power: m^${e} exceeded the product of the moduli.`, { m: r.root, exact: r.exact }));
    return { m: r.exact ? r.root : null, x: crt.x, trace };
  };
  L.hastad = (seed, opts = {}) => seeded(seed, () => {
    const e = B(opts.e || 3), items = [], bits = opts.bits || 512;
    const keys = [];
    while (keys.length < Number(e)) { const k = R.keygen(bits, { e }); if (keys.every((o) => N().gcd(o.n, k.n) === 1n)) keys.push(k); }
    const m = N().randomBits(bits - 8) | 1n;
    for (const k of keys) items.push({ n: k.n, c: N().pow(m, e, k.n) });
    return { secret: { m }, public: { e, items } };
  });

  A.wiener = ({ n, e }) => {
    n = B(n); e = B(e);
    const cf = N().contfrac(e, n), rows = [], trace = [];
    trace.push(step('start', `Expand e/n as a continued fraction: [${cf.terms.slice(0, 12).map(sh).join(', ')}${cf.terms.length > 12 ? ', …' : ''}]. If d is small, k/d is one of its convergents.`, { terms: cf.terms }));
    for (const { h: k, k: d } of cf.convergents) {
      if (k === 0n) continue;
      const row = { h: k, k: d, phi: null, ok: false };
      rows.push(row);
      if ((e * d - 1n) % k !== 0n) { trace.push(step('try', `k/d = ${sh(k)}/${sh(d)}: (e·d − 1)/k is not a whole number.`, { k, d })); continue; }
      const phi = (e * d - 1n) / k, s = n - phi + 1n, disc = s * s - 4n * n;
      row.phi = phi;
      if (disc >= 0n && N().isSquare(disc)) {
        const r = N().isqrt(disc), p = (s + r) / 2n, q = (s - r) / 2n;
        if (p * q === n && q > 1n) {
          row.ok = true;
          trace.push(step('found', `k/d = ${sh(k)}/${sh(d)} gives φ = ${sh(phi)}; x² − ${sh(s)}x + n = 0 has the roots p = ${sh(p)} and q = ${sh(q)}. The private exponent is d = ${sh(d)}.`, { k, d, phi, p, q }));
          return { d, p, q, rows, trace };
        }
      }
      trace.push(step('try', `k/d = ${sh(k)}/${sh(d)} gives φ = ${sh(phi)}, but x² − (n − φ + 1)x + n has no whole roots.`, { k, d, phi }));
    }
    trace.push(step('fail', 'No convergent works: d is not small enough for this attack.'));
    return { d: null, rows, trace };
  };
  L.wiener = (seed, opts = {}) => seeded(seed, () => {
    const bits = opts.bits || 1024;
    for (;;) {
      const p = N().randomPrime(bits / 2).prime, q = N().randomPrime(bits / 2).prime;
      if (p === q) continue;
      const n = p * q, phi = (p - 1n) * (q - 1n), limit = N().iroot(n, 4).root / 3n;
      let d = N().randBelow(limit / 2n) + limit / 2n;
      d |= 1n;
      while (N().gcd(d, phi) !== 1n) d -= 2n;
      return { secret: { d, p, q }, public: { n, e: N().inv(d, phi) } };
    }
  });

  A.fermat = ({ n, limit = 1000000 }) => {
    n = B(n);
    const steps = [], trace = [];
    let a = N().isqrt(n);
    if (a * a < n) a++;
    trace.push(step('start', `Look for n = a² − b² = (a − b)(a + b), starting at a = ⌈√n⌉ = ${sh(a)}.`, { a }));
    for (let i = 0; i < limit; i++, a++) {
      const b2 = a * a - n, sq = N().isSquare(b2);
      if (steps.length < 64 || sq) steps.push({ a, b2, square: sq });
      if (i < 6 || sq) trace.push(step('try', `a = ${sh(a)}: a² − n = ${sh(b2)}${sq ? ` = ${sh(N().isqrt(b2))}², a square` : ', not a square'}.`, { a, b2, square: sq }));
      if (sq) {
        const b = N().isqrt(b2), p = a + b, q = a - b;
        trace.push(step('found', `n = (a + b)(a − b) = ${sh(p)}·${sh(q)} after ${i + 1} step${i ? 's' : ''}: the primes were close together.`, { p, q, tries: i + 1 }));
        return { p, q, tries: i + 1, steps, trace };
      }
    }
    trace.push(step('fail', `No square within ${limit} steps: the primes are not close enough.`));
    return { p: null, q: null, steps, trace };
  };
  L.fermat = (seed, opts = {}) => seeded(seed, () => {
    const bits = opts.bits || 1024, p = N().randomPrime(bits / 2).prime, gap = N().randomBits(opts.gapBits || Math.floor(bits / 4) + 3);
    const q = N().nextPrime(p + gap);
    return { secret: { p, q }, public: { n: p * q } };
  });

  /** batch GCD: a product tree, then a remainder tree: P mod n_i², divided by n_i, shares any prime n_i has with another key */
  A.sharedPrimes = (ns) => {
    ns = ns.map(B);
    const trace = [], tree = [ns];
    while (tree[tree.length - 1].length > 1) {
      const lv = tree[tree.length - 1], up = [];
      for (let i = 0; i < lv.length; i += 2) up.push(i + 1 < lv.length ? lv[i] * lv[i + 1] : lv[i]);
      tree.push(up);
    }
    trace.push(step('product-tree', `Multiply the ${ns.length} moduli in pairs, level by level: ${tree.length} levels up to P, a ${N().bitLength(tree[tree.length - 1][0])}-bit product.`, { levels: tree.length }));
    let rems = [tree[tree.length - 1][0]];
    for (let lvl = tree.length - 2; lvl >= 0; lvl--) rems = tree[lvl].map((v, i) => rems[i >> 1] % (v * v));
    trace.push(step('remainder-tree', 'Walk back down: at each node keep P mod (node)², so each leaf gets P mod n_i² cheaply.'));
    const factors = ns.map((n, i) => {
      const g = N().gcd(rems[i] / n, n);
      if (g === 1n) return null;
      if (g === n) {
        for (let j = 0; j < ns.length; j++) { if (j === i) continue; const h = N().gcd(n, ns[j]); if (h !== 1n && h !== n) return { i, p: h, q: n / h }; }
        return null;
      }
      return { i, p: g, q: n / g };
    });
    factors.forEach((f) => { if (f) trace.push(step('factor', `Key ${f.i}: gcd(n_${f.i}, P/n_${f.i} mod n_${f.i}) = ${sh(f.p)}, a shared prime, so n_${f.i} = ${sh(f.p)}·${sh(f.q)}.`, f)); });
    trace.push(step('done', `${factors.filter(Boolean).length} of ${ns.length} keys share a prime with some other key and are broken.`));
    return { factors, tree, rems, trace };
  };
  L.sharedPrimes = (seed, opts = {}) => seeded(seed, () => {
    const count = opts.count || 24, bits = opts.bits || 512, weak = opts.weak || 4, primes = [];
    for (let i = 0; i < 2 * count - weak; i++) primes.push(N().randomPrime(bits / 2).prime);
    const ns = [], broken = new Map();
    // a weak generator handed out the same prime twice: `weak` pairs of keys share a factor
    for (let i = 0; i < count; i++) ns.push(null);
    let next = 0;
    for (let w = 0; w < weak; w++) {
      const a = 2 * w, b = 2 * w + 1, shared = primes[next++];
      for (const i of [a, b]) { const q = primes[next++]; ns[i] = shared * q; broken.set(i, shared); }
    }
    for (let i = 0; i < count; i++) if (!ns[i]) { ns[i] = primes[next++] * primes[next++]; }
    const idx = ns.map((_, i) => i);
    for (let i = idx.length - 1; i > 0; i--) { const j = Number(N().randBelow(BigInt(i + 1))); [idx[i], idx[j]] = [idx[j], idx[i]]; }
    return { secret: { broken: [...broken.entries()].map(([i, p]) => ({ i: idx.indexOf(i), p })) }, public: { ns: idx.map((i) => ns[i]) } };
  });

  A.crtFault = ({ n, e, m, s }) => {
    n = B(n); e = B(e); m = B(m); s = B(s);
    const v = N().pow(s, e, n), g = N().gcd(N().mod(v - m, n), n), trace = [];
    trace.push(step('check', `s^e mod n = ${sh(v)} ≠ m = ${sh(m)}: the signature is faulty.`, { v }));
    trace.push(step('gcd', `The half modulo one prime was right, so s^e − m is a multiple of that prime: gcd(s^e − m, n) = ${sh(g)}.`, { g }));
    if (g === 1n || g === n) { trace.push(step('fail', 'The gcd is trivial: the fault hit both halves or none.')); return { p: null, q: null, trace }; }
    trace.push(step('done', `n = ${sh(g)}·${sh(n / g)}: one faulty signature gave away the key.`, { p: g, q: n / g }));
    return { p: g, q: n / g, trace };
  };
  A.crtFaultPair = ({ n, s, sFaulty }) => {
    n = B(n);
    const g = N().gcd(N().mod(B(s) - B(sFaulty), n), n);
    const trace = [step('gcd', `The correct and faulty signatures agree modulo one prime only: gcd(s − s′, n) = ${sh(g)}.`, { g })];
    return g === 1n || g === n ? { p: null, q: null, trace } : { p: g, q: n / g, trace };
  };
  L.crtFault = (seed, opts = {}) => seeded(seed, () => {
    const key = R.keygen(opts.bits || 1024), m = N().randBelow(key.n), which = N().randBelow(2n) ? 'p' : 'q';
    const bit = Number(N().randBelow(BigInt(N().bitLength(key[which]) - 1)));
    const sFaulty = R.signRaw(m, key, { fault: which, bit }).value, s = R.signRaw(m, key, { crt: true }).value;
    return { secret: { p: key.p, q: key.q, faultIn: which }, public: { n: key.n, e: key.e, m, s: sFaulty, sCorrect: s } };
  });

  // ---- the timing attack on left-to-right Montgomery exponentiation
  const mean = (a) => { let s = 0; for (const v of a) s += v; return a.length ? s / a.length : 0; };
  /**
   * Bit by bit from the top. With the bits known so far the attacker replays every sample exactly, so it knows the
   * value the device holds before the current bit. Guess 1: the device multiplies, then squares at the next bit;
   * guess 0: it only squares, then squares again. For each guess, split the samples by whether that next squaring
   * needs the extra subtraction. Under the true guess the split is real and the two groups' mean times differ by
   * about the extra cost; under the wrong guess the predicted squaring never ran and the gap is near 0. The cost of the
   * extra subtractions already known is taken off each time first (priced at the typical gap so far), which removes
   * noise. If the final check fails, the attack reruns from its least certain bits with that bit flipped.
   */
  A.timingSteps = function* ({ n, e, samples, bits }, opts = {}) {
    n = B(n);
    const M = R.montgomery(n), T = samples.map((s) => s.time), xb = samples.map((s) => M.to(s.x)), cnt = samples.length;
    const out = [], trace = [step('start', `${cnt} timed decryptions; d has ${bits} bits and its top bit is 1.`, { samples: cnt, bits })];
    const check = (hist) => { let d = 1n; for (const h of hist) d = (d << 1n) | BigInt(h.bit); d = (d << 1n) | 1n; return { d, ok: N().pow(N().pow(2n, B(e), n), d, n) === 2n }; };
    // one pass from bit `from` on, given the decisions before it; `force` fixes the bit at `from`
    const pass = function* (prefix, from, force) {
      const hist = prefix.slice();
      let acc = from === 1 ? xb : null, K = from === 1 ? new Array(cnt).fill(0) : null;
      if (from > 1) { const h = hist[hist.length - 1]; acc = h.bit ? h.one : h.sq; K = h.bit ? h.K1 : h.K0; }
      for (let i = from; i < bits - 1; i++) {
        const sqR = acc.map((a) => M.mul(a, a)), sq = sqR.map((r) => r.value);
        const mulR = sq.map((a, j) => M.mul(a, xb[j])), one = mulR.map((r) => r.value);
        const K0 = K.map((k, j) => k + (sqR[j].extra ? 1 : 0)), K1 = K0.map((k, j) => k + (mulR[j].extra ? 1 : 0));
        const price = hist.length ? mean(hist.map((h) => h.strength)) : 0;
        const res = T.map((t, j) => t - price * K0[j]);
        const split = (vals) => { let a = 0, na = 0, b = 0, nb = 0; vals.forEach((v, j) => { if (M.mul(v, v).extra) { a += res[j]; na++; } else { b += res[j]; nb++; } }); return { diff: na && nb ? a / na - b / nb : 0, nHi: na }; };
        const g1 = split(one), g0 = split(sq);
        const bit = i === from && force != null ? force : g1.diff > g0.diff ? 1 : 0;
        hist.push({ i, sq, one, K0, K1, bit, strength: Math.max(g1.diff, g0.diff), margin: Math.abs(g1.diff - g0.diff) });
        acc = bit ? one : sq; K = bit ? K1 : K0;
        const rec = { i, bit, diff1: g1.diff, diff0: g0.diff, n1: g1.nHi, n0: g0.nHi, price, forced: i === from && force != null };
        out.push(rec);
        trace.push(step('bit', rec.forced ? `Bit ${i} is flipped to ${bit} for this retry.` : `Bit ${i}: under guess 1 the times split ${g1.diff.toFixed(2)} apart, under guess 0 ${g0.diff.toFixed(2)} apart, so the bit is ${bit}.`, rec));
        yield rec;
      }
      return hist;
    };
    let hist = yield* pass([], 1), res = check(hist), retries = 0;
    const firstPass = hist;
    if (!res.ok && bits > 2) {
      const order = firstPass.map((h, k) => k).sort((x, y) => firstPass[x].margin - firstPass[y].margin).slice(0, opts.retries || 4);
      for (const k of order) {
        retries++;
        trace.push(step('retry', `(2^e)^d ≠ 2, so a bit is wrong. Bit ${firstPass[k].i} was the least certain (the two gaps were only ${firstPass[k].margin.toFixed(2)} apart): flip it and redo the bits after it.`, { i: firstPass[k].i }));
        hist = yield* pass(firstPass.slice(0, k), firstPass[k].i, 1 - firstPass[k].bit);
        res = check(hist);
        if (res.ok) break;
      }
    }
    trace.push(step('last', 'The last bit is 1, since d is odd (e·d ≡ 1 modulo an even number).'));
    trace.push(step(res.ok ? 'done' : 'fail', res.ok ? `d = ${sh(res.d)}; (2^e)^d mod n = 2 confirms it.` : `The candidate ${sh(res.d)} fails the check (2^e)^d = 2: more samples are needed.`, { d: res.d, ok: res.ok }));
    return { d: res.d, ok: res.ok, retries, bits: out, trace };
  };
  A.timing = (input) => N().drain(A.timingSteps(input));
  L.timing = (seed, opts = {}) => seeded(seed, () => {
    const key = R.keygen(opts.bits || 48), model = R.timingModel(key.n, { seed, base: opts.base, extra: opts.extra, noise: opts.noise });
    const samples = [], count = opts.samples || 6000;
    for (let i = 0; i < count; i++) { const x = N().randBelow(key.n); samples.push({ x, time: model.time(x, key.d).time }); }
    return { secret: { d: key.d }, key, model, public: { n: key.n, e: key.e, samples, bits: N().bitLength(key.d) } };
  });
})(globalThis.Sifer = globalThis.Sifer || {});
