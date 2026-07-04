// RSA on BigInt: key generation from two random primes (as a step generator, so a page or a Web Worker can run it a
// slice at a time), toy keys from primes the student picks, three ways to compute x^e mod n with their operation
// counts, textbook encryption and decryption, decryption by the Chinese remainder theorem with Garner's recombination,
// and a timing model of Montgomery multiplication whose extra reductions leak the exponent.
//   S.RSA.fromPrimes(p, q[, e, {useLambda, trusted}]) -> key {n, e, d, p, q, dp, dq, qinv, phi, lambda, bits, trace}
//   S.RSA.keygenSteps(bits[, {e, rounds}])   generator; yields {phase: 'p'|'q', tried, candidate, outcome}, returns a key
//   S.RSA.keygen(bits[, opts]) / keygenChunked(bits[, opts]) -> key / Promise of key (S.NT.runChunked)
//   S.RSA.public(key) -> {n, e}
//   S.RSA.powLR(x, e, n) / powRL(x, e, n) / ladder(x, e, n) -> {value, steps, squarings, multiplications, trace}
//   S.RSA.encrypt(m, pub) / decrypt(c, key) -> {value, trace}
//   S.RSA.decryptCRT(c, key[, {fault}]) -> {value, mp, mq, h, trace}     Garner: m = mq + q·(qinv·(mp − mq) mod p)
//   S.RSA.signRaw(m, key[, {crt, fault}]) / verifyRaw(s, pub) -> {value, trace}
//   S.RSA.montgomery(n) -> {R, mul(a, b) -> {value, extra}, to(x), from(x)}
//   S.RSA.timingModel(n[, {seed, base, extra, noise}]) -> {time(x, d) -> {time, ops, extras}}
(function (S) {
  'use strict';
  const N = () => S.NT;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const sh = (v) => N().short(v);
  const R = (S.RSA = S.RSA || {});

  /** a key from two chosen primes, with every number derived and explained */
  R.fromPrimes = (p, q, e = 65537n, opts = {}) => {
    p = B(p); q = B(q); e = B(e);
    const T = N(), trace = [];
    if (p === q) throw new Error('p and q must be different primes');
    // trusted: primes already proven elsewhere (the built-in key pools, tested once in tests/), not re-tested here
    if (!opts.trusted && (!T.isProbablePrime(p) || !T.isProbablePrime(q))) throw new Error('p and q must both be prime');
    const n = p * q, phi = (p - 1n) * (q - 1n), lambda = T.lcm(p - 1n, q - 1n);
    trace.push(step('modulus', `n = p·q = ${sh(p)}·${sh(q)} = ${sh(n)}, a ${T.bitLength(n)}-bit modulus.`, { p, q, n }));
    trace.push(step('phi', `φ(n) = (p − 1)(q − 1) = ${sh(p - 1n)}·${sh(q - 1n)} = ${sh(phi)}; λ(n) = lcm(p − 1, q − 1) = ${sh(lambda)}.`, { phi, lambda }));
    const m = opts.useLambda ? lambda : phi, mName = opts.useLambda ? 'λ(n)' : 'φ(n)';
    const g = T.gcd(e, m);
    if (g !== 1n || e < 2n || e >= m) {
      trace.push(step('bad-e', `gcd(e, ${mName}) = gcd(${sh(e)}, ${sh(m)}) = ${sh(g)}, so e = ${sh(e)} has no inverse: pick another e.`, { e, g }));
      throw Object.assign(new Error(`e = ${e} is not invertible modulo ${mName}`), { trace });
    }
    trace.push(step('e', `The public exponent e = ${sh(e)} shares no factor with ${mName}.`, { e }));
    const inv = T.inverse(e, m);
    const d = inv.inv;
    trace.push(step('d', `d = e⁻¹ mod ${mName} = ${sh(d)}, found by the extended Euclidean algorithm: e·d = ${sh(e * d)} ≡ 1 (mod ${sh(m)}).`, { d, egcd: inv.egcd.rows }));
    const dp = d % (p - 1n), dq = d % (q - 1n), qinv = T.inv(q, p);
    trace.push(step('crt', `For fast decryption keep dp = d mod (p − 1) = ${sh(dp)}, dq = d mod (q − 1) = ${sh(dq)} and qinv = q⁻¹ mod p = ${sh(qinv)}.`, { dp, dq, qinv }));
    trace.push(step('done', `The public key is (n, e) = (${sh(n)}, ${sh(e)}); p, q, φ(n) and d stay secret.`, { n, e }));
    return { n, e, d, p, q, dp, dq, qinv, phi, lambda, bits: T.bitLength(n), trace };
  };
  R.public = (k) => ({ n: k.n, e: k.e });

  /** the key search, one prime candidate per yield */
  R.keygenSteps = function* (bits, opts = {}) {
    bits = Number(bits);
    const T = N(), e = B(opts.e || 65537n), half = bits >> 1, trace = [];
    if (bits < 8) throw new Error('use at least 8 bits');
    trace.push(step('start', `Make a ${bits}-bit RSA key: two random ${half}-bit primes p and q with gcd(e, p − 1) = gcd(e, q − 1) = 1, e = ${sh(e)}.`, { bits, e }));
    const pick = function* (phase, avoid) {
      for (;;) {
        const gen = T.primeSteps(phase === 'p' ? bits - half : half, { rounds: opts.rounds });
        let r;
        for (;;) { r = gen.next(); if (r.done) break; yield Object.assign({ phase }, r.value); }
        const pr = r.value.prime;
        if (avoid && pr === avoid) continue;
        if (T.gcd(e, pr - 1n) !== 1n) { trace.push(step('reject', `${phase} = ${sh(pr)} is prime, but ${phase} − 1 shares a factor with e; draw again.`, { phase, prime: pr })); continue; }
        if (avoid && bits >= 512 && T.abs(pr - avoid) >> BigInt(half - 100) === 0n) continue;
        trace.push(step('prime', `${phase} = ${sh(pr)} (found after ${r.value.tried} candidate${r.value.tried === 1 ? '' : 's'}).`, { phase, prime: pr, tried: r.value.tried, log: r.value.log }));
        return pr;
      }
    };
    let p = yield* pick('p');
    let q = yield* pick('q', p);
    if (p < q) [p, q] = [q, p];
    const key = R.fromPrimes(p, q, e, opts);
    key.trace = trace.concat(key.trace);
    return key;
  };
  R.keygen = (bits, opts) => N().drain(R.keygenSteps(bits, opts));
  R.keygenChunked = (bits, opts = {}) => N().runChunked(R.keygenSteps(bits, opts), opts);

  // ---- three ways to compute x^e mod n
  const bitsOf = (e) => B(e).toString(2);
  /** left to right: square for every bit after the first, multiply by x for every 1 */
  R.powLR = (x, e, n) => {
    x = N().mod(x, n); e = B(e); n = B(n);
    const bits = bitsOf(e), steps = [], trace = [];
    let v = 1n, sq = 0, mul = 0;
    if (e === 0n) return { value: 1n % n, bits, steps, squarings: 0, multiplications: 0, trace: [step('zero', 'x^0 = 1.')] };
    for (let i = 0; i < bits.length; i++) {
      const bit = bits[i] === '1' ? 1 : 0;
      if (i === 0) { v = x; steps.push({ i, bit, ops: '', value: v }); trace.push(step('bit', `Bit 0 (the leading 1): start with x = ${sh(v)}.`, { i, bit, value: v, ops: '' })); continue; }
      const s = (v * v) % n; sq++;
      v = s;
      if (bit) { v = (v * x) % n; mul++; }
      steps.push({ i, bit, ops: bit ? 'SM' : 'S', squared: s, value: v });
      trace.push(step('bit', bit ? `Bit ${i} is 1: square to ${sh(s)}, multiply by x to get ${sh(v)}.` : `Bit ${i} is 0: square to ${sh(v)}.`, { i, bit, ops: bit ? 'SM' : 'S', squared: s, value: v }));
    }
    trace.push(step('done', `${sh(x)}^${sh(e)} mod ${sh(n)} = ${sh(v)} with ${sq} squarings and ${mul} multiplications.`, { value: v, squarings: sq, multiplications: mul }));
    return { value: v, bits, steps, squarings: sq, multiplications: mul, trace };
  };
  /** right to left: keep x, x², x⁴, … and multiply in the ones whose bit is 1 */
  R.powRL = (x, e, n) => {
    x = N().mod(x, n); e = B(e); n = B(n);
    const bits = bitsOf(e), L = bits.length, steps = [], trace = [];
    let acc = 1n, base = x, sq = 0, mul = 0, started = false;
    for (let j = 0; j < L && e; j++) {
      const bit = Number((e >> BigInt(j)) & 1n);
      const was = acc;
      if (bit) { if (started) { acc = (acc * base) % n; mul++; } else { acc = base; started = true; } }
      steps.push({ j, bit, power: base, acc });
      trace.push(step('bit', bit ? `Bit ${j} (from the right) is 1: x^${2n ** BigInt(j)} = ${sh(base)} is multiplied in: ${sh(was)} → ${sh(acc)}.` : `Bit ${j} is 0: x^${2n ** BigInt(j)} = ${sh(base)} is skipped.`, { j, bit, power: base, acc }));
      if (j < L - 1) { base = (base * base) % n; sq++; }
    }
    trace.push(step('done', `The product is ${sh(acc)}: ${sq} squarings and ${mul} multiplications.`, { value: acc, squarings: sq, multiplications: mul }));
    return { value: acc % n, bits, steps, squarings: sq, multiplications: mul, trace };
  };
  /** the Montgomery ladder: one multiplication and one squaring for every bit, whatever its value; R1 = R0·x always */
  R.ladder = (x, e, n) => {
    x = N().mod(x, n); e = B(e); n = B(n);
    const bits = bitsOf(e), steps = [], trace = [];
    let r0 = 1n, r1 = x, sq = 0, mul = 0;
    trace.push(step('start', `R0 = 1 and R1 = x = ${sh(x)}; at every step R1 = R0·x.`, { r0, r1 }));
    for (let i = 0; i < bits.length && e; i++) {
      const bit = bits[i] === '1' ? 1 : 0;
      if (bit) { r0 = (r0 * r1) % n; r1 = (r1 * r1) % n; } else { r1 = (r0 * r1) % n; r0 = (r0 * r0) % n; }
      sq++; mul++;
      steps.push({ i, bit, r0, r1 });
      trace.push(step('bit', bit ? `Bit ${i} is 1: R0 = R0·R1 = ${sh(r0)}, R1 = R1² = ${sh(r1)}.` : `Bit ${i} is 0: R1 = R0·R1 = ${sh(r1)}, R0 = R0² = ${sh(r0)}.`, { i, bit, r0, r1 }));
    }
    trace.push(step('done', `R0 = ${sh(r0)}: ${sq} squarings and ${mul} multiplications, the same pattern for every exponent of this length.`, { value: r0 }));
    return { value: r0, bits, steps, squarings: sq, multiplications: mul, trace };
  };

  // ---- encryption, decryption and raw signatures
  R.encrypt = (m, pub) => {
    m = B(m);
    const { n, e } = pub;
    if (m < 0n || m >= n) throw new Error('the message must be a number from 0 to n − 1');
    const value = N().pow(m, e, n);
    return { value, trace: [step('encrypt', `c = m^e mod n = ${sh(m)}^${sh(e)} mod ${sh(n)} = ${sh(value)}.`, { m, c: value })] };
  };
  R.decrypt = (c, key) => {
    c = B(c);
    const value = N().pow(c, key.d, key.n);
    return { value, trace: [step('decrypt', `m = c^d mod n = ${sh(c)}^${sh(key.d)} mod ${sh(key.n)} = ${sh(value)}.`, { c, m: value })] };
  };
  /** CRT decryption; opts.fault = 'p' or 'q' corrupts that half (for the fault attack) */
  R.decryptCRT = (c, key, opts = {}) => {
    c = B(c);
    const T = N(), { p, q, dp, dq, qinv, n } = key, trace = [];
    let mp = T.pow(c % p, dp, p), mq = T.pow(c % q, dq, q);
    trace.push(step('halves', `Work modulo each prime with short exponents: mp = c^dp mod p = ${sh(mp)}, mq = c^dq mod q = ${sh(mq)}.`, { mp, mq, dp, dq }));
    if (opts.fault === 'p') { mp = T.mod(mp ^ (1n << BigInt(opts.bit || 0)), p); trace.push(step('fault', `A glitch flips a bit of the half modulo p: mp becomes ${sh(mp)}.`, { mp })); }
    if (opts.fault === 'q') { mq = T.mod(mq ^ (1n << BigInt(opts.bit || 0)), q); trace.push(step('fault', `A glitch flips a bit of the half modulo q: mq becomes ${sh(mq)}.`, { mq })); }
    const h = T.mod(qinv * (mp - mq), p), value = mq + h * q;
    trace.push(step('garner', `Garner: h = qinv·(mp − mq) mod p = ${sh(h)}, and m = mq + h·q = ${sh(value)}.`, { h, m: value }));
    trace.push(step('check', `This equals m mod p = ${sh(value % p)} and m mod q = ${sh(value % q)}, as the halves require.`, { n }));
    return { value, mp, mq, h, trace };
  };
  R.signRaw = (m, key, opts = {}) => {
    m = B(m);
    if (opts.crt || opts.fault) { const r = R.decryptCRT(m, key, opts); return { value: r.value, trace: r.trace }; }
    const value = N().pow(m, key.d, key.n);
    return { value, trace: [step('sign', `s = m^d mod n = ${sh(value)}.`, { m, s: value })] };
  };
  R.verifyRaw = (s, pub) => {
    const value = N().pow(B(s), pub.e, pub.n);
    return { value, trace: [step('verify', `s^e mod n = ${sh(value)}.`, { s, m: value })] };
  };

  // ---- Montgomery multiplication and a timing model built on it
  /** a·b·R⁻¹ mod n with R = 2^k (k = bit length of n); extra is true when the final subtraction is needed */
  R.montgomery = (n) => {
    n = B(n);
    if (!(n & 1n)) throw new Error('Montgomery multiplication needs an odd modulus');
    const k = BigInt(N().bitLength(n)), Rv = 1n << k, mask = Rv - 1n;
    const nprime = N().mod(-N().inv(n, Rv), Rv), R2 = (Rv * Rv) % n;
    const mul = (a, b) => {
      const t = a * b, m = ((t & mask) * nprime) & mask;
      let u = (t + m * n) >> k;
      const extra = u >= n;
      if (extra) u -= n;
      return { value: u, extra };
    };
    return { n, R: Rv, k, nprime, mul, to: (x) => mul(N().mod(x, n), R2).value, from: (x) => mul(x, 1n).value };
  };
  /** a Gaussian sampler on a seeded uniform source */
  R.gauss = (seed) => {
    let s = (Number(seed) >>> 0) || 1;
    const u = () => { s = (s + 0x6d2b79f5) >>> 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t ^= t + Math.imul(t ^ (t >>> 7), 61 | t); return (((t ^ (t >>> 14)) >>> 0) + 0.5) / 4294967296; };
    return () => Math.sqrt(-2 * Math.log(u())) * Math.cos(2 * Math.PI * u());
  };
  /**
   * The device computes x^d mod n left to right with Montgomery multiplication. Each multiplication costs `base`
   * time units, plus `extra` when its final subtraction runs, and the measurement adds Gaussian noise (σ = noise).
   */
  R.timingModel = (n, opts = {}) => {
    const M = R.montgomery(n), base = opts.base || 100, extra = opts.extra == null ? 14 : opts.extra, noise = opts.noise == null ? 6 : opts.noise;
    const g = R.gauss(opts.seed || 1);
    const time = (x, d) => {
      const xb = M.to(x), bits = bitsOf(d);
      let acc = xb, ops = 1, extras = 0, t = base;
      for (let i = 1; i < bits.length; i++) {
        let r = M.mul(acc, acc); acc = r.value; ops++; t += base + (r.extra ? extra : 0); extras += r.extra ? 1 : 0;
        if (bits[i] === '1') { r = M.mul(acc, xb); acc = r.value; ops++; t += base + (r.extra ? extra : 0); extras += r.extra ? 1 : 0; }
      }
      return { value: M.from(acc), time: t + noise * g(), ops, extras };
    };
    return { n: M.n, base, extra, noise, montgomery: M, time };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
