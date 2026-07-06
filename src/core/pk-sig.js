// Signatures whose security rests on the discrete logarithm: DSA (over a toy group and over a real 2048/224 group),
// the Elgamal signature it grew from, and Schnorr signatures, all in a prime-order subgroup of Z_p*. SHA-256 gives
// the message hash (truncated to the subgroup size for DSA). Each signing and verifying step is traced. The nonce in
// each scheme must be fresh and secret; two signatures that reused one let the key be recovered, shown for DSA and
// Schnorr.
//   S.SIG.dsaParams({L, Nbits}|{p, q, g}) -> {p, q, g}            L = 2048, Nbits = 224 for the real group; toy() for a small one
//   S.SIG.dsaKey(params[, x]) -> {params, x, y, trace}
//   S.SIG.dsaSign(key, msg[, k]) / dsaVerify(pub, msg, sig) -> traced {r, s} and {ok}
//   S.SIG.elgamalSign(p, g, x, msg[, k]) / elgamalVerify(p, g, y, msg, sig) -> traced
//   S.SIG.schnorrKey(params[, x]) / schnorrSign(key, msg[, k]) / schnorrVerify(pub, msg, sig) -> traced {e, s} (or {R, s})
//   S.SIG.attack.dsaNonceReuse(pub, m1, sig1, m2, sig2) -> {k, x, trace}
//   S.SIG.attack.schnorrNonceReuse(pub, m1, sig1, m2, sig2) -> {k, x, trace}
//   S.SIG.labs.<name>(seed) -> planted key and signatures for the nonce-reuse attacks
(function (S) {
  'use strict';
  const N = () => S.NT;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const sh = (v) => N().short(v);
  const SIG = (S.SIG = S.SIG || {});
  const hashInt = (msg) => N().fromBytes(S.SHA256.hash(typeof msg === 'string' ? new TextEncoder().encode(msg) : Uint8Array.from(msg)));
  /** the hash truncated to the leftmost bits of q, as FIPS 186 defines for DSA */
  const hashMod = (msg, q) => { const H = hashInt(msg), qb = N().bitLength(q), hb = 256; return qb >= hb ? H : H >> BigInt(hb - qb); };

  // ---- DSA domain parameters
  /** a toy group: q a small prime, p = q·k + 1 prime, g of order q */
  SIG.toyParams = (qMin = 101n) => {
    let q = N().nextPrime(B(qMin) - 1n);
    for (;;) {
      for (let k = 2n; k < 5000n; k += 2n) { const p = q * k + 1n; if (N().isProbablePrime(p)) { const h = 2n; let g = N().pow(h, (p - 1n) / q, p); if (g === 1n) continue; return { p, q, g }; } }
      q = N().nextPrime(q);
    }
  };
  /** real parameters: generate q (Nbits), then p = q·k + 1 of L bits, then g = h^((p−1)/q). Slow; use a worker. */
  SIG.dsaParamsSteps = function* (opts = {}) {
    const L = opts.L || 2048, Nbits = opts.Nbits || 224;
    const q = opts.q ? B(opts.q) : N().randomPrime(Nbits).prime;
    yield { phase: 'q', q };
    let p = opts.p ? B(opts.p) : null, tried = 0;
    if (!p) {
      for (;;) {
        tried++;
        const base = N().randomBits(L) | (1n << BigInt(L - 1));
        const cand = base - (base % (2n * q)) + 1n; // ≡ 1 (mod 2q)
        if (N().bitLength(cand) === L && N().isProbablePrime(cand)) { p = cand; break; }
        if (tried % 64 === 0) yield { phase: 'p', tried };
      }
    }
    let g = 2n;
    for (let h = 2n; ; h++) { g = N().pow(B(h), (p - 1n) / q, p); if (g !== 1n) break; }
    return { p, q, g };
  };
  SIG.dsaParams = (opts = {}) => (opts.toy ? SIG.toyParams(opts.qMin) : N().drain(SIG.dsaParamsSteps(opts)));

  SIG.dsaKey = (params, x) => {
    const { p, q, g } = params;
    x = x == null ? 1n + N().randBelow(q - 1n) : B(x);
    const y = N().pow(g, x, p), trace = [];
    trace.push(step('key', `Private key x = ${sh(x)} in [1, q − 1]; public key y = g^x mod p = ${sh(y)}.`, { x, y }));
    return { params, x, y, pub: { params, y }, trace };
  };
  SIG.dsaSign = (key, msg, k) => {
    const { p, q, g } = key.params, trace = [];
    const z = hashMod(msg, q);
    trace.push(step('hash', `z = the leftmost ${N().bitLength(q)} bits of SHA-256(message) = ${sh(z)}.`, { z }));
    let r, s, kk;
    for (;;) {
      kk = k != null ? B(k) : 1n + N().randBelow(q - 1n);
      r = N().pow(g, kk, p) % q;
      if (r === 0n) { if (k != null) throw new Error('this k gives r = 0'); continue; }
      const kinv = N().inv(kk, q);
      s = N().mod(kinv * (z + x_of(key) * r), q);
      if (s === 0n) { if (k != null) throw new Error('this k gives s = 0'); continue; }
      break;
    }
    trace.push(step('nonce', `A fresh secret nonce k = ${sh(kk)}; r = (g^k mod p) mod q = ${sh(r)}.`, { k: kk, r }));
    trace.push(step('s', `s = k⁻¹·(z + x·r) mod q = ${sh(s)}. The signature is (r, s).`, { s }));
    return { r, s, k: kk, z, trace };
  };
  const x_of = (key) => key.x;
  SIG.dsaVerify = (pub, msg, sig) => {
    const { p, q, g } = pub.params, y = pub.y, { r, s } = sig, trace = [];
    if (!(r > 0n && r < q && s > 0n && s < q)) { trace.push(step('range', 'r or s is out of [1, q − 1]: reject.')); return { ok: false, trace }; }
    const z = hashMod(msg, q), w = N().inv(s, q);
    const u1 = N().mod(z * w, q), u2 = N().mod(r * w, q);
    const v = (N().pow(g, u1, p) * N().pow(y, u2, p) % p) % q;
    trace.push(step('check', `w = s⁻¹ mod q = ${sh(w)}, u1 = z·w = ${sh(u1)}, u2 = r·w = ${sh(u2)}; v = (g^u1·y^u2 mod p) mod q = ${sh(v)}.`, { w, u1, u2, v }));
    const ok = v === r;
    trace.push(step(ok ? 'accept' : 'reject', ok ? `v = r, so the signature is valid.` : `v = ${sh(v)} ≠ r = ${sh(r)}: invalid.`, { ok }));
    return { ok, v, trace };
  };

  // ---- Elgamal signatures in Z_p* (g a generator, the exponent group has order p − 1)
  SIG.elgamalKey = (p, g, x) => { p = B(p); g = B(g); x = x == null ? 2n + N().randBelow(p - 3n) : B(x); return { p, g, x, y: N().pow(g, x, p) }; };
  SIG.elgamalSign = (p, g, x, msg, k) => {
    p = B(p); g = B(g); x = B(x);
    const pm1 = p - 1n, z = N().mod(hashInt(msg), pm1), trace = [];
    let r, s, kk;
    for (;;) {
      kk = k != null ? B(k) : (() => { let t; do { t = 2n + N().randBelow(pm1 - 2n); } while (N().gcd(t, pm1) !== 1n); return t; })();
      r = N().pow(g, kk, p);
      s = N().mod(N().inv(kk, pm1) * (z - x * r), pm1);
      if (s !== 0n) break;
      if (k != null) throw new Error('this k gives s = 0');
    }
    trace.push(step('nonce', `A nonce k = ${sh(kk)} coprime to p − 1; r = g^k mod p = ${sh(r)}.`, { k: kk, r }));
    trace.push(step('s', `s = k⁻¹·(H(m) − x·r) mod (p − 1) = ${sh(s)}. The signature is (r, s).`, { s, z }));
    return { r, s, k: kk, z, trace };
  };
  SIG.elgamalVerify = (p, g, y, msg, sig) => {
    p = B(p); g = B(g); y = B(y);
    const { r, s } = sig, z = N().mod(hashInt(msg), p - 1n), trace = [];
    if (!(r > 0n && r < p)) return { ok: false, trace: [step('reject', '0 < r < p is required.')] };
    const lhs = N().pow(g, z, p), rhs = (N().pow(y, r, p) * N().pow(r, s, p)) % p;
    trace.push(step('check', `g^H(m) mod p = ${sh(lhs)} and y^r·r^s mod p = ${sh(rhs)}.`, { lhs, rhs }));
    const ok = lhs === rhs;
    trace.push(step(ok ? 'accept' : 'reject', ok ? 'The two sides match: valid.' : 'The two sides differ: invalid.', { ok }));
    return { ok, trace };
  };

  // ---- Schnorr signatures in the order-q subgroup
  SIG.schnorrKey = (params, x) => {
    const { p, q, g } = params;
    x = x == null ? 1n + N().randBelow(q - 1n) : B(x);
    const y = N().pow(g, x, p);
    return { params, x, y, pub: { params, y }, trace: [step('key', `Private key x = ${sh(x)}; public key y = g^x mod p = ${sh(y)}.`, { x, y })] };
  };
  const schnorrChallenge = (R, msg, q) => N().mod(hashInt(concatBytes(N().toBytes(R), toBytes(msg))), q);
  const toBytes = (m) => (typeof m === 'string' ? new TextEncoder().encode(m) : Uint8Array.from(m));
  const concatBytes = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
  SIG.schnorrSign = (key, msg, k) => {
    const { p, q, g } = key.params, trace = [];
    const kk = k != null ? B(k) : 1n + N().randBelow(q - 1n);
    const R = N().pow(g, kk, p), e = schnorrChallenge(R, msg, q), s = N().mod(kk + e * key.x, q);
    trace.push(step('commit', `A fresh nonce k = ${sh(kk)}; the commitment is R = g^k mod p = ${sh(R)}.`, { k: kk, R }));
    trace.push(step('challenge', `The challenge is e = H(R ‖ message) mod q = ${sh(e)}.`, { e }));
    trace.push(step('response', `s = k + e·x mod q = ${sh(s)}. The signature is (e, s).`, { s }));
    return { e, s, R, k: kk, trace };
  };
  SIG.schnorrVerify = (pub, msg, sig) => {
    const { p, q, g } = pub.params, y = pub.y, { e, s } = sig, trace = [];
    if (!(s >= 0n && s < q)) return { ok: false, trace: [step('reject', 's is out of range.')] };
    const Rv = N().mod(N().pow(g, s, p) * N().pow(y, N().mod(-e, q), p), p);
    const ev = schnorrChallenge(Rv, msg, q);
    trace.push(step('recompute', `R' = g^s·y^(−e) mod p = ${sh(Rv)}; H(R' ‖ message) mod q = ${sh(ev)}.`, { R: Rv, e: ev }));
    const ok = ev === e;
    trace.push(step(ok ? 'accept' : 'reject', ok ? 'The recomputed challenge equals e: valid.' : 'The recomputed challenge differs from e: invalid.', { ok }));
    return { ok, trace };
  };

  // ---- nonce-reuse key recovery
  const A = (SIG.attack = {});
  /** two DSA signatures with the same r shared the nonce k: s1 − s2 = k⁻¹(z1 − z2), so k and then x fall out */
  A.dsaNonceReuse = (pub, m1, sig1, m2, sig2) => {
    const { q } = pub.params, trace = [];
    if (sig1.r !== sig2.r) { trace.push(step('fail', 'The two signatures have different r, so the nonces differ: nothing to do.')); return { k: null, x: null, trace }; }
    const z1 = hashMod(m1, q), z2 = hashMod(m2, q);
    trace.push(step('spot', `Both signatures share r = ${sh(sig1.r)}, so they used the same nonce k.`, { r: sig1.r }));
    const ds = N().mod(sig1.s - sig2.s, q);
    if (ds === 0n) { trace.push(step('fail', 's1 = s2: the messages hash the same, so k cannot be found this way.')); return { k: null, x: null, trace }; }
    const k = N().mod((z1 - z2) * N().inv(ds, q), q);
    trace.push(step('nonce', `s1 − s2 = k⁻¹(z1 − z2) mod q, so k = (z1 − z2)·(s1 − s2)⁻¹ mod q = ${sh(k)}.`, { k }));
    const x = N().mod((N().mod(sig1.s * k, q) - z1) * N().inv(sig1.r, q), q);
    trace.push(step('key', `From s1 = k⁻¹(z1 + x·r): x = (s1·k − z1)·r⁻¹ mod q = ${sh(x)}.`, { x }));
    return { k, x, z1, z2, trace };
  };
  /** two Schnorr signatures with the same R (hence same e per message, different message) reused k: x = (s1 − s2)/(e1 − e2) */
  A.schnorrNonceReuse = (pub, m1, sig1, m2, sig2) => {
    const { q } = pub.params, trace = [];
    if (sig1.R != null && sig2.R != null && sig1.R !== sig2.R) { trace.push(step('fail', 'Different commitments R: the nonces differ.')); return { k: null, x: null, trace }; }
    const de = N().mod(sig1.e - sig2.e, q);
    if (de === 0n) { trace.push(step('fail', 'The challenges are equal; the messages must differ to recover the key.')); return { k: null, x: null, trace }; }
    trace.push(step('spot', `Both signatures used the same commitment R, so the same nonce k, with challenges e1 = ${sh(sig1.e)} and e2 = ${sh(sig2.e)}.`, { e1: sig1.e, e2: sig2.e }));
    const x = N().mod((sig1.s - sig2.s) * N().inv(de, q), q);
    trace.push(step('key', `s = k + e·x, so s1 − s2 = (e1 − e2)·x and x = (s1 − s2)·(e1 − e2)⁻¹ mod q = ${sh(x)}.`, { x }));
    const k = N().mod(sig1.s - sig1.e * x, q);
    trace.push(step('nonce', `Then k = s1 − e1·x mod q = ${sh(k)}.`, { k }));
    return { k, x, trace };
  };

  // ---- labs
  const seeded = (seed, fn) => { const old = N().setRandom(N().seededRandom(seed)); try { return fn(); } finally { N().setRandom(old); } };
  SIG.labs = {
    dsaNonceReuse: (seed, opts = {}) => seeded(seed, () => {
      const params = SIG.toyParams(opts.qMin || 100003n), key = SIG.dsaKey(params);
      const k = 1n + N().randBelow(params.q - 1n);
      const sig1 = SIG.dsaSign(key, opts.m1 || 'transfer 100 to a', k), sig2 = SIG.dsaSign(key, opts.m2 || 'transfer 999 to b', k);
      return { secret: { x: key.x, k }, pub: key.pub, m1: opts.m1 || 'transfer 100 to a', m2: opts.m2 || 'transfer 999 to b', sig1, sig2 };
    }),
    schnorrNonceReuse: (seed, opts = {}) => seeded(seed, () => {
      const params = SIG.toyParams(opts.qMin || 100003n), key = SIG.schnorrKey(params);
      const k = 1n + N().randBelow(params.q - 1n);
      const sig1 = SIG.schnorrSign(key, opts.m1 || 'open the north gate', k), sig2 = SIG.schnorrSign(key, opts.m2 || 'open the south gate', k);
      return { secret: { x: key.x, k }, pub: key.pub, m1: opts.m1 || 'open the north gate', m2: opts.m2 || 'open the south gate', sig1, sig2 };
    }),
  };
})(globalThis.Sifer = globalThis.Sifer || {});
