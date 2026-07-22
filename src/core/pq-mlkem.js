// ML-KEM (FIPS 203), complete: the number-theoretic transform over Z_3329[X]/(X^256 + 1), sampling (SampleNTT and
// the centred binomial distribution), compression, byte encoding, K-PKE and the Fujisaki–Okamoto transform with
// implicit rejection, for ML-KEM-512, ML-KEM-768 and ML-KEM-1024. Polynomials are arrays of 256 numbers in [0, q).
// Every top-level call returns a trace at the level of the polynomial vectors: each step carries the vectors a
// picture needs (Â, s, e, t̂, y, u, v, w and the noise left after decryption).
//   S.PQ.MLKEM.params(512 | 768 | 1024 | 'ML-KEM-768') -> {name, k, eta1, eta2, du, dv, sizes}
//   S.PQ.MLKEM.keyGen(set, {d, z}?)        -> {ek, dk, d, z, trace}
//   S.PQ.MLKEM.encaps(set, ek, {m}?)       -> {K, c, m, trace}
//   S.PQ.MLKEM.decaps(set, dk, c)          -> {K, rejected, trace}
//   S.PQ.MLKEM.checkEk(set, ek) / checkDk(set, dk) -> {ok, why}   the input checks of section 7
//   ntt, invNtt, multiplyNtts, sampleNtt, cbd, compress, decompress, byteEncode, byteDecode are exposed too.
(function (S) {
  'use strict';
  const P = (S.PQ = S.PQ || {});
  const K = (P.MLKEM = {});
  const q = 3329, N = 256;
  K.q = q; K.n = N; K.zeta = 17;
  const SETS = {
    512: { k: 2, eta1: 3, eta2: 2, du: 10, dv: 4 },
    768: { k: 3, eta1: 2, eta2: 2, du: 10, dv: 4 },
    1024: { k: 4, eta1: 2, eta2: 2, du: 11, dv: 5 },
  };
  K.params = (set) => {
    const key = String(set).replace(/\D/g, '');
    const p = SETS[key];
    if (!p) throw new Error('ML-KEM parameter set must be 512, 768 or 1024');
    const sizes = { ek: 384 * p.k + 32, dk: 768 * p.k + 96, c: 32 * (p.du * p.k + p.dv), K: 32 };
    return Object.assign({ name: 'ML-KEM-' + key }, p, { sizes });
  };
  const step = (...a) => P.step(...a);
  const mod = (a) => ((a % q) + q) % q;
  const bitrev7 = (i) => { let r = 0; for (let b = 0; b < 7; b++) r |= ((i >> b) & 1) << (6 - b); return r; };
  const powq = (b, e) => { let r = 1; b %= q; while (e) { if (e & 1) r = (r * b) % q; b = (b * b) % q; e >>= 1; } return r; };
  K.ZETAS = Array.from({ length: 128 }, (_, i) => powq(17, bitrev7(i)));
  K.GAMMAS = Array.from({ length: 128 }, (_, i) => powq(17, 2 * bitrev7(i) + 1));

  /** Algorithm 9: the NTT, as seven layers of butterflies */
  K.ntt = (f) => {
    f = Array.from(f);
    let i = 1;
    for (let len = 128; len >= 2; len >>= 1)
      for (let start = 0; start < 256; start += 2 * len) {
        const z = K.ZETAS[i++];
        for (let j = start; j < start + len; j++) { const t = (z * f[j + len]) % q; f[j + len] = mod(f[j] - t); f[j] = (f[j] + t) % q; }
      }
    return f;
  };
  /** Algorithm 10: the inverse NTT, ending with the factor 128⁻¹ = 3303 */
  K.invNtt = (f) => {
    f = Array.from(f);
    let i = 127;
    for (let len = 2; len <= 128; len <<= 1)
      for (let start = 0; start < 256; start += 2 * len) {
        const z = K.ZETAS[i--];
        for (let j = start; j < start + len; j++) { const t = f[j]; f[j] = (t + f[j + len]) % q; f[j + len] = (z * mod(f[j + len] - t)) % q; }
      }
    return f.map((v) => (v * 3303) % q);
  };
  /** Algorithms 11 and 12: the product in the NTT domain, 128 products of degree-one polynomials mod X² − γ */
  K.multiplyNtts = (f, g) => {
    const h = new Array(256);
    for (let i = 0; i < 128; i++) {
      const a0 = f[2 * i], a1 = f[2 * i + 1], b0 = g[2 * i], b1 = g[2 * i + 1];
      h[2 * i] = (a0 * b0 + ((a1 * b1) % q) * K.GAMMAS[i]) % q;
      h[2 * i + 1] = (a0 * b1 + a1 * b0) % q;
    }
    return h;
  };
  const add = (f, g) => f.map((v, i) => (v + g[i]) % q);
  const sub = (f, g) => f.map((v, i) => mod(v - g[i]));
  /** schoolbook product in Z_q[X]/(X^256 + 1), for checking the NTT and for pictures */
  K.mulSchoolbook = (f, g) => {
    const h = new Array(256).fill(0);
    for (let i = 0; i < 256; i++) if (f[i]) for (let j = 0; j < 256; j++) {
      const k = i + j, v = f[i] * g[j];
      if (k < 256) h[k] = (h[k] + v) % q; else h[k - 256] = mod(h[k - 256] - v);
    }
    return h;
  };

  /** Algorithm 7: rejection sampling of a polynomial in NTT form from a SHAKE128 stream */
  K.sampleNtt = (seed34) => {
    const x = P.xof(seed34, 128), a = [];
    let rejected = 0;
    while (a.length < 256) {
      const C = x.read(3), d1 = C[0] + 256 * (C[1] & 15), d2 = (C[1] >> 4) + 16 * C[2];
      if (d1 < q) a.push(d1); else rejected++;
      if (a.length < 256) { if (d2 < q) a.push(d2); else rejected++; }
    }
    a.rejected = rejected;
    return a;
  };
  /** Algorithm 8: the centred binomial distribution CBD_η from 64η bytes */
  K.cbd = (B, eta) => {
    const bit = (i) => (B[i >> 3] >> (i & 7)) & 1, f = new Array(256);
    for (let i = 0; i < 256; i++) {
      let x = 0, y = 0;
      for (let j = 0; j < eta; j++) { x += bit(2 * i * eta + j); y += bit(2 * i * eta + eta + j); }
      f[i] = mod(x - y);
    }
    return f;
  };
  K.prf = (eta, s, b) => P.shake256(P.concat(s, [b]), 64 * eta);
  K.H = (s) => P.sha3_256(s);
  K.J = (s) => P.shake256(s, 32);
  K.G = (c) => { const o = P.sha3_512(c); return [o.slice(0, 32), o.slice(32)]; };

  /** Compress_d and Decompress_d, with the rounding of section 4.2.1 done in integers */
  K.compress = (x, d) => Math.floor((x * 2 ** (d + 1) + q) / (2 * q)) % 2 ** d;
  K.decompress = (y, d) => Math.floor((y * q * 2 + 2 ** d) / 2 ** (d + 1));
  /** Algorithms 5 and 6: d bits per coefficient, least significant first */
  K.byteEncode = (F, d) => {
    const out = new Uint8Array(32 * d);
    let pos = 0;
    for (let i = 0; i < 256; i++) { let a = F[i]; for (let j = 0; j < d; j++, pos++) { out[pos >> 3] |= (a & 1) << (pos & 7); a >>= 1; } }
    return out;
  };
  K.byteDecode = (B, d) => {
    const F = new Array(256), m = d < 12 ? 2 ** d : q;
    let pos = 0;
    for (let i = 0; i < 256; i++) { let a = 0; for (let j = 0; j < d; j++, pos++) a |= ((B[pos >> 3] >> (pos & 7)) & 1) << j; F[i] = a % m; }
    return F;
  };
  const vecEncode = (v, d) => P.concat(...v.map((f) => K.byteEncode(f, d)));
  const vecDecode = (B, k, d) => Array.from({ length: k }, (_, i) => K.byteDecode(B.slice(32 * d * i, 32 * d * (i + 1)), d));
  /** Â[i][j] = SampleNTT(ρ ‖ j ‖ i) */
  K.matrix = (rho, k) => Array.from({ length: k }, (_, i) => Array.from({ length: k }, (_, j) => K.sampleNtt(P.concat(rho, [j, i]))));
  const sampleVec = (seed, N0, k, eta) => Array.from({ length: k }, (_, i) => K.cbd(K.prf(eta, seed, N0 + i), eta));
  /** Â∘v̂ (or Âᵀ∘v̂) in the NTT domain */
  const matVec = (A, v, transpose) => A.map((_, i) => {
    let acc = new Array(256).fill(0);
    for (let j = 0; j < v.length; j++) acc = add(acc, K.multiplyNtts(transpose ? A[j][i] : A[i][j], v[j]));
    return acc;
  });
  const dot = (a, b) => { let acc = new Array(256).fill(0); for (let j = 0; j < a.length; j++) acc = add(acc, K.multiplyNtts(a[j], b[j])); return acc; };
  const centred = (f) => f.map((v) => (v > q / 2 ? v - q : v));
  const range = (v) => { let lo = Infinity, hi = -Infinity; for (const f of v) for (const c of centred(f)) { if (c < lo) lo = c; if (c > hi) hi = c; } return [lo, hi]; };

  /** Algorithm 13: K-PKE.KeyGen */
  K.pkeKeyGen = (p, d, trace) => {
    const [rho, sigma] = K.G(P.concat(d, [p.k]));
    trace.push(step('seeds', `(ρ, σ) = G(d ‖ ${p.k}): ρ = ${P.hex(rho).slice(0, 16)}… is public and seeds the matrix; σ = ${P.hex(sigma).slice(0, 16)}… is secret and seeds the noise.`, { rho, sigma }));
    const A = K.matrix(rho, p.k);
    const rej = A.flat().reduce((n, f) => n + f.rejected, 0);
    trace.push(step('matrix', `Â is a ${p.k}×${p.k} matrix of polynomials sampled straight into the NTT domain from SHAKE128(ρ ‖ j ‖ i); ${rej} candidates of 12 bits were ${q} or more and were rejected.`, { A: A.map((r) => r.map((f) => f.slice())), rejected: rej }));
    const s = sampleVec(sigma, 0, p.k, p.eta1), e = sampleVec(sigma, p.k, p.k, p.eta1);
    trace.push(step('secret', `s is ${p.k} small polynomials from CBD_${p.eta1}(PRF(σ, 0…${p.k - 1})); every coefficient lies in [${range(s).join(', ')}].`, { s: s.map(centred), eta: p.eta1 }));
    trace.push(step('error', `e is ${p.k} more small polynomials from CBD_${p.eta1}(PRF(σ, ${p.k}…${2 * p.k - 1})), coefficients in [${range(e).join(', ')}].`, { e: e.map(centred), eta: p.eta1 }));
    const sh = s.map(K.ntt), eh = e.map(K.ntt);
    trace.push(step('ntt', `ŝ = NTT(s) and ê = NTT(e): small polynomials become ones that look uniform mod ${q}, ready for fast products.`, { sHat: sh, eHat: eh }));
    const th = add2(matVec(A, sh), eh);
    trace.push(step('public', `t̂ = Â∘ŝ + ê: the learning-with-errors sample. Without e this would be linear algebra; with it, finding s is the Module-LWE problem.`, { tHat: th }));
    const ek = P.concat(vecEncode(th, 12), rho), dk = vecEncode(sh, 12);
    trace.push(step('encode', `ek_PKE = ByteEncode₁₂(t̂) ‖ ρ is ${ek.length} bytes; dk_PKE = ByteEncode₁₂(ŝ) is ${dk.length} bytes.`, { ekLen: ek.length, dkLen: dk.length }));
    return { ek, dk, A, s, e, sHat: sh, tHat: th };
  };
  const add2 = (a, b) => a.map((f, i) => add(f, b[i]));

  /** Algorithm 14: K-PKE.Encrypt */
  K.pkeEncrypt = (p, ek, m, r, trace) => {
    const k = p.k, tHat = vecDecode(ek.slice(0, 384 * k), k, 12), rho = ek.slice(384 * k, 384 * k + 32);
    const A = K.matrix(rho, k);
    trace.push(step('enc-matrix', `The encrypter rebuilds Â from ρ = ${P.hex(rho).slice(0, 16)}… and reads t̂ from ek.`, { tHat }));
    const y = sampleVec(r, 0, k, p.eta1), e1 = sampleVec(r, k, k, p.eta2), e2 = K.cbd(K.prf(p.eta2, r, 2 * k), p.eta2);
    trace.push(step('enc-noise', `From the seed r: y (CBD_${p.eta1}), e₁ (CBD_${p.eta2}) and e₂ (CBD_${p.eta2}), all small; y in [${range(y).join(', ')}].`, { y: y.map(centred), e1: e1.map(centred), e2: centred(e2) }));
    const yh = y.map(K.ntt);
    const u = add2(matVec(A, yh, true).map(K.invNtt), e1);
    trace.push(step('enc-u', `u = NTT⁻¹(Âᵀ∘ŷ) + e₁: ${k} polynomials that hide y the way t̂ hides s.`, { u }));
    const mu = K.byteDecode(m, 1).map((b) => K.decompress(b, 1));
    trace.push(step('enc-mu', `μ = Decompress₁(m): each of the 256 message bits becomes 0 or ${K.decompress(1, 1)} (about q/2).`, { mu, bits: K.byteDecode(m, 1) }));
    const v = add(add(K.invNtt(dot(tHat, yh)), e2), mu);
    trace.push(step('enc-v', `v = NTT⁻¹(t̂ᵀ∘ŷ) + e₂ + μ: the message rides on top of a value only the holder of s can cancel.`, { v }));
    const uc = u.map((f) => f.map((x) => K.compress(x, p.du))), vc = v.map((x) => K.compress(x, p.dv));
    const c1 = vecEncode(uc, p.du), c2 = K.byteEncode(vc, p.dv);
    trace.push(step('enc-compress', `Compress u to ${p.du} bits and v to ${p.dv} bits a coefficient: c₁ is ${c1.length} bytes and c₂ is ${c2.length}. Rounding adds a little more noise.`, { uCompressed: uc, vCompressed: vc, du: p.du, dv: p.dv }));
    return P.concat(c1, c2);
  };
  /** Algorithm 15: K-PKE.Decrypt */
  K.pkeDecrypt = (p, dk, c, trace) => {
    const k = p.k, split = 32 * p.du * k;
    const u = vecDecode(c.slice(0, split), k, p.du).map((f) => f.map((y) => K.decompress(y, p.du)));
    const v = K.byteDecode(c.slice(split), p.dv).map((y) => K.decompress(y, p.dv));
    const sHat = vecDecode(dk, k, 12);
    const w = sub(v, K.invNtt(dot(sHat, u.map(K.ntt))));
    const m = K.byteEncode(w.map((x) => K.compress(x, 1)), 1);
    const bits = K.byteDecode(m, 1);
    const noise = w.map((x, i) => P.centre(x - bits[i] * 1665, q));
    const worst = noise.reduce((a, b) => Math.max(a, Math.abs(b)), 0);
    trace.push(step('dec-w', `w = v′ − NTT⁻¹(ŝᵀ∘NTT(u′)) = μ + (e·y − s·e₁ + e₂ + rounding). The largest noise is ${worst}; ${worst < 832 ? 'it is inside' : 'it reaches'} the ±832 at which a bit would flip.`, { w, noise, worst, limit: 832 }));
    trace.push(step('dec-m', `Each coefficient of w is rounded to 0 or 1 by whether it lies nearer 0 or q/2: m′ = ${P.hex(m).slice(0, 16)}….`, { m, bits }));
    return m;
  };

  /** Algorithm 16 and 19: ML-KEM.KeyGen, from 32-byte seeds d and z */
  K.keyGen = (set, seeds) => {
    const p = K.params(set), trace = [];
    const d = (seeds && seeds.d) || P.randomBytes(32), z = (seeds && seeds.z) || P.randomBytes(32);
    trace.push(step('kg-start', `${p.name}: k = ${p.k}, η₁ = ${p.eta1}, η₂ = ${p.eta2}, d_u = ${p.du}, d_v = ${p.dv}. Seeds d = ${P.hex(d).slice(0, 16)}… and z = ${P.hex(z).slice(0, 16)}….`, { params: p, d, z }));
    const pke = K.pkeKeyGen(p, d, trace);
    const h = K.H(pke.ek), dk = P.concat(pke.dk, pke.ek, h, z);
    trace.push(step('kg-dk', `dk = dk_PKE ‖ ek ‖ H(ek) ‖ z, ${dk.length} bytes; z is kept for implicit rejection.`, { h, dkLen: dk.length }));
    return { ek: pke.ek, dk, d, z, trace, vectors: { A: pke.A, s: pke.s, e: pke.e, tHat: pke.tHat } };
  };
  /** Algorithms 17 and 20: Encaps */
  K.encaps = (set, ek, opts) => {
    const p = K.params(set), trace = [];
    const chk = K.checkEk(p, ek);
    if (!chk.ok) throw new Error(chk.why);
    const m = (opts && opts.m) || P.randomBytes(32);
    const [Kk, r] = K.G(P.concat(m, K.H(ek)));
    trace.push(step('enc-start', `Pick m = ${P.hex(m).slice(0, 16)}…; (K, r) = G(m ‖ H(ek)) gives the shared key K = ${P.hex(Kk).slice(0, 16)}… and the encryption randomness r.`, { m, K: Kk, r }));
    const c = K.pkeEncrypt(p, ek, m, r, trace);
    trace.push(step('enc-done', `The ciphertext c is ${c.length} bytes; both sides will hold K.`, { cLen: c.length }));
    return { K: Kk, c, m, trace };
  };
  /** Algorithms 18 and 21: Decaps, re-encrypting and comparing (the FO transform), with implicit rejection */
  K.decaps = (set, dk, c) => {
    const p = K.params(set), trace = [], k = p.k;
    if (c.length !== p.sizes.c) throw new Error(`${p.name} ciphertexts are ${p.sizes.c} bytes`);
    const chk = K.checkDk(p, dk);
    if (!chk.ok) throw new Error(chk.why);
    const dkPke = dk.slice(0, 384 * k), ek = dk.slice(384 * k, 768 * k + 32), h = dk.slice(768 * k + 32, 768 * k + 64), z = dk.slice(768 * k + 64);
    const m2 = K.pkeDecrypt(p, dkPke, c, trace);
    const [K2, r2] = K.G(P.concat(m2, h));
    const Kbar = K.J(P.concat(z, c));
    const sub2 = [];
    const c2 = K.pkeEncrypt(p, ek, m2, r2, sub2);
    const same = P.eqBytes(c, c2);
    trace.push(step('dec-reencrypt', `Re-encrypt m′ with r′ from G(m′ ‖ H(ek)): the result ${same ? 'equals' : 'differs from'} c.`, { same, sub: sub2 }));
    trace.push(same
      ? step('dec-accept', `Accepted: K = ${P.hex(K2).slice(0, 16)}…, the same key the encrypter derived.`, { K: K2 })
      : step('dec-reject', `Rejected without saying so: K = J(z ‖ c) = ${P.hex(Kbar).slice(0, 16)}…, a key that looks random and tells an attacker nothing.`, { K: Kbar }));
    return { K: same ? K2 : Kbar, rejected: !same, trace };
  };
  /** the encapsulation-key check of section 7.2: length and every coefficient below q */
  K.checkEk = (set, ek) => {
    const p = typeof set === 'object' ? set : K.params(set);
    if (ek.length !== p.sizes.ek) return { ok: false, why: `${p.name} encapsulation keys are ${p.sizes.ek} bytes` };
    for (let i = 0; i < p.k; i++) {
      const B = ek.slice(384 * i, 384 * (i + 1));
      if (!P.eqBytes(K.byteEncode(K.byteDecode(B, 12), 12), B)) return { ok: false, why: 'a coefficient of t̂ is not below q' };
    }
    return { ok: true };
  };
  /** the decapsulation-key check of section 7.3: length and the stored hash of ek */
  K.checkDk = (set, dk) => {
    const p = typeof set === 'object' ? set : K.params(set), k = p.k;
    if (dk.length !== p.sizes.dk) return { ok: false, why: `${p.name} decapsulation keys are ${p.sizes.dk} bytes` };
    if (!P.eqBytes(K.H(dk.slice(384 * k, 768 * k + 32)), dk.slice(768 * k + 32, 768 * k + 64))) return { ok: false, why: 'the hash of ek stored in dk does not match' };
    return { ok: true };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
