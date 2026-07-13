// The SHA-2 family: SHA-224 and SHA-256 on 32-bit words (the traced compression function is S.SHA256's), and
// SHA-384, SHA-512 and SHA-512/256 on 64-bit words, each held as a pair of 32-bit halves. The constants are not
// typed in: they are computed as the standard defines them, from the square and cube roots of the first primes.
//   S.Hash.SHA2.K512 / IV512 / IV384 / IV224 / IV512_256  constants as [hi, lo, hi, lo, …]
//   S.Hash.SHA2.compress256(state8, block64[, traced]) -> state | S.SHA256.compress's result with .state
//   S.Hash.SHA2.compress512(state16, block128[, traced]) -> state | {state, rounds: [{t, T1, T2, regs}], trace}
//   S.Hash.SHA2.roots() -> the trace of how the constants come from the primes
//   S.Hash.get('sha224' | 'sha256' | 'sha384' | 'sha512' | 'sha512-256')
(function (S) {
  'use strict';
  const H = (S.Hash = S.Hash || {});
  const { step, h8, rotr, readBE, wordsBE } = H;
  const S2 = (H.SHA2 = {});

  // ---- constants from the primes
  const primes = [];
  for (let n = 2; primes.length < 80; n++) if (primes.every((p) => n % p)) primes.push(n);
  const iroot = (n, k) => { // floor(n^(1/k)) for BigInt n by Newton's method
    if (n < 2n) return n;
    let x = 1n << BigInt(Math.ceil(n.toString(2).length / k) + 1);
    for (;;) { const y = ((BigInt(k) - 1n) * x + n / x ** BigInt(k - 1)) / BigInt(k); if (y >= x) return x; x = y; }
  };
  /** the first `bits` bits of the fractional part of p^(1/k) */
  const frac = (p, k, bits) => iroot(BigInt(p) << BigInt(bits * k), k) & ((1n << BigInt(bits)) - 1n);
  const split = (v) => [Number(v >> 32n), Number(v & 0xffffffffn)];
  S2.primes = primes;
  S2.K512 = primes.flatMap((p) => split(frac(p, 3, 64)));
  S2.IV512 = primes.slice(0, 8).flatMap((p) => split(frac(p, 2, 64)));
  S2.IV384 = primes.slice(8, 16).flatMap((p) => split(frac(p, 2, 64)));
  S2.K256 = primes.slice(0, 64).map((p) => Number(frac(p, 3, 32)));
  S2.IV256 = primes.slice(0, 8).map((p) => Number(frac(p, 2, 32)));
  S2.IV224 = primes.slice(8, 16).map((p) => Number(frac(p, 2, 64) & 0xffffffffn));
  S2.roots = () => [
    step('k', `K${0} is the first 32 bits of the fractional part of the cube root of 2: ∛2 = 1.2599…, and 0.2599… × 2³² = ${h8(S2.K256[0])}.`, { k: S2.K256[0] }),
    step('iv', `H0 is the fractional part of √2 = 1.41421…, as 32 bits: ${h8(S2.IV256[0])}. Nobody chose these numbers, so nobody could have hidden a weakness in them.`, { iv: S2.IV256[0] }),
    step('k512', `SHA-512 takes 64 bits of the same roots, for the first 80 primes: K0 = ${h8(S2.K512[0])}${h8(S2.K512[1])}.`, {}),
    step('iv384', `SHA-384 starts from the square roots of the 9th to 16th primes (23 … 53), so its digest is not a prefix of SHA-512's.`, {}),
  ];

  // ---- SHA-256 and SHA-224 (fast path here, the traced compression from S.SHA256)
  const W = new Uint32Array(64);
  S2.compress256 = (st, block, traced) => {
    if (traced && S.SHA256) { const r = S.SHA256.compress(st, block); r.state = r.H; return r; }
    for (let t = 0; t < 16; t++) W[t] = readBE(block, 4 * t);
    for (let t = 16; t < 64; t++) {
      const x = W[t - 15], y = W[t - 2];
      W[t] = (W[t - 16] + (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) + W[t - 7] + (rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10))) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = st;
    const K = S2.K256;
    for (let t = 0; t < 64; t++) {
      const T1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + W[t]) >>> 0;
      const T2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + T1) >>> 0; d = c; c = b; b = a; a = (T1 + T2) >>> 0;
    }
    return [a, b, c, d, e, f, g, h].map((v, i) => (v + st[i]) >>> 0);
  };
  const words = (s) => s.map(h8).join(' ');
  H.register(H.md({ name: 'sha256', iv: S2.IV256, blockLen: 64, outLen: 32, compress: S2.compress256, output: (s) => wordsBE(s), wordHex: words }));
  H.register(H.md({ name: 'sha224', iv: S2.IV224, blockLen: 64, outLen: 28, compress: S2.compress256, output: (s) => wordsBE(s.slice(0, 7)), wordHex: words, truncate: true }));

  // ---- 64-bit words as [hi, lo] halves
  const rr = (hi, lo, n) => { // rotate right by n (0 < n < 64): returns [hi, lo]
    if (n >= 32) { const t = hi; hi = lo; lo = t; n -= 32; }
    if (n === 0) return [hi >>> 0, lo >>> 0];
    return [((hi >>> n) | (lo << (32 - n))) >>> 0, ((lo >>> n) | (hi << (32 - n))) >>> 0];
  };
  const sr = (hi, lo, n) => [hi >>> n, ((lo >>> n) | (hi << (32 - n))) >>> 0]; // shift right, n < 32
  const x3 = (a, b, c) => [(a[0] ^ b[0] ^ c[0]) >>> 0, (a[1] ^ b[1] ^ c[1]) >>> 0];
  const add = (...xs) => { let lo = 0, hi = 0; for (const x of xs) { lo += x[1]; hi += x[0]; } hi += Math.floor(lo / 4294967296); return [hi >>> 0, lo >>> 0]; };
  const h16 = (p) => h8(p[0]) + h8(p[1]);
  S2.h16 = h16;
  S2.compress512 = (st, block, traced) => {
    const Wp = [];
    for (let t = 0; t < 16; t++) Wp.push([readBE(block, 8 * t), readBE(block, 8 * t + 4)]);
    for (let t = 16; t < 80; t++) {
      const x = Wp[t - 15], y = Wp[t - 2];
      const s0 = x3(rr(x[0], x[1], 1), rr(x[0], x[1], 8), sr(x[0], x[1], 7));
      const s1 = x3(rr(y[0], y[1], 19), rr(y[0], y[1], 61), sr(y[0], y[1], 6));
      Wp.push(add(Wp[t - 16], s0, Wp[t - 7], s1));
    }
    const r = []; for (let i = 0; i < 8; i++) r.push([st[2 * i], st[2 * i + 1]]);
    let [a, b, c, d, e, f, g, h] = r;
    const rounds = traced ? [] : null, trace = traced ? [] : null;
    for (let t = 0; t < 80; t++) {
      const S1 = x3(rr(e[0], e[1], 14), rr(e[0], e[1], 18), rr(e[0], e[1], 41));
      const ch = [((e[0] & f[0]) ^ (~e[0] & g[0])) >>> 0, ((e[1] & f[1]) ^ (~e[1] & g[1])) >>> 0];
      const T1 = add(h, S1, ch, [S2.K512[2 * t], S2.K512[2 * t + 1]], Wp[t]);
      const S0 = x3(rr(a[0], a[1], 28), rr(a[0], a[1], 34), rr(a[0], a[1], 39));
      const maj = [((a[0] & b[0]) ^ (a[0] & c[0]) ^ (b[0] & c[0])) >>> 0, ((a[1] & b[1]) ^ (a[1] & c[1]) ^ (b[1] & c[1])) >>> 0];
      const T2 = add(S0, maj);
      h = g; g = f; f = e; e = add(d, T1); d = c; c = b; b = a; a = add(T1, T2);
      if (traced) {
        rounds.push({ t, T1: h16(T1), T2: h16(T2), regs: [a, b, c, d, e, f, g, h].map(h16) });
        trace.push(step('round', `Round ${t}: T1 = ${h16(T1)}, T2 = ${h16(T2)}; the new a is ${h16(a)} and the new e is ${h16(e)}.`, { t }));
      }
    }
    const out = [];
    [a, b, c, d, e, f, g, h].forEach((v, i) => { const s = add(v, r[i]); out.push(s[0], s[1]); });
    if (!traced) return out;
    trace.push(step('feed-forward', `Adding the input chaining value (64-bit words, mod 2⁶⁴) gives ${words(out.slice(0, 4))} …`, { state: out }));
    return { state: out, W: Wp.map(h16), rounds, trace };
  };
  const w64 = (s) => { const o = []; for (let i = 0; i < s.length; i += 2) o.push(h8(s[i]) + h8(s[i + 1])); return o.join(' '); };
  const md512 = (name, iv, outLen) => H.md({ name, iv, blockLen: 128, lenBytes: 16, outLen, compress: S2.compress512, output: (s) => wordsBE(s).slice(0, outLen), wordHex: w64, truncate: outLen < 64 });
  H.register(md512('sha512', S2.IV512, 64));
  H.register(md512('sha384', S2.IV384, 48));
  // SHA-512/t: the IV is SHA-512, started from IV512 ⊕ a5a5…, of the text "SHA-512/256" (FIPS 180-4, 5.3.6)
  S2.ivFor = (t) => {
    const iv = S2.IV512.map((v) => (v ^ 0xa5a5a5a5) >>> 0);
    return H.get('sha512').run(H.utf8('SHA-512/' + t), { iv }).state;
  };
  S2.IV512_256 = S2.ivFor(256);
  H.register(md512('sha512-256', S2.IV512_256, 32));
})(globalThis.Sifer = globalThis.Sifer || {});
