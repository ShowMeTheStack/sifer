// Fault injection on RSA-CRT signing. The signer computes s_p = m^(d mod p−1) mod p and s_q = m^(d mod q−1) mod q
// and joins them by Garner's formula. If a glitch spoils s_q only, the signature s is still right mod p but wrong
// mod q, so s^e − m is a multiple of p and not of q: gcd(s^e − m, N) = p. One faulty signature factors N.
//   S.SC.Fault.key({bits, seed}) -> {n, e, d, p, q, dp, dq, qinv}   (S.RSA's key if that engine provides one)
//   S.SC.Fault.sign(key, m, {fault: {half: 'p' | 'q', bit}, check}) -> {s, sp, sq, faulty, released, trace}
//   S.SC.Fault.attack({n, e}, m, s) -> {p, q, ok, trace}
(function (S) {
  'use strict';
  const C = (S.SC = S.SC || {});
  const F = (C.Fault = {});
  const modpow = (b, e, m) => { let r = 1n; b %= m; if (b < 0n) b += m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
  const gcd = (a, b) => { a = a < 0n ? -a : a; while (b) [a, b] = [b, a % b]; return a; };
  const inv = (a, m) => { let [r0, r1, s0, s1] = [((a % m) + m) % m, m, 1n, 0n]; while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; } if (r0 !== 1n) throw new Error('not invertible'); return ((s0 % m) + m) % m; };
  const short = (v) => { const s = v.toString(); return s.length > 22 ? s.slice(0, 8) + '…' + s.slice(-8) + ` (${s.length} digits)` : s; };
  F.modpow = modpow; F.gcd = gcd; F.inv = inv;
  const randBig = (r, bits) => { let v = 0n; for (let i = 0; i < bits; i += 16) v = (v << 16n) | BigInt(r.int(65536)); return v & ((1n << BigInt(bits)) - 1n); };
  const isPrime = (n, r) => {
    if (n < 2n) return false;
    for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) { if (n === p) return true; if (n % p === 0n) return false; }
    let d = n - 1n, s = 0;
    while (!(d & 1n)) { d >>= 1n; s++; }
    for (let i = 0; i < 24; i++) {
      const a = 2n + (randBig(r, 64) % (n - 3n));
      let x = modpow(a, d, n);
      if (x === 1n || x === n - 1n) continue;
      let comp = true;
      for (let j = 1; j < s && comp; j++) { x = (x * x) % n; if (x === n - 1n) comp = false; }
      if (comp) return false;
    }
    return true;
  };
  const prime = (r, bits, e) => { for (;;) { const c = randBig(r, bits) | (1n << BigInt(bits - 1)) | (1n << BigInt(bits - 2)) | 1n; if (isPrime(c, r) && gcd(c - 1n, e) === 1n) return c; } };
  const complete = (k) => {
    const n = BigInt(k.n), e = BigInt(k.e), d = BigInt(k.d), p = BigInt(k.p), q = BigInt(k.q);
    return { n, e, d, p, q, dp: d % (p - 1n), dq: d % (q - 1n), qinv: inv(q, p) };
  };
  /** an RSA key: from S.RSA if it is there and gives one, otherwise a small one made here (seeded) */
  F.key = (o = {}) => {
    if (o.key) return complete(o.key);
    if (S.RSA && typeof S.RSA.keyGen === 'function' && !o.own) {
      try { const k = S.RSA.keyGen(o.bits || 512, { seed: o.seed }); const kk = k && (k.sk || k.priv || k); if (kk && kk.p && kk.q && kk.d) { const c = complete(Object.assign({ e: 65537n }, kk, { n: kk.n || BigInt(kk.p) * BigInt(kk.q) })); if (c.n === c.p * c.q && modpow(2n, c.e * c.d, c.n) === 2n) return c; } } catch (err) { /* fall back below */ }
    }
    const bits = o.bits || 512, r = C.rng(o.seed || 77), e = 65537n;
    const p = prime(r, bits >> 1, e);
    let q;
    do q = prime(r, bits - (bits >> 1), e); while (q === p);
    return complete({ n: p * q, e, d: inv(e, (p - 1n) * (q - 1n)), p, q });
  };
  F.sign = (key, m, o = {}) => {
    m = BigInt(m);
    const k = complete(key), trace = [];
    let sp = modpow(m, k.dp, k.p), sq = modpow(m, k.dq, k.q);
    trace.push(F.step('crt-halves', `s_p = m^(d mod (p−1)) mod p = ${short(sp)}, s_q = m^(d mod (q−1)) mod q = ${short(sq)}: two half-size exponentiations, about four times faster than one.`, { sp, sq }));
    const f = o.fault;
    if (f) {
      const bit = BigInt(f.bit != null ? f.bit : 5);
      if (f.half === 'p') sp ^= 1n << bit; else sq ^= 1n << bit;
      trace.push(F.step('fault', `A glitch flips bit ${bit} of s_${f.half === 'p' ? 'p' : 'q'} while it sits in a register.`, { half: f.half || 'q', bit: Number(bit) }));
    }
    const h = (k.qinv * (sp - sq)) % k.p, s = sq + ((h + k.p) % k.p) * k.q;
    trace.push(F.step('garner', `Garner: s = s_q + q·(q⁻¹(s_p − s_q) mod p) = ${short(s)}.`, { s }));
    const good = modpow(s, k.e, k.n) === m % k.n;
    let released = true;
    if (o.check) {
      released = good;
      trace.push(F.step('check', good ? 'The signer checks s^e ≡ m before releasing it: fine.' : 'The signer checks s^e ≡ m (mod N), sees it fail, and releases nothing: the countermeasure.', { good }));
    }
    return { s: released ? s : null, sp, sq, faulty: !good, released, trace };
  };
  F.attack = (pub, m, s) => {
    const n = BigInt(pub.n), e = BigInt(pub.e);
    m = BigInt(m); s = BigInt(s);
    const t = (modpow(s, e, n) - (m % n) + n) % n, g = gcd(t, n), ok = g > 1n && g < n;
    const trace = [
      F.step('fault-diff', `s^e − m mod N = ${short(t)}: zero mod one prime (that half was right) and not mod the other.`, { t }),
      F.step(ok ? 'fault-factor' : 'fault-none', ok ? `gcd(s^e − m, N) = ${short(g)}: a prime factor. N = ${short(g)} × ${short(n / g)}, and the private key follows.` : `gcd(s^e − m, N) = ${short(g)}: this signature is not faulty in one half only.`, { g }),
    ];
    return { p: ok ? g : null, q: ok ? n / g : null, ok, trace };
  };
  F.step = (kind, say, data) => Object.assign({ kind, say }, data || {});
})(globalThis.Sifer = globalThis.Sifer || {});
