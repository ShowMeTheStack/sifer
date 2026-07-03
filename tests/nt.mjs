// Number theory and finite fields: thousands of random cases against independent references, and GCM's GF(2^128)
// ghash against node:crypto's AES-GCM tag.  node tests/nt.mjs
import { createCipheriv } from 'node:crypto';
import { load, harness, rng } from './load.mjs';
const S = load(['core']), t = harness('nt'), N = S.NT, GF = S.GF;
const R = rng(20260218);
const randBig = (bits) => { let v = 0n; for (let i = 0; i < bits; i += 30) v = (v << 30n) | BigInt((R() * (1 << 30)) >>> 0); return v & ((1n << BigInt(bits)) - 1n); };
const randIn = (n) => randBig(N.bitLength(n) + 8) % n;

// ---- gcd, egcd, inverse
for (let i = 0; i < 3000; i++) {
  const a = randBig(40) + 1n, b = randBig(40) + 1n;
  const e = N.egcd(a, b);
  t.ok(e.g === N.gcd(a, b), 'gcd matches egcd');
  t.ok(a * e.x + b * e.y === e.g, 'Bezout: a·x + b·y = g');
  const n = randBig(32) + 2n, x = randIn(n);
  if (N.gcd(x, n) === 1n) { const inv = N.inv(x, n); t.ok(N.mod(x * inv, n) === 1n, 'inverse times x is 1'); t.ok(N.inverse(x, n).inv === inv, 'inverse() agrees with inv()'); }
  else t.ok(N.inverse(x, n).inv === null, 'no inverse when not coprime');
}

// ---- modular exponentiation against a slow reference and against the ModExp engine
for (let i = 0; i < 2000; i++) {
  const n = randBig(24) + 2n, b = randIn(n), e = randBig(16);
  let ref = 1n % n; for (let k = 0n; k < e; k++) ref = (ref * b) % n;
  t.ok(N.pow(b, e, n) === ref, 'pow against repeated multiplication');
}
for (let i = 0; i < 300; i++) { const n = randBig(60) + 3n, b = randIn(n), e = randBig(40) + 1n; t.ok(N.pow(b, e, n) === S.ModExp.pow(b, e, n).value, 'pow agrees with the square-and-multiply engine'); }

// ---- CRT against brute force for small coprime moduli
for (let i = 0; i < 2000; i++) {
  const ms = [], used = new Set();
  while (ms.length < 3) { const m = 2n + BigInt((R() * 40) | 0); if ([...ms].every((x) => N.gcd(x, m) === 1n)) ms.push(m); }
  const M = ms.reduce((a, b) => a * b, 1n), target = randIn(M);
  const rs = ms.map((m) => target % m);
  const x = N.crt(rs, ms).x;
  // brute force: the unique residue below M matching every congruence
  let brute = null; for (let v = 0n; v < M; v++) if (ms.every((m, j) => v % m === rs[j])) { brute = v; break; }
  t.ok(x === brute, 'CRT matches brute force');
  t.ok(ms.every((m, j) => x % m === rs[j]), 'CRT solution satisfies each congruence');
}
// crtGeneral on moduli that need not be coprime
for (let i = 0; i < 500; i++) {
  const m1 = 2n + BigInt((R() * 30) | 0), m2 = 2n + BigInt((R() * 30) | 0), v = randBig(16);
  const r = N.crtGeneral([v % m1, v % m2], [m1, m2]);
  t.ok(r && (v - r.x) % N.gcd(m1, m2) === 0n && r.x % m1 === v % m1 && r.x % m2 === v % m2, 'crtGeneral solves consistent systems');
}

// ---- Miller–Rabin against a sieve up to 10^6
const LIM = 1000000, sieve = new Uint8Array(LIM + 1);
for (let i = 2; i * i <= LIM; i++) if (!sieve[i]) for (let j = i * i; j <= LIM; j += i) sieve[j] = 1;
const isPrime = (n) => n >= 2 && !sieve[n];
let mism = 0;
for (let i = 0; i < 20000; i++) { const n = 2 + ((R() * (LIM - 2)) | 0); if (N.isProbablePrime(n) !== isPrime(n)) mism++; }
t.ok(mism === 0, 'Miller–Rabin matches the sieve on 20000 numbers below 10^6 (' + mism + ' mismatches)');
// the deterministic bases catch every odd composite in a stretch
for (let n = 3; n < 20000; n += 2) t.ok(N.millerRabin(n, 8).probablePrime === isPrime(n), 'millerRabin on ' + n);
// Fermat liars: Carmichael numbers pass Fermat for every coprime base but Miller–Rabin exposes them
for (const c of N.carmichael(100000)) { t.ok(!isPrime(Number(c)), c + ' is composite'); t.ok(!N.isProbablePrime(c), 'Miller–Rabin exposes the Carmichael number ' + c); }

// ---- factoring and phi
for (let i = 0; i < 400; i++) {
  const n = randBig(44) + 2n, f = N.factor(n);
  let prod = 1n; for (const [p, k] of f) { t.ok(N.isProbablePrime(p), 'factor ' + p + ' is prime'); prod *= p ** BigInt(k); }
  t.ok(prod === n, 'the factors multiply back to n');
}
for (let i = 0; i < 300; i++) { const n = randBig(20) + 2n; let count = 0n; for (let a = 1n; a < n; a++) if (N.gcd(a, n) === 1n) count++; t.ok(N.phi(n).phi === count, 'phi counts the units of ' + n); }
// order divides the group order; a generator has full order
for (let i = 0; i < 300; i++) { const p = N.randomPrime(16).prime, a = 2n + randIn(p - 3n); const ord = N.order(a, p).order; t.ok((p - 1n) % ord === 0n, 'order divides p − 1'); t.ok(N.pow(a, ord, p) === 1n, 'a^order = 1'); }

// ---- integer roots and continued fractions
for (let i = 0; i < 1000; i++) {
  const r = randBig(40) + 1n, k = 2n + BigInt((R() * 4) | 0);
  t.ok(N.iroot(r ** k, k).root === r && N.iroot(r ** k, k).exact, 'exact k-th root of a k-th power');
  const off = r ** k + 1n, ir = N.iroot(off, k); t.ok(ir.root === r && !ir.exact, 'floor root just above a power');
  t.ok(N.isqrt(r * r) === r && N.isqrt(r * r + 1n) === r, 'isqrt');
}
for (let i = 0; i < 500; i++) { const a = randBig(24) + 1n, b = randBig(24) + 1n, cf = N.contfrac(a, b); const last = cf.convergents[cf.convergents.length - 1]; const g = N.gcd(a, b); t.ok(last.h === a / g && last.k === b / g, 'the last convergent is a/b in lowest terms'); }

// ---- GF(p): inverses, Tonelli–Shanks square roots
for (let i = 0; i < 1000; i++) {
  const p = N.randomPrime(18).prime, F = GF.prime(p), a = randIn(p);
  if (a !== 0n) t.ok(F.mul(a, F.inv(a)) === 1n, 'GF(p) inverse');
  const sq = F.mul(a, a), r = F.sqrt(sq); t.ok(r !== null && F.mul(r, r) === sq, 'Tonelli–Shanks recovers a square root');
  const b = randIn(p); t.ok(F.isSquare(b) === (b === 0n || F.pow(b, (p - 1n) / 2n) === 1n), "Euler's criterion");
}

// ---- GF(2^m) multiplication against a reference (carry-less multiply then reduce by the modulus)
for (const m of [4, 8, 9, 12, 16, 32, 128]) {
  const F = GF.binary(m), f = F.f, mask = (1n << BigInt(m)) - 1n;
  const refMul = (a, b) => { let r = 0n; for (let i = 0n; b >> i; i++) if ((b >> i) & 1n) r ^= a << i; // then reduce
    for (let d = GF.poly.deg(r); d >= m; d = GF.poly.deg(r)) r ^= f << BigInt(d - m); return r; };
  const bigField = m > 16, muls = bigField ? 500 : 1500;
  for (let i = 0; i < muls; i++) {
    const a = randBig(m) & mask, b = randBig(m) & mask;
    t.ok(F.mul(a, b) === refMul(a, b), 'GF(2^' + m + ') mul against reference');
    if (m <= 16) t.ok(F.mulTrace(a, b).value === F.mul(a, b), 'mulTrace agrees with mul');
    if (a !== 0n && (!bigField || i < 60)) t.ok(F.mul(a, F.inv(a)) === 1n, 'GF(2^' + m + ') inverse');
  }
}
// an irreducible modulus has no proper factor; a reducible one does
t.ok(GF.poly.isIrreducible(GF.IRREDUCIBLE[8]), 'the AES modulus is irreducible');
t.ok(!GF.poly.isIrreducible(GF.poly.mul(GF.IRREDUCIBLE[4], 0b111n)), 'a product is reducible');

// ---- GCM GF(2^128) ghash against node:crypto
// For AES-GCM with a given key and 96-bit IV, H = AES_K(0^128), J0 = IV ‖ 0^31 1, the tag is
// GHASH_H(AAD, C) XOR AES_K(J0).  We compute GHASH with S.GF.gcm and the cipher with S.AES, and the tag must equal node's.
const aesBlock = (keyBytes, block) => S.AES.encrypt(block, keyBytes).out;
for (let i = 0; i < 40; i++) {
  const key = Uint8Array.from({ length: 16 }, () => (R() * 256) | 0);
  const iv = Uint8Array.from({ length: 12 }, () => (R() * 256) | 0);
  const aadLen = (R() * 40) | 0, ptLen = (R() * 80) | 0;
  const aad = Uint8Array.from({ length: aadLen }, () => (R() * 256) | 0);
  const pt = Uint8Array.from({ length: ptLen }, () => (R() * 256) | 0);
  const c = createCipheriv('aes-128-gcm', Buffer.from(key), Buffer.from(iv));
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(Buffer.from(pt)), c.final()]);
  const nodeTag = c.getAuthTag();
  // our side
  const H = aesBlock(key, new Uint8Array(16));
  const j0 = new Uint8Array(16); j0.set(iv); j0[15] = 1;
  const ghash = S.GF.gcm.ghash(H, aad, new Uint8Array(ct));
  const ekJ0 = aesBlock(key, j0);
  const tag = ghash.map((v, j) => v ^ ekJ0[j]);
  t.ok(Buffer.from(tag).equals(nodeTag), 'GCM tag from our GHASH + AES matches node ' + i);
  // the block multiply on its own: X·H reversed order consistency
  t.ok(S.GF.gcm.fromPoly(S.GF.gcm.toPoly(H)).every((v, j) => v === H[j]), 'gcm poly round trip');
}

t.done();
