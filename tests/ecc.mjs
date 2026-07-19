// Elliptic curves: the group law on every toy curve, the scalar-multiplication methods against each other, RFC 7748
// (X25519), RFC 8032 (Ed25519) and RFC 6979 (deterministic ECDSA, P-256) vectors, node:crypto both ways for ECDH,
// ECDSA and EdDSA over hundreds of random cases, and every attack recovering planted keys across seeds.
import { generateKeyPairSync, createPublicKey, createPrivateKey, diffieHellman, sign, verify, createHash, randomBytes } from 'node:crypto';
import { load, harness, rng } from './load.mjs';
const S = load(['core']), t = harness('ecc'), E = S.ECC, { hex, fromHex, utf8 } = S.bytes;
const b64 = (b) => Buffer.from(b).toString('base64url'), unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const big = (b) => E.bytesToBig(b), toB = (v, n) => E.bigToBytes(v, n);
const rand = rng(20261018), pick = (a) => a[Math.floor(rand() * a.length)];
const randBig = (n) => { let v = 0n; for (let i = 0; i < 40; i++) v = (v << 8n) | BigInt(Math.floor(rand() * 256)); return v % n; };

// ---- toy curves: points, counts, Hasse, structure, group law, Jacobian, scalar methods, encoding
for (const T of E.TOYS) {
  const { C, points, count, hasse, structure } = E.toyInfo(T.id), N = count.N;
  if (points) {
    t.ok(points.every(C.on), T.id + ': every listed point is on the curve');
    t.eq(BigInt(points.length + 1), N, T.id + ': point count matches the list');
    t.eq(structure.n1 * structure.n2, N, T.id + ': n1·n2 = #E');
    t.ok(structure.n1 % structure.n2 === 0n && (C.p - 1n) % structure.n2 === 0n, T.id + ': n2 divides n1 and p − 1');
    if (structure.n2 > 1n) {
      const { P1, P2, n1, n2 } = structure;
      t.ok(!!P2, T.id + ': a non-cyclic group names its second generator P2');
      if (P2) {
        t.eq(C.order(P1).order, n1, T.id + ': P1 has order n1'); t.eq(C.order(P2).order, n2, T.id + ': P2 has order n2');
        const key = (R) => (R ? R.x + ',' + R.y : 'O'), all = new Set();
        for (let i = 0n, A = null; i < n1; i++, A = C.add(A, P1)) for (let j = 0n, B = A; j < n2; j++, B = C.add(B, P2)) all.add(key(B));
        t.eq(BigInt(all.size), N, T.id + ': a·P1 + b·P2 reaches every point once (Z_n1 × Z_n2)');
      }
    }
  }
  t.ok(hasse.N >= hasse.lo && hasse.N <= hasse.hi, T.id + ': Hasse bound');
  if (T.n) t.eq(N, BigInt(T.n) * BigInt(T.h), T.id + ': the stated order is the counted order');
  if (T.n && C.p <= 20000n) t.eq(C.count().N, BigInt(points.length + 1), T.id + ': stated order equals brute force');
  if (C.G) { t.ok(C.on(C.G), T.id + ': G on the curve'); t.ok(C.mul(C.n, C.G) === null, T.id + ': n·G = O'); }
  const sample = points ? points : [C.G];
  for (let i = 0; i < 60; i++) {
    const P = pick(sample), Q = pick(sample), R = pick(sample);
    t.ok(C.eq(C.add(C.add(P, Q), R), C.add(P, C.add(Q, R))), T.id + ': associativity');
    t.ok(C.eq(C.add(P, Q), C.add(Q, P)), T.id + ': commutativity');
    t.ok(C.add(P, C.neg(P)) === null, T.id + ': P + (−P) = O');
    t.ok(C.eq(C.addT(P, Q).R, C.add(P, Q)), T.id + ': traced addition agrees');
    t.ok(C.eq(C.fromJ(C.jadd(C.toJ(P), C.toJ(Q))), C.add(P, Q)), T.id + ': Jacobian addition agrees');
    t.ok(C.eq(C.fromJ(C.jaddMixed(C.jdbl(C.toJ(P)), Q)), C.add(C.dbl(P), Q)), T.id + ': Jacobian doubling and mixed addition agree');
    if (C.p < 2000n) { const o = C.order(P).order; t.ok(N % o === 0n && C.mul(o, P) === null, T.id + ': order divides #E and kills P'); }
    const k = randBig(3n * N) + 1n, ref = C.mul(k, P);
    for (const m of ['ltr', 'rtl', 'ladder']) t.ok(C.eq(E.scalar[m](C, k, P).R, ref), `${T.id}: ${m} agrees with mul`);
    t.ok(C.eq(E.scalar.wnaf(C, k, P, 2 + (i % 4)).R, ref), T.id + ': wNAF agrees with mul');
    const enc = C.compress(P).bytes;
    t.ok(C.eq(C.decode(enc).P, P), T.id + ': compress and decompress');
    t.ok(C.eq(C.decode(C.encode(P)).P, P), T.id + ': uncompressed round trip');
  }
  if (points && C.p < 200n) {
    for (const P of points) t.ok(C.mul(N, P) === null, T.id + ': #E·P = O for every point');
    let k = 0n; for (let i = 0n; i < 30n; i++) k += C.eq(C.mul(i, points[0]), E.scalar.ltr(C, i || 1n, points[0]).R) || i === 0n ? 1n : 0n;
    t.eq(k, 30n, T.id + ': small multiples');
  }
}
// naf digits reconstruct k and have no adjacent nonzero digits
for (let i = 0; i < 200; i++) {
  const k = randBig(1n << 256n) + 1n, w = 2 + (i % 5), d = E.naf(k, w);
  t.eq(d.reduce((s, x, j) => s + BigInt(x) * (1n << BigInt(j)), 0n), k, 'wNAF digits sum to k');
  t.ok(d.every((x, j) => !x || (x % 2 && Math.abs(x) < 1 << (w - 1) && d.slice(j + 1, j + w).every((y) => !y))), 'wNAF digits are odd, bounded and spaced');
}
// a step-by-step check of the ladder record on the curve over GF(101)
{ const C = E.toy('gf101'), r = E.scalar.ladder(C, 77n, C.G);
  t.ok(r.steps.every((s) => C.eq(C.sub(s.R1, s.R0), C.G)), 'ladder: R1 − R0 = P at every step');
  t.eq(r.doubles, r.adds, 'ladder: one doubling per addition'); }

// ---- standard curves
for (const C of [E.P256, E.secp256k1]) {
  t.ok(C.on(C.G) && C.validate(C.G).ok, C.name + ': G is valid'); t.ok(C.mul(C.n, C.G) === null, C.name + ': n·G = O');
  for (let i = 0; i < 6; i++) {
    const k = randBig(C.n), ref = C.mul(k, C.G);
    for (const m of ['ltr', 'rtl', 'ladder']) t.ok(C.eq(E.scalar[m](C, k, C.G).R, ref), C.name + ': ' + m);
    t.ok(C.eq(E.scalar.wnaf(C, k, C.G, 5).R, ref), C.name + ': wNAF');
    t.ok(C.eq(C.decode(C.compress(ref).bytes).P, ref), C.name + ': compression round trip');
  }
  t.ok(!C.validate({ x: C.G.x, y: C.G.y + 1n }).ok, C.name + ': an off-curve point fails validation');
  t.ok(C.validate(null).ok === false, C.name + ': O fails validation');
}

// ---- RFC 6979 (P-256 with SHA-256)
{ const C = E.P256, d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721n, Q = C.mul(d, C.G);
  t.eq(Q.x.toString(16), '60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6', 'RFC 6979 P-256 Ux');
  t.eq(Q.y.toString(16), '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299', 'RFC 6979 P-256 Uy');
  for (const [m, k, r, s] of [
    ['sample', 'a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60', 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716', 'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8'],
    ['test', 'd16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0', 'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367', '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083'],
  ]) {
    const g = E.ecdsa.sign(C, d, utf8(m));
    t.eq(g.k.toString(16).padStart(64, '0'), k, 'RFC 6979 k for ' + m); t.eq(g.r.toString(16).padStart(64, '0'), r, 'RFC 6979 r for ' + m); t.eq(g.s.toString(16).padStart(64, '0'), s, 'RFC 6979 s for ' + m);
    t.ok(E.ecdsa.verify(C, Q, utf8(m), g).ok, 'RFC 6979 signature verifies: ' + m);
    t.ok(!E.ecdsa.verify(C, Q, utf8(m + '.'), g).ok, 'a changed message fails: ' + m);
  }
}

// ---- node:crypto: ECDH and ECDSA on P-256 and secp256k1
const jwkPub = (C, crv, Q) => createPublicKey({ key: { kty: 'EC', crv, x: b64(toB(Q.x, 32)), y: b64(toB(Q.y, 32)) }, format: 'jwk' });
const jwkPriv = (C, crv, d, Q) => createPrivateKey({ key: { kty: 'EC', crv, x: b64(toB(Q.x, 32)), y: b64(toB(Q.y, 32)), d: b64(toB(d, 32)) }, format: 'jwk' });
for (const [C, crv, nodeName, reps] of [[E.P256, 'P-256', 'prime256v1', 120], [E.secp256k1, 'secp256k1', 'secp256k1', 110]]) {
  for (let i = 0; i < reps; i++) {
    const kp = generateKeyPairSync('ec', { namedCurve: nodeName }), j = kp.privateKey.export({ format: 'jwk' });
    const dN = big(unb64(j.d)), QN = { x: big(unb64(j.x)), y: big(unb64(j.y)) };
    t.ok(C.eq(C.mul(dN, C.G), QN), crv + ': our d·G equals node\'s public key ' + i);
    const mine = E.keygen(C);
    if (crv === 'P-256') {
      const ours = E.ecdh(C, mine.d, QN).shared;
      const theirs = diffieHellman({ privateKey: kp.privateKey, publicKey: jwkPub(C, crv, mine.Q) });
      t.eq(hex(ours), theirs.toString('hex'), 'ECDH P-256 against node ' + i);
    }
    const msg = randomBytes(Math.floor(rand() * 100));
    // ours signs, node verifies (P1363 and DER)
    const g = E.ecdsa.sign(C, mine.d, msg, { nonce: i % 2 ? 'random' : 'rfc6979' });
    t.ok(verify('sha256', msg, { key: jwkPub(C, crv, mine.Q), dsaEncoding: 'ieee-p1363' }, E.p1363.encode(C, g)), `${crv}: node verifies our signature (P1363) ${i}`);
    t.ok(verify('sha256', msg, jwkPub(C, crv, mine.Q), E.der.encode(g)), `${crv}: node verifies our signature (DER) ${i}`);
    // node signs, ours verifies
    const der = sign('sha256', msg, kp.privateKey), sig = E.der.decode(new Uint8Array(der));
    t.eq(hex(E.der.encode(sig)), der.toString('hex'), `${crv}: DER re-encodes identically ${i}`);
    t.ok(E.ecdsa.verify(C, QN, msg, sig).ok, `${crv}: we verify node's signature ${i}`);
    const p1363 = sign('sha256', msg, { key: jwkPriv(C, crv, dN, QN), dsaEncoding: 'ieee-p1363' });
    t.ok(E.ecdsa.verify(C, QN, msg, E.p1363.decode(C, new Uint8Array(p1363))).ok, `${crv}: we verify node's P1363 signature ${i}`);
    if (i % 10 === 0) t.ok(!E.ecdsa.verify(C, QN, msg, { r: sig.r, s: E.mod(sig.s + 1n, C.n) }).ok, `${crv}: a tampered s fails ${i}`);
  }
}
{ const C = E.P256, bad = { x: C.G.x, y: C.G.y ^ 1n }; t.ok(E.ecdh(C, 5n, bad).S === null, 'ECDH refuses an off-curve point'); }

// ---- SHA-512 fallback
for (let i = 0; i < 80; i++) { const m = randomBytes(Math.floor(rand() * 300)); t.eq(hex(E.sha512Local(m)), createHash('sha512').update(m).digest('hex'), 'SHA-512 ' + i); }

// ---- RFC 7748: X25519
const X = E.X25519;
t.eq(hex(X.x25519(fromHex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'), fromHex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')).out), 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552', 'RFC 7748 vector 1');
t.eq(hex(X.x25519(fromHex('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'), fromHex('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493')).out), '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957', 'RFC 7748 vector 2');
{ let k = X.toLe(9n), u = X.toLe(9n);
  for (let i = 1; i <= 1000; i++) { const out = X.x25519(k, u, { trace: false }).out; u = k; k = out; if (i === 1) t.eq(hex(k), '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079', 'RFC 7748 iterated, 1'); }
  t.eq(hex(k), '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51', 'RFC 7748 iterated, 1000'); }
{ const a = fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'), b = fromHex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
  t.eq(hex(X.publicKey(a)), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'RFC 7748 Alice public');
  t.eq(hex(X.publicKey(b)), 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'RFC 7748 Bob public');
  t.eq(hex(X.shared(a, X.publicKey(b)).shared), '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742', 'RFC 7748 shared secret');
  t.ok(X.shared(a, new Uint8Array(32)).shared === null, 'X25519 rejects the all-zero result');
  const tr = X.x25519(a, X.toLe(9n)); t.eq(tr.steps.length, 255, 'the ladder records 255 steps'); }
for (let i = 0; i < 150; i++) {
  const kp = generateKeyPairSync('x25519'), j = kp.privateKey.export({ format: 'jwk' }), mine = randomBytes(32);
  t.eq(hex(X.publicKey(unb64(j.d))), hex(unb64(j.x)), 'X25519 public key against node ' + i);
  const theirPub = createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b64(X.publicKey(mine)) }, format: 'jwk' });
  t.eq(hex(X.shared(mine, unb64(j.x)).shared), diffieHellman({ privateKey: kp.privateKey, publicKey: theirPub }).toString('hex'), 'X25519 shared secret against node ' + i);
}

// ---- RFC 8032: Ed25519
const Ed = E.Ed25519;
for (const [sk, pk, m, sg] of [
  ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '', 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'],
  ['4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72', '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'],
  ['c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7', 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82', '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'],
]) {
  const g = Ed.sign(fromHex(sk), fromHex(m));
  t.eq(hex(g.pub), pk, 'RFC 8032 public key ' + pk.slice(0, 8)); t.eq(hex(g.sig), sg, 'RFC 8032 signature ' + pk.slice(0, 8));
  t.ok(Ed.verify(fromHex(pk), fromHex(m), fromHex(sg)).ok, 'RFC 8032 verifies ' + pk.slice(0, 8));
  const bad = fromHex(sg); bad[40] ^= 1; t.ok(!Ed.verify(fromHex(pk), fromHex(m), bad).ok, 'a flipped bit in S fails ' + pk.slice(0, 8));
}
for (let i = 0; i < 150; i++) {
  const kp = generateKeyPairSync('ed25519'), j = kp.privateKey.export({ format: 'jwk' }), msg = randomBytes(Math.floor(rand() * 200));
  const seed = unb64(j.d), g = Ed.sign(seed, msg);
  t.eq(hex(g.pub), hex(unb64(j.x)), 'Ed25519 public key against node ' + i);
  t.eq(hex(g.sig), sign(null, msg, kp.privateKey).toString('hex'), 'Ed25519 signature equals node\'s (deterministic) ' + i);
  t.ok(verify(null, msg, kp.publicKey, g.sig), 'node verifies our Ed25519 signature ' + i);
  t.ok(Ed.verify(unb64(j.x), msg, new Uint8Array(sign(null, msg, kp.privateKey))).ok, 'we verify node\'s Ed25519 signature ' + i);
  if (i % 15 === 0) t.ok(!Ed.verify(unb64(j.x), Buffer.concat([msg, Buffer.from([1])]), g.sig).ok, 'Ed25519 rejects another message ' + i);
  if (i % 10 === 0) t.eq(E.forms.edToMontU(g.pub), X.le(X.x25519(Ed.toLe(Ed.keygen(seed).a), X.toLe(9n), { trace: false }).out), 'Ed25519 key maps to the X25519 key of the same scalar ' + i);
}

// ---- the three forms on the toy curve
{ const F = E.forms.toy(), c = E.forms.check(F), rows = F.rows();
  t.ok(c.ok, `forms: sums agree under both maps for all ${c.pairs} pairs`);
  t.ok(F.edw.complete, 'forms: the toy Edwards curve is complete');
  t.ok(rows.every((r) => F.mont.on(r.mont) && F.edw.on(r.edw) && F.weier.on(r.weier)), 'forms: every point lands on all three curves');
  t.ok(rows.every((r) => { const b = F.fromEdw(r.edw); return (!b && !r.mont) || (b && r.mont && b.u === r.mont.u && b.v === r.mont.v); }), 'forms: Edwards back to Montgomery');
  t.eq(BigInt(rows.length), F.weier.count().N, 'forms: same number of points in each shape'); }

// ---- attacks
for (let seed = 1; seed <= 6; seed++) {
  for (const C of [E.P256, E.secp256k1, E.toy('gf1009')]) { const r = E.attacks.nonceReuseDemo(C, { seed }); t.ok(r.result.ok && r.result.d === r.d, `nonce reuse recovers the key on ${C.name}, seed ${seed}`); }
  { const C = E.toy('target10007'), d = 1n + randBig(C.n - 1n); t.eq(E.attacks.invalidCurve(C, d, { seed }).d, d, 'invalid-curve attack, seed ' + seed); }
  { const q = 2549n, d = 1n + randBig(q - 1n), r = E.attacks.twist(d, { seed }); t.ok(r.candidates.includes(d) || r.candidates.includes(q - d), 'twist attack, seed ' + seed); }
  { const C = E.toy('smooth10007'), k = randBig(C.n); t.eq(E.dlog.pohligHellman(C, C.G, C.mul(k, C.G), C.n).k, k, 'Pohlig–Hellman, seed ' + seed); }
  { const C = E.toy('anomalous1013'), k = randBig(C.n); t.eq(E.dlog.smart(C, C.G, C.mul(k, C.G)).k, k, 'Smart\'s attack on the anomalous curve, seed ' + seed); }
  { const C = E.toy('dlog65537'), k = randBig(C.n), Q = C.mul(k, C.G);
    t.eq(E.dlog.bsgs(C, C.G, Q, C.n).k, k, 'baby-step giant-step, seed ' + seed);
    const r = E.dlog.rho(C, C.G, Q, C.n, { seed }); t.eq(r.k, k, 'Pollard rho, seed ' + seed);
    t.ok(r.walk.length === r.mu + r.lambda && r.walk.every((w) => C.eq(w.P, C.add(C.mul(w.a, C.G), C.mul(w.b, Q)))), 'rho walk: every point is a·G + b·Q, seed ' + seed); }
  { const C = E.toy('hnp2e20');
    let r = E.hnp.demo(C, { seed, m: 2, bits: 8 }); t.eq(r.result.d, r.d, 'HNP, two signatures in 2-D, seed ' + seed);
    r = E.hnp.demo(C, { seed, m: 5, bits: 13 }); t.eq(r.result.d, r.d, 'HNP, five signatures with 7 zero top bits, seed ' + seed);
    r = E.hnp.demo(C, { seed, m: 5, bits: 13, known: true }); t.eq(r.result.d, r.d, 'HNP, five signatures with 7 known top bits, seed ' + seed); }
}
for (const [C, seed] of [[E.P256, 1], [E.P256, 2], [E.secp256k1, 3]]) { const r = E.hnp.demo(C, { seed, m: 6, bits: 192 }); t.eq(r.result.d, r.d, `HNP on ${C.name}, 64 zero top bits in 6 nonces, seed ${seed}`); }
{ const B = [[1n, 0n, 0n, 1345n], [0n, 1n, 0n, 35n], [0n, 0n, 1n, 154n]], r = E.lll(B), fl = S.PQ.Lattice.lll(B.map((x) => x.map(Number)), 0.99);
  t.ok(S.PQ.Lattice.isReduced(r.B.map((x) => x.map(Number)), 0.99), 'exact LLL output is LLL-reduced'); t.eq(r.B.map((x) => x.map(Number)), fl.B, 'exact LLL agrees with the floating LLL'); }
// ---- the structure of every curve over a few small fields: P2 is found whenever the group is not cyclic
{
  let tried = 0, missing = [];
  for (const p of [13, 17, 19, 23, 29, 31, 37, 41]) for (let a = 0; a < p; a++) for (let b = 0; b < p; b++) {
    if ((4 * a ** 3 + 27 * b * b) % p === 0) continue;
    const C = E.curve({ p, a, b }), st = C.structure(); tried++;
    if (st.n2 > 1n && !st.P2) missing.push(p + ':' + a + ',' + b);
  }
  t.ok(!missing.length, 'every non-cyclic curve over GF(13 … 41) gets a P2 (' + tried + ' curves); missing: ' + missing.slice(0, 5).join(' '));
  const st = E.curve({ p: 17, a: 6, b: 3 }).structure();
  t.ok(st.n1 === 8n && st.n2 === 2n && !!st.P2, 'GF(17), a = 6, b = 3 is Z_8 × Z_2 with a P2');
}
t.done();
