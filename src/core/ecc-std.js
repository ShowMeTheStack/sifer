// The named curves: P-256 and secp256k1 (SEC 2 / FIPS 186 domain parameters), and a set of small curves for teaching,
// each chosen for what it shows. Curve25519 and Ed25519 live in their own engines.
//   S.ECC.P256 / S.ECC.secp256k1 -> curve objects with n, h and G
//   S.ECC.TOYS -> [{id, p, a, b, G?, n?, h?, shows}];  S.ECC.toy(id) -> curve object (G set when the group has one)
//   S.ECC.toyInfo(id) -> {C, points, count, hasse, structure}  the full point list and the group structure
(function (S) {
  'use strict';
  const E = (S.ECC = S.ECC || {});
  const H = (h) => BigInt('0x' + h);
  let p256 = null, k1 = null;
  Object.defineProperty(E, 'P256', {
    enumerable: true,
    get: () => p256 || (p256 = E.curve({
      name: 'P-256', p: H('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'), a: -3n,
      b: H('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
      G: { x: H('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'), y: H('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5') },
      n: H('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'), h: 1n,
    })),
  });
  Object.defineProperty(E, 'secp256k1', {
    enumerable: true,
    get: () => k1 || (k1 = E.curve({
      name: 'secp256k1', p: (1n << 256n) - (1n << 32n) - 977n, a: 0n, b: 7n,
      G: { x: H('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'), y: H('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8') },
      n: H('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'), h: 1n,
    })),
  });
  E.named = (name) => ({ 'P-256': E.P256, p256: E.P256, secp256r1: E.P256, prime256v1: E.P256, secp256k1: E.secp256k1 })[name];

  E.TOYS = [
    { id: 'gf17', p: 17, a: 3, b: 5, n: 23, h: 1, G: [1, 3], shows: 'a prime number of points (23): every point but O generates the whole group' },
    { id: 'gf17x2', p: 17, a: 6, b: 3, shows: 'a group that is not cyclic: Z8 × Z2, so no point has order 16' },
    { id: 'gf97', p: 97, a: 2, b: 20, shows: '81 points forming Z27 × Z3: the order of a point divides 27' },
    { id: 'gf101', p: 101, a: 6, b: 14, n: 103, h: 1, G: [1, 18], shows: 'a prime-order cloud of 103 points to draw' },
    { id: 'gf1009', p: 1009, a: 7, b: 26, n: 1019, h: 1, G: [2, 413], shows: 'prime order 1019: big enough that brute force is no longer instant by hand' },
    { id: 'smooth10007', p: 10007, a: 4, b: 9, shows: 'order 10206 = 2 · 3⁶ · 7, smooth: Pohlig–Hellman splits the logarithm into tiny pieces' },
    { id: 'anomalous1013', p: 1013, a: 2, b: 126, n: 1013, h: 1, G: [2, 420], shows: 'exactly p points (an anomalous curve): the logarithm falls to a p-adic lift' },
    { id: 'dlog65537', p: 65537, a: 14, b: 13, n: 65557, h: 1, G: [2, 7], shows: 'prime order 65557 for baby-step giant-step and Pollard rho' },
    { id: 'target10007', p: 10007, a: 14, b: 10, n: 10009, h: 1, G: [1, 5], shows: 'prime order 10009: the victim curve of the invalid-curve attack' },
    { id: 'hnp2e20', p: 1048573, a: 5, b: 7, n: 1050281, h: 1, G: [2, 5], shows: 'prime order near 2²⁰ for the biased-nonce lattice attack' },
  ];
  const cache = new Map();
  E.toy = (id) => {
    if (cache.has(id)) return cache.get(id);
    const t = E.TOYS.find((x) => x.id === id);
    if (!t) throw new Error('no toy curve ' + id);
    const C = E.curve({ p: t.p, a: t.a, b: t.b, n: t.n, h: t.h, G: t.G ? { x: t.G[0], y: t.G[1] } : null, name: `y² = x³ + ${t.a}x + ${t.b} over GF(${t.p})` });
    C.id = id; C.shows = t.shows;
    if (!C.G && t.p <= 20000) {
      const st = C.structure();
      if (st.cyclic) { C.G = st.P1; C.n = st.N; C.h = 1n; }
    }
    cache.set(id, C);
    return C;
  };
  E.toyInfo = (id) => {
    const C = E.toy(id);
    const points = C.p <= 20000n ? C.points() : null;
    const count = C.count(), hasse = C.hasse();
    const structure = C.p <= 20000n ? C.structure() : { N: count.N, n1: count.N, n2: 1n, cyclic: true, P1: C.G, P2: null, trace: [] };
    return { C, points, count, hasse, structure };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
