// The sandbox's coding tasks: small pieces of real cryptography a student writes in plain JavaScript. Each task's
// tests come from the engines (ref) on our own cases, plus the published examples where they are natural (the
// xtime and multiplication examples of FIPS 197, the quarter-round vector of RFC 8439). Values may be BigInt.
//   S.Sandbox.tasks = [{id, title, level, blurb, fn, params, start, solution, hints: [3], ref, cases | tests, timeLimit}]
//   S.Sandbox.testsOf(task) -> [{args, want} | {args, check}]
(function (S) {
  'use strict';
  const SB = (S.Sandbox = S.Sandbox || {});
  const fn = (name, params, body) => 'function ' + name + '(' + params.join(', ') + ') {\n' + body + '\n}\n';

  // a small curve of our own for double-and-add: y² = x³ + 5x + 11 over GF(103)
  const CURVE = { p: 103n, a: 5n, b: 11n };
  let curveBase = null;
  const curve = () => S.EC.field(CURVE.p, CURVE.a, CURVE.b);
  const base = () => {
    if (curveBase) return curveBase;
    const E = curve();
    let best = null, bo = 0n;
    for (const P of E.points()) { const o = BigInt(E.order(P)); if (o > bo) { bo = o; best = P; } }
    curveBase = { P: [Number(best.x), Number(best.y)], order: Number(bo) };
    return curveBase;
  };
  const toPt = (P) => (P ? [Number(P.x), Number(P.y)] : null);
  const fromPt = (P) => (P ? { x: BigInt(P[0]), y: BigInt(P[1]) } : null);

  // original sentences for the Caesar breaker, each enciphered with a known shift
  const CAESAR = [
    ['The ferry waits for nobody after the second bell rings across the harbour.', 7],
    ['Pack the kettle, two candles and the folding map before the rain arrives.', 19],
    ['Seven gulls argued over a single chip while the band played on the pier.', 3],
    ['Leave the spare key under the blue pot by the greenhouse door tonight.', 22],
    ['Every orchard in the valley blossoms a week earlier than it did last spring.', 13],
  ];

  SB.tasks = [
    {
      id: 'square-multiply', title: 'Square-and-multiply', level: 1, fn: 'modPow', params: ['x', 'e', 'n'],
      blurb: 'Compute `x^e mod n` for BigInts by reading the bits of `e` from the left: square for every bit, and multiply by `x` when the bit is 1. RSA and Diffie–Hellman rest on this loop.',
      ref: (x, e, n) => S.NT.pow(x, e, n),
      cases: [[5n, 0n, 23n], [5n, 1n, 23n], [4n, 13n, 497n], [7n, 560n, 561n], [123456789n, 65537n, 1000000007n], [2n, 1000003n, 1000033n], [987654321987654321n, 2n ** 127n - 3n, 2n ** 127n - 1n]],
      hints: ['Start with `r = 1n`. For each bit of `e` from the top, set `r = r * r % n`, then if the bit is 1, `r = r * x % n`.', '`e.toString(2)` gives the bits as a string of 0s and 1s, most significant first. Remember that every number must be a BigInt: `1n`, not `1`.', 'function modPow(x, e, n) {\n  let r = 1n;\n  for (const b of e.toString(2)) {\n    r = r * r % n;\n    if (b === "1") r = r * x % n;\n  }\n  return r % n;\n}'],
      solution: fn('modPow', ['x', 'e', 'n'], '  let r = 1n;\n  x %= n;\n  for (const b of e.toString(2)) {\n    r = r * r % n;\n    if (b === \'1\') r = r * x % n;\n  }\n  return r % n;'),
    },
    {
      id: 'xtime', title: 'xtime in GF(2^8)', level: 1, radix: 16, fn: 'xtime', params: ['a'],
      blurb: 'Multiply a byte by `x` in the AES field: shift left one place, and if a bit fell off the top, reduce by XORing with `0x1b`. The result must stay a byte (0 to 255).',
      ref: (a) => S.gf256.xtime(a),
      cases: [[0x57], [0xae], [0x47], [0x8e], [0x00], [0x80], [0xff], [0x01], [0xc3], [0x7f]],
      hints: ['`a << 1` shifts left; the bit that matters is `a & 0x80`, the top bit before the shift.', 'If the top bit was set, XOR the shifted value with `0x1b`, then keep the low eight bits with `& 0xff`.', 'function xtime(a) {\n  return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;\n}'],
      solution: fn('xtime', ['a'], '  return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;'),
    },
    {
      id: 'gf-mul', title: 'Multiplying in GF(2^8)', level: 2, radix: 16, fn: 'gmul', params: ['a', 'b'],
      blurb: 'Multiply two bytes in the AES field by shift-and-add: for each bit of `b`, add (XOR) the current `a` into the result when the bit is 1, then replace `a` by `xtime(a)`. FIPS 197 works {57}·{83} = {c1} this way.',
      ref: (a, b) => S.gf256.mul(a, b),
      cases: [[0x57, 0x83], [0x57, 0x13], [0x02, 0x87], [0x01, 0xd4], [0x00, 0x9a], [0xff, 0xff], [0x53, 0xca], [0x3c, 0x5e]],
      hints: ['Addition in this field is XOR, so the result starts at 0 and is XORed with `a` for every 1 bit of `b`.', 'Go through the bits of `b` from the bottom: test `b & 1`, then shift `b >>= 1` and double `a` with xtime (shift, and XOR with 0x1b if the top bit was set).', 'function gmul(a, b) {\n  let r = 0;\n  while (b) {\n    if (b & 1) r ^= a;\n    a = ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;\n    b >>= 1;\n  }\n  return r;\n}'],
      solution: fn('gmul', ['a', 'b'], '  let r = 0;\n  while (b) {\n    if (b & 1) r ^= a;\n    a = ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;\n    b >>= 1;\n  }\n  return r;'),
    },
    {
      id: 'sbox', title: 'The AES S-box from scratch', level: 3, radix: 16, fn: 'sbox', params: ['b'],
      blurb: 'Build one S-box entry without the table: take the inverse of `b` in GF(2^8) (0 stays 0), then apply the affine map: each bit i of the result is bit i XOR bits i+4, i+5, i+6, i+7 (mod 8) of the inverse, XOR bit i of `0x63`. FIPS 197 gives S({53}) = {ed}.',
      ref: (b) => S.gf256.SBOX[b],
      cases: [[0x53], [0x00], [0x01], [0x10], [0x7c], [0xc9], [0xff], [0x2a], [0x9e]],
      hints: ['The inverse can be found by brute force: the `y` with `gmul(b, y) === 1`. Write a small gmul first (see the GF(2^8) task).', 'The affine map is easiest with rotations: `s = inv ^ rotl(inv,1) ^ rotl(inv,2) ^ rotl(inv,3) ^ rotl(inv,4) ^ 0x63`, where `rotl(v,k) = ((v << k) | (v >> (8 - k))) & 0xff`.', 'function sbox(b) {\n  const mul = (a, c) => { let r = 0; while (c) { if (c & 1) r ^= a; a = ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff; c >>= 1; } return r; };\n  let inv = 0;\n  for (let y = 1; y < 256 && b; y++) if (mul(b, y) === 1) { inv = y; break; }\n  const rotl = (v, k) => ((v << k) | (v >> (8 - k))) & 0xff;\n  return inv ^ rotl(inv, 1) ^ rotl(inv, 2) ^ rotl(inv, 3) ^ rotl(inv, 4) ^ 0x63;\n}'],
      solution: fn('sbox', ['b'], '  const mul = (a, c) => { let r = 0; while (c) { if (c & 1) r ^= a; a = ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff; c >>= 1; } return r; };\n  let inv = 0;\n  for (let y = 1; y < 256 && b; y++) if (mul(b, y) === 1) { inv = y; break; }\n  const rotl = (v, k) => ((v << k) | (v >> (8 - k))) & 0xff;\n  return inv ^ rotl(inv, 1) ^ rotl(inv, 2) ^ rotl(inv, 3) ^ rotl(inv, 4) ^ 0x63;'),
    },
    {
      id: 'quarter-round', title: 'The ChaCha quarter-round', level: 2, radix: 16, width: 8, fn: 'quarterRound', params: ['a', 'b', 'c', 'd'],
      blurb: 'Write the quarter-round on four 32-bit words and return `[a, b, c, d]`: a += b; d ^= a; d <<<= 16; c += d; b ^= c; b <<<= 12; a += b; d ^= a; d <<<= 8; c += d; b ^= c; b <<<= 7. Additions wrap at 2^32; return unsigned words. The first test is the vector of RFC 8439, section 2.1.1.',
      ref: (a, b, c, d) => S.ChaCha.qr(a, b, c, d).out.map((x) => x >>> 0),
      cases: [[0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567], [0, 0, 0, 0], [1, 0, 0, 0], [0xffffffff, 1, 0xdeadbeef, 0x0badf00d], [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]],
      hints: ['In JavaScript `(x + y) >>> 0` adds modulo 2^32, and `x >>> 0` turns any 32-bit pattern into an unsigned number.', 'Rotation left by n: `((x << n) | (x >>> (32 - n))) >>> 0`.', 'function quarterRound(a, b, c, d) {\n  const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;\n  a = (a + b) >>> 0; d = rotl(d ^ a, 16);\n  c = (c + d) >>> 0; b = rotl(b ^ c, 12);\n  a = (a + b) >>> 0; d = rotl(d ^ a, 8);\n  c = (c + d) >>> 0; b = rotl(b ^ c, 7);\n  return [a, b, c, d];\n}'],
      solution: fn('quarterRound', ['a', 'b', 'c', 'd'], '  const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;\n  a = (a + b) >>> 0; d = rotl(d ^ a, 16);\n  c = (c + d) >>> 0; b = rotl(b ^ c, 12);\n  a = (a + b) >>> 0; d = rotl(d ^ a, 8);\n  c = (c + d) >>> 0; b = rotl(b ^ c, 7);\n  return [a, b, c, d];'),
    },
    {
      id: 'egcd', title: 'Extended Euclid', level: 1, fn: 'egcd', params: ['a', 'b'],
      blurb: 'Return `[g, x, y]` with g = gcd(a, b) and a·x + b·y = g, for BigInts. Any pair x, y that works is accepted.',
      tests: () => [[240n, 46n], [17n, 3120n], [1071n, 462n], [13n, 13n], [1n, 0n], [0n, 9n], [2n ** 89n - 1n, 2n ** 61n - 1n], [270n, 192n]].map(([a, b]) => ({
        args: [a, b],
        check(got) {
          if (!Array.isArray(got) || got.length !== 3) return 'an array [g, x, y] is wanted';
          const [g, x, y] = got;
          if (![g, x, y].every((v) => typeof v === 'bigint')) return 'all three must be BigInts';
          const want = S.NT.gcd(a, b);
          if (g !== want) return 'g should be ' + want + 'n';
          return a * x + b * y === g ? true : 'a·x + b·y is ' + (a * x + b * y) + 'n, not g';
        },
      })),
      hints: ['Keep two rows (r, s, t), starting with (a, 1, 0) and (b, 0, 1). Each step subtracts q times the second row from the first, with q = r0 / r1 (BigInt division rounds toward zero).', 'Stop when the remainder is 0: the row before holds g with its x and y. Use array swaps: `[r0, r1] = [r1, r0 - q * r1]`.', 'function egcd(a, b) {\n  let [r0, r1, s0, s1, t0, t1] = [a, b, 1n, 0n, 0n, 1n];\n  while (r1 !== 0n) {\n    const q = r0 / r1;\n    [r0, r1] = [r1, r0 - q * r1];\n    [s0, s1] = [s1, s0 - q * s1];\n    [t0, t1] = [t1, t0 - q * t1];\n  }\n  return [r0, s0, t0];\n}'],
      solution: fn('egcd', ['a', 'b'], '  let [r0, r1, s0, s1, t0, t1] = [a, b, 1n, 0n, 0n, 1n];\n  while (r1 !== 0n) {\n    const q = r0 / r1;\n    [r0, r1] = [r1, r0 - q * r1];\n    [s0, s1] = [s1, s0 - q * s1];\n    [t0, t1] = [t1, t0 - q * t1];\n  }\n  return [r0, s0, t0];'),
    },
    {
      id: 'mod-inverse', title: 'The modular inverse', level: 1, fn: 'modInverse', params: ['a', 'n'],
      blurb: 'Return the inverse of `a` modulo `n` as a BigInt in 0 … n−1, or `null` when gcd(a, n) ≠ 1 and there is none. This is how an RSA private exponent d is found from e.',
      ref: (a, n) => S.NT.inverse(a, n).inv,
      cases: [[17n, 3120n], [3n, 11n], [10n, 17n], [6n, 9n], [65537n, 2n ** 64n - 59n - 1n], [1n, 7n], [123456789n, 1000000007n]],
      hints: ['Run extended Euclid on (a, n): if g = 1 then a·x ≡ 1 (mod n), so x is the inverse.', 'x may come out negative: bring it into range with `((x % n) + n) % n`. If g is not 1, return null.', 'function modInverse(a, n) {\n  let [r0, r1, s0, s1] = [a % n, n, 1n, 0n];\n  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }\n  if (r0 !== 1n) return null;\n  return ((s0 % n) + n) % n;\n}'],
      solution: fn('modInverse', ['a', 'n'], '  let [r0, r1, s0, s1] = [((a % n) + n) % n, n, 1n, 0n];\n  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }\n  if (r0 !== 1n) return null;\n  return ((s0 % n) + n) % n;'),
    },
    {
      id: 'crt', title: 'The Chinese remainder theorem', level: 2, fn: 'crt', params: ['r1', 'm1', 'r2', 'm2'],
      blurb: 'Given x ≡ r1 (mod m1) and x ≡ r2 (mod m2) with coprime moduli, return the x in 0 … m1·m2 − 1 (BigInts). RSA decryption by the CRT joins its two halves exactly this way.',
      ref: (r1, m1, r2, m2) => S.NT.crt([r1, r2], [m1, m2]).x,
      cases: [[2n, 5n, 3n, 7n], [0n, 4n, 0n, 9n], [6n, 11n, 13n, 16n], [1n, 2n, 2n, 3n], [123n, 1009n, 456n, 2003n], [5n, 6n, 1n, 35n]],
      hints: ['x = r1 + m1·k for some k. Put that into the second congruence: m1·k ≡ r2 − r1 (mod m2).', 'So k = (r2 − r1)·m1⁻¹ mod m2. You need the inverse of m1 modulo m2 (extended Euclid), and to bring k into 0 … m2 − 1 before forming x.', 'function crt(r1, m1, r2, m2) {\n  const inv = (a, n) => { let [r0, r, s0, s] = [a % n, n, 1n, 0n]; while (r) { const q = r0 / r; [r0, r] = [r, r0 - q * r]; [s0, s] = [s, s0 - q * s]; } return ((s0 % n) + n) % n; };\n  const k = (((r2 - r1) % m2 + m2) % m2) * inv(m1 % m2, m2) % m2;\n  return r1 + m1 * k;\n}'],
      solution: fn('crt', ['r1', 'm1', 'r2', 'm2'], '  const inv = (a, n) => { let [r0, r, s0, s] = [((a % n) + n) % n, n, 1n, 0n]; while (r) { const q = r0 / r; [r0, r] = [r, r0 - q * r]; [s0, s] = [s, s0 - q * s]; } return ((s0 % n) + n) % n; };\n  const k = (((r2 - r1) % m2 + m2) % m2) * inv(m1, m2) % m2;\n  return ((r1 % m1) + m1) % m1 + m1 * k;'),
    },
    {
      id: 'double-add', title: 'Double-and-add on a small curve', level: 3, fn: 'scalarMul', params: ['k', 'P'],
      blurb: 'On the curve y² = x³ + 5x + 11 over GF(103), points are `[x, y]` (Numbers) and the point at infinity is `null`. Return k·P by double-and-add, using the chord and tangent formulas with inverses mod 103.',
      tests: () => { const B = base(); const E = curve(); return [0, 1, 2, 3, 5, 10, 17, B.order - 1, B.order, B.order + 4, 60].map((k) => ({ args: [k, B.P], want: toPt(E.mul(BigInt(k), fromPt(B.P))) })).concat([{ args: [7, null], want: null }]); },
      hints: ['Write add(P, Q) first: if one is null return the other; if x1 = x2 and y1 + y2 ≡ 0 the sum is null; otherwise λ = (y2 − y1)/(x2 − x1), or (3x1² + 5)/(2y1) when P = Q; x3 = λ² − x1 − x2, y3 = λ(x1 − x3) − y1, all mod 103.', 'Division is multiplication by an inverse: with a prime modulus, inv(v) = v^(101) mod 103 (Fermat), or use extended Euclid. Keep every value in 0 … 102 with ((v % 103) + 103) % 103. Then for each bit of k from the top: R = add(R, R), and if the bit is 1, R = add(R, P).', 'function scalarMul(k, P) {\n  const p = 103, a = 5, m = (v) => ((v % p) + p) % p;\n  const inv = (v) => { let r = 1, b = m(v), e = p - 2; while (e) { if (e & 1) r = r * b % p; b = b * b % p; e >>= 1; } return r; };\n  const add = (A, B) => {\n    if (!A) return B; if (!B) return A;\n    if (A[0] === B[0] && m(A[1] + B[1]) === 0) return null;\n    const l = A[0] === B[0] ? m((3 * A[0] * A[0] + a) * inv(2 * A[1])) : m((B[1] - A[1]) * inv(B[0] - A[0]));\n    const x = m(l * l - A[0] - B[0]);\n    return [x, m(l * (A[0] - x) - A[1])];\n  };\n  let R = null;\n  for (const bit of k.toString(2)) { R = add(R, R); if (bit === "1") R = add(R, P); }\n  return R;\n}'],
      solution: fn('scalarMul', ['k', 'P'], '  const p = 103, a = 5, m = (v) => ((v % p) + p) % p;\n  const inv = (v) => { let r = 1, b = m(v), e = p - 2; while (e) { if (e & 1) r = r * b % p; b = b * b % p; e >>= 1; } return r; };\n  const add = (A, B) => {\n    if (!A) return B; if (!B) return A;\n    if (A[0] === B[0] && m(A[1] + B[1]) === 0) return null;\n    const l = A[0] === B[0] ? m((3 * A[0] * A[0] + a) * inv(2 * A[1])) : m((B[1] - A[1]) * inv(B[0] - A[0]));\n    const x = m(l * l - A[0] - B[0]);\n    return [x, m(l * (A[0] - x) - A[1])];\n  };\n  let R = null;\n  for (const bit of k.toString(2)) { R = add(R, R); if (bit === \'1\') R = add(R, P); }\n  return R;'),
    },
    {
      id: 'miller-rabin', title: 'One round of Miller–Rabin', level: 2, fn: 'mrRound', params: ['n', 'a'],
      blurb: 'For an odd n > 3 and a base a, write n − 1 = 2^s · d with d odd and return `true` if n passes the strong test to base a (it may be prime), `false` if a proves n composite. 561 fools Fermat for every coprime base; it does not fool this.',
      ref: (n, a) => S.NT.millerRabin(n, [a]).probablePrime,
      cases: [[97n, 5n], [561n, 2n], [561n, 5n], [1105n, 7n], [2047n, 2n], [2047n, 3n], [1000003n, 2n], [3215031751n, 2n], [3215031751n, 11n], [2n ** 61n - 1n, 3n], [221n, 174n]],
      hints: ['Find s and d by halving n − 1 while it is even. Then x = a^d mod n (you need square-and-multiply on BigInts).', 'If x is 1 or n − 1, the base says "maybe prime". Otherwise square x up to s − 1 times: if it ever becomes n − 1, "maybe prime"; if not, n is composite.', 'function mrRound(n, a) {\n  const pow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };\n  let d = n - 1n, s = 0;\n  while (d % 2n === 0n) { d /= 2n; s++; }\n  let x = pow(a, d, n);\n  if (x === 1n || x === n - 1n) return true;\n  for (let i = 1; i < s; i++) { x = x * x % n; if (x === n - 1n) return true; }\n  return false;\n}'],
      solution: fn('mrRound', ['n', 'a'], '  const pow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };\n  let d = n - 1n, s = 0;\n  while (d % 2n === 0n) { d /= 2n; s++; }\n  let x = pow(a, d, n);\n  if (x === 1n || x === n - 1n) return true;\n  for (let i = 1; i < s; i++) { x = x * x % n; if (x === n - 1n) return true; }\n  return false;'),
    },
    {
      id: 'caesar-break', title: 'Breaking a shift cipher', level: 2, fn: 'breakShift', params: ['ciphertext'],
      blurb: 'Each ciphertext is an English sentence shifted by an unknown k (A→A+k). Return k, a Number from 0 to 25. Try all 26 and score each by how English its letters look: frequent letters such as E, T, A, O should be common.',
      tests: () => CAESAR.map(([plain, k]) => ({ args: [S.Classic.shift.encrypt(plain, k).out], want: k })),
      hints: ['Undo a shift k with `(c - 65 - k + 26) % 26 + 65` on each upper-case letter code. Score each candidate plaintext.', 'A simple score: add up a weight per letter, for instance E 12, T 9, A 8, O 8, I 7, N 7, S 6, H 6, R 6, and 1 for the rest. The k with the highest score wins.', 'function breakShift(ciphertext) {\n  const w = { E: 12, T: 9, A: 8, O: 8, I: 7, N: 7, S: 6, H: 6, R: 6, D: 4, L: 4, U: 3 };\n  let best = 0, bestScore = -1;\n  for (let k = 0; k < 26; k++) {\n    let score = 0;\n    for (const ch of ciphertext.toUpperCase()) {\n      const c = ch.charCodeAt(0);\n      if (c < 65 || c > 90) continue;\n      score += w[String.fromCharCode((c - 65 - k + 26) % 26 + 65)] || 1;\n    }\n    if (score > bestScore) { bestScore = score; best = k; }\n  }\n  return best;\n}'],
      solution: fn('breakShift', ['ciphertext'], '  const w = { E: 12, T: 9, A: 8, O: 8, I: 7, N: 7, S: 6, H: 6, R: 6, D: 4, L: 4, U: 3 };\n  let best = 0, bestScore = -1;\n  for (let k = 0; k < 26; k++) {\n    let score = 0;\n    for (const ch of ciphertext.toUpperCase()) {\n      const c = ch.charCodeAt(0);\n      if (c < 65 || c > 90) continue;\n      score += w[String.fromCharCode((c - 65 - k + 26) % 26 + 65)] || 1;\n    }\n    if (score > bestScore) { bestScore = score; best = k; }\n  }\n  return best;'),
    },
    {
      id: 'scratch', title: 'Scratch pad', level: 0, fn: 'main', params: [], free: true,
      blurb: 'Anything you like: `main()` runs in the same sealed worker and its return value and `console.log` lines are shown. Handy for trying an idea before a task.',
      tests: () => [{ args: [], free: true }],
      hints: ['BigInt literals end in n: `2n ** 127n - 1n` is a Mersenne prime.', '`console.log` prints into the console under the editor.', 'function main() {\n  const p = 2n ** 127n - 1n;\n  console.log(p.toString().length + " digits");\n  return p;\n}'],
      start: 'function main() {\n  const p = 2n ** 127n - 1n;\n  console.log(\'a Mersenne prime with\', p.toString().length, \'digits\');\n  return p % 1000n;\n}\n',
      solution: 'function main() {\n  return 42;\n}\n',
    },
  ];
  for (const t of SB.tasks) if (!t.start) t.start = fn(t.fn, t.params, '  // your code here\n');
  SB.testsOf = (t) => (typeof t.tests === 'function' ? t.tests() : t.tests ? t.tests : t.cases.map((args) => ({ args, want: t.ref(...args) })));
  SB.task = (id) => SB.tasks.find((t) => t.id === id) || null;
})(globalThis.Sifer = globalThis.Sifer || {});
