// Part 14, post-quantum cryptography: the exercises. The lessons are in 140-pq.js; the tour and the course in
// 142-pq-tour.js. Messages, seeds and bases are our own; sizes are those of FIPS 203 and FIPS 204. Every
// answer was worked out with the engines (S.PQ.Quantum, S.PQ.Lattice, S.PQ.LWE, S.PQ.MLKEM, S.PQ.Lamport,
// S.PQ.WOTS, S.PQ.Merkle, S.PQ.Hamming), and the code exercises are checked against them.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('pq-x-grover-iters')) return;
  const ex = (o) => C.exercise(o);
  const P = () => S.PQ;

  // =========================================================================================================
  // Chapter 1: the quantum threat
  // =========================================================================================================
  ex({
    id: 'pq-x-grover-iters', chapter: 'pq-ch-threat', title: 'How many Grover iterations?', level: 1, kind: 'number',
    text: ['A search space of N = 1024 = 2¹⁰ indices has exactly one marked index. How many Grover iterations give the best chance of measuring it? Use the rule ⌊(π/4)·√N⌋ (more precisely ⌊π/(4θ)⌋ with sin θ = 1/√N; both give the same here).'],
    answer: 25,
    hints: ['√1024 = 32.', '(π/4) × 32 = 25.13.', 'Round down: 25 iterations. A classical search would need 512 tries on average; 25 is the square-root saving. One more iteration than the best already starts to lower the chance.'],
    solution: '25', wrong: ['32', '512', '804'],
    whyNot: 'Multiply √N by π/4 and round down.',
  });
  ex({
    id: 'pq-x-grover-aes', chapter: 'pq-ch-threat', title: 'AES-192 against a quantum attacker', level: 1, kind: 'number',
    text: ['Grover\'s search halves the exponent of a key search. How many bits of security does AES-192 keep against an attacker with a large quantum computer?'],
    answer: 96,
    hints: ['A 192-bit key has 2¹⁹² values.', 'Grover needs about √(2¹⁹²) iterations.', '√(2¹⁹²) = 2⁹⁶: 96 bits. AES-256 keeps 128.'],
    solution: '96', wrong: ['192', '0', '64'],
    whyNot: 'Take the square root of 2¹⁹²: the exponent halves.',
  });
  ex({
    id: 'pq-x-levels', chapter: 'pq-ch-threat', title: '128 bits after the quantum computer', level: 1, kind: 'choice',
    text: ['Which of these still gives about 128 bits of security against an attacker with a large quantum computer?'],
    options: ['AES-128', 'RSA with a 4096-bit modulus', 'AES-256', 'ECDH on the curve P-384'],
    answer: 2,
    whyNot: { 0: 'Grover halves AES-128 to 64 bits.', 1: 'Shor factors any RSA modulus in polynomial time: a bigger modulus does not help.', 3: 'Shor solves discrete logarithms on every curve, whatever its size.' },
    hints: ['Two kinds of quantum attack matter: Grover (a square-root speed-up of search) and Shor (polynomial time for factoring and discrete logarithms).', 'Shor breaks RSA and elliptic curves at any size; Grover halves the bits of a symmetric key.', 'AES-256: 256 bits halved is 128. RSA-4096 and P-384 fall to Shor, and AES-128 drops to 64.'],
    solution: 2, wrong: [0, 1, 3],
  });
  ex({
    id: 'pq-x-shor-factor', chapter: 'pq-ch-threat', title: 'From a period to a factor', level: 2, kind: 'number',
    text: ['The quantum part of Shor\'s algorithm reports that 3ˣ mod 35 has period r = 12. Compute 3^(r/2) mod 35 and use it to find the smaller prime factor of 35.'],
    answer: 5,
    hints: ['r/2 = 6, so compute 3⁶ = 729 mod 35.', '729 = 20·35 + 29, so 3⁶ ≡ 29. It is not −1 (that would be 34), so the method works.', 'gcd(29 − 1, 35) = gcd(28, 35) = 7 and gcd(29 + 1, 35) = gcd(30, 35) = 5. The smaller factor is 5.'],
    solution: '5', wrong: ['7', '29', '12'],
    whyNot: 'Take gcd(3⁶ − 1, 35) and gcd(3⁶ + 1, 35), and give the smaller of the two factors.',
  });
  ex({
    id: 'pq-x-shor-bad-a', chapter: 'pq-ch-threat', title: 'When a choice of a fails', level: 3, kind: 'choice',
    text: ['Shor\'s method is run on N = 21. For which of these bases a does the classical part fail, so that another a must be tried? Choose every one that fails.', { table: [['a', 'period r of aˣ mod 21'], ['2', '6'], ['4', '3'], ['5', '6'], ['10', '6']] }],
    options: ['a = 2', 'a = 4', 'a = 5', 'a = 10'],
    answer: [1, 2],
    hints: ['The method needs r even, and a^(r/2) ≢ −1 (mod N), that is a^(r/2) mod 21 ≠ 20.', 'a = 4 has r = 3: odd. For the others compute a³ mod 21: 2³ = 8, 5³ = 125 ≡ 20, 10³ = 1000 ≡ 13.', 'a = 4 fails (odd period) and a = 5 fails (5³ ≡ −1). a = 2 gives gcd(7, 21) = 7, and a = 10 gives gcd(12, 21) = 3.'],
    solution: [1, 2], wrong: [[1], [2], [0, 3], [1, 2, 3]],
  });
  ex({
    id: 'pq-x-assumption', chapter: 'pq-ch-threat', title: 'What does ML-KEM rest on?', level: 1, kind: 'choice',
    text: ['ML-KEM, the key encapsulation standardised in FIPS 203, is secure if which problem is hard?'],
    options: ['Factoring large integers', 'Learning with errors over module lattices (Module-LWE)', 'Inverting a hash function', 'Decoding a random binary linear code'],
    answer: 1,
    whyNot: { 0: 'Factoring is what RSA rests on, and Shor solves it.', 2: 'That is the assumption of the hash-based signatures, SLH-DSA, XMSS and LMS.', 3: 'That is McEliece\'s assumption.' },
    hints: ['ML-KEM\'s public key is t̂ = Â∘ŝ + ê: a matrix times a short secret, plus a small error.', 'A secret hidden by a matrix product and a small error is the learning-with-errors pattern, here with polynomials in a module.', 'Module-LWE. Factoring falls to Shor; hash inversion is SLH-DSA\'s assumption; decoding random codes is McEliece\'s.'],
    solution: 1, wrong: [0, 2, 3],
  });

  // =========================================================================================================
  // Chapter 2: lattices and LWE
  // =========================================================================================================
  ex({
    id: 'pq-x-det', chapter: 'pq-ch-lattice', title: 'The area of the cell', level: 1, kind: 'number',
    text: ['A lattice has the basis b₁ = (5, 1), b₂ = (2, 4). What is the area of its fundamental cell, |det B|?'],
    answer: 18,
    hints: ['The area of the parallelogram on two vectors is the absolute value of the determinant of the matrix with them as rows.', 'det = 5·4 − 1·2.', '20 − 2 = 18. Every other basis of the same lattice has a cell of area 18 too.'],
    solution: '18', wrong: ['22', '20', '-18'],
    whyNot: 'Compute 5·4 − 1·2 and take the absolute value.',
  });
  ex({
    id: 'pq-x-unimodular', chapter: 'pq-ch-lattice', title: 'Another basis of the same lattice', level: 2, kind: 'choice',
    text: ['B has rows g₁ and g₂. Which matrix U turns B into U·B, a basis of the very same lattice?'],
    options: ['U = [[2, 1], [1, 2]]', 'U = [[1, 1], [0, 2]]', 'U = [[3, 2], [4, 3]]', 'U = [[1, 0.5], [0, 1]]'],
    answer: 2,
    whyNot: { 0: 'Its determinant is 3: the new vectors span a sub-lattice whose cell is three times larger.', 1: 'Its determinant is 2: the cell doubles, so some lattice points are missed.', 3: 'Its entries are not whole numbers, so g₁ + 0.5·g₂ need not be a lattice point at all.' },
    hints: ['U·B must be made of lattice vectors (U has whole entries), and B must be recoverable from U·B the same way (U⁻¹ has whole entries).', 'An integer matrix has an integer inverse exactly when its determinant is ±1.', 'det [[3, 2], [4, 3]] = 9 − 8 = 1. The others have determinant 3 and 2, or are not integer matrices.'],
    solution: 2, wrong: [0, 1, 3],
  });
  ex({
    id: 'pq-x-gs-mu', chapter: 'pq-ch-lattice', title: 'A Gram–Schmidt coefficient', level: 2, kind: 'number',
    text: ['For the basis b₁ = (5, 2), b₂ = (3, 4), compute μ = ⟨b₂, b₁⟩ / ⟨b₁, b₁⟩, to three decimal places.'],
    answer: 23 / 29, tolerance: 0.0015,
    hints: ['⟨b₂, b₁⟩ = 3·5 + 4·2.', '⟨b₂, b₁⟩ = 23 and ⟨b₁, b₁⟩ = 25 + 4 = 29.', 'μ = 23/29 = 0.793. Then b₂* = b₂ − μ·b₁ = (−0.966, 2.414), perpendicular to b₁.'],
    solution: '0.793', wrong: ['1.15', '0.5', '23'],
    whyNot: 'Divide the inner product of b₂ with b₁ by the squared length of b₁.',
  });
  ex({
    id: 'pq-x-gauss-table', chapter: 'pq-ch-lattice', title: 'Gauss reduction step by step', level: 2, kind: 'table',
    text: ['Reduce the basis b₁ = (11, 11), b₂ = (14, 16) with Lagrange–Gauss. At each step b₁ is the shorter vector, m = round(⟨b₂, b₁⟩ / ⟨b₁, b₁⟩), and b₂ becomes b₂ − m·b₁; then the two are swapped if the new b₂ is shorter. Fill in m and the new b₂ for the three steps that change something.', { math: 'repeat:\n  if |b₂| < |b₁|: swap them\n  m = round(⟨b₂, b₁⟩ / ⟨b₁, b₁⟩)\n  if m = 0: stop\n  b₂ ← b₂ − m·b₁' }],
    rows: ['step 1', 'step 2', 'step 3'], cols: ['m', 'new b₂, x', 'new b₂, y'],
    cells: { 'step 1|m': '1', 'step 1|new b₂, x': '3', 'step 1|new b₂, y': '5', 'step 2|m': '3', 'step 2|new b₂, x': '2', 'step 2|new b₂, y': '-4', 'step 3|m': '-1', 'step 3|new b₂, x': '5', 'step 3|new b₂, y': '1' },
    hints: ['Step 1: ⟨b₂, b₁⟩ = 154 + 176 = 330 and ⟨b₁, b₁⟩ = 242, so m = round(1.36) = 1, and b₂ = (3, 5). It is shorter than b₁, so swap: b₁ = (3, 5), b₂ = (11, 11).', 'Step 2: ⟨b₂, b₁⟩ = 88, ⟨b₁, b₁⟩ = 34, m = round(2.59) = 3, b₂ = (11, 11) − 3·(3, 5) = (2, −4). Swap again: b₁ = (2, −4), b₂ = (3, 5).', 'Step 3: ⟨b₂, b₁⟩ = −14, ⟨b₁, b₁⟩ = 20, m = round(−0.7) = −1, b₂ = (3, 5) + (2, −4) = (5, 1). Now m rounds to 0: the basis (2, −4), (5, 1) is reduced, and (2, −4) is a shortest vector.'],
    solution: { 'step 1|m': '1', 'step 1|new b₂, x': '3', 'step 1|new b₂, y': '5', 'step 2|m': '3', 'step 2|new b₂, x': '2', 'step 2|new b₂, y': '-4', 'step 3|m': '-1', 'step 3|new b₂, x': '5', 'step 3|new b₂, y': '1' },
    wrong: [{ 'step 1|m': '1', 'step 1|new b₂, x': '3', 'step 1|new b₂, y': '5', 'step 2|m': '2', 'step 2|new b₂, x': '5', 'step 2|new b₂, y': '1', 'step 3|m': '1', 'step 3|new b₂, x': '3', 'step 3|new b₂, y': '5' }],
  });

  // Is got a reduced basis of the lattice of B? (same lattice: got = U·B with U whole and det U = ±1)
  const reducedOf = (B) => (got) => {
    if (!Array.isArray(got) || got.length !== 2 || !got.every((v) => Array.isArray(v) && v.length === 2 && v.every(Number.isInteger))) return 'return two vectors of whole numbers, like [[2, -4], [5, 1]]';
    const det = B[0][0] * B[1][1] - B[0][1] * B[1][0], adj = [[B[1][1], -B[0][1]], [-B[1][0], B[0][0]]];
    const U = got.map((r) => [r[0] * adj[0][0] + r[1] * adj[1][0], r[0] * adj[0][1] + r[1] * adj[1][1]]);
    if (!U.every((r) => r.every((v) => v % det === 0))) return 'these vectors are not both points of the lattice';
    const u = U.map((r) => r.map((v) => v / det)), du = u[0][0] * u[1][1] - u[0][1] * u[1][0];
    if (Math.abs(du) !== 1) return 'these are lattice vectors, but they span only part of the lattice';
    const dot = (a, b) => a[0] * b[0] + a[1] * b[1], [b1, b2] = got;
    if (dot(b1, b1) > dot(b2, b2)) return 'the first vector should be the shorter';
    if (2 * Math.abs(dot(b1, b2)) > dot(b1, b1)) return 'a multiple of the first vector still shortens the second: the basis is not reduced';
    return true;
  };
  const GAUSS_BASES = [[[11, 11], [14, 16]], [[9, 12], [4, 8]], [[12, 18], [6, 11]], [[15, 17], [5, 7]], [[5, 22], [2, 13]], [[6, 1], [1, 5]], [[101, 37], [64, 23]], [[1, 0], [0, 1]]];
  ex({
    id: 'pq-x-gauss-code', chapter: 'pq-ch-lattice', title: 'Write Lagrange–Gauss reduction', level: 3, kind: 'code', fn: 'gauss', params: ['b1', 'b2'],
    text: ['Write `gauss(b1, b2)`: given a basis of a two-dimensional lattice (two vectors `[x, y]` of whole numbers), return a reduced basis `[c1, c2]` of the same lattice: `c1` no longer than `c2`, and |2⟨c1, c2⟩| ≤ ⟨c1, c1⟩, so that `c1` is a shortest non-zero vector. Any reduced basis is accepted (signs and ties may differ).', { math: 'repeat:\n  if |b₂| < |b₁|: swap them\n  m = round(⟨b₂, b₁⟩ / ⟨b₁, b₁⟩)\n  if m = 0: stop\n  b₂ ← b₂ − m·b₁' }],
    start: 'function gauss(b1, b2) {\n  \n}\n',
    tests: () => GAUSS_BASES.map((B) => ({ args: B, check: reducedOf(B) })),
    hints: ['Keep the squared lengths ⟨v, v⟩ as whole numbers; only m needs a division. Math.round works for m.', 'Loop: swap if b₂ is shorter; compute m; stop when m is 0; otherwise subtract m·b₁ from b₂ coordinate by coordinate.', 'function gauss(b1, b2) {\n  const dot = (a, b) => a[0] * b[0] + a[1] * b[1];\n  for (;;) {\n    if (dot(b2, b2) < dot(b1, b1)) [b1, b2] = [b2, b1];\n    const m = Math.round(dot(b2, b1) / dot(b1, b1));\n    if (m === 0) return [b1, b2];\n    b2 = [b2[0] - m * b1[0], b2[1] - m * b1[1]];\n  }\n}'],
    solution: 'function gauss(b1, b2) {\n  const dot = (a, b) => a[0] * b[0] + a[1] * b[1];\n  for (;;) {\n    if (dot(b2, b2) < dot(b1, b1)) [b1, b2] = [b2, b1];\n    const m = Math.round(dot(b2, b1) / dot(b1, b1));\n    if (m === 0) return [b1, b2];\n    b2 = [b2[0] - m * b1[0], b2[1] - m * b1[1]];\n  }\n}\n',
    wrong: ['function gauss(b1, b2) {\n  return [b1, b2];\n}\n', 'function gauss(b1, b2) {\n  const dot = (a, b) => a[0] * b[0] + a[1] * b[1];\n  const m = Math.round(dot(b2, b1) / dot(b1, b1));\n  return [b1, [b2[0] - m * b1[0], b2[1] - m * b1[1]]];\n}\n', 'function gauss(b1, b2) {\n  const dot = (a, b) => a[0] * b[0] + a[1] * b[1];\n  for (let i = 0; i < 50; i++) {\n    if (dot(b2, b2) < dot(b1, b1)) [b1, b2] = [b2, b1];\n    const m = Math.floor(dot(b2, b1) / dot(b1, b1));\n    if (m === 0) return [b1, b2];\n    b2 = [b2[0] - m * b1[0], b2[1] - m * b1[1]];\n  }\n  return [b1, b2];\n}\n'],
  });
  ex({
    id: 'pq-x-babai', chapter: 'pq-ch-lattice', title: 'Babai\'s rounding by hand', level: 2, kind: 'set',
    text: ['The good basis g₁ = (6, 0), g₂ = (−1, 4) and the target t = (15, 9). Write t = a·g₁ + b·g₂, round a and b to the nearest whole numbers, and give the lattice point you reach as (x, y).'],
    answer: '(16, 8)',
    hints: ['The second coordinate gives b at once: 4b = 9.', 'b = 2.25, and 6a − b = 15 gives a = 17.25/6 = 2.875.', 'Round to a = 3, b = 2: the point 3·(6, 0) + 2·(−1, 4) = (16, 8), at distance √2 from t. It is the closest lattice point. With the bad basis (9, 12), (4, 8) the same rounding lands on (20, 16), 8.60 away.'],
    solution: '(16, 8)', wrong: ['(3, 2)', '(20, 16)', '(8, 16)'],
    whyNot: 'Use the good basis, round a and b to whole numbers, and give the lattice point a·g₁ + b·g₂ itself, not the coefficients.',
  });
  ex({
    id: 'pq-x-lwe-dec', chapter: 'pq-ch-lattice', title: 'Decrypt one LWE bit', level: 1, kind: 'number',
    text: ['A toy LWE scheme has q = 17 and the secret s = (3, 7, 1). A ciphertext is u = (10, 4, 9), v = 9. Compute d = v − s·u mod 17 (a number from 0 to 16). Is the bit 0 or 1?'],
    answer: 10,
    hints: ['s·u = 3·10 + 7·4 + 1·9 = 67.', '67 mod 17 = 16, so d = 9 − 16 = −7 ≡ 10 (mod 17).', 'd = 10. Centred it is −7, and |−7| > q/4 = 4.25, so it lies nearer ⌊q/2⌋ = 8 than 0: the bit is 1, with noise 2 (10 = 8 + 2).'],
    solution: '10', wrong: ['16', '-7', '1'],
    whyNot: 'Give d itself, reduced to a number from 0 to 16.',
    why: 'd is nearer 8 than 0, so the bit is 1; the noise carried along was 2.',
  });
  ex({
    id: 'pq-x-lwe-worst', chapter: 'pq-ch-lattice', title: 'Noise that can never cause a failure', level: 3, kind: 'number',
    text: ['A toy LWE scheme uses m = 16 samples, q = 257, and errors drawn uniformly from [−B, B]. An encryption adds up to all 16 errors. What is the largest whole B for which decryption can never fail, for either bit?', 'Decryption reads v − s·u: for the bit 0 it fails if the centred result is more than q/4 from 0; for the bit 1, if it is within q/4 of 0 after ⌊q/2⌋ = 128 has been added.'],
    answer: 3,
    hints: ['The worst case is all 16 errors at +B or all at −B: a total of ±16B.', 'For the bit 1, a noise of −16B gives 128 − 16B, which must stay more than q/4 = 64.25 from 0. For the bit 0, 16B must stay at most 64.25.', 'B = 4 gives 128 − 64 = 64 ≤ 64.25: the bit 1 can read as 0. B = 3 gives a worst case of 48, safe for both bits. So B = 3. With B = 8, as in the topic, failure is possible but rare (0.001% for q = 257).'],
    solution: '3', wrong: ['4', '16', '64'],
    whyNot: 'Check both bits with a total noise of 16B; the bit 1 with negative noise is the tighter case.',
  });
  ex({
    id: 'pq-x-lwe-fail', chapter: 'pq-ch-lattice', title: 'Read the failure rate', level: 2, kind: 'number',
    text: ['Open the LWE topic and set the noise bound to ±6, with 16 samples and q = 101. Frame 5 gives the exact chance that a decryption fails, as a percentage. What is it?', { topic: 'pq-lwe', frame: 0, inputs: true, caption: 'Change the noise bound, then step to frame 5.' }],
    answer: 1.76, tolerance: 0.01,
    hints: ['The noise bound is the first input. Frame 5 is the bell of summed noise with its red tails.', 'The chance is the mass of the tails beyond ±q/4 = 25.25, computed exactly by convolving the 16 terms.', '1.76%. With ±2 it is below 0.01%, with ±8 it is 6.87%: the failure rate climbs steeply with the noise.'],
    solution: '1.76', wrong: ['6.87', '0.06', '25.25'],
    whyNot: 'Set the bound to ±6 exactly (with m = 16 and q = 101), and read the percentage on frame 5.',
  });

  // =========================================================================================================
  // Chapter 3: ML-KEM and lattice signatures
  // =========================================================================================================
  ex({
    id: 'pq-x-mlkem-ek', chapter: 'pq-ch-mlkem', title: 'The size of an ML-KEM-512 key', level: 1, kind: 'number',
    text: ['ML-KEM-512 has k = 2. Its encapsulation key is ByteEncode₁₂(t̂) ‖ ρ: k polynomials of 256 coefficients at 12 bits each, then the 32-byte seed ρ. How many bytes is it?'],
    answer: 800,
    hints: ['One polynomial: 256 × 12 bits = 3072 bits = 384 bytes.', 'k = 2 polynomials: 768 bytes.', '768 + 32 = 800 bytes.'],
    solution: '800', wrong: ['768', '1184', '832'],
    whyNot: 'Count 384 bytes per polynomial, k of them, and add the 32-byte seed.',
  });
  ex({
    id: 'pq-x-mlkem-c', chapter: 'pq-ch-mlkem', title: 'The size of an ML-KEM-1024 ciphertext', level: 2, kind: 'number',
    text: ['ML-KEM-1024 has k = 4, d_u = 11 and d_v = 5. The ciphertext is u compressed to d_u bits a coefficient (k polynomials) and v compressed to d_v bits (one polynomial). How many bytes is it?'],
    answer: 1568,
    hints: ['A polynomial of 256 coefficients at d bits takes 32·d bytes.', 'u: 4 × 32 × 11 = 1408 bytes. v: 32 × 5 = 160 bytes.', '1408 + 160 = 1568 bytes, the same as the encapsulation key of ML-KEM-1024 by coincidence.'],
    solution: '1568', wrong: ['1088', '1408', '1600'],
    whyNot: 'c = 32·(d_u·k + d_v) bytes.',
  });
  ex({
    id: 'pq-x-mlkem-dk', chapter: 'pq-ch-mlkem', title: 'The size of an ML-KEM-512 decapsulation key', level: 2, kind: 'number',
    text: ['The decapsulation key of ML-KEM is dk = dk_PKE ‖ ek ‖ H(ek) ‖ z, where dk_PKE = ByteEncode₁₂(ŝ) and H(ek) and z are 32 bytes each. How many bytes is it for ML-KEM-512 (k = 2)?'],
    answer: 1632,
    hints: ['dk_PKE is k polynomials at 12 bits: 384k bytes. ek is 384k + 32 bytes.', 'For k = 2: dk_PKE = 768, ek = 800.', '768 + 800 + 32 + 32 = 1632 bytes (768k + 96 in general).'],
    solution: '1632', wrong: ['768', '1600', '2400'],
    whyNot: 'Add dk_PKE, the whole of ek, H(ek) and z.',
  });
  ex({
    id: 'pq-x-compress', chapter: 'pq-ch-mlkem', title: 'Compress and decompress', level: 2, kind: 'number',
    text: ['ML-KEM compresses a coefficient x mod q = 3329 to d bits with Compress_d(x) = ⌈(2ᵈ/q)·x⌋ mod 2ᵈ (⌈·⌋ rounds to the nearest whole number) and expands it back with Decompress_d(y) = ⌈(q/2ᵈ)·y⌋. What is Decompress₄(Compress₄(2000))?'],
    answer: 2081,
    hints: ['(16/3329) × 2000 = 9.61.', 'Compress₄(2000) = 10. Then (3329/16) × 10 = 2080.6.', 'Decompress₄(10) = 2081: the round trip moved 2000 by 81, rounding noise that v carries. With 10 bits (as for u) the round trip gives 1999.'],
    solution: '2081', wrong: ['10', '2000', '2080'],
    whyNot: 'Compress first (a 4-bit number), then decompress, rounding to the nearest whole number each time.',
  });

  // a toy NTT in the shape of FIPS 203's: q = 17, n = 8, ζ = 2 (a primitive 8th root of unity), two layers
  const nttRef = (f, q, zetas) => { f = f.slice(); const n = f.length; let k = 1; for (let len = n / 2; len >= 2; len /= 2) for (let st = 0; st < n; st += 2 * len) { const z = zetas[k++]; for (let j = st; j < st + len; j++) { const t = (z * f[j + len]) % q; f[j + len] = (f[j] - t + q) % q; f[j] = (f[j] + t) % q; } } return f; };
  const TOY_Z = [1, 4, 2, 8], TOY_F = [3, 1, 4, 1, 5, 9, 2, 6];
  const layer1 = (() => { const f = TOY_F.slice(); for (let j = 0; j < 4; j++) { const t = (4 * f[j + 4]) % 17; f[j + 4] = (f[j] - t + 17) % 17; f[j] = (f[j] + t) % 17; } return f; })();
  const layer2 = nttRef(TOY_F, 17, TOY_Z);
  const nttCells = Object.fromEntries([].concat(...layer1.map((v, i) => [['index ' + i + '|after layer 1', String(v)], ['index ' + i + '|after layer 2', String(layer2[i])]])));
  ex({
    id: 'pq-x-ntt-table', chapter: 'pq-ch-mlkem', title: 'Two layers of butterflies', level: 2, kind: 'table',
    text: ['A toy NTT in the shape of ML-KEM\'s: q = 17, n = 8 coefficients, ζ = 2 (a primitive 8th root of unity mod 17). Layer 1 pairs j with j + 4 and uses ζ₁ = 4; layer 2 pairs j with j + 2 inside blocks of 4, with ζ₂ = 2 for the first block and ζ₃ = 8 for the second. Each butterfly is t = ζ·b mod q, then (a, b) ↦ (a + t, a − t) mod q. Transform f = (3, 1, 4, 1, 5, 9, 2, 6).'],
    rows: ['index 0', 'index 1', 'index 2', 'index 3', 'index 4', 'index 5', 'index 6', 'index 7'], cols: ['after layer 1', 'after layer 2'],
    cells: nttCells,
    hints: ['Layer 1, pair (0, 4): t = 4 × 5 = 20 ≡ 3, so index 0 becomes 3 + 3 = 6 and index 4 becomes 3 − 3 = 0.', 'After layer 1: ' + layer1.join(', ') + '. Layer 2, pair (0, 2) with ζ₂ = 2: t = 2 × 12 = 24 ≡ 7, giving 6 + 7 = 13 and 6 − 7 ≡ 16.', 'After layer 2: ' + layer2.join(', ') + '. Each pair (f̂₂ᵢ, f̂₂ᵢ₊₁) is f reduced modulo one factor X² − γ: the first pair, (13, 2), is f mod (X² − 2).'],
    solution: nttCells,
    wrong: [Object.assign({}, nttCells, { 'index 0|after layer 2': '6', 'index 2|after layer 2': '0' })],
  });
  const NTT_CASES = [[TOY_F, 17, TOY_Z], [[0, 0, 0, 0, 0, 0, 0, 1], 17, TOY_Z], [[16, 16, 16, 16, 16, 16, 16, 16], 17, TOY_Z], [[1, 2, 3, 4, 5, 6, 7, 8], 17, TOY_Z], [[5, 0, 0, 0, 0, 0, 0, 0], 17, TOY_Z]];
  ex({
    id: 'pq-x-ntt-code', chapter: 'pq-ch-mlkem', title: 'Write the NTT', level: 3, kind: 'code', fn: 'ntt', params: ['f', 'q', 'zetas'],
    text: ['Write `ntt(f, q, zetas)` in the shape of FIPS 203, Algorithm 9: for len = n/2, n/4, …, 2, walk the blocks of 2·len coefficients, take the next ζ from `zetas` (starting at index 1), and apply the butterfly t = ζ·f[j + len] mod q; f[j + len] = f[j] − t; f[j] = f[j] + t (mod q) for each j in the first half of the block. Return a new array.', 'The tests use the toy of the previous exercise (q = 17, n = 8, zetas = [1, 4, 2, 8]) and the real ML-KEM transform: q = 3329, n = 256, and the 128 values 17^BitRev₇(i) mod 3329, checked against the engine.'],
    start: 'function ntt(f, q, zetas) {\n  f = f.slice();\n  \n  return f;\n}\n',
    tests: () => {
      const K = P().MLKEM, r = P().rng(1403), polys = [0, 1, 2].map(() => Array.from({ length: 256 }, () => r.int(3329)));
      return NTT_CASES.map((args) => ({ args, want: nttRef(...args) })).concat(polys.map((f) => ({ args: [f, 3329, K.ZETAS.slice()], want: K.ntt(f) })));
    },
    hints: ['Three loops: len halves from n/2 down to 2; start runs over 0, 2·len, 4·len, …; j runs from start to start + len − 1. One ζ per block.', 'Products stay below 3329² ≈ 11 million, safe for ordinary numbers. Keep results in [0, q): add q before taking % on a difference.', 'function ntt(f, q, zetas) {\n  f = f.slice();\n  let k = 1;\n  for (let len = f.length / 2; len >= 2; len /= 2)\n    for (let start = 0; start < f.length; start += 2 * len) {\n      const z = zetas[k++];\n      for (let j = start; j < start + len; j++) {\n        const t = (z * f[j + len]) % q;\n        f[j + len] = (f[j] - t + q) % q;\n        f[j] = (f[j] + t) % q;\n      }\n    }\n  return f;\n}'],
    solution: 'function ntt(f, q, zetas) {\n  f = f.slice();\n  let k = 1;\n  for (let len = f.length / 2; len >= 2; len /= 2)\n    for (let start = 0; start < f.length; start += 2 * len) {\n      const z = zetas[k++];\n      for (let j = start; j < start + len; j++) {\n        const t = (z * f[j + len]) % q;\n        f[j + len] = (f[j] - t + q) % q;\n        f[j] = (f[j] + t) % q;\n      }\n    }\n  return f;\n}\n',
    wrong: ['function ntt(f, q, zetas) {\n  f = f.slice();\n  let k = 1;\n  for (let len = f.length / 2; len >= 2; len /= 2)\n    for (let start = 0; start < f.length; start += 2 * len) {\n      const z = zetas[k++];\n      for (let j = start; j < start + len; j++) {\n        const t = (z * f[j + len]) % q;\n        f[j + len] = (f[j] - t) % q;\n        f[j] = (f[j] + t) % q;\n      }\n    }\n  return f;\n}\n', 'function ntt(f, q, zetas) {\n  f = f.slice();\n  let k = 0;\n  for (let len = f.length / 2; len >= 2; len /= 2)\n    for (let start = 0; start < f.length; start += 2 * len) {\n      const z = zetas[k++];\n      for (let j = start; j < start + len; j++) {\n        const t = (z * f[j + len]) % q;\n        f[j + len] = (f[j] - t + q) % q;\n        f[j] = (f[j] + t) % q;\n      }\n    }\n  return f;\n}\n'],
  });
  ex({
    id: 'pq-x-reject', chapter: 'pq-ch-mlkem', title: 'Why reject silently?', level: 1, kind: 'choice',
    text: ['When ML-KEM\'s re-encryption check fails, decapsulation returns K̄ = J(z ‖ c) instead of an error. Why?'],
    options: ['To save the time of sending an error message', 'So that an attacker who sends crafted ciphertexts learns nothing from which ones were rejected', 'Because the check cannot fail for honest ciphertexts', 'So that the sender can retry with the same ciphertext'],
    answer: 1,
    whyNot: { 0: 'An error message is no slower than a key. The reason is what the answer would reveal.', 2: 'Honest ciphertexts almost never fail, but that is not why the reply looks like a key.', 3: 'A retry would give the same K̄ again; nothing is gained by it.' },
    hints: ['Think of an attacker who modifies ciphertexts and watches how the receiver reacts.', 'Whether decryption of a crafted ciphertext succeeds depends on the secret s; a visible "invalid" answer would leak a little of s each time.', 'Implicit rejection makes every reply a 32-byte key, honest or not, so the reaction says nothing about s.'],
    solution: 1, wrong: [0, 2, 3],
  });
  ex({
    id: 'pq-x-mldsa-bound', chapter: 'pq-ch-mlkem', title: 'The rejection bound of ML-DSA-44', level: 1, kind: 'number',
    text: ['In ML-DSA-44, γ₁ = 2¹⁷ = 131 072, the challenge has τ = 39 entries ±1, and the secret s₁ has coefficients in [−η, η] with η = 2. A response z is rejected unless every coefficient satisfies |zᵢ| < γ₁ − β, with β = τ·η. What is γ₁ − β?'],
    answer: 130994,
    hints: ['β bounds every coefficient of c·s₁: τ terms, each at most η in size.', 'β = 39 × 2 = 78.', 'γ₁ − β = 131 072 − 78 = 130 994.'],
    solution: '130994', wrong: ['131072', '130994.5', '78'],
    whyNot: 'Subtract β = τ·η from γ₁.',
  });
  ex({
    id: 'pq-x-mldsa-why', chapter: 'pq-ch-mlkem', title: 'What the aborts protect', level: 2, kind: 'choice',
    text: ['A lattice signer skips the rejection step and publishes every z = y + c·s₁, where y is uniform in [−γ₁ + 1, γ₁] and the challenge c is public. What can someone who collects many signatures learn?'],
    options: ['Nothing: y hides c·s₁ completely', 'Where a coefficient of z lies beyond γ₁, the sign of c·s₁ there; enough of these give s₁', 'Only the message', 'The mask y of each signature, but nothing about s₁'],
    answer: 1,
    whyNot: { 0: 'y is bounded, so near the edges it cannot hide the shift c·s₁: a z beyond γ₁ can only come from a positive push.', 2: 'The message is public anyway; the danger is to the key.', 3: 'y is not revealed directly; what leaks is information about c·s₁, and so about s₁.' },
    hints: ['If y were uniform modulo q, z would be uniform too. Here y is bounded.', 'A coefficient of z above γ₁ cannot come from y alone.', 'Each such coefficient reveals the sign of the matching coefficient of c·s₁, and c is public: linear information about s₁ that piles up. Rejecting every z with ‖z‖∞ ≥ γ₁ − β makes z uniform on the accepted range.'],
    solution: 1, wrong: [0, 2, 3],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
