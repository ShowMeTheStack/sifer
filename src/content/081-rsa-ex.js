// Part 8, RSA: the exercises, the part's tour and its course. The lessons are in 080-rsa.js. The exercises compute
// (a toy key by hand, encryption and decryption, square-and-multiply, the CRT), implement (square-and-multiply, the
// inverse, Garner's recombination, a Miller–Rabin round) and ask why each rule for choosing and using a key exists.
// Every number below was worked out with the engines (S.NT, S.RSA) in a scratch script before it was written down.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('rsa-x-keygen-d')) return;
  const ex = (o) => C.exercise(o);
  const fn = (name, params, body) => 'function ' + name + '(' + params.join(', ') + ') {\n' + body + '\n}';
  // small BigInt helpers for the reference answers of the code exercises
  const mod = (a, n) => ((a % n) + n) % n;
  const pow = (b, e, n) => { let r = 1n; b = mod(b, n); while (e > 0n) { if (e & 1n) r = r * b % n; b = b * b % n; e >>= 1n; } return r % n; };
  const inv = (a, n) => { let [r0, r1, s0, s1] = [mod(a, n), n, 1n, 0n]; while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; } return r0 === 1n ? mod(s0, n) : null; };

  // ===========================================================================================================
  // Chapter 1: the scheme
  // ===========================================================================================================
  ex({
    id: 'rsa-x-keygen-d', chapter: 'rsa-scheme', title: 'The private exponent', level: 1, kind: 'number', answer: 5597,
    text: ['A toy key is made from p = 89 and q = 107 with e = 5. Compute φ(n) and then the private exponent d = e⁻¹ mod φ(n), as a number between 1 and φ(n) − 1. The number-theory bench (Euclid) runs the extended algorithm if you want to check your table.'],
    hints: ['φ(n) = (p − 1)(q − 1) = 88·106.', 'φ(n) = 9328. Find d with 5·d ≡ 1 (mod 9328): extended Euclid on 9328 and 5, or notice that 9328 = 5·1865 + 3 and keep going.', 'd = 5597: 5·5597 = 27985 = 3·9328 + 1.'],
    solution: '5597', wrong: ['9328', '3731', '9523'],
    whyNot: { 9328: 'That is φ(n). d is the inverse of e modulo φ(n).', 9523: 'That is n = p·q. d lives modulo φ(n), not modulo n.', '*': 'Check your d: 5·d mod 9328 must be 1.' },
  });
  ex({
    id: 'rsa-x-bad-e', chapter: 'rsa-scheme', title: 'Which exponents are allowed?', level: 1, kind: 'choice',
    text: ['A key generator found p = 71 and q = 83. Which of these public exponents can it use, that is, which have an inverse modulo φ(n)?'],
    options: ['e = 3', 'e = 5', 'e = 7', 'e = 11', 'e = 41', 'e = 13'],
    answer: [0, 3, 5],
    hints: ['e needs gcd(e, φ(n)) = 1, which is the same as gcd(e, p − 1) = 1 and gcd(e, q − 1) = 1.', 'p − 1 = 70 = 2·5·7 and q − 1 = 82 = 2·41.', 'Allowed: 3, 11 and 13. 5 and 7 divide 70, and 41 divides 82, so they have no inverse and there would be no d.'],
    solution: [0, 3, 5], wrong: [[0, 1, 2, 3, 4, 5], [0, 3], [1, 2, 4]],
  });
  const KG = { 'n|value': '20413', 'φ(n)|value': '20128', 'd|value': '5751', 'dp = d mod (p − 1)|value': '39', 'dq = d mod (q − 1)|value': '127', 'qinv = q⁻¹ mod p|value': '80' };
  ex({
    id: 'rsa-x-keygen-table', chapter: 'rsa-scheme', title: 'A whole key, CRT values included', level: 2, kind: 'table',
    text: ['Build the full private key from p = 137, q = 149 and e = 7: the modulus, φ(n), d, and the three numbers kept for decryption by the CRT. The [number-theory bench](#bench/nt) does the extended Euclid steps.'],
    rows: ['n', 'φ(n)', 'd', 'dp = d mod (p − 1)', 'dq = d mod (q − 1)', 'qinv = q⁻¹ mod p'], cols: ['value'], corner: 'Key part',
    cells: KG,
    hints: ['n = 137·149 and φ(n) = 136·148. Then d = 7⁻¹ mod φ(n) by extended Euclid.', 'φ(n) = 20128 and d = 5751, since 7·5751 = 40257 = 2·20128 + 1. Reduce d modulo 136 and modulo 148; qinv is the inverse of 149 ≡ 12 modulo 137.', 'n = 20413, φ(n) = 20128, d = 5751, dp = 39, dq = 127, qinv = 80 (149·80 = 11920 = 87·137 + 1).'],
    solution: KG,
    wrong: [Object.assign({}, KG, { 'n|value': '20413', 'd|value': '2876' }), Object.assign({}, KG, { 'qinv = q⁻¹ mod p|value': '125' })],
  });
  ex({
    id: 'rsa-x-candidates', chapter: 'rsa-scheme', title: 'Trial division first', level: 1, kind: 'set', answer: '{1003, 1007, 1009, 1013, 1019}',
    text: ['A key generator draws the odd candidates 1001, 1003, 1005, …, 1019 and first throws out every one divisible by a prime up to 13 (3, 5, 7, 11 or 13). Which candidates survive to the Miller–Rabin test? Write them as a set, such as {1003, 1009}.'],
    hints: ['Strike out the multiples of 3 (digit sum divisible by 3) and of 5 (ending in 5), then test 7, 11 and 13.', '1001 = 7·11·13, 1005 and 1015 end in 5, and 1011 and 1017 are multiples of 3.', 'Survivors: {1003, 1007, 1009, 1013, 1019}. Two of them are not prime (1003 = 17·59, 1007 = 19·53): Miller–Rabin catches those.'],
    solution: '{1003, 1007, 1009, 1013, 1019}', wrong: ['{1009, 1013, 1019}', '{1001, 1003, 1007, 1009, 1013, 1019}'],
    whyNot: 'Only divisibility by 3, 5, 7, 11 and 13 is tested at this stage, so some composites with larger factors survive.',
  });
  const MR = { 's|value': '4', 'd|value': '35', 'x₀ = 2^d mod n|value': '263', 'x₁ = x₀² mod n|value': '166', 'x₂ = x₁² mod n|value': '67', 'x₃ = x₂² mod n|value': '1' };
  ex({
    id: 'rsa-x-mr-table', chapter: 'rsa-scheme', title: 'One Miller–Rabin round on 561', level: 2, kind: 'table',
    text: ['561 = 3·11·17 passes Fermat\'s test for every base coprime to it. Run one round of Miller–Rabin with base a = 2: write n − 1 = 2^s·d with d odd, then fill in x₀ = 2^d mod 561 and its successive squares. (The bench\'s Powers tool computes x₀.)'],
    rows: ['s', 'd', 'x₀ = 2^d mod n', 'x₁ = x₀² mod n', 'x₂ = x₁² mod n', 'x₃ = x₂² mod n'], cols: ['value'], corner: 'n = 561, a = 2',
    cells: MR,
    hints: ['560 = 16·35, so s = 4 and d = 35.', '2³⁵ mod 561 = 263. Square it three times modulo 561.', 's = 4, d = 35, then 263, 166, 67, 1. The sequence reaches 1 without passing through 560 = −1, so 67 is a square root of 1 other than ±1: 561 is composite, and base 2 proves it.'],
    solution: MR,
    wrong: [Object.assign({}, MR, { 's|value': '1', 'd|value': '280' }), Object.assign({}, MR, { 'x₃ = x₂² mod n|value': '560' })],
  });
  ex({
    id: 'rsa-x-code-mr', chapter: 'rsa-scheme', title: 'Write one Miller–Rabin round', level: 2, kind: 'code', fn: 'mrRound', params: ['n', 'a'],
    text: ['Write `mrRound(n, a)` for an odd BigInt n > 3 and a base a in 2 … n − 2. Write n − 1 = 2^s·d with d odd and return `true` if n passes the strong test to base a (it may be prime) and `false` if a proves n composite. Carmichael numbers such as 561 and 1105 must be caught.'],
    start: 'function mrRound(n, a) {\n  \n}',
    ref: (n, a) => { let d = n - 1n, s = 0; while (d % 2n === 0n) { d /= 2n; s++; } let x = pow(a, d, n); if (x === 1n || x === n - 1n) return true; for (let i = 1; i < s; i++) { x = x * x % n; if (x === n - 1n) return true; } return false; },
    cases: [[97n, 5n], [561n, 2n], [561n, 50n], [1105n, 7n], [2047n, 2n], [2047n, 3n], [1009n, 11n], [1003n, 2n], [3215031751n, 2n], [3215031751n, 11n], [2n ** 61n - 1n, 3n], [221n, 174n], [221n, 137n]],
    hints: ['Halve n − 1 while it is even to find s and d. Then x = a^d mod n with square-and-multiply on BigInts.', 'If x is 1 or n − 1, return true. Otherwise square x up to s − 1 more times: if it becomes n − 1, return true. If it never does, return false.', fn('mrRound', ['n', 'a'], '  const pow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };\n  let d = n - 1n, s = 0;\n  while (d % 2n === 0n) { d /= 2n; s++; }\n  let x = pow(a, d, n);\n  if (x === 1n || x === n - 1n) return true;\n  for (let i = 1; i < s; i++) { x = x * x % n; if (x === n - 1n) return true; }\n  return false;')],
    solution: fn('mrRound', ['n', 'a'], '  const pow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };\n  let d = n - 1n, s = 0;\n  while (d % 2n === 0n) { d /= 2n; s++; }\n  let x = pow(a, d, n);\n  if (x === 1n || x === n - 1n) return true;\n  for (let i = 1; i < s; i++) { x = x * x % n; if (x === n - 1n) return true; }\n  return false;'),
    wrong: [
      fn('mrRound', ['n', 'a'], '  let r = 1n, b = a % n, e = n - 1n;\n  while (e > 0n) { if (e & 1n) r = r * b % n; b = b * b % n; e >>= 1n; }\n  return r === 1n;'),
      fn('mrRound', ['n', 'a'], '  const pow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };\n  let d = n - 1n, s = 0;\n  while (d % 2n === 0n) { d /= 2n; s++; }\n  let x = pow(a, d, n);\n  if (x === 1n || x === n - 1n) return true;\n  for (let i = 1; i < s; i++) { x = x * x % n; if (x === 1n) return true; }\n  return false;'),
    ],
  });
  ex({
    id: 'rsa-x-encrypt', chapter: 'rsa-scheme', title: 'Encrypt with a toy key', level: 1, kind: 'number', answer: 8147,
    text: ['The toy public key is n = 9523 (= 89·107) and e = 5. Encrypt m = 2024 with textbook RSA: c = m⁵ mod n. Reduce after every multiplication.'],
    hints: ['5 = 101 in binary: square, square, then multiply by m.', 'm² mod 9523 = 1686, and m⁴ = 1686² mod 9523 = 4742.', 'c = 4742·2024 mod 9523 = 8147: 2 squarings and 1 multiplication.'],
    solution: '8147', wrong: ['2024', '4742', '1686'],
    whyNot: { 4742: 'That is m⁴: one multiplication by m is still to come.', 1686: 'That is m². Square once more, then multiply by m.', '*': 'Compute m², m⁴ and m⁵ in turn, reducing modulo 9523 each time.' },
  });
  ex({
    id: 'rsa-x-decrypt', chapter: 'rsa-scheme', title: 'Decrypt with the same key', level: 2, kind: 'number', answer: 4321,
    text: ['For the key n = 9523, e = 5, the private exponent is d = 5597. Decrypt c = 5803. The bench\'s Powers tool takes x = 5803, e = 5597, n = 9523; then check your answer by encrypting it again.'],
    hints: ['m = c^d mod n.', 'd = 5597 = 1010111011101 in binary: 12 squarings and 8 multiplications, too many to enjoy by hand.', 'm = 5803^5597 mod 9523 = 4321, and 4321⁵ mod 9523 = 5803.'],
    solution: '4321', wrong: ['5803', '5597', '1234'],
    whyNot: 'Raise c to d modulo n, and check by raising your answer to e = 5: you should get 5803 back.',
  });
  ex({
    id: 'rsa-x-lambda', chapter: 'rsa-scheme', title: 'A smaller d from λ(n)', level: 2, kind: 'number', answer: 933,
    text: ['Many standards compute the private exponent modulo λ(n) = lcm(p − 1, q − 1) instead of φ(n). For p = 89, q = 107 and e = 5, what is d = e⁻¹ mod λ(n)? It decrypts exactly like the d = 5597 found modulo φ(n).'],
    hints: ['p − 1 = 88 = 2³·11 and q − 1 = 106 = 2·53. Their lcm keeps the highest power of each prime.', 'λ(n) = 2³·11·53 = 4664, half of φ(n) = 9328. Now invert 5 modulo 4664.', 'd = 933: 5·933 = 4665 = 4664 + 1. And 5597 = 933 + 4664, so the two exponents differ by a multiple of λ(n) and give the same powers.'],
    solution: '933', wrong: ['5597', '4664', '9328'],
    whyNot: { 5597: 'That is the inverse modulo φ(n). Reduce the work: invert 5 modulo λ(n).', '*': 'Check: 5·d mod λ(n) must be 1, with λ(n) = lcm(88, 106).' },
  });
  ex({
    id: 'rsa-x-secrets', chapter: 'rsa-scheme', title: 'Which leaks lose the whole key?', level: 2, kind: 'choice',
    text: ['An RSA public key (n, e) is published. Which of these, if they leaked, would let anyone compute the private key?'],
    options: ['φ(n)', 'd', 'p', 'One ciphertext c and its plaintext m', 'p + q', 'dp = d mod (p − 1)'],
    answer: [0, 1, 2, 4, 5],
    hints: ['From φ(n) or from p + q, p and q are the two roots of x² − (p + q)·x + n = 0, since p + q = n − φ(n) + 1.', 'From d, e·d − 1 is a multiple of φ(n), and a few random square roots of 1 split n. From dp, for a random a, gcd(a^(e·dp) − a, n) = p, since e·dp ≡ 1 modulo p − 1.', 'Every one except the plaintext and ciphertext pair: anyone can make such pairs by encrypting with the public key. φ(n), d, p, p + q and dp each give the factors.'],
    solution: [0, 1, 2, 4, 5], wrong: [[1, 2], [0, 1, 2, 3, 4, 5], [0, 1, 2]],
    why: 'Each secret number of an RSA key is equivalent to knowing the factors of n.',
  });
  ex({
    id: 'rsa-x-fixed', chapter: 'rsa-scheme', title: 'Messages that do not move', level: 3, kind: 'number', answer: 15,
    text: ['With n = 35 = 5·7 and e = 5, how many messages m in 0 … 34 have m⁵ ≡ m (mod 35), so that textbook RSA leaves them unchanged? Think modulo 5 and modulo 7 separately, then join with the CRT.'],
    hints: ['Modulo a prime p, m^e ≡ m holds for m = 0 and for the m ≠ 0 with m^(e − 1) ≡ 1, which number gcd(e − 1, p − 1).', 'Modulo 5: 1 + gcd(4, 4) = 5 solutions (all of them). Modulo 7: 1 + gcd(4, 6) = 3 solutions (0, 1 and 6).', '5·3 = 15 fixed messages, by the CRT. At real size the count is tiny compared with n, but 0, 1 and n − 1 are always among them.'],
    solution: '15', wrong: ['3', '35', '9'],
    whyNot: { 3: 'Count 0 too, and both primes: the CRT multiplies the counts modulo 5 and modulo 7.', 35: 'Modulo 7 only 0, 1 and 6 are fixed, so not every message is.', '*': 'Count the solutions modulo 5 and modulo 7, and multiply.' },
  });

  // ===========================================================================================================
  // Chapter 2: making it fast
  // ===========================================================================================================
  ex({
    id: 'rsa-x-sqm-count', chapter: 'rsa-speed', title: 'Counting operations', level: 1, kind: 'number', answer: 27,
    text: ['Left-to-right square-and-multiply raises c to d = 1000003. How many operations does it take in all, squarings plus multiplications?'],
    hints: ['Write d in binary. The leading 1 costs nothing; every later bit is a squaring, and every later 1 bit a multiplication too.', '1000003 = 11110100001001000011: 20 bits, 9 of them 1.', '19 squarings and 8 multiplications: 27 operations.'],
    solution: '27', wrong: ['20', '29', '1000002'],
    whyNot: { 29: 'The leading bit only sets the start value to c: count the squarings and multiplications after it.', 1000002: 'That is repeated multiplication. Square-and-multiply needs about one operation per bit.', '*': 'Count the bits after the first, and the 1 bits after the first.' },
  });
  const SQ = { 'bit 1 (1)|r': '7', 'bit 2 (1)|r': '132', 'bit 3 (0)|r': '122', 'bit 4 (1)|r': '165', 'bit 5 (0)|r': '6', 'bit 6 (1)|r': '41' };
  ex({
    id: 'rsa-x-sqm-table', chapter: 'rsa-speed', title: 'Square-and-multiply, step by step', level: 2, kind: 'table',
    text: ['Compute 7⁵³ mod 211 from the left. 53 = 110101 in binary. Fill in the value r after each bit is handled: for the first bit r = 7; for each later bit square r, and if the bit is 1 multiply by 7, reducing modulo 211.'],
    rows: ['bit 1 (1)', 'bit 2 (1)', 'bit 3 (0)', 'bit 4 (1)', 'bit 5 (0)', 'bit 6 (1)'], cols: ['r'], corner: '53 = 110101',
    cells: SQ,
    hints: ['Bit 2: r = 7²·7 = 343 mod 211 = 132.', 'Bit 3 is 0: just square, 132² mod 211 = 122. Bit 4: 122² = 114 (mod 211), times 7 is 165.', 'r = 7, 132, 122, 165, 6, 41. So 7⁵³ mod 211 = 41, after 5 squarings and 3 multiplications.'],
    solution: SQ,
    wrong: [Object.assign({}, SQ, { 'bit 3 (0)|r': '76' }), Object.assign({}, SQ, { 'bit 1 (1)|r': '49' })],
  });
  ex({
    id: 'rsa-x-code-sqm', chapter: 'rsa-speed', title: 'Write square-and-multiply', level: 2, kind: 'code', fn: 'modPow', params: ['x', 'e', 'n'],
    text: ['Write `modPow(x, e, n)` for BigInts with e ≥ 0 and n ≥ 2: return x^e mod n in 0 … n − 1 by reading the bits of e. One test has a 127-bit exponent, so multiplying e times will not finish.'],
    start: 'function modPow(x, e, n) {\n  \n}',
    ref: (x, e, n) => pow(x, e, n),
    cases: [[5n, 0n, 23n], [5n, 1n, 23n], [7n, 53n, 211n], [2024n, 5n, 9523n], [5803n, 5597n, 9523n], [7n, 560n, 561n], [100n, 3n, 7n], [123456789n, 65537n, 1000000007n], [987654321987654321n, 2n ** 127n - 3n, 2n ** 127n - 1n]],
    hints: ['Start with r = 1n. For each bit of e from the top: r = r·r mod n, then if the bit is 1, r = r·x mod n.', '`e.toString(2)` gives the bits, most significant first. Reduce x modulo n first, so that x ≥ n works too, and use BigInt literals: `1n`, not `1`.', fn('modPow', ['x', 'e', 'n'], '  let r = 1n;\n  x %= n;\n  for (const b of e.toString(2)) {\n    r = r * r % n;\n    if (b === "1") r = r * x % n;\n  }\n  return r % n;')],
    solution: fn('modPow', ['x', 'e', 'n'], '  let r = 1n;\n  x %= n;\n  for (const b of e.toString(2)) {\n    r = r * r % n;\n    if (b === \'1\') r = r * x % n;\n  }\n  return r % n;'),
    wrong: [fn('modPow', ['x', 'e', 'n'], '  let r = 1n;\n  for (let i = 0n; i < e; i++) r = r * x % n;\n  return r;'), fn('modPow', ['x', 'e', 'n'], '  let r = x;\n  for (const b of e.toString(2)) {\n    r = r * r % n;\n    if (b === \'1\') r = r * x % n;\n  }\n  return r;')],
    timeLimit: 3000,
  });
  ex({
    id: 'rsa-x-ladder', chapter: 'rsa-speed', title: 'What the ladder hides', level: 2, kind: 'choice',
    text: ['An attacker can watch a chip compute c^d mod n and tell each squaring from each multiplication. Which statement is right?'],
    options: ['Against left-to-right square-and-multiply, the S/M sequence spells out d; against the Montgomery ladder it shows only how many bits d has', 'Both loops leak d, since both multiply', 'Neither leaks d, since the values are reduced modulo n', 'The ladder hides d because it does fewer operations'],
    answer: 0,
    whyNot: { 1: 'The ladder multiplies on every bit, whatever its value, so the pattern no longer depends on d.', 2: 'The values are hidden; the pattern of operations is not, and it follows the bits.', 3: 'The ladder does more work: one squaring and one multiplication for every bit.' },
    hints: ['In square-and-multiply, a multiplication happens only after a 1 bit.', 'The ladder does M then S for every bit; the bit only decides which register gets which result.', 'The first: S·SM·S·SM… reads off d bit by bit, while the ladder\'s MSMSMS… is the same for every exponent of the same length.'],
    solution: 0, wrong: [1, 3],
  });
  ex({
    id: 'rsa-x-montmul', chapter: 'rsa-speed', title: 'Into Montgomery form', level: 1, kind: 'number', answer: 28,
    text: ['Montgomery multiplication modulo n = 97 uses R = 128. Before an exponentiation each operand is converted once into Montgomery form, ā = a·R mod n. What is the Montgomery form of a = 76?'],
    hints: ['Multiply by R, then reduce modulo n (this one conversion still needs a division).', '76·128 = 9728.', '9728 = 100·97 + 28, so ā = 28.'],
    solution: '28', wrong: ['9728', '76', '0'],
    whyNot: { 9728: 'Reduce a·R modulo n = 97.', 0: 'Reduce modulo n = 97, not modulo R = 128.', '*': 'Compute 76·128 and take the remainder on division by 97.' },
  });
  const CR = { 'c mod p|value': '99', 'c mod q|value': '5', 'mp = (c mod p)^dp mod p|value': '15', 'mq = (c mod q)^dq mod q|value': '127', 'h = qinv·(mp − mq) mod p|value': '82', 'm = mq + h·q|value': '12345' };
  ex({
    id: 'rsa-x-crt-table', chapter: 'rsa-speed', title: 'Decrypt by the CRT', level: 2, kind: 'table',
    text: ['The key p = 137, q = 149, e = 7 has dp = 39, dq = 127 and qinv = 80. Decrypt c = 18183 the way a key holder does: two half-size exponentiations, then Garner\'s formula. The bench\'s Powers tool does the exponentiations.'],
    rows: ['c mod p', 'c mod q', 'mp = (c mod p)^dp mod p', 'mq = (c mod q)^dq mod q', 'h = qinv·(mp − mq) mod p', 'm = mq + h·q'], cols: ['value'], corner: 'Step',
    cells: CR,
    hints: ['18183 = 132·137 + 99 and 18183 = 122·149 + 5.', 'mp = 99³⁹ mod 137 = 15 and mq = 5¹²⁷ mod 149 = 127. Then mp − mq = −112 ≡ 25 (mod 137).', 'c mod p = 99, c mod q = 5, mp = 15, mq = 127, h = 80·25 mod 137 = 82, m = 127 + 82·149 = 12345. Check: 12345 leaves 15 modulo 137 and 127 modulo 149.'],
    solution: CR,
    wrong: [Object.assign({}, CR, { 'h = qinv·(mp − mq) mod p|value': '-8960' }), Object.assign({}, CR, { 'm = mq + h·q|value': '11361' })],
  });
  ex({
    id: 'rsa-x-code-inverse', chapter: 'rsa-speed', title: 'Write the modular inverse', level: 2, kind: 'code', fn: 'modInverse', params: ['a', 'n'],
    text: ['Write `modInverse(a, n)` for BigInts with n ≥ 2: return the x in 0 … n − 1 with a·x ≡ 1 (mod n), or `null` when gcd(a, n) ≠ 1. This is how d comes from e and how qinv comes from q.'],
    start: 'function modInverse(a, n) {\n  \n}',
    ref: (a, n) => inv(a, n),
    cases: [[5n, 9328n], [7n, 20128n], [149n, 137n], [17n, 136n * 148n], [6n, 9n], [1n, 7n], [65537n, (2n ** 64n - 59n) - 1n], [123456789n, 1000000007n], [-3n, 11n]],
    hints: ['Extended Euclid on (a mod n, n), tracking only the coefficient of a: rows (r, s) start as (a, 1) and (n, 0).', 'When the remainder reaches 0 the row before holds g and s with a·s ≡ g. If g ≠ 1 there is no inverse. s may be negative: return ((s % n) + n) % n. Reduce a first, so that a negative a works.', fn('modInverse', ['a', 'n'], '  let [r0, r1, s0, s1] = [((a % n) + n) % n, n, 1n, 0n];\n  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }\n  if (r0 !== 1n) return null;\n  return ((s0 % n) + n) % n;')],
    solution: fn('modInverse', ['a', 'n'], '  let [r0, r1, s0, s1] = [((a % n) + n) % n, n, 1n, 0n];\n  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }\n  if (r0 !== 1n) return null;\n  return ((s0 % n) + n) % n;'),
    wrong: [fn('modInverse', ['a', 'n'], '  let [r0, r1, s0, s1] = [a, n, 1n, 0n];\n  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }\n  return s0;'), fn('modInverse', ['a', 'n'], '  for (let x = 1n; x < n; x++) if (a * x % n === 1n) return x;\n  return null;')],
    timeLimit: 3000,
  });
  ex({
    id: 'rsa-x-code-garner', chapter: 'rsa-speed', title: 'Write Garner\'s recombination', level: 3, kind: 'code', fn: 'garner', params: ['mp', 'mq', 'p', 'q', 'qinv'],
    text: ['Write `garner(mp, mq, p, q, qinv)` for BigInts: given mp = m mod p, mq = m mod q and qinv = q⁻¹ mod p, return m in 0 … p·q − 1. Watch the sign: mp − mq is often negative, and JavaScript\'s % keeps the sign of the left operand.'],
    start: 'function garner(mp, mq, p, q, qinv) {\n  \n}',
    ref: (mp, mq, p, q, qinv) => mq + q * mod(qinv * (mp - mq), p),
    cases: [[15n, 127n, 137n, 149n, 80n], [297n, 359n, 1031n, 1019n, inv(1019n, 1031n)], [0n, 0n, 89n, 107n, inv(107n, 89n)], [88n, 106n, 89n, 107n, inv(107n, 89n)], [1n, 0n, 1000003n, 999983n, inv(999983n, 1000003n)], [123n, 456n, 2n ** 61n - 1n, 2n ** 31n - 1n, inv(2n ** 31n - 1n, 2n ** 61n - 1n)]],
    hints: ['h = qinv·(mp − mq) mod p, brought into 0 … p − 1. Then m = mq + h·q.', 'In JavaScript, (−112n) % 137n is −112n. Use ((v % p) + p) % p.', fn('garner', ['mp', 'mq', 'p', 'q', 'qinv'], '  const h = ((qinv * (mp - mq)) % p + p) % p;\n  return mq + h * q;')],
    solution: fn('garner', ['mp', 'mq', 'p', 'q', 'qinv'], '  const h = ((qinv * (mp - mq)) % p + p) % p;\n  return mq + h * q;'),
    wrong: [fn('garner', ['mp', 'mq', 'p', 'q', 'qinv'], '  const h = (qinv * (mp - mq)) % p;\n  return mq + h * q;'), fn('garner', ['mp', 'mq', 'p', 'q', 'qinv'], '  const h = ((qinv * (mp - mq)) % p + p) % p;\n  return mp + h * q;')],
  });
  ex({
    id: 'rsa-x-crt-speed', chapter: 'rsa-speed', title: 'What the CRT saves', level: 2, kind: 'number', answer: 5, tolerance: 0.5,
    text: ['A server decrypts with an RSA-4096 key in 20 ms using c^d mod n directly. About how many milliseconds does decryption take with the CRT? Assume schoolbook multiplication, whose cost grows with the square of the length.'],
    hints: ['Each half has an exponent half as long and numbers half as long.', 'Half the squarings, each a quarter of the cost: one half costs 1/8 of the whole. There are two halves.', '2·(1/8) = 1/4 of the work: about 5 ms.'],
    solution: '5', wrong: ['10', '2.5', '20'],
    whyNot: { 10: 'Each half is cheaper on two counts: shorter exponents and shorter numbers.', 2.5: 'There are two halves to compute, one modulo p and one modulo q.', '*': 'Work out the cost of one half as a fraction of the whole, then double it.' },
    higherLower: true,
  });
  ex({
    id: 'rsa-x-small-e', chapter: 'rsa-speed', title: 'Why 65537?', level: 1, kind: 'choice',
    text: ['Almost every RSA key uses e = 65537 = 2¹⁶ + 1. Which reason is right?'],
    options: ['It is the largest exponent RSA allows', 'It costs only 17 operations, yet unlike e = 3 it does not turn a missing or broken padding into an easy cube-root break', 'A smaller e makes d easy to find from n', 'It is the only prime exponent that works for every pair of primes'],
    answer: 1,
    whyNot: { 0: 'e can be any number coprime to φ(n), up to φ(n).', 2: 'A small d is the danger, not a small e: e = 3 with proper padding is still secure.', 3: 'A prime p with p ≡ 1 (mod 65537) cannot be used with it, and the key generator skips such primes.' },
    hints: ['Count the operations: 16 squarings and 1 multiplication.', 'With e = 3, an unpadded short message has m³ < n and an ordinary cube root reads it. With 65537 the same mistake needs m^65537 < n, which only m = 0 or 1 meet.', 'The second. Speed is almost the same as e = 3, and a margin of safety against padding mistakes is gained; the padding itself is still required.'],
    solution: 1, wrong: [0, 2],
  });

  // ===========================================================================================================
  // Chapter 3: padding
  // ===========================================================================================================
  ex({
    id: 'rsa-x-malleable', chapter: 'rsa-padding', title: 'A bid changed in transit', level: 1, kind: 'number', answer: 2477,
    text: ['An auction house uses textbook RSA with n = 9523, e = 5. A bid m = 6000 is sent as c = 4413. On the way, c is replaced by c′ = c·2⁵ mod n = 7894. What does the auction house get when it decrypts c′?'],
    hints: ['c·2⁵ = m⁵·2⁵ = (2m)⁵ modulo n.', 'So c′ decrypts to 2m mod n. Note that 2m is larger than n.', '2·6000 − 9523 = 2477. Without padding a change like this is accepted silently: OAEP would reject c′, since its decoded block would fail the checks.'],
    solution: '2477', wrong: ['12000', '6000', '7894'],
    whyNot: { 12000: 'Every decryption is a number modulo n = 9523: reduce.', 6000: 'c′ is a different ciphertext; it does not decrypt to the original bid.', '*': 'c·2⁵ is an encryption of 2m. Reduce 2m modulo n.' },
  });
  ex({
    id: 'rsa-x-deterministic', chapter: 'rsa-padding', title: 'Same message, same ciphertext', level: 1, kind: 'choice',
    text: ['A voting system encrypts each ballot, "yes" or "no", under the tallier\'s public key with textbook RSA and e = 65537 on a 3072-bit modulus. Which statement is right?'],
    options: ['The ballots are safe: the modulus has 3072 bits', 'Anyone can encrypt "yes" and "no" with the public key and compare, so every ballot can be read', 'Only the tallier can tell two equal ballots apart', 'Switching to e = 3 would hide the ballots'],
    answer: 1,
    whyNot: { 0: 'The key size protects against factoring, not against guessing a message from a list of two.', 2: 'Equal ballots give equal ciphertexts, and anyone can see that.', 3: 'Any fixed e is deterministic; the problem is the missing randomness.' },
    hints: ['Textbook RSA has no randomness: c depends only on m and the public key.', 'With only two possible messages, an attacker needs two encryptions.', 'The second. Randomised padding (OAEP) makes every encryption of "yes" different, which is what an encryption scheme must do.'],
    solution: 1, wrong: [0, 3],
  });
  const BL = { 'c′ = c·r^e mod n|value': '7133', 'm′ = c′^d mod n|value': '9314', 'r⁻¹ mod n|value': '7262', 'm = m′·r⁻¹ mod n|value': '9999' };
  ex({
    id: 'rsa-x-blind', chapter: 'rsa-padding', title: 'Blinding a decryption', level: 2, kind: 'table',
    text: ['To keep the time of a decryption from depending on the ciphertext, a server blinds it: it draws a random r, decrypts c′ = c·r^e mod n instead of c, and divides the result by r. With n = 20413, e = 7, d = 5751, c = 4804 and r = 1234, fill in each step. (The bench\'s Powers and Euclid tools help.)'],
    rows: ['c′ = c·r^e mod n', 'm′ = c′^d mod n', 'r⁻¹ mod n', 'm = m′·r⁻¹ mod n'], cols: ['value'], corner: 'Step',
    cells: BL,
    hints: ['1234⁷ mod 20413 first, then multiply by 4804 and reduce.', 'c′ = 7133, and since c′ = (m·r)^e, m′ = m·r mod n. Then invert 1234 modulo 20413.', 'c′ = 7133, m′ = 9314, r⁻¹ = 7262, m = 9314·7262 mod 20413 = 9999. The private exponent only ever touched c′, a number unrelated to c.'],
    solution: BL,
    wrong: [Object.assign({}, BL, { 'm = m′·r⁻¹ mod n|value': '9314' }), Object.assign({}, BL, { 'r⁻¹ mod n|value': '1234' })],
  });
  const OA = { 'lHash|bytes': '32', 'seed|bytes': '32', 'DB = lHash ‖ PS ‖ 01 ‖ M|bytes': '223', 'PS for a 20-byte M|bytes': '170', 'largest M|bytes': '190' };
  ex({
    id: 'rsa-x-oaep-table', chapter: 'rsa-padding', title: 'OAEP field sizes', level: 2, kind: 'table',
    text: ['RSA-2048 (k = 256 bytes) with OAEP and SHA-256 (32-byte hashes). The encoded block is EM = 00 ‖ maskedSeed ‖ maskedDB. Fill in the lengths in bytes.'],
    rows: ['lHash', 'seed', 'DB = lHash ‖ PS ‖ 01 ‖ M', 'PS for a 20-byte M', 'largest M'], cols: ['bytes'], corner: 'Field',
    cells: OA,
    hints: ['lHash and the seed are each one hash long. DB fills what is left of the k bytes after the leading 00 and the seed.', 'DB = 256 − 1 − 32 = 223 bytes. Inside DB, lHash takes 32 and the 01 separator 1.', 'lHash 32, seed 32, DB 223, PS = 223 − 32 − 1 − 20 = 170, and the largest message has PS empty: 223 − 33 = 190 = k − 2·32 − 2.'],
    solution: OA,
    wrong: [Object.assign({}, OA, { 'largest M|bytes': '256' }), Object.assign({}, OA, { 'DB = lHash ‖ PS ‖ 01 ‖ M|bytes': '224' })],
  });
  ex({
    id: 'rsa-x-oaep-why', chapter: 'rsa-padding', title: 'What OAEP adds', level: 2, kind: 'choice',
    text: ['Which of these does OAEP give that textbook RSA lacks?'],
    options: ['A fresh random seed, so equal messages encrypt differently', 'Checks on decryption (lHash, the zero bytes, the 01), so a modified ciphertext is rejected', 'A shorter ciphertext', 'Protection even if the private key leaks', 'Two rounds of masking, so no part of the block can be set without knowing all of it'],
    answer: [0, 1, 4],
    hints: ['Think of the two faults of textbook RSA: deterministic and malleable.', 'The ciphertext is still exactly k bytes, and nothing survives the loss of d.', 'The first, second and fifth: randomness, checked structure, and masks that tie every byte to every other.'],
    solution: [0, 1, 4], wrong: [[0, 1], [0, 1, 2, 4], [3]],
  });
  ex({
    id: 'rsa-x-pss-why', chapter: 'rsa-padding', title: 'Why sign with PSS', level: 2, kind: 'choice',
    text: ['Raw RSA signatures multiply: s₁·s₂ mod n is a valid signature of m₁·m₂ mod n. How does PSS stop this?'],
    options: ['It signs an encoding of a salted hash that the verifier rebuilds and checks, and the product of two encodings is almost never a valid encoding', 'It uses a larger e', 'It encrypts the signature with the verifier\'s public key', 'It keeps the signature secret'],
    answer: 0,
    whyNot: { 1: 'Any fixed e keeps the multiplicative property.', 2: 'Signatures are public by design; encrypting them does not change what they verify.', 3: 'A signature is checked by anyone with the public key, so it is public.' },
    hints: ['The verifier of PSS does not compare s^e with the message itself; it unpacks s^e and checks its structure.', 'The block holds H, a masked DB of zeros, 01 and a salt, and ends in 0xbc. A product of two such blocks has random-looking bytes in all those places.', 'The first: the checked structure (and the hash) is what a product cannot keep.'],
    solution: 0, wrong: [1, 2],
  });

  // ===========================================================================================================
  // Chapter 4: why the rules for keys exist
  // ===========================================================================================================
  ex({
    id: 'rsa-x-cube-why', chapter: 'rsa-attacks', title: 'Small e without padding', level: 2, kind: 'choice',
    text: ['A firmware updater encrypts a 16-byte AES key to a server with RSA-2048, e = 3 and no padding. What is wrong, and what is the right fix?'],
    options: ['m³ is far below n, so c is m³ as an ordinary integer and its cube root is m; the fix is OAEP, which fills the block with random bytes', 'Nothing: 2048 bits is enough', 'The modulus is too short; the fix is RSA-4096 with the same scheme', 'e = 3 is broken; the fix is any larger e, padding still optional'],
    answer: 0,
    whyNot: { 1: 'A 128-bit m gives a 384-bit m³: no reduction modulo n ever happens.', 2: 'A longer n makes the cube root no harder: m³ is still below n.', 3: 'A larger e helps only against this one mistake. Without padding RSA stays deterministic and malleable.' },
    hints: ['How large is m³ for a 128-bit m?', 'm³ has about 384 bits, and n has 2048: c = m³ exactly.', 'The first. OAEP makes the encoded message as long as n and random, so its cube is reduced many times over; a larger e with padding is the usual choice too.'],
    solution: 0, wrong: [1, 2, 3],
  });
  ex({
    id: 'rsa-x-cube-size', chapter: 'rsa-attacks', title: 'How short is too short?', level: 2, kind: 'number', answer: 85,
    text: ['With RSA-2048 (n ≥ 2²⁰⁴⁷), e = 3 and no padding, a message of up to how many whole bytes is guaranteed to have m³ < n, so that its ciphertext is an exact cube?'],
    hints: ['A b-byte message is below 2^(8b), so its cube is below 2^(24b).', 'You need 24b ≤ 2047.', 'b = 85 bytes (680 bits, cube below 2²⁰⁴⁰). An 86-byte message can wrap. With OAEP no message is short: the encoded block is always 256 bytes.'],
    solution: '85', wrong: ['256', '682', '86'],
    whyNot: { 682: 'That counts bits. The question asks for whole bytes.', 86: '86 bytes is 688 bits, whose cube can reach 2²⁰⁶⁴, above n.', '*': 'Solve 24·b ≤ 2047 for the largest whole b.' },
    higherLower: true,
  });
  ex({
    id: 'rsa-x-hastad-why', chapter: 'rsa-attacks', title: 'One message, three recipients', level: 2, kind: 'choice',
    text: ['A newsletter is sent with textbook RSA and e = 3 to three subscribers, each with their own 2048-bit modulus. Which statements are right?'],
    options: ['The CRT joins the three ciphertexts into m³ modulo n₁n₂n₃, which is m³ exactly, so a cube root gives m', 'It is safe because each modulus is different', 'With e = 65537 the same mistake needs 65537 recipients', 'OAEP stops it, because each copy is padded with a different random seed', 'It works only if the three moduli share a prime'],
    answer: [0, 2, 3],
    hints: ['Each ciphertext gives m³ modulo one nᵢ. What does the CRT make of three such congruences?', 'm is below each nᵢ, so m³ is below their product. The attack needs e copies of the same m.', 'True: the first, third and fourth. Random padding makes the three encoded messages different numbers, so no common m³ exists.'],
    solution: [0, 2, 3], wrong: [[0], [0, 3], [1, 4]],
  });
  ex({
    id: 'rsa-x-common-why', chapter: 'rsa-attacks', title: 'One modulus for the office', level: 2, kind: 'choice',
    text: ['An office gives every employee the same modulus n, each with their own pair (eᵢ, dᵢ), to save key generation. Which statements are right?'],
    options: ['Any employee can factor n from their own eᵢ and dᵢ, and then compute everyone\'s d', 'One message encrypted to two employees with coprime exponents can be read by anyone, with no private key', 'It is safe as long as every eᵢ is different', 'Each employee needs their own modulus, made from their own fresh primes'],
    answer: [0, 1, 3],
    hints: ['eᵢ·dᵢ − 1 is a multiple of φ(n). What does that let its holder do?', 'Two powers of one m under one n, with coprime exponents, can be combined into m from public values alone.', 'True: the first, second and fourth. A modulus is a secret of one key pair; it must never be shared.'],
    solution: [0, 1, 3], wrong: [[1], [0, 1, 2, 3], [2, 3]],
  });
  ex({
    id: 'rsa-x-wiener-bound', chapter: 'rsa-attacks', title: 'How small is too small for d?', level: 3, kind: 'number', answer: 254, tolerance: 1,
    text: ['A private exponent below n^¼/3 is given away by (n, e) alone. For a 1024-bit modulus, below about how many bits must d be for that to apply? (Give a whole number of bits.)'],
    hints: ['n is about 2¹⁰²⁴, so n^¼ is about 2²⁵⁶.', 'Dividing by 3 takes off log₂ 3 ≈ 1.6 bits.', 'About 2^254.4: a d of 254 bits or fewer is found. Later methods push the bound to about n^0.292 (299 bits here). A d of full length, made from e = 65537, is far outside; for speed use the CRT, never a short d.'],
    solution: '254', wrong: ['256', '512', '1024'],
    whyNot: { 512: 'That is half the modulus. The bound is a quarter of the bits, less a little.', 1024: 'A full-length d is safe; only a short one is found.', '*': 'Take a quarter of 1024 bits, then subtract log₂ 3.' },
  });
  ex({
    id: 'rsa-x-balanced', chapter: 'rsa-attacks', title: 'How to choose the primes', level: 2, kind: 'choice',
    text: ['Which of these practices does a sound RSA key generator follow?'],
    options: ['Draw p and q independently, each a random prime of exactly half the modulus length', 'Take q as the next prime after p, to save time', 'Reject the pair if |p − q| ≤ 2^(nlen/2 − 100)', 'Seed the random generator with enough entropy before the first key is made', 'Reuse one prime across all devices of a product line, with a different second prime for each'],
    answer: [0, 2, 3],
    hints: ['Fermat\'s method factors n quickly when p and q are close; a gcd finds a prime shared by two moduli.', 'FIPS 186 asks for the distance check; independent random primes pass it almost always. Poor entropy at first boot made real devices share primes.', 'Sound: the first, third and fourth. The second makes n almost a square, and the fifth hands every owner of a device the shared prime with one gcd.'],
    solution: [0, 2, 3], wrong: [[0, 1, 2, 3], [0], [1, 4]],
  });
  ex({
    id: 'rsa-x-fermat-gap', chapter: 'rsa-attacks', title: 'Why the distance rule is enough', level: 3, kind: 'number', answer: 821, tolerance: 1,
    text: ['Fermat\'s method needs about (q − p)²/(8√n) steps. For a 2048-bit modulus, FIPS 186 requires |p − q| > 2^(1024 − 100) = 2⁹²⁴. Take n ≈ 2²⁰⁴⁸ and |p − q| = 2⁹²⁴ exactly: about 2 to what power is the number of steps?'],
    hints: ['(q − p)² = 2¹⁸⁴⁸ and √n = 2¹⁰²⁴.', '8 = 2³, so the denominator is 2¹⁰²⁷.', '2¹⁸⁴⁸/2¹⁰²⁷ = 2⁸²¹ steps: hopeless. The rule only shuts out generators that are broken, since random primes are almost always far further apart than that.'],
    solution: '821', wrong: ['924', '1848', '8'],
    whyNot: { 924: 'Square the gap first, then divide by 8√n.', 1848: 'Divide by 8√n = 2¹⁰²⁷.', '*': 'Work with exponents of 2: 2·924 − (1024 + 3).' },
  });
  ex({
    id: 'rsa-x-shared-why', chapter: 'rsa-attacks', title: 'Two routers, one prime', level: 2, kind: 'choice',
    text: ['A survey of public keys finds two routers whose moduli have a gcd of 1 < g < n. What went wrong, and what prevents it?'],
    options: ['Both drew the same prime because their random generators had too little entropy at first boot; seed the generator properly before making keys', 'Their moduli are too short; use RSA-4096', 'They used e = 65537; choose a random e', 'Nothing is wrong: a gcd above 1 is normal for moduli of the same length'],
    answer: 0,
    whyNot: { 1: 'Two 4096-bit moduli that share a prime are broken by the same gcd.', 2: 'e has nothing to do with p and q being shared.', 3: 'Two independent random primes of 1024 bits essentially never coincide.' },
    hints: ['g divides both moduli, so g is one of each one\'s primes.', 'Independent random 1024-bit primes collide with negligible probability, so the primes were not independent.', 'The first: identical generator states at boot give identical first primes. Batch GCD over millions of keys finds every such pair at once.'],
    solution: 0, wrong: [1, 3],
  });
  ex({
    id: 'rsa-x-fault-why', chapter: 'rsa-attacks', title: 'Guarding CRT signing', level: 2, kind: 'choice',
    text: ['A smart card signs with RSA using the CRT. Which countermeasures stop one faulty half from giving away the factors?'],
    options: ['Verify each signature with the public key before releasing it, and release nothing if it fails', 'Sign with PSS, so the attacker does not know the exact encoded message the card exponentiated', 'Use a longer modulus', 'Drop the CRT and sign with c^d mod n directly, accepting that it is four times slower', 'Use e = 3 to make verification cheaper'],
    answer: [0, 1, 3],
    hints: ['The attack needs a wrong signature to leave the card and the message that was signed.', 'A fault in one half makes s′ right modulo p only; turning that into a factor of n needs the m that was signed.', 'The first, second and fourth. Verifying costs 17 multiplications with e = 65537. A longer modulus changes nothing, and e = 3 does not stop a faulty signature from leaving.'],
    solution: [0, 1, 3], wrong: [[2], [0], [0, 1, 2, 3, 4]],
  });

  // ===========================================================================================================
  // The part's tour and course
  // ===========================================================================================================
  C.tour({
    id: 'rsa-tour', title: 'Tour: RSA', blurb: 'From two primes to a padded, fast and safely made key, in eight steps.',
    steps: [
      { route: 'part=rsa', target: '#main', text: 'Part 8 of the catalogue: making an RSA key, using it, making it fast, padding it, and the rules that keep a key from being made or used carelessly.' },
      { route: 'topic=p08-keygen', target: '#stageWrap', text: 'Key generation: random odd candidates, trial division, Miller–Rabin, and d from extended Euclid. Step through a 24-bit toy key.' },
      { target: '#btnPlay', text: 'Play runs the steps; the arrow keys go one at a time. The line under the picture names the actual numbers.' },
      { route: 'topic=p08-why', target: '#stageWrap', text: 'Why decryption works: the powers of a message run round a cycle whose length divides φ(n).' },
      { route: 'topic=p08-sqm', target: '#inputs', text: 'Square-and-multiply from either end. Change the exponent and count the squarings and multiplications.' },
      { route: 'topic=p08-crt', target: '#stageWrap', text: 'Decryption by the CRT: two half-size exponentiations joined by Garner\'s formula, about four times faster.' },
      { route: 'topic=p08-oaep', target: '#stageWrap', text: 'OAEP field by field: a random seed and two masks make RSA randomised and tamper-evident.' },
      { route: 'learn', target: '[data-chapter="rsa-scheme"]', text: 'The part\'s lessons and exercises start here: make a key by hand, decrypt by the CRT, write square-and-multiply and Garner, and say why each rule for keys exists.' },
    ],
  });

  C.course({
    id: 'rsa-course', title: 'RSA from key to padding', blurb: 'An ordered path through every topic of part 8, from key generation to OAEP and the rules for safe keys, with lessons and exercises on the way.',
    steps: [
      { topic: 'p08-keygen', note: 'Random primes, e and d.' },
      { lesson: 'rsa-keygen', note: 'Making an RSA key.' },
      { exercise: 'rsa-x-keygen-table', note: 'A whole key by hand.' },
      { exercise: 'rsa-x-code-mr', note: 'One Miller–Rabin round.' },
      { topic: 'p08-encdec', note: 'Powers modulo n.' },
      { topic: 'p08-sizes', note: 'Toy and real side by side.' },
      { topic: 'p08-why', note: 'Euler\'s theorem at work.' },
      { lesson: 'rsa-why', note: 'Why decryption works.' },
      { topic: 'p08-sqm', note: 'Reading the exponent\'s bits.' },
      { topic: 'p08-ladder', note: 'The same work for every bit.' },
      { exercise: 'rsa-x-code-sqm', note: 'Write square-and-multiply.' },
      { topic: 'p08-montmul', note: 'No division by n.' },
      { topic: 'p08-crt', note: 'Two halves and Garner.' },
      { exercise: 'rsa-x-crt-table', note: 'Decrypt by the CRT.' },
      { exercise: 'rsa-x-code-garner', note: 'Write the recombination.' },
      { topic: 'p08-small-e', note: 'Why 65537.' },
      { topic: 'p08-malleable', note: 'Textbook RSA is not secure.' },
      { topic: 'p08-oaep', note: 'Randomised, checked padding.' },
      { topic: 'p08-pss', note: 'The same for signatures.' },
      { exercise: 'rsa-x-oaep-table', note: 'The field sizes.' },
      { topic: 'p08-small-e-attack', note: 'Why padding is required.' },
      { topic: 'p08-hastad', note: 'Why padding is random.' },
      { topic: 'p08-common-modulus', note: 'Why a modulus is never shared.' },
      { topic: 'p08-wiener', note: 'Why d is never short.' },
      { topic: 'p08-fermat', note: 'Why the primes are far apart.' },
      { topic: 'p08-batch-gcd', note: 'Why the generator needs entropy.' },
      { topic: 'p08-crt-fault', note: 'Why a signature is checked before it leaves.' },
      { exercise: 'rsa-x-balanced', note: 'How to choose the primes.' },
    ],
  });

  // ---- what the diagram checker looks at on these pages -----------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'rsa lesson rsa-keygen')) {
    const ready = (sel) => "document.querySelector('" + sel + "')";
    for (const ch of C.chapters.filter((c) => c.part === 'rsa')) for (const id of ch.lessons) S.Checks.push({ group: 'learn', name: 'rsa lesson ' + id, hash: 'lesson=' + id, ready: ready('#lessonView'), sel: '#main' });
    for (const id of ['rsa-x-keygen-table', 'rsa-x-code-garner', 'rsa-x-hastad-why']) S.Checks.push({ group: 'learn', name: 'rsa exercise ' + id, hash: 'exercise=' + id, ready: ready('#exerciseView'), sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'rsa course', hash: 'course=rsa-course', ready: ready('#courseView'), sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
