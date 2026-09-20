// Part 2, modular arithmetic, number theory and finite fields: the exercises. The lessons are in 020-numbers.js.
// Every answer was worked out by the engines (S.NT, S.GF, S.gf256), and the checks that need arithmetic (a Fermat
// liar, a factor, a code exercise's expected values) call the same engines.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('num-x-reduce')) return;
  const ex = (o) => C.exercise(o);
  const NT = () => S.NT;
  /** a whole number typed by the student, or null */
  const big = (t) => { const s = String(t).trim().replace(/[,_\s]/g, '').replace('−', '-'); return /^-?\d+$/.test(s) ? BigInt(s) : null; };
  /** source of a function, for reference solutions and wrong attempts */
  const fn = (name, params, body) => 'function ' + name + '(' + params.join(', ') + ') {\n' + body + '\n}';

  // ===========================================================================================================
  // Chapter 1: modular arithmetic and Euclid
  // ===========================================================================================================
  ex({
    id: 'num-x-reduce', chapter: 'num-mod', title: 'A negative number, reduced', level: 1, kind: 'number', answer: 7,
    text: ['What is −47 mod 9? Give the remainder in the range 0 to 8.'],
    hints: ['Find the multiple of 9 just below −47 (below means further left on the number line, so more negative).', '−54 = −6·9 is the multiple of 9 just below −47, and −47 − (−54) = 7.', '−47 = −6·9 + 7, so −47 mod 9 = 7. (JavaScript\'s −47 % 9 gives −2; adding 9 brings it to 7.)'],
    solution: '7', wrong: ['-2', '2', '5'],
    whyNot: 'The remainder must lie between 0 and 8. Write −47 as q·9 + r with that r.',
    why: 'Check: −47 + 54 = 7, and 54 is a multiple of 9.',
  });
  ex({
    id: 'num-x-congruent', chapter: 'num-mod', title: 'Which are congruent?', level: 1, kind: 'choice',
    text: ['Which of these congruences are true?'],
    options: ['38 ≡ 3 (mod 7)', '−4 ≡ 10 (mod 7)', '100 ≡ 1 (mod 9)', '25 ≡ 52 (mod 8)', '17 ≡ −17 (mod 6)'],
    answer: [0, 1, 2],
    hints: ['a ≡ b (mod n) exactly when n divides a − b.', 'The differences are 35, −14, 99, −27 and 34.', '35 = 5·7, −14 = −2·7 and 99 = 11·9 are multiples of their moduli; 27 is not a multiple of 8, nor 34 of 6. So the first three are true.'],
    solution: [0, 1, 2], wrong: [[0, 1], [0, 1, 2, 4], [3]],
    why: 'A shortcut for the third: 100 has digit sum 1, and a number is congruent to its digit sum modulo 9.',
  });
  ex({
    id: 'num-x-units', chapter: 'num-mod', title: 'The units of Z_15', level: 1, kind: 'set',
    answer: '{1, 2, 4, 7, 8, 11, 13, 14}',
    text: ['List every element of Z_15 that has a multiplicative inverse, as a set like {1, 2}.'],
    hints: ['a has an inverse modulo 15 exactly when gcd(a, 15) = 1.', '15 = 3·5, so strike out 0 and every multiple of 3 or 5 among 0 to 14.', 'What is left: {1, 2, 4, 7, 8, 11, 13, 14}, eight of them, and φ(15) = 2·4 = 8 agrees. For instance 2·8 = 16 ≡ 1 and 7·13 = 91 ≡ 1.'],
    solution: '{1, 2, 4, 7, 8, 11, 13, 14}', wrong: ['{1, 2, 4, 7, 8, 11, 13}', '{2, 3, 5, 7, 11, 13}', '{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}'],
  });
  ex({
    id: 'num-x-inv-small', chapter: 'num-mod', title: 'An inverse modulo 26', level: 1, kind: 'number', answer: 15,
    text: ['An affine cipher multiplies each letter by 7 modulo 26. To decrypt you need 7⁻¹ mod 26. What is it?'],
    hints: ['You want x with 7·x ≡ 1 (mod 26), that is 7·x = 1 + 26·k for some k.', 'Try k = 1, 2, 3, 4: 27, 53, 79, 105. Which is a multiple of 7?', '105 = 7·15 = 4·26 + 1, so 7⁻¹ ≡ 15 (mod 26).'],
    solution: '15', wrong: ['19', '4', '7'],
    whyNot: 'Multiply your answer by 7 and reduce modulo 26: the inverse gives 1.',
  });
  ex({
    id: 'num-x-solve-lin', chapter: 'num-mod', title: 'A congruence with several solutions', level: 3, kind: 'set',
    answer: '{4, 9, 14, 19, 24, 29}',
    text: ['Find every x in 0 … 29 with 12·x ≡ 18 (mod 30). Write them as a set.'],
    hints: ['gcd(12, 30) = 6, and 6 divides 18, so solutions exist: exactly 6 of them modulo 30.', 'Divide everything by 6: 2·x ≡ 3 (mod 5). The inverse of 2 modulo 5 is 3.', 'x ≡ 3·3 = 9 ≡ 4 (mod 5), so x is 4, 9, 14, 19, 24 or 29. Check one: 12·9 = 108 = 3·30 + 18.'],
    solution: '{4, 9, 14, 19, 24, 29}', wrong: ['{4}', '{9}', '{4, 9, 14, 19, 24}', '{3, 8, 13, 18, 23, 28}'],
    accept(v, canon) {
      if (v.t !== 'set' && v.t !== 'atom') return 'Write the solutions as a set, like {1, 2}.';
      const items = (v.t === 'set' ? v.items : [v]).map((i) => big(i.v));
      if (items.some((x) => x === null)) return 'Each solution is a whole number.';
      const bad = items.filter((x) => (12n * x - 18n) % 30n !== 0n);
      if (bad.length) return bad[0] + ' is not a solution: 12·' + bad[0] + ' = ' + 12n * bad[0] + ', which is ' + NT().mod(12n * bad[0], 30n) + ' modulo 30, not 18.';
      if (items.some((x) => x < 0n || x > 29n)) return 'Give the solutions between 0 and 29.';
      const n = new Set(items.map(String)).size;
      return n === 6 ? true : 'Every number you gave is a solution, but there are 6 in all, and you gave ' + n + '. gcd(12, 30) = 6 says how many.';
    },
  });
  ex({
    id: 'num-x-gcd', chapter: 'num-mod', title: 'A gcd by Euclid', level: 1, kind: 'number', answer: 61,
    text: ['Find gcd(9089, 7442) with the Euclidean algorithm.'],
    hints: ['9089 = 1·7442 + 1647: carry on with gcd(7442, 1647).', '7442 = 4·1647 + 854, 1647 = 1·854 + 793, 854 = 1·793 + 61.', '793 = 13·61 + 0, so the gcd is the last divisor, 61. Check: 9089 = 149·61 and 7442 = 122·61.'],
    solution: '61', wrong: ['1', '1647', '793'],
    whyNot: 'Keep dividing until the remainder is 0: the gcd is the last divisor, not the last remainder.',
  });
  ex({
    id: 'num-x-egcd-table', chapter: 'num-mod', title: 'Fill the extended Euclid table', level: 2, kind: 'table',
    text: [
      'Run the extended Euclidean algorithm on a = 544 and b = 119. Rows 0 and 1 are given. For each new row, q is the quotient r(i−2) div r(i−1), and the row is row (i−2) − q·row (i−1), so r = 544·s + 119·t holds on every row. Fill rows 2 to 5 (write negatives with a minus sign, like -4).',
      { table: [['Row', 'q', 'r', 's', 't'], ['0', '', '544', '1', '0'], ['1', '', '119', '0', '1']], caption: 'The two starting rows.' },
    ],
    rows: ['row 2', 'row 3', 'row 4', 'row 5'], cols: ['q', 'r', 's', 't'], corner: 'Row',
    cells: { 'row 2|q': '4', 'row 2|r': '68', 'row 2|s': '1', 'row 2|t': '-4', 'row 3|q': '1', 'row 3|r': '51', 'row 3|s': '-1', 'row 3|t': '5', 'row 4|q': '1', 'row 4|r': '17', 'row 4|s': '2', 'row 4|t': '-9', 'row 5|q': '3', 'row 5|r': '0', 'row 5|s': '-7', 'row 5|t': '32' },
    hints: ['Row 2: q = 544 div 119 = 4, so r = 544 − 4·119 = 68, s = 1 − 4·0 = 1 and t = 0 − 4·1 = −4.', 'Row 3 uses q = 119 div 68 = 1; row 4 uses q = 68 div 51 = 1. Check each row: 544·s + 119·t must equal r.', 'Rows: (4, 68, 1, −4), (1, 51, −1, 5), (1, 17, 2, −9), (3, 0, −7, 32). The gcd is 17 = 544·2 + 119·(−9), and row 5 gives 0 = 544·(−7) + 119·32.'],
    solution: { 'row 2|q': '4', 'row 2|r': '68', 'row 2|s': '1', 'row 2|t': '-4', 'row 3|q': '1', 'row 3|r': '51', 'row 3|s': '-1', 'row 3|t': '5', 'row 4|q': '1', 'row 4|r': '17', 'row 4|s': '2', 'row 4|t': '-9', 'row 5|q': '3', 'row 5|r': '0', 'row 5|s': '-7', 'row 5|t': '32' },
    wrong: [
      { 'row 2|q': '4', 'row 2|r': '68', 'row 2|s': '1', 'row 2|t': '4', 'row 3|q': '1', 'row 3|r': '51', 'row 3|s': '1', 'row 3|t': '5', 'row 4|q': '1', 'row 4|r': '17', 'row 4|s': '2', 'row 4|t': '9', 'row 5|q': '3', 'row 5|r': '0', 'row 5|s': '7', 'row 5|t': '32' },
      { 'row 2|q': '4', 'row 2|r': '68', 'row 2|s': '1', 'row 2|t': '-4' },
    ],
    why: 'gcd(544, 119) = 17 = 544·2 + 119·(−9).',
  });
  ex({
    id: 'num-x-rsa-d', chapter: 'num-mod', title: 'A private exponent', level: 2, kind: 'number', answer: 1713,
    text: ['A toy RSA key has p = 53, q = 71 and public exponent e = 17. The private exponent d is the inverse of e modulo (p − 1)(q − 1). Find d in the range 1 to (p − 1)(q − 1) − 1.'],
    hints: ['(p − 1)(q − 1) = 52·70 = 3640. You need 17·d ≡ 1 (mod 3640).', 'Extended Euclid on 3640 and 17: 3640 = 214·17 + 2, then 17 = 8·2 + 1. Track t: 0, 1, −214, then 1 − 8·(−214) = 1713.', '1 = 3640·(−8) + 17·1713, so d = 1713. Check: 17·1713 = 29121 = 8·3640 + 1.'],
    solution: '1713', wrong: ['-1927', '214', '2753'],
    whyNot: 'Check your d: 17·d must leave remainder 1 on division by 3640, and d must be positive.',
  });
  ex({
    id: 'num-x-code-gcd', chapter: 'num-mod', title: 'Write gcd', level: 1, kind: 'code', fn: 'gcd', params: ['a', 'b'],
    text: ['Write `gcd(a, b)` for non-negative BigInts a and b, returning their greatest common divisor as a BigInt (with gcd(a, 0) = a). Use Euclid: replace (a, b) by (b, a mod b) until b is 0. It is tested on numbers of up to 40 digits.'],
    start: 'function gcd(a, b) {\n  \n}',
    ref: (a, b) => S.NT.gcd(a, b),
    cases: [[2024n, 748n], [9089n, 7442n], [17n, 0n], [0n, 17n], [6765n, 4181n], [2n ** 64n + 1n, 2n ** 32n + 1n], [1000000007n * 998244353n, 1000000007n * 1000000009n], [3n ** 80n, 6n ** 40n]],
    hints: ['A loop: while b is not 0n, set [a, b] = [b, a % b]. The answer is a.', 'Every literal must be a BigInt: compare with `0n`, not 0. BigInt % works just like % on numbers.', 'function gcd(a, b) {\n  while (b !== 0n) [a, b] = [b, a % b];\n  return a;\n}'],
    solution: fn('gcd', ['a', 'b'], '  while (b !== 0n) [a, b] = [b, a % b];\n  return a;'),
    wrong: [fn('gcd', ['a', 'b'], '  a = Number(a); b = Number(b);\n  while (b) [a, b] = [b, a % b];\n  return a;'), fn('gcd', ['a', 'b'], '  while (b !== 0n) [a, b] = [b, a % b];\n  return b;')],
  });
  ex({
    id: 'num-x-code-egcd', chapter: 'num-mod', title: 'Write extended Euclid', level: 2, kind: 'code', fn: 'egcd', params: ['a', 'b'],
    text: ['Write `egcd(a, b)` for non-negative BigInts, returning `[g, x, y]` with g = gcd(a, b) and a·x + b·y = g. Any x and y that satisfy the equation are accepted.'],
    start: 'function egcd(a, b) {\n  \n}',
    tests: () => [[360n, 77n], [544n, 119n], [3640n, 17n], [8448n, 17n], [5n, 5n], [7n, 0n], [0n, 7n], [2n ** 127n - 1n, 2n ** 89n - 1n], [12345678901234567890n, 9876543210n]].map(([a, b]) => ({
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
    hints: ['Keep two rows (r, s, t): (a, 1n, 0n) and (b, 0n, 1n). Each step computes q = r0 / r1 (BigInt division rounds down for non-negative numbers) and replaces the rows by (row1, row0 − q·row1).', 'Stop when r1 is 0n: row 0 then holds g, x and y. Destructuring keeps it short: [r0, r1] = [r1, r0 - q * r1], and the same for s and t.', 'function egcd(a, b) {\n  let [r0, r1, s0, s1, t0, t1] = [a, b, 1n, 0n, 0n, 1n];\n  while (r1 !== 0n) {\n    const q = r0 / r1;\n    [r0, r1] = [r1, r0 - q * r1];\n    [s0, s1] = [s1, s0 - q * s1];\n    [t0, t1] = [t1, t0 - q * t1];\n  }\n  return [r0, s0, t0];\n}'],
    solution: fn('egcd', ['a', 'b'], '  let [r0, r1, s0, s1, t0, t1] = [a, b, 1n, 0n, 0n, 1n];\n  while (r1 !== 0n) {\n    const q = r0 / r1;\n    [r0, r1] = [r1, r0 - q * r1];\n    [s0, s1] = [s1, s0 - q * s1];\n    [t0, t1] = [t1, t0 - q * t1];\n  }\n  return [r0, s0, t0];'),
    wrong: [
      fn('egcd', ['a', 'b'], '  while (b !== 0n) [a, b] = [b, a % b];\n  return [a, 1n, 0n];'),
      fn('egcd', ['a', 'b'], '  let [r0, r1, s0, s1, t0, t1] = [a, b, 1n, 0n, 0n, 1n];\n  while (r1 !== 0n) {\n    const q = r0 / r1;\n    [r0, r1] = [r1, r0 - q * r1];\n    [s0, s1] = [s1, s0 - q * s1];\n    [t0, t1] = [t1, t0 + q * t1];\n  }\n  return [r0, s0, t0];'),
    ],
  });

  // ===========================================================================================================
  // Chapter 2: Euler, Fermat and primes
  // ===========================================================================================================
  ex({
    id: 'num-x-phi', chapter: 'num-euler', title: 'φ(360)', level: 1, kind: 'number', answer: 96,
    text: ['How many of the numbers 1 to 360 share no factor with 360? That is, what is φ(360)?'],
    hints: ['Factor first: 360 = 2³·3²·5.', 'φ(2³) = 2²·1 = 4, φ(3²) = 3·2 = 6, φ(5) = 4, and φ multiplies over coprime parts.', 'φ(360) = 4·6·4 = 96. The same from the product formula: 360·½·⅔·⅘ = 96.'],
    solution: '96', wrong: ['72', '144', '359'],
    whyNot: 'Use the factorisation 360 = 2³·3²·5 and φ(pᵏ) = pᵏ⁻¹·(p − 1).',
  });
  ex({
    id: 'num-x-phi-12', chapter: 'num-euler', title: 'Every n with φ(n) = 12', level: 3, kind: 'set',
    answer: '{13, 21, 26, 28, 36, 42}',
    text: ['Find every positive integer n with φ(n) = 12. There are finitely many; write them as a set.'],
    hints: ['If a prime p divides n, then p − 1 divides φ(n) = 12. So the only possible primes are those with p − 1 in {1, 2, 3, 4, 6, 12}: 2, 3, 5, 7 and 13.', 'Try the combinations: 13 alone gives 12; 7 with a factor contributing 2 (3, 4 or 6 → φ = 2) gives 21, 28 and 42; 13·2 = 26; and with 3² and 2²: φ(36) = 6·2 = 12. 5 cannot appear, since 4 would need a partner with φ = 3, which does not exist.', 'n ∈ {13, 21, 26, 28, 36, 42}. Check: φ(21) = 2·6, φ(26) = 1·12, φ(28) = 2·6, φ(36) = 2·6, φ(42) = 1·2·6.'],
    solution: '{13, 21, 26, 28, 36, 42}', wrong: ['{13}', '{13, 21, 26, 28, 42}', '{13, 21, 26, 28, 36, 42, 39}'],
    accept(v) {
      const items = (v.t === 'set' ? v.items : [v]).map((i) => (i.t === 'atom' ? big(i.v) : null));
      if (items.some((x) => x === null || x < 1n)) return 'Each element is a positive whole number.';
      const bad = items.find((x) => NT().phi(x).phi !== 12n);
      if (bad !== undefined) return 'φ(' + bad + ') = ' + NT().phi(bad).phi + ', not 12.';
      const n = new Set(items.map(String)).size;
      return n === 6 ? true : 'All of yours have φ = 12, but there are 6 such n and you gave ' + n + '.';
    },
  });
  ex({
    id: 'num-x-factor-phi', chapter: 'num-euler', title: 'Factor n from a leaked φ(n)', level: 3, kind: 'break', target: 'factor', normalize: 'int',
    text: [
      'A careless server logged both its RSA modulus and φ(n). Recover a prime factor of n.',
      { code: 'n    = 736916761758338939711\nφ(n) = 736916761703466224112' },
      'The numbers are far too large to factor by trial division in a few minutes, but too much has been leaked.',
    ],
    verify(v) {
      const n = 736916761758338939711n, x = BigInt(v);
      if (x === 1n || x === n) return 'Every number has the factors 1 and itself; find a prime factor in between.';
      if (x <= 1n || x >= n) return 'A factor lies between 1 and n.';
      return n % x === 0n ? true : x + ' does not divide n: the remainder is ' + n % x + '.';
    },
    hints: ['n = p·q and φ(n) = (p − 1)(q − 1) = n − (p + q) + 1. So p + q = n − φ(n) + 1.', 'p + q = 54872715600. Then p and q are the roots of z² − 54872715600·z + n = 0; the discriminant (p + q)² − 4n is a perfect square.', '(p + q)² − 4n = 63347870285127601156, and its integer square root is exactly 7959137534 = q − p, so p = (54872715600 − 7959137534)/2 = 23456789033 and q = 31415926567. Check: 23456789033·31415926567 = n.'],
    solution: '23456789033', wrong: ['54872715600', '1', '23456789031'],
  });
  ex({
    id: 'num-x-fermat-pow', chapter: 'num-euler', title: 'A huge power, by Fermat', level: 2, kind: 'number', answer: 16,
    text: ['Compute 6²⁰⁰⁰ mod 23 by hand, using Fermat\'s little theorem.'],
    hints: ['23 is prime and does not divide 6, so 6²² ≡ 1 (mod 23). Only 2000 mod 22 matters.', '2000 = 90·22 + 20, so 6²⁰⁰⁰ ≡ 6²⁰. And 6²⁰ = 6²² / 6² ≡ (6²)⁻¹ = 36⁻¹ ≡ 13⁻¹ (mod 23).', '13·16 = 208 = 9·23 + 1, so 13⁻¹ ≡ 16 and 6²⁰⁰⁰ ≡ 16 (mod 23).'],
    solution: '16', wrong: ['1', '6', '13'],
    whyNot: 'Reduce the exponent modulo 22 = 23 − 1 first, then work out the smaller power.',
  });
  ex({
    id: 'num-x-last-digits', chapter: 'num-euler', title: 'The last two digits', level: 2, kind: 'number', answer: 29,
    text: ['What are the last two digits of 3²⁰²⁶? Give them as a number from 0 to 99.'],
    hints: ['The last two digits are the remainder modulo 100. gcd(3, 100) = 1 and φ(100) = 40, so 3⁴⁰ ≡ 1 (mod 100).', '2026 = 50·40 + 26, so 3²⁰²⁶ ≡ 3²⁶. In fact 3²⁰ ≡ 1 already (3¹⁰ = 59049 ≡ 49, and 49² = 2401 ≡ 1), so 3²⁶ ≡ 3⁶.', '3⁶ = 729, so the last two digits are 29.'],
    solution: '29', wrong: ['9', '1', '69'],
    whyNot: 'Work modulo 100 and use Euler\'s theorem with φ(100) = 40 to shrink the exponent.',
  });
  ex({
    id: 'num-x-code-modpow', chapter: 'num-euler', title: 'Write square-and-multiply', level: 2, kind: 'code', fn: 'modPow', params: ['x', 'e', 'n'],
    text: ['Write `modPow(x, e, n)` returning x^e mod n for BigInts with x ≥ 0, e ≥ 0 and n ≥ 1, as a value in 0 … n − 1. Exponents of hundreds of bits are tested, so multiplying e times will not finish: read the bits of e.'],
    start: 'function modPow(x, e, n) {\n  \n}',
    ref: (x, e, n) => S.NT.pow(x, e, n),
    cases: [[7n, 0n, 13n], [7n, 1000n, 13n], [6n, 2000n, 23n], [3n, 2026n, 100n], [2n, 560n, 561n], [123456789n, 2n ** 200n + 7n, 2n ** 127n - 1n], [31337n, 65537n, 736916761758338939711n], [5n, 0n, 1n]],
    hints: ['Start with r = 1n. Going through the bits of e from the top: square r, then if the bit is 1, multiply r by x. Reduce modulo n after every multiplication.', '`e.toString(2)` gives the bits as a string. Watch the case n = 1: every value is 0 there, so return r % n at the end.', 'function modPow(x, e, n) {\n  let r = 1n;\n  x %= n;\n  for (const bit of e.toString(2)) {\n    r = r * r % n;\n    if (bit === "1") r = r * x % n;\n  }\n  return r % n;\n}'],
    solution: fn('modPow', ['x', 'e', 'n'], '  let r = 1n;\n  x %= n;\n  for (const bit of e.toString(2)) {\n    r = r * r % n;\n    if (bit === \'1\') r = r * x % n;\n  }\n  return r % n;'),
    wrong: [fn('modPow', ['x', 'e', 'n'], '  let r = 1n;\n  for (let i = 0n; i < e; i++) r = r * x % n;\n  return r;'), fn('modPow', ['x', 'e', 'n'], '  return x ** e % n;'), fn('modPow', ['x', 'e', 'n'], '  let r = 1n;\n  for (const bit of e.toString(2).split(\'\').reverse()) {\n    if (bit === \'1\') r = r * x % n;\n  }\n  return r % n;')],
  });
  ex({
    id: 'num-x-fermat-liar', chapter: 'num-euler', title: 'Find a Fermat liar', level: 2, kind: 'break', target: 'liar', normalize: 'int',
    text: ['1387 is composite (it is 19·73). Find a base a, with 2 ≤ a ≤ 1385, for which 1387 nevertheless passes Fermat\'s test: a¹³⁸⁶ ≡ 1 (mod 1387). The bench or a modPow of your own will help.'],
    verify(v) {
      const a = BigInt(v), n = 1387n;
      if (a === 1n || a === n - 1n) return a + ' passes for every odd n, so it proves nothing: find a base between 2 and 1385.';
      if (a < 2n || a > n - 2n) return 'The base must lie between 2 and 1385.';
      const g = NT().gcd(a, n);
      if (g !== 1n) return a + ' shares the factor ' + g + ' with 1387, and such a base is always a witness.';
      const r = NT().pow(a, n - 1n, n);
      return r === 1n ? true : a + '¹³⁸⁶ ≡ ' + r + ' (mod 1387), not 1: ' + a + ' is a witness, not a liar.';
    },
    hints: ['Liars are not rare here: 324 of the 1296 bases coprime to 1387 lie. Start with small bases.', 'Compute 2¹³⁸⁶ mod 1387 by square-and-multiply (or on the number-theory bench, Powers).', '2¹³⁸⁶ ≡ 1 (mod 1387), so 2 is a Fermat liar: 1387 is a Fermat pseudoprime to base 2. Base 3 gives 875 and exposes it.'],
    solution: '2', wrong: ['3', '1', '19', '1386'],
  });
  ex({
    id: 'num-x-mr-chain', chapter: 'num-euler', title: 'Miller–Rabin on 1729, step by step', level: 2, kind: 'table',
    text: ['Run Miller–Rabin on n = 1729 with base 2. First 1728 = 2⁶·27, so d = 27 and s = 6. Fill in the chain x₀ = 2²⁷ mod 1729 and then each square of the one before, modulo 1729.'],
    rows: ['x₀ = 2²⁷', 'x₁ = x₀²', 'x₂ = x₁²', 'x₃ = x₂²', 'x₄ = x₃²', 'x₅ = x₄²'], cols: ['mod 1729'], corner: 'Chain',
    cells: { 'x₀ = 2²⁷|mod 1729': '645', 'x₁ = x₀²|mod 1729': '1065', 'x₂ = x₁²|mod 1729': '1', 'x₃ = x₂²|mod 1729': '1', 'x₄ = x₃²|mod 1729': '1', 'x₅ = x₄²|mod 1729': '1' },
    hints: ['2²⁷ = 134217728. Divide by 1729 and keep the remainder (or square-and-multiply with reductions).', 'x₀ = 645. Then 645² = 416025 ≡ 1065, and 1065² = 1134225 ≡ 1 (mod 1729).', 'The chain is 645, 1065, 1, 1, 1, 1. It turns into 1 straight after 1065, which is not 1728 (that is, −1): 1065 is a square root of 1 other than ±1, so 2 is a witness and 1729 is composite. Indeed gcd(1064, 1729) = 133 = 7·19.'],
    solution: { 'x₀ = 2²⁷|mod 1729': '645', 'x₁ = x₀²|mod 1729': '1065', 'x₂ = x₁²|mod 1729': '1', 'x₃ = x₂²|mod 1729': '1', 'x₄ = x₃²|mod 1729': '1', 'x₅ = x₄²|mod 1729': '1' },
    wrong: [{ 'x₀ = 2²⁷|mod 1729': '645', 'x₁ = x₀²|mod 1729': '1065', 'x₂ = x₁²|mod 1729': '1728', 'x₃ = x₂²|mod 1729': '1', 'x₄ = x₃²|mod 1729': '1', 'x₅ = x₄²|mod 1729': '1' }],
    why: 'The jump from 1065 straight to 1 is what Fermat\'s test never sees: 1729 is a Carmichael number, yet base 2 exposes it here.',
  });
  ex({
    id: 'num-x-carmichael', chapter: 'num-euler', title: 'Spot the Carmichael numbers', level: 2, kind: 'choice',
    text: ['Which of these are Carmichael numbers? Use Korselt\'s criterion: n is composite, squarefree, and p − 1 divides n − 1 for every prime p dividing n.'],
    options: ['1105 = 5·13·17', '1001 = 7·11·13', '2465 = 5·17·29', '341 = 11·31', '2821 = 7·13·31', '1541 = 23·67'],
    answer: [0, 2, 4],
    hints: ['All six are squarefree, so only the divisibility test matters. For 1105, check that 4, 12 and 16 divide 1104.', '1104 = 4·276 = 12·92 = 16·69: yes. For 1001, 6 divides 1000? No. For 341, 30 does not divide 340. For 1541, 22 does not divide 1540? 1540 = 70·22, it does, but 66 does not.', '1105 (4, 12, 16 | 1104), 2465 (4, 16, 28 | 2464) and 2821 (6, 12, 30 | 2820) are Carmichael numbers. 1001, 341 and 1541 each fail for one prime.'],
    solution: [0, 2, 4], wrong: [[0, 2], [0, 1, 2, 4], [3]],
  });
  ex({
    id: 'num-x-mr-witness', chapter: 'num-euler', title: 'The first witness', level: 2, kind: 'number', answer: 5,
    text: ['n = 1373653 is composite (829·1657). Try the bases 2, 3, 5, 7, … in order with one round of Miller–Rabin each. Which is the first base that proves n composite?'],
    hints: ['1373652 = 2²·343413, so d = 343413 and s = 2: each base gives a^d, then one squaring.', 'For a = 2 and a = 3 the chain passes (it meets −1 or starts at 1): both are strong liars. This n was chosen to fool them.', 'Base 5 gives a chain that never meets −1, so 5 is the first witness. The number-theory bench, Primality, shows the chains.'],
    solution: '5', wrong: ['2', '3', '7'],
    whyNot: 'Run the strong test base by base: a base is a witness only if the chain a^d, a^(2d) neither starts at 1 nor meets n − 1.',
  });

  // ===========================================================================================================
  // Chapter 3: groups and the Chinese remainder theorem
  // ===========================================================================================================
  ex({
    id: 'num-x-order', chapter: 'num-groups', title: 'The order of 2 modulo 31', level: 1, kind: 'number', answer: 5,
    text: ['What is the order of 2 in Z_31*, the smallest k ≥ 1 with 2ᵏ ≡ 1 (mod 31)?'],
    hints: ['List the powers: 2, 4, 8, 16, …, reducing modulo 31.', '2⁵ = 32 = 31 + 1.', '2⁵ ≡ 1 and no smaller power is 1, so ord(2) = 5. It divides 30 = |Z_31*|, as Lagrange says it must.'],
    solution: '5', wrong: ['30', '32', '6'],
    whyNot: 'The order is the first exponent at which the powers return to 1.',
  });
  ex({
    id: 'num-x-generators', chapter: 'num-groups', title: 'The generators modulo 11', level: 2, kind: 'set',
    answer: '{2, 6, 7, 8}',
    text: ['List every primitive root modulo 11: the g in 1 … 10 whose powers run through all ten units.'],
    hints: ['|Z_11*| = 10 = 2·5. g is a generator exactly when g² ≢ 1 and g⁵ ≢ 1 (mod 11).', 'The squares modulo 11 have g⁵ ≡ 1, so they are out: 1, 4, 9, 5, 3. And 10 has order 2.', 'The generators are {2, 6, 7, 8}: φ(10) = 4 of them, as a cyclic group of order 10 must have.'],
    solution: '{2, 6, 7, 8}', wrong: ['{2}', '{2, 6, 7, 8, 10}', '{1, 3, 4, 5, 9}'],
  });
  ex({
    id: 'num-x-lagrange', chapter: 'num-groups', title: 'Possible subgroup sizes', level: 2, kind: 'choice',
    text: ['Z_31* has 30 elements. Which of these could be the number of elements of a subgroup of Z_31*?'],
    options: ['4', '5', '6', '8', '15', '20'],
    answer: [1, 2, 4],
    hints: ['Lagrange: the size of a subgroup divides the size of the group.', 'The divisors of 30 are 1, 2, 3, 5, 6, 10, 15 and 30.', '5, 6 and 15 divide 30; 4, 8 and 20 do not. (Z_31* is cyclic, so each divisor really is the size of a subgroup.)'],
    solution: [1, 2, 4], wrong: [[1, 2], [0, 1, 2, 4], [0, 3, 5]],
  });
  ex({
    id: 'num-x-crt-small', chapter: 'num-groups', title: 'Two clocks', level: 1, kind: 'number', answer: 60,
    text: ['Find the x in 0 … 62 with x ≡ 4 (mod 7) and x ≡ 6 (mod 9).'],
    hints: ['The numbers ≡ 6 (mod 9) are 6, 15, 24, 33, 42, 51, 60. Which leaves 4 on division by 7?', 'Or by the formula: M = 63, M₁ = 9 with 9⁻¹ ≡ 4 (mod 7), M₂ = 7 with 7⁻¹ ≡ 4 (mod 9).', 'x = 4·9·4 + 6·7·4 = 144 + 168 = 312 ≡ 60 (mod 63). Check: 60 = 8·7 + 4 = 6·9 + 6.'],
    solution: '60', wrong: ['312', '24', '4'],
    whyNot: 'Check your x against both congruences, and give it between 0 and 62.',
  });
  ex({
    id: 'num-x-crt-table', chapter: 'num-groups', title: 'Build the CRT solution', level: 2, kind: 'table',
    text: ['Solve x ≡ 1 (mod 5), x ≡ 4 (mod 7), x ≡ 6 (mod 11) by the formula. M = 385. For each modulus fill Mᵢ = M/mᵢ, yᵢ = Mᵢ⁻¹ mod mᵢ (between 0 and mᵢ − 1) and the term rᵢ·Mᵢ·yᵢ; then the sum reduced modulo 385.'],
    rows: ['x ≡ 1 (mod 5)', 'x ≡ 4 (mod 7)', 'x ≡ 6 (mod 11)', 'x = Σ mod 385'], cols: ['Mᵢ', 'yᵢ', 'rᵢ·Mᵢ·yᵢ'], corner: 'Congruence',
    cells: { 'x ≡ 1 (mod 5)|Mᵢ': '77', 'x ≡ 1 (mod 5)|yᵢ': '3', 'x ≡ 1 (mod 5)|rᵢ·Mᵢ·yᵢ': '231', 'x ≡ 4 (mod 7)|Mᵢ': '55', 'x ≡ 4 (mod 7)|yᵢ': '6', 'x ≡ 4 (mod 7)|rᵢ·Mᵢ·yᵢ': '1320', 'x ≡ 6 (mod 11)|Mᵢ': '35', 'x ≡ 6 (mod 11)|yᵢ': '6', 'x ≡ 6 (mod 11)|rᵢ·Mᵢ·yᵢ': '1260', 'x = Σ mod 385|rᵢ·Mᵢ·yᵢ': '116' },
    hints: ['M₁ = 385/5 = 77, M₂ = 55, M₃ = 35.', 'Reduce each Mᵢ first: 77 ≡ 2 (mod 5), 55 ≡ 6 (mod 7), 35 ≡ 2 (mod 11). Their inverses are 3, 6 and 6.', 'Terms: 1·77·3 = 231, 4·55·6 = 1320, 6·35·6 = 1260. Sum 2811 = 7·385 + 116, so x = 116. Check: 116 = 23·5 + 1 = 16·7 + 4 = 10·11 + 6.'],
    solution: { 'x ≡ 1 (mod 5)|Mᵢ': '77', 'x ≡ 1 (mod 5)|yᵢ': '3', 'x ≡ 1 (mod 5)|rᵢ·Mᵢ·yᵢ': '231', 'x ≡ 4 (mod 7)|Mᵢ': '55', 'x ≡ 4 (mod 7)|yᵢ': '6', 'x ≡ 4 (mod 7)|rᵢ·Mᵢ·yᵢ': '1320', 'x ≡ 6 (mod 11)|Mᵢ': '35', 'x ≡ 6 (mod 11)|yᵢ': '6', 'x ≡ 6 (mod 11)|rᵢ·Mᵢ·yᵢ': '1260', 'x = Σ mod 385|rᵢ·Mᵢ·yᵢ': '116' },
    wrong: [{ 'x ≡ 1 (mod 5)|Mᵢ': '77', 'x ≡ 1 (mod 5)|yᵢ': '3', 'x ≡ 1 (mod 5)|rᵢ·Mᵢ·yᵢ': '231', 'x ≡ 4 (mod 7)|Mᵢ': '55', 'x ≡ 4 (mod 7)|yᵢ': '6', 'x ≡ 4 (mod 7)|rᵢ·Mᵢ·yᵢ': '1320', 'x ≡ 6 (mod 11)|Mᵢ': '35', 'x ≡ 6 (mod 11)|yᵢ': '6', 'x ≡ 6 (mod 11)|rᵢ·Mᵢ·yᵢ': '1260', 'x = Σ mod 385|rᵢ·Mᵢ·yᵢ': '2811' }],
  });
  ex({
    id: 'num-x-crt-nonco', chapter: 'num-groups', title: 'Moduli with a common factor', level: 3, kind: 'number', answer: 29,
    text: ['Find the smallest x ≥ 0 with x ≡ 5 (mod 12) and x ≡ 11 (mod 18). The moduli share the factor 6, so first decide whether a solution exists, and modulo what it is unique.'],
    hints: ['gcd(12, 18) = 6. A solution exists only if 5 ≡ 11 (mod 6): it does, since 11 − 5 = 6.', 'Write x = 5 + 12k. Then 12k ≡ 6 (mod 18), that is 2k ≡ 1 (mod 3), so k ≡ 2 (mod 3).', 'k = 2 gives x = 29; the solution is unique modulo lcm(12, 18) = 36. Check: 29 = 2·12 + 5 = 18 + 11.'],
    solution: '29', wrong: ['65', '5', '11'],
    whyNot: 'Check your x against both congruences; the solutions repeat every lcm(12, 18) = 36, and the smallest lies in 0 … 35.',
  });
  ex({
    id: 'num-x-crt-rsa', chapter: 'num-groups', title: 'Join the two halves of an RSA decryption', level: 2, kind: 'number', answer: 271828,
    text: ['An RSA key holder with p = 1033 and q = 1051 (n = 1085683) decrypted modulo each prime and got m_p = 149 and m_q = 670. Join them with Garner\'s formula: h = (m_p − m_q)·(q⁻¹ mod p) mod p and m = m_q + h·q. What is m?'],
    hints: ['First q⁻¹ mod p: 1051 ≡ 18 (mod 1033), and 18·287 = 5166 = 5·1033 + 1, so q⁻¹ ≡ 287.', 'm_p − m_q = 149 − 670 = −521. h = (−521)·287 mod 1033 = 258.', 'm = 670 + 258·1051 = 670 + 271158 = 271828. Check: 271828 mod 1033 = 149 and mod 1051 = 670.'],
    solution: '271828', wrong: ['149', '670', '1085683'],
    whyNot: 'Your m must leave remainder 149 modulo 1033 and 670 modulo 1051. Remember to take h modulo p, as a number from 0 to p − 1.',
  });
  ex({
    id: 'num-x-code-crt', chapter: 'num-groups', title: 'Write the CRT for any number of moduli', level: 3, kind: 'code', fn: 'crt', params: ['rs', 'ms'],
    text: ['Write `crt(rs, ms)`: given arrays of BigInts rs and ms (pairwise coprime moduli, any length from 1 up), return the unique x in 0 … M − 1 with x ≡ rs[i] (mod ms[i]) for every i, where M is the product of the moduli. Remainders may be larger than their moduli or negative.'],
    start: 'function crt(rs, ms) {\n  \n}',
    ref: (rs, ms) => S.NT.crt(rs, ms).x,
    cases: [[[4n], [7n]], [[4n, 6n], [7n, 9n]], [[1n, 4n, 6n], [5n, 7n, 11n]], [[2n, 7n, 5n], [9n, 10n, 11n]], [[25n, -40n], [6n, 11n]], [[0n, 0n, 0n], [3n, 4n, 5n]], [[500n, 17n, 1000n], [1009n, 1013n, 1019n]], [[123456789n, 987654321n, 55555n, 1n], [2n ** 61n - 1n, 2n ** 31n - 1n, 65537n, 257n]]],
    hints: ['Either fold the congruences two at a time (x = r₁ + m₁·k with k = (r₂ − r₁)·m₁⁻¹ mod m₂), or use the formula x = Σ rᵢ·Mᵢ·yᵢ mod M.', 'You need an inverse modulo mᵢ: write a small extended Euclid inside the function. Reduce with ((v % m) + m) % m so negative values come out right.', 'function crt(rs, ms) {\n  const md = (v, m) => ((v % m) + m) % m;\n  const inv = (a, m) => { let [r0, r1, s0, s1] = [md(a, m), m, 1n, 0n]; while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; } return md(s0, m); };\n  const M = ms.reduce((a, b) => a * b, 1n);\n  let x = 0n;\n  ms.forEach((m, i) => { const Mi = M / m; x += md(rs[i], m) * Mi * inv(Mi, m); });\n  return md(x, M);\n}'],
    solution: fn('crt', ['rs', 'ms'], '  const md = (v, m) => ((v % m) + m) % m;\n  const inv = (a, m) => { let [r0, r1, s0, s1] = [md(a, m), m, 1n, 0n]; while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; } return md(s0, m); };\n  const M = ms.reduce((a, b) => a * b, 1n);\n  let x = 0n;\n  ms.forEach((m, i) => { const Mi = M / m; x += md(rs[i], m) * Mi * inv(Mi, m); });\n  return md(x, M);'),
    wrong: [
      fn('crt', ['rs', 'ms'], '  const md = (v, m) => ((v % m) + m) % m;\n  const inv = (a, m) => { let [r0, r1, s0, s1] = [md(a, m), m, 1n, 0n]; while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; } return md(s0, m); };\n  const M = ms.reduce((a, b) => a * b, 1n);\n  let x = 0n;\n  ms.forEach((m, i) => { const Mi = M / m; x += rs[i] * Mi * inv(Mi, m); });\n  return x;'),
      fn('crt', ['rs', 'ms'], '  const M = ms.reduce((a, b) => a * b, 1n);\n  let x = 0n;\n  ms.forEach((m, i) => { x += rs[i] * (M / m); });\n  return x % M;'),
    ],
  });

  // ===========================================================================================================
  // Chapter 4: finite fields
  // ===========================================================================================================
  ex({
    id: 'num-x-gfp-div', chapter: 'num-fields', title: 'Dividing in GF(17)', level: 1, kind: 'number', answer: 8,
    text: ['In GF(17), what is 5 / 7? Give the element from 0 to 16.'],
    hints: ['Dividing by 7 is multiplying by 7⁻¹, the x with 7·x ≡ 1 (mod 17).', '7·5 = 35 = 2·17 + 1, so 7⁻¹ = 5.', '5 / 7 = 5·5 = 25 ≡ 8 (mod 17). Check: 7·8 = 56 = 3·17 + 5.'],
    solution: '8', wrong: ['5', '0', '12'],
    whyNot: 'Your answer times 7 must give 5 modulo 17.',
  });
  ex({
    id: 'num-x-gf2-mul', chapter: 'num-fields', title: 'Multiplying polynomials over GF(2)', level: 2, kind: 'string', placeholder: 'bits, highest power first',
    text: ['Multiply (x⁴ + x + 1)·(x³ + x² + 1) with coefficients in GF(2), where 1 + 1 = 0. Write the product as a string of bits, highest power first (so x³ + x is 1010).'],
    accept(t) {
      const s = String(t).replace(/\s/g, '');
      if (!/^[01]+$/.test(s)) return 'Write the product as bits only, like 1010.';
      const v = BigInt('0b' + s);
      if (v === 0b11000111n) return true;
      if (v === 247n) return 'That is 19·13 = 247 as integers, with carries. Over GF(2) the column sums are taken modulo 2 and nothing carries.';
      return 'Not quite: XOR the shifted copies 10011000, 1001100 and 10011 column by column.';
    },
    hints: ['a = 10011 and b = 1101. For each 1 bit of b, take a copy of a shifted by that bit\'s power: x³, x² and 1.', 'The copies are 10011000, 01001100 and 00010011. XOR them column by column.', '10011000 ⊕ 01001100 ⊕ 00010011 = 11000111, that is x⁷ + x⁶ + x² + x + 1.'],
    solution: '11000111', wrong: ['11110111', '1100011', '11000110'],
  });
  ex({
    id: 'num-x-irreducible', chapter: 'num-fields', title: 'Irreducible or not?', level: 2, kind: 'choice',
    text: ['Over GF(2), which of these polynomials of degree 4 are irreducible (cannot be written as a product of two polynomials of lower degree)?'],
    options: ['x⁴ + x + 1', 'x⁴ + x² + 1', 'x⁴ + x³ + 1', 'x⁴ + 1', 'x⁴ + x³ + x² + x + 1', 'x⁴ + x³ + x + 1'],
    answer: [0, 2, 4],
    hints: ['A factor of degree 1 means a root: plug in 0 and 1. A polynomial with constant term 1 has no root 0; it has the root 1 when it has an even number of terms.', 'x⁴ + 1 and x⁴ + x³ + x + 1 have four or two terms, so x + 1 divides them. The others have no root, so the only possible factor left is the one irreducible quadratic, x² + x + 1.', '(x² + x + 1)² = x⁴ + x² + 1, so that one factors. x⁴ + x + 1, x⁴ + x³ + 1 and x⁴ + x³ + x² + x + 1 are irreducible.'],
    solution: [0, 2, 4], wrong: [[0, 1, 2, 4], [0, 2], [3, 5]],
  });
  ex({
    id: 'num-x-xtime', chapter: 'num-fields', title: 'One xtime', level: 1, kind: 'hex', answer: '95',
    text: ['In the AES field GF(2⁸), compute xtime({c7}) = {02}·{c7}. Answer as one byte in hex.'],
    hints: ['{c7} = 11000111. Shift left one place: 110001110, nine bits.', 'The top bit of {c7} was 1, so an x⁸ term appeared: XOR with {11b} (or keep the low byte and XOR {1b}).', '{18e} ⊕ {11b} = {095}: xtime({c7}) = {95}.'],
    solution: '95', wrong: ['8e', '18e', 'b5'],
    whyNot: 'Shift left, and if the top bit was 1, XOR the low byte with 1b.',
  });
  ex({
    id: 'num-x-gmul-table', chapter: 'num-fields', title: 'Shift-and-add, row by row', level: 2, kind: 'table', cellKind: 'hex',
    text: ['Multiply a = {3a} by b = {95} in GF(2⁸) by shift-and-add. b = 10010101, so its bits b₀ … b₇ are 1, 0, 1, 0, 1, 0, 0, 1. Row i holds xⁱ·a (row 0 is a itself; each row is xtime of the one before) and the running sum after adding xⁱ·a when bᵢ = 1. The last sum is the product.'],
    rows: ['i = 0', 'i = 1', 'i = 2', 'i = 3', 'i = 4', 'i = 5', 'i = 6', 'i = 7'], cols: ['xⁱ·a', 'sum'], corner: 'Row',
    cells: { 'i = 0|xⁱ·a': '3a', 'i = 0|sum': '3a', 'i = 1|xⁱ·a': '74', 'i = 1|sum': '3a', 'i = 2|xⁱ·a': 'e8', 'i = 2|sum': 'd2', 'i = 3|xⁱ·a': 'cb', 'i = 3|sum': 'd2', 'i = 4|xⁱ·a': '8d', 'i = 4|sum': '5f', 'i = 5|xⁱ·a': '01', 'i = 5|sum': '5f', 'i = 6|xⁱ·a': '02', 'i = 6|sum': '5f', 'i = 7|xⁱ·a': '04', 'i = 7|sum': '5b' },
    hints: ['The first column is {3a}, then xtime again and again: {74}, {e8}; {e8} has its top bit set, so the next is {1d0} ⊕ {11b} = {cb}.', 'Continue: {cb} → {8d}, {8d} → {01}, then {02}, {04}. Add a row into the sum only where bᵢ = 1: rows 0, 2, 4 and 7.', 'Sums: {3a}, {3a}, {3a} ⊕ {e8} = {d2}, {d2}, {d2} ⊕ {8d} = {5f}, {5f}, {5f}, {5f} ⊕ {04} = {5b}. So {3a}·{95} = {5b}.'],
    solution: { 'i = 0|xⁱ·a': '3a', 'i = 0|sum': '3a', 'i = 1|xⁱ·a': '74', 'i = 1|sum': '3a', 'i = 2|xⁱ·a': 'e8', 'i = 2|sum': 'd2', 'i = 3|xⁱ·a': 'cb', 'i = 3|sum': 'd2', 'i = 4|xⁱ·a': '8d', 'i = 4|sum': '5f', 'i = 5|xⁱ·a': '01', 'i = 5|sum': '5f', 'i = 6|xⁱ·a': '02', 'i = 6|sum': '5f', 'i = 7|xⁱ·a': '04', 'i = 7|sum': '5b' },
    wrong: [{ 'i = 0|xⁱ·a': '3a', 'i = 0|sum': '3a', 'i = 1|xⁱ·a': '74', 'i = 1|sum': '3a', 'i = 2|xⁱ·a': 'e8', 'i = 2|sum': 'd2', 'i = 3|xⁱ·a': 'd0', 'i = 3|sum': 'd2', 'i = 4|xⁱ·a': 'a0', 'i = 4|sum': '72', 'i = 5|xⁱ·a': '40', 'i = 5|sum': '72', 'i = 6|xⁱ·a': '80', 'i = 6|sum': '72', 'i = 7|xⁱ·a': '00', 'i = 7|sum': '72' }],
    why: 'Three of the eight xtimes needed a reduction; the AES tables agree that {3a}·{95} = {5b}.',
  });
  ex({
    id: 'num-x-gmul', chapter: 'num-fields', title: 'A product from InvMixColumns', level: 2, kind: 'hex', answer: '35',
    text: ['AES decryption multiplies bytes by {0d}. Compute {e5}·{0d} in GF(2⁸). Answer as one byte in hex.'],
    hints: ['{0d} = x³ + x² + 1, so the product is {e5} ⊕ x²·{e5} ⊕ x³·{e5}.', 'xtime({e5}) = {d1}, xtime({d1}) = {b9}, xtime({b9}) = {69}.', '{e5} ⊕ {b9} ⊕ {69} = {35}.'],
    solution: '35', wrong: ['5c', 'e5', '0d'],
    whyNot: 'Add (XOR) the multiples x⁰·a, x²·a and x³·a, one for each 1 bit of {0d}, reducing whenever a shift overflows.',
  });
  ex({
    id: 'num-x-gf-inv', chapter: 'num-fields', title: 'An inverse in GF(2⁸)', level: 3, kind: 'hex',
    text: ['Find the inverse of {9c} in GF(2⁸), the byte b with {9c}·b = {01}. Use the extended Euclidean algorithm on polynomials, the logarithm table, or b = {9c}²⁵⁴ by square-and-multiply.'],
    accept(hx) {
      if (hx.length > 2 && !/^0+/.test(hx.slice(0, hx.length - 2))) return 'An element of GF(2⁸) is one byte: two hex digits.';
      const b = parseInt(hx, 16) & 255;
      const p = S.gf256.mul(0x9c, b);
      return p === 1 ? true : '{9c}·{' + b.toString(16).padStart(2, '0') + '} = {' + p.toString(16).padStart(2, '0') + '}, not {01}.';
    },
    hints: ['The logarithm route: log {9c} = 156 (the power of {03} that gives {9c}). The inverse is {03}^(255 − 156).', 'So the inverse is {03}⁹⁹. Or by Euclid: divide f = {11b} by {9c} and keep going, tracking t, until the remainder is 1.', '{9c}⁻¹ = {f9}. Check: {9c}·{f9} = {01}.'],
    solution: 'f9', wrong: ['9c', '01', '63'],
  });
  ex({
    id: 'num-x-code-xtime', chapter: 'num-fields', title: 'Write xtime', level: 1, kind: 'code', radix: 16, fn: 'xtime', params: ['a'],
    text: ['Write `xtime(a)` for a byte a (a Number from 0 to 255): multiply by x in the AES field. Shift left one place and, if a bit fell off the top, XOR with 0x1b. The result must be a byte.'],
    start: 'function xtime(a) {\n  \n}',
    ref: (a) => S.gf256.xtime(a),
    cases: [[0x57], [0xae], [0xc7], [0x80], [0x00], [0x01], [0xff], [0x7f], [0xb4], [0x3a]],
    hints: ['`a << 1` shifts; the bit that falls off is the top bit of a, `a & 0x80`.', 'XOR with 0x1b only when that bit was 1, and keep the low eight bits with `& 0xff`.', 'function xtime(a) {\n  return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;\n}'],
    solution: fn('xtime', ['a'], '  return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;'),
    wrong: [fn('xtime', ['a'], '  return (a << 1) ^ (a & 0x80 ? 0x1b : 0);'), fn('xtime', ['a'], '  return (a << 1) & 0xff;')],
  });
  ex({
    id: 'num-x-code-gmul', chapter: 'num-fields', title: 'Multiply in any GF(2ᵐ)', level: 3, kind: 'code', radix: 16, decimalArgs: [2], fn: 'gfMul', params: ['a', 'b', 'm', 'f'],
    text: ['Write `gfMul(a, b, m, f)` multiplying a and b (Numbers below 2ᵐ) in GF(2ᵐ) with the irreducible modulus f, given with its xᵐ bit (so the AES field is m = 8, f = 0x11b, and GF(2⁴) with x⁴ + x + 1 is m = 4, f = 0x13). Fields up to m = 16 are tested.'],
    start: 'function gfMul(a, b, m, f) {\n  \n}',
    ref: (a, b, m, f) => Number(S.GF.binary(m, BigInt(f)).mul(BigInt(a), BigInt(b))),
    cases: [[0x57, 0x83, 8, 0x11b], [0x3a, 0x95, 8, 0x11b], [0xb, 0x6, 4, 0x13], [0x6, 0x7, 3, 0xb], [0x15, 0x1b, 5, 0x25], [0x00, 0x42, 7, 0x83], [0x7f, 0x7f, 7, 0x83], [0xbeef, 0x1234, 16, 0x1100b], [0xffff, 0xffff, 16, 0x1100b]],
    hints: ['The AES loop works for any m: for each bit of b from the bottom, XOR a into the result if the bit is 1, then multiply a by x.', 'Multiplying by x in GF(2ᵐ): shift left; if bit m is now set (`a & (1 << m)`), XOR with the whole f, which clears that bit and adds the low terms.', 'function gfMul(a, b, m, f) {\n  let r = 0;\n  while (b) {\n    if (b & 1) r ^= a;\n    a <<= 1;\n    if (a & (1 << m)) a ^= f;\n    b >>= 1;\n  }\n  return r;\n}'],
    solution: fn('gfMul', ['a', 'b', 'm', 'f'], '  let r = 0;\n  while (b) {\n    if (b & 1) r ^= a;\n    a <<= 1;\n    if (a & (1 << m)) a ^= f;\n    b >>= 1;\n  }\n  return r;'),
    wrong: [fn('gfMul', ['a', 'b', 'm', 'f'], '  let r = 0;\n  while (b) {\n    if (b & 1) r ^= a;\n    a = ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;\n    b >>= 1;\n  }\n  return r;'), fn('gfMul', ['a', 'b', 'm', 'f'], '  let r = 0;\n  while (b) {\n    if (b & 1) r ^= a;\n    a <<= 1;\n    b >>= 1;\n  }\n  return r;')],
  });

  // ---- what the diagram checker looks at on these pages -----------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'num exercise num-x-egcd-table')) {
    const ready = "document.querySelector('#exerciseView')";
    for (const id of ['num-x-egcd-table', 'num-x-mr-chain', 'num-x-crt-table', 'num-x-gmul-table', 'num-x-code-modpow', 'num-x-factor-phi', 'num-x-carmichael', 'num-x-units', 'num-x-gf2-mul'])
      S.Checks.push({ group: 'learn', name: 'num exercise ' + id, hash: 'exercise=' + id, ready, sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
