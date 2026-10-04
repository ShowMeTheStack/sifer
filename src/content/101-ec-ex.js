// Part 10, elliptic curves: the exercises. The lessons are in 100-ec.js; the tour and the course in 102-ec-tour.js.
// By hand on toy curves (the group law, orders, double-and-add and the ladder, ECDH), code checked against the engine
// (point addition, double-and-add, point validation), sizes and bounds, and the choices a defender makes. Nothing
// here asks the student to carry out an attack. Every answer was worked out with S.ECC (curve, add, mul, count,
// structure, scalar.ltr, scalar.ladder, naf, encode, X25519.clamp), and the code exercises check against it.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('ecc-x-singular')) return;
  const ex = (o) => C.exercise(o);
  const E = () => S.ECC;
  const big = (t) => (/^-?\d+$/.test(String(t).trim()) ? BigInt(String(t).trim()) : null);
  const curve = (p, a, b) => E().curve({ p, a, b });

  /**
   * accept() for a point typed as (x, y), or O for the point at infinity, on y² = x³ + ax + b over GF(p). It says
   * which slip a wrong point looks like: the mirror image, a point off the curve, or an unreduced coordinate.
   */
  const pointAnswer = (p, a, b, want) => (v) => {
    const Cv = curve(p, a, b), P = BigInt(p);
    if (v.t === 'atom' && /^(O|∞|inf|infinity)$/i.test(v.v)) return want ? 'Not O: the sum here is an ordinary point.' : true;
    if (v.t !== 'tuple' || v.items.length !== 2 || v.items.some((i) => i.t !== 'atom' || big(i.v) === null)) return 'Write the point as (x, y) with two whole numbers, or O for the point at infinity.';
    const x = big(v.items[0].v), y = big(v.items[1].v);
    if (!want) return 'The answer is the point at infinity, O.';
    if (x < 0n || y < 0n || x >= P || y >= P) return 'Reduce both coordinates to the range 0 … ' + (P - 1n) + '.';
    if (x === want.x && y === want.y) return true;
    if (x === want.x && y === E().mod(-want.y, P)) return '(' + x + ', ' + y + ') is the mirror image of the answer: check the sign of y₃ = λ(x₁ − x₃) − y₁, or the final reflection.';
    if (!Cv.on({ x, y })) return '(' + x + ', ' + y + ') is not on the curve: y² ≡ ' + E().mod(y * y, P) + ' but x³ + ax + b ≡ ' + Cv.rhs(x) + ' (mod ' + p + ').';
    return '(' + x + ', ' + y + ') is on the curve, but it is a different point. Check λ first.';
  };
  const pt = (x, y) => ({ x: BigInt(x), y: BigInt(y) });

  // =========================================================================================================
  // Chapter 1: the group of points
  // =========================================================================================================
  ex({
    id: 'ecc-x-singular', chapter: 'ecc-ch-law', title: 'Which curves are singular', level: 1, kind: 'choice',
    text: ['A curve y² = x³ + ax + b is excluded when 4a³ + 27b² = 0: it has a node, a cusp or a lone point, where no tangent is defined. Which of these choices of a and b are singular?'],
    options: ['a = −3, b = 2', 'a = −4, b = 2', 'a = 1, b = 3', 'a = 0, b = 0', 'a = −3, b = −2'],
    answer: [0, 3, 4],
    hints: ['Work out 4a³ + 27b² for each; only the value 0 is singular, whatever the sign otherwise.', 'For a = −3: 4·(−27) = −108, and 27b² = 108 for b = ±2.', 'Singular: (−3, 2) and (−3, −2), both giving −108 + 108 = 0, and (0, 0), the cusp y² = x³. (−4, 2) gives −148 and (1, 3) gives 247: smooth curves.'],
    solution: [0, 3, 4], wrong: [[0], [0, 3], [1, 2]],
  });
  ex({
    id: 'ecc-x-on-curve', chapter: 'ecc-ch-law', title: 'Points on a curve mod 17', level: 1, kind: 'choice',
    text: ['On y² = x³ + 3x + 5 over GF(17), which of these pairs are points of the curve?'],
    options: ['(4, 8)', '(3, 5)', '(12, 16)', '(0, 5)', '(6, 6)'],
    answer: [0, 2],
    hints: ['For each pair compare y² mod 17 with x³ + 3x + 5 mod 17.', '(4, 8): 64 ≡ 13, and 64 + 12 + 5 = 81 ≡ 13. (0, 5): 25 ≡ 8, but the right side is 5.', 'On the curve: (4, 8) and (12, 16), where 256 ≡ 1 and 1728 + 36 + 5 = 1769 ≡ 1. (3, 5) gives 8 against 41 ≡ 7, (0, 5) gives 8 against 5, and (6, 6) gives 2 against 239 ≡ 1.'],
    solution: [0, 2], wrong: [[0], [0, 2, 3], [1, 4]],
  });
  ex({
    id: 'ecc-x-neg', chapter: 'ecc-ch-law', title: 'The negative of a point', level: 1, kind: 'set',
    text: ['On y² = x³ + 3x + 5 over GF(17), P = (5, 14). Write −P as (x, y), with both coordinates reduced to 0 … 16.'],
    answer: '(5, 3)', accept: pointAnswer(17, 3, 5, pt(5, 3)),
    hints: ['−P is the mirror image of P: same x.', 'Replace y by −y mod 17.', '17 − 14 = 3, so −P = (5, 3). Check: 3² = 9 and 14² = 196 ≡ 9 (mod 17), the same square.'],
    solution: '(5, 3)', wrong: ['(5, -14)', '(12, 14)', '(5, 14)'],
  });
  const addCells = { 'λ|value': '15', 'x₃|value': '9', 'y₃|value': '8' };
  ex({
    id: 'ecc-x-add', chapter: 'ecc-ch-law', title: 'Adding two points by hand', level: 2, kind: 'table',
    text: ['On y² = x³ + 3x + 5 over GF(17), add P = (2, 6) and Q = (10, 7). Give λ, x₃ and y₃ as numbers from 0 to 16.'],
    rows: ['λ', 'x₃', 'y₃'], cols: ['value'], cells: addCells,
    hints: ['λ = (y₂ − y₁)·(x₂ − x₁)⁻¹ = 1·8⁻¹ (mod 17). Find the inverse of 8: which multiple of 8 is one more than a multiple of 17?', '8·15 = 120 = 7·17 + 1, so 8⁻¹ ≡ 15 and λ = 15. Then x₃ = λ² − x₁ − x₂.', 'λ = 15; x₃ = 225 − 2 − 10 = 213 ≡ 9; y₃ = 15·(2 − 9) − 6 = −111 ≡ 8. P + Q = (9, 8), and 8² = 64 ≡ 13 ≡ 9³ + 27 + 5 = 761 (mod 17).'],
    solution: addCells,
    wrong: [Object.assign({}, addCells, { 'λ|value': '8', 'x₃|value': '1', 'y₃|value': '8' }), Object.assign({}, addCells, { 'y₃|value': '9' })],
  });
  const dblCells = { '3x₁² + a|value': '10', '(2y₁)⁻¹|value': '3', 'λ|value': '13', 'x₃|value': '6', 'y₃|value': '1' };
  ex({
    id: 'ecc-x-dbl', chapter: 'ecc-ch-law', title: 'Doubling a point by hand', level: 2, kind: 'table',
    text: ['On y² = x³ + 3x + 5 over GF(17), double P = (5, 3). Fill in each step mod 17.'],
    rows: ['3x₁² + a', '(2y₁)⁻¹', 'λ', 'x₃', 'y₃'], cols: ['value'], cells: dblCells,
    hints: ['3·5² + 3 = 78 ≡ 10 (mod 17), and 2y₁ = 6.', '6·3 = 18 ≡ 1, so 6⁻¹ ≡ 3, and λ = 10·3 = 30 ≡ 13.', 'x₃ = 13² − 2·5 = 159 ≡ 6; y₃ = 13·(5 − 6) − 3 = −16 ≡ 1. So 2P = (6, 1).'],
    solution: dblCells,
    wrong: [Object.assign({}, dblCells, { '3x₁² + a|value': '9', 'λ|value': '10' }), Object.assign({}, dblCells, { 'x₃|value': '1', 'y₃|value': '6' })],
  });

  // the helpers given to the student in the code exercises: the remainder in 0 … p − 1, and an inverse mod p
  const MOD_SRC = '// given: the remainder in 0 … p − 1, and the inverse of v modulo a prime p (extended Euclid)\nconst mod = (v, p) => ((v % p) + p) % p;\nfunction inv(v, p) {\n  let [r0, r1, s0, s1] = [mod(v, p), p, 1n, 0n];\n  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }\n  return mod(s0, p);\n}';
  const ADD_SOL = 'function ecAdd(P, Q, a, p) {\n  if (!P) return Q;\n  if (!Q) return P;\n  let l;\n  if (P.x === Q.x) {\n    if (mod(P.y + Q.y, p) === 0n) return null;\n    l = mod((3n * P.x * P.x + a) * inv(2n * P.y, p), p);\n  } else {\n    l = mod((Q.y - P.y) * inv(Q.x - P.x, p), p);\n  }\n  const x = mod(l * l - P.x - Q.x, p);\n  return { x, y: mod(l * (P.x - x) - P.y, p) };\n}\n';
  // a reference that goes through the engine: the curve's b follows from any point given
  const bOf = (P, a, p) => (P ? E().mod(P.y * P.y - P.x * P.x * P.x - a * P.x, p) : 1n);
  const engineAdd = (P, Q, a, p) => curve(p, a, bOf(P || Q, a, p)).add(P, Q);
  const P256 = () => E().P256;
  const addCases = () => {
    const G = P256().G, G2 = P256().dbl(G);
    return [
      [pt(2, 6), pt(10, 7), 3n, 17n], [pt(5, 3), pt(5, 3), 3n, 17n], [pt(5, 3), pt(5, 14), 3n, 17n], [null, pt(1, 3), 3n, 17n], [pt(1, 3), null, 3n, 17n],
      [pt(1, 18), pt(17, 79), 6n, 101n], [pt(1, 18), pt(1, 18), 6n, 101n], [pt(24, 0), pt(24, 0), 3n, 103n], [pt(16, 16), pt(1, 3), 3n, 17n],
      [G, G2, P256().a, P256().p], [G2, G2, P256().a, P256().p],
    ];
  };
  ex({
    id: 'ecc-x-code-add', chapter: 'ecc-ch-law', title: 'Write point addition', level: 2, kind: 'code', fn: 'ecAdd', params: ['P', 'Q', 'a', 'p'],
    text: ['Write `ecAdd(P, Q, a, p)` for y² = x³ + ax + b over GF(p). Points are objects `{x, y}` of BigInts, and `null` is the point at infinity O; a and p are BigInts. Return P + Q, reduced to 0 … p − 1.', 'Handle every case: P or Q is O; Q = −P (return null); P = Q (the tangent); and the ordinary chord. `mod` and `inv` are given. The tests run on toy curves and on P-256.'],
    prelude: MOD_SRC,
    start: 'function ecAdd(P, Q, a, p) {\n  \n}\n',
    ref: (P, Q, a, p) => engineAdd(P, Q, a, p),
    get cases() { return addCases(); },
    hints: ['Start with the identities: if P is null return Q, if Q is null return P.', 'Same x: either Q = −P (y₁ + y₂ ≡ 0, return null) or P = Q (λ = (3x² + a)/(2y)). Different x: λ = (y₂ − y₁)/(x₂ − x₁). Divide with inv.', ADD_SOL],
    solution: ADD_SOL,
    wrong: [
      'function ecAdd(P, Q, a, p) {\n  if (!P) return Q;\n  if (!Q) return P;\n  const l = mod((Q.y - P.y) * inv(Q.x - P.x, p), p);\n  const x = mod(l * l - P.x - Q.x, p);\n  return { x, y: mod(l * (P.x - x) - P.y, p) };\n}\n',
      'function ecAdd(P, Q, a, p) {\n  if (!P) return Q;\n  if (!Q) return P;\n  let l;\n  if (P.x === Q.x) l = mod((3n * P.x * P.x + a) * inv(2n * P.y, p), p);\n  else l = mod((Q.y - P.y) * inv(Q.x - P.x, p), p);\n  const x = mod(l * l - P.x - Q.x, p);\n  return { x, y: mod(l * (P.x - x) - P.y, p) };\n}\n',
      'function ecAdd(P, Q, a, p) {\n  if (!P) return Q;\n  if (!Q) return P;\n  let l;\n  if (P.x === Q.x) {\n    if (mod(P.y + Q.y, p) === 0n) return null;\n    l = mod((3n * P.x * P.x + a) * inv(2n * P.y, p), p);\n  } else l = mod((Q.y - P.y) * inv(Q.x - P.x, p), p);\n  const x = mod(l * l - P.x - Q.x, p);\n  return { x, y: l * (P.x - x) - P.y };\n}\n',
    ],
  });
  const walkCells = { '2P|x': '14', '2P|y': '14', '3P|x': '8', '3P|y': '11', '4P|x': '15', '4P|y': '0' };
  ex({
    id: 'ecc-x-walk', chapter: 'ecc-ch-law', title: 'Walking the multiples of a point', level: 2, kind: 'table',
    text: ['On y² = x³ + 6x + 3 over GF(17) (16 points), take P = (10, 3) and compute 2P, 3P = 2P + P and 4P = 2·(2P). Look at 4P: what does it tell you about the order of P?'],
    rows: ['2P', '3P', '4P'], cols: ['x', 'y'], cells: walkCells,
    hints: ['2P: λ = (3·10² + 6)·(2·3)⁻¹ = 306·6⁻¹ ≡ 0·3 = 0 (mod 17), since 306 = 18·17. So x = 0 − 20 ≡ 14 and y = 0 − 3 ≡ 14.', '3P = (14, 14) + (10, 3): λ = (3 − 14)·(10 − 14)⁻¹ = (−11)·(−4)⁻¹ ≡ 6·13⁻¹ ≡ 6·4 = 24 ≡ 7, giving (8, 11). 4P doubles (14, 14).', '2P = (14, 14), 3P = (8, 11), 4P = (15, 0). 4P has y = 0, so it has order 2: 8P = O while 4P ≠ O, and the order of P is 8, a divisor of 16 as Lagrange demands.'],
    solution: walkCells,
    wrong: [Object.assign({}, walkCells, { '2P|y': '3' }), Object.assign({}, walkCells, { '4P|x': '8', '4P|y': '6' })],
  });
  ex({
    id: 'ecc-x-order', chapter: 'ecc-ch-law', title: 'An order from a few tests', level: 2, kind: 'number',
    text: ['A curve has #E = 60 = 2²·3·5 points. For a point P you compute 30P ≠ O, 20P ≠ O and 12P = O, then 6P ≠ O and 4P ≠ O. What is the order of P?'],
    answer: 12,
    hints: ['The order divides 60 (Lagrange), and 12P = O means it divides 12.', 'If the order were a proper divisor of 12, it would divide 12/2 = 6 or 12/3 = 4.', '6P ≠ O and 4P ≠ O, so no proper divisor of 12 works: the order is 12. The tests 30P and 20P were not needed once 12P = O was known.'],
    solution: '12', wrong: ['60', '6', '4'],
    whyNot: { 60: '12P = O already, so the order is at most 12.', 6: '6P ≠ O, so the order is not 6.', 4: '4P ≠ O, so the order is not 4.', '*': 'The order is the smallest n with nP = O, and it divides 60.' },
  });
  ex({
    id: 'ecc-x-lagrange', chapter: 'ecc-ch-law', title: 'Which orders are possible', level: 1, kind: 'set',
    text: ['y² = x³ + 4x + 6 over GF(31) has 28 points. Which orders can a point of this curve have? Write them as a set.'],
    answer: '{1, 2, 4, 7, 14, 28}',
    hints: ['By Lagrange, the order of a point divides the number of points.', '28 = 2²·7.', 'The divisors of 28: {1, 2, 4, 7, 14, 28}. O alone has order 1.'],
    solution: '{1, 2, 4, 7, 14, 28}', wrong: ['{2, 4, 7, 14}', '{1, 2, 4, 7, 14}', '{1, 2, 3, 4, 7, 14, 28}'],
    whyNot: 'Every order divides #E = 28, and every divisor of 28 is listed once.',
  });
  ex({
    id: 'ecc-x-count', chapter: 'ecc-ch-law', title: 'Count the points by hand', level: 2, kind: 'number',
    text: ['Count the points of y² = x³ + 3x + 7 over GF(13), O included. The nonzero squares mod 13 are 1, 3, 4, 9, 10 and 12.'],
    answer: 13,
    hints: ['Work out f(x) = x³ + 3x + 7 mod 13 for x = 0 … 12, and ask of each value: 0, a nonzero square, or neither?', 'The values are 7, 11, 8, 4, 5, 4, 7, 7, 10, 9, 10, 6, 3.', 'Squares at x = 3, 5, 8, 9, 10 and 12: 6 values, two points each; no zero. #E = 1 + 2·6 = 13. Note that #E = p: such a curve is anomalous, and chapter 4 explains why it must never be used.'],
    solution: '13', wrong: ['12', '14', '7'],
    whyNot: { 12: 'Count O as well.', 14: 'p + 1 is only the average; count the squares.', 7: 'Each nonzero square gives two points, y and −y.', '*': '#E = 1 + (number of x with f(x) = 0) + 2·(number of x with f(x) a nonzero square).' },
  });
  const hasseCells = { 'p = 211|smallest #E': '183', 'p = 211|largest #E': '241', 'p = 1009|smallest #E': '947', 'p = 1009|largest #E': '1073' };
  ex({
    id: 'ecc-x-hasse', chapter: 'ecc-ch-law', title: 'Hasse\'s interval', level: 1, kind: 'table',
    text: ['By Hasse\'s theorem, |#E − (p + 1)| ≤ 2√p. Give the smallest and the largest whole number of points a curve over GF(p) can have.'],
    rows: ['p = 211', 'p = 1009'], cols: ['smallest #E', 'largest #E'], cells: hasseCells,
    hints: ['2√211 ≈ 29.05 and 2√1009 ≈ 63.53.', 'p + 1 = 212: 212 − 29.05 = 182.95 and 212 + 29.05 = 241.05. Round inwards.', 'p = 211: 183 to 241. p = 1009: 1010 − 63.53 = 946.47 and 1010 + 63.53 = 1073.53, so 947 to 1073.'],
    solution: hasseCells,
    wrong: [Object.assign({}, hasseCells, { 'p = 211|smallest #E': '182', 'p = 211|largest #E': '242' }), Object.assign({}, hasseCells, { 'p = 1009|smallest #E': '946' })],
  });
  ex({
    id: 'ecc-x-hasse-which', chapter: 'ecc-ch-law', title: 'Impossible counts', level: 2, kind: 'choice',
    text: ['A report lists point counts for curves over GF(101). Which of the counts cannot be right?'],
    options: ['80', '95', '103', '122', '123'],
    answer: [0, 4],
    hints: ['2√101 ≈ 20.10 and p + 1 = 102.', 'Allowed: 102 − 20.10 = 81.90 up to 102 + 20.10 = 122.10, so 82 … 122.', '80 and 123 are outside. 103 is the count of the course\'s own toy curve y² = x³ + 6x + 14, and 122 is right at the edge.'],
    solution: [0, 4], wrong: [[0], [0, 3, 4], [4]],
  });

  // =========================================================================================================
  // Chapter 2: scalar multiplication
  // =========================================================================================================
  const daCells = { 'bit 4 = 1|m': '1', 'bit 4 = 1|x': '1', 'bit 4 = 1|y': '3', 'bit 3 = 0|m': '2', 'bit 3 = 0|x': '16', 'bit 3 = 0|y': '16', 'bit 2 = 0|m': '4', 'bit 2 = 0|x': '11', 'bit 2 = 0|y': '3', 'bit 1 = 1|m': '9', 'bit 1 = 1|x': '2', 'bit 1 = 1|y': '6', 'bit 0 = 1|m': '19', 'bit 0 = 1|x': '11', 'bit 0 = 1|y': '14' };
  ex({
    id: 'ecc-x-dbladd-table', chapter: 'ecc-ch-scalar', title: 'Double-and-add, bit by bit', level: 2, kind: 'table',
    text: ['Compute 19·P on y² = x³ + 3x + 5 over GF(17), with P = (1, 3), by left-to-right double-and-add. 19 = 10011₂. After each bit, give m (the running point is R = m·P) and R\'s coordinates.'],
    rows: ['bit 4 = 1', 'bit 3 = 0', 'bit 2 = 0', 'bit 1 = 1', 'bit 0 = 1'], cols: ['m', 'x', 'y'], corner: 'after',
    cells: daCells,
    hints: ['The top bit sets R = P (m = 1). Each later bit doubles (m → 2m) and a 1 bit then adds P (m → 2m + 1).', 'm goes 1, 2, 4, 9, 19. 2P = (16, 16); 4P = 2·(16, 16) = (11, 3).', '9P = 2·(11, 3) + P = (2, 6); 19P = 2·(2, 6) + P = (11, 14). Four doublings and two additions, against 18 additions one by one.'],
    solution: daCells,
    wrong: [Object.assign({}, daCells, { 'bit 1 = 1|m': '8', 'bit 0 = 1|m': '17' }), Object.assign({}, daCells, { 'bit 0 = 1|y': '3' })],
  });
  ex({
    id: 'ecc-x-dbladd-count', chapter: 'ecc-ch-scalar', title: 'Counting operations', level: 1, kind: 'number',
    text: ['A 256-bit scalar k (its top bit 1) has 100 bits equal to 1. How many group operations, doublings plus additions, does left-to-right double-and-add do?'],
    answer: 354,
    hints: ['The top bit only sets R = P.', 'A doubling for each of the 255 later bits, an addition for each of the 99 later 1 bits.', '255 + 99 = 354. Since the count depends on the number of 1 bits, the running time already says something about k.'],
    solution: '354', wrong: ['356', '256', '512'],
    whyNot: { 356: 'The top bit needs no doubling and no addition: it just sets R = P.', 256: 'Count the additions too.', 512: 'Additions happen only for 1 bits.', '*': 'Doublings: bits after the first. Additions: 1 bits after the first.' },
  });
  const DA_SOL = 'function scalarMul(k, P, a, p) {\n  let R = null;\n  for (const b of k.toString(2)) {\n    R = ecAdd(R, R, a, p);\n    if (b === \'1\') R = ecAdd(R, P, a, p);\n  }\n  return R;\n}\n';
  const daCases = () => {
    const G = P256().G;
    return [[19n, pt(1, 3), 3n, 17n], [1n, pt(1, 3), 3n, 17n], [23n, pt(1, 3), 3n, 17n], [22n, pt(1, 3), 3n, 17n], [45n, pt(1, 18), 6n, 101n], [77n, pt(1, 18), 6n, 101n], [2n, pt(1, 18), 6n, 101n], [8n, pt(10, 3), 6n, 17n],
      [3141592653n, G, P256().a, P256().p], [0x31801b1230f5ffab374a7a0a4b38d1837a0974b0489490e3dfef8e69d8898cd2n, G, P256().a, P256().p]];
  };
  ex({
    id: 'ecc-x-code-dbladd', chapter: 'ecc-ch-scalar', title: 'Write double-and-add', level: 2, kind: 'code', fn: 'scalarMul', params: ['k', 'P', 'a', 'p'], decimalArgs: [0],
    text: ['Write `scalarMul(k, P, a, p)`: k is a BigInt of at least 1, P a point `{x, y}` of BigInts, and the curve is y² = x³ + ax + b over GF(p). Return k·P, or `null` when it is O, by left-to-right double-and-add.', '`ecAdd(P, Q, a, p)` is given (with `mod` and `inv`), and handles O as null, doubling and P + (−P). The tests include k equal to the order of P, a 256-bit k on P-256, and a point whose multiples pass through O.'],
    prelude: MOD_SRC + '\n' + ADD_SOL,
    start: 'function scalarMul(k, P, a, p) {\n  \n}\n',
    ref: (k, P, a, p) => curve(p, a, bOf(P, a, p)).mul(k, P),
    get cases() { return daCases(); },
    hints: ['Start from R = null (O). `k.toString(2)` gives the bits from the top.', 'For each bit: R = ecAdd(R, R, a, p); then, if the bit is 1, R = ecAdd(R, P, a, p). Doubling O gives O, so the first bit just sets R = P.', DA_SOL],
    solution: DA_SOL,
    wrong: [
      'function scalarMul(k, P, a, p) {\n  let R = null;\n  for (const b of k.toString(2)) {\n    if (b === \'1\') R = ecAdd(R, P, a, p);\n    R = ecAdd(R, R, a, p);\n  }\n  return R;\n}\n',
      'function scalarMul(k, P, a, p) {\n  let R = P;\n  for (const b of k.toString(2)) {\n    R = ecAdd(R, R, a, p);\n    if (b === \'1\') R = ecAdd(R, P, a, p);\n  }\n  return R;\n}\n',
    ],
  });
  const ladCells = { 'bit 3 = 1|R₀: m': '1', 'bit 3 = 1|R₁: m': '2', 'bit 3 = 1|x of R₀': '1', 'bit 3 = 1|y of R₀': '3', 'bit 2 = 1|R₀: m': '3', 'bit 2 = 1|R₁: m': '4', 'bit 2 = 1|x of R₀': '4', 'bit 2 = 1|y of R₀': '8', 'bit 1 = 0|R₀: m': '6', 'bit 1 = 0|R₁: m': '7', 'bit 1 = 0|x of R₀': '9', 'bit 1 = 0|y of R₀': '9', 'bit 0 = 1|R₀: m': '13', 'bit 0 = 1|R₁: m': '14', 'bit 0 = 1|x of R₀': '6', 'bit 0 = 1|y of R₀': '1' };
  ex({
    id: 'ecc-x-ladder-table', chapter: 'ecc-ch-scalar', title: 'A Montgomery ladder by hand', level: 3, kind: 'table',
    text: ['Run the Montgomery ladder for 13·P on y² = x³ + 3x + 5 over GF(17), P = (1, 3). 13 = 1101₂. Start with R₀ = O, R₁ = P. For a 1 bit: R₀ ← R₀ + R₁, R₁ ← 2R₁; for a 0 bit: R₁ ← R₀ + R₁, R₀ ← 2R₀. After each bit give the multiples held by R₀ and R₁, and R₀\'s coordinates.'],
    rows: ['bit 3 = 1', 'bit 2 = 1', 'bit 1 = 0', 'bit 0 = 1'], cols: ['R₀: m', 'R₁: m', 'x of R₀', 'y of R₀'], corner: 'after',
    cells: ladCells,
    hints: ['R₁ − R₀ = P always, so R₁ holds one more multiple than R₀. A 1 bit takes m to 2m + 1, a 0 bit to 2m.', 'The multiples go (1, 2), (3, 4), (6, 7), (13, 14). 3P = P + 2P with 2P = (16, 16) gives (4, 8).', 'R₀: P = (1, 3), 3P = (4, 8), 6P = 2·(4, 8) = (9, 9), 13P = 6P + 7P = (6, 1), where 7P = 3P + 4P = (15, 12). Every bit cost one addition and one doubling.'],
    solution: ladCells,
    wrong: [Object.assign({}, ladCells, { 'bit 1 = 0|R₀: m': '7', 'bit 1 = 0|R₁: m': '8' }), Object.assign({}, ladCells, { 'bit 0 = 1|x of R₀': '2', 'bit 0 = 1|y of R₀': '11' })],
  });
  ex({
    id: 'ecc-x-leak', chapter: 'ecc-ch-scalar', title: 'Which loops give the scalar away', level: 2, kind: 'choice',
    text: ['Each loop computes d·P for a secret d. Which of them let the sequence of operations, the branches or the memory accessed depend on the bits of d?'],
    options: ['Double-and-add: `R = dbl(R); if (bit) R = add(R, P);`', 'A ladder written as `if (bit) { R0 = add(R0, R1); R1 = dbl(R1); } else { R1 = add(R0, R1); R0 = dbl(R0); }`', 'A ladder that does `cswap(bit ^ prev, R0, R1)` with masks, then always `R1 = add(R0, R1); R0 = dbl(R0);`', 'Add-always: compute T = add(R, P) every time and keep T or R with a mask select', 'A window method that reads `table[digit]` straight from memory'],
    answer: [0, 1, 4],
    whyNot: { 2: 'The masked swap runs the same instructions for both bits, and the same add and dbl follow: nothing depends on the bit.', 3: 'Computing the addition every time and selecting with a mask hides the bit, as long as the select has no branch.' },
    hints: ['Look for an `if` on a secret bit, and for a memory address chosen by a secret.', 'The second loop does one add and one dbl either way, but the branch and the registers it writes still follow the bit.', 'Leaky: double-and-add (an extra addition for each 1), the branching ladder (a branch on the bit) and the plain table lookup (a secret address). Safe: the masked-swap ladder and add-always with a mask select.'],
    solution: [0, 1, 4], wrong: [[0], [0, 4], [0, 1, 3, 4]],
  });
  ex({
    id: 'ecc-x-x25519-cost', chapter: 'ecc-ch-scalar', title: 'The cost of an X25519 ladder', level: 1, kind: 'number',
    text: ['X25519 runs its ladder over 255 bits, and every step costs 5 field multiplications and 4 squarings, whatever the bit. How many multiplications does one ladder take (not counting squarings or the final inversion)?'],
    answer: 1275,
    hints: ['The work is the same for every step.', '255 steps × 5 multiplications.', '1275 multiplications and 255 × 4 = 1020 squarings, for every key: the count gives nothing away.'],
    solution: '1275', wrong: ['1020', '2295', '1280'],
    whyNot: { 1020: 'That is the number of squarings.', 2295: 'Only the multiplications are asked for.', 1280: 'The ladder has 255 steps, not 256.', '*': 'Multiply the steps by the multiplications per step.' },
  });
  const nafValue = (ds) => ds.reduce((v, d) => 2 * v + d, 0);
  ex({
    id: 'ecc-x-naf', chapter: 'ecc-ch-scalar', title: 'The NAF of 55', level: 3, kind: 'string',
    text: ['Write 55 (110111₂) in non-adjacent form: digits −1, 0 and 1, no two nonzero digits next to each other. Give the digits from the most significant, separated by spaces, writing −1 as -1.'],
    answer: '1 0 0 -1 0 0 -1',
    accept(t) {
      const toks = String(t).replace(/[−–]/g, '-').split(/[\s,]+/).filter(Boolean);
      if (!toks.length || toks.some((d) => !/^-?[01]$/.test(d))) return 'Use only the digits 1, 0 and -1, separated by spaces.';
      const ds = toks.map(Number), v = nafValue(ds);
      if (v !== 55) return 'Those digits make ' + v + ', not 55.';
      for (let i = 1; i < ds.length; i++) if (ds[i] && ds[i - 1]) return 'Those digits make 55, but two nonzero digits are next to each other: that is not the NAF.';
      if (ds[0] === 0) return 'Leave out leading zeros.';
      return true;
    },
    hints: ['Work from the bottom: if k is odd, take the digit d = 2 − (k mod 4), which is 1 or −1, so that k − d is divisible by 4; if k is even, the digit is 0. Then k ← (k − d)/2.', '55 mod 4 = 3, so d₀ = −1 and k becomes 28; then 0, 0 (k = 7); 7 mod 4 = 3, so d₃ = −1 and k becomes 4; then 0, 0, and finally 1.', 'From the top: 1 0 0 -1 0 0 -1, that is 64 − 8 − 1 = 55. Three nonzero digits against five 1 bits in binary.'],
    solution: '1 0 0 -1 0 0 -1', wrong: ['1 1 0 1 1 1', '1 0 0 -1 0 1 -1', '1 0 0 0 -1 0 0 -1'],
  });
  ex({
    id: 'ecc-x-jacobian', chapter: 'ecc-ch-scalar', title: 'From Jacobian back to affine', level: 2, kind: 'set',
    text: ['On y² = x³ + 6x + 14 over GF(101), a point is held in Jacobian coordinates as (X : Y : Z) = (25 : 28 : 5). Which affine point (x, y) = (X/Z², Y/Z³) is it?'],
    answer: '(1, 18)', accept: pointAnswer(101, 6, 14, pt(1, 18)),
    hints: ['Z² = 25 and Z³ = 125 ≡ 24 (mod 101).', 'x = 25·25⁻¹ = 1. For y, find 24⁻¹ mod 101, or check which y gives 24·y ≡ 28.', '24·18 = 432 = 4·101 + 28, so y = 18: the point is (1, 18), the toy curve\'s base point G. One inversion of Z recovers it, however many operations came before.'],
    solution: '(1, 18)', wrong: ['(25, 28)', '(1, 83)', '(5, 28)'],
  });

  // =========================================================================================================
  // Chapter 3: key exchange and encodings
  // =========================================================================================================
  const dhCells = { '2·Q_B|λ': '7', '2·Q_B|x': '2', '2·Q_B|y': '11', 'S = 3·Q_B|λ': '4', 'S = 3·Q_B|x': '16', 'S = 3·Q_B|y': '1' };
  ex({
    id: 'ecc-x-ecdh', chapter: 'ecc-ch-use', title: 'An ECDH shared point by hand', level: 2, kind: 'table',
    text: ['Alice and Bob use y² = x³ + 3x + 5 over GF(17) with G = (1, 3) of prime order 23. Alice\'s secret is d_A = 3, and Bob has sent Q_B = (15, 12), which she has checked is on the curve. Compute her shared point S = 3·Q_B as 2·Q_B, then 2·Q_B + Q_B.'],
    rows: ['2·Q_B', 'S = 3·Q_B'], cols: ['λ', 'x', 'y'], cells: dhCells,
    hints: ['Doubling: λ = (3·15² + 3)·(2·12)⁻¹. 15² = 225 ≡ 4, so the top is 15; 24 ≡ 7 and 7⁻¹ ≡ 5.', '2·Q_B: λ = 15·5 = 75 ≡ 7, x = 49 − 30 ≡ 2, y = 7·(15 − 2) − 12 = 79 ≡ 11. Then add (2, 11) and (15, 12): λ = 1·13⁻¹ ≡ 4.', 'S = (16, 1): x = 16 − 2 − 15 ≡ 16, y = 4·(2 − 16) − 11 = −67 ≡ 1. Bob, with d_B = 7, gets the same point as 7·Q_A = 7·(4, 8), since both are 21·G.'],
    solution: dhCells,
    wrong: [Object.assign({}, dhCells, { 'S = 3·Q_B|y': '16' }), Object.assign({}, dhCells, { '2·Q_B|λ': '15', '2·Q_B|x': '4' })],
  });
  ex({
    id: 'ecc-x-ecdh-why', chapter: 'ecc-ch-use', title: 'What ECDH does and does not give', level: 1, kind: 'choice',
    text: ['Which statements about elliptic-curve Diffie–Hellman are true?'],
    options: ['Eve can get S by adding the public points Q_A and Q_B', 'S = d_A·Q_B = d_B·Q_A = (d_A·d_B)·G', 'The x-coordinate of S is passed through a key-derivation function, because its bits are not uniformly random', 'ECDH on its own proves to Alice that she is talking to Bob'],
    answer: [1, 2],
    whyNot: { 0: 'Q_A + Q_B = (d_A + d_B)·G, a different point.', 3: 'Nothing in the exchange identifies Bob: a man in the middle can run one exchange with each side. Authentication comes from signatures or certificates.' },
    hints: ['Write each public point as a multiple of G.', 'Multiplying is what needs a secret; adding public points gives a sum of secrets, not a product.', 'True: S = (d_A·d_B)·G, and the KDF step. False: adding the public points, and authentication by ECDH alone.'],
    solution: [1, 2], wrong: [[0, 1, 2], [1, 2, 3], [1]],
  });
  const clampCells = { 'byte 0 (7b)|after clamping': '78', 'byte 31 (9a)|after clamping': '5a' };
  ex({
    id: 'ecc-x-clamp', chapter: 'ecc-ch-use', title: 'Clamping an X25519 key', level: 2, kind: 'table', cellKind: 'hex',
    text: ['An X25519 secret key is 32 random bytes; here byte 0 is 7b and byte 31 is 9a. Clamping does byte 0 &= 248 (f8), byte 31 &= 127 (7f), byte 31 |= 64 (40). Give the two bytes after clamping, in hex.'],
    rows: ['byte 0 (7b)', 'byte 31 (9a)'], cols: ['after clamping'], cells: clampCells,
    hints: ['7b = 0111 1011 and 9a = 1001 1010.', 'Byte 0: clear the low three bits. Byte 31: clear bit 7, then set bit 6.', 'Byte 0: 0111 1000 = 78, a multiple of 8. Byte 31: 0001 1010 | 0100 0000 = 0101 1010 = 5a, so bit 254 of the scalar is set and bit 255 clear.'],
    solution: clampCells,
    wrong: [{ 'byte 0 (7b)|after clamping': '7b', 'byte 31 (9a)|after clamping': '1a' }, { 'byte 0 (7b)|after clamping': '78', 'byte 31 (9a)|after clamping': 'da' }],
  });
  ex({
    id: 'ecc-x-forms', chapter: 'ecc-ch-use', title: 'Why Edwards form', level: 2, kind: 'choice',
    text: ['Ed25519 does its arithmetic on a twisted Edwards curve, though the same group can be written in Weierstrass form. What is the main gain?'],
    options: ['The group is larger, so security is higher', 'One complete addition formula with no special cases: doubling, adding O and adding −P all use it, with no branches to leak or forget', 'Points need no validation', 'The discrete logarithm is harder on an Edwards curve'],
    answer: 1,
    whyNot: { 0: 'The forms describe the same group, with the same number of points.', 2: 'Received points still have to be decoded and checked.', 3: 'The logarithm is the same problem in every form: the maps between forms are cheap.' },
    hints: ['The three forms in the lesson had the same 148 points.', 'What did the Weierstrass formulas need that Edwards did not?', 'Completeness: when a is a square and d is not, the Edwards denominators are never zero, so one formula handles every case. Fewer branches means fewer timing leaks and fewer forgotten cases.'],
    solution: 1, wrong: [0, 2, 3],
  });
  const sizeCells = { 'P-256, uncompressed|bytes': '65', 'P-256, compressed|bytes': '33', 'P-384, compressed|bytes': '49', 'X25519 public key|bytes': '32' };
  ex({
    id: 'ecc-x-sizes', chapter: 'ecc-ch-use', title: 'How long is a public key', level: 1, kind: 'table',
    text: ['Give the length in bytes of each public key encoding. P-256 coordinates are 32 bytes, P-384 coordinates 48; SEC 1 adds one prefix byte (04, or 02/03 when compressed); X25519 sends u alone, little-endian, with no prefix.'],
    rows: ['P-256, uncompressed', 'P-256, compressed', 'P-384, compressed', 'X25519 public key'], cols: ['bytes'], cells: sizeCells,
    hints: ['Uncompressed: 1 + 2 coordinates. Compressed: 1 + one coordinate.', 'P-256: 1 + 64 and 1 + 32.', '65, 33, 1 + 48 = 49, and 32.'],
    solution: sizeCells,
    wrong: [Object.assign({}, sizeCells, { 'P-256, compressed|bytes': '32' }), Object.assign({}, sizeCells, { 'P-256, uncompressed|bytes': '64', 'X25519 public key|bytes': '33' })],
  });
  ex({
    id: 'ecc-x-encode', chapter: 'ecc-ch-use', title: 'Compress a toy point', level: 1, kind: 'hex',
    text: ['On y² = x³ + 6x + 14 over GF(101), coordinates fit in one byte. Write the compressed SEC 1 encoding of Q = (87, 32) in hex: a prefix byte (02 for even y, 03 for odd y) and then x.'],
    answer: '0257',
    hints: ['y = 32 is even.', 'The prefix is 02, and 87 = 0x57.', '02 57. Uncompressed it would be 04 57 20.'],
    solution: '0257', wrong: ['0357', '045720', '0287'],
  });
  ex({
    id: 'ecc-x-decompress', chapter: 'ecc-ch-use', title: 'Decompress a point', level: 3, kind: 'set',
    text: ['On y² = x³ + x + 4 over GF(23) you receive the compressed point 03 09: x = 9, and the prefix asks for an odd y. Since 23 ≡ 3 (mod 4), a square root of s is s^6 mod 23 (if s is a square). Recover the point.'],
    answer: '(9, 11)', accept: pointAnswer(23, 1, 4, pt(9, 11)),
    hints: ['s = 9³ + 9 + 4 = 742 ≡ 6 (mod 23).', '6^6: 6² = 36 ≡ 13, 6⁴ ≡ 13² = 169 ≡ 8, 6⁶ ≡ 13·8 = 104 ≡ 12. Check: 12² = 144 ≡ 6, so 6 is a square and the point exists.', 'The roots are 12 and 23 − 12 = 11. The prefix 03 asks for the odd one: (9, 11). Had 12² not come back to 6, the decoder would have to reject the point.'],
    solution: '(9, 11)', wrong: ['(9, 12)', '(9, 6)', '(9, 3)'],
  });

  // =========================================================================================================
  // Chapter 4: the rules for safe curves
  // =========================================================================================================
  const secCells = { 'n of 224 bits|security (bits)': '112', 'n of 256 bits|security (bits)': '128', 'n of 384 bits|security (bits)': '192' };
  ex({
    id: 'ecc-x-security', chapter: 'ecc-ch-rules', title: 'Group size and security level', level: 1, kind: 'table',
    text: ['The best generic attack on a group of prime order n takes about √n operations. Give the security level in bits for base points of these prime orders.'],
    rows: ['n of 224 bits', 'n of 256 bits', 'n of 384 bits'], cols: ['security (bits)'], cells: secCells,
    hints: ['√(2^b) = 2^(b/2).', 'Halve the number of bits.', '112, 128 and 192 bits: the levels of P-224, P-256 and P-384.'],
    solution: secCells,
    wrong: [Object.assign({}, secCells, { 'n of 256 bits|security (bits)': '256' }), Object.assign({}, secCells, { 'n of 384 bits|security (bits)': '128' })],
  });
  ex({
    id: 'ecc-x-rho-size', chapter: 'ecc-ch-rules', title: 'Sizing against rho', level: 2, kind: 'number', tolerance: 3,
    text: ['A test group has prime order n = 65557. The expected number of steps of Pollard\'s rho is about √(πn/2). Work it out, to the nearest whole number. (It says how far below a real group\'s size a test group must be kept: at n ≈ 2²⁵⁶ the same formula gives about 2¹²⁸.)'],
    answer: 321,
    hints: ['πn/2 = 3.14159 × 65557 / 2.', 'πn/2 ≈ 102977.', '√102977 ≈ 320.9, so about 321 steps.'],
    solution: '321', wrong: ['256', '65557', '102977'],
    whyNot: { 256: 'That is √n; the rho estimate has the extra factor √(π/2) ≈ 1.25.', 65557: 'Trying every value is the slow method; rho needs about √n.', 102977: 'Take the square root.', '*': 'Compute √(π·65557/2).' },
  });
  ex({
    id: 'ecc-x-prime-order', chapter: 'ecc-ch-rules', title: 'Which base points to accept', level: 2, kind: 'choice',
    text: ['A library offers five curves over 256-bit fields, each with a base point G. Which base points are fit for a key exchange at the 128-bit level?'],
    options: ['G has prime order n ≈ 2²⁵⁶ (cofactor 1)', 'G has order n = 2⁸⁰·3⁵⁰·5³⁰·…, every prime factor below 100', 'G has order 4·q with q a 64-bit prime', 'G has order 8·L with L a 252-bit prime', 'G has prime order L ≈ 2²⁵², on a curve with cofactor 8 that the protocol handles'],
    answer: [0, 4],
    whyNot: { 1: 'A smooth order splits the logarithm into tiny pieces (Pohlig–Hellman).', 2: 'The largest prime factor is 64 bits, so the logarithm costs about 2³² steps.', 3: 'A base point of order 8L puts part of every key into a subgroup of order 8, which leaks d mod 8. Use a base point of order L.' },
    hints: ['The security follows the largest prime factor of the base point\'s order.', 'A cofactor is fine if the base point itself has prime order and the protocol keeps out points of small order.', 'Fit: prime order 2²⁵⁶, and prime order L on the cofactor-8 curve (as Curve25519 does). Unfit: the smooth order, the 64-bit q, and the base point of order 8L.'],
    solution: [0, 4], wrong: [[0], [0, 3, 4], [0, 2, 4]],
  });
  const chkCells = { 'a point on y² = x³ + ax + b′ with b′ ≠ b|check': 'B', 'a point of order 4 on the right curve, cofactor 4|check': 'C', 'u on the twist, sent to an x-only ladder|check': 'E', 'the point at infinity sent as a public key|check': 'D', 'x sent as x + p, which reduces to a point|check': 'A' };
  ex({
    id: 'ecc-x-checks', chapter: 'ecc-ch-rules', title: 'Which check stops which point', level: 3, kind: 'table',
    text: ['A key-exchange server receives a public point. Match each hostile input with the check that rejects it (one letter each):', { list: ['A: 0 ≤ x, y < p', 'B: y² ≡ x³ + ax + b (mod p)', 'C: n·Q = O (Q in the prime-order subgroup)', 'D: Q ≠ O', 'E: u³ + Au² + u is a square mod p (or a twist-secure curve)'] }],
    rows: ['a point on y² = x³ + ax + b′ with b′ ≠ b', 'a point of order 4 on the right curve, cofactor 4', 'u on the twist, sent to an x-only ladder', 'the point at infinity sent as a public key', 'x sent as x + p, which reduces to a point'], cols: ['check'], cells: chkCells,
    hints: ['Ask for each input: which statement about it is false?', 'The order-4 point satisfies the right equation, so only the subgroup check catches it. The x-only ladder never sees a y, so the test is on u.', 'B for the invalid curve, C for the small-subgroup point, E for the twist, D for O, A for the unreduced coordinate. Each check closes one door; a server needs all that apply to its curve.'],
    solution: chkCells,
    wrong: [Object.assign({}, chkCells, { 'a point of order 4 on the right curve, cofactor 4|check': 'B' }), Object.assign({}, chkCells, { 'u on the twist, sent to an x-only ladder|check': 'B', 'x sent as x + p, which reduces to a point|check': 'B' })],
  });

  // point validation on a cofactor-4 toy curve, on a prime-order toy and on P-256
  const VC = { p: 103n, a: 3n, b: 9n, n: 31n, h: 4n };
  const VAL_SOL = 'function isValid(Q, C) {\n  if (Q === null) return false;\n  const { p, a, b, n, h } = C;\n  if (Q.x < 0n || Q.x >= p || Q.y < 0n || Q.y >= p) return false;\n  if (mod(Q.y * Q.y - (Q.x * Q.x * Q.x + a * Q.x + b), p) !== 0n) return false;\n  if (h !== 1n && scalarMul(n, Q, a, p) !== null) return false;\n  return true;\n}\n';
  const valCases = () => {
    const V = curve(103, 3, 9), G = V.mul(4n, pt(1, 42)), G2 = V.mul(5n, G);
    const P = P256(), PC = { p: P.p, a: P.a, b: P.b, n: P.n, h: 1n }, T = { p: 17n, a: 3n, b: 5n, n: 23n, h: 1n };
    return [
      [G, VC], [G2, VC], [null, VC], [pt(24, 0), VC], [pt(7, 8), VC], [pt(1, 42), VC], [pt(1, 43), VC], [{ x: G.x + 103n, y: G.y }, VC], [{ x: G.x, y: G.y - 103n }, VC],
      [pt(1, 3), T], [pt(3, 5), T], [P.G, PC], [{ x: P.G.x, y: P.G.y + 1n }, PC], [{ x: P.G.x + P.p, y: P.G.y }, PC],
    ];
  };
  const valRef = (Q, Cv) => {
    if (!Q) return false;
    const K = curve(Cv.p, Cv.a, Cv.b);
    return K.on(Q) && (Cv.h === 1n || K.mul(Cv.n, Q) === null);
  };
  ex({
    id: 'ecc-x-code-valid', chapter: 'ecc-ch-rules', title: 'Write point validation', level: 3, kind: 'code', fn: 'isValid', params: ['Q', 'C'],
    text: ['Write `isValid(Q, C)`: Q is a received point `{x, y}` of BigInts, or `null` for O; C is a curve `{p, a, b, n, h}` of BigInts, with n the prime order of the subgroup in use and h the cofactor. Return true only if Q may be used: not O, both coordinates in 0 … p − 1, on the curve, and, when h is not 1, in the subgroup (n·Q = O).', '`mod`, `inv`, `ecAdd` and `scalarMul(k, P, a, p)` are given. The tests use a curve over GF(103) with 124 = 4·31 points, a prime-order curve over GF(17), and P-256.'],
    prelude: MOD_SRC + '\n' + ADD_SOL + '\n' + DA_SOL,
    start: 'function isValid(Q, C) {\n  \n}\n',
    ref: valRef,
    get cases() { return valCases(); },
    hints: ['Check in order: null, the range of x and y, the curve equation, then the subgroup.', 'The equation test is mod(y² − (x³ + ax + b), p) === 0n. Do the range test separately: x + p satisfies the equation mod p.', VAL_SOL],
    solution: VAL_SOL,
    wrong: [
      'function isValid(Q, C) {\n  if (Q === null) return false;\n  const { p, a, b } = C;\n  return mod(Q.y * Q.y - (Q.x * Q.x * Q.x + a * Q.x + b), p) === 0n;\n}\n',
      'function isValid(Q, C) {\n  if (Q === null) return false;\n  const { p, a, b, n } = C;\n  if (mod(Q.y * Q.y - (Q.x * Q.x * Q.x + a * Q.x + b), p) !== 0n) return false;\n  return scalarMul(n, Q, a, p) === null;\n}\n',
      'function isValid(Q, C) {\n  const { p, a, b, n, h } = C;\n  if (Q === null) return true;\n  if (Q.x < 0n || Q.x >= p || Q.y < 0n || Q.y >= p) return false;\n  if (mod(Q.y * Q.y - (Q.x * Q.x * Q.x + a * Q.x + b), p) !== 0n) return false;\n  return h === 1n || scalarMul(n, Q, a, p) === null;\n}\n',
    ],
  });
  ex({
    id: 'ecc-x-twist', chapter: 'ecc-ch-rules', title: 'The size of the twist', level: 2, kind: 'number',
    text: ['A curve over GF(61) has #E = 60 points. Its quadratic twist has 2p + 2 − #E points. How many, and would you let an x-only ladder on this curve accept any u without a check?'],
    answer: 64,
    hints: ['Every x gives two points on the curve or two on the twist (or one on each when f(x) = 0); together they share 2p + 2 points.', '2·61 + 2 − 60.', '64 = 2⁶: every point of the twist has an order that is a power of 2, at most 64. An unchecked x-only ladder would leak the key a few bits at a time, so this curve needs the check on u (or should not be used).'],
    solution: '64', wrong: ['62', '60', '124'],
    whyNot: { 62: 'p + 1 is the average size; the twist has 2p + 2 − #E points.', 60: 'That is the curve itself.', 124: 'Subtract #E from 2p + 2.', '*': 'Compute 2p + 2 − #E.' },
  });
  ex({
    id: 'ecc-x-anomalous', chapter: 'ecc-ch-rules', title: 'Curves to reject', level: 2, kind: 'choice',
    text: ['Candidate curves over the same 256-bit prime p are described by their group orders. Which must be rejected, whatever else is true of them?'],
    options: ['#E = p: the trace t is 1', '#E = p + 1: the trace t is 0', '#E = n, a prime different from p and p + 1, with a large embedding degree', '#E = 8·L with L a 252-bit prime, a twist with a large prime factor, and protocols that handle the cofactor'],
    answer: [0, 1],
    whyNot: { 2: 'That is what a good prime-order curve looks like.', 3: 'That describes Curve25519: a cofactor is acceptable when it is small and handled.' },
    hints: ['The exercise on counting points found a curve with #E = p, and the last lesson showed why that is fatal.', 't = 0 curves have a small embedding degree: a pairing moves the logarithm into a finite field.', 'Reject #E = p (the anomalous lift solves the logarithm with no search) and #E = p + 1 (the pairing attack). Keep the prime-order curve and the handled-cofactor curve.'],
    solution: [0, 1], wrong: [[0], [1], [0, 1, 3]],
  });
  ex({
    id: 'ecc-x-cofactor', chapter: 'ecc-ch-rules', title: 'What clamping to a multiple of 8 does', level: 2, kind: 'choice',
    text: ['Curve25519 has 8·L points. X25519 clears the low three bits of every scalar. What does that protect against?'],
    options: ['Timing leaks in the ladder', 'A peer\'s point with a component of order 2, 4 or 8: multiplying by a multiple of 8 removes it, so no bits of the key leak through the small subgroup', 'Points that are not on the curve', 'Pollard\'s rho'],
    answer: 1,
    whyNot: { 0: 'That is the job of the fixed bit 254 and the masked swap.', 2: 'Off-curve u values land on the twist, which Curve25519 made safe; clamping is about the cofactor.', 3: 'Rho works in the large subgroup of order L; clamping does not change its cost.' },
    hints: ['8 = the cofactor h.', 'Any point is (part in the large subgroup) + (part of order dividing 8).', 'k·Q with 8 | k sends the small part to O, so a hostile point of small order gives O or nothing about k mod 8: the small-subgroup leak is closed.'],
    solution: 1, wrong: [0, 2, 3],
  });
  ex({
    id: 'ecc-x-choose', chapter: 'ecc-ch-rules', title: 'Choosing a curve for a device', level: 3, kind: 'choice',
    text: ['A small device will agree keys with any peer on the network. Its code works with x-coordinates only, accepts any 32-byte value as the peer\'s key, and has no point checks. It must be constant time. Which choice fits?'],
    options: ['P-256 with the same x-only code', 'secp256k1 with the same x-only code', 'X25519: Curve25519 with clamped scalars and its constant-time ladder', 'A new curve the device generates for itself, of prime order, at first boot'],
    answer: 2,
    whyNot: { 0: 'P-256\'s twist has the small factors 3·5·13·179 and then a 241-bit prime: unchecked x values on the twist leak part of the key and weaken the rest. This code would need the point checks.', 1: 'secp256k1\'s twist has the small factors 3²·13²·3319·22639 and then only a 220-bit prime, so unchecked x-only input leaks part of the key. The code would need validation.', 3: 'A new curve gets none of the scrutiny a standard curve has had, the peer cannot know it is safe, and generating one correctly (counting, twist, embedding degree) is easy to get wrong.' },
    hints: ['Which curve was designed so that every 32-byte input is safe?', 'Twist security plus clamping to the cofactor means no input needs a check beyond an all-zero result.', 'X25519. Curve25519\'s twist has a 253-bit prime factor, the clamped scalar handles the cofactor, and the ladder is constant time with a fixed 255 steps.'],
    solution: 2, wrong: [0, 1, 3],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
