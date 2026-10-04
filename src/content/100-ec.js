// Part 10, elliptic curves: the chapters and the lessons. The exercises are in 101-ec-ex.js; the tour, the course and
// the pages the diagram checker looks at in 102-ec-tour.js. The unit is defensive: the group law and scalar
// multiplication are built by hand, and the attacks on the logarithm and on careless code are shown only as the
// reasons for the rules a curve and its code must follow (a prime-order group, cofactor handling, point validation,
// twist security, curves chosen in the open). Every value quoted was read off the topics' own narration for the
// inputs given, or worked out by S.ECC and S.EC.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('ecc-real')) return;
  const X = (id) => ({ exercise: id });

  C.chapter({ id: 'ecc-ch-law', part: 'ecc', n: 1, title: 'The group of points', blurb: 'Chord and tangent over the reals, the same formulas modulo p, the point at infinity, the order of a point and how many points a curve has.' });
  C.chapter({ id: 'ecc-ch-scalar', part: 'ecc', n: 2, title: 'Scalar multiplication', blurb: 'k·P by double-and-add, by the Montgomery ladder that does the same work for every bit, and faster with signed digits and Jacobian coordinates.' });
  C.chapter({ id: 'ecc-ch-use', part: 'ecc', n: 3, title: 'Key exchange and encodings', blurb: 'Elliptic-curve Diffie–Hellman on a toy curve, on P-256 and as X25519; three shapes of one curve; points compressed to x and one bit.' });
  C.chapter({ id: 'ecc-ch-rules', part: 'ecc', n: 4, title: 'The rules for safe curves', blurb: 'Why the group must be large and of prime order, why every received point is validated, why the twist matters, and how to choose a curve.' });

  // =========================================================================================================
  // Chapter 1: the group of points
  // =========================================================================================================
  C.lesson({
    id: 'ecc-real', chapter: 'ecc-ch-law', title: 'Chord and tangent', minutes: 7,
    summary: 'The points of y² = x³ + ax + b form a group. A line through two points meets the curve in exactly one more, and mirroring that third point in the x-axis gives the sum. To double a point, use the tangent.',
    blocks: [
      'Take two points on a cubic curve and draw the straight line through them. A cubic cut by a line has three crossings, so a third point appears for free. Can that be turned into a way of adding points?',
      { def: 'Elliptic curve', text: 'the points (x, y) with y² = x³ + ax + b, where 4a³ + 27b² ≠ 0, together with one extra point O, the point at infinity.' },
      { topic: 'ec-real-shape', frame: 2, caption: 'y² = x³ − 4x + 2: the curve exists only where the cubic f(x) is not negative, and is symmetric about the x-axis, since y and −y have the same square. Here it has two pieces, an oval and a branch.' },
      { topic: 'ec-real-shape', frame: 5, caption: 'At a = −3 (b = 2) the number 4a³ + 27b² is exactly 0: the oval meets the branch at x = 1 and the curve crosses itself. No single tangent is defined there, which is why such singular curves are excluded.' },
      { predict: { q: 'For y² = x³ + x + 3, is 4a³ + 27b² positive, negative or zero, and how many pieces does the curve have?', options: ['247, positive: one piece', '−247, negative: two pieces', '0: singular', '31, positive: two pieces'], answer: 0, explain: '4·1³ + 27·3² = 4 + 243 = 247 > 0. The cubic has one real root, so the curve is one piece. The sign decides the shape; only zero is forbidden.' } },
      { h: 'Adding two points' },
      { topic: 'ec-real-add', frame: 2, caption: 'P = (−1.00, 2.24) and Q = (2.60, 3.03): the line through them has slope λ = 0.22 and meets the curve once more, at x₃ = λ² − x₁ − x₂ = −1.55.' },
      { topic: 'ec-real-add', frame: 3, caption: 'Mirror the third point: P + Q = (−1.55, −2.11). P, Q and −(P + Q) lie on one line, and the three add up to O.' },
      { topic: 'ec-real-add', frame: 5, caption: 'To double P, take the tangent at P, with slope λ = (3x₁² + a)/2y₁ = −0.22. It meets the curve once more at x₃ = λ² − 2x₁ = 2.05, so 2P = (2.05, −1.55).' },
      { math: 'P ≠ Q:  λ = (y₂ − y₁) / (x₂ − x₁)\nP = Q:  λ = (3x₁² + a) / (2y₁)\nx₃ = λ² − x₁ − x₂\ny₃ = λ(x₁ − x₃) − y₁' },
      'Every formula here uses only +, −, × and ÷. Nothing in them needs real numbers, and the next lesson runs them modulo a prime, where there are no rounding errors and no picture is needed. Notice too that b never appears: the formulas use a, and the point coordinates. That small fact returns in the last chapter.',
      { tip: 'P + (−P): the line is vertical and meets no third point. The sum is defined to be O, the identity, the point "at the top of every vertical line".' },
      { bench: 'curve', state: { tool: 'real', real: { a: -2, b: 2, mode: 'add', P: -1.6, Ps: -1, Q: 0.4, Qs: 1 } }, text: 'The curve explorer over the reals: click two points and watch the chord, the third point and its mirror.' },
      { h: 'Recap' },
      { list: ['An elliptic curve is y² = x³ + ax + b with 4a³ + 27b² ≠ 0, plus the point O.', 'P + Q: the line through P and Q meets the curve at a third point; its mirror image is the sum. 2P uses the tangent.', 'The formulas use a but never b, and only field operations, so they work in any field.'] },
      X('ecc-x-singular'),
    ],
  });

  C.lesson({
    id: 'ecc-gfp', chapter: 'ecc-ch-law', title: 'The same rule modulo p', minutes: 9,
    summary: 'Over GF(p) the curve is a cloud of points with no shape, but the chord-and-tangent formulas work unchanged: division becomes multiplication by an inverse mod p. The point at infinity closes the group, and −(x, y) is (x, p − y).',
    blocks: [
      'Cryptography cannot use real numbers: they need rounding, and rounding loses information. What happens to the curve if x and y are numbers modulo a prime?',
      { topic: 'ec-gfp-law', frame: 0, caption: 'y² ≡ x³ + 2x + 9 (mod 61): 59 points with no visible shape. They are still symmetric about the middle line y = 30.5, since y and 61 − y have the same square.' },
      { topic: 'ec-gfp-law', frame: 2, caption: 'P = (3, 15), Q = (5, 12): λ ≡ (12 − 15)·(5 − 3)⁻¹ ≡ 58·31 ≡ 29 (mod 61), since 2·31 = 62 ≡ 1. Division is multiplication by an inverse.' },
      { topic: 'ec-gfp-law', frame: 4, caption: 'x₃ ≡ 29² − 3 − 5 ≡ 40 and y₃ ≡ λ(x₁ − x₃) − y₁ ≡ 10: P + Q = (40, 10), and 10² ≡ 39 ≡ 40³ + 2·40 + 9 (mod 61). The result is on the curve.' },
      { predict: { q: 'On the same curve, P = (3, 15). What is −P?', options: ['(3, −15)', '(3, 46)', '(58, 15)', '(−3, 15)'], answer: 1, explain: 'The mirror image keeps x and replaces y by −y mod 61: 61 − 15 = 46. Writing −15 is the same number, but a coordinate is always reduced to 0 … p − 1.' } },
      { topic: 'ec-gfp-law', frame: 5, caption: 'Doubling: λ ≡ (3·3² + 2)·(2·15)⁻¹ ≡ 29·59 ≡ 3, and the same two formulas give 2P = (3, 46). Notice that 2P = −P here, so 3P = O.' },
      { h: 'The point at infinity' },
      { topic: 'ec-infinity', frame: 1, caption: 'P = (4, 9) and −P = (4, 52) lie on the vertical line x = 4, which meets the curve nowhere else. Their sum is the identity O.' },
      { topic: 'ec-infinity', frame: 3, caption: 'A point with y = 0 is its own mirror image: (7, 0) has 2P = O, order 2. There is one such point for each root of x³ + 2x + 9 mod 61, here exactly one.' },
      { topic: 'ec-infinity', frame: 4, caption: 'Counting the group counts O too: #E = 59 + 1 = 60. In projective coordinates O is the ordinary point (0 : 1 : 0).' },
      { warn: 'Code that adds points has three special cases: P or Q is O, Q = −P (the answer is O), and P = Q (use the tangent). A missing case gives a wrong answer or a division by zero, and a case handled by a branch can leak through time. Complete formulas, met in chapter 3, have no special cases.' },
      { bench: 'curve', state: { tool: 'field', field: { toy: 'gf17', P: null, Q: null, k: '5', alg: 'ltr', step: -1 } }, text: 'The curve explorer over GF(17): click two points of the cloud to add them, with λ, x₃ and y₃ shown.' },
      { h: 'Recap' },
      { list: ['Over GF(p) the formulas are the same; ÷ means × the inverse mod p.', '−(x, y) = (x, p − y); P + (−P) = O; P + O = P.', 'A point with y = 0 has order 2. #E counts the affine points plus O.'] },
      X('ecc-x-on-curve'), X('ecc-x-neg'), X('ecc-x-add'), X('ecc-x-dbl'), X('ecc-x-code-add'),
    ],
  });

  C.lesson({
    id: 'ecc-order', chapter: 'ecc-ch-law', title: 'The order of a point', minutes: 8,
    summary: 'Adding P to itself again and again eventually returns to O. The number of steps is the order of P, it divides the number of points (Lagrange), and the multiples of P form a subgroup. Cryptography works in a subgroup of large prime order.',
    blocks: [
      'Start at a point and keep adding it: P, 2P, 3P, … The group is finite, so the walk must repeat. Where does it come back, and does it visit every point?',
      { topic: 'ec-order', frame: 3, caption: 'P = (17, 25) on the curve mod 61 with 60 points: 6P = (7, 0) lies on the axis, and 7P = (28, 39). The jumps show no pattern; from 7P alone nothing reveals the 7.' },
      { topic: 'ec-order', frame: 6, caption: '11P = (17, 36) is the mirror image of P, so 12P = O. P has order 12 and generates a subgroup of 12 points.' },
      { def: 'Order of a point', text: 'ord(P), the smallest n ≥ 1 with n·P = O. The multiples O, P, 2P, …, (n − 1)P are all different and form a subgroup.' },
      { topic: 'ec-order', frame: 7, caption: 'Lagrange\'s theorem: the order of any point divides #E = 60, and 12 does. So an order can be found by testing (60/q)·P for each prime q dividing 60, without walking all the way.' },
      { predict: { q: 'A curve has #E = 60 and P is a point with 30P ≠ O, 20P ≠ O and 12P = O. Which orders are still possible?', options: ['Only 12', '1, 2, 3, 4, 6 or 12', 'Any divisor of 60', '12 or 60'], answer: 1, explain: '12P = O means the order divides 12. To pin it down, test 6P and 4P (12/2 and 12/3): if both differ from O, the order is exactly 12. That is the method of the exercise on orders.' } },
      { topic: 'ec-order', frame: 8, caption: 'Coloured by order: 16 of the 60 points have order 60, and each of those generates the whole group.' },
      { topic: 'ec-order', input: { p: 17, a: 6, b: 3, P: '8, 6' }, frame: 10, caption: 'Not every group is cyclic: y² = x³ + 6x + 3 over GF(17) has 16 points but no point of order 16. It is Z₈ × Z₂, with P₁ = (8, 6) of order 8 and P₂ = (6, 0) of order 2.' },
      { h: 'Why a prime order' },
      'If n = #E is prime, Lagrange leaves only the orders 1 and n: every point but O generates the whole group, and there are no small subgroups to hide in. When #E is not prime, standards write #E = h·n with n a large prime, use a base point G of order n, and call h the cofactor. P-256 has h = 1; Curve25519 has h = 8. Chapter 4 shows what goes wrong when the small factor h is forgotten.',
      { h: 'Recap' },
      { list: ['ord(P) is the least n with n·P = O, and it divides #E.', 'Find it by testing (#E/q)·P for the primes q dividing #E.', 'Systems use a base point G of large prime order n; #E = h·n with a small cofactor h.'] },
      X('ecc-x-walk'), X('ecc-x-order'), X('ecc-x-lagrange'),
    ],
  });

  C.lesson({
    id: 'ecc-count', chapter: 'ecc-ch-law', title: 'How many points: Hasse\'s bound', minutes: 7,
    summary: 'Each x gives two points when x³ + ax + b is a nonzero square mod p, one when it is 0 and none otherwise. About half the values are squares, so #E is close to p + 1, and Hasse\'s theorem bounds the distance: |#E − (p + 1)| ≤ 2√p.',
    blocks: [
      'A designer needs a curve whose group has a large prime order. Before searching, how large can the group be at all, for a given p?',
      { topic: 'ec-hasse', frame: 0, caption: 'y² = x³ + 4x + 6 over GF(31): at x = 3, f(x) ≡ 14 and 14¹⁵ ≡ 1 (mod 31), so 14 is a square (Euler\'s criterion) and x = 3 gives two points.' },
      { topic: 'ec-hasse', frame: 1, caption: 'All 31 values of x: 13 give a nonzero square (two points each), 1 gives 0 (one point), 17 give none. With O, #E = 1 + 1 + 2·13 = 28.' },
      { math: '#E = 1 + #{x : f(x) = 0} + 2·#{x : f(x) a nonzero square}\nHasse:  p + 1 − 2√p  ≤  #E  ≤  p + 1 + 2√p\ntrace   t = p + 1 − #E,   |t| ≤ 2√p' },
      { predict: { q: 'For p = 31, 2√31 ≈ 11.14. Which group sizes does Hasse allow?', options: ['From 21 to 43', 'From 20 to 44', 'From 1 to 62', 'Exactly 32'], answer: 0, explain: '32 − 11.14 = 20.86 and 32 + 11.14 = 43.14, so the whole numbers 21 to 43. #E = 28 is inside, with t = 4.' } },
      { topic: 'ec-hasse', frame: 3, caption: 'The same equation over every prime up to 101: each dot is one curve\'s trace t, and every dot lies between the dashed lines ±2√p.' },
      { topic: 'ec-hasse', frame: 4, caption: 'At real size the count comes from Schoof\'s algorithm and its successors. For P-256, #E = n is prime and agrees with p in its top half: t has 127 bits while 2√p has 129.' },
      'For a designer this means two things. First, a 256-bit field gives a group of about 2²⁵⁶ points, never much more or less. Second, the count must be computed and checked, not assumed: a count of exactly p, or exactly p + 1, is a warning sign that chapter 4 explains.',
      { h: 'Recap' },
      { list: ['Count by going through every x and asking whether f(x) is a square.', '#E lies within 2√p of p + 1, so a k-bit field gives a group of about 2^k points.', 'The trace t = p + 1 − #E is small; t = 1 (#E = p) and t = 0 (#E = p + 1) are curves to reject.'] },
      X('ecc-x-count'), X('ecc-x-hasse'), X('ecc-x-hasse-which'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: scalar multiplication
  // =========================================================================================================
  C.lesson({
    id: 'ecc-dbladd', chapter: 'ecc-ch-scalar', title: 'Double-and-add', minutes: 8,
    summary: 'k·P for a 256-bit k cannot be done by adding P k times. Reading k in binary from the top bit, double the running point for every bit and add P for every 1: about 1.5 group operations per bit.',
    blocks: [
      'A public key is Q = d·G with a secret d of about 256 bits. Adding G to itself d − 1 times would outlast the universe. How does a phone compute it in a millisecond?',
      { topic: 'ec-double-add', frame: 0, caption: 'k = 77 = 1001101₂ on y² = x³ + 6x + 14 over GF(101). Start from the top bit with R = O; each bit doubles R, and a 1 bit then adds P.' },
      { topic: 'ec-double-add', frame: 4, caption: 'After bit 3: R = 9·P = (65, 39). The multiple in R is always the number written by the bits read so far: 1, 10, 100, 1001.' },
      { topic: 'ec-double-add', frame: 8, caption: 'Done: 77·P = (72, 14) after 6 doublings and 3 additions. Adding P 77 times would take 76 additions.' },
      { math: 'R ← O\nfor each bit b of k, from the top:\n    R ← 2R\n    if b = 1:  R ← R + P\nreturn R' },
      { predict: { q: 'k has 256 bits, the top bit is 1, and 128 of its bits are 1. How many doublings and additions does double-and-add do?', options: ['256 and 128', '255 and 127', '128 and 128', '255 and 255'], answer: 1, explain: 'The top bit only sets R = P, so 255 doublings follow; each 1 bit after the top adds P once, 127 times. About 1.5 operations per bit.' } },
      { topic: 'ec-double-add', input: { curve: 'P-256', k: '0x31801b1230f5ffab374a7a0a4b38d1837a0974b0489490e3dfef8e69d8898cd2', dir: 'ltr' }, frame: 15, caption: 'At real size, on P-256: a 254-bit k with 122 ones takes 253 doublings and 121 additions.' },
      { warn: 'The `if` in the loop is a branch on a secret bit. Its timing and its power trace show a doubling followed by an addition exactly where k has a 1: the sequence of operations spells out the key. The next lesson removes it.' },
      { h: 'Recap' },
      { list: ['Double for every bit, add for every 1: n − 1 doublings and (ones − 1) additions for an n-bit k.', 'The running point always holds (the bits read so far)·P.', 'The plain loop branches on secret bits; it is for public scalars, or for learning.'] },
      X('ecc-x-dbladd-table'), X('ecc-x-dbladd-count'), X('ecc-x-code-dbladd'),
    ],
  });

  C.lesson({
    id: 'ecc-ladder', chapter: 'ecc-ch-scalar', title: 'The Montgomery ladder', minutes: 8,
    summary: 'The ladder keeps two points, R₀ = m·P and R₁ = (m + 1)·P, and for every bit does exactly one addition and one doubling. Which register gets which result depends on the bit, and a conditional swap with masks makes even that choice invisible.',
    blocks: [
      'Double-and-add does more work for a 1 bit than for a 0 bit. Can the work per bit be made the same, without wasted dummy operations that a fault could expose?',
      { topic: 'ec-ladder', frame: 0, caption: 'R₀ = O and R₁ = P: two registers that always differ by exactly P. k = 77 again, 7 bits.' },
      { topic: 'ec-ladder', frame: 2, caption: 'Bit 5 is 0: R₁ ← R₀ + R₁ and R₀ ← 2R₀, taking the multiples from 1 and 2 to 2 and 3. For a 1 bit the roles swap. Either way, one addition and one doubling.' },
      { math: 'R₀ ← O,  R₁ ← P\nfor each bit b of k, from the top:\n    b = 0:  R₁ ← R₀ + R₁,  R₀ ← 2R₀\n    b = 1:  R₀ ← R₀ + R₁,  R₁ ← 2R₁\ninvariant:  R₁ − R₀ = P\nreturn R₀' },
      { predict: { q: 'Before a bit, R₀ = 9·P and R₁ = 10·P. The bit is 1. What do the registers hold after it?', options: ['18·P and 19·P', '19·P and 20·P', '18·P and 20·P', '10·P and 20·P'], answer: 1, explain: 'R₀ ← R₀ + R₁ = 19·P and R₁ ← 2R₁ = 20·P: the multiple m becomes 2m + 1, the invariant R₁ − R₀ = P holds. For a 0 bit it would become 18·P and 19·P.' } },
      { topic: 'ec-ladder', frame: 8, caption: 'Done: 77·P = (72, 14), after 7 additions and 7 doublings. Double-and-add did 6 doublings and 3 additions in an order that spells out the bits; the ladder\'s rhythm is the same for every k.' },
      { h: 'Making the choice invisible' },
      'The ladder still chooses which register to double. Real code does not branch on the bit: it swaps the two registers with a mask before the step and swaps back after, so the same instructions run for both values of the bit.',
      { code: '// constant-time conditional swap of two field elements (as 32-bit words), bit is 0 or 1\nfunction cswap(bit, a, b) {\n  const m = -bit;                 // 0x00000000 or 0xffffffff\n  for (let i = 0; i < a.length; i++) {\n    const t = m & (a[i] ^ b[i]);\n    a[i] ^= t; b[i] ^= t;\n  }\n}' },
      { topic: 'ec-x25519', frame: 2, caption: 'X25519 at real size: every one of its 255 steps is a masked conditional swap, one differential addition and one x-only doubling, 5 multiplications and 4 squarings whatever the bit.' },
      { topic: 'ec-x25519', frame: 10, caption: 'The whole ladder cost 1275 multiplications and 1020 squarings, the same for every secret: the time says nothing about the key.' },
      { tip: 'Constant time also needs constant length. X25519 sets bit 254 of every scalar, so every ladder has exactly 255 steps; with a leading zero bit skipped, a short key would finish early.' },
      { h: 'Recap' },
      { list: ['Two registers, one addition and one doubling per bit, R₁ − R₀ = P throughout.', 'The bit only decides which register receives which result: swap with masks, not with a branch.', 'Fixed length, fixed work, no dummy operations: the standard shape for secret scalars.'] },
      X('ecc-x-ladder-table'), X('ecc-x-leak'), X('ecc-x-x25519-cost'),
    ],
  });

  C.lesson({
    id: 'ecc-fast', chapter: 'ecc-ch-scalar', title: 'Fewer operations: signed digits and Jacobian coordinates', minutes: 8,
    summary: 'Subtracting a point costs the same as adding one, so k can be rewritten with digits −1, 0 and 1 (or wider odd digits) and fewer nonzero digits. And every affine addition needs an inversion; Jacobian coordinates postpone all of them to one at the end.',
    blocks: [
      'Double-and-add pays one addition per 1 bit. A run of ones such as 0111 1111 costs seven additions, yet 0111 1111 = 1000 0000 − 1. Can negative digits save work?',
      { def: 'NAF (non-adjacent form)', text: 'a way of writing k with digits in {−1, 0, 1} in which no two adjacent digits are nonzero. Every k has exactly one, and on average a third of its digits are nonzero, against half in binary.' },
      { topic: 'ec-wnaf', frame: 0, caption: 'A 254-bit k with 122 ones. The width-4 recoding takes odd digits from −7 to 7: subtracting the digit leaves k divisible by 16, so at least three zeros follow every nonzero digit.' },
      { topic: 'ec-wnaf', frame: 6, caption: 'The recoding has 49 nonzero digits against 122 ones. With a table of 4 odd multiples, k·P costs 2840 field multiplications and squarings instead of 3355; both give the same point.' },
      { predict: { q: 'Which is the NAF of 7 (binary 111), written from the top digit?', options: ['1 1 1', '1 0 0 −1', '1 0 −1 1', '1 −1 1 1'], answer: 1, explain: '8 − 1 = 7, and no two nonzero digits are adjacent. After the top digit, which only starts R, binary 111 needs two additions and the NAF 1 0 0 −1 one subtraction.' } },
      { h: 'Postponing the inversions' },
      'Each affine addition divides by x₂ − x₁, and an inversion mod a 256-bit prime costs as much as dozens of multiplications. Projective coordinates keep a denominator Z alongside the point and divide only once.',
      { topic: 'ec-jacobian', frame: 0, caption: 'Jacobian coordinates: (X : Y : Z) stands for (X/Z², Y/Z³), Z = 0 for O. Scaling by Z = 7 changes the numbers but not the point.' },
      { topic: 'ec-jacobian', frame: 1, caption: 'On P-256 a Jacobian doubling costs 3 multiplications and 5 squarings, a mixed addition 8M + 3S, and no inversion; one inversion, 255 squarings and 127 multiplications by Fermat, is paid at the end.' },
      { topic: 'ec-jacobian', frame: 2, caption: 'The same k by five methods: wNAF with w = 5 is cheapest at 1335M + 1457S; the Montgomery ladder costs 3798M + 2282S. In affine coordinates double-and-add would add 374 inversions.' },
      { warn: 'Speed and secrecy pull apart. A window method with a precomputed table must look up the table in constant time (read every entry and keep one with a mask), and the digits must not decide a branch. For secret scalars, prefer a constant-time ladder or a carefully written fixed window; for public scalars, as in signature verification, the fastest method is fine.' },
      { h: 'Recap' },
      { list: ['Signed digits: subtraction is as cheap as addition, so a NAF or wNAF has far fewer nonzero digits.', 'Jacobian (X : Y : Z): no inversion per operation, one at the end.', 'Fast methods for public scalars; constant-time ones for secret scalars.'] },
      X('ecc-x-naf'), X('ecc-x-jacobian'),
    ],
  });

  // =========================================================================================================
  // Chapter 3: key exchange and encodings
  // =========================================================================================================
  C.lesson({
    id: 'ecc-ecdh', chapter: 'ecc-ch-use', title: 'Elliptic-curve Diffie–Hellman', minutes: 9,
    summary: 'Alice publishes Q_A = d_A·G, Bob Q_B = d_B·G. Each multiplies the other\'s point by his or her own secret, and both reach S = d_A·d_B·G. The received point is validated first, and the shared x-coordinate goes through a KDF.',
    blocks: [
      'Diffie–Hellman in part 9 needed a 2048-bit prime for 112-bit security. On a curve the same agreement takes 256-bit numbers for 128-bit security. How does it go?',
      { topic: 'ec-ecdh', frame: 0, caption: 'Public: y² = x³ + 6x + 14 over GF(101) and G = (1, 18) of prime order n = 103.' },
      { topic: 'ec-ecdh', frame: 4, caption: 'Alice\'s d_A = 23 gives Q_A = (45, 2), Bob\'s d_B = 58 gives Q_B = (16, 41). Alice validates Q_B first, then both reach S = (90, 58), because d_A·(d_B·G) = d_B·(d_A·G).' },
      { predict: { q: 'Eve sees G, Q_A and Q_B. Which of these would let her compute S?', options: ['Adding Q_A and Q_B', 'Finding d_A from Q_A = d_A·G, a discrete logarithm', 'Doubling Q_A d_B times', 'Nothing, even with unlimited time'], answer: 1, explain: 'Q_A + Q_B = (d_A + d_B)·G, not d_A·d_B·G. To get S she needs one of the secrets, which means solving the elliptic-curve discrete logarithm problem. With unlimited time she can; the point of a 256-bit group is that no one has that time.' } },
      { topic: 'ec-ecdh', frame: 5, caption: 'The secret is the x-coordinate of S, 5a here. It is fed to a key-derivation function, since its bits are not uniformly random.' },
      { topic: 'ec-ecdh', input: { curve: 'P-256', dA: '0x85c7eab8b78be17f687e1f63feee94f0cf459048f362af9f7ff11b299b885042', dB: '0x5a03cd70d9172a652292588073f006ed0a3ea97c000667038a616378f79625c3' }, frame: 6, caption: 'On P-256 the best known attack on Q_A takes about √n ≈ 2¹²⁸ group operations.' },
      { h: 'X25519' },
      'X25519 is ECDH on Curve25519 in Montgomery form, using only x-coordinates (called u). A key is any 32 bytes; the scalar is clamped before use.',
      { topic: 'ec-x25519', frame: 0, caption: 'Clamping: byte 0 goes from 00101111 to 00101000 and byte 31 from 10000100 to 01000100. The scalar becomes a multiple of 8, which multiplies away any small-order part of a hostile point (the curve has 8·L points), and bit 254 is set, so every ladder takes the same 255 steps.' },
      { topic: 'ec-x25519', frame: 11, caption: 'Both sides reach the same 32 bytes. The only check X25519 needs is that the result is not all zero: its twist is safe too, so any 32 bytes may be accepted as u.' },
      { warn: 'ECDH alone does not say who is on the other side: a man in the middle can run one exchange with each party. Real protocols sign the exchange or bind it to certificates (part 13).' },
      { h: 'Recap' },
      { list: ['Q = d·G is public, d is secret; S = d_A·Q_B = d_B·Q_A.', 'Validate the received point (or use a curve and encoding where every input is safe), then hash the shared x with a KDF.', 'X25519: x-only, clamped scalars, a ladder of 255 steps, reject an all-zero result.'] },
      X('ecc-x-ecdh'), X('ecc-x-ecdh-why'), X('ecc-x-clamp'),
    ],
  });

  C.lesson({
    id: 'ecc-shapes', chapter: 'ecc-ch-use', title: 'Shapes and encodings', minutes: 8,
    summary: 'One group can be written as a Weierstrass, a Montgomery or a twisted Edwards curve; each suits a job. A point is sent as 04 ‖ x ‖ y or compressed to 02 or 03 ‖ x, and the receiver recovers y with a square root, rejecting any x with none.',
    blocks: [
      'P-256 is written y² = x³ + ax + b; Curve25519 is written By² = x³ + Ax² + x; Ed25519 uses yet another equation. Are these different groups?',
      { topic: 'ec-forms', frame: 0, caption: 'Over GF(127): the Montgomery curve 3v² = u³ + 4u² + u, the twisted Edwards curve with a = 2, d = 43 and the Weierstrass curve y² = x³ + 103x + 28 have the same 148 points, shuffled.' },
      { topic: 'ec-forms', frame: 2, caption: 'The Edwards addition is one formula with no special cases: since a = 2 is a square and d = 43 is not mod 127, its denominators are never zero. The same formula doubles, adds O and adds −P.' },
      { topic: 'ec-forms', frame: 4, caption: 'For all 21904 ordered pairs of points the sum agrees in all three forms. Curve25519 is used as a Montgomery curve for X25519 and as the Edwards curve Ed25519 for signatures.' },
      { table: [['Form', 'Equation', 'Good for'], ['Short Weierstrass', 'y² = x³ + ax + b', 'every curve has one; the form of the standards (P-256, secp256k1)'], ['Montgomery', 'By² = x³ + Ax² + x', 'the x-only ladder: key exchange (X25519)'], ['Twisted Edwards', 'ax² + y² = 1 + dx²y²', 'complete addition: signatures (Ed25519)']], caption: 'Complete formulas remove the branches that leak and the cases that are forgotten.' },
      { h: 'Sending a point' },
      { topic: 'ec-compress', frame: 1, caption: 'Q = 29·G = (85, 93) on the GF(101) curve. Of the two points with this x, Q has the odd y, so the compressed form is 03 ‖ x: 2 bytes instead of 3.' },
      { predict: { q: 'P-256 coordinates are 32 bytes each. How long is a compressed point?', options: ['32 bytes', '33 bytes', '64 bytes', '65 bytes'], answer: 1, explain: 'One prefix byte (02 or 03) and 32 bytes of x. Uncompressed it is 04 ‖ x ‖ y, 65 bytes.' } },
      { topic: 'ec-compress', frame: 2, caption: 'To decode, compute x³ + ax + b = 64 and its square root 8; the other root is 101 − 8 = 93, and the prefix 03 asks for the odd one.' },
      { topic: 'ec-compress', frame: 3, caption: 'For x = 88, x³ + ax + b = 62 has no square root mod 101: no point has this x. The decoder must reject it, never invent a y.' },
      { tip: 'For p ≡ 3 (mod 4) the square root of s is s^((p+1)/4) mod p, one exponentiation; check that its square really is s, which is the on-curve test for free. P-256 has p ≡ 3 (mod 4).' },
      { h: 'Recap' },
      { list: ['Weierstrass, Montgomery and Edwards forms can describe the same group; pick the shape for the job.', 'Uncompressed 04 ‖ x ‖ y; compressed 02/03 ‖ x, the prefix giving the parity of y.', 'Decoding takes a square root and must reject an x with none.'] },
      X('ecc-x-forms'), X('ecc-x-sizes'), X('ecc-x-encode'), X('ecc-x-decompress'),
    ],
  });

  // =========================================================================================================
  // Chapter 4: the rules for safe curves
  // =========================================================================================================
  C.lesson({
    id: 'ecc-size', chapter: 'ecc-ch-rules', title: 'A large group of prime order', minutes: 9,
    summary: 'Generic methods find a logarithm in about √n steps, so 128-bit security needs a group of about 2²⁵⁶ points. And if the order n splits into small factors, the logarithm splits with it: the base point must have large prime order.',
    blocks: [
      'Why are elliptic-curve keys 256 bits for "128-bit security", and why does every standard insist that the base point\'s order is prime? Both rules come from what a generic attacker can do, which is what a defender must size against.',
      { topic: 'ec-bsgs', frame: 6, caption: 'Baby-step giant-step on a group of order 1019 needs about 2√n = 64 operations and a table of √n points, against 1019 for trying every k. For a 256-bit n, √n is still 2¹²⁸.' },
      { topic: 'ec-rho', frame: 5, caption: 'Pollard\'s rho does the same √n work with almost no memory: about √(πn/2) ≈ 40 steps expected for n = 1019. This is the attack that sets key sizes.' },
      { math: 'generic cost ≈ √(πn/4) to √(πn/2) group operations\nsecurity level ≈ (bits of n) / 2\n128-bit security  ⇒  n ≈ 2²⁵⁶' },
      { predict: { q: 'A curve over a 384-bit field has a base point of prime order n ≈ 2³⁸⁴. Roughly what security level does it give?', options: ['384 bits', '192 bits', '128 bits', '96 bits'], answer: 1, explain: 'Rho needs about √n = 2¹⁹² operations. That is P-384\'s level. Compare RSA, where 192-bit security needs a modulus of about 7680 bits.' } },
      { h: 'Why prime' },
      { topic: 'ec-pohlig', frame: 9, caption: 'A base point of order n = 10206 = 2 · 3⁶ · 7: the logarithm splits into pieces modulo 2, 729 and 7, found digit by digit, and 18 small searches recover k = 5000 instead of up to 10206. The cost follows the largest prime factor of n, not n itself; with n prime there is nothing to split.' },
      'So the rule is not "n is large" but "the largest prime factor of n is large". The simplest way to meet it is a prime n. A curve with cofactor h, such as Curve25519 with h = 8, still works in the subgroup of prime order L and must keep received points out of the small subgroup of order dividing h, which is the next lesson.',
      { h: 'Recap' },
      { list: ['Generic attacks take about √n steps: n of 256 bits for 128-bit security.', 'The cost is set by the largest prime factor of n: use a base point of prime order.', 'With a cofactor, the protocol must deal with the small part (clamping, multiplying by h, or checking the subgroup).'] },
      X('ecc-x-security'), X('ecc-x-rho-size'), X('ecc-x-prime-order'),
    ],
  });

  C.lesson({
    id: 'ecc-validate', chapter: 'ecc-ch-rules', title: 'Validate every point you receive', minutes: 9,
    summary: 'The addition formulas never use b, so code fed a point that is not on its curve computes on another curve, perhaps of small order. Checking that a received point is on the curve, in range and in the right subgroup closes the hole; x-only code needs the point checked or a twist that is safe too.',
    blocks: [
      'ECDH multiplies a point the other side sent by a long-term secret. The other side is not always honest. What can a point that is not what it claims do?',
      'Picture a server with a fixed secret d that answers d·Q for any Q it is sent, on y² = x³ + 14x + 10 over GF(10007), a curve of prime order 10009. Its formulas use a = 14 but never b, so a point that is not on the curve is silently processed on some other curve y² = x³ + 14x + b′, and that curve may have points of small order.',
      { topic: 'ec-invalid', frame: 6, caption: 'Each point of small order on such another curve makes the answer reveal d modulo a small number; five answers together give all of d. No logarithm on the real curve was ever computed: the missing check did all the work.' },
      { topic: 'ec-invalid', frame: 7, caption: 'The defence is one check before any multiplication: is y² ≡ x³ + 14x + 10? Every point the attacker sent fails it. With a cofactor above 1, also check the subgroup.' },
      { h: 'The checks' },
      { steps: ['Q is not O.', '0 ≤ x < p and 0 ≤ y < p (reduced coordinates, so no two encodings name one point).', 'y² ≡ x³ + ax + b (mod p): Q is on this curve.', 'n·Q = O, when the cofactor h is not 1: Q lies in the subgroup of prime order n. With h = 1 every point on the curve passes this, and the test can be skipped.'] },
      { predict: { q: 'A received point satisfies the curve equation, but the curve has cofactor 4 and the point has order 2. What can go wrong if it is accepted?', options: ['Nothing: it is on the curve', 'd·Q reveals d mod 2, and the shared secret takes only 2 values', 'The program divides by zero', 'The point decodes to the wrong y'], answer: 1, explain: 'd·Q for a point of order 2 is Q or O depending on d mod 2: one bit of the key leaks, and the "shared" secret can be guessed. The subgroup check, or multiplying by the cofactor, removes it.' } },
      { h: 'x-only code and the twist' },
      { topic: 'ec-twist', frame: 0, caption: 'An x-only ladder accepts a number u, not a point. If u³ + 55u² + u is not a square, u belongs to the quadratic twist, here of 9880 = 2³·5·13·19 points: all small factors.' },
      { topic: 'ec-twist', frame: 6, caption: 'Two cures: check that u is on the curve, or choose a curve whose twist also has a large prime factor. Curve25519 took the second way: its twist has 4·L′ points with L′ a 253-bit prime.' },
      { tip: 'Compressed points are partly protected: decoding computes y from the right equation, so an off-curve point cannot be described. A subgroup check is still needed when h > 1.' },
      { h: 'Recap' },
      { list: ['Range, on-curve, not O, and (when h > 1) n·Q = O: before any secret touches the point.', 'A point skipped past these checks can leak the secret a few bits at a time.', 'x-only code: check u or use a twist-secure curve; X25519 clamps to a multiple of 8.'] },
      X('ecc-x-checks'), X('ecc-x-code-valid'), X('ecc-x-twist'),
    ],
  });

  C.lesson({
    id: 'ecc-choose', chapter: 'ecc-ch-rules', title: 'Choosing a curve', minutes: 8,
    summary: 'A good curve has a large prime-order subgroup, a small cofactor the protocol handles, a twist with a large prime factor, a trace that is not 0 or 1, fast reduction, complete or ladder-friendly formulas, and constants whose origin is explained.',
    blocks: [
      'A team must pick a curve for a new protocol. P-256, secp256k1 and Curve25519 all give about 128-bit security. What else should decide?',
      { topic: 'ec-curve-choice', frame: 0, caption: 'Both fields are about 256 bits. P-256\'s prime 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1 reduces fast in 32-bit pieces; Curve25519\'s 2²⁵⁵ − 19 reduces with a multiplication by 19.' },
      { topic: 'ec-curve-choice', frame: 1, caption: 'P-256 has cofactor 1. Curve25519 has 8·L points, so protocols handle the cofactor: X25519 clamps, Ed25519 multiplies by 8 when verifying.' },
      { topic: 'ec-curve-choice', frame: 2, caption: 'P-256\'s twist has order 3·5·13·179 times a 241-bit prime; Curve25519\'s has 2·2 times a 253-bit prime. Only the second lets x-only code skip the point check.' },
      { topic: 'ec-curve-choice', frame: 3, caption: 'Weierstrass addition has special cases; Edwards has one complete formula. Curve25519\'s A = 486662 is the smallest that meets a published list of conditions; P-256\'s b comes from hashing a seed whose origin was never explained.' },
      { h: 'Curves to reject outright' },
      { topic: 'ec-smart', frame: 0, caption: 'y² = x³ + 2x + 126 over GF(1013) has 1013 points, a prime: it looks ideal. But #E = p, trace 1: the curve is anomalous.' },
      { topic: 'ec-smart', frame: 4, caption: 'On an anomalous curve a p-adic lift turns the logarithm into a division mod p, with no search at all. The defence is one test when choosing a curve: #E ≠ p. Curves with t = 0 fall to the MOV pairing attack, so standards exclude those too.' },
      { predict: { q: 'A search finds a curve over a 256-bit prime p whose order is a prime n. Which extra test is still required?', options: ['None: a prime order is enough', 'n ≠ p (not anomalous), and the embedding degree is large (not t = 0 or a small pairing degree)', 'n must be smaller than p', 'n must be a safe prime'], answer: 1, explain: 'Prime order defeats Pohlig–Hellman, but #E = p falls to the lift, and a small embedding degree (t = 0 is the common case) moves the logarithm to a finite field where index calculus works. Standards test both.' } },
      { table: [['Requirement', 'What it rules out'], ['n prime and about 2²⁵⁶', 'rho, baby-step giant-step, Pohlig–Hellman'], ['#E ≠ p, large embedding degree', 'the anomalous lift, pairing (MOV) attacks'], ['cofactor small and handled', 'small-subgroup confinement'], ['twist with a large prime factor', 'twist attacks on x-only code'], ['complete formulas or a ladder', 'branches that leak, forgotten special cases'], ['explained constants', 'doubt about how the curve was chosen']], caption: 'A checklist: the first four are mathematics, the last two are engineering and trust.' },
      { topic: 'ec-curve-choice', frame: 4, caption: 'For the same 256-bit k: P-256 with a width-5 NAF takes 1392M + 1488S, the X25519 ladder 1275M + 1020S, constant time with no table. Both give about 128-bit security.' },
      { h: 'Recap' },
      { list: ['Use a standard, well-studied curve: P-256, Curve25519/Ed25519, or their larger siblings.', 'For x-only key exchange that accepts any input, Curve25519 (X25519).', 'Never invent a curve: the checks above are easy to miss and impossible to see from outside.'] },
      X('ecc-x-anomalous'), X('ecc-x-cofactor'), X('ecc-x-choose'),
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
