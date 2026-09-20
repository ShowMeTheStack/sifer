// Part 2, modular arithmetic, number theory and finite fields: the chapters and the lessons. The exercises are in
// 021-numbers-ex.js and the CTF challenges in 022-numbers-ctf.js; the tour and the course are at the end of the
// challenges file, since they lead to all three. Each lesson opens with a question, runs the topic that animates the
// idea at a frame chosen for the point being made, asks for a prediction, sums up, and leads to its exercises. Every
// number here is our own and was worked out by the engines (S.NT, S.GF).
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('num-clock')) return;
  const X = (id) => ({ exercise: id });

  C.chapter({ id: 'num-mod', part: 'numbers', n: 1, title: 'Modular arithmetic and Euclid', blurb: 'Arithmetic on a clock, the ring Z_n and who in it has an inverse, and the algorithm that finds gcds and inverses at any size.' });
  C.chapter({ id: 'num-euler', part: 'numbers', n: 2, title: 'Euler, Fermat and primes', blurb: 'Counting units with φ, powers that go round in cycles, the theorems behind RSA, and how to test a 300-digit number for primality.' });
  C.chapter({ id: 'num-groups', part: 'numbers', n: 3, title: 'Groups and the Chinese remainder theorem', blurb: 'Orders, generators and Lagrange\'s theorem, and two clocks that together name every number below their product.' });
  C.chapter({ id: 'num-fields', part: 'numbers', n: 4, title: 'Finite fields', blurb: 'GF(p), polynomials over GF(2), and GF(2⁸), the field of bytes that AES computes in.' });

  // =========================================================================================================
  // Chapter 1: modular arithmetic and Euclid
  // =========================================================================================================
  C.lesson({
    id: 'num-clock', chapter: 'num-mod', title: 'Arithmetic on a clock', minutes: 6,
    summary: 'a mod n is the remainder of a on division by n, always between 0 and n − 1. Two numbers are congruent modulo n when they leave the same remainder, and sums and products can be reduced at every step.',
    blocks: [
      'A night shift starts at 9 o\'clock and lasts 17 hours. Where is the hour hand when it ends? Nobody adds 9 + 17 = 26 and looks for 26 on the dial: you go round once and land on 2. That is arithmetic **modulo 12**, and it is the arithmetic of almost all public-key cryptography, with moduli of 600 digits instead of 12.',
      { def: 'a mod n', text: 'the remainder r when a is divided by n: a = q·n + r with 0 ≤ r < n. The remainder is never negative, even when a is.' },
      { topic: 'mod-clock', frame: 1, caption: '17 steps on a 12-hour clock: one whole lap and 5 more. The lap brings the hand back where it was, so only the 5 extra steps matter.' },
      { topic: 'mod-clock', frame: 7, caption: 'The hand stops at 2: 9 + 17 = 26 = 2·12 + 2, so 26 mod 12 = 2. Try a negative turn with the preset "Backwards".' },
      { predict: { q: 'What is −23 mod 10?', options: ['−3', '3', '7', '13'], answer: 2, explain: '−23 = −3·10 + 7, and the remainder must lie between 0 and 9, so it is 7. Turning the clock 23 steps backwards from 0 lands on 7.' } },
      { warn: 'JavaScript\'s `%` keeps the sign of the left side: `-23 % 10` is `-3`, not 7. Code that works modulo n writes `((a % n) + n) % n`, or uses BigInt and corrects the sign the same way.' },
      { h: 'Congruence' },
      { def: 'a ≡ b (mod n)', text: 'a and b are congruent modulo n: they leave the same remainder, which is the same as saying n divides a − b.' },
      'So 26 ≡ 2 ≡ 14 ≡ −10 (mod 12). Each number belongs to exactly one of n **congruence classes**, and modulo n we may swap any number for another one in its class.',
      { topic: 'mod-classes', frame: 3, caption: 'Cut the number line every 5 and stack the pieces: each column is a class. 13 sits in column 3, with −2, 3, 8 and every other 3 + 5k.' },
      { topic: 'mod-classes', frame: 5, caption: 'Any member of a class will do. 13 + 7 and 8 + 12 both land in [0]; 13·7 and 8·12 both land in [1]. That is why the arithmetic can work with the remainders alone.' },
      { h: 'Reduce early, reduce often' },
      'Because any member of a class will do, you may reduce in the middle of a calculation, not only at the end. To find 123·456 mod 7, reduce first: 123 ≡ 4 and 456 ≡ 1, so the product is ≡ 4·1 = 4. The long way agrees: 123·456 = 56088 = 8012·7 + 4.',
      'This is what keeps public-key arithmetic possible. A 2048-bit RSA computation multiplies two numbers below n and reduces at once, so no intermediate value ever has more than 4096 bits, even when the exponent has 2048 bits.',
      { h: 'Recap' },
      { list: ['a mod n is the remainder in 0 … n − 1; for a negative a, add n until it is in range.', 'a ≡ b (mod n) means n divides a − b: they are in the same class.', 'Sums, differences and products may be reduced at every step without changing the answer.'] },
      X('num-x-reduce'), X('num-x-congruent'),
    ],
  });

  C.lesson({
    id: 'num-ring', chapter: 'num-mod', title: 'The ring Z_n: who has an inverse', minutes: 8,
    summary: 'Z_n is the numbers 0 to n − 1 with + and · modulo n. An element a has an inverse, a number x with a·x ≡ 1, exactly when gcd(a, n) = 1; the others are zero divisors, and multiplying by them loses information.',
    blocks: [
      'Division undoes multiplication. Modulo 10, multiplying by 3 can be undone: multiply by 7, since 3·7 = 21 ≡ 1. Multiplying by 4 cannot: 4·1 = 4 and 4·6 = 24 ≡ 4, so after multiplying by 4 you cannot tell whether you started from 1 or from 6. Which multipliers can be undone, and how do you find the undoing number?',
      { def: 'Z_n', text: 'the set {0, 1, …, n − 1} with addition and multiplication modulo n. It is a ring: both operations behave as usual, but division is not always possible.' },
      { topic: 'zn-ring', frame: 3, caption: 'The multiplication table of Z_10, row 3: every element appears exactly once, so 1 appears too, in column 7. 3 is a unit with inverse 7.' },
      { topic: 'zn-ring', input: { n: 10, a: 4 }, frame: 3, caption: 'Row 4 holds only the even numbers, the multiples of gcd(4, 10) = 2, each twice. It never reaches 1 and it hits 0 at column 5: 4 is a zero divisor.' },
      { def: 'Unit', text: 'an a with an inverse a⁻¹, the x with a·x ≡ 1 (mod n). a is a unit exactly when gcd(a, n) = 1; then the inverse is unique modulo n.' },
      { predict: { q: 'Which of these has an inverse modulo 12?', options: ['4', '6', '9', '11'], answer: 3, explain: '4, 6 and 9 share a factor with 12. 11 does not, and indeed 11·11 = 121 = 10·12 + 1, so 11 is its own inverse.' } },
      { h: 'Finding an inverse by hopping' },
      { topic: 'mod-inverse', frame: 7, caption: 'Looking for 5⁻¹ modulo 17: hop round the clock 5 steps at a time. The seventh hop lands on 1, since 5·7 = 35 = 2·17 + 1.' },
      'Hopping takes up to n − 1 hops, hopeless for a modulus of 600 digits. The extended Euclidean algorithm, two lessons on, finds the same inverse in a few hundred divisions.',
      { topic: 'mod-inverse', input: { a: 9, n: 26 }, frame: 4, caption: 'The affine cipher of part 1 multiplies letters by a key modulo 26. Key 9 is undone by 3, since 9·3 = 27 ≡ 1 (mod 26). A key such as 13 shares a factor with 26 and could never be undone.' },
      { h: 'When n is prime' },
      'If n is a prime p, every number from 1 to p − 1 shares no factor with p, so every nonzero element is a unit. Then Z_p is a **field**: you can add, subtract, multiply and divide by anything but 0. Chapter 4 builds on that.',
      { tip: 'A congruence a·x ≡ b (mod n) is solved by multiplying by a⁻¹ when a is a unit. When g = gcd(a, n) > 1, it has a solution only if g divides b, and then it has g solutions modulo n.' },
      { h: 'Recap' },
      { list: ['Z_n: the remainders 0 … n − 1, added and multiplied modulo n.', 'a has an inverse modulo n exactly when gcd(a, n) = 1. The units are counted by Euler\'s φ(n).', 'Every other nonzero element is a zero divisor: multiplying by it cannot be undone.', 'Z_p is a field when p is prime.'] },
      X('num-x-units'), X('num-x-inv-small'), X('num-x-solve-lin'),
    ],
  });

  C.lesson({
    id: 'num-euclid', chapter: 'num-mod', title: 'Euclid\'s algorithm', minutes: 7,
    summary: 'gcd(a, b) = gcd(b, a mod b): replace the pair by the smaller number and the remainder until the remainder is 0. The number of divisions grows with the number of digits, so it is fast for numbers of any size.',
    blocks: [
      'What is the greatest common divisor of 2024 and 748? You could factor both. That works for numbers of four digits, but nobody can factor a 617-digit RSA modulus. Yet the gcd of two such moduli can be found in a millisecond, and if they happen to share a prime, that prime falls out. The method is more than two thousand years old.',
      { math: 'gcd(a, b) = gcd(b, a mod b)\ngcd(a, 0) = a' },
      'Why does the first line hold? Write a = q·b + r. Any number that divides a and b also divides r = a − q·b, and any number that divides b and r also divides a. So the pairs (a, b) and (b, r) have exactly the same common divisors, and the same greatest one.',
      { topic: 'euclid', frame: 1, caption: 'The first division: 2024 = 2·748 + 528. In the rectangle, two squares of side 748 fit, and a 528 by 748 strip is left over.' },
      { topic: 'euclid', frame: 6, caption: 'Five divisions later the remainder is 0, and the last divisor, 44, is the gcd. Squares of side 44 would tile the whole 2024 by 748 rectangle.' },
      { predict: { q: '6765 and 4181 are consecutive Fibonacci numbers. How many divisions does Euclid need for them?', options: ['2', '5', '18', '4181'], answer: 2, explain: 'Each quotient is 1 (except the last), so each step only steps one Fibonacci number down: 6765 = 1·4181 + 2584, 4181 = 1·2584 + 1597, and so on, 18 divisions in all. Consecutive Fibonacci numbers are the slowest pairs of their size.' } },
      { topic: 'euclid', input: { a: '6765', b: '4181' }, frame: 9, caption: 'The worst case: quotient 1 at almost every step, so the rectangle is cut one square at a time.' },
      'Even the worst case is fast. The number of divisions is at most about 2.08·ln(b) + 2, where b is the smaller number, so it grows with the number of digits, not with the size: two 600-digit numbers need fewer than 2,900 divisions.',
      { h: 'Why an attacker cares' },
      'Two RSA moduli made by a faulty random number generator may share a prime. Take n₁ = 1009·1013 = 1022117 and n₂ = 1009·1019 = 1028171. Each alone is hard to factor at real sizes, but gcd(n₁, n₂) = 1009, and dividing gives the other two primes at once. Scans of millions of public keys on the internet have found real keys broken exactly this way; part 8 runs the [batch version](#topic=p08-batch-gcd).',
      { bench: 'nt', state: { tool: 'euclid', euclid: { a: '1028171', b: '1022117' } }, text: 'Run Euclid on the two moduli that share a prime.' },
      { h: 'Recap' },
      { list: ['gcd(a, b) = gcd(b, a mod b), repeated until the remainder is 0; the last divisor is the gcd.', 'The number of divisions grows with the number of digits: fast for any size.', 'Consecutive Fibonacci numbers are the slowest case.', 'gcd of two moduli exposes a shared prime.'] },
      X('num-x-gcd'), X('num-x-code-gcd'),
    ],
  });

  C.lesson({
    id: 'num-egcd', chapter: 'num-mod', title: 'Extended Euclid and inverses at any size', minutes: 9,
    summary: 'Carry two coefficients s and t along with every remainder, so that each row keeps r = a·s + b·t. On the row where r is the gcd, s and t are Bézout\'s coefficients, and when the gcd is 1, t is the inverse of b modulo a.',
    blocks: [
      'Euclid says gcd(360, 77) = 1, so 77 has an inverse modulo 360. But which number is it? The remainders alone do not say. The trick is to keep a record of how each remainder was made out of a and b.',
      { math: 'row 0:  r = a,  s = 1,  t = 0\nrow 1:  r = b,  s = 0,  t = 1\nrow i:  q = r(i−2) div r(i−1),  row i = row (i−2) − q·row (i−1)\nevery row:  r = a·s + b·t' },
      'The first two rows say a = a·1 + b·0 and b = a·0 + b·1. Subtracting q times one true equation from another gives a true equation, so every row stays true, and the r column is exactly the sequence of remainders of plain Euclid.',
      { topic: 'egcd', frame: 4, caption: 'Row 5 reaches r = 1 with s = −37 and t = 173: 360·(−37) + 77·173 = −13320 + 13321 = 1.' },
      { topic: 'egcd', frame: 10, caption: 'The same equation by back-substitution, working up from the last division. The table did these substitutions as it went down, so it never needs the way back.' },
      { predict: { q: 'From 1 = 360·(−37) + 77·173, what is 360⁻¹ modulo 77?', options: ['−37 exactly, as it stands', '37', '40', '173'], answer: 2, explain: 'Read the equation modulo 77: the term 77·173 vanishes, so 360·(−37) ≡ 1. As a number between 0 and 76, −37 is −37 + 77 = 40.' } },
      { h: 'An RSA key in three rows' },
      'A toy RSA key: p = 89 and q = 97, so n = 8633 and (p − 1)(q − 1) = 88·96 = 8448. The public exponent is e = 17, and the private exponent d must satisfy 17·d ≡ 1 (mod 8448). That is an inverse, and extended Euclid finds it.',
      { topic: 'egcd', input: { a: '8448', b: '17' }, frame: 7, caption: 'Three rows: 8448·(−1) + 17·497 = 1, so d = 17⁻¹ ≡ 497 (mod 8448). Check: 17·497 = 8449 = 8448 + 1.' },
      'At real size nothing changes but the length of the numbers. With e = 65537 and a 2048-bit (p − 1)(q − 1), the first division already brings the pair below 65537, and the table ends after about a dozen rows. Two random 2048-bit numbers take about 1,200 rows, still well under a millisecond.',
      { sandbox: 'egcd' },
      { sandbox: 'mod-inverse' },
      { h: 'Recap' },
      { list: ['Each row keeps r = a·s + b·t; the next row is the row two up minus q times the row above.', 'On the last row with r ≠ 0, r is the gcd and s, t are Bézout\'s coefficients.', 'If the gcd is 1, t is b⁻¹ modulo a (bring it into 0 … a − 1 by adding a).', 'This is how an RSA private exponent is computed from e.'] },
      X('num-x-egcd-table'), X('num-x-rsa-d'), X('num-x-code-egcd'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: Euler, Fermat and primes
  // =========================================================================================================
  C.lesson({
    id: 'num-phi', chapter: 'num-euler', title: 'Euler\'s φ: counting the units', minutes: 7,
    summary: 'φ(n) counts the numbers from 1 to n that share no factor with n, which are the units of Z_n. From the factorisation, φ(n) = n·Π(1 − 1/p); for an RSA modulus n = p·q it is (p − 1)(q − 1), and knowing it is as good as knowing the factors.',
    blocks: [
      'How many of the numbers from 1 to 60 have an inverse modulo 60? You could test all sixty. A sieve does it faster, and the factorisation of 60 does it in one line.',
      { def: 'φ(n)', text: 'Euler\'s totient: the number of k with 1 ≤ k ≤ n and gcd(k, n) = 1, the number of units of Z_n.' },
      { topic: 'euler-phi', frame: 2, caption: '60 = 2²·3·5. Striking the multiples of 2 leaves 30 numbers; striking the multiples of 3 removes 10 more (the other 10 were even already), leaving 20.' },
      { topic: 'euler-phi', frame: 4, caption: 'After the multiples of 5, 16 numbers survive: φ(60) = 16. Each prime p keeps the fraction 1 − 1/p of what is left: 60·½·⅔·⅘ = 16.' },
      { math: 'φ(p) = p − 1 for a prime p\nφ(pᵏ) = pᵏ⁻¹·(p − 1)\nφ(m·n) = φ(m)·φ(n) when gcd(m, n) = 1' },
      { predict: { q: 'What is φ(77)?', options: ['60', '76', '70', '18'], answer: 0, explain: '77 = 7·11, so φ(77) = φ(7)·φ(11) = 6·10 = 60. Of the 77 numbers, the 11 multiples of 7 and the 7 multiples of 11 fall, with 77 itself counted in both: 77 − 11 − 7 + 1 = 60.' } },
      { topic: 'euler-phi', input: { n: 77 }, frame: 3, caption: 'φ(7·11) = 6·10 = 60. For two primes the count is always (p − 1)(q − 1).' },
      { h: 'φ of an RSA modulus' },
      'An RSA modulus is n = p·q, so φ(n) = (p − 1)(q − 1) = n − (p + q) + 1. The key holder computes it from p and q in one line; anyone else would have to factor n. And the reverse holds: whoever learns φ(n) learns p and q.',
      { steps: ['p + q = n − φ(n) + 1.', 'p and q are the two roots of z² − (p + q)·z + n = 0.', 'Solve with the square root of the discriminant (p + q)² − 4n, an exact integer square.'] },
      'For the toy key n = 8633, φ(n) = 8448: p + q = 8633 − 8448 + 1 = 186, the discriminant is 186² − 4·8633 = 34596 − 34532 = 64, and its root 8 gives p, q = (186 ∓ 8)/2 = 89 and 97.',
      { warn: 'So computing φ(n) for an RSA modulus is exactly as hard as factoring it. Leaking φ(n), or anything that gives it away such as d together with e, breaks the key.' },
      { h: 'Recap' },
      { list: ['φ(n) counts the units of Z_n.', 'φ(n) = n·Π(1 − 1/p) over the distinct primes p dividing n.', 'For n = p·q: φ(n) = (p − 1)(q − 1), and n with φ(n) gives back p and q.'] },
      X('num-x-phi'), X('num-x-phi-12'), X('num-x-factor-phi'),
    ],
  });

  C.lesson({
    id: 'num-powers', chapter: 'num-euler', title: 'Powers go round: Fermat, Euler and square-and-multiply', minutes: 9,
    summary: 'The powers of a unit modulo n come back to 1 and repeat. Euler\'s theorem says a^φ(n) ≡ 1, Fermat\'s little theorem is the prime case a^(p−1) ≡ 1, and square-and-multiply computes any power in a number of steps that grows with the bits of the exponent.',
    blocks: [
      'What is 7¹⁰⁰⁰ modulo 13? The number 7¹⁰⁰⁰ has 846 digits, and multiplying by 7 a thousand times is tedious even modulo 13. There is a better way, because powers modulo n cannot grow for ever: there are only n values for them to take.',
      { topic: 'power-cycles', frame: 9, caption: 'The powers of 3 modulo 17 visit all 16 nonzero values and come back to 1 at 3¹⁶. The cycle then repeats for ever: ord(3) = 16.' },
      { topic: 'power-cycles', input: { a: 2, n: 12 }, frame: 4, caption: '2 is not a unit modulo 12. Its powers run along a tail (2) into a cycle (4, 8, 4, 8, …) and never return to 1: a ρ shape.' },
      { h: 'Fermat and Euler' },
      { topic: 'fermat-euler', frame: 2, caption: 'Multiply each unit modulo 13 by 7: the products are the same twelve units in another order. Multiplying by a unit only reshuffles.' },
      { topic: 'fermat-euler', frame: 3, caption: 'So the product of all the units equals 7¹² times itself, and cancelling gives 7¹² ≡ 1 (mod 13). Nothing in the argument depends on 7.' },
      { math: 'Euler:  gcd(a, n) = 1  ⇒  a^φ(n) ≡ 1 (mod n)\nFermat: p prime, p ∤ a  ⇒  a^(p−1) ≡ 1 (mod p)\nhence a^e ≡ a^(e mod φ(n)) for a unit a' },
      { predict: { q: 'So what is 7¹⁰⁰⁰ mod 13?', options: ['1', '7', '9', '12'], answer: 2, explain: '1000 = 83·12 + 4, and every 7¹² is 1, so 7¹⁰⁰⁰ ≡ 7⁴ = 2401 = 184·13 + 9. The answer is 9.' } },
      'This is the heart of RSA. The exponents satisfy e·d = 1 + k·φ(n), so (mᵉ)ᵈ = m·(m^φ(n))ᵏ ≡ m·1ᵏ = m: decryption undoes encryption.',
      { h: 'Square-and-multiply' },
      'Reducing the exponent needs φ(n), which only the key holder knows. Everyone else computes the power directly, and does it fast by reading the exponent in binary: square once for every bit, and multiply by the base for every bit that is 1.',
      { topic: 'p08-sqm', frame: 13, caption: '7²⁹⁸⁹ mod 10403 in 11 squarings and 7 multiplications, instead of 2988 multiplications. Both directions, from the top bit and from the bottom bit, reach 8587.' },
      'A 2048-bit exponent costs about 2048 squarings and 1024 multiplications on average, which is why RSA is practical at all. The loop has a catch: it multiplies only on the 1 bits, so its timing and its power use can leak the exponent. [Simple power analysis](#topic=sc-spa) in part 15 reads a key out of exactly that.',
      { sandbox: 'square-multiply' },
      { h: 'Recap' },
      { list: ['Powers of a unit modulo n cycle back to 1; non-units run into a cycle that misses 1.', 'a^φ(n) ≡ 1 for a unit a (Euler); a^(p−1) ≡ 1 modulo a prime p (Fermat).', 'With φ(n) known, exponents can be reduced modulo φ(n); that is why RSA decrypts.', 'Square-and-multiply: one squaring per bit, one multiplication per 1 bit.'] },
      X('num-x-fermat-pow'), X('num-x-last-digits'), X('num-x-code-modpow'),
    ],
  });

  C.lesson({
    id: 'num-primes', chapter: 'num-euler', title: 'Is it prime? Fermat\'s test, its liars, and Miller–Rabin', minutes: 10,
    summary: 'Fermat\'s test calls n composite when a^(n−1) ≢ 1. Carmichael numbers pass it for every base coprime to them. Miller–Rabin also watches the square roots of 1 on the way, and no composite fools more than a quarter of its bases.',
    blocks: [
      'Making an RSA key needs two random primes of 1024 bits. Trial division by every number up to the square root would take around 2⁵¹² divisions. Instead, key generators pick random odd numbers and test them with a quick check that a prime always passes. The question is how often a composite passes too.',
      { h: 'Fermat\'s test' },
      'If n is prime, a^(n−1) ≡ 1 (mod n) for every a from 1 to n − 1. So pick a base a and compute a^(n−1) mod n by square-and-multiply. If the answer is not 1, n is certainly composite and a is a **witness**. If it is 1, n may be prime, or a may be a **liar**.',
      { topic: 'carmichael', input: { n: 341 }, frame: 5, caption: '341 = 11·31 fools base 2, but of the 300 bases coprime to it only 100 lie. A few random bases expose it.' },
      { predict: { q: '561 = 3·11·17. Of the 320 bases below 561 that share no factor with it, how many are Fermat witnesses?', options: ['about 160', 'none at all', 'exactly 1', 'all 320'], answer: 1, explain: 'Every one of them lies. Only bases that share a factor with 561 expose it, and finding one of those is as hard as finding a factor.' } },
      { topic: 'carmichael', frame: 5, caption: '561: 0 witnesses among the 320 coprime bases, 320 liars. Only the 240 bases that share a factor with 561 give anything other than 1.' },
      { topic: 'carmichael', frame: 6, caption: 'Korselt\'s criterion explains why: 561 is squarefree, and 2, 10 and 16 all divide 560. Composites like this are Carmichael numbers, and there are infinitely many of them.' },
      { h: 'Miller–Rabin: listen to the square roots of 1' },
      'Modulo a prime, the only square roots of 1 are 1 and −1: if x² ≡ 1 then p divides (x − 1)(x + 1), so it divides one factor. Miller–Rabin writes n − 1 = 2ˢ·d with d odd, computes x = a^d, and squares it s times, which ends at a^(n−1). For a prime that last value is 1 (Fermat), and the value before each 1 must be ±1, so the chain is 1 from the start or reaches −1 just before it turns into 1.',
      { topic: 'miller-rabin', input: { n: '561', bases: ['2', '7', '50'] }, frame: 4, caption: 'Base 2 on 561: 263, 166, 67, then 67² ≡ 1. So 67 is a square root of 1 that is neither 1 nor −1, impossible modulo a prime: 561 is composite.' },
      'The impossible square root does more than prove n composite. Since 67² − 1 = 66·68 is a multiple of 561 while neither 66 nor 68 is, each shares a factor with it: gcd(66, 561) = 33 and gcd(68, 561) = 17. Miller–Rabin caught 561 and very nearly factored it.',
      { tip: 'For an odd composite n, at most a quarter of the bases are strong liars. Forty random bases leave a chance of at most 4⁻⁴⁰ = 2⁻⁸⁰ that a composite passes all of them.' },
      { sandbox: 'miller-rabin' },
      { h: 'Recap' },
      { list: ['Fermat: a^(n−1) ≢ 1 proves n composite; = 1 proves nothing.', 'Carmichael numbers (561, 1105, 1729, …) fool Fermat for every coprime base.', 'Miller–Rabin also checks the chain a^d, a^(2d), …: a square root of 1 other than ±1 exposes n.', 'No composite fools more than a quarter of Miller–Rabin\'s bases.'] },
      X('num-x-fermat-liar'), X('num-x-carmichael'), X('num-x-mr-chain'), X('num-x-mr-witness'),
      { challenge: 'num-ctf-impostor' },
    ],
  });

  // =========================================================================================================
  // Chapter 3: groups and the Chinese remainder theorem
  // =========================================================================================================
  C.lesson({
    id: 'num-groups', chapter: 'num-groups', title: 'Order, generators and Lagrange', minutes: 8,
    summary: 'The order of a unit a is the smallest k with a^k ≡ 1. Every order divides the size of the group (Lagrange). A generator has the largest possible order, and is checked with one power per prime factor of the group size.',
    blocks: [
      'Diffie–Hellman publishes a prime p and a number g, and everyone raises g to secret powers. If the powers of g ran through only a handful of values, an eavesdropper could simply try them all. So which g are good, and how is that checked when p has 600 digits?',
      { def: 'Order', text: 'ord(a), the smallest k ≥ 1 with a^k ≡ 1 (mod n), for a unit a. The powers of a then repeat with period ord(a).' },
      { topic: 'group-order', frame: 7, caption: 'The powers of every unit modulo 13. The orders are 1, 2, 3, 4, 6 and 12, and each divides 12. The full rows, of 2, 6, 7 and 11, are the generators.' },
      { predict: { q: 'Can an element of Z_13* have order 5?', options: ['Yes, some element does', 'No: 5 does not divide 12', 'Only the element 5 itself'], answer: 1, explain: 'The powers of an element form a subgroup, and the size of a subgroup always divides the size of the group (Lagrange\'s theorem). Z_13* has 12 elements, and 5 does not divide 12.' } },
      { h: 'Lagrange\'s theorem' },
      { topic: 'lagrange', frame: 8, caption: 'Z_21* has 12 elements. H = ⟨4⟩ = {1, 4, 16}, and its cosets 2·H, 5·H and 10·H split the group into four blocks of three. Since the blocks never overlap, 3 divides 12.' },
      'The argument works for any subgroup: its cosets are all the same size and never overlap, so they cut the group into equal blocks. The size of the subgroup, and so the order of every element, divides the size of the group.',
      { h: 'Testing a generator' },
      'g generates Z_p* when ord(g) = p − 1. Writing out all the powers is impossible at real size, but Lagrange limits the possibilities: if ord(g) were smaller, it would divide (p − 1)/q for some prime q dividing p − 1. So it is enough to check that g^((p−1)/q) ≢ 1 for each such q.',
      { topic: 'group-order', frame: 10, caption: '12 = 2²·3, so two powers decide whether 6 generates Z_13*: 6⁶ ≡ 12 and 6⁴ ≡ 9. Neither is 1, so ord(6) = 12.' },
      { topic: 'group-order', input: { n: 15, g: 2 }, frame: 5, caption: 'Not every group of units has a generator: in Z_15* the largest order is 4, so no element reaches all 8 units.' },
      { tip: 'Real Diffie–Hellman groups are chosen so that p − 1 = 2q with q prime (a safe prime) and work in the subgroup of order q. A group whose size has only small prime factors can be broken one small factor at a time, the [Pohlig–Hellman attack](#topic=p09-pohlig) of part 9.' },
      { h: 'Recap' },
      { list: ['ord(a): the first k with a^k ≡ 1. The powers of a form a subgroup of that size.', 'Lagrange: the size of a subgroup divides the size of the group, so ord(a) divides φ(n).', 'g is a generator of Z_p* when g^((p−1)/q) ≢ 1 for every prime q dividing p − 1.'] },
      X('num-x-order'), X('num-x-generators'), X('num-x-lagrange'),
    ],
  });

  C.lesson({
    id: 'num-crt', chapter: 'num-groups', title: 'The Chinese remainder theorem', minutes: 9,
    summary: 'When m₁, …, m_k share no factors, each list of remainders belongs to exactly one x modulo their product M. The solution is built from one term per modulus, and RSA uses the same idea to decrypt about four times faster.',
    blocks: [
      'A number leaves remainder 3 on division by 5 and remainder 2 on division by 7. Which number is it, and is there only one? Think of two clocks, one with 5 positions and one with 7, turned together one step at a time.',
      { topic: 'crt-clocks', frame: 10, caption: 'Write each x in the cell (x mod 5, x mod 7). The diagonal wraps round and, because 5 and 7 share no factor, fills all 35 cells exactly once before both hands are back at 0.' },
      { topic: 'crt-clocks', frame: 11, caption: 'The cell in row 3, column 2 holds 23: 23 ≡ 3 (mod 5) and 23 ≡ 2 (mod 7). The solutions are 23, 58, 93, …, one in every 35.' },
      { predict: { q: 'Two clocks with 4 and 6 positions. Can their hands ever read 1 and 2 at the same time?', options: ['Yes, once every 24 steps', 'Yes, once every 12 steps', 'Never'], answer: 2, explain: 'x ≡ 1 (mod 4) makes x odd and x ≡ 2 (mod 6) makes it even. With a common factor 2, only pairs that agree modulo 2 ever occur: 12 of the 24.' } },
      { topic: 'crt-clocks', input: { m1: 4, m2: 6, r1: 1, r2: 3 }, frame: 12, caption: 'Clocks of 4 and 6: the hands are back at 0 after lcm(4, 6) = 12 steps, so half the cells stay empty.' },
      { h: 'Building the solution' },
      'Counting along the clocks takes M steps. The formula takes one term per modulus. Each term is made to be the right remainder for its own modulus and 0 for all the others; adding the terms then satisfies every congruence at once.',
      { math: 'M = m₁·m₂·…·m_k,  Mᵢ = M / mᵢ\nyᵢ = Mᵢ⁻¹ mod mᵢ\nx = Σ rᵢ·Mᵢ·yᵢ  mod M' },
      { topic: 'crt-solve', frame: 7, caption: 'x ≡ 2 (mod 9), 7 (mod 10), 5 (mod 11). The three terms 1100, 6237 and 2700 add to 10037, which is 137 modulo 990.' },
      { h: 'RSA, four times faster' },
      'The RSA key holder knows p and q, so she can decrypt modulo p and modulo q separately, with exponents reduced modulo p − 1 and q − 1, and join the two halves with the CRT. Each half works with numbers of half the length and an exponent of half the length.',
      { topic: 'crt-speedup', frame: 5, caption: 'm_p = 617 and m_q = 654 are joined by Garner\'s form of the CRT into the same m = 1142805 the direct computation gives.' },
      { warn: 'If a fault corrupts one half, the joined result is right modulo one prime and wrong modulo the other, and a gcd with n then reveals the prime: [one fault in CRT signing](#topic=p08-crt-fault), in part 8.' },
      { sandbox: 'crt' },
      { h: 'Recap' },
      { list: ['With pairwise coprime moduli, every list of remainders has exactly one solution modulo M = Πmᵢ.', 'x = Σ rᵢ·Mᵢ·yᵢ mod M, with Mᵢ = M/mᵢ and yᵢ its inverse modulo mᵢ.', 'With a common factor, a solution exists only if the remainders agree modulo the gcd; it is then unique modulo the lcm.', 'RSA decrypts modulo p and q separately and joins the halves with the CRT.'] },
      X('num-x-crt-small'), X('num-x-crt-table'), X('num-x-crt-nonco'), X('num-x-crt-rsa'), X('num-x-code-crt'),
      { challenge: 'num-ctf-clocks' },
    ],
  });

  // =========================================================================================================
  // Chapter 4: finite fields
  // =========================================================================================================
  C.lesson({
    id: 'num-gfp', chapter: 'num-fields', title: 'Fields: GF(p), and polynomials over GF(2)', minutes: 8,
    summary: 'A field lets you add, subtract, multiply and divide by anything but 0. Z_p is a field for a prime p. Fields of 2ᵐ elements are built from polynomials with bit coefficients, where adding is XOR and an irreducible polynomial plays the part of the prime.',
    blocks: [
      'Elliptic curves, AES and GCM all need arithmetic in which every nonzero element can be divided by. Z_n gives that only when n is prime. But AES works on bytes, and 256 is not prime. So where does a field with 256 elements come from?',
      { def: 'Field', text: 'a set with + and · in which the usual rules hold and every nonzero element has a multiplicative inverse. A finite field with q elements is written GF(q).' },
      { topic: 'gf-p', frame: 8, caption: 'In GF(13) every nonzero element is joined to its inverse. Only 1 and 12 (that is, −1) are their own partners.' },
      { topic: 'gf-p', frame: 9, caption: 'Division is multiplication by the inverse: 5 / 9 = 5·3 = 15 ≡ 2 (mod 13). Fermat gives the inverse too: 9¹¹ ≡ 3.' },
      { predict: { q: 'Which of these is a field, with + and · taken modulo n?', options: ['Z_12', 'Z_13', 'Z_15', 'Z_16'], answer: 1, explain: 'Only Z_13: 13 is prime. In Z_16, 2·8 ≡ 0, so 2 has no inverse. A field with 16 elements does exist, GF(2⁴), but its multiplication is not multiplication modulo 16; it is built from polynomials, as below.' } },
      { h: 'Polynomials with bit coefficients' },
      'Read a string of bits as a polynomial: 1011 is x³ + x + 1. Coefficients live in GF(2), where 1 + 1 = 0. So adding two polynomials is XOR of their bit strings, with no carries, and subtracting is the same as adding.',
      { topic: 'gf2-poly', frame: 3, caption: '(x³ + x + 1)·(x² + x): shifted copies of a, one for each term of b, XORed together. The result is 111010, while 11·6 = 66 = 1000010 as integers: ordinary multiplication carries, this does not.' },
      'Division works as in school, by cancelling the leading term again and again with shifted copies of the divisor, and the remainder always has a smaller degree than the divisor.',
      { topic: 'gf2-poly', input: { a: '101101110110', b: '100011011', op: 'div' }, frame: 4, caption: 'Reducing a polynomial of degree 11 by the AES polynomial x⁸ + x⁴ + x³ + x + 1: three XORs leave x⁷ + x + 1, which fits in a byte.' },
      { h: 'The role of the prime' },
      'Take all polynomials of degree below m, and multiply them modulo a fixed polynomial f of degree m. If f cannot be factored, it is **irreducible**, and the result is a field with 2ᵐ elements: GF(2ᵐ). An f that factors gives zero divisors, just as a composite n does in Z_n.',
      { tip: 'Over GF(2), x⁴ + x² + 1 looks irreducible but is (x² + x + 1)², since the cross terms 2x³ and 2x vanish. x⁴ + x + 1 really is irreducible and gives GF(16).' },
      { h: 'Recap' },
      { list: ['GF(p) = Z_p for a prime p; a / b = a·b⁻¹.', 'Polynomials over GF(2) are bit strings: + is XOR, · is shift-and-XOR, with no carries.', 'Polynomials modulo an irreducible f of degree m form GF(2ᵐ).'] },
      X('num-x-gfp-div'), X('num-x-gf2-mul'), X('num-x-irreducible'),
    ],
  });

  C.lesson({
    id: 'num-gf256', chapter: 'num-fields', title: 'GF(2⁸): the field inside AES', minutes: 10,
    summary: 'A byte is a polynomial of degree below 8, and AES multiplies bytes modulo x⁸ + x⁴ + x³ + x + 1. Multiplying by x is xtime, a shift with an XOR of 1b when a bit falls off; any product is shift-and-add; inverses come from Euclid or from logarithm tables.',
    blocks: [
      'AES MixColumns multiplies bytes by {02} and {03}, and the AES S-box starts by inverting a byte. Neither is integer arithmetic: {80}·{02} is not {100}, which would not fit in a byte. Both happen in GF(2⁸), with the modulus FIPS 197 fixes.',
      { math: 'a byte b₇b₆…b₀  =  b₇x⁷ + … + b₁x + b₀\nf = x⁸ + x⁴ + x³ + x + 1  = {11b}\n{57} + {83} = {57} ⊕ {83} = {d4}' },
      { h: 'xtime: multiplying by x' },
      'Multiplying by x (the byte {02}) shifts every bit up one place. If the top bit was 1, an x⁸ appears, and it is removed by adding f, which in the byte means XOR with {1b}.',
      { topic: 'gf2m-mul', input: { m: '8', a: 'b4', b: '02' }, frame: 2, caption: '{b4}·{02}: the shift gives {168}, nine bits long. XOR with f = {11b} gives {73}, back inside a byte.' },
      { predict: { q: 'What is xtime({57})?', options: ['{ae}', '{b5}', '{af}', '{57}'], answer: 0, explain: '{57} = 01010111 has top bit 0, so xtime is just the shift: 10101110 = {ae}. One more xtime gives {15c} ⊕ {11b} = {47}, since now the top bit was 1.' } },
      { h: 'Any product: shift and add' },
      'To multiply a by b, go through the bits of b from the bottom. Keep xⁱ·a, updated by one xtime per step, and add (XOR) it into a running sum when bit i of b is 1. Eight steps, each a shift and at most two XORs.',
      { topic: 'gf2m-mul', frame: 4, caption: '{4d}·{a6}, row 2: shifting x·a = {9a} gives {134}, so f is added and x²·a = {2f}. Bit 2 of b is 1, so {2f} joins the sum.' },
      { topic: 'gf2m-mul', frame: 16, caption: 'All eight rows: 4 additions, 7 shifts and 3 reductions give {4d}·{a6} = {41}.' },
      { h: 'Inverses' },
      'Every nonzero byte has an inverse, since f is irreducible. One way is the extended Euclidean algorithm on polynomials, exactly as on integers, with long division of polynomials and XOR for subtraction.',
      { topic: 'gf256-inverse', frame: 5, caption: '{7c}⁻¹ by Euclid: after four divisions the remainder is 1, and the t column holds the inverse {a1}. The S-box then applies its affine map: S({7c}) = {10}.' },
      'The other way uses a generator. {03} has order 255, so every nonzero byte is a power of {03}, and a table of logarithms turns multiplication into addition of exponents modulo 255.',
      { topic: 'gf256-table', frame: 4, caption: 'log {4d} = 70 and log {a6} = 73; 70 + 73 = 143, and {03}¹⁴³ = {41}: the same product as shift-and-add.' },
      { warn: 'Table lookups indexed by secret bytes take different times depending on the cache. Constant-time AES code multiplies by shift-and-add with masks instead, or uses the processor\'s AES instructions.' },
      { sandbox: 'xtime' },
      { sandbox: 'gf-mul' },
      { bench: 'nt', state: { tool: 'field', field: { kind: '2m', p: '29', m: '8', f: '', a: '0x4d', b: '0xa6', op: 'mul' } }, text: 'Multiply, divide and invert in GF(2⁸) or any other field.' },
      { h: 'Recap' },
      { list: ['A byte is a polynomial; + is XOR; products are reduced modulo {11b}.', 'xtime(a): shift left, and XOR {1b} if the top bit was 1.', 'a·b: add xⁱ·a for every 1 bit bᵢ, computing xⁱ·a by repeated xtime.', 'a⁻¹ by extended Euclid on polynomials, or as {03}^(255 − log a).'] },
      X('num-x-xtime'), X('num-x-gmul-table'), X('num-x-gmul'), X('num-x-gf-inv'), X('num-x-code-xtime'), X('num-x-code-gmul'),
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
