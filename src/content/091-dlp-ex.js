// Part 9, the discrete logarithm problem: the exercises, the part's tour and its course. The lessons are in 090-dlp.js.
// The exercises compute (orders, Diffie–Hellman, Elgamal, DSA and Schnorr at toy size), implement (baby-step
// giant-step, the check on a received value) and ask why each rule for choosing a group and a nonce exists. Every
// number below was worked out with the engines (S.NT, S.DLP, S.SIG) in a scratch script before it was written down.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('dlp-x-powers')) return;
  const ex = (o) => C.exercise(o);
  const fn = (name, params, body) => 'function ' + name + '(' + params.join(', ') + ') {\n' + body + '\n}';
  const pow = (b, e, n) => { let r = 1n; b = ((b % n) + n) % n; while (e > 0n) { if (e & 1n) r = r * b % n; b = b * b % n; e >>= 1n; } return r % n; };

  // ===========================================================================================================
  // Chapter 1: the problem
  // ===========================================================================================================
  ex({
    id: 'dlp-x-powers', chapter: 'dlp-problem', title: 'A logarithm by listing', level: 1, kind: 'number', answer: 11,
    text: ['3 is a generator of Z_31*. Find the x in 0 … 29 with 3^x ≡ 13 (mod 31) by listing powers.'],
    hints: ['Start at 3⁰ = 1 and multiply by 3 each time, reducing modulo 31.', '3⁰ … 3⁶ are 1, 3, 9, 27, 19, 26, 16.', '3⁷ … 3¹¹ are 17, 20, 29, 25, 13, so x = 11.'],
    solution: '11', wrong: ['13', '10', '12'],
    whyNot: { 13: 'That is h itself. x is the exponent that gives it.', '*': 'Check by computing 3 to your answer modulo 31: it should be 13.' },
  });
  ex({
    id: 'dlp-x-order', chapter: 'dlp-problem', title: 'The order of 10', level: 1, kind: 'number', answer: 15,
    text: ['What is the order of 10 in Z_31*, the smallest k > 0 with 10^k ≡ 1 (mod 31)? Only divisors of 30 need testing.'],
    hints: ['The order divides 30, so test k = 1, 2, 3, 5, 6, 10, 15, 30 in turn.', '10³ ≡ 8 and 10⁵ ≡ 25 (mod 31), so neither 3 nor 5 works; nor do 2, 6 and 10.', '10¹⁵ ≡ 1 (mod 31): the order is 15, so 10 is not a generator; it generates the subgroup of 15 elements.'],
    solution: '15', wrong: ['30', '5', '3'],
    whyNot: { 30: '10^30 ≡ 1 holds for every element (Fermat). The order is the smallest such exponent.', '*': 'Test the divisors of 30 in increasing order.' },
  });
  ex({
    id: 'dlp-x-generators', chapter: 'dlp-problem', title: 'Which are generators?', level: 2, kind: 'set', answer: '{5, 7, 10, 11}',
    text: ['Which of 2, 3, 4, 5, 6, 7, 10 and 11 generate Z_23*? Write the generators as a set, such as {2, 3}. Use the test: g generates exactly when g¹¹ ≢ 1 and g² ≢ 1 (mod 23).'],
    hints: ['22 = 2·11, so the order of each element is 1, 2, 11 or 22. Only 22 = −1 has order 2.', 'So g generates exactly when g¹¹ ≡ −1 = 22 (mod 23). The bench\'s Order tool shows each order.', '{5, 7, 10, 11}: each has g¹¹ ≡ 22. 2, 3, 4 and 6 have g¹¹ ≡ 1 and order 11.'],
    solution: '{5, 7, 10, 11}', wrong: ['{2, 3, 5, 7, 11}', '{5, 7}', '{2, 3, 4, 6}'],
    whyNot: 'Compute g¹¹ mod 23 for each candidate: 22 means a generator, 1 means order 11.',
  });
  ex({
    id: 'dlp-x-orders-set', chapter: 'dlp-problem', title: 'Possible orders', level: 1, kind: 'set', answer: '{1, 2, 4, 7, 14, 28}',
    text: ['Which numbers occur as the order of some element of Z_29*? Write them as a set.'],
    hints: ['By Lagrange, every order divides the size of the group, 28.', 'A cyclic group of order 28 has an element of every order that divides 28.', '{1, 2, 4, 7, 14, 28}: the divisors of 28.'],
    solution: '{1, 2, 4, 7, 14, 28}', wrong: ['{28}', '{1, 2, 4, 7, 14}', '{2, 7}'],
    whyNot: 'List all the divisors of p − 1 = 28, including 1 and 28.',
  });

  // ===========================================================================================================
  // Chapter 2: agreeing and encrypting
  // ===========================================================================================================
  ex({
    id: 'dlp-x-dh-pub', chapter: 'dlp-exchange', title: 'Alice\'s public value', level: 1, kind: 'number', answer: 98,
    text: ['Alice and Bob use p = 101 and g = 2. Alice\'s secret is a = 19. What does she send, A = g^a mod p?'],
    hints: ['19 = 10011 in binary: square-and-multiply, or build up powers of 2 by doubling and reducing.', '2¹⁰ = 1024 ≡ 14 (mod 101), so 2¹⁹ = 2¹⁰·2⁹ ≡ 14·512.', '14·512 = 7168 = 70·101 + 98, so A = 98.'],
    solution: '98', wrong: ['38', '19', '14'],
    whyNot: 'Raise 2 to the 19th power and reduce modulo 101 at each step.',
  });
  const DH = { 'A = g^a mod p|value': '155', 'B = g^b mod p|value': '37', 'Alice: B^a mod p|value': '176', 'Bob: A^b mod p|value': '176' };
  ex({
    id: 'dlp-x-dh-table', chapter: 'dlp-exchange', title: 'A whole exchange', level: 2, kind: 'table',
    text: ['Run Diffie–Hellman with p = 211, g = 2, Alice\'s a = 37 and Bob\'s b = 118. Fill in the public values and the key each side computes. The [public-key bench](#bench/pk) (Diffie–Hellman) or its Powers tool will help.'],
    rows: ['A = g^a mod p', 'B = g^b mod p', 'Alice: B^a mod p', 'Bob: A^b mod p'], cols: ['value'], corner: 'Step',
    cells: DH,
    hints: ['Four exponentiations modulo 211. The last two must agree.', 'A = 2³⁷ mod 211 = 155 and B = 2¹¹⁸ mod 211 = 37.', 'A = 155, B = 37, and both keys are 37³⁷ ≡ 155¹¹⁸ ≡ 176 (mod 211). Eve\'s A·B mod 211 = 38 is not the key.'],
    solution: DH,
    wrong: [Object.assign({}, DH, { 'Alice: B^a mod p|value': '38', 'Bob: A^b mod p|value': '38' }), Object.assign({}, DH, { 'B = g^b mod p|value': '118' })],
  });
  ex({
    id: 'dlp-x-dh-eve', chapter: 'dlp-exchange', title: 'What Eve can compute', level: 1, kind: 'choice',
    text: ['Eve sees p, g, A = g^a and B = g^b. Which of these can she compute easily?'],
    options: ['A·B mod p = g^(a+b)', 'A/B mod p = g^(a−b)', 'g^(ab) mod p, the key', 'a, from A, when p has 2048 bits', 'A² mod p = g^(2a)'],
    answer: [0, 1, 4],
    hints: ['Multiplying and dividing powers adds and subtracts exponents; that is easy.', 'Getting a product of exponents from two powers is the Diffie–Hellman problem.', 'Easy: the first, second and fifth. The key and a both need, as far as anyone knows, a discrete logarithm.'],
    solution: [0, 1, 4], wrong: [[0, 1, 2, 4], [2], [0]],
  });
  ex({
    id: 'dlp-x-ephemeral', chapter: 'dlp-exchange', title: 'Fresh exponents', level: 2, kind: 'choice',
    text: ['A server draws a new Diffie–Hellman exponent for every connection and erases it afterwards (ephemeral Diffie–Hellman). What does that give?'],
    options: ['Forward secrecy: stealing the server\'s long-term signing key later does not reveal past session keys', 'Protection against a man in the middle, without any signatures', 'A shorter prime can be used safely', 'Answers to small-subgroup probes reveal only something about a secret that is already thrown away'],
    answer: [0, 3],
    hints: ['What can an attacker do with today\'s exponent tomorrow if it no longer exists?', 'Authentication is a separate matter: without signatures a man in the middle still runs two exchanges.', 'The first and fourth. The prime must be just as long, and the values must still be signed.'],
    solution: [0, 3], wrong: [[0, 1], [1, 2], [0]],
  });
  ex({
    id: 'dlp-x-mitm-fix', chapter: 'dlp-exchange', title: 'Stopping the man in the middle', level: 2, kind: 'choice',
    text: ['Mallory sits between Alice and Bob during a Diffie–Hellman exchange and replaces each public value with her own. Which measures stop her?'],
    options: ['Bob signs B together with A using his long-term key, certified by an authority Alice trusts, and Alice checks the signature', 'Use a 4096-bit prime', 'Both compare a short hash of the transcript over a channel Mallory cannot change, such as reading it aloud', 'Use a safe prime', 'Run the exchange twice'],
    answer: [0, 2],
    hints: ['Mallory solves no hard problem, so harder problems do not help.', 'Alice needs to know that B came from Bob, or that what she saw is what Bob saw.', 'The first and third: a certified signature, or an out-of-band comparison of the exchanged values.'],
    solution: [0, 2], wrong: [[1, 3], [0], [0, 2, 4]],
  });
  const EL = { 'h = g^x mod p|value': '17', 'c1 = g^k mod p|value': '26', 's = h^k mod p|value': '15', 'c2 = m·s mod p|value': '27' };
  ex({
    id: 'dlp-x-elgamal-enc', chapter: 'dlp-exchange', title: 'Encrypt with Elgamal', level: 2, kind: 'table',
    text: ['Bob\'s Elgamal key uses p = 107, g = 2 and the private x = 29. Alice encrypts m = 66 with the nonce k = 15. Fill in Bob\'s public key and the ciphertext.'],
    rows: ['h = g^x mod p', 'c1 = g^k mod p', 's = h^k mod p', 'c2 = m·s mod p'], cols: ['value'], corner: 'Step',
    cells: EL,
    hints: ['h = 2²⁹ mod 107 and c1 = 2¹⁵ mod 107.', 'h = 17, c1 = 26, and the mask s = 17¹⁵ mod 107 = 15 (also equal to c1^x).', 'h = 17, c1 = 26, s = 15, c2 = 66·15 mod 107 = 990 − 963 = 27. The ciphertext is (26, 27).'],
    solution: EL,
    wrong: [Object.assign({}, EL, { 'c2 = m·s mod p|value': '81' }), Object.assign({}, EL, { 's = h^k mod p|value': '26' })],
  });
  ex({
    id: 'dlp-x-elgamal-dec', chapter: 'dlp-exchange', title: 'Decrypt with Elgamal', level: 2, kind: 'number', answer: 91,
    text: ['With the same key (p = 107, g = 2, x = 29), Bob receives the ciphertext (c1, c2) = (41, 80). What is the message?'],
    hints: ['s = c1^x mod p, then m = c2·s⁻¹ mod p.', 's = 41²⁹ mod 107 = 102, and 102 ≡ −5, whose inverse modulo 107 is 64 (5·64 = 320 = 3·107 − 1).', 'm = 80·64 mod 107 = 5120 − 47·107 = 91.'],
    solution: '91', wrong: ['80', '102', '16'],
    whyNot: { 102: 'That is the mask s. Divide c2 by it.', 16: 'That is c2·s mod p. Multiply by the inverse of s, not by s.', '*': 'Compute s = c1^x mod p, invert it modulo p, and multiply by c2.' },
  });
  ex({
    id: 'dlp-x-elgamal-nonce', chapter: 'dlp-exchange', title: 'A nonce used twice', level: 2, kind: 'choice',
    text: ['A sender encrypts two messages m and m′ to the same Elgamal key with the same nonce k. What follows?'],
    options: ['Both ciphertexts have the same c1, and c2/c2′ = m/m′ mod p, so knowing one message reveals the other', 'Nothing: the messages are different', 'The private key x leaks at once', 'Bob can no longer decrypt either'],
    answer: 0,
    whyNot: { 1: 'The masks are equal, and equal masks cancel in a quotient.', 2: 'x stays hidden: the mask h^k is reused, not the key.', 3: 'Decryption works as before; the damage is to secrecy.' },
    hints: ['c1 = g^k is the same in both. What about the mask h^k?', 'c2 = m·s and c2′ = m′·s with the same s.', 'The first. The rule is a fresh, uniformly random k for every encryption.'],
    solution: 0, wrong: [1, 2],
  });
  ex({
    id: 'dlp-x-elgamal-mall', chapter: 'dlp-exchange', title: 'A ciphertext changed in transit', level: 1, kind: 'choice',
    text: ['The ciphertext (26, 27) of m = 66 under the key p = 107, g = 2, x = 29 is changed on the way to (26, 81), where 81 = 3·27 mod 107. What does Bob decrypt, and what does that show?'],
    options: ['91 = 3·66 mod 107: Elgamal is malleable, so a changed ciphertext must be detected by an authenticated scheme around it', '66: the change is ignored', 'An error: Bob\'s decryption checks c2', '198: three times the message'],
    answer: 0,
    whyNot: { 1: 'c2 is multiplied by 3 and the mask is unchanged, so the result is multiplied by 3.', 2: 'Plain Elgamal has nothing to check.', 3: 'Every decryption is a number modulo p = 107.' },
    hints: ['The mask s = 15 is unchanged, since c1 is.', '81·s⁻¹ = 3·27·s⁻¹ = 3·m mod p.', '3·66 = 198 ≡ 91 (mod 107). Real systems use Elgamal (or Diffie–Hellman) only to agree a key, and an AEAD cipher for the data.'],
    solution: 0, wrong: [1, 3],
  });

  // ===========================================================================================================
  // Chapter 3: signatures
  // ===========================================================================================================
  const DS = { 'y = g^x mod p|value': '143', 'g^k mod p|value': '489', 'r = (g^k mod p) mod q|value': '85', 'k⁻¹ mod q|value': '69', 's = k⁻¹(z + x·r) mod q|value': '14' };
  ex({
    id: 'dlp-x-dsa-sign', chapter: 'dlp-sign', title: 'Sign with toy DSA', level: 3, kind: 'table',
    text: ['Toy DSA parameters: p = 607, q = 101 (q divides p − 1 = 606) and g = 64, of order q. The private key is x = 37. Sign a message whose hash is z = 55 with the nonce k = 41.'],
    rows: ['y = g^x mod p', 'g^k mod p', 'r = (g^k mod p) mod q', 'k⁻¹ mod q', 's = k⁻¹(z + x·r) mod q'], cols: ['value'], corner: 'Step',
    cells: DS,
    hints: ['Exponentiations are modulo p = 607; everything after r is modulo q = 101.', 'y = 64³⁷ mod 607 = 143, g^k = 64⁴¹ mod 607 = 489, so r = 489 mod 101 = 85. 41·69 = 2829 = 28·101 + 1, so k⁻¹ = 69.', 'z + x·r = 55 + 37·85 = 3200 ≡ 69 (mod 101), and s = 69·69 mod 101 = 14. The signature is (85, 14).'],
    solution: DS,
    wrong: [Object.assign({}, DS, { 'r = (g^k mod p) mod q|value': '489' }), Object.assign({}, DS, { 'k⁻¹ mod q|value': '311', 's = k⁻¹(z + x·r) mod q|value': '71' })],
  });
  const DV = { 'w = s⁻¹ mod q|value': '65', 'u1 = z·w mod q|value': '40', 'u2 = r·w mod q|value': '71', 'g^u1·y^u2 mod p|value': '489', 'v = (g^u1·y^u2 mod p) mod q|value': '85' };
  ex({
    id: 'dlp-x-dsa-verify', chapter: 'dlp-sign', title: 'Verify the toy signature', level: 3, kind: 'table',
    text: ['Verify the signature (r, s) = (85, 14) on z = 55 with the public key y = 143 and the parameters p = 607, q = 101, g = 64. The signature is valid when v = r.'],
    rows: ['w = s⁻¹ mod q', 'u1 = z·w mod q', 'u2 = r·w mod q', 'g^u1·y^u2 mod p', 'v = (g^u1·y^u2 mod p) mod q'], cols: ['value'], corner: 'Step',
    cells: DV,
    hints: ['14·w ≡ 1 (mod 101): 14·65 = 910 = 9·101 + 1.', 'u1 = 55·65 mod 101 = 40 and u2 = 85·65 mod 101 = 71. Then 64⁴⁰·143⁷¹ mod 607.', 'w = 65, u1 = 40, u2 = 71, g^u1·y^u2 = 489 = g^k, and v = 489 mod 101 = 85 = r: valid.'],
    solution: DV,
    wrong: [Object.assign({}, DV, { 'v = (g^u1·y^u2 mod p) mod q|value': '489' }), Object.assign({}, DV, { 'w = s⁻¹ mod q|value': '14' })],
  });
  ex({
    id: 'dlp-x-elgamal-sig', chapter: 'dlp-sign', title: 'An Elgamal signature', level: 3, kind: 'number', answer: 82,
    text: ['Elgamal signatures with p = 107, g = 2, private x = 29 (public y = 17). Sign the hash z = 50 with the nonce k = 13, which is coprime to p − 1 = 106: r = g^k mod p and s = k⁻¹(z − x·r) mod (p − 1). What is s?'],
    hints: ['r = 2¹³ mod 107 = 60. The exponents live modulo 106, so k⁻¹ is an inverse modulo 106.', '13·49 = 637 = 6·106 + 1, so k⁻¹ = 49. z − x·r = 50 − 1740 = −1690 ≡ 6 (mod 106).', 's = 49·6 mod 106 = 294 − 212 = 82. Check: g^z = 2⁵⁰ ≡ 40 and y^r·r^s = 17⁶⁰·60⁸² ≡ 40 (mod 107).'],
    solution: '82', wrong: ['60', '24', '30'],
    whyNot: { 60: 'That is r. s comes from k⁻¹(z − x·r).', '*': 'Work modulo p − 1 = 106 for k⁻¹ and s, not modulo p.' },
  });
  ex({
    id: 'dlp-x-schnorr', chapter: 'dlp-sign', title: 'A Schnorr response', level: 2, kind: 'number', answer: 42,
    text: ['Schnorr signing in the toy group p = 607, q = 101, g = 64, with private x = 37 and nonce k = 41. The commitment is R = g^k mod p = 489, and the challenge hash comes out as e = 71. What is the response s = k + e·x mod q?'],
    hints: ['No inverse is needed: one multiplication and one addition modulo 101.', 'e·x = 71·37 = 2627.', 's = 41 + 2627 = 2668 ≡ 42 (mod 101). The verifier rebuilds g^s·y^(−e) mod p = 489 = R.'],
    solution: '42', wrong: ['2668', '72', '30'],
    whyNot: { 2668: 'Reduce modulo q = 101.', '*': 'Compute 41 + 71·37 and reduce modulo 101.' },
  });
  ex({
    id: 'dlp-x-nonce-rule', chapter: 'dlp-sign', title: 'Choosing the nonce', level: 2, kind: 'choice',
    text: ['Which ways of choosing DSA or ECDSA nonces are sound?'],
    options: ['A fresh value drawn uniformly from 1 … q − 1 by a well-seeded cryptographic generator, for every signature', 'k derived deterministically from the private key and the message hash with HMAC, as in RFC 6979', 'A counter that starts at 1 and goes up by one per signature', 'A random 224-bit k whose top 8 bits are always zero, to save time', 'The same random k for every signature, kept as secret as the key'],
    answer: [0, 1],
    hints: ['Any two signatures with the same k expose x, and so does a k anyone can predict.', 'A counter is predictable, and a k with known bits is biased: over many signatures the bias gives x away.', 'Sound: the first and second. RFC 6979 needs no random generator at signing time, and different messages get unrelated nonces.'],
    solution: [0, 1], wrong: [[0, 1, 4], [0], [2, 3]],
  });
  ex({
    id: 'dlp-x-nonce-r', chapter: 'dlp-sign', title: 'Spotting a repeated nonce', level: 1, kind: 'choice',
    text: ['Looking only at public data, how can anyone tell that two DSA signatures from one key used the same nonce?'],
    options: ['They have the same r', 'They have the same s', 'The messages hash to the same z', 'It cannot be told from public data'],
    answer: 0,
    whyNot: { 1: 's depends on the message too, so it differs even when k repeats.', 2: 'Equal hashes mean equal messages, which says nothing about k.', 3: 'r = (g^k mod p) mod q depends only on k, and r is public.' },
    hints: ['Which part of the signature depends only on k?', 'r = (g^k mod p) mod q.', 'The same r. That is the first thing a scan of public signatures looks for.'],
    solution: 0, wrong: [1, 3],
  });

  // ===========================================================================================================
  // Chapter 4: choosing the group
  // ===========================================================================================================
  ex({
    id: 'dlp-x-bsgs-m', chapter: 'dlp-params', title: 'Sizing the table', level: 1, kind: 'number', answer: 101,
    text: ['Baby-step giant-step in Z_10007* (order n = 10006) writes x = i·m + j with m = ⌈√n⌉. What is m, the number of baby steps stored?'],
    hints: ['√10006 is just above 100.', '100² = 10000 < 10006, so √10006 is not a whole number and rounds up.', 'm = 101, and at most 101 giant steps follow: about 202 operations instead of 10006.'],
    solution: '101', wrong: ['100', '10006', '5003'],
    whyNot: { 100: '100² = 10000 is less than n = 10006, so 100 is too few: round up.', '*': 'Take the square root of 10006 and round up.' },
  });
  ex({
    id: 'dlp-x-code-bsgs', chapter: 'dlp-params', title: 'Write baby-step giant-step', level: 3, kind: 'code', fn: 'bsgs', params: ['g', 'h', 'p', 'n'],
    text: ['Write `bsgs(g, h, p, n)` for BigInts: g has order n modulo the prime p. Return the x in 0 … n − 1 with g^x ≡ h (mod p), or `null` if h is not a power of g. Store the baby steps in a `Map` keyed by `String(value)`. One test has n near 2²⁹ and an answer near the top of the range: a linear search through half a billion powers runs out of time, while baby-step giant-step needs about 45,000 steps.'],
    start: 'function bsgs(g, h, p, n) {\n  \n}',
    tests: () => {
      const cases = [[2n, 777n, 1019n, 1018n], [2n, 1n, 1019n, 1018n], [5n, 2026n, 10007n, 10006n], [4n, 2n, 23n, 11n], [4n, 5n, 23n, 11n], [3n, 13n, 31n, 30n], [64n, 489n, 607n, 101n]];
      const out = cases.map((a) => { const [g, h, p, n] = a; let want = null; for (let x = 0n; x < n; x++) if (pow(g, x, p) === h) { want = x; break; } return { args: a, want }; });
      // a 30-bit safe prime: g = 4 has the prime order q = (p − 1)/2, and h = g^x for a fixed x
      const P = 1000000007n, q = (P - 1n) / 2n, x = q - 12345n; // near the top of the range: about 5·10⁸ steps by brute force
      out.push({ args: [4n, pow(4n, x, P), P, q], want: x });
      return out;
    },
    timeLimit: 6000,
    hints: ['m = ⌈√n⌉. Baby steps: put g^j → j into the map for j = 0 … m − 1. Then compute c = g^(−m) mod p, the inverse of g^m (Fermat: g^(p−1−m) when p is prime).', 'Giant steps: start with y = h; for i = 0 … m − 1, if the map has y return i·m + j, else y = y·c mod p. If nothing matches, return null. A BigInt square root: start from BigInt(Math.ceil(Math.sqrt(Number(n)))) and adjust.', fn('bsgs', ['g', 'h', 'p', 'n'], '  const pow = (b, e) => { let r = 1n; b %= p; while (e > 0n) { if (e & 1n) r = r * b % p; b = b * b % p; e >>= 1n; } return r; };\n  let m = BigInt(Math.ceil(Math.sqrt(Number(n))));\n  while (m * m < n) m++;\n  const baby = new Map();\n  let v = 1n;\n  for (let j = 0n; j < m; j++) { if (!baby.has(String(v))) baby.set(String(v), j); v = v * g % p; }\n  const c = pow(pow(g, m), p - 2n);\n  let y = h % p;\n  for (let i = 0n; i < m; i++) {\n    if (baby.has(String(y))) { const x = i * m + baby.get(String(y)); if (x < n) return x; }\n    y = y * c % p;\n  }\n  return null;')],
    solution: fn('bsgs', ['g', 'h', 'p', 'n'], '  const pow = (b, e) => { let r = 1n; b %= p; while (e > 0n) { if (e & 1n) r = r * b % p; b = b * b % p; e >>= 1n; } return r; };\n  let m = BigInt(Math.ceil(Math.sqrt(Number(n))));\n  while (m * m < n) m++;\n  const baby = new Map();\n  let v = 1n;\n  for (let j = 0n; j < m; j++) { if (!baby.has(String(v))) baby.set(String(v), j); v = v * g % p; }\n  const c = pow(pow(g, m), p - 2n);\n  let y = h % p;\n  for (let i = 0n; i < m; i++) {\n    if (baby.has(String(y))) { const x = i * m + baby.get(String(y)); if (x < n) return x; }\n    y = y * c % p;\n  }\n  return null;'),
    wrong: [
      fn('bsgs', ['g', 'h', 'p', 'n'], '  let v = 1n;\n  for (let x = 0n; x < n; x++) { if (v === h) return x; v = v * g % p; }\n  return null;'),
      fn('bsgs', ['g', 'h', 'p', 'n'], '  const pow = (b, e) => { let r = 1n; b %= p; while (e > 0n) { if (e & 1n) r = r * b % p; b = b * b % p; e >>= 1n; } return r; };\n  const m = BigInt(Math.floor(Math.sqrt(Number(n))));\n  const baby = new Map();\n  let v = 1n;\n  for (let j = 0n; j < m; j++) { baby.set(String(v), j); v = v * g % p; }\n  const c = pow(pow(g, m), p - 2n);\n  let y = h % p;\n  for (let i = 0n; i < m; i++) { if (baby.has(String(y))) return i * m + baby.get(String(y)); y = y * c % p; }\n  return null;'),
    ],
  });
  ex({
    id: 'dlp-x-generic-bits', chapter: 'dlp-params', title: 'Security of a 224-bit subgroup', level: 1, kind: 'number', answer: 112,
    text: ['DSA with 2048/224 parameters does its exponent arithmetic in a subgroup of prime order q with 224 bits. Pollard\'s rho needs about √q steps there. About how many bits of security does that give against generic attacks?'],
    hints: ['√(2²²⁴) = 2^(224/2).', 'Halve the number of bits.', '112 bits, matching the 2048-bit p, which the number field sieve also puts at about 112 bits.'],
    solution: '112', wrong: ['224', '2048', '56'],
    whyNot: { 224: 'That is the size of q. A square-root attack halves it.', 56: 'Only one square root: halve once.', '*': 'Take the square root of 2²²⁴.' },
  });
  ex({
    id: 'dlp-x-rho-memory', chapter: 'dlp-params', title: 'Rho or baby-step giant-step?', level: 1, kind: 'choice',
    text: ['Both baby-step giant-step and Pollard\'s rho need about √n group operations. Why is rho the method used in record computations?'],
    options: ['It needs almost no memory, and many machines can walk in parallel, where baby-step giant-step must store √n elements', 'It needs fewer operations by a factor of n', 'It works only in prime-order groups, which are the ones used', 'It gives the answer exactly, while baby-step giant-step is probabilistic'],
    answer: 0,
    whyNot: { 1: 'Both are about √n; rho is slightly slower on average.', 2: 'Both work in any cyclic group.', 3: 'Baby-step giant-step is deterministic; rho is the probabilistic one.' },
    hints: ['Compare what each stores.', 'Baby-step giant-step stores a table of √n values; for 2¹²⁸ steps that is 2¹²⁸ elements.', 'The first: rho keeps two points (or a few distinguished points when parallel).'],
    solution: 0, wrong: [1, 3],
  });
  ex({
    id: 'dlp-x-pohlig-work', chapter: 'dlp-params', title: 'Where the work goes', level: 2, kind: 'number', answer: 1000, tolerance: 5,
    text: ['A group has order n = 2³·3²·1000003, about 2²⁶. With Pohlig–Hellman and rho on each piece, the largest piece dominates the work. About how many steps does that largest piece take? (Rho costs about the square root of the prime.)'],
    hints: ['The pieces are logarithms in groups of order 2, 3 and 1000003.', 'The pieces of order 2 and 3 cost a handful of steps each. The piece of order 1000003 costs about √1000003.', 'About 1000 steps, against about √n ≈ 2¹³ ≈ 8500 for a generic attack on the whole order. The largest prime factor, not n, sets the difficulty.'],
    solution: '1000', wrong: ['1000003', '8485', '26'],
    whyNot: { 1000003: 'Rho on a group of prime order q costs about √q, not q.', 8485: 'That is about √n, a generic attack on the whole order. Pohlig–Hellman splits it first.', '*': 'Take the square root of the largest prime factor of n.' },
    higherLower: true,
  });
  ex({
    id: 'dlp-x-safe-primes', chapter: 'dlp-params', title: 'Safe primes', level: 2, kind: 'set', answer: '{23, 47, 59, 83, 107}',
    text: ['A prime p is safe when (p − 1)/2 is prime too. Which of 23, 29, 47, 59, 61, 83 and 107 are safe primes? Write them as a set.'],
    hints: ['Compute (p − 1)/2 for each and test it for primality.', '11, 14, 23, 29, 30, 41 and 53.', '{23, 47, 59, 83, 107}. 29 and 61 are not safe: 14 = 2·7 and 30 = 2·3·5, so Z_29* has a subgroup of order 7, and Z_61* subgroups of orders 3 and 5.'],
    solution: '{23, 47, 59, 83, 107}', wrong: ['{23, 29, 47, 59, 61, 83, 107}', '{23, 47}', '{29, 61}'],
    whyNot: 'Halve p − 1 and check whether the result is prime.',
  });
  ex({
    id: 'dlp-x-index-why', chapter: 'dlp-params', title: 'Two sizes in one group', level: 2, kind: 'choice',
    text: ['For 128-bit security, DSA-style parameters use a 3072-bit p and a 256-bit q. Why two such different sizes?'],
    options: ['p must resist index calculus (the number field sieve), which works in Z_p* and is subexponential; q must resist generic attacks, which cost √q', 'p must be large to make signatures long', 'q is short only for speed; security comes from p alone', 'The two sizes are equal in bits of security, so either could be dropped'],
    answer: 0,
    whyNot: { 1: 'Signatures are two numbers modulo q, so they are short; p does not make them long.', 2: 'A short q would fall to rho however long p is.', 3: 'Both must hold: the attacker takes whichever route is cheaper.' },
    hints: ['Which attack uses the fact that elements of Z_p* are integers that may factor?', 'Index calculus needs smooth integers, which is a property of Z_p*; rho needs only the subgroup.', 'The first. The attacker takes the cheaper of the two routes, so both sizes are set to the same level.'],
    solution: 0, wrong: [1, 2],
  });
  const LV = { '112|p': '2048', '112|q': '224', '128|p': '3072', '128|q': '256', '192|p': '7680', '192|q': '384', '256|p': '15360', '256|q': '512' };
  ex({
    id: 'dlp-x-levels', chapter: 'dlp-params', title: 'Sizes for each level', level: 2, kind: 'table',
    text: ['Fill in the bit lengths of the prime p and the subgroup order q for each security level, as in NIST SP 800-57.'],
    rows: ['112', '128', '192', '256'], cols: ['p', 'q'], corner: 'Level (bits)',
    cells: LV,
    hints: ['q is twice the level, because of √q attacks.', 'p matches the RSA modulus of the same level: 2048, 3072, … .', 'p: 2048, 3072, 7680, 15360. q: 224, 256, 384, 512.'],
    solution: LV,
    wrong: [Object.assign({}, LV, { '128|q': '128' }), Object.assign({}, LV, { '192|p': '4096' })],
  });
  ex({
    id: 'dlp-x-subgroup-set', chapter: 'dlp-params', title: 'Which received values pass?', level: 2, kind: 'set', answer: '{2, 3, 4}',
    text: ['A server works in the subgroup of prime order q = 11 of Z_23* (p = 23 = 2·11 + 1). It accepts a received y only if 1 < y < p − 1 and y¹¹ ≡ 1 (mod 23). Which of 1, 2, 3, 4, 5 and 22 does it accept?'],
    hints: ['1 and 22 = p − 1 fail the range check.', 'Compute y¹¹ mod 23 for 2, 3, 4 and 5.', '2¹¹, 3¹¹ and 4¹¹ are 1 and 5¹¹ is 22, so the server accepts {2, 3, 4}. 5 has order 22 and lies outside the subgroup.'],
    solution: '{2, 3, 4}', wrong: ['{1, 2, 3, 4}', '{2, 3, 4, 5}', '{5, 22}'],
    whyNot: 'Apply both checks: the range 1 < y < 22, and y¹¹ mod 23 = 1.',
  });
  ex({
    id: 'dlp-x-code-check', chapter: 'dlp-params', title: 'Write the public-value check', level: 2, kind: 'code', fn: 'validPublic', params: ['y', 'p', 'q'],
    text: ['Write `validPublic(y, p, q)` for BigInts: return `true` when the received value y lies in the subgroup of prime order q of Z_p* and is not 1, that is when 1 < y < p − 1 and y^q ≡ 1 (mod p); `false` otherwise. One test uses the 2048-bit MODP prime, so use square-and-multiply.'],
    start: 'function validPublic(y, p, q) {\n  \n}',
    tests: () => {
      // the 2048-bit MODP prime of RFC 3526, as the topics hold it
      const M = BigInt('0x' + S.PK.DATA.modp14), MQ = (M - 1n) / 2n;
      const cases = [[2n, 23n, 11n, true], [3n, 23n, 11n, true], [4n, 23n, 11n, true], [5n, 23n, 11n, false], [1n, 23n, 11n, false], [22n, 23n, 11n, false], [0n, 23n, 11n, false], [23n, 23n, 11n, false], [143n, 607n, 101n, true], [3n, 607n, 101n, false], [4n, M, MQ, true], [M - 1n, M, MQ, false], [pow(2n, 123456789n, M), M, MQ, true], [M - 2n, M, MQ, false]];
      return cases.map(([y, p, q, want]) => ({ args: [y, p, q], want }));
    },
    hints: ['First the range: return false unless y > 1n and y < p − 1n.', 'Then compute y^q mod p with square-and-multiply on BigInts and compare with 1n.', fn('validPublic', ['y', 'p', 'q'], '  if (y <= 1n || y >= p - 1n) return false;\n  let r = 1n, b = y % p, e = q;\n  while (e > 0n) { if (e & 1n) r = r * b % p; b = b * b % p; e >>= 1n; }\n  return r === 1n;')],
    solution: fn('validPublic', ['y', 'p', 'q'], '  if (y <= 1n || y >= p - 1n) return false;\n  let r = 1n, b = y % p, e = q;\n  while (e > 0n) { if (e & 1n) r = r * b % p; b = b * b % p; e >>= 1n; }\n  return r === 1n;'),
    wrong: [
      fn('validPublic', ['y', 'p', 'q'], '  let r = 1n, b = y % p, e = q;\n  while (e > 0n) { if (e & 1n) r = r * b % p; b = b * b % p; e >>= 1n; }\n  return r === 1n;'),
      fn('validPublic', ['y', 'p', 'q'], '  return y > 1n && y < p - 1n;'),
    ],
  });
  ex({
    id: 'dlp-x-subgroup-fix', chapter: 'dlp-params', title: 'Closing the small-subgroup hole', level: 2, kind: 'choice',
    text: ['A server keeps one Diffie–Hellman secret for months, in Z_p* where p − 1 has many small prime factors, and raises whatever it receives to that secret. Which changes close the hole?'],
    options: ['Use a safe prime p = 2q + 1, or a subgroup of large prime order q', 'Reject any received y unless 1 < y < p − 1 and y^q ≡ 1 (mod p)', 'Draw a fresh secret for every exchange', 'Hash the shared key before use, and change nothing else', 'Make the secret exponent longer'],
    answer: [0, 1, 2],
    hints: ['The attacker sends an element of small order r and learns x mod r from the server\'s answer.', 'Hashing the key does not stop the attacker from trying the r possible keys against the answer; a longer x has the same residues to leak.', 'The first three: no small subgroups to probe, no unchecked values accepted, and no long-lived secret to learn about.'],
    solution: [0, 1, 2], wrong: [[3, 4], [0], [0, 1, 2, 3]],
  });

  // ===========================================================================================================
  // The part's tour and course
  // ===========================================================================================================
  C.tour({
    id: 'dlp-tour', title: 'Tour: the discrete logarithm', blurb: 'Powers that are easy to compute and hard to undo, and what is built on them, in eight steps.',
    steps: [
      { route: 'part=dlp', target: '#main', text: 'Part 9 of the catalogue: the discrete logarithm problem, Diffie–Hellman, Elgamal, the signatures of the Elgamal family, and the rules for choosing a group.' },
      { route: 'topic=p09-dlp', target: '#stageWrap', text: 'The problem: the powers of a generator hop round Z_p* in an order with no visible pattern. Step through to find one logarithm by hand.' },
      { target: '#btnPlay', text: 'Play runs the steps; the arrow keys go one at a time. The line under the picture names the actual numbers.' },
      { route: 'topic=p09-dh-paint', target: '#stageWrap', text: 'Diffie–Hellman as mixing paint, then with numbers: two public values, one shared key.' },
      { route: 'topic=p09-dh-mitm', target: '#stageWrap', text: 'Why the exchange must be signed: a man in the middle needs no mathematics at all.' },
      { route: 'topic=p09-sigs', target: '#inputs', text: 'DSA, Schnorr and Elgamal signatures. Switch scheme and size, and change the message to see verification fail.' },
      { route: 'topic=p09-pohlig', target: '#stageWrap', text: 'Why the group order must be a large prime: a smooth order splits into many easy pieces.' },
      { route: 'learn', target: '[data-chapter="dlp-problem"]', text: 'The part\'s lessons and exercises start here: compute orders, run Diffie–Hellman, Elgamal and DSA by hand, write baby-step giant-step, and say why each rule for parameters exists.' },
    ],
  });

  C.course({
    id: 'dlp-course', title: 'The discrete logarithm and what rests on it', blurb: 'An ordered path through every topic of part 9, from the problem itself to Diffie–Hellman, signatures and the choice of group, with lessons and exercises on the way.',
    steps: [
      { topic: 'p09-dlp', note: 'Powers that wrap round.' },
      { lesson: 'dlp-what', note: 'The problem.' },
      { lesson: 'dlp-groups', note: 'Generators and subgroups.' },
      { exercise: 'dlp-x-generators', note: 'Find the generators of Z_23*.' },
      { topic: 'p09-dh-paint', note: 'Key agreement as paint.' },
      { topic: 'p09-dh', note: 'Key agreement with numbers.' },
      { exercise: 'dlp-x-dh-table', note: 'A whole exchange by hand.' },
      { topic: 'p09-dh-mitm', note: 'Why the exchange is signed.' },
      { lesson: 'dlp-mitm', note: 'Authentication.' },
      { topic: 'p09-elgamal', note: 'Encrypting with a fresh nonce.' },
      { exercise: 'dlp-x-elgamal-enc', note: 'Encrypt with Elgamal.' },
      { topic: 'p09-sigs', note: 'Elgamal, DSA and Schnorr.' },
      { exercise: 'dlp-x-dsa-sign', note: 'Sign with toy DSA.' },
      { topic: 'p09-dsa-nonce', note: 'Why a nonce is never reused.' },
      { exercise: 'dlp-x-nonce-rule', note: 'Sound ways to choose k.' },
      { topic: 'p09-bsgs', note: 'Square-root time, square-root memory.' },
      { topic: 'p09-rho', note: 'Square-root time, no memory.' },
      { exercise: 'dlp-x-code-bsgs', note: 'Write baby-step giant-step.' },
      { topic: 'p09-pohlig', note: 'Why the order is prime.' },
      { topic: 'p09-index', note: 'Why p is long.' },
      { exercise: 'dlp-x-levels', note: 'Sizes for each level.' },
      { topic: 'p09-small-subgroup', note: 'Why received values are checked.' },
      { exercise: 'dlp-x-code-check', note: 'Write the check.' },
    ],
  });

  // ---- what the diagram checker looks at on these pages -----------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'dlp lesson dlp-what')) {
    const ready = (sel) => "document.querySelector('" + sel + "')";
    for (const ch of C.chapters.filter((c) => c.part === 'dlp')) for (const id of ch.lessons) S.Checks.push({ group: 'learn', name: 'dlp lesson ' + id, hash: 'lesson=' + id, ready: ready('#lessonView'), sel: '#main' });
    for (const id of ['dlp-x-dsa-sign', 'dlp-x-code-bsgs', 'dlp-x-subgroup-fix']) S.Checks.push({ group: 'learn', name: 'dlp exercise ' + id, hash: 'exercise=' + id, ready: ready('#exerciseView'), sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'dlp course', hash: 'course=dlp-course', ready: ready('#courseView'), sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
