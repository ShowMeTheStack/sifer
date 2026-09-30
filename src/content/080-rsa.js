// Part 8, RSA: the chapters and the lessons. The exercises, the part's tour and its course are in 081-rsa-ex.js.
// The lessons build the scheme (key generation, encryption, why decryption
// works), make it fast (square-and-multiply, the ladder, Montgomery, the CRT, small e), show why textbook RSA must be
// padded, and end with the standard attacks on weak or misused keys, each run on parameters the tool generates. Every
// number quoted was read off the topics' own narration for the inputs given, or worked out by S.RSA and S.NT.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('rsa-keygen')) return;
  const X = (id) => ({ exercise: id });

  C.chapter({ id: 'rsa-scheme', part: 'rsa', n: 1, title: 'The scheme', blurb: 'Two random primes, a public exponent and its inverse; encryption and decryption as powers modulo n, and Euler\'s theorem, which makes them undo each other.' });
  C.chapter({ id: 'rsa-speed', part: 'rsa', n: 2, title: 'Making it fast', blurb: 'Square-and-multiply and the Montgomery ladder, Montgomery multiplication, decryption by the Chinese remainder theorem, and why e = 65537.' });
  C.chapter({ id: 'rsa-padding', part: 'rsa', n: 3, title: 'Padding', blurb: 'Textbook RSA is deterministic and malleable. OAEP for encryption and PSS for signatures add randomness and structure that is checked.' });
  C.chapter({ id: 'rsa-attacks', part: 'rsa', n: 4, title: 'Attacks on weak keys', blurb: 'Cube roots, Håstad\'s broadcast, a shared modulus, a small private exponent, close primes, shared primes and one faulty signature: each breaks a key that was made or used carelessly.' });

  // =========================================================================================================
  // Chapter 1: the scheme
  // =========================================================================================================
  C.lesson({
    id: 'rsa-keygen', chapter: 'rsa-scheme', title: 'Making an RSA key', minutes: 9,
    summary: 'Draw two random primes p and q of half the modulus length, testing candidates with trial division and Miller–Rabin. Then n = p·q, φ(n) = (p − 1)(q − 1), a public exponent e with no factor in common with φ(n), and d = e⁻¹ mod φ(n).',
    blocks: [
      'An RSA key is a handful of numbers that all come from two secret primes. Where do the primes come from? Nobody keeps a list of 1024-bit primes: there are about 2¹⁰¹⁴ of them. The key generator draws random odd numbers of the right size and keeps the first ones that pass a primality test.',
      { topic: 'p08-keygen', frame: 1, caption: 'A 24-bit toy key: the first candidate, 3105, is divisible by 3. Trial division by small primes throws out most candidates cheaply.' },
      { topic: 'p08-keygen', frame: 8, caption: 'The eighth candidate, 3877, survives trial division and passes every Miller–Rabin round: p = 3877.' },
      { topic: 'p08-keygen', frame: 10, caption: 'q = 3257 is found after one more candidate. Nine candidates in all, and only two needed the expensive test.' },
      { predict: { q: 'The generator uses e = 3. It finds that 211 is prime. Why would it still throw 211 away?', options: ['211 is too small', '211 − 1 = 210 is divisible by 3, so e would share a factor with φ(n)', 'Primes ending in 1 are weak', 'It would not: 211 is kept'], answer: 1, explain: 'φ(n) = (p − 1)(q − 1) would then be a multiple of 3, and e = 3 would have no inverse modulo φ(n): there would be no d. So the generator insists that gcd(e, p − 1) = 1.' } },
      { topic: 'p08-keygen', input: { bits: '16', e: '3', seed: 12 }, frame: 2, caption: 'With e = 3: 211 is prime, but 210 is a multiple of 3, so it is drawn again.' },
      { h: 'From the primes to the key' },
      { topic: 'p08-keygen', frame: 12, caption: 'n = 3877·3257 = 12627389 and φ(n) = 3876·3256 = 12620256.' },
      { topic: 'p08-keygen', frame: 14, caption: 'd = e⁻¹ mod φ(n) by extended Euclid: 11 rows give d = 10131329, and e·d ≡ 1 (mod φ(n)).' },
      { topic: 'p08-keygen', frame: 15, caption: 'Three more numbers for fast decryption: dp = d mod (p − 1), dq = d mod (q − 1) and qinv = q⁻¹ mod p.' },
      { math: 'n = p·q                      public\ne,  gcd(e, φ(n)) = 1           public\nφ(n) = (p − 1)(q − 1)         secret\nd = e⁻¹ mod φ(n)              secret\ndp, dq, qinv                  secret, for the CRT' },
      { tip: 'Standards often use λ(n) = lcm(p − 1, q − 1) in place of φ(n). The d it gives is smaller but works the same way, since every message\'s order divides λ(n).' },
      { bench: 'pk', state: { tool: 'rsa', rsa: { size: 'toy', p: '157', q: '211', e: '11', msgKind: 'number', msg: '2026', pad: 'textbook' } }, text: 'Build a toy key from primes you choose, or search for a real 2048-bit one in a worker.' },
      { h: 'Recap' },
      { list: ['Primes come from random odd candidates: trial division first, then Miller–Rabin.', 'gcd(e, p − 1) = gcd(e, q − 1) = 1, or e has no inverse.', 'd = e⁻¹ mod φ(n) by extended Euclid; dp, dq and qinv are kept for the CRT.', 'p, q, φ(n) and d are secret, and any one of them gives the others away.'] },
      X('rsa-x-keygen-d'), X('rsa-x-bad-e'), X('rsa-x-keygen-table'), X('rsa-x-candidates'), X('rsa-x-mr-table'), X('rsa-x-code-mr'),
    ],
  });

  C.lesson({
    id: 'rsa-encdec', chapter: 'rsa-scheme', title: 'Encryption and decryption', minutes: 7,
    summary: 'c = m^e mod n with the public key, m = c^d mod n with the private one, for a message m below n. Encryption with a small e is cheap; decryption with a full-length d costs much more. Toy and real keys run exactly the same formulas.',
    blocks: [
      'The key is made. What does it cost to use it, and is the toy version really the same as the one in a browser? Take a toy key and the message 2026.',
      { topic: 'p08-encdec', frame: 1, caption: 'Encrypting with e = 65537 = 2¹⁶ + 1: 16 squarings and 1 multiplication.' },
      { topic: 'p08-encdec', frame: 3, caption: 'Decrypting with a 20-bit d: 19 squarings and 8 multiplications, about twice the work. At 2048 bits the gap is much larger.' },
      { predict: { q: 'What is the textbook RSA encryption of m = 1, with any key?', options: ['1', 'e', 'n − 1', 'It depends on n'], answer: 0, explain: '1 to any power is 1. The same holds for 0, and n − 1 ≡ −1 goes to −1 since e is odd. These fixed messages are one more sign that raw RSA must never be applied to bare messages.' } },
      { topic: 'p08-encdec', input: { key: 'toy', msg: '1' }, frame: 2, caption: 'c = 1: the message does not move.' },
      { h: 'Toy and real side by side' },
      { topic: 'p08-sizes', frame: 3, caption: 'n = 89·97 = 8633 next to a modulus of 617 digits. Anyone can factor the first; nobody can factor the second.' },
      { topic: 'p08-sizes', frame: 9, caption: 'The same formula decrypts both. The toy key took 12 squarings and 7 multiplications; the real one 2046 squarings and 969 multiplications on 2048-bit numbers.' },
      { warn: 'Every secret number is equivalent to the factors. From n and φ(n), p + q = n − φ(n) + 1 and p, q are the roots of a quadratic. From n, e and d, the multiple e·d − 1 of φ(n) lets anyone factor n with a few random tries. Leaking d is losing the key, not one message.' },
      { h: 'Recap' },
      { list: ['c = m^e mod n and m = c^d mod n, for 0 ≤ m < n.', 'A short e makes encryption cheap; a full-length d makes decryption the expensive side.', 'n and φ(n), or n, e and d, are enough to factor n.'] },
      X('rsa-x-encrypt'), X('rsa-x-decrypt'), X('rsa-x-lambda'), X('rsa-x-secrets'),
    ],
  });

  C.lesson({
    id: 'rsa-why', chapter: 'rsa-scheme', title: 'Why decryption works', minutes: 7,
    summary: 'The powers of m modulo n go round a cycle whose length divides φ(n). Since e·d = 1 + k·φ(n), raising to e and then to d goes round whole laps and one step more, landing on m. Messages that share a factor with n come back too, by the same argument modulo p and modulo q.',
    blocks: [
      'Raising to e scrambles m; raising to d unscrambles it. Why should two exponentiations undo each other at all? Watch the powers of one message go round.',
      { topic: 'p08-why', frame: 1, caption: 'n = 91: the powers of m = 6 run round a cycle of length 12 and are back at 1 after 6¹².' },
      { topic: 'p08-why', frame: 2, caption: '12 divides φ(91) = 72, so m⁷² is 6 whole laps: m^φ(n) ≡ 1. That is Euler\'s theorem.' },
      { predict: { q: 'Here e = 5 and d = 29, so e·d = 145. Where does m^145 land on the cycle of length 12?', options: ['At 1', 'At m', 'At m⁵', 'At m¹²'], answer: 1, explain: '145 = 12·12 + 1: twelve whole laps and one step, so m¹⁴⁵ = m. That is decryption.' } },
      { topic: 'p08-why', frame: 4, caption: 'Decrypting raises m to e·d = 145 = 12·12 + 1: whole laps change nothing, and one step lands on m = 6.' },
      { math: 'e·d = 1 + k·φ(n)\nm^(e·d) = m·(m^φ(n))^k ≡ m·1^k = m   (mod n)' },
      { topic: 'p08-why', frame: 5, caption: 'A message sharing a factor with n has no cycle through 1, yet 13¹⁴⁵ mod 91 = 13 still: the argument works modulo p and modulo q separately, and the CRT joins them.' },
      { topic: 'p08-why', input: { p: '5', q: '11', e: '3', m: '2' }, frame: 4, caption: 'n = 55, e = 3, d = 27: the powers of 2 have a cycle of 20, and 81 = 4·20 + 1.' },
      { h: 'Recap' },
      { list: ['The order of m divides φ(n) (Lagrange), so m^φ(n) ≡ 1 for m coprime to n.', 'e·d ≡ 1 (mod φ(n)) makes m^(ed) ≡ m.', 'For every m, including multiples of p or q, the same holds modulo p and modulo q, hence modulo n.'] },
      X('rsa-x-fixed'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: making it fast
  // =========================================================================================================
  C.lesson({
    id: 'rsa-sqm', chapter: 'rsa-speed', title: 'Square-and-multiply and the ladder', minutes: 8,
    summary: 'Read the exponent in binary: square once per bit and multiply by x for every 1 bit. A k-bit exponent costs about k squarings and k/2 multiplications. The Montgomery ladder does one of each per bit, whatever the bit, so its pattern does not show the exponent.',
    blocks: [
      'A 2048-bit private exponent is a number with 617 digits. Multiplying by c that many times is out of the question: there are more steps than atoms in the universe. Yet a laptop decrypts in a millisecond. The trick is to read the exponent\'s bits.',
      { topic: 'p08-sqm', frame: 0, caption: '7^2989 mod 10403: e = 101110101101 in binary, 12 bits.' },
      { topic: 'p08-sqm', frame: 3, caption: 'Bit 2 is 1: from the left, square and then multiply by 7; from the right, x⁴ is multiplied into the product.' },
      { topic: 'p08-sqm', frame: 13, caption: 'Both ends reach 8587 with 11 squarings and 7 multiplications, where repeated multiplication would need 2988.' },
      { predict: { q: 'How many multiplications (not counting squarings) does the left-to-right loop need for e = 4096 = 2¹²?', options: ['0', '1', '12', '4095'], answer: 0, explain: '4096 is a 1 followed by twelve 0s. The leading 1 just starts the value at x, and the zeros only square: 12 squarings and no multiplications.' } },
      { topic: 'p08-sqm', input: { x: '5', e: '4096', n: '9973' }, frame: 14, caption: 'e = 4096: 12 squarings and 0 multiplications.' },
      { h: 'A pattern that leaks, and one that does not' },
      'The loop multiplies only when a bit is 1. If an observer can tell squarings from multiplications, by timing or by the power a chip draws, the sequence S, SM, SM, S, … spells out the exponent. Part 15 reads a key from exactly such a power trace.',
      { topic: 'p08-ladder', frame: 2, caption: 'The ladder on a 0 bit: R1 = R0·R1 and R0 = R0², one multiplication and one squaring; on a 1 bit the registers swap roles.' },
      { topic: 'p08-ladder', frame: 13, caption: 'The same 8587 with 12 squarings and 12 multiplications: a little more work, but the same M S M S … for every exponent.' },
      { sandbox: 'square-multiply' },
      { h: 'Recap' },
      { list: ['Left to right: start at x for the leading 1; then square for each bit, and multiply by x for each 1 bit.', 'Cost: one squaring per bit after the first, one multiplication per 1 bit after the first.', 'The ladder does one of each per bit, so its sequence of operations does not depend on the exponent.'] },
      X('rsa-x-sqm-count'), X('rsa-x-sqm-table'), X('rsa-x-code-sqm'), X('rsa-x-ladder'),
    ],
  });

  C.lesson({
    id: 'rsa-montgomery', chapter: 'rsa-speed', title: 'Montgomery multiplication', minutes: 7,
    summary: 'Every step of an exponentiation reduces a double-length product modulo n, which needs a division. Montgomery multiplication replaces the division by n with a division by R = 2^k, a shift, by working with numbers in the form a·R mod n.',
    blocks: [
      'Square-and-multiply makes a few thousand multiplications. Each product of two 2048-bit numbers has up to 4096 bits and must be reduced modulo n, which is a long division, the slowest thing a processor does with big numbers. Can the division be avoided?',
      { topic: 'p08-montmul', frame: 0, caption: 'n = 97, so R = 2⁷ = 128, the power of two just above n. n′ = −n⁻¹ mod R = 95 is computed once per modulus.' },
      { topic: 'p08-montmul', frame: 3, caption: 'Only the low 7 bits of t = ā·b̄ matter: m = (t mod R)·n′ mod R = 116. Masks and multiplications, no division.' },
      { topic: 'p08-montmul', frame: 4, caption: 't + m·n ends in 7 zero bits, and adding a multiple of n changes nothing modulo n.' },
      { predict: { q: 'What does dividing t + m·n by R give, modulo n?', options: ['a·b', 'a·b·R', 'a·b·R⁻¹', 'a·b·R²'], answer: 1, explain: 't = ā·b̄ = a·b·R², and dividing by R leaves a·b·R: the Montgomery form of the product, ready for the next multiplication.' } },
      { topic: 'p08-montmul', frame: 7, caption: 'Leaving Montgomery form at the end gives 25 = 45·76 mod 97, with no division by n anywhere.' },
      { tip: 'The final subtraction (when the result is at least n) is taken for some inputs and not others. In a careless implementation that shows up in the timing, which is why constant-time code always computes it and selects with a mask.' },
      { h: 'Recap' },
      { list: ['Montgomery form: ā = a·R mod n with R = 2^k > n.', 'MonPro(ā, b̄) = ā·b̄·R⁻¹ mod n, using only multiplications, masks and a shift.', 'Convert in once, run the whole exponentiation in this form, and convert out once.'] },
      X('rsa-x-montmul'),
    ],
  });

  C.lesson({
    id: 'rsa-crt', chapter: 'rsa-speed', title: 'Decryption with the CRT', minutes: 8,
    summary: 'The key holder knows p and q, so she decrypts modulo each with exponents dp and dq of half the length, and joins the halves with Garner\'s formula m = mq + q·(qinv·(mp − mq) mod p). It is about four times faster.',
    blocks: [
      'Decryption is the expensive side of RSA. The person decrypting holds the factors of n, which nobody else has. Can knowing p and q make the work smaller?',
      { topic: 'p08-crt', frame: 1, caption: 'Reduce the ciphertext modulo p and modulo q, and the exponent modulo p − 1 and q − 1: dp = 2049 and dq = 2133, half the size of d.' },
      { topic: 'p08-crt', frame: 2, caption: 'Two half-size exponentiations: mp = 297 and mq = 359.' },
      { topic: 'p08-crt', frame: 3, caption: 'Garner\'s formula: h = qinv·(mp − mq) mod p = 2542, with qinv = q⁻¹ mod p stored in the key.' },
      { topic: 'p08-crt', frame: 4, caption: 'm = mq + h·q = 7654321. It leaves 297 modulo p and 359 modulo q, as the halves require.' },
      { math: 'dp = d mod (p − 1),  dq = d mod (q − 1),  qinv = q⁻¹ mod p\nmp = c^dp mod p,     mq = c^dq mod q\nh  = qinv·(mp − mq) mod p\nm  = mq + h·q' },
      { predict: { q: 'Each half has an exponent half as long, on numbers half as long. Roughly how much faster is the CRT than c^d mod n?', options: ['2 times', '4 times', '8 times', '16 times'], answer: 1, explain: 'Each half does half the squarings, each on numbers half as long and so about a quarter of the cost: 1/8 of the work. Two halves make 1/4, so about 4 times faster.' } },
      { topic: 'p08-crt', input: { key: 'rsa2048', m: '9876543210987654321' }, frame: 5, caption: 'RSA-2048: 3015 operations on 2048-bit numbers, against 1547 and 1544 on 1024-bit numbers, about 3.9 times faster.' },
      { warn: 'The speed has a price: p and q must be kept in the device, and if a fault corrupts one half, the result gives the factors away. The last lesson of this part runs that attack.' },
      { sandbox: 'crt' },
      { h: 'Recap' },
      { list: ['Decrypt modulo p and modulo q with dp and dq, then join the halves.', 'Garner: m = mq + q·(qinv·(mp − mq) mod p).', 'About 4 times faster than c^d mod n.'] },
      X('rsa-x-crt-table'), X('rsa-x-code-inverse'), X('rsa-x-code-garner'), X('rsa-x-crt-speed'),
    ],
  });

  C.lesson({
    id: 'rsa-small-e', chapter: 'rsa-speed', title: 'Small public exponents', minutes: 5,
    summary: 'e can be small, which makes encryption and verification cheap: e = 3 costs 2 operations, e = 65537 costs 17. A small d is a different matter: it can be recovered from e and n. 65537 is the usual choice, because e = 3 makes the unpadded attacks easy.',
    blocks: [
      'The public exponent only has to share no factor with φ(n). The smaller it is, the faster everyone who encrypts or verifies a signature works. So why does almost every key use e = 65537 and not e = 3?',
      { topic: 'p08-small-e', frame: 0, caption: 'e = 3 = 11 in binary: 2 operations, the cheapest possible.' },
      { topic: 'p08-small-e', frame: 2, caption: 'e = 65537 = 2¹⁶ + 1: 17 operations, still almost free.' },
      { predict: { q: 'A colleague suggests making d small instead, to speed up decryption. Is that as safe as a small e?', options: ['Yes, it is the same trade the other way round', 'No: a small d can be found from e and n alone', 'Yes, if e is then large'], answer: 1, explain: 'A d below about n^¼/3 is recovered from the continued fraction of e/n (Wiener\'s attack, in chapter 4). Speed up decryption with the CRT instead.' } },
      { topic: 'p08-small-e', frame: 4, caption: 'Decrypting with a 2047-bit d takes 3015 operations, about 177 times the cost of encrypting with 65537.' },
      'e = 3 is not broken in itself. It is dangerous because it makes mistakes fatal: a short message without padding is read off by an ordinary cube root, and the same message sent to three people is recovered by the CRT. Both are in chapter 4.',
      { h: 'Recap' },
      { list: ['A small e is safe and fast; 65537 is the usual choice.', 'e = 3 works with proper padding, but turns padding mistakes into breaks.', 'A small d is never safe.'] },
      X('rsa-x-small-e'),
    ],
  });

  // =========================================================================================================
  // Chapter 3: padding
  // =========================================================================================================
  C.lesson({
    id: 'rsa-malleable', chapter: 'rsa-padding', title: 'Textbook RSA is not secure', minutes: 8,
    summary: 'Raw RSA is deterministic, so anyone can test guesses by encrypting them, and multiplicative, so anyone can turn an encryption of m into an encryption of s·m. Both are fatal for real messages.',
    blocks: [
      'An auction house takes sealed bids encrypted with its public key and no padding. The bids are numbers, and the auction house decrypts them at the close. What can someone on the network do with a sealed bid, without the private key?',
      { topic: 'p08-malleable', frame: 1, caption: 'Anyone can encrypt: the attacker computes 3^e mod n with the public key.' },
      { topic: 'p08-malleable', frame: 2, caption: 'c′ = c·3^e mod n is a valid encryption of 3·m, since m^e·3^e = (3m)^e.' },
      { topic: 'p08-malleable', frame: 3, caption: 'The auction house decrypts 1260: the bid was tripled, and nothing looked wrong.' },
      { predict: { q: 'A vote is encrypted as 0 or 1 with textbook RSA, e = 65537. How hard is it to read the vote from the ciphertext?', options: ['As hard as factoring n', 'Two encryptions with the public key', 'Impossible without d', 'It needs the CRT'], answer: 1, explain: 'Encryption is deterministic: encrypt 0 and 1 yourself and compare. Here it is even simpler, since 0 and 1 are their own encryptions.' } },
      { topic: 'p08-malleable', frame: 4, caption: 'Deterministic: encrypt each guess and compare. The guess 420 gives exactly c.' },
      { h: 'A decryption service helps the attacker too' },
      'Suppose a server decrypts anything except the one ciphertext you want. Send it c·2^e mod n instead. It decrypts to 2m mod n, which looks unrelated, and you divide by 2 modulo n. This chosen-ciphertext attack is why a decryption must reject anything that does not have the right structure.',
      { topic: 'p08-malleable', frame: 5, caption: 'The cure for both: padding that is random and checked.' },
      { h: 'Recap' },
      { list: ['Deterministic: equal messages give equal ciphertexts, and guesses can be tested.', 'Malleable: c·s^e mod n decrypts to s·m mod n.', 'Never use RSA without a padding scheme: OAEP to encrypt, PSS to sign.'] },
      X('rsa-x-malleable'), X('rsa-x-deterministic'), X('rsa-x-blind'),
    ],
  });

  C.lesson({
    id: 'rsa-oaep', chapter: 'rsa-padding', title: 'OAEP and PSS', minutes: 9,
    summary: 'OAEP fills the block with the message, a hash of a label, zeros and a separator, and masks it all with two rounds of MGF1 driven by a fresh random seed. Each encryption is different, and a changed ciphertext fails the checks. PSS does the same job for signatures with a salt.',
    blocks: [
      'The fix for raw RSA must do two things: make every encryption of the same message different, and make it impossible to change a ciphertext into another valid one. OAEP, Optimal Asymmetric Encryption Padding, does both with a random seed and two masks.',
      { topic: 'p08-oaep', frame: 0, caption: 'RSA-1024: k = 128 bytes. OAEP with SHA-256 reserves 66 of them, so a 27-byte message fits with 35 to spare.' },
      { topic: 'p08-oaep', frame: 3, caption: 'DB = lHash ‖ PS ‖ 01 ‖ M: the label\'s hash, zero bytes, a separator and the message, 95 bytes.' },
      { topic: 'p08-oaep', frame: 6, caption: 'maskedDB = DB ⊕ MGF1(seed): the zeros, the 01 and the message vanish into bytes that look random.' },
      { topic: 'p08-oaep', frame: 8, caption: 'maskedSeed = seed ⊕ MGF1(maskedDB). To find the seed you need all of maskedDB; to unmask DB you need the seed.' },
      { predict: { q: 'The same message is encrypted twice with OAEP. How many of the 128 bytes of the encoded block would you expect to differ?', options: ['None: it is the same message', 'Only the seed\'s 32 bytes', 'Almost all of them', 'Exactly half'], answer: 2, explain: 'A new seed changes the mask over DB, which changes maskedDB, which changes the mask over the seed. Everything but the leading 00 changes.' } },
      { topic: 'p08-oaep', frame: 11, caption: 'One bit of the seed flipped: 127 of the 128 bytes change.' },
      { topic: 'p08-oaep', frame: 10, caption: 'Decryption reverses the two rounds and checks lHash, the zeros and the 01. A tampered ciphertext almost surely fails.' },
      { h: 'PSS for signatures' },
      { topic: 'p08-pss', frame: 4, caption: 'PSS builds a block from a salted hash H and DB = zeros ‖ 01 ‖ salt, masked with MGF1(H).' },
      { topic: 'p08-pss', frame: 8, caption: 'Change one character of the message and the hash no longer matches: rejected. Two signatures can no longer be multiplied into a third.' },
      { warn: 'The older PKCS#1 v1.5 encryption padding is still found in the wild. A server that reveals whether a decrypted block was well-formed gives an oracle that decrypts any ciphertext with about a million queries. Use OAEP, and give the same error for every failure.' },
      { h: 'Recap' },
      { list: ['OAEP: EM = 00 ‖ maskedSeed ‖ maskedDB, two MGF1 rounds keyed by a fresh seed.', 'With SHA-256, a k-byte modulus holds at most k − 66 bytes of message.', 'PSS signs a salted hash; the verifier recomputes it from the block.'] },
      X('rsa-x-oaep-table'), X('rsa-x-oaep-why'), X('rsa-x-pss-why'),
    ],
  });

  // =========================================================================================================
  // Chapter 4: attacks on weak keys
  // =========================================================================================================
  C.lesson({
    id: 'rsa-roots', chapter: 'rsa-attacks', title: 'Why RSA needs padding: small e', minutes: 8,
    summary: 'With e = 3 and no padding, a short message has m³ < n, so c is m³ as an ordinary integer and no key protects it. The same message sent to three people with e = 3 is exposed too, because the three ciphertexts together fix m³ exactly. Random padding (OAEP) removes both weaknesses.',
    blocks: [
      'RSA\'s security comes from the reduction modulo n: m^e wraps round n many times and the wrapping hides m. What if it never wraps?',
      { topic: 'p08-small-e-attack', frame: 1, caption: 'RSA-2048, e = 3, a 223-bit message: m³ has 669 bits, far fewer than n. "mod n" did nothing.' },
      { topic: 'p08-small-e-attack', frame: 2, caption: 'The outcome: c is m³ over the integers, so the plaintext is recovered without d and without factoring n.' },
      { predict: { q: 'A toy key with n = 1050589 encrypts m = 113 with e = 3. 113³ is a little larger than n, so it wrapped once. Is the message safe?', options: ['Yes: it wrapped, so the reduction hides it', 'No: a ciphertext that wrapped only a few times is still nearly an ordinary integer', 'Only with d'], answer: 1, explain: 'A handful of wraps hides nothing; only a message whose cube wraps round n an astronomical number of times is protected, and padding is what guarantees that.' } },
      { topic: 'p08-small-e-attack', input: { key: 'toy', msg: '113' }, frame: 2, caption: 'm³ wrapped round n only once: still exposed.' },
      { topic: 'p08-small-e-attack', frame: 3, caption: 'The defence: OAEP makes every encoded message as long as n and random, so its cube wraps round n about 2^4096 times.' },
      { h: 'One message to three people' },
      'Now the message is longer than a third of the modulus, so one ciphertext is safe. But the sender broadcasts it to three people, each with e = 3 and their own modulus. Each ciphertext says what m³ is modulo one nᵢ.',
      { topic: 'p08-hastad', frame: 3, caption: 'Each ciphertext alone is as hard as RSA: m³ wrapped round each modulus.' },
      { topic: 'p08-hastad', frame: 4, caption: 'But m is below every nᵢ, so m³ is below n₁n₂n₃, and three remainders fix it exactly: the message is recovered with no private key.' },
      { topic: 'p08-hastad', frame: 5, caption: 'The defence: a fresh random seed per copy makes the three encrypted numbers different, and there is no common m³.' },
      { h: 'Recap' },
      { list: ['e = 3 and m³ < n (or only a few wraps): c is no protection at all.', 'e copies of one unpadded message under e different moduli expose it as well.', 'Random padding defeats both: every copy is a different, full-length number. With padding, e = 65537 is the usual choice.'] },
      X('rsa-x-cube-why'), X('rsa-x-cube-size'), X('rsa-x-hastad-why'),
    ],
  });

  C.lesson({
    id: 'rsa-misuse', chapter: 'rsa-attacks', title: 'A shared modulus and a small d', minutes: 8,
    summary: 'Two exponents on one modulus let anyone read a message sent to both, from public values alone, and let either key holder factor n. A private exponent below about n^¼/3 is given away by the public key. Each key pair gets its own modulus, and d is always full length.',
    blocks: [
      'An office decides to save on key generation: one modulus n for everyone, each person with their own exponent pair. Each person\'s d is safe from the others, isn\'t it? And a smart card, slow at private-key work, uses a small d to sign faster. Both choices break the key.',
      { h: 'A common modulus' },
      { topic: 'p08-common-modulus', frame: 0, caption: 'The same m = 271828 is sent under e₁ = 17 and e₂ = 65537 with the same n.' },
      { predict: { q: 'An eavesdropper has n, e₁, e₂, c₁ and c₂ and no private key. gcd(e₁, e₂) = 1. Can they read m?', options: ['No: they need d', 'Yes: the two powers of one m under one n can be combined into m', 'Only if e₁ = 3', 'Only by factoring n'], answer: 1, explain: 'With coprime exponents the public values alone give m. And any employee holding their own (e, d) on n can factor n outright.' } },
      { topic: 'p08-common-modulus', frame: 2, caption: 'The message, without d. And worse: anyone who holds one key pair on n can factor n and compute every other d.' },
      { topic: 'p08-common-modulus', frame: 3, caption: 'The defence: one modulus per key pair, from its own fresh primes.' },
      { h: 'A small private exponent' },
      'e·d = 1 + k·φ(n), and φ(n) is close to n. So e/n is very close to k/d. When d is small, that closeness is enough for the public key alone to give d away.',
      { topic: 'p08-wiener', frame: 0, caption: 'A 64-bit n and a 62-bit e: an e nearly as long as n is what you get when a small d was chosen first.' },
      { topic: 'p08-wiener', frame: 2, caption: 'd is below n^¼/3: the public key alone reveals d and the factors.' },
      { topic: 'p08-wiener', input: { bits: '64', kind: 'normal', seed: 7 }, frame: 2, caption: 'With e = 65537 and a 64-bit d, far above n^¼/3, nothing is revealed.' },
      { topic: 'p08-wiener', frame: 3, caption: 'The defence: compute d from e = 65537, so it is full length, and get speed from the CRT.' },
      { h: 'Recap' },
      { list: ['Never share a modulus: two ciphertexts of one message leak it, and any one key pair factors n.', 'A d below about n^¼/3 is exposed by (n, e) alone.', 'Speed up the private side with the CRT, never with a small d.'] },
      X('rsa-x-common-why'), X('rsa-x-wiener-bound'),
    ],
  });

  C.lesson({
    id: 'rsa-weak-primes', chapter: 'rsa-attacks', title: 'Weak primes: close together, or shared', minutes: 8,
    summary: 'If p and q are close, n is nearly a square and Fermat\'s method factors it at once, whatever its size. If two keys share a prime, a greatest common divisor exposes it, and batch GCD finds every such key in a large collection. Both are failures of key generation.',
    blocks: [
      'Both factors of n are secret, but they also have to be random. Two failures of a key generator turn up again and again: a q chosen just after p, and two devices that drew the same prime. Neither needs a real factoring algorithm to exploit.',
      { h: 'Close primes' },
      { topic: 'p08-fermat', input: { size: 'toy', gap: 9 }, frame: 0, caption: 'n = 105363703 with primes about 2⁹ apart: n sits just above a square, n = a² − b² with b small.' },
      { predict: { q: 'Two 512-bit primes were chosen about 2²⁵⁹ apart. How much work does Fermat\'s method need to factor their 1024-bit product?', options: ['About 2²⁵⁹ steps', 'About 2⁵¹² steps', 'A handful of steps', 'It cannot work at that size'], answer: 2, explain: 'The work is about (q − p)²/(8√n) = 2⁵¹⁸/2⁵¹⁵ steps, about 8. Primes that agree in their top half are as good as published.' } },
      { topic: 'p08-fermat', frame: 2, caption: 'RSA-1024 with primes 2²⁵⁹ apart: factored after 10 steps.' },
      { topic: 'p08-fermat', frame: 3, caption: 'FIPS 186 requires |p − q| > 2^(nlen/2 − 100). Random primes are that far apart anyway; only a broken generator makes them close.' },
      { h: 'Shared primes' },
      { topic: 'p08-batch-gcd', frame: 0, caption: 'Eight public keys from devices with a weak random generator. Each looks fine alone.' },
      { topic: 'p08-batch-gcd', frame: 3, caption: 'A product tree: 7 multiplications give P, the product of all keys. Comparing every pair would take 28 gcds, and for a million keys about 5·10¹¹.' },
      { topic: 'p08-batch-gcd', frame: 4, caption: 'The outcome: n₇ and n₈ share a prime, so both are factored.' },
      { topic: 'p08-batch-gcd', frame: 5, caption: 'The defence is in key generation: a well-seeded generator before the first key.' },
      { tip: 'A device should never make its long-term key before its random generator has gathered enough entropy. Generating keys on first boot, from a fresh image, is exactly how real devices came to share primes.' },
      { h: 'Recap' },
      { list: ['Close primes: n is nearly a square, and the work to factor it depends on q − p, not on the size of n.', 'A prime shared by two keys is exposed by their gcd; batch GCD tests a whole collection at once.', 'Both are failures of key generation, cured by independent primes from a properly seeded random generator.'] },
      X('rsa-x-balanced'), X('rsa-x-fermat-gap'), X('rsa-x-shared-why'),
    ],
  });

  C.lesson({
    id: 'rsa-fault', chapter: 'rsa-attacks', title: 'One fault in CRT signing', minutes: 6,
    summary: 'A device that signs with the CRT and suffers a fault in one half sends out a signature that is right modulo one prime and wrong modulo the other. That one signature, with its message, factors n. The defence is to verify every signature before it leaves the device.',
    blocks: [
      'A smart card signs with RSA, using the CRT for speed. Someone holding the card can disturb it: a voltage spike, a flash of light, a heated chip. Most faults just produce a wrong signature. Why would one wrong signature be worse than useless?',
      { topic: 'p08-crt-fault', input: { size: 'toy', msg: '123456', half: 'q', bit: 2 }, frame: 1, caption: 'Done right: s_p = 513, s_q = 823, joined into s = 902638, and s^e mod n = m.' },
      { topic: 'p08-crt-fault', input: { size: 'toy', msg: '123456', half: 'q', bit: 2 }, frame: 2, caption: 'A glitch flips bit 2 of the half modulo q: s_q becomes 819. The half modulo p is untouched.' },
      { predict: { q: 'The faulty s′ is still right modulo p and wrong modulo q, and it leaves the card. What does it cost?', options: ['Nothing: it is just a wrong signature', 'The factors of n, and so the key', 'Only this one message', 'The next signature'], answer: 1, explain: 'A signature right modulo one prime and wrong modulo the other, with its message, is enough to factor n.' } },
      { topic: 'p08-crt-fault', frame: 4, caption: 'RSA-1024: one faulty signature and its message factor the modulus.' },
      { topic: 'p08-crt-fault', frame: 5, caption: 'The defence: verify every signature before it leaves the device. With e = 65537 the check costs 17 multiplications.' },
      { h: 'Recap' },
      { list: ['A fault in one CRT half gives s′ ≡ s modulo the other prime only.', 'One such signature with its message factors n.', 'Verify before releasing; randomised padding (PSS) also hides the m that was signed.'] },
      X('rsa-x-fault-why'),
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
