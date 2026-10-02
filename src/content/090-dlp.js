// Part 9, the discrete logarithm problem: the chapters and the lessons. The exercises, the part's tour and its course
// are in 091-dlp-ex.js. The lessons pose the problem in Z_p*, build Diffie–Hellman, Elgamal and the signatures of the
// Elgamal family on it, and end with the rules for choosing a group: each rule is explained by the attack it shuts out
// (baby-step giant-step and rho, Pohlig–Hellman, index calculus, small subgroups). Every number quoted was read off the
// topics' own narration for the inputs given, or worked out by S.NT, S.DLP and S.SIG.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('dlp-what')) return;
  const X = (id) => ({ exercise: id });

  C.chapter({ id: 'dlp-problem', part: 'dlp', n: 1, title: 'The problem', blurb: 'Powers modulo a prime are easy to compute and hard to undo. Generators, the order of an element, and the subgroups an element can live in.' });
  C.chapter({ id: 'dlp-exchange', part: 'dlp', n: 2, title: 'Agreeing and encrypting', blurb: 'Diffie–Hellman key agreement, why it must be authenticated, and Elgamal encryption with a fresh nonce for every message.' });
  C.chapter({ id: 'dlp-sign', part: 'dlp', n: 3, title: 'Signatures', blurb: 'Elgamal, DSA and Schnorr signatures, and the one rule they all share: a nonce is never used twice and never predictable.' });
  C.chapter({ id: 'dlp-params', part: 'dlp', n: 4, title: 'Choosing the group', blurb: 'Why the group order is a large prime, why the prime p has 2048 bits while the exponents have 224, and why a received value is checked before it is used.' });

  // =========================================================================================================
  // Chapter 1: the problem
  // =========================================================================================================
  C.lesson({
    id: 'dlp-what', chapter: 'dlp-problem', title: 'Logarithms that wrap round', minutes: 7,
    summary: 'In Z_p*, computing h = g^x mod p takes a few hundred multiplications by square-and-multiply. Going back from h to x, the discrete logarithm, has no such shortcut: the powers of a generator visit the residues in an order that looks random.',
    blocks: [
      'Over the real numbers, 2^x = 21 is solved by a logarithm: x ≈ 4.39. Modulo a prime the powers of 2 wrap round, and the same question, which power of 2 is 21 modulo 29, has no formula at all. Watch the powers hop round the ring.',
      { topic: 'p09-dlp', frame: 0, caption: 'Z_29* drawn as a ring of 28 residues. g = 2 is a generator, and h = 21 is published.' },
      { topic: 'p09-dlp', frame: 5, caption: 'g⁵ = 16·2 mod 29 = 3: the hop from 16 wrapped round, 13 places away. Small powers climb; then the reduction scatters them.' },
      { topic: 'p09-dlp', frame: 11, caption: 'g¹⁷ = 21 = h, so x = 17, found by trying 17 powers.' },
      { predict: { q: 'For a generator of Z_29*, at most how many powers does trying them one by one need before any h is found?', options: ['About √28, 6', '28', '29', '14 on every h'], answer: 1, explain: 'The powers g¹ … g²⁸ are all 28 residues, each once. In the worst case h is the last one tried; on average half that. At real size, 28 becomes 2²⁰⁴⁷.' } },
      { topic: 'p09-dlp', frame: 12, caption: 'All 28 powers: each residue once, in an order with no visible pattern.' },
      { topic: 'p09-dlp', frame: 13, caption: 'Contrast: the same-sized group written additively, Z_28 under +. There the "logarithm" of 17 is 17 at once. Hardness is a property of how a group is written, not of its size alone.' },
      { h: 'At real size' },
      { topic: 'p09-dlp', input: { size: 'real', seed: 9 }, frame: 1, caption: 'The 2048-bit MODP group of RFC 3526: one forward power is 2044 squarings and 1036 multiplications.' },
      { topic: 'p09-dlp', input: { size: 'real', seed: 9 }, frame: 2, caption: 'Backwards: 2²⁰⁴⁷ tries one by one, 2¹⁰²³ by the best generic methods, about 2¹¹⁷ by the number field sieve. Chapter 4 explains each figure.' },
      { math: 'given p, g and h = g^x mod p, find x        (the discrete logarithm problem)\ngiven g^a and g^b, find g^(ab)              (the Diffie–Hellman problem)' },
      { h: 'Recap' },
      { list: ['Forwards: g^x mod p by square-and-multiply, about 1.5 multiplications per bit of x.', 'Backwards: no known method is fast for a well-chosen group of the right size.', 'The hardness depends on the group and how it is written: Z_p*, a subgroup of it, or an elliptic curve.'] },
      X('dlp-x-powers'), X('dlp-x-order'),
    ],
  });

  C.lesson({
    id: 'dlp-groups', chapter: 'dlp-problem', title: 'Generators, orders and subgroups', minutes: 7,
    summary: 'The order of g is the smallest k with g^k = 1. It divides p − 1 (Lagrange), and g generates Z_p* exactly when its order is p − 1. An element of smaller order lives in a smaller subgroup, and only the elements of that subgroup have a logarithm to its base.',
    blocks: [
      'Is every base as good as every other? Take p = 23 and the base 4 instead of a generator.',
      { topic: 'p09-dlp', input: { p: 23, g: 4, x: 6 }, frame: 0, caption: 'Z_23* has 22 residues, but the powers of 4 return to 1 after 11 steps.' },
      { topic: 'p09-dlp', input: { p: 23, g: 4, x: 6 }, frame: 6, caption: 'g⁶ = 2 = h, so x = 6 to base 4.' },
      { topic: 'p09-dlp', input: { p: 23, g: 4, x: 6 }, frame: 7, caption: 'The powers of 4 visit only 11 of the 22 residues. Any h off that cycle, 5 for instance, has no logarithm to base 4.' },
      { predict: { q: 'In Z_23*, which orders can an element have?', options: ['Any number from 1 to 22', 'Only 1, 2, 11 and 22, the divisors of 22', 'Only 11 and 22', 'Only primes'], answer: 1, explain: 'The powers of g form a subgroup, and a subgroup\'s size divides the group\'s size (Lagrange). 22 = 2·11, so the orders are 1 (the element 1), 2 (the element 22 = −1), 11 or 22.' } },
      { math: 'ord(g) = smallest k > 0 with g^k ≡ 1 (mod p)\nord(g) divides p − 1\ng is a generator  ⇔  g^((p − 1)/r) ≢ 1 for every prime r dividing p − 1' },
      'The last line is how a program tests a generator without listing every power: if g^((p − 1)/r) = 1 for some prime r, the order of g divides (p − 1)/r and is too small. For p = 23 the tests are g² and g¹¹: for g = 4, 4¹¹ ≡ 1, so 4 is not a generator.',
      { tip: 'Real systems often work on purpose in a subgroup of prime order q, with q much smaller than p. Chapter 4 explains why a prime order is exactly what is wanted.' },
      { bench: 'nt', state: { tool: 'order', order: { a: '4', n: '23' } }, text: 'The order of 4 modulo 23, with the subgroup it generates. Try other bases and moduli.' },
      { h: 'Recap' },
      { list: ['The order of g divides p − 1; g is a generator when the order is exactly p − 1.', 'Test a generator with g^((p − 1)/r) for each prime r dividing p − 1.', 'An element of order q generates a subgroup of q elements, and logarithms to its base exist only inside it.'] },
      X('dlp-x-generators'), X('dlp-x-orders-set'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: agreeing and encrypting
  // =========================================================================================================
  C.lesson({
    id: 'dlp-dh', chapter: 'dlp-exchange', title: 'Diffie–Hellman key agreement', minutes: 8,
    summary: 'Alice sends g^a, Bob sends g^b, and both compute g^(ab): Alice as (g^b)^a, Bob as (g^a)^b. An eavesdropper sees g, g^a and g^b, and getting g^(ab) from them is believed as hard as a discrete logarithm.',
    blocks: [
      'Alice and Bob have never met and share no secret. Everything they send passes Eve. Can they still end up with a key Eve does not have? Start with paint.',
      { topic: 'p09-dh-paint', frame: 5, caption: 'Each stirs a secret colour into the other\'s mixture: common + b + a and common + a + b are the same colour K.' },
      { topic: 'p09-dh-paint', frame: 6, caption: 'Eve holds the common paint, A and B. Mixing A with B gives too much of the common paint: a different colour.' },
      { h: 'With numbers' },
      { topic: 'p09-dh', frame: 2, caption: 'p = 23, g = 5: A = 5⁶ mod 23 = 8 and B = 5¹⁵ mod 23 = 19.' },
      { topic: 'p09-dh', frame: 4, caption: 'Alice computes B^a, Bob A^b, and both get K = 2, since (g^b)^a = g^(ab) = (g^a)^b.' },
      { predict: { q: 'Eve multiplies the two public values: A·B mod 23. What does she get?', options: ['The key K = 2', 'g^(a+b) mod p, which is not the key', 'g^(ab) mod p', 'Nothing defined'], answer: 1, explain: 'g^a·g^b = g^(a+b). Mixing two pots adds the exponents; the key needs their product. Here A·B mod 23 = 14, not 2.' } },
      { topic: 'p09-dh-paint', frame: 8, caption: 'A·B = g^(a+b) mod p = 14, not the key 2.' },
      { topic: 'p09-dh', input: { size: 'real', seed: 7 }, frame: 2, caption: 'The same exchange in the 2048-bit MODP group: about 2040 squarings each, a few milliseconds.' },
      { topic: 'p09-dh', input: { size: 'real', seed: 7 }, frame: 5, caption: 'Eve\'s best known route is a discrete logarithm modulo a 2048-bit prime, about 2¹¹⁷ steps. K goes through a key-derivation function before it keys a cipher.' },
      { tip: 'TLS 1.3 draws fresh exponents for every connection (ephemeral Diffie–Hellman). A later theft of a server\'s long-term key then reveals nothing about past sessions: forward secrecy.' },
      { bench: 'pk', state: { tool: 'dh', dh: { group: 'toy', p: '211', g: '2', a: '37', b: '118', mitm: false, m: '99' } }, text: 'Run Diffie–Hellman with your own prime and secrets, or in the 2048-bit group.' },
      { h: 'Recap' },
      { list: ['Public: p, g, A = g^a, B = g^b. Secret: a, b and K = g^(ab).', 'Both sides compute K with one exponentiation each.', 'Eve faces the Diffie–Hellman problem; the best known way is a discrete logarithm.', 'Use fresh exponents per session and pass K through a KDF.'] },
      X('dlp-x-dh-pub'), X('dlp-x-dh-table'), X('dlp-x-dh-eve'), X('dlp-x-ephemeral'),
    ],
  });

  C.lesson({
    id: 'dlp-mitm', chapter: 'dlp-exchange', title: 'Why the exchange must be authenticated', minutes: 6,
    summary: 'Plain Diffie–Hellman says nothing about who sent g^a. Someone in the middle can run one exchange with Alice and another with Bob and relay everything. The defence is authentication: sign the exchanged values with keys whose owners are known.',
    blocks: [
      'Eve only listens. What if the attacker can also change what passes? Nothing in the exchange says where a number came from.',
      { topic: 'p09-dh-mitm', frame: 1, caption: 'Mallory keeps Alice\'s A = 8 and passes Bob her own M = 11.' },
      { topic: 'p09-dh-mitm', frame: 3, caption: 'Alice\'s key is M^a = 9 and Bob\'s is M^b = 10. Mallory computes both, as A^m and B^m.' },
      { predict: { q: 'Mallory solved no logarithm. Which change to the protocol stops her?', options: ['A larger prime p', 'Each side signs its value with a long-term key that the other already trusts, and checks the other\'s signature', 'Choosing a and b as safe primes', 'Sending A and B twice'], answer: 1, explain: 'Mallory\'s M carries no valid signature from Alice or from Bob, so the exchange stops. A larger p makes no difference, since nothing is being broken.' } },
      { topic: 'p09-dh-mitm', frame: 4, caption: 'She decrypts, reads and changes each message, and re-encrypts it under the other key. Nobody sees an error.' },
      { topic: 'p09-dh-mitm', frame: 5, caption: 'What failed is authentication. Signed exchanges with certified keys close the gap.' },
      { h: 'Recap' },
      { list: ['Unauthenticated Diffie–Hellman gives a key with someone, not with a known person.', 'A man in the middle runs two exchanges and relays.', 'The rule: authenticate the exchanged values (signatures, certificates, or a pre-shared key), as TLS 1.3 does.'] },
      X('dlp-x-mitm-fix'),
    ],
  });

  C.lesson({
    id: 'dlp-elgamal', chapter: 'dlp-exchange', title: 'Elgamal encryption', minutes: 7,
    summary: 'Elgamal is Diffie–Hellman with a one-sided key: the sender draws a fresh k, sends c1 = g^k and c2 = m·h^k. The receiver rebuilds the mask h^k = c1^x and divides it out. A fresh k makes every encryption different; reusing k, or leaving c2 unprotected, causes trouble.',
    blocks: [
      'Diffie–Hellman agrees a key with someone who is online. How do you encrypt to someone who is not? Bob publishes h = g^x once, and the sender does her half of an exchange with every message.',
      { topic: 'p09-elgamal', frame: 2, caption: 'A fresh nonce k = 4: c1 = g^k = 4, the mask s = h^k = 8, and c2 = m·s mod p = 19.' },
      { topic: 'p09-elgamal', frame: 4, caption: 'Bob rebuilds s = c1^x = 8, inverts it (3), and c2·s⁻¹ mod 23 = 11.' },
      { predict: { q: 'The same m = 11 is encrypted again with a new nonce. What does the new ciphertext look like?', options: ['Identical to the first', 'Different in both parts', 'Only c2 changes', 'Only c1 changes'], answer: 1, explain: 'A new k changes c1 = g^k and the mask h^k, so both parts change. Here it is (11, 8) against (4, 19).' } },
      { topic: 'p09-elgamal', frame: 5, caption: 'With k′ = 9 the ciphertext is (11, 8). A listener cannot tell that the same message was sent twice.' },
      { topic: 'p09-elgamal', frame: 6, caption: 'But c2 can be multiplied on the way: 2·c2 decrypts to 2m mod p. A changed ciphertext must be rejected, which needs padding or an authenticated hybrid scheme.' },
      { warn: 'A nonce used twice gives two masks that are equal: c2/c2′ = m/m′, so one known message reveals the other. Each encryption draws a new k.' },
      { topic: 'p09-elgamal', input: { size: 'real', seed: 5 }, frame: 4, caption: 'In the 2048-bit group: a 36-byte sentence decrypts from two 617-digit numbers.' },
      { bench: 'pk', state: { tool: 'elgamal', elgamal: { group: 'toy', p: '107', g: '2', x: '29', m: '66', k: '15' } }, text: 'Encrypt and decrypt with Elgamal at toy size or in the real group.' },
      { h: 'Recap' },
      { list: ['Key: x secret, h = g^x public.', 'Encrypt: fresh k, c1 = g^k, c2 = m·h^k mod p.', 'Decrypt: m = c2·(c1^x)⁻¹ mod p.', 'Randomised but malleable; in practice it is used as a key-encapsulation step with an authenticated cipher.'] },
      X('dlp-x-elgamal-enc'), X('dlp-x-elgamal-dec'), X('dlp-x-elgamal-nonce'), X('dlp-x-elgamal-mall'),
    ],
  });

  // =========================================================================================================
  // Chapter 3: signatures
  // =========================================================================================================
  C.lesson({
    id: 'dlp-sigs', chapter: 'dlp-sign', title: 'Elgamal, DSA and Schnorr', minutes: 9,
    summary: 'All three sign with a fresh nonce k: a commitment r from g^k, and a response s that ties k, the hash of the message and the private key x together. The verifier checks the relation with the public key y = g^x only. DSA works in a subgroup of prime order q, which keeps signatures short.',
    blocks: [
      'RSA signs by running its trapdoor backwards. A discrete-logarithm key has no trapdoor to run. How can it sign? The signer proves she knows x without revealing it, using a one-time secret k.',
      { h: 'DSA' },
      { topic: 'p09-sigs', frame: 0, caption: 'A subgroup of order q = 1009 inside Z_10091*, generated by g = 1024. Private x = 345, public y = 2434.' },
      { topic: 'p09-sigs', frame: 2, caption: 'A fresh nonce k = 211: r = (g^k mod p) mod q = 775.' },
      { topic: 'p09-sigs', frame: 3, caption: 's = k⁻¹(z + x·r) mod q = 811. The signature (775, 811) is two numbers below q.' },
      { predict: { q: 'The verifier knows p, q, g, y, z and (r, s), but not k or x. What power of g does g^u1·y^u2 equal, with u1 = z/s and u2 = r/s modulo q?', options: ['g^x', 'g^k', 'g^z', 'g^s'], answer: 1, explain: 'g^(z/s)·g^(xr/s) = g^((z + xr)/s), and s = (z + xr)/k, so the exponent is k. Reducing modulo q must give r.' } },
      { topic: 'p09-sigs', frame: 5, caption: 'w = 372, u1 = 904, u2 = 735, and v = (g^u1·y^u2 mod p) mod q = 775 = r.' },
      { topic: 'p09-sigs', frame: 7, caption: 'Change "tuesday" to "thursday": z′ = 611, v = 482 ≠ r. Rejected.' },
      { h: 'Schnorr and Elgamal' },
      { topic: 'p09-sigs', input: { scheme: 'schnorr' }, frame: 3, caption: 'Schnorr: e = H(R ‖ m) mod q = 553 and s = k + e·x mod q = 295. No inverse needed.' },
      { topic: 'p09-sigs', input: { scheme: 'schnorr' }, frame: 5, caption: 'The verifier rebuilds R′ = g^s·y^(−e) = 5820 and checks that it hashes to the same e.' },
      { topic: 'p09-sigs', input: { scheme: 'elgamal', q: 101, x: 400, k: 295 }, frame: 3, caption: 'Elgamal, the ancestor, works modulo p − 1 in all of Z_607*: s = k⁻¹(z − x·r) mod 606 = 32.' },
      { table: [['', 'Elgamal', 'DSA', 'Schnorr'], ['group', 'Z_p*', 'order-q subgroup', 'order-q subgroup'], ['commitment', 'r = g^k mod p', 'r = (g^k mod p) mod q', 'R = g^k, e = H(R ‖ m)'], ['response', 'k⁻¹(z − x·r) mod (p − 1)', 'k⁻¹(z + x·r) mod q', 'k + e·x mod q'], ['signature size (2048/224)', 'two 2048-bit numbers', 'two 224-bit numbers', 'two 224-bit numbers']], caption: 'Three schemes, one idea: a one-time secret k hides x in the response.' },
      { bench: 'pk', state: { tool: 'dsa', dsa: { size: 'toy', qMin: '101', x: '37', k: '41', msg: 'Pay the ferryman 3 coins', real: null } }, text: 'Sign and verify with DSA at toy size, or generate 2048/224 parameters.' },
      { h: 'Recap' },
      { list: ['Each signature uses a fresh secret nonce k; r commits to it.', 'DSA: s = k⁻¹(z + x·r) mod q, checked with u1 = z/s, u2 = r/s.', 'Schnorr: s = k + e·x mod q, with e a hash of the commitment and the message.', 'A subgroup of prime order q keeps signatures short: 2·224 bits for 112-bit security.'] },
      X('dlp-x-dsa-sign'), X('dlp-x-dsa-verify'), X('dlp-x-elgamal-sig'), X('dlp-x-schnorr'),
    ],
  });

  C.lesson({
    id: 'dlp-nonce', chapter: 'dlp-sign', title: 'Why each nonce must be fresh', minutes: 7,
    summary: 'The nonce is as secret as the key. Two signatures with the same k show the same r, in public, and the shared r with the two s values lets anyone compute the private key. So k is drawn fresh and uniformly for every signature, or derived deterministically from the key and the message as in RFC 6979; and a verifier or auditor can watch for a repeated r.',
    blocks: [
      'The response s = k⁻¹(z + x·r) has two unknowns, k and x. One equation with two unknowns is safe. What happens if a signer\'s nonce generator repeats?',
      { topic: 'p09-dsa-nonce', frame: 1, caption: 'Two signatures with the same r = 7049: since r depends only on k, the nonce was repeated.' },
      { predict: { q: 'Two signatures share k, so they give two equations s = k⁻¹(z + x·r) in the same unknowns. Who can now compute the private key x?', options: ['No one: x is still a discrete logarithm', 'Anyone who holds both signatures', 'Only someone who also knows k', 'Only the signer'], answer: 1, explain: 'z, r and both s values are public, so two equations in the two unknowns k and x can be solved by anyone. A repeated nonce is a published key.' } },
      { topic: 'p09-dsa-nonce', frame: 2, caption: 'The shared r and the two s values are enough to solve for x. From then on anyone can sign in the signer\'s name.' },
      { topic: 'p09-dsa-nonce', input: { size: 'real', seed: 11 }, frame: 1, caption: 'At 2048/224 the sign is the same, a repeated r, and so is the outcome. Size gives no protection against a repeated nonce.' },
      { h: 'The rule, and two ways to keep it' },
      { topic: 'p09-dsa-nonce', frame: 3, caption: 'A fresh uniform k for each signature: the two r values are unrelated.' },
      { topic: 'p09-dsa-nonce', frame: 4, caption: 'RFC 6979: k from HMAC-SHA-256 seeded with the key and the message hash. Different messages get different nonces; the same message gets the same, harmless, signature.' },
      { list: ['Draw k uniformly from 1 … q − 1 with a sound random generator, fresh for every signature. A counter, a timestamp or a weak generator is not enough.', 'Or derive k deterministically: RFC 6979 computes it with HMAC from the private key and the hash of the message, so equal messages give equal (harmless) signatures and different messages different nonces, with no random generator at all.', 'Do not let k be biased: even a few known or fixed bits of k, over many signatures, are enough to give x away.'] },
      { tip: 'Schnorr has the same weakness, since its s = k + e·x is just as linear in k and x. Ed25519 derives its nonce deterministically from a hash of the key and the message for exactly this reason.' },
      { h: 'Spotting a repeat' },
      { topic: 'p09-dsa-nonce', frame: 5, caption: 'A log of every r seen under one public key: signature #4 repeats the r of #1 on a different message, so the key is treated as exposed and revoked.' },
      { h: 'Recap' },
      { list: ['A repeated nonce shows as a repeated r, and with the two s values exposes x.', 'A known or biased nonce is as bad as a known key.', 'Fresh uniform nonces, or deterministic ones as in RFC 6979.', 'Verifiers and auditors can keep the r values per key and revoke a key whose r repeats.'] },
      X('dlp-x-nonce-rule'), X('dlp-x-nonce-r'),
    ],
  });

  // =========================================================================================================
  // Chapter 4: choosing the group
  // =========================================================================================================
  C.lesson({
    id: 'dlp-generic', chapter: 'dlp-params', title: 'Why the order needs twice the bits', minutes: 9,
    summary: 'Baby-step giant-step and Pollard\'s rho solve any discrete logarithm in a group of order n with about √n operations. So a group of order n gives at most half its bits of security: 112-bit security needs a subgroup order of 224 bits, 128-bit security 256 bits.',
    blocks: [
      'Trying every exponent costs n steps for a group of order n. Is there something faster that works in every group, using nothing but multiplication? Yes, and its cost sets the first rule for parameters.',
      { h: 'Baby-step giant-step' },
      { topic: 'p09-bsgs', frame: 0, caption: 'Z_1019*, g = 2 of order 1018, h = 777. Write x = i·m + j with m = ⌈√1018⌉ = 32.' },
      { topic: 'p09-bsgs', frame: 1, caption: 'Baby steps: g⁰ … g³¹, 32 values in a hash table.' },
      { topic: 'p09-bsgs', frame: 7, caption: 'Giant steps multiply h by g^(−32). Step 31 gives 20 = g¹², a table hit.' },
      { topic: 'p09-bsgs', frame: 8, caption: 'x = 31·32 + 12 = 1004, after 64 operations instead of 1004.' },
      { predict: { q: 'A subgroup order gains 20 bits, from 160 to 180. By what factor does the work of baby-step giant-step grow?', options: ['2²⁰', '2¹⁰', '20', '2'], answer: 1, explain: 'The work is about √n: 2⁸⁰ becomes 2⁹⁰, a factor 2¹⁰. Every 2 bits of group order buy 1 bit of security.' } },
      { h: 'Pollard\'s rho: the same cost, almost no memory' },
      { topic: 'p09-rho', frame: 2, caption: 'A pseudo-random walk g^a·h^b must repeat: a tail of 15, then a cycle of 8, the shape of a ρ.' },
      { topic: 'p09-rho', frame: 8, caption: 'Floyd\'s tortoise and hare meet at 137, reached as g⁹⁰·h³⁰ and as g³⁷⁸·h¹²⁹.' },
      { topic: 'p09-rho', frame: 9, caption: 'Equating the exponents gives x = 321 modulo the prime order 509, with two points of memory.' },
      { topic: 'p09-rho', frame: 10, caption: 'The walk repeats after about √(πq/2) steps. For a 2047-bit order that is about 2¹⁰²³·⁸.' },
      { topic: 'p09-bsgs', input: { size: 'modp', seed: 5 }, frame: 3, caption: 'The rule this gives: the group order needs at least twice as many bits as the security wanted.' },
      { table: [['security', 'subgroup order q', 'generic cost √q'], ['112 bits', '224 bits', '2¹¹²'], ['128 bits', '256 bits', '2¹²⁸'], ['192 bits', '384 bits', '2¹⁹²'], ['256 bits', '512 bits', '2²⁵⁶']], caption: 'Generic attacks set the size of the subgroup order.' },
      { h: 'Recap' },
      { list: ['Baby-step giant-step: √n time and √n memory.', 'Pollard\'s rho: √(πn/2) time and constant memory, and it runs in parallel.', 'No generic method does better than √n, so the order must have twice the bits of the security level.'] },
      X('dlp-x-bsgs-m'), X('dlp-x-code-bsgs'), X('dlp-x-generic-bits'), X('dlp-x-rho-memory'),
    ],
  });

  C.lesson({
    id: 'dlp-pohlig', chapter: 'dlp-params', title: 'Why the order must be a large prime', minutes: 8,
    summary: 'If the group order n factors, Pohlig–Hellman solves the logarithm modulo each prime power separately and joins the pieces by the CRT. The cost is set by the largest prime factor of n, not by n. So the group used has a large prime order q: a safe prime p = 2q + 1, or a subgroup of prime order q.',
    blocks: [
      'Z_8101* has order 8100. That sounds like 8100 possibilities. But 8100 = 2²·3⁴·5², and every one of those primes is tiny. Does that matter?',
      { topic: 'p09-pohlig', frame: 0, caption: 'g = 6, h = 1234, n = 8100 = 2²·3⁴·5²: three prime powers.' },
      { topic: 'p09-pohlig', frame: 1, caption: 'Raising to n/2 projects everything into a subgroup of order 2: x mod 2 is read off with a search through 2 values.' },
      { topic: 'p09-pohlig', frame: 6, caption: 'Four base-3 digits, one at a time: x ≡ 70 (mod 81), each digit a search through 3 values.' },
      { topic: 'p09-pohlig', frame: 9, caption: 'The CRT joins x ≡ 2 (mod 4), 70 (mod 81) and 12 (mod 25) into x = 2662.' },
      { predict: { q: 'An order n = 2·3·5·…·59 (all primes up to 59, with powers) has 210 bits. Roughly how hard is a logarithm in that group?', options: ['About 2¹⁰⁵, the square root of n', 'About 59 steps per digit, a few hundred in all', 'About 2²¹⁰', 'As hard as in the MODP group'], answer: 1, explain: 'Each piece is a search through at most 59 values. The size of n is irrelevant; its largest prime factor is what counts.' } },
      { topic: 'p09-pohlig', input: { size: 'big', seed: 7 }, frame: 19, caption: 'A 210-bit smooth order falls in 676 steps, where a generic attack on the whole order would need about 2¹⁰⁵.' },
      { h: 'The rule' },
      { topic: 'p09-pohlig', input: { size: 'modp', seed: 5 }, frame: 0, caption: 'The MODP group uses a safe prime: p − 1 = 2·q with q a 2047-bit prime.' },
      { topic: 'p09-pohlig', input: { size: 'modp', seed: 5 }, frame: 1, caption: 'There is nothing to split: one piece of 2047 bits, about 2¹⁰²³·⁸ steps by rho.' },
      { list: ['Use a safe prime p = 2q + 1 with q prime, and work in the subgroup of order q; or', 'use a prime p with a subgroup of prime order q (224 or 256 bits) and a generator g of that subgroup, as DSA does.', 'Either way, the group the secret exponent lives in has prime order, so Pohlig–Hellman has nothing to split.'] },
      { h: 'Recap' },
      { list: ['Pohlig–Hellman: one small logarithm per prime power of n, joined by the CRT.', 'Cost about Σ eᵢ·√pᵢ: the largest prime factor decides.', 'Rule: the order of the group in use is a large prime.'] },
      X('dlp-x-pohlig-work'), X('dlp-x-safe-primes'),
    ],
  });

  C.lesson({
    id: 'dlp-index', chapter: 'dlp-params', title: 'Why p has 2048 bits but q only 224', minutes: 8,
    summary: 'Index calculus uses a fact particular to Z_p*: its elements are integers, and many factor into small primes. Collect enough smooth powers of g, solve for the logarithms of the small primes, then express h. At real size this is the number field sieve, far faster than √q, which is why p must be much longer than q.',
    blocks: [
      'Generic attacks cost √q, so a 224-bit q gives 112-bit security. Why then does DSA pair that q with a 2048-bit p, not a 224-bit one? Because Z_p* is not a generic group: its elements can be factored.',
      { topic: 'p09-index', frame: 1, caption: 'g^7429 mod 10007 = 2420 = 2²·5·11²: smooth. Its logarithm is a sum of the logarithms of 2, 5 and 11.' },
      { topic: 'p09-index', frame: 5, caption: '14 smooth powers give 14 equations in the 6 unknown logarithms of 2, 3, 5, 7, 11 and 13.' },
      { topic: 'p09-index', frame: 6, caption: 'Linear algebra modulo 10006 gives every one: log_g(2) = 6578.' },
      { predict: { q: 'Could the same trick work on an elliptic curve?', options: ['Yes, factor the coordinates', 'No: points have no notion of "small" that makes many of them products of a few fixed points', 'Only on curves over binary fields', 'Only with a quantum computer'], answer: 1, explain: 'Smoothness is what index calculus needs, and well-chosen curves have no such notion. That is why a 224-bit curve gives 112-bit security and Z_p* needs about 2048 bits for the same.' } },
      { topic: 'p09-index', frame: 8, caption: 'h·g^3355 = 1792 = 2⁸·7 is smooth, so x = 540 from the known logarithms.' },
      { topic: 'p09-index', frame: 9, caption: 'At 2048 bits the number field sieve costs about 2¹¹⁷, against 2¹⁰²³·⁸ for a generic attack.' },
      { table: [['security', 'p (bits)', 'q (bits)', 'elliptic curve (bits)'], ['112', '2048', '224', '224'], ['128', '3072', '256', '256'], ['192', '7680', '384', '384'], ['256', '15360', '512', '512']], caption: 'The modulus is sized against the number field sieve, the subgroup order against generic attacks (NIST SP 800-57).' },
      { h: 'Recap' },
      { list: ['Index calculus: logarithms of a factor base from smooth powers, then one smooth h·g^k.', 'Subexponential at real size: p must be far longer than the security level.', 'Two separate rules: p for index calculus, q for generic attacks.'] },
      X('dlp-x-index-why'), X('dlp-x-levels'),
    ],
  });

  C.lesson({
    id: 'dlp-subgroup', chapter: 'dlp-params', title: 'Why received values are checked', minutes: 8,
    summary: 'A server that raises whatever it receives to a fixed secret x, in a group whose order has small factors, answers questions about x modulo each small factor, and together the answers give x away. The defences: a safe prime or a prime-order subgroup, a check that a received y has y^q = 1 and y ≠ 1, and fresh secrets per exchange.',
    blocks: [
      'A server keeps one Diffie–Hellman secret x for every client and computes β^x for whatever β a client sends. What could a client learn by sending something other than an honest g^b?',
      { topic: 'p09-small-subgroup', frame: 0, caption: 'p = 3117559 with p − 1 = 2·3·19·23·29·41: only small primes.' },
      { topic: 'p09-small-subgroup', frame: 1, caption: 'A β of order 3: the server\'s answer is keyed by β^x, one of only 3 values, so it depends on x mod 3 alone.' },
      { topic: 'p09-small-subgroup', frame: 2, caption: 'One such question for each small factor of p − 1, and together they give away the whole secret.' },
      { predict: { q: 'The server switches to a safe prime p = 2q + 1. Which small subgroup can a client still probe?', options: ['None', 'Only the subgroup of order 2, which gives x mod 2', 'All subgroups below 1000', 'The subgroup of order q'], answer: 1, explain: 'The orders divide 2q, so the only small one is 2: one bit of x. The rest is a logarithm in a group of prime order q.' } },
      { topic: 'p09-small-subgroup', frame: 3, caption: 'With the safe prime 2357183 = 2·1178591 + 1 only x mod 2 leaks.' },
      { topic: 'p09-small-subgroup', frame: 4, caption: 'The fixes together: a safe prime or prime-order subgroup, a check on every received value, fresh secrets.' },
      { math: 'received y is accepted only if\n  1 < y < p − 1        (rules out 0, 1 and −1)\n  y^q ≡ 1 (mod p)       (y lies in the subgroup of prime order q)' },
      { tip: 'With a safe prime the check y^q ≡ 1 is the same as y being a quadratic residue, and it costs one exponentiation. Protocols that use fresh exponents for every exchange limit the damage further, since each answer tells about a secret that is thrown away.' },
      { h: 'Recap' },
      { list: ['A fixed secret applied to unchecked input leaks x modulo every small factor of the group order.', 'Safe primes or prime-order subgroups leave no small factor but 2.', 'Always check 1 < y < p − 1 and y^q ≡ 1 before using a received value.'] },
      X('dlp-x-subgroup-set'), X('dlp-x-code-check'), X('dlp-x-subgroup-fix'),
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
