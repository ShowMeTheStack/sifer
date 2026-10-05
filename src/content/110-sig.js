// Part 11, digital signatures: the chapters and the lessons. The exercises are in 111-sig-ex.js; the tour, the course
// and the pages the diagram checker looks at in 112-sig-tour.js. Each lesson opens with a question, runs the topic that
// shows the idea at a frame chosen for the point being made, asks for a prediction, sums up, and leads to its exercises.
// Every value quoted here was worked out by the engines (S.RSA, S.SIG, S.ECC, S.ECC.Ed25519, S.SHA256) on the topics'
// own inputs. The part is taught from the defender's side: what each check protects, and how a signer keeps its key.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('sg-what')) return;
  const X = (id) => ({ exercise: id });

  C.chapter({ id: 'sg-ch-rsa', part: 'signatures', n: 1, title: 'What a signature is, and RSA', blurb: 'What a signature gives that a MAC cannot, why raw RSA signing is unsafe, hash-then-sign, and the PSS encoding the standards require.' });
  C.chapter({ id: 'sg-ch-dlog', part: 'signatures', n: 2, title: 'Discrete-log signatures', blurb: 'Elgamal and the two lanes of DSA, and Schnorr\'s proof of knowledge turned into a signature by a hash.' });
  C.chapter({ id: 'sg-ch-curve', part: 'signatures', n: 3, title: 'Signatures on curves', blurb: 'ECDSA with a nonce derived by RFC 6979, and Ed25519, where the nonce is derived by design.' });
  C.chapter({ id: 'sg-ch-use', part: 'signatures', n: 4, title: 'Nonces and choosing a scheme', blurb: 'The three rules for a nonce and how derived nonces keep them, then sizes, costs and security levels side by side.' });

  // =========================================================================================================
  // Chapter 1: what a signature is, and RSA
  // =========================================================================================================
  C.lesson({
    id: 'sg-what', chapter: 'sg-ch-rsa', title: 'What a signature gives', minutes: 7,
    summary: 'A MAC and a signature both detect a changed message. Only a signature can be checked by someone who holds no secret, and only a signature shows who made it: the property called non-repudiation.',
    blocks: [
      'Alice runs a warehouse and sends Bob the order "deliver 40 crates to dock 7". Bob wants to know that the order is unchanged and really from Alice. A MAC under a key they share does that. So why does every certificate, software update and signed document use a signature instead?',
      { def: 'Digital signature', text: 'a pair of algorithms: Sign(private key, m) gives σ; Verify(public key, m, σ) says valid or invalid. Only the private key can make a σ that verifies; anyone with the public key can check it.' },
      { topic: 'p11-what', frame: 1, caption: 'The MAC: tag = HMAC-SHA-256(K, m) = f3b43a…48e11c. Bob holds the same K, computes the same 32 bytes, and accepts.' },
      { topic: 'p11-what', frame: 3, caption: 'The signature: σ = 30a5f2…7ac104, 64 bytes of Ed25519. Bob checks it with Alice\'s public key A and nothing secret.' },
      'Both catch a changed message: "deliver 400 crates to dock 7" fails the MAC and fails the signature. For integrity the two are equally good. The difference shows only when the two ends disagree.',
      { predict: { q: 'Bob claims Alice ordered 400 crates and shows the judge, Carol, the message with a valid HMAC tag. Carol is even given K. What can she conclude?', options: ['Alice sent it: the tag is valid', 'Bob forged it: tags only come from the sender', 'Nothing about who made it: Alice and Bob both hold K', 'The key K has leaked'], answer: 2, explain: 'Whoever holds K can make a valid tag, and both of them do. A MAC authenticates the message only towards the other key holder; it cannot settle a dispute between them.' } },
      { topic: 'p11-what', frame: 5, caption: 'Bob made the tag 57d184…05f05e on the altered order himself. It checks out, and nobody can tell it from one of Alice\'s.' },
      { topic: 'p11-what', frame: 6, caption: 'With signatures the dispute is settled: Bob would need Alice\'s private seed to sign the altered order. Alice\'s real pair verifies, Bob\'s does not.' },
      { table: [['Property', 'MAC (HMAC-SHA-256)', 'Signature (Ed25519)'], ['Detects a changed message', 'yes', 'yes'], ['Who can check it', 'only holders of K', 'anyone with the public key'], ['Who could have made it', 'any holder of K', 'only the private-key holder'], ['Non-repudiation', 'no', 'yes'], ['Size here', '32 bytes', '64 bytes']], caption: 'What each gives. A MAC is faster and smaller; a signature is what makes a message provable to a third party.' },
      { tip: 'A signature does not hide the message. Signing and encrypting are separate jobs, and a protocol that needs both does both.' },
      { h: 'Recap' },
      { list: ['A MAC and a signature both give integrity.', 'A MAC authenticates only towards someone who shares its key, and either holder could have made it.', 'A signature is made with a private key and checked with a public one: anyone can verify it, and only one party could have made it. That is non-repudiation.'] },
      X('sg-x-mac-prop'), X('sg-x-dispute'),
    ],
  });

  C.lesson({
    id: 'sg-rsa', chapter: 'sg-ch-rsa', title: 'RSA signatures: hash, then sign', minutes: 8,
    summary: 'RSA signs by raising to the private exponent d, and anyone verifies by raising to e. Raw RSA signing is unsafe because RSA is multiplicative; signing a hash of the message, and in practice an encoding of it, closes that gap.',
    blocks: [
      'RSA encryption raises to the public e and decryption to the private d, and (mᵈ)ᵉ ≡ m (mod n) either way round. Turn it round, so that only the key owner can compute the power and everyone can undo it, and you have a signature. Is that enough?',
      { topic: 'p11-rsa-sign', frame: 0, caption: 'A toy key: n = 1050589, e = 65537, d = 60493. Signing raises to d, verifying raises to e.' },
      { topic: 'p11-rsa-sign', frame: 1, caption: 'The number 30 signed raw: s₁ = 30^d mod n = 953564, and s₁^e mod n gives back 30.' },
      { predict: { q: 'The signer has signed 30 and 7 raw. Which further number is now validly signed, by anyone who has the two signatures and the public key?', options: ['37', '210', '23', 'None: only the key owner can sign'], answer: 1, explain: '(s₁·s₂)^e = s₁^e·s₂^e = 30·7 (mod n), so s₁·s₂ mod n is a valid raw signature on 210, a number the signer never signed. Raw RSA is multiplicative.' } },
      { topic: 'p11-rsa-sign', frame: 3, caption: 's₁·s₂ mod n = 157948 verifies as a signature on 210 = 30 · 7.' },
      { topic: 'p11-rsa-sign', frame: 4, caption: 'Worse, any number s at all is a raw signature on s^e mod n, here 942868. A scheme must not let anyone make a valid pair.' },
      { h: 'Hash, then sign' },
      'The repair is to sign a hash of the message instead. The algebra still multiplies, but a product of two hashes is useless unless some message hashes to it, and finding one is a preimage search.',
      { math: 'Sign(d, m):       z = H(m),  s = z^d mod n\nVerify(e, m, s):  valid when s^e mod n = H(m)' },
      { topic: 'p11-rsa-sign', frame: 5, caption: '"pay 30 to the printer" hashes to z₁ = 730287 (reduced modulo the toy n) and is signed as s = 351448.' },
      { topic: 'p11-rsa-sign', frame: 6, caption: 'The product of two hashed signatures verifies only for 755077, and no message is known to hash to it: finding one costs about 2²⁵⁶ work.' },
      { tip: 'A signer with the factors signs faster by the Chinese remainder theorem: s mod p from z^(d mod (p − 1)) and s mod q from z^(d mod (q − 1)), then the two are joined. The exercise "Sign by the CRT" does it at toy size. A careful signer also verifies its own s before releasing it, so a fault during the computation cannot leak a factor.' },
      { topic: 'p11-rsa-sign', frame: 7, caption: 'At real size a bare hash is a small, structured number inside a 2048-bit modulus. The standards sign an encoding that fills the whole width: PSS, the next lesson.' },
      { h: 'Recap' },
      { list: ['RSA signs with s = z^d mod n and verifies with s^e mod n = z.', 'Raw RSA is multiplicative, and every number is a signature on something; signing H(m) makes such pairs worthless.', 'Real systems sign an encoding of the hash, RSA-PSS, never the bare hash.'] },
      X('sg-x-rsa-verify'), X('sg-x-rsa-crt'), X('sg-x-hash-why'),
    ],
  });

  C.lesson({
    id: 'sg-pss', chapter: 'sg-ch-rsa', title: 'RSA-PSS, field by field', minutes: 9,
    summary: 'PSS builds a block as wide as the modulus from the message hash and a random salt: a hash H of both, a data block holding the salt, masked with MGF1(H), and the trailer byte bc. The verifier unmasks it, recovers the salt and recomputes H.',
    blocks: [
      'Hash-then-sign leaves a 256-bit number inside a 2048-bit modulus, with the top 1792 bits zero. RSA\'s algebra still acts on that structure. PSS fills all 2048 bits with bytes that look random, yet the verifier can still check every one of them. How, when the signer used a random salt the verifier never sees?',
      { topic: 'p11-pss', frame: 2, caption: 'M′ = eight zero bytes ‖ mHash ‖ salt, 72 bytes, and H = SHA-256(M′). H ties the message and the salt together; the verifier must arrive at the same 32 bytes.' },
      { topic: 'p11-pss', frame: 4, caption: 'The data block DB: 190 zero bytes, the separator 01, and the 32-byte salt, 223 bytes in all for a 2048-bit key.' },
      { topic: 'p11-pss', frame: 3, caption: 'MGF1 stretches H into a mask as long as DB: ⌈223/32⌉ = 7 SHA-256 blocks, the last cut to 31 bytes.' },
      { topic: 'p11-pss', frame: 5, caption: 'EM = maskedDB ‖ H ‖ bc, 256 bytes, with the top bit cleared so EM stays below n. Only H and bc are visible.' },
      { math: 'emLen  = ⌈(modBits − 1) / 8⌉ bytes\nDB     = PS (zero bytes) ‖ 01 ‖ salt          emLen − 33 bytes\nEM     = (DB ⊕ MGF1(H)) ‖ H ‖ bc            H is 32 bytes, bc is 1\ns      = EM^d mod n' },
      { predict: { q: 'The salt is random and is not sent alongside the signature. How does the verifier get it?', options: ['It cannot: PSS verification ignores the salt', 'It recomputes MGF1(H) from the H in EM, unmasks DB, and reads the salt after the 01', 'The salt is part of the public key', 'It tries every possible salt'], answer: 1, explain: 'H sits in EM in the clear, so the verifier can rebuild the same mask, strip it off DB and read the salt. Then it recomputes H′ from the message and that salt and compares.' } },
      { topic: 'p11-pss', frame: 8, caption: 'Unmasked: 190 zero bytes, then 01, then the salt c3ae91a684e745fc…. A block of any other shape is rejected here.' },
      { topic: 'p11-pss', frame: 9, caption: 'H′ = SHA-256(00×8 ‖ SHA-256(message) ‖ salt) equals H: valid.' },
      { topic: 'p11-pss', frame: 10, caption: 'Another salt gives another H, another mask and another s, and it verifies too: two signatures of one message cannot be linked by comparing them.' },
      { topic: 'p11-pss', frame: 11, caption: 'One added character changes mHash, so H′ ≠ H: rejected.' },
      { warn: 'RFC 8017 recommends PSS for new applications. The older PKCS #1 v1.5 signature encoding is deterministic and still widely deployed; a verifier of it must rebuild the whole expected block and compare, never parse it loosely.' },
      { h: 'Recap' },
      { list: ['PSS signs EM = maskedDB ‖ H ‖ bc, as wide as the modulus, with H = SHA-256(00×8 ‖ mHash ‖ salt).', 'DB is zero bytes, 01 and the salt; MGF1(H) masks it, in ⌈|DB|/32⌉ SHA-256 blocks.', 'The verifier checks bc and the top bits, unmasks DB, checks its shape, recovers the salt and recomputes H.'] },
      X('sg-x-pss-table'), X('sg-x-pss-blocks'), X('sg-x-pss-topbyte'), X('sg-x-pss-salt'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: discrete-log signatures
  // =========================================================================================================
  C.lesson({
    id: 'sg-dsa', chapter: 'sg-ch-dlog', title: 'From Elgamal to DSA', minutes: 9,
    summary: 'An Elgamal signature commits to a secret nonce k with r = g^k and solves for s so that g^z = y^r·r^s. DSA does the same work in a small subgroup of order q, so the signature is two numbers below q.',
    blocks: [
      'In a group where discrete logarithms are hard, nobody can take a logarithm, so the RSA trick of inverting a power is not available. The discrete-log signatures do something else: the signer commits to a fresh secret number, then answers with one value that only the private key could have produced. How can a verifier check such an answer without learning the key?',
      { topic: 'p11-elgamal', frame: 2, caption: 'p = 1019, g = 2, private x = 123. A fresh secret nonce k = 101, invertible modulo p − 1, and the commitment r = g^k mod p = 77.' },
      { topic: 'p11-elgamal', frame: 3, caption: 's = k⁻¹(z − x·r) mod (p − 1) = 721 for z = 852. The signature is (r, s) = (77, 721).' },
      { topic: 'p11-elgamal', frame: 4, caption: 'The verifier: g^z mod p = 122 and y^r·r^s mod p = 122. Equal, so valid.' },
      { topic: 'p11-elgamal', frame: 5, caption: 'Why: x·r + k·s ≡ z (mod p − 1), here 309 + 543 = 852. Raised as powers of g, that is y^r·r^s = g^z. The verifier sees only the left side.' },
      { predict: { q: 'The signer picks k = 100 with p − 1 = 1018. What goes wrong?', options: ['Nothing', 'gcd(100, 1018) = 2, so k has no inverse modulo p − 1 and s cannot be computed', 'r comes out as 0', 'The signature becomes longer'], answer: 1, explain: 's needs k⁻¹ modulo p − 1, and an even k shares the factor 2 with the even p − 1. Elgamal draws k coprime to p − 1.' } },
      { h: 'DSA: two lanes' },
      'An Elgamal signature is two numbers as long as p, and p must be long for security. DSA keeps p long but works in a subgroup of prime order q, much shorter: exponents, the nonce and the signature all live modulo q, and only the powers of g live modulo p.',
      { topic: 'p11-dsa', input: { q: 101, x: 45, k: 77, msg: 'gate 3 opens at six' }, frame: 4, caption: 'q = 101 and p = 607. The nonce k = 77 climbs to g^k mod p = 552 in the big group and comes straight back down as r = 552 mod 101 = 47.' },
      { topic: 'p11-dsa', input: { q: 101, x: 45, k: 77, msg: 'gate 3 opens at six' }, frame: 5, caption: 'The rest is modulo q: k⁻¹ = 21 and s = k⁻¹(z + x·r) mod q = 94. The signature (47, 94) is two numbers below q.' },
      { topic: 'p11-dsa', input: { q: 101, x: 45, k: 77, msg: 'gate 3 opens at six' }, frame: 7, caption: 'Verifying: w = s⁻¹, u1 = z·w and u2 = r·w modulo q, then g^u1·y^u2 mod p = 552 = g^k, and v = 552 mod 101 = 47 = r: valid.' },
      { topic: 'p11-dsa', frame: 8, caption: 'With q of 10 bits and p of 14, the DSA signature is 20 bits against about 28 for Elgamal modulo the same p. At real size: q of 224 or 256 bits, p of 2048 or 3072.' },
      { warn: 'A verifier must check 0 < r < q and 0 < s < q before anything else. Without the range check, s and s + q give the same s⁻¹ mod q, so one valid signature turns into others that a careless verifier also accepts.' },
      { bench: 'pk', state: { tool: 'dsa', dsa: { size: 'toy', qMin: '101', x: '45', k: '77', msg: 'gate 3 opens at six', real: null } }, text: 'The public-key bench on DSA with q = 101: change the message, the key or the nonce, and verify.' },
      { h: 'Recap' },
      { list: ['Elgamal: r = g^k mod p, s = k⁻¹(z − x·r) mod (p − 1); valid when y^r·r^s = g^z.', 'DSA works in a subgroup of prime order q: r = (g^k mod p) mod q, s = k⁻¹(z + x·r) mod q.', 'The verifier checks the ranges, rebuilds g^k as g^u1·y^u2 and compares it, reduced modulo q, with r.'] },
      X('sg-x-elg-k'), X('sg-x-elg-sign'), X('sg-x-elg-verify'), X('sg-x-dsa-sign'), X('sg-x-dsa-verify'), X('sg-x-dsa-code'),
    ],
  });

  C.lesson({
    id: 'sg-schnorr', chapter: 'sg-ch-dlog', title: 'Schnorr signatures and Fiat–Shamir', minutes: 8,
    summary: 'Schnorr\'s identification proves knowledge of x in three moves: commit R = g^k, receive a challenge c, answer s = k + c·x. Replacing the challenger by a hash of R and the message turns the conversation into a signature (e, s).',
    blocks: [
      'How can you convince someone that you know a private key without showing it, and without them being able to repeat the trick to a third person? Schnorr\'s protocol does it in three moves, and the simplest discrete-log signature falls out of it.',
      { topic: 'p11-schnorr', input: { q: 101, x: 33, k: 58, c: 12, msg: 'hello', fake: 'hello!' }, frame: 1, caption: 'q = 101, p = 607, g = 64; the prover knows x = 33, everyone knows y = 480. Commit: a fresh secret k = 58 and R = g^k mod p = 214.' },
      { topic: 'p11-schnorr', input: { q: 101, x: 33, k: 58, c: 12, msg: 'hello', fake: 'hello!' }, frame: 3, caption: 'The verifier sends the challenge c = 12; the response is s = k + c·x mod q = 50. The random k masks x completely.' },
      { topic: 'p11-schnorr', input: { q: 101, x: 33, k: 58, c: 12, msg: 'hello', fake: 'hello!' }, frame: 4, caption: 'Check: g^s mod p = 76 and R·y^c mod p = 76, because g^(k + c·x) = g^k·(g^x)^c.' },
      { predict: { q: 'Suppose the prover could learn c before it sends R. Would passing the check still show that it knows x?', options: ['Yes, the equation still needs x', 'No: it could pick s first and set R = g^s·y^(−c), which passes with no x at all', 'Only if c is large', 'Only if k is fresh'], answer: 1, explain: 'With c known in advance, R can be made to fit any s. The protocol is sound only because the challenge is fixed after the commitment.' } },
      { topic: 'p11-schnorr', input: { q: 101, x: 33, k: 58, c: 12, msg: 'hello', fake: 'hello!' }, frame: 5, caption: 'Knowing c = 12 in advance, a transcript is made without x: s = 5, R = 26. The order of the moves is the whole security.' },
      { h: 'Fiat–Shamir: a hash plays the verifier' },
      { topic: 'p11-schnorr', input: { q: 101, x: 33, k: 58, c: 12, msg: 'hello', fake: 'hello!' }, frame: 6, caption: 'The challenge becomes e = H(R ‖ m) mod q, here 59 for "hello". Since e is computed from R, nobody can choose R after seeing e.' },
      { topic: 'p11-schnorr', input: { q: 101, x: 33, k: 58, c: 12, msg: 'hello', fake: 'hello!' }, frame: 8, caption: 'The signature is (e, s) = (59, 86). Verifying rebuilds R′ = g^s·y^(−e) mod p = 214 and hashes it with the message: e′ = 59 = e.' },
      { topic: 'p11-schnorr', input: { q: 101, x: 33, k: 58, c: 12, msg: 'hello', fake: 'hello!' }, frame: 9, caption: 'Against "hello!" the same R′ hashes to e′ = 14, not 59: rejected.' },
      { math: 'Sign:    k fresh, R = g^k mod p, e = H(R ‖ m) mod q, s = k + e·x mod q\nVerify:  0 ≤ s < q,  R′ = g^s·y^(−e) mod p,  valid when H(R′ ‖ m) mod q = e' },
      { tip: 'No inverse is needed, and the signing equation is linear in x. Ed25519, two lessons on, is this scheme on an elliptic curve, with the challenge hashing the public key as well.' },
      { h: 'Recap' },
      { list: ['Schnorr identification: commit R = g^k, challenge c, response s = k + c·x; check g^s = R·y^c.', 'The challenge must come after the commitment; a hash of R and the message enforces that, with no live verifier.', 'The signature is (e, s); the verifier rebuilds R′ and recomputes the hash.'] },
      X('sg-x-schnorr-sign'), X('sg-x-schnorr-rebuild'), X('sg-x-schnorr-code'), X('sg-x-fs-order'),
    ],
  });

  // =========================================================================================================
  // Chapter 3: signatures on curves
  // =========================================================================================================
  C.lesson({
    id: 'sg-ecdsa', chapter: 'sg-ch-curve', title: 'ECDSA, with a derived nonce', minutes: 9,
    summary: 'ECDSA is DSA in the group of points of an elliptic curve: R = k·G gives r = R.x mod n, and s = k⁻¹(e + r·d) mod n. The verifier rebuilds R as u₁·G + u₂·Q. RFC 6979 derives k from the key and the message hash.',
    blocks: [
      'DSA needs a 2048-bit p to be safe. On a well-chosen elliptic curve the best known attack on the discrete logarithm is the generic one, so a 256-bit group gives 128-bit security. Can the DSA equations simply move to a curve?',
      { topic: 'p11-ecdsa', input: { curve: 'gf1009', d: '345', msg: 'sample' }, frame: 0, caption: 'A toy curve y² = x³ + 7x + 26 over GF(1009), with G of prime order n = 1019. Private key d = 345, public key Q = d·G.' },
      { topic: 'p11-ecdsa', input: { curve: 'gf1009', d: '345', msg: 'sample' }, frame: 6, caption: 'The nonce k = 537 gives the point R = k·G, and r is its x-coordinate reduced modulo n: 952.' },
      { topic: 'p11-ecdsa', input: { curve: 'gf1009', d: '345', msg: 'sample' }, frame: 7, caption: 'k⁻¹ mod n = 315 and s = k⁻¹(e + r·d) mod n = 945. The signature (952, 945) is two numbers below n.' },
      { predict: { q: 'The verifier computes w = s⁻¹, u₁ = e·w and u₂ = r·w modulo n. Which point is u₁·G + u₂·Q?', options: ['Q', 'R = k·G', 'G', 'The point at infinity'], answer: 1, explain: 'u₁·G + u₂·Q = s⁻¹(e + r·d)·G, and s⁻¹(e + r·d) ≡ k (mod n). So the verifier rebuilds R without knowing k or d.' } },
      { topic: 'p11-ecdsa', input: { curve: 'gf1009', d: '345', msg: 'sample' }, frame: 9, caption: 'u₁·G + u₂·Q has x-coordinate 952, which reduced modulo n is r: valid.' },
      { h: 'The nonce, derived' },
      'Everything in ECDSA rests on k: it must be secret, it must never repeat across messages, and it must be uniform. RFC 6979 removes the random generator from signing altogether. It feeds the private key and the message hash into HMAC-SHA-256, used as a deterministic generator, and takes k from its output.',
      { topic: 'p11-ecdsa', frame: 5, caption: 'On P-256 with the key and the message "sample" of RFC 6979\'s own test: k = 0xa6e3c57d…3d8aad60, the value the standard lists.' },
      { topic: 'p11-ecdsa', frame: 10, caption: 'Signing "sample" again gives the same k and the same signature, which reveals nothing new; "sample." gets an unrelated k. Two different messages cannot share a nonce.' },
      { warn: 'A verifier checks that r and s lie in [1, n − 1] and that Q is a valid point of the curve before computing anything. Either check missing has let invalid signatures through in real libraries.' },
      { bench: 'pk', state: { tool: 'ecdsa', ecdsa: { curve: 'toy', d: '', nonce: 'rfc6979', k: '29', msg: 'Ship forty crates to the north quay' } }, text: 'The public-key bench on ECDSA: sign on a toy curve or on P-256, with a derived or a given nonce, and verify.' },
      { h: 'Recap' },
      { list: ['Sign: R = k·G, r = R.x mod n, s = k⁻¹(e + r·d) mod n.', 'Verify: check ranges and Q; w = s⁻¹, u₁ = e·w, u₂ = r·w; valid when (u₁·G + u₂·Q).x mod n = r.', 'RFC 6979 derives k from d and the hash, so it is secret, uniform and fresh for every new message.'] },
      X('sg-x-ecdsa-sign'), X('sg-x-ecdsa-verify'), X('sg-x-ecdsa-code'),
    ],
  });

  C.lesson({
    id: 'sg-ed25519', chapter: 'sg-ch-curve', title: 'Ed25519, step by step', minutes: 8,
    summary: 'Ed25519 is a Schnorr signature on an Edwards curve. A 32-byte seed is hashed into a clamped scalar and a secret prefix; the nonce is a hash of the prefix and the message, so no generator is needed. The signature is R ‖ S, 64 bytes.',
    blocks: [
      'ECDSA can be made safe, but every rule is the implementer\'s job: derive the nonce, check the ranges, avoid branches on secrets. EdDSA was designed so that the safe choice is the only one. What does that look like?',
      { topic: 'p11-ed25519', frame: 1, caption: 'h = SHA-512(seed): the low 32 bytes become the secret scalar, the high 32 the prefix, a second secret used only for nonces.' },
      { topic: 'p11-ed25519', frame: 2, caption: 'Clamping: in byte 0 the three low bits are cleared, so a is a multiple of 8, the cofactor; in byte 31 the top bit is cleared and the next one set, so a has exactly 255 bits.' },
      { math: 'byte 0:   h[0]  & 0xf8        (clear bits 0, 1, 2)\nbyte 31:  (h[31] & 0x7f) | 0x40   (clear bit 7, set bit 6)\na = the 32 bytes read little-endian' },
      { topic: 'p11-ed25519', frame: 4, caption: 'The nonce r = SHA-512(prefix ‖ M) mod L depends only on the secret prefix and the message.' },
      { predict: { q: 'The same key signs the same message twice. What happens?', options: ['Two different signatures, because the nonce is random', 'The same 64-byte signature both times', 'The second signing fails', 'The key is exposed'], answer: 1, explain: 'r is a hash of the prefix and the message, so the same message gives the same r, R and S. That reveals nothing: it is the signature already published.' } },
      { topic: 'p11-ed25519', frame: 7, caption: 'S = (r + k·a) mod L, with the challenge k = SHA-512(R ‖ A ‖ M) mod L. The signature R ‖ S is 64 bytes.' },
      { topic: 'p11-ed25519', frame: 8, caption: 'The verifier decodes A and R, checks S < L, and recomputes k from R, A and M.' },
      { topic: 'p11-ed25519', frame: 9, caption: 'Check [8][S]B = [8]R + [8][k]A. The factor 8 clears any small-order part, so every implementation reaches the same verdict.' },
      { topic: 'p11-ed25519', frame: 10, caption: 'One changed bit of the message changes k, and the equation fails: rejected.' },
      { tip: 'Without the check S < L, S and S + L would both verify: a second signature on the same message made by anyone. Systems that identify a signed object by its signature bytes rely on this check.' },
      { bench: 'pk', state: { tool: 'ed25519', ed25519: { sk: '', msg: 'Gate code changes at dawn' } }, text: 'The public-key bench on Ed25519: make a key, sign, change a byte and verify again.' },
      { h: 'Recap' },
      { list: ['SHA-512 of the seed gives the clamped scalar a and the secret prefix.', 'r = H(prefix ‖ M), R = r·B, k = H(R ‖ A ‖ M), S = r + k·a mod L; the signature is R ‖ S.', 'The verifier checks S < L and [8]S·B = [8]R + [8]k·A.'] },
      X('sg-x-ed-clamp'), X('sg-x-ed-s-range'),
    ],
  });

  // =========================================================================================================
  // Chapter 4: nonces and choosing a scheme
  // =========================================================================================================
  C.lesson({
    id: 'sg-nonce', chapter: 'sg-ch-use', title: 'The nonce rules', minutes: 7,
    summary: 'In every Elgamal-family signature the nonce must be fresh, secret and uniform. A repeated, revealed or biased nonce gives the private key away. Deriving the nonce from the key and the message, as RFC 6979 and EdDSA do, keeps all three rules without trusting a generator.',
    blocks: [
      'DSA, ECDSA, Schnorr and EdDSA all hide the private key behind a one-time number k. The signature equation has two unknowns, k and the key, and only the secrecy of k keeps the key out of reach. What does a signer have to guarantee about k?',
      { topic: 'p11-nonce', frame: 0, caption: 'A good generator: two messages, two unrelated nonces, two valid signatures.' },
      { topic: 'p11-nonce', frame: 1, caption: 'A stuck generator returns the same k for both messages. Both signatures verify, and their r values are equal, which anyone can see.' },
      { predict: { q: 'An auditor finds two ECDSA signatures on different messages, from one key, with the same r. What should happen?', options: ['Nothing: equal r values are a coincidence', 'The key must be treated as compromised: revoke it, replace it, and fix the nonce generation', 'Sign the messages again', 'Switch to a longer hash'], answer: 1, explain: 'Equal r on different messages means a repeated k, and two equations sharing the unknowns k and d give d by simple algebra. The key is lost; only replacing it helps.' } },
      { topic: 'p11-nonce', frame: 2, caption: 'A biased generator: every nonce starts with 8 zero bits. Each signature leaks a little; enough of them give the key to a lattice computation. So k must be uniform, and never revealed.' },
      { topic: 'p11-nonce', frame: 3, caption: 'RFC 6979: k from HMAC-SHA-256 of the key and the hash. The same message gets the same k (harmless), another message an unrelated one.' },
      { topic: 'p11-nonce', frame: 4, caption: 'EdDSA builds the rule in: r = SHA-512(prefix ‖ M). A hedged nonce mixes fresh randomness into a derived one, which also helps against fault attacks.' },
      { table: [['Rule', 'What breaks it', 'What keeps it'], ['Fresh', 'a stuck or cloned generator; a restored virtual machine', 'deriving k from the key and the message'], ['Secret', 'k logged, leaked by timing or power', 'constant-time code; never storing k'], ['Uniform', 'a few top bits always zero; modulo bias', 'HMAC output reduced correctly, or rejection sampling']], caption: 'The three rules and the defences.' },
      { h: 'Recap' },
      { list: ['k must be fresh, secret and uniform for every signature.', 'Equal r values on different messages from one key mean the key is lost: revoke and replace it.', 'Derive the nonce (RFC 6979, EdDSA), or hedge it with fresh randomness; never trust a bare generator.'] },
      X('sg-x-nonce-fresh'), X('sg-x-nonce-same-r'),
    ],
  });

  C.lesson({
    id: 'sg-choose', chapter: 'sg-ch-use', title: 'Choosing a signature scheme', minutes: 7,
    summary: 'RSA-PSS has large keys and signatures and the cheapest verification; DSA and Schnorr have short signatures but large public keys; ECDSA and Ed25519 are small and fast at 128-bit security. New systems usually choose Ed25519 or ECDSA P-256.',
    blocks: [
      'A firmware update is checked by millions of small devices, a certificate authority signs all day, and a ledger keeps every signature for ever. Each cares about a different number. Which numbers, and which scheme wins each?',
      { topic: 'p11-compare', frame: 1, caption: 'Sizes: RSA-2048 has 256-byte keys and signatures; DSA has a 256-byte public key and a 56-byte signature; ECDSA P-256 33 and 64 bytes; Ed25519 32 and 64.' },
      { topic: 'p11-compare', frame: 2, caption: 'Signing, counted in multiplications of 256-bit numbers: RSA-2048 about 49,456 even with the CRT; ECDSA 3,514 and Ed25519 3,133.' },
      { predict: { q: 'Which is the cheapest to verify?', options: ['Ed25519', 'ECDSA P-256', 'RSA-2048 with e = 65537', 'DSA 2048/224'], answer: 2, explain: 'Verifying RSA is one exponentiation by e = 65537: 16 squarings and 1 multiplication. The curve schemes need two scalar multiplications.' } },
      { topic: 'p11-compare', frame: 3, caption: 'Verifying: RSA-2048 about 1,088 units, the cheapest; Ed25519 6,086, ECDSA 6,943, DSA 42,944.' },
      { topic: 'p11-compare', frame: 4, caption: 'Security levels as NIST SP 800-57 rates them: RSA-2048 and DSA 2048/224 give 112 bits; RSA-3072, P-256 and Ed25519 give 128.' },
      { topic: 'p11-compare', input: { goal: 'verify' }, frame: 5, caption: 'If cheap verification matters most, RSA-PSS wins; for new systems Ed25519 or ECDSA P-256 are the usual choice.' },
      { table: [['Situation', 'A good choice', 'Why'], ['A new protocol, small messages', 'Ed25519', 'small, fast, nonce derived by design'], ['Hardware or standards that require NIST curves', 'ECDSA P-256 with RFC 6979 nonces', 'widely certified; derived nonces remove the generator risk'], ['Many verifiers, existing RSA infrastructure', 'RSA-PSS, 3072 bits for 128-bit security', 'verification is cheapest'], ['Signatures that must outlive a quantum computer', 'a hash-based or lattice scheme (part 14)', 'Shor breaks all six schemes here']], caption: 'Situations and choices.' },
      { h: 'Recap' },
      { list: ['RSA: large, slow to sign, cheapest to verify. DSA and Schnorr: short signatures, large keys.', 'ECDSA P-256 and Ed25519: 32- or 33-byte keys, 64-byte signatures, 128-bit security.', 'None of them survives a large quantum computer.'] },
      X('sg-x-sizes'), X('sg-x-level'), X('sg-x-choose'),
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
