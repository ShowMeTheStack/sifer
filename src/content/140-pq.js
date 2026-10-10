// Part 14, post-quantum cryptography: the chapters and the lessons. The exercises are in 141-pq-ex.js and 141-pq-ex-b.js;
// the tour and the course in 142-pq-tour.js. Each lesson opens with a question, runs the topic that shows
// the idea at a frame chosen for the point being made, asks for a prediction, sums up, and leads to its exercises.
// Every value quoted here was worked out by the engines (S.PQ.Quantum, S.PQ.Lattice, S.PQ.LWE, S.PQ.MLKEM,
// S.PQ.Lamport, S.PQ.WOTS, S.PQ.Merkle, S.PQ.SLH, S.PQ.McEliece, S.PQ.ToyDSA) on the topics' own inputs.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('pq-grover')) return;
  const X = (id) => ({ exercise: id });

  C.chapter({ id: 'pq-ch-threat', part: 'pq', n: 1, title: 'The quantum threat', blurb: 'Grover halves the exponent of a search; Shor finds periods and with them factors and discrete logarithms. What survives, and at what size.' });
  C.chapter({ id: 'pq-ch-lattice', part: 'pq', n: 2, title: 'Lattices and learning with errors', blurb: 'Good bases and bad ones, reduction in two dimensions, Babai\'s rounding, and a bit hidden under noise you can see.' });
  C.chapter({ id: 'pq-ch-mlkem', part: 'pq', n: 3, title: 'ML-KEM and lattice signatures', blurb: 'The standard key encapsulation from seed to shared key, the NTT that makes it fast, its noise budget, implicit rejection, and why lattice signatures abort.' });
  C.chapter({ id: 'pq-ch-hash', part: 'pq', n: 4, title: 'Hash-based signatures and codes', blurb: 'Lamport and Winternitz one-time keys, Merkle trees and the stateless hypertree, and McEliece\'s scrambled code.' });

  // =========================================================================================================
  // Chapter 1: the quantum threat
  // =========================================================================================================
  C.lesson({
    id: 'pq-grover', chapter: 'pq-ch-threat', title: 'Grover\'s search and key sizes', minutes: 8,
    summary: 'A quantum computer can search N possibilities with about √N calls to the test, not N/2. That halves the exponent of every brute-force attack, so symmetric keys and hashes survive by doubling in size.',
    blocks: [
      'An AES-128 key is one of 2¹²⁸. Classically you try keys one by one and expect to succeed halfway. A quantum computer cannot try them all at once and read the right one off, whatever popular accounts say: measuring a register gives one index at random. So what does it gain?',
      { def: 'Amplitude', text: 'a quantum register over N indices holds N numbers, one per index; measuring it gives index i with chance equal to the square of its amplitude. The squares add up to 1.' },
      { topic: 'pq-grover', frame: 0, caption: 'Four qubits: 16 indices, each with amplitude 1/√16 = 0.25. Measuring now finds the marked index 11 with chance 1/16, no better than a guess.' },
      { topic: 'pq-grover', frame: 2, caption: 'One iteration: the oracle flips the sign of the marked amplitude, then every amplitude is reflected about the mean 0.2188. The marked one grows to 0.6875 and the chance of success is already 0.4727.' },
      { predict: { q: 'Each iteration adds roughly the same angle to the state. After three iterations the chance is 0.9613. What happens after a fourth?', options: ['It reaches 1 exactly', 'It falls, to about 0.58', 'It stays at 0.9613', 'It climbs to 0.99'], answer: 1, explain: 'The state keeps turning by the same angle 2θ, and once it passes the marked direction the chance drops: here to 0.5817. Grover\'s search must stop at the right moment, about (π/4)·√N iterations.' } },
      { topic: 'pq-grover', frame: 7, caption: 'Three iterations are the best for N = 16, about (π/4)·√16. Grover needs about √N tests where a classical search needs N/2 on average: a quadratic speed-up, not an exponential one.' },
      { h: 'What it does to key sizes' },
      'A search over 2ᵏ keys takes about 2^(k/2) Grover iterations, and each iteration is a full run of the cipher on a quantum computer, done one after another. So a k-bit key gives about k/2 bits of security against a quantum attacker. The cure is simple: double k.',
      { topic: 'pq-levels', frame: 2, caption: 'AES-256 keeps 128 bits against a quantum attacker: doubling the key length undoes Grover.' },
      { topic: 'pq-levels', frame: 8, caption: 'For 128 bits against a quantum attacker, AES-256, a SHA-256 preimage and ML-KEM-768 qualify. RSA-2048 and P-256 fall to Shor at any size, the subject of the next lesson.' },
      { tip: 'Hash collisions are a special case. A collision search needs memory as well as time, and the quantum algorithm\'s memory cost is so large that 128 bits remains the practical figure for SHA-256 collisions.' },
      { h: 'Recap' },
      { list: ['Measuring a register gives one index; Grover first moves the probability onto the marked one by repeated sign flips and reflections about the mean.', 'About (π/4)·√N iterations are best; more is worse, because the state keeps turning.', 'A k-bit key gives about k/2 bits against a quantum attacker, so AES-256 and SHA-256 keep 128 bits.'] },
      X('pq-x-grover-iters'), X('pq-x-grover-aes'), X('pq-x-levels'),
    ],
  });

  C.lesson({
    id: 'pq-shor', chapter: 'pq-ch-threat', title: 'Shor\'s period finding', minutes: 9,
    summary: 'Factoring N reduces to finding the period r of aˣ mod N. A quantum Fourier transform finds periods fast; the rest is classical: continued fractions, then two gcds. Discrete logarithms, on curves too, fall the same way.',
    blocks: [
      'RSA rests on factoring and elliptic curves on discrete logarithms. Neither is a search with a single right answer that Grover could speed up a little. Shor\'s method does something stronger: it turns both problems into finding the period of a function, which a quantum computer does in polynomial time. How does a period give a factor?',
      { topic: 'pq-shor', frame: 1, caption: 'For N = 21 and a = 2, the powers 2ˣ mod 21 run 1, 2, 4, 8, 16, 11 and repeat: the period is r = 6.' },
      { math: 'aʳ ≡ 1 (mod N), with r even\n⇒ (a^(r/2) − 1)(a^(r/2) + 1) ≡ 0 (mod N)\n⇒ gcd(a^(r/2) − 1, N) and gcd(a^(r/2) + 1, N) are factors,\n  unless a^(r/2) ≡ −1 (mod N)' },
      { topic: 'pq-shor', frame: 5, caption: 'a^(r/2) = 2³ = 8. gcd(7, 21) = 7 and gcd(9, 21) = 3: N = 7 × 3.' },
      { predict: { q: 'Take N = 21 and a = 4. The powers of 4 mod 21 are 1, 4, 16, 1, … What happens?', options: ['The factors come out as before', 'The period 3 is odd, so a^(r/2) is not defined: choose another a', 'gcd(4, 21) gives a factor', 'The method proves 21 is prime'], answer: 1, explain: 'r = 3 is odd, so there is no a^(r/2) to take. The method simply tries another a; at least half of all choices work.' } },
      { h: 'The quantum part' },
      'Only finding r needs a quantum computer. A register holds every x at once, the function aˣ mod N is computed into a second register, and a quantum Fourier transform turns the repetition into peaks at multiples of Q/r. One measurement gives a value y near one of them.',
      { topic: 'pq-shor', frame: 2, caption: 'With Q = 512, the peaks sit near multiples of 512/6 = 85.33. Each of the 6 peaks has a chance of about 1/6.' },
      { topic: 'pq-shor', frame: 3, caption: 'The measurement gives y = 341. y/Q = 341/512 ≈ 0.66602, and its continued-fraction convergents with denominator below N are 0/1, 1/1, 1/2, 2/3. The denominators are the candidates for r.' },
      'Candidate 3 fails (2³ = 8, not 1), and doubling it gives 6, which works. Every step after the measurement is ordinary arithmetic.',
      { topic: 'pq-shor', frame: 6, caption: 'For RSA-2048 the same steps take a number of operations polynomial in 2048: its 112 bits of classical security drop to 0. Shor works in any group, so P-256 falls too. No larger key helps.' },
      { warn: 'Data encrypted today can be recorded and decrypted later, once a large quantum computer exists. This "harvest now, decrypt later" threat is why key exchange is moving to post-quantum schemes before such machines are built.' },
      { h: 'Recap' },
      { list: ['Factoring reduces to finding the period r of aˣ mod N; with r even and a^(r/2) ≢ −1, two gcds give the factors.', 'The quantum Fourier transform makes the period show as peaks; continued fractions read r off one measurement.', 'RSA and elliptic-curve cryptography are broken at every key size; they must be replaced, not enlarged.'] },
      X('pq-x-shor-factor'), X('pq-x-shor-bad-a'), X('pq-x-assumption'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: lattices and LWE
  // =========================================================================================================
  C.lesson({
    id: 'pq-bases', chapter: 'pq-ch-lattice', title: 'Lattices, good bases and bad', minutes: 8,
    summary: 'A lattice is every whole-number combination of a few basis vectors. The same lattice has many bases: short, nearly perpendicular ones make problems easy, long and nearly parallel ones hide its structure.',
    blocks: [
      'The schemes that replace RSA and elliptic curves for key exchange are built on lattices. The hard problems sound innocent: find a short vector, or the lattice point nearest a given point. Why are they hard, when in two dimensions you could do them by eye?',
      { def: 'Lattice', text: 'all the points m·b₁ + n·b₂ (in two dimensions) for whole numbers m and n. The vectors b₁ and b₂ are a basis.' },
      { topic: 'pq-lattice-bases', frame: 1, caption: 'A good basis, g₁ = (6, 0) and g₂ = (−1, 4): short and nearly at right angles. Its cell has area 24, and its Hadamard ratio is 0.985, close to 1.' },
      { topic: 'pq-lattice-bases', frame: 3, caption: 'A bad basis of the very same lattice: b₁ = (9, 12) and b₂ = (4, 8). The cell still has area 24, but it is a thin sliver: the Hadamard ratio is only 0.423.' },
      { predict: { q: 'Mixing a basis by an integer matrix U gives another set of lattice vectors. When is it a basis of the same lattice?', options: ['When U has whole entries', 'When the determinant of U is ±1', 'When U is symmetric', 'Always'], answer: 1, explain: 'U must have whole entries and an inverse with whole entries, which happens exactly when det U = ±1. Any other U gives a sub-lattice, with a bigger cell.' } },
      { topic: 'pq-lattice-bases', frame: 4, caption: 'Here U has rows (2, 3) and (1, 2), with determinant 1. Each basis gives the other: a basis is only a way of naming the same points.' },
      { topic: 'pq-lattice-bases', frame: 5, caption: 'The shortest non-zero vector is (1, −4), of length 4.12. From the good basis it is in plain sight; from the bad one alone, finding it is the shortest vector problem.' },
      { h: 'Gram–Schmidt: how good is a basis?' },
      'Gram–Schmidt makes the basis perpendicular, step by step: each vector keeps only the part the earlier ones do not point along. The lengths of the new vectors measure the basis. For a good basis they are even; for a bad one the first is long and the last tiny.',
      { topic: 'pq-gram-schmidt', frame: 1, caption: 'For b₁ = (6, 1) and b₂ = (2, 5): μ = ⟨b₂, b₁⟩ / ⟨b₁, b₁⟩ = 17/37 = 0.46, the length of b₂\'s shadow on b₁ in units of b₁.' },
      { topic: 'pq-gram-schmidt', frame: 3, caption: 'b₂* = b₂ − μ·b₁ = (−0.76, 4.54). The product |b₁*|·|b₂*| = 6.08 × 4.60 = 28.00 is the area of the cell, |det B|, for every basis.' },
      { h: 'Recap' },
      { list: ['A lattice has many bases; two bases differ by an integer matrix of determinant ±1.', 'The cell\'s area, |det B|, is the same for every basis; the shape is not.', 'Good bases are short and nearly perpendicular (Hadamard ratio near 1); the shortest vector problem asks for what a good basis shows.'] },
      X('pq-x-det'), X('pq-x-unimodular'), X('pq-x-gs-mu'),
    ],
  });

  C.lesson({
    id: 'pq-reduce', chapter: 'pq-ch-lattice', title: 'Reduction and the closest vector', minutes: 9,
    summary: 'In two dimensions Lagrange–Gauss reduction turns any basis into a good one, like Euclid\'s algorithm on vectors. With a good basis, rounding the coordinates of a target finds the nearest lattice point; with a bad one it misses.',
    blocks: [
      'If a good basis makes lattice problems easy, why not compute one from the bad basis? In two dimensions that is exactly what an algorithm from the eighteenth century does. The trouble starts in hundreds of dimensions.',
      { topic: 'pq-gauss', frame: 0, caption: 'Start with the bad basis b₁ = (9, 12) and b₂ = (4, 8).' },
      { math: 'repeat:\n  if |b₂| < |b₁|: swap them\n  m = round(⟨b₂, b₁⟩ / ⟨b₁, b₁⟩)\n  if m = 0: stop\n  b₂ ← b₂ − m·b₁' },
      { topic: 'pq-gauss', frame: 2, caption: 'b₂ ← b₂ − 2·b₁ = (1, −4), of length 4.123. The cell keeps its area, 24, and leans less.' },
      { predict: { q: 'Gauss reduction looks like another algorithm you know. Which one?', options: ['Square-and-multiply', 'Euclid\'s algorithm for the gcd', 'Gaussian elimination', 'The Chinese remainder theorem'], answer: 1, explain: 'Each step subtracts the best multiple of the shorter vector from the longer, and swaps: Euclid\'s algorithm with vectors in place of numbers. It stops when no multiple shortens anything.' } },
      { topic: 'pq-gauss', frame: 5, caption: 'Reduced: b₁ = (1, −4) is a shortest non-zero vector, and exhaustive search agrees, length 4.12.' },
      'In higher dimensions the LLL algorithm does a similar job, but only approximately: the vector it finds can be longer than the shortest by a factor that grows exponentially with the dimension. For the dimensions of ML-KEM (768 for the middle set) no known algorithm, classical or quantum, finds short enough vectors in reasonable time.',
      { h: 'Babai\'s rounding' },
      'To find the lattice point nearest a target t, write t in the basis and round each coordinate to a whole number. Whether this works depends on the basis.',
      { topic: 'pq-babai', frame: 1, caption: 'Good basis: t = (7, 3) = 1.29·g₁ + 0.75·g₂ rounds to (1, 1), the point (5, 4) at distance 2.24, the closest.' },
      { topic: 'pq-babai', frame: 2, caption: 'Bad basis, same t: the coefficients round to (2, −2), the point (10, 8) at distance 5.83, 2.61 times too far. The region that rounds to a point is a long thin sliver.' },
      { tip: 'This is the shape of lattice encryption: the public key is a bad description, the private key a good one. Decrypting means finding the nearest lattice point to a noisy target, which only the holder of the good description can do.' },
      { h: 'Recap' },
      { list: ['Lagrange–Gauss reduction is Euclid on vectors; it finds a shortest vector in two dimensions.', 'In high dimensions reduction (LLL and its successors) only approximates, and the gap is what lattice cryptography relies on.', 'Babai\'s rounding finds the closest point with a good basis and misses with a bad one.'] },
      X('pq-x-gauss-table'), X('pq-x-gauss-code'), X('pq-x-babai'),
    ],
  });

  C.lesson({
    id: 'pq-lwe', chapter: 'pq-ch-lattice', title: 'Learning with errors', minutes: 9,
    summary: 'Linear equations about a secret are solved in a moment; the same equations with a small error added to each are believed hard even for a quantum computer. A bit is encrypted by adding up equations, and decrypts correctly while the summed noise stays under a quarter of the modulus.',
    blocks: [
      'Give someone sixteen equations Aᵢ·s = bᵢ (mod 101) in eight unknowns and they find s by Gaussian elimination. Add a small random error to each bᵢ and elimination falls apart: subtracting equations adds their errors, until the noise swamps the values. How can that noise be useful for encryption, rather than a nuisance?',
      { topic: 'pq-lwe', frame: 2, caption: 'The public key is A and b = A·s + e mod 101, with each eᵢ in [−2, 2]. Row 0 reads 68 + 0 = 68. Recovering s from (A, b) is the learning-with-errors problem.' },
      { topic: 'pq-lwe', frame: 3, caption: 'To encrypt the bit 1, add up a random set of 8 rows: u is the sum of those Aᵢ, and v is the sum of their bᵢ plus ⌊q/2⌋ = 50. The pair (u, v) looks like one more LWE sample.' },
      { topic: 'pq-lwe', frame: 4, caption: 'The holder of s computes v − s·u = 47 (mod 101): the Aᵢ·s cancel, leaving 50 plus the noise −3. The result is nearer 50 than 0, so the bit is 1.' },
      { math: 'v − s·u = bit·⌊q/2⌋ + Σ eᵢ (over the chosen rows)   (mod q)\ncorrect while |Σ eᵢ| < q/4' },
      { predict: { q: 'Raise the noise bound from ±2 to ±8, keeping 16 samples and q = 101. What happens to decryption?', options: ['Nothing: the noise cancels', 'It fails now and then', 'It always fails', 'It becomes faster'], answer: 1, explain: 'A sum of about 8 errors of up to ±8 often passes q/4 = 25.25. With these parameters about 6.87% of decryptions go wrong.' } },
      { topic: 'pq-lwe', frame: 4, input: { B: '8', m: '16', q: '101', bit: '1', seed: 1, enc: 5 }, caption: 'Noise ±8: here the summed noise is −30, past q/4 = 25.25, and the bit 1 decrypts as 0.' },
      { topic: 'pq-lwe', frame: 5, input: { B: '8', m: '16', q: '101', bit: '1', seed: 1, enc: 5 }, caption: 'The summed noise is a bell; decryption fails when it lands in the red tails beyond ±q/4. For these parameters that is 6.87%; the worst case, 16 × 8 = 128, is far beyond 25.25.' },
      'There are two ways to make failure impossible or negligible: keep the worst case m·B below q/4, or choose sizes so that the tails are astronomically thin. Real schemes take the second, because the first needs a modulus too large for the noise to protect the secret.',
      { h: 'Recap' },
      { list: ['LWE: given A and b = A·s + e (mod q) with small e, find s. Without e it is linear algebra; with e it is believed hard, quantum or not.', 'Encrypt a bit: sum a random set of samples and add bit·⌊q/2⌋. Decrypt: v − s·u, and see whether it is nearer 0 or q/2.', 'Decryption is right while the summed noise stays under q/4; more noise is more security and more failures.'] },
      X('pq-x-lwe-dec'), X('pq-x-lwe-worst'), X('pq-x-lwe-fail'),
    ],
  });

  // =========================================================================================================
  // Chapter 3: ML-KEM and lattice signatures
  // =========================================================================================================
  C.lesson({
    id: 'pq-mlkem', chapter: 'pq-ch-mlkem', title: 'ML-KEM from seed to shared key', minutes: 10,
    summary: 'ML-KEM (FIPS 203) is LWE over polynomial rings, wrapped so that two parties end up with the same 32-byte key. Key generation makes t̂ = Â∘ŝ + ê; encapsulation hides a random message under the public key; decapsulation recovers it, re-encrypts, and compares.',
    blocks: [
      'The toy LWE scheme encrypts one bit with a public key of hundreds of numbers. A key exchange for every web connection needs 256 bits at once, a public key of about a kilobyte, and protection against an attacker who sends crafted ciphertexts. How does the standard get there?',
      'Three changes. The numbers become polynomials of degree below 256 with coefficients mod q = 3329, so one sample carries 256 coefficients. The matrix is a small k×k matrix of such polynomials (k = 2, 3 or 4), made from a 32-byte seed rather than stored. And the encryption is wrapped in a transform that checks every ciphertext.',
      { topic: 'pq-mlkem-flow', frame: 0, caption: 'ML-KEM-768: k = 3. Two seeds d and z; (ρ, σ) = G(d ‖ 3) splits into the public ρ, which seeds the matrix, and the secret σ, which seeds the noise.' },
      { topic: 'pq-mlkem-flow', frame: 4, caption: 't̂ = Â∘ŝ + ê: the Module-LWE sample, computed in the NTT domain. Without ê this would be linear algebra.' },
      { topic: 'pq-mlkem-flow', frame: 5, caption: 'ek = ByteEncode₁₂(t̂) ‖ ρ is 1184 bytes; dk is 2400 bytes, and keeps a copy of ek, its hash H(ek) and the secret z.' },
      { h: 'Encapsulation' },
      { topic: 'pq-mlkem-flow', frame: 6, caption: 'Bob picks a random 32-byte m. (K, r) = G(m ‖ H(ek)) gives the shared key K and the randomness r for encrypting m: everything after this is determined by m.' },
      { topic: 'pq-mlkem-flow', frame: 10, caption: 'Each message bit becomes 0 or 1665 (about q/2), and v = NTT⁻¹(t̂ᵀ∘ŷ) + e₂ + μ carries it under noise: the toy LWE bit, 256 times over.' },
      { topic: 'pq-mlkem-flow', frame: 11, caption: 'u is compressed to 10 bits a coefficient and v to 4: c is 960 + 128 = 1088 bytes.' },
      { predict: { q: 'Alice decrypts and gets m′. Why does she then encrypt m′ again with r′ from G(m′ ‖ H(ek)) before accepting?', options: ['To refresh her key', 'To check that the ciphertext is exactly what an honest encrypter of m′ would have sent', 'To compress the key', 'It is only a test run and can be skipped'], answer: 1, explain: 'Re-encryption is the Fujisaki–Okamoto check. A ciphertext crafted by an attacker does not re-encrypt to itself, so it is caught, and decryption failures cannot be probed.' } },
      { topic: 'pq-mlkem-flow', frame: 12, caption: 'Decryption: w = v′ − ŝᵀu′ leaves μ plus noise. The largest noise here is 243, inside the ±832 at which a bit would flip.' },
      { topic: 'pq-mlkem-flow', frame: 17, caption: 'The re-encryption equals c, so K = 34f98ac3682f376c… is accepted: both sides hold the same 32 bytes.' },
      { h: 'Implicit rejection' },
      'Suppose one bit of v is flipped on the way. Decryption then gets an m′ that differs from m in one bit, so r′ differs completely, and the re-encryption differs from the received ciphertext in 1084 of its 1088 bytes.',
      { topic: 'pq-mlkem-reject', frame: 4, caption: 'Decapsulation does not say "invalid". It returns K̄ = J(z ‖ c), a key that looks real; the connection simply fails later. The attacker learns nothing about why.' },
      { table: [['Set', 'k', 'ek (bytes)', 'dk (bytes)', 'c (bytes)', 'Category'], ['ML-KEM-512', '2', '800', '1632', '768', '1'], ['ML-KEM-768', '3', '1184', '2400', '1088', '3'], ['ML-KEM-1024', '4', '1568', '3168', '1568', '5']], caption: 'Sizes: ek = 384k + 32, dk = 768k + 96, c = 32(d_u·k + d_v). The shared key is always 32 bytes.' },
      { h: 'Recap' },
      { list: ['ML-KEM is Module-LWE over Z₃₃₂₉[X]/(X²⁵⁶ + 1) with a k×k matrix made from a seed.', 'Encapsulation derives K and all its randomness from a random m; decapsulation decrypts m, re-encrypts and compares.', 'A mismatch gives a pseudo-random key J(z ‖ c), never an error message.'] },
      X('pq-x-mlkem-ek'), X('pq-x-mlkem-c'), X('pq-x-mlkem-dk'), X('pq-x-reject'),
    ],
  });

  C.lesson({
    id: 'pq-ntt', chapter: 'pq-ch-mlkem', title: 'The NTT and the noise budget', minutes: 9,
    summary: 'Multiplying polynomials of 256 coefficients takes 65 536 products done naively. The number-theoretic transform does it in a few thousand, with butterflies like the FFT\'s. Compression then shrinks the ciphertext by adding rounding noise, spent from the same budget as the LWE noise.',
    blocks: [
      'Every step of ML-KEM multiplies polynomials mod X²⁵⁶ + 1. Done coefficient by coefficient, one product costs 256 × 256 multiplications, and a key generation needs dozens. Is there a shortcut?',
      'The trick is the same as in the fast Fourier transform: evaluate instead of multiply. Because q = 3329 has a 256th root of unity, ζ = 17, the polynomial X²⁵⁶ + 1 splits mod q into 128 factors X² − γ. Reducing f modulo each factor turns one big product into 128 small ones.',
      { topic: 'pq-ntt', frame: 1, caption: 'Layer 1: coefficient j meets j + 128. With ζ = 1729, t = 1729 × 3328 mod 3329 = 1600, and the pair becomes 1600 and 1729: (a, b) ↦ (a + ζb, a − ζb).' },
      { math: 'butterfly(a, b, ζ):  t = ζ·b mod q;  a′ = a + t;  b′ = a − t   (mod q)' },
      { topic: 'pq-ntt', frame: 5, caption: 'Layer 5 for coefficient 5: it meets 13, with ζ = 296. Seven layers of 128 butterflies each make the transform.' },
      { predict: { q: 'ML-KEM\'s NTT stops after 7 layers, not 8. What is left at the end?', options: ['256 single numbers', '128 pairs, each a polynomial of degree one modulo some X² − γ', 'One polynomial of degree 255', 'Two halves of 128 coefficients'], answer: 1, explain: 'ζ = 17 is a 256th root of unity, not a 512th, so X²⁵⁶ + 1 splits only into quadratics. Products in the NTT domain multiply 128 pairs of degree-one polynomials.' } },
      { topic: 'pq-ntt', frame: 8, caption: 'Three transforms of 896 butterflies and 128 small products give the same 256 coefficients as the schoolbook product: a few thousand multiplications instead of 65 536.' },
      { h: 'Compression and the noise budget' },
      { topic: 'pq-mlkem-noise', frame: 0, caption: 'Compress₄ keeps the top 4 bits: Compress₄(1000) = 5, and Decompress₄(5) = 1040, 40 away. That rounding error is extra noise, accepted to make the ciphertext smaller.' },
      { topic: 'pq-mlkem-noise', frame: 1, caption: 'The rounding error is at most 2 for u (d_u = 10) but 104 for v (d_v = 4). A bit of m is lost only when the total noise in a coefficient reaches 832, about q/4.' },
      { topic: 'pq-mlkem-noise', frame: 3, caption: 'Eight runs, 2048 coefficients: the noise is a narrow bell, the largest 232, 3.6 times inside the budget. A coefficient reaching 832 is astronomically rare.' },
      { h: 'Recap' },
      { list: ['The NTT evaluates a polynomial modulo the factors of X²⁵⁶ + 1, with butterflies (a, b) ↦ (a + ζb, a − ζb).', 'ML-KEM stops at 128 quadratic factors; a product becomes 128 small products.', 'Compression saves bytes and adds noise; the parameters keep the total far below q/4.'] },
      X('pq-x-ntt-table'), X('pq-x-ntt-code'), X('pq-x-compress'),
    ],
  });

  C.lesson({
    id: 'pq-mldsa', chapter: 'pq-ch-mlkem', title: 'Lattice signatures and rejection', minutes: 7,
    summary: 'ML-DSA signs by Fiat–Shamir: commit to a masked value, get a challenge from a hash, answer z = y + c·s₁. Each answer would leak a little about s₁, so answers that come too near the edge are thrown away and the signer tries again.',
    blocks: [
      'A Schnorr signature answers a challenge with z = y + c·x, and the random y hides x completely because it is uniform modulo the group order. In a lattice signature, z must stay short, so y is drawn from a bounded range. Can a bounded y still hide c·s₁?',
      { topic: 'pq-toysig', frame: 0, caption: 'A toy in the style of ML-DSA: the secret s₁ has coefficients in [−2, 2]; with τ = 8 entries ±1 in the challenge, c·s₁ is at most β = 16 in each coefficient. γ₁ = 1024 bounds the mask y.' },
      { topic: 'pq-toysig', frame: 1, caption: 'Attempt 1: ‖z‖∞ = 1016 is at least γ₁ − β = 1008, so this z would show where c·s₁ pushed it. Abort and draw a new y.' },
      { predict: { q: 'y alone never goes past 1024. A published z has a coefficient of 1030. What does the attacker learn?', options: ['Nothing', 'That c·s₁ is positive in that coefficient', 'The whole of s₁', 'The mask y'], answer: 1, explain: 'Only a positive push from c·s₁ could carry z past the range of y. Each such coefficient tells the sign of c·s₁ there; enough of them give s₁ away.' } },
      { topic: 'pq-toysig', frame: 6, caption: 'Without rejection, 300 signatures put 12 coefficients past γ₁, and all 12 sit where c·s₁ is positive.' },
      { topic: 'pq-toysig', frame: 7, caption: 'With rejection only answers with every |zᵢ| < 1008 go out: 106 of the 300 pass. Inside that range z is uniform whatever c·s₁ was, so nothing leaks.' },
      'The price is time: a signer may need several attempts. ML-DSA chooses its bounds so that the expected number of attempts stays small (about four to five for its sets), and its verification is a single pass.',
      { h: 'Recap' },
      { list: ['A lattice signature answers a challenge with a short z = y + c·s₁.', 'A bounded y cannot hide c·s₁ near the edges, so answers with ‖z‖∞ ≥ γ₁ − β are rejected.', 'The accepted answers are uniform on a smaller range: nothing about s₁ leaks.'] },
      X('pq-x-mldsa-bound'), X('pq-x-mldsa-why'),
    ],
  });

  // =========================================================================================================
  // Chapter 4: hash-based signatures and codes
  // =========================================================================================================
  C.lesson({
    id: 'pq-lamport', chapter: 'pq-ch-hash', title: 'Lamport one-time signatures', minutes: 8,
    summary: 'A signature can rest on nothing but a hash function: publish the hashes of secret strings, and sign by revealing some of the strings. It is quantum-safe and simple, and a key may be used once only.',
    blocks: [
      'Every public-key signature so far rests on a number-theoretic problem that Shor breaks. Is there a signature that needs only a hash function, which a quantum computer at best speeds up by Grover?',
      { topic: 'pq-lamport', frame: 0, caption: 'The private key: 16 pairs of random 2-byte strings, one pair per bit of a 16-bit digest. The public key is the hash of each of the 32 strings.' },
      { topic: 'pq-lamport', frame: 1, caption: 'Sign “ship the tea on Tuesday”: its digest bits are 1111000010100011. For each bit reveal one string of the pair, the first for 0 and the second for 1.' },
      { topic: 'pq-lamport', frame: 2, caption: 'The verifier hashes each revealed string and compares it with the public half the digest bit selects: all 16 match.' },
      { predict: { q: 'The same key now signs a second message whose digest differs from the first in 10 of the 16 bits. How many pairs have both strings public?', options: ['0', '6', '10', '16'], answer: 2, explain: 'Wherever the two digests differ, the second signature reveals the other string of the pair. Both halves of those 10 pairs are now known.' } },
      { topic: 'pq-lamport', frame: 3, caption: '“hold the tea until Friday” has digest 1110110101000100: 10 pairs are now fully public.' },
      { topic: 'pq-lamport', frame: 4, caption: 'The forger needs a message whose digest agrees with both signatures wherever they agreed. “pay the bearer 7 crowns” fits: its signature is assembled from the two public ones, and it verifies.' },
      { warn: 'A 16-bit digest makes the forgery quick, but the reuse is the flaw, not the size. With a 256-bit digest, each signature on the same key halves, on average, the number of digest bits a forger is still bound to: about 128 after two signatures, 32 after four, 16 after five. A few reuses and the search is over in seconds.' },
      { table: [['Digest', 'String', 'Public key', 'Signature'], ['256 bits', '32 bytes', '2 × 256 × 32 = 16 384 bytes', '256 × 32 = 8192 bytes']], caption: 'Lamport is simple and large: one key, one message.' },
      { h: 'Recap' },
      { list: ['Public key: the hashes of 2 × (digest bits) secret strings. Signature: one string per digest bit, chosen by the bit.', 'Security needs only a one-way hash; Grover is the best quantum attack.', 'A second signature reveals the other half of every pair where the digests differ: a key signs once.'] },
      X('pq-x-lamport-pk'), X('pq-x-lamport-sig'), X('pq-x-lamport-sign'), X('pq-x-lamport-verify'), X('pq-x-lamport-reuse'), X('pq-x-reuse-defence'),
    ],
  });

  C.lesson({
    id: 'pq-wots', chapter: 'pq-ch-hash', title: 'Winternitz chains and the checksum', minutes: 8,
    summary: 'Winternitz signs several bits per secret: each secret starts a chain of hashes, and the signature for a base-w digit d is the value d steps up the chain. A checksum on the digits stops anyone walking chains forward to sign a larger digest.',
    blocks: [
      'Lamport spends two secrets on every bit. A hash chain can encode a whole number instead: publish the end of a chain of 15 hashes, and reveal the value d steps from the start to sign the digit d. The verifier finishes the chain. What stops an attacker from taking a few more steps?',
      { topic: 'pq-winternitz', frame: 0, caption: 'w = 16: 4 chains for the four hex digits of a 16-bit digest and 2 for the checksum, each 15 hashes long. The public key is the hash of the 6 chain ends.' },
      { topic: 'pq-winternitz', frame: 1, caption: 'The digest of “release the second shipment” gives the digits 4, 2, 15, 8. Chain i will be revealed dᵢ steps up.' },
      { topic: 'pq-winternitz', frame: 2, caption: 'Checksum Σ(15 − dᵢ) = 11 + 13 + 0 + 7 = 31, written in base 16 as 1 15. Raising any message digit lowers the checksum.' },
      { predict: { q: 'Without the checksum, an attacker holds a signature on the digits 4, 2, 15, 8. Which digest could he sign?', options: ['Any digest at all', 'Any digest whose digits are each at least 4, 2, 15, 8', 'Any digest whose digits are each at most 4, 2, 15, 8', 'None'], answer: 1, explain: 'Walking forward along a chain is just hashing, which anyone can do. Walking back would mean inverting the hash. So every digit can only go up.' } },
      { topic: 'pq-winternitz', frame: 4, input: { cs: 'no' }, caption: 'No checksum: “release shipment number 30” has digits 11, 15, 15, 10, all at least the signed ones. Walking each chain forward gives a valid signature.' },
      { topic: 'pq-winternitz', frame: 5, caption: 'With the checksum, raising the message digits lowers the checksum digits: for “release shipment number 300” two chains would have to go backwards. None of 300 tries works.' },
      { math: 'len₁ = ⌈8n / log₂ w⌉ message digits\nlen₂ = ⌊log₂(len₁·(w − 1)) / log₂ w⌋ + 1 checksum digits\nsignature = (len₁ + len₂) values of n bytes' },
      { h: 'Recap' },
      { list: ['A chain of w − 1 hashes signs one base-w digit: reveal the value d steps up; the verifier walks the remaining w − 1 − d.', 'The checksum Σ(w − 1 − dᵢ) makes any forward walk on the message digits force a backward walk on the checksum.', 'Larger w means shorter signatures and more hashing. A Winternitz key is still one-time.'] },
      X('pq-x-wots-table'), X('pq-x-wots-size'),
    ],
  });

  C.lesson({
    id: 'pq-merkle', chapter: 'pq-ch-hash', title: 'Merkle trees and SLH-DSA', minutes: 9,
    summary: 'A Merkle tree hashes many one-time public keys into one short root. A signature is one one-time signature plus the path of siblings to the root. Stateful trees must never reuse a leaf; SLH-DSA picks the leaf from the message hash and needs no state.',
    blocks: [
      'One-time keys are fine for one message. A server that signs thousands of messages would have to publish thousands of public keys. Can one short public key stand for all of them?',
      { topic: 'pq-merkle', frame: 3, caption: '8 WOTS public keys are hashed in pairs, level by level, to the root 43ceac37c420…: the whole public key is 16 bytes.' },
      { topic: 'pq-merkle', frame: 5, caption: 'Signing with key 5 attaches its authentication path: the 3 siblings on the way from leaf 5 to the root.' },
      { predict: { q: 'Leaf 5 sits at the bottom of a tree of height 3. Its sibling at level 0 is leaf 4. Which node is its sibling at level 1?', options: ['Node 1', 'Node 3', 'Node 2', 'Node 0'], answer: 1, explain: 'Leaf 5\'s parent is node ⌊5/2⌋ = 2 at level 1, and its sibling is 2 XOR 1 = 3. At level 2 the parent is node 1, whose sibling is node 0.' } },
      { topic: 'pq-merkle', frame: 9, caption: 'The verifier hashes the leaf with each sibling in turn, on the left or the right as the index bits say, and reaches node 0 = 43ceac37c420…' },
      { topic: 'pq-merkle', frame: 10, caption: 'The computed root equals the public key. But the signer must keep state: key 5 is spent, and after 8 signatures the tree is used up.' },
      { warn: 'State is the weak point of stateful schemes such as XMSS and LMS. A backup restored, a virtual machine cloned or a counter not saved before a crash, and a leaf is used twice: the Lamport forgery again.' },
      { h: 'SLH-DSA: no state' },
      { topic: 'pq-slhdsa', frame: 1, caption: 'The message digest itself chooses the bottom tree, the leaf and the FORS indices: here FORS indices (4, 3, 2, 3) under bottom tree 4, leaf 7. The signer keeps nothing.' },
      { topic: 'pq-slhdsa', frame: 5, caption: 'The toy signature is 1488 bytes; the standard\'s sets give 8 to 50 kilobytes. That is the price of resting on a hash function alone.' },
      { h: 'Recap' },
      { list: ['A Merkle root stands for 2ʰ one-time keys; a signature carries the h siblings that lead from the leaf to the root.', 'Stateful schemes must never reuse a leaf.', 'SLH-DSA chooses the leaf with the message hash in a huge hypertree, with FORS at the bottom, so it needs no state, at the cost of large signatures.'] },
      X('pq-x-merkle-path'),
    ],
  });

  C.lesson({
    id: 'pq-mceliece', chapter: 'pq-ch-hash', title: 'McEliece, and choosing a scheme', minutes: 8,
    summary: 'McEliece hides a fast-decodable Goppa code behind a random-looking generator matrix. Encryption adds a few errors; only the owner of the structure can remove them. It has resisted attack for over four decades, at the price of very large keys.',
    blocks: [
      'Error-correcting codes fix a few flipped bits for anyone who knows the code. Could a code be published in a disguise that hides how to decode it, so that adding errors becomes encryption?',
      'The simplest code shows the idea. In the Hamming [7, 4] code, column j of the check matrix H is j in binary, so the syndrome H·wᵀ of a word with one flipped bit spells the position of that bit.',
      { topic: 'pq-mceliece', frame: 1, caption: 'The secret Goppa code corrects 2 errors. It is published as G′ = S·G·P: scrambled by an invertible S and a permutation P, it looks like a random code.' },
      { topic: 'pq-mceliece', frame: 3, caption: 'Encrypt 10110010: m·G′ plus an error of weight 2 gives c = 1011000110100110. Without the structure, finding the 2 flipped bits means decoding a random-looking code.' },
      { predict: { q: 'The sender adds 3 errors to a code that corrects 2. What does the receiver get?', options: ['The message, with one extra step', 'A wrong message or a decoding failure', 'An error message from the code, saying 3 bits were wrong', 'The message, because S and P absorb an error'], answer: 1, explain: 'A code that corrects t errors may decode a word with t + 1 errors to the wrong codeword, or fail. The scheme fixes the weight at t exactly.' } },
      { topic: 'pq-mceliece', frame: 9, caption: 'The owner undoes P, decodes the Goppa code with Patterson\'s algorithm, finds the errors at positions 11 and 13, and solves for m = 10110010.' },
      { topic: 'pq-mceliece', frame: 10, caption: 'The secret is the structure: g, the support, S and P. Real public keys run to hundreds of kilobytes.' },
      { h: 'Choosing a post-quantum scheme' },
      { table: [['Use', 'Scheme', 'Rests on', 'Sizes (bytes)'], ['Key exchange in TLS, VPNs', 'ML-KEM-768', 'Module-LWE', 'ek 1184, c 1088'], ['General signatures', 'ML-DSA', 'Module-LWE and SIS', 'signatures a few thousand'], ['Long-lived signatures: firmware, roots of trust', 'SLH-DSA', 'hash functions only', 'signatures 8 000 to 50 000'], ['Stateful signing with careful state', 'XMSS, LMS', 'hash functions only', 'signatures a few thousand'], ['Conservative encryption, large static keys acceptable', 'Classic McEliece', 'decoding random codes', 'public keys 250 000 and up']], caption: 'Each choice trades size, speed and how conservative the assumption is.' },
      { tip: 'During the transition, many systems run a classical and a post-quantum scheme together (a hybrid, such as X25519 with ML-KEM-768) and derive the key from both, so that the connection is safe if either one holds.' },
      { h: 'Recap' },
      { list: ['McEliece encrypts by adding t errors to a codeword of a disguised Goppa code; the owner decodes with the hidden structure.', 'Decoding a random linear code has no known fast method, quantum or classical.', 'ML-KEM for key exchange, ML-DSA for signatures, SLH-DSA where only hash assumptions will do.'] },
      X('pq-x-hamming'), X('pq-x-choose'),
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
