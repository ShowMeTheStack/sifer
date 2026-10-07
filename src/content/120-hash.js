// Part 12, hash functions: the chapters and the lessons. The exercises are in 121-hash-ex.js and the CTF challenges,
// the tour and the course in 122-hash-ctf.js. Each lesson opens with a question, runs a topic at a frame chosen for
// the point being made, asks for a prediction, sums up, and leads to its exercises. Every value quoted in a caption
// is what the topic's engine (S.Hash, S.SHA256, S.Keccak) computes for that input.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('hs-games')) return;
  const X = (id) => ({ exercise: id });

  C.chapter({ id: 'hs-req', part: 'hash', n: 1, title: 'What a hash must resist', blurb: 'Preimages, second preimages and collisions as games, and the birthday paradox that makes collisions cost only the square root.' });
  C.chapter({ id: 'hs-md', part: 'hash', n: 2, title: 'Merkle–Damgård and SHA-256', blurb: 'Padding with the length, a chain of compressions, the message schedule and the 64 rounds of SHA-256, and how SHA-1 and MD5 fell.' });
  C.chapter({ id: 'hs-sha3', part: 'hash', n: 3, title: 'SHA-3 and the sponge', blurb: 'Absorb into the rate, squeeze out of it, never touch the capacity; θ, ρ, π, χ and ι on a 1600-bit state; SHAKE.' });
  C.chapter({ id: 'hs-attacks', part: 'hash', n: 4, title: 'Attacks on hashes', blurb: 'Birthday tables and rho walks on truncated digests, Joux multicollisions, and length extension against a secret-prefix MAC.' });

  // =========================================================================================================
  // Chapter 1: what a hash must resist
  // =========================================================================================================
  C.lesson({
    id: 'hs-games', chapter: 'hs-req', title: 'Three games a hash must win', minutes: 8,
    summary: 'A cryptographic hash is judged by three games. Preimage: given a digest, find any message for it. Second preimage: given a message, find another with the same digest. Collision: find any two messages with one digest. The last is the easiest to win.',
    blocks: [
      'A website stores SHA-256 of each password instead of the password. A software mirror publishes SHA-256 of each download. A signature scheme signs SHA-256 of a contract instead of the contract. All three trust the hash, but they trust it for different things. What exactly must be hard?',
      { def: 'Preimage resistance', text: 'given a digest y, it is infeasible to find any m with H(m) = y. The password file relies on it.' },
      { def: 'Second-preimage resistance', text: 'given a message m, it is infeasible to find m′ ≠ m with H(m′) = H(m). The download mirror relies on it.' },
      { def: 'Collision resistance', text: 'it is infeasible to find any pair m ≠ m′ with H(m) = H(m′). The signed contract relies on it: whoever writes the contract may also have prepared its evil twin.' },
      'To watch the games being played we cut SHA-256 down to its first 12 bits, so there are only 4,096 possible digests and an adversary can win in a moment.',
      { topic: 'p12-games', frame: 1, caption: 'The preimage game: the challenger hashes a secret and hands over only y = 5d6. Any message with that digest wins, not just the secret.' },
      { topic: 'p12-games', frame: 3, caption: 'The adversary can only guess and check. Try 741, “guess 741”, hashes to 5d6: it wins after 741 tries, against 4,096 expected on average.' },
      { predict: { q: 'With the same 12-bit hash, about how many messages must the adversary hash to win the collision game, where it may choose both messages?', options: ['About 4,096, as for a preimage', 'About 2,048, half as many', 'About 80', 'About 12'], answer: 2, explain: 'Each new digest can match any of the ones already stored, not one fixed target. The expected number is about √(πN/2) ≈ 80 for N = 4,096: the square root, not N.' } },
      { topic: 'p12-games', input: { game: 'coll', bits: '12', seed: 3 }, frame: 3, caption: 'The collision game: try 70, “ticket 3-70”, gives cc8, already in the table from try 18. The full digests differ beyond the first 12 bits (cc82c33e… and cc8bf417…).' },
      { topic: 'p12-games', input: { game: 'coll', bits: '12', seed: 3 }, frame: 4, caption: '70 tries against about 80 expected. A collision costs about 2⁶ here, the square root of 2¹².' },
      { table: [['Game', 'Generic cost for an n-bit digest', 'For SHA-256'], ['Preimage', '2ⁿ', '2²⁵⁶'], ['Second preimage', '2ⁿ', '2²⁵⁶'], ['Collision', '2ⁿᐟ²', '2¹²⁸']], caption: 'What brute force costs against an ideal hash. A hash is broken when someone does better than this table.' },
      { tip: 'Collision resistance implies second-preimage resistance: a second preimage is a collision with one message fixed in advance. So a hash with no known collisions is the strongest promise, and the first one to fall.' },
      { h: 'Recap' },
      { list: ['Preimage: hit a given digest. Second preimage: match a given message. Collision: any pair at all.', 'Generic costs are 2ⁿ, 2ⁿ and 2ⁿᐟ²: the collision game is the cheapest.', 'A 256-bit digest is chosen so that even the cheapest game costs 2¹²⁸.'] },
      X('hs-x-props'), X('hs-x-props-use'), X('hs-x-pre-work'), X('hs-x-work-table'),
    ],
  });

  C.lesson({
    id: 'hs-birthday', chapter: 'hs-req', title: 'The birthday paradox', minutes: 7,
    summary: 'Among q random values from N, the chance that two coincide passes one half at about 1.18·√N. With 365 days that is 23 people; with n-bit digests it is about 2ⁿᐟ² messages, which is why digests are twice as long as keys.',
    blocks: [
      'A class of 30 students: would you bet that two share a birthday? Most people say no, since 30 is far below 365. They lose the bet about seven times in ten.',
      { topic: 'p12-birthday', frame: 1, caption: 'People walk into a room one at a time. Person 1 has Jul 3; nobody can share yet.' },
      { topic: 'p12-birthday', frame: 14, caption: 'After 20 people the chance of a shared day is already 0.406.' },
      { predict: { q: 'The question is not whether someone shares *your* birthday, but whether *any two* people share one. With 29 people in the room, how many pairs are there to compare?', options: ['29', '58', '406', '841'], answer: 2, explain: '29·28/2 = 406 pairs, and each pair shares a day with chance 1/365. Many pairs, each a small chance, add up quickly.' } },
      { topic: 'p12-birthday', frame: 16, caption: 'Person 29 lands on Oct 19, which is already taken: the first shared slot.' },
      { math: 'P(no match among q) = (1 − 1/N)(1 − 2/N) ⋯ (1 − (q−1)/N) ≈ exp(−q(q−1)/2N)\nP(match) ≈ 1/2  when  q ≈ √(2 ln 2 · N) ≈ 1.18 √N\nexpected draws to the first match ≈ √(πN/2) ≈ 1.25 √N' },
      { topic: 'p12-birthday', input: { space: '4096', q: 150, seed: 7 }, frame: 0, caption: 'The same game on 12-bit digests: 4,096 slots instead of 365 days. A match is expected after about √(π·4096/2) ≈ 80 messages.' },
      { tip: 'This is why output sizes come in pairs with security levels: a 128-bit security level needs a 256-bit digest, because collisions come at 2¹²⁸. An AES-128 key, which is attacked by search, not by birthdays, needs only 128 bits.' },
      { h: 'Recap' },
      { list: ['q draws make q(q−1)/2 pairs; that is why matches come early.', 'P(match) ≈ 1 − exp(−q²/2N); it passes one half near 1.18·√N.', 'For an n-bit hash, collisions cost about 2ⁿᐟ² evaluations.'] },
      X('hs-x-pairs'), X('hs-x-bday-23'), X('hs-x-bday-prob'), X('hs-x-bday-bound'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: Merkle–Damgård and SHA-256
  // =========================================================================================================
  C.lesson({
    id: 'hs-md', chapter: 'hs-md', title: 'Merkle–Damgård: padding and the chain', minutes: 8,
    summary: 'A hash of any length is built from a compression function of fixed size: pad the message with a 1 bit, zeros and its length, cut it into blocks, and chain the compressions from a fixed IV. The digest is the last chaining value.',
    blocks: [
      'A compression function takes a fixed amount in, say 32 bytes of state and 64 bytes of message, and gives 32 bytes out. A message can be any length, even zero. How do you build a hash of any message out of a function that only takes fixed blocks?',
      { topic: 'p12-md', frame: 0, caption: 'The message is 44 bytes. SHA-256 eats it in 64-byte blocks, so it must first be padded.' },
      { topic: 'p12-md', frame: 1, caption: 'First a single 1 bit, written as the byte 80, at position 44. It marks where the message ends.' },
      { topic: 'p12-md', frame: 3, caption: 'Then 11 zero bytes and the length in bits, 352, as 8 big-endian bytes: 0000000000000160. The padded message is exactly one block.' },
      { predict: { q: 'A message of 56 bytes is padded for SHA-256. How many 64-byte blocks does the padded message fill?', options: ['1', '2', '3', 'It depends on the bytes'], answer: 1, explain: 'The 80 byte and the 8-byte length need 9 bytes; 56 + 9 = 65 is more than 64, so the padding spills into a second block, made almost entirely of zeros and the length. 55 bytes is the most that fits in one block.' } },
      { topic: 'p12-md', input: { msg: 'Fifty-six bytes leave no room for the length: two blocks', hash: 'sha256' }, frame: 3, caption: 'The 56-byte preset: the length no longer fits, so a second block is added.' },
      { h: 'The chain' },
      { topic: 'p12-md', frame: 5, caption: 'Compression 1: f takes the chaining value 6a09e667… and block M₁, and gives ae224580…. f never sees the whole message, only the state so far and one block.' },
      { topic: 'p12-md', frame: 6, caption: 'The digest is the last chaining value. Because it is the whole final state, anyone who knows it can carry on hashing from it: remember this for length extension.' },
      { tip: 'The Merkle–Damgård theorem: if the compression function is collision resistant, so is the hash, provided the padding ends in the length (“length strengthening”). Two messages of different lengths always differ in their last block.' },
      { topic: 'p12-md', input: { msg: 'Sifer hashes this line, one round at a time.', hash: 'md5' }, frame: 3, caption: 'MD5 pads in the same way, but writes the length little-endian. The rule is the same; only the byte order of the length differs.' },
      { h: 'Recap' },
      { list: ['Pad with 80, then zeros, then the length in bits (8 bytes for SHA-256), to a whole number of blocks.', 'At most 55 bytes fit with their padding in one 64-byte block.', 'Chain the compression function from a fixed IV; the digest is the last chaining value.'] },
      X('hs-x-pad-len'), X('hs-x-pad-table'), X('hs-x-pad-hex'), X('hs-x-code-pad'),
    ],
  });

  C.lesson({
    id: 'hs-schedule', chapter: 'hs-md', title: 'The SHA-256 message schedule', minutes: 7,
    summary: 'The 64-byte block gives sixteen 32-bit words; the schedule stretches them to 64, one per round, each new word mixing four earlier ones through the functions σ0 and σ1 and additions mod 2³².',
    blocks: [
      'SHA-256 has 64 rounds but a block is only sixteen words. Feeding each word in four times would let an attacker cancel a change in one word with a change in another. Instead the words are stretched by a recurrence that mixes them. How?',
      { topic: 'p12-schedule', frame: 0, caption: 'The block read as sixteen big-endian words, W₀ = 53696665 (“Sife”) to W₁₅ = 00000160 (the length).' },
      { math: 'σ0(x) = (x ⋙ 7) ⊕ (x ⋙ 18) ⊕ (x ≫ 3)\nσ1(x) = (x ⋙ 17) ⊕ (x ⋙ 19) ⊕ (x ≫ 10)\nWₜ = σ1(Wₜ₋₂) + Wₜ₋₇ + σ0(Wₜ₋₁₅) + Wₜ₋₁₆   (mod 2³², t = 16 … 63)' },
      { topic: 'p12-schedule', frame: 2, caption: 'σ0 rotates W₁ = 72206861 right by 7 and by 18, shifts it right by 3, and XORs the three: σ0 = d6b81154.' },
      { predict: { q: 'σ0 contains a shift (≫ 3) as well as two rotations (⋙). What does the shift change?', options: ['Nothing: a shift is a rotation', 'Bits are lost, so σ0 is not just a rotation and cannot be undone bit for bit as one', 'It makes σ0 non-linear', 'It makes σ0 faster'], answer: 1, explain: 'A rotation keeps every bit; a shift drops three and brings in zeros. σ0 stays linear over GF(2) (XORs only), but it is no longer a mere rotation of the word, which stops patterns from lining up across words.' } },
      { topic: 'p12-schedule', frame: 4, caption: 'W₁₆ = σ1 + W₉ + σ0 + W₀ = 00000000 + 20612074 + d6b81154 + 53696665 = 4a82982d, mod 2³².' },
      { topic: 'p12-schedule', frame: 5, caption: 'The same rule fills all 64 words: W₆₃ = 7cc92ed9. A change of one message bit spreads into most of the later words.' },
      { h: 'Recap' },
      { list: ['W₀ … W₁₅ are the block as big-endian words; W₁₆ … W₆₃ come from the recurrence.', 'σ0 and σ1: two rotations and a shift, XORed; additions are mod 2³².', 'Each word taps t−2, t−7, t−15 and t−16.'] },
      X('hs-x-sigma1'), X('hs-x-sched-w16'),
    ],
  });

  C.lesson({
    id: 'hs-compress', chapter: 'hs-md', title: 'One round of SHA-256', minutes: 9,
    summary: 'Eight registers a…h start as the chaining value. Each round computes T1 from e, f, g, h, a constant and a schedule word, and T2 from a, b, c; the new a is T1 + T2, the new e is d + T1, and the rest shift down. After 64 rounds the input is added back.',
    blocks: [
      'The compression function has to be very hard to invert and to collide, yet it is built from nothing but 32-bit additions, rotations and bitwise logic. What does one round do with those?',
      { topic: 'p12-compress', frame: 0, caption: 'The registers a…h start as the IV: a = 6a09e667, …, h = 5be0cd19.' },
      { math: 'Ch(e, f, g)  = (e ∧ f) ⊕ (¬e ∧ g)              e chooses f or g, bit by bit\nMaj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)    the majority of three bits\nΣ0(a) = (a ⋙ 2) ⊕ (a ⋙ 13) ⊕ (a ⋙ 22)\nΣ1(e) = (e ⋙ 6) ⊕ (e ⋙ 11) ⊕ (e ⋙ 25)\nT1 = h + Σ1(e) + Ch(e, f, g) + Kₜ + Wₜ\nT2 = Σ0(a) + Maj(a, b, c)' },
      { topic: 'p12-compress', frame: 1, caption: 'Ch(e, f, g) = 1f85c98c: where e has a 1, the bit comes from f; where it has a 0, from g. Maj(a, b, c) = 3a6fe667.' },
      { topic: 'p12-compress', frame: 2, caption: 'Round 0: T1 = 5be0cd19 + 3587272b + 1f85c98c + 428a2f98 + 53696665 = 46e153cd, mod 2³².' },
      { predict: { q: 'After round 0, which registers hold newly computed values?', options: ['All eight', 'Only a and e', 'Only a', 'a, b, c and d'], answer: 1, explain: 'New a = T1 + T2 and new e = d + T1. The other six just move down one place: b takes the old a, c the old b, and so on, and the old h is dropped.' } },
      { topic: 'p12-compress', frame: 4, caption: 'New a = T1 + T2 = 4f71eeb2; new e = d + T1 = a54ff53a + 46e153cd = ec314907.' },
      { topic: 'p12-compress', frame: 5, caption: 'Every other register moves one place down. Only a and e are computed fresh.' },
      { topic: 'p12-compress', frame: 15, caption: 'The feed-forward: after 64 rounds, add the incoming chaining value word by word: 6a09e667 + 44185f19 = ae224580. Without it, the rounds could be run backwards from the output.' },
      { warn: 'Every addition is mod 2³². In code, keep words unsigned: in JavaScript write (x + y) >>> 0, or a sum of five words can exceed 2³² and a bitwise operator turns it negative.' },
      { h: 'Recap' },
      { list: ['T1 = h + Σ1(e) + Ch(e, f, g) + Kₜ + Wₜ;  T2 = Σ0(a) + Maj(a, b, c).', 'New a = T1 + T2, new e = d + T1; b, c, d, f, g, h shift down.', 'After 64 rounds, add the chaining value back in (the feed-forward).'] },
      X('hs-x-ch-maj'), X('hs-x-round-table'), X('hs-x-code-round'), X('hs-x-feedforward'),
    ],
  });

  C.lesson({
    id: 'hs-older', chapter: 'hs-md', title: 'SHA-1, MD5 and how hashes fall', minutes: 6,
    summary: 'MD5 and SHA-1 are Merkle–Damgård hashes of the same family as SHA-256, with fewer registers and simpler schedules. Both were broken in the same pattern: a theoretical attack, a practical collision years later, then a chosen-prefix collision that forged real certificates.',
    blocks: [
      'In 2008 a browser would accept a certificate authority that no real authority had ever signed, because of an MD5 collision. How does a hash go from trusted to dangerous, and how much warning is there?',
      { topic: 'p12-older', frame: 0, caption: 'SHA-1 keeps five registers and runs 80 steps; its schedule only XORs and rotates.' },
      { topic: 'p12-older', frame: 1, caption: 'MD5 keeps four registers, reads the block as little-endian words, and runs 64 steps.' },
      { topic: 'p12-older', frame: 7, caption: '2004: the first full MD5 collision, two different 128-byte messages with the same digest, found in hours.' },
      { topic: 'p12-older', frame: 9, caption: '2008: a chosen-prefix MD5 collision makes a rogue certificate authority certificate that browsers would trust.' },
      { predict: { q: 'A collision attack produces two messages with the same digest. Why is a chosen-prefix collision so much more dangerous than an ordinary one?', options: ['It is faster', 'The attacker picks two different meaningful beginnings, such as an honest certificate request and a CA certificate, and only appends gibberish', 'It gives preimages too', 'It works on SHA-3'], answer: 1, explain: 'An ordinary collision gives two random-looking blocks. A chosen-prefix collision lets each message start with whatever the attacker wants, so one can be signed innocently and the signature moved to the other.' } },
      { topic: 'p12-older', frame: 12, caption: '2017: the first public SHA-1 collision, two different PDF files, after about 2^63 computations, far below the 2^80 a birthday search would need.' },
      { topic: 'p12-older', frame: 15, caption: 'The pattern: a crack, a practical collision about ten years later, then a chosen-prefix collision. SHA-256 still has no known collision.' },
      { h: 'Recap' },
      { list: ['MD5: 128-bit digest, four registers, little-endian. SHA-1: 160 bits, five registers, 80 steps.', 'Both fell to differential attacks well below the birthday bound.', 'Chosen-prefix collisions turned the breaks into forged certificates; use SHA-256 or SHA-3.'] },
      X('hs-x-md5-endian'), X('hs-x-history'),
    ],
  });

  // =========================================================================================================
  // Chapter 3: SHA-3 and the sponge
  // =========================================================================================================
  C.lesson({
    id: 'hs-sponge', chapter: 'hs-sha3', title: 'The sponge: absorb, then squeeze', minutes: 7,
    summary: 'SHA-3 keeps a 1600-bit state split into a rate, where input is XORed in and output is read, and a capacity that is never touched from outside. A permutation scrambles the whole state between blocks. The capacity sets the security; SHAKE squeezes as much output as asked.',
    blocks: [
      'After MD5 and SHA-1 fell, the world wanted a second standard built in a completely different way, so that one breakthrough could not take down both. SHA-3 has no compression function and no feed-forward. What does it have instead?',
      { topic: 'p12-sponge', frame: 0, caption: 'The state is 200 bytes, all zero. SHA3-256 uses a rate of 136 bytes, the only part input ever touches, and a capacity of 64 bytes.' },
      { topic: 'p12-sponge', frame: 1, caption: 'Padding: after the 15 bytes of the message comes 06 (two domain bits and the first 1), zeros, and 80 at the end of the block.' },
      { predict: { q: 'A message is exactly 135 bytes, one less than the rate of SHA3-256. The padding must add both the 06 and the final 80, but there is room for one byte only. What happens?', options: ['A second block is added', 'The two are combined into one byte, 86', 'The 80 is dropped', 'The message is cut'], answer: 1, explain: 'The 06 and the 80 overlap in the same byte and are ORed: 06 | 80 = 86. The padding is never empty, and here it is exactly one byte.' } },
      { topic: 'p12-sponge', frame: 2, caption: 'Absorb: the 136 bytes are XORed into the rate; the 64 capacity bytes are left alone.' },
      { topic: 'p12-sponge', frame: 3, caption: 'Keccak-f, 24 rounds, scrambles the whole state, capacity included: 199 of the 200 bytes changed.' },
      { topic: 'p12-sponge', frame: 4, caption: 'Squeeze: the digest is the first 32 bytes of the rate. The capacity is never output, so whoever sees the digest still lacks 512 bits of the state: no length extension.' },
      { h: 'SHAKE' },
      { topic: 'p12-shake', frame: 2, caption: 'SHAKE128 squeezes 168 bytes at a time; when the rate is used up, Keccak-f runs again and the next bytes are read.' },
      { topic: 'p12-shake', frame: 3, caption: 'A shorter output is always a prefix of a longer one: 16 bytes are the first 16 of 200.' },
      { tip: 'Generic attacks on a sponge cost about 2^(c/2), where c is the capacity in bits. SHA3-256 has c = 512, so collisions cost 2¹²⁸, as the birthday bound for a 256-bit digest asks, and the capacity also blocks attacks on the inner state.' },
      { h: 'Recap' },
      { list: ['State 1600 bits = rate r + capacity c; SHA3-n uses c = 2n.', 'Absorb: XOR each r-bit block into the rate, then Keccak-f. Squeeze: read the rate, Keccak-f, read again.', 'Padding: 06 … 80 for SHA-3, 1F … 80 for SHAKE; they combine into one byte when there is room for one only.'] },
      X('hs-x-rate'), X('hs-x-capacity'), X('hs-x-sha3-pad'), X('hs-x-shake-prefix'),
    ],
  });

  C.lesson({
    id: 'hs-keccak', chapter: 'hs-sha3', title: 'Inside Keccak-f: θ, ρ, π, χ and ι', minutes: 9,
    summary: 'Keccak-f works on a 5×5 grid of 64-bit lanes. θ XORs each bit with the parities of two neighbouring columns; ρ rotates lanes; π moves them; χ, the only non-linear step, mixes each row of five bits; ι adds a round constant.',
    blocks: [
      'The state is 1600 bits and Keccak-f must scramble all of it, 24 times, with steps cheap enough for small chips. Each of its five steps has one job. Which step does what?',
      { topic: 'p12-theta', frame: 1, caption: 'A column is the five bits of lanes (x, 0) … (x, 4) at one position z. Its XOR is the parity C[x][z]; here C[1][29] = 1.' },
      { math: 'C[x][z] = A[x,0][z] ⊕ A[x,1][z] ⊕ A[x,2][z] ⊕ A[x,3][z] ⊕ A[x,4][z]\nD[x][z] = C[x−1][z] ⊕ C[x+1][z−1]          (x mod 5, z mod 64)\nθ:  A[x,y][z] ← A[x,y][z] ⊕ D[x][z]' },
      { topic: 'p12-theta', frame: 2, caption: 'D[1][29] mixes the column to the left at the same z, C[0][29] = 1, and the column to the right one slice back, C[2][28] = 0. Their XOR, 1, flips all five bits of column (1, 29).' },
      { predict: { q: 'Start θ from a state with a single 1 bit. How many bits are set afterwards?', options: ['1', '5', '11', '25'], answer: 2, explain: 'The bit changes the parity of its own column, and two columns read that parity, so θ flips 5 + 5 bits, plus the original: 11. That is θ’s job: spreading each bit across columns.' } },
      { topic: 'p12-theta', frame: 4, caption: 'One bit at x = 2, y = 1, z = 30 becomes 11: the columns x = 1 at z = 30 and x = 3 at z = 31 flip.' },
      { h: 'ρ, π, χ, ι' },
      { topic: 'p12-keccak', frame: 1, caption: 'ρ rotates every lane by its own fixed offset; nothing moves between lanes.' },
      { topic: 'p12-keccak', frame: 2, caption: 'π moves whole lanes: (x, y) goes to (y, 2x + 3y mod 5). Lane (1, 0) will move to (0, 2).' },
      { math: 'χ:  a[x] ← a[x] ⊕ (¬a[x+1] ∧ a[x+2])     along each row of five bits (x mod 5)' },
      { topic: 'p12-keccak', frame: 4, caption: 'χ on row y = 0 at z = 0: the bits 0 0 1 0 0 become 1 0 1 0 0. The AND makes χ the only non-linear step.' },
      { topic: 'p12-keccak', frame: 5, caption: 'ι XORs the round constant RC[0] = 0000000000000001 into lane (0, 0) alone. Without it every round would be the same.' },
      { h: 'Recap' },
      { list: ['θ: XOR each bit with the parities of two neighbouring columns (diffusion across columns).', 'ρ and π: rotate the lanes and move them (diffusion within and between lanes).', 'χ: a ⊕ (¬b ∧ c) along rows, the only non-linear step. ι: a round constant into lane (0, 0).'] },
      X('hs-x-theta-parity'), X('hs-x-theta-d'), X('hs-x-chi'),
    ],
  });

  // =========================================================================================================
  // Chapter 4: attacks on hashes
  // =========================================================================================================
  C.lesson({
    id: 'hs-bday-attack', chapter: 'hs-attacks', title: 'Collisions by table and by walk', minutes: 8,
    summary: 'A birthday attack hashes many messages and stores the digests until two match: about 2ⁿᐟ² work and as much memory. Pollard’s rho walks from value to value with no table at all. Joux showed that once collisions are cheap, many-way collisions are almost free in an iterated hash.',
    blocks: [
      'The birthday bound says 2ⁿᐟ² hashes find a collision. But to notice the match, you must remember every digest so far. For a 64-bit digest that is four billion entries. Is the memory a real price, or can it be avoided?',
      { topic: 'p12-bday-attack', frame: 0, caption: 'The attacker wants two messages whose SHA-256 digests agree in the first 24 bits: 16,777,216 digests, but a collision is expected after about 5,134 messages.' },
      { topic: 'p12-bday-attack', frame: 5, caption: 'Message 3,128 has the 24-bit digest 32ee9e, already in the table from message 2,022: a collision.' },
      { topic: 'p12-bday-attack', frame: 6, caption: 'The price was memory: 3,127 digests stored. Each 2 more bits of digest double the work.' },
      { predict: { q: 'Instead of storing digests, step x → H(x) over and over from one start. The values are 12 bits, so 4,096 possible. What must happen eventually?', options: ['The walk runs forever without repeating', 'The walk reaches a value it has seen and loops; the two arrows into the join are a collision', 'The walk returns to its start', 'The walk stops at 000'], answer: 1, explain: 'A walk on a finite set must repeat. Where the tail meets the loop, two different values hash to the same next value: a collision, found in about √N steps.' } },
      { topic: 'p12-rho', frame: 3, caption: 'Floyd’s trick: a tortoise steps once, a hare twice; after 32 steps they meet at fe5 on the loop. Only two values are kept.' },
      { topic: 'p12-rho', frame: 4, caption: 'Restart the tortoise and step both together: they reach the join, 12f, after 12 steps. Its predecessors d3c and 2a4 collide.' },
      { h: 'Multicollisions' },
      { topic: 'p12-joux', frame: 3, caption: 'Three collisions in a row on a toy hash with a 16-bit chaining value: from f491 to 331b, to e485, to beca.' },
      { topic: 'p12-joux', frame: 4, caption: 'Choosing either block at each stage gives 8 different messages, all with one digest.' },
      { tip: 'Joux’s lesson: 2ᵗ messages with one digest cost only t collisions. So concatenating two iterated hashes, H₁(m) ‖ H₂(m), is barely stronger than the better of the two: build 2ⁿᐟ² colliding messages for H₁, and among them a birthday collision for H₂ is expected.' },
      { h: 'Recap' },
      { list: ['Birthday table: about 1.25·2ⁿᐟ² hashes and as many stored digests.', 'Rho: the same order of work with constant memory (Floyd’s cycle finding).', 'Joux: t collisions in a row give 2ᵗ messages with one digest.'] },
      X('hs-x-collide'), X('hs-x-rho'), X('hs-x-joux'),
    ],
  });

  C.lesson({
    id: 'hs-lenext', chapter: 'hs-attacks', title: 'Length extension', minutes: 7,
    summary: 'A Merkle–Damgård digest is the hash’s whole final state. So a tag made as SHA-256(secret ‖ m) lets anyone holding it carry on hashing, and a longer message gets a valid tag without the secret. Secret-prefix MACs fall; HMAC and SHA-3 do not.',
    blocks: [
      'An API signs each request as SHA-256(secret ‖ request), and refuses requests whose signature does not match. The secret never leaves the server. Is that a sound MAC?',
      { topic: 'p12-lenext', frame: 0, caption: 'The server’s tag for “user=wren&role=reader” is SHA-256(secret ‖ message) = 1d8a3be63e0dbb41….' },
      { topic: 'p12-lenext', frame: 1, caption: 'Before hashing, SHA-256 padded the 32 bytes of secret ‖ message with 32 bytes of glue: 80, zeros and the length, 256 bits. The tag is the chaining value after that block: the hash’s whole state.' },
      { predict: { q: 'The tag is exactly the state the server reached. Can someone without the secret make a valid tag for a longer message that starts with this one?', options: ['No: every tag needs the secret', 'Yes: they can carry on hashing from the tag', 'Only with a collision', 'Only for SHA-1'], answer: 1, explain: 'Nothing is hidden after the last compression, so the tag is all that is needed to keep hashing. The server, hashing the longer input from the start, passes through the same state.' } },
      { topic: 'p12-lenext', frame: 2, caption: 'The outcome: a valid tag for a longer message ending in “&role=admin”, which the server never tagged, made without the secret.' },
      { topic: 'p12-lenext', frame: 3, caption: 'Against HMAC the same trick gives 3ce4a1a4…, but the true HMAC is 27ea8916…: rejected. SHA3-256(secret ‖ message) shows only 32 of 200 state bytes and cannot be resumed.' },
      { bench: 'hash', state: { panel: 'lenext' }, text: 'The hash bench’s length-extension card lists, for each hash, how much of its state the digest shows, and the rules for building a keyed tag.' },
      { warn: 'Truncated SHA-2 variants (SHA-512/256, SHA-384) hide part of the state and so resist this too, but the right fix for a MAC is HMAC (or KMAC with SHA-3), not a cleverer secret-prefix construction.' },
      { h: 'Recap' },
      { list: ['A Merkle–Damgård digest is the full internal state: anyone can keep hashing from it.', 'So H(secret ‖ m) is no MAC: a longer message gets a valid tag without the secret.', 'HMAC hashes the inner digest again under a second key; SHA-3 never outputs the capacity. Both resist.'] },
      X('hs-x-exposed'), X('hs-x-resist'), X('hs-x-hmac-why'),
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
