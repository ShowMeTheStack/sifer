// Part 4, DES and the Feistel network: the chapters and the lessons. The exercises are in 041-des-ex.js and the CTF
// challenges, the tour and the course in 042-des-ctf.js. Each lesson opens with a question, runs the topic that
// animates the idea at a frame chosen for the point being made, asks for a prediction, sums up, and leads to its
// exercises. Every value here is our own (or a published test vector, named as such) and was worked out by the engines
// (S.Feistel, S.DES, S.MITM, S.TDES, S.DESX, S.SPN, S.PRESENT).
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('des-feistel')) return;
  const X = (id) => ({ exercise: id });


  C.chapter({ id: 'des-ladder', part: 'des', n: 1, title: 'The Feistel network and DES', blurb: 'A ladder that makes any round function invertible, and DES end to end: IP, sixteen rounds, the f-function with its eight S-boxes, the key schedule, and decryption.' });
  C.chapter({ id: 'des-weak', part: 'des', n: 2, title: 'Weaknesses and fixes', blurb: 'Weak keys and the complement, what a 56-bit key costs to search, double DES met in the middle, and 3DES and DESX.' });
  C.chapter({ id: 'des-spn', part: 'des', n: 3, title: 'Breaking a toy SPN, and PRESENT', blurb: 'Differences and linear approximations through an S-box, the last round key of a toy cipher recovered by counting, and a real lightweight SPN.' });

  // =========================================================================================================
  // Chapter 1: the Feistel network and DES
  // =========================================================================================================
  C.lesson({
    id: 'des-feistel', chapter: 'des-ladder', title: 'The Feistel principle: any function, invertible', minutes: 8,
    summary: 'Split the block into halves L and R; each round XORs F(R, k) into L and swaps. Whatever F is, even a function that loses information, the ladder is undone by running it again with the round keys in reverse order.',
    blocks: [
      'A block cipher must be invertible: every ciphertext has to decrypt to exactly one plaintext. The obvious way to get that is to build it from invertible pieces, and then write the inverse of every piece for decryption. In the 1970s there was a cleverer way, which lets the designer use a round function that cannot be inverted at all.',
      { math: 'round i:  Lᵢ = Rᵢ₋₁\n          Rᵢ = Lᵢ₋₁ ⊕ F(Rᵢ₋₁, kᵢ)\noutput:   (Rₙ, Lₙ)   the halves swapped once more' },
      { topic: 'des-feistel', frame: 1, caption: 'Round 1: F(656e, k₁) = 4ac0 is XORed into the left half, 7772 ⊕ 4ac0 = 3db2, and 656e passes on untouched. The untouched half is what makes the round reversible.' },
      { topic: 'des-feistel', frame: 5, caption: 'After four rounds the ciphertext is 61217622. The half changed last goes on the left: that final swap is what lets decryption reuse the same ladder.' },
      { predict: { q: 'To decrypt, the ciphertext goes into the same ladder. In decryption round 1, which round key is used?', options: ['k₁', 'k₄', 'Any of them: the order does not matter', 'The inverse of F is needed instead of a key'], answer: 1, explain: 'Decryption round 1 must remove the last thing encryption did, which was XORing F(R₃, k₄). It recomputes exactly that F, with k₄, and XORs it out.' } },
      { topic: 'des-feistel', frame: 7, caption: 'Decryption round 1 with k₄: F(7622) = 8511 is the very value encryption XORed in, so 6121 ⊕ 8511 = e430 undoes it.' },
      { topic: 'des-feistel', frame: 11, caption: 'Four decryption rounds later, out comes 7772656e. The ladder only ever ran F forwards.' },
      { h: 'F need not be invertible' },
      { topic: 'des-feistel', input: { F: 'square', pt: '6d6f7468', keys: ['0f1e', 'a5c3', '7d42'] }, frame: 9, caption: 'Here F takes the middle bits of a square, so two inputs can give the same output: F(0f00, k₁) = F(0f01, k₁). The ladder decrypts anyway, because it never needs F backwards.' },
      'This is the freedom DES uses: its f-function expands 32 bits to 48 and squeezes them back to 32 through S-boxes that are many-to-one, and nobody ever has to invert it. Security is a separate matter: with a linear F, such as R ⊕ k, every output bit is an XOR of plaintext and key bits, and a few known plaintexts solve for the keys.',
      { topic: 'des-feistel', input: { F: 'zero', pt: '7772656e', keys: ['3a7c', '91e4'] }, frame: 3, caption: 'F = 0: each round just swaps, and two rounds with the final swap give the halves swapped, 656e7772. Invertible, and no cipher at all.' },
      { h: 'Recap' },
      { list: ['A Feistel round: L ← R, R ← L ⊕ F(R, k).', 'After the last round the halves are swapped once more, so decryption is the same ladder with the keys reversed.', 'F can be any function, even one that loses information; its strength decides the cipher\'s security, not its invertibility.'] },
      X('des-x-feistel-table'), X('des-x-feistel-decrypt'), X('des-x-feistel-f'), X('des-x-feistel-zero'), X('des-x-code-feistel'), X('des-x-two-rounds'),
    ],
  });

  C.lesson({
    id: 'des-overview', chapter: 'des-ladder', title: 'DES end to end: IP and sixteen rounds', minutes: 8,
    summary: 'DES permutes the 64 plaintext bits (IP), runs sixteen Feistel rounds on 32-bit halves with 48-bit round keys, swaps the halves and applies the inverse permutation. The key has 64 bits, of which 56 count.',
    blocks: [
      'DES was the standard block cipher for a quarter of a century: banks, passwords and smart cards all used it. Its whole structure fits on one page. Here it encrypts the eight letters “nightjar” under the key “bramble7”, every value shown.',
      { topic: 'des-overview', frame: 0, caption: 'One 64-bit block under a 64-bit key; 8 of the key bits are parity bits, so 56 count.' },
      { h: 'The initial permutation' },
      { topic: 'des-ipfp', frame: 1, caption: 'IP reads the plaintext as an 8×8 grid of bits and takes its columns: the first output byte is column 2, read from byte 8 up to byte 1.' },
      { predict: { q: 'IP and the final permutation are fixed and public. How much do they add to the security of DES?', options: ['Nothing', 'About 6 bits', 'They double the work of a key search', 'They are what stops the complement property'], answer: 0, explain: 'Anyone can apply IP or undo it, so an attacker simply strips them off. They suited the 8-bit hardware of the 1970s, which loaded the block a byte at a time.' } },
      { topic: 'des-ipfp', frame: 9, caption: 'L₀ = ff901546 takes the even columns and R₀ = 00ff2ba5 the odd ones.' },
      { h: 'Sixteen rounds' },
      { topic: 'des-overview', frame: 2, caption: 'Round 1: f(R₀, K₁) = f27a6449 is XORed into L₀, giving R₁ = 0dea710f, while R₀ passes on as L₁. The lanes take turns.' },
      { topic: 'des-overview', frame: 17, caption: 'Round 16, with its own 48-bit round key: R₁₆ = 3a669372.' },
      { topic: 'des-overview', frame: 18, caption: 'The halves leave swapped, R₁₆L₁₆, and the final permutation, the inverse of IP, gives the ciphertext 0ed590e0cdf11306.' },
      { bench: 'cipher', state: { algo: 'des', mode: 'ecb', view: 'rounds' }, text: 'Run DES on your own block and key, every round shown.' },
      { h: 'Recap' },
      { list: ['64-bit block, 64-bit key with 8 parity bits: 56 effective key bits.', 'IP, then sixteen Feistel rounds on 32-bit halves, a final swap, and FP = IP⁻¹.', 'IP and FP are public wiring and add no security.'] },
      X('des-x-ip'), X('des-x-rounds'),
    ],
  });

  C.lesson({
    id: 'des-f', chapter: 'des-ladder', title: 'Inside f: expansion, the key, eight S-boxes, P', minutes: 10,
    summary: 'f expands R from 32 to 48 bits, XORs in the round key, feeds eight 6-bit groups to eight S-boxes that each give 4 bits, and permutes the 32 results with P. The S-boxes are the only nonlinear part of DES.',
    blocks: [
      'Everything in a Feistel cipher rests on F. In DES it takes the 32-bit right half and a 48-bit round key and returns 32 bits. Where does the key go in, and what makes the result hard to predict?',
      { topic: 'des-f', frame: 1, caption: 'E copies each 4-bit group together with the edge bits of its two neighbours: 32 bits become 48, with 16 of them appearing twice. E(R) = 8017fe957d0a.' },
      { topic: 'des-f', frame: 3, caption: 'The round key enters by XOR, and only here: E(R) ⊕ K₁ = 70a9d8a46cae, cut into eight groups of six bits.' },
      { def: 'S-box lookup', text: 'each S-box is a table of 4 rows and 16 columns of 4-bit numbers. Of its 6 input bits, the outer two (first and last) pick the row and the middle four pick the column.' },
      { topic: 'des-f', frame: 4, caption: 'S1 gets 011100: outer bits 00 pick row 0, middle bits 1110 pick column 14, and the entry there is 0 = 0000.' },
      { predict: { q: 'S2 gets 001010. Which row and column does it read?', options: ['row 0, column 5', 'row 2, column 5', 'row 0, column 10', 'row 1, column 2'], answer: 0, explain: 'The outer bits are the first and last, 0 and 0: row 0. The middle four, 0101, are column 5. S2 has 11 there.' } },
      { topic: 'des-f', frame: 5, caption: 'S2: row 0, column 5, entry 11 = 1011.' },
      { topic: 'des-f', frame: 12, caption: 'The eight outputs make 0b0b1ff2, and P scatters them so that each S-box\'s four bits reach four different S-boxes in the next round: f = f27a6449.' },
      'The S-boxes are what make DES nonlinear: change one input bit and the output can change in any of its four bits, with no XOR formula describing how. Every other step, E, the key XOR and P, is linear. Without the S-boxes DES would be a large system of linear equations, solved from a handful of known plaintexts.',
      { topic: 'des-f', input: { round: 9 }, frame: 12, caption: 'Round 9 of the same encryption, with its own key K₉: the same machinery on different values.', inputs: true },
      { h: 'Recap' },
      { list: ['E: 32 → 48 bits, each group taking its neighbours\' edge bits.', 'The round key is XORed in after E, and nowhere else.', 'Eight S-boxes, 6 bits in and 4 out: outer bits pick the row, middle bits the column.', 'P spreads each S-box\'s output over four S-boxes of the next round.'] },
      X('des-x-expand'), X('des-x-s1'), X('des-x-f-sboxes'), X('des-x-code-sbox'), X('des-x-p'),
    ],
  });

  C.lesson({
    id: 'des-keys', chapter: 'des-ladder', title: 'The key schedule: PC-1, rotations, PC-2', minutes: 7,
    summary: 'PC-1 drops the 8 parity bits and splits the other 56 into two 28-bit registers C and D. Before each round both rotate left by one or two places, and PC-2 picks 48 of their bits as the round key. The rotations add up to 28, a full turn.',
    blocks: [
      'DES needs sixteen 48-bit round keys and has one 56-bit key. Storing sixteen independent keys would cost 768 bits; DES instead derives each round key from the same 56 bits, picked in a different pattern every round.',
      'The key 6272616d626c6537 (“bramble7”) is eight bytes; the last bit of each byte is a parity bit and takes no part in encryption.',
      { topic: 'des-keys', frame: 1, caption: 'PC-1 drops the parity bits and sorts the other 56 into C₀ = 007fff8 and D₀ = 93e8282.' },
      { topic: 'des-keys', frame: 2, caption: 'Round 1: both halves rotate left by one, and PC-2 picks 48 of the 56 bits: K₁ = f0be263111a4.' },
      { predict: { q: 'Rounds 1, 2, 9 and 16 rotate by one place, the others by two. How many places in all after round 16?', options: ['16', '24', '28', '32'], answer: 2, explain: '4 × 1 + 12 × 2 = 28, a whole turn of a 28-bit register: C₁₆ = C₀ and D₁₆ = D₀.' } },
      { topic: 'des-keys', frame: 18, caption: 'C₁₆ and D₁₆ are C₀ and D₀ again. Decryption starts from them and rotates right, producing K₁₆, K₁₅, … in order.' },
      { tip: 'The parity bits really are ignored: flipping one changes no round key and no ciphertext bit. Run the avalanche topic with the preset “A parity bit of the key” to see a zero-bit avalanche.' },
      { h: 'Recap' },
      { list: ['PC-1: 64 → 56 bits, split into 28-bit halves C and D.', 'Each round: rotate C and D left by 1 or 2; PC-2 picks 48 bits as Kᵢ.', 'The rotations total 28, so the registers end where they began.'] },
      X('des-x-shifts'), X('des-x-keys'),
    ],
  });

  C.lesson({
    id: 'des-decrypt', chapter: 'des-ladder', title: 'Decryption, and the avalanche', minutes: 7,
    summary: 'DES decrypts by running the same sixteen rounds with the round keys in reverse order. And it diffuses: one flipped plaintext or key bit changes about half of the 64 state bits within a few rounds.',
    blocks: [
      'A hardware DES chip in the 1970s was expensive. Did a bank need a second chip to decrypt?',
      { topic: 'des-decrypt', frame: 2, caption: 'Decryption round 1 uses K₁₆: 3a669372 ⊕ f(3e2811c1, K₁₆) gives 310a2b04, which is R₁₄ of the encryption. Each step peels off one encryption round.' },
      { topic: 'des-decrypt', frame: 18, caption: 'After sixteen rounds the plaintext ‘nightjar’ comes back. Nothing ran backwards; only the order of the keys changed, so one chip does both.' },
      { h: 'The avalanche' },
      'A good cipher should hide every simple relation between input and output. A clear test is to flip one input bit: if only a few output bits changed, an attacker would learn which bits depend on which.',
      { predict: { q: 'Flip the first plaintext bit. After round 1 the two states differ in 6 bits. Roughly how many of the 64 bits differ after round 16?', options: ['About 6', 'About 32', 'All 64', 'It keeps growing, to about 48'], answer: 1, explain: 'Once the difference has spread, each output bit is like a coin toss for the two encryptions: they agree about half the time. The count settles around 32 and wanders up and down.' } },
      { topic: 'des-avalanche', frame: 3, caption: 'After round 3 the states differ in 29 of 64 bits: the one flipped bit has passed through the S-boxes twice and spread.' },
      { topic: 'des-avalanche', frame: 17, caption: 'The two ciphertexts differ in 29 bits. From round 3 on the count hovers around 32, half the block.' },
      { topic: 'des-avalanche', input: { pt: '636f707065723432', key: '7175696c6c26696e', what: 'key', bit: 8 }, frame: 17, caption: 'Flip bit 8 of the key, a parity bit, and nothing changes at all: 0 bits differ.' },
      { h: 'Recap' },
      { list: ['Decryption is encryption with K₁₆ … K₁.', 'One flipped input bit changes about half the state within three or four rounds.', 'Parity bits of the key change nothing.'] },
      X('des-x-decrypt-order'), X('des-x-avalanche'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: weaknesses and fixes
  // =========================================================================================================
  C.lesson({
    id: 'des-weak', chapter: 'des-weak', title: 'Weak keys, the complement, and the price of a key search', minutes: 9,
    summary: 'Four weak keys make every round key the same, so encrypting twice gives the plaintext back. The complement property DES(¬p, ¬k) = ¬DES(p, k) halves a key search. And 2⁵⁶ keys, once out of reach, fell within a day by 1999.',
    blocks: [
      'Is every one of the 2⁵⁶ DES keys as good as every other? And is 2⁵⁶ enough?',
      { topic: 'des-weak', frame: 0, caption: 'The key 0101010101010101 makes C₀ and D₀ all zeros. Rotating a register of zeros changes nothing, so every round key is the same.' },
      { topic: 'des-weak', frame: 3, caption: 'With all sixteen round keys equal, the reversed order is the same order: encryption is decryption, and encrypting twice gives the plaintext back.' },
      { topic: 'des-weak', input: { key: '01fe01fe01fe01fe' }, frame: 3, caption: 'A semi-weak key: its round keys alternate between two values, and its partner fe01fe01fe01fe01 produces them in reverse, so one decrypts what the other encrypts.' },
      { predict: { q: 'You know DES(p, k) = c. What is DES(¬p, ¬k), with every bit of the plaintext and the key flipped?', options: ['¬c', 'c', 'Unrelated to c', 'p'], answer: 0, explain: 'E(¬R) = ¬E(R), and the round key is complemented too, so the S-box input E(R) ⊕ K is unchanged. Following the ladder through, every half comes out complemented.' } },
      { topic: 'des-weak', frame: 4, caption: 'DES(¬p, ¬k) = 2f1dbeb0eda80b33, the complement of d0e2414f1257f4cc. It holds for every key.' },
      { topic: 'des-weak', frame: 5, caption: 'Weak and semi-weak keys are easy to avoid. The complement matters more: one encryption tests a key and its complement, so a search needs 2⁵⁵ trials, not 2⁵⁶.' },
      { h: 'The price of trying every key' },
      { topic: 'des-search', frame: 1, caption: 'A special-purpose machine proposed in 1977 would have swept all 2⁵⁶ keys in 20 hours, for a price estimated at $20 million.' },
      { topic: 'des-search', frame: 4, caption: 'In 1999 a purpose-built machine with 100 000 volunteers\' PCs tried 2.45 × 10¹¹ keys a second: every key in 3.4 days, and a given key in 40.8 hours on average.' },
      { topic: 'des-search', frame: 7, caption: 'The rate grew about a hundredfold in fifteen years. Two-key 3DES, with 112 bits, would still take 2.1 × 10¹⁴ years at the fastest rate here.' },
      { h: 'Recap' },
      { list: ['4 weak keys (all round keys equal) and 6 pairs of semi-weak keys; easy to avoid.', 'Complement property: DES(¬p, ¬k) = ¬DES(p, k), so a key search costs 2⁵⁵.', '56 bits fell to special hardware in 1998–99; key length, not machine speed, decides.'] },
      X('des-x-weak'), X('des-x-complement'), X('des-x-search'),
    ],
  });

  C.lesson({
    id: 'des-mitm', chapter: 'des-weak', title: 'Double DES met in the middle; 3DES and DESX', minutes: 10,
    summary: 'Encrypting twice under two keys does not square the work: a table of every middle value from one side, met by decryptions from the other, finds both keys in about 2·2⁵⁶ operations. 3DES (encrypt, decrypt, encrypt) and DESX (whitening) are the fixes that stuck.',
    blocks: [
      'DES\'s key is too short, so use two of them: C = E_K₂(E_K₁(P)), with 112 key bits. Does that make a search 2⁵⁶ times harder?',
      { topic: 'des-mitm', frame: 1, caption: 'P₁ goes forward under every value of K₁ (8 unknown bits here, so 256 of them), and C₁ will come back under every value of K₂. If the keys are right, the two meet at the same middle value.' },
      'Forward: encrypt P₁ under every K₁ and keep each middle value with its key, in a table that can be searched at once (sorted, or a hash table). That is 2ⁿ encryptions for n-bit keys, and 2ⁿ entries of memory.',
      { predict: { q: 'The table holds E_K₁(P₁) for every K₁. What do you compute from the other side?', options: ['E_K₂(C₁) for every K₂', 'D_K₂(C₁) for every K₂', 'D_K₁(C₁) for every K₁', 'Every pair (K₁, K₂) again'], answer: 1, explain: 'If C₁ = E_K₂(E_K₁(P₁)) then D_K₂(C₁) = E_K₁(P₁): decrypting one layer from the ciphertext lands on the same middle value. Look each one up in the table.' } },
      { topic: 'des-mitm', frame: 4, caption: 'Backward: C₁ decrypted under K₂ = 141 gives da418dda5ae74cca, and the sorted table holds it at K₁ = 67. At most 256 decryptions find the meeting point.' },
      { topic: 'des-mitm', frame: 5, caption: 'A 64-bit middle value can match by chance, so the second pair decides: (67, 141) takes P₂ to C₂. In all 512 DES operations and 256 entries of memory, against 65 536 double encryptions for every pair.' },
      'For real double DES that is about 2⁵⁷ operations and 2⁵⁶ table entries instead of 2¹¹²: the second key bought one bit of strength, at the price of a lot of memory.',
      { bench: 'cipher', state: { area: 'labs', lab: 'mitm' }, text: 'Run the attack with up to 18 unknown bits per key.' },
      { h: 'Three times: 3DES' },
      { topic: 'des-3des', frame: 0, caption: 'Two-key 3DES: encrypt under K₁, decrypt under K₂, encrypt under K₁ again. A meet-in-the-middle attack must still guess two keys on one side.' },
      { topic: 'des-3des', input: { variant: 'compat' }, frame: 4, caption: 'Why decrypt in the middle: with all keys equal, the first two steps cancel and EDE is single DES, so a 3DES box can talk to an old DES box.' },
      { topic: 'des-3des', input: { variant: 'desx' }, frame: 0, caption: 'DESX instead wraps one DES call in two XORs with extra 64-bit keys: C = K₂ ⊕ DES_K(P ⊕ K₁). Almost free, and it stops a plain key search.' },
      { warn: '3DES is retired now, and not only for speed: its 64-bit block is too small. After about 2³² blocks under one key, two ciphertext blocks collide by the birthday bound and leak the XOR of their plaintexts. Part 6 comes back to block size.' },
      { h: 'Recap' },
      { list: ['Double encryption falls to meet-in-the-middle: about 2·2ⁿ work and 2ⁿ memory for two n-bit keys.', '3DES = E_K₃(D_K₂(E_K₁(P))); with equal keys it is single DES. Three keys give about 112 bits of strength.', 'DESX: K₂ ⊕ DES_K(P ⊕ K₁), whitening that costs two XORs.'] },
      X('des-x-mitm-cost'), X('des-x-mitm-break'), X('des-x-3des'), X('des-x-3des-bits'), X('des-x-desx'),
      { challenge: 'des-ctf-relay' },
    ],
  });

  // =========================================================================================================
  // Chapter 3: breaking a toy SPN, and PRESENT
  // =========================================================================================================
  C.lesson({
    id: 'des-ddt', chapter: 'des-spn', title: 'Differences through an S-box', minutes: 8,
    summary: 'Differential cryptanalysis follows XOR differences. The key cancels from a difference, so only the S-boxes change it, and the difference distribution table counts how often each input difference becomes each output difference. Chained through rounds, the best entries make a characteristic.',
    blocks: [
      'DES\'s S-boxes were chosen with care, and for years nobody outside knew why. The reason, made public in the 1990s, is an attack that watches pairs of plaintexts rather than single ones. We learn it on a toy cipher small enough to break completely: a 16-bit block, four 4-bit S-boxes a round, four rounds.',
      { topic: 'spn-ddt', frame: 0, caption: 'The toy SPN\'s S-box maps 0 … f to 6, b, 5, 4, 2, e, 7, a, 9, d, f, c, 3, 1, 0, 8. The question: if two inputs differ by Δx, how often do the outputs differ by Δy?' },
      { predict: { q: 'Two plaintexts differ by Δ. Both have the same round key XORed in. How do the two results differ?', options: ['By Δ', 'By Δ ⊕ k', 'It depends on the key', 'By 0'], answer: 0, explain: '(x ⊕ k) ⊕ (x′ ⊕ k) = x ⊕ x′ = Δ. The key cancels from every difference; only the S-boxes can change it.' } },
      { topic: 'spn-ddt', frame: 1, caption: 'Δx = b, run over all 16 inputs: the output difference a turns up 4 times, so a pair with input difference b leaves with difference a with probability 4/16.' },
      { topic: 'spn-ddt', frame: 3, caption: 'The whole difference distribution table. Every entry is even; the largest is 4, so no difference passes an S-box with probability above 1/4.' },
      { h: 'A characteristic through the rounds' },
      { topic: 'spn-ddt', frame: 4, caption: 'Round 1: ΔP = 0300 meets one active S-box, which turns 3 into 2 with probability 4/16; the permutation sends the difference to 0040.' },
      { topic: 'spn-ddt', frame: 7, caption: 'Three rounds: ΔP = 0300 leads to 0044 in front of the last S-boxes with probability about 1/64. Only nibbles 2 and 3 of the last round are involved.' },
      { h: 'Recap' },
      { list: ['The key cancels from an XOR difference; only S-boxes change differences.', 'DDT entry (Δx, Δy): how many of the 16 inputs x give S(x) ⊕ S(x ⊕ Δx) = Δy.', 'A characteristic chains DDT entries through the rounds; its probability is the product.'] },
      X('des-x-ddt-row'), X('des-x-char-prob'),
    ],
  });

  C.lesson({
    id: 'des-diff', chapter: 'des-spn', title: 'The differential attack on the last round key', minutes: 9,
    summary: 'Encrypt many chosen pairs with the characteristic\'s input difference. Guess the last-round key bits in front of the active S-boxes, undo the last S-boxes with each guess, and count the pairs that show the predicted difference: the right guess collects the right pairs.',
    blocks: [
      'The characteristic says that about one pair in 64 with ΔP = 0300 reaches the last S-boxes with difference 0044. The attacker cannot see that difference: the last S-boxes and the last round key stand in the way. But she can guess the key bits that matter.',
      { topic: 'spn-diff', frame: 0, caption: '1500 chosen plaintexts P, each encrypted with its partner P ⊕ 0300. About 23 of the pairs should follow the characteristic.' },
      { topic: 'spn-diff', frame: 1, caption: 'A right pair can differ only in nibbles 2 and 3 of the ciphertext, so every pair that differs elsewhere is thrown away: 141 of 1500 are kept.' },
      { predict: { q: 'For the guess 00b4, a kept pair undoes to the difference 0064 instead of 0044. What does that say?', options: ['The guess is wrong', 'Nothing much: this pair may simply not be a right pair', 'The characteristic is wrong', 'The key must be 0064'], answer: 1, explain: 'Only about one pair in 64 follows the characteristic, so most kept pairs do not show 0044 even under the true key. The attack never decides from one pair; it counts over all of them.' } },
      { topic: 'spn-diff', frame: 3, caption: 'Under the true key bits 0054 the same pair gives 0044: a right pair always scores for the right key. Wrong guesses also score now and then, by chance.' },
      { topic: 'spn-diff', frame: 4, caption: 'All 256 guesses over all 141 kept pairs: 0054 scores 43, the next best 18. The right guess stands out.' },
      { topic: 'spn-diff', frame: 5, caption: '8 bits of K₅ from chosen pairs, by testing 256 guesses. The other nibbles fall to other characteristics, and K₄ after K₅ is peeled off.' },
      { bench: 'cipher', state: { area: 'labs', lab: 'spn' }, text: 'Recover all of K₅ for a fresh secret key.' },
      { h: 'Recap' },
      { list: ['Choose pairs with the characteristic\'s ΔP; keep those whose ciphertexts differ only in the active nibbles.', 'For each guess of those key bits, undo the last S-boxes and check for the predicted difference.', 'The right guess scores about pairs × probability more than the rest.'] },
      X('des-x-filter'), X('des-x-spn-break'),
      { challenge: 'des-ctf-keypad' },
    ],
  });

  C.lesson({
    id: 'des-linear', chapter: 'des-spn', title: 'Linear approximations and the piling-up lemma', minutes: 9,
    summary: 'A linear approximation says that the parity of some input bits equals the parity of some output bits more (or less) often than half the time. Chained through rounds, the biases multiply by the piling-up lemma, and the last round key falls to known plaintexts alone.',
    blocks: [
      'The differential attack needs chosen plaintexts. What can an attacker do with plaintexts she merely knows? She can look for a parity of plaintext bits and of bits just before the last round that agree more often than chance.',
      { topic: 'spn-linear', frame: 0, caption: 'Mask a = 3 on the input and b = 1 on the output: the two parities agree for 12 of the 16 inputs. The LAT entry is 12 − 8 = +4, a bias of 1/4.' },
      { topic: 'spn-linear', frame: 1, caption: 'The whole linear approximation table. Entries far from 0 in either direction are useful: a parity usually wrong is as good as one usually right.' },
      { def: 'Piling-up lemma', text: 'if n independent approximations hold with biases ε₁, …, εₙ, their XOR holds with bias 2ⁿ⁻¹·ε₁·ε₂·…·εₙ.' },
      { predict: { q: 'Three approximations, each with bias 1/4, are chained. What is the bias of the result?', options: ['1/4', '1/16', '1/64', '3/4'], answer: 1, explain: '2² · (1/4)³ = 4/64 = 1/16 = 0.0625. The bias shrinks with every round, which is why ciphers have many rounds.' } },
      { topic: 'spn-linear', frame: 5, caption: 'Through three rounds the approximation holds with bias 0.0625; about 1/ε² = 256 known plaintexts show it, more to be safe.' },
      { topic: 'spn-linear', frame: 6, caption: 'For each guess of a K₅ nibble, undo the last S-box on every ciphertext and measure the bias: the right guess sees about 0.0625, the wrong ones near 0.' },
      { topic: 'spn-linear', input: { a: '8', b: '2', approx: 'A', mode: 'one', texts: 6000, key: 4 }, frame: 7, caption: 'For this key one approximation misses: several approximations through the same S-boxes partly cancel.' },
      { topic: 'spn-linear', input: { a: '8', b: '2', approx: 'A', mode: 'several', texts: 6000, key: 4 }, frame: 7, caption: 'Adding up eight approximations on the same nibble recovers it: 00e0.' },
      { h: 'Recap' },
      { list: ['LAT entry (a, b): agreements of the parities a·x and b·S(x), minus 8.', 'Piling-up: the bias of a chain is 2ⁿ⁻¹ times the product of the biases.', 'About 1/ε² known plaintexts reveal a bias ε; the right key guess shows it.'] },
      X('des-x-lat'), X('des-x-pileup'),
    ],
  });

  C.lesson({
    id: 'des-present', chapter: 'des-spn', title: 'PRESENT: a real SPN for tiny chips', minutes: 6,
    summary: 'PRESENT has the shape of the toy SPN at full size: a 64-bit block, an 80-bit key, 31 rounds of round-key XOR, sixteen 4-bit S-boxes and a bit permutation. It was designed for chips with a few thousand gates.',
    blocks: [
      'The toy SPN is broken because it has four rounds and a 16-bit block. Scale it up with care and it becomes a cipher in real use: PRESENT, built for RFID tags and sensors where every gate costs power.',
      { topic: 'spn-present', frame: 0, caption: 'PRESENT: 64-bit block, 80-bit key, 31 rounds of three layers. The plaintext and key are the all-zero test vector.' },
      { topic: 'spn-present', frame: 2, caption: 'The S-box layer: sixteen copies of one 4-bit S-box. Its difference table has no entry above 4, as the toy\'s.' },
      { predict: { q: 'pLayer sends bit i to bit 16·i mod 63 (bit 63 stays). Where does bit 4 go?', options: ['1', '4', '64', '20'], answer: 0, explain: '16·4 = 64 = 63 + 1, so bit 4 goes to bit 1. The four output bits of each S-box are sent to four different S-boxes of the next round.' } },
      { topic: 'spn-present', frame: 3, caption: 'pLayer is pure wiring: in hardware it costs nothing.' },
      { topic: 'spn-present', frame: 6, caption: 'After 31 rounds and the last round key, the ciphertext 5579c1387b228445 matches the published test vector.' },
      { tip: 'Why 31 rounds when the toy fell in 4? Every round multiplies a characteristic\'s probability by at most 1/4 per active S-box, and the designers showed that any 5 rounds have at least 10 active S-boxes. Long before round 31, every characteristic is far rarer than 2⁻⁶⁴.' },
      { bench: 'cipher', state: { algo: 'present', mode: 'ecb', view: 'rounds' }, text: 'Encrypt with PRESENT, or set the toy SPN beside it.' },
      { h: 'Recap' },
      { list: ['PRESENT: 64-bit block, 80-bit key, 31 rounds of key XOR, 4-bit S-boxes and a bit permutation.', 'The same structure as the toy SPN, with enough rounds that no characteristic or approximation survives.', 'Small and cheap in hardware: the permutation is wiring.'] },
      X('des-x-present-p'), X('des-x-present'),
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
