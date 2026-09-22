// Part 3, stream ciphers: the chapters and the lessons. The exercises are in 031-stream-ex.js and the CTF challenges,
// the tour and the course in 032-stream-ctf.js. Each lesson opens with a question, runs the topic that animates the
// idea at a frame chosen for the point being made, asks for a prediction, sums up, and leads to its exercises. Every
// value here is our own and was worked out by the engines (S.OTP, S.LFSR, S.Geffe, S.Trivium, S.Salsa, S.ChaCha).
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('st-otp')) return;
  const X = (id) => ({ exercise: id });

  C.chapter({ id: 'st-pad', part: 'stream', n: 1, title: 'The one-time pad', blurb: 'Perfect secrecy from a random key as long as the message, and how a second use of the key gives both messages away.' });
  C.chapter({ id: 'st-gen', part: 'stream', n: 2, title: 'Generators and LFSRs', blurb: 'True, pseudo and cryptographic randomness; the linear feedback shift register, its period, and Berlekamp–Massey taking it apart from 2L bits.' });
  C.chapter({ id: 'st-comb', part: 'stream', n: 3, title: 'Combining registers', blurb: 'Hiding the linearity of LFSRs behind a combining function, the correlation attack that splits the Geffe generator, and Trivium.' });
  C.chapter({ id: 'st-arx', part: 'stream', n: 4, title: 'Salsa20 and ChaCha20', blurb: 'Add, rotate and XOR on a 4×4 state of words: the quarter-round, the double rounds, the block counter and the nonce.' });

  // =========================================================================================================
  // Chapter 1: the one-time pad
  // =========================================================================================================
  C.lesson({
    id: 'st-otp', chapter: 'st-pad', title: 'The one-time pad: perfect secrecy', minutes: 7,
    summary: 'XOR the message with a key of truly random bytes, as long as the message and never used again. Every plaintext of that length is then equally likely given the ciphertext: no amount of computing helps the attacker.',
    blocks: [
      'An agent sends a 16-byte message. The enemy intercepts it, and has a computer that can try every key there is, all 2¹²⁸ of them, in an afternoon. Is there any cipher that still keeps the message secret? There is, and it is the simplest cipher of all.',
      { def: 'One-time pad', text: 'c = m ⊕ k, byte by byte, where k is as long as m, chosen uniformly at random, and used for one message only. Decryption is the same XOR: c ⊕ k = m.' },
      { topic: 'st-otp-secrecy', frame: 2, caption: 'Each byte of “meet me at dawn!” is XORed with a key byte: “m” = 6d and 6d ⊕ ac = c1. Because the key byte is uniformly random, so is the ciphertext byte, whatever the message byte was.' },
      { predict: { q: 'The enemy tries every one of the 2¹²⁸ keys on the ciphertext c1b3da78…. What does that tell them?', options: ['The message, after enough tries', 'Only its length: every 16-byte message comes out of exactly one key', 'The first few bytes, which are less random', 'Nothing at all, not even the length'], answer: 1, explain: 'For every 16-byte message m′ there is exactly one key, c ⊕ m′, that turns c into it. Trying all keys lists every possible message once: the meeting at dawn, a retreat, an all-clear. The length is the only thing that leaks.' } },
      { topic: 'st-otp-secrecy', frame: 3, caption: 'The key b3c6b458… “decrypts” the same ciphertext to “run away tonight”. That key is exactly as likely as the true one, so the ciphertext cannot favour either message.' },
      { def: 'Perfect secrecy', text: 'Pr[M = m | C = c] = Pr[M = m] for every m and c: seeing the ciphertext does not change what the attacker believes about the message. The attacker\'s computing power does not enter at all.' },
      { topic: 'st-otp-secrecy', frame: 6, caption: 'Each of the 2¹²⁸ keys is equally likely, and each maps c to a different message, so every message is still as likely as before.' },
      { h: 'The price, and what the pad does not give' },
      'Perfect secrecy needs at least as many keys as messages, so the key must be as long as the message, truly random (a formula would make some keys likelier than others), and never used twice. Keys that size have to be carried to the other side in advance, which is why the pad survives only where couriers and diplomatic bags are cheaper than the risk.',
      { warn: 'The pad hides the message but does not protect it. Flipping a bit of c flips the same bit of m, and nobody notices. If the enemy guesses that the message ends “at dawn!”, XORing bytes 12, 13 and 14 of the ciphertext with 14 04 05 (that is, “awn” ⊕ “usk”) makes the receiver read “meet me at dusk!”. Integrity needs a MAC, part 12.' },
      { h: 'Recap' },
      { list: ['One-time pad: c = m ⊕ k with a uniformly random key as long as m, used once.', 'Perfect secrecy: the ciphertext leaves every message of that length exactly as likely as before; only the length leaks.', 'The key must be as long as the message and never reused, which makes the pad impractical for most uses.', 'XOR is malleable: flipped ciphertext bits flip the same plaintext bits.'] },
      X('st-x-otp-xor'), X('st-x-otp-anykey'), X('st-x-otp-cond'),
    ],
  });

  C.lesson({
    id: 'st-twotime', chapter: 'st-pad', title: 'The two-time pad and crib dragging', minutes: 9,
    summary: 'Encrypt two messages with the same pad and XOR the ciphertexts: the key cancels and m₁ ⊕ m₂ is left. Spaces show up as bytes of 40 or more, and a guessed word slid along the XOR reveals the other message wherever the guess is right.',
    blocks: [
      'Making truly random pads is tedious, so an operator who has run out is tempted to use one again. Each ciphertext on its own is still perfectly hidden. What goes wrong when an attacker holds both?',
      { topic: 'st-two-time', frame: 1, caption: 'XOR the two ciphertexts: (m₁ ⊕ k) ⊕ (m₂ ⊕ k) = m₁ ⊕ m₂, because k ⊕ k = 0. At byte 0, 8d ⊕ 8e = 03 is m₁[0] ⊕ m₂[0], whatever the key was.' },
      'The pad is gone, and what is left is two English texts tangled together. That is far from random: English has a lot of structure, and the XOR keeps much of it.',
      { predict: { q: 'The letter “t” is 74 in hex and a space is 20. If m₁ has a space where m₂ has “t”, what byte does m₁ ⊕ m₂ hold there?', options: ['00', '20', '54', '74'], answer: 2, explain: '74 ⊕ 20 = 54, which is “T”: XOR with a space flips bit 5, the bit that tells lower case from upper case. Two letters, both in 41–7a, XOR to a byte below 40; a letter and a space give 40 or more.' } },
      { topic: 'st-two-time', frame: 2, caption: 'The lit bytes are 40 or more: at each of them one message has a space, and the other has the letter shown with its case flipped. The gaps between words already show.' },
      { h: 'Crib dragging' },
      'Guess a word that one message probably contains, a **crib**, and XOR it into m₁ ⊕ m₂ at some position. If the guess is right there, what comes out is the other message at that place. If it is wrong, what comes out is usually not text at all.',
      { topic: 'st-two-time', frame: 3, caption: 'The crib “harbour” at position 0 gives “kh~6,ro”: not English, so “harbour” does not start either message.' },
      { topic: 'st-two-time', frame: 6, caption: 'At position 35 it gives “the old”, which reads like English: a likely hit. Each readable piece is extended a letter at a time to both sides, by guessing how the words go on.' },
      'Each piece found in one message gives the same stretch of the other, and the two grow together until both messages are read. With a third or fourth ciphertext under the same pad it gets easier still, because every column must decrypt to text in every message at once.',
      { bench: 'cipher', state: { area: 'labs', lab: 'twotime' }, text: 'Drag cribs yourself, then let a language model recover both messages from the XOR alone.' },
      { warn: 'Every stream cipher has this weakness, not only the pad. ChaCha20 or AES in CTR mode with a repeated key and nonce produce the same keystream twice, and the two ciphertexts XOR to m₁ ⊕ m₂ exactly as here. Chapter 4 comes back to it.' },
      { h: 'Recap' },
      { list: ['Two messages under one pad: c₁ ⊕ c₂ = m₁ ⊕ m₂, with no key left.', 'A byte of 40 or more in m₁ ⊕ m₂ means one of the messages has a space there.', 'Crib dragging: XOR a guessed word in at each position; readable output means the guess fits there, and shows the other message.', 'Known plaintext is worse still: m₂ = c₁ ⊕ c₂ ⊕ m₁ at once.'] },
      X('st-x-space'), X('st-x-twotime-known'), X('st-x-crib'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: generators and LFSRs
  // =========================================================================================================
  C.lesson({
    id: 'st-rng', chapter: 'st-gen', title: 'True, pseudo and cryptographic randomness', minutes: 7,
    summary: 'A true generator measures noise, which is unpredictable but biased. A pseudo-random generator stretches a seed with a formula, fast but predictable from its output. A cryptographically secure generator is a cipher under a secret key: nobody without the key can tell its output from coin flips.',
    blocks: [
      'The one-time pad needs as many random bytes as there are message bytes. A stream cipher makes do with a short key and stretches it into a long keystream. Where do random bits come from, and which kind is good enough to stand in for a pad?',
      { topic: 'st-rng', frame: 1, caption: 'A physical source that gives 1 with probability 0.7: 25 ones in 32 bits. Noise from hardware is unpredictable, but almost never fair.' },
      { topic: 'st-rng', frame: 2, caption: 'Read the bits in pairs, keep 01 as 0 and 10 as 1, and drop 00 and 11. The two kept pairs are equally likely whatever the bias, so the 7 kept bits are fair; most of the input is thrown away.' },
      { predict: { q: 'A generator computes xₙ₊₁ = 37·xₙ + 11 mod 251. You see three outputs in a row. How much more do you need to predict all the rest?', options: ['Nothing more: three outputs give a and c', 'About 251 more outputs', 'The seed, which is secret', 'It cannot be predicted'], answer: 0, explain: 'x₂ − x₁ = a·(x₁ − x₀) mod 251 gives a with one modular inverse, and then c = x₁ − a·x₀. From there every output follows.' } },
      { topic: 'st-rng', frame: 4, caption: 'From 42, 59 and 186: a = 127 / 17 mod 251 = 37 and c = 11, and the next 9 outputs are predicted exactly. A formula that is fast and passes statistical tests can still be useless for keys.' },
      { def: 'Cryptographically secure', text: 'a generator whose output cannot be told from uniformly random bits by anyone without the key or seed, in any feasible amount of computing; in particular, no earlier output helps predict the next bit.' },
      { topic: 'st-rng', frame: 5, caption: 'ChaCha20 run on a counter under a secret key is such a generator. Its bytes d4 5e 7a 3c … pass every test, and predicting them would mean breaking ChaCha20.' },
      { topic: 'st-rng', frame: 7, caption: 'In practice the three work together: the operating system collects true randomness, conditions it, and seeds a cryptographic generator with it.' },
      'A stream cipher is exactly such a generator: the key (and a nonce) is the seed, and the keystream is XORed with the message. The rest of this part looks at generators built for speed in hardware, the LFSRs, at what is wrong with them, and at the fixes.',
      { h: 'Recap' },
      { list: ['True randomness is unpredictable but biased; an extractor such as the pairs trick makes it fair.', 'A pseudo-random formula (an LCG, a bare LFSR) can be solved from a few outputs: never use one for keys.', 'A cryptographically secure generator is a cipher under a secret key; a stream cipher is one.'] },
      X('st-x-vn'), X('st-x-lcg'), X('st-x-lcg-break'),
    ],
  });

  C.lesson({
    id: 'st-lfsr', chapter: 'st-gen', title: 'The LFSR: a register with taps', minutes: 8,
    summary: 'A linear feedback shift register of L cells outputs its oldest bit each clock and shifts in the XOR of the tapped cells. The connection polynomial C(x) names the taps; every output bit is a fixed XOR of the seed bits.',
    blocks: [
      'Hardware engineers want keystream at one bit per clock, from a handful of gates. Take a row of flip-flops that pass their bits along, and feed the end back to the start through a few XOR gates. How long can such a register run before it repeats, and is it any good as a cipher?',
      { def: 'LFSR', text: 'a shift register of L cells. Each clock the oldest bit leaves as output, every bit moves one place, and the new bit is the XOR of the tapped cells: sₙ = c₁·sₙ₋₁ ⊕ c₂·sₙ₋₂ ⊕ … ⊕ c_L·sₙ₋L.' },
      { def: 'Connection polynomial', text: 'C(x) = 1 + c₁x + c₂x² + … + c_L·x^L: the term xᵏ is present when the bit from k clocks ago is tapped. 1 + x³ + x⁴ means sₙ = sₙ₋₃ ⊕ sₙ₋₄.' },
      { topic: 'st-lfsr', frame: 0, caption: 'Four cells and C(x) = 1 + x³ + x⁴. The cell under xᵏ holds the bit from k clocks ago; the seed 1000 is the first four output bits, oldest on the right.' },
      { topic: 'st-lfsr', frame: 1, caption: 'Clock 1: the taps under x⁴ and x³ read 1 and 0, so 1 ⊕ 0 = 1 enters on the left, and the oldest bit, 1, leaves as s₀.' },
      { predict: { q: 'The stream so far is s₀ … s₇ = 1000 1001. With C(x) = 1 + x³ + x⁴ the next bit is s₈ = s₅ ⊕ s₄. What is it?', options: ['0', '1', 'It cannot be told without the seed'], answer: 1, explain: 's₅ = 0 and s₄ = 1, so s₈ = 0 ⊕ 1 = 1. The register holds exactly the last four bits, and they are all the recurrence needs: the seed is no longer required.' } },
      { topic: 'st-lfsr', frame: 17, caption: 'Sixteen clocks give 1000100110101111. Every bit is an XOR of seed bits, so the stream is linear in the seed: four bits of state predict it for ever.' },
      { topic: 'st-lfsr', input: { taps: ['5', '2'], seed: '10010', clocks: 12 }, frame: 1, caption: 'Five cells and C(x) = 1 + x² + x⁵, with the seed 10010: the taps read 1 and 1, so the first new bit is 0. Change the taps and the seed under the figure to run your own register.', inputs: true },
      { sandbox: 'scratch' },
      { h: 'Recap' },
      { list: ['Each clock: output the oldest bit, shift, and shift in the XOR of the tapped cells.', 'C(x) = 1 + Σ cₖxᵏ names the taps; L, its degree, is the number of cells.', 'The first L output bits are the seed; every later bit is an XOR of seed bits.'] },
      X('st-x-lfsr-table'), X('st-x-lfsr-bits'), X('st-x-code-lfsr'),
    ],
  });

  C.lesson({
    id: 'st-period', chapter: 'st-gen', title: 'Period, primitive polynomials, and the Galois form', minutes: 8,
    summary: 'An L-cell register has 2^L − 1 nonzero states, so it repeats after at most that many clocks. It reaches that maximum from every nonzero seed exactly when C(x) is primitive. The Galois form makes the same sequence with its XORs side by side.',
    blocks: [
      'A keystream that repeats is a two-time pad waiting to happen. A 4-cell register has only 16 states, so it must repeat within 16 clocks. Does every choice of taps use all of them?',
      { topic: 'st-period', frame: 1, caption: 'C(x) = 1 + x³ + x⁴: from 0001 the register visits all 15 nonzero states before it comes back. The all-zero state is left out; it would stay zero for ever.' },
      { predict: { q: 'C(x) = 1 + x² + x⁴ also has degree 4. What is the longest period it can give?', options: ['15, like every register of 4 cells', '6', '4', '16'], answer: 1, explain: '1 + x² + x⁴ = (1 + x + x²)² over GF(2), since the cross term 2x³ vanishes. A reducible polynomial splits the 15 states into shorter cycles: here 6, 6 and 3.' } },
      { topic: 'st-period', input: { taps: ['4', '2'] }, frame: 4, caption: 'The states of 1 + x² + x⁴ fall into cycles of 6, 6 and 3. Which cycle you are on depends on the seed, and none is long.' },
      { def: 'Primitive polynomial', text: 'a C(x) of degree L for which the register runs through all 2^L − 1 nonzero states from any nonzero seed. A primitive polynomial is irreducible, but not every irreducible one is primitive.' },
      { topic: 'st-period', input: { taps: ['5', '3'] }, frame: 2, caption: '1 + x³ + x⁵ is primitive: a single cycle of 31. There are 6 primitive polynomials of degree 5, and a designer always picks one.' },
      'A long period is necessary, not sufficient. A 64-cell register with a primitive polynomial repeats only after 2⁶⁴ − 1 bits, yet the next lesson recovers it from 128 bits of output.',
      { h: 'Two ways to wire the same register' },
      { topic: 'st-galois', frame: 1, caption: 'The Fibonacci form (top) XORs the tapped cells into one new bit. The Galois form (bottom) shifts, and when its output is 1 it flips the bits passing each tap. Both output 1.' },
      { topic: 'st-galois', frame: 13, caption: 'After 12 clocks both streams are 100010011010. The registers never hold the same bits, but the outputs agree at every clock; the Galois XORs are one gate deep, so it runs faster in hardware.' },
      { h: 'Recap' },
      { list: ['An L-cell register has period at most 2^L − 1; the all-zero state is a dead end.', 'The maximum is reached from every nonzero seed exactly when C(x) is primitive.', 'A reducible C(x) splits the states into short cycles that depend on the seed.', 'Fibonacci and Galois registers with the same C(x) give the same sequence.'] },
      X('st-x-period'), X('st-x-primitive'), X('st-x-galois'),
    ],
  });

  C.lesson({
    id: 'st-bm', chapter: 'st-gen', title: 'Berlekamp–Massey: an LFSR from 2L bits', minutes: 9,
    summary: 'Berlekamp–Massey reads output bits one at a time and keeps the shortest register that explains them, correcting it with an earlier version whenever it predicts a bit wrongly. After 2L bits it has the register, and the rest of the keystream follows.',
    blocks: [
      'An eavesdropper knows that a radio link encrypts with a single LFSR of unknown taps and unknown seed, and learns a few dozen keystream bits from a known file header. How many bits does she need to predict the rest of the keystream?',
      { def: 'Linear complexity', text: 'the length L of the shortest LFSR that generates a sequence. For the output of an L-cell register with a primitive C(x), it is L.' },
      'If the taps were known, L bits would be enough: they are the seed. With unknown taps the attacker can write L linear equations in the L tap bits from 2L output bits and solve them. Berlekamp–Massey does the same work in a neater way, bit by bit, and always finds the shortest register.',
      { topic: 'st-bm', frame: 1, caption: 'Bit 0 is 1, but the empty register predicts 0. The discrepancy forces a correction: C(x) becomes 1 + x, and since no register of length 0 can make a 1, L grows to 1.' },
      { topic: 'st-bm', frame: 5, caption: 'Bit 4 is 1, but C(x) = 1 predicts 0. The fix adds x⁴·B(x), the polynomial saved when L last grew, shifted to line up: C(x) = 1 + x⁴, and L jumps to 4.' },
      { predict: { q: 'Now C(x) = 1 + x⁴ with L = 4, and bits 5 and 6 are 0 and 0. The register predicts both correctly. What does the algorithm do?', options: ['Nothing: C(x) and L stand', 'It lengthens the register anyway', 'It starts again from C(x) = 1'], answer: 0, explain: 'A correct prediction is a discrepancy of 0, and then the register is kept as it is. Only a wrong prediction changes C(x), and only some of those make L grow.' } },
      { topic: 'st-bm', frame: 8, caption: 'Bit 7 disagrees, and adding x³·B(x) gives C(x) = 1 + x³ + x⁴. L stays 4, because a register of length 4 can be fixed without growing.' },
      { topic: 'st-bm', frame: 9, caption: 'Eight bits, so 8 ≥ 2L: 1 + x³ + x⁴ is the only register of length 4 that makes them. Seeded with the first four bits it regenerates all the rest.' },
      { topic: 'st-bm', input: { bits: '10110' }, frame: 6, caption: 'Too few bits: five output bits of a 4-cell register are explained by a register of length 2, 1 + x + x². It fits these five bits and is wrong about the sixth. Only 2L bits make the answer certain.' },
      { bench: 'cipher', state: { area: 'labs', lab: 'bm' }, text: 'Paste any bits and watch Berlekamp–Massey build the register.' },
      { warn: 'So a bare LFSR is never a cipher, however long. A 128-cell register is recovered from 256 bits of keystream, in a fraction of a millisecond. Real designs keep LFSRs only as parts, behind something nonlinear.' },
      { h: 'Recap' },
      { list: ['Linear complexity L: the length of the shortest LFSR that makes the sequence.', 'Berlekamp–Massey corrects its register at each wrong prediction, growing L when it must.', '2L bits of output determine an L-cell LFSR completely.', 'A bare LFSR keystream is broken from a known header.'] },
      X('st-x-bm-table'), X('st-x-bm-break'), X('st-x-code-bm'), X('st-x-lfsr-recover'),
      { challenge: 'st-ctf-chart' },
    ],
  });

  // =========================================================================================================
  // Chapter 3: combining registers
  // =========================================================================================================
  C.lesson({
    id: 'st-geffe', chapter: 'st-comb', title: 'Combining registers, and the correlation attack', minutes: 9,
    summary: 'The Geffe generator lets one LFSR choose between two others. Its output agrees with each of the chosen registers three times in four, so each can be found on its own by trying its start states and counting agreements: the key falls one register at a time.',
    blocks: [
      'One LFSR falls to Berlekamp–Massey. What if three registers run side by side and a nonlinear function combines their bits? The key is then all three start states, and trying every key costs the product of their sizes. Or does it?',
      { topic: 'st-geffe', frame: 0, caption: 'Registers of 7, 11 and 13 cells: 31 key bits in all, 2³¹ keys. Each clock x₁ chooses whether x₂ or x₃ becomes the output z.' },
      { math: 'z = x₁·x₂ ⊕ (1 ⊕ x₁)·x₃\nx₁ = 1: z = x₂      x₁ = 0: z = x₃' },
      { topic: 'st-geffe', frame: 1, caption: 'Clock 1: x₁ = 0, so the selector passes x₃ = 1, and z = 1.' },
      { predict: { q: 'Over the eight equally likely inputs (x₁, x₂, x₃), in how many does z equal x₂?', options: ['4, half of them', '6', '8, all of them', '2'], answer: 1, explain: 'When x₁ = 1 (four cases) z is x₂ by definition. When x₁ = 0, z is x₃, which equals x₂ in two of the four cases. So 4 + 2 = 6 of 8: z agrees with x₂ three times in four.' } },
      { topic: 'st-geffe', frame: 4, caption: 'The first 40 bits with every agreement marked: over 200 bits, z agrees with x₂ 150 times and with x₃ 147 times, far from the 100 that unrelated bits would give.' },
      { h: 'Divide and conquer' },
      'So try each start state of register 2 alone, run it for 200 bits, and count how often it agrees with z. A wrong start state gives bits unrelated to z, agreeing about half the time; the right one agrees about three times in four. Register 3 falls the same way, and register 1 last of all.',
      { topic: 'st-geffe', frame: 6, caption: 'All 2047 start states of R2: the wrong ones pile up near 50%, the best reaches 75.0%, and the runner-up only 64.0%. The best is the true start state.' },
      { topic: 'st-geffe', frame: 8, caption: 'With x₂ and x₃ known, z shows x₁ wherever x₂ and x₃ differ (103 places), and R1\'s start state is the one that fits them all.' },
      { topic: 'st-geffe', frame: 9, caption: '10 368 start states tried, one register at a time, instead of 2 147 483 648 keys. The correlation splits the key into pieces that are guessed separately.' },
      { topic: 'st-geffe', input: { seed: '9', n: 60 }, frame: 6, caption: 'With only 60 bits the right state does not stand out: the best wrong state agrees 71.7% of the time. The attack needs enough output for the 75% to beat every lucky guess.' },
      { bench: 'cipher', state: { area: 'labs', lab: 'geffe' }, text: 'Run the correlation attack on a fresh Geffe generator.' },
      { tip: 'The lesson for designers: the combining function must not agree with any single input, or any small set of inputs, more often than half the time. Such functions are called correlation-immune, and there is a trade-off between that and the nonlinearity needed against Berlekamp–Massey.' },
      { h: 'Recap' },
      { list: ['Geffe: z = x₁·x₂ ⊕ (1 ⊕ x₁)·x₃. Its output agrees with x₂ and with x₃ three times in four.', 'Correlation attack: try each register\'s start states alone and keep the one that agrees with z most.', 'The cost is the sum of the register sizes, not their product.'] },
      X('st-x-geffe-table'), X('st-x-geffe-x1'), X('st-x-geffe-break'),
    ],
  });

  C.lesson({
    id: 'st-trivium', chapter: 'st-comb', title: 'Trivium: three registers coupled by AND', minutes: 6,
    summary: 'Trivium keeps 288 bits in three shift registers. Each new bit mixes linear taps of its own register, one AND of two neighbouring cells, and a cell of another register; 1152 warm-up clocks spread the key and IV through all of it before any output.',
    blocks: [
      'Correlation attacks feed on a combining function that sits after the registers. Trivium puts the nonlinearity inside instead: each register is fed by an AND, and the registers feed each other. It is one of the smallest stream ciphers in use, built for chips that have a few thousand gates to spare.',
      { topic: 'st-trivium', frame: 0, caption: 'Three registers of 93, 84 and 111 cells. The 80-bit key goes into the first, the 80-bit IV into the second, the last three cells of the third are set to 1, and the rest are 0.' },
      { predict: { q: 'Why does Trivium run 1152 clocks and throw the output away before encrypting anything?', options: ['To slow down brute force', 'So that every key and IV bit has passed through the AND gates and reached every cell', 'To wait for the hardware to warm up', 'To make the period longer'], answer: 1, explain: 'Right after loading, the first output bits would be simple functions of a few key and IV bits. After 4 × 288 clocks every cell depends on the whole key and IV in a complicated, nonlinear way.' } },
      { topic: 'st-trivium', frame: 1, caption: 'After the 1152 warm-up clocks, 138 of the 288 bits are set, with no trace of the key\'s pattern.' },
      { topic: 'st-trivium', frame: 2, caption: 'One clock: t₁, t₂ and t₃ are sums of two cells of each register, and the output is their XOR, z = 1. Each new bit adds one AND of two neighbouring cells and one cell of another register.' },
      { topic: 'st-trivium', frame: 6, caption: 'The keystream bytes c1 6d 0e d0 … XOR “low tide” into the ciphertext. Each clock costs three ANDs and a few XORs.' },
      'Because the nonlinearity is inside the feedback, the linear complexity of Trivium\'s output is enormous, and no single register can be split off and attacked alone. Its security rests on years of public cryptanalysis rather than on a proof; reduced versions with fewer warm-up clocks have been broken, the full one has not.',
      { bench: 'cipher', state: { algo: 'trivium', view: 'registers' }, text: 'Encrypt with Trivium and watch its three registers.' },
      { h: 'Recap' },
      { list: ['288 bits in three registers of 93, 84 and 111 cells; 80-bit key and IV.', 'Each new bit: linear taps, one AND of neighbouring cells, and a bit from another register.', '1152 warm-up clocks before the first output bit.', 'Tiny in hardware: three ANDs and a handful of XORs per bit.'] },
      X('st-x-trivium'),
    ],
  });

  // =========================================================================================================
  // Chapter 4: Salsa20 and ChaCha20
  // =========================================================================================================
  C.lesson({
    id: 'st-arx', chapter: 'st-arx', title: 'Add, rotate, XOR: the quarter-round', minutes: 9,
    summary: 'Salsa20 and ChaCha20 work on a 4×4 grid of 32-bit words with only three operations: addition modulo 2³², rotation and XOR. The quarter-round mixes four words in four lines; ChaCha\'s version makes every input bit reach every output word faster.',
    blocks: [
      'Shift registers are cheap in hardware and slow in software, which works on whole 32-bit or 64-bit words. A software stream cipher wants operations every processor does in one instruction, in constant time, with no tables to leak through the cache. Three are enough.',
      { def: 'ARX', text: 'add modulo 2³² (⊞), rotate by a fixed amount (<<<), and XOR (⊕). Addition carries bits upward and is not linear over GF(2); rotation moves bits sideways; XOR combines without losing anything.' },
      { topic: 'st-salsa', frame: 0, caption: 'Salsa20\'s state: the constants spelling “expand 32-byte k” on the diagonal, the key around them, the nonce and the block counter in the middle.' },
      { topic: 'st-salsa', frame: 2, caption: 'A Salsa20 quarter-round line: b ^= (a + d) <<< 7. The sum 81d5e0d9, rotated by 7, is eaf06cc0, and XORed into b it gives 999402a5.' },
      { h: 'ChaCha\'s quarter-round' },
      'ChaCha20 rearranges the same three operations so that each line updates a word and the next line uses it at once. Four lines, each an add, an XOR and a rotation:',
      { math: 'a ⊞= b;  d ⊕= a;  d <<<= 16\nc ⊞= d;  b ⊕= c;  b <<<= 12\na ⊞= b;  d ⊕= a;  d <<<= 8\nc ⊞= d;  b ⊕= c;  b <<<= 7' },
      { topic: 'st-chacha-qr', frame: 1, caption: 'Column 2 of the ChaCha state: a = 3320646e, b = 206e6f72, c = 64656572, d = 726f6873, about to go through the twelve steps.' },
      { topic: 'st-chacha-qr', frame: 2, caption: 'Step 1: a ⊞= b gives 538ed3e0. 17 of a\'s bits change, some of them through carries.' },
      { predict: { q: 'Step 2 sets d = 726f6873 ⊕ 538ed3e0 = 21e1bb93. Step 3 rotates d left by 16. What is d then?', options: ['bb9321e1', '1e1bb932', '21e1bb93', '3bb91e12'], answer: 0, explain: 'A rotation by 16 swaps the two 16-bit halves: 21e1 bb93 becomes bb93 21e1. No bit changes value; each moves 16 places.' } },
      { topic: 'st-chacha-qr', frame: 4, caption: 'Step 3: d <<<= 16 gives bb9321e1, the halves swapped.' },
      { topic: 'st-chacha-qr', frame: 14, caption: 'After the four lines, column 2 is c210e7d9 9e561ae6 a3bebfcc 83c63879. The same quarter-round runs on all four columns; 267 of the 512 state bits have changed.' },
      { topic: 'st-chacha-qr', frame: 15, caption: 'Then the four diagonals, so every word depends on every other. A column round and a diagonal round make a double round; ChaCha20 runs ten.' },
      { sandbox: 'quarter-round' },
      { h: 'Recap' },
      { list: ['ARX: add modulo 2³², rotate, XOR; fast and constant-time in software, no tables.', 'ChaCha quarter-round: four lines of add, XOR, rotate, with rotations 16, 12, 8, 7.', 'A double round: the quarter-round on the four columns, then on the four diagonals.'] },
      X('st-x-rotl'), X('st-x-add32'), X('st-x-salsa-line'), X('st-x-qr-table'), X('st-x-code-qr'),
    ],
  });

  C.lesson({
    id: 'st-chacha', chapter: 'st-arx', title: 'The ChaCha20 block, the counter and the nonce', minutes: 9,
    summary: 'ChaCha20 builds its state from constants, a 256-bit key, a 32-bit block counter and a 96-bit nonce, runs twenty rounds and adds the input back, giving 64 keystream bytes. The counter numbers the blocks of one message; the nonce must never repeat under the same key.',
    blocks: [
      'The quarter-round scrambles a state. To be a stream cipher, ChaCha20 must turn a key into a long keystream, a different one for every message, and let either side jump to any block at once. Each part of the starting state has one of those jobs.',
      { math: 'row 0: the constants 61707865 3320646e 79622d32 6b206574 ("expand 32-byte k")\nrows 1–2: the key, eight words, each read lowest byte first\nrow 3: the block counter, then three words of nonce' },
      { topic: 'st-chacha-block', frame: 0, caption: 'The starting state for block 1 of a 96-byte message. The key “a heron waits where reeds divide” fills rows 1 and 2; x₁₂ holds the counter.' },
      { topic: 'st-chacha-block', frame: 1, caption: 'Ten double rounds later about half the bits differ from the start. But the rounds can be run backwards: this state alone would give the key away.' },
      { topic: 'st-chacha-block', frame: 2, caption: 'So each word of the starting state is added back: bbf83840 ⊞ 61707865 = 1d68b0a5. With the key on both sides of the sum, the rounds can no longer be undone.' },
      { predict: { q: 'Word 0 of the result is 1d68b0a5. What are the first four keystream bytes?', options: ['1d 68 b0 a5', 'a5 b0 68 1d', 'b0 a5 1d 68', '5a 0b 86 d1'], answer: 1, explain: 'ChaCha20 writes each word lowest byte first (little-endian): 1d68b0a5 becomes a5 b0 68 1d.' } },
      { topic: 'st-chacha-block', frame: 4, caption: 'Block counter 1 gives 64 keystream bytes starting a5b0681d; “Meet” (4d656574) becomes e8d50d69.' },
      { topic: 'st-chacha-block', frame: 6, caption: 'The next block uses counter 2, so no keystream byte is used twice within a message. Decryption runs the same computation and XORs again.' },
      { h: 'The nonce' },
      'The counter keeps the blocks of one message apart; the nonce keeps messages apart. Two messages under the same key and the same nonce get exactly the same keystream, and their ciphertexts XOR to m₁ ⊕ m₂: the two-time pad of chapter 1, with every tool from that lesson working again.',
      { warn: 'A 96-bit nonce is safe as a counter that never repeats. Chosen at random it is not: by the birthday bound, random 12-byte nonces are likely to collide after about 2⁴⁸ messages under one key.' },
      { topic: 'st-xchacha', frame: 0, caption: 'XChaCha20 takes a 24-byte nonce. The first 16 bytes go with the key into HChaCha20 to make a subkey; the last 8 become an ordinary ChaCha20 nonce.' },
      { topic: 'st-xchacha', frame: 6, caption: 'Random 24-byte nonces are safe for about 2⁹⁶ messages, for the price of one extra HChaCha20 call per message.' },
      { bench: 'cipher', state: { algo: 'chacha20', view: 'keystream' }, text: 'Encrypt with ChaCha20 and see each block\'s counter and keystream.' },
      { h: 'Recap' },
      { list: ['State: 4 constant words, 8 key words, a 32-bit counter, 3 nonce words; words are little-endian.', 'Twenty rounds, then the input added back: 64 bytes of keystream per block.', 'The counter numbers blocks; the nonce must never repeat under one key.', 'XChaCha20 derives a subkey from a 24-byte nonce, so nonces can be random.'] },
      X('st-x-state'), X('st-x-counter'), X('st-x-nonce-reuse'), X('st-x-xchacha'),
      { challenge: 'st-ctf-buoys' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
