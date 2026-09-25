// Part 5, AES: the chapters and the lessons. The exercises are in 051-aes-ex.js and the CTF challenges, the tour and
// the course in 052-aes-ctf.js. Each lesson opens with a question, runs the topic that shows the idea at a frame chosen
// for the point being made, asks for a prediction, sums up, and leads to its exercises. Every value quoted here was
// worked out by the engines (S.AES, S.gf256, S.MiniAES) on the topics' own inputs.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('ae-state')) return;
  const X = (id) => ({ exercise: id });

  C.chapter({ id: 'ae-state', part: 'aes', n: 1, title: 'The state and the S-box', blurb: 'Sixteen bytes in a 4×4 grid, ten rounds over them, and SubBytes built from inversion in GF(2⁸) and an affine map.' });
  C.chapter({ id: 'ae-round', part: 'aes', n: 2, title: 'The round steps and the key schedule', blurb: 'ShiftRows and MixColumns spread every byte over the state; AddRoundKey brings in the key; the key expansion makes eleven round keys with the g-function.' });
  C.chapter({ id: 'ae-whole', part: 'aes', n: 3, title: 'The whole cipher', blurb: 'One encryption round by round, the inverse cipher that retraces it, and one flipped bit spreading to half the block in two rounds.' });
  C.chapter({ id: 'ae-practice', part: 'aes', n: 4, title: 'Mini-AES and real implementations', blurb: 'The same design on 16 bits, small enough for pencil and paper; T-tables and the cache lines they leak; and what key length buys.' });

  // =========================================================================================================
  // Chapter 1: the state and the S-box
  // =========================================================================================================
  C.lesson({
    id: 'ae-state', chapter: 'ae-state', title: 'The state and its rounds', minutes: 7,
    summary: 'AES works on 16 bytes laid out as a 4×4 grid, filled column by column. A 128-bit key gives ten rounds of four steps each, after a first key addition; the ciphertext is the final grid read out the same way.',
    blocks: [
      'DES worked on two 32-bit halves and spent half of each round just swapping them. AES, chosen in 2001 to replace it, treats the block as a small grid of bytes and changes all of it in every round. How is the grid laid out, and what happens to it in a round?',
      { def: 'State', text: 'the 16 bytes being encrypted, as a 4×4 grid. Byte i of the input goes to row i mod 4 and column ⌊i/4⌋: the grid is filled one column at a time, top to bottom.' },
      { topic: 'aes-overview', frame: 2, caption: '“Lanterns at dusk” is 4c616e74 65726e73 20617420 6475736b. The first four bytes fill column 0 from the top, the next four column 1, and so on. Byte 6, 6e, is lit: it sits in row 2, column 1.' },
      { predict: { q: 'Byte 13 of the input goes where in the grid?', options: ['Row 3, column 1', 'Row 1, column 3', 'Row 1, column 1', 'Row 3, column 3'], answer: 1, explain: 'Row 13 mod 4 = 1 and column ⌊13/4⌋ = 3. Reading the grid row by row instead of column by column is the commonest slip when working AES by hand.' } },
      { topic: 'aes-overview', frame: 3, caption: 'Each column is a 32-bit word: column 0 is 4c616e74. The key is cut into words the same way and expanded into 11 round keys; round key 0 is the key itself, 6f636872652d72697665722d32303236.' },
      { h: 'Rounds' },
      { table: [['Key', 'Rounds', 'Round keys', 'Key words made'], ['128 bits', '10', '11', '44'], ['192 bits', '12', '13', '52'], ['256 bits', '14', '15', '60']], caption: 'The block is always 128 bits; only the key length changes the number of rounds.' },
      { topic: 'aes-overview', frame: 4, caption: 'Round 0 is only AddRoundKey: XOR the first round key into the state. The state becomes 23020606005f1c1a5604060d5645415d.' },
      { topic: 'aes-overview', frame: 5, caption: 'Round 1 applies SubBytes, ShiftRows, MixColumns and AddRoundKey. After it the state is 4f1e8e03280022327f769183e00fd8b5: nothing of the text is recognisable.' },
      { topic: 'aes-overview', frame: 14, caption: 'Round 10 leaves out MixColumns. The final state dd4d23f3bf51ab4561eae6a9f830b787, read column by column, is the ciphertext.' },
      { tip: 'Each step has a job. SubBytes is the only non-linear one (confusion). ShiftRows and MixColumns spread each byte over the state (diffusion). AddRoundKey is the only one that uses the key. Without the key steps, the rest would be a public permutation anyone could undo.' },
      { h: 'Recap' },
      { list: ['The state is a 4×4 grid of bytes, filled column by column: byte i is at row i mod 4, column ⌊i/4⌋.', 'AES-128 runs round 0 (a key addition), nine full rounds and a last round without MixColumns.', '192- and 256-bit keys give 12 and 14 rounds; the block stays at 128 bits.'] },
      X('ae-x-layout'), X('ae-x-state-load'),
    ],
  });

  C.lesson({
    id: 'ae-sub', chapter: 'ae-state', title: 'SubBytes: inversion and an affine map', minutes: 9,
    summary: 'Every byte of the state goes through the same 256-entry table, the S-box. The table is not arbitrary: each entry is the inverse of the byte in GF(2⁸), followed by a fixed affine map over the bits.',
    blocks: [
      'A cipher made only of XORs, rotations and matrix products is linear: an attacker could write every output bit as an XOR of input and key bits and solve the equations. Something has to break the linearity. In AES that something is one small table. Where does its contents come from?',
      { topic: 'aes-subbytes', frame: 1, caption: 'The byte in row 2, column 1 is 1c = 00011100, read as the polynomial x⁴ + x³ + x² over GF(2).' },
      { topic: 'aes-subbytes', frame: 2, caption: 'Step one: the inverse in GF(2⁸), the field of bytes modulo x⁸ + x⁴ + x³ + x + 1. The inverse of 1c is ff, because 1c · ff = 01. The byte 00 has no inverse and is mapped to 00.' },
      'Inversion is very non-linear: knowing x and y tells you little about the inverse of x ⊕ y. But on its own it has a weakness: it is a simple algebraic formula, and it maps 00 and 01 to themselves. The second step fixes both.',
      { topic: 'aes-subbytes', frame: 3, caption: 'Step two: an affine map on the bits of ff. Output bit 0 is the XOR of input bits 0, 4, 5, 6 and 7 and bit 0 of the constant 63.' },
      { math: 'bᵢ′ = bᵢ ⊕ bᵢ₊₄ ⊕ bᵢ₊₅ ⊕ bᵢ₊₆ ⊕ bᵢ₊₇ ⊕ cᵢ   (indices mod 8, c = 63 = 01100011)' },
      { topic: 'aes-subbytes', frame: 5, caption: 'All eight output bits read 10011100, so S(1c) = 9c.' },
      { predict: { q: 'The state above holds the byte 06 in three places. S(06) = 6f. After SubBytes, what do those three places hold?', options: ['6f in all three', '6f in one and different values in the others, since the position matters', 'It depends on the round key', 'It depends on the round number'], answer: 0, explain: 'The S-box is one fixed table for every byte, every position and every round. Equal bytes in give equal bytes out; the key and the position enter only through the other steps.' } },
      { h: 'The whole table' },
      { topic: 'aes-sbox', frame: 6, caption: 'Look up 6e at row 6, column e: 9f. It is the affine map of the inverse 21, since 6e · 21 = 01.' },
      { topic: 'aes-sbox', frame: 7, caption: 'All 256 values appear once, so the table can be inverted for decryption: S⁻¹(9f) = 6e. No byte maps to itself and none to its complement, which is what the constant 63 was chosen for.' },
      { h: 'Multiplying by 02: xtime' },
      'Inversion and MixColumns both need products in GF(2⁸). The basic one is multiplication by 02, called xtime: shift the byte one bit left, and if a 1 fell off the top, XOR in 1b (the low byte of the modulus 11b). Any product is built from xtimes and XORs: 03·b = 02·b ⊕ b.',
      { math: 'xtime(57) = ae         (no bit falls off)\nxtime(ae) = 5c ⊕ 1b = 47   (a bit fell off)' },
      { sandbox: 'xtime' },
      { h: 'Recap' },
      { list: ['S(x) is the inverse of x in GF(2⁸) (with 00 ↦ 00), then an affine map of the bits with the constant 63.', 'The S-box is the only non-linear part of AES, and the same table is used everywhere.', 'It is a permutation, so it can be undone; it has no fixed points.', 'xtime multiplies by 02: shift left and, on overflow, XOR 1b.'] },
      X('ae-x-sbox-look'), X('ae-x-xtime'), X('ae-x-inv02'), X('ae-x-affine'), X('ae-x-subbytes-state'), X('ae-x-code-xtime'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: the round steps and the key schedule
  // =========================================================================================================
  C.lesson({
    id: 'ae-shiftmix', chapter: 'ae-round', title: 'ShiftRows and MixColumns', minutes: 9,
    summary: 'ShiftRows turns row r of the state r places to the left, so each column gathers one byte from every column. MixColumns then multiplies each column by a fixed matrix over GF(2⁸), so every output byte depends on all four input bytes.',
    blocks: [
      'SubBytes works byte by byte: a change in one byte stays in that byte. For the cipher to be secure, one changed input bit has to reach every output bit within a few rounds. Two steps do the spreading, one along the rows and one down the columns.',
      { topic: 'aes-shiftrows', frame: 1, caption: 'Row 0 stays. Row 1 turns one place left: 77 cf f2 6e becomes cf f2 6e 77.' },
      { topic: 'aes-shiftrows', frame: 4, caption: 'After all four rows, column 0 holds 26 cf 6f 4c: one byte from each input column, read along a diagonal. The colours show where each byte came from.' },
      { predict: { q: 'Before ShiftRows, a byte sits in row 3, column 1. Which column is it in afterwards?', options: ['Column 1', 'Column 2', 'Column 0', 'Column 3'], answer: 1, explain: 'Row 3 turns three places left, which is one place right: column 1 goes to column (1 − 3) mod 4 = 2.' } },
      { h: 'MixColumns' },
      { math: '⎡d₀⎤   ⎡02 03 01 01⎤ ⎡b₀⎤\n⎢d₁⎥ = ⎢01 02 03 01⎥ ⎢b₁⎥\n⎢d₂⎥   ⎢01 01 02 03⎥ ⎢b₂⎥\n⎣d₃⎦   ⎣03 01 01 02⎦ ⎣b₃⎦   products in GF(2⁸), sums are XOR' },
      { topic: 'aes-mixcolumns', frame: 1, caption: 'Row 0 for the column c9 e2 18 7a: 02·c9 ⊕ 03·e2 ⊕ 18 ⊕ 7a = 89 ⊕ 3d ⊕ 18 ⊕ 7a = d6. 02·c9 is xtime: c9 has its top bit set, so 92 ⊕ 1b = 89.' },
      { topic: 'aes-mixcolumns', frame: 5, caption: 'The column becomes d6 44 95 4e. Change one input byte and all four output bytes change: the matrix is chosen so that input and output differences together always touch at least five of the eight bytes.' },
      { predict: { q: 'Two columns differ in exactly one byte. In how many bytes do their MixColumns outputs differ?', options: ['1', '2', '4', 'It depends on the bytes'], answer: 2, explain: 'MixColumns has branch number 5: nonzero input differences plus nonzero output differences is at least 5. With 1 byte in, all 4 bytes out must differ.' } },
      'Together the two steps reach everything in two rounds: after round 1 a changed byte fills one column; ShiftRows of round 2 sends that column\'s four bytes to four different columns, and MixColumns fills each of them.',
      { h: 'Recap' },
      { list: ['ShiftRows: row r turns r places left; each new column takes one byte from every old column.', 'MixColumns: each column times a fixed matrix of 01, 02 and 03 over GF(2⁸); every output byte depends on all four inputs.', 'A one-byte difference becomes four after MixColumns, and sixteen one round later.'] },
      X('ae-x-shiftrows'), X('ae-x-mul'), X('ae-x-mixcol'), X('ae-x-code-mixcol'),
    ],
  });

  C.lesson({
    id: 'ae-ark', chapter: 'ae-round', title: 'AddRoundKey', minutes: 5,
    summary: 'AddRoundKey XORs a 16-byte round key into the state. It is the only step that depends on the key, and XOR undoes itself, so decryption removes it by adding the same round key again.',
    blocks: [
      'SubBytes, ShiftRows and MixColumns are published and fixed. Anyone can apply them, and anyone can undo them. Where does the secret enter?',
      { topic: 'aes-addroundkey', frame: 0, caption: 'Round 1: the state after MixColumns and round key 1, 6a406d510f6d1f3879086d154b385f23, made from words 4 to 7 of the key schedule.' },
      { topic: 'aes-addroundkey', frame: 1, caption: 'Column 0: 255ee352 ⊕ 6a406d51 = 4f1e8e03, byte by byte. There is no carry between bytes or bits.' },
      { predict: { q: 'A round key byte is 00. What does AddRoundKey do to the state byte it meets?', options: ['Leaves it unchanged', 'Sets it to 00', 'Flips all its bits', 'Swaps its halves'], answer: 0, explain: 'b ⊕ 00 = b. Each 1 bit of the key flips the matching state bit; each 0 bit leaves it alone. A byte that comes out 00, as row 1, column 1 does here (6d ⊕ 6d), says the state and the key agreed there.' } },
      { topic: 'aes-addroundkey', frame: 6, caption: 'XOR is its own inverse: 00 ⊕ 6d = 6d. Decryption adds the same round key again to remove it.' },
      { h: 'Recap' },
      { list: ['AddRoundKey: state ⊕ round key, byte by byte.', 'It is the only keyed step; it comes first (round 0) and last, so no unkeyed step can simply be peeled off by an attacker.', 'Adding the same round key again undoes it.'] },
      X('ae-x-ark'),
    ],
  });

  C.lesson({
    id: 'ae-keys', chapter: 'ae-round', title: 'The key expansion and the g-function', minutes: 9,
    summary: 'The key is cut into 32-bit words, and each new word is the word four back XOR the previous word. Every fourth word first sends the previous word through g: rotate one byte, substitute each byte with the S-box, and XOR a round constant into the first byte.',
    blocks: [
      'AES-128 needs eleven round keys of 16 bytes from one 16-byte key. Repeating the key would make the rounds alike, and a cipher whose rounds are all alike can be attacked by sliding one encryption against another. How are the round keys made different, cheaply?',
      { topic: 'aes-keyexp', frame: 0, caption: 'The key “ochre-river-2026” is the four words w0 = 6f636872, w1 = 652d7269, w2 = 7665722d and w3 = 32303236: round key 0.' },
      { topic: 'aes-keyexp', frame: 1, caption: 'w4 needs g(w3). RotWord moves each byte up one place: 32303236 becomes 30323632.' },
      { topic: 'aes-keyexp', frame: 2, caption: 'SubWord puts each byte through the S-box: 30323632 becomes 04230523.' },
      { topic: 'aes-keyexp', frame: 3, caption: 'XOR the round constant Rcon(1) = 01 into the first byte: g(w3) = 05230523.' },
      { topic: 'aes-keyexp', frame: 4, caption: 'w4 = w0 ⊕ g(w3) = 6f636872 ⊕ 05230523 = 6a406d51.' },
      { predict: { q: 'w5 is made next. Which words does it use?', options: ['w1 and g(w4)', 'w1 and w4', 'w4 and w3', 'w0 and w4'], answer: 1, explain: 'Only every fourth word goes through g. w5 = w1 ⊕ w4 = 652d7269 ⊕ 6a406d51 = 0f6d1f38.' } },
      { topic: 'aes-keyexp', frame: 5, caption: 'w5 = w1 ⊕ w4 = 0f6d1f38, a plain XOR. w6 and w7 follow the same way, and w4 … w7 are round key 1.' },
      { def: 'Round constants', text: 'Rcon(i) = 02^(i−1) in GF(2⁸): 01, 02, 04, 08, 10, 20, 40, 80, then 1b and 36, where doubling 80 overflows and is reduced. They make each round\'s g different, so no two round keys are built alike.' },
      { topic: 'aes-keyexp', frame: 16, caption: 'Round key 10 uses Rcon(10) = 36 and comes out de5309caad0c3c6be9f9070de926e734. Every round key depends on every key byte.' },
      { h: 'Longer keys' },
      { topic: 'aes-keysched-wide', frame: 2, caption: 'A 256-bit key is 8 words, and the schedule works in steps of 8. AES-256 adds a SubWord without rotation or constant halfway through each step: w12 = w4 ⊕ SubWord(w11).' },
      { topic: 'aes-keysched-wide', frame: 11, caption: 'AES-128 makes 44 words with 10 g-steps; AES-192 52 words with 8; AES-256 60 words with 7 g-steps and 6 extra SubWords.' },
      { h: 'Recap' },
      { list: ['wᵢ = wᵢ₋₄ ⊕ wᵢ₋₁, except every fourth word: wᵢ = wᵢ₋₄ ⊕ g(wᵢ₋₁).', 'g = RotWord, then SubWord, then XOR Rcon into the first byte.', 'Rcon(i) = 02^(i−1) in GF(2⁸): 01, 02, … 80, 1b, 36.', 'For AES-256 the step is 8 words, with an extra SubWord in the middle of each.'] },
      X('ae-x-rcon'), X('ae-x-g'), X('ae-x-w4'), X('ae-x-code-g'), X('ae-x-rk1'), X('ae-x-wide'),
    ],
  });

  // =========================================================================================================
  // Chapter 3: the whole cipher
  // =========================================================================================================
  C.lesson({
    id: 'ae-enc', chapter: 'ae-whole', title: 'One encryption, round by round', minutes: 8,
    summary: 'Follow one byte through all four steps of a round, then watch the rest of the rounds go by. The last round has no MixColumns. The bench reproduces the standard\'s own test vector.',
    blocks: [
      'The steps are clear one at a time. What does one byte go through on its way from plaintext to ciphertext, and why is the last round different?',
      { topic: 'aes-encrypt', frame: 1, caption: 'Round 0 XORs round key 0 into the plaintext. Byte 5, lit: 72 ⊕ 2d = 5f.' },
      { topic: 'aes-encrypt', frame: 2, caption: 'SubBytes: byte 5 is 5f, its inverse in GF(2⁸) is 17, and the affine map gives cf.' },
      { topic: 'aes-encrypt', frame: 3, caption: 'ShiftRows: byte 5 is in row 1, so it moves from column 1 to column 0.' },
      { topic: 'aes-encrypt', frame: 4, caption: 'MixColumns: column 0, 26 cf 6f 4c, becomes 25 5e e3 52. Row 1 is 26 ⊕ 85 ⊕ b1 ⊕ 4c = 5e, where 85 = 02·cf.' },
      { topic: 'aes-encrypt', frame: 5, caption: 'AddRoundKey with round key 1: in row 1, column 0, 5e ⊕ 40 = 1e. The state after round 1 is 4f1e8e03280022327f769183e00fd8b5.' },
      { predict: { q: 'Why does the last round leave out MixColumns?', options: ['To save time', 'It would add nothing: a final MixColumns can be moved past the last key addition and undone by anyone', 'It would make decryption impossible', 'The standard ran out of round keys'], answer: 1, explain: 'MixColumns is linear, so M(s) ⊕ k = M(s ⊕ M⁻¹(k)): a last MixColumns could be peeled off by anyone, adding no security. Dropping it also makes the inverse cipher line up neatly with the forward one.' } },
      { topic: 'aes-encrypt', frame: 19, caption: 'Round 10: SubBytes, ShiftRows and AddRoundKey only. In row 1, column 0, 1e ⊕ 53 = 4d.' },
      { topic: 'aes-encrypt', frame: 20, caption: 'The ciphertext of “Lanterns at dusk” under “ochre-river-2026” is dd4d23f3bf51ab4561eae6a9f830b787.' },
      { bench: 'cipher', state: { algo: 'aes128', mode: 'ecb', view: 'rounds' }, text: 'Run AES-128 on your own block and key, with every round open. Try the standard\'s test vector: key 000102…0f and plaintext 00112233…ff.' },
      { h: 'Recap' },
      { list: ['A round: SubBytes, ShiftRows, MixColumns, AddRoundKey.', 'Round 0 is only AddRoundKey; the last round has no MixColumns.', 'A byte changes column in ShiftRows and spreads over its column in MixColumns.'] },
      X('ae-x-round1'), X('ae-x-fips'),
    ],
  });

  C.lesson({
    id: 'ae-dec', chapter: 'ae-whole', title: 'Decryption: the inverse steps', minutes: 7,
    summary: 'Decryption undoes the rounds in reverse order: InvShiftRows turns the rows right, InvSubBytes uses the inverse table, AddRoundKey is its own inverse, and InvMixColumns multiplies by the inverse matrix of 0e, 0b, 0d and 09.',
    blocks: [
      'Unlike DES, AES is not a Feistel network: its rounds are not their own inverses. Every step must be undone separately. Which steps are easy to undo, and which cost more?',
      { topic: 'aes-decrypt', frame: 1, caption: 'Start by XORing the last round key into the ciphertext: that strips the key added at the end of round 10.' },
      { topic: 'aes-decrypt', frame: 2, caption: 'InvShiftRows turns row r right by r places, putting every byte back in its column.' },
      { topic: 'aes-decrypt', frame: 3, caption: 'InvSubBytes: in row 1, column 2, S⁻¹(5d) = 8d. The state d5ffe0c3… is exactly the state after round 9 of the encryption.' },
      { predict: { q: 'InvMixColumns uses the matrix with rows 0e 0b 0d 09 (turned). Why is it slower than MixColumns?', options: ['It has more rows', 'Its coefficients are larger, so each product needs more xtimes and XORs', 'It needs the key', 'It has to be done twice'], answer: 1, explain: 'Multiplying by 02 or 03 is one xtime and at most one XOR. Multiplying by 0e = 08 ⊕ 04 ⊕ 02 needs three xtimes and two XORs. This is one reason fast AES software precomputes tables for decryption too.' } },
      { topic: 'aes-decrypt', frame: 5, caption: 'InvMixColumns of column 2: d3 78 ae 2d becomes 02 f3 2f f6.' },
      { topic: 'aes-decrypt', frame: 20, caption: 'After all ten rounds undone, “Lanterns at dusk” is back: 4c616e7465726e73206174206475736b.' },
      { h: 'Recap' },
      { list: ['Undo the rounds last to first, using the round keys in reverse order.', 'InvShiftRows turns rows right; InvSubBytes uses S⁻¹; AddRoundKey is its own inverse.', 'InvMixColumns multiplies by the inverse matrix, 0e 0b 0d 09, which is costlier than 02 03 01 01.'] },
      X('ae-x-dec-order'), X('ae-x-invmix'),
    ],
  });

  C.lesson({
    id: 'ae-aval', chapter: 'ae-whole', title: 'The avalanche across the state', minutes: 6,
    summary: 'Flip one plaintext bit: after round 1 one column differs, after round 2 all sixteen bytes differ, and from then on about half of the 128 bits differ, as for two unrelated blocks.',
    blocks: [
      'A good block cipher should make two plaintexts that differ in one bit look unrelated after encryption. How many rounds does AES need before nothing of the flipped bit is visible?',
      { topic: 'aes-avalanche', frame: 1, caption: 'Byte 9, bit 2: 61 against 65. After round 0 the states still differ in one bit; the same key is XORed into both.' },
      { topic: 'aes-avalanche', frame: 2, caption: 'Round 1: SubBytes turns 04 and 00 into f2 and 63, which differ in 3 bits. MixColumns spreads that over its column: 4 of 16 bytes differ.' },
      { predict: { q: 'After round 2, how many of the 16 bytes differ?', options: ['4', '8', '12', '16'], answer: 3, explain: 'ShiftRows of round 2 sends the four differing bytes to four different columns, and MixColumns fills each column: all 16 bytes differ (72 bits here).' } },
      { topic: 'aes-avalanche', frame: 3, caption: 'Round 2: 16 of 16 bytes differ, 72 bits in all.' },
      { topic: 'aes-avalanche', frame: 11, caption: 'After round 10 the ciphertexts differ in 71 of 128 bits. From round 2 on the count stays near 64, the average for two random blocks.' },
      { bench: 'cipher', state: { algo: 'aes128', mode: 'ecb', view: 'aval' }, text: 'Flip any bit of the plaintext or the key, and watch the difference spread round by round.' },
      { h: 'Recap' },
      { list: ['A one-bit difference fills one column after round 1 and the whole state after round 2.', 'After that about 64 of 128 bits differ, as for unrelated blocks.', 'Full diffusion in two rounds is why ten rounds leave a wide safety margin.'] },
      X('ae-x-aval'), X('ae-x-aval2'),
    ],
  });

  // =========================================================================================================
  // Chapter 4: Mini-AES and real implementations
  // =========================================================================================================
  C.lesson({
    id: 'ae-mini', chapter: 'ae-practice', title: 'Mini-AES by hand', minutes: 10,
    summary: 'Mini-AES keeps every step of AES on a 16-bit block: four nibbles in a 2×2 state, a 4-bit S-box, a row swap, a 2×2 matrix over GF(2⁴), and a key schedule with the same shape. Two rounds fit on one page.',
    blocks: [
      'A full AES encryption by hand takes hours and is easy to get wrong. To see every step at once, shrink every part. What survives when the block is only 16 bits?',
      { table: [['', 'AES-128', 'Mini-AES'], ['Block', '16 bytes, 4×4', '4 nibbles, 2×2'], ['S-box', '8 bits, from GF(2⁸)', '4 bits, a fixed table'], ['Rows', 'ShiftRows: row r turns r places', 'ShiftRow: the bottom row swaps'], ['Columns', '4×4 matrix over GF(2⁸)', '[3 2 / 2 3] over GF(2⁴), modulo x⁴ + x + 1'], ['Rounds', '10', '2, the last without MixColumn']], caption: 'Every step has its small twin.' },
      { topic: 'aes-mini', frame: 1, caption: 'The key c3f0 is the nibbles w0 … w3 = c, 3, f, 0. w4 = w0 ⊕ NibbleSub(w3) ⊕ rcon(1) = 1100 ⊕ 1110 ⊕ 0001 = 0011.' },
      { topic: 'aes-mini', frame: 2, caption: 'w5, w6 and w7 are plain XORs: K1 = 30ff. K2 = 6696 follows the same way with rcon(2) = 2.' },
      { topic: 'aes-mini', frame: 6, caption: 'The plaintext 9c63 fills the state column by column: [9 6 / c 3]. Adding K0 = c3f0 gives [5 9 / f 3].' },
      { topic: 'aes-mini', frame: 8, caption: 'After NibbleSub, ShiftRow swaps the two nibbles of the bottom row, 7 and 1: [f a / 1 7].' },
      { predict: { q: 'MixColumn on column 0, (f, 1): the top output is 3·f ⊕ 2·1 in GF(2⁴). 3·f = 2. What is the top output?', options: ['0', '2', 'e', 'd'], answer: 0, explain: '2·1 = 2, and 2 ⊕ 2 = 0. The bottom one is 2·f ⊕ 3·1 = d ⊕ 3 = e.' } },
      { topic: 'aes-mini', frame: 9, caption: 'MixColumn: column 0 becomes 0, e. The state is [0 3 / e e].' },
      { topic: 'aes-mini', frame: 14, caption: 'Round 2 has no MixColumn. After adding K2 = 6696 the ciphertext is 72c6.' },
      { tip: 'Decrypting is the same shape backwards: add K2, ShiftRow and the inverse S-box, add K1, MixColumn (the matrix [3 2 / 2 3] is its own inverse over GF(2⁴)), ShiftRow and the inverse S-box, add K0.' },
      { bench: 'cipher', state: { algo: 'miniaes', mode: 'ecb', view: 'rounds', toy: true }, text: 'Check your hand calculations: Mini-AES beside AES-128, round by round.' },
      { h: 'Recap' },
      { list: ['Mini-AES: 16-bit block and key, 2 rounds, every AES step in miniature.', 'Key schedule: w4 = w0 ⊕ NibbleSub(w3) ⊕ rcon(1), then plain XORs; then w8 with rcon(2).', 'With only 2¹⁶ keys it is a toy: a computer tries them all at once.'] },
      X('ae-x-mini-key'), X('ae-x-mini-round'), X('ae-x-mini-enc'), X('ae-x-mini-dec'), X('ae-x-mini-brute'),
      { challenge: 'ae-ctf-mini-note' },
    ],
  });

  C.lesson({
    id: 'ae-ttable', chapter: 'ae-practice', title: 'T-tables, cache timing, and the fixes', minutes: 8,
    summary: 'Fast software folds SubBytes, ShiftRows and MixColumns into four table lookups per column. The tables are indexed by key-dependent bytes, so which cache lines are touched gives part of the key away. Bitsliced code and AES instructions look nothing up.',
    blocks: [
      'Done literally, a round costs 16 S-box lookups and dozens of field operations. Fast software does far less. How, and what does the shortcut cost in security?',
      { topic: 'aes-ttable', frame: 1, caption: 'Te0[x] is the column MixColumns would make from S(x) in row 0: (02·S(x), S(x), S(x), 03·S(x)). For x = 23, S(x) = 26, so Te0[23] = 4c26266a.' },
      { topic: 'aes-ttable', frame: 3, caption: 'Four lookups and four XORs with the round key give column 0 after round 1, 4f1e8e03: exactly what the byte-by-byte steps give.' },
      { predict: { q: 'Each table is 1 KiB, read in 64-byte cache lines of 16 entries. Which part of the index x decides the line?', options: ['The low four bits', 'The top four bits', 'All eight bits', 'None: the cache is the same for all'], answer: 1, explain: 'Entry x sits at byte 4x, so its line is 4x / 64 = x >> 4: the top nibble. In round 1, x = p ⊕ k, so the line gives away the top nibble of p ⊕ k.' } },
      { topic: 'aes-ttable', frame: 6, caption: 'A program sharing the cache sees which lines were touched. Knowing the plaintext, it XORs it out: half of every key byte leaks from round 1 alone.' },
      { warn: 'This is a real attack, not a curiosity: table-based AES has been broken across processes and virtual machines on one physical host. Never run table-based AES where untrusted code shares the cache.' },
      { topic: 'aes-ttable', frame: 7, caption: 'The fixes: bitsliced AES computes the S-box with logic on many blocks at once; processors with AES instructions do a round in one instruction. No memory address depends on the key, and the ciphertext is the same.' },
      { h: 'Recap' },
      { list: ['T-tables merge SubBytes, ShiftRows and MixColumns into 4 lookups and XORs per column.', 'Lookups indexed by p ⊕ k touch cache lines that another program can measure: the top nibble of each key byte leaks.', 'Use constant-time AES: hardware instructions or bitslicing.'] },
      X('ae-x-ttable'), X('ae-x-cacheline'), X('ae-x-impl-fix'),
    ],
  });

  C.lesson({
    id: 'ae-sec', chapter: 'ae-practice', title: 'Key length and exhaustive search', minutes: 6,
    summary: 'With no shortcut known, the attacker must try keys: 2¹²⁷ on average for AES-128. Even a million machines at 10¹² keys a second need trillions of years. Grover\'s quantum search halves the exponent, which is why long-lived secrets use 256-bit keys.',
    blocks: [
      'Twenty-five years of cryptanalysis have found no practical attack on full AES. So its strength is the work of trying keys. How long is that, really, and what could change it?',
      { topic: 'aes-security', frame: 1, caption: 'The attacker has 10⁶ machines at 10¹² keys a second. DES, 56 bits: 2⁵⁵ guesses on average take 0.036 seconds.' },
      { predict: { q: 'Each extra key bit doubles the work. Going from 56 to 128 bits multiplies the time by about…', options: ['2⁷²', '72', '2.3', '128 / 56'], answer: 0, explain: '128 − 56 = 72 extra bits, so 2⁷² ≈ 4.7 × 10²¹ times longer.' } },
      { topic: 'aes-security', frame: 5, caption: 'AES-128: 2¹²⁷ guesses take 5.4 × 10¹² years, longer than the universe has existed.' },
      { topic: 'aes-security', frame: 8, caption: 'Grover\'s search needs about 2^(n/2) steps, one after another: AES-128 drops to about 2⁶⁴, AES-256 keeps 2¹²⁸.' },
      { topic: 'aes-security', frame: 9, caption: 'The best known attacks on the full cipher, bicliques, cost about 2^126.1 for AES-128: a few bits under exhaustive search. The key length is the security.' },
      { warn: 'A 256-bit key derived from a 6-digit PIN has only a million possibilities. The cipher\'s key length is an upper bound: the real strength is how the key was made.' },
      { h: 'Recap' },
      { list: ['Exhaustive search costs 2^(n−1) trials on average.', 'AES-128 is far out of reach of classical search; AES-256 also resists Grover.', 'A key is only as strong as the secret it came from.'] },
      X('ae-x-grover'), X('ae-x-misuse-key'),
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
