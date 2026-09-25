// Part 5, AES: the exercises. The lessons are in 050-aes.js; the challenges, the tour and the course in 052-aes-ctf.js.
// Keys, plaintexts and columns are our own (“violet-ferry-031”, “Moss on the quay”, …) except where a standard's
// published vector is named; every answer was worked out with S.AES, S.gf256 and S.MiniAES, and the code exercises are
// checked against the engines and the FIPS 197 example values.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('ae-x-layout')) return;
  const ex = (o) => C.exercise(o);
  const h2 = (v) => v.toString(16).padStart(2, '0');
  const hex = (a) => Array.from(a, h2).join('');
  const bytesOf = (t) => String(t).replace(/\s+/g, '').match(/../g).map((x) => parseInt(x, 16));
  const R = ['r0', 'r1', 'r2', 'r3'], CC = ['c0', 'c1', 'c2', 'c3'];
  /** a state (32 hex digits in column order) as a table block, row by row */
  const rowsTable = (st, caption) => { const b = bytesOf(st); return { table: [['', 'column 0', 'column 1', 'column 2', 'column 3']].concat([0, 1, 2, 3].map((r) => ['row ' + r].concat([0, 1, 2, 3].map((c) => '`' + h2(b[r + 4 * c]) + '`')))), caption }; };
  /** the answer to a state table: every cell not given */
  const stateAns = (st, give, patch) => { const b = bytesOf(st), g = new Set(give || []), o = {}; for (let i = 0; i < 16; i++) if (!g.has(i)) o[R[i % 4] + '|' + CC[i >> 2]] = h2(b[i]); return Object.assign(o, patch || {}); };
  const cell = (i) => R[i % 4] + '|' + CC[i >> 2];
  const SBOX_HEX = hex(S.gf256.SBOX);
  // the S-box as 16 lines of 16 bytes, so the code editor needs no sideways scrolling
  const sboxLine = 'const SBOX = (\n' + SBOX_HEX.match(/.{32}/g).map((r) => '  "' + r + '"').join(' +\n') + '\n).match(/../g)\n  .map((h) => parseInt(h, 16));\n\n';

  // ---- the values of these exercises, from the engines ----------------------------------------------------------
  const KEY = 'violet-ferry-031', PT = 'Moss on the quay';
  const enc = (t) => new TextEncoder().encode(t);
  const run = S.AES.encrypt(enc(PT), enc(KEY));
  const R0 = hex(run.rounds[0].end), R1 = run.rounds[1];
  const SUB1 = hex(R1.sub), SHIFT1 = hex(R1.shift), MIX1 = hex(R1.mix), RK1 = hex(R1.key), END1 = hex(R1.end);

  // =========================================================================================================
  // Chapter 1: the state and the S-box
  // =========================================================================================================
  ex({
    id: 'ae-x-layout', chapter: 'ae-state', title: 'Where does a byte go?', level: 1, kind: 'number',
    text: ['The 16 input bytes are numbered 0 to 15 and written into the 4×4 state. Which byte number ends up in row 3, column 2?'],
    answer: 11,
    hints: ['The state is filled one column at a time, top to bottom.', 'Byte i sits in row i mod 4 and column ⌊i/4⌋. So column 2 holds bytes 8, 9, 10 and 11.', 'Row 3 of column 2 is byte 4·2 + 3 = 11.'],
    solution: '11', wrong: ['14', '13', '7'],
    whyNot: 'Byte i is at row i mod 4, column ⌊i/4⌋: the grid is filled column by column, not row by row.',
  });
  ex({
    id: 'ae-x-state-load', chapter: 'ae-state', title: 'Load a block into the state', level: 1, kind: 'table', table: 'state',
    text: ['The plaintext “Copper kettle 42” is the 16 bytes 43 6f 70 70 65 72 20 6b 65 74 74 6c 65 20 34 32. Write it into the state.'],
    state: '436f70706572206b6574746c65203432',
    hints: ['Fill column 0 first, from the top: 43, 6f, 70, 70.', 'Column 1 is 65 72 20 6b, column 2 is 65 74 74 6c, column 3 is 65 20 34 32.', 'Row 0 reads 43 65 65 65; row 1 reads 6f 72 74 20; row 2 reads 70 20 74 34; row 3 reads 70 6b 6c 32.'],
    solution: stateAns('436f70706572206b6574746c65203432'),
    wrong: [stateAns('436565656f72742070207434706b6c32')],
  });
  ex({
    id: 'ae-x-sbox-look', chapter: 'ae-state', title: 'Look up the S-box', level: 1, kind: 'hex',
    text: ['Use the table to find S(4b).', { topic: 'aes-sbox', frame: 5, caption: 'The full S-box: the row is the first hex digit of x, the column the second.' }],
    answer: 'b3',
    hints: ['The row is the high hex digit, the column the low one.', 'Go to row 4, column b.', 'S(4b) = b3. (Row b, column 4 holds S(b4) = 8d: a different entry.)'],
    solution: 'b3', wrong: ['8d', '4b', 'b4'],
    whyNot: 'Read row 4 (the first digit), then column b (the second).',
  });
  ex({
    id: 'ae-x-xtime', chapter: 'ae-state', title: 'Multiply by 03', level: 1, kind: 'hex',
    text: ['Compute 03 · b6 in GF(2⁸), the field AES uses (modulus x⁸ + x⁴ + x³ + x + 1).'],
    answer: 'c1',
    hints: ['03 · b = 02 · b ⊕ b, and 02 · b is xtime(b).', 'b6 = 10110110 has its top bit set, so xtime(b6) = 01101100 ⊕ 00011011 = 77.', '03 · b6 = 77 ⊕ b6 = c1.'],
    solution: 'c1', wrong: ['da', '77', '22'],
    whyNot: 'When the top bit falls off in xtime, XOR in 1b; then add b6 once more.',
  });
  ex({
    id: 'ae-x-inv02', chapter: 'ae-state', title: 'The inverse of 02', level: 2, kind: 'hex',
    text: ['Find the inverse of 02 in GF(2⁸), the byte y with 02 · y = 01.'],
    answer: '8d',
    hints: ['02 · y is xtime(y). For the result to be 01, a bit must fall off the top (otherwise xtime gives an even byte), so y has its top bit set.', 'Then xtime(y) = (y << 1 mod 256) ⊕ 1b = 01, so (y << 1) mod 256 = 1a, and y = 0d with the top bit set back.', 'y = 8d: xtime(8d) = 1a ⊕ 1b = 01.'],
    solution: '8d', wrong: ['80', '0d', '1b'],
    whyNot: 'Check your answer: shifting it left by one and XORing 1b on overflow must give 01.',
  });
  ex({
    id: 'ae-x-affine', chapter: 'ae-state', title: 'The affine step by hand', level: 3, kind: 'hex',
    text: ['The inverse of 9a in GF(2⁸) is 9f. Apply the S-box\'s affine map to 9f to get S(9a).', { math: 'bᵢ′ = bᵢ ⊕ bᵢ₊₄ ⊕ bᵢ₊₅ ⊕ bᵢ₊₆ ⊕ bᵢ₊₇ ⊕ cᵢ   (indices mod 8, c = 63 = 01100011)' }],
    answer: 'b8',
    hints: ['Write the bits: 9f = 10011111, so b₇ … b₀ = 1 0 0 1 1 1 1 1. The constant 63 has c₀, c₁, c₅, c₆ = 1.', 'b₀′ = b₀ ⊕ b₄ ⊕ b₅ ⊕ b₆ ⊕ b₇ ⊕ c₀ = 1 ⊕ 1 ⊕ 0 ⊕ 0 ⊕ 1 ⊕ 1 = 0, and b₃′ = b₃ ⊕ b₇ ⊕ b₀ ⊕ b₁ ⊕ b₂ ⊕ c₃ = 1 ⊕ 1 ⊕ 1 ⊕ 1 ⊕ 1 ⊕ 0 = 1.', 'The eight bits b₇′ … b₀′ are 1 0 1 1 1 0 0 0, so S(9a) = b8.'],
    solution: 'b8', wrong: ['db', '9f', '63'],
    whyNot: 'Work bit by bit with the indices taken mod 8, and do not forget the constant 63.',
  });
  ex({
    id: 'ae-x-subbytes-state', chapter: 'ae-state', title: 'SubBytes on a state', level: 2, kind: 'table', table: 'state',
    text: ['This is the state entering round 1 when “Moss on the quay” is encrypted under the key “violet-ferry-031”. Columns 0 and 2 after SubBytes are filled in; fill in columns 1 and 3, using the S-box.', rowsTable(R0, 'The state before SubBytes.'), { topic: 'aes-sbox', frame: 5, caption: 'The S-box.' }],
    state: SUB1, give: [0, 1, 2, 3, 8, 9, 10, 11],
    hints: ['Each byte is looked up on its own: the cell keeps its place.', 'Column 1 before is 45 1b 43 46: S(45) = 6e, S(1b) = af.', 'Column 1 becomes 6e af 1a 5a, and column 3 (5c 45 52 48) becomes 4a 6e 00 52.'],
    solution: stateAns(SUB1, [0, 1, 2, 3, 8, 9, 10, 11]),
    wrong: [stateAns(SUB1, [0, 1, 2, 3, 8, 9, 10, 11], { [cell(4)]: '45' }), stateAns(SUB1, [0, 1, 2, 3, 8, 9, 10, 11], { [cell(15)]: '42' })],
  });
  ex({
    id: 'ae-x-code-xtime', chapter: 'ae-state', title: 'Write xtime', level: 1, kind: 'code', fn: 'xtime', radix: 16, params: ['a'],
    text: ['Write `xtime(a)`: multiply the byte `a` (a Number from 0 to 255) by 02 in GF(2⁸) and return the byte. The tests include the example values of FIPS 197, section 4.2.1: xtime(57) = ae, xtime(ae) = 47, xtime(47) = 8e, xtime(8e) = 07.'],
    start: 'function xtime(a) {\n  \n}\n',
    ref: (a) => S.gf256.xtime(a),
    cases: [[0x57], [0xae], [0x47], [0x8e], [0x00], [0x80], [0xff], [0x01], [0xb6], [0x7f], [0xc9]],
    hints: ['Shift left by one bit; a byte must stay below 256.', 'If bit 7 of a was 1, the shifted value overflowed: XOR 0x1b into the low 8 bits.', 'function xtime(a) {\n  return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;\n}'],
    solution: 'function xtime(a) {\n  return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;\n}\n',
    wrong: ['function xtime(a) {\n  return (a << 1) & 0xff;\n}\n', 'function xtime(a) {\n  return (a << 1) ^ (a & 0x80 ? 0x1b : 0);\n}\n'],
  });

  // =========================================================================================================
  // Chapter 2: the round steps and the key schedule
  // =========================================================================================================
  ex({
    id: 'ae-x-shiftrows', chapter: 'ae-round', title: 'ShiftRows by hand', level: 1, kind: 'table', table: 'state',
    text: ['Apply ShiftRows to this state, the one SubBytes gave in round 1 of “Moss on the quay”.', rowsTable(SUB1, 'The state before ShiftRows.')],
    state: SHIFT1,
    hints: ['Row r turns r places to the left; row 0 stays.', 'Row 1, 6f af a2 6e, becomes af a2 6e 6f.', 'Rows after: e2 6e 82 4a / af a2 6e 6f / f0 00 9c 1a / 52 c0 5a cb.'],
    solution: stateAns(SHIFT1),
    wrong: [stateAns(SHIFT1, null, { [cell(1)]: '6e', [cell(5)]: '6f' }), stateAns(SUB1)],
  });
  ex({
    id: 'ae-x-mul', chapter: 'ae-round', title: 'A product in GF(2⁸)', level: 2, kind: 'hex',
    text: ['InvMixColumns multiplies by 0b. Compute 0b · 9e in GF(2⁸).'],
    answer: '25',
    hints: ['0b = 08 ⊕ 02 ⊕ 01, so 0b · 9e = 08·9e ⊕ 02·9e ⊕ 9e. Get 02·9e, 04·9e and 08·9e by repeated xtime.', 'xtime(9e) = 3c ⊕ 1b = 27; xtime(27) = 4e; xtime(4e) = 9c.', '9c ⊕ 27 ⊕ 9e = 25.'],
    solution: '25', wrong: ['9c', '3e', 'b9'],
    whyNot: 'Split 0b into powers of two (08 ⊕ 02 ⊕ 01), use xtime for each, and XOR the three products.',
  });
  ex({
    id: 'ae-x-mixcol', chapter: 'ae-round', title: 'MixColumns on one column', level: 2, kind: 'hex',
    text: ['Apply MixColumns to the column 5a 13 c4 e8 (top first). Give the four output bytes, top first.', { math: 'd₀ = 02·b₀ ⊕ 03·b₁ ⊕ b₂ ⊕ b₃\nd₁ = b₀ ⊕ 02·b₁ ⊕ 03·b₂ ⊕ b₃\nd₂ = b₀ ⊕ b₁ ⊕ 02·b₂ ⊕ 03·b₃\nd₃ = 03·b₀ ⊕ b₁ ⊕ b₂ ⊕ 02·b₃' }],
    answer: 'adc3f9f2',
    hints: ['You need 02· and 03· of every byte: 02·5a = b4, 02·13 = 26, 02·c4 = 93, 02·e8 = cb; add the byte itself for 03·.', 'd₀ = b4 ⊕ 35 ⊕ c4 ⊕ e8 = ad and d₁ = 5a ⊕ 26 ⊕ 57 ⊕ e8 = c3.', 'd₂ = 5a ⊕ 13 ⊕ 93 ⊕ 23 = f9 and d₃ = ee ⊕ 13 ⊕ c4 ⊕ cb = f2: the column is ad c3 f9 f2.'],
    solution: 'ad c3 f9 f2', wrong: ['adc3f9f3', '5a13c4e8', 'f2f9c3ad'],
    whyNot: 'Work each row of the matrix with xtime for 02·, xtime ⊕ the byte for 03·, and XOR the four terms.',
  });
  ex({
    id: 'ae-x-code-mixcol', chapter: 'ae-round', title: 'Write MixColumns for one column', level: 2, kind: 'code', fn: 'mixColumn', radix: 16, params: ['col'],
    text: ['Write `mixColumn(col)`: `col` is an array of four bytes (Numbers), top first; return the array of four bytes MixColumns makes. The tests include the first column of round 1 in FIPS 197, appendix B: d4 bf 5d 30 becomes 04 66 81 e5.'],
    start: 'function mixColumn(col) {\n  \n}\n',
    ref: (col) => S.AES.mixColumn(col).out,
    cases: [[[0xd4, 0xbf, 0x5d, 0x30]], [[0x5a, 0x13, 0xc4, 0xe8]], [[0xc9, 0xe2, 0x18, 0x7a]], [[0, 0, 0, 0]], [[1, 1, 1, 1]], [[0xff, 0x00, 0x80, 0x7f]], [[0x26, 0xcf, 0x6f, 0x4c]]],
    hints: ['Write xtime first: `const x2 = (b) => ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff;` and 03·b = x2(b) ^ b.', 'Row 0 is x2(a) ^ x3(b) ^ c ^ d; each next row is the same pattern moved one place to the right.', 'function mixColumn(col) {\n  const x2 = (b) => ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff;\n  const x3 = (b) => x2(b) ^ b;\n  const [a, b, c, d] = col;\n  return [x2(a) ^ x3(b) ^ c ^ d, a ^ x2(b) ^ x3(c) ^ d, a ^ b ^ x2(c) ^ x3(d), x3(a) ^ b ^ c ^ x2(d)];\n}'],
    solution: 'function mixColumn(col) {\n  const x2 = (b) => ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff;\n  const x3 = (b) => x2(b) ^ b;\n  const [a, b, c, d] = col;\n  return [x2(a) ^ x3(b) ^ c ^ d, a ^ x2(b) ^ x3(c) ^ d, a ^ b ^ x2(c) ^ x3(d), x3(a) ^ b ^ c ^ x2(d)];\n}\n',
    wrong: ['function mixColumn(col) {\n  const x2 = (b) => (b << 1) & 0xff;\n  const x3 = (b) => x2(b) ^ b;\n  const [a, b, c, d] = col;\n  return [x2(a) ^ x3(b) ^ c ^ d, a ^ x2(b) ^ x3(c) ^ d, a ^ b ^ x2(c) ^ x3(d), x3(a) ^ b ^ c ^ x2(d)];\n}\n', 'function mixColumn(col) {\n  const x2 = (b) => ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff;\n  const x3 = (b) => x2(b) ^ b;\n  const [a, b, c, d] = col;\n  return [x2(a) ^ x3(b) ^ c ^ d, x3(a) ^ x2(b) ^ c ^ d, a ^ b ^ x2(c) ^ x3(d), a ^ b ^ x3(c) ^ x2(d)];\n}\n'],
  });
  ex({
    id: 'ae-x-ark', chapter: 'ae-round', title: 'AddRoundKey on a state', level: 1, kind: 'table', table: 'state',
    text: ['Finish round 1 of “Moss on the quay” under “violet-ferry-031”: XOR round key 1 into the state after MixColumns.', rowsTable(MIX1, 'The state after MixColumns.'), rowsTable(RK1, 'Round key 1, in the same layout.')],
    state: END1,
    hints: ['XOR each state byte with the key byte in the same cell.', 'Row 0, column 0: 97 ⊕ 73 = e4.', 'Rows after: e4 f7 18 aa / 54 2f 17 ed / e8 12 d6 93 / 72 59 70 bc.'],
    solution: stateAns(END1),
    wrong: [stateAns(END1, null, { [cell(0)]: '04' }), stateAns(MIX1)],
  });
  ex({
    id: 'ae-x-rcon', chapter: 'ae-round', title: 'The tenth round constant', level: 1, kind: 'hex',
    text: ['Rcon(i) = 02^(i−1) in GF(2⁸): Rcon(1) = 01, Rcon(2) = 02, … , Rcon(8) = 80. What is Rcon(10)?'],
    answer: '36',
    hints: ['Each constant is xtime of the one before.', 'Rcon(9) = xtime(80) = 00 ⊕ 1b = 1b, because the top bit falls off.', 'Rcon(10) = xtime(1b) = 36.'],
    solution: '36', wrong: ['200', '00', '1b'],
    whyNot: 'Keep doubling with xtime, reducing by 1b when a bit falls off the top.',
  });
  ex({
    id: 'ae-x-g', chapter: 'ae-round', title: 'The g-function for round key 1', level: 2, kind: 'hex',
    text: ['The key “violet-ferry-031” gives w3 = 2d 30 33 31. Compute g(w3) for round key 1: RotWord, SubWord, then XOR Rcon(1) = 01 into the first byte.', { topic: 'aes-sbox', frame: 5, caption: 'The S-box.' }],
    answer: '05c3c7d8',
    hints: ['RotWord moves each byte up one place: 2d 30 33 31 becomes 30 33 31 2d.', 'SubWord: S(30) = 04, S(33) = c3, S(31) = c7, S(2d) = d8.', 'XOR 01 into the first byte: g(w3) = 05 c3 c7 d8.'],
    solution: '05c3c7d8', wrong: ['04c3c7d8', '3033312d', 'd804c3c7'],
    whyNot: 'Rotate first (one byte up), then substitute each byte, then add Rcon to the first byte only.',
  });
  ex({
    id: 'ae-x-w4', chapter: 'ae-round', title: 'The first new word', level: 2, kind: 'hex',
    text: ['For the key “violet-ferry-031”, w0 = 76 69 6f 6c and g(w3) = 05 c3 c7 d8. Compute w4.'],
    answer: '73aaa8b4',
    hints: ['w4 = w0 ⊕ g(w3).', '76 ⊕ 05 = 73 and 69 ⊕ c3 = aa.', 'w4 = 73 aa a8 b4.'],
    solution: '73aaa8b4', wrong: ['76696f6c', '05c3c7d8', '73aaa8b5'],
    whyNot: 'XOR the two words byte by byte.',
  });
  ex({
    id: 'ae-x-code-g', chapter: 'ae-round', title: 'Write the g-function', level: 2, kind: 'code', fn: 'g', radix: 16, params: ['word', 'round'],
    text: ['Write `g(word, round)`: `word` is an array of four bytes, `round` is 1 to 10; return RotWord, then SubWord, then Rcon(round) XORed into the first byte. The S-box is given as `SBOX`. The first test is from FIPS 197, appendix A.1: for w3 = 09 cf 4f 3c and round 1 the result is 8b 84 eb 01.'],
    start: sboxLine + 'function g(word, round) {\n  \n}\n',
    ref: (w, r) => { const s = [w[1], w[2], w[3], w[0]].map((b) => S.gf256.SBOX[b]); s[0] ^= S.AES.RCON[r - 1]; return s; },
    cases: [[[0x09, 0xcf, 0x4f, 0x3c], 1], [[0x2d, 0x30, 0x33, 0x31], 1], [[0x32, 0x30, 0x32, 0x36], 1], [[0x00, 0x00, 0x00, 0x00], 9], [[0x5e, 0x9c, 0xc4, 0x9a], 2], [[0x12, 0x34, 0x56, 0x78], 10], [[0xff, 0x80, 0x01, 0x63], 8]],
    hints: ['Rcon(1) = 1 and each next constant is xtime of the one before; or list all ten: 01 02 04 08 10 20 40 80 1b 36.', 'RotWord is `[word[1], word[2], word[3], word[0]]`; then map each byte through SBOX.', sboxLine + 'function g(word, round) {\n  const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];\n  const s = [word[1], word[2], word[3], word[0]].map((b) => SBOX[b]);\n  s[0] ^= RCON[round - 1];\n  return s;\n}'],
    solution: sboxLine + 'function g(word, round) {\n  const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];\n  const s = [word[1], word[2], word[3], word[0]].map((b) => SBOX[b]);\n  s[0] ^= RCON[round - 1];\n  return s;\n}\n',
    wrong: [sboxLine + 'function g(word, round) {\n  const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];\n  const s = [word[3], word[0], word[1], word[2]].map((b) => SBOX[b]);\n  s[0] ^= RCON[round - 1];\n  return s;\n}\n', sboxLine + 'function g(word, round) {\n  const s = [word[1], word[2], word[3], word[0]].map((b) => SBOX[b]);\n  s[0] ^= 1 << (round - 1);\n  return s;\n}\n'],
  });
  ex({
    id: 'ae-x-rk1', chapter: 'ae-round', title: 'Round key 1 in full', level: 3, kind: 'hex',
    text: ['The key “violet-ferry-031” is 76696f6c 65742d66 65727279 2d303331, and w4 = 73aaa8b4. Finish round key 1, w4 w5 w6 w7, and give its 16 bytes.'],
    answer: RK1,
    hints: ['w5 = w1 ⊕ w4, w6 = w2 ⊕ w5, w7 = w3 ⊕ w6: plain XORs, no g.', 'w5 = 65742d66 ⊕ 73aaa8b4 = 16de85d2.', 'w6 = 65727279 ⊕ 16de85d2 = 73acf7ab and w7 = 2d303331 ⊕ 73acf7ab = 5e9cc49a. Round key 1 is 73aaa8b4 16de85d2 73acf7ab 5e9cc49a.'],
    solution: RK1, wrong: ['73aaa8b416de85d273acf7ab5e9cc49b', '73aaa8b416de85d2104ef71d3dcc9a5e', '76696f6c65742d66657272792d303331'],
    whyNot: 'Each of w5, w6, w7 is the word four back XOR the word just made.',
  });
  ex({
    id: 'ae-x-wide', chapter: 'ae-round', title: 'g in the AES-192 schedule', level: 2, kind: 'number',
    text: ['AES-192 has a 6-word key and 12 rounds. Its schedule makes words w6 … w51, and a word goes through g when its index is a multiple of 6. How many times is g used?'],
    answer: 8,
    hints: ['13 round keys of 4 words make 52 words, w0 to w51; w0 … w5 come from the key.', 'g is used for w6, w12, w18, … up to the last multiple of 6 below 52.', 'w6, w12, w18, w24, w30, w36, w42, w48: 8 times.'],
    solution: '8', wrong: ['12', '10', '9'],
    whyNot: 'List the multiples of 6 from 6 to 51.',
  });

  // =========================================================================================================
  // Chapter 3: the whole cipher
  // =========================================================================================================
  ex({
    id: 'ae-x-round1', chapter: 'ae-whole', title: 'A whole round, one column', level: 3, kind: 'table', table: 'state',
    text: ['Carry out round 1 of “Moss on the quay” under “violet-ferry-031” for column 0 of the result. The state after round 0 and round key 1 are below; columns 1 to 3 of the result are filled in.', rowsTable(R0, 'The state after round 0.'), rowsTable(RK1, 'Round key 1.'), { topic: 'aes-sbox', frame: 5, caption: 'The S-box.' }],
    state: END1, give: [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    hints: ['After ShiftRows, column 0 takes the diagonal: row 0 of column 0, row 1 of column 1, row 2 of column 2, row 3 of column 3: 3b 1b 17 48. Put them through the S-box first.', 'S(3b) = e2, S(1b) = af, S(17) = f0, S(48) = 52. MixColumns of e2 af f0 52 gives 97 fe 40 c6.', 'XOR round key 1\'s column 0, 73 aa a8 b4: the column is e4 54 e8 72.'],
    solution: stateAns(END1, [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
    wrong: [stateAns(END1, [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], { [cell(0)]: '97', [cell(1)]: 'fe', [cell(2)]: '40', [cell(3)]: 'c6' }), stateAns(END1, [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], { [cell(1)]: '55' })],
  });
  ex({
    id: 'ae-x-fips', chapter: 'ae-whole', title: 'Check against the standard', level: 1, kind: 'hex',
    text: ['FIPS 197, appendix C.1, gives a test vector for AES-128: the key 00 01 02 … 0f and the plaintext 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff. Encrypt it on the bench (AES-128, ECB, input as hex) and give the ciphertext.', { bench: 'cipher', state: { algo: 'aes128', mode: 'ecb', view: 'rounds' }, text: 'Set the key and the input to hex.' }],
    answer: '69c4e0d86a7b0430d8cdb78070b4c55a',
    hints: ['Choose AES-128 and ECB, and switch the key and the input to hex.', 'The key is 000102030405060708090a0b0c0d0e0f and the input 00112233445566778899aabbccddeeff, with no padding (one block).', 'The ciphertext is 69c4e0d86a7b0430d8cdb78070b4c55a, as printed in the standard.'],
    solution: '69c4e0d86a7b0430d8cdb78070b4c55a', wrong: ['69c4e0d86a7b0430d8cdb78070b4c55a0000000000000000', '00112233445566778899aabbccddeeff'],
    whyNot: 'Make sure the key and the input are read as hex, not as text, and that no padding block is added.',
  });
  ex({
    id: 'ae-x-dec-order', chapter: 'ae-whole', title: 'The order of the inverse steps', level: 2, kind: 'choice',
    text: ['A student writes AES-128 decryption. After XORing round key 10, which order undoes one middle round correctly?'],
    options: ['InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns', 'InvMixColumns, InvShiftRows, InvSubBytes, AddRoundKey', 'InvSubBytes, InvMixColumns, InvShiftRows, AddRoundKey', 'AddRoundKey, InvMixColumns, InvSubBytes, InvShiftRows'],
    answer: 0,
    hints: ['A round is SubBytes, ShiftRows, MixColumns, AddRoundKey. Undo the steps last first.', 'The last round has no MixColumns, so the first thing after removing round key 10 is InvShiftRows and InvSubBytes (these two commute). Then the next round key is removed, and only then InvMixColumns.', 'InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns, repeated, with a final InvShiftRows, InvSubBytes and AddRoundKey of round key 0.'],
    solution: 0, wrong: [1, 3],
    whyNot: { 1: 'InvMixColumns cannot come first: round 10 has no MixColumns, and the round key must be removed before the MixColumns it follows is undone.', 3: 'This undoes the steps in the forward order; they must be undone last first.' },
  });
  ex({
    id: 'ae-x-invmix', chapter: 'ae-whole', title: 'InvMixColumns by hand', level: 3, kind: 'hex',
    text: ['Apply InvMixColumns to the column 3b 82 d1 46 (top first). Then check your answer by applying MixColumns to it.', { math: 'd₀ = 0e·b₀ ⊕ 0b·b₁ ⊕ 0d·b₂ ⊕ 09·b₃\nd₁ = 09·b₀ ⊕ 0e·b₁ ⊕ 0b·b₂ ⊕ 0d·b₃\nd₂ = 0d·b₀ ⊕ 09·b₁ ⊕ 0e·b₂ ⊕ 0b·b₃\nd₃ = 0b·b₀ ⊕ 0d·b₁ ⊕ 09·b₂ ⊕ 0e·b₃' }],
    answer: '925c24c4',
    hints: ['For each byte, make 02·, 04· and 08· with xtime; then 09 = 08 ⊕ 01, 0b = 08 ⊕ 02 ⊕ 01, 0d = 08 ⊕ 04 ⊕ 01, 0e = 08 ⊕ 04 ⊕ 02.', 'Row 0: 0e·3b ⊕ 0b·82 ⊕ 0d·d1 ⊕ 09·46 = 59 ⊕ e1 ⊕ 6a ⊕ 40 = 92.', 'The rows give 92, 5c, 24, c4; MixColumns of 92 5c 24 c4 is 3b 82 d1 46 again.'],
    solution: '925c24c4', wrong: ['3b82d146', '925c24c5', 'c4245c92'],
    whyNot: 'Build each product from xtimes, XOR the four terms of each row, and check with MixColumns.',
  });
  ex({
    id: 'ae-x-aval', chapter: 'ae-whole', title: 'One byte after round 1', level: 1, kind: 'number',
    text: ['Two plaintexts differ in one bit. Encrypted under the same key, in how many of the 16 bytes do the two states differ after round 1?'],
    answer: 4,
    hints: ['After round 0 one byte differs. SubBytes and ShiftRows keep it to one byte (in a new place).', 'MixColumns spreads a one-byte difference over its whole column.', '4 bytes, one column.'],
    solution: '4', wrong: ['1', '16', '8'],
    whyNot: 'Follow the one differing byte through the four steps; only MixColumns spreads it.',
  });
  ex({
    id: 'ae-x-aval2', chapter: 'ae-whole', title: 'Which column?', level: 2, kind: 'number',
    text: ['“Moss on the quay” and a copy with one bit of byte 9 flipped are encrypted under the same key. After round 1, the differing bytes fill one whole column. Which column (0 to 3)?'],
    answer: 1,
    hints: ['Byte 9 sits in row 9 mod 4 = 1, column ⌊9/4⌋ = 2.', 'ShiftRows turns row 1 one place to the left: column 2 goes to column 1.', 'Column 1: bytes 4 to 7 differ after round 1.'],
    solution: '1', wrong: ['2', '3', '0'],
    whyNot: 'Find byte 9\'s row and column, then move it with ShiftRows before MixColumns spreads it.',
  });

  // =========================================================================================================
  // Chapter 4: Mini-AES and real implementations
  // =========================================================================================================
  const MK = 0x5b2e, MP = 0x7d4a, MR = S.MiniAES.encrypt(MP, MK);
  const n4 = (v) => v.toString(16);
  const X16 = [...Array(16).keys()];
  // the Mini-AES tables as monospaced lines, narrow enough for a phone
  const MINI_SBOX = { math: 'x    ' + X16.map(n4).join(' ') + '\nS(x) ' + S.MiniAES.SBOX.map(n4).join(' ') + '\nthe Mini-AES S-box' };
  const MINI_MUL = { math: 'x    ' + X16.map(n4).join(' ') + '\n2·x  ' + X16.map((v) => n4(S.MiniAES.mul(2, v))).join(' ') + '\n3·x  ' + X16.map((v) => n4(S.MiniAES.mul(3, v))).join(' ') + '\nproducts in GF(2⁴) mod x⁴ + x + 1' };
  ex({
    id: 'ae-x-mini-key', chapter: 'ae-practice', title: 'A Mini-AES round key', level: 1, kind: 'hex',
    text: ['The Mini-AES key is 5b2e: w0 … w3 = 5, b, 2, e. Compute K1 = w4 w5 w6 w7.', MINI_SBOX],
    answer: S.MiniAES.hex(S.MiniAES.join(MR.keys[1])),
    hints: ['w4 = w0 ⊕ NibbleSub(w3) ⊕ rcon(1), with rcon(1) = 1.', 'NibbleSub(e) = 0, so w4 = 5 ⊕ 0 ⊕ 1 = 4.', 'w5 = b ⊕ 4 = f, w6 = 2 ⊕ f = d, w7 = e ⊕ d = 3: K1 = 4fd3.'],
    solution: '4fd3', wrong: ['5fd3', '4f2e', '5b2e'],
    whyNot: 'w4 uses w0, the S-box of w3 and rcon(1); w5, w6 and w7 are plain XORs of the word four back and the word just made.',
  });
  ex({
    id: 'ae-x-mini-round', chapter: 'ae-practice', title: 'Mini-AES round 1', level: 2, kind: 'table', table: 'state', dim: 2, state: '4068', corner: 'state',
    text: ['Encrypt 7d4a under the key 5b2e with Mini-AES and fill in the state after round 1 (after adding K1 = 4fd3). The state is [n0 n2 / n1 n3], filled column by column.', MINI_SBOX, MINI_MUL],
    hints: ['Adding K0 = 5b2e to 7d4a gives 2664: [2 6 / 6 4]. NibbleSub gives [d b / b 2].', 'ShiftRow swaps the bottom row: [d b / 2 b]. MixColumn: column 0 (d, 2) becomes 3·d ⊕ 2·2 = 4 ⊕ 4 = 0 and 2·d ⊕ 3·2 = 9 ⊕ 6 = f; column 1 (b, b) becomes b, b.', 'Before the key: [0 b / f b]. Adding K1 = 4fd3 nibble by nibble (n0 = 0 ⊕ 4, n1 = f ⊕ f, n2 = b ⊕ d, n3 = b ⊕ 3) gives [4 6 / 0 8].'],
    solution: { 'r0|c0': '4', 'r1|c0': '0', 'r0|c1': '6', 'r1|c1': '8' },
    wrong: [{ 'r0|c0': '0', 'r1|c0': 'f', 'r0|c1': 'b', 'r1|c1': 'b' }, { 'r0|c0': '4', 'r1|c0': '6', 'r0|c1': '0', 'r1|c1': '8' }],
  });
  ex({
    id: 'ae-x-mini-enc', chapter: 'ae-practice', title: 'Mini-AES, the whole encryption', level: 3, kind: 'hex',
    text: ['Finish the encryption of 7d4a under 5b2e. After round 1 the state is [4 6 / 0 8], that is 4068; K2 = 7856. Round 2 is NibbleSub, ShiftRow and adding K2, with no MixColumn. Give the ciphertext as four hex digits.'],
    answer: '5be8',
    hints: ['NibbleSub: 4 → 2, 0 → e, 6 → b, 8 → 3, so [2 b / e 3].', 'ShiftRow swaps the bottom row: [2 b / 3 e], that is 23be.', '23be ⊕ 7856 = 5be8.'],
    solution: '5be8', wrong: ['2be3', '23be', '5b3e'],
    whyNot: 'The state is read column by column: [n0 n2 / n1 n3] is the hex n0 n1 n2 n3.',
  });
  ex({
    id: 'ae-x-mini-dec', chapter: 'ae-practice', title: 'Decrypt a Mini-AES block', level: 2, kind: 'break', target: 'plaintext', normalize: 'hex',
    text: ['Decrypt the Mini-AES block b3e1 under the key 94f7. Give the plaintext as four hex digits.', { bench: 'cipher', state: { algo: 'miniaes', mode: 'ecb', dir: 'dec', view: 'rounds', toy: true }, text: 'Check each step on the bench once you have tried it by hand.' }],
    answer: 'b507',
    hints: ['The round keys of 94f7 come first: K0 = 94f7, then K1 and K2 by the schedule. Decryption adds K2, applies ShiftRow and the inverse S-box, adds K1, applies MixColumn (its own inverse), ShiftRow and the inverse S-box, and adds K0.', 'After adding K2 the state is [c 6 / 0 5]; ShiftRow and the inverse S-box give [b a / c e]; adding K1 gives [b 1 / 8 2].', 'MixColumn gives [d 7 / e 4]; ShiftRow and the inverse S-box give [2 f / 1 0]; adding K0 = 94f7 gives b507. Encrypting b507 gives b3e1 back.'],
    solution: 'b507', wrong: ['b3e1', '94f7', 'b570'],
    whyNot: 'Run the encryption steps backwards with the inverse S-box, and check by encrypting your answer.',
  });
  ex({
    id: 'ae-x-mini-brute', chapter: 'ae-practice', title: 'Every Mini-AES key', level: 3, kind: 'break', target: 'key', normalize: 'hex',
    text: ['A Mini-AES key is only 16 bits. You know two plaintext and ciphertext pairs from one key: 4869 → 9d44 and 2c20 → 9f2f. Find the key by trying all 65 536 keys in the sandbox (the sandbox lets you write the cipher, or use the bench to check a guess).', { sandbox: 'scratch' }],
    verify: (v) => { const k = parseInt(v, 16); if (!(v.length <= 4 && k >= 0)) return 'A Mini-AES key is four hex digits.'; return S.MiniAES.encrypt(0x4869, k).out === 0x9d44 && S.MiniAES.encrypt(0x2c20, k).out === 0x9f2f ? true : 'That key does not turn 4869 into 9d44 and 2c20 into 9f2f.'; },
    hints: ['Write Mini-AES encryption (key schedule, two rounds) as a function, then loop k from 0 to 65535 and keep the keys with E_k(4869) = 9d44.', 'With 2¹⁶ keys and 2¹⁶ possible outputs, about one wrong key survives the first pair by chance; the second pair removes it. Here only one key survives the first pair already.', 'The key is c61d.'],
    solution: 'c61d', wrong: ['4869', '9d44', 'c61c'],
  });
  ex({
    id: 'ae-x-ttable', chapter: 'ae-practice', title: 'A T-table entry', level: 2, kind: 'hex',
    text: ['Te0[x] is the word (02·S(x), S(x), S(x), 03·S(x)). Given S(a7) = 5c, compute Te0[a7].'],
    answer: 'b85c5ce4',
    hints: ['02·5c is xtime(5c): no bit falls off the top.', '02·5c = b8 and 03·5c = b8 ⊕ 5c = e4.', 'Te0[a7] = b8 5c 5c e4.'],
    solution: 'b85c5ce4', wrong: ['5cb8b8e4', 'b85c5c5c', 'a75c5ce4'],
    whyNot: 'Multiply S(x), not x, and keep the order 02·, 01·, 01·, 03·.',
  });
  ex({
    id: 'ae-x-cacheline', chapter: 'ae-practice', title: 'What one cache line gives away', level: 2, kind: 'hex', value: true,
    text: ['In round 1 of table-based AES, the lookup for byte 0 reads Te0 at index x = p₀ ⊕ k₀, and the cache line it touches is x >> 4. A program sharing the cache sees that line 9 was touched, and the plaintext byte p₀ was 3c. What is the top hex digit of the key byte k₀?'],
    answer: 'a',
    hints: ['The line is the top hex digit of p₀ ⊕ k₀.', 'So top(k₀) = top(p₀) ⊕ 9 = 3 ⊕ 9.', '3 ⊕ 9 = a: the key byte starts with a. The low digit stays hidden in round 1.'],
    solution: 'a', wrong: ['9', '3', '6'],
    whyNot: 'XOR the observed line with the top digit of the plaintext byte.',
  });
  ex({
    id: 'ae-x-impl-fix', chapter: 'ae-practice', title: 'Spot the risk: AES on a shared host', level: 2, kind: 'choice',
    text: ['A design note: “Our multi-tenant cloud service encrypts customer files with AES-256 in GCM mode. To avoid a dependency we use our own table-based AES, which is fast on every processor. Each customer\'s code runs in its own virtual machine on shared hardware.” What is the problem, and the fix?'],
    options: ['AES-256 is too weak; switch to a longer key', 'Table lookups indexed by key bytes leak through the shared cache; use a constant-time implementation (AES instructions or bitsliced code)', 'GCM is the wrong mode for files; use ECB', 'Virtual machines cannot share hardware safely, so nothing can be done'],
    answer: 1,
    hints: ['The cipher, the key length and the mode are fine. Look at how AES is implemented and where it runs.', 'Other tenants share the processor\'s cache, and table-based AES makes key-dependent memory accesses.', 'The cache-timing leak: use AES that makes no key-dependent lookups, such as the processor\'s AES instructions or a bitsliced library.'],
    solution: 1, wrong: [0, 2],
    whyNot: { 0: 'Key length does not help: the leak reveals the key bits directly.', 2: 'ECB would add a second problem (equal blocks show) and leaves the leak in place.' },
  });
  ex({
    id: 'ae-x-grover', chapter: 'ae-practice', title: 'AES-256 against a quantum search', level: 1, kind: 'number',
    text: ['Grover\'s search finds an n-bit key in about 2^(n/2) steps. About how many bits of security does AES-256 keep against it? Give the exponent.'],
    answer: 128,
    hints: ['Halve the exponent.', '256 / 2.', '128: about 2¹²⁸ sequential steps, still far out of reach.'],
    solution: '128', wrong: ['256', '64', '255'],
    whyNot: 'Grover halves the exponent of exhaustive search.',
  });
  ex({
    id: 'ae-x-misuse-key', chapter: 'ae-practice', title: 'Spot the misuse: a key from a PIN', level: 2, kind: 'choice',
    text: ['A design note: “The vault app encrypts each note with AES-256. The key is SHA-256 of the user\'s 6-digit PIN, so it is a full 256 bits.” What is wrong, and what is the fix?'],
    options: ['Nothing: the key has 256 bits', 'Only 10⁶ keys are possible, about 20 bits: an attacker with a ciphertext tries every PIN in seconds. Derive the key with a slow, salted password hash and limit guesses (for example, keep the key in secure hardware that rate-limits PIN attempts)', 'SHA-256 output is too short for AES-256', 'Use AES-128 instead, which is faster'],
    answer: 1,
    hints: ['How many different keys can this scheme produce?', 'A 6-digit PIN has 10⁶ values, and log₂ 10⁶ ≈ 19.9 bits. Hashing does not add any.', 'The key is as strong as its source: about 20 bits. Slow down each guess (a salted password hash with a high work factor) and limit the number of guesses.'],
    solution: 1, wrong: [0, 3],
    whyNot: { 0: 'The key length is 256 bits, but only 10⁶ of those keys can ever occur.', 3: 'The problem is the PIN, not the cipher.' },
  });
})(globalThis.Sifer = globalThis.Sifer || {});
