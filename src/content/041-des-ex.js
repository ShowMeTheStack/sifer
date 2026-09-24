// Part 4, DES and the Feistel network: the exercises. The lessons are in 040-des.js; the challenges, the tour and the
// course in 042-des-ctf.js. Every block, key and round function here is our own; each answer was worked out by the
// engines (S.Feistel, S.DES, S.SPN) and is checked by them where a check needs computing. The DES tables shown are
// those of the standard (FIPS 46-3).
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('des-x-feistel-table')) return;
  const ex = (o) => C.exercise(o);
  const hexNums = (t) => String(t).toLowerCase().replace(/0x/g, '').split(/[^0-9a-f]+/).filter(Boolean).map((w) => parseInt(w, 16));
  const D = () => S.DES;

  // the 8-bit round function of the hand exercises: (R + k) mod 256, rotated left by 3
  const F8 = (R, k) => { const v = (R + k) & 0xff; return ((v << 3) | (v >>> 5)) & 0xff; };
  // Tern, the toy cipher of the meet-in-the-middle exercise and challenge; TERN_SRC is the same function as text
  const TERN_SRC = 'function tern(block, key, decrypt) {\n'
    + '  const rotl20 = (k, n) => ((k << n) | (k >>> (20 - n))) & 0xfffff;\n'
    + '  const roundKey = (i) => (rotl20(key, (5 * i) % 20) & 0xffff) ^ ((0x1357 * (i + 1)) & 0xffff);\n'
    + '  const F = (r, k) => {\n'
    + '    let x = ((r ^ k) * 0x6255 + 0x3c6e) & 0xffff;\n'
    + '    x = ((x << 5) | (x >>> 11)) & 0xffff;\n'
    + '    return x ^ (x >>> 7);\n'
    + '  };\n'
    + '  let L = block >>> 16, R = block & 0xffff;\n'
    + '  for (let i = 0; i < 6; i++) {\n'
    + '    const t = L ^ F(R, roundKey(decrypt ? 5 - i : i));\n'
    + '    L = R; R = t;\n'
    + '  }\n'
    + '  return ((R << 16) | L) >>> 0;\n'
    + '}';
  function tern(block, key, decrypt) {
    const rotl20 = (k, n) => ((k << n) | (k >>> (20 - n))) & 0xfffff;
    const roundKey = (i) => (rotl20(key, (5 * i) % 20) & 0xffff) ^ ((0x1357 * (i + 1)) & 0xffff);
    const F = (r, k) => { let x = ((r ^ k) * 0x6255 + 0x3c6e) & 0xffff; x = ((x << 5) | (x >>> 11)) & 0xffff; return x ^ (x >>> 7); };
    let L = block >>> 16, R = block & 0xffff;
    for (let i = 0; i < 6; i++) { const t = L ^ F(R, roundKey(decrypt ? 5 - i : i)); L = R; R = t; }
    return ((R << 16) | L) >>> 0;
  }
  S.Tern = { encrypt: tern, SRC: TERN_SRC };
  const sboxRows = (boxes) => {
    const head = ['', ...Array.from({ length: 16 }, (_, i) => String(i))];
    const rows = [];
    for (const b of boxes) for (let r = 0; r < 4; r++) rows.push(['S' + (b + 1) + ' row ' + r, ...D().SBOX[b].slice(16 * r, 16 * r + 16).map(String)]);
    return [head, ...rows];
  };

  // =========================================================================================================
  // Chapter 1: the Feistel network and DES
  // =========================================================================================================
  ex({
    id: 'des-x-feistel-table', chapter: 'des-ladder', title: 'Three Feistel rounds by hand', level: 1, kind: 'table', cellKind: 'hex', corner: 'round',
    text: ['A toy Feistel cipher works on 8-bit halves with F(R, k) = ((R + k) mod 256) rotated left by 3 bits. The block is L₀ = a7, R₀ = 3c and the round keys are 5d, e2, 19. Fill in F and the halves after each round (Lᵢ = Rᵢ₋₁, Rᵢ = Lᵢ₋₁ ⊕ F(Rᵢ₋₁, kᵢ)).'],
    rows: ['1', '2', '3'], cols: ['F(R, k)', 'L', 'R'],
    cells: { '1|F(R, k)': 'cc', '1|L': '3c', '1|R': '6b', '2|F(R, k)': '6a', '2|L': '6b', '2|R': '56', '3|F(R, k)': '7b', '3|L': '56', '3|R': '10' },
    hints: ['Round 1: 3c + 5d = 99 = 1001 1001; rotated left by 3 it is 1100 1100 = cc.', 'R₁ = a7 ⊕ cc = 6b and L₁ = 3c. Round 2: 6b + e2 = 14d, so 4d = 0100 1101, rotated: 0110 1010 = 6a, and R₂ = 3c ⊕ 6a = 56.', 'Round 3: 56 + 19 = 6f, rotated 7b; R₃ = 6b ⊕ 7b = 10. So the rows are (cc, 3c, 6b), (6a, 6b, 56), (7b, 56, 10), and the ciphertext after the final swap is 10 56.'],
    solution: { '1|F(R, k)': 'cc', '1|L': '3c', '1|R': '6b', '2|F(R, k)': '6a', '2|L': '6b', '2|R': '56', '3|F(R, k)': '7b', '3|L': '56', '3|R': '10' },
    wrong: [{ '1|F(R, k)': '99', '1|L': '3c', '1|R': '3e', '2|F(R, k)': '4d', '2|L': '3e', '2|R': '71', '3|F(R, k)': '57', '3|L': '71', '3|R': '69' }, { '1|F(R, k)': 'cc', '1|L': '6b', '1|R': '3c', '2|F(R, k)': '6a', '2|L': '56', '2|R': '6b', '3|F(R, k)': '7b', '3|L': '10', '3|R': '56' }],
  });
  ex({
    id: 'des-x-feistel-decrypt', chapter: 'des-ladder', title: 'Decrypt with the same ladder', level: 2, kind: 'hex',
    text: ['The same toy cipher (F(R, k) = ((R + k) mod 256) <<< 3 on 8-bit halves) ran four rounds with the keys 3e, 81, c4, 07 and gave the ciphertext a1 f3 (left half first, after the final swap). Decrypt it.'],
    answer: '6f6b',
    hints: ['Put the ciphertext into the same ladder: L = a1, R = f3, and use the keys in reverse order: 07, c4, 81, 3e.', 'Round 1 with 07: f3 + 07 = fa, rotated left by 3 is d7, and a1 ⊕ d7 = 76. Continue the ladder, then swap at the end.', 'The plaintext is 6f 6b, the letters “ok”.'],
    solution: '6f6b', wrong: ['a1f3', '6b6f', '6f6c'],
    why: 'Decryption never needed F to be inverted; it ran the same ladder with the keys reversed.',
  });
  ex({
    id: 'des-x-feistel-f', chapter: 'des-ladder', title: 'What must F be?', level: 1, kind: 'choice',
    text: ['For a Feistel cipher to be decryptable, what does the round function F have to satisfy?'],
    options: ['F must be a bijection on the half-block', 'Nothing: any function F gives an invertible cipher', 'F must be linear, so that it can be undone', 'F must use every key bit in every round'],
    answer: 1,
    hints: ['Look at how decryption round 1 removes the last encryption round.', 'It recomputes F(R, k) from a value it can see and XORs it out. F is only ever evaluated forwards.', 'Any F works: invertibility comes from the ladder. F decides security, not decryptability; DES\'s f is many-to-one.'],
    solution: 1, wrong: [0, 2, 3],
    whyNot: { 0: 'DES\'s f is not a bijection (eight 6-to-4-bit S-boxes), yet DES decrypts.', 2: 'A linear F would make the cipher easy to break; and it need not be undone at all.', 3: 'That matters for security, not for decryption.' },
  });
  ex({
    id: 'des-x-feistel-zero', chapter: 'des-ladder', title: 'A Feistel cipher with F = 0', level: 2, kind: 'hex',
    text: ['A Feistel cipher on 16-bit halves uses F(R, k) = 0 for every R and k, three rounds, and the usual final swap. What does it output for the block c0ff ee12?'],
    answer: 'c0ffee12',
    hints: ['With F = 0, a round just swaps: (L, R) → (R, L).', 'Three rounds swap three times, giving (ee12, c0ff), and the final swap makes it (c0ff, ee12).', 'The output is c0ffee12, the input itself: with an odd number of rounds, F = 0 is the identity, and with an even number it just swaps the halves.'],
    solution: 'c0ffee12', wrong: ['ee12c0ff', '00000000', 'c0ffc0ff'],
  });
  ex({
    id: 'des-x-code-feistel', chapter: 'des-ladder', title: 'Write a Feistel network', level: 2, kind: 'code', radix: 16, width: 4, fn: 'feistel', params: ['L', 'R', 'keys'],
    text: ['Write `feistel(L, R, keys)` for 16-bit halves and the round function F given in the editor. Run one round per key: L ← R, R ← L ⊕ F(R, k). After the last round swap once more and return `[left, right]` of the output, so that the same function decrypts when given the keys reversed.'],
    start: '// the round function, on 16-bit halves\nconst F = (r, k) =>\n  ((r ^ k) * 157 + (r >>> 3)) & 0xffff;\n\nfunction feistel(L, R, keys) {\n  \n}\n',
    ref: (L, R, keys) => { const r = S.Feistel.run({ L, R, keys, F: (r0, k) => ((r0 ^ k) * 157 + (r0 >>> 3)) & 0xffff, bits: 16 }); return [r.L, r.R]; },
    cases: [[0x6e69, 0x6768, [0x1234, 0xabcd, 0x0f0f, 0x7777]], [0x7772, 0x656e, [0x3a7c]], [0, 0, [1, 2, 3]], [0xffff, 0x0001, [0xbeef, 0xcafe]], [0xb97c, 0xfa00, [0x7777, 0x0f0f, 0xabcd, 0x1234]], [0x1111, 0x2222, []]],
    hints: ['Keep the halves in two variables; each round compute `const t = L ^ F(R, k); L = R; R = t;`.', 'At the end return `[R, L]`: the halves swapped once more. With no keys at all, that just swaps the input.', '// the round function, on 16-bit halves\nconst F = (r, k) =>\n  ((r ^ k) * 157 + (r >>> 3)) & 0xffff;\n\nfunction feistel(L, R, keys) {\n  for (const k of keys) {\n    const t = L ^ F(R, k);\n    L = R; R = t;\n  }\n  return [R, L];\n}'],
    solution: 'const F = (r, k) => ((r ^ k) * 157 + (r >>> 3)) & 0xffff;\n\nfunction feistel(L, R, keys) {\n  for (const k of keys) {\n    const t = L ^ F(R, k);\n    L = R; R = t;\n  }\n  return [R, L];\n}\n',
    wrong: ['const F = (r, k) => ((r ^ k) * 157 + (r >>> 3)) & 0xffff;\n\nfunction feistel(L, R, keys) {\n  for (const k of keys) {\n    const t = L ^ F(R, k);\n    L = R; R = t;\n  }\n  return [L, R];\n}\n', 'const F = (r, k) => ((r ^ k) * 157 + (r >>> 3)) & 0xffff;\n\nfunction feistel(L, R, keys) {\n  for (const k of keys) {\n    const t = R ^ F(L, k);\n    R = L; L = t;\n  }\n  return [R, L];\n}\n'],
  });
  ex({
    id: 'des-x-two-rounds', chapter: 'des-ladder', title: 'Two rounds are not enough', level: 2, kind: 'break', target: 'round keys',
    text: ['The toy cipher of the first exercise (8-bit halves, F(R, k) = ((R + k) mod 256) <<< 3) is used with only two rounds and secret keys k₁, k₂. You know one pair: the plaintext 5a c3 encrypts to 75 a8 (after the final swap). Recover k₁ and k₂, written as two hex bytes like 4f 0b.'],
    verify: (v, raw) => {
      const n = hexNums(raw);
      if (n.length !== 2 || n.some((x) => !(x >= 0 && x < 256))) return 'Give the two round keys as two hex bytes, like 4f 0b.';
      const r = S.Feistel.run({ L: 0x5a, R: 0xc3, keys: n, F: F8, bits: 8 });
      return r.L === 0x75 && r.R === 0xa8 ? true : 'With those keys, 5a c3 encrypts to ' + r.L.toString(16).padStart(2, '0') + ' ' + r.R.toString(16).padStart(2, '0') + ', not 75 a8.';
    },
    hints: ['After two rounds and the swap, the output is (R₂, R₁): the right half of the ciphertext is R₁ = a8, the result of round 1, in plain view.', 'Round 1: R₁ = L₀ ⊕ F(R₀, k₁), so F(c3, k₁) = a8 ⊕ 5a = f2. Undo the rotation: f2 rotated right by 3 is 5e = c3 + k₁ mod 256.', 'k₁ = 5e − c3 = 9b (mod 256). Round 2 the same way: F(a8, k₂) = 75 ⊕ c3 = b6, rotated right by 3 is d6 = a8 + k₂, so k₂ = 2e. The keys are 9b 2e.'],
    solution: '9b 2e', wrong: ['2e 9b', '5a c3', '9b'],
  });
  ex({
    id: 'des-x-ip', chapter: 'des-ladder', title: 'The initial permutation by columns', level: 3, kind: 'hex',
    text: ['Apply DES\'s initial permutation to the plaintext “harriers” (68 61 72 72 69 65 72 73) and give L₀ R₀ as 16 hex digits. Use the column rule: write the bytes as rows of an 8×8 grid of bits, most significant bit on the left. Output byte j of L₀ is column 2j of the grid read from the last row up to the first (j = 1 … 4), and output byte j of R₀ is column 2j − 1 read the same way.', { topic: 'des-ipfp', input: { pt: '6861727269657273' }, frame: 1, caption: 'The topic does it with your plaintext. Try the first byte by hand first.' }],
    answer: 'ffcc20b200ff11cc',
    hints: ['In binary the rows are 01101000, 01100001, 01110010, 01110010, 01101001, 01100101, 01110010, 01110011.', 'Column 2 is the second bit of every row: all 1s, so L₀ starts ff. Column 1, the first bit, is all 0s, so R₀ starts 00.', 'L₀ = ff cc 20 b2 and R₀ = 00 ff 11 cc.'],
    solution: 'ffcc20b200ff11cc', wrong: ['00ff11ccffcc20b2', 'ffcc20b2', '6861727269657273'],
  });
  ex({
    id: 'des-x-rounds', chapter: 'des-ladder', title: 'Three DES rounds', level: 1, kind: 'table', cellKind: 'hex', corner: 'round',
    text: ['Encrypting “harriers” under the key “salt&oak”, IP gives L₀ = ffcc20b2 and R₀ = 00ff11cc. The f-function gives efcaef63 in round 1, 91e71dbb in round 2 and df770e29 in round 3. Fill in Lᵢ and Rᵢ.'],
    rows: ['1', '2', '3'], cols: ['L', 'R'],
    cells: { '1|L': '00ff11cc', '1|R': '1006cfd1', '2|L': '1006cfd1', '2|R': '91180c77', '3|L': '91180c77', '3|R': 'cf71c1f8' },
    hints: ['Lᵢ = Rᵢ₋₁, and Rᵢ = Lᵢ₋₁ ⊕ f.', 'Round 1: L₁ = 00ff11cc and R₁ = ffcc20b2 ⊕ efcaef63 = 1006cfd1.', 'Round 2: L₂ = 1006cfd1, R₂ = 00ff11cc ⊕ 91e71dbb = 91180c77. Round 3: L₃ = 91180c77, R₃ = 1006cfd1 ⊕ df770e29 = cf71c1f8.'],
    solution: { '1|L': '00ff11cc', '1|R': '1006cfd1', '2|L': '1006cfd1', '2|R': '91180c77', '3|L': '91180c77', '3|R': 'cf71c1f8' },
    wrong: [{ '1|L': '1006cfd1', '1|R': '00ff11cc', '2|L': '91180c77', '2|R': '1006cfd1', '3|L': 'cf71c1f8', '3|R': '91180c77' }, { '1|L': '00ff11cc', '1|R': 'efcaef63', '2|L': 'efcaef63', '2|R': '91e71dbb', '3|L': '91e71dbb', '3|R': 'df770e29' }],
  });
  ex({
    id: 'des-x-expand', chapter: 'des-ladder', title: 'The expansion E', level: 2, kind: 'hex',
    text: ['Expand R = f0a5c33c to 48 bits with E: each 4-bit group of R is written with the last bit of the group before it in front and the first bit of the group after it behind (wrapping round at the ends), giving eight groups of six bits. Give E(R) in hex (12 digits).'],
    answer: '7a150be069f9',
    hints: ['R in bits: 1111 0000 1010 0101 1100 0011 0011 1100.', 'Group 1, 1111, gets the last bit of group 8 (0) in front and the first bit of group 2 (0) behind: 011110. Group 2, 0000, gets 1 and 1: 100001.', 'The eight groups are 011110 100001 010100 001011 111000 000110 100111 111001, which is 7a150be069f9.'],
    solution: '7a150be069f9', wrong: ['f0a5c33c', '7a150be069f8', '7a150be0'],
  });
  const s1Cells = { '011011|row': '1', '011011|column': '13', '011011|output': '5', '100110|row': '2', '100110|column': '3', '100110|output': '8', '111111|row': '3', '111111|column': '15', '111111|output': '13', '000001|row': '1', '000001|column': '0', '000001|output': '0' };
  ex({
    id: 'des-x-s1', chapter: 'des-ladder', title: 'Look up S1', level: 1, kind: 'table', cellKind: 'text', corner: 'input',
    text: ['Here is S1, the first DES S-box. For each 6-bit input, give the row (from the outer bits), the column (from the middle four bits) and the output, all in decimal.', { table: sboxRows([0]), caption: 'S1, from FIPS 46-3: rows 0 to 3, columns 0 to 15.' }],
    rows: ['011011', '100110', '111111', '000001'], cols: ['row', 'column', 'output'],
    cells: s1Cells,
    hints: ['Outer bits: the first and the last. 011011 has outer bits 0 and 1, so row 01 = 1.', 'The middle four bits of 011011 are 1101 = 13. S1 row 1, column 13 is 5.', '011011: row 1, column 13, output 5. 100110: row 2, column 3, output 8. 111111: row 3, column 15, output 13. 000001: row 1, column 0, output 0.'],
    solution: Object.assign({}, s1Cells),
    wrong: [Object.assign({}, s1Cells, { '011011|row': '0', '011011|column': '27', '011011|output': '1' }), Object.assign({}, s1Cells, { '000001|row': '0', '000001|column': '1', '000001|output': '4' })],
  });
  const sbCells = { 'S1|output': 'f', 'S2|output': 'b', 'S3|output': '9', 'S4|output': 'b', 'S5|output': '9', 'S6|output': '1', 'S7|output': 'b', 'S8|output': 'f' };
  ex({
    id: 'des-x-f-sboxes', chapter: 'des-ladder', title: 'All eight S-boxes of one round', level: 3, kind: 'table', cellKind: 'hex', corner: 'S-box',
    text: ['In round 1 of encrypting “harriers” under “salt&oak”, the S-boxes receive E(R₀) ⊕ K₁ = c0a9986d3178 (48 bits). Cut it into eight groups of six bits, S1 first, and give each S-box\'s output as one hex digit.', { table: sboxRows([0, 1, 2, 3, 4, 5, 6, 7]), caption: 'The eight DES S-boxes, from FIPS 46-3.' }],
    rows: ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8'], cols: ['output'],
    cells: sbCells,
    hints: ['c0a9986d3178 in bits: 1100 0000 1010 1001 1001 1000 0110 1101 0011 0001 0111 1000. The groups are 110000 001010 100110 011000 011011 010011 000101 111000.', 'S1 gets 110000: outer bits 10 = row 2, middle 1000 = column 8, and S1 has 15 there: f.', 'The outputs are f b 9 b 9 1 b f: 15, 11, 9, 11, 9, 1, 11, 15. Together they are fb9b91bf, which P turns into f = efcaef63.'],
    solution: Object.assign({}, sbCells),
    wrong: [Object.assign({}, sbCells, { 'S1|output': '3' }), { 'S1|output': 'c', 'S2|output': '0', 'S3|output': 'a', 'S4|output': '9', 'S5|output': '8', 'S6|output': '6', 'S7|output': 'd', 'S8|output': '1' }],
  });
  // the S-boxes as the editor shows them: each row of 16 entries as 16 hex digits, two rows to a line
  const SBOX_SRC = 'const SBOX = [\n' + S.DES.SBOX.map((b) => { const r = [0, 1, 2, 3].map((k) => "'" + b.slice(16 * k, 16 * k + 16).map((v) => v.toString(16)).join('') + "'"); return '  [' + r[0] + ', ' + r[1] + ',\n   ' + r[2] + ', ' + r[3] + '],'; }).join('\n') + '\n];\n';
  ex({
    id: 'des-x-code-sbox', chapter: 'des-ladder', title: 'Write a DES S-box lookup', level: 2, kind: 'code', radix: 16, width: 2, fn: 'desSbox', params: ['box', 'six'],
    text: ['Write `desSbox(box, six)`: `box` is 1 to 8 and `six` a number from 0 to 63 whose six bits are the S-box input, the first bit as the most significant. Return the 4-bit output as a number. The tables are in the editor: `SBOX[box − 1][row]` is a string of 16 hex digits, the entries for columns 0 to 15.'],
    start: '// the S-boxes of FIPS 46-3: four rows\n// of 16 hex digits each\n' + SBOX_SRC + '\nfunction desSbox(box, six) {\n  \n}\n',
    ref: (box, six) => { const row = ((six >> 4) & 2) | (six & 1), col = (six >> 1) & 15; return D().SBOX[box - 1][16 * row + col]; },
    cases: [[1, 0b011100], [2, 0b001010], [1, 0b011011], [1, 0b100110], [1, 0b111111], [1, 0b000001], [3, 0b100111], [8, 0b101110], [5, 0], [6, 63], [7, 0b110010], [4, 0b011000]],
    hints: ['The row is made of the first and last bits: `((six >> 4) & 2) | (six & 1)`.', 'The column is the middle four bits: `(six >> 1) & 15`. Read that hex digit of the row\'s string and turn it into a number with `parseInt(…, 16)`.', 'function desSbox(box, six) {\n  const row = ((six >> 4) & 2) | (six & 1);\n  const col = (six >> 1) & 15;\n  return parseInt(SBOX[box - 1][row][col], 16);\n}'],
    solution: SBOX_SRC + '\nfunction desSbox(box, six) {\n  const row = ((six >> 4) & 2) | (six & 1);\n  const col = (six >> 1) & 15;\n  return parseInt(SBOX[box - 1][row][col], 16);\n}\n',
    wrong: [SBOX_SRC + '\nfunction desSbox(box, six) {\n  return parseInt(SBOX[box - 1][six >> 4][six & 15], 16);\n}\n', SBOX_SRC + '\nfunction desSbox(box, six) {\n  const row = ((six >> 4) & 2) | (six & 1);\n  const col = (six >> 1) & 15;\n  return SBOX[box - 1][row][col];\n}\n'],
  });
  ex({
    id: 'des-x-p', chapter: 'des-ladder', title: 'Why P?', level: 1, kind: 'choice',
    text: ['After the eight S-boxes, DES applies the fixed permutation P to their 32 output bits. What is P for?'],
    options: ['It adds key material', 'It sends the four output bits of each S-box to four different S-boxes in the next round, so a change spreads', 'It makes f invertible', 'It is a leftover from the hardware of the 1970s and does nothing'],
    answer: 1,
    hints: ['P has no key and is public, so it cannot hide anything by itself.', 'Without P, the bits from S1 would come back mostly into S1 and its neighbours next round, and changes would stay local.', 'P spreads each S-box\'s output over several S-boxes of the next round: that is diffusion, which makes the avalanche happen in a few rounds.'],
    solution: 1, wrong: [0, 2, 3],
    whyNot: { 0: 'P has no key: it is the same fixed wiring in every round.', 2: 'f need not be invertible in a Feistel cipher, and P alone could not make it so.', 3: 'That describes IP and FP. P is inside every round and is essential to diffusion.' },
  });
  ex({
    id: 'des-x-shifts', chapter: 'des-ladder', title: 'Rotations so far', level: 1, kind: 'number',
    text: ['The DES key schedule rotates C and D left by 1 place in rounds 1, 2, 9 and 16 and by 2 places in every other round. By how many places in all have C and D been rotated after round 9?'],
    answer: 15,
    hints: ['Rounds 1 to 9: which of them rotate by 1?', 'Rounds 1, 2 and 9 rotate by 1; rounds 3 to 8, six rounds, rotate by 2.', '3 × 1 + 6 × 2 = 15.'],
    solution: '15', wrong: ['16', '18', '9'],
    whyNot: 'Add 1 for rounds 1, 2 and 9 and 2 for each of rounds 3 to 8.',
  });
  const keyCells = { 'C|round 1': '01dffe0', 'C|round 2': '03bffc0', 'C|round 3': '0efff00', 'D|round 1': '6279493', 'D|round 2': 'c4f2926', 'D|round 3': '13ca49b' };
  ex({
    id: 'des-x-keys', chapter: 'des-ladder', title: 'Rotate the key registers', level: 2, kind: 'table', cellKind: 'hex', corner: 'half',
    text: ['For the key “salt&oak”, PC-1 gives the 28-bit halves C₀ = 00efff0 and D₀ = b13ca49 (7 hex digits each). Rounds 1 and 2 rotate both left by 1 place, round 3 by 2. Give C and D after each round, as 7 hex digits.'],
    rows: ['C', 'D'], cols: ['round 1', 'round 2', 'round 3'],
    cells: keyCells,
    hints: ['Rotate the 28 bits, not 32: the bit that leaves on the left comes back on the right of the 28.', 'D₀ = b13ca49 = 1011 0001 0011 1100 1010 0100 1001. Rotated by 1: 0110 0010 0111 1001 0100 1001 0011 = 6279493.', 'C: 01dffe0, 03bffc0, 0efff00. D: 6279493, c4f2926, 13ca49b.'],
    solution: Object.assign({}, keyCells),
    wrong: [Object.assign({}, keyCells, { 'D|round 1': '6279492' }), Object.assign({}, keyCells, { 'C|round 3': '077ff80', 'D|round 3': '89e524c' })],
  });
  ex({
    id: 'des-x-decrypt-order', chapter: 'des-ladder', title: 'Decryption keys', level: 1, kind: 'choice',
    text: ['DES decrypts by running the same sixteen rounds on the ciphertext. Which round key does the first decryption round use?'],
    options: ['K₁', 'K₁₆', 'The complement of K₁', 'A key computed by inverting PC-2'],
    answer: 1,
    hints: ['The first decryption round has to undo the last encryption round.', 'The last encryption round XORed in f(R₁₅, K₁₆).', 'K₁₆: decryption uses K₁₆, K₁₅, …, K₁, obtained by rotating C and D right instead of left.'],
    solution: 1, wrong: [0, 2],
  });
  ex({
    id: 'des-x-avalanche', chapter: 'des-ladder', title: 'Count the avalanche', level: 2, kind: 'number',
    text: ['Under the key “salt&oak”, “harriers” encrypts to 5f13d8db47e9462f. Flipping the very last plaintext bit gives 6ff337b6d6cc30af. In how many of the 64 bits do the two ciphertexts differ?'],
    answer: 29,
    hints: ['XOR the two ciphertexts and count the 1 bits.', 'The XOR is 30e0ef6d91257680.', 'Byte by byte: 30 has 2 ones, e0 3, ef 7, 6d 5, 91 3, 25 3, 76 5, 80 1: 29 bits, close to half of 64.'],
    solution: '29', wrong: ['32', '1', '35'],
    whyNot: 'XOR the ciphertexts and count the bits that are 1.',
  });

  // =========================================================================================================
  // Chapter 2: weaknesses and fixes
  // =========================================================================================================
  ex({
    id: 'des-x-weak', chapter: 'des-weak', title: 'Spot the weak keys', level: 1, kind: 'choice',
    text: ['Which of these are weak DES keys, keys for which all sixteen round keys are equal? Choose all that apply.'],
    options: ['01 01 01 01 01 01 01 01', 'fe fe fe fe fe fe fe fe', '01 fe 01 fe 01 fe 01 fe', 'e0 e0 e0 e0 f1 f1 f1 f1', '01 23 45 67 89 ab cd ef'],
    answer: [0, 1, 3],
    hints: ['Ignore the parity bits (the last bit of each byte). A key is weak when PC-1 gives C and D that are each all zeros or all ones.', '01…01 makes both halves zero, fe…fe both ones; e0e0e0e0f1f1f1f1 makes C all ones and D all zeros. 01fe01fe… makes halves of alternating bits.', 'Weak: 0101010101010101, fefefefefefefefe and e0e0e0e0f1f1f1f1 (the fourth is 1f1f1f1f0e0e0e0e). 01fe01fe01fe01fe is semi-weak: its partner fe01fe01fe01fe01 decrypts what it encrypts.'],
    solution: [0, 1, 3], wrong: [[0, 1], [0, 1, 2, 3], [2, 4]],
  });
  ex({
    id: 'des-x-complement', chapter: 'des-weak', title: 'Use the complement property', level: 1, kind: 'hex',
    text: ['DES encrypts 6861727269657273 under the key 73616c74266f616b to 5f13d8db47e9462f. Without running DES, what does 979e8d8d969a8d8c encrypt to under 8c9e938bd9909e94?'],
    answer: 'a0ec2724b816b9d0',
    hints: ['Compare the new plaintext and key with the old ones: 68 ⊕ 97 = ff, 73 ⊕ 8c = ff.', 'Both are complemented, so DES(¬p, ¬k) = ¬DES(p, k).', 'The complement of 5f13d8db47e9462f is a0ec2724b816b9d0.'],
    solution: 'a0ec2724b816b9d0', wrong: ['5f13d8db47e9462f', 'a0ec2724b816b9d1', '6861727269657273'],
  });
  ex({
    id: 'des-x-search', chapter: 'des-weak', title: 'How long to find a key?', level: 2, kind: 'number', tolerance: 0.15,
    text: ['A machine tests 10¹⁰ DES encryptions per second and uses the complement property, so each encryption rules out two keys. On average the right key turns up after half of the 2⁵⁶ keys have been ruled out. How many days does that take on average? (One decimal place is enough.)'],
    answer: 20.85,
    hints: ['Half of the 2⁵⁶ keys is 2⁵⁵ keys, and each encryption covers two of them: 2⁵⁴ ≈ 1.80 × 10¹⁶ encryptions.', '1.80 × 10¹⁶ / 10¹⁰ = 1.80 × 10⁶ seconds.', '1.80 × 10⁶ s / 86 400 s ≈ 20.8 days. Without the complement property it would be twice as long, 41.7 days.'],
    solution: '20.8', wrong: ['41.7', '83.4', '0.2'],
    whyNot: 'Count the encryptions (half the keys, two keys per encryption), divide by the rate for seconds, then by 86 400 for days.',
  });
  ex({
    id: 'des-x-mitm-cost', chapter: 'des-weak', title: 'The cost of meeting in the middle', level: 2, kind: 'number',
    text: ['A double cipher C = E_K₂(E_K₁(P)) uses two independent 40-bit keys. A meet-in-the-middle attack encrypts P under every K₁ and decrypts C under every K₂. That is 2ˣ cipher operations in all: what is x?'],
    answer: 41,
    hints: ['Each side tries every key once: 2⁴⁰ encryptions and 2⁴⁰ decryptions.', '2⁴⁰ + 2⁴⁰ = 2 · 2⁴⁰.', '2⁴¹, against 2⁸⁰ for trying every pair of keys. The memory is the price: a table of 2⁴⁰ middle values.'],
    solution: '41', wrong: ['80', '40', '81'],
    whyNot: 'Add the work of the two sides; do not multiply them.',
  });
  ex({
    id: 'des-x-mitm-break', chapter: 'des-weak', title: 'Meet a toy double cipher in the middle', level: 3, kind: 'break', target: 'key pair',
    text: [
      'Tern is a toy cipher on 32-bit blocks: six Feistel rounds on 16-bit halves, with keys of up to 20 bits. A sender encrypts twice, C = tern(tern(P, K₁), K₂), with two keys of 12 bits each (0 to fff). Here is Tern:',
      { code: TERN_SRC },
      'You know two pairs. Trying all 2²⁴ key pairs would take too long in the sandbox; meet in the middle instead. Give K₁ and K₂ in hex, like 1a2 3b4.',
      { code: 'P1 = 6b657931   C1 = b87494cc\nP2 = 6c6f636b   C2 = 79386893' },
      { sandbox: 'scratch' },
    ],
    verify: (v, raw) => {
      const n = hexNums(raw);
      if (n.length !== 2) return 'Give the two keys in hex, K₁ first, like 1a2 3b4.';
      const dbl = (p) => tern(tern(p, n[0]), n[1]);
      if (dbl(0x6b657931) !== 0xb87494cc || dbl(0x6c6f636b) !== 0x79386893) return 'Those keys do not take P1 to C1 and P2 to C2.';
      return dbl(0x66656e63) === 0xa7b8ba1f ? true : 'They fit both pairs, but not a third pair you have not seen: a false alarm. Look for another candidate.';
    },
    hints: ['Forward: for every K₁ from 0 to fff, store tern(P1, K₁) in a Map, with K₁ as its value.', 'Backward: for every K₂, compute tern(C1, K₂, true) and look it up. Every hit is a candidate (K₁, K₂); check it on the second pair. 8192 Tern calls in all.', 'The only candidate is K₁ = 768, K₂ = 596.'],
    solution: '768 596', wrong: ['596 768', '768', '0 0'],
  });
  ex({
    id: 'des-x-3des', chapter: 'des-weak', title: 'Why encrypt, decrypt, encrypt?', level: 2, kind: 'choice',
    text: ['3DES computes C = E_K₃(D_K₂(E_K₁(P))). Why is the middle step a decryption?'],
    options: ['Decryption is more secure than encryption', 'With K₁ = K₂ = K₃ it reduces to single DES, so 3DES equipment can talk to DES equipment', 'It defeats the meet-in-the-middle attack completely', 'Because DES decryption is faster'],
    answer: 1,
    hints: ['Try K₁ = K₂: what do the first two steps do?', 'D_K(E_K(P)) = P, so with equal keys only the last encryption is left.', 'Compatibility: setting all three keys equal gives single DES. Security is the same with E or D in the middle.'],
    solution: 1, wrong: [0, 2, 3],
    whyNot: { 0: 'With a different key, decrypting scrambles exactly as well as encrypting.', 2: 'Meet-in-the-middle still applies; it reduces three-key 3DES to about 2¹¹² work.', 3: 'DES decryption costs exactly as much as encryption.' },
  });
  ex({
    id: 'des-x-3des-bits', chapter: 'des-weak', title: 'The strength of three-key 3DES', level: 2, kind: 'number',
    text: ['Three-key 3DES has 3 × 56 = 168 key bits. A meet-in-the-middle attack stores the middle values after the first encryption and attacks the last two layers together from the other side. About how many bits of strength (log₂ of the work) are left?'],
    answer: 112,
    hints: ['One side guesses one 56-bit key; the other side guesses two.', 'The work is about 2⁵⁶ + 2¹¹², dominated by the two-key side.', 'About 112 bits.'],
    solution: '112', wrong: ['168', '56', '57'],
    whyNot: 'The attacker meets in the middle, so the work is set by the side that has to guess two keys.',
  });
  ex({
    id: 'des-x-desx', chapter: 'des-weak', title: 'DESX whitening', level: 1, kind: 'hex',
    text: ['DESX computes C = K₂ ⊕ DES_K(P ⊕ K₁). With P = “moonrise” (6d 6f 6f 6e 72 69 73 65) and K₁ = 0f 1e 2d 3c 4b 5a 69 78, what block goes into DES?'],
    answer: '6271425239331a1d',
    hints: ['The input to DES is P ⊕ K₁.', '6d ⊕ 0f = 62, 6f ⊕ 1e = 71, 6f ⊕ 2d = 42 …', 'P ⊕ K₁ = 62 71 42 52 39 33 1a 1d.'],
    solution: '6271425239331a1d', wrong: ['6d6f6f6e72697365', '6271425239331a1c', '0f1e2d3c4b5a6978'],
  });

  // =========================================================================================================
  // Chapter 3: breaking a toy SPN, and PRESENT
  // =========================================================================================================
  const ddtCells = {};
  [0, 4, 0, 0, 0, 2, 0, 2, 0, 2, 2, 0, 2, 2, 0, 0].forEach((v, i) => { ddtCells[i.toString(16) + '|count'] = String(v); });
  ex({
    id: 'des-x-ddt-row', chapter: 'des-spn', title: 'A row of the difference table', level: 2, kind: 'table', cellKind: 'text', corner: 'Δy',
    text: ['The toy SPN\'s S-box maps 0 … f to 6, b, 5, 4, 2, e, 7, a, 9, d, f, c, 3, 1, 0, 8. Fill in row Δx = 6 of its difference distribution table, here written as a column: for each Δy, how many of the 16 inputs x give S(x) ⊕ S(x ⊕ 6) = Δy?'],
    rows: '0123456789abcdef'.split(''), cols: ['count'],
    cells: ddtCells,
    hints: ['For x = 0: S(0) ⊕ S(6) = 6 ⊕ 7 = 1. For x = 1: S(1) ⊕ S(7) = b ⊕ a = 1.', 'Go through all 16 x. The pairs x and x ⊕ 6 give the same Δy, so every count is even, and the row adds up to 16.', 'Δy = 1 occurs 4 times; 5, 7, 9, a, c and d occur twice each; the rest 0: 0 4 0 0 0 2 0 2 0 2 2 0 2 2 0 0.'],
    solution: Object.assign({}, ddtCells),
    wrong: [Object.assign({}, ddtCells, { '1|count': '2', '3|count': '2' }), Object.assign({}, ddtCells, { '0|count': '16', '1|count': '0' })],
  });
  ex({
    id: 'des-x-char-prob', chapter: 'des-spn', title: 'How rare is a characteristic?', level: 2, kind: 'number',
    text: ['A characteristic of the toy SPN passes four active S-boxes in all, and each passes its difference with probability 4/16. About one pair in how many follows the characteristic?'],
    answer: 256,
    hints: ['The S-boxes are treated as independent, so the probabilities multiply.', '(4/16)⁴ = (1/4)⁴.', '1/256: one pair in 256. The attack needs a few times that many pairs to see the right pairs pile up.'],
    solution: '256', wrong: ['64', '16', '1024'],
    whyNot: 'Multiply the four probabilities and take the reciprocal.',
  });
  ex({
    id: 'des-x-filter', chapter: 'des-spn', title: 'Which pairs could be right?', level: 2, kind: 'choice',
    text: ['The characteristic ΔP = 0300 → ΔU₄ = 0044 predicts difference 4 into last-round S-boxes 2 and 3 and difference 0 into S-boxes 0 and 1. Which ciphertext differences ΔC could come from a right pair? Choose all that apply.'],
    options: ['00c3', '0300', '0040', '1043', '0071'],
    answer: [0, 4],
    hints: ['Equal inputs to an S-box give equal outputs, and the last key cancels from the difference: nibbles 0 and 1 of ΔC must be 0.', 'An S-box is a permutation, so a nonzero input difference gives a nonzero output difference: nibbles 2 and 3 of ΔC must both be nonzero.', '00c3 and 0071. 0300 and 1043 differ in nibbles 0 or 1; 0040 has nibble 3 equal to 0, which an input difference of 4 cannot produce.'],
    solution: [0, 4], wrong: [[0, 2, 4], [0], [1, 3]],
  });
  const SPN_KEPT = 'a0b0 a4b0, c552 cc52, 27ee 29ee, 1db4 18b4, a007 a607, 2f9b 2c9b, b129 b829, 488b 4a8b, cb2e c72e, 4cd7 48d7, 27e8 2be8, bd03 b503, c0f8 c4f8, ec77 ef77, 2719 2919, 5b9e 579e, 9fc8 9cc8, 6b1a 621a, fb62 f262, e7ab ebab, 4947 4347, a2d0 abd0, ee19 e019, 8d19 8e19, 7447 7147, a639 a239, 8abb 89bb, 6bd0 62d0, 3b79 3779, 4c07 4f07, 71be 74be, 173e 1b3e, e278 e678, b2b7 bbb7, 484f 4d4f, e233 e633, 23a8 29a8, 45b7 4ab7, 4dcf 48cf';
  ex({
    id: 'des-x-spn-break', chapter: 'des-spn', title: 'Recover a nibble of the last round key', level: 3, kind: 'break', target: 'key nibble', normalize: 'hex',
    text: [
      'You may encrypt chosen plaintexts with the toy SPN under a secret key. You use the characteristic ΔP = 0400 → ΔU₄ = 0400 (probability about 1/64), which reaches only S-box 1 of the last round, the second nibble from the left. Of 800 chosen pairs (P, P ⊕ 0400), these 39 have ciphertexts that differ only in nibble 1; the rest were thrown away:',
      { code: SPN_KEPT.replace(/, /g, '\n') },
      'The S-box is 6 b 5 4 2 e 7 a 9 d f c 3 1 0 8 (for inputs 0 … f). For each guess g of nibble 1 of K₅, undo the last S-box on nibble 1 of both ciphertexts, u = S⁻¹(c ⊕ g), and count the pairs with u ⊕ u′ = 4. Which nibble collects the most?',
      { sandbox: 'scratch' },
    ],
    verify: (v) => { const n = parseInt(v, 16); const nib = v.length >= 3 ? (n >> 8) & 15 : n; if (v.length >= 3 && (n & 0xf0ff)) return 'Give the one nibble, like 7, or the key bits in place, like 0700.'; return nib === 10 ? true : 'That guess scores less than the best one: count again for all 16 guesses.'; },
    hints: ['Nibble 1 of a 16-bit word is (c >> 8) & 15. Invert the S-box first: S⁻¹ maps 6 → 0, b → 1, 5 → 2, and so on.', 'The first pair, a0b0 and a4b0, has nibbles 0 and 4. For g = a: S⁻¹(0 ⊕ a) = S⁻¹(a) = 7 and S⁻¹(4 ⊕ a) = S⁻¹(e) = 5, and 7 ⊕ 5 = 2, not 4. Not every pair is a right pair; count over all 39.', 'The guess a scores 16 of 39; the runner-up, 6, scores 11. Nibble 1 of K₅ is a (the key bits 0a00).'],
    solution: 'a', wrong: ['6', '4', '0f00'],
  });
  ex({
    id: 'des-x-lat', chapter: 'des-spn', title: 'An entry of the linear approximation table', level: 2, kind: 'number',
    text: ['For the toy S-box (6 b 5 4 2 e 7 a 9 d f c 3 1 0 8), take the input mask a = 6 (bits 2 and 1 of x) and the output mask b = e (bits 3, 2 and 1 of S(x)). The LAT entry is the number of the 16 inputs x for which the two parities agree, minus 8. What is it?'],
    answer: 4,
    hints: ['For each x, compute the parity of x AND 6 and the parity of S(x) AND e, and count where they are equal.', 'x = 0: parity(0) = 0 and S(0) = 6, parity(6 AND e) = parity(6) = 0: agree. x = 1: 0 against parity(b AND e) = parity(a) = 0: agree.', 'They agree for 12 of the 16 inputs, so the entry is 12 − 8 = +4: a bias of 4/16 = 1/4, as large as the toy S-box allows.'],
    solution: '4', wrong: ['12', '-4', '0'],
    whyNot: 'Count the agreements over all 16 inputs and subtract 8.',
  });
  ex({
    id: 'des-x-pileup', chapter: 'des-spn', title: 'Pile up four approximations', level: 2, kind: 'number', tolerance: 0.0002,
    text: ['Four approximations, each with bias 1/4, are chained through four S-boxes. By the piling-up lemma, what is the bias of the whole chain? Give it as a decimal.'],
    answer: 0.03125,
    hints: ['The lemma: bias = 2ⁿ⁻¹ · ε₁ · ε₂ · … · εₙ.', '2³ · (1/4)⁴ = 8 / 256.', '1/32 = 0.03125, so about 1/ε² = 1024 known plaintexts are needed to see it.'],
    solution: '0.03125', wrong: ['0.0625', '0.00390625', '0.25'],
    whyNot: 'Use 2ⁿ⁻¹ times the product of the n biases, with n = 4.',
  });
  ex({
    id: 'des-x-present-p', chapter: 'des-spn', title: 'Follow a bit through pLayer', level: 1, kind: 'number',
    text: ['PRESENT\'s pLayer moves bit i to bit 16·i mod 63, for i = 0 … 62, and leaves bit 63 where it is. Where does bit 5 go?'],
    answer: 17,
    hints: ['Compute 16 · 5 = 80.', '80 mod 63 = 80 − 63.', 'Bit 5 goes to bit 17.'],
    solution: '17', wrong: ['80', '5', '20'],
    whyNot: 'Multiply by 16 and reduce modulo 63.',
  });
  ex({
    id: 'des-x-present', chapter: 'des-spn', title: 'What PRESENT is made of', level: 2, kind: 'choice',
    text: ['Which statements about PRESENT are true? Choose all that apply.'],
    options: ['Its bit permutation costs nothing in hardware: it is only wiring', 'It decrypts with the same circuit and the round keys reversed, like DES', 'Each round uses sixteen copies of one 4-bit S-box', 'Its S-box has a difference table entry of 8'],
    answer: [0, 2],
    hints: ['PRESENT is an SPN, not a Feistel cipher.', 'An SPN must invert its S-box and its permutation to decrypt; a Feistel cipher never inverts anything.', 'True: 1 and 3. PRESENT decrypts with the inverse S-box and permutation, and its S-box keeps every difference table entry at 4 or below.'],
    solution: [0, 2], wrong: [[0, 1, 2], [2], [1, 3]],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
