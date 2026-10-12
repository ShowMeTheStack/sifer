// Part 15, secure implementation of cryptography: the exercises. The lessons are in 150-impl.js; the tour and the
// course in 152-impl-tour.js. Every exercise is defensive: measure a leak in Hamming weights, write constant-time
// code checked against vectors, size a countermeasure, or choose the defence that fits a threat. Every answer was
// worked out with the engines (S.SC.HW, S.SC.sbox, S.SC.maskedLookup), and the code is checked by its own tests.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('im-x-hw')) return;
  const ex = (o) => C.exercise(o);
  const B = (...v) => Uint8Array.from(v);

  // =========================================================================================================
  // Chapter 1: how implementations leak
  // =========================================================================================================
  ex({
    id: 'im-x-hw', chapter: 'im-ch-leak', title: 'The weight of a word', level: 1, kind: 'number',
    text: ['A device loads the 4-byte word 3c a5 ff 08 onto a bus that is cleared to zero before each load, so its power follows the Hamming weight. What is the total Hamming weight of the four bytes?'],
    answer: 17,
    hints: ['Count the 1 bits of each byte in binary.', '3c = 00111100 (4), a5 = 10100101 (4), ff = 11111111 (8), 08 = 00001000 (1).', '4 + 4 + 8 + 1 = 17.'],
    solution: '17', wrong: ['16', '32', '4'],
    whyNot: { 32: 'That is the number of bits in the word, not the number that are 1.', 16: 'Check 08 = 00001000: it has one bit set.', '*': 'Write each byte in binary and count its 1 bits.' },
  });
  ex({
    id: 'im-x-hd', chapter: 'im-ch-leak', title: 'Bits that flip', level: 1, kind: 'number',
    text: ['A register holds 6e and is overwritten with d3. On a device whose power follows the Hamming distance, how many bits draw power in this update?'],
    answer: 6,
    hints: ['The Hamming distance is the weight of the XOR: HD(a, b) = HW(a ⊕ b).', '6e ⊕ d3 = 01101110 ⊕ 11010011 = 10111101 = bd.', 'HW(bd) = 6. Both values have weight 5, which says nothing about the distance.'],
    solution: '6', wrong: ['5', '0', '2'],
    whyNot: { 5: 'That is the weight of the new value d3; the distance counts the bits that change.', 0: 'Equal weights do not mean no bits change: XOR the two values.', '*': 'XOR the two bytes and count the 1 bits.' },
  });
  const seqCells = { '00 → 5a|HW(new)': '4', '00 → 5a|HD(old, new)': '4', '5a → c3|HW(new)': '4', '5a → c3|HD(old, new)': '4', 'c3 → 3c|HW(new)': '4', 'c3 → 3c|HD(old, new)': '8', '3c → ff|HW(new)': '8', '3c → ff|HD(old, new)': '4', 'ff → 81|HW(new)': '2', 'ff → 81|HD(old, new)': '6' };
  ex({
    id: 'im-x-hw-table', chapter: 'im-ch-leak', title: 'Weights and distances of a register', level: 2, kind: 'table',
    text: ['A register starts at 00 and is loaded in turn with 5a, c3, 3c, ff and 81. For each update, give the Hamming weight of the new value and the Hamming distance from the old value to the new. Write the counts in decimal.'],
    rows: ['00 → 5a', '5a → c3', 'c3 → 3c', '3c → ff', 'ff → 81'], cols: ['HW(new)', 'HD(old, new)'], corner: 'update',
    cells: seqCells,
    hints: ['HD(old, new) = HW(old ⊕ new).', 'The XORs are 5a, 99, ff, c3 and 7e.', 'HW: 4, 4, 4, 8, 2. HD: 4, 4, 8, 4, 6. The three middle values all weigh 4, yet c3 → 3c flips all eight bits: a distance device sees a large spike where a weight device sees nothing new.'],
    solution: seqCells,
    wrong: [Object.assign({}, seqCells, { 'c3 → 3c|HD(old, new)': '0' }), Object.assign({}, seqCells, { 'ff → 81|HD(old, new)': '2' })],
  });
  ex({
    id: 'im-x-model', chapter: 'im-ch-leak', title: 'Which model to test with', level: 2, kind: 'choice',
    text: ['You are evaluating a microcontroller before shipping. Its data bus is precharged to all zeros before every value is driven onto it; its internal registers are overwritten in place. When you check the bus for leaks of the S-box output y, which quantity should you correlate the measured power with?'],
    options: ['HW(y), the weight of the value driven', 'HD(previous bus value, y)', 'The value y itself, as a number from 0 to 255', 'Nothing: a precharged bus does not leak'],
    answer: 0,
    whyNot: { 1: 'The bus is precharged to zero, so the previous value is always 00 and the distance equals the weight; the weight is the direct model.', 2: 'Power follows the number of bits switched, not the size of the number: ff and 80 differ hugely in weight but not much in value.', 3: 'Driving each 1 bit from a precharged 0 costs energy: that is exactly the weight.' },
    hints: ['A precharged bus starts every transfer from the same value.', 'From all zeros, the bits that flip are the 1 bits of the new value.', 'HW(y): the distance from 00 is the weight. For the registers, overwritten in place, test with the Hamming distance instead.'],
    solution: 0, wrong: [1, 2, 3],
  });
  ex({
    id: 'im-x-leak-kinds', chapter: 'im-ch-leak', title: 'Which lines can leak through time', level: 1, kind: 'choice',
    text: ['In a function that handles a secret key k (an array of bytes) and a secret bit b, which of these lines can make the running time or the cache state depend on the secret? Assume the processor does XOR and AND in constant time.'],
    options: ['`t = k[0] ^ k[1];`', '`v = SBOX[k[0] ^ p[0]];`', '`for (i = 0; i < n; i++) if (a[i] !== k[i]) return false;`', '`if (b) r = r * x % N;`'],
    answer: [1, 2, 3],
    hints: ['Look for three things: a secret index, a loop or return that depends on a secret, and a branch on a secret.', 'XOR of two registers takes the same time whatever the values.', 'The lookup has a secret address, the loop stops at a secret position, and the if branches on a secret bit. Only the XOR is safe.'],
    solution: [1, 2, 3], wrong: [[0, 1, 2, 3], [2, 3], [1]],
  });
  ex({
    id: 'im-x-always-count', chapter: 'im-ch-leak', title: 'The cost of multiplying always', level: 1, kind: 'number',
    text: ['Left-to-right square-and-multiply on an exponent of 20 bits (its top bit 1) squares once for each bit after the first. The multiply-always version also multiplies once for each of those bits, whatever the bit. How many operations (squarings plus multiplications) does the multiply-always version do?'],
    answer: 38,
    hints: ['The leading 1 needs no work: 19 bits follow it.', 'Each of the 19 bits costs one squaring and one multiplication.', '19 + 19 = 38, the same for every 20-bit exponent. The naive version does 19 squarings plus one multiplication per 1 bit, which is what made its time a leak.'],
    solution: '38', wrong: ['40', '19', '20'],
    whyNot: { 40: 'The leading 1 bit needs neither a squaring nor a multiplication.', 19: 'That counts only the squarings; add one multiplication per bit.', '*': 'Count the bits after the leading 1, and two operations for each.' },
  });

  // =========================================================================================================
  // Chapter 2: constant-time programming
  // =========================================================================================================
  ex({
    id: 'im-x-ct-snippets', chapter: 'im-ch-ct', title: 'Which snippets are constant time', level: 2, kind: 'choice',
    text: ['a, b are byte arrays of the same public length; bit is a secret 0 or 1; x, y are 32-bit words. Which of these run in constant time with respect to the secrets?'],
    options: ['`for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true;`', '`let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d;`', '`return bit ? x : y;`', '`const m = -bit >>> 0; return (y ^ ((x ^ y) & m)) >>> 0;`'],
    answer: [1, 3],
    hints: ['Ask of each line: does the number of steps, or any branch, depend on a secret?', 'The first returns at the first difference; the third is a branch on bit (compilers often emit a jump for ?:).', 'The OR-accumulating loop always visits every byte, and the mask select has no branch at all: options 2 and 4.'],
    solution: [1, 3], wrong: [[0, 1, 3], [1, 2, 3], [3]],
  });

  const diffTests = [
    { args: [B(1, 2, 3, 4), B(1, 2, 3, 4)], want: 0 },
    { args: [B(1, 2, 3, 4), B(1, 0, 7, 4)], want: 6 },
    { args: [B(0x10, 0x20, 0x30), B(0x11, 0x20, 0x33)], want: 3 },
    { args: [B(0xff, 0x00, 0x5a, 0xc3, 0x3c, 0x81), B(0x7f, 0x00, 0x5a, 0xc3, 0x3c, 0x80)], want: 0x81 },
    { args: [B(0x6e, 0x6e), B(0xd3, 0xd3)], want: 0xbd },
    { args: [B(), B()], want: 0 },
  ];
  ex({
    id: 'im-x-code-diff', chapter: 'im-ch-ct', title: 'Write the difference accumulator', level: 1, kind: 'code', fn: 'diffAll', params: ['a', 'b'], radix: 16,
    text: ['Write `diffAll(a, b)` for two `Uint8Array`s of the same length. Return the OR of `a[i] ^ b[i]` over every index i, as a number from 0 to 255. It is 0 exactly when the arrays are equal.', 'Visit every byte, whatever you find: the tests include arrays that differ in more than one place, so a loop that stops early returns the wrong value.'],
    start: 'function diffAll(a, b) {\n  \n}\n',
    tests: diffTests,
    hints: ['Start with d = 0 and loop over all indices.', 'In the loop: d |= a[i] ^ b[i]. No if, no return inside the loop.', 'function diffAll(a, b) {\n  let d = 0;\n  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];\n  return d;\n}'],
    solution: 'function diffAll(a, b) {\n  let d = 0;\n  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];\n  return d;\n}\n',
    wrong: ['function diffAll(a, b) {\n  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] ^ b[i];\n  return 0;\n}\n', 'function diffAll(a, b) {\n  let d = 0;\n  for (let i = 0; i < a.length; i++) d += a[i] ^ b[i];\n  return d;\n}\n'],
  });
  const eqTests = [
    { args: [B(1, 2, 3, 4), B(1, 2, 3, 4)], want: 1 },
    { args: [B(1, 2, 3, 4), B(0, 2, 3, 4)], want: 0 },
    { args: [B(1, 2, 3, 4), B(1, 2, 3, 5)], want: 0 },
    { args: [B(0xac, 0xd6, 0xbf, 0x0c), B(0xac, 0xd6, 0xbf, 0x0c)], want: 1 },
    { args: [B(0x00, 0xff), B(0xff, 0x00)], want: 0 },
    { args: [B(0x80), B(0x00)], want: 0 },
    { args: [B(), B()], want: 1 },
  ];
  ex({
    id: 'im-x-code-eq', chapter: 'im-ch-ct', title: 'Write a constant-time compare', level: 2, kind: 'code', fn: 'ctEqual', params: ['a', 'b'],
    text: ['Write `ctEqual(a, b)` for two `Uint8Array`s of the same, public, length. Return the number 1 if they are equal and 0 if not.', 'Look at every byte, accumulate the differences with OR, and turn the accumulated byte d into 1 or 0 without a branch: `((d - 1) >>> 8) & 1` is 1 exactly when d is 0. The tests check the results on equal and unequal arrays; keeping the loop free of early exits is up to you.'],
    start: 'function ctEqual(a, b) {\n  \n}\n',
    tests: eqTests,
    hints: ['First accumulate: d |= a[i] ^ b[i] for every i.', 'For d from 0 to 255, d − 1 is −1 only when d = 0, and −1 >>> 8 has its low bit set; for 1 ≤ d ≤ 255, (d − 1) >>> 8 is 0.', 'function ctEqual(a, b) {\n  let d = 0;\n  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];\n  return ((d - 1) >>> 8) & 1;\n}'],
    solution: 'function ctEqual(a, b) {\n  let d = 0;\n  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];\n  return ((d - 1) >>> 8) & 1;\n}\n',
    wrong: ['function ctEqual(a, b) {\n  let d = 0;\n  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];\n  return d === 0;\n}\n', 'function ctEqual(a, b) {\n  let d = 0;\n  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];\n  return (d >>> 8) & 1;\n}\n', 'function ctEqual(a, b) {\n  let d = 0;\n  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];\n  return d ? 1 : 0;\n}\n'],
  });

  const SX = 0x3c5a96f0, SY = 0x0f0f1234;
  const selCells = { 'bit = 0|m': '00000000', 'bit = 0|(x ⊕ y) & m': '00000000', 'bit = 0|result': '0f0f1234', 'bit = 1|m': 'ffffffff', 'bit = 1|(x ⊕ y) & m': '335584c4', 'bit = 1|result': '3c5a96f0' };
  ex({
    id: 'im-x-select-table', chapter: 'im-ch-ct', title: 'A mask select by hand', level: 2, kind: 'table', cellKind: 'hex',
    text: ['Work through select(bit, x, y) = y ⊕ ((x ⊕ y) & m) with m = −bit as a 32-bit word, for x = 3c5a96f0 and y = 0f0f1234, once with bit = 0 and once with bit = 1. Write each cell as 8 hex digits.'],
    rows: ['bit = 0', 'bit = 1'], cols: ['m', '(x ⊕ y) & m', 'result'],
    cells: selCells,
    hints: ['−0 is 00000000 and −1 in 32 bits is ffffffff.', 'x ⊕ y = 3c5a96f0 ⊕ 0f0f1234 = 335584c4.', 'bit = 0: m = 00000000, the AND is 00000000, result y = 0f0f1234. bit = 1: m = ffffffff, the AND is 335584c4, result 0f0f1234 ⊕ 335584c4 = 3c5a96f0 = x. The same instructions ran both times.'],
    solution: selCells,
    wrong: [Object.assign({}, selCells, { 'bit = 1|m': '00000001', 'bit = 1|(x ⊕ y) & m': '00000000', 'bit = 1|result': '0f0f1234' }), Object.assign({}, selCells, { 'bit = 0|result': '3c5a96f0', 'bit = 1|result': '0f0f1234' })],
  });
  ex({
    id: 'im-x-code-select', chapter: 'im-ch-ct', title: 'Write a conditional select', level: 2, kind: 'code', fn: 'ctSelect', params: ['bit', 'x', 'y'], radix: 16, width: 8, decimalArgs: [0],
    text: ['Write `ctSelect(bit, x, y)`: bit is 0 or 1, x and y are unsigned 32-bit words. Return x when bit is 1 and y when bit is 0, as an unsigned 32-bit number, without `if`, `?:` or any other branch on bit.', 'Make the mask m = −bit (all zeros or all ones) and compute y ⊕ ((x ⊕ y) & m). JavaScript\'s bit operators give signed 32-bit results: finish with `>>> 0`.'],
    start: 'function ctSelect(bit, x, y) {\n  \n}\n',
    ref: (bit, x, y) => (bit ? x : y) >>> 0,
    cases: [[1, SX, SY], [0, SX, SY], [1, 0xffffffff, 0], [0, 0xffffffff, 0], [1, 0x80000000, 0x7fffffff], [0, 0x80000000, 0x7fffffff], [1, 0, 0xdeadbeef], [0, 0x12345678, 0x9abcdef0], [1, 0x9abcdef0, 0x12345678]],
    hints: ['m = −bit: for bit = 1 that is −1, which in 32-bit two\'s complement is ffffffff.', '(x ^ y) & m is x ⊕ y or 0; XOR it onto y.', 'function ctSelect(bit, x, y) {\n  const m = -bit;\n  return (y ^ ((x ^ y) & m)) >>> 0;\n}'],
    solution: 'function ctSelect(bit, x, y) {\n  const m = -bit;\n  return (y ^ ((x ^ y) & m)) >>> 0;\n}\n',
    wrong: ['function ctSelect(bit, x, y) {\n  const m = -bit;\n  return y ^ ((x ^ y) & m);\n}\n', 'function ctSelect(bit, x, y) {\n  const m = bit - 1;\n  return (y ^ ((x ^ y) & m)) >>> 0;\n}\n', 'function ctSelect(bit, x, y) {\n  return ((x & bit) | (y & (1 - bit))) >>> 0;\n}\n'],
  });
  ex({
    id: 'im-x-code-min', chapter: 'im-ch-ct', title: 'Write a branch-free minimum', level: 3, kind: 'code', fn: 'ctMin', params: ['a', 'b'], radix: 16, width: 8,
    text: ['Write `ctMin(a, b)` for unsigned 32-bit words a and b: return the smaller, as an unsigned 32-bit number, with no branch and no `<` on the values.', 'Get the bit lt = 1 if a < b (unsigned) from the borrow of a − b: lt = (a ⊕ ((a ⊕ b) | ((a − b) ⊕ a))) ≫ 31, where a − b is taken as a 32-bit word. Then select with a mask. The tests include words with the top bit set, where a signed comparison gets the order wrong.'],
    start: 'function ctMin(a, b) {\n  \n}\n',
    ref: (a, b) => Math.min(a, b) >>> 0,
    cases: [[5, 9], [9, 5], [7, 7], [0, 0xffffffff], [0xffffffff, 0], [0x80000000, 0x7fffffff], [0x7fffffff, 0x80000000], [0x80000001, 0x80000000], [0, 0x80000001], [0xfffffffe, 0xffffffff], [0x9e3779b9, 0x3c5a96f0], [0x12345678, 0x12345679]],
    hints: ['The 32-bit difference is (a - b) >>> 0. Its top bit alone is not the answer when a and b are far apart, which is why the formula mixes in a ⊕ b.', 'lt = ((a ^ ((a ^ b) | (((a - b) >>> 0) ^ a))) >>> 31); then m = −lt and min = b ⊕ ((a ⊕ b) & m).', 'function ctMin(a, b) {\n  const lt = (a ^ ((a ^ b) | (((a - b) >>> 0) ^ a))) >>> 31;\n  const m = -lt;\n  return (b ^ ((a ^ b) & m)) >>> 0;\n}'],
    solution: 'function ctMin(a, b) {\n  const lt = (a ^ ((a ^ b) | (((a - b) >>> 0) ^ a))) >>> 31;\n  const m = -lt;\n  return (b ^ ((a ^ b) & m)) >>> 0;\n}\n',
    wrong: ['function ctMin(a, b) {\n  const m = (a - b) >> 31;\n  return (b ^ ((a ^ b) & m)) >>> 0;\n}\n', 'function ctMin(a, b) {\n  const lt = (((a - b) >>> 0) >>> 31);\n  return (b ^ ((a ^ b) & -lt)) >>> 0;\n}\n', 'function ctMin(a, b) {\n  const lt = (a ^ ((a ^ b) | (((a - b) >>> 0) ^ a))) >>> 31;\n  return (a ^ ((a ^ b) & -lt)) >>> 0;\n}\n'],
  });
  ex({
    id: 'im-x-branch', chapter: 'im-ch-ct', title: 'A fix that is not one', level: 2, kind: 'choice',
    text: ['A colleague removes the multiplication that depends on a key bit from an exponentiation loop:', { code: '// before\nif (bit) r = (r * x) % N;\n\n// after\nconst t = (r * x) % N;\nif (bit) r = t;' }, 'Is the new loop constant time?'],
    options: ['Yes: the multiplication now happens for every bit', 'No: the assignment still depends on a branch on the secret bit; select t or r with a mask instead', 'Yes, as long as N is public', 'No: the multiplication must be removed altogether'],
    answer: 1,
    whyNot: { 0: 'The multiplication is fixed, but `if (bit)` remains a branch on the secret: a conditional jump the predictor and the timer can see.', 2: 'Whether N is public does not matter; the branch is on the key bit.', 3: 'Multiplying every time is right; it is the choice of the result that must not branch.' },
    hints: ['Look for any `if` whose condition is a secret.', 'The work is now equal, but the control flow still splits on bit.', 'Replace `if (bit) r = t;` with a mask select, r = select(bit, t, r), so the same instructions run for both values of the bit. With BigInt values, use a constant-time conditional swap from a vetted library rather than writing one.'],
    solution: 1, wrong: [0, 2, 3],
  });

  // a 4-bit S-box (the one published in the PRESENT block cipher specification) for the lookup exercise
  const PRESENT = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2];
  ex({
    id: 'im-x-code-lookup', chapter: 'im-ch-ct', title: 'Write a lookup that reads every entry', level: 3, kind: 'code', fn: 'ctLookup', params: ['table', 'idx'], decimalArgs: [1],
    text: ['Write `ctLookup(table, idx)`: table is an array of small numbers (here 16 entries of 4 bits), idx a secret index. Return `table[idx]`, but read every entry of the table, in order, and keep the wanted one with a mask, so that the memory touched does not depend on idx.', 'For each i, make m all ones when i = idx and 0 otherwise without a comparison: `-(((i ^ idx) - 1) >>> 31)` does it. The tests check the values on every index of two tables.'],
    start: 'function ctLookup(table, idx) {\n  \n}\n',
    ref: (table, idx) => table[idx],
    cases: [...Array.from({ length: 16 }, (_, i) => [PRESENT, i]), ...[0, 5, 15].map((i) => [PRESENT.map((v) => v ^ 0xa), i])],
    hints: ['i ^ idx is 0 only at the wanted entry; subtracting 1 makes it −1 there and non-negative elsewhere.', 'm = -(((i ^ idx) - 1) >>> 31) is −1 (all ones) at i = idx and 0 elsewhere; then r |= table[i] & m.', 'function ctLookup(table, idx) {\n  let r = 0;\n  for (let i = 0; i < table.length; i++) {\n    const m = -(((i ^ idx) - 1) >>> 31);\n    r |= table[i] & m;\n  }\n  return r;\n}'],
    solution: 'function ctLookup(table, idx) {\n  let r = 0;\n  for (let i = 0; i < table.length; i++) {\n    const m = -(((i ^ idx) - 1) >>> 31);\n    r |= table[i] & m;\n  }\n  return r;\n}\n',
    wrong: ['function ctLookup(table, idx) {\n  let r = 0;\n  for (let i = 0; i < table.length; i++) {\n    const m = -((i ^ idx) >>> 31);\n    r |= table[i] & m;\n  }\n  return r;\n}\n', 'function ctLookup(table, idx) {\n  let r = 0;\n  for (let i = 0; i < table.length; i++) r |= table[i];\n  return r;\n}\n'],
  });
  ex({
    id: 'im-x-lookup-fix', chapter: 'im-ch-ct', title: 'Removing a cache leak from AES', level: 2, kind: 'choice',
    text: ['A service encrypts with a table-based AES whose first-round table index is pᵢ ⊕ kᵢ, on servers shared with other customers. Which changes remove the dependence of the cache state on the key?'],
    options: ['Switch to the processor\'s AES instructions', 'Add a random delay after each encryption', 'Use a bitsliced AES that has no tables', 'Make the tables larger so that each entry has its own cache line'],
    answer: [0, 2],
    hints: ['A fix must make the addresses touched independent of the key, not just harder to measure.', 'A random delay adds noise to the time but leaves the cache lines touched unchanged; larger tables make every index its own line, which leaks more.', 'The AES instructions and a bitsliced implementation both compute the S-box without any secret memory address.'],
    solution: [0, 2], wrong: [[0, 1, 2], [3], [1, 2]],
  });

  // =========================================================================================================
  // Chapter 3: countermeasures in practice
  // =========================================================================================================
  const shCells = { 'x = 6c, m = 5a|the other share': '36', 'x = 6c, m = 5a|its weight': '4', 'x = b8, m = 2f|the other share': '97', 'x = b8, m = 2f|its weight': '5', 'x = 00, m = 9d|the other share': '9d', 'x = 00, m = 9d|its weight': '5', 'x = 9e, shares 4d and e1|the other share': '32', 'x = 9e, shares 4d and e1|its weight': '3' };
  ex({
    id: 'im-x-shares', chapter: 'im-ch-defend', title: 'Mask shares of a byte', level: 1, kind: 'table', cellKind: 'hex',
    text: ['In Boolean masking a secret byte x is held as shares that XOR to x. For the first three rows, x is held as (x ⊕ m, m): give the share x ⊕ m and its Hamming weight. In the last row x is split into three shares, two of which are given: give the third and its weight.'],
    rows: ['x = 6c, m = 5a', 'x = b8, m = 2f', 'x = 00, m = 9d', 'x = 9e, shares 4d and e1'], cols: ['the other share', 'its weight'], corner: 'secret and mask',
    cells: shCells,
    hints: ['The shares must XOR back to x, so the missing share is x XORed with the shares you have.', '6c ⊕ 5a = 36, b8 ⊕ 2f = 97, 00 ⊕ 9d = 9d, and 9e ⊕ 4d ⊕ e1 = 32.', 'Shares 36, 97, 9d, 32 with weights 4, 5, 5, 3. Note that x = 00 has weight 0, but its masked share weighs 5: with a fresh mask, the weight of a share says nothing about x.'],
    solution: shCells,
    wrong: [Object.assign({}, shCells, { 'x = 9e, shares 4d and e1|the other share': 'd3' }), Object.assign({}, shCells, { 'x = 00, m = 9d|its weight': '0' })],
  });
  const mbCells = { 'x = 6c, S(x) = 50|index x ⊕ mIn': '36', 'x = 6c, S(x) = 50|entry T[x ⊕ mIn]': '93', 'x = 00, S(x) = 63|index x ⊕ mIn': '5a', 'x = 00, S(x) = 63|entry T[x ⊕ mIn]': 'a0', 'x = a7, S(x) = 5c|index x ⊕ mIn': 'fd', 'x = a7, S(x) = 5c|entry T[x ⊕ mIn]': '9f', 'x = f1, S(x) = a1|index x ⊕ mIn': 'ab', 'x = f1, S(x) = a1|entry T[x ⊕ mIn]': '62' };
  ex({
    id: 'im-x-masked-sbox', chapter: 'im-ch-defend', title: 'A masked S-box lookup', level: 2, kind: 'table', cellKind: 'hex',
    text: ['A masked AES recomputes its S-box table for the masks mIn = 5a and mOut = c3 as T[x ⊕ mIn] = S(x) ⊕ mOut, so it only ever handles x ⊕ mIn and S(x) ⊕ mOut. For each x (its S-box value is given), give the index the device actually reads and the entry it gets back.'],
    rows: ['x = 6c, S(x) = 50', 'x = 00, S(x) = 63', 'x = a7, S(x) = 5c', 'x = f1, S(x) = a1'], cols: ['index x ⊕ mIn', 'entry T[x ⊕ mIn]'], corner: 'value',
    cells: mbCells,
    hints: ['The index is x ⊕ 5a; the entry is S(x) ⊕ c3.', 'For x = 6c: index 6c ⊕ 5a = 36, entry 50 ⊕ c3 = 93. These match the masking topic\'s own example.', 'Indexes 36, 5a, fd, ab; entries 93, a0, 9f, 62. Removing mOut from an entry gives S(x) back, but the device does that only at the very end, and with fresh masks next time.'],
    solution: mbCells,
    wrong: [Object.assign({}, mbCells, { 'x = 00, S(x) = 63|entry T[x ⊕ mIn]': '39' }), Object.assign({}, mbCells, { 'x = a7, S(x) = 5c|index x ⊕ mIn': 'a7' })],
  });
  ex({
    id: 'im-x-traces', chapter: 'im-ch-defend', title: 'Sizing the noise: how many traces', level: 2, kind: 'number',
    text: ['When you evaluate an unmasked device, a rule of thumb predicts how many traces a correlation measurement needs to single out one key byte: N ≈ c / ρ², with ρ ≈ √(2 / (2 + σ²)) for a byte\'s Hamming weight under Gaussian noise of standard deviation σ. Take c = 25. How many traces does the rule predict at σ = 4?'],
    answer: 225,
    hints: ['ρ² = 2 / (2 + σ²) = 2 / 18 = 1/9.', 'N ≈ 25 / (1/9).', '25 × 9 = 225. The part\'s trace-count topic measured a median of 200 at σ = 4, close to the rule. At σ = 8 the rule gives 825: doubling the noise only about quadruples the cost.'],
    solution: '225', wrong: ['200', '75', '100'],
    whyNot: { 200: 'That is the median the topic measured; the rule with c = 25 gives a slightly different number.', 75: 'That is the rule at σ = 2: use σ² = 16.', 100: 'Divide c by ρ², not by ρ.', '*': 'Compute ρ² = 2 / (2 + σ²) first, then c / ρ².' },
  });
  ex({
    id: 'im-x-noise-design', chapter: 'im-ch-defend', title: 'Noise alone against a million traces', level: 3, kind: 'number', tolerance: 1,
    text: ['A designer wants an unmasked device to need at least 1 000 000 traces per key byte, using noise alone. With the rule N ≈ c·(2 + σ²) / 2 and c = 25, what noise standard deviation σ (in the same units as one bit of Hamming weight) is needed? Give it to the nearest whole number.'],
    answer: 283,
    hints: ['Solve 12.5·(2 + σ²) = 1 000 000.', '2 + σ² = 80 000, so σ² = 79 998.', 'σ = √79 998 ≈ 282.8, about 283 times the power of one bit. Real hardware cannot drown a signal that much at a sensible cost, which is why masking, not noise, is the main defence; noise multiplies the cost of whatever leak masking leaves.'],
    solution: '283', wrong: ['80000', '200', '4'],
    whyNot: { 80000: 'That is 2 + σ²; take the square root.', '*': 'Solve 12.5·(2 + σ²) = 10⁶ for σ.' },
  });
  ex({
    id: 'im-x-share-order', chapter: 'im-ch-defend', title: 'Shares and the order of a measurement', level: 2, kind: 'number',
    text: ['With one mask, x is held as two shares, and a measurement has to combine two time samples (one for each share) before it correlates with x: a second-order measurement. A designer moves to masking with three shares, x = s₀ ⊕ s₁ ⊕ s₂, each pair of them uniformly random. How many samples must a measurement combine at least?'],
    answer: 3,
    hints: ['Any set of shares smaller than all of them is uniformly random and independent of x.', 'With two shares, two samples had to be combined; the pattern is one sample per share.', 'Three: every share must be in the combination. With noise, the traces needed grow roughly like σ to the power of twice the order, so each extra share is worth a great deal.'],
    solution: '3', wrong: ['2', '4', '1'],
    whyNot: { 2: 'Any two of the three shares are random and independent of x.', 4: 'One sample per share suffices: there are three shares.', 1: 'A single share is uniformly random.', '*': 'Count the shares: all of them must be combined.' },
  });
  ex({
    id: 'im-x-verify-cost', chapter: 'im-ch-defend', title: 'The cost of checking a signature', level: 1, kind: 'number',
    text: ['An RSA signer checks every signature before releasing it by computing s^e mod N with e = 65537 = 2¹⁶ + 1, by square-and-multiply. How many modular multiplications (squarings included) does the check take?'],
    answer: 17,
    hints: ['65537 in binary is 1 followed by fifteen 0s and a 1: 17 bits.', 'After the leading 1, there are 16 bits: 16 squarings, and one multiplication for the final 1.', '16 + 1 = 17 multiplications, next to roughly 3000 for the two half-size exponentiations of a 2048-bit CRT signature (about 1535 each): the check is almost free.'],
    solution: '17', wrong: ['16', '65537', '32'],
    whyNot: { 16: 'Count the multiplication for the last 1 bit too.', 65537: 'Square-and-multiply needs one squaring per bit, not one multiplication per unit of e.', '*': 'Write 65537 in binary and count squarings and multiplications.' },
  });
  ex({
    id: 'im-x-fault-fit', chapter: 'im-ch-defend', title: 'A defence for glitches', level: 2, kind: 'choice',
    text: ['A hardware token signs with RSA-CRT. Its threat model includes an attacker who holds the token and can inject brief glitches on its supply voltage while it signs. Which countermeasure answers that threat directly?'],
    options: ['Masking the exponent with a fresh random value', 'A constant-time comparison of the message', 'Verifying s^e ≡ m (mod N) before releasing s, and releasing nothing if it fails', 'Adding random delays between the two half exponentiations'],
    answer: 2,
    whyNot: { 0: 'Masking answers power analysis; a glitched half-result still leaves the device.', 1: 'The threat is a corrupted result, not a timing leak.', 3: 'Delays may make a glitch harder to time, but a faulty signature that does get through is just as damaging.' },
    hints: ['The threat is a wrong result, not a measured one.', 'What stops a wrong signature from ever leaving the token?', 'Verify before release: the faulty signature fails the check with the public exponent and is never output. Masking and constant time remain useful for the token\'s other threats.'],
    solution: 2, wrong: [0, 1, 3],
  });
  ex({
    id: 'im-x-ttest', chapter: 'im-ch-defend', title: 'A timing test on your own code', level: 3, kind: 'number', tolerance: 0.02,
    text: ['You test a comparison function for constant time. You time it 10 000 times on a fixed input and 10 000 times on random inputs. The fixed class has mean 1000.0 cycles and standard deviation 20; the random class has mean 1002.0 and standard deviation 20. Compute Welch\'s t = (mean₁ − mean₂) / √(s₁²/n₁ + s₂²/n₂), as a positive number to two decimal places. Is the function leaking, by the usual threshold |t| > 4.5?'],
    answer: 7.07,
    hints: ['s²/n = 400 / 10 000 = 0.04 for each class.', '√(0.04 + 0.04) = √0.08 = 0.2828.', 't = 2 / 0.2828 = 7.07, above 4.5: the time depends on the input class, so the function leaks. A 2-cycle difference under 20 cycles of noise is easy to see with enough measurements.'],
    solution: '7.07', wrong: ['25', '2', '0.71'],
    whyNot: { 25: 'Take the square root of s₁²/n₁ + s₂²/n₂.', 2: 'Divide the difference of means by its standard error.', 0.71: 'Use the variance s² = 400, not s = 20, inside the square root.', '*': 'Compute s²/n for each class, add, take the square root, and divide 2 by it.' },
  });
  ex({
    id: 'im-x-threat', chapter: 'im-ch-defend', title: 'Threat model first', level: 2, kind: 'choice',
    text: ['A key-management service runs in virtual machines on a public cloud, next to other customers\' machines on the same processors. No one outside the provider can touch the hardware. Which threat should its AES and RSA code be hardened against first?'],
    options: ['Power analysis with a probe on the processor', 'Cache and timing measurements by a co-resident virtual machine', 'Voltage glitches on the supply', 'None: virtual machines are isolated'],
    answer: 1,
    whyNot: { 0: 'A power probe needs physical access, which this threat model rules out.', 2: 'Glitching needs physical access too.', 3: 'Virtual machines share caches and other microarchitectural state, so timing crosses the boundary.' },
    hints: ['List what an attacker in this setting can actually reach.', 'A neighbour on the same processor shares its caches.', 'Cache and timing: write constant-time code with no secret addresses (AES instructions, constant-time big-number arithmetic). Power and faults need hands on the hardware.'],
    solution: 1, wrong: [0, 2, 3],
  });
  ex({
    id: 'im-x-practice', chapter: 'im-ch-defend', title: 'Good practice', level: 2, kind: 'choice',
    text: ['Which of these are sound engineering practice for cryptographic code?'],
    options: ['Use a vetted library\'s constant-time comparison, such as Node\'s crypto.timingSafeEqual', 'Write your own table-based AES, since it is faster than the library\'s', 'Run a fixed-versus-random timing test with Welch\'s t-test in continuous integration', 'Inspect the compiled code of a mask select to make sure no branch came back', 'Log the key on a failed decryption, to help debugging'],
    answer: [0, 2, 3],
    hints: ['Ask of each: does it reduce the chance that a secret reaches a channel?', 'A home-made table-based AES has secret addresses; logging a key puts it into a channel of its own.', 'Use the library, test timing statistically, and check the compiled code. Never log secrets, and do not write table-based ciphers for shared hardware.'],
    solution: [0, 2, 3], wrong: [[0, 1, 2, 3], [0, 2], [0, 2, 3, 4]],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
