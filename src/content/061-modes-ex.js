// Part 6, modes of operation: the exercises, the guided tour and the course. The lessons are in 060-modes.js. The
// exercises are about correct use: computing what a mode does, choosing a mode, and spotting misuse in a design. The
// code exercises are checked against the engines (S.Modes, S.AES) and the published vectors of NIST SP 800-38A;
// every other value is our own and was worked out by the engines.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('mo-x-ecb-count')) return;
  const ex = (o) => C.exercise(o);
  const h2 = (v) => v.toString(16).padStart(2, '0');
  const fx = (s) => Uint8Array.from(String(s).replace(/\s+/g, '').match(/../g).map((x) => parseInt(x, 16)));
  const enc = (t) => new TextEncoder().encode(t);

  // A compact AES-128 for the code exercises, given in the starting code so the student writes only the mode.
  const AES_SRC = 'const SBOX = (\n' + Array.from(S.gf256.SBOX, h2).join('').match(/.{32}/g).map((r) => '  "' + r + '"').join(' +\n') + '\n).match(/../g)\n  .map((h) => parseInt(h, 16));\n'
    + '// AES-128 on one block: key and\n'
    + '// block are arrays of 16 bytes.\n'
    + 'function aesEncrypt(key, block) {\n'
    + '  const xt = (b) =>\n'
    + '    ((b << 1) ^ (b & 128 ? 27 : 0)) & 255;\n'
    + '  const w = Array.from(key);\n'
    + '  let rc = 1;\n'
    + '  for (let i = 16; i < 176; i += 4) {\n'
    + '    let t = w.slice(i - 4, i);\n'
    + '    if (i % 16 === 0) {\n'
    + '      t = [SBOX[t[1]] ^ rc, SBOX[t[2]],\n'
    + '        SBOX[t[3]], SBOX[t[0]]];\n'
    + '      rc = xt(rc);\n'
    + '    }\n'
    + '    for (let j = 0; j < 4; j++)\n'
    + '      w[i + j] = w[i - 16 + j] ^ t[j];\n'
    + '  }\n'
    + '  let s = Array.from(block,\n'
    + '    (b, i) => b ^ w[i]);\n'
    + '  for (let r = 1; r <= 10; r++) {\n'
    + '    // SubBytes and ShiftRows\n'
    + '    const t = [];\n'
    + '    for (let i = 0; i < 16; i++)\n'
    + '      t[i] = SBOX[s[(5 * i) % 16]];\n'
    + '    // MixColumns, except in round 10\n'
    + '    if (r < 10)\n'
    + '    for (let c = 0; c < 16; c += 4) {\n'
    + '      const a = t[c], b = t[c + 1];\n'
    + '      const d = t[c + 2], e = t[c + 3];\n'
    + '      const x = a ^ b ^ d ^ e;\n'
    + '      t[c] ^= x ^ xt(a ^ b);\n'
    + '      t[c + 1] ^= x ^ xt(b ^ d);\n'
    + '      t[c + 2] ^= x ^ xt(d ^ e);\n'
    + '      t[c + 3] ^= x ^ xt(e ^ a);\n'
    + '    }\n'
    + '    s = t.map((v, i) =>\n'
    + '      v ^ w[16 * r + i]);\n'
    + '  }\n'
    + '  return s;\n'
    + '}\n'
    + '\n';
  // SP 800-38A, appendix F: the AES-128 key and the four plaintext blocks of every example
  const K38 = '2b7e151628aed2a6abf7158809cf4f3c';
  const P38 = '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710';
  const OWNKEY = '686172626f75722d6c616d702d6b6579'; // “harbour-lamp-key”
  // Code tests pass bytes as plain arrays of Numbers: they cross into the sandbox and back as they are.
  const U8 = (a) => Uint8Array.from(a);
  const cbcRef = (key, iv, data) => Array.from(S.Modes.encrypt('cbc', S.AES.cipher(U8(key)), U8(data), { iv: U8(iv), trace: false }).out);
  const ctrRef = (key, ctr, data) => Array.from(S.Modes.encrypt('ctr', S.AES.cipher(U8(key)), U8(data), { iv: U8(ctr), trace: false }).out);
  const hex = (a) => Array.from(a, h2).join('');
  const hexOf = (t) => hex(enc(t));
  const arr = (x) => (x === '' ? [] : Array.from(fx(x)));
  const Z16 = '00000000000000000000000000000000';
  const CBC_SOL = 'function cbcEncrypt(key, iv, data) {\n  const out = [];\n  let prev = iv;\n  for (let i = 0; i < data.length; i += 16) {\n    const x = data.slice(i, i + 16).map((b, j) => b ^ prev[j]);\n    prev = aesEncrypt(key, x);\n    out.push(...prev);\n  }\n  return out;\n}';
  const INC_SOL = 'function ctrIncrement(block) {\n  const c = block.slice();\n  for (let k = 15; k >= 0; k--) {\n    c[k] = (c[k] + 1) & 0xff;\n    if (c[k] !== 0) break;\n  }\n  return c;\n}';
  const CTR_SOL = 'function ctrEncrypt(key, counter, data) {\n  const out = [];\n  const c = counter.slice();\n  for (let i = 0; i < data.length; i += 16) {\n    const ks = aesEncrypt(key, c);\n    for (let j = 0; j < 16 && i + j < data.length; j++) out.push(data[i + j] ^ ks[j]);\n    for (let k = 15; k >= 0; k--) { c[k] = (c[k] + 1) & 0xff; if (c[k]) break; }\n  }\n  return out;\n}';
  const PAD_SOL = 'function pkcs7Pad(data, n) {\n  const k = n - (data.length % n);\n  return data.concat(new Array(k).fill(k));\n}';
  const UNPAD_SOL = 'function pkcs7Unpad(data, n) {\n  const k = data[data.length - 1];\n  if (!(k >= 1 && k <= n) || k > data.length) return null;\n  for (let i = data.length - k; i < data.length; i++) if (data[i] !== k) return null;\n  return data.slice(0, data.length - k);\n}';

  // =========================================================================================================
  // Chapter 1: ECB and CBC
  // =========================================================================================================
  ex({
    id: 'mo-x-ecb-count', chapter: 'mo-block', title: 'Repeats under ECB', level: 1, kind: 'number',
    text: ['A ticket office broadcasts its seat board, encrypted with AES in ECB under one key. The plaintext is six 16-byte blocks: “ROW 7: SEAT FREE”, “ROW 8: SEAT SOLD”, “ROW 7: SEAT FREE”, “ROW 9: SEAT FREE”, “ROW 7: SEAT FREE”, “ROW 8: SEAT SOLD”. How many different ciphertext blocks are sent?'],
    answer: 3,
    hints: ['In ECB each block is encrypted on its own: equal blocks give equal ciphertext.', 'Count the distinct plaintext blocks: “ROW 7 … FREE”, “ROW 8 … SOLD” and “ROW 9 … FREE”.', '3. An eavesdropper sees the pattern A B A C A B without knowing the key: which rows match is already leaked.'],
    solution: '3', wrong: ['6', '2', '4'],
    whyNot: 'Equal plaintext blocks under one key give equal ciphertext blocks; count the distinct blocks.',
  });
  ex({
    id: 'mo-x-ecb-spot', chapter: 'mo-block', title: 'Spot the misuse: an encrypted column', level: 2, kind: 'choice',
    text: ['A design note: “Salaries are stored encrypted. Each salary is a 16-byte record, encrypted with AES-256 in ECB mode under one database key, so that equal records can still be indexed.” What is the problem, and the fix?'],
    options: ['AES-256 is too slow for a database', 'ECB gives equal salaries equal ciphertexts, so anyone who reads the table sees who earns the same, and can find a salary by encrypting nothing at all: one known salary reveals every equal one. Use a randomised mode (an AEAD such as GCM with a fresh nonce per record), and index by a separate keyed hash only if equality search is truly needed', 'The key should be 128 bits, not 256', 'Nothing is wrong: the records are encrypted'],
    answer: 1,
    hints: ['What does ECB do with two equal blocks?', 'Equal salaries become equal ciphertexts. “So that equal records can still be indexed” is the leak, stated as a feature.', 'The equality of records is visible. Encrypt each record with a fresh nonce (GCM), and if equality search is needed, add it deliberately with a keyed hash, knowing what it reveals.'],
    solution: 1, wrong: [3, 2],
    whyNot: { 3: 'Encryption that keeps equality visible leaks: compare two ciphertexts and you know whether the salaries match.', 2: 'The key length is not the problem; the mode is.' },
  });
  ex({
    id: 'mo-x-cbc-dec', chapter: 'mo-block', title: 'Decrypt a CBC block', level: 1, kind: 'hex',
    text: ['In CBC decryption, Pᵢ = Dₖ(Cᵢ) ⊕ Cᵢ₋₁. The block cipher gave Dₖ(C₂) = 5f d5 8d 74 de 6e 70 51 f4 85 2d d8 81 1b dc 16, and C₁ = 7f a5 e4 11 ac 4e 46 71 96 fc 0d bc f4 68 b7 37. Give P₂ in hex.'],
    answer: '20706965722036206279206475736b21',
    hints: ['XOR the two blocks byte by byte.', '5f ⊕ 7f = 20 (a space), d5 ⊕ a5 = 70 (“p”).', 'P₂ = 20 70 69 65 72 20 36 20 62 79 20 64 75 73 6b 21, the text “ pier 6 by dusk!”.'],
    solution: '20706965722036206279206475736b21', wrong: ['5fd58d74de6e7051f4852dd8811bdc16', '20706965722036206279206475736b20'],
    whyNot: 'XOR Dₖ(C₂) with the previous ciphertext block, C₁.',
  });
  ex({
    id: 'mo-x-cbc-error', chapter: 'mo-block', title: 'A damaged block in CBC', level: 1, kind: 'choice',
    text: ['A CBC ciphertext of five blocks is stored on a disk, and one bit of C₃ is damaged. After decryption, which plaintext blocks are affected?'],
    options: ['P₃ only', 'P₃ entirely garbled, and one bit of P₄ flipped', 'P₃, P₄ and P₅, all garbled', 'Every block'],
    answer: 1,
    hints: ['Pᵢ = Dₖ(Cᵢ) ⊕ Cᵢ₋₁: C₃ is used twice, in P₃ and in P₄.', 'In P₃ the damaged C₃ goes through the cipher, which scrambles it. In P₄ it is only XORed.', 'P₃ is garbled, and P₄ has the same single bit flipped. P₅ uses C₄ and C₅, which are intact.'],
    solution: 1, wrong: [0, 2],
    whyNot: { 0: 'C₃ is also XORed into P₄.', 2: 'CBC decryption recovers after two blocks: P₅ uses only C₄ and C₅.' },
  });
  ex({
    id: 'mo-x-cbc-iv', chapter: 'mo-block', title: 'Spot the misuse: the IV', level: 2, kind: 'choice',
    text: ['Which of these ways of choosing the CBC IV are sound? Choose all that apply.'],
    options: ['A new IV from a cryptographic random generator for every message, sent with the ciphertext', 'The same fixed IV for every message, kept secret', 'A message counter: 1, 2, 3, … sent as the IV', 'The last ciphertext block of the previous message', 'A nonce encrypted under the key (a unique counter, encrypted, used as the IV)'],
    answer: [0, 4],
    hints: ['The IV must be unpredictable to an attacker and new for every message.', 'A fixed IV repeats; a counter and the last ciphertext block are known in advance, which lets a chosen-plaintext attacker test guesses.', 'Options 1 and 5: random IVs, or a unique counter encrypted under the key, which makes it unpredictable.'],
    solution: [0, 4], wrong: [[0], [0, 2, 4], [1]],
  });
  ex({
    id: 'mo-x-code-cbc', chapter: 'mo-block', title: 'Write CBC encryption', level: 2, kind: 'code', fn: 'cbcEncrypt', radix: 16, params: ['key', 'iv', 'data'],
    text: ['Write `cbcEncrypt(key, iv, data)`. Bytes are arrays of Numbers from 0 to 255: `key` and `iv` hold 16, and `data` a whole number of 16-byte blocks (padding is already done). Return the ciphertext as an array of bytes. `aesEncrypt(key, block)` is given, and returns a 16-byte array. The first test is the CBC-AES128.Encrypt example of NIST SP 800-38A, appendix F.2.1, with IV 00 01 … 0f; its first ciphertext block is 76 49 ab ac 81 19 b2 46 ce e9 8e 9b 12 e9 19 7d.'],
    start: AES_SRC + 'function cbcEncrypt(key, iv, data) {\n  \n}\n',
    ref: cbcRef,
    cases: [[K38, '000102030405060708090a0b0c0d0e0f', P38], [K38, '000102030405060708090a0b0c0d0e0f', P38.slice(0, 32)], [OWNKEY, '3c91e7a24f0b68d5172ec9a083f64b1d', hexOf('Unload crates at pier 6 by dusk!')], [OWNKEY, Z16, Z16 + Z16 + Z16], [K38, 'ffffffffffffffffffffffffffffffff', hexOf('HOLD THE BRIDGE.HOLD THE BRIDGE.')]].map((c) => c.map(arr)),
    hints: ['Keep a variable `prev`, starting as the IV. For each block: XOR it with `prev`, encrypt, append the result, and make it the new `prev`.', 'The blocks are `data.slice(i, i + 16)` for i = 0, 16, 32, …; XOR with `.map((b, j) => b ^ prev[j])`.', AES_SRC + CBC_SOL],
    solution: AES_SRC + CBC_SOL + '\n',
    wrong: [AES_SRC + 'function cbcEncrypt(key, iv, data) {\n  const out = [];\n  for (let i = 0; i < data.length; i += 16) out.push(...aesEncrypt(key, data.slice(i, i + 16).map((b, j) => b ^ iv[j])));\n  return out;\n}\n', AES_SRC + 'function cbcEncrypt(key, iv, data) {\n  const out = [];\n  let prev = iv;\n  for (let i = 0; i < data.length; i += 16) {\n    out.push(...aesEncrypt(key, data.slice(i, i + 16).map((b, j) => b ^ prev[j])));\n    prev = data.slice(i, i + 16);\n  }\n  return out;\n}\n'],
  });

  // =========================================================================================================
  // Chapter 2: CFB, OFB and CTR
  // =========================================================================================================
  ex({
    id: 'mo-x-ofb-cfb', chapter: 'mo-stream', title: 'CFB or OFB?', level: 2, kind: 'choice',
    text: ['A link sometimes flips single bits but never loses whole blocks. Which statement about CFB and OFB (full-block segments) is right?'],
    options: ['In OFB a flipped ciphertext bit flips only the same plaintext bit; in CFB it flips that bit and garbles the whole next block', 'Both garble every block after the error', 'In CFB a flipped bit affects only that bit; in OFB it garbles the next block', 'Neither is affected, since both are stream ciphers'],
    answer: 0,
    hints: ['In OFB the keystream never depends on the ciphertext. In CFB, each ciphertext block is encrypted to make the next keystream block.', 'A changed Cᵢ in CFB changes Eₖ(Cᵢ), the keystream for block i + 1.', 'OFB: only that bit. CFB: that bit, then the whole next block, and then it recovers.'],
    solution: 0, wrong: [2, 3],
    whyNot: { 2: 'It is the other way round: CFB feeds the ciphertext back, OFB does not.', 3: 'The bit itself always flips; the question is what else is affected.' },
  });
  ex({
    id: 'mo-x-ctr-inc', chapter: 'mo-stream', title: 'The next counter block', level: 1, kind: 'hex',
    text: ['In CTR mode the counter block is incremented as one 128-bit big-endian number. What follows 5f1a7c3e 9b2d4f60 00000000 ffffffff?'],
    answer: '5f1a7c3e9b2d4f600000000100000000',
    hints: ['Add 1 to the last byte, and carry into the byte before while a byte wraps from ff to 00.', 'The last four bytes ff ff ff ff all wrap to 00, and the carry reaches byte 11.', '5f1a7c3e 9b2d4f60 00000001 00000000.'],
    solution: '5f1a7c3e9b2d4f600000000100000000', wrong: ['5f1a7c3e9b2d4f600000000000000000', '5f1a7c3e9b2d4f6000000000ffffff00', '5f1a7c3e9b2d4f600000000100000001'],
    whyNot: 'Carry the 1 through every ff byte from the right.',
  });
  ex({
    id: 'mo-x-ctr-xor', chapter: 'mo-stream', title: 'One CTR block', level: 1, kind: 'hex',
    text: ['The keystream block Eₖ(counter) is 5f c2 0c 43 4b d1 7f d1 bf ad b2 a5 70 55 92 37, and the plaintext block is “Gulls nest early” (47 75 6c 6c 73 20 6e 65 73 74 20 65 61 72 6c 79). Give the ciphertext block.'],
    answer: '18b7602f38f111b4ccd992c01127fe4e',
    hints: ['C = P ⊕ Eₖ(counter); the block cipher is not applied to the plaintext.', '47 ⊕ 5f = 18 and 75 ⊕ c2 = b7.', 'C = 18 b7 60 2f 38 f1 11 b4 cc d9 92 c0 11 27 fe 4e.'],
    solution: '18b7602f38f111b4ccd992c01127fe4e', wrong: ['5fc20c434bd17fd1bfadb2a570559237', '18b7602f38f111b4ccd992c01127fe4f'],
    whyNot: 'XOR the plaintext with the keystream, byte by byte.',
  });
  ex({
    id: 'mo-x-ctr-far', chapter: 'mo-stream', title: 'Jump to a far block', level: 2, kind: 'hex',
    text: ['A file is encrypted in CTR mode; block 1 uses the counter block 0c21a4e9 5b7d3f88 00000000 fffffff0, and each block adds one, as a 128-bit number. Which counter block does block 70 000 use?'],
    answer: '0c21a4e95b7d3f88000000010001115f',
    hints: ['Block 70 000 uses start + 69 999. In hex, 69 999 = 1116f.', 'Add 1116f to the low bytes: fffffff0 + 0001116f = 1 0001115f, which carries into the next 32-bit word.', '0c21a4e9 5b7d3f88 00000001 0001115f. A counter that only wrapped its low 32 bits would give …00000000 0001115f and repeat counters from an earlier message range: here the full 128-bit increment carries over.'],
    solution: '0c21a4e95b7d3f88000000010001115f', wrong: ['0c21a4e95b7d3f88000000000001115f', '0c21a4e95b7d3f88000000010001116f', '0c21a4e95b7d3f8800000000fffffff0'],
    whyNot: 'Add 69 999 (1116f in hex) to the whole 128-bit counter, carrying past the lowest 32 bits.',
  });
  ex({
    id: 'mo-x-code-ctrinc', chapter: 'mo-stream', title: 'Write the counter increment', level: 1, kind: 'code', fn: 'ctrIncrement', radix: 16, params: ['block'],
    text: ['Write `ctrIncrement(block)`: `block` is an array of 16 bytes (Numbers from 0 to 255); return a new array holding block + 1 as a big-endian 128-bit number, wrapping from all ff to all 00. Do not change `block`. The tests include the counter blocks of NIST SP 800-38A, appendix F.5: f0 f1 … fe ff is followed by f0 f1 … ff 00.'],
    start: 'function ctrIncrement(block) {\n  \n}\n',
    ref: (b) => Array.from(S.Modes.increment(b)),
    cases: ['f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdff00', '5f1a7c3e9b2d4f6000000000ffffffff', 'ffffffffffffffffffffffffffffffff', Z16, '00ffffffffffffffffffffffffffffff'].map((x) => [arr(x)]),
    hints: ['Copy the block first: `const c = block.slice();`.', 'Walk from the last byte: add 1; if it wrapped to 0, carry on to the byte before; otherwise stop.', INC_SOL],
    solution: INC_SOL + '\n',
    wrong: ['function ctrIncrement(block) {\n  const c = block.slice();\n  c[15] = (c[15] + 1) & 0xff;\n  return c;\n}\n', 'function ctrIncrement(block) {\n  const c = block.slice();\n  for (let k = 0; k < 16; k++) {\n    c[k] = (c[k] + 1) & 0xff;\n    if (c[k] !== 0) break;\n  }\n  return c;\n}\n'],
  });
  ex({
    id: 'mo-x-code-ctr', chapter: 'mo-stream', title: 'Write CTR encryption', level: 3, kind: 'code', fn: 'ctrEncrypt', radix: 16, params: ['key', 'counter', 'data'],
    text: ['Write `ctrEncrypt(key, counter, data)`. Bytes are arrays of Numbers from 0 to 255: `key` and `counter` (the first counter block) hold 16, and `data` any number. Return the ciphertext, as long as `data`. `aesEncrypt(key, block)` is given. The first test is the CTR-AES128.Encrypt example of NIST SP 800-38A, appendix F.5.1: its first ciphertext block is 87 4d 61 91 b6 20 e3 26 1b ef 68 64 99 0d b6 ce.'],
    start: AES_SRC + 'function ctrEncrypt(key, counter, data) {\n  \n}\n',
    ref: ctrRef,
    cases: [[K38, 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', P38], [K38, 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', P38.slice(0, 50)], [OWNKEY, '0c21a4e95b7d3f8800000000ffffffff', hexOf('Gulls nest early on the cliffs.')], [OWNKEY, 'ffffffffffffffffffffffffffffffff', hexOf('wrap around!')], [OWNKEY, Z16, '']].map((c) => c.map(arr)),
    hints: ['For each 16-byte piece of data: encrypt the current counter, XOR as many keystream bytes as the piece has, then increment the counter (carrying through every byte).', 'The last piece may be short: stop at `data.length`. Decryption is the same function.', AES_SRC + CTR_SOL],
    solution: AES_SRC + CTR_SOL + '\n',
    wrong: [AES_SRC + 'function ctrEncrypt(key, counter, data) {\n  const ks = aesEncrypt(key, counter);\n  return data.map((b, i) => b ^ ks[i % 16]);\n}\n', AES_SRC + 'function ctrEncrypt(key, counter, data) {\n  const out = [];\n  const c = counter.slice();\n  for (let i = 0; i < data.length; i += 16) {\n    const ks = aesEncrypt(key, c);\n    for (let j = 0; j < 16 && i + j < data.length; j++) out.push(data[i + j] ^ ks[j]);\n    c[15] = (c[15] + 1) & 0xff;\n  }\n  return out;\n}\n'],
  });
  ex({
    id: 'mo-x-parallel', chapter: 'mo-stream', title: 'Which modes encrypt in parallel?', level: 2, kind: 'choice',
    text: ['A server has 16 cores and must encrypt one large file fast. In which modes can the blocks of one message be encrypted in parallel? Choose all that apply.'],
    options: ['ECB', 'CBC', 'CFB', 'OFB', 'CTR', 'XTS'],
    answer: [0, 4, 5],
    hints: ['A block can start only when everything it depends on is known.', 'CBC and CFB need the previous ciphertext block; OFB needs the previous keystream block. ECB, CTR and XTS need only the block\'s own position.', 'ECB, CTR and XTS. (CBC and CFB can still decrypt in parallel, since all the ciphertext is there.) Of these, only CTR is a general-purpose choice; GCM, built on CTR, is parallel too.'],
    solution: [0, 4, 5], wrong: [[4], [0, 1, 4, 5], [4, 5]],
  });

  // =========================================================================================================
  // Chapter 3: disks and authenticated encryption
  // =========================================================================================================
  ex({
    id: 'mo-x-xts-alpha', chapter: 'mo-ae', title: 'The next XTS tweak', level: 2, kind: 'hex',
    text: ['In XTS the tweak for the next block is T·α: treat the 16 bytes as a 128-bit number with byte 0 the least significant, shift it left by one bit, and if a bit falls off the top of byte 15, XOR 87 into byte 0. Compute T·α for T = 3a 7f 0c 11 d2 e4 5b 90 66 a1 c3 f0 0b 8e 27 d4.'],
    answer: 'f3fe1822a4c9b720cd4287e1171c4fa8',
    hints: ['Each byte doubles, and takes in the top bit of the byte before it (byte i − 1) as its new lowest bit.', 'Byte 15 is d4 = 11010100: its top bit is 1, so a bit falls off and 87 goes into byte 0. Byte 0 becomes 74 ⊕ 87 = f3.', 'T·α = f3 fe 18 22 a4 c9 b7 20 cd 42 87 e1 17 1c 4f a8.'],
    solution: 'f3fe1822a4c9b720cd4287e1171c4fa8', wrong: ['74fe1822a4c9b720cd4287e1171c4fa8', '74fe1822a4c9b720cd4287e1171c4fa9'],
    whyNot: 'Carry the top bit of each byte into the next one, and fold the bit that leaves byte 15 back in as 87 at byte 0.',
  });
  ex({
    id: 'mo-x-xts-why', chapter: 'mo-ae', title: 'Choose a mode: a laptop disk', level: 1, kind: 'choice',
    text: ['A laptop encrypts its whole disk. Each 4096-byte sector must stay 4096 bytes, be readable on its own, and there is no space to store an IV per sector. Which mode fits?'],
    options: ['ECB', 'CBC with a random IV per sector', 'XTS with the sector number as the tweak', 'GCM with a random nonce per sector'],
    answer: 2,
    hints: ['The ciphertext must have exactly the size of the data, with nothing extra stored.', 'Random IVs and nonces, and GCM tags, all need extra space; ECB needs none but shows repeated blocks.', 'XTS: the sector number is the tweak, so nothing extra is stored, and equal data in different places encrypts differently.'],
    solution: 2, wrong: [0, 3],
    whyNot: { 0: 'ECB shows which blocks of the disk are equal.', 3: 'GCM needs room for a nonce and a tag in every sector.' },
  });
  ex({
    id: 'mo-x-gcm-j0', chapter: 'mo-ae', title: 'GCM\'s first data counter', level: 1, kind: 'hex',
    text: ['A GCM message uses the 96-bit IV 9b4e21d0 7a3c58f6 e1042b7d. Which counter block encrypts the first block of data?'],
    answer: '9b4e21d07a3c58f6e1042b7d00000002',
    hints: ['A 96-bit IV becomes J0 by appending 00000001.', 'J0 is kept for masking the tag; the data starts at J0 + 1.', '9b4e21d0 7a3c58f6 e1042b7d 00000002.'],
    solution: '9b4e21d07a3c58f6e1042b7d00000002', wrong: ['9b4e21d07a3c58f6e1042b7d00000001', '9b4e21d07a3c58f6e1042b7d', '9b4e21d07a3c58f6e1042b7d00000000'],
    whyNot: 'J0 = IV ‖ 00000001 is used for the tag; data blocks start one later.',
  });
  ex({
    id: 'mo-x-gcm-len', chapter: 'mo-ae', title: 'GCM\'s length block', level: 2, kind: 'hex',
    text: ['GHASH ends with a block holding the length of the associated data and the length of the ciphertext, each in bits as a 64-bit big-endian number. Give this block for 20 bytes of associated data and 37 bytes of ciphertext.'],
    answer: '00000000000000a00000000000000128',
    hints: ['Lengths are in bits: 20 bytes = 160 bits and 37 bytes = 296 bits.', '160 = a0 and 296 = 128 in hex, each written in 8 bytes.', '00000000000000a0 0000000000000128.'],
    solution: '00000000000000a00000000000000128', wrong: ['00000000000000140000000000000025', '00000000000001280000000000000000a0', '000000000000012800000000000000a0'],
    whyNot: 'Count bits, not bytes, and put the associated data first.',
  });
  ex({
    id: 'mo-x-gcm-nonce', chapter: 'mo-ae', title: 'Spot the misuse: a nonce after a reboot', level: 2, kind: 'choice',
    text: ['A design note: “Each meter encrypts its readings with AES-GCM under its own key. The 96-bit nonce is a counter kept in RAM, starting at 0 when the meter powers up, so nonces never repeat.” What is the problem, and the fix?'],
    options: ['GCM needs 128-bit nonces', 'After every power cut the counter starts again at 0, so nonces repeat under the same key: the XOR of plaintexts leaks and tags can be forged. Keep the counter in non-volatile memory and advance it before use (or reserve a block of values at each boot), or derive a fresh key at every boot', 'The counter is predictable, so it must be random', 'Nothing: a counter never repeats'],
    answer: 1,
    hints: ['When does this counter go back to a value it has already used?', 'RAM is cleared by a power cut, and the key stays the same.', 'Nonces repeat after each reboot. The counter must survive restarts (stored before use), or the key must change.'],
    solution: 1, wrong: [2, 3],
    whyNot: { 2: 'GCM nonces need to be unique, not unpredictable: a counter is fine if it never repeats.', 3: 'This counter restarts at every power-up.' },
  });
  ex({
    id: 'mo-x-nonce-birthday', chapter: 'mo-ae', title: 'Random nonces, how many?', level: 2, kind: 'number',
    text: ['Random 96-bit GCM nonces collide with chance about q²/2⁹⁷ after q messages. About how many messages make a collision even odds? Give the exponent of 2, to the nearest whole number.'],
    answer: 48, tolerance: 0.5,
    hints: ['Set q²/2⁹⁷ = 1/2 and solve: q² = 2⁹⁶.', 'q = 2⁴⁸ (more exactly, with the birthday formula, 2^48.2).', '48. NIST\'s limit of 2³² messages per key keeps the chance below about 2⁻³³.'],
    solution: '48', wrong: ['96', '32', '64'],
    whyNot: 'Solve q²/2⁹⁷ = 1/2 for q.',
  });
  ex({
    id: 'mo-x-po-fix', chapter: 'mo-ae', title: 'A padding oracle: the right fix', level: 3, kind: 'choice',
    text: ['A review finds that an API decrypts AES-CBC messages without any MAC, and answers “invalid padding” and “invalid request” with different errors, a known setting for a padding-oracle attack that decrypts messages without the key. Which fix removes the problem at its root?'],
    options: ['Make both errors read “invalid request”', 'Add a random delay to every error', 'Switch to an AEAD mode such as AES-GCM (or encrypt-then-MAC), and reject any message whose tag fails before decrypting or looking at padding', 'Switch from PKCS#7 to ISO/IEC 7816-4 padding'],
    answer: 2,
    hints: ['Hiding the error text still leaves timing and behaviour that can differ.', 'The root cause is that the server decrypts and inspects ciphertexts an attacker has altered.', 'Authenticate first: with a tag over the ciphertext, an altered message is rejected before decryption, so no padding check ever runs on it.'],
    solution: 2, wrong: [0, 3],
    whyNot: { 0: 'The same text helps, but timing and side effects can still tell the cases apart; the server still decrypts forged ciphertexts.', 3: 'Any padding check on unauthenticated data can become an oracle.' },
  });
  ex({
    id: 'mo-x-etm-order', chapter: 'mo-ae', title: 'Which order?', level: 2, kind: 'choice',
    text: ['A legacy system must combine AES-CBC with HMAC-SHA-256. Which construction should it use?'],
    options: ['Encrypt, then compute the HMAC over the IV and the ciphertext with an independent key; the receiver checks the HMAC first', 'Compute the HMAC of the plaintext, append it, then encrypt both', 'Encrypt, and send the HMAC of the plaintext alongside', 'Use the same key for the encryption and the HMAC, to keep key management simple'],
    answer: 0,
    hints: ['The receiver should be able to reject a forged message before it decrypts anything.', 'Only one of the orders lets the receiver check the tag over exactly what it received.', 'Encrypt-then-MAC, over the IV and ciphertext, with independent keys, checked first in constant time.'],
    solution: 0, wrong: [1, 3],
    whyNot: { 1: 'MAC-then-encrypt forces the receiver to decrypt and unpad before it can check anything: the setting of padding oracles.', 3: 'Keys for different purposes must be independent.' },
  });
  ex({
    id: 'mo-x-tag-first', chapter: 'mo-ae', title: 'Spot the misuse: streaming before the tag', level: 3, kind: 'choice',
    text: ['A design note: “To save memory, our client decrypts large AES-GCM downloads chunk by chunk and writes each decrypted chunk straight into the installed application folder; the tag is checked at the end, and the install is cancelled if it fails.” What is the problem, and the fix?'],
    options: ['GCM cannot decrypt large files', 'Unverified plaintext is used before the tag is checked: a tampered download is already written where it can run or be read. Write to a temporary place and use nothing until the tag verifies, or split the file into separately authenticated chunks (each with its own tag, numbered so they cannot be reordered or cut off)', 'The tag is too short', 'Nothing: the install is cancelled if the tag fails'],
    answer: 1,
    hints: ['What exists on disk at the moment the tag check fails?', 'The tampered chunks are already in the application folder before anything has been verified.', 'Release plaintext only after verification: stage it, or authenticate chunks one by one with numbered, final-marked chunks.'],
    solution: 1, wrong: [3, 0],
    whyNot: { 3: 'By the time the install is cancelled, unverified data has already been written where it is used.', 0: 'GCM handles large messages; the issue is using plaintext before its tag is checked.' },
  });
  ex({
    id: 'mo-x-nonce-rules', chapter: 'mo-ae', title: 'Nonce rules', level: 3, kind: 'choice',
    text: ['Which of these nonce schemes for AES-GCM under one long-lived key are sound? Choose all that apply.'],
    options: ['A 96-bit counter stored on disk and advanced before each use', 'A random 96-bit nonce per message, with at most 2³² messages under the key', 'The current time in seconds as the nonce', 'A random 32-bit nonce, padded with zeros to 96 bits', 'Each of two devices sharing the key uses its own fixed device number in the top 32 bits of the nonce and its own stored counter in the rest'],
    answer: [0, 1, 4],
    hints: ['A nonce must never repeat under one key, across restarts and across devices.', 'Time repeats when two messages are sent in the same second or the clock is set back; 32 random bits collide after about 2¹⁶ messages.', 'Options 1, 2 and 5: a persistent counter, random 96-bit nonces within the limit, and disjoint counter spaces per device.'],
    solution: [0, 1, 4], wrong: [[0, 1], [0, 1, 2, 4], [1, 3]],
  });

  // =========================================================================================================
  // Chapter 4: padding, limits and choosing a mode
  // =========================================================================================================
  ex({
    id: 'mo-x-pkcs7', chapter: 'mo-use', title: 'PKCS#7 by hand', level: 1, kind: 'hex',
    text: ['The message “Nets dry on the wall.” is 21 bytes. After PKCS#7 padding to 16-byte blocks, what is the second block? (Its first five bytes are 77 61 6c 6c 2e, “wall.”.)'],
    answer: '77616c6c2e0b0b0b0b0b0b0b0b0b0b0b',
    hints: ['k = 16 − (21 mod 16) bytes are added, each of value k.', 'k = 16 − 5 = 11 = 0b.', '77 61 6c 6c 2e followed by eleven bytes of 0b.'],
    solution: '77616c6c2e0b0b0b0b0b0b0b0b0b0b0b', wrong: ['77616c6c2e0a0a0a0a0a0a0a0a0a0a0a', '77616c6c2e0b', '77616c6c2e8000000000000000000000'],
    whyNot: 'Fill the block to 16 bytes with copies of the number of bytes added.',
  });
  ex({
    id: 'mo-x-iso', chapter: 'mo-use', title: 'ISO/IEC 7816-4 padding', level: 1, kind: 'hex',
    text: ['Pad the same 21-byte message “Nets dry on the wall.” with ISO/IEC 7816-4 padding instead. What is the second block?'],
    answer: '77616c6c2e8000000000000000000000',
    hints: ['The padding is a single 1 bit followed by 0 bits.', 'In bytes: 80, then 00 up to the end of the block.', '77 61 6c 6c 2e 80 and ten 00 bytes.'],
    solution: '77616c6c2e8000000000000000000000', wrong: ['77616c6c2e0b0b0b0b0b0b0b0b0b0b0b', '77616c6c2e0100000000000000000000'],
    whyNot: 'The marker is the byte 80 (a single 1 bit), followed by zero bytes.',
  });
  ex({
    id: 'mo-x-unpad-valid', chapter: 'mo-use', title: 'Valid PKCS#7 padding', level: 2, kind: 'choice',
    text: ['Here are the endings of five decrypted 16-byte blocks. Which end in valid PKCS#7 padding? Choose all that apply.'],
    options: ['… 6e 65 04 04 04 04', '… 21 03 03 02', '… 74 61 6c 00', '… 72 6f 6d 01', 'sixteen bytes of 10', '… 61 05 05 05 05'],
    answer: [0, 3, 4],
    hints: ['Read the last byte k: it must be between 1 and 16, and the last k bytes must all equal k.', '02 needs two 02 bytes; 00 is never valid; five 05s are needed after 61.', 'Valid: 04 04 04 04, a lone 01, and a whole block of 10.'],
    solution: [0, 3, 4], wrong: [[0, 3], [0, 3, 4, 5], [0, 1, 3, 4]],
  });
  ex({
    id: 'mo-x-code-pad', chapter: 'mo-use', title: 'Write PKCS#7 padding', level: 1, kind: 'code', fn: 'pkcs7Pad', radix: 16, params: ['data', 'n'],
    text: ['Write `pkcs7Pad(data, n)`: `data` is an array of bytes (Numbers from 0 to 255) and `n` the block size in bytes (16 for AES, 8 for DES). Return a new array with k bytes of value k added, where k = n − (length mod n), so between 1 and n bytes are always added.'],
    start: 'function pkcs7Pad(data, n) {\n  \n}\n',
    ref: (d, n) => Array.from(S.Modes.pkcs7(Uint8Array.from(d), n)),
    cases: [[arr(hexOf('Nets dry on the wall.')), 16], [arr(hexOf('Three gulls on the harbour rail')), 16], [arr(hexOf('exactly 16 bytes')), 16], [[], 16], [arr(hexOf('heron')), 8], [arr(hexOf('kingfish')), 8]],
    hints: ['k = n - (data.length % n); when the length is already a multiple of n, k = n.', 'Append k copies of k: `data.concat(new Array(k).fill(k))`.', PAD_SOL],
    solution: PAD_SOL + '\n',
    wrong: ['function pkcs7Pad(data, n) {\n  const k = (n - (data.length % n)) % n;\n  return data.concat(new Array(k).fill(k));\n}\n', 'function pkcs7Pad(data, n) {\n  const k = n - (data.length % n);\n  return data.concat(new Array(k).fill(0));\n}\n'],
  });
  ex({
    id: 'mo-x-code-unpad', chapter: 'mo-use', title: 'Write PKCS#7 unpadding', level: 2, kind: 'code', fn: 'pkcs7Unpad', radix: 16, params: ['data', 'n'],
    text: ['Write `pkcs7Unpad(data, n)`: `data` is a decrypted array of bytes whose length is a multiple of `n`. If it ends in valid PKCS#7 padding, return a new array without it; otherwise return `null`. (In a real system this runs only after the message\'s tag has been verified.)'],
    start: 'function pkcs7Unpad(data, n) {\n  \n}\n',
    ref: (d, n) => { try { return Array.from(S.Modes.unpkcs7(Uint8Array.from(d), n)); } catch (e) { return null; } },
    cases: [[hex(S.Modes.pkcs7(enc('Nets dry on the wall.'), 16)), 16], [hex(S.Modes.pkcs7(enc('exactly 16 bytes'), 16)), 16], ['41424344454647484940414243030302', 16], ['41424344454647484940414243440000', 16], ['41424344454647484940414243440011', 16], ['41424344454647484940414243444501', 16], ['41424344454647484940414243040404', 16], ['0808080808080808', 8], ['6865726f6e030303', 8]].map(([x, n]) => [arr(x), n]),
    hints: ['Let k be the last byte. It must satisfy 1 ≤ k ≤ n, and each of the last k bytes must equal k.', 'If any check fails, return null; otherwise `data.slice(0, data.length - k)`.', UNPAD_SOL],
    solution: UNPAD_SOL + '\n',
    wrong: ['function pkcs7Unpad(data, n) {\n  const k = data[data.length - 1];\n  return data.slice(0, data.length - k);\n}\n', 'function pkcs7Unpad(data, n) {\n  const k = data[data.length - 1];\n  if (k < 1 || k > n) return null;\n  return data.slice(0, data.length - k);\n}\n'],
  });
  ex({
    id: 'mo-x-birthday', chapter: 'mo-use', title: 'The birthday bound for 64-bit blocks', level: 2, kind: 'number',
    text: ['Under one key, q ciphertext blocks of 64 bits contain a repeated block with chance about 1 − e^(−q²/2⁶⁵). Find q for even odds, and give the amount of data in GiB (2³⁰ bytes, 8 bytes to a block), to the nearest GiB.'],
    answer: 38, tolerance: 1,
    hints: ['Set e^(−q²/2⁶⁵) = 1/2: q² = 2⁶⁵ · ln 2.', 'q = √(2 ln 2) · 2³² ≈ 1.177 · 2³² ≈ 5.06 × 10⁹ blocks.', '5.06 × 10⁹ blocks × 8 bytes ≈ 4.05 × 10¹⁰ bytes ≈ 37.7 GiB: about 38 GiB.'],
    solution: '38', wrong: ['32', '4', '256'],
    whyNot: 'Solve for q at probability 1/2, then multiply by 8 bytes and divide by 2³⁰.',
  });
  ex({
    id: 'mo-x-sweet32', chapter: 'mo-use', title: 'Sweet32: the chance at 32 GiB', level: 2, kind: 'number',
    text: ['A 3DES connection (64-bit blocks) carries 32 GiB under one key, that is 2³² blocks. Using 1 − e^(−q²/2⁶⁵), what is the chance that some ciphertext block repeats? Give it to two decimal places.'],
    answer: 0.39, tolerance: 0.01,
    hints: ['q = 2³², so q² = 2⁶⁴.', 'q²/2⁶⁵ = 1/2, so the chance is 1 − e^(−1/2).', '1 − e^(−0.5) ≈ 1 − 0.607 = 0.39. Rekey long before this, or use a 128-bit block cipher.'],
    solution: '0.39', wrong: ['0.5', '0.61', '1'],
    whyNot: 'Put q = 2³² into the formula: the exponent is −2⁶⁴/2⁶⁵.',
  });
  ex({
    id: 'mo-x-aes-limit', chapter: 'mo-use', title: 'The same bound for AES', level: 2, kind: 'number',
    text: ['For AES\'s 128-bit blocks, repeats become likely around 2⁶⁴ blocks under one key. How many bytes is that, as a power of 2? Give the exponent.'],
    answer: 68,
    hints: ['A block is 16 = 2⁴ bytes.', '2⁶⁴ blocks × 2⁴ bytes.', '2⁶⁸ bytes, about 256 exbibytes: no single session comes close, though the usual advice is still to rekey long before (for example after 2⁴⁸ blocks).'],
    solution: '68', wrong: ['64', '128', '72'],
    whyNot: 'Multiply the number of blocks by the 16 bytes in each.',
  });
  ex({
    id: 'mo-x-choose-stream', chapter: 'mo-use', title: 'Choose a mode: video to many viewers', level: 1, kind: 'choice',
    text: ['A camera sends live video packets over a network. Packets may arrive out of order or not at all, each must be decrypted on its own, and a viewer must reject packets that were altered. Which choice fits?'],
    options: ['AES-CBC over the whole stream', 'AES-GCM per packet, with a nonce built from the packet sequence number', 'AES-ECB per packet', 'AES-OFB over the whole stream, with one IV'],
    answer: 1,
    hints: ['Each packet must stand alone, and alterations must be caught.', 'Chained modes over the whole stream break when a packet is lost; only an authenticated mode catches changes.', 'AES-GCM per packet: the sequence number (unique per key) gives the nonce, and the tag rejects altered packets.'],
    solution: 1, wrong: [0, 3],
    whyNot: { 0: 'One lost packet breaks the chain for the next one, and CBC gives no integrity.', 3: 'A lost packet loses the place in the keystream, and OFB gives no integrity.' },
  });
  ex({
    id: 'mo-x-choose-auth', chapter: 'mo-use', title: 'Choose a mode: an API token', level: 2, kind: 'choice',
    text: ['A web service hands each user an encrypted token holding their user id and role, and later reads it back. The user must not be able to read the role, nor change it. Which design is right?'],
    options: ['AES-ECB of the token text', 'AES-CBC with a random IV', 'AES-CTR with a random nonce', 'AES-GCM with a random 96-bit nonce, the service rejecting any token whose tag fails'],
    answer: 3,
    hints: ['Two goals: secrecy and protection from changes.', 'ECB, CBC and CTR hide the content but let a user change ciphertext blocks or bits and still get a token that decrypts.', 'AES-GCM: an altered token fails the tag and is rejected; the random nonce stays well within 2³² tokens per key, or the key is rotated.'],
    solution: 3, wrong: [1, 2],
    whyNot: { 1: 'CBC hides the role, but a user who changes the ciphertext still gets a token that decrypts, with changes they can steer.', 2: 'In CTR a user can flip bits of the role field at will: encryption is not integrity.' },
  });
  ex({
    id: 'mo-x-misuse-review', chapter: 'mo-use', title: 'Review a design', level: 3, kind: 'choice',
    text: ['A design note for a backup tool: “(a) Files are encrypted with AES-128-CBC. (b) The IV is all zeros, since the key is secret. (c) An HMAC-SHA-256 of the ciphertext is appended, with a key derived separately from the master key. (d) On restore, the file is decrypted and unpadded first, and the HMAC is checked afterwards. (e) The key is derived from the user\'s passphrase with a slow, salted password hash.” Which statements describe a misuse? Choose all that apply.'],
    options: ['(a)', '(b)', '(c)', '(d)', '(e)'],
    answer: [1, 3],
    hints: ['Check each line against the rules: fresh unpredictable IVs, independent keys, check the tag before decrypting, a strong key derivation.', 'A fixed IV makes equal file beginnings encrypt equally. Checking the HMAC after unpadding runs the padding check on unauthenticated data.', '(b) and (d) are misuses: use a random IV per file, and verify the HMAC over IV and ciphertext before decrypting. (a), (c) and (e) are sound.'],
    solution: [1, 3], wrong: [[1], [0, 1, 3], [1, 2, 3]],
  });

  // ---- the guided tour ---------------------------------------------------------------------------------------------
  C.tour({
    id: 'mo-tour', title: 'Tour: modes of operation', blurb: 'From ECB\'s surviving picture to GCM\'s tag, in eight steps.',
    steps: [
      { route: 'part=modes', target: '#main', text: 'Part 6 of the catalogue: modes of operation. Each topic draws a mode as wires between block-cipher boxes, with the value on every wire.' },
      { route: 'topic=modes-ecb', target: '#stageWrap', text: 'ECB encrypts each block alone, and the outline of the picture survives. Compare it with CBC on the same pixels.' },
      { target: '#btnPlay', text: 'Play steps through the run; the arrow keys go one step at a time, forwards or back.' },
      { route: 'topic=modes-cbc', target: '#inputs', text: 'CBC: choose to decrypt and flip a bit of C₁, and see which plaintext blocks it damages.' },
      { route: 'topic=modes-ctr', target: '#stageWrap', text: 'CTR encrypts a counter. Nothing is chained, so any block can be reached directly, and a counter must never repeat.' },
      { route: 'topic=modes-gcm', target: '#stageWrap', text: 'GCM adds a tag from GHASH over GF(2¹²⁸). Change a ciphertext bit in the inputs and the tag check fails.' },
      { route: 'lesson=mo-integrity', target: '#lessonView', text: 'Encryption is not integrity: this lesson shows a changed CTR message accepted, the same change rejected by GCM, and the rules for nonces.' },
      { route: 'learn', target: '[data-chapter="mo-block"]', text: 'The lessons and exercises of this part start here: compute counters and tweaks, write CBC, CTR and PKCS#7, and review designs for misuse.' },
    ],
  });

  // ---- a course through every topic of the part --------------------------------------------------------------------
  const steps = [
    { topic: 'modes-ecb', note: 'Each block alone, and what that shows.' },
    { lesson: 'mo-ecb', note: 'Why ECB is only for a single random block.' },
    { topic: 'modes-cbc', note: 'Chaining through an IV.' },
    { exercise: 'mo-x-cbc-iv', note: 'Which IVs are sound.' },
    { exercise: 'mo-x-code-cbc', note: 'Write CBC, checked against SP 800-38A.' },
    { topic: 'modes-cfb', note: 'Feedback from the ciphertext.' },
    { topic: 'modes-ofb', note: 'Feedback from the cipher\'s own output.' },
    { topic: 'modes-ctr', note: 'A counter, and random access.' },
    { lesson: 'mo-ctr', note: 'The one rule of counter mode.' },
    { exercise: 'mo-x-code-ctr', note: 'Write CTR, checked against SP 800-38A.' },
    { topic: 'modes-xts', note: 'A disk sector, tweaked by its number.' },
    { topic: 'modes-gcm', note: 'CTR plus GHASH.' },
    { lesson: 'mo-gcm', note: 'How the tag is made and checked.' },
  ];
  if (S.byId && S.byId('integrity-malleable')) steps.push({ topic: 'integrity-malleable', note: 'A changed CTR message is accepted; GCM rejects it.' });
  if (S.byId && S.byId('integrity-nonce')) steps.push({ topic: 'integrity-nonce', note: 'What a repeated nonce gives away.' });
  for (const t of (S.topics || []).filter((t) => t.family === 'p06-labs' && !/^integrity-(malleable|nonce)$/.test(t.id))) steps.push({ topic: t.id, note: t.title + '.' });
  steps.push(
    { lesson: 'mo-integrity', note: 'Encrypt-then-MAC, and checking the tag first.' },
    { exercise: 'mo-x-gcm-nonce', note: 'A nonce that restarts at every boot.' },
    { topic: 'modes-padding', note: 'PKCS#7, ISO/IEC 7816-4 and ciphertext stealing.' },
    { exercise: 'mo-x-code-unpad', note: 'Check and remove padding.' },
    { topic: 'modes-keysearch', note: 'Key length, and the birthday bound of the block size.' },
    { exercise: 'mo-x-sweet32', note: 'The chance of a repeat at 32 GiB.' },
    { lesson: 'mo-choose', note: 'Which mode for which job.' },
    { exercise: 'mo-x-misuse-review', note: 'Review a design.' },
  );
  C.course({ id: 'mo-course', title: 'Modes of operation', blurb: 'Every topic of part 6, from ECB to GCM and the rules of correct use, with the lessons and a few exercises on the way.', steps });

  // ---- what the diagram checker looks at on these pages -------------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'lesson mo-ecb')) {
    const lessonReady = "document.querySelector('#lessonView')", exReady = "document.querySelector('#exerciseView')";
    for (const id of C.chapters.filter((c) => c.part === 'modes').flatMap((c) => c.lessons)) S.Checks.push({ group: 'learn', name: 'lesson ' + id, hash: 'lesson=' + id, ready: lessonReady, sel: '#main' });
    for (const id of ['mo-x-ecb-count', 'mo-x-code-cbc', 'mo-x-ctr-far', 'mo-x-xts-alpha', 'mo-x-tag-first', 'mo-x-nonce-rules', 'mo-x-unpad-valid', 'mo-x-misuse-review'])
      S.Checks.push({ group: 'learn', name: 'exercise ' + id, hash: 'exercise=' + id, ready: exReady, sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'course mo-course', hash: 'course=mo-course', ready: "document.querySelector('#courseView')", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
