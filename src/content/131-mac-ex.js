// Part 13, MACs, key establishment and protocols: the exercises. The lessons are in 130-mac.js; the tour and the course
// in 132-mac-ctf.js. Keys and messages are our own (“salt-marsh-7”, “harbour-cmac-key”, …) except where a standard's
// published vector is named (RFC 4231, RFC 4493, RFC 5869, RFC 8439); every answer is worked out here by S.MAC, S.Hash
// and S.Proto when the page loads, and the code exercises are checked against those engines.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('mc-x-game')) return;
  const ex = (o) => C.exercise(o);
  const M = S.MAC, H = S.Hash;
  const enc = (t) => new TextEncoder().encode(t);
  const hex = (a) => Array.from(a, (v) => v.toString(16).padStart(2, '0')).join('');
  const unhex = (s) => { const t = String(s).replace(/\s+/g, ''); const o = new Uint8Array(t.length >> 1); for (let i = 0; i < o.length; i++) o[i] = parseInt(t.substr(2 * i, 2), 16); return o; };
  const cat = (...xs) => { const o = new Uint8Array(xs.reduce((n, x) => n + x.length, 0)); let k = 0; for (const x of xs) { o.set(x, k); k += x.length; } return o; };
  const sp = (h) => String(h).replace(/(.{8})(?=.)/g, '$1 ');
  /** tests whose answer is bytes: compared item by item, whatever kind of byte array came back */
  const byteTests = (ref, cases) => cases.map((args) => {
    const want = ref(...args);
    return { args, want, check: (got) => {
      if (!got || typeof got !== 'object' || typeof got.length !== 'number') return 'it should return bytes (a Uint8Array)';
      if (got.length !== want.length) return got.length + ' bytes came back where ' + want.length + ' are wanted';
      for (let i = 0; i < want.length; i++) if (got[i] !== want[i]) return 'byte ' + i + ' is ' + got[i] + ' where ' + want[i] + ' is wanted';
      return true;
    } };
  });
  // SHA-256, HMAC and HKDF-Expand written plainly, in lines short enough for the editor on a phone; SHA-256 and HMAC
  // are given to the student, as preludes, in the code exercises that build on them
  const SHA_SRC = "function sha256(msg) {\n  const P = [];\n  for (let n = 2; P.length < 64; n++) {\n    if (P.every((p) => n % p)) {\n      P.push(n);\n    }\n  }\n  const fr = (x) =>\n    ((x - Math.floor(x)) * 2 ** 32)\n    >>> 0;\n  const K = P\n    .map((p) => fr(Math.cbrt(p)));\n  const V = P.slice(0, 8)\n    .map((p) => fr(Math.sqrt(p)));\n  const R = (x, n) =>\n    (x >>> n) | (x << (32 - n));\n  const n = msg.length;\n  const len =\n    Math.ceil((n + 9) / 64) * 64;\n  const m = new Uint8Array(len);\n  m.set(msg);\n  m[n] = 0x80;\n  for (let i = 0; i < 4; i++) {\n    m[len - 1 - i] =\n      (n * 8) >>> (8 * i);\n  }\n  const W = [];\n  for (let o = 0; o < len; o += 64) {\n    for (let t = 0; t < 64; t++) {\n      if (t < 16) {\n        const j = o + 4 * t;\n        W[t] = ((m[j] << 24)\n          | (m[j + 1] << 16)\n          | (m[j + 2] << 8)\n          | m[j + 3]) >>> 0;\n        continue;\n      }\n      const x = W[t - 15], y = W[t - 2];\n      const s0 = R(x, 7) ^ R(x, 18)\n        ^ (x >>> 3);\n      const s1 = R(y, 17) ^ R(y, 19)\n        ^ (y >>> 10);\n      W[t] = (W[t - 16] + s0\n        + W[t - 7] + s1) >>> 0;\n    }\n    let [a, b, c, d, e, f, g, h] = V;\n    for (let t = 0; t < 64; t++) {\n      const S1 = R(e, 6) ^ R(e, 11)\n        ^ R(e, 25);\n      const S0 = R(a, 2) ^ R(a, 13)\n        ^ R(a, 22);\n      const ch = (e & f) ^ (~e & g);\n      const mj = (a & b) ^ (a & c)\n        ^ (b & c);\n      const t1 = (h + S1 + ch\n        + K[t] + W[t]) | 0;\n      const t2 = (S0 + mj) | 0;\n      h = g; g = f; f = e;\n      e = (d + t1) | 0;\n      d = c; c = b; b = a;\n      a = (t1 + t2) | 0;\n    }\n    const r = [a, b, c, d, e, f, g, h];\n    for (let i = 0; i < 8; i++) {\n      V[i] = (V[i] + r[i]) >>> 0;\n    }\n  }\n  const out = new Uint8Array(32);\n  for (let i = 0; i < 32; i++) {\n    out[i] =\n      V[i >> 2] >>> (24 - 8 * (i & 3));\n  }\n  return out;\n}\n";
  const HMAC_SRC = "function hmacSha256(key, msg) {\n  if (key.length > 64) {\n    key = sha256(key);\n  }\n  const k = new Uint8Array(64);\n  k.set(key);\n  const join = (a, b) => {\n    const o = new Uint8Array(\n      a.length + b.length);\n    o.set(a);\n    o.set(b, a.length);\n    return o;\n  };\n  const ki = k.map((b) => b ^ 0x36);\n  const ko = k.map((b) => b ^ 0x5c);\n  return sha256(join(ko,\n    sha256(join(ki, msg))));\n}\n";
  const HKDF_SRC = "function hkdfExpand(prk, info, L) {\n  const out = new Uint8Array(L);\n  let t = new Uint8Array(0), have = 0;\n  for (let i = 1; have < L; i++) {\n    const m = new Uint8Array(\n      t.length + info.length + 1);\n    m.set(t);\n    m.set(info, t.length);\n    m[m.length - 1] = i;\n    t = hmacSha256(prk, m);\n    out.set(t.slice(0, L - have), have);\n    have += t.length;\n  }\n  return out;\n}\n";
  const HMAC_NOHASH = HMAC_SRC.replace('  if (key.length > 64) {\n    key = sha256(key);\n  }\n', '');
  const HMAC_PLAIN = 'function hmacSha256(key, msg) {\n  const m = new Uint8Array(\n    key.length + msg.length);\n  m.set(key);\n  m.set(msg, key.length);\n  return sha256(m);\n}\n';

  // =========================================================================================================
  // Chapter 1: message authentication codes
  // =========================================================================================================
  ex({
    id: 'mc-x-game', chapter: 'mc-mac', title: 'What counts as a forgery?', level: 1, kind: 'choice',
    text: ['In the chosen-message forgery game, the forger asked for tags of “amount=20&to=wren” and “amount=35&to=ash”. Which of these outputs wins the game?'],
    options: ['“amount=20&to=wren” with the tag it was given', 'A valid tag on “amount=36&to=ash”', 'The key', 'An invalid tag on “amount=9000&to=mallory”'],
    answer: 1,
    hints: ['Replaying a tag the forger was handed proves nothing.', 'The forger must produce a valid tag on a message it never asked about.', 'A valid tag on any new message, however similar, wins. Recovering the key would also let it forge, but the game asks for the forgery itself.'],
    solution: 1, wrong: [0, 3],
    whyNot: { 0: 'That message was asked about: its tag was handed over, so returning it is no forgery.', 3: 'The tag must be valid.' },
  });
  ex({
    id: 'mc-x-tag-guess', chapter: 'mc-mac', title: 'Guessing a 32-bit tag', level: 1, kind: 'number',
    text: ['A device truncates its HMAC tags to 32 bits and accepts unlimited verification attempts. In the worst case, how many guesses does it take to hit the right tag for one chosen message?'],
    answer: 4294967296,
    hints: ['Each guess is one of the 2³² possible tags.', 'Trying each in turn hits the right one at the latest on the last try.', '2³² = 4,294,967,296 guesses, about half that on average. Rate limits and longer tags (64 bits or more) push this out of reach.'],
    solution: '4294967296', wrong: ['65536', '2147483648', '32'],
    whyNot: 'Count every possible 32-bit value.',
  });
  ex({
    id: 'mc-x-leaky', chapter: 'mc-mac', title: 'Comparing tags', level: 2, kind: 'choice',
    text: ['A server checks tags with a loop that returns false at the first byte that differs. Why should it compare in constant time instead?'],
    options: ['Constant-time comparison is faster', 'The time to answer reveals how many leading bytes were right, so a tag can be found one byte at a time in about 256 guesses per byte instead of 2^(8·length)', 'The early exit can return true for a wrong tag', 'It makes HMAC immune to length extension'],
    answer: 1,
    hints: ['What differs, from the outside, between a guess wrong in its first byte and one wrong in its fifth?', 'The loop runs longer when more leading bytes match.', 'The running time leaks the length of the correct prefix, so the search splits into one small search per byte. A comparison that always looks at every byte, accumulating the differences with OR, gives nothing away.'],
    solution: 1, wrong: [0, 2, 3],
  });
  const IKEY = 'salt-marsh-7', IK = new Uint8Array(64); IK.set(enc(IKEY));
  const xo = (b, v) => hex(IK.slice(b, b + 8).map((x) => x ^ v));
  const IPT = { 'K′ ⊕ ipad|bytes 0–7': xo(0, 0x36), 'K′ ⊕ ipad|bytes 8–15': xo(8, 0x36), 'K′ ⊕ opad|bytes 0–7': xo(0, 0x5c), 'K′ ⊕ opad|bytes 8–15': xo(8, 0x5c) };
  ex({
    id: 'mc-x-ipad', chapter: 'mc-mac', title: 'The ipad and opad blocks', level: 1, kind: 'table',
    text: [`HMAC-SHA-256 with the 12-byte key “${IKEY}”. K′ is the key padded with zeros to 64 bytes; its first 16 bytes are below. Fill in the first 16 bytes of K′ ⊕ ipad and K′ ⊕ opad (ipad is 36 repeated, opad 5c repeated).`, { bytes: { hex: hex(IK.slice(0, 16)), cols: 16 }, caption: 'K′, bytes 0 to 15: the key, then zeros.' }],
    rows: ['K′ ⊕ ipad', 'K′ ⊕ opad'], cols: ['bytes 0–7', 'bytes 8–15'], cells: IPT, cellKind: 'hex', corner: 'block',
    hints: ['XOR each byte with 36 for ipad and with 5c for opad.', `“s” = 73: 73 ⊕ 36 = 45 and 73 ⊕ 5c = 2f. The zero bytes become 36 and 5c themselves.`, `ipad: ${sp(IPT['K′ ⊕ ipad|bytes 0–7'])} ${sp(IPT['K′ ⊕ ipad|bytes 8–15'])}; opad: ${sp(IPT['K′ ⊕ opad|bytes 0–7'])} ${sp(IPT['K′ ⊕ opad|bytes 8–15'])}.`],
    solution: IPT, wrong: [Object.assign({}, IPT, { 'K′ ⊕ ipad|bytes 8–15': hex(IK.slice(8, 16)) }), Object.assign({}, IPT, { 'K′ ⊕ opad|bytes 0–7': xo(0, 0x36) })],
  });
  const RFC4231 = [
    [unhex('0b'.repeat(20)), enc('Hi There')],
    [enc('Jefe'), enc('what do ya want for nothing?')],
    [unhex('aa'.repeat(20)), unhex('dd'.repeat(50))],
    [unhex('0102030405060708090a0b0c0d0e0f10111213141516171819'), unhex('cd'.repeat(50))],
    [unhex('aa'.repeat(131)), enc('Test Using Larger Than Block-Size Key - Hash Key First')],
    [unhex('aa'.repeat(131)), enc('This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.')],
    [enc(IKEY), enc('amount=20&to=wren')],
    [unhex('5c'.repeat(64)), new Uint8Array(0)],
  ];
  ex({
    id: 'mc-x-code-hmac', chapter: 'mc-mac', title: 'Write HMAC-SHA-256', level: 3, kind: 'code', fn: 'hmacSha256', params: ['key', 'msg'],
    text: ['Write `hmacSha256(key, msg)` around the `sha256(bytes)` given above the editor (read-only): both arguments are Uint8Arrays; return the 32-byte tag. The tests are RFC 4231 test cases 1, 2, 3, 4, 6 and 7 (6 and 7 use a 131-byte key, longer than a block) and two of our own.'],
    prelude: SHA_SRC,
    start: 'function hmacSha256(key, msg) {\n  \n}\n',
    tests: byteTests((k, m) => M.hmac('sha256', k, m), RFC4231),
    timeLimit: 4000,
    hints: ['A key longer than the 64-byte block is hashed first; then pad it with zeros to 64 bytes.', 'Make two blocks: every byte XOR 0x36, and every byte XOR 0x5c. Hash the first block followed by the message, then hash the second block followed by that 32-byte digest.', HMAC_SRC],
    solution: HMAC_SRC,
    wrong: [HMAC_NOHASH, HMAC_PLAIN],
  });
  ex({
    id: 'mc-x-cmac-why', chapter: 'mc-mac', title: 'What CMAC adds', level: 2, kind: 'choice',
    text: ['CBC-MAC is secure only for messages of one fixed length. What change makes CMAC safe for messages of any length?'],
    options: ['It uses a random IV', 'It XORs the last block with a secret subkey (K1 or K2, derived from AES_K(0)) before the last encryption, so a tag is never the chaining value that an extended message would continue from', 'It encrypts the tag a second time with the same key', 'It appends the length at the end'],
    answer: 1,
    hints: ['Plain CBC-MAC fails on varying lengths because the tag of m1 is exactly the chaining value after m1.', 'In CMAC, the last block of m1 was masked with a subkey before it was encrypted.', 'The subkey mask means t1 is not the state a longer message passes through after m1, so it does not cancel. A random IV would break verification (and CBC-MAC with a random IV is insecure); a length prefix would also work but needs the length in advance.'],
    solution: 1, wrong: [0, 2, 3],
  });
  ex({
    id: 'mc-x-cmac-last', chapter: 'mc-mac', title: 'Which subkey?', level: 1, kind: 'choice',
    text: ['CMAC with AES (16-byte blocks) on a 40-byte message. How is the last block treated?'],
    options: ['It is 16 bytes, XORed with K1', 'It is 8 bytes, padded with 80 00 … 00 to 16 bytes and XORed with K2', 'It is 8 bytes, padded with zeros and XORed with K1', 'It is dropped'],
    answer: 1,
    hints: ['40 = 16 + 16 + 8.', 'A partial last block is padded with a 1 bit (the byte 80) and zeros.', 'The last block is 8 bytes: pad with 80 and seven 00s, XOR with K2, encrypt. A complete last block would use K1 and no padding; the two subkeys keep “m” and “m ‖ 80 00…” apart.'],
    solution: 1, wrong: [0, 2],
  });
  const DB = 'c1fdf8e096e2063a5b9e4a7f00c4d211';
  ex({
    id: 'mc-x-dbl', chapter: 'mc-mac', title: 'Doubling in GF(2¹²⁸)', level: 1, kind: 'hex',
    text: [`CMAC doubles blocks: shift all 128 bits left by one, and if the top bit fell off, XOR 87 into the last byte. Double the block ${sp(DB)}.`],
    answer: hex(M.dbl(unhex(DB))),
    hints: ['The first byte is c1 = 1100 0001: its top bit is 1, so 87 will be XORed in at the end.', 'Shift: each byte becomes (byte << 1) | (top bit of the next byte), cut to 8 bits. c1 fd → 83 …; the last byte 11 becomes 22, then 22 ⊕ 87 = a5.', sp(hex(M.dbl(unhex(DB)))) + '.'],
    solution: hex(M.dbl(unhex(DB))), wrong: [DB.replace(/../g, (b) => (((parseInt(b, 16) << 1) & 255).toString(16).padStart(2, '0'))), hex(M.dbl(unhex(DB))).slice(0, 30) + '22'],
    whyNot: 'Carry the top bit of each byte into the one before it, and XOR 87 into the last byte when the top bit of the whole block was 1.',
  });
  const CK = 'harbour-cmac-key', SK = M.cmacSubkeys(enc(CK));
  const SKT = { 'K1|value': hex(SK.K1), 'K2|value': hex(SK.K2) };
  ex({
    id: 'mc-x-cmac-subkeys', chapter: 'mc-mac', title: 'CMAC subkeys', level: 3, kind: 'table',
    text: [`CMAC under the AES-128 key “${CK}” begins with L = AES_K(0¹²⁸) = ${sp(hex(SK.L))}. Compute the subkeys K1 = L·x and K2 = K1·x.`],
    rows: ['K1', 'K2'], cols: ['value'], cells: SKT, cellKind: 'hex',
    hints: ['Doubling: shift the 16 bytes left by one bit; if the top bit of the block was 1, XOR 87 into the last byte.', `L begins with ${hex(SK.L).slice(0, 2)}, so its top bit is ${SK.L[0] >> 7}; K1 begins with ${hex(SK.K1).slice(0, 2)}, top bit ${SK.K1[0] >> 7}.`, `K1 = ${sp(hex(SK.K1))}, K2 = ${sp(hex(SK.K2))}.`],
    solution: SKT, wrong: [Object.assign({}, SKT, { 'K2|value': hex(SK.L) }), Object.assign({}, SKT, { 'K1|value': hex(SK.K2), 'K2|value': hex(SK.K1) })],
  });
  const LEn = (b) => b.reduceRight((v, x) => (v << 8n) | BigInt(x), 0n);
  const PCH = 'meet at the nort', PN = LEn(enc(PCH)) + (1n << 128n);
  ex({
    id: 'mc-x-poly-n', chapter: 'mc-mac', title: 'One Poly1305 chunk as a number', level: 2, kind: 'hex', value: true,
    text: [`Poly1305 turns each 16-byte chunk into a number n: the bytes read little-endian, plus 2¹²⁸ (a 01 byte on top). What is n for the chunk “${PCH}”? Give it in hex.`],
    answer: PN.toString(16).padStart(34, '0'),
    hints: ['Little-endian: the last byte is the most significant. “t” = 74 is the top byte of the chunk.', `The chunk’s bytes are ${sp(hex(enc(PCH)))}; reversed they read ${sp(hex(enc(PCH).slice().reverse()))}.`, `Put 01 on top: n = ${sp(PN.toString(16).padStart(34, '0'))}.`],
    solution: PN.toString(16).padStart(34, '0'), wrong: ['01' + hex(enc(PCH)), hex(enc(PCH).slice().reverse()), hex(enc(PCH).slice().reverse()) + '01'],
    whyNot: 'Reverse the bytes (little-endian) and put the 01 above the most significant byte.',
  });
  const RB = unhex('f3a91c4e7b2d0a85d6e47f13a9c2b5e8'), RC = RB.slice();
  for (const i of [3, 7, 11, 15]) RC[i] &= 0x0f;
  for (const i of [4, 8, 12]) RC[i] &= 0xfc;
  ex({
    id: 'mc-x-clamp', chapter: 'mc-mac', title: 'Clamp r', level: 2, kind: 'hex',
    text: [`The first 16 bytes of a Poly1305 key are ${sp(hex(RB))}. Clamp them: clear the top 4 bits of bytes 3, 7, 11 and 15 and the low 2 bits of bytes 4, 8 and 12 (bytes counted from 0). Give the 16 bytes in the same order.`],
    answer: hex(RC),
    hints: ['Byte 3 is 4e: clearing the top 4 bits gives 0e. Byte 4 is 7b: clearing the low 2 bits gives 78.', 'Bytes 7, 11, 15: 85 → 05, 13 → 03, e8 → 08. Bytes 8, 12: d6 → d4, a9 → a8.', sp(hex(RC)) + '.'],
    solution: hex(RC), wrong: [hex(RB), hex(RC).slice(0, 30) + 'e8', hex(RC.slice().reverse())],
    whyNot: 'Only seven bytes change: AND bytes 3, 7, 11, 15 with 0f and bytes 4, 8, 12 with fc.',
  });
  const RFCKEY = unhex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
  const PR = M.poly1305(RFCKEY, enc('Cryptographic Forum Research Group'), { trace: true });
  const P1305 = (1n << 130n) - 5n;
  const polyStep = (acc, chunk, r) => ((acc + LEn(chunk) + (1n << BigInt(8 * chunk.length))) * r) % P1305;
  const RFCMSG = enc('Cryptographic Forum Research Group');
  const pcases = [[0n, RFCMSG.slice(0, 16), PR.r], [PR.steps[0].acc, RFCMSG.slice(16, 32), PR.r], [PR.steps[1].acc, RFCMSG.slice(32), PR.r], [0n, enc(PCH), PR.r], [P1305 - 1n, new Uint8Array(16).fill(255), 0x0ffffffc0ffffffc0ffffffc0fffffffn], [12345n, new Uint8Array(0), 7n]];
  ex({
    id: 'mc-x-code-poly', chapter: 'mc-mac', title: 'Write the Poly1305 accumulator step', level: 3, kind: 'code', fn: 'polyStep', params: ['acc', 'chunk', 'r'],
    text: ['Write `polyStep(acc, chunk, r)`: `acc` and `r` are BigInts, `chunk` a Uint8Array of 0 to 16 bytes. Return the new accumulator (acc + n) · r mod 2¹³⁰ − 5, where n is the chunk read little-endian plus 2^(8·length). The first three tests are the three chunks of RFC 8439, section 2.5.2, with its clamped r = 806d5400e52447c036d555408bed685.'],
    start: 'function polyStep(acc, chunk, r) {\n  const p = (1n << 130n) - 5n;\n  \n}\n',
    tests: pcases.map((args) => ({ args, want: polyStep(...args) })),
    hints: ['Read the chunk from its last byte down: n = n · 256 + byte, as BigInts.', 'Then add 1n << BigInt(8 * chunk.length), add acc, multiply by r, and take % p.', 'function polyStep(acc, chunk, r) {\n  const p = (1n << 130n) - 5n;\n  let n = 0n;\n  for (let i = chunk.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(chunk[i]);\n  n += 1n << BigInt(8 * chunk.length);\n  return ((acc + n) * r) % p;\n}'],
    solution: 'function polyStep(acc, chunk, r) {\n  const p = (1n << 130n) - 5n;\n  let n = 0n;\n  for (let i = chunk.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(chunk[i]);\n  n += 1n << BigInt(8 * chunk.length);\n  return ((acc + n) * r) % p;\n}\n',
    wrong: ['function polyStep(acc, chunk, r) {\n  const p = (1n << 130n) - 5n;\n  let n = 0n;\n  for (let i = 0; i < chunk.length; i++) n = (n << 8n) | BigInt(chunk[i]);\n  n += 1n << BigInt(8 * chunk.length);\n  return ((acc + n) * r) % p;\n}\n', 'function polyStep(acc, chunk, r) {\n  const p = (1n << 130n) - 5n;\n  let n = 0n;\n  for (let i = chunk.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(chunk[i]);\n  n += 1n << 128n;\n  return ((acc + n) * r) % p;\n}\n'],
  });
  ex({
    id: 'mc-x-onetime', chapter: 'mc-mac', title: 'One key, one message', level: 2, kind: 'choice',
    text: ['Which of these must never be used twice with the same key and nonce (or, for Poly1305, the same one-time key)? Choose all that apply.'],
    options: ['A Poly1305 one-time key (r, s)', 'A GMAC (GCM) IV under one AES key', 'An HMAC key', 'A CMAC key'],
    answer: [0, 1],
    hints: ['Which MACs evaluate a polynomial at a secret point and hide it with a mask?', 'Two tags under the same mask: XOR them and the mask cancels, leaving an equation in the secret point.', 'Poly1305 and GMAC. HMAC and CMAC keys are made to tag many messages.'],
    solution: [0, 1], wrong: [[0], [0, 1, 2], [2, 3]],
  });

  // =========================================================================================================
  // Chapter 2: authenticated encryption and key derivation
  // =========================================================================================================
  ex({
    id: 'mc-x-compose', chapter: 'mc-aead', title: 'Choosing a composition', level: 2, kind: 'choice',
    text: ['A team combines AES-CTR and HMAC with independent keys. Which order is safe in general?'],
    options: ['MAC the plaintext, then encrypt the plaintext and tag together', 'Encrypt the plaintext, and send a MAC of the plaintext alongside', 'Encrypt the plaintext, then MAC the ciphertext (and nonce), and check the tag before decrypting', 'Any order: both primitives are secure'],
    answer: 2,
    hints: ['Which order lets the receiver reject a forged message without decrypting it?', 'A MAC of the plaintext sent in the clear is deterministic: equal plaintexts give equal tags.', 'Encrypt-then-MAC: the tag covers exactly what was sent, is checked first, and nothing is decrypted unless it passes. MAC-then-encrypt has led to padding oracles; encrypt-and-MAC leaks equality.'],
    solution: 2, wrong: [0, 1, 3],
  });
  ex({
    id: 'mc-x-aad', chapter: 'mc-aead', title: 'Associated data', level: 1, kind: 'choice',
    text: ['A packet header (addresses, sequence number) must be readable by routers but must not be changed. Where does it go in an AEAD?'],
    options: ['Into the plaintext', 'Into the associated data: sent in the clear, covered by the tag', 'Into the nonce', 'Nowhere: AEAD cannot protect it'],
    answer: 1,
    hints: ['Routers must read it, so it cannot be encrypted.', 'The tag can cover data that is not encrypted.', 'Associated data is authenticated but not encrypted: any change makes the tag check fail.'],
    solution: 1, wrong: [0, 2],
  });
  ex({
    id: 'mc-x-nonce', chapter: 'mc-aead', title: 'A repeated nonce', level: 2, kind: 'choice',
    text: ['A device seals two messages with ChaCha20-Poly1305 under the same key and the same nonce. Which statements are true? Choose all that apply.'],
    options: ['The XOR of the two ciphertexts is the XOR of the two plaintexts', 'Both messages share one Poly1305 key, so tags can be forged afterwards', 'Nothing is lost as long as the plaintexts differ', 'Only the associated data is exposed'],
    answer: [0, 1],
    hints: ['The keystream depends only on the key, the nonce and the counter.', 'The one-time Poly1305 key comes from ChaCha20 block 0 under the same key and nonce.', 'The keystream repeats, so c₁ ⊕ c₂ = p₁ ⊕ p₂; and the Poly1305 key repeats, which gives r away. Nonces must be unique per key: a counter is the simplest way.'],
    solution: [0, 1], wrong: [[0], [2], [0, 1, 3]],
  });
  ex({
    id: 'mc-x-hkdf-blocks', chapter: 'mc-aead', title: 'How many HMAC blocks?', level: 1, kind: 'number',
    text: ['HKDF-Expand with SHA-256 is asked for 100 bytes of output. How many blocks T(i) must it compute?'],
    answer: 4,
    hints: ['Each T(i) is one HMAC-SHA-256 output: 32 bytes.', '⌈100 / 32⌉.', '4 blocks (128 bytes), of which the first 100 are kept. The most HKDF-SHA-256 can give is 255 · 32 = 8,160 bytes.'],
    solution: '4', wrong: ['3', '100', '5'],
    whyNot: 'Divide by the 32-byte HMAC output and round up.',
  });
  const HK = { ikm: 'a secret from the ferry handshake', salt: 'quay-salt', info: 'client write key' };
  const PRK = M.hkdfExtract('sha256', enc(HK.salt), enc(HK.ikm));
  const INFO = enc(HK.info);
  const T1 = M.hmac('sha256', PRK, cat(INFO, [1]));
  const IN2 = cat(T1, INFO, [2]);
  ex({
    id: 'mc-x-hkdf-input', chapter: 'mc-aead', title: 'The input to T(2)', level: 1, kind: 'hex',
    text: [`HKDF-SHA-256 with the info “${HK.info}” (${INFO.length} bytes, ${sp(hex(INFO))}). The first block is T(1) = ${sp(hex(T1))}. Write the message HMAC is given to compute T(2), in hex.`],
    answer: hex(IN2),
    hints: ['T(i) = HMAC(PRK, T(i−1) ‖ info ‖ i), with i as one byte.', 'So the message is T(1), then the info bytes, then 02.', sp(hex(IN2)) + ': 32 + 16 + 1 = 49 bytes.'],
    solution: hex(IN2), wrong: [hex(cat(INFO, [2])), hex(cat(T1, INFO, [1])), hex(cat(INFO, T1, [2]))],
    whyNot: 'The previous block comes first, then the info, then the counter byte 02.',
  });
  ex({
    id: 'mc-x-hkdf-t1', chapter: 'mc-aead', title: 'Compute T(1)', level: 3, kind: 'hex',
    text: [`HKDF-SHA-256 with IKM “${HK.ikm}”, salt “${HK.salt}” and info “${HK.info}”. Extract gives PRK = ${sp(hex(PRK))}. Compute the first output block T(1) = HMAC-SHA-256(PRK, info ‖ 01).`, { bench: 'hash', state: { panel: 'hmac' }, text: 'The HMAC panel takes the key in hex: paste the PRK, and the message info ‖ 01 in hex.' }],
    answer: hex(T1),
    hints: ['The HMAC key is the PRK (32 bytes, in hex), not the salt.', `The message is the 16 info bytes followed by 01: ${sp(hex(cat(INFO, [1])))}.`, `T(1) = ${sp(hex(T1))}.`],
    solution: hex(T1), wrong: [hex(M.hmac('sha256', PRK, INFO)), hex(M.hmac('sha256', enc(HK.salt), cat(INFO, [1]))), hex(PRK)],
    whyNot: 'Key: the PRK. Message: the info bytes, then the single byte 01.',
  });
  const RFC5869 = [
    [M.hkdfExtract('sha256', unhex('000102030405060708090a0b0c'), unhex('0b'.repeat(22))), unhex('f0f1f2f3f4f5f6f7f8f9'), 42],
    [M.hkdfExtract('sha256', unhex(Array.from({ length: 80 }, (_, i) => (0x60 + i).toString(16)).join('')), unhex(Array.from({ length: 80 }, (_, i) => i.toString(16).padStart(2, '0')).join(''))), unhex(Array.from({ length: 80 }, (_, i) => (0xb0 + i).toString(16)).join('')), 82],
    [M.hkdfExtract('sha256', new Uint8Array(0), unhex('0b'.repeat(22))), new Uint8Array(0), 42],
    [PRK, INFO, 16], [PRK, INFO, 32], [PRK, INFO, 100],
  ];
  ex({
    id: 'mc-x-code-hkdf', chapter: 'mc-aead', title: 'Write HKDF-Expand', level: 3, kind: 'code', fn: 'hkdfExpand', params: ['prk', 'info', 'L'],
    text: ['Write `hkdfExpand(prk, info, L)`: `prk` and `info` are Uint8Arrays and `L` a Number; return the first L bytes of T(1) ‖ T(2) ‖ …, where T(i) = HMAC(PRK, T(i−1) ‖ info ‖ i) and T(0) is empty. `sha256` and `hmacSha256` are given above the editor (read-only). The first three tests are RFC 5869 test cases 1, 2 and 3.'],
    prelude: SHA_SRC + '\n' + HMAC_SRC,
    start: 'function hkdfExpand(prk, info, L) {\n  \n}\n',
    tests: byteTests((p, i, L) => M.hkdfExpand('sha256', p, i, L), RFC5869),
    timeLimit: 4000,
    hints: ['Keep the previous block t (empty at first) and an output array; loop i = 1, 2, … until you have L bytes.', 'Each message is t, then info, then the single byte i: build it in a new Uint8Array of length t.length + info.length + 1.', HKDF_SRC],
    solution: HKDF_SRC,
    wrong: [HKDF_SRC.replace('    m.set(t);\n', ''), HKDF_SRC.replace('let i = 1;', 'let i = 0;')],
  });

  // =========================================================================================================
  // Chapter 3: key distribution with a trusted server
  // =========================================================================================================
  ex({
    id: 'mc-x-kdc-keys', chapter: 'mc-kdc', title: 'Keys without a server', level: 1, kind: 'number',
    text: ['A company of 1,000 people wants every pair to share its own secret key, with no key distribution centre. How many keys are there in all?'],
    answer: 499500,
    hints: ['One key per unordered pair of people.', 'n(n − 1)/2 for n = 1,000.', '1,000 · 999 / 2 = 499,500 keys, and each person stores 999. With a KDC each person stores one key, shared with the server.'],
    solution: '499500', wrong: ['999000', '1000', '1000000'],
    whyNot: 'Count unordered pairs: n(n − 1)/2.',
  });
  ex({
    id: 'mc-x-ns-flaw', chapter: 'mc-kdc', title: 'The flaw in Needham–Schroeder', level: 2, kind: 'choice',
    text: ['In the symmetric Needham–Schroeder protocol, message 3 is the ticket A → B: {Kab, A}Kbs. An old session key K′ab has leaked. What can an attacker who recorded the old run do?'],
    options: ['Nothing: Kbs is still secret', 'Resend the old ticket {K′ab, A}Kbs to Bob and answer his nonce challenge with K′ab, so Bob accepts K′ab as a fresh key with Alice', 'Read Alice’s new messages to the server', 'Recover Kbs from the ticket'],
    answer: 1,
    hints: ['What in the ticket would tell Bob it is new?', 'Bob’s check in messages 4 and 5 shows only that the other side knows the key inside the ticket.', 'The ticket has no freshness for Bob, so an old ticket plus its leaked key passes. Alice’s nonce Na protects only Alice.'],
    solution: 1, wrong: [0, 3],
  });
  ex({
    id: 'mc-x-ns-fix', chapter: 'mc-kdc', title: 'The repair', level: 2, kind: 'choice',
    text: ['Which change to Needham–Schroeder stops the replay of an old ticket?'],
    options: ['Encrypting the ticket twice', 'Bob first issues a nonce Jb, sealed for the server; the server puts Jb into the ticket, and Bob accepts only a ticket carrying the Jb he just issued', 'Alice signs the ticket', 'Making session keys longer'],
    answer: 1,
    hints: ['Bob needs a value he chose for this session inside the ticket.', 'Only the server can make the ticket, so the value must reach the server first.', 'Bob’s nonce travels through the server into the ticket. An old ticket carries an old nonce and is rejected. Kerberos takes the other route: timestamps.'],
    solution: 1, wrong: [0, 2, 3],
  });
  const KW = { 'ticket-granting ticket|sealed under': 'Ktgs', 'ticket-granting ticket|who can open it': 'TGS', 'service ticket|sealed under': 'Kv', 'service ticket|who can open it': 'V', 'authenticator to V|sealed under': 'Kc,v', 'authenticator to V|who can open it': 'V' };
  ex({
    id: 'mc-x-kerb-who', chapter: 'mc-kdc', title: 'Who can open what', level: 2, kind: 'table',
    text: ['In the Kerberos flow, fill in the key each item is sealed under and who can open it. Write keys as Kc, Kc,tgs, Ktgs, Kc,v or Kv, and parties as C, AS, TGS or V.', { topic: 'p13-kerberos', frame: 6, caption: 'Message 4: the TGS hands the client a service key and a service ticket.' }],
    rows: ['ticket-granting ticket', 'service ticket', 'authenticator to V'], cols: ['sealed under', 'who can open it'], cells: KW, cellKind: 'text', corner: 'item',
    hints: ['Tickets are sealed for the server that will read them, so the client carries them without reading.', 'The TGT is read by the TGS; the service ticket by the service V. The authenticator proves the client holds the session key from the ticket.', 'TGT: Ktgs, opened by the TGS. Service ticket: Kv, opened by V. Authenticator to V: Kc,v, opened by V (after it gets Kc,v from the ticket).'],
    solution: KW, wrong: [Object.assign({}, KW, { 'service ticket|who can open it': 'C' }), Object.assign({}, KW, { 'ticket-granting ticket|sealed under': 'Kc' })],
  });
  ex({
    id: 'mc-x-kerb-clock', chapter: 'mc-kdc', title: 'Why Kerberos needs clocks', level: 1, kind: 'choice',
    text: ['A server’s clock drifts twenty minutes behind the rest of the network, beyond the allowed skew. What happens to Kerberos logins to it?'],
    options: ['Nothing', 'Its checks of authenticator timestamps fail, so valid requests are refused', 'Replays become possible but logins work', 'Passwords are sent in the clear'],
    answer: 1,
    hints: ['Authenticators carry a timestamp, checked against the receiver’s clock.', 'A timestamp outside the window is treated as a replay.', 'Fresh authenticators look stale to that server, so it refuses them. Kerberos trades nonce round trips for synchronised clocks.'],
    solution: 1, wrong: [0, 2],
  });

  // =========================================================================================================
  // Chapter 4: Diffie–Hellman, certificates and TLS 1.3
  // =========================================================================================================
  const mp = (b, e, m) => { let r = 1n; b %= m; while (e) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
  const DP = 47n, DG = 5n, DA = 9n, DBb = 13n;
  const GA = mp(DG, DA, DP), GB = mp(DG, DBb, DP), DK = mp(GB, DA, DP);
  ex({
    id: 'mc-x-dh-pub', chapter: 'mc-pki', title: 'Alice’s share', level: 1, kind: 'number',
    text: ['A toy Diffie–Hellman exchange uses p = 47 and g = 5. Alice’s secret is a = 9. What does she send, g^a mod p?'],
    answer: Number(GA),
    hints: ['Square and multiply: 5² = 25, 5⁴ = 625 mod 47.', `5⁴ ≡ ${mp(5n, 4n, 47n)}, 5⁸ ≡ ${mp(5n, 8n, 47n)}, and 5⁹ = 5⁸ · 5.`, `5⁹ mod 47 = ${GA}.`],
    solution: String(GA), wrong: ['45', String(mp(DG, DA, 48n)), '1953125'],
    whyNot: 'Reduce mod 47 after every multiplication.',
  });
  ex({
    id: 'mc-x-dh-toy', chapter: 'mc-pki', title: 'The shared key', level: 2, kind: 'number',
    text: [`The same exchange: p = 47, g = 5, Alice’s a = 9 and Bob’s b = 13. Bob sends g^b mod p = ${GB}. What key do both compute?`],
    answer: Number(DK),
    hints: ['Alice computes (g^b)^a mod p; Bob computes (g^a)^b mod p. They agree.', `Alice: ${GB}⁹ mod 47. Bob: ${GA}¹³ mod 47.`, `Both get ${DK}. With a 47-element group an eavesdropper finds a by trying every value; real groups have 2²⁵⁶ or more.`],
    solution: String(DK), wrong: [String(mp(DG, DA + DBb, DP)), String((GA * GB) % DP), String(GB)],
    whyNot: 'Raise the other side’s share to your own secret, mod 47.',
  });
  ex({
    id: 'mc-x-mitm', chapter: 'mc-pki', title: 'What is missing?', level: 2, kind: 'choice',
    text: ['Two parties run plain Diffie–Hellman, then encrypt and MAC everything under the shared key with a sound AEAD. Someone who can change messages on the line reads and rewrites everything. Which flaw lets this happen?'],
    options: ['The group is too small', 'Nothing authenticates the shares: each side cannot tell whether g^x came from the other party or from someone in the middle', 'The AEAD has no associated data', 'The shared key is not hashed'],
    answer: 1,
    hints: ['The attacker ran two exchanges, one with each side.', 'Each side’s key is perfectly good, just shared with the wrong party.', 'The exchange is unauthenticated. Signing both shares with long-term keys (whose public halves are trusted through certificates) binds them to identities, as TLS 1.3 does.'],
    solution: 1, wrong: [0, 2, 3],
  });
  // certificate chains from the engine, laid out field by field
  const chainTable = (chain) => chain.map((c, i) => {
    const v = (k) => (k === 'ca' ? (c.ca ? 'yes' : 'no') : k === 'pathLen' ? (c.pathLen === null || c.pathLen === undefined ? '–' : String(c.pathLen)) : k === 'names' ? (c.names || []).join(', ') || '–' : k === 'keyId' ? '`' + c.keyId + '`' : String(c[k]).replace(/^CN=/, ''));
    const rows = [['Subject', 'subject'], ['Issuer', 'issuer'], ['Valid from', 'notBefore'], ['Valid until', 'notAfter'], ['CA', 'ca'], ['Path length', 'pathLen'], ['Names', 'names'], ['Key id', 'keyId']];
    return { table: [['Certificate ' + (i + 1), i === 0 ? 'the server’s' : 'issuer of certificate ' + i]].concat(rows.map(([l, k]) => [l, v(k)])), caption: i === chain.length - 1 ? 'Every signature in this chain verifies under the key of the certificate after it.' : '' };
  });
  const today = (d) => ((d.result.checks.find((c) => c.what === 'validity') || {}).say || '').replace(/.*today is ([0-9-]+).*/, '$1');
  const CEX = S.Proto.certScenario('expired', { seed: 1 });
  ex({
    id: 'mc-x-cert-expired', chapter: 'mc-pki', title: 'A chain checked in winter', level: 1, kind: 'choice',
    text: [`A client asks for www.harbourbank.example on ${today(CEX)} and receives this chain. Its trust store holds Lantern Root CA with key id ${CEX.chain[CEX.chain.length - 1].keyId}. Which certificate fails, and why?`, ...chainTable(CEX.chain)],
    options: ['Certificate 1: it has expired', 'Certificate 2: it is not a CA', 'Certificate 3: it is not in the trust store', 'None: the chain is valid'],
    answer: 0,
    hints: ['Compare each validity window with today’s date.', `Certificate 1 is valid until ${CEX.chain[0].notAfter}.`, `Certificate 1 expired on ${CEX.chain[0].notAfter}, before ${today(CEX)}; the client rejects the chain at that check.`],
    solution: 0, wrong: [1, 3],
  });
  const CRT = S.Proto.certScenario('self-made-root', { seed: 1 });
  const TS = CRT.pki.trustStore[0];
  ex({
    id: 'mc-x-cert-root', chapter: 'mc-pki', title: 'The right name, the wrong key', level: 3, kind: 'choice',
    text: [`A client asks for www.harbourbank.example on ${today(CRT)} and receives this chain. Its trust store holds one root: ${TS.subject.replace(/^CN=/, '')}, key id ${TS.keyId}. Which certificate fails, and why?`, ...chainTable(CRT.chain)],
    options: ['Certificate 1: the name does not match', 'Certificate 1: it is not signed by its issuer', 'Certificate 2: it carries the trusted root’s name but a different key, so it is not the trust anchor', 'None: the root’s name is in the trust store'],
    answer: 2,
    hints: ['A trust store holds keys, not just names.', `Compare certificate 2’s key id, ${CRT.chain[1].keyId}, with the stored root’s, ${TS.keyId}.`, 'Certificate 2 calls itself Lantern Root CA but its key is not the trusted one: anyone can make a self-signed certificate with any name. The chain ends at no trust anchor and is rejected.'],
    solution: 2, wrong: [0, 1, 3],
  });
  const CLF = S.Proto.certScenario('leaf-as-ca', { seed: 1 });
  ex({
    id: 'mc-x-cert-leaf', chapter: 'mc-pki', title: 'Four certificates', level: 3, kind: 'choice',
    text: [`A client asks for mail.lanterntrust.example on ${today(CLF)} and receives this chain, which ends at the root in its trust store (key id ${CLF.chain[CLF.chain.length - 1].keyId}). Which certificate fails validation, and why?`, ...chainTable(CLF.chain)],
    options: ['Certificate 1: its name does not match', 'Certificate 2: it signed certificate 1 but is not a CA certificate', 'Certificate 3: its path length of 0 is exceeded', 'Certificate 4: the root is not trusted'],
    answer: 1,
    hints: ['Check each certificate that signed another: it must be marked as a CA, within its path length.', 'Certificate 2 belongs to www.harbourbank.example, a server.', `Certificate 2 is an end-entity certificate (CA: no), so its genuine signature on certificate 1 counts for nothing. The validator stops there; it would also have found that certificate 3’s path length 0 is exceeded, but the first failure is certificate 2.`],
    solution: 1, wrong: [0, 3],
    whyNot: { 2: 'The validator checks from the server certificate upwards and stops at the first failure: certificate 2 fails before certificate 3 is examined.' },
  });
  ex({
    id: 'mc-x-revocation', chapter: 'mc-pki', title: 'CRL or OCSP', level: 1, kind: 'choice',
    text: ['A certificate’s key was stolen this morning and the CA revoked it at once. Which statements are true? Choose all that apply.'],
    options: ['A client using last week’s CRL may still accept the certificate', 'An OCSP response for the serial, fetched now, reports it revoked', 'Revocation changes the certificate itself', 'An OCSP responder learns which sites the client visits, unless the server staples the response'],
    answer: [0, 1, 3],
    hints: ['A CRL is a signed list published every few days.', 'OCSP is a signed answer about one serial, fetched when needed.', 'A stale CRL misses it; a fresh OCSP answer catches it; the responder sees each query (stapling avoids that). The certificate itself never changes: that is why revocation needs a separate channel.'],
    solution: [0, 1, 3], wrong: [[1], [0, 1, 2, 3], [0, 3]],
  });
  ex({
    id: 'mc-x-tls-rtt', chapter: 'mc-pki', title: 'Round trips', level: 1, kind: 'number',
    text: ['In a full TLS 1.3 handshake without a pre-shared key, how many round trips pass before the client can send its first application data (the request)?'],
    answer: 1,
    hints: ['The client sends its key share in the ClientHello, guessing the group.', 'The server’s reply carries its share, certificate, signature and Finished in one flight.', 'One: the request goes with the client Finished. TLS 1.2 needed two.'],
    solution: '1', wrong: ['2', '0', '3'],
    whyNot: 'Count the flights: the key shares travel in the hellos.',
  });
  ex({
    id: 'mc-x-tls-keys', chapter: 'mc-pki', title: 'Which keys protect the certificate?', level: 2, kind: 'choice',
    text: ['In TLS 1.3, under which keys does the server’s Certificate message travel?'],
    options: ['In the clear', 'The server handshake traffic keys, derived from the handshake secret (after the key shares)', 'The application traffic keys', 'The server’s long-term private key'],
    answer: 1,
    hints: ['Everything after ServerHello is encrypted.', 'The application keys come from the master secret, later in the schedule.', 'The handshake traffic keys: so an eavesdropper does not even see which certificate was sent, unlike in TLS 1.2.'],
    solution: 1, wrong: [0, 2, 3],
  });
  ex({
    id: 'mc-x-tls-label', chapter: 'mc-pki', title: 'A label in the schedule', level: 2, kind: 'string',
    text: ['TLS 1.3 derives the server’s handshake traffic secret with Derive-Secret(handshake secret, label, H(ClientHello ‖ ServerHello)). What is the label? (The client’s is “c hs traffic”.)', { topic: 'p13-tls-keys', frame: 4, caption: 'The server handshake traffic secret in the schedule.' }],
    answer: 's hs traffic',
    accept: (t) => String(t).trim().replace(/^["“]|["”]$/g, '').replace(/\s+/g, ' ').toLowerCase() === 's hs traffic',
    hints: ['Labels are short ASCII strings naming who and what.', 'c for client, s for server; hs for handshake.', '“s hs traffic”. Different labels give unrelated secrets from the same handshake secret.'],
    solution: 's hs traffic', wrong: ['c hs traffic', 's ap traffic', 'server handshake'],
  });
  const TIV = '1b675a1542d854bbdc7d0f53', SEQ = 257n;
  const TN = (BigInt('0x' + TIV) ^ SEQ).toString(16).padStart(24, '0');
  ex({
    id: 'mc-x-tls-nonce', chapter: 'mc-pki', title: 'A record nonce', level: 2, kind: 'hex',
    text: [`A TLS 1.3 connection has the 12-byte write IV ${sp(TIV)}. Each record’s nonce is the IV XORed with the record’s sequence number, written as a 64-bit big-endian number and padded on the left to 12 bytes. What is the nonce of record 257?`],
    answer: TN,
    hints: ['257 = 0x101: as 12 bytes, 00 … 00 01 01.', 'Only the last two bytes of the IV change: 0f 53 ⊕ 01 01.', `0f53 ⊕ 0101 = 0e52, so the nonce is ${sp(TN)}.`],
    solution: TN, wrong: [TIV, TIV.slice(0, 20) + '0f54', (BigInt('0x' + TIV) + SEQ).toString(16).padStart(24, '0')],
    whyNot: 'XOR, do not add; and the sequence number sits in the last bytes.',
  });
})(globalThis.Sifer = globalThis.Sifer || {});
