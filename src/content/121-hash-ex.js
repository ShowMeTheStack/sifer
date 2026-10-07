// Part 12, hash functions: the exercises. The lessons are in 120-hash.js; the challenges, the tour and the course in
// 122-hash-ctf.js. Messages, words and keys are our own (“Gulls over the pier at noon”, …) except where a standard's
// published vector is named; every answer is worked out here by S.Hash, S.SHA256 and S.Keccak when the page loads,
// and the code exercises are checked against those engines and the FIPS 180-4 example values.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('hs-x-props')) return;
  const ex = (o) => C.exercise(o);
  const H = S.Hash, SH = S.SHA256;
  const enc = (t) => new TextEncoder().encode(t);
  const hex = (a) => Array.from(a, (v) => v.toString(16).padStart(2, '0')).join('');
  const h8 = (v) => (v >>> 0).toString(16).padStart(8, '0');
  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
  const sig0 = (x) => (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0;
  const sig1 = (x) => (rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10)) >>> 0;
  const Sig0 = (x) => (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)) >>> 0;
  const Sig1 = (x) => (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) >>> 0;
  const ch = (e, f, g) => ((e & f) ^ (~e & g)) >>> 0;
  const maj = (a, b, c) => ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
  const add = (...xs) => xs.reduce((s, x) => (s + x) >>> 0, 0);
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

  // ---- the values of these exercises, from the engines ------------------------------------------------------------
  const GULLS = 'Gulls over the pier at noon';
  const GBLOCK = SH.pad(enc(GULLS)).slice(0, 64);
  const GW = SH.schedule(GBLOCK).W;
  const IV = H.get('sha256').iv.slice();
  const R0 = SH.compress(IV, GBLOCK).rounds[0];
  const K0 = R0.K, W0 = R0.W;
  /** one SHA-256 round on eight registers, written out as a student would */
  const round = (r, k, w) => {
    const [a, b, c, d, e, f, g, hh] = r;
    const t1 = add(hh, Sig1(e), ch(e, f, g), k, w), t2 = add(Sig0(a), maj(a, b, c));
    return [add(t1, t2), a, b, c, add(d, t1), e, f, g];
  };
  const RG = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];
  const T1 = add(IV[7], Sig1(IV[4]), ch(IV[4], IV[5], IV[6]), K0, W0), T2 = add(Sig0(IV[0]), maj(IV[0], IV[1], IV[2]));

  // =========================================================================================================
  // Chapter 1: what a hash must resist
  // =========================================================================================================
  ex({
    id: 'hs-x-props', chapter: 'hs-req', title: 'Which game is it?', level: 1, kind: 'choice',
    text: ['An attacker is handed the digest 3f9a… of a stolen PIN-reset token and wants any input with that digest. Which property is she attacking?'],
    options: ['Preimage resistance', 'Second-preimage resistance', 'Collision resistance', 'None: digests can be inverted'],
    answer: 0,
    hints: ['She is given a digest, not a message.', 'Finding any input for a given output is the preimage game.', 'Preimage resistance. Second preimage would start from a given message; collision lets the attacker choose both messages.'],
    solution: 0, wrong: [1, 2],
    whyNot: { 1: 'A second preimage starts from a given message, not from a digest alone.', 2: 'In the collision game no target is given at all: the attacker picks both messages.' },
  });
  ex({
    id: 'hs-x-props-use', chapter: 'hs-req', title: 'Who relies on collision resistance?', level: 2, kind: 'choice',
    text: ['In which of these uses can the party who chooses the message also profit from a collision? Choose all that apply.'],
    options: ['A notary signs SHA-256 of a contract that the client drafted', 'A server stores SHA-256 of each password', 'A build system signs SHA-256 of a source archive submitted by an outside contributor', 'A mirror publishes the digest of a file its own staff produced'],
    answer: [0, 2],
    hints: ['A collision helps only someone who prepares two messages in advance and gets one of them accepted.', 'In the password file the attacker does not choose the stored password; at the mirror the staff, not the attacker, chose the file.', 'The contract and the contributed archive: in both, the party choosing the message can prepare an innocent and a harmful twin with one digest, get the innocent one signed, and swap.'],
    solution: [0, 2], wrong: [[0], [0, 1, 2], [1, 3]],
  });
  ex({
    id: 'hs-x-pre-work', chapter: 'hs-req', title: 'The price of a preimage', level: 1, kind: 'number',
    text: ['A system keeps only the first 24 bits of SHA-256 as a check value. About how many guesses does a generic preimage search need on average to hit a given 24-bit value?'],
    answer: 16777216, tolerance: 200000,
    hints: ['Each guess hits the target with chance 1 in 2²⁴.', 'The expected number of tries for an event of chance p is 1/p.', '2²⁴ = 16,777,216 tries on average. A collision on the same 24 bits would take only about 5,000.'],
    solution: '16777216', wrong: ['4096', '8388608', '5134'],
    whyNot: 'With one target fixed there are no pairs to exploit: each try has chance 2⁻²⁴.',
  });
  const WT = { 'n = 64|preimage': '64', 'n = 64|collision': '32', 'n = 160|preimage': '160', 'n = 160|collision': '80', 'n = 256|preimage': '256', 'n = 256|collision': '128' };
  ex({
    id: 'hs-x-work-table', chapter: 'hs-req', title: 'Generic work factors', level: 2, kind: 'table',
    text: ['For an ideal hash with an n-bit digest, write the base-2 logarithm of the generic work for each game (write 64 for 2⁶⁴).'],
    rows: ['n = 64', 'n = 160', 'n = 256'], cols: ['preimage', 'collision'], cells: WT, cellKind: 'text', corner: 'digest',
    hints: ['Preimage: one target, each try has chance 2⁻ⁿ.', 'Collision: the birthday bound, about 2ⁿᐟ².', 'Preimage 64, 160, 256; collision 32, 80, 128. SHA-1’s 160 bits promised 2⁸⁰ for collisions; the 2017 attack needed about 2⁶³.'],
    solution: WT, wrong: [Object.assign({}, WT, { 'n = 256|collision': '256' }), Object.assign({}, WT, { 'n = 160|collision': '40' })],
  });
  ex({
    id: 'hs-x-pairs', chapter: 'hs-req', title: 'Counting pairs', level: 1, kind: 'number',
    text: ['Forty messages are hashed. How many unordered pairs of messages could collide?'],
    answer: 780,
    hints: ['Each message pairs with every other, and the pair (i, j) is the pair (j, i).', 'q(q − 1)/2.', '40 · 39 / 2 = 780.'],
    solution: '780', wrong: ['1600', '1560', '40'],
    whyNot: 'Count unordered pairs of different messages: q(q − 1)/2.',
  });
  ex({
    id: 'hs-x-bday-23', chapter: 'hs-req', title: 'The smallest room', level: 1, kind: 'number',
    text: ['What is the smallest number of people for which the chance that two share a birthday (365 equally likely days) is more than one half?'],
    answer: 23,
    hints: ['Compute the chance that all are different: (364/365)(363/365)⋯.', 'It drops below one half between 22 and 23 people.', '23 people: the chance of a shared day is about 0.507 (for 22 it is 0.476).'],
    solution: '23', wrong: ['183', '22', '366'],
    whyNot: 'Multiply (1 − i/365) for i = 1 … q−1 until the product drops below one half.',
  });
  const BP = H.birthdayProb(300, 65536);
  ex({
    id: 'hs-x-bday-prob', chapter: 'hs-req', title: 'Three hundred 16-bit tags', level: 2, kind: 'number',
    text: ['A protocol gives each message a 16-bit check value. After 300 messages, what is the chance that at least two share a value? Give it as a decimal between 0 and 1, to two places.'],
    answer: +BP.toFixed(3), tolerance: 0.01,
    hints: ['N = 2¹⁶ = 65,536 and q = 300.', 'P ≈ 1 − exp(−q(q − 1)/2N) = 1 − exp(−89,700/131,072).', `The exponent is about −0.684, so P ≈ ${BP.toFixed(2)}: a coin toss after only 300 messages.`],
    solution: BP.toFixed(2), wrong: ['0.0046', '0.68', '0.0137'],
    whyNot: 'Use P ≈ 1 − exp(−q(q − 1)/2N) with N = 65,536.',
  });
  const EXP40 = Math.sqrt((Math.PI * 2 ** 40) / 2);
  ex({
    id: 'hs-x-bday-bound', chapter: 'hs-req', title: 'A 40-bit digest', level: 2, kind: 'number',
    text: ['A legacy system keeps 40-bit digests. How many random messages does a birthday search hash, on average, before the first collision? Use √(πN/2) and give a whole number (within 1%).'],
    answer: Math.round(EXP40), tolerance: Math.round(EXP40 / 100),
    hints: ['N = 2⁴⁰ ≈ 1.0995 · 10¹².', 'πN/2 ≈ 1.727 · 10¹²; take the square root.', `About ${Math.round(EXP40).toLocaleString('en')} messages, a second's work for a laptop. 40 bits protect nothing against collisions.`],
    solution: String(Math.round(EXP40)), wrong: ['1048576', '1099511627776', '549755813888'],
    whyNot: 'The birthday bound is about the square root of N, times √(π/2).',
  });

  // =========================================================================================================
  // Chapter 2: Merkle–Damgård and SHA-256
  // =========================================================================================================
  ex({
    id: 'hs-x-pad-len', chapter: 'hs-md', title: 'How long after padding?', level: 1, kind: 'number',
    text: ['A 100-byte message is padded for SHA-256. How many bytes long is the padded message?'],
    answer: 128,
    hints: ['Padding adds the byte 80, zeros, and 8 bytes of length, to a multiple of 64.', '100 + 9 = 109 bytes at least; round up to a multiple of 64.', '128 bytes: two blocks, with 19 zero bytes between the 80 and the length.'],
    solution: '128', wrong: ['109', '64', '192'],
    whyNot: 'Add at least 9 bytes (80 and the 8-byte length), then round up to a multiple of 64.',
  });
  const LENS = [0, 27, 55, 56, 119, 120];
  const PADT = {};
  for (const n of LENS) { PADT[n + ' bytes|zero bytes'] = String((((55 - n) % 64) + 64) % 64); PADT[n + ' bytes|blocks'] = String(Math.ceil((n + 9) / 64)); }
  ex({
    id: 'hs-x-pad-table', chapter: 'hs-md', title: 'Padding for six lengths', level: 2, kind: 'table',
    text: ['For SHA-256, fill in how many zero bytes go between the 80 byte and the 8-byte length, and how many 64-byte blocks the padded message has.'],
    rows: LENS.map((n) => n + ' bytes'), cols: ['zero bytes', 'blocks'], cells: PADT, cellKind: 'text', corner: 'message',
    hints: ['Message + 1 + zeros + 8 must be a multiple of 64, with as few zeros as possible.', 'zeros = (55 − length) mod 64; blocks = ⌈(length + 9)/64⌉.', 'Zero bytes: 55, 28, 0, 63, 0, 63. Blocks: 1, 1, 1, 2, 2, 3.'],
    solution: PADT, wrong: [Object.assign({}, PADT, { '56 bytes|blocks': '1' }), Object.assign({}, PADT, { '0 bytes|zero bytes': '63' })],
  });
  const GLUE27 = hex(H.get('sha256').glue(27));
  ex({
    id: 'hs-x-pad-hex', chapter: 'hs-md', title: 'Write the padding', level: 2, kind: 'hex',
    text: [`The message “${GULLS}” is 27 bytes. Write the bytes SHA-256 appends to it, in hex, up to the end of the block.`],
    answer: GLUE27,
    hints: ['The padding is 80, then zeros, then the length in bits as an 8-byte big-endian number.', '27 + 1 + 28 + 8 = 64: 28 zero bytes. The length is 27 · 8 = 216 bits = d8.', `80, then 28 bytes of 00, then 00000000000000d8: ${sp(GLUE27)}.`],
    solution: GLUE27, wrong: ['80' + '00'.repeat(28) + '000000000000001b', '80' + '00'.repeat(29) + '00000000000000d8', '80' + '00'.repeat(28) + 'd800000000000000'],
    whyNot: 'The length is in bits, not bytes, and big-endian: the last byte holds its low eight bits.',
  });
  ex({
    id: 'hs-x-code-pad', chapter: 'hs-md', title: 'Write SHA-256 padding', level: 2, kind: 'code', fn: 'sha256Pad', params: ['msg'],
    text: ['Write `sha256Pad(msg)`: `msg` is a Uint8Array; return a new Uint8Array holding the message followed by its SHA-256 padding. The tests include the FIPS 180-4 example “abc”, which pads to 61 62 63 80 00 … 00 18, and lengths 55, 56 and 64.'],
    start: 'function sha256Pad(msg) {\n  \n}\n',
    tests: byteTests((m) => SH.pad(m), [[enc('abc')], [new Uint8Array(0)], [enc(GULLS)], [new Uint8Array(55).fill(0x61)], [new Uint8Array(56).fill(0x62)], [new Uint8Array(64).fill(0x63)], [new Uint8Array(119).fill(7)], [new Uint8Array(300).map((_, i) => i & 255)]]),
    hints: ['The length of the result is the smallest multiple of 64 that is at least msg.length + 9.', 'Copy the message, put 0x80 right after it, and write the bit length into the last 8 bytes, most significant byte first. For these lengths the top four bytes stay 0.', 'function sha256Pad(msg) {\n  const n = msg.length, total = Math.ceil((n + 9) / 64) * 64;\n  const out = new Uint8Array(total);\n  out.set(msg);\n  out[n] = 0x80;\n  const bits = n * 8;\n  for (let i = 0; i < 4; i++) out[total - 1 - i] = (bits >>> (8 * i)) & 255;\n  return out;\n}'],
    solution: 'function sha256Pad(msg) {\n  const n = msg.length, total = Math.ceil((n + 9) / 64) * 64;\n  const out = new Uint8Array(total);\n  out.set(msg);\n  out[n] = 0x80;\n  const bits = n * 8;\n  for (let i = 0; i < 4; i++) out[total - 1 - i] = (bits >>> (8 * i)) & 255;\n  return out;\n}\n',
    wrong: ['function sha256Pad(msg) {\n  const n = msg.length, total = Math.ceil((n + 9) / 64) * 64;\n  const out = new Uint8Array(total);\n  out.set(msg);\n  out[n] = 0x80;\n  for (let i = 0; i < 4; i++) out[total - 1 - i] = (n >>> (8 * i)) & 255;\n  return out;\n}\n', 'function sha256Pad(msg) {\n  const n = msg.length, total = Math.ceil((n + 1) / 64) * 64 + 8;\n  const out = new Uint8Array(total);\n  out.set(msg);\n  out[n] = 0x80;\n  const bits = n * 8;\n  for (let i = 0; i < 4; i++) out[total - 1 - i] = (bits >>> (8 * i)) & 255;\n  return out;\n}\n'],
  });
  const SX = 0x5c3a91e7;
  ex({
    id: 'hs-x-sigma1', chapter: 'hs-md', title: 'σ1 of one word', level: 2, kind: 'hex', value: true,
    text: ['Compute σ1(5c3a91e7), where σ1(x) = (x ⋙ 17) ⊕ (x ⋙ 19) ⊕ (x ≫ 10) on 32-bit words. Give 8 hex digits.'],
    answer: h8(sig1(SX)),
    hints: ['⋙ rotates (the bits that fall off the right come back on the left); ≫ shifts in zeros.', `x ⋙ 17 = ${h8(rotr(SX, 17))}, x ⋙ 19 = ${h8(rotr(SX, 19))}, x ≫ 10 = ${h8(SX >>> 10)}.`, `XOR the three: σ1(5c3a91e7) = ${h8(sig1(SX))}.`],
    solution: h8(sig1(SX)), wrong: [h8((rotr(SX, 17) ^ rotr(SX, 19) ^ rotr(SX, 10)) >>> 0), h8(sig0(SX)), h8((SX >>> 17 ^ SX >>> 19 ^ SX >>> 10) >>> 0)],
    whyNot: 'Two rotations (17 and 19) and one plain shift (10), XORed.',
  });
  const W16 = GW[16];
  ex({
    id: 'hs-x-sched-w16', chapter: 'hs-md', title: 'A schedule word', level: 3, kind: 'hex', value: true,
    text: [`The block of “${GULLS}” (with its padding) gives these words. Compute W₁₆ = σ1(W₁₄) + W₉ + σ0(W₁) + W₀ mod 2³².`,
      { table: [['word', 'value'], ['W₀', '`' + h8(GW[0]) + '`'], ['W₁', '`' + h8(GW[1]) + '`'], ['W₉', '`' + h8(GW[9]) + '`'], ['W₁₄', '`' + h8(GW[14]) + '`']], caption: 'The four taps of W₁₆.' },
      { math: 'σ0(x) = (x ⋙ 7) ⊕ (x ⋙ 18) ⊕ (x ≫ 3)\nσ1(x) = (x ⋙ 17) ⊕ (x ⋙ 19) ⊕ (x ≫ 10)' }],
    answer: h8(W16),
    hints: [`W₁₄ is 0 (the top half of the length), so σ1(W₁₄) = 0.`, `σ0(W₁) = σ0(${h8(GW[1])}) = ${h8(sig0(GW[1]))}.`, `W₁₆ = 0 + ${h8(GW[9])} + ${h8(sig0(GW[1]))} + ${h8(GW[0])} = ${h8(W16)} (mod 2³²).`],
    solution: h8(W16), wrong: [h8((GW[9] ^ sig0(GW[1]) ^ GW[0]) >>> 0), h8(add(GW[9], GW[1], GW[0])), h8(GW[17])],
    whyNot: 'The four terms are added mod 2³², not XORed, and σ0 is applied to W₁.',
  });
  const CE = 0xf0f0aa55, CF = 0x12345678, CG = 0x9abcdef0, MA = 0x0ff00ff0, MB = 0x33cc33cc, MC = 0x55aa55aa;
  const CMT = { 'Ch(e, f, g)|value': h8(ch(CE, CF, CG)), 'Maj(a, b, c)|value': h8(maj(MA, MB, MC)) };
  ex({
    id: 'hs-x-ch-maj', chapter: 'hs-md', title: 'Ch and Maj', level: 2, kind: 'table',
    text: ['Compute the two bitwise functions of a SHA-256 round on these words: e = f0f0aa55, f = 12345678, g = 9abcdef0 and a = 0ff00ff0, b = 33cc33cc, c = 55aa55aa.', { math: 'Ch(e, f, g)  = (e ∧ f) ⊕ (¬e ∧ g)\nMaj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)' }],
    rows: ['Ch(e, f, g)', 'Maj(a, b, c)'], cols: ['value'], cells: CMT, cellKind: 'hex',
    hints: ['Work one hex digit at a time: every bit is independent.', 'Ch: where e has a 1 take f’s bit, else g’s. The first digit of e is f (1111), so Ch’s first digit is f’s, 1; the second digit of e is 0, so Ch takes g’s second digit, a.', `Ch = ${CMT['Ch(e, f, g)|value']}, Maj = ${CMT['Maj(a, b, c)|value']}.`],
    solution: CMT, wrong: [Object.assign({}, CMT, { 'Ch(e, f, g)|value': h8(ch(CE, CG, CF)) }), Object.assign({}, CMT, { 'Maj(a, b, c)|value': h8((MA ^ MB ^ MC) >>> 0) })],
  });
  const AFTER = round(IV, K0, W0);
  const RT = Object.fromEntries(RG.map((r, i) => [r + '|after round 0', h8(AFTER[i])]));
  ex({
    id: 'hs-x-round-table', chapter: 'hs-md', title: 'The registers after round 0', level: 3, kind: 'table',
    text: [`Run round 0 of SHA-256 on the first block of “${GULLS}”. The registers start as the IV; K₀ = ${h8(K0)} and W₀ = ${h8(W0)}. Fill in all eight registers after the round.`,
      { table: [['register', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'], ['before'].concat(IV.map((v) => '`' + h8(v) + '`'))], caption: 'The IV of SHA-256.' },
      { math: 'T1 = h + Σ1(e) + Ch(e, f, g) + K₀ + W₀      Σ1(e) = (e ⋙ 6) ⊕ (e ⋙ 11) ⊕ (e ⋙ 25)\nT2 = Σ0(a) + Maj(a, b, c)                 Σ0(a) = (a ⋙ 2) ⊕ (a ⋙ 13) ⊕ (a ⋙ 22)\nnew a = T1 + T2, new e = d + T1, the others shift down' }],
    rows: RG, cols: ['after round 0'], cells: RT, cellKind: 'hex', corner: 'register',
    hints: ['Six of the eight are free: b, c, d take the old a, b, c, and f, g, h the old e, f, g.', `Σ1(e) = ${h8(Sig1(IV[4]))}, Ch(e, f, g) = ${h8(ch(IV[4], IV[5], IV[6]))}, so T1 = ${h8(T1)}; Σ0(a) = ${h8(Sig0(IV[0]))}, Maj = ${h8(maj(IV[0], IV[1], IV[2]))}, so T2 = ${h8(T2)}.`, `a = T1 + T2 = ${h8(AFTER[0])}, e = d + T1 = ${h8(AFTER[4])}; then b…d = ${h8(AFTER[1])} ${h8(AFTER[2])} ${h8(AFTER[3])} and f…h = ${h8(AFTER[5])} ${h8(AFTER[6])} ${h8(AFTER[7])}.`],
    solution: RT, wrong: [Object.assign({}, RT, { 'b|after round 0': h8(IV[1]) }), Object.assign({}, RT, { 'e|after round 0': h8(T1) })],
  });
  const ABC = SH.pad(enc('abc'));
  const W0abc = H.readBE(ABC, 0);
  const KS = SH.compress(IV, ABC).rounds.map((r) => r.K);
  const rnd = (seed) => { let s = seed >>> 0; return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s; }; };
  const R = rnd(1207);
  const rcases = [[IV.slice(), KS[0], W0abc], [AFTER.slice(), KS[1], GW[1]]];
  for (let i = 0; i < 6; i++) rcases.push([Array.from({ length: 8 }, R), KS[(i * 11) % 64], R()]);
  ex({
    id: 'hs-x-code-round', chapter: 'hs-md', title: 'Write one SHA-256 round', level: 3, kind: 'code', fn: 'sha256Round', params: ['r', 'k', 'w'],
    text: ['Write `sha256Round(r, k, w)`: `r` is an array of the eight registers [a, b, c, d, e, f, g, h] (unsigned 32-bit Numbers), `k` the round constant and `w` the schedule word; return the eight registers after the round, unsigned. The first test is round 0 of the FIPS 180-4 example “abc”, where a becomes 5d6aebcd and e becomes fa2a4622.'],
    start: 'function sha256Round(r, k, w) {\n  const rotr = (x, n) =>\n    ((x >>> n) | (x << (32 - n))) >>> 0;\n  \n}\n',
    ref: (r, k, w) => round(r, k, w),
    cases: rcases,
    hints: ['Write Σ0, Σ1, Ch and Maj as small arrow functions with rotr; ~e flips every bit of e.', 'Add with (x + y) >>> 0 after each sum (or sum and finish with >>> 0: five 32-bit numbers stay below 2⁵³, so a plain sum then >>> 0 is exact).', 'function sha256Round(r, k, w) {\n  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;\n  const [a, b, c, d, e, f, g, h] = r;\n  const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);\n  const ch = (e & f) ^ (~e & g), maj = (a & b) ^ (a & c) ^ (b & c);\n  const t1 = (h + (S1 >>> 0) + (ch >>> 0) + k + w) >>> 0, t2 = ((S0 >>> 0) + (maj >>> 0)) >>> 0;\n  return [(t1 + t2) >>> 0, a, b, c, (d + t1) >>> 0, e, f, g];\n}'],
    solution: 'function sha256Round(r, k, w) {\n  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;\n  const [a, b, c, d, e, f, g, h] = r;\n  const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);\n  const ch = (e & f) ^ (~e & g), maj = (a & b) ^ (a & c) ^ (b & c);\n  const t1 = (h + (S1 >>> 0) + (ch >>> 0) + k + w) >>> 0, t2 = ((S0 >>> 0) + (maj >>> 0)) >>> 0;\n  return [(t1 + t2) >>> 0, a, b, c, (d + t1) >>> 0, e, f, g];\n}\n',
    wrong: ['function sha256Round(r, k, w) {\n  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;\n  const [a, b, c, d, e, f, g, h] = r;\n  const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);\n  const ch = (e & f) ^ (~e & g), maj = (a & b) ^ (a & c) ^ (b & c);\n  const t1 = h + S1 + ch + k + w, t2 = S0 + maj;\n  return [t1 + t2, a, b, c, d + t1, e, f, g];\n}\n', 'function sha256Round(r, k, w) {\n  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;\n  const [a, b, c, d, e, f, g, h] = r;\n  const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);\n  const ch = (e & f) ^ (~e & g), maj = (a & b) ^ (a & c) ^ (b & c);\n  const t1 = (h + (S1 >>> 0) + (ch >>> 0) + k + w) >>> 0, t2 = ((S0 >>> 0) + (maj >>> 0)) >>> 0;\n  return [(t1 + t2) >>> 0, a, b, c, (d + t2) >>> 0, e, f, g];\n}\n'],
  });
  ex({
    id: 'hs-x-feedforward', chapter: 'hs-md', title: 'Why add the input back?', level: 2, kind: 'choice',
    text: ['After its 64 rounds, SHA-256 adds the incoming chaining value to the registers. What would go wrong without this feed-forward?'],
    options: ['Nothing; it only adds diffusion', 'Each round can be undone given its K and W, so from an output and a chosen block anyone could compute the chaining value that leads to it, and preimages of the compression function would be easy', 'The digest would be shorter', 'The padding would no longer encode the length'],
    answer: 1,
    hints: ['Given the registers after a round and the K and W used, can you recover the registers before it?', 'Yes: b, c, d, f, g, h give back the old a, b, c, e, f, g, and then T1 and the old h, d follow. The rounds are a permutation of the registers for a fixed block.', 'Without the feed-forward the compression function is an invertible block cipher keyed by the block: run it backwards from any target to get a matching chaining value. Adding the input back makes that useless (the Davies–Meyer construction).'],
    solution: 1, wrong: [0, 2],
  });
  ex({
    id: 'hs-x-md5-endian', chapter: 'hs-md', title: 'MD5’s byte order', level: 1, kind: 'choice',
    text: ['How do MD5 and SHA-256 differ in how they read a block and write the length?'],
    options: ['They do not differ', 'MD5 reads words little-endian and writes the length little-endian; SHA-256 uses big-endian for both', 'MD5 writes the length in bytes, SHA-256 in bits', 'MD5 has no length in its padding'],
    answer: 1,
    hints: ['Both pad with 80, zeros and an 8-byte bit length.', 'The difference is the byte order.', 'MD5 is little-endian throughout, SHA-1 and SHA-2 big-endian. The padding rule and the length in bits are the same.'],
    solution: 1, wrong: [0, 2, 3],
  });
  ex({
    id: 'hs-x-history', chapter: 'hs-md', title: 'Which came when?', level: 1, kind: 'choice',
    text: ['Which of these events showed a chosen-prefix collision used to forge a certificate authority that browsers trusted?'],
    options: ['The first public SHA-1 collision, two PDF files (2017)', 'The rogue CA certificate built on MD5 (2008)', 'The publication of SHA-3 in FIPS 202 (2015)', 'The first full MD5 collision (2004)'],
    answer: 1,
    hints: ['A plain collision makes two random-looking messages; a forged CA needs control of both prefixes.', 'It was MD5, four years after its first full collision.', '2008: a chosen-prefix MD5 collision gave a rogue CA certificate. The 2017 SHA-1 collision was an identical-prefix one; SHA-1 chosen-prefix collisions came in 2020.'],
    solution: 1, wrong: [0, 3],
  });

  // =========================================================================================================
  // Chapter 3: SHA-3 and the sponge
  // =========================================================================================================
  ex({
    id: 'hs-x-rate', chapter: 'hs-sha3', title: 'The rate of SHA3-512', level: 1, kind: 'number',
    text: ['SHA3-512 uses a capacity of twice its digest size. How many bytes of message does it absorb per permutation (its rate)?'],
    answer: 72,
    hints: ['The state is 1600 bits = 200 bytes.', 'The capacity is 2 · 512 = 1024 bits = 128 bytes.', 'Rate = 200 − 128 = 72 bytes, about half of SHA3-256’s 136: SHA3-512 is slower per byte.'],
    solution: '72', wrong: ['136', '64', '128'],
    whyNot: 'Rate = 200 bytes minus the capacity, and the capacity is 2 × 512 bits.',
  });
  ex({
    id: 'hs-x-capacity', chapter: 'hs-sha3', title: 'Capacity and security', level: 2, kind: 'number',
    text: ['SHA3-384 has a capacity of 2 · 384 bits. Generic attacks on a sponge cost about 2^(c/2). What is the capacity in bits, and so what is c/2? Give c/2.'],
    answer: 384,
    hints: ['c = 2 · 384 = 768 bits.', 'c/2 = 384: generic attacks on the inner state cost 2³⁸⁴.', '384. Collisions on a 384-bit digest still cost 2¹⁹² by the birthday bound; the capacity is chosen so that the sponge is never the weak point.'],
    solution: '384', wrong: ['768', '192', '832'],
    whyNot: 'Take the capacity, 2 × 384 bits, and halve it.',
  });
  ex({
    id: 'hs-x-sha3-pad', chapter: 'hs-sha3', title: 'Padding with one byte of room', level: 2, kind: 'hex',
    text: ['A message of exactly 135 bytes is hashed with SHA3-256 (rate 136 bytes). What is byte 135, the last byte of the first block, after padding?'],
    answer: '86',
    hints: ['SHA-3 padding puts 06 right after the message and 80 at the last byte of the block.', 'Here those are the same byte.', 'They are ORed together: 06 | 80 = 86, and the padded message is exactly one block.'],
    solution: '86', wrong: ['06', '80', '8006'],
    whyNot: 'When only one byte is left, the first and last padding bytes share it.',
  });
  ex({
    id: 'hs-x-shake-prefix', chapter: 'hs-sha3', title: 'Short and long SHAKE', level: 1, kind: 'choice',
    text: ['You ask SHAKE256 for 32 bytes of a message, and then for 64 bytes of the same message. How are the two outputs related?'],
    options: ['They are unrelated', 'The 32 bytes are the first 32 of the 64', 'The 64 bytes are the 32 twice', 'The second is the hash of the first'],
    answer: 1,
    hints: ['The output length is not part of the input to the sponge.', 'Squeezing just reads further along the same stream.', 'The short output is a prefix of the long one. If two lengths must give unrelated outputs, put the length into the message.'],
    solution: 1, wrong: [0, 2],
  });
  // θ on the state after absorbing our own message: the bits of two slices, their column parities, and one D
  const KM = 'a sponge drinks the rate';
  const KP = H.SHA3.pad(enc(KM), 136, 0x06);
  const KB = new Uint8Array(200); KB.set(KP.slice(0, 136));
  const KA = S.Keccak.fromBytes(KB);
  const bitAt = (x, y, z) => Number((KA[x + 5 * y] >> BigInt(z)) & 1n);
  const par = (x, z) => [0, 1, 2, 3, 4].reduce((p, y) => p ^ bitAt(x, y, ((z % 64) + 64) % 64), 0);
  let Z = 1;
  { let best = -1; for (let z = 1; z < 64; z++) { let n = 0; for (let x = 0; x < 5; x++) n += par(x, z) + par(x, z - 1); const ones = [0, 1, 2, 3, 4].map((x) => par(x, z)).filter(Boolean).length; if (ones >= 2 && ones <= 3 && n > best) { best = n; Z = z; } } }
  const sliceTable = (z) => ({ table: [['', 'x = 0', 'x = 1', 'x = 2', 'x = 3', 'x = 4']].concat([0, 1, 2, 3, 4].map((y) => ['y = ' + y].concat([0, 1, 2, 3, 4].map((x) => String(bitAt(x, y, z)))))), caption: 'Slice z = ' + z + ': bit z of each lane (x, y).' });
  const CT = Object.fromEntries([0, 1, 2, 3, 4].map((x) => ['x = ' + x + '|C[x][' + Z + ']', String(par(x, Z))]));
  ex({
    id: 'hs-x-theta-parity', chapter: 'hs-sha3', title: 'Column parities for θ', level: 3, kind: 'table',
    text: [`After “${KM}” is padded and absorbed into SHA3-256’s state, slice z = ${Z} holds these bits. Compute the five column parities C[x][${Z}].`, sliceTable(Z), { math: 'C[x][z] = A[x,0][z] ⊕ A[x,1][z] ⊕ A[x,2][z] ⊕ A[x,3][z] ⊕ A[x,4][z]' }],
    rows: [0, 1, 2, 3, 4].map((x) => 'x = ' + x), cols: ['C[x][' + Z + ']'], cells: CT, cellKind: 'bit',
    hints: ['A column is the five bits in one column of the slice table (one x, every y).', 'The parity is 1 when the column has an odd number of 1s.', 'C[0…4][' + Z + '] = ' + [0, 1, 2, 3, 4].map((x) => par(x, Z)).join(' ') + '.'],
    solution: CT, wrong: [Object.assign({}, CT, { ['x = 2|C[x][' + Z + ']']: String(1 - par(2, Z)) })],
  });
  const D2 = par(1, Z) ^ par(3, Z - 1);
  ex({
    id: 'hs-x-theta-d', chapter: 'hs-sha3', title: 'One bit of D', level: 2, kind: 'number',
    text: [`The same state. θ XORs D[2][${Z}] = C[1][${Z}] ⊕ C[3][${Z - 1}] into all five bits of column (2, ${Z}). Using slice ${Z} and slice ${Z - 1} below, compute D[2][${Z}] (0 or 1).`, sliceTable(Z), sliceTable(Z - 1)],
    answer: D2,
    hints: [`C[1][${Z}] is the parity of column x = 1 in slice ${Z}; C[3][${Z - 1}] the parity of column x = 3 in slice ${Z - 1}.`, `C[1][${Z}] = ${par(1, Z)} and C[3][${Z - 1}] = ${par(3, Z - 1)}.`, `D[2][${Z}] = ${par(1, Z)} ⊕ ${par(3, Z - 1)} = ${D2}. ${D2 ? 'All five bits of column (2, ' + Z + ') flip.' : 'Column (2, ' + Z + ') is left as it is.'}`],
    solution: String(D2), wrong: [String(1 - D2), '2', String(par(1, Z) ^ par(3, Z))].filter((v, i, a) => v !== String(D2) && a.indexOf(v) === i),
    whyNot: 'D[x][z] uses the column to the left at the same z and the column to the right one slice back, z − 1.',
  });
  const ROW = [1, 1, 0, 1, 0];
  const CHI = ROW.map((a, x) => a ^ ((1 - ROW[(x + 1) % 5]) & ROW[(x + 2) % 5]));
  ex({
    id: 'hs-x-chi', chapter: 'hs-sha3', title: 'χ on one row', level: 2, kind: 'string',
    text: ['A row of five bits a₀ … a₄ is 1 1 0 1 0. Apply χ: aₓ ← aₓ ⊕ (¬aₓ₊₁ ∧ aₓ₊₂), indices mod 5, all computed from the old row. Write the five new bits, a₀ first.'],
    answer: CHI.join(' '),
    accept: (t) => String(t).replace(/[^01]/g, '') === CHI.join(''),
    hints: ['Use the old row for every bit; do not update in place.', 'a₃: ¬a₄ ∧ a₀ = 1 ∧ 1 = 1, so a₃ flips to 0. a₁: ¬a₂ ∧ a₃ = 1, so a₁ flips to 0.', 'The new row is ' + CHI.join(' ') + '.'],
    solution: CHI.join(' '), wrong: ['1 1 0 1 0', '0 0 1 0 1', '1 0 0 1 0'],
    whyNot: 'Compute each new bit from the old row: a bit flips when its right neighbour is 0 and the next one is 1.',
  });

  // =========================================================================================================
  // Chapter 4: attacks on hashes
  // =========================================================================================================
  const BD = H.birthday({ hash: 'sha256', bits: 20, seed: 12 });
  const dec = (b) => new TextDecoder().decode(b);
  const t20 = (m) => H.truncate(H.digest('sha256', m), 20);
  ex({
    id: 'hs-x-collide', chapter: 'hs-attacks', title: 'A birthday collision on 20 bits', level: 3, kind: 'string',
    text: ['A ticket system prints only the first 20 bits of SHA-256 (5 hex digits) of each ticket’s text. Find two different texts with the same 20-bit value. Write them on one line, separated by a vertical bar |, like first text | second text.', { tip: 'About √(π·2²⁰/2) ≈ 1,300 texts are needed on average. Hash “ticket 1”, “ticket 2”, … in the sandbox and keep a table of what you have seen.' }],
    placeholder: 'first text | second text',
    accept: (raw) => {
      const ls = String(raw).split(/\r?\n|\|/).map((l) => l.trim()).filter(Boolean);
      if (ls.length !== 2) return 'Write exactly two texts, separated by |.';
      if (ls[0] === ls[1]) return 'The two texts must be different.';
      const a = t20(ls[0]), b = t20(ls[1]);
      return a === b ? true : 'Their 20-bit values are ' + a.toString(16).padStart(5, '0') + ' and ' + b.toString(16).padStart(5, '0') + ': not the same.';
    },
    hints: ['A birthday search: hash many texts, store each 20-bit value, stop when one repeats.', 'In the sandbox: a Map from value to text; for i = 1, 2, …, compute the first 20 bits of SHA-256(“ticket ” + i), look it up, and store it.', `One pair the engine found: “${dec(BD.a)}” and “${dec(BD.b)}”, both ${t20(dec(BD.a)).toString(16).padStart(5, '0')}, after ${BD.tries} texts.`],
    solution: dec(BD.a) + ' | ' + dec(BD.b), wrong: [dec(BD.a) + ' | ' + dec(BD.a), 'ticket 1 | ticket 2', dec(BD.a)],
  });
  ex({
    id: 'hs-x-rho', chapter: 'hs-attacks', title: 'What rho saves', level: 2, kind: 'choice',
    text: ['Compared with a birthday table, what does Pollard’s rho with Floyd’s cycle finding change when looking for a collision on an n-bit hash?'],
    options: ['It needs far fewer hash evaluations', 'It needs about the same number of evaluations (a small constant more) but only a constant amount of memory', 'It finds preimages too', 'It only works on Merkle–Damgård hashes'],
    answer: 1,
    hints: ['Both find a collision after about 2ⁿᐟ² steps.', 'Rho keeps only the tortoise and the hare.', 'Same order of work, about 2ⁿᐟ² (rho takes roughly three times as many calls), and memory that does not grow. That is what makes 2⁶⁴-scale searches possible: a table of 2⁶⁴ digests is not.'],
    solution: 1, wrong: [0, 2],
  });
  ex({
    id: 'hs-x-joux', chapter: 'hs-attacks', title: 'A 1024-way collision', level: 2, kind: 'number',
    text: ['An iterated hash has a 64-bit chaining value. Using Joux’s method, about how many compression calls does it take to build 1,024 messages that all share one digest? Use 2³² calls per collision.'],
    answer: 10 * 2 ** 32, tolerance: 2 ** 30,
    hints: ['1,024 = 2¹⁰ messages need 10 collisions in a row.', 'Each costs about 2⁶⁴ᐟ² = 2³² compression calls.', '10 · 2³² = 42,949,672,960 calls, about 2³⁵·³. An ideal 64-bit hash would need far more for a 1,024-way collision.'],
    solution: String(10 * 2 ** 32), wrong: [String(1024 * 2 ** 32), String(2 ** 32), String(2 ** 64)],
    whyNot: 'Count the collisions needed (log₂ of the number of messages) and multiply by 2³².',
  });
  ex({
    id: 'hs-x-resist', chapter: 'hs-attacks', title: 'Who resists length extension?', level: 2, kind: 'choice',
    text: ['Which of these tags resist length extension? Choose all that apply.'],
    options: ['SHA-256(key ‖ m)', 'HMAC-SHA-256(key, m)', 'SHA3-256(key ‖ m)', 'SHA-1(key ‖ m)', 'SHA-512/256(key ‖ m), the truncated SHA-512'],
    answer: [1, 2, 4],
    hints: ['Length extension needs the digest to be the hash’s entire state.', 'SHA-3 never outputs its capacity; SHA-512/256 outputs only half its state; HMAC hashes the inner digest again under a second key.', 'HMAC, SHA3-256 and SHA-512/256 resist. SHA-256 and SHA-1 of key ‖ m are both plain Merkle–Damgård with the whole state as output.'],
    solution: [1, 2, 4], wrong: [[1], [0, 1, 2, 4], [1, 2]],
  });
  const EXP = { 'SHA-256|state bytes': '32', 'SHA-256|digest bytes': '32', 'SHA-512/256|state bytes': '64', 'SHA-512/256|digest bytes': '32', 'SHA3-256|state bytes': '200', 'SHA3-256|digest bytes': '32' };
  ex({
    id: 'hs-x-hmac-why', chapter: 'hs-attacks', title: 'Why HMAC is immune', level: 2, kind: 'choice',
    text: ['HMAC-SHA-256 uses SHA-256, a Merkle–Damgård hash that is open to length extension. Why does HMAC’s tag not let anyone compute the tag of a longer message?'],
    options: ['HMAC uses a longer key', 'The tag is the outer hash of a fixed-size inner digest under a second key block; continuing from it gives the hash of (K′ ⊕ opad) ‖ inner ‖ glue ‖ x, which is not the HMAC of any message', 'HMAC encrypts the tag', 'HMAC pads differently from SHA-256'],
    answer: 1,
    hints: ['Length extension continues hashing from the state that a digest reveals. Which hash’s state does the HMAC tag reveal?', 'It is the state after the outer hash, whose input is the opad block and a 32-byte inner digest, never the message itself.', 'The outer hash always has the same short shape, (K′ ⊕ opad) ‖ inner. Extending it produces a hash of something that is not of that shape, so it is not a valid tag of any message, and the inner state stays hidden.'],
    solution: 1, wrong: [0, 2, 3],
  });
  ex({
    id: 'hs-x-exposed', chapter: 'hs-attacks', title: 'How much state does a digest show?', level: 1, kind: 'table',
    text: ['A digest reveals part or all of the hash’s internal state at the end. Fill in the size of the final internal state and of the digest, in bytes.'],
    rows: ['SHA-256', 'SHA-512/256', 'SHA3-256'], cols: ['state bytes', 'digest bytes'], cells: EXP, cellKind: 'text', corner: 'hash',
    hints: ['SHA-256 keeps eight 32-bit words; SHA-512/256 eight 64-bit words; SHA-3 a 1600-bit state.', 'SHA-256: 32 and 32. SHA-512/256: 64 and 32. SHA3-256: 200 and 32.', 'Only SHA-256 shows its whole state (32 of 32 bytes), which is what length extension needs. SHA-512/256 shows half; SHA3-256 shows 32 of 200 bytes and none of the capacity.'],
    solution: EXP, wrong: [Object.assign({}, EXP, { 'SHA3-256|state bytes': '32' }), Object.assign({}, EXP, { 'SHA-512/256|state bytes': '32' })],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
