// Part 10, key exchange: elliptic-curve Diffie–Hellman on a toy curve (with the cloud) and on P-256 or secp256k1,
// the received point validated before use; and X25519, with its clamped scalar and the x-only Montgomery ladder run
// bit by bit, between two parties who end with the same 32 bytes.
(function (S) {
  'use strict';
  const U = S.P10, E = () => S.ECC;
  const f = U.f, P$ = (P) => U.fp(P);
  const CURVES = [
    { value: 'gf101', label: 'toy: GF(101), 103 points' },
    { value: 'gf1009', label: 'toy: GF(1009), 1019 points' },
    { value: 'P-256', label: 'P-256' },
    { value: 'secp256k1', label: 'secp256k1' },
  ];
  const curveOf = (id) => (/^gf/.test(id) ? E().toy(id) : E().named(id));
  const parseK = (v) => { const t = String(v).trim().toLowerCase(); return /^(0x[0-9a-f]+|\d+)$/.test(t) ? BigInt(t) : null; };
  const secret = (label) => '0x' + U.hex(S.SHA256.hash(U.utf8(label)));
  const dIn = (id, label, def) => ({ id, kind: 'text', label, def, check: (v, inp) => { const d = parseK(v); if (d === null) return label + ': a whole number, in decimal or as 0x and hex digits'; const C = curveOf(inp.curve); if (d < 1n || d >= C.n) return label + ': from 1 to n − 1 = ' + f(C.n - 1n); return null; } });

  // ---------------------------------------------------------------------------------------------------------------
  // ECDH
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-ecdh', family: 'p10-ecdh', order: 10, title: 'Elliptic-curve Diffie–Hellman',
    blurb: 'Alice and Bob agree on a curve and a base point G. Each picks a secret number d and publishes d·G. Each multiplies the other\'s point by their own secret, and both reach d_A·d_B·G. An eavesdropper sees G, d_A·G and d_B·G, and would need an elliptic-curve discrete logarithm to go further.',
    inputs: [{ id: 'curve', kind: 'choice', label: 'Curve', def: 'gf101', options: CURVES }, dIn('dA', 'Alice\'s secret d_A', '23'), dIn('dB', 'Bob\'s secret d_B', '58')],
    presets: [
      { label: 'Toy: d_A = 23, d_B = 58', values: { curve: 'gf101', dA: '23', dB: '58' } },
      { label: 'Toy on GF(1009)', values: { curve: 'gf1009', dA: '777', dB: '205' } },
      { label: 'P-256', values: { curve: 'P-256', dA: secret('Alice, the P-256 key'), dB: secret('Bob, the P-256 key') } },
      { label: 'secp256k1', values: { curve: 'secp256k1', dA: secret('Alice on secp256k1'), dB: secret('Bob on secp256k1') } },
    ],
    run(inp) {
      const C = curveOf(inp.curve), G = C.G, dA = parseK(inp.dA), dB = parseK(inp.dB), F = new S.Frames();
      const QA = C.mul(dA, G), QB = C.mul(dB, G), rA = E().ecdh(C, dA, QB), rB = E().ecdh(C, dB, QA), Sp = rA.S;
      const toy = C.toy, LW = toy ? 560 : 900, xA = toy ? 110 : 160, xB = LW - xA, xE = LW / 2;
      const ptxt = (P) => (toy ? P$(P) : U.hs(P.x.toString(16), 6));
      const head = U.head('ed:h', 30, 28, `ECDH on ${C.name}`);
      const people = [...U.party('ed:A', xA, 90, 'Alice', 'act'), ...U.party('ed:B', xB, 90, 'Bob', 'key')];
      const pub = U.t('ed:pub', xE, 74, `public: the curve, G = ${ptxt(G)}, n = ${f(C.n)}`, 'e10-note', 'middle', 13);
      const blk = (key, x, y, label, value, cls) => U.value(key, x, y, label, value, cls, toy ? 190 : 250);
      const cloud = (marks) => (toy ? (() => { const cl = U.cloud(C, { prefix: 'ed:c', x: 620, y: 150, s: 270, r: Number(C.p) > 200 ? 1.3 : 2.4, grid: false }); return [...cl.items, ...cl.marks(marks, [], 14)]; })() : []);
      const sec = (who) => (toy ? f(who === 'A' ? dA : dB) : U.hs((who === 'A' ? dA : dB).toString(16), 6));
      const add = (items, say, facts, meta) => F.add({ items: [head, pub, ...people, ...items], say, facts: Object.assign({ n: C.n, G, curve: [C.p, C.a, C.b] }, facts), meta });
      add(cloud([['G', G, 'G', 'P', 'ne']]), `Alice and Bob agree in public on ${C.name} and its base point G = ${P$(G)}, whose order is n = ${f(C.n)}. Nothing has been secret so far.`, {}, { stage: 'public' });
      const aBlk = [blk('ed:dA', xA, 200, 'secret d_A', sec('A'), 'key'), blk('ed:QA', xA, 290, 'Q_A = d_A·G', ptxt(QA), 'act')];
      add([...aBlk, ...cloud([['G', G, 'G', 'P', 'ne'], ['QA', QA, 'Q_A', 'R', 'sw']])], `Alice picks a secret d_A = ${f(dA)} and computes Q_A = d_A·G = ${P$(QA)} by double-and-add: ${S.ECC.bitLength(dA)} bits, so a few hundred group operations at most.`, { dA, QA, nb: S.ECC.bitLength(dA) }, { stage: 'alice' });
      const bBlk = [blk('ed:dB', xB, 200, 'secret d_B', sec('B'), 'key'), blk('ed:QB', xB, 290, 'Q_B = d_B·G', ptxt(QB), 'act')];
      add([...aBlk, ...bBlk, ...cloud([['G', G, 'G', 'P', 'ne'], ['QA', QA, 'Q_A', 'R', 'sw'], ['QB', QB, 'Q_B', 'Q', 'se']])], `Bob does the same with his own secret d_B = ${f(dB)}: Q_B = ${P$(QB)}.`, { dB, QB }, { stage: 'bob' });
      const msgs = [...U.arrow('ed:m1', xA + 100, xB - 100, 360, 'Q_A →', 'act'), ...U.arrow('ed:m2', xB - 100, xA + 100, 400, '← Q_B', 'key')];
      const eve = [...U.party('ed:E', xE, 470, 'Eve', ''), U.t('ed:et', xE, 530, 'sees G, Q_A and Q_B', 'e10-note', 'middle', 13)];
      add([...aBlk, ...bBlk, ...msgs, ...eve, ...cloud([['QA', QA, 'Q_A', 'R', 'sw'], ['QB', QB, 'Q_B', 'Q', 'se']])], 'They swap the public points over an open channel. Eve, listening, learns G, Q_A and Q_B, but neither secret.', {}, { stage: 'swap' });
      const v = C.validate(QB);
      const sA = blk('ed:SA', xA, 450, 'S = d_A·Q_B', ptxt(Sp), 'good'), sB = blk('ed:SB', xB, 450, 'S = d_B·Q_A', ptxt(rB.S), 'good');
      add([...aBlk, ...bBlk, ...msgs, sA, sB, ...cloud([['QA', QA, 'Q_A', 'R', 'sw'], ['QB', QB, 'Q_B', 'Q', 'se'], ['S', Sp, 'S', 'third', 'ne']])], `Alice first checks that Q_B is a valid point (${v.checks.map((c) => c.name).join(', ')}: ${v.ok ? 'all pass' : 'it fails'}), then computes d_A·Q_B; Bob computes d_B·Q_A. Both get S = ${P$(Sp)}, because d_A·(d_B·G) = d_B·(d_A·G) = (d_A·d_B)·G.`, { S: Sp, SB: rB.S }, { stage: 'shared', equal: C.eq(Sp, rB.S) });
      const hex = U.hex(rA.shared);
      add([...aBlk, ...bBlk, ...msgs, sA, sB, ...U.eqs('ed:e', toy ? 30 : 140, 530, [[`shared secret: the x of S as ${rA.shared.length} bytes`, 'strong'], [U.hs(hex, 16), 'mono good']], 15, 26)], `The shared secret is the x-coordinate of S as ${rA.shared.length} bytes, ${U.hs(hex, 8)}. It is fed to a key-derivation function rather than used as a key directly, since its bits are not uniform.`, { shared: hex, len: rA.shared.length }, { stage: 'secret' });
      const work = toy ? `Here n = ${f(C.n)}, so Eve can simply try every d: at most ${f(C.n)} additions.` : `At this size the best known attack takes about √n ≈ 2^${Math.floor(S.ECC.bitLength(C.n) / 2)} group operations.`;
      add([...aBlk, ...bBlk, ...msgs, ...eve, ...cloud([['G', G, 'G', 'P', 'ne'], ['QA', QA, 'Q_A', 'R', 'sw']])], `Eve's way in is to find d_A from Q_A = d_A·G: the elliptic-curve discrete logarithm problem. ${work} Deciding whether a given point is S is no easier, as far as anyone knows.`, { half: Math.floor(S.ECC.bitLength(C.n) / 2) }, { stage: 'eve' });
      U.fix(F.list);
      return { frames: F.list, def: U.def('ECDH', ['public: curve, G of prime order n', 'Alice: d_A secret, Q_A = d_A·G', 'Bob: d_B secret, Q_B = d_B·G', 'S = d_A·Q_B = d_B·Q_A = d_A·d_B·G', 'validate the peer\'s point first; key = KDF(S.x)']) };
    },
    predict: [{ at: (f) => f.meta.stage === 'swap', pick: 'option', ask: 'Bob multiplies Q_A by d_B. Does he get the same point as Alice?', options: ['yes, always', 'only if d_A = d_B', 'no'], answer: 'yes, always', explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'What does Eve see in ECDH?', options: ['G, d_A·G and d_B·G', 'd_A and d_B', 'S', 'nothing'], answer: 0, why: 'The public points travel in the open.' },
      { q: 'Why do both sides get the same S?', options: ['d_A·(d_B·G) = d_B·(d_A·G)', 'S = G', 'they share d', 'by luck'], answer: 0, why: 'Scalar multiplication commutes in this sense.' },
      { q: 'Why check the peer\'s point before using it?', options: ['a point off the curve or of small order can leak your secret', 'it saves time', 'it is optional', 'to compress it'], answer: 0, why: 'See the invalid-curve topic.' },
      { q: 'What is usually used as the key?', options: ['a KDF applied to the x-coordinate of S', 'S.y', 'd_A', 'Q_A'], answer: 0, why: 'The raw coordinate is not uniform.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // X25519
  // ---------------------------------------------------------------------------------------------------------------
  const hex32 = (label) => ({ id: label, kind: 'hex', label: label === 'a' ? 'Alice\'s 32 secret bytes' : 'Bob\'s 32 secret bytes', def: U.hex(S.SHA256.hash(U.utf8(label === 'a' ? 'Alice keeps this to herself' : 'Bob keeps this to himself'))), bytes: 32 });
  S.topic({
    id: 'ec-x25519', family: 'p10-ecdh', order: 20, title: 'X25519: clamping and the ladder',
    blurb: 'X25519 is Diffie–Hellman on Curve25519 using only the u-coordinate. The 32 secret bytes are clamped (three bits cleared, one cleared and one set), then a Montgomery ladder of exactly 255 steps computes k·u with no branch on the secret. Any 32 bytes are a valid public key, so there is nothing to validate but an all-zero result.',
    inputs: [hex32('a'), hex32('b')],
    presets: [
      { label: 'Our own two secrets', values: { a: U.hex(S.SHA256.hash(U.utf8('Alice keeps this to herself'))), b: U.hex(S.SHA256.hash(U.utf8('Bob keeps this to himself'))) } },
      { label: 'RFC 7748, section 6.1', values: { a: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', b: '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb' } },
      { label: 'All bits set', values: { a: 'ff'.repeat(32), b: '01'.repeat(32) } },
      { label: 'All zero', values: { a: '00'.repeat(32), b: '80'.repeat(32) } },
    ],
    counters: [{ id: 'steps', label: 'ladder steps' }],
    run(inp) {
      const X = E().X25519, a32 = U.unhex(inp.a), b32 = U.unhex(inp.b), F = new S.Frames(['steps']);
      const cA = X.clamp(a32), base = X.toLe(9n), rA = X.x25519(a32, base), pubA = rA.out, pubB = X.publicKey(b32);
      const shA = X.shared(a32, pubB), shB = X.shared(b32, pubA);
      const head = U.head('xd:h', 30, 28, 'X25519 on Curve25519: v² = u³ + 486662u² + u over GF(2²⁵⁵ − 19)');
      const bytesRow = (key, y, bytes, label, hl) => [U.t(key + ':l', 30, y - 8, label, 'e10-note', 'start', 13), ...U.cells({ prefix: key, x: 30, y, cw: 50, ch: 26, gap: 3, values: [...bytes].map((v) => v.toString(16).padStart(2, '0')), size: 13, cls: (i) => (hl && hl.includes(i) ? 'hot' : '') })];
      const two = (key, y, bytes, label, hl) => [...bytesRow(key + 'a', y, bytes.subarray(0, 16), label + ' (bytes 0–15)', hl), ...bytesRow(key + 'b', y + 52, bytes.subarray(16), 'bytes 16–31', hl && hl.map((i) => i - 16))];
      const bin = (v) => v.toString(2).padStart(8, '0');
      const flips = (before, after, key, y, label) => [U.t(key + ':l', 30, y + 18, label, 'eq', 'start', 15), ...U.bits({ prefix: key + 'x', x: 190, y, bits: bin(before), cw: 26, cls: () => '' }), U.t(key + ':ar', 438, y + 18, '→', 'eq strong', 'middle', 16), ...U.bits({ prefix: key + 'y', x: 462, y, bits: bin(after), cw: 26, cls: (i) => (bin(before)[i] !== bin(after)[i] ? 'flip' : '') })];
      const b0 = a32[0], b31 = a32[31], c0 = cA.bytes[0], c31 = cA.bytes[31];
      F.add({ items: [head, ...two('xd:s', 80, a32, 'Alice\'s secret, little-endian', [0, 31]), ...flips(b0, c0, 'xd:f0', 220, 'byte 0'), ...flips(b31, c31, 'xd:f1', 262, 'byte 31'), ...U.eqs('xd:e', 30, 340, [['byte 0: clear bits 0, 1 and 2', 'act'], ['byte 31: clear bit 7, set bit 6', 'act']], 16, 28)], say: `Alice's 32 secret bytes are read little-endian, byte 0 the lowest. Clamping changes three things: byte 0 goes from ${bin(b0)} to ${bin(c0)} (the low three bits cleared), and byte 31 from ${bin(b31)} to ${bin(c31)} (bit 255 cleared, bit 254 set).`, facts: { b0: bin(b0), c0: bin(c0), b31: bin(b31), c31: bin(c31) }, meta: { stage: 'clamp' } });
      const k = cA.k, kb = k.toString(2);
      F.add({ items: [head, ...U.eqs('xd:e', 30, 80, [[`k = ${f(k)}`, 'strong mono'], [`k is a multiple of 8: k mod 8 = ${k % 8n}`, 'good'], [`2²⁵⁴ ≤ k < 2²⁵⁵: k has exactly ${kb.length} bits`, 'good'], ['multiple of 8: the cofactor of Curve25519 is 8,'], ['so a point of small order is wiped out'], ['top bit fixed: every ladder runs 255 steps,'], ['so its length gives nothing away']], 16, 32)], say: `The clamped scalar is k = ${f(k)}. Being a multiple of 8 (the curve has 8·L points) means a hostile point's small-order part is multiplied away; having bit 254 set means every k has exactly ${kb.length} bits, so every ladder takes the same 255 steps.`, facts: { k, m8: k % 8n, nb: kb.length, steps: 255 }, meta: { stage: 'scalar' } });
      // the ladder: the first bits one at a time, then in stretches
      const bitsView = (t0) => { const items = []; for (let t = 254; t >= 0; t--) { const j = 254 - t; items.push({ key: 'xd:b' + j, kind: 'cell', x: 30 + (j % 85) * 10, y: 84 + Math.floor(j / 85) * 12, w: 9, h: 10, rx: 1, text: '', cls: 'bit e10-bit ' + (kb[j] === '1' ? 'one' : 'zero') + ' ' + (t > t0 ? 'done' : t === t0 ? 'cur' : '') }); } items.push(U.t('xd:bl', 30, 74, 'the 255 bits of k, bit 254 first', 'e10-note', 'start', 13)); return items; };
      const st = rA.steps, at = [254, 253, 252, 200, 128, 64, 3, 0];
      for (const t of at) {
        const s = st[254 - t], m = k >> BigInt(t), u = X.ladder(m, 9n, { trace: false }).u, u1 = X.ladder(m + 1n, 9n, { trace: false }).u;
        F.set('steps', 255 - t);
        F.add({ items: [head, ...bitsView(t), U.value('xd:r2', 230, 230, 'x₂/z₂ = u of m·B', U.hs(u.toString(16), 6), 'act', 300), U.value('xd:r3', 620, 230, 'x₃/z₃ = u of (m + 1)·B', U.hs(u1.toString(16), 6), 'key', 300), ...U.eqs('xd:e', 30, 320, [[`bit ${t} = ${s.bit}${s.swap ? ': swap the pair first' : ': no swap'}`, 'hot'], ['add the two (their difference is B, the base point u = 9)'], [`double the ${s.bit ? 'second' : 'first'}`], [`m = the top ${255 - t} bits of k = ${f(m)}`], ['shown as u = x/z (the ladder itself never divides)']], 16, 30)], say: t >= 252 ? `Bit ${t} is ${s.bit}. A conditional swap (done with masks, not a branch) ${s.swap ? 'swaps' : 'leaves'} the two pairs, then one differential addition and one x-only doubling update them, 5 multiplications and 4 squarings in all. The pair now holds m·9 and (m + 1)·9 for m = ${f(m)}.` : `On to bit ${t}: ${255 - t} steps done, each the same 5 multiplications and 4 squarings whatever the bit. m, the top ${255 - t} bits of k, is ${f(m)}, and the first u is ${U.hs(u.toString(16), 6)}.`, facts: { t, bit: s.bit, m, u: u.toString(16), u1: u1.toString(16), done: 255 - t }, meta: { stage: 'ladder', t } });
      }
      F.add({ items: [head, ...two('xd:p', 80, pubA, 'Alice\'s public key: u of k·9, little-endian'), ...U.eqs('xd:e', 30, 220, [[`cost: 255 × (5M + 4S) = ${rA.cost.M}M + ${rA.cost.S}S`, 'act'], ['then one inversion, z^(p−2)'], ['the base point is u = 9']], 16, 30)], say: `After the last bit, one inversion turns (x₂ : z₂) into u, written as 32 bytes little-endian: Alice's public key ${U.hs(U.hex(pubA), 8)}. The ladder cost ${rA.cost.M} multiplications and ${rA.cost.S} squarings, the same for every secret.`, facts: { pub: U.hex(pubA), M: rA.cost.M, Sq: rA.cost.S, n255: 255 }, meta: { stage: 'public' } });
      const eq = shA.shared && shB.shared && U.hex(shA.shared) === U.hex(shB.shared);
      F.add({ items: [head, ...U.party('xd:A', 110, 110, 'Alice', 'act'), ...U.party('xd:B', 810, 110, 'Bob', 'key'), ...U.arrow('xd:m1', 170, 750, 120, 'A = ' + U.hs(U.hex(pubA), 6), 'act'), ...U.arrow('xd:m2', 750, 170, 175, 'B = ' + U.hs(U.hex(pubB), 6), 'key'), ...two('xd:z', 280, shA.shared || new Uint8Array(32), 'X25519(a, B) on Alice\'s side'), ...two('xd:y', 420, shB.shared || new Uint8Array(32), 'X25519(b, A) on Bob\'s side'), U.t('xd:eq', 30, 560, eq ? 'the same 32 bytes' : 'all zero: abort', eq ? 'good' : 'bad', 'start', 16)], say: eq ? `Bob does the same with his secret and sends B = ${U.hs(U.hex(pubB), 8)}. Alice runs the ladder on Bob's u and Bob on Alice's: both get ${U.hs(U.hex(shA.shared), 8)}. A value of u that is not on the curve lies on its twist, which is also safe for Curve25519, so the only check is that the result is not all zero.` : 'The result is all zero: one side sent a point of small order. X25519 says to abort.', facts: { A: U.hex(pubA), B: U.hex(pubB), S: shA.shared ? U.hex(shA.shared) : '' }, meta: { stage: 'shared', eq } });
      // the fixed numbers of the standard, which the narration may quote
      for (const fr of F.list) fr.facts = Object.assign({ std: [32, 31, 255, 254, 8, 9, 5, 4, 3] }, fr.facts);
      U.fix(F.list);
      return { frames: F.list, def: U.def('X25519 (RFC 7748)', ['clamp: k[0] &= 248; k[31] &= 127; k[31] |= 64', 'ladder over bits 254 … 0 on (x₂ : z₂), (x₃ : z₃)', 'each bit: conditional swap, add, double (5M + 4S)', 'public key = X25519(k, 9)', 'shared = X25519(a, B) = X25519(b, A); reject all zero']) };
    },
    predict: [{ at: (f) => f.meta.stage === 'clamp', pick: 'option', ask: 'After clamping, how many bits will k have?', options: ['255', '256', '253', 'it depends on the secret'], answer: '255', explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'Why does clamping clear the three low bits?', options: ['k becomes a multiple of the cofactor 8, killing small-order parts', 'to make k smaller', 'to save a byte', 'for little-endian order'], answer: 0, why: 'A point of order dividing 8 times a multiple of 8 is O.' },
      { q: 'Why set bit 254?', options: ['every ladder runs the same number of steps', 'to make k odd', 'to make k prime', 'it is a checksum'], answer: 0, why: 'A constant length leaks nothing through timing.' },
      { q: 'What does X25519 transmit?', options: ['only the u-coordinate', 'u and v', 'the secret', 'a signature'], answer: 0, why: 'The ladder never needs v.' },
      { q: 'Which received values must X25519 reject?', options: ['none, but an all-zero result means abort', 'any u not on the curve', 'u above 2²⁵⁴', 'odd u'], answer: 0, why: 'The twist of Curve25519 is also secure, so off-curve u leak nothing useful.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
