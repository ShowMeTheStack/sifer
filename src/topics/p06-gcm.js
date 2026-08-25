// Part 6, GCM (NIST SP 800-38D): CTR encryption from the counter block J0 + 1 on, and a tag made by GHASH, a running
// sum multiplied by the hash key H = Eₖ(0) in GF(2¹²⁸) over the associated data, the ciphertext and a length block,
// finally masked with Eₖ(J0). Change one bit anywhere and the receiver's tag no longer matches.
(function (S) {
  'use strict';
  const U = S.P5, K6 = () => S.Kit.p06, Fl = () => S.Kit.flow;
  const sub = (n) => K6().sub(n);
  const bytesOf = (v) => { const t = String(v), h = t.replace(/\s+/g, ''); return /^([0-9a-fA-F]{2}){16,}$/.test(h) ? S.bytes.fromHex(h) : S.bytes.utf8(t); };
  const ivOf = (v) => { const t = String(v), h = t.replace(/\s+/g, ''); if (/^[0-9a-fA-F]{24}$/.test(h)) return S.bytes.fromHex(h); const b = S.bytes.utf8(t); return b.length === 12 ? b : null; };

  function gcm(inp) {
    const key = U.key(inp.key), iv = ivOf(inp.iv), msg = bytesOf(inp.msg), aad = S.bytes.utf8(String(inp.aad)), G = S.GCM, E = S.AES.cipher(key);
    const res = G.encrypt(key, iv, msg, aad), ctrs = res.trace.filter((t) => t.kind === 'gcm-ctr'), gh = res.trace.filter((t) => t.kind === 'ghash');
    const n = ctrs.length, CX = n === 1 ? [300] : [170, 430], F = new S.Frames(), box = (...a) => K6().box(...a);
    const Pb = K6().blocks(msg), Cb = K6().blocks(res.ct);
    const names = gh.map((g) => (g.what === 'an AAD block' ? 'A' + sub(g.i + 1) : g.what === 'a ciphertext block' ? 'C' + sub(g.i + 1 - Math.ceil(aad.length / 16)) : 'lengths'));
    const yN = 70, yE = 160, yX = 232, yC = 320, yG = 512, yXb = 440, JX = 720;
    const GX = (k) => 80 + 150 * k;
    // o: {ctr: block being made, ghash: GHASH block done up to, tag, j0, h, bad: index of a tampered GHASH block}
    const build = (o) => {
      const N = Fl().net('gcm'), later = [];
      box(N, 'J0', JX, yN, 'J0 = IV ‖ 00000001', res.J0, 'key' + (o.j0 ? ' act' : ''));
      N.box('EJ', JX, yE, 80, 40, 'Eₖ', 'cipher' + (o.tag ? ' act' : ''));
      N.wire('jj', [N.port('J0', 's'), N.port('EJ', 'n')], { head: true, cls: o.tag ? 'act' : '' });
      ctrs.forEach((c, i) => {
        const x = CX[i], cur = o.ctr === i, done = o.ctr > i || o.ctr === undefined;
        box(N, 'N' + i, x, yN, 'J0 + ' + (i + 1), c.ctr, cur ? 'act' : '');
        N.box('E' + i, x, yE, 80, 40, 'Eₖ', 'cipher' + (cur ? ' act' : ''));
        N.op('x' + i, x, yX, 'xor', cur ? 'act' : '');
        box(N, 'P' + i, x - 95, yX, 'P' + sub(i + 1), Pb[i], cur ? 'act' : '', { quad: true });
        box(N, 'C' + i, x, yC, 'C' + sub(i + 1) + (o.bad !== undefined && names[o.bad] === 'C' + sub(i + 1) ? ', as sent' : ''), done || cur ? Cb[i] : null, cur ? 'hot' : done ? '' : 'soft');
        N.wire('ne' + i, [N.port('N' + i, 's'), N.port('E' + i, 'n')], { head: true, cls: cur ? 'act' : '' });
        N.wire('ex' + i, [N.port('E' + i, 's'), N.port('x' + i, 'n')], { head: true, cls: cur ? 'act' : '' });
        N.wire('px' + i, [N.port('P' + i, 'e'), N.port('x' + i, 'w')], { head: true, cls: cur ? 'act' : '' });
        N.wire('xc' + i, [N.port('x' + i, 's'), N.port('C' + i, 'n')], { head: true, cls: cur ? 'act' : '' });
      });
      // GHASH: Y ← (Y ⊕ X)·H for every block, then the tag
      N.label('gt', 30, 392, 'GHASH over GF(2¹²⁸), with H = Eₖ(0¹²⁸)', 'title', 'start', 13);
      N.box('y0', 30, yG, 30, 30, '0', 'val');
      gh.forEach((g, k) => {
        const x = GX(k), done = o.ghash !== undefined && k <= o.ghash, cur = o.ghash === k, bad = o.bad === k;
        N.box('X' + k, x, yXb, 120, 44, [names[k], K6().short(g.x)], 'val2' + (bad ? ' hot' : cur ? ' act' : ''));
        N.op('g' + k, x, yG, 'xor', cur ? 'act' : '');
        N.box('H' + k, x + 55, yG, 46, 30, '·H', 'val key' + (cur ? ' act' : ''));
        N.wire('xg' + k, [N.port('X' + k, 's'), N.port('g' + k, 'n')], { head: true, cls: cur ? 'act' : '' });
        N.wire('gh' + k, [N.port('g' + k, 'e'), N.port('H' + k, 'w')], { head: true, cls: cur ? 'act' : '' });
        later.push(() => N.wire('hn' + k, [N.port('H' + k, 'e'), k < gh.length - 1 ? N.port('g' + (k + 1), 'w') : N.port('T', 'w')], { head: true, cls: (cur || (o.tag && k === gh.length - 1)) ? 'act' : done ? '' : '' }));
      });
      N.wire('y0w', [N.port('y0', 'e'), N.port('g0', 'w')], { head: true });
      N.op('T', JX, yG, 'xor', o.tag ? 'hot' : '');
      N.wire('ej', [N.port('EJ', 's'), N.port('T', 'n')], { head: true, cls: o.tag ? 'act' : '' });
      box(N, 'tag', JX, 595, o.recv ? 'tag computed' : 'tag', o.tag ? (o.recv || res.tag) : null, o.tag ? (o.recv ? 'hot' : 'hot') : 'soft');
      N.wire('tt', [N.port('T', 's'), N.port('tag', 'n')], { head: true, cls: o.tag ? 'hot' : '' });
      later.forEach((f) => f());
      if (o.y) N.label('yv', 30, 600, o.y, 'math', 'start', 14);
      return N.items;
    };
    F.add({ items: build({}), say: `GCM encrypts and authenticates in one pass. The ${msg.length}-byte message will be encrypted; the ${aad.length}-byte associated data${aad.length ? `, ${U.asText(aad) || U.hex(aad)},` : ''} is only authenticated. The IV is 96 bits: ${U.hex(iv)}.`, facts: { len: msg.length, alen: aad.length, iv }, meta: { stage: 'start' } });
    F.add({ items: build({ h: true, y: 'H = ' + U.hex(res.H) }), hl: { d: [0] }, say: `The hash key is H = Eₖ(0¹²⁸) = ${U.hex(res.H)}, the encryption of an all-zero block. Every GHASH step multiplies by it.`, facts: { H: res.H }, meta: { stage: 'h' } });
    F.add({ items: build({ j0: true }), hl: { d: [1] }, say: `A 96-bit IV becomes the first counter block by appending 00000001: J0 = ${U.hex(res.J0)}. J0 itself is kept for the tag; the data uses J0 + 1, J0 + 2, and so on.`, facts: { J0: res.J0, one: '00000001' }, meta: { stage: 'j0' } });
    ctrs.forEach((c, i) => F.add({ items: build({ ctr: i }), narrowView: K6().follow(CX[i]), hl: { d: [2] }, say: `Block ${i + 1}: Eₖ(${U.hex(c.ctr)}) = ${U.hex(c.ks)}, XORed with P${sub(i + 1)}: C${sub(i + 1)} = ${U.hex(Cb[i])}. This is plain CTR.`, facts: { i: i + 1, ctr: c.ctr, ks: c.ks, c: Cb[i] }, meta: { stage: 'ctr', i } }));
    gh.forEach((g, k) => F.add({ items: build({ ghash: k, y: `Y${sub(k + 1)} = ${U.hex(g.y)}` }), narrowView: K6().follow(GX(k) + 60, { y: 300, h: 340 }), hl: { d: [3] }, say: `GHASH block ${k + 1}, ${g.what === 'the length block' ? `the lengths in bits (${aad.length * 8} and ${msg.length * 8})` : names[k]}, ${U.hex(g.x)}: Y = (Y ⊕ X)·H = (${U.hex(g.before)} ⊕ ${U.hex(g.x)})·H = ${U.hex(g.y)}.`, facts: { k: k + 1, x: g.x, before: g.before, y: g.y, a: aad.length * 8, m: msg.length * 8 }, meta: { stage: 'ghash', k } }));
    F.add({ items: build({ ghash: gh.length, tag: true, y: 'GHASH = ' + U.hex(res.ghash) }), hl: { d: [4] }, say: `The tag is GHASH ⊕ Eₖ(J0) = ${U.hex(res.ghash)} ⊕ ${U.hex(res.EJ0)} = ${U.hex(res.tag)}. GHASH alone is linear in the data; the mask Eₖ(J0), new for every IV, hides it.`, facts: { ghash: res.ghash, EJ0: res.EJ0, tag: res.tag }, meta: { stage: 'tag' } });
    if (inp.tamper !== 'none') {
      const ct2 = Uint8Array.from(res.ct), aad2 = Uint8Array.from(aad);
      let what, bad;
      if (inp.tamper === 'ct' || !aad.length) { ct2[0] ^= 1; what = 'the first bit of C₁'; bad = Math.ceil(aad.length / 16); }
      else { aad2[aad2.length - 1] ^= 1; what = 'the last bit of the associated data'; bad = Math.ceil(aad.length / 16) - 1; }
      const H = res.H, g2 = G.ghash(H, aad2, ct2, { trace: false }).out, t2 = g2.map((v, i) => v ^ res.EJ0[i]), dec = G.decrypt(key, iv, ct2, res.tag, aad2, { trace: false });
      F.add({ items: build({ ghash: gh.length, tag: true, recv: t2, bad, y: 'received tag ' + U.hex(res.tag) }), hl: { d: [5] }, say: `On the way, an attacker flips ${what}. The receiver recomputes the tag: ${U.hex(t2)}, not the ${U.hex(res.tag)} that came with the message, so it ${dec.ok ? 'accepts' : 'rejects the message and releases no plaintext at all'}.`, facts: { t2, tag: res.tag }, meta: { stage: 'tamper', ok: dec.ok } });
    }
    U.fix(F.list);
    return { frames: F.list, def: U.def('GCM', ['H = Eₖ(0¹²⁸)', 'J0 = IV ‖ 0³¹1   (96-bit IV)', 'Cᵢ = Pᵢ ⊕ Eₖ(J0 + i)', 'Y₀ = 0,  Yⱼ = (Yⱼ₋₁ ⊕ Xⱼ)·H over A, C, len(A) ‖ len(C)', 'T = Yₘ ⊕ Eₖ(J0)', 'decrypt: recompute T, compare, and only then release P']) };
  }
  S.topic({
    id: 'modes-gcm', family: 'p06-gcm', order: 10, title: 'GCM: CTR plus GHASH',
    blurb: 'Galois/Counter Mode encrypts with CTR and authenticates with GHASH, a polynomial in the hash key H evaluated over GF(2¹²⁸). The tag catches any change to the ciphertext or the associated data.',
    inputs: [
      { id: 'msg', kind: 'text', label: 'Message (1 to 32 characters, or hex)', def: 'Pay the ferryman two coins', check: (v) => { const n = bytesOf(v).length; return n < 1 ? 'Message: at least 1 byte' : n > 32 ? 'Message: at most 32 bytes, so it fits the picture' : null; } },
      { id: 'aad', kind: 'text', label: 'Associated data (0 to 16 characters)', def: 'dock 4', check: (v) => (S.bytes.utf8(String(v)).length > 16 ? 'Associated data: at most 16 bytes' : null) },
      K6().keyInput(),
      { id: 'iv', kind: 'text', label: 'IV (12 characters or 24 hex digits)', def: 'tern-and-gul', check: (v) => (ivOf(v) ? null : 'IV: 12 characters or 24 hex digits (96 bits)') },
      { id: 'tamper', kind: 'choice', label: 'In transit', def: 'none', options: [{ value: 'none', label: 'nothing changes' }, { value: 'ct', label: 'flip a ciphertext bit' }, { value: 'aad', label: 'flip a bit of the associated data' }] },
    ],
    presets: [
      { label: 'Two blocks with associated data', values: { msg: 'Pay the ferryman two coins', aad: 'dock 4', tamper: 'none' } },
      { label: 'A flipped ciphertext bit is caught', values: { msg: 'Pay the ferryman two coins', aad: 'dock 4', tamper: 'ct' } },
      { label: 'A flipped bit of associated data is caught', values: { msg: 'Pay the ferryman two coins', aad: 'dock 4', tamper: 'aad' } },
      { label: 'All-zero key, IV and block', values: { msg: '00000000000000000000000000000000', aad: '', key: '00000000000000000000000000000000', iv: '000000000000000000000000', tamper: 'none' } },
      { label: 'AES-256, no associated data', values: { msg: 'Shutters open at six', aad: '', key: 'thirty-two bytes of copper wire!', tamper: 'none' } },
    ],
    run: gcm,
    predict: [{ at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta && fr[i + 1].meta.stage === 'tamper', pick: 'option', options: ['accepted', 'rejected'], ask: 'One bit changed in transit. Will the receiver accept the message?', answer: 'rejected', explain: 'The change alters GHASH, so the recomputed tag differs, and GCM releases nothing.' }],
    quiz: [
      { q: 'What is the hash key H in GCM?', options: ['The AES key', 'Eₖ(0¹²⁸)', 'The IV', 'Eₖ(J0)'], answer: 1, why: 'It is derived from the key once, and every GHASH step multiplies by it.' },
      { q: 'Why is the last GHASH block the lengths of A and C?', options: ['For padding', 'So that data cannot be moved between A and C or extended unnoticed', 'To fill the block', 'It holds the IV'], answer: 1, why: 'Both lengths are bound into the tag.' },
      { q: 'Which counter block encrypts the first plaintext block?', options: ['J0', 'J0 + 1', 'the IV', '0'], answer: 1, why: 'Eₖ(J0) is saved to mask the tag.' },
      { q: 'Why must a GCM IV never repeat under one key?', options: ['It only slows things down', 'Two tags with the same Eₖ(J0) reveal a polynomial in H; H falls out and tags can be forged', 'It changes the block size', 'It does not matter'], answer: 1, why: 'Besides the CTR keystream repeating, the authentication breaks completely.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
