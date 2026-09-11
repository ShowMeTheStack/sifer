// Part 13, MACs from a block cipher (AES-128): CBC-MAC, why its tag lets a longer message be tagged without the key
// when lengths vary (stated as an outcome, then the fixes, and CMAC holding), CMAC's two subkeys made by doubling in GF(2^128), and GMAC, a polynomial in
// the hash key H over the data blocks, masked with an encrypted counter block.
(function (S) {
  'use strict';
  const U = S.P12, Mc = () => S.MAC;
  const { t } = U;
  const blocksOf = (b) => { const o = []; for (let i = 0; i < b.length; i += 16) o.push(b.slice(i, i + 16)); return o; };
  const show16 = (b) => { const s = U.show(b); return s.length <= 20 ? s : U.hex(b).slice(0, 16) + '…'; };
  const keyInput = (def) => ({ id: 'key', kind: 'text', label: 'Key (16 characters, or 32 hex digits)', def, check: (v) => (/^[0-9a-fA-F]{32}$/.test(v) || U.utf8(v).length === 16 ? null : 'Key: 16 characters, or 32 hex digits') });
  const keyOf = (v) => (/^[0-9a-fA-F]{32}$/.test(v) ? U.fromHex(v) : U.utf8(v));

  /**
   * One CBC chain on the stage, one column per block: the block, ⊕ with the chaining value, E_K, and the value out.
   * o: {prefix, y, chain: [{m, x, c}], label, lit(i) -> class, first: text of the zero IV, tagCls, last: label}
   */
  function chainRow(o) {
    const N = S.Kit.flow.net(o.prefix), items = [], n = o.chain.length, cw = Math.min(210, 820 / n), x0 = 90 + cw / 2;
    items.push(t(o.prefix + ':lab', 20, o.y - 12, o.label, 'ptitle'));
    o.chain.forEach((s, i) => {
      const cx = x0 + i * cw, lit = o.lit ? o.lit(i) : '';
      N.box('m' + i, cx, o.y + 16, cw - 30, 28, show16(s.m), 'val small ' + (o.mcls ? o.mcls(i) : ''));
      N.op('x' + i, cx, o.y + 58, 'xor', lit === 'act' ? 'act' : '');
      N.box('e' + i, cx, o.y + 96, 56, 28, 'E_K', 'cipher' + (lit ? ' ' + lit : ''));
      N.wire('mx' + i, [N.port('m' + i, 's'), N.port('x' + i, 'n')], { head: true });
      N.wire('xe' + i, [N.port('x' + i, 's'), N.port('e' + i, 'n')], { head: true });
      if (i === 0) { N.wire('iv', [[cx - cw / 2 + 6, o.y + 58], N.port('x0', 'w')], { head: true }); items.push(t(o.prefix + ':iv', cx - cw / 2 - 2, o.y + 63, o.first || '0', 'mono ptick', 'end', 13)); }
      else N.wire('c' + i, [N.port('e' + (i - 1), 'e'), [cx - cw / 2, o.y + 96], [cx - cw / 2, o.y + 58], N.port('x' + i, 'w')], { head: true, cls: lit === 'good' ? 'good' : '' });
      items.push({ key: o.prefix + ':cv' + i, kind: 'cell', x: U.r2(cx - 60), y: o.y + 122, w: 120, h: 22, rx: 4, text: U.hex(s.c).slice(0, 12) + '…', size: 13.5, cls: 'hex ' + (i === n - 1 ? o.tagCls || 'key' : lit === 'good' ? 'good' : '') });
    });
    if (o.last) items.push(t(o.prefix + ':tl', x0 + (n - 1) * cw + 66, o.y + 138, o.last, o.tagCls === 'good' ? 'good' : o.tagCls === 'bad' ? 'bad' : 'key', 'start', 13));
    return items.concat(N.items);
  }

  // ---------------------------------------------------------------------------------------------------------------
  // CBC-MAC on messages of more than one length, and its fixes
  // ---------------------------------------------------------------------------------------------------------------
  function cbc(inp) {
    const M = Mc(), key = keyOf(inp.key), isC = inp.mac === 'cmac';
    const pad = (s) => { const b = U.utf8(s); const n = Math.max(16, Math.ceil(b.length / 16) * 16), o = new Uint8Array(n).fill(0x20); o.set(b); return o; };
    const m1 = pad(inp.m1), m2 = pad(inp.m2);
    const r = M.cbcMacForge({ key, m1, m2, mac: isC ? 'cmac' : 'cbc' });
    const tagger = (m) => (isC ? M.cmac(key, m, { trace: true }) : M.cbcMac(key, m, { trace: true }));
    const c1 = tagger(m1), c2 = tagger(m2), cf = tagger(r.forged), t1 = U.hex(r.t1), t2 = U.hex(r.t2), tf = U.hex(cf.tag);
    const name = isC ? 'CMAC' : 'CBC-MAC';
    const head = U.head('cb:h', name + ' on messages of more than one length', 'AES-128; the messages are padded with spaces to whole 16-byte blocks');
    const F = new S.Frames(['tags']);
    const row1 = () => chainRow({ prefix: 'r1', y: 98, chain: c1.chain, label: 'MAC(m1), asked for', tagCls: 'key', last: 't1' });
    const row2 = () => chainRow({ prefix: 'r2', y: 266, chain: c2.chain, label: 'MAC(m2), asked for', tagCls: 'key', last: 't2' });
    F.count('tags');
    F.add({ items: [...head, ...row1()], hl: { d: [0] }, say: `The ${name} tag of m1, “${U.text(m1).trim()}”: t1 = ${U.short(t1, 8)}. ${isC ? 'Under CMAC the last block is first XORed with a secret subkey.' : 'CBC-MAC encrypts block by block, each XORed with the previous output, from a zero start; the tag is the last output. So the tag is exactly the value the chain would carry into a next block.'}`, facts: { t1 }, meta: { stage: 'm1' } });
    F.count('tags');
    F.add({ items: [...head, ...row1(), ...row2()], hl: { d: [1] }, say: `And the tag of m2, “${U.text(m2).trim()}”: t2 = ${U.short(t2, 8)}. The preconditions are now met: tags on messages of an outsider's choosing, and a verifier that accepts messages of more than one length.`, facts: { t2 }, meta: { stage: 'm2' } });
    // the outcome only, never the construction
    const outcome = [...U.panel('cb:oc', 20, 440, 860, 130, 'what anyone holding these two tags can do, without the key'),
      t('cb:o1', 36, 492, 'a longer message, ' + r.forged.length / 16 + ' blocks, that the key holder never tagged', 'mono ' + (r.ok ? 'hot' : ''), 'start', 14),
      t('cb:o2', 36, 524, r.ok ? 'with a valid ' + name + ' tag ✓' : 'but the tag an outsider can predict is rejected by ' + name, r.ok ? 'bad' : 'good', 'start', 14),
      t('cb:o3', 36, 552, r.ok ? 'the first tag is the chain\'s state, so it lets the chain continue' : 'the subkey on the last block means a tag is not the chain\'s state', 'ptick', 'start', 13)];
    F.add({ items: [...head, ...row1(), ...row2(), ...outcome], hl: { d: [2] }, say: r.ok ? `The outcome: because a CBC-MAC tag is the chaining value after the message, these two tags let anyone build a ${r.forged.length / 16}-block message, never tagged by the key holder, whose ${name} tag is valid. No key is needed.` : `The outcome under CMAC: the same attempt fails. The last block was masked with a secret subkey, so t1 is not the chain's state, and the predicted tag ${U.short(t2, 8)} is not the tag of the longer message (${U.short(tf, 8)}): rejected.`, facts: { nb: r.forged.length / 16, tf, t2, ok: r.ok }, meta: { stage: 'outcome' } });
    const fixes = [...U.panel('cb:fx', 20, 440, 860, 150, 'the defences'),
      t('cb:f1', 36, 490, 'CMAC: XOR the last block with a secret subkey (K1 or K2)', isC ? 'good' : 'strong', 'start', 14),
      t('cb:f2', 36, 520, 'or prepend the message length as the first block', 'strong', 'start', 14),
      t('cb:f3', 36, 550, 'or encrypt the final value under a second key (EMAC)', 'strong', 'start', 14),
      t('cb:f4', 36, 578, 'never accept a plain CBC-MAC on messages of varying length', 'bad', 'start', 13)];
    F.add({ items: [...head, ...row1(), ...row2(), ...fixes], hl: { d: [3] }, say: `The defences all stop a tag from being a state the chain can continue from: CMAC masks the last block with a secret subkey; a length prefix makes a longer message differ from its very first block; EMAC encrypts the final value under a second key. ${isC ? 'CMAC is the one in use here, and it held.' : 'Plain CBC-MAC is safe only when every message has one fixed length.'}`, facts: { ok: r.ok }, meta: { stage: 'defence' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def(name, isC ? ['as CBC-MAC, but the last block is XORed with K1 (complete) or K2 (padded)', 'the subkeys come from L = E_K(0)', 'so a tag is not the chain\'s state: no continuation', 'standard: NIST SP 800-38B, RFC 4493'] : ['C₀ = 0;  Cᵢ = E_K(Mᵢ ⊕ Cᵢ₋₁);  tag = Cₙ', 'the tag is the chain\'s final state', 'secure only for messages of one fixed length', 'fixes: CMAC, or prepend the length, or encrypt the tag (EMAC)']) };
  }
  S.topic({
    id: 'p13-cbcmac', family: 'p13-mac', order: 30, title: 'CBC-MAC, and why it needs one fixed length',
    blurb: 'CBC-MAC is secure for messages of one fixed length. Its tag is the chain\'s final state, so when lengths vary, two tags are enough for anyone to make a valid tag on a longer message never tagged. Why, and the fixes: CMAC, a length prefix, or encrypting the tag.',
    inputs: [keyInput('lantern-key-0042'), { id: 'm1', kind: 'text', label: 'Message m1', def: 'pay 10 to wren', check: (v) => (U.utf8(v).length > 32 ? 'm1: at most 32 bytes' : null) }, { id: 'm2', kind: 'text', label: 'Message m2', def: 'pay 9000 to mallory, ok', check: (v) => (U.utf8(v).length > 32 ? 'm2: at most 32 bytes' : null) }, { id: 'mac', kind: 'choice', label: 'MAC', def: 'cbc', options: [{ value: 'cbc', label: 'CBC-MAC' }, { value: 'cmac', label: 'CMAC' }] }],
    presets: [
      { label: 'Two one-block messages', values: { key: 'lantern-key-0042', m1: 'pay 10 to wren', m2: 'grant: read only', mac: 'cbc' } },
      { label: 'A two-block second message', values: { key: 'lantern-key-0042', m1: 'pay 10 to wren', m2: 'pay 9000 to mallory, ok', mac: 'cbc' } },
      { label: 'The same messages under CMAC', values: { key: 'lantern-key-0042', m1: 'pay 10 to wren', m2: 'pay 9000 to mallory, ok', mac: 'cmac' } },
    ],
    counters: [{ id: 'tags', label: 'tags asked for' }],
    run: cbc,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'm2', pick: 'option', options: ['yes', 'no'], ask: 'With these two tags in hand, can someone without the key make a valid tag for a longer message the key holder never tagged?', answer: (fr, i, inp) => (inp.mac === 'cmac' ? 'no' : 'yes'), explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'For which messages is plain CBC-MAC secure?', options: ['all', 'messages of one fixed length', 'short ones', 'none'], answer: 1, why: 'Its security proof needs every message to have the same number of blocks.' },
      { q: 'What makes plain CBC-MAC forgeable when lengths vary?', options: ['AES is weak', 'its tag is the chain\'s final state, the value a longer message would carry on from', 'the key is short', 'the IV is zero'], answer: 1, why: 'A tag that is also a starting point lets a chain be continued without the key.' },
      { q: 'Which of these makes CBC-MAC safe for messages of any length?', options: ['a random IV sent with the tag', 'prepending the message length, or using CMAC', 'a longer key', 'tagging twice'], answer: 1, why: 'A length prefix, CMAC\'s subkey, or encrypting the tag under a second key (EMAC) all stop the continuation.' },
      { q: 'What does CMAC change?', options: ['the cipher', 'the last block is XORed with a secret subkey', 'the IV is random', 'the tag is longer'], answer: 1, why: 'The tag is no longer the chaining value a continuation would start from.' },
      { q: 'Why must CBC-MAC use a fixed IV of zero, not a random one sent with the tag?', options: ['for speed', 'an attacker could alter the IV to change the first block freely', 'it does not matter', 'to save space'], answer: 1, why: 'A random IV sent along lets the forger XOR any change into the first block.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // CMAC
  // ---------------------------------------------------------------------------------------------------------------
  function cmac(inp) {
    const M = Mc(), key = keyOf(inp.key), msg = inp.hex ? U.fromHex(inp.msg) : U.utf8(inp.msg);
    const r = M.cmac(key, msg, { trace: true }), sk = r.subkeys, complete = msg.length > 0 && msg.length % 16 === 0;
    const bitRow = (pre, y, b, label, lit, carry) => {
      const items = [t(pre + ':l', 20, y + 14, label, 'strong', 'start', 14)];
      const rows = [''];
      for (let i = 0; i < 128; i++) { const bit = (b[i >> 3] >> (7 - (i & 7))) & 1; rows[0] += lit && lit(i, bit) ? lit(i, bit) : bit ? '1' : '0'; }
      items.push({ key: pre + ':bm', kind: 'bitmap', x: 70, y, cw: 6.4, ch: 18, gap: 1, rows });
      items.push(t(pre + ':h', 70, y + 38, U.hex(b).replace(/(.{8})(?!$)/g, '$1 '), 'mono', 'start', 13));
      if (carry !== undefined) items.push(t(pre + ':c', 70 + 128 * 6.4 + 8, y + 14, carry ? '87' : '', 'hot', 'start', 13));
      return items;
    };
    const top = (stage) => {
      const items = [bitRow('cL', 92, sk.L, 'L', (i, bit) => (stage === 1 && i === 0 && bit ? '2' : ''))].flat();
      if (stage >= 1) items.push(...bitRow('c1', 160, sk.K1, 'K1', (i) => (stage === 1 && i >= 120 && sk.L[0] & 0x80 ? '3' : '') || (i === 127 && stage === 1 ? '4' : '')));
      if (stage >= 2) items.push(...bitRow('c2', 228, sk.K2, 'K2', (i) => (stage === 2 && i >= 120 && sk.K1[0] & 0x80 ? '3' : '')));
      return items;
    };
    const nb = r.chain.length;
    const row = (upto, done) => chainRow({ prefix: 'cr', y: 340, chain: r.chain.slice(0, upto), label: 'the CBC chain; the last block is ' + (complete ? 'complete, so it is XORed with K1' : 'padded with 80 00 … and XORed with K2'), mcls: (i) => (i === nb - 1 ? 'key' : ''), lit: (i) => (i === upto - 1 && !done ? 'act' : ''), tagCls: done ? 'hot' : '', last: done ? 'tag' : '' });
    const head = U.head('cm:h', 'CMAC with AES-128', U.plural(msg.length, 'byte') + ' of message, ' + U.plural(nb, 'block'));
    const F = new S.Frames(['blocks']);
    const L = U.hex(sk.L), K1 = U.hex(sk.K1), K2 = U.hex(sk.K2);
    F.add({ items: [...head, ...top(0)], hl: { d: [0] }, say: `First the subkeys. L = AES_K(0¹²⁸) = ${L}.`, facts: { L }, meta: { stage: 'L' } });
    F.add({ items: [...head, ...top(1)], hl: { d: [1] }, say: `K1 = L·x in GF(2¹²⁸): shift all 128 bits left by one; ${sk.L[0] & 0x80 ? 'the top bit of L was 1 and fell off, so 87 is XORed into the last byte' : 'the top bit of L was 0, so nothing else'}. K1 = ${K1}.`, facts: { K1, top: sk.L[0] >> 7 }, meta: { stage: 'K1' } });
    F.add({ items: [...head, ...top(2)], hl: { d: [1] }, say: `K2 = K1·x, the same once more${sk.K1[0] & 0x80 ? ', with the 87 fold' : ''}: K2 = ${K2}.`, facts: { K2 }, meta: { stage: 'K2' } });
    const last = U.hex(r.chain[nb - 1].m);
    F.add({ items: [...head, ...top(2), ...row(0, false)], hl: { d: [2] }, say: complete ? `The message is ${nb} whole ${nb === 1 ? 'block' : 'blocks'}, so its last block is XORed with K1: ${last}.` : `The last block has ${msg.length % 16} ${msg.length % 16 === 1 ? 'byte' : 'bytes'}, so it is padded with 80 and zeros and XORed with K2: ${last}. The two subkeys keep a padded message apart from one that happens to end in 80 00 ….`, facts: { last, nb, rem: msg.length % 16 }, meta: { stage: 'last' } });
    r.chain.forEach((s, i) => {
      F.count('blocks');
      F.add({ items: [...head, ...top(2), ...row(i + 1, false)], hl: { d: [3] }, say: `Block ${i + 1}: ${U.short(s.m, 8)} ⊕ ${U.short(s.prev, 8)} → AES → ${U.hex(s.c)}.`, facts: { i: i + 1, c: U.hex(s.c), m: U.hex(s.m), prev: U.hex(s.prev) }, meta: { stage: 'block', i } });
    });
    const tag = U.hex(r.tag);
    F.add({ items: [...head, ...top(2), ...row(nb, true)], hl: { d: [4] }, say: `The CMAC tag is the last output, ${tag}. The subkey on the last block is what CBC-MAC lacked: a forger extending a tagged message would have to know it.`, facts: { tag }, meta: { stage: 'tag' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('CMAC (NIST SP 800-38B, RFC 4493)', ['L = E_K(0¹²⁸)', 'K1 = L·x, K2 = K1·x  (x: shift left; if a 1 fell off, ⊕ 87)', 'last block complete: Mₙ ⊕ K1;  else (Mₙ ‖ 80 00…) ⊕ K2', 'then CBC from zero: Cᵢ = E_K(Mᵢ ⊕ Cᵢ₋₁)', 'tag = Cₙ (often cut to 64 or more bits)']) };
  }
  S.topic({
    id: 'p13-cmac', family: 'p13-mac', order: 40, title: 'CMAC and its two subkeys',
    blurb: 'Encrypt zero, double the result twice in GF(2¹²⁸), and mask the last block with one of the two subkeys: CBC-MAC made safe for messages of any length.',
    inputs: [keyInput('2b7e151628aed2a6abf7158809cf4f3c'), { id: 'hex', kind: 'choice', label: 'Message is', def: 'hex', options: [{ value: 'hex', label: 'hex bytes' }, { value: '', label: 'text' }] }, { id: 'msg', kind: 'text', label: 'Message', def: '6bc1bee22e409f96e93d7e117393172a', check: (v, inp) => (inp.hex ? U.hexCheck('Message', 0, 64)(v) : U.utf8(v).length > 64 ? 'Message: at most 64 bytes' : null) }],
    presets: [
      { label: 'RFC 4493: one block', values: { key: '2b7e151628aed2a6abf7158809cf4f3c', hex: 'hex', msg: '6bc1bee22e409f96e93d7e117393172a' } },
      { label: 'RFC 4493: the empty message', values: { key: '2b7e151628aed2a6abf7158809cf4f3c', hex: 'hex', msg: '' } },
      { label: 'RFC 4493: 40 bytes', values: { key: '2b7e151628aed2a6abf7158809cf4f3c', hex: 'hex', msg: '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411' } },
      { label: 'Our own text', values: { key: 'lantern-key-0042', hex: '', msg: 'pay 9000 to mallory, ok' } },
    ],
    counters: [{ id: 'blocks', label: 'blocks' }],
    run: cmac,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'K2', pick: 'option', options: ['K1', 'K2'], ask: 'Which subkey will mask the last block of this message?', answer: (fr) => (fr[3].facts.rem === 0 && fr[3].facts.nb > 0 && !/padded/.test(fr[3].say) ? 'K1' : 'K2'), explain: 'K1 for a complete last block, K2 for a padded one.' }],
    quiz: [
      { q: 'How is K1 made from L?', options: ['L ⊕ 87', 'L shifted left one bit, with 87 folded in if a 1 fell off', 'AES of L', 'L reversed'], answer: 1, why: 'Multiplication by x in GF(2¹²⁸).' },
      { q: 'When is K2 used?', options: ['always', 'when the last block had to be padded', 'for the first block', 'never'], answer: 1, why: 'It keeps a padded message apart from an unpadded one.' },
      { q: 'What does the empty message become under CMAC?', options: ['no tag', 'one padded block 80 00 … XORed with K2', 'a zero tag', 'an error'], answer: 1, why: 'n = 1 block, incomplete.' },
      { q: 'Why does CMAC need no length prefix, unlike some CBC-MAC fixes?', options: ['it does need one', 'the secret subkey on the last block already stops extensions', 'messages are fixed length', 'the IV carries the length'], answer: 1, why: 'A continuation would have to undo an unknown mask.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // GMAC
  // ---------------------------------------------------------------------------------------------------------------
  function gmac(inp) {
    const key = keyOf(inp.key), iv = U.fromHex(inp.iv), aad = inp.hex ? U.fromHex(inp.aad) : U.utf8(inp.aad);
    const r = Mc().gmac(key, iv, aad, { trace: true }), g = S.GCM.ghash(r.H, aad, new Uint8Array(0), { trace: false });
    const Hh = U.hex(r.H), J0 = U.hex(r.J0), Sg = U.hex(r.S), tag = U.hex(r.tag), EJ = U.hex(S.AES.encrypt(r.J0, key).out);
    const nb = g.blocks.length, cw = Math.min(200, 740 / nb), x0 = 150;
    const chain = (upto) => {
      const N = S.Kit.flow.net('gm'), items = [t('gm:ct', 20, 238, 'GHASH: Y ← (Y ⊕ X)·H for each block X', 'ptitle')];
      for (let i = 0; i < upto; i++) {
        const cx = x0 + i * cw, isLen = i === nb - 1, cur = i === upto - 1;
        N.box('x' + i, cx, 270, cw - 26, 28, isLen ? 'lengths' : show16(g.blocks[i]), 'val small ' + (isLen ? 'key' : ''));
        N.op('o' + i, cx, 316, 'xor', cur ? 'act' : '');
        N.box('m' + i, cx, 356, 50, 28, '·H', 'cipher' + (cur ? ' act' : ''));
        N.wire('a' + i, [N.port('x' + i, 's'), N.port('o' + i, 'n')], { head: true });
        N.wire('b' + i, [N.port('o' + i, 's'), N.port('m' + i, 'n')], { head: true });
        if (i === 0) { N.wire('z', [[cx - cw / 2 + 4, 316], N.port('o0', 'w')], { head: true }); items.push(t('gm:z', cx - cw / 2, 321, '0', 'mono ptick', 'end', 13)); }
        else N.wire('c' + i, [N.port('m' + (i - 1), 'e'), [cx - cw / 2, 356], [cx - cw / 2, 316], N.port('o' + i, 'w')], { head: true });
        items.push({ key: 'gm:y' + i, kind: 'cell', x: U.r2(cx - 58), y: 382, w: 116, h: 22, rx: 4, text: U.hex(g.ys[i]).slice(0, 12) + '…', size: 13.5, cls: 'hex ' + (cur ? 'act' : '') });
      }
      return items.concat(N.items);
    };
    const top = () => {
      const items = [];
      items.push(...U.readout('gm:k', 20, 76, 430, 'from the key and the IV', [['H = AES_K(0¹²⁸)', U.short(Hh, 10), 'key'], ['J0 = IV ‖ 00000001', U.short(J0, 10)], ['AES_K(J0)', U.short(EJ, 10)]], { dy: 30 }));
      items.push(...U.readout('gm:d', 470, 76, 430, 'the data, authenticated only', [['associated data', U.plural(aad.length, 'byte')], ['blocks, with the length block', String(nb)], ['plaintext', 'none']], { dy: 30 }));
      return items;
    };
    const fin = () => {
      const N = S.Kit.flow.net('gf');
      N.box('s', 200, 470, 260, 34, 'GHASH = ' + Sg.slice(0, 16) + '…', 'val small act');
      N.op('x', 420, 470, 'xor', 'hot');
      N.box('e', 420, 540, 260, 34, 'AES_K(J0) = ' + EJ.slice(0, 16) + '…', 'val small key');
      N.box('t', 690, 470, 300, 34, 'tag = ' + tag.slice(0, 20) + '…', 'val small hot');
      N.wire('a', [N.port('s', 'e'), N.port('x', 'w')], { head: true }); N.wire('b', [N.port('e', 'n'), N.port('x', 's')], { head: true }); N.wire('c', [N.port('x', 'e'), N.port('t', 'w')], { head: true });
      return N.items;
    };
    const head = U.head('gx:h', 'GMAC: GCM with nothing to encrypt', 'AES-128; a 12-byte IV');
    const F = new S.Frames(['multiplies']);
    F.add({ items: [...head, ...top()], hl: { d: [0] }, say: `The hash key H = AES_K(0¹²⁸) = ${Hh}, and the first counter block J0 = IV ‖ 00000001 = ${J0}.`, facts: { Hh, J0 }, meta: { stage: 'setup' } });
    for (let i = 0; i < nb; i++) {
      F.count('multiplies');
      const isLen = i === nb - 1;
      F.add({ items: [...head, ...top(), ...chain(i + 1)], hl: { d: [1] }, say: `${isLen ? 'The length block (the data length in bits, then the plaintext length, 0)' : 'Block ' + (i + 1) + ' of the data'} ${U.hex(g.blocks[i])} is XORed in and the sum multiplied by H in GF(2¹²⁸): Y = ${U.hex(g.ys[i])}.`, facts: { i: i + 1, x: U.hex(g.blocks[i]), y: U.hex(g.ys[i]) }, meta: { stage: 'ghash', i } });
    }
    F.add({ items: [...head, ...top(), ...chain(nb), ...fin()], hl: { d: [2] }, say: `GHASH = ${Sg}, a polynomial in H whose coefficients are the blocks. The tag masks it with AES_K(J0) = ${EJ}: tag = ${tag}.`, facts: { Sg, EJ, tag }, meta: { stage: 'tag' } });
    F.add({ items: [...head, ...top(), ...chain(nb), ...fin()], hl: { d: [3] }, say: `Never reuse an IV: two tags under the same IV share the mask AES_K(J0), so their XOR is a known polynomial in H, whose roots give H to anyone, and with H every tag can be forged.`, facts: {}, meta: { stage: 'reuse' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('GMAC (GCM with an empty plaintext)', ['H = E_K(0¹²⁸),  J0 = IV ‖ 0³¹1', 'X₁ … Xₘ: the data in blocks, then [len(A)]₆₄ ‖ [0]₆₄', 'Y₀ = 0;  Yᵢ = (Yᵢ₋₁ ⊕ Xᵢ)·H in GF(2¹²⁸)', 'tag = E_K(J0) ⊕ Yₘ', 'a fresh IV for every message']) };
  }
  S.topic({
    id: 'p13-gmac', family: 'p13-mac', order: 50, title: 'GMAC: a polynomial in H',
    blurb: 'GCM\'s authentication alone: the data blocks become the coefficients of a polynomial evaluated at the secret point H, and an encrypted counter block masks the result. Fast, and fragile if an IV repeats.',
    inputs: [keyInput('lantern-key-0042'), { id: 'iv', kind: 'text', label: 'IV (12 bytes, hex)', def: 'cafebabefacedbaddecaf888', check: U.hexCheck('IV', 12, 12) }, { id: 'hex', kind: 'choice', label: 'Data is', def: '', options: [{ value: '', label: 'text' }, { value: 'hex', label: 'hex bytes' }] }, { id: 'aad', kind: 'text', label: 'Associated data', def: 'header: route 7, seq 41', check: (v, inp) => (inp.hex ? U.hexCheck('Data', 0, 80)(v) : U.utf8(v).length > 80 ? 'Data: at most 80 bytes' : null) }],
    presets: [
      { label: 'A header', values: { key: 'lantern-key-0042', iv: 'cafebabefacedbaddecaf888', hex: '', aad: 'header: route 7, seq 41' } },
      { label: 'No data at all', values: { key: 'lantern-key-0042', iv: '000000000000000000000000', hex: '', aad: '' } },
      { label: 'Four blocks of data', values: { key: 'feffe9928665731c6d6a8f9467308308', iv: 'cafebabefacedbaddecaf888', hex: 'hex', aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2feedfacedeadbeeffeedfacedeadbeefabaddad2' } },
    ],
    counters: [{ id: 'multiplies', label: 'multiplications by H' }],
    run: gmac,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'setup', pick: 'option', options: (fr) => { const n = fr.filter((f) => f.meta.stage === 'ghash').length; return [String(n - 1), String(n), String(n + 1)]; }, ask: 'How many multiplications by H will GHASH make here?', answer: (fr) => String(fr.filter((f) => f.meta.stage === 'ghash').length), explain: 'One per data block, plus one for the length block.' }],
    quiz: [
      { q: 'What does GMAC authenticate?', options: ['a ciphertext', 'associated data, with nothing encrypted', 'the key', 'the IV only'], answer: 1, why: 'It is GCM with an empty plaintext.' },
      { q: 'What is H?', options: ['the IV', 'AES_K of the zero block', 'the tag', 'a hash of the data'], answer: 1, why: 'The secret point at which the polynomial is evaluated.' },
      { q: 'Why is the length block included?', options: ['padding', 'so data that differs only in trailing zero bytes gets different tags', 'for speed', 'it is not'], answer: 1, why: 'Zero-padding alone would make such messages collide.' },
      { q: 'What happens if two messages use the same IV?', options: ['nothing', 'the mask cancels and H can be found, enabling forgeries', 'the tags are equal', 'decryption fails'], answer: 1, why: 'The forbidden attack on GCM.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
