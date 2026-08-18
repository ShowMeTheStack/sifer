// Part 3, ChaCha20 as a stream cipher: one block from state to keystream (twenty rounds, then the input added
// back, then the words written out little-endian), the block counter that gives every 64 bytes their own
// keystream, and XChaCha20, which turns a 24-byte nonce into a subkey and a 12-byte nonce with HChaCha20.
(function (S) {
  'use strict';
  const U = S.SymT, W = S.P03b, h8 = U.h8;
  const xs = (i) => 'x' + U.sub(i);
  const le = (w) => [w & 255, (w >>> 8) & 255, (w >>> 16) & 255, w >>> 24];
  const msgCheck = (max) => (v) => { const n = S.bytes.utf8(String(v)).length; return n < 1 ? 'Message: at least one byte' : n > max ? 'Message: at most ' + max + ' bytes, so the picture stays readable' : null; };
  /** byte cells in rows of 16 */
  const byteRows = (prefix, x, y, bytes, cls, o) => {
    o = o || {};
    const cw = o.cw || 34, ch = o.ch || 28, per = o.per || 16, items = [];
    Array.from(bytes).forEach((b, i) => items.push({ key: prefix + i, kind: 'cell', x: x + (i % per) * (cw + 3) + (i % per >= per / 2 ? 6 : 0), y: y + Math.floor(i / per) * (ch + 6), w: cw, h: ch, rx: 3, text: U.h2(b), size: o.size || 14, cls: 'hex ' + (cls ? cls(i, b) || '' : '') }));
    return items;
  };

  // ---------------------------------------------------------------------------------------------------------------
  // The ChaCha20 block and its counter
  // ---------------------------------------------------------------------------------------------------------------
  function chachaBlock(inp) {
    const C = S.ChaCha, key = S.bytes.utf8(inp.key), nonce = S.bytes.utf8(inp.nonce), ctr = inp.counter, msg = S.bytes.utf8(inp.msg);
    const blk = C.block(key, ctr, nonce), st = blk.state, r10 = blk.rounds[9], enc = C.encryptTrace(key, ctr, nonce, msg);
    const F = new S.Frames(), head = U.head('cb:h', 'ChaCha20: one block, then the counter');
    const grid = (words, cls, title) => W.grid({ prefix: 'cb', x: 24, y: 78, words, role: words === st ? W.chachaRole : null, cls, title }).items;
    const side = (title, rows) => U.readout('cb:r', 536, 64, 360, title, rows, { dy: 32 });
    const leg = W.legend('cb:lg', 24, 370);
    F.add({ items: [head, ...grid(st, (i) => (i === 12 ? 'hot' : ''), 'block ' + 0 + ': the starting state'), ...leg, ...side('what goes in', [['key', '32 bytes', 'key'], ['nonce', U.hex(nonce), ''], ['block counter, word 12', String(ctr), 'hot'], ['blocks needed', String(enc.blocks.length) + ' for ' + msg.length + ' bytes']]), ...U.readout('cb:bl', 24, 400, 872, 'one state per block: only word 12 changes', enc.blocks.map((b) => ['block ' + b.i + ': message bytes ' + 64 * b.i + '–' + (64 * b.i + b.p.length - 1), xs(12) + ' = ' + h8(b.counter), b.i ? '' : 'hot']), { dy: 32 })],
      say: `To encrypt ${msg.length} bytes, ChaCha20 needs ${enc.blocks.length} block${enc.blocks.length === 1 ? '' : 's'} of 64 keystream bytes. Each block starts from this state: the constants, the key, the nonce and, in ${xs(12)}, the block counter, here ${ctr} = ${h8(st[12])}.`,
      facts: { n: msg.length, blocks: enc.blocks.length, ctr, w12: h8(st[12]) }, meta: { stage: 'state' } });
    const d = W.diffBits(st, r10);
    F.add({ items: [head, ...grid(r10, () => '', 'after 20 rounds'), ...leg, ...side('ten double rounds', [['rounds', '20'], ['bits that differ from the start', String(d)], [xs(0), h8(r10[0])], ['invertible so far', 'yes', 'hot']])],
      say: `Ten double rounds later ${d} of the 512 bits differ from the starting state, about half, as for an unrelated random state. But the rounds are a permutation: this state alone could be run backwards to reveal the key.`,
      facts: { d, x0: h8(r10[0]) }, meta: { stage: 'rounds' } });
    F.add({ items: [head, ...grid(blk.words, () => 'hot', 'after 20 rounds ⊞ the starting state'), ...leg, ...side('adding the input back', [[xs(0) + ' after the rounds', h8(r10[0])], ['⊞ ' + xs(0) + ' at the start', h8(st[0])], ['= keystream word 0', h8(blk.words[0]), 'hot'], [xs(12) + ': ' + h8(r10[12]) + ' ⊞ ' + h8(st[12]), h8(blk.words[12]), 'hot']])],
      hl: { d: [2] }, say: `Each word of the result is added, modulo 2³², to the same word of the starting state: ${h8(r10[0])} + ${h8(st[0])} = ${h8(blk.words[0])}. With the key on both sides of the addition, the rounds can no longer be undone.`,
      facts: { a: h8(r10[0]), b: h8(st[0]), w: h8(blk.words[0]) }, meta: { stage: 'add' } });
    const ks0 = blk.out, w0 = le(blk.words[0]);
    F.add({ items: [head, ...grid(blk.words, (i) => (i === 0 ? 'hot' : ''), 'the keystream words'), ...side('little-endian bytes', [['word 0', h8(blk.words[0]), 'hot'], ['as bytes, lowest first', w0.map(U.h2).join(' '), 'act'], ['keystream bytes', '64 per block']]), U.t('cb:kt', 24, 390, 'the 64 keystream bytes of block 0', 'title', 'start', 14), ...byteRows('cb:k', 24, 402, ks0, (i) => (i < 4 ? 'hot' : ''))],
      hl: { d: [3] }, say: `Each word is written out lowest byte first: word 0, ${h8(blk.words[0])}, becomes the bytes ${w0.map(U.h2).join(' ')}. Sixteen words give the 64 keystream bytes of this block.`,
      facts: { w: h8(blk.words[0]), b: w0.map(U.h2).join(' ') }, meta: { stage: 'bytes' } });
    // the blocks as a row of counter → ChaCha20 → ⊕ columns
    const nb = enc.blocks.length, colX = (j) => 170 + j * (nb === 1 ? 0 : 560 / (nb - 1)) + (nb === 1 ? 280 : 0);
    const flow = (at) => {
      const N = S.Kit.flow.net('cf');
      enc.blocks.forEach((b, j) => {
        const x = colX(j), on = at === j || at === 'all';
        N.box('ctr' + j, x, 92, 150, 36, 'counter ' + b.counter, 'small ' + (on ? 'act' : ''));
        N.box('f' + j, x, 170, 190, 44, 'ChaCha20 block', 'cipher');
        N.op('x' + j, x, 262, 'xor', on ? 'act' : '');
        N.box('p' + j, x - 120, 262, 76, 32, 'P' + U.sub(j), 'small');
        N.box('c' + j, x, 336, 150, 34, 'C' + U.sub(j) + ' (' + b.p.length + ' bytes)', 'small ' + (on ? 'hot' : ''));
        N.wire('a' + j, [N.port('ctr' + j, 's'), N.port('f' + j, 'n')], { head: true, cls: on ? 'act' : '' });
        N.wire('b' + j, [N.port('f' + j, 's'), N.port('x' + j, 'n')], { head: true, cls: on ? 'act' : '' });
        N.wire('p' + j, [N.port('p' + j, 'e'), N.port('x' + j, 'w')], { head: true });
        N.wire('o' + j, [N.port('x' + j, 's'), N.port('c' + j, 'n')], { head: true, cls: on ? 'hot' : '' });
      });
      return N.items;
    };
    enc.blocks.forEach((b, j) => {
      const n = b.p.length, show = Math.min(16, n);
      const rows = [
        U.t('cb:l0', 24, 402, 'plaintext', 'tick', 'start', 13), ...byteRows('cb:p', 120, 388, b.p.slice(0, show), null, { cw: 44 }),
        U.t('cb:l1', 24, 438, 'keystream', 'tick', 'start', 13), ...byteRows('cb:s', 120, 424, b.ks.slice(0, show), () => 'act', { cw: 44 }),
        U.t('cb:l2', 24, 474, 'ciphertext', 'tick', 'start', 13), ...byteRows('cb:c', 120, 460, b.c.slice(0, show), () => 'hot', { cw: 44 }),
        U.t('cb:l3', 120, 512, '“' + U.show(b.p.slice(0, show)) + '”' + (n > show ? ' and ' + (n - show) + ' more bytes' : ''), 'mono', 'start', 14),
      ];
      F.add({ items: [head, ...flow(j), ...rows, U.t('cb:note', 24, 560, n < 64 ? 'the last ' + (64 - n) + ' keystream bytes of this block are not used' : 'all 64 keystream bytes are used', 'tick', 'start', 14)],
        hl: { d: [4] }, say: `Block ${j}: the counter ${b.counter} goes into word 12, the block function gives 64 fresh keystream bytes starting ${U.hex(b.ks.slice(0, 4))}, and ${n} plaintext bytes are XORed with them: “${U.show(b.p.slice(0, 4))}” (${U.hex(b.p.slice(0, 4))}) becomes ${U.hex(b.c.slice(0, 4))}.` + (n < 64 ? ` The other ${64 - n} keystream bytes are thrown away.` : ''),
        facts: { j, pt: U.show(b.p.slice(0, 4)), counter: b.counter, ks: U.hex(b.ks.slice(0, 4)), p: U.hex(b.p.slice(0, 4)), c: U.hex(b.c.slice(0, 4)), n, rest: 64 - n }, meta: { stage: 'block', j } });
    });
    const back = C.encrypt(key, ctr, nonce, enc.out), ok = S.bytes.eq(back, msg);
    F.add({ items: [head, ...flow('all'), ...U.readout('cb:end', 24, 384, 872, 'the whole message', [['ciphertext, first 16 bytes', U.hexs(enc.out.slice(0, 16)), 'hot'], ['decrypt: the same keystream XORed again', ok ? 'gives the message back' : 'fails', ok ? 'good' : 'bad'], ['counters used', enc.blocks.map((b) => b.counter).join(', '), 'act'], ['blocks per nonce, at most', '2³² (256 GiB)']], { dy: 40, size: 15, vsize: 15 })],
      say: `The ciphertext begins ${U.hexs(enc.out.slice(0, 16))}. Decryption is the same computation: the same key, nonce and counters give the same keystream, and XOR cancels it. Every block has its own counter, so no keystream byte is used twice; but a nonce must never be reused with the same key, or two messages share a keystream.`,
      facts: { c: U.hexs(enc.out.slice(0, 16)), ok }, meta: { stage: 'end' } });
    W.dropLegend(F.list, 'cb:lg', ['state']);
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 620 });
    return { frames: F.list, def: U.def('The ChaCha20 block', ['state = constants ‖ key ‖ counter ‖ nonce (16 words)', 'block = 20 rounds(state) ⊞ state', 'keystream = the 16 words, little-endian: 64 bytes', 'block j of a message uses counter + j', 'C = P ⊕ keystream; P = C ⊕ keystream']) };
  }
  S.topic({
    id: 'st-chacha-block', family: 'p03-arx', order: 30, title: 'The ChaCha20 block and its counter',
    blurb: 'Twenty rounds scramble the state, adding the starting state back makes the result one-way, and the sixteen words become 64 keystream bytes. The block counter gives each 64 bytes of a message their own keystream.',
    inputs: [
      { id: 'key', kind: 'string', spaces: true, label: 'Key (32 bytes of text)', def: 'a heron waits where reeds divide', check: W.textCheck('Key', 32) },
      { id: 'nonce', kind: 'string', spaces: true, label: 'Nonce (12 bytes)', def: 'shore#000042', check: W.textCheck('Nonce', 12) },
      { id: 'counter', kind: 'number', label: 'First block counter', def: 1, min: 0, max: 4294967200 },
      { id: 'msg', kind: 'string', spaces: true, label: 'Message', def: 'Meet me by the lighthouse steps when the fog lifts; bring the brass compass and the tide tables.', check: msgCheck(180) },
    ],
    presets: [
      { label: 'Two blocks', values: {} },
      { label: 'One short block', values: { msg: 'gulls circle the old pier; wait', counter: 1 } },
      { label: 'Three blocks from counter 0', values: { counter: 0, msg: 'Meet me by the lighthouse steps when the fog lifts; bring the brass compass and the tide tables. Leave the oars in the boathouse.' } },
      { label: 'Another nonce', values: { nonce: 'shore#000043' } },
    ],
    run: chachaBlock,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'rounds', pick: 'option', options: ['to make it longer', 'so it cannot be run backwards to the key', 'to add the counter'], ask: 'Next the starting state is added to this one. Why?', answer: 'so it cannot be run backwards to the key', explain: 'The twenty rounds are invertible; the addition with the (secret) input breaks that.' },
      { at: (f) => f.meta && f.meta.stage === 'bytes', pick: 'option', options: ['the same keystream as block 0', 'a new keystream, because the counter is one more'], ask: 'Block 1 of the message uses the same key and nonce. What does it get?', answer: 'a new keystream, because the counter is one more', explain: 'Word 12 differs, and twenty rounds turn that one-bit-ish change into an unrelated block.' },
    ],
    quiz: [
      { q: 'How many keystream bytes does one ChaCha20 block give?', options: ['16', '32', '64', '128'], answer: 2, why: 'Sixteen 32-bit words.' },
      { q: 'Why is the starting state added to the output of the rounds?', options: ['To make the function one-way: without it the rounds could be inverted to find the key', 'To add the counter', 'For speed', 'To make the output longer'], answer: 0, why: 'A permutation alone hides nothing: anyone can run it backwards.' },
      { q: 'What happens to unused keystream bytes in the last block?', options: ['They are thrown away', 'They are kept for the next message', 'They are XORed into the key', 'They pad the ciphertext'], answer: 0, why: 'Keeping them for later would risk using a keystream twice.' },
      { q: 'With a 32-bit block counter, how much can one key and nonce encrypt?', options: ['2³² bytes', '2³² blocks of 64 bytes (256 GiB)', 'unlimited', '64 bytes'], answer: 1, why: 'After that the counter would wrap and repeat keystream.' },
      { q: 'How does ChaCha20 decryption differ from encryption?', options: ['It runs the rounds backwards', 'It is the same: XOR with the same keystream', 'It uses a different key', 'It subtracts the input'], answer: 1, why: 'A stream cipher only ever computes keystream in the forward direction.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // XChaCha20
  // ---------------------------------------------------------------------------------------------------------------
  function xchacha(inp) {
    const C = S.ChaCha, key = S.bytes.utf8(inp.key), nonce = S.bytes.utf8(inp.nonce), msg = S.bytes.utf8(inp.msg);
    const n16 = nonce.subarray(0, 16), le32 = (b, i) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
    const hst = C.state(key, le32(n16, 0), n16.subarray(4, 16)), hb = C.block(key, le32(n16, 0), n16.subarray(4, 16)), hr = hb.rounds[9];
    const h = C.hchacha(key, n16), x = C.xencrypt(key, nonce, msg), sub = h.out, n12 = x.nonce12;
    const F = new S.Frames(), head = U.head('xc:h', 'XChaCha20: a 24-byte nonce');
    const pipe = (at) => {
      const N = S.Kit.flow.net('xp'), on = (k) => (at === k ? 'act' : '');
      nonce.forEach((b, i) => N.add({ key: 'xp:n' + i, kind: 'cell', x: 64 + i * 33 + (i >= 16 ? 14 : 0), y: 70, w: 30, h: 28, rx: 3, text: U.h2(b), size: 13, cls: 'hex ' + (i < 16 ? (at === 'hstate' || at === 'nonce' ? 'act' : '') : at === 'nonce12' || at === 'nonce' ? 'wnonce' : '') }));
      N.label('nl', 64, 62, 'the 24-byte nonce', 'tick', 'start', 13);
      const xa = 64 + 8 * 33, xb = 64 + 20 * 33 + 14;
      N.box('K', 108, 150, 110, 38, 'key', 'key small');
      N.box('H', xa, 150, 250, 44, 'HChaCha20(key, n₀…₁₅)', 'cipher ' + on('hrounds'));
      N.box('SK', xa, 236, 220, 36, 'subkey (32 bytes)', 'small ' + (at === 'subkey' ? 'hot' : ''));
      N.box('N12', xb, 150, 210, 38, '00000000 ‖ bytes 16–23', 'small ' + (at === 'nonce12' ? 'hot' : ''));
      N.box('CC', xb, 236, 220, 44, 'ChaCha20(subkey, n₁₂)', 'cipher ' + on('encrypt'));
      N.wire('nh', [[xa, 98], N.port('H', 'n')], { head: true, cls: on('hstate') });
      N.wire('nn', [[xb, 98], N.port('N12', 'n')], { head: true, cls: on('nonce12') });
      N.wire('kh', [N.port('K', 'e'), N.port('H', 'w')], { head: true, cls: 'key' });
      N.wire('hs', [N.port('H', 's'), N.port('SK', 'n')], { head: true, cls: on('subkey') });
      N.wire('sc', [N.port('SK', 'e'), N.port('CC', 'w')], { head: true, cls: on('encrypt') });
      N.wire('nc', [N.port('N12', 's'), N.port('CC', 'n')], { head: true, cls: on('encrypt') });
      N.wire('ks', [N.port('CC', 'e'), [904, 236]], { head: true, cls: at === 'encrypt' ? 'hot' : '' });
      N.label('ksl', 904, 284, 'keystream', 'tick', 'end', 13);
      return N.items;
    };
    const grid = (words, cls, title) => W.grid({ prefix: 'xg', x: 24, y: 312, words, role: words === hst ? (i) => (i < 4 ? 'wconst' : i < 12 ? 'key' : 'wnonce') : null, cls, title, ch: 52 }).items;
    const side = (title, rows) => U.readout('xc:r', 536, 300, 360, title, rows, { dy: 32 });
    F.add({ items: [head, ...pipe('nonce'), ...U.readout('xc:r', 24, 300, 872, 'the nonce', [['as text', '“' + inp.nonce + '”'], ['bytes 0–15, into HChaCha20', U.hex(n16), 'act'], ['bytes 16–23, into the ChaCha20 nonce', U.hex(nonce.subarray(16)), ''], ['why 24 bytes', 'random nonces that never collide']], { dy: 40, size: 15, vsize: 15 })],
      say: `XChaCha20 takes a 24-byte nonce, long enough to pick at random for every message. The first 16 bytes, ${U.hex(n16)}, go with the key into HChaCha20 to make a subkey; the last 8, ${U.hex(nonce.subarray(16))}, become part of an ordinary 12-byte ChaCha20 nonce.`,
      facts: { a: U.hex(n16), b: U.hex(nonce.subarray(16)) }, meta: { stage: 'nonce' } });
    F.add({ items: [head, ...pipe('hstate'), ...grid(hst, (i) => (i >= 12 ? 'act' : ''), 'the HChaCha20 state'), ...side('HChaCha20 input', [['constants', 'x₀ … x₃'], ['key', 'x₄ … x₁₁', 'key'], ['nonce bytes 0–15', 'x₁₂ … x₁₅', 'act'], [xs(12), h8(hst[12]), 'act']])],
      hl: { d: [1] }, say: `HChaCha20 builds a ChaCha20 state with the 16 nonce bytes where the counter and nonce would go: ${xs(12)} = ${h8(hst[12])} through ${xs(15)} = ${h8(hst[15])}.`,
      facts: { a: h8(hst[12]), b: h8(hst[15]) }, meta: { stage: 'hstate' } });
    const keep = (i) => i < 4 || i >= 12;
    F.add({ items: [head, ...pipe('hrounds'), ...grid(hr, (i) => (keep(i) ? 'wsub' : 'dim'), 'after 20 rounds, no addition'), ...side('the subkey words', [['kept', 'x₀ … x₃, x₁₂ … x₁₅', 'hot'], [xs(0), h8(hr[0]), 'hot'], [xs(15), h8(hr[15]), 'hot'], ['input added back', 'no']])],
      hl: { d: [2] }, say: `It runs the same twenty rounds, but does not add the input back. It keeps words 0 to 3 and 12 to 15, from ${h8(hr[0])} to ${h8(hr[15])}: the positions that held only the constants and the nonce, which an attacker knows anyway, so adding them back would hide nothing. The subkey is never shown to anyone.`,
      facts: { a: h8(hr[0]), b: h8(hr[15]) }, meta: { stage: 'hrounds' } });
    F.add({ items: [head, ...pipe('subkey'), U.t('xc:skt', 24, 330, 'the subkey, 32 bytes', 'title', 'start', 14), ...byteRows('xc:sk', 24, 342, sub, () => 'wsub', { cw: 46 }), ...U.readout('xc:r2', 24, 430, 872, 'from the eight kept words, little-endian', [[xs(0) + ' = ' + h8(hr[0]), U.hexs(sub.slice(0, 4)), 'hot'], [xs(12) + ' = ' + h8(hr[12]), U.hexs(sub.slice(16, 20)), 'hot']], { dy: 34 })],
      hl: { d: [3] }, say: `The eight words, written out lowest byte first, are the 32-byte subkey ${U.hex(sub.slice(0, 8))}…: ${xs(0)} = ${h8(hr[0])} gives the bytes ${U.hexs(sub.slice(0, 4))}. A different nonce gives an unrelated subkey.`,
      facts: { s: U.hex(sub.slice(0, 8)), x0: h8(hr[0]), b: U.hexs(sub.slice(0, 4)) }, meta: { stage: 'subkey' } });
    F.add({ items: [head, ...pipe('nonce12'), U.t('xc:n12t', 24, 330, 'the ChaCha20 nonce, 12 bytes', 'title', 'start', 14), ...byteRows('xc:nn', 24, 342, n12, (i) => (i < 4 ? 'soft' : 'wnonce'), { cw: 52 }), U.t('xc:n12n', 24, 410, 'four zero bytes, then nonce bytes 16–23', 'tick', 'start', 14)],
      hl: { d: [4] }, say: `The ChaCha20 nonce is four zero bytes followed by the last 8 nonce bytes: ${U.hex(n12)}.`,
      facts: { n: U.hex(n12) }, meta: { stage: 'nonce12' } });
    const b0 = x.out.slice(0, Math.min(16, msg.length)), ks = C.block(sub, 0, n12).out.slice(0, b0.length);
    F.add({ items: [head, ...pipe('encrypt'), ...U.readout('xc:r', 24, 300, 872, 'ChaCha20 with the subkey, counter 0', [['message', '“' + U.show(msg.slice(0, 22)) + (msg.length > 22 ? '…' : '') + '”'], ['keystream', U.hexs(ks), 'act'], ['ciphertext', U.hexs(b0), 'hot'], ['length', msg.length + ' bytes']], { dy: 40, size: 15, vsize: 15 })],
      hl: { d: [5] }, say: `Then it is ordinary ChaCha20 under the subkey with that nonce, counter from 0: the keystream begins ${U.hex(ks.slice(0, 8))}, and the ${msg.length}-byte message encrypts to ${U.hex(b0.slice(0, 8))}…`,
      facts: { ks: U.hex(ks.slice(0, 8)), c: U.hex(b0.slice(0, 8)), n: msg.length }, meta: { stage: 'encrypt' } });
    F.add({ items: [head, ...pipe(null), ...U.readout('xc:r', 24, 300, 872, 'random nonces: when do two collide?', [['12-byte nonce (96 bits)', 'likely after about 2⁴⁸ messages', 'bad'], ['24-byte nonce (192 bits)', 'likely after about 2⁹⁶ messages', 'good'], ['cost of the extension', 'one HChaCha20 per message']], { dy: 40, size: 15, vsize: 15 })],
      say: `Why bother: by the birthday bound, random 12-byte nonces are likely to repeat after about 2^48 messages under one key, and a repeat is a two-time pad. Random 24-byte nonces are safe for about 2^96 messages, for the price of one extra HChaCha20 call per message.`,
      facts: { a: 48, b: 96 }, meta: { stage: 'why' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 600 });
    return { frames: F.list, def: U.def('XChaCha20', ['subkey = HChaCha20(key, nonce[0..16])', 'HChaCha20: 20 rounds, no addition, words 0–3 and 12–15', 'nonce12 = 00000000 ‖ nonce[16..24]', 'XChaCha20(key, nonce) = ChaCha20(subkey, nonce12)', 'random 192-bit nonces: no birthday worry']) };
  }
  S.topic({
    id: 'st-xchacha', family: 'p03-arx', order: 40, title: 'XChaCha20: a nonce you can pick at random',
    blurb: 'A 12-byte nonce chosen at random repeats too soon for comfort. XChaCha20 takes 24 bytes: HChaCha20 folds the first 16 into a subkey, and the last 8 make an ordinary ChaCha20 nonce.',
    inputs: [
      { id: 'key', kind: 'string', spaces: true, label: 'Key (32 bytes of text)', def: 'a heron waits where reeds divide', check: W.textCheck('Key', 32) },
      { id: 'nonce', kind: 'string', spaces: true, label: 'Nonce (24 bytes)', def: 'gulls-over-the-old-pier!', check: W.textCheck('Nonce', 24) },
      { id: 'msg', kind: 'string', spaces: true, label: 'Message', def: 'gulls circle the old pier; wait', check: msgCheck(120) },
    ],
    presets: [
      { label: 'Default', values: {} },
      { label: 'Nonce one byte different', values: { nonce: 'gulls-over-the-old-pier?' } },
      { label: 'Only the last 8 bytes differ', values: { nonce: 'gulls-over-the-old-dock!' } },
      { label: 'Another key', values: { key: 'otters nap in kelp beds at dusk.' } },
    ],
    run: xchacha,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'hstate', pick: 'option', options: ['yes, as in ChaCha20', 'no'], ask: 'Will HChaCha20 add the input state back after its twenty rounds?', answer: 'no', explain: 'It keeps only the words that held known values, so adding the input would add nothing secret; the subkey is never revealed.' },
      { at: (f) => f.meta && f.meta.stage === 'nonce12', pick: 'option', options: ['about 2^32', 'about 2^48', 'about 2^96', 'never'], ask: 'Random 12-byte nonces: after about how many messages is a repeat likely?', answer: 'about 2^48', explain: 'The birthday bound: the square root of 2^96.' },
    ],
    quiz: [
      { q: 'What does HChaCha20 produce?', options: ['A keystream', 'A 32-byte subkey from the key and the first 16 nonce bytes', 'A 24-byte nonce', 'A MAC'], answer: 1, why: 'The subkey replaces the key for the ChaCha20 that follows.' },
      { q: 'Which words does HChaCha20 output?', options: ['0–7', '4–11', '0–3 and 12–15', 'all sixteen'], answer: 2, why: 'The positions that held the constants and the nonce.' },
      { q: 'What is the 12-byte ChaCha20 nonce in XChaCha20?', options: ['The first 12 nonce bytes', 'Four zero bytes and the last 8 nonce bytes', 'The subkey', 'Random'], answer: 1, why: 'The first 16 bytes are already spent on the subkey.' },
      { q: 'Why is a 24-byte nonce useful?', options: ['It is faster', 'Nonces can be chosen at random without a realistic chance of a repeat', 'It makes the key longer', 'It removes the counter'], answer: 1, why: 'A collision is likely only after about 2^96 messages.' },
      { q: 'If two messages share a key and a 24-byte nonce, then…', options: ['nothing bad happens', 'they share a keystream: a two-time pad', 'the subkeys differ', 'the counter protects them'], answer: 1, why: 'Same subkey, same nonce12, same keystream.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
