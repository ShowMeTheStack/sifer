// Part 6, the keystream modes: OFB (the cipher run on its own output, a keystream that never sees the data) and CTR
// (the cipher run on counter blocks: every block independent, so blocks can be made in parallel or reached directly).
(function (S) {
  'use strict';
  const U = S.P5, K6 = () => S.Kit.p06, Fl = () => S.Kit.flow;
  const sub = (n) => K6().sub(n);
  const inputsOf = (inp) => ({ key: U.key(inp.key), iv: U.block(inp.iv), msg: S.bytes.utf8(String(inp.msg)) });
  const yR = 110, yE = 215, yKs = 280, yX = 320, yC = 430;
  const keyStub = (N, i, x) => { N.wire('k' + i, [[x + 82, yE], [x + 52, yE]], { head: true, cls: 'key' }); N.label('kl' + i, x + 70, yE - 10, 'k', 'key', 'middle', 15); };

  // ---- OFB ---------------------------------------------------------------------------------------------------
  function ofb(inp) {
    const { key, iv, msg } = inputsOf(inp), E = S.AES.cipher(key), M = S.Modes, F = new S.Frames(), box = (...a) => K6().box(...a);
    const res = M.encrypt('ofb', E, msg, { iv }), Pb = K6().blocks(msg), Cb = K6().blocks(res.out), n = Pb.length, CX = K6().cols(n);
    const regOf = (i) => (i ? res.steps[i - 1].ks : iv);
    const build = (blk, stage) => {
      const N = Fl().net('ofb'), later = [];
      for (let i = 0; i < n; i++) {
        const x = CX[i], cur = i === blk, done = i < blk || (cur && stage >= 1), st = res.steps[i];
        box(N, 'R' + i, x, yR, i ? 'register = keystream ' + i : 'register = IV', i <= blk || i === 0 ? regOf(i) : null, (i === 0 ? 'key' : '') + (cur && stage === 0 ? ' act' : ''));
        N.box('E' + i, x, yE, 104, 50, 'Eₖ', 'cipher' + (cur && stage === 0 ? ' act' : ''));
        N.op('x' + i, x, yX, 'xor', cur && stage === 1 ? 'act' : '');
        box(N, 'P' + i, x - 95, yX, 'P' + sub(i + 1), Pb[i], cur && stage === 1 ? 'act' : '', { quad: true });
        box(N, 'C' + i, x, yC, 'C' + sub(i + 1), done ? Cb[i] : null, done ? (cur ? 'hot' : '') : 'soft');
        const a = (k) => (cur && stage === k ? 'act' : '');
        N.wire('re' + i, [N.port('R' + i, 's'), N.port('E' + i, 'n')], { head: true, cls: a(0) });
        N.wire('ex' + i, [N.port('E' + i, 's'), N.port('x' + i, 'n')], { head: true, cls: a(0) || a(1) });
        N.wire('px' + i, [N.port('P' + i, 'e'), N.port('x' + i, 'w')], { head: true, cls: a(1) });
        N.wire('xc' + i, [N.port('x' + i, 's'), N.port('C' + i, 'n')], { head: true, cls: a(1) });
        keyStub(N, i, x);
        if (i < n - 1) later.push(() => { const on = i + 1 === blk && stage === 0; N.dot(x, yKs, on ? 'act' : ''); N.wire('fb' + i, [[x, yKs], [x + 100, yKs], [x + 100, 50], [CX[i + 1], 50], N.port('R' + (i + 1), 'n')], { head: true, cls: on ? 'act' : '' }); });
        if (i <= blk) N.chip('ks' + i, K6().short(st.ks), [x, (yE + 25 + yKs) / 2 - 2], cur ? 'act' : 'plain');
      }
      later.forEach((f) => f());
      return N.items;
    };
    F.add({ items: [...build(-1, 0), ...K6().readout([['key', U.hex(key)], ['IV', U.hex(iv), 'key'], ['message', U.asText(msg) || U.hex(msg)]], 'OFB')], say: `OFB makes a keystream by encrypting the IV, ${U.hex(iv)}, then encrypting the result, and so on. The ${msg.length}-byte message only meets the keystream at the XORs.`, facts: { iv, len: msg.length }, meta: { stage: 'start' } });
    for (let i = 0; i < n; i++) {
      const st = res.steps[i], nv = K6().follow(CX[i]);
      F.add({ items: [...build(i, 0), ...K6().readout([['register', U.hex(regOf(i)), i ? '' : 'key'], ['keystream ' + (i + 1), U.hex(st.ks), 'act']])], narrowView: nv, hl: { d: [0, 1] }, say: `Keystream block ${i + 1} = Eₖ(${i ? 'keystream block ' + i : 'IV'}) = Eₖ(${U.hex(regOf(i))}) = ${U.hex(st.ks)}.`, facts: { i: i + 1, j: i, reg: regOf(i), ks: st.ks }, meta: { stage: 'ks', i } });
      F.add({ items: [...build(i, 1), ...K6().readout([['P' + sub(i + 1), U.hex(st.in)], ['C' + sub(i + 1), U.hex(st.out), 'hot']])], narrowView: nv, hl: { d: [2] }, say: `C${sub(i + 1)} = P${sub(i + 1)} ⊕ keystream = ${U.hex(st.in)} ⊕ ${U.hex(st.ks.slice(0, st.in.length))} = ${U.hex(st.out)}.`, facts: { p: st.in, ks: st.ks.slice(0, st.in.length), c: st.out }, meta: { stage: 'xor', i } });
    }
    F.add({ items: [...build(n, 0), ...K6().readout([['ciphertext', U.hex(res.out), 'hot']])], say: `The ciphertext is ${K6().hexb(res.out)}. The keystream depends only on the key and the IV, so it can be made before the message arrives, and decryption is the same XOR. A flipped ciphertext bit flips just that plaintext bit; and reusing an IV repeats the whole keystream.`, facts: { C: res.out, Cb: K6().blocks(res.out) }, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('OFB', ['O₀ = IV', 'Oᵢ = Eₖ(Oᵢ₋₁)', 'Cᵢ = Pᵢ ⊕ Oᵢ  (decrypt: Pᵢ = Cᵢ ⊕ Oᵢ)', 'the keystream never depends on the data']) };
  }
  S.topic({
    id: 'modes-ofb', family: 'p06-modes', order: 40, title: 'OFB: output feedback',
    blurb: 'The block cipher is fed its own output, starting from the IV, to make a keystream; the data is XORed with it. The keystream never depends on the message.',
    inputs: [K6().msgInput('Lamps lit along the canal path', 48), K6().keyInput(), K6().ivInput()],
    presets: [
      { label: 'Two blocks', values: { msg: 'Lamps lit along the canal path' } },
      { label: 'Three full blocks', values: { msg: 'Ferns unfurl at dawn; the tide keeps its counsel' } },
      { label: 'SP 800-38A F.4.1 key and IV', values: { msg: 'one block, short', key: '2b7e151628aed2a6abf7158809cf4f3c', iv: '000102030405060708090a0b0c0d0e0f' } },
      { label: 'AES-192 key', values: { msg: 'Lamps lit along the canal path', key: 'a quiet orchard of 24 by' } },
    ],
    run: ofb,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'xor' && f.meta.i === 0, pick: 'option', options: ['keystream block 1', 'C₁', 'P₁', 'the IV again'], ask: 'What will the register hold for block 2?', answer: 'keystream block 1', explain: 'OFB feeds back the cipher output, not the ciphertext.' }],
    quiz: [
      { q: 'What is fed back in OFB?', options: ['The ciphertext', 'The block cipher output', 'The plaintext', 'A counter'], answer: 1, why: 'Output feedback: Oᵢ = Eₖ(Oᵢ₋₁).' },
      { q: 'A bit of the ciphertext flips in transit. What does the receiver see?', options: ['The whole block garbled', 'Only that bit flipped', 'Every later block garbled', 'An error'], answer: 1, why: 'Decryption is a plain XOR with a keystream that does not depend on the ciphertext.' },
      { q: 'Can the OFB keystream be computed in parallel?', options: ['Yes, any block at once', 'No, each block needs the one before', 'Only in decryption', 'Only with AES-256'], answer: 1, why: 'Each output is the encryption of the previous one, though it can be computed ahead of time.' },
      { q: 'Why must an OFB IV never repeat under one key?', options: ['It would give the same keystream, and C ⊕ C′ = P ⊕ P′', 'It would leak the key directly', 'Padding would fail', 'It is fine to repeat'], answer: 0, why: 'A repeated keystream is a two-time pad.' },
    ],
  });

  // ---- CTR ---------------------------------------------------------------------------------------------------
  function ctr(inp) {
    const { key, iv, msg } = inputsOf(inp), E = S.AES.cipher(key), M = S.Modes, F = new S.Frames(), box = (...a) => K6().box(...a);
    const res = M.encrypt('ctr', E, msg, { iv }), Pb = K6().blocks(msg), Cb = K6().blocks(res.out), n = Pb.length, CX = K6().cols(n);
    const build = (blk, stage, o) => {
      o = o || {};
      const N = Fl().net('ctr');
      for (let i = 0; i < n; i++) {
        const x = CX[i], st = res.steps[i], cur = i === blk || o.all, lit = o.only === undefined || o.only === i, done = o.all || i < blk || (i === blk && stage >= 1) || (o.only === i && stage >= 1);
        box(N, 'N' + i, x, yR, 'counter ' + (i === 0 ? '= start' : '= start + ' + i), st.ctr, (cur && stage === 0 ? 'act' : '') + (lit ? '' : ' soft'));
        N.box('E' + i, x, yE, 104, 50, 'Eₖ', 'cipher' + (cur && stage === 0 ? ' act' : '') + (lit ? '' : ' soft'));
        N.op('x' + i, x, yX, 'xor', cur && stage === 1 ? 'act' : '');
        box(N, 'P' + i, x - 95, yX, (o.dec ? 'C' : 'P') + sub(i + 1), o.dec ? Cb[i] : Pb[i], (cur && stage === 1 ? 'act' : '') + (lit ? '' : ' soft'), { quad: true });
        box(N, 'C' + i, x, yC, (o.dec ? 'P' : 'C') + sub(i + 1), done && lit ? (o.dec ? Pb[i] : Cb[i]) : null, done && lit ? (cur ? 'hot' : '') : 'soft');
        const a = (k) => (cur && stage === k ? 'act' : '');
        N.wire('n' + i, [N.port('N' + i, 's'), N.port('E' + i, 'n')], { head: true, cls: a(0) });
        N.wire('ks' + i, [N.port('E' + i, 's'), N.port('x' + i, 'n')], { head: true, cls: a(0) || a(1) });
        N.wire('p' + i, [N.port('P' + i, 'e'), N.port('x' + i, 'w')], { head: true, cls: a(1) });
        N.wire('c' + i, [N.port('x' + i, 's'), N.port('C' + i, 'n')], { head: true, cls: a(1) });
        keyStub(N, i, x);
        if ((i <= blk || o.all || o.only === i) && lit) N.chip('kc' + i, K6().short(st.ks), [x, (yE + 25 + yX - 11) / 2], cur ? 'act' : 'plain');
      }
      return N.items;
    };
    F.add({ items: [...build(-1, 0), ...K6().readout([['key', U.hex(key)], ['first counter', U.hex(iv), 'key'], ['message', U.asText(msg) || U.hex(msg)]], 'CTR')], say: `CTR encrypts counter blocks: the first is ${U.hex(iv)}, and each block adds one to it as a 128-bit number. The encrypted counters are the keystream. Nothing is chained.`, facts: { iv }, meta: { stage: 'start' } });
    for (let i = 0; i < n; i++) {
      const st = res.steps[i], nv = K6().follow(CX[i]);
      F.add({ items: [...build(i, 0), ...K6().readout([['counter', U.hex(st.ctr)], ['keystream', U.hex(st.ks), 'act']])], narrowView: nv, hl: { d: [0, 1] }, say: `Block ${i + 1}: Eₖ(${U.hex(st.ctr)}) = ${U.hex(st.ks)}.`, facts: { i: i + 1, ctr: st.ctr, ks: st.ks }, meta: { stage: 'ks', i } });
      F.add({ items: [...build(i, 1), ...K6().readout([['P' + sub(i + 1), U.hex(st.in)], ['C' + sub(i + 1), U.hex(st.out), 'hot']])], narrowView: nv, hl: { d: [2] }, say: `C${sub(i + 1)} = ${U.hex(st.in)} ⊕ ${U.hex(st.ks.slice(0, st.in.length))} = ${U.hex(st.out)}.${st.in.length < 16 ? ` The last block is ${st.in.length} bytes, so only ${st.in.length} keystream bytes are used: no padding.` : ''}`, facts: { p: st.in, ks: st.ks.slice(0, st.in.length), c: st.out, len: st.in.length }, meta: { stage: 'xor', i } });
    }
    F.add({ items: [...build(-1, 0, { all: true }), ...K6().readout([['ciphertext', U.hex(res.out), 'hot']])], hl: { d: [3] }, say: `No block waited for another: ${n === 1 ? 'with more blocks, every' : `all ${n}`} Eₖ calls could run at the same moment on separate cores, and the keystream could even be made before the message existed.`, facts: { n }, meta: { stage: 'parallel' } });
    const j = Math.min(n, Math.max(1, inp.jump)) - 1, sj = res.steps[j];
    F.add({ items: [...build(-1, 1, { only: j, dec: true }), ...K6().readout([['counter', U.hex(sj.ctr)], ['C' + sub(j + 1), U.hex(sj.out)], ['P' + sub(j + 1), U.hex(sj.in), 'hot']], 'decrypt one block alone')], narrowView: K6().follow(CX[j]), hl: { d: [3] }, say: `Random access: to read block ${j + 1} alone, compute its counter, start + ${j}, encrypt it and XOR: ${U.hex(sj.out)} ⊕ ${U.hex(sj.ks.slice(0, sj.out.length))} = ${U.hex(sj.in)}${U.asText(sj.in) ? ', ' + U.asText(sj.in) : ''}. The other blocks are never touched.`, facts: { j: j + 1, jj: j, c: sj.out, ks: sj.ks.slice(0, sj.out.length), p: sj.in }, meta: { stage: 'jump' } });
    const far = inp.far, cf = M.counter(iv, far), kf = E.encrypt(cf);
    F.add({ items: [...build(-1, 0, { only: -1 }), ...K6().readout([['block', String(far + 1)], ['counter', U.hex(cf), 'key'], ['keystream', U.hex(kf), 'act']], 'a block far away')], say: `The same works for block ${far + 1} of a huge file: its counter is start + ${far} = ${U.hex(cf)}, and its keystream ${U.hex(kf)}, in one call of Eₖ. The rule that pays for all this: never use a counter value twice under one key.`, facts: { far, b: far + 1, cf, kf }, meta: { stage: 'far' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('CTR', ['Tᵢ = T₁ + (i − 1) mod 2¹²⁸', 'Cᵢ = Pᵢ ⊕ Eₖ(Tᵢ)', 'Pᵢ = Cᵢ ⊕ Eₖ(Tᵢ): the same operation', 'blocks are independent: parallel, random access, no padding']) };
  }
  S.topic({
    id: 'modes-ctr', family: 'p06-modes', order: 50, title: 'CTR: counter mode',
    blurb: 'Encrypt a counter, XOR the result into the data. Every block stands alone: blocks can be computed in parallel, read in any order, and the last one needs no padding.',
    inputs: [K6().msgInput('Ferns unfurl at dawn; the tide keeps its counsel', 48), K6().keyInput(), K6().ivInput('5f1a7c3e9b2d4f600000000000000000', 'First counter block (16 characters or 32 hex digits)'),
      { id: 'jump', kind: 'number', label: 'Block to decrypt alone', def: 2, min: 1, max: 3 },
      { id: 'far', kind: 'number', label: 'A far block index', def: 999999, min: 3, max: 4294967295 }],
    presets: [
      { label: 'Three blocks', values: { msg: 'Ferns unfurl at dawn; the tide keeps its counsel', jump: 2, far: 999999 } },
      { label: 'A short last block, no padding', values: { msg: 'Meet by the old mill at nine', jump: 2, far: 1000 } },
      { label: 'SP 800-38A F.5.1 key and counter', values: { msg: 'counter mode, one block', key: '2b7e151628aed2a6abf7158809cf4f3c', iv: 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', jump: 1, far: 65535 } },
      { label: 'A counter that carries', values: { msg: 'carry the one', iv: '000000000000000000000000ffffffff', jump: 1, far: 4294967295 } },
    ],
    run: ctr,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'start', pick: 'option', options: ['Eₖ', 'Dₖ', 'both'], ask: 'To decrypt CTR, does the receiver run Eₖ or Dₖ on the counters?', answer: 'Eₖ', explain: 'The receiver rebuilds the same keystream Eₖ(Tᵢ) and XORs it off.' }],
    quiz: [
      { q: 'Why can CTR decrypt block 1000 without touching blocks 1 to 999?', options: ['It caches them', 'Its keystream depends only on the key and counter 1000', 'It cannot', 'Blocks are stored in reverse'], answer: 1, why: 'Tᵢ is computed directly from the starting counter.' },
      { q: 'What happens if two messages use the same counter values under one key?', options: ['Nothing', 'Their keystreams repeat, so C ⊕ C′ = P ⊕ P′', 'The key is revealed at once', 'Decryption fails'], answer: 1, why: 'It is a two-time pad.' },
      { q: 'Does CTR need padding?', options: ['Yes', 'No', 'Only for AES-256', 'Only when encrypting'], answer: 1, why: 'Only as many keystream bytes as needed are used.' },
      { q: 'Which part of the block cipher does CTR use?', options: ['Only encryption', 'Only decryption', 'Both', 'Neither'], answer: 0, why: 'Both directions use Eₖ on the counters.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
