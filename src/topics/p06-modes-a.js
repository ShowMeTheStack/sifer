// Part 6, the chained modes: CBC (each plaintext block XORed with the ciphertext before it, then encrypted; and
// decryption, where one damaged ciphertext block spoils two plaintext blocks), and CFB (the cipher run on the last
// ciphertext to make a keystream), with CFB8's byte-wide shift register.
(function (S) {
  'use strict';
  const U = S.P5, K6 = () => S.Kit.p06, Fl = () => S.Kit.flow;
  const sub = (n) => K6().sub(n);
  const keyStub = (N, x, y, cls) => { N.wire('k' + x, [[x - 82, y], [x - 52, y]], { head: true, cls: 'key' }); N.label('kl' + x, x - 88, y + 5, 'k', 'key', 'end', 15); };
  /** a readout panel at the bottom: rows [label, hex, cls] */
  const readout = (rows, title) => K6().readout(rows, title), colsFor = (n) => K6().cols(n);
  const inputsOf = (inp) => ({ key: U.key(inp.key), iv: U.block(inp.iv), msg: S.bytes.utf8(String(inp.msg)) });

  // ---- CBC ---------------------------------------------------------------------------------------------------
  function cbc(inp) {
    const { key, iv, msg } = inputsOf(inp), E = S.AES.cipher(key), M = S.Modes, dec = inp.dir === 'dec';
    const padded = M.pkcs7(msg, 16), padN = padded.length - msg.length, n = padded.length / 16;
    const enc = M.encrypt('cbc', E, padded, { iv }), C = enc.out, Pb = K6().blocks(padded), Cb = K6().blocks(C);
    const F = new S.Frames(), box = (...a) => K6().box(...a), CX = colsFor(n);
    const nm = (k, i) => k + sub(i + 1);
    if (!dec) {
      const yP = 110, yX = 200, yE = 280, yT = 340, yC = 430;
      const build = (blk, stage) => {
        const N = Fl().net('cbc'), later = [];
        box(N, 'iv', CX[0] - 125, yX, 'IV', iv, 'key' + (blk === 0 && stage === 0 ? ' act' : ''), { quad: true });
        for (let i = 0; i < n; i++) {
          const x = CX[i], cur = i === blk, done = i < blk || (cur && stage >= 2);
          box(N, 'P' + i, x, yP, nm('P', i) + (i === n - 1 && padN ? '  + padding' : ''), Pb[i], cur && stage === 0 ? 'act' : '');
          N.op('x' + i, x, yX, 'xor', cur && stage === 0 ? 'act' : '');
          N.box('E' + i, x, yE, 104, 50, 'Eₖ', 'cipher' + (cur && stage === 1 ? ' act' : ''));
          box(N, 'C' + i, x, yC, nm('C', i), done ? Cb[i] : null, done ? (cur ? 'hot' : '') : 'soft');
          const a = (k) => (cur && stage === k ? 'act' : '');
          N.wire('p' + i, [N.port('P' + i, 's'), N.port('x' + i, 'n')], { head: true, cls: a(0) });
          N.wire('xe' + i, [N.port('x' + i, 's'), N.port('E' + i, 'n')], { head: true, cls: a(1) });
          N.wire('ec' + i, [N.port('E' + i, 's'), N.port('C' + i, 'n')], { head: true, cls: a(2) });
          keyStub(N, x, yE);
          later.push(() => { if (i < n - 1) { const on = i + 1 === blk && stage === 0; N.dot(x, yT, on ? 'act' : ''); N.wire('ch' + i, [[x, yT], [x + 100, yT], [x + 100, yX], N.port('x' + (i + 1), 'w')], { head: true, cls: on ? 'act' : '' }); } });
        }
        later.forEach((f) => f());
        N.wire('ivw', [N.port('iv', 'e'), N.port('x0', 'w')], { head: true, cls: blk === 0 && stage === 0 ? 'act' : '' });
        if (blk >= 0 && blk < n) {
          const st = enc.steps[blk], x = CX[blk];
          if (stage === 1) N.chip('x', K6().short(st.x), [x, (yX + 11 + yE - 25) / 2], 'act');
          if (stage === 2) N.chip('c', K6().short(st.c), [x, yT + 30], 'hot');
        }
        return N.items;
      };
      F.add({ items: [...build(-1, 0), ...readout([['key', U.hex(key)], ['IV', U.hex(iv)], ['message', U.asText(msg) || U.hex(msg)]], 'CBC encryption')], say: `The message is ${msg.length} bytes; PKCS#7 padding adds ${padN} byte${padN > 1 ? 's' : ''} of value ${U.h2(padN)}, making ${n} block${n > 1 ? 's' : ''} of 16. The IV, ${U.hex(iv)}, must be unpredictable and fresh for every message.`, facts: { len: msg.length, padN, n, iv }, meta: { stage: 'start' } });
      for (let i = 0; i < n; i++) {
        const st = enc.steps[i], nv = K6().follow(CX[i]);
        F.add({ items: [...build(i, 0), ...readout([[nm('P', i), U.hex(st.p)], [i ? nm('C', i - 1) : 'IV', U.hex(st.prev), 'key'], ['⊕', U.hex(st.x), 'act']])], narrowView: nv, hl: { d: [0] }, say: `Block ${i + 1}: ${nm('P', i)} = ${U.hex(st.p)} is XORed with ${i ? nm('C', i - 1) + ', the ciphertext just made' : 'the IV'}, ${U.hex(st.prev)}, giving ${U.hex(st.x)}.`, facts: { i: i + 1, p: st.p, prev: st.prev, x: st.x }, meta: { stage: 'xor', i } });
        F.add({ items: [...build(i, 1), ...readout([['Eₖ input', U.hex(st.x), 'act'], ['Eₖ output', U.hex(st.c), 'hot']])], narrowView: nv, hl: { d: [0] }, say: `The block cipher encrypts that XOR, never the plaintext itself: Eₖ(${U.hex(st.x)}) = ${U.hex(st.c)}.`, facts: { x: st.x, c: st.c }, meta: { stage: 'enc', i } });
        F.add({ items: [...build(i, 2), ...readout([[nm('C', i), U.hex(st.c), 'hot']])], narrowView: nv, say: `${nm('C', i)} = ${U.hex(st.c)}.${i < n - 1 ? ` It goes out, and it is also what block ${i + 2} is XORed with.` : ''}`, facts: { i: i + 1, c: st.c, j: i + 2 }, meta: { stage: 'out', i } });
      }
      F.add({ items: [...build(n, 0), ...readout([['ciphertext', U.hex(C), 'hot']])], say: `The ciphertext is ${K6().hexb(C)}. Encryption is a chain: block ${n} cannot start before block ${Math.max(1, n - 1)} is done. Two equal plaintext blocks give different ciphertext blocks, because what they are XORed with differs.`, facts: { C, Cb: K6().blocks(C), n, m: Math.max(1, n - 1) }, meta: { stage: 'end' } });
    } else {
      const yC = 110, yT = 165, yD = 215, yX = 320, yP = 430;
      const flip = inp.flip === 'none' ? -1 : +inp.flip;
      const Cx = Uint8Array.from(C); if (flip >= 0) Cx[flip] ^= 1;
      const d = M.decrypt('cbc', E, C, { iv }), dx = M.decrypt('cbc', E, Cx, { iv });
      const build = (blk, stage, bad) => {
        const N = Fl().net('cbcd'), later = [], steps = bad ? dx.steps : d.steps, CC = K6().blocks(bad ? Cx : C);
        box(N, 'iv', CX[0] - 125, yX, 'IV', iv, 'key', { quad: true });
        for (let i = 0; i < n; i++) {
          const x = CX[i], cur = i === blk, done = blk === n || i < blk || (cur && stage >= 1);
          box(N, 'C' + i, x, yC, nm('C', i) + (bad && i === 0 ? '  (1 bit flipped)' : ''), CC[i], cur && stage === 0 ? 'act' : bad && i === 0 ? 'key' : '');
          N.box('D' + i, x, yD, 104, 50, 'Dₖ', 'cipher' + (cur && stage === 0 ? ' act' : ''));
          N.op('x' + i, x, yX, 'xor', cur && stage === 1 ? 'act' : '');
          const pbad = bad && i < 2;
          box(N, 'P' + i, x, yP, nm('P', i), done ? steps[i].p : null, done ? (pbad ? 'hot' : cur ? 'hot' : '') : 'soft');
          const a = (k) => (cur && stage === k ? 'act' : '');
          N.wire('cd' + i, [N.port('C' + i, 's'), N.port('D' + i, 'n')], { head: true, cls: a(0) });
          N.wire('dx' + i, [N.port('D' + i, 's'), N.port('x' + i, 'n')], { head: true, cls: a(1) });
          N.wire('xp' + i, [N.port('x' + i, 's'), N.port('P' + i, 'n')], { head: true, cls: a(1) });
          keyStub(N, x, yD);
          later.push(() => { if (i < n - 1) { const on = i + 1 === blk && stage === 1; N.dot(x, yT, on ? 'act' : ''); N.wire('ch' + i, [[x, yT], [x + 100, yT], [x + 100, yX], N.port('x' + (i + 1), 'w')], { head: true, cls: on ? 'act' : '' }); } });
        }
        later.forEach((f) => f());
        N.wire('ivw', [N.port('iv', 'e'), N.port('x0', 'w')], { head: true, cls: blk === 0 && stage === 1 ? 'act' : '' });
        if (blk >= 0 && blk < n && stage === 0) N.chip('d', K6().short(steps[blk].x), [CX[blk], (yD + 25 + yX - 11) / 2], 'act');
        return N.items;
      };
      F.add({ items: [...build(-1, 0), ...readout([['key', U.hex(key)], ['IV', U.hex(iv)], ['ciphertext', U.hex(C)]], 'CBC decryption')], say: `To decrypt, the receiver has the ${n} ciphertext block${n > 1 ? 's' : ''}, the key and the IV, ${U.hex(iv)}. Each block goes through Dₖ, then is XORed with the ciphertext block before it.`, facts: { n, iv, C }, meta: { stage: 'start' } });
      for (let i = 0; i < n; i++) {
        const st = d.steps[i], nv = K6().follow(CX[i]);
        F.add({ items: [...build(i, 0), ...readout([[nm('C', i), U.hex(st.c)], ['Dₖ output', U.hex(st.x), 'act']])], narrowView: nv, hl: { d: [1] }, say: `Block ${i + 1}: Dₖ(${U.hex(st.c)}) = ${U.hex(st.x)}. This is still masked by what was XORed in before encryption.`, facts: { i: i + 1, c: st.c, x: st.x }, meta: { stage: 'dec', i } });
        F.add({ items: [...build(i, 1), ...readout([['Dₖ output', U.hex(st.x), 'act'], [i ? nm('C', i - 1) : 'IV', U.hex(st.prev), 'key'], [nm('P', i), U.hex(st.p), 'hot']])], narrowView: nv, hl: { d: [1] }, say: `XOR with ${i ? nm('C', i - 1) : 'the IV'}, ${U.hex(st.prev)}: ${nm('P', i)} = ${U.hex(st.p)}${U.asText(st.p) ? ', ' + U.asText(st.p) : ''}.`, facts: { prev: st.prev, p: st.p }, meta: { stage: 'xor', i } });
      }
      const un = M.unpkcs7(d.out, 16);
      F.add({ items: [...build(n, 1), ...readout([['padded', U.hex(d.out)], ['message', U.asText(un) || U.hex(un), 'hot']])], say: `The last byte, ${U.h2(d.out[d.out.length - 1])}, says how many padding bytes to strip. Every block could be decrypted at once: all the ciphertext blocks it needs are already there.`, facts: { last: d.out[d.out.length - 1], P: d.out }, meta: { stage: 'unpad' } });
      if (flip >= 0) {
        const p0 = d.steps[0].p, q0 = dx.steps[0].p, nBad0 = p0.filter((v, k) => v !== q0[k]).length;
        const rows = [['P₁ was', U.hex(p0)], ['P₁ now', U.hex(q0), 'hot']];
        let say = `Now flip one bit of C₁, in byte ${flip}. P₁ comes out as ${U.hex(q0)}: ${nBad0} of its 16 bytes are wrong, since Dₖ scrambles the whole block.`;
        const facts = { flip, q0, nBad0 };
        if (n > 1) { const p1 = d.steps[1].p, q1 = dx.steps[1].p, diff = p1.map((v, k) => v ^ q1[k]), at = diff.findIndex((v) => v); rows.push(['P₂ now', U.hex(q1), 'hot']); say += ` P₂ has exactly one bit flipped, in byte ${at}, the same place: ${U.h2(p1[at])} became ${U.h2(q1[at])}.${n > 2 ? ' P₃ and later blocks are untouched.' : ''}`; Object.assign(facts, { at, a: p1[at], b: q1[at] }); }
        F.add({ items: [...build(n, 1, true), ...readout(rows, 'one bit of C₁ flipped')], hl: { d: [2] }, say, facts, meta: { stage: 'error' } });
      }
    }
    U.fix(F.list);
    return { frames: F.list, def: U.def('CBC', ['C₀ = IV', 'Cᵢ = Eₖ(Pᵢ ⊕ Cᵢ₋₁)', 'Pᵢ = Dₖ(Cᵢ) ⊕ Cᵢ₋₁', 'a flipped bit in Cᵢ garbles Pᵢ and flips the same bit of Pᵢ₊₁']) };
  }
  S.topic({
    id: 'modes-cbc', family: 'p06-modes', order: 20, title: 'CBC: cipher block chaining',
    blurb: 'Each plaintext block is XORed with the previous ciphertext block (the IV for the first) before it is encrypted, so equal blocks no longer look equal. Decryption runs the chain backwards.',
    inputs: [K6().msgInput('Ferns unfurl at dawn; the tide keeps counsel', 47), K6().keyInput(), K6().ivInput(),
      { id: 'dir', kind: 'choice', label: 'Direction', def: 'enc', options: [{ value: 'enc', label: 'encrypt' }, { value: 'dec', label: 'decrypt' }] },
      { id: 'flip', kind: 'choice', label: 'When decrypting, flip a bit of C₁', def: 'none', options: [{ value: 'none', label: 'no' }, { value: '0', label: 'in byte 0' }, { value: '7', label: 'in byte 7' }, { value: '15', label: 'in byte 15' }] }],
    presets: [
      { label: 'Encrypt three blocks', values: { msg: 'Ferns unfurl at dawn; the tide keeps counsel', dir: 'enc', flip: 'none' } },
      { label: 'Equal blocks, different ciphertext', values: { msg: 'NORTH GATE OPEN.NORTH GATE OPEN.', dir: 'enc', flip: 'none' } },
      { label: 'Decrypt', values: { msg: 'Ferns unfurl at dawn; the tide keeps counsel', dir: 'dec', flip: 'none' } },
      { label: 'Decrypt with a flipped bit in C₁', values: { msg: 'Ferns unfurl at dawn; the tide keeps counsel', dir: 'dec', flip: '7' } },
      { label: 'AES-256, one short block', values: { msg: 'tea at four', key: 'thirty-two bytes of copper wire!', dir: 'enc', flip: 'none' } },
    ],
    run: cbc,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'start' && !f.facts.C, once: true, pick: 'option', options: ['the IV', 'the key', 'P₁', 'nothing'], ask: 'What is P₁ XORed with before it is encrypted?', answer: 'the IV', explain: 'The first block has no ciphertext before it, so the IV takes that place.' },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta && fr[i + 1].meta.stage === 'error', pick: 'option', options: ['only P₁', 'P₁ and P₂', 'every block after C₁', 'none'], ask: 'One bit of C₁ is about to flip. Which plaintext blocks come out wrong?', answer: 'P₁ and P₂', explain: 'C₁ goes into Dₖ for P₁ (all scrambled) and is XORed into P₂ (one bit flipped); P₃ uses C₂ only.' },
    ],
    quiz: [
      { q: 'Why does CBC need an IV?', options: ['To pad the message', 'So the first block is randomised and the same message encrypts differently each time', 'To make decryption faster', 'It holds the key'], answer: 1, why: 'Without a fresh unpredictable IV, equal first blocks would give equal ciphertexts.' },
      { q: 'Which direction of CBC can run in parallel?', options: ['Encryption', 'Decryption', 'Both', 'Neither'], answer: 1, why: 'Decryption needs only ciphertext blocks, which are all known; encryption needs the previous result.' },
      { q: 'A bit of Cᵢ flips in transit. What happens?', options: ['Only Pᵢ is garbled', 'Pᵢ is garbled and the same bit of Pᵢ₊₁ flips', 'Every later block is garbled', 'Nothing'], answer: 1, why: 'This controlled flip in Pᵢ₊₁ is what CBC bit-flipping attacks exploit.' },
      { q: 'Why must the last block be padded in CBC?', options: ['Eₖ only takes whole 16-byte blocks', 'For integrity', 'To hide the length exactly', 'It need not be'], answer: 0, why: 'The block cipher works on whole blocks; padding (or ciphertext stealing) fills the last one.' },
    ],
  });

  // ---- CFB and CFB8 ---------------------------------------------------------------------------------------------
  function cfb(inp) {
    const { key, iv, msg } = inputsOf(inp), E = S.AES.cipher(key), M = S.Modes, F = new S.Frames(), box = (...a) => K6().box(...a);
    if (inp.mode === 'cfb') {
      const res = M.encrypt('cfb', E, msg, { iv }), Pb = K6().blocks(msg), Cb = K6().blocks(res.out), n = Pb.length, CX = colsFor(n);
      const yR = 110, yE = 215, yX = 320, yTap = 380, yC = 430;
      const build = (blk, stage) => {
        const N = Fl().net('cfb'), later = [];
        for (let i = 0; i < n; i++) {
          const x = CX[i], cur = i === blk, done = i < blk || (cur && stage >= 1), st = res.steps[i];
          box(N, 'R' + i, x, yR, i ? 'register = ' + 'C' + sub(i) : 'register = IV', i <= blk ? st.reg : i === 0 ? iv : null, (i === 0 ? 'key' : '') + (cur && stage === 0 ? ' act' : ''));
          N.box('E' + i, x, yE, 104, 50, 'Eₖ', 'cipher' + (cur && stage === 0 ? ' act' : ''));
          N.op('x' + i, x, yX, 'xor', cur && stage === 1 ? 'act' : '');
          box(N, 'P' + i, x - 95, yX, 'P' + sub(i + 1), Pb[i], cur && stage === 1 ? 'act' : '', { quad: true });
          box(N, 'C' + i, x, yC, 'C' + sub(i + 1), done ? Cb[i] : null, done ? (cur ? 'hot' : '') : 'soft');
          const a = (k) => (cur && stage === k ? 'act' : '');
          N.wire('re' + i, [N.port('R' + i, 's'), N.port('E' + i, 'n')], { head: true, cls: a(0) });
          N.wire('ex' + i, [N.port('E' + i, 's'), N.port('x' + i, 'n')], { head: true, cls: a(0) || a(1) });
          N.wire('px' + i, [N.port('P' + i, 'e'), N.port('x' + i, 'w')], { head: true, cls: a(1) });
          N.wire('xc' + i, [N.port('x' + i, 's'), N.port('C' + i, 'n')], { head: true, cls: a(1) });
          N.wire('k' + i, [[x + 82, yE], [x + 52, yE]], { head: true, cls: 'key' }); N.label('kl' + i, x + 70, yE - 10, 'k', 'key', 'middle', 15);
          later.push(() => { if (i < n - 1) { const on = i + 1 === blk && stage === 0; N.dot(x, yTap, on ? 'act' : ''); N.wire('fb' + i, [[x, yTap], [x + 100, yTap], [x + 100, 50], [CX[i + 1], 50], N.port('R' + (i + 1), 'n')], { head: true, cls: on ? 'act' : '' }); } });
          if (i <= blk) N.chip('ks' + i, K6().short(st.ks), [x, (yE + 25 + yX - 11) / 2], cur ? 'act' : 'plain');
        }
        later.forEach((f) => f());
        return N.items;
      };
      F.add({ items: [...build(-1, 0), ...readout([['key', U.hex(key)], ['IV', U.hex(iv), 'key'], ['message', U.asText(msg) || U.hex(msg)]], 'CFB, full-block segments')], say: `CFB turns the block cipher into a self-synchronising stream cipher. The register starts as the IV, ${U.hex(iv)}; the ${msg.length}-byte message needs no padding.`, facts: { iv, len: msg.length }, meta: { stage: 'start' } });
      for (let i = 0; i < n; i++) {
        const st = res.steps[i], nv = K6().follow(CX[i]);
        F.add({ items: [...build(i, 0), ...readout([['register', U.hex(st.reg), i ? '' : 'key'], ['Eₖ(register)', U.hex(st.ks), 'act']])], narrowView: nv, hl: { d: [0] }, say: `Block ${i + 1}: the register holds ${i ? 'C' + sub(i) + ', the last ciphertext block' : 'the IV'}, ${U.hex(st.reg)}. Encrypting it gives the keystream ${U.hex(st.ks)}.`, facts: { i: i + 1, reg: st.reg, ks: st.ks }, meta: { stage: 'ks', i } });
        F.add({ items: [...build(i, 1), ...readout([['P' + sub(i + 1), U.hex(st.in)], ['C' + sub(i + 1), U.hex(st.out), 'hot']])], narrowView: nv, hl: { d: [1] }, say: `C${sub(i + 1)} = P${sub(i + 1)} ⊕ keystream = ${U.hex(st.in)} ⊕ ${U.hex(st.ks.slice(0, st.in.length))} = ${U.hex(st.out)}.${i < n - 1 ? ' That ciphertext becomes the next register.' : st.in.length < 16 ? ' A short last block just uses part of the keystream.' : ''}`, facts: { p: st.in, ks: st.ks.slice(0, st.in.length), c: st.out }, meta: { stage: 'xor', i } });
      }
      F.add({ items: [...build(n, 0), ...readout([['ciphertext', U.hex(res.out), 'hot']])], say: `The ciphertext, ${K6().hexb(res.out)}, is exactly as long as the message. Decryption runs Eₖ too, never Dₖ, on the ciphertext it receives, so it can decrypt all blocks at once; encryption must go in order.`, facts: { C: res.out, Cb: K6().blocks(res.out) }, meta: { stage: 'end' } });
    } else {
      const res = M.encrypt('cfb8', E, msg, { iv }), n = Math.min(msg.length, 6);
      const RX = 150, RY = 100, CWr = 38, OY = 300, EX = RX + 12 * (CWr + 2) + CWr / 2;
      const regAt = (st) => st.reg;
      const build = (i, stage) => {
        const st = res.steps[i], N = Fl().net('c8'), items = [];
        items.push(U.t('c8:rt', RX, RY - 12, i === 0 ? 'register = IV' : `register: IV shifted ${i} byte${i > 1 ? 's' : ''}, ciphertext in`, 'title'));
        items.push(...U.cells('c8:r', RX, RY, regAt(st), { cw: CWr, ch: 32, gap: 2, size: 14, cls: (k) => (k >= 16 - i ? 'hot' : 'key') }));
        N.box('E', EX, 200, 104, 50, 'Eₖ', 'cipher' + (stage === 0 ? ' act' : ''));
        N.wire('re', [[EX, RY + 32 + 4], N.port('E', 'n')], { head: true, cls: stage === 0 ? 'act' : '' });
        items.push(U.t('c8:ot', RX, OY - 12, 'Eₖ(register): only its first byte is used', 'title'));
        const ob = E.encrypt(st.reg);
        items.push(...U.cells('c8:o', RX, OY, ob, { cw: CWr, ch: 32, gap: 2, size: 14, cls: (k) => (k === 0 ? 'act' : 'soft') }));
        N.wire('eo', [N.port('E', 's'), [EX, OY - 4]], { head: true, cls: stage === 0 ? 'act' : '' });
        const ox = RX + CWr / 2;
        N.op('x', ox, 420, 'xor', stage === 1 ? 'act' : '');
        N.wire('ox', [[ox, OY + 36], N.port('x', 'n')], { head: true, cls: 'act' });
        N.box('p', ox - 90, 420, 56, 36, U.h2(st.in), 'val' + (stage === 1 ? ' act' : ''));
        N.label('pl', ox - 90, 392, 'P byte ' + (i + 1), 'strong', 'middle', 13);
        N.wire('px', [N.port('p', 'e'), N.port('x', 'w')], { head: true });
        N.box('c', ox, 500, 56, 36, stage >= 1 ? U.h2(st.out) : '', 'val' + (stage >= 1 ? ' hot' : ' soft'));
        N.wire('xc', [N.port('x', 's'), N.port('c', 'n')], { head: true, cls: stage === 1 ? 'act' : '' });
        // the feedback: the ciphertext byte shifts into the right end of the register
        N.wire('fb', [N.port('c', 'e'), [RX + 16 * (CWr + 2) + 30, 500], [RX + 16 * (CWr + 2) + 30, RY + 16], [RX + 16 * (CWr + 2) + 2, RY + 16]], { head: true, cls: stage === 1 ? 'hot' : '' });
        N.label('fbl', RX + 16 * (CWr + 2) + 38, 300, 'shift in', 'hot', 'start', 13);
        items.push(U.t('c8:st', 250, 560, 'ciphertext so far', 'title'));
        items.push(...U.cells('c8:s', 250, 572, res.out.slice(0, i + (stage >= 1 ? 1 : 0)), { cw: 40, ch: 30, gap: 3, size: 14, cls: (k) => (k === i ? 'hot' : '') }));
        return items.concat(N.items);
      };
      F.add({ items: build(0, 0), say: `CFB8 feeds back one byte at a time. The 16-byte register starts as the IV, ${U.hex(iv)}. For each message byte the whole block is encrypted, and only its first byte is used.`, facts: { iv }, meta: { stage: 'start' } });
      for (let i = 0; i < n; i++) {
        const st = res.steps[i];
        if (i) F.add({ items: build(i, 0), hl: { d: [2] }, say: `Byte ${i + 1}: the register has shifted one byte left and taken in the last ciphertext byte, ${U.h2(res.out[i - 1])}. The first byte of Eₖ(register) is ${U.h2(st.ks)}.`, facts: { i: i + 1, c: res.out[i - 1], ks: st.ks }, meta: { stage: 'ks', i } });
        F.add({ items: build(i, 1), hl: { d: [2] }, say: `${U.h2(st.in)}${st.in >= 32 && st.in < 127 ? ' (“' + String.fromCharCode(st.in) + '”)' : ''} ⊕ ${U.h2(st.ks)} = ${U.h2(st.out)}: one ciphertext byte, which now shifts into the register.`, facts: { p: st.in, ks: st.ks, c: st.out }, meta: { stage: 'xor', i } });
      }
      F.add({ items: build(n - 1, 1), say: `So it goes for all ${msg.length} bytes: ${K6().hexb(res.out)}. One call of Eₖ per byte makes CFB8 sixteen times slower than full-block CFB, but a lost or garbled byte disturbs only the next 16 bytes, after which the register is clean again.`, facts: { len: msg.length, C: res.out, Cb: K6().blocks(res.out) }, meta: { stage: 'end' } });
    }
    U.fix(F.list);
    return { frames: F.list, def: U.def(inp.mode === 'cfb' ? 'CFB' : 'CFB8', inp.mode === 'cfb' ? ['register₁ = IV', 'Cᵢ = Pᵢ ⊕ Eₖ(registerᵢ)', 'registerᵢ₊₁ = Cᵢ', 'decrypt: Pᵢ = Cᵢ ⊕ Eₖ(Cᵢ₋₁): Eₖ only, never Dₖ'] : ['register = IV (16 bytes)', 'cᵢ = pᵢ ⊕ first byte of Eₖ(register)', 'register ← register shifted left one byte, with cᵢ at the end', 'one Eₖ per byte; recovers after 16 good bytes']) };
  }
  S.topic({
    id: 'modes-cfb', family: 'p06-modes', order: 30, title: 'CFB and CFB8: ciphertext feedback',
    blurb: 'The cipher encrypts the last ciphertext to make the next piece of keystream. Full-block CFB feeds back whole blocks; CFB8 shifts one byte at a time through a register.',
    inputs: [K6().msgInput('Kites over the salt flats', 48), K6().keyInput(), K6().ivInput(),
      { id: 'mode', kind: 'choice', label: 'Segment size', def: 'cfb', options: [{ value: 'cfb', label: 'CFB (128-bit segments)' }, { value: 'cfb8', label: 'CFB8 (8-bit segments)' }] }],
    presets: [
      { label: 'CFB, a short message', values: { msg: 'Kites over the salt flats', mode: 'cfb' } },
      { label: 'CFB, three full blocks', values: { msg: 'Ferns unfurl at dawn; the tide keeps its counsel', mode: 'cfb' } },
      { label: 'CFB8, byte by byte', values: { msg: 'Kites over the salt flats', mode: 'cfb8' } },
      { label: 'SP 800-38A F.3.13 key and IV (CFB128)', values: { msg: 'six bytes', key: '2b7e151628aed2a6abf7158809cf4f3c', iv: '000102030405060708090a0b0c0d0e0f', mode: 'cfb' } },
    ],
    run: cfb,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'start', pick: 'option', options: ['Eₖ', 'Dₖ', 'both'], ask: 'To decrypt CFB, which direction of the block cipher does the receiver use?', answer: 'Eₖ', explain: 'The receiver rebuilds the same keystream by encrypting the register, and XORs it off.' }],
    quiz: [
      { q: 'What goes into the register for the next segment in CFB?', options: ['The plaintext', 'The ciphertext just produced', 'The keystream', 'The key'], answer: 1, why: 'Ciphertext feedback gives the mode its name.' },
      { q: 'Does CFB need padding?', options: ['Yes, always', 'No: the last segment uses only part of the keystream', 'Only CFB8 does', 'Only for AES-256'], answer: 1, why: 'Like any stream mode, the ciphertext is exactly as long as the plaintext.' },
      { q: 'How many block-cipher calls does CFB8 make for a 32-byte message?', options: ['2', '16', '32', '256'], answer: 2, why: 'One call per byte, using one byte of each output.' },
      { q: 'Why is CFB called self-synchronising?', options: ['It needs no key', 'After a lost or wrong segment, the register refills with good ciphertext and decryption recovers', 'It carries a clock', 'The IV repeats'], answer: 1, why: 'The register holds only the most recent ciphertext.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
