// Part 5, the key schedule: AES-128's words made one at a time (RotWord, SubWord and the round constant in the
// g-function every fourth word, a plain XOR otherwise), and the wider schedules of AES-192 and AES-256.
(function (S) {
  'use strict';
  const U = S.P5, A = () => S.AES;
  const Fk = () => S.Kit.flow;

  // ---- AES-128 key expansion ----------------------------------------------------------------------------------
  function keyExp(inp) {
    const K = U.key(inp.key, [16]), ex = A().expandKey(K), w = ex.w, F = new S.Frames();
    // the strip: 44 words as columns of four bytes, round keys 0-5 on the first row, 6-10 on the second
    const CW = 30, CH = 20, WG = 2, GG = 10;
    const at = (i) => { const rk = Math.floor(i / 4), row = rk < 6 ? 0 : 1, g = row ? rk - 6 : rk, j = i % 4; return { x: 30 + g * (4 * (CW + WG) + GG) + j * (CW + WG), y: row ? 196 : 52 }; };
    const strip = (upto, src, dst) => {
      const items = [];
      for (let i = 0; i < 44; i++) {
        const p = at(i), on = i <= upto;
        for (let b = 0; b < 4; b++) items.push({ key: `ke:${i}:${b}`, kind: 'cell', x: p.x, y: p.y + b * (CH + 2), w: CW, h: CH, rx: 2, text: on ? U.h2(w[i][b]) : '', size: 13, cls: 'hex ' + (!on ? 'soft' : dst === i ? 'hot' : src.includes(i) ? 'act' : i < 4 ? 'key' : '') });
      }
      for (let k = 0; k <= 10; k++) { const p = at(4 * k); items.push(U.t('ke:rk' + k, p.x + 2 * (CW + WG) - WG / 2, p.y + 4 * (CH + 2) + 16, 'rk ' + k, 4 * k + 3 <= upto ? 'strong' : 'tick', 'middle', 13)); }
      items.push(U.t('ke:t', 30, 38, '44 words, w0 … w43, as columns of four bytes; four words make a round key', 'title'));
      return items;
    };
    // Rcon: x^(j−1) in GF(2^8), a chain of xtime
    const rcons = A().RCON;
    const rconRow = (lit) => [U.t('ke:rct', 30, 326, 'Rcon', lit >= 0 ? 'key' : 'tick', 'start', 14), ...U.cells('ke:rc', 80, 308, rcons, { cw: 36, ch: 26, gap: 4, size: 14, cls: (j) => (j === lit ? 'keyhot' : j < lit ? 'key' : 'soft') }), U.t('ke:rcn', 490, 326, 'each one is 02 times the one before', 'tick', 'start', 14)];
    // the lane: the computation of word i
    const LY = 360, LCW = 54, LCH = 26, H = 4 * (LCH + 2) - 2, MY = LY + H / 2, BY = LY + H + 26;
    const colAt = (key, x, y, bytes, cls, title, tcls) => [U.t(key + ':t', x + LCW / 2, y - 9, title, tcls || 'strong', 'middle', 13), ...bytes.map((v, b) => ({ key: key + ':' + b, kind: 'cell', x, y: y + b * (LCH + 2), w: LCW, h: LCH, rx: 3, text: v === null ? '' : U.h2(v), size: 14, cls: 'hex ' + (cls || '') }))];
    const XS = [40, 172, 304, 450, 520, 650, 740];
    const lane = (i, stage) => {
      const N = Fk().net('kl'), items = [];
      const arrow = (k, xa, xb, label) => { N.wire('a' + k, [[xa + 4, MY], [xb - 4, MY]], { head: true }); if (label) N.label('al' + k, (xa + xb) / 2, MY - 10, label, 'act', 'middle', 13); };
      if (i % 4 === 0) {
        const g = A().g(w[i - 1], i);
        items.push(...colAt('kl:in', XS[0], LY, w[i - 1], 'act', 'w' + (i - 1), 'act'));
        if (stage >= 1) { items.push(...colAt('kl:rot', XS[1], LY, g.rot, stage === 1 ? 'hot' : '', 'RotWord')); arrow(1, XS[0] + LCW, XS[1]); }
        if (stage >= 2) { items.push(...colAt('kl:sub', XS[2], LY, g.sub, stage === 2 ? 'hot' : '', 'SubWord')); arrow(2, XS[1] + LCW, XS[2]); }
        if (stage >= 3) {
          N.op('x1', XS[3], MY, 'xor', stage === 3 ? 'act' : '', 12);
          N.wire('a3', [[XS[2] + LCW + 4, MY], N.port('x1', 'w')], { head: true });
          items.push(...colAt('kl:rc', XS[3] - LCW / 2, BY, [g.rc, 0, 0, 0], 'key', 'Rcon', 'key'));
          N.wire('rc', [[XS[3], BY - 22], N.port('x1', 's')], { head: true, cls: 'key' });
          items.push(...colAt('kl:g', XS[4], LY, g.out, stage === 3 ? 'hot' : '', 'g(w' + (i - 1) + ')'));
          N.wire('a4', [N.port('x1', 'e'), [XS[4] - 4, MY]], { head: true });
        }
        if (stage >= 4) {
          N.op('x2', XS[5], MY, 'xor', 'act', 12);
          N.wire('a5', [[XS[4] + LCW + 4, MY], N.port('x2', 'w')], { head: true });
          items.push(...colAt('kl:back', XS[5] - LCW / 2, BY, w[i - 4], 'act', 'w' + (i - 4), 'act'));
          N.wire('bk', [[XS[5], BY - 22], N.port('x2', 's')], { head: true });
          items.push(...colAt('kl:out', XS[6], LY, w[i], 'hot', 'w' + i, 'hot'));
          N.wire('a6', [N.port('x2', 'e'), [XS[6] - 4, MY]], { head: true });
        }
      } else {
        items.push(...colAt('kl:g', XS[4], LY, w[i - 1], 'act', 'w' + (i - 1), 'act'));
        N.op('x2', XS[5], MY, 'xor', 'act', 12);
        N.wire('a5', [[XS[4] + LCW + 4, MY], N.port('x2', 'w')], { head: true });
        items.push(...colAt('kl:back', XS[5] - LCW / 2, BY, w[i - 4], 'act', 'w' + (i - 4), 'act'));
        N.wire('bk', [[XS[5], BY - 22], N.port('x2', 's')], { head: true });
        items.push(...colAt('kl:out', XS[6], LY, w[i], 'hot', 'w' + i, 'hot'));
        N.wire('a6', [N.port('x2', 'e'), [XS[6] - 4, MY]], { head: true });
        items.push(U.t('kl:note', XS[0], MY + 5, 'no g: not a multiple of 4', 'tick', 'start', 14));
      }
      return items.concat(N.items);
    };
    const hexw = (v) => U.hex(v);
    F.add({ items: [...strip(3, [], -1), ...rconRow(-1)], hl: { d: [0] }, say: `The 16-byte key is cut into four words, w0 = ${hexw(w[0])}, w1 = ${hexw(w[1])}, w2 = ${hexw(w[2])} and w3 = ${hexw(w[3])}. They are round key 0; the other 40 words are made from them.`, facts: { w0: w[0], w1: w[1], w2: w[2], w3: w[3] }, meta: { stage: 'key' } });
    const g4 = A().g(w[3], 4);
    F.add({ items: [...strip(3, [3], -1), ...rconRow(-1), ...lane(4, 1)], hl: { d: [2] }, say: `w4 starts round key 1, so it needs g(w3). RotWord turns the word one byte up: ${hexw(w[3])} becomes ${hexw(g4.rot)}.`, facts: { w3: w[3], rot: g4.rot }, meta: { stage: 'rot' } });
    F.add({ items: [...strip(3, [3], -1), ...rconRow(-1), ...lane(4, 2)], hl: { d: [2] }, say: `SubWord puts each byte through the S-box: ${hexw(g4.rot)} becomes ${hexw(g4.sub)}.`, facts: { rot: g4.rot, sub: g4.sub }, meta: { stage: 'sub' } });
    F.add({ items: [...strip(3, [3], -1), ...rconRow(0), ...lane(4, 3)], hl: { d: [2, 3] }, say: `The round constant Rcon(1) = ${U.h2(g4.rc)} is XORed into the first byte only: g(w3) = ${hexw(g4.out)}. Without it, every round key would be built the same way and related keys would give related schedules.`, facts: { rc: g4.rc, g: g4.out }, meta: { stage: 'rcon' } });
    F.add({ items: [...strip(4, [0, 3], 4), ...rconRow(0), ...lane(4, 4)], hl: { d: [1] }, say: `w4 = w0 ⊕ g(w3) = ${hexw(w[0])} ⊕ ${hexw(g4.out)} = ${hexw(w[4])}.`, facts: { w0: w[0], g: g4.out, w4: w[4] }, meta: { stage: 'word', i: 4 } });
    for (const i of [5, 6, 7]) F.add({ items: [...strip(i, [i - 4, i - 1], i), ...rconRow(0), ...lane(i, 4)], hl: { d: [1] }, say: `w${i} = w${i - 4} ⊕ w${i - 1} = ${hexw(w[i - 4])} ⊕ ${hexw(w[i - 1])} = ${hexw(w[i])}. No g here: only every fourth word goes through it.`, facts: { i, a: w[i - 4], b: w[i - 1], c: w[i] }, meta: { stage: 'word', i } });
    for (let k = 2; k <= 10; k++) {
      const i = 4 * k, g = A().g(w[i - 1], i);
      F.add({ items: [...strip(i + 3, [i - 1], i), ...rconRow(k - 1), ...lane(i, 4)], hl: { d: [1, 2, 3] }, say: `Round key ${k}: g(w${i - 1}) with Rcon(${k}) = ${U.h2(g.rc)} gives ${hexw(g.out)}, so w${i} = ${hexw(w[i])}; then w${i + 1}, w${i + 2} and w${i + 3} by plain XORs. Round key ${k} is ${U.hex(A().roundKey(w, k))}.`, facts: { k, i, rc: g.rc, g: g.out, wi: w[i], rk: A().roundKey(w, k) }, meta: { stage: 'rk', k } });
    }
    F.add({ items: [...strip(43, [], -1), ...rconRow(10)], hl: { d: [4] }, say: `All 44 words are made: 11 round keys. The last, round key 10, is ${U.hex(A().roundKey(w, 10))}. Each word depends on the key through the chain, and one changed key bit reaches every byte within a few round keys.`, facts: { rk: A().roundKey(w, 10), k: 10 }, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('AES-128 key expansion', ['w0 … w3 = the key', 'wᵢ = wᵢ₋₄ ⊕ wᵢ₋₁                 (i not a multiple of 4)', 'wᵢ = wᵢ₋₄ ⊕ g(wᵢ₋₁),  g = SubWord(RotWord(w)) ⊕ (Rcon(i/4), 0, 0, 0)', 'Rcon(j) = x^(j−1) in GF(2⁸): 01 02 04 08 10 20 40 80 1b 36', 'round key r = w4r … w4r+3']) };
  }
  S.topic({
    id: 'aes-keyexp', family: 'p05-keys', order: 10, title: 'The key expansion and the g-function',
    blurb: 'AES-128 stretches 4 key words into 44. Each new word is the word four back XOR the word before it, and every fourth word first goes through g: rotate, substitute, add a round constant.',
    inputs: [{ id: 'key', kind: 'text', label: 'Key (16 characters or 32 hex digits)', def: 'ochre-river-2026', check: U.keyCheck('Key', [16]) }],
    presets: [
      { label: 'Our own key', values: { key: 'ochre-river-2026' } },
      { label: 'FIPS 197 Appendix A.1 key', values: { key: '2b7e151628aed2a6abf7158809cf4f3c' } },
      { label: 'All-zero key: Rcon breaks the symmetry', values: { key: '00000000000000000000000000000000' } },
      { label: 'All ff key', values: { key: 'ffffffffffffffffffffffffffffffff' } },
    ],
    run: keyExp,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'sub', pick: 'option', options: ['the first', 'the last', 'all four', 'none'], ask: 'The round constant is coming. Which bytes of the word does it change?', answer: 'the first', explain: 'Rcon is (rc, 00, 00, 00): only the first byte changes.' }],
    quiz: [
      { q: 'Which words go through the g-function in AES-128?', options: ['Every word', 'Every fourth word: w4, w8, …', 'Only w4', 'The odd words'], answer: 1, why: 'Words whose index is a multiple of 4 start a new round key and use g.' },
      { q: 'What does RotWord do to (a0, a1, a2, a3)?', options: ['(a3, a0, a1, a2)', '(a1, a2, a3, a0)', 'Reverses it', 'Substitutes each byte'], answer: 1, why: 'A cyclic shift of one byte towards the front.' },
      { q: 'What is Rcon(9)?', options: ['80', '100', '1b', '36'], answer: 2, why: '02⁸ = 100 overflows a byte, and reducing by the AES polynomial gives 1b.' },
      { q: 'How many words does AES-128 expand its key into?', options: ['16', '40', '44', '64'], answer: 2, why: 'Eleven round keys of four words.' },
      { q: 'Why does the schedule use SubWord?', options: ['To make it faster', 'So the round keys are a non-linear function of the key', 'To pad the key', 'It does not'], answer: 1, why: 'Without the S-box the round keys would be linear in the key, which helps related-key and algebraic attacks.' },
    ],
  });

  // ---- AES-192 and AES-256 schedules -----------------------------------------------------------------------------
  function wide(inp) {
    const K = U.key(inp.key), ex = A().expand(K), w = ex.w, Nk = ex.Nk, Nr = ex.Nr, total = w.length, F = new S.Frames();
    const kind = (i) => (i < Nk ? 'key' : i % Nk === 0 ? 'g' : Nk > 6 && i % Nk === 4 ? 'sub' : 'plain');
    const rows = Math.ceil(total / Nk), CW = 92, CH = 24, PX = 70, PY = 58, pitchY = Math.min(36, 330 / rows);
    const at = (i) => ({ x: PX + (i % Nk) * (CW + 4), y: PY + Math.floor(i / Nk) * pitchY });
    const cls = { key: 'key', g: 'hot', sub: 'act', plain: '' };
    const strip = (upto, focus) => {
      const items = [U.t('kw:t', 30, 40, `${total} words in rows of ${Nk}; the bar under each word marks its round key`, 'title')];
      for (let r = 0; r < rows; r++) items.push(U.t('kw:rh' + r, PX - 10, PY + r * pitchY + CH / 2 + 5, 'w' + r * Nk, 'tick', 'end', 13));
      for (let i = 0; i < total; i++) {
        const p = at(i), on = i <= upto;
        items.push({ key: 'kw:' + i, kind: 'cell', x: p.x, y: p.y, w: CW, h: CH, rx: 3, text: on ? U.hex(w[i]) : '', size: 13, cls: 'hex ' + (on ? cls[kind(i)] : 'soft') + (i === focus ? ' ring' : '') });
        items.push({ key: 'kw:b' + i, kind: 'cell', x: p.x, y: p.y + CH + 2, w: CW, h: 4, rx: 1, text: '', cls: 'bar ' + (Math.floor(i / 4) % 2 ? 'key' : 'act') + (on ? '' : ' dim'), audit: 'overlap-ok' });
      }
      return items;
    };
    const legend = () => {
      const y = PY + rows * pitchY + 18, items = [];
      let x = 70;
      [['key', 'from the key'], ['hot', 'via g'], ...(Nk > 6 ? [['act', 'via SubWord only']] : []), ['', 'plain XOR']].forEach(([c, t], k) => {
        if (k) x += 34 + S.geom.textWidth(items[items.length - 1].text, 13) + 36;
        items.push({ key: 'kw:lg' + k, kind: 'cell', x, y, w: 26, h: 18, rx: 3, text: '', cls: 'hex ' + c });
        items.push(U.t('kw:lt' + k, x + 34, y + 14, t, 'tick', 'start', 13));
      });
      return items;
    };
    // the lane for word i, as whole words
    const LY = 480, BW = 110, BH = 30;
    const lane = (i) => {
      const N = S.Kit.flow.net('kn'), k = kind(i), items = [];
      const box = (id, x, y, v, c, title) => { items.push(U.t('kn:' + id + 't', x + BW / 2, y - 8, title, 'strong', 'middle', 13)); items.push({ key: 'kn:' + id, kind: 'cell', x, y, w: BW, h: BH, rx: 4, text: U.hex(v), size: 14, cls: 'hex ' + (c || '') }); };
      const ar = (id, x1, x2, y) => N.wire(id, [[x1 + 4, y], [x2 - 4, y]], { head: true });
      const my = LY + BH / 2;
      let tx = 500;
      if (k === 'g') {
        const rot = [w[i - 1][1], w[i - 1][2], w[i - 1][3], w[i - 1][0]], sub = rot.map((b) => S.gf256.SBOX[b]), rc = A().RCON[i / Nk - 1];
        box('p', 30, LY, w[i - 1], 'act', 'w' + (i - 1));
        box('r', 180, LY, rot, '', 'RotWord'); ar('a1', 140, 180, my);
        box('s', 330, LY, sub, '', 'SubWord'); ar('a2', 290, 330, my);
        box('g', 500, LY, [sub[0] ^ rc, sub[1], sub[2], sub[3]], 'hot', `⊕ Rcon ${U.h2(rc)}`); ar('a3', 440, 500, my);
      } else if (k === 'sub') {
        box('p', 30, LY, w[i - 1], 'act', 'w' + (i - 1));
        box('s', 500, LY, w[i - 1].map((b) => S.gf256.SBOX[b]), 'act', 'SubWord'); ar('a2', 140, 500, my);
      } else box('p', 500, LY, w[i - 1], 'act', 'w' + (i - 1));
      N.op('x', 670, my, 'xor', 'act', 12);
      N.wire('a4', [[tx + BW + 4, my], N.port('x', 'w')], { head: true });
      const y2 = LY + 70;
      box('b', 670 - BW / 2, y2, w[i - Nk], '', 'w' + (i - Nk));
      N.wire('a5', [[670, y2 - 22], N.port('x', 's')], { head: true });
      box('o', 740, LY, w[i], 'hot', 'w' + i);
      N.wire('a6', [N.port('x', 'e'), [740 - 4, my]], { head: true });
      return items.concat(N.items);
    };
    const wordSay = (i) => {
      const k = kind(i);
      return k === 'g' ? `w${i} = w${i - Nk} ⊕ g(w${i - 1}) = ${U.hex(w[i - Nk])} ⊕ ${U.hex(ex.trace.find((t) => t.kind === 'g' && t.i === i).gout)} = ${U.hex(w[i])}`
        : k === 'sub' ? `w${i} = w${i - Nk} ⊕ SubWord(w${i - 1}) = ${U.hex(w[i - Nk])} ⊕ ${U.hex(w[i - 1].map((b) => S.gf256.SBOX[b]))} = ${U.hex(w[i])}`
          : `w${i} = w${i - Nk} ⊕ w${i - 1} = ${U.hex(w[i - Nk])} ⊕ ${U.hex(w[i - 1])} = ${U.hex(w[i])}`;
    };
    const gT = (i) => ex.trace.find((t) => t.kind === 'g' && t.i === i);
    F.add({ items: [...strip(Nk - 1), ...legend()], say: `A ${K.length * 8}-bit key is ${Nk} words, w0 to w${Nk - 1}. AES-${K.length * 8} has ${Nr} rounds, so it needs ${Nr + 1} round keys, ${total} words in all. The schedule works in steps of ${Nk} words, not 4.`, facts: { bits: K.length * 8, Nk, last: Nk - 1, Nr, n: Nr + 1, total }, meta: { stage: 'key' } });
    F.add({ items: [...strip(Nk, Nk), ...legend(), ...lane(Nk)], hl: { d: [1] }, say: `w${Nk} is the first made word, and the first to go through g: ${wordSay(Nk)}.`, facts: { i: Nk, a: w[0], g: gT(Nk).gout, c: w[Nk] }, meta: { stage: 'first' } });
    if (Nk > 6) F.add({ items: [...strip(12, 12), ...legend(), ...lane(12)], hl: { d: [2] }, say: `AES-256 adds one more S-box step: halfway through each group of 8, w12 uses SubWord without rotation or constant. ${wordSay(12)}.`, facts: { a: w[4], b: w[11].map((b) => S.gf256.SBOX[b]), c: w[12] }, meta: { stage: 'subword' } });
    for (let r = 1; r < rows; r++) {
      const a = r * Nk, b = Math.min(total - 1, a + Nk - 1);
      F.add({ items: [...strip(b, a), ...legend(), ...lane(a)], hl: { d: [1, 2] }, say: `Words w${a} to w${b}: w${a} through g with Rcon ${U.h2(gT(a).rc)}${Nk > 6 && a + 4 <= b ? `, w${a + 4} through SubWord` : ''}, the rest by plain XOR. w${b} = ${U.hex(w[b])}.`, facts: { a, b, rc: gT(a).rc, wb: w[b], a4: a + 4, wa: w[a], an: a - Nk, a1: a - 1 }, meta: { stage: 'row', r } });
    }
    const fi = Math.max(Nk, Math.min(total - 1, inp.word));
    F.add({ items: [...strip(total - 1, fi), ...legend(), ...lane(fi)], hl: { d: [kind(fi) === 'g' ? 1 : kind(fi) === 'sub' ? 2 : 0] }, say: `Word ${fi}, close up: ${wordSay(fi)}. It is word ${fi % 4} of round key ${Math.floor(fi / 4)}.`, facts: { fi, a: w[fi - Nk], c: w[fi], j: fi % 4, rk: Math.floor(fi / 4), t: kind(fi) === 'g' ? gT(fi).gout : kind(fi) === 'sub' ? w[fi - 1].map((b) => S.gf256.SBOX[b]) : w[fi - 1] }, meta: { stage: 'focus' } });
    const gs = [16, 24, 32].map((n) => { const nk = n / 4, t = 4 * (nk + 7); let g = 0, s = 0; for (let i = nk; i < t; i++) { if (i % nk === 0) g++; else if (nk > 6 && i % nk === 4) s++; } return { n, t, g, s }; });
    F.add({ items: [...strip(total - 1), ...legend()], say: `The three schedules side by side: AES-128 makes ${gs[0].t} words with ${gs[0].g} g-steps, AES-192 ${gs[1].t} words with ${gs[1].g}, and AES-256 ${gs[2].t} words with ${gs[2].g} g-steps and ${gs[2].s} extra SubWord steps. The wider the key, the fewer non-linear steps per word, which is why AES-256 has more rounds but a weaker schedule against related-key attacks.`, facts: { gs }, meta: { stage: 'compare' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def(`AES-${K.length * 8} key schedule`, [`wᵢ = wᵢ₋${U.sub(Nk)} ⊕ wᵢ₋₁   (plain)`, `wᵢ = wᵢ₋${U.sub(Nk)} ⊕ g(wᵢ₋₁)   when i mod ${Nk} = 0`, 'wᵢ = wᵢ₋₈ ⊕ SubWord(wᵢ₋₁)   when Nk = 8 and i mod 8 = 4', `${total} words = ${Nr + 1} round keys of 4 words`]) };
  }
  S.topic({
    id: 'aes-keysched-wide', family: 'p05-keys', order: 20, title: 'AES-192 and AES-256 key schedules',
    blurb: 'Longer keys run the same recurrence in steps of 6 or 8 words. AES-256 adds a SubWord halfway through each step; round keys still take 4 words each, so they straddle the steps.',
    inputs: [
      { id: 'key', kind: 'text', label: 'Key (16, 24 or 32 characters, or hex)', def: 'thirty-two bytes of copper wire!', check: U.keyCheck('Key') },
      { id: 'word', kind: 'number', label: 'A word to look at closely', def: 20, min: 4, max: 59 },
    ],
    presets: [
      { label: 'AES-256, our own key', values: { key: 'thirty-two bytes of copper wire!', word: 20 } },
      { label: 'AES-192, our own key', values: { key: 'a quiet orchard of 24 by', word: 30 } },
      { label: 'FIPS 197 A.2 key (AES-192)', values: { key: '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b', word: 12 } },
      { label: 'FIPS 197 A.3 key (AES-256)', values: { key: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', word: 12 } },
      { label: 'AES-128 for comparison', values: { key: 'ochre-river-2026', word: 9 } },
    ],
    run: wide,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'key', pick: 'option', options: ['4', '6', '8', '12'], ask: 'How many words apart are the two words XORed to make each new word?', answer: (fr, i) => String(fr[i].facts.Nk), explain: (fr, i) => `wᵢ = wᵢ₋${fr[i].facts.Nk} ⊕ (something from wᵢ₋₁): the distance is the key length in words, ${fr[i].facts.Nk}.` }],
    quiz: [
      { q: 'How many words does AES-256 expand to?', options: ['44', '52', '60', '64'], answer: 2, why: '15 round keys of 4 words.' },
      { q: 'In AES-256, which words use SubWord without RotWord and Rcon?', options: ['None', 'Words with i mod 8 = 4', 'Every odd word', 'w8 only'], answer: 1, why: 'The extra non-linear step sits halfway through each group of 8.' },
      { q: 'How many rounds does AES-192 have?', options: ['10', '12', '14', '11'], answer: 1, why: 'Nr = Nk + 6 = 12.' },
      { q: 'Why can a round key of AES-192 come from two different groups of 6 words?', options: ['It cannot', 'Round keys are 4 words but the schedule steps by 6, so their boundaries do not line up', 'Round keys are 6 words', 'The schedule is run twice'], answer: 1, why: 'The schedule is one long list of words cut into fours, whatever Nk is.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
