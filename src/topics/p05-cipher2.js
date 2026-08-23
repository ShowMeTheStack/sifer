// Part 5, the avalanche: two encryptions that differ in one bit (of the plaintext or of the key), run side by side.
// After each round a heat grid shows how many bits of each byte differ, and a bar chart counts them against the 64
// that two unrelated blocks would show.
(function (S) {
  'use strict';
  const U = S.P5;

  function avalanche(inp) {
    const P0 = U.block(inp.pt), K0 = U.key(inp.key), inKey = inp.where === 'key';
    const P1 = Uint8Array.from(P0), K1 = Uint8Array.from(K0), byte = inp.byte, bit = inp.bit;
    (inKey ? K1 : P1)[byte] ^= 1 << bit;
    const a = S.AES.encrypt(P0, K0), b = S.AES.encrypt(P1, K1), Nr = a.rounds.length - 1, pc = S.bytes.popcount;
    const diffs = a.rounds.map((r, k) => r.end.map((v, i) => v ^ b.rounds[k].end[i]));
    const bits = diffs.map((d) => d.reduce((n, v) => n + pc(v), 0)), bytes = diffs.map((d) => d.filter((v) => v).length);
    const F = new S.Frames();
    // the two inputs that differ
    const X0 = inKey ? K0 : P0, X1 = inKey ? K1 : P1, n = X0.length, pw = n > 16 ? 21 : 30, ph = 26;
    const name = inKey ? 'K' : 'P';
    const head = [];
    [[X0, name], [X1, name + '′']].forEach(([u, nm], j) => {
      head.push(U.t('av:n' + j, 0, 30 + j * (ph + 6) + ph / 2 + 5, nm, 'strong', 'start', 15));
      head.push(...U.cells(`av:p${j}:`, 30, 30 + j * (ph + 6), u, { cw: pw, ch: ph, gap: 2, size: 13, cls: (i) => (i === byte ? 'h4 hframe' : inKey ? 'key' : 'soft') }));
    });
    if (n <= 16) head.push(U.t('av:note', 30 + 16 * (pw + 2) + 18, 30 + ph + 8, `${inKey ? 'key' : 'plaintext'} byte ${byte}, bit ${bit}: ${U.h2(X0[byte])} → ${U.h2(X1[byte])}`, 'heat', 'start', 14));
    // the heat grids: eight to a row
    const per = 8, sx = 105, sy = 146, top = 104, cw = 22, ch = 20, gp = 2;
    const pos = (r) => ({ x: 20 + (r % per) * sx, y: top + Math.floor(r / per) * sy });
    const grid = (r, now) => {
      const p = pos(r);
      const g = U.grid('av' + r + ':', p.x, p.y + 22, diffs[r], { cw, ch, gap: gp, size: 13, rx: 2, cls: (i, rr, c, v) => 'hframe h' + pc(v) });
      return [U.t('av' + r + ':t', p.x, p.y + 12, r === 0 ? 'round 0' : 'round ' + r, now ? 'act' : 'strong', 'start', 13), ...g.items,
        U.t('av' + r + ':c', p.x, p.y + 22 + 4 * (ch + gp) + 17, bits[r] + ' bit' + (bits[r] === 1 ? '' : 's'), now ? 'heat' : 'tick', 'start', 13)];
    };
    // the bar chart of differing bits per round, with the 64 of two unrelated blocks
    const cx0 = 70, cy0 = top + 2 * sy + 34, CHh = 150, bw = Math.min(40, 700 / (Nr + 1) - 8), step = 760 / (Nr + 1);
    const yOf = (v) => cy0 + CHh - (v / 128) * CHh;
    const chart = (upto) => {
      const items = [U.t('ch:t', 20, cy0 - 14, 'bits that differ, of 128', 'title')];
      items.push({ key: 'ch:base', kind: 'line', x1: cx0 - 6, y1: cy0 + CHh, x2: cx0 + (Nr + 1) * step, y2: cy0 + CHh, cls: 'rule' });
      items.push({ key: 'ch:64', kind: 'line', x1: cx0 - 6, y1: yOf(64), x2: cx0 + (Nr + 1) * step, y2: yOf(64), cls: 'dash', audit: 'ignore', layer: 'top' });
      items.push(U.t('ch:64t', cx0 - 12, yOf(64) + 5, '64', 'tick', 'end', 13));
      items.push(U.t('ch:128t', cx0 - 12, yOf(128) + 5, '128', 'tick', 'end', 13));
      items.push(U.t('ch:0t', cx0 - 12, yOf(0) + 5, '0', 'tick', 'end', 13));
      for (let r = 0; r <= Nr; r++) {
        const x = cx0 + r * step + (step - bw) / 2;
        items.push(U.t('ch:r' + r, x + bw / 2, cy0 + CHh + 18, String(r), 'tick', 'middle', 13));
        if (r > upto) continue;
        // the count sits inside a tall bar (clear of the 64 line), above a short one
        const hh = yOf(0) - yOf(bits[r]), inside = hh > 60;
        items.push({ key: 'ch:b' + r, kind: 'cell', x, y: yOf(bits[r]), w: bw, h: Math.max(1.5, hh), rx: 2, text: inside ? String(bits[r]) : '', size: 13, cls: 'hex h' + Math.min(8, Math.round(bits[r] / 8)) + ' hframe', enter: 'grow' });
        if (!inside) items.push(U.t('ch:v' + r, x + bw / 2, yOf(bits[r]) - 6, String(bits[r]), r === upto ? 'heat' : 'tick', 'middle', 13));
      }
      return items;
    };
    const sb = a.rounds[1].sub, sb1 = b.rounds[1].sub;
    F.add({ items: [...head, ...chart(-1)], say: `Two ${inKey ? 'keys' : 'plaintexts'} that differ in a single bit: byte ${byte}, bit ${bit}, ${U.h2(X0[byte])} against ${U.h2(X1[byte])}. ${inKey ? 'Both encrypt the same plaintext.' : 'Both are encrypted under the same key.'} Each grid to come is the XOR of the two states after a round: the hotter a cell, the more of its 8 bits differ.`, facts: { byte, bit, x0: X0[byte], x1: X1[byte] }, meta: { stage: 'start' } });
    for (let r = 0; r <= Nr; r++) {
      const items = [...head];
      for (let k = 0; k <= r; k++) items.push(...grid(k, k === r));
      items.push(...chart(r));
      let say, facts = { r, bits: bits[r], bytes: bytes[r] };
      if (r === 0) say = `After round 0 the states differ in ${bits[r]} bit${bits[r] === 1 ? '' : 's'}: ${inKey ? 'the flipped key bit is XORed into the state' : 'the same key is XORed into both, so the difference passes straight through'}.`;
      else if (r === 1 && !inKey) {
        const i = byte, d = pc(sb[i] ^ sb1[i]);
        Object.assign(facts, { s0: a.rounds[1].start[i], s1: b.rounds[1].start[i], o0: sb[i], o1: sb1[i], d });
        say = `Round 1: SubBytes turns ${U.h2(a.rounds[1].start[i])} and ${U.h2(b.rounds[1].start[i])} into ${U.h2(sb[i])} and ${U.h2(sb1[i])}, which differ in ${d} bit${d === 1 ? '' : 's'}. MixColumns then spreads that byte over its whole column: ${bytes[r]} of 16 bytes differ, ${bits[r]} bits in all.`;
      } else if (r === 1) say = `Round 1: ${bytes[r]} of 16 bytes differ, ${bits[r]} bits. The key difference reaches the state twice: in round key 0, and spread by the key schedule into round key 1.`;
      else if (r === 2) say = `Round 2: ShiftRows sends the differing bytes into different columns and MixColumns fills them: ${bytes[r]} of 16 bytes differ, ${bits[r]} bits.`;
      else if (r === Nr) {
        const tail = bits.slice(2), mean = tail.reduce((x, y) => x + y, 0) / tail.length;
        Object.assign(facts, { mean: mean.toFixed(1), Nr });
        say = `After the last round the ciphertexts differ in ${bits[r]} of 128 bits. From round 2 on the count averaged ${mean.toFixed(1)}; two unrelated blocks differ in 64 on average. Nothing of the single flipped bit is left to see.`;
      } else say = `Round ${r}: ${bits[r]} bits differ, in ${bytes[r]} bytes. From here the count only wanders around 64, as it would for two random blocks.`;
      F.add({ items, say, facts, meta: { stage: 'round', r } });
    }
    U.fix(F.list);
    return { frames: F.list, def: U.def('The avalanche', ['Δ after round r = state(P, K) ⊕ state(P′, K′)', 'one byte in: SubBytes changes about half its bits', 'MixColumns: one byte in a column → all 4 bytes', 'ShiftRows + MixColumns: 4 bytes → all 16 by round 2', 'random pair of blocks: 64 of 128 bits differ on average']) };
  }
  S.topic({
    id: 'aes-avalanche', family: 'p05-cipher', order: 30, title: 'The avalanche: one bit, round by round',
    blurb: 'Flip one bit of the plaintext or of the key and run both encryptions side by side. A heat map of the difference fills the whole state in two rounds.',
    inputs: [
      { id: 'pt', kind: 'text', label: 'Plaintext (16 characters or 32 hex digits)', def: 'Lanterns at dusk', check: U.blockCheck('Plaintext') },
      { id: 'key', kind: 'text', label: 'Key (16, 24 or 32 characters, or hex)', def: 'ochre-river-2026', check: U.keyCheck('Key') },
      { id: 'where', kind: 'choice', label: 'Flip a bit of', def: 'pt', options: [{ value: 'pt', label: 'the plaintext' }, { value: 'key', label: 'the key' }] },
      { id: 'byte', kind: 'number', label: 'Byte', def: 9, min: 0, max: 31, check: (v, inp) => (inp.where === 'key' ? (U.key(inp.key) && v >= U.key(inp.key).length ? 'Byte: the key has only ' + U.key(inp.key).length + ' bytes' : null) : v > 15 ? 'Byte: the block has 16 bytes (0 to 15)' : null) },
      { id: 'bit', kind: 'number', label: 'Bit', def: 2, min: 0, max: 7 },
    ],
    presets: [
      { label: 'One plaintext bit', values: { pt: 'Lanterns at dusk', key: 'ochre-river-2026', where: 'pt', byte: 9, bit: 2 } },
      { label: 'One key bit', values: { pt: 'Lanterns at dusk', key: 'ochre-river-2026', where: 'key', byte: 0, bit: 0 } },
      { label: 'All-zero block, top bit', values: { pt: '00000000000000000000000000000000', key: '00000000000000000000000000000000', where: 'pt', byte: 15, bit: 7 } },
      { label: 'AES-256, a key bit near the end', values: { pt: 'Moth on the pane', key: 'thirty-two bytes of copper wire!', where: 'key', byte: 30, bit: 5 } },
    ],
    run: avalanche,
    predict: [{
      at: (f, i, fr) => f.meta && f.meta.stage === 'round' && f.meta.r === 1 && fr[i + 1], once: true, pick: 'option',
      options: (fr, i) => [...new Set(['4', '8', '12', '16', String(fr[i + 1].facts.bytes)])].sort((x, y) => x - y),
      ask: 'How many of the 16 bytes will differ after round 2?', answer: (fr, i) => String(fr[i + 1].facts.bytes),
      explain: 'ShiftRows puts the differing bytes of one column into four different columns, and MixColumns spreads each over its whole column.',
    }],
    quiz: [
      { q: 'After how many rounds does a one-bit plaintext difference reach every byte of the AES state?', options: ['1', '2', '4', '10'], answer: 1, why: 'Round 1 spreads it over one column; ShiftRows and MixColumns of round 2 spread that column over all four.' },
      { q: 'About how many bits differ between the two ciphertexts?', options: ['1', 'About 16', 'About 64', 'All 128'], answer: 2, why: 'Like two unrelated random blocks: each bit differs with probability one half.' },
      { q: 'Which step makes one input byte affect four output bytes?', options: ['SubBytes', 'ShiftRows', 'MixColumns', 'AddRoundKey'], answer: 2, why: 'MixColumns is a maximum-distance-separable map: a change in one byte of a column changes all four.' },
      { q: 'Why does it matter that a key bit avalanches too?', options: ['It makes encryption faster', 'Related keys then give unrelated ciphertexts, so nothing is learnt by comparing them', 'It shortens the key schedule', 'It is needed for padding'], answer: 1, why: 'If a key bit changed only a few output bits, comparing ciphertexts would reveal key bits one at a time.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
