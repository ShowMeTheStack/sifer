// Part 12, SHA-256 opened up: the message schedule (sixteen words become 64, each new word from four earlier ones,
// two of them through σ0 and σ1, drawn bit by bit), and the compression function round by round (the registers
// a…h, the two sums T1 and T2, the shift down one place, and the feed-forward that ends the compression).
(function (S) {
  'use strict';
  const U = S.P12, H2 = () => S.SHA256;
  const { t, h8, sub } = U;
  const NAMES = 'abcdefgh';
  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
  const bitsOf = (v) => Array.from({ length: 32 }, (_, i) => (v >>> (31 - i)) & 1);
  const blockOf = (msg, k) => { const p = H2().pad(U.utf8(msg)); return { padded: p, block: p.subarray(64 * k, 64 * k + 64), nb: p.length / 64 }; };
  const msgInput = { id: 'msg', kind: 'text', label: 'Message', def: 'Sifer hashes this line, one round at a time.', check: (v) => (U.utf8(v).length > 183 ? 'Message: at most 183 bytes (three blocks)' : null) };
  const blockInput = { id: 'block', kind: 'number', label: 'Block to follow', def: 1, min: 1, max: 3, check: (v, inp) => { const nb = Math.ceil((U.utf8(inp.msg).length + 9) / 64); return v > nb ? 'Block to follow: the padded message has only ' + U.plural(nb, 'block') : null; } };

  /**
   * One σ function drawn as rows of 32 bits: the word, its two rotations, its shift, and their XOR. o: {prefix, x, y,
   * v, rots: [r1, r2], shr, name, on, lit}
   */
  function sigmaRows(o) {
    const items = [], cw = 12, gap = 1, gg = 5, rh = 21, lab = 92;
    const xOf = (i) => o.x + lab + i * (cw + gap) + Math.floor(i / 8) * gg;
    const rows = [
      [o.src, o.v, null],
      ['ROTR ' + o.rots[0], rotr(o.v, o.rots[0]), o.rots[0]],
      ['ROTR ' + o.rots[1], rotr(o.v, o.rots[1]), o.rots[1]],
      ['SHR ' + o.shr, o.v >>> o.shr, -o.shr],
    ];
    const res = (rows[1][1] ^ rows[2][1] ^ rows[3][1]) >>> 0;
    items.push(t(o.prefix + ':t', o.x, o.y - 10, o.name + '(' + o.src + ') = ROTR ' + o.rots[0] + ' ⊕ ROTR ' + o.rots[1] + ' ⊕ SHR ' + o.shr, 'strong', 'start', 13));
    rows.forEach(([name, v, r], k) => {
      const y = o.y + k * rh;
      items.push(t(o.prefix + ':n' + k, o.x, y + 14, name, k ? 'ptick' : 'src', 'start', 13));
      bitsOf(v).forEach((b, i) => {
        // bits that wrapped round in a rotation, and the zeros a shift brought in
        const wrapped = r > 0 && i < r, filled = r < 0 && i < -r;
        items.push({ key: o.prefix + ':b' + k + '-' + i, kind: 'cell', x: U.r2(xOf(i)), y, w: cw, h: rh - 3, rx: 2, text: '', cls: 'bit solid ' + (b ? 'one' : 'zero') + (wrapped ? ' act' : filled ? ' soft' : k === 0 ? ' src' : '') + (o.on ? '' : ' dim') });
      });
      items.push(t(o.prefix + ':h' + k, xOf(31) + cw + 12, y + 14, h8(v), 'mono', 'start', 13));
    });
    const y = o.y + 4 * rh + 8;
    items.push({ key: o.prefix + ':rule', kind: 'line', x1: o.x + lab, y1: y - 4, x2: U.r2(xOf(31) + cw), y2: y - 4, cls: 'rule' });
    items.push(t(o.prefix + ':rn', o.x, y + 14, o.name, 'hot', 'start', 14));
    bitsOf(res).forEach((b, i) => items.push({ key: o.prefix + ':r' + i, kind: 'cell', x: U.r2(xOf(i)), y, w: cw, h: rh - 3, rx: 2, text: '', cls: 'bit solid ' + (b ? 'one hot' : 'zero') + (o.on ? '' : ' dim') }));
    items.push(t(o.prefix + ':rh', xOf(31) + cw + 12, y + 14, h8(res), 'mono hot', 'start', 14));
    return { items, value: res };
  }

  // ---------------------------------------------------------------------------------------------------------------
  // the message schedule
  // ---------------------------------------------------------------------------------------------------------------
  function schedule(inp) {
    const E = H2(), k = +inp.block - 1, { block, nb } = blockOf(inp.msg, k), sc = E.schedule(block), W = sc.W, tt = +inp.word;
    const tr = sc.trace[tt], [a, b, c, d] = tr.terms;
    const cw = 100, chh = 26, gx = 78, gy = 84;
    const cell = (j) => ({ x: gx + (j % 8) * (cw + 4), y: gy + Math.floor(j / 8) * (chh + 6) });
    const grid = (upto, lit, done) => {
      const items = [t('ms:gt', 20, gy - 14, 'the 64 words of the schedule, eight to a row', 'ptitle')];
      for (let r = 0; r < 8; r++) items.push(t('ms:rl' + r, gx - 10, gy + r * (chh + 6) + 18, 'W' + sub(8 * r), 'ptick', 'end', 13));
      for (let j = 0; j < 64; j++) {
        const p = cell(j), on = j < upto || (done && done.includes(j));
        const role = lit ? lit(j) : '';
        items.push({ key: 'ms:w' + j, kind: 'cell', x: p.x, y: p.y, w: cw, h: chh, rx: 4, text: on ? h8(W[j]) : '', size: 13, cls: 'hex ' + (role || (on ? (j < 16 ? '' : 'p12-sched') : 'soft')) });
      }
      return items;
    };
    const taps = (j) => (j === tt ? 'hot' : j === tt - 15 || j === tt - 2 ? 'act' : j === tt - 16 || j === tt - 7 ? 'src' : '');
    const s0 = (on) => sigmaRows({ prefix: 's0', x: 24, y: 360, v: W[tt - 15], src: 'W' + sub(tt - 15), rots: [7, 18], shr: 3, name: 'σ0', on });
    const s1 = (on) => sigmaRows({ prefix: 's1', x: 24, y: 520, v: W[tt - 2], src: 'W' + sub(tt - 2), rots: [17, 19], shr: 10, name: 'σ1', on });
    const sum = (on) => {
      const items = [], x = 690, y = 380, rows = [['σ1(W' + sub(tt - 2) + ')', a, 'act'], ['W' + sub(tt - 7), b, 'src'], ['σ0(W' + sub(tt - 15) + ')', c, 'act'], ['W' + sub(tt - 16), d, 'src']];
      items.push(...U.panel('ms:sp', x - 14, y - 34, 236, 228, 'the sum, mod 2³²'));
      rows.forEach(([n, v, cl], i) => { items.push(t('ms:sn' + i, x, y + 18 + i * 28, n, cl, 'start', 13)); items.push(t('ms:sv' + i, x + 206, y + 18 + i * 28, h8(v), 'mono', 'end', 14)); });
      items.push({ key: 'ms:sr', kind: 'line', x1: x + 110, y1: y + 128, x2: x + 208, y2: y + 128, cls: 'rule' });
      items.push(t('ms:sl', x + 96, y + 102, '+', 'strong', 'end', 15));
      items.push(t('ms:tn', x, y + 154, 'W' + sub(tt), 'hot', 'start', 15));
      items.push(t('ms:tv', x + 206, y + 154, on ? h8(W[tt]) : '', 'mono hot', 'end', 15));
      return items;
    };
    const F = new S.Frames(['words']);
    const head = U.head('ms:h', 'The message schedule of block ' + (k + 1) + (nb > 1 ? ' of ' + nb : ''));
    F.set('words', 16);
    const w16 = W.slice(0, 16).map(h8);
    F.add({ items: [...head, ...grid(16)], hl: { d: [0] }, say: `The 64-byte block is read as sixteen 32-bit big-endian words, W₀ = ${h8(W[0])} to W₁₅ = ${h8(W[15])}. The compression function needs 64 words, one per round: the other 48 are mixed from these.`, facts: { w: w16, k: k + 1, nb }, meta: { stage: 'block' } });
    F.add({ items: [...head, ...grid(tt, taps)], hl: { d: [1] }, say: `W${sub(tt)} takes four taps: W${sub(tt - 16)} and W${sub(tt - 7)} as they are, W${sub(tt - 15)} through σ0 and W${sub(tt - 2)} through σ1 (lit).`, facts: { t: tt, src: tr.src }, meta: { stage: 'taps' } });
    F.add({ items: [...head, ...grid(tt, taps), ...s0(true).items], hl: { d: [2] }, say: `σ0 rotates W${sub(tt - 15)} = ${h8(W[tt - 15])} right by 7 and by 18 (the bits that wrap round are lit), shifts it right by 3 (zeros come in), and XORs the three: σ0 = ${h8(c)}.`, facts: { v: h8(W[tt - 15]), s0: h8(c), t: tt }, meta: { stage: 's0' } });
    F.add({ items: [...head, ...grid(tt, taps), ...s0(false).items, ...s1(true).items], hl: { d: [3] }, say: `σ1 does the same to W${sub(tt - 2)} = ${h8(W[tt - 2])} with rotations 17 and 19 and a shift of 10: σ1 = ${h8(a)}. The shift is what keeps σ from being a rotation: it cannot be undone bit for bit.`, facts: { v: h8(W[tt - 2]), s1: h8(a), t: tt }, meta: { stage: 's1' } });
    F.set('words', tt + 1);
    F.add({ items: [...head, ...grid(tt + 1, taps), ...s0(false).items, ...s1(false).items, ...sum(true)], hl: { d: [4] }, say: `W${sub(tt)} = σ1 + W${sub(tt - 7)} + σ0 + W${sub(tt - 16)} = ${h8(a)} + ${h8(b)} + ${h8(c)} + ${h8(d)} = ${h8(W[tt])}, modulo 2³². Additions carry between bits; the σ functions mix bits within a word.`, facts: { terms: tr.terms.map(h8), w: h8(W[tt]), t: tt }, meta: { stage: 'sum' } });
    F.set('words', 64);
    const last = W.slice(60).map(h8);
    F.add({ items: [...head, ...grid(64, (j) => (j === tt ? 'hot' : '')), ...sum(true)], hl: { d: [4] }, say: `The same rule, word after word, fills all 64: W₆₃ = ${h8(W[63])}. Every word from W₁₆ on depends on many words of the block, so a change of one message bit spreads into most of the later words.`, facts: { last, w63: h8(W[63]) }, meta: { stage: 'all' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('The SHA-256 message schedule', ['Wₜ = word t of the block, for 0 ≤ t ≤ 15', 'Wₜ = σ1(Wₜ₋₂) + Wₜ₋₇ + σ0(Wₜ₋₁₅) + Wₜ₋₁₆  mod 2³²', 'σ0(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)', 'σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)', 'for 16 ≤ t ≤ 63']) };
  }
  S.topic({
    id: 'p12-schedule', family: 'p12-md', order: 20, title: 'The SHA-256 message schedule',
    blurb: 'Sixteen words of the block become 64. Each new word adds four earlier ones, two of them first stirred by σ0 and σ1: two rotations and a shift, XORed, drawn bit by bit.',
    inputs: [msgInput, blockInput, { id: 'word', kind: 'number', label: 'Follow word', def: 16, min: 16, max: 63 }],
    presets: [
      { label: 'W₁₆ of our line', values: { msg: 'Sifer hashes this line, one round at a time.', block: 1, word: 16 } },
      { label: 'W₄₀', values: { msg: 'Sifer hashes this line, one round at a time.', block: 1, word: 40 } },
      { label: 'The empty message, W₆₃', values: { msg: '', block: 1, word: 63 } },
      { label: 'Block 2 of a long message', values: { msg: 'Fifty-six bytes leave no room for the length: two blocks', block: 2, word: 17 } },
    ],
    counters: [{ id: 'words', label: 'words known' }],
    run: schedule,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'block', pick: 'item', ask: (fr) => 'Click one of the words that W' + sub(fr[1].facts.t) + ' reads through σ0 or σ1.', answer: (fr) => [fr[1].facts.src[0], fr[1].facts.src[2]].map((j) => 'ms:w' + j), explain: (fr) => fr[1].say },
    ],
    quiz: [
      { q: 'How many words does the SHA-256 schedule produce for one block?', options: ['16', '48', '64', '80'], answer: 2, why: 'One word per round, 64 rounds.' },
      { q: 'Which earlier words feed Wₜ?', options: ['Wₜ₋₁ and Wₜ₋₂', 'Wₜ₋₂, Wₜ₋₇, Wₜ₋₁₅, Wₜ₋₁₆', 'all sixteen before it', 'only Wₜ₋₁₆'], answer: 1, why: 'Four taps: two directly, two through σ0 and σ1.' },
      { q: 'Why does σ0 include a shift and not only rotations?', options: ['for speed', 'a XOR of rotations alone could be undone and is too regular; the shift breaks the symmetry', 'to make room for the length', 'to add the constants'], answer: 1, why: 'Pure rotations commute with rotation of the input; the shift loses bits and breaks that structure.' },
      { q: 'The words of the schedule are combined with…', options: ['XOR only', 'addition modulo 2³²', 'multiplication', 'AES'], answer: 1, why: 'The four terms are added modulo 2³², which carries between bit positions.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // the compression function
  // ---------------------------------------------------------------------------------------------------------------
  function compress(inp) {
    const E = H2(), k = +inp.block - 1, msg = U.utf8(inp.msg), r0 = +inp.round;
    const run = S.Hash.get('sha256').run(msg, { rounds: true }), blk = run.blocks[k], nb = run.blocks.length;
    const cvIn = blk.cvIn, c = E.compress(cvIn, blk.block), R = c.rounds;
    const regX = (i) => 70 + i * 112, regY = 104;
    const regs = (vals, lit, shifted, fresh) => {
      const items = [];
      for (let i = 0; i < 8; i++) {
        // after the shift a register keeps the key of the value it holds, so the values glide one place along
        const key = shifted ? (i === 0 ? 'cr:na' + shifted : i === 4 ? 'cr:ne' + shifted : 'cr:r' + (i - 1) + '-' + (shifted - 1)) : 'cr:r' + i + '-' + (fresh || 0);
        items.push(Object.assign(U.val(key, regX(i), regY, 100, NAMES[i], h8(vals[i]), (lit && lit.includes(i) ? 'src' : '') + (shifted && (i === 0 || i === 4) ? ' hot' : '')), {}));
      }
      return items;
    };
    // the two sums as data flow, as on the demo page
    const net = (r, stage) => {
      const N = S.Kit.flow.net('cn'), on = (s) => stage >= s, a = (s) => (stage === s ? 'act' : '');
      const vb = (name, v, s) => [name, on(s) ? h8(v) : ''];
      const yIn = 196, yAdd = 270, yT = 336, yL = 408, yE = 470, tt = r.t;
      const xs = [330, 450, 570, 690, 810];
      [['h', r.before[7]], ['Σ1(e)', r.sig1], ['Ch(e,f,g)', r.ch], ['K' + sub(tt), r.K], ['W' + sub(tt), r.W]].forEach(([n, v], j) => N.box('i' + j, xs[j], yIn, 104, 50, vb(n, v, 1), 'val2' + (j >= 3 ? ' key' : '') + (stage === 1 ? ' act' : !on(1) ? ' soft' : '')));
      for (let j = 1; j < 5; j++) N.op('p' + j, xs[j], yAdd, 'add', a(1));
      N.wire('i0', [N.port('i0', 's'), [xs[0], yAdd], N.port('p1', 'w')], { head: true, cls: a(1) });
      for (let j = 1; j < 5; j++) N.wire('i' + j, [N.port('i' + j, 's'), N.port('p' + j, 'n')], { head: true, cls: a(1) });
      for (let j = 1; j < 4; j++) N.wire('c' + j, [N.port('p' + j, 'e'), N.port('p' + (j + 1), 'w')], { head: true, cls: a(1) });
      N.box('T1', xs[4], yT, 104, 50, vb('T1', r.T1, 1), 'val2' + (stage === 1 ? ' hot' : !on(1) ? ' soft' : ''));
      N.wire('t1', [N.port('p4', 's'), N.port('T1', 'n')], { head: true, cls: a(1) });
      N.box('s0', 74, yIn, 104, 50, vb('Σ0(a)', r.sig0, 2), 'val2' + (stage === 2 ? ' act' : !on(2) ? ' soft' : ''));
      N.box('mj', 194, yIn, 104, 50, vb('Maj(a,b,c)', r.maj, 2), 'val2' + (stage === 2 ? ' act' : !on(2) ? ' soft' : ''));
      N.op('q', 134, yAdd, 'add', a(2));
      N.wire('s0', [N.port('s0', 's'), [74, yAdd], N.port('q', 'w')], { head: true, cls: a(2) });
      N.wire('mj', [N.port('mj', 's'), [194, yAdd], N.port('q', 'e')], { head: true, cls: a(2) });
      N.box('T2', 134, yT, 104, 50, vb('T2', r.T2, 2), 'val2' + (stage === 2 ? ' hot' : !on(2) ? ' soft' : ''));
      N.wire('t2', [N.port('q', 's'), N.port('T2', 'n')], { head: true, cls: a(2) });
      N.op('na', 330, yL, 'add', a(3));
      N.op('ne', 690, yE, 'add', a(3));
      N.wire('T1', [N.port('T1', 's'), [xs[4], yL], N.port('na', 'e')], { head: true, cls: a(3) });
      N.dot(690, yL, stage === 3 ? 'act' : '');
      N.wire('T1e', [[690, yL], N.port('ne', 'n')], { head: true, cls: a(3) });
      N.wire('T2a', [N.port('T2', 's'), [134, yL], N.port('na', 'w')], { head: true, cls: a(3) });
      N.box('d', 570, yE, 104, 50, vb('d', r.before[3], 3), 'val2' + (stage === 3 ? ' act' : !on(3) ? ' soft' : ''));
      N.wire('d', [N.port('d', 'e'), N.port('ne', 'w')], { head: true, cls: a(3) });
      N.box('oa', 330, 500, 104, 50, vb('new a', r.regs[0], 3), 'val2' + (on(3) ? ' hot' : ' soft'));
      N.box('oe', 810, yE, 104, 50, vb('new e', r.regs[4], 3), 'val2' + (on(3) ? ' hot' : ' soft'));
      N.wire('oa', [N.port('na', 's'), N.port('oa', 'n')], { head: true, cls: a(3) });
      N.wire('oe', [N.port('ne', 'e'), N.port('oe', 'w')], { head: true, cls: a(3) });
      return N.items;
    };
    // the 64 rounds as a strip, the rounds done lit
    const strip = (done, cur) => {
      const items = [t('cs:t', 20, 590, 'rounds', 'ptitle')];
      for (let j = 0; j < 64; j++) items.push({ key: 'cs:' + j, kind: 'cell', x: 20 + j * 13.9, y: 600, w: 12, h: 18, rx: 2, text: '', cls: 'hex ' + (j === cur ? 'hot' : j < done ? 'p12-b1' : 'p12-b0') });
      items.push(t('cs:n0', 20, 638, '0', 'ptick', 'start', 13), t('cs:n63', 20 + 63 * 13.9 + 12, 638, '63', 'ptick', 'end', 13));
      return items;
    };
    // inside Ch and Maj, bit by bit (the first 16 bits)
    const bitwise = (r) => {
      const items = [], cw = 15, x0 = 120;
      const row = (pre, y, name, v, cls) => {
        items.push(t(pre + ':n', x0 - 14, y + 14, name, cls || 'ptick', 'end', 13));
        bitsOf(v).slice(0, 16).forEach((b, i) => items.push({ key: pre + ':' + i, kind: 'cell', x: x0 + i * (cw + 2) + Math.floor(i / 4) * 5, y, w: cw, h: 19, rx: 2, text: String(b), size: 13, cls: 'bit ' + (b ? 'one' : 'zero') + (cls === 'hot' ? ' hot' : cls === 'src' ? ' src' : '') }));
        items.push(t(pre + ':h', x0 + 16 * (cw + 2) + 20, y + 14, h8(v).slice(0, 4) + '…', 'mono', 'start', 13));
      };
      items.push(t('bw:t1', 20, 186, 'Ch(e, f, g): where e has a 1, take f; where it has a 0, take g (first 16 bits)', 'ptitle'));
      row('bw:e', 200, 'e', r.before[4], 'src'); row('bw:f', 224, 'f', r.before[5]); row('bw:g', 248, 'g', r.before[6]); row('bw:c', 276, 'Ch', r.ch, 'hot');
      items.push(t('bw:t2', 20, 340, 'Maj(a, b, c): each bit is the majority of three (first 16 bits)', 'ptitle'));
      row('bw:a', 354, 'a', r.before[0]); row('bw:b', 378, 'b', r.before[1]); row('bw:cc', 402, 'c', r.before[2]); row('bw:m', 430, 'Maj', r.maj, 'hot');
      return items;
    };
    const F = new S.Frames(['round']);
    const head = U.head('cm:h', 'SHA-256 compression of block ' + (k + 1) + (nb > 1 ? ' of ' + nb : ''), 'eight 32-bit registers, 64 rounds, then the feed-forward');
    F.add({ items: [...head, ...regs(cvIn, null, 0, 0), ...strip(0, -1)], hl: { d: [0] }, say: `The registers a…h start as the chaining value${k ? ' left by block ' + k : ', the IV'}: a = ${h8(cvIn[0])}, …, h = ${h8(cvIn[7])}. Each of the 64 rounds reads all eight, one schedule word Wₜ and one constant Kₜ.`, facts: { cv: cvIn.map(h8), k: k + 1 }, meta: { stage: 'start' } });
    const show = [r0, r0 + 1, r0 + 2].filter((x) => x < 64);
    let key = 0;
    for (const rr of show) {
      const r = R[rr];
      const prevVals = rr === r0 ? (rr ? R[rr - 1].regs : cvIn) : r.before;
      if (rr === r0 && rr > 0) { F.set('round', rr); F.add({ items: [...head, ...regs(prevVals, null, 0, key), ...strip(rr, -1)], hl: { d: [0] }, say: `Fast-forward to round ${rr}: after ${U.plural(rr, 'round')} the registers hold a = ${h8(prevVals[0])} … h = ${h8(prevVals[7])}.`, facts: { rr, a: h8(prevVals[0]), h: h8(prevVals[7]) }, meta: { stage: 'jump' } }); }
      if (rr === r0) F.add({ items: [...head, ...regs(r.before, [4, 5, 6, 0, 1, 2], 0, key), ...bitwise(r), ...strip(rr, rr)], hl: { d: [2, 3] }, say: `Two of the functions work bit by bit. Ch(e, f, g) = ${h8(r.ch)}: e chooses, at each bit, f (where e is 1) or g (where e is 0). Maj(a, b, c) = ${h8(r.maj)}: the majority vote of a, b and c at each bit.`, facts: { ch: h8(r.ch), maj: h8(r.maj) }, meta: { stage: 'bitwise', rr } });
      F.set('round', rr);
      F.add({ items: [...head, ...regs(r.before, [4, 5, 6, 7], 0, key), ...net(r, 1), ...strip(rr, rr)], hl: { d: [1, 2] }, say: `Round ${rr}: T1 = h + Σ1(e) + Ch(e, f, g) + K${sub(rr)} + W${sub(rr)} = ${h8(r.before[7])} + ${h8(r.sig1)} + ${h8(r.ch)} + ${h8(r.K)} + ${h8(r.W)} = ${h8(r.T1)}, modulo 2³².`, facts: { rr, terms: [r.before[7], r.sig1, r.ch, r.K, r.W].map(h8), T1: h8(r.T1) }, meta: { stage: 'T1', rr } });
      F.add({ items: [...head, ...regs(r.before, [0, 1, 2], 0, key), ...net(r, 2), ...strip(rr, rr)], hl: { d: [3] }, say: `T2 = Σ0(a) + Maj(a, b, c) = ${h8(r.sig0)} + ${h8(r.maj)} = ${h8(r.T2)}.`, facts: { rr, sig0: h8(r.sig0), maj: h8(r.maj), T2: h8(r.T2) }, meta: { stage: 'T2', rr } });
      F.add({ items: [...head, ...regs(r.before, [3], 0, key), ...net(r, 3), ...strip(rr, rr)], hl: { d: [4] }, say: `New a = T1 + T2 = ${h8(r.regs[0])}; new e = d + T1 = ${h8(r.before[3])} + ${h8(r.T1)} = ${h8(r.regs[4])}.`, facts: { rr, a: h8(r.regs[0]), d: h8(r.before[3]), e: h8(r.regs[4]), T1: h8(r.T1) }, meta: { stage: 'new', rr } });
      F.count('round');
      F.add({ items: [...head, ...regs(r.regs, null, key + 1, key), ...net(r, 4), ...strip(rr + 1, -1)], hl: { d: [5] }, say: `Every other register moves one place: b takes the old a (${h8(r.before[0])}), c the old b, d the old c, f the old e, g the old f, h the old g; the old h, ${h8(r.before[7])}, is dropped. Only registers a and e are computed fresh.`, facts: { rr, olda: h8(r.before[0]), oldh: h8(r.before[7]) }, meta: { stage: 'shift', rr } });
      key++;
    }
    // the end of the 64 rounds, and the feed-forward
    const end = R[63].regs, out = c.H;
    F.set('round', 64);
    F.add({ items: [...head, ...regs(end, null, 0, 99), ...strip(64, -1)], hl: { d: [0] }, say: `After all 64 rounds the registers hold a = ${h8(end[0])} … h = ${h8(end[7])}. They look nothing like where they started.`, facts: { a: h8(end[0]), h: h8(end[7]) }, meta: { stage: 'after' } });
    const ff = () => {
      const items = [];
      const rows = [['chaining value in', cvIn, 'key'], ['after 64 rounds', end, ''], ['sum, mod 2³²', out, 'hot']];
      rows.forEach(([lab, vals, cls], j) => {
        const y = 210 + j * 76;
        items.push(t('ff:l' + j, 20, y - 8, lab, 'ptitle'));
        vals.forEach((v, i) => items.push({ key: 'ff:' + j + '-' + i, kind: 'cell', x: 20 + i * 112, y, w: 104, h: 34, rx: 5, text: h8(v), size: 14, cls: 'hex ' + cls }));
        if (j === 1) for (let i = 0; i < 8; i++) items.push(t('ff:p' + i, 72 + i * 112, y - 26, '+', 'strong', 'middle', 15));
      });
      return items;
    };
    F.add({ items: [...head, ...regs(end, null, 0, 99), ...ff(), ...strip(64, -1)], hl: { d: [6] }, say: `The feed-forward: add the chaining value that came in, word by word: ${h8(cvIn[0])} + ${h8(end[0])} = ${h8(out[0])}, and so on. Without it the 64 rounds could be run backwards from the output, and finding preimages of f would be easy.`, facts: { cv0: h8(cvIn[0]), end0: h8(end[0]), out0: h8(out[0]) }, meta: { stage: 'ff' } });
    const isLast = k === nb - 1, dg = out.map(h8).join('');
    F.add({ items: [...head, ...regs(out, null, 0, 98), ...ff(), ...strip(64, -1)], hl: { d: [6] }, say: isLast ? `That was the last block, so the new chaining value is the SHA-256 digest: ${U.spaced(dg)}.` : `This is the chaining value for block ${k + 2}: ${U.spaced(dg)}. ${U.cap(U.plural(nb - k - 1, 'more compression'))} and the last chaining value is the digest.`, facts: { dg, digest: U.hex(run.digest), k: k + 2, more: nb - k - 1 }, meta: { stage: 'out' } });
    U.fix(F.list);
    return {
      frames: F.list, def: U.def('One round of SHA-256 (mod 2³²)', ['registers a…h, from the chaining value', 'T1 = h + Σ1(e) + Ch(e,f,g) + Kₜ + Wₜ', 'Ch(e,f,g) = (e ∧ f) ⊕ (¬e ∧ g);  Σ1(e) = ROTR⁶ ⊕ ROTR¹¹ ⊕ ROTR²⁵', 'T2 = Σ0(a) + Maj(a,b,c);  Maj = (a∧b) ⊕ (a∧c) ⊕ (b∧c)', 'a ← T1 + T2,  e ← d + T1', 'h←g, g←f, f←e, d←c, c←b, b←a', 'after 64 rounds: H ← H + (a, …, h)']),
    };
  }
  S.topic({
    id: 'p12-compress', family: 'p12-md', order: 30, title: 'The SHA-256 compression function, round by round',
    blurb: 'Eight registers, two sums each round, and a shift down one place: only a and e are new. Follow three rounds from any point, then the feed-forward that adds the chaining value back in.',
    inputs: [msgInput, blockInput, { id: 'round', kind: 'number', label: 'Start at round', def: 0, min: 0, max: 61 }],
    presets: [
      { label: 'Rounds 0 to 2', values: { msg: 'Sifer hashes this line, one round at a time.', block: 1, round: 0 } },
      { label: 'Rounds 30 to 32', values: { msg: 'Sifer hashes this line, one round at a time.', block: 1, round: 30 } },
      { label: 'The empty message', values: { msg: '', block: 1, round: 0 } },
      { label: 'Last rounds of block 2', values: { msg: 'Fifty-six bytes leave no room for the length: two blocks', block: 2, round: 61 } },
    ],
    counters: [{ id: 'round', label: 'rounds done' }],
    run: compress,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'new', pick: 'option', options: ['all eight', 'two: a and e', 'four', 'only h'], ask: 'How many registers get a freshly computed value in this round?', answer: 'two: a and e', explain: 'The rest only move one place along.' },
      { at: (f) => f.meta && f.meta.stage === 'T1', pick: 'item', ask: 'Which register value will be dropped at the end of this round? Click it.', answer: (fr, i) => ['cr:r7-' + fr.slice(0, i).filter((f) => f.meta && f.meta.stage === 'shift').length], explain: 'h is added into T1 and then falls off the end.' },
    ],
    quiz: [
      { q: 'How many registers does a SHA-256 round compute from scratch?', options: ['8', '4', '2', '1'], answer: 2, why: 'a = T1 + T2 and e = d + T1; the others shift.' },
      { q: 'What does Ch(e, f, g) compute?', options: ['the majority of e, f, g', 'f where e is 1 and g where e is 0', 'e ⊕ f ⊕ g', 'e + f + g'], answer: 1, why: 'e chooses between f and g bit by bit.' },
      { q: 'Why is the chaining value added back after the 64 rounds?', options: ['to make the output longer', 'otherwise the rounds, which are invertible, could be run backwards and f would be easy to invert', 'for the length padding', 'to save memory'], answer: 1, why: 'The round function is a permutation of the state for a fixed message; the feed-forward makes f one-way.' },
      { q: 'Where do the constants Kₜ come from?', options: ['random choice', 'the cube roots of the first 64 primes', 'π', 'the IV'], answer: 1, why: 'The first 32 bits of the fractional parts of the cube roots of the first 64 primes: nothing up the sleeve.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
