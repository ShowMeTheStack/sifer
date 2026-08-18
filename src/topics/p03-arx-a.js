// Part 3, Salsa20 and ChaCha20: the 4×4 state of 32-bit words with the role of every word coloured, Salsa20's
// quarter-round (add, rotate, XOR into a third word) on the columns and then the rows, and ChaCha20's quarter-round
// as an add–rotate–XOR network beside the bits of its four words, then on the columns and the diagonals.
// S.P03b holds the word-grid helper that p03-arx-b.js shares.
(function (S) {
  'use strict';
  const U = S.SymT, h8 = U.h8;
  const W = (S.P03b = S.P03b || {});
  const xs = (i) => 'x' + U.sub(i);

  /**
   * The 4×4 state as cells of hex words, each with its name above the value. o: {prefix, x, y, words, role(i) -> class,
   * cls(i) -> extra class, cw, ch, gap, title, names: false}
   */
  W.grid = function (o) {
    const P = o.prefix || 'wg', cw = o.cw || 112, ch = o.ch || 56, gap = o.gap === undefined ? 8 : o.gap, items = [];
    if (o.title) items.push(U.t(P + ':title', o.x, o.y - 12, o.title, 'title', 'start', 14));
    o.words.forEach((v, i) => {
      const r = Math.floor(i / 4), c = i % 4, cls = [o.role ? o.role(i) || '' : '', o.cls ? o.cls(i) || '' : ''].join(' ');
      items.push({ key: P + ':' + i, kind: 'cell', x: o.x + c * (cw + gap), y: o.y + r * (ch + gap), w: cw, h: ch, rx: 5, lines: o.names === false ? undefined : [xs(i), h8(v)], text: o.names === false ? h8(v) : undefined, size: o.size || 16, cls: 'hex ' + cls });
    });
    return { items, box: { x: o.x, y: o.y, w: 4 * cw + 3 * gap, h: 4 * ch + 3 * gap }, centre: (i) => ({ x: o.x + (i % 4) * (cw + gap) + cw / 2, y: o.y + Math.floor(i / 4) * (ch + gap) + ch / 2 }) };
  };
  /** a small 4×4 map: which quarter-round of a round touches each word (groups: four lists of indices) */
  W.groupMap = function (prefix, x, y, groups, title, mark) {
    const items = [U.t(prefix + ':t', x, y - 10, title, 'title', 'start', 14)], cls = ['act', 'hot', 'key', 'src'];
    for (let i = 0; i < 16; i++) {
      const g = groups.findIndex((q) => q.includes(i)), pos = groups[g].indexOf(i);
      items.push({ key: prefix + ':' + i, kind: 'cell', x: x + (i % 4) * 50, y: y + Math.floor(i / 4) * 38, w: 46, h: 34, rx: 4, text: (mark || 'QR') + (g + 1) + 'abcd'[pos], size: 13, cls: 'bit ' + cls[g] });
    }
    return items;
  };
  /** keep a legend only on the frames whose stage is listed (where the roles are drawn) */
  W.dropLegend = (frames, prefix, keep) => { for (const f of frames) if (!keep.includes(f.meta.stage)) f.items = f.items.filter((it) => !it.key.startsWith(prefix)); };
  /** the bits that differ between two lists of words */
  W.diffBits = (a, b) => a.reduce((n, v, i) => n + U.pop((v ^ b[i]) >>> 0), 0);
  /** the role of each word of a ChaCha20 state */
  W.chachaRole = (i) => (i < 4 ? 'wconst' : i < 12 ? 'key' : i === 12 ? 'wctr' : 'wnonce');
  W.salsaRole = (i) => ([0, 5, 10, 15].includes(i) ? 'wconst' : [6, 7].includes(i) ? 'wnonce' : [8, 9].includes(i) ? 'wctr' : 'key');
  W.textCheck = (label, n) => (v) => (S.bytes.utf8(String(v)).length === n ? null : label + ': exactly ' + n + ' bytes of text (now ' + S.bytes.utf8(String(v)).length + ')');
  W.legend = (prefix, x, y, salsa) => U.legend(prefix, x, y, [['wconst', 'constants'], ['key', 'key'], ['wctr', 'counter'], ['wnonce', 'nonce']]);

  // ---------------------------------------------------------------------------------------------------------------
  // Salsa20
  // ---------------------------------------------------------------------------------------------------------------
  function salsa(inp) {
    const key = S.bytes.utf8(inp.key), nonce = S.bytes.utf8(inp.nonce), ctr = inp.counter, Sa = S.Salsa;
    const blk = Sa.block(key, nonce, ctr), st = blk.state;
    const F = new S.Frames(), head = U.head('sa:h', 'Salsa20: the state and its quarter-round');
    const gx = 24, gy = 78;
    const grid = (words, cls) => W.grid({ prefix: 'sa', x: gx, y: gy, words, role: words === st ? W.salsaRole : null, cls, title: words === st ? 'the state, sixteen 32-bit words' : 'the working state' }).items;
    const side = (title, rows) => U.readout('sa:r', 536, 64, 360, title, rows, { dy: 32 });
    const lower = (lines) => [...U.panel('sa:p', 24, 360, 872, Math.max(190, 56 + lines.rows.length * 34), lines.title), ...lines.rows.map(([t, c], j) => U.t('sa:pl' + j, 44, 410 + j * 34, t, c || 'math', 'start', 17))];
    const leg = W.legend('sa:lg', 536, 330);
    F.add({ items: [head, ...grid(st), ...leg, ...side('what goes in', [['key (32 bytes)', U.show(key).slice(0, 18) + '…', 'key'], ['nonce (8 bytes)', U.hex(nonce), ''], ['block counter (64 bits)', String(ctr), 'hot'], ['constants', '“expand 32-byte k”', '']]), ...lower({ title: 'the layout', rows: [['x₀ x₅ x₁₀ x₁₅  constants, on the diagonal'], ['x₁…x₄, x₁₁…x₁₄  the key'], ['x₆ x₇  the nonce;  x₈ x₉  the block counter']] })],
      say: `Salsa20 fills a 4×4 grid of 32-bit words: the four constants spelling “expand 32-byte k” on the diagonal (${[0, 5, 10, 15].map((i) => h8(st[i])).join(', ')}), the eight words of the key around them, and in the middle the nonce (${h8(st[6])} ${h8(st[7])}) and the 64-bit block counter (${h8(st[8])} ${h8(st[9])}, that is ${ctr}).`,
      facts: { c: [0, 5, 10, 15].map((i) => h8(st[i])), n: [h8(st[6]), h8(st[7])], k: [h8(st[8]), h8(st[9])], ctr }, meta: { stage: 'state' } });
    // the first column quarter-round, step by step
    const q = Sa.COLUMNS[0], qr = Sa.qr(...q.map((i) => st[i])), names = 'abcd';
    F.add({ items: [head, ...grid(st, (i) => (q.includes(i) ? 'act' : 'dim')), ...leg, ...side('quarter-round on column 0', q.map((i, k) => [names[k] + ' = ' + xs(i), h8(st[i]), 'act'])), ...lower({ title: 'the quarter-round', rows: [['b ^= (a + d) <<< 7'], ['c ^= (b + a) <<< 9'], ['d ^= (c + b) <<< 13'], ['a ^= (d + c) <<< 18']] })],
      hl: { d: [1] }, say: `A quarter-round works on four words. The column round starts each column at its diagonal word, so the first takes a = ${xs(0)}, b = ${xs(4)}, c = ${xs(8)}, d = ${xs(12)}: ${q.map((i) => h8(st[i])).join(', ')}. Each of its four steps adds two words, rotates the sum and XORs it into a third.`,
      facts: { w: q.map((i) => h8(st[i])) }, meta: { stage: 'column' } });
    let cur = st.slice();
    qr.trace.forEach((tr, k) => {
      const tgt = q[tr.t], src = [q[tr.x], q[tr.y]];
      cur = cur.slice(); cur[tgt] = tr.after;
      F.add({ items: [head, ...grid(cur, (i) => (i === tgt ? 'hot' : src.includes(i) ? 'act' : q.includes(i) ? '' : 'dim')), ...leg, ...side('step ' + (k + 1) + ' of 4', [[names[tr.x] + ' + ' + names[tr.y] + ' (mod 2³²)', h8(tr.sum), 'act'], ['rotated left ' + tr.r, h8(tr.rot), 'act'], [names[tr.t] + ' before', h8(tr.before)], [names[tr.t] + ' after', h8(tr.after), 'hot']]),
        ...lower({ title: 'step ' + (k + 1), rows: [[`${names[tr.t]} ^= (${names[tr.x]} + ${names[tr.y]}) <<< ${tr.r}`], [`${h8(cur[src[0]])} + ${h8(cur[src[1]])} = ${h8(tr.sum)}`], [`${h8(tr.sum)} <<< ${tr.r} = ${h8(tr.rot)}`], [`${h8(tr.before)} ⊕ ${h8(tr.rot)} = ${h8(tr.after)}`, 'math hot']] })],
        hl: { d: [1] }, say: `Step ${k + 1}: ${names[tr.t]} ^= (${names[tr.x]} + ${names[tr.y]}) <<< ${tr.r}. The sum ${h8(tr.sum)}, rotated left by ${tr.r} bits, is ${h8(tr.rot)}; XORed into ${names[tr.t]} = ${h8(tr.before)} it gives ${h8(tr.after)}.` + (k === 0 ? ' Addition mixes bits upward through the carries; the rotation moves them sideways; XOR combines without loss.' : ''),
        facts: { k: k + 1, r: tr.r, sum: h8(tr.sum), rot: h8(tr.rot), before: h8(tr.before), after: h8(tr.after) }, meta: { stage: 'step', k } });
    });
    // the whole column round, then the row round (the engine's first double round)
    const col = st.slice();
    for (const g of Sa.COLUMNS) { const o = Sa.qr(...g.map((i) => col[i])).out; g.forEach((i, j) => { col[i] = o[j]; }); }
    const colOf = (i) => Sa.COLUMNS.findIndex((g) => g.includes(i)), rowOf = (i) => Sa.ROWS.findIndex((g) => g.includes(i));
    F.add({ items: [head, ...grid(col), ...leg, ...side('after the column round', [['quarter-rounds', '4, one per column'], ['bits changed from the start', String(W.diffBits(st, col))], [xs(0), h8(col[0]), 'hot']]), ...lower({ title: 'the column round', rows: [['(x₀, x₄, x₈, x₁₂)  (x₅, x₉, x₁₃, x₁)'], ['(x₁₀, x₁₄, x₂, x₆)'], ['(x₁₅, x₃, x₇, x₁₁)'], ['each column starts at its diagonal word']] }), ...W.groupMap('sa:gm', 676, 420, Sa.COLUMNS, 'column round')],
      hl: { d: [2] }, say: `The same quarter-round runs on all four columns, each starting from its diagonal word: (${xs(0)}, ${xs(4)}, ${xs(8)}, ${xs(12)}), (${xs(5)}, ${xs(9)}, ${xs(13)}, ${xs(1)}) and so on. After this column round ${W.diffBits(st, col)} of the 512 bits differ from the start, and ${xs(0)} is ${h8(col[0])}.`,
      facts: { d: W.diffBits(st, col), x0: h8(col[0]) }, meta: { stage: 'colround' } });
    const r1 = blk.rounds[0];
    F.add({ items: [head, ...grid(r1), ...leg, ...side('after the row round', [['quarter-rounds', '4, one per row'], ['bits changed from the start', String(W.diffBits(st, r1))], [xs(0), h8(r1[0]), 'hot']]), ...lower({ title: 'the row round', rows: [['(x₀, x₁, x₂, x₃)  (x₅, x₆, x₇, x₄)'], ['(x₁₀, x₁₁, x₈, x₉)'], ['(x₁₅, x₁₂, x₁₃, x₁₄)'], ['column round + row round = one double round']] }), ...W.groupMap('sa:gm', 676, 420, Sa.ROWS, 'row round')],
      hl: { d: [2] }, say: `Then the rows, again each from its diagonal word: (${xs(0)}, ${xs(1)}, ${xs(2)}, ${xs(3)}), (${xs(5)}, ${xs(6)}, ${xs(7)}, ${xs(4)}) and so on. A column round and a row round make a double round; after just one, ${W.diffBits(st, r1)} of the 512 bits have changed and every word depends on every other.`,
      facts: { d: W.diffBits(st, r1), x0: h8(r1[0]) }, meta: { stage: 'rowround', rowOf: rowOf(0) } });
    const r10 = blk.rounds[9];
    F.add({ items: [head, ...grid(r10), ...leg, ...side('after 10 double rounds', [['rounds', '20'], ['bits changed from the start', String(W.diffBits(st, r10))], [xs(0), h8(r10[0]), 'hot']]), ...lower({ title: 'twenty rounds', rows: [['10 × (column round, row round)'], ['each round is invertible:'], ['without a last step it could be run backwards to the key', 'math hot']] })],
      hl: { d: [3] }, say: `Ten double rounds, twenty rounds in all. ${W.diffBits(st, r10)} of the 512 bits now differ from the starting state, close to the 256 of a random change. But every step so far can be undone: from this state alone, anyone could run the rounds backwards and read off the key.`,
      facts: { d: W.diffBits(st, r10), x0: h8(r10[0]) }, meta: { stage: 'rounds' } });
    F.add({ items: [head, ...grid(blk.words, () => 'hot'), ...leg, ...side('the keystream block', [['= after 20 rounds ⊞ input', 'word by word'], [xs(0), h8(r10[0]) + ' ⊞ ' + h8(st[0]), ''], ['', '= ' + h8(blk.words[0]), 'hot'], ['first bytes (little-endian)', U.hex(blk.out.slice(0, 8)), 'act']]), ...lower({ title: 'adding the input back', rows: [['keystream word i = round output i + input word i (mod 2³²)'], ['the key is now on both sides of an addition with an unknown:'], ['the rounds can no longer be undone'], ['64 bytes of keystream; the next block uses counter ' + (ctr + 1)]] })],
      hl: { d: [4] }, say: `So the input is added back, word by word modulo 2³²: ${xs(0)} becomes ${h8(r10[0])} + ${h8(st[0])} = ${h8(blk.words[0])}. Now the key sits on both sides of the sum and the rounds cannot be run backwards. Written out little-endian, the sixteen words are 64 bytes of keystream starting ${U.hex(blk.out.slice(0, 8))}; the next block uses counter ${ctr + 1}.`,
      facts: { a: h8(r10[0]), b: h8(st[0]), w: h8(blk.words[0]), out: U.hex(blk.out.slice(0, 8)), next: ctr + 1 }, meta: { stage: 'add' } });
    W.dropLegend(F.list, 'sa:lg', ['state', 'column']);
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 634 });
    return { frames: F.list, def: U.def('Salsa20', ['state: constants on the diagonal, key, nonce, 64-bit counter', 'quarter-round: b ^= (a+d)<<<7, c ^= (b+a)<<<9,', '               d ^= (c+b)<<<13, a ^= (d+c)<<<18', 'double round: 4 column quarter-rounds, then 4 row quarter-rounds', '20 rounds = 10 double rounds', 'keystream block = rounds(input) ⊞ input, 64 bytes']) };
  }
  S.topic({
    id: 'st-salsa', family: 'p03-arx', order: 10, title: 'Salsa20: add, rotate, XOR',
    blurb: 'A 4×4 grid of words with the constants on its diagonal. Its quarter-round only adds, rotates and XORs; twenty rounds and one final addition of the input turn key, nonce and counter into 64 bytes of keystream.',
    inputs: [
      { id: 'key', kind: 'string', spaces: true, label: 'Key (32 bytes of text)', def: 'dune grass bends to the sea wind', check: W.textCheck('Key', 32) },
      { id: 'nonce', kind: 'string', spaces: true, label: 'Nonce (8 bytes)', def: 'kelp-07!', check: W.textCheck('Nonce', 8) },
      { id: 'counter', kind: 'number', label: 'Block counter', def: 0, min: 0, max: 1000000 },
    ],
    presets: [
      { label: 'Block 0', values: { key: 'dune grass bends to the sea wind', nonce: 'kelp-07!', counter: 0 } },
      { label: 'Block 1, same key', values: { key: 'dune grass bends to the sea wind', nonce: 'kelp-07!', counter: 1 } },
      { label: 'Another key', values: { key: 'otters nap in kelp beds at dusk.', nonce: 'kelp-07!', counter: 0 } },
      { label: 'Another nonce', values: { key: 'dune grass bends to the sea wind', nonce: 'kelp-08!', counter: 0 } },
    ],
    run: salsa,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'state', pick: 'option', options: ['x₀, x₄, x₈, x₁₂', 'x₀, x₁, x₂, x₃', 'x₀, x₅, x₁₀, x₁₅'], ask: 'The first quarter-round of the column round works on which four words?', answer: 'x₀, x₄, x₈, x₁₂', explain: 'The first column, starting at its diagonal word x₀.' },
      { at: (f) => f.meta && f.meta.stage === 'rounds', pick: 'option', options: ['to make the output longer', 'so the rounds cannot be run backwards to the key', 'to add the counter', 'it is not needed'], ask: 'Next the input state is added to the output of the rounds. Why?', answer: 'so the rounds cannot be run backwards to the key', explain: 'The rounds are a permutation; adding the input makes the whole a one-way function of the key.' },
    ],
    quiz: [
      { q: 'Which three operations make up Salsa20?', options: ['Addition modulo 2³², rotation and XOR', 'S-boxes, shifts and XOR', 'Multiplication, rotation and AND', 'Table lookups only'], answer: 0, why: 'Add–rotate–XOR (ARX): fast on any CPU and free of table lookups that leak through caches.' },
      { q: 'Where are the four constants in the Salsa20 state?', options: ['The first row', 'The diagonal', 'The last column', 'Mixed with the key'], answer: 1, why: 'x₀, x₅, x₁₀ and x₁₅.' },
      { q: 'How many rounds does Salsa20 run for one block?', options: ['10', '12', '20', '64'], answer: 2, why: 'Ten double rounds of a column round and a row round.' },
      { q: 'What changes from one 64-byte block to the next under the same key and nonce?', options: ['The constants', 'The block counter', 'The key', 'Nothing'], answer: 1, why: 'x₈ and x₉ count blocks, so each block has its own state and keystream.' },
      { q: 'Where is the nonlinearity in Salsa20?', options: ['In XOR', 'In the carries of the additions', 'In the rotations', 'There is none'], answer: 1, why: 'Over GF(2), XOR and rotation are linear; addition with carries is not.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The ChaCha20 quarter-round and double round
  // ---------------------------------------------------------------------------------------------------------------
  const GROUPS = [['c0', 'column 1', 0, 0], ['c1', 'column 2', 0, 1], ['c2', 'column 3', 0, 2], ['c3', 'column 4', 0, 3], ['d0', 'diagonal 1', 1, 0], ['d1', 'diagonal 2', 1, 1], ['d2', 'diagonal 3', 1, 2], ['d3', 'diagonal 4', 1, 3]];
  function chachaQr(inp) {
    const C = S.ChaCha, key = S.bytes.utf8(inp.key), nonce = S.bytes.utf8(inp.nonce), ctr = inp.counter;
    const st = C.state(key, ctr, nonce), [, gname, diag, gi] = GROUPS.find((g) => g[0] === inp.group);
    const col = st.slice();
    for (const g of C.COLUMNS) { const o = C.qr(...g.map((i) => col[i])).out; g.forEach((i, j) => { col[i] = o[j]; }); }
    const blk = C.block(key, ctr, nonce), dbl = blk.rounds[0];
    const idx = (diag ? C.DIAGONALS : C.COLUMNS)[gi], from = diag ? col : st, init = idx.map((i) => from[i]), q = C.qr(...init);
    const F = new S.Frames(), head = U.head('cq:h', 'ChaCha20: the quarter-round on ' + gname);
    const N_ = 'abcd';
    // the network: four lanes and twelve steps, as in the demo scene but on our stage
    const lx = [56, 136, 216, 296], y0 = 82, dy = 40, yOf = (k) => y0 + 22 + k * dy;
    const net = (at) => {
      const N = S.Kit.flow.net('cq');
      lx.forEach((x, t) => N.label('n' + t, x, 72, N_[t] + ' = ' + xs(idx[t]), at >= 0 && C.STEPS[at] && C.STEPS[at][1] === t ? 'act' : 'strong', 'middle', 14));
      const cuts = [[], [], [], []];
      C.STEPS.forEach(([op, t, s2], k) => {
        const y = yOf(k), x = lx[t], cur = k === at, done = k < at;
        if (op === 'rot') { N.box('r' + k, x, y, 60, 24, '<<< ' + s2, 'small ' + (cur ? 'act' : done ? '' : 'soft')); cuts[t].push([y - 12, y + 12]); }
        else { N.op('o' + k, x, y, op === 'add' ? 'add' : 'xor', cur ? 'act' : '', 11); cuts[t].push([y - 11, y + 11]); }
      });
      const hopsOn = [[], [], [], []];
      C.STEPS.forEach(([op, t, s2], k) => {
        if (op === 'rot') return;
        const y = yOf(k), xa = lx[s2], xt = lx[t], dir = Math.sign(xt - xa), cur = k === at;
        N.dot(xa, y, cur ? 'act' : '');
        const end = [xt - dir * 11, y], between = lx.filter((x) => (x - xa) * (x - xt) < 0);
        if (!between.length) { N.wire('s' + k, [[xa, y], end], { head: true, cls: cur ? 'act' : '' }); return; }
        let d = `M${xa},${y}`;
        for (const bx of between.sort((u, v) => dir * (u - v))) { d += ` L${bx - dir * 6},${y} A6,6 0 0 ${dir > 0 ? 1 : 0} ${bx + dir * 6},${y}`; hopsOn[lx.indexOf(bx)].push(y); }
        d += ` L${end[0]},${end[1]}`;
        N.add({ key: 'cq:hop' + k, kind: 'path', d, cls: 'hopwire' + (cur ? ' act' : ''), pathAudit: 'edge-x', layer: 'lines' });
        N.add({ key: 'cq:hh' + k, kind: 'wire', pts: [[end[0] - dir * 8, y], end], head: true, cls: 'tick ' + (cur ? 'act' : ''), audit: 'ignore' });
      });
      const top = 82, bot = yOf(11) + 34;
      for (let t = 0; t < 4; t++) {
        const x = lx[t], cs = cuts[t].sort((u, v) => u[0] - v[0]);
        let y = top, n = 0;
        for (const [a, b] of cs.concat([[bot, bot]])) {
          if (a - y > 1) { const crossed = hopsOn[t].some((hy) => hy > y && hy < a); N.wire('l' + t + '-' + n++, [[x, y], [x, a]], { head: a !== bot, cls: crossed ? 'hop' : '' }); }
          y = b;
        }
      }
      return N.items;
    };
    // the four words as bits, with the hex beside the name
    const px = 392, rowH = 128, bw = 12.6, bh = 22, ids = [0, 1, 2, 3].map(() => Array.from({ length: 32 }, (_, j) => j));
    const words = (k) => {
      const v = k < 0 ? init : q.trace[k].words, prev = k <= 0 ? init : q.trace[k - 1].words, step = k >= 0 ? C.STEPS[k] : null, items = [];
      if (step && step[0] === 'rot') { const t = step[1], n = step[2]; ids[t] = ids[t].slice(n).concat(ids[t].slice(0, n)); }
      for (let t = 0; t < 4; t++) {
        const y = 92 + t * rowH, tgt = step && step[1] === t, src = step && step[0] !== 'rot' && step[2] === t;
        const now = S.Kit.bytes.toBits(v[t], 32), was = S.Kit.bytes.toBits(prev[t], 32);
        items.push(U.t('cw:n' + t, px, y + 6, N_[t], tgt ? 'act' : src ? 'src' : 'strong', 'start', 18));
        items.push(U.t('cw:h' + t, px + 28, y + 6, h8(v[t]), 'mono ' + (tgt ? 'hot' : ''), 'start', 17));
        if (tgt) items.push(U.t('cw:was' + t, px + 140, y + 6, 'was ' + h8(prev[t]), 'tick', 'start', 14));
        let changed = 0;
        now.forEach((b, j) => {
          const ch = tgt && step[0] !== 'rot' && b !== was[j];
          if (ch) changed++;
          items.push({ key: `cb:${t}:${ids[t][j]}`, kind: 'cell', x: U.r2(px + j * (bw + 1) + Math.floor(j / 8) * 5), y: y + 20, w: bw, h: bh, rx: 2, text: '', cls: 'bit solid ' + (b ? 'one ' : '') + (ch ? 'hot' : tgt && step[0] === 'rot' ? 'act' : src ? 'src' : '') });
        });
        if (tgt && step[0] !== 'rot') items.push(U.t('cw:c' + t, px, y + 66, changed + ' of 32 bits changed', 'hot', 'start', 13));
      }
      if (step) items.push(U.t('cw:op', px, 44, `step ${k + 1}:  ${N_[step[1]]} ${step[0] === 'add' ? '+=' : step[0] === 'xor' ? '^=' : '<<<='} ${step[0] === 'rot' ? step[2] : N_[step[2]]}`, 'act', 'start', 16));
      return items;
    };
    const grid = (words2, cls) => W.grid({ prefix: 'cg', x: 24, y: 78, words: words2, role: words2 === st ? W.chachaRole : null, cls, title: words2 === st ? 'the state: constants, key, counter, nonce' : 'the working state' }).items;
    const side = (title, rows) => U.readout('cq:r', 536, 64, 360, title, rows, { dy: 32 });
    const leg = W.legend('cq:lg', 24, 370);
    F.add({ items: [head, ...grid(st, (i) => (idx.includes(i) ? 'act' : '')), ...leg, ...side('the quarter-rounds', [['double round', '8 quarter-rounds'], ['first: the columns', '(0,4,8,12) …'], ['then: the diagonals', '(0,5,10,15) …'], ['watching', gname, 'act'], ['its words', idx.map((i) => xs(i)).join(' '), 'act']]), ...W.groupMap('cq:gc', 24, 430, C.COLUMNS, 'column round', 'C'), ...W.groupMap('cq:gd', 290, 430, C.DIAGONALS, 'diagonal round', 'D')],
      say: `ChaCha20's state is a 4×4 grid of 32-bit words: the constants in the top row, the key in the next two rows, then the block counter (${ctr}) and three nonce words. A double round runs the quarter-round on the four columns, then on the four diagonals. We watch ${gname}: ${idx.map((i) => xs(i)).join(', ')}${diag ? ', taken after the column round' : ''}.`,
      facts: { ctr }, meta: { stage: 'state' } });
    F.add({ items: [head, ...net(-1), ...words(-1)], hl: { d: [1] }, say: `Its four words: a = ${h8(init[0])}, b = ${h8(init[1])}, c = ${h8(init[2])}, d = ${h8(init[3])}. Twelve steps follow: add (⊞, modulo 2³²), XOR and rotate, in that rhythm four times, with rotations of 16, 12, 8 and 7.`, facts: { w: init.map(h8) }, meta: { stage: 'words' } });
    q.trace.forEach((tr, k) => {
      const [op, t, s2] = C.STEPS[k], before = tr.before, after = tr.after;
      const changed = op === 'rot' ? 0 : U.pop((before ^ after) >>> 0);
      const say = op === 'add' ? `Step ${k + 1}: ${N_[t]} += ${N_[s2]}: ${h8(before)} + ${h8(tr.words[s2])} = ${h8(after)} modulo 2³²; ${changed} of ${N_[t]}'s 32 bits changed, some of them through carries.`
        : op === 'xor' ? `Step ${k + 1}: ${N_[t]} ^= ${N_[s2]}: ${h8(before)} ⊕ ${h8(tr.words[s2])} = ${h8(after)}; a bit flips exactly where ${N_[s2]} has a 1, ${changed} bits here.`
          : `Step ${k + 1}: ${N_[t]} <<<= ${s2}: ${h8(before)} rotated left by ${s2} is ${h8(after)}. No bit changes value; each moves ${s2} places, the top ${s2} wrapping round to the bottom.`;
      F.add({ items: [head, ...net(k), ...words(k)], hl: { d: [1] }, say, facts: { k: k + 1, before: h8(before), src: h8(tr.words[s2] === undefined ? 0 : tr.words[s2]), after: h8(after), changed, by: s2 }, meta: { stage: 'step', k } });
    });
    F.add({ items: [head, ...grid(col, (i) => (C.COLUMNS.flat().includes(i) ? (diag ? '' : idx.includes(i) ? 'hot' : '') : '')), ...leg, ...side('after the column round', [['quarter-rounds', '4'], ['bits changed from the start', String(W.diffBits(st, col))], diag ? ['', ''] : [gname + ' out', q.out.map(h8).slice(0, 2).join(' '), 'hot']].filter((r) => r[0])), ...W.groupMap('cq:gc', 24, 430, C.COLUMNS, 'column round', 'C')],
      hl: { d: [2] }, say: `The same quarter-round on all four columns, each on its own words, so the four could run at once. After this column round ${W.diffBits(st, col)} of the 512 state bits differ from the start${diag ? '' : `; ${gname} came out as ${q.out.map(h8).join(' ')}`}.`,
      facts: { d: W.diffBits(st, col), out: q.out.map(h8) }, meta: { stage: 'colround' } });
    F.add({ items: [head, ...grid(dbl, (i) => (diag && idx.includes(i) ? 'hot' : '')), ...leg, ...side('after the diagonal round', [['quarter-rounds', '4'], ['bits changed from the start', String(W.diffBits(st, dbl))], ['one double round', '2 of 20 rounds']]), ...W.groupMap('cq:gd', 290, 430, C.DIAGONALS, 'diagonal round', 'D')],
      hl: { d: [3] }, say: `Then the diagonals: (${xs(0)}, ${xs(5)}, ${xs(10)}, ${xs(15)}), (${xs(1)}, ${xs(6)}, ${xs(11)}, ${xs(12)}) and so on, so every word now depends on every other. After one double round ${W.diffBits(st, dbl)} of the 512 bits have changed; ChaCha20 runs ten.`,
      facts: { d: W.diffBits(st, dbl) }, meta: { stage: 'diag' } });
    W.dropLegend(F.list, 'cq:lg', ['state']);
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 620 });
    return { frames: F.list, def: U.def('The ChaCha20 quarter-round', ['a += b; d ^= a; d <<<= 16', 'c += d; b ^= c; b <<<= 12', 'a += b; d ^= a; d <<<= 8', 'c += d; b ^= c; b <<<= 7', 'double round: QR on 4 columns, then on 4 diagonals', '20 rounds = 10 double rounds']) };
  }
  S.topic({
    id: 'st-chacha-qr', family: 'p03-arx', order: 20, title: 'ChaCha20\'s quarter-round and double round',
    blurb: 'Twelve steps on four words, only add, XOR and rotate. Every word is updated twice, and a double round runs the quarter-round down the columns and then along the diagonals of the 4×4 state.',
    inputs: [
      { id: 'key', kind: 'string', spaces: true, label: 'Key (32 bytes of text)', def: 'a heron waits where reeds divide', check: W.textCheck('Key', 32) },
      { id: 'nonce', kind: 'string', spaces: true, label: 'Nonce (12 bytes)', def: 'shore#000042', check: W.textCheck('Nonce', 12) },
      { id: 'counter', kind: 'number', label: 'Block counter', def: 1, min: 0, max: 4294967295 },
      U.choice('group', 'Quarter-round to watch', 'c1', GROUPS.map((g) => [g[0], g[1]])),
    ],
    presets: [
      { label: 'Column 2', values: { group: 'c1' } },
      { label: 'Column 1', values: { group: 'c0' } },
      { label: 'Diagonal 1', values: { group: 'd0' } },
      { label: 'Diagonal 3, counter 7', values: { group: 'd2', counter: 7 } },
    ],
    run: chachaQr,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'state', pick: 'option', options: ['1', '2', '4', '8'], ask: 'In one double round, how many quarter-rounds touch the word x₅?', answer: '2', explain: 'One column (x₁, x₅, x₉, x₁₃) and one diagonal (x₀, x₅, x₁₀, x₁₅).' },
      { at: (f) => f.meta && f.meta.stage === 'step' && f.meta.k === 1, pick: 'option', options: ['some bits change value', 'no bit changes value; they only move'], ask: 'The next step rotates d left by 16. What happens to its bits?', answer: 'no bit changes value; they only move', explain: 'A rotation is a permutation of positions: the same 32 bits, moved round.' },
    ],
    quiz: [
      { q: 'How many times does one ChaCha20 quarter-round update each of a, b, c and d?', options: ['once', 'twice', 'three times', 'four times'], answer: 1, why: 'a and c are added to twice, b and d are XORed and rotated twice: more diffusion per step than Salsa20.' },
      { q: 'What are the four rotation amounts?', options: ['7, 9, 13, 18', '16, 12, 8, 7', '1, 2, 4, 8', '8, 8, 8, 8'], answer: 1, why: '16, 12, 8 and 7 in ChaCha20; 7, 9, 13, 18 are Salsa20\'s.' },
      { q: 'A double round runs the quarter-round on…', options: ['the rows, then the columns', 'the columns, then the diagonals', 'all 16 words at once', 'the diagonals only'], answer: 1, why: 'Four column quarter-rounds, then four diagonal ones.' },
      { q: 'Why can the four column quarter-rounds run in parallel?', options: ['They share no words', 'They are the same', 'They use different keys', 'They cannot'], answer: 0, why: 'Each column is a separate set of four words, which suits SIMD units.' },
      { q: 'Which ChaCha20 step is not linear over GF(2)?', options: ['XOR', 'Rotation', 'Addition modulo 2³²', 'None of them'], answer: 2, why: 'The carries of the addition are what make ARX nonlinear.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
