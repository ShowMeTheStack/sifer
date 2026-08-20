// Part 4, a toy SPN broken by differences: the difference distribution table of its S-box, a characteristic that
// carries one input difference through three rounds with a known probability, and the attack that peels off the
// last round under every guess of the key bits it reaches and counts how often the prediction comes true.
// S.P04b holds the drawing helpers shared with p04-spn-b.js (the linear attack and PRESENT).
(function (S) {
  'use strict';
  const U = S.SymT, SP = () => S.SPN;
  const B = (S.P04b = S.P04b || {});
  const h1 = (v) => v.toString(16), h4 = U.h4;
  const nib = (x, i) => (x >> (12 - 4 * i)) & 15;

  // the characteristic and approximation searches take a fraction of a second: once, then kept
  let chars = null, approxes = null;
  B.chars = () => chars || (chars = SP().searchDifferential({ maxActive: 2 }));
  B.approxes = () => approxes || (approxes = SP().searchLinear({ maxActive: 2 }));
  /** the characteristics a topic offers, by name */
  B.CHARS = { A: [0x0300, 0x0044], B: [0x0400, 0x0400], C: [0x0300, 0x0004], D: [0x0500, 0x4000] };
  B.char = (id) => { const [a, b] = B.CHARS[id]; return B.chars().find((c) => c.dIn === a && c.dU4 === b); };
  B.charOptions = [['A', 'ΔP 0300 → ΔU4 0044 (two S-boxes, 1/64)'], ['B', 'ΔP 0400 → ΔU4 0400 (one S-box, 1/64)'], ['C', 'ΔP 0300 → ΔU4 0004 (one S-box, 1/128)'], ['D', 'ΔP 0500 → ΔU4 4000 (one S-box, 1/128)']];
  /** a fraction n/16 written small: 4/16 → "1/4" */
  B.frac = (n, d) => { const g = (a, b) => (b ? g(b, a % b) : a), k = g(Math.abs(n), d); return (n < 0 ? '−' : '') + Math.abs(n) / k + '/' + d / k; };

  /**
   * The four-round network, top to bottom: o {prefix, x, y, path: [{u, v, boxes}] (rounds 1–3), upto (rounds lit),
   * top (ΔP or mask), bottom (ΔU4), target (nibbles of round 4 in key colour), fmt(a, b) -> box text, unit: 'Δ'}
   * Returns {items, xBit(b), yBox(r)}.
   */
  B.network = function (o) {
    const P = o.prefix || 'nw', X = o.x || 64, Y = o.y || 70, items = [], pitch = 21, upto = o.upto === undefined ? 3 : o.upto;
    const xb = (b) => U.r2(X + b * pitch + Math.floor(b / 4) * 12 + pitch / 2), yBox = (r) => Y + 52 + (r - 1) * 104, bh = 30;
    const bitOn = (v, b) => (v >> (15 - b)) & 1;
    // the input bits
    items.push(U.t(P + ':tl', X - 44, Y + 15, o.unit === 'mask' ? 'a' : 'ΔP', 'strong', 'start', 14));
    for (let b = 0; b < 16; b++) items.push({ key: P + ':tb' + b, kind: 'cell', x: U.r2(xb(b) - 8), y: Y, w: 16, h: 20, rx: 2, text: '', cls: 'bit ' + (bitOn(o.top, b) ? 'hot' : 'zero') });
    const wire = (key, d, on) => items.push({ key, kind: 'path', d, cls: 'p4wire' + (on ? ' hot' : ''), audit: 'ignore', layer: 'lines' });
    for (let r = 1; r <= 4; r++) {
      const y = yBox(r), st = r <= 3 ? o.path[r - 1] : null, lit = r <= upto || (r === 4 && upto >= 3);
      const inDiff = r === 1 ? o.top : o.path[r - 2] ? SP().permute(o.path[r - 2].v) : 0;
      // the key line above the S-boxes
      items.push({ key: P + ':kl' + r, kind: 'path', d: `M${X - 4},${y - 14} H${xb(15) + 12}`, cls: 'p4guide act', audit: 'ignore', layer: 'back' });
      items.push(U.t(P + ':k' + r, X - 44, y - 9, 'K' + U.sub(r), 'key', 'start', 14));
      // wires into the boxes: from the bits above (round 1) or from the permutation of the round before
      for (let b = 0; b < 16; b++) {
        const on = lit && bitOn(inDiff, b);
        if (r === 1) wire(P + ':i' + b, `M${xb(b)},${Y + 20} V${y}`, on);
        else { const pr = SP().PERM.indexOf(b), y0 = yBox(r - 1) + bh; wire(P + ':p' + r + '_' + b, `M${xb(pr)},${y0} V${y0 + 10} L${xb(b)},${y - 26} V${y}`, on); }
      }
      for (let i = 0; i < 4; i++) {
        const a = nib(inDiff, i), x0 = xb(4 * i) - pitch / 2 + 1, w = 4 * pitch - 2;
        const box = r <= 3 && st ? st.boxes.find((q) => q.i === i) : null;
        const active = lit && a !== 0, tgt = r === 4 && (o.target || []).includes(i);
        const text = !active ? 'S' : box ? o.fmt(box.a, box.b, box.n) : r === 4 ? o.unit === 'mask' ? 'mask ' + h1(a) : 'Δ ' + h1(a) : 'S';
        items.push({ key: P + ':s' + r + '_' + i, kind: 'cell', x: U.r2(x0), y, w, h: bh, rx: 5, text, size: 14, cls: 'hex ' + (tgt && active ? 'keyhot' : tgt ? 'key' : active ? (r === upto ? 'act' : 'hot') : 'soft') });
      }
    }
    items.push(U.t(P + ':ul', X - 44, yBox(4) + 50, o.unit === 'mask' ? 'U₄' : 'ΔU₄', 'strong', 'start', 14));
    items.push(U.t(P + ':uv', X + 4, yBox(4) + 50, (upto >= 3 ? h4(o.bottom) : '?') + '  (input of the last S-boxes)', upto >= 3 ? 'mono hot' : 'tick', 'start', 14));
    return { items, xBit: xb, yBox };
  };

  /** a 16 × 16 table of an S-box (DDT or LAT): o {prefix, x, y, table, rows: Set | null (all), sel: [[r, c]], cls(v, r, c), text(v), rowLabel, colLabel} */
  B.table = function (o) {
    const P = o.prefix || 'tb', cs = 25, g = 1, x0 = o.x + 26, y0 = o.y + 22, items = [];
    items.push(U.t(P + ':cl', x0 + 16 * (cs + g), o.y + 2, o.colLabel, 'tick', 'end', 13));
    items.push(U.t(P + ':rl', o.x, o.y + 2, o.rowLabel, 'tick', 'start', 13));
    for (let c = 0; c < 16; c++) items.push(U.t(P + ':ch' + c, x0 + c * (cs + g) + cs / 2, y0 - 6, h1(c), 'tick', 'middle', 13));
    const sel = new Set((o.sel || []).map(([r, c]) => r * 16 + c));
    for (let r = 0; r < 16; r++) {
      const show = !o.rows || o.rows.has(r);
      items.push(U.t(P + ':rh' + r, x0 - 8, y0 + r * (cs + g) + 17, h1(r), o.hot === r ? 'hot' : 'tick', 'end', 13));
      for (let c = 0; c < 16; c++) {
        const v = o.table[r][c];
        items.push({ key: P + ':' + r + '_' + c, kind: 'cell', x: x0 + c * (cs + g), y: y0 + r * (cs + g), w: cs, h: cs, rx: 2, text: show ? (o.text ? o.text(v) : String(v)) : '', size: 13, cls: 'hex hframe ' + (show ? o.cls(v, r, c) : 'soft') + (sel.has(r * 16 + c) ? ' p4sel' : '') });
      }
    }
    return { items, box: { x: o.x, y: o.y, w: 26 + 16 * (cs + g), h: 22 + 16 * (cs + g) }, cell: (r, c) => ({ x: x0 + c * (cs + g), y: y0 + r * (cs + g), w: cs, h: cs }) };
  };

  /** bars of a count per guess: o {prefix, x, y, w, h, values, hot (index), key (index), label(i) for ticks, ticks: [i], ylabel, fmt} */
  B.bars = function (o) {
    const P = o.prefix || 'bc', n = o.values.length, max = Math.max(...o.values, 1e-12), items = [];
    const bw = o.w / n, Y = (v) => U.r2(o.y + o.h - (v / max) * o.h);
    items.push({ key: P + ':ax', kind: 'path', d: `M${o.x},${o.y} V${o.y + o.h} H${o.x + o.w}`, cls: 'p4axis', audit: 'ignore', layer: 'back', box: { x: o.x, y: o.y, w: o.w, h: o.h } });
    o.values.forEach((v, i) => {
      const yy = Y(v), h = Math.max(0.6, U.r2(o.y + o.h - yy));
      items.push({ key: P + ':b' + i, kind: 'cell', x: U.r2(o.x + i * bw + bw * 0.12), y: U.r2(o.y + o.h - h), w: U.r2(Math.max(1, bw * 0.76)), h, rx: Math.min(2, bw / 5), text: '', cls: 'p4bar ' + (i === o.hot ? 'hot' : i === o.key ? 'key' : ''), audit: 'overlap-ok' });
    });
    for (const i of o.ticks || []) items.push(U.t(P + ':tx' + i, U.r2(o.x + (i + 0.5) * bw), o.y + o.h + 18, o.label(i), i === o.hot ? 'hot' : 'tick', 'middle', 13));
    const f = o.fmt || ((v) => String(+v.toFixed(4)));
    items.push(U.t(P + ':ym', o.x - 8, o.y + 5, f(max), 'tick', 'end', 13), U.t(P + ':y0', o.x - 8, o.y + o.h + 4, '0', 'tick', 'end', 13));
    if (o.ylabel) items.push(U.t(P + ':yl', o.x, o.y - 12, o.ylabel, 'tick', 'start', 13));
    return { items, xOf: (i) => o.x + (i + 0.5) * bw, Y };
  };

  // ---------------------------------------------------------------------------------------------------------------
  // The DDT and a differential characteristic
  // ---------------------------------------------------------------------------------------------------------------
  const heat = (v) => (v === 0 ? 'h0 p4zero' : v >= 16 ? 'h8' : 'h' + Math.min(8, v * 1.5 | 0));
  function ddt(inp) {
    const sb = SP().SBOX, D = SP().ddt(), dx = parseInt(inp.dx, 16), ch = B.char(inp.char);
    const outs = Array.from({ length: 16 }, (_, x) => sb[x] ^ sb[x ^ dx]), row = D[dx], best = Math.max(...row), bestDy = row.indexOf(best);
    const Fr = new S.Frames();
    const head = U.head('dd:h', 'The toy SPN: its S-box\'s differences, and one path through three rounds');
    const sboxRows = () => {
      const items = [U.t('dd:st', 24, 74, 'the S-box', 'title', 'start', 14), U.t('dd:sx', 24, 106, 'x', 'tick', 'start', 14), U.t('dd:sy', 24, 136, 'S(x)', 'tick', 'start', 14)];
      items.push(...U.cells({ prefix: 'dd:x', x: 64, y: 88, cw: 22, ch: 26, gap: 2, values: sb.map((_, i) => h1(i)), cls: () => 'soft', size: 14 }));
      items.push(...U.cells({ prefix: 'dd:y', x: 64, y: 118, cw: 22, ch: 26, gap: 2, values: sb.map(h1), size: 14 }));
      return items;
    };
    const pairs = (on) => {
      if (!on) return [];
      const items = [U.t('dd:pt', 24, 190, 'Every pair with input difference Δx = ' + h1(dx) + ':', 'strong', 'start', 15), U.t('dd:p1', 24, 222, 'x', 'tick', 'start', 14), U.t('dd:p2', 24, 252, 'x ⊕ ' + h1(dx), 'tick', 'start', 13), U.t('dd:p3', 24, 282, 'Δy', 'tick', 'start', 14)];
      items.push(...U.cells({ prefix: 'dd:a', x: 64, y: 204, cw: 22, ch: 26, gap: 2, values: sb.map((_, i) => h1(i)), cls: () => 'soft', size: 14 }));
      items.push(...U.cells({ prefix: 'dd:b', x: 64, y: 234, cw: 22, ch: 26, gap: 2, values: sb.map((_, i) => h1(i ^ dx)), cls: () => 'soft', size: 14 }));
      items.push(...U.cells({ prefix: 'dd:c', x: 64, y: 264, cw: 22, ch: 26, gap: 2, values: outs.map(h1), cls: (i, v) => (parseInt(v, 16) === bestDy ? 'hot' : ''), size: 14 }));
      items.push(U.t('dd:hw1', 24, 380, 'In the table: the row is the input difference Δx,', 'tick', 'start', 14), U.t('dd:hw2', 24, 404, 'the column the output difference Δy, and the entry', 'tick', 'start', 14), U.t('dd:hw3', 24, 428, 'how many of the 16 inputs x give that Δy.', 'tick', 'start', 14));
      items.push(U.t('dd:pn', 24, 322, `Δy = ${h1(bestDy)} turns up ${best} times of 16: probability ${B.frac(best, 16)}`, 'hot', 'start', 14));
      return items;
    };
    const T = (rows, sel, hot) => B.table({ prefix: 'dd:tab', x: 476, y: 64, table: D, rows, sel, hot, cls: heat, rowLabel: 'Δx ↓', colLabel: 'Δy →' }).items;
    const usedSel = (upto) => { const s = []; ch.path.slice(0, upto).forEach((p) => p.boxes.forEach((q) => s.push([q.a, q.b]))); return s; };
    const fmt = (a, b) => h1(a) + ' → ' + h1(b);
    const net = (upto) => B.network({ prefix: 'dd:n', x: 70, y: 70, path: ch.path, upto, top: ch.dIn, bottom: ch.dU4, target: ch.active, fmt }).items;
    const pathRows = (upto) => {
      const items = [...U.panel('dd:r', 476, 512, 420, 104, 'the path so far')];
      ch.path.slice(0, upto).forEach((p, j) => items.push(U.t('dd:r' + j, 490, 556 + j * 20, 'round ' + (j + 1) + ': ' + p.boxes.map((q) => 'S-box ' + q.i + ' ' + h1(q.a) + '→' + h1(q.b) + ' (' + B.frac(q.n, 16) + ')').join(', '), 'mono', 'start', 13)));
      return items;
    };
    Fr.add({ items: [head, ...sboxRows(), ...T(new Set())], hl: { d: [0] }, say: `The toy SPN has a 16-bit block, four 4-bit S-boxes a round and four rounds. Its S-box maps 0…f to ${sb.map(h1).join(', ')}. Differential cryptanalysis asks: if two inputs differ by Δx, how often do the outputs differ by Δy?`, facts: { sb: sb.map(h1).join(', ') }, meta: { stage: 'sbox' } });
    Fr.add({ items: [head, ...sboxRows(), ...pairs(true), ...T(new Set())], hl: { d: [0] }, say: `Take Δx = ${h1(dx)} and run all 16 inputs: x and x ⊕ ${h1(dx)} give output differences ${outs.map(h1).join(', ')}. The value ${h1(bestDy)} turns up ${best} times, so a pair with input difference ${h1(dx)} leaves with difference ${h1(bestDy)} with probability ${best}/16.`, facts: { dx: h1(dx), outs: outs.map(h1).join(', '), best, bestDy: h1(bestDy) }, meta: { stage: 'pairs' } });
    Fr.add({ items: [head, ...sboxRows(), ...pairs(true), ...T(new Set([dx]), row.map((v, c) => [dx, c]).filter(([, c]) => c === bestDy), dx)], hl: { d: [1] }, say: `Counting each Δy fills row ${h1(dx)} of the difference distribution table: ${row.join(' ')}. Every entry is even, because the pairs (x, x ⊕ Δx) and (x ⊕ Δx, x) count twice, and the row adds up to 16.`, facts: { row: row.join(' '), dx: h1(dx) }, meta: { stage: 'row' } });
    const n4 = D.slice(1).flat().filter((v) => v === 4).length;
    Fr.add({ items: [head, ...sboxRows(), ...pairs(true), ...T(null, [], dx)], say: `The whole table. Row 0 is trivial: equal inputs give equal outputs, all 16 times. Elsewhere the largest entry is 4, so no difference passes an S-box with probability above 1/4; there are ${n4} such entries, the attacker's footholds.`, facts: { n4 }, meta: { stage: 'table' } });
    for (let r = 1; r <= 3; r++) {
      const p = ch.path[r - 1], v = SP().permute(p.v), prob = p.boxes.reduce((t, q) => t * q.n / 16, 1);
      const cum = ch.path.slice(0, r).reduce((t, pp) => t * pp.boxes.reduce((s, q) => s * q.n / 16, 1), 1);
      Fr.add({ items: [head, ...net(r), ...T(null, usedSel(r)), ...pathRows(r)], hl: { d: [2] }, say: `Round ${r}: the difference ${h4(p.u)} enters ${U.plural(p.boxes.length, 'active S-box', 'active S-boxes')} (${p.boxes.map((q) => `S-box ${q.i}: ${h1(q.a)} → ${h1(q.b)} with probability ${q.n}/16`).join('; ')}), leaving ${h4(p.v)}.` + (r < 3 ? ` The permutation spreads it to ${h4(v)} for round ${r + 1}.` : ` The permutation turns it into ${h4(v)}, the difference in front of the last S-boxes.`) + ` The key is XORed into both texts of a pair alike, so it cancels from the difference. Probability so far: 1/${Math.round(1 / cum)}.`, facts: { u: h4(p.u), v: h4(p.v), pv: h4(v), boxes: p.boxes.map((q) => [q.i, h1(q.a), h1(q.b), q.n]), cum: Math.round(1 / cum), r, prob }, meta: { stage: 'round', r } });
    }
    Fr.add({ items: [head, ...net(3), ...T(null, usedSel(3)), ...pathRows(3)], say: `The characteristic: ΔP = ${h4(ch.dIn)} gives ΔU₄ = ${h4(ch.dU4)}, the difference entering the last S-boxes, with probability about 1/${Math.round(1 / ch.prob)}. It touches only nibble${ch.active.length > 1 ? 's' : ''} ${ch.active.join(' and ')} of round 4, so only those ${4 * ch.active.length} bits of the last round key decide whether a pair looks right: the next topic guesses them.`, facts: { dIn: h4(ch.dIn), dU4: h4(ch.dU4), inv: Math.round(1 / ch.prob), active: ch.active, bits: 4 * ch.active.length }, meta: { stage: 'end' } });
    U.fix(Fr.list, { x: 0, y: 0, w: 920, h: 630 });
    return { frames: Fr.list, def: U.def('Differences', ['Δx = x ⊕ x′, Δy = S(x) ⊕ S(x′)', 'DDT[Δx][Δy] = #{x : S(x) ⊕ S(x ⊕ Δx) = Δy}', 'P(Δx → Δy) = DDT[Δx][Δy] / 16', 'the key cancels: (x ⊕ k) ⊕ (x′ ⊕ k) = Δx', 'a characteristic: rounds multiply']) };
  }
  S.topic({
    id: 'spn-ddt', family: 'p04-spn', order: 10, title: 'Differences through an S-box, and through rounds',
    blurb: 'Count, for every input difference, how often each output difference comes out: the difference table. Chain its best entries through the rounds and a chosen difference in the plaintext predicts one in front of the last S-boxes.',
    inputs: [U.choice('dx', 'Input difference Δx to count', 'b', '123456789abcdef'.split('').map((c) => [c, c])), U.choice('char', 'Characteristic', 'A', B.charOptions)],
    presets: [{ label: 'Δx = b, two-box path', values: { dx: 'b', char: 'A' } }, { label: 'Δx = 4, one-box path', values: { dx: '4', char: 'B' } }, { label: 'Δx = 3', values: { dx: '3', char: 'C' } }, { label: 'Δx = 1', values: { dx: '1', char: 'D' } }],
    run: ddt,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'pairs', once: true, pick: 'option', options: ['yes', 'no'], ask: 'Can an entry of the difference table be odd?', answer: 'no', explain: 'Pairs come two at a time: x and x ⊕ Δx give the same output difference.' },
      { at: (f) => f.meta && f.meta.stage === 'round' && f.meta.r === 2, once: true, pick: 'option', options: ['1/16', '1/64', '1/128', '1/256'], ask: 'Before the last step: what will the probability of the whole path be, roughly?', answer: (fr) => '1/' + fr[fr.length - 1].facts.inv, explain: 'Multiply the probabilities of every active S-box on the path.' },
    ],
    quiz: [
      { q: 'Why does the round key not change a difference?', options: ['It is XORed into both texts, so (x ⊕ k) ⊕ (x′ ⊕ k) = x ⊕ x′', 'It is too short', 'The S-box removes it', 'It does'], answer: 0, why: 'XOR with the same value cancels in the difference.' },
      { q: 'A DDT entry of 4 means…', options: ['the difference passes with probability 4/16 = 1/4', 'four S-boxes are active', 'the key has four bits', 'four rounds'], answer: 0, why: '4 of the 16 inputs with that Δx give that Δy.' },
      { q: 'How is the probability of a characteristic estimated?', options: ['The product of the probabilities of its active S-boxes', 'Their sum', 'The largest one', 'By the number of rounds'], answer: 0, why: 'Treating the rounds as independent, the probabilities multiply.' },
      { q: 'What makes an S-box good against differential cryptanalysis?', options: ['Small largest DDT entry (low differential uniformity)', 'Many zeros in row 0', 'Being linear', 'A large block'], answer: 0, why: 'Then every difference passes with low probability.' },
      { q: 'Why is row 0 of the DDT 16, 0, 0, …?', options: ['Equal inputs always give equal outputs', 'The S-box maps 0 to 0', 'It is a convention', 'Because of the key'], answer: 0, why: 'Δx = 0 means the two inputs are the same.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The differential attack on the last round key
  // ---------------------------------------------------------------------------------------------------------------
  B.spread = (g, nibs) => { let k = 0; nibs.forEach((n, j) => { k |= ((g >> (4 * (nibs.length - 1 - j))) & 15) << (12 - 4 * n); }); return k; };
  B.maskOf = (nibs) => B.spread((1 << (4 * nibs.length)) - 1, nibs);
  B.undo = (c, k, nibs) => { let u = 0; for (const n of nibs) u |= SP().INV_SBOX[nib(c ^ k, n)] << (12 - 4 * n); return u; };
  /** four nibbles of a 16-bit value as cells; mute the nibbles outside nibs */
  B.nibs = (prefix, x, y, v, nibs, cls, o) => {
    o = o || {};
    return [0, 1, 2, 3].map((i) => ({ key: prefix + i, kind: 'cell', x: x + i * 38, y, w: 34, h: 28, rx: 3, text: o.blank && !nibs.includes(i) ? '' : h1(nib(v, i)), size: 15, cls: 'hex ' + (nibs.includes(i) ? cls || '' : 'soft muted') }));
  };
  function diff(inp) {
    const keys = SP().keys(inp.key), ch = B.char(inp.char), nibs = ch.active, G = 1 << (4 * nibs.length), pairs = inp.pairs;
    const res = SP().diffAttack({ keys, char: ch, pairs, seed: inp.key });
    const right = res.right, rightG = res.counts.findIndex((_, g) => B.spread(g, nibs) === right), E = SP().fast(keys).enc;
    const r = S.Sym.rng(inp.key), outside = ~B.maskOf(nibs) & 0xffff;
    // the first pair that passes the filter and the first that does not, from the same chosen plaintexts
    let kept = null, dropped = null;
    for (let i = 0; i < pairs && !(kept && dropped); i++) {
      const p = Math.floor(r() * 65536), c1 = E(p), c2 = E(p ^ ch.dIn), ok = !((c1 ^ c2) & outside);
      if (ok && !kept) kept = { p, c1, c2 }; else if (!ok && !dropped) dropped = { p, c1, c2 };
    }
    kept = kept || dropped;
    const wrongG = res.best.find((b) => b.k !== right) ? res.counts.findIndex((_, g) => B.spread(g, nibs) === res.best.find((b) => b.k !== right).k) : (rightG + 1) % G;
    const wrong = B.spread(wrongG, nibs);
    const Fr = new S.Frames();
    const head = U.head('df:h', 'Recovering ' + 4 * nibs.length + ' bits of K₅ by counting right pairs');
    const chain = U.readout('df:c', 24, 56, 420, 'the characteristic', [['ΔP → ΔU₄', h4(ch.dIn) + ' → ' + h4(ch.dU4)], ['probability', '≈ 1/' + Math.round(1 / ch.prob)], ['K₅ nibbles to guess', nibs.join(', ') + ' (' + G + ' guesses)', 'key'], ['chosen pairs', String(pairs)], ['kept by the filter', String(res.used)], ['right pairs expected', '≈ ' + Math.round(pairs * ch.prob)]], { dy: 28, size: 14 });
    const peel = (pr, g, show) => {
      const items = [...U.panel('df:p', 460, 56, 436, 236, show ? 'peel the last round, guess ' + h4(g) : 'one pair of ciphertexts')];
      const u1 = B.undo(pr.c1, g, nibs), u2 = B.undo(pr.c2, g, nibs);
      [['C₁', pr.c1, ''], ['C₂', pr.c2, ''], ['ΔC', pr.c1 ^ pr.c2, (pr.c1 ^ pr.c2) & outside ? 'bad' : 'act']].forEach(([l, v, c], j) => {
        items.push(U.t('df:pl' + j, 476, 112 + j * 36, l, 'strong', 'start', 14));
        items.push(...B.nibs('df:p' + j + ':', 566, 92 + j * 36, v, j === 2 ? [0, 1, 2, 3] : [0, 1, 2, 3], c));
      });
      if (show) {
        const d = u1 ^ u2, hit = d === ch.dU4;
        items.push(U.t('df:ul', 476, 230, 'S⁻¹(C ⊕ g)', 'tick', 'start', 13), U.t('df:ul2', 476, 248, 'differ by', 'tick', 'start', 13));
        items.push(U.t('df:u1', 730, 210, 'ΔU₄ = ' + h4(d), hit ? 'hot' : 'tick', 'start', 15));
        items.push(...B.nibs('df:u:', 566, 220, d, nibs, hit ? 'hot' : '', { blank: true }));
        items.push(U.t('df:u2', 730, 240, hit ? '= ' + h4(ch.dU4) + ': a point' : '≠ ' + h4(ch.dU4), hit ? 'hot' : 'tick', 'start', 15));
      }
      return items;
    };
    const bars = (on) => {
      if (!on) return [U.t('df:bt', 24, 336, 'right pairs counted for each guess', 'title', 'start', 14)];
      const ticks = G === 16 ? [...Array(16).keys()] : [0, 64, 128, 192, 255];
      return [U.t('df:bt', 24, 336, 'right pairs counted for each guess', 'title', 'start', 14), ...B.bars({ prefix: 'df:b', x: 60, y: 372, w: 836, h: 190, values: res.counts, hot: res.counts.indexOf(Math.max(...res.counts)), key: rightG, ticks, label: (i) => h1(i).padStart(nibs.length, '0'), ylabel: 'count', fmt: (v) => String(v) }).items, U.t('df:tg', 60 + (res.counts.indexOf(Math.max(...res.counts)) + 0.5) * 836 / G, 366, h4(res.guess), 'hot', 'middle', 13), ...U.legend('df:lg', 520, 336, [['hot', 'the top guess'], ['key', 'the true key bits']], 13)];
    };
    const exp = Math.round(pairs * ch.prob);
    Fr.add({ items: [head, ...chain, ...peel(kept, 0, false), ...bars(false)], hl: { d: [0] }, say: `The secret key is five round keys; we attack the last, K₅. Choose ${pairs} plaintexts P and encrypt both P and P ⊕ ${h4(ch.dIn)}. About 1 pair in ${Math.round(1 / ch.prob)} follows the characteristic and has ΔU₄ = ${h4(ch.dU4)} just before the last S-boxes: about ${exp} right pairs.`, facts: { pairs, inv: Math.round(1 / ch.prob), dIn: h4(ch.dIn), dU4: h4(ch.dU4), exp }, meta: { stage: 'plan' } });
    Fr.add({ items: [head, ...chain, ...peel(kept, 0, false), ...bars(false)], say: `A right pair can differ only in nibble${nibs.length > 1 ? 's' : ''} ${nibs.join(' and ')} of the ciphertext, the S-boxes the characteristic reaches. This pair, P = ${h4(kept.p)}, gives C₁ = ${h4(kept.c1)} and C₂ = ${h4(kept.c2)}: ΔC = ${h4(kept.c1 ^ kept.c2)}. Of all ${pairs} pairs, ${res.used} pass this filter; the rest are thrown away unexamined.`, facts: { p: h4(kept.p), c1: h4(kept.c1), c2: h4(kept.c2), dc: h4(kept.c1 ^ kept.c2), used: res.used, pairs, nibs }, meta: { stage: 'filter' } });
    const uR = B.undo(kept.c1, right, nibs) ^ B.undo(kept.c2, right, nibs), uW = B.undo(kept.c1, wrong, nibs) ^ B.undo(kept.c2, wrong, nibs);
    Fr.add({ items: [head, ...chain, ...peel(kept, wrong, true), ...bars(false)], hl: { d: [1] }, say: `Guess the key bits, say ${h4(wrong)}: XOR them into both ciphertexts and run the target nibbles back through the inverse S-box. The difference that comes out is ${h4(uW)}` + (uW === ch.dU4 ? `, which matches ${h4(ch.dU4)}: this guess scores a point.` : `, not ${h4(ch.dU4)}: no point for this guess.`), facts: { g: h4(wrong), d: h4(uW), dU4: h4(ch.dU4) }, meta: { stage: 'guess' } });
    Fr.add({ items: [head, ...chain, ...peel(kept, right, true), ...bars(false)], say: `The same pair under the true key bits ${h4(right)} gives ${h4(uR)}` + (uR === ch.dU4 ? `, the predicted difference: a right pair always scores for the right key.` : `: this pair is not a right pair after all, so even the true key gives it no point. Only about 1 in ${Math.round(1 / ch.prob)} pairs is right.`) + ` Wrong guesses also score now and then, by chance.`, facts: { right: h4(right), d: h4(uR), inv: Math.round(1 / ch.prob) }, meta: { stage: 'right' } });
    const top = res.best.slice(0, 3);
    Fr.add({ items: [head, ...chain, ...peel(kept, res.guess, true), ...bars(true)], hl: { d: [2] }, say: `Do this for all ${G} guesses and all ${res.used} kept pairs. The counts: ${top.map((b) => h4(b.k) + ' scores ' + b.c).join(', ')}. The right guess collects the right pairs, about ${exp}, on top of the chance hits every guess gets.`, facts: { G, used: res.used, top: top.map((b) => [h4(b.k), b.c]), exp }, meta: { stage: 'counts', ok: res.ok } });
    Fr.add({ items: [head, ...chain, ...peel(kept, res.guess, true), ...bars(true)], say: `The top guess is ${h4(res.guess)}; the true bits of K₅ are ${h4(right)}: ` + (res.ok ? `recovered from ${pairs} chosen pairs, by testing only these ${G} guesses instead of searching all five round keys at once. The other nibbles fall the same way, and then K₄ with K₅ peeled off.` : `not recovered: too few pairs for the right count to stand out. More pairs, roughly a few times 1/p, make it stand out.`), facts: { guess: h4(res.guess), right: h4(right), pairs, G, ok: res.ok }, meta: { stage: 'end' } });
    U.fix(Fr.list, { x: 0, y: 0, w: 920, h: 600 });
    return { frames: Fr.list, def: U.def('The differential attack', ['choose pairs (P, P ⊕ ΔP), get (C₁, C₂)', 'keep a pair only if ΔC = 0 outside the target nibbles', 'for each guess k: Δ = S⁻¹(C₁ ⊕ k) ⊕ S⁻¹(C₂ ⊕ k)', 'count the guess when Δ = ΔU₄', 'the right key collects about N·p extra points']) };
  }
  S.topic({
    id: 'spn-diff', family: 'p04-spn', order: 20, title: 'The differential attack on the last round key',
    blurb: 'Chosen pairs with one input difference, the last round peeled off under every guess of the key bits it touches, and a count per guess: the right guess collects the pairs that followed the characteristic.',
    inputs: [U.choice('char', 'Characteristic', 'A', B.charOptions), { id: 'pairs', kind: 'number', label: 'Chosen pairs', def: 1500, min: 100, max: 4000 }, { id: 'key', kind: 'number', label: 'Secret key (seed)', def: 3, min: 1, max: 999 }],
    presets: [{ label: 'Two nibbles, 1500 pairs', values: { char: 'A', pairs: 1500, key: 3 } }, { label: 'One nibble, 1000 pairs', values: { char: 'B', pairs: 1000, key: 8 } }, { label: 'Too few pairs (150)', values: { char: 'A', pairs: 150, key: 5 } }, { label: 'Weaker path, 3000 pairs', values: { char: 'C', pairs: 3000, key: 12 } }],
    run: diff,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'right', once: true, pick: 'option', options: ['the true key bits', 'a wrong guess'], ask: 'After counting every kept pair for every guess, which guess will have the highest count?', answer: (fr, i) => (fr[i + 1].meta.ok ? 'the true key bits' : 'a wrong guess'), explain: 'With enough pairs the right pairs lift the true key above the chance hits; with too few they may not.' }],
    quiz: [
      { q: 'Why does the attack guess only some bits of K₅ at a time?', options: ['The characteristic reaches only some S-boxes of the last round; only their key bits matter', 'K₅ is short', 'Memory', 'The others are zero'], answer: 0, why: 'Only the target nibbles must be undone to test ΔU₄.' },
      { q: 'What does the filter on ΔC do?', options: ['Drops pairs that cannot be right, since a right pair differs only in the target nibbles', 'Keeps only right pairs', 'Finds the key', 'Nothing useful'], answer: 0, why: 'Inactive S-boxes have zero difference, so the ciphertexts agree there.' },
      { q: 'With probability p and N pairs, the right guess collects about…', options: ['N·p right pairs on top of the chance hits', 'N pairs', 'p pairs', '1/p pairs'], answer: 0, why: 'Each pair follows the characteristic with probability p.' },
      { q: 'Is this a chosen- or a known-plaintext attack?', options: ['Chosen: the pairs must have the difference ΔP', 'Known', 'Ciphertext only', 'Related key'], answer: 0, why: 'The attacker picks P and P ⊕ ΔP.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
