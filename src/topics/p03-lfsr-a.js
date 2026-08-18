// Part 3, the LFSR as a shifting register with taps: each clock the taps read some cells, their XOR enters on the
// left, every bit moves one place right and the oldest leaves as output. The bits keep their identity, so the
// picture shows them gliding along the register and dropping into the output stream.
(function (S) {
  'use strict';
  const U = S.SymT, LF = () => S.LFSR;
  const xp = (k) => 'x' + U.sup(k);
  const polyText = (taps) => '1 + ' + taps.slice().sort((a, b) => a - b).map(xp).join(' + ');
  const seedCheck = (v, input) => {
    const s = String(v);
    if (!/^[01]+$/.test(s)) return 'Seed: only 0 and 1';
    const L = Math.max(...(input.taps || []).map(Number).filter(Number.isFinite));
    if (Number.isFinite(L) && s.length !== L) return 'Seed: exactly ' + L + ' bits, one for each cell of the register (the largest tap is ' + L + ')';
    if (!/1/.test(s)) return 'Seed: at least one 1 (the all-zero register stays zero for ever)';
    return null;
  };

  function shifting(inp) {
    const taps = inp.taps.map(Number).sort((a, b) => b - a), L = taps[0], seed = U.toBits(inp.seed), n = inp.clocks;
    const seq = LF().sequence(taps, seed, n + L);
    const reg = LF().fibonacci(taps, seed);
    const F = new S.Frames(), poly = polyText(taps);
    const cw = L <= 6 ? 64 : L <= 8 ? 56 : L <= 12 ? 48 : 40, gap = 6, W = L * (cw + gap) - gap, x0 = Math.round((920 - W) / 2), y0 = 112;
    const head = U.head('lf:h', 'An LFSR with C(x) = ' + poly);
    const tapCols = new Set(taps.map((k) => k - 1));
    // the states before each clock, newest bit on the left as in the register; the last eight are listed
    const hx = 484, hcw = L <= 12 ? 20 : 16, hgap = L <= 12 ? 2 : 1, hy = 382, hdy = 26;
    const history = (upto, lit) => {
      const items = [...U.panel('lf:hp', 468, 316, 428, 284, 'the register, clock by clock')];
      items.push(U.t('lf:hh', hx, 358, 'clock', 'tick', 'start', 13), U.t('lf:hh2', hx + 58, 358, 'state before (x¹ … x' + U.sup(L) + ')', 'tick', 'start', 13), U.t('lf:hh3', 880, 358, 'out', 'tick', 'end', 13));
      const from = Math.max(0, upto - 7);
      for (let r = from; r <= upto; r++) {
        const y = hy + (r - from) * hdy, cur = lit && r === upto;
        items.push(U.t('lf:hr' + r, hx + 22, y + 15, String(r + 1), cur ? 'act' : 'tick', 'middle', 13));
        for (let c = 0; c < L; c++) {
          const b = seq[r + L - 1 - c];
          items.push({ key: 'lf:hc' + r + ':' + c, kind: 'cell', x: hx + 58 + c * (hcw + hgap), y, w: hcw, h: 20, rx: 2, text: String(b), size: 12, cls: 'bit ' + (b ? 'one' : 'zero') + (cur && tapCols.has(c) ? ' act' : cur && c === L - 1 ? ' hot' : '') });
        }
        items.push(U.t('lf:ho' + r, 880, y + 15, String(seq[r]), cur ? 'hot' : 'mono', 'end', 14));
      }
      return items;
    };
    const draw = (i, lit) => {
      // before clock i the register holds s(i) … s(i + L − 1); column c holds s(i + L − 1 − c)
      const bits = seq.slice(i, i + L);
      const g = S.Kit.reg.fib({ prefix: 'lf', x: x0, y: y0, bits, taps, cw, ch: cw, gap, rise: 46, lit: lit ? { taps: true, fb: true, out: true } : {}, fbBit: lit ? seq[i + L] : null, ids: (c) => i + L - 1 - c, label: (c) => xp(c + 1), labelCls: (c) => (tapCols.has(c) ? 'act' : ''), cls: (c) => (lit && tapCols.has(c) ? 'act' : lit && c === L - 1 ? 'hot' : ''), size: cw >= 48 ? 22 : 18 });
      const items = [head, ...g.items];
      items.push(U.t('lf:new', x0 - 30, y0 - 62, 'new bit', 'tick', 'middle', 13));
      items.push(U.t('lf:o', g.xOut + 6, g.yMid + 5, 'out', 'tick', 'start', 14));
      // the output stream so far
      const shown = lit ? i + 1 : i;
      items.push(U.t('lf:ot', 24, 252, 'output stream s₀ s₁ s₂ …' + (shown ? '' : ' (nothing yet)'), 'title', 'start'));
      const row = U.bitRow({ prefix: 'lfo', x: 24, y: 264, bits: seq.slice(0, shown), cw: 28, ch: 32, group: L, groupGap: 8, size: 15, cls: (j) => (lit && j === i ? 'hot' : j < L ? 'key' : '') });
      items.push(...row.items);
      items.push(...history(Math.min(i, n - 1), lit));
      return items;
    };
    const eqPanel = (i) => {
      const read = taps.map((k) => seq[i + L - k]);
      return [...U.panel('lf:eq', 24, 316, 420, 284, 'this clock'),
        U.t('lf:eq0', 44, 370, 's' + U.sub(i + L) + ' = ' + taps.map((k) => 's' + U.sub(i + L - k)).join(' ⊕ '), 'math', 'start', 20),
        U.t('lf:eq1', 44, 410, '= ' + read.join(' ⊕ ') + ' = ' + seq[i + L], 'math act', 'start', 20),
        U.t('lf:eq2', 44, 460, 'enters at x¹', 'tick', 'start', 14),
        U.t('lf:eq3', 44, 490, 'leaves: s' + U.sub(i) + ' = ' + seq[i], 'hot', 'start', 16),
        U.t('lf:eq4', 44, 560, 'the taps: ' + taps.slice().reverse().map(xp).join(', '), 'tick', 'start', 14)];
    };
    F.add({ items: [...draw(0, false), ...U.panel('lf:eq', 24, 316, 420, 284, 'the rule'), U.t('lf:eq0', 44, 370, taps.length <= 2 ? 's(n) = ' + taps.map((k) => 's(n−' + k + ')').join(' ⊕ ') : 's(n) = ⊕ of s(n−k), k = ' + taps.join(', '), 'math', 'start', taps.length <= 2 ? 20 : 17), U.t('lf:eq1', 44, 410, 'one tap for each term xᵏ of C(x)', 'tick', 'start', 15), U.t('lf:eq2', 44, 460, 'seed: ' + seed.join(''), 'key', 'start', 16)],
      say: `A linear feedback shift register of ${L} cells with connection polynomial C(x) = ${poly}. The cell under xᵏ holds the bit from k clocks ago, s(n−k); the tapped cells, ${taps.map(xp).join(' and ')}, are XORed to make the next bit. The seed ${seed.join('')} fills the register, oldest bit on the right.`,
      facts: { L, seed: seed.join(''), taps }, meta: { stage: 'start' } });
    for (let i = 0; i < n; i++) {
      const st = reg.step(), read = taps.map((k) => seq[i + L - k]);
      const say = `Clock ${i + 1}: the taps read ${read.join(' and ')}, so the new bit is ${read.join(' ⊕ ')} = ${st.fb}; it enters on the left, every bit moves one place right, and ${st.out} leaves as output bit s${U.sub(i)}.` + (i === L - 1 ? ` The first ${L} output bits were just the seed; from here on every bit is made by the feedback.` : i === 1 ? ' In the list on the right each bit runs down a diagonal: it moves one cell per clock.' : '');
      F.add({ items: [...draw(i, true), ...eqPanel(i)], hl: { d: [1] }, say, facts: { i: i + 1, read, fb: st.fb, out: st.out, L, state: st.before.join('') }, meta: { stage: 'clock', i } });
    }
    const out = seq.slice(0, n), ones = out.filter((b) => b).length;
    F.add({ items: [...draw(n, false), ...U.panel('lf:eq', 24, 316, 420, 284, 'after ' + n + ' clocks'), U.t('lf:eq0', 44, 370, out.slice(0, 16).join(''), 'math', 'start', 20), U.t('lf:eq1', 44, 404, out.slice(16).join(''), 'math', 'start', 20), U.t('lf:eq2', 44, 460, ones + ' ones, ' + (n - ones) + ' zeros', 'tick', 'start', 15), U.t('lf:eq3', 44, 490, 'register now: ' + seq.slice(n, n + L).reverse().join(''), 'act', 'start', 16)],
      say: `After ${n} clocks the output is ${out.join('')}: ${ones} ones and ${n - ones} zeros. Every bit is an XOR of seed bits, so the whole stream is linear in the seed, and the register's ${L} bits are all an attacker needs to predict it for ever.`,
      facts: { n, out: out.join(''), ones, zeros: n - ones, L }, meta: { stage: 'end' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 616 });
    return { frames: F.list, def: U.def('A Fibonacci LFSR', ['C(x) = 1 + c₁x + c₂x² + … + c_L·x^L', 's(n) = c₁·s(n−1) ⊕ c₂·s(n−2) ⊕ … ⊕ c_L·s(n−L)', 'state: the last L bits; output: the oldest', 'the first L outputs are the seed', 'linear: every output is an XOR of seed bits']) };
  }

  S.topic({
    id: 'st-lfsr', family: 'p03-lfsr', order: 20, title: 'The LFSR: a register with taps',
    blurb: 'A row of bit cells that shifts once a clock. The tapped cells are XORed into the new bit at the left; the oldest bit leaves at the right as output. Simple, fast in hardware, and entirely linear.',
    inputs: [
      { id: 'taps', kind: 'list', label: 'Taps (exponents of C(x))', def: ['4', '3'], check: U.tapsCheck(16) },
      { id: 'seed', kind: 'string', label: 'Seed (oldest bit first)', def: '1000', alphabet: '01', max: 16, check: seedCheck },
      { id: 'clocks', kind: 'number', label: 'Clocks', def: 16, min: 4, max: 24 },
    ],
    presets: [
      { label: '1 + x³ + x⁴, seed 1000', values: { taps: ['4', '3'], seed: '1000', clocks: 16 } },
      { label: '1 + x³ + x⁵, seed 10110', values: { taps: ['5', '3'], seed: '10110', clocks: 20 } },
      { label: 'Four taps, 8 cells', values: { taps: ['8', '6', '5', '4'], seed: '11010010', clocks: 20 } },
      { label: '1 + x + x², seed 01', values: { taps: ['2', '1'], seed: '01', clocks: 9 } },
      { label: '12 cells', values: { taps: ['12', '6', '4', '1'], seed: '100000000001', clocks: 24 } },
    ],
    run: shifting,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'start', once: true, pick: 'option', options: ['0', '1'], ask: 'Which bit leaves the register first?', answer: (fr) => String(fr[1].facts.out), explain: 'The oldest bit, the rightmost cell: the first L output bits are the seed itself.' },
      { at: (f, i, fr) => f.meta && f.meta.stage === 'clock' && f.meta.i === fr[0].facts.L, once: true, pick: 'option', options: ['0', '1'], ask: 'Read the tapped cells as they stand after this clock. Which bit enters next?', answer: (fr, i) => String(fr[i + 1].facts.fb), explain: 'XOR the bits under the taps; an even number of ones gives 0, an odd number gives 1.' },
    ],
    quiz: [
      { q: 'What makes an LFSR linear?', options: ['Its cells are in a line', 'The new bit is an XOR (a sum mod 2) of earlier bits', 'It shifts by one place', 'Its output is balanced'], answer: 1, why: 'XOR is addition in GF(2), so every output bit is a linear combination of the seed bits.' },
      { q: 'An LFSR with 5 cells is seeded with 10110 (oldest first). What are its first five output bits?', options: ['01101', '10110', '00000', 'They depend on the taps'], answer: 1, why: 'The register shifts its contents out in order before any feedback bit reaches the output.' },
      { q: 'Why must the seed not be all zeros?', options: ['XOR of zeros is zero, so the register would output zeros for ever', 'It would make the period 2^L', 'It would reverse the output', 'Zeros cannot be stored'], answer: 0, why: 'The all-zero state maps to itself.' },
      { q: 'With C(x) = 1 + x³ + x⁴, which earlier bits make s(n)?', options: ['s(n−1) and s(n−4)', 's(n−3) and s(n−4)', 's(n−1) and s(n−3)', 'all four'], answer: 1, why: 'A term xᵏ in C(x) means the bit from k clocks ago is tapped.' },
      { q: 'An attacker sees a stretch of output from a known LFSR. What else does she need to predict the rest?', options: ['Nothing: L consecutive output bits are the whole state', 'The key schedule', 'All earlier output', 'At least 2^L bits'], answer: 0, why: 'L consecutive bits fill the register; from there the recurrence gives everything that follows.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
