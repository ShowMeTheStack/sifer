// Part 3, combining registers: the Geffe generator (three LFSRs and a selector) and the correlation attack that
// takes it apart one register at a time; then Trivium, whose three registers feed each other through AND gates.
(function (S) {
  'use strict';
  const U = S.SymT, G = () => S.Geffe, LF = () => S.LFSR;
  const xp = (k) => 'x' + U.sup(k);
  const pct = (a, n) => (100 * a / n).toFixed(1);

  // ---------------------------------------------------------------------------------------------------------------
  // Geffe and the correlation attack
  // ---------------------------------------------------------------------------------------------------------------
  function geffe(inp) {
    const n = inp.n, setup = G().setup({ seed: +inp.seed, n }), taps = setup.taps, seeds = setup.seeds, z = setup.z;
    const Ls = taps.map((t) => t[0]), x = seeds.map((s, i) => LF().sequence(taps[i], s, n + Ls[i]));
    const att = G().attack({ z, taps });
    const F = new S.Frames();
    const head = U.head('ge:h', 'Geffe: three LFSRs and a selector');
    // three registers, left; their outputs run straight into the selector
    const cw = 26, gap = 3, x0 = 76, ys = [92, 188, 284], mx = 560, mw = 128;
    const regs = (t, o) => {
      o = o || {};
      const items = [];
      for (let r = 0; r < 3; r++) {
        const L = Ls[r], W = L * (cw + gap) - gap, bits = x[r].slice(t, t + L);
        const g = S.Kit.reg.fib({ prefix: 'ge' + r, x: x0, y: ys[r], bits, taps: taps[r], cw, ch: cw, gap, rise: 30, lead: 24, outLen: mx - (x0 + W), size: 14, lit: o.lit ? { out: true } : {}, cls: () => (o.hi === r ? 'act' : '') });
        const dim = o.hi !== undefined && o.hi !== r;
        for (const it of g.items) { if (dim) it.dim = true; items.push(it); }
        items.push(U.t('ge:n' + r, x0 - 30, ys[r] + cw + 22, 'R' + (r + 1) + ': ' + L + ' cells, 1 + ' + taps[r].slice().sort((a, b) => a - b).map(xp).join(' + '), dim ? 'tick dim' : o.hi === r ? 'act' : 'tick', 'start', 13));
        if (o.chips) items.push({ key: 'ge:xc' + r, kind: 'chip', x: mx - 28, y: g.yMid, text: 'x' + U.sub(r + 1) + ' = ' + o.chips[r], cls: o.sel === r ? 'act' : 'plain' });
      }
      const ymid = ys.map((y) => y + cw / 2), top = ymid[0] - 26, bot = ymid[2] + 26;
      items.push({ key: 'ge:mux', kind: 'state', x: mx + mw / 2, y: (top + bot) / 2, w: mw, h: bot - top, rx: 8, lines: ['select', 'x₁ = 1: x₂', 'x₁ = 0: x₃'], cls: 'block' + (o.lit ? ' act' : '') });
      items.push({ key: 'ge:zw', kind: 'wire', pts: [[mx + mw, (top + bot) / 2], [mx + mw + 90, (top + bot) / 2]], head: true, cls: o.lit ? 'hot' : '' });
      items.push(U.t('ge:zl', mx + mw + 98, (top + bot) / 2 + 5, o.z === undefined ? 'z' : 'z = ' + o.z, o.z === undefined ? 'strong' : 'hot', 'start', 16));
      return items;
    };
    const N = Math.min(40, n);
    const rowsOf = (list, o) => {
      o = o || {};
      const items = [];
      list.forEach(([name, bits, cls], k) => {
        const y = 382 + k * 34;
        items.push(U.t('ge:rn' + k, 24, y + 17, name, 'strong', 'start', 14));
        items.push(...U.bitRow({ prefix: 'ge:r' + k, x: 76, y, bits: bits.slice(0, N), cw: 18, ch: 24, gap: 2, group: 8, groupGap: 4, size: 12, cls: (j, b) => cls(j, b) }).items);
      });
      return items;
    };
    const eqz = (j) => z[j] === x[1][j];
    const agree2 = x[1].slice(0, n).filter((b, j) => b === z[j]).length, agree3 = x[2].slice(0, n).filter((b, j) => b === z[j]).length;

    F.add({ items: [head, ...regs(0, {})], say: `Three LFSRs of ${Ls.join(', ')} cells run side by side; each clock x₁ chooses which of x₂ and x₃ becomes the output z: z = x₁·x₂ ⊕ (1 ⊕ x₁)·x₃. The key is the three start states, ${Ls.join(' + ')} = ${Ls[0] + Ls[1] + Ls[2]} bits, so trying every key means 2^${Ls[0] + Ls[1] + Ls[2]} guesses.`, facts: { Ls, sum: Ls[0] + Ls[1] + Ls[2] }, meta: { stage: 'setup' } });
    for (let t = 0; t < 3; t++) {
      const a = x[0][t], b = x[1][t], c = x[2][t];
      const so = (arr) => arr.slice(0, t + 1);
      const rows = rowsOf([['x₁', so(x[0]), (j) => (j === t ? 'act' : '')], ['x₂', so(x[1]), (j) => (x[0][j] ? 'act' : 'soft')], ['x₃', so(x[2]), (j) => (x[0][j] ? 'soft' : 'act')], ['z', so(z), (j) => (j === t ? 'hot' : '')]]);
      F.add({ items: [head, ...regs(t, { lit: true, chips: [a, b, c], sel: a ? 1 : 2, z: z[t] }), ...rows], hl: { d: [0] }, say: `Clock ${t + 1}: the registers put out x₁ = ${a}, x₂ = ${b} and x₃ = ${c}. Since x₁ = ${a}, the selector passes ${a ? 'x₂' : 'x₃'}, so z = ${z[t]}.`, facts: { t: t + 1, a, b, c, z: z[t] }, meta: { stage: 'clock', t } });
    }
    F.add({ items: [head, ...regs(0, {}), ...rowsOf([['x₁', x[0], (j, b2) => (b2 ? 'act' : '')], ['x₂', x[1], (j) => (eqz(j) ? 'good' : '')], ['x₃', x[2], (j) => (z[j] === x[2][j] ? 'good' : '')], ['z', z, () => 'hot']])],
      say: `The first ${N} bits of each stream, with every place where x₂ or x₃ equals z marked. Over all ${n} output bits z agrees with x₂ ${agree2} times (${pct(agree2, n)}%) and with x₃ ${agree3} times (${pct(agree3, n)}%): far more often than the half that unrelated bits would.`,
      facts: { N, n, agree2, agree3, p2: pct(agree2, n), p3: pct(agree3, n) }, meta: { stage: 'stream' } });
    // the truth table: z = x2 in six rows of eight
    const tt = [];
    for (let v = 0; v < 8; v++) { const a = v >> 2, b = (v >> 1) & 1, c = v & 1; tt.push({ a, b, c, z: G().combine(a, b, c) }); }
    const same2 = tt.filter((r) => r.z === r.b).length, same3 = tt.filter((r) => r.z === r.c).length;
    const ttItems = [...U.panel('ge:tt', 24, 360, 872, 250, 'the selector, all eight inputs')];
    ['x₁', 'x₂', 'x₃', 'z', 'z = x₂?', 'z = x₃?'].forEach((name, k) => ttItems.push(U.t('ge:th' + k, 150, 418 + k * 31, name, 'strong', 'end', 15)));
    tt.forEach((r, j) => {
      const X = 180 + j * 86;
      [r.a, r.b, r.c, r.z].forEach((v, k) => ttItems.push({ key: 'ge:tc' + j + ':' + k, kind: 'cell', x: X, y: 400 + k * 31, w: 70, h: 26, rx: 3, text: String(v), size: 14, cls: 'bit ' + (k === 3 ? 'hot' : '') }));
      ttItems.push({ key: 'ge:t2' + j, kind: 'cell', x: X, y: 524, w: 70, h: 26, rx: 3, text: r.z === r.b ? 'yes' : 'no', size: 13, cls: r.z === r.b ? 'good' : 'bad' });
      ttItems.push({ key: 'ge:t3' + j, kind: 'cell', x: X, y: 555, w: 70, h: 26, rx: 3, text: r.z === r.c ? 'yes' : 'no', size: 13, cls: r.z === r.c ? 'good' : 'bad' });
    });
    F.add({ items: [head, ...regs(0, {}), ...ttItems], hl: { d: [1] }, say: `Why: of the eight inputs, z equals x₂ in ${same2} and equals x₃ in ${same3}. When x₁ picks x₂ they agree by definition; when it picks x₃ they still agree half the time. So z leaks each of x₂ and x₃ with probability ${same2}/8, three in four: a correlation.`, facts: { same2, same3 }, meta: { stage: 'table' } });

    // the scans: every start state of one register against z
    const scan = (r) => {
      const L = Ls[r], all = [];
      for (let v = 1; v < 1 << L; v++) {
        const seed = Array.from({ length: L }, (_, i) => (v >> i) & 1), s = LF().sequence(taps[r], seed, n);
        let a = 0; for (let i = 0; i < n; i++) a += s[i] === z[i];
        all.push(a);
      }
      return all;
    };
    const hist = (r, all, best) => {
      const items = [], lo = 30, hi = 85, bins = new Array(hi - lo + 1).fill(0);
      for (const a of all) bins[Math.max(0, Math.min(hi - lo, Math.floor(100 * a / n) - lo))]++;
      const max = Math.max(...bins), px = 70, pw = 520, py = 400, ph = 170, bw = pw / bins.length, bestBin = Math.max(0, Math.min(hi - lo, Math.floor(100 * best / n) - lo));
      items.push(...U.panel('ge:hp', 24, 352, 600, 262, 'agreement with z, all ' + all.length + ' start states of R' + (r + 1)));
      items.push({ key: 'ge:ax', kind: 'path', d: `M${px},${py} V${py + ph} H${px + pw}`, cls: 'gaxis', audit: 'ignore', layer: 'back' });
      bins.forEach((c, k) => {
        if (!c) return;
        const h = Math.max(3, (c / max) * ph), right = k === bestBin;
        items.push({ key: 'ge:b' + k, kind: 'cell', x: U.r2(px + k * bw + 0.8), y: U.r2(py + ph - h), w: U.r2(bw - 1.6), h: U.r2(h), rx: 1, text: '', cls: 'gbar' + (right ? ' hot' : '') });
      });
      for (let p = 30; p <= 80; p += 10) items.push(U.t('ge:tk' + p, px + (p - lo) * bw, py + ph + 18, p + '%', 'tick', 'middle', 13));
      const bx = px + bestBin * bw + bw / 2;
      const bt = py + ph - Math.max(3, (bins[bestBin] / max) * ph);
      items.push({ key: 'ge:bp', kind: 'path', d: `M${U.r2(bx)},${py + 14} V${U.r2(bt - 4)}`, cls: 'trtap hot', audit: 'ignore' });
      items.push(U.t('ge:bl', bx + 6, py + 4, 'the best: ' + pct(best, n) + '%', 'hot', bx > px + pw - 80 ? 'end' : 'start', 13));
      items.push(U.t('ge:wl', px + (50 - lo) * bw, py - 8, 'wrong states, near 50%', 'tick', 'middle', 13));
      return items;
    };
    const top3 = (r, scores) => {
      const tr = att.trace[r === 1 ? 0 : 1].top.slice(0, 3);
      return U.readout('ge:tp', 640, 352, 256, 'best start states', tr.map((c, k) => [c.seed.join(''), pct(c.agree, n) + '%', k === 0 ? 'good' : '']), { size: 13, vsize: 14, dy: 34 });
    };
    for (const r of [1, 2]) {
      const all = scan(r), top = att.trace[r === 1 ? 0 : 1].top, best = top[0].agree, second = top[1].agree;
      const right = top[0].seed.join('') === seeds[r].join('');
      F.add({ items: [head, ...regs(0, { hi: r }), ...hist(r, all, best), ...top3(r)], hl: { d: [2] },
        say: `The attack on R${r + 1} alone: run each of its ${all.length} nonzero start states for ${n} bits and count where it agrees with z. Wrong states pile up around 50%; the best reaches ${pct(best, n)}% and the runner-up only ${pct(second, n)}%. ${right ? `The best is the true start state, ${seeds[r].join('')}` : `With so few bits the best is not the true start state`}${r === 2 ? ', found without knowing anything about R1 or R2' : ', found without knowing anything about R1 or R3'}.`,
        facts: { count: all.length, n, best: pct(best, n), second: pct(second, n), seed: seeds[r].join(''), r: r + 1 }, meta: { stage: 'scan', r, right } });
    }
    // R1 from the places where x2 and x3 differ
    const k1 = att.trace[2], x2 = att.seeds[1] ? LF().sequence(taps[1], att.seeds[1], n) : x[1], x3 = att.seeds[2] ? LF().sequence(taps[2], att.seeds[2], n) : x[2];
    const differ = (j) => x2[j] !== x3[j];
    const known = x2.map((b, j) => (differ(j) ? (z[j] === b ? 1 : 0) : null));
    const kItems = rowsOf([['x₂', x2, (j) => (differ(j) ? 'act' : '')], ['x₃', x3, (j) => (differ(j) ? 'act' : '')], ['z', z, (j) => (differ(j) ? 'hot' : '')], ['x₁', x[0], (j) => (differ(j) ? 'good' : 'soft')]]);
    F.add({ items: [head, ...regs(0, { hi: 0 }), ...kItems], hl: { d: [3] },
      say: `With x₂ and x₃ known, R1 falls too: wherever x₂ and x₃ differ (${k1.known} of the ${n} places), z shows which one was picked, so it shows x₁. ${k1.s1 ? `Only the start state ${k1.s1.join('')} of R1 fits all of them; it was found after ${k1.say.match(/\((\d+) states tried\)/)[1]} tries.` : 'No start state of R1 fits them all: one of the other registers was guessed wrong.'}`,
      facts: { known: k1.known, n, s1: k1.s1 ? k1.s1.join('') : '', tried: +(k1.say.match(/\((\d+) states tried\)/) || [0, 0])[1], first: known.slice(0, N).filter((v) => v !== null).length }, meta: { stage: 'x1' } });
    const work = (1 << Ls[1]) + (1 << Ls[2]) + (1 << Ls[0]), brute = 2 ** (Ls[0] + Ls[1] + Ls[2]);
    F.add({ items: [head, ...regs(0, {}), ...U.readout('ge:wk', 24, 352, 872, 'the cost', [['divide and conquer: 2' + U.sup(Ls[1]) + ' + 2' + U.sup(Ls[2]) + ' + 2' + U.sup(Ls[0]), U.big(work), 'good'], ['every key at once: 2' + U.sup(Ls[0] + Ls[1] + Ls[2]), U.big(brute), 'bad'], ['the recovered states reproduce z', att.ok ? 'all ' + n + ' bits' : 'no', att.ok ? 'good' : 'bad']], { dy: 40, size: 15, vsize: 17 })],
      say: att.ok ? `The three recovered start states reproduce all ${n} output bits. The attack tried ${U.big(work)} start states one register at a time, instead of ${U.big(brute)} keys: the correlation splits the key into pieces that can be guessed separately. A combining function must not let its output agree with any single input more often than half the time.` : `The recovered start states do not reproduce the output: ${n} bits are too few to separate the true states from the lucky ones. With more output the right state stands out further, since the wrong ones crowd ever closer to 50%.`,
      facts: { n, work, brute, workS: U.big(work), bruteS: U.big(brute) }, meta: { stage: 'done', ok: att.ok } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 630 });
    return { frames: F.list, def: U.def('The Geffe generator', ['z = x₁·x₂ ⊕ (1 ⊕ x₁)·x₃', 'Pr[z = x₂] = Pr[z = x₃] = 3/4', 'attack R2 alone: the right state agrees ~75%, wrong ones ~50%', 'then R3 alone, then R1 where x₂ ≠ x₃', 'work 2^L₁ + 2^L₂ + 2^L₃ instead of 2^(L₁+L₂+L₃)']) };
  }
  S.topic({
    id: 'st-geffe', family: 'p03-combine', order: 10, title: 'Geffe and the correlation attack',
    blurb: 'Three LFSRs and a selector look like a 31-bit key. But the output agrees with two of the registers three times in four, and that leak lets an attacker guess each register on its own.',
    inputs: [U.choice('seed', 'Secret start states', '1', [['1', 'Setting 1'], ['2', 'Setting 2'], ['5', 'Setting 3'], ['9', 'Setting 4']]), { id: 'n', kind: 'number', label: 'Output bits seen', def: 200, min: 60, max: 400 }],
    presets: [
      { label: '200 bits', values: { seed: '1', n: 200 } },
      { label: 'Setting 2, 300 bits', values: { seed: '2', n: 300 } },
      { label: 'Setting 3, 400 bits', values: { seed: '5', n: 400 } },
      { label: 'Only 60 bits', values: { seed: '9', n: 60 } },
    ],
    run: geffe,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'clock' && f.meta.t === 2, pick: 'option', options: ['about 50%', 'about 75%', 'always', 'never'], ask: 'Over many clocks, how often will z equal x₂?', answer: 'about 75%', explain: 'Half the time x₁ picks x₂; the other half z = x₃, which matches x₂ half of those times.' },
      { at: (f) => f.meta && f.meta.stage === 'table', pick: 'option', options: ['one start state of R2 near 75%', 'every start state near 75%', 'all of them near 50%'], ask: 'Now each start state of R2 alone is compared with z. What will the counts show?', answer: 'one start state of R2 near 75%', explain: 'Only the true state carries the correlation; a wrong state is unrelated to z and agrees about half the time.' },
    ],
    quiz: [
      { q: 'Why is the Geffe generator weak?', options: ['Its registers are too short', 'Its output agrees with x₂ (and with x₃) three times in four', 'It uses XOR', 'Its period is short'], answer: 1, why: 'The correlation lets each register be attacked on its own.' },
      { q: 'For registers of 7, 11 and 13 cells, the correlation attack costs about…', options: ['2^31 tries', '2^7 + 2^11 + 2^13 tries', '2^13 × 2^11 tries', '31 tries'], answer: 1, why: 'Divide and conquer: each register is searched separately.' },
      { q: 'How is R1 found once x₂ and x₃ are known?', options: ['By another correlation', 'Where x₂ ≠ x₃, z reveals x₁ directly', 'It cannot be', 'By Berlekamp–Massey on z'], answer: 1, why: 'If z = x₂ there, x₁ was 1; if z = x₃, x₁ was 0.' },
      { q: 'With very few output bits, the attack can fail because…', options: ['a wrong start state can agree with z by luck as well as the right one', 'the registers repeat', 'XOR is not invertible', 'R1 has no taps'], answer: 0, why: 'Wrong states spread around 50% with a spread that shrinks only as the number of bits grows.' },
      { q: 'What property should a combining function have against this attack?', options: ['Its output should agree with each single input exactly half the time (correlation immunity)', 'It should be linear', 'It should use only AND', 'It should have few inputs'], answer: 0, why: 'Then no single register can be tested against the output alone.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Trivium
  // ---------------------------------------------------------------------------------------------------------------
  const TR = { A: [1, 93], B: [94, 177], C: [178, 288] };
  // per register: the cells it outputs from, its AND pair, the cell of another register its new bit takes in
  const TAPS = [
    { name: 'A', first: 1, out: [66, 93], and: [91, 92], feeds: 94, t: 't₁', inCell: 171 },
    { name: 'B', first: 94, out: [162, 177], and: [175, 176], feeds: 178, t: 't₂', inCell: 264 },
    { name: 'C', first: 178, out: [243, 288], and: [286, 287], feeds: 1, t: 't₃', inCell: 69 },
  ];
  const sN = (i) => 's' + U.sub(i);
  /** the register state as loaded, before any clock: s1 … s80 the key bits (s1 the last), s94 … s173 the IV, s286 … s288 set */
  const loaded = (key, iv) => {
    const st = new Array(288).fill(0), bit = (b, j) => (b[j >> 3] >> (j & 7)) & 1;
    for (let j = 0; j < 80; j++) { st[79 - j] = bit(key, j); st[93 + 79 - j] = bit(iv, j); }
    st[285] = st[286] = st[287] = 1;
    return st;
  };
  function trivium(inp) {
    const key = U.fromHex(inp.key), iv = U.fromHex(inp.iv), n = inp.clocks;
    const tr = S.Trivium.trace(key, iv, n).trace, init = loaded(key, iv);
    const F = new S.Frames(), cw = 7.8, ch = 22, x0 = 34, ys = [112, 236, 360];
    const head = U.head('tr:h', 'Trivium: three registers, 288 bits');
    const xOf = (s) => { const r = s <= 93 ? 0 : s <= 177 ? 1 : 2, i = s - [1, 94, 178][r]; return { r, x: U.r2(x0 + i * cw + cw / 2) }; };
    const lookOf = (st, s, lit, phase) => {
      const b = st[s - 1];
      if (phase === 'load') return s <= 80 ? (b ? '4' : '0') : s >= 94 && s <= 173 ? (b ? '3' : '0') : s >= 286 ? '2' : '0';
      if (lit) { for (const T of TAPS) { if (T.out.includes(s)) return '3'; if (T.and.includes(s)) return '2'; if (s === T.inCell) return '4'; } }
      return b ? '1' : '0';
    };
    const regs = (st, o) => {
      o = o || {};
      const items = [];
      TAPS.forEach((T, r) => {
        const [a, b] = TR[T.name], y = ys[r];
        let row = '';
        for (let s2 = a; s2 <= b; s2++) row += lookOf(st, s2, o.lit, o.phase);
        items.push({ key: 'tr:bm' + r, kind: 'bitmap', x: x0, y, cw, ch, gap: 1.2, rows: [row] });
        items.push(U.t('tr:rn' + r, x0, y - 12, 'register ' + T.name + ': ' + sN(a) + ' … ' + sN(b) + ' (' + (b - a + 1) + ' bits)', 'strong', 'start', 14));
        if (o.lit) {
          // marks under the output and AND cells, over the cell another register takes in
          const mark = (s2, below, cls, text, k) => {
            const p = xOf(s2), yy = below ? ys[p.r] + ch + 2 : ys[p.r] - 2;
            items.push({ key: 'tr:m' + k, kind: 'path', d: `M${p.x},${yy} V${below ? yy + 8 : yy - 8}`, cls: 'trtap ' + cls, audit: 'ignore' });
            if (text) items.push(U.t('tr:ml' + k, p.x, below ? yy + 23 : yy - 13, text, cls === 'hot' ? 'hot' : cls === 'key' ? 'key' : 'act', 'middle', 13));
          };
          T.out.forEach((s2, k) => mark(s2, true, '', k ? '' : String(s2), r + 'o' + k));
          mark(T.out[1], true, '', '', r + 'o9');
          T.and.forEach((s2, k) => mark(s2, true, 'hot', '', r + 'a' + k));
          items.push(U.t('tr:al' + r, xOf(T.out[1]).x - 8, ys[r] + ch + 25, T.and[0] + '·' + T.and[1] + ' ' + T.out[1], 'tick', 'end', 13));
          mark(T.inCell, false, 'key', String(T.inCell), r + 'i');
        }
      });
      // the feedback wires: the end of each register feeds the start of the next, C feeds A
      const ends = [0, 1, 2].map((r) => x0 + (TR[TAPS[r].name][1] - TR[TAPS[r].name][0] + 1) * cw), mid = (r) => ys[r] + ch / 2;
      const lit = !!o.lit;
      items.push({ key: 'tr:wAB', kind: 'wire', pts: [[ends[0], mid(0)], [ends[0] + 40, mid(0)], [ends[0] + 40, 186], [x0 - 18, 186], [x0 - 18, mid(1)], [x0, mid(1)]], head: true, cls: lit ? 'act' : '' });
      items.push({ key: 'tr:wBC', kind: 'wire', pts: [[ends[1], mid(1)], [ends[1] + 40, mid(1)], [ends[1] + 40, 310], [x0 - 18, 310], [x0 - 18, mid(2)], [x0, mid(2)]], head: true, cls: lit ? 'act' : '' });
      items.push({ key: 'tr:wCA', kind: 'wire', pts: [[ends[2], mid(2)], [ends[2] + 14, mid(2)], [ends[2] + 14, 76], [x0 - 26, 76], [x0 - 26, mid(0)], [x0, mid(0)]], head: true, cls: lit ? 'act' : '' });
      if (o.fb) {
        items.push({ key: 'tr:fA', kind: 'chip', x: U.r2(x0 + 300), y: 76, text: sN(1) + ' ← ' + o.fb[0], cls: 'act' });
        items.push({ key: 'tr:fB', kind: 'chip', x: U.r2(x0 + 300), y: 186, text: sN(94) + ' ← ' + o.fb[1], cls: 'act' });
        items.push({ key: 'tr:fC', kind: 'chip', x: U.r2(x0 + 300), y: 310, text: sN(178) + ' ← ' + o.fb[2], cls: 'act' });
      }
      return items;
    };
    const mode = 'key: ' + U.hexs(key) + '   IV: ' + U.hexs(iv);
    F.add({ items: [head, ...regs(init, { phase: 'load' }), ...U.readout('tr:p', 24, 430, 872, 'loading', [['the key, 80 bits (last bit first)', sN(1) + ' … ' + sN(80) + '  ' + U.hex(key), 'key'], ['the IV, 80 bits', sN(94) + ' … ' + sN(173) + '  ' + U.hex(iv), 'act'], ['set to 1', sN(286) + ', ' + sN(287) + ', ' + sN(288), 'hot'], ['every other cell', '0']], { dy: 34 })],
      say: `Trivium keeps 288 bits in three shift registers of 93, 84 and 111 cells. The 80-bit key ${U.hex(key)} goes into the start of the first, the 80-bit IV ${U.hex(iv)} into the start of the second, the last three cells of the third are set to 1, and every other cell is 0.`,
      facts: { key: U.hex(key), iv: U.hex(iv) }, meta: { stage: 'load' } });
    const warm = tr[0].state, ones = warm.filter((b) => b).length;
    F.add({ items: [head, ...regs(warm, {}), ...U.readout('tr:p', 24, 430, 872, 'after the warm-up', [['clocks with no output', '4 × 288 = 1152'], ['bits set now', ones + ' of 288'], [mode, '']], { dy: 34 })],
      say: `Before any output, the cipher is clocked 4 × 288 = 1152 times and the output thrown away, so that every key and IV bit has passed through the AND gates and mixed into every cell. Now ${ones} of the 288 bits are set, with no trace of the key's pattern.`,
      facts: { ones }, meta: { stage: 'warm' } });
    const zs = [];
    for (let k = 0; k < n; k++) {
      const before = tr[k].state, L = tr[k + 1], b = (s2) => before[s2 - 1];
      zs.push(L.z);
      const lines = TAPS.map((T, r) => {
        const t = [L.t1, L.t2, L.t3][r], and = [L.and1, L.and2, L.and3][r];
        return [
          `${T.t} = ${sN(T.out[0])} ⊕ ${sN(T.out[1])} = ${b(T.out[0])} ⊕ ${b(T.out[1])} = ${t}`,
          `${sN(T.and[0])}·${sN(T.and[1])} = ${b(T.and[0])}·${b(T.and[1])} = ${and}`,
          `${sN(T.feeds)} ← ${T.t} ⊕ ${and} ⊕ ${sN(T.inCell)} = ${[L.f2, L.f3, L.f1][r]}`,
        ];
      });
      const pItems = [...U.panel('tr:p', 24, 430, 872, 190, 'clock ' + (k + 1))];
      lines.forEach((ls, r) => ls.forEach((t, j) => pItems.push(U.t('tr:pl' + r + j, 40 + r * 290, 476 + j * 30, t, j === 2 ? 'math act' : 'math', 'start', 14))));
      pItems.push(U.t('tr:pz', 40, 600, `z = t₁ ⊕ t₂ ⊕ t₃ = ${L.t1} ⊕ ${L.t2} ⊕ ${L.t3} = ${L.z}   ·   output so far: ${zs.join('')}`, 'math hot', 'start', 15));
      F.add({ items: [head, ...regs(before, { lit: true, fb: [L.f1, L.f2, L.f3] }), ...pItems], hl: { d: [1, 2, 3] },
        say: `Clock ${k + 1}: each register adds two of its own cells, t₁ = ${L.t1}, t₂ = ${L.t2} and t₃ = ${L.t3}, and the output is z = ${L.z}. Each new bit is that sum, the AND of two neighbouring cells and one cell of another register: s₁ ← ${L.f1}, s₉₄ ← ${L.f2}, s₁₇₈ ← ${L.f3}. Every register then shifts one place along.`,
        facts: { k: k + 1, t: [L.t1, L.t2, L.t3], z: L.z, f: [L.f1, L.f2, L.f3] }, meta: { stage: 'clock', k } });
    }
    const msg = U.bytesOf('low tide'), ks = S.Trivium.create(key, iv).keystream(msg.length), ct = S.Trivium.encrypt(key, iv, msg);
    F.add({ items: [head, ...regs(tr[n].state, {}), ...U.readout('tr:p', 24, 430, 872, 'the keystream', [['the first ' + n + ' output bits', zs.join('')], ['as bytes (first bit lowest)', U.hexs(ks), 'act'], ['“low tide”', U.hexs(msg)], ['⊕ keystream', U.hexs(ct), 'hot']], { dy: 34 })],
      say: `The output bits form the keystream, packed into bytes with the first bit as the lowest: ${U.hexs(ks)}. XORed with the ASCII of “low tide” it gives the ciphertext ${U.hexs(ct)}. Each clock costs three ANDs and a few XORs: Trivium was built for small, cheap hardware.`,
      facts: { ks: U.hexs(ks), ct: U.hexs(ct), n }, meta: { stage: 'stream' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 632 });
    return { frames: F.list, def: U.def('Trivium', ['t₁ = s₆₆ ⊕ s₉₃,  t₂ = s₁₆₂ ⊕ s₁₇₇,  t₃ = s₂₄₃ ⊕ s₂₈₈', 'z = t₁ ⊕ t₂ ⊕ t₃', 's₉₄ ← t₁ ⊕ s₉₁·s₉₂ ⊕ s₁₇₁', 's₁₇₈ ← t₂ ⊕ s₁₇₅·s₁₇₆ ⊕ s₂₆₄', 's₁ ← t₃ ⊕ s₂₈₆·s₂₈₇ ⊕ s₆₉', 'key → s₁…s₈₀, IV → s₉₄…s₁₇₃, s₂₈₆…s₂₈₈ = 1; 1152 warm-up clocks']) };
  }
  const hex10 = (label) => (v) => (String(v).length === 20 ? null : label + ': exactly 10 bytes (20 hex digits)');
  S.topic({
    id: 'st-trivium', family: 'p03-combine', order: 20, title: 'Trivium\'s three registers',
    blurb: 'Three shift registers in a ring, 288 bits in all. Each feeds the next through an AND of two neighbouring cells, the only nonlinear step, and 1152 warm-up clocks pass before the first output bit.',
    inputs: [{ id: 'key', kind: 'hex', label: 'Key (10 bytes)', def: '6865726f6e7265656473', bytes: 10, check: hex10('Key') }, { id: 'iv', kind: 'hex', label: 'IV (10 bytes)', def: '746964652f30333a3137', bytes: 10, check: hex10('IV') }, { id: 'clocks', kind: 'number', label: 'Clocks to watch', def: 4, min: 2, max: 10 }],
    presets: [
      { label: 'Key “heronreeds”', values: { key: '6865726f6e7265656473', iv: '746964652f30333a3137', clocks: 4 } },
      { label: 'Same key, next IV', values: { key: '6865726f6e7265656473', iv: '746964652f30333a3138', clocks: 4 } },
      { label: 'All zero', values: { key: '00000000000000000000', iv: '00000000000000000000', clocks: 6 } },
      { label: 'eSTREAM set 1, vector 0', values: { key: '80000000000000000000', iv: '00000000000000000000', clocks: 3 } },
    ],
    run: trivium,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'load', pick: 'option', options: ['0', '93', '288', '1152'], ask: 'How many clocks pass before the first keystream bit is used?', answer: '1152', explain: 'Four full turns of the 288-bit state, so that key and IV are mixed through the nonlinear feedback.' },
      { at: (f) => f.meta && f.meta.stage === 'warm', pick: 'option', options: ['linear', 'nonlinear'], ask: 'The output z is the XOR of six cells. Is z, given the state of this clock, a linear or a nonlinear function of it?', answer: 'linear', explain: 'z itself is a plain XOR; the nonlinearity comes in through the ANDs in the feedback, and builds up clock after clock.' },
    ],
    quiz: [
      { q: 'Where does Trivium get its nonlinearity?', options: ['From the output XOR', 'From the AND of two neighbouring cells in each feedback', 'From the IV', 'From S-boxes'], answer: 1, why: 'Without the three ANDs Trivium would be one big LFSR, broken by Berlekamp–Massey.' },
      { q: 'How big is Trivium\'s state?', options: ['80 bits', '160 bits', '288 bits', '1152 bits'], answer: 2, why: '93 + 84 + 111 = 288.' },
      { q: 'Why does Trivium clock 1152 times before giving output?', options: ['To slow attackers', 'So key and IV bits are mixed through the whole state before anything is revealed', 'To fill the IV', 'It is a hardware delay'], answer: 1, why: 'Early output bits would otherwise depend simply on few key bits.' },
      { q: 'Why must the IV change for each message under one key?', options: ['It does not matter', 'The same key and IV give the same keystream: a two-time pad', 'The registers would stop', 'The warm-up would be skipped'], answer: 1, why: 'A stream cipher is a keystream generator; reusing its input reuses its output.' },
      { q: 'How many output bits does Trivium give per clock?', options: ['1', '3', '8', '288'], answer: 0, why: 'z = t₁ ⊕ t₂ ⊕ t₃, one bit; hardware can compute 64 clocks at once because the taps are far from the inputs.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
