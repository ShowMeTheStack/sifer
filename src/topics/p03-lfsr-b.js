// Part 3, LFSRs further: the period (every nonzero state of the register, split into the cycles the register walks
// round, one long cycle exactly when C(x) is primitive), and the Galois form beside the Fibonacci form, different
// registers giving the same output.
(function (S) {
  'use strict';
  const U = S.SymT, LF = () => S.LFSR, GP = () => S.GF.poly, NTK = () => S.Kit.nt;
  const xp = (k) => 'x' + U.sup(k);
  const polyText = (taps) => '1 + ' + taps.slice().sort((a, b) => a - b).map((k) => (k === 1 ? 'x' : xp(k))).join(' + ');
  const tapsOf = (inp) => inp.taps.map(Number).sort((a, b) => b - a);
  /** the register as drawn: newest bit on the left */
  const disp = (st) => st.slice().reverse().join('');

  /** a GF(2) polynomial (BigInt mask) as text, 1 first */
  const pstr = (p) => { const t = []; for (let k = 0; (p >> BigInt(k)) > 0n; k++) if ((p >> BigInt(k)) & 1n) t.push(k === 0 ? '1' : k === 1 ? 'x' : xp(k)); return t.join(' + '); };
  /** the irreducible factors of f with their multiplicities, by trial division (degree ≤ 6) */
  const factor = (f) => {
    const out = [];
    let g = f;
    for (let d = 1; d <= 6 && GP().deg(g) >= 1; d++) {
      for (let p = 1n << BigInt(d); p < 1n << BigInt(d + 1); p++) {
        if (!GP().isIrreducible(p)) continue;
        let k = 0;
        while (GP().deg(g) >= d && GP().divmod(g, p).r === 0n) { g = GP().divmod(g, p).q; k++; }
        if (k) out.push([p, k]);
      }
    }
    return out;
  };
  const factorText = (fs) => fs.map(([p, k]) => (fs.length === 1 && k === 1 ? pstr(p) : '(' + pstr(p) + ')') + (k > 1 ? U.sup(k) : '')).join('·');

  // ---------------------------------------------------------------------------------------------------------------
  // Period and primitive polynomials
  // ---------------------------------------------------------------------------------------------------------------
  function period(inp) {
    const taps = tapsOf(inp), L = taps[0], N = 2 ** L;
    // walk every nonzero state with the register itself, collecting the cycles it runs round
    const seen = new Set(), cycles = [];
    for (let v = 1; v < N; v++) {
      const st = Array.from({ length: L }, (_, i) => (v >> i) & 1), k = disp(st);
      if (seen.has(k)) continue;
      const reg = LF().fibonacci(taps, st), list = [];
      let cur = k;
      do { seen.add(cur); list.push(cur); cur = disp(reg.step().state); } while (cur !== k && list.length <= N);
      cycles.push(list);
    }
    const lens = cycles.map((c) => c.length), f = LF().poly(taps), prim = LF().isPrimitive(taps), irr = GP().isIrreducible(f), fs = factor(f);
    const per0 = LF().period(taps, Array.from({ length: L }, (_, i) => (i === 0 ? 1 : 0)));
    const nPrim = Number(S.NT.phi(N - 1).phi) / L;
    // layout: rings on a shelf, biggest first, the zero state last
    const bin = L <= 4, nodeW = bin ? 48 : 26, nodeH = 26;
    const label = (st) => (bin ? st : String(parseInt(st, 2)));
    const order = cycles.map((c, i) => i).sort((a, b) => cycles[b].length - cycles[a].length);
    const all = order.map((i) => ({ i, list: cycles[i] })).concat([{ i: -1, list: ['0'.repeat(L)] }]);
    // pack the rings on shelves in the area left of the panels, as widely spaced as they fit
    const pack = (sp) => {
      const out = [];
      let x = 24, y = 64, rowH = 0;
      for (const c of all) {
        const one = c.list.length === 1, R = one ? 0 : Math.max((c.list.length * sp) / (2 * Math.PI), 36), size = 2 * R + nodeW + 14, hgt = 2 * R + nodeH + (one ? 44 : 30);
        if (x + size > 596 && x > 24) { x = 24; y += rowH + 12; rowH = 0; }
        out.push({ c, R, cx: U.r2(x + size / 2), cy: U.r2(y + (one ? 30 : 0) + hgt / 2) });
        x += size + 12; rowH = Math.max(rowH, hgt);
        if (x - 12 > 596) return null;
      }
      return y + rowH <= 612 ? out : null;
    };
    let place = null;
    if (all[0].list.length > 40) place = [{ c: all[0], R: 0, cx: 300, cy: 340, rect: { x0: 44, y0: 92, w: 520, h: 496 } }, { c: all[1], R: 0, cx: 300, cy: 300 + 34 }];
    for (let sp = bin ? 130 : 90; !place && sp >= 30; sp -= 2) place = pack(sp);
    if (!place) {
      // a few long cycles: tall ellipses side by side; the single states sit inside the first one
      const big = all.filter((c) => c.list.length > 1), one = all.filter((c) => c.list.length === 1), cwid = 572 / big.length;
      place = big.map((c, j) => ({ c, R: 0, cx: U.r2(24 + cwid * (j + 0.5)), cy: 340, ell: { a: cwid / 2 - 20, b: 252 } }));
      one.forEach((c, j) => place.push({ c, R: 0, cx: place[0].cx, cy: 300 + j * 80 }));
    }
    const ring = (p, cls, lit) => {
      const items = [], n = p.c.list.length, P = 'pr' + p.c.i;
      if (n === 1) {
        const s = p.c.list[0];
        items.push(...NTK().arc({ key: P + ':loop', cx: p.cx, cy: p.cy - nodeH / 2 - 12, r: 12, a0: 215, a1: 505, cls: 'thin ' + (cls === 'soft' ? 'faint' : cls) }));
        items.push(node(P + ':n0', p.cx, p.cy, label(s), cls, lit && lit(0)));
        return items;
      }
      if (p.ell) {
        // equal steps of arc length round the ellipse
        const { a, b } = p.ell, M = 720, pts = [], cum = [0];
        for (let i = 0; i <= M; i++) { const t = (2 * Math.PI * i) / M; pts.push({ x: p.cx + a * Math.sin(t), y: p.cy - b * Math.cos(t) }); if (i) cum.push(cum[i - 1] + Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y)); }
        const at = (k) => { const want = (k / n) * cum[M]; let i = 0; while (cum[i + 1] < want) i++; return pts[i]; };
        items.push({ key: P + ':ring', kind: 'path', d: `M${p.cx},${U.r2(p.cy - b)} A${U.r2(a)},${b} 0 1 1 ${p.cx},${U.r2(p.cy + b)} A${U.r2(a)},${b} 0 1 1 ${p.cx},${U.r2(p.cy - b)}`, cls: 'nt-ring', audit: 'ignore', layer: 'back' });
        p.c.list.forEach((s, k) => { const q = at(k); items.push(node(P + ':n' + k, q.x, q.y, label(s), cls, lit && lit(k))); });
        return items;
      }
      if (p.rect) {
        // a long cycle runs round the edge of a rounded rectangle, which has room for more states than a circle
        const { x0, y0, w, h } = p.rect, per = 2 * (w + h);
        // so many states on each edge that a corner holds a state and the spacing is even along every edge
        const nw = Math.round((n * w) / per), nh = Math.round((n * h) / per), cnt = [nw, nh, nw, n - 2 * nw - nh];
        const at = (k) => { let e = 0; while (k >= cnt[e]) { k -= cnt[e]; e++; } const t = k / cnt[e]; return [{ x: x0 + t * w, y: y0 }, { x: x0 + w, y: y0 + t * h }, { x: x0 + w - t * w, y: y0 + h }, { x: x0, y: y0 + h - t * h }][e]; };
        items.push({ key: P + ':ring', kind: 'path', d: `M${x0},${y0} H${x0 + w} V${y0 + h} H${x0} Z`, cls: 'nt-ring', audit: 'ignore', layer: 'back' });
        p.c.list.forEach((s, k) => { const q = at(k); items.push(node(P + ':n' + k, q.x, q.y, label(s), cls, lit && lit(k))); });
        return items;
      }
      const pos = (k) => NTK().at(n, k, p.cx, p.cy, p.R), gapDeg = ((Math.max(nodeW, nodeH) / 2 + 4) / p.R) * (180 / Math.PI) * (bin ? 0.9 : 1);
      const step = 360 / n, arcs = step - 2 * gapDeg > 4;
      if (arcs) for (let k = 0; k < n; k++) items.push(...NTK().arc({ key: P + ':a' + k, cx: p.cx, cy: p.cy, r: p.R, a0: k * step + gapDeg, a1: (k + 1) * step - gapDeg, cls: 'thin ' + (cls === 'soft' ? 'faint' : cls), head: step - 2 * gapDeg > 14 }));
      else items.push({ key: P + ':ring', kind: 'path', d: `M${p.cx},${U.r2(p.cy - p.R)} A${U.r2(p.R)},${U.r2(p.R)} 0 1 1 ${p.cx},${U.r2(p.cy + p.R)} A${U.r2(p.R)},${U.r2(p.R)} 0 1 1 ${p.cx},${U.r2(p.cy - p.R)}`, cls: 'nt-ring', audit: 'ignore', layer: 'back' });
      p.c.list.forEach((s, k) => { const q = pos(k); items.push(node(P + ':n' + k, q.x, q.y, label(s), cls, lit && lit(k))); });
      return items;
    };
    function node(key, x0, y0, text, cls, lit) {
      return bin ? { key, kind: 'state', x: U.r2(x0), y: U.r2(y0), w: nodeW, h: nodeH, rx: 5, text, cls: 'ntp prst ' + (lit ? 'hot' : cls) }
        : { key, kind: 'state', x: U.r2(x0), y: U.r2(y0), r: 12.5, text, size: 13, cls: 'ntp prst small ' + (lit ? 'hot' : cls) };
    }
    const F = new S.Frames(), poly = polyText(taps), head = U.head('pr:h', 'The states of C(x) = ' + poly);
    const reg = (st) => { const g = S.Kit.reg.fib({ prefix: 'prg', x: 668, y: 122, bits: st.slice().reverse().map(Number), taps, cw: 26, ch: 26, gap: 4, rise: 30, lead: 24, outLen: 30, size: 14 }); return g.items; };
    const right = (shown, extra) => {
      const items = [...U.panel('pr:r', 620, 54, 276, 128, 'the register')];
      items.push(...U.panel('pr:c', 620, 196, 276, 404, 'cycles'));
      const rows = all.slice(0, shown).concat(shown < all.length && extra ? [] : []);
      rows.forEach((c, j) => items.push(U.t('pr:cl' + j, 640, 252 + j * 28, c.i < 0 ? 'the zero state, alone' : 'cycle of ' + c.list.length + (c.list.length === 1 ? ' state' : ' states'), c.i < 0 ? 'tick' : j === shown - 1 && !extra ? 'act' : 'mono', 'start', 15)));
      return items;
    };
    const cls = (j, upto, cur) => (j === cur ? 'act' : j < upto ? '' : 'soft');
    const draw = (upto, cur) => place.map((p, j) => ring(p, p.c.i < 0 ? 'soft' : cls(j, upto, cur))).flat();
    const start = cycles[0][0];
    const startBits = start.split('').reverse().map(Number);
    F.add({ items: [head, ...draw(0, -1), ...right(0), ...reg(startBits)], say: `A register of ${L} cells has 2^${L} = ${N} states. The all-zero state goes nowhere (it stays zero); the other ${N - 1} fall into cycles, because each state has exactly one next state and exactly one previous one. Start from ${label(start)}.`, facts: { L, N, n1: N - 1, start: label(start) }, meta: { stage: 'start', per: per0 } });
    order.forEach((ci, j) => {
      const c = cycles[ci], first = c[0];
      const say = j === 0 ? `From state ${label(first)} the register runs through ${c.length} states and comes back: the period from this state is ${c.length}.` + (c.length === N - 1 ? ` That is every nonzero state, the most any ${L}-cell register can manage.` : ` That leaves ${N - 1 - c.length} nonzero states it never visits.`)
        : `A state not yet seen, ${label(first)}, starts another cycle of ${c.length}.` + (j === order.length - 1 ? ` That covers all ${N - 1} nonzero states: ${order.map((i) => cycles[i].length).join(' + ')} = ${N - 1}.` : '');
      F.add({ items: [head, ...draw(j + 1, j), ...right(j + 1), ...reg(first.split('').reverse().map(Number))], hl: { d: [1] }, say, facts: { len: c.length, first: label(first), left: N - 1 - c.length, lens, n1: N - 1, L }, meta: { stage: 'cycle', j } });
    });
    const verdict = prim ? 'primitive' : irr ? 'irreducible, not primitive' : 'reducible';
    const sum = [head, ...draw(all.length, -1), ...right(all.length, true)];
    const sp2 = [...U.panel('pr:s', 620, 54, 276, 128, 'C(x) is ' + (prim ? 'primitive' : 'not primitive'), prim ? 'good' : 'bad'),
      U.t('pr:s0', 636, 108, irr ? 'irreducible' : '= ' + factorText(fs), 'math', 'start', fs.length > 1 && !irr ? 13 : 15),
      U.t('pr:s1', 636, 140, 'from ' + label(cycles[0][0]) + ': period ' + per0 + (prim ? ' = 2' + U.sup(L) + ' − 1' : ' < 2' + U.sup(L) + ' − 1 = ' + (N - 1)), prim ? 'good' : 'bad', 'start', 15),
      U.t('pr:s2', 636, 166, nPrim + ' primitive polynomials of degree ' + L, 'tick', 'start', 13)];
    F.add({ items: [...sum.filter((it) => !String(it.key).startsWith('pr:r')), ...sp2], hl: { d: [2, 3, 4] },
      say: prim ? `C(x) = ${poly} is primitive: one cycle through all ${N - 1} nonzero states, so any nonzero seed gives the maximal period 2^${L} − 1. There are ${nPrim} primitive polynomials of degree ${L}; a designer always picks one of them.`
        : `C(x) = ${poly} is ${verdict}${irr ? '' : ': ' + factorText(fs)}. The states split into cycles of ${lens.join(', ')}, so the period depends on the seed and is at most ${Math.max(...lens)}, short of 2^${L} − 1 = ${N - 1}. Only a primitive C(x) (there are ${nPrim} of degree ${L}) gives one full cycle.`,
      facts: { N, n1: N - 1, nPrim, lens, max: Math.max(...lens), L, prim, irr }, meta: { stage: 'end' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 620 });
    return { frames: F.list, def: U.def('Period of an LFSR', ['the next state is a function of the state, and it can be undone', 'so the 2^L − 1 nonzero states split into cycles', 'period = length of the cycle the seed is on ≤ 2^L − 1', 'maximal for every seed ⇔ C(x) is primitive', 'primitive ⇒ irreducible; the converse can fail']) };
  }
  S.topic({
    id: 'st-period', family: 'p03-lfsr', order: 30, title: 'Period and primitive polynomials',
    blurb: 'Every nonzero state of a register lies on a cycle. A primitive connection polynomial makes one cycle through all 2^L − 1 of them; any other splits the states into shorter loops.',
    inputs: [{ id: 'taps', kind: 'list', label: 'Taps (exponents of C(x))', def: ['4', '3'], check: U.tapsCheck(6) }],
    presets: [
      { label: '1 + x³ + x⁴ (primitive)', values: { taps: ['4', '3'] } },
      { label: '1 + x + x² + x³ + x⁴ (irreducible)', values: { taps: ['4', '3', '2', '1'] } },
      { label: '1 + x² + x⁴ (reducible)', values: { taps: ['4', '2'] } },
      { label: '1 + x⁴ (a rotation)', values: { taps: ['4'] } },
      { label: '1 + x³ + x⁵ (primitive)', values: { taps: ['5', '3'] } },
      { label: '1 + x + x⁵', values: { taps: ['5', '1'] } },
      { label: '1 + x³ + x⁶', values: { taps: ['6', '3'] } },
      { label: '1 + x⁵ + x⁶ (63 states)', values: { taps: ['6', '5'] } },
      { label: '1 + x⁴ + x⁵ + x⁶ (two long cycles)', values: { taps: ['6', '5', '4'] } },
    ],
    run: period,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'start', once: true, pick: 'option', options: (fr) => { const L = fr[0].facts.L, N = 2 ** L; return [...new Set([String(L), String(N / 2 - 1), String(fr[0].meta.per), String(N - 1)])].sort((a, b) => a - b); }, ask: 'How many states will the register pass through before it returns to its start?', answer: (fr) => String(fr[0].meta.per), explain: 'Count the cycle that is drawn next.' }],
    quiz: [
      { q: 'What is the largest possible period of an LFSR with 8 cells?', options: ['8', '255', '256', '65535'], answer: 1, why: '2^8 − 1: every state but the all-zero one.' },
      { q: 'Why do the states of an LFSR split into cycles rather than ending somewhere?', options: ['Because the register is circular', 'Each state has one successor and one predecessor, so the map is a permutation', 'Because the taps are random', 'They do end, at zero'], answer: 1, why: 'With c_L = 1 the step can be run backwards, so no two states lead to the same one.' },
      { q: 'C(x) is irreducible but not primitive. Then…', options: ['the period is 2^L − 1', 'all nonzero states lie on cycles of the same length, shorter than 2^L − 1', 'the register outputs zeros', 'the period depends on nothing'], answer: 1, why: 'The period is the order of x modulo C(x), a proper divisor of 2^L − 1.' },
      { q: 'With C(x) = 1 + x⁴ the register…', options: ['has period 15', 'just rotates its seed, so the period is at most 4', 'is primitive', 'cannot be started'], answer: 1, why: 's(n) = s(n−4): the seed repeats every four clocks.' },
      { q: 'How many primitive polynomials of degree 4 are there over GF(2)?', options: ['1', '2', '4', '15'], answer: 1, why: 'φ(15) / 4 = 8 / 4 = 2: 1 + x + x⁴ and 1 + x³ + x⁴.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Galois against Fibonacci
  // ---------------------------------------------------------------------------------------------------------------
  function galois(inp) {
    const taps = tapsOf(inp), L = taps[0], seed = U.toBits(inp.seed), n = inp.clocks;
    const fib = LF().fibonacci(taps, seed), gal = LF().galois(taps, seed);
    const seq = LF().sequence(taps, seed, n + L);
    const cw = L <= 6 ? 46 : 40, F = new S.Frames(), poly = polyText(taps);
    const head = U.head('ga:h', 'Two forms of C(x) = ' + poly);
    const Wf = L * (cw + 6) - 6, xf = Math.round((920 - Wf) / 2);
    const tapSet = new Set(taps);
    const wGal = (() => { let w = 0; for (let c = 0; c < L; c++) w += cw + (c < L - 1 ? (tapSet.has(L - 1 - c) ? 36 : 6) : 0); return w; })(), xg = Math.round((920 - wGal) / 2);
    const outRow = (P, y, upto, hot) => [...U.bitRow({ prefix: P, x: 160, y, bits: seq.slice(0, upto), cw: 26, ch: 28, group: 4, groupGap: 6, size: 14, cls: (j) => (j === hot ? 'hot' : '') }).items];
    const tapCols = new Set(taps.map((k) => k - 1));
    const draw = (i, lit, fb, gb, fbBit) => [head,
      U.t('ga:ft', 24, 64, 'Fibonacci: one XOR of the tapped cells feeds the left end', 'title', 'start', 14),
      ...S.Kit.reg.fib({ prefix: 'gf', x: xf, y: 132, bits: fb, taps, cw, ch: cw, gap: 6, rise: 38, lit: lit ? { taps: true, fb: true, out: true } : {}, fbBit: lit ? fbBit : null, ids: (c) => i + L - 1 - c, label: (c) => xp(c + 1), cls: (c) => (lit && tapCols.has(c) ? 'act' : lit && c === L - 1 ? 'hot' : ''), size: 18 }).items,
      U.t('ga:gt', 24, 252, 'Galois: the output is XORed back into the cells after the taps', 'title', 'start', 14),
      ...S.Kit.reg.galois({ prefix: 'gg', x: xg, y: 278, bits: gb, taps, cw, ch: cw, gap: 6, xgap: 36, lit: lit ? { fb: true, out: true } : {}, fbBit: lit ? gb[0] : null, label: (c) => 'r' + U.sub(L - 1 - c), cls: (c) => (lit && c === L - 1 ? 'hot' : ''), size: 18 }).items,
      ...U.panel('ga:o', 24, 396, 872, 116, 'the two output streams'),
      U.t('ga:fo', 44, 456, 'Fibonacci', 'strong', 'start', 15), ...outRow('gfo', 436, lit ? i + 1 : i, lit ? i : -1),
      U.t('ga:go', 44, 494, 'Galois', 'strong', 'start', 15), ...outRow('ggo', 474, lit ? i + 1 : i, lit ? i : -1)];
    const nx = taps.length - 1;
    const cmp = (rows) => [...U.panel('ga:p', 24, 526, 872, 92, ''), ...rows.map(([t, c], j) => U.t('ga:p' + j, 44, 562 + j * 30, t, c, 'start', 15))];
    F.add({ items: [...draw(0, false, fib.state(), gal.state()), ...cmp([['Fibonacci holds the seed ' + disp(fib.state()) + '; Galois holds ' + disp(gal.state()) + ' (r' + U.sub(L - 1) + ' … r₀)', ''], ['different contents, chosen so that both give the same stream', 'tick']])],
      say: `Both registers implement C(x) = ${poly}. The Fibonacci register holds the seed ${seed.join('')}, oldest bit on the right; the Galois register holds ${disp(gal.state())} (r${U.sub(L - 1)} on the left, r₀ on the right), partial sums of the stream rather than the stream itself, set up so that its output is the same.`, facts: { fs: seed.join(''), gs: disp(gal.state()) }, meta: { stage: 'start' } });
    for (let i = 0; i < n; i++) {
      const fbBefore = fib.state(), gbBefore = gal.state(), a = fib.step(), b = gal.step();
      const say = `Clock ${i + 1}: Fibonacci XORs its ${taps.length} tapped cells into ${a.fb} and shifts it in; Galois shifts, and since its output is ${b.out} it ${b.out ? (nx ? 'flips the bit passing each XOR and puts 1 in the leftmost cell' : 'puts 1 in the leftmost cell') : 'changes nothing else'}. Both output ${a.out}.` + (i === 0 ? ' The Galois XORs all act at once, side by side; the Fibonacci XORs form one chain.' : '');
      F.add({ items: [...draw(i, true, fbBefore, gbBefore, a.fb), ...cmp([['Fibonacci out ' + a.out + ', new bit ' + a.fb + ';  Galois out ' + b.out + ', next ' + disp(b.state), 'math'], [a.out === b.out ? 'the same output bit' : 'the outputs differ', a.out === b.out ? 'good' : 'bad']])], hl: { d: [1, 2] }, say, facts: { i: i + 1, fb: a.fb, out: a.out, gout: b.out, nt: taps.length, nx, gnext: disp(b.state) }, meta: { stage: 'clock', i, same: a.out === b.out } });
    }
    const out = seq.slice(0, n).join('');
    F.add({ items: [...draw(n, false, fib.state(), gal.state()), ...cmp([['both streams: ' + out, 'math'], ['Fibonacci now ' + disp(fib.state()) + ', Galois now ' + disp(gal.state()) + ': still different, same future', 'tick']])], hl: { d: [3] },
      say: `After ${n} clocks both streams are ${out}. The registers never held the same bits, yet the outputs agree at every clock. In hardware the Galois form is faster: ${nx === 1 ? 'its single XOR sits between two cells' : `its ${nx} XORs sit side by side`}, one gate deep, instead of a chain through all ${taps.length} taps.`, facts: { n, out, nx, nt: taps.length }, meta: { stage: 'end' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 624 });
    return { frames: F.list, def: U.def('Fibonacci and Galois', ['Fibonacci: s(n) = c₁s(n−1) ⊕ … ⊕ c_L·s(n−L), shift in', 'Galois: out = r₀; r_j ← r_(j+1) ⊕ c_(j+1)·out', 'same C(x), same output sequence', 'Galois state: r_j = s_j ⊕ c₁s_(j−1) ⊕ … ⊕ c_j·s₀', 'Galois XORs act in parallel: one gate deep']) };
  }
  const seedCheck = (v, input) => {
    const s = String(v), L = Math.max(...(input.taps || []).map(Number).filter(Number.isFinite));
    if (!/^[01]+$/.test(s)) return 'Seed: only 0 and 1';
    if (Number.isFinite(L) && s.length !== L) return 'Seed: exactly ' + L + ' bits, the first ' + L + ' output bits';
    if (!/1/.test(s)) return 'Seed: at least one 1';
    return null;
  };
  S.topic({
    id: 'st-galois', family: 'p03-lfsr', order: 40, title: 'Galois against Fibonacci',
    blurb: 'The same connection polynomial built two ways: XOR the taps into the new bit, or XOR the output back into the register between the cells. Different contents, the same stream.',
    inputs: [
      { id: 'taps', kind: 'list', label: 'Taps (exponents of C(x))', def: ['4', '3'], check: U.tapsCheck(8) },
      { id: 'seed', kind: 'string', label: 'Seed (first output bits)', def: '1000', alphabet: '01', max: 8, check: seedCheck },
      { id: 'clocks', kind: 'number', label: 'Clocks', def: 12, min: 4, max: 16 },
    ],
    presets: [
      { label: '1 + x³ + x⁴, seed 1000', values: { taps: ['4', '3'], seed: '1000', clocks: 12 } },
      { label: '1 + x + x⁴, seed 1011', values: { taps: ['4', '1'], seed: '1011', clocks: 12 } },
      { label: 'Four taps, 6 cells', values: { taps: ['6', '4', '3', '1'], seed: '110010', clocks: 14 } },
      { label: '8 cells', values: { taps: ['8', '6', '5', '4'], seed: '10000001', clocks: 16 } },
    ],
    run: galois,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'start', once: true, pick: 'option', options: ['Yes, bit for bit', 'No: the contents differ', 'Only every other bit'], ask: 'The two registers hold different bits. Will their output streams be the same?', answer: 'Yes, bit for bit', explain: 'The Galois state is a transformed copy of the Fibonacci state; the output sequence is the same.' },
      { at: (f) => f.meta && f.meta.stage === 'clock' && f.meta.i === 2, once: true, pick: 'option', options: ['0', '1'], ask: 'Read r₀ of the Galois register as it stands after this clock. What is the next output bit?', answer: (fr, i) => String(fr[i + 1].facts.out), explain: 'The Galois output is simply r₀.' },
    ],
    quiz: [
      { q: 'In the Galois form, where is the output bit used?', options: ['Nowhere', 'It is XORed into the cells at the tap positions', 'It replaces the whole register', 'It is added to the seed'], answer: 1, why: 'r_j ← r_(j+1) ⊕ c_(j+1)·out.' },
      { q: 'Why is the Galois form often faster in hardware?', options: ['It uses fewer cells', 'Its XORs sit side by side, so the longest path is one XOR gate', 'It has no feedback', 'It runs at twice the clock'], answer: 1, why: 'The Fibonacci form XORs all tapped bits in one chain or tree.' },
      { q: 'A Fibonacci and a Galois register with the same C(x) and matching seeds have…', options: ['the same contents and the same output', 'different contents but the same output', 'the same contents but different output', 'unrelated output'], answer: 1, why: 'The states differ by an invertible linear map; the sequences agree.' },
      { q: 'Does the Galois form change the period of the sequence?', options: ['Yes, it doubles it', 'No: the output is the same sequence', 'Yes, it halves it', 'Only for primitive C(x)'], answer: 1, why: 'Same sequence, same period.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
