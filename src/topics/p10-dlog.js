// Part 10, attacks on the elliptic-curve discrete logarithm: given G and Q = k·G, find k. Baby-step giant-step meets
// in the middle with a table of √n points; Pollard's rho walks until it bites its own tail; Pohlig–Hellman splits a
// smooth group order into small pieces; Smart's attack solves an anomalous curve (#E = p) with one division.
(function (S) {
  'use strict';
  const U = S.P10, E = () => S.ECC;
  const f = U.f, P$ = (P) => U.fp(P);
  const kIn = (def, curveOf) => ({ id: 'k', kind: 'text', label: 'The secret k (Q = k·G)', def, check: (v, inp) => { if (!/^\d+$/.test(String(v).trim())) return 'k: a whole number'; const k = BigInt(String(v).trim()), n = curveOf(inp).n; return k < 1n || k >= n ? 'k: from 1 to n − 1 = ' + (n - 1n) : null; } });
  const toyN = (inp) => E().toy(inp.curve);
  const curveChoice = { id: 'curve', kind: 'choice', label: 'Curve', def: 'gf1009', options: [{ value: 'gf1009', label: 'GF(1009), n = 1019' }, { value: 'dlog65537', label: 'GF(65537), n = 65557' }] };

  // ---------------------------------------------------------------------------------------------------------------
  // Baby-step giant-step
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-bsgs', family: 'p10-dlog', order: 10, title: 'Baby-step giant-step',
    blurb: 'Write the unknown k as i·m + j with m ≈ √n. Store the m baby steps j·G in a table; then take giant steps Q, Q − m·G, Q − 2m·G, … until one lands in the table. About 2√n group operations and √n points of memory, instead of n tries: square-root work, which is why a 256-bit curve gives 128-bit security.',
    inputs: [curveChoice, kIn('777', toyN)],
    presets: [
      { label: 'GF(1009): k = 777', values: { curve: 'gf1009', k: '777' } },
      { label: 'GF(1009): k = 20 (found at once)', values: { curve: 'gf1009', k: '20' } },
      { label: 'GF(65537): k = 31415', values: { curve: 'dlog65537', k: '31415' } },
      { label: 'GF(65537): k = 1234', values: { curve: 'dlog65537', k: '1234' } },
    ],
    counters: [{ id: 'ops', label: 'group operations' }],
    run(inp) {
      const C = E().toy(inp.curve), G = C.G, n = C.n, k = BigInt(inp.k), Q = C.mul(k, G), F = new S.Frames(['ops']);
      const r = E().dlog.bsgs(C, G, Q, n), m = r.m, hit = r.hit;
      const head = U.head('bs:h', 30, 28, `Find k with Q = k·G on ${C.name}, n = ${f(n)}`);
      // the number line of k
      const X0 = 60, W = 820, Y = 560, xOf = (v) => U.r2(X0 + (Number(v) / Number(n)) * W);
      const line = (pos, giants) => {
        const items = [{ key: 'bs:nl', kind: 'line', x1: X0, y1: Y, x2: X0 + W, y2: Y }, { key: 'bs:win', kind: 'cell', x: X0, y: Y - 10, w: Math.max(4, xOf(m) - X0), h: 20, rx: 3, text: '', cls: 'e10-cell good', audit: 'overlap-ok' }, U.t('bs:0', X0, Y + 28, '0', 'tick', 'middle', 13), U.t('bs:n', X0 + W, Y + 28, String(n), 'tick', 'middle', 13), U.t('bs:wl', X0, Y - 20, 'baby steps: 0 … m − 1', 'good', 'start', 13)];
        for (const g of giants) items.push({ key: 'bs:g' + g, kind: 'dot', x: xOf(Number(k) - g * Number(m)), y: Y, r: Number(n) > 5000 ? 2.5 : 4, cls: 'key', audit: 'overlap-ok' });
        if (pos !== null) items.push({ key: 'bs:k', kind: 'dot', x: xOf(pos), y: Y, r: 7, cls: 'hot', audit: 'overlap-ok', layer: 'top' }, U.t('bs:kl', xOf(pos), Y + 52, pos === Number(k) ? 'k' : 'k − ' + giants[giants.length - 1] + 'm', 'hot', 'middle', 14));
        return items;
      };
      const babyRows = (upto, lit) => { const idx = []; for (let j = 0; j < Math.min(Number(upto), Number(m)); j++) idx.push(j); const keep = idx.length <= 9 ? idx : [0, 1, 2, 3, -1, ...idx.slice(-3)]; if (lit !== undefined && !keep.includes(lit)) { keep.splice(keep.indexOf(-1) + 1, 0, lit, -1); } return keep.map((j) => (j < 0 ? ['…', '…'] : [{ text: String(j), cls: j === lit ? 'good' : '' }, { text: P$(r.baby[j].P), cls: j === lit ? 'good' : '' }])); };
      const babyT = (upto, lit) => U.table({ prefix: 'bs:bt', x: 30, y: 60, cols: [{ w: 60, head: 'j' }, { w: 180, head: 'j·G (stored)' }], rows: babyRows(upto, lit), rh: 30 }).items;
      const giantT = (upto) => { const rows = r.giant.slice(0, upto).map((g) => [String(g.i), P$(g.P)]); const shown = rows.length <= 9 ? rows : [...rows.slice(0, 4), ['…', '…'], ...rows.slice(-4)]; return U.table({ prefix: 'bs:gt', x: 300, y: 60, cols: [{ w: 60, head: 'i' }, { w: 200, head: 'Q − i·m·G' }], rows: shown, rh: 30, hl: (i) => (i === shown.length - 1 ? 'act' : '') }).items; };
      const eq = (L) => U.eqs('bs:e', 600, 80, L, 15, 28);
      F.add({ items: [head, ...line(Number(k), []), ...eq([[`m = ⌈√n⌉ = ${m}`, 'strong'], ['k = i·m + j, 0 ≤ j < m'], [`Q = ${P$(Q)}`, 'key']])], say: `Q = ${P$(Q)} is k·G for some k below n = ${f(n)}, marked on the line (we know it; the attacker does not). Write k = i·m + j with m = ⌈√n⌉ = ${m}: then Q − i·(m·G) = j·G, a point among the first ${m} multiples of G.`, facts: { n, m, Q }, meta: { stage: 'plan' } });
      F.set('ops', Number(m));
      F.add({ items: [head, ...babyT(m), ...line(Number(k), []), ...eq([[`${m} baby steps stored`, 'good'], ['a hash table: point ↦ j'], [`${m} additions`]])], say: `Baby steps: compute 0·G, 1·G, …, ${m - 1n}·G, one addition each, and store them in a hash table keyed by the point. That covers the green window [0, ${m}) of the line.`, facts: { m, m1: m - 1n }, meta: { stage: 'baby' } });
      const last = Number(hit ? hit.i : r.giant.length - 1), shownG = last <= 4 ? [...Array(last + 1).keys()] : [0, 1, 2, last];
      for (const i of shownG) {
        F.set('ops', Number(m) + i);
        const g = r.giant[i], isHit = hit && i === last, giants = [...Array(i + 1).keys()];
        F.add({ items: [head, ...babyT(m, isHit ? Number(hit.j) : undefined), ...giantT(i + 1), ...line(Number(k) - i * Number(m), giants), ...eq([[`giant step ${i}: Q − ${i}·${m}·G`, 'act'], [P$(g.P), isHit ? 'good' : ''], [isHit ? `in the table: j = ${hit.j}` : 'not in the table', isHit ? 'good' : 'muted']])], say: isHit ? `Giant step ${i}: Q − ${i}·${m}·G = ${P$(g.P)}, and the table has it: it is ${hit.j}·G. The jump of ${i}·${m} carried k into the baby window.` : `Giant step ${i}: Q − ${i}·${m}·G = ${P$(g.P)}. Not in the table; subtract another ${m}·G, a stride of ${m} along the line.`, facts: { i, m, P: g.P, j: hit && hit.j }, meta: { stage: isHit ? 'hit' : 'giant', i } });
      }
      const kf = r.k;
      F.add({ items: [head, ...babyT(m, Number(hit.j)), ...giantT(last + 1), ...line(Number(k) - last * Number(m), [...Array(last + 1).keys()]), ...eq([[`k = ${hit.i}·${m} + ${hit.j} = ${f(kf)}`, 'good'], [`check: ${f(kf)}·G = ${P$(C.mul(kf, G))}`, 'good'], [`${r.ops} operations, at most about 2√n = ${2n * m}`, 'act']])], say: `So Q − ${hit.i}·${m}·G = ${hit.j}·G, and k = ${hit.i}·${m} + ${hit.j} = ${f(kf)}. It took ${r.ops} group operations and a table of ${m} points; the worst case is about 2√n = ${2n * m}, against ${f(n)} for trying every k. For a 256-bit n that is still 2¹²⁸, far out of reach.`, facts: { i: hit.i, j: hit.j, m, k: kf, ops: r.ops, w: 2n * m, n }, meta: { stage: 'done' } });
      U.fix(F.list);
      return { frames: F.list, def: U.def('Baby-step giant-step', ['m = ⌈√n⌉', 'baby: store j·G for 0 ≤ j < m', 'giant: Y = Q − i·(m·G) for i = 0, 1, …', 'Y = j·G in the table ⇒ k = i·m + j', 'time and memory ≈ √n']) };
    },
    predict: [{ at: (f) => f.meta.stage === 'baby', pick: 'option', ask: 'How many giant steps will it take, at most?', options: (fr, i) => { const m = Number(fr[i].facts.m); return [String(m), String(m * m), String(Math.round(m / 2)), '1']; }, answer: (fr, i) => String(fr[i].facts.m), explain: (fr) => fr[fr.length - 1].say }],
    quiz: [
      { q: 'For n ≈ 2²⁵⁶, baby-step giant-step needs about…', options: ['2¹²⁸ operations and 2¹²⁸ memory', '2²⁵⁶ operations', '256 operations', '2⁶⁴ operations'], answer: 0, why: 'Square-root time and square-root memory.' },
      { q: 'With m = 32, giant step i = 5 tests…', options: ['Q − 160·G', 'Q − 5·G', 'Q + 160·G', '5·Q'], answer: 0, why: 'Each giant step subtracts m·G.' },
      { q: 'A match Q − i·m·G = j·G gives k = …', options: ['i·m + j', 'i + j', 'i·j', 'm − j'], answer: 0, why: 'Q = (i·m + j)·G.' },
      { q: 'What is the weak point of baby-step giant-step?', options: ['the memory for the table', 'it only works on small curves', 'it needs the order', 'it may give a wrong k'], answer: 0, why: 'Pollard rho reaches the same time with almost no memory.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Pollard's rho
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-rho', family: 'p10-dlog', order: 20, title: 'Pollard\'s rho',
    blurb: 'Walk through the group by a rule that only looks at the current point, keeping track of X = a·G + b·Q. In a finite group the walk must repeat, and from then on it goes round a cycle: the path has the shape of the letter ρ. Two ways of writing one point give an equation for k. The walk takes about √n steps, like baby-step giant-step, but keeps only two points.',
    inputs: [curveChoice, kIn('777', toyN), { id: 'seed', kind: 'number', label: 'Starting seed', def: 3, min: 1, max: 999 }],
    presets: [
      { label: 'GF(1009): k = 777', values: { curve: 'gf1009', k: '777', seed: 3 } },
      { label: 'GF(1009), another start', values: { curve: 'gf1009', k: '777', seed: 11 } },
      { label: 'GF(65537): k = 4321', values: { curve: 'dlog65537', k: '4321', seed: 3 } },
      { label: 'GF(65537): k = 60000', values: { curve: 'dlog65537', k: '60000', seed: 7 } },
    ],
    counters: [{ id: 'steps', label: 'steps' }],
    run(inp) {
      const C = E().toy(inp.curve), G = C.G, n = C.n, k = BigInt(inp.k), Q = C.mul(k, G), F = new S.Frames(['steps']);
      const r = E().dlog.rho(C, G, Q, n, { seed: inp.seed }), w = r.walk, mu = r.mu, lam = r.lambda, N = w.length;
      const head = U.head('rh:h', 30, 28, `Pollard's rho on ${C.name}, n = ${f(n)}`);
      // positions: the cycle on a circle, the tail coming up into it from the lower left
      const cx = 560, cy = 290, R = 210, tailLen = 380;
      const pos = (i) => {
        if (i >= mu) { const t = (i - mu) / lam, a = Math.PI / 2 + 2 * Math.PI * t; return { x: U.r2(cx + R * Math.cos(a) * -1), y: U.r2(cy + R * Math.sin(a)) }; }
        const s = mu ? (mu - i) / mu : 0, ex = cx, ey = cy + R; return { x: U.r2(ex - tailLen * 0.8 * s), y: U.r2(ey + 120 * s) };
      };
      const dotR = N > 300 ? 2 : N > 100 ? 3 : 4.5;
      const walk = (upto) => {
        const items = [];
        let d = '';
        for (let i = 0; i < upto; i++) { const p = pos(i); d += (i ? 'L' : 'M') + p.x + ',' + p.y + ' '; }
        if (upto === N) { const p = pos(mu); d += 'L' + p.x + ',' + p.y; }
        items.push({ key: 'rh:path', kind: 'path', d, cls: 'e10-walk', audit: 'ignore', layer: 'back' });
        for (let i = 0; i < upto; i++) { const p = pos(i); items.push({ key: 'rh:d' + i, kind: 'dot', x: p.x, y: p.y, r: dotR, cls: 'e10-w' + w[i].part, audit: 'ignore' }); }
        return items;
      };
      const legend = [0, 1, 2].flatMap((q) => [{ key: 'rh:lg' + q, kind: 'cell', x: 30, y: 60 + q * 26, w: 14, h: 14, rx: 3, text: '', cls: 'e10-swatch e10-w' + q }, U.t('rh:lt' + q, 52, 72 + q * 26, ['x mod 3 = 0: X + G (a + 1)', 'x mod 3 = 1: 2X (a, b doubled)', 'x mod 3 = 2: X + Q (b + 1)'][q], 'e10-note', 'start', 13)]);
      const lab = (key, i, text, cls, dx, dy) => { const p = pos(i); return U.t(key, p.x + (dx || 0), p.y + (dy || 0), text, cls, dx < 0 ? 'end' : 'start', 14); };
      const eq = (L) => U.eqs('rh:e', 30, 160, L, 15, 27);
      const x0 = w[0];
      F.add({ items: [head, ...legend, ...walk(1), lab('rh:l0', 0, 'X₀', 'act', -10, 18), ...eq([[`X₀ = ${x0.a}·G + ${x0.b}·Q`, 'act'], [P$(x0.P)]])], say: `Start from a random combination X₀ = ${x0.a}·G + ${x0.b}·Q = ${P$(x0.P)}. Each step looks only at the current point: by its x mod 3 it adds G, doubles, or adds Q, and updates a and b so that X = a·G + b·Q stays true.`, facts: { a: x0.a, b: x0.b, P: x0.P }, meta: { stage: 'start' } });
      const cuts = [...new Set([Math.max(2, Math.round(mu / 2)), Math.max(2, mu), Math.round(mu + lam / 2), N])].filter((c) => c >= 2 && c <= N).sort((x, y) => x - y);
      for (const c of cuts) {
        F.set('steps', c - 1);
        const p = w[c - 1];
        const done = c === N;
        F.add({ items: [head, ...legend, ...walk(c), lab('rh:l0', 0, 'X₀', 'act', -10, 18), ...(c > mu ? [lab('rh:lm', mu, 'X' + U.sub(mu), 'hot', 12, 18)] : []), ...eq([[`step ${c - 1}: X = ${p.a}·G + ${p.b}·Q`, 'act'], [P$(p.P)], [done ? `back at X${U.sub(mu)}: the walk repeats` : c > mu ? 'on the cycle' : 'on the tail', done ? 'hot' : 'muted']])], say: done ? `After ${N} steps the next point is X${U.sub(mu)} again: the walk has a tail of ${mu} points and a cycle of ${lam}, the shape of the letter ρ. A random walk in a group of n points repeats after about √(πn/2) steps.` : `Step ${c - 1}: X = ${p.a}·G + ${p.b}·Q = ${P$(p.P)}. The points look random, but the walk is a fixed function of the current point, so once it repeats it loops for ever.`, facts: { c1: c - 1, a: p.a, b: p.b, P: p.P, mu, lam, N }, meta: { stage: done ? 'collide' : 'walk' } });
      }
      const eqT = r.trace.find((t) => t.kind === 'equation'), sol = r.trace.find((t) => t.kind === 'solve');
      F.add({ items: [head, ...legend, ...walk(N), lab('rh:lm', mu, 'X' + U.sub(mu), 'hot', 12, 18), ...eq([[`Floyd: tortoise 1 step, hare 2 steps`, 'act'], [`they meet after ${r.floydSteps} steps`], ['memory: two points, not √n'], [`expected steps ≈ √(πn/2) ≈ ${Math.round(Math.sqrt(Math.PI * Number(n) / 2))}`]])], say: `In practice nobody stores the walk. Floyd's method runs a tortoise one step at a time and a hare two steps at a time; the hare catches the tortoise on the cycle, here after ${r.floydSteps} steps. So rho needs the same √n time as baby-step giant-step with almost no memory, about ${Math.round(Math.sqrt(Math.PI * Number(n) / 2))} steps expected here.`, facts: { fl: r.floydSteps, exp: Math.round(Math.sqrt(Math.PI * Number(n) / 2)) }, meta: { stage: 'floyd' } });
      F.add({ items: [head, ...legend, ...walk(N), lab('rh:lm', mu, 'X' + U.sub(mu), 'hot', 12, 18), ...eq([[`${eqT.a1}·G + ${eqT.b1}·Q = ${eqT.a2}·G + ${eqT.b2}·Q`, 'strong'], [`(${eqT.a1} − ${eqT.a2}) ≡ k·(${eqT.b2} − ${eqT.b1}) (mod ${n})`], [`k = ${f(sol.k)}`, 'good'], [`check: k·G = ${P$(C.mul(sol.k, G))} = Q`, 'good']])], say: `The repeated point has two names: ${eqT.a1}·G + ${eqT.b1}·Q = ${eqT.a2}·G + ${eqT.b2}·Q. Since Q = k·G, (${eqT.a1} − ${eqT.a2}) ≡ k·(${eqT.b2} − ${eqT.b1}) (mod ${n}), and dividing gives k = ${f(sol.k)}: indeed k·G = Q.`, facts: { a1: eqT.a1, b1: eqT.b1, a2: eqT.a2, b2: eqT.b2, k: sol.k, n, Q }, meta: { stage: 'solve' } });
      U.fix(F.list);
      return { frames: F.list, def: U.def('Pollard\'s rho', ['X = a·G + b·Q, a step depends only on X', 'repeat: a₁G + b₁Q = a₂G + b₂Q', 'k = (a₁ − a₂)/(b₂ − b₁) mod n', 'expected √(πn/2) steps; Floyd: O(1) memory']) };
    },
    predict: [{ at: (f) => f.meta.stage === 'start', pick: 'option', ask: 'About how many steps until the walk repeats?', options: (fr, i, inp) => { const n = Number(S.ECC.toy(inp.curve).n); return [Math.round(Math.sqrt(n)), Math.round(n / 2), n, 10].map((x) => 'about ' + x); }, answer: (fr, i, inp) => 'about ' + Math.round(Math.sqrt(Number(S.ECC.toy(inp.curve).n))), explain: (fr) => fr.find((x) => x.meta.stage === 'collide').say }],
    quiz: [
      { q: 'Why must the walk repeat?', options: ['the group is finite and each step depends only on the current point', 'it is random', 'k is small', 'by Hasse'], answer: 0, why: 'A function on a finite set eventually cycles.' },
      { q: 'What does rho save compared with baby-step giant-step?', options: ['memory', 'time', 'the order', 'nothing'], answer: 0, why: 'Floyd keeps two points instead of √n.' },
      { q: 'The collision a₁G + b₁Q = a₂G + b₂Q gives k = …', options: ['(a₁ − a₂)/(b₂ − b₁) mod n', 'a₁ + b₁', '(b₁ − b₂)/(a₁ − a₂)', 'a₁·a₂'], answer: 0, why: '(a₁ − a₂)G = (b₂ − b₁)kG.' },
      { q: 'Expected steps for n = 10⁶?', options: ['about 1250', 'about 10⁶', 'about 10', 'about 10³⁰'], answer: 0, why: '√(π·10⁶/2) ≈ 1253.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Pohlig–Hellman
  // ---------------------------------------------------------------------------------------------------------------
  const PH = { smooth10007: 'GF(10007): n = 10206 = 2·3⁶·7', gf97: 'GF(97): a subgroup of order 27 = 3³', gf17x2: 'GF(17): a subgroup of order 8 = 2³' };
  const phCurve = (id) => { const C = E().toy(id); if (C.G) return { C, G: C.G, n: C.n }; const st = C.structure(); return { C, G: st.P1, n: st.n1 }; };
  S.topic({
    id: 'ec-pohlig', family: 'p10-dlog', order: 30, title: 'Pohlig–Hellman on a smooth order',
    blurb: 'If the order n of G factors into small primes, the logarithm splits. Multiplying by n/qᵉ lands in a subgroup of order qᵉ, where k mod qᵉ can be found one base-q digit at a time, each by a search among q points. The Chinese remainder theorem glues the pieces. The cost depends on the largest prime factor of n, which is why curves use a prime-order subgroup.',
    inputs: [{ id: 'curve', kind: 'choice', label: 'Group', def: 'smooth10007', options: Object.entries(PH).map(([value, label]) => ({ value, label })) }, kIn('5000', (inp) => phCurve(inp.curve))],
    presets: [
      { label: 'n = 10206 = 2·3⁶·7, k = 5000', values: { curve: 'smooth10007', k: '5000' } },
      { label: 'n = 10206, k = 777', values: { curve: 'smooth10007', k: '777' } },
      { label: 'n = 27 = 3³, k = 20', values: { curve: 'gf97', k: '20' } },
      { label: 'n = 8 = 2³, k = 5', values: { curve: 'gf17x2', k: '5' } },
    ],
    counters: [{ id: 'tries', label: 'small searches' }],
    run(inp) {
      const { C, G, n } = phCurve(inp.curve), k = BigInt(inp.k), Q = C.mul(k, G), F = new S.Frames(['tries']);
      const r = E().dlog.pohligHellman(C, G, Q, n), parts = r.parts;
      const head = U.head('ph:h', 30, 28, `k from Q = k·G, G of order n = ${f(n)} on ${C.name}`);
      const colW = Math.min(parts.length === 1 ? 520 : 280, Math.floor(860 / parts.length));
      const cols = (upto) => {
        const items = []; let seen = 0;
        parts.forEach((pt, c) => {
          const x = 30 + c * colW, qe = pt.e > 1 ? `${pt.q}${U.sup(pt.e)}` : String(pt.q);
          items.push({ key: 'ph:c' + c, kind: 'region', x, y: 60, w: colW - 14, h: 170, rx: 10, cls: 'panel' }, U.t('ph:ct' + c, x + 14, 84, 'mod ' + qe, 'eq strong', 'start', 16));
          pt.digits.forEach((d, j) => { const shown = seen < upto; items.push({ key: 'ph:d' + c + '_' + j, kind: 'cell', x: x + 14 + (j % 6) * 36, y: 110 + Math.floor(j / 6) * 40, w: 32, h: 32, rx: 4, text: shown ? String(d) : '?', size: 15, cls: 'e10-cell mono ' + (shown ? (seen === upto - 1 ? 'hot' : 'good') : 'faint') }); seen++; });
          const done = seen <= upto;
          items.push(U.t('ph:cr' + c, x + 14, 208, done ? `k ≡ ${pt.residue} (mod ${pt.modulus})` : 'digits, lowest first', done ? 'good' : 'e10-note', 'start', 14));
        });
        return items;
      };
      const eq = (L) => U.eqs('ph:e', 30, 280, L, 15, 28);
      const total = parts.reduce((s, x) => s + x.e, 0);
      F.add({ items: [head, ...cols(0), ...eq([[`n = ${parts.map((x) => (x.e > 1 ? x.q + U.sup(x.e) : String(x.q))).join(' · ')}`, 'strong'], [`Q = ${P$(Q)}`, 'key'], ['find k mod each prime power, then use the CRT']])], say: `G has order n = ${f(n)} = ${parts.map((x) => (x.e > 1 ? `${x.q}^${x.e}` : x.q)).join(' · ')}, a product of small primes. Instead of one search among ${f(n)} values, find k modulo ${U.list(parts.map((x) => String(x.modulus)))} separately: ${total} digits in all.`, facts: { n, parts: parts.map((x) => [x.q, x.e, x.modulus]), total, Q }, meta: { stage: 'plan' } });
      const digitSteps = r.trace.filter((t) => t.kind === 'digit');
      let tries = 0;
      digitSteps.forEach((t, i) => {
        tries += Number(t.digit) + 1;
        F.set('tries', tries);
        if (digitSteps.length > 10 && i > 2 && i < digitSteps.length - 2 && digitSteps[i + 1] && digitSteps[i + 1].q === t.q) return;
        const pt = parts.find((x) => x.q === t.q);
        F.add({ items: [head, ...cols(i + 1), ...eq([[`(n/${t.q}${U.sup(t.j + 1)})·(Q − (k so far)·G) = ${P$(t.Qj)}`, 'act'], [`G₀ = (n/${t.q})·G = ${P$(t.G0)} has order ${t.q}`], [`${P$(t.Qj)} = ${t.digit}·G₀: digit ${t.j} is ${t.digit}`, 'hot']])], say: `Modulo ${pt.modulus}, digit ${t.j}: multiplying by n/${t.q}^${t.j + 1} kills everything but that digit's part, leaving ${P$(t.Qj)}. G₀ = (n/${t.q})·G has order ${t.q}, so at most ${t.q} tries find it: ${P$(t.Qj)} = ${t.digit}·G₀, and digit ${t.j} of k in base ${t.q} is ${t.digit}.`, facts: { q: t.q, j: t.j, j1: t.j + 1, digit: t.digit, Qj: t.Qj, G0: t.G0, mod: pt.modulus }, meta: { stage: 'digit' } });
      });
      const res = parts.map((x) => `k ≡ ${x.residue} (mod ${x.modulus})`).join(', ');
      F.add({ items: [head, ...cols(total), ...eq([[res, 'good'], [`CRT: k = ${f(r.k)}`, 'good'], [`check: k·G = ${P$(C.mul(r.k, G))}`, 'good'], [`work: ${tries} small tries instead of up to ${f(n)}`, 'act']])], say: `The Chinese remainder theorem combines ${res} into k = ${f(r.k)}, and k·G = Q. The work was ${tries} small tries, bounded by the sum of e·q over the factors, instead of up to ${f(n)}. With n prime there is nothing to split: that is why the base point of a real curve has prime order.`, facts: { res: parts.map((x) => [x.residue, x.modulus]), k: r.k, tries, n }, meta: { stage: 'crt' } });
      U.fix(F.list);
      return { frames: F.list, def: U.def('Pohlig–Hellman', ['n = Π qᵢ^eᵢ', 'for each qᵉ: digits of k in base q,', '  digit j from (n/q^(j+1))·(Q − (known part)·G)', '  a search among q points', 'CRT: k mod n', 'cost ≈ Σ eᵢ·qᵢ (or Σ eᵢ√qᵢ with BSGS)']) };
    },
    predict: [{ at: (f) => f.meta.stage === 'plan', pick: 'option', ask: 'How many base-q digits must be found in all?', options: (fr, i) => { const t = fr[i].facts.total; return [t, t + 1, t * 2, Math.max(1, t - 1)].map(String); }, answer: (fr, i) => String(fr[i].facts.total), explain: (fr, i) => fr[i].say }],
    quiz: [
      { q: 'What does Pohlig–Hellman need?', options: ['an order made of small prime factors', 'a prime order', 'an anomalous curve', 'the private key'], answer: 0, why: 'Its cost is set by the largest prime factor.' },
      { q: 'For n = 2·3⁶·7, how many digits are found?', options: ['8', '3', '10206', '6'], answer: 0, why: '1 + 6 + 1.' },
      { q: 'Why do real curves use a prime-order subgroup?', options: ['so the logarithm cannot be split', 'for speed', 'to compress points', 'it is required by Hasse'], answer: 0, why: 'A prime n leaves Pohlig–Hellman nothing to do.' },
      { q: 'What glues the pieces k mod qᵉ together?', options: ['the Chinese remainder theorem', 'Euclid alone', 'Hasse', 'the ladder'], answer: 0, why: 'The moduli are coprime.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Smart's attack on an anomalous curve
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-smart', family: 'p10-dlog', order: 40, title: 'Smart\'s attack: when #E = p',
    blurb: 'A curve with exactly p points looks perfect: the order is prime and no small factor helps. But such an anomalous curve has a hidden map onto the additive group of GF(p), where the logarithm is a division. Lift the points to the integers mod p², multiply by p, and read off a number: k falls out in a handful of operations.',
    inputs: [kIn('555', () => E().toy('anomalous1013'))],
    presets: [{ label: 'k = 555', values: { k: '555' } }, { label: 'k = 1', values: { k: '1' } }, { label: 'k = 1000', values: { k: '1000' } }],
    run(inp) {
      const C = E().toy('anomalous1013'), G = C.G, p = C.p, k = BigInt(inp.k), Q = C.mul(k, G), F = new S.Frames(), r = E().dlog.smart(C, G, Q), h = C.hasse();
      const lifts = r.trace.filter((t) => t.kind === 'lift'), psis = r.trace.filter((t) => t.kind === 'psi'), L = lifts[lifts.length - 1], Ps = psis[psis.length - 1];
      const head = U.head('sa:h', 30, 28, `${C.name}: an anomalous curve`);
      const box = (key, y, title, lines, cls, on) => ({ key, kind: 'state', x: 300, y, w: 520, h: 26 + 24 * lines.length, rx: 10, lines: [title, ...lines], cls: 'block val3 ' + (on ? cls : 'soft'), size: 14 });
      const arrow = (key, y1, y2, text, on) => [{ key, kind: 'wire', pts: [[300, y1], [300, y2]], head: true, cls: 'e10-arrow ' + (on ? 'act' : '') }, U.t(key + ':t', 320, (y1 + y2) / 2 + 5, text, on ? 'act' : 'e10-note', 'start', 14)];
      const tower = (lvl) => [
        box('sa:b0', 560, 'E over GF(' + p + ')', [`G = ${P$(G)}, Q = ${P$(Q)}`, `#E = ${h.N} = p`], 'act', lvl >= 0),
        ...arrow('sa:a1', 520, 460, 'lift: same x, adjust y (Hensel)', lvl >= 1),
        box('sa:b1', 410, 'E over Z/' + p * p, lvl >= 1 ? [`Ĝ = ${P$(L.G)}`, `Q̂ = ${P$(L.Q)}`] : ['lifted points'], 'act', lvl >= 1),
        ...arrow('sa:a2', 362, 302, 'multiply by p: both land in the kernel', lvl >= 2),
        box('sa:b2', 262, 'p·Ĝ and p·Q̂ reduce to O mod p', ['their −x/y is a multiple of p'], 'act', lvl >= 2),
        ...arrow('sa:a3', 226, 166, 'divide by p: the p-adic logarithm ψ', lvl >= 3),
        box('sa:b3', 128, 'ψ(G) and ψ(Q) in GF(' + p + ')', lvl >= 3 ? [`ψ(G) = ${Ps.psiG}, ψ(Q) = ${Ps.psiQ}`] : ['two numbers'], 'good', lvl >= 3),
      ];
      const eq = (L) => U.eqs('sa:e', 600, 90, L, 15, 28);
      F.add({ items: [head, ...tower(0), ...eq([['#E = p: trace t = 1', 'hot'], [`n = ${p} is prime`], [`rho would need ≈ ${Math.round(Math.sqrt(Number(p)))} steps`]])], say: `A story: a designer wants a curve of prime order and searches until #E is prime. ${C.name} qualifies, with #E = ${h.N}, prime, no small factors, nothing for Pohlig–Hellman. But #E = ${h.N} is exactly p: the trace t = p + 1 − #E is ${h.t}. Such a curve is called anomalous, and that is fatal.`, facts: { N: h.N, p, t: h.t, rho: Math.round(Math.sqrt(Number(p))) }, meta: { stage: 'story' } });
      F.add({ items: [head, ...tower(1), ...eq([[`lifted curve: a = ${L.a}, b = ${L.b}`], [`mod ${p * p}`], ['G and Q still lie on it', 'act']])], say: `Lift everything from GF(${p}) to the integers mod p² = ${p * p}: keep x, adjust y by a multiple of p so the points satisfy the lifted equation y² = x³ + ${L.a}x + ${L.b} (Hensel's lemma). Ĝ = ${P$(L.G)} and Q̂ = ${P$(L.Q)}.`, facts: { a: L.a, b: L.b, pp: p * p, G: L.G, Q: L.Q }, meta: { stage: 'lift' } });
      F.add({ items: [head, ...tower(2), ...eq([['p·G = O over GF(p)', 'strong'], ['so p·Ĝ reduces to O:'], ['it lies in the kernel of reduction'], ['there, addition is like adding numbers', 'act']])], say: `Multiply both lifts by p. Over GF(${p}) every point times p is O, since the group has p elements; so p·Ĝ and p·Q̂ reduce to O, which means they lie in the kernel of reduction. In that kernel the group law, read through −x/y, is just addition of multiples of p.`, facts: { p }, meta: { stage: 'kernel' } });
      F.add({ items: [head, ...tower(3), ...eq([[`ψ(G) = ${Ps.psiG}`, 'good'], [`ψ(Q) = ${Ps.psiQ}`, 'good'], ['ψ(Q) = k·ψ(G) (mod p)', 'strong']])], say: `Divide −x/y of each by p to get a number mod ${p}: ψ(G) = ${Ps.psiG} and ψ(Q) = ${Ps.psiQ}. The map ψ turns the curve's group into ordinary addition mod p, so Q = k·G becomes ψ(Q) = k·ψ(G) (mod ${p}).${psis.length > 1 ? ` (A first lift gave ψ(G) = 0 and was replaced by another.)` : ''}`, facts: { psiG: Ps.psiG, psiQ: Ps.psiQ, p }, meta: { stage: 'psi' } });
      F.add({ items: [head, ...tower(3), ...eq([[`k = ${Ps.psiQ}·${Ps.psiG}⁻¹ mod ${p}`, 'strong'], [`k = ${r.k}`, 'good'], [`check: k·G = ${P$(C.mul(r.k, G))}`, 'good'], ['the defence: check that #E ≠ p', 'hot']])], say: `So k = ψ(Q)/ψ(G) mod ${p} = ${r.k}, and k·G = Q. No search at all: the same handful of operations would break a 256-bit anomalous curve. The defence is one test when choosing a curve: #E ≠ p. Curves with t = 0 fall to a different shortcut, the MOV pairing attack, so standards exclude those too.`, facts: { k: r.k, psiG: Ps.psiG, psiQ: Ps.psiQ, p }, meta: { stage: 'solve' } });
      for (const fr of F.list) fr.facts = Object.assign({ curve: [C.p, C.a, C.b] }, fr.facts);
      U.fix(F.list);
      return { frames: F.list, def: U.def('Smart\'s attack', ['anomalous: #E(GF(p)) = p (trace t = 1)', 'lift G, Q to E over Z/p² (Hensel)', 'p·Ĝ, p·Q̂ lie in the kernel of reduction', 'ψ(P) = −x/(p·y) of p·P̂, mod p', 'k = ψ(Q)/ψ(G) mod p']) };
    },
    predict: [{ at: (f) => f.meta.stage === 'story', pick: 'option', ask: 'Pohlig–Hellman cannot split a prime order. How long will this attack take?', options: ['a handful of operations', 'about √p steps', 'about p steps', 'it cannot work'], answer: 'a handful of operations', explain: (fr) => fr[fr.length - 1].say }],
    quiz: [
      { q: 'A curve is anomalous when…', options: ['#E = p', '#E = p + 1', '#E is prime', 'a = 0'], answer: 0, why: 'The trace of Frobenius is 1.' },
      { q: 'What does ψ do?', options: ['maps the group onto addition mod p', 'compresses points', 'counts points', 'finds square roots'], answer: 0, why: 'There the logarithm is a division.' },
      { q: 'How is the curve defended against Smart\'s attack?', options: ['by checking #E ≠ p when choosing it', 'by longer keys', 'by the ladder', 'by clamping'], answer: 0, why: 'No size helps an anomalous curve.' },
      { q: 'Which curves fall to the MOV attack?', options: ['those with a small embedding degree, such as t = 0', 'all prime-order curves', 'Edwards curves', 'none'], answer: 0, why: 'A pairing moves the logarithm into a finite field.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
