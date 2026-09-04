// Part 10, curves over GF(p): the group law on a cloud of points (a line that wraps round, a mirror y ↦ p − y), the
// point at infinity, the order of a point and the shape of the whole group, and Hasse's bound on the number of points.
(function (S) {
  'use strict';
  const U = S.P10, E = () => S.ECC;
  const f = (v) => U.f(v), P$ = U.pt;
  const md = (v, p) => ((v % p) + p) % p;

  /** the curve inputs every topic of this file shares, with a point (or two) given as "x, y" */
  const curveInputs = (d, pts) => [
    { id: 'p', kind: 'number', label: 'Prime p', def: d.p, min: 5, max: 127 },
    { id: 'a', kind: 'number', label: 'a', def: d.a, min: -50, max: 200 },
    { id: 'b', kind: 'number', label: 'b', def: d.b, min: -50, max: 200 },
  ].concat(pts.map(([id, label, def]) => ({
    id, kind: 'text', label, def,
    check: (v, inp) => {
      const P = U.parsePoint(v);
      if (!P) return label + ': two whole numbers, x and y, like 3, 15';
      const p = BigInt(inp.p);
      if (P.x >= p || P.y >= p) return label + ': both coordinates below p = ' + inp.p;
      if (md(P.y * P.y - P.x ** 3n - BigInt(inp.a) * P.x - BigInt(inp.b), p) !== 0n) return label + ': (' + P.x + ', ' + P.y + ') is not on the curve: y² and x³ + ax + b differ mod ' + inp.p;
      return null;
    },
  })));
  const curveCheck = (inp) => U.curveCheck(inp, 127);
  const curveOf = (inp) => E().curve({ p: inp.p, a: inp.a, b: inp.b });
  const eqn = (C) => `y² = x³ + ${C.a}x + ${C.b} (mod ${C.p})`;
  const CX = 50, CY = 50, CS = 520, PX = 612;
  const panel = (lines, size) => U.eqs('gp:e', PX, 66, lines, size || 16, 29);
  const headOf = (C) => U.head('gp:h', CX, 28, eqn(C));

  // ---------------------------------------------------------------------------------------------------------------
  // The group law on the cloud
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-gfp-law', family: 'p10-field', order: 10, title: 'The group law on a cloud of points',
    blurb: 'Over a prime field the curve is a scatter of points, but the rule is the same as over the reals. The division in the slope becomes a multiplication by an inverse modulo p, the line wraps round each time it passes p, and the mirror is y ↦ p − y.',
    inputs: curveInputs({ p: 61, a: 2, b: 9 }, [['P', 'P', '3, 15'], ['Q', 'Q', '5, 12']]),
    presets: [
      { label: 'GF(61): P = (3, 15), Q = (5, 12)', values: { p: 61, a: 2, b: 9, P: '3, 15', Q: '5, 12' } },
      { label: 'GF(17), 23 points', values: { p: 17, a: 3, b: 5, P: '1, 3', Q: '2, 6' } },
      { label: 'P = Q: the tangent', values: { p: 61, a: 2, b: 9, P: '4, 9', Q: '4, 9' } },
      { label: 'Q = −P: no third point', values: { p: 61, a: 2, b: 9, P: '4, 9', Q: '4, 52' } },
      { label: 'GF(101), a bigger cloud', values: { p: 101, a: 6, b: 14, P: '1, 18', Q: '0, 32' } },
      { label: 'A point of order 2', values: { p: 61, a: 2, b: 9, P: '7, 0', Q: '3, 15' } },
    ],
    check: curveCheck,
    run(inp) {
      const C = curveOf(inp), F = new S.Frames(), p = C.p;
      const P = U.parsePoint(inp.P), Q = U.parsePoint(inp.Q);
      const cl = U.cloud(C, { prefix: 'gp', x: CX, y: CY, s: CS });
      const N = cl.pts.length, half = cl.hline('gp:half', Number(p) / 2);
      const base = [headOf(C), ...cl.items, ...half];
      const add = (extra, lines, say, facts, meta, hl) => F.add({ items: [...base, ...extra, ...panel(lines)], say, facts: Object.assign({ p, a: C.a, b: C.b, P, Q }, facts), meta, hl: hl || {} });
      const lhs = (R) => md(R.y * R.y, p), rhs = (R) => C.rhs(R.x);
      add([], [[N + ' points (x, y)', 'strong'], ['and the point at infinity O'], ['mirror line y = ' + Number(p) / 2]], `Every pair (x, y) of numbers mod ${p} with y² ≡ x³ + ${C.a}x + ${C.b} is a point: ${N} of them, with no shape to speak of. They are still symmetric about the dotted line y = ${Number(p) / 2}, because y and ${p} − y have the same square.`, { N, half: Number(p) / 2 }, { stage: 'cloud' });
      const same = P.x === Q.x && P.y === Q.y, opp = P.x === Q.x && !same;
      const pq = [`P = ${P$(P)}`, 'act'], qq = [`Q = ${P$(Q)}`, 'key'];
      const mk = (list, drawn) => cl.marks(list, drawn);
      const PQm = [['P', P, 'P', 'P', 'ne'], ['Q', Q, same ? '' : 'Q', 'Q', 'ne']];
      add(mk(PQm), [pq, same ? ['Q = P', 'key'] : qq, [`${P.y}² ≡ ${lhs(P)} and ${P.x}³ + ${C.a}·${P.x} + ${C.b} ≡ ${rhs(P)}`]], `Take P = ${P$(P)}${same ? ' and double it' : ` and Q = ${P$(Q)}`}. P is on the curve: ${P.y}² ≡ ${lhs(P)} (mod ${p}), and x³ + ${C.a}x + ${C.b} at x = ${P.x} is ${rhs(P)} too.`, { P, Q, l: lhs(P), r: rhs(P) }, { stage: 'points' });
      if (opp || (same && P.y === 0n)) {
        const v = cl.vline('gp:v', P.x);
        add([...v, ...mk(PQm, v)], [pq, qq, ['the line x = ' + P.x + ' is vertical', 'hot'], [(same ? '2P' : 'P + Q') + ' = O', 'good']], same ? `P has y = 0, so P is its own mirror image and its tangent is vertical: 2P = O, the point at infinity. P has order 2.` : `Q = (${Q.x}, ${p} − ${P.y}) is the mirror image of P: Q = −P. The line through them is vertical and passes through no other point of the cloud, so P + Q = O, the point at infinity.`, { P, Q }, { stage: 'vertical' }, { d: [4] });
        U.fix(F.list);
        return { frames: F.list, def: lawDef() };
      }
      const s = C.addT(P, Q), t = s.trace[0], R = s.R, T = C.neg(R);
      const line = cl.modLine('gp:l', P, s.lambda, 'modline', [P, Q, T]);
      const lamLines = same ? [[`λ = (3x₁² + a)·(2y₁)⁻¹`, 'hot'], [`  = ${t.num}·${t.den}⁻¹ = ${t.num}·${t.di} = ${s.lambda}`, 'hot']] : [[`λ = (y₂ − y₁)·(x₂ − x₁)⁻¹`, 'hot'], [`  = ${t.num}·${t.den}⁻¹ = ${t.num}·${t.di} = ${s.lambda}`, 'hot']];
      const num = same ? `3·${P.x}² + ${C.a}` : `${Q.y} − ${P.y}`, den = same ? `2·${P.y}` : `${Q.x} − ${P.x}`;
      add([...line, ...mk(PQm, line)], [pq, same ? null : qq, ...lamLines], `The slope ${same ? 'of the tangent' : 'of the line'} is λ = (${num})·(${den})⁻¹ ≡ ${t.num}·${t.den}⁻¹ (mod ${p}). Dividing means multiplying by an inverse: ${t.den}⁻¹ ≡ ${t.di}, since ${t.den}·${t.di} = ${t.den * t.di} ≡ 1 (mod ${p}). So λ ≡ ${t.num}·${t.di} ≡ ${s.lambda} (mod ${p}). Drawn on the grid, the line leaves the top and comes back at the bottom, lap after lap; the laps that matter are drawn bold.`, { P, Q, lambda: s.lambda, num: t.num, den: t.den, di: t.di, prod: t.den * t.di }, { stage: 'slope', R, same }, { d: [same ? 1 : 0] });
      const third = [...PQm, ['T', T, '−(' + (same ? '2P' : 'P + Q') + ')', 'third', 'e']];
      add([...line, ...mk(third, line)], [pq, same ? null : qq, [`λ = ${s.lambda}`, 'hot'], [`x₃ = λ² − x₁ − x₂ = ${R.x}`]], `On one of its laps the line runs through a third point of the cloud, at x₃ ≡ λ² − x₁ − x₂ = ${s.lambda}² − ${P.x} − ${Q.x} ≡ ${R.x} (mod ${p}): the point (${T.x}, ${T.y}).`, { lambda: s.lambda, R, T, sq: s.lambda * s.lambda }, { stage: 'third' }, { d: [2] });
      const mir = cl.seg('gp:mr', T, R, 'mirror');
      add([...line, ...mir, ...mk([...third.slice(0, 2), ['T', T, '', 'third', 'e'], ['R', R, same ? '2P' : 'P + Q', 'R', 'e']], line.concat(mir))], [pq, same ? null : qq, [`λ = ${s.lambda}`, 'hot'], [`x₃ = ${R.x}`], [`y₃ = λ(x₁ − x₃) − y₁ = ${R.y}`], [`${same ? '2P' : 'P + Q'} = ${P$(R)}`, 'good'], [`${R.y}² ≡ ${lhs(R)} ≡ x₃³ + ${C.a}x₃ + ${C.b}`, 'good']], `Mirror it in y ↦ ${p} − y: ${same ? '2P' : 'P + Q'} = (${R.x}, ${p} − ${T.y}) = ${P$(R)}, with y₃ ≡ λ(x₁ − x₃) − y₁ (mod ${p}). It is on the curve: ${R.y}² ≡ ${lhs(R)} (mod ${p}), and so is x₃³ + ${C.a}x₃ + ${C.b}. Three lines of modular arithmetic, and no picture needed.`, { R, T, l: lhs(R) }, { stage: 'sum' }, { d: [3] });
      if (!same && P.y !== 0n) {
        const d = C.addT(P, P), td = d.trace[0], tan = cl.modLine('gp:t', P, d.lambda, 'modline', [P, C.neg(d.R)]);
        add([...tan, ...mk([['P', P, 'P', 'P', 'ne'], ['D', d.R, '2P', 'R', 'e']], tan)], [pq, [`λ = (3x₁² + a)·(2y₁)⁻¹ = ${d.lambda}`, 'hot'], [`2P = ${P$(d.R)}`, 'good']], `Doubling uses the tangent's slope instead: λ ≡ (3·${P.x}² + ${C.a})·(2·${P.y})⁻¹ ≡ ${td.num}·${td.di} ≡ ${d.lambda} (mod ${p}), and the same two formulas give 2P = ${P$(d.R)}.`, { lambda: d.lambda, num: td.num, di: td.di, R2: d.R }, { stage: 'double' }, { d: [1] });
      }
      U.fix(F.list);
      return { frames: F.list, def: lawDef() };
    },
    predict: [
      { at: (f) => f.meta.stage === 'slope', pick: 'item', ask: (fr, i) => 'Click the point ' + (fr[i].meta.same ? '2P' : 'P + Q') + ' will be.', answer: (fr, i, inp) => 'gp:p:' + fr[i].meta.R.x + ',' + fr[i].meta.R.y, explain: (fr, i) => fr[i + 2].say },
    ],
    quiz: [
      { q: 'Over GF(p), how is the division in the slope done?', options: ['multiply by the inverse modulo p', 'round the fraction', 'divide as real numbers', 'it is skipped'], answer: 0, why: 'a / b means a·b⁻¹, and every nonzero b has an inverse mod a prime.' },
      { q: 'In GF(61), the mirror image of (4, 9) is…', options: ['(4, 52)', '(57, 9)', '(4, −9)', '(52, 4)'], answer: 0, why: '−9 ≡ 61 − 9 = 52.' },
      { q: 'Why is the cloud symmetric about y = p/2?', options: ['y and p − y have the same square', 'the curve has two pieces', 'x³ is symmetric', 'it is not'], answer: 0, why: '(p − y)² = p² − 2py + y² ≡ y² (mod p).' },
      { q: 'With λ = 5, x₁ = 3 and x₂ = 10 in GF(13), x₃ = …', options: ['12', '25', '2', '7'], answer: 0, why: '25 − 3 − 10 = 12.' },
      { q: 'Why does the line seem to break into pieces?', options: ['its y values are taken mod p, so it wraps at p', 'the field has holes', 'λ changes', 'it is drawn wrongly'], answer: 0, why: 'Each time λx + c passes a multiple of p it starts again at the bottom.' },
    ],
  });
  function lawDef() { return U.def('The group law mod p', ['P ≠ Q: λ = (y₂ − y₁)·(x₂ − x₁)⁻¹ mod p', 'P = Q: λ = (3x₁² + a)·(2y₁)⁻¹ mod p', 'x₃ = λ² − x₁ − x₂ mod p', 'y₃ = λ(x₁ − x₃) − y₁ mod p', 'Q = −P = (x, p − y): P + Q = O']); }

  // ---------------------------------------------------------------------------------------------------------------
  // The point at infinity
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-infinity', family: 'p10-field', order: 20, title: 'The point at infinity',
    blurb: 'A curve\'s points form a group only with one extra point, O, where every vertical line ends. It is the zero of the group: P + O = P, and P + (−P) = O. Points on the x-axis are their own negatives, so doubling them gives O. In projective coordinates O is an ordinary point, (0 : 1 : 0).',
    inputs: curveInputs({ p: 61, a: 2, b: 9 }, [['P', 'P', '4, 9']]),
    presets: [
      { label: 'GF(61): P = (4, 9)', values: { p: 61, a: 2, b: 9, P: '4, 9' } },
      { label: 'GF(17): three points of order 2', values: { p: 17, a: 6, b: 3, P: '14, 3' } },
      { label: 'GF(23): no point of order 2', values: { p: 23, a: 1, b: 4, P: '4, 7' } },
      { label: 'GF(61): P on the axis', values: { p: 61, a: 2, b: 9, P: '7, 0' } },
      { label: 'GF(97)', values: { p: 97, a: 2, b: 20, P: '9, 31' } },
    ],
    check: curveCheck,
    run(inp) {
      const C = curveOf(inp), F = new S.Frames(), p = C.p, P = U.parsePoint(inp.P), nP = C.neg(P);
      const cl = U.cloud(C, { prefix: 'gp', x: CX, y: CY, s: CS });
      const N = cl.pts.length, o2 = cl.pts.filter((R) => R.y === 0n);
      const base = [headOf(C), ...cl.items];
      const add = (extra, lines, say, facts, meta, hl) => F.add({ items: [...base, ...extra, ...panel(lines)], say, facts: Object.assign({ p, a: C.a, b: C.b }, facts), meta, hl: hl || {} });
      const axis = P.y === 0n;
      const v = cl.vline('gp:v', P.x);
      if (!axis) {
        add([...cl.seg('gp:mr', P, nP), ...cl.marks([['P', P, 'P', 'P', 'e'], ['N', nP, '−P', 'Q', 'e']], cl.seg('gp:mr', P, nP))], [[`P = ${P$(P)}`, 'act'], [`−P = (${P.x}, ${p} − ${P.y}) = ${P$(nP)}`, 'key']], `The negative of P = ${P$(P)} is its mirror image, −P = (${P.x}, ${p} − ${P.y}) = ${P$(nP)}: same x, and y replaced by −y mod ${p}.`, { P, nP }, { stage: 'neg' }, { d: [1] });
        add([...v, ...cl.marks([['P', P, 'P', 'P', 'e'], ['N', nP, '−P', 'Q', 'e']], v)], [[`P = ${P$(P)}`, 'act'], [`−P = ${P$(nP)}`, 'key'], ['x = ' + P.x + ': a vertical line', 'hot'], ['P + (−P) = O', 'good']], `The line through P and −P is the vertical line x = ${P.x}. Over GF(${p}) as over the reals it meets the curve only at these two points: x = ${P.x} gives one value of y² and two square roots. With no third point to reflect, the rule needs a new point: P + (−P) = O, the point at infinity.`, { P, nP }, { stage: 'vertical' }, { d: [2] });
        add([...v, ...cl.marks([['P', P, 'P + O = P', 'R', 'e'], ['N', nP, 'third point: −P', 'third', 'e']], v)], [['O + P: the line through P and O'], ['is the vertical line through P', 'hot'], ['third point −P, mirror P', 'good'], ['P + O = P', 'good']], `O lies on every vertical line, so the line through P and O is x = ${P.x} again. Its third point is −P, and the mirror of −P is P: P + O = P. O is the zero of the group.`, { P }, { stage: 'identity' }, { d: [0] });
      }
      const lit = o2.length ? cl.marks(o2.map((R, i) => ['o' + i, R, '', 'third', 'n']), []) : [];
      add([...cl.hline('gp:x0', 0, 'e10-half'), ...lit], [[o2.length ? 'y = 0: ' + o2.map(P$).join(', ') : 'no point has y = 0', 'hot'], ['for these P = −P, so 2P = O'], [`x³ + ${C.a}x + ${C.b} has ${o2.length} root${o2.length === 1 ? '' : 's'} mod ${p}`]], o2.length ? `A point with y = 0 is its own mirror image, so P = −P and 2P = O: a point of order 2. Here ${o2.length === 1 ? 'one point has' : o2.length + ' points have'} y = 0, ${U.list(o2.map(P$))}, one for each root of x³ + ${C.a}x + ${C.b} mod ${p}.` : `A point with y = 0 would be its own negative, with 2P = O. Here x³ + ${C.a}x + ${C.b} has no root mod ${p}, so no point has y = 0 and no point has order 2.`, { o2, n2: o2.length }, { stage: 'order2', axis }, { d: [3] });
      add([], [[N + ' affine points', 'strong'], ['+ 1 for O'], [`#E = ${N + 1}`, 'good'], ['projective: (X : Y : Z), x = X/Z, y = Y/Z'], ['O = (0 : 1 : 0)', 'good']], `Counting the group means counting O too: #E = ${N} + 1 = ${N + 1}. In projective coordinates (X : Y : Z), with x = X/Z and y = Y/Z, the equation becomes Y²Z = X³ + ${C.a}XZ² + ${C.b}Z³. Setting Z = 0 leaves X³ = 0, so the only point at infinity is (0 : 1 : 0), and O is a point like any other.`, { N, NE: N + 1 }, { stage: 'count' }, { d: [4] });
      U.fix(F.list);
      return { frames: F.list, def: U.def('The point at infinity O', ['P + O = O + P = P', '−(x, y) = (x, p − y)', 'P + (−P) = O: the vertical line', 'y = 0: P = −P, 2P = O (order 2)', '#E = affine points + 1; O = (0 : 1 : 0)']) };
    },
    predict: [
      { at: (f) => f.meta.stage === 'identity', pick: 'option', ask: 'How many points of this curve have y = 0?', options: ['0', '1', '2', '3'], answer: (fr, i) => String(fr[i + 1].facts.n2), explain: (fr, i) => fr[i + 1].say },
      { at: (f) => f.meta.stage === 'order2' && f.meta.axis, pick: 'option', ask: 'How many points does the group have, O included?', options: (fr, i) => { const n = fr[i + 1].facts.N; return [n - 1, n, n + 1, 2 * n].map(String); }, answer: (fr, i) => String(fr[i + 1].facts.NE), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'P + O = …', options: ['P', 'O', '−P', '2P'], answer: 0, why: 'O is the zero of the group.' },
      { q: 'Which points have order 2?', options: ['those with y = 0', 'those with x = 0', 'O', 'none ever'], answer: 0, why: 'y = 0 means P = −P, so P + P = O.' },
      { q: 'At most how many points of order 2 can a curve over GF(p) have?', options: ['3', '1', '2', 'p'], answer: 0, why: 'One for each root of the cubic x³ + ax + b, and a cubic has at most three.' },
      { q: 'In projective coordinates, O is…', options: ['(0 : 1 : 0)', '(0 : 0 : 1)', '(1 : 1 : 1)', 'not a point'], answer: 0, why: 'Z = 0 forces X = 0, and Y can be scaled to 1.' },
      { q: 'A curve over GF(61) has 60 affine points. #E = …', options: ['61', '60', '59', '122'], answer: 0, why: 'Add one for O.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The order of a point and the shape of the group
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-order', family: 'p10-field', order: 30, title: 'The order of a point, and the shape of the group',
    blurb: 'Add P to itself again and again: P, 2P, 3P, … jump round the cloud with no visible pattern and come back to O after a fixed number of steps, the order of P. By Lagrange\'s theorem it divides the number of points. The whole group is either cyclic, or Z_n₁ × Z_n₂ with n₂ dividing n₁.',
    inputs: curveInputs({ p: 61, a: 2, b: 9 }, [['P', 'P', '17, 25']]),
    presets: [
      { label: 'GF(61): a point of order 12', values: { p: 61, a: 2, b: 9, P: '17, 25' } },
      { label: 'GF(61): a generator of Z₆₀', values: { p: 61, a: 2, b: 9, P: '1, 16' } },
      { label: 'GF(61), a point of order 5', values: { p: 61, a: 2, b: 9, P: '8, 7' } },
      { label: 'GF(17): Z₈ × Z₂', values: { p: 17, a: 6, b: 3, P: '8, 6' } },
      { label: 'GF(97): Z₂₇ × Z₃', values: { p: 97, a: 2, b: 20, P: '2, 41' } },
      { label: 'GF(23): prime order 29', values: { p: 23, a: 1, b: 4, P: '1, 12' } },
      { label: 'GF(13): Z₁₈', values: { p: 13, a: 2, b: 3, P: '3, 7' } },
    ],
    check: curveCheck,
    run(inp) {
      const C = curveOf(inp), F = new S.Frames(['steps']), p = C.p, P = U.parsePoint(inp.P);
      const cl = U.cloud(C, { prefix: 'gp', x: CX, y: CY, s: CS });
      const NE = C.count().N, ordT = C.order(P), ord = Number(ordT.order);
      const mult = [];
      for (let k = 1, R = P; k < ord; k++, R = C.add(R, P)) mult.push(R);
      const base = [headOf(C), ...cl.items];
      const add = (extra, lines, say, facts, meta, hl) => F.add({ items: [...base, ...extra, ...panel(lines)], say, facts: Object.assign({ p, NE }, facts), meta, hl: hl || {} });
      const hop = (k) => { const A = mult[k - 1], Bp = mult[k], x1 = cl.X(Number(A.x)), y1 = cl.Y(Number(A.y)), x2 = cl.X(Number(Bp.x)), y2 = cl.Y(Number(Bp.y)), mx = (x1 + x2) / 2 - (y2 - y1) * 0.18, my = (y1 + y2) / 2 + (x2 - x1) * 0.18; return { key: 'gp:hop' + k, kind: 'path', d: `M${x1},${y1} Q${U.r2(mx)},${U.r2(my)} ${x2},${y2}`, cls: 'e10-hop', audit: 'ignore', layer: 'back' }; };
      const name = (k) => (k === 1 ? 'P' : k + 'P');
      const shown = (upto) => { const ks = [...Array(upto).keys()].map((k) => k + 1); const keep = ks.length <= 8 ? ks : [1, 2, 3, upto - 1, upto].filter((k, i, a) => a.indexOf(k) === i && k >= 1); return keep.map((k) => [name(k), mult[k - 1], name(k), k === upto ? 'R' : k === 1 ? 'P' : 'pt', 'ne']); };
      add(cl.marks([['P', P, 'P', 'P', 'ne']]), [[`P = ${P$(P)}`, 'act'], ['add P again and again'], [`#E = ${NE}`]], `Start at P = ${P$(P)} and keep adding P. The group has #E = ${NE} points, O included.`, { P }, { stage: 'start' });
      const L = ord - 1, stride = L <= 10 ? 1 : Math.ceil(L / 8);
      for (let up = Math.min(L, 1 + stride); ; up = Math.min(L, up + stride)) {
        F.set('steps', up - 1);
        const hops = []; for (let k = 1; k < up; k++) hops.push(hop(k));
        const newest = mult.slice(Math.max(1, up - stride), up);
        add([...hops, ...cl.marks(shown(up), hops)], [[`P = ${P$(P)}`, 'act'], [`${name(up)} = ${P$(mult[up - 1])}`, 'good'], [`${up - 1} additions so far`]], up === 2 ? `2P = ${P$(mult[1])}: a jump across the cloud.` : `${newest.length > 1 ? 'More jumps: ' : ''}${mult.slice(Math.max(1, up - stride), up).map((R, j) => `${name(up - newest.length + 1 + j)} = ${P$(R)}`).join(', ')}. No pattern shows: knowing ${name(up)} tells you nothing visible about how many steps it took.`, { up, R: mult[up - 1], newest, ks: newest.map((_, j) => up - newest.length + 1 + j) }, { stage: 'walk', up });
        if (up >= L) break;
      }
      const last = mult[ord - 2];
      const vv = last ? cl.vline('gp:v', last.x) : [];
      add([...vv, ...cl.marks([['P', P, 'P', 'P', 'ne'], ['L', last, last && name(ord - 1), 'R', 'ne']], vv)], [[`${name(ord - 1)} = ${P$(last)} = −P`, 'good'], [`${ord}P = O`, 'good'], [`the order of P is ${ord}`, 'hot']], ord === 2 ? `P has y = 0, so P = −P and already 2P = O: the order of P is 2.` : `${name(ord - 1)} = ${P$(last)} is the mirror image of P, so one more addition gives ${ord}P = O. The multiples of P repeat from here with period ${ord}: the order of P is ${ord}, and P generates a subgroup of ${ord} points.`, { last, ord, sub: ord, prev: ord - 1 }, { stage: 'order', ord });
      const divs = S.NT.divisors(NE).map(Number);
      add([], [[`#E = ${NE}`, 'strong'], ...(divs.length > 7 ? [['divisors: ' + divs.slice(0, 7).join(', ') + ','], ['  ' + divs.slice(7).join(', ')]] : [['divisors: ' + divs.join(', ')]]), [`ord(P) = ${ord} divides ${NE}`, 'good'], [`${NE} = ${ord} · ${Number(NE) / ord}`]], `Lagrange's theorem: the order of any point divides the number of points, ${NE}. Its divisors are ${U.list(divs)}, and ${ord} is one: ${NE} = ${ord}·${Number(NE) / ord}. So the order of any point can be found by testing (${NE}/q)·P for the prime factors q of ${NE}, without walking.`, { divs, ord, cof: Number(NE) / ord }, { stage: 'lagrange' });
      // every point coloured by its order
      const st = C.structure(), n1 = Number(st.n1), n2 = Number(st.n2);
      // a second generator: a point of order n₂ outside the subgroup of P₁ (found here directly)
      if (n2 > 1) {
        const inSub = new Set(); for (let i = 0, R = null; i < n1; i++, R = C.add(R, st.P1)) inSub.add(R ? R.x + ',' + R.y : 'O');
        st.P2 = cl.pts.find((R) => Number(C.order(R).order) === n2 && !inSub.has(R.x + ',' + R.y)) || null;
      }
      const counts = new Map();
      for (const R of cl.pts) { const o = Number(C.order(R).order); counts.set(o, (counts.get(o) || 0) + 1); }
      counts.set(1, 1);
      const orders = [...counts.keys()].sort((x, y) => x - y);
      const clsOf = (R) => { const o = Number(C.order(R).order); return o === n1 ? 'e10-k0' : o === ord ? 'e10-k3' : ''; };
      const cl2 = U.cloud(C, { prefix: 'gp', x: CX, y: CY, s: CS, cls: clsOf });
      const rows = orders.map((o) => [`order ${o}`, String(counts.get(o)), o === n1 ? 'act' : o === ord ? 'hot' : '']);
      const tight = rows.length > 9;
      const items2 = [headOf(C), ...cl2.items, ...U.readout('gp:ro', PX, 50, 290, 'points by order', rows.slice(0, 13), { dy: tight ? 24 : 28 })];
      F.add({ items: items2, say: `Now colour every point by its order. ${orders.map((o) => `${counts.get(o)} ${counts.get(o) === 1 ? 'point has' : 'points have'} order ${o}`).join(', ')}. The largest order is ${n1}${n1 === Number(NE) ? ', which is #E: those blue points each generate the whole group' : `, less than #E = ${NE}: no point generates the whole group`}.`, facts: { counts: [...counts.entries()], n1, NE }, meta: { stage: 'orders' }, hl: {} });
      F.add({ items: [headOf(C), ...cl2.items, ...U.readout('gp:ro', PX, 50, 290, 'the shape of the group', [['#E', String(NE)], ['largest order n₁', String(n1), 'act'], ['n₂ = #E / n₁', String(n2)], ['group', n2 === 1 ? 'cyclic, Z' + U.sub(n1) : 'Z' + U.sub(n1) + ' × Z' + U.sub(n2), 'good'], ['P₁ of order n₁', P$(st.P1)], n2 > 1 ? ['P₂ of order n₂', P$(st.P2)] : null].filter(Boolean))], say: n2 === 1 ? `So the group is cyclic: E ≅ Z${U.sub(n1)}, and P₁ = ${P$(st.P1)} reaches every point as k·P₁. A group of prime order, like the ones cryptography uses, is always cyclic, and then every point but O generates it.` : `So the group is not cyclic: E ≅ Z${U.sub(n1)} × Z${U.sub(n2)}. Every point is a·P₁ + b·P₂ with P₁ = ${P$(st.P1)} of order ${n1} and P₂ = ${P$(st.P2)} of order ${n2}, and n₂ = ${n2} divides both n₁ and p − 1 = ${Number(p) - 1}.`, facts: { NE, n1, n2, P1: st.P1, P2: st.P2, pm1: Number(p) - 1 }, meta: { stage: 'structure' }, hl: {} });
      U.fix(F.list);
      return { frames: F.list, def: U.def('Order and structure', ['ord(P): the least n ≥ 1 with n·P = O', 'Lagrange: ord(P) divides #E', 'E(GF(p)) ≅ Z_n₁ × Z_n₂, n₂ | n₁, n₂ | p − 1', 'cyclic when n₂ = 1; prime #E is always cyclic']) };
    },
    counters: [{ id: 'steps', label: 'additions' }],
    predict: [
      { at: (f, i, fr) => f.meta.stage === 'start', pick: 'option', ask: 'Which of these could the order of P be?', options: (fr, i) => { const NE = Number(fr[i].facts.NE), o = fr.find((x) => x.meta.stage === 'order').meta.ord; const bad = [NE + 1, NE - 1, o + 1].filter((x) => x > 1 && NE % x !== 0); return [String(o)].concat(bad.slice(0, 2).map(String)); }, answer: (fr) => String(fr.find((x) => x.meta.stage === 'order').meta.ord), explain: (fr) => fr.find((x) => x.meta.stage === 'lagrange').say },
    ],
    quiz: [
      { q: 'A curve has 60 points. Which cannot be the order of a point?', options: ['7', '5', '12', '60'], answer: 0, why: '7 does not divide 60.' },
      { q: 'If #E is prime, every point other than O…', options: ['generates the whole group', 'has order 2', 'has order #E − 1', 'is its own negative'], answer: 0, why: 'Its order divides a prime and is not 1.' },
      { q: 'E ≅ Z₈ × Z₂ means…', options: ['16 points, and no point of order 16', '8 points', '10 points', 'a cyclic group'], answer: 0, why: 'The largest order is 8 < 16.' },
      { q: 'If (k−1)·P = −P, then k·P = …', options: ['O', 'P', '2P', '−2P'], answer: 0, why: '−P + P = O.' },
      { q: 'In Z_n₁ × Z_n₂ for a curve over GF(p), n₂ always divides…', options: ['p − 1 and n₁', 'p', 'p + 1 only', 'nothing'], answer: 0, why: 'This is part of the structure theorem for curves over finite fields.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Counting points: Hasse's bound
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-hasse', family: 'p10-field', order: 40, title: 'Counting points: Hasse\'s bound',
    blurb: 'Each x gives two points when x³ + ax + b is a nonzero square mod p, one when it is 0, and none otherwise. About half the numbers are squares, so a curve has about p + 1 points, and Hasse proved it is never far off: |#E − (p + 1)| ≤ 2√p.',
    inputs: [
      { id: 'p', kind: 'number', label: 'Prime p', def: 31, min: 5, max: 199, check: (v) => (!S.NT.isProbablePrime(BigInt(v)) ? 'p: a prime' : null) },
      { id: 'a', kind: 'number', label: 'a', def: 4, min: -20, max: 50 },
      { id: 'b', kind: 'number', label: 'b', def: 6, min: -20, max: 50 },
    ],
    presets: [
      { label: 'GF(31): y² = x³ + 4x + 6', values: { p: 31, a: 4, b: 6 } },
      { label: 'GF(13): every x by hand', values: { p: 13, a: 2, b: 3 } },
      { label: 'GF(61): y² = x³ + 2x + 9', values: { p: 61, a: 2, b: 9 } },
      { label: 'GF(101): y² = x³ + 6x + 14', values: { p: 101, a: 6, b: 14 } },
      { label: 'GF(199): y² = x³ + 7', values: { p: 199, a: 0, b: 7 } },
    ],
    check: (inp) => { const p = inp.p, a = md(inp.a, p), b = md(inp.b, p); return (4 * a * a * a + 27 * b * b) % p === 0 ? 'This curve is singular mod ' + p + ': 4a³ + 27b² ≡ 0' : null; },
    run(inp) {
      const p = inp.p, C = E().curve({ p, a: inp.a, b: inp.b }), F = new S.Frames(), cnt = C.count(), h = C.hasse();
      const N = Number(cnt.N), zeros = cnt.trace[0].zeros, twos = cnt.trace[0].twos, none = p - zeros - twos;
      const per = p <= 40 ? 10 : 20, cw = p <= 40 ? 50 : 26, gap = 3;
      const kind = (x) => { const r = C.rhs(BigInt(x)); return r === 0n ? 1 : S.NT.pow(r, BigInt((p - 1) / 2), BigInt(p)) === 1n ? 2 : 0; };
      const ks = [...Array(p).keys()].map(kind);
      const grid = (upto, hl) => {
        const items = [];
        for (let x = 0; x < p; x++) {
          const r = Math.floor(x / per), c = x % per, k = ks[x];
          items.push({ key: 'hs:c' + x, kind: 'cell', x: 40 + c * (cw + gap), y: 80 + r * (p <= 40 ? 68 : 34), w: cw, h: p <= 40 ? 44 : 28, rx: 4, text: x < upto ? String(k) : '', size: 14, cls: 'e10-cell mono ' + (x >= upto ? 'faint' : k === 2 ? 'good' : k === 1 ? 'hot' : '') + (hl === x ? ' act' : '') });
          if (p <= 40) items.push({ key: 'hs:x' + x, kind: 'text', x: 40 + c * (cw + gap) + cw / 2, y: 80 + r * 68 + 60, text: 'x=' + x, anchor: 'middle', size: 11, cls: 'e10-note' });
        }
        return items;
      };
      const head = U.head('hs:h', 40, 28, `y² = x³ + ${C.a}x + ${C.b} (mod ${p})`);
      const gridH = Math.ceil(p / per) * (p <= 40 ? 68 : 34);
      const lines = (L) => U.eqs('hs:e', 40, 80 + gridH + 40, L, 16, 28);
      const legend = [['2', 'a nonzero square: two points', 'good'], ['1', 'zero: one point (y = 0)', 'hot'], ['0', 'not a square: none', '']];
      const leg = legend.flatMap(([n, t, c], i) => [{ key: 'hs:lg' + i, kind: 'cell', x: 640, y: 80 + i * 38, w: 30, h: 28, rx: 4, text: n, size: 14, cls: 'e10-cell mono ' + c }, U.t('hs:lt' + i, 680, 80 + i * 38 + 19, t, 'e10-note', 'start', 13)]);
      const x0 = Math.min(3, p - 1), r0 = C.rhs(BigInt(x0)), e0 = S.NT.pow(r0, BigInt((p - 1) / 2), BigInt(p));
      F.add({ items: [head, ...grid(x0 + 1, x0), ...leg, ...lines([[`x = ${x0}: x³ + ${C.a}x + ${C.b} ≡ ${r0}`, 'act'], [r0 === 0n ? 'zero: one point' : `${r0}^${(p - 1) / 2} ≡ ${e0 === 1n ? 1 : -1} (mod ${p}): ${e0 === 1n ? 'a square' : 'not a square'}`]])], say: `Go through x = 0, 1, …, ${p - 1}. For each x work out f(x) = x³ + ${C.a}x + ${C.b} mod ${p} and ask whether it is a square. At x = ${x0}, f(x) ≡ ${r0}${r0 === 0n ? ', so y = 0 is the only root: one point' : `; Euler's criterion gives ${r0}^${(p - 1) / 2} ≡ ${e0 === 1n ? '1' : '−1'} (mod ${p}), so it ${e0 === 1n ? 'is a square with two square roots: two points' : 'is not a square: no point'}`}.`, facts: { p, pm1: p - 1, x0, r0, half: (p - 1) / 2, e: e0 === 1n ? 1 : 0, a: C.a, b: C.b }, meta: { stage: 'one' } });
      F.add({ items: [head, ...grid(p), ...leg, ...lines([[`${twos} values give 2 points, ${zeros} give${zeros === 1 ? 's' : ''} 1, ${none} give${none === 1 ? 's' : ''} 0`], [`#E = 1 + ${zeros} + 2·${twos} = ${N}`, 'good']])], say: `All ${p} values: ${twos} give a nonzero square (two points each), ${zeros} give${zeros === 1 ? 's' : ''} 0 (one point each) and ${none} give${none === 1 ? 's' : ''} a non-square (none). With O, #E = 1 + ${zeros} + 2·${twos} = ${N}.`, facts: { p, twos, zeros, none, N }, meta: { stage: 'count' } });
      // the bound on a number line
      const lo = Number(h.lo), hi = Number(h.hi), span = hi - lo, X0 = 60, W = 800, xOf = (v) => X0 + ((v - (lo - 2)) / (span + 4)) * W, yL = 220;
      const lineItems = [{ key: 'hs:nl', kind: 'line', x1: X0, y1: yL, x2: X0 + W, y2: yL, cls: '' }, { key: 'hs:band', kind: 'cell', x: xOf(lo), y: yL - 12, w: xOf(hi) - xOf(lo), h: 24, rx: 4, text: '', cls: 'e10-cell good', audit: 'overlap-ok' },
        { key: 'hs:p1', kind: 'line', x1: xOf(p + 1), y1: yL - 30, x2: xOf(p + 1), y2: yL + 30, cls: 'dash' }, U.t('hs:p1t', xOf(p + 1), yL + 50, 'p + 1 = ' + (p + 1), 'e10-note', 'middle', 14),
        U.t('hs:lot', xOf(lo), yL - 26, String(lo), 'mono', 'middle', 14), U.t('hs:hit', xOf(hi), yL - 26, String(hi), 'mono', 'middle', 14),
        { key: 'hs:N', kind: 'dot', x: xOf(N), y: yL, r: 8, cls: 'hot', point: true, layer: 'top' }, U.t('hs:Nt', xOf(N), yL + (Math.abs(N - p - 1) < span / 6 ? 80 : 50), '#E = ' + N, 'hot', 'middle', 15)];
      const sq2 = 2 * Math.sqrt(p);
      F.add({ items: [head, ...lineItems, ...U.eqs('hs:e', 60, 340, [['|#E − (p + 1)| ≤ 2√p', 'strong'], [`2√${p} ≈ ${sq2.toFixed(2)}, so ${lo} ≤ #E ≤ ${hi}`], [`#E = ${N}: t = p + 1 − #E = ${U.int(Number(h.t))}`, 'good']], 17, 32)], say: `Hasse's theorem: |#E − (p + 1)| ≤ 2√p. About half the nonzero numbers mod ${p} are squares, so on average each x gives one point and #E is near p + 1 = ${p + 1}. Here 2√${p} ≈ ${sq2.toFixed(2)}, so ${lo} ≤ #E ≤ ${hi}, and #E = ${N} lies inside, with t = p + 1 − #E = ${U.int(Number(h.t))}.`, facts: { p, p1: p + 1, sq2, lo, hi, N, t: Number(h.t) }, meta: { stage: 'bound' } });
      // the same curve over many primes
      const top = Math.max(p, 101), primes = [];
      for (let q = 5; q <= top; q++) if (S.NT.isProbablePrime(BigInt(q))) {
        const a = md(inp.a, q), b = md(inp.b, q);
        if ((4 * a * a * a + 27 * b * b) % q === 0) continue;
        const Nq = Number(E().curve({ p: q, a: inp.a, b: inp.b }).count().N);
        primes.push({ q, t: q + 1 - Nq });
      }
      const ym = Math.ceil(2 * Math.sqrt(top)) + 2;
      const pl = S.Kit.curve.plot({ prefix: 'hp', x: 70, y: 60, w: 760, h: 470, xr: [0, top + 4], yr: [-ym, ym], ticks: { x: top > 150 ? 50 : 20, y: ym > 20 ? 10 : 5 }, labels: { xAt: 'bottom', yAt: 'left' }, tickSize: 13 });
      const bound = (sg) => { let d = ''; for (let i = 0; i <= 200; i++) { const x = ((top + 4) * i) / 200; d += (i ? 'L' : 'M') + pl.X(x) + ',' + pl.Y(sg * 2 * Math.sqrt(x)) + ' '; } return { key: 'hp:b' + sg, kind: 'path', d, cls: 'e10-cubic', audit: 'ignore' }; };
      const dots = primes.map(({ q, t }) => ({ key: 'hp:d' + q, kind: 'dot', x: pl.X(q), y: pl.Y(t), r: q === p ? 7 : 4, cls: q === p ? 'hot' : 'act', point: true }));
      let skipped = 0; for (let q = 5; q <= top; q++) if (S.NT.isProbablePrime(BigInt(q)) && !primes.some((x) => x.q === q)) skipped++;
      const inside = primes.every(({ q, t }) => t * t <= 4 * q);
      const mine = primes.find((x) => x.q === p);
      F.add({ items: [U.head('hs:h', 70, 28, `t = p + 1 − #E for y² = x³ + ${U.int(inp.a)}x + ${U.int(inp.b)}, every prime up to ${top}`), ...pl.items, bound(1), bound(-1), ...dots, U.t('hp:lab', pl.X(top * 0.55), pl.Y(2 * Math.sqrt(top * 0.55)) - 14, 't = ±2√p', 'e10-note', 'middle', 14), U.t('hp:xl', 830, 560, 'p', 'e10-note', 'end', 14)], say: `The same equation over every prime up to ${top} (${primes.length} curves${skipped ? `, leaving out the ${U.plural(skipped, 'prime')} where it is singular` : ''}). Each dot is one curve's t = p + 1 − #E; the dashed lines are ±2√p. ${inside ? 'Every dot lies between them' : 'A dot outside would break the theorem'}, and they scatter with no pattern inside the band. ${mine ? `The large dot is p = ${p}, t = ${U.int(mine.t)}.` : ''}`, facts: { top, n: primes.length, p, t: mine ? mine.t : 0, skipped }, meta: { stage: 'scatter', inside } });
      // real sizes
      const C2 = E().P256, h2 = C2.hasse(), tb = S.ECC.bitLength(h2.t < 0n ? -h2.t : h2.t);
      F.add({ items: [U.head('hs:h', 60, 28, 'At real size: P-256'), ...U.readout('hs:r', 60, 60, 800, 'P-256', [['p', f(C2.p)], ['#E = n (cofactor 1)', f(C2.n), 'good'], ['t = p + 1 − #E', f(h2.t), 'hot'], ['bits of t', String(tb)], ['bits of 2√p', String(S.ECC.bitLength(S.NT.isqrt(4n * C2.p)))]], { dy: 40, vsize: 16 })], say: `At real size nobody lists points, but the count is still known exactly, by Schoof's algorithm and its successors. For P-256, #E = n = ${f(C2.n)} with cofactor 1, so t = p + 1 − #E = ${f(h2.t)}: a ${tb}-bit number, while 2√p has ${S.ECC.bitLength(S.NT.isqrt(4n * C2.p))} bits. #E agrees with p in its top half and is prime.`, facts: { p: C2.p, n: C2.n, t: h2.t, tb, sb: S.ECC.bitLength(S.NT.isqrt(4n * C2.p)) }, meta: { stage: 'real' } });
      U.fix(F.list);
      return { frames: F.list, def: U.def('Counting points', ['f(x) = x³ + ax + b mod p', 'square ≠ 0: 2 points; 0: 1 point; non-square: 0', '#E = 1 + #zeros + 2·#squares', 'Hasse: |#E − (p + 1)| ≤ 2√p']) };
    },
    predict: [
      { at: (f) => f.meta.stage === 'one', pick: 'option', ask: 'Roughly how many points will the curve have?', options: (fr, i, inp) => [String(inp.p + 1) + ' or so', 'about ' + 2 * inp.p, 'about ' + Math.round(inp.p / 2), 'about ' + inp.p * inp.p], answer: (fr, i, inp) => String(inp.p + 1) + ' or so', explain: (fr, i) => fr[i + 2].say },
    ],
    quiz: [
      { q: 'If f(x) is a nonzero square mod p, the column x holds…', options: ['two points', 'one point', 'no point', 'p points'], answer: 0, why: 'y and p − y, the two square roots.' },
      { q: 'Hasse: a curve over GF(101) has between … points.', options: ['82 and 122', '0 and 202', '101 and 102', '50 and 150'], answer: 0, why: '2√101 ≈ 20.1, so 102 ± 20.' },
      { q: 'Why is #E close to p + 1?', options: ['about half the values of f(x) are squares, each giving two points', 'every x gives one point', 'the curve is a line', 'by definition'], answer: 0, why: 'On average one point per x, plus O.' },
      { q: 'Which counts are possible over GF(13)?', options: ['16', '25', '5', '30'], answer: 0, why: '2√13 ≈ 7.2, so 7 ≤ #E ≤ 21.' },
      { q: 't = p + 1 − #E is called…', options: ['the trace of Frobenius', 'the cofactor', 'the order', 'the discriminant'], answer: 0, why: 'Hasse says |t| ≤ 2√p.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
