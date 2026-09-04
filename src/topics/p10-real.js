// Part 10, curves over the reals: the shape of y² = x³ + ax + b as a and b change (one piece or two, and the
// singular curves in between), and the chord-and-tangent rule that adds two points, doubles one, and sends a point
// and its mirror image to the point at infinity.
(function (S) {
  'use strict';
  const U = S.P10, CV = () => S.Kit.curve, EC = () => S.EC;
  const fx = U.fx, f2 = (v) => fx(v, 2);
  const pt = (P) => `(${f2(P.x)}, ${f2(P.y)})`;
  const sgn = (v) => (v < 0 ? '−' : '+') + ' ' + U.int(Math.abs(v));
  const eqn = (a, b) => 'y² = x³' + (a ? ' ' + sgn(a) + 'x' : '') + (b ? ' ' + sgn(b) : '');
  const cubic = (a, b) => 'x³' + (a ? ' ' + sgn(a) + 'x' : '') + (b ? ' ' + sgn(b) : '');

  /** the real roots of x³ + ax + b, by bisection on a fine grid */
  function roots(a, b) {
    const f = (x) => x * x * x + a * x + b, out = [];
    let prev = -20, fp = f(prev);
    for (let i = 1; i <= 8000; i++) {
      const x = -20 + (40 * i) / 8000, fv = f(x);
      if (fp === 0) out.push(prev);
      else if ((fp < 0) !== (fv < 0) && fv !== 0) { let lo = prev, hi = x; for (let k = 0; k < 80; k++) { const m = (lo + hi) / 2; if ((f(lo) < 0) === (f(m) < 0)) lo = m; else hi = m; } out.push((lo + hi) / 2); }
      prev = x; fp = fv;
    }
    return out;
  }
  const disc = (a, b) => 4 * a * a * a + 27 * b * b;

  // the plot both topics draw on
  const plotFor = (prefix, yr) => CV().plot({ prefix, x: 56, y: 40, w: 430, h: 560, xr: [-4, 4], yr: yr || [-8, 8], ticks: { x: 1, y: 2 }, labels: { xAt: 'bottom', yAt: 'left' }, tickSize: 13 });
  const PX = 540, PW = 370;

  // ---------------------------------------------------------------------------------------------------------------
  // The shape of the curve
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-real-shape', family: 'p10-real', order: 10, title: 'The shape of y² = x³ + ax + b',
    blurb: 'An elliptic curve over the real numbers is the set of points with y² = x³ + ax + b. Where the cubic on the right is negative there is no point at all, so the curve is one piece or two. The sign of 4a³ + 27b² decides which, and when it is zero the curve crosses itself or has a cusp, and is not allowed.',
    inputs: [
      { id: 'a', kind: 'number', label: 'a', def: -4, min: -6, max: 4 },
      { id: 'b', kind: 'number', label: 'b', def: 2, min: -6, max: 6 },
    ],
    presets: [
      { label: 'Two pieces: a = −4, b = 2', values: { a: -4, b: 2 } },
      { label: 'One piece: a = 1, b = 3', values: { a: 1, b: 3 } },
      { label: 'Two pieces, symmetric: a = −5, b = 0', values: { a: -5, b: 0 } },
      { label: 'Singular, a node: a = −3, b = 2', values: { a: -3, b: 2 } },
      { label: 'Singular, a cusp: a = 0, b = 0', values: { a: 0, b: 0 } },
      { label: 'Singular, a lone point: a = −3, b = −2', values: { a: -3, b: -2 } },
      { label: 'One piece with a bulge: a = −2, b = 4', values: { a: -2, b: 4 } },
    ],
    run(inp) {
      const a = inp.a, b = inp.b, F = new S.Frames();
      const pl = plotFor('rs');
      const curveItems = (A, Bv, key, cls) => CV().real(pl, EC().real(A, Bv), key, cls);
      const cubicPath = (A, Bv, key) => {
        let d = '', pen = false;
        for (let i = 0; i <= 400; i++) {
          const x = -4 + (8 * i) / 400, y = x * x * x + A * x + Bv;
          if (y < -8 || y > 8) { pen = false; continue; }
          d += (pen ? 'L' : 'M') + pl.X(x) + ',' + pl.Y(y) + ' '; pen = true;
        }
        return { key, kind: 'path', d, cls: 'e10-cubic', pathAudit: 'edge-x' };
      };
      const rs = roots(a, b), D = disc(a, b);
      const pieces = D < 0 ? 2 : 1;
      const rootDots = (list, key) => list.filter((x) => x >= -4 && x <= 4).map((x, i) => ({ key: key + i, kind: 'dot', x: pl.X(x), y: pl.Y(0), r: 5, cls: 'hot', point: true }));
      const bands = () => {
        const out = [];
        const segs = rs.length >= 3 ? [[rs[0], rs[1]], [rs[2], 4]] : [[rs[rs.length - 1], 4]];
        segs.forEach(([u, v], i) => { u = Math.max(-4, u); v = Math.min(4, v); if (v > u) out.push({ key: 'rs:band' + i, kind: 'path', d: `M${pl.X(u)},${pl.Y(0)} H${pl.X(v)}`, cls: 'e10-band', audit: 'ignore', layer: 'back' }); });
        return out;
      };
      const head = [U.head('rs:h', 56, 24, eqn(a, b))];
      const panel = (lines) => U.eqs('rs:e', PX, 70, lines, 16, 30);
      const rootList = U.list(rs.map(f2));
      const facts0 = { a, b, roots: rs, D, pieces };
      // 1. the cubic
      F.add({ items: [...head, ...pl.items, cubicPath(a, b, 'rs:cubic'), ...rootDots(rs, 'rs:r')], hl: { d: [0] }, say: `Start from the cubic on the right-hand side, f(x) = ${cubic(a, b)} (the dashed line). It crosses zero ${rs.length === 1 ? 'once, at x ≈ ' + rootList : rs.length === 2 ? 'at x ≈ ' + rootList + ', touching the axis at one of them' : 'three times, at x ≈ ' + rootList}.`, facts: facts0, meta: { stage: 'cubic' } });
      F.list[0].items.push(...panel([['f(x) = ' + cubic(a, b), 'strong'], ['real roots: ' + rs.map(f2).join(', '), 'hot']]));
      // 2. where f(x) ≥ 0
      const where = rs.length >= 3 ? `from ${f2(rs[0])} to ${f2(rs[1])} and from ${f2(rs[2])} onwards` : `from ${f2(rs[rs.length - 1])} onwards`;
      F.add({ items: [...head, ...pl.items, cubicPath(a, b, 'rs:cubic'), ...bands(), ...rootDots(rs, 'rs:r'), ...panel([['f(x) = ' + cubic(a, b), 'strong'], ['y² = f(x) needs f(x) ≥ 0', 'act'], ['so x runs ' + where]])], hl: { d: [1] }, say: `A point (x, y) needs y² = f(x), and a square is never negative. So the curve exists only where f(x) ≥ 0: ${where} (the thick stretches of the axis).`, facts: facts0, meta: { stage: 'where' } });
      // 3. the curve
      const sing = D === 0;
      F.add({ items: [...head, ...pl.items, ...bands(), ...curveItems(a, b, 'rs:c', ''), ...rootDots(rs, 'rs:r'), ...panel([['y = ±√f(x)', 'strong'], ['symmetric about the x-axis'], [pieces === 2 ? 'two pieces: an oval and a branch' : sing ? b > 0 ? 'one piece that crosses itself' : b < 0 ? 'a branch and a lone point' : 'one piece with a cusp' : 'one piece', 'good']])], hl: { d: [1] }, say: `Over each stretch y = ±√f(x): an upper half and its mirror image in the x-axis, since y and −y have the same square. ${pieces === 2 ? 'Here that makes two pieces: a closed oval on the left and an open branch running off to the right.' : sing ? (b > 0 ? 'Here the two halves meet at a repeated root and the curve crosses itself there.' : b < 0 ? 'Here the repeated root gives a lone point on the axis, apart from the branch.' : 'Here the two halves meet in a sharp point at the origin.') : 'Here that makes a single piece, open to the right.'}`, facts: facts0, meta: { stage: 'curve', pieces, sing } });
      // 4. the discriminant
      const dLine = `4·(${U.int(a)})³ + 27·(${U.int(b)})² = ${U.int(D)}`;
      F.add({ items: [...head, ...pl.items, ...curveItems(a, b, 'rs:c', ''), ...rootDots(rs, 'rs:r'), ...panel([['4a³ + 27b²', 'strong'], ['= ' + dLine.split(' = ')[0]], ['= ' + U.int(D), D < 0 ? 'act' : D > 0 ? 'good' : 'hot'], ['< 0: three roots, two pieces'], ['> 0: one root, one piece'], ['= 0: a repeated root, singular', 'hot']])], hl: { d: [2] }, say: `One number decides the shape: 4a³ + 27b² = ${dLine}. ${D < 0 ? 'It is negative, so the cubic has three real roots and the curve two pieces.' : D > 0 ? 'It is positive, so the cubic has one real root and the curve one piece.' : 'It is zero: the cubic has a repeated root, and the curve is singular.'}`, facts: Object.assign({ cube: a * a * a, sq: b * b }, facts0), meta: { stage: 'disc' } });
      // 5. a sweep through the singular value, b fixed
      const ac = -Math.cbrt((27 * b * b) / 4), sweep = [ac + 2, ac, ac - 2];
      const ghost = curveItems(a, b, 'rs:g', 'e10-ghost');
      sweep.forEach((A, i) => {
        const Dv = i === 1 ? 0 : disc(A, b), kind = i === 1 ? (b === 0 ? 'a cusp' : b > 0 ? 'a node' : 'an isolated point') : Dv < 0 ? 'two pieces' : 'one piece';
        const x0 = i === 1 && b !== 0 ? (-3 * b) / (2 * A) : 0;
        const mark = i === 1 ? [{ key: 'rs:sing', kind: 'dot', x: pl.X(x0), y: pl.Y(0), r: 6, cls: 'e10-ring', audit: 'overlap-ok' }] : [];
        F.add({ items: [U.head('rs:h', 56, 24, 'b = ' + U.int(b) + ', a = ' + f2(A)), ...pl.items, ...ghost, ...curveItems(A, b, 'rs:s', 'e10-sweep'), ...mark, ...panel([['keep b = ' + U.int(b) + ', change a', 'strong'], ['a = ' + f2(A), 'act'], ['4a³ + 27b² = ' + fx(Dv, 2)], [kind, i === 1 ? 'hot' : 'good'], ['faint: your curve', '']])], say: i === 0 ? `Watch the shape change: keep b = ${U.int(b)} and move a. At a = ${f2(A)}, 4a³ + 27b² = ${fx(Dv, 2)} > 0: ${kind}.` : i === 1 ? `At a = ${f2(A)} the number 4a³ + 27b² is exactly 0. ${b === 0 ? 'The curve y² = x³ comes to a sharp point, a cusp, at the origin.' : b > 0 ? `The oval and the branch meet at x = ${f2(x0)}, where the curve crosses itself: a node.` : `The curve is one branch plus a single isolated point at x = ${f2(x0)}, where an oval is about to grow.`} No single tangent is defined there.` : `At a = ${f2(A)}, 4a³ + 27b² = ${fx(Dv, 2)} < 0: ${kind}${b > 0 ? ', the oval having pinched off from the branch' : b < 0 ? ', the isolated point having grown into an oval' : ''}.`, facts: { a: A, b, D: Dv, x0, ac }, meta: { stage: 'sweep', i, kind } });
      });
      // 6. why singular curves are excluded
      const x0 = sing ? (b === 0 ? 0 : (-3 * b) / (2 * a)) : null;
      F.add({ items: [...head, ...pl.items, ...curveItems(a, b, 'rs:c', ''), ...(sing ? [{ key: 'rs:sing', kind: 'dot', x: pl.X(x0), y: pl.Y(0), r: 6, cls: 'e10-ring', audit: 'overlap-ok' }] : []), ...panel([[eqn(a, b), 'strong'], ['4a³ + 27b² = ' + U.int(D), sing ? 'hot' : 'good'], [sing ? 'singular: not an elliptic curve' : 'smooth: an elliptic curve', sing ? 'hot' : 'good'], ['every point has one tangent'], ['the addition rule needs it']])], hl: { d: [3] }, say: sing ? `So ${eqn(a, b)} is not an elliptic curve: at x = ${f2(x0)} it has no single tangent, and the rule for doubling a point breaks down there. Cryptography uses only curves with 4a³ + 27b² ≠ 0.` : `${eqn(a, b)} is smooth: 4a³ + 27b² = ${U.int(D)} ≠ 0, so every point has exactly one tangent line. The rule for adding points, in the next topic, is built from lines like these.`, facts: { a, b, D, x0 }, meta: { stage: 'end' } });
      U.fix(F.list);
      return { frames: F.list, def: U.def('The curve over the reals', ['f(x) = x³ + ax + b', 'points: y² = f(x), so f(x) ≥ 0, y = ±√f(x)', '4a³ + 27b² < 0: two pieces; > 0: one piece', '4a³ + 27b² = 0: singular (a node or a cusp), excluded']) };
    },
    predict: [
      { at: (f) => f.meta.stage === 'where', pick: 'option', ask: 'How many pieces will the curve have?', options: ['one', 'two', 'singular: a node, a cusp or a lone point'], answer: (fr, i) => { const m = fr[i + 1].meta; return m.sing ? 'singular: a node, a cusp or a lone point' : m.pieces === 2 ? 'two' : 'one'; }, explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta.stage === 'sweep' && f.meta.i === 1, pick: 'option', ask: 'Now lower a below this value. What does the curve become?', options: ['two pieces', 'one piece', 'still singular'], answer: 'two pieces', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why is there no point of y² = x³ − 4x + 2 at x = −3?', options: ['f(−3) is negative, and no square is negative', 'x must be positive', 'the curve stops at x = −2', 'y would be 0'], answer: 0, why: 'f(−3) = −27 + 12 + 2 = −13 < 0, and y² cannot be negative.' },
      { q: 'If 4a³ + 27b² < 0, the curve over the reals has…', options: ['two pieces', 'one piece', 'no points', 'a cusp'], answer: 0, why: 'The cubic then has three real roots: an oval between the first two and a branch after the third.' },
      { q: 'Why is the curve symmetric about the x-axis?', options: ['(x, y) and (x, −y) give the same y²', 'because a and b are integers', 'because it is a cubic', 'it is not symmetric'], answer: 0, why: 'Only y² appears in the equation.' },
      { q: 'Why are curves with 4a³ + 27b² = 0 excluded?', options: ['they have a point with no single tangent', 'they have no points', 'they are too slow', 'they have only one piece'], answer: 0, why: 'At a node or cusp the tangent is not defined, so doubling a point there fails.' },
      { q: 'y² = x³ + x + 3 has 4a³ + 27b² = …', options: ['247', '−247', '31', '0'], answer: 0, why: '4·1 + 27·9 = 4 + 243 = 247 > 0: one piece.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Chord and tangent
  // ---------------------------------------------------------------------------------------------------------------
  const onCurve = (a, b, x) => x * x * x + a * x + b >= 0;
  S.topic({
    id: 'ec-real-add', family: 'p10-real', order: 20, title: 'Adding points: chord and tangent',
    blurb: 'To add P and Q, draw the line through them. A line meets a cubic curve at most three times, so it meets the curve once more; reflect that third point in the x-axis and you have P + Q. To double P, use the tangent at P. A vertical line meets no third point: the sum is the point at infinity O.',
    inputs: [
      { id: 'a', kind: 'number', label: 'a', def: -4, min: -6, max: 4 },
      { id: 'b', kind: 'number', label: 'b', def: 2, min: -6, max: 6, check: (v, inp) => (disc(inp.a, v) === 0 ? 'This curve is singular (4a³ + 27b² = 0): choose another a or b' : null) },
      { id: 'xp', kind: 'number', label: 'x of P', def: -1, integer: false, min: -3.5, max: 3.5, check: (v, inp) => (!onCurve(inp.a, inp.b, v) ? 'x of P: no point there, since x³ + ax + b < 0' : null) },
      { id: 'sp', kind: 'choice', label: 'P is', def: 'up', options: [{ value: 'up', label: 'above the axis' }, { value: 'down', label: 'below the axis' }] },
      { id: 'xq', kind: 'number', label: 'x of Q', def: 2.6, integer: false, min: -3.5, max: 3.5, check: (v, inp) => (!onCurve(inp.a, inp.b, v) ? 'x of Q: no point there, since x³ + ax + b < 0' : null) },
      { id: 'sq', kind: 'choice', label: 'Q is', def: 'up', options: [{ value: 'up', label: 'above the axis' }, { value: 'down', label: 'below the axis' }] },
    ],
    presets: [
      { label: 'P on the oval, Q on the branch', values: { a: -4, b: 2, xp: -1, sp: 'up', xq: 2.6, sq: 'up' } },
      { label: 'Both on the branch', values: { a: -4, b: 2, xp: 1.8, sp: 'down', xq: 2.9, sq: 'up' } },
      { label: 'One piece: a = 1, b = 3', values: { a: 1, b: 3, xp: -1, sp: 'up', xq: 1, sq: 'down' } },
      { label: 'Q = −P: a vertical line', values: { a: -2, b: 4, xp: 0.5, sp: 'up', xq: 0.5, sq: 'down' } },
      { label: 'P = Q: the tangent', values: { a: -2, b: 4, xp: 1, sp: 'up', xq: 1, sq: 'up' } },
      { label: 'Symmetric curve: a = −5, b = 0', values: { a: -5, b: 0, xp: -2, sp: 'up', xq: 2.5, sq: 'down' } },
    ],
    check: (inp) => {
      const yp = Math.sqrt(Math.max(0, inp.xp ** 3 + inp.a * inp.xp + inp.b)), yq = Math.sqrt(Math.max(0, inp.xq ** 3 + inp.a * inp.xq + inp.b));
      if (Math.abs(inp.xp - inp.xq) > 1e-9 && Math.abs(inp.xp - inp.xq) < 0.25) return 'P and Q: keep their x at least 0.25 apart, or make them equal';
      if (yp < 0.05 && yq < 0.05) return 'Choose points off the x-axis';
      return null;
    },
    run(inp) {
      const a = inp.a, b = inp.b, cu = EC().real(a, b), F = new S.Frames();
      const y = (x, s) => Math.sqrt(Math.max(0, cu.rhs(x))) * (s === 'down' ? -1 : 1);
      const P = { x: inp.xp, y: y(inp.xp, inp.sp) }, Q = { x: inp.xq, y: y(inp.xq, inp.sq) };
      // a y range that holds every point drawn
      const s = cu.add(P, Q), d = Math.abs(P.y) > 1e-9 ? cu.add(P, P) : { R: null };
      const ys = [P.y, Q.y, s.R && s.R.y, d.R && d.R.y].filter((v) => v !== null && v !== undefined && isFinite(v));
      const ym = Math.min(14, Math.max(6, Math.ceil(Math.max(...ys.map(Math.abs)) + 1)));
      const pl = CV().plot({ prefix: 'ra', x: 56, y: 40, w: 430, h: 560, xr: [-4, 4], yr: [-ym, ym], ticks: { x: 1, y: ym > 8 ? 4 : 2 }, labels: { xAt: 'bottom', yAt: 'left' }, tickSize: 13 });
      const inPlot = (R) => R && R.x >= -4 && R.x <= 4 && Math.abs(R.y) <= ym;
      const base = [...pl.items, ...CV().real(pl, cu, 'ra:c', '')];
      const marks = (list, drawn) => CV().marks(pl, list.filter((m) => m[1] && inPlot(m[1])).map(([k, Pt, name, cls, dir]) => ({ key: 'ra:m:' + k, P: Pt, name, cls, prefer: dir })), base.concat(drawn || []));
      const head = [U.head('ra:h', 56, 24, eqn(a, b))];
      const panel = (lines) => U.eqs('ra:e', PX, 70, lines, 16, 30);
      const pq = [`P = ${pt(P)}`, 'act'], qq = [`Q = ${pt(Q)}`, 'key'];
      const same = Math.abs(P.x - Q.x) < 1e-12 && Math.abs(P.y - Q.y) < 1e-12;
      const opposite = Math.abs(P.x - Q.x) < 1e-12 && !same;
      const add = (items, lines, say, facts, meta, hl) => F.add({ items: [...head, ...base, ...items, ...panel(lines)], say, facts: Object.assign({ a, b }, facts), meta, hl: hl || {} });
      add(marks([['P', P, 'P', 'P', 'nw'], ['Q', Q, 'Q', 'Q', 'ne']]), [pq, same ? ['Q = P: double P', 'key'] : qq], `On ${eqn(a, b)} take P = ${pt(P)}${same ? ' and add it to itself' : ` and Q = ${pt(Q)}`}.`, { P, Q }, { stage: 'start' });
      if (opposite) {
        const v = [{ key: 'ra:v', kind: 'path', d: `M${pl.X(P.x)},${pl.Y(-ym)} V${pl.Y(ym)}`, cls: 'chord', pathAudit: 'edge-x', samples: CV().sampleSeg([pl.X(P.x), pl.Y(-ym)], [pl.X(P.x), pl.Y(ym)]) }];
        add([...v, ...marks([['P', P, 'P', 'P', 'nw'], ['Q', Q, 'Q = −P', 'Q', 'sw']], v)], [pq, qq, ['the line x = ' + f2(P.x) + ' is vertical', 'hot']], `Q is the mirror image of P, so Q = −P, and the line through them is vertical: x = ${f2(P.x)}. It meets the curve at no third point.`, { P, Q }, { stage: 'vertical' }, { d: [3] });
        add([...v, ...marks([['P', P, 'P', 'P', 'nw'], ['Q', Q, '−P', 'Q', 'sw']], v)], [pq, qq, ['P + (−P) = O', 'good'], ['O: the point at infinity', 'good'], ['P + O = P for every P']], 'The rule says the sum is the point at infinity O, which we imagine far up the vertical direction where every vertical line ends. O behaves like zero: P + O = P, and P + (−P) = O, so −P really is the negative of P.', { P }, { stage: 'infinity' }, { d: [3] });
      } else if (!same) {
        const chord = CV().line(pl, 'ra:l', P, s.lambda, 'chord');
        const pts = [['P', P, 'P', 'P', 'nw'], ['Q', Q, 'Q', 'Q', 'ne']];
        add([...chord, ...marks(pts, chord)], [pq, qq, [`λ = (y₂ − y₁) / (x₂ − x₁)`, 'hot'], [`  = ${f2(s.lambda)}`, 'hot']], `The line through P and Q has slope λ = (${f2(Q.y)} − (${f2(P.y)})) / (${f2(Q.x)} − (${f2(P.x)})) = ${f2(s.lambda)}.`, { P, Q, lambda: s.lambda }, { stage: 'chord' }, { d: [0] });
        add([...chord, ...marks([...pts, ['T', s.third, '−(P + Q)', 'third', 's']], chord)], [pq, qq, [`λ = ${f2(s.lambda)}`, 'hot'], [`x₃ = λ² − x₁ − x₂ = ${f2(s.R.x)}`]], `Put the line into the equation: a cubic in x with roots x₁, x₂ and one more, and the roots of x³ − λ²x² + … add up to λ². So the third point has x₃ = λ² − x₁ − x₂ = ${f2(s.R.x)}: it is ${pt(s.third)}.`, { lambda: s.lambda, R: s.R, third: s.third }, { stage: 'third', above: s.third.y > 0 }, { d: [1] });
        const mir = CV().segment(pl, 'ra:mr', s.third, s.R, 'mirror');
        add([...chord, ...mir, ...marks([...pts, ['T', s.third, '', 'third', 's'], ['R', s.R, 'P + Q', 'R', 'se']], chord.concat(mir))], [pq, qq, [`λ = ${f2(s.lambda)}`, 'hot'], [`x₃ = ${f2(s.R.x)}`], [`y₃ = λ(x₁ − x₃) − y₁ = ${f2(s.R.y)}`], [`P + Q = ${pt(s.R)}`, 'good']], `Reflect it in the x-axis: P + Q = ${pt(s.R)}. The reflection is what makes this a group: P, Q and −(P + Q) lie on one line, and the three of them add up to O.`, { R: s.R }, { stage: 'sum' }, { d: [2] });
      }
      if (!opposite && Math.abs(P.y) > 1e-9) {
        const tan = CV().line(pl, 'ra:t', P, d.lambda, 'tangent');
        const tp = [['P', P, 'P', 'P', 'nw']];
        add([...tan, ...marks(tp, tan)], [pq, [`λ = (3x₁² + a) / 2y₁`, 'hot'], [`  = ${f2(d.lambda)}`, 'hot']], `To double P there is no second point to draw a line through, so take the tangent at P, the limit of chords as Q slides into P. Its slope is λ = (3·(${f2(P.x)})² + (${U.int(a)})) / (2·(${f2(P.y)})) = ${f2(d.lambda)}.`, { P, lambda: d.lambda, a }, { stage: 'tangent' }, { d: [0] });
        const mir = inPlot(d.third) && inPlot(d.R) ? CV().segment(pl, 'ra:mr2', d.third, d.R, 'mirror') : [];
        add([...tan, ...mir, ...marks([...tp, ['T2', d.third, '−2P', 'third', 'n'], ['R2', d.R, '2P', 'R', 's']], tan.concat(mir))], [pq, [`λ = ${f2(d.lambda)}`, 'hot'], [`x₃ = λ² − 2x₁ = ${f2(d.R.x)}`], [`2P = ${pt(d.R)}`, 'good']], `The tangent touches the curve twice at P and meets it once more, at x₃ = λ² − 2x₁ = ${f2(d.R.x)}. Reflect: 2P = ${pt(d.R)}${inPlot(d.R) ? '' : ', off this picture'}.`, { R: d.R, third: d.third, lambda: d.lambda }, { stage: 'double' }, { d: [1, 2] });
      } else if (same) {
        add([], [pq, ['y = 0: the tangent is vertical', 'hot'], ['2P = O', 'good']], 'P lies on the x-axis, so its tangent is vertical and meets no other point: 2P = O. P is a point of order 2.', { P }, { stage: 'order2' }, { d: [3] });
      }
      U.fix(F.list);
      return { frames: F.list, def: U.def('Adding points', ['P ≠ Q: λ = (y₂ − y₁) / (x₂ − x₁)', 'P = Q: λ = (3x₁² + a) / 2y₁', 'x₃ = λ² − x₁ − x₂, y₃ = λ(x₁ − x₃) − y₁', 'P + (−P) = O, P + O = P']) };
    },
    predict: [
      { at: (f, i, fr) => f.meta.stage === 'third' && fr[i + 1], pick: 'option', ask: 'P + Q is the mirror image of this third point. Will it be above or below the x-axis?', options: ['above', 'below'], answer: (fr, i) => (fr[i].meta.above ? 'below' : 'above'), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta.stage === 'start' && fr[i + 1] && fr[i + 1].meta.stage === 'vertical', pick: 'option', ask: 'Q is the mirror image of P. What is P + Q?', options: ['O, the point at infinity', '2P', 'the origin (0, 0)', 'P'], answer: 'O, the point at infinity', explain: (fr, i) => fr[i + 2].say },
    ],
    quiz: [
      { q: 'Why does the line through P and Q meet the curve exactly once more?', options: ['substituting it gives a cubic, which has three roots counted together', 'every line meets every curve three times', 'because the curve is symmetric', 'it may meet it many more times'], answer: 0, why: 'Two roots are x₁ and x₂, and a real cubic with two real roots has a third.' },
      { q: 'After finding the third point on the line, you…', options: ['reflect it in the x-axis', 'use it as P + Q', 'double it', 'draw the tangent there'], answer: 0, why: 'P + Q is the mirror image of the third point.' },
      { q: 'What line is used to compute 2P?', options: ['the tangent at P', 'the vertical line through P', 'the line through P and the origin', 'the x-axis'], answer: 0, why: 'The tangent is the limit of the chord through P and Q as Q approaches P.' },
      { q: 'P + (−P) = …', options: ['O, the point at infinity', '(0, 0)', '2P', 'P'], answer: 0, why: 'The line through them is vertical and meets no third point.' },
      { q: 'With λ = 2, x₁ = 1 and x₂ = −1, x₃ = …', options: ['4', '2', '0', '6'], answer: 0, why: 'x₃ = λ² − x₁ − x₂ = 4 − 1 + 1 = 4.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
