// Elliptic-curve addition: chord and tangent on a curve over the reals, and the same rule on the points of a curve
// over GF(43), where the line wraps round and the mirror is y ↦ p − y.
(function (S) {
  'use strict';
  const D = S.Demo, E = S.EC, CV = S.Kit.curve, box = D.box;
  const f2 = (v) => (Math.abs(v) < 5e-3 ? 0 : v).toFixed(2).replace('-', '−');
  const pt = (P) => `(${f2(P.x)}, ${f2(P.y)})`;
  const tone = { P: 'act', Q: 'key', R: 'good', hot: 'hot', strong: 'strong' };
  const panelLines = (x, y, lines, narrow) => lines.map(([t, cls], k) => ({ key: 'pn' + k, kind: 'text', x, y: y + k * (narrow ? 25 : 30), text: t, cls: 'eq ' + (tone[cls] || ''), size: narrow ? 14 : 16 }));

  D.add({
    id: 'ec-real', order: 70, tag: 'Elliptic curves · over the reals', short: 'EC over ℝ', title: 'Adding points: the chord and the tangent',
    blurb: 'The line through P and Q meets the curve in exactly one more point; its mirror image in the x-axis is P + Q. For 2P the line is the tangent at P.',
    frames({ narrow }) {
      const cu = E.real(-4, 2);
      const P = { x: -1, y: Math.sqrt(cu.rhs(-1)) }, Q = { x: 2.6, y: Math.sqrt(cu.rhs(2.6)) };
      const s = cu.add(P, Q), d = cu.add(P, P);
      const L = narrow
        ? { view: box(-6, -10, 396, 720), plot: { x: 30, y: 0, w: 350, h: 430 }, panel: [0, 476] }
        : { view: box(0, -10, 1160, 600), plot: { x: 50, y: 0, w: 455, h: 560 }, panel: [580, 40] };
      const pl = CV.plot(Object.assign({ prefix: 'er', xr: [-3, 3.5], yr: [-4, 4], ticks: { x: 1, y: 1 }, labels: { xAt: 'bottom', yAt: 'left' } }, L.plot));
      const curve = CV.real(pl, cu, 'ec:c', '');
      const base = [...pl.items, ...curve];
      const chord = CV.line(pl, 'ec:l', P, s.lambda, 'chord'), tan = CV.line(pl, 'ec:t', P, d.lambda, 'tangent');
      const drawn = chord.concat(tan, CV.segment(pl, 'ec:m', s.third, s.R, 'mirror'), CV.segment(pl, 'ec:m2', d.third, d.R, 'mirror'));
      const pts = (list) => CV.marks(pl, list.map(([k, Pt, n, c, dir]) => ({ key: 'ep:' + k, P: Pt, name: n, cls: c, prefer: dir })), base.concat(drawn));
      const head = [['y² = x³ − 4x + 2', 'strong']];
      const pq = [`P = ${pt(P)}`, 'P'], qq = [`Q = ${pt(Q)}`, 'Q'];
      const frames = [];
      const F = (items, lines, say) => frames.push({ view: L.view, items: [...base, ...items, ...panelLines(L.panel[0], L.panel[1], head.concat(lines), narrow)], say });
      F([], [], 'Over the real numbers, y² = x³ − 4x + 2 has two pieces: a closed oval on the left and an open branch on the right. The curve is symmetric about the x-axis, since y and −y give the same y².');
      F(pts([['P', P, 'P', 'P', 'nw'], ['Q', Q, 'Q', 'Q', 'nw']]), [pq, qq], `Take P = ${pt(P)} on the oval and Q = ${pt(Q)} on the right branch.`);

      F([...chord, ...pts([['P', P, 'P', 'P', 'nw'], ['Q', Q, 'Q', 'Q', 'nw']])], [pq, qq, [`λ = (y₂ − y₁) / (x₂ − x₁) = ${f2(s.lambda)}`, 'hot']], `The line through them has slope λ = (${f2(Q.y)} − ${f2(P.y)}) / (${f2(Q.x)} − (${f2(P.x)})) = ${f2(s.lambda)}.`);
      F([...chord, ...pts([['P', P, 'P', 'P', 'nw'], ['Q', Q, 'Q', 'Q', 'nw'], ['T', s.third, '−(P+Q)', 'third', 'n']])], [pq, qq, [`λ = ${f2(s.lambda)}`, 'hot'], [`x₃ = λ² − x₁ − x₂ = ${f2(s.R.x)}`]], `A line meets a cubic at most three times, so it meets the curve exactly once more, at x₃ = λ² − x₁ − x₂ = ${f2(s.R.x)}: the point ${pt(s.third)}.`);
      F([...chord, ...CV.segment(pl, 'ec:m', s.third, s.R, 'mirror'), ...pts([['P', P, 'P', 'P', 'nw'], ['Q', Q, 'Q', 'Q', 'nw'], ['T', s.third, '', 'third', 'n'], ['R', s.R, 'P + Q', 'R', 'sw']])], [pq, qq, [`λ = ${f2(s.lambda)}`, 'hot'], [`x₃ = ${f2(s.R.x)}`], [`y₃ = λ(x₁ − x₃) − y₁ = ${f2(s.R.y)}`], [`P + Q = ${pt(s.R)}`, 'R']], `Reflect it in the x-axis: P + Q = ${pt(s.R)}. The reflection is what makes the rule a group: P, Q and −(P+Q) on one line sum to the point at infinity.`);

      F([...tan, ...pts([['P', P, 'P', 'P', 'nw']])], [pq, [`λ = (3x₁² + a) / 2y₁ = ${f2(d.lambda)}`, 'hot']], `To double P there is no second point, so take the tangent at P: λ = (3·(${f2(P.x)})² − 4) / (2·${f2(P.y)}) = ${f2(d.lambda)}.`);
      F([...tan, ...CV.segment(pl, 'ec:m2', d.third, d.R, 'mirror'), ...pts([['P', P, 'P', 'P', 'nw'], ['T2', d.third, '−2P', 'third', 'ne'], ['R2', d.R, '2P', 'R', 'se']])], [pq, [`λ = ${f2(d.lambda)}`, 'hot'], [`x₃ = λ² − 2x₁ = ${f2(d.R.x)}`], [`2P = ${pt(d.R)}`, 'R']], `The tangent leaves the oval and meets the right branch at ${pt(d.third)}; its mirror image is 2P = ${pt(d.R)}.`);
      return frames;
    },
  });

  D.add({
    id: 'ec-field', order: 71, tag: 'Elliptic curves · over GF(p)', short: 'EC over GF(p)', title: 'The same rule over GF(43): a cloud of points',
    blurb: 'Over a prime field the curve is a scatter of points, but the formulas are the same, with division done by a modular inverse. The line wraps round; the mirror is y ↦ 43 − y.',
    frames({ narrow }) {
      const p = 43, cu = E.field(p, 3, 13), pts = cu.points();
      const P = { x: 1n, y: 19n }, Q = { x: 14n, y: 2n }, s = cu.add(P, Q), R = s.R, T = cu.neg(R);
      const n = (P2) => ({ x: Number(P2.x), y: Number(P2.y) });
      const L = narrow
        ? { view: box(-6, -14, 396, 720), plot: { x: 30, y: 0, w: 350, h: 350 }, panel: [0, 410], fs: 14 }
        : { view: box(0, -14, 1160, 540), plot: { x: 50, y: 0, w: 488, h: 488 }, panel: [610, 40], fs: 16 };
      const pl = CV.plot(Object.assign({ prefix: 'ef', xr: [0, p - 1], yr: [0, p - 1], ticks: { x: 10, y: 10 }, labels: { origin: true }, axisAt: { x: 0, y: 0 } }, L.plot));
      const cloud = CV.cloud(pl, 'ef:p', pts, '', narrow ? 3 : 3.8);
      const base = [...pl.items, ...cloud];
      const line0 = CV.modLine(pl, 'ef:l', n(P), Number(s.lambda), p, 'modline');
      let drawn = line0.concat(CV.segment(pl, 'ef:m', n(T), n(R), 'mirror'));
      const mark = (list) => CV.marks(pl, list.map(([k, Pt, nm, c, dir]) => ({ key: 'efm:' + k, P: n(Pt), name: nm, cls: c, prefer: dir })), base.concat(drawn), narrow ? 14 : 15);
      const head = [[`y² = x³ + 3x + 13 (mod ${p})`, 'strong'], [`${pts.length} points, and the point at infinity`]];
      const frames = [];
      const F = (items, lines, say) => frames.push({ view: L.view, items: [...base, ...items, ...panelLines(L.panel[0], L.panel[1], head.concat(lines), narrow)], say });
      const pP = [`P = (${P.x}, ${P.y})`, 'P'], pQ = [`Q = (${Q.x}, ${Q.y})`, 'Q'];
      F([], [], `Every pair (x, y) with y² ≡ x³ + 3x + 13 (mod ${p}) is a point: ${pts.length} of them, symmetric about the line y = ${p / 2}, since y and ${p} − y have the same square.`);
      F(mark([['P', P, 'P', 'P', 'ne'], ['Q', Q, 'Q', 'Q', 'ne']]), [pP, pQ], `Take P = (${P.x}, ${P.y}) and Q = (${Q.x}, ${Q.y}).`);
      const tr = s.trace[0];
      const line = CV.modLine(pl, 'ef:l', n(P), Number(s.lambda), p, 'modline');
      F([...line, ...mark([['P', P, 'P', 'P', 'ne'], ['Q', Q, 'Q', 'Q', 'ne']])], [pP, pQ, [`λ = (${Q.y} − ${P.y}) · (${Q.x} − ${P.x})⁻¹`, 'hot'], [`  = ${tr.num} · ${tr.den}⁻¹ = ${tr.num} · ${tr.di} = ${s.lambda}`, 'hot']], `The slope needs a division, done as a multiplication by an inverse modulo ${p}: ${tr.den}⁻¹ = ${tr.di}, because ${tr.den} · ${tr.di} = ${Number(tr.den) * Number(tr.di)} ≡ 1. So λ = ${s.lambda}. The line y = ${s.lambda}x + ${(((P.y - s.lambda * P.x) % BigInt(p)) + BigInt(p)) % BigInt(p)} wraps round each time it passes ${p}.`);
      F([...line, ...mark([['P', P, 'P', 'P', 'ne'], ['Q', Q, 'Q', 'Q', 'ne'], ['T', T, '−(P+Q)', 'third', 'e']])], [pP, pQ, [`λ = ${s.lambda}`, 'hot'], [`x₃ = λ² − x₁ − x₂ = ${R.x} (mod ${p})`]], `On one of its laps the line passes through a third point of the cloud, (${T.x}, ${T.y}): x₃ = ${s.lambda}² − ${P.x} − ${Q.x} = ${R.x} (mod ${p}).`);
      F([...line, ...CV.segment(pl, 'ef:m', n(T), n(R), 'mirror'), ...mark([['P', P, 'P', 'P', 'ne'], ['Q', Q, 'Q', 'Q', 'ne'], ['T', T, '', 'third', 'e'], ['R', R, 'P + Q', 'R', 'e']])], [pP, pQ, [`λ = ${s.lambda}`, 'hot'], [`x₃ = ${R.x}`], [`y₃ = λ(x₁ − x₃) − y₁ = ${R.y}`], [`P + Q = (${R.x}, ${R.y})`, 'R']], `Its mirror image, y ↦ ${p} − y, is P + Q = (${R.x}, ${R.y}). No pictures are needed to compute it: three lines of modular arithmetic.`);
      const G = P, ord = cu.order(G);
      drawn = [];
      const mult = []; let A = G; for (let k = 1; k <= 6; k++) { mult.push([k, A]); A = cu.add(A, G).R; }
      F([...mark(mult.map(([k, Pt]) => ['m' + k, Pt, k === 1 ? 'P' : k + 'P', k === 1 ? 'P' : 'R', 'ne']))], [pP, [`P, 2P, 3P, … jump around the cloud`], [`P has order ${ord}: ${ord}·P = O`]], `Adding P again and again jumps around the cloud with no visible pattern: P, 2P = (${mult[1][1].x}, ${mult[1][1].y}), 3P = (${mult[2][1].x}, ${mult[2][1].y}), … After ${ord} steps it reaches the point at infinity. Finding k from kP is the discrete logarithm problem on the curve.`);
      return frames;
    },
  });
})(globalThis.Sifer = globalThis.Sifer || {});
