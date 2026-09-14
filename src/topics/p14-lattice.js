// Part 14, lattices: one lattice with a good and a bad basis, Gram–Schmidt as projections you can see, Lagrange–
// Gauss reduction turning a long skewed basis into a short square one, and Babai's rounding, which finds the
// closest lattice point with a good basis and misses it with a bad one.
(function (S) {
  'use strict';
  const U = S.P14, L = () => S.PQ.Lattice;
  const fx = U.fx, f2 = (v) => fx(v, 2);
  const vec = (v) => '(' + v.map((x) => (Number.isInteger(x) ? U.int(x) : f2(x))).join(', ') + ')';

  /**
   * A square lattice plot at (30, 66) of side 564, centred on the origin, big enough for every point given. Returns
   * {X, Y, s, H, items (axes), dots(B), vec(key, from, to, cls, label), cell(key, B, at, cls), pt(key, p, cls, r)}.
   */
  function plane(points, opts) {
    opts = opts || {};
    let m = 4;
    for (const p of points) m = Math.max(m, Math.abs(p[0]), Math.abs(p[1]));
    const H = Math.ceil(m * 1.12 + 2), side = 564, ox = 30, oy = 66, s = side / (2 * H);
    const X = (u) => U.r2(ox + (u + H) * s), Y = (v) => U.r2(oy + (H - v) * s);
    const items = [
      { key: 'lp:frame', kind: 'region', x: ox, y: oy, w: side, h: side, rx: 6, cls: 'frame', audit: 'ignore', layer: 'back' },
      { key: 'lp:ax', kind: 'path', d: `M${ox},${Y(0)} H${ox + side} M${X(0)},${oy} V${oy + side}`, cls: 'axis', audit: 'ignore', layer: 'back' },
    ];
    const P = {
      X, Y, s, H, items,
      dots: (B, cls) => L().points(B, { x0: -H, x1: H, y0: -H, y1: H }).map(({ p }) => ({ key: 'lp:d' + p[0] + '_' + p[1], kind: 'dot', x: X(p[0]), y: Y(p[1]), r: 2.8, cls: 'lat ' + (cls || ''), layer: 'back' })),
      vec(key, a, b, cls, label, side2) {
        const good = /good/.test(cls || '');
        const out = [good ? { key, kind: 'edge', from: { x: X(a[0]), y: Y(a[1]) }, to: { x: X(b[0]), y: Y(b[1]) }, cls: 'good', gapB: 0 } : { key, kind: 'wire', pts: [[X(a[0]), Y(a[1])], [X(b[0]), Y(b[1])]], head: true, cls: 'vecw ' + (cls === 'soft' ? 'soft dim' : cls || '') }];
        if (label) {
          // the name sits beside the tip, on the side away from `away` (another vector) or on the side asked
          const dx = b[0] - a[0], dy = b[1] - a[1], l = Math.hypot(dx, dy) || 1, ux = dx / l, uy = dy / l;
          let sg = side2 === 'r' ? -1 : 1;
          if (Array.isArray(side2)) sg = ux * side2[1] - uy * side2[0] > 0 ? -1 : 1;
          // on screen: back along the arrow a little, then off to the side; a long name hangs away from the arrow
          const px = -uy * sg, py = -ux * sg, anchor = Math.abs(px) > 0.45 ? (px > 0 ? 'start' : 'end') : 'middle';
          const lx = X(b[0]) - ux * 16 + px * 12, ly = Y(b[1]) + uy * 16 + py * 14;
          out.push({ key: key + ':n', kind: 'text', x: U.r2(lx), y: U.r2(ly + 5), text: label, anchor, size: 15, cls: 'ptname ' + (cls || '') });
        }
        return out;
      },
      cell(key, B, at, cls) {
        const o = at || [0, 0], a = B[0], b = B[1];
        const c = [o, [o[0] + a[0], o[1] + a[1]], [o[0] + a[0] + b[0], o[1] + a[1] + b[1]], [o[0] + b[0], o[1] + b[1]]];
        return { key, kind: 'path', d: 'M' + c.map((p) => X(p[0]) + ',' + Y(p[1])).join(' L') + ' Z', cls: 'cellpath ' + (cls || ''), audit: 'ignore', layer: 'back' };
      },
      pt: (key, p, cls, r) => (cls === 'ring' ? { key, kind: 'dot', x: X(p[0]), y: Y(p[1]), r: r || 9, cls, audit: 'overlap-ok' } : { key, kind: 'dot', x: X(p[0]), y: Y(p[1]), r: r || 6, cls: cls || 'hot', point: true }),
    };
    return P;
  }
  const basisCheck = (v) => {
    if (v.length !== 4 || v.some((x) => !/^-?\d+$/.test(x))) return 'Basis: four whole numbers, b₁ then b₂ (as x, y, x, y)';
    if (v.some((x) => Math.abs(+x) > 60)) return 'Basis: entries from −60 to 60, so the picture stays readable';
    const [a, b, c, d] = v.map(Number);
    if (a * d - b * c === 0) return 'Basis: the two vectors must not be parallel';
    if (Math.abs(a * d - b * c) < 6) return 'Basis: a determinant of at least 6, so the points stay apart';
    return null;
  };
  /** x₁·a + x₂·b written with the sign of the second term in front of it */
  const comb = (x1, a, x2, b) => `${f2(x1)}·${a} ${x2 < 0 ? '−' : '+'} ${f2(Math.abs(x2))}·${b}`;
  const toB = (v) => [[+v[0], +v[1]], [+v[2], +v[3]]];
  const det = (B) => B[0][0] * B[1][1] - B[0][1] * B[1][0];
  const len = (v) => Math.hypot(v[0], v[1]);

  // ---------------------------------------------------------------------------------------------------------------
  // Good and bad bases
  // ---------------------------------------------------------------------------------------------------------------
  function bases(inp) {
    const g = L().goodBad(+inp.seed), G = g.good, B = g.bad, D = Math.abs(det(G));
    const sh = L().shortest(G, 4);
    const P = plane([G[0], G[1], B[0], B[1], [B[0][0] + B[1][0], B[0][1] + B[1][1]]]);
    const F = new S.Frames();
    const dots = P.dots(G);
    const panel = (rows, title) => U.readout('lb:r', 618, 66, 288, title, rows);
    const goodV = () => [...P.vec('lb:g1', [0, 0], G[0], 'act', 'g₁', G[1]), ...P.vec('lb:g2', [0, 0], G[1], 'act', 'g₂', G[0])];
    const badV = () => [...P.vec('lb:b1', [0, 0], B[0], 'hot', 'b₁', B[1]), ...P.vec('lb:b2', [0, 0], B[1], 'hot', 'b₂', B[0])];
    const head = U.t('lb:h', 30, 34, 'One lattice, two bases', 'strong', 'start', 16);
    F.add({ items: [head, ...P.items, ...dots, ...panel([['points shown', String(dots.length)], ['area per point', String(D)]], 'the lattice')], say: `A lattice: the points m·g₁ + n·g₂ for all whole numbers m and n. Every point has the same neighbourhood, and each one takes up an area of ${D}, the absolute determinant.`, facts: { D }, meta: { stage: 'points' } });
    const gRows = [['g₁', vec(G[0]), 'act'], ['g₂', vec(G[1]), 'act'], ['|g₁|, |g₂|', f2(len(G[0])) + ', ' + f2(len(G[1]))], ['area of the cell', String(D)], ['Hadamard ratio', fx(g.hGood, 3)]];
    F.add({ items: [head, ...P.items, ...dots, P.cell('lb:gc', G, null, ''), ...goodV(), ...panel(gRows, 'good basis')], hl: { d: [0, 1] }, say: `A good basis: g₁ = ${vec(G[0])} and g₂ = ${vec(G[1])}, short and nearly at right angles. Their parallelogram, the fundamental cell, has area ${D}; its Hadamard ratio, (area ÷ |g₁||g₂|)^(1/2), is ${fx(g.hGood, 3)}, close to 1, the value for a square corner.`, facts: { G, D, h: g.hGood, l1: len(G[0]), l2: len(G[1]) }, meta: { stage: 'good' } });
    const tiles = [];
    for (let a = -1; a <= 1; a++) for (let b = -1; b <= 1; b++) if (a || b) tiles.push(P.cell('lb:t' + a + '_' + b, G, [a * G[0][0] + b * G[1][0], a * G[0][1] + b * G[1][1]], 'faint'));
    F.add({ items: [head, ...P.items, ...dots, P.cell('lb:gc', G, null, ''), ...tiles, ...goodV(), ...panel(gRows, 'good basis')], hl: { d: [1] }, say: `Copies of the cell, moved to every lattice point, tile the plane with no gaps and no overlaps: one cell for each point, which is why its area ${D} is the same for every basis of this lattice.`, facts: { D }, meta: { stage: 'tile' } });
    const bRows = [['b₁', vec(B[0]), 'hot'], ['b₂', vec(B[1]), 'hot'], ['|b₁|, |b₂|', f2(len(B[0])) + ', ' + f2(len(B[1]))], ['area of the cell', String(Math.abs(det(B)))], ['Hadamard ratio', fx(g.hBad, 3)]];
    F.add({ items: [head, ...P.items, ...dots, P.cell('lb:bc', B, null, 'key'), ...badV(), ...panel(bRows, 'bad basis')], hl: { d: [2] }, say: `A bad basis of the very same lattice: b₁ = ${vec(B[0])} and b₂ = ${vec(B[1])}, long and nearly parallel. Every lattice point is still a whole combination of them, and the cell still has area ${Math.abs(det(B))}, but it is a thin sliver: the Hadamard ratio is only ${fx(g.hBad, 3)}.`, facts: { B, D: Math.abs(det(B)), h: g.hBad }, meta: { stage: 'bad' } });
    const Um = g.U, u = (r) => '(' + r.map(U.int).join(', ') + ')';
    F.add({ items: [head, ...P.items, ...dots, P.cell('lb:bc', B, null, 'key'), ...badV(), ...goodV(), ...panel([['b₁ = ' + Um[0][0] + '·g₁ + ' + Um[0][1] + '·g₂', vec(B[0]), 'hot'], ['b₂ = ' + Um[1][0] + '·g₁ + ' + Um[1][1] + '·g₂', vec(B[1]), 'hot'], ['U', u(Um[0]) + ' ' + u(Um[1])], ['det U', U.int(det(Um))]], 'the change of basis')], hl: { d: [3] }, say: `The bad basis is the good one mixed by a whole-number matrix U with rows ${u(Um[0])} and ${u(Um[1])}, whose determinant is ${U.int(det(Um))}. Its inverse has whole entries too, so each basis gives the other: a basis is only a way of naming the same points.`, facts: { U: Um, detU: det(Um) }, meta: { stage: 'mix' } });
    F.add({ items: [head, ...P.items, ...dots, P.cell('lb:bc', B, null, 'key'), ...badV(), ...P.vec('lb:sv', [0, 0], sh.v, 'good', 'v'), P.pt('lb:svp', sh.v, 'good', 5), ...panel([['shortest v', vec(sh.v), 'good'], ['|v|', f2(sh.len), 'good'], ['|b₁|', f2(len(B[0]))], ['|b₂|', f2(len(B[1]))]], 'shortest vector')], hl: { d: [4] }, say: `The shortest non-zero lattice vector is v = ${vec(sh.v)}, of length ${f2(sh.len)}. With the good basis it is in plain sight; from the bad basis alone, finding it is the shortest vector problem. In two dimensions it is easy, as the reduction topic shows; in the hundreds of dimensions of ML-KEM no method is known that does it fast. A public bad basis and a secret good one is the shape of lattice cryptography.`, facts: { v: sh.v, l: sh.len, lb1: len(B[0]), lb2: len(B[1]) }, meta: { stage: 'short' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Lattices and bases', ['L = { a·b₁ + b·b₂ : a, b whole numbers }', 'area of the cell = |det B|, the same for every basis', 'Hadamard ratio = (|det B| / |b₁||b₂|)^(1/n): 1 square, near 0 skewed', 'B′ = U·B with U whole and det U = ±1 names the same lattice', 'SVP: find the shortest non-zero vector']) };
  }
  S.topic({
    id: 'pq-lattice-bases', family: 'p14-lattice', order: 10, title: 'Lattices, good and bad bases',
    blurb: 'A lattice is all the whole-number combinations of a basis. The same points have short square bases and long skewed ones; the cell they make has the same area, and the good one makes hard problems easy.',
    inputs: [{ id: 'seed', kind: 'choice', label: 'Lattice', def: '13', options: [['13', 'A, mildly skewed'], ['6', 'B'], ['23', 'C'], ['4', 'D, square-ish'], ['24', 'E, very thin'], ['12', 'F, long']].map(([v, l]) => ({ value: v, label: l })) }],
    presets: [{ label: 'Lattice A', values: { seed: '13' } }, { label: 'Lattice C', values: { seed: '23' } }, { label: 'Lattice E (thin)', values: { seed: '24' } }, { label: 'Lattice F (long)', values: { seed: '12' } }],
    run: bases,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'tile', pick: 'option', options: ['larger', 'the same', 'smaller'], ask: 'The bad basis is coming. Will its cell have a larger area, the same or a smaller one?', answer: 'the same', explain: 'Both cells tile the plane with one cell per lattice point, so both have area |det|.' }],
    quiz: [
      { q: 'Two bases describe the same lattice exactly when…', options: ['their vectors have the same lengths', 'one is the other times a whole matrix with determinant ±1', 'they have the same first vector', 'their cells have the same shape'], answer: 1, why: 'Such a matrix and its inverse both have whole entries, so each basis is made of the other\'s points.' },
      { q: 'The area of the fundamental cell…', options: ['depends on the basis', 'is |det B|, the same for every basis', 'is the length of the shortest vector', 'is always 1'], answer: 1, why: 'One cell per lattice point tiles the plane, so the area is fixed by the lattice.' },
      { q: 'A Hadamard ratio near 0 means the basis is…', options: ['nearly orthogonal', 'long and nearly parallel', 'the shortest possible', 'not a basis'], answer: 1, why: 'The vectors are long compared with the area they span.' },
      { q: 'Why publish a bad basis and keep a good one secret?', options: ['Bad bases are shorter', 'Hard problems such as the closest vector are easy with the good basis and hard with the bad one', 'Good bases cannot be stored', 'It saves space'], answer: 1, why: 'This asymmetry is the trapdoor behind lattice cryptography.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Gram–Schmidt
  // ---------------------------------------------------------------------------------------------------------------
  function gramSchmidt(inp) {
    const B = toB(inp.basis), gs = L().gramSchmidt(B), mu = gs.mu[1][0], b2s = gs.Bs[1], proj = [mu * B[0][0], mu * B[0][1]];
    const D = Math.abs(det(B)), l1 = len(B[0]), l2s = Math.sqrt(gs.norms2[1]);
    const P = plane([B[0], B[1], proj, b2s]);
    const F = new S.Frames();
    const head = U.t('gs:h', 30, 34, 'Gram–Schmidt in two dimensions', 'strong', 'start', 16);
    const base = () => [head, ...P.items, ...P.dots(B)];
    const zero = Math.abs(mu) < 1e-9;
    const b1v = () => P.vec('gs:b1', [0, 0], B[0], 'act', 'b₁', B[1]), b2v = (lab) => P.vec('gs:b2', [0, 0], B[1], 'key', lab || 'b₂', B[0]);
    const projv = () => (zero ? [] : [...P.vec('gs:pr', [0, 0], proj, 'soft', 'μ·b₁', B[1]), { key: 'gs:drop', kind: 'path', d: `M${P.X(B[1][0])},${P.Y(B[1][1])} L${P.X(proj[0])},${P.Y(proj[1])}`, cls: 'dline soft', audit: 'ignore' }]);
    const starv = () => (zero ? [] : P.vec('gs:bs', [0, 0], b2s, 'good', 'b₂*', B[0]));
    const rows = (k) => U.readout('gs:r', 618, 66, 288, 'values', [['b₁', vec(B[0]), 'act'], ['b₂', vec(B[1]), 'key'], ['μ = ⟨b₂, b₁⟩ / ⟨b₁, b₁⟩', k >= 1 ? f2(mu) : '…'], ['b₂* = b₂ − μ·b₁', k >= 2 ? vec(b2s) : '…', 'good'], ['|b₁*| · |b₂*|', k >= 3 ? f2(l1 * l2s) : '…'], ['|det B|', k >= 3 ? String(D) : '…']]);
    F.add({ items: [...base(), ...b1v(), ...b2v(), ...rows(0)], hl: { d: [0] }, say: `Two basis vectors, b₁ = ${vec(B[0])} and b₂ = ${vec(B[1])}. Gram–Schmidt makes them perpendicular: b₁* = b₁ stays, and b₂* keeps only the part of b₂ that b₁ does not already point along.`, facts: { B }, meta: { stage: 'start' } });
    F.add({ items: [...base(), P.cell('gs:c', B, null, ''), ...b1v(), ...b2v(), ...projv(), ...rows(1)], hl: { d: [1] }, say: `The shadow of b₂ on b₁: μ = ⟨b₂, b₁⟩ / ⟨b₁, b₁⟩ = ${B[1][0] * B[0][0] + B[1][1] * B[0][1]} / ${B[0][0] ** 2 + B[0][1] ** 2} = ${f2(mu)}, so the part of b₂ along b₁ is μ·b₁ = ${vec(proj)}.` + (zero ? ' The vectors are already at right angles: there is no shadow.' : ''), facts: { dot: B[1][0] * B[0][0] + B[1][1] * B[0][1], n1: B[0][0] ** 2 + B[0][1] ** 2, mu, proj }, meta: { stage: 'mu', mu } });
    F.add({ items: [...base(), P.cell('gs:c', B, null, ''), ...b1v(), ...b2v(zero ? 'b₂ = b₂*' : ''), ...projv(), ...starv(), ...rows(2)], hl: { d: [2] }, say: `Take that shadow away: b₂* = b₂ − μ·b₁ = ${vec(b2s)}, at right angles to b₁ (their inner product is ${f2(b2s[0] * B[0][0] + b2s[1] * B[0][1])}). It is not a lattice vector unless μ is whole; it is a measuring stick.`, facts: { b2s, ip: b2s[0] * B[0][0] + b2s[1] * B[0][1] }, meta: { stage: 'perp' } });
    const rect = [[0, 0], B[0], [B[0][0] + b2s[0], B[0][1] + b2s[1]], b2s];
    F.add({ items: [...base(), P.cell('gs:c', B, null, ''), { key: 'gs:rect', kind: 'path', d: 'M' + rect.map((p) => P.X(p[0]) + ',' + P.Y(p[1])).join(' L') + ' Z', cls: 'cellpath key', audit: 'ignore', layer: 'back' }, ...b1v(), ...b2v(zero ? 'b₂ = b₂*' : ''), ...starv(), ...rows(3)], hl: { d: [3, 4] }, say: `The rectangle on b₁* and b₂* has the same area as the cell: |b₁*| · |b₂*| = ${f2(l1)} × ${f2(l2s)} = ${f2(l1 * l2s)} = |det B| = ${D}. ${l2s < 0.5 * l1 ? `Here b₂* is much shorter than b₁: the Gram–Schmidt lengths fall away, the mark of a bad basis.` : `Here the Gram–Schmidt lengths are even, the mark of a good basis.`}`, facts: { l1, l2s, area: l1 * l2s, D }, meta: { stage: 'area' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Gram–Schmidt', ['b₁* = b₁', 'μ₂₁ = ⟨b₂, b₁*⟩ / ⟨b₁*, b₁*⟩', 'b₂* = b₂ − μ₂₁·b₁*', '|det B| = |b₁*| · |b₂*| · …', 'reduction keeps |μ| ≤ ½ and the |bᵢ*| from falling fast']) };
  }
  S.topic({
    id: 'pq-gram-schmidt', family: 'p14-lattice', order: 20, title: 'Gram–Schmidt as shadows',
    blurb: 'Subtract from each vector its shadow on the ones before it, and what is left stands at right angles. The lengths that remain measure a basis: even for a good one, falling away for a bad one.',
    inputs: [{ id: 'basis', kind: 'list', label: 'Basis b₁, b₂ (x, y, x, y)', def: ['6', '1', '2', '5'], check: basisCheck }],
    presets: [
      { label: 'A good basis', values: { basis: ['6', '1', '2', '5'] } },
      { label: 'A bad basis', values: { basis: ['9', '12', '4', '8'] } },
      { label: 'Already perpendicular', values: { basis: ['5', '0', '0', '4'] } },
      { label: 'Nearly parallel', values: { basis: ['12', '18', '6', '11'] } },
    ],
    run: gramSchmidt,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'perp', pick: 'option', options: ['smaller', 'the same', 'larger'], ask: 'Compare the rectangle on b₁* and b₂* with the cell of b₁ and b₂. Its area is…', answer: 'the same', explain: 'Removing the shadow is a shear: it keeps the area, so |b₁*||b₂*| = |det B|.' }],
    quiz: [
      { q: 'b₂* is…', options: ['always a lattice vector', 'b₂ with its component along b₁ removed', 'the shortest vector', 'b₁ + b₂'], answer: 1, why: 'It is the part of b₂ at right angles to b₁; it need not be in the lattice.' },
      { q: 'For b₁ = (4, 0) and b₂ = (3, 5), μ is…', options: ['0.75', '1.25', '3', '0.6'], answer: 0, why: '⟨b₂, b₁⟩ / ⟨b₁, b₁⟩ = 12 / 16.' },
      { q: '|b₁*| · |b₂*| equals…', options: ['|b₁| · |b₂|', '|det B|', '1', 'the shortest length'], answer: 1, why: 'The shear that removes the shadow keeps the area of the cell.' },
      { q: 'A bad basis shows up in Gram–Schmidt as…', options: ['all lengths equal', 'later lengths |bᵢ*| much smaller than earlier ones', 'μ = 0 everywhere', 'negative lengths'], answer: 1, why: 'Long nearly parallel vectors leave little at right angles.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Lagrange–Gauss reduction
  // ---------------------------------------------------------------------------------------------------------------
  function gauss(inp) {
    const B0 = toB(inp.basis), res = L().gauss(B0), tr = res.trace;
    const all = [B0[0], B0[1]];
    for (const st of tr) all.push(st.B[0], st.B[1]);
    const P = plane(all), F = new S.Frames(['swaps', 'reductions']);
    const dots = P.dots(B0);
    const head = U.t('gg:h', 30, 34, 'Lagrange–Gauss reduction', 'strong', 'start', 16);
    let prev = null;
    tr.forEach((st, k) => {
      const Bc = st.B, ghost = prev && st.kind === 'reduce' ? P.vec('gg:old', [0, 0], prev[1], 'soft', '') : [];
      if (st.kind === 'swap') F.count('swaps');
      if (st.kind === 'reduce') F.count('reductions');
      const rows = [['b₁', vec(Bc[0]), 'act'], ['b₂', vec(Bc[1]), 'key'], ['|b₁|', f2(len(Bc[0]))], ['|b₂|', f2(len(Bc[1]))], ['⟨b₁, b₂⟩ / ⟨b₁, b₁⟩', f2((Bc[0][0] * Bc[1][0] + Bc[0][1] * Bc[1][1]) / (Bc[0][0] ** 2 + Bc[0][1] ** 2))], ['Hadamard ratio', fx(L().hadamard(Bc), 3)]];
      const items = [head, ...P.items, ...dots, P.cell('gg:c', Bc, null, st.kind === 'gauss-done' ? '' : 'key'), ...ghost, ...P.vec('gg:b1', [0, 0], Bc[0], 'act', 'b₁', Bc[1]), ...P.vec('gg:b2', [0, 0], Bc[1], 'key', 'b₂', Bc[0]), ...U.readout('gg:r', 618, 66, 288, 'basis now', rows)];
      const ratio = (Bc[0][0] * Bc[1][0] + Bc[0][1] * Bc[1][1]) / (Bc[0][0] ** 2 + Bc[0][1] ** 2);
      F.add({ items, hl: { d: st.kind === 'swap' ? [1] : st.kind === 'reduce' ? [2] : st.kind === 'gauss-done' ? [3] : [0] }, say: st.say + (st.kind === 'reduce' ? ` The cell keeps its area, ${Math.abs(det(Bc))}, but leans less.` : ''), facts: { B: Bc, m: st.m, l1: len(Bc[0]), l2: len(Bc[1]), ratio, D: Math.abs(det(Bc)) }, meta: { stage: st.kind, m: st.m } });
      prev = Bc;
    });
    const sh = L().shortest(res.B, 3);
    const last = F.last();
    last.say += ` Exhaustive search agrees: the shortest length in the lattice is ${f2(sh.len)}.`;
    last.facts.short = sh.len;
    U.fix(F.list);
    return { frames: F.list, def: U.def('Lagrange–Gauss', ['repeat:', '  if |b₂| < |b₁|, swap them', '  m = round(⟨b₁, b₂⟩ / ⟨b₁, b₁⟩); b₂ ← b₂ − m·b₁', 'until m = 0: then b₁ is a shortest vector', 'LLL does the same in n dimensions, with a slack δ']) };
  }
  S.topic({
    id: 'pq-gauss', family: 'p14-lattice', order: 30, title: 'Lagrange–Gauss reduction',
    blurb: 'Subtract the nearest whole multiple of the shorter vector from the longer, swap, repeat. A long skewed basis turns into a short square one, and its first vector is a shortest vector of the lattice.',
    inputs: [{ id: 'basis', kind: 'list', label: 'Basis b₁, b₂ (x, y, x, y)', def: ['9', '12', '4', '8'], check: basisCheck }],
    presets: [
      { label: 'Lattice A, bad basis', values: { basis: ['9', '12', '4', '8'] } },
      { label: 'Lattice B, bad basis', values: { basis: ['12', '18', '6', '11'] } },
      { label: 'Lattice C, bad basis', values: { basis: ['15', '17', '5', '7'] } },
      { label: 'Thin lattice E', values: { basis: ['5', '22', '2', '13'] } },
      { label: 'Already reduced', values: { basis: ['6', '1', '1', '5'] } },
    ],
    counters: [{ id: 'reductions', label: 'reductions' }, { id: 'swaps', label: 'swaps' }],
    run: gauss,
    predict: [{ at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.stage === 'reduce' && i <= 2, pick: 'option', options: (fr, i) => { const m = fr[i + 1].meta.m; return [...new Set([m - 1, m, m + 1, -m])].sort((a, b) => a - b).map(String); }, ask: 'The next step subtracts m·b₁ from b₂, with m the rounded ratio in the panel. What is m?', answer: (fr, i) => String(fr[i + 1].meta.m), explain: (fr, i) => fr[i + 1].say, once: true }],
    quiz: [
      { q: 'Gauss reduction stops when…', options: ['b₁ = b₂', 'the rounded ratio ⟨b₁, b₂⟩/⟨b₁, b₁⟩ is 0, with |b₁| ≤ |b₂|', 'after two steps', 'the determinant is 1'], answer: 1, why: 'Then no whole multiple of b₁ shortens b₂.' },
      { q: 'Each reduction step changes the area of the cell by…', options: ['a factor m', 'nothing', 'a factor 2', 'it halves it'], answer: 1, why: 'b₂ − m·b₁ is a shear with determinant 1.' },
      { q: 'At the end, b₁ is…', options: ['the longest vector', 'a shortest non-zero lattice vector', 'perpendicular to b₂', 'the original b₁'], answer: 1, why: 'In two dimensions the reduced basis gives the shortest vector exactly.' },
      { q: 'What does LLL do in many dimensions?', options: ['Finds the exact shortest vector quickly', 'Finds a fairly short vector, within an exponential factor', 'Breaks ML-KEM', 'Nothing'], answer: 1, why: 'LLL is polynomial but approximate; in hundreds of dimensions its factor is far too large to break ML-KEM.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Babai rounding
  // ---------------------------------------------------------------------------------------------------------------
  function babai(inp) {
    const g = L().goodBad(+inp.seed), G = g.good, B = g.bad, t = [+inp.tx, +inp.ty];
    const rg = L().babai(G, t), rb = L().babai(B, t), best = L().closest(G, t, 8);
    const P = plane([G[0], G[1], t, rb.v, rg.v, [rb.v[0] + (B[0][0] + B[1][0]) / 2, rb.v[1] + (B[0][1] + B[1][1]) / 2], [rb.v[0] - (B[0][0] + B[1][0]) / 2, rb.v[1] - (B[0][1] + B[1][1]) / 2]]);
    const F = new S.Frames();
    const dots = P.dots(G);
    const head = U.t('bb:h', 30, 34, 'Babai\'s rounding: the closest lattice point to t', 'strong', 'start', 16);
    const cen = (Bm, v) => [v[0] - (Bm[0][0] + Bm[1][0]) / 2, v[1] - (Bm[0][1] + Bm[1][1]) / 2];
    // t is a ring, so a lattice point under it shows through; its name goes where no point of the picture is
    const marks = [rg.v, rb.v, best.v];
    const tl = [[12, -10, 'start'], [-12, -10, 'end'], [12, 20, 'start'], [-12, 20, 'end']].find(([dx, dy]) => !marks.some((m) => Math.abs(P.X(m[0]) - (P.X(t[0]) + dx + (dx > 0 ? 5 : -5))) < 14 && Math.abs(P.Y(m[1]) - (P.Y(t[1]) + dy - 5)) < 14)) || [12, -10, 'start'];
    const tgt = () => [P.pt('bb:t', t, 'ring', 9), U.t('bb:tn', P.X(t[0]) + tl[0], P.Y(t[1]) + tl[1], 't', 'ptname third', tl[2], 15)];
    const reach = (key, v, cls) => ({ key, kind: 'path', d: `M${P.X(t[0])},${P.Y(t[1])} L${P.X(v[0])},${P.Y(v[1])}`, cls: 'dline ' + cls, audit: 'ignore' });
    const rowsFor = (name, r, cls) => [['basis', name, cls], ['t in this basis', vec(r.real)], ['rounded', vec(r.coeffs)], ['lattice point', vec(r.v), cls], ['distance to t', f2(r.dist), cls], ['closest possible', f2(best.dist), 'good']];
    F.add({ items: [head, ...P.items, ...dots, ...tgt(), ...U.readout('bb:r', 618, 66, 288, 'the problem', [['t', vec(t), 'hot'], ['closest distance', '?']])], say: `A target t = ${vec(t)} that is not a lattice point. Which lattice point is closest? This is the closest vector problem; decryption in lattice schemes is an instance of it, with a secret good basis.`, facts: { t }, meta: { stage: 'start' } });
    F.add({ items: [head, ...P.items, ...dots, P.cell('bb:gc', G, cen(G, rg.v), ''), ...P.vec('bb:g1', [0, 0], G[0], 'act', 'g₁', G[1]), ...P.vec('bb:g2', [0, 0], G[1], 'act', 'g₂', G[0]), reach('bb:lg', rg.v, 'good'), ...tgt(), P.pt('bb:vg', rg.v, 'good', 6), ...U.readout('bb:r', 618, 66, 288, 'good basis', rowsFor('good', rg, 'act'))], hl: { d: [0, 1] }, say: `With the good basis, t = ${comb(rg.real[0], 'g₁', rg.real[1], 'g₂')}. Round each coefficient: ${vec(rg.coeffs)}, the lattice point ${vec(rg.v)} at distance ${f2(rg.dist)}. The shaded cell, centred on that point, is every target that rounds to it: nearly a square, so it holds the points nearest to its centre.${Math.abs(rg.dist - best.dist) < 1e-9 ? ' This is the closest point.' : ` The closest point is at ${f2(best.dist)}: rounding came near.`}`, facts: { x: rg.real, c: rg.coeffs, v: rg.v, d: rg.dist, best: best.dist }, meta: { stage: 'good', hit: Math.abs(rg.dist - best.dist) < 1e-9 } });
    const hit = Math.abs(rb.dist - best.dist) < 1e-9;
    F.add({ items: [head, ...P.items, ...dots, P.cell('bb:bc', B, cen(B, rb.v), 'key'), ...P.vec('bb:b1', [0, 0], B[0], 'hot', 'b₁', B[1]), ...P.vec('bb:b2', [0, 0], B[1], 'hot', 'b₂', B[0]), reach('bb:lb', rb.v, hit ? 'good' : 'bad'), ...tgt(), P.pt('bb:vb', rb.v, hit ? 'good' : 'bad', 6), ...(hit ? [] : [P.pt('bb:vg', rg.v, 'good', 5)]), ...U.readout('bb:r', 618, 66, 288, 'bad basis', rowsFor('bad', rb, 'hot'))], hl: { d: [2] }, say: `With the bad basis, t = ${comb(rb.real[0], 'b₁', rb.real[1], 'b₂')}, rounded to ${vec(rb.coeffs)}: the lattice point ${vec(rb.v)}, at distance ${f2(rb.dist)}. ${hit ? 'This time it still lands on the closest point, by luck.' : `That is ${f2(rb.dist / best.dist)} times too far.`} The region that rounds to a point is now a long thin sliver, reaching far from its centre.`, facts: { x: rb.real, c: rb.coeffs, v: rb.v, d: rb.dist, ratio: rb.dist / best.dist }, meta: { stage: 'bad', hit } });
    F.add({ items: [head, ...P.items, ...dots, P.cell('bb:bc', B, cen(B, rb.v), 'key'), P.cell('bb:gc', G, cen(G, rg.v), ''), reach('bb:lb', rb.v, hit ? 'good' : 'bad'), reach('bb:lg', rg.v, 'good'), ...tgt(), P.pt('bb:vb', rb.v, hit ? 'good' : 'bad', 6), ...(hit ? [] : [P.pt('bb:vg', rg.v, 'good', 6)]), ...U.readout('bb:r', 618, 66, 288, 'both', [['good basis gives', vec(rg.v), 'good'], ['at distance', f2(rg.dist)], ['bad basis gives', vec(rb.v), hit ? 'good' : 'bad'], ['at distance', f2(rb.dist)], ['Hadamard, good', fx(g.hGood, 3)], ['Hadamard, bad', fx(g.hBad, 3)]])], hl: { d: [3] }, say: `Same lattice, same target, same method: the good basis (Hadamard ratio ${fx(g.hGood, 3)}) answers within ${f2(rg.dist)}, the bad one (${fx(g.hBad, 3)}) within ${f2(rb.dist)}. Whoever holds the good basis decodes; whoever holds only the public bad one does not. In two dimensions the attacker can reduce the bad basis first; in hundreds, no one knows how.`, facts: { dg: rg.dist, db: rb.dist, hg: g.hGood, hb: g.hBad }, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Babai\'s rounding', ['write t = x₁·b₁ + x₂·b₂ with real xᵢ', 'round: cᵢ = round(xᵢ)', 'answer v = c₁·b₁ + c₂·b₂', 't − v lies in the cell centred on v', 'good basis: a squat cell, so v is close; bad: a sliver']) };
  }
  S.topic({
    id: 'pq-babai', family: 'p14-lattice', order: 40, title: 'Babai\'s rounding, good basis and bad',
    blurb: 'Write the target in the basis and round each coefficient. With a good basis the answer is the closest lattice point or near it; with a bad basis of the same lattice it can be far away.',
    inputs: [
      { id: 'seed', kind: 'choice', label: 'Lattice', def: '13', options: [['13', 'A'], ['6', 'B'], ['23', 'C'], ['24', 'E, very thin'], ['12', 'F, long']].map(([v, l]) => ({ value: v, label: l })) },
      { id: 'tx', kind: 'number', label: 't, x', def: 7, min: -30, max: 30 },
      { id: 'ty', kind: 'number', label: 't, y', def: 3, min: -30, max: 30 },
    ],
    presets: [
      { label: 'Lattice A, t = (7, 3)', values: { seed: '13', tx: 7, ty: 3 } },
      { label: 'Lattice C, t = (−4, 9)', values: { seed: '23', tx: -4, ty: 9 } },
      { label: 'Thin lattice E, t = (3, 8)', values: { seed: '24', tx: 3, ty: 8 } },
      { label: 'Long lattice F, t = (13, 2)', values: { seed: '12', tx: 13, ty: 2 } },
    ],
    run: babai,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'good', pick: 'option', options: ['yes', 'no'], ask: 'Now the same rounding with the bad basis. Will it land on the closest point?', answer: (fr, i) => (fr[i + 1].meta.hit ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'Babai\'s rounding finds…', options: ['always the closest point', 'the lattice point whose basis cell, centred on it, contains t', 'the shortest vector', 'a random point'], answer: 1, why: 't − v has coordinates in [−½, ½] in the basis.' },
      { q: 'Why does a bad basis give a worse answer?', options: ['Its cell is a long thin sliver, so t can be far from the centre of its cell', 'It has fewer points', 'Rounding is slower', 'It does not'], answer: 0, why: 'The worst error is half the cell\'s diagonal.' },
      { q: 'In a lattice cryptosystem, the good basis plays the part of…', options: ['the public key', 'the private key', 'the message', 'the noise'], answer: 1, why: 'Only its holder can solve the closest vector problem easily.' },
      { q: 'Could the attacker reduce the bad basis first?', options: ['Yes in 2 dimensions; not well enough in hundreds', 'Never', 'Always', 'Only with a quantum computer'], answer: 0, why: 'Reduction in high dimensions only finds vectors within a large factor of the shortest.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
