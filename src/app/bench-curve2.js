// The curve explorer over GF(p): every point of a small curve as a cloud; two clicks add (the chord drawn as the line
// that wraps round modulo p, when it wraps only a few times), k·P is built step by step by double-and-add or by the
// Montgomery ladder, the order of P is found from the group order, and the count is set inside Hasse's bound.
(function (S) {
  'use strict';
  const { h } = S.UI;
  const MB = () => S.MathBench, U = () => S.BenchUI, CK = () => S.CurveKit;
  const fp = (P) => (P ? '(' + P.x + ', ' + P.y + ')' : 'O');
  const big = (P) => (P ? { x: BigInt(P.x), y: BigInt(P.y) } : null);
  const str = (P) => (P ? { x: String(P.x), y: String(P.y) } : null);

  S.CurveTools.field = function (left, right, o, save) {
    const plotBox = h('div.b-stage.cv-stage', { id: 'cvFieldStage' });
    const hint = h('p.cv-hint', { id: 'cvFhint' });
    const legend = h('div.cv-legend', { id: 'cvLegend' });
    const out = h('div.b-out', { id: 'cvFieldInfo' });
    right.append(MB().result('The points of the curve', null, plotBox, hint, legend), out);
    let C = null, pts = null, picking = 0, last = null;
    const curveOf = () => {
      let p, a, b;
      if (o.toy !== 'custom') { const t = S.ECC.TOYS.find((x) => x.id === o.toy) || S.ECC.TOYS[0]; p = BigInt(t.p); a = BigInt(t.a); b = BigInt(t.b); o.p = String(p); o.a = String(a); o.b = String(b); }
      else {
        p = MB().big(o.p, 'p', { min: 5, max: 1009, why: 'so that every point can be drawn' });
        if (!S.NT.isProbablePrime(p)) throw new Error('p = ' + p + ' is not prime; the next prime is ' + S.NT.nextPrime(p) + '.');
        a = S.NT.mod(MB().big(o.a, 'a'), p); b = S.NT.mod(MB().big(o.b, 'b'), p);
        if (S.NT.mod(4n * a ** 3n + 27n * b ** 2n, p) === 0n) throw new Error('4a³ + 27b² ≡ 0 (mod ' + p + '): the curve is singular, and its points do not form a group.');
      }
      return S.ECC.curve({ p, a, b });
    };
    const draw = () => {
      plotBox.innerHTML = ''; out.innerHTML = ''; legend.innerHTML = '';
      C = MB().guard(out, curveOf);
      if (!C) return;
      pts = C.points();
      const p = Number(C.p);
      const W0 = CK().width(plotBox), step = p <= 20 ? 2 : p <= 60 ? 10 : p <= 130 ? (W0 < 500 ? 25 : 20) : p <= 300 ? 50 : (W0 < 500 ? 250 : 200);
      const W = CK().width(plotBox);
      const pl = last = CK().plot({ W, H: Math.round(W * 0.86), xr: [-0.5, p - 0.5], yr: [-0.5, p - 0.5], step: { x: step, y: step }, axes: false, aria: 'the ' + pts.length + ' points of the curve over GF(' + p + ')' });
      const r = Math.max(1.5, Math.min(6, (W * 0.66) / p));
      // a first look shows something: the base point (or the first point) as P, and 3·P as Q
      if (!o.P && !o.touched && pts.length) {
        const t = S.ECC.TOYS.find((x) => x.id === o.toy), G = t && t.G ? { x: BigInt(t.G[0]), y: BigInt(t.G[1]) } : pts[Math.floor(pts.length / 3)];
        const Q3 = C.mul(3n, G);
        o.P = str(G); o.Q = Q3 ? str(Q3) : null;
      }
      const P = big(o.P), Q = big(o.Q);
      if (P && !C.on(P)) o.P = null;
      if (Q && !C.on(Q)) o.Q = null;
      // the chord, as the line y = λ(x − x1) + y1 wrapping round modulo p
      let sum = null, wraps = 0;
      if (o.P && o.Q) {
        sum = C.addT(big(o.P), big(o.Q));
        if (sum.lambda !== undefined && sum.lambda !== null) {
          let lam = Number(sum.lambda); if (lam > p / 2) lam -= p;
          if (Math.abs(lam) <= 10) {
            const x1 = Number(o.P.x), y1 = Number(o.P.y);
            let d = '';
            for (let k = -Math.abs(lam) - 1; k <= Math.abs(lam) + 1; k++) {
              // y = lam·(x − x1) + y1 − k·p, kept to 0 ≤ y ≤ p − 1 over 0 ≤ x ≤ p − 1
              const yAt = (x) => lam * (x - x1) + y1 - k * p;
              let xa = -0.5, xb = p - 0.5;
              if (lam !== 0) { const xs = [(-0.5 - y1 + k * p) / lam + x1, (p - 0.5 - y1 + k * p) / lam + x1].sort((u, v) => u - v); xa = Math.max(xa, xs[0]); xb = Math.min(xb, xs[1]); }
              else if (yAt(0) < -0.5 || yAt(0) > p - 0.5) continue;
              if (xb - xa < 0.05) continue;
              d += `M${pl.X(xa).toFixed(1)},${pl.Y(yAt(xa)).toFixed(1)} L${pl.X(xb).toFixed(1)},${pl.Y(yAt(xb)).toFixed(1)} `;
            }
            if (d) pl.lines.appendChild(CK().sv('path', { d, class: 'cv-line', 'data-audit': 'edge-x' }));
          } else wraps = Math.abs(lam);
        }
      }
      // the k·P walk
      let walk = null;
      if (o.P && o.k) {
        try {
          const k = MB().big(o.k, 'k', { min: 1, max: '1000000' });
          walk = (o.alg === 'ladder' ? S.ECC.scalar.ladder : S.ECC.scalar.ltr)(C, k, big(o.P));
        } catch (e) { walk = { error: e.message }; }
      }
      const stepIdx = walk && walk.steps ? (o.step < 0 || o.step >= walk.steps.length ? walk.steps.length - 1 : o.step) : -1;
      const runPt = walk && walk.steps && walk.steps[stepIdx] ? walk.steps[stepIdx].R : null;
      const key = (Pt) => (Pt ? Pt.x + ',' + Pt.y : '');
      const role = {};
      if (runPt) role[key(runPt)] = 'k';
      if (sum && sum.R) role[key(sum.R)] = 'r';
      if (o.Q) role[key(big(o.Q))] = 'q';
      if (o.P) role[key(big(o.P))] = 'p';
      for (const pt of pts) {
        const c = CK().sv('circle', { cx: pl.X(Number(pt.x)).toFixed(1), cy: pl.Y(Number(pt.y)).toFixed(1), r: r.toFixed(1), class: 'cv-dot' + (role[key(pt)] ? ' ' + role[key(pt)] : ''), 'data-audit': 'point' });
        pl.dots.appendChild(c);
      }
      for (const [k2, cls] of Object.entries(role)) {
        const [x, y] = k2.split(',').map(Number);
        pl.dots.appendChild(CK().sv('circle', { cx: pl.X(x).toFixed(1), cy: pl.Y(y).toFixed(1), r: (r + 4.5).toFixed(1), class: 'cv-ring ' + cls, 'data-audit': 'overlap-ok' }));
      }
      plotBox.appendChild(pl.svg);
      legend.append(o.P ? h('span', h('i.p'), 'P = ' + fp(o.P)) : null, o.Q ? h('span', h('i.q'), 'Q = ' + fp(o.Q)) : null, sum ? h('span', h('i.r'), 'P + Q = ' + fp(sum.R)) : null, runPt ? h('span', h('i.k'), 'the running point of k·P') : null);
      hint.textContent = (wraps ? 'The line through P and Q wraps round the plot ' + wraps + ' times, too often to draw clearly. ' : '') + (!o.P ? 'Click a point to choose P.' : !o.Q ? 'Click another point (or P again, to double it) to choose Q.' : 'Click a point to start again with a new P.');
      // the facts about the curve
      const count = C.count(), hasse = C.hasse(), struct = C.structure();
      const lo = Number(hasse.lo), hi = Number(hasse.hi), N = Number(count.N), mid = p + 1, span = Math.max(1, hi - lo);
      const pos = (v) => ((v - lo) / span) * 100;
      out.append(MB().result('Counting the points', 'Hasse: the number of points #E (with O) lies within 2√p of p + 1.',
        h('div.cv-hasse', h('div.cv-hasse-bar', { id: 'cvHasse' }, h('span.band', { style: { left: '0%', right: '0%' } }), h('span.mid', { style: { left: pos(mid) + '%' } }), h('span.mark', { style: { left: 'calc(' + pos(N) + '% - 1px)' }, title: '#E = ' + N })),
          h('div.cv-hasse-l', h('span', String(lo)), h('span', 'p + 1 = ' + mid), h('span', String(hi)))),
        MB().facts(['curve', 'y² = x³ + ' + C.a + 'x + ' + C.b + ' over GF(' + C.p + ')'], ['#E', N + ' (' + pts.length + ' points and O)'], ['group', struct.cyclic ? 'cyclic, Z_' + struct.N : 'Z_' + struct.n1 + ' × Z_' + struct.n2 + ' (not cyclic)']), U().trace(count.trace)));
      if (sum) out.append(MB().result('P + Q', 'The same formulas as over the reals, with division by multiplying by an inverse mod p.', MB().facts(['P + Q', fp(sum.R)]), U().trace(sum.trace)));
      if (o.P) {
        const ord = C.order(big(o.P));
        out.append(MB().result('The order of P', 'The smallest n with n·P = O; by Lagrange it divides #E = ' + N + '.', MB().facts(['ord(P)', ord.order]), U().trace(ord.trace)));
      }
      if (walk && walk.error) out.append(h('div.berr', walk.error));
      else if (walk) {
        const rows = walk.steps.map((s, i) => [s.i, s.bit, (s.ops || []).join(', ') || 'start', fp(s.R), s.R0 !== undefined ? fp(s.R0) + ' | ' + fp(s.R1) : '']);
        const tbl = MB().table(['bit', 'value', 'operations', 'running point', o.alg === 'ladder' ? 'R0 | R1' : ''], rows, { hl: stepIdx, id: 'cvWalk' });
        let quiet = true;
        const stepper = MB().stepper(walk.steps.length, (k) => { if (!quiet && o.step !== k - 1) { o.step = k - 1; save(); draw(); } }, { label: 'step', id: 'cvWalkStep' });
        stepper.go(stepIdx + 1);
        quiet = false;
        out.append(MB().result(o.k + '·P by ' + (o.alg === 'ladder' ? 'the Montgomery ladder' : 'double-and-add'), o.alg === 'ladder' ? 'One addition and one doubling for every bit, whatever its value: the same work every time, so the timing gives nothing away.' : 'Double for every bit; add P for every 1 bit.', stepper, tbl,
          MB().facts(['k·P', fp(walk.R)], ['work', walk.doubles + ' doublings and ' + walk.adds + ' additions']), U().trace(walk.trace)));
      }
      pl.svg.addEventListener('click', (ev) => {
        const q = pl.at(ev);
        if (!q) return;
        let best = null;
        for (const pt of pts) { const d = Math.hypot(pl.X(Number(pt.x)) - q.sx, pl.Y(Number(pt.y)) - q.sy); if (!best || d < best.d) best = { d, pt }; }
        if (!best || best.d > 24) return;
        pick(best.pt);
      });
    };
    const pick = (pt) => {
      if (!o.P || (o.P && o.Q)) { o.P = str(pt); o.Q = null; } else o.Q = str(pt);
      o.step = -1; o.touched = true; picking++; save(); draw();
    };
    const opts = S.ECC.TOYS.filter((t) => t.p <= 1009).map((t) => ({ value: t.id, label: 'p = ' + t.p + ', a = ' + t.a + ', b = ' + t.b })).concat([{ value: 'custom', label: 'my own curve' }]);
    const shows = h('p.b-note', { id: 'cvShows' });
    const custom = h('div.brow', ...['p', 'a', 'b'].map((k) => U().field(k, U().input('cvF' + k, o[k], (v) => { o[k] = v; save(); S.UI.debounce(draw, 250)(); }, { attrs: { inputmode: 'numeric' } }))));
    const vis = () => { custom.style.display = o.toy === 'custom' ? '' : 'none'; const t = S.ECC.TOYS.find((x) => x.id === o.toy); shows.textContent = t ? 'It shows ' + t.shows + '.' : 'Any prime p up to 1009 and coefficients a, b with 4a³ + 27b² ≢ 0.'; };
    left.appendChild(MB().result('The curve', 'Small fields, so that every point can be drawn and counted.', U().field('curve', U().select('cvToy', opts, o.toy, (v) => { o.toy = v; o.P = o.Q = null; o.touched = false; save(); vis(); draw(); })), shows, custom));
    left.appendChild(MB().result('k·P', 'Choose P on the plot, then a multiplier.', U().field('k', U().input('cvK', o.k, (v) => { o.k = v; o.step = -1; save(); S.UI.debounce(draw, 250)(); }, { attrs: { inputmode: 'numeric' } })),
      U().seg('cvAlg', [['ltr', 'Double-and-add'], ['ladder', 'Montgomery ladder']], o.alg, (v) => { o.alg = v; o.step = -1; save(); draw(); })));
    vis(); draw();
    CK().onResize(plotBox, () => draw());
    return { redraw: draw, screen: (x, y) => last.screen(x, y), pick: (x, y) => pick({ x: BigInt(x), y: BigInt(y) }), curve: () => C, points: () => pts };
  };

  // ---- what the diagram checker looks at ------------------------------------------------------------------------------
  const cvClick = (sel) => `document.querySelector('${sel}').click(); await new Promise((r) => setTimeout(r, 200));`;
  if (S.Checks) for (const [name, setup] of [['over the reals, P + Q', cvClick('#cv-tool button[data-v=real]') + cvClick('#cvMode button[data-v=add]')],
    ['over the reals, 2P', cvClick('#cvMode button[data-v=double]')], ['over the reals, an egg and an arm', cvClick('#cvMode button[data-v=add]') + cvClick('.mb-ex .chip:nth-of-type(2)')],
    ['over GF(p), P + Q and k·P', cvClick('#cv-tool button[data-v=field]')], ['over GF(p), the ladder', cvClick('#cvAlg button[data-v=ladder]')]]) {
    S.Checks.push({ group: 'bench-curve', name, hash: 'bench/curve', ready: "document.querySelector('#cvOut .bcard svg')", setup, sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
