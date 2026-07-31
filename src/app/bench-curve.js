// The curve explorer (#bench/curve): y² = x³ + ax + b over the reals, where a click on the curve places P, a second
// places Q, and the chord (or the tangent, to double) finds the third point and its mirror P + Q; and over GF(p)
// (bench-curve2.js), a cloud of points where two clicks add, k·P is built by double-and-add or the Montgomery ladder,
// and the count sits inside Hasse's bound. S.CurveKit draws the plots both share.
(function (S) {
  'use strict';
  const { h } = S.UI;
  const MB = () => S.MathBench, U = () => S.BenchUI;
  const NS = 'http://www.w3.org/2000/svg';
  const sv = (tag, attrs, text) => { const e = document.createElementNS(NS, tag); for (const k in attrs || {}) if (attrs[k] !== undefined && attrs[k] !== null) e.setAttribute(k, attrs[k]); if (text !== undefined) e.textContent = text; return e; };
  const TOOLS = [['real', 'Over the reals'], ['field', 'Over GF(p)']];
  const DEF = {
    tool: 'real',
    real: { a: -2, b: 2, mode: 'add', P: -1.6, Ps: -1, Q: 0.4, Qs: 1 },
    field: { toy: 'gf101', p: '97', a: '2', b: '20', P: null, Q: null, k: '13', alg: 'ltr', step: -1 },
  };
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const CT = (S.CurveTools = {});
  const CK = (S.CurveKit = { sv });

  S.Bench.tab('curve', {
    title: 'Curves', icon: 'curve', order: 40,
    blurb: 'Elliptic curves over the reals and over GF(p): click points and watch the group law.',
    open(host, saved, ctx) {
      const st = clone(DEF);
      for (const k of Object.keys(DEF)) { if (typeof DEF[k] === 'object') Object.assign(st[k], (saved || {})[k] || {}); else if (saved && saved[k] !== undefined) st[k] = saved[k]; }
      if (!S.EC && !S.ECC) { host.appendChild(U().missing('The elliptic-curve engine')); return { state: () => st }; }
      let inst = null;
      const draw = () => {
        host.innerHTML = '';
        const fr = MB().frame(host, { id: 'cv', title: 'Curve explorer', blurb: 'An elliptic curve is a group: any two points add to a third. Over the reals the sum is drawn with a ruler; over GF(p) the same formulas act on a cloud of points.', tools: TOOLS, tool: st.tool, ctx, onTool: (t) => { st.tool = t; ctx.save(); draw(); } });
        inst = CT[st.tool](fr.left, fr.right, st[st.tool], () => ctx.save()) || {};
      };
      draw();
      return { state: () => st, redraw() { if (inst && inst.redraw) inst.redraw(); }, get view() { return inst; } };
    },
  });

  /**
   * a plot: an SVG with a frame, a light grid, axes and tick labels outside the frame (so no curve passes through
   * them). o = {W, H, xr: [a, b], yr: [a, b], step: {x, y}, axes: true}
   */
  CK.plot = function (o) {
    const W = o.W || 640, H = o.H || 520, L = 50, R = 14, T = 14, B = 34;
    const pw = W - L - R, ph = H - T - B;
    const [x0, x1] = o.xr, [y0, y1] = o.yr;
    const X = (u) => L + ((u - x0) / (x1 - x0)) * pw, Y = (v) => T + ph - ((v - y0) / (y1 - y0)) * ph;
    const svg = sv('svg', { viewBox: `0 0 ${W} ${H}`, class: 'cv-svg', role: 'img', 'aria-label': o.aria || 'a plot' });
    const clipId = 'cvclip' + Math.random().toString(36).slice(2, 8);
    const defs = sv('defs'), cp = sv('clipPath', { id: clipId });
    cp.appendChild(sv('rect', { x: L, y: T, width: pw, height: ph }));
    defs.appendChild(cp); svg.appendChild(defs);
    const back = sv('g', { 'data-audit': 'ignore' });
    let g = '';
    const sx = o.step.x, sy = o.step.y;
    for (let u = Math.ceil(x0 / sx) * sx; u <= x1 + 1e-9; u += sx) g += `M${X(u).toFixed(1)},${T} V${T + ph} `;
    for (let v = Math.ceil(y0 / sy) * sy; v <= y1 + 1e-9; v += sy) g += `M${L},${Y(v).toFixed(1)} H${L + pw} `;
    back.appendChild(sv('path', { d: g, class: 'cv-grid' }));
    if (o.axes !== false) back.appendChild(sv('path', { d: `M${L},${Y(0).toFixed(1)} H${L + pw} M${X(0).toFixed(1)},${T} V${T + ph}`, class: 'cv-axis' }));
    back.appendChild(sv('rect', { x: L, y: T, width: pw, height: ph, class: 'cv-frame' }));
    svg.appendChild(back);
    const ticks = sv('g', { class: 'cv-ticks' });
    const fmt = (v) => String(+v.toFixed(2)).replace('-', '−');
    for (let u = Math.ceil(x0 / sx) * sx; u <= x1 + 1e-9; u += sx) ticks.appendChild(sv('text', { x: X(u).toFixed(1), y: T + ph + 20, 'text-anchor': 'middle', class: 'cv-tick' }, fmt(u)));
    for (let v = Math.ceil(y0 / sy) * sy; v <= y1 + 1e-9; v += sy) ticks.appendChild(sv('text', { x: L - 8, y: (Y(v) + 4).toFixed(1), 'text-anchor': 'end', class: 'cv-tick' }, fmt(v)));
    svg.appendChild(ticks);
    const lines = sv('g', { 'clip-path': `url(#${clipId})` }), dots = sv('g'), labels = sv('g');
    svg.append(lines, dots, labels);
    /** the plot point under a pointer event */
    const at = (ev) => { const m = svg.getScreenCTM(); if (!m) return null; const p = svg.createSVGPoint(); p.x = ev.clientX; p.y = ev.clientY; const q = p.matrixTransform(m.inverse()); return { sx: q.x, sy: q.y, x: x0 + ((q.x - L) / pw) * (x1 - x0), y: y0 + ((T + ph - q.y) / ph) * (y1 - y0), inside: q.x >= L && q.x <= L + pw && q.y >= T && q.y <= T + ph }; };
    /** where a plot point is on the screen (client pixels), for tests and tours */
    const screen = (u, v) => { const m = svg.getScreenCTM(), p = svg.createSVGPoint(); p.x = X(u); p.y = Y(v); const q = p.matrixTransform(m); return [q.x, q.y]; };
    return { svg, X, Y, screen, lines, dots, labels, at, box: { L, T, pw, ph, W, H }, inside: (u, v) => u >= x0 && u <= x1 && v >= y0 && v <= y1 };
  };

  /**
   * labels placed clear of everything: obstacles are sample points (in SVG units) of the curves and lines, the dots,
   * and the labels already placed. Each label tries eight places round its point and takes the freest.
   */
  CK.placer = function (pl) {
    const pts = [], boxes = [];
    const { L, T, pw, ph } = pl.box;
    return {
      avoid(list) { for (const p of list) pts.push(p); },
      avoidBox(b) { boxes.push(b); },
      place(px, py, text, cls) {
        const w = text.length * 8.6 + 6, hh = 18;
        const cands = [[12, -12, 'start'], [12, 18, 'start'], [-12, -12, 'end'], [-12, 18, 'end'], [0, -16, 'middle'], [0, 26, 'middle'], [16, 4, 'start'], [-16, 4, 'end'], [22, -24, 'start'], [-22, -24, 'end'], [22, 32, 'start'], [-22, 32, 'end']];
        let best = null;
        for (const [dx, dy, anchor] of cands) {
          const x = px + dx, y = py + dy;
          const bx = anchor === 'start' ? x - 2 : anchor === 'end' ? x - w + 2 : x - w / 2, by = y - 14;
          const b = { x: bx, y: by, w, h: hh };
          let cost = 0;
          if (b.x < L + 2 || b.y < T + 2 || b.x + b.w > L + pw - 2 || b.y + b.h > T + ph - 2) cost += 1000;
          for (const p of pts) if (p[0] > b.x - 3 && p[0] < b.x + b.w + 3 && p[1] > b.y - 3 && p[1] < b.y + b.h + 3) cost += 10;
          for (const o of boxes) if (b.x < o.x + o.w + 2 && o.x < b.x + b.w + 2 && b.y < o.y + o.h + 2 && o.y < b.y + b.h + 2) cost += 50;
          if (!best || cost < best.cost) best = { cost, x, y, anchor, b };
          if (cost === 0) break;
        }
        boxes.push(best.b);
        const t = sv('text', { x: best.x.toFixed(1), y: best.y.toFixed(1), 'text-anchor': best.anchor, class: 'cv-lab' + (cls ? ' ' + cls : '') }, text);
        pl.labels.appendChild(t);
        return t;
      },
    };
  };
  /** sample points of a path in SVG units, for the placer */
  CK.samples = (list) => list;
  CK.dot = (pl, x, y, cls, r) => { const c = sv('circle', { cx: x.toFixed(1), cy: y.toFixed(1), r: r || 6, class: 'cv-pt ' + cls, 'data-audit': 'point' }); pl.dots.appendChild(c); return c; };
  /** the plot's width in its own units: the box it is shown in (so its text keeps its size), from 340 to 640 */
  CK.width = (box) => Math.max(340, Math.min(640, Math.round((box && box.clientWidth) || 640) - 2));
  /** redraw when the width of the box changes */
  CK.onResize = (box, draw) => { let w = CK.width(box); const f = S.UI.debounce(() => { if (!box.isConnected) { removeEventListener('resize', f); return; } const w2 = CK.width(box); if (w2 !== w) { w = w2; draw(); } }, 150); addEventListener('resize', f); };
  CK.f2 = (v) => (Math.abs(v) < 0.005 ? '0.00' : v.toFixed(2)).replace('-', '−');

  // ---- over the reals -----------------------------------------------------------------------------------------------
  const XR = [-4, 4], YR = [-7, 7];
  CT.real = function (left, right, o, save) {
    const plotBox = h('div.b-stage.cv-stage', { id: 'cvRealStage' });
    const info = h('div.b-out', { id: 'cvRealInfo' });
    const hint = h('p.cv-hint', { id: 'cvHint' });
    right.append(MB().result('y² = x³ + ax + b', null, plotBox, hint, h('div.cv-legend', h('span', h('i.p'), 'P'), h('span', h('i.q'), 'Q'), h('span', h('i.t'), 'the third point, −(P + Q)'), h('span', h('i.r'), 'P + Q, its mirror'))), info);
    let clicks = o.mode === 'double' ? 1 : 2, last = null;
    const curve = () => S.EC.real(+o.a, +o.b);
    const pointAt = (x, s) => { const C = curve(), ys = C.ys(x); if (!ys.length) return null; return { x, y: s >= 0 ? Math.max(...ys) : Math.min(...ys) }; };
    const draw = () => {
      plotBox.innerHTML = ''; info.innerHTML = '';
      const C = curve(), disc = -16 * (4 * o.a ** 3 + 27 * o.b ** 2);
      const W = CK.width(plotBox);
      const pl = (last = CK.plot({ W, H: Math.round(W * 0.8), xr: XR, yr: YR, step: { x: 1, y: 1 }, aria: 'the curve y² = x³ + ' + o.a + 'x + ' + o.b }));
      // the curve, branch by branch, sampled finely in x near its roots
      const N = 1400, samp = [];
      let up = [], down = [];
      const flush = () => {
        if (up.length > 1) {
          // an egg (both ends are roots) is a closed ring; the arm that runs off the window is drawn bottom → root → top
          const egg = up[up.length - 1][0] < XR[1] - 1e-6;
          const pts = egg ? up.concat(down.slice().reverse()) : down.slice().reverse().concat(up);
          pl.lines.appendChild(sv('path', { d: 'M' + pts.map((p) => pl.X(p[0]).toFixed(1) + ',' + pl.Y(p[1]).toFixed(1)).join(' L'), class: 'cv-curve', 'data-audit': 'edge-x' }));
        }
        up = []; down = [];
      };
      const rhs = (x) => x * x * x + o.a * x + o.b;
      for (let i = 0; i <= N; i++) {
        const x = XR[0] + ((XR[1] - XR[0]) * i) / N;
        const r = rhs(x);
        if (r >= 0) {
          if (!up.length && i > 0) { let a = x - (XR[1] - XR[0]) / N, b = x; for (let k = 0; k < 40; k++) { const m = (a + b) / 2; if (rhs(m) >= 0) b = m; else a = m; } up.push([b, 0]); down.push([b, 0]); }
          const y = Math.sqrt(r);
          up.push([x, y]); down.push([x, -y]);
          if (i < N && rhs(x + (XR[1] - XR[0]) / N) < 0) { let a = x, b = x + (XR[1] - XR[0]) / N; for (let k = 0; k < 40; k++) { const m = (a + b) / 2; if (rhs(m) >= 0) a = m; else b = m; } up.push([a, 0]); down.push([a, 0]); flush(); }
        } else flush();
      }
      flush();
      for (let i = 0; i <= 400; i++) { const x = XR[0] + ((XR[1] - XR[0]) * i) / 400, r = rhs(x); if (r >= 0) { const y = Math.sqrt(r); if (y <= YR[1]) { samp.push([pl.X(x), pl.Y(y)], [pl.X(x), pl.Y(-y)]); } } }
      const place = CK.placer(pl);
      place.avoid(samp);
      // the axes too: a label lying across one is hard to read
      for (let k = 0; k <= 160; k++) { place.avoid([[pl.X(XR[0] + ((XR[1] - XR[0]) * k) / 160), pl.Y(0)], [pl.X(0), pl.Y(YR[0] + ((YR[1] - YR[0]) * k) / 160)]]); }
      const P = pointAt(o.P, o.Ps), Q = o.mode === 'double' ? P : pointAt(o.Q, o.Qs);
      const facts = [];
      if (Math.abs(disc) < 1e-9) facts.push(h('div.berr', 'The discriminant −16(4a³ + 27b²) is 0: the curve has a cusp or a node, and its points do not form a group.'));
      let res = null;
      if (P && Q && clicks >= (o.mode === 'double' ? 1 : 2)) {
        const same = o.mode === 'double' || (Math.abs(P.x - Q.x) < 1e-9 && Math.abs(P.y - Q.y) < 1e-9);
        const vertical = same ? Math.abs(P.y) < 1e-9 : Math.abs(P.x - Q.x) < 1e-9;
        if (vertical) {
          pl.lines.appendChild(sv('path', { d: `M${pl.X(P.x).toFixed(1)},${pl.Y(YR[0])} V${pl.Y(YR[1])}`, class: 'cv-line', 'data-audit': 'edge-x' }));
          for (let v = YR[0]; v <= YR[1]; v += 0.1) place.avoid([[pl.X(P.x), pl.Y(v)]]);
          facts.push(MB().facts(['P + Q', 'O, the point at infinity: the ' + (same ? 'tangent' : 'line') + ' is vertical and meets the curve nowhere else']));
        } else {
          res = C.add(P, Q);
          const lam = res.lambda, yAt = (x) => P.y + lam * (x - P.x);
          pl.lines.appendChild(sv('path', { d: `M${pl.X(XR[0]).toFixed(1)},${pl.Y(yAt(XR[0])).toFixed(1)} L${pl.X(XR[1]).toFixed(1)},${pl.Y(yAt(XR[1])).toFixed(1)}`, class: 'cv-line', 'data-audit': 'edge-x' }));
          for (let k = 0; k <= 300; k++) { const x = XR[0] + ((XR[1] - XR[0]) * k) / 300, y = yAt(x); if (y >= YR[0] && y <= YR[1]) place.avoid([[pl.X(x), pl.Y(y)]]); }
          const T3 = res.third, R = res.R;
          if (pl.inside(T3.x, T3.y) || pl.inside(R.x, R.y)) {
            pl.lines.appendChild(sv('path', { d: `M${pl.X(T3.x).toFixed(1)},${pl.Y(T3.y).toFixed(1)} V${pl.Y(R.y).toFixed(1)}`, class: 'cv-mirror', 'data-audit': 'edge-x' }));
            for (let k = 0; k <= 60; k++) place.avoid([[pl.X(T3.x), pl.Y(T3.y + ((R.y - T3.y) * k) / 60)]]);
          }
          facts.push(MB().facts(['λ (slope)', CK.f2(lam)], ['third point', '(' + CK.f2(T3.x) + ', ' + CK.f2(T3.y) + ')'], [same ? '2P' : 'P + Q', '(' + CK.f2(R.x) + ', ' + CK.f2(R.y) + ')']), U().trace(res.trace));
        }
      }
      const marks = [];
      const mark = (pt, cls, name) => { if (!pt || !pl.inside(pt.x, pt.y)) return; const sx = pl.X(pt.x), sy = pl.Y(pt.y); const near = marks.some((m) => Math.hypot(m[0] - sx, m[1] - sy) < 13); const d = CK.dot(pl, sx, sy, cls); if (near) d.setAttribute('data-audit', 'overlap-ok'); marks.push([sx, sy]); place.avoidBox({ x: sx - 7, y: sy - 7, w: 14, h: 14 }); return name; };
      const named = [];
      if (P) named.push([mark(P, 'p', o.mode === 'double' ? 'P' : 'P'), P]);
      if (Q && o.mode !== 'double' && clicks >= 2) named.push([mark(Q, 'q', 'Q'), Q]);
      if (res) { named.push([mark(res.third, 'third', o.mode === 'double' ? '−2P' : '−(P+Q)'), res.third]); named.push([mark(res.R, 'r', o.mode === 'double' ? '2P' : 'P+Q'), res.R]); }
      for (const [name, pt] of named) if (name && pl.inside(pt.x, pt.y)) place.place(pl.X(pt.x), pl.Y(pt.y), name, name.includes('+') || name === '2P' ? 'r' : '');
      if (res && (!pl.inside(res.R.x, res.R.y) || !pl.inside(res.third.x, res.third.y))) facts.unshift(h('p.b-note', 'The ' + (pl.inside(res.R.x, res.R.y) ? 'third point' : 'sum') + ' lies outside the window drawn; its coordinates are below.'));
      plotBox.appendChild(pl.svg);
      hint.textContent = o.mode === 'double' ? 'Click the curve to place P; the tangent there gives 2P.' : clicks >= 2 ? 'Click the curve again to start over with a new P.' : 'Now click the curve to place Q.';
      info.append(MB().result('The group law', 'Draw the line through P and Q; it meets the curve in exactly one more point. Its mirror image in the x-axis is P + Q.', MB().facts(['curve', 'y² = x³ ' + (o.a < 0 ? '− ' + -o.a : '+ ' + o.a) + 'x ' + (o.b < 0 ? '− ' + -o.b : '+ ' + o.b)], ['discriminant', CK.f2(disc) + (Math.abs(disc) < 1e-9 ? ' (singular)' : '')]), ...facts));
      pl.svg.addEventListener('click', (ev) => {
        const q = pl.at(ev);
        if (!q || !q.inside) return;
        // snap: the nearest point of the curve on screen
        let best = null;
        for (let i = 0; i <= 1600; i++) {
          const x = XR[0] + ((XR[1] - XR[0]) * i) / 1600, r = rhs(x);
          if (r < 0) continue;
          for (const s of [1, -1]) { const y = s * Math.sqrt(r), d = Math.hypot(pl.X(x) - q.sx, pl.Y(y) - q.sy); if (!best || d < best.d) best = { d, x, s }; }
        }
        if (!best || best.d > 40) return;
        // where the curve is steep the nearest point is found by the scan; elsewhere the clicked x, to the nearest 0.05
        let x = Math.round(best.x * 100) / 100;
        const xc = Math.round(q.x * 20) / 20;
        if (rhs(xc) >= 0) { const yc = best.s * Math.sqrt(rhs(xc)); if (Math.hypot(pl.X(xc) - q.sx, pl.Y(yc) - q.sy) <= best.d + 3) x = xc; }
        if (rhs(x) < 0) x = best.x;
        if (o.mode === 'double' || clicks >= 2) { o.P = x; o.Ps = best.s; clicks = 1; } else { o.Q = x; o.Qs = best.s; clicks = 2; }
        save(); draw();
      });
    };
    // the inputs: the two coefficients, and what to do with the points
    const slider = (k, label) => {
      const r = h('input', { type: 'range', min: '-5', max: '5', step: '0.1', value: String(o[k]), id: 'cv' + k.toUpperCase(), 'aria-label': label });
      const n = h('input', { type: 'number', min: '-5', max: '5', step: '0.1', value: String(o[k]), 'aria-label': label + ' (exact)' });
      const set = (v) => { if (!Number.isFinite(v)) return; o[k] = Math.max(-5, Math.min(5, Math.round(v * 10) / 10)); r.value = String(o[k]); n.value = String(o[k]); save(); draw(); };
      r.addEventListener('input', () => set(+r.value)); n.addEventListener('change', () => set(+n.value));
      return h('div.cv-slider', h('span', k), r, n);
    };
    left.appendChild(MB().result('The curve', 'Move a and b; points you placed slide along with the curve.', h('div.cv-sliders', slider('a', 'a'), slider('b', 'b')),
      U().seg('cvMode', [['add', 'Add P + Q'], ['double', 'Double P']], o.mode, (v) => { o.mode = v; clicks = v === 'double' ? 1 : 2; save(); draw(); }),
      MB().examples([['two branches', { a: -2, b: 2 }], ['an egg and an arm', { a: -4, b: 1 }], ['one branch', { a: 1, b: 1 }], ['singular (cusp)', { a: 0, b: 0 }]], (v) => { Object.assign(o, v); save(); left.querySelectorAll('.cv-slider').forEach((s, i) => { const k = i ? 'b' : 'a'; s.querySelectorAll('input').forEach((x) => { x.value = String(o[k]); }); }); draw(); })));
    draw();
    CK.onResize(plotBox, () => draw());
    return { redraw: draw, screen: (x, y) => last.screen(x, y), click: (x, s) => { if (o.mode === 'double' || clicks >= 2) { o.P = x; o.Ps = s; clicks = 1; } else { o.Q = x; o.Qs = s; clicks = 2; } draw(); } };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
