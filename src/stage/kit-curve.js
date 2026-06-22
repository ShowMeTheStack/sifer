// Curves on the stage: axes with ticks, an elliptic curve over the reals drawn branch by branch, lines clipped to
// the plot (a chord, a tangent, a mirror), points with labels placed clear of the curve, and the points of a curve
// over GF(p) as a cloud, with a line of slope λ drawn as it wraps round modulo p.
//   S.Kit.curve.plot({prefix, x, y, w, h, xr: [a, b], yr: [a, b], ticks: {x: step, y: step}, grid, labels})
//     -> {items, X(u), Y(v), inside(u, v), box}
//   S.Kit.curve.real(plot, curve, key, cls) -> path items of y² = x³ + ax + b inside the plot
//   S.Kit.curve.line(plot, key, P, slope, cls) / segment(plot, key, P, Q, cls) -> a path item clipped to the plot
//   S.Kit.curve.point(plot, key, P, name, cls, dir) -> a dot and its label (dir: 'ne' | 'nw' | 'se' | 'sw' | 'e' | 'w')
//   S.Kit.curve.cloud(plot, key, points, cls) -> dots;  S.Kit.curve.modLine(plot, key, P, lambda, p, cls) -> paths
(function (S) {
  'use strict';
  const K = (S.Kit = S.Kit || {});
  const C = (K.curve = {});
  const r2 = (v) => Math.round(v * 100) / 100;

  C.plot = function (o) {
    const P = o.prefix || 'pl', [x0, x1] = o.xr, [y0, y1] = o.yr;
    const X = (u) => r2(o.x + ((u - x0) / (x1 - x0)) * o.w), Y = (v) => r2(o.y + o.h - ((v - y0) / (y1 - y0)) * o.h);
    const items = [];
    const tx = (o.ticks && o.ticks.x) || 1, ty = (o.ticks && o.ticks.y) || 1;
    const ax = o.axisAt || { x: Math.max(x0, Math.min(x1, 0)), y: Math.max(y0, Math.min(y1, 0)) };
    let g = '';
    if (o.grid !== false) {
      for (let u = Math.ceil(x0 / tx) * tx; u <= x1 + 1e-9; u += tx) g += `M${X(u)},${Y(y0)} V${Y(y1)} `;
      for (let v = Math.ceil(y0 / ty) * ty; v <= y1 + 1e-9; v += ty) g += `M${X(x0)},${Y(v)} H${X(x1)} `;
      items.push({ key: P + ':grid', kind: 'path', d: g, cls: 'grid', audit: 'ignore', layer: 'back' });
    }
    items.push({ key: P + ':ax', kind: 'path', d: `M${X(x0)},${Y(ax.y)} H${X(x1)} M${X(ax.x)},${Y(y0)} V${Y(y1)}`, cls: 'axis', audit: 'ignore', layer: 'back' });
    // tick labels: below the x axis and left of the y axis, skipping the origin and the frame's own corners
    const lab = o.labels || {};
    for (let u = Math.ceil(x0 / tx) * tx; u <= x1 + 1e-9; u += tx) {
      if (Math.abs(u - ax.x) < 1e-9 && !lab.origin) continue;
      items.push({ key: P + ':t:x' + u, kind: 'text', x: X(u), y: (lab.xAt === 'bottom' ? Y(y0) : Y(ax.y)) + 16, text: String(+u.toFixed(2)).replace('-', '−'), anchor: 'middle', size: o.tickSize || 12, cls: 'tick' });
    }
    for (let v = Math.ceil(y0 / ty) * ty; v <= y1 + 1e-9; v += ty) {
      if (Math.abs(v - ax.y) < 1e-9 && !lab.origin) continue;
      items.push({ key: P + ':t:y' + v, kind: 'text', x: (lab.yAt === 'left' ? X(x0) : X(ax.x)) - 7, y: Y(v) + 4, text: String(+v.toFixed(2)).replace('-', '−'), anchor: 'end', size: o.tickSize || 12, cls: 'tick' });
    }
    const inside = (u, v) => u >= x0 && u <= x1 && v >= y0 && v <= y1;
    return { items, X, Y, inside, o, box: { x: o.x, y: o.y, w: o.w, h: o.h } };
  };

  /** y² = x³ + ax + b over the reals, as closed or open branches clipped to the plot */
  C.real = function (pl, curve, key, cls) {
    const [x0, x1] = pl.o.xr, [y0, y1] = pl.o.yr, N = 900;
    // the x where the right-hand side is ≥ 0, in runs; each run is a branch (a closed egg or the open arm)
    const runs = [];
    let cur = null;
    for (let i = 0; i <= N; i++) {
      const u = x0 + ((x1 - x0) * i) / N, ok = curve.rhs(u) >= 0;
      if (ok && !cur) { cur = [u, u]; runs.push(cur); } else if (ok) cur[1] = u; else cur = null;
    }
    const root = (a, b) => { for (let k = 0; k < 60; k++) { const m = (a + b) / 2; if ((curve.rhs(a) >= 0) === (curve.rhs(m) >= 0)) a = m; else b = m; } return (a + b) / 2; };
    const items = [];
    runs.forEach((r, k) => {
      let a = r[0], b = r[1];
      if (a > x0) a = root(a - (x1 - x0) / N, a);
      if (b < x1) b = root(b + (x1 - x0) / N, b);
      const top = [], bot = [];
      const M = 400;
      for (let i = 0; i <= M; i++) {
        // points crowd near the ends, where the curve turns vertical
        const t = 0.5 - 0.5 * Math.cos((Math.PI * i) / M), u = a + (b - a) * t, y = Math.sqrt(Math.max(0, curve.rhs(u)));
        if (y <= y1) top.push([pl.X(u), pl.Y(y)]); else if (top.length) top.push(null);
        if (-y >= y0) bot.push([pl.X(u), pl.Y(-y)]); else if (bot.length) bot.push(null);
      }
      // a closed egg: up along the top, back along the bottom
      const closed = a > x0 && b < x1;
      const pts = closed ? top.concat(bot.reverse()) : null;
      const toD = (list) => { let d = '', pen = false; for (const p of list) { if (!p) { pen = false; continue; } d += (pen ? 'L' : 'M') + p[0] + ',' + p[1] + ' '; pen = true; } return d; };
      const d = closed ? toD(pts) + 'Z' : toD(top.slice().reverse().concat(bot.slice(1)));
      items.push({ key: key + k, kind: 'path', d, cls: 'curve ' + (cls || ''), pathAudit: 'edge-x', samples: top.concat(bot).filter(Boolean) });
    });
    return items;
  };

  /** the part of the line through P with this slope (or vertical) inside the plot */
  C.clip = function (pl, P, slope) {
    const [x0, x1] = pl.o.xr, [y0, y1] = pl.o.yr;
    if (!isFinite(slope)) return [[P.x, y0], [P.x, y1]];
    const f = (u) => P.y + slope * (u - P.x), g = (v) => P.x + (v - P.y) / slope;
    const cand = [[x0, f(x0)], [x1, f(x1)]];
    if (slope) cand.push([g(y0), y0], [g(y1), y1]);
    const ok = cand.filter(([u, v]) => u >= x0 - 1e-9 && u <= x1 + 1e-9 && v >= y0 - 1e-9 && v <= y1 + 1e-9).sort((p, q) => p[0] - q[0]);
    return ok.length >= 2 ? [ok[0], ok[ok.length - 1]] : null;
  };
  C.line = function (pl, key, P, slope, cls) {
    const s = C.clip(pl, P, slope);
    if (!s) return [];
    return [{ key, kind: 'path', d: `M${pl.X(s[0][0])},${pl.Y(s[0][1])} L${pl.X(s[1][0])},${pl.Y(s[1][1])}`, cls: cls || 'chord', pathAudit: 'edge-x', samples: C.sampleSeg([pl.X(s[0][0]), pl.Y(s[0][1])], [pl.X(s[1][0]), pl.Y(s[1][1])]) }];
  };
  C.segment = (pl, key, P, Q, cls) => [{ key, kind: 'path', d: `M${pl.X(P.x)},${pl.Y(P.y)} L${pl.X(Q.x)},${pl.Y(Q.y)}`, cls: cls || 'mirror', pathAudit: 'edge-x', samples: C.sampleSeg([pl.X(P.x), pl.Y(P.y)], [pl.X(Q.x), pl.Y(Q.y)]) }];
  /** points every few pixels along a segment, for keeping labels off it */
  C.sampleSeg = (a, b) => { const n = Math.max(2, Math.ceil(Math.hypot(b[0] - a[0], b[1] - a[1]) / 5)), out = []; for (let i = 0; i <= n; i++) out.push([a[0] + ((b[0] - a[0]) * i) / n, a[1] + ((b[1] - a[1]) * i) / n]); return out; };

  /** a point and its name, the name set off in the direction asked so it stays clear of the curve */
  C.point = function (pl, key, P, name, cls, dir, size) {
    const x = pl.X(P.x), y = pl.Y(P.y), d = dir || 'ne', off = 11, fs = size || 15;
    const dx = /e/.test(d) ? off : /w/.test(d) ? -off : 0, dy = /n/.test(d) ? -off + 2 : /s/.test(d) ? off + fs * 0.7 : fs * 0.35;
    const items = [{ key: key, kind: 'dot', x, y, r: 5.5, cls: 'pt ' + (cls || ''), point: true }];
    if (name) items.push({ key: key + ':n', kind: 'text', x: x + dx, y: y + dy, text: name, anchor: dx > 0 ? 'start' : dx < 0 ? 'end' : 'middle', size: fs, cls: 'ptname ' + (cls || '') });
    return items;
  };
  C.cloud = (pl, key, points, cls, r) => points.map((P) => ({ key: key + ':' + P.x + ',' + P.y, kind: 'dot', x: pl.X(Number(P.x)), y: pl.Y(Number(P.y)), r: r || 3.6, cls: 'cloud ' + (cls || ''), point: true }));
  /**
   * Marked points with their names placed where they collide with nothing: marks [{key, P, name, cls, prefer}],
   * drawn (a list of items already on the plot: dots, and paths with samples), size. Each name tries eight places
   * round its point, the preferred one first, and takes the first clear of every dot, sampled line and earlier name.
   */
  C.marks = function (pl, marks, drawn, size) {
    const fs = size || 15, items = [], boxes = [], dots = [], pts = [];
    for (const it of drawn || []) { if (it.kind === 'dot') dots.push([it.x, it.y, (it.r || 3.5) + 2]); if (it.samples) pts.push(...it.samples); }
    for (const m of marks) dots.push([pl.X(m.P.x), pl.Y(m.P.y), 7.5]);
    for (const m of marks) items.push({ key: m.key, kind: 'dot', x: pl.X(m.P.x), y: pl.Y(m.P.y), r: 5.5, cls: 'pt ' + (m.cls || ''), point: true });
    const dirs = ['ne', 'nw', 'se', 'sw', 'e', 'w', 'n', 's'];
    for (const m of marks) {
      if (!m.name) continue;
      const x = pl.X(m.P.x), y = pl.Y(m.P.y), w = S.geom.textWidth(m.name, fs, { bold: true }) + 6, h = fs + 4;
      const order = [m.prefer || 'ne'].concat(dirs.filter((d) => d !== m.prefer));
      let best = null, bestHit = Infinity;
      for (const d of order) {
        for (const off of [11, 17, 24]) {
          const dx = /e/.test(d) ? off : /w/.test(d) ? -off : 0, dy = /n/.test(d) ? -off + 2 : /s/.test(d) ? off + fs * 0.7 : fs * 0.35;
          const anchor = dx > 0 ? 'start' : dx < 0 ? 'end' : 'middle';
          const bx = { x: anchor === 'start' ? x + dx - 3 : anchor === 'end' ? x + dx - w + 3 : x - w / 2, y: y + dy - fs * 0.85, w, h };
          const inPlot = bx.x >= pl.o.x && bx.x + bx.w <= pl.o.x + pl.o.w && bx.y >= pl.o.y && bx.y + bx.h <= pl.o.y + pl.o.h;
          let hit = inPlot ? 0 : 50;
          for (const [cx, cy, r] of dots) if (cx > bx.x - r && cx < bx.x + bx.w + r && cy > bx.y - r && cy < bx.y + bx.h + r) hit += 10;
          for (const [px, py] of pts) if (px > bx.x - 1 && px < bx.x + bx.w + 1 && py > bx.y - 1 && py < bx.y + bx.h + 1) hit += 1;
          for (const b of boxes) if (bx.x < b.x + b.w && bx.x + bx.w > b.x && bx.y < b.y + b.h && bx.y + bx.h > b.y) hit += 20;
          if (hit < bestHit) { bestHit = hit; best = { dx, dy, anchor, bx }; }
          if (!hit) break;
        }
        if (bestHit === 0) break;
      }
      boxes.push(best.bx);
      items.push({ key: m.key + ':n', kind: 'text', x: x + best.dx, y: y + best.dy, text: m.name, anchor: best.anchor, size: fs, cls: 'ptname ' + (m.cls || '') });
    }
    return items;
  };
  /** the line y = λ(x − x₁) + y₁ modulo p, drawn lap by lap as it leaves the top and comes back at the bottom */
  C.modLine = function (pl, key, P, lambda, p, cls) {
    const items = [], x0 = 0, x1 = p - 1, f = (u) => lambda * (u - P.x) + P.y;
    // over x in [0, p−1] the line climbs (or falls) through several multiples of p
    const lo = Math.floor(Math.min(f(x0), f(x1)) / p), hi = Math.floor(Math.max(f(x0), f(x1)) / p);
    for (let k = lo; k <= hi; k++) {
      // the stretch of x where k·p ≤ f(x) < (k+1)·p
      let a = (k * p - P.y) / lambda + P.x, b = ((k + 1) * p - P.y) / lambda + P.x;
      if (a > b) [a, b] = [b, a];
      a = Math.max(a, x0); b = Math.min(b, x1);
      if (b - a < 1e-6) continue;
      items.push({ key: key + k, kind: 'path', d: `M${pl.X(a)},${pl.Y(f(a) - k * p)} L${pl.X(b)},${pl.Y(f(b) - k * p)}`, cls: cls || 'modline', pathAudit: 'edge-x', samples: C.sampleSeg([pl.X(a), pl.Y(f(a) - k * p)], [pl.X(b), pl.Y(f(b) - k * p)]) });
    }
    return items;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
