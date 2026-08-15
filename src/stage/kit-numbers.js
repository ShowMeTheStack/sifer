// Number theory on the stage: the modular clock (n positions on a ring, a hand, the arc it turned through), a
// number line with ticks and coloured integers, rings of residues joined by chords or hops, and a panel of
// equation lines. Part 2 draws its clocks, cycles, cosets and fields from these.
//   S.Kit.nt.at(n, k, cx, cy, R) -> {x, y}                      position k of n round a ring (0 at the top, clockwise)
//   S.Kit.nt.clock({prefix, cx, cy, R, n, r, cls(k), text(k), hand, handCls, ring}) -> {items, pos(k)}
//   S.Kit.nt.arc({key, cx, cy, r, a0, a1, cls, head}) -> items  an arc between two angles (degrees, 0 at the top,
//                                                               clockwise), with an arrowhead at a1
//   S.Kit.nt.hop({key, from: {x, y}, to: {x, y}, cx, cy, bow, cls, gap}) -> items   a curved arrow between two
//                                                               positions, bowed towards (bow > 0) or away from the centre
//   S.Kit.nt.line({prefix, x, y, from, to, step, cls(k), text(k), sub(k), w, h}) -> {items, xOf(k)}
//   S.Kit.nt.eqs({prefix, x, y, lines: [[text, cls]], size, gap}) -> items
(function (S) {
  'use strict';
  const K = (S.Kit = S.Kit || {});
  const NT = (K.nt = {});
  const r2 = (v) => Math.round(v * 100) / 100;
  const rad = (deg) => ((deg - 90) * Math.PI) / 180;
  const pt = (cx, cy, r, deg) => ({ x: r2(cx + r * Math.cos(rad(deg))), y: r2(cy + r * Math.sin(rad(deg))) });

  NT.at = (n, k, cx, cy, R) => pt(cx, cy, R, (360 * k) / n);
  NT.angle = (n, k) => (360 * k) / n;

  NT.clock = function (o) {
    const P = o.prefix || 'ck', n = o.n, R = o.R, cx = o.cx, cy = o.cy, items = [];
    // the boxes of two neighbours must stay apart too (a circle is drawn in a square box): r ≤ 0.35 of their distance
    const r = o.r || Math.max(10, Math.min(22, 0.7 * R * Math.sin(Math.PI / n) - 0.5));
    if (o.ring !== false) items.push({ key: P + ':ring', kind: 'path', d: `M${cx},${r2(cy - R)} A${R},${R} 0 1 1 ${cx},${r2(cy + R)} A${R},${R} 0 1 1 ${cx},${r2(cy - R)}`, cls: 'nt-ring', audit: 'ignore', layer: 'back' });
    const pos = (k) => NT.at(n, k, cx, cy, R);
    if (o.hand !== undefined && o.hand !== null) {
      const tip = pt(cx, cy, R - r - 8, NT.angle(n, o.hand));
      items.push({ key: P + ':hand', kind: 'line', x1: cx, y1: cy, x2: tip.x, y2: tip.y, cls: 'nt-hand ' + (o.handCls || ''), audit: 'ignore', layer: 'lines' });
      items.push({ key: P + ':hub', kind: 'dot', x: cx, y: cy, r: 6, cls: 'nt-hub' });
    }
    for (let k = 0; k < n; k++) {
      const p = pos(k);
      const it = { key: P + ':' + k, kind: 'state', x: p.x, y: p.y, r, text: o.text ? o.text(k) : String(k), cls: 'ntp ' + (o.cls ? o.cls(k) || '' : '') };
      if (o.size) it.size = o.size;
      else if (r < 15) it.size = 12;
      items.push(it);
    }
    return { items, pos, r };
  };

  /** an arc from angle a0 to a1 (degrees, clockwise when a1 > a0), radius r, with a head at a1 */
  NT.arc = function (o) {
    const { cx, cy, r } = o;
    let a0 = o.a0, a1 = o.a1;
    const span = Math.abs(a1 - a0);
    if (span < 0.5) return [];
    const cw = a1 > a0 ? 1 : 0;
    const segs = [];
    // an arc longer than a half turn is drawn in two pieces, so the large-arc flag never guesses
    const mid = span > 180 ? (a0 + a1) / 2 : null;
    const p0 = pt(cx, cy, r, a0), p1 = pt(cx, cy, r, a1);
    let d = `M${p0.x},${p0.y}`;
    if (mid !== null) { const pm = pt(cx, cy, r, mid); d += ` A${r},${r} 0 0 ${cw} ${pm.x},${pm.y}`; }
    d += ` A${r},${r} 0 0 ${cw} ${p1.x},${p1.y}`;
    segs.push({ key: o.key, kind: 'path', d, cls: 'nt-arc ' + (o.cls || ''), layer: o.layer || 'lines', audit: o.audit });
    if (o.head !== false) {
      // the head points along the tangent at a1, in the direction of travel
      const t = rad(a1), dir = cw ? 1 : -1;
      const tx = -Math.sin(t) * dir, ty = Math.cos(t) * dir, nx = Math.cos(t), ny = Math.sin(t), L = 11, W = 6;
      const bx = p1.x - tx * L, by = p1.y - ty * L;
      segs.push({ key: o.key + ':h', kind: 'path', d: `M${r2(p1.x + tx * 2)},${r2(p1.y + ty * 2)} L${r2(bx + nx * W)},${r2(by + ny * W)} L${r2(bx - nx * W)},${r2(by - ny * W)} Z`, cls: 'nt-head ' + (o.cls || ''), layer: o.layer || 'lines' });
    }
    return segs;
  };

  /** a curved arrow between two points, its middle pulled towards the centre (bow > 0) or pushed out (bow < 0) */
  NT.hop = function (o) {
    const a = o.from, b = o.to, gap = o.gap === undefined ? 16 : o.gap;
    const dx = b.x - a.x, dy = b.y - a.y, L = Math.hypot(dx, dy) || 1;
    const ux = dx / L, uy = dy / L;
    const A = { x: a.x + ux * gap, y: a.y + uy * gap }, Bp = { x: b.x - ux * (gap + 1), y: b.y - uy * (gap + 1) };
    const mx = (A.x + Bp.x) / 2, my = (A.y + Bp.y) / 2;
    let cx = mx, cy = my;
    if (o.cx !== undefined) {
      const vx = o.cx - mx, vy = o.cy - my, vl = Math.hypot(vx, vy) || 1;
      const bow = o.bow === undefined ? 0.25 : o.bow;
      cx = mx + (vx / vl) * L * bow; cy = my + (vy / vl) * L * bow;
    }
    const items = [{ key: o.key, kind: 'path', d: `M${r2(A.x)},${r2(A.y)} Q${r2(cx)},${r2(cy)} ${r2(Bp.x)},${r2(Bp.y)}`, cls: 'nt-arc ' + (o.cls || ''), layer: o.layer || 'lines', audit: o.audit }];
    if (o.head !== false) {
      const tx0 = Bp.x - cx, ty0 = Bp.y - cy, tl = Math.hypot(tx0, ty0) || 1, tx = tx0 / tl, ty = ty0 / tl, nx = -ty, ny = tx, Lh = 10, W = 5.5;
      const bx = Bp.x - tx * Lh, by = Bp.y - ty * Lh;
      items.push({ key: o.key + ':h', kind: 'path', d: `M${r2(Bp.x + tx)},${r2(Bp.y + ty)} L${r2(bx + nx * W)},${r2(by + ny * W)} L${r2(bx - nx * W)},${r2(by - ny * W)} Z`, cls: 'nt-head ' + (o.cls || ''), layer: o.layer || 'lines' });
    }
    return items;
  };

  /** integers from..to on a line, one cell each */
  NT.line = function (o) {
    const P = o.prefix || 'nl', step = o.step || 40, w = o.w || step - 6, h = o.h || 32, items = [];
    const xOf = (k) => o.x + (k - o.from) * step;
    items.push({ key: P + ':axis', kind: 'line', x1: r2(xOf(o.from) - 14), y1: o.y + h / 2, x2: r2(xOf(o.to) + w + 14), y2: o.y + h / 2, cls: 'nt-axis', audit: 'ignore', layer: 'back' });
    for (let k = o.from; k <= o.to; k++) {
      const it = { key: P + ':' + k, kind: 'cell', x: r2(xOf(k)), y: o.y, w, h, rx: 6, text: o.text ? o.text(k) : String(k).replace('-', '−'), cls: 'mono ntc ' + (o.cls ? o.cls(k) || '' : '') };
      if (o.size) it.size = o.size;
      if (o.sub) it.sub = o.sub(k);
      items.push(it);
    }
    return { items, xOf, w, h };
  };

  /** lines of equations, one under the other */
  NT.eqs = function (o) {
    const P = o.prefix || 'eq', gap = o.gap || Math.round((o.size || 16) * 1.75);
    return (o.lines || []).filter(Boolean).map(([t, cls], k) => ({ key: P + ':' + k, kind: 'text', x: o.x, y: o.y + k * gap, text: t, cls: 'eq ' + (cls || ''), size: o.size || 16 }));
  };
})(globalThis.Sifer = globalThis.Sifer || {});
