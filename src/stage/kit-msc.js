// Message-sequence charts on the stage: a head and a lifeline for each party, messages as arrows between lifelines
// (a name above the arrow, the content below it), checks as pills on a lifeline, notes as bands across the chart,
// and under each lifeline a panel of what that party knows, with what it has just learned lit.
// Nothing is clobbered: every row has its own band, a lifeline breaks wherever an arrow passes over it or a label
// lies across it, and a label too wide for its span is kept inside the chart. When the rows do not fit, the chart
// shows the latest ones (and the earlier ones glide up out of view).
//   S.Kit.msc.chart({prefix, x, w, y, parties: [{id, label, role, sub}], rows, cur, maxH, bottom}) -> {items, xOf(id), bottom}
//     rows: {type: 'msg', from, to, label, term, cls ('bad' | 'dashed' …)} | {type: 'check', party, text, ok}
//           | {type: 'note', text}; rows after cur are not drawn yet, rows before it are drawn as past
//   S.Kit.msc.knowledge({prefix, x, y, w, h, title, chips: [{text, cls}], role}) -> items
(function (S) {
  'use strict';
  const K = (S.Kit = S.Kit || {});
  const M = (K.msc = {});
  const r2 = (v) => Math.round(v * 100) / 100;
  const tw = (s, size, mono) => S.geom.textWidth(String(s), size, { mono: !!mono, bold: !mono });
  const ROW = { msg: 54, check: 36, note: 36 };

  M.chart = function (o) {
    const P = o.prefix || 'msc', parties = o.parties, n = parties.length, x0 = o.x, W = o.w, y0 = o.y;
    const lane = W / n, xOf = (id) => r2(x0 + lane * (parties.findIndex((p) => p.id === id) + 0.5));
    const headH = 40, top = y0 + headH / 2 + 14, bottom = o.bottom;
    const items = [], gaps = new Map(parties.map((p) => [p.id, []]));
    // heads
    for (const p of parties) {
      const it = { key: P + ':h:' + p.id, kind: 'state', x: xOf(p.id), y: y0, w: Math.min(lane - 16, Math.max(96, tw(p.label, 14) + 30)), h: headH, rx: 8, text: p.label, cls: 'msc-head ' + (p.role || '') };
      items.push(it);
    }
    // which rows fit: the latest ones, ending at cur
    const cur = o.cur === undefined ? o.rows.length - 1 : o.cur, room = (o.maxH || bottom - top - 8);
    let first = 0, used = 0;
    for (let i = cur; i >= 0; i--) { const h = ROW[o.rows[i].type] || 40; if (used + h > room) { first = i + 1; break; } used += h; }
    let y = top;
    const clamp = (cx, width) => Math.max(x0 + width / 2 + 2, Math.min(x0 + W - width / 2 - 2, cx));
    o.rows.forEach((r, i) => {
      const k = P + ':r' + i;
      if (i > cur || i < first) return;
      const h = ROW[r.type] || 40, past = i < cur, st = past ? 'past' : (r.cls && /bad/.test(r.cls) ? 'bad' : 'act');
      if (r.type === 'msg') {
        const xa = xOf(r.from), xb = xOf(r.to), ym = r2(y + 22), dir = xb > xa ? 1 : -1;
        const lo = Math.min(xa, xb), hi = Math.max(xa, xb);
        items.push({ key: k + ':w', kind: 'wire', pts: [[xa, ym], [r2(xb - dir * 1.5), ym]], head: true, cls: 'msc-msg ' + st + (r.dashed ? ' dashed' : '') });
        // lifelines between the two ends break under the arrow
        for (const p of parties) { const px = xOf(p.id); if (px > lo + 1 && px < hi - 1) gaps.get(p.id).push([ym - 7, ym + 7]); }
        const lab = r.label || '', term = r.term || '';
        const lw = tw(lab, 14), tw2 = tw(term, 13.5, true);
        const lc = clamp((xa + xb) / 2, lw), tc = clamp((xa + xb) / 2, tw2);
        if (lab) items.push({ key: k + ':l', kind: 'text', x: r2(lc), y: r2(ym - 8), text: lab, anchor: 'middle', cls: 'msc-lab ' + st });
        if (term) items.push({ key: k + ':t', kind: 'text', x: r2(tc), y: r2(ym + 19), text: term, anchor: 'middle', cls: 'msc-term ' + st });
        // a label wider than its span lies across lifelines: break them there too
        for (const [cx, wdt, a, b] of [[lc, lw, ym - 22, ym - 3], [tc, tw2, ym + 6, ym + 24]]) for (const p of parties) { const px = xOf(p.id); if (px > cx - wdt / 2 - 4 && px < cx + wdt / 2 + 4) gaps.get(p.id).push([a, b]); }
      } else if (r.type === 'check') {
        const text = (r.ok ? '✓ ' : '✗ ') + r.text, w = tw(text, 13) + 20, cx = clamp(xOf(r.party), w);
        items.push({ key: k + ':c', kind: 'cell', x: r2(cx - w / 2), y: r2(y + 5), w: r2(w), h: 26, rx: 13, text, cls: 'msc-check ' + (past ? 'past' : '') + (r.ok ? '' : ' bad') });
        for (const p of parties) { const px = xOf(p.id); if (px > cx - w / 2 - 2 && px < cx + w / 2 + 2) gaps.get(p.id).push([y + 3, y + 33]); }
      } else {
        const w = Math.min(W - 8, tw(r.text, 13) + 28);
        items.push({ key: k + ':n', kind: 'cell', x: r2(x0 + W / 2 - w / 2), y: r2(y + 5), w: r2(w), h: 26, rx: 4, text: r.text, cls: 'msc-note ' + (past ? 'past' : '') });
        for (const p of parties) { const px = xOf(p.id); if (px > x0 + W / 2 - w / 2 - 2 && px < x0 + W / 2 + w / 2 + 2) gaps.get(p.id).push([y + 3, y + 33]); }
      }
      y += h;
    });
    if (first > 0) items.push({ key: P + ':more', kind: 'text', x: r2(x0 + 4), y: r2(top - 2), text: '↑ ' + first + ' earlier', cls: 'ptick', size: 13 });
    // lifelines in pieces, around every gap
    for (const p of parties) {
      const px = xOf(p.id), gs = gaps.get(p.id).sort((a, b) => a[0] - b[0]);
      let from = y0 + headH / 2, seg = 0;
      for (const [a, b] of gs) {
        if (a > from + 2) items.push({ key: P + ':ll:' + p.id + ':' + seg++, kind: 'line', x1: px, y1: r2(from), x2: px, y2: r2(a), cls: 'msc-life' });
        from = Math.max(from, b);
      }
      if (bottom > from + 2) items.push({ key: P + ':ll:' + p.id + ':' + seg++, kind: 'line', x1: px, y1: r2(from), x2: px, y2: r2(bottom), cls: 'msc-life' });
    }
    return { items, xOf, lane, top, first };
  };

  /** a panel of chips (what a party knows), wrapped into rows inside {x, y, w} */
  M.knowledge = function (o) {
    const P = o.prefix, items = [{ key: P, kind: 'region', x: r2(o.x), y: r2(o.y), w: r2(o.w), h: r2(o.h), rx: 8, cls: 'panel' + (o.cls ? ' ' + o.cls : '') }];
    if (o.title) items.push({ key: P + ':t', kind: 'text', x: r2(o.x + 10), y: r2(o.y + 18), text: o.title, cls: 'ptitle', size: 13 });
    let cx = o.x + 8, cy = o.y + (o.title ? 28 : 8);
    const chH = 21, gap = 4, maxY = o.y + o.h - 6;
    let hidden = 0;
    o.chips.forEach((c, i) => {
      let text = c.text;
      while (text.length > 4 && S.geom.textWidth(text, 13, { mono: true }) + 14 > o.w - 16) text = text.slice(0, -2) + '…';
      if (text !== c.text) text = text.replace(/……$/, '…');
      const w = S.geom.textWidth(text, 13, { mono: true }) + 14;
      if (cx + w > o.x + o.w - 8) { cx = o.x + 8; cy += chH + gap; }
      if (cy + chH > maxY) { hidden++; return; }
      items.push({ key: P + ':c:' + (c.key || c.text), kind: 'cell', x: r2(cx), y: r2(cy), w: r2(w), h: chH, rx: 4, text, cls: 'msc-know ' + (c.cls || '') });
      cx += w + gap;
    });
    if (hidden) items.push({ key: P + ':more', kind: 'text', x: r2(o.x + o.w - 10), y: r2(o.y + 18), text: '+' + hidden + ' more', anchor: 'end', cls: 'ptick', size: 13 });
    return items;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
