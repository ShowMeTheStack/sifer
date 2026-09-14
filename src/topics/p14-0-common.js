// Parts 14 and 15 share these: the families, and the small drawing helpers their pictures are made of (a plot
// with axes and ticks, a data line, bars, a framed panel, a row of value cells). Every frame a topic of these
// parts adds carries `facts`: the values its narration quotes, by name, so tests/claims-p14.mjs and
// tests/claims-p15.mjs can check each one against an independent working-out.
(function (S) {
  'use strict';
  const U = (S.P14 = S.P14 || {});
  const r2 = (v) => Math.round(v * 100) / 100;
  U.r2 = r2;
  /** a number with d decimals, with a true minus sign */
  U.fx = (v, d) => { const s = Number(v).toFixed(d === undefined ? 3 : d); return /^-0(\.0*)?$/.test(s) ? s.slice(1) : s.replace('-', '−'); };
  /** an integer with a true minus sign */
  U.int = (v) => String(v).replace('-', '−');
  U.hex2 = (v) => (v & 255).toString(16).padStart(2, '0');
  U.hex = (a) => Array.from(a, U.hex2).join('');
  U.sub = (i) => String(i).split('').map((d) => '₀₁₂₃₄₅₆₇₈₉'[d]).join('');
  U.sup = (i) => String(i).split('').map((d) => '⁰¹²³⁴⁵⁶⁷⁸⁹'[d] || d).join('');
  U.plural = (n, w, ws) => n + ' ' + (n === 1 ? w : ws || w + 's');

  S.family({ id: 'p14-quantum', part: 'pq', order: 10, title: 'The quantum threat', blurb: 'Grover\'s search and Shor\'s period finding, simulated on tiny registers, and what they do to key sizes.' });
  S.family({ id: 'p14-lattice', part: 'pq', order: 20, title: 'Lattices', blurb: 'Bases good and bad, Gram–Schmidt, reduction in two dimensions and Babai\'s rounding for the closest vector.' });
  S.family({ id: 'p14-lwe', part: 'pq', order: 30, title: 'Learning with errors', blurb: 'A bit hidden under noise you can see, decrypted while the noise stays small, and lost when it does not.' });
  S.family({ id: 'p14-mlkem', part: 'pq', order: 40, title: 'ML-KEM', blurb: 'The standard lattice key encapsulation: its data flow, the NTT, compression and the noise budget, and implicit rejection.' });
  S.family({ id: 'p14-hashsig', part: 'pq', order: 50, title: 'Hash-based signatures', blurb: 'Lamport and Winternitz one-time signatures, Merkle trees, and the stateless hypertree of SLH-DSA.' });
  S.family({ id: 'p14-other', part: 'pq', order: 60, title: 'Codes and lattice signatures', blurb: 'McEliece\'s scrambled Goppa code, and the rejection sampling that keeps a lattice signature from leaking its key.' });
  S.family({ id: 'p15-power', part: 'side', order: 10, title: 'Power analysis', blurb: 'What a power trace shows, the leakage models, simple power analysis and the difference of means.' });
  S.family({ id: 'p15-cpa', part: 'side', order: 20, title: 'Correlation power analysis', blurb: 'One key byte out of many noisy traces, how many traces it takes, and masking against it.' });
  S.family({ id: 'p15-timing', part: 'side', order: 30, title: 'Timing and caches', blurb: 'Cache lines that give away table indices, a comparison that stops early, and code that takes the same time whatever the secret.' });
  S.family({ id: 'p15-faults', part: 'side', order: 40, title: 'Faults and defences', blurb: 'One glitch in RSA-CRT that factors the modulus, and a map of the defences against every channel.' });

  /**
   * A plot: a frame of axes with tick labels, inside {x, y, w, h}. o: {prefix, x, y, w, h, xr: [a, b], yr: [a, b],
   * xticks: [values], yticks: [values], fx(v), fy(v) (tick text), xlabel, ylabel, zero (a line at y = 0), grid}
   * Returns {items, X(u), Y(v), box}.
   */
  U.plot = function (o) {
    const P = o.prefix || 'pl', [x0, x1] = o.xr, [y0, y1] = o.yr;
    const X = (u) => r2(o.x + ((u - x0) / (x1 - x0)) * o.w), Y = (v) => r2(o.y + o.h - ((v - y0) / (y1 - y0)) * o.h);
    const items = [];
    const fx = o.fx || ((v) => U.int(+v.toFixed(3))), fy = o.fy || ((v) => U.int(+v.toFixed(3)));
    if (o.grid) {
      let g = '';
      for (const v of o.yticks || []) g += `M${o.x},${Y(v)} H${o.x + o.w} `;
      items.push({ key: P + ':grid', kind: 'path', d: g, cls: 'grid', audit: 'ignore', layer: 'back' });
    }
    items.push({ key: P + ':ax', kind: 'path', d: `M${o.x},${o.y} V${o.y + o.h} H${o.x + o.w}`, cls: 'axis', audit: 'ignore', layer: 'back', box: { x: o.x, y: o.y, w: o.w, h: o.h } });
    if (o.zero && y0 < 0 && y1 > 0) items.push({ key: P + ':zero', kind: 'path', d: `M${o.x},${Y(0)} H${o.x + o.w}`, cls: 'axis', audit: 'ignore', layer: 'back' });
    const ts = o.tickSize || 12;
    for (const u of o.xticks || []) items.push({ key: P + ':tx' + u, kind: 'text', x: X(u), y: o.y + o.h + ts + 5, text: fx(u), anchor: 'middle', size: ts, cls: 'tick' });
    for (const v of o.yticks || []) items.push({ key: P + ':ty' + v, kind: 'text', x: o.x - 7, y: Y(v) + ts * 0.35, text: fy(v), anchor: 'end', size: ts, cls: 'tick' });
    if (o.xlabel) items.push({ key: P + ':xl', kind: 'text', x: o.x + o.w, y: o.y + o.h + ts + 24, text: o.xlabel, anchor: 'end', size: 13, cls: '' });
    if (o.ylabel) items.push({ key: P + ':yl', kind: 'text', x: o.x, y: o.y - 12, text: o.ylabel, anchor: 'start', size: 13, cls: '' });
    return { items, X, Y, o, box: { x: o.x, y: o.y, w: o.w, h: o.h } };
  };
  /** a data line through (xs[i], ys[i]) in a plot, clipped to its y range; audit: 'edge-x' (default) or 'ignore' */
  U.line = function (pl, key, xs, ys, cls, audit) {
    const [y0, y1] = pl.o.yr;
    let d = '', pen = false;
    for (let i = 0; i < xs.length; i++) {
      const v = Math.max(y0, Math.min(y1, ys[i]));
      d += (pen ? 'L' : 'M') + pl.X(xs[i]) + ',' + pl.Y(v) + ' ';
      pen = true;
    }
    const it = { key, kind: 'path', d, cls: 'dline ' + (cls || '') };
    if (audit === 'ignore') it.audit = 'ignore'; else it.pathAudit = audit || 'edge-x';
    return it;
  };
  /** a vertical bar from the value 0 (or base) up or down to v, as a cell */
  U.bar = function (pl, key, u, v, w, cls, base) {
    const b = base || 0, ya = pl.Y(Math.max(v, b)), yb = pl.Y(Math.min(v, b));
    return { key, kind: 'cell', x: r2(pl.X(u) - w / 2), y: ya, w: r2(w), h: Math.max(0.5, r2(yb - ya)), rx: Math.min(2, w / 4), text: '', cls: 'bar ' + (cls || '') };
  };
  /** a framed panel with a title in its top-left corner */
  U.panel = (key, x, y, w, h, title, cls) => [
    { key: key, kind: 'region', x, y, w, h, rx: 10, cls: 'panel ' + (cls || '') },
    title ? { key: key + ':t', kind: 'text', x: x + 14, y: y + 22, text: title, cls: 'title' } : null,
  ].filter(Boolean);
  /** a row of cells holding values: o {prefix, x, y, cw, ch, gap, values, cls(i, v), size, text(v)} */
  U.cells = function (o) {
    const items = [];
    o.values.forEach((v, i) => items.push({ key: o.prefix + i, kind: 'cell', x: r2(o.x + i * (o.cw + (o.gap === undefined ? 2 : o.gap))), y: o.y, w: o.cw, h: o.ch, rx: 3, text: o.text ? o.text(v, i) : String(v), size: o.size || 13, cls: 'hex ' + (o.cls ? o.cls(i, v) : '') }));
    return items;
  };
  /** free text */
  U.t = (key, x, y, text, cls, anchor, size) => { const it = { key, kind: 'text', x: r2(x), y: r2(y), text, cls: cls || '', anchor: anchor || 'start' }; if (size) it.size = size; return it; };
  /** the stage every picture of these parts is drawn on: about the shape of the topic player's stage */
  U.V = { x: 0, y: 0, w: 920, h: 660 };
  /** give every frame the same camera (the canvas, or a box given) */
  U.fix = (frames, box) => {
    for (const f of frames) {
      f.view = Object.assign({}, box || U.V);
      // an engine sentence that ends a hex value with an ellipsis needs no full stop after it
      if (f.say) f.say = f.say.replace(/…\.(?=\s|$)/g, '…');
    }
    return frames;
  };
  /** a column of label: value rows in a panel; rows [[label, value, cls]] */
  U.readout = function (prefix, x, y, w, title, rows, o) {
    o = o || {};
    const dy = o.dy || 32, items = U.panel(prefix, x, y, w, 40 + rows.length * dy, title);
    rows.forEach(([label, value, cls], i) => {
      items.push(U.t(prefix + ':l' + i, x + 14, y + 52 + i * dy, label, '', 'start', o.size || 13));
      items.push(U.t(prefix + ':v' + i, x + w - 14, y + 52 + i * dy, String(value), 'mono ' + (cls || ''), 'end', o.vsize || 15));
    });
    return items;
  };
  /** a row of colour keys: entries [[bar class, text]] laid out from (x, y) */
  U.legend = function (prefix, x, y, entries, size) {
    const items = [], fs = size || 13;
    let at = x;
    entries.forEach(([cls, text], i) => {
      items.push({ key: prefix + ':s' + i, kind: 'cell', x: at, y: y - fs * 0.8, w: 14, h: 14, rx: 3, text: '', cls: 'bar ' + cls });
      items.push(U.t(prefix + ':t' + i, at + 20, y + 2, text, 'tick', 'start', fs));
      at += 20 + S.geom.textWidth(text, fs) + 24;
    });
    return items;
  };
  /** the definition panel from math lines; lit: the lines to light */
  U.def = (title, lines) => ({ sections: [{ id: 'd', kind: 'math', title, text: lines.join('\n') }] });
})(globalThis.Sifer = globalThis.Sifer || {});
