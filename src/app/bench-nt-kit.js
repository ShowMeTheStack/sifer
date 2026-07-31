// The frame the mathematical benches share (number theory, public key, curves): a head with the bench's name and a
// Share button, a row of tools, inputs on the left and results on the right; big integers read from decimal or hex
// with a sentence for every mistake; tables that fill row by row under a small stepper; and a ring of powers.
//   S.MathBench.frame(host, {title, blurb, tools: [[id, label]], tool, onTool(id), ctx}) -> {left, right, tool}
//   S.MathBench.big(text, label, {min, max, positive}) -> BigInt (throws a sentence)
//   S.MathBench.table(heads, rows, {hl, id, cls}) -> a scrolling table; rows are arrays of cells (text or nodes)
//   S.MathBench.stepper(n, show(k), {label}) -> a bar revealing rows 1..k (k = n at first)
//   S.MathBench.ring(values, {label(i), hl}) -> an SVG ring of the values in order, an arrow from each to the next
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const MB = (S.MathBench = {});
  const NS = 'http://www.w3.org/2000/svg';
  const sv = (tag, attrs, text) => { const e = document.createElementNS(NS, tag); for (const k in attrs || {}) if (attrs[k] !== undefined && attrs[k] !== null) e.setAttribute(k, attrs[k]); if (text !== undefined) e.textContent = text; return e; };
  MB.sv = sv;

  MB.frame = function (host, o) {
    const U = S.BenchUI;
    const share = h('button.btn.small', { type: 'button', id: 'benchShare', title: 'Copy a link to this bench with these inputs' }, icon('link'), 'Share');
    share.addEventListener('click', () => o.ctx && o.ctx.share());
    host.appendChild(h('div.bench-head', h('div', h('h1', o.title), h('p', o.blurb)), h('div.bench-acts', share)));
    const bar = U.seg(o.id + '-tool', o.tools, o.tool, (v) => o.onTool(v));
    bar.classList.add('mb-tools');
    host.appendChild(h('div.mb-toolbar', bar));
    S.UI.scrollRow(bar);
    const left = h('div.mb-left'), right = h('div.b-out.mb-right', { id: o.id + 'Out', 'aria-live': 'polite' });
    host.appendChild(h('div.bench-grid.mb-grid', left, right));
    return { left, right };
  };

  /** a whole number from decimal (spaces, commas and underscores allowed), or hex with 0x */
  MB.big = function (text, label, o) {
    o = o || {};
    const t = String(text === undefined || text === null ? '' : text).trim().replace(/[\s,_]/g, '');
    if (!t) throw new Error(label + ': type a whole number.');
    let v;
    if (/^-?0x[0-9a-f]+$/i.test(t)) v = t[0] === '-' ? -BigInt(t.slice(1)) : BigInt(t);
    else if (/^-?\d+$/.test(t)) v = BigInt(t);
    else throw new Error(label + ': "' + text.trim().slice(0, 24) + '" is not a whole number (write it in decimal, or in hex as 0x…).');
    if (o.positive && v <= 0n) throw new Error(label + ' must be at least 1.');
    if (o.min !== undefined && v < BigInt(o.min)) throw new Error(label + ' must be at least ' + o.min + '.');
    if (o.max !== undefined && v > BigInt(o.max)) throw new Error(label + ' must be at most ' + o.max + (o.why ? ' ' + o.why : '') + '.');
    return v;
  };
  /** a number for a sentence or a cell: long ones folded */
  MB.n = (v) => { const s = String(v); return s.length > 40 ? S.BenchUI.big(typeof v === 'bigint' ? v : BigInt(s)) : s; };

  MB.table = function (heads, rows, o) {
    o = o || {};
    const t = h('table.b-table' + (o.cls ? '.' + o.cls : ''), { id: o.id || null },
      h('thead', h('tr', ...heads.map((x) => h('th', x)))),
      h('tbody', ...rows.map((r, i) => h('tr' + (o.hl === i ? '.hl' : '') + (o.act && o.act(i) ? '.act' : ''), { dataset: { row: String(i) } }, ...r.map((c, k) => h('td' + (o.mono === false || (o.text && o.text.includes(k)) ? '' : '.mono'), c instanceof Node ? c : String(c)))))));
    const box = h('div.b-scroll.mb-table.fit-table', t);
    // too wide for its card (a phone): smaller type, then wrapping, then a visible sideways scroll
    requestAnimationFrame(() => { if (box.isConnected && S.UI.fitTables) S.UI.fitTables(box.parentElement); });
    return box;
  };

  MB.stepper = function (n, show, o) {
    o = o || {};
    let k = n;
    const pos = h('span.mb-pos');
    const b = (ic, label, fn) => { const x = h('button.icon-btn.mb-sb', { type: 'button', title: label, 'aria-label': label }, icon(ic)); x.addEventListener('click', fn); return x; };
    const first = b('first', 'Only the first row', () => go(1)), prev = b('prev', 'One row fewer', () => go(k - 1));
    const next = b('next', 'The next row', () => go(k + 1)), all = b('fit', 'Every row', () => go(n));
    const go = (j) => { k = Math.max(1, Math.min(n, j)); pos.textContent = (o.label || 'row') + ' ' + k + ' of ' + n; first.disabled = prev.disabled = k <= 1; next.disabled = all.disabled = k >= n; show(k); };
    const bar = h('div.mb-stepper', { id: o.id || null }, first, prev, next, all, pos);
    bar.go = go;
    requestAnimationFrame(() => go(k));
    go(k);
    return bar;
  };

  /**
   * a ring: values placed round a circle in their order, each with its index outside, and an arc from each to the
   * next (the last back to the first when o.closed). Sized to its count; meant for up to about 40 values.
   */
  MB.ring = function (values, o) {
    o = o || {};
    // on a narrow screen a long cycle reads better as a line that wraps
    if (values.length > 12 && typeof innerWidth !== 'undefined' && innerWidth < 640) {
      return h('div.mb-cycle', { role: 'img', 'aria-label': o.aria || 'a cycle of values' }, ...values.map((v, i) => h('span.mb-cyc' + (o.hl && o.hl(i) ? '.hl' : ''), o.label ? h('small', o.label(i)) : null, h('b', String(v)))), h('span.mb-cyc-back', '↺ back to the start'));
    }
    const n = values.length, longest = Math.max(...values.map((v) => String(v).length));
    const rNode = Math.max(16, 7 + longest * 4.4);
    const R = Math.max(90, (n * (2 * rNode + 16)) / (2 * Math.PI));
    const pad = 52, W = 2 * (R + rNode + pad);
    const svg = sv('svg', { viewBox: `0 0 ${W} ${W}`, class: 'mb-ring', role: 'img', 'aria-label': o.aria || 'a cycle of values', style: 'max-width:' + Math.round(W) + 'px' });
    const c = W / 2, ang = (i) => -Math.PI / 2 + (2 * Math.PI * i) / n;
    const at = (i, r) => [c + r * Math.cos(ang(i)), c + r * Math.sin(ang(i))];
    if (o.centre) {
      svg.appendChild(sv('text', { x: c, y: c - 4, 'text-anchor': 'middle', class: 'mb-ring-c' }, o.centre[0]));
      if (o.centre[1]) svg.appendChild(sv('text', { x: c, y: c + 16, 'text-anchor': 'middle', class: 'mb-ring-c2' }, o.centre[1]));
    }
    const gap = Math.asin(Math.min(0.95, (rNode + 4) / R));
    for (let i = 0; i < n; i++) {
      if (i === n - 1 && !o.closed) break;
      if (n < 2) break;
      const a0 = ang(i) + gap, a1 = ang((i + 1) % n) - gap + (i === n - 1 ? 2 * Math.PI : 0);
      if (a1 <= a0) continue;
      const p0 = [c + R * Math.cos(a0), c + R * Math.sin(a0)], p1 = [c + R * Math.cos(a1), c + R * Math.sin(a1)];
      svg.appendChild(sv('path', { d: `M${p0[0].toFixed(1)},${p0[1].toFixed(1)} A${R},${R} 0 0 1 ${p1[0].toFixed(1)},${p1[1].toFixed(1)}`, class: 'mb-arc', 'marker-end': 'url(#mbArrow)' }));
    }
    const defs = sv('defs');
    const m = sv('marker', { id: 'mbArrow', viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '7', markerHeight: '7', orient: 'auto-start-reverse' });
    m.appendChild(sv('path', { d: 'M0,0 L10,5 L0,10 z', class: 'mb-arrowhead' }));
    defs.appendChild(m); svg.appendChild(defs);
    values.forEach((v, i) => {
      const [x, y] = at(i, R);
      const g = sv('g', { class: 'mb-node' + (o.hl && o.hl(i) ? ' hl' : ''), 'data-audit': 'node' });
      g.appendChild(sv('circle', { cx: x.toFixed(1), cy: y.toFixed(1), r: rNode }));
      g.appendChild(sv('text', { x: x.toFixed(1), y: (y + 5).toFixed(1), 'text-anchor': 'middle', class: 'mb-node-t' }, String(v)));
      svg.appendChild(g);
      if (o.label) { const t = o.label(i), w = t.length * 7.4, a = ang(i); const [lx, ly] = at(i, R + rNode + 9 + Math.abs(Math.cos(a)) * w / 2 + Math.abs(Math.sin(a)) * 8); svg.appendChild(sv('text', { x: lx.toFixed(1), y: (ly + 4).toFixed(1), 'text-anchor': 'middle', class: 'mb-node-l' }, t)); }
    });
    return h('div.b-stage.mb-ring-box', svg);
  };
  /**
   * run fn, and show what it throws as a sentence in box. A sentence (a message ending in a full stop) is the
   * student's input refused; anything else is a fault, and goes to the console too.
   */
  MB.guard = function (box, fn) {
    try { return fn(); } catch (e) {
      box.appendChild(h('div.berr', { role: 'alert' }, icon('warn'), h('span', String(e && e.message || e))));
      if (!(e && e.name === 'Error' && /[.?]$/.test(e.message || ''))) console.error(e);
      return null;
    }
  };
  /** a short line of facts under a result */
  MB.facts = (...pairs) => h('div.mb-facts', ...pairs.filter(Boolean).map(([k, v]) => S.BenchUI.kv(k, v)));
  /** a tool's result card */
  MB.result = (title, sub, ...kids) => S.BenchUI.card(title, sub, ...kids);
  /** a button row under the inputs */
  MB.go = (label, fn, id) => { const b = h('button.btn.primary', { type: 'button', id: id || null }, icon('run'), label); b.addEventListener('click', fn); return b; };
  /** example chips: [[label, values]] */
  MB.examples = (list, pick) => {
    const box = h('div.presets.mb-ex', { role: 'group', 'aria-label': 'Examples' }, h('span.muted.mb-ex-l', 'Try'));
    for (const [label, v] of list) { const c = h('button.chip', { type: 'button' }, label); c.addEventListener('click', () => pick(v)); box.appendChild(c); }
    return box;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
