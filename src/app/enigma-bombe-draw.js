// Pictures for the Bombe: the menu as a graph (letters joined by the crib's pairs, each pair labelled with its place in
// the crib, the edges that close loops lit, the test register ringed), laid out by many short spring runs and keeping
// the one with the fewest crossings and the most room; and the bank of drums, three to a scrambler, that turn as the
// run goes on.
//   S.BombeDraw.menu(host, menu) -> svg;   S.BombeDraw.drums(host, edges) -> {set(drums: [{drums: 'ABC'}]), spin(on)}
(function (S) {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const el = (tag, a, text) => { const e = document.createElementNS(NS, tag); for (const k in a || {}) if (a[k] !== undefined && a[k] !== null) e.setAttribute(k, a[k]); if (text !== undefined) e.textContent = text; return e; };
  const D = (S.BombeDraw = {});
  const R = 19;

  const segCross = (a, b, c, d) => {
    const o = (p, q, r) => (q.x - p.x) * (r.y - p.y) - (q.y - p.y) * (r.x - p.x);
    return o(a, b, c) * o(a, b, d) < 0 && o(c, d, a) * o(c, d, b) < 0;
  };
  const distSeg = (p, a, b) => { const dx = b.x - a.x, dy = b.y - a.y, L = dx * dx + dy * dy || 1; const t = Math.max(0, Math.min(1, ((p.x - a.x) * dx + (p.y - a.y) * dy) / L)); return Math.hypot(p.x - a.x - t * dx, p.y - a.y - t * dy); };

  /**
   * positions in pixels for one connected group of letters inside a box {x, y, w, h}: the best of many seeded spring
   * runs, scored by crossings first, then edges passing close to letters, then letters too close together
   */
  D.layout = function (letters, pairs, box) {
    const n = letters.length, idx = Object.fromEntries(letters.map((l, i) => [l, i]));
    const E = [...new Set(pairs.map(([a, b]) => Math.min(idx[a], idx[b]) + ',' + Math.max(idx[a], idx[b])))].map((s) => s.split(',').map(Number));
    if (n === 1) return { P: [{ x: box.x + box.w / 2, y: box.y + box.h / 2 }], cross: 0 };
    if (n === 2) return { P: [{ x: box.x + box.w * 0.25, y: box.y + box.h / 2 }, { x: box.x + box.w * 0.75, y: box.y + box.h / 2 }], cross: 0 };
    let rnd = 12345 + n;
    const rand = () => { rnd = (rnd * 1103515245 + 12345) & 0x7fffffff; return rnd / 0x7fffffff; };
    const k = Math.sqrt((box.w * box.h) / n) * 0.62;
    let best = null;
    for (let trial = 0; trial < 90; trial++) {
      const P = letters.map((_, i) => (trial === 0 ? { x: box.x + box.w / 2 + 0.4 * box.w * Math.cos((2 * Math.PI * i) / n), y: box.y + box.h / 2 + 0.4 * box.h * Math.sin((2 * Math.PI * i) / n) } : { x: box.x + rand() * box.w, y: box.y + rand() * box.h }));
      for (let it = 0; it < 260; it++) {
        const F = P.map(() => ({ x: 0, y: 0 })), t = (Math.max(box.w, box.h) / 12) * (1 - it / 260) + 1;
        for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) { let dx = P[i].x - P[j].x, dy = P[i].y - P[j].y; const d = Math.max(1, Math.hypot(dx, dy)); const f = (k * k) / d; dx /= d; dy /= d; F[i].x += dx * f; F[i].y += dy * f; F[j].x -= dx * f; F[j].y -= dy * f; }
        for (const [a, b] of E) { let dx = P[a].x - P[b].x, dy = P[a].y - P[b].y; const d = Math.max(1, Math.hypot(dx, dy)); const f = (d * d) / k; dx /= d; dy /= d; F[a].x -= dx * f; F[a].y -= dy * f; F[b].x += dx * f; F[b].y += dy * f; }
        for (let i = 0; i < n; i++) { const m = Math.hypot(F[i].x, F[i].y) || 1; P[i].x = Math.max(box.x, Math.min(box.x + box.w, P[i].x + (F[i].x / m) * Math.min(m, t))); P[i].y = Math.max(box.y, Math.min(box.y + box.h, P[i].y + (F[i].y / m) * Math.min(m, t))); }
      }
      // stretch to fill the box (the same scale both ways keeps the angles)
      const xs = P.map((p) => p.x), ys = P.map((p) => p.y), x0 = Math.min(...xs), y0 = Math.min(...ys), sw = Math.max(...xs) - x0 || 1, sh = Math.max(...ys) - y0 || 1;
      const sc = Math.min(box.w / sw, box.h / sh), ox = box.x + (box.w - sw * sc) / 2, oy = box.y + (box.h - sh * sc) / 2;
      const Q = P.map((p) => ({ x: ox + (p.x - x0) * sc, y: oy + (p.y - y0) * sc }));
      let cross = 0, brush = 0, crowd = 0;
      for (let i = 0; i < E.length; i++) for (let j = i + 1; j < E.length; j++) { const [a, b] = E[i], [c, d] = E[j]; if (a === c || a === d || b === c || b === d) continue; if (segCross(Q[a], Q[b], Q[c], Q[d])) cross++; }
      for (const [a, b] of E) for (let i = 0; i < n; i++) if (i !== a && i !== b && distSeg(Q[i], Q[a], Q[b]) < R * 2.2) brush++;
      for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) crowd += Math.max(0, 100 - Math.hypot(Q[i].x - Q[j].x, Q[i].y - Q[j].y)) * 8;
      for (const [a, b] of E) crowd += Math.max(0, 84 - Math.hypot(Q[a].x - Q[b].x, Q[a].y - Q[b].y)) * 6;
      const score = cross * 1000 + brush * 300 + crowd;
      if (!best || score < best.score) best = { score, P: Q, cross };
    }
    return best;
  };

  D.menu = function (host, menu) {
    const W = 760, H = 470, PAD = 36;
    const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, class: 'menu-svg', role: 'img', 'aria-label': 'The menu: crib letters joined to cipher letters' });
    host.innerHTML = '';
    host.appendChild(svg);
    if (!menu.edges.length) { svg.appendChild(el('text', { x: W / 2, y: H / 2, 'text-anchor': 'middle', class: 'mn-empty' }, 'No menu: the crib faces itself here.')); return svg; }
    // each connected group in its own box: the largest on the left, the others stacked on the right
    const comps = menu.components.slice().sort((a, b) => b.letters.length - a.letters.length);
    const total = comps.reduce((n, c) => n + c.letters.length, 0);
    const pos = {};
    let cross = 0;
    const place = (c, box) => { const pairs = menu.edges.filter((e) => c.letters.includes(e.a)).map((e) => [e.a, e.b]); const lay = D.layout(c.letters, pairs, box); cross += lay.cross; c.letters.forEach((l, i) => { pos[l] = lay.P[i]; }); };
    if (comps.length === 1) place(comps[0], { x: PAD, y: PAD, w: W - 2 * PAD, h: H - 2 * PAD });
    else {
      const mainW = Math.max(0.64, Math.min(0.76, comps[0].letters.length / total + 0.1)) * (W - 2 * PAD);
      place(comps[0], { x: PAD, y: PAD, w: mainW - 30, h: H - 2 * PAD });
      const rest = comps.slice(1), rw = W - 2 * PAD - mainW, rt = rest.reduce((n, c) => n + Math.max(2, c.letters.length), 0);
      let y = PAD - 10;
      for (const c of rest) { const hh = ((H - 2 * PAD + 20) * Math.max(2, c.letters.length)) / rt; place(c, { x: PAD + mainW + 10, y: y + Math.min(hh / 2 - 4, 20), w: rw - 10, h: Math.max(0, hh - Math.min(hh - 8, 40)) }); y += hh; }
    }
    const letters = menu.letters, lay = { cross };
    const inLoop = new Set(); for (const lp of menu.loops) for (const i of lp.edges) inLoop.add(i);
    const mainSet = new Set(menu.main.letters);
    const edgeG = el('g'), labG = el('g'), nodeG = el('g');
    // pairs met more than once are drawn as arcs side by side
    const seen = {};
    for (const e of menu.edges) {
      const key = [e.a, e.b].sort().join('');
      const k = (seen[key] = (seen[key] || 0) + 1) - 1;
      const total = menu.edges.filter((x) => [x.a, x.b].sort().join('') === key).length;
      // the same pair met twice is bent to either side of one line: the sides are taken from the letters in order
      const [ka, kb] = [e.a, e.b].sort(), A = pos[ka], B = pos[kb], dx = B.x - A.x, dy = B.y - A.y, d = Math.hypot(dx, dy) || 1, ux = dx / d, uy = dy / d;
      const bend = total > 1 ? (k - (total - 1) / 2) * 46 : 0;
      const p0 = { x: A.x + ux * (R + 2), y: A.y + uy * (R + 2) }, p1 = { x: B.x - ux * (R + 2), y: B.y - uy * (R + 2) };
      const mx = (A.x + B.x) / 2 - uy * bend, my = (A.y + B.y) / 2 + ux * bend;
      const dpath = bend ? `M${p0.x.toFixed(1)},${p0.y.toFixed(1)} Q${(2 * mx - (p0.x + p1.x) / 2).toFixed(1)},${(2 * my - (p0.y + p1.y) / 2).toFixed(1)} ${p1.x.toFixed(1)},${p1.y.toFixed(1)}` : `M${p0.x.toFixed(1)},${p0.y.toFixed(1)} L${p1.x.toFixed(1)},${p1.y.toFixed(1)}`;
      const cls = 'mn-edge' + (inLoop.has(e.i) ? ' loop' : '') + (mainSet.has(e.a) ? '' : ' off');
      edgeG.appendChild(el('path', { d: dpath, class: cls, 'data-edge': String(e.i), 'data-audit': lay.cross ? 'edge-x' : 'edge' }));
      const t = String(e.i + 1), w = 9 + t.length * 8;
      labG.append(el('rect', { x: mx - w / 2, y: my - 10, width: w, height: 20, rx: 10, class: 'mn-pill' + (inLoop.has(e.i) ? ' loop' : ''), 'data-audit': 'overlap-ok' }), el('text', { x: mx, y: my + 5, 'text-anchor': 'middle', class: 'mn-num', 'data-audit': 'on-wire' }, t));
    }
    for (const l of letters) {
      const p = pos[l], reg = l === menu.register;
      const g = el('g', { class: 'mn-node' + (reg ? ' reg' : '') + (mainSet.has(l) ? '' : ' off'), 'data-letter': l });
      if (reg) g.appendChild(el('circle', { cx: p.x, cy: p.y, r: R + 6, class: 'mn-reg', 'data-audit': 'ignore' }));
      g.append(el('circle', { cx: p.x, cy: p.y, r: R, class: 'mn-c' }), el('text', { x: p.x, y: p.y + 6.5, 'text-anchor': 'middle', class: 'mn-t' }, l));
      nodeG.appendChild(g);
    }
    svg.append(edgeG, nodeG, labG);
    svg.dataset.crossings = String(lay.cross);
    return svg;
  };

  D.drums = function (host, edges) {
    const n = edges.length, perRow = Math.min(n, 13), rows = Math.ceil(n / perRow), CW = 58, CH = 196;
    const W = Math.max(perRow * CW + 30, 300), H = rows * CH + 10;
    const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, class: 'drums-svg', role: 'img', 'aria-label': 'The drums of the Bombe, three to a scrambler' });
    host.innerHTML = '';
    host.appendChild(svg);
    const cells = [];
    edges.forEach((e, k) => {
      const col = k % perRow, row = Math.floor(k / perRow), x = 15 + col * CW + CW / 2, y0 = row * CH + 26;
      const g = el('g', { class: 'dr-col', 'data-edge': String(e.i) });
      g.appendChild(el('rect', { x: x - 25, y: y0 - 18, width: 50, height: 152, rx: 10, class: 'dr-frame', 'data-audit': 'group' }));
      const ts = [];
      for (let j = 0; j < 3; j++) {
        const cy = y0 + 4 + j * 46;
        const spin = el('g', { class: 'dr-spin s' + j, 'data-audit': 'ignore' });
        for (let t = 0; t < 8; t++) { const a = (t * Math.PI) / 4; spin.appendChild(el('line', { x1: x + Math.cos(a) * 14, y1: cy + Math.sin(a) * 14, x2: x + Math.cos(a) * 19, y2: cy + Math.sin(a) * 19, class: 'dr-tick' })); }
        spin.style.transformOrigin = x + 'px ' + cy + 'px';
        g.append(el('circle', { cx: x, cy, r: 20, class: 'dr-drum d' + j }), spin);
        const t = el('text', { x, y: cy + 5.5, 'text-anchor': 'middle', class: 'dr-t' }, 'A');
        g.appendChild(t);
        ts.push(t);
      }
      g.append(el('text', { x, y: y0 + 156, 'text-anchor': 'middle', class: 'dr-n' }, String(e.i + 1)), el('text', { x, y: y0 + 160 + 15, 'text-anchor': 'middle', class: 'dr-p' }, e.a + e.b));
      svg.appendChild(g);
      cells.push(ts);
    });
    return {
      svg,
      set(list) { list.forEach((d, k) => { if (!cells[k]) return; for (let j = 0; j < 3; j++) cells[k][j].textContent = d.drums[j]; }); },
      spin(on) { svg.classList.toggle('spinning', !!on); },
    };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
