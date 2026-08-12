// Part 1, the Enigma wing as topics: the shared scenario (an original practice message and its daily key), the
// machine drawn as columns of contacts with the current's path, and the Bombe's menu laid out as a graph.
(function (S) {
  'use strict';
  const P = (S.P1 = S.P1 || {});
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const E = () => S.Enigma;

  // the worked scenario: a practice net's weather report, its key, and the crib an analyst would guess
  P.EN = {
    key: { order: ['IV', 'I', 'III'], reflector: 'B', rings: 'AAA', window: 'BXC', plugs: 'IE NZ MU KF OC XS DV PL JT YG' },
    plain: 'WEATHER REPORT FOR THE NORTH VALLEY RAIN BY EVENING AND A STRONG WIND FROM THE WEST AFTER MIDNIGHT',
    crib: 'WEATHERREPORTFOR',
    day: { order: ['II', 'V', 'I'], reflector: 'B', rings: 'AAA', window: 'KQD', plugs: 'AM BT CY DR FO GW HL JS KV NU' },
  };
  P.enCipher = () => E().encrypt(P.EN.key, P.letters(P.EN.plain));

  // ---- inputs shared by the machine topics --------------------------------------------------------------------------
  P.enInputs = (defs) => [
    { id: 'order', kind: 'text', label: 'Rotors, left to right', def: defs.order || 'IV I III', check: (v) => { const r = String(v).trim().toUpperCase().split(/[\s,]+/); if (r.length !== 3 || new Set(r).size !== 3 || r.some((x) => !E().ROTORS[x])) return 'Rotors: three different ones of I, II, III, IV, V'; return null; } },
    { id: 'rings', kind: 'text', label: 'Rings', def: defs.rings || 'AAA', check: (v) => (/^[A-Za-z]{3}$/.test(String(v).trim()) ? null : 'Rings: three letters') },
    { id: 'window', kind: 'text', label: 'Window', def: defs.window || 'BXC', check: (v) => (/^[A-Za-z]{3}$/.test(String(v).trim()) ? null : 'Window: three letters') },
    { id: 'plugs', kind: 'text', label: 'Plugboard', def: defs.plugs === undefined ? 'IE NZ MU KF OC XS DV PL JT YG' : defs.plugs, check: (v) => { try { E().parsePlugs(v, 13); return null; } catch (e) { return 'Plugboard: ' + e.message; } } },
  ];
  P.enCfg = (inp) => ({ order: String(inp.order).trim().toUpperCase().split(/[\s,]+/), reflector: 'B', rings: String(inp.rings).trim().toUpperCase(), window: String(inp.window).trim().toUpperCase(), plugs: inp.plugs });

  // ---- the machine as columns of contacts --------------------------------------------------------------------------
  // right to left: keys and lamps, plugboard, entry wheel, rotors R, M, L, reflector. Row y of contact c is fixed.
  const RY = 64, RP = 16;
  P.EM = { cols: { UKW: 40, L: 170, M: 300, R: 430, ETW: 540, PB: 640, KEY: 740 }, w: 70, ry: (c) => RY + c * RP + 8 };
  /**
   * o: {cfg, windows: [l, m, r] letters, path: the press path (from m.press), upto: how many path parts to draw,
   *     moved: [bool × 3] rotors that just moved, key: pressed index, lamp: lit index}
   */
  P.machineItems = function (o) {
    const X = P.EM.cols, W = P.EM.w, ry = P.EM.ry, items = [], H = 26 * RP + 8;
    const box = (id, x, title, sub, cls) => {
      items.push({ key: 'mc:' + id, kind: 'region', x: x - W / 2, y: RY - 4, w: W, h: H, rx: 8, cls: cls || '', audit: 'group', layer: 'back' });
      items.push(P.text('mc:t' + id, x, RY - 34, title, 'strong', 14, 'middle'));
      if (sub) items.push(P.text('mc:s' + id, x, RY - 16, sub, 'tick', 13, 'middle'));
    };
    box('UKW', X.UKW, 'UKW-B', 'reflector');
    const nm = ['L', 'M', 'R'];
    nm.forEach((k, i) => box(k, X[k], (o.cfg.order[i]) + ' (' + k + ')', 'window ' + o.windows[i], o.moved && o.moved[i] ? 'hot' : ''));
    box('ETW', X.ETW, 'entry', 'wheel');
    box('PB', X.PB, 'plugboard', '');
    // contact letters on the entry wheel and at the keys
    for (let c = 0; c < 26; c++) {
      const on = o.marks && o.marks.has(c);
      items.push({ key: 'mc:e' + c, kind: 'text', x: X.ETW, y: ry(c) + 4.5, text: ABC[c], anchor: 'middle', size: 12, cls: 'mono' + (on ? ' act' : ''), audit: 'small-ok' });
      const isKey = o.key === c, isLamp = o.lamp === c;
      items.push({ key: 'mc:k' + c, kind: 'cell', x: X.KEY - 13, y: ry(c) - 7, w: 26, h: 14, rx: 7, text: ABC[c], size: 11, cls: 'mono ' + (isLamp ? 'p1-lamp' : isKey ? 'act' : 'soft'), audit: 'small-ok' });
    }
    items.push(P.text('mc:kt', X.KEY, RY - 34, 'key / lamp', 'strong', 14, 'middle'));
    // plug cables: a short bracket between the two rows on the plugboard column
    E().parsePlugs(o.cfg.plugs || '').forEach(([a, b], k) => {
      const ia = ABC.indexOf(a), ib = ABC.indexOf(b), lo = Math.min(ia, ib), hi = Math.max(ia, ib), x0 = X.PB - 27 + (k % 13) * 4.2;
      items.push({ key: 'mc:p' + a + b, kind: 'path', d: `M${x0 - 3} ${ry(lo)} h3 V${ry(hi)} h-3`, cls: 'p1-cable', pathAudit: 'ignore', layer: 'back' });
    });
    // the path, part by part
    if (o.path) {
      const n = Math.min(o.upto === undefined ? o.path.length : o.upto, o.path.length);
      const segs = [];
      for (let k = 0; k < n; k++) {
        const p = o.path[k];
        let a, b;
        if (p.part === 'plugboard') { a = [X.PB + (p.dir === 'in' ? W / 2 : -W / 2), ry(p.from)]; b = [X.PB + (p.dir === 'in' ? -W / 2 : W / 2), ry(p.to)]; if (p.dir === 'in') segs.push({ d: [[X.KEY - 13, ry(p.from)], a, b], back: false }); else segs.push({ d: [a, b, [X.KEY - 13, ry(p.to)]], back: true }); continue; }
        if (p.part === 'ETW') { const xx = X.ETW; segs.push({ d: p.dir === 'in' ? [[X.PB - W / 2, ry(p.from)], [xx + W / 2, ry(p.from)], [xx - W / 2, ry(p.to)]] : [[xx - W / 2, ry(p.from)], [xx + W / 2, ry(p.to)], [X.PB - W / 2, ry(p.to)]], back: p.dir !== 'in' }); continue; }
        if (p.part === 'UKW') { const xx = X.UKW; segs.push({ d: [[X.L - W / 2, ry(p.from)], [xx + W / 2 - 6, ry(p.from)], [xx - 10, ry(p.from)], [xx - 10, ry(p.to)], [xx + W / 2 - 6, ry(p.to)], [X.L - W / 2, ry(p.to)]], back: true, turn: true }); continue; }
        const xx = X[p.part], prevX = p.dir === 'fwd' ? (p.part === 'R' ? X.ETW : p.part === 'M' ? X.R : X.M) : null;
        if (p.dir === 'fwd') segs.push({ d: [[prevX - W / 2, ry(p.from)], [xx + W / 2, ry(p.from)], [xx - W / 2, ry(p.to)]], back: false });
        else { const nextX = p.part === 'L' ? X.M : p.part === 'M' ? X.R : X.ETW; segs.push({ d: [[xx - W / 2, ry(p.from)], [xx + W / 2, ry(p.to)], [nextX - W / 2, ry(p.to)]], back: true }); }
      }
      segs.forEach((s, k) => items.push({ key: 'mc:w' + k, kind: 'path', d: 'M' + s.d.map((q) => q[0].toFixed(1) + ' ' + q[1].toFixed(1)).join(' L'), cls: s.back ? 'p1-back' : 'p1-fwd', pathAudit: 'ignore', layer: 'lines', box: { x: Math.min(...s.d.map((q) => q[0])), y: Math.min(...s.d.map((q) => q[1])), w: 1, h: 1 } }));
    }
    return items;
  };

  // ---- the menu as a graph ----------------------------------------------------------------------------------------------
  /** a layout with few crossings: spring embedding from many seeded starts, the best kept */
  const layouts = new Map();
  /** the distance from point p to the segment a–b */
  const segDist = (p, a, b) => { const dx = b.x - a.x, dy = b.y - a.y, L = dx * dx + dy * dy, t = L ? Math.max(0, Math.min(1, ((p.x - a.x) * dx + (p.y - a.y) * dy) / L)) : 0; return Math.sqrt((p.x - a.x - t * dx) ** 2 + (p.y - a.y - t * dy) ** 2); };
  /**
   * A layout for the menu: the largest group by spring embedding from many seeded starts (fewest crossings, then the
   * most room between letters and between letters and edges), the small groups in a row beneath it.
   */
  P.menuLayout = function (menu, box) {
    const ck = menu.crib + '@' + menu.offset + ':' + menu.cipher.slice(menu.offset, menu.offset + menu.length) + JSON.stringify(box);
    if (layouts.has(ck)) return layouts.get(ck);
    const main = menu.main.letters, n = main.length, idx = {}; main.forEach((l, i) => { idx[l] = i; });
    const pairs = [], seen = new Set();
    for (const e of menu.edges) { if (idx[e.a] === undefined) continue; const k = [idx[e.a], idx[e.b]].sort().join(); if (!seen.has(k)) { seen.add(k); pairs.push([idx[e.a], idx[e.b]]); } }
    const others = menu.components.filter((c) => c !== menu.main);
    const W = box.w, H = others.length ? box.h - 80 : box.h, rand = E().rng('menu:' + main.join('') + menu.edges.length);
    const { sqrt, max, min } = Math, rnd = rand;
    const X = new Float64Array(n), Y = new Float64Array(n), DX = new Float64Array(n), DY = new Float64Array(n), K = sqrt((W * H) / Math.max(1, n)), K2 = K * K;
    const pa = Int32Array.from(pairs.map((q) => q[0])), pb = Int32Array.from(pairs.map((q) => q[1])), np = pairs.length;
    let best = null;
    for (let t = 0; t < 70; t++) {
      for (let i = 0; i < n; i++) { X[i] = W / 2 + (rnd() - 0.5) * W * 0.5; Y[i] = H / 2 + (rnd() - 0.5) * H * 0.5; }
      for (let it = 0; it < 300; it++) {
        const temp = 30 * (1 - it / 300) + 0.5;
        DX.fill(0); DY.fill(0);
        for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) { const dx = X[i] - X[j], dy = Y[i] - Y[j], d2 = max(1, dx * dx + dy * dy), f = K2 / d2; DX[i] += dx * f; DY[i] += dy * f; DX[j] -= dx * f; DY[j] -= dy * f; }
        for (let e = 0; e < np; e++) { const a = pa[e], b = pb[e], dx = X[a] - X[b], dy = Y[a] - Y[b], dist = max(1, sqrt(dx * dx + dy * dy)), f = dist / K; DX[a] -= dx * f; DY[a] -= dy * f; DX[b] += dx * f; DY[b] += dy * f; }
        for (let i = 0; i < n; i++) { const L = max(1e-6, sqrt(DX[i] * DX[i] + DY[i] * DY[i])), m = min(L, temp) / L; X[i] += DX[i] * m; Y[i] += DY[i] * m; }
      }
      // fit into the box, keeping the aspect
      let x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity;
      for (let i = 0; i < n; i++) { x0 = min(x0, X[i]); x1 = max(x1, X[i]); y0 = min(y0, Y[i]); y1 = max(y1, Y[i]); }
      const sc = min(W / max(1, x1 - x0), H / max(1, y1 - y0));
      const p = Array.from(X, (x, i) => ({ x: (x - x0) * sc + (W - (x1 - x0) * sc) / 2, y: (Y[i] - y0) * sc + (H - (y1 - y0) * sc) / 2 }));
      let minD = Infinity, minE = Infinity;
      for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) minD = min(minD, sqrt((p[i].x - p[j].x) ** 2 + (p[i].y - p[j].y) ** 2));
      for (let i = 0; i < n; i++) for (const [a, b] of pairs) if (a !== i && b !== i) minE = min(minE, segDist(p[i], p[a], p[b]));
      let c = 0;
      for (let i = 0; i < np; i++) for (let j = i + 1; j < np; j++) { const [a, b] = pairs[i], [c2, d] = pairs[j]; if (a === c2 || a === d || b === c2 || b === d) continue; if (P.segX(p[a], p[b], p[c2], p[d])) c++; }
      const score = c * 1000 + (minD < 80 ? (80 - minD) * 20 : 0) + (minE < 40 ? (40 - minE) * 40 : 0) - 0.3 * min(minD, 160) - 0.3 * min(minE, 80);
      if (!best || score < best.score) best = { score, p, c };
    }
    // spread: push letters that sit too close (to each other or to an edge) apart, while no crossing appears
    const p = best.p.map((q) => ({ x: q.x, y: q.y })), crossings = () => { let c = 0; for (let i = 0; i < np; i++) for (let j = i + 1; j < np; j++) { const [a, b] = pairs[i], [c2, d] = pairs[j]; if (a === c2 || a === d || b === c2 || b === d) continue; if (P.segX(p[a], p[b], p[c2], p[d])) c++; } return c; };
    for (let it = 0; it < 300; it++) {
      const old = p.map((q) => ({ x: q.x, y: q.y }));
      let moved = false;
      for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) { const dx = p[j].x - p[i].x, dy = p[j].y - p[i].y, d = Math.max(0.1, sqrt(dx * dx + dy * dy)); if (d < 90) { const f = (90 - d) / 2 / d; p[i].x -= dx * f; p[i].y -= dy * f; p[j].x += dx * f; p[j].y += dy * f; moved = true; } }
      for (let i = 0; i < n; i++) for (const [a, b] of pairs) { if (a === i || b === i) continue; const dd = segDist(p[i], p[a], p[b]); if (dd < 44) { const mx = (p[a].x + p[b].x) / 2, my = (p[a].y + p[b].y) / 2, dx = p[i].x - mx, dy = p[i].y - my, d = Math.max(0.1, sqrt(dx * dx + dy * dy)); p[i].x += (dx / d) * (44 - dd) * 0.5; p[i].y += (dy / d) * (44 - dd) * 0.5; moved = true; } }
      for (const q of p) { q.x = min(W, max(0, q.x)); q.y = min(H, max(0, q.y)); }
      if (crossings() > best.c) { p.forEach((q, i) => { q.x = old[i].x; q.y = old[i].y; }); break; }
      if (!moved) break;
    }
    const out = {};
    main.forEach((l, i) => { out[l] = { x: box.x + p[i].x, y: box.y + p[i].y }; });
    // the small groups, each drawn in a little box of its own along the bottom
    let x = box.x, rowY = 0;
    for (const c of others) {
      if (x > box.x && x + (c.letters.length - 1) * 80 > box.x + box.w) { x = box.x; rowY += 110; }
      const w = Math.max(70, (c.letters.length - 1) * 80), ids = {}; c.letters.forEach((l, i) => { ids[l] = i; });
      const q = c.letters.map((l, i) => ({ x: (i / Math.max(1, c.letters.length - 1)) * w, y: 0 }));
      // a chain when the group is a path, otherwise a short fan: order by a walk from an end
      const adj = {}; for (const e of menu.edges) if (ids[e.a] !== undefined) { (adj[e.a] = adj[e.a] || new Set()).add(e.b); (adj[e.b] = adj[e.b] || new Set()).add(e.a); }
      const start = c.letters.find((l) => adj[l].size === 1) || c.letters[0], order = [], seenL = new Set([start]), st = [start];
      while (st.length) { const v = st.shift(); order.push(v); for (const w2 of [...adj[v]].sort()) if (!seenL.has(w2)) { seenL.add(w2); st.push(w2); } }
      // levels of a walk from the root, drawn left to right; a path becomes a straight chain
      const isPath = c.letters.every((l) => adj[l].size <= 2), root = isPath ? start : c.letters.reduce((m, l) => (adj[l].size > adj[m].size ? l : m));
      const lvl = { [root]: 0 }, qq = [root], levels = [[root]];
      while (qq.length) { const v = qq.shift(); for (const w2 of [...adj[v]].sort()) if (lvl[w2] === undefined) { lvl[w2] = lvl[v] + 1; (levels[lvl[w2]] = levels[lvl[w2]] || []).push(w2); qq.push(w2); } }
      levels.forEach((ls, k) => ls.forEach((l, j) => { out[l] = { x: x + k * 80, y: box.y + box.h + rowY + (j - (ls.length - 1) / 2) * 52 }; }));
      void q; void order;
      x += (levels.length - 1) * 80 + 90;
    }
    out.crossings = best.c;
    layouts.set(ck, out);
    return out;
  };
  P.segX = (p, q, r, s) => { const o = (a, b, c) => Math.sign((b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x)); return o(p, q, r) * o(p, q, s) < 0 && o(r, s, p) * o(r, s, q) < 0; };
  /**
   * The menu: letters as circles, crib pairs as numbered edges. o: {pos, edges: Set of crib indexes to draw (default all),
   * hotEdges, hotLetters, register, subs: {letter: text}, dimOthers}
   */
  P.menuItems = function (menu, o) {
    const items = [], pos = o.pos, show = o.edges || new Set(menu.edges.map((e) => e.i));
    const multi = {};
    for (const e of menu.edges) { const k = [e.a, e.b].sort().join(''); (multi[k] = multi[k] || []).push(e.i); }
    const used = new Set(), placed = [];
    for (const e of menu.edges) if (show.has(e.i)) { used.add(e.a); used.add(e.b); }
    for (const l of menu.letters) {
      if (!used.has(l) && !o.allLetters) continue;
      const hot = o.hotLetters && o.hotLetters.has(l), reg = o.register === l;
      const it = { key: 'mn:' + l, kind: 'state', x: pos[l].x, y: pos[l].y, r: 18, text: l, size: 16, cls: 'p1-node' + (reg ? ' p1-reg' : '') + (hot ? ' hot' : '') + (o.dim && o.dim.has(l) ? ' dim' : ''), accept: reg };
      // a deduced partner goes inside the letter's box, so nothing hangs below it in the way of the edges
      if (o.subs && o.subs[l]) Object.assign(it, { r: undefined, w: 48, h: 42, rx: 10, text: undefined, lines: [l, o.subs[l]], size: 14 });
      items.push(it);
    }
    // one line per pair of letters; when the crib joins the same two letters twice, both numbers go on it
    for (const k of Object.keys(multi)) {
      const ids = multi[k].filter((i) => show.has(i));
      if (!ids.length) continue;
      const e = menu.edges.find((x) => x.i === ids[0]), hot = o.hotEdges && ids.some((i) => o.hotEdges.has(i));
      // the label beside the edge's middle, on the side further from every letter and every label placed so far
      const A = pos[e.a], Bp = pos[e.b], dx = Bp.x - A.x, dy = Bp.y - A.y, len = Math.max(1, Math.hypot(dx, dy)), nx = -dy / len, ny = dx / len;
      const mx = (A.x + Bp.x) / 2, my = (A.y + Bp.y) / 2, text = ids.map((i) => i + 1).join(', ');
      let lab = null;
      for (const sgn of [1, -1]) for (const off of [14, 20]) {
        const c = { x: mx + nx * (off + (text.length > 2 ? 6 : 0)) * sgn, y: my + ny * (off + (text.length > 2 ? 6 : 0)) * sgn };
        const clear = Math.min(...Object.keys(pos).filter((q) => q.length === 1).map((q) => Math.hypot(pos[q].x - c.x, pos[q].y - c.y)), ...placed.map((q) => Math.hypot(q.x - c.x, q.y - c.y) * 1.6));
        if (!lab || clear > lab.clear + 0.5) lab = { x: c.x, y: c.y, clear };
      }
      placed.push(lab);
      items.push({ key: 'me:' + k, kind: 'edge', from: 'mn:' + e.a, to: 'mn:' + e.b, head: false, label: text, lx: lab.x, ly: lab.y + 4, size: 14, cls: (hot ? 'hot' : o.dimEdges && ids.every((i) => o.dimEdges.has(i)) ? 'p1-faint' : '') + (ids.length > 1 ? ' p1-double' : ''), labelCls: hot ? 'p1-elab hot' : 'p1-elab', audit: 'edge-x' });
    }
    return items;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
