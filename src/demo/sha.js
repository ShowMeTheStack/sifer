// SHA-256 scenes: one round of the compression function (the adders that make T1 and T2, and the registers a..h
// moving down one place), and the message schedule as a window of sixteen words with four taps.
(function (S) {
  'use strict';
  const D = S.Demo, { h8 } = S.bytes, H = S.SHA256, F = S.Kit.flow, BY = S.Kit.bytes, box = D.box;
  const sub = (n) => String(n).replace(/\d/g, (d) => '₀₁₂₃₄₅₆₇₈₉'[d]);
  const compress = () => H.compress(H.IV, H.pad(D.data.shaMsg));
  const NAMES = 'abcdefgh';

  D.add({
    id: 'sha-round', order: 50, tag: 'SHA-256 · compression', short: 'SHA-256 round', title: 'One round of SHA-256',
    blurb: 'Two sums are formed, T1 and T2. The registers all move down one place; only the new a and the new e are computed.',
    frames({ narrow }) {
      const c = compress(), t = 4, r = c.rounds[t], old = r.before, nw = r.regs;
      const regX = (i) => (narrow ? 0 + (i % 4) * 98 : 92 + i * 140), regY = (i) => (narrow ? 20 + Math.floor(i / 4) * 64 : 46);
      const regs = (vals, shifted, lit) => {
        const items = [];
        // a register keeps the key of the value it holds, so the shift glides
        for (let i = 0; i < 8; i++) {
          const k = shifted ? (i === 0 ? 'newa' : i === 4 ? 'newe' : 'r' + (i - 1)) : 'r' + i;
          if (shifted && i === 0) continue;
          if (shifted && i === 4) continue;
          items.push({ key: 'sr:' + k, kind: 'state', x: regX(i), y: regY(i), w: narrow ? 92 : 124, h: 50, rx: 6, lines: [NAMES[i], h8(vals[i])], cls: 'block val2' + (lit && lit.includes(i) ? ' src' : '') });
        }
        if (shifted) { items.push({ key: 'sr:newa', kind: 'state', x: regX(0), y: regY(0), w: narrow ? 92 : 124, h: 50, rx: 6, lines: ['a', h8(vals[0])], cls: 'block val2 hot', enter: 'fly', from: { x: regX(0), y: regY(0) + 200 } }, { key: 'sr:newe', kind: 'state', x: regX(4), y: regY(4), w: narrow ? 92 : 124, h: 50, rx: 6, lines: ['e', h8(vals[4])], cls: 'block val2 hot', enter: 'fly', from: { x: regX(4), y: regY(4) + 200 } }); }
        return items;
      };
      const view = narrow ? box(-56, -12, 400, 760) : box(0, 0, 1160, 560);
      if (narrow) {
        // a phone: the registers in two rows, and the two sums written as column additions
        const stack = (key, x, y, rows, total, hot) => {
          const items = [];
          rows.forEach(([name, v], k) => { items.push({ key: key + ':n' + k, kind: 'text', x, y: y + k * 22, text: name, size: 13, cls: 'strong' }); items.push({ key: key + ':v' + k, kind: 'text', x: x + 250, y: y + k * 22, text: h8(v), size: 14, cls: 'mono', anchor: 'end' }); });
          const yy = y + rows.length * 22 - 12;
          items.push({ key: key + ':plus', kind: 'text', x: x + 150, y: y + (rows.length - 1) * 22, text: '+', size: 15, cls: 'strong' });
          items.push({ key: key + ':rule', kind: 'line', x1: x + 150, y1: yy, x2: x + 254, y2: yy, cls: 'rule' });
          items.push({ key: key + ':tn', kind: 'text', x, y: yy + 20, text: total[0], size: 14, cls: hot ? 'hot' : 'act' });
          items.push({ key: key + ':tv', kind: 'text', x: x + 250, y: yy + 20, text: h8(total[1]), size: 15, cls: 'mono ' + (hot ? 'hot' : 'act'), anchor: 'end' });
          return items;
        };
        const T1rows = [['h', old[7]], ['Σ1(e)', r.sig1], ['Ch(e, f, g)', r.ch], ['K' + sub(t), r.K], ['W' + sub(t), r.W]];
        const f0 = [...regs(old, false)], y0 = 180;
        const f1 = [...regs(old, false, [4, 5, 6, 7]), ...stack('t1', -40, y0, T1rows, ['T1', r.T1])];
        const f2 = [...f1, ...regs(old, false, [0, 1, 2]).filter(() => false), ...stack('t2', -40, y0 + 170, [['Σ0(a)', r.sig0], ['Maj(a, b, c)', r.maj]], ['T2', r.T2])];
        const f3 = [...f2, ...stack('na', -40, y0 + 280, [['T1', r.T1], ['T2', r.T2]], ['new a', nw[0]], true), ...stack('ne', -40, y0 + 390, [['d', old[3]], ['T1', r.T1]], ['new e', nw[4]], true)];
        const f4 = [...regs(nw, true), ...f3.filter((it) => !it.key.startsWith('sr:'))];
        return [
          { view, items: f0, say: `Round ${t} of 64 starts from these eight registers.` },
          { view, items: f1, say: `T1 = h + Σ1(e) + Ch(e, f, g) + K${sub(t)} + W${sub(t)} = \`${h8(r.T1)}\`, all modulo 2³².` },
          { view, items: f2, say: `T2 = Σ0(a) + Maj(a, b, c) = \`${h8(r.T2)}\`.` },
          { view, items: f3, say: `The new a is T1 + T2 = \`${h8(nw[0])}\`; the new e is d + T1 = \`${h8(nw[4])}\`.` },
          { view, items: f4, say: `Everything else moves down one place: b takes a, c takes b, …, and the old h is dropped.` },
        ];
      }
      // a desktop: the adders drawn as data flow
      const net = (stage) => {
        const N = F.net('sh');
        const a = (k) => (stage === k ? 'act' : '');
        const vb = (name, v, on) => [name, on ? h8(v) : ''];
        const yIn = 160, yAdd = 248, yT = 318, yL = 392, yE = 460;
        // T1: h, Σ1(e), Ch(e,f,g), K_t, W_t, added left to right
        const xs = [500, 640, 780, 920, 1060];
        const ins = [['h', old[7]], ['Σ1(e)', r.sig1], ['Ch(e,f,g)', r.ch], ['K' + sub(t), r.K], ['W' + sub(t), r.W]];
        ins.forEach(([n, v], k) => N.box('i' + k, xs[k], yIn, 124, 50, vb(n, v, stage >= 1), 'val2' + (k >= 3 ? ' key' : '') + (stage === 1 ? ' act' : stage < 1 ? ' soft' : '')));
        for (let k = 1; k < 5; k++) N.op('p' + k, xs[k], yAdd, 'add', a(1));
        N.wire('i0', [N.port('i0', 's'), [xs[0], yAdd], N.port('p1', 'w')], { head: true, cls: a(1) });
        for (let k = 1; k < 5; k++) N.wire('i' + k, [N.port('i' + k, 's'), N.port('p' + k, 'n')], { head: true, cls: a(1) });
        for (let k = 1; k < 4; k++) N.wire('c' + k, [N.port('p' + k, 'e'), N.port('p' + (k + 1), 'w')], { head: true, cls: a(1) });
        N.box('T1', xs[4], yT, 124, 50, vb('T1', r.T1, stage >= 1), 'val2' + (stage === 1 ? ' hot' : stage < 1 ? ' soft' : ''));
        N.wire('t1', [N.port('p4', 's'), N.port('T1', 'n')], { head: true, cls: a(1) });
        // T2: Σ0(a) + Maj(a,b,c)
        N.box('s0', 100, yIn, 124, 50, vb('Σ0(a)', r.sig0, stage >= 2), 'val2' + (stage === 2 ? ' act' : stage < 2 ? ' soft' : ''));
        N.box('mj', 290, yIn, 140, 50, vb('Maj(a,b,c)', r.maj, stage >= 2), 'val2' + (stage === 2 ? ' act' : stage < 2 ? ' soft' : ''));
        N.op('q', 195, yAdd, 'add', a(2));
        N.wire('s0', [N.port('s0', 's'), [100, yAdd], N.port('q', 'w')], { head: true, cls: a(2) });
        N.wire('mj', [N.port('mj', 's'), [290, yAdd], N.port('q', 'e')], { head: true, cls: a(2) });
        N.box('T2', 195, yT, 124, 50, vb('T2', r.T2, stage >= 2), 'val2' + (stage === 2 ? ' hot' : stage < 2 ? ' soft' : ''));
        N.wire('t2', [N.port('q', 's'), N.port('T2', 'n')], { head: true, cls: a(2) });
        // new a = T1 + T2, new e = d + T1
        N.op('na', 360, yL, 'add', a(3));
        N.op('ne', 760, yE, 'add', a(3));
        N.wire('T1', [N.port('T1', 's'), [xs[4], yL], N.port('na', 'e')], { head: true, cls: a(3) });
        N.dot(760, yL, stage === 3 ? 'act' : '');
        N.wire('T1e', [[760, yL], N.port('ne', 'n')], { head: true, cls: a(3) });
        N.wire('T2a', [N.port('T2', 's'), [195, yL], N.port('na', 'w')], { head: true, cls: a(3) });
        N.box('d', 600, yE, 124, 50, vb('d', old[3], stage >= 3), 'val2' + (stage === 3 ? ' act' : stage < 3 ? ' soft' : ''));
        N.wire('d', [N.port('d', 'e'), N.port('ne', 'w')], { head: true, cls: a(3) });
        N.box('oa', 360, 500, 124, 50, vb('new a', nw[0], stage >= 3), 'val2' + (stage >= 3 ? ' hot' : ' soft'));
        N.box('oe', 920, yE, 124, 50, vb('new e', nw[4], stage >= 3), 'val2' + (stage >= 3 ? ' hot' : ' soft'));
        N.wire('oa', [N.port('na', 's'), N.port('oa', 'n')], { head: true, cls: a(3) });
        N.wire('oe', [N.port('ne', 'e'), N.port('oe', 'w')], { head: true, cls: a(3) });
        return N.items;
      };
      const label = { key: 'sh:lab', kind: 'text', x: 20, y: 16, text: `round ${t} of 64`, cls: 'title' };
      return [
        { view, items: [label, ...regs(old, false), ...net(0)], say: `Round ${t} starts from the eight registers a…h. The round reads all of them, and the word W${sub(t)} of the message schedule and the constant K${sub(t)}.` },
        { view, items: [label, ...regs(old, false, [4, 5, 6, 7]), ...net(1)], say: `T1 adds five 32-bit words modulo 2³²: h, Σ1(e) = \`${h8(r.sig1)}\`, Ch(e, f, g) = \`${h8(r.ch)}\` (e chooses, bit by bit, between f and g), K${sub(t)} and W${sub(t)}: T1 = \`${h8(r.T1)}\`.` },
        { view, items: [label, ...regs(old, false, [0, 1, 2]), ...net(2)], say: `T2 = Σ0(a) + Maj(a, b, c) = \`${h8(r.sig0)}\` + \`${h8(r.maj)}\` = \`${h8(r.T2)}\`. Maj takes, bit by bit, the majority of a, b and c.` },
        { view, items: [label, ...regs(old, false, [3]), ...net(3)], say: `The new a is T1 + T2 = \`${h8(nw[0])}\`, and the new e is d + T1 = \`${h8(nw[4])}\`.` },
        { view, items: [label, ...regs(nw, true), ...net(4)], say: `All the registers move one place along: b takes the old a, c the old b, and so on; the old h is dropped. Only a and e are new. Sixty-four such rounds make one compression.` },
      ];
    },
  });

  D.add({
    id: 'sha-schedule', order: 51, tag: 'SHA-256 · message schedule', short: 'SHA-256 schedule', title: 'The message schedule: 16 words become 64',
    blurb: 'Each new word mixes four earlier ones: two of them through the small σ functions (rotations, a shift and XOR). The window slides one word at a time.',
    frames({ narrow }) {
      const sc = H.schedule(H.pad(D.data.shaMsg)), W = sc.W;
      const frames = [];
      if (narrow) {
        const view = box(-6, -26, 398, 400);
        const grid = (t, show) => BY.grid({ prefix: 'ws', x: 0, y: 0, values: W.slice(t - 16, t), order: 'row', cw: 88, ch: 34, gap: 5, size: 13, fmt: (v) => h8(v), title: `W${sub(t - 16)} … W${sub(t - 1)}`, cls: (i) => (!show ? '' : i === 0 || i === 9 ? 'src' : i === 1 || i === 14 ? 'act' : '') }).items;
        const lines = (t) => {
          const tr = sc.trace[t], items = [], y0 = 200;
          const rows = [[`σ1(W${sub(t - 2)})`, tr.terms[0], 'act'], [`W${sub(t - 7)}`, tr.terms[1], 'src'], [`σ0(W${sub(t - 15)})`, tr.terms[2], 'act'], [`W${sub(t - 16)}`, tr.terms[3], 'src']];
          rows.forEach(([n, v, c], k) => { items.push({ key: 'wl:n' + k, kind: 'text', x: 0, y: y0 + k * 26, text: n, cls: c, size: 14 }); items.push({ key: 'wl:v' + k, kind: 'text', x: 300, y: y0 + k * 26, text: h8(v), cls: 'mono', size: 15, anchor: 'end' }); });
          items.push({ key: 'wl:r', kind: 'line', x1: 200, y1: y0 + 4 * 26 - 14, x2: 304, y2: y0 + 4 * 26 - 14, cls: 'rule' });
          items.push({ key: 'wl:plus', kind: 'text', x: 196, y: y0 + 3 * 26, text: '+', size: 15, cls: 'strong', anchor: 'end' });
          items.push({ key: 'wl:tn', kind: 'text', x: 0, y: y0 + 4 * 26 + 8, text: 'W' + sub(t), cls: 'hot', size: 15 });
          items.push({ key: 'wl:tv', kind: 'text', x: 300, y: y0 + 4 * 26 + 8, text: h8(W[t]), cls: 'mono hot', size: 16, anchor: 'end' });
          return items;
        };
        frames.push({ view, items: grid(16, false), say: `The padded block of “Sifer hashes this line, one round at a time.” is sixteen 32-bit words, W₀ to W₁₅.` });
        for (const t of [16, 17, 18]) frames.push({ view, items: [...grid(t, true), ...lines(t)], say: sc.trace[t].say.replace(/\b([0-9a-f]{8})\b/g, '`$1`') });
        return frames;
      }
      const view = box(0, 0, 1160, 470);
      const cw = 64, gap = 3, x0 = 20, y0 = 60;
      const xOf = (j) => x0 + j * (cw + gap);
      const build = (t, stage) => {
        // the window W(t−16) … W(t−1) at places 0..15, and the new word at place 16
        const N = F.net('ms'), items = [];
        for (let j = 0; j < 16; j++) {
          const w = t - 16 + j, tap = stage && (j === 0 || j === 1 || j === 9 || j === 14);
          items.push({ key: 'ms:w' + w, kind: 'cell', x: xOf(j), y: y0, w: cw, h: 40, rx: 4, text: h8(W[w]), size: 12, cls: 'hex ' + (tap ? (j === 1 || j === 14 ? 'act' : 'src') : '') });
          items.push({ key: 'ms:l' + w, kind: 'text', x: xOf(j) + cw / 2, y: y0 - 10, text: 'W' + sub(w), anchor: 'middle', size: 13, cls: tap ? 'strong' : '' });
        }
        items.push({ key: 'ms:w' + t, kind: 'cell', x: xOf(16), y: y0, w: cw, h: 40, rx: 4, text: stage >= 2 ? h8(W[t]) : '', size: 12, cls: 'hex ' + (stage >= 2 ? 'hot' : 'soft') });
        items.push({ key: 'ms:l' + t, kind: 'text', x: xOf(16) + cw / 2, y: y0 - 10, text: 'W' + sub(t), anchor: 'middle', size: 13, cls: 'hot' });
        if (!stage) return items;
        const tr = sc.trace[t], c = (j) => xOf(j) + cw / 2, ys = 196, ya = 300;
        const a = stage === 1 ? 'act' : '';
        N.box('s0', c(1), ys, 96, 50, ['σ0', h8(tr.terms[2])], 'val2 act');
        N.box('s1', c(14), ys, 96, 50, ['σ1', h8(tr.terms[0])], 'val2 act');
        N.wire('w1', [[c(1), y0 + 40], N.port('s0', 'n')], { head: true, cls: a });
        N.wire('w14', [[c(14), y0 + 40], N.port('s1', 'n')], { head: true, cls: a });
        N.op('a1', c(1), ya, 'add', a); N.op('a2', c(9), ya, 'add', a); N.op('a3', c(14), ya, 'add', a);
        N.wire('w0', [[c(0), y0 + 40], [c(0), ya], N.port('a1', 'w')], { head: true, cls: a });
        N.wire('s0o', [N.port('s0', 's'), N.port('a1', 'n')], { head: true, cls: a });
        N.wire('w9', [[c(9), y0 + 40], N.port('a2', 'n')], { head: true, cls: a });
        N.wire('s1o', [N.port('s1', 's'), N.port('a3', 'n')], { head: true, cls: a });
        N.wire('c1', [N.port('a1', 'e'), N.port('a2', 'w')], { head: true, cls: a });
        N.wire('c2', [N.port('a2', 'e'), N.port('a3', 'w')], { head: true, cls: a });
        N.wire('back', [N.port('a3', 'e'), [c(16), ya], [c(16), y0 + 40]], { head: true, cls: stage === 2 ? 'hot' : a });
        N.label('f', c(0), 446, `W${sub(t)} = σ1(W${sub(t - 2)}) + W${sub(t - 7)} + σ0(W${sub(t - 15)}) + W${sub(t - 16)}   (mod 2³²)`, 'strong', 'start', 15);
        if (stage >= 2) N.chip('sum', h8(W[t]), [c(16), (ya + y0 + 40) / 2 + 30], 'hot');
        return items.concat(N.items);
      };
      frames.push({ view, items: build(16, 0), say: `The padded block of “Sifer hashes this line, one round at a time.” is sixteen 32-bit words, W₀ to W₁₅. The schedule makes 48 more.` });
      frames.push({ view, items: build(16, 1), say: `W₁₆ takes four taps from the window: W₀ and W₉ as they are, W₁ through σ0 and W₁₄ through σ1.` });
      frames.push({ view, items: build(16, 2), say: sc.trace[16].say.replace(/\b([0-9a-f]{8})\b/g, '`$1`') });
      for (const t of [17, 18, 19]) frames.push({ view, items: build(t, 2), say: `The window slides one word: ${sc.trace[t].say.replace(/\b([0-9a-f]{8})\b/g, '`$1`')}` });
      return frames;
    },
  });
})(globalThis.Sifer = globalThis.Sifer || {});
