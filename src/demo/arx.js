// The ChaCha20 quarter-round as an ARX network: four lanes a, b, c, d and twelve steps (add modulo 2³², XOR,
// rotate), beside the four words as bits that light up when a step changes them.
(function (S) {
  'use strict';
  const D = S.Demo, { h8 } = S.bytes, C = S.ChaCha, BY = S.Kit.bytes, F = S.Kit.flow, box = D.box;
  D.add({
    id: 'chacha-qr', order: 40, tag: 'ChaCha20 · ARX', short: 'ChaCha quarter-round', title: 'The ChaCha20 quarter-round, step by step',
    blurb: 'Only three operations, on 32-bit words: add (⊞, modulo 2³²), XOR (⊕) and rotate. The additions carry bits upward; the XORs and rotations spread them sideways.',
    frames({ narrow }) {
      const st = C.state(D.data.chachaKey, 1, D.data.chachaNonce), idx = [1, 5, 9, 13];
      const init = idx.map((i) => st[i]), q = C.qr(...init);
      const L = narrow
        ? { view: box(-6, -10, 396, 790), lx: [70, 150, 230, 310], y0: 46, dy: 28, panel: [0, 446], bw: 9.4, bh: 16, bg: 4, rowH: 78, text: false, nameX: 0, hexX: 20 }
        : { view: box(-10, -10, 1170, 560), lx: [60, 150, 240, 330], y0: 50, dy: 37, panel: [430, 52], bw: 16, bh: 24, bg: 6, rowH: 120, text: true, nameX: 430, hexX: 462 };
      const N_ = 'abcd';
      // bit identities, so a rotation glides the bits round
      const ids = [0, 1, 2, 3].map(() => Array.from({ length: 32 }, (_, j) => j));
      const yOf = (k) => L.y0 + 22 + k * L.dy;
      const net = (at) => {
        const N = F.net('qr');
        N.label('h', L.lx[0] - 30, 14, '', '', 'start');
        L.lx.forEach((x, t) => N.label('n' + t, x, 18, N_[t], at >= 0 && C.STEPS[at] && C.STEPS[at][1] === t ? 'act' : 'strong', 'middle', 16));
        // the operators, and where each lane is cut by them
        const cuts = [[], [], [], []];
        C.STEPS.forEach(([op, t, s], k) => {
          const y = yOf(k), x = L.lx[t], cur = k === at, done = k < at;
          const cls = cur ? 'act' : '';
          if (op === 'rot') { N.box('r' + k, x, y, 58, 22, '<<< ' + s, 'small ' + (cur ? 'act' : done ? '' : 'soft')); cuts[t].push([y - 11, y + 11]); }
          else { N.op('o' + k, x, y, op === 'add' ? 'add' : 'xor', cls, 10); cuts[t].push([y - 10, y + 10]); }
        });
        // the source wires: from a dot on the source lane to the side of the operator
        const hopsOn = [[], [], [], []];
        C.STEPS.forEach(([op, t, s], k) => {
          if (op === 'rot') return;
          const y = yOf(k), xs = L.lx[s], xt = L.lx[t], dir = Math.sign(xt - xs), cur = k === at;
          N.dot(xs, y, cur ? 'act' : '');
          const end = [xt - dir * 10, y];
          const between = L.lx.filter((x, j) => (x - xs) * (x - xt) < 0);
          if (!between.length) { N.wire('s' + k, [[xs, y], end], { head: true, cls: cur ? 'act' : '' }); return; }
          // over each lane in the way, a small hop
          let d = `M${xs},${y}`;
          for (const bx of between.sort((u, v) => dir * (u - v))) { d += ` L${bx - dir * 6},${y} A6,6 0 0 ${dir > 0 ? 1 : 0} ${bx + dir * 6},${y}`; hopsOn[L.lx.indexOf(bx)].push(y); }
          d += ` L${end[0]},${end[1]}`;
          N.add({ key: 'qr:hop' + k, kind: 'path', d, cls: 'hopwire' + (cur ? ' act' : ''), pathAudit: 'edge-x', layer: 'lines' });
          N.add({ key: 'qr:hh' + k, kind: 'wire', pts: [[end[0] - dir * 8, y], end], head: true, cls: 'tick ' + (cur ? 'act' : ''), audit: 'ignore' });
        });
        // the lanes, in pieces between operators
        const top = 28, bot = yOf(11) + 34;
        for (let t = 0; t < 4; t++) {
          const x = L.lx[t], cs = cuts[t].sort((u, v) => u[0] - v[0]);
          let y = top, n = 0;
          for (const [a, b] of cs.concat([[bot, bot]])) {
            if (a - y > 1) { const crossed = hopsOn[t].some((hy) => hy > y && hy < a); N.wire('l' + t + '-' + n++, [[x, y], [x, a]], { head: a !== bot, cls: crossed ? 'hop' : '' }); }
            y = b;
          }
        }
        return N.items;
      };
      // the words as bits, and their hex
      const words = (k) => {
        const v = k < 0 ? init : q.trace[k].words, prev = k <= 0 ? init : q.trace[k - 1].words;
        const step = k >= 0 ? C.STEPS[k] : null, items = [];
        if (step && step[0] === 'rot') { const t = step[1], n = step[2]; ids[t] = ids[t].slice(n).concat(ids[t].slice(0, n)); }
        for (let t = 0; t < 4; t++) {
          const y = L.panel[1] + t * L.rowH, tgt = step && step[1] === t, src = step && step[0] !== 'rot' && step[2] === t;
          const bitsNow = BY.toBits(v[t], 32), bitsWas = BY.toBits(prev[t], 32);
          items.push({ key: 'qw:n' + t, kind: 'text', x: L.nameX, y: y + 6, text: N_[t], cls: tgt ? 'act' : src ? 'src' : 'strong', size: 18 });
          items.push({ key: 'qw:h' + t, kind: 'text', x: L.hexX, y: y + 6, text: h8(v[t]), cls: 'mono ' + (tgt ? 'hot' : ''), size: narrow ? 15 : 17 });
          if (tgt && !narrow) items.push({ key: 'qw:was' + t, kind: 'text', x: L.hexX + 110, y: y + 6, text: 'was ' + h8(prev[t]), cls: '', size: 14 });
          const by = y + 18;
          bitsNow.forEach((b, j) => {
            const changed = tgt && step[0] !== 'rot' && b !== bitsWas[j];
            const xj = L.panel[0] + j * (L.bw + 1) + Math.floor(j / 8) * L.bg;
            items.push({ key: `qb:${t}:${ids[t][j]}`, kind: 'cell', x: xj, y: by, w: L.bw, h: L.bh, rx: 2, text: L.text ? String(b) : '', size: 12, cls: 'bit ' + (L.text ? '' : 'solid ') + (b ? 'one ' : '') + (changed ? 'hot' : tgt && step[0] === 'rot' ? 'act' : src ? 'src' : '') });
          });
        }
        if (!narrow && step) items.push({ key: 'qw:op', kind: 'text', x: L.panel[0], y: 18, text: `step ${k + 1}:  ${N_[step[1]]} ${step[0] === 'add' ? '+=' : step[0] === 'xor' ? '^=' : '<<<='} ${step[0] === 'rot' ? step[2] : N_[step[2]]}`, cls: 'act', size: 16 });
        return items;
      };
      const view = L.view, frames = [];
      // the starting state: four constants, eight key words, the block counter and three nonce words
      const role = ['const', 'const', 'const', 'const', 'key', 'key', 'key', 'key', 'key', 'key', 'key', 'key', 'ctr', 'nonce', 'nonce', 'nonce'];
      const g = BY.grid({ prefix: 'cs', x: L.panel[0] + (narrow ? 0 : 20), y: L.panel[1] + 6, values: st, order: 'row', cw: narrow ? 88 : 118, ch: narrow ? 32 : 44, gap: narrow ? 4 : 8, size: narrow ? 13 : 16, fmt: h8, title: 'the starting state, 16 words', cls: (i) => (idx.includes(i) ? 'act' : role[i] === 'key' ? 'key' : 'soft') });
      const legend = narrow ? [] : [{ key: 'cs:l1', kind: 'text', x: L.panel[0] + 20, y: L.panel[1] + 4 * 52 + 30, text: 'row 0: constants · rows 1–2: the key · row 3: counter and nonce', size: 14 }];
      frames.push({ view, items: [...net(-1), ...g.items, ...legend], say: `ChaCha20 starts from a 4×4 state of 32-bit words: four constants, the eight words of our key \`a lantern keeper guards 32 bytes\`, a block counter and the nonce. A quarter-round works on one column at a time; here, column 1.` });
      frames.push({ view, items: [...net(-1), ...words(-1)], say: `The four words come from column 1 of the starting state: a constant (\`${h8(init[0])}\`), two words of our key (\`${h8(init[1])}\`, \`${h8(init[2])}\`) and the first nonce word (\`${h8(init[3])}\`, the letters “salt”).` });
      q.trace.forEach((tr, k) => {
        const [op, t, s] = C.STEPS[k];
        const extra = op === 'add' ? ' Watch the carries: one changed bit can flip a run of higher bits.' : op === 'rot' ? ' Nothing changes value; every bit moves ' + s + ' places to the left, the top ' + s + ' coming round to the bottom.' : ' A bit of the result changes exactly where the two words differ.';
        frames.push({ view, items: [...net(k), ...words(k)], say: tr.say.replace(/\b([0-9a-f]{8})\b/g, '`$1`') + (k < 4 ? extra : '') });
      });
      return frames;
    },
  });
})(globalThis.Sifer = globalThis.Sifer || {});
