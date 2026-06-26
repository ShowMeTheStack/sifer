// AES scenes: SubBytes with one byte's inversion and affine map, ShiftRows, MixColumns on one column, the key
// expansion's g-function and words, and the avalanche of one flipped plaintext bit.
(function (S) {
  'use strict';
  const D = S.Demo, { h2, hex } = S.bytes, G = S.gf256, A = S.AES, BY = S.Kit.bytes, F = S.Kit.flow;
  const box = D.box;
  const run = () => A.encrypt(D.data.aesPlain, D.data.aesKey);
  const cellName = (i) => `row ${i % 4}, column ${Math.floor(i / 4)}`;

  // ---- SubBytes ---------------------------------------------------------------------------------------------
  D.add({
    id: 'aes-subbytes', order: 10, tag: 'AES · round step', short: 'SubBytes', title: 'SubBytes: every byte through one S-box',
    blurb: 'The S-box is not a random table: it is the inverse in GF(2⁸) followed by a fixed affine map of the bits.',
    frames({ narrow }) {
      const r1 = run().rounds[1], st = r1.start, out = r1.sub, pick = 6, b = st[pick], tr = G.subByteTrace(b);
      const L = narrow
        ? { view: box(-6, -34, 394, 540), cw: 42, ch: 34, gap: 4, size: 15, gA: [0, 0], gB: [202, 0], panel: box(0, 196, 382, 304), pad: 14, bit: 16 }
        : { view: box(-10, -40, 1160, 470), cw: 64, ch: 52, gap: 6, size: 18, gA: [20, 30], gB: [420, 30], panel: box(744, -10, 400, 372), pad: 22, bit: 20 };
      const gridA = (cls) => BY.grid({ prefix: 'sa', x: L.gA[0], y: L.gA[1], values: st, cw: L.cw, ch: L.ch, gap: L.gap, size: L.size, title: 'state in', cls });
      const gridB = (filled, cls) => BY.grid({ prefix: 'sb', x: L.gB[0], y: L.gB[1], values: out.map((v, i) => (filled(i) ? v : null)), cw: L.cw, ch: L.ch, gap: L.gap, size: L.size, title: 'after SubBytes', cls: (i) => (filled(i) ? cls(i) : 'soft') });
      const ga = gridA(() => '');
      const gx = L.gA[0] + ga.inner.w, gb0 = L.gB[0];
      // the arrow between the grids, with the S-box named over it
      const ay = L.gA[1] + ga.inner.h / 2;
      const arrow = [{ key: 'arr', kind: 'wire', pts: [[gx + 12, ay], [gb0 - 12, ay]], head: true, cls: 'act' }, ...(narrow ? [] : [{ key: 'arrl', kind: 'text', x: (gx + gb0) / 2, y: ay - 12, text: 'S-box', anchor: 'middle', cls: 'act', size: 14 }])];
      const P = L.panel;
      const panel = (title) => ({ key: 'panel', kind: 'region', x: P.x, y: P.y, w: P.w, h: P.h, text: title, cls: 'panel' });
      const px = P.x + L.pad, py = P.y + 50;
      const line = (k, y, text, cls, size) => ({ key: 'pl' + k, kind: 'text', x: px, y, text, cls: cls || 'math', size: size || (narrow ? 13 : 14) });
      const callByte = (i) => [line('b', py, `byte ${h2(b)} = ${G.poly(b)}`, 'math'), ...(i >= 1 ? [line('inv', py + 26, `inverse: ${h2(b)}⁻¹ = ${h2(tr.inv)}   (${h2(b)} · ${h2(tr.inv)} = 01)`, 'math')] : [])];
      // the affine map as a matrix of bits times the inverse's bits, plus the bits of 63
      const affine = (lit) => {
        const items = [], s = L.bit, top = py + 86, mx = px + (narrow ? 22 : 30);
        const v = tr.inv, o = tr.out;
        items.push({ key: 'af:t', kind: 'text', x: px, y: top - 36, text: 'affine map: b′ = M·b ⊕ 63', cls: 'strong', size: narrow ? 12 : 13 });
        for (let r = 0; r < 8; r++) {
          items.push({ key: 'af:rl' + r, kind: 'text', x: mx - 6, y: top + r * s + s * 0.72, text: 'b' + r, anchor: 'end', size: 11, cls: 'muted', audit: 'small-ok' });
          for (let c = 0; c < 8; c++) {
            const one = [0, 4, 5, 6, 7].includes((c - r + 8) % 8);
            const on = lit === r && one && ((v >> c) & 1);
            items.push({ key: `af:m${r},${c}`, kind: 'cell', x: mx + c * s, y: top + r * s, w: s - 1, h: s - 1, rx: 1, text: one ? '1' : '0', size: 12, cls: 'bit ' + (one ? 'one ' : 'muted ') + (on ? 'act' : '') });
          }
        }
        const col = (k, x, bits, cls, head) => { items.push({ key: 'af:h' + k, kind: 'text', x: x + s / 2, y: top - 12 - (narrow ? 0 : 0), text: head, anchor: 'middle', size: 12, cls: 'strong' }); for (let r = 0; r < 8; r++) items.push({ key: `af:${k}${r}`, kind: 'cell', x, y: top + r * s, w: s - 1, h: s - 1, rx: 1, text: String(bits[r]), size: 12, cls: 'bit ' + (bits[r] ? 'one ' : '') + (typeof cls === 'function' ? cls(r) : cls) }); };
        const gx2 = mx + 8 * s + 12;
        col('v', gx2, [0, 1, 2, 3, 4, 5, 6, 7].map((k) => (v >> k) & 1), (r) => (lit !== undefined && [0, 4, 5, 6, 7].map((d) => (lit + d) % 8).includes(r) ? 'act' : ''), h2(v));
        items.push({ key: 'af:x', kind: 'text', x: gx2 + s + 11, y: top + 4 * s, text: '⊕', anchor: 'middle', size: 15, cls: 'strong' });
        col('c', gx2 + s + 22, [0, 1, 2, 3, 4, 5, 6, 7].map((k) => (0x63 >> k) & 1), 'key', '63');
        items.push({ key: 'af:e', kind: 'text', x: gx2 + 2 * s + 33, y: top + 4 * s, text: '=', anchor: 'middle', size: 15, cls: 'strong' });
        col('o', gx2 + 2 * s + 44, [0, 1, 2, 3, 4, 5, 6, 7].map((k) => (o >> k) & 1), (r) => (lit === undefined || lit === r ? 'hot' : ''), h2(o));
        items.push({ key: 'af:n', kind: 'text', x: px, y: top + 8 * s + 22, text: `bit 0 is at the top: ${h2(v)} becomes ${h2(o)}`, size: narrow ? 12 : 13 });
        return items;
      };
      const view = L.view;
      const B = (i) => i === pick;
      const frames = [];
      frames.push({ view, items: [...ga.items, ...gridB(() => false, () => '').items, ...arrow], say: `The state entering round 1 is the plaintext \`${'Lanterns at dusk'}\` XORed with the key. SubBytes replaces each of its 16 bytes by looking it up in the S-box.` });
      frames.push({ view, items: [...gridA((i) => (B(i) ? 'act' : '')).items, ...gridB(() => false, () => '').items, ...arrow, panel('one byte, ' + cellName(pick)), ...callByte(0)], say: `Take the byte at ${cellName(pick)}: \`${h2(b)}\`. Read as a polynomial over GF(2), it is ${G.poly(b)}.` });
      frames.push({ view, items: [...gridA((i) => (B(i) ? 'act' : '')).items, ...gridB(() => false, () => '').items, ...arrow, panel('one byte, ' + cellName(pick)), ...callByte(1)], say: tr.trace[0].say.replace(/([0-9a-f]{2})(?=[ ,.]|$)/g, '`$1`') });
      frames.push({ view, items: [...gridA((i) => (B(i) ? 'act' : '')).items, ...gridB(() => false, () => '').items, ...arrow, panel('one byte, ' + cellName(pick)), ...callByte(1), ...affine(0)], say: `Bit 0 of the output is the XOR of bits 0, 4, 5, 6 and 7 of \`${h2(tr.inv)}\` with bit 0 of \`63\`: ${tr.trace[1].bits[0].src.join(' ⊕ ')} ⊕ ${tr.trace[1].bits[0].c} = ${tr.trace[1].bits[0].bit}. Each row of the matrix picks five bits the same way.` });
      frames.push({ view, items: [...gridA((i) => (B(i) ? 'act' : '')).items, ...gridB(B, () => 'hot').items, ...arrow, panel('one byte, ' + cellName(pick)), ...callByte(1), ...affine()], say: `${tr.trace[1].say.replace(/\b([0-9a-f]{2})\b/g, '`$1`')} So S(\`${h2(b)}\`) = \`${h2(tr.out)}\`, and it takes its place in the new state.` });
      frames.push({ view, items: [...gridA(() => '').items, ...gridB(() => true, (i) => (B(i) ? 'hot' : 'changed')).items, ...arrow], say: `Every byte goes through the same S-box, so the 256-entry table can be computed once. The new state's first column is \`${hex(out.slice(0, 4), ' ')}\`.` });
      return frames;
    },
  });

  // ---- ShiftRows --------------------------------------------------------------------------------------------
  D.add({
    id: 'aes-shiftrows', order: 11, tag: 'AES · round step', short: 'ShiftRows', title: 'ShiftRows: row r turns left by r places',
    blurb: 'Coloured by the column each byte started in: after ShiftRows every column holds one byte from each of the four.',
    frames({ narrow }) {
      const r1 = run().rounds[1], st = r1.sub;
      const L = narrow
        ? { view: box(-34, -34, 400, 520), cw: 46, ch: 38, gap: 5, size: 15, a: [0, 0], b: [0, 260], note: [222, 260] }
        : { view: box(0, -40, 1000, 340), cw: 64, ch: 52, gap: 6, size: 18, a: [40, 30], b: [430, 30], note: [730, 30] };
      const colCls = (i) => 'col' + Math.floor(i / 4);
      const before = BY.grid({ prefix: 'sr0', x: L.a[0], y: L.a[1], values: st, cw: L.cw, ch: L.ch, gap: L.gap, size: L.size, title: 'after SubBytes', cls: colCls });
      const pitch = L.cw + L.gap, rowH = L.ch + L.gap;
      // the moving grid: cells keep the key of the byte they hold, so a shift glides
      const after = (k) => {
        const items = [{ key: 'sr1:title', kind: 'text', x: L.b[0], y: L.b[1] - 12, text: k ? 'after ShiftRows' : 'shifting rows', cls: 'title' }];
        for (let i = 0; i < 16; i++) {
          const r = i % 4, c = Math.floor(i / 4), shift = r <= k ? r : 0, nc = (c - shift + 4) % 4;
          items.push({ key: 'sr1:' + i, kind: 'cell', x: L.b[0] + nc * pitch, y: L.b[1] + r * rowH, w: L.cw, h: L.ch, rx: 5, text: h2(st[i]), size: L.size, cls: 'hex ' + colCls(i) + (r === k && k > 0 ? ' ring' : '') });
        }
        return items;
      };
      const notes = (k) => [0, 1, 2, 3].map((r) => ({ key: 'srn' + r, kind: 'text', x: L.note[0], y: L.b[1] + r * rowH + L.ch / 2 + 5, text: narrow ? (r ? '← ' + r : '· 0') : (r ? `row ${r}: ${r} place${r > 1 ? 's' : ''} left` : 'row 0: stays'), cls: r === k ? 'act' : r < k ? 'strong' : '', size: narrow ? 14 : 15, dim: r > k }));
      const out = A.shiftRows(st);
      const view = L.view, frames = [];
      const say = ['Row 0 stays where it is. The colours say which column each byte came from.', `Row 1 turns one place left: \`${A.rows(st)[1]}\` becomes \`${A.rows(out)[1]}\`.`, `Row 2 turns two places: \`${A.rows(st)[2]}\` becomes \`${A.rows(out)[2]}\`.`, `Row 3 turns three places, the same as one place right: \`${A.rows(st)[3]}\` becomes \`${A.rows(out)[3]}\`.`];
      for (let k = 0; k < 4; k++) frames.push({ view, items: [...before.items, ...after(k), ...notes(k)], say: say[k] });
      frames.push({ view, items: [...BY.grid({ prefix: 'sr0', x: L.a[0], y: L.a[1], values: st, cw: L.cw, ch: L.ch, gap: L.gap, size: L.size, title: 'after SubBytes', cls: (i) => colCls(i) + ([0, 5, 10, 15].includes(i) ? ' ring' : '') }).items.map((it) => (/^sr0:\d+$/.test(it.key) && ![0, 5, 10, 15].includes(+it.key.slice(4)) ? Object.assign({}, it, { dim: true }) : it)), ...after(3).map((it) => (it.key.startsWith('sr1:') && it.kind === 'cell' ? Object.assign({}, it, { cls: it.cls.replace(' ring', '') + ([0, 5, 10, 15].includes(+it.key.slice(4)) ? ' ring' : '') }) : it)), ...notes(4)],
        say: `Now column 0 holds \`${hex(out.slice(0, 4), ' ')}\`: one byte from each input column, taken along a diagonal. MixColumns will mix each column, so after two rounds every byte depends on every input byte.` });
      return frames;
    },
  });

  // ---- MixColumns -------------------------------------------------------------------------------------------
  D.add({
    id: 'aes-mixcolumns', order: 12, tag: 'AES · round step', short: 'MixColumns', title: 'MixColumns: a matrix times each column, over GF(2⁸)',
    blurb: 'Multiplying by 02 is xtime (a shift, and XOR 1b if a bit fell off); 03·b is 02·b ⊕ b; addition is XOR.',
    frames({ narrow }) {
      const r1 = run().rounds[1], st = r1.shift, after = r1.mix, c = 2, col = st.slice(4 * c, 4 * c + 4), mc = A.mixColumn(col);
      const L = narrow
        ? { view: box(-8, -34, 396, 584), sg: [96, 0], scw: 38, sch: 30, m: [0, 200], cw: 42, ch: 36, lines: [0, 400], fs: 13 }
        : { view: box(-10, -40, 1100, 470), sg: [20, 30], scw: 52, sch: 42, m: [320, 30], cw: 50, ch: 42, lines: [320, 260], fs: 15, after: [830, 30] };
      const g = 4, pitch = L.cw + g;
      const state = (lit, done) => BY.grid({ prefix: 'mcs', x: L.sg[0], y: L.sg[1], values: done ? after : st, cw: L.scw, ch: L.sch, gap: 4, size: narrow ? 13 : 16, title: done ? 'after MixColumns' : 'after ShiftRows', cls: (i) => (Math.floor(i / 4) === c ? (done ? 'hot' : 'act') : '') });
      const mx = L.m[0], my = L.m[1];
      const vx = mx + 4 * pitch + 30, rx = vx + L.cw + 40;
      const mat = (row) => {
        const items = [{ key: 'mc:mt', kind: 'text', x: mx, y: my - 12, text: 'matrix', cls: 'title' }, { key: 'mc:vt', kind: 'text', x: vx, y: my - 12, text: 'column ' + c, cls: 'title' }, { key: 'mc:rt', kind: 'text', x: rx, y: my - 12, text: 'result', cls: 'title' }];
        for (let r = 0; r < 4; r++) for (let k = 0; k < 4; k++) items.push({ key: `mc:m${r}${k}`, kind: 'cell', x: mx + k * pitch, y: my + r * (L.ch + g), w: L.cw, h: L.ch, rx: 4, text: h2(A.MIX[r][k]), size: L.fs + 1, cls: 'hex ' + (r === row ? 'act' : 'soft') });
        for (let r = 0; r < 4; r++) items.push({ key: 'mc:v' + r, kind: 'cell', x: vx, y: my + r * (L.ch + g), w: L.cw, h: L.ch, rx: 4, text: h2(col[r]), size: L.fs + 1, cls: 'hex ' + (row !== undefined && row >= 0 ? 'act' : '') });
        for (let r = 0; r < 4; r++) items.push({ key: 'mc:r' + r, kind: 'cell', x: rx, y: my + r * (L.ch + g), w: L.cw, h: L.ch, rx: 4, text: row === undefined || r <= row ? h2(mc.out[r]) : '', size: L.fs + 1, cls: 'hex ' + (r === row ? 'hot' : row === undefined || r < row ? '' : 'soft') });
        const midY = my + 2 * (L.ch + g) - g / 2;
        items.push({ key: 'mc:dot', kind: 'text', x: vx - 15, y: midY + 6, text: '·', anchor: 'middle', size: 22, cls: 'strong' });
        items.push({ key: 'mc:eq', kind: 'text', x: rx - 20, y: midY + 6, text: '=', anchor: 'middle', size: 20, cls: 'strong' });
        return items;
      };
      // the arithmetic of one row: the products, how 02 and 03 were done, the sum
      const work = (r) => {
        const t = mc.trace[r], items = [], x0 = L.lines[0], y0 = L.lines[1], lh = narrow ? 22 : 27, fs = L.fs;
        const prod = (m, b) => (m === 1 ? `01·${h2(b)} = ${h2(b)}` : m === 2 ? `02·${h2(b)} = ${h2(G.xtime(b))}${b & 0x80 ? ' (1b in)' : ''}` : `03·${h2(b)} = ${h2(G.xtime(b))} ⊕ ${h2(b)} = ${h2(G.xtime(b) ^ b)}`);
        items.push({ key: 'mcw:h', kind: 'text', x: x0, y: y0, text: `row ${r}`, cls: 'title' });
        A.MIX[r].forEach((m, k) => items.push({ key: 'mcw:p' + k, kind: 'text', x: x0, y: y0 + 26 + k * lh, text: prod(m, col[k]), cls: 'math', size: fs }));
        items.push({ key: 'mcw:s', kind: 'text', x: x0, y: y0 + 26 + 4 * lh + 6, text: `${t.terms.map(h2).join(' ⊕ ')} = ${h2(t.v)}`, cls: 'mono hot', size: fs + 1 });
        return items;
      };
      const view = L.view, frames = [];
      frames.push({ view, items: [...state(true).items, ...mat(-1)], say: `MixColumns works on one column at a time. Take column ${c}, \`${hex(col, ' ')}\`, and multiply it by the fixed matrix. Every product is in GF(2⁸), and the sums are XORs.` });
      for (let r = 0; r < 4; r++) frames.push({ view, items: [...state(true).items, ...mat(r), ...work(r)], say: `Row ${r}: ${mc.trace[r].say.replace(/^Row \d+: /, '').replace(/\b([0-9a-f]{2})\b/g, '`$1`')}` });
      const fin = narrow ? state(true, true).items : [...state(true).items, ...BY.grid({ prefix: 'mca', x: L.after[0], y: L.after[1], values: after, cw: L.scw, ch: L.sch, gap: 4, size: 16, title: 'after MixColumns', cls: (i) => (Math.floor(i / 4) === c ? 'hot' : ''), enter: 'fade' }).items];
      if (!narrow) fin.push({ key: 'mc:back', kind: 'wire', pts: [[rx + L.cw + 12, my + 2 * (L.ch + g) - g / 2], [L.after[0] - 12, my + 2 * (L.ch + g) - g / 2]], head: true, cls: 'act' });
      frames.push({ view, items: [...fin, ...mat()], say: `Column ${c} becomes \`${hex(mc.out, ' ')}\`. Change one input byte and all four output bytes change: that is the diffusion this step adds.` });
      return frames;
    },
  });

  // ---- the key expansion ------------------------------------------------------------------------------------
  D.add({
    id: 'aes-keyexp', order: 13, tag: 'AES · key schedule', short: 'Key expansion', title: 'The key expansion: words, and the g-function',
    blurb: 'Each new word is the word four back XOR the word just before it; at every fourth word that one first goes through g.',
    frames({ narrow }) {
      const ex = A.expandKey(D.data.aesKey), w = ex.w, N = 12;
      const L = narrow
        ? { view: box(-8, -30, 400, 740), cw: 38, ch: 26, gap: 3, colGap: 8, size: 14, strip: [0, 0], perRow: 4, lane: [0, 470], lcw: 42, lch: 28, lfs: 14 }
        : { view: box(-20, -40, 1160, 560), cw: 44, ch: 30, gap: 3, colGap: 10, size: 14, strip: [20, 20], perRow: 12, lane: [20, 250], lcw: 48, lch: 30, lfs: 15 };
      const pitch = L.cw + L.colGap;
      const rowH = 4 * (L.ch + L.gap) + (narrow ? 44 : 66);
      const at = (i) => ({ x: L.strip[0] + (i % L.perRow) * pitch + Math.floor((i % L.perRow) / 4) * (narrow ? 8 : 26), y: L.strip[1] + Math.floor(i / L.perRow) * rowH });
      // the strip of words: a column of four bytes each, grouped into round keys
      const strip = (upto, src, dst) => {
        const items = [];
        for (let i = 0; i < N; i++) {
          const p = at(i), on = i <= upto;
          items.push({ key: 'kw:l' + i, kind: 'text', x: p.x + L.cw / 2, y: p.y - 8, text: 'w' + i, anchor: 'middle', size: narrow ? 12 : 13, cls: dst === i ? 'hot' : src.includes(i) ? 'act' : 'strong' });
          for (let b = 0; b < 4; b++) items.push({ key: `kw:${i}:${b}`, kind: 'cell', x: p.x, y: p.y + b * (L.ch + L.gap), w: L.cw, h: L.ch, rx: 3, text: on ? h2(w[i][b]) : '', size: L.size, cls: 'hex ' + (!on ? 'soft' : dst === i ? 'hot' : src.includes(i) ? 'act' : 'key') });
        }
        for (let k = 0; k < N / 4; k++) {
          const a = at(4 * k), b = at(4 * k + 3);
          if (narrow) items.push({ key: 'kw:br' + k, kind: 'text', x: b.x + L.cw + 18, y: a.y + 2 * (L.ch + L.gap) + 4, text: 'round key ' + k, cls: 'key', size: 14 });
          else items.push({ key: 'kw:br' + k, kind: 'bracket', x1: a.x, x2: b.x + L.cw, y: a.y + 4 * (L.ch + L.gap) + 2, side: 'below', text: 'round key ' + k, cls: 'key' });
        }
        return items;
      };
      // the lane: one word's computation drawn as a chain of columns
      const colAt = (key, x, y, bytes, cls, title, tcls) => {
        const items = [{ key: key + ':t', kind: 'text', x: x + L.lcw / 2, y: y - 9, text: title, anchor: 'middle', size: narrow ? 12 : 13, cls: tcls || 'strong' }];
        bytes.forEach((v, b) => items.push({ key: key + ':' + b, kind: 'cell', x, y: y + b * (L.lch + 2), w: L.lcw, h: L.lch, rx: 3, text: v === null ? '' : h2(v), size: L.lfs, cls: 'hex ' + (cls || '') }));
        return items;
      };
      const H = 4 * (L.lch + 2) - 2;
      const gLane = (i, stage) => {
        const g = A.g(w[i - 1], i), N2 = F.net('kg');
        const x0 = L.lane[0], y0 = L.lane[1], sp = narrow ? 64 : 128, midY = y0 + H / 2;
        const xs = narrow ? [0, 120, 240] : [0, 150, 300, 470, 640, 800];
        const items = [];
        items.push(...colAt('kg:in', x0 + xs[0], y0, w[i - 1], 'act', 'w' + (i - 1), 'act'));
        const arrow = (k, xa, xb, label) => { N2.wire('a' + k, [[xa, midY], [xb, midY]], { head: true }); if (label) N2.label('al' + k, (xa + xb) / 2, midY - 10, label, 'strong', 'middle', narrow ? 11 : 13); };
        if (stage >= 1) { items.push(...colAt('kg:rot', x0 + xs[1], y0, g.rot, stage === 1 ? 'hot' : '', 'rotated')); arrow(1, x0 + xs[0] + L.lcw + 6, x0 + xs[1] - 6, narrow ? '' : 'RotWord'); }
        if (stage >= 2) { items.push(...colAt('kg:sub', x0 + xs[2], y0, g.sub, stage === 2 ? 'hot' : '', 'S-box')); arrow(2, x0 + xs[1] + L.lcw + 6, x0 + xs[2] - 6, narrow ? '' : 'SubWord'); }
        if (stage >= 3 && !narrow) {
          const ox = x0 + xs[3];
          N2.op('x1', ox, midY, 'xor');
          N2.wire('a3', [[x0 + xs[2] + L.lcw + 6, midY], N2.port('x1', 'w')], { head: true });
          items.push(...colAt('kg:rc', ox - L.lcw / 2, midY + 56, [g.rc, 0, 0, 0], 'key', 'Rcon', 'key'));
          N2.wire('rc', [[ox, midY + 56 - 24], N2.port('x1', 's')], { head: true, cls: 'key' });
          items.push(...colAt('kg:g', x0 + xs[4], y0, g.out, stage === 3 ? 'hot' : '', 'g(w' + (i - 1) + ')'));
          N2.wire('a4', [N2.port('x1', 'e'), [x0 + xs[4] - 6, midY]], { head: true });
        }
        return items.concat(N2.items);
      };
      // a word from two: w(i−4) ⊕ v = w(i)
      const xorLane = (i, viaG) => {
        const N2 = F.net('kx'), x0 = L.lane[0] + (narrow ? 0 : (viaG ? 640 : 300)), y0 = L.lane[1], midY = y0 + H / 2;
        const a = w[i - 4], bb = viaG ? A.g(w[i - 1], i).out : w[i - 1], items = [];
        const gap = narrow ? 70 : 90;
        if (!viaG || narrow) items.push(...colAt('kx:b', x0, y0, bb, 'act', viaG ? 'g(w' + (i - 1) + ')' : 'w' + (i - 1), 'act'));
        const ox = x0 + L.lcw + gap / 2 + 10;
        N2.op('x', ox, midY, 'xor');
        N2.wire('in', [[x0 + L.lcw + 6, midY], N2.port('x', 'w')], { head: true });
        items.push(...colAt('kx:a', ox - L.lcw / 2, midY + 56, a, 'act', 'w' + (i - 4), 'act'));
        N2.wire('a', [[ox, midY + 56 - 24], N2.port('x', 's')], { head: true });
        items.push(...colAt('kx:o', ox + gap / 2 + 20, y0, w[i], 'hot', 'w' + i, 'hot'));
        N2.wire('out', [N2.port('x', 'e'), [ox + gap / 2 + 14, midY]], { head: true });
        return items.concat(N2.items);
      };
      const view = L.view, frames = [];
      const wh = (v) => hex(v);
      frames.push({ view, items: [...strip(3, [], -1)], say: `The 16-byte key \`ochre-river-2026\` is cut into four words: w0 = \`${wh(w[0])}\`, w1 = \`${wh(w[1])}\`, w2 = \`${wh(w[2])}\`, w3 = \`${wh(w[3])}\`. They are round key 0.` });
      const t4 = A.g(w[3], 4);
      frames.push({ view, items: [...strip(3, [3], -1), ...gLane(4, 1)], say: `w4 needs g(w3). First RotWord turns the word one byte up: \`${wh(w[3])}\` becomes \`${wh(t4.rot)}\`.` });
      frames.push({ view, items: [...strip(3, [3], -1), ...gLane(4, 2)], say: `SubWord puts each byte through the AES S-box: \`${wh(t4.rot)}\` becomes \`${wh(t4.sub)}\`.` });
      if (!narrow) frames.push({ view, items: [...strip(3, [3], -1), ...gLane(4, 3)], say: `The round constant for this round is \`${h2(t4.rc)}\`, XORed into the first byte only: g(w3) = \`${wh(t4.out)}\`.` });
      frames.push({ view, items: [...strip(4, [0, 3], 4), ...(narrow ? [] : gLane(4, 3)), ...xorLane(4, true)], say: `w4 = w0 ⊕ g(w3) = \`${wh(w[0])}\` ⊕ \`${wh(t4.out)}\` = \`${wh(w[4])}\`.` });
      for (const i of [5, 6, 7]) frames.push({ view, items: [...strip(i, [i - 4, i - 1], i), ...xorLane(i, false)], say: `w${i} = w${i - 4} ⊕ w${i - 1} = \`${wh(w[i - 4])}\` ⊕ \`${wh(w[i - 1])}\` = \`${wh(w[i])}\`. No g here: only every fourth word goes through it.` });
      const t8 = A.g(w[7], 8);
      frames.push({ view, items: [...strip(8, [4, 7], 8), ...(narrow ? [] : gLane(8, 3)), ...xorLane(8, true)], say: `w8 starts round key 2, so g comes back, now with the round constant \`${h2(t8.rc)}\`: g(w7) = \`${wh(t8.out)}\`, and w8 = w4 ⊕ g(w7) = \`${wh(w[8])}\`.` });
      frames.push({ view, items: [...strip(11, [], -1)], say: `The same steps give w9 to w43: eleven round keys of four words. The last word is \`${wh(w[43])}\`.` });
      return frames;
    },
  });

  // ---- the avalanche ----------------------------------------------------------------------------------------
  D.add({
    id: 'aes-avalanche', order: 14, tag: 'AES · diffusion', short: 'Avalanche', title: 'The avalanche: one plaintext bit, round by round',
    blurb: 'Two plaintexts that differ in one bit, run side by side. Each grid is the XOR of their states after a round: the hotter a byte, the more of its bits differ.',
    frames({ narrow }) {
      const P0 = D.data.aesPlain, P1 = Uint8Array.from(P0), byte = 9, bit = 2;
      P1[byte] ^= 1 << bit;
      const a = A.encrypt(P0, D.data.aesKey), b = A.encrypt(P1, D.data.aesKey);
      const diffs = a.rounds.map((r, k) => r.end.map((v, i) => v ^ b.rounds[k].end[i]));
      const count = diffs.map((d) => d.reduce((n, v) => n + S.bytes.popcount(v), 0));
      const L = narrow
        ? { view: box(-6, -10, 396, 780), per: 3, cw: 26, ch: 22, gap: 3, fs: 12, sx: 136, sy: 168, top: 76, chart: null }
        : { view: box(-20, -10, 1160, 520), per: 6, cw: 33, ch: 27, gap: 3, fs: 13, sx: 186, sy: 196, top: 84, chart: true };
      const pos = (r) => ({ x: (r % L.per) * L.sx, y: L.top + Math.floor(r / L.per) * L.sy });
      const grid = (r, now) => {
        const p = pos(r), d = diffs[r];
        const g = BY.grid({ prefix: 'av' + r, x: p.x, y: p.y + 22, values: d, cw: L.cw, ch: L.ch, gap: L.gap, size: L.fs, rx: 3, cls: (i, rr, c, v) => 'hframe h' + S.bytes.popcount(v) });
        return [{ key: 'av' + r + ':t', kind: 'text', x: p.x, y: p.y + 12, text: r === 0 ? 'after round 0' : 'round ' + r, size: narrow ? 12 : 13, cls: now ? 'act' : 'strong' }, ...g.items,
          { key: 'av' + r + ':n', kind: 'text', x: p.x, y: p.y + 22 + 4 * (L.ch + L.gap) + 16, text: count[r] + (count[r] === 1 ? ' bit differs' : ' bits differ'), size: narrow ? 12 : 13, cls: now ? 'heat' : '' }];
      };
      const head = [];
      const pw = narrow ? 20 : 30, ph = narrow ? 20 : 24, px0 = narrow ? 24 : 34;
      [[P0, 'P'], [P1, 'P′']].forEach(([u, name], j) => {
        head.push({ key: 'av:pn' + j, kind: 'text', x: 0, y: j * (ph + 6) + ph / 2 + 5, text: name, cls: 'strong', size: narrow ? 13 : 14 });
        for (let i = 0; i < 16; i++) head.push({ key: `av:p${j}:${i}`, kind: 'cell', x: px0 + i * (pw + 2), y: j * (ph + 6), w: pw, h: ph, rx: 3, text: h2(u[i]), size: narrow ? 12 : 13, cls: 'hex ' + (i === byte ? 'h4 hframe' : 'soft') });
      });
      if (!narrow) head.push({ key: 'av:note', kind: 'text', x: px0 + 16 * (pw + 2) + 20, y: ph + 8, text: `byte ${byte}, bit ${bit} flipped: ${h2(P0[byte])} → ${h2(P1[byte])}`, cls: 'heat', size: 14 });
      // a small bar chart of the differing bits per round, against the 64 of two unrelated blocks
      const chart = (upto) => {
        if (!L.chart) return [];
        const x0 = 5 * L.sx + 8, y0 = L.top + L.sy + 26, Hh = 4 * (L.ch + L.gap) - 6, bw = 11, items = [];
        items.push({ key: 'ch:t', kind: 'text', x: x0 - 8, y: y0 - 14, text: 'bits that differ', size: 13, cls: 'strong' });
        items.push({ key: 'ch:base', kind: 'line', x1: x0, y1: y0 + Hh, x2: x0 + 11 * (bw + 3), y2: y0 + Hh, cls: 'rule' });
        const yOf = (n) => y0 + Hh - (n / 128) * Hh;
        items.push({ key: 'ch:64', kind: 'line', x1: x0, y1: yOf(64), x2: x0 + 11 * (bw + 3), y2: yOf(64), cls: 'dash', audit: 'ignore', layer: 'top' });
        items.push({ key: 'ch:64t', kind: 'text', x: x0 + 11 * (bw + 3) + 6, y: yOf(64) + 4, text: '64', size: 12 });
        items.push({ key: 'ch:r0', kind: 'text', x: x0 + bw / 2, y: y0 + Hh + 16, text: '0', size: 12, anchor: 'middle' });
        items.push({ key: 'ch:r10', kind: 'text', x: x0 + 10 * (bw + 3) + bw / 2, y: y0 + Hh + 16, text: '10', size: 12, anchor: 'middle' });
        items.push({ key: 'ch:rl', kind: 'text', x: x0 + 5 * (bw + 3) + bw / 2, y: y0 + Hh + 16, text: 'round', size: 12, anchor: 'middle' });
        for (let r = 0; r <= upto; r++) items.push({ key: 'ch:b' + r, kind: 'cell', x: x0 + r * (bw + 3), y: yOf(count[r]), w: bw, h: Math.max(1, yOf(0) - yOf(count[r])), rx: 1, text: '', cls: 'h' + Math.min(8, Math.round(count[r] / 8)) + ' hframe', enter: 'grow' });
        return items;
      };
      const view = L.view, frames = [];
      for (let r = 0; r <= 10; r++) {
        const items = [...head];
        for (let k = 0; k <= r; k++) items.push(...grid(k, k === r));
        items.push(...chart(r));
        const say = r === 0 ? `The two plaintexts differ in one bit (byte ${byte}, bit ${bit}). AddRoundKey XORs the same key into both, so after round 0 they still differ in exactly one bit.`
          : r === 1 ? `Round 1: SubBytes turns \`${h2(a.rounds[1].start[byte])}\` and \`${h2(b.rounds[1].start[byte])}\` into \`${h2(a.rounds[1].sub[byte])}\` and \`${h2(b.rounds[1].sub[byte])}\`, which differ in ${S.bytes.popcount(a.rounds[1].sub[byte] ^ b.rounds[1].sub[byte])} bits. MixColumns then spreads that byte over its whole column: ${diffs[1].filter((v) => v).length} bytes differ, ${count[1]} bits in all.`
            : r === 2 ? `Round 2: ShiftRows sends those four bytes to four columns, and MixColumns fills each: ${diffs[2].filter((v) => v).length} of 16 bytes differ (${count[2]} bits).`
              : r === 10 ? `After round 10 the ciphertexts differ in ${count[10]} of 128 bits; two unrelated blocks differ in 64 on average. Nothing of the single flipped bit is left to see.`
                : `Round ${r}: ${count[r]} bits differ. From round 2 on the count just wanders around 64, as it would for two random blocks.`;
        frames.push({ view, items, say });
      }
      return frames;
    },
  });
})(globalThis.Sifer = globalThis.Sifer || {});
