// Bytes and bits on the stage: a state of bytes or words as a grid of hex cells (the AES 4×4 state, the ChaCha
// word state), rows of bits that light up, the heat map of a difference, and the Keccak state as lanes of bits
// with an isometric hint of the 5×5×64 block.
//   S.Kit.bytes.grid({prefix, x, y, values, rows, cols, order: 'col'|'row', cw, ch, gap, fmt, cls(i, r, c, v), size,
//     rowHead, colHead, title}) -> {items, key(i), box, cellBox(i), centre(i)}
//   S.Kit.bytes.bits({prefix, x, y, bits, cw, ch, group, groupGap, cls(i, b), size, index}) -> {items, box, centre(i)}
//   S.Kit.bytes.heat(a, b) -> per byte the number of differing bits (0..8), the class 'h0'..'h8' of a heat cell
//   S.Kit.bytes.lanes({prefix, x, y, A (25 BigInt lanes), cw, ch, look(x, y, z, bit) -> '0'..'7'}) -> {items, box, cell(x, y, z)}
//   S.Kit.bytes.iso({prefix, x, y, s, depth, hot: [{x, z}], act: [{x, z}]}) -> {items, box}
(function (S) {
  'use strict';
  const K = (S.Kit = S.Kit || {});
  const BY = (K.bytes = {});
  const Geo = () => S.geom;
  const r2 = (v) => Math.round(v * 100) / 100;
  const h2 = (v) => (v & 255).toString(16).padStart(2, '0');

  BY.grid = function (o) {
    const P = o.prefix || 'g', R = o.rows || 4, C = o.cols || 4, cw = o.cw || 56, ch = o.ch || 44, gap = o.gap === undefined ? 4 : o.gap;
    const fmt = o.fmt || h2, colMajor = (o.order || 'col') === 'col';
    const x0 = (o.x || 0) + (o.rowHead ? (o.rowHeadW || 34) : 0), y0 = (o.y || 0) + (o.colHead ? 24 : 0);
    const items = [];
    const idx = (r, c) => (colMajor ? r + R * c : c + C * r);
    const cellBox = (i) => { const r = colMajor ? i % R : Math.floor(i / C), c = colMajor ? Math.floor(i / R) : i % C; return { x: x0 + c * (cw + gap), y: y0 + r * (ch + gap), w: cw, h: ch }; };
    if (o.title) items.push({ key: P + ':title', kind: 'text', x: o.x || 0, y: (o.y || 0) - 12, text: o.title, cls: 'title' + (o.titleCls ? ' ' + o.titleCls : '') });
    if (o.colHead) for (let c = 0; c < C; c++) items.push({ key: P + ':ch:' + c, kind: 'text', x: r2(x0 + c * (cw + gap) + cw / 2), y: y0 - 8, text: o.colHead[c], anchor: 'middle', size: 12, cls: 'colhead' });
    if (o.rowHead) for (let r = 0; r < R; r++) items.push({ key: P + ':rh:' + r, kind: 'text', x: x0 - 10, y: r2(y0 + r * (ch + gap) + ch / 2 + 4), text: o.rowHead[r], anchor: 'end', size: 12 });
    for (let r = 0; r < R; r++) for (let c = 0; c < C; c++) {
      const i = idx(r, c), b = cellBox(i), v = o.values[i];
      const it = { key: P + ':' + i, kind: 'cell', x: r2(b.x), y: r2(b.y), w: cw, h: ch, rx: o.rx === undefined ? 5 : o.rx, text: v === null || v === undefined ? '' : fmt(v, i), cls: ['hex', o.cls ? o.cls(i, r, c, v) || '' : ''].join(' ').trim() };
      if (o.size) it.size = o.size;
      if (o.enter) it.enter = o.enter;
      items.push(it);
    }
    const W = C * cw + (C - 1) * gap, H = R * ch + (R - 1) * gap;
    const box = { x: o.x || 0, y: (o.y || 0) - (o.title ? 24 : 0), w: W + (x0 - (o.x || 0)), h: H + (y0 - (o.y || 0)) + (o.title ? 24 : 0) };
    return { items, key: (i) => P + ':' + i, box, cellBox, centre: (i) => { const b = cellBox(i); return { x: b.x + b.w / 2, y: b.y + b.h / 2 }; }, inner: { x: x0, y: y0, w: W, h: H } };
  };

  /** a word or byte as bits, most significant first */
  BY.toBits = (v, n) => { const out = []; if (typeof v === 'bigint') for (let i = n - 1; i >= 0; i--) out.push(Number((v >> BigInt(i)) & 1n)); else for (let i = n - 1; i >= 0; i--) out.push((v >>> i) & 1); return out; };

  BY.bits = function (o) {
    const P = o.prefix || 'b', bits = o.bits, cw = o.cw || 16, ch = o.ch || 22, g = o.group || 8, gg = o.groupGap === undefined ? 6 : o.groupGap, gap = o.gap === undefined ? 1 : o.gap;
    const items = [];
    const xOf = (i) => (o.x || 0) + i * (cw + gap) + Math.floor(i / g) * gg;
    bits.forEach((b, i) => {
      const it = { key: P + ':' + i, kind: 'cell', x: r2(xOf(i)), y: o.y || 0, w: cw, h: ch, rx: 2, text: o.text === false ? '' : String(b), cls: ['bit', b ? 'one' : 'zero', o.cls ? o.cls(i, b) || '' : ''].join(' ').trim() };
      if (o.size) it.size = o.size;
      items.push(it);
    });
    if (o.index) for (let i = 0; i < bits.length; i += g) items.push({ key: P + ':ix:' + i, kind: 'text', x: r2(xOf(i)), y: (o.y || 0) + ch + 14, text: String(o.index(i)), size: 11, cls: 'ix', audit: 'small-ok' });
    const W = xOf(bits.length - 1) + cw - (o.x || 0);
    return { items, box: { x: o.x || 0, y: o.y || 0, w: W, h: ch }, centre: (i) => ({ x: xOf(i) + cw / 2, y: (o.y || 0) + ch / 2 }), xOf };
  };

  BY.heat = (a, b) => Array.from(a, (v, i) => { let x = (v ^ b[i]) & 255, n = 0; while (x) { n += x & 1; x >>= 1; } return n; });

  /** the Keccak state as 25 rows of 64 bits: row x + 5y is lane (x, y); bit z runs left to right */
  BY.lanes = function (o) {
    const P = o.prefix || 'kl', cw = o.cw || 14, ch = o.ch || 12, A = o.A, look = o.look || ((x, y, z, b) => (b ? '1' : '0'));
    const rows = [];
    for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) {
      let s = '';
      const v = A[x + 5 * y];
      for (let z = 0; z < 64; z++) s += look(x, y, z, Number((v >> BigInt(z)) & 1n));
      rows.push(s);
    }
    // a little gap between the five groups of lanes with the same y
    const items = [];
    for (let y = 0; y < 5; y++) items.push({ key: P + ':bm' + y, kind: 'bitmap', x: o.x, y: r2(o.y + y * (5 * ch + (o.ygap || 6))), cw, ch, gap: o.cellGap === undefined ? 1.5 : o.cellGap, rows: rows.slice(5 * y, 5 * y + 5) });
    const cell = (x, y, z) => ({ x: o.x + z * cw, y: o.y + y * (5 * ch + (o.ygap || 6)) + x * ch, w: cw, h: ch });
    return { items, box: { x: o.x, y: o.y, w: 64 * cw, h: 25 * ch + 4 * (o.ygap || 6) }, cell };
  };

  /**
   * An isometric hint of the 5×5×w state: the front face is the 5×5 slice (x across, y up), the block runs back
   * along z. hot and act light whole columns (all five y at one x and z) on the top face, as θ reads them.
   */
  BY.iso = function (o) {
    const P = o.prefix || 'iso', s = o.s || 22, D = o.depth || 150, n = o.slices || 16;
    const dx = D * 0.62, dy = -D * 0.42, x0 = o.x || 0, y0 = (o.y || 0) - dy;
    const items = [];
    const pt = (x, y, z) => [r2(x0 + x * s + (z / n) * dx), r2(y0 + (5 - y) * s + (z / n) * dy)];
    const poly = (ps) => 'M' + ps.map((p) => p.join(',')).join(' L') + ' Z';
    // three faces
    items.push({ key: P + ':side', kind: 'path', cls: 'iso side', d: poly([pt(5, 0, 0), pt(5, 0, n), pt(5, 5, n), pt(5, 5, 0)]), audit: 'ignore' });
    items.push({ key: P + ':top', kind: 'path', cls: 'iso top', d: poly([pt(0, 5, 0), pt(5, 5, 0), pt(5, 5, n), pt(0, 5, n)]), audit: 'ignore' });
    items.push({ key: P + ':front', kind: 'path', cls: 'iso', d: poly([pt(0, 0, 0), pt(5, 0, 0), pt(5, 5, 0), pt(0, 5, 0)]), audit: 'ignore' });
    // columns lit on the top face: column (x, z) is the strip from (x, 5, z) to (x + 1, 5, z + 1)
    for (const [cls, list] of [['hot', o.hot || []], ['act', o.act || []]]) for (const c of list) items.push({ key: P + ':' + cls + c.x + '-' + c.z, kind: 'path', cls: 'iso ' + cls, d: poly([pt(c.x, 5, c.z), pt(c.x + 1, 5, c.z), pt(c.x + 1, 5, c.z + 1), pt(c.x, 5, c.z + 1)]) + ' ' + poly([pt(c.x, 0, c.z), pt(c.x + 1, 0, c.z), pt(c.x + 1, 5, c.z), pt(c.x, 5, c.z)]), audit: 'ignore' });
    // the grid lines of the front face and the slices on the top
    let d = '';
    for (let k = 1; k < 5; k++) { d += 'M' + pt(k, 0, 0).join(',') + ' L' + pt(k, 5, 0).join(',') + ' M' + pt(0, k, 0).join(',') + ' L' + pt(5, k, 0).join(',') + ' '; }
    for (let k = 1; k < 5; k++) d += 'M' + pt(k, 5, 0).join(',') + ' L' + pt(k, 5, n).join(',') + ' M' + pt(5, k, 0).join(',') + ' L' + pt(5, k, n).join(',') + ' ';
    for (let z = 1; z < n; z++) d += 'M' + pt(0, 5, z).join(',') + ' L' + pt(5, 5, z).join(',') + ' L' + pt(5, 0, z).join(',') + ' ';
    items.push({ key: P + ':lines', kind: 'path', cls: 'iso lines', d, audit: 'ignore' });
    const box = { x: x0, y: (o.y || 0), w: 5 * s + dx, h: 5 * s - dy };
    return { items, box, pt };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
