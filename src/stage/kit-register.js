// Shift registers on the stage: an LFSR in Fibonacci form (taps read cells and feed one XOR chain whose result
// enters at the left) and in Galois form (the output bit is fed back along the bottom and XORed in between the
// cells under the taps). The output leaves at the right. Cells, taps, the feedback path and the output are
// drawn so that no two wires cross.
//   S.Kit.reg.fib({prefix, x, y, bits, taps, cw, ch, gap, lit: {fb, out, taps}, label(col), cls(col, bit), fbBit, ids(col)})
//     ids(col) names the bit a cell holds, so a bit keeps its key and glides along as the register shifts
//     bits: the register, index 0 the oldest bit (the next output); taps: exponents k (the cell s(n−k));
//     drawn with the newest bit on the left: column c holds bits[L − 1 − c], and tap k reads column k − 1
//     -> {items, box, cell(col) -> {x, y, w, h}, xOut, yMid}
//   S.Kit.reg.galois({prefix, x, y, bits, taps, cw, ch, gap, xgap, lit, label(col), cls(col, bit), fbBit})
//     bits: r0 … r(L−1), r0 the next output; column c holds r(L − 1 − c); a tap k < L puts an XOR between columns
//     L − 1 − k and L − k, and the tap k = L feeds column 0 directly -> the same shape of result
(function (S) {
  'use strict';
  const K = (S.Kit = S.Kit || {});
  const R = (K.reg = {});
  const r2 = (v) => Math.round(v * 100) / 100;

  /** the cells of a register in a row, with optional labels under them; xs: the left edge of each column */
  const cells = (P, xs, y, cw, ch, colBits, o, items) => {
    colBits.forEach((b, c) => {
      const it = { key: P + (o.ids ? ':s' + o.ids(c) : ':c' + c), kind: 'cell', x: r2(xs[c]), y, w: cw, h: ch, rx: 4, text: b === null || b === undefined ? '' : String(b), size: o.size || 16, cls: ['bit', b ? 'one' : 'zero', o.cls ? o.cls(c, b) || '' : ''].join(' ').trim() };
      items.push(it);
      if (o.label) { const t = o.label(c); if (t !== null && t !== undefined && t !== '') items.push({ key: P + ':lb' + c, kind: 'text', x: r2(xs[c] + cw / 2), y: y + ch + 17, text: t, anchor: 'middle', size: o.labelSize || 13, cls: 'reglabel ' + (o.labelCls ? o.labelCls(c) || '' : '') }); }
    });
  };

  R.fib = function (o) {
    const P = o.prefix || 'rf', bits = o.bits, L = bits.length, cw = o.cw || 40, ch = o.ch || 40, gap = o.gap === undefined ? 6 : o.gap;
    const x0 = o.x || 0, y0 = o.y || 0, lit = o.lit || {}, items = [];
    const xs = Array.from({ length: L }, (_, c) => x0 + c * (cw + gap)), cx = (c) => r2(xs[c] + cw / 2);
    const colBits = Array.from({ length: L }, (_, c) => bits[L - 1 - c]);
    cells(P, xs, y0, cw, ch, colBits, o, items);
    const yx = y0 - (o.rise || 44), cols = [...new Set(o.taps)].map((k) => k - 1).sort((a, b) => a - b), wc = (on) => (on ? 'act' : '');
    const tapOn = !!lit.taps, fbOn = !!lit.fb;
    // the XOR chain: one ⊕ over every tapped column but the rightmost, which joins the chain from the east
    const opCols = cols.slice(0, -1), last = cols[cols.length - 1];
    for (const c of opCols) items.push({ key: P + ':x' + c, kind: 'op', x: cx(c), y: yx, r: 11, op: 'xor', cls: tapOn ? 'act' : '' });
    for (const c of cols) {
      const isOp = opCols.includes(c), top = isOp ? yx + 11 : yx;
      items.push({ key: P + ':t' + c, kind: 'wire', pts: [[cx(c), y0], [cx(c), top]], head: isOp, cls: wc(tapOn) });
      if (!isOp && opCols.length) items.push({ key: P + ':tl' + c, kind: 'wire', pts: [[cx(c), yx], [cx(opCols[opCols.length - 1]) + 11, yx]], head: true, cls: wc(tapOn) });
    }
    for (let i = opCols.length - 1; i > 0; i--) items.push({ key: P + ':xc' + i, kind: 'wire', pts: [[cx(opCols[i]) - 11, yx], [cx(opCols[i - 1]) + 11, yx]], head: true, cls: wc(tapOn || fbOn) });
    // the chain's result goes left past the register and down into column 0
    const from = opCols.length ? cx(opCols[0]) - 11 : cx(last), xl = x0 - (o.lead || 30), ym = r2(y0 + ch / 2);
    items.push({ key: P + ':fb', kind: 'wire', pts: [[from, yx], [xl, yx], [xl, ym], [x0, ym]], head: true, cls: wc(fbOn) });
    if (o.fbBit !== undefined && o.fbBit !== null) items.push({ key: P + ':fbv', kind: 'chip', x: xl, y: r2((yx + ym) / 2), text: String(o.fbBit), cls: fbOn ? 'act' : 'plain' });
    // the output
    const xe = xs[L - 1] + cw, xOut = xe + (o.outLen || 46);
    items.push({ key: P + ':out', kind: 'wire', pts: [[xe, ym], [xOut, ym]], head: true, cls: lit.out ? 'hot' : '' });
    const box = { x: xl - 12, y: yx - 14, w: xOut - xl + 12, h: y0 + ch - yx + 14 + (o.label ? 22 : 0) };
    return { items, box, cell: (c) => ({ x: xs[c], y: y0, w: cw, h: ch }), xOut, yMid: ym, xs, yx };
  };

  R.galois = function (o) {
    const P = o.prefix || 'rg', bits = o.bits, L = bits.length, cw = o.cw || 40, ch = o.ch || 40, gap = o.gap === undefined ? 6 : o.gap, xg = o.xgap || 36;
    const x0 = o.x || 0, y0 = o.y || 0, lit = o.lit || {}, items = [];
    const tapSet = new Set(o.taps);
    // an XOR sits in the gap after column c (between c and c + 1) when the tap k = L − 1 − c is used
    const opAfter = (c) => c < L - 1 && tapSet.has(L - 1 - c);
    const xs = [];
    let at = x0;
    for (let c = 0; c < L; c++) { xs.push(at); at += cw + (opAfter(c) ? xg : gap); }
    const colBits = Array.from({ length: L }, (_, c) => bits[L - 1 - c]);
    cells(P, xs, y0, cw, ch, colBits, o, items);
    const ym = r2(y0 + ch / 2), yb = y0 + ch + (o.drop || (o.label ? 40 : 30)), fbOn = !!lit.fb, wc = (on) => (on ? 'act' : '');
    const xe = xs[L - 1] + cw, xOut = xe + (o.outLen || 46), xr = xe + 18, xl = x0 - (o.lead || 30);
    items.push({ key: P + ':out', kind: 'wire', pts: [[xe, ym], [xOut, ym]], head: true, cls: lit.out ? 'hot' : '' });
    items.push({ key: P + ':dj', kind: 'dot', x: xr, y: ym, r: 3.6, cls: fbOn ? 'act' : '' });
    // the feedback runs under the register, right to left, and enters column 0
    items.push({ key: P + ':fb', kind: 'wire', pts: [[xr, ym], [xr, yb], [xl, yb], [xl, ym], [x0, ym]], head: true, cls: wc(fbOn) });
    for (let c = 0; c < L - 1; c++) {
      const xa = xs[c] + cw;
      if (!opAfter(c)) continue;
      const ox = r2(xa + xg / 2);
      items.push({ key: P + ':x' + c, kind: 'op', x: ox, y: ym, r: 10, op: 'xor', cls: fbOn ? 'act' : '' });
      items.push({ key: P + ':xi' + c, kind: 'wire', pts: [[xa, ym], [ox - 10, ym]], head: true });
      items.push({ key: P + ':xo' + c, kind: 'wire', pts: [[ox + 10, ym], [xs[c + 1], ym]], head: true });
      items.push({ key: P + ':xd' + c, kind: 'wire', pts: [[ox, yb], [ox, ym + 10]], head: true, cls: wc(fbOn) });
      items.push({ key: P + ':xj' + c, kind: 'dot', x: ox, y: yb, r: 3.6, cls: fbOn ? 'act' : '' });
    }
    if (o.fbBit !== undefined && o.fbBit !== null) items.push({ key: P + ':fbv', kind: 'chip', x: xl, y: r2((yb + ym) / 2), text: String(o.fbBit), cls: fbOn ? 'act' : 'plain' });
    const box = { x: xl - 12, y: y0, w: xOut - xl + 12, h: yb - y0 + 8 };
    return { items, box, cell: (c) => ({ x: xs[c], y: y0, w: cw, h: ch }), xOut, yMid: ym, xs, yb };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
