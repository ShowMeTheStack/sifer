// An exponent's bits on the stage, for square-and-multiply: a row of bit cells with, under each, what the bit
// does (S for a squaring, S · M when a multiplication follows), the running value and the exponent reached; the
// operations in order, as a power trace would show them; and a long exponent as a carpet of bits with a lens and
// a zoomed row of the bits under it.
//   S.Kit.bits.columns({prefix, x, pitch, cw, bits, steps, at, rows: {bit, op, value, power}, sizes}) -> items
//   S.Kit.bits.ops({prefix, x, y, steps, at}) -> items        the S and M cells in the order they happen
//   S.Kit.bits.carpet({prefix, x, y, bits, per, cs, upto, gap}) -> a bitmap item (read bits lit)
//   S.Kit.bits.lens({prefix, x, y, cs, per, from, width, zoomY, zcw, bits, steps, at, size}) -> items
(function (S) {
  'use strict';
  const K = (S.Kit = S.Kit || {});
  const KB = (K.bits = {});

  KB.columns = function (o) {
    const P = o.prefix || 'sq', items = [], z = o.sizes || {};
    const power = (i) => parseInt(o.bits.slice(0, i + 1), 2);
    for (let i = 0; i < o.bits.length; i++) {
      const s = o.steps[i], X = o.x + i * o.pitch, on = i <= o.at, cur = i === o.at;
      items.push({ key: P + ':b' + i, kind: 'cell', x: X, y: o.rows.bit, w: o.cw, h: z.bitH || 50, rx: 5, text: o.bits[i], size: z.bit || 22, cls: 'hex ' + (cur ? 'act' : on && s.bit ? 'one bit' : on ? '' : 'soft') });
      items.push({ key: P + ':o' + i, kind: 'text', x: X + o.cw / 2, y: o.rows.op, text: on ? (i === 0 ? 'start' : s.bit ? 'S · M' : 'S') : '', anchor: 'middle', size: z.op || 14, cls: s.bit ? 'hot' : 'act' });
      items.push({ key: P + ':v' + i, kind: 'text', x: X + o.cw / 2, y: o.rows.value, text: on ? String(s.value) : '', anchor: 'middle', size: z.value || 13, cls: 'mono' + (cur ? ' act' : '') });
      if (o.rows.power !== undefined) items.push({ key: P + ':p' + i, kind: 'text', x: X + o.cw / 2, y: o.rows.power, text: on ? String(power(i)) : '', anchor: 'middle', size: z.power || 14, cls: 'mono' + (cur ? ' act' : '') });
    }
    return items;
  };
  KB.ops = function (o) {
    const P = o.prefix || 'sq', ops = [], items = [];
    for (let i = 1; i <= o.at; i++) { ops.push('S'); if (o.steps[i].bit) ops.push('M'); }
    ops.forEach((op, k) => items.push({ key: P + ':op' + k, kind: 'cell', x: o.x + k * 34, y: o.y, w: 30, h: op === 'S' ? 34 : 48, rx: 3, text: op, size: 13, cls: op === 'S' ? 'act' : 'hot' }));
    return { items, squarings: ops.filter((x) => x === 'S').length, multiplications: ops.filter((x) => x === 'M').length };
  };
  KB.carpet = function (o) {
    const rows = [], N = o.bits.length;
    for (let k = 0; k < N; k += o.per) { let s = ''; for (let j = k; j < Math.min(N, k + o.per); j++) s += j <= o.upto ? (o.bits[j] === '1' ? '3' : '7') : o.bits[j] === '1' ? '1' : '0'; rows.push(s); }
    return { key: (o.prefix || 'rs') + ':c', kind: 'bitmap', x: o.x, y: o.y, cw: o.cs, ch: o.cs, gap: o.gap === undefined ? 1.5 : o.gap, rows };
  };
  KB.lens = function (o) {
    const P = o.prefix || 'rs', items = [], row = Math.floor(o.from / o.per), col = o.from % o.per, w = o.width, cs = o.cs;
    items.push({ key: P + ':lens', kind: 'region', x: o.x + col * cs - 2, y: o.y + row * cs - 2, w: w * cs + 4, h: cs + 4, rx: 2, cls: 'lens', audit: 'overlap-ok' });
    // the zoom: two faint lines from the lens down to the row of large cells
    const zx0 = o.x, zx1 = o.x + w * (o.zcw + 1);
    items.push({ key: P + ':z1', kind: 'line', x1: o.x + col * cs - 2, y1: o.y + (row + 1) * cs + 2, x2: zx0, y2: o.zoomY - 2, cls: 'act faint', audit: 'ignore' });
    items.push({ key: P + ':z2', kind: 'line', x1: o.x + (col + w) * cs + 2, y1: o.y + (row + 1) * cs + 2, x2: zx1, y2: o.zoomY - 2, cls: 'act faint', audit: 'ignore' });
    for (let j = 0; j < w; j++) {
      const i = o.from + j, b = o.bits[i], s = o.steps[i];
      items.push({ key: P + ':zb' + j, kind: 'cell', x: zx0 + j * (o.zcw + 1), y: o.zoomY, w: o.zcw, h: 30, rx: 3, text: b, size: o.size || 15, cls: 'hex ' + (b === '1' ? 'one bit' : '') + (i === o.at ? ' act' : '') });
      items.push({ key: P + ':zo' + j, kind: 'text', x: zx0 + j * (o.zcw + 1) + o.zcw / 2, y: o.zoomY + 48, text: i === 0 ? '·' : s.bit ? 'SM' : 'S', anchor: 'middle', size: o.opSize || 13, cls: s.bit ? 'hot' : 'act' });
    }
    items.push({ key: P + ':zl', kind: 'text', x: zx0, y: o.zoomY - 12, text: `bits ${o.from} to ${o.from + w - 1}`, cls: 'act', size: 13 });
    return items;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
