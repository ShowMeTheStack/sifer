// Part 6's drawing helpers for the modes of operation: a data block as a box with its name and bytes (two lines of
// eight bytes, or four lines of four for a narrow box), short hex for chips, and a phone camera that follows one
// column of a three-column mode diagram.
//   S.Kit.p06.box(N, id, x, y, name, bytes, cls, {quad, w, h})   a value box on a flow net, centred on (x, y)
//   S.Kit.p06.two(b) / quad(b) -> lines;  short(b, n) -> 'a1b2c3d4…';  sub(i) -> subscript digits
//   S.Kit.p06.follow(x, o) -> a narrow camera box around x, for frame.narrowView
(function (S) {
  'use strict';
  const K = (S.Kit = S.Kit || {});
  const P6 = (K.p06 = {});
  const hex = (a) => S.bytes.hex(a);
  P6.sub = (n) => String(n).replace(/\d/g, (d) => '₀₁₂₃₄₅₆₇₈₉'[d]);
  P6.two = (b) => (b.length > 8 ? [hex(b.slice(0, 8)), hex(b.slice(8))] : [hex(b), '']);
  P6.quad = (b) => { const out = []; for (let i = 0; i < 16; i += 4) out.push(hex(b.slice(i, i + 4))); return out; };
  P6.short = (b, n) => { const h = hex(b); n = n || 8; return h.length > n ? h.slice(0, n) + '…' : h; };
  /** a value box: its name on the first line, then its bytes (blank lines when bytes is null) */
  P6.box = (N, id, x, y, name, bytes, cls, o) => {
    o = o || {};
    const lines = o.quad ? (bytes ? P6.quad(bytes) : ['', '', '', '']) : bytes ? P6.two(bytes) : ['', ''];
    const w = o.w || (o.quad ? 104 : 170), h = o.h || (o.quad ? 100 : 66);
    return N.box(id, x, y, w, h, [name, ...lines], 'val3 ' + (cls || ''));
  };
  P6.follow = (x, o) => { o = o || {}; const w = o.w || 420, h = o.h || 560; const x0 = Math.max(0, Math.min(880 - w, x - w / 2)); return { x: x0, y: o.y === undefined ? 40 : o.y, w, h }; };
})(globalThis.Sifer = globalThis.Sifer || {});
// the inputs most mode topics share: a message, a key and an IV (text or hex, read by the part 5 helpers)
(function (S) {
  'use strict';
  const P6 = S.Kit.p06;
  const U = () => S.P5;
  P6.msgInput = (def, max, min) => ({ id: 'msg', kind: 'text', label: `Message (${min || 1} to ${max} characters)`, def, check: (v) => { const n = S.bytes.utf8(String(v)).length; return n < (min || 1) ? `Message: at least ${min || 1} character${(min || 1) > 1 ? 's' : ''}` : n > max ? `Message: at most ${max} bytes, so it fits the picture` : null; } });
  P6.keyInput = (def) => ({ id: 'key', kind: 'text', label: 'Key (16, 24 or 32 characters, or hex)', def: def || 'saffron-harbour9', check: (v) => U().keyCheck('Key')(v) });
  P6.ivInput = (def, label) => ({ id: 'iv', kind: 'text', label: label || 'IV (16 characters or 32 hex digits)', def: def || 'quiet-iv-rowan-7', check: (v) => U().blockCheck(label ? label.split(' (')[0] : 'IV')(v) });
  /** long hex in narration: one group of 32 digits per 16-byte block, so a sentence can wrap */
  P6.hexb = (b) => P6.blocks(b).map((x) => S.bytes.hex(x)).join(' ');
  P6.blocks = (b) => { const out = []; for (let i = 0; i < b.length; i += 16) out.push(b.slice(i, i + 16)); return out; };
  const U2 = () => S.P5;
  /** a readout panel at the bottom of the canvas: rows [label, value, cls]; long values wrap at 64 characters */
  P6.readout = (rows0, title) => {
    const rows = [];
    for (const [l, v, c] of rows0) { const t = String(v); for (let k = 0; k < Math.max(1, t.length); k += 64) rows.push([k ? '' : l, t.slice(k, k + 64), c]); }
    const items = U2().panel('rd', 30, 484, 820, 36 + rows.length * 26, title || '');
    rows.forEach(([l, v, c], i) => { items.push(U2().t('rd:l' + i, 50, 528 + i * 26, l, 'strong', 'start', 14)); items.push(U2().t('rd:v' + i, 190, 528 + i * 26, v, 'math ' + (c || ''), 'start', 15)); });
    return items;
  };
  /** the centres of the columns of a diagram of n blocks */
  P6.cols = (n) => (n >= 3 ? [200, 470, 740] : n === 2 ? [300, 600] : [450]);
})(globalThis.Sifer = globalThis.Sifer || {});
