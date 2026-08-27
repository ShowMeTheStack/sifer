// Public-key pictures (parts 7 to 9): numbers that may run to hundreds of digits, the people who exchange them, and
// the byte layouts of padded blocks. A long number is drawn abbreviated (its first and last digits and its length);
// a click on it opens the whole value, so a 2048-bit modulus can be read and copied.
//   S.Kit.pk.fmt(v, {max, hex}) -> {text, full, long, digits}   v a BigInt (or a number); max: longest text kept whole
//   S.Kit.pk.value({key, x, y, w, label, value, cls, max, hex, size, anchor, inline}) -> item  a labelled value block
//   S.Kit.pk.chip({key, x, y, value, label, cls, max, hex}) -> item       a value in a pill
//   S.Kit.pk.party({key, x, y, name, cls, r}) -> items                     a person: a disc with an initial, a name below
//   S.Kit.pk.lanes({prefix, names: [..], xs: [..], y0, y1, cls}) -> items  message-chart lifelines with heads
//   S.Kit.pk.msg({key, x1, x2, y, text, cls, max}) -> items                an arrow from one lifeline to another with a
//                                                                          value riding on it
//   S.Kit.pk.bar({prefix, x, y, h, segs: [{w, text, sub, cls}], size}) -> {items, box, at(i)}  a block of fields
//   S.Kit.pk.expand(title, value)                                         the dialog with a whole value (also on click)
(function (S) {
  'use strict';
  const K = (S.Kit = S.Kit || {});
  const PK = (K.pk = {});
  const r2 = (v) => Math.round(v * 100) / 100;
  const Geo = () => S.geom;

  /** an abbreviated number: digits ≤ max are kept whole, longer ones keep their first and last digits */
  PK.fmt = function (v, o) {
    o = o || {};
    const max = o.max || 22, neg = typeof v === 'bigint' ? v < 0n : v < 0;
    const abs = typeof v === 'bigint' ? (neg ? -v : v) : Math.abs(v);
    let full = o.hex ? abs.toString(16) : abs.toString();
    const digits = full.length;
    const keep = Math.max(3, Math.floor((max - 2) / 2));
    const long = digits > max;
    let text = long ? full.slice(0, keep) + '…' + full.slice(-keep) : full;
    if (neg) { text = '−' + text; full = '−' + full; }
    return { text, full, long, digits, bits: S.NT ? S.NT.bitLength(typeof v === 'bigint' ? abs : BigInt(abs)) : 0 };
  };
  /** the item's hover text and the dialog's content: "label = digits" */
  const titleOf = (label, f, hex) => (label ? label + ' = ' : '') + (hex ? '0x' : '') + f.full + (f.long ? ' (' + f.digits + (hex ? ' hex' : '') + ' digits, ' + f.bits + ' bits)' : '');

  PK.value = function (o) {
    const f = PK.fmt(o.value, { max: o.max, hex: o.hex });
    const val = (o.hex ? '0x' : '') + f.text + (f.long && o.count !== false ? '  (' + f.bits + ' bits)' : '');
    // inline: one line "label = value"
    const lines = o.label === undefined || o.label === null ? [val] : o.inline ? [o.label + ' = ' + val] : [o.label, val];
    const sz = o.size || 14;
    const w = o.w || Math.ceil(Math.max(...lines.map((l, i) => Geo().textWidth(l, i === lines.length - 1 ? sz + 1 : 13, { mono: i === lines.length - 1, bold: i < lines.length - 1 }))) + 26);
    const h = lines.length * 21 + 16;
    const x = o.anchor === 'start' ? o.x + w / 2 : o.anchor === 'end' ? o.x - w / 2 : o.x;
    const it = { key: o.key, kind: 'state', x: r2(x), y: o.y, w, h, rx: 7, lines, cls: 'block ' + (lines.length > 1 ? 'val2' : 'val pk-inline') + ' ' + (o.cls || '') + (f.long ? ' pk-long' : ''), title: titleOf(o.label, f, o.hex) };
    if (o.pick) it.pick = true;
    return it;
  };
  PK.chip = function (o) {
    const f = PK.fmt(o.value, { max: o.max || 16, hex: o.hex });
    const it = { key: o.key, kind: 'chip', x: o.x, y: o.y, text: (o.label ? o.label + ' = ' : '') + (o.hex ? '0x' : '') + f.text, cls: (o.cls || '') + (f.long ? ' pk-long' : ''), title: titleOf(o.label, f, o.hex) };
    if (o.path) { it.path = o.path; it.t = o.t === undefined ? 1 : o.t; }
    if (o.onWire === false) it.onWire = false;
    return it;
  };

  PK.party = function (o) {
    const r = o.r || 22;
    return [
      { key: o.key, kind: 'state', x: o.x, y: o.y, r, text: o.initial || o.name[0], cls: 'pk-party ' + (o.cls || ''), size: Math.round(r * 0.9) },
      { key: o.key + ':n', kind: 'text', x: o.x, y: o.y + r + 19, text: o.name, anchor: 'middle', size: o.size || 14, cls: 'strong pk-name ' + (o.cls || '') },
    ];
  };

  PK.lanes = function (o) {
    const P = o.prefix || 'ln', items = [];
    o.names.forEach((name, i) => {
      items.push(...PK.party({ key: P + ':p' + i, x: o.xs[i], y: o.y0, name, cls: (o.cls && o.cls[i]) || '' }));
      items.push({ key: P + ':l' + i, kind: 'line', x1: o.xs[i], y1: o.y0 + 52, x2: o.xs[i], y2: o.y1, cls: 'pk-life', audit: 'ignore', layer: 'back' });
    });
    return items;
  };
  PK.msg = function (o) {
    const dir = o.x2 > o.x1 ? 1 : -1, x1 = o.x1 + dir * 6, x2 = o.x2 - dir * 6;
    const items = [{ key: o.key, kind: 'wire', pts: [[r2(x1), o.y], [r2(x2), o.y]], head: true, cls: 'pk-msg ' + (o.cls || '') }];
    if (o.text !== undefined) items.push({ key: o.key + ':c', kind: 'chip', x: r2((x1 + x2) / 2), y: o.y, text: o.text, cls: o.chipCls || o.cls || '', title: o.title });
    if (o.label) items.push({ key: o.key + ':t', kind: 'text', x: r2((x1 + x2) / 2), y: o.y - 22, text: o.label, anchor: 'middle', size: 13, cls: 'tick' });
    return items;
  };

  /** fields side by side: segs [{w, text, sub, cls}], widths in stage units */
  PK.bar = function (o) {
    const P = o.prefix || 'bar', items = [], xs = [];
    let x = o.x;
    o.segs.forEach((s, i) => {
      xs.push(x);
      const it = { key: P + ':' + (s.id || i), kind: 'cell', x: r2(x), y: o.y, w: s.w, h: o.h || 40, rx: 0, text: s.text || '', size: s.size || o.size || 13, cls: 'pk-field ' + (s.cls || '') };
      if (s.sub !== undefined) it.sub = s.sub;
      if (s.title) it.title = s.title;
      items.push(it);
      x += s.w;
    });
    return { items, box: { x: o.x, y: o.y, w: x - o.x, h: o.h || 40 }, at: (i) => ({ x: xs[i], w: o.segs[i].w, cx: xs[i] + o.segs[i].w / 2 }) };
  };

  // ---- the whole value, on a click ------------------------------------------------------------------------------
  PK.expand = function (title) {
    const UI = S.UI;
    if (!UI || !UI.modal) return;
    const m = /^(.*?) = (.*)$/.exec(title) || [null, 'Value', title];
    const digits = m[2].replace(/\s*\(.*\)$/, ''), note = (/\((.*)\)$/.exec(m[2]) || [])[1];
    const box = UI.h('div.pk-expand', UI.h('div.pk-digits', digits), note ? UI.h('p.pk-note', note) : null);
    UI.modal({ title: m[1], body: box, wide: true, buttons: [{ label: 'Copy', value: 'copy' }, { label: 'Close', value: true, primary: true }] }).then((v) => {
      if (v === 'copy' && navigator.clipboard) navigator.clipboard.writeText(digits).catch(() => {});
    });
  };
  if (typeof document !== 'undefined' && !PK.installed) {
    PK.installed = true;
    document.addEventListener('click', (e) => {
      const g = e.target && e.target.closest ? e.target.closest('.it.pk-long') : null;
      if (!g) return;
      const t = g.querySelector(':scope > title');
      if (t && t.textContent) PK.expand(t.textContent);
    });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
