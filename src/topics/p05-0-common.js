// Part 5, AES: the families, and the small drawing helpers its topics (and those of part 6) share: free text, a
// framed panel, a 4×4 state grid, a row of byte cells, a readout of label: value rows, and the inputs every AES
// topic takes (a 16-byte block or key typed as text or hex). Every frame carries `facts`: the values its narration
// quotes, by name, so tests/claims-p05.mjs can check each one against an independent working-out.
(function (S) {
  'use strict';
  const U = (S.P5 = S.P5 || {});
  const r2 = (v) => Math.round(v * 100) / 100;
  U.r2 = r2;

  S.family({ id: 'p05-state', part: 'aes', order: 10, title: 'The AES state', blurb: 'Sixteen bytes in a 4×4 grid, filled column by column, and the rounds that work on it.' });
  S.family({ id: 'p05-steps', part: 'aes', order: 20, title: 'The four round steps', blurb: 'SubBytes from inversion in GF(2⁸) and an affine map, ShiftRows, MixColumns as a matrix over the field, and AddRoundKey.' });
  S.family({ id: 'p05-keys', part: 'aes', order: 30, title: 'The key schedule', blurb: 'Words made from words: the g-function with RotWord, SubWord and the round constant, for keys of 128, 192 and 256 bits.' });
  S.family({ id: 'p05-cipher', part: 'aes', order: 40, title: 'The whole cipher', blurb: 'Ten rounds from plaintext to ciphertext, the inverse cipher that undoes them, and one flipped bit spreading through the state.' });
  S.family({ id: 'p05-mini', part: 'aes', order: 50, title: 'Mini-AES by hand', blurb: 'The same steps on a 16-bit block of four nibbles, small enough to work with pencil and paper.' });
  S.family({ id: 'p05-impl', part: 'aes', order: 60, title: 'Implementation and security', blurb: 'T-tables that fold a round into lookups, the cache lines they give away, and what key length buys against exhaustive search.' });

  // ---- text ------------------------------------------------------------------------------------------------------
  U.h2 = (v) => (v & 255).toString(16).padStart(2, '0');
  U.hex = (a, sep) => Array.from(a, U.h2).join(sep || '');
  U.bin8 = (v) => (v & 255).toString(2).padStart(8, '0');
  U.sub = (i) => String(i).split('').map((d) => '₀₁₂₃₄₅₆₇₈₉'[d]).join('');
  U.sup = (i) => String(i).split('').map((d) => '⁰¹²³⁴⁵⁶⁷⁸⁹'[d] || d).join('');
  U.plural = (n, w, ws) => n + ' ' + (n === 1 ? w : ws || w + 's');
  U.cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  /** printable text of bytes, a middle dot for anything else */
  U.txt = (a) => Array.from(a, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '·')).join('');
  /** "row r, column c" of state byte i (column order) */
  U.cell = (i) => `row ${i % 4}, column ${Math.floor(i / 4)}`;
  U.list = (xs) => (xs.length < 2 ? xs.join('') : xs.slice(0, -1).join(', ') + ' and ' + xs[xs.length - 1]);
  /** a / an before a hex byte or a word: an 8e, a 63, an e5 */
  U.an = (w) => {
    const s = String(w);
    const v = /^[0-9a-f]+$/.test(s) && /[a-f]/.test(s) && /\d/.test(s) ? /^[8aef]/.test(s) : /^(8|11|18|[aefhilmnorsx]$|[aeio])/i.test(s) && !/^(one|use|uni|eu)/i.test(s);
    return (v ? 'an ' : 'a ') + s;
  };

  // ---- items -----------------------------------------------------------------------------------------------------
  // titles are drawn at 13px: the stage is scaled down a little to fit the player, and 12px would fall under 11
  U.t = (key, x, y, text, cls, anchor, size) => { const it = { key, kind: 'text', x: r2(x), y: r2(y), text: String(text), cls: cls || '', anchor: anchor || 'start' }; if (size) it.size = size; else if (/(^|\s)title(\s|$)/.test(cls || '')) it.size = 13; return it; };
  U.panel = (key, x, y, w, h, title, cls) => [
    { key, kind: 'region', x, y, w, h, rx: 10, cls: 'panel ' + (cls || '') },
    title ? U.t(key + ':t', x + 14, y + 22, title, 'title') : null,
  ].filter(Boolean);
  /** a 4×4 state (column order) with a title: o {cw, ch, gap, size, cls(i, v), title, fmt, enter, rx} */
  U.grid = (prefix, x, y, values, o) => {
    o = o || {};
    const g = S.Kit.bytes.grid({ prefix, x, y, values, cw: o.cw || 50, ch: o.ch || 40, gap: o.gap === undefined ? 4 : o.gap, size: o.size || 16, title: o.title, titleCls: o.titleCls, cls: o.cls, fmt: o.fmt, enter: o.enter, rx: o.rx, rows: o.rows, cols: o.cols, order: o.order, colHead: o.colHead, rowHead: o.rowHead });
    for (const it of g.items) if (it.kind === 'text' && !it.size) it.size = 13;
    return g;
  };
  /** a row of byte cells: o {cw, ch, gap, size, cls(i, v), text(v, i), sub(i)} */
  U.cells = (prefix, x, y, values, o) => {
    o = o || {};
    const cw = o.cw || 30, ch = o.ch || 30, gap = o.gap === undefined ? 2 : o.gap;
    return Array.from(values, (v, i) => {
      const it = { key: prefix + i, kind: 'cell', x: r2(x + i * (cw + gap)), y, w: cw, h: ch, rx: o.rx === undefined ? 3 : o.rx, text: v === null || v === undefined ? '' : o.text ? o.text(v, i) : U.h2(v), size: o.size || 14, cls: 'hex ' + (o.cls ? o.cls(i, v) || '' : '') };
      if (o.sub) { const s = o.sub(i); if (s !== undefined && s !== null && s !== '') it.sub = String(s); }
      return it;
    });
  };
  /** a column of label: value rows in a panel; rows [[label, value, cls]] */
  U.readout = (prefix, x, y, w, title, rows, o) => {
    o = o || {};
    const dy = o.dy || 30, items = U.panel(prefix, x, y, w, 42 + rows.length * dy, title);
    rows.forEach(([label, value, cls], i) => {
      items.push(U.t(prefix + ':l' + i, x + 14, y + 54 + i * dy, label, '', 'start', o.size || 13));
      items.push(U.t(prefix + ':v' + i, x + w - 14, y + 54 + i * dy, String(value), 'mono ' + (cls || ''), 'end', o.vsize || 14));
    });
    return items;
  };
  /** an arrow drawn as a wire from (x1, y1) to (x2, y2), straight or with one corner */
  U.arrow = (key, pts, cls) => ({ key, kind: 'wire', pts: pts.map((p) => [r2(p[0]), r2(p[1])]), head: true, cls: cls || '' });

  /** the stage every picture of parts 5 and 6 is drawn on: about the shape of the topic player's stage */
  U.V = { x: 0, y: 0, w: 880, h: 640 };
  U.fix = (frames, box) => { for (const f of frames) if (!f.view) f.view = Object.assign({}, box || U.V); return frames; };
  /** the definition panel from math lines (and more sections) */
  U.def = (title, lines, more) => ({ sections: [{ id: 'd', kind: 'math', title, text: lines.join('\n') }].concat(more || []) });

  // ---- inputs ----------------------------------------------------------------------------------------------------
  /** a block typed as 16 characters of text or 32 hex digits (spaces in hex are allowed) */
  U.block = (v, n) => {
    n = n || 16;
    const s = String(v === undefined || v === null ? '' : v), h = s.replace(/\s+/g, '');
    if (new RegExp('^[0-9a-fA-F]{' + 2 * n + '}$').test(h)) return S.bytes.fromHex(h);
    const b = S.bytes.utf8(s);
    if (b.length === n) return b;
    return null;
  };
  U.blockCheck = (label, n) => (v) => (U.block(v, n) ? null : `${label}: ${n} characters of text, or ${2 * n} hex digits`);
  /** an AES key typed as text or hex: 16, 24 or 32 bytes (sizes limits the choice) */
  U.key = (v, sizes) => { for (const n of sizes || [16, 24, 32]) { const b = U.block(v, n); if (b) return b; } return null; };
  U.keyCheck = (label, sizes) => (v) => (U.key(v, sizes) ? null : `${label}: ${(sizes || [16, 24, 32]).map((n) => n + ' characters').join(', ').replace(/, ([^,]*)$/, ' or $1')} of text, or ${(sizes || [16, 24, 32]).map((n) => 2 * n).join(', ').replace(/, ([^,]*)$/, ' or $1')} hex digits`);
  /** how a block reads in narration: its text in quotes when it is all printable, else nothing */
  U.asText = (b) => (Array.from(b).every((x) => x >= 32 && x < 127) ? '“' + U.txt(b) + '”' : '');
})(globalThis.Sifer = globalThis.Sifer || {});
