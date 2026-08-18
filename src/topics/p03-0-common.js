// Parts 3 and 4 share these: the families of part 3, and the small drawing helpers the stream-cipher and block-
// cipher pictures are made of (titles, panels of values, rows of bits and bytes, legends). Every frame a topic of
// these parts adds carries `facts`: the values its narration quotes, by name, so tests/claims-p03.mjs and
// tests/claims-p04.mjs can check each one against an independent working-out.
(function (S) {
  'use strict';
  const U = (S.SymT = S.SymT || {});
  const r2 = (v) => Math.round(v * 100) / 100;
  U.r2 = r2;
  U.sub = (i) => String(i).split('').map((d) => '₀₁₂₃₄₅₆₇₈₉'[d] || d).join('');
  U.sup = (i) => String(i).split('').map((d) => '⁰¹²³⁴⁵⁶⁷⁸⁹'[d] || d).join('');
  U.plural = (n, w, ws) => n + ' ' + (n === 1 ? w : ws || w + 's');
  U.h2 = (v) => (v & 255).toString(16).padStart(2, '0');
  U.hex = (a) => Array.from(a, U.h2).join('');
  /** hex in pairs separated by spaces */
  U.hexs = (a) => Array.from(a, U.h2).join(' ');
  U.h8 = (v) => (v >>> 0).toString(16).padStart(8, '0');
  U.h4 = (v) => (v & 0xffff).toString(16).padStart(4, '0');
  /** printable ASCII, a middle dot for anything else */
  U.show = (a) => Array.from(a, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '·')).join('');
  U.bytesOf = (s) => S.bytes.utf8(s);
  U.fromHex = (h) => S.bytes.fromHex(String(h).replace(/\s+/g, ''));
  U.pop = (x) => { let n = 0; x >>>= 0; while (x) { n += x & 1; x >>>= 1; } return n; };
  /** a number with d decimals */
  U.fx = (v, d) => Number(v).toFixed(d === undefined ? 2 : d);
  /** a whole number with thin groups of three: 72 057 594 037 927 936 */
  U.big = (v) => String(v).replace(/\B(?=(\d{3})+(?!\d))/g, ' ');

  S.family({ id: 'p03-otp', part: 'stream', order: 10, title: 'The one-time pad', blurb: 'Perfect secrecy from a key as long as the message and used once, and what a second use gives away.' });
  S.family({ id: 'p03-lfsr', part: 'stream', order: 20, title: 'Generators and LFSRs', blurb: 'True, pseudo and cryptographic randomness; the linear feedback shift register, its period, its two forms, and Berlekamp–Massey taking it apart.' });
  S.family({ id: 'p03-combine', part: 'stream', order: 30, title: 'Combining registers', blurb: 'Hiding linearity behind a combining function, the correlation attack that splits Geffe apart, and Trivium\'s three coupled registers.' });
  S.family({ id: 'p03-arx', part: 'stream', order: 40, title: 'Salsa20 and ChaCha20', blurb: 'Add, rotate and XOR on a 4×4 state of words: the quarter-rounds, the double rounds, the block counter and the extended nonce.' });

  /** free text */
  U.t = (key, x, y, text, cls, anchor, size) => { const it = { key, kind: 'text', x: r2(x), y: r2(y), text, cls: cls || '', anchor: anchor || 'start' }; if (size) it.size = size; return it; };
  /** the heading of a picture, top left */
  U.head = (key, text, x, y) => U.t(key, x === undefined ? 24 : x, y === undefined ? 34 : y, text, 'strong', 'start', 17);
  /** a framed panel with a title in its top-left corner */
  U.panel = (key, x, y, w, h, title, cls) => [
    { key, kind: 'region', x, y, w, h, rx: 10, cls: 'panel ' + (cls || '') },
    title ? { key: key + ':t', kind: 'text', x: x + 14, y: y + 24, text: title, cls: 'title', size: 14 } : null,
  ].filter(Boolean);
  /** a column of label: value rows in a panel; rows [[label, value, cls]] */
  U.readout = function (prefix, x, y, w, title, rows, o) {
    o = o || {};
    const dy = o.dy || 30, items = U.panel(prefix, x, y, w, 36 + rows.length * dy, title, o.cls);
    rows.forEach(([label, value, cls], i) => {
      items.push(U.t(prefix + ':l' + i, x + 14, y + 50 + i * dy, label, '', 'start', o.size || 14));
      items.push(U.t(prefix + ':v' + i, x + w - 14, y + 50 + i * dy, String(value), 'mono ' + (cls || ''), 'end', o.vsize || 15));
    });
    return items;
  };
  /** a row of cells holding values: o {prefix, x, y, cw, ch, gap, values, cls(i, v), size, text(v, i), sub(v, i)} */
  U.cells = function (o) {
    const items = [];
    o.values.forEach((v, i) => {
      const it = { key: o.prefix + i, kind: 'cell', x: r2(o.x + i * (o.cw + (o.gap === undefined ? 2 : o.gap))), y: o.y, w: o.cw, h: o.ch, rx: 3, text: o.text ? o.text(v, i) : String(v), size: o.size || 14, cls: (o.mono === false ? '' : 'hex ') + (o.cls ? o.cls(i, v) || '' : '') };
      if (o.sub) it.sub = o.sub(v, i);
      items.push(it);
    });
    return items;
  };
  /** a row of bits as cells (S.Kit.bytes.bits with our defaults) */
  U.bitRow = (o) => S.Kit.bytes.bits(Object.assign({ cw: 18, ch: 24, gap: 2, group: 8, groupGap: 6, size: 13 }, o));
  /** a row of colour keys: entries [[cell class, text]] laid out from (x, y) */
  U.legend = function (prefix, x, y, entries, size) {
    const items = [], fs = size || 13;
    let at = x;
    entries.forEach(([cls, text], i) => {
      items.push({ key: prefix + ':s' + i, kind: 'cell', x: at, y: y - fs * 0.8, w: 14, h: 14, rx: 3, text: '', cls: 'bit ' + cls });
      items.push(U.t(prefix + ':t' + i, at + 20, y + 2, text, 'tick', 'start', fs));
      at += 20 + S.geom.textWidth(text, fs) + 24;
    });
    return items;
  };
  /** the stage every picture of these parts is drawn on: about the shape of the topic player's stage */
  U.V = { x: 0, y: 0, w: 920, h: 640 };
  /** give every frame the same camera (the canvas, or a box given) */
  U.fix = (frames, box) => { for (const f of frames) f.view = Object.assign({}, box || U.V); return frames; };
  /** the definition panel from math lines */
  U.def = (title, lines) => ({ sections: [{ id: 'd', kind: 'math', title, text: lines.join('\n') }] });
  /** a choice input from [value, label] pairs */
  U.choice = (id, label, def, pairs) => ({ id, kind: 'choice', label, def, options: pairs.map(([value, l]) => ({ value, label: l })) });
  /** taps written as a list of exponents ("4, 3"), checked */
  U.tapsCheck = (max) => (v) => {
    if (!v.length || v.some((x) => !/^\d+$/.test(x))) return 'Taps: whole numbers, the exponents of the connection polynomial (e.g. 4, 3)';
    const n = v.map(Number);
    if (n.some((k) => k < 1 || k > max)) return 'Taps: from 1 to ' + max + ', so the register fits the stage';
    if (new Set(n).size !== n.length) return 'Taps: each exponent once';
    return null;
  };
  /** a bit string checked: only 0 and 1, with a length range */
  U.bitsCheck = (label, min, max) => (v) => {
    const s = String(v).replace(/\s+/g, '');
    if (!/^[01]*$/.test(s)) return label + ': only 0 and 1';
    if (s.length < min) return label + ': at least ' + min + ' bits';
    if (s.length > max) return label + ': at most ' + max + ' bits, so the picture stays readable';
    return null;
  };
  U.toBits = (s) => String(s).replace(/\s+/g, '').split('').map(Number);
})(globalThis.Sifer = globalThis.Sifer || {});
