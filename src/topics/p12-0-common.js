// Parts 12 and 13 share these: the families of both parts, and the small drawing helpers their pictures are made
// of (free text, framed panels, read-outs, rows of byte cells, a block of a padded message, a fixed camera). Every
// frame a topic of these parts adds carries `facts`: the values its narration quotes, by name, taken from the
// engines in src/core, so tests/claims-p12.mjs and tests/claims-p13.mjs can check each one against an independent
// working-out (node:crypto, or a second method).
(function (S) {
  'use strict';
  const U = (S.P12 = S.P12 || {});
  const r2 = (v) => Math.round(v * 100) / 100;
  U.r2 = r2;
  U.h2 = (v) => (v & 255).toString(16).padStart(2, '0');
  U.h8 = (v) => (v >>> 0).toString(16).padStart(8, '0');
  U.hex = (a) => Array.from(a || [], U.h2).join('');
  /** the first n bytes of a byte array (or n digits pairs of a hex string) in hex, with an ellipsis if cut */
  U.short = (a, n) => { const h = typeof a === 'string' ? a : U.hex(a); n = n || 8; return h.length > 2 * n ? h.slice(0, 2 * n) + '…' : h; };
  U.sub = (i) => String(i).split('').map((d) => '₀₁₂₃₄₅₆₇₈₉'[d] || d).join('');
  U.sup = (i) => String(i).split('').map((d) => '⁰¹²³⁴⁵⁶⁷⁸⁹'[d] || d).join('');
  U.plural = (n, w, ws) => n + ' ' + (n === 1 ? w : ws || w + 's');
  U.commas = (n) => Number(n).toLocaleString('en');
  U.fx = (v, d) => Number(v).toFixed(d === undefined ? 3 : d);
  U.utf8 = (s) => new TextEncoder().encode(String(s));
  U.text = (b) => new TextDecoder().decode(b);
  /** printable bytes as text, the rest as \xNN */
  U.show = (b) => { let s = ''; for (const v of b) s += v >= 32 && v < 127 ? String.fromCharCode(v) : '\\x' + U.h2(v); return s; };
  /** a / an before a word */
  U.an = (w) => (/^([aeio]|u(?!ni|se|su)|[AEFHILMNORSX](\b|[A-Z0-9-])|8|11|18|hour|honest)/.test(String(w)) ? 'an ' : 'a ') + w;
  U.cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  U.list = (xs) => (xs.length < 2 ? xs.join('') : xs.slice(0, -1).join(', ') + ' and ' + xs[xs.length - 1]);

  S.family({ id: 'p12-req', part: 'hash', order: 10, title: 'What a hash must do', blurb: 'Preimage, second-preimage and collision resistance as games against a challenger, and the birthday paradox that sets the price of a collision.' });
  S.family({ id: 'p12-md', part: 'hash', order: 20, title: 'Merkle–Damgård and SHA-2', blurb: 'Padding with the length, a chain of compressions, and SHA-256 opened up: the message schedule and the 64 rounds of its compression function.' });
  S.family({ id: 'p12-old', part: 'hash', order: 30, title: 'SHA-1, MD5 and how hashes fall', blurb: 'The two hashes the world ran on for twenty years, their step functions, and the timeline of the attacks that broke them.' });
  S.family({ id: 'p12-sha3', part: 'hash', order: 40, title: 'SHA-3 and the sponge', blurb: 'Absorb and squeeze on a 1600-bit state, the five steps of Keccak-f drawn on the state, and SHAKE, which squeezes as much output as you ask for.' });
  S.family({ id: 'p12-attacks', part: 'hash', order: 50, title: 'Attacks on hashes', blurb: 'Birthday collisions on a cut-down hash, rho with no memory, Joux\'s multicollisions, and length extension against a secret-prefix MAC.' });
  S.family({ id: 'p13-mac', part: 'protocols', order: 10, title: 'Message authentication codes', blurb: 'The forgery game a MAC must win, HMAC\'s two nested hashes, CBC-MAC and its splice, CMAC\'s subkeys, GMAC and Poly1305.' });
  S.family({ id: 'p13-aead', part: 'protocols', order: 20, title: 'Authenticated encryption and key derivation', blurb: 'ChaCha20-Poly1305 sealing and opening a message, and HKDF turning a shared secret into as many keys as a protocol needs.' });
  S.family({ id: 'p13-kdc', part: 'protocols', order: 30, title: 'Key distribution with a trusted server', blurb: 'Needham–Schroeder, the replay that breaks it and its repair, and the tickets of Kerberos, drawn as message sequences with what each party knows.' });
  S.family({ id: 'p13-pki', part: 'protocols', order: 40, title: 'Diffie–Hellman and public-key infrastructure', blurb: 'A key from public messages, a man in the middle who runs two exchanges, signatures that catch him, and certificate chains checked one rule at a time.' });
  S.family({ id: 'p13-tls', part: 'protocols', order: 50, title: 'TLS 1.3', blurb: 'One round trip: key shares in the hellos, a key schedule of HKDF calls, the server proven by its certificate and Finished, then application data.' });

  // ---- items -------------------------------------------------------------------------------------------------
  /** free text */
  U.t = (key, x, y, text, cls, anchor, size) => { const it = { key, kind: 'text', x: r2(x), y: r2(y), text: String(text), cls: cls || '', anchor: anchor || 'start' }; if (size) it.size = size; return it; };
  /** a framed panel with a title in its top-left corner */
  U.panel = (key, x, y, w, h, title, cls) => [
    { key, kind: 'region', x: r2(x), y: r2(y), w: r2(w), h: r2(h), rx: 10, cls: 'panel ' + (cls || '') },
    title ? { key: key + ':t', kind: 'text', x: r2(x + 14), y: r2(y + 22), text: title, cls: 'ptitle' } : null,
  ].filter(Boolean);
  /** a column of label: value rows in a panel; rows [[label, value, cls]] */
  U.readout = function (prefix, x, y, w, title, rows, o) {
    o = o || {};
    const dy = o.dy || 30, items = U.panel(prefix, x, y, w, 40 + rows.length * dy, title, o.cls);
    rows.forEach(([label, value, cls], i) => {
      items.push(U.t(prefix + ':l' + i, x + 14, y + 52 + i * dy, label, '', 'start', o.size || 13));
      items.push(U.t(prefix + ':v' + i, x + w - 14, y + 52 + i * dy, String(value), 'mono ' + (cls || ''), 'end', o.vsize || 14));
    });
    return items;
  };
  /** a row of cells: o {prefix, x, y, cw, ch, gap, values, text(v, i), cls(i, v), size, sub(i)} */
  U.cells = function (o) {
    const items = [], gap = o.gap === undefined ? 2 : o.gap;
    o.values.forEach((v, i) => {
      const it = { key: o.prefix + i, kind: 'cell', x: r2(o.x + i * (o.cw + gap)), y: r2(o.y), w: o.cw, h: o.ch, rx: o.rx === undefined ? 3 : o.rx, text: o.text ? o.text(v, i) : String(v), size: o.size || 13, cls: 'hex ' + (o.cls ? o.cls(i, v) || '' : '') };
      if (o.sub) { const s = o.sub(i, v); if (s !== undefined && s !== null && s !== '') it.sub = String(s); }
      items.push(it);
    });
    return items;
  };
  /** a block of a value: a rounded box with a name and a value on two lines (the demo's val2 look) */
  U.val = (key, x, y, w, name, value, cls, h) => ({ key, kind: 'state', x: r2(x), y: r2(y), w, h: h || 50, rx: 6, lines: [name, value], cls: 'block val2 ' + (cls || '') });
  /** a row of colour keys: entries [[cell class, text]] laid out from (x, y) */
  U.legend = function (prefix, x, y, entries, size) {
    const items = [], fs = size || 13;
    let at = x;
    entries.forEach(([cls, text], i) => {
      items.push({ key: prefix + ':s' + i, kind: 'cell', x: r2(at), y: r2(y - fs * 0.8), w: 14, h: 14, rx: 3, text: '', cls: 'hex ' + cls });
      items.push(U.t(prefix + ':t' + i, at + 20, y + 2, text, 'ptick', 'start', fs));
      at += 20 + S.geom.textWidth(text, fs) + 22;
    });
    return items;
  };
  /**
   * Bytes in rows of `per` cells, each coloured by its role: o {prefix, x, y, bytes, per, cw, ch, gap, role(i) ->
   * class, text(i, v) (default hex), size, rowGap}. Returns {items, xy(i), box}.
   */
  U.byteRows = function (o) {
    const per = o.per || 16, cw = o.cw || 22, ch = o.ch || 22, gap = o.gap === undefined ? 1.5 : o.gap, rg = o.rowGap === undefined ? 4 : o.rowGap, items = [];
    const xy = (i) => ({ x: r2(o.x + (i % per) * (cw + gap) + Math.floor((i % per) / (o.group || 1e9)) * (o.groupGap || 0)), y: r2(o.y + Math.floor(i / per) * (ch + rg)) });
    Array.from(o.bytes).forEach((v, i) => {
      const p = xy(i);
      items.push({ key: o.prefix + i, kind: 'cell', x: p.x, y: p.y, w: cw, h: ch, rx: 2, text: o.text ? o.text(i, v) : U.h2(v), size: o.size || 11, cls: 'hex ' + (o.role ? o.role(i, v) || '' : ''), audit: o.audit });
    });
    const rows = Math.ceil(o.bytes.length / per);
    return { items, xy, box: { x: o.x, y: o.y, w: per * (cw + gap), h: rows * (ch + rg) } };
  };
  /**
   * A plot: axes with tick labels inside {x, y, w, h}. o: {prefix, x, y, w, h, xr: [a, b], yr: [a, b], xticks, yticks,
   * fx(v), fy(v), xlabel, ylabel, grid, tickSize}. Returns {items, X(u), Y(v)}.
   */
  U.plot = function (o) {
    const P = o.prefix || 'pl', [x0, x1] = o.xr, [y0, y1] = o.yr;
    const X = (u) => r2(o.x + ((u - x0) / (x1 - x0)) * o.w), Y = (v) => r2(o.y + o.h - ((v - y0) / (y1 - y0)) * o.h);
    const items = [], ts = o.tickSize || 13;
    const fx = o.fx || ((v) => String(+v.toFixed(3))), fy = o.fy || ((v) => String(+v.toFixed(3)));
    if (o.grid) { let g = ''; for (const v of o.yticks || []) g += `M${o.x},${Y(v)} H${o.x + o.w} `; items.push({ key: P + ':grid', kind: 'path', d: g, cls: 'grid', audit: 'ignore', layer: 'back' }); }
    items.push({ key: P + ':ax', kind: 'path', d: `M${o.x},${o.y} V${o.y + o.h} H${o.x + o.w}`, cls: 'axis', audit: 'ignore', layer: 'back' });
    for (const u of o.xticks || []) items.push({ key: P + ':tx' + u, kind: 'text', x: X(u), y: o.y + o.h + ts + 5, text: fx(u), anchor: 'middle', size: ts, cls: 'ptick' });
    for (const v of o.yticks || []) items.push({ key: P + ':ty' + v, kind: 'text', x: o.x - 7, y: r2(Y(v) + ts * 0.35), text: fy(v), anchor: 'end', size: ts, cls: 'ptick' });
    if (o.xlabel) items.push({ key: P + ':xl', kind: 'text', x: o.x + o.w, y: o.y + o.h + ts + 24, text: o.xlabel, anchor: 'end', size: 13 });
    if (o.ylabel) items.push({ key: P + ':yl', kind: 'text', x: o.x, y: o.y - 12, text: o.ylabel, anchor: 'start', size: 13 });
    return { items, X, Y, o };
  };
  /** a data line through (xs[i], ys[i]) in a plot */
  U.line = (pl, key, xs, ys, cls) => ({ key, kind: 'path', d: xs.map((x, i) => (i ? 'L' : 'M') + pl.X(x) + ',' + pl.Y(ys[i])).join(' '), cls: 'p12-line ' + (cls || ''), audit: 'ignore' });
  /** the stage every picture of these parts is drawn on: about the shape of the topic player's stage */
  U.V = { x: 0, y: 0, w: 920, h: 660 };
  /** give every frame the same camera (the canvas, or a box given) */
  U.fix = (frames, box) => { for (const f of frames) f.view = Object.assign({}, box || U.V); return frames; };
  /** the definition panel from math lines */
  U.def = (title, lines, more) => ({ sections: [{ id: 'd', kind: 'math', title, text: lines.join('\n') }].concat(more || []) });
  /** a heading line at the top of the stage */
  U.head = (key, text, sub) => [U.t(key, 24, 34, text, 'strong', 'start', 17), sub ? U.t(key + ':s', 24, 58, sub, 'ptick', 'start', 13) : null].filter(Boolean);
  /** a check mark or a cross as text */
  U.tick = (ok) => (ok ? '✓' : '✗');
  /** text cut to n characters with an ellipsis */
  /** a long hex string in groups of eight, so it can wrap */
  U.spaced = (h) => String(h).replace(/(.{8})(?=.)/g, '$1 ');
  U.cut = (s, n) => (String(s).length > n ? String(s).slice(0, n - 1) + '…' : String(s));
  /** an input refused if it is not hex of whole bytes (and within lo..hi bytes) */
  U.hexCheck = (label, lo, hi) => (v) => {
    const t = String(v).replace(/\s+/g, '');
    if (!/^[0-9a-fA-F]*$/.test(t)) return label + ': hex digits only';
    if (t.length % 2) return label + ': whole bytes (an even number of hex digits)';
    if (lo !== undefined && t.length / 2 < lo) return label + ': at least ' + lo + ' bytes';
    if (hi !== undefined && t.length / 2 > hi) return label + ': at most ' + hi + ' bytes';
    return null;
  };
  U.fromHex = (s) => { const t = String(s).replace(/\s+/g, ''); const o = new Uint8Array(t.length >> 1); for (let i = 0; i < o.length; i++) o[i] = parseInt(t.substr(2 * i, 2), 16); return o; };
})(globalThis.Sifer = globalThis.Sifer || {});
