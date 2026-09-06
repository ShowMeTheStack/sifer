// Part 11, digital signatures: the small helpers its topics share (value blocks for long numbers and for bytes, rows of
// byte cells, wires and boxes, real keys made from labels), on top of the part 7 to 10 kits. The families are declared here. Every frame carries `facts`, the
// values its narration quotes, so tests/claims-p11.mjs can check each one against node:crypto or a second working-out.
(function (S) {
  'use strict';
  const W = (S.P11 = S.P11 || {});
  const KP = () => S.Kit.pk;
  const r2 = (v) => Math.round(v * 100) / 100;
  W.r2 = r2;

  const fam = (id, order, title, blurb) => S.family({ id, part: 'signatures', order, title, blurb });
  fam('p11-basics', 10, 'What a signature is', 'Integrity, authenticity and non-repudiation, and how they differ from what a MAC gives.');
  fam('p11-rsa', 20, 'RSA signatures', 'Signing with the private exponent, why raw RSA signing is unsafe, and the PSS encoding that the standards require.');
  fam('p11-dlp', 30, 'Discrete-log signatures', 'Elgamal, DSA and Schnorr in a prime-order group, toy and real, and the Fiat–Shamir idea behind Schnorr.');
  fam('p11-ec', 40, 'Curve signatures', 'ECDSA on P-256 with deterministic nonces, and EdDSA on Ed25519, step by step.');
  fam('p11-nonce', 50, 'The nonce rules', 'Why every signature needs a fresh, secret and uniform nonce, and how deriving it from the key and the message removes the risk.');
  fam('p11-compare', 60, 'Choosing a scheme', 'Key and signature sizes, the work of signing and verifying, and the assumption each scheme rests on.');

  // ---- numbers and bytes ------------------------------------------------------------------------------------------
  W.B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  /** a number for a sentence: whole up to 24 digits, else its first and last 10 digits and its length */
  W.n = (v) => S.PK.n(v);
  W.utf8 = (s) => new TextEncoder().encode(String(s));
  W.hex = (b) => Array.from(b, (x) => (x & 255).toString(16).padStart(2, '0')).join('');
  W.unhex = (h) => { h = String(h).replace(/\s+/g, ''); const o = new Uint8Array(h.length >> 1); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(2 * i, 2), 16); return o; };
  /** bytes as hex, cut to the first n bytes and an ellipsis */
  W.hx = (b, n) => { const s = W.hex(b); n = n || 8; return s.length > 2 * n ? s.slice(0, 2 * n) + '…' : s; };
  /** a hex string cut to its first and last n digits */
  W.hs = (h, n) => { n = n || 8; return h.length > 2 * n + 2 ? h.slice(0, n) + '…' + h.slice(-n) : h; };
  /** a BigInt as len bytes of hex (big-endian) */
  W.bhex = (v, len) => W.B(v).toString(16).padStart(2 * (len || 1), '0');
  W.big = (b) => { let v = 0n; for (const x of b) v = (v << 8n) | BigInt(x); return v; };
  W.sha256 = (b) => S.SHA256.hash(typeof b === 'string' ? W.utf8(b) : b);
  W.cat = (...as) => { const o = new Uint8Array(as.reduce((n, a) => n + a.length, 0)); let i = 0; for (const a of as) { o.set(a, i); i += a.length; } return o; };
  W.plural = (k, w, ws) => k + ' ' + (Number(k) === 1 ? w : ws || w + 's');
  W.memo = (id, input, fn) => S.PK.memo(id, input, fn);

  // ---- inputs -----------------------------------------------------------------------------------------------------
  W.textIn = (id, label, def, max) => ({ id, kind: 'text', label, def, check: (v) => (!String(v).length ? label + ': at least one character' : String(v).length > (max || 48) ? label + ': at most ' + (max || 48) + ' characters' : null) });
  W.hexIn = (id, label, def, bytes) => ({ id, kind: 'hex', label, def, bytes });
  /** a private scalar in [1, n − 1] made from a label (SHA-256 of it, reduced) */
  W.scalarOf = (label, n) => (W.big(W.sha256(label)) % (n - 1n)) + 1n;
  /** a decimal or 0x-hex whole number, or null */
  W.parseK = (v) => { const t = String(v).trim().toLowerCase(); return /^(0x[0-9a-f]+|\d+)$/.test(t) ? BigInt(t) : null; };

  // ---- drawing ----------------------------------------------------------------------------------------------------
  W.t = (key, x, y, text, cls, anchor, size) => { const it = { key, kind: 'text', x: r2(x), y: r2(y), text, cls: cls || '', anchor: anchor || 'start' }; if (size) it.size = size; return it; };
  W.title = (key, x, y, text, anchor) => ({ key, kind: 'text', x, y, text, cls: 'title', anchor: anchor || 'start' });
  W.panel = (key, x, y, w, h, title, cls) => [{ key, kind: 'region', x, y, w, h, rx: 10, cls: 'panel ' + (cls || '') }].concat(title ? [{ key: key + ':t', kind: 'text', x: x + 14, y: y + 22, text: title, cls: 'title' }] : []);
  W.eqs = (prefix, x, y, lines, size, gap) => lines.filter(Boolean).map(([text, cls], k) => ({ key: prefix + k, kind: 'text', x, y: r2(y + k * (gap || 28)), text, cls: 'eq ' + (cls || ''), size: size || 16 }));
  /** a long number in a block: abbreviated, the whole of it on a click */
  W.vb = (key, x, y, label, value, cls, w, max) => KP().value({ key, x, y, w, label, value: W.B(value), cls: cls || '', max: max || 14, count: false });
  /** a block of two lines, label over a value (hex or words); title holds the whole value */
  W.hb = (key, x, y, label, text, cls, w, title) => {
    const it = { key, kind: 'state', x: r2(x), y: r2(y), w: w || Math.max(130, Math.ceil(Math.max(S.geom.textWidth(label, 13, { bold: true }), S.geom.textWidth(text, 15, { mono: true })) + 26)), h: 58, rx: 8, lines: [label, text], cls: 'block val2 s11-hb ' + (cls || '') };
    if (title) it.title = title;
    return it;
  };
  W.box = (key, x, y, w, h, lines, cls) => ({ key, kind: 'state', x: r2(x), y: r2(y), w, h, rx: 7, lines, cls: 'block ' + (cls || '') });
  W.wire = (key, pts, cls, head) => ({ key, kind: 'wire', pts: pts.map((p) => [r2(p[0]), r2(p[1])]), head: head !== false, cls: cls || '' });
  W.edge = (key, from, to, cls, label) => { const e = { key, kind: 'edge', from, to, cls: cls || '' }; if (label) e.label = label; return e; };
  W.chip = (key, x, y, text, cls, title) => { const c = { key, kind: 'chip', x: r2(x), y: r2(y), text, cls: cls || '', onWire: false }; if (title) c.title = title; return c; };
  W.party = (key, x, y, name, cls) => KP().party({ key, x, y, name, cls, r: 22 });
  W.arrow = (key, x1, x2, y, text, cls) => KP().msg({ key, x1, x2, y, text, cls });
  /** a row of byte cells: bytes, from (x, y), cell width cw; cls(i) for each */
  W.strip = (o) => Array.from(o.bytes, (v, i) => ({ key: o.prefix + i, kind: 'cell', x: r2(o.x + i * (o.cw || 22)), y: o.y, w: (o.cw || 22) - (o.gap === undefined ? 2 : o.gap), h: o.h || 24, rx: 2, text: v.toString(16).padStart(2, '0'), size: o.size || 12, cls: 's11-byte mono ' + (o.cls ? o.cls(i, v) || '' : '') }));
  /** a row of bits, most significant first */
  W.bitrow = (o) => [...o.bits].map((b, i) => ({ key: o.prefix + i, kind: 'cell', x: r2(o.x + i * (o.cw || 24)), y: o.y, w: (o.cw || 24) - 2, h: o.h || 26, rx: 3, text: b, size: 13, cls: 'bit ' + (b === '1' ? 'one ' : '') + (o.cls ? o.cls(i, b) || '' : '') }));
  /** a verdict: ✓ or ✗ with words */
  W.verdict = (key, x, y, ok, words, anchor) => W.t(key, x, y, (ok ? '✓ ' : '✗ ') + words, ok ? 'good s11-verdict' : 'bad s11-verdict', anchor || 'middle', 17);
  /** a table: cols [{w, head, mono}], rows [[text | {text, cls}]], from (x, y); returns {items, h} */
  W.table = function (o) {
    const P = o.prefix || 'tb', rh = o.rh || 30, items = [], fs = o.size || 13;
    let x = o.x;
    o.cols.forEach((c, j) => { if (c.head !== undefined) items.push({ key: P + ':h' + j, kind: 'text', x: r2(x + c.w / 2), y: o.y + 15, text: c.head, anchor: 'middle', size: 13, cls: 's11-head' }); x += c.w; });
    const y0 = o.y + (o.cols.some((c) => c.head !== undefined) ? 26 : 0);
    o.rows.forEach((row, i) => {
      let cx = o.x;
      row.forEach((cell, j) => {
        const c = cell !== null && typeof cell === 'object' ? cell : { text: cell === null || cell === undefined ? '' : String(cell) };
        const it = { key: P + ':' + i + ':' + j, kind: 'cell', x: r2(cx), y: r2(y0 + i * rh), w: o.cols[j].w, h: rh - 2, rx: 3, text: c.text, size: c.size || fs, cls: 's11-cell ' + (o.cols[j].mono ? 'mono ' : '') + (c.cls || '') };
        if (c.title) it.title = c.title;
        items.push(it);
        cx += o.cols[j].w;
      });
    });
    return { items, h: y0 - o.y + o.rows.length * rh };
  };
  W.def = (title, lines) => ({ sections: [{ id: 'd', kind: 'math', title, text: lines.join('\n') }] });
  W.fix = (frames, box) => { for (const f of frames) f.view = Object.assign({}, box); return frames; };

  // ---- keys -------------------------------------------------------------------------------------------------------
  /** the toy RSA keys: two small primes each */
  W.TOY_RSA = { toy: [1031n, 1019n], toy2: [65521n, 65519n] };
  W.rsaKey = (name) => (W.TOY_RSA[name] ? S.RSA.fromPrimes(W.TOY_RSA[name][0], W.TOY_RSA[name][1], 65537n) : S.PK.rsaKey(name));
  W.rsaName = (name) => (W.TOY_RSA[name] ? 'the toy key' : name.replace('rsa', 'RSA-'));
})(globalThis.Sifer = globalThis.Sifer || {});
