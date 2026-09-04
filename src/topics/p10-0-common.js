// Part 10, elliptic curves: the families, and the drawing helpers their pictures share
// (a point cloud over GF(p) with marked points and wrapped lines, rows of bits, small tables, panels of equations and
// readouts, people and messages). Every frame these parts add carries `facts`, the values its narration quotes, so
// tests/claims-p10.mjs can check each one against an independent working-out.
(function (S) {
  'use strict';
  const U = (S.P10 = S.P10 || {});
  const fam = (id, part, order, title, blurb) => S.family({ id, part, order, title, blurb });
  fam('p10-real', 'ecc', 10, 'Curves over the reals', 'The shape of y² = x³ + ax + b as a and b change, and the chord-and-tangent rule that adds two points.');
  fam('p10-field', 'ecc', 20, 'Curves over GF(p)', 'The same rule on a cloud of points, the point at infinity, the order of a point, the shape of the group and Hasse\'s bound.');
  fam('p10-scalar', 'ecc', 30, 'Scalar multiplication', 'k·P by double-and-add, by the Montgomery ladder and by signed digits, and what Jacobian coordinates save.');
  fam('p10-ecdh', 'ecc', 40, 'Key exchange', 'Elliptic-curve Diffie–Hellman on a toy curve and on P-256, and X25519 with its clamped scalar and ladder.');
  fam('p10-forms', 'ecc', 50, 'Curve shapes and encodings', 'Weierstrass, Montgomery and Edwards forms of one curve, P-256 against Curve25519, and point compression.');
  fam('p10-dlog', 'ecc', 60, 'Attacks on the logarithm', 'Baby-step giant-step and Pollard\'s rho on any curve, Pohlig–Hellman on a smooth order, and Smart\'s attack on an anomalous curve.');
  fam('p10-valid', 'ecc', 70, 'Validation attacks', 'Points that are not on the curve, and points on its twist: what a victim leaks when it skips one check.');

  const r2 = (v) => Math.round(v * 100) / 100;
  U.r2 = r2;
  /** a number short enough for a sentence (decimal below 2^40, else 0x and its first and last 8 hex digits) */
  U.f = (v) => S.ECC.fmt(v);
  U.fp = (P) => S.ECC.fp(P);
  /** a decimal number with d places and a true minus sign */
  U.fx = (v, d) => { const s = Number(v).toFixed(d === undefined ? 2 : d); return /^-0(\.0*)?$/.test(s) ? s.slice(1) : s.replace('-', '−'); };
  U.int = (v) => String(v).replace('-', '−');
  U.sub = (i) => String(i).split('').map((d) => '₀₁₂₃₄₅₆₇₈₉'[d] || d).join('');
  U.sup = (i) => String(i).split('').map((d) => ('0123456789'.includes(d) ? '⁰¹²³⁴⁵⁶⁷⁸⁹'[d] : d === '-' ? '⁻' : d)).join('');
  U.plural = (n, w, ws) => n + ' ' + (Number(n) === 1 ? w : ws || w + 's');
  U.list = (xs) => { xs = xs.map(String); return xs.length < 2 ? xs.join('') : xs.slice(0, -1).join(', ') + ' and ' + xs[xs.length - 1]; };
  U.hex = (b) => Array.from(b, (x) => (x & 255).toString(16).padStart(2, '0')).join('');
  U.unhex = (h) => { h = String(h).replace(/\s+/g, ''); const out = new Uint8Array(h.length >> 1); for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(2 * i, 2), 16); return out; };
  U.utf8 = (s) => new TextEncoder().encode(s);
  /** a hex string cut to its first and last n digits */
  U.hs = (h, n) => { n = n || 8; return h.length > 2 * n + 2 ? h.slice(0, n) + '…' + h.slice(-n) : h; };
  U.B = (v) => (typeof v === 'bigint' ? v : BigInt(String(v).trim()));
  /** a whole-number input between lo and hi (BigInt-safe) */
  U.range = (lo, hi, what) => (v) => { let x; try { x = U.B(v); } catch (e) { return what + ': a whole number'; } if (x < U.B(lo)) return what + ': at least ' + lo; if (hi !== undefined && x > U.B(hi)) return what + ': at most ' + hi; return null; };
  /** "x, y" or "(x, y)" as a point of BigInts, or null */
  U.parsePoint = (s) => { const m = /^\s*\(?\s*(\d+)\s*[, ]\s*(\d+)\s*\)?\s*$/.exec(String(s || '')); return m ? { x: BigInt(m[1]), y: BigInt(m[2]) } : null; };
  U.pt = (P) => (P ? `(${P.x}, ${P.y})` : 'O');

  // ---- the canvas -------------------------------------------------------------------------------------------------
  U.V = { x: 0, y: 0, w: 920, h: 660 };
  U.fix = (frames, box) => { for (const f of frames) f.view = Object.assign({}, box || U.V); return frames; };
  U.def = (title, lines) => ({ sections: [{ id: 'd', kind: 'math', title, text: lines.join('\n') }] });
  /** free text */
  U.t = (key, x, y, text, cls, anchor, size) => { const it = { key, kind: 'text', x: r2(x), y: r2(y), text, cls: cls || '', anchor: anchor || 'start' }; if (size) it.size = size; return it; };
  U.title = (key, x, y, text) => ({ key, kind: 'text', x, y, text, cls: 'title' });
  /** a heading that is an equation or a name: not in capitals */
  U.head = (key, x, y, text, cls) => ({ key, kind: 'text', x, y, text, cls: 'eq strong ' + (cls || ''), size: 17 });
  /** lines of equations, each [text, cls] */
  U.eqs = (prefix, x, y, lines, size, gap) => lines.filter(Boolean).map(([text, cls], k) => ({ key: prefix + k, kind: 'text', x, y: r2(y + k * (gap || 28)), text, cls: 'eq ' + (cls || ''), size: size || 16 }));
  /** a framed panel with a title in its top-left corner */
  U.panel = (key, x, y, w, h, title, cls) => [{ key, kind: 'region', x, y, w, h, rx: 10, cls: 'panel ' + (cls || '') }].concat(title ? [{ key: key + ':t', kind: 'text', x: x + 14, y: y + 22, text: title, cls: 'title' }] : []);
  /** label: value rows in a panel; rows [[label, value, cls]] */
  U.readout = function (prefix, x, y, w, title, rows, o) {
    o = o || {};
    const dy = o.dy || 30, items = U.panel(prefix, x, y, w, 36 + rows.length * dy + 6, title, o.cls);
    rows.forEach(([label, value, cls], i) => {
      items.push(U.t(prefix + ':l' + i, x + 14, y + 52 + i * dy, label, 'e10-lab', 'start', o.size || 13));
      items.push(U.t(prefix + ':v' + i, x + w - 14, y + 52 + i * dy, String(value), 'mono e10-val ' + (cls || ''), 'end', o.vsize || 14));
    });
    return items;
  };
  /**
   * A table of cells: cols [{w, head, align}], rows [[text | {text, cls}]], from (x, y). o: {prefix, rh, size, hl(r) -> cls}
   * Returns {items, h}.
   */
  U.table = function (o) {
    const P = o.prefix || 'tb', rh = o.rh || 30, items = [], fs = o.size || 13;
    let x = o.x;
    o.cols.forEach((c, j) => {
      if (c.head !== undefined) items.push({ key: P + '/h' + j, kind: 'text', x: r2(x + c.w / 2), y: o.y + 15, text: c.head, anchor: 'middle', size: 13, cls: 'e10-head' });
      x += c.w;
    });
    const y0 = o.y + (o.cols.some((c) => c.head !== undefined) ? 26 : 0);
    o.rows.forEach((row, i) => {
      let cx = o.x;
      const rc = o.hl ? o.hl(i) || '' : '';
      row.forEach((cell, j) => {
        const c = cell !== null && typeof cell === 'object' ? cell : { text: cell === null || cell === undefined ? '' : String(cell) };
        items.push({ key: P + '/r' + i + 'c' + j, kind: 'cell', x: r2(cx), y: r2(y0 + i * rh), w: o.cols[j].w, h: rh - 2, rx: 3, text: c.text, size: c.size || fs, cls: 'e10-cell ' + (o.cols[j].mono === false ? '' : 'mono ') + rc + ' ' + (c.cls || ''), align: o.cols[j].align });
        cx += o.cols[j].w;
      });
    });
    return { items, h: y0 - o.y + o.rows.length * rh };
  };
  /** a row of bit cells, most significant first: bits a string of 0/1; cls(i, bit) where i counts from the top */
  U.bits = function (o) {
    const items = [], cw = o.cw || 22, gap = o.gap === undefined ? 2 : o.gap;
    [...o.bits].forEach((b, i) => {
      items.push({ key: o.prefix + i, kind: 'cell', x: r2(o.x + i * (cw + gap)), y: o.y, w: cw, h: o.ch || 26, rx: 3, text: o.text ? o.text(b, i) : b, size: o.size || 14, cls: 'bit ntc e10-bit ' + (b === '1' ? 'one' : 'zero') + ' ' + (o.cls ? o.cls(i, b) || '' : '') });
    });
    return items;
  };
  /** a row of value cells: values [text], from (x, y) */
  U.cells = function (o) {
    const items = [], gap = o.gap === undefined ? 3 : o.gap;
    o.values.forEach((v, i) => items.push({ key: o.prefix + i, kind: 'cell', x: r2(o.x + i * (o.cw + gap)), y: o.y, w: o.cw, h: o.ch || 30, rx: 3, text: String(v), size: o.size || 13, cls: 'e10-cell mono ' + (o.cls ? o.cls(i, v) || '' : '') }));
    return items;
  };

  // ---- curves over GF(p) ------------------------------------------------------------------------------------------
  /** a small curve from {p, a, b} or a toy id; the error message when it cannot be made */
  U.curveOf = function (p, a, b) {
    p = U.B(p);
    if (!S.NT.isProbablePrime(p) || p < 5n) throw new Error('p must be a prime of at least 5');
    return S.ECC.curve({ p, a, b });
  };
  /** check a (p, a, b) input: the error sentence or null */
  U.curveCheck = (inp, maxP) => {
    const p = Number(inp.p);
    if (!S.NT.isProbablePrime(BigInt(p)) || p < 5) return 'p: a prime of at least 5';
    if (p > maxP) return 'p: at most ' + maxP + ', so every point can be drawn';
    const a = ((Number(inp.a) % p) + p) % p, b = ((Number(inp.b) % p) + p) % p;
    if ((4 * a * a * a + 27 * b * b) % p === 0) return 'This curve is singular: 4a³ + 27b² ≡ 0 (mod ' + p + ')';
    return null;
  };
  const tickStep = (p) => (p <= 20 ? 2 : p <= 40 ? 5 : p <= 70 ? 10 : p <= 140 ? 20 : p <= 400 ? 50 : 200);
  const dotR = (p) => (p <= 20 ? 6 : p <= 40 ? 4.6 : p <= 70 ? 3.8 : p <= 140 ? 3.2 : 1.7);
  /**
   * The cloud of a small curve in the square {x, y, s}: every affine point as a dot. Returns {pl, items, pts, X, Y,
   * dotKey(P), marks(list, drawn) (names placed clear of everything), modLine(key, P, λ, cls), vline(key, x, cls),
   * seg(key, P, Q, cls), r}.
   */
  U.cloud = function (C, o) {
    const p = Number(C.p), s = o.s || 470, CV = S.Kit.curve;
    const step = tickStep(p);
    const lo = p <= 140 ? -1 : -p / 60;
    const pl = CV.plot({ prefix: o.prefix || 'cl', x: o.x, y: o.y, w: s, h: s, xr: [lo, p - 1], yr: [lo, p - 1], ticks: { x: step, y: step }, labels: { origin: true }, axisAt: { x: lo, y: lo }, tickSize: 13, grid: o.grid !== false && p <= 140 });
    const r = o.r || dotR(p), pts = o.points || C.points();
    const pre = (o.prefix || 'cl') + ':p';
    const dots = pts.map((P) => ({ key: pre + ':' + P.x + ',' + P.y, kind: 'dot', x: pl.X(Number(P.x)), y: pl.Y(Number(P.y)), r, cls: 'cloud ' + (o.cls ? o.cls(P) || '' : ''), point: p <= 200, audit: p > 200 ? 'ignore' : undefined }));
    const n = (P) => ({ x: Number(P.x), y: Number(P.y) });
    const out = {
      pl, pts, r, X: pl.X, Y: pl.Y, items: [...pl.items, ...dots], dots,
      dotKey: (P) => pre + ':' + P.x + ',' + P.y,
      /** marks [[key, P, name, cls, prefer]] with their names placed clear of the cloud and of drawn lines */
      marks: (list, drawn, size) => CV.marks(pl, list.filter((m) => m[1]).map(([k, P, name, cls, dir]) => ({ key: (o.prefix || 'cl') + ':m:' + k, P: n(P), name, cls, prefer: dir })), dots.concat(drawn || []), size || 15),
      /** the line through P with slope λ, lap by lap; the laps through the points in `on` are drawn strong, the rest faint */
      modLine: (key, P, lambda, cls, on) => {
        let l = Number(lambda);
        if (Math.abs(l - p) < Math.abs(l)) l -= p;
        // lap k: the stretch of x where k·p ≤ f(x) ≤ k·p + p − 1, drawn inside the square
        const items = [], f0 = (u) => l * (u - Number(P.x)) + Number(P.y), fr = [f0(0), f0(p - 1)];
        for (let k = Math.floor(Math.min(...fr) / p); k <= Math.floor(Math.max(...fr) / p); k++) {
          let a = (k * p - Number(P.y)) / l + Number(P.x), b = (k * p + p - 1 - Number(P.y)) / l + Number(P.x);
          if (a > b) [a, b] = [b, a];
          a = Math.max(a, 0); b = Math.min(b, p - 1);
          if (b - a < 1e-6) continue;
          const A = [pl.X(a), pl.Y(f0(a) - k * p)], Bq = [pl.X(b), pl.Y(f0(b) - k * p)];
          items.push({ key: key + k, kind: 'path', d: `M${A[0]},${A[1]} L${Bq[0]},${Bq[1]}`, cls: cls || 'modline', pathAudit: 'edge-x', samples: CV.sampleSeg(A, Bq) });
        }
        if (!on) return items;
        const laps = new Set(on.filter(Boolean).map((R) => Math.floor((l * (Number(R.x) - Number(P.x)) + Number(P.y)) / p)));
        return items.map((it) => { const k = Number(it.key.slice(key.length)); return laps.has(k) ? it : Object.assign({}, it, { cls: (it.cls || '') + ' e10-faintline', pathAudit: undefined, audit: 'ignore', samples: undefined, layer: 'back' }); });
      },
      vline: (key, x, cls) => [{ key, kind: 'path', d: `M${pl.X(Number(x))},${pl.Y(0)} V${pl.Y(p - 1)}`, cls: cls || 'modline', pathAudit: 'edge-x', samples: CV.sampleSeg([pl.X(Number(x)), pl.Y(0)], [pl.X(Number(x)), pl.Y(p - 1)]) }],
      hline: (key, y, cls) => [{ key, kind: 'path', d: `M${pl.X(0)},${pl.Y(y)} H${pl.X(p - 1)}`, cls: cls || 'e10-half', audit: 'ignore', layer: 'back' }],
      seg: (key, P, Q, cls) => CV.segment(pl, key, n(P), n(Q), cls || 'mirror'),
    };
    return out;
  };
  /** the toy curves a picture can draw whole, as choice options */
  U.toyOptions = (ids) => ids.map((id) => { const t = S.ECC.TOYS.find((x) => x.id === id); return { value: id, label: `y² = x³ + ${t.a}x + ${t.b} over GF(${t.p})` }; });

  // ---- people and messages ----------------------------------------------------------------------------------------
  U.party = (key, x, y, name, cls, r) => S.Kit.pk.party({ key, x, y, name, cls, r: r || 24 });
  /** a value block: label above, value below, centred on (x, y) */
  U.value = (key, x, y, label, value, cls, w) => ({ key, kind: 'state', x: r2(x), y: r2(y), w: w || Math.max(120, Math.ceil(Math.max(S.geom.textWidth(label, 13, { bold: true }), S.geom.textWidth(value, 15, { mono: true })) + 26)), h: 58, rx: 8, lines: [label, value], cls: 'block val2 ' + (cls || '') });
  /** a horizontal arrow from x1 to x2 at height y with a value chip on it */
  U.arrow = (key, x1, x2, y, text, cls) => S.Kit.pk.msg({ key, x1, x2, y, text, cls });
})(globalThis.Sifer = globalThis.Sifer || {});
