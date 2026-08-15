// Part 2, Euclid: the Euclidean algorithm as a table that fills row by row (with the rectangle cut into squares
// beside it while the numbers are small), and the extended algorithm as a table of r, q, s and t, followed by the
// back-substitution that reaches the same coefficients from the other end, and the inverse read off the last row.
(function (S) {
  'use strict';
  const H = S.P02, NT = () => S.NT;
  const n$ = H.n;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const abs = (v) => (v < 0n ? -v : v);
  const CH = 15 * 0.6; // the width of one monospace character at 15px
  const colW = (vals, min) => Math.max(min || 48, Math.ceil(Math.max(...vals.map((v) => n$(v).length)) * CH + 22));
  /** the rows of a long table to show once `shown` rows are filled: the first three, a gap, the latest seven */
  const windowOf = (shown) => (shown <= 11 ? [...Array(shown).keys()] : [0, 1, 2, -1].concat([...Array(7).keys()].map((k) => shown - 7 + k)));
  /** a term of a sum with its sign: " + 5·46" or " − 4·240" (the first term keeps a plain minus) */
  const term = (c, x, first) => { const xs = typeof x === 'string' ? x : n$(x), m = abs(c) === 1n ? xs : n$(abs(c)) + '·' + xs; return first ? (c < 0n ? '−' : '') + m : (c < 0n ? ' − ' : ' + ') + m; };
  const lin = (c1, x1, c2, x2) => term(c1, x1, true) + term(c2, x2, false);

  // ---------------------------------------------------------------------------------------------------------------
  // The Euclidean algorithm
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'euclid', family: 'p02-euclid', order: 10, title: 'The Euclidean algorithm',
    blurb: 'To find gcd(a, b), divide a by b and keep the remainder; then divide b by that remainder, and so on. Each row of the table moves b up to a and the remainder up to b, and the last divisor before a remainder of 0 is the greatest common divisor. As a picture: cut the largest squares you can from an a × b rectangle, again and again; the last square tiles everything.',
    inputs: [
      { id: 'a', kind: 'bigint', label: 'a', def: '2024', check: H.range(1, 10n ** 24n - 1n, 'a') },
      { id: 'b', kind: 'bigint', label: 'b', def: '748', check: H.range(1, 10n ** 24n - 1n, 'b') },
    ],
    presets: [
      { label: '2024 and 748', values: { a: '2024', b: '748' } },
      { label: 'Coprime: 391 and 105', values: { a: '391', b: '105' } },
      { label: 'b divides a: 96 and 32', values: { a: '96', b: '32' } },
      { label: 'Smaller first: 126 and 300', values: { a: '126', b: '300' } },
      { label: 'The worst case: Fibonacci 6765 and 4181', values: { a: '6765', b: '4181' } },
      { label: 'Large: 2^61 − 1 and 65537', values: { a: '2305843009213693951', b: '65537' } },
      { label: 'Large with a common factor', values: { a: '614889782588491410', b: '3749562977351496827' } },
    ],
    counters: [{ id: 'div', label: 'divisions' }],
    run(inp) {
      const a0 = H.big(inp.a), b0 = H.big(inp.b);
      const eu = NT().euclid(a0, b0), rows = eu.rows, g = eu.g, total = rows.length;
      const F = new S.Frames(['div']);
      // the table: a = q·b + r, one row per division
      const wa = colW(rows.map((r) => r.a), 64), wq = colW(rows.map((r) => r.q), 44), wb = colW(rows.map((r) => r.b), 64), wr = colW(rows.map((r) => r.r), 64);
      const gap = 30, rh = 36, top = 44;
      const xa = 0, xq = xa + wa + gap, xb = xq + wq + gap, xr = xb + wb + gap, tW = xr + wr;
      const head = [H.title('tt', 0, 0, 'Divide, and divide again')];
      [['a', xa, wa], ['q', xq, wq], ['b', xb, wb], ['r', xr, wr]].forEach(([t, x, w]) => head.push({ key: 'hd' + t, kind: 'text', x: x + w / 2, y: 30, text: t, anchor: 'middle', size: 15, cls: 'ntlab' }));
      const table = (shown, lit) => {
        const it = [];
        windowOf(shown).forEach((i, j) => {
          const y = top + j * rh;
          if (i < 0) { it.push({ key: 'gap', kind: 'text', x: xa + wa / 2, y: y + 22, text: '⋮  ' + (shown - 10) + ' more rows  ⋮', size: 14, cls: 'ntlab' }); return; }
          const r = rows[i], L = lit(i) || {};
          const c = (k, x, w, v, cls, src) => { const o = { key: 'r' + i + k, kind: 'cell', x, y, w, h: rh - 6, rx: 5, text: n$(v), size: 15, cls: 'mono ntc ' + (cls || '') }; if (src) { o.enter = 'from'; o.src = src; } return o; };
          it.push(c('a', xa, wa, r.a, L.a, i ? 'r' + (i - 1) + 'b' : null), c('q', xq, wq, r.q, L.q), c('b', xb, wb, r.b, L.b, i ? 'r' + (i - 1) + 'r' : null), c('r', xr, wr, r.r, L.r));
          for (const [k, x, t] of [['e', xq - gap / 2, '='], ['m', xb - gap / 2, '·'], ['p', xr - gap / 2, '+']]) it.push({ key: 'r' + i + k, kind: 'text', x, y: y + rh / 2 + 2, text: t, anchor: 'middle', size: 16, cls: 'strong' });
        });
        return it;
      };
      // the rectangle cut into squares, while the numbers are small enough to see
      const tiles = total <= 9 && a0 < 1000000n && b0 < 1000000n && (a0 > b0 ? a0 <= 8n * b0 : b0 <= 8n * a0);
      const big = a0 >= b0 ? a0 : b0, small = a0 >= b0 ? b0 : a0;
      const px = tW + 70, side = 400, sc = side / Number(big);
      const rect = () => {
        if (!tiles) return [];
        return [H.title('rt', px, 0, 'A ' + big + ' × ' + small + ' rectangle'), { key: 'rect', kind: 'region', x: px - 3, y: top - 3, w: Number(big) * sc + 6, h: Number(small) * sc + 6, rx: 3, cls: 'frame', audit: 'group' }];
      };
      // squares cut by row i (q of them, side b): the rectangle left is b by r
      const squares = (upto, hot) => {
        if (!tiles) return [];
        const it = [];
        let X = 0, Y = 0, W = Number(big), Ht = Number(small);
        rows.forEach((r, i) => {
          if (i > upto) return;
          const s = Number(r.b), q = Number(r.q);
          const along = W >= Ht;
          for (let k = 0; k < q; k++) {
            const x = along ? X + k * s : X, y = along ? Y : Y + k * s, pw = s * sc;
            if (pw < 3) continue;
            it.push({ key: 'sq' + i + '_' + k, kind: 'cell', x: px + x * sc + 1.5, y: top + y * sc + 1.5, w: pw - 3, h: pw - 3, rx: 2, text: pw >= 34 && k === 0 ? String(s) : '', size: 13, cls: 'mono ntc ' + (i === hot ? 'hot' : H.kc(i)) });
          }
          if (along) { X += q * s; W -= q * s; } else { Y += q * s; Ht -= q * s; }
        });
        return it;
      };
      F.add({ items: head.concat(table(0, () => ({})), rect()), say: 'Find gcd(' + n$(a0) + ', ' + n$(b0) + '). Divide the larger by the smaller and keep only the remainder: any common divisor of a and b also divides the remainder.', meta: { phase: 'start' } });
      const frameRows = total <= 14 ? [...Array(total).keys()] : [0, 1, 2, 3, Math.floor(total / 2), total - 3, total - 2, total - 1];
      frameRows.forEach((i, k) => {
        const r = rows[i], prev = frameRows[k - 1];
        F.set('div', i + 1);
        const lit = (j) => (j === i ? { a: 'act', q: 'hot', b: 'key', r: 'hot' } : j === i - 1 ? { b: 'act', r: 'key' } : {});
        let say = n$(r.a) + ' = ' + n$(r.q) + '·' + n$(r.b) + ' + ' + n$(r.r) + '.';
        if (i === 0 && r.q === 0n) say += ' a is the smaller, so the quotient is 0 and the first row just swaps them.';
        else if (prev !== undefined && i - prev > 1) say = 'After ' + (i - prev - 1) + ' more rows: ' + say;
        else if (i > 0) say = 'The divisor ' + n$(r.a) + ' moves up to a and the remainder ' + n$(r.b) + ' to b: ' + say;
        if (r.r === 0n) say += ' The remainder is 0, so the algorithm stops.';
        else if (tiles && r.q > 0n) say += ' In the rectangle: ' + H.plural(Number(r.q), 'square') + ' of side ' + n$(r.b) + ', leaving ' + n$(r.r) + ' by ' + n$(r.b) + '.';
        F.add({ items: head.concat(table(i + 1, lit), rect(), squares(i, i)), say, meta: { phase: 'row', i, r: r.r, q: r.q } });
      });
      const lastI = total - 1;
      const done = (j) => (j === lastI ? { b: 'good', r: 'muted' } : {});
      const lines = [['gcd(' + n$(a0) + ', ' + n$(b0) + ') = ' + n$(g), 'good']].concat(g === 1n ? [['coprime: no common factor but 1', 'muted']] : [[n$(a0) + ' = ' + n$(a0 / g) + '·' + n$(g), 'act'], [n$(b0) + ' = ' + n$(b0 / g) + '·' + n$(g), 'key']]);
      const ly = top + windowOf(total).length * rh + 30;
      F.add({ items: head.concat(table(total, done), rect(), squares(lastI, -1), H.eqs('gl', 0, ly, lines, 16, 30)), say: 'The last divisor is ' + n$(g) + ', so gcd(' + n$(a0) + ', ' + n$(b0) + ') = ' + n$(g) + ', found in ' + H.plural(total, 'division') + '. Check: ' + n$(a0) + ' = ' + n$(a0 / g) + '·' + n$(g) + ' and ' + n$(b0) + ' = ' + n$(b0 / g) + '·' + n$(g) + (g === 1n ? ': the two numbers are coprime.' : '.') + (tiles ? ' The smallest squares, ' + n$(g) + ' by ' + n$(g) + ', would tile the whole rectangle.' : ''), meta: { phase: 'done', g } });
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'Euclid', text: ['gcd(a, b) = gcd(b, a mod b)', 'gcd(a, 0) = a', 'a = q·b + r, 0 ≤ r < b', 'at most about 2.08·ln(min) + 2 divisions;', 'consecutive Fibonacci numbers need the most'].join('\n') }] } };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'row' && fr[i + 1].meta.i > 0 && fr[i + 1].meta.i - (f.meta.i === undefined ? -1 : f.meta.i) === 1, once: true, pick: 'option', ask: 'What will the next remainder be?', options: (fr, i) => { const r = fr[i + 1].meta.r, q = fr[i + 1].meta.q; return [...new Set([r, r + 1n, q, r + 2n])].map(String); }, answer: (fr, i) => String(fr[i + 1].meta.r), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i) => f.meta.phase === 'start', pick: 'option', ask: (fr, i, inp) => 'What is gcd(' + inp.a + ', ' + inp.b + ')?', options: (fr) => { const g = fr[fr.length - 1].meta.g; return [...new Set([g, 1n, 2n * g, g + 2n])].map(String); }, answer: (fr) => String(fr[fr.length - 1].meta.g), explain: (fr) => fr[fr.length - 1].say },
    ],
    quiz: [
      { q: 'What is gcd(84, 36)?', options: ['6', '12', '4', '18'], answer: 1, why: '84 = 2·36 + 12, 36 = 3·12 + 0.' },
      { q: 'Why does gcd(a, b) = gcd(b, r) when a = q·b + r?', options: ['a common divisor of a and b divides r = a − q·b, and one of b and r divides a', 'because r < b', 'because q is an integer', 'it is not true in general'], answer: 0, why: 'The two pairs have exactly the same common divisors.' },
      { q: 'Which pairs make Euclid take the most steps for their size?', options: ['consecutive Fibonacci numbers', 'two primes', 'powers of 2', 'a number and its square'], answer: 0, why: 'Every quotient is 1, so the numbers shrink as slowly as they can.' },
      { q: 'How does the number of divisions grow with the size of the numbers?', options: ['with the number of digits', 'with the numbers themselves', 'with their square', 'it is constant'], answer: 0, why: 'The remainder at least halves every two steps, so a 600-digit pair needs only a few thousand divisions.' },
      { q: 'If the last nonzero remainder is 1, the numbers are…', options: ['coprime', 'both prime', 'equal', 'both odd'], answer: 0, why: 'Their only common divisor is 1.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The extended Euclidean algorithm
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'egcd', family: 'p02-euclid', order: 20, title: 'The extended Euclidean algorithm',
    blurb: 'Keep, beside each remainder r, two numbers s and t with r = a·s + b·t. The first two rows are free (a = a·1 + b·0, b = a·0 + b·1), and each new row is the row two above minus q times the row above. When r reaches the gcd, its s and t are the coefficients: g = a·s + b·t. When g = 1, t is the inverse of b modulo a. Back-substitution reaches the same coefficients by working up from the last division.',
    inputs: [
      { id: 'a', kind: 'bigint', label: 'a', def: '360', check: H.range(1, 10n ** 20n - 1n, 'a') },
      { id: 'b', kind: 'bigint', label: 'b', def: '77', check: H.range(1, 10n ** 20n - 1n, 'b') },
    ],
    presets: [
      { label: '360 and 77: an inverse', values: { a: '360', b: '77' } },
      { label: '240 and 46: gcd 2', values: { a: '240', b: '46' } },
      { label: 'A toy RSA key: 8448 and 17', values: { a: '8448', b: '17' } },
      { label: 'b divides a: 91 and 13', values: { a: '91', b: '13' } },
      { label: 'Fibonacci: 610 and 377', values: { a: '610', b: '377' } },
      { label: 'Large: 2^61 − 1 and 65537', values: { a: '2305843009213693951', b: '65537' } },
    ],
    counters: [{ id: 'rows', label: 'rows' }, { id: 'subs', label: 'substitutions' }],
    run(inp) {
      const a = H.big(inp.a), b = H.big(inp.b);
      const eg = NT().egcd(a, b), rows = eg.rows, g = eg.g, total = rows.length;
      const F = new S.Frames(['rows', 'subs']);
      const wi = 40, wr = colW(rows.map((r) => r.r), 60), wq = colW(rows.map((r) => r.q === null ? 0n : r.q), 48), ws = colW(rows.map((r) => r.s), 60), wt = colW(rows.map((r) => r.t), 60);
      const gx = 8, rh = 36, top = 44;
      const cols = [['i', wi], ['r', wr], ['q', wq], ['s', ws], ['t', wt]];
      const X = {}; let x = 0; for (const [k, w] of cols) { X[k] = x; x += w + gx; }
      const tW = x - gx;
      const head = [H.title('tt', 0, 0, 'The extended table')];
      cols.forEach(([k, w]) => head.push({ key: 'hd' + k, kind: 'text', x: X[k] + w / 2, y: 30, text: k, anchor: 'middle', size: 15, cls: 'ntlab' }));
      const table = (shown, lit, qShown) => {
        const it = [];
        windowOf(shown).forEach((i, j) => {
          const y = top + j * rh;
          if (i < 0) { it.push({ key: 'gap', kind: 'text', x: tW / 2, y: y + 22, text: '⋮  ' + (shown - 10) + ' more rows  ⋮', anchor: 'middle', size: 14, cls: 'ntlab' }); return; }
          const r = rows[i], L = lit(i) || {};
          for (const [k, w] of cols) {
            const v = k === 'i' ? String(i) : k === 'q' ? (r.q === null || i >= qShown ? '' : n$(r.q)) : n$(r[k]);
            it.push({ key: 'e' + i + k, kind: 'cell', x: X[k], y, w, h: rh - 6, rx: 5, text: v, size: 15, cls: 'mono ntc ' + (k === 'i' ? 'muted ' : '') + (L[k] || L.all || '') });
          }
        });
        return it;
      };
      // the side panel: the table's work, then the back-substitution
      const px = tW + 60, wide = tW > 520;
      const panelAt = (n) => (wide ? { x: 0, y: top + windowOf(total).length * rh + 34 } : { x: px, y: 40 });
      const panel = (title, lines, n) => { const p = panelAt(n); return [wide ? H.text('pt', p.x, p.y - 26, title, 'ntlab', 15) : H.title('pt', p.x, p.y - 26, title)].concat(H.eqs('pl', p.x, p.y, lines, wide ? 14 : 16, wide ? 26 : 30)); };
      F.set('rows', 2);
      F.add({ items: head.concat(table(2, (i) => ({ s: 'key', t: 'key' }), 2), panel('Why rows 0 and 1 hold', [[n$(a) + ' = ' + n$(a) + '·1 + ' + n$(b) + '·0', 'key'], [n$(b) + ' = ' + n$(a) + '·0 + ' + n$(b) + '·1', 'key']])), say: 'Rows 0 and 1 are a = ' + n$(a) + ' and b = ' + n$(b) + ' themselves: ' + n$(a) + ' = ' + n$(a) + '·1 + ' + n$(b) + '·0 and ' + n$(b) + ' = ' + n$(a) + '·0 + ' + n$(b) + '·1. Every row will keep r = a·s + b·t true.', meta: { phase: 'start' } });
      const show = total <= 14 ? [...Array(total).keys()].slice(2) : [2, 3, 4, Math.floor(total / 2), total - 3, total - 2, total - 1];
      show.forEach((i, k) => {
        const p = rows[i - 2], c = rows[i - 1], nr = rows[i], q = c.q;
        F.set('rows', i + 1);
        const lit = (j) => (j === i ? { all: 'hot' } : j === i - 1 ? { all: 'act', q: 'hot' } : j === i - 2 ? { all: 'key' } : {});
        const lines = [['q = ' + n$(p.r) + ' div ' + n$(c.r) + ' = ' + n$(q), 'hot'], ['r: ' + n$(p.r) + ' − ' + n$(q) + '·' + n$(c.r) + ' = ' + n$(nr.r)], ['s: ' + n$(p.s) + ' − ' + n$(q) + '·' + (c.s < 0n ? '(' + n$(c.s) + ')' : n$(c.s)) + ' = ' + n$(nr.s)], ['t: ' + n$(p.t) + ' − ' + n$(q) + '·' + (c.t < 0n ? '(' + n$(c.t) + ')' : n$(c.t)) + ' = ' + n$(nr.t)]];
        if (nr.r !== 0n) lines.push([n$(nr.r) + ' = ' + n$(a) + '·' + (nr.s < 0n ? '(' + n$(nr.s) + ')' : n$(nr.s)) + ' + ' + n$(b) + '·' + (nr.t < 0n ? '(' + n$(nr.t) + ')' : n$(nr.t)), 'good']);
        const skip = k > 0 && i - show[k - 1] > 1 ? 'After ' + H.plural(i - show[k - 1] - 1, 'more row') + ': ' : '';
        const say = skip + 'q = ' + n$(p.r) + ' div ' + n$(c.r) + ' = ' + n$(q) + '. Row ' + i + ' = row ' + (i - 2) + ' − ' + n$(q) + '·row ' + (i - 1) + ': r = ' + n$(p.r) + ' − ' + n$(q) + '·' + n$(c.r) + ' = ' + n$(nr.r) + ', s = ' + n$(nr.s) + ', t = ' + n$(nr.t) + '. ' + (nr.r === 0n ? 'The remainder is 0: the row above holds the gcd.' : 'Check: ' + n$(a) + '·' + (nr.s < 0n ? '(' + n$(nr.s) + ')' : n$(nr.s)) + ' + ' + n$(b) + '·' + (nr.t < 0n ? '(' + n$(nr.t) + ')' : n$(nr.t)) + ' = ' + n$(nr.r) + '.');
        F.add({ items: head.concat(table(i + 1, lit, i), panel('Row ' + i, lines)), say, meta: { phase: 'row', i, r: nr.r, s: nr.s, t: nr.t } });
      });
      const gi = total - 2, x0 = eg.x, y0 = eg.y;
      const sgn = (v) => (v < 0n ? '(' + n$(v) + ')' : n$(v));
      F.add({ items: head.concat(table(total, (j) => (j === gi ? { all: 'good' } : {}), total), panel('The result', [['gcd(' + n$(a) + ', ' + n$(b) + ') = ' + n$(g), 'good'], [n$(g) + ' = ' + n$(a) + '·' + sgn(x0) + ' + ' + n$(b) + '·' + sgn(y0), 'good']])), say: 'Row ' + gi + ' holds the last nonzero remainder: gcd(' + n$(a) + ', ' + n$(b) + ') = ' + n$(g) + ', and its s and t give ' + n$(g) + ' = ' + n$(a) + '·' + sgn(x0) + ' + ' + n$(b) + '·' + sgn(y0) + '.', meta: { phase: 'result', x: x0, y: y0 } });
      // back-substitution from the plain Euclid rows: g = u·A + v·B, walked up one division at a time
      const eu = NT().euclid(a, b).rows, m = eu.length;
      let bs;
      if (m < 2) {
        bs = { lines: [[n$(g) + ' = ' + n$(a) + '·0 + ' + n$(b) + '·1', 'good']], u: 0n, v: 1n };
        F.add({ items: head.concat(table(total, (j) => (j === gi ? { all: 'good' } : {}), total), panel('Back-substitution', bs.lines)), say: 'Back-substitution has nothing to do here: ' + n$(b) + ' divides ' + n$(a) + ', so the gcd is b itself, ' + n$(g) + ' = ' + n$(a) + '·0 + ' + n$(b) + '·1.', meta: { phase: 'back', u: 0n, v: 1n } });
      } else {
        // g comes from row m − 2: g = a_j − q_j·b_j
        let j = m - 2, A = eu[j].a, Bv = eu[j].b, u = 1n, v = -eu[j].q;
        const lines = [[n$(g) + ' = ' + lin(u, A, v, Bv), 'act']];
        const many = m - 2 > 6;
        const panelLines = () => (lines.length > 9 ? [lines[0], ['⋮', 'muted']].concat(lines.slice(-7)) : lines);
        F.add({ items: head.concat(table(total, (k) => (k === gi ? { all: 'good' } : {}), total), panel('Back-substitution', panelLines())), say: 'Now the other way: back-substitution. Division ' + (j + 1) + ' of plain Euclid, ' + n$(eu[j].a) + ' = ' + n$(eu[j].q) + '·' + n$(eu[j].b) + ' + ' + n$(g) + ', gives ' + n$(g) + ' = ' + lin(u, A, v, Bv) + '.', meta: { phase: 'back', u, v } });
        let subs = 0;
        while (j > 0) {
          const pr = eu[j - 1]; // pr.r = Bv: replace it by pr.a − pr.q·pr.b
          const sub = n$(g) + ' = ' + term(u, A, true) + term(v, '(' + n$(pr.a) + ' − ' + n$(pr.q) + '·' + n$(pr.b) + ')', false);
          const nu = v, nv = u - v * pr.q;
          A = pr.a; Bv = pr.b; u = nu; v = nv; j--; subs++;
          lines.push([sub]); lines.push([n$(g) + ' = ' + lin(u, A, v, Bv), j === 0 ? 'good' : 'act']);
          F.set('subs', subs);
          if (many && j > 2 && j < m - 4) continue;
          F.add({ items: head.concat(table(total, (k) => (k === gi ? { all: 'good' } : {}), total), panel('Back-substitution', panelLines())), say: 'Replace ' + n$(pr.r) + ' by ' + n$(pr.a) + ' − ' + n$(pr.q) + '·' + n$(pr.b) + ' (from division ' + (j + 1) + '): ' + sub + ', which collects to ' + n$(g) + ' = ' + lin(u, A, v, Bv) + '.', meta: { phase: 'back', u, v } });
        }
        bs = { u, v };
        const last = F.last();
        const same = u === x0 && v === y0;
        last.say += same ? ' The same coefficients as the table, ' + n$(x0) + ' and ' + n$(y0) + ': the table simply does the substitutions as it goes down.' : ' The table gave ' + n$(x0) + ' and ' + n$(y0) + ': a different pair, as the coefficients are not unique.';
        last.meta.same = same;
      }
      // the inverse, when the gcd is 1
      if (g === 1n) {
        const ib = NT().mod(y0, a), ia = b > 1n ? NT().mod(x0, b) : null;
        F.add({ items: head.concat(table(total, (k) => (k === gi ? { t: 'good', s: ia !== null ? 'key' : '' } : {}), total), panel('Inverses for free', [['1 = ' + n$(a) + '·' + sgn(x0) + ' + ' + n$(b) + '·' + sgn(y0)], [n$(b) + '⁻¹ ≡ ' + n$(ib) + ' (mod ' + n$(a) + ')', 'good']].concat(ia !== null ? [[n$(a) + '⁻¹ ≡ ' + n$(ia) + ' (mod ' + n$(b) + ')', 'key']] : []))), say: 'The gcd is 1, so read the equation modulo ' + n$(a) + ': the multiple of ' + n$(a) + ' vanishes and ' + n$(b) + '·' + sgn(y0) + ' ≡ 1 (mod ' + n$(a) + '), so ' + n$(b) + '⁻¹ ≡ ' + n$(ib) + ' (mod ' + n$(a) + ')' + (y0 < 0n ? ' (' + n$(y0) + ' + ' + n$(a) + ')' : '') + '.' + (ia !== null ? ' Modulo ' + n$(b) + ' it gives ' + n$(a) + '⁻¹ ≡ ' + n$(ia) + ' (mod ' + n$(b) + ').' : ''), meta: { phase: 'inverse', inv: ib } });
      }
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'Extended Euclid', text: ['row 0: r = a, s = 1, t = 0', 'row 1: r = b, s = 0, t = 1', 'q = r(i−2) div r(i−1)', 'row i = row (i−2) − q·row (i−1)', 'invariant: r = a·s + b·t', 'gcd = a·s + b·t on the last nonzero row', 'g = 1  ⇒  b⁻¹ ≡ t (mod a)'].join('\n') }] } };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'row' && fr[i + 1].meta.r !== 0n && (f.meta.phase === 'row' || f.meta.phase === 'start') && fr[i + 1].meta.i - (f.meta.i === undefined ? 1 : f.meta.i) === 1, once: true, pick: 'option', ask: (fr, i) => 'What will t be on row ' + fr[i + 1].meta.i + '?', options: (fr, i) => { const t = fr[i + 1].meta.t; return [...new Set([t, -t, t + 1n, t - 1n])].map(n$); }, answer: (fr, i) => n$(fr[i + 1].meta.t), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta.phase === 'result' && fr[i + 1], pick: 'option', ask: 'Will back-substitution end with the same coefficients as the table?', options: ['yes', 'no'], answer: (fr) => { const l = fr.filter((x) => x.meta.phase === 'back').pop(); return l && l.meta.same === false ? 'no' : 'yes'; }, explain: (fr) => fr.filter((x) => x.meta.phase === 'back').pop().say },
    ],
    quiz: [
      { q: 'In the extended table, row i is computed as…', options: ['row (i−2) − q·row (i−1)', 'row (i−1) − q·row (i−2)', 'row (i−1)·q', 'row (i−2) + row (i−1)'], answer: 0, why: 'The same step as the remainder r(i) = r(i−2) − q·r(i−1), applied to s and t too.' },
      { q: '1 = 17·(−5) + 43·2. What is 17⁻¹ modulo 43?', options: ['38', '5', '2', '−2'], answer: 0, why: 'Modulo 43 the 43-term vanishes: 17·(−5) ≡ 1, and −5 + 43 = 38.' },
      { q: 'Why can every row keep r = a·s + b·t?', options: ['the rule is linear, so subtracting q times one true equation from another gives a true equation', 'because q is the quotient', 'because the gcd divides r', 'because s and t are small'], answer: 0, why: 'Rows 0 and 1 are true, and each new row is a combination of the two above.' },
      { q: 'When gcd(a, b) = 3, the equation a·x + b·y = 1 has…', options: ['no integer solution', 'exactly one', 'infinitely many', 'a solution only if a > b'], answer: 0, why: '3 divides the left-hand side for every integer x and y, but not 1.' },
      { q: 'RSA computes the private exponent d with…', options: ['the extended Euclidean algorithm on e and φ(n)', 'square-and-multiply', 'the Chinese remainder theorem', 'Miller–Rabin'], answer: 0, why: 'd = e⁻¹ mod φ(n), read off the extended table.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
