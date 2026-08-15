// Part 2, the binary fields GF(2^m): multiplication by shift-and-add with reduction, step by step; the inverse in
// GF(2^8) by the extended Euclidean algorithm on polynomials; and the 16 × 16 table of the AES field, where every
// nonzero byte is a power of {03}, so logarithms turn multiplication into addition.
(function (S) {
  'use strict';
  const H = S.P02, GF = () => S.GF, G8 = () => S.gf256;
  const sup = H.sup;
  const xp = (k) => (k === 0 ? '1' : k === 1 ? 'x' : 'x' + sup(k));
  const hex2 = (v) => Number(v).toString(16).padStart(2, '0');
  const byteIn = (what) => (v) => (!/^[0-9a-f]{1,2}$/i.test(String(v).trim()) ? what + ': one byte in hex, 00 to ff' : null);
  const byteOf = (v) => parseInt(String(v).trim(), 16);

  // ---------------------------------------------------------------------------------------------------------------
  // GF(2^m) multiplication: shift and add, with reduction
  // ---------------------------------------------------------------------------------------------------------------
  const fieldOf = (m) => GF().binary(m);
  /** how a field element is written in a sentence: bits for a small field, {hex} for a byte */
  const say$ = (m, v) => (m <= 5 ? BigInt(v).toString(2).padStart(m, '0') + '₂' : '{' + BigInt(v).toString(16).padStart(Math.ceil(m / 4), '0') + '}');
  S.topic({
    id: 'gf2m-mul', family: 'p02-fields', order: 30, title: 'Multiplying in GF(2^m): shift, add, reduce',
    blurb: 'GF(2^m) is the polynomials over GF(2) of degree below m, multiplied modulo an irreducible polynomial f of degree m. Walk the bits of b from the bottom: where a bit is 1, add the current multiple of a; then multiply that multiple by x, a shift, and if an x^m term appears, cancel it by adding f.',
    inputs: [
      { id: 'm', kind: 'choice', label: 'Field', def: '8', options: [{ value: '3', label: 'GF(2³), f = x³ + x + 1' }, { value: '4', label: 'GF(2⁴), f = x⁴ + x + 1' }, { value: '5', label: 'GF(2⁵), f = x⁵ + x² + 1' }, { value: '8', label: 'GF(2⁸), the AES field' }] },
      { id: 'a', kind: 'string', label: 'a (hex)', def: '4d', alphabet: '0123456789abcdef', min: 1, max: 2, check: (v, inp) => (parseInt(v, 16) >= 1 << +inp.m ? 'a: below ' + (1 << +inp.m).toString(16) + ' (hex) in this field' : null) },
      { id: 'b', kind: 'string', label: 'b (hex)', def: 'a6', alphabet: '0123456789abcdef', min: 1, max: 2, check: (v, inp) => (parseInt(v, 16) >= 1 << +inp.m ? 'b: below ' + (1 << +inp.m).toString(16) + ' (hex) in this field' : null) },
    ],
    presets: [
      { label: 'AES field: {4d}·{a6}', values: { m: '8', a: '4d', b: 'a6' } },
      { label: 'AES field: {c9}·{0b}', values: { m: '8', a: 'c9', b: '0b' } },
      { label: 'Times {02} is xtime', values: { m: '8', a: 'b4', b: '02' } },
      { label: 'GF(2⁴): 1011 · 0110', values: { m: '4', a: 'b', b: '6' } },
      { label: 'GF(2³): 110 · 111', values: { m: '3', a: '6', b: '7' } },
      { label: 'GF(2⁵): 10101 · 11011', values: { m: '5', a: '15', b: '1b' } },
    ],
    counters: [{ id: 'adds', label: 'additions' }, { id: 'shifts', label: 'shifts' }, { id: 'reductions', label: 'reductions' }],
    run(inp) {
      const m = +inp.m, F = fieldOf(m), a = BigInt(parseInt(inp.a, 16)), b = BigInt(parseInt(inp.b, 16));
      const res = F.mulTrace(a, b), rows = res.rows, f = F.f, low = f ^ (1n << BigInt(m));
      const Fr = new S.Frames(['adds', 'shifts', 'reductions']);
      const cw = m > 5 ? 26 : 32, ch = 28, gp = 3;
      const xT = 150, xA = xT + m * (cw + gp) + 56, xG = xT - (cw + gp), yG = 46 + m * (ch + 8) + 40;
      const rowY = (i) => 46 + i * (ch + 8);
      const bitCells = (key, x, y, v, width, cls, opts = {}) => {
        const it = [];
        for (let j = width - 1; j >= 0; j--) {
          const bit = Number((BigInt(v) >> BigInt(j)) & 1n), col = width - 1 - j;
          it.push({ key: key + ':' + j, kind: 'cell', x: x + col * (cw + gp), y, w: cw, h: ch, rx: 3, text: String(bit), size: 14, cls: 'bit ntc ' + (bit ? 'one' : 'zero') + ' ' + (typeof cls === 'function' ? cls(j, bit) || '' : cls || '') });
        }
        if (opts.hex !== false) it.push({ key: key + ':h', kind: 'text', x: x + width * (cw + gp) + 8, y: y + 19, text: m > 5 ? '{' + hex2(v) + '}' : '', size: 13, cls: 'mono' });
        return it;
      };
      const bitsB = [...Array(m).keys()].map((i) => Number((b >> BigInt(i)) & 1n));
      const topB = bitsB.lastIndexOf(1);
      const head = () => [H.text('t1', 0, 30, 'bits of b', 'ntlab', 14), H.text('t2', xT, 30, 'xⁱ·a, reduced mod f', 'ntlab', 14), H.text('t3', xA, 30, 'running sum', 'ntlab', 14)];
      // the table so far: rows 0..i, row i lit
      const table = (upto, accUpto, lit, addHot) => {
        const it = head();
        for (let i = 0; i < m; i++) {
          const on = i <= upto, r = rows[i];
          it.push({ key: 'bi' + i, kind: 'cell', x: 0, y: rowY(i), w: 92, h: ch, rx: 4, text: 'b' + subI(i) + ' = ' + bitsB[i], size: 14, cls: 'mono ntc ' + (i === lit ? 'act' : i > topB ? 'soft' : bitsB[i] ? '' : 'soft') });
          if (on) it.push(...bitCells('ta' + i, xT, rowY(i), r.term, m, i === lit ? 'act' : bitsB[i] ? '' : 'soft'));
          if (i <= accUpto) it.push(...bitCells('ac' + i, xA, rowY(i), r.acc, m, i === accUpto && addHot ? (j, bit) => (((r.term >> BigInt(j)) & 1n) ? 'hot' : '') : i === accUpto ? 'act' : ''));
        }
        return it;
      };
      const subI = (i) => String(i).split('').map((d) => '₀₁₂₃₄₅₆₇₈₉'[d]).join('');
      // the shift-and-reduce gadget for step i: term, shifted (m + 1 bits), maybe ⊕ f, next
      const gadget = (i) => {
        const r = rows[i], W = m + 1, gy = (k) => yG + k * (ch + 8);
        const it = [H.text('g0', 0, yG - 14, 'Row ' + i + ' to row ' + (i + 1) + ': multiply by x', 'ntlab act', 14)];
        it.push(H.text('gl1', 0, gy(0) + 19, xp(i) + '·a', 'ntlab', 14));
        it.push(...bitCells('g1', xG, gy(0), r.term, W, (j) => (j === m ? 'soft' : ''), { hex: false }));
        it.push(H.text('gl2', 0, gy(1) + 19, 'shifted', 'ntlab', 14));
        it.push(...bitCells('g2', xG, gy(1), r.shifted, W, (j, bit) => (j === m && bit ? 'hot' : ''), { hex: false }));
        let k = 2;
        if (r.reduced) {
          it.push(H.text('gl3', 0, gy(2) + 19, '⊕ f', 'ntlab key', 14));
          it.push(...bitCells('g3', xG, gy(2), f, W, 'key', { hex: false }));
          k = 3;
        }
        const yN = gy(k) + 6;
        it.push({ key: 'grule', kind: 'line', x1: xG - 3, y1: yN - 7, x2: xG + W * (cw + gp), y2: yN - 7, cls: 'rule' });
        it.push(H.text('gl4', 0, yN + 19, xp(i + 1) + '·a', 'ntlab good', 14));
        it.push(...bitCells('g4', xG, yN, r.next, W, (j) => (j === m ? 'soft' : 'good'), { hex: false }));
        return it;
      };
      const def = { sections: [{ id: 'eq', kind: 'math', title: 'GF(2^' + m + ')', text: ['elements: polynomials of degree < ' + m + ' over GF(2)', 'f = ' + GF().poly.str(f) + (m === 8 ? ' ({11b})' : ''), 'a + b = a ⊕ b', 'a·b: for each 1 bit bᵢ add xⁱ·a; x·v = shift, ⊕ f if xᵐ appears'].join('\n') }] };
      Fr.add({ items: table(0, -1, -1), say: 'Multiply a = ' + say$(m, a) + ' = ' + GF().poly.str(a) + ' by b = ' + say$(m, b) + ' = ' + GF().poly.str(b) + ' in GF(2' + sup(m) + '), where f = ' + GF().poly.str(f) + '. Row i will hold xⁱ·a (reduced) and the sum of the rows whose bit of b is 1.', meta: { phase: 'start' } });
      for (let i = 0; i < m; i++) {
        const r = rows[i];
        if (i > topB) break;
        if (r.bit) Fr.count('adds');
        const before = i ? rows[i - 1].acc : 0n;
        Fr.add({ items: table(i, i, i, !!r.bit), say: r.bit ? 'Bit ' + i + ' of b is 1: add ' + xp(i) + '·a = ' + say$(m, r.term) + ' to the running sum: ' + say$(m, before) + ' ⊕ ' + say$(m, r.term) + ' = ' + say$(m, r.acc) + '.' : 'Bit ' + i + ' of b is 0: ' + xp(i) + '·a = ' + say$(m, r.term) + ' is not added; the sum stays ' + say$(m, r.acc) + '.', meta: { phase: 'add', i, bit: r.bit, acc: r.acc.toString() } });
        if (i < topB) {
          Fr.count('shifts'); if (r.reduced) Fr.count('reductions');
          Fr.add({ items: table(i + 1, i, i + 1, false).concat(gadget(i)), say: 'Multiply by x for the next row: shift ' + say$(m, r.term) + ' one place left' + (r.reduced ? '. A term x' + sup(m) + ' appears, which is not in the field, so add f: ' + say$(m + 1, r.shifted) + ' ⊕ ' + say$(m + 1, f) + ' gives ' + xp(i + 1) + '·a = ' + say$(m, r.next) + '.' : ', and no x' + sup(m) + ' term appears: ' + xp(i + 1) + '·a = ' + say$(m, r.next) + '.'), meta: { phase: 'shift', i, reduced: r.reduced, next: r.next.toString() } });
        }
      }
      const pr = res.value;
      const extra = m === 8 ? ' The AES tables agree: {' + hex2(a) + '}·{' + hex2(b) + '} = {' + hex2(G8().fastMul(Number(a), Number(b))) + '}.' : '';
      Fr.add({ items: table(topB < 0 ? 0 : topB, topB < 0 ? 0 : topB, -1, false).concat(bitCells('pr', xA, rowY(m) + 14, pr, m, 'good'), [H.text('prl', xA - 12, rowY(m) + 33, 'a·b =', 'strong', 16, 'end')]), say: 'a·b = ' + say$(m, pr) + ' = ' + GF().poly.str(pr) + ' in GF(2' + sup(m) + '): ' + Fr.counts.adds + ' addition' + (Fr.counts.adds === 1 ? '' : 's') + ', ' + Fr.counts.shifts + ' shift' + (Fr.counts.shifts === 1 ? '' : 's') + ' and ' + Fr.counts.reductions + ' reduction' + (Fr.counts.reductions === 1 ? '' : 's') + ', all of them XORs and shifts.' + extra, meta: { phase: 'done', value: pr.toString() } });
      return { frames: Fr.list, def };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta && fr[i + 1].meta.phase === 'shift', pick: 'option', ask: 'After the shift, will an xᵐ term appear, so that f must be added?', options: ['yes', 'no'], answer: (fr, i) => (fr[i + 1].meta.reduced ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta && fr[i + 1].meta.phase === 'done', pick: 'option', ask: 'What is a·b?', options: (fr, i, inp) => { const m = +inp.m, v = BigInt(fr[i + 1].meta.value), M = (1n << BigInt(m)) - 1n; return [...new Set([v, v ^ 1n, (v << 1n) & M, v ^ (1n << BigInt(m - 1))])].map((x) => say$(m, x)); }, answer: (fr, i, inp) => say$(+inp.m, BigInt(fr[i + 1].meta.value)), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'In GF(2⁸) with f = {11b}, what is {80}·{02}?', options: ['{1b}', '{00}', '{100}', '{01}'], answer: 0, why: 'The shift gives x⁸, which is replaced by x⁴ + x³ + x + 1 = {1b}.' },
      { q: 'Why must f be irreducible?', options: ['so every nonzero element has an inverse', 'so the shifts are fast', 'so a·b = b·a', 'so that 1 + 1 = 0'], answer: 0, why: 'If f factored as g·h, then g·h ≡ 0 with g, h ≠ 0: zero divisors, as in Z_n for composite n.' },
      { q: 'How many elements does GF(2⁴) have?', options: ['16', '15', '4', '8'], answer: 0, why: 'All polynomials of degree below 4: 2⁴ of them.' },
      { q: 'Multiplying by x in GF(2^m) costs…', options: ['a shift, and at most one XOR with f', 'a full multiplication', 'a table lookup only', 'a division'], answer: 0, why: 'That is xtime in AES: shift left, and XOR {1b} if the top bit fell off.' },
      { q: 'Adding two elements of GF(2⁸) is…', options: ['XOR of the bytes', 'addition modulo 256', 'addition modulo 255', 'OR of the bytes'], answer: 0, why: 'Coefficients add modulo 2.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The inverse in GF(2^8) by the extended Euclidean algorithm
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'gf256-inverse', family: 'p02-fields', order: 40, title: 'Inverting in GF(2⁸) with Euclid',
    blurb: 'The extended Euclidean algorithm works for polynomials as for numbers: divide f by a, then a by the remainder, and so on, carrying a second column t with each remainder r ≡ t·a (mod f). When the remainder reaches 1, t is a⁻¹. This is the inverse the AES S-box starts from.',
    inputs: [{ id: 'a', kind: 'string', label: 'a (one byte, hex)', def: '7c', alphabet: '0123456789abcdef', min: 1, max: 2 }],
    presets: [
      { label: '{7c}', values: { a: '7c' } },
      { label: '{95}', values: { a: '95' } },
      { label: '{02}: one division', values: { a: '02' } },
      { label: '{01}: its own inverse', values: { a: '01' } },
      { label: '{e4}', values: { a: 'e4' } },
      { label: '{00}: no inverse', values: { a: '00' } },
    ],
    counters: [{ id: 'divs', label: 'divisions' }],
    run(inp) {
      const a = BigInt(parseInt(inp.a, 16)), F = fieldOf(8), P = GF().poly, ps = P.str;
      const res = F.invTrace(a), rows = res.rows;
      const Fr = new S.Frames(['divs']);
      const TB = S.Kit.table;
      // rows: r_i, q_i, t_i; r_0 = f, r_1 = a; the quotient of row i is stored on row i when the next row is made
      const tableItems = (upto, lit, done) => {
        const body = [];
        for (let i = 0; i <= upto; i++) {
          const r = rows[i];
          body.push([String(i), ps(r.r), '{' + (i === 0 ? '11b' : hex2(r.r)) + '}', r.q !== null && i < upto ? ps(r.q) : '', ps(r.t)]);
        }
        return TB.draw({ prefix: 'iv', x: 0, y: 24, rows: body, colHead: ['i', 'remainder rᵢ', 'hex', 'quotient qᵢ', 'tᵢ (rᵢ ≡ tᵢ·a)'], ch: 36, size: 15, cls: (r, c) => 'ntc ' + (r === lit ? (c === 4 ? 'key' : 'act') : done && r === upto ? 'good' : '') }).items;
      };
      const head = H.text('tt', 0, 8, 'Extended Euclid on polynomials over GF(2), modulo f = x⁸ + x⁴ + x³ + x + 1', 'ntlab', 15);
      const def = { sections: [{ id: 'eq', kind: 'math', title: 'The rows', text: ['r₀ = f, t₀ = 0;  r₁ = a, t₁ = 1', 'rᵢ₋₁ = qᵢ·rᵢ + rᵢ₊₁  (long division)', 'tᵢ₊₁ = tᵢ₋₁ + qᵢ·tᵢ', 'every row: rᵢ ≡ tᵢ·a (mod f)', 'rᵢ = 1  ⇒  a⁻¹ = tᵢ'].join('\n') }] };
      if (a === 0n) {
        Fr.add({ items: [head].concat(tableItems(1, 1)), say: '{00} is the zero polynomial: no t makes 0·t ≡ 1, so it has no inverse. AES simply maps {00} to {00} before its affine step.', meta: { phase: 'zero' } });
        Fr.add({ items: [head].concat(tableItems(1, -1)), say: 'The S-box value of {00} is therefore the affine map of {00}: {' + hex2(G8().SBOX[0]) + '}.', meta: { phase: 'zero2' } });
        return { frames: Fr.list, def };
      }
      Fr.add({ items: [head].concat(tableItems(1, 1)), say: 'Row 0 holds f = ' + ps(F.f) + ' with t = 0, row 1 holds a = {' + hex2(a) + '} = ' + ps(a) + ' with t = 1: each row\'s remainder is t times a, modulo f.', meta: { phase: 'start' } });
      for (let i = 2; i < rows.length; i++) {
        const prev = rows[i - 2], cur = rows[i - 1], nx = rows[i];
        Fr.count('divs');
        Fr.add({ items: [head].concat(tableItems(i, i)), say: 'Divide r' + subI(i - 2) + ' = ' + ps(prev.r) + ' by r' + subI(i - 1) + ' = ' + ps(cur.r) + ': quotient ' + ps(cur.q) + ', remainder ' + ps(nx.r) + '. Then t' + subI(i) + ' = t' + subI(i - 2) + ' + q·t' + subI(i - 1) + ' = ' + ps(prev.t) + ' + (' + ps(cur.q) + ')(' + ps(cur.t) + ') = ' + ps(nx.t) + '.', meta: { phase: 'row', i, r: nx.r.toString(), t: nx.t.toString() } });
      }
      const inv = res.inv, last = rows.length - 1;
      const check = F.mul(a, inv);
      Fr.add({ items: [head].concat(tableItems(last, -1, true), H.eqs('ck', 0, 24 + 34 + (last + 1) * 36 + 40, [['a⁻¹ = {' + hex2(inv) + '} = ' + ps(inv), 'good'], ['{' + hex2(a) + '}·{' + hex2(inv) + '} = {' + hex2(check) + '}', 'good']], 16, 30)), say: 'The remainder is 1 in row ' + last + ', so 1 ≡ t' + subI(last) + '·a (mod f): a⁻¹ = {' + hex2(inv) + '} = ' + ps(inv) + '. Check: {' + hex2(a) + '}·{' + hex2(inv) + '} = {' + hex2(check) + '}, and the log tables give the same inverse, {' + hex2(G8().inv(Number(a))) + '}. The AES S-box then applies its affine map: S({' + hex2(a) + '}) = {' + hex2(G8().SBOX[Number(a)]) + '}.', meta: { phase: 'done', inv: inv.toString() } });
      return { frames: Fr.list, def };
    },
    predict: [
      { at: (f, i, fr) => f.meta && (f.meta.phase === 'start' || f.meta.phase === 'row') && fr[i + 1] && fr[i + 1].meta.phase === 'done', pick: 'option', ask: 'The remainder has reached 1. What is a⁻¹?', options: (fr, i) => { const v = BigInt(fr[i + 1].meta.inv); return [...new Set([v, v ^ 1n, v ^ 0x80n, (v << 1n) & 255n])].map((x) => '{' + hex2(x) + '}'); }, answer: (fr, i) => '{' + hex2(BigInt(fr[i + 1].meta.inv)) + '}', explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta && f.meta.phase === 'start' && fr[i + 1] && fr[i + 1].meta.phase === 'row', pick: 'option', ask: 'How many divisions will it take to reach a remainder of 1?', options: (fr) => { const k = fr.filter((x) => x.meta.phase === 'row').length; return [...new Set([k, k + 1, Math.max(1, k - 1), k + 2])].map(String); }, answer: (fr) => String(fr.filter((x) => x.meta.phase === 'row').length), explain: (fr) => fr[fr.length - 1].say },
    ],
    quiz: [
      { q: 'What is the inverse of {02} in the AES field?', options: ['{8d}', '{80}', '{01}', '{1b}'], answer: 0, why: '{8d} = x⁷ + x³ + x² + 1; times x it is x⁸ + x⁴ + x³ + x, and x⁸ ≡ x⁴ + x³ + x + 1 (mod f), so the product is 1.' },
      { q: 'What does every row of the table keep true?', options: ['rᵢ ≡ tᵢ·a (mod f)', 'rᵢ = tᵢ', 'qᵢ = rᵢ + 1', 'tᵢ = 1'], answer: 0, why: 'It holds for rows 0 and 1, and each new row is a combination of the two before.' },
      { q: 'Why does the algorithm always reach 1 for a ≠ 0?', options: ['f is irreducible, so gcd(f, a) = 1', 'because a < f', 'because 2 is prime', 'it does not'], answer: 0, why: 'An irreducible f shares no factor with any nonzero polynomial of lower degree.' },
      { q: 'What does AES do with {00}, which has no inverse?', options: ['maps it to {00}', 'skips the byte', 'uses {01}', 'raises an error'], answer: 0, why: 'By definition, then the affine map gives S({00}) = {63}.' },
      { q: 'Subtraction in the division steps is…', options: ['XOR', 'subtraction modulo 256', 'AND', 'a shift'], answer: 0, why: 'Coefficients are taken modulo 2, where − and + agree.' },
    ],
  });
  const subI = (i) => String(i).split('').map((d) => '₀₁₂₃₄₅₆₇₈₉'[d]).join('');

  // ---------------------------------------------------------------------------------------------------------------
  // The table of the AES field: logarithms to the base {03}
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'gf256-table', family: 'p02-fields', order: 50, title: 'The AES field as a table',
    blurb: 'Every nonzero byte of GF(2⁸) is a power of {03}: walking {01}, {03}, {05}, {0f}, … visits all 255 of them. Write each byte\'s exponent in a 16 × 16 table and multiplication becomes adding exponents modulo 255; the inverse is the exponent 255 − log a. Fast tables of this kind are how software multiplies in the field.',
    inputs: [
      { id: 'a', kind: 'string', label: 'a (hex)', def: '4d', alphabet: '0123456789abcdef', min: 1, max: 2, check: byteIn('a') },
      { id: 'b', kind: 'string', label: 'b (hex)', def: 'a6', alphabet: '0123456789abcdef', min: 1, max: 2, check: byteIn('b') },
    ],
    presets: [
      { label: '{4d}·{a6}', values: { a: '4d', b: 'a6' } },
      { label: '{02}·{87}', values: { a: '02', b: '87' } },
      { label: '{ff}·{ff}', values: { a: 'ff', b: 'ff' } },
      { label: '{01} times anything', values: { a: '01', b: 'c3' } },
      { label: 'A product with {00}', values: { a: '00', b: '4e' } },
    ],
    counters: [{ id: 'powers', label: 'powers of {03}' }],
    run(inp) {
      const a = byteOf(inp.a), b = byteOf(inp.b), g = G8();
      const Fr = new S.Frames(['powers']);
      // the powers of {03}, computed by the field's own multiplication
      const pows = [1];
      for (let k = 1; k < 255; k++) pows.push(g.mul(pows[k - 1], 3));
      const log = new Array(256).fill(null);
      pows.forEach((v, k) => { if (log[v] === null) log[v] = k; });
      const cw = 36, ch = 26, gp = 2, x0 = 30, y0 = 40;
      const cx = (v) => x0 + (v & 15) * (cw + gp), cy = (v) => y0 + (v >> 4) * (ch + gp);
      const heads = () => { const it = []; for (let c = 0; c < 16; c++) it.push({ key: 'hc' + c, kind: 'text', x: x0 + c * (cw + gp) + cw / 2, y: y0 - 8, text: c.toString(16), anchor: 'middle', size: 14, cls: 'ntlab' }); for (let r = 0; r < 16; r++) it.push({ key: 'hr' + r, kind: 'text', x: x0 - 8, y: y0 + r * (ch + gp) + 18, text: r.toString(16), anchor: 'end', size: 14, cls: 'ntlab' }); return it; };
      const grid = (title, text, cls) => [H.text('gt', 0, 12, title, 'ntlab', 15)].concat(heads(), [...Array(256).keys()].map((v) => ({ key: 'g' + v, kind: 'cell', x: cx(v), y: cy(v), w: cw, h: ch, rx: 3, text: text(v), size: 14, cls: 'mono ntc ' + (cls(v) || '') })));
      const px = x0 + 16 * (cw + gp) + 28, lines = [];
      const panel = () => H.eqs('pl', px, 40, lines, 15, 28);
      const logText = (upto) => (v) => (v === 0 ? '–' : log[v] <= upto ? String(log[v]) : '');
      const def = { sections: [{ id: 'eq', kind: 'math', title: 'Logarithms in GF(2⁸)', text: ['{03} generates: {03}ᵏ, k = 0 … 254, is every nonzero byte', 'log a: the k with {03}ᵏ = a', 'a·b = {03}^((log a + log b) mod 255)', 'a⁻¹ = {03}^(255 − log a)', 'row = high hex digit, column = low hex digit'].join('\n') }] };
      Fr.add({ items: grid('The 256 bytes: row = high digit, column = low digit', (v) => hex2(v), () => ''), say: 'The 256 elements of the AES field, one cell each: row ' + (a >> 4).toString(16) + ', column ' + (a & 15).toString(16) + ' is the byte {' + hex2(a) + '}. Now fill in, for each byte, which power of {03} it is.', meta: { phase: 'bytes' } });
      // the walk of powers, in growing strides
      let shown = -1;
      for (const upto of [7, 31, 254]) {
        const from = shown + 1;
        shown = upto;
        Fr.set('powers', upto + 1);
        lines.length = 0;
        const firsts = pows.slice(from, Math.min(upto + 1, from + 6));
        lines.push(['{03}⁰ = {01}', 'strong']);
        const say = from === 0 ? 'Start at {03}⁰ = {01} and multiply by {03} again and again: ' + pows.slice(0, 8).map((v, k) => '{' + hex2(v) + '}').join(', ') + '. Each cell gets its exponent.' : upto < 254 ? 'Powers ' + from + ' to ' + upto + ' fill more cells, in no visible pattern: ' + firsts.map((v, k) => '{03}' + sup(from + k) + ' = {' + hex2(v) + '}').join(', ') + ', …' : 'By {03}' + sup(254) + ' = {' + hex2(pows[254]) + '} every nonzero byte has appeared exactly once, and {03}' + sup(255) + ' = {' + hex2(g.mul(pows[254], 3)) + '} starts again. {03} generates all 255 nonzero elements: this table of exponents is the logarithm table.';
        lines.push(['{03}' + sup(upto) + ' = {' + hex2(pows[upto]) + '}', 'act']);
        if (upto === 254) lines.push(['{03}²⁵⁵ = {01}', 'good'], ['255 distinct powers', 'good']);
        Fr.add({ items: grid('log₀₃ of each byte: the k with {03}ᵏ = byte', logText(upto), (v) => (v && log[v] >= from && log[v] <= upto ? 'act' : v && log[v] <= upto ? '' : 'empty')).concat(panel()), say, meta: { phase: 'walk', upto } });
      }
      lines.length = 0;
      const all = (v) => (v === 0 ? '–' : String(log[v]));
      if (a === 0 || b === 0) {
        lines.push(['log {00} does not exist', 'bad'], ['{' + hex2(a) + '}·{' + hex2(b) + '} = {00}', 'strong']);
        Fr.add({ items: grid('log₀₃ of each byte', all, (v) => (v === a || v === b ? 'hot' : '')).concat(panel()), say: '{00} is no power of {03}, so it has no logarithm: a table-driven multiply must test for zero first. {' + hex2(a) + '}·{' + hex2(b) + '} = {00}.', meta: { phase: 'mul', value: 0 } });
      } else {
        const s = log[a] + log[b], sm = s % 255, pr = pows[sm];
        lines.push(['log {' + hex2(a) + '} = ' + log[a], 'act'], ['log {' + hex2(b) + '} = ' + log[b], 'key'], [log[a] + ' + ' + log[b] + ' = ' + s + (s >= 255 ? ' ≡ ' + sm + ' (mod 255)' : ''), 'strong'], ['{03}' + sup(sm) + ' = {' + hex2(pr) + '}', 'good'], ['{' + hex2(a) + '}·{' + hex2(b) + '} = {' + hex2(pr) + '}', 'good']);
        Fr.add({ items: grid('log₀₃ of each byte', all, (v) => (v === a ? 'act' : v === b ? 'key' : v === pr ? 'good' : '')).concat(panel()), say: 'To multiply, add logarithms: log {' + hex2(a) + '} = ' + log[a] + ' and log {' + hex2(b) + '} = ' + log[b] + '; ' + log[a] + ' + ' + log[b] + ' = ' + s + (s >= 255 ? ' ≡ ' + sm + ' (mod 255)' : '') + ', and the cell holding ' + sm + ' is {' + hex2(pr) + '}. So {' + hex2(a) + '}·{' + hex2(b) + '} = {' + hex2(pr) + '}, which shift-and-add confirms: {' + hex2(g.mul(a, b)) + '}.', meta: { phase: 'mul', value: pr } });
      }
      // the inverse of a, and the inverse table
      const ai = g.inv(a), invLog = a ? '255 − ' + log[a] + ' = ' + (255 - log[a]) + (log[a] === 0 ? ' ≡ 0 (mod 255)' : '') : '';
      lines.length = 0;
      if (a) lines.push(['log a⁻¹ = ' + invLog, 'act'], ['{' + hex2(a) + '}⁻¹ = {' + hex2(ai) + '}', 'good'], ['{' + hex2(a) + '}·{' + hex2(ai) + '} = {' + hex2(g.mul(a, ai)) + '}', 'good']);
      else lines.push(['{00} has no inverse', 'bad'], ['AES maps it to {00}', 'muted']);
      Fr.add({ items: grid('log₀₃ of each byte', all, (v) => (v === a ? 'act' : a && v === ai ? 'good' : '')).concat(panel()), say: a ? 'The inverse needs only one subtraction: log a⁻¹ = ' + invLog + ', so {' + hex2(a) + '}⁻¹ = {' + hex2(ai) + '}, because the exponents add to 255 ≡ 0 (mod 255) and {03}⁰ = {01}.' : '{00} has no logarithm and no inverse; AES defines its "inverse" to be {00}.', meta: { phase: 'inv', inv: ai } });
      lines.length = 0;
      lines.push(['cell v holds v⁻¹', 'strong'], ['{' + hex2(a) + '} → {' + hex2(ai) + '}', 'act'], ['then the affine map:', 'muted'], ['S({' + hex2(a) + '}) = {' + hex2(g.SBOX[a]) + '}', 'key']);
      Fr.add({ items: grid('The inverse of each byte', (v) => hex2(g.inv(v)), (v) => (v === a ? 'act' : v === ai ? 'good' : '')).concat(panel()), say: 'Done for every byte, this is the table of inverses, the first half of the AES S-box: cell {' + hex2(a) + '} holds {' + hex2(ai) + '}' + (a && a !== ai ? ', and cell {' + hex2(ai) + '} holds {' + hex2(a) + '}: inverting twice gives the byte back' : '') + '. The affine map that follows turns {' + hex2(ai) + '} into S({' + hex2(a) + '}) = {' + hex2(g.SBOX[a]) + '}.', meta: { phase: 'table' } });
      return { frames: Fr.list, def };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta && fr[i + 1].meta.phase === 'mul' && fr[i + 1].meta.value !== 0, pick: 'item', ask: 'Which cell holds the product? Click it.', answer: (fr, i) => 'g' + fr[i + 1].meta.value, explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta && fr[i + 1].meta.phase === 'walk' && fr[i + 1].meta.upto === 254, pick: 'option', ask: 'Will the powers of {03} reach every nonzero byte before repeating?', options: ['yes, all 255', 'no, only some of them'], answer: 'yes, all 255', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'How many nonzero elements does GF(2⁸) have?', options: ['255', '256', '128', '254'], answer: 0, why: 'Every byte but {00}.' },
      { q: 'If log a = 200 and log b = 100, then log(a·b) = …', options: ['45', '300', '100', '55'], answer: 0, why: '300 mod 255 = 45.' },
      { q: 'If log a = 10, what is log a⁻¹?', options: ['245', '10', '−10', '246'], answer: 0, why: '10 + 245 = 255 ≡ 0, and {03}⁰ = {01}.' },
      { q: 'Why is {02} not used as the generator here?', options: ['its powers repeat after 51 steps', 'it is not in the field', 'it is its own inverse', 'it is zero'], answer: 0, why: '{02} has order 51 in this field; {03} has the full order 255.' },
      { q: 'Why do table lookups of this kind worry implementers?', options: ['lookups indexed by secret bytes can leak through cache timing', 'they give wrong answers', 'they are slower than division', 'they need floating point'], answer: 0, why: 'The address a lookup touches depends on the secret, and caches remember it.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
