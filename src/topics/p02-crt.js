// Part 2, the Chinese remainder theorem: two clocks turning together while x counts up, each x filling the cell of
// its pair of remainders (every pair once when the moduli share no factor); the constructive formula as a table
// that fills row by row; and the speed-up it gives RSA, working modulo p and q with half-size exponents.
(function (S) {
  'use strict';
  const H = S.P02, NT = () => S.NT, KN = () => S.Kit.nt;
  const n$ = H.n;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const mod = (a, n) => ((a % n) + n) % n;

  // ---------------------------------------------------------------------------------------------------------------
  // Two clocks
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'crt-clocks', family: 'p02-crt', order: 10, title: 'The Chinese remainder theorem: two clocks',
    blurb: 'Count x = 0, 1, 2, … on two clocks at once, one with m₁ positions and one with m₂. Each x shows a pair of remainders. When m₁ and m₂ share no factor, the pairs do not repeat until x = m₁·m₂, so every pair appears exactly once: the two remainders name x modulo m₁·m₂.',
    inputs: [
      { id: 'm1', kind: 'number', label: 'm₁', def: 5, min: 2, max: 9 },
      { id: 'm2', kind: 'number', label: 'm₂', def: 7, min: 2, max: 9 },
      { id: 'r1', kind: 'number', label: 'Find x ≡ r₁', def: 3, min: 0, max: 8, check: (v, inp) => (v >= inp.m1 ? 'r₁: below m₁' : null) },
      { id: 'r2', kind: 'number', label: 'and x ≡ r₂', def: 2, min: 0, max: 8, check: (v, inp) => (v >= inp.m2 ? 'r₂: below m₂' : null) },
    ],
    presets: [
      { label: 'Clocks of 5 and 7', values: { m1: 5, m2: 7, r1: 3, r2: 2 } },
      { label: 'Clocks of 3 and 4', values: { m1: 3, m2: 4, r1: 2, r2: 1 } },
      { label: 'Clocks of 8 and 9', values: { m1: 8, m2: 9, r1: 5, r2: 7 } },
      { label: '4 and 6 share a factor', values: { m1: 4, m2: 6, r1: 1, r2: 3 } },
      { label: '4 and 6, a pair that exists', values: { m1: 4, m2: 6, r1: 1, r2: 5 } },
      { label: '2 and 9', values: { m1: 2, m2: 9, r1: 1, r2: 4 } },
    ],
    counters: [{ id: 'x', label: 'x counted to' }, { id: 'cells', label: 'pairs hit' }],
    run(inp) {
      const m1 = inp.m1, m2 = inp.m2, r1 = inp.r1, r2 = inp.r2;
      const F = new S.Frames(['x', 'cells']);
      const M = m1 * m2, g = Number(NT().gcd(m1, m2)), L = Number(NT().lcm(m1, m2));
      const R = 82, c1 = { x: 100, y: 130 }, c2 = { x: 100, y: 370 };
      const cw = 52, ch = 40, gp = 4, gx = 260, gy = 50;
      const filled = new Map();
      const lines = [];
      const draw = (x, opt) => {
        opt = opt || {};
        const it = [H.title('t1', 0, 14, 'x mod ' + m1), H.title('t2', 0, 254, 'x mod ' + m2), H.title('t3', gx, 14, 'Each x in the cell of its pair')];
        const a = x === null ? null : x % m1, b = x === null ? null : x % m2;
        it.push(...KN().clock({ prefix: 'ca', cx: c1.x, cy: c1.y, R, n: m1, hand: a, handCls: 'act', cls: (k) => (k === a ? 'act' : opt.r1 === k ? 'key' : '') }).items);
        it.push(...KN().clock({ prefix: 'cb', cx: c2.x, cy: c2.y, R, n: m2, hand: b, handCls: 'act', cls: (k) => (k === b ? 'act' : opt.r2 === k ? 'key' : '') }).items);
        for (let c = 0; c < m2; c++) it.push({ key: 'hc' + c, kind: 'text', x: gx + 34 + c * (cw + gp) + cw / 2, y: gy - 8, text: String(c), anchor: 'middle', size: 13, cls: 'ntlab' + (opt.r2 === c ? ' key' : '') });
        for (let r = 0; r < m1; r++) {
          it.push({ key: 'hr' + r, kind: 'text', x: gx + 20, y: gy + r * (ch + gp) + ch / 2 + 5, text: String(r), anchor: 'end', size: 13, cls: 'ntlab' + (opt.r1 === r ? ' key' : '') });
          for (let c = 0; c < m2; c++) {
            const v = filled.get(r + ',' + c);
            const on = opt.r1 === r && opt.r2 === c;
            it.push({ key: 'g' + r + '_' + c, kind: 'cell', x: gx + 34 + c * (cw + gp), y: gy + r * (ch + gp), w: cw, h: ch, rx: 4, text: v === undefined ? '' : String(v), size: 14, cls: 'mono ntc ' + (on ? (v === undefined ? 'bad' : 'good') : v === undefined ? (opt.gaps ? 'empty' : 'empty') : v === x && !opt.nohot ? 'hot' : opt.lit && opt.lit(r, c) ? 'key' : '') });
          }
        }
        it.push(...H.eqs('pe', gx + 34, gy + m1 * (ch + gp) + 40, lines.slice(-3), 16, 30));
        return it;
      };
      lines.push(['x = 0: both hands at 0', 'strong']);
      filled.set('0,0', 0);
      F.set('x', 0).set('cells', 1);
      F.add({ items: draw(0), say: 'Two clocks, with ' + m1 + ' and ' + m2 + ' positions, both at 0 for x = 0. Each step adds 1 to x and turns both hands one place. Write each x in the grid at row x mod ' + m1 + ', column x mod ' + m2 + '.', meta: { phase: 'start' } });
      const stride = L > 16 ? Math.ceil(L / 10) : 1;
      for (let x0 = 1; x0 < L; x0 += stride) {
        const x1 = Math.min(L - 1, x0 + stride - 1);
        for (let x = x0; x <= x1; x++) filled.set((x % m1) + ',' + (x % m2), x);
        F.set('x', x1).set('cells', filled.size);
        lines.length = 0;
        lines.push(['x = ' + x1, 'strong'], [x1 + ' mod ' + m1 + ' = ' + (x1 % m1), 'act'], [x1 + ' mod ' + m2 + ' = ' + (x1 % m2), 'act']);
        const wrap = x0 <= m1 && x1 >= m1 ? ' The first hand passed ' + (m1 - 1) + ' and wrapped to 0, so the next cells start again at the top row, one column further on: the diagonal wraps.' : '';
        F.add({ items: draw(x1), say: (x0 === x1 ? 'x = ' + x1 + ': ' : 'x = ' + x0 + ' to ' + x1 + ': the last, ') + x1 + ' mod ' + m1 + ' = ' + (x1 % m1) + ' and ' + x1 + ' mod ' + m2 + ' = ' + (x1 % m2) + '.' + wrap, meta: { phase: 'walk', x: x1 } });
      }
      // x = L: both hands are back at 0
      lines.length = 0;
      const empty = M - L;
      lines.push(['x = ' + L + ' = lcm(' + m1 + ', ' + m2 + ')', 'strong'], [L + ' mod ' + m1 + ' = 0 and ' + L + ' mod ' + m2 + ' = 0', ''], [g === 1 ? 'all ' + M + ' cells filled' : empty + ' cells never filled', g === 1 ? 'good' : 'bad']);
      F.set('x', L);
      F.add({ items: draw(L % m1 === 0 && L % m2 === 0 ? 0 : 0, { nohot: true }), say: 'At x = ' + L + ' both hands are back at 0 together for the first time, since ' + L + ' = lcm(' + m1 + ', ' + m2 + '). From here the pairs repeat. ' + (g === 1 ? 'gcd(' + m1 + ', ' + m2 + ') = 1, so lcm = ' + m1 + '·' + m2 + ' = ' + M + ' and all ' + M + ' cells are filled, each exactly once: each pair of remainders belongs to exactly one x below ' + M + '.' : 'gcd(' + m1 + ', ' + m2 + ') = ' + g + ', so only ' + L + ' of the ' + M + ' cells are filled: x mod ' + m1 + ' and x mod ' + m2 + ' always agree modulo ' + g + ', and the ' + empty + ' other pairs never occur.'), meta: { phase: 'full', L } });
      // the pair asked for
      const v = filled.get(r1 + ',' + r2);
      lines.length = 0;
      if (v !== undefined) {
        const sol = NT().crtGeneral([r1, r2], [m1, m2]);
        lines.push(['x ≡ ' + r1 + ' (mod ' + m1 + '), x ≡ ' + r2 + ' (mod ' + m2 + ')', 'key'], ['x = ' + sol.x + ' (mod ' + sol.M + ')', 'good']);
        F.add({ items: draw(null, { r1, r2, nohot: true }), say: 'Look up row ' + r1 + ', column ' + r2 + ': the cell holds ' + sol.x + '. Check: ' + sol.x + ' ≡ ' + r1 + ' (mod ' + m1 + ') and ' + sol.x + ' ≡ ' + r2 + ' (mod ' + m2 + '). The solution is unique modulo ' + sol.M + '; the other solutions are ' + sol.x + ' plus multiples of ' + sol.M + '.', meta: { phase: 'look', x: Number(sol.x) } });
      } else {
        lines.push(['x ≡ ' + r1 + ' (mod ' + m1 + '), x ≡ ' + r2 + ' (mod ' + m2 + ')', 'key'], ['no solution: ' + r1 + ' ≢ ' + r2 + ' (mod ' + g + ')', 'bad']);
        F.add({ items: draw(null, { r1, r2, nohot: true }), say: 'Row ' + r1 + ', column ' + r2 + ' is empty: no x has these remainders. Any x with x ≡ ' + r1 + ' (mod ' + m1 + ') has x ≡ ' + (r1 % g) + ' (mod ' + g + '), and x ≡ ' + r2 + ' (mod ' + m2 + ') forces x ≡ ' + (r2 % g) + ' (mod ' + g + ') instead.', meta: { phase: 'look', x: null } });
      }
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'The Chinese remainder theorem', text: ['gcd(m₁, m₂) = 1, M = m₁·m₂:', 'x ↦ (x mod m₁, x mod m₂) is one-to-one on 0 … M − 1', 'every pair (r₁, r₂) comes from exactly one x', 'with a common factor g: only pairs with r₁ ≡ r₂ (mod g)'].join('\n') }] } };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'full' && f.meta.phase !== 'full', pick: 'option', ask: 'At which x will both hands first be back at 0 together?', options: (fr, i, inp) => [...new Set([inp.m1 * inp.m2, Number(S.NT.lcm(inp.m1, inp.m2)), inp.m1 + inp.m2, Math.max(inp.m1, inp.m2)])].map(String), answer: (fr, i) => String(fr[i + 1].meta.L), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta.phase === 'full', pick: 'item', ask: (fr, i, inp) => 'Which cell holds the x with x ≡ ' + inp.r1 + ' (mod ' + inp.m1 + ') and x ≡ ' + inp.r2 + ' (mod ' + inp.m2 + ')? Click it.', answer: (fr, i, inp) => 'g' + inp.r1 + '_' + inp.r2, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Which x below 15 has x ≡ 2 (mod 3) and x ≡ 4 (mod 5)?', options: ['14', '11', '8', '4'], answer: 0, why: '14 = 4·3 + 2 = 2·5 + 4.' },
      { q: 'With clocks of 4 and 6, how many of the 24 pairs ever occur?', options: ['12', '24', '6', '10'], answer: 0, why: 'They repeat after lcm(4, 6) = 12 steps.' },
      { q: 'Why can x ≡ 1 (mod 4) and x ≡ 2 (mod 6) not both hold?', options: ['the first makes x odd, the second even', '4 and 6 are even', 'there are too many solutions', '1 < 2'], answer: 0, why: 'They disagree modulo gcd(4, 6) = 2.' },
      { q: 'If gcd(m₁, m₂) = 1, the solution x is unique modulo…', options: ['m₁·m₂', 'm₁ + m₂', 'max(m₁, m₂)', 'gcd(m₁, m₂)'], answer: 0, why: 'The pairs repeat only after m₁·m₂ steps.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The constructive formula
  // ---------------------------------------------------------------------------------------------------------------
  const listNums = (v, what) => { if (!Array.isArray(v) || v.length < 2 || v.length > 3) return what + ': 2 or 3 numbers'; for (const x of v) if (!/^\d+$/.test(x)) return what + ': whole numbers, not negative'; return null; };
  S.topic({
    id: 'crt-solve', family: 'p02-crt', order: 20, title: 'Solving with the Chinese remainder theorem',
    blurb: 'To solve x ≡ r_i (mod m_i) for pairwise coprime moduli, build one term per congruence: M_i = M/m_i is 0 modulo every other modulus, and multiplying it by its inverse y_i modulo m_i makes it 1 modulo m_i. The sum of r_i·M_i·y_i is the answer, modulo M.',
    inputs: [
      { id: 'r', kind: 'list', label: 'Remainders r', def: ['2', '7', '5'], check: (v) => listNums(v, 'Remainders') },
      { id: 'm', kind: 'list', label: 'Moduli m', def: ['9', '10', '11'], check: (v, inp) => {
        const e = listNums(v, 'Moduli'); if (e) return e;
        if (!Array.isArray(inp.r) || v.length !== inp.r.length) return 'Moduli: as many as remainders';
        for (const x of v) if (+x < 2 || +x > 100000) return 'Moduli: each from 2 to 100000';
        for (let i = 0; i < v.length; i++) for (let j = i + 1; j < v.length; j++) if (S.NT.gcd(BigInt(v[i]), BigInt(v[j])) !== 1n) return 'Moduli: ' + v[i] + ' and ' + v[j] + ' share the factor ' + S.NT.gcd(BigInt(v[i]), BigInt(v[j])) + ' (pairwise coprime moduli only)';
        return null;
      } },
    ],
    presets: [
      { label: 'Three small moduli: 9, 10, 11', values: { r: ['2', '7', '5'], m: ['9', '10', '11'] } },
      { label: 'Two: modulo 8 and 15', values: { r: ['3', '10'], m: ['8', '15'] } },
      { label: 'Two: modulo 7 and 12', values: { r: ['6', '0'], m: ['7', '12'] } },
      { label: 'Larger: 1009, 1013, 1019', values: { r: ['500', '17', '1000'], m: ['1009', '1013', '1019'] } },
      { label: 'Remainders above the moduli', values: { r: ['25', '40'], m: ['6', '11'] } },
    ],
    counters: [{ id: 'rows', label: 'terms built' }],
    run(inp) {
      const rs = inp.r.map(B), ms = inp.m.map(B), k = ms.length;
      const res = NT().crt(rs, ms), M = res.M, F = new S.Frames(['rows']);
      const TB = S.Kit.table;
      const heads = ['r_i', 'm_i', 'M_i = M/m_i', 'M_i mod m_i', 'y_i = M_i⁻¹', 'r_i·M_i·y_i'];
      const rowOf = (i, upto) => { const r = res.rows[i]; const red = r.Mi % r.m; return [r.r, r.m, upto >= 1 ? r.Mi : '', upto >= 1 ? red : '', upto >= 2 ? r.yi : '', upto >= 2 ? r.term : ''].map((v) => (v === '' ? '' : v.toString())); };
      const done = [];
      const table = (hot) => TB.draw({ prefix: 'tb', x: 0, y: 40, rows: [...Array(k).keys()].map((i) => rowOf(i, done[i] || 0)), colHead: heads, rowHead: [...Array(k).keys()].map((i) => 'i = ' + (i + 1)), size: 15, mono: true, minW: 70, cls: (r, c, v) => 'ntc ' + (v === '' ? 'empty' : hot && hot[0] === r && hot[1].includes(c) ? 'hot' : c === 5 ? 'act' : '') });
      const lines = [];
      const draw = (hot) => { const t = table(hot); return [H.title('tt', 0, 22, 'M = ' + ms.join('·') + ' = ' + M)].concat(t.items, H.eqs('pe', 0, t.box.y + t.box.h + 40, lines.slice(-6), 16, 30)); };
      const sys = rs.map((r, i) => 'x ≡ ' + r + ' (mod ' + ms[i] + ')');
      sys.forEach((x) => lines.push([x, 'strong']));
      F.add({ items: draw(), say: 'Solve ' + H.list(sys) + '. The moduli share no factor, so there is one solution modulo M = ' + ms.join('·') + ' = ' + M + '.', meta: { phase: 'start' } });
      res.rows.forEach((r, i) => {
        done[i] = 1;
        const others = ms.filter((_, j) => j !== i);
        F.add({ items: draw([i, [2, 3]]), say: 'Row ' + (i + 1) + ': M' + (i + 1) + ' = ' + M + '/' + r.m + ' = ' + r.Mi + ', the product of the other moduli, so it is ≡ 0 modulo ' + H.list(others) + '. Modulo ' + r.m + ' it is ' + r.Mi + ' mod ' + r.m + ' = ' + r.Mi % r.m + '.', meta: { phase: 'Mi', i } });
        done[i] = 2;
        F.count('rows');
        const rr = r.r % r.m;
        F.add({ items: draw([i, [4, 5]]), say: 'Its inverse modulo ' + r.m + ' is y' + (i + 1) + ' = ' + r.yi + ', since ' + r.Mi + '·' + r.yi + ' ≡ 1 (mod ' + r.m + '). ' + (rr !== r.r ? 'With ' + r.r + ' mod ' + r.m + ' = ' + rr + ', the' : 'The') + ' term ' + rr + '·' + r.Mi + '·' + r.yi + ' = ' + r.term + ' is then ≡ ' + rr + ' modulo ' + r.m + ' and ≡ 0 modulo the others.', meta: { phase: 'yi', i, yi: r.yi.toString() } });
      });
      const sum = res.rows.reduce((a, r) => a + r.term, 0n);
      lines.length = 0;
      lines.push([res.rows.map((r) => r.term).join(' + ') + ' = ' + sum, '']);
      lines.push([sum + ' mod ' + M + ' = ' + res.x, 'good']);
      F.add({ items: draw(), say: 'Add the terms: ' + res.rows.map((r) => r.term).join(' + ') + ' = ' + sum + ', and reduce: ' + sum + ' mod ' + M + ' = ' + res.x + '. So x = ' + res.x + '.', meta: { phase: 'sum', x: res.x.toString() } });
      res.rows.forEach((r) => lines.push([res.x + ' mod ' + r.m + ' = ' + (res.x % r.m), 'good']));
      F.add({ items: draw(), say: 'Check: ' + H.list(res.rows.map((r) => res.x + ' ≡ ' + r.r + ' (mod ' + r.m + ')')) + '. Every number ' + res.x + ' + k·' + M + ' works too, and nothing else does.', meta: { phase: 'check' } });
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'The formula', text: ['M = m₁·m₂·…·m_k', 'M_i = M/m_i,  y_i = M_i⁻¹ mod m_i', 'x = Σ r_i·M_i·y_i  mod M', 'r_i·M_i·y_i ≡ r_i (mod m_i), ≡ 0 (mod m_j), j ≠ i'].join('\n') }] } };
    },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'Mi' && fr[i + 1].meta.phase === 'yi', once: true, pick: 'option', ask: (fr, i, inp) => 'What is the inverse y' + (fr[i].meta.i + 1) + ' of M' + (fr[i].meta.i + 1) + ' modulo ' + inp.m[fr[i].meta.i] + '?', options: (fr, i, inp) => { const m = +inp.m[fr[i].meta.i], y = +fr[i + 1].meta.yi; return [...new Set([y, (y + 1) % m, (m - y) % m, (y * 2) % m])].map(String); }, answer: (fr, i) => fr[i + 1].meta.yi, explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'sum', pick: 'option', ask: 'What is x?', options: (fr, i) => { const x = BigInt(fr[i + 1].meta.x); return [x, x + 1n, x > 1n ? x - 1n : x + 2n, x * 2n].map(String); }, answer: (fr, i) => fr[i + 1].meta.x, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Solve x ≡ 1 (mod 4), x ≡ 2 (mod 5). x mod 20 = …', options: ['17', '13', '9', '7'], answer: 0, why: '17 = 4·4 + 1 = 3·5 + 2.' },
      { q: 'Why is M_i ≡ 0 modulo m_j for j ≠ i?', options: ['M_i is the product of all the moduli but m_i', 'M_i is prime', 'y_i is 0', 'the moduli are equal'], answer: 0, why: 'm_j is one of its factors.' },
      { q: 'The inverse y_i = M_i⁻¹ mod m_i exists because…', options: ['the moduli are pairwise coprime', 'M_i is even', 'r_i < m_i', 'M is prime'], answer: 0, why: 'M_i shares no factor with m_i.' },
      { q: 'Adding M to the answer gives…', options: ['another solution', 'no solution', 'the inverse', 'zero'], answer: 0, why: 'M is ≡ 0 modulo every m_i.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The speed-up for RSA
  // ---------------------------------------------------------------------------------------------------------------
  const cache = new Map();
  /** a fixed pair of primes of the given size (found once, from fixed starting points, so the topic is repeatable) */
  const primes = (size) => {
    if (cache.has(size)) return cache.get(size);
    let p, q;
    if (size === 'toy') { p = NT().nextPrime(1000n); q = NT().nextPrime(1200n); }
    else { const b = BigInt(size); p = NT().nextPrime((1n << (b - 1n)) + (1n << (b - 2n)) + 7919n * 104729n); q = NT().nextPrime((1n << (b - 1n)) + (1n << (b - 3n)) + 15485863n); }
    const v = { p, q };
    cache.set(size, v);
    return v;
  };
  const ops = (e) => { const s = e.toString(2); return { sq: s.length - 1, mul: s.split('').filter((c) => c === '1').length - 1, bits: s.length }; };
  const shortN = (v) => { const s = B(v).toString(); return s.length > 14 ? s.slice(0, 6) + '…' + s.slice(-4) : s; };
  S.topic({
    id: 'crt-speedup', family: 'p02-crt', order: 30, title: 'The CRT speed-up for RSA',
    blurb: 'Decrypting with RSA computes c^d mod n with a long d. Whoever holds the key knows p and q, and can compute modulo p and modulo q instead, with exponents d mod (p − 1) and d mod (q − 1) of half the length and numbers of half the size, then join the two answers by the Chinese remainder theorem. That is about four times less work.',
    inputs: [{ id: 'size', kind: 'choice', label: 'Primes', def: 'toy', options: [{ value: 'toy', label: 'toy: about 10 bits' }, { value: '128', label: '128 bits each' }, { value: '256', label: '256 bits each' }, { value: '512', label: '512 bits each' }] }],
    presets: [
      { label: 'Toy primes', values: { size: 'toy' } },
      { label: '128-bit primes', values: { size: '128' } },
      { label: '512-bit primes (RSA-1024)', values: { size: '512' } },
    ],
    counters: [{ id: 'sq', label: 'squarings' }, { id: 'mul', label: 'multiplications' }],
    run(inp) {
      const { p, q } = primes(inp.size), n = p * q, e = 65537n, phi = (p - 1n) * (q - 1n);
      const d = NT().inv(e, phi);
      const m0 = NT().fromBytes(S.bytes.utf8('Ferns at dawn')) % n;
      const c = NT().pow(m0, e, n);
      const F = new S.Frames(['sq', 'mul']);
      const bn = NT().bitLength(n), bp = NT().bitLength(p), bq = NT().bitLength(q);
      const direct = NT().pow(c, d, n), od = ops(d);
      const dp = d % (p - 1n), dq = d % (q - 1n), cp = c % p, cq = c % q;
      const mp = NT().pow(cp, dp, p), mq = NT().pow(cq, dq, q), op = ops(dp), oq = ops(dq);
      const qinv = NT().inv(q, p), h = mod((mp - mq) * qinv, p), m = mq + h * q;
      const W = (o, b) => (o.sq + o.mul) * b * b;
      const wd = W(od, bn), wp = W(op, bp), wq = W(oq, bq), ratio = (wd / (wp + wq)).toFixed(1);
      // the picture: the direct lane on top, the two half lanes below, joined by the CRT
      const yD = 70, yP = 200, yQ = 330, yC = 265;
      const draw = (lit) => {
        const N = S.Kit.flow.net('sp');
        const on = (k) => (lit.includes(k) ? 'act' : '');
        const big = { size: 15 };
        N.box('c', 40, yC, 64, 40, 'c', 'val ' + (lit.includes('c') ? 'key' : ''), big);
        N.box('dir', 400, yD, 340, 54, ['c^d mod n', bn + '-bit numbers, ' + od.bits + '-bit d'], 'block ' + on('dir'), big);
        N.box('rp', 215, yP, 100, 40, 'mod p', on('red'), big);
        N.box('rq', 215, yQ, 100, 40, 'mod q', on('red'), big);
        N.box('pp', 440, yP, 230, 54, ['c_p^(d_p) mod p', bp + ' bits, ' + op.bits + '-bit d_p'], 'block ' + on('p'), big);
        N.box('pq', 440, yQ, 230, 54, ['c_q^(d_q) mod q', bq + ' bits, ' + oq.bits + '-bit d_q'], 'block ' + on('q'), big);
        N.box('cr', 700, yC, 110, 54, ['join', 'by CRT'], 'block ' + on('crt'), big);
        N.box('out', 870, yC, 70, 40, 'm', 'val ' + (lit.includes('out') ? 'good' : ''), big);
        const tx = 110;
        N.wire('c0', [N.port('c', 'e'), [tx, yC]], { cls: on('red') || on('dir') });
        N.dot(tx, yC, on('red') || on('dir'));
        N.wire('cd', [[tx, yC], [tx, yD], N.port('dir', 'w')], { head: true, cls: on('dir') });
        N.wire('cq', [[tx, yC], [tx, yQ], N.port('rq', 'w')], { head: true, cls: on('red') });
        N.wire('cp', [[tx, yP], N.port('rp', 'w')], { head: true, cls: on('red') });
        N.dot(tx, yP, on('red') || on('dir'));
        N.wire('pp', [N.port('rp', 'e'), N.port('pp', 'w')], { head: true, cls: on('p') });
        N.wire('qq', [N.port('rq', 'e'), N.port('pq', 'w')], { head: true, cls: on('q') });
        N.wire('pc', [N.port('pp', 'e'), [610, yP], [610, yC - 14], N.port('cr', 'w', -0.52)], { head: true, cls: on('crt') });
        N.wire('qc', [N.port('pq', 'e'), [610, yQ], [610, yC + 14], N.port('cr', 'w', 0.52)], { head: true, cls: on('crt') });
        N.wire('co', [N.port('cr', 'e'), N.port('out', 'w')], { head: true, cls: on('crt') });
        N.wire('do', [N.port('dir', 'e'), [870, yD], N.port('out', 'n')], { head: true, cls: on('dir') });
        return N.items;
      };
      // the work, as bars
      const bars = (show) => {
        const it = [H.title('wt', 0, 400, 'Work: operations × (bits)²')], full = 560;
        const bar = (k, y, label, w, cls) => { it.push(H.text('wl' + k, 0, y + 17, label, 'ntlab', 13)); it.push({ key: 'wb' + k, kind: 'cell', x: 170, y, w: Math.max(4, Math.round(full * w)), h: 24, rx: 3, text: '', cls: 'ntc ' + cls }); };
        if (show.includes('dir')) bar('d', 416, 'directly mod n', 1, 'k3');
        if (show.includes('p')) bar('p', 448, 'mod p', wp / wd, 'k0');
        if (show.includes('q')) bar('q', 480, 'mod q', wq / wd, 'k1');
        return it;
      };
      const lines = [];
      const panel = () => H.eqs('pe', 0, 540, lines.slice(-2), 15, 28);
      const frame = (lit, show, say, meta) => F.add({ items: draw(lit).concat(bars(show), panel()), say, meta });
      lines.push(['p = ' + shortN(p) + ' (' + bp + ' bits),  q = ' + shortN(q) + ' (' + bq + ' bits)', 'strong'], ['e = ' + e + ',  d = e⁻¹ mod (p − 1)(q − 1), ' + od.bits + ' bits', '']);
      frame(['c'], [], 'An RSA key: p = ' + n$(p) + ' and q = ' + n$(q) + ', so n = ' + n$(n) + ' has ' + bn + ' bits; e = ' + e + ' and d = ' + n$(d) + ', the inverse of e modulo (p − 1)(q − 1) = ' + n$(phi) + '. A ciphertext c = ' + n$(c) + ' arrives.', { phase: 'start', p: p.toString(), q: q.toString(), c: c.toString(), d: d.toString(), m0: m0.toString() });
      F.set('sq', od.sq).set('mul', od.mul);
      lines.push(['directly: ' + od.sq + ' squarings, ' + od.mul + ' multiplications mod n', 'act']);
      frame(['c', 'dir', 'out'], ['dir'], 'Directly: c^d mod n by square-and-multiply. d has ' + od.bits + ' bits, so ' + od.sq + ' squarings and ' + od.mul + ' multiplications, each of ' + bn + '-bit numbers. The result is m = ' + n$(direct) + '.', { phase: 'direct', m: direct.toString() });
      lines.push(['d_p = d mod (p − 1) = ' + shortN(dp) + ',  d_q = ' + shortN(dq), 'act'], ['c_p = c mod p = ' + shortN(cp) + ',  c_q = ' + shortN(cq), 'act']);
      frame(['c', 'red'], ['dir'], 'The key holder knows p and q. Reduce c: c_p = c mod p = ' + n$(cp) + ', c_q = c mod q = ' + n$(cq) + '. And the exponent: since x^(p−1) ≡ 1 (mod p), only d mod (p − 1) matters: d_p = ' + n$(dp) + ' and d_q = ' + n$(dq) + ', each about half as long as d.', { phase: 'reduce' });
      F.set('sq', op.sq).set('mul', op.mul);
      lines.push(['m_p = c_p^(d_p) mod p = ' + shortN(mp), 'act'], [op.sq + ' squarings, ' + op.mul + ' multiplications of ' + bp + '-bit numbers', '']);
      frame(['red', 'p'], ['dir', 'p'], 'Modulo p: m_p = ' + n$(cp) + '^' + n$(dp) + ' mod ' + n$(p) + ' = ' + n$(mp) + '. ' + op.sq + ' squarings and ' + op.mul + ' multiplications of ' + bp + '-bit numbers.', { phase: 'p' });
      F.set('sq', op.sq + oq.sq).set('mul', op.mul + oq.mul);
      lines.push(['m_q = c_q^(d_q) mod q = ' + shortN(mq), 'act'], [oq.sq + ' squarings, ' + oq.mul + ' multiplications of ' + bq + '-bit numbers', '']);
      frame(['red', 'p', 'q'], ['dir', 'p', 'q'], 'Modulo q: m_q = ' + n$(cq) + '^' + n$(dq) + ' mod ' + n$(q) + ' = ' + n$(mq) + '. ' + oq.sq + ' squarings and ' + oq.mul + ' multiplications of ' + bq + '-bit numbers.', { phase: 'q' });
      lines.push(['h = (m_p − m_q)·q⁻¹ mod p = ' + shortN(h), 'act'], ['m = m_q + h·q = ' + shortN(m) + (m === direct ? '  ✓' : '  ✗'), m === direct ? 'good' : 'bad']);
      frame(['p', 'q', 'crt', 'out'], ['dir', 'p', 'q'], 'Join them (Garner\'s form of the CRT): q⁻¹ mod p = ' + n$(qinv) + ', h = (m_p − m_q)·q⁻¹ mod p = ' + n$(h) + ', and m = m_q + h·q = ' + n$(m) + (m === direct ? ', the same m as the direct way.' : ', which differs from the direct result.'), { phase: 'crt', m: m.toString(), same: m === direct });
      lines.push(['direct: ' + (od.sq + od.mul) + ' operations on ' + bn + ' bits', 'strong'], ['CRT: ' + (op.sq + op.mul + oq.sq + oq.mul) + ' operations on ' + bp + ' bits: ' + ratio + ' times less work', 'good']);
      frame(['p', 'q', 'crt', 'out'], ['dir', 'p', 'q'], 'The cost of one multiplication grows with the square of the size. Directly: ' + (od.sq + od.mul) + ' operations on ' + bn + '-bit numbers; with the CRT: ' + (op.sq + op.mul) + ' + ' + (oq.sq + oq.mul) + ' operations on numbers half as long. Counting operations times bits squared, the CRT way is ' + ratio + ' times cheaper. Every RSA library decrypts and signs this way.', { phase: 'work', ratio });
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'RSA with the CRT', text: ['d_p = d mod (p − 1),  d_q = d mod (q − 1)', 'm_p = c^(d_p) mod p,  m_q = c^(d_q) mod q', 'h = (m_p − m_q)·(q⁻¹ mod p) mod p', 'm = m_q + h·q', 'about 4 times faster than c^d mod n'].join('\n') }] } };
    },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'q', pick: 'option', ask: 'Will the joined m equal the direct result?', options: ['yes', 'no'], answer: (fr, i) => (fr[i + 1].meta.same ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta.phase === 'start', pick: 'option', ask: 'Working modulo p and q with half-size numbers and half-length exponents: about how much less work?', options: ['2 times', '4 times', '8 times', 'no saving'], answer: '4 times', explain: (fr) => fr[fr.length - 1].say },
    ],
    quiz: [
      { q: 'Why may the exponent be reduced to d mod (p − 1) when working modulo p?', options: ['x^(p−1) ≡ 1 (mod p) for x not divisible by p', 'd is prime', 'p − 1 is even', 'q divides p − 1'], answer: 0, why: 'Fermat\'s little theorem: whole multiples of p − 1 in the exponent change nothing.' },
      { q: 'Halving both the size of the numbers and the length of the exponent makes one exponentiation about…', options: ['8 times cheaper', '2 times cheaper', '4 times cheaper', 'no cheaper'], answer: 0, why: 'Half as many operations, each a quarter of the cost; two of them make the total about 4 times cheaper.' },
      { q: 'Who can use the CRT speed-up?', options: ['only whoever knows p and q', 'anyone who knows n', 'anyone who knows e'], answer: 0, why: 'It needs the factors of n, the private key.' },
      { q: 'In Garner\'s step, m = m_q + h·q with h = (m_p − m_q)·q⁻¹ mod p. Modulo q, m is…', options: ['m_q', 'm_p', 'h', '0'], answer: 0, why: 'h·q ≡ 0 (mod q).' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
