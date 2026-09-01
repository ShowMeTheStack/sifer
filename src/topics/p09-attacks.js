// Part 9, computing discrete logarithms: baby-step giant-step with its two tables, and Pollard's rho with its walk
// drawn as a tail running into a cycle where Floyd's tortoise and hare meet. Each topic runs the real attack on a
// toy group and on the largest group that stays quick, and prices the same steps in the 2048-bit MODP group.
(function (S) {
  'use strict';
  const P = S.PK, NT = () => S.NT, DLP = () => S.DLP;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const H = (S.P09B = S.P09B || {});
  const sh = (v) => P.n(v);
  /** a value for a table cell: whole, or its ends */
  const cellv = (v) => S.Kit.pk.fmt(B(v), { max: 14 }).text;
  H.cellv = cellv;
  /** an input that must be a prime in [lo, hi] */
  H.primeIn = (lo, hi, what) => (v) => { let p; try { p = B(String(v).trim()); } catch (e) { return what + ': a whole number'; } if (p < B(lo) || p > B(hi)) return what + ': between ' + lo + ' and ' + hi; return NT().isProbablePrime(p) ? null : what + ': ' + p + ' is not prime'; };
  H.seeded = (seed, fn) => S.RSA.seeded(seed, fn);
  /** a secret exponent of the 2048-bit MODP group, the same for a given seed */
  H.modpSecret = (seed) => H.seeded(seed, () => 1n + NT().randBelow(P.modp14().order - 1n));
  H.log2 = (v) => { v = B(v); const b = NT().bitLength(v); return b <= 53 ? Math.log2(Number(v)) : b - 53 + Math.log2(Number(v >> BigInt(b - 53))); };
  /** a table whose cells may hold BigInts: long ones are abbreviated, and a click opens them (label from the header) */
  H.tab = function (o) {
    const full = new Map();
    const rows = o.rows.map((row, r) => row.map((v, c) => { if (typeof v !== 'bigint') return v; const f = S.Kit.pk.fmt(v, { max: o.max || 14 }); if (f.long) full.set(r + ',' + c, f); return f.text; }));
    const t = S.Kit.table.draw(Object.assign({}, o, { rows, mono: o.mono !== false }));
    for (const [rc, f] of full) {
      const [r, c] = rc.split(',').map(Number), it = t.items.find((x) => x.key === t.key(r, c));
      if (it) { it.cls += ' pk-long'; it.title = ((o.colHead || [])[c] || 'value') + (o.rowHead ? ' (' + o.rowHead[r] + ')' : '') + ' = ' + f.full + ' (' + f.digits + ' digits, ' + f.bits + ' bits)'; }
    }
    return t;
  };
  /** labelled values stacked from (x, y), each a block that opens when long: rows [[label, value, cls]] */
  H.vals = (prefix, x, y, rows, w) => rows.map(([label, value, cls], i) => S.Kit.pk.value({ key: prefix + i, x, y: y + i * 64, anchor: 'start', label, value: B(value), cls, w, max: 18 }));
  const f1 = (x) => (Math.round(x * 10) / 10).toFixed(1);
  H.f1 = f1;

  // ---------------------------------------------------------------------------------------------------------------
  // Baby-step giant-step
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p09-bsgs', family: 'p09-attacks', order: 10, title: 'Baby-step giant-step',
    blurb: 'Write the unknown exponent as x = i·m + j with m = ⌈√n⌉. Store the m baby steps g^j in a table, then take giant steps h·g^(−m·i) until one lands in the table: about 2√n group operations instead of n, paid for with a table of √n entries.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Group', def: 'toy', options: [{ value: 'toy', label: 'toy: Z_p* with p below', }, { value: 'lab', label: 'a 28-bit prime (computed)' }, { value: 'modp', label: 'the 2048-bit MODP group' }] },
      { id: 'p', kind: 'bigint', label: 'Prime p (toy)', def: '1019', check: H.primeIn(11, 200003, 'p') },
      { id: 'h', kind: 'bigint', label: 'Target h', def: '777', check: (v, inp) => { let h; try { h = B(String(v).trim()); } catch (e) { return 'h: a whole number'; } return inp.size === 'toy' && (h < 1n || h >= B(inp.p)) ? 'h: from 1 to p − 1' : null; } },
      { id: 'seed', kind: 'number', label: 'Seed (larger groups)', def: 3, min: 1, max: 9999 },
    ],
    presets: [
      { label: 'p = 1019, h = 777', values: { size: 'toy', p: '1019', h: '777' } },
      { label: 'A small group: p = 101', values: { size: 'toy', p: '101', h: '50' } },
      { label: 'h = 1: x = 0', values: { size: 'toy', p: '467', h: '1' } },
      { label: 'p = 30011', values: { size: 'toy', p: '30011', h: '2026' } },
      { label: 'A 28-bit prime', values: { size: 'lab', seed: 3 } },
      { label: 'The 2048-bit MODP group', values: { size: 'modp', seed: 5 } },
    ],
    counters: [{ id: 'ops', label: 'group operations' }, { id: 'stored', label: 'table entries' }],
    run(inp) { return P.memo('p09-bsgs', inp, () => bsgs(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'start' && f.facts.m !== undefined && !f.meta.real, pick: 'option', ask: (fr, i) => `The order is n = ${fr[i].facts.n}. How many baby steps go into the table?`, options: (fr, i) => { const m = fr[i].facts.m; return [...new Set([String(m), String(m * 2n), String(fr[i].facts.n / 2n), String(m - 1n > 0n ? m - 1n : m + 3n)])]; }, answer: (fr, i) => String(fr[i].facts.m), explain: (fr, i) => `m = ⌈√n⌉ = ${fr[i].facts.m}: the baby steps cover every j from 0 to m − 1, and giant steps of m cover the rest.` },
      { at: (f, i, fr) => f.meta.phase === 'match', pick: 'option', ask: (fr, i) => `Giant step i = ${fr[i].facts.i} met baby step j = ${fr[i].facts.j}, with m = ${fr[i].facts.m}. What is x?`, options: (fr, i) => { const { i: a0, j, m, x } = fr[i].facts, a = B(a0); return [...new Set([String(x), String(a + j), String(a * j + 1n), String(j * m + a)])]; }, answer: (fr, i) => String(fr[i].facts.x), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'For a group of order about 10^12, how many group operations does baby-step giant-step need, roughly?', options: ['10^12', '10^6', '2·10^6', '12'], answer: 2, why: 'm ≈ √n = 10^6 baby steps and at most m giant steps.' },
      { q: 'What is the price of the speed-up?', options: ['A table of about √n group elements', 'It only works for prime p', 'It needs the factors of n', 'Nothing'], answer: 0, why: 'The baby steps must be stored and looked up; Pollard\'s rho gets the same time with almost no memory.' },
      { q: 'Why does every x in [0, n) have the form i·m + j with 0 ≤ i, j < m?', options: ['Division by m with remainder, and m² ≥ n', 'Because n is prime', 'Because g is a generator', 'It does not'], answer: 0, why: 'i = ⌊x/m⌋ and j = x mod m; since x < n ≤ m², i < m.' },
      { q: 'In the 2048-bit MODP group the order is a 2047-bit prime. How many baby steps would the table need?', options: ['About 2^11', 'About 2^1024', 'About 2^2047', 'About 2^112'], answer: 1, why: '√(2^2047) ≈ 2^1024: far beyond any memory or time.' },
    ],
  });

  function bsgs(inp) {
    const F = new S.Frames(['ops', 'stored']);
    const real = inp.size === 'modp';
    let group, h, secret = null;
    if (inp.size === 'toy') { group = DLP().groupZp(B(inp.p)); h = B(inp.h); }
    else if (inp.size === 'lab') { const L = DLP().labs.dlog(inp.seed, { bits: 28 }); group = L.group; h = L.public.h; secret = L.secret.x; }
    else { group = P.modp14(); secret = H.modpSecret(inp.seed); h = group.pow(group.generator, secret); }
    const g = group.generator, n = B(group.generatorOrder || group.order), m = NT().isqrt(n - 1n) + 1n;
    const p = group.p, name = real ? 'the 2048-bit MODP group' : 'Z_' + p + '*';
    const view = { x: -20, y: -70, w: 900, h: 620 };
    const BX = 0, GX = 300, RX = 610, maxRows = 11;
    const add = (say, facts, items, meta) => F.add({ items, say, facts, meta: Object.assign({ real }, meta || {}) });
    const head = [P.title('h:b', BX, -40, 'Baby steps, stored'), P.title('h:g', GX, -40, 'Giant steps, looked up'), P.title('h:r', RX, -40, 'The numbers')];
    const eqs = (lines) => P.eqs('q', RX, -2, lines, 16, 30);
    const base = [['g = ' + cellv(g) + ', h = ' + cellv(h)], ['n = ' + cellv(n)], ['m = ⌈√n⌉ = ' + cellv(m), 'act']];

    if (real) {
      // the attack cannot run: show its first steps, and what the whole would take
      const shown = 5, baby = [], giant = [];
      let cur = group.id;
      for (let j = 0; j < shown; j++) { baby.push(cur); cur = group.op(cur, g); }
      const fac = group.pow(group.inv(g), m);
      let gm = h;
      for (let i = 0; i < 3; i++) { giant.push(gm); gm = group.op(gm, fac); }
      const nb = NT().bitLength(n), mb = NT().bitLength(m);
      const tb1 = H.tab({ prefix: 'tb', x: BX, y: 0, colHead: ['j', 'g^j'], rows: baby.map((v, j) => [String(j), v]).concat([['⋮', '⋮']]), size: 14, ch: 36, minW: 54 });
      const tb2 = H.tab({ prefix: 'tg', x: GX, y: 0, colHead: ['i', 'h·g^(−m·i)'], rows: giant.map((v, i) => [String(i), v]).concat([['⋮', '⋮']]), size: 14, ch: 36, minW: 54 });
      const rv = (extra) => H.vals('v', RX - 35, 0, [['generator g', g], ['target h = g^x', h, 'key'], ['order n, a prime', n], ['m = ⌈√n⌉', m, 'act']]).concat(extra || []);
      add(`In ${name} the generator g = ${g} has order n = ${sh(n)}, a ${nb}-bit prime, and h = g^x for a secret x. The method is the same: m = ⌈√n⌉ = ${sh(m)}, a ${mb}-bit number.`, { g, n, nb, m, mb, pbits: NT().bitLength(p) }, [...head, ...rv()], { phase: 'start' });
      F.set('ops', shown).set('stored', shown);
      add(`The first baby steps are easy: g^0 to g^${shown - 1} are ${baby.map((v) => sh(v)).join(', ')}. The table needs all ${sh(m)} of them.`, { shown: shown - 1, baby, m }, [...head, ...rv(), ...tb1.items], { phase: 'baby' });
      F.set('ops', shown + 3);
      add(`Giant steps multiply by g^(−m), itself one exponentiation: h·g^(−m) = ${sh(giant[1])}. None of these values can be looked up in a table that cannot be built.`, { giant }, [...head, ...rv(), ...tb1.items, ...tb2.items], { phase: 'giant' });
      const work = P.eqs('w', RX, 290, [['table: about 2^' + (mb - 1) + ' entries', 'bad'], ['time: about 2^' + mb + ' operations', 'bad'], ['brute force: about 2^' + nb, 'muted']], 16, 30);
      add(`So the whole attack would store about 2^${mb - 1} group elements and take about 2^${mb} operations, the square root of the 2^${nb} of brute force. Square roots are the best any generic method can do, which is why the group's order must have at least twice as many bits as the security wanted.`, { mb: mb - 1, mb1: mb, nb }, [...head, ...rv(), ...work, ...tb1.items, ...tb2.items], { phase: 'cost' });
      return { frames: P.fix(F.list, view), def: def() };
    }

    const r = DLP().attack.bsgs(group, h, { n });
    if (r.x === null) throw new Error('h is not a power of g');
    const I = r.giantSteps - 1, J = B(r.trace[r.trace.length - 1].j), x = r.x;
    const baby = [], giant = [];
    let cur = group.id;
    for (let j = 0n; j < m; j++) { baby.push(cur); cur = group.op(cur, g); }
    const fac = group.pow(group.inv(g), m);
    let gm = h;
    for (let i = 0; i <= I; i++) { giant.push(gm); gm = group.op(gm, fac); }
    const babyT = (lit) => H.tab({ prefix: 'tb', x: BX, y: 0, colHead: ['j', 'g^j'], rows: baby.map((v, j) => [String(j), v]), maxRows, minW: 64, focus: lit === undefined ? undefined : [Number(lit), 1], hot: lit === undefined ? [] : [[Number(lit), 0], [Number(lit), 1]], size: 14, mono: true, ch: 36 });
    const giantT = (upto, lit) => H.tab({ prefix: 'tg', x: GX, y: 0, colHead: ['i', 'h·g^(−m·i)'], rows: giant.slice(0, upto + 1).map((v, i) => [String(i), v]), maxRows, minW: 64, focus: [upto, 1], act: lit ? [] : [[upto, 0], [upto, 1]], hot: lit ? [[upto, 0], [upto, 1]] : [], size: 14, mono: true, ch: 36 });

    add(`Solve g^x = h in ${name}: g = ${g}, h = ${h}, and g has order n = ${n}. Trying x = 0, 1, 2, … could take ${n} steps. Instead write x = i·m + j with m = ⌈√n⌉ = ${m}, so g^j = h·(g^−m)^i.`, { g, h, n, m, p }, [...head, ...eqs(base)], { phase: 'start' });
    F.set('ops', Number(m)).set('stored', Number(m));
    add(`Baby steps: g^0, g^1, …, g^${m - 1n}, each one multiplication more than the last: ${m} values stored in a table that can be searched by value (a hash table).`, { m, last: m - 1n }, [...head, ...eqs(base), ...babyT().items], { phase: 'baby' });
    const factor = ['g^(−m) = ' + cellv(fac), 'key'];
    const shown = I <= 5 ? I : 3;
    for (let i = 0; i <= shown && i < I; i++) {
      F.set('ops', Number(m) + i + 1);
      add(i === 0 ? `Giant step 0 is h itself, ${giant[0]}: not in the table. Each next giant step multiplies by g^(−m) = ${fac}, jumping m = ${m} down the exponents.` : `Giant step ${i}: h·g^(−${m}·${i}) = ${giant[i]}, not in the table.`, { i, v: giant[i], fac, m }, [...head, ...eqs(base.concat([factor])), ...babyT().items, ...giantT(i).items], { phase: 'giant', i });
    }
    if (I > shown + 1) {
      F.set('ops', Number(m) + I);
      add(`Giant steps ${shown + 1} to ${I - 1} miss as well: no value among them is a baby step.`, { a: shown + 1, b: I - 1 }, [...head, ...eqs(base.concat([factor])), ...babyT().items, ...giantT(I - 1).items], { phase: 'giant', i: I - 1 });
    }
    F.set('ops', Number(m) + I + 1);
    const mt = babyT(J), gt = giantT(I, true);
    const link = { key: 'link', kind: 'edge', from: gt.key(I, 1), to: mt.key(Number(J), 1), head: true, bend: 0, cls: 'hot', layer: 'top', audit: 'ignore' };
    add(`Giant step ${I}: h·g^(−${m}·${I}) = ${giant[I]}, and ${giant[I]} is in the table as g^${J}. So h·g^(−m·i) = g^j with i = ${I} and j = ${J}.`, { i: I, j: J, m, v: giant[I] }, [...head, ...eqs(base.concat([factor, ['h·g^(−m·' + I + ') = g^' + J, 'hot']])), ...mt.items, ...gt.items, link], { phase: 'match' });
    const ok = group.eq(group.pow(g, x), h);
    add(`Then h = g^(i·m + j), so x = ${I}·${m} + ${J} = ${x}. Check: g^${x} = ${group.pow(g, x)} = h. It took ${m} baby steps and ${I + 1} giant steps, ${m + B(I + 1)} operations, where counting up would have taken ${x}.`, { x, i: I, j: J, m, check: group.pow(g, x), steps: I + 1, ops: m + B(I + 1), ok }, [...head, ...eqs(base.concat([factor, ['x = ' + I + '·' + m + ' + ' + J + ' = ' + x, 'good']])), ...mt.items, ...gt.items, link], { phase: 'done', x });
    const M = P.modp14(), qb = NT().bitLength(M.order);
    add(`The cost grows with √n: ${m} entries here. In the 2048-bit MODP group the order has ${qb} bits, so the table would need about 2^${Math.ceil(qb / 2)} entries. Generic methods only win a square root; safety comes from the size of the group.`, { m, qb, half: Math.ceil(qb / 2), pbits: NT().bitLength(M.p) }, [...head, ...eqs(base.concat([factor, ['x = ' + x, 'good'], ['', ''], ['2048-bit group: 2^' + Math.ceil(qb / 2) + ' entries', 'bad']])), ...mt.items, ...gt.items], { phase: 'cost' });
    const box = { x: -20, y: -70, w: 600, h: 620 };
    for (const f of F.list) f.narrowView = f.meta.phase === 'start' || f.meta.phase === 'cost' ? { x: RX - 20, y: -70, w: 300, h: 420 } : box;
    return { frames: P.fix(F.list, view), def: def() };
  }
  function def() {
    return P.def('Baby-step giant-step', ['solve g^x = h, g of order n', 'm = ⌈√n⌉, x = i·m + j, 0 ≤ i, j < m', 'baby steps: store g^j for j = 0 … m − 1', 'giant steps: h·(g^−m)^i for i = 0, 1, …', 'a match g^j = h·g^(−m·i) gives x = i·m + j', 'time and memory: about √n each']);
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Pollard's rho
  // ---------------------------------------------------------------------------------------------------------------
  /** the order-q subgroup used for rho in Z_p*: q the largest prime factor of p − 1, g a generator raised to (p − 1)/q */
  H.rhoGroup = (p) => {
    p = B(p);
    const q = [...NT().factor(p - 1n).keys()].reduce((a, b) => (a > b ? a : b));
    const g0 = DLP().groupZp(p).generator, g = NT().pow(g0, (p - 1n) / q, p);
    return DLP().subgroupZp(p, q, g);
  };
  /** the walk the engine's rho takes (x → x·h, x², x·g as x mod 3 is 0, 1, 2), run until a value repeats */
  H.walk = (G, h, att, limit) => {
    const g = G.generator, n = G.order, seq = [], seen = new Map();
    let a = NT().mod(1n + BigInt(att), n), b = NT().mod(BigInt(att), n), X = G.op(G.pow(g, a), G.pow(h, b));
    while (!seen.has(X) && seq.length < (limit || 1e7)) {
      seen.set(X, seq.length);
      const br = Number(X % 3n);
      seq.push({ X, a, b, br });
      if (br === 0) { X = G.op(X, h); b = NT().mod(b + 1n, n); } else if (br === 1) { X = G.op(X, X); a = NT().mod(2n * a, n); b = NT().mod(2n * b, n); } else { X = G.op(X, g); a = NT().mod(a + 1n, n); }
    }
    const mu = seen.has(X) ? seen.get(X) : null;
    return { seq, mu, lam: mu === null ? null : seq.length - mu };
  };
  const BR = ['× h', 'square', '× g'];
  const rhoCheckX = (v, inp) => { if (inp.size !== 'toy') return null; let x; try { x = B(String(v).trim()); } catch (e) { return 'x: a whole number'; } if (H.primeIn(23, 100003, 'p')(inp.p)) return null; const q = H.rhoGroup(inp.p).order; if (q < 11n) return 'p − 1 needs a prime factor of at least 11 (here the largest is ' + q + ')'; return x < 1n || x >= q ? 'x: from 1 to q − 1 = ' + (q - 1n) : null; };

  S.topic({
    id: 'p09-rho', family: 'p09-attacks', order: 20, title: 'Pollard\'s rho',
    blurb: 'A walk through the group that multiplies by g, multiplies by h or squares, chosen by the current value, and keeps track of x = g^a·h^b. In a finite group it must repeat: a tail, then a cycle, the shape of the letter ρ. Floyd\'s tortoise and hare find the repeat with no table at all, and the two ways of writing the same value give the logarithm.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Group', def: 'toy', options: [{ value: 'toy', label: 'toy: order q in Z_p*' }, { value: 'lab', label: 'a 30-bit safe prime (computed)' }, { value: 'modp', label: 'the 2048-bit MODP group' }] },
      { id: 'p', kind: 'bigint', label: 'Prime p (toy)', def: '1019', check: H.primeIn(23, 100003, 'p') },
      { id: 'x', kind: 'bigint', label: 'Secret x (toy)', def: '321', check: rhoCheckX },
      { id: 'seed', kind: 'number', label: 'Seed (larger groups)', def: 4, min: 1, max: 9999 },
    ],
    presets: [
      { label: 'p = 1019, x = 321: a long tail', values: { size: 'toy', p: '1019', x: '321' } },
      { label: 'p = 467, x = 99', values: { size: 'toy', p: '467', x: '99' } },
      { label: 'p = 1019, x = 100: a big cycle', values: { size: 'toy', p: '1019', x: '100' } },
      { label: 'p = 863: almost no tail', values: { size: 'toy', p: '863', x: '200' } },
      { label: 'p = 2039: a walk of 100 steps', values: { size: 'toy', p: '2039', x: '777' } },
      { label: 'A 30-bit safe prime', values: { size: 'lab', seed: 4 } },
      { label: 'The 2048-bit MODP group', values: { size: 'modp', seed: 5 } },
    ],
    counters: [{ id: 'steps', label: 'tortoise steps' }, { id: 'ops', label: 'group operations' }],
    run(inp) { return P.memo('p09-rho', inp, () => rho(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'shape', pick: 'option', ask: (fr, i) => `The tail has ${fr[i].facts.mu} steps and the cycle ${fr[i].facts.lam}. The tortoise takes one step at a time, the hare two. After how many tortoise steps do they first stand on the same value?`, options: (fr, i) => { const { mu, lam, meet } = fr[i].facts; return [...new Set([String(meet), String(mu + lam), String(lam), String(mu + 1), String(2 * lam)])].slice(0, 4).sort((a, b) => a - b); }, answer: (fr, i) => String(fr[i].facts.meet), explain: (fr, i) => `They meet at the first i that is a multiple of the cycle length ${fr[i].facts.lam} and at least the tail length ${fr[i].facts.mu}: then x_i and x_2i are i apart on the cycle, a whole number of laps. That is i = ${fr[i].facts.meet}.` },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'meet' && fr[i + 1].meta.dots, pick: 'item', ask: 'Click the point where the tortoise and the hare will meet.', answer: (fr, i) => fr[i + 1].meta.at, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why must the walk repeat?', options: ['The group is finite, and each step depends only on the current value', 'Because q is prime', 'Because the hare is faster', 'It need not repeat'], answer: 0, why: 'A deterministic walk in a finite set must revisit a value, and from then on it cycles.' },
      { q: 'How much memory does Pollard\'s rho with Floyd\'s method need?', options: ['A table of √q values', 'Two points and their exponents', 'q values', 'The factor base'], answer: 1, why: 'Only the tortoise and the hare, each with its (a, b): that is the advantage over baby-step giant-step.' },
      { q: 'The meeting gives g^a1·h^b1 = g^a2·h^b2. What does that give, with h = g^x?', options: ['x = a1 + a2', '(b1 − b2)·x ≡ a2 − a1 (mod q)', 'a1 = a2', 'x = b1·b2'], answer: 1, why: 'Write both sides as powers of g: a1 + x·b1 ≡ a2 + x·b2 (mod q).' },
      { q: 'About how many steps does rho take in a group of prime order q?', options: ['q', 'log q', 'about √q', 'q²'], answer: 2, why: 'By the birthday bound a random walk repeats after about √(πq/2) values.' },
      { q: 'When does the method fail and need a fresh start?', options: ['When b1 ≡ b2 (mod q)', 'When the tail is long', 'When q is prime', 'Never'], answer: 0, why: 'Then the equation has no x in it; start the walk from another point.' },
    ],
  });

  function rho(inp) {
    const F = new S.Frames(['steps', 'ops']);
    const real = inp.size === 'modp';
    let G, h, secret;
    if (inp.size === 'toy') { G = H.rhoGroup(inp.p); secret = B(inp.x); }
    else if (inp.size === 'lab') { const sp = H.seeded(inp.seed, () => NT().randomSafePrime(30)); G = DLP().subgroupZp(sp.prime, sp.q, 4n); secret = H.seeded(inp.seed + 1, () => 1n + NT().randBelow(sp.q - 1n)); }
    else { G = P.modp14(); secret = H.modpSecret(inp.seed); }
    h = G.pow(G.generator, secret);
    const g = G.generator, q = G.order, p = G.p, qb = NT().bitLength(q);
    const view = { x: -20, y: 0, w: 900, h: 560 }, RX = 560;
    const add = (say, facts, items, meta) => F.add({ items, say, facts, meta: Object.assign({ real }, meta || {}) });
    const rules = [['each value is g^a·h^b', 'strong'], ['the next, by x mod 3:', 'strong'], ['0: x·h   (b + 1)', 'act'], ['1: x²   (2a, 2b)', 'key'], ['2: x·g   (a + 1)', 'good']];
    const title = [P.title('h:r', RX, 30, 'The walk')];
    const exp = 'the expected √(πq/2) ≈ ';

    if (real) {
      const w = H.walk(G, h, 0, 6), rows = w.seq.map((s, k) => ['x' + P.sub(k), s.X, BR[s.br]]);
      const tb = H.tab({ prefix: 'tw', x: 0, y: 60, colHead: ['', 'value', 'next step'], rows, size: 14, ch: 38, max: 22 });
      const rb = P.rhoBits(qb);
      add(`In the 2048-bit MODP group, g = ${g} has order q = ${sh(q)}, a ${qb}-bit prime, and h = g^x for a secret x. The walk starts at x₀ = g·h⁰ = g and every step is one 2048-bit multiplication.`, { g, q, qb, pbits: NT().bitLength(p) }, [...title, ...P.eqs('q', RX, 70, rules, 16, 30), P.title('h:w', 0, 30, 'The first steps')], { phase: 'start' });
      F.set('steps', 5).set('ops', 5);
      add(`The first steps: ${w.seq.slice(0, 5).map((s) => sh(s.X)).join(', ')}, each chosen by its value mod 3. The values look random, which is what the method needs.`, { vals: w.seq.map((s) => s.X) }, [...title, ...P.eqs('q', RX, 70, rules, 16, 30), P.title('h:w', 0, 30, 'The first steps'), ...tb.items], { phase: 'walk' });
      add(`The walk would repeat after about √(πq/2) values, about 2^${f1(rb + 0.5)} here, and Floyd's hare does three operations per tortoise step: around 2^${f1(rb + 0.5 + Math.log2(3))} multiplications. No computer will ever finish. A generic attack needs only the order to be large: that is why a 224-bit or 256-bit prime-order subgroup already defeats it.`, { rb: f1(rb + 0.5), ops: f1(rb + 0.5 + Math.log2(3)), qb }, [...title, ...P.eqs('q', RX, 70, rules.concat([['', ''], ['about 2^' + f1(rb + 0.5) + ' steps', 'bad']]), 16, 30), P.title('h:w', 0, 30, 'The first steps'), ...tb.items], { phase: 'cost' });
      return { frames: P.fix(F.list, view), def: def2() };
    }

    const r = DLP().attack.rho(G, h, { n: q });
    if (r.x === null) throw new Error('the walk found no useful collision');
    const w = H.walk(G, h, r.attempts - 1), mu = w.mu, lam = w.lam, seq = w.seq;
    const meet = r.iterations, col = r.trace.find((t) => t.kind === 'collision');
    const at = (k) => (k < mu ? k : mu + ((k - mu) % lam));
    // the ρ: dots when it fits, a drawn shape otherwise
    const dots = lam <= 40 && mu <= 30;
    const R = dots ? Math.max(70, (lam * 26) / (2 * Math.PI)) : 150, cx = 260, cy = dots ? 50 + R : 200;
    const ex = cx, ey = cy + R, room = 520 - ey, st = dots ? Math.min(24, room / Math.max(mu, 1)) : 0;
    const dir = { x: -0.5, y: 0.866 };
    const pos = (k) => {
      if (k < mu) { const d = dots ? (mu - k) * st : (150 * (mu - k)) / mu; return { x: P.r2(ex + dir.x * d), y: P.r2(ey + dir.y * d), side: { x: -dir.y, y: dir.x } }; }
      const t = (k - mu) / lam, a = Math.PI / 2 - 2 * Math.PI * t;
      return { x: P.r2(cx + R * Math.cos(a)), y: P.r2(cy + R * Math.sin(a)), side: { x: Math.cos(a), y: Math.sin(a) } };
    };
    const dotKey = (k) => 'd' + at(k);
    const shape = (upto, lit) => {
      const out = [];
      if (dots) {
        let d = '';
        for (let k = 0; k <= Math.min(upto, seq.length - 1); k++) { const p0 = pos(k); d += (k ? 'L' : 'M') + p0.x + ',' + p0.y + ' '; }
        if (upto >= seq.length) { const p0 = pos(mu); d += 'L' + p0.x + ',' + p0.y; }
        out.push({ key: 'walk', kind: 'path', d, cls: 'p9-walk', audit: 'ignore', layer: 'back' });
        for (let k = 0; k <= Math.min(upto, seq.length - 1); k++) { const p0 = pos(k); out.push({ key: 'd' + k, kind: 'dot', x: p0.x, y: p0.y, r: 5.5, cls: 'p9-pt ' + (k < mu ? 'tail ' : 'cyc ') + ((lit && lit[k]) || ''), pick: true, title: 'x' + P.sub(k) + ' = ' + seq[k].X }); }
      } else {
        const t0 = pos(0), e0 = pos(mu);
        out.push({ key: 'tailp', kind: 'path', d: `M${t0.x},${t0.y} L${e0.x},${e0.y}`, cls: 'p9-walk', audit: 'ignore', layer: 'back' });
        if (upto >= mu) out.push({ key: 'cycp', kind: 'path', d: `M${cx},${cy - R} A${R},${R} 0 1 1 ${cx},${cy + R} A${R},${R} 0 1 1 ${cx},${cy - R}`, cls: 'p9-walk', audit: 'ignore', layer: 'back' });
        out.push({ key: 'd0', kind: 'dot', x: t0.x, y: t0.y, r: 6, cls: 'p9-pt tail' });
        out.push({ key: 'dm', kind: 'dot', x: e0.x, y: e0.y, r: 6, cls: 'p9-pt cyc' });
        for (const [k, c] of Object.entries(lit || {})) { const q0 = pos(+k); out.push({ key: 'dl' + c, kind: 'dot', x: q0.x, y: q0.y, r: 6, cls: 'p9-pt ' + c, audit: 'overlap-ok' }); }
        out.push(P.t('l:tail', (t0.x + e0.x) / 2 - 16, (t0.y + e0.y) / 2 + 4, 'tail: ' + mu, 'strong', 'end', 14));
        out.push(P.t('l:cyc', cx, cy + 4, 'cycle: ' + lam, 'strong', 'middle', 15));
      }
      const s0 = pos(0);
      out.push(P.t('l:x0', s0.x + 14, s0.y + 18, 'x₀ = ' + seq[0].X, 'tick', 'start', 13));
      if (upto >= mu && mu > 0) { const e0 = pos(mu); out.push(P.t('l:mu', e0.x + 16, e0.y + 18, 'x' + P.sub(mu) + ' joins the cycle', 'tick', 'start', 13)); }
      return out;
    };
    const tokens = (i) => {
      const a = pos(i), b = pos(2 * i);
      const tp = dots ? at(i) < mu ? { x: a.x - 20, y: a.y } : { x: a.x + a.side.x * 24, y: a.y + a.side.y * 24 } : { x: a.x + (a.side.x) * 24, y: a.y + a.side.y * 24 };
      const hp = at(2 * i) < mu ? { x: b.x + 20, y: b.y } : { x: b.x - b.side.x * 24, y: b.y - b.side.y * 24 };
      return [{ key: 'tok:t', kind: 'token', x: P.r2(tp.x), y: P.r2(tp.y), r: 13, text: 'T', cls: 'p9-tort', audit: 'overlap-ok' }, { key: 'tok:h', kind: 'token', x: P.r2(hp.x), y: P.r2(hp.y), r: 13, text: 'H', cls: 'p9-hare', audit: 'overlap-ok' }];
    };
    const panel = (extra) => [...title, ...P.eqs('q', RX, 70, rules.concat(extra || []), 16, 30)];
    const nm = 'the order-' + q + ' subgroup of Z_' + p + '*';

    add(`Solve g^x = h in ${nm}: g = ${g}, h = ${h}. The walk starts at x₀ = g^${seq[0].a}·h^${seq[0].b} = ${seq[0].X} and moves by the rule on the right, tracking both exponents in x = g^a·h^b.`, { g, h, q, p, a0: seq[0].a, b0: seq[0].b, x0: seq[0].X }, [...shape(0), ...panel()], { phase: 'start', dots });
    const few = Math.min(5, seq.length - 1);
    add(`The first steps: ${seq.slice(0, few + 1).map((s, k) => (k ? BR[seq[k - 1].br] + ' → ' : '') + s.X).join(', ')}. Each value picks the next move; the values look scattered at random.`, { vals: seq.slice(0, few + 1).map((s) => s.X) }, [...shape(few), ...panel()], { phase: 'walk', dots });
    add(`A walk in a finite group must repeat, and since each step depends only on the value, it then goes round for ever: a tail of ${mu} step${mu === 1 ? '' : 's'}, then a cycle of ${lam}. Together the shape of a ρ.`, { mu, lam, meet, total: seq.length }, [...shape(seq.length), ...panel([['', ''], ['tail μ = ' + mu + ', cycle λ = ' + lam, 'hot']])], { phase: 'shape', dots });
    const show = meet <= 9 ? [...Array(meet - 1).keys()].map((k) => k + 1) : [1, 2, 3, meet - 2, meet - 1];
    for (const i of show) {
      F.set('steps', i).set('ops', 3 * i);
      const ti = seq[at(i)], hi = seq[at(2 * i)];
      add((i === 1 ? 'Floyd: the tortoise T takes one step at a time, the hare H two. ' : i === meet - 2 && show[2] === 3 ? `Steps 4 to ${meet - 3} go the same way. ` : '') + `Step ${i}: T is at x${P.sub(i)} = ${ti.X}, H at x${P.sub(2 * i)} = ${hi.X}${ti.X === hi.X ? '' : ': different'}.`, { i, t: ti.X, hv: hi.X, i2: 2 * i, a: 4, b: meet - 3 }, [...shape(seq.length, { [at(i)]: 'act', [at(2 * i)]: 'key' }), ...tokens(i), ...panel([['', ''], ['T: x' + P.sub(i) + ' = ' + ti.X, 'act'], ['H: x' + P.sub(2 * i) + ' = ' + hi.X, 'key']])], { phase: 'floyd', i, dots });
    }
    F.set('steps', meet).set('ops', 3 * meet);
    const mv = seq[at(meet)].X, a1 = B(col.a1), b1 = B(col.b1), a2 = B(col.a2), b2 = B(col.b2);
    add(`Step ${meet}: T at x${P.sub(meet)} and H at x${P.sub(2 * meet)} are both ${mv}. They meet: the hare is exactly ${meet} steps ahead, a whole number of laps of ${lam}. The tortoise reached it as g^${a1}·h^${b1}, the hare as g^${a2}·h^${b2}.`, { meet, m2: 2 * meet, mv, lam, a1, b1, a2, b2 }, [...shape(seq.length, { [at(meet)]: 'hot' }), ...tokens(meet), ...panel([['', ''], ['g^' + a1 + '·h^' + b1, 'act'], ['= g^' + a2 + '·h^' + b2, 'key']])], { phase: 'meet', at: dotKey(meet), dots });
    const db = NT().mod(b1 - b2, q), da = NT().mod(a2 - a1, q), x = r.x, ok = G.eq(G.pow(g, x), h);
    add(`With h = g^x both are powers of g: ${a1} + ${b1}·x ≡ ${a2} + ${b2}·x (mod ${q}), so ${db}·x ≡ ${da} (mod ${q}) and x = ${da}·${db}⁻¹ mod ${q} = ${x}. Check: g^${x} = ${G.pow(g, x)} = h. ${3 * meet} group operations and two points of memory.`, { a1, b1, a2, b2, q, db, da, x, check: G.pow(g, x), ops: 3 * meet, ok }, [...shape(seq.length, { [at(meet)]: 'hot' }), ...panel([['', ''], [db + '·x ≡ ' + da + ' (mod ' + q + ')', 'strong'], ['x = ' + x, 'good']])], { phase: 'solve', x, dots });
    const M = P.modp14(), mq = NT().bitLength(M.order), rb = P.rhoBits(mq) + 0.5, ex2 = Math.sqrt(Math.PI * Number(q) / 2);
    add(`Here the walk took ${seq.length} values before repeating, near ${exp}${f1(ex2)}. The 2048-bit MODP group has a ${mq}-bit order: about 2^${f1(rb)} steps, far out of reach, and no memory saving changes that.`, { total: seq.length, ex: f1(ex2), mq, rb: f1(rb), pbits: NT().bitLength(M.p) }, [...shape(seq.length), ...panel([['', ''], ['x = ' + x, 'good'], ['2048-bit group: 2^' + f1(rb) + ' steps', 'bad']])], { phase: 'cost', dots });
    for (const f of F.list) f.narrowView = { x: -20, y: 0, w: 540, h: 560 };
    return { frames: P.fix(F.list, view), def: def2() };
  }
  function def2() {
    return P.def('Pollard\'s rho', ['a walk with x = g^a·h^b, the next step chosen by x mod 3:', '  0: x·h,  1: x²,  2: x·g', 'it repeats: a tail μ, then a cycle λ', 'Floyd: T steps once, H twice, until x_i = x_2i', 'g^a1·h^b1 = g^a2·h^b2 ⇒ (b1 − b2)·x ≡ a2 − a1 (mod q)', 'about √(πq/2) steps, two points of memory']);
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Pohlig–Hellman
  // ---------------------------------------------------------------------------------------------------------------
  const smoothCheck = (v) => { const e = H.primeIn(7, 2000003, 'p')(v); if (e) return e; const big = [...NT().factor(B(v) - 1n).keys()].reduce((a, b) => (a > b ? a : b)); return big > 1000n ? 'p − 1 must be smooth: its largest prime factor, ' + big + ', is above 1000' : null; };
  S.topic({
    id: 'p09-pohlig', family: 'p09-attacks', order: 30, title: 'Pohlig–Hellman',
    blurb: 'When the order n of the group is a product of small primes, the logarithm splits: raise everything to n/q to land in a subgroup of order q, read x mod q there by a short search, peel off one base-q digit at a time to get x mod q^e, and glue the pieces with the Chinese remainder theorem. The cost depends on the largest prime factor of n, not on n.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Group', def: 'toy', options: [{ value: 'toy', label: 'toy: Z_p* with p − 1 smooth' }, { value: 'big', label: 'a 200-bit prime with p − 1 smooth (computed)' }, { value: 'modp', label: 'the 2048-bit MODP group' }] },
      { id: 'p', kind: 'bigint', label: 'Prime p (toy)', def: '8101', check: smoothCheck },
      { id: 'h', kind: 'bigint', label: 'Target h', def: '1234', check: (v, inp) => { let h; try { h = B(String(v).trim()); } catch (e) { return 'h: a whole number'; } return inp.size === 'toy' && !smoothCheck(inp.p) && (h < 1n || h >= B(inp.p)) ? 'h: from 1 to p − 1' : null; } },
      { id: 'seed', kind: 'number', label: 'Seed (larger groups)', def: 7, min: 1, max: 9999 },
    ],
    presets: [
      { label: 'p = 8101: n = 2²·3⁴·5²', values: { size: 'toy', p: '8101', h: '1234' } },
      { label: 'p = 7681: n = 2⁹·3·5', values: { size: 'toy', p: '7681', h: '2026' } },
      { label: 'p = 3001: n = 2³·3·5³', values: { size: 'toy', p: '3001', h: '999' } },
      { label: 'p = 1999: n = 2·3³·37', values: { size: 'toy', p: '1999', h: '5' } },
      { label: 'A 200-bit smooth group', values: { size: 'big', seed: 7 } },
      { label: 'The MODP group: one big prime', values: { size: 'modp', seed: 5 } },
    ],
    counters: [{ id: 'ops', label: 'subgroup steps' }, { id: 'known', label: 'bits of x known' }],
    run(inp) { return P.memo('p09-pohlig', inp, () => pohlig(inp)); },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'start' && fr.some((x) => x.meta.phase === 'crt'), pick: 'option', ask: (fr, i) => `n = ${fr[i].facts.nf}. Into how many separate logarithm problems does it split?`, options: (fr, i) => { const k = fr[i].facts.parts; return [...new Set([String(k), String(fr[i].facts.digits), '1', String(k + 2)])].sort((a, b) => a - b); }, answer: (fr, i) => String(fr[i].facts.parts), explain: (fr, i) => `One for each prime power: ${fr[i].facts.parts}. Each is solved in its own small subgroup, digit by digit.` },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'crt', pick: 'option', ask: (fr, i) => 'All the residues are known. What is x?', options: (fr, i) => { const x = fr[i + 1].facts.x, n = fr[i + 1].facts.n; return [...new Set([String(x), String(NT().mod(x + n / 2n, n)), String(NT().mod(x - 1n, n)), String(NT().mod(3n * x, n))])].sort((a, b) => (B(a) < B(b) ? -1 : 1)); }, answer: (fr, i) => String(fr[i + 1].facts.x), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'p − 1 = 2⁴·3·5·7. What does the cost of Pohlig–Hellman depend on most?', options: ['The size of p', 'The largest prime factor, 7', 'The number 2⁴', 'The generator'], answer: 1, why: 'Each piece is a logarithm in a subgroup of prime order q; the largest q is the hardest piece.' },
      { q: 'Why does raising to n/q land in a subgroup of order q?', options: ['Because (g^(n/q))^q = g^n = 1', 'Because q is odd', 'Because h is a square', 'It does not'], answer: 0, why: 'g^(n/q) has order exactly q when g generates the group of order n.' },
      { q: 'How is x put together from x mod 4, x mod 81 and x mod 25?', options: ['By adding them', 'By the Chinese remainder theorem', 'By Euclid', 'It cannot be'], answer: 1, why: '4, 81 and 25 are coprime with product n, so the residues fix x mod n.' },
      { q: 'Which choice of prime defeats Pohlig–Hellman?', options: ['p − 1 a power of 2', 'p = 2q + 1 with q prime (a safe prime), or a prime-order subgroup', 'Any p of 64 bits', 'p ≡ 1 (mod 4)'], answer: 1, why: 'Then the order has a huge prime factor q, and the piece mod q is as hard as the whole problem.' },
    ],
  });

  function pohlig(inp) {
    const F = new S.Frames(['ops', 'known']);
    const view = { x: -20, y: -40, w: 900, h: 580 }, RX = 560;
    const add = (say, facts, items, meta) => F.add({ items, say, facts, meta: meta || {} });
    if (inp.size === 'modp') {
      const G = P.modp14(), q = G.order, qb = NT().bitLength(q), rb = P.rhoBits(qb) + 0.5;
      const vals = H.vals('v', 0, 30, [['p', G.p], ['p − 1 = 2·q, q prime', q, 'bad']], 330);
      add(`The 2048-bit MODP group uses a safe prime: p − 1 = 2·q with q a ${qb}-bit prime, and g = ${G.generator} generates the subgroup of order q. Its order has a single prime factor, q itself.`, { qb, g: G.generator, pbits: 2048 }, [P.title('h', 0, -10, 'The order of the group'), ...vals], { phase: 'start' });
      add(`So Pohlig–Hellman has nothing to split: the one piece is the whole problem, a logarithm in a group of prime order with ${qb} bits, about 2^${f1(rb)} steps by rho. Choosing the order to be a large prime is exactly the defence.`, { qb, rb: f1(rb) }, [P.title('h', 0, -10, 'The order of the group'), ...vals, ...P.eqs('q', 380, 50, [['one prime power: q¹', 'strong'], ['digits to search: up to q', 'bad'], ['about 2^' + f1(rb) + ' steps', 'bad']], 16, 30)], { phase: 'cost' });
      return { frames: P.fix(F.list, view), def: def3() };
    }
    let G, h;
    if (inp.size === 'toy') { G = DLP().groupZp(B(inp.p)); h = B(inp.h); }
    else { const L = DLP().labs.smooth(inp.seed, { minOrder: 2n ** 200n }); G = L.group; h = L.public.h; }
    const g = G.generator, n = G.order, p = G.p, big = inp.size === 'big';
    const r = DLP().attack.pohligHellman(G, h);
    if (r.x === null) throw new Error('h is not a power of g');
    const fac = [...NT().factor(n)], nf = NT().fmtFactors(NT().factor(n)).replace(/\^(\d+)/g, (m, e) => P.sup(e));
    const digitsAll = fac.reduce((a, [, e]) => a + e, 0);
    const pw = (q, e) => q + (e > 1 ? P.sup(e) : '');
    const rowsOf = (state) => fac.map(([q, e], i) => { const st = state[i] || {}; return [pw(q, e), st.digits ? st.digits.join(' ') : '', st.x === undefined ? '' : st.x]; });
    const table = (state, cur) => H.tab({ prefix: 'tp', x: 0, y: 30, colHead: ['prime power', 'digits, base q', 'x mod q^e'], rows: rowsOf(state), maxRows: 9, focus: cur === undefined ? undefined : [cur, 2], act: cur === undefined ? [] : [[cur, 0], [cur, 1], [cur, 2]], size: 15, ch: 38, minW: 110 });
    const head = [P.t('h', 0, -6, 'n = p − 1 = ' + (big ? 'a product of small primes' : nf), 'strong', 'start', 16), P.title('h2', RX, -10, 'This step')];
    const state = [];
    const nb = NT().bitLength(n);
    const top = fac[fac.length - 1][0];
    add(big ? `Solve g^x = h modulo a ${NT().bitLength(p)}-bit prime p, with g = ${g}. The order n = p − 1 has ${nb} bits but is made of ${fac.length} prime powers, none with a prime above ${top}: ${digitsAll} digits in all.` : `Solve g^x = h in Z_${p}*, with g = ${g} and h = ${h}. The order n = p − 1 = ${n} = ${nf}: ${fac.length} prime powers, ${digitsAll} digits in all.`, { p, g, h, n, nf, parts: fac.length, digits: digitsAll, nb, top, pb: NT().bitLength(p) }, [...head, ...table(state).items, ...P.eqs('q', RX, 30, [['x mod q^e for each prime power,', 'strong'], ['one base-q digit at a time', 'strong'], ['then the CRT glues them', 'strong']], 16, 30)], { phase: 'start' });
    let ops = 0, known = 0;
    const perDigit = !big && digitsAll <= 12;
    let ti = 1;
    fac.forEach(([q, e], idx) => {
      const gq = G.pow(g, n / q);
      state[idx] = { digits: [], x: 0n };
      for (let k = 0; k < e; k++) {
        const tr = r.trace[ti++], d = B(tr.digit), xk = B(tr.x);
        const target = G.pow(G.op(h, G.inv(G.pow(g, state[idx].x))), n / q ** BigInt(k + 1));
        state[idx].digits.push(d); state[idx].x = xk;
        ops += Number(d) + 1; known += Math.log2(Number(q));
        F.set('ops', ops).set('known', Math.floor(known));
        if (!perDigit && k < e - 1) continue;
        const mod = q ** BigInt(k + 1), lines = perDigit ? [['γ = g^(n/' + q + ') = ' + cellv(gq) + ', order ' + q, 'key'], ['t = (h·g^(−' + (state[idx].x - d * q ** BigInt(k)) + '))^(n/' + mod + ')', ''], ['  = ' + cellv(target), ''], ['t = γ' + P.sup(d) + ', so digit ' + k + ' = ' + d, 'act'], ['x ≡ ' + xk + ' (mod ' + mod + ')', 'good']] : [['prime ' + q + ': ' + e + ' digit' + (e > 1 ? 's' : ''), 'key'], ['digits ' + state[idx].digits.join(', '), 'act'], ['x ≡ ' + cellv(xk) + ' (mod ' + cellv(mod) + ')', 'good']];
        const say = perDigit
          ? (k === 0 ? `Prime ${q}: γ = g^(n/${q}) = ${gq} has order ${q}. Raise h to n/${q} too: t = ${target}, which is γ${P.sup(d)}. So x ≡ ${d} (mod ${q}), found in ${Number(d) + 1} step${d ? 's' : ''} of a search through only ${q} values.` : `Digit ${k} for ${q}: take off what is known, raise h·g^(−${state[idx].x - d * q ** BigInt(k)}) to n/${mod}: t = ${target} = γ${P.sup(d)}. The digit is ${d}, so x ≡ ${xk} (mod ${mod}).`)
          : `Prime ${q}${e > 1 ? ` to the power ${e}` : ''}: the digits ${state[idx].digits.join(', ')} in base ${q} give x ≡ ${sh(xk)} (mod ${sh(mod)}).`;
        const clock = [];
        if (perDigit && q <= 13n) {
          const c = S.Kit.nt.clock({ prefix: 'ck', cx: RX + 130, cy: 330, R: q <= 3n ? 60 : 95, n: Number(q), r: 20, text: (j) => 'γ' + P.sup(j), cls: (j) => (j === Number(d) ? 'hot' : j < Number(d) ? 'soft' : '') });
          clock.push(P.title('ck:t', RX, 200, 'The subgroup of order ' + q), ...c.items);
          for (let j = 0; j < Number(q); j++) { const it = clock.find((x) => x.key === 'ck:' + j); if (it) it.title = 'γ^' + j + ' = ' + G.pow(gq, B(j)); }
        }
        add(say, { q, k, d, x: xk, mod, gq, target, e, digits: state[idx].digits, prev: state[idx].x - d * q ** BigInt(k), steps: Number(d) + 1 }, [...head, ...table(state, idx).items, ...P.eqs('q', RX, 30, lines, 16, 30), ...clock], { phase: 'digit', q, k, at: 'ck:' + d });
      }
    });
    const crt = r.crt, x = r.x;
    const ct = H.tab({ prefix: 'tc', x: RX, y: 30, colHead: ['x ≡ r', 'mod m'], rows: r.parts.map((pt) => [pt.residue, pt.modulus]), maxRows: 7, size: 15, ch: 36, minW: 90 });
    add(`The Chinese remainder theorem joins ${r.parts.map((pt) => `x ≡ ${sh(pt.residue)} (mod ${sh(pt.modulus)})`).join(', ')} into one x modulo their product n: x = ${sh(x)}.`, { x, n, parts: r.parts.map((pt) => [pt.residue, pt.modulus]) }, [...head.slice(0, 1), P.title('h3', RX, -10, 'The Chinese remainder theorem'), ...table(state).items, ...ct.items, ...P.eqs('q2', RX, 60 + 36 * Math.min(r.parts.length + 1, 8) + 10, [['x = ' + cellv(x), 'good']], 17)], { phase: 'crt' });
    const check = G.pow(g, x), rb = Math.log2(Math.sqrt(Math.PI * Number(n) / 2)), biggest = fac[fac.length - 1][0];
    add(`Check: g^x = ${sh(check)} = h. The searches took ${ops} steps in all, the largest piece needing at most ${biggest}; a generic attack on the whole order would need about 2^${f1(rb)}. The largest prime factor of n is the true size of the problem.`, { check, ops, biggest, rb: f1(rb), ok: G.eq(check, h) }, [...head.slice(0, 1), P.title('h3', RX, -10, 'Done'), ...table(state).items, ...P.eqs('q2', RX, 30, [['x = ' + cellv(x), 'good'], ['steps: ' + ops, 'strong'], ['generic: about 2^' + f1(rb), 'muted']], 17, 32)], { phase: 'done' });
    for (const f of F.list) f.narrowView = f.meta.phase === 'digit' && perDigit ? { x: RX - 20, y: -40, w: 360, h: 520 } : { x: -20, y: -40, w: 560, h: 520 };
    return { frames: P.fix(F.list, view), def: def3() };
  }
  function def3() {
    return P.def('Pohlig–Hellman', ['n = q₁^e₁ ··· q_r^e_r, g of order n, h = g^x', 'for each q^e: γ = g^(n/q), of order q', '  digit k: t = (h·g^(−x so far))^(n/q^(k+1)) = γ^d', '  x mod q^e = d₀ + d₁q + … + d_(e−1)q^(e−1)', 'then x mod n by the Chinese remainder theorem', 'cost: about Σ e·(√q or q), set by the largest q']);
  }
})(globalThis.Sifer = globalThis.Sifer || {});
