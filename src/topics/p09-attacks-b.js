// Part 9, computing discrete logarithms (continued): index calculus on a small prime (a factor base, relations from
// smooth powers, the logarithms of the small primes by linear algebra, and one more relation that brings in h), and
// the small-subgroup attack on a static Diffie–Hellman secret, with the safe prime that leaves it nothing to find.
(function (S) {
  'use strict';
  const P = S.PK, NT = () => S.NT, DLP = () => S.DLP;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const H = () => S.P09B;
  const sh = (v) => P.n(v);
  const f1 = (x) => (Math.round(x * 10) / 10).toFixed(1);

  // ---------------------------------------------------------------------------------------------------------------
  // Index calculus
  // ---------------------------------------------------------------------------------------------------------------
  const factorText = (base, exps) => base.map((q, i) => (exps[i] ? String(q) + (exps[i] > 1n ? P.sup(exps[i]) : '') : '')).filter(Boolean).join('·');
  const smoothOver = (base, v) => { const e = base.map(() => 0n); let m = B(v); base.forEach((q, i) => { while (m % q === 0n) { m /= q; e[i]++; } }); return m === 1n ? e : null; };
  S.topic({
    id: 'p09-index', family: 'p09-attacks', order: 40, title: 'Index calculus',
    blurb: 'In Z_p* a number can be factored into primes, and the logarithm turns products into sums. Collect powers g^k that are smooth (made only of small primes), solve the linear equations they give for the logarithms of the small primes, then find one h·g^k that is smooth too. The work grows more slowly than any generic attack, which is why Z_p* needs primes of 2048 bits and more.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Prime', def: 'toy', options: [{ value: 'toy', label: 'toy: p below a million' }, { value: 'lab', label: 'a 28-bit prime (computed)' }, { value: 'modp', label: 'the 2048-bit MODP prime' }] },
      { id: 'p', kind: 'bigint', label: 'Prime p (toy)', def: '10007', check: (v) => H().primeIn(1009, 1000003, 'p')(v) },
      { id: 'h', kind: 'bigint', label: 'Target h', def: '2026', check: (v, inp) => { let h; try { h = B(String(v).trim()); } catch (e) { return 'h: a whole number'; } return inp.size === 'toy' && !H().primeIn(1009, 1000003, 'p')(inp.p) && (h < 2n || h >= B(inp.p)) ? 'h: from 2 to p − 1' : null; } },
      { id: 'bound', kind: 'number', label: 'Factor base: primes up to', def: 13, min: 5, max: 47 },
      { id: 'seed', kind: 'number', label: 'Seed', def: 3, min: 1, max: 9999 },
    ],
    presets: [
      { label: 'p = 10007, primes up to 13', values: { size: 'toy', p: '10007', h: '2026', bound: 13, seed: 3 } },
      { label: 'p = 1019, primes up to 7', values: { size: 'toy', p: '1019', h: '777', bound: 7, seed: 2 } },
      { label: 'p = 100003, primes up to 19', values: { size: 'toy', p: '100003', h: '31337', bound: 19, seed: 5 } },
      { label: 'Another draw of relations', values: { size: 'toy', p: '10007', h: '2026', bound: 13, seed: 8 } },
      { label: 'A 28-bit prime', values: { size: 'lab', bound: 47, seed: 4 } },
      { label: 'The 2048-bit MODP prime', values: { size: 'modp', seed: 5 } },
    ],
    counters: [{ id: 'rel', label: 'relations' }, { id: 'known', label: 'logarithms known' }],
    run(inp) { return P.memo('p09-index', inp, () => indexCalc(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'relation' && f.meta.first, pick: 'option', ask: (fr, i) => `How many unknowns does the system have?`, options: (fr, i) => { const b = fr[i].facts.nb; return [...new Set([String(b), String(b + 1), String(fr[i].facts.bound), '1'])].sort((a, c) => a - c); }, answer: (fr, i) => String(fr[i].facts.nb), explain: (fr, i) => `One unknown for each prime in the factor base: their logarithms. So at least ${fr[i].facts.nb} independent relations are needed.` },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'final', pick: 'option', ask: (fr, i) => { const k = fr[i + 1].facts; return `h·g^${k.k} = ${k.v} = ${k.fac}. Which formula gives log_g(h)?`; }, options: () => ['Σ e_i·log_g(p_i) − k', 'Σ e_i·log_g(p_i) + k', 'Π log_g(p_i)^e_i − k', 'k − Σ e_i'], answer: () => 'Σ e_i·log_g(p_i) − k', explain: (fr, i) => 'Take logarithms of h·g^k = Π p_i^e_i: log h + k = Σ e_i·log p_i (mod p − 1).' },
    ],
    quiz: [
      { q: 'What makes a relation useful in index calculus?', options: ['g^k mod p factors completely over the small primes', 'g^k is prime', 'k is small', 'g^k is a square'], answer: 0, why: 'Then log g^k = k is a sum of the unknown logarithms of the small primes: one linear equation.' },
      { q: 'The equations are solved modulo…', options: ['p', 'p − 1, the order of g', '2', 'the bound B'], answer: 1, why: 'Exponents of g live modulo its order p − 1.' },
      { q: 'Why does the same attack not work on elliptic curves?', options: ['Points cannot be factored into small points the way integers factor into primes', 'Curves are too small', 'Curves have no generator', 'It works just as well'], answer: 0, why: 'There is no notion of a smooth point; only generic methods (rho) apply, so 256-bit curves suffice where Z_p* needs 2048-bit and more.' },
      { q: 'A larger factor base…', options: ['makes smooth values more common but needs more relations', 'always helps', 'always hurts', 'changes nothing'], answer: 0, why: 'That trade-off is what gives the subexponential running time, balanced at the best bound.' },
    ],
  });

  function indexCalc(inp) {
    const F = new S.Frames(['rel', 'known']);
    const view = { x: -20, y: -50, w: 900, h: 620 }, FX = 520;
    const add = (say, facts, items, meta) => F.add({ items, say, facts, meta: meta || {} });
    if (inp.size === 'modp') {
      const G = P.modp14(), gb = P.gnfsBits(2048), qb = NT().bitLength(G.order), rb = P.rhoBits(qb) + 0.5;
      const vals = H().vals('v', 0, 30, [['p', G.p]], 340);
      const rows = [['index calculus (number field sieve)', 'about 2^' + f1(gb)], ['generic (rho) on the 2047-bit order', 'about 2^' + f1(rb)]];
      const tb = S.Kit.table.draw({ prefix: 'tc', x: 0, y: 110, colHead: ['method', 'work'], rows, size: 15, hot: [[0, 1]] });
      add(`For the 2048-bit MODP prime the same idea, refined into the number field sieve, costs about 2^${f1(gb)} operations (the L[1/3] estimate without its smaller terms), against about 2^${f1(rb)} for rho on the ${qb}-bit order. Index calculus is why Z_p* needs a 2048-bit prime for roughly 112-bit security, while a curve, which has no smooth points, needs only 224 bits.`, { gb: f1(gb), rb: f1(rb), qb, pbits: NT().bitLength(G.p) }, [P.title('h', 0, -10, 'At real size'), ...vals, ...tb.items], { phase: 'cost' });
      add(`The pieces stay the same: a factor base, relations from smooth numbers, linear algebra modulo p − 1, and one last relation with h. What changes is how the smooth numbers are found: sieving over a number field instead of trying random powers.`, { gb: f1(gb), pbits: NT().bitLength(G.p) }, [P.title('h', 0, -10, 'At real size'), ...vals, ...tb.items, ...P.eqs('q', 0, 260, [['1. factor base of small primes', 'strong'], ['2. relations: smooth values', 'strong'], ['3. linear algebra mod p − 1', 'strong'], ['4. one relation with h', 'strong']], 16, 30)], { phase: 'steps' });
      return { frames: P.fix(F.list, view), def: def4() };
    }
    let p, g, h, bound = inp.bound;
    if (inp.size === 'toy') { p = B(inp.p); g = DLP().groupZp(p).generator; h = B(inp.h); }
    else { const L = DLP().labs.indexCalculus(inp.seed, { bits: 28 }); p = L.public.p; g = L.public.g; h = L.public.h; }
    const r = H().seeded(inp.seed, () => DLP().attack.indexCalculus(p, g, h, { bound, extra: 4 }));
    if (r.x === null) throw new Error('no solution with this factor base: try a larger bound');
    const base = r.factorBase, nb = base.length, n = p - 1n, rels = r.relations;
    const relRows = (upto, lit) => rels.slice(0, upto).map((rl) => [rl.k, NT().pow(g, rl.k, p), '= ' + factorText(base, rl.exps)]);
    const relT = (upto, lit) => H().tab({ prefix: 'tr', x: 0, y: 30, colHead: ['k', 'g^k mod p', 'factored'], rows: relRows(upto), maxRows: 9, focus: lit === undefined ? undefined : [lit, 2], act: lit === undefined ? [] : [[lit, 0], [lit, 1], [lit, 2]], size: 14, ch: 34, minW: 70 });
    const baseT = (logs, lit) => H().tab({ prefix: 'tf', x: FX, y: 30, colHead: ['prime', 'log_g'], rows: base.map((q, i) => [String(q), logs ? logs[i] : '?']), maxRows: 9, hot: lit === undefined ? [] : [[lit, 0], [lit, 1]], act: logs ? base.map((q, i) => [i, 1]) : [], size: 14, ch: 34, minW: 70 });
    const head = (t) => [P.title('h1', 0, -10, t || 'Relations: smooth powers of g'), P.title('h2', FX, -10, 'Factor base')];
    const eqY = 30 + 34 + 34 * Math.min(Math.max(rels.length, nb), 9) + 40;
    const eqs = (lines) => P.eqs('q', 0, eqY, lines, 16, 30);
    add(`Solve g^x = h in Z_${p}* with g = ${g} and h = ${h}. The factor base is the ${nb} primes up to ${bound}: ${P.list(base.map(String))}. Their logarithms are the unknowns.`, { p, g, h, nb, bound, base }, [...head(), ...baseT(null).items], { phase: 'start' });
    const shown = Math.min(4, rels.length);
    for (let i = 0; i < shown; i++) {
      const rl = rels[i], v = NT().pow(g, rl.k, p), fac = factorText(base, rl.exps);
      const lin = base.map((q, j) => (rl.exps[j] ? (rl.exps[j] > 1n ? rl.exps[j] + '·' : '') + 'L' + P.sub(q) : '')).filter(Boolean).join(' + ');
      F.set('rel', i + 1);
      add(`g^${rl.k} mod ${p} = ${v} = ${fac}: only small primes, so it is smooth. Taking logarithms, ${rl.k} ≡ ${lin} (mod ${n}), where L${P.sub(base[0])} stands for log_g(${base[0]}), and so on.`, { k: rl.k, v, fac, n, p, exps: rl.exps, nb, bound, base }, [...head(), ...relT(i + 1, i).items, ...baseT(null).items, ...eqs([[rl.k + ' ≡ ' + lin + '  (mod ' + n + ')', 'act'], ['most powers are not smooth and are thrown away', 'muted']])], { phase: 'relation', first: i === 0 });
    }
    F.set('rel', rels.length);
    add(`Keep drawing random k: ${rels.length} smooth powers in all, ${rels.length} equations for ${nb} unknowns, a few more than needed so the system has full rank.`, { rels: rels.length, nb }, [...head(), ...relT(rels.length).items, ...baseT(null).items, ...eqs([[rels.length + ' equations, ' + nb + ' unknowns, modulo ' + n, 'strong']])], { phase: 'all' });
    F.set('known', nb);
    const L2 = r.logs[0], chk = NT().pow(g, L2, p);
    add(`Gaussian elimination modulo ${n} (prime power by prime power, then the CRT) gives every logarithm: log_g(${base[0]}) = ${L2}, and indeed g^${L2} = ${chk}. The small primes are now known.`, { n, p, L2, chk, q0: base[0], logs: r.logs }, [...head(), ...relT(rels.length).items, ...baseT(r.logs, 0).items, ...eqs([['g^' + L2 + ' mod ' + p + ' = ' + chk, 'good']])], { phase: 'solve' });
    const sv = r.trace.find((t) => t.kind === 'solve'), k = B(sv.k), x = r.x, v = NT().mod(h * NT().pow(g, k, p), p), exps = smoothOver(base, v), fac = factorText(base, exps);
    const sum = base.map((q, i) => (exps[i] ? (exps[i] > 1n ? exps[i] + '·' : '') + r.logs[i] : '')).filter(Boolean).join(' + ');
    add(`Now bring in h: try h·g^k for random k until one is smooth. h·g^${k} mod ${p} = ${v} = ${fac}.`, { k, v, fac, p }, [...head('The last relation'), ...relT(rels.length).items, ...baseT(r.logs).items, ...eqs([['h·g^' + k + ' = ' + v + ' = ' + fac, 'act']])], { phase: 'final' });
    const ok = NT().pow(g, x, p) === NT().mod(h, p);
    add(`So log_g(h) + ${k} ≡ ${sum} (mod ${n}), and x = ${x}. Check: g^${x} mod ${p} = ${NT().pow(g, x, p)} = h.`, { k, sum, n, p, x, check: NT().pow(g, x, p), logs: r.logs, exps, ok }, [...head('The last relation'), ...relT(rels.length).items, ...baseT(r.logs).items, ...eqs([['x + ' + k + ' ≡ ' + sum, 'act'], ['x = ' + x, 'good']])], { phase: 'done' });
    const gb = P.gnfsBits(2048), rb = P.rhoBits(2047) + 0.5;
    add(`At real size the same idea, as the number field sieve, costs about 2^${f1(gb)} for a 2048-bit prime, far less than the 2^${f1(rb)} of a generic attack. That is why Z_p* needs a 2048-bit prime where an elliptic curve, with no smooth points to collect, needs only about 224 bits.`, { gb: f1(gb), rb: f1(rb), pbits: NT().bitLength(P.modp14().p) }, [...head('The last relation'), ...relT(rels.length).items, ...baseT(r.logs).items, ...eqs([['x = ' + x, 'good'], ['2048-bit p: about 2^' + f1(gb) + ', not 2^' + f1(rb), 'bad']])], { phase: 'cost' });
    for (const f of F.list) f.narrowView = { x: -20, y: -50, w: 520, h: 620 };
    return { frames: P.fix(F.list, view), def: def4() };
  }
  function def4() {
    return P.def('Index calculus in Z_p*', ['factor base: the primes q ≤ B; unknowns L_q = log_g(q)', 'relation: g^k mod p = Π q^e_q (smooth)', '  ⇒ k ≡ Σ e_q·L_q (mod p − 1)', 'solve the linear system for every L_q', 'last: h·g^k = Π q^e_q ⇒ x ≡ Σ e_q·L_q − k', 'subexponential: L_p[1/3] with the number field sieve']);
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Small subgroups and safe primes
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p09-small-subgroup', family: 'p09-attacks', order: 50, title: 'Small subgroups and safe primes',
    blurb: 'A server keeps one Diffie–Hellman secret x and raises whatever it receives to x without checking it. If p − 1 has small prime factors q, an element of order q gets an answer that can only be one of q values, and so says something about x mod q. Enough small factors, and together they give x away. The defences: a safe prime p = 2q + 1 or a prime-order subgroup, and a check on every received value.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Prime', def: 'toy', options: [{ value: 'toy', label: 'toy: p − 1 = 2·(small primes)' }, { value: 'modp', label: 'the 2048-bit MODP safe prime' }] },
      { id: 'k', kind: 'number', label: 'Small odd primes in p − 1', def: 5, min: 3, max: 6 },
      { id: 'cap', kind: 'number', label: 'Each below', def: 50, min: 20, max: 100 },
      { id: 'seed', kind: 'number', label: 'Seed', def: 7, min: 1, max: 9999 },
    ],
    presets: [
      { label: 'Five small primes', values: { size: 'toy', k: 5, cap: 50, seed: 7 } },
      { label: 'Three primes below 30', values: { size: 'toy', k: 3, cap: 30, seed: 2 } },
      { label: 'Six primes below 100', values: { size: 'toy', k: 6, cap: 100, seed: 11 } },
      { label: 'Another server', values: { size: 'toy', k: 4, cap: 60, seed: 19 } },
      { label: 'The 2048-bit MODP safe prime', values: { size: 'modp', seed: 5 } },
    ],
    counters: [{ id: 'probes', label: 'probes sent' }],
    run(inp) { return P.memo('p09-small-subgroup', inp, () => smallSub(inp)); },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'start' && fr.some((x) => x.meta.phase === 'probe'), pick: 'option', ask: (fr, i) => `A probe of order ${fr[i].facts.q1} reaches the server. How many different answers can the server's β^x have?`, options: (fr, i) => { const q = fr[i].facts.q1; return [...new Set([String(q), String(q - 1n), "2", String(fr[i].facts.pm1)])]; }, answer: (fr, i) => String(fr[i].facts.q1), explain: (fr, i) => `β has order ${fr[i].facts.q1}, so β^x is one of β^0, …, β^${fr[i].facts.q1 - 1n}: at most ${fr[i].facts.q1} answers, and which one says x mod ${fr[i].facts.q1}.` },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'safe', pick: 'option', ask: (fr, i) => `With a safe prime p = 2q + 1, which part of x can a probe reveal cheaply?`, options: () => ['x mod 2', 'x mod q', 'all of x', 'nothing at all'], answer: () => 'x mod 2', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'An element of order 7 is sent to the server. Its answer depends on…', options: ['x mod 7 only', 'all of x', 'x mod 6', 'nothing'], answer: 0, why: 'β^x depends only on x mod 7, so the answer is one of seven values.' },
      { q: 'Which check stops the attack?', options: ['Checking that the received value lies in the intended prime-order subgroup (β^q = 1, β ≠ 1)', 'Using a longer x', 'Using a new nonce for the cipher', 'Hashing the shared secret'], answer: 0, why: 'Then every accepted element has order q, and the leak is as hard as the whole logarithm.' },
      { q: 'p = 2q + 1 with q prime. What are the possible orders of elements of Z_p*?', options: ['1, 2, q and 2q', 'any number up to p', 'only q', '2 and p'], answer: 0, why: 'Element orders divide p − 1 = 2q.' },
      { q: 'Why does a fresh secret for every exchange also defeat the attack?', options: ['Each probe then learns about a different x', 'It makes p safe', 'It hides the generator', 'It does not'], answer: 0, why: 'The residues of different secrets cannot be combined by the CRT.' },
    ],
  });

  function smallSub(inp) {
    const F = new S.Frames(['probes']);
    const view = { x: -20, y: -30, w: 900, h: 600 };
    const add = (say, facts, items, meta) => F.add({ items, say, facts, meta: meta || {} });
    const people = (lit) => [...S.Kit.pk.party({ key: 'att', x: 60, y: 30, name: 'attacker', initial: 'M', cls: 'eve' }), ...S.Kit.pk.party({ key: 'srv', x: 760, y: 30, name: 'server (keeps x)', initial: 'S', cls: lit ? 'hot' : 'bob' })];
    const msg = (beta, q) => S.Kit.pk.msg({ key: 'm1', x1: 90, x2: 730, y: 14, text: 'β = ' + H().cellv(beta) + ' (order ' + H().cellv(q) + ')', cls: 'bad' });
    const reply = () => S.Kit.pk.msg({ key: 'm2', x1: 730, x2: 90, y: 46, text: 'a message keyed by βˣ', cls: '' });
    if (inp.size === 'modp') {
      const G = P.modp14(), p = G.p, q = G.order, x = H().modpSecret(inp.seed), gfull = p - 2n;
      const oracle = (pt, t) => NT().pow(pt, x, p) === NT().pow(pt, t, p);
      const r = DLP().attack.smallSubgroup({ p, g: gfull, order: p - 1n, oracle, factors: new Map([[2n, 1], [q, 1]]), maxFactor: 100000 });
      const two = r.parts[0], qb = NT().bitLength(q), rb = P.rhoBits(qb) + 0.5;
      const vals = H().vals('v', 0, 150, [['p = 2q + 1', p], ['q, a prime', q]], 330);
      F.set('probes', 1);
      add(`The 2048-bit MODP prime is safe: p − 1 = 2·q with q a ${qb}-bit prime. The only small subgroup has order 2: it is {1, p − 1}. Sending β = p − 1 shows whether x is even or odd: here x ≡ ${two.residue} (mod 2).`, { qb, r2: two.residue, pbits: NT().bitLength(p) }, [...people(true), ...msg(p - 1n, 2n), ...reply(), ...vals, ...P.eqs('q', 380, 170, [['probe of order 2: x ≡ ' + two.residue + ' (mod 2)', 'bad'], ['the rest: order q, ' + qb + ' bits', 'good']], 16, 30)], { phase: 'safe' });
      add(`Any other element has order q or 2q, and its answer depends on x mod q: as hard as the whole logarithm, about 2^${f1(rb)} steps. One bit leaks, and a server that checks β^q = 1 (and β ≠ 1) leaks not even that.`, { rb: f1(rb) }, [...people(false), ...vals, ...P.eqs('q', 380, 170, [['x ≡ ' + two.residue + ' (mod 2): one bit', 'bad'], ['x mod q: about 2^' + f1(rb) + ' steps', 'good'], ['check β^q = 1 and β ≠ 1', 'good']], 16, 30)], { phase: 'check' });
      return { frames: P.fix(F.list, view), def: def5() };
    }
    const L = DLP().labs.smallSubgroup(inp.seed, { k: inp.k, cap: inp.cap });
    const { p, g } = L.public, x = L.secret.x;
    const r = DLP().attack.smallSubgroup(L.public);
    const fac = [...L.factors], pf = NT().fmtFactors(L.factors).replace(/\^(\d+)/g, (m, e) => P.sup(e));
    const gap = 10, cw = Math.min(118, Math.floor((860 - gap * (r.parts.length - 1)) / r.parts.length)), cy = 200;
    const cards = (state, cur) => r.parts.map((pt, i) => {
      const lines = ['order ' + pt.q, 'x mod ' + pt.q, state === 'leak' || i === cur ? 'leaks' : '?'];
      return { key: 'c' + i, kind: 'state', x: cw / 2 + i * (cw + gap), y: cy, w: cw, h: 86, rx: 8, lines, cls: 'block val3 ' + (i === cur ? 'hot' : state === 'leak' ? 'bad' : 'soft') };
    });
    const head = [P.t('h', 0, cy - 58, 'One small subgroup for each prime factor of p − 1', 'strong', 'start', 15)];
    const q1 = r.parts[1] ? r.parts[1].q : r.parts[0].q;
    add(`The server's prime is p = ${p}, and p − 1 = ${pf}: nothing but small primes. Its secret x stays fixed, and it raises anything it receives to x without a check.`, { p, pf, q1, pm1: p - 1n, factors: fac }, [...people(false), ...head, ...cards('')], { phase: 'start' });
    const pt1 = r.parts[1] || r.parts[0], i1 = r.parts.indexOf(pt1), beta1 = NT().pow(g, (p - 1n) / pt1.q, p);
    F.set('probes', 1);
    add(`The weakness: β = ${beta1} has order ${pt1.q}. The server's answer is keyed by β^x, and β^x depends only on x mod ${pt1.q}, so it is one of just ${pt1.q} values: the answer itself says what x mod ${pt1.q} is. An unchecked value of small order is a question about the secret.`, { q: pt1.q, beta: beta1 }, [...people(true), ...msg(beta1, pt1.q), ...reply(), ...head, ...cards('', i1)], { phase: 'probe', q: pt1.q });
    F.set('probes', r.parts.length);
    const xr = r.secret, ok = xr === x;
    add(`The outcome: one such question for each of the ${r.parts.length} small factors of p − 1, and the pieces together determine x completely, since their product is p − 1 itself. This recovers the server's long-term secret.`, { parts: r.parts.length, ok }, [...people(false), ...head, ...cards('leak'), ...P.eqs('q', 60, cy + 90, [['outcome: the secret x is recovered', 'bad']], 17, 32)], { phase: 'crt', ok });
    // the same size, a safe prime
    const bits = NT().bitLength(p), sp = H().seeded(inp.seed + 100, () => NT().randomSafePrime(bits)), Q = sp.q;
    const safeCards = [['order 2', 'β = ' + (sp.prime - 1n), 'x mod 2: cheap', 'bad'], ['order ' + Q, 'βˣ: ' + Q + ' values', 'x mod q: hard', 'good']].map(([a, b, c, cls], i) => ({ key: 's' + i, kind: 'state', x: 60 + 90 + i * 260, y: cy + 210, w: 230, h: 86, rx: 8, lines: [a, b, c], cls: 'block val3 ' + cls }));
    add(`Now a safe prime of the same size: p = ${sp.prime} = 2·${Q} + 1 with ${Q} prime. Element orders divide 2·${Q}, so the only small probe has order 2 and reveals x mod 2. The other piece is x mod ${Q}, a logarithm in a group of prime order ${Q}: no shortcut.`, { sp: sp.prime, Q, bits }, [...people(false), ...head, ...cards(''), P.t('h2', 60, cy + 154, 'With a safe prime p = 2q + 1', 'strong', 'start', 15), ...safeCards], { phase: 'safe' });
    add(`At real size the 2048-bit MODP prime is safe in the same way. The fixes: use a safe prime or a prime-order subgroup, check that a received β satisfies β^q = 1 and β ≠ 1, or use a fresh secret for every exchange.`, { bits, pbits: NT().bitLength(P.modp14().p) }, [...people(false), ...head, ...cards(''), P.t('h2', 60, cy + 154, 'With a safe prime p = 2q + 1', 'strong', 'start', 15), ...safeCards], { phase: 'fix' });
    const idxOf = (q) => r.parts.findIndex((pt) => pt.q === q);
    for (const f of F.list) {
      if (f.meta.phase === 'safe' || f.meta.phase === 'fix') f.narrowView = { x: 40, y: cy + 120, w: 560, h: 260 };
      else if (f.meta.phase === 'probe') { const c = cw / 2 + idxOf(f.meta.q) * (cw + gap); const x0 = Math.max(-20, Math.min(880 - 420, c - 210)); f.narrowView = { x: x0, y: -30, w: 420, h: 290 }; }
      else f.narrowView = { x: -20, y: -30, w: 900, h: 400 };
    }
    return { frames: P.fix(F.list, view), def: def5() };
  }
  function def5() {
    return P.def('Small subgroups', ['the server computes β^x for any β it receives', 'β of small order q: β^x depends on x mod q only', 'small factors covering p − 1: x is exposed', 'safe prime p = 2q + 1: only x mod 2 leaks', 'defence: check 1 < β < p − 1 and β^q = 1; or fresh secrets']);
  }
})(globalThis.Sifer = globalThis.Sifer || {});
