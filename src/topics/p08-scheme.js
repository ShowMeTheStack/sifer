// Part 8, the RSA scheme: key generation (random candidates, small-prime sieving, Miller–Rabin traced round by round,
// then n, φ, d by the extended Euclidean algorithm and the CRT values), encryption and decryption of a message, and why
// decryption undoes encryption (the powers of m run round a cycle whose length divides φ(n)).
(function (S) {
  'use strict';
  const P = S.PK, B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const A = (S.P08A = S.P08A || {});
  const NT = () => S.NT;
  const n$ = (v) => P.n(v);
  const fmt = (v, max) => S.Kit.pk.fmt(B(v), { max: max || 18 }).text;
  /** a labelled value block, left-aligned at x */
  A.val = (key, x, y, label, value, cls, o) => S.Kit.pk.value(Object.assign({ key, x, y, label, value: B(value), cls, anchor: 'start', max: 20 }, o || {}));
  /** a readout row: a label (right-aligned at x + lw) and the value in a cell after it; long values open on a click */
  A.row = (key, x, y, label, value, cls, o) => {
    o = o || {};
    const lw = o.lw || 150, w = o.w || 250, f = S.Kit.pk.fmt(B(value), { max: o.max || 18 });
    const it = { key, kind: 'cell', x: x + lw + 10, y, w, h: 34, rx: 6, text: f.text + (f.long ? ' · ' + f.bits + ' bits' : ''), size: 13, cls: 'mono ' + (cls || '') + (f.long ? ' pk-long' : ''), title: label + ' = ' + f.full + (f.long ? ' (' + f.digits + ' digits, ' + f.bits + ' bits)' : '') };
    return [P.t(key + ':l', x + lw, y + 22, label, 'strong', 'end', 14), it];
  };
  /** our toy keys: small primes that work with e = 3, 17 and 65537 */
  A.TOY = { p: 4409n, q: 3011n };
  A.TOY2 = { p: 52067n, q: 40013n };
  A.key = (name, e) => (name === 'toy' ? S.RSA.fromPrimes(A.TOY.p, A.TOY.q, B(e || 65537)) : name === 'toy2' ? S.RSA.fromPrimes(A.TOY2.p, A.TOY2.q, B(e || 65537)) : P.rsaKey(name, e));
  A.KEYS = [{ value: 'toy', label: 'toy: 4409 · 3011' }, { value: 'rsa1024', label: 'RSA-1024' }, { value: 'rsa2048', label: 'RSA-2048' }];
  A.textNum = (s) => NT().fromBytes(new TextEncoder().encode(s));
  A.numText = (v) => { try { return new TextDecoder('utf-8', { fatal: true }).decode(NT().toBytes(v)); } catch (e) { return null; } };

  // ---------------------------------------------------------------------------------------------------------------
  // Key generation
  // ---------------------------------------------------------------------------------------------------------------
  const KIND = { small: 'divisible by a small prime', witness: 'the Miller–Rabin test finds a witness', prime: 'it is prime' };
  /** the search, replayed: every candidate in order with what became of it, and the key */
  function search(bits, e, seed) {
    return S.RSA.seeded(seed, () => {
      const gen = S.RSA.keygenSteps(bits, { e }), ys = [];
      let r;
      for (;;) { r = gen.next(); if (r.done) break; ys.push(r.value); }
      const key = r.value, ends = { p: [], q: [] };
      for (const s of key.trace) if (s.kind === 'reject' || s.kind === 'prime') ends[s.phase].push({ kind: s.kind, prime: s.prime });
      // the yields of one prime search count tried = 1, 2, …; a reset means the run before ended at a prime
      const out = { p: [], q: [] };
      for (const ph of ['p', 'q']) {
        const mine = ys.filter((y) => y.phase === ph);
        let run = 0;
        mine.forEach((y, i) => {
          if (i && y.tried <= mine[i - 1].tried) { const end = ends[ph][run++]; if (end) out[ph].push({ candidate: end.prime, kind: end.kind === 'reject' ? 'reject' : 'prime' }); }
          out[ph].push({ candidate: y.candidate, kind: y.outcome.kind, by: y.outcome.by });
        });
        const last = ends[ph][ends[ph].length - 1];
        out[ph].push({ candidate: last.prime, kind: 'prime', final: true });
      }
      // the primes found, in the order searched (keygenSteps puts the larger first as p)
      out.pFound = out.p[out.p.length - 1].candidate; out.qFound = out.q[out.q.length - 1].candidate;
      return { key, list: out };
    });
  }

  S.topic({
    id: 'p08-keygen', family: 'p08-scheme', order: 10, title: 'RSA key generation',
    blurb: 'Draw random odd numbers of the right size, throw out those with a small factor, and test the rest with Miller–Rabin until two primes turn up. Then n = p·q, φ(n) = (p − 1)(q − 1), and d is the inverse of e modulo φ(n), found by the extended Euclidean algorithm.',
    inputs: [
      { id: 'bits', kind: 'choice', label: 'Key size', def: '24', options: [{ value: '16', label: '16 bits (toy)' }, { value: '24', label: '24 bits (toy)' }, { value: '40', label: '40 bits' }, { value: '512', label: '512 bits' }, { value: '1024', label: '1024 bits' }, { value: '2048', label: '2048 bits' }] },
      { id: 'e', kind: 'choice', label: 'Public exponent e', def: '65537', options: [{ value: '3', label: '3' }, { value: '17', label: '17' }, { value: '65537', label: '65537' }] },
      { id: 'seed', kind: 'number', label: 'Random seed', def: 7, min: 1, max: 99999 },
    ],
    check: (inp) => (inp.bits === '16' && inp.e === '65537' ? 'A 16-bit key is too small for e = 65537 (e must be below φ(n)): choose e = 3 or 17, or a larger key' : null),
    presets: [
      { label: 'A 24-bit toy key', values: { bits: '24', e: '65537', seed: 7 } },
      { label: '16 bits, e = 3 (some primes rejected)', values: { bits: '16', e: '3', seed: 12 } },
      { label: 'A 40-bit key, e = 17', values: { bits: '40', e: '17', seed: 3 } },
      { label: 'A real RSA-1024 key', values: { bits: '1024', e: '65537', seed: 2026 } },
      { label: 'A real RSA-2048 key', values: { bits: '2048', e: '65537', seed: 11 } },
    ],
    counters: [{ id: 'cands', label: 'candidates drawn' }, { id: 'mr', label: 'Miller–Rabin tests run' }],
    run(inp) {
      const bits = +inp.bits, e = B(inp.e), seed = inp.seed;
      const { key, list } = P.memo('p08-keygen', inp, () => search(bits, e, seed));
      const F = new S.Frames(['cands', 'mr']);
      const half = bits >> 1, L = 0, Rx = 470, view = { x: -20, y: -10, w: 880, h: 560 };
      const heads = () => [P.title('h1', L, 14, 'The search'), P.title('h2', Rx, 14, 'What it found')];
      const table = (ph, upto, lit) => {
        const rows = list[ph].slice(0, upto + 1), from = Math.max(0, rows.length - 8), shown = rows.slice(from);
        const tb = S.Kit.table.draw({ prefix: 'tb', x: L, y: 34, colHead: ['#', ph + ' candidate', 'test'], rows: shown.map((a, i) => [String(from + i + 1), fmt(a.candidate, 20), a.kind === 'small' ? '÷ ' + a.by : a.kind === 'witness' ? 'witness ' + fmt(a.by, 6) : a.kind === 'reject' ? 'prime, rejected' : 'prime']), size: 14, mono: true, cls: (r, c) => (c === 2 ? (shown[r].kind === 'prime' ? 'good' : shown[r].kind === 'reject' ? 'hot' : 'muted') : r === shown.length - 1 && lit ? 'act' : '') });
        return tb.items;
      };
      const candPanel = (a, i) => {
        const lines = [[`candidate ${i + 1}`, 'muted'], [fmt(a.candidate, 24), 'strong']];
        if (a.kind === 'small') lines.push([`= ${a.by} · ${fmt(a.candidate / B(a.by), 20)}`, 'bad'], ['composite: a small factor', 'bad']);
        else if (a.kind === 'witness') lines.push(['no factor below 2000', ''], [`base ${fmt(a.by, 10)} is a witness`, 'bad'], ['composite', 'bad']);
        else if (a.kind === 'reject') lines.push(['passes Miller–Rabin: prime', 'good'], [`but ${e} divides p − 1`, 'bad'], ['rejected: draw again', 'bad']);
        else lines.push(['no factor below 2000', ''], ['passes every Miller–Rabin round', 'good'], ['p is prime', 'good']);
        return P.eqs('cp', Rx, 64, lines, 17, 32);
      };
      let cands = 0, mr = 0;
      const tally = (a) => { cands++; if (a.kind !== 'small') mr++; F.set('cands', cands).set('mr', mr); };
      const add = (items, say, facts, meta) => F.add({ items: heads().concat(items), say, facts, meta });
      add([P.eqs('st', Rx, 60, [[`key size ${bits} bits`, 'strong'], [`two primes of ${half} bits each`], [`e = ${e}`, 'key']], 17)].flat(),
        `Make ${P.an(bits)}-bit key: two random ${half}-bit primes p and q, each with gcd(e, prime − 1) = 1 for e = ${e}. Candidates are odd ${half}-bit numbers with the top two bits set, so that p·q has exactly ${bits} bits.`, { bits, half, e }, { phase: 'start' });
      // the search for p
      const steps = list.p.length, detail = steps <= 9 ? steps : 6;
      for (let i = 0; i < steps; i++) {
        const a = list.p[i];
        tally(a);
        if (i >= detail - 1 && i < steps - 1) continue;
        if (i === steps - 1 && steps > detail) {
          add(table('p', i, true).concat(candPanel(a, i)), `${steps - detail} more candidates fail in the same ways. Candidate ${i + 1}, ${n$(a.candidate)}, is the first to pass every test: p = ${n$(a.candidate)}. On average about ${Math.round(half * Math.LN2 / 2)} odd candidates are needed for ${P.an(half)}-bit prime.`,
            { i: i + 1, skipped: steps - detail, p: a.candidate, expect: Math.round(half * Math.LN2 / 2), half }, { phase: 'cand', kind: a.kind, i });
          continue;
        }
        const s = a.kind === 'small' ? `Candidate ${i + 1}: ${n$(a.candidate)} is divisible by ${a.by}. Trial division by the primes below 2000 throws most candidates out before any expensive test.`
          : a.kind === 'witness' ? `Candidate ${i + 1}: ${n$(a.candidate)} has no small factor, but the base ${n$(a.by)} is a witness in the Miller–Rabin test: ${n$(a.candidate)} is composite.`
            : a.kind === 'reject' ? `Candidate ${i + 1}: ${n$(a.candidate)} is prime, but p − 1 shares the factor ${e} with e, so e would have no inverse: draw again.`
              : `Candidate ${i + 1}: ${n$(a.candidate)} passes every Miller–Rabin round: p = ${n$(a.candidate)}.`;
        add(table('p', i, true).concat(candPanel(a, i)), s, { i: i + 1, c: a.candidate, by: a.by, e }, { phase: 'cand', kind: a.kind, i });
      }
      // Miller–Rabin on p, traced
      const p0 = list.pFound, bases = [2n, 3n, 5n, 7n].filter((b) => b < p0 - 1n).slice(0, bits >= 512 ? 3 : 4);
      const mrP = NT().millerRabin(p0, bases);
      const mrLines = (r, name) => {
        const out = [[`${name} − 1 = 2${P.sup(r.s)} · ${fmt(r.d, 16)}`, 'strong']];
        r.rounds.forEach((rd) => out.push([`a = ${rd.a}: ${rd.x.map((x) => (x === p0 - 1n || x === r.n - 1n ? '−1' : fmt(x, 12))).join(' → ')}  ${rd.verdict === 'pass' ? '✓' : '✗'}`, rd.verdict === 'pass' ? 'good' : 'bad']));
        return out;
      };
      mrP.n = p0;
      add(table('p', steps - 1, false).concat(P.eqs('mr', Rx, 60, mrLines(mrP, 'p').concat([['', ''], ['each base: a^d, then square up to s − 1 times', 'muted'], ['a prime must reach 1 at a^d or pass −1 on the way', 'muted']]), 15, 30)),
        `Miller–Rabin on p: p − 1 = 2^${mrP.s}·${n$(mrP.d)} with the second factor d odd. For each base a, compute a^d and square it at most ${P.plural(mrP.s - 1, 'more time')}; a prime must start at 1 or meet −1 on the way. ${P.plural(mrP.rounds.length, 'base')} (${P.list(bases.map(String))}) all pass, so p is prime, or composite with probability below 4^−${mrP.rounds.length}.`,
        { s: mrP.s, d: mrP.d, s1: mrP.s - 1, rounds: mrP.rounds.length, bases }, { phase: 'mr' });
      const wit = list.p.concat(list.q).find((a) => a.kind === 'witness');
      if (wit) {
        const w = NT().millerRabin(wit.candidate, [wit.by]); w.n = wit.candidate;
        const last = w.rounds[0].x[w.rounds[0].x.length - 1];
        add(table('p', steps - 1, false).concat(P.eqs('mr', Rx, 60, [[`a composite: ${fmt(wit.candidate, 18)}`, 'strong']].concat(mrLines(w, 'c')), 15, 30)),
          `Compare a composite candidate, ${n$(wit.candidate)}: with base ${n$(wit.by)} the sequence ${last === 1n ? 'reaches 1 without passing −1, a square root of 1 that no prime allows' : 'never meets −1'}, so ${n$(wit.by)} is a witness and the number is certainly composite.`,
          { c: wit.candidate, a: wit.by, s: w.s }, { phase: 'witness' });
      }
      // q, in one look
      for (const a of list.q) tally(a);
      const q0 = list.qFound;
      add(table('q', list.q.length - 1, false).concat(A.row('v0', Rx - 50, 46, 'p', p0, 'key'), A.row('v1', Rx - 50, 92, 'q', q0, 'key')),
        `The same search for q takes ${P.plural(list.q.length, 'candidate')}: q = ${n$(q0)}. In all ${cands} candidates were drawn and only ${mr} of them needed Miller–Rabin.`,
        { q: q0, nq: list.q.length, cands, mr }, { phase: 'q' });
      // the derivation
      const { n, phi, d, dp, dq, qinv } = key, pk = key.p, qk = key.q;
      const col = (upto, extra) => {
        const rows = [['p', pk, 'key'], ['q', qk, 'key'], ['n = p·q', n, 'good'], ['φ(n) = (p − 1)(q − 1)', phi, 'key'], ['e', e, 'good'], ['d = e⁻¹ mod φ(n)', d, 'key'], ['dp = d mod (p − 1)', dp, 'key'], ['dq = d mod (q − 1)', dq, 'key'], ['qinv = q⁻¹ mod p', qinv, 'key']];
        return rows.slice(0, upto).flatMap(([l, v, c], i) => A.row('v' + i, Rx - 50, 46 + i * 46, l, v, (extra && extra[i]) || c));
      };
      const swap = pk !== p0 ? ' (the larger prime is called p)' : '';
      add(col(3, { 2: 'act' }), `n = p·q = ${n$(pk)}·${n$(qk)} = ${n$(n)}${swap}, a ${bits}-bit modulus. n is public; its factors are the secret.`, { p: pk, q: qk, n, bits }, { phase: 'n' });
      add(col(4, { 3: 'act' }), `φ(n) = (p − 1)(q − 1) = ${n$(pk - 1n)}·${n$(qk - 1n)} = ${n$(phi)}: the number of units modulo n. Without p and q nobody knows of a way to find it.`, { phi, pm: pk - 1n, qm: qk - 1n }, { phase: 'phi' });
      const g = NT().gcd(e, phi);
      add(col(5, { 4: 'act' }), `e = ${e} must share no factor with φ(n): gcd(${e}, ${n$(phi)}) = ${g}. That is why the search insisted on gcd(e, p − 1) = gcd(e, q − 1) = 1.`, { e, g, phi }, { phase: 'e' });
      const eg = NT().egcd(phi, e), dEg = NT().mod(eg.y, phi);
      const egRows = eg.rows.filter((r) => r.r !== 0n);
      const egT = S.Kit.table.draw({ prefix: 'eg', x: L, y: 34, colHead: ['row', 'r', 'quotient', 't'], rows: egRows.map((r) => [String(r.i), fmt(r.r, 14), r.q === null ? '' : fmt(r.q, 14), (r.t < 0n ? '−' : '') + fmt(r.t < 0n ? -r.t : r.t, 14)]), size: 13, mono: true, maxRows: 9, focus: [egRows.length - 1, 0], act: [[egRows.length - 1, 3]] });
      add(egT.items.concat(col(6, { 5: 'act' })), `d is the inverse of e modulo φ(n). The extended Euclidean algorithm on (φ(n), e) takes ${P.plural(egRows.length, 'row')}; the last non-zero remainder is 1 = φ(n)·s + e·t with t = ${n$(eg.y)}, so d = t mod φ(n) = ${n$(d)} and e·d ≡ 1 (mod φ(n)).`,
        { rows: egRows.length, t: eg.y, d, dEg }, { phase: 'd' });
      add(egT.items.concat(col(9, { 6: 'act', 7: 'act', 8: 'act' })), `For decryption by the Chinese remainder theorem keep three more numbers: dp = ${n$(dp)}, dq = ${n$(dq)} and qinv = ${n$(qinv)}. They are half the size of d and n.`, { dp, dq, qinv }, { phase: 'crt' });
      const pub = { 2: 'good', 4: 'good' };
      for (const i of [0, 1, 3, 5, 6, 7, 8]) pub[i] = 'key';
      add([P.panel('pubp', Rx - 14, 32, 404, 30, null)].flat().slice(0, 0).concat(col(9, pub), [P.t('lgp', L, 120, 'public key: (n, e)', 'good', 'start', 18), P.t('lgs', L, 160, 'private: p, q, φ(n), d, dp, dq, qinv', 'key', 'start', 16), P.t('lgb', L, 200, `${bits} bits of modulus, made from`, 'muted', 'start', 15), P.t('lgc', L, 224, `${cands} random candidates`, 'muted', 'start', 15)]),
        `The public key is (n, e) = (${n$(n)}, ${e}). Everything else (p, q, φ(n), d and the CRT values) stays secret: any one of p, q, φ(n) or d gives the others away.`, { n, e, cands, bits }, { phase: 'done' });
      for (const f of F.list) f.narrowView = /^(cand|q)$/.test(f.meta.phase) ? { x: -20, y: -10, w: 460, h: 470 } : f.meta.phase === 'd' && false ? null : { x: Rx - 30, y: -10, w: 420, h: 570 };
      return { frames: P.fix(F.list, view), def: P.def('RSA key generation', ['pick random odd candidates of bits/2 bits', 'discard those with a small prime factor', 'Miller–Rabin: n − 1 = 2^s·d, test a^d, a^2d, …', 'n = p·q,  φ(n) = (p − 1)(q − 1)', 'gcd(e, φ(n)) = 1,  d = e⁻¹ mod φ(n)', 'dp = d mod (p − 1), dq = d mod (q − 1), qinv = q⁻¹ mod p', 'public: (n, e);  private: d (and p, q)']) };
    },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'cand' && fr[i + 1] && fr[i + 1].meta.phase === 'cand' && fr[i + 1].facts.c !== undefined, once: true, pick: 'option', ask: (fr, i) => `The next candidate is ${P.n(fr[i + 1].facts.c)}. What becomes of it?`, options: () => [KIND.small, KIND.witness, KIND.prime], answer: (fr, i) => KIND[fr[i + 1].meta.kind === 'reject' ? 'prime' : fr[i + 1].meta.kind], explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'phi', pick: 'option', ask: 'What is φ(n) for these two primes?', options: (fr, i) => { const x = fr[i + 1].facts; return ['(p − 1)(q − 1) = ' + P.n(x.phi), 'n − 1 = ' + P.n(x.pm * x.qm + x.pm + x.qm), 'p·q = ' + P.n(x.pm * x.qm + x.pm + x.qm + 1n)]; }, answer: (fr, i) => '(p − 1)(q − 1) = ' + P.n(fr[i + 1].facts.phi), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why test candidates for small prime factors before Miller–Rabin?', options: ['It is required by the definition of RSA', 'It is far cheaper and removes most candidates', 'Miller–Rabin fails on numbers with small factors', 'It makes the primes stronger'], answer: 1, why: 'A few trial divisions throw out most odd numbers; the expensive modular exponentiations run only on the survivors.' },
      { q: 'A base a is a witness for n in the Miller–Rabin test. What follows?', options: ['n is certainly composite', 'n is probably prime', 'n is a Carmichael number', 'a divides n'], answer: 0, why: 'A witness proves compositeness outright; passing bases only make primality more likely (below 4^−k after k random bases).' },
      { q: 'Why must gcd(e, p − 1) = 1 for the chosen primes?', options: ['So that n is odd', 'So that e has an inverse modulo φ(n)', 'So that p is prime', 'So that encryption is fast'], answer: 1, why: 'φ(n) = (p − 1)(q − 1); if e shared a factor with it, no d with e·d ≡ 1 would exist.' },
      { q: 'Which algorithm finds d from e and φ(n)?', options: ['Miller–Rabin', 'The extended Euclidean algorithm', 'Square-and-multiply', 'Trial division'], answer: 1, why: 'It writes 1 = φ(n)·s + e·t, and then d = t mod φ(n).' },
      { q: 'Anyone who learns φ(n) for an RSA modulus can…', options: ['Only encrypt', 'Compute d, and also factor n', 'Do nothing useful', 'Only verify signatures'], answer: 1, why: 'd = e⁻¹ mod φ(n) directly; and p + q = n − φ(n) + 1 gives p and q as the roots of a quadratic.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Encryption and decryption
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p08-encdec', family: 'p08-scheme', order: 20, title: 'Encryption and decryption',
    blurb: 'A message becomes a number m below n. Anyone with the public key computes c = m^e mod n; only the holder of d gets m back as c^d mod n. With e = 65537 encryption is a handful of multiplications; decryption with a full-size d takes thousands.',
    inputs: [
      { id: 'key', kind: 'choice', label: 'Key', def: 'toy', options: A.KEYS },
      { id: 'msg', kind: 'text', label: 'Message (a number below n for the toy key)', def: '2026' },
    ],
    check: (inp) => {
      const key = A.key(inp.key), t = String(inp.msg);
      if (inp.key === 'toy') { if (!/^\d+$/.test(t.trim())) return 'The toy key encrypts a number: type digits only'; if (B(t.trim()) >= key.n) return 'The message must be below n = ' + key.n; return null; }
      if (!t.length) return 'Type a message';
      const k = NT().byteLength(key.n);
      if (new TextEncoder().encode(t).length > k - 1) return 'At most ' + (k - 1) + ' bytes fit below this n';
      return null;
    },
    presets: [
      { label: 'Toy key: the number 2026', values: { key: 'toy', msg: '2026' } },
      { label: 'Toy key: m = 1 and m = 0 do not move', values: { key: 'toy', msg: '1' } },
      { label: 'RSA-1024: a short note', values: { key: 'rsa1024', msg: 'Meet me by the old mill at six.' } },
      { label: 'RSA-2048: a longer line', values: { key: 'rsa2048', msg: 'The lantern in the east window means the bridge is safe to cross.' } },
    ],
    counters: [{ id: 'enc', label: 'multiplications to encrypt' }, { id: 'dec', label: 'multiplications to decrypt' }],
    run(inp) {
      const key = A.key(inp.key), toy = inp.key === 'toy', { n, e, d } = key;
      const m = toy ? B(String(inp.msg).trim()) : A.textNum(inp.msg);
      const enc = P.memo('p08-enc', [inp.key, m.toString()], () => S.RSA.powLR(m, e, n));
      const c = enc.value;
      const dec = P.memo('p08-dec', [inp.key, c.toString()], () => S.RSA.powLR(c, d, n));
      const back = dec.value, text = toy ? null : A.numText(back);
      const F = new S.Frames(['enc', 'dec']);
      const X = 0, view = { x: -10, y: 0, w: 880, h: 520 }, KX = 550;
      const keyPanel = (lit) => [...P.panel('kp', KX, 20, 300, 230, null), P.t('kpt', KX + 16, 42, 'THE KEY', 'muted', 'start', 13),
        P.t('kp1', KX + 16, 64, 'public: anyone may use', 'good', 'start', 14), ...A.row('kn', KX - 120, 74, 'n', n, 'good', { lw: 150, w: 230, max: 16 }), ...A.row('ke', KX - 120, 116, 'e', e, 'good', { lw: 150, w: 230, max: 16 }),
        P.t('kp2', KX + 16, 186, 'private: only the owner', 'key', 'start', 14), ...A.row('kd', KX - 120, 196, 'd', d, lit === 'd' ? 'act' : 'key', { lw: 150, w: 230, max: 16 })];
      const msgCell = (k, y, t, cls) => ({ key: k, kind: 'cell', x: X + 120, y, w: 310, h: 36, rx: 6, text: t.length > 30 ? '“' + t.slice(0, 27) + '…”' : '“' + t + '”', size: 14, cls: 'mono ' + (cls || ''), title: t });
      const op = (k, y, lines, cls) => ({ key: k, kind: 'state', x: X + 275, y, w: 310, h: 52, rx: 8, lines, cls: 'block ' + (cls || '') });
      const arrow = (k, a, b, cls) => ({ key: k, kind: 'edge', from: a, to: b, cls: cls || '' });
      const chain = (upto, lit) => {
        const it = [];
        const Y = { msg: 30, m: 96, enc: 178, c: 240, dec: 322, m2: 384, msg2: 450 };
        if (!toy) it.push(msgCell('msg', Y.msg, inp.msg, ''), P.t('msgl', X + 110, Y.msg + 23, 'message', 'strong', 'end', 14));
        it.push(...A.row('m', X - 30, Y.m, toy ? 'm' : 'm (its bytes)', m, lit === 'm' ? 'act' : '', { lw: 140, w: 310 }));
        if (!toy) it.push(arrow('a0', 'msg', 'm'));
        if (upto >= 1) it.push(op('enc', Y.enc, ['c = m^e mod n', `${P.plural(enc.squarings, 'squaring')} + ${P.plural(enc.multiplications, 'multiplication')}`], lit === 'enc' ? 'act' : 'soft'), arrow('a1', 'm', 'enc'));
        if (upto >= 2) it.push(...A.row('c', X - 30, Y.c, 'c', c, 'hot', { lw: 140, w: 310 }), arrow('a2', 'enc', 'c'));
        if (upto >= 3) it.push(op('dec', Y.dec, ['m = c^d mod n', `${P.plural(dec.squarings, 'squaring')} + ${P.plural(dec.multiplications, 'multiplication')}`], lit === 'dec' ? 'act' : 'soft'), arrow('a3', 'c', 'dec'));
        if (upto >= 4) it.push(...A.row('m2', X - 30, Y.m2, 'c^d mod n', back, 'good', { lw: 140, w: 310 }), arrow('a4', 'dec', 'm2'));
        if (upto >= 5 && !toy) it.push(msgCell('msg2', Y.msg2, text || '?', 'good'), P.t('msg2l', X + 110, Y.msg2 + 23, 'message', 'strong', 'end', 14), arrow('a5', 'm2', 'msg2'));
        return it;
      };
      const kb = P.bits(n), mb = P.bits(m), cb = P.bits(c);
      F.add({ items: [...keyPanel(), ...chain(0, 'm')], say: toy ? `The toy key has n = ${n$(n)} and e = ${e}. The message is already a number: m = ${n$(m)}, which must be below n.` : `The message, ${new TextEncoder().encode(inp.msg).length} bytes of text, read as one big number: m = ${n$(m)}, ${P.an(mb)}-bit number, below the ${kb}-bit modulus n.`, facts: { n, e, m, mb, kb, len: new TextEncoder().encode(inp.msg).length }, meta: { phase: 'm' } });
      F.set('enc', enc.squarings + enc.multiplications);
      F.add({ items: [...keyPanel(), ...chain(1, 'enc')], say: `Encrypt with the public key: c = m^e mod n. e = ${e} has ${enc.bits.length} bits, so square-and-multiply takes ${enc.squarings} squarings and ${P.plural(enc.multiplications, 'multiplication')}, ${enc.squarings + enc.multiplications} in all, each reduced modulo n.`, facts: { e, sq: enc.squarings, mul: enc.multiplications, bits: enc.bits.length, total: enc.squarings + enc.multiplications }, meta: { phase: 'enc' } });
      const fixed = m === 0n || m === 1n || m === n - 1n;
      F.add({ items: [...keyPanel(), ...chain(2, 'c')], say: fixed ? `c = ${n$(c)}: the same number. 0, 1 and n − 1 are their own e-th powers, one reason raw RSA is never used on bare messages (padding fixes it).` : `c = ${n$(c)}, ${P.an(cb)}-bit number with no visible link to m. Anyone could have computed it; nobody without d is known to be able to undo it.`, facts: { c, cb }, meta: { phase: 'c' } });
      F.set('dec', dec.squarings + dec.multiplications);
      F.add({ items: [...keyPanel('d'), ...chain(3, 'dec')], say: `Decrypt with the private exponent: m = c^d mod n. d has ${dec.bits.length} bits, so this takes ${dec.squarings} squarings and ${dec.multiplications} multiplications, ${dec.squarings + dec.multiplications} in all: about ${Math.round((dec.squarings + dec.multiplications) / Math.max(1, enc.squarings + enc.multiplications))} times the work of encrypting.`, facts: { db: dec.bits.length, sq: dec.squarings, mul: dec.multiplications, total: dec.squarings + dec.multiplications, ratio: Math.round((dec.squarings + dec.multiplications) / Math.max(1, enc.squarings + enc.multiplications)) }, meta: { phase: 'dec' } });
      F.add({ items: [...keyPanel(), ...chain(5, 'm2')], say: toy ? `c^d mod n = ${n$(back)}, the message m = ${n$(m)} again${back === m ? '' : ' (NOT)'}.` : `c^d mod n = ${n$(back)}, the same number as m, and its bytes read “${text}” again.`, facts: { back, m, msg: inp.msg }, meta: { phase: 'back', ok: back === m } });
      for (const f of F.list) f.narrowView = { x: -10, y: 0, w: 540, h: 590 };
      return { frames: P.fix(F.list, view), def: P.def('Textbook RSA', ['public key (n, e), private key d', 'e·d ≡ 1 (mod φ(n))', 'encrypt: c = m^e mod n   (0 ≤ m < n)', 'decrypt: m = c^d mod n', 'cost: about log₂ e squarings to encrypt,', '        about log₂ n to decrypt']) };
    },
    predict: [
      { at: (f) => f.meta.phase === 'm', pick: 'option', ask: 'How many modular multiplications (squarings included) will encryption take?', options: (fr, i) => { const x = fr[i + 1].facts; return [...new Set([String(x.total), String(x.e - 1n), String(x.bits * 2), String(x.mul)])]; }, answer: (fr, i) => String(fr[i + 1].facts.total), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Who can compute c = m^e mod n?', options: ['Only the key owner', 'Anyone with the public key', 'Only someone who knows φ(n)', 'Nobody without d'], answer: 1, why: 'n and e are public: encryption needs nothing secret.' },
      { q: 'With e = 65537, encrypting takes how many squarings?', options: ['1', '16', '17', '65536'], answer: 1, why: '65537 = 2^16 + 1 has 17 bits: 16 squarings and one multiplication.' },
      { q: 'Why is decryption much slower than encryption?', options: ['d is about as long as n, while e is short', 'Decryption needs a prime test', 'c is longer than m', 'It uses a different modulus'], answer: 0, why: 'Square-and-multiply costs one squaring per exponent bit; d has as many bits as n.' },
      { q: 'What must hold for the message number m?', options: ['m is prime', '0 ≤ m < n', 'm < e', 'gcd(m, e) = 1'], answer: 1, why: 'Everything is modulo n; a larger m would come back reduced.' },
      { q: 'Raw RSA maps the message 1 to…', options: ['n − 1', '1', 'e', 'a random value'], answer: 1, why: '1^e = 1: raw RSA leaves some messages unchanged and is deterministic, which is why padding is used.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Why decryption works
  // ---------------------------------------------------------------------------------------------------------------
  const whyCheck = (inp) => {
    if (inp.size !== 'toy') { let m; try { m = B(String(inp.m).trim()); } catch (e) { return 'm: a whole number'; } const k = A.key(inp.size); return m < 2n || m >= k.n - 1n ? 'm: between 2 and n − 2' : null; }
    let p, q, e, m;
    try { [p, q, e, m] = [inp.p, inp.q, inp.e, inp.m].map((v) => B(String(v).trim())); } catch (x) { return 'p, q, e and m: whole numbers'; }
    if (!NT().isProbablePrime(p) || !NT().isProbablePrime(q) || p === q) return 'p and q: two different primes';
    if (p * q > 40000n) return 'Keep n = p·q below 40000 so the cycle can be drawn';
    const phi = (p - 1n) * (q - 1n);
    if (e < 2n || e >= phi || NT().gcd(e, phi) !== 1n) return 'e: between 2 and φ(n) − 1 = ' + (phi - 1n) + ' with no factor in common with φ(n) = ' + phi;
    const n = p * q;
    if (m < 2n || m >= n - 1n) return 'm: between 2 and n − 2 = ' + (n - 2n);
    if (NT().gcd(m, n) !== 1n) return 'm: choose m with no factor in common with n (the last step shows that the others work too)';
    const L = NT().order(m, n).order;
    if (L > 24n) return 'The powers of ' + m + ' cycle after ' + L + ' steps, too many to draw: try another m (or smaller primes)';
    return null;
  };
  S.topic({
    id: 'p08-why', family: 'p08-scheme', order: 30, title: 'Why decryption works',
    blurb: 'The powers of m modulo n run round a cycle, and its length divides φ(n), so m^φ(n) = 1 (Euler). Since e·d = 1 + k·φ(n), raising to e and then to d goes round the cycle k·φ(n)/length whole times and one step more: back to m.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Key', def: 'toy', options: [{ value: 'toy', label: 'toy: choose p, q, e' }, { value: 'rsa1024', label: 'RSA-1024' }, { value: 'rsa2048', label: 'RSA-2048' }] },
      { id: 'p', kind: 'bigint', label: 'p', def: '7' },
      { id: 'q', kind: 'bigint', label: 'q', def: '13' },
      { id: 'e', kind: 'bigint', label: 'e', def: '5' },
      { id: 'm', kind: 'bigint', label: 'Message m', def: '6' },
    ],
    check: whyCheck,
    presets: [
      { label: 'n = 91, e = 5, m = 6', values: { size: 'toy', p: '7', q: '13', e: '5', m: '6' } },
      { label: 'A cycle of 20: n = 55, m = 2', values: { size: 'toy', p: '5', q: '11', e: '3', m: '2' } },
      { label: 'A short cycle: n = 91, m = 3', values: { size: 'toy', p: '7', q: '13', e: '5', m: '3' } },
      { label: 'n = 33, e = 3, m = 7', values: { size: 'toy', p: '3', q: '11', e: '3', m: '7' } },
      { label: 'RSA-1024', values: { size: 'rsa1024', m: '31415926535' } },
      { label: 'RSA-2048', values: { size: 'rsa2048', m: '27182818284' } },
    ],
    counters: [{ id: 'laps', label: 'whole laps of the cycle' }],
    run(inp) {
      const toy = inp.size === 'toy';
      const key = toy ? S.RSA.fromPrimes(B(inp.p) > B(inp.q) ? B(inp.p) : B(inp.q), B(inp.p) > B(inp.q) ? B(inp.q) : B(inp.p), B(inp.e)) : A.key(inp.size);
      const { n, e, d, phi } = key, m = B(String(inp.m).trim()), ed = e * d, k = (ed - 1n) / phi;
      const c = NT().pow(m, e, n), back = NT().pow(c, d, n);
      const F = new S.Frames(['laps']);
      const defn = P.def('Why m^(ed) = m', ['the powers of m cycle; the cycle length L divides φ(n)', 'so m^φ(n) ≡ 1 (mod n)   (Euler)', 'e·d = 1 + k·φ(n)', 'm^(ed) = m^(1 + kφ(n)) = m·(m^φ(n))^k = m·1^k = m']);
      if (!toy) {
        const mphi = P.memo('p08-why-mphi', [inp.size, m.toString()], () => NT().pow(m, phi, n));
        const view = { x: -10, y: 0, w: 860, h: 470 };
        const rows = (lit) => [['n', n], ['φ(n)', phi], ['e', e], ['d', d], ['k = (e·d − 1)/φ(n)', k], ['m', m], ['m^φ(n) mod n', mphi], ['c = m^e mod n', c], ['c^d mod n', back]].flatMap(([l, v], i) => A.row('r' + i, 0, 20 + i * 48, l, v, lit.includes(i) ? (i === 8 || i === 6 ? 'good' : 'act') : '', { lw: 190, w: 300 }));
        const side = (lines) => P.eqs('q', 540, 60, lines, 16, 32);
        F.add({ items: [...rows([0, 1, 2, 3]), ...side([['e·d ≡ 1 (mod φ(n))', 'strong']])], say: `A real key: n has ${P.bits(n)} bits, φ(n) = ${n$(phi)}, e = ${e} and d = ${n$(d)}. The cycle of powers of m is far too long to draw, but the argument does not care.`, facts: { nb: P.bits(n), phi, e, d }, meta: { phase: 'setup' } });
        F.add({ items: [...rows([4]), ...side([['e·d = 1 + k·φ(n)', 'strong'], [`k = ${fmt(k, 16)}`, 'act']])], say: `e·d ≡ 1 (mod φ(n)) means e·d = 1 + k·φ(n) for a whole number k; here k = ${n$(k)}, which is below e = ${e}, since d < φ(n).`, facts: { k, e }, meta: { phase: 'k' } });
        F.add({ items: [...rows([5, 6]), ...side([['m^φ(n) ≡ 1 (mod n)', 'good'], ['Euler, for m coprime to n', 'muted']])], say: `Euler's theorem: m^φ(n) ≡ 1. Computed here with ${P.bits(n)}-bit arithmetic: ${n$(m)}^φ(n) mod n = ${n$(mphi)}.`, facts: { m, mphi, nb: P.bits(n) }, meta: { phase: 'euler' } });
        F.add({ items: [...rows([7, 8]), ...side([['m^(ed) = m·(m^φ(n))^k', 'strong'], ['= m·1^k = m', 'good']])], say: `So c = m^e mod n = ${n$(c)} and c^d = m^(ed) = m·(m^φ(n))^k = m: the computation gives ${n$(back)}, the message ${n$(m)} again.`, facts: { c, back, m }, meta: { phase: 'back', ok: back === m } });
        return { frames: P.fix(F.list, view), def: defn };
      }
      const L = Number(NT().order(m, n).order), pows = []; for (let i = 0; i < L; i++) pows.push(NT().pow(m, i, n));
      const cx = 220, cy = 255, R = 185, view = { x: -20, y: 20, w: 880, h: 490 }, QX = 490;
      const KN = S.Kit.nt, ang = (i) => KN.angle(L, i);
      const ring = (hand, lit, extra) => {
        const ck = KN.clock({ prefix: 'ck', cx, cy, R, n: L, hand, text: (i) => String(pows[i]), cls: (i) => lit[i] || '' });
        const labs = []; for (let i = 0; i < L; i++) { const p = KN.at(L, i, cx, cy, R + ck.r + 18); labs.push(P.t('ex' + i, p.x, p.y + 5, 'm' + P.sup(i), 'muted', 'middle', 13)); }
        return ck.items.concat(labs, extra || []);
      };
      const eq = (lines, hl) => [P.t('qt', QX, 44, 'n = ' + n + ',  φ(n) = ' + phi + ',  e = ' + e + ',  d = ' + d, 'muted', 'start', 15), ...P.eqs('q', QX, 84, lines.map((l, i) => (i === hl ? [l[0], (l[1] || '') + ' hot'] : l)), 17, 34)];
      const base = [[`e·d = ${e}·${d} = ${ed} = 1 + ${k}·${phi}`, 'strong']];
      F.add({ items: [...ring(null, {}), ...eq(base)], say: `p = ${key.p} and q = ${key.q} give n = ${n} and φ(n) = ${phi}; e = ${e} and d = ${d}, because e·d = ${ed} = 1 + ${k}·${phi}. Why does raising to e and then to d give m back?`, facts: { p: key.p, q: key.q, n, phi, e, d, ed, k }, meta: { phase: 'setup' } });
      const l2 = base.concat([[`powers of m = ${m}: a cycle of L = ${L}`, 'act'], [`m${P.sup(L)} ≡ 1 (mod ${n})`, 'act']]);
      F.add({ items: [...ring(0, { 0: 'act', 1: 'key' }), ...eq(l2, 1)], say: `The powers m⁰ = 1, m¹ = ${m}, m² = ${pows[Math.min(2, L - 1)]}, … modulo ${n} run round a cycle: after L = ${L} steps they are back at 1, since ${m}^${L} ≡ 1 (mod ${n}). Every power of m is somewhere on this ring.`, facts: { m, L, p2: pows[Math.min(2, L - 1)], n }, meta: { phase: 'ring' } });
      const laps = Number(phi) / L;
      F.set('laps', laps);
      const l3 = l2.concat([[`L = ${L} divides φ(n) = ${phi} = ${laps}·${L}`, 'good'], [`so m^φ(n) ≡ 1   (Euler)`, 'good']]);
      F.add({ items: [...ring(0, { 0: 'good' }, KN.arc({ key: 'lap', cx, cy, r: R - 58, a0: 0, a1: 359, cls: 'good' })), ...eq(l3, 3)], say: `The cycle length ${L} divides φ(n) = ${phi} (Lagrange: the order of m divides the size of the group), so raising m to φ(n) goes round ${P.plural(laps, 'whole lap')} and lands on 1. That is Euler's theorem, m^φ(n) ≡ 1.`, facts: { L, phi, laps }, meta: { phase: 'euler' } });
      const ePos = Number(e % BigInt(L)), eLaps = Number(e / BigInt(L));
      F.set('laps', eLaps);
      const l4 = l3.concat([[`c = m^e: ${e} = ${eLaps}·${L} + ${ePos}  →  c = ${c}`, '']]);
      F.add({ items: [...ring(ePos, { [ePos]: 'hot', 1: 'key' }, ePos ? KN.arc({ key: 'arcE', cx, cy, r: R - 58, a0: 0, a1: ang(ePos), cls: 'hot' }) : []), ...eq(l4, 5)], say: `Encrypting raises m to e = ${e}: ${eLaps ? P.plural(eLaps, 'whole lap') + ' and ' : ''}${P.plural(ePos, 'step')} round the ring from 1, landing on m^${ePos} = ${c}. So c = ${c}.`, facts: { e, eLaps, ePos, c }, meta: { phase: 'enc', pos: ePos } });
      const edLaps = (ed - 1n) / BigInt(L);
      F.set('laps', Number(edLaps));
      const l5 = l4.concat([[`c^d = m^(ed): ${ed} = ${edLaps}·${L} + 1  →  ${back}`, '']]);
      F.add({ items: [...ring(1, { 1: 'good' }, KN.arc({ key: 'lap', cx, cy, r: R - 58, a0: 0, a1: 359, cls: 'faint', head: false }).concat(KN.arc({ key: 'arcE', cx, cy, r: R - 74, a0: 0, a1: ang(1), cls: 'good' }))), ...eq(l5, 6)], say: `Decrypting raises c to d, so m to e·d = ${ed} = ${edLaps}·${L} + 1: ${P.plural(edLaps, 'whole lap')}, which change nothing, and one step: m¹ = ${back}, the message.`, facts: { ed, edLaps, L, back }, meta: { phase: 'dec', pos: 1 } });
      const pf = key.p, pfBack = NT().pow(pf, ed, n);
      F.add({ items: [...ring(1, { 1: 'good' }), ...eq([[`m^(ed) = m^(1 + kφ(n))`, 'strong'], ['= m·(m^φ(n))^k = m·1^k = m', 'good'], ['', ''], [`even m = ${pf}, sharing p with n:`, 'strong'], [`${pf}^${ed} mod ${n} = ${pfBack}`, 'good']])], say: `In general m^(ed) = m^(1 + kφ(n)) = m·(m^φ(n))^k = m. A message sharing a factor with n has no cycle back through 1, yet it still returns, because the same argument works modulo p and modulo q separately: ${pf}^${ed} mod ${n} = ${pfBack}.`, facts: { pf, ed, n, pfBack }, meta: { phase: 'general' } });
      for (const f of F.list) f.narrowView = f.meta.phase === 'general' || f.meta.phase === 'setup' ? { x: QX - 20, y: 20, w: 400, h: 330 } : { x: -20, y: 20, w: 480, h: 490 };
      return { frames: P.fix(F.list, view), def: defn };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'enc' && fr[i + 1].meta.pos !== undefined, pick: 'item', ask: 'c = m^e. Click the position on the ring where it lands.', answer: (fr, i) => 'ck:' + fr[i + 1].meta.pos, explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'dec', pick: 'item', ask: 'Now c^d = m^(ed). Where does it land?', answer: (fr, i) => 'ck:' + fr[i + 1].meta.pos, explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'back', pick: 'option', ask: 'What will c^d mod n be?', options: (fr, i) => ['m itself', '1', 'c', 'n − m'], answer: 'm itself', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Euler\'s theorem says, for m coprime to n…', options: ['m^n ≡ m', 'm^φ(n) ≡ 1 (mod n)', 'm^(n−1) ≡ 1 always', 'm^e ≡ m'], answer: 1, why: 'The order of m divides φ(n), the size of the group of units.' },
      { q: 'If e·d = 1 + k·φ(n), then m^(ed) equals…', options: ['1', 'm^k', 'm', 'm^φ(n)'], answer: 2, why: 'm^(ed) = m·(m^φ(n))^k = m·1 = m.' },
      { q: 'The powers of m = 6 modulo 91 repeat every 12 steps. What is 6^25 mod 91 in terms of the ring?', options: ['6^1 = 6', '6^0 = 1', '6^12', 'it cannot be said'], answer: 0, why: '25 = 2·12 + 1: two laps and one step.' },
      { q: 'Does RSA decryption work for a message sharing a prime factor with n?', options: ['No, never', 'Yes: the argument works modulo p and modulo q separately', 'Only if e = 3', 'Only for m = 0'], answer: 1, why: 'Modulo the shared prime both sides are 0; modulo the other prime Fermat applies; the CRT glues them.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
