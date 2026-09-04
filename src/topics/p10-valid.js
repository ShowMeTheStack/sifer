// Part 10, why received points must be validated: a key holder who multiplies whatever point it is sent by its
// secret, without checking that the point is on its curve, can be steered onto weak curves (the formulas never use b)
// and leak its key piece by piece; x-only code that accepts any u can be steered onto the curve's twist. Each attack
// is shown on a toy curve with a planted key, as the reason for one line of checking.
(function (S) {
  'use strict';
  const U = S.P10, E = () => S.ECC;
  const f = U.f, P$ = (P) => U.fp(P);

  // ---------------------------------------------------------------------------------------------------------------
  // Invalid curves
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-invalid', family: 'p10-valid', order: 10, title: 'Why points must be validated: invalid curves',
    blurb: 'The formulas for adding and doubling points use a but never b. So code that multiplies a received point by its secret d, without checking that the point is on the curve, will happily compute on a different curve y² = x³ + ax + b′, one with points of small order. Each answer then gives d modulo a small prime, and a few answers give all of d. The fix is a single check.',
    inputs: [
      { id: 'd', kind: 'text', label: 'The victim\'s secret d (planted)', def: '4242', check: (v) => { if (!/^\d+$/.test(String(v).trim())) return 'd: a whole number'; const d = BigInt(String(v).trim()); return d < 1n || d >= 10009n ? 'd: from 1 to 10008' : null; } },
      { id: 'seed', kind: 'number', label: 'Seed for the points sent', def: 1, min: 1, max: 999 },
    ],
    presets: [{ label: 'd = 4242', values: { d: '4242', seed: 1 } }, { label: 'd = 9999', values: { d: '9999', seed: 2 } }, { label: 'd = 17', values: { d: '17', seed: 5 } }],
    counters: [{ id: 'q', label: 'queries' }],
    run(inp) {
      const C = E().toy('target10007'), d = BigInt(String(inp.d).trim()), F = new S.Frames(['q']);
      const r = E().attacks.invalidCurve(C, d, { seed: inp.seed }), qs = r.queries;
      const head = U.head('iv:h', 30, 28, `The victim's curve: ${C.name}, prime order n = ${C.n}`);
      const cols = [{ w: 70, head: 'b′' }, { w: 120, head: '#points' }, { w: 90, head: 'order l' }, { w: 190, head: 'point sent' }, { w: 160, head: 'answer gives' }];
      const tbl = (upto) => U.table({ prefix: 'iv:t', x: 30, y: 250, cols, rows: qs.slice(0, upto).map((q) => [String(q.b), String(q.order), String(q.l), P$(q.Q), `d ≡ ${q.residue} (mod ${q.l})`]), rh: 32, hl: (i) => (i === upto - 1 ? 'act' : '') }).items;
      const forms = U.eqs('iv:f', 30, 80, [['add: λ = (y₂ − y₁)/(x₂ − x₁)', ''], ['double: λ = (3x₁² + a)/(2y₁)', ''], ['x₃ = λ² − x₁ − x₂, y₃ = λ(x₁ − x₃) − y₁', ''], ['no b anywhere', 'hot']], 15, 28);
      F.add({ items: [head, ...forms, ...U.readout('iv:v', 560, 60, 330, 'the victim', [['holds a fixed secret', 'd'], ['computes', 'd·Q for any Q'], ['checks Q is on the curve?', 'no', 'bad']])], say: `A server keeps a fixed secret d and answers each Diffie–Hellman request with d·Q for the point Q it is sent. Its curve has prime order ${C.n}, so it looks safe. But look at the formulas: they use a, never b. Fed a point that is not on its curve, the code computes on whichever curve y² = x³ + ${C.a}x + b′ that point happens to lie on.`, facts: { n: C.n, a: C.a, curve: [C.p, C.a, C.b] }, meta: { stage: 'setup' } });
      qs.forEach((q, i) => {
        F.set('q', i + 1);
        F.add({ items: [head, ...forms, ...tbl(i + 1)], say: `Query ${i + 1}: the curve with b′ = ${q.b} has ${q.order} points, a multiple of ${q.l}. Send a point Q = ${P$(q.Q)} of order ${q.l}. The answer d·Q is one of only ${q.l} points, and trying t·Q for t < ${q.l} finds it at t = ${q.residue}: so d ≡ ${q.residue} (mod ${q.l}).`, facts: Object.assign({ nq: i + 1 }, q), meta: { stage: 'query', i } });
      });
      const M = qs.reduce((s, q) => s * q.l, 1n);
      F.add({ items: [head, ...forms, ...tbl(qs.length), ...U.eqs('iv:e', 30, 470, [[`moduli ${qs.map((q) => q.l).join(' · ')} = ${M} > n = ${C.n}`, 'strong'], [`CRT: d = ${r.d}`, 'good'], [r.d === d ? 'the planted secret, recovered' : 'not the planted secret', r.d === d ? 'good' : 'bad']], 15, 28)], say: `${qs.length} queries, and the product of the small orders, ${qs.map((q) => q.l).join('·')} = ${M}, exceeds n = ${C.n}. The Chinese remainder theorem combines the residues into d = ${r.d}${r.d === d ? ', exactly the secret' : ''}. No discrete logarithm on the real curve was ever needed.`, facts: { M, n: C.n, d: r.d, ls: qs.map((q) => q.l), nq: qs.length }, meta: { stage: 'crt' } });
      const bad = qs[qs.length - 1].Q, v = C.validate(bad);
      const rows = v.checks.map((c) => [c.name.replace('-', ' '), c.ok ? 'passes' : 'FAILS', c.ok ? 'good' : 'bad']);
      F.add({ items: [head, ...forms, ...U.readout('iv:c', 560, 60, 330, 'validate Q first', rows), ...U.eqs('iv:e', 30, 300, [[`y² ≡ x³ + ${C.a}x + ${C.b}?`, 'strong'], [`for ${P$(bad)}: no`, 'bad'], ['reject before multiplying', 'good']], 16, 30)], say: `The defence is one check before using any received point: is it on the curve, y² ≡ x³ + ${C.a}x + ${C.b}? Each point the attacker sent fails it; ${P$(bad)} lies on the curve with b′ = ${qs[qs.length - 1].b}, not ${C.b}. With a cofactor above 1, also check that the point lies in the prime-order subgroup. Compressed points are partly protected, since decoding computes y from the right equation.`, facts: { a: C.a, b: C.b, Q: bad, b2: qs[qs.length - 1].b }, meta: { stage: 'defence' } });
      U.fix(F.list);
      return { frames: F.list, def: U.def('Invalid-curve attack', ['the group law never uses b', 'Q on y² = x³ + ax + b′ of small order l', 'd·Q reveals d mod l', 'CRT over enough l: all of d', 'defence: check Q is on the curve (and in the subgroup)']) };
    },
    predict: [{ at: (f) => f.meta.stage === 'setup', pick: 'option', ask: 'Can the victim\'s answers reveal d without solving a discrete logarithm on its curve?', options: ['yes, a few residues at a time', 'no, n is prime', 'only if d is small'], answer: 'yes, a few residues at a time', explain: (fr) => fr.find((x) => x.meta.stage === 'crt').say }],
    quiz: [
      { q: 'Why can a point on another curve fool the victim?', options: ['the addition formulas do not use b', 'all curves are the same', 'b is secret', 'the order is prime'], answer: 0, why: 'The code computes on whatever curve the point is on.' },
      { q: 'A query with a point of order 31 reveals…', options: ['d mod 31', 'd', 'nothing', 'd mod n'], answer: 0, why: 'd·Q is one of 31 points.' },
      { q: 'What stops the attack?', options: ['checking the point is on the curve before using it', 'a bigger d', 'a prime n', 'hashing the result'], answer: 0, why: 'One equation check.' },
      { q: 'Why is a fixed (static) key more at risk than a fresh one per session?', options: ['the attacker can ask many questions about the same d', 'it is shorter', 'it is not', 'it is public'], answer: 0, why: 'Each answer leaks another residue of the same d.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The twist
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-twist', family: 'p10-valid', order: 20, title: 'Why the twist must be safe too',
    blurb: 'An x-only ladder, like X25519\'s, never sees y, so it never notices when a u belongs to no point of the curve. Such a u lies on the quadratic twist, another curve with its own number of points. If that number has small factors, the same trick as the invalid-curve attack leaks the key. The cure is either to check u, or to choose a curve whose twist is strong as well.',
    inputs: [
      { id: 'd', kind: 'text', label: 'The victim\'s secret d (planted)', def: '1234', check: (v) => { if (!/^\d+$/.test(String(v).trim())) return 'd: a whole number'; const d = BigInt(String(v).trim()); return d < 1n || d >= 2549n ? 'd: from 1 to 2548' : null; } },
      { id: 'seed', kind: 'number', label: 'Seed for the values sent', def: 1, min: 1, max: 999 },
    ],
    presets: [{ label: 'd = 1234', values: { d: '1234', seed: 1 } }, { label: 'd = 2000', values: { d: '2000', seed: 3 } }, { label: 'd = 99', values: { d: '99', seed: 7 } }],
    counters: [{ id: 'q', label: 'queries' }],
    run(inp) {
      const d = BigInt(String(inp.d).trim()), F = new S.Frames(['q']), r = E().attacks.twist(d, { seed: inp.seed });
      const { p, A } = E().attacks.MONT_TOY, set = r.trace[0], sg = r.trace.find((t) => t.kind === 'signs'), qs = r.queries;
      const fac = [...S.NT.factor(set.T)].map(([q, e]) => (e > 1 ? q + U.sup(e) : String(q))).join('·');
      const head = U.head('tw:h', 30, 28, `v² = u³ + ${A}u² + u over GF(${p}), used x-only`);
      const box = (key, x, title, lines, cls) => ({ key, kind: 'state', x, y: 140, w: 400, h: 120, rx: 10, lines: [title, ...lines], cls: 'block val3 ' + cls, size: 14 });
      const curves = [box('tw:c', 230, 'the curve', [`${set.N} = 4·${set.q} points`, `u³ + ${A}u² + u a square`], 'act'), box('tw:t', 670, 'its twist', [`${set.T} = ${fac} points`, 'u³ + ' + A + 'u² + u not a square'], 'key')];
      const cols = [{ w: 120, head: 'u sent' }, { w: 160, head: 'order on twist' }, { w: 240, head: 'answer gives' }];
      const tbl = (upto) => U.table({ prefix: 'tw:t', x: 30, y: 250, cols, rows: qs.slice(0, upto).map((q) => [String(q.u), String(q.order), `d ≡ ±${q.residue} (mod ${q.order})`]), rh: 32, hl: (i) => (i === upto - 1 ? 'act' : '') }).items;
      F.add({ items: [head, ...curves, ...U.eqs('tw:e', 30, 320, [['every u is one of two kinds:'], ['f(u) a square: a point of the curve', 'act'], ['f(u) not a square: a point of the twist', 'key'], ['an x-only ladder works the same on both', 'hot']], 16, 30)], say: `The victim runs an x-only ladder with a fixed secret d on a curve of ${set.N} = 4·${set.q} points, a large prime subgroup. For each u, u³ + ${A}u² + u is either a square (u belongs to a point of the curve) or not (u belongs to a point of the quadratic twist). The ladder's formulas are the same for both, and the twist has ${set.T} = ${fac} points: all small factors.`, facts: { N: set.N, q: set.q, T: set.T, A, p, fac: [...S.NT.factor(set.T)].flat() }, meta: { stage: 'setup' } });
      qs.forEach((q, i) => {
        F.set('q', i + 1);
        F.add({ items: [head, ...curves.map((c) => Object.assign({}, c, { y: 120, h: 90, lines: c.lines.slice(0, 2) })), ...tbl(i + 1)], say: `Query ${i + 1}: send u = ${q.u}, a twist point of order ${q.order}. The answer is the u of d·P, one of only a few values, and matching it against t·P gives d ≡ ±${q.residue} (mod ${q.order}). With only u, d and −d look the same, hence the ±.`, facts: Object.assign({ nq: i + 1 }, q), meta: { stage: 'query', i } });
      });
      F.add({ items: [head, ...curves.map((c) => Object.assign({}, c, { y: 120, h: 90, lines: c.lines.slice(0, 2) })), ...tbl(qs.length), ...U.eqs('tw:e', 30, 430, [[`${sg.say.split(';')[0]}`.slice(0, 70)], [`d ∈ {${r.candidates.join(', ')}} (mod ${r.q})`, 'good'], [r.candidates.map(String).includes(String(d)) || r.candidates.map(String).includes(String(r.q - d)) ? 'the planted secret (up to sign), recovered' : 'not recovered', 'good']], 15, 28)], say: `Each residue is known only up to sign, so try all ${2 ** qs.length} sign choices, glue each with the CRT modulo ${sg.M}, and keep those that reproduce the victim's public u = ${r.pubU}: d ∈ {${r.candidates.join(', ')}} (mod ${r.q}). In x-only arithmetic d and −d give the same results, so that is the key.`, facts: { n2: 2 ** qs.length, M: sg.M, pub: r.pubU, cands: r.candidates, q: r.q }, meta: { stage: 'signs' } });
      const tw = (2n * ((1n << 255n) - 19n) + 2n - 8n * E().Ed25519.L);
      let rest = tw, small = 0n; for (const q of [2n, 2n]) if (rest % q === 0n) { rest /= q; small++; }
      F.add({ items: [head, ...U.eqs('tw:e', 30, 90, [['two cures', 'strong'], ['check that u³ + Au² + u is a square, or', 'act'], ['use a curve whose twist is also strong', 'good'], [`Curve25519: twist order = 4 · a ${S.ECC.bitLength(rest)}-bit number`, 'good'], [`${S.NT.isProbablePrime(rest) ? 'which is prime' : 'which is composite'}, so no small factors to exploit`]], 16, 32)], say: `There are two cures. Check every received u (is u³ + ${A}u² + u a square mod p?), or choose a curve whose twist is strong as well. Curve25519 took the second way: its twist has 4·L′ points, with L′ a ${S.ECC.bitLength(rest)}-bit ${S.NT.isProbablePrime(rest) ? 'prime' : 'number'}, and X25519 clamps the scalar to a multiple of 8, so any 32 bytes are safe to accept.`, facts: { A, bits: S.ECC.bitLength(rest) }, meta: { stage: 'defence' } });
      U.fix(F.list);
      return { frames: F.list, def: U.def('The twist attack', ['f(u) = u³ + Au² + u', 'f(u) not a square: u lies on the twist', '#twist = 2p + 2 − #E', 'twist points of small order l leak d mod l (up to sign)', 'defence: check u, or a twist-secure curve']) };
    },
    predict: [{ at: (f) => f.meta.stage === 'setup', pick: 'option', ask: 'Which number decides how much the twist leaks?', options: ['the factors of the twist\'s order', 'the size of p', 'the value of A', 'nothing: the twist is harmless'], answer: 'the factors of the twist\'s order', explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'Why does an x-only ladder not notice a twist point?', options: ['it never computes y, and its formulas are the same', 'it checks y', 'twist points do not exist', 'it uses b'], answer: 0, why: 'Only u enters the formulas.' },
      { q: '#E + #twist = …', options: ['2p + 2', 'p', 'p²', '2p'], answer: 0, why: 'Each u gives two points on one of the two curves (or one when f(u) = 0).' },
      { q: 'How does X25519 avoid the twist attack?', options: ['Curve25519\'s twist is also strong', 'it checks every u', 'it uses y', 'it is not safe'], answer: 0, why: 'The twist has a large prime factor.' },
      { q: 'Why does each twist answer leave a ± ambiguity?', options: ['u alone cannot tell P from −P', 'the CRT is ambiguous', 'the order is even', 'random noise'], answer: 0, why: 'P and −P have the same u.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
