// Part 10, curve shapes and encodings: one toy curve drawn in its Montgomery, twisted Edwards and Weierstrass forms,
// with points and sums carried across by the maps; P-256 set against Curve25519 (and secp256k1) on what matters when
// choosing a curve; and point compression, which keeps x and one bit of y.
(function (S) {
  'use strict';
  const U = S.P10, E = () => S.ECC;
  const f = U.f, P$ = (P) => U.fp(P);
  const md = (v, p) => ((v % p) + p) % p;
  const uv = (P) => (P ? `(${P.u}, ${P.v})` : 'O');

  // ---------------------------------------------------------------------------------------------------------------
  // Three shapes of one curve
  // ---------------------------------------------------------------------------------------------------------------
  const montPoint = (label) => (v, inp) => {
    const P = U.parsePoint(v);
    if (!P) return label + ': two whole numbers, u and v, like 1, 16';
    let F; try { F = E().forms.make(inp.p, inp.A, inp.B); } catch (e) { return 'This Montgomery curve is singular: choose another A or B'; }
    if (P.x >= F.p || P.y >= F.p) return label + ': both coordinates below p';
    if (!F.mont.on({ u: P.x, v: P.y })) return label + ': (' + P.x + ', ' + P.y + ') is not on B·v² = u³ + A·u² + u';
    return null;
  };
  S.topic({
    id: 'ec-forms', family: 'p10-forms', order: 10, title: 'Three shapes of one curve',
    blurb: 'The same group can be written as a Montgomery curve B·v² = u³ + A·u² + u, as a twisted Edwards curve a·x² + y² = 1 + d·x²y², or in the short Weierstrass form y² = x³ + a′x + b′. Rational maps carry points across, and sums go to sums. Each shape has its strength: the Montgomery ladder, the complete Edwards addition, the familiar Weierstrass formulas.',
    inputs: [
      { id: 'p', kind: 'number', label: 'Prime p', def: 127, min: 11, max: 127, check: (v) => (!S.NT.isProbablePrime(BigInt(v)) ? 'p: a prime' : null) },
      { id: 'A', kind: 'number', label: 'A', def: 4, min: 0, max: 126 },
      { id: 'B', kind: 'number', label: 'B', def: 3, min: 1, max: 126 },
      { id: 'P', kind: 'text', label: 'P (u, v)', def: '1, 16', check: montPoint('P') },
      { id: 'Q', kind: 'text', label: 'Q (u, v)', def: '3, 28', check: montPoint('Q') },
    ],
    presets: [
      { label: 'GF(127): A = 4, B = 3', values: { p: 127, A: 4, B: 3, P: '1, 16', Q: '3, 28' } },
      { label: 'Doubling a point', values: { p: 127, A: 4, B: 3, P: '4, 60', Q: '4, 60' } },
      { label: 'With the point (0, 0) of order 2', values: { p: 127, A: 4, B: 3, P: '0, 0', Q: '6, 54' } },
    ],
    check: (inp) => { let F; try { F = E().forms.make(inp.p, inp.A, inp.B); } catch (e) { return 'This Montgomery curve is singular: B(A² − 4) ≡ 0'; } if (!F.edw.complete) return 'Choose A and B so that the Edwards form is complete: (A + 2)/B a square and (A − 2)/B not a square mod p'; if (Number(F.p) % 3 === 0) return 'p: not 3'; return null; },
    run(inp) {
      const F = E().forms.make(inp.p, inp.A, inp.B), p = F.p, Fr = new S.Frames();
      const P = (() => { const t = U.parsePoint(inp.P); return { u: t.x, v: t.y }; })(), Q = (() => { const t = U.parsePoint(inp.Q); return { u: t.x, v: t.y }; })();
      const rows = F.rows(), wp = F.weier.points();
      const mpts = rows.filter((r) => r.mont).map((r) => ({ x: r.mont.u, y: r.mont.v })), epts = rows.filter((r) => r.edw).map((r) => r.edw), wpts = wp;
      const s = 256, X0 = [46, 344, 642], Y0 = 120;
      const mk = (C, pts, i, pre) => U.cloud({ p, points: () => pts }, { prefix: pre, x: X0[i], y: Y0, s, points: pts, r: Number(p) > 80 ? 2.2 : 3, grid: false });
      const cm = mk(null, mpts, 0, 'fm'), ce = mk(null, epts, 1, 'fe'), cw = mk(null, wpts, 2, 'fw');
      const wE = (P) => { const q = F.toEdw(P); return q; };
      const heads = [U.head('fm:h', X0[0] - 20, 40, 'Montgomery'), U.t('fm:e', X0[0] - 20, 64, `${F.B}v² = u³ + ${F.A}u² + u`, 'eq', 'start', 15), U.head('fe:h', X0[1] - 20, 40, 'twisted Edwards'), U.t('fe:e', X0[1] - 20, 64, `${F.edw.a}x² + y² = 1 + ${F.edw.d}x²y²`, 'eq', 'start', 15), U.head('fw:h', X0[2] - 20, 40, 'short Weierstrass'), U.t('fw:e', X0[2] - 20, 64, `y² = x³ + ${F.weier.a}x + ${F.weier.b}`, 'eq', 'start', 15)];
      const base = [...heads, ...cm.items, ...ce.items, ...cw.items];
      const sum = F.mont.add(P, Q), R = sum.R;
      const pE = [wE(P), wE(Q), R ? wE(R) : { x: 0n, y: 1n }], pW = [F.toWeier(P), F.toWeier(Q), F.toWeier(R)];
      const dup = P.u === Q.u && P.v === Q.v, names = dup ? ['P', '', '2P'] : ['P', 'Q', 'P + Q'], cls = ['P', 'Q', 'R'];
      const marksOn = (cl, list, n) => cl.marks(list.slice(0, n).map((Pt, j) => ['m' + j, Pt && (Pt.u !== undefined ? { x: Pt.u, y: Pt.v } : Pt), names[j], cls[j], 'ne']).filter((m, j) => m[1] && !(dup && j === 1)), [], 14);
      const lines = (L) => U.eqs('fm:t', 24, 440, L, 15, 27);
      const add = (items, L, say, facts, meta) => Fr.add({ items: [...base, ...items, ...lines(L)], say, facts: Object.assign({ p, A: F.A, B: F.B, P, Q }, facts), meta });
      add([], [[`${mpts.length + 1} points in each form, the identity included`, 'strong'], [`Edwards: a = (A + 2)/B = ${F.edw.a}, d = (A − 2)/B = ${F.edw.d}`], [`Weierstrass: a′ = (3 − A²)/(3B²) = ${F.weier.a}, b′ = (2A³ − 9A)/(27B³) = ${F.weier.b}`]], `One group, three equations over GF(${p}). The Montgomery curve ${F.B}v² = u³ + ${F.A}u² + u has ${mpts.length} points plus O; the twisted Edwards curve with a = ${F.edw.a} and d = ${F.edw.d} and the Weierstrass curve y² = x³ + ${F.weier.a}x + ${F.weier.b} have the same ${mpts.length + 1} points, shuffled.`, { n: mpts.length, N: mpts.length + 1, a: F.edw.a, d: F.edw.d, wa: F.weier.a, wb: F.weier.b }, { stage: 'start' });
      const t = sum.trace[0];
      add(marksOn(cm, [P, Q, R], 3), [[`P = ${uv(P)}, Q = ${uv(Q)}`, 'act'], [t.say.replace(/\.$/, ''), 'hot'], [`P + Q = ${uv(R)}`, 'good']], R ? `On the Montgomery curve the chord-and-tangent rule has its own constants: ${t.say} So P + Q = ${uv(R)}.` : 'Q is the negative of P on the Montgomery curve, so P + Q = O.', { R, lambda: t.lambda }, { stage: 'mont' });
      const eSum = F.edw.add(pE[0], pE[1]).R;
      const okE = pE.every(Boolean) && eSum.x === pE[2].x && eSum.y === pE[2].y;
      add([...marksOn(cm, [P, Q, R], 3), ...marksOn(ce, pE, 3)], [['x = u/v, y = (u − 1)/(u + 1)', 'strong'], [`P ↦ ${P$(pE[0])}, Q ↦ ${P$(pE[1])}`, 'act'], [`P + Q ↦ ${P$(pE[2])}`, 'good'], [okE ? 'the Edwards formula gives the same point' : 'the Edwards sum differs!', okE ? 'good' : 'bad']], `Map each point to the Edwards curve with x = u/v and y = (u − 1)/(u + 1): P ↦ ${P$(pE[0])} and Q ↦ ${P$(pE[1])}. Adding them with the single Edwards formula, x₃ = (x₁y₂ + y₁x₂)/(1 + d·x₁x₂y₁y₂) and y₃ = (y₁y₂ − a·x₁x₂)/(1 − d·x₁x₂y₁y₂), gives ${P$(eSum)}: the image of P + Q.${F.edw.complete ? ` Since a = ${F.edw.a} is a square and d = ${F.edw.d} is not mod ${p}, the denominators are never zero: no special cases at all.` : ''}`, { E: pE, eSum, a: F.edw.a, d: F.edw.d }, { stage: 'edw', ok: okE });
      const wS = F.weier.add(pW[0], pW[1]), okW = F.weier.eq(wS, pW[2]);
      add([...marksOn(cm, [P, Q, R], 3), ...marksOn(ce, pE, 3), ...marksOn(cw, pW, 3)], [[`x = u/B + A/(3B), y = v/B`, 'strong'], [`P ↦ ${P$(pW[0])}, Q ↦ ${P$(pW[1])}`, 'act'], [`P + Q ↦ ${P$(pW[2])}`, 'good'], [okW ? 'the Weierstrass rule agrees' : 'the Weierstrass sum differs!', okW ? 'good' : 'bad']], `And to Weierstrass with x = u/${F.B} + ${F.A}/(3·${F.B}), y = v/${F.B}: P ↦ ${P$(pW[0])}, Q ↦ ${P$(pW[1])}, and the usual chord-and-tangent rule gives ${P$(wS)}, the image of P + Q again.`, { W: pW, wS }, { stage: 'weier', ok: okW });
      const chk = E().forms.check(F);
      add([...marksOn(cm, [P, Q, R], 3), ...marksOn(ce, pE, 3), ...marksOn(cw, pW, 3)], [[`all ${chk.pairs} ordered pairs of points checked`, 'strong'], [chk.ok ? 'every sum agrees in all three forms' : 'some sums disagree', chk.ok ? 'good' : 'bad'], ['Montgomery: the x-only ladder (X25519)'], ['Edwards: one complete formula (Ed25519)'], ['Weierstrass: the standard form (P-256, secp256k1)']], `Not just this pair: for all ${chk.pairs} ordered pairs of points, ${chk.ok ? 'the sum is the same group element in all three forms' : 'something disagrees'}. So a protocol can pick the shape whose arithmetic suits it, and Curve25519 is used both ways: as a Montgomery curve in X25519 and, as the Edwards curve Ed25519, for signatures.`, { pairs: chk.pairs }, { stage: 'all', ok: chk.ok });
      Fr.list.forEach((x) => { x.view = Object.assign({}, U.V); });
      return { frames: Fr.list, def: U.def('Three forms', ['Montgomery: B·v² = u³ + A·u² + u', 'Edwards: a = (A + 2)/B, d = (A − 2)/B; x = u/v, y = (u − 1)/(u + 1)', 'Weierstrass: x = u/B + A/(3B), y = v/B', 'Edwards is complete when a is a square and d is not']) };
    },
    predict: [{ at: (f) => f.meta.stage === 'mont', pick: 'option', ask: 'Map P and Q to the Edwards curve and add them there. What do you get?', options: ['the image of P + Q', 'a different point', 'the identity'], answer: (fr, i) => (fr[i + 1].meta.ok ? 'the image of P + Q' : 'a different point'), explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'What is special about the Edwards addition law when a is a square and d is not?', options: ['it is complete: one formula, no exceptions', 'it is faster than everything', 'it needs no field', 'it only doubles'], answer: 0, why: 'No input makes a denominator zero, so P = Q, P = −P and the identity need no special code.' },
      { q: 'Which form does X25519 use?', options: ['Montgomery', 'Edwards', 'short Weierstrass', 'none'], answer: 0, why: 'The ladder works with u alone.' },
      { q: 'Which form does Ed25519 use?', options: ['twisted Edwards', 'Montgomery', 'Weierstrass', 'a hyperbola'], answer: 0, why: 'Its addition law is complete.' },
      { q: 'Do the three forms have the same number of points?', options: ['yes: they are the same group', 'no', 'only for big p', 'Edwards has fewer'], answer: 0, why: 'The maps are one-to-one on the group.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // P-256 against Curve25519
  // ---------------------------------------------------------------------------------------------------------------
  /** strip the small prime factors of a number; the leftover and whether it is prime */
  const smallPart = (N) => { const out = []; let r = N; for (let q = 2n; q < 300000n; q++) while (r % q === 0n) { out.push(q); r /= q; } return { small: out, rest: r, prime: S.NT.isProbablePrime(r), bits: S.ECC.bitLength(r) }; };
  S.topic({
    id: 'ec-curve-choice', family: 'p10-forms', order: 20, title: 'Choosing a curve: P-256 and Curve25519',
    blurb: 'Two curves at the 128-bit level, side by side. Both have a prime near 2²⁵⁶ and a large prime subgroup. They differ in the shape of the prime, the cofactor, how the twist behaves, whether the formulas have exceptions, how the constants were chosen, and how much work a scalar multiplication takes.',
    inputs: [{ id: 'left', kind: 'choice', label: 'Weierstrass curve', def: 'P-256', options: [{ value: 'P-256', label: 'P-256' }, { value: 'secp256k1', label: 'secp256k1' }] }],
    presets: [{ label: 'P-256 against Curve25519', values: { left: 'P-256' } }, { label: 'secp256k1 against Curve25519', values: { left: 'secp256k1' } }],
    run(inp) {
      const C = E().named(inp.left), Fr = new S.Frames(), X = E().X25519, Ed = E().Ed25519;
      const p2 = X.p, L = Ed.L, N2 = 8n * L;
      const tw1 = smallPart(2n * C.p + 2n - C.n), tw2 = smallPart(2n * p2 + 2n - N2);
      const k = BigInt('0x' + U.hex(S.SHA256.hash(U.utf8('a cost probe'))));
      const w5 = E().scalar.wnaf(C, k % C.n, C.G, 5), xl = X.ladder(k, 9n);
      const isP256 = inp.left === 'P-256';
      const pForm = isP256 ? (C.p === (1n << 256n) - (1n << 224n) + (1n << 192n) + (1n << 96n) - 1n ? '2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1' : '?') : (C.p === (1n << 256n) - (1n << 32n) - 977n ? '2²⁵⁶ − 2³² − 977' : '?');
      const rowsAll = [
        ['equation', isP256 ? 'y² = x³ − 3x + b' : 'y² = x³ + 7', 'v² = u³ + 486662u² + u'],
        ['prime p', pForm, p2 === (1n << 255n) - 19n ? '2²⁵⁵ − 19' : '?'],
        ['#E', `n, cofactor ${C.h}`, '8·L, cofactor 8'],
        ['prime subgroup', S.ECC.bitLength(C.n) + ' bits', S.ECC.bitLength(L) + ' bits'],
        ['twist order', tw1.small.join('·') + '·(' + tw1.bits + '-bit ' + (tw1.prime ? 'prime' : 'composite') + ')', tw2.small.join('·') + '·(' + tw2.bits + '-bit ' + (tw2.prime ? 'prime' : 'composite') + ')'],
        ['addition law', 'exceptions: P = Q, P = −P, O', 'complete (as Edwards)'],
        ['constants', isP256 ? 'b from a hash of an unexplained seed' : 'b = 7, the simplest choice', 'smallest A meeting stated rules'],
        ['k·P cost', `${w5.cost.M}M + ${w5.cost.S}S (wNAF)`, `${xl.cost.M}M + ${xl.cost.S}S (ladder)`],
        ['public key', '33 bytes compressed', '32 bytes (u only)'],
      ];
      const cols = [{ w: 170, head: '', mono: false, align: 'left' }, { w: 360, head: inp.left, mono: false }, { w: 330, head: 'Curve25519', mono: false }];
      const tbl = (n, hl) => U.table({ prefix: 'cc:t', x: 30, y: 60, cols, rows: rowsAll.slice(0, n).map((r, i) => r.map((c, j) => ({ text: c, cls: j === 0 ? 'head' : '' }))), rh: 46, size: 14, hl: (i) => (i >= hl ? 'act' : '') }).items;
      const head = U.head('cc:h', 30, 28, `${inp.left} and Curve25519`);
      const add = (n, hl, say, facts) => Fr.add({ items: [head, ...tbl(n, hl)], say, facts: Object.assign({ std: [256, 255, 19, 8, 486662, 33, 32, 7, 3] }, facts), meta: { stage: 'row' + n } });
      add(2, 0, `Both curves work over a prime field of about 256 bits. ${inp.left} uses ${isP256 ? 'a special prime, 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1, whose 32-bit pieces make reduction fast on 32-bit machines' : 'the prime 2²⁵⁶ − 2³² − 977, close to a power of 2'}; Curve25519 uses 2²⁵⁵ − 19, which makes reduction a multiplication by 19.`, {});
      add(4, 2, `${inp.left} has cofactor ${C.h}: the whole group, ${S.ECC.bitLength(C.n)} bits, has prime order. Curve25519 has 8·L points with L a ${S.ECC.bitLength(L)}-bit prime, so a careless protocol can meet points of order 2, 4 or 8; X25519 clamps its scalars and Ed25519 multiplies by 8 when verifying.`, { h: C.h, nb: S.ECC.bitLength(C.n), lb: S.ECC.bitLength(L) });
      add(5, 4, `The twist, the curve's partner that x-only code may stumble onto, has 2p + 2 − #E points. For ${inp.left} that is ${tw1.small.join('·')} times a ${tw1.bits}-bit ${tw1.prime ? 'prime' : 'number'}; for Curve25519, ${tw2.small.join('·')} times a ${tw2.bits}-bit ${tw2.prime ? 'prime' : 'number'}. Curve25519 was chosen so that its twist is strong too, which is why X25519 can accept any 32 bytes.`, { s1: tw1.small, b1: tw1.bits, s2: tw2.small, b2: tw2.bits });
      add(7, 5, `The Weierstrass addition needs special cases for doubling, for P + (−P) and for O, and each special case is a branch that can leak or be forgotten. Curve25519 in Edwards form has one complete formula. Its constant A = 486662 is the smallest that meets a published list of conditions, while ${isP256 ? 'P-256\'s b comes from hashing a seed whose origin was never explained' : 'secp256k1 simply takes b = 7'}.`, {});
      add(9, 7, `The work for one scalar multiplication, counted by the engines for the same 256-bit k: ${inp.left} with a width-5 NAF takes ${w5.cost.M} multiplications and ${w5.cost.S} squarings, the X25519 ladder ${xl.cost.M}M + ${xl.cost.S}S, constant-time and with no table. A public key is 33 bytes compressed against 32. Both give about 128-bit security: the best attack is Pollard's rho, near 2¹²⁸ steps.`, { M1: w5.cost.M, S1: w5.cost.S, M2: xl.cost.M, S2: xl.cost.S });
      Fr.list.forEach((x) => { x.view = Object.assign({}, U.V); });
      return { frames: Fr.list, def: U.def('What to compare', ['the prime: fast reduction', 'cofactor 1, or a cofactor handled by the protocol', 'a twist with a large prime factor', 'complete formulas, constant time', 'constants that are explained']) };
    },
    predict: [{ at: (f) => f.meta.stage === 'row2', pick: 'option', ask: 'Which curve has a cofactor bigger than 1?', options: ['Curve25519', 'the Weierstrass curve', 'both', 'neither'], answer: 'Curve25519', explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'Why does 2²⁵⁵ − 19 make arithmetic fast?', options: ['2²⁵⁵ ≡ 19, so reducing is a multiply by 19 and an add', 'it is small', 'it is even', 'it has no inverse'], answer: 0, why: 'High bits fold back down multiplied by 19.' },
      { q: 'What is the cofactor of Curve25519?', options: ['8', '1', '4', '19'], answer: 0, why: '#E = 8·L.' },
      { q: 'Why should the twist also be secure?', options: ['x-only code accepts any u, and some u lie on the twist', 'the twist is used for signatures', 'to double the key size', 'it need not be'], answer: 0, why: 'See the twist attack topic.' },
      { q: 'About how many steps does the best known attack on either curve take?', options: ['2¹²⁸', '2²⁵⁶', '2⁶⁴', '2³²'], answer: 0, why: 'Pollard rho needs about √n.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Point compression
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-compress', family: 'p10-forms', order: 30, title: 'Point compression',
    blurb: 'For each x there are at most two points, (x, y) and (x, p − y), and since p is odd exactly one of the two y values is even. So a point can be sent as x and one bit: prefix 02 for an even y, 03 for odd. The receiver solves y² = x³ + ax + b for y with a square root and picks the root with the right parity.',
    inputs: [
      { id: 'curve', kind: 'choice', label: 'Curve', def: 'gf101', options: [{ value: 'gf101', label: 'toy: GF(101)' }, { value: 'P-256', label: 'P-256' }, { value: 'secp256k1', label: 'secp256k1' }] },
      { id: 'd', kind: 'text', label: 'The point is d·G for d =', def: '29', check: (v, inp) => { if (!/^\d+$/.test(String(v).trim())) return 'd: a whole number'; const C = /^gf/.test(inp.curve) ? E().toy(inp.curve) : E().named(inp.curve); const d = BigInt(String(v).trim()); return d < 1n || d >= C.n ? 'd: from 1 to n − 1' : null; } },
    ],
    presets: [
      { label: 'Toy: 29·G', values: { curve: 'gf101', d: '29' } },
      { label: 'Toy: 3·G', values: { curve: 'gf101', d: '3' } },
      { label: 'P-256: 2025·G', values: { curve: 'P-256', d: '2025' } },
      { label: 'secp256k1: 31337·G', values: { curve: 'secp256k1', d: '31337' } },
    ],
    run(inp) {
      const C = /^gf/.test(inp.curve) ? E().toy(inp.curve) : E().named(inp.curve), d = BigInt(String(inp.d).trim()), Q = C.mul(d, C.G), F = new S.Frames();
      const L = C.size, un = C.encode(Q, false), co = C.encode(Q, true), dec = C.decode(co), neg = C.neg(Q);
      const hx = (b) => U.hex(b), toy = C.toy;
      const head = U.head('pc:h', 30, 28, `Point compression on ${C.name}`);
      const segs = (bytes, y, parts) => { let x = 30; const items = []; parts.forEach(([n, label, cls], i) => { const w = toy ? 120 : (n === 1 ? 70 : 380); const piece = hx(bytes.subarray(parts.slice(0, i).reduce((s, q) => s + q[0], 0), parts.slice(0, i + 1).reduce((s, q) => s + q[0], 0))); items.push({ key: 'pc:s' + y + ':' + i, kind: 'cell', x, y, w, h: 54, rx: 4, lines: [label, n > 6 ? U.hs(piece, 8) : piece], size: 13, cls: 'e10-cell mono ' + cls }); x += w + 4; }); return items; };
      const cloud = (marks) => (toy ? (() => { const cl = U.cloud(C, { prefix: 'pc:c', x: 560, y: 250, s: 330, r: 2.6, grid: false }); return [...cl.items, ...cl.hline('pc:half', Number(C.p) / 2), ...cl.marks(marks, [], 14)]; })() : []);
      F.add({ items: [head, U.t('pc:u', 30, 70, `uncompressed: ${un.length} bytes`, 'e10-note', 'start', 13), ...segs(un, 80, [[1, 'prefix', 'act'], [L, 'x', ''], [L, 'y', 'key']]), ...cloud([['Q', Q, 'Q', 'R', 'ne']])], say: `The point Q = ${d}·G = ${P$(Q)}. Sent in full it is 04 ‖ x ‖ y: ${un.length} bytes.`, facts: { d, Q, len: un.length }, meta: { stage: 'full' } });
      const par = Number(Q.y & 1n);
      F.add({ items: [head, U.t('pc:u', 30, 70, `uncompressed: ${un.length} bytes`, 'e10-note', 'start', 13), ...segs(un, 80, [[1, 'prefix', 'act'], [L, 'x', ''], [L, 'y', 'key']]), U.t('pc:c', 30, 170, `compressed: ${co.length} bytes`, 'e10-note', 'start', 13), ...segs(co, 180, [[1, 'prefix', 'hot'], [L, 'x', '']]), ...U.eqs('pc:e', 30, 270, [[`y = ${f(Q.y)} is ${par ? 'odd' : 'even'}: prefix 0${co[0]}`, 'hot'], [`the other point, (x, p − y), has an ${par ? 'even' : 'odd'} y`]], 15, 28), ...cloud([['Q', Q, 'Q', 'R', 'ne'], ['N', neg, '−Q', 'Q', 'ne']])], say: `For this x the curve has two points, Q and −Q = (x, p − y), and since p is odd their y values have different parities. Q's y is ${par ? 'odd' : 'even'}, so keep x and the prefix 0${co[0]}: ${co.length} bytes instead of ${un.length}.`, facts: { y: Q.y, len: co.length, len2: un.length, pre: co[0] }, meta: { stage: 'compress', par } });
      const rhs = dec.trace.find((x) => x.kind === 'rhs'), sq = dec.trace.find((x) => x.kind === 'sqrt'), pr = dec.trace.find((x) => x.kind === 'parity');
      F.add({ items: [head, U.t('pc:c', 30, 70, `received: ${co.length} bytes`, 'e10-note', 'start', 13), ...segs(co, 80, [[1, 'prefix', 'hot'], [L, 'x', '']]), ...U.eqs('pc:e', 30, 190, [[`y² = x³ + ax + b = ${f(rhs.rhs)}`, 'strong'], [`a square root: ${f(sq.y)}; the other: ${f(md(-sq.y, C.p))}`], [`prefix 0${co[0]}: take the ${co[0] === 2 ? 'even' : 'odd'} one, y = ${f(pr.y)}`, 'good'], [C.eq(dec.P, Q) ? 'the point is Q again' : 'wrong point!', C.eq(dec.P, Q) ? 'good' : 'bad']], 15, 30), ...cloud([['Q', dec.P, 'Q', 'R', 'ne'], ['N', neg, '', 'Q', 'ne']])], say: `To decompress, compute y² = x³ + ax + b = ${f(rhs.rhs)} and take a square root mod p, ${f(sq.y)} (for p ≡ 3 mod 4 it is (y²)^((p+1)/4), otherwise a slightly longer algorithm). The other root is p minus it. The prefix asks for ${co[0] === 2 ? 'an even' : 'an odd'} y, so y = ${f(pr.y)}, and Q is back.`, facts: { rhs: rhs.rhs, r1: sq.y, r2: md(-sq.y, C.p), y: pr.y, pre: co[0] }, meta: { stage: 'decode' } });
      // an x that is on no point
      let xb = Q.x + 1n; while (C.sqrt(C.rhs(xb % C.p)) !== null) xb++;
      xb %= C.p;
      const bad = C.encode({ x: xb, y: 0n }, true), db = C.decode(bad), r2 = db.trace.find((x) => x.kind === 'rhs');
      F.add({ items: [head, U.t('pc:c', 30, 70, 'received: a different x', 'e10-note', 'start', 13), ...segs(bad, 80, [[1, 'prefix', 'hot'], [L, 'x', 'bad']]), ...U.eqs('pc:e', 30, 190, [[`x = ${f(xb)}: y² would be ${f(r2.rhs)}`, 'strong'], [`${f(r2.rhs)} is not a square mod p`, 'bad'], ['no point has this x: reject', 'bad']], 15, 30), ...cloud(toy ? [['X', { x: xb, y: 0n }, 'x has no point', 'third', 'n']] : [])], say: `Not every x has a point. For x = ${f(xb)}, x³ + ax + b = ${f(r2.rhs)}, which is not a square mod p: about half of all x fail like this. The decoder must reject the point, not pass a made-up y along; checking that a received point really is on the curve is the defence in the validation attacks.`, facts: { x: xb, rhs: r2.rhs }, meta: { stage: 'reject' } });
      U.fix(F.list);
      return { frames: F.list, def: U.def('SEC 1 encoding', ['04 ‖ x ‖ y: uncompressed', '02 ‖ x: y even;  03 ‖ x: y odd', 'decode: y = √(x³ + ax + b) mod p, pick the parity', 'no square root: not a point, reject']) };
    },
    predict: [{ at: (f) => f.meta.stage === 'full', pick: 'option', ask: 'Which prefix will the compressed point have?', options: ['02', '03', '04'], answer: (fr, i) => '0' + fr[i + 1].facts.pre, explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'Why is one bit enough to choose y?', options: ['y and p − y have different parities, since p is odd', 'y is always even', 'the curve is symmetric about x', 'it is not enough'], answer: 0, why: 'Their sum is p, which is odd.' },
      { q: 'A compressed P-256 point is…', options: ['33 bytes', '65 bytes', '32 bytes', '64 bytes'], answer: 0, why: 'One prefix byte and 32 bytes of x.' },
      { q: 'What fraction of x values have a point?', options: ['about half', 'all', 'about a quarter', 'none'], answer: 0, why: 'x³ + ax + b is a square for about half the x.' },
      { q: 'What must a decoder do with an x that has no point?', options: ['reject it', 'use y = 0', 'pick a random y', 'add 1 to x'], answer: 0, why: 'Anything else invites invalid-curve attacks.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
