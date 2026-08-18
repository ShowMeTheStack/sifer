// Part 3: Berlekamp–Massey, which reads a stretch of output and returns the shortest LFSR that makes it, one bit at
// a time (a discrepancy, and a correction of C(x) when the prediction fails); and the three kinds of random number
// generator side by side: a biased physical source made fair, a fast formula an attacker can solve, and a stream
// cipher that nobody can predict without its key.
(function (S) {
  'use strict';
  const U = S.SymT, LF = () => S.LFSR;
  const xp = (k) => (k === 1 ? 'x' : 'x' + U.sup(k));
  /** a connection polynomial (BigInt mask) as text, 1 first */
  const pstr = (p) => { const t = []; for (let k = 0; (p >> BigInt(k)) > 0n; k++) if ((p >> BigInt(k)) & 1n) t.push(k === 0 ? '1' : xp(k)); return t.join(' + '); };
  const bitOf = (p, i) => Number((p >> BigInt(i)) & 1n);
  const seqOf = (taps, seed, n) => (S.LFSR ? S.LFSR.sequence(taps, seed.split('').map(Number), n).join('') : '');

  // ---------------------------------------------------------------------------------------------------------------
  // Berlekamp–Massey
  // ---------------------------------------------------------------------------------------------------------------
  function bm(inp) {
    const s = U.toBits(inp.bits), N = s.length, res = LF().berlekampMassey(s), steps = res.steps;
    const F = new S.Frames(), head = U.head('bm:h', 'Berlekamp–Massey on ' + N + ' bits');
    const cw = Math.min(34, Math.floor(780 / N) - 2), x0 = 104;
    const bitsRow = (n, used) => {
      const items = [U.t('bm:sl', 24, 92, 's', 'strong', 'start', 18)];
      s.forEach((b, i) => items.push({ key: 'bm:b' + i, kind: 'cell', x: x0 + i * (cw + 2), y: 66, w: cw, h: 36, rx: 3, text: String(b), size: 16, cls: 'bit ' + (b ? 'one' : 'zero') + (i === n ? ' hot' : used.includes(i) ? ' act' : i > n ? ' soft' : '') }));
      for (let i = 0; i < N; i += 4) items.push(U.t('bm:ix' + i, x0 + i * (cw + 2) + cw / 2, 58, String(i), 'tick', 'middle', 13));
      return items;
    };
    // L after each bit, as a staircase against n/2
    const maxL = Math.max(2, res.L, Math.ceil(N / 2));
    const plot = (upto) => {
      const px = 500, py = 182, pw = 370, ph = 150, X = (n) => U.r2(px + (n / N) * pw), Y = (l) => U.r2(py + ph - (l / maxL) * ph);
      const items = [...U.panel('bm:pl', 468, 124, 428, 244, 'the length L after each bit')];
      items.push({ key: 'bm:ax', kind: 'path', d: `M${px},${py} V${py + ph} H${px + pw}`, cls: 'axis', audit: 'ignore', layer: 'back', box: { x: px, y: py, w: pw, h: ph } });
      items.push({ key: 'bm:half', kind: 'path', d: `M${X(0)},${Y(0)} L${X(N)},${Y(N / 2)}`, cls: 'dline soft', audit: 'ignore' });
      items.push(U.t('bm:hl', px + pw, Y(N / 2) - 8, 'n / 2', 'tick', 'end', 13));
      for (const l of [0, Math.round(maxL / 2), maxL]) items.push(U.t('bm:ty' + l, px - 8, Y(l) + 5, String(l), 'tick', 'end', 13));
      for (const n of [0, N]) items.push(U.t('bm:tx' + n, X(n), py + ph + 20, String(n), 'tick', 'middle', 13));
      items.push(U.t('bm:xl', px + pw / 2, py + ph + 20, 'bits read', 'tick', 'middle', 13));
      if (upto >= 0) {
        let d = `M${X(0)},${Y(0)}`, cur = 0;
        for (let n = 0; n <= upto; n++) { const l = steps[n].L; if (l !== cur) { d += ` H${X(n)} V${Y(l)}`; cur = l; } }
        d += ` H${X(upto + 1)}`;
        items.push({ key: 'bm:st', kind: 'path', d, cls: 'dline act', pathAudit: 'edge-x' });
      }
      return items;
    };
    const table = (upto) => {
      const items = [...U.panel('bm:tb', 24, 384, 872, 232, 'C(x), bit by bit')];
      const cols = [44, 104, 154, 204, 810];
      ['n', 'sₙ', 'd', 'C(x) after', 'L'].forEach((t, j) => items.push(U.t('bm:th' + j, j === 4 ? 860 : cols[j], 432, t, 'tick', j === 4 ? 'end' : 'start', 13)));
      for (let n = Math.max(0, upto - 5); n <= upto; n++) {
        const y = 462 + (n - Math.max(0, upto - 5)) * 26, st = steps[n], cur = n === upto;
        items.push(U.t('bm:tn' + n, cols[0], y, String(n), cur ? 'act' : 'mono', 'start', 14), U.t('bm:ts' + n, cols[1], y, String(st.s), 'mono', 'start', 14), U.t('bm:td' + n, cols[2], y, String(st.d), st.d ? 'hot' : 'mono', 'start', 14), U.t('bm:tc' + n, cols[3], y, pstr(st.C), cur ? 'act' : 'math', 'start', 14), U.t('bm:tl' + n, 860, y, String(st.L), cur ? 'act' : 'mono', 'end', 14));
      }
      return items;
    };
    F.add({ items: [head, ...bitsRow(-1, []), ...U.panel('bm:sp', 24, 124, 428, 244, 'start'), U.t('bm:s0', 44, 180, 'C(x) = 1,  L = 0', 'math', 'start', 18), U.t('bm:s1', 44, 216, 'B(x) = 1: the last C before L grew', 'tick', 'start', 14), U.t('bm:s2', 44, 246, 'read the bits left to right', 'tick', 'start', 14), ...plot(-1), ...U.panel('bm:tb', 24, 384, 872, 232, 'C(x), bit by bit')],
      say: `${N} output bits from an unknown LFSR. Berlekamp–Massey keeps the shortest register that explains the bits read so far: its connection polynomial C(x) and length L, starting from C(x) = 1 and L = 0, which predicts nothing but zeros.`, facts: { N }, meta: { stage: 'start' } });
    let Cp = 1n, Lp = 0, Bp = 1n, mp = -1;
    steps.forEach((st, n) => {
      const used = []; for (let i = 1; i <= Lp; i++) if (bitOf(Cp, i)) used.push(n - i);
      const terms = ['s' + U.sub(n)].concat(used.map((j) => 's' + U.sub(j))), vals = [s[n]].concat(used.map((j) => s[j]));
      const shift = n - mp, grew = st.L !== Lp;
      const lines = [[(used.length ? 'd = ' + terms.join(' ⊕ ') : 'd = s' + U.sub(n)), 'math', 18], ['  = ' + (vals.length > 1 ? vals.join(' ⊕ ') + ' = ' : '') + st.d, st.d ? 'math hot' : 'math', 18]];
      if (st.d) { lines.push(['C(x) ← ' + pstr(Cp) + ' + ' + (shift === 1 ? 'x' : xp(shift)) + '·(' + pstr(Bp) + ')', 'math', pstr(Cp).length + pstr(Bp).length > 26 ? 13 : 15]); lines.push(['= ' + pstr(st.C), 'math act', pstr(st.C).length > 30 ? 15 : 17]); lines.push([grew ? `L: ${Lp} → ${st.L}  (2L ≤ n, so it must grow)` : `L stays ${st.L}`, grew ? 'hot' : 'tick', 14]); }
      else { lines.push(['C(x) predicted sₙ: nothing changes', 'good', 15]); lines.push(['C(x) = ' + pstr(st.C) + ',  L = ' + st.L, 'math act', 16]); }
      const pane = [...U.panel('bm:sp', 24, 124, 428, 244, 'bit ' + n), ...lines.map(([t, c, z], j) => U.t('bm:s' + j, 44, 172 + j * 40, t, c, 'start', z))];
      const pred = vals.slice(1).reduce((a, b) => a ^ b, 0);
      const say = st.d === 0
        ? `Bit ${n} is ${s[n]}, and C(x) = ${pstr(Cp)} predicts ${pred}: discrepancy 0, so C(x) and L = ${Lp} stand.`
        : `Bit ${n} is ${s[n]}, but C(x) = ${pstr(Cp)} predicts ${pred}: discrepancy 1. Add ${shift === 1 ? 'x' : xp(shift)}·B(x), the polynomial saved when L last grew, shifted to line up with this bit: C(x) becomes ${pstr(st.C)}.` + (grew ? ` A register of length ${Lp} cannot fit these ${n + 1} bits, so L grows to n + 1 − L = ${st.L}.` : ` L stays ${st.L}.`);
      F.add({ items: [head, ...bitsRow(n, used), ...pane, ...plot(n), ...table(n)], hl: { d: st.d ? (grew ? [2, 3] : [2]) : [1] }, say, facts: { n, s: s[n], d: st.d, pred, C: pstr(st.C), Cp: pstr(Cp), B: pstr(Bp), shift, L: st.L, Lp, n1: n + 1 }, meta: { stage: 'step', n, d: st.d } });
      if (st.d && grew) { Bp = Cp; mp = n; }
      Cp = st.C; Lp = st.L;
    });
    // check: the register found regenerates the bits
    const taps = res.taps, L = res.L, regen = L ? LF().sequence(taps.length ? taps : [L], s.slice(0, L), N) : new Array(N).fill(0);
    const ok = regen.join('') === s.join(''), unique = N >= 2 * L;
    const fin = [head, ...bitsRow(N, []), ...U.panel('bm:sp', 24, 124, 428, 244, 'the register found'),
      U.t('bm:s0', 44, 172, 'C(x) = ' + pstr(res.poly), 'act', 'start', pstr(res.poly).length > 28 ? 15 : 18), U.t('bm:s1', 44, 212, 'length L = ' + L, 'act', 'start', 17),
      U.t('bm:s2', 44, 252, 'seed: the first L bits', 'tick', 'start', 14), U.t('bm:s3', 44, 290, ok ? 'regenerates all ' + N + ' bits' : 'does not regenerate the bits', ok ? 'good' : 'bad', 'start', 16),
      U.t('bm:s4', 44, 326, unique ? N + ' ≥ 2L: the answer is unique' : N + ' < 2L: more bits are needed to be sure', unique ? 'tick' : 'bad', 'start', 14),
      ...plot(N - 1), ...table(N - 1)];
    F.add({ items: fin, hl: { d: [4] }, say: `The shortest LFSR that makes these ${N} bits has length ${L} and C(x) = ${pstr(res.poly)}; seeded with the first ${L} bits it ${ok ? 'regenerates every one of them' : 'fails to regenerate them'}. ` + (unique ? `Since ${N} ≥ 2L = ${2 * L}, it is the only such register: 2L bits of output give away an LFSR completely, which is why a bare LFSR is never a cipher.` : `With fewer than 2L = ${2 * L} bits another register of the same length might fit as well; read more bits to be sure.`), facts: { N, L, L2: 2 * L, C: pstr(res.poly), ok, unique }, meta: { stage: 'end', ok } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 626 });
    return { frames: F.list, def: U.def('Berlekamp–Massey', ['start: C(x) = 1, B(x) = 1, L = 0, m = −1', 'd = sₙ ⊕ c₁sₙ₋₁ ⊕ … ⊕ c_L·sₙ₋L', 'd = 0: keep C(x)', 'd = 1: C(x) ← C(x) + x^(n−m)·B(x); if 2L ≤ n: L ← n + 1 − L, B ← old C, m ← n', 'L is the linear complexity; 2L bits fix the register']) };
  }
  const bmPresets = () => [
    { label: '8 bits of 1 + x³ + x⁴', values: { bits: seqOf([4, 3], '1000', 8) } },
    { label: '10 bits of 1 + x³ + x⁵', values: { bits: seqOf([5, 3], '10110', 10) } },
    { label: '14 bits of a 6-cell register', values: { bits: seqOf([6, 4, 3, 1], '110010', 14) } },
    { label: 'A late 1: 00000001', values: { bits: '00000001' } },
    { label: '16 bits from a coin', values: { bits: '1101011100100110' } },
    { label: 'Too few bits: 5 of a 4-cell register', values: { bits: seqOf([4, 1], '1011', 5) } },
  ];
  S.topic({
    id: 'st-bm', family: 'p03-lfsr', order: 50, title: 'Berlekamp–Massey: an LFSR from 2n bits',
    blurb: 'Read the bits one by one, keep the shortest register that explains them, and fix it whenever it mispredicts. After 2L bits the register is known for certain.',
    inputs: [{ id: 'bits', kind: 'string', label: 'Output bits', def: '10001001', alphabet: '01', check: (v) => U.bitsCheck('Bits', 4, 24)(v) || (/1/.test(v) ? null : 'Bits: at least one 1 (all zeros come from the empty register)') }],
    presets: bmPresets(),
    run: bm,
    predict: [
      { at: (f, i, fr) => f.meta && f.meta.stage === 'step' && i + 1 < fr.length && fr[i + 1].meta.stage === 'step' && f.meta.n >= 2, once: true, pick: 'option', options: ['0', '1'], ask: 'Use C(x) as it stands now to predict the next bit. Will the discrepancy be 0 or 1?', answer: (fr, i) => String(fr[i + 1].facts.d), explain: 'XOR the bit with the earlier bits that C(x) taps; 0 means the prediction held.' },
      { at: (f) => f.meta && f.meta.stage === 'start', once: true, pick: 'option', options: (fr) => { const N = fr[0].facts.N; return [...new Set(['1', '2', String(Math.max(1, Math.floor(N / 4))), String(fr[fr.length - 1].facts.L), String(Math.ceil(N / 2)), String(N)])].sort((a, b) => a - b); }, ask: 'How long will the shortest register be?', answer: (fr) => String(fr[fr.length - 1].facts.L), explain: 'The final length L is the linear complexity of the bits.' },
    ],
    quiz: [
      { q: 'How many output bits does Berlekamp–Massey need to pin down an LFSR of length L for certain?', options: ['L', '2L', 'L²', '2^L'], answer: 1, why: 'With 2L bits the shortest register is unique.' },
      { q: 'What does a discrepancy of 0 at bit n mean?', options: ['The bit is 0', 'The current C(x) predicted the bit correctly', 'The register must grow', 'The algorithm stops'], answer: 1, why: 'd is the bit XOR the prediction from the earlier bits.' },
      { q: 'When the discrepancy is 1 and 2L ≤ n, the new length is…', options: ['L + 1', 'n + 1 − L', '2L', 'n'], answer: 1, why: 'A register of length L cannot fit; the shortest that can has length n + 1 − L.' },
      { q: 'The bits 0000000 1 (seven zeros, then a one) need a register of length…', options: ['1', '2', '7', '8'], answer: 3, why: 'Any shorter register fed seven zeros keeps giving zeros, so L = 8.' },
      { q: 'Why does Berlekamp–Massey make a lone LFSR useless as a keystream generator?', options: ['It is too slow to run', 'From 2L known keystream bits, for example under a known plaintext, it recovers the whole register', 'It needs the key', 'It only works on primitive polynomials'], answer: 1, why: 'Known plaintext gives keystream bits; 2L of them give the register.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // True, pseudo and cryptographically secure
  // ---------------------------------------------------------------------------------------------------------------
  const M = 251;
  function rng(inp) {
    const seed = inp.seed, bias = Number(inp.bias), [a, c] = inp.lcg.split(',').map(Number);
    const r = S.Sym.rng(seed), raw = Array.from({ length: 32 }, () => (r() < bias ? 1 : 0)), ones = raw.filter((b) => b).length;
    // von Neumann: pairs 01 → 0, 10 → 1, 00 and 11 dropped
    const pairs = []; for (let i = 0; i + 1 < raw.length; i += 2) pairs.push([raw[i], raw[i + 1]]);
    const vn = pairs.filter(([p, q]) => p !== q).map(([p]) => p), vnOnes = vn.filter((b) => b).length;
    // the LCG
    const lcg = [seed % M]; while (lcg.length < 12) lcg.push((a * lcg[lcg.length - 1] + c) % M);
    const [x0, x1, x2] = lcg, inv = Number(S.NT.inv(BigInt(((x1 - x0) % M + M) % M), BigInt(M)));
    const ga = (((x2 - x1) % M + M) % M) * inv % M, gc = ((x1 - ga * x0) % M + M) % M;
    const pred = lcg.slice(0, 3); while (pred.length < 12) pred.push((ga * pred[pred.length - 1] + gc) % M);
    const right = pred.slice(3).filter((v, i) => v === lcg[3 + i]).length;
    // the CSPRNG: ChaCha20 with a key from the seed
    const key = S.Sym.bytes(S.Sym.rng(seed * 7919 + 1), 32), nonce = new Uint8Array(12);
    const b0 = S.ChaCha.block(key, 0, nonce).out.slice(0, 16), b1 = S.ChaCha.block(key, 1, nonce).out.slice(0, 16);
    const F = new S.Frames(), head = U.head('rg:h', 'Three ways to get random bits');
    const lane = (k, y, title, sub, on, verdict) => [
      { key: 'rg:ln' + k, kind: 'region', x: 24, y, w: 872, h: 172, rx: 10, cls: on ? 'act' : 'panel' },
      { key: 'rg:bx' + k, kind: 'state', x: 112, y: y + 70, w: 156, h: 66, rx: 8, size: 14, lines: title, cls: 'block ' + (on ? 'cipher' : 'soft') },
      U.t('rg:sb' + k, 112, y + 124, sub, 'tick', 'middle', 13),
      verdict ? U.t('rg:vd' + k, 112, y + 152, verdict[0], verdict[1], 'middle', 14) : null,
    ].filter(Boolean);
    const bitsCells = (P, x, y, bits, cls) => U.bitRow({ prefix: P, x, y, bits, cw: 16, ch: 24, gap: 1, group: 2, groupGap: 4, size: 13, cls }).items;
    const L1 = 60, L2 = 248, L3 = 436;
    const lanes = (on, show, verdicts) => {
      const v = verdicts || [];
      const it = [head, ...lane(1, L1, ['true', 'random'], 'a physical noise source', on === 1, v[0]), ...lane(2, L2, ['pseudo-', 'random'], 'a short formula, a seed', on === 2, v[1]), ...lane(3, L3, ['crypto-', 'graphically secure'], 'a cipher keyed by a secret', on === 3, v[2])];
      if (show.raw) { it.push(U.t('rg:rt', 210, L1 + 30, 'raw bits: ' + ones + ' ones in ' + raw.length, 'strong', 'start', 14), ...bitsCells('rgr', 210, L1 + 42, raw, (i) => (show.vn ? (raw[i - (i % 2)] !== raw[i - (i % 2) + 1] ? 'act' : 'soft') : ''))); }
      if (show.vn) { it.push(U.t('rg:vt', 210, L1 + 98, 'kept (01 → 0, 10 → 1): ' + vnOnes + ' ones in ' + vn.length, 'strong', 'start', 14), ...bitsCells('rgv', 210, L1 + 110, vn, () => 'act')); }
      if (show.lcg) { it.push(U.t('rg:lt', 210, L2 + 30, 'xₙ₊₁ = ' + a + '·xₙ + ' + c + ' mod ' + M, 'math', 'start', 15), ...U.cells({ prefix: 'rgl', x: 210, y: L2 + 42, cw: 50, ch: 34, gap: 4, values: lcg, text: (x) => String(x), size: 15, cls: (i) => (show.pred && i < 3 ? 'key' : '') })); }
      if (show.pred) { it.push(U.t('rg:pt', 210, L2 + 104, 'predicted from the first three: a = ' + ga + ', c = ' + gc, 'strong', 'start', 14), ...U.cells({ prefix: 'rgp', x: 210, y: L2 + 116, cw: 50, ch: 34, gap: 4, values: pred, text: (x, i) => (i < 3 ? '' : String(x)), size: 15, cls: (i) => (i < 3 ? 'soft' : pred[i] === lcg[i] ? 'good' : 'bad') })); }
      if (show.cs) { it.push(U.t('rg:ct', 210, L3 + 30, 'ChaCha20 keystream, block 0', 'strong', 'start', 14), ...U.cells({ prefix: 'rgc', x: 210, y: L3 + 42, cw: 38, ch: 34, gap: 4, values: Array.from(b0), text: U.h2, size: 15, cls: () => 'key' })); }
      if (show.cs2) { it.push(U.t('rg:c2', 210, L3 + 104, 'block 1: no shortcut from block 0 to these', 'strong', 'start', 14), ...U.cells({ prefix: 'rgd', x: 210, y: L3 + 116, cw: 38, ch: 34, gap: 4, values: Array.from(b1), text: U.h2, size: 15, cls: () => 'hot' })); }
      return it;
    };
    F.add({ items: lanes(0, {}), say: `Three kinds of generator. A true one measures something physical; a pseudo-random one stretches a seed with a formula; a cryptographically secure one is a cipher run on a secret key. All three print bits that look alike; what differs is who can predict them.`, facts: {}, meta: { stage: 'start' } });
    F.add({ items: lanes(1, { raw: 1 }), hl: { d: [0] }, say: `A physical source, here a simulated one that gives 1 with probability ${bias}: ${ones} ones in ${raw.length} bits. Real noise is unpredictable but rarely fair, so it is never used raw.`, facts: { bias, ones, n: raw.length }, meta: { stage: 'raw' } });
    F.add({ items: lanes(1, { raw: 1, vn: 1 }), hl: { d: [0] }, say: `Von Neumann's fix: read the bits in pairs, output 0 for 01 and 1 for 10, and drop 00 and 11. Both kept pairs are equally likely whatever the bias, so the ${vn.length} kept bits (${vnOnes} ones) are fair, at the cost of throwing most of the bits away.`, facts: { kept: vn.length, vnOnes }, meta: { stage: 'vn' } });
    F.add({ items: lanes(2, { raw: 1, vn: 1, lcg: 1 }), hl: { d: [1] }, say: `A linear congruential generator: x₀ = ${x0} and xₙ₊₁ = ${a}·xₙ + ${c} mod ${M} gives ${lcg.slice(1, 6).join(', ')} and so on. Fast, repeatable from its seed, and good enough for a simulation.`, facts: { x0, a, c, M, lcg }, meta: { stage: 'lcg' } });
    F.add({ items: lanes(2, { raw: 1, vn: 1, lcg: 1, pred: 1 }), hl: { d: [1] }, say: `But it is no secret. From three outputs ${x0}, ${x1}, ${x2}: a = (${x2} − ${x1}) / (${x1} − ${x0}) mod ${M} = ${ga} and c = ${x1} − a·${x0} mod ${M} = ${gc}. With those, ${right} of the next ${pred.length - 3} outputs are predicted exactly. An LFSR falls the same way, to Berlekamp–Massey.`, facts: { x0, x1, x2, ga, gc, M, right, n9: pred.length - 3 }, meta: { stage: 'pred' } });
    F.add({ items: lanes(3, { raw: 1, vn: 1, lcg: 1, pred: 1, cs: 1 }), hl: { d: [2] }, say: `A cryptographically secure generator: ChaCha20 under a secret 256-bit key, counter 0, gives ${U.hexs(b0.slice(0, 4))} … From outside these bytes cannot be told from coin flips.`, facts: { b0: U.hexs(b0.slice(0, 4)) }, meta: { stage: 'cs' } });
    F.add({ items: lanes(3, { raw: 1, vn: 1, lcg: 1, pred: 1, cs: 1, cs2: 1 }), hl: { d: [2] }, say: `Counter 1 gives ${U.hexs(b1.slice(0, 4))} … Seeing every earlier byte does not help to guess these: doing better than chance would break ChaCha20, and the best known way is to try keys, 2^256 of them.`, facts: { b1: U.hexs(b1.slice(0, 4)) }, meta: { stage: 'cs2' } });
    const verd = [['fair after conditioning', 'good'], ['predictable: solved', 'bad'], ['unpredictable', 'good']];
    F.add({ items: lanes(0, { raw: 1, vn: 1, lcg: 1, pred: 1, cs: 1, cs2: 1 }, verd), hl: { d: [3] }, say: `In practice the three work together: the operating system gathers true randomness, conditions it, and uses it to seed a cryptographically secure generator, which then gives fast unpredictable bits for keys and nonces. A plain pseudo-random formula is never used for keys.`, facts: {}, meta: { stage: 'end' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 624 });
    return { frames: F.list, def: U.def('Random number generators', ['true: physical noise, unpredictable, often biased', 'von Neumann: 01 → 0, 10 → 1, drop 00 and 11', 'pseudo: xₙ₊₁ = f(xₙ), fast and repeatable', 'CSPRNG: no efficient test predicts the next bit', 'OS: true entropy seeds a CSPRNG']) };
  }
  S.topic({
    id: 'st-rng', family: 'p03-lfsr', order: 10, title: 'True, pseudo and cryptographic randomness',
    blurb: 'A noisy physical source made fair, a quick formula that three outputs give away, and a cipher whose next byte nobody can guess without the key.',
    inputs: [
      { id: 'seed', kind: 'number', label: 'Seed', def: 42, min: 1, max: 9999 },
      U.choice('bias', 'Source bias (chance of 1)', '0.7', [['0.6', '0.6'], ['0.7', '0.7'], ['0.8', '0.8'], ['0.9', '0.9']]),
      U.choice('lcg', 'Formula (a, c) mod 251', '37,11', [['37,11', 'a = 37, c = 11'], ['5,3', 'a = 5, c = 3'], ['101,57', 'a = 101, c = 57'], ['200,1', 'a = 200, c = 1']]),
    ],
    presets: [
      { label: 'Seed 42', values: { seed: 42, bias: '0.7', lcg: '37,11' } },
      { label: 'A strongly biased source', values: { seed: 7, bias: '0.9', lcg: '5,3' } },
      { label: 'Another formula', values: { seed: 2026, bias: '0.6', lcg: '101,57' } },
    ],
    check: (inp) => { const [a, c] = inp.lcg.split(',').map(Number), x0 = inp.seed % M, x1 = (a * x0 + c) % M; return x1 === x0 ? 'Seed: this seed is a fixed point of the formula; choose another' : null; },
    run: rng,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'lcg', once: true, pick: 'option', options: ['None', 'A few, by luck', 'All of them'], ask: 'An attacker sees the first three outputs and knows the form of the formula but neither a nor c. How many of the next outputs can she predict?', answer: 'All of them', explain: 'Two differences give a, then c; after that the formula is hers.' }],
    quiz: [
      { q: 'Why is raw output from a physical noise source passed through a conditioner?', options: ['It is too slow', 'It is unpredictable but usually biased or correlated', 'It is predictable', 'To encrypt it'], answer: 1, why: 'Conditioning, such as von Neumann or hashing, removes bias.' },
      { q: 'In von Neumann\'s method, which pairs are thrown away?', options: ['01 and 10', '00 and 11', 'only 00', 'none'], answer: 1, why: 'Equal pairs carry the bias; 01 and 10 are equally likely.' },
      { q: 'What makes a generator cryptographically secure?', options: ['A long period', 'Passing statistical tests', 'No efficient method predicts the next bit from the earlier ones better than chance', 'Using physical noise'], answer: 2, why: 'Long periods and statistics are not enough: an LCG or LFSR passes many tests and is still predictable.' },
      { q: 'Which is a sound way to make a key?', options: ['An LCG seeded with the time', 'A CSPRNG seeded from the operating system\'s entropy', 'An LFSR with a primitive polynomial', 'The first bytes of a hash of the user name'], answer: 1, why: 'Only an unpredictable seed fed to a secure generator gives unpredictable keys.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
