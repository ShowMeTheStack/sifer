// Part 14, learning with errors: Regev's bit encryption with every row of the public key shown, the noise in its
// own colour, the decryption drawn on the wheel of Z_q, and the distribution of the noise that decides whether
// decryption works. And the toy lattice signature: rejection sampling, and what its responses would give away
// without it.
(function (S) {
  'use strict';
  const U = S.P14, W = () => S.PQ.LWE, D = () => S.PQ.ToyDSA;
  const fx = U.fx;
  const sgn = (v) => (v < 0 ? '−' + -v : '+' + v);

  // ---------------------------------------------------------------------------------------------------------------
  // LWE
  // ---------------------------------------------------------------------------------------------------------------
  /** the wheel of Z_q: 0 at the top, q/2 at the bottom; the top half decrypts to 0, the bottom half to 1 */
  function wheel(q, cx, cy, R) {
    const at = (x, r) => { const t = (2 * Math.PI * x) / q; return [U.r2(cx + (r || R) * Math.sin(t)), U.r2(cy - (r || R) * Math.cos(t))]; };
    const arc = (a, b, r, n) => { const pts = []; for (let i = 0; i <= (n || 48); i++) pts.push(at(a + ((b - a) * i) / (n || 48), r)); return pts; };
    const band = (a, b, cls, key) => { const o = arc(a, b, R + 12), inn = arc(b, a, R - 12); return { key, kind: 'path', d: 'M' + o.concat(inn).map((p) => p.join(',')).join(' L') + ' Z', cls: 'band ' + cls, audit: 'ignore', layer: 'back' }; };
    const items = [
      band(-q / 4, q / 4, '', 'wh:b0'), band(q / 4, (3 * q) / 4, 'hot', 'wh:b1'),
      { key: 'wh:c', kind: 'path', d: 'M' + arc(0, q, R, 96).map((p) => p.join(',')).join(' L') + ' Z', cls: 'axis', audit: 'ignore', layer: 'back' },
    ];
    const lab = (k, x, text, cls) => { const [px, py] = at(x, R + 30); items.push(U.t('wh:l' + k, px, py + 5, text, cls || 'tick', Math.abs(px - cx) < 8 ? 'middle' : px > cx ? 'start' : 'end', 14)); };
    lab('0', 0, '0', 'strong'); lab('h', Math.floor(q / 2), '⌊q/2⌋ = ' + Math.floor(q / 2), 'strong'); lab('q4', q / 4, 'q/4'); lab('q34', (3 * q) / 4, '3q/4');
    items.push(U.t('wh:t0', cx, cy - 22, 'reads as 0', 'good', 'middle', 14), U.t('wh:t1', cx, cy + 32, 'reads as 1', 'hot', 'middle', 14));
    return { items, at, arc };
  }
  function lwe(inp) {
    const params = W().params({ n: 8, m: +inp.m, q: +inp.q, noise: { kind: 'uniform', B: +inp.B } });
    const { n, m, q } = params, half = Math.floor(q / 2), bit = +inp.bit;
    const kg = W().keyGen(params, +inp.seed), enc = W().encrypt(kg.pk, bit, +inp.enc), dec = W().decrypt(kg.sk, enc.ct, { r: enc.r, e: kg.e });
    const fail = W().failure(params);
    const A = kg.pk.A, s = kg.sk.s, e = kg.e, b = kg.pk.b, r = enc.r;
    const As = A.map((row) => row.reduce((acc, v, j) => acc + v * s[j], 0) % q);
    const F = new S.Frames();
    const head = U.t('lw:h', 20, 32, `LWE with n = ${n}, m = ${m}, q = ${q}, noise in [−${params.noise.B}, ${params.noise.B}]`, 'strong', 'start', 16);
    // the rows of the public key: i, A_i·s, + e_i, = b_i, chosen?
    const rowH = Math.min(27, 432 / m), top = 84, fs = rowH < 26 ? 14 : 15;
    const table = (cols) => {
      const items = [];
      const C = { i: [20, 34], as: [58, 72], e: [134, 54], b: [192, 72], r: [268, 40] };
      const hd = { i: 'i', as: 'Aᵢ·s', e: '+ eᵢ', b: '= bᵢ', r: 'in r' };
      for (const k of Object.keys(C)) if (cols[k] !== undefined) items.push(U.t('lw:hd' + k, C[k][0] + C[k][1] / 2, top - 10, hd[k], k === 'e' ? 'key' : 'strong', 'middle', 14));
      for (let i = 0; i < m; i++) {
        const y = U.r2(top + i * rowH), h = U.r2(rowH - 3);
        const cell = (k, text, cls) => items.push({ key: 'lw:' + k + i, kind: 'cell', x: C[k][0], y, w: C[k][1], h, rx: 3, text, size: fs, cls: 'hex ' + (cls || '') });
        cell('i', String(i), 'soft muted');
        if (cols.as) cell('as', String(As[i]), '');
        if (cols.e) cell('e', sgn(e[i]), Math.abs(e[i]) === params.noise.B ? 'keyhot' : 'key');
        if (cols.b) cell('b', String(b[i]), 'act');
        if (cols.r) cell('r', r[i] ? '✓' : '', r[i] ? 'hot' : 'soft');
      }
      return items;
    };
    const vecRow = (key, y, label, v, cls) => [U.t(key + ':l', 20, y + 19, label, 'strong', 'start', 15), ...U.cells({ prefix: key + ':', x: 72, y, cw: 38, ch: 28, gap: 3, values: v, cls: () => cls || '', size: 14 })];
    const sRow = () => vecRow('lw:s', top + m * rowH + 14, 's =', s, 'key');
    const wh = wheel(q, 690, 216, 118);
    const noisePlot = () => {
      const lim = Math.max(Math.ceil(q / 4) + 6, (() => { let k = 0, mass = 0; const keys = [...fail.dist.keys()].sort((x, y) => Math.abs(x) - Math.abs(y)); for (const v of keys) { mass += fail.dist.get(v); k = Math.abs(v); if (mass > 0.9995) break; } return k + 2; })());
      let top2 = 0; for (const p of fail.dist.values()) top2 = Math.max(top2, p);
      const pl = U.plot({ prefix: 'lw:n', x: 470, y: 462, w: 430, h: 130, xr: [-lim, lim], yr: [0, top2 * 1.15], xticks: [0, -Math.round(q / 4), Math.round(q / 4)].concat(lim - q / 4 > lim * 0.25 ? [-lim, lim] : []).sort((x, y) => x - y), yticks: [], ylabel: 'the noise e·r over all keys and choices of r', tickSize: 13 });
      const out = (k) => Math.abs(k) > q / 4;
      const shape = (keep, cls, key) => { let d = ''; for (let k = -lim; k <= lim; k++) { const p = fail.dist.get(k) || 0; if (!p || !keep(k)) continue; d += `M${pl.X(k - 0.45)},${pl.Y(0)} V${pl.Y(p)} H${pl.X(k + 0.45)} V${pl.Y(0)} Z `; } return { key, kind: 'path', d: d || 'M0,0', cls: 'dline ' + cls, audit: 'ignore' }; };
      const items = pl.items.concat([shape((k) => !out(k), 'prob', 'lw:n:in'), shape(out, 'bad prob', 'lw:n:out')]);
      for (const sg of [-1, 1]) items.push({ key: 'lw:n:q' + sg, kind: 'path', d: `M${pl.X((sg * q) / 4)},${pl.Y(0)} V${pl.Y(top2 * 1.15)}`, cls: 'needline', audit: 'ignore' });
      if (dec.noise !== null) items.push({ key: 'lw:n:me', kind: 'dot', x: pl.X(Math.max(-lim, Math.min(lim, dec.noise))), y: pl.Y(0), r: 6, cls: Math.abs(dec.noise) < q / 4 ? 'good' : 'bad', point: true });
      return items;
    };
    const urow = () => vecRow('lw:u', top + m * rowH + 52, 'u =', enc.ct.u, 'act');
    const vtext = () => U.t('lw:v', 20, top + m * rowH + 112, `v = ${enc.ct.v}`, 'mono', 'start', 16);
    const point = (show) => {
      if (!show) return [];
      const [px, py] = wh.at(dec.d), [cx2, cy2] = wh.at(bit * half), ok = dec.bit === bit;
      const noise = dec.noise, arcPts = wh.arc(bit * half, bit * half + noise, 118, Math.max(4, Math.abs(noise)));
      return [
        { key: 'wh:clean', kind: 'dot', x: cx2, y: cy2, r: 9, cls: 'ring', audit: 'overlap-ok' },
        { key: 'wh:arc', kind: 'path', d: 'M' + arcPts.map((p) => p.join(',')).join(' L'), cls: 'dline ' + (ok ? 'good' : 'bad'), audit: 'ignore' },
        { key: 'wh:d', kind: 'dot', x: px, y: py, r: 7, cls: ok ? 'good' : 'bad', point: true },
      ];
    };
    const readout = (rows) => U.readout('lw:ro', 470, 400, 430, 'decryption', rows, { dy: 28 });
    const facts0 = { n, m, q, B: params.noise.B };
    F.add({ items: [head, ...table({}), ...sRow(), ...wh.items], hl: { d: [0] }, say: `The secret is s, ${n} numbers mod ${q}: (${s.join(', ')}). The public key will be ${m} noisy equations about it.`, facts: Object.assign({ s }, facts0), meta: { stage: 'secret' } });
    F.add({ items: [head, ...table({ as: 1 }), ...sRow(), ...wh.items], hl: { d: [1] }, say: `Each row Aᵢ of a random ${m}×${n} matrix A gives Aᵢ·s mod ${q}. Published like this, ${n} of these equations would give s by Gaussian elimination in a moment.`, facts: Object.assign({ As }, facts0), meta: { stage: 'As' } });
    F.add({ items: [head, ...table({ as: 1, e: 1, b: 1 }), ...sRow(), ...wh.items], hl: { d: [2] }, say: `So each equation is spoiled by a small secret error eᵢ in [−${params.noise.B}, ${params.noise.B}]: the public key is A and b = A·s + e mod ${q}. Row 0 reads ${As[0]} ${e[0] < 0 ? '−' : '+'} ${Math.abs(e[0])} = ${b[0]}. Elimination now mixes the errors together until they swamp everything; recovering s from (A, b) is the learning-with-errors problem.`, facts: Object.assign({ e, b, As }, facts0), meta: { stage: 'noise' } });
    const chosen = r.reduce((a, x, i) => (x ? a.concat(i) : a), []);
    F.add({ items: [head, ...table({ as: 1, e: 1, b: 1, r: 1 }), ...sRow(), ...urow(), vtext(), ...wh.items], hl: { d: [3] }, say: `To encrypt the bit ${bit}, pick a random set r of rows (${chosen.length} of them: ${chosen.join(', ')}) and add them up: u = the sum of those Aᵢ, v = the sum of those bᵢ${bit ? ` plus ⌊q/2⌋ = ${half}` : ''}, all mod ${q}. Then v = ${enc.ct.v}. The pair (u, v) looks like one more LWE sample.`, facts: Object.assign({ chosen, count: chosen.length, v: enc.ct.v, half, bit }, facts0), meta: { stage: 'enc' } });
    const ok = dec.bit === bit, su = (enc.ct.v - dec.d + q * 4) % q;
    F.add({ items: [head, ...table({ as: 1, e: 1, b: 1, r: 1 }), ...sRow(), ...urow(), vtext(), ...wh.items, ...point(true), ...readout([['v − s·u mod q', String(dec.d)], ['centred', U.int(dec.centred), ok ? 'good' : 'bad'], ['carried noise e·r', U.int(dec.noise), ok ? 'good' : 'bad'], ['decrypted bit', String(dec.bit), ok ? 'good' : 'bad']])], hl: { d: [4] }, say: `To decrypt, the holder of s computes v − s·u mod ${q} = ${dec.d}: the sums of the Aᵢ·s cancel, leaving bit·⌊q/2⌋ plus the noise e·r = ${U.int(dec.noise)}, the sum of the chosen eᵢ. On the wheel the result sits ${Math.abs(dec.centred) > q / 4 ? 'in the bottom half, nearer ⌊q/2⌋' : 'in the top half, nearer 0'}, so the bit reads as ${dec.bit}${ok ? ': correct.' : `: wrong! The noise passed q/4 = ${fx(q / 4, 2)} and carried the value into the other half.`}`, facts: Object.assign({ d: dec.d, c: dec.centred, noise: dec.noise, bit: dec.bit, su, q4: q / 4 }, facts0), meta: { stage: 'dec', ok } });
    F.add({ items: [head, ...table({ as: 1, e: 1, b: 1, r: 1 }), ...sRow(), ...urow(), vtext(), ...wh.items, ...point(true), ...noisePlot()], hl: { d: [5] }, say: `How often does that go wrong? e·r is a sum of about ${Math.round(m / 2)} small errors, so it spreads into a bell. Decryption fails exactly when it lands outside ±q/4 (the red tails): a chance of ${fx(fail.average * 100, 2)}% for these parameters.${fail.safe ? ` Here even the worst case, ${fail.worst}, stays inside ${fx(q / 4, 2)}: it can never fail.` : ` The worst case, ${fail.worst}, is beyond ${fx(q / 4, 2)}, so failures are possible.`}`, facts: Object.assign({ pct: fail.average * 100, worst: fail.worst, q4: q / 4, half: Math.round(m / 2) }, facts0), meta: { stage: 'dist' } });
    F.add({ items: [head, ...table({ as: 1, e: 1, b: 1, r: 1 }), ...sRow(), ...urow(), vtext(), ...wh.items, ...point(true), ...noisePlot()], hl: { d: [5] }, say: `The trade-off of every lattice scheme: more noise makes the secret harder to find, but eats into the room before decryption fails. Real schemes such as ML-KEM pick sizes that make a failure astronomically rare, and add a check (the Fujisaki–Okamoto transform) so that a rare failure cannot be used against them.`, facts: facts0, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Regev\'s encryption (LWE)', ['secret s ∈ Z_q^n; noise eᵢ small', 'public: A (m×n), b = A·s + e mod q', 'public key rows are LWE samples (Aᵢ, bᵢ)', 'encrypt bit: r ⊆ rows; u = Σ Aᵢ, v = Σ bᵢ + bit·⌊q/2⌋', 'decrypt: v − s·u = bit·⌊q/2⌋ + e·r; nearer 0 → 0, nearer q/2 → 1', 'correct while |e·r| < q/4']) };
  }
  S.topic({
    id: 'pq-lwe', family: 'p14-lwe', order: 10, title: 'LWE: a bit under noise you can see',
    blurb: 'Noisy linear equations about a secret make a public key. A bit rides at 0 or q/2 under the sum of the noises; it decrypts while that sum stays inside a quarter of the wheel, and flips when it does not.',
    inputs: [
      { id: 'B', kind: 'choice', label: 'Noise bound B', def: '2', options: ['1', '2', '4', '6', '8'].map((v) => ({ value: v, label: '±' + v })) },
      { id: 'm', kind: 'choice', label: 'Samples m', def: '16', options: ['12', '16'].map((v) => ({ value: v, label: v })) },
      { id: 'q', kind: 'choice', label: 'Modulus q', def: '101', options: ['101', '257'].map((v) => ({ value: v, label: v })) },
      { id: 'bit', kind: 'choice', label: 'Bit', def: '1', options: [{ value: '0', label: '0' }, { value: '1', label: '1' }] },
      { id: 'seed', kind: 'number', label: 'Key seed', def: 3, min: 1, max: 999 },
      { id: 'enc', kind: 'number', label: 'Encryption seed', def: 2, min: 1, max: 999 },
    ],
    presets: [
      { label: 'Small noise, bit 1', values: { B: '2', m: '16', q: '101', bit: '1', seed: 3, enc: 2 } },
      { label: 'Small noise, bit 0', values: { B: '2', m: '16', q: '101', bit: '0', seed: 7, enc: 4 } },
      { label: 'Noise ±8: it fails', values: { B: '8', m: '16', q: '101', bit: '1', seed: 1, enc: 5 } },
      { label: 'Noise ±8, bit 0: it fails', values: { B: '8', m: '16', q: '101', bit: '0', seed: 4, enc: 4 } },
      { label: 'Noise ±8, q = 257: safe', values: { B: '8', m: '16', q: '257', bit: '1', seed: 1, enc: 5 } },
    ],
    run: lwe,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'enc', pick: 'option', options: ['0', '1'], ask: 'Decryption is next. Which bit will it read?', answer: (fr, i) => String(fr[i + 1].facts.bit), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Without the noise e, how would you find s from (A, b = A·s)?', options: ['It is impossible', 'Gaussian elimination on n of the equations', 'Factor b', 'Guess'], answer: 1, why: 'Exact linear equations are solved in polynomial time; the noise is what makes LWE hard.' },
      { q: 'v − s·u equals…', options: ['the bit exactly', 'bit·⌊q/2⌋ + (the sum of the chosen eᵢ)', 's', 'zero'], answer: 1, why: 'The Aᵢ·s parts cancel; the chosen errors remain.' },
      { q: 'Decryption fails when…', options: ['q is prime', 'the accumulated noise e·r reaches q/4 or more', 'the bit is 1', 'r is empty'], answer: 1, why: 'Then the value lands nearer the other of 0 and q/2.' },
      { q: 'Making the noise larger…', options: ['only helps', 'makes the secret harder to find but decryption failures likelier', 'only hurts', 'changes nothing'], answer: 1, why: 'That tension sets the parameters of every lattice scheme.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The toy lattice signature: rejection sampling
  // ---------------------------------------------------------------------------------------------------------------
  function toySig(inp) {
    const kg = D().keyGen('toy-dsa'), p = kg.sk.p, msg = inp.msg;
    const sg = D().sign(kg.sk, msg, { seed: +inp.seed }), vr = D().verify(kg.pk, msg, sg.sig);
    const bound = p.gamma1 - p.beta;
    const F = new S.Frames(['attempts', 'aborts']);
    const head = U.t('ts:h', 20, 32, 'A toy lattice signature (not ML-DSA): Fiat–Shamir with aborts', 'strong', 'start', 16);
    // a bar for each attempt: its largest |z| against the bound
    const attempts = sg.trace;
    const ap = U.plot({ prefix: 'ts:a', x: 80, y: 84, w: 360, h: 200, xr: [0.4, Math.max(attempts.length, 4) + 0.6], yr: [p.gamma1 - 4 * p.beta, p.gamma1 + p.beta], xticks: attempts.map((_, k) => k + 1), yticks: [p.gamma1 - 4 * p.beta, bound, p.gamma1], ylabel: 'largest |zᵢ| in each attempt', xlabel: 'attempt', tickSize: 13 });
    const attemptBars = (upto) => {
      const items = [...ap.items, { key: 'ts:a:bd', kind: 'path', d: `M${ap.X(0.4)},${ap.Y(bound)} H${ap.X(Math.max(attempts.length, 4) + 0.6)}`, cls: 'needline', audit: 'ignore' }];
      items.push(U.t('ts:a:bt', ap.X(Math.max(attempts.length, 4) + 0.6) + 6, ap.Y(bound) + 5, 'γ₁ − β', 'hot', 'start', 14));
      attempts.forEach((a, k) => { if (k < upto) items.push(U.bar(ap, 'ts:a:b' + k, k + 1, a.zNorm, 30, a.kind === 'dsa-accept' ? 'good' : 'bad', p.gamma1 - 4 * p.beta)); });
      return items;
    };
    // the sk, and one attempt's vectors as bars of the first polynomial: y, c·s₁, z
    const s1 = kg.trace[1].s1;
    const poly = (key, y, label, vals, scale, cls, lim) => {
      const items = [U.t(key + ':l', 470, y - 8, label, 'strong', 'start', 14), { key: key + ':ax', kind: 'path', d: `M480,${y + 30} H900`, cls: 'axis', audit: 'ignore', layer: 'back' }];
      vals.forEach((v, i) => { const h = Math.max(-28, Math.min(28, v * scale)); items.push({ key: key + ':' + i, kind: 'cell', x: U.r2(482 + i * 13), y: U.r2(y + 30 - Math.max(h, 0)), w: 10, h: Math.max(0.6, U.r2(Math.abs(h))), rx: 1, text: '', cls: 'bar ' + (lim && Math.abs(v) >= lim ? 'bad' : cls) }); });
      return items;
    };
    const facts0 = { n: p.n, q: p.q, eta: p.eta, tau: p.tau, beta: p.beta, g1: p.gamma1, g2: p.gamma2, k: p.k, l: p.l, bound };
    F.add({ items: [head, ...attemptBars(0), ...poly('ts:s', 330, 's₁, first polynomial (coefficients in [−' + p.eta + ', ' + p.eta + '])', s1[0], 12, 'key')], hl: { d: [0] }, say: kg.trace[0].say + ` The secret s₁ is short: every coefficient is in [−${p.eta}, ${p.eta}]. The public key is t = A·s₁ + s₂.`, facts: facts0, meta: { stage: 'key' } });
    attempts.forEach((a, k) => {
      F.count('attempts'); if (a.kind !== 'dsa-accept') F.count('aborts');
      const cs = a.z[0].map((v, i) => v - a.y[0][i]);
      const worst = a.z.flat().reduce((mx, v) => Math.max(mx, Math.abs(v)), 0);
      F.add({ items: [head, ...attemptBars(k + 1), ...poly('ts:y', 330, 'y, the mask (random in [−' + (p.gamma1 - 1) + ', ' + p.gamma1 + '])', a.y[0], 28 / p.gamma1, 'soft'), ...poly('ts:c', 430, 'c·s₁ (small: at most β = ' + p.beta + ')', cs, 28 / p.beta, 'key'), ...poly('ts:z', 530, 'z = y + c·s₁ (red: past γ₁ − β)', a.z[0], 28 / p.gamma1, 'act', bound), ...U.readout('ts:ro', 80, 340, 340, 'attempt ' + a.attempt, [['largest |zᵢ|', String(worst), a.zNorm < bound ? 'good' : 'bad'], ['bound γ₁ − β', String(bound)], ['low bits of w − c·s₂', String(a.lowNorm), a.lowNorm < p.gamma2 - p.beta ? 'good' : 'bad'], ['bound γ₂ − β', String(p.gamma2 - p.beta)], ['verdict', a.kind === 'dsa-accept' ? 'accept' : 'abort', a.kind === 'dsa-accept' ? 'good' : 'bad']])], hl: { d: a.kind === 'dsa-accept' ? [1, 2, 4] : [1, 2, 3] }, say: a.say.trim() + (a.kind === 'dsa-accept' ? '' : ` The largest coefficient is ${worst}.`), facts: Object.assign({ attempt: a.attempt, z: a.zNorm, worst, low: a.lowNorm, g2: p.gamma2, lowBound: p.gamma2 - p.beta, y1: p.gamma1 - 1 }, facts0), meta: { stage: a.kind, k } });
    });
    F.add({ items: [head, ...attemptBars(attempts.length), U.t('ts:ok', 470, 330, vr.ok ? 'Verified ✓' : 'Rejected', vr.ok ? 'good' : 'bad', 'start', 18)], hl: { d: [5] }, say: `After ${sg.attempts} ${sg.attempts === 1 ? 'attempt' : 'attempts'}, the signature (c, z) is out. ${vr.trace[1].say}`, facts: Object.assign({ attempts: sg.attempts, z: vr.trace[1].zNorm }, facts0), meta: { stage: 'verify' } });
    // what the responses show over many signatures: z near the top edge, split by the sign of c·s₁
    const N = +inp.count, lo = p.gamma1 - 4 * p.beta, hi = p.gamma1 + p.beta, width = 2;
    const coll = (abort) => {
      const pos = new Map(), neg = new Map();
      let beyond = 0, beyondPos = 0, kept = 0;
      for (let i = 1; i <= N; i++) {
        const t = D().sign(kg.sk, 'm' + i, { seed: 1000 + i, noAbort: true }).trace[0];
        if (abort && t.kind !== 'dsa-accept') continue;
        kept++;
        t.z.forEach((f, a) => f.forEach((z, j) => {
          const cs = z - t.y[a][j];
          if (z > p.gamma1) { beyond++; if (cs > 0) beyondPos++; }
          if (z < lo || z > hi || !cs) return;
          const bin = Math.floor((z - lo) / width), M = cs > 0 ? pos : neg;
          M.set(bin, (M.get(bin) || 0) + 1);
        }));
      }
      return { pos, neg, beyond, beyondPos, kept };
    };
    const hist = (h, abort) => {
      let top = 1; for (const M of [h.pos, h.neg]) for (const v of M.values()) top = Math.max(top, v);
      const pl = U.plot({ prefix: 'ts:h', x: 80, y: 360, w: 760, h: 200, xr: [lo, hi], yr: [0, top * 1.15], xticks: [lo, p.gamma1 - 2 * p.beta, bound, p.gamma1, hi], yticks: [], ylabel: 'zᵢ near the top of its range, ' + (abort ? 'after rejection' : 'with no rejection'), tickSize: 13 });
      const items = [...pl.items];
      const bins = Math.round((hi - lo) / width);
      for (let k = 0; k < bins; k++) {
        const x0 = lo + k * width, a = h.pos.get(k) || 0, b = h.neg.get(k) || 0;
        if (a) items.push({ key: 'ts:h:p' + k, kind: 'cell', x: pl.X(x0), y: pl.Y(a), w: U.r2(pl.X(x0 + width / 2) - pl.X(x0) - 0.5), h: U.r2(pl.Y(0) - pl.Y(a)), rx: 0, text: '', cls: 'bar hot' });
        if (b) items.push({ key: 'ts:h:n' + k, kind: 'cell', x: pl.X(x0 + width / 2), y: pl.Y(b), w: U.r2(pl.X(x0 + width) - pl.X(x0 + width / 2) - 0.5), h: U.r2(pl.Y(0) - pl.Y(b)), rx: 0, text: '', cls: 'bar act' });
      }
      items.push({ key: 'ts:h:band', kind: 'path', d: `M${pl.X(p.gamma1)},${pl.Y(0)} V${pl.Y(top * 1.15)} H${pl.X(hi)} V${pl.Y(0)} Z`, cls: 'band bad', audit: 'ignore', layer: 'back' });
      for (const [v, t, an] of [[p.gamma1, 'γ₁', 'start'], [bound, 'γ₁ − β', 'end']]) {
        items.push({ key: 'ts:h:v' + v, kind: 'path', d: `M${pl.X(v)},${pl.Y(0)} V${pl.Y(top * 1.15) - 4}`, cls: 'needline', audit: 'ignore' });
        items.push(U.t('ts:h:vt' + v, pl.X(v) + (an === 'start' ? 5 : -5), pl.Y(top * 1.15) + 2, t, 'hot', an, 14));
      }
      items.push(U.t('ts:h:bt', pl.X(hi) - 6, pl.Y(top * 1.15) + 22, 'y alone never reaches here', 'bad', 'end', 13));
      items.push(...U.legend('ts:h:k', 80, 610, [['hot', 'c·s₁ > 0 at that coefficient'], ['act', 'c·s₁ < 0']]));
      return items;
    };
    const h0 = coll(false), h1 = coll(true);
    F.add({ items: [head, ...attemptBars(attempts.length), ...hist(h0, false)], hl: { d: [3] }, say: `Why abort at all? Here are ${N} signatures made with no rejection, every coefficient of z near the top of the range. y alone never passes γ₁ = ${p.gamma1}, so a z beyond it means c·s₁ pushed it there: ${h0.beyond} coefficients went past, and ${h0.beyondPos} of them sit where c·s₁ is positive. Anyone who sees signatures and knows c learns the sign of c·s₁ there, and enough of those give s₁ away.`, facts: Object.assign({ N, beyond: h0.beyond, agree: h0.beyondPos }, facts0), meta: { stage: 'leak' } });
    F.add({ items: [head, ...attemptBars(attempts.length), ...hist(h1, true)], hl: { d: [3] }, say: `With rejection, a signature goes out only if every |zᵢ| < γ₁ − β = ${bound}. Of the same ${N} tries, ${h1.kept} pass; inside that range z = y + c·s₁ is uniform whatever c·s₁ was, so the two colours look alike and nothing passes the line: ${h1.beyond} coefficients beyond γ₁. The aborts cost a few attempts per signature and buy a response that says nothing about the key.`, facts: Object.assign({ N, kept: h1.kept, beyond: h1.beyond }, facts0), meta: { stage: 'flat' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Fiat–Shamir with aborts (toy)', ['key: short s₁, s₂; public t = A·s₁ + s₂', 'mask y with |yᵢ| ≤ γ₁; w₁ = HighBits(A·y); c = H(μ, w₁)', 'z = y + c·s₁', 'abort unless ‖z‖∞ < γ₁ − β and the low bits are safe', 'verify: HighBits(A·z − c·t) = w₁ and z is small', 'aborts make z independent of s₁']) };
  }
  S.topic({
    id: 'pq-toysig', family: 'p14-other', order: 20, title: 'A toy lattice signature and rejection sampling',
    blurb: 'A signature z = y + c·s₁ hides the short secret under a large random mask, but near the edges of the mask the secret shows. Throwing away every z that comes near an edge makes the responses independent of the key.',
    inputs: [
      { id: 'msg', kind: 'text', label: 'Message', def: 'meet at the north gate', check: (v) => (!v.length ? 'Message: at least one character' : v.length > 60 ? 'Message: at most 60 characters' : null) },
      { id: 'seed', kind: 'number', label: 'Signing seed', def: 4, min: 1, max: 999 },
      { id: 'count', kind: 'choice', label: 'Signatures for the histogram', def: '300', options: ['150', '300', '600'].map((v) => ({ value: v, label: v })) },
    ],
    presets: [
      { label: 'Four attempts', values: { msg: 'meet at the north gate', seed: 4 } },
      { label: 'Accepted at once', values: { msg: 'meet at the north gate', seed: 7 } },
      { label: 'Another message', values: { msg: 'the lighthouse key is under the third stone', seed: 2 } },
      { label: 'More signatures', values: { msg: 'meet at the north gate', seed: 4, count: '600' } },
    ],
    counters: [{ id: 'attempts', label: 'attempts' }, { id: 'aborts', label: 'aborts' }],
    run: toySig,
    predict: [
      { at: (f, i, fr) => fr[i + 1] && /^dsa-/.test(fr[i + 1].meta.stage || '') && fr[i + 1].meta.k === 0, pick: 'option', options: ['accept', 'abort'], ask: 'The first attempt is coming. Will its z pass the test, or be thrown away?', answer: (fr, i) => (fr[i + 1].meta.stage === 'dsa-accept' ? 'accept' : 'abort'), explain: (fr, i) => fr[i + 1].say },
      { at: (f) => f.meta && f.meta.stage === 'leak', pick: 'option', options: ['still some', 'none'], ask: 'With rejection, how many coefficients will lie beyond γ₁?', answer: 'none', explain: 'Every z with a coefficient at or past γ₁ − β is thrown away, so none can pass γ₁.' },
    ],
    quiz: [
      { q: 'Why does the signer throw away some z?', options: ['To save time', 'Because z near the edge of its range reveals the direction c·s₁ pushed it, and so the secret', 'Because z is too small', 'To change the message'], answer: 1, why: 'Rejection leaves z uniform on a range that does not depend on s₁.' },
      { q: 'The mask y is drawn from [−γ₁ + 1, γ₁]. A response with a coefficient of γ₁ + 5 means…', options: ['nothing', 'c·s₁ was positive at that coefficient', 'c·s₁ was negative there', 'the signature is invalid'], answer: 1, why: 'y cannot exceed γ₁, so the excess came from c·s₁.' },
      { q: 'What does an abort cost?', options: ['Security', 'A fresh y and another try: a few attempts on average', 'A new key', 'Nothing at all'], answer: 1, why: 'The bound is chosen so most attempts pass.' },
      { q: 'This toy differs from ML-DSA in that it…', options: ['has no secret', 'drops compression of t, hints and the real parameters', 'uses RSA', 'has no aborts'], answer: 1, why: 'It keeps the ideas only; it is labelled a toy everywhere.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
