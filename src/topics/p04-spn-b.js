// Part 4, the toy SPN broken by linear approximations (the LAT, a path of masks through three rounds, the piling-
// up lemma and the count over known plaintexts for every guess of the last round key), and PRESENT, a real
// lightweight SPN: sixteen 4-bit S-boxes, a bit permutation and an 80-bit key register.
(function (S) {
  'use strict';
  const U = S.SymT, B = S.P04b, SP = () => S.SPN, PR = () => S.PRESENT;
  const h1 = (v) => v.toString(16), h4 = U.h4;
  const par = (x) => { let n = 0; while (x) { n ^= x & 1; x >>= 1; } return n; };

  // ---------------------------------------------------------------------------------------------------------------
  // The LAT and Matsui's linear attack
  // ---------------------------------------------------------------------------------------------------------------
  const APPROX = { A: [0x1000, 0x0020], B: [0x3000, 0x2000], C: [0x4000, 0x0200] };
  const signed = (v) => (v === 0 ? 'p4zero' : v >= 4 ? 'p4pos2' : v > 0 ? 'p4pos' : v <= -4 ? 'p4neg2' : 'p4neg');
  const sgn = (v) => (v > 0 ? '+' : v < 0 ? '−' : '') + Math.abs(v);
  function linear(inp) {
    const sb = SP().SBOX, L = SP().lat(), a = parseInt(inp.a, 16), b = parseInt(inp.b, 16);
    const [ma, mb] = APPROX[inp.approx], ap = B.approxes().find((x) => x.a === ma && x.bU4 === mb), nb = ap.active;
    const list = inp.mode === 'several' ? B.approxes().filter((x) => x.active.length === 1 && x.active[0] === nb[0]).slice(0, 8) : [ap];
    const keys = SP().keys(inp.key), texts = inp.texts;
    const res = SP().linearAttack({ keys, approx: list, texts, seed: inp.key });
    const G = 1 << (4 * nb.length), rightG = res.counts.findIndex((_, g) => B.spread(g, nb) === res.right), topG = res.counts.indexOf(Math.max(...res.counts));
    const one = list.length === 1, score = one ? res.per[0] : res.counts.map((v) => v * 1e4);
    const agree = Array.from({ length: 16 }, (_, x) => par(a & x) === par(b & sb[x]));
    const nAgree = agree.filter(Boolean).length, e = L[a][b];
    const Fr = new S.Frames();
    const head = U.head('ln:h', 'Linear approximations of the toy SPN, and the last round key');
    const xs = () => {
      const items = [U.t('ln:st', 24, 74, 'Masks a = ' + h1(a) + ' on x and b = ' + h1(b) + ' on S(x):', 'strong', 'start', 15), U.t('ln:x', 24, 108, 'x', 'tick', 'start', 14), U.t('ln:y', 24, 138, 'S(x)', 'tick', 'start', 14), U.t('ln:p1', 24, 168, 'a·x', 'tick', 'start', 14), U.t('ln:p2', 24, 198, 'b·S(x)', 'tick', 'start', 13)];
      items.push(...U.cells({ prefix: 'ln:cx', x: 74, y: 90, cw: 22, ch: 26, gap: 2, values: sb.map((_, i) => h1(i)), cls: () => 'soft', size: 14 }));
      items.push(...U.cells({ prefix: 'ln:cy', x: 74, y: 120, cw: 22, ch: 26, gap: 2, values: sb.map(h1), size: 14 }));
      items.push(...U.cells({ prefix: 'ln:ca', x: 74, y: 150, cw: 22, ch: 26, gap: 2, values: sb.map((_, x) => par(a & x)), cls: (x) => (agree[x] ? 'act' : ''), size: 14 }));
      items.push(...U.cells({ prefix: 'ln:cb', x: 74, y: 180, cw: 22, ch: 26, gap: 2, values: sb.map((v) => par(b & v)), cls: (x) => (agree[x] ? 'act' : ''), size: 14 }));
      items.push(U.t('ln:n', 24, 240, `the parities agree ${nAgree} times of 16: LAT entry ${nAgree} − 8 = ${sgn(e)}`, 'act', 'start', 14));
      items.push(U.t('ln:w1', 24, 330, 'a·x is the parity (XOR) of the bits of x where a has', 'tick', 'start', 14), U.t('ln:w2', 24, 354, 'a 1; blue columns are where the two parities agree.', 'tick', 'start', 14), U.t('ln:w3', 24, 390, 'In the table: row a, column b, entry agreements − 8.', 'tick', 'start', 14), U.t('ln:w4', 24, 414, 'Blue: agree more than half the time; pink: less.', 'tick', 'start', 14));
      items.push(U.t('ln:n2', 24, 266, `bias ε = ${sgn(e)}/16 = ${B.frac(e, 16)}`, 'hot', 'start', 14));
      return items;
    };
    const used = (upto) => { const s = []; ap.path.slice(0, upto).forEach((p) => p.boxes.forEach((q) => s.push([q.a, q.b]))); return s; };
    const T = (sel, rows) => B.table({ prefix: 'ln:tab', x: 476, y: 64, table: L, rows, sel, cls: signed, text: (v) => (v === 0 ? '0' : sgn(v)), rowLabel: 'a ↓', colLabel: 'b →' }).items;
    const net = (upto) => B.network({ prefix: 'ln:n', x: 70, y: 70, path: ap.path, upto, top: ap.a, bottom: ap.bU4, target: nb, unit: 'mask', fmt: (x, y) => h1(x) + ' → ' + h1(y) }).items;
    const pathRows = (upto) => {
      const items = [...U.panel('ln:r', 476, 512, 420, 104, 'the path so far')];
      ap.path.slice(0, upto).forEach((p, j) => items.push(U.t('ln:r' + j, 490, 556 + j * 20, 'round ' + (j + 1) + ': ' + p.boxes.map((q) => 'S-box ' + q.i + ' ' + h1(q.a) + '→' + h1(q.b) + ' (' + B.frac(q.n, 16) + ')').join(', '), 'mono', 'start', 13)));
      return items;
    };
    Fr.add({ items: [head, ...xs(), ...T([[a, b]], new Set([a]))], hl: { d: [0] }, say: `A linear approximation of the S-box: the parity of the input bits picked by the mask a = ${h1(a)} (hex) against the parity of the output bits picked by the mask b = ${h1(b)}. Over all 16 inputs they agree ${nAgree} times. A perfectly nonlinear box would agree 8 times; the difference, ${sgn(e)}, is the LAT entry, and ${B.frac(e, 16)} is the bias.`, facts: { a: h1(a), b: h1(b), nAgree, e, frac: B.frac(e, 16) }, meta: { stage: 'pair' } });
    const n4 = L.slice(1).flat().filter((v) => Math.abs(v) === 4).length;
    Fr.add({ items: [head, ...xs(), ...T([[a, b]], null)], say: `The whole linear approximation table: entry (a, b) is the number of agreements minus 8. Blue entries agree more often than chance, pink ones less; both help, since a parity that is usually wrong is as useful as one usually right. The largest entries are ±4, a bias of 1/4; there are ${n4} of them.`, facts: { n4 }, meta: { stage: 'lat' } });
    for (let r = 1; r <= 3; r++) {
      const p = ap.path[r - 1], m = ap.path.slice(0, r).reduce((t, q) => t + q.boxes.length, 0), prod = ap.path.slice(0, r).reduce((t, q) => t * q.boxes.reduce((s2, x) => s2 * Math.abs(x.n) / 16, 1), 1);
      Fr.add({ items: [head, ...net(r), ...T(used(r), null), ...pathRows(r)], hl: { d: [1] }, say: `Round ${r}: the mask ${h4(p.u)} meets ${U.plural(p.boxes.length, 'active S-box', 'active S-boxes')} (${p.boxes.map((q) => `S-box ${q.i}: ${h1(q.a)} → ${h1(q.b)}, LAT ${sgn(q.n)}`).join('; ')}), and leaves as ${h4(p.v)}. The key bits under the mask only flip the parity by a constant, so they do not change the size of the bias.`, facts: { u: h4(p.u), v: h4(p.v), boxes: p.boxes.map((q) => [q.i, h1(q.a), h1(q.b), q.n]), m, prod }, meta: { stage: 'round', r } });
    }
    const m = ap.boxes;
    Fr.add({ items: [head, ...net(3), ...T(used(3), null), ...pathRows(3)], hl: { d: [2] }, say: `The piling-up lemma: ${m} approximations with bias 1/4 each combine to a bias of 2^(${m}−1) × (1/4)^${m} = ${ap.bias}. So P·${h4(ap.a)} ⊕ U₄·${h4(ap.bU4)} equals a fixed sum of key bits with probability 1/2 ± ${ap.bias}, and about 1/ε², ${Math.round(1 / ap.bias / ap.bias)} known plaintexts, show it.`, facts: { m, bias: ap.bias, inv: Math.round(1 / ap.bias / ap.bias), a: h4(ap.a), b: h4(ap.bU4) }, meta: { stage: 'pile' } });
    const ticks = G === 16 ? [...Array(16).keys()] : [0, 64, 128, 192, 255];
    const bars = () => [U.t('ln:bt', 24, 64, one ? 'measured bias for each guess of K₅ nibble ' + nb.join(', ') : 'sum of squared biases of ' + list.length + ' approximations (× 10⁴)', 'title', 'start', 14), ...U.legend('ln:lg', 560, 64, [['hot', 'the top guess'], ['key', 'the true key bits']], 13), ...B.bars({ prefix: 'ln:b', x: 70, y: 110, w: 826, h: 300, values: score, hot: topG, key: rightG, ticks, label: (i) => h1(i), ylabel: one ? '|count − N/2| / N' : 'Σ ε²', fmt: (v) => v.toFixed(one ? 4 : 1) }).items];
    const panel = () => U.readout('ln:q', 24, 450, 872, 'the attack', [['known plaintexts N', String(texts)], ['approximations used', String(list.length)], ['top guess', h4(res.guess), 'hot'], ['true K₅ bits', h4(res.right), 'key']], { dy: 30, size: 14 });
    const best = res.best.slice(0, 3), fmt = (v) => (one ? Math.sqrt(v).toFixed(4) : (v * 1e4).toFixed(1));
    Fr.add({ items: [head, ...bars(), ...panel()], hl: { d: [3] }, say: `Matsui's attack, with ${texts} known plaintexts: for each of the ${G} guesses of K₅ nibble ${nb.join(', ')}, undo the last S-box on every ciphertext and count how often the parity relation holds. A wrong guess scrambles U₄ and sees a bias near 0; the right one sees about ${ap.bias}. Best: ${best.map((q) => h4(q.k) + ' (' + fmt(q.c) + ')').join(', ')}.` + (one ? '' : ` With ${list.length} approximations on the same nibble, their squared biases are added, so one that happens to cancel for this key cannot hide the right guess.`), facts: { texts, G, bias: ap.bias, best: best.map((q) => [h4(q.k), fmt(q.c)]), n: list.length }, meta: { stage: 'count', ok: res.ok } });
    Fr.add({ items: [head, ...bars(), ...panel()], say: `The top guess is ${h4(res.guess)} and the true bits are ${h4(res.right)}: ` + (res.ok ? 'recovered from known plaintexts alone, nothing chosen.' : 'missed. Several approximations through the same S-boxes can partly cancel for some keys (a linear hull); using several approximations, or more texts, fixes it.'), facts: { guess: h4(res.guess), right: h4(res.right), ok: res.ok }, meta: { stage: 'end' } });
    U.fix(Fr.list, { x: 0, y: 0, w: 920, h: 630 });
    return { frames: Fr.list, def: U.def('Linear cryptanalysis', ['LAT[a][b] = #{x : a·x = b·S(x)} − 8', 'bias ε = LAT / 16', 'piling-up: ε = 2^(m−1) · ε₁ · … · ε_m', 'P·α ⊕ U₄·β = key bits, with probability ½ ± ε', 'about 1/ε² known plaintexts']) };
  }
  S.topic({
    id: 'spn-linear', family: 'p04-spn', order: 30, title: 'The LAT and the linear attack',
    blurb: 'Parities of input and output bits that agree more often than chance, tabulated for the S-box, chained through three rounds by the piling-up lemma, and turned into a count over known plaintexts that singles out the last round key.',
    inputs: [U.choice('a', 'Input mask a', '3', '123456789abcdef'.split('').map((c) => [c, c])), U.choice('b', 'Output mask b', '1', '123456789abcdef'.split('').map((c) => [c, c])), U.choice('approx', 'Approximation', 'A', [['A', 'P·1000 → U₄·0020 (nibble 2)'], ['B', 'P·3000 → U₄·2000 (nibble 0)'], ['C', 'P·4000 → U₄·0200 (nibble 1)']]), U.choice('mode', 'Approximations used', 'one', [['one', 'one'], ['several', 'several on the same nibble']]), { id: 'texts', kind: 'number', label: 'Known plaintexts', def: 6000, min: 500, max: 12000 }, { id: 'key', kind: 'number', label: 'Secret key (seed)', def: 3, min: 1, max: 999 }],
    presets: [{ label: 'One approximation', values: { a: '3', b: '1', approx: 'A', mode: 'one', texts: 6000, key: 3 } }, { label: 'Where one misses', values: { a: '8', b: '2', approx: 'A', mode: 'one', texts: 6000, key: 4 } }, { label: 'Several fix it', values: { a: '8', b: '2', approx: 'A', mode: 'several', texts: 6000, key: 4 } }, { label: 'Nibble 0, few texts', values: { a: '4', b: '4', approx: 'B', mode: 'one', texts: 800, key: 6 } }],
    run: linear,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'pile', once: true, pick: 'option', options: ['the true key bits', 'a wrong guess'], ask: 'Which guess will show the largest bias?', answer: (fr, i) => (fr[i + 1].meta.ok ? 'the true key bits' : 'a wrong guess'), explain: 'Usually the true key; but approximations can cancel for some keys, and too few texts leave it in the noise.' }],
    quiz: [
      { q: 'A LAT entry of −4 means…', options: ['the parities agree 4 times of 16: a bias of −1/4, as useful as +1/4', 'the approximation is useless', 'four S-boxes', 'the key is negative'], answer: 0, why: 'A relation that is usually false is a relation whose complement is usually true.' },
      { q: 'Three approximations of bias 1/4 pile up to…', options: ['2² × (1/4)³ = 1/16', '3/4', '1/64', '1/4'], answer: 0, why: 'ε = 2^(m−1) ∏ εᵢ.' },
      { q: 'Roughly how many known plaintexts does a bias of 1/16 need?', options: ['About 1/ε² = 256 (a few times that in practice)', '16', '65 536', '4'], answer: 0, why: 'The signal ε·N must beat the noise √N.' },
      { q: 'Differential cryptanalysis needs chosen plaintexts. Linear cryptanalysis needs…', options: ['only known plaintexts', 'chosen ciphertexts', 'related keys', 'the key schedule'], answer: 0, why: 'It counts a relation over whatever pairs it sees.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // PRESENT
  // ---------------------------------------------------------------------------------------------------------------
  const h16 = (v) => v.toString(16).padStart(16, '0');
  const VECTORS = { '0000000000000000|00000000000000000000': '5579c1387b228445', '0000000000000000|ffffffffffffffffffff': 'e72c46c0f5945049', 'ffffffffffffffff|00000000000000000000': 'a112ffc72f68417b', 'ffffffffffffffff|ffffffffffffffffffff': '3333dcd3213210d2' };
  function present(inp) {
    const p = U.fromHex(inp.plain), k = U.fromHex(inp.key), r = PR().encrypt(p, k), ks = PR().keySchedule(k), R1 = r.rounds[0], out = U.hex(r.out);
    const vec = VECTORS[inp.plain.toLowerCase() + '|' + inp.key.toLowerCase()];
    const Fr = new S.Frames();
    const head = U.head('pr:h', 'PRESENT-80: a 64-bit SPN for small chips');
    const nibCells = (prefix, y, v, cls, label) => {
      const items = [U.t(prefix + ':l', 24, y + 20, label, 'strong', 'start', 14)];
      for (let i = 0; i < 16; i++) { const n = Number((v >> BigInt(4 * (15 - i))) & 15n); items.push({ key: prefix + i, kind: 'cell', x: 130 + i * 48, y, w: 44, h: 30, rx: 4, text: h1(n), size: 16, cls: 'hex ' + (typeof cls === 'function' ? cls(i) : cls || '') }); }
      return items;
    };
    const reg = (prefix, y, v, label, cls) => [U.t(prefix + ':l', 24, y + 20, label, 'strong', 'start', 14), ...Array.from({ length: 20 }, (_, i) => ({ key: prefix + i, kind: 'cell', x: 170 + i * 36, y, w: 33, h: 30, rx: 4, text: h1(Number((v >> BigInt(4 * (19 - i))) & 15n)), size: 15, cls: 'hex ' + (typeof cls === 'function' ? cls(i) : cls || '') }))];
    const sbox = () => [U.t('pr:sbt', 24, 520, 'the S-box', 'tick', 'start', 13), ...U.cells({ prefix: 'pr:sx', x: 130, y: 504, cw: 44, ch: 24, gap: 4, values: PR().SBOX.map((_, i) => h1(i)), cls: () => 'soft', size: 14 }), ...U.cells({ prefix: 'pr:sy', x: 130, y: 532, cw: 44, ch: 24, gap: 4, values: PR().SBOX.map(h1), cls: () => 'act', size: 14 }), U.t('pr:sbt2', 24, 548, 'x → S(x)', 'tick', 'start', 13)];
    const x0 = BigInt('0x' + U.hex(p));
    Fr.add({ items: [head, ...nibCells('pr:p', 80, x0, '', 'plaintext'), ...reg('pr:kk', 370, BigInt('0x' + U.hex(k)), 'key, 80 bits', 'key'), U.t('pr:kn', 170, 424, 'round key Kᵢ: the leftmost 64 bits of this register', 'tick', 'start', 13), ...U.readout('pr:o', 24, 150, 872, 'one round, 31 times, then a last key', [['addRoundKey', 'XOR a 64-bit round key'], ['sBoxLayer', 'the same 4-bit S-box on all 16 nibbles'], ['pLayer', 'bit i moves to 16·i mod 63 (bit 63 stays)'], ['key schedule', '80-bit register: rotate 61, S-box the top nibble, XOR the round counter']], { dy: 34, size: 14 }), ...sbox()], hl: { d: [0] }, say: `PRESENT encrypts a 64-bit block under an 80-bit key with 31 rounds of three layers: a round-key XOR, sixteen copies of one 4-bit S-box, and a permutation of the 64 bits. Everything is small enough for a few thousand gates. The plaintext is ${U.hex(p)} and the key ${U.hex(k)}.`, facts: { p: U.hex(p), k: U.hex(k) }, meta: { stage: 'overview' } });
    Fr.add({ items: [head, ...nibCells('pr:p', 80, x0, '', 'state'), ...nibCells('pr:k', 130, R1.key, 'key', 'K₁'), ...nibCells('pr:a', 180, R1.added, 'act', '⊕'), ...sbox()], say: `Round 1, addRoundKey: the first round key is the top 64 bits of the key register, K₁ = ${h16(R1.key)}. XORed into the state it gives ${h16(R1.added)}.`, facts: { K1: h16(R1.key), added: h16(R1.added) }, meta: { stage: 'addkey' } });
    const n0 = Number(R1.added >> 60n), s0 = PR().SBOX[n0];
    Fr.add({ items: [head, ...nibCells('pr:a', 80, R1.added, '', 'state'), ...nibCells('pr:s', 130, R1.sub, 'hot', 'S'), ...sbox().map((it) => (it.key === 'pr:sx' + n0 || it.key === 'pr:sy' + n0 ? Object.assign({}, it, { cls: 'hex hot' }) : it))], say: `sBoxLayer: each nibble goes through the S-box, all sixteen in parallel; the first, ${h1(n0)}, becomes ${h1(s0)}. The state is now ${h16(R1.sub)}. This is the only nonlinear step, and PRESENT's S-box keeps every difference table entry at 4 or below.`, facts: { n0: h1(n0), s0: h1(s0), sub: h16(R1.sub) }, meta: { stage: 'sbox' } });
    // the bit permutation: the 64 bits of the S-box output on top, the permuted bits below
    const bitX = (i) => U.r2(30 + (63 - i) * 13.6 + Math.floor((63 - i) / 4) * 1.5), yT = 250, yB = 420;
    const bitsRow = (prefix, y, v, lit) => { const items = []; for (let i = 0; i < 64; i++) { const b = Number((v >> BigInt(i)) & 1n); items.push({ key: prefix + i, kind: 'cell', x: U.r2(bitX(i) - 5.5), y, w: 11, h: 18, rx: 2, text: '', cls: 'bit ' + (b ? 'one' : 'zero') + (lit(i) ? ' hot' : '') }); } return items; };
    const src = [63, 62, 61, 60], dst = src.map((i) => PR().PERM[i]);
    const plines = []; for (let i = 0; i < 64; i++) plines.push({ key: 'pr:pl' + i, kind: 'path', d: `M${bitX(i)},${yT + 18} L${bitX(PR().PERM[i])},${yB}`, cls: 'p4wire' + (src.includes(i) ? ' hot' : ''), audit: 'ignore', layer: 'lines' });
    const permItems = [U.t('pr:pt', 24, yT - 14, 'after the S-boxes  ' + h16(R1.sub), 'mono', 'start', 14), ...bitsRow('pr:bt', yT, R1.sub, (i) => src.includes(i)), ...plines, ...bitsRow('pr:bb', yB, R1.perm, (i) => dst.includes(i)), U.t('pr:pb', 24, yB + 44, 'after the permutation  ' + h16(R1.perm), 'mono hot', 'start', 14), U.t('pr:pn', 24, yB + 74, 'bit 63 on the left, bit 0 on the right; the four bits of the leftmost S-box go to bits ' + dst.join(', '), 'tick', 'start', 13)];
    Fr.add({ items: [head, ...nibCells('pr:s', 80, R1.sub, '', 'after S'), ...nibCells('pr:q', 130, R1.perm, 'act', 'after P'), ...permItems], hl: { d: [1] }, say: `pLayer moves bit i to bit 16·i mod 63. The four output bits of one S-box land in four different S-boxes of the next round: the leftmost S-box's bits 63, 62, 61 and 60 go to ${dst.join(', ')}. After round 1 the state is ${h16(R1.perm)}. A permutation is just wiring: in hardware it costs nothing.`, facts: { dst, perm: h16(R1.perm) }, meta: { stage: 'perm' } });
    const kt = ks.trace[0];
    const afterS = (kt.rot & ((1n << 76n) - 1n)) | (BigInt(PR().SBOX[Number(kt.rot >> 76n)]) << 76n);
    Fr.add({ items: [head, ...reg('pr:r0', 80, kt.K, 'register', (i) => (i < 16 ? 'key' : '')), ...reg('pr:r1', 140, kt.rot, 'rotate 61', ''), ...reg('pr:r2', 200, afterS, 'S-box top', (i) => (i === 0 ? 'hot' : '')), ...reg('pr:r3', 260, kt.next, '⊕ counter 1', (i) => (i >= 15 && i <= 16 ? 'act' : i < 16 ? 'key' : '')), U.t('pr:rk', 170, 330, 'the round key is the leftmost 16 digits (64 bits) of the register', 'tick', 'start', 14), U.t('pr:rk2', 170, 360, 'K₂ = ' + h16(kt.next >> 16n), 'key', 'start', 16), ...sbox()], hl: { d: [2] }, say: `The key schedule: the 80-bit register ${kt.K.toString(16).padStart(20, '0')} rotates left by 61 places, its top nibble goes through the same S-box, and the round counter is XORed into bits 19 to 15. Its top 64 bits are the next round key, K₂ = ${h16(kt.next >> 16n)}.`, facts: { K: kt.K.toString(16).padStart(20, '0'), K2: h16(kt.next >> 16n), rot: kt.rot.toString(16) }, meta: { stage: 'key' } });
    const list = (upto) => {
      const items = [];
      for (let i = 0; i < 31; i++) {
        const col = i < 16 ? 0 : 1, row = i < 16 ? i : i - 16, x = 24 + col * 440, y = 80 + row * 28;
        if (i >= upto) continue;
        items.push(U.t('pr:ln' + i, x + 40, y + 16, String(i + 1), i === upto - 1 ? 'hot' : 'tick', 'end', 13), { key: 'pr:lv' + i, kind: 'cell', x: x + 50, y, w: 190, h: 24, rx: 3, text: h16(r.rounds[i].perm), size: 14, cls: 'hex ' + (i === upto - 1 ? 'hot' : '') });
      }
      return items;
    };
    Fr.add({ items: [head, U.t('pr:lt', 24, 64, 'the state after each round', 'title', 'start', 14), ...list(16)], say: `Rounds 1 to 16. One round already sends every S-box's output into four different S-boxes, so after a few rounds every bit depends on every plaintext bit: after round 16 the state is ${h16(r.rounds[15].perm)}.`, facts: { s16: h16(r.rounds[15].perm) }, meta: { stage: 'rounds' } });
    const k32 = r.keys[31];
    Fr.add({ items: [head, U.t('pr:lt', 24, 64, 'the state after each round', 'title', 'start', 14), ...list(31), ...U.readout('pr:f', 464, 532, 432, 'the end', [['⊕ K₃₂', h16(k32), 'key'], ['ciphertext', out, 'hot']], { dy: 28, size: 14 })], say: `After round 31 (${h16(r.rounds[30].perm)}) the last round key K₃₂ = ${h16(k32)} is XORed in: the ciphertext is ${out}.` + (vec ? ` The published test vector for this plaintext and key is ${vec}: ${vec === out ? 'the same' : 'different'}.` : ''), facts: { s31: h16(r.rounds[30].perm), k32: h16(k32), out, vec }, meta: { stage: 'end' } });
    U.fix(Fr.list, { x: 0, y: 0, w: 920, h: 620 });
    return { frames: Fr.list, def: U.def('PRESENT-80', ['state: 64 bits, 16 nibbles; key: 80 bits', 'round i = 1 … 31: x ← P(S(x ⊕ Kᵢ))', 'S: one 4-bit S-box, 16 copies', 'P: bit i → 16·i mod 63, bit 63 fixed', 'register ← rotl61; S on bits 79…76; ⊕ i on bits 19…15', 'ciphertext = x ⊕ K₃₂']) };
  }
  S.topic({
    id: 'spn-present', family: 'p04-spn', order: 40, title: 'PRESENT, a lightweight SPN',
    blurb: 'A real cipher built like the toy: round key, sixteen 4-bit S-boxes, a bit permutation, 31 times over. Small enough for an RFID tag; its permutation is pure wiring.',
    inputs: [{ id: 'plain', kind: 'hex', label: 'Plaintext (8 bytes)', def: '0000000000000000', bytes: 8 }, { id: 'key', kind: 'hex', label: 'Key (10 bytes)', def: '00000000000000000000', bytes: 10 }],
    presets: [
      { label: 'Test vector: zeros', values: { plain: '0000000000000000', key: '00000000000000000000' } },
      { label: 'Test vector: key all ones', values: { plain: '0000000000000000', key: 'ffffffffffffffffffff' } },
      { label: 'Test vector: plaintext all ones', values: { plain: 'ffffffffffffffff', key: '00000000000000000000' } },
      { label: 'Our own: "tidepool"', values: { plain: '74696465706f6f6c', key: '6c616e7465726e733a37' } },
    ],
    run: present,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'sbox', once: true, pick: 'option', options: ['four different S-boxes', 'the same S-box', 'two S-boxes'], ask: 'The permutation comes next. Where do the four output bits of one S-box go?', answer: 'four different S-boxes', explain: 'Bit i goes to 16·i mod 63: neighbouring bits land 16 places apart, in different nibbles.' }],
    quiz: [
      { q: 'Why is PRESENT\'s permutation layer cheap in hardware?', options: ['It is only wires: no gates at all', 'It uses a table', 'It is skipped in most rounds', 'It is a multiplication'], answer: 0, why: 'A fixed bit permutation is just routing.' },
      { q: 'Where does bit 5 go in PRESENT\'s permutation?', options: ['16·5 mod 63 = 17', '5', '80', '21'], answer: 0, why: 'P(i) = 16·i mod 63 for i < 63.' },
      { q: 'How many S-box lookups does one PRESENT encryption make (data path)?', options: ['31 × 16 = 496', '16', '64', '31'], answer: 0, why: 'Sixteen per round, 31 rounds.' },
      { q: 'What does the key schedule add besides a rotation?', options: ['An S-box on the top nibble and the round counter', 'Nothing', 'A multiplication', 'A hash'], answer: 0, why: 'The S-box makes it nonlinear; the counter makes rounds differ.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
