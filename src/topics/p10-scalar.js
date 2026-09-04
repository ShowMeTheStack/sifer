// Part 10, scalar multiplication: k·P by double-and-add (from the top bit or from the bottom), by the Montgomery
// ladder (the same work for every bit), by signed digits (wNAF) with a table of odd multiples, and the cost of each in
// Jacobian coordinates, where no step needs an inversion. Toy curves show the running point on the cloud; P-256 and
// secp256k1 show the same steps at real size.
(function (S) {
  'use strict';
  const U = S.P10, E = () => S.ECC;
  const f = U.f, P$ = (P) => U.fp(P);

  const CURVES = [
    { value: 'gf101', label: 'toy: GF(101), 103 points' },
    { value: 'gf1009', label: 'toy: GF(1009), 1019 points' },
    { value: 'P-256', label: 'P-256 (256 bits)' },
    { value: 'secp256k1', label: 'secp256k1 (256 bits)' },
  ];
  const curveOf = (id) => (/^gf/.test(id) ? E().toy(id) : E().named(id));
  const parseK = (v) => { const t = String(v).trim().toLowerCase(); if (!/^(0x[0-9a-f]+|\d+)$/.test(t)) return null; return BigInt(t); };
  const kInput = (def, max) => ({ id: 'k', kind: 'text', label: 'Scalar k (decimal or 0x hex)', def, check: (v, inp) => { const k = parseK(v); if (k === null) return 'k: a whole number, in decimal or as 0x followed by hex digits'; const C = curveOf(inp.curve); if (k < 1n || k >= C.n) return 'k: from 1 to n − 1 = ' + f(C.n - 1n); if (max && S.ECC.bitLength(k) > max) return 'k: at most ' + max + ' bits here, so every step can be shown'; return null; } });
  const curveInput = (def) => ({ id: 'curve', kind: 'choice', label: 'Curve', def: def || 'gf101', options: CURVES });
  const realK = () => '0x' + U.hex(S.SHA256.hash(U.utf8('a scalar for Sifer'))).slice(0, 64);
  /** the running point on the right: the toy cloud, or the coordinates of a real point */
  function pointView(C, marks, opts) {
    opts = opts || {};
    if (C.toy) {
      const cl = U.cloud(C, { prefix: 'sm', x: opts.x || 640, y: opts.y || 160, s: opts.s || 260, r: Number(C.p) > 200 ? 1.3 : 2.4, grid: false });
      return [...cl.items, ...cl.marks(marks.filter((m) => m[1]), [], 14)];
    }
    const [, R, name] = marks[marks.length - 1];
    return U.readout('sm:r', opts.x || 590, opts.y || 160, 310, name + ' on ' + C.name, R ? [['x', U.hs(R.x.toString(16), 9)], ['y', U.hs(R.y.toString(16), 9)]] : [['', 'O']], { dy: 32 });
  }
  /** the bits of k, most significant first: cells with digits for short k, small squares for long */
  function bitRow(bits, cls, o) {
    o = o || {};
    const n = bits.length, y = o.y || 70;
    if (n <= 32) {
      const cw = n <= 16 ? 40 : 25, items = U.bits({ prefix: 'sm:b', x: 30, y, bits, cw, ch: 30, cls: (i, b) => cls(n - 1 - i, b) });
      for (let i = 0; i < n; i++) { const idx = n - 1 - i; if (idx % 4 === 0 || i === 0) items.push(U.t('sm:bi' + i, 30 + i * (cw + 2) + cw / 2, y - 7, String(idx), 'e10-note', 'middle', 13)); }
      return { items, h: 40 };
    }
    const per = 64, cw = 13, rows = Math.ceil(n / per), items = [];
    for (let i = 0; i < n; i++) items.push({ key: 'sm:b' + i, kind: 'cell', x: 30 + (i % per) * cw, y: y + Math.floor(i / per) * cw, w: cw - 1, h: cw - 1, rx: 1, text: '', cls: 'bit e10-bit ' + (bits[i] === '1' ? 'one' : 'zero') + ' ' + (cls(n - 1 - i, bits[i]) || '') });
    items.push(U.t('sm:bl', 30, y - 8, `${n} bits, from bit ${n - 1} on the left to bit 0`, 'e10-note', 'start', 13));
    return { items, h: rows * cw + 6 };
  }
  /** a log of the steps so far: the last few rows of a table */
  const stepTable = (rows, y, cols, keep) => {
    const shown = rows.slice(-(keep || 10));
    return U.table({ prefix: 'sm:t', x: 30, y, cols, rows: shown, rh: 30, hl: (i) => (i === shown.length - 1 ? 'act' : '') }).items;
  };
  /** frames for each bit, or for groups of bits when there are many */
  const groups = (n, most) => { const g = Math.max(1, Math.ceil(n / most)), out = []; for (let i = 0; i < n; i += g) out.push([i, Math.min(n, i + g)]); return out; };

  // ---------------------------------------------------------------------------------------------------------------
  // Double-and-add
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-double-add', family: 'p10-scalar', order: 10, title: 'Double-and-add',
    blurb: 'k·P means P added to itself k times, but nobody adds 2²⁵⁶ times. Read k in binary instead: from the top bit down, double the running point at every bit and add P where the bit is 1. Or go from the bottom up, keeping 2ⁱ·P and adding it in where bit i is 1. Either way the work grows with the number of bits, not with k.',
    inputs: [curveInput(), kInput('77'), { id: 'dir', kind: 'choice', label: 'Direction', def: 'ltr', options: [{ value: 'ltr', label: 'left to right (top bit first)' }, { value: 'rtl', label: 'right to left (bit 0 first)' }] }],
    presets: [
      { label: 'Toy: 77·P, top bit first', values: { curve: 'gf101', k: '77', dir: 'ltr' } },
      { label: 'Toy: 77·P, bit 0 first', values: { curve: 'gf101', k: '77', dir: 'rtl' } },
      { label: 'Toy: 1000·P on GF(1009)', values: { curve: 'gf1009', k: '1000', dir: 'ltr' } },
      { label: 'P-256: a 32-bit k', values: { curve: 'P-256', k: '3141592653', dir: 'ltr' } },
      { label: 'P-256: a full 256-bit k', values: { curve: 'P-256', k: realK(), dir: 'ltr' } },
      { label: 'secp256k1: bit 0 first', values: { curve: 'secp256k1', k: '0xc0ffee1234', dir: 'rtl' } },
    ],
    counters: [{ id: 'dbl', label: 'doublings' }, { id: 'add', label: 'additions' }],
    run(inp) {
      const C = curveOf(inp.curve), k = parseK(inp.k), P = C.G, ltr = inp.dir === 'ltr', F = new S.Frames(['dbl', 'add']);
      const res = ltr ? E().scalar.ltr(C, k, P) : E().scalar.rtl(C, k, P);
      const bits = k.toString(2), n = bits.length;
      const head = U.head('sm:h', 30, 28, `${ltr ? 'Left to right' : 'Right to left'}: k = ${f(k)} on ${C.toy ? C.name : C.name}`);
      const brH = bitRow(bits, () => '').h, tY = 70 + brH + 30;
      const cols = ltr ? [{ w: 60, head: 'bit' }, { w: 50, head: 'is' }, { w: 160, head: 'do' }, { w: 120, head: 'now holds' }, { w: 160, head: 'point' }] : [{ w: 60, head: 'bit' }, { w: 50, head: 'is' }, { w: 130, head: 'Q = 2ⁱ·P' }, { w: 120, head: 'sum holds' }, { w: 190, head: 'sum' }];
      const ptx = (R) => (R ? (C.toy ? P$(R) : 'x ' + U.hs(R.x.toString(16), 5)) : 'O');
      const rows = [], fm = (v) => (v < 1n << 40n ? v.toString() : '0x' + U.hs(v.toString(16), 4));
      F.add({ items: [head, ...bitRow(bits, () => '').items, ...stepTable([], tY, cols), ...pointView(C, [['P', P, 'P', 'P', 'ne']])], say: ltr ? `Compute k·P for k = ${f(k)}, which has ${n} bits${n <= 40 ? ': ' + bits + '₂' : ''}. Start at the top bit with the running point R = O; at every bit double R, and where the bit is 1 add P. Doubling shifts the multiple one bit left, adding P sets its last bit.` : `Compute k·P for k = ${f(k)}, which has ${n} bits${n <= 40 ? ': ' + bits + '₂' : ''}. Start at bit 0 with Q = P and the sum O; at bit i add Q = 2ⁱ·P into the sum if the bit is 1, then double Q for the next bit.`, facts: { k, n, bits }, meta: { stage: 'start' } });
      let dbl = 0, add = 0;
      for (const [a, b] of groups(n, 14)) {
        const done = new Set();
        for (let j = a; j < b; j++) {
          const st = res.steps[j];
          if (st.ops.includes('dbl')) dbl++;
          if (st.ops.includes('add')) add++;
          const mult = ltr ? k >> BigInt(st.i) : k & ((1n << BigInt(st.i + 1)) - 1n);
          rows.push(ltr ? [String(st.i), String(st.bit), st.ops.length ? st.ops.map((o) => (o === 'dbl' ? 'double' : 'add P')).join(', ') : 'R = P', fm(mult) + '·P', ptx(st.R)] : [String(st.i), String(st.bit), ptx(st.Q), fm(mult) + '·P', ptx(st.R)]);
          done.add(st.i);
        }
        F.set('dbl', dbl).set('add', add);
        const st = res.steps[b - 1], mult = ltr ? k >> BigInt(st.i) : k & ((1n << BigInt(st.i + 1)) - 1n);
        const cls = (i) => (done.has(i) ? 'cur' : (ltr ? i > st.i : i < st.i) ? 'done' : '');
        const marks = ltr ? [['P', P, 'P', 'P', 'ne'], ['R', st.R, 'R = ' + f(mult) + 'P', 'R', 'sw']] : [['P', P, 'P', 'P', 'ne'], ['Q', st.Q, 'Q', 'Q', 'nw'], ['R', st.R, 'sum', 'R', 'sw']];
        const one = b - a === 1;
        const say = ltr
          ? (one ? `Bit ${st.i} is ${st.bit}: ${st.ops.length ? st.ops.map((o) => (o === 'dbl' ? 'double R' : 'add P')).join(', then ') : 'the top bit is always 1, so R starts as P'}. R now holds ${f(mult)}·P, the number written by the bits from the top down to bit ${st.i}${C.toy ? ': ' + ptx(st.R) : ''}.` : `Bits ${res.steps[a].i} down to ${st.i}: ${b - a} more doublings and an addition for each 1 among them. R now holds ${f(mult)}·P, the top bits of k down to bit ${st.i}.`)
          : (one ? `Bit ${st.i} is ${st.bit}: ${st.bit ? `add Q = 2^${st.i}·P into the sum` : 'skip Q'}${st.i < n - 1 ? ', then double Q' : ''}. The sum holds ${f(mult)}·P, the bits of k up to bit ${st.i}${C.toy ? ': ' + ptx(st.R) : ''}.` : `Bits ${res.steps[a].i} to ${st.i}: Q is doubled at each and added in at each 1. The sum holds ${f(mult)}·P, the low ${st.i + 1} bits of k.`);
        F.add({ items: [head, ...bitRow(bits, cls).items, ...stepTable(rows, tY, cols), ...pointView(C, marks)], say, facts: { k, i: st.i, i0: res.steps[a].i, bit: st.bit, mult, R: st.R, Q: st.Q, g: b - a, low: st.i + 1 }, meta: { stage: 'bit', one, R: st.R, i: st.i } });
      }
      const ones = bits.split('1').length - 1;
      F.add({ items: [head, ...bitRow(bits, () => 'done').items, ...stepTable(rows, tY, cols), ...pointView(C, [['P', P, 'P', 'P', 'ne'], ['R', res.R, f(k) + '·P', 'R', 'sw']])], say: `Done: k·P = ${P$(res.R)}. It took ${res.doubles} doublings and ${res.adds} additions: one doubling per bit after the first, and one addition per 1 bit after the first (k has ${ones} ones). Adding P ${f(k)} times would take ${f(k - 1n)} additions.`, facts: { k, R: res.R, d: res.doubles, a: res.adds, ones, k1: k - 1n }, meta: { stage: 'done' } });
      U.fix(F.list);
      return { frames: F.list, def: U.def(ltr ? 'Left-to-right double-and-add' : 'Right-to-left double-and-add', ltr ? ['R ← O', 'for i from the top bit down to 0:', '  R ← 2R', '  if bit i of k is 1: R ← R + P', 'return R'] : ['R ← O, Q ← P', 'for i from 0 to the top bit:', '  if bit i of k is 1: R ← R + Q', '  Q ← 2Q', 'return R']) };
    },
    predict: [
      { at: (f, i, fr) => f.meta.stage === 'bit' && f.meta.one && fr[i + 1] && fr[i + 1].meta.stage === 'bit' && fr[i + 1].meta.one && f.meta.i >= 2 && f.meta.i <= 5, once: true, pick: 'option', ask: (fr, i) => 'What multiple of P will the running point hold after the next bit?', options: (fr, i) => { const m = BigInt(fr[i + 1].facts.mult), m0 = BigInt(fr[i].facts.mult); return [...new Set([m, m0 * 2n, m0 * 2n + 1n, m0 + 1n, m0 + (1n << BigInt(fr[i + 1].facts.i))])].slice(0, 4).map((x) => x + '·P'); }, answer: (fr, i) => fr[i + 1].facts.mult + '·P', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'How many doublings does left-to-right double-and-add need for a 256-bit k?', options: ['255', '256²', 'about 2²⁵⁶', '128'], answer: 0, why: 'One per bit after the first.' },
      { q: 'k = 13 = 1101₂. Left to right, the running multiples are…', options: ['1, 3, 6, 13', '1, 2, 4, 8', '1, 5, 13', '13, 6, 3, 1'], answer: 0, why: '1; 1·2 + 1 = 3; 3·2 + 0 = 6; 6·2 + 1 = 13.' },
      { q: 'Which bits cost an addition?', options: ['the 1 bits (after the first)', 'the 0 bits', 'every bit', 'only the last'], answer: 0, why: 'A 0 bit only doubles.' },
      { q: 'Right to left keeps Q = …', options: ['2ⁱ·P', 'i·P', 'k·P', 'P'], answer: 0, why: 'Q doubles once per bit.' },
      { q: 'Why can the time taken leak k?', options: ['additions happen only at 1 bits, so the sequence of operations follows the bits', 'doubling is slow', 'P is public', 'it cannot'], answer: 0, why: 'A power or timing trace shows double, add, double, double, … The Montgomery ladder fixes this.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The Montgomery ladder
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-ladder', family: 'p10-scalar', order: 20, title: 'The Montgomery ladder',
    blurb: 'Keep two points, R₀ = m·P and R₁ = (m + 1)·P. For each bit, one addition and one doubling: a 0 bit makes them 2m and 2m + 1, a 1 bit makes them 2m + 1 and 2m + 2. The work is the same whatever the bit, so the sequence of operations gives nothing away, and R₁ − R₀ = P all the way.',
    inputs: [curveInput(), kInput('77')],
    presets: [
      { label: 'Toy: 77·P', values: { curve: 'gf101', k: '77' } },
      { label: 'Toy: 100·P', values: { curve: 'gf101', k: '100' } },
      { label: 'Toy: 1000·P on GF(1009)', values: { curve: 'gf1009', k: '1000' } },
      { label: 'P-256: a 24-bit k', values: { curve: 'P-256', k: '11259375' } },
      { label: 'secp256k1: a full k', values: { curve: 'secp256k1', k: realK() } },
    ],
    counters: [{ id: 'add', label: 'additions' }, { id: 'dbl', label: 'doublings' }],
    run(inp) {
      const C = curveOf(inp.curve), k = parseK(inp.k), P = C.G, F = new S.Frames(['add', 'dbl']);
      const res = E().scalar.ladder(C, k, P), da = E().scalar.ltr(C, k, P);
      const bits = k.toString(2), n = bits.length;
      const head = U.head('sm:h', 30, 28, `Montgomery ladder: k = ${f(k)} on ${C.name}`);
      const brH = bitRow(bits, () => '').h, rY = 70 + brH + 50;
      const ptx = (R) => (R ? (C.toy ? P$(R) : 'x ' + U.hs(R.x.toString(16), 6)) : 'O');
      const regs = (m, R0, R1, hot) => [
        { key: 'sm:R0', kind: 'state', x: 150, y: rY, w: 230, h: 62, rx: 8, lines: ['R₀ = ' + f(m) + '·P', ptx(R0)], cls: 'block val2 e10-reg ' + (hot === 0 ? 'hot' : '') },
        { key: 'sm:R1', kind: 'state', x: 420, y: rY, w: 230, h: 62, rx: 8, lines: ['R₁ = ' + f(m + 1n) + '·P', ptx(R1)], cls: 'block val2 e10-reg key ' + (hot === 1 ? 'hot' : '') },
      ];
      const opsY = rY + 70;
      const opsRow = (list, y, key, label) => { const items = [U.t(key + ':l', 30, y + 18, label, 'e10-note', 'start', 13)]; list.slice(0, 28).forEach((o, i) => items.push({ key: key + i, kind: 'cell', x: 170 + i * 25, y, w: 23, h: 26, rx: 3, text: o, size: 13, cls: 'e10-cell mono ' + (o === 'A' ? 'key' : 'act') })); return items; };
      const seqL = res.steps.flatMap(() => ['A', 'D']), seqD = da.steps.flatMap((s) => s.ops.map((o) => (o === 'dbl' ? 'D' : 'A')));
      F.add({ items: [head, ...bitRow(bits, () => '').items, ...regs(0n, null, P), ...pointView(C, [['P', P, 'P', 'P', 'ne']], { y: 200 })], say: `Start with R₀ = O = 0·P and R₁ = P = 1·P. The ladder will keep R₁ = R₀ + P at every step, for k = ${f(k)} with ${n} bits.`, facts: { k, n }, meta: { stage: 'start' } });
      let m = 0n;
      for (const [a, b] of groups(n, 12)) {
        const done = new Set();
        for (let j = a; j < b; j++) done.add(res.steps[j].i);
        const st = res.steps[b - 1];
        const m0 = k >> BigInt(st.i + (b - a)); m = k >> BigInt(st.i);
        F.set('add', b).set('dbl', b);
        const cls = (i) => (done.has(i) ? 'cur' : i > st.i ? 'done' : '');
        const one = b - a === 1;
        F.add({ items: [head, ...bitRow(bits, cls).items, ...regs(m, st.R0, st.R1, one ? (st.bit ? 1 : 0) : null), ...pointView(C, [['P', P, 'P', 'P', 'ne'], ['A', st.R0, 'R₀', 'R', 'sw'], ['B', st.R1, 'R₁', 'Q', 'se']], { y: 200 })], say: one ? `Bit ${st.i} is ${st.bit}: ${st.bit ? 'R₀ ← R₀ + R₁ and R₁ ← 2R₁' : 'R₁ ← R₀ + R₁ and R₀ ← 2R₀'}. The multiples go from ${f(m0)} and ${f(m0 + 1n)} to ${f(m)} and ${f(m + 1n)}: one addition and one doubling, the same as for a ${st.bit ? '0' : '1'} bit.` : `Bits ${res.steps[a].i} down to ${st.i}: one addition and one doubling each, whatever the bit. Now R₀ = ${f(m)}·P and R₁ = ${f(m + 1n)}·P.`, facts: { k, i: st.i, i0: res.steps[a].i, bit: st.bit, m, m0, m1: m + 1n, m01: m0 + 1n, R0: st.R0, R1: st.R1 }, meta: { stage: 'bit', one, bit: st.bit } });
      }
      F.add({ items: [head, ...bitRow(bits, () => 'done').items, ...regs(k, res.R, C.add(res.R, P)), ...opsRow(seqD, opsY + 6, 'sm:od', 'double-and-add'), ...opsRow(seqL, opsY + 40, 'sm:ol', 'ladder'), U.t('sm:olg', 30, opsY + 92, 'A = an addition, D = a doubling', 'e10-note', 'start', 13), ...pointView(C, [['P', P, 'P', 'P', 'ne'], ['A', res.R, 'k·P', 'R', 'sw']], { y: 330, s: 250 })], say: `Done: R₀ = k·P = ${P$(res.R)}, after ${res.adds} additions and ${res.doubles} doublings, one of each per bit. The rows compare the operations: double-and-add does ${da.doubles} doublings and ${da.adds} additions in an order that spells out the bits, the ladder an even rhythm of add, double, add, double. ${seqD.length > 28 ? 'Only the first 28 operations are drawn.' : ''}`.trim(), facts: { k, R: res.R, a: res.adds, d: res.doubles, dd: da.doubles, da: da.adds, n48: 28 }, meta: { stage: 'done' } });
      U.fix(F.list);
      return { frames: F.list, def: U.def('Montgomery ladder', ['R₀ ← O, R₁ ← P', 'for each bit from the top:', '  bit 0: R₁ ← R₀ + R₁, R₀ ← 2R₀', '  bit 1: R₀ ← R₀ + R₁, R₁ ← 2R₁', 'invariant: R₁ − R₀ = P', 'return R₀']) };
    },
    predict: [
      { at: (f, i, fr) => f.meta.stage === 'bit' && f.meta.one && fr[i + 1] && fr[i + 1].meta.one && f.facts.i <= 5 && f.facts.i >= 1, once: true, pick: 'option', ask: 'After the next bit, how many additions will the ladder have done for it?', options: ['one, whatever the bit', 'one if the bit is 1, none if 0', 'two', 'none'], answer: 'one, whatever the bit', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What stays true at every step of the ladder?', options: ['R₁ − R₀ = P', 'R₀ = R₁', 'R₀ = O', 'R₁ = 2R₀'], answer: 0, why: 'Both updates keep the two multiples one apart.' },
      { q: 'R₀ = 5P, R₁ = 6P and the next bit is 1. Afterwards…', options: ['R₀ = 11P, R₁ = 12P', 'R₀ = 10P, R₁ = 11P', 'R₀ = 6P, R₁ = 12P', 'R₀ = 5P, R₁ = 11P'], answer: 0, why: 'R₀ ← R₀ + R₁ = 11P, R₁ ← 2R₁ = 12P.' },
      { q: 'Why is the ladder preferred against side channels?', options: ['every bit costs one addition and one doubling', 'it uses fewer operations', 'it needs no doubling', 'it skips 0 bits'], answer: 0, why: 'The sequence of operations no longer depends on the bits (the code must also avoid branches and secret memory accesses).' },
      { q: 'For a 256-bit k, the ladder does about…', options: ['256 additions and 256 doublings', '128 additions', '2²⁵⁶ additions', '256 additions only'], answer: 0, why: 'One of each per bit.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Signed digits: wNAF
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-wnaf', family: 'p10-scalar', order: 30, title: 'Signed digits: the wNAF',
    blurb: 'On a curve subtracting costs the same as adding, since −Q is Q mirrored. So write k with digits that may be negative: the width-w non-adjacent form uses odd digits up to 2^(w−1) − 1 in size, with at least w − 1 zeros after each one. Fewer nonzero digits mean fewer additions, paid for by a small table of odd multiples of P.',
    inputs: [curveInput('P-256'), kInput(realK()), { id: 'w', kind: 'number', label: 'Width w', def: 4, min: 2, max: 6 }],
    presets: [
      { label: 'P-256, w = 4', values: { curve: 'P-256', k: realK(), w: 4 } },
      { label: 'P-256, w = 2 (the plain NAF)', values: { curve: 'P-256', k: realK(), w: 2 } },
      { label: 'P-256, w = 6', values: { curve: 'P-256', k: realK(), w: 6 } },
      { label: 'Toy: k = 7 = 111₂, w = 2', values: { curve: 'gf101', k: '7', w: 2 } },
      { label: 'Toy: k = 87, w = 3', values: { curve: 'gf101', k: '87', w: 3 } },
      { label: 'A run of ones: 2²⁰ − 1', values: { curve: 'secp256k1', k: '1048575', w: 4 } },
    ],
    counters: [{ id: 'digits', label: 'digits' }, { id: 'nz', label: 'nonzero' }],
    run(inp) {
      const C = curveOf(inp.curve), k = parseK(inp.k), w = inp.w, F = new S.Frames(['digits', 'nz']), W = 1n << BigInt(w), half = W >> 1n;
      const digits = E().naf(k, w), res = E().scalar.wnaf(C, k, C.G, w), lr = E().scalar.ltr(C, k, C.G);
      const bits = k.toString(2), ones = bits.split('1').length - 1, nz = digits.filter((d) => d).length;
      const head = U.head('sm:h', 30, 28, `Width-${w} NAF of k = ${f(k)}`);
      // the recoding, step by step: k odd → d = k mods 2^w, k ← (k − d) / 2
      const rec = []; let kk = k;
      while (kk > 0n) { let d = 0n; if (kk & 1n) { d = kk % W; if (d >= half) d -= W; } rec.push({ k: kk, r: kk % W, d }); kk = (kk - d) >> 1n; }
      const cols = [{ w: 70, head: 'step i' }, { w: 230, head: 'k now' }, { w: 120, head: 'k mod 2^w' }, { w: 90, head: 'digit' }];
      const kx = (v) => (S.ECC.bitLength(v) > 60 ? f(v) : v.toString());
      const digitRow = (upto) => {
        const L = digits.length, cw = L <= 24 ? 34 : L <= 64 ? 13 : 6, items = [];
        const y = 450;
        items.push(U.t('sm:dl', 30, y - 10, `digits, the top one on the left (${L} of them; blue +, pink −)`, 'e10-note', 'start', 13));
        for (let j = 0; j < L; j++) {
          const i = L - 1 - j, d = digits[i], shown = i < upto;
          items.push({ key: 'sm:d' + j, kind: 'cell', x: 30 + (L <= 64 ? j * (cw + 1) : (j % 128) * (cw + 0.5)), y: y + (L <= 64 ? 0 : Math.floor(j / 128) * 18), w: cw, h: L <= 24 ? 30 : 16, rx: 2, text: L <= 24 && shown ? String(d).replace('-', '−') : '', size: 13, cls: 'bit e10-bit ' + (!shown ? 'done' : d > 0 ? 'pos' : d < 0 ? 'neg' : 'zero') });
        }
        return items;
      };
      F.add({ items: [head, ...digitRow(0), ...U.eqs('sm:e', 30, 80, [[`k has ${bits.length} bits, ${ones} of them 1`, 'strong'], [`w = ${w}: digits are 0 or odd, from −${half - 1n} to ${half - 1n}`], ['rule: if k is odd, d = k mod 2^w, minus 2^w if it is ' + half + ' or more'], ['then k ← (k − d)/2, and the next digit']], 16, 30)], say: `Binary k has ${ones} ones among ${bits.length} bits, and double-and-add pays an addition for each. Recode it: while k > 0, if k is odd take the digit d = k mod 2^${w}, moved into the range −${half - 1n} to ${half - 1n} by subtracting 2^${w} when it is ${half} or more; then k ← (k − d)/2. Subtracting d makes k divisible by 2^${w}, so the next ${w - 1} digits are 0.`, facts: { k, nb: bits.length, ones, w, w1: w - 1, hm: half - 1n, half, W }, meta: { stage: 'start' } });
      const shownSteps = rec.length <= 12 ? rec.map((_, i) => i) : [0, 1, 2, 3, 4, 5].concat([rec.length - 3, rec.length - 2, rec.length - 1]);
      const rows = [];
      let lastI = -1;
      for (const i of shownSteps) {
        if (i - lastI > 1) rows.push(['…', '…', '…', '…']);
        const s = rec[i]; rows.push([String(i), kx(s.k), s.k & 1n ? String(s.r) : 'even', String(s.d).replace('-', '−')]);
        lastI = i;
        if (i < 4 || i === rec.length - 1) {
          const nzs = digits.slice(0, i + 1).filter((d) => d).length;
          F.set('digits', i + 1).set('nz', nzs);
          F.add({ items: [head, ...U.table({ prefix: 'sm:t', x: 30, y: 60, cols, rows: rows.slice(-11), rh: 30, hl: (r) => (r === Math.min(rows.length, 11) - 1 ? 'act' : '') }).items, ...digitRow(i + 1)], say: i === rec.length - 1 ? `The last step: k = ${kx(s.k)} gives the digit ${String(s.d).replace('-', '−')} and leaves 0. The recoding has ${digits.length} digits, ${nz} of them nonzero, against ${ones} ones in binary.` : s.k & 1n ? `Step ${i}: k = ${kx(s.k)} is odd; k mod ${W} = ${s.r}, so the digit is ${String(s.d).replace('-', '−')}${s.d < 0n ? ` (${s.r} − ${W})` : ''}, and k becomes (k − d)/2.` : `Step ${i}: k = ${kx(s.k)} is even, so the digit is 0 and k is halved.`, facts: { k: s.k, r: s.r, d: s.d, W, i, nd: digits.length, nz, ones }, meta: { stage: 'recode', i } });
        }
      }
      // evaluation: the table of odd multiples, then the comparison of costs
      const m = 1 << (w - 2), tbl = [];
      for (let j = 0, R = C.G, P2 = C.dbl(C.G); j < m; j++, R = C.add(R, P2)) tbl.push([(2 * j + 1) + 'P', C.toy ? P$(R) : 'x ' + U.hs(R.x.toString(16), 6)]);
      const tView = U.table({ prefix: 'sm:p', x: 30, y: 60, cols: [{ w: 60, head: 'odd' }, { w: 230, head: 'point' }], rows: tbl.slice(0, 8), rh: 30 }).items;
      const cmp = U.table({ prefix: 'sm:c', x: 380, y: 60, cols: [{ w: 170, head: 'method', mono: false }, { w: 90, head: 'doublings' }, { w: 90, head: 'additions' }, { w: 120, head: 'field M + S' }], rows: [['binary, top first', String(lr.doubles), String(lr.adds), (lr.cost.M + lr.cost.S) + ''], [`w = ${w} NAF`, String(res.doubles), String(res.adds), (res.cost.M + res.cost.S) + '']], rh: 34, hl: (r) => (r === 1 ? 'good' : '') }).items;
      F.add({ items: [head, ...tView, ...cmp, ...digitRow(digits.length)], say: `To evaluate, ${m > 1 ? `precompute the odd multiples P, 3P, …, ${2 * m - 1}P (${m} points, ${m} group operations), then` : 'with digits only ±1 no table is needed:'} run double-and-add over the digits, adding dP for a positive digit and subtracting |d|P for a negative one. Counting the table, that is ${U.plural(res.doubles, 'doubling')} and ${U.plural(res.adds, 'addition')}, against ${lr.doubles} and ${lr.adds} for plain binary: ${res.cost.M + res.cost.S} field multiplications and squarings instead of ${lr.cost.M + lr.cost.S}${res.cost.M + res.cost.S >= lr.cost.M + lr.cost.S ? ', so for so short a k the recoding does not pay' : ''}. Both give k·P = ${P$(res.R)}.`, facts: { m, odd: 2 * m - 1, d: res.doubles, a: res.adds, ld: lr.doubles, la: lr.adds, c: res.cost.M + res.cost.S, lc: lr.cost.M + lr.cost.S, R: res.R }, meta: { stage: 'cost' } });
      U.fix(F.list);
      return { frames: F.list, def: U.def('Width-w NAF', ['while k > 0:', '  if k odd: d = k mods 2^w (odd, |d| < 2^(w−1))', '  else: d = 0', '  k ← (k − d)/2', 'after a nonzero digit come at least w − 1 zeros', 'about n/(w + 1) nonzero digits for n bits']) };
    },
    predict: [
      { at: (f, i, fr) => f.meta.stage === 'start', pick: 'option', ask: 'Will the recoding have more nonzero digits than binary has ones, or fewer?', options: ['fewer', 'more', 'the same'], answer: (fr) => { const x = fr.find((y) => y.meta.stage === 'cost').facts; const last = fr.filter((y) => y.meta.stage === 'recode').pop().facts; return last.nz < last.ones ? 'fewer' : last.nz > last.ones ? 'more' : 'the same'; }, explain: (fr) => fr.filter((y) => y.meta.stage === 'recode').pop().say },
    ],
    quiz: [
      { q: 'Why may digits be negative on an elliptic curve?', options: ['−Q is just Q mirrored, so subtracting costs the same as adding', 'negative numbers are smaller', 'the curve is symmetric about y = x', 'they may not'], answer: 0, why: 'Negating a point only negates y.' },
      { q: 'The plain NAF (w = 2) of 7 is…', options: ['1 0 0 −1 (8 − 1)', '1 1 1', '1 −1 1', '7'], answer: 0, why: '7 = 8 − 1: two nonzero digits instead of three.' },
      { q: 'After a nonzero digit in a width-w NAF there are at least…', options: ['w − 1 zeros', 'w zeros', 'one zero', 'no zeros'], answer: 0, why: 'Subtracting d makes k divisible by 2^w.' },
      { q: 'What does a larger w cost?', options: ['a bigger table of odd multiples to precompute', 'more doublings', 'more nonzero digits', 'nothing'], answer: 0, why: '2^(w−2) points are precomputed.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Jacobian coordinates and the cost table
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'ec-jacobian', family: 'p10-scalar', order: 40, title: 'Jacobian coordinates and the cost of k·P',
    blurb: 'Every affine addition divides, and a division mod p costs as much as dozens of multiplications. Jacobian coordinates (X : Y : Z) stand for (X/Z², Y/Z³); with them, doubling and adding need only multiplications and squarings, and the single inversion comes at the very end. The table compares the methods for one k.',
    inputs: [curveInput('P-256'), kInput(realK()), { id: 'z', kind: 'text', label: 'A scale Z for the example', def: '7', check: (v) => (!/^\d+$/.test(String(v).trim()) || BigInt(String(v).trim()) < 2n ? 'Z: a whole number of at least 2' : null) }],
    presets: [
      { label: 'P-256 (a = −3)', values: { curve: 'P-256', k: realK(), z: '7' } },
      { label: 'secp256k1 (a = 0)', values: { curve: 'secp256k1', k: realK(), z: '7' } },
      { label: 'Toy: GF(101)', values: { curve: 'gf101', k: '77', z: '3' } },
      { label: 'P-256, a short k', values: { curve: 'P-256', k: '1000003', z: '12345' } },
    ],
    run(inp) {
      const C = curveOf(inp.curve), k = parseK(inp.k), F = new S.Frames(), G = C.G, Z = BigInt(inp.z) % C.p || 2n;
      const head = U.head('sm:h', 30, 28, `Jacobian coordinates on ${C.name}`);
      const sh = (v) => (C.toy ? v.toString() : U.hs(v.toString(16), 6));
      const Z2 = C.m(Z * Z), Z3 = C.m(Z2 * Z), J = { X: C.m(G.x * Z2), Y: C.m(G.y * Z3), Z };
      const back = C.fromJ(J);
      F.add({ items: [head, ...U.readout('sm:a', 30, 60, 420, 'affine G', [['x', sh(G.x)], ['y', sh(G.y)]]), ...U.readout('sm:j', 470, 60, 420, `Jacobian, Z = ${Z}`, [['X = x·Z²', sh(J.X)], ['Y = y·Z³', sh(J.Y)], ['Z', sh(Z)]]), ...U.eqs('sm:e', 30, 260, [['(X : Y : Z) means the point (X/Z², Y/Z³)', 'strong'], ['any Z ≠ 0 names the same point'], [`back: x = X/Z² = ${sh(back.x)}`, 'good'], ['Z = 0 is the point at infinity O']], 16, 30)], say: `A point in Jacobian coordinates is (X : Y : Z), standing for the affine point (X/Z², Y/Z³). Scaling by any Z names the same point: with Z = ${Z}, G becomes X = x·Z², Y = y·Z³, and dividing back gives x again${C.toy ? `, ${back.x}` : ''}. Z = 0 stands for O.`, facts: { Z, J, G, back }, meta: { stage: 'repr' } });
      // one doubling and one mixed addition, counted
      const c1 = { M: 0, S: 0, I: 0 }, D = C.jdbl(C.toJ(G), c1), c2 = { M: 0, S: 0, I: 0 }, A = C.jaddMixed(D, G, c2), c3 = { M: 0, S: 0, I: 0 }, A3 = C.fromJ(A, c3);
      const aKind = C.a === C.p - 3n ? 'a = −3 lets 3X² + aZ⁴ factor as 3(X − Z²)(X + Z²)' : C.a === 0n ? 'a = 0 drops the aZ⁴ term' : 'a general a costs a little more';
      const pb = S.ECC.bitLength(C.p - 2n), pw = (C.p - 2n).toString(2).split('1').length - 1;
      F.add({ items: [head, ...U.table({ prefix: 'sm:c', x: 30, y: 60, cols: [{ w: 300, head: 'operation', mono: false, align: 'left' }, { w: 120, head: 'M' }, { w: 120, head: 'S' }, { w: 120, head: 'inversions' }], rows: [['affine doubling', '2', '2', '1'], ['Jacobian doubling', String(c1.M), String(c1.S), '0'], ['Jacobian + affine (mixed add)', String(c2.M), String(c2.S), '0'], ['back to affine at the end', String(c3.M), String(c3.S), '1']], rh: 36, hl: (r) => (r === 1 || r === 2 ? 'good' : r === 0 ? 'hot' : '') }).items, ...U.eqs('sm:e', 30, 300, [[aKind, 'act'], [`one inversion by Fermat, z^(p−2): ${pb - 1} S + ${pw - 1} M`, 'hot'], [`3P = ${P$(A3)}`, 'good']], 16, 30)], say: `Counted by the engine: a Jacobian doubling here costs ${c1.M} multiplications and ${c1.S} squarings (${aKind}), and adding an affine point to a Jacobian one ${c2.M}M + ${c2.S}S, with no inversion. An inversion by Fermat's little theorem, z^(p−2), would cost ${pb - 1} squarings and ${pw - 1} multiplications on its own, more than ${Math.floor((pb - 1 + pw - 1) / (c1.M + c1.S))} Jacobian doublings. The conversion back pays it once: G + 2G = ${P$(A3)}.`, facts: { M1: c1.M, S1: c1.S, M2: c2.M, S2: c2.S, pb1: pb - 1, pw1: pw - 1, ratio: Math.floor((pb - 1 + pw - 1) / (c1.M + c1.S)), R: A3 }, meta: { stage: 'count' } });
      // the cost table for k
      const L = E().scalar.ltr(C, k, G), Rr = E().scalar.rtl(C, k, G), Ld = E().scalar.ladder(C, k, G), W4 = E().scalar.wnaf(C, k, G, 4), W5 = E().scalar.wnaf(C, k, G, 5);
      const all = [['double-and-add, top first', L], ['double-and-add, bit 0 first', Rr], ['Montgomery ladder', Ld], ['wNAF, w = 4', W4], ['wNAF, w = 5', W5]];
      const best = all.reduce((x, y) => (y[1].cost.M + y[1].cost.S < x[1].cost.M + x[1].cost.S ? y : x));
      const worst = all.reduce((x, y) => (y[1].cost.M + y[1].cost.S > x[1].cost.M + x[1].cost.S ? y : x))[1];
      const same = all.every(([, r]) => C.eq(r.R, L.R));
      F.add({ items: [head, U.t('sm:k', 30, 56, `k = ${f(k)} (${S.ECC.bitLength(k)} bits)`, 'eq strong', 'start', 15), ...U.table({ prefix: 'sm:c', x: 30, y: 72, cols: [{ w: 290, head: 'method', mono: false, align: 'left' }, { w: 120, head: 'doublings' }, { w: 120, head: 'additions' }, { w: 90, head: 'M' }, { w: 90, head: 'S' }, { w: 120, head: 'affine: I' }], rows: all.map(([nm, r]) => [nm, String(r.doubles), String(r.adds), String(r.cost.M), String(r.cost.S), String(r.doubles + r.adds)]), rh: 38, hl: (r) => (all[r] === best ? 'good' : all[r][0] === 'Montgomery ladder' ? 'act' : '') }).items, ...U.eqs('sm:e', 30, 330, [[same ? 'all five give the same k·P' : 'the methods disagree!', same ? 'good' : 'bad'], [`cheapest here: ${best[0]}`, 'good'], [worst === Ld ? 'the ladder costs most, but its rhythm hides the bits' : 'the ladder\'s even rhythm hides the bits', 'act'], ['affine would need one inversion per operation', 'hot']], 16, 30)], say: `For this k, in Jacobian coordinates: ${all.map(([nm, r]) => `${nm}: ${r.cost.M}M + ${r.cost.S}S`).join('; ')}. The cheapest is ${best[0]}. In affine coordinates each of those group operations would also need an inversion, ${L.doubles + L.adds} of them for double-and-add. ${same ? 'All five agree on k·P.' : ''}`, facts: { k, ws: [4, 5], rows: all.map(([, r]) => [r.doubles, r.adds, r.cost.M, r.cost.S]), inv: L.doubles + L.adds, nb: S.ECC.bitLength(k) }, meta: { stage: 'table', same } });
      U.fix(F.list);
      return { frames: F.list, def: U.def('Jacobian coordinates', ['(X : Y : Z) ↦ (X/Z², Y/Z³); Z = 0 is O', 'doubling: no inversion (a few M and S)', 'mixed addition with Z₂ = 1: cheaper still', 'one inversion at the end: x = X/Z², y = Y/Z³']) };
    },
    predict: [
      { at: (f) => f.meta.stage === 'count', pick: 'option', ask: 'Which method do you expect to be cheapest for this k?', options: ['wNAF, w = 4', 'wNAF, w = 5', 'Montgomery ladder', 'double-and-add, top first'], answer: (fr, i) => { const t = fr[i + 1].facts.rows; const names = ['double-and-add, top first', 'double-and-add, bit 0 first', 'Montgomery ladder', 'wNAF, w = 4', 'wNAF, w = 5']; let b = 0; t.forEach((r, j) => { if (r[2] + r[3] < t[b][2] + t[b][3]) b = j; }); return names[b] === 'double-and-add, bit 0 first' ? 'double-and-add, top first' : names[b]; }, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: '(X : Y : Z) in Jacobian coordinates is the affine point…', options: ['(X/Z², Y/Z³)', '(X/Z, Y/Z)', '(XZ, YZ)', '(X, Y)'], answer: 0, why: 'The weights 2 and 3 make the formulas need no division.' },
      { q: 'What do Jacobian coordinates save?', options: ['the inversion in every group operation', 'all multiplications', 'the doublings', 'memory'], answer: 0, why: 'Only one inversion remains, at the end.' },
      { q: 'Which point has Z = 0?', options: ['O', 'G', '(0, 0)', 'none'], answer: 0, why: 'It is the point at infinity.' },
      { q: 'Why is P-256\'s a = −3?', options: ['it makes the doubling formula cheaper', 'it makes the curve prime', 'it was random', 'it hides the order'], answer: 0, why: '3X² − 3Z⁴ = 3(X − Z²)(X + Z²) saves multiplications.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
