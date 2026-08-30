// Part 8, making RSA fast (1): square-and-multiply read from the left and from the right, side by side with their
// operation counts, and the Montgomery ladder, whose pattern of operations does not depend on the exponent's bits.
(function (S) {
  'use strict';
  const P = S.PK, B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const NT = () => S.NT, A = () => S.P08A;
  const n$ = (v) => P.n(v);
  const fmt = (v, max) => S.Kit.pk.fmt(B(v), { max: max || 14 }).text;
  const MSG = 'Pay the bearer twelve silver coins.';

  /** the inputs shared by both topics: a toy x^e mod n, or the private exponent of a real key */
  const inputs = (def) => [
    { id: 'size', kind: 'choice', label: 'Size', def: 'toy', options: [{ value: 'toy', label: 'toy: choose x, e, n' }, { value: 'rsa1024', label: 'RSA-1024: m^d mod n' }, { value: 'rsa2048', label: 'RSA-2048: m^d mod n' }] },
    { id: 'x', kind: 'bigint', label: 'x', def: def.x },
    { id: 'e', kind: 'bigint', label: 'e', def: def.e },
    { id: 'n', kind: 'bigint', label: 'n', def: def.n },
  ];
  const check = (inp) => {
    if (inp.size !== 'toy') return null;
    let x, e, n;
    try { [x, e, n] = [inp.x, inp.e, inp.n].map((v) => B(String(v).trim())); } catch (er) { return 'x, e and n: whole numbers'; }
    if (n < 3n) return 'n: at least 3';
    if (n > 10n ** 12n) return 'n: at most 10^12 for the toy size (the real sizes are in the menu)';
    if (x < 2n || x >= n) return 'x: between 2 and n − 1';
    if (e < 2n) return 'e: at least 2';
    if (NT().bitLength(e) > 16) return 'e: at most 16 bits (65535), so every bit has its own column';
    return null;
  };
  /** the three numbers: x, e, n */
  const operands = (inp) => {
    if (inp.size === 'toy') return { x: B(inp.x), e: B(inp.e), n: B(inp.n), toy: true };
    const key = P.rsaKey(inp.size);
    return { x: A().textNum(MSG), e: key.d, n: key.n, toy: false };
  };
  /** which bits get a frame: all of a toy exponent; for a real one the start, the middle and the end */
  const frameBits = (L, toy) => (toy ? [...Array(L).keys()] : [...new Set([0, 1, 2, 3, Math.floor(L / 2), L - 2, L - 1])]);
  /** the exponent's bits as a row of cells (toy) or a carpet (real), with up to two pointers */
  const bitRow = (bits, y, lr, rl, toy) => {
    const items = [], L = bits.length;
    if (toy) {
      const cw = 36, x0 = 430 - (L * (cw + 4)) / 2;
      for (let i = 0; i < L; i++) {
        const cls = i === lr ? 'hot' : L - 1 - i === rl ? 'act' : bits[i] === '1' ? 'one bit' : '';
        items.push({ key: 'b' + i, kind: 'cell', x: P.r2(x0 + i * (cw + 4)), y, w: cw, h: 36, rx: 5, text: bits[i], size: 18, cls: 'hex ' + cls });
        items.push(P.t('bi' + i, x0 + i * (cw + 4) + cw / 2, y + 54, String(L - 1 - i), 'act', 'middle', 13));
        items.push(P.t('bt' + i, x0 + i * (cw + 4) + cw / 2, y - 10, String(i), 'hot', 'middle', 13));
      }
      items.push(P.t('bl', x0 - 12, y + 24, 'e =', 'strong', 'end', 16), P.t('bli', x0 - 12, y - 10, 'i from the left', 'hot', 'end', 13), P.t('blj', x0 - 12, y + 54, 'j from the right', 'act', 'end', 13));
      return items;
    }
    const per = 128, cs = 5;
    items.push(S.Kit.bits.carpet({ prefix: 'cp', x: 430 - (per * cs) / 2, y, bits, per, cs, upto: lr === null ? -1 : lr, gap: 1 }));
    items.push(P.t('bl', 430 - (per * cs) / 2, y - 10, `d: ${L} bits, ${per} to a row (read so far lit)`, 'strong', 'start', 14));
    return items;
  };

  // ---------------------------------------------------------------------------------------------------------------
  // Square-and-multiply, both ways
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p08-sqm', family: 'p08-speed', order: 10, title: 'Square-and-multiply, from either end',
    blurb: 'x^e mod n in about log₂ e steps instead of e. Read the exponent from the left: square at every bit, multiply by x at every 1. Or from the right: keep squaring x to get x, x², x⁴, x⁸, … and multiply in the powers whose bit is 1. The counts come out the same.',
    inputs: inputs({ x: '7', e: '2989', n: '10403' }),
    check,
    presets: [
      { label: '7^2989 mod 10403', values: { size: 'toy', x: '7', e: '2989', n: '10403' } },
      { label: 'e = 2^15 + 1: two 1 bits', values: { size: 'toy', x: '123', e: '32769', n: '1000003' } },
      { label: 'e = 2^12: no multiplications', values: { size: 'toy', x: '5', e: '4096', n: '9973' } },
      { label: 'All ones: e = 255', values: { size: 'toy', x: '3', e: '255', n: '1009' } },
      { label: 'RSA-1024 private exponent', values: { size: 'rsa1024' } },
      { label: 'RSA-2048 private exponent', values: { size: 'rsa2048' } },
    ],
    counters: [{ id: 'lrs', label: 'left: squarings' }, { id: 'lrm', label: 'left: multiplications' }, { id: 'rls', label: 'right: squarings' }, { id: 'rlm', label: 'right: multiplications' }],
    run(inp) {
      const { x, e, n, toy } = operands(inp);
      const lr = P.memo('p08-lr', [x, e, n].map(String), () => S.RSA.powLR(x, e, n)), rl = P.memo('p08-rl', [x, e, n].map(String), () => S.RSA.powRL(x, e, n));
      const bits = lr.bits, L = bits.length, ones = [...bits].filter((b) => b === '1').length;
      const F = new S.Frames(['lrs', 'lrm', 'rls', 'rlm']);
      const view = { x: -10, y: -40, w: 880, h: toy ? 620 : 560 }, ty = toy ? 120 : 150;
      const tables = (t) => {
        const rowsL = lr.steps.map((s, i) => (i <= t ? [String(i), s.bit ? '1' : '0', i === 0 ? 'start' : s.bit ? 'S·M' : 'S', fmt(s.value)] : [String(i), bits[i], '', '']));
        const rowsR = rl.steps.map((s, j) => (j <= t ? [String(j), fmt(s.power), String(s.bit), s.bit || j === 0 ? fmt(s.acc) : '–'] : [String(j), '', String(s.bit), '']));
        const o = { size: 13, mono: true, ch: toy ? (L > 13 ? 25 : 28) : undefined, maxRows: toy ? undefined : 9, focus: [t, 0] };
        const tl = S.Kit.table.draw(Object.assign({ prefix: 'tl', x: 0, y: ty, colHead: ['i', 'bit', 'step', 'value'], rows: rowsL, act: [[t, 2], [t, 3]], title: 'left to right' }, o));
        const tr = S.Kit.table.draw(Object.assign({ prefix: 'tr', x: 380, y: ty, colHead: ['j', 'x^(2^j)', 'bit', 'product'], rows: rowsR, hot: rl.steps[t] && rl.steps[t].bit ? [[t, 3]] : [], act: [[t, 1]], title: 'right to left' }, o, { focus: [t, 0] }));
        return tl.items.concat(tr.items);
      };
      const tally = (t) => {
        const s = lr.steps.slice(1, t + 1), r = rl.steps.slice(0, t + 1);
        F.set('lrs', s.length).set('lrm', s.filter((z) => z.bit).length).set('rls', Math.min(t, L - 1)).set('rlm', Math.max(0, r.filter((z) => z.bit).length - 1));
      };
      F.add({ items: bitRow(bits, -10, null, null, toy).concat(tables(-1)), say: `Compute ${n$(x)}^e mod ${n$(n)} with e = ${n$(e)}, ${P.plural(L, 'bit')} of which ${ones} are 1. Multiplying by x again and again would take e − 1 = ${n$(e - 1n)} multiplications; reading the bits takes about ${L} steps.`, facts: { x, e, n, L, ones, em: e - 1n }, meta: { phase: 'start' } });
      for (const t of frameBits(L, toy)) {
        tally(t);
        const s = lr.steps[t], r = rl.steps[t];
        const left = t === 0 ? `From the left, the leading 1 starts the value at x = ${n$(s.value)}.` : s.bit ? `From the left, bit ${t} is 1: square to ${n$(s.squared)}, then multiply by x: ${n$(s.value)}.` : `From the left, bit ${t} is 0: square to ${n$(s.value)}.`;
        const jj = toy ? `x^${2 ** t}` : `x^(2^${t})`;
        const right = r.bit ? (t === 0 || rl.steps.slice(0, t).every((z) => !z.bit) ? `From the right, bit ${t} is 1: the product starts as ${jj} = ${n$(r.power)}.` : `From the right, bit ${t} is 1: ${jj} = ${n$(r.power)} is multiplied in, giving ${n$(r.acc)}.`) : `From the right, bit ${t} is 0: ${jj} = ${n$(r.power)} is skipped.`;
        F.add({ items: bitRow(bits, -10, t, t, toy).concat(tables(t)), say: left + ' ' + right, facts: { t, lr: s, rl: r, pw: toy ? 2 ** t : t }, meta: { phase: 'bit', t } });
      }
      const same = lr.value === rl.value;
      F.add({ items: bitRow(bits, -10, L - 1, L - 1, toy).concat(tables(L - 1)), say: `Both give ${n$(lr.value)}${same ? '' : ' (they differ!)'}. Left to right: ${lr.squarings} squarings and ${P.plural(lr.multiplications, 'multiplication')}; right to left: ${rl.squarings} squarings and ${P.plural(rl.multiplications, 'multiplication')}: one squaring per bit after the first and one multiplication per 1 bit after the first. The left-to-right loop always multiplies by the same x (so tables of x³, x⁵, … can speed it up); the right-to-left loop can square ahead independently.`, facts: { v: lr.value, ls: lr.squarings, lm: lr.multiplications, rs: rl.squarings, rm: rl.multiplications }, meta: { phase: 'end' } });
      for (const f of F.list) f.narrowView = { x: -10, y: toy ? 60 : 110, w: 400, h: toy ? 520 : 440 };
      return { frames: P.fix(F.list, view), def: P.def('Square-and-multiply', ['left to right: v = x', '  for each later bit: v = v² mod n; if the bit is 1, v = v·x mod n', 'right to left: p = x, acc = 1', '  for each bit from the right: if 1, acc = acc·p; then p = p²', 'cost: (bits − 1) squarings + (ones − 1) multiplications']) };
    },
    predict: [
      { at: (f) => f.meta.phase === 'start', pick: 'option', ask: 'How many multiplications (not counting squarings) will the left-to-right method need?', options: (fr) => { const x = fr[fr.length - 1].facts, o = fr[0].facts; return [...new Set([String(x.lm), String(o.ones), String(o.L - 1), String(o.L)])]; }, answer: (fr) => String(fr[fr.length - 1].facts.lm), explain: (fr) => fr[fr.length - 1].say },
      { at: (f, i, fr) => f.meta.phase === 'bit' && fr[i + 1] && fr[i + 1].meta.phase === 'bit' && f.meta.t === 1, pick: 'option', ask: (fr, i) => `What does the left-to-right loop do at bit ${fr[i + 1].meta.t}?`, options: ['square only', 'square, then multiply by x'], answer: (fr, i) => (fr[i + 1].facts.lr.bit ? 'square, then multiply by x' : 'square only'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'x^e by square-and-multiply needs about how many squarings?', options: ['e', 'e/2', 'log₂ e', '√e'], answer: 2, why: 'One squaring for each bit after the first.' },
      { q: 'For e = 2^12 = 4096, how many multiplications by x (left to right)?', options: ['0', '1', '12', '4095'], answer: 0, why: 'A single 1 bit, the leading one: twelve squarings and no multiplication.' },
      { q: 'Which values does the right-to-left method keep squaring?', options: ['The product so far', 'x, x², x⁴, x⁸, …', 'The exponent', 'n'], answer: 1, why: 'Each step squares the power of x; the ones whose bit is 1 are multiplied into the product.' },
      { q: 'Why does the order of S and M operations matter for security?', options: ['It does not', 'Someone measuring time or power can read the 1 bits of a secret exponent from it', 'It changes the result', 'It makes n easier to factor'], answer: 1, why: 'An S followed by M marks a 1 bit; that is the timing and power leak the ladder avoids.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The Montgomery ladder
  // ---------------------------------------------------------------------------------------------------------------
  /** a row of operations grouped by exponent bit, each group headed by its bit: what a power trace would show */
  const strip = (prefix, ops, y, x0, label) => {
    const items = [P.t(prefix + ':l', x0, y - 34, label, 'title')];
    let x = x0, last = null;
    ops.forEach((o, k) => {
      if (last !== null && o.i !== last) x += 8;
      if (o.i !== last) items.push(P.t(prefix + ':b' + o.i, x + 11, y - 8, o.bit, 'muted', 'start', 13));
      items.push({ key: prefix + ':' + k, kind: 'cell', x, y, w: 21, h: o.op === 'S' ? 28 : 40, rx: 3, text: o.op, size: 13, cls: (o.op === 'S' ? 'act' : 'hot') + (o.cur ? ' ring' : '') });
      x += 23; last = o.i;
    });
    return items;
  };
  S.topic({
    id: 'p08-ladder', family: 'p08-speed', order: 20, title: 'The Montgomery ladder',
    blurb: 'Two registers, R0 and R1 = R0·x. At every bit one of them is multiplied by the other and the other is squared, whatever the bit; the bit only decides which is which. The sequence of operations is the same for every exponent of a given length.',
    inputs: inputs({ x: '7', e: '2989', n: '10403' }),
    check,
    presets: [
      { label: '7^2989 mod 10403', values: { size: 'toy', x: '7', e: '2989', n: '10403' } },
      { label: 'e = 1000: few 1 bits', values: { size: 'toy', x: '11', e: '1000', n: '65537' } },
      { label: 'e = 255: all ones', values: { size: 'toy', x: '3', e: '255', n: '1009' } },
      { label: 'RSA-1024 private exponent', values: { size: 'rsa1024' } },
    ],
    counters: [{ id: 'lad', label: 'ladder operations' }, { id: 'sqm', label: 'square-and-multiply operations' }],
    run(inp) {
      const { x, e, n, toy } = operands(inp);
      const ld = P.memo('p08-lad', [x, e, n].map(String), () => S.RSA.ladder(x, e, n)), lr = P.memo('p08-lr', [x, e, n].map(String), () => S.RSA.powLR(x, e, n));
      const bits = ld.bits, L = bits.length;
      const F = new S.Frames(['lad', 'sqm']);
      const view = { x: -10, y: -40, w: 880, h: 560 }, RY = toy ? 100 : 130;
      const opsUpTo = (t) => {
        const lo = toy ? 0 : Math.max(0, t - 7), sqm = [], lad = [];
        for (let i = lo; i <= t; i++) {
          const b = bits[i];
          if (i > 0) { sqm.push({ op: 'S', cur: i === t, i, bit: b }); if (b === '1') sqm.push({ op: 'M', cur: i === t, i, bit: b }); }
          lad.push({ op: 'M', cur: i === t, i, bit: b }, { op: 'S', cur: i === t, i, bit: b });
        }
        return { sqm, lad, lo };
      };
      const regs = (s, lit) => [
        ...A().row('r0', 0, RY, 'R0', s ? s.r0 : 1n, lit === 0 ? 'act' : s ? 'hot' : '', { lw: 60, w: 300, max: 20 }),
        ...A().row('r1', 430, RY, 'R1', s ? s.r1 : x, lit === 1 ? 'act' : s ? 'hot' : '', { lw: 60, w: 300, max: 20 }),
      ].concat(s ? [P.t('o0', 220, RY + 56, s.bit ? '← R0·R1' : '← R0²', s.bit ? 'act' : 'hot', 'middle', 15), P.t('o1', 650, RY + 56, s.bit ? '← R1²' : '← R0·R1', s.bit ? 'hot' : 'act', 'middle', 15)] : []);
      const draw = (t, extra) => {
        const s = t >= 0 ? ld.steps[t] : null, o = opsUpTo(Math.max(t, 0));
        const lit = s ? (s.bit ? 1 : 0) : -1;
        const items = bitRow(bits, -10, t >= 0 ? t : null, null, toy).concat(regs(s, s ? (s.bit ? 0 : 1) : -1));
        const inv = s ? P.t('inv', 430, RY + 92, `R1 = R0·x mod n: ${(s.r0 * x) % n === s.r1 ? 'holds' : 'broken'}`, (s.r0 * x) % n === s.r1 ? 'good' : 'bad', 'middle', 15) : P.t('inv', 430, RY + 92, 'start: R0 = 1, R1 = x', 'muted', 'middle', 15);
        items.push(inv);
        if (t >= 0) {
          const from = o.lo ? ` (bits ${o.lo} to ${t})` : '';
          items.push(...strip('sq', o.sqm, RY + 180, 0, 'square-and-multiply' + from), ...strip('ld', o.lad, RY + 300, 0, 'Montgomery ladder' + from));
        }
        return items.concat(extra || []);
      };
      F.add({ items: draw(-1), say: `Compute ${n$(x)}^e mod ${n$(n)}, e = ${n$(e)} with ${P.plural(L, 'bit')}. The ladder keeps R0 = 1 and R1 = x, and keeps R1 = R0·x after every step.`, facts: { x, e, n, L }, meta: { phase: 'start' } });
      for (const t of frameBits(L, toy)) {
        const s = ld.steps[t];
        F.set('lad', 2 * (t + 1)).set('sqm', t + [...bits.slice(1, t + 1)].filter((b) => b === '1').length);
        const say = s.bit ? `Bit ${t} is 1: R0 = R0·R1 = ${n$(s.r0)} and R1 = R1² = ${n$(s.r1)}. One multiplication and one squaring.` : `Bit ${t} is 0: R1 = R0·R1 = ${n$(s.r1)} and R0 = R0² = ${n$(s.r0)}. Again one multiplication and one squaring: only the registers swap roles.`;
        F.add({ items: draw(t), say, facts: { t, r0: s.r0, r1: s.r1 }, meta: { phase: 'bit', t, bit: s.bit } });
      }
      F.add({ items: draw(L - 1), say: `R0 = ${n$(ld.value)}, the same as square-and-multiply's ${n$(lr.value)}. The ladder did ${ld.squarings} squarings and ${ld.multiplications} multiplications, square-and-multiply ${lr.squarings} and ${lr.multiplications}: the ladder costs a little more, but its row of operations is M S M S … for every exponent, so timing and power traces no longer show the bits.`, facts: { v: ld.value, w: lr.value, ls: ld.squarings, lm: ld.multiplications, ss: lr.squarings, sm: lr.multiplications }, meta: { phase: 'end' } });
      return { frames: P.fix(F.list, view), def: P.def('Montgomery ladder', ['R0 = 1, R1 = x', 'for each bit from the left:', '  bit 1: R0 = R0·R1, R1 = R1²', '  bit 0: R1 = R0·R1, R0 = R0²', 'invariant: R1 = R0·x', 'result: R0 = x^e', 'one multiplication and one squaring per bit, always']) };
    },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'bit' && fr[i + 1] && fr[i + 1].meta.phase === 'bit' && f.meta.t === 0, pick: 'option', ask: (fr, i) => `Bit ${fr[i + 1].meta.t} is ${fr[i + 1].meta.bit}. Which register is squared?`, options: ['R0', 'R1'], answer: (fr, i) => (fr[i + 1].meta.bit ? 'R1' : 'R0'), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'end', pick: 'option', ask: 'Watching only the sequence of operations, what can an attacker learn about the exponent from the ladder?', options: ['every bit', 'the number of 1 bits', 'only its length'], answer: 'only its length', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What stays true after every step of the ladder?', options: ['R0 = R1', 'R1 = R0·x', 'R0 = x^bit', 'R1 = 1'], answer: 1, why: 'Both branches keep R1 = R0·x, so the result in R0 is x^e.' },
      { q: 'How many operations does the ladder do per exponent bit?', options: ['One or two, depending on the bit', 'Always one multiplication and one squaring', 'Always two squarings', 'None for a 0 bit'], answer: 1, why: 'The bit only chooses which register is multiplied and which is squared.' },
      { q: 'Why is that good?', options: ['It is faster', 'The pattern of operations does not depend on the secret bits', 'It needs less memory', 'It works without a modulus'], answer: 1, why: 'A uniform sequence removes the simple timing and power leak of square-and-multiply.' },
      { q: 'Is a uniform sequence of operations enough on its own?', options: ['Yes, always', 'No: memory access and the data values can still leak', 'Only for even exponents', 'Only on toy sizes'], answer: 1, why: 'Which register is read or written, and the values themselves, can still leak; real code also avoids secret-dependent branches and addresses.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
