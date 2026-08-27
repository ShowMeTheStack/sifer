// Part 7, why public keys: trapdoor one-way functions. Three functions, each computed forwards and then undone the
// hard way: multiplying two primes (undone by factoring), raising a generator to a power (undone by a discrete
// logarithm), and the RSA function x^e mod n (undone by taking e-th roots, which is easy only with the trapdoor d).
// Toy and 40-bit sizes are really attacked here; for real sizes the work is the best known attack's estimate.
(function (S) {
  'use strict';
  const P = S.PK, NT = () => S.NT;
  const enc = (s) => NT().fromBytes(new TextEncoder().encode(s));
  const log2 = (v) => Math.log2(Math.max(1, Number(v)));
  const fmt = (v) => BigInt(v).toLocaleString('en-US');

  /** trial division of an odd n by 3, 5, 7, …: the factor and the number of divisions it took */
  const trial = (n) => {
    if (n < 2n ** 53n) { const m = Number(n); let k = 0; for (let d = 3; d * d <= m; d += 2) { k++; if (m % d === 0) return { p: BigInt(d), divisions: k }; } return { p: null, divisions: k }; }
    let k = 0; for (let d = 3n; d * d <= n; d += 2n) { k++; if (n % d === 0n) return { p: d, divisions: k }; } return { p: null, divisions: k };
  };

  /** the setting for a function and a size: everything worked out once */
  const setting = (fn, size) => P.memo('p07-trapdoor', { fn, size }, () => {
    const o = { fn, size, real: size === 'real' };
    if (fn === 'dlog') {
      const group = size === 'toy' ? S.DLP.groupZp(1019n) : size === 'small' ? S.DLP.groupZp(NT().nextPrime(4000000000n)) : P.modp14();
      const p = group.p, g = group.generator;
      const x = size === 'toy' ? 777n : size === 'small' ? 3141592653n % (p - 1n) : NT().fromBytes(S.SHA256.hash(new TextEncoder().encode('a secret exponent for the trapdoor page')));
      const fw = S.RSA.powLR(g, x, p);
      Object.assign(o, { p, g, x, y: fw.value, fwOps: fw.squarings + fw.multiplications, fwSq: fw.squarings, fwMul: fw.multiplications, bits: P.bits(p) });
      if (!o.real) { const r = S.DLP.attack.bsgs(group, fw.value); Object.assign(o, { found: r.x, m: r.m, giant: r.giantSteps, backOps: Number(r.m) + r.giantSteps }); o.backBits = log2(o.backOps); }
      else o.backBits = P.gnfsBits(o.bits);
      return o;
    }
    let key;
    if (size === 'toy') key = S.RSA.fromPrimes(233n, 211n, 17n);
    else if (size === 'small') key = S.RSA.fromPrimes(NT().nextPrime(900000n), NT().nextPrime(700000n), 65537n);
    else key = P.rsaKey('rsa2048');
    Object.assign(o, { p: key.p, q: key.q, n: key.n, e: key.e, d: key.d, bits: key.bits });
    if (fn === 'factor') { o.fwOps = 1; o.y = key.n; }
    else {
      o.x = size === 'toy' ? 4321n : size === 'small' ? 123456789n : enc('meet me by the old mill at six');
      const fw = S.RSA.powLR(o.x, key.e, key.n), tr = S.RSA.powLR(fw.value, key.d, key.n);
      Object.assign(o, { y: fw.value, fwOps: fw.squarings + fw.multiplications, fwSq: fw.squarings, fwMul: fw.multiplications, trOps: tr.squarings + tr.multiplications, back: tr.value });
      o.trBits = log2(o.trOps);
    }
    if (!o.real) { const t = trial(key.n); Object.assign(o, { found: t.p, divisions: t.divisions, backOps: t.divisions }); o.backBits = log2(t.divisions); }
    else o.backBits = P.gnfsBits(o.bits);
    return o;
  });

  const TITLE = { factor: 'Multiplying two primes', dlog: 'Powers of a generator', rsa: 'The RSA function' };
  S.topic({
    id: 'p07-trapdoor', family: 'p07-why', order: 20, title: 'Trapdoor one-way functions',
    blurb: 'A one-way function is easy to compute and infeasible to undo: multiplying primes, or raising a generator to a power. A trapdoor one-way function is undone easily by whoever holds one extra secret, the trapdoor; RSA is the classic one, and the trapdoor is d.',
    inputs: [
      { id: 'fn', kind: 'choice', label: 'Function', def: 'rsa', options: [{ value: 'rsa', label: 'x ↦ x^e mod n (RSA)' }, { value: 'factor', label: '(p, q) ↦ p·q' }, { value: 'dlog', label: 'x ↦ g^x mod p' }] },
      { id: 'size', kind: 'choice', label: 'Size', def: 'toy', options: [{ value: 'toy', label: 'toy (5 digits)' }, { value: 'small', label: 'small (10 to 12 digits)' }, { value: 'real', label: 'real (2048 bits)' }] },
    ],
    presets: [
      { label: 'RSA, toy', values: { fn: 'rsa', size: 'toy' } },
      { label: 'RSA, 12 digits', values: { fn: 'rsa', size: 'small' } },
      { label: 'RSA-2048', values: { fn: 'rsa', size: 'real' } },
      { label: 'Factoring, 12 digits', values: { fn: 'factor', size: 'small' } },
      { label: 'Factoring 2048 bits', values: { fn: 'factor', size: 'real' } },
      { label: 'Logarithm, toy', values: { fn: 'dlog', size: 'toy' } },
      { label: 'Logarithm, 2048 bits', values: { fn: 'dlog', size: 'real' } },
    ],
    counters: [{ id: 'fw', label: 'operations forwards' }, { id: 'back', label: 'operations backwards' }],
    run(inp) {
      const o = setting(inp.fn, inp.size), fn = inp.fn, real = o.real;
      const F = new S.Frames(['fw', 'back']);
      const view = { x: -10, y: 0, w: 880, h: 470 };
      const K = S.Kit.pk;
      const inLabel = fn === 'factor' ? 'p, q' : 'x', outLabel = fn === 'factor' ? 'n = p·q' : 'y = f(x)';
      const inVal = fn === 'factor' ? null : o.x;
      const lx = 150, rx = 690, cy = 130;
      const fName = fn === 'factor' ? 'multiply' : fn === 'dlog' ? 'g^x mod p' : 'x^e mod n';
      const boxes = (stage) => {
        const items = [P.title('h', 0, 22, TITLE[fn] + ' · ' + P.bits(fn === 'dlog' ? o.p : o.n) + '-bit ' + (fn === 'dlog' ? 'p' : 'n'))];
        if (fn === 'factor') {
          items.push(K.value({ key: 'in1', x: lx, y: cy - 26, label: 'p', value: o.p, max: 18 }), K.value({ key: 'in2', x: lx, y: cy + 38, label: 'q', value: o.q, max: 18 }));
        } else items.push(K.value({ key: 'in1', x: lx, y: cy, label: 'x', value: inVal, max: 18, cls: stage >= 3 && fn === 'rsa' ? 'good' : '' }));
        if (stage >= 1) items.push(K.value({ key: 'out', x: rx, y: cy, label: outLabel, value: o.y, max: 18, cls: 'act' }));
        else items.push({ key: 'out', kind: 'state', x: rx, y: cy, w: 150, h: 58, rx: 7, lines: [outLabel, '?'], cls: 'block val2 soft' });
        items.push({ key: 'fbox', kind: 'state', x: 420, y: cy - 50, w: 120, h: 34, rx: 6, text: fName, cls: 'block small' + (stage === 1 ? ' act' : '') });
        items.push({ key: 'fw', kind: 'wire', pts: [[262, cy - 50], [358, cy - 50]], cls: stage === 1 ? 'act' : '' }, { key: 'fw2', kind: 'wire', pts: [[482, cy - 50], [596, cy - 50]], head: true, cls: stage === 1 ? 'act' : '' });
        items.push({ key: 'bk', kind: 'wire', pts: [[596, cy + 70], [262, cy + 70]], head: true, cls: stage === 2 ? 'hot' : stage >= 3 && fn === 'rsa' ? 'good' : 'faint' });
        const backText = fn === 'factor' ? 'factor n' : fn === 'dlog' ? 'discrete logarithm' : stage >= 3 ? 'y^d mod n, with the trapdoor d' : 'e-th root mod n';
        items.push(P.t('bkl', 429, cy + 96, backText, stage === 2 ? 'hot' : stage >= 3 && fn === 'rsa' ? 'good' : 'muted', 'middle', 14));
        if (stage >= 3 && fn === 'rsa') items.push(K.chip({ key: 'trap', x: 429, y: cy + 70, label: 'd', value: o.d, max: 12, cls: 'key' }));
        return items;
      };
      // the bars: log2 of the work
      const top = Math.max(o.backBits, o.trBits || 0, 4) * 1.12, step = [1, 2, 5, 10, 25, 50, 100].find((v) => top / v <= 6), maxBits = Math.ceil(top / step) * step;
      const bars = (rows) => {
        const items = [P.title('bt', 0, 262, 'work, as a power of two (log₂ of the operations)')], x0 = 220, W = 560;
        for (let v = 0; v <= maxBits; v += step) {
          const x = x0 + (v / maxBits) * W;
          items.push({ key: 'g' + v, kind: 'line', x1: P.r2(x), y1: 280, x2: P.r2(x), y2: 284 + rows.length * 44, cls: 'faint', audit: 'ignore', layer: 'back' }, P.t('gl' + v, x, 300 + rows.length * 44, '2' + P.sup(v), 'tick', 'middle', 13));
        }
        rows.forEach(([label, bits, cls, note], i) => {
          const y = 290 + i * 44;
          items.push(P.t('bl' + i, x0 - 12, y + 18, label, 'strong', 'end', 14));
          items.push({ key: 'bar' + i, kind: 'cell', x: x0, y, w: Math.max(3, P.r2((bits / maxBits) * W)), h: 26, rx: 3, text: '', cls: cls });
          items.push(P.t('bn' + i, x0 + Math.max(3, (bits / maxBits) * W) + 10, y + 18, note, 'mono', 'start', 14));
        });
        return items;
      };
      const fwBits = log2(o.fwOps), fwNote = P.plural(o.fwOps, 'operation');
      const backNote = real ? '≈ 2' + P.sup(Math.round(o.backBits)) : P.plural(fmt(o.backOps), fn === 'dlog' ? 'step' : 'division');
      const rowsAt = (k) => [['forwards', fwBits, 'good', fwNote]].concat(k >= 2 ? [['backwards', o.backBits, 'bad', backNote]] : []).concat(k >= 3 && fn === 'rsa' ? [['with the trapdoor', o.trBits, 'key', P.plural(o.trOps, 'operation')]] : []);
      const add = (stage, say, facts, phase) => F.add({ items: boxes(stage).concat(bars(rowsAt(stage))), say, facts, meta: { phase } });

      // 0: the function
      const what = fn === 'factor' ? `Take two primes p = ${P.n(o.p)} and q = ${P.n(o.q)}. The function multiplies them.`
        : fn === 'dlog' ? `Work modulo the prime p = ${P.n(o.p)} with the generator g = ${o.g}. The function takes an exponent x = ${P.n(o.x)} to g^x mod p.`
          : `An RSA public key n = ${P.n(o.n)}, e = ${o.e}. The function takes x = ${P.n(o.x)} to x^e mod n.`;
      add(0, what + ' Forwards it is quick; the question is how hard it is to go back.', { p: o.p, q: o.q, g: o.g, x: o.x, n: o.n, e: o.e }, 'start');
      // 1: forwards
      F.set('fw', o.fwOps);
      add(1, fn === 'factor' ? `Forwards: one multiplication gives n = ${P.n(o.n)}, ${P.an(o.bits)}-bit number.`
        : `Forwards: square-and-multiply needs ${o.fwSq} squarings and ${o.fwMul} multiplications, ${o.fwOps} operations in all, and gives y = ${P.n(o.y)}.`,
      { n: o.n, bits: o.bits, sq: o.fwSq, mul: o.fwMul, ops: o.fwOps, y: o.y }, 'forward');
      // 2: backwards, the hard way
      F.set('back', real ? 0 : o.backOps);
      let back;
      if (real) {
        back = fn === 'dlog' ? `Backwards: find x from y. The best known method for a ${o.bits}-bit prime, the number field sieve, needs about 2^${Math.round(o.backBits)} operations: far beyond every computer on Earth.`
          : `Backwards: ${fn === 'rsa' ? 'without d, the only known way to take e-th roots modulo n is to factor n, and ' : ''}the best factoring method, the number field sieve, needs about 2^${Math.round(o.backBits)} operations for ${P.an(o.bits)}-bit n: out of reach.`;
      } else if (fn === 'dlog') back = `Backwards: baby-step giant-step finds x = ${P.n(o.found)} in ${fmt(o.backOps)} steps (a table of ${P.n(o.m)} baby steps and ${o.giant} giant steps). It grows with √p: each extra bit of p makes it about 1.4 times slower.`;
      else back = `Backwards: ${fn === 'rsa' ? 'without d, the way back is to factor n. ' : ''}Trial division finds p = ${P.n(o.found)} after ${fmt(o.backOps)} divisions. Every extra digit of n makes this about 3 times slower; better methods exist, but none is fast.`;
      add(2, back, { bits: o.bits, back: Math.round(o.backBits), found: o.found, ops: o.backOps, m: o.m, giant: o.giant }, 'back');
      // 3: the trapdoor, or none
      if (fn === 'rsa') {
        add(3, `With the trapdoor d = ${P.n(o.d)}, going back is easy: y^d mod n takes ${P.plural(o.trOps, 'operation')} and gives ${P.n(o.back)}, the x we started from. ${o.trOps > 4 * o.fwOps ? 'That is more than forwards, because d is long and e is short, but it is still nothing. ' : ''}Publishing n and e lets anyone go forwards; only the holder of d comes back.`,
          { d: o.d, ops: o.trOps, back: o.back }, 'trapdoor');
      } else {
        add(2, fn === 'factor' ? 'Multiplication is one-way, but it has no trapdoor: nobody holds a secret that makes factoring easy. RSA builds a trapdoor on top of it: whoever knows p and q can compute d.'
          : 'The power map is one-way with no trapdoor: nobody can take logarithms easily. That is still enough for Diffie–Hellman and for signatures, which need a one-way function but no way back.', {}, 'none');
      }
      const gap = Math.round(o.backBits - fwBits);
      const grow = Math.round(P.gnfsBits(2 * o.bits) - o.backBits);
      add(fn === 'rsa' ? 3 : 2, `The gap is the point: about ${real ? '2^' + gap : fmt(Math.round(2 ** (o.backBits - fwBits)))} times more work backwards than forwards${real ? '' : ' even at this size'}${fn === 'rsa' ? `, and only ${P.plural(o.trOps, 'operation')} for whoever holds the trapdoor` : ''}. ` + (real ? `Doubling the length to ${o.bits * 2} bits would multiply the forward work by about 8 and the attack work by about 2^${grow}.` : `Doubling the length of the numbers multiplies the forward work by about 8 and squares the work of this attack.`),
        { gap, ratio: Math.round(2 ** (o.backBits - fwBits)), ops: o.trOps, bits2: o.bits * 2, grow }, 'end');
      for (const f of F.list) f.narrowView = { x: -10, y: 0, w: 880, h: 470 };
      return { frames: P.fix(F.list, view), def: P.def('One-way and trapdoor', ['one-way: f(x) easy, x from f(x) infeasible', 'trapdoor: easy to invert given a secret t', 'RSA: f(x) = x^e mod n, t = d (or p and q)', 'multiplication: undone by factoring', 'g^x mod p: undone by the discrete logarithm']) };
    },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'forward', pick: 'option', ask: 'Going backwards, without any secret: how does the work compare?', options: ['about the same', 'a few times more', 'enormously more'], answer: 'enormously more', explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta.phase === 'back' && fr[i + 1] && fr[i + 1].meta.phase === 'trapdoor', pick: 'option', ask: 'With the trapdoor d, how much work is going back?', options: ['easy: one exponentiation', 'as hard as factoring', 'impossible'], answer: 'easy: one exponentiation', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What makes a one-way function a trapdoor one-way function?', options: ['It is fast', 'A secret makes inverting it easy', 'It has no inverse', 'It is a permutation'], answer: 1, why: 'A trapdoor is extra information that turns the infeasible inverse into an easy one; RSA\'s is d (or p and q).' },
      { q: 'Which function has no known trapdoor?', options: ['x ↦ x^e mod n', 'x ↦ g^x mod p', 'both', 'neither'], answer: 1, why: 'Nobody knows a secret that makes discrete logarithms easy; RSA\'s inverse is easy given d.' },
      { q: 'Squaring-and-multiplying a 2048-bit exponent costs about…', options: ['2048 operations', '3000 operations', '2^2048 operations', '2^112 operations'], answer: 1, why: 'One squaring per bit and a multiplication for about half of them: roughly 3000 operations.' },
      { q: 'Why can Diffie–Hellman use a function with no trapdoor?', options: ['It never needs to invert it', 'It uses RSA inside', 'It is not secure', 'It inverts it by brute force'], answer: 0, why: 'Both sides only compute forwards (powers); nobody ever needs a logarithm.' },
      { q: 'Trial division of n needs about how many divisions?', options: ['log n', '√n / 2 at worst', 'n²', 'n'], answer: 1, why: 'The smaller prime is at most √n, and only odd divisors are tried.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
