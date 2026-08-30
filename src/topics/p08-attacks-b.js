// Part 8, why the rules for RSA keys exist (second half): primes chosen too close together, primes shared between
// keys, and one glitch in CRT signing. Each shows the weakness and when it applies, states what it costs without
// working the recovery through, and ends with its defence. Keys are made here; the engines of
// src/core/pk-rsa-attacks.js only confirm the outcome each frame states.
(function (S) {
  'use strict';
  const P = S.PK, NT = () => S.NT, K = () => S.Kit.pk;
  const fmt = (v) => BigInt(v).toLocaleString('en-US');

  // ---------------------------------------------------------------------------------------------------------------
  // Fermat factoring of close primes
  // ---------------------------------------------------------------------------------------------------------------
  const FSIZE = { toy: { bits: 0, def: 9, min: 1, max: 13 }, rsa1024: { bits: 512, def: 259, min: 2, max: 262 }, rsa2048: { bits: 1024, def: 515, min: 2, max: 518 } };
  const fermatCase = (size, gapBits) => P.memo('p08-fermat', { size, gapBits }, () => {
    const c = FSIZE[size], p0 = size === 'toy' ? 10007n : P.prime(c.bits, 0);
    const lo = p0, hi = NT().nextPrime(p0 + (1n << BigInt(gapBits)));
    const n = lo * hi, r0 = NT().isqrt(n), root = r0 * r0 < n ? r0 + 1n : r0;
    const mid = (lo + hi) / 2n, expect = mid - root + 1n;
    const run = expect <= 2000n ? S.RSA.attack.fermat({ n, limit: 2000 }) : null;
    return { size, gapBits, lo, hi, n, root, mid, expect, run, nlen: P.bits(n), gap: hi - lo };
  });
  S.topic({
    id: 'p08-fermat', family: 'p08-attacks', order: 50, title: 'Fermat factoring of close primes',
    blurb: 'If p and q are close, n is close to a square: n = a² − b² with a just above √n and b small. Fermat\'s method looks for exactly that shape, and for close primes it succeeds almost at once, whatever the size of n. Key generation standards therefore require the primes to be far apart.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Key', def: 'rsa1024', options: [{ value: 'toy', label: 'toy (p = 10007)' }, { value: 'rsa1024', label: 'RSA-1024' }, { value: 'rsa2048', label: 'RSA-2048' }] },
      { id: 'gap', kind: 'number', label: 'q − p about 2^', def: 259, min: 1, max: 1100, check: (v, inp) => { const c = FSIZE[inp.size]; return c && (v < c.min || v > (inp.size === 'toy' ? c.max : c.bits - 2)) ? 'q − p about 2^: from ' + c.min + ' to ' + (inp.size === 'toy' ? c.max : c.bits - 2) + ' for this key' : null; } },
    ],
    presets: [
      { label: 'RSA-1024, primes 2^259 apart', values: { size: 'rsa1024', gap: 259 } },
      { label: 'Toy, 512 apart', values: { size: 'toy', gap: 9 } },
      { label: 'Toy, 4096 apart: more steps', values: { size: 'toy', gap: 12 } },
      { label: 'RSA-2048, primes 2^517 apart', values: { size: 'rsa2048', gap: 517 } },
      { label: 'RSA-2048, 2^30 apart: one step', values: { size: 'rsa2048', gap: 30 } },
      { label: 'RSA-2048 at the safe distance', values: { size: 'rsa2048', gap: 924 } },
    ],
    counters: [{ id: 'tries', label: 'values of a tried' }],
    run(inp) {
      const o = fermatCase(inp.size, inp.gap), r = o.run, Kp = K();
      const F = new S.Frames(['tries']);
      const view = { x: -24, y: 0, w: 900, h: 500 };
      const x = { q: 150, root: 430, p: 710 }; // left: the smaller prime p, right: the larger q
      const line = (stage, aVal, lit) => {
        const items = [P.title('h', 0, 22, (inp.size === 'toy' ? 'toy key' : 'RSA-' + o.nlen) + ': n = p·q with q − p ≈ 2' + P.sup(inp.gap))];
        items.push({ key: 'axis', kind: 'line', x1: 30, y1: 112, x2: 830, y2: 112, cls: 'nt-axis', audit: 'ignore', layer: 'back' });
        items.push({ key: 'br', kind: 'bracket', x1: x.q, x2: x.p, y: 66, side: 'above', text: 'q − p = ' + P.n(o.gap).replace(/ \(.*\)/, '') + (o.gap > 10n ** 12n ? '  (' + P.bits(o.gap) + ' bits)' : ''), cls: 'hot' });
        const tick = (k, at, label, val, cls) => [
          { key: 'tk' + k, kind: 'line', x1: at, y1: 102, x2: at, y2: 122, cls: cls || 'act', audit: 'ignore' },
          Kp.value({ key: 'v' + k, x: at, y: 162, label: label + (P.bits(val) > 40 ? ', ' + P.bits(val) + ' bits' : ''), value: val, max: 16, count: false, cls: cls === 'good' || cls === 'bad' ? cls : '' }),
        ];
        const done = stage >= 3;
        items.push(...tick('q', x.q, done ? 'p (exposed)' : 'p (secret)', o.lo, done ? 'bad' : 'act'));
        items.push(...tick('p', x.p, done ? 'q (exposed)' : 'q (secret)', o.hi, done ? 'bad' : 'act'));
        items.push(...tick('r', x.root, '⌈√n⌉', o.root, 'key'));
        if (!done) for (const it of items) if (/^(v|tk)[qp]$/.test(it.key)) it.dim = true;
        if (aVal !== undefined) items.push({ key: 'acur', kind: 'head', x: P.r2(x.root + 14 + 36 * Math.min(1, lit)), y: 112, text: 'a', side: 'above', cls: stage >= 2 ? 'hot' : 'act' });
        return items;
      };
      const eq = (lines) => P.eqs('eq', 40, 290, lines, 17, 34);
      const add = (items, say, facts, phase) => F.add({ items, say, facts, meta: { phase } });

      add(line(0).concat(eq([['n = p·q, and only n is public', 'strong'], ['p < √n < q, both close to √n'], ['so n = a² − b² with b = (q − p)/2 small']])), `Someone made a key with two primes only about 2^${inp.gap} apart: n = ${P.n(o.n)}, ${P.an(o.nlen)}-bit modulus. Only n is public. Since q and p sit on either side of √n, n is nearly a square: a² − b² with b small.`,
        { gap: inp.gap, n: o.n, nlen: o.nlen }, 'start');
      const lb = P.bits(o.expect > 0n ? o.expect : 1n);
      if (!r) {
        add(line(1, o.root, 0).concat(eq([['steps ≈ (q − p)² / (8√n)', 'strong'], [`≈ 2^${lb} steps`, 'good'], ['a computer doing 2^40 steps a second would never finish', 'muted']])), `Fermat's method needs about (q − p)²/(8√n) steps, and with the primes this far apart that is ${P.an(lb)}-bit number of them, ${P.n(o.expect)}. At this distance the weakness does not apply.`,
          { lb, steps: o.expect }, 'far');
      } else {
        add(line(1, o.root, 0).concat(eq([['steps ≈ (q − p)² / (8√n)', 'strong'], [`here: about ${P.n(o.expect)}`, 'bad'], ['close primes: a handful of steps at any size', 'bad']])), `The precondition: the work Fermat's method needs is about (q − p)²/(8√n) steps, which depends on how close the primes are, not on the size of n. Here that is about ${P.n(o.expect)}.`,
          { expect: o.expect }, 'pre');
        F.set('tries', r.tries);
        add(line(3, undefined, 1).concat(eq([['outcome: n is factored', 'bad'], [`after ${P.plural(r.tries, 'step')}`, 'bad'], ['and with p and q, the private key follows', 'bad']])), `The outcome: from n alone, Fermat's method finds p and q after ${P.plural(r.tries, 'step')}, and the ${o.nlen}-bit key is broken without any real factoring. This recovers the private key.`,
          { tries: r.tries, nlen: o.nlen, ok: true }, 'found');
      }
      const safe = Math.floor(o.nlen / 2) - 100, stepsBits = 2 * safe - Math.floor(o.nlen / 2) - 3;
      add(line(r ? 3 : 1, r ? undefined : o.root, 0).concat(eq([['FIPS 186: |p − q| > 2^(nlen/2 − 100)', 'strong'], [`nlen = ${o.nlen}: |p − q| > 2^${safe}`, 'good'], [`then steps ≈ 2^${stepsBits}`, 'good']])), `The defence is in the key generation standard (FIPS 186): |p − q| must exceed 2^(nlen/2 − 100), here 2^${safe}. Then Fermat's method needs about 2^${stepsBits} steps, and random primes are that far apart anyway; only a broken generator, one that picks q just after p, makes them close.`,
        { safe, stepsBits, nlen: o.nlen }, 'defence');
      for (const f of F.list) f.narrowView = { x: -24, y: 30, w: 900, h: 440 };
      return { frames: P.fix(F.list, view), def: P.def('Close primes', ['n = a² − b² with a = (p + q)/2, b = (q − p)/2', 'work ≈ (q − p)² / (8√n) steps, whatever the size of n', 'p, q close ⇒ n is factored at once', 'defence, FIPS 186: |p − q| > 2^(nlen/2 − 100)']) };
    },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'start', pick: 'option', ask: 'How many values of a will Fermat\'s method try?', options: ['1 to 10', '11 to 1000', 'more than 1000'], answer: (fr) => { const t = fr.find((f) => f.meta.phase === 'found'); const k = t ? t.facts.tries : Infinity; return k <= 10 ? '1 to 10' : k <= 1000 ? '11 to 1000' : 'more than 1000'; }, explain: (fr) => (fr.find((f) => f.meta.phase === 'found') || fr.find((f) => f.meta.phase === 'far')).say },
    ],
    quiz: [
      { q: 'Why is n with close primes nearly a square?', options: ['p and q both sit just beside √n', 'n is even', 'e is small', 'It is not'], answer: 0, why: 'n = a² − b² with a = (p + q)/2 and b = (q − p)/2, and b is small when the primes are close.' },
      { q: 'Does a longer modulus help when p and q are close?', options: ['Yes', 'No: the work depends on q − p, not on the size of n', 'Only above 4096 bits', 'Only with e = 3'], answer: 1, why: 'The work is about (q − p)²/(8√n) steps, which stays tiny for close primes at any size.' },
      { q: 'For which keys does it finish in one step?', options: ['When p and q are very close', 'When e is small', 'When n is small', 'Never'], answer: 0, why: 'The number of steps is about (q − p)²/(8√n): when that is below 1, the first a works.' },
      { q: 'What does FIPS 186 require of RSA primes for this reason?', options: ['p = q', '|p − q| > 2^(nlen/2 − 100)', 'p < 2^100', 'q = p + 2'], answer: 1, why: 'Primes that far apart make Fermat\'s method take an astronomical number of steps.' },
      { q: 'Random 1024-bit primes p and q are typically how far apart?', options: ['about 2', 'about 2^30', 'about 2^1020 or more', 'exactly 2^512'], answer: 2, why: 'Two independent random numbers of that size differ in their top bits almost always.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Shared primes found by batch GCD
  // ---------------------------------------------------------------------------------------------------------------
  const SUBS = ['₁', '₂', '₃', '₄', '₅', '₆', '₇', '₈'];
  /** sixteen distinct primes of the size: toy primes from 101 to 997, or the 512-bit pool and ten more made once */
  const gcdPrimes = (size) => P.memo('p08-batch-primes', { size }, () => {
    if (size === 'toy') { const out = []; for (let p = 101n; out.length < 40; p = NT().nextPrime(p)) if (NT().isProbablePrime(p)) out.push(p); return out; }
    const out = []; for (let i = 0; i < 6; i++) out.push(P.prime(512, i));
    S.RSA.seeded(512, () => { while (out.length < 16) { const p = NT().randomPrime(512).prime; if (!out.includes(p)) out.push(p); } });
    return out;
  });
  const gcdCase = (size, pairs, seed) => P.memo('p08-batch', { size, pairs, seed }, () => {
    const pool = gcdPrimes(size).slice();
    // the seed picks which primes go where (a small generator of our own, so the story can be replayed)
    let st = (seed * 2654435761) >>> 0;
    const rnd = (k) => { st = (st * 1103515245 + 12345) >>> 0; return (st >>> 8) % k; };
    for (let i = pool.length - 1; i > 0; i--) { const j = rnd(i + 1); [pool[i], pool[j]] = [pool[j], pool[i]]; }
    const keys = [];
    let next = 0;
    for (let w = 0; w < pairs; w++) { const s0 = pool[next++]; keys.push([s0, pool[next++]], [s0, pool[next++]]); }
    while (keys.length < 8) keys.push([pool[next++], pool[next++]]);
    const order = [...keys.keys()];
    for (let i = 7; i > 0; i--) { const j = rnd(i + 1); [order[i], order[j]] = [order[j], order[i]]; }
    const ks = order.map((k) => keys[k]), ns = ks.map(([a, b]) => a * b);
    const r = S.RSA.attack.sharedPrimes(ns);
    // the remainder tree, level by level: P mod (node)²
    const rem = [[r.tree[r.tree.length - 1][0]]];
    for (let lvl = r.tree.length - 2; lvl >= 0; lvl--) rem.unshift(r.tree[lvl].map((v, i) => rem[0][i >> 1] % (v * v)));
    return { ns, ks, r, rem, tree: r.tree };
  });
  S.topic({
    id: 'p08-batch-gcd', family: 'p08-attacks', order: 60, title: 'Shared primes found by batch GCD',
    blurb: 'Two keys made by a generator that repeated a prime share a factor, and a greatest common divisor exposes it at once, whatever the size of the keys. With millions of keys, one sweep over a product tree tests every key against all the others. The defence is good randomness when keys are made.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Keys', def: 'toy', options: [{ value: 'toy', label: 'toy (primes 101 to 997)' }, { value: 'rsa1024', label: 'RSA-1024' }] },
      { id: 'pairs', kind: 'number', label: 'Pairs sharing a prime', def: 1, min: 0, max: 3 },
      { id: 'seed', kind: 'number', label: 'Seed', def: 7, min: 1, max: 9999 },
    ],
    presets: [
      { label: 'Toy: one shared prime', values: { size: 'toy', pairs: 1, seed: 7 } },
      { label: 'Toy: three shared primes', values: { size: 'toy', pairs: 3, seed: 21 } },
      { label: 'Toy: all primes different', values: { size: 'toy', pairs: 0, seed: 5 } },
      { label: 'RSA-1024: two shared primes', values: { size: 'rsa1024', pairs: 2, seed: 11 } },
    ],
    counters: [{ id: 'mults', label: 'multiplications' }, { id: 'broken', label: 'keys exposed' }],
    run(inp) {
      const o = gcdCase(inp.size, inp.pairs, inp.seed), Kp = K(), T = o.tree, R = o.rem;
      const F = new S.Frames(['mults', 'broken']);
      const view = { x: -10, y: 0, w: 880, h: 540 };
      const ys = [380, 285, 190, 95], W = [100, 190, 380, 560], X0 = 20, pitch = 105;
      const cx = (lvl, i) => X0 + (pitch * (2 ** lvl)) * i + (pitch * (2 ** lvl) - 5) / 2;
      const short = (v, m) => Kp.fmt(v, { max: m }).text;
      const names = ['n', 'n·n', 'n·n·n·n', 'P'];
      const nodeName = (lvl, i) => (lvl === 0 ? 'n' + SUBS[i] : lvl === 3 ? 'P' : 'n' + SUBS[i * 2 ** lvl] + '…n' + SUBS[(i + 1) * 2 ** lvl - 1]);
      const broken = o.r.factors.map((f) => !!f);
      const node = (lvl, i, mode, upto) => {
        const w = lvl === 0 ? 98 : Math.min(W[lvl], pitch * 2 ** lvl - 14), v = mode === 'rem' ? R[lvl][i] : T[lvl][i];
        const maxc = lvl === 0 ? 11 : lvl === 1 ? 18 : 22;
        const label = mode === 'rem' ? (lvl === 3 ? 'P' : lvl === 0 ? 'P mod ' + nodeName(lvl, i) + '²' : 'P mod (' + nodeName(lvl, i) + ')²') : nodeName(lvl, i);
        const it = { key: 'nd' + lvl + '-' + i, kind: 'cell', x: P.r2(cx(lvl, i) - w / 2), y: ys[lvl], w, h: 54, rx: 6, lines: [label, short(v, maxc)], size: 13, cls: 'mono pk-node ' + (mode === 'rem' ? 'act' : '') };
        const f = Kp.fmt(v, { max: maxc });
        if (f.long) { it.cls += ' pk-long'; it.title = label + ' = ' + f.full + ' (' + f.digits + ' digits, ' + f.bits + ' bits)'; }
        return it;
      };
      /** the tree: levels 0..upTo built; rem levels from remFrom down drawn as remainders */
      const tree = (upTo, remFrom, leafCls) => {
        const items = [P.title('h', 0, 24, (inp.size === 'toy' ? 'Eight toy keys' : 'Eight RSA-1024 keys') + ': the product tree' + (remFrom !== undefined ? ', then the remainder tree' : ''))];
        for (let lvl = 0; lvl <= upTo; lvl++) for (let i = 0; i < T[lvl].length; i++) {
          const it = node(lvl, i, remFrom !== undefined && lvl >= remFrom ? 'rem' : 'prod');
          if (lvl === 0 && leafCls) it.cls += ' ' + (leafCls(i) || '');
          items.push(it);
          if (lvl > 0) for (const c of [2 * i, 2 * i + 1]) if (c < T[lvl - 1].length) items.push({ key: 'ed' + lvl + '-' + c, kind: 'edge', from: 'nd' + (lvl - 1) + '-' + c, to: 'nd' + lvl + '-' + i, head: false, cls: remFrom !== undefined && lvl - 1 >= remFrom ? 'act' : 'faint' });
        }
        return items;
      };
      const add = (items, say, facts, phase) => F.add({ items, say, facts, meta: { phase } });
      const bits = (v) => P.bits(v);

      add(tree(0), `Eight public keys, collected from devices on a network. Each n = p·q looks fine on its own. But the devices made their keys with a weak random generator, and ${inp.pairs ? 'some primes came out twice' : 'we will check whether any prime came out twice'}. For two keys, gcd(n₁, n₂) would expose a shared prime at once; with millions of keys, trying every pair is too slow.`,
        { pairs: inp.pairs, ns: o.ns.slice(), pairsAll: 28 }, 'start');
      for (let lvl = 1; lvl <= 3; lvl++) {
        F.count('mults', T[lvl].length);
        add(tree(lvl), lvl === 3 ? `The root: P = n₁·n₂·…·n₈, the product of every key, ${P.an(bits(T[3][0]))}-bit number. In all ${F.counts.mults} multiplications, where trying every pair would need 28 gcds; for a million keys the tree needs about 2·10⁶ steps, not 5·10¹¹.` : `Multiply the keys in pairs, level by level: ${T[lvl].length} products of ${P.an(bits(T[lvl][0]))}-bit size or so.`,
          { level: lvl, count: T[lvl].length, bits: bits(T[lvl][0]), mults: F.counts.mults }, lvl === 3 ? 'root' : 'product');
      }
      F.set('broken', broken.filter(Boolean).length);
      const leaf = (i) => (broken[i] ? 'bad' : 'good');
      const nb = broken.filter(Boolean).length;
      const outItems = tree(0, undefined, leaf);
      o.ns.forEach((n, i) => { outItems.push(P.t('gl' + i, cx(0, i), ys[0] + 74, broken[i] ? 'shares a prime' : 'no shared prime', broken[i] ? 'bad' : 'good', 'middle', 13)); });
      outItems.push(...P.eqs('oc', 30, 160, nb ? [['outcome: every key that shares a prime is factored', 'bad'], ['and its private key follows', 'bad']] : [['outcome: no prime appears twice', 'good'], ['the sweep learns nothing, as it should', 'good']], 17, 34));
      add(outItems, nb ? `The outcome: one more sweep back down the tree gives each key's greatest common divisor with the product of all the others. For ${P.plural(nb, 'key')} it is not 1: ${P.list(broken.map((b, i) => (b ? 'n' + (i + 1) : null)).filter(Boolean))} share a prime with another key, so each of them is factored and its private key exposed. Scans of real keys found exactly this, in devices that made keys at boot before they had gathered any randomness.` : 'The outcome: one more sweep back down the tree gives each key\'s greatest common divisor with the product of all the others, and every one is 1. No prime appears in two keys, so the sweep learns nothing, as it should for well-made keys.',
        { nb, idx: broken.map((b, i) => (b ? i + 1 : null)).filter(Boolean), ok: o.r.factors.every((f, i) => !f || o.ks[i].includes(f.p)) }, 'gcd');
      add(tree(0, undefined, nb ? leaf : null).concat(P.eqs('df', 30, 160, [['the defence: real randomness when keys are made', 'good'], ['seed the generator before the first key', 'strong'], ['never let two devices start from the same state', 'strong']], 17, 34)), `The defence is not in RSA at all but in key generation: draw primes from a well-seeded random generator, so that the chance of two keys ever sharing a prime is negligible. With 512-bit primes there are about 2^503 of them to choose from.`,
        { nb }, 'defence');
      return { frames: P.fix(F.list, view), def: P.def('Shared primes', ['gcd(n₁, n₂) > 1: a shared prime, both keys factored', 'batch GCD: one sweep tests each key against all others', 'about k·log k multiplications, not k² gcds', 'defence: a well-seeded generator before the first key']) };
    },
    predict: [
      { at: (f) => f.meta.phase === 'start', pick: 'option', ask: 'How many of the eight keys will turn out to share a prime with another?', options: ['0', '2', '4', '6', '8'], answer: (fr) => String(fr.find((f) => f.meta.phase === 'gcd').facts.nb), explain: (fr) => fr.find((f) => f.meta.phase === 'gcd').say },
    ],
    quiz: [
      { q: 'Two RSA moduli share the prime p. What follows?', options: ['Nothing, each is still hard to factor', 'Anyone can compute gcd(n₁, n₂) = p, and both keys are factored', 'Only the first key is weak', 'It cannot be noticed'], answer: 1, why: 'Euclid\'s algorithm finds the common factor in a fraction of a second, whatever the size.' },
      { q: 'Does a longer modulus protect two keys that share a prime?', options: ['Yes', 'No: the gcd exposes the prime at any size', 'Only above 4096 bits', 'Only with e = 65537'], answer: 1, why: 'Euclid\'s algorithm is fast on numbers of any practical size.' },
      { q: 'Why not just compute gcd(n_i, n_j) for every pair?', options: ['It gives wrong answers', 'With a million keys that is 5·10¹¹ gcds', 'gcd needs the private key', 'It only works for two keys'], answer: 1, why: 'Pairs grow with the square of the number of keys; the trees grow about linearly (times a logarithm).' },
      { q: 'What caused shared primes in real keys?', options: ['Small e', 'Poor randomness at key generation', 'Padding', 'Short moduli'], answer: 1, why: 'Devices made keys before their random generators had any entropy, so many drew the same first prime.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // One fault in CRT signing
  // ---------------------------------------------------------------------------------------------------------------
  const faultKey = (size) => (size === 'toy' ? P.memo('p08-crt-fault-key', {}, () => S.RSA.fromPrimes(1031n, 1019n, 17n)) : P.rsaKey(size));
  const faultMsg = (size, text) => (size === 'toy' ? BigInt(text) : NT().fromBytes(new TextEncoder().encode(text)));
  S.topic({
    id: 'p08-crt-fault', family: 'p08-attacks', order: 70, title: 'One fault in CRT signing',
    blurb: 'A signer that uses the CRT computes the signature modulo p and modulo q separately. If a glitch spoils just one half, the faulty signature is still right modulo the other prime, and that mismatch alone lets anyone holding the signature and the message factor n: one bad signature costs the key. The defence is to check s^e = m before letting s out.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Key', def: 'rsa1024', options: [{ value: 'toy', label: 'toy (n = 1031·1019)' }, { value: 'rsa1024', label: 'RSA-1024' }, { value: 'rsa2048', label: 'RSA-2048' }] },
      { id: 'msg', kind: 'text', label: 'Message (a number below n for the toy key)', def: 'pay the gardener 40 coins', check: (v, inp) => { if (inp.size === 'toy') return /^\d+$/.test(String(v).trim()) && BigInt(v) > 1n && BigInt(v) < 1031n * 1019n ? null : 'Message: a whole number from 2 to 1050588 for the toy key'; return String(v).length >= 1 && new TextEncoder().encode(v).length <= (inp.size === 'rsa1024' ? 120 : 250) ? null : 'Message: 1 to ' + (inp.size === 'rsa1024' ? 120 : 250) + ' bytes'; } },
      { id: 'half', kind: 'choice', label: 'The glitch hits', def: 'p', options: [{ value: 'p', label: 'the half modulo p' }, { value: 'q', label: 'the half modulo q' }] },
      { id: 'bit', kind: 'number', label: 'Bit flipped', def: 5, min: 0, max: 500, check: (v, inp) => (v > (inp.size === 'toy' ? 8 : 500) ? 'Bit flipped: at most ' + (inp.size === 'toy' ? 8 : 500) + ' for this key' : null) },
    ],
    presets: [
      { label: 'RSA-1024, a glitch modulo p', values: { size: 'rsa1024', msg: 'pay the gardener 40 coins', half: 'p', bit: 5 } },
      { label: 'Toy key, glitch modulo q', values: { size: 'toy', msg: '123456', half: 'q', bit: 2 } },
      { label: 'Toy key, glitch modulo p', values: { size: 'toy', msg: '777777', half: 'p', bit: 0 } },
      { label: 'RSA-2048, a high bit', values: { size: 'rsa2048', msg: 'open the east door at dawn', half: 'q', bit: 400 } },
    ],
    counters: [{ id: 'sigs', label: 'signatures seen' }],
    run(inp) {
      const key = faultKey(inp.size), m = faultMsg(inp.size, inp.msg) % key.n, Kp = K();
      const good = S.RSA.decryptCRT(m, key), bad = S.RSA.decryptCRT(m, key, { fault: inp.half, bit: inp.bit });
      const att = S.RSA.attack.crtFault({ n: key.n, e: key.e, m, s: bad.value });
      const v = NT().pow(bad.value, key.e, key.n), vGood = NT().pow(good.value, key.e, key.n);
      const F = new S.Frames(['sigs']);
      const view = { x: -10, y: 0, w: 900, h: 520 };
      const other = inp.half === 'p' ? 'q' : 'p';
      const found = att.p, foundName = found === key.p ? 'p' : 'q';
      const pic = (stage) => {
        const glitch = stage >= 2, sv = glitch ? bad : good;
        const items = [P.title('h', 0, 22, (inp.size === 'toy' ? 'toy key' : 'RSA-' + key.bits) + ': signing with the CRT' + (glitch ? ', and a glitch' : ''))];
        items.push(Kp.value({ key: 'm', x: 100, y: 230, label: 'm', value: m, max: 14, count: false, cls: 'act' }));
        const sp = Kp.value({ key: 'sp', x: 340, y: 130, label: 's_p = m^dp mod p', value: sv.mp, max: 14, count: false, cls: glitch && inp.half === 'p' ? 'bad' : stage >= 1 ? 'good' : '' });
        const sq = Kp.value({ key: 'sq', x: 340, y: 330, label: 's_q = m^dq mod q', value: sv.mq, max: 14, count: false, cls: glitch && inp.half === 'q' ? 'bad' : stage >= 1 ? 'good' : '' });
        items.push(sp, sq);
        const gar = { key: 'gar', kind: 'state', x: 575, y: 230, w: 150, h: 58, rx: 7, lines: ['Garner', 'combine'], cls: 'block val2' };
        items.push(gar);
        const mR = 100 + items[1].w / 2, xs = 210;
        items.push({ key: 'w1', kind: 'wire', pts: [[mR, 230], [xs, 230], [xs, 130], [340 - sp.w / 2, 130]], head: true }, { key: 'w2', kind: 'wire', pts: [[xs, 230], [xs, 330], [340 - sq.w / 2, 330]], head: true });
        items.push({ key: 'dot', kind: 'dot', x: xs, y: 230, r: 3.6, audit: 'ignore' });
        items.push({ key: 'w3', kind: 'wire', pts: [[340 + sp.w / 2, 130], [575, 130], [575, 201]], head: true, cls: glitch && inp.half === 'p' ? 'hot' : '' }, { key: 'w4', kind: 'wire', pts: [[340 + sq.w / 2, 330], [575, 330], [575, 259]], head: true, cls: glitch && inp.half === 'q' ? 'hot' : '' });
        if (stage >= 1) {
          const so = Kp.value({ key: 's', x: 790, y: 230, label: glitch ? 's′ (faulty)' : 's', value: sv.value, max: 12, count: false, cls: glitch ? 'bad' : 'good' });
          items.push({ key: 'w5', kind: 'wire', pts: [[650, 230], [790 - so.w / 2, 230]], head: true }, so);
        }
        if (glitch) items.push(P.t('zap', 340, inp.half === 'p' ? 82 : 382, '⚡ bit ' + inp.bit + ' of s_' + inp.half + ' flipped', 'bad', 'middle', 14));
        return items;
      };
      const eq = (lines) => P.eqs('eq', 30, 430, lines, 16, 30);
      const add = (items, say, facts, phase) => F.add({ items, say, facts, meta: { phase } });
      const s$ = P.n;
      add(pic(0), `The signer holds n = ${s$(key.n)} and signs m = ${s$(m)} with d. To save time it works modulo each prime with the short exponents dp = ${s$(key.dp)} and dq = ${s$(key.dq)}, and joins the halves at the end.`,
        { n: key.n, m, dp: key.dp, dq: key.dq }, 'start');
      F.set('sigs', 1);
      add(pic(1).concat(eq([['s^e mod n = m', 'good']])), `Done right: s_p = ${s$(good.mp)}, s_q = ${s$(good.mq)}, and Garner's formula gives s = ${s$(good.value)}. Anyone can check it: s^e mod n = ${s$(vGood)} = m.`,
        { sp: good.mp, sq: good.mq, s: good.value, v: vGood }, 'good');
      add(pic(2), `Now a glitch (a voltage spike, a stray particle) flips bit ${inp.bit} of the half modulo ${inp.half}: s_${inp.half} becomes ${s$(inp.half === 'p' ? bad.mp : bad.mq)} instead of ${s$(inp.half === 'p' ? good.mp : good.mq)}. The half modulo ${other} is untouched.`,
        { bit: inp.bit, wrong: inp.half === 'p' ? bad.mp : bad.mq, right: inp.half === 'p' ? good.mp : good.mq }, 'glitch');
      F.set('sigs', 2);
      add(pic(2), `Garner joins the halves anyway, and the device sends out s′ = ${s$(bad.value)}. It is wrong modulo ${inp.half} but still right modulo ${other}: s′ ≡ s (mod ${other}).`,
        { s: bad.value }, 'release');
      add(pic(2).concat(eq([['s′ right modulo one prime, wrong modulo the other', 'bad'], ['outcome: s′ and m alone factor n', 'bad']])), `The outcome: anyone can see that s′^e mod n = ${s$(v)} is not m. And a signature that is right modulo one prime and wrong modulo the other, together with its message, is enough to factor n with one short computation. From the factors the private key follows: a single faulty signature has cost the key.`,
        { v, m, ok: (found === key.p || found === key.q) && found * att.q === key.n }, 'gcd');
      const cost = S.RSA.powLR(2n, key.e, key.n);
      add(pic(2).concat(eq([['before releasing s: is s^e mod n = m?', 'good'], [`with e = ${key.e}: ${cost.squarings + cost.multiplications} multiplications`, 'strong'], ['if not: release nothing, raise an alarm', 'strong']])), `The defence: verify every signature before it leaves the device. With e = ${key.e} the check costs ${cost.squarings + cost.multiplications} multiplications, nothing next to the signing itself. Padding with randomness (PSS) also helps, since the attacker then does not know the exact m that was signed.`,
        { e: key.e, ops: cost.squarings + cost.multiplications }, 'defence');
      for (const f of F.list) f.narrowView = { x: -10, y: 40, w: 900, h: 480 };
      return { frames: P.fix(F.list, view), def: P.def('A fault in CRT signing', ['s_p = m^dp mod p, s_q = m^dq mod q, joined by Garner', 'a fault in s_p: s′ ≡ s (mod q) only', 'one such s′ with its m factors n', 'defence: check s^e ≡ m before release; or PSS']) };
    },
    predict: [
      { at: (f) => f.meta.phase === 'release', pick: 'option', ask: 'The faulty s′ leaves the device. What does it cost the signer?', options: ['nothing: it is just a wrong signature', 'the factors of n, and so the key', 'only this one message', 'the next signature'], answer: 'the factors of n, and so the key', explain: (fr) => fr.find((f) => f.meta.phase === 'gcd').say },
    ],
    quiz: [
      { q: 'A fault spoils only the half modulo p. The faulty s′ is still correct modulo…', options: ['p', 'q', 'n', 'nothing'], answer: 1, why: 'The half modulo q was computed correctly, and Garner\'s formula keeps it: s′ ≡ s (mod q).' },
      { q: 'How many faulty signatures does it take to lose the key?', options: ['One', 'About a hundred', 'One per bit of d', 'Thousands'], answer: 0, why: 'A single faulty signature with its message is enough to factor n.' },
      { q: 'Which defence stops it?', options: ['A larger e', 'Checking s^e = m before releasing s', 'Using a 4096-bit key', 'Signing twice as fast'], answer: 1, why: 'A faulty signature is caught and never leaves the device.' },
      { q: 'Why does signing without the CRT resist this exact fault?', options: ['It is never faulty', 'A fault there spoils the result modulo both primes', 'It uses padding', 'It uses e instead of d'], answer: 1, why: 'Without two independent halves, a fault leaves nothing correct modulo just one prime.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
