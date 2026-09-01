// Part 9, Diffie–Hellman and Elgamal: the exchange as mixing paint (colours mix easily and do not unmix), then the
// same exchange as numbers, toy and in the 2048-bit MODP group; the attacker who sits in the middle of an exchange
// nobody authenticated; and Elgamal encryption with its fresh mask for every message.
(function (S) {
  'use strict';
  const P = S.PK, NT = () => S.NT, KP = () => S.Kit.pk;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const isP = (v) => { try { return NT().isProbablePrime(B(v)); } catch (e) { return false; } };
  const seeded = (seed, fn) => { const old = NT().setRandom(NT().seededRandom(seed)); try { return fn(); } finally { NT().setRandom(old); } };
  const H = (S.P09 = S.P09 || {});

  // ---- the group of a topic: a toy Z_p* (g given or the smallest generator) or the 2048-bit MODP group -------------
  H.group = (inp) => {
    if (inp.size === 'real') return P.modp14();
    const p = B(inp.p);
    return P.memo('p09-group', [String(p), inp.g], () => S.DLP.groupZp(p, inp.g ? { gen: B(inp.g) } : {}));
  };
  /** secrets: the toy inputs, or random exponents below the group order drawn from the seed */
  H.secrets = (inp, G, names) => {
    if (inp.size !== 'real') return names.map((k) => B(inp[k]));
    return seeded(inp.seed, () => names.map(() => 2n + NT().randBelow(G.order - 3n)));
  };
  H.toyInputs = (more) => [
    { id: 'size', kind: 'choice', label: 'Size', def: 'toy', options: [{ value: 'toy', label: 'toy: a small prime p' }, { value: 'real', label: 'real: the 2048-bit MODP group' }] },
    { id: 'p', kind: 'number', label: 'Prime p', def: 23, min: 5, max: 1000000007, check: (v) => (isP(v) ? null : 'p: a prime') },
    { id: 'g', kind: 'number', label: 'Generator g (0: the smallest)', def: 0, min: 0, max: 1000000006, check: (v, inp) => (v === 0 ? null : v < 2 || v >= inp.p ? 'g: 0, or from 2 to p − 1' : !NT().isGenerator(B(v), B(inp.p)).ok ? 'g: a generator of Z_p* (or 0 to pick one)' : null) },
  ].concat(more, [{ id: 'seed', kind: 'number', label: 'Seed (real size)', def: 7, min: 1, max: 99999 }]);
  /** an exponent input that must lie from 2 to p − 2 */
  H.exp = (id, label, def) => ({ id, kind: 'number', label, def, min: 2, max: 1000000005, check: (v, inp) => (v > inp.p - 2 ? label + ': from 2 to p − 2' : null) });
  /** a value block centred at x */
  H.V = (key, x, y, label, v, cls, max) => KP().value({ key, x, y, label, value: v, cls, max: max || 18 });
  /** the short form a label uses */
  H.s = (v) => KP().fmt(B(v), { max: 14 }).text;
  H.n = P.n;

  // ---------------------------------------------------------------------------------------------------------------
  // Diffie–Hellman as mixing paint
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p09-dh-paint', family: 'p09-protocols', order: 10, title: 'Diffie–Hellman as mixing paint',
    blurb: 'Two people agree a colour in public, each stirs in a secret colour, and they swap the mixtures. Each adds their own secret to what arrives, and both end with the same colour. Paint is easy to mix and impossible to unmix, so the listener who saw every pot cannot make it. Then the paint turns back into the numbers it stands for.',
    inputs: H.toyInputs([H.exp('a', 'Alice\'s secret a', 6), H.exp('b', 'Bob\'s secret b', 15)]),
    presets: [
      { label: 'p = 23, a = 6, b = 15', values: { size: 'toy', p: 23, g: 0, a: 6, b: 15 } },
      { label: 'p = 101 with g = 2', values: { size: 'toy', p: 101, g: 2, a: 37, b: 84 } },
      { label: 'A larger prime', values: { size: 'toy', p: 1000003, g: 0, a: 271901, b: 655360 } },
      { label: 'Real: the 2048-bit group', values: { size: 'real', seed: 7 } },
    ],
    counters: [{ id: 'sent', label: 'pots sent in public' }],
    run(inp) { return P.memo('p09-dh-paint', inp, () => paint(inp)); },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'arrive', pick: 'option', ask: 'Each now stirs their own secret into the mixture that arrived. Will the two final colours…', options: ['match', 'differ', 'depend on who goes first'], answer: 'match', explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'numbers', pick: 'option', ask: 'In the numbers, stirring a secret colour into a pot is…', options: ['adding the secret', 'raising to the power of the secret', 'multiplying by the secret'], answer: 'raising to the power of the secret', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What does the public paint stand for?', options: ['the shared secret', 'the generator g (with p)', 'Alice\'s secret', 'the ciphertext'], answer: 1, why: 'Everyone agrees g and p in public, like the common pot.' },
      { q: 'Why can the listener not make the shared colour from the two mixtures?', options: ['She never saw them', 'Unmixing a pot to get a secret colour back is the hard step, like the discrete logarithm', 'Paint is encrypted', 'She can, by mixing them'], answer: 1, why: 'Getting a from g^a is the discrete logarithm; mixing g^a with g^b gives g^(a+b), not g^(ab).' },
      { q: 'Alice\'s mixture is the number…', options: ['g + a', 'g^a mod p', 'a·b', 'g^(ab)'], answer: 1, why: 'Stirring in a secret is raising to it: A = g^a mod p.' },
      { q: 'What does Diffie–Hellman not give by itself?', options: ['a shared secret', 'confidentiality from a listener', 'knowing who is on the other end', 'agreement on the same key'], answer: 2, why: 'Nothing in the exchange proves who sent a mixture: an attacker in the middle can swap them.' },
    ],
  });

  function paint(inp) {
    const G = H.group(inp), real = inp.size === 'real', p = G.p, g = G.generator;
    const [a, b] = H.secrets(inp, G, ['a', 'b']);
    const dh = S.DLP.dh(G, a, b), A = dh.A, Bv = dh.B, K = dh.shared, eve = G.op(A, Bv);
    const F = new S.Frames(['sent']);
    const view = { x: -20, y: 0, w: 900, h: 540 };
    const ia = Number(a % 6n), ib0 = Number(b % 6n), ib = ib0 === ia ? (ib0 + 1) % 6 : ib0, ha = 'ha' + ia, hb = 'hb' + ib;
    const pot = (key, x, y, role, text, more) => ({ key, kind: 'state', x, y, r: 30, text: text || '', cls: 'pot ' + ha + ' ' + hb + ' ' + role + ' ' + (more || '') });
    const lab = (key, x, y, t, cls) => P.t(key, x, y, t, cls || 'strong', 'middle', 14);
    const people = [...KP().party({ key: 'al', x: 90, y: 50, name: 'Alice', cls: 'alice' }), ...KP().party({ key: 'bo', x: 790, y: 50, name: 'Bob', cls: 'bob' }), ...KP().party({ key: 'ev', x: 440, y: 400, name: 'Eve, listening', cls: 'eve' })];
    const pub = [pot('pc', 440, 70, 'pc', 'g'), lab('pc:l', 440, 125, 'the public paint')];
    const sec = [pot('pa', 90, 210, 'pa secret', 'a'), P.t('pa:l', 104, 265, 'secret', 'key', 'start', 14), pot('pb', 790, 210, 'pb secret', 'b'), P.t('pb:l', 776, 265, 'secret', 'key', 'end', 14)];
    const mixes = [pot('ma', 250, 210, 'pca', 'A'), lab('ma:l', 250, 265, 'g + a'), pot('mb', 630, 210, 'pcb', 'B'), lab('mb:l', 630, 265, 'g + b'),
      { key: 'e1', kind: 'edge', from: 'pc', to: 'ma', cls: 'faint' }, { key: 'e2', kind: 'edge', from: 'pa', to: 'ma', cls: 'key' }, { key: 'e3', kind: 'edge', from: 'pc', to: 'mb', cls: 'faint' }, { key: 'e4', kind: 'edge', from: 'pb', to: 'mb', cls: 'key' }];
    const eveSaw = [pot('vc', 330, 480, 'pc', 'g'), pot('va', 410, 480, 'pca', 'A'), pot('vb', 490, 480, 'pcb', 'B')];
    const add = (items, say, facts, meta) => F.add({ items, say, facts, meta });
    add([...people, ...pub], 'Alice and Bob want a shared secret colour, but every pot they send passes Eve. First they agree a common paint in public: Eve sees it too.', {}, { phase: 'start' });
    add([...people, ...pub, ...sec], 'Each picks a secret colour and keeps it at home: Alice the one marked a, Bob the one marked b. Eve never sees these.', {}, { phase: 'secrets' });
    add([...people, ...pub, ...sec, ...mixes], 'Each stirs their secret into a pot of the public paint: Alice makes mixture A, Bob makes mixture B. Mixing is easy; nobody knows how to unmix a pot back into its colours.', {}, { phase: 'mix' });
    F.set('sent', 2);
    const transit = [pot('ta', 380, 300, 'pca', 'A'), pot('tb', 500, 300, 'pcb', 'B'), { key: 't1', kind: 'edge', from: 'ma', to: 'ta', cls: 'act' }, { key: 't2', kind: 'edge', from: 'mb', to: 'tb', cls: 'act' }];
    add([...people, ...pub, ...sec, ...mixes, ...transit, ...eveSaw], 'They swap the mixtures in public. Eve copies both pots on the way: she now has the common paint, A and B.', {}, { phase: 'send' });
    const arrived = [pot('ra', 630, 340, 'pca', 'A'), pot('rb', 250, 340, 'pcb', 'B'), lab('ra:l', 630, 395, 'from Alice'), lab('rb:l', 250, 395, 'from Bob')];
    add([...people, ...pub, ...sec, ...mixes, ...arrived, ...eveSaw], 'Alice now holds Bob\'s mixture B, and Bob holds Alice\'s mixture A.', {}, { phase: 'arrive' });
    const fin = [pot('ka', 140, 470, 'pcab shared', 'K'), lab('ka:l', 140, 525, 'B + a', 'good'), pot('kb', 740, 470, 'pcab shared', 'K'), lab('kb:l', 740, 525, 'A + b', 'good'),
      { key: 'f1', kind: 'edge', from: 'rb', to: 'ka', cls: 'faint' }, { key: 'f2', kind: 'edge', from: 'pa', to: 'ka', cls: 'key', bend: -40 }, { key: 'f3', kind: 'edge', from: 'ra', to: 'kb', cls: 'faint' }, { key: 'f4', kind: 'edge', from: 'pb', to: 'kb', cls: 'key', bend: 40 }];
    const allPaint = [...people, ...pub, ...sec, ...mixes, ...arrived, ...fin];
    add([...allPaint, ...eveSaw], 'Each stirs their own secret into the pot that arrived. Alice gets common + b + a, Bob gets common + a + b: the same three colours, so the same final colour K, though no secret colour ever left home.', {}, { phase: 'shared' });
    const evePot = [pot('ve', 440, 575, 'peve wrong', '?'), { key: 'v1', kind: 'edge', from: 'va', to: 've', cls: 'bad' }, { key: 'v2', kind: 'edge', from: 'vb', to: 've', cls: 'bad' }];
    add([...allPaint, ...eveSaw, ...evePot], 'Eve has the common paint, A and B, but not a or b. Mixing A with B gives common + common + a + b: too much of the common paint, a different colour. To make K she would have to unmix A or B.', {}, { phase: 'eve' });
    // the numbers behind the paint
    const v = (k, x, y, t) => P.t(k, x, y, t, 'mono', 'middle', 14);
    const nums = [v('n:c', 440, 22, `g = ${H.s(g)}, p = ${H.s(p)}`)].concat(real ? [P.t('pa:l', 104, 265, 'secret', 'key', 'start', 14), P.t('pb:l', 776, 265, 'secret', 'key', 'end', 14)] : [P.t('n:a', 104, 265, `a = ${H.s(a)}`, 'mono', 'start', 14), P.t('n:b', 776, 265, `b = ${H.s(b)}`, 'mono', 'end', 14)], [v('n:A', 250, 265, `A = ${H.s(A)}`), v('n:B', 630, 265, `B = ${H.s(Bv)}`)]);
    const keyNums = [P.t('n:ka', 140, 549, `K = ${H.s(K)}`, 'mono good', 'middle', 14), P.t('n:kb', 740, 549, `K = ${H.s(K)}`, 'mono good', 'middle', 14)];
    const itemsN = allPaint.filter((it) => !/:l$/.test(it.key)).concat(nums, keyNums, eveSaw, evePot, [P.t('n:e', 490, 580, `A·B = ${H.s(eve)}`, 'mono bad', 'start', 14)]);
    for (const it of itemsN) if (/^(pc|pa|pb|ma|mb|ka|kb|ve)$/.test(it.key)) { const val = { pc: g, pa: a, pb: b, ma: A, mb: Bv, ka: K, kb: K, ve: eve }[it.key]; it.title = KP().fmt(val).full; if (KP().fmt(val).long) it.cls += ' pk-long'; }
    add(itemsN, `Now the numbers. The paint is g = ${H.n(g)} modulo p = ${H.n(p)}; stirring in a secret is raising to it. A = g^a mod p = ${H.n(A)} and B = g^b mod p = ${H.n(Bv)}. Alice computes B^a and Bob A^b, and both are g^(ab) = ${H.n(K)}.`, { g, p, a, b, A, B: Bv, K }, { phase: 'numbers' });
    add(itemsN, `Eve's mixture is A·B = g^(a+b) mod p = ${H.n(eve)}, not the key ${H.n(K)}. To get g^(ab) from g^a and g^b she needs a discrete logarithm${real ? ', and in a 2048-bit group nobody knows how to take one' : ', easy here but hopeless when p has hundreds of digits'}.`, { eve, K }, { phase: 'eve-numbers' });
    return { frames: P.fix(F.list, { x: -20, y: 0, w: 900, h: 625 }), def: P.def('Paint and numbers', ['public paint      g (and p)', 'stir in a secret  raise to it: g^a mod p', 'swap mixtures     send A = g^a, B = g^b', 'add own secret    B^a = A^b = g^(ab)', 'unmix a pot       the discrete logarithm']) };
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Diffie–Hellman with the numbers
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p09-dh', family: 'p09-protocols', order: 20, title: 'Diffie–Hellman with numbers',
    blurb: 'Alice and Bob agree a prime p and a generator g in public, raise g to secret exponents a and b, swap g^a and g^b, and each raises what arrives to their own secret. Both reach g^(ab) mod p; a listener holding p, g, g^a and g^b does not.',
    inputs: H.toyInputs([H.exp('a', 'Alice\'s secret a', 6), H.exp('b', 'Bob\'s secret b', 15)]),
    presets: [
      { label: 'p = 23, a = 6, b = 15', values: { size: 'toy', p: 23, g: 0, a: 6, b: 15 } },
      { label: 'p = 467', values: { size: 'toy', p: 467, g: 0, a: 153, b: 400 } },
      { label: 'A 30-bit prime', values: { size: 'toy', p: 1000000007, g: 0, a: 123456789, b: 987654321 } },
      { label: 'Real: the 2048-bit MODP group', values: { size: 'real', seed: 7 } },
      { label: 'Real, other secrets', values: { size: 'real', seed: 2026 } },
    ],
    counters: [{ id: 'mults', label: 'multiplications (each side)' }, { id: 'sent', label: 'numbers sent' }],
    run(inp) { return P.memo('p09-dh', inp, () => dhRun(inp)); },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'sent', pick: 'option', ask: 'Bob raises A to his secret b. What does he get?', options: (fr, i) => { const x = fr[i].facts; return [...new Set([H.s(x.K), H.s(x.AB), H.s(x.A)])]; }, answer: (fr, i) => H.s(fr[i].facts.K), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'With p = 11, g = 2, a = 3 and b = 4, what is the shared key?', options: ['2^7 mod 11 = 7', '2^12 mod 11 = 4', '8·5 mod 11 = 7', '2^1 = 2'], answer: 1, why: 'K = g^(ab) = 2^12 mod 11 = 4096 mod 11 = 4.' },
      { q: 'Which values travel in public?', options: ['a and b', 'p, g, g^a and g^b', 'only g^(ab)', 'nothing'], answer: 1, why: 'The group and both public values are sent in the clear; a, b and the key never are.' },
      { q: 'Why is the key g^(ab) the same on both sides?', options: ['(g^a)^b = g^(ab) = (g^b)^a', 'a = b', 'p is prime', 'g is 2'], answer: 0, why: 'Exponents multiply when a power is raised to a power, and multiplication commutes.' },
      { q: 'What does a real system do with g^(ab)?', options: ['uses it as the AES key directly', 'feeds it to a key-derivation function', 'publishes it', 'signs it'], answer: 1, why: 'The shared element is not uniformly random bits; a KDF such as HKDF turns it into keys.' },
    ],
  });

  function dhRun(inp) {
    const G = H.group(inp), real = inp.size === 'real', p = G.p, g = G.generator;
    const [a, b] = H.secrets(inp, G, ['a', 'b']);
    const dh = S.DLP.dh(G, a, b), A = dh.A, Bv = dh.B, K = dh.shared;
    const fa = S.RSA.powLR(g, a, p), fb = S.RSA.powLR(g, b, p), ka = S.RSA.powLR(Bv, a, p);
    const F = new S.Frames(['mults', 'sent']);
    const xs = [150, 440, 730], lanes = KP().lanes({ prefix: 'ln', names: ['Alice', 'Eve', 'Bob'], xs, y0: 40, y1: 560, cls: ['alice', 'eve', 'bob'] });
    const V = (k, x, y, l, val, cls) => H.V(k, x, y, l, val, cls, 18);
    const groupBox = [V('gp', 440, 130, real ? 'p, the 2048-bit MODP prime' : 'prime p', p, ''), V('gg', 440, 196, 'generator g', g, '')];
    const step1 = [V('sa', 150, 196, 'secret a', a, 'key'), V('sb', 730, 196, 'secret b', b, 'key')];
    const step2 = [V('pa', 150, 270, 'A = g^a mod p', A, 'act'), V('pb', 730, 270, 'B = g^b mod p', Bv, 'act')];
    const msgs = [...KP().msg({ key: 'm1', x1: 150 + 4, x2: 730 - 4, y: 340, text: 'A = ' + H.s(A), cls: 'act', title: 'A = ' + A }), ...KP().msg({ key: 'm2', x1: 730 - 4, x2: 150 + 4, y: 395, text: 'B = ' + H.s(Bv), cls: 'act', title: 'B = ' + Bv })];
    const eveNote = [P.t('ev1', 440, 450, 'Eve has p, g, A and B', 'bad', 'middle', 15)];
    const keys = [V('ka', 150, 500, 'K = B^a mod p', K, 'good'), V('kb', 730, 500, 'K = A^b mod p', K, 'good')];
    const add = (items, say, facts, meta) => F.add({ items: lanes.concat(items), say, facts, meta });
    add(groupBox, `Alice and Bob agree, in public, a prime p = ${H.n(p)} and a generator g = ${H.n(g)} of ${real ? 'a subgroup of prime order q = (p − 1)/2' : `Z_${H.n(p)}*`}. Eve hears this too.`, { p, g }, { phase: 'group' });
    add([...groupBox, ...step1], `Each picks a secret exponent: Alice a = ${H.n(a)}, Bob b = ${H.n(b)}. These never leave them.`, { a, b }, { phase: 'secrets' });
    F.set('mults', fa.squarings + fa.multiplications);
    add([...groupBox, ...step1, ...step2], `Each raises g to their secret: A = ${H.n(g)}^a mod p = ${H.n(A)} and B = g^b mod p = ${H.n(Bv)}. Square-and-multiply makes this quick: Alice needs ${fa.squarings} squarings and ${fa.multiplications} multiplications, Bob ${fb.squarings} and ${fb.multiplications}.`, { g, A, B: Bv, sa: fa.squarings, ma: fa.multiplications, sb: fb.squarings, mb: fb.multiplications }, { phase: 'public' });
    F.set('sent', 2);
    add([...groupBox, ...step1, ...step2, ...msgs, ...eveNote], `They send A = ${H.n(A)} and B = ${H.n(Bv)} across the open network. Eve copies both.`, { A, B: Bv, K, AB: G.op(A, Bv) }, { phase: 'sent' });
    F.set('mults', fa.squarings + fa.multiplications + ka.squarings + ka.multiplications);
    add([...groupBox, ...step1, ...step2, ...msgs, ...eveNote, ...keys], `Alice computes B^a mod p and Bob computes A^b mod p. Both get K = ${H.n(K)}, because (g^b)^a = g^(ab) = (g^a)^b.`, { K }, { phase: 'shared' });
    add([...groupBox, ...step1, ...step2, ...msgs, ...keys, P.t('ev2', 440, 450, 'Eve: from A, B to g^(ab)?', 'bad', 'middle', 15)], real ? `To find K Eve must compute g^(ab) from g^a and g^b. The best known way is a discrete logarithm modulo a ${P.bits(p)}-bit prime, about 2^${P.gnfsBits(P.bits(p)).toFixed(0)} steps of the number field sieve. In practice K goes through a key-derivation function before it keys a cipher.` : `To find K Eve must compute g^(ab) from g^a and g^b. With p = ${H.n(p)} she can just search for a; with a prime of 2048 bits that search is out of reach. In practice K goes through a key-derivation function before it keys a cipher.`, real ? { bits: P.bits(p), nfs: P.gnfsBits(P.bits(p)) } : { p }, { phase: 'eve' });
    for (const f of F.list) f.narrowView = { x: 0, y: 0, w: 880, h: 580 };
    return { frames: P.fix(F.list, { x: 0, y: 0, w: 880, h: 570 }), def: P.def('Diffie–Hellman', ['public: p, g', 'Alice: secret a, sends A = g^a mod p', 'Bob:   secret b, sends B = g^b mod p', 'Alice: K = B^a mod p', 'Bob:   K = A^b mod p', 'K = g^(ab); a listener sees only g^a, g^b']) };
  }

  // ---------------------------------------------------------------------------------------------------------------
  // The man in the middle
  // ---------------------------------------------------------------------------------------------------------------
  const NOTE = 'meet at the old mill at noon', NOTE2 = 'meet at the old mill at one';
  S.topic({
    id: 'p09-dh-mitm', family: 'p09-protocols', order: 30, title: 'The man in the middle',
    blurb: 'Diffie–Hellman tells you that you share a key with whoever answered, not with whom. Mallory sits on the wire, answers Alice as if she were Bob and Bob as if she were Alice, and ends up with one key for each. Every message passes through her, to read and to change.',
    inputs: H.toyInputs([H.exp('a', 'Alice\'s secret a', 6), H.exp('b', 'Bob\'s secret b', 15), H.exp('m', 'Mallory\'s secret m', 9)]),
    presets: [
      { label: 'p = 23', values: { size: 'toy', p: 23, g: 0, a: 6, b: 15, m: 9 } },
      { label: 'p = 1019', values: { size: 'toy', p: 1019, g: 0, a: 345, b: 811, m: 77 } },
      { label: 'Real: the 2048-bit MODP group', values: { size: 'real', seed: 31 } },
    ],
    counters: [{ id: 'keys', label: 'keys Mallory holds' }, { id: 'read', label: 'messages read' }],
    run(inp) { return P.memo('p09-dh-mitm', inp, () => mitm(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'swap-b', pick: 'option', ask: 'Alice now computes M^a. Who else can compute that key?', options: ['nobody', 'Bob', 'Mallory', 'both Bob and Mallory'], answer: 'Mallory', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What does Mallory need to sit in the middle of a Diffie–Hellman exchange?', options: ['the discrete logarithm of A', 'control of the wire, to replace the public values', 'Alice\'s password', 'a quantum computer'], answer: 1, why: 'She never solves anything: she runs one honest exchange with each side using her own secret.' },
      { q: 'After the attack, how many keys does Mallory hold?', options: ['none', 'one, shared by all three', 'two: one with Alice, one with Bob', 'only Bob\'s'], answer: 2, why: 'A^m is Alice\'s key and B^m is Bob\'s; they differ, and only Mallory has both.' },
      { q: 'Which fix stops this attack?', options: ['a larger prime', 'authenticating the public values (signatures, certificates)', 'a new secret each time', 'hashing the key'], answer: 1, why: 'If A comes signed by Alice and B by Bob, Mallory cannot substitute her own value unnoticed.' },
      { q: 'Can Alice tell from her key that something is wrong?', options: ['yes, it is smaller', 'yes, it is not prime', 'no, it is an ordinary group element', 'yes, it equals A'], answer: 2, why: 'M^a looks like any other shared key; nothing in the numbers betrays the attacker.' },
    ],
  });

  function mitm(inp) {
    const G = H.group(inp), real = inp.size === 'real', p = G.p, g = G.generator;
    const [a, b, m] = H.secrets(inp, G, ['a', 'b', 'm']);
    const r = S.DLP.dhMITM(G, a, b, m), A = r.A, Bv = r.B, M = r.M, kA = r.Am, kB = r.Bm, honest = G.pow(A, b);
    const F = new S.Frames(['keys', 'read']);
    const xs = [140, 440, 740], lanes = KP().lanes({ prefix: 'ln', names: ['Alice', 'Mallory', 'Bob'], xs, y0: 40, y1: 545, cls: ['alice', 'eve', 'bob'] });
    const V = (k, x, y, l, val, cls) => H.V(k, x, y, l, val, cls, 16);
    const secrets = [V('sa', 140, 130, 'secret a', a, 'key'), V('sm', 440, 130, 'secret m', m, 'bad'), V('sb', 740, 130, 'secret b', b, 'key')];
    const m1 = KP().msg({ key: 'm1', x1: 140, x2: 440, y: 192, text: 'A = ' + H.s(A), cls: 'act' });
    const m2 = KP().msg({ key: 'm2', x1: 440, x2: 740, y: 228, text: 'M = ' + H.s(M), cls: 'bad' });
    const m3 = KP().msg({ key: 'm3', x1: 740, x2: 440, y: 268, text: 'B = ' + H.s(Bv), cls: 'act' });
    const m4 = KP().msg({ key: 'm4', x1: 440, x2: 140, y: 304, text: 'M = ' + H.s(M), cls: 'bad' });
    const keys = [V('ka', 140, 368, 'key = M^a', kA, 'hot'), V('kma', 440, 368, 'A^m (Alice\'s key)', kA, 'hot'), V('kmb', 440, 428, 'B^m (Bob\'s key)', kB, 'act'), V('kb', 740, 428, 'key = M^b', kB, 'act')];
    const n1 = KP().msg({ key: 'n1', x1: 140, x2: 440, y: 488, text: 'E(' + NOTE + ')', cls: 'hot' });
    const n2 = KP().msg({ key: 'n2', x1: 440, x2: 740, y: 524, text: 'E(' + NOTE2 + ')', cls: 'bad' });
    for (const it of [...m1, ...m2, ...m3, ...m4, ...n1, ...n2]) if (it.kind === 'chip') it.size = 14;
    const add = (items, say, facts, meta) => F.add({ items: lanes.concat(items), say, facts, meta });
    add(secrets, `Alice and Bob run Diffie–Hellman with p = ${H.n(p)} and g = ${H.n(g)}, but nothing proves who sent which number. Mallory controls the wire between them and has her own secret m = ${H.n(m)}. Alice's secret is a = ${H.n(a)}, Bob's b = ${H.n(b)}.`, { p, g, m, a, b }, { phase: 'setup' });
    add([...secrets, ...m1, ...m2], `Alice sends A = g^a mod p = ${H.n(A)}. Mallory keeps it and passes Bob her own M = g^m mod p = ${H.n(M)}, as if it came from Alice.`, { A, M }, { phase: 'swap-a' });
    add([...secrets, ...m1, ...m2, ...m3, ...m4], `Bob answers with B = ${H.n(Bv)}. Mallory keeps that too and hands Alice the same M = ${H.n(M)}, as if it came from Bob.`, { B: Bv, M }, { phase: 'swap-b' });
    F.set('keys', 2);
    add([...secrets, ...m1, ...m2, ...m3, ...m4, ...keys], `Alice's key is M^a = ${H.n(kA)}, which Mallory also gets as A^m. Bob's key is M^b = ${H.n(kB)}, which Mallory gets as B^m. Two different keys, and Mallory holds both; the key Alice and Bob would have shared, g^(ab) = ${H.n(honest)}, exists nowhere.`, { kA, kB, honest }, { phase: 'keys' });
    F.set('read', 1);
    add([...secrets, ...m1, ...m2, ...m3, ...m4, ...keys, ...n1, ...n2], `Alice encrypts "${NOTE}" under her key. Mallory decrypts it with A^m, reads it, changes noon to one, and encrypts again under Bob's key. Bob decrypts without error and goes at the wrong time; neither notices anything.`, {}, { phase: 'relay' });
    const fix = [P.t('fx1', 440, 578, 'the fix: Alice signs A, Bob signs B, each checks the other\'s signature', 'good', 'middle', 15), P.t('fx2', 440, 604, 'Mallory cannot sign M as Alice, so Bob would reject it', 'good', 'middle', 15)];
    add([...secrets, ...m1, ...m2, ...m3, ...m4, ...keys, ...n1, ...n2, ...fix], `Nothing here is broken mathematically: Mallory solved no logarithm${real ? ` in the ${P.bits(p)}-bit group` : ''}. What failed is authentication. If Alice signs A and Bob signs B, with keys certified in advance, Mallory's M carries no valid signature and the exchange stops.`, real ? { bits: P.bits(p) } : {}, { phase: 'fix' });
    return { frames: P.fix(F.list, { x: -10, y: 0, w: 900, h: 620 }), def: P.def('The attack', ['Alice → Mallory: A = g^a      Mallory → Bob: M = g^m', 'Bob → Mallory: B = g^b        Mallory → Alice: M', 'Alice\'s key M^a = A^m (Mallory has it)', 'Bob\'s key   M^b = B^m (Mallory has it)', 'defence: authenticate A and B (sign them)']) };
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Elgamal encryption
  // ---------------------------------------------------------------------------------------------------------------
  const TEXT = 'the cellar key is under the blue pot';
  S.topic({
    id: 'p09-elgamal', family: 'p09-protocols', order: 40, title: 'Elgamal encryption',
    blurb: 'Bob publishes h = g^x. To write to him, Alice runs half of a Diffie–Hellman exchange with a fresh secret k: she sends g^k and her message multiplied by the mask h^k. Bob rebuilds the mask from g^k with his x and divides it out. A new k each time makes every ciphertext different, even for the same message.',
    inputs: H.toyInputs([H.exp('x', 'Bob\'s private key x', 7), { id: 'm', kind: 'number', label: 'Message m (toy)', def: 11, min: 1, max: 1000000006, check: (v, inp) => (v >= inp.p ? 'm: from 1 to p − 1' : null) }, H.exp('k', 'Nonce k', 4), H.exp('k2', 'Second nonce k′', 9)]),
    presets: [
      { label: 'p = 23, m = 11', values: { size: 'toy', p: 23, g: 0, x: 7, m: 11, k: 4, k2: 9 } },
      { label: 'p = 2027', values: { size: 'toy', p: 2027, g: 0, x: 1234, m: 1999, k: 777, k2: 1500 } },
      { label: 'A 30-bit prime', values: { size: 'toy', p: 1000000007, g: 0, x: 424242, m: 31337, k: 271828, k2: 314159 } },
      { label: 'Real: a sentence in the 2048-bit group', values: { size: 'real', seed: 5 } },
    ],
    counters: [{ id: 'ct', label: 'ciphertexts made' }],
    run(inp) { return P.memo('p09-elgamal', inp, () => elgamal(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'sent', pick: 'option', ask: 'Bob raises c1 to his x. What does he get?', options: (fr, i) => [...new Set([H.s(fr[i].facts.s), H.s(fr[i].facts.c2), H.s(fr[i].facts.h)])], answer: (fr, i) => H.s(fr[i].facts.s), explain: (fr, i) => fr[i + 1].say },
      { at: (f) => f.meta.phase === 'again', pick: 'option', ask: 'Someone doubles c2 on the way. What will Bob decrypt?', options: (fr, i) => [...new Set([H.s(fr[i + 1].facts.m2), H.s(fr[i + 1].facts.m), 'an error'])], answer: (fr, i) => H.s(fr[i + 1].facts.m2), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What does Alice send?', options: ['g^x', '(g^k, m·h^k)', 'm^k', '(k, m·h)'], answer: 1, why: 'c1 = g^k lets Bob rebuild the mask; c2 = m·h^k carries the message.' },
      { q: 'How does Bob get the mask h^k?', options: ['from k', 'c1^x = g^(kx) = h^k', 'from c2', 'it is public'], answer: 1, why: 'Only the holder of x can turn g^k into g^(kx).' },
      { q: 'Why must k be fresh for every message?', options: ['to make c1 short', 'two messages under one k share a mask: m1/m2 = c2/c2′ leaks', 'k is the private key', 'it need not be'], answer: 1, why: 'With the same mask s, c2/c2′ = m/m′; knowing one message reveals the other.' },
      { q: 'Elgamal ciphertexts are how long compared with the message?', options: ['the same', 'about twice as long', 'half', 'one bit longer'], answer: 1, why: 'Two group elements, c1 and c2, for one element of message.' },
      { q: 'Multiplying c2 by 3 makes Bob decrypt…', options: ['an error', '3·m', 'm + 3', 'm'], answer: 1, why: 'Elgamal is malleable: (c1, 3·c2) is a valid encryption of 3m. Padding or a message authentication code is needed to stop this.' },
    ],
  });

  function elgamal(inp) {
    const G = H.group(inp), real = inp.size === 'real', p = G.p, g = G.generator;
    const [x, k, k2] = H.secrets(inp, G, ['x', 'k', 'k2']);
    const bytes = new TextEncoder().encode(TEXT), m = real ? NT().fromBytes(bytes) : B(inp.m);
    const key = S.DLP.elgamalKey(G, x), h = key.h;
    const e1 = S.DLP.elgamalEncrypt(key.pub, m, k), d1 = S.DLP.elgamalDecrypt(key, e1);
    const e2 = S.DLP.elgamalEncrypt(key.pub, m, k2), d2 = S.DLP.elgamalDecrypt(key, e2);
    const c2x = G.op(e1.c2, 2n), d3 = S.DLP.elgamalDecrypt(key, { c1: e1.c1, c2: c2x }), sInv = G.inv(d1.s);
    const F = new S.Frames(['ct']);
    const W = 246, V = (k_, x_, y_, l, v, cls) => KP().value({ key: k_, x: x_, y: y_, w: W, label: l, value: v, cls, max: 12 });
    const L = 150, M = 440, R = 730, ys = [118, 186, 254, 322, 390, 458];
    const frame = [...P.panel('pa', L - 130, 40, 260, 455, 'Alice, the sender'), ...P.panel('pm', M - 130, 40, 260, 455, 'in public'), ...P.panel('pb', R - 130, 40, 260, 455, 'Bob, the receiver')];
    const group = [V('gp', M, ys[0], real ? 'p, the MODP prime' : 'prime p, g = ' + H.s(g), p, '')];
    const bob = [V('bx', R, ys[0], 'private key x', x, 'key'), V('bh', R, ys[1], 'public key h = g^x', h, 'good')];
    const pubH = [V('mh', M, ys[1], 'h', h, 'good'), { key: 'eh', kind: 'edge', from: 'bh', to: 'mh', cls: 'good' }];
    const alice = (kk, enc, cls) => [V('am', L, ys[0], real ? 'm: the sentence as a number' : 'message m', m, 'act'), V('ak', L, ys[1], 'fresh nonce k', kk, 'key'), V('ac1', L, ys[2], 'c1 = g^k', enc.c1, cls), V('as', L, ys[3], 'mask s = h^k', enc.s, 'hot'), V('ac2', L, ys[4], 'c2 = m·s mod p', enc.c2, cls)];
    const sent = (enc, c2v, cls) => [V('mc1', M, ys[2], 'c1', enc.c1, cls), V('mc2', M, ys[4], 'c2', c2v, cls), { key: 'e1', kind: 'edge', from: 'ac1', to: 'mc1', cls: 'act' }, { key: 'e2', kind: 'edge', from: 'ac2', to: 'mc2', cls: 'act' }];
    const dec = (dd, cls) => [V('bs', R, ys[2], 's = c1^x', dd.s, 'hot'), V('bi', R, ys[3], 's⁻¹ mod p', G.inv(dd.s), ''), V('bm', R, ys[4], 'm = c2·s⁻¹', dd.m, cls), { key: 'e3', kind: 'edge', from: 'mc1', to: 'bs', cls: 'act' }, { key: 'e4', kind: 'edge', from: 'mc2', to: 'bm', cls: 'act' }];
    const add = (items, say, facts, meta) => F.add({ items: frame.concat(items), say, facts, meta });
    add([...group, ...bob, ...pubH], `Bob picks a private key x = ${H.n(x)} and publishes h = g^x mod p = ${H.n(h)}, with p = ${H.n(p)} and g = ${H.n(g)}.`, { x, h, p, g }, { phase: 'key' });
    add([...group, ...bob, ...pubH, V('am', L, ys[0], real ? 'm: the sentence as a number' : 'message m', m, 'act')], real ? `Alice's message "${TEXT}" is ${bytes.length} bytes; read as one number it is m = ${H.n(m)}, well below p.` : `Alice wants to send m = ${H.n(m)}, a number from 1 to p − 1.`, real ? { len: bytes.length, m } : { m }, { phase: 'message' });
    F.set('ct', 1);
    add([...group, ...bob, ...pubH, ...alice(k, e1, 'act')], `She draws a fresh nonce k = ${H.n(k)} and computes c1 = g^k = ${H.n(e1.c1)}, the mask s = h^k = ${H.n(e1.s)}, and c2 = m·s mod p = ${H.n(e1.c2)}. The mask is a Diffie–Hellman key between her k and Bob's x.`, { k, c1: e1.c1, s: e1.s, c2: e1.c2 }, { phase: 'encrypt' });
    add([...group, ...bob, ...pubH, ...alice(k, e1, 'act'), ...sent(e1, e1.c2, 'act')], `The ciphertext (c1, c2) = (${H.n(e1.c1)}, ${H.n(e1.c2)}) travels in public. Without x nobody can rebuild s.`, { c1: e1.c1, c2: e1.c2, s: e1.s, h }, { phase: 'sent' });
    add([...group, ...bob, ...pubH, ...alice(k, e1, 'act'), ...sent(e1, e1.c2, 'act'), ...dec(d1, 'good')], `Bob computes s = c1^x = ${H.n(d1.s)}, the same mask, since (g^k)^x = (g^x)^k. Its inverse is ${H.n(sInv)}, and c2·s⁻¹ mod p = ${H.n(d1.m)}: the message.`, { s: d1.s, sInv, m: d1.m }, { phase: 'decrypt' });
    F.set('ct', 2);
    add([...group, ...bob, ...pubH, ...alice(k2, e2, 'hot'), ...sent(e2, e2.c2, 'hot'), ...dec(d2, 'good')], `Encrypting the same m again with a new nonce k′ = ${H.n(k2)} gives a different ciphertext, (${H.n(e2.c1)}, ${H.n(e2.c2)}), which decrypts to the same ${H.n(d2.m)}. A listener cannot even tell that the same message was sent twice.`, { k2, c1: e2.c1, c2: e2.c2, m: d2.m }, { phase: 'again' });
    add([...group, ...bob, ...pubH, ...alice(k, e1, 'act'), ...sent(e1, c2x, 'bad'), ...dec(d3, 'bad'), P.t('tw', M, ys[5] - 6, 'c2 doubled on the wire', 'bad', 'middle', 14)], `But the scheme is malleable. Someone on the wire replaces c2 by 2·c2 mod p = ${H.n(c2x)} without knowing m; Bob decrypts ${H.n(d3.m)}, which is 2m mod p. Real systems add padding or a message authentication code, so that a changed ciphertext is rejected.`, { c2x, m2: d3.m, m }, { phase: 'malleable' });
    const col = (cx) => ({ x: cx - 140, y: 30, w: 280, h: 480 }), where = { key: R, message: L, encrypt: L, sent: M, decrypt: R, again: L, malleable: R };
    for (const f of F.list) f.narrowView = col(where[f.meta.phase]);
    return { frames: P.fix(F.list, { x: -10, y: 20, w: 900, h: 510 }), def: P.def('Elgamal', ['key: private x, public h = g^x mod p', 'encrypt m: fresh k, c1 = g^k, c2 = m·h^k mod p', 'decrypt: s = c1^x, m = c2·s⁻¹ mod p', 'randomised: a new k gives a new (c1, c2)', 'malleable: (c1, t·c2) decrypts to t·m']) };
  }
})(globalThis.Sifer = globalThis.Sifer || {});
