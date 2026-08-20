// Part 4, weaknesses and fixes: weak and semi-weak keys with the complementation property, the price of trying
// every key over the years, double DES met in the middle, and the two ways DES was stretched: 3DES and DESX.
(function (S) {
  'use strict';
  const U = S.SymT, F = () => S.Kit.flow;
  const hx = (a) => U.hex(a);
  const not = (a) => a.map((v) => ~v & 255);
  const desE = (k) => S.DES.cipher(k);
  const sub = U.sub;
  const hexIn = (id, label, def, bytes) => ({ id, kind: 'hex', label, def, bytes });

  // ---------------------------------------------------------------------------------------------------------------
  // Weak and semi-weak keys, and the complementation property
  // ---------------------------------------------------------------------------------------------------------------
  function weak(inp) {
    const key = U.fromHex(inp.key), p = U.fromHex(inp.plain);
    const kc = S.DES.keyClass(key), ks = S.DES.keySchedule(key), C0 = ks.trace[0].C, D0 = ks.trace[0].D;
    const c0 = S.DES.hex(C0), d0 = S.DES.hex(D0), keys = kc.subkeys, distinct = [...new Set(keys)];
    const partner = kc.partner ? U.fromHex(kc.partner) : null, k2 = partner || key;
    const demo = S.DES.weakDemo(p, key, k2), comp = S.DES.complementation(p, key);
    const kind = kc.weak ? 'weak' : kc.semiWeak ? 'semi-weak' : 'ordinary';
    const Fr = new S.Frames();
    const head = U.head('wk:h', 'The key ' + hx(key) + ' (' + kind + ')');
    const constC = C0.every((b) => b === C0[0]), constD = D0.every((b) => b === D0[0]);
    // C0 and D0 as rows of 28 bits
    const halves = (lit) => {
      const items = [U.t('wk:kl', 24, 74, 'PC-1 drops the 8 parity bits and splits the other 56:', 'tick', 'start', 14)];
      [['C', C0, c0, 98], ['D', D0, d0, 132]].forEach(([n, bits, h, y]) => {
        items.push(U.t('wk:n' + n, 24, y + 15, n + '₀', 'strong', 'start', 16));
        items.push(...U.bitRow({ prefix: 'wk' + n, x: 64, y, bits, cw: 14, ch: 22, gap: 1, group: 7, groupGap: 5, text: false, cls: () => (lit ? 'act' : '') }).items);
        items.push(U.t('wk:h' + n, 520, y + 16, h, 'mono', 'start', 16));
      });
      items.push(U.t('wk:rot', 620, 116, 'each round rotates C and D', 'tick', 'start', 14));
      items.push(U.t('wk:rot2', 620, 138, (constC && constD) ? 'all equal: rotation changes nothing' : 'left by 1 or 2 places', constC && constD ? 'hot' : 'tick', 'start', 14));
      return items;
    };
    const cls = (v) => (v === distinct[0] ? 'act' : v === distinct[1] ? 'key' : '');
    const subkeys = (show) => {
      const items = [U.t('wk:kt', 24, 196, 'the sixteen round keys K₁ … K₁₆', 'title', 'start', 14)];
      keys.forEach((v, i) => {
        const r = Math.floor(i / 8), c = i % 8;
        items.push({ key: 'wk:k' + i, kind: 'cell', x: 24 + c * 109, y: 210 + r * 58, w: 104, h: 34, rx: 4, text: show ? v : '', size: 13, sub: 'K' + sub(i + 1), cls: 'hex ' + (show ? cls(v) : 'soft') });
      });
      return items;
    };
    const flow = (stage) => {
      const N = F().net('wkf'), y = 400;
      N.label('t', 24, 346, 'encrypt twice', 'title', 'start', 14);
      N.chip('p', hx(p), [110, y], 'plain');
      N.box('e1', 290, y, 130, 46, 'DES', 'cipher' + (stage === 1 ? ' act' : '')); N.label('k1', 290, y - 34, 'key ' + hx(key), 'key', 'middle', 13);
      N.chip('c', stage >= 1 ? hx(demo.once) : '?', [480, y], stage === 1 ? 'act' : 'plain');
      N.box('e2', 660, y, 130, 46, 'DES', 'cipher' + (stage === 2 ? ' act' : '')); N.label('k2', 660, y - 34, 'key ' + hx(k2), 'key', 'middle', 13);
      N.chip('cc', stage >= 2 ? hx(demo.twice) : '?', [840, y], stage === 2 ? (demo.back ? 'act' : 'hot') : 'plain');
      N.wire('a', [[184, y], N.port('e1', 'w')], { head: true });
      N.wire('b', [N.port('e1', 'e'), [406, y]], { head: true, cls: stage === 1 ? 'act' : '' });
      N.wire('c', [[554, y], N.port('e2', 'w')], { head: true });
      N.wire('d', [N.port('e2', 'e'), [766, y]], { head: true, cls: stage === 2 ? 'act' : '' });
      return N.items;
    };
    const compPanel = (on) => {
      if (!on) return [];
      const rows = [['DES(p, k)', hx(comp.c), ''], ['DES(¬p, ¬k)', hx(comp.cc), 'hot'], ['¬DES(p, k)', hx(not(comp.c)), comp.holds ? 'act' : 'bad']];
      const items = [...U.panel('wk:cp', 24, 456, 872, 150, 'the complementation property')];
      rows.forEach(([l, v, c], i) => { items.push(U.t('wk:cl' + i, 44, 512 + i * 30, l, 'math', 'start', 16)); items.push(U.t('wk:cv' + i, 260, 512 + i * 30, v, 'mono ' + c, 'start', 17)); });
      items.push(U.t('wk:ck', 470, 542, comp.holds ? '= the complement of the first: equal' : 'not equal', comp.holds ? 'act' : 'bad', 'start', 15));
      items.push(U.t('wk:ck2', 470, 572, '¬p = ' + hx(not(p)) + ', ¬k = ' + hx(not(key)), 'tick', 'start', 14));
      return items;
    };
    const base = (st) => [head, ...halves(st === 0), ...subkeys(st >= 1)];
    Fr.add({ items: [...base(0), ...flow(0)], hl: { d: [0] }, say: `PC-1 turns the key ${hx(key)} into two 28-bit halves, C₀ = ${c0} and D₀ = ${d0}. Every round key is picked from C and D after they rotate. ` + (constC && constD ? 'Here each half is all zeros or all ones, so no rotation can change it.' : 'Here the bits of each half differ, so the rotations move them around.'), facts: { c0, d0, key: hx(key) }, meta: { stage: 'pc1' } });
    Fr.add({ items: [...base(1), ...flow(0)], hl: { d: [1] }, say: `The sixteen round keys take ${U.plural(distinct.length, 'distinct value')}: ` + (distinct.length <= 2 ? distinct.join(' and ') + '. ' : 'one for every round. ') + (kc.weak ? 'With every round key equal, the keys in reverse order are the same keys: decryption is encryption.' : kc.semiWeak ? `They alternate, so the partner key ${hx(partner)} makes the same round keys in reverse order: it decrypts what this key encrypts.` : 'Reversed, they are a different list, so encrypting is not the same as decrypting.'), facts: { distinct: distinct.length, list: distinct.slice(0, 2), partner: partner ? hx(partner) : null }, meta: { stage: 'keys' } });
    Fr.add({ items: [...base(1), ...flow(1)], say: `Encrypt the plaintext ${hx(p)} with the key: ${hx(demo.once)}.`, facts: { p: hx(p), c: hx(demo.once) }, meta: { stage: 'once' } });
    Fr.add({ items: [...base(1), ...flow(2)], say: `Encrypt that again with ${partner ? 'the partner key ' + hx(partner) : 'the same key'}: ${hx(demo.twice)}. ` + (demo.back ? 'That is the plaintext again: a second encryption undid the first.' : 'That is not the plaintext: for an ordinary key, encrypting twice just scrambles further.'), facts: { cc: hx(demo.twice), back: demo.back }, meta: { stage: 'twice', back: demo.back } });
    Fr.add({ items: [...base(1), ...flow(2), ...compPanel(true)], hl: { d: [2] }, say: `Complement the plaintext and the key: DES(¬p, ¬k) = ${hx(comp.cc)}, which is the complement of DES(p, k) = ${hx(comp.c)}. Inside each round E sees R complemented and the round key is complemented too, so their XOR, the S-box input, is unchanged. This holds for every key.`, facts: { c: hx(comp.c), cc: hx(comp.cc), holds: comp.holds }, meta: { stage: 'comp' } });
    const total = 2n ** 56n, half = total / 2n;
    Fr.add({ items: [...base(1), ...flow(2), ...compPanel(true)], say: `Of the ${U.big(total)} keys, 4 are weak and 12 are semi-weak (6 pairs): easy to avoid, so they matter little. The complement matters more: one encryption of a known plaintext tests a key and its complement at once, so a search needs only ${U.big(half)} encryptions, 2⁵⁵ instead of 2⁵⁶.`, facts: { total: U.big(total), half: U.big(half), weak: 4, semi: 12, pairs: 6 }, meta: { stage: 'end' } });
    U.fix(Fr.list, { x: 0, y: 0, w: 920, h: 620 });
    return { frames: Fr.list, def: U.def('Weak keys and complements', ['C₀, D₀ = PC-1(k); Kᵢ = PC-2(rotate(C, D))', 'weak: K₁ = … = K₁₆, so DES_k(DES_k(p)) = p', 'semi-weak pair k, k′: DES_k′(DES_k(p)) = p', 'DES(¬p, ¬k) = ¬DES(p, k)', 'search: 2⁵⁵ trials with one chosen pair']) };
  }
  S.topic({
    id: 'des-weak', family: 'p04-weak', order: 10, title: 'Weak keys and the complement',
    blurb: 'A few keys make every round key the same, so encrypting twice gives the plaintext back; and complementing both plaintext and key complements the ciphertext, which halves an exhaustive search.',
    inputs: [hexIn('key', 'Key (8 bytes)', '0101010101010101', 8), hexIn('plain', 'Plaintext (8 bytes)', '74696465706f6f6c', 8)],
    presets: [
      { label: 'Weak: 01 01 … 01', values: { key: '0101010101010101' } },
      { label: 'Weak: e0e0e0e0f1f1f1f1', values: { key: 'e0e0e0e0f1f1f1f1' } },
      { label: 'Semi-weak: 01fe01fe…', values: { key: '01fe01fe01fe01fe' } },
      { label: 'Semi-weak: 1fe01fe0…', values: { key: '1fe01fe00ef10ef1' } },
      { label: 'Ordinary: "kestrel!"', values: { key: '6b65737472656c21' } },
    ],
    run: weak,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'keys', once: true, pick: 'option', options: ['the plaintext', 'something else'], ask: 'The ciphertext will be encrypted a second time (with the partner key, if there is one). What comes out?', answer: (fr) => (fr.find((f) => f.meta.stage === 'twice').meta.back ? 'the plaintext' : 'something else'), explain: 'Only weak keys, and semi-weak pairs, undo themselves; an ordinary key\'s round keys reversed are a different list.' },
      { at: (f) => f.meta && f.meta.stage === 'twice', once: true, pick: 'option', options: ['¬DES(p, k)', 'DES(p, k)', 'nothing related'], ask: 'Complement the plaintext and the key. What will DES(¬p, ¬k) be?', answer: '¬DES(p, k)', explain: 'The two complements cancel at every S-box input, and the complement then runs through the XORs to the output.' },
    ],
    quiz: [
      { q: 'Why does the key 0101010101010101 make all sixteen round keys equal?', options: ['Its parity bits are set', 'After PC-1 both halves are all zeros, so rotating them changes nothing', 'It is shorter than other keys', 'DES skips the key schedule for it'], answer: 1, why: 'The round keys are chosen from rotated C and D; a constant half rotates to itself.' },
      { q: 'With a weak key k, what is DES_k(DES_k(p))?', options: ['p', '¬p', 'DES_k(p)', 'a random block'], answer: 0, why: 'Decryption uses the round keys in reverse order, and reversed they are the same list.' },
      { q: 'The complementation property says…', options: ['DES(¬p, ¬k) = ¬DES(p, k)', 'DES(¬p, k) = DES(p, ¬k)', 'DES(p, ¬k) = ¬p', 'the complement of a weak key is semi-weak'], answer: 0, why: 'E commutes with complementing, and the complemented round key cancels it before the S-boxes.' },
      { q: 'How much does the complementation property save an exhaustive search?', options: ['Nothing', 'Half the keys: 2⁵⁵ trials', 'A quarter', 'It makes search impossible'], answer: 1, why: 'Encrypting p under k also tells you, for free, whether ¬k encrypts ¬p to the complement you know.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Exhaustive search economics
  // ---------------------------------------------------------------------------------------------------------------
  // Public figures for machines that searched (or were designed to search) DES keys, in keys per second.
  const MACHINES = [
    { year: 1977, name: 'a proposed special-purpose machine', rate: 1e12, cost: 'about $20 million (an estimate)' },
    { year: 1997, name: 'volunteers\' PCs over the internet', rate: 7e9, cost: 'spare cycles (peak rate)' },
    { year: 1998, name: 'a purpose-built search machine', rate: 9e10, cost: 'about $250 000' },
    { year: 1999, name: 'that machine plus 100 000 volunteers\' PCs', rate: 2.45e11, cost: 'spare cycles' },
    { year: 2006, name: 'a box of 120 FPGAs', rate: 6.5e10, cost: 'about €9 000' },
    { year: 2012, name: 'a rack of 48 FPGAs', rate: 7.68e11, cost: 'a service charging per key' },
  ];
  const dur = (s) => {
    const m = 60, h = 3600, d = 86400, y = 365.25 * d;
    if (s < 2 * m) return s.toFixed(s < 10 ? 1 : 0) + ' seconds';
    if (s < 2 * h) return (s / m).toFixed(s < 10 * m ? 1 : 0) + ' minutes';
    if (s < 3 * d) return (s / h).toFixed(1) + ' hours';
    if (s < 2 * y) return (s / d).toFixed(1) + ' days';
    if (s < 100 * y) return (s / y).toFixed(1) + ' years';
    if (s < 1e6 * y) return U.big(Math.round(s / y)) + ' years';
    return (s / y).toExponential(1).replace('e+', ' × 10^') + ' years';
  };
  const sci = (v) => { const e = Math.floor(Math.log10(v)), m = v / 10 ** e; return (Math.abs(m - 1) < 1e-9 ? '' : (+m.toFixed(2)) + ' × ') + '10' + U.sup(e); };
  function search(inp) {
    const bits = +inp.bits, comp = inp.comp === 'yes' && bits === 56, space = Math.pow(2, bits - (comp ? 1 : 0));
    const Fr = new S.Frames();
    const head = U.head('ds:h', 'Trying every ' + bits + '-bit key' + (comp ? ', with the complement' : ''));
    // the plot: years across, keys per second up (log scale)
    const px = 80, py = 70, pw = 470, ph = 440, x0 = 1975, x1 = 2015, l0 = 9, l1 = 13;
    const X = (yr) => U.r2(px + ((yr - x0) / (x1 - x0)) * pw), Y = (r) => U.r2(py + ph - ((Math.log10(r) - l0) / (l1 - l0)) * ph);
    const axes = [{ key: 'ds:ax', kind: 'path', d: `M${px},${py} V${py + ph} H${px + pw}`, cls: 'p4axis', audit: 'ignore', layer: 'back', box: { x: px, y: py, w: pw, h: ph } }];
    for (let e = l0; e <= l1; e++) axes.push(U.t('ds:ty' + e, px - 8, Y(10 ** e) + 5, '10' + U.sup(e), 'tick', 'end', 13));
    for (let yr = 1975; yr <= 2015; yr += 10) axes.push(U.t('ds:tx' + yr, X(yr), py + ph + 20, String(yr), 'tick', 'middle', 13));
    axes.push(U.t('ds:yl', px, py - 14, 'keys tried per second', 'tick', 'start', 13));
    // the rates that sweep the whole space in a day and in a year
    const lines = [];
    [['day', 86400], ['year', 365.25 * 86400]].forEach(([n, s]) => {
      const r = space / s;
      if (Math.log10(r) < l0 || Math.log10(r) > l1) return;
      lines.push({ key: 'ds:ln' + n, kind: 'path', d: `M${px},${Y(r)} H${px + pw}`, cls: 'p4guide', audit: 'ignore', layer: 'back' });
      lines.push(U.t('ds:lt' + n, X(1987), Y(r) - 7, 'all keys in a ' + n, 'tick', 'middle', 13));
    });
    const dots = (upto) => MACHINES.slice(0, upto + 1).map((m, i) => ({ key: 'ds:d' + i, kind: 'dot', x: X(m.year), y: Y(m.rate), r: i === upto ? 8 : 6, cls: i === upto ? 'hot' : 'act', point: true }));
    const labels = (upto) => MACHINES.slice(0, upto + 1).map((m, i) => U.t('ds:dl' + i, X(m.year) + (m.year > 2005 ? -12 : 12), Y(m.rate) + (i === 3 ? -10 : 18), String(m.year), i === upto ? 'hot' : 'tick', m.year > 2005 ? 'end' : 'start', 13));
    const panel = (m, upto) => {
      const full = space / m.rate, items = [...U.panel('ds:r', 580, 70, 316, 236, String(m.year))];
      const words = m.name.split(' '), l1 = [], l2 = [];
      for (const w of words) ((l1.join(' ') + ' ' + w).length <= 34 && !l2.length ? l1 : l2).push(w);
      items.push(U.t('ds:n1', 594, 118, l1.join(' '), 'strong', 'start', 14), U.t('ds:n2', 594, 138, l2.join(' '), 'strong', 'start', 14));
      [['keys per second', sci(m.rate), ''], ['cost', m.cost.split(' (')[0], ''], ['every key', dur(full), 'hot'], ['on average', dur(full / 2), 'act']].forEach(([l, v, c], j) => {
        items.push(U.t('ds:rl' + j, 594, 176 + j * 32, l, '', 'start', 13), U.t('ds:rv' + j, 882, 176 + j * 32, v, 'mono ' + c, 'end', 14));
      });
      items.push(...U.panel('ds:s', 580, 322, 316, 222, 'every key, machine by machine'));
      MACHINES.slice(0, upto + 1).forEach((q, j) => {
        items.push(U.t('ds:sy' + j, 594, 370 + j * 28, String(q.year), j === upto ? 'hot' : 'tick', 'start', 14), U.t('ds:sv' + j, 882, 370 + j * 28, dur(space / q.rate), 'mono ' + (j === upto ? 'hot' : ''), 'end', 14));
      });
      return items;
    };
    Fr.add({ items: [head, ...axes, ...lines, ...U.readout('ds:r', 580, 70, 316, 'the key space', [['key bits', String(bits)], ['keys to try', sci(space).includes('×') ? sci(space) : sci(space)], ['exactly', bits <= 64 ? U.big(BigInt(2) ** BigInt(bits - (comp ? 1 : 0))) : '2^' + (bits - (comp ? 1 : 0))]], { dy: 34 })], say: `A key of ${bits} bits leaves ${bits <= 64 ? U.big(2n ** BigInt(bits)) : '2^' + bits} keys.` + (comp ? ` The complementation property tests two keys with one encryption, so the search needs ${U.big(2n ** BigInt(bits - 1))}.` : '') + ' What matters is how many keys a machine tries per second; the guide lines mark the rates that sweep them all in a day and in a year.', facts: { bits, n: bits <= 64 ? [U.big(2n ** BigInt(bits)), U.big(2n ** BigInt(bits - 1))] : bits }, meta: { stage: 'space' } });
    MACHINES.forEach((m, i) => {
      const full = space / m.rate;
      Fr.add({ items: [head, ...axes, ...lines, ...dots(i), ...labels(i), ...panel(m, i)], say: `${m.year}: ${m.name}, ${m.cost}, trying ${sci(m.rate)} keys a second, would go through every key in ${dur(full)}, and find a given key in ${dur(full / 2)} on average.`, facts: { year: m.year, rv: m.rate, rate: sci(m.rate), cost: m.cost, full: dur(full), avg: dur(full / 2), name: m.name }, meta: { stage: 'machine', i, day: full <= 86400 } });
    });
    const fast = MACHINES[MACHINES.length - 1], k112 = Math.pow(2, 112) / fast.rate;
    Fr.add({ items: [head, ...axes, ...lines, ...dots(MACHINES.length - 1).map((d) => Object.assign(d, { cls: 'act', r: 6 })), ...labels(MACHINES.length - 1), ...U.readout('ds:r', 580, 70, 316, 'and with 112 bits', [['rate (fastest here)', sci(fast.rate)], ['every 112-bit key', dur(k112), 'hot'], ['each extra bit', 'doubles the time']], { dy: 34, size: 13, vsize: 14 }), ...panel(fast, MACHINES.length - 1).filter((it) => it.key.startsWith('ds:s'))], say: `Machines actually built went from ${sci(MACHINES[1].rate)} keys a second in ${MACHINES[1].year} to ${sci(fast.rate)} in ${fast.year}, about ${Math.round(fast.rate / MACHINES[1].rate)} times faster, so searching ${bits}-bit keys went from a fortune to ${dur(space / fast.rate)}. Two-key 3DES has 112 key bits: at the fastest rate here, ${sci(fast.rate)} keys a second, every key would take ${dur(k112)}. Longer keys, not faster machines, decide this race.`, facts: { bits, full: dur(space / fast.rate), rate: sci(fast.rate), k112: dur(k112), from: { year: MACHINES[1].year, rate: sci(MACHINES[1].rate), rv: MACHINES[1].rate }, to: { year: fast.year, rv: fast.rate }, ratio: Math.round(fast.rate / MACHINES[1].rate) }, meta: { stage: 'end' } });
    U.fix(Fr.list, { x: 0, y: 0, w: 920, h: 560 });
    return { frames: Fr.list, def: U.def('Exhaustive search', ['keys to try: 2ⁿ (2ⁿ⁻¹ with the complement trick)', 'time = keys ÷ rate', 'on average the key turns up halfway', 'one more key bit doubles the time', 'DES: n = 56; two-key 3DES: n = 112']) };
  }
  S.topic({
    id: 'des-search', family: 'p04-weak', order: 20, title: 'The price of trying every key',
    blurb: 'Fifty-six bits were costly to search in 1977 and a day\'s work by 1999. A plot of machines and their key rates, the time each needs, and why 112 bits are out of reach.',
    inputs: [U.choice('bits', 'Key length', '56', [['40', '40 bits (old export grade)'], ['56', '56 bits (DES)'], ['64', '64 bits'], ['112', '112 bits (two-key 3DES)']]), U.choice('comp', 'Use the complement trick', 'no', [['no', 'no'], ['yes', 'yes (DES only)']])],
    presets: [{ label: 'DES, 56 bits', values: { bits: '56', comp: 'no' } }, { label: 'DES with the complement', values: { bits: '56', comp: 'yes' } }, { label: '40-bit export keys', values: { bits: '40' } }, { label: '64 bits', values: { bits: '64' } }, { label: '112 bits', values: { bits: '112' } }],
    run: search,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'machine' && f.meta.i === 4, once: true, pick: 'option', options: ['within a day', 'more than a day'], ask: 'The 2012 machine tries 7.68 × 10¹¹ keys a second. Will it sweep every key within a day?', answer: (fr, i) => (fr[i + 1].meta.day ? 'within a day' : 'more than a day'), explain: 'Divide the number of keys by the rate: a day is 86 400 seconds.' }],
    quiz: [
      { q: 'A machine tries 10¹² keys a second. Roughly how long for all 2⁵⁶ ≈ 7.2 × 10¹⁶ DES keys?', options: ['20 hours', '20 seconds', '20 years', '20 minutes'], answer: 0, why: '7.2 × 10¹⁶ ÷ 10¹² = 72 000 seconds, about 20 hours.' },
      { q: 'On average, how much of the key space does a search try before finding the key?', options: ['All of it', 'Half', 'A quarter', 'The square root'], answer: 1, why: 'The key is equally likely to be anywhere in the order of trial.' },
      { q: 'Adding 8 bits to a key multiplies the search time by…', options: ['8', '16', '256', '64'], answer: 2, why: 'Each bit doubles the space: 2⁸ = 256.' },
      { q: 'Why did 56-bit DES fall to search while 112-bit 3DES did not?', options: ['3DES is faster', '2¹¹² is 2⁵⁶ times larger: no growth in machine speed covers that', '3DES has no weak keys', 'Search machines only fit DES'], answer: 1, why: 'Even a billion times faster machines leave 112 bits far out of reach.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Double DES and the meet-in-the-middle attack
  // ---------------------------------------------------------------------------------------------------------------
  function mitm(inp) {
    const bits = inp.bits, lab = S.MITM.setup({ seed: inp.seed, bits }), N = 1 << bits;
    const res = S.MITM.attack({ base: lab.base, bits, pairs: lab.pairs });
    const P1 = lab.pairs[0], P2 = lab.pairs[1];
    const kf = (v) => S.MITM.keyFrom(lab.base, v, bits);
    const fwd = Array.from({ length: N }, (_, v) => ({ v, m: hx(desE(kf(v)).encrypt(P1.p)) }));
    const sorted = fwd.slice().sort((a, b) => (a.m < b.m ? -1 : a.m > b.m ? 1 : a.v - b.v));
    const found = res.found[0] || { k1v: lab.k1v, k2v: lab.k2v };
    const target = hx(desE(kf(found.k2v)).decrypt(P1.c));
    const tset = new Set(fwd.map((r) => r.m));
    const back = (v) => hx(desE(kf(v)).decrypt(P1.c));
    const misses = []; for (let v = 0; v < N && misses.length < 3; v++) if (v !== found.k2v && !tset.has(back(v))) misses.push(v);
    const Fr = new S.Frames();
    const head = U.head('mm:h', 'Double DES met in the middle, ' + bits + ' unknown bits per key');
    const flow = (st) => {
      const Nn = F().net('mmf'), y = 94;
      Nn.chip('p', 'P₁ ' + hx(P1.p), [110, y], 'plain');
      Nn.box('e1', 300, y, 116, 52, ['E', 'K₁ = ?'], 'cipher' + (st === 'forward' ? ' act' : ''), { size: 15 });
      Nn.chip('m', st === 'hit' || st === 'confirm' || st === 'end' ? target : 'middle', [460, y], st === 'hit' ? 'hot' : 'plain');
      Nn.box('e2', 620, y, 116, 52, ['E', 'K₂ = ?'], 'cipher' + (st === 'back' || st === 'hit' ? ' act' : ''), { size: 15 });
      Nn.chip('c', 'C₁ ' + hx(P1.c), [810, y], 'plain');
      Nn.wire('a', [[194, y], Nn.port('e1', 'w')], { head: true });
      Nn.wire('b', [Nn.port('e1', 'e'), [394, y]], { head: true, cls: st === 'forward' ? 'act' : '' });
      Nn.wire('c', [[526, y], Nn.port('e2', 'w')], { head: true });
      Nn.wire('d', [Nn.port('e2', 'e'), [726, y]], { head: true });
      Nn.label('fw', 380, 140, '→ forward from P₁', st === 'forward' || st === 'sorted' ? 'act' : 'tick', 'middle', 13);
      Nn.label('bw', 540, 140, 'back from C₁ ←', st === 'back' || st === 'hit' ? 'act' : 'tick', 'middle', 13);
      return Nn.items;
    };
    // the forward table: rows of K1 and the middle value
    const table = (rows, title, lit) => {
      const items = [...U.panel('mm:t', 24, 170, 430, 330, title)];
      items.push(U.t('mm:th1', 44, 218, 'K₁', 'tick', 'start', 13), U.t('mm:th2', 140, 218, 'E_K₁(P₁)', 'tick', 'start', 13));
      rows.forEach((r, i) => {
        const y = 232 + i * 32, on = lit !== undefined && r && r.v === lit;
        if (!r) { items.push(U.t('mm:dots' + i, 140, y + 20, '⋮', 'tick', 'start', 15)); return; }
        items.push({ key: 'mm:tk' + i, kind: 'cell', x: 40, y, w: 80, h: 26, rx: 3, text: String(r.v), size: 14, cls: 'hex ' + (on ? 'hot' : 'key') });
        items.push({ key: 'mm:tm' + i, kind: 'cell', x: 130, y, w: 200, h: 26, rx: 3, text: r.m, size: 14, cls: 'hex ' + (on ? 'hot' : '') });
      });
      if (rows.length && rows[0] && rows.length > 5) items.push(U.t('mm:tn', 44, 484, 'rows ' + (lo + 1) + '–' + (lo + rows.length) + ' of ' + N + ' (sorted)', 'tick', 'start', 13));
      else if (rows.length) items.push(U.t('mm:tn', 44, 484, '… ' + N + ' rows in all', 'tick', 'start', 13));
      return items;
    };
    const backPanel = (rows) => {
      const items = [...U.panel('mm:b', 470, 170, 426, 330, 'backward: decrypt C₁ under each K₂')];
      items.push(U.t('mm:bh1', 490, 218, 'K₂', 'tick', 'start', 13), U.t('mm:bh2', 586, 218, 'D_K₂(C₁)', 'tick', 'start', 13), U.t('mm:bh3', 880, 218, 'in table?', 'tick', 'end', 13));
      rows.forEach((r, i) => {
        const y = 232 + i * 32;
        items.push({ key: 'mm:bk' + i, kind: 'cell', x: 486, y, w: 80, h: 26, rx: 3, text: String(r.v), size: 14, cls: 'hex ' + (r.hit ? 'hot' : 'key') });
        items.push({ key: 'mm:bm' + i, kind: 'cell', x: 576, y, w: 200, h: 26, rx: 3, text: r.m, size: 14, cls: 'hex ' + (r.hit ? 'hot' : '') });
        items.push(U.t('mm:bx' + i, 880, y + 19, r.hit ? 'yes: K₁ = ' + r.k1 : 'no', r.hit ? 'hot' : 'tick', 'end', 14));
      });
      return items;
    };
    const firstRows = fwd.slice(0, 4);
    const at = sorted.findIndex((r) => r.v === found.k1v), lo = Math.max(0, Math.min(at - 3, N - 7)), win = sorted.slice(lo, lo + 7);
    const missRows = misses.map((v) => ({ v, m: back(v) }));
    const hitRows = missRows.concat([{ v: found.k2v, m: target, hit: true, k1: found.k1v }]);
    const footer = (txt, cls) => [U.t('mm:f', 24, 540, txt, cls || 'tick', 'start', 15)];
    Fr.add({ items: [head, ...flow('start'), ...table([], 'forward table (empty)'), ...backPanel([]), ...footer(`known pairs: ${hx(P1.p)} → ${hx(P1.c)} and ${hx(P2.p)} → ${hx(P2.c)}`)], hl: { d: [0] }, say: `Double DES encrypts twice, C = E_K₂(E_K₁(P)). Here each key has ${bits} unknown bits, ${N} values, so trying every pair of keys would take ${U.big(N * N)} double encryptions. We know two plaintext–ciphertext pairs.`, facts: { bits, N, NN: U.big(N * N), p1: hx(P1.p), c1: hx(P1.c), p2: hx(P2.p), c2: hx(P2.c) }, meta: { stage: 'start' } });
    Fr.add({ items: [head, ...flow('forward'), ...table(firstRows.concat([null]), 'forward table, filling'), ...backPanel([]), ...footer(`${N} encryptions of P₁, one per K₁`, 'act')], hl: { d: [1] }, say: `Forward: encrypt P₁ under every K₁ and store each middle value: K₁ = ${firstRows.map((r) => r.v + ' gives ' + r.m).slice(0, 2).join(', ')}, and so on for all ${N} values.`, facts: { rows: firstRows.slice(0, 2).map((r) => [r.v, r.m]), N }, meta: { stage: 'forward' } });
    Fr.add({ items: [head, ...flow('sorted'), ...table(win, 'forward table, sorted by middle value'), ...backPanel([]), ...footer(`${N} rows, sorted so a lookup is fast`, 'act')], say: `The ${N} rows are sorted by middle value (a hash table would do as well), so any middle value can be looked up at once. This table is the memory the attack pays: ${N} entries.`, facts: { N }, meta: { stage: 'sorted' } });
    Fr.add({ items: [head, ...flow('back'), ...table(win, 'forward table, sorted by middle value'), ...backPanel(missRows), ...footer('each K₂ costs one decryption and one lookup', 'act')], hl: { d: [2] }, say: `Backward: decrypt C₁ under each K₂ and look the result up. K₂ = ${missRows.map((r) => r.v).join(', ')} give ${missRows.map((r) => r.m).join(', ')}: none of them is in the table, so none can be right.`, facts: { misses: missRows.map((r) => [r.v, r.m]) }, meta: { stage: 'back' } });
    Fr.add({ items: [head, ...flow('hit'), ...table(win, 'forward table, sorted by middle value', found.k1v), ...backPanel(hitRows), ...footer('the two halves meet', 'hot')], say: `K₂ = ${found.k2v} decrypts C₁ to ${target}, and the table has that middle value at K₁ = ${found.k1v}: P₁ encrypted under K₁ meets C₁ decrypted under K₂. The pair (K₁, K₂) = (${found.k1v}, ${found.k2v}) is a candidate.`, facts: { k1: found.k1v, k2: found.k2v, m: target }, meta: { stage: 'hit' } });
    const c2 = S.MITM.double(P2.p, kf(found.k1v), kf(found.k2v)), ok = S.bytes.eq(c2, P2.c), cands = res.candidates.length, falses = res.candidates.filter((c) => !c.ok).length;
    Fr.add({ items: [head, ...flow('confirm'), ...table(win, 'forward table, sorted by middle value', found.k1v), ...backPanel(hitRows), ...footer(`check: E_K₂(E_K₁(P₂)) = ${hx(c2)} ${ok ? '= C₂' : '≠ C₂'}`, ok ? 'act' : 'bad')], say: `A middle value of 64 bits can match by chance, so the second pair decides: double encryption of P₂ under (${found.k1v}, ${found.k2v}) gives ${hx(c2)}, ${ok ? 'which is C₂' : 'which is not C₂'}. In all, the lookups found ${U.plural(cands, 'candidate')}, ${falses} of them false.`, facts: { c2: hx(c2), ok, cands, falses, k: [found.k1v, found.k2v] }, meta: { stage: 'confirm' } });
    const work = 2 * N;
    Fr.add({ items: [head, ...flow('end'), ...table(win, 'forward table, sorted by middle value', found.k1v), ...backPanel(hitRows), ...footer(`work ${U.big(work)} DES operations + ${U.big(N)} rows, against ${U.big(N * N)}`, 'hot')], say: `The attack cost ${U.big(work)} DES operations and a table of ${U.big(N)} entries instead of ${U.big(N * N)} double encryptions. For real double DES that is about 2⁵⁷ operations and 2⁵⁶ entries instead of 2¹¹²: two keys bought one bit of strength. False alarms are expected there (2¹¹² key pairs, 64-bit middle values leave about 2⁴⁸), which is why a second pair is checked.`, facts: { work: U.big(work), N: U.big(N), NN: U.big(N * N) }, meta: { stage: 'end' } });
    U.fix(Fr.list, { x: 0, y: 0, w: 920, h: 560 });
    return { frames: Fr.list, def: U.def('Meet in the middle', ['C = E_K₂(E_K₁(P))', 'forward: table of E_K₁(P₁) for every K₁', 'backward: D_K₂(C₁) for every K₂, look it up', 'a hit is a candidate; a second pair confirms', 'work 2·2ᵏ, memory 2ᵏ, instead of 2²ᵏ']) };
  }
  S.topic({
    id: 'des-mitm', family: 'p04-weak', order: 30, title: 'Double DES, met in the middle',
    blurb: 'Encrypting twice with two keys should square the work of a search, but it does not: encrypt forward from the plaintext, decrypt backward from the ciphertext, and wait for the two to meet in a table.',
    inputs: [{ id: 'bits', kind: 'number', label: 'Unknown bits per key', def: 8, min: 4, max: 10 }, { id: 'seed', kind: 'number', label: 'Secret (seed)', def: 3, min: 1, max: 999 }],
    presets: [{ label: '8 bits, secret 3', values: { bits: 8, seed: 3 } }, { label: '6 bits', values: { bits: 6, seed: 11 } }, { label: '10 bits', values: { bits: 10, seed: 7 } }, { label: '4 bits', values: { bits: 4, seed: 5 } }],
    run: mitm,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'back', once: true, pick: 'option', options: ['2 × 2ᵏ', '2²ᵏ', '2ᵏ⁺¹ squared'], ask: 'With k unknown bits per key, about how many DES operations does the whole attack need?', answer: '2 × 2ᵏ', explain: 'One encryption per K₁ forward and one decryption per K₂ backward.' }],
    quiz: [
      { q: 'Why is double DES not 112 bits strong?', options: ['Its keys overlap', 'Meet in the middle finds the keys with about 2⁵⁷ operations and 2⁵⁶ memory', 'DES is a group', 'The second encryption cancels the first'], answer: 1, why: 'The two encryptions can be attacked separately and joined in a table.' },
      { q: 'What does the forward table store?', options: ['E_K₁(P₁) for every K₁', 'Every pair of keys', 'The ciphertexts', 'D_K₂(C₁) for every K₂'], answer: 0, why: 'The middle values from the plaintext side, indexed for lookup.' },
      { q: 'Why check a second plaintext–ciphertext pair?', options: ['To find K₂', 'Some wrong key pairs meet in the middle by chance: about 2¹¹²/2⁶⁴ = 2⁴⁸ for real DES', 'To sort the table', 'It is not needed'], answer: 1, why: 'A second pair leaves about 2⁴⁸/2⁶⁴, far below one false key pair.' },
      { q: 'What does meet in the middle trade?', options: ['Time for memory', 'Keys for plaintexts', 'Rounds for S-boxes', 'Nothing'], answer: 0, why: 'A table of 2ᵏ entries replaces 2ᵏ times as much work.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // 3DES (EDE) and DESX
  // ---------------------------------------------------------------------------------------------------------------
  function tdes(inp) {
    const v = inp.variant, p = U.fromHex(inp.plain), K = U.fromHex(inp.key), k1 = K.slice(0, 8), k2 = K.slice(8, 16), k3 = K.slice(16, 24);
    const desx = v === 'desx';
    let keys, steps, out, name;
    if (desx) {
      const a = S.bytes.xor(p, k2), b = desE(k1).encrypt(a), c = S.bytes.xor(b, k3);
      out = S.DESX.encrypt(p, k1, k2, k3).out;
      steps = [a, b, c]; keys = [k2, k1, k3]; name = 'DESX';
    } else {
      const kk = v === 'ede2' ? K.slice(0, 16) : v === 'ede3' ? K : Uint8Array.from([...k1, ...k1, ...k1]);
      const r = S.TDES.encrypt(p, kk);
      out = r.out; steps = r.steps; keys = [kk.slice(0, 8), kk.slice(8, 16), kk.length === 24 ? kk.slice(16, 24) : kk.slice(0, 8)];
      name = v === 'ede2' ? 'two-key 3DES' : v === 'ede3' ? 'three-key 3DES' : '3DES with K₁ = K₂ = K₃';
    }
    const single = hx(desE(k1).encrypt(p));
    const labels = desx ? [['⊕', 'K₁'], ['DES', 'K'], ['⊕', 'K₂']] : [['E', 'K₁'], ['D', 'K₂'], ['E', 'K₃']];
    const Fr = new S.Frames();
    const head = U.head('td:h', name[0].toUpperCase() + name.slice(1) + (desx ? ': C = K₂ ⊕ DES_K(P ⊕ K₁)' : ': C = E_K₃(D_K₂(E_K₁(P)))'));
    const flow = (st) => {
      const N = F().net('tdf'), y = 230, xs = [250, 460, 670];
      N.chip('p', hx(p), [90, y], st === 0 ? 'act' : 'plain');
      xs.forEach((x, i) => {
        const on = st === i + 1;
        if (desx && i !== 1) N.op('b' + i, x, y, 'xor', on ? 'act' : '', 16);
        else N.box('b' + i, x, y, 104, 56, labels[i][0] === 'DES' ? 'DES' : labels[i][0] === 'E' ? 'encrypt' : 'decrypt', 'cipher' + (on ? ' act' : ''));
        const kx = x, ky = 120;
        N.chip('k' + i, labels[i][1] + ' ' + hx(keys[i]), [kx, ky], 'key');
        N.wire('kw' + i, [[kx, ky + 14], N.port('b' + i, 'n')], { head: true, cls: 'key' });
        if (st > i) N.chip('s' + i, hx(steps[i]), i === 2 ? [842, y] : [x + 105, y + 50], on ? (i === 2 ? 'hot' : 'act') : 'plain');
      });
      N.wire('w0', [[164, y], N.port('b0', 'w')], { head: true });
      N.wire('w1', [N.port('b0', 'e'), N.port('b1', 'w')], { head: true, cls: st === 1 ? 'act' : '' });
      N.wire('w2', [N.port('b1', 'e'), N.port('b2', 'w')], { head: true, cls: st === 2 ? 'act' : '' });
      N.wire('w3', [N.port('b2', 'e'), [766, y]], { head: true, cls: st === 3 ? 'act' : '' });
      return N.items;
    };
    const mine = { compat: 0, ede2: 1, ede3: 2, desx: 3 }[v];
    const table = () => U.readout('td:s', 24, 360, 872, 'key bits and strength', [
      ['single DES', '56 key bits, about 56 bits of strength'],
      ['two-key 3DES (K₃ = K₁)', '112 key bits, about 80 bits (NIST SP 800-57)'],
      ['three-key 3DES', '168 key bits, 112 bits: meet in the middle'],
      ['DESX', '184 key bits, at least 119 − log₂(texts) bits'],
    ].map((r, j) => r.concat([j === mine ? 'hot' : ''])), { dy: 34, size: 14, vsize: 14 });
    const kw = desx ? 'K₁ ' + hx(k2) + ', K ' + hx(k1) + ', K₂ ' + hx(k3) : 'K₁ ' + hx(keys[0]) + ', K₂ ' + hx(keys[1]) + ', K₃ ' + hx(keys[2]);
    Fr.add({ items: [head, ...flow(0), ...table()], hl: { d: desx ? [3] : [0] }, say: desx ? `DESX wraps one DES encryption in two XORs with extra 64-bit keys: C = K₂ ⊕ DES_K(P ⊕ K₁). Here ${kw}. The whitening costs almost nothing and blocks a plain key search.` : `${name[0].toUpperCase() + name.slice(1)} runs DES three times, encrypt, decrypt, encrypt (EDE): C = E_K₃(D_K₂(E_K₁(P))). Here ${kw}.` + (v === 'ede2' ? ' The two-key version reuses K₁ as K₃.' : ''), facts: { keys: keys.map(hx), name, width: 64 }, meta: { stage: 'start' } });
    for (let i = 0; i < 3; i++) {
      const what = desx ? (i === 0 ? `Pre-whitening: ${hx(p)} ⊕ ${hx(keys[0])} = ${hx(steps[0])}.` : i === 1 ? `One DES encryption under K = ${hx(keys[1])}: ${hx(steps[1])}.` : `Post-whitening: ${hx(steps[1])} ⊕ ${hx(keys[2])} = ${hx(steps[2])}, the ciphertext.`)
        : (i === 0 ? `Encrypt ${hx(p)} under K₁ = ${hx(keys[0])}: ${hx(steps[0])}.` : i === 1 ? `Decrypt that under K₂ = ${hx(keys[1])}: ${hx(steps[1])}.` + (v === 'compat' ? ' K₂ = K₁, so this undoes the first step: the plaintext is back.' : ' With a different key, decrypting scrambles just as encrypting does.') : `Encrypt under K₃ = ${hx(keys[2])}: the ciphertext ${hx(steps[2])}.` + (v === 'compat' ? ` That equals single DES under K₁, ${single}: EDE with equal keys talks to old single-DES equipment.` : ''));
      Fr.add({ items: [head, ...flow(i + 1), ...table()], hl: { d: desx ? [3] : [i === 1 ? 1 : 0] }, say: what, facts: { s: hx(steps[i]), prev: i ? hx(steps[i - 1]) : hx(p), k: hx(keys[i]), single }, meta: { stage: 's' + (i + 1), back: v === 'compat' && i === 1 } });
    }
    Fr.add({ items: [head, ...flow(3), ...table()], hl: { d: [2] }, say: `The ciphertext is ${hx(out)}. ` + (desx ? 'An attacker must now guess K and both whitening keys together; its designers proved that a key search needs about 2¹¹⁹ ÷ m work when the attacker holds m plaintext–ciphertext pairs (56 + 64 − 1 = 119), and attacks of about that cost are known.' : v === 'ede3' ? 'Three independent keys give 168 key bits, but meet in the middle splits the three stages into one and two, so the strength is about 112 bits.' : v === 'ede2' ? 'Two keys give 112 key bits; with many known plaintexts the best attacks bring it to about 80 bits, so two-key 3DES has been retired.' : 'With all three keys equal it is single DES: compatible, and exactly as weak.'), facts: { out: hx(out) }, meta: { stage: 'end' } });
    U.fix(Fr.list, { x: 0, y: 0, w: 920, h: 560 });
    return { frames: Fr.list, def: U.def('3DES and DESX', ['3DES (EDE): C = E_K₃(D_K₂(E_K₁(P)))', 'two-key: K₃ = K₁', 'K₁ = K₂: the first two steps cancel, single DES', 'DESX: C = K₂ ⊕ DES_K(P ⊕ K₁)']) };
  }
  const tdesKey = '6b65737472656c21' + '6d61726c696e2d37' + '7069706572626f78';
  S.topic({
    id: 'des-3des', family: 'p04-weak', order: 40, title: '3DES and DESX',
    blurb: 'Two ways to stretch DES. 3DES runs it three times, encrypt, decrypt, encrypt, so that equal keys fall back to single DES; DESX XORs a key in before and after, nearly for free.',
    inputs: [U.choice('variant', 'Construction', 'ede2', [['ede2', '3DES, two keys'], ['ede3', '3DES, three keys'], ['compat', '3DES with K₁ = K₂ = K₃'], ['desx', 'DESX']]), hexIn('plain', 'Plaintext (8 bytes)', '74696465706f6f6c', 8), hexIn('key', 'Keys K₁ K₂ K₃ (24 bytes)', tdesKey, 24)],
    presets: [{ label: 'Two-key 3DES', values: { variant: 'ede2' } }, { label: 'Three-key 3DES', values: { variant: 'ede3' } }, { label: 'Equal keys: single DES', values: { variant: 'compat' } }, { label: 'DESX', values: { variant: 'desx' } }, { label: 'Three-key, other plaintext', values: { variant: 'ede3', plain: '6d61726b65727321' } }],
    run: tdes,
    predict: [{ at: (f) => f.meta && f.meta.stage === 's1', once: true, pick: 'option', options: ['the plaintext', 'a new block'], ask: 'The middle step decrypts under K₂. What will come out?', answer: (fr, i) => (fr[i + 1].meta.back ? 'the plaintext' : 'a new block'), explain: 'Decrypting under the same key as the first step undoes it; under another key it scrambles further.' }],
    quiz: [
      { q: 'Why is the middle step of 3DES a decryption?', options: ['Decryption is faster', 'With K₁ = K₂ it cancels the first step, so 3DES can talk to single DES', 'It makes the cipher a group', 'It removes weak keys'], answer: 1, why: 'EDE with equal keys is exactly single DES.' },
      { q: 'Why does three-key 3DES give about 112 bits of strength, not 168?', options: ['Parity bits', 'Meet in the middle against one stage and two stages', 'The middle step cancels', 'Weak keys'], answer: 1, why: 'Tabulate one side, search the other two keys: about 2¹¹² work.' },
      { q: 'DESX computes…', options: ['K₂ ⊕ DES_K(P ⊕ K₁)', 'DES_K₂(DES_K₁(P))', 'DES_K(P) ⊕ P', 'DES_K(P ⊕ K)'], answer: 0, why: 'Whitening keys are XORed in before and after one DES.' },
      { q: 'Why does whitening stop a plain exhaustive search on DESX?', options: ['Each trial key K must be paired with unknown 64-bit whitening keys', 'It adds rounds', 'It changes the S-boxes', 'It does not'], answer: 0, why: 'A guess of K alone cannot be tested without also knowing K₁ and K₂.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
