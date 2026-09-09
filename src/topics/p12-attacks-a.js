// Part 12, attack labs on a cut-down hash: the birthday attack (a table of every digest seen, run in slices of work
// as a page would run it), and Pollard's rho, which finds the same kind of collision with no table at all by walking
// x → H(x) until the walk bites its own tail.
(function (S) {
  'use strict';
  const U = S.P12, H = () => S.Hash;
  const { t } = U;

  // ---------------------------------------------------------------------------------------------------------------
  // the birthday attack, in slices
  // ---------------------------------------------------------------------------------------------------------------
  function bday(inp) {
    const Hs = H(), bits = +inp.bits, seed = +inp.seed, N = 2 ** bits;
    // run the engine's generator to the end, counting the slices of work it hands back
    const g = Hs.birthdaySteps({ hash: 'sha256', bits, seed });
    let res, slices = 0;
    for (;;) { const r = g.next(); if (r.done) { res = r.value; break; } slices++; }
    const sha = (m) => Hs.get('sha256').hash(m), cut = (m) => Hs.truncate(sha(m), bits);
    const A = U.text(res.a), B = U.text(res.b);
    // the engine's notes differ only in their counter; rebuild the ones before the hit for the picture
    const noteOf = (i) => U.utf8(A.replace(/-\d+:/, '-' + i + ':'));
    const iA = +A.match(/-(\d+):/)[1];
    const COLS = 96, ROWS = 40, cells = COLS * ROWS, cellOf = (v) => Math.floor((v / N) * cells);
    const vals = Array.from({ length: res.tries }, (_, i) => cut(noteOf(i)));
    const map = (k, hit) => {
      const rows = Array.from({ length: ROWS }, () => new Array(COLS).fill('0'));
      for (let i = 0; i < k; i++) { const c = cellOf(vals[i]); rows[Math.floor(c / COLS)][c % COLS] = '1'; }
      if (hit) { const c = cellOf(res.digestA ? Hs.truncate(res.digestA, bits) : vals[iA]); rows[Math.floor(c / COLS)][c % COLS] = '2'; }
      return { key: 'ba:map', kind: 'bitmap', x: 30, y: 96, cw: 6, ch: 6, gap: 1, rows: rows.map((r) => r.join('')) };
    };
    const xMax = Math.max(res.tries, res.expected) * 1.6;
    const pl = U.plot({ prefix: 'bp', x: 640, y: 120, w: 250, h: 170, xr: [0, xMax], yr: [0, 1], yticks: [0, 0.5, 1], fy: (v) => U.fx(v, 1), xticks: [], xlabel: 'digests stored', ylabel: 'chance a collision has turned up', tickSize: 13, grid: true });
    const xs = [], ys = [];
    for (let k = 0; k <= 80; k++) { xs.push((xMax * k) / 80); ys.push(Hs.birthdayProb((xMax * k) / 80, N)); }
    const curve = (k) => [...pl.items, U.line(pl, 'bp:c', xs, ys, 'soft'), { key: 'bp:e', kind: 'path', d: `M${pl.X(res.expected)},${pl.Y(0)} V${pl.Y(1)}`, cls: 'p12-line dash', audit: 'ignore' }, t('bp:et', pl.X(res.expected) + 5, pl.Y(1) + 12, 'expected', 'act', 'start', 13), { key: 'bp:k', kind: 'dot', x: pl.X(k), y: pl.Y(Hs.birthdayProb(k, N)), r: 6, cls: 'hot', audit: 'point', layer: 'top' }];
    const panel = (k, hit) => U.readout('ba:r', 640, 340, 250, hit ? 'collision found' : 'work so far', [
      ['messages hashed', U.commas(k), hit ? 'hot' : ''],
      ['expected √(πN/2)', U.commas(Math.round(res.expected))],
      ['share of the estimate', Math.round((100 * k) / res.expected) + '%'],
      ['table size', U.commas(hit ? res.stored : k) + ' digests'],
    ], { dy: 30 });
    const head = U.head('ba:h', 'Birthday attack on SHA-256 cut to ' + bits + ' bits', 'each cell is a stretch of the ' + U.commas(N) + ' digests; it lights when a stored digest falls in it');
    const F = new S.Frames(['hashed', 'stored']);
    F.add({ items: [...head, map(0), ...curve(0), ...panel(0, false)], hl: { d: [0] }, say: `The attacker wants any two messages whose SHA-256 digests agree in the first ${bits} bits. There are ${U.commas(N)} such digests, but a collision should turn up after about √(πN/2) ≈ ${U.commas(Math.round(res.expected))} messages: hash notes that differ in a counter, and store each digest in a table.`, facts: { bits, N, expected: Math.round(res.expected) }, meta: { stage: 'start' } });
    for (const f of [0.15, 0.4, 0.7, 0.92]) {
      const k = Math.max(1, Math.floor(f * res.tries));
      if (k >= res.tries) continue;
      F.set('hashed', k).set('stored', k);
      F.add({ items: [...head, map(k), ...curve(k), ...panel(k, false)], hl: { d: [1] }, say: `${U.commas(k)} notes hashed and stored, no two alike yet. Each new digest is looked up in the table: with ${U.commas(k)} stored, the next one collides with chance about ${U.commas(k)}/${U.commas(N)}, and that chance keeps growing.`, facts: { k, N }, meta: { stage: 'work', k } });
    }
    F.set('hashed', res.tries).set('stored', res.stored);
    const dA = U.hex(res.digestA), dB = U.hex(res.digestB), hx = res.value;
    const pair = () => {
      const items = [t('ba:pt', 30, 412, 'the colliding pair', 'ptitle')];
      [[A, dA], [B, dB]].forEach(([m, d], j) => {
        items.push({ key: 'ba:m' + j, kind: 'cell', x: 30, y: 424 + j * 64, w: 580, h: 26, rx: 4, text: '“' + m + '”', size: 13, cls: 'mono ' + (j ? 'hot' : 'act') });
        items.push(t('ba:d' + j, 30, 470 + j * 64, d.slice(0, Math.ceil(bits / 4)), 'mono hot', 'start', 14), t('ba:e' + j, 30 + Math.ceil(bits / 4) * 9.2, 470 + j * 64, d.slice(Math.ceil(bits / 4), 52) + '…', 'mono', 'start', 14));
      });
      return items;
    };
    F.add({ items: [...head, map(res.tries, true), ...curve(res.tries), ...panel(res.tries, true), ...pair()], hl: { d: [2] }, say: `Message ${U.commas(res.tries)}, “${B}”, has the ${bits}-bit digest ${hx}, already in the table from “${A}”: a collision after ${U.commas(res.tries)} hashes, ${Math.round((100 * res.tries) / res.expected)}% of the estimate. The full digests agree only in their first ${bits} bits.`, facts: { tries: res.tries, value: hx, pct: Math.round((100 * res.tries) / res.expected), dA, dB, bits, a: A, b: B }, meta: { stage: 'hit' } });
    const bytes = res.stored * (Math.ceil(bits / 8) + 4);
    F.add({ items: [...head, map(res.tries, true), ...curve(res.tries), ...panel(res.tries, true), ...pair()], hl: { d: [3] }, say: `The price was memory: ${U.commas(res.stored)} digests stored, about ${U.commas(bytes)} bytes. ${slices ? `The engine handed its work back in ${U.plural(slices, 'slice')} of 4,096 hashes, so a page can run it without freezing.` : 'The work was so small that the engine needed no slices of 4,096 hashes.'} Each extra 2 bits of digest doubles the work: for the full 256 bits it is 2¹²⁸.`, facts: { stored: res.stored, bytes, slices, slice: 4096 }, meta: { stage: 'cost' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('The birthday attack', ['repeat: pick a new message m, compute y = H(m)', 'if y is in the table: collision (m, table[y])', 'else store table[y] = m', 'expected messages ≈ √(πN/2) ≈ 1.25·2ⁿᐟ²', 'memory: as many digests as messages']) };
  }
  S.topic({
    id: 'p12-bday-attack', family: 'p12-attacks', order: 10, title: 'Attack lab: birthday collisions on a truncated hash',
    blurb: 'Hash note after note, keep every digest in a table, and wait for a repeat. On SHA-256 cut to n bits, a collision comes after about 2ⁿᐟ² notes, and the table is the price.',
    inputs: [
      { id: 'bits', kind: 'choice', label: 'Digest cut to', def: '24', options: ['16', '20', '24', '28', '32'].map((v) => ({ value: v, label: v + ' bits' })) },
      { id: 'seed', kind: 'number', label: 'Seed', def: 1, min: 1, max: 999 },
    ],
    presets: [
      { label: '24 bits', values: { bits: '24', seed: 1 } },
      { label: '16 bits', values: { bits: '16', seed: 2 } },
      { label: '32 bits: about 82,000 hashes', values: { bits: '32', seed: 3 } },
    ],
    counters: [{ id: 'hashed', label: 'hashed' }, { id: 'stored', label: 'stored' }],
    run: bday,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'start', pick: 'option', options: ['about 2ⁿ', 'about 2ⁿᐟ²', 'about n²'], ask: 'About how many messages until two share an n-bit digest?', answer: 'about 2ⁿᐟ²', explain: 'Pairs grow with the square of the count: the birthday bound.' }],
    quiz: [
      { q: 'What does the birthday attack need besides time?', options: ['nothing', 'memory for every digest seen', 'the key', 'a second preimage'], answer: 1, why: 'A table of about 2ⁿᐟ² digests (rho avoids it).' },
      { q: 'Cutting a digest from 32 to 24 bits makes collisions about … times cheaper.', options: ['2', '16', '256', '8'], answer: 1, why: 'The work is 2^(n/2): 2^16 versus 2^12, a factor of 16.' },
      { q: 'Why does a 64-bit tag or digest not resist collisions?', options: ['it does', '2^32 messages, a few seconds of work, give a collision', 'it is too slow', 'only for MD5'], answer: 1, why: 'The birthday bound for 64 bits is 2^32.' },
      { q: 'Does this attack let you collide with a given message?', options: ['yes', 'no: both messages come out of the search; a given target needs about 2ⁿ', 'only for short messages', 'only with MD5'], answer: 1, why: 'That would be a second preimage, with no birthday shortcut.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // rho
  // ---------------------------------------------------------------------------------------------------------------
  function rho(inp) {
    const Hs = H(), bits = +inp.bits, seed = +inp.seed;
    const r = Hs.rho({ hash: 'sha256', bits, seed });
    const hx = (v) => Hs.truncHex(v, bits), path = r.path, mu = r.mu, lam = r.lambda;
    const idx = (k) => (k < mu ? k : mu + ((k - mu) % lam));
    // where each point of the walk sits: the tail on a slanted line, the cycle on a circle
    const cx = 590, cy = 300, R = 180, entryAng = Math.PI / 2 + 0.5;
    const tailStart = { x: 80, y: 600 }, entry = { x: cx + R * Math.cos(entryAng), y: cy + R * Math.sin(entryAng) };
    const at = (i) => {
      if (i < mu) { const f = mu > 1 ? i / mu : 0; return { x: U.r2(tailStart.x + (entry.x - tailStart.x) * f), y: U.r2(tailStart.y + (entry.y - tailStart.y) * f) }; }
      const a = entryAng - (2 * Math.PI * (i - mu)) / lam;
      return { x: U.r2(cx + R * Math.cos(a)), y: U.r2(cy + R * Math.sin(a)) };
    };
    const base = () => {
      const items = [{ key: 'rh:tail', kind: 'path', d: `M${tailStart.x},${tailStart.y} L${U.r2(entry.x)},${U.r2(entry.y)}`, cls: 'p12-line faint', audit: 'ignore' }, { key: 'rh:cyc', kind: 'path', d: `M${cx + R},${cy} A${R},${R} 0 1 1 ${cx - R},${cy} A${R},${R} 0 1 1 ${cx + R},${cy}`, cls: 'p12-line faint', audit: 'ignore' }];
      if (mu + lam <= 160) for (let i = 0; i < mu + lam; i++) { const p = at(i); items.push({ key: 'rh:p' + i, kind: 'dot', x: p.x, y: p.y, r: 2.6, cls: '', audit: 'ignore' }); }
      items.push(t('rh:tl', 96, 640, 'tail: ' + U.plural(mu, 'step'), 'ptick', 'start', 13), t('rh:cl', cx, cy + 6, 'cycle: ' + U.plural(lam, 'point'), 'ptick', 'middle', 14));
      return items;
    };
    const tok = (key, i, cls, label, dy, left) => { const p = at(idx(i)); return [{ key, kind: 'dot', x: p.x, y: p.y, r: 8, cls, layer: 'top', audit: 'overlap-ok' }, t(key + ':l', p.x + (left ? -14 : 14), p.y + (dy || -10), label, cls, left ? 'end' : 'start', 13)]; };
    const head = U.head('rh:h', 'Rho on SHA-256 cut to ' + bits + ' bits', 'walk x → H(x); the walk must repeat, and where it joins its loop is a collision');
    // the first meeting of tortoise (i) and hare (2i)
    let m = 1; while (path[idx(m)] !== path[idx(2 * m)]) m++;
    const F = new S.Frames(['calls']);
    const x0 = path[0];
    F.add({ items: [...head, ...base(), ...tok('rh:s', 0, 'act', 'start ' + hx(x0), 18)], hl: { d: [0] }, say: `Start from ${hx(x0)} and walk: each step hashes the current ${bits}-bit value (as a short text) and keeps the first ${bits} bits. There are only ${U.commas(2 ** bits)} values, so the walk must come back to one it has seen, after about √N steps: a ρ shape, a tail and a loop.`, facts: { x0: hx(x0), N: 2 ** bits, bits }, meta: { stage: 'start' } });
    for (const f of [0.35, 0.7]) {
      const i = Math.max(1, Math.floor(m * f));
      if (i >= m) continue;
      F.set('calls', 3 * i);
      F.add({ items: [...head, ...base(), ...tok('rh:t', i, 'act', 'tortoise'), ...tok('rh:r', 2 * i, 'hot', 'hare', 22)], hl: { d: [1] }, say: `Floyd's trick: a tortoise takes one step at a time, a hare two. After ${i} steps the tortoise is at ${hx(path[idx(i)])} and the hare at ${hx(path[idx(2 * i)])}. Only these two values are kept, nothing else.`, facts: { i, tv: hx(path[idx(i)]), hv: hx(path[idx(2 * i)]), bits }, meta: { stage: 'walk' } });
    }
    F.set('calls', 3 * m);
    F.add({ items: [...head, ...base(), ...tok('rh:t', m, 'act', 'tortoise'), ...tok('rh:r', 2 * m, 'hot', 'hare', 22)], hl: { d: [1] }, say: `After ${m} steps they meet at ${hx(path[idx(m)])}: once both are on the loop, the hare gains one place per step and must catch up. The walk has looped.`, facts: { m, v: hx(path[idx(m)]), bits }, meta: { stage: 'meet' } });
    const pa = path[mu - 1], pb = path[mu + lam - 1], v = path[mu];
    F.set('calls', r.evals);
    F.add({ items: [...head, ...base(), ...tok('rh:a', mu - 1, 'act', hx(pa) + ' (tail)', 4, true), ...tok('rh:b', mu + lam - 1, 'key', hx(pb) + ' (loop)', -12), ...tok('rh:v', mu, 'hot', 'join: ' + hx(v), 28)], hl: { d: [2] }, say: `Send the tortoise back to the start and step both one at a time; they reach the join together, ${hx(v)}, after ${mu} steps. Its two predecessors, ${hx(pa)} on the tail and ${hx(pb)} on the loop, are different inputs with the same ${bits}-bit digest ${hx(v)}.`, facts: { mu, v: hx(v), pa: hx(pa), pb: hx(pb), a: hx(r.a), b: hx(r.b), value: hx(r.value), bits, seed }, meta: { stage: 'join' } });
    const sha = (m2) => U.hex(Hs.get('sha256').hash(m2)), d = Math.ceil(bits / 4);
    const msgs = () => {
      const items = [t('rh:mt', 30, 96, 'the collision', 'ptitle')];
      [[r.ma, 'act'], [r.mb, 'key']].forEach(([mm, c], j) => {
        items.push({ key: 'rh:m' + j, kind: 'cell', x: 30, y: 108 + j * 58, w: 210, h: 26, rx: 4, text: '“' + U.text(mm) + '”', size: 13, cls: 'mono ' + c });
        items.push(t('rh:d' + j, 30, 152 + j * 58, sha(mm).slice(0, d), 'mono hot', 'start', 14), t('rh:e' + j, 30 + d * 9.2, 152 + j * 58, sha(mm).slice(d, 24) + '…', 'mono', 'start', 14));
      });
      return items;
    };
    F.add({ items: [...head, ...base(), ...tok('rh:v', mu, 'hot', 'join: ' + hx(v), 24), ...msgs()], hl: { d: [3] }, say: `As messages: “${U.text(r.ma)}” and “${U.text(r.mb)}” share the first ${bits} bits of their SHA-256 digests. ${U.commas(r.evals)} hash calls in all (tail ${mu}, loop ${lam}), against about ${U.commas(Math.round(Math.sqrt((Math.PI * 2 ** bits) / 2)))} for a birthday table, and the memory used was two values, not a table.`, facts: { evals: r.evals, mu, lam, est: Math.round(Math.sqrt((Math.PI * 2 ** bits) / 2)), bits }, meta: { stage: 'msgs' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Rho with Floyd\'s cycle finding', ['f(x) = first n bits of H(x)', 'tortoise T ← f(T), hare R ← f(f(R)) until T = R', 'T ← x₀; step both once until f(T) = f(R)', 'then T ≠ R and f(T) = f(R): a collision', 'time ≈ √N, memory: two values']) };
  }
  S.topic({
    id: 'p12-rho', family: 'p12-attacks', order: 20, title: 'Attack lab: rho collisions with no memory',
    blurb: 'Walk x → H(x) on a cut-down hash. The walk must loop, tracing a ρ; a tortoise and a hare find the loop, and the point where the tail joins it has two different predecessors: a collision, found with two stored values.',
    inputs: [
      { id: 'bits', kind: 'choice', label: 'Digest cut to', def: '12', options: ['12', '16', '20', '24'].map((v) => ({ value: v, label: v + ' bits' })) },
      { id: 'seed', kind: 'number', label: 'Seed', def: 1, min: 1, max: 999 },
    ],
    check: (inp) => { const r = S.Hash.rho({ hash: 'sha256', bits: +inp.bits, seed: +inp.seed }); return r.found ? null : 'Seed: this walk found no collision; try another seed'; },
    presets: [
      { label: '12 bits', values: { bits: '12', seed: 1 } },
      { label: '16 bits', values: { bits: '16', seed: 4 } },
      { label: '20 bits', values: { bits: '20', seed: 1 } },
      { label: '24 bits', values: { bits: '24', seed: 2 } },
    ],
    counters: [{ id: 'calls', label: 'hash calls' }],
    run: rho,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'meet', pick: 'option', options: ['a table of every value', 'two values', 'one bit'], ask: 'How much memory does rho need to find the collision?', answer: 'two values', explain: 'The tortoise and the hare; nothing else is stored.' }],
    quiz: [
      { q: 'Why must the walk x → H(x) eventually repeat?', options: ['H is a permutation', 'there are finitely many n-bit values', 'by design of SHA-256', 'it never does'], answer: 1, why: 'Only 2ⁿ values exist, so some value comes back.' },
      { q: 'Where is the collision in the ρ?', options: ['at the start', 'where the tail joins the loop: two predecessors map to the same value', 'at the meeting point', 'nowhere'], answer: 1, why: 'The last tail point and the last loop point both map to the join.' },
      { q: 'What is rho\'s main advantage over the table-based birthday attack?', options: ['fewer hash calls', 'almost no memory', 'it finds preimages', 'it needs no hash'], answer: 1, why: 'About the same √N time, but constant memory (and it parallelises with distinguished points).' },
      { q: 'Which other attack uses the same idea?', options: ['Pollard\'s rho for discrete logarithms', 'frequency analysis', 'a padding oracle', 'CPA'], answer: 0, why: 'The same cycle finding in a group walk.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
