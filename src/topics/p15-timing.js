// Part 15, timing and caches: T-table AES, where a slow run after an eviction shows which cache line a first-round
// lookup used, which exposes the high half of every key byte, and the implementations with no secret addresses that
// stop it; a tag comparison that stops at the first wrong byte, whose timing exposes the tag, and the constant-time
// comparison that stops it; and constant-time code beside leaky code.
(function (S) {
  'use strict';
  const U = S.P14, V = S.P15, C = () => S.SC;
  const fx = U.fx, h2 = U.hex2;

  // ---------------------------------------------------------------------------------------------------------------
  // Cache timing on T-table AES
  // ---------------------------------------------------------------------------------------------------------------
  function cache(inp) {
    const key = V.key(inp.key), pt = new TextEncoder().encode(String(inp.pt).padEnd(16, '.').slice(0, 16));
    const Ca = C().Cache, one = Ca.encrypt(key, pt, { rounds: 'first' }), first = one.lookups.filter((l) => l.round === 1);
    const used = first.find((l) => l.byte === 0), unusedLine = [...Array(16).keys()].find((ln) => !first.some((l) => l.table === 0 && l.line === ln));
    const slow = Ca.encrypt(key, pt, { rounds: 'first', evict: { table: 0, line: used.line } }), fast = Ca.encrypt(key, pt, { rounds: 'first', evict: { table: 0, line: unusedLine } });
    const F = new S.Frames();
    const head = U.t('ca:h', 20, 30, 'Evict+time against T-table AES: four tables of 16 cache lines', 'strong', 'start', 16);
    const tables = (lit, evicted) => {
      const items = [];
      for (let t = 0; t < 4; t++) {
        const x = 40 + t * 112;
        items.push(U.t('ca:tn' + t, x + 46, 74, 'T' + t, 'strong', 'middle', 15));
        for (let ln = 0; ln < 16; ln++) {
          const hits = (lit || []).filter((l) => l.table === t && l.line === ln), ev = evicted && evicted.table === t && evicted.line === ln;
          items.push({ key: 'ca:c' + t + '_' + ln, kind: 'cell', x, y: 84 + ln * 28, w: 92, h: 25, rx: 3, text: hits.length ? hits.map((l) => 'b' + l.byte).join(' ') : 'line ' + ln, size: 13, cls: 'hex ' + (ev ? (hits.length ? 'bad' : 'hot') : hits.length ? 'act' : 'soft muted') });
        }
      }
      return items;
    };
    const facts0 = { pt: inp.pt, b0: h2(pt[0]), k0: h2(key[0]), idx: h2(used.index), line: used.line, un: unusedLine };
    F.add({ items: [head, ...tables(), U.t('ca:n1', 500, 100, 'Each table: 256 entries of 4 bytes = 1 KB,', 'strong', 'start', 14), U.t('ca:n2', 500, 126, '16 cache lines of 16 entries.', 'strong', 'start', 14), U.t('ca:n3', 500, 166, 'In round 1, byte i is looked up in table T(i mod 4)', 'strong', 'start', 14), U.t('ca:n4', 500, 192, 'at index pᵢ ⊕ kᵢ, which lies in line (pᵢ ⊕ kᵢ) ≫ 4.', 'strong', 'start', 14)], hl: { d: [0] }, say: 'Fast AES software merges SubBytes, ShiftRows and MixColumns into four tables of 256 four-byte entries. Each table fills 16 cache lines. Which line a lookup touches depends on the index, and in the first round the index is pᵢ ⊕ kᵢ: plaintext mixed with key.', facts: facts0, meta: { stage: 'tables' } });
    F.add({ items: [head, ...tables(first), ...U.readout('ca:r', 500, 80, 400, 'round 1 for “' + inp.pt + '”', first.slice(0, 4).map((l) => ['byte ' + l.byte + ': T' + l.table + '[' + h2(pt[l.byte]) + ' ⊕ ' + h2(key[l.byte]) + ']', 'index ' + h2(l.index) + ', line ' + l.line, 'act']).concat([['… and 12 more', '']]), { dy: 30 })], hl: { d: [1] }, say: `Encrypting “${inp.pt}”: the 16 first-round lookups touch the lit lines. Byte 0 reads T0 at ${h2(pt[0])} ⊕ ${h2(key[0])} = ${h2(used.index)}, in line ${used.line}. Lines are what the cache sees; which entry within a line, it cannot tell.`, facts: facts0, meta: { stage: 'lookups' } });
    F.add({ items: [head, ...tables(first, { table: 0, line: used.line }), ...U.readout('ca:r', 500, 80, 400, 'evict, then time one encryption', [['evict T0 line ' + used.line + ' (used)', slow.cycles + ' cycles', 'bad'], ['evict T0 line ' + unusedLine + ' (unused)', fast.cycles + ' cycles', 'good'], ['difference', String(slow.cycles - fast.cycles)]], { dy: 30 })], hl: { d: [2] }, say: `The attacker evicts one line of T0 from the cache, lets the victim encrypt, and times it. Evicting line ${used.line}, which byte 0 needs, costs a miss: ${slow.cycles} cycles. Evicting line ${unusedLine}, which no first-round lookup uses, leaves it at ${fast.cycles}. A slow run says: some byte i with i mod 4 = 0 had (pᵢ ⊕ kᵢ) ≫ 4 equal to the evicted line.`, facts: Object.assign({ slow: slow.cycles, fast: fast.cycles, diff: slow.cycles - fast.cycles, four: 4 }, facts0), meta: { stage: 'evict' } });
    // the outcome over many timed runs, checked by the engine; its per-guess scoring is not drawn
    const at = Ca.attack({ key, samples: +inp.samples, seed: +inp.seed, rounds: inp.rounds });
    const ok = at.correct.filter(Boolean).length;
    F.add({ items: [head, ...tables(), ...U.readout('ca:r', 500, 80, 400, 'over many timed encryptions', [['timed encryptions', String(+inp.samples)], ['victim', inp.rounds === 'all' ? 'all nine table rounds' : 'first round only'], ['high nibbles exposed', ok + ' of 16', ok ? 'bad' : 'good'], ['key bits exposed', String(4 * ok), ok ? 'bad' : 'good']], { dy: 30 })], hl: { d: [3] }, say: `Repeated over ${+inp.samples} timed encryptions of known plaintexts, slow runs like that one expose the high half of key bytes: here ${ok} of the 16, ${4 * ok} key bits, from the clock alone, without ever touching the victim's memory.${ok < 16 ? ' The rest are blurred by the later rounds, whose lookups also fill and evict lines; more runs would sharpen them.' : ' The low halves stay hidden in the first round, since a line holds 16 entries, but later rounds leak them the same way.'}`, facts: Object.assign({ ok, bits: 4 * ok, got: at.nibbles.map((v) => v.toString(16)).join(''), want: Array.from(key, (v) => (v >> 4).toString(16)).join(''), samples: +inp.samples }, facts0), meta: { stage: 'result', ok } });
    F.add({ items: [head, ...tables(), ...U.readout('ca:d', 500, 80, 400, 'no secret-dependent addresses', [['bitsliced AES', 'no table at all', 'good'], ['AES instructions', 'S-box in the CPU', 'good'], ['small table', 'scan every line', 'good'], ['random delays', 'average away', 'bad']], { dy: 30 })], hl: { d: [4] }, say: 'The defence is to make the memory touched independent of the key. Bitsliced AES computes the S-box with logic operations, the processor\'s AES instructions keep it inside the chip, and a small table can be read in full every time with a mask keeping the one entry wanted. Then evicting any line costs every run the same, and the clock says nothing. Random delays do not help: they average away.', facts: facts0, meta: { stage: 'defence' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Evict+time on T-tables', ['round 1: byte i looks up T(i mod 4)[pᵢ ⊕ kᵢ]', 'cache line = (pᵢ ⊕ kᵢ) ≫ 4, the high nibble', 'evict line ℓ of a table; time an encryption', 'slow ⇒ some pᵢ ⊕ kᵢ had high nibble ℓ', 'defence: no secret-dependent addresses (bitsliced or AES-NI)']) };
  }
  S.topic({
    id: 'sc-cache', family: 'p15-timing', order: 10, title: 'Cache timing on T-table AES',
    blurb: 'Table lookups at secret-dependent addresses leave traces in the cache: a run is slower when a line the key sent a lookup to had been thrown out. Over many runs that exposes four key bits per byte. The defence is code with no secret addresses.',
    inputs: [
      { id: 'key', kind: 'text', label: 'AES key (16 characters)', def: 'harbour-lights-7', check: V.keyCheck },
      { id: 'pt', kind: 'text', label: 'A plaintext (16 characters)', def: 'meet me at dusk!', check: (v) => (!v || v.length > 16 ? 'Plaintext: 1 to 16 characters' : null) },
      { id: 'samples', kind: 'choice', label: 'Timed encryptions', def: '3000', options: ['1000', '3000', '10000'].map((v) => ({ value: v, label: v })) },
      { id: 'rounds', kind: 'choice', label: 'Victim', def: 'first', options: [{ value: 'first', label: 'first round only (clean)' }, { value: 'all', label: 'all nine table rounds (noisy)' }] },
      { id: 'seed', kind: 'number', label: 'Seed', def: 2, min: 1, max: 999 },
    ],
    presets: [
      { label: 'First round, 3000 runs', values: { samples: '3000', rounds: 'first' } },
      { label: 'Whole cipher, 3000 runs', values: { samples: '3000', rounds: 'all' } },
      { label: 'Whole cipher, 10000 runs', values: { samples: '10000', rounds: 'all' } },
      { label: 'Another key', values: { key: 'quiet-orchard-91', samples: '1000', rounds: 'first', pt: 'tea at four, ok?' } },
    ],
    run: cache,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'lookups', pick: 'option', options: ['slower', 'the same'], ask: 'If the attacker evicts the line byte 0 needs, will the encryption be slower or the same?', answer: 'slower', explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'Why does a T-table lookup leak through the cache?', options: ['It is slow', 'The address it reads depends on pᵢ ⊕ kᵢ, and the cache keeps track of addresses', 'It writes the key', 'It does not'], answer: 1, why: 'Hits and misses reveal which lines were used.' },
      { q: 'A first-round cache leak on 64-byte lines exposes…', options: ['the whole key', 'the high nibble (4 bits) of each key byte', 'nothing', 'the plaintext'], answer: 1, why: 'A line holds 16 entries, so the low 4 bits of the index are hidden.' },
      { q: 'Which implementation resists cache timing?', options: ['T-tables', 'Bitsliced AES or the AES instructions in the processor', 'Bigger tables', 'Faster RAM'], answer: 1, why: 'They make no memory access whose address depends on secrets.' },
      { q: 'Do random delays fix a cache-timing leak?', options: ['Yes', 'No: they add noise that averages away over more runs', 'Only on servers', 'Only for AES'], answer: 1, why: 'The dependence of the memory touched on the key is still there.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // A MAC tag recovered from timing
  // ---------------------------------------------------------------------------------------------------------------
  function macTiming(inp) {
    const len = +inp.len, ct = inp.ct === 'yes';
    const o = C().Timing.oracle({ len, seed: +inp.seed, sigma: +inp.sigma, constantTime: ct }), rec = C().Timing.recover(o, { reps: +inp.reps });
    const tag = o.secret, F = new S.Frames(['queries']);
    const head = U.t('mt:h', 20, 30, `Timing a ${len}-byte MAC tag check (${ct ? 'constant-time' : 'early-exit'} comparison, σ = ${inp.sigma} cycles)`, 'strong', 'start', 16);
    const code = (lit, safe) => {
      const lines = safe ? ['d = 0', 'for i = 0 … n − 1:', '    d = d | (tag[i] ⊕ guess[i])', 'return d == 0'] : ['for i = 0 … n − 1:', '    if tag[i] ≠ guess[i]:', '        return reject', 'return accept'];
      return lines.map((l, k) => ({ key: 'mt:code' + k, kind: 'cell', x: 40, y: 64 + k * 30, w: 360, h: 28, rx: 3, text: l, size: 14, align: 'left', cls: 'code ' + (lit && lit.includes(k) ? (safe ? 'good' : 'hot') : '') }));
    };
    const tagRow = (shown) => [U.t('mt:tl', 460, 82, 'the server\'s tag', 'strong', 'start', 14), ...Array.from(tag, (v, i) => ({ key: 'mt:t' + i, kind: 'cell', x: 460 + i * 52, y: 92, w: 48, h: 32, rx: 3, text: '??', size: 15, cls: 'hex key' })),
      ...(shown ? [U.t('mt:gl', 460, 156, 'pieced together from timing', 'strong', 'start', 14), ...Array.from({ length: len }, (_, i) => ({ key: 'mt:g' + i, kind: 'cell', x: 460 + i * 52, y: 166, w: 48, h: 32, rx: 3, text: h2(rec.tag[i]), size: 15, cls: 'hex ' + (rec.tag[i] === tag[i] ? 'bad' : 'good') }))] : [])];
    const facts0 = { len, sigma: +inp.sigma, reps: +inp.reps, bits: 8 * len };
    F.add({ items: [head, ...code(ct ? [2] : [1, 2], ct), ...tagRow(false), U.t('mt:n', 40, 260, ct ? 'The loop always runs to the end and never branches on the data.' : 'The loop stops at the first byte that differs: one more right byte, one more trip round the loop.', 'strong', 'start', 14)], hl: { d: [0] }, say: ct ? 'This server compares the whole tag every time, ORing the differences together, so it takes the same time whatever the guess.' : `The server checks a ${len}-byte tag byte by byte and returns at the first difference. A guess whose first byte is right takes one loop iteration longer than one whose first byte is wrong: a few cycles, buried in noise of σ = ${inp.sigma} cycles.`, facts: facts0, meta: { stage: 'code' } });
    // the leak, for the first byte only: all 256 values there, each timed reps times and averaged
    const pl = U.plot({ prefix: 'mt:p', x: 70, y: 300, w: 820, h: 280, xr: [-1, 256], yr: [0, 1], xticks: [0, 64, 128, 192, 255], yticks: [], ylabel: 'mean response time, first byte set to each value', xlabel: 'value of the first byte', tickSize: 13 });
    const prof = rec.profiles[0], st = rec.trace[0], lo = Math.min(...prof) - 1, hi = Math.max(...prof) + 1, Y = (v) => (v - lo) / (hi - lo);
    const bars = prof.map((v, c) => U.bar(pl, 'mt:b' + c, c, Y(v), 2.6, c === tag[0] ? (st.best === tag[0] ? 'bad' : 'act') : 'soft'));
    const lab = [U.t('mt:lo', 62, pl.Y(0) + 5, fx(lo, 0), 'tick', 'end', 13), U.t('mt:hi', 62, pl.Y(1) + 5, fx(hi, 0), 'tick', 'end', 13)];
    F.count('queries', 256 * +inp.reps);
    const stands = st.best === tag[0];
    F.add({ items: [head, ...code(ct ? [2] : [1, 2], ct), ...tagRow(false), ...pl.items, ...bars, ...lab], hl: { d: [1] }, say: ct ? `Every value of the first byte, timed ${inp.reps} times and averaged: the bars are flat up to the noise, and the true byte ${h2(tag[0])} does not stand out. The clock has nothing to say.` : stands ? `Every value of the first byte, timed ${inp.reps} times and averaged: the true byte ${h2(tag[0])} answers slowest, by ${fx(st.margin, 1)} cycles over the next. The noise is still there, but averaging shrinks it, and one extra loop iteration stands out. That is the leak.` : `Every value of the first byte, timed only ${inp.reps === '1' ? 'once' : inp.reps + ' times'}: the true byte ${h2(tag[0])} does not yet stand out of noise of σ = ${inp.sigma} cycles. More tries per value would average the noise down; the leak is still there.`, facts: Object.assign({ truth: h2(tag[0]), margin: st.margin, cand: 256 }, facts0), meta: { stage: 'leak', ok: stands } });
    F.count('queries', o.calls - 256 * +inp.reps);
    F.add({ items: [head, ...code(ct ? [2] : [1, 2], ct), ...tagRow(true), U.t('mt:r', 460, 240, rec.ok ? 'accepted' : 'rejected', rec.ok ? 'bad' : 'good', 'start', 18)], hl: { d: [2] }, say: rec.ok ? `Byte after byte, the same timing exposes the whole tag: all ${len} bytes in ${o.calls} timed queries, where guessing blindly would take 2^${8 * len} tries, and the server accepts the forged tag. The early exit, not the MAC, is what failed.` : ct ? `Byte after byte, the timing gives nothing: the tag pieced together from the slowest values is rejected after ${o.calls} queries. A constant-time comparison gives the clock nothing to read.` : `With this much noise and so few tries, the tag pieced together from the slowest values is wrong and is rejected after ${o.calls} queries. The leak is still there: more tries per value would expose it.`, facts: Object.assign({ calls: o.calls, tag: Array.from(rec.tag, h2).join(''), cand: 256 }, facts0), meta: { stage: 'end', ok: rec.ok } });
    if (!ct) F.add({ items: [head, ...code([0, 2, 3], true), ...tagRow(false), U.t('mt:f1', 460, 170, 'every byte compared, one test at the end', 'good', 'start', 15), U.t('mt:f2', 460, 200, 'or call the library: timingSafeEqual', 'good', 'start', 15)], hl: { d: [3] }, say: 'The fix: compare every byte whatever happens, OR the differences into one value, and test it once at the end, or call the library\'s constant-time comparison. The time is then the same for every guess, and the clock has nothing to read.', facts: facts0, meta: { stage: 'fix' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Timing a comparison', ['leaky: return at the first differing byte', 'time ≈ base + per-byte × (matching prefix + 1) + noise', 'so the time exposes the tag, byte after byte', 'averaging defeats the noise; only the code can remove the leak', 'fix: d |= a[i] ⊕ b[i] over every byte; test d once']) };
  }
  S.topic({
    id: 'sc-mac-timing', family: 'p15-timing', order: 20, title: 'A MAC check that leaks through the clock',
    blurb: 'A server that compares a tag byte by byte and stops at the first mismatch answers a little later for every right byte. Averaged over a few tries, that difference exposes the tag. A constant-time comparison takes the same time whatever the guess.',
    inputs: [
      { id: 'len', kind: 'choice', label: 'Tag length', def: '4', options: ['3', '4', '6'].map((v) => ({ value: v, label: v + ' bytes' })) },
      { id: 'reps', kind: 'choice', label: 'Tries per candidate', def: '15', options: ['1', '5', '15', '40'].map((v) => ({ value: v, label: v })) },
      { id: 'sigma', kind: 'choice', label: 'Timing noise σ', def: '3', options: ['1', '3', '6'].map((v) => ({ value: v, label: v + ' cycles' })) },
      { id: 'ct', kind: 'choice', label: 'Comparison', def: 'no', options: [{ value: 'no', label: 'stops at the first difference' }, { value: 'yes', label: 'constant time' }] },
      { id: 'seed', kind: 'number', label: 'Seed', def: 31, min: 1, max: 999 },
    ],
    presets: [
      { label: 'Leaky, 15 tries each', values: { len: '4', reps: '15', sigma: '3', ct: 'no' } },
      { label: 'Too few tries', values: { len: '4', reps: '1', sigma: '6', ct: 'no' } },
      { label: 'Constant time', values: { len: '4', reps: '15', sigma: '3', ct: 'yes' } },
      { label: 'Six bytes', values: { len: '6', reps: '15', sigma: '3', ct: 'no', seed: 12 } },
    ],
    counters: [{ id: 'queries', label: 'timed queries' }],
    run: macTiming,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'code', pick: 'option', options: ['the right byte', 'a random byte'], ask: 'For the first byte, which value will take the longest on average?', answer: (fr, i) => (fr[i + 1].meta.ok ? 'the right byte' : 'a random byte'), explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'Why does an early-exit comparison leak?', options: ['It uses the key', 'Its running time depends on how many leading bytes match', 'It is random', 'It does not'], answer: 1, why: 'Each extra matching byte adds a loop iteration.' },
      { q: 'Why does the early exit make a 64-bit tag weak?', options: ['It does not', 'The tag leaks a byte at a time, so the cost is about 8 × 256 × r queries, not 2^64', 'It shortens the tag', 'It reveals the key'], answer: 1, why: 'Each byte can be found on its own, which turns one huge search into eight small ones.' },
      { q: 'Is network or timing noise a defence?', options: ['Yes', 'No: averaging r tries shrinks the noise by √r', 'Only above 1 ms', 'Only for long tags'], answer: 1, why: 'Noise only raises the number of queries; the constant-time comparison removes the leak.' },
      { q: 'A constant-time comparison…', options: ['compares every byte and decides once at the end', 'is slower in a way that depends on the data', 'uses encryption', 'stops early'], answer: 0, why: 'Its time does not depend on where the guess differs.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Constant-time code beside leaky code
  // ---------------------------------------------------------------------------------------------------------------
  function constTime(inp) {
    const len = 4, seed = +inp.seed;
    const leaky = C().Timing.oracle({ len, seed, sigma: 0 }), safe = C().Timing.oracle({ len, seed, sigma: 0, constantTime: true });
    const tag = Array.from(leaky.secret);
    const g1 = tag.map((v, i) => (i === 0 ? v ^ 0x40 : v)), g2 = tag.map((v, i) => (i === 3 ? v ^ 0x01 : v));
    const t = { l1: leaky.time(g1), l2: leaky.time(g2), s1: safe.time(g1), s2: safe.time(g2) };
    const e1 = BigInt(inp.e1), e2 = BigInt(inp.e2);
    const sp = (e, always) => C().spaTrace(e, { seed: 4, sigma: 0, always }).ops;
    const o = { a1: sp(e1, false), a2: sp(e2, false), b1: sp(e1, true), b2: sp(e2, true) };
    const F = new S.Frames();
    const head = U.t('ct:h', 20, 30, 'The same job, written two ways', 'strong', 'start', 16);
    const panel = (key, x, title, lines, lit, cls) => [U.t(key + ':t', x, 72, title, cls, 'start', 15), ...lines.map((l, k) => ({ key: key + ':l' + k, kind: 'cell', x, y: 84 + k * 30, w: 410, h: 28, rx: 3, text: l, size: 14, align: 'left', cls: 'code ' + (lit.includes(k) ? (cls === 'bad' ? 'bad' : 'good') : '') }))];
    const result = (key, x, y, rows) => rows.map(([a, b2, c], k) => U.t(key + k, x, y + 26 * k, a + ': ' + b2, c || 'mono', 'start', 15));
    // the work as strips: one cell per operation (S blue, M orange), or a bar as long as the time
    const strip = (key, x, y, ops) => ops.map((op, k, all) => ({ key: key + k, kind: 'cell', x: U.r2(x + k * Math.min(13, 410 / all.length)), y, w: U.r2(Math.min(13, 410 / all.length) - 2), h: op === 'S' ? 22 : 30, rx: 2, text: '', cls: 'bar ' + (op === 'S' ? 'act' : 'hot') }));
    const tbar = (key, x, y, cyc, max, cls) => [{ key, kind: 'cell', x, y, w: U.r2((cyc / max) * 380), h: 22, rx: 3, text: '', cls: 'bar ' + cls }];
    const cmpL = ['for i = 0 … 3:', '    if tag[i] ≠ guess[i]: return reject', 'return accept'], cmpS = ['d = 0', 'for i = 0 … 3:  d = d | (tag[i] ⊕ guess[i])', 'return d == 0'];
    const facts0 = { len, l1: t.l1, l2: t.l2, s1: t.s1, s2: t.s2 };
    F.add({ items: [head, ...panel('ct:a', 40, 'leaky: returns early', cmpL, [1], 'bad'), ...panel('ct:b', 480, 'constant time: no early exit', cmpS, [1], 'good')], hl: { d: [0] }, say: 'Comparing a 4-byte tag. On the left the loop returns as soon as a byte differs; on the right every byte is compared and the differences are ORed into d, with one test at the end.', facts: facts0, meta: { stage: 'cmp-code' } });
    F.add({ items: [head, ...panel('ct:a', 40, 'leaky: returns early', cmpL, [1], 'bad'), ...panel('ct:b', 480, 'constant time: no early exit', cmpS, [1], 'good'), ...result('ct:ra', 40, 210, [['first byte wrong', t.l1 + ' cycles', 'bad'], ['only last byte wrong', t.l2 + ' cycles', 'bad']]), ...result('ct:rb', 480, 210, [['first byte wrong', t.s1 + ' cycles', 'good'], ['only last byte wrong', t.s2 + ' cycles', 'good']]), ...tbar('ct:ba1', 40, 280, t.l1, Math.max(t.l2, t.s1), 'bad'), ...tbar('ct:ba2', 40, 312, t.l2, Math.max(t.l2, t.s1), 'bad'), ...tbar('ct:bb1', 480, 280, t.s1, Math.max(t.l2, t.s1), 'good'), ...tbar('ct:bb2', 480, 312, t.s2, Math.max(t.l2, t.s1), 'good')], hl: { d: [0, 1] }, say: `Timed with no noise: the leaky version takes ${t.l1} cycles when the first byte is wrong and ${t.l2} when only the last is, so the clock counts the matching bytes. The constant-time version takes ${t.s1} and ${t.s2}: the same.`, facts: facts0, meta: { stage: 'cmp-time' } });
    const expL = ['for each bit of e, from the top:', '    r = r · r', '    if bit = 1:  r = r · x'], expS = ['for each bit of e, from the top:', '    r = r · r', '    t = r · x;  r = select(bit, t, r)'];
    const cnt = (ops) => ops.filter((x) => x === 'S').length + ' S, ' + ops.filter((x) => x === 'M').length + ' M';
    F.add({ items: [head, ...panel('ct:c', 40, 'leaky: branches on the bit', expL, [2], 'bad'), ...panel('ct:d', 480, 'constant time: multiply always, select', expS, [2], 'good'), ...result('ct:rc', 40, 210, [['e = ' + e1, cnt(o.a1), 'bad'], ['e = ' + e2, cnt(o.a2), 'bad']]), ...result('ct:rd', 480, 210, [['e = ' + e1, cnt(o.b1), 'good'], ['e = ' + e2, cnt(o.b2), 'good']]), ...strip('ct:sa', 40, 280, o.a1), ...strip('ct:sb', 40, 330, o.a2), ...strip('ct:sc', 480, 280, o.b1), ...strip('ct:sd', 480, 330, o.b2), ...U.legend('ct:k', 40, 400, [['act', 'squaring'], ['hot', 'multiplication']])], hl: { d: [2, 3] }, say: `Exponentiation: branching on each bit makes the work depend on the exponent: ${e1} costs ${cnt(o.a1)} and ${e2} costs ${cnt(o.a2)}. Multiplying every time and keeping the product only when the bit is 1, with a select that does not branch, gives ${cnt(o.b1)} and ${cnt(o.b2)}: the operation count no longer depends on the bits.`, facts: Object.assign({ e1: String(e1), e2: String(e2), a1: [o.a1.filter((x) => x === 'S').length, o.a1.filter((x) => x === 'M').length], a2: [o.a2.filter((x) => x === 'S').length, o.a2.filter((x) => x === 'M').length], b1: [o.b1.filter((x) => x === 'S').length, o.b1.filter((x) => x === 'M').length], b2: [o.b2.filter((x) => x === 'S').length, o.b2.filter((x) => x === 'M').length] }, facts0), meta: { stage: 'exp' } });
    const tabL = ['v = T[secret]'], tabS = ['v = 0', 'for j = 0 … 255:', '    v = v | (T[j] & mask(j == secret))'];
    F.add({ items: [head, ...panel('ct:e', 40, 'leaky: address depends on a secret', tabL, [0], 'bad'), ...panel('ct:f', 480, 'constant time: read everything, keep one', tabS, [2], 'good'), U.t('ct:fn', 40, 230, 'The rules of constant-time code:', 'strong', 'start', 15), ...['no branch on a secret', 'no memory address computed from a secret', 'no variable-time instruction (division, some multiplies) on a secret', 'and check the compiler kept it that way'].map((s2, k) => U.t('ct:r' + k, 60, 262 + 28 * k, '• ' + s2, '', 'start', 15))], hl: { d: [4] }, say: 'Table lookups: reading T[secret] touches a cache line that depends on the secret, as the T-table attack showed. Reading every entry and keeping the one wanted with a mask touches the same lines every time. The three rules: no secret branches, no secret addresses, no variable-time instructions on secrets.', facts: facts0, meta: { stage: 'table' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Constant-time code', ['time must not depend on secret data', 'no if on a secret: compute both, select with a mask', 'no T[secret]: scan the table, or use bit operations', 'compare with d |= a ⊕ b, test once', 'beware: compilers and CPUs may undo it']) };
  }
  S.topic({
    id: 'sc-consttime', family: 'p15-timing', order: 30, title: 'Constant-time code beside leaky code',
    blurb: 'Three everyday jobs, each written twice: a tag comparison, an exponentiation and a table lookup. The leaky versions take time that depends on the secret; the constant-time ones do the same work whatever it is.',
    inputs: [
      { id: 'seed', kind: 'number', label: 'Tag seed', def: 31, min: 1, max: 999 },
      { id: 'e1', kind: 'text', label: 'Exponent 1', def: '40961', check: (v) => (!/^\d+$/.test(v) || BigInt(v) < 2n || BigInt(v) > 2n ** 24n ? 'Exponent 1: 2 to 2²⁴' : null) },
      { id: 'e2', kind: 'text', label: 'Exponent 2', def: '65535', check: (v) => (!/^\d+$/.test(v) || BigInt(v) < 2n || BigInt(v) > 2n ** 24n ? 'Exponent 2: 2 to 2²⁴' : null) },
    ],
    presets: [
      { label: 'Few ones against many', values: { e1: '40961', e2: '65535' } },
      { label: 'Same length, other bits', values: { e1: '43690', e2: '52428', seed: 7 } },
    ],
    run: constTime,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'cmp-code', pick: 'option', options: ['the leaky one', 'the constant-time one', 'both'], ask: 'Which version will take a different time for the two guesses?', answer: 'the leaky one', explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'Which of these is safe for secret data?', options: ['if (secret_bit) x = y;', 'x = (y & mask) | (x & ~mask), mask from the bit', 'v = T[secret]', 'return at the first wrong byte'], answer: 1, why: 'A mask selects without a branch.' },
      { q: 'Why can constant-time C still leak?', options: ['C is slow', 'The compiler may turn the mask back into a branch', 'Masks are random', 'It cannot'], answer: 1, why: 'Constant-time code must be checked at the machine-code level.' },
      { q: 'Square-and-multiply-always costs…', options: ['the same as plain square-and-multiply', 'one multiplication per bit, used or not', 'half the work', 'no multiplications'], answer: 1, why: 'Doing the multiply every time is the price of hiding the bits.' },
      { q: 'Which is not a constant-time rule?', options: ['no branches on secrets', 'no secret-dependent memory addresses', 'always use the fastest algorithm', 'no variable-time instructions on secrets'], answer: 2, why: 'Speed that depends on the data is exactly what leaks.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
