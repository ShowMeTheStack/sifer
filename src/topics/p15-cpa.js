// Part 15, correlation power analysis as evidence of a leak: the correlation of every possible key byte with every
// time sample as traces pile up, the true key's peak standing out of the noise; how the number of traces grows with
// the noise; and Boolean masking, which removes the single-sample leak, though two samples combined still show it.
(function (S) {
  'use strict';
  const U = S.P14, V = S.P15, C = () => S.SC;
  const fx = U.fx, h2 = U.hex2;
  const keyInput = { id: 'key', kind: 'text', label: 'AES key (16 characters)', def: 'harbour-lights-7', check: (v) => S.P15.keyCheck(v) };
  const byteInput = { id: 'byte', kind: 'number', label: 'Key byte', def: 0, min: 0, max: 15 };

  /** the correlation of all 256 guesses over time: one grey path for the wrong ones, the true one in colour */
  function corrPlot(prefix, box, corr, T, kb, top, extra) {
    const pl = V.tracePlot(Object.assign({ prefix, yr: [-top, top], yticks: [-top / 2, 0, top / 2], fy: (v) => fx(v, 2), zero: true, ylabel: 'correlation ρ of each key guess with each sample', xlabel: 'time sample', T, xticks: T === 1 ? [0] : undefined }, box));
    let d = '';
    for (let g = 0; g < 256; g++) { if (g === kb) continue; for (let t = 0; t < T; t++) d += (t ? 'L' : 'M') + pl.X(t) + ',' + pl.Y(Math.max(-top, Math.min(top, corr[g * T + t]))) + ' '; }
    const items = pl.items.concat([{ key: prefix + ':wrong', kind: 'path', d, cls: 'dline faint', audit: 'ignore', layer: 'back' }, pl.trace(prefix + ':true', corr.subarray(kb * T, kb * T + T), 'hot')]);
    return { pl, items: items.concat(extra || []) };
  }
  /** the rank of the true key byte against the number of traces, on a log scale of rank */
  function rankPlot(prefix, box, progress, maxN, upto) {
    const lg = (r) => Math.log2(r);
    const pl = U.plot({ prefix, x: box.x, y: box.y, w: box.w, h: box.h, xr: [0, maxN], yr: [0, 8], xticks: [0, maxN / 2, maxN], yticks: [0, 4, 8], fy: (v) => String(2 ** v), xlabel: 'traces', ylabel: 'rank of the true byte (1 is found)', tickSize: 13 });
    const pts = progress.filter((p) => p.traces <= upto);
    const items = pl.items.slice();
    if (pts.length) items.push(U.line(pl, prefix + ':l', pts.map((p) => p.traces), pts.map((p) => lg(p.rank + 1)), 'hot', 'ignore'));
    if (pts.length) { const p = pts[pts.length - 1]; items.push({ key: prefix + ':d', kind: 'dot', x: pl.X(p.traces), y: pl.Y(lg(p.rank + 1)), r: 5, cls: p.rank ? 'hot' : 'good', point: true }); }
    return items;
  }

  // ---------------------------------------------------------------------------------------------------------------
  // CPA
  // ---------------------------------------------------------------------------------------------------------------
  function cpa(inp) {
    const key = V.key(inp.key), b = +inp.byte, kb = key[b], sigma = +inp.sigma, total = +inp.n, T = 52;
    const src = C().source({ key, sigma, seed: +inp.seed });
    const marks = [25, 50, 100, 200, 400, 800, 1600, 3200].filter((n) => n <= total);
    if (marks[marks.length - 1] !== total) marks.push(total);
    const snaps = [];
    let progress = [];
    for (const st of C().cpaSteps({ source: src, byte: b, key: kb, total, chunk: 25 })) {
      progress = st.progress;
      if (marks.includes(st.cpa.n)) snaps.push({ n: st.cpa.n, corr: st.cpa.corr(), r: st.last });
    }
    const ts = C().sampleOf(b, 'sbox');
    const F = new S.Frames(['traces']);
    const head = U.t('cp:h', 20, 30, `The power leak of key byte ${b} (true value 0x${h2(kb)}), Hamming-weight model, σ = ${sigma}`, 'strong', 'start', 16);
    const facts0 = { b, kb: h2(kb), sigma, ts, total };
    // the leak itself: a few raw traces, the S-box sample of this byte shaded
    const ch0 = C().source({ key, sigma, seed: +inp.seed }).next(12);
    const raw = V.tracePlot({ prefix: 'cp:w', x: 70, y: 70, w: 820, h: 260, yr: [-4, 12], yticks: [0, 4, 8], ylabel: 'power, 12 raw traces' });
    const idea = [...raw.items, raw.shade(b, 'sbox', 'hot'), ...Array.from({ length: 12 }, (_, i) => raw.trace('cp:wt' + i, ch0.traces.subarray(i * T, i * T + T), 'faint')),
      U.t('cp:n1', 70, 400, `sample ${ts}: the chip handles S(p${U.sub(b)} ⊕ k${U.sub(b)}), and draws power ≈ HW(S(p ⊕ k)) + noise`, 'strong', 'start', 15),
      U.t('cp:n2', 70, 432, 'one trace shows nothing through the noise; many traces together do', 'tick', 'start', 14)];
    F.add({ items: [head, ...idea], hl: { d: [0, 1] }, say: `At sample ${ts} the chip handles S(p${U.sub(b)} ⊕ k${U.sub(b)}), and its power follows the Hamming weight of that value, under noise of σ = ${sigma}. One trace shows nothing. Over many traces with random plaintexts, though, the power at that sample correlates with the weight computed from the true key byte, and with nothing else: the plots that follow show the correlation for all 256 possible byte values as the traces pile up.`, facts: Object.assign({ shown: 12 }, facts0), meta: { stage: 'idea' } });
    let prevN = 0;
    for (const s of snaps) {
      F.count('traces', s.n - prevN); prevN = s.n;
      const r = s.r, wrong = r.ranking.find((g) => g !== kb), top = Math.max(0.3, Math.ceil(Math.max(r.peaks[kb], r.peaks[wrong]) * 11) / 10);
      const cp = corrPlot('cp:c', { x: 70, y: 70, w: 820, h: 280 }, s.corr, T, kb, top, [V.tracePlot({ prefix: 'cp:z', x: 70, y: 70, w: 820, h: 280, yr: [-top, top] }).shade(b, 'sbox', 'hot')]);
      const ro = U.readout('cp:r', 560, 410, 346, s.n + ' traces', [['true byte ' + h2(kb) + ', peak |ρ|', fx(r.peaks[kb], 3), 'hot'], ['highest other value ' + h2(wrong), fx(r.peaks[wrong], 3)], ['noise level, about 4/√N', fx(4 / Math.sqrt(s.n), 3)], ['rank of the true byte', String(r.rank + 1), r.rank ? 'bad' : 'good']], { dy: 30 });
      F.add({ items: [head, ...cp.items, ...rankPlot('cp:k', { x: 90, y: 420, w: 400, h: 160 }, progress, total, s.n), ...ro], hl: { d: [2, 3] }, say: `${s.n} traces. The true byte's correlation peaks at ${fx(r.peaks[kb], 3)} (sample ${r.peakAt[kb]}); the strongest of the other 255 values reaches ${fx(r.peaks[wrong], 3)}. ${r.rank === 0 ? 'The true byte\'s peak stands highest.' : `${r.rank} other values still stand higher: the leak is lost in the noise.`} The others scatter by about 4/√N = ${fx(4 / Math.sqrt(s.n), 3)}; the true peak stays put while that shrinks.`, facts: Object.assign({ n: s.n, peak: r.peaks[kb], at: r.peakAt[kb], wpeak: r.peaks[wrong], rank: r.rank + 1, above: r.rank, noise: 4 / Math.sqrt(s.n), four: 4 }, facts0), meta: { stage: 'snap', n: s.n, rank: r.rank } });
    }
    const first = progress.findIndex((p, i) => progress.slice(i).every((q) => q.rank === 0)), settled = first >= 0 ? progress[first].traces : null;
    const last = snaps[snaps.length - 1];
    F.add({ items: [head, ...corrPlot('cp:c', { x: 70, y: 70, w: 820, h: 280 }, last.corr, T, kb, Math.max(0.3, Math.ceil(last.r.peaks[kb] * 11) / 10)).items, ...rankPlot('cp:k', { x: 90, y: 420, w: 400, h: 160 }, progress, total, total), ...U.readout('cp:r', 560, 410, 346, 'what it means', [['stands out for good after', settled ? settled + ' traces' : 'not yet', settled ? 'bad' : 'good'], ['so this byte is', settled ? 'exposed' : 'not yet exposed', settled ? 'bad' : 'good'], ['the defence', 'masking, shuffling']], { dy: 30 })], hl: { d: [3, 4] }, say: settled ? `The true byte's peak stood clear of all the others for good after ${settled} traces: from then on, these measurements expose the key byte. Each of the 16 bytes leaks the same way at its own sample, so ${total} power measurements expose the whole AES key, where brute force would need 2^128 tries. Key length is no defence here; removing the leak is. Masking makes the value handled independent of the key, shuffling moves it to a random sample, and noise only raises the trace count.` : `After ${total} traces the true byte's peak has not stood clear for good: with σ = ${sigma} the leak needs more traces to show. It is still there, and more traces will expose it; only masking or shuffling removes it.`, facts: Object.assign({ settled, bits: 128, bytes: 16 }, facts0), meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('A first-order power leak', ['power at the S-box sample ≈ a · HW(S(p ⊕ k)) + noise', 'its correlation with the true key\'s weights: large', 'with any other value: about the noise, near 4/√N', 'each key byte leaks on its own: 16 small problems, not 2^128', 'defences: masking, shuffling; noise only raises the trace count']) };
  }
  S.topic({
    id: 'sc-cpa', family: 'p15-cpa', order: 10, title: 'CPA: a key byte\'s leak out of the noise',
    blurb: 'A chip\'s power follows the Hamming weight of the S-box output it handles. Over enough traces the correlation for the true key byte stands out of the grey band of all other values: the evidence that the device leaks, and the reason for masking.',
    inputs: [keyInput, byteInput, { id: 'sigma', kind: 'choice', label: 'Noise σ', def: '3', options: ['1', '2', '3', '4'].map((v) => ({ value: v, label: v })) }, { id: 'n', kind: 'choice', label: 'Traces', def: '800', options: ['400', '800', '1600'].map((v) => ({ value: v, label: v })) }, { id: 'seed', kind: 'number', label: 'Seed', def: 7, min: 1, max: 999 }],
    presets: [
      { label: 'σ = 3, 800 traces', values: { sigma: '3', n: '800', byte: 0 } },
      { label: 'Little noise', values: { sigma: '1', n: '400', byte: 9 } },
      { label: 'Heavy noise', values: { sigma: '4', n: '1600', byte: 3 } },
    ],
    counters: [{ id: 'traces', label: 'traces' }],
    run: cpa,
    predict: [{ at: (f, i, fr) => f.meta && f.meta.stage === 'snap' && f.meta.n === 25, pick: 'option', options: ['grows', 'stays about the same', 'shrinks'], ask: 'As traces are added, what happens to the true byte\'s peak correlation?', answer: 'stays about the same', explain: 'The peak estimates a fixed correlation; what shrinks is the noise of all the other values, about 4/√N.' }],
    quiz: [
      { q: 'What makes the true key byte\'s correlation stand out?', options: ['its value', 'only the true byte\'s weights match what the chip really handled', 'the number of traces', 'the timing'], answer: 1, why: 'For any other value the predicted weights are unrelated to the power drawn.' },
      { q: 'The spread of the other values\' correlations shrinks like…', options: ['1/N', '1/√N', 'it does not shrink', 'N'], answer: 1, why: 'A sample correlation of unrelated data has a standard deviation near 1/√N.' },
      { q: 'Why is a 128-bit key no protection against this leak?', options: ['It is', 'Each key byte leaks separately at its own sample, so the leak is 16 small problems, not one of 2^128', 'The key is too short', 'Power ignores the key'], answer: 1, why: 'Each byte enters the S-box separately; the defence has to remove the leak, not lengthen the key.' },
      { q: 'More noise means…', options: ['the leak is gone', 'a smaller true correlation, so more traces are needed', 'fewer traces are needed', 'nothing'], answer: 1, why: 'The traces needed grow about with 1/ρ²: noise delays, masking removes.' },
      { q: 'Which countermeasure removes this first-order leak?', options: ['a longer key', 'Boolean masking: every value handled is XORed with a fresh random mask', 'a faster clock', 'more rounds'], answer: 1, why: 'A masked value is uniform whatever the key, so its weight no longer follows HW(S(p ⊕ k)).' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // How many traces
  // ---------------------------------------------------------------------------------------------------------------
  function traces(inp) {
    const key = V.key(inp.key), b = +inp.byte, kb = key[b], total = +inp.n;
    const sigmas = inp.set === 'high' ? [4, 8, 12, 16] : [2, 4, 6, 8];
    // three runs at each noise level with different seeds; a single run scatters a lot, so the median is quoted
    const runs = sigmas.map((sigma, k) => {
      const three = [0, 1, 2].map((j) => C().cpaRun({ source: C().source({ key, sigma, seed: 40 + 10 * k + j }), byte: b, key: kb, total, chunk: 100 }));
      const sts = three.map((r) => (r.settled === null ? Infinity : r.settled)).sort((x, y) => x - y), med = sts[1];
      return { sigma, run: three[0], all: three.map((r) => r.settled), settled: med === Infinity ? null : med };
    });
    const F = new S.Frames();
    const head = U.t('ct:h', 20, 30, `Key byte ${b}: how many traces before the leak shows, for each noise level`, 'strong', 'start', 16);
    const lg = (r) => Math.log2(r);
    const pl = U.plot({ prefix: 'ct:p', x: 80, y: 80, w: 520, h: 420, xr: [0, total], yr: [0, 8], xticks: [0, total / 4, total / 2, (3 * total) / 4, total], yticks: [0, 2, 4, 6, 8], fy: (v) => String(2 ** v), xlabel: 'traces', ylabel: 'rank of the true byte (1 is found)', tickSize: 13 });
    const CLS = ['act', 'good', 'hot', 'key'];
    const scene = (upto) => {
      const items = [head, ...pl.items];
      const rows = [];
      runs.forEach((R, k) => {
        if (k > upto) return;
        const pr = R.run.progress;
        items.push(U.line(pl, 'ct:l' + k, pr.map((p) => p.traces), pr.map((p) => lg(p.rank + 1)), CLS[k], 'ignore'));
        rows.push(['σ = ' + R.sigma + ': |ρ| ' + fx(R.run.result.peaks[kb], 3), R.settled ? R.settled + ' traces' : 'more than ' + total, CLS[k]]);
      });
      items.push(...U.readout('ct:r', 630, 80, 276, 'found for good after', rows, { dy: 34 }));
      items.push(...U.legend('ct:k', 80, 560, runs.slice(0, upto + 1).map((R, k) => [CLS[k], 'σ = ' + R.sigma])));
      return items;
    };
    runs.forEach((R, k) => {
      const s = R.settled, rho = R.run.result.peaks[kb];
      F.add({ items: scene(k), hl: { d: [k ? 1 : 0] }, say: `σ = ${R.sigma}: the true byte's correlation is about ${fx(rho, 3)}. In three runs it settled at rank 1 after ${R.all.map((v) => (v === null ? 'more than ' + total : v)).join(', ')} traces: a median of ${s ? s : 'more than ' + total}. The curve shows the first run.${k ? ` Against σ = ${runs[k - 1].sigma}, the noise is ${fx(R.sigma / runs[k - 1].sigma, 1)} times larger.` : ''}`, facts: { sigma: R.sigma, rho, s, all: R.all, total, b, three: 3, ratio: k ? R.sigma / runs[k - 1].sigma : 1 }, meta: { stage: 'run', k, s: s } });
    });
    const sett = runs.map((R) => R.settled);
    F.add({ items: scene(runs.length - 1), hl: { d: [2, 3] }, say: `The pattern: the true correlation falls roughly like 1/σ once the noise dominates, and the traces needed grow like 1/ρ², so like σ². Here, as medians: ${runs.map((R, k) => 'σ = ' + R.sigma + ', ' + (sett[k] ? sett[k] : 'over ' + total)).join('; ')}. Noise alone only raises the number of traces; it does not remove the leak. That is why real defences change the leakage itself, with masking and shuffling.`, facts: { list: runs.map((R) => R.sigma), sett, total }, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Traces needed', ['true correlation ρ ≈ √(Var HW / (Var HW + σ²))', 'Var HW = 2 for a uniform byte', 'traces needed N ≈ c / ρ², for a constant c near 20 to 30', 'so N grows about like σ²', 'noise slows the attack; masking changes what leaks']) };
  }
  S.topic({
    id: 'sc-cpa-traces', family: 'p15-cpa', order: 20, title: 'How many traces: noise against the peak',
    blurb: 'The same leak at four noise levels. The true key\'s correlation shrinks as the noise grows, and the number of traces before it stands out grows about with the square of the noise: noise raises the price, it does not remove the leak.',
    inputs: [keyInput, byteInput, { id: 'set', kind: 'choice', label: 'Noise levels', def: 'low', options: [{ value: 'low', label: 'σ = 2, 4, 6, 8' }, { value: 'high', label: 'σ = 4, 8, 12, 16' }] }, { id: 'n', kind: 'choice', label: 'Traces', def: '2000', options: ['2000', '3000'].map((v) => ({ value: v, label: v })) }],
    presets: [
      { label: 'σ from 2 to 8', values: { set: 'low', n: '2000' } },
      { label: 'σ from 4 to 16', values: { set: 'high', n: '3000' } },
      { label: 'Byte 14', values: { set: 'low', byte: 14, n: '2000' } },
    ],
    run: traces,
    predict: [{ at: (f, i, fr) => f.meta && f.meta.stage === 'run' && f.meta.k === 1, pick: 'option', options: ['fewer', 'about the same', 'more'], ask: 'The next noise level is larger. Will it take fewer or more traces?', answer: (fr, i) => ((fr[i + 1].meta.s || 1e9) >= (fr[i].meta.s || 1e9) ? 'more' : 'fewer'), explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'Doubling the noise σ (when noise dominates) multiplies the traces needed by about…', options: ['2', '4', '1', '√2'], answer: 1, why: 'N ∝ 1/ρ² ∝ σ².' },
      { q: 'Is adding noise a complete defence?', options: ['Yes', 'No: it only multiplies the number of traces', 'Only for RSA', 'It makes things worse'], answer: 1, why: 'Given enough traces, the averaging still wins.' },
      { q: 'With no noise at all, CPA needs…', options: ['very few traces', 'millions', 'no traces', 'a quantum computer'], answer: 0, why: 'The correlation is then nearly perfect.' },
      { q: 'The true correlation is bounded by…', options: ['how well the model matches the leakage, and the noise', 'the key length', 'the clock speed', 'nothing'], answer: 0, why: 'ρ is the fraction of the measured variance that the model explains.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Masking, and the second-order attack
  // ---------------------------------------------------------------------------------------------------------------
  function masking(inp) {
    const key = V.key(inp.key), b = +inp.byte, kb = key[b], sigma = +inp.sigma, N = +inp.n, T = 52;
    const ex = C().maskedLookup(+inp.x, 0x5a, 0xc3);
    const F = new S.Frames(['traces']);
    const head = U.t('ms:h', 20, 30, `Boolean masking of the S-box, measured at first and at second order (σ = ${sigma})`, 'strong', 'start', 16);
    // 1. the masked lookup
    const x = +inp.x, mIn = 0x5a, mOut = 0xc3;
    const flow = () => {
      const N1 = S.Kit.flow.net('ms');
      N1.box('x', 120, 120, 120, 44, 'x = ' + h2(x), 'key');
      N1.op('xi', 270, 120, 'xor');
      N1.box('mi', 270, 200, 120, 40, 'mIn = ' + h2(mIn), 'soft');
      N1.box('t', 470, 120, 160, 52, ['T[·] = S(· ⊕ mIn)', '⊕ mOut'], 'act');
      N1.box('y', 700, 120, 170, 44, 'S(x) ⊕ mOut = ' + h2(ex.ym), 'act');
      N1.box('mo', 700, 200, 120, 40, 'mOut = ' + h2(mOut), 'soft');
      N1.wire('a', [N1.port('x', 'e'), N1.port('xi', 'w')], { head: true });
      N1.wire('b', [N1.port('mi', 'n'), N1.port('xi', 's')], { head: true });
      N1.wire('c', [N1.port('xi', 'e'), N1.port('t', 'w')], { head: true, cls: 'act' });
      N1.wire('d', [N1.port('t', 'e'), N1.port('y', 'w')], { head: true, cls: 'act' });
      N1.chip('xm', h2(ex.xm), [340, 120], 'act');
      return N1.items.concat([U.t('ms:fn', 40, 260, `The chip only ever holds ${h2(ex.xm)} and ${h2(ex.ym)}; the true values ${h2(x)} and ${h2(ex.y)} never appear.`, 'strong', 'start', 14)]);
    };
    F.add({ items: [head, ...flow()], hl: { d: [0] }, say: ex.trace.map((t) => t.say).join(' ') + ' Fresh masks are drawn for every encryption.', facts: { x: h2(x), xm: h2(ex.xm), ym: h2(ex.ym), y: h2(ex.y), mIn: h2(mIn), mOut: h2(mOut) }, meta: { stage: 'lookup' } });
    // 2. first-order CPA on the masked device
    const src = C().source({ key, sigma, seed: +inp.seed, masked: true }), first = C().CPA({ byte: b, T });
    const second = C().CPA({ byte: b, T: 1 }), prog1 = [], prog2 = [], ts = C().sampleOf(b, 'sbox');
    for (let n = 0; n < N; n += 250) { const ch = src.next(250); first.add(ch); second.add(C().secondOrder(ch, 1, ts)); prog1.push({ traces: first.n, rank: first.result(kb).rank }); prog2.push({ traces: second.n, rank: second.result(kb).rank }); }
    const r1 = first.result(kb), corr1 = first.corr(), r2 = second.result(kb);
    const top = 0.3;
    const cp = corrPlot('ms:c', { x: 70, y: 300, w: 820, h: 200 }, corr1, T, kb, top);
    const rk = (prog, cls) => rankPlot('ms:k', { x: 90, y: 560, w: 300, h: 70 }, prog, N, N);
    F.count('traces', N);
    const w1 = r1.ranking.find((g) => g !== kb);
    F.add({ items: [head, ...flow(), ...cp.items, U.t('ms:r1', 470, 580, `first order, ${N} traces: true byte ranks ${r1.rank + 1}, |ρ| = ${fx(r1.peaks[kb], 3)}`, r1.rank ? 'bad' : 'good', 'start', 15)], hl: { d: [1] }, say: `The first-order correlation over ${N} traces of the masked device. Every value it handles is S(x) ⊕ mOut with a fresh random mask, so its weight no longer follows S(p ⊕ k): the true byte's correlation is only ${fx(r1.peaks[kb], 3)}, no better than the best wrong guess's ${fx(r1.peaks[w1], 3)}, and it ranks ${r1.rank + 1} of 256.`, facts: { N, peak: r1.peaks[kb], wpeak: r1.peaks[w1], rank: r1.rank + 1, b }, meta: { stage: 'first', rank: r1.rank } });
    // 3. second order: the centred product of the mask's leak and the masked value's leak
    const pl2 = U.plot({ prefix: 'ms:q', x: 70, y: 300, w: 820, h: 200, xr: [-1, 256], yr: [0, Math.max(...r2.peaks) * 1.15], xticks: [0, 64, 128, 192, 255], yticks: [], ylabel: `|ρ| of each guess with (sample 1 − mean) × (sample ${ts} − mean)`, xlabel: 'key guess g', tickSize: 13 });
    const bars = r2.peaks.map((v, g) => U.bar(pl2, 'ms:qb' + g, g, v, 2.6, g === kb ? 'hot' : 'soft'));
    const settled = prog2.findIndex((p, i) => prog2.slice(i).every((q) => q.rank === 0));
    F.add({ items: [head, ...flow(), ...pl2.items, ...bars, U.t('ms:r2', 470, 580, `second order, ${N} traces: true byte ranks ${r2.rank + 1}, |ρ| = ${fx(r2.peaks[kb], 3)}`, r2.rank ? 'bad' : 'good', 'start', 15)], hl: { d: [2, 3] }, say: `But the mask leaks too, at its own sample (sample 1), while the masked value leaks at sample ${ts}. A measurement that combines the two samples cancels the mask on average, and the dependence on S(x) comes back: here the true byte's bar stands ${r2.rank === 0 ? 'highest' : 'in place ' + (r2.rank + 1)}${settled >= 0 ? `, for good after ${prog2[settled].traces} traces` : ''}, with |ρ| = ${fx(r2.peaks[kb], 3)}. One mask raises the order of the leak; it does not end it.`, facts: { N, peak: r2.peaks[kb], rank: r2.rank + 1, ts, settled: settled >= 0 ? prog2[settled].traces : null }, meta: { stage: 'second', rank: r2.rank } });
    F.add({ items: [head, ...flow(), ...pl2.items, ...bars, U.t('ms:r3', 70, 560, 'first order: no leak', 'good', 'start', 15), U.t('ms:r4', 470, 560, 'second order: needs about the square of the traces', 'hot', 'start', 15)], hl: { d: [4] }, say: `Masking with one mask forces any measurement to combine two points, which squares the effect of the noise: with σ = ${sigma} that is still cheap here, but every extra share raises the order again. Real implementations pair masking (with more shares, refreshed every run) with noise and shuffling, so that the higher-order measurement needs more traces than anyone can collect.`, facts: { sigma }, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Masking', ['hold x ⊕ m, never x; the table T[x ⊕ mIn] = S(x) ⊕ mOut', 'each held value is uniform on its own: first-order CPA fails', 'but HW(m) and HW(S(x) ⊕ m) leak at two samples', 'combining the two samples brings the dependence back: second order', 'd shares push the leak to order d + 1; add noise and shuffling']) };
  }
  S.topic({
    id: 'sc-masking', family: 'p15-cpa', order: 30, title: 'Masking, and the second-order attack',
    blurb: 'Hide every value under a fresh random mask and no single sample says anything about the key: the first-order leak is gone. The mask leaks at its own sample, though, so two samples combined still show the key; more shares, noise and shuffling raise that price.',
    inputs: [keyInput, byteInput, { id: 'x', kind: 'number', label: 'An example x for the lookup', def: 108, min: 0, max: 255 }, { id: 'sigma', kind: 'choice', label: 'Noise σ', def: '1', options: ['0.5', '1', '1.5'].map((v) => ({ value: v, label: v })) }, { id: 'n', kind: 'choice', label: 'Traces', def: '2000', options: ['1000', '2000', '4000'].map((v) => ({ value: v, label: v })) }, { id: 'seed', kind: 'number', label: 'Seed', def: 5, min: 1, max: 999 }],
    presets: [
      { label: 'σ = 1, 2000 traces', values: { sigma: '1', n: '2000' } },
      { label: 'Little noise', values: { sigma: '0.5', n: '1000', byte: 6 } },
      { label: 'More noise', values: { sigma: '1.5', n: '4000', byte: 2 } },
    ],
    counters: [{ id: 'traces', label: 'traces' }],
    run: masking,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'lookup', pick: 'option', options: ['still singles out the key byte', 'no longer singles out the key byte'], ask: 'The first-order correlation on the masked device:', answer: (fr, i) => (fr[i + 1].meta.rank === 0 ? 'still singles out the key byte' : 'no longer singles out the key byte'), explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'Why does a first-order correlation see nothing on a masked S-box?', options: ['The S-box is different', 'Each value handled is uniformly random on its own, whatever the key', 'There is no power', 'The traces are longer'], answer: 1, why: 'Its weight does not depend on S(p ⊕ k) alone.' },
      { q: 'A second-order leak comes from…', options: ['two key bytes', 'two leakage points, such as the mask and the masked value, taken together', 'two devices', 'two plaintexts'], answer: 1, why: 'Their joint behaviour depends on the unmasked value.' },
      { q: 'Splitting a value into d + 1 shares pushes the leak to order…', options: ['1', 'd', 'd + 1', 'never'], answer: 2, why: 'Only all d + 1 shares together depend on the value.' },
      { q: 'Why pair masking with noise and shuffling?', options: ['They are cheaper than masking', 'Each extra order multiplies the effect of the noise, so the traces needed grow steeply', 'They replace masking', 'They make the masks shorter'], answer: 1, why: 'Products of noisy samples are much noisier, so with noise a higher-order measurement needs far more traces.' },
      { q: 'What must be true of the masks?', options: ['They may be reused', 'Fresh and uniformly random for every run, and never in a register together with the value they hide', 'Equal to the key', 'Public'], answer: 1, why: 'A reused mask or a register holding x ⊕ m then m leaks HW(x) directly.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
