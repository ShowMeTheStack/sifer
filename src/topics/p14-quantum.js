// Part 14, the quantum threat: Grover's amplitude amplification drawn as bars, Shor's period finding on a tiny N
// with the probability peaks the Fourier transform makes, and the table of what both do to key sizes.
(function (S) {
  'use strict';
  const U = S.P14, Q = () => S.PQ.Quantum;
  const fx = U.fx;

  // ---------------------------------------------------------------------------------------------------------------
  // Grover
  // ---------------------------------------------------------------------------------------------------------------
  const groverIters = (mode, best) => (mode === 'best' ? best : mode === 'over' ? 2 * best + 1 : +mode);
  function grover(inp) {
    const n = +inp.n, N = 2 ** n, marked = inp.marked.map(Number);
    const base = Q().grover({ n, marked });
    const best = base.best, K = groverIters(inp.iters, best);
    const g = Q().grover({ n, marked, iterations: K }), M = g.M, theta = g.theta;
    const mk = new Set(marked);
    // the bars on the left; on the right the chance of success against the iterations, and the values of this step
    const pl = U.plot({ prefix: 'gb', x: 66, y: 84, w: 540, h: 460, xr: [-0.5, N - 0.5], yr: [-1, 1], yticks: [-1, -0.5, 0, 0.5, 1], fy: (v) => U.fx(v, 1), zero: true, ylabel: 'amplitude', tickSize: 13 });
    const kMax = Math.max(K, best + 1, 3), step = Math.ceil(kMax / 6);
    const sp = U.plot({ prefix: 'gs', x: 704, y: 100, w: 192, h: 180, xr: [0, kMax], yr: [0, 1], xticks: Array.from({ length: kMax + 1 }, (_, k) => k).filter((k) => k % step === 0), yticks: [0, 0.5, 1], fy: (v) => U.fx(v, 1), xlabel: 'iterations', ylabel: 'chance of success', tickSize: 13 });
    const bw = Math.max(3, (540 / N) * 0.72);
    const curveXs = [], curveYs = [];
    for (let i = 0; i <= 200; i++) { const k = (kMax * i) / 200; curveXs.push(k); curveYs.push(Math.sin((2 * k + 1) * theta) ** 2); }
    const firstOther = [...Array(N).keys()].find((i) => !mk.has(i));
    const scene = (amps, k, phase, mean, calls) => {
      const items = [...pl.items, ...sp.items];
      for (let i = 0; i < N; i++) items.push(U.bar(pl, 'gb:b' + i, i, amps[i], bw, mk.has(i) ? (amps[i] < 0 ? 'key neg' : 'key') : amps[i] < 0 ? 'neg' : ''));
      // index labels: every index when there are few, else the marked ones and the ends
      const lab = N <= 16 ? [...Array(N).keys()] : [0, N - 1].concat(marked).filter((v, i, a) => a.indexOf(v) === i);
      for (const i of lab) items.push(U.t('gb:i' + i, pl.X(i), pl.Y(-1) + 20, String(i), mk.has(i) ? 'key' : 'tick', 'middle', 13));
      if (mean !== undefined) {
        items.push({ key: 'gb:mean', kind: 'path', d: `M${pl.X(-0.5)},${pl.Y(mean)} H${pl.X(N - 0.5)}`, cls: 'meanline', audit: 'ignore' });
        items.push(U.t('gb:meant', pl.X(N - 0.5) + 8, pl.Y(mean) + 5, 'mean', 'hot', 'start', 13));
      }
      items.push(U.line(sp, 'gs:curve', curveXs, curveYs, 'soft', 'ignore'));
      const pNow = phase === 'oracle' ? g.success[k - 1] : g.success[k], done = phase === 'oracle' ? k - 1 : k;
      for (let j = 0; j <= done; j++) items.push({ key: 'gs:d' + j, kind: 'dot', x: sp.X(j), y: sp.Y(g.success[j]), r: j === done ? 6 : 4.5, cls: j === done ? 'hot' : 'act', point: true });
      items.push(...U.readout('gr', 690, 350, 216, 'this step', [
        ['marked amplitude', U.fx(amps[marked[0]], 4), 'key'],
        ['each other one', U.fx(amps[firstOther], 4)],
        ['mean', mean === undefined ? '—' : U.fx(mean, 4), 'hot'],
        ['chance of success', U.fx(pNow, 4), 'act'],
        ['oracle calls', String(calls)],
      ]));
      items.push(U.t('gb:h', 20, 34, `N = ${N} indices, ${M} marked (${marked.join(', ')}): iteration ${phase === 'start' ? 0 : k} of ${K}`, 'strong', 'start', 16));
      return items;
    };
    const F = new S.Frames(['iteration', 'oracle']);
    const a0 = g.amps[0][0];
    F.add({ items: scene(g.amps[0], 0, 'start', undefined, 0), hl: { d: [0] }, say: `${n} qubits hold all ${N} indices at once, each with amplitude 1/√${N} = ${fx(a0, 4)}. Measuring now would give a marked index with chance ${M}/${N} = ${fx(g.success[0], 4)}: no better than a guess.`, facts: { n, N, M, amp: a0, p: g.success[0] }, meta: { stage: 'start' } });
    for (let k = 1; k <= K; k++) {
      const prev = g.amps[k - 1], flipped = prev.map((v, i) => (mk.has(i) ? -v : v));
      const mean = flipped.reduce((s, v) => s + v, 0) / N;
      F.count('oracle');
      F.add({ items: scene(flipped, k, 'oracle', mean, k), hl: { d: [1] }, say: `Iteration ${k}: the oracle flips the sign of the marked ${M === 1 ? 'amplitude' : 'amplitudes'}, to ${fx(flipped[marked[0]], 4)}. No chance changes yet, since a chance is the square of an amplitude; only the sign marks the index. The mean amplitude falls to ${fx(mean, 4)}.`, facts: { k, flipped: flipped[marked[0]], mean }, meta: { stage: 'oracle', k } });
      F.count('iteration');
      const a = g.amps[k], am = a[marked[0]], other = a[firstOther];
      F.add({ items: scene(a, k, 'diffuse', mean, k), hl: { d: [2, 4] }, say: `Reflect every amplitude about the mean ${fx(mean, 4)}: each becomes 2 × mean − itself. The marked ${M === 1 ? 'amplitude' : 'amplitudes'} ${Math.abs(am) >= Math.abs(prev[marked[0]]) ? (M === 1 ? 'grows' : 'grow') : M === 1 ? 'shrinks' : 'shrink'} to ${fx(am, 4)} and the others become ${fx(other, 4)}. The chance of success is now ${fx(g.success[k], 4)}, which is sin²(${2 * k + 1}θ).`, facts: { k, amp: am, other, mean, p: g.success[k], formula: Math.sin((2 * k + 1) * theta) ** 2 }, meta: { stage: 'diffuse', k, p: g.success[k], next: Math.sin((2 * k + 3) * theta) ** 2 } });
    }
    const pk = g.success[K], next = Math.sin((2 * K + 3) * theta) ** 2, classical = (N + 1) / (M + 1);
    F.add({ items: scene(g.amps[K], K, 'end', undefined, K), hl: { d: [3, 4] }, say: (K === best ? `${K} ${K === 1 ? 'iteration is' : 'iterations are'} the best, about (π/4)·√(${N}/${M}). Measuring now gives a marked index with chance ${fx(pk, 4)}; one more iteration would go past the peak, to ${fx(next, 4)}.` : K > best ? `${K} iterations went past the best (${best}): the chance has fallen to ${fx(pk, 4)}. The state keeps turning, so too much amplification undoes itself.` : `After ${K} ${K === 1 ? 'iteration' : 'iterations'} the chance is ${fx(pk, 4)}; the best would be ${best}.`) + ` A classical search tries about ${fx(classical, 1)} indices on average; Grover needs about √N oracle calls, a quadratic speed-up.`, facts: { K, best, p: pk, next, classical, N, M }, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Grover\'s iteration', ['start: every amplitude 1/√N', 'oracle: a_w ← −a_w for each marked w', 'diffusion: a_i ← 2·mean − a_i', 'θ = arcsin √(M/N) = ' + fx(theta, 4) + ',  best k ≈ (π/4)·√(N/M) = ' + best, 'P(marked after k) = sin²((2k + 1)θ)']) };
  }
  S.topic({
    id: 'pq-grover', family: 'p14-quantum', order: 10, title: 'Grover\'s search as bars',
    blurb: 'An oracle that flips the sign of the right answer, and a reflection about the mean that turns the flip into height. After about √N rounds the marked index is almost certain; after more it fades again.',
    inputs: [
      { id: 'n', kind: 'choice', label: 'Qubits', def: '4', options: [2, 3, 4, 5, 6].map((v) => ({ value: String(v), label: v + ' (N = ' + 2 ** v + ')' })) },
      { id: 'marked', kind: 'list', label: 'Marked indices', def: ['11'], min: 1, max: 4, check: (v, inp) => { const N = 2 ** +inp.n; if (v.some((x) => !/^\d+$/.test(x) || +x >= N)) return 'Marked indices: whole numbers from 0 to ' + (N - 1); if (new Set(v.map(Number)).size !== v.length) return 'Marked indices: each once'; if (v.length * 4 > N) return 'Marked indices: at most a quarter of the ' + N; return null; } },
      { id: 'iters', kind: 'choice', label: 'Iterations', def: 'best', options: [{ value: 'best', label: 'the best number' }, { value: 'over', label: 'too many (twice the best, plus one)' }, { value: '1', label: 'just one' }] },
    ],
    presets: [
      { label: 'N = 16, one marked', values: { n: '4', marked: ['11'], iters: 'best' } },
      { label: 'N = 4: one iteration is exact', values: { n: '2', marked: ['2'], iters: 'best' } },
      { label: 'N = 64, one marked', values: { n: '6', marked: ['37'], iters: 'best' } },
      { label: 'N = 32, two marked', values: { n: '5', marked: ['6', '25'], iters: 'best' } },
      { label: 'Too many iterations', values: { n: '4', marked: ['5'], iters: 'over' } },
    ],
    counters: [{ id: 'iteration', label: 'iterations' }, { id: 'oracle', label: 'oracle calls' }],
    run: grover,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'start', pick: 'item', ask: 'The oracle is about to act. Click the bar it changes.', answer: (fr, i, inp) => inp.marked.map((m) => 'gb:b' + +m), explain: 'The oracle only flips the sign of the marked amplitude; its height (and the chance of measuring it) is unchanged.' },
      { at: (f, i, fr) => f.meta && f.meta.stage === 'oracle' && f.meta.k === 1, pick: 'option', options: ['grows', 'shrinks', 'stays the same'], ask: 'Each amplitude is about to become 2 × mean − itself. The marked one is far below the mean. Does it grow or shrink in size?', answer: 'grows', explain: 'Reflecting a value far below the mean puts it as far above: it grows.' },
      { at: (f, i, fr) => f.meta && f.meta.stage === 'diffuse' && fr[i + 1] && fr[i + 1].meta.stage === 'end', pick: 'option', options: ['rise', 'fall'], ask: 'If we ran one more iteration, would the chance of success rise or fall?', answer: (fr, i) => (fr[i].meta.next > fr[i].meta.p ? 'rise' : 'fall'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What does Grover\'s oracle do to the marked amplitude?', options: ['Doubles it', 'Flips its sign', 'Sets it to 1', 'Measures it'], answer: 1, why: 'A sign flip changes no probability by itself; the reflection about the mean turns it into growth.' },
      { q: 'About how many iterations does Grover need for N items and one marked?', options: ['N', 'N/2', '(π/4)·√N', 'log₂ N'], answer: 2, why: 'Each iteration turns the state by 2θ with sin θ = 1/√N, so about (π/4)·√N iterations reach the marked state.' },
      { q: 'What happens if you run twice the best number of iterations?', options: ['Success becomes certain', 'The chance of success falls again', 'Nothing changes', 'The register breaks'], answer: 1, why: 'The state keeps rotating past the marked direction, so the chance follows sin² back down.' },
      { q: 'Against AES-128 key search, Grover gives about…', options: ['2^128 work', '2^64 work', '2^32 work', 'polynomial work'], answer: 1, why: 'A quadratic speed-up halves the exponent; that is why AES-256 is recommended for the long term.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Shor
  // ---------------------------------------------------------------------------------------------------------------
  function shor(inp) {
    const N = +inp.N, Qe = Q();
    const r = Qe.shor(N, { a: +inp.a, seed: +inp.seed });
    const F = new S.Frames(['attempts']);
    // the modular powers as a strip of cells, the probability spikes, the measurement panel, the result lines
    const strip = (period, a) => {
      const items = [], n = Math.min(22, Math.max(period ? 2 * period + 2 : 12, 12)), cw = Math.min(44, 860 / n - 3);
      items.push(U.t('sh:sl', 30, 66, `${a}^x mod ${N}, for x = 0, 1, 2, …`, 'strong', 'start', 14));
      for (let x = 0; x < n; x++) {
        const v = Qe.powmod(a, x, N), first = period && x < period;
        items.push({ key: 'sh:p' + x, kind: 'cell', x: U.r2(30 + x * (cw + 3)), y: 118, w: U.r2(cw), h: 34, rx: 3, text: String(v), size: 14, cls: 'hex ' + (v === 1 ? 'key' : first ? 'act' : '') });
        if (x % (period || 99) === 0) items.push(U.t('sh:px' + x, U.r2(30 + x * (cw + 3) + cw / 2), 172, 'x = ' + x, 'tick', 'middle', 13));
      }
      if (period) items.push({ key: 'sh:br', kind: 'bracket', x1: 30, x2: U.r2(30 + period * (cw + 3) - 3), y: 112, side: 'above', text: 'period r = ' + period, cls: 'act' });
      return items;
    };
    const spikes = (probs, Qn, y, period) => {
      const top = Math.max(...probs) * 1.15;
      const pl = U.plot({ prefix: 'sq', x: 60, y: 214, w: 600, h: 290, xr: [0, Qn], yr: [0, top], xticks: [0, Qn / 4, Qn / 2, (3 * Qn) / 4, Qn], yticks: [], ylabel: `chance of measuring y, for 0 ≤ y < Q = ${Qn}`, tickSize: 13 });
      // one column a pixel: the largest chance in it, so every peak shows
      const cols = 300, d = [`M${pl.X(0)},${pl.Y(0)}`];
      for (let c = 0; c < cols; c++) {
        const lo = Math.floor((c * Qn) / cols), hi = Math.max(lo + 1, Math.floor(((c + 1) * Qn) / cols));
        let m = 0; for (let k = lo; k < hi; k++) m = Math.max(m, probs[k]);
        d.push(`L${pl.X(lo)},${pl.Y(m)} L${pl.X(hi)},${pl.Y(m)}`);
      }
      d.push(`L${pl.X(Qn)},${pl.Y(0)} Z`);
      const items = pl.items.concat([{ key: 'sq:l', kind: 'path', d: d.join(' '), cls: 'dline prob', audit: 'ignore' }]);
      const peaks = Array.from({ length: period }, (_, j) => Math.round((j * Qn) / period));
      if (600 / period >= String(Qn).length * 9 + 10) peaks.forEach((p, j) => j && items.push(U.t('sq:pk' + j, pl.X(p + 0.5), pl.Y(probs[p]) - 9, String(p), 'tick', 'middle', 14)));
      if (y !== undefined) {
        items.push({ key: 'sq:y', kind: 'dot', x: pl.X(y + 0.5), y: pl.Y(probs[y]), r: 6, cls: 'hot', point: true });
        items.push({ key: 'sq:ym', kind: 'head', x: pl.X(y + 0.5), y: pl.Y(0) + 26, text: 'y = ' + y, side: 'below', cls: 'hot' });
      }
      return items;
    };
    const head = () => U.t('sh:h', 30, 34, `Factor N = ${N} with Shor's algorithm`, 'strong', 'start', 16);
    let a = null, period = null, qft = null, meas = null;
    const panel = () => {
      if (!meas) return [];
      const cv = meas.convergents, rows = [['y', String(meas.y)], ['y / Q', meas.y + ' / ' + qft.Q], ['≈', U.fx(meas.y / qft.Q, 5)]];
      const items = U.readout('sh:m', 690, 214, 216, 'measured', rows);
      items.push(U.t('sh:m:ct', 704, 380, 'convergents of y/Q', 'title'));
      cv.slice(-5).forEach((c, j, l) => items.push(U.t('sh:m:c' + j, 704, 408 + 24 * j, c.p + '/' + c.q, j === l.length - 1 ? 'act' : 'mono', 'start', 15)));
      if (!cv.length) items.push(U.t('sh:m:c0', 704, 408, 'none below N', 'mono', 'start', 15));
      return items;
    };
    const res = (lines) => lines.map(([t, c], j) => U.t('sh:res' + j, 30, 584 + 30 * j, t, c, 'start', 15));
    const scene = (extra) => [head()].concat(a !== null ? strip(period, a) : [], qft ? spikes(qft.probs, qft.Q, meas ? meas.y : undefined, period) : [], panel(), extra || []);
    for (const st of r.trace) {
      if (st.kind === 'choose') {
        a = st.a; period = null; qft = null; meas = null; F.count('attempts');
        F.add({ items: scene(), say: st.say + ` The quantum part will look for the period of x ↦ ${a}^x mod ${N}.`, facts: { a }, meta: { stage: 'choose' } });
      } else if (st.kind === 'lucky' || st.kind === 'even' || st.kind === 'power') {
        F.add({ items: scene(res([[st.say, 'good']])), say: st.say, facts: { g: st.g, a }, meta: { stage: 'lucky' } });
      } else if (st.kind === 'modexp') {
        period = st.r;
        F.add({ items: scene(), hl: { d: [1] }, say: st.say, facts: { r: period, table: st.table.slice(0, 12) }, meta: { stage: 'modexp', r: period } });
      } else if (st.kind === 'qft') {
        qft = st;
        F.add({ items: scene(), hl: { d: [2] }, say: st.say + ` There are ${period} peaks, each with a chance of about 1/${period}.`, facts: { t: st.t, Q: st.Q, r: period, Qr: st.Q / period }, meta: { stage: 'qft', r: period } });
      } else if (st.kind === 'measure') {
        meas = st;
        F.add({ items: scene(), hl: { d: [3] }, say: st.say, facts: { y: st.y, Q: qft.Q, yq: st.y / qft.Q, convergents: st.convergents.map((c) => c.p + '/' + c.q) }, meta: { stage: 'measure' } });
      } else if (st.kind === 'factor') {
        F.add({ items: scene(res([[`${a}^(r/2) mod ${N} = ${st.h}`, 'act'], [`gcd(${st.h} − 1, ${N}) = ${st.f1},  gcd(${st.h} + 1, ${N}) = ${st.f2}`, 'good']])), hl: { d: [4] }, say: st.say, facts: { h: st.h, f1: st.f1, f2: st.f2 }, meta: { stage: 'factor' } });
      } else F.add({ items: scene(res([[st.say, st.kind === 'period' ? 'act' : 'hot']])), hl: { d: st.kind === 'period' ? [3] : [4] }, say: st.say, facts: { r: st.r, a }, meta: { stage: st.kind } });
    }
    const imp = Qe.impact(), rsa = imp.find((x) => x.primitive === 'RSA-2048'), ecc = imp.find((x) => x.primitive === 'ECC P-256');
    const fac = r.factors;
    F.add({ items: scene(res([[fac ? `${N} = ${fac[0]} × ${fac[1]}` : 'no factor this time', 'good'], [`RSA-2048: ${rsa.classical} bits of security classically, ${rsa.quantum} against Shor.  P-256: ${ecc.classical} → ${ecc.quantum}.`, 'strong']])), hl: { d: [5] }, say: (fac ? `${N} = ${fac[0]} × ${fac[1]}. ` : '') + `Only the period finding needs a quantum computer; the rest is classical. For RSA-2048 the same steps take a number of operations polynomial in 2048, so its ${rsa.classical} bits of classical security drop to ${rsa.quantum}; Shor's method works in any group, so P-256 goes from ${ecc.classical} to ${ecc.quantum} too. No larger key helps: RSA and elliptic curves must be replaced.`, facts: { f: fac, bits: 2048, rsaC: rsa.classical, rsaQ: rsa.quantum, eccC: ecc.classical, eccQ: ecc.quantum }, meta: { stage: 'end' } });
    for (const f of F.list) f.facts = Object.assign({ N }, f.facts);
    U.fix(F.list);
    return { frames: F.list, def: U.def('Shor\'s algorithm', ['pick a < N; if gcd(a, N) > 1 we are done', 'period r: the least r > 0 with a^r ≡ 1 (mod N)', 'QFT of the first register: peaks near y ≈ j·Q/r', 'continued fraction of y/Q → a fraction j/r', 'r even, a^(r/2) ≢ −1: gcd(a^(r/2) ± 1, N) are factors', 'RSA and ECC: polynomial time, so no key size is safe']) };
  }
  const SHOR_N = [15, 21, 33, 35, 39, 51, 55, 57, 65, 77, 85, 91];
  S.topic({
    id: 'pq-shor', family: 'p14-quantum', order: 20, title: 'Shor\'s period finding',
    blurb: 'Factoring reduces to finding the period of a^x mod N. The quantum Fourier transform turns that period into evenly spaced peaks; one measurement and a continued fraction give it back, and two gcds give the factors.',
    inputs: [
      { id: 'N', kind: 'choice', label: 'N', def: '21', options: SHOR_N.map((v) => ({ value: String(v), label: String(v) })) },
      { id: 'a', kind: 'number', label: 'a', def: 2, min: 2, check: (v, inp) => (v >= +inp.N - 1 ? 'a: below N − 1' : null) },
      { id: 'seed', kind: 'number', label: 'Measurement seed', def: 5, min: 1, max: 999 },
    ],
    presets: [
      { label: 'N = 21, a = 2', values: { N: '21', a: 2, seed: 5 } },
      { label: 'N = 15, a = 7', values: { N: '15', a: 7, seed: 3 } },
      { label: 'N = 35, a = 3', values: { N: '35', a: 3, seed: 8 } },
      { label: 'N = 91, a = 5', values: { N: '91', a: 5, seed: 2 } },
      { label: 'N = 21, a = 6 (lucky gcd)', values: { N: '21', a: 6, seed: 5 } },
    ],
    counters: [{ id: 'attempts', label: 'choices of a' }],
    run: shor,
    predict: [
      { at: (f, i, fr) => f.meta && f.meta.stage === 'modexp' && fr[i + 1] && fr[i + 1].meta.stage === 'qft', pick: 'option', options: (fr, i) => { const r = fr[i].meta.r; return [...new Set([1, 2, r, r + 1, 2 * r])].sort((x, y) => x - y).map(String); }, ask: 'After the Fourier transform the first register will have peaks. How many?', answer: (fr, i) => String(fr[i].meta.r), explain: 'One peak for each multiple j·Q/r with j from 0 to r − 1: r peaks.' },
    ],
    quiz: [
      { q: 'What does the quantum computer actually find in Shor\'s algorithm?', options: ['The factors directly', 'The period of a^x mod N', 'The private exponent d', 'A collision'], answer: 1, why: 'Everything else (the gcds, the continued fraction) is classical.' },
      { q: 'With a^r ≡ 1 (mod N), r even and a^(r/2) ≢ −1, a factor of N is…', options: ['gcd(a^(r/2) − 1, N)', 'a^r − 1', 'r/2', 'N mod a'], answer: 0, why: '(a^(r/2) − 1)(a^(r/2) + 1) ≡ 0 mod N, and neither factor is 0 mod N, so each shares a prime with N.' },
      { q: 'Why does the measured y give r?', options: ['y = r always', 'y/Q is close to j/r, and the continued fraction recovers that fraction', 'y is a factor of N', 'It does not'], answer: 1, why: 'The peaks sit near multiples of Q/r, so y/Q ≈ j/r with small denominator r.' },
      { q: 'What can be done about Shor against RSA?', options: ['Use RSA-4096', 'Use RSA-16384', 'Replace RSA with a post-quantum scheme', 'Nothing is needed'], answer: 2, why: 'Shor runs in polynomial time in the key length: a bigger key only delays it a little.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The table of security levels
  // ---------------------------------------------------------------------------------------------------------------
  function levels(inp) {
    const rows = Q().impact(), need = +inp.need;
    const F = new S.Frames(['ok', 'broken']);
    const x0 = 214, scale = 1.84, rowH = 62, top = 84, bottom = top + rows.length * rowH;
    const X = (b) => U.r2(x0 + b * scale);
    const scene = (upto, verdict) => {
      const items = [U.t('lv:h', 20, 34, `Bits of security against the best known attack, classical and quantum`, 'strong', 'start', 16)];
      for (const b of [0, 64, 128, 192, 256]) { items.push({ key: 'lv:g' + b, kind: 'path', d: `M${X(b)},${top - 4} V${bottom}`, cls: 'grid', audit: 'ignore', layer: 'back' }); items.push(U.t('lv:gt' + b, X(b), bottom + 20, String(b), 'tick', 'middle', 13)); }
      items.push({ key: 'lv:need', kind: 'path', d: `M${X(need)},${top - 12} V${bottom + 4}`, cls: 'needline', audit: 'ignore' });
      items.push(U.t('lv:needt', X(need), top - 18, 'target ' + need, 'hot', 'middle', 13));
      items.push(U.t('lv:hc', 790, top - 18, 'classical', 'title', 'end'));
      items.push(U.t('lv:hq', 900, top - 18, 'quantum', 'title', 'end'));
      rows.forEach((r, i) => {
        const y = top + i * rowH, on = i <= upto, ok = r.quantum >= need;
        items.push(U.t('lv:n' + i, x0 - 14, y + 30, r.primitive, on ? 'strong' : '', 'end', 15));
        items.push({ key: 'lv:c' + i, kind: 'cell', x: x0, y: y + 8, w: U.r2(r.classical * scale), h: 20, rx: 3, text: '', cls: 'bar soft' });
        items.push(U.t('lv:ct' + i, 790, y + 36, String(r.classical), 'mono', 'end', 15));
        if (on) {
          if (r.quantum > 0) items.push({ key: 'lv:q' + i, kind: 'cell', x: x0, y: y + 32, w: U.r2(r.quantum * scale), h: 20, rx: 3, text: '', cls: 'bar ' + (ok ? 'good' : 'hot') });
          items.push(U.t('lv:qt' + i, 900, y + 36, (ok ? '✓ ' : '✗ ') + r.quantum, ok ? 'good' : 'heat', 'end', 15));
        }
      });
      if (verdict) items.push(U.t('lv:v', 20, bottom + 64, verdict, 'strong', 'start', 15));
      items.push(...U.legend('lv:k', 20, bottom + 98, [['soft', 'classical'], ['good', 'quantum, meets the target'], ['hot', 'quantum, falls short']]));
      return items;
    };
    F.add({ items: scene(-1), say: `Seven primitives, each with its security in bits against the best known classical attack. Which still give ${need} bits against an attacker with a large quantum computer?`, facts: { need }, meta: { row: -1 } });
    rows.forEach((r, i) => {
      const ok = r.quantum >= need;
      F.count(ok ? 'ok' : 'broken');
      F.add({ items: scene(i), hl: { d: [/AES|SHA/.test(r.primitive) ? 0 : /KEM/.test(r.primitive) ? 3 : 1] }, say: `${r.primitive}: ${r.classical} bits classically, ${r.quantum} against a quantum attacker. ${r.note} ${ok ? `That meets ${need}.` : `That falls short of ${need}.`}`, facts: { classical: r.classical, quantum: r.quantum, need }, meta: { row: i, ok } });
    });
    const keep = rows.filter((r) => r.quantum >= need).map((r) => r.primitive);
    F.add({ items: scene(rows.length - 1, keep.length ? 'Meets the target: ' + keep.join(', ') : 'Nothing here meets the target'), hl: { d: [2, 3] }, say: `For ${need} bits against a quantum attacker: ${keep.length ? keep.join(', ') : 'none of these'}. Symmetric primitives survive by doubling their sizes, since Grover only halves the exponent; RSA and elliptic curves fall to Shor at any size and must give way to lattices, hashes or codes.`, facts: { need, count: keep.length }, meta: { row: rows.length } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Grover and Shor, in bits', ['Grover: key search in 2^(k/2), so k bits → k/2', 'Shor: factoring and discrete logs in polynomial time → 0', 'symmetric: double the key (AES-256), the hash (SHA-384/512)', 'public key: move to ML-KEM, ML-DSA, SLH-DSA']) };
  }
  S.topic({
    id: 'pq-levels', family: 'p14-quantum', order: 30, title: 'Security levels before and after',
    blurb: 'The bits of security of AES, SHA-256, RSA, elliptic curves and ML-KEM, classically and against a quantum attacker, held up against the level you need.',
    inputs: [{ id: 'need', kind: 'choice', label: 'Target', def: '128', options: ['64', '112', '128', '192'].map((v) => ({ value: v, label: v + ' bits' })) }],
    presets: [{ label: '128 bits', values: { need: '128' } }, { label: '192 bits', values: { need: '192' } }, { label: '64 bits', values: { need: '64' } }],
    counters: [{ id: 'ok', label: 'meet it' }, { id: 'broken', label: 'fall short' }],
    run: levels,
    predict: [{ at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta && fr[i + 1].meta.row === 0 && f.meta.row === -1, pick: 'option', options: ['128', '85', '64', '0'], ask: 'AES-128 has 128 bits of security classically. How many against Grover?', answer: '64', explain: 'Grover searches 2^128 keys in about 2^64 steps.' },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta && fr[i + 1].meta.row === 4, pick: 'option', options: ['112', '56', '0'], ask: 'RSA-2048 gives 112 bits classically. And against Shor?', answer: '0', explain: 'Shor factors in polynomial time: no security is left.' }],
    quiz: [
      { q: 'To keep 128-bit security against a quantum attacker, a symmetric cipher needs…', options: ['a 128-bit key', 'a 256-bit key', 'a 1024-bit key', 'no change'], answer: 1, why: 'Grover halves the exponent of exhaustive search.' },
      { q: 'Why does a bigger RSA modulus not help against Shor?', options: ['Shor runs in polynomial time in the size of N', 'RSA keys cannot grow', 'Shor only works on small N', 'It does help'], answer: 0, why: 'Doubling the key only multiplies the quantum work by a small polynomial factor.' },
      { q: 'Elliptic-curve keys against Shor are…', options: ['safe', 'broken just like RSA', 'safe if 521 bits', 'twice as strong'], answer: 1, why: 'Shor solves discrete logarithms in any group, curves included.' },
      { q: 'ML-KEM-768 is believed to give about…', options: ['0 bits against quantum attacks', '192 bits (category 3) against both', '64 bits', '1024 bits'], answer: 1, why: 'No quantum algorithm beyond small constant factors is known against Module-LWE.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
