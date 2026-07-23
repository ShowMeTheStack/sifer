// Differential and correlation power analysis on one key byte. Both keep running sums, so traces can be added in
// chunks (from a Web Worker, or a few hundred at a time between frames) and the answer read at any moment.
//   S.SC.CPA({byte, T, model: 'hw' | 'hd', target: 'sbox' | 'ark'}) -> {add(chunk), corr(), result(key?), n}
//      corr() -> Float64Array(256·T): ρ for guess g at sample t is corr[g·T + t]
//      result(key) -> {best, peaks: [max |ρ| per guess], peakSample, rank (of the true key byte), ranking}
//   S.SC.DPA({byte, T, bit}) -> {add(chunk), diff(), result(key?)}   difference of means on one bit of S(p ⊕ g)
//   S.SC.cpaRun({source, byte, key, total, chunk}) -> {progress: [{traces, rank, best, correct, wrong}], result, trace}
//   S.SC.cpaSteps(...) is the same as a generator that yields after each chunk.
//   S.SC.secondOrder(chunk, tA, tB) -> a one-sample chunk of centred products, for attacking a masked device
(function (S) {
  'use strict';
  const C = (S.SC = S.SC || {});
  /** the hypothetical leakage of the device for plaintext byte p under key guess g */
  C.hypo = (model, target) => {
    const SB = C.sbox(), HW = C.HW, h = new Float64Array(256 * 256);
    for (let g = 0; g < 256; g++) for (let p = 0; p < 256; p++) {
      const x = p ^ g, y = SB[x];
      h[g * 256 + p] = target === 'ark' ? HW[x] : model === 'hd' ? HW[x ^ y] : HW[y];
    }
    return h;
  };
  C.CPA = (opts = {}) => {
    const byte = opts.byte || 0, T = opts.T || 52, H = C.hypo(opts.model || 'hw', opts.target || 'sbox');
    const Sx = new Float64Array(T), Sxx = new Float64Array(T), Sh = new Float64Array(256), Shh = new Float64Array(256), Shx = new Float64Array(256 * T);
    let n = 0;
    const self = {
      get n() { return n; },
      add(chunk) {
        const { count, plaintexts, traces } = chunk, Tc = chunk.T;
        for (let i = 0; i < count; i++) {
          const p = plaintexts[i * 16 + byte], o = i * Tc;
          for (let t = 0; t < T; t++) { const x = traces[o + t]; Sx[t] += x; Sxx[t] += x * x; }
          for (let g = 0; g < 256; g++) {
            const h = H[g * 256 + p], b = g * T;
            Sh[g] += h; Shh[g] += h * h;
            for (let t = 0; t < T; t++) Shx[b + t] += h * traces[o + t];
          }
        }
        n += count;
        return self;
      },
      corr() {
        const out = new Float64Array(256 * T);
        for (let g = 0; g < 256; g++) {
          const vh = n * Shh[g] - Sh[g] * Sh[g];
          for (let t = 0; t < T; t++) {
            const vx = n * Sxx[t] - Sx[t] * Sx[t], d = Math.sqrt(vh * vx);
            out[g * T + t] = d > 0 ? (n * Shx[g * T + t] - Sh[g] * Sx[t]) / d : 0;
          }
        }
        return out;
      },
      result(key) { return rankOf(self.corr(), T, key); },
    };
    return self;
  };
  const rankOf = (vals, T, key) => {
    const peaks = new Float64Array(256), at = new Int32Array(256);
    for (let g = 0; g < 256; g++) for (let t = 0; t < T; t++) { const v = Math.abs(vals[g * T + t]); if (v > peaks[g]) { peaks[g] = v; at[g] = t; } }
    const ranking = Array.from({ length: 256 }, (_, g) => g).sort((a, b) => peaks[b] - peaks[a]);
    const best = ranking[0];
    return { best, peaks: Array.from(peaks), peakSample: at[best], peakAt: Array.from(at), ranking, rank: key == null ? null : ranking.indexOf(key) };
  };
  C.DPA = (opts = {}) => {
    const byte = opts.byte || 0, T = opts.T || 52, bit = opts.bit || 0, SB = C.sbox();
    const S1 = new Float64Array(256 * T), n1 = new Float64Array(256), Sall = new Float64Array(T);
    let n = 0;
    const self = {
      get n() { return n; },
      add(chunk) {
        const { count, plaintexts, traces } = chunk, Tc = chunk.T;
        for (let i = 0; i < count; i++) {
          const p = plaintexts[i * 16 + byte], o = i * Tc;
          for (let t = 0; t < T; t++) Sall[t] += traces[o + t];
          for (let g = 0; g < 256; g++) if ((SB[p ^ g] >> bit) & 1) { n1[g]++; const b = g * T; for (let t = 0; t < T; t++) S1[b + t] += traces[o + t]; }
        }
        n += count;
        return self;
      },
      /** mean of the traces whose predicted bit is 1, minus the mean of the rest */
      diff() {
        const out = new Float64Array(256 * T);
        for (let g = 0; g < 256; g++) { const a = n1[g], b = n - n1[g]; if (!a || !b) continue; for (let t = 0; t < T; t++) out[g * T + t] = S1[g * T + t] / a - (Sall[t] - S1[g * T + t]) / b; }
        return out;
      },
      result(key) { return rankOf(self.diff(), T, key); },
    };
    return self;
  };
  /** run CPA in chunks, recording the rank of the true key byte as traces accumulate */
  C.cpaSteps = function* (opts) {
    const src = opts.source, byte = opts.byte || 0, key = opts.key, total = opts.total || 1000, chunk = opts.chunk || 50;
    const cpa = C.CPA({ byte, T: src.T, model: opts.model || src.model, target: opts.target });
    const progress = [];
    while (cpa.n < total) {
      cpa.add(src.next(Math.min(chunk, total - cpa.n)));
      const r = cpa.result(key);
      const wrong = r.ranking.find((g) => g !== key);
      progress.push({ traces: cpa.n, rank: r.rank, best: r.best, correct: r.peaks[key], wrong: r.peaks[wrong] });
      yield { cpa, progress, last: r };
    }
  };
  C.cpaRun = (opts) => {
    let last = null;
    for (const s of C.cpaSteps(opts)) last = s;
    const byte = opts.byte || 0, key = opts.key, r = last.last, prog = last.progress, T = opts.source.T;
    const firstTop = prog.findIndex((p, i) => prog.slice(i).every((q) => q.rank === 0));
    const corr = last.cpa.corr();
    const trace = [
      C.step('cpa-model', `Predict the power of S(p ⊕ g) for every guess g of key byte ${byte} with the ${opts.model || opts.source.model || 'hw'} model, and correlate each prediction with every time sample.`, { byte }),
      C.step('cpa-plot', `After ${last.cpa.n} traces the best guess is ${C.h2(r.best)} with |ρ| = ${r.peaks[r.best].toFixed(3)} at sample ${r.peakSample}; the true byte ${C.h2(key)} ranks ${r.rank + 1}${r.rank === 0 ? ' (first)' : ''}.`, { corrBest: Array.from(corr.subarray(r.best * T, r.best * T + T)), corrTrue: Array.from(corr.subarray(key * T, key * T + T)), peaks: r.peaks }),
      C.step('cpa-rank', firstTop >= 0 ? `The true key byte reaches rank 1 for good after ${prog[firstTop].traces} traces.` : 'The true key byte has not settled at rank 1: more traces are needed, or the device does not leak at first order.', { progress: prog, settled: firstTop >= 0 ? prog[firstTop].traces : null }),
    ];
    return { result: r, progress: prog, corr, settled: firstTop >= 0 ? prog[firstTop].traces : null, trace };
  };
  /**
   * combine two time samples of each trace into their centred product (means taken over this chunk). Against a
   * device masked with one fresh mask, the product of the mask's leak and the masked value's leak correlates with
   * the unmasked value: a second-order attack.
   */
  C.secondOrder = (chunk, tA, tB) => {
    const { count, traces, T } = chunk;
    let mA = 0, mB = 0;
    for (let i = 0; i < count; i++) { mA += traces[i * T + tA]; mB += traces[i * T + tB]; }
    mA /= count; mB /= count;
    const out = new Float32Array(count);
    for (let i = 0; i < count; i++) out[i] = (traces[i * T + tA] - mA) * (traces[i * T + tB] - mB);
    return { count, T: 1, plaintexts: chunk.plaintexts, traces: out };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
