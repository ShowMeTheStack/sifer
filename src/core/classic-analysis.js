// Classical cryptanalysis: counting, measuring against English, and breaking. Every attack returns a trace.
//   S.Classic.freq(text)                     -> {counts, total, pct, ranked, trace}
//   S.Classic.ngrams(text, n, top)           -> [{gram, count, pct}]
//   S.Classic.chiSquared(textOrCounts)       -> {chi, terms, n}    against the standard English frequencies
//   S.Classic.ioc(text)                      -> {ioc, n, counts, trace}
//   S.Classic.kasiski(text, {minLen, maxFactor}) -> {repeats, votes, ranked, best, trace}
//   S.Classic.friedman(text)                 -> {ioc, estimate, trace}
//   S.Classic.periodIoC(text, maxLen)        -> [{len, avg, cols}]
//   S.Classic.columnShifts(text, len)        -> {key, columns, trace}   per-column chi-squared over the 26 shifts
//   S.Classic.breakVigenere(text, {maxLen})  -> {key, len, plain, kasiski, friedman, period, trace}
//   S.Classic.bruteShift(text) / bruteAffine(text) / bruteRailfence(text, max) -> ranked candidates
//   S.Classic.solveSubstitution(text, {seed, restarts, patience}) -> {alphabet, plain, score, trace}
//   S.Classic.substitutionSolver(text, opts) -> {run(ms) -> {done, progress, best}}  the same, in chunks
(function (S) {
  'use strict';
  const C = (S.Classic = S.Classic || {});
  const step = (kind, say, data) => S.Classic.step(kind, say, data);
  const { floor } = Math;
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const md = (n) => ((n % 26) + 26) % 26;
  const L = (i) => ABC[md(i)];
  const letters = (t) => String(t).toUpperCase().replace(/[^A-Z]/g, '');
  const idxs = (t) => Array.from(letters(t), (c) => c.charCodeAt(0) - 65);
  const f3 = (x) => x.toFixed(3), f4 = (x) => x.toFixed(4);
  const countsOf = (t) => { const c = new Array(26).fill(0); for (const ch of letters(t)) c[ch.charCodeAt(0) - 65]++; return c; };

  C.freq = (text) => {
    const counts = countsOf(text), total = counts.reduce((a, b) => a + b, 0);
    const pct = counts.map((c) => (total ? (100 * c) / total : 0));
    const ranked = counts.map((c, i) => ({ letter: ABC[i], count: c, pct: pct[i] })).sort((a, b) => b.count - a.count || (a.letter < b.letter ? -1 : 1));
    const top = ranked.slice(0, 6).map((r) => `${r.letter} ${r.count}`).join(', ');
    return { counts, total, pct, ranked, trace: [step('freq', `${total} letters; the commonest are ${top}. In English the commonest are E, T, A, O, I, N.`, { counts, total, ranked: ranked.map((r) => r.letter).join('') })] };
  };
  C.ngrams = (text, n = 2, top = 20) => {
    const t = letters(text), m = new Map();
    for (let i = 0; i + n <= t.length; i++) { const g = t.substr(i, n); m.set(g, (m.get(g) || 0) + 1); }
    const tot = Math.max(1, t.length - n + 1);
    return [...m].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, top).map(([gram, count]) => ({ gram, count, pct: (100 * count) / tot }));
  };
  /** Σ (observed − expected)² / expected over the 26 letters, expected from the English frequencies */
  C.chiSquared = (x) => {
    const counts = Array.isArray(x) ? x : countsOf(x), n = counts.reduce((a, b) => a + b, 0);
    let chi = 0; const terms = [];
    for (let i = 0; i < 26; i++) { const e = (n * C.ENGLISH[i]) / 100, t = e ? ((counts[i] - e) ** 2) / e : 0; terms.push(t); chi += t; }
    return { chi, terms, n };
  };
  C.ioc = (text) => {
    const counts = countsOf(text), n = counts.reduce((a, b) => a + b, 0);
    const pairs = counts.reduce((s, c) => s + c * (c - 1), 0), ioc = n > 1 ? pairs / (n * (n - 1)) : 0;
    return { ioc, n, counts, trace: [step('ioc', `Σ nᵢ(nᵢ−1) = ${pairs} over N(N−1) = ${n * (n - 1)} gives an index of coincidence of ${f4(ioc)} (English is about ${f4(C.model().kappa)}, random letters ${f4(1 / 26)}).`, { ioc, n, pairs })] };
  };

  /** Kasiski: repeated sequences, the distances between them, and votes for the factors of those distances */
  C.kasiski = (text, opts = {}) => {
    const t = letters(text), minLen = opts.minLen || 3, maxLen = opts.maxLen || 12, maxFactor = opts.maxFactor || 20;
    const found = new Map();
    for (let len = maxLen; len >= minLen; len--) {
      const seen = new Map();
      for (let i = 0; i + len <= t.length; i++) { const g = t.substr(i, len); if (!seen.has(g)) seen.set(g, []); seen.get(g).push(i); }
      for (const [g, pos] of seen) {
        if (pos.length < 2) continue;
        // keep only maximal repeats: skip a gram whose occurrences all sit inside a longer repeat already found
        let inside = false; for (const [h, p2] of found) if (h.length > len && h.includes(g) && pos.every((q) => p2.some((r) => q >= r && q + len <= r + h.length))) { inside = true; break; }
        if (!inside) found.set(g, pos);
      }
    }
    const repeats = [], votes = new Array(maxFactor + 1).fill(0), trace = [];
    for (const [gram, positions] of found) {
      const distances = []; for (let k = 1; k < positions.length; k++) distances.push(positions[k] - positions[0]);
      const g = C.gcdAll(distances);
      for (const d of distances) for (let f = 2; f <= maxFactor; f++) if (d % f === 0) votes[f]++;
      repeats.push({ gram, positions, distances, gcd: g });
    }
    repeats.sort((a, b) => b.gram.length - a.gram.length || a.positions[0] - b.positions[0]);
    for (const r of repeats.slice(0, 12)) trace.push(step('kasiski-repeat', `${r.gram} appears at ${r.positions.join(', ')}; the distance${r.distances.length > 1 ? 's are ' : ' is '}${r.distances.join(', ')}, with gcd ${r.gcd}.`, r));
    const ranked = votes.map((v, f) => ({ factor: f, votes: v })).slice(2).sort((a, b) => b.votes - a.votes || b.factor - a.factor);
    // the key length is the largest factor that nearly every distance shares: a multiple of it collects fewer votes
    const total = repeats.reduce((s, r) => s + r.distances.length, 0);
    let best = null; if (total) { const strong = ranked.filter((r) => r.votes >= 0.7 * ranked[0].votes); best = strong.reduce((m, r) => (r.factor > m.factor ? r : m), strong[0]).factor; }
    trace.push(step('kasiski-votes', total ? `Of ${total} distances, ${ranked.slice(0, 5).map((r) => `${r.votes} are multiples of ${r.factor}`).join(', ')}. The key length is probably ${best}.` : 'No repeated sequences were found, so Kasiski gives no evidence here.', { votes, best, total }));
    return { repeats, votes, ranked, best, total, trace };
  };

  /** Friedman: the key length that makes the index of coincidence come out as observed */
  C.friedman = (text) => {
    const { ioc, n } = C.ioc(text), kp = C.model().kappa, kr = 1 / 26;
    const est = n > 1 ? ((kp - kr) * n) / ((n - 1) * ioc - kr * n + kp) : 0;
    return { ioc, n, estimate: est, trace: [step('friedman', `With N = ${n} and IC = ${f4(ioc)}, the estimate L ≈ (κp − κr)·N / ((N − 1)·IC − κr·N + κp) = ${est.toFixed(2)}, with κp = ${f4(kp)} and κr = ${f4(kr)}.`, { ioc, n, estimate: est })] };
  };
  C.columns = (text, len) => { const t = letters(text), cols = Array.from({ length: len }, () => ''); for (let i = 0; i < t.length; i++) cols[i % len] += t[i]; return cols; };
  C.periodIoC = (text, maxLen = 20) => {
    const out = [];
    for (let len = 1; len <= maxLen; len++) { const cols = C.columns(text, len), v = cols.map((c) => C.ioc(c).ioc); out.push({ len, avg: v.reduce((a, b) => a + b, 0) / len, cols: v }); }
    return out;
  };
  /** for each column, the shift whose undoing best fits English by chi-squared */
  C.columnShifts = (text, len) => {
    const cols = C.columns(text, len), columns = [], trace = [];
    cols.forEach((col, i) => {
      const c = countsOf(col), chis = [];
      for (let s = 0; s < 26; s++) { const sh = new Array(26); for (let k = 0; k < 26; k++) sh[k] = c[md(k + s)]; chis.push(C.chiSquared(sh).chi); }
      let best = 0; for (let s = 1; s < 26; s++) if (chis[s] < chis[best]) best = s;
      const second = Math.min(...chis.filter((_, s) => s !== best));
      columns.push({ col: i, text: col, chis, shift: best, letter: L(best), margin: second - chis[best] });
      trace.push(step('column-shift', `Column ${i + 1} (${col.length} letters): undoing a shift of ${best} gives χ² = ${chis[best].toFixed(1)}, the best of 26 (next best ${second.toFixed(1)}), so key letter ${i + 1} is ${L(best)}.`, { col: i, shift: best, chi: chis[best], chis }));
    });
    return { key: columns.map((c) => c.letter).join(''), columns, trace };
  };
  const vigDecIdx = (x, k) => x.map((v, i) => md(v - k[i % k.length]));

  /** Vigenère broken in three moves: Kasiski, the index of coincidence (Friedman and per-column), and the shifts */
  C.breakVigenere = (text, opts = {}) => {
    const t = letters(text), x = idxs(t), maxLen = Math.min(opts.maxLen || 20, Math.max(1, floor(t.length / 4)));
    const trace = [step('vig-start', `The ciphertext has ${t.length} letters. First find the key length, then each key letter.`, { n: t.length })];
    const kas = C.kasiski(t, { maxFactor: maxLen }); trace.push(...kas.trace);
    const fr = C.friedman(t); trace.push(...fr.trace);
    const per = C.periodIoC(t, maxLen), top = Math.max(...per.map((p) => p.avg));
    trace.push(step('period-ioc', `Splitting into columns: the average column IC is ${per.slice(0, 10).map((p) => `${p.len}: ${f3(p.avg)}`).join(', ')}${per.length > 10 ? ' …' : ''}. Columns of the right length look like English (about ${f3(C.model().kappa)}).`, { period: per }));
    // candidates: lengths whose columns look English, tried with their shifts and judged by quadgram score
    const cands = per.filter((p) => p.avg >= Math.min(0.055, top * 0.9)).map((p) => p.len);
    if (kas.best && !cands.includes(kas.best)) cands.push(kas.best);
    const fl = Math.max(1, Math.round(fr.estimate)); if (fl <= maxLen && !cands.includes(fl)) cands.push(fl);
    let best = null;
    for (const len of cands.slice(0, 8)) {
      const cs = C.columnShifts(t, len), k = cs.columns.map((c) => c.shift), polished = polishKey(x, k);
      const plain = vigDecIdx(x, polished.key), score = C.scoreIdx(plain) / Math.max(1, x.length - 3);
      if (!best || score > best.score + 0.02 || (Math.abs(score - best.score) <= 0.02 && len < best.len)) best = { len, cs, key: polished.key, changed: polished.changed, score };
    }
    trace.push(step('vig-length', `The key length is ${best.len}${kas.best === best.len ? ', in agreement with Kasiski' : ''}.`, { len: best.len, candidates: cands }));
    trace.push(...best.cs.trace);
    if (best.changed.length) trace.push(step('vig-polish', `Short columns can mislead χ²; trying each key letter again against the quadgram score changes ${best.changed.map((c) => `letter ${c.at + 1} from ${L(c.from)} to ${L(c.to)}`).join(', ')}.`, { changed: best.changed }));
    const key = best.key.map(L).join(''), plain = vigDecIdx(x, best.key).map(L).join('');
    trace.push(step('vig-done', `The key is ${key}; the message begins ${plain.slice(0, 40)}.`, { key, plain }));
    return { key, len: best.len, plain, kasiski: kas, friedman: fr, period: per, trace };
  };
  /** coordinate ascent: each key letter in turn takes the value that maximises the quadgram score of the whole text */
  function polishKey(x, key) {
    const k = key.slice(), changed = [];
    for (let round = 0; round < 3; round++) {
      let moved = false;
      for (let i = 0; i < k.length; i++) {
        let bestS = -Infinity, bestV = k[i];
        for (let v = 0; v < 26; v++) { k[i] = v; const s = C.scoreIdx(vigDecIdx(x, k)); if (s > bestS) { bestS = s; bestV = v; } }
        if (bestV !== key[i] && !changed.some((c) => c.at === i)) changed.push({ at: i, from: key[i], to: bestV });
        if (k[i] !== bestV) moved = true;
        k[i] = bestV;
      }
      if (!moved) break;
    }
    return { key: k, changed: changed.filter((c) => k[c.at] !== c.from).map((c) => ({ ...c, to: k[c.at] })) };
  }

  /** every shift, ranked by quadgram score (and chi-squared shown beside it) */
  C.bruteShift = (text) => {
    const x = idxs(text), rows = [];
    for (let k = 0; k < 26; k++) { const p = x.map((v) => md(v - k)); rows.push({ k, chi: C.chiSquared(p.map(L).join('')).chi, score: C.scoreIdx(p) / Math.max(1, p.length - 3), plain: p.map(L).join('') }); }
    const ranked = rows.slice().sort((a, b) => b.score - a.score);
    return { rows, ranked, best: ranked[0], trace: [step('brute-shift', `All 26 shifts tried; the best by quadgram score is ${ranked[0].k} (χ² ${ranked[0].chi.toFixed(1)}), giving ${ranked[0].plain.slice(0, 30)}.`, { k: ranked[0].k })] };
  };
  C.bruteAffine = (text) => {
    const x = idxs(text), rows = [];
    for (const [a, b] of C.affine.keys()) {
      const ai = C.inverse(a).inv, p = x.map((v) => md(ai * (v - b)));
      rows.push({ a, b, chi: C.chiSquared(p.map(L).join('')).chi, score: C.scoreIdx(p) / Math.max(1, p.length - 3), plain: p.map(L).join('') });
    }
    const ranked = rows.slice().sort((a, b) => b.score - a.score);
    return { rows, ranked, best: ranked[0], trace: [step('brute-affine', `All ${rows.length} keys (12 values of a coprime to 26, times 26 values of b) tried; the best is a = ${ranked[0].a}, b = ${ranked[0].b}, giving ${ranked[0].plain.slice(0, 30)}.`, { a: ranked[0].a, b: ranked[0].b })] };
  };
  C.bruteRailfence = (text, max = 10) => {
    const rows = [];
    for (let r = 2; r <= max; r++) { const p = C.railfence.decrypt(text, r).out; rows.push({ rails: r, score: C.score(p, true), plain: p }); }
    const ranked = rows.slice().sort((a, b) => b.score - a.score);
    return { rows, ranked, best: ranked[0] };
  };

  /* ---- the substitution solver: hill climbing on quadgram scores, from a seed ---- */
  C.substitutionSolver = (text, opts = {}) => {
    const x = Int8Array.from(idxs(text)), n = x.length, rand = C.rng(opts.seed == null ? 1 : opts.seed);
    const restarts = opts.restarts || 12, patience = opts.patience || 1500;
    const q = C.model().quad, buf = new Int8Array(n), trace = [];
    const fit = (key) => { for (let i = 0; i < n; i++) buf[i] = key[x[i]]; let s = 0; for (let i = 0; i + 4 <= n; i++) s += q[((buf[i] * 26 + buf[i + 1]) * 26 + buf[i + 2]) * 26 + buf[i + 3]]; return s; };
    // the start: the commonest cipher letter becomes E, the next T, and so on down the English order
    const order = C.ENGLISH.map((p, i) => [p, i]).sort((a, b) => b[0] - a[0]).map((e) => e[1]);
    const cnt = new Array(26).fill(0); for (const v of x) cnt[v]++;
    const byCount = cnt.map((c, i) => [c, i]).sort((a, b) => b[0] - a[0] || a[1] - b[1]).map((e) => e[1]);
    const freqKey = new Array(26); byCount.forEach((c, r) => { freqKey[c] = order[r]; });
    const show = (key) => Array.from(x.slice(0, 40), (v) => L(key[v])).join('');
    let best = { key: freqKey.slice(), score: fit(freqKey) }, restart = 0, key = null, cur = 0, fails = 0, swaps = 0;
    trace.push(step('sub-start', `Start from frequency order (commonest cipher letter = E, next = T, …): ${show(freqKey)}…, score ${best.score.toFixed(1)}.`, { key: freqKey.map(L).join(''), score: best.score }));
    const begin = () => {
      key = restart === 0 ? freqKey.slice() : best.key.slice();
      if (restart > 0) for (let k = 0; k < 4 + (restart % 5); k++) { const a = floor(rand() * 26), b = floor(rand() * 26); [key[a], key[b]] = [key[b], key[a]]; }
      cur = fit(key); fails = 0;
    };
    begin();
    const api = {
      run(budget = Infinity) {
        const t0 = Date.now();
        while (restart < restarts) {
          for (let it = 0; it < 2000 && fails < patience; it++) {
            const a = floor(rand() * 26), b = floor(rand() * 26); if (a === b) continue;
            [key[a], key[b]] = [key[b], key[a]]; swaps++;
            const s = fit(key);
            if (s > cur) { cur = s; fails = 0; if (s > best.score + 1e-9) { best = { key: key.slice(), score: s }; trace.push(step('sub-better', `Swap after ${swaps} tries: ${show(key)}…, score ${s.toFixed(1)}.`, { key: key.map(L).join(''), score: s, swaps, restart })); } }
            else { [key[a], key[b]] = [key[b], key[a]]; fails++; }
          }
          if (fails >= patience) { restart++; if (restart < restarts) begin(); }
          if (Date.now() - t0 > budget) break;
        }
        const done = restart >= restarts;
        return { done, progress: Math.min(1, (restart + Math.min(1, fails / patience)) / restarts), best: api.result() };
      },
      result() {
        // the solver's key maps cipher letters to plain letters; the cipher alphabet maps plain to cipher
        const alpha = new Array(26); for (let c = 0; c < 26; c++) alpha[best.key[c]] = L(c);
        return { decryptKey: best.key.map(L).join(''), alphabet: alpha.join(''), plain: C.substitution.decrypt(text, alpha.join('')).out, score: best.score, perLetter: best.score / Math.max(1, n - 3), swaps, trace };
      },
    };
    return api;
  };
  C.solveSubstitution = (text, opts) => { const s = C.substitutionSolver(text, opts); s.run(); return s.result(); };
})(globalThis.Sifer = globalThis.Sifer || {});
