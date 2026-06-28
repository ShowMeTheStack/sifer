// Letters, numbers mod 26 and the English reference model that every classical attack measures against.
//   S.Classic.ABC, idx(ch), chr(i), mod(n, m), letters(text) -> 'ONLYUPPERCASELETTERS'
//   S.Classic.egcd(a, b)         -> {g, x, y, rows, trace}   extended Euclid as a table that fills in row by row
//   S.Classic.inverse(a, m)      -> {inv | null, g, rows, trace}
//   S.Classic.gcd(a, b), gcdAll(list)
//   S.Classic.rng(seed)          -> a deterministic generator of floats in [0, 1)
//   S.Classic.ENGLISH            -> the standard published English letter frequencies, in percent, A..Z
//   S.Classic.model()            -> {letters, bigrams, trigrams, quad, floor, kappa}  built once, lazily, from the corpus
//   S.Classic.score(text)        -> the quadgram log-likelihood of a text (higher is more English)
//   S.Classic.groups(text, n)    -> text in groups of n letters, as a cipher clerk writes it
(function (S) {
  'use strict';
  const C = (S.Classic = S.Classic || {});
  // a negative number in a sentence gets a true minus sign, not a hyphen
  const minus = (say) => String(say).replace(/(^|[\s(=·×+−,\[/:])-(?=\d)/g, '$1−');
  const step = (kind, say, data) => Object.assign({ kind, say: minus(say) }, data || {});
  const { imul, log10, max } = Math;   // local copies: hot loops should not look up globals
  C.step = step;
  C.minus = minus;
  C.ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  C.idx = (ch) => ch.toUpperCase().charCodeAt(0) - 65;
  C.chr = (i) => String.fromCharCode(65 + (((i % 26) + 26) % 26));
  C.mod = (n, m = 26) => ((n % m) + m) % m;
  C.isLetter = (ch) => /^[A-Za-z]$/.test(ch);
  /** the letters of a text, upper case, everything else removed */
  C.letters = (t) => String(t).toUpperCase().replace(/[^A-Z]/g, '');
  C.groups = (t, n = 5) => (C.letters(t).match(new RegExp('.{1,' + n + '}', 'g')) || []).join(' ');
  C.gcd = (a, b) => { a = Math.abs(a); b = Math.abs(b); while (b) [a, b] = [b, a % b]; return a; };
  C.gcdAll = (xs) => xs.reduce((g, x) => C.gcd(g, x), 0);

  /** extended Euclid on (a, b): each row is q, r, s, t with r = s·a + t·b, as the table is filled in */
  C.egcd = (a, b) => {
    const par = (x) => (x < 0 ? '(' + x + ')' : x);
    const rows = [{ q: null, r: a, s: 1, t: 0 }, { q: null, r: b, s: 0, t: 1 }];
    const trace = [step('egcd-start', `Start the table with ${a} = 1·${a} + 0·${b} and ${b} = 0·${a} + 1·${b}.`, { a, b, rows: rows.slice() })];
    while (rows[rows.length - 1].r !== 0) {
      const p = rows[rows.length - 2], c = rows[rows.length - 1];
      const q = Math.floor(p.r / c.r), row = { q, r: p.r - q * c.r, s: p.s - q * c.s, t: p.t - q * c.t };
      rows.push(row);
      trace.push(step('egcd-row', `${p.r} = ${q}·${c.r} + ${row.r}, so the new row is r = ${row.r}, s = ${p.s} − ${q}·${par(c.s)} = ${row.s}, t = ${p.t} − ${q}·${par(c.t)} = ${row.t}.`, { row, index: rows.length - 1 }));
    }
    const last = rows[rows.length - 2];
    trace.push(step('egcd-done', `The remainder reached 0, so gcd(${a}, ${b}) = ${last.r} = ${par(last.s)}·${a} + ${par(last.t)}·${b}.`, { g: last.r, x: last.s, y: last.t }));
    return { g: last.r, x: last.s, y: last.t, rows, trace };
  };
  /** the inverse of a modulo m by extended Euclid, or null when gcd(a, m) is not 1 */
  C.inverse = (a, m = 26) => {
    const e = C.egcd(m, C.mod(a, m)), trace = e.trace.slice();
    if (e.g !== 1) { trace.push(step('no-inverse', `gcd(${a}, ${m}) = ${e.g}, not 1, so ${a} has no inverse modulo ${m}.`, { a, m, g: e.g })); return { inv: null, g: e.g, rows: e.rows, trace }; }
    const inv = C.mod(e.y, m);
    trace.push(step('inverse', `1 = ${e.x < 0 ? "(" + e.x + ")" : e.x}·${m} + ${e.y < 0 ? "(" + e.y + ")" : e.y}·${C.mod(a, m)}, so ${C.mod(a, m)}·${e.y < 0 ? "(" + e.y + ")" : e.y} ≡ 1 (mod ${m}) and the inverse is ${e.y} mod ${m} = ${inv}.`, { a, m, inv }));
    return { inv, g: 1, rows: e.rows, trace };
  };

  /** a small deterministic generator (the same one the tests use): reproducible solver runs from a seed */
  C.rng = (seed = 1) => {
    let s = seed >>> 0;
    return () => { s = (s + 0x6D2B79F5) >>> 0; let t = imul(s ^ (s >>> 15), 1 | s); t ^= t + imul(t ^ (t >>> 7), 61 | t); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  };
  C.shuffle = (arr, rand) => { for (let i = arr.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [arr[i], arr[j]] = [arr[j], arr[i]]; } return arr; };

  // standard published English letter frequencies (percent of letters in typical English text)
  C.ENGLISH = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
    6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074];

  let M = null;
  C.model = () => {
    if (M) return M;
    const t = C.letters(C.corpus.text()), n = t.length, x = Array.from(t, (c) => c.charCodeAt(0) - 65);
    const tally = (k) => { const m = new Map(); for (let i = 0; i + k <= n; i++) { const g = t.substr(i, k); m.set(g, (m.get(g) || 0) + 1); } return m; };
    const top = (m, k) => [...m].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, k).map(([g, c]) => ({ gram: g, count: c, pct: (100 * c) / (n - g.length + 1) }));
    const letters = C.ENGLISH.map((p) => p / 100);
    const kappa = letters.reduce((s, p) => s + p * p, 0);
    // quadgram log-probabilities, backed off to trigrams and letters for quadgrams the corpus never saw
    const Q = 26 * 26 * 26 * 26, q4 = new Uint32Array(Q), q3 = new Uint32Array(26 * 26 * 26);
    for (let i = 0; i + 4 <= n; i++) q4[((x[i] * 26 + x[i + 1]) * 26 + x[i + 2]) * 26 + x[i + 3]]++;
    for (let i = 0; i + 3 <= n; i++) q3[(x[i] * 26 + x[i + 1]) * 26 + x[i + 2]]++;
    const n4 = n - 3, n3 = n - 2, quad = new Float32Array(Q);
    for (let i = 0; i < Q; i++) {
      const a = (i / 17576) | 0, tri = i % 17576, d = i % 26;
      const pTri = (q3[tri] + 0.1 * letters[(tri / 676) | 0] * 26) / (n3 + 2.6);
      const pBack = 0.04 * pTri * letters[a] * letters[d] * 26;
      quad[i] = log10(q4[i] ? q4[i] / n4 : max(pBack, 1e-9));
    }
    M = { size: n, letters, kappa, bigrams: top(tally(2), 60), trigrams: top(tally(3), 60), quad, floor: log10(1e-9) };
    return M;
  };
  /** quadgram log-likelihood of a text (letters only); per letter with perLetter */
  C.score = (text, perLetter) => {
    const q = C.model().quad, t = C.letters(text);
    let s = 0;
    for (let i = 0; i + 4 <= t.length; i++) s += q[(((t.charCodeAt(i) - 65) * 26 + t.charCodeAt(i + 1) - 65) * 26 + t.charCodeAt(i + 2) - 65) * 26 + t.charCodeAt(i + 3) - 65];
    return perLetter ? s / Math.max(1, t.length - 3) : s;
  };
  /** the same on an index array, for the solvers */
  C.scoreIdx = (x, len = x.length) => {
    const q = C.model().quad; let s = 0;
    for (let i = 0; i + 4 <= len; i++) s += q[((x[i] * 26 + x[i + 1]) * 26 + x[i + 2]) * 26 + x[i + 3]];
    return s;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
