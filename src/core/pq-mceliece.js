// Code-based encryption: a toy McEliece on a binary Goppa code, decoded by Patterson's algorithm, and a Hamming
// [7,4] code for the simplest syndrome decoding. Bit vectors are arrays of 0/1; matrices are arrays of rows.
//   S.PQ.Goppa.make({m, t, n, seed}) -> {code: {m, t, n, g, L, H, G, k}, trace}
//   S.PQ.Goppa.decode(code, word) -> {codeword, error, positions, trace}       Patterson
//   S.PQ.McEliece.keyGen({m, t, n, seed}) -> {pk: {Gpub, t, n, k}, sk, trace}
//   S.PQ.McEliece.encrypt(pk, msgBits, {seed | error}) -> {c, error, trace}
//   S.PQ.McEliece.decrypt(sk, c) -> {msg, error, trace}
//   S.PQ.Hamming.code() / encode(msg4) / decode(word7) -> syndrome decoding of one error
(function (S) {
  'use strict';
  const P = (S.PQ = S.PQ || {});
  const step = (...a) => P.step(...a);
  const bits = (v) => v.join('');

  // GF(2^m) by log tables, with a fixed primitive polynomial for each m
  const PRIM = { 3: 0b1011, 4: 0b10011, 5: 0b100101, 6: 0b1000011, 7: 0b10001001, 8: 0b100011101 };
  const fieldCache = {};
  const field = (m) => {
    if (fieldCache[m]) return fieldCache[m];
    if (!PRIM[m]) throw new Error('m must be between 3 and 8');
    const size = 1 << m, exp = new Array(2 * size), log = new Array(size).fill(-1);
    let x = 1;
    for (let i = 0; i < size - 1; i++) { exp[i] = x; log[x] = i; x <<= 1; if (x & size) x ^= PRIM[m]; }
    for (let i = size - 1; i < 2 * size; i++) exp[i] = exp[i - (size - 1)];
    const F = {
      m, size,
      mul: (a, b) => (a && b ? exp[log[a] + log[b]] : 0),
      inv: (a) => { if (!a) throw new Error('0 has no inverse'); return exp[(size - 1 - log[a]) % (size - 1)]; },
      sq: (a) => (a ? exp[(2 * log[a]) % (size - 1)] : 0),
    };
    F.div = (a, b) => F.mul(a, F.inv(b));
    return (fieldCache[m] = F);
  };
  // polynomials over GF(2^m): coefficient arrays, lowest degree first, no trailing zeros
  const trim = (a) => { a = a.slice(); while (a.length && a[a.length - 1] === 0) a.pop(); return a; };
  const deg = (a) => trim(a).length - 1;
  const padd = (a, b) => trim(Array.from({ length: Math.max(a.length, b.length) }, (_, i) => (a[i] || 0) ^ (b[i] || 0)));
  const pmul = (F, a, b) => { if (!a.length || !b.length) return []; const r = new Array(a.length + b.length - 1).fill(0); for (let i = 0; i < a.length; i++) for (let j = 0; j < b.length; j++) r[i + j] ^= F.mul(a[i], b[j]); return trim(r); };
  const pscale = (F, a, c) => trim(a.map((v) => F.mul(v, c)));
  const pdivmod = (F, a, b) => {
    a = trim(a); b = trim(b);
    const db = b.length - 1, lead = F.inv(b[db]), qt = new Array(Math.max(a.length - db, 1)).fill(0);
    let r = a.slice();
    while (r.length - 1 >= db && r.length) {
      const d = r.length - 1 - db, c = F.mul(r[r.length - 1], lead);
      qt[d] = c;
      for (let i = 0; i <= db; i++) r[i + d] ^= F.mul(c, b[i]);
      r = trim(r);
    }
    return { q: trim(qt), r };
  };
  const pmod = (F, a, b) => pdivmod(F, a, b).r;
  const peval = (F, a, x) => { let v = 0; for (let i = a.length - 1; i >= 0; i--) v = F.mul(v, x) ^ a[i]; return v; };
  /** inverse of a modulo g by the extended Euclidean algorithm */
  const pinvmod = (F, a, g) => {
    let r0 = g.slice(), r1 = pmod(F, a, g), s0 = [], s1 = [1];
    while (deg(r1) > 0) { const { q, r } = pdivmod(F, r0, r1); [r0, r1] = [r1, r]; [s0, s1] = [s1, padd(s0, pmul(F, q, s1))]; }
    if (!r1.length) throw new Error('not invertible');
    return pscale(F, s1, F.inv(r1[0]));
  };
  /** Ben-Or: g of degree t is irreducible iff gcd(z^(2^(m i)) − z, g) = 1 for i ≤ t/2 */
  const pgcd = (F, a, b) => { a = trim(a); b = trim(b); while (b.length) [a, b] = [b, pmod(F, a, b)]; return a; };
  const irreducible = (F, g) => {
    const t = deg(g);
    let zp = [0, 1];
    for (let i = 1; i <= Math.floor(t / 2); i++) {
      for (let j = 0; j < F.m; j++) zp = pmod(F, pmul(F, zp, zp), g);
      if (deg(pgcd(F, g, padd(zp, [0, 1]))) > 0) return false;
    }
    return true;
  };
  const fmtPoly = (F, a) => {
    a = trim(a);
    if (!a.length) return '0';
    const t = [];
    for (let i = a.length - 1; i >= 0; i--) if (a[i]) t.push((a[i] === 1 && i ? '' : fmtEl(F, a[i])) + (i ? (i === 1 ? 'z' : 'z' + sup(i)) : ''));
    return t.join(' + ');
  };
  const logOf = (F, v) => { let x = 1; for (let i = 0; i < F.size; i++) { if (x === v) return i; x = F.mul(x, 2); } return -1; };
  const sup = (n) => String(n).split('').map((d) => '⁰¹²³⁴⁵⁶⁷⁸⁹'[d]).join('');
  const fmtEl = (F, v) => { if (v <= 1) return String(v); const l = logOf(F, v); return l === 1 ? 'α' : 'α' + sup(l); };

  // GF(2) linear algebra
  const rref = (M, cols) => {
    M = M.map((r) => r.slice());
    const piv = [];
    let row = 0;
    for (let c = 0; c < cols && row < M.length; c++) {
      const p = M.findIndex((r, i) => i >= row && r[c]);
      if (p < 0) continue;
      [M[row], M[p]] = [M[p], M[row]];
      for (let i = 0; i < M.length; i++) if (i !== row && M[i][c]) M[i] = M[i].map((v, j) => v ^ M[row][j]);
      piv.push(c); row++;
    }
    return { M: M.slice(0, row), piv };
  };
  const nullspace = (H, n) => {
    const { M, piv } = rref(H, n), free = [...Array(n).keys()].filter((c) => !piv.includes(c));
    return free.map((f) => { const v = new Array(n).fill(0); v[f] = 1; piv.forEach((pc, i) => { v[pc] = M[i][f]; }); return v; });
  };
  const vecMat = (v, M) => M[0].map((_, j) => M.reduce((s, row, i) => s ^ (v[i] & row[j]), 0));
  const matMul = (A, B) => A.map((r) => vecMat(r, B));
  const invert = (A) => {
    const n = A.length, { M, piv } = rref(A.map((r, i) => r.concat(Array.from({ length: n }, (_, j) => +(i === j)))), n);
    if (piv.length < n || piv[n - 1] !== n - 1) return null;
    return M.map((r) => r.slice(n));
  };
  /** x with x·M = y, for M of full row rank (null if y is not in the row space) */
  const solve = (M, y) => {
    const k = M.length, n = M[0].length, aug = Array.from({ length: n }, (_, j) => M.map((r) => r[j]).concat([y[j]]));
    const { M: R, piv } = rref(aug, k);
    if (R.some((r, i) => piv[i] === undefined && r[k])) return null;
    const x = new Array(k).fill(0);
    piv.forEach((c, i) => { x[c] = R[i][k]; });
    return vecMat(x, M).every((v, j) => v === y[j]) ? x : null;
  };
  P.GF2 = { rref, nullspace, vecMat, matMul, invert, solve };

  const Gp = (P.Goppa = {});
  Gp.field = field;
  Gp.make = (opts = {}) => {
    const m = opts.m || 4, t = opts.t || 2, F = field(m), n = opts.n || F.size, r = P.rng(opts.seed || 11);
    if (n > F.size || n <= m * t) throw new Error(`need m·t < n ≤ 2^m (here ${m * t} < n ≤ ${F.size})`);
    let g;
    do { g = Array.from({ length: t }, () => r.int(F.size)).concat([1]); } while (!irreducible(F, g));
    const all = [...Array(F.size).keys()];
    for (let i = all.length - 1; i > 0; i--) { const j = r.int(i + 1); [all[i], all[j]] = [all[j], all[i]]; }
    const L = all.slice(0, n);
    // H over GF(2^m): row i, column j is α_j^i / g(α_j); each entry expands to m bits
    const Hf = Array.from({ length: t }, (_, i) => L.map((a) => { let p = 1; for (let e = 0; e < i; e++) p = F.mul(p, a); return F.div(p, peval(F, g, a)); }));
    const H = [];
    for (let i = 0; i < t; i++) for (let b = 0; b < m; b++) H.push(Hf[i].map((v) => (v >> b) & 1));
    const G = nullspace(H, n), k = G.length;
    const code = { m, t, n, k, g, L, H, Hf, G, F };
    const trace = [
      step('goppa-g', `Goppa polynomial g(z) = ${fmtPoly(F, g)} over GF(2^${m}), irreducible, so it has no roots and the code corrects ${t} errors.`, { g, gText: fmtPoly(F, g) }),
      step('goppa-L', `Support: ${n} distinct field elements ${L.slice(0, 8).map((v) => fmtEl(F, v)).join(', ')}${n > 8 ? ', …' : ''}.`, { L }),
      step('goppa-H', `The parity-check matrix has ${t} rows over GF(2^${m}), α_j^i / g(α_j), written out in binary as ${m * t} × ${n}.`, { H }),
      step('goppa-G', `Its null space gives a generator matrix of dimension k = ${k}: messages of ${k} bits, codewords of ${n}.`, { G, k }),
    ];
    return { code, trace };
  };
  /** Patterson's algorithm: syndrome S(z), T = S⁻¹, R = √(T + z), the key equation a ≡ bR, σ = a² + z b² */
  Gp.decode = (code, word) => {
    const { F, g, L, t, n } = code, trace = [];
    let Sz = [];
    for (let j = 0; j < n; j++) if (word[j]) Sz = padd(Sz, pinvmod(F, [L[j], 1], g)); // 1/(z − α) = 1/(z + α) in characteristic 2
    const binSyn = code.H.map((row) => row.reduce((s, v, j) => s ^ (v & word[j]), 0));
    trace.push(step('syndrome', `Syndrome H·cᵀ = ${bits(binSyn)}; as a polynomial S(z) = Σ c_j/(z − α_j) mod g = ${fmtPoly(F, Sz)}.`, { syndrome: binSyn, S: Sz }));
    if (!Sz.length) {
      trace.push(step('no-error', 'The syndrome is zero: the word is already a codeword.', {}));
      return { codeword: word.slice(), error: new Array(n).fill(0), positions: [], trace };
    }
    const T = pinvmod(F, Sz, g);
    let sigma;
    if (T.length === 2 && T[0] === 0 && T[1] === 1) {
      sigma = [0, 1];
      trace.push(step('T', `T = S(z)⁻¹ mod g = z, so σ(z) = z: a single error at the support element 0.`, { T }));
    } else {
      let R = padd(T, [0, 1]);
      for (let i = 0; i < F.m * t - 1; i++) R = pmod(F, pmul(F, R, R), g);
      trace.push(step('T', `T = S(z)⁻¹ mod g = ${fmtPoly(F, T)}; R = √(T + z) mod g = ${fmtPoly(F, R)} (squaring is linear in characteristic 2, so the root is a power).`, { T, R }));
      // run Euclid on (g, R) until deg a ≤ t/2, keeping b with a ≡ b·R
      let a0 = g.slice(), a1 = R, b0 = [], b1 = [1];
      while (deg(a1) > Math.floor(t / 2)) { const { q, r } = pdivmod(F, a0, a1); [a0, a1] = [a1, r]; [b0, b1] = [b1, padd(b0, pmul(F, q, b1))]; }
      sigma = padd(pmul(F, a1, a1), pmul(F, [0, 1], pmul(F, b1, b1)));
      trace.push(step('key-equation', `Euclid on (g, R) stops at a = ${fmtPoly(F, a1)}, b = ${fmtPoly(F, b1)} with a ≡ b·R; σ(z) = a² + z·b² = ${fmtPoly(F, sigma)}.`, { a: a1, b: b1, sigma }));
    }
    const positions = L.map((a, j) => (peval(F, sigma, a) === 0 ? j : -1)).filter((j) => j >= 0);
    const error = new Array(n).fill(0);
    positions.forEach((j) => { error[j] = 1; });
    const codeword = word.map((v, j) => v ^ error[j]);
    const ok = code.H.every((row) => row.reduce((s, v, j) => s ^ (v & codeword[j]), 0) === 0);
    trace.push(step('roots', `σ vanishes at ${positions.map((j) => fmtEl(F, L[j])).join(', ') || 'no support element'}: errors at positions ${positions.join(', ') || 'none'}. Error vector ${bits(error)}.`, { positions, error }));
    trace.push(step(ok ? 'corrected' : 'decode-fail', ok ? `Flip them: ${bits(codeword)} has zero syndrome.` : 'More errors than the code corrects: decoding failed.', { codeword, ok }));
    return { codeword, error, positions, ok, trace };
  };

  const Mc = (P.McEliece = {});
  Mc.keyGen = (opts = {}) => {
    const { code, trace } = Gp.make(opts), r = P.rng((opts.seed || 11) * 7 + 3), { k, n } = code;
    let Sm, Si;
    do { Sm = Array.from({ length: k }, () => Array.from({ length: k }, () => r.int(2))); Si = invert(Sm); } while (!Si);
    const perm = [...Array(n).keys()];
    for (let i = n - 1; i > 0; i--) { const j = r.int(i + 1); [perm[i], perm[j]] = [perm[j], perm[i]]; }
    const SG = matMul(Sm, code.G), Gpub = SG.map((row) => perm.map((p) => row[p]));
    trace.push(step('mce-scramble', `Hide the structure: G′ = S·G·P with a random invertible ${k}×${k} matrix S and a permutation P of the ${n} columns. G′ looks like a random code.`, { S: Sm, perm, Gpub }));
    return { pk: { Gpub, t: code.t, n, k }, sk: { code, S: Sm, Sinv: Si, perm }, trace };
  };
  Mc.encrypt = (pk, msg, opts = {}) => {
    let e = opts.error;
    if (!e) {
      const r = P.rng(opts.seed || 1); e = new Array(pk.n).fill(0);
      let c = 0;
      while (c < pk.t) { const j = r.int(pk.n); if (!e[j]) { e[j] = 1; c++; } }
    }
    const cw = vecMat(msg, pk.Gpub), c = cw.map((v, j) => v ^ e[j]);
    const w = e.reduce((s, v) => s + v, 0);
    return { c, error: e, trace: [
      step('mce-encode', `m·G′ = ${bits(cw)} for the message ${bits(msg)}.`, { codeword: cw }),
      step('mce-error', `Add an error of weight ${w}: e = ${bits(e)}. The ciphertext is c = ${bits(c)}.`, { error: e, c }),
    ] };
  };
  Mc.decrypt = (sk, c) => {
    const { code, Sinv, perm } = sk, n = code.n, trace = [];
    const unperm = new Array(n);
    perm.forEach((p, j) => { unperm[p] = c[j]; });
    trace.push(step('mce-unpermute', `Undo the permutation: c·P⁻¹ = ${bits(unperm)} = (m·S)·G + e·P⁻¹, a word of the secret Goppa code plus ${code.t} errors at most.`, { word: unperm }));
    const d = Gp.decode(code, unperm);
    trace.push(...d.trace);
    const mS = solve(code.G, d.codeword);
    if (!mS) { trace.push(step('mce-fail', 'Decoding did not land on a codeword.', {})); return { msg: null, trace }; }
    const msg = vecMat(mS, Sinv), err = new Array(n);
    perm.forEach((p, j) => { err[j] = d.error[p]; });
    trace.push(step('mce-solve', `Solve x·G = codeword: m·S = ${bits(mS)}; multiply by S⁻¹: m = ${bits(msg)}.`, { mS, msg }));
    trace.push(step('mce-error', `The error vector, in the ciphertext's own positions: ${bits(err)}.`, { error: err }));
    return { msg, error: err, trace };
  };

  // Hamming [7,4]: column j of H is j in binary, so the syndrome of a single error spells its position
  const Hm = (P.Hamming = {});
  Hm.code = () => {
    const H = [0, 1, 2].map((b) => Array.from({ length: 7 }, (_, j) => ((j + 1) >> b) & 1));
    const G = nullspace(H, 7);
    return { H, G, n: 7, k: 4, t: 1 };
  };
  Hm.encode = (msg) => vecMat(msg, Hm.code().G);
  Hm.decode = (word) => {
    const { H, G } = Hm.code(), s = H.map((row) => row.reduce((a, v, j) => a ^ (v & word[j]), 0)), pos = s[0] + 2 * s[1] + 4 * s[2];
    const fixed = word.slice();
    if (pos) fixed[pos - 1] ^= 1;
    const msg = solve(G, fixed);
    return { syndrome: s, position: pos ? pos - 1 : -1, codeword: fixed, msg, trace: [
      step('ham-syndrome', `Syndrome H·wᵀ = ${s.slice().reverse().join('')} in binary = ${pos}: ${pos ? `the error is in position ${pos}` : 'no error'}.`, { syndrome: s, position: pos }),
      step('ham-fix', `Corrected word ${bits(fixed)}, message ${msg ? bits(msg) : '?'}.`, { codeword: fixed, msg }),
    ] };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
