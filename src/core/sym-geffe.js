// A combination generator and the correlation attack that splits it apart. The Geffe generator runs three LFSRs and
// outputs z = x1·x2 ⊕ (1 ⊕ x1)·x3: x1 chooses whether x2 or x3 is seen. So z agrees with x2 three times in four, and
// with x3 three times in four. An attacker who knows the feedback polynomials tries every start state of register 2
// alone, keeps the one whose output agrees with z about 75% of the time (the wrong ones agree about 50%), does the
// same for register 3, and then finds register 1 from the places where x2 and x3 differ: there z equals x2 exactly
// when x1 = 1. The work is 2^L2 + 2^L3 + 2^L1 instead of 2^(L1 + L2 + L3).
//   S.Geffe.TAPS: three primitive registers, lengths 7, 11 and 13
//   S.Geffe.make(seeds[, taps]) -> {run(n) -> {z, x: [x1, x2, x3], trace}}
//   S.Geffe.setup({seed, n}) -> {seeds, z}
//   S.Geffe.attack({z, taps}) -> {seeds: [s1, s2, s3], scores: [[...], [...]], ok, trace}
(function (S) {
  'use strict';
  const Ge = (S.Geffe = {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  Ge.TAPS = [[7, 1], [11, 2], [13, 4, 3, 1]];
  Ge.combine = (x1, x2, x3) => (x1 & x2) ^ ((1 ^ x1) & x3);
  Ge.make = (seeds, taps = Ge.TAPS) => ({
    run: (n) => {
      const x = seeds.map((s, i) => S.LFSR.sequence(taps[i], s, n)), z = [], trace = [];
      for (let i = 0; i < n; i++) {
        z.push(Ge.combine(x[0][i], x[1][i], x[2][i]));
        if (i < 16) trace.push(step('geffe', `t = ${i}: x1 = ${x[0][i]} selects ${x[0][i] ? 'x2' : 'x3'} = ${x[0][i] ? x[1][i] : x[2][i]}, so z = ${z[i]}.`, { i, x1: x[0][i], x2: x[1][i], x3: x[2][i], z: z[i] }));
      }
      return { z, x, trace };
    },
  });
  const randSeed = (r, L) => { const s = Array.from({ length: L }, () => (r() < 0.5 ? 1 : 0)); if (!s.some((b) => b)) s[0] = 1; return s; };
  Ge.setup = ({ seed = 1, n = 200, taps = Ge.TAPS } = {}) => {
    const r = S.Sym.rng(seed), seeds = taps.map((t) => randSeed(r, t[0]));
    return { seeds, taps, n, z: Ge.make(seeds, taps).run(n).z };
  };
  const fromInt = (v, L) => Array.from({ length: L }, (_, i) => (v >> i) & 1);
  /** agreement of one register's output with z for every start state, best first */
  const scan = (taps, z) => {
    const L = taps[0], n = z.length, all = [];
    for (let v = 1; v < 1 << L; v++) {
      const seed = fromInt(v, L), x = S.LFSR.sequence(taps, seed, n);
      let agree = 0; for (let i = 0; i < n; i++) agree += x[i] === z[i];
      all.push({ v, seed, agree, x });
    }
    return all.sort((a, b) => b.agree - a.agree);
  };
  Ge.attack = ({ z, taps = Ge.TAPS }) => {
    const n = z.length, trace = [];
    const s2 = scan(taps[1], z), s3 = scan(taps[2], z);
    const show = (list) => list.slice(0, 3).map((c) => `${c.seed.join('')} (${(100 * c.agree / n).toFixed(1)}%)`).join(', ');
    trace.push(step('corr-x2', `Register 2: try all ${(1 << taps[1][0]) - 1} nonzero start states against the ${n} output bits; the best agreements are ${show(s2)}. The right state agrees about 75% of the time, a wrong one about 50%.`, { top: s2.slice(0, 8).map((c) => ({ seed: c.seed, agree: c.agree })), n }));
    trace.push(step('corr-x3', `Register 3: all ${(1 << taps[2][0]) - 1} start states; the best are ${show(s3)}.`, { top: s3.slice(0, 8).map((c) => ({ seed: c.seed, agree: c.agree })), n }));
    const x2 = s2[0].x, x3 = s3[0].x;
    // where x2 ≠ x3 the output reveals x1; then check every start state of register 1 against those bits
    const known = [];
    for (let i = 0; i < n; i++) if (x2[i] !== x3[i]) known.push({ i, x1: z[i] === x2[i] ? 1 : 0 });
    let s1 = null, tried = 0;
    for (let v = 1; v < 1 << taps[0][0] && !s1; v++) {
      const seed = fromInt(v, taps[0][0]), x = S.LFSR.sequence(taps[0], seed, n);
      tried++;
      if (known.every((k) => x[k.i] === k.x1)) s1 = seed;
    }
    trace.push(step('corr-x1', `Where x2 and x3 differ (${known.length} places), z shows x1 directly; the start state ${s1 ? s1.join('') : 'none'} of register 1 fits them all (${tried} states tried).`, { known: known.length, s1 }));
    const seeds = [s1, s2[0].seed, s3[0].seed];
    const ok = !!s1 && Ge.make(seeds, taps).run(n).z.every((b, i) => b === z[i]);
    const L = taps.map((t) => t[0]);
    trace.push(step('corr-done', `${ok ? 'The three recovered registers reproduce every output bit' : 'The recovered states do not reproduce the output'}. Work: ${2 ** L[1]} + ${2 ** L[2]} + ${2 ** L[0]} start states instead of 2^${L[0] + L[1] + L[2]} = ${2 ** (L[0] + L[1] + L[2])}.`, { ok }));
    return { seeds, scores: [s2.slice(0, 8).map((c) => c.agree), s3.slice(0, 8).map((c) => c.agree)], ok, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
