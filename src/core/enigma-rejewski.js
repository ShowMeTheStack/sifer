// Rejewski's characteristic: under the early procedure every operator enciphered his three-letter message key twice
// at the day's ground setting, so the six indicator letters come from six fixed permutations A1..A6 of the day.
// Each Ai is an involution, so the products AD = A4∘A1, BE = A5∘A2, CF = A6∘A3 have cycles that come in pairs of
// equal length. The plugboard σ only conjugates them (σ·AD·σ), which relabels the cycles and leaves their lengths
// alone: the characteristic depends on the rotors and their positions, not on the cables.
//   S.Enigma.rejewski.sixPermutations(cfg)        -> {perms: [6 × Int8Array], trace}
//   S.Enigma.rejewski.products(perms)             -> {AD, BE, CF}
//   S.Enigma.rejewski.cycles(perm)                -> {cycles: ['AXQ', ...], lengths, trace}
//   S.Enigma.rejewski.characteristic(cfg)         -> {AD, BE, CF: {cycles, lengths}, text, trace}
//   S.Enigma.rejewski.indicators(cfg, n, rand)    -> [{key, indicator}]   a day's traffic
//   S.Enigma.rejewski.fromIndicators(list)        -> {maps, complete, cycles, text, conflicts, trace}
//   S.Enigma.rejewski.conjugacy(cfg)              -> the cycles with and without cables, and the relabelling
//   S.Enigma.rejewski.catalogue({target, rotors, reflector}) -> job: run(ms) -> {done, progress, matches}
(function (S) {
  'use strict';
  const E = (S.Enigma = S.Enigma || {});
  const R = (E.rejewski = {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const I = (c) => c.charCodeAt(0) - 65;
  const NAMES = ['AD', 'BE', 'CF'];

  R.sixPermutations = (cfg) => {
    const m = E.machine(cfg), perms = [], trace = [];
    for (let k = 0; k < 6; k++) { m.step(); const p = m.permutation(); perms.push(p); trace.push(step('perm', `A${k + 1} (window ${m.window}): ${Array.from(p, (x) => ABC[x]).join('')}. It swaps letters in 13 pairs.`, { k, window: m.window, perm: Array.from(p) })); }
    return { perms, trace };
  };
  R.products = (perms) => {
    const out = {};
    NAMES.forEach((nm, k) => { const a = perms[k], d = perms[k + 3], p = new Int8Array(26); for (let x = 0; x < 26; x++) p[x] = d[a[x]]; out[nm] = p; });
    return out;
  };
  R.cycles = (perm) => {
    const seen = new Array(26).fill(false), cycles = [], trace = [];
    for (let s = 0; s < 26; s++) {
      if (seen[s] || perm[s] < 0) continue;
      let x = s, c = '', open = false;
      while (!seen[x]) { seen[x] = true; c += ABC[x]; x = perm[x]; if (x < 0) { open = true; break; } }
      if (!open) { cycles.push(c); trace.push(step('cycle', `Start at ${ABC[s]}: ${c.split('').join(' → ')} → ${ABC[s]}, a cycle of length ${c.length}.`, { cycle: c })); }
    }
    cycles.sort((a, b) => b.length - a.length || (a < b ? -1 : 1));
    return { cycles, lengths: cycles.map((c) => c.length), trace };
  };
  const charText = (cs) => NAMES.map((nm) => `${nm}: ${cs[nm].lengths.join(' ')}`).join('  ');

  R.characteristic = (cfg) => {
    const six = R.sixPermutations(cfg), pr = R.products(six.perms), out = { trace: six.trace.slice() };
    for (const nm of NAMES) {
      const c = R.cycles(pr[nm]); out[nm] = c;
      out.trace.push(step('product', `${nm}: follow each letter through ${nm[0]} then ${nm[1]}; the cycles are ${c.cycles.map((x) => '(' + x + ')').join(' ')}, of lengths ${c.lengths.join(', ')}, paired as they must be.`, { name: nm, cycles: c.cycles, lengths: c.lengths }));
    }
    out.text = charText(out);
    out.key = NAMES.map((nm) => out[nm].lengths.join('.')).join('|');
    return out;
  };

  /** a day's indicators: random message keys, each typed twice at the ground setting */
  R.indicators = (cfg, n, rand) => {
    const out = [];
    for (let i = 0; i < n; i++) {
      const key = ABC[Math.floor(rand() * 26)] + ABC[Math.floor(rand() * 26)] + ABC[Math.floor(rand() * 26)];
      out.push({ key, indicator: E.machine(cfg).run(key + key) });
    }
    return out;
  };
  /** the products as far as a list of indicators reveals them: letter 1 → letter 4, 2 → 5, 3 → 6 */
  R.fromIndicators = (list) => {
    const maps = NAMES.map(() => new Int8Array(26).fill(-1)), conflicts = [], trace = [];
    for (const it of list) {
      const s = typeof it === 'string' ? it : it.indicator;
      for (let k = 0; k < 3; k++) {
        const a = I(s[k]), b = I(s[k + 3]);
        if (maps[k][a] >= 0 && maps[k][a] !== b) conflicts.push({ indicator: s, at: k });
        else maps[k][a] = b;
      }
    }
    const out = { maps: {}, complete: {}, cycles: {}, conflicts, trace };
    NAMES.forEach((nm, k) => {
      const known = maps[k].filter((v) => v >= 0).length;
      out.maps[nm] = maps[k]; out.complete[nm] = known === 26;
      const c = R.cycles(maps[k]); out.cycles[nm] = c;
      trace.push(step('indicator-map', `${list.length} indicators fix ${known} of 26 letters of ${nm}${known === 26 ? `; its cycles are ${c.cycles.map((x) => '(' + x + ')').join(' ')}` : `; the closed cycles so far are ${c.cycles.map((x) => '(' + x + ')').join(' ') || 'none'}`}.`, { name: nm, known, cycles: c.cycles }));
    });
    out.text = NAMES.every((nm) => out.complete[nm]) ? NAMES.map((nm) => `${nm}: ${out.cycles[nm].lengths.join(' ')}`).join('  ') : null;
    return out;
  };

  /** with and without the cables: the same cycle lengths, the letters renamed by σ */
  R.conjugacy = (cfg) => {
    const withP = R.characteristic(cfg), noP = R.characteristic(Object.assign({}, cfg, { plugs: '' }));
    const sigma = E.plugMap(E.parsePlugs(cfg.plugs || ''));
    const relabel = (cy) => Array.from(cy, (c) => ABC[sigma[I(c)]]).join('');
    const canon = (cy) => { let best = cy; for (let i = 1; i < cy.length; i++) { const r = cy.slice(i) + cy.slice(0, i); if (r < best) best = r; } return best; };
    const same = NAMES.every((nm) => { const a = noP[nm].cycles.map((c) => canon(relabel(c))).sort(), b = withP[nm].cycles.map(canon).sort(); return a.join() === b.join(); });
    const trace = [step('conjugacy', `Without cables AD has cycles of lengths ${noP.AD.lengths.join(' ')}; with the cables ${cfg.plugs || '(none)'} it has ${withP.AD.lengths.join(' ')}. Renaming every letter by its cable turns one set of cycles into the other: σ·AD·σ is a conjugate of AD.`, { same })];
    return { withPlugs: withP, withoutPlugs: noP, sigma: Array.from(sigma), relabelled: NAMES.map((nm) => noP[nm].cycles.map(relabel)), same, trace };
  };

  /** the card catalogue: the characteristic of every position of every rotor order (rings at A, no cables) */
  R.catalogue = (opts = {}) => {
    const orders = opts.orders || E.bombe.orders(opts.rotors || ['I', 'II', 'III']), refl = opts.reflector || 'B', target = opts.target;
    const total = orders.length * 17576, matches = [], seen = new Uint8Array(26);
    let oi = 0, p = 0, table = null, nm = 0, nr = 0, done = 0;
    // the cycle lengths of x → Ad(Aa(x)), as a sorted dot-joined string (the same form as characteristic().key)
    const cyc = (pa, pd) => {
      seen.fill(0); const out = [];
      for (let s = 0; s < 26; s++) { if (seen[s]) continue; let x = s, n = 0; while (!seen[x]) { seen[x] = 1; n++; x = table[pd + table[pa + x]]; } out.push(n); }
      return out.sort((a, b) => b - a).join('.');
    };
    return {
      total, matches,
      run(budget = 50) {
        const t0 = Date.now();
        while (oi < orders.length) {
          if (p === 0) { table = E.bombe.scramblerTable(orders[oi], refl); nm = E.wheel(orders[oi][1]).notch; nr = E.wheel(orders[oi][2]).notch; }
          for (; p < 17576; p++) {
            let w = [(p / 676) | 0, ((p / 26) | 0) % 26, p % 26]; const offs = [];
            for (let k = 0; k < 6; k++) { w = E.advance(w, nm, nr); offs.push(((w[0] * 26 + w[1]) * 26 + w[2]) * 26); }
            const key = cyc(offs[0], offs[3]) + '|' + cyc(offs[1], offs[4]) + '|' + cyc(offs[2], offs[5]);
            done++;
            if (key === target) matches.push({ order: orders[oi].slice(), window: ABC[(p / 676) | 0] + ABC[((p / 26) | 0) % 26] + ABC[p % 26] });
            if ((p & 1023) === 1023 && Date.now() - t0 > budget) { p++; return { done: false, progress: done / total, matches }; }
          }
          p = 0; oi++;
        }
        return { done: true, progress: 1, matches };
      },
    };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
