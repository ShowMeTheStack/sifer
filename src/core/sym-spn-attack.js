// Breaking the toy SPN: differential and linear cryptanalysis recover the last round key K5, nibble by nibble.
// Both attacks guess the K5 bits in front of the S-boxes that a characteristic (or approximation) reaches in round 4,
// peel off the last round with each guess, and count how often the prediction holds; the right guess stands out.
//   S.SPN.diffAttack({keys, char, pairs, seed}) -> {guess, counts: [per guess], right, used, trace}
//       chosen plaintexts: pairs (P, P ⊕ ΔP); pairs whose ciphertexts differ outside the target nibbles are dropped
//   S.SPN.linearAttack({keys, approx (one or a list on the same nibbles), texts, seed}) -> {guess, counts, per, trace}
//       known plaintexts (Matsui's algorithm 2)
//   S.SPN.recoverK5({keys, seed, method: 'differential' | 'linear', pairs, texts}) -> {k5, nibbles: [...], ok, trace}
//   S.SPN.recoverK5Steps(opts) -> the same as a generator, one nibble per step
(function (S) {
  'use strict';
  const P = (S.SPN = S.SPN || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const h4 = (x) => x.toString(16).padStart(4, '0');
  /** spread a guess of 4·|nibs| bits over the target nibbles */
  const spread = (g, nibs) => { let k = 0; nibs.forEach((n, j) => { k |= ((g >> (4 * (nibs.length - 1 - j))) & 15) << (12 - 4 * n); }); return k; };
  const maskOf = (nibs) => spread((1 << (4 * nibs.length)) - 1, nibs);
  const undo = (c, k, nibs) => { let u = 0; for (const n of nibs) u |= P.INV_SBOX[P.nib(c ^ k, n)] << (12 - 4 * n); return u; };
  const top = (counts, nibs, n = 5) => counts.map((c, g) => ({ g, k: spread(g, nibs), c })).sort((a, b) => b.c - a.c).slice(0, n);

  P.diffAttack = ({ keys, char, pairs = 2000, seed = 1 }) => {
    const E = P.fast(keys).enc, r = S.Sym.rng(seed), nibs = char.active, G = 1 << (4 * nibs.length), outside = ~maskOf(nibs) & 0xffff;
    const counts = new Array(G).fill(0);
    let used = 0;
    for (let i = 0; i < pairs; i++) {
      const p = Math.floor(r() * 65536), c1 = E(p), c2 = E(p ^ char.dIn);
      if ((c1 ^ c2) & outside) continue;
      used++;
      for (let g = 0; g < G; g++) { const k = spread(g, nibs); if ((undo(c1, k, nibs) ^ undo(c2, k, nibs)) === char.dU4) counts[g]++; }
    }
    const best = top(counts, nibs), guess = best[0].k, right = keys[4] & maskOf(nibs);
    const trace = [
      step('diff-char', `Use the characteristic ΔP = ${h4(char.dIn)} → ΔU4 = ${h4(char.dU4)} (probability about ${char.prob.toPrecision(2)}), so the K5 nibble${nibs.length > 1 ? 's' : ''} ${nibs.join(' and ')} (${G} guesses) can be tested.`, { char }),
      step('diff-filter', `Of ${pairs} chosen pairs, ${used} have ciphertexts that agree outside nibble${nibs.length > 1 ? 's' : ''} ${nibs.join(', ')}; the others cannot be right pairs and are dropped.`, { pairs, used }),
      step('diff-count', `For each guess, undo the last S-boxes on both ciphertexts and count the pairs whose difference is ${h4(char.dU4)}: the best guesses are ${best.map((b) => `${h4(b.k)} (${b.c})`).join(', ')}.`, { counts, best, nibs }),
      step('diff-result', `The top guess ${h4(guess)} ${guess === right ? 'is' : 'is not'} the true value of those K5 bits; expected right pairs ≈ ${Math.round(pairs * char.prob)}.`, { guess, right, ok: guess === right }),
    ];
    return { guess, counts, best, right, ok: guess === right, used, nibs, trace };
  };

  /** one approximation, or several on the same target nibbles (their squared biases are added: a key that makes one
   *  approximation's bias vanish, as linear hulls can, is still caught by the others) */
  P.linearAttack = ({ keys, approx, texts = 8000, seed = 1 }) => {
    const list = Array.isArray(approx) ? approx : [approx];
    const E = P.fast(keys).enc, r = S.Sym.rng(seed), nibs = list[0].active, G = 1 << (4 * nibs.length);
    const holds = list.map(() => new Array(G).fill(0)), par = P.parity;
    for (let i = 0; i < texts; i++) {
      const p = Math.floor(r() * 65536), c = E(p);
      for (let g = 0; g < G; g++) {
        const u = undo(c, spread(g, nibs), nibs);
        list.forEach((ap, j) => { if ((par(p & ap.a) ^ par(u & ap.bU4)) === 0) holds[j][g]++; });
      }
    }
    const per = holds.map((h) => h.map((x) => Math.abs(x - texts / 2) / texts));
    const counts = new Array(G).fill(0).map((_, g) => per.reduce((s, b) => s + b[g] * b[g], 0));
    const best = top(counts, nibs), guess = best[0].k, right = keys[4] & maskOf(nibs);
    const fmt = (v) => (list.length > 1 ? (1e4 * v).toFixed(1) : Math.sqrt(v).toFixed(4));
    const trace = [
      ...list.map((ap) => step('lin-approx', `Approximation P·${h4(ap.a)} ⊕ U4·${h4(ap.bU4)} = (key bits), predicted bias ${ap.bias.toPrecision(2)}; about 1/bias² = ${Math.round(1 / ap.bias / ap.bias)} known plaintexts give a signal.`, { approx: ap })),
      step('lin-count', `For each of the ${G} guesses of K5 nibble${nibs.length > 1 ? 's' : ''} ${nibs.join(', ')}, undo the last S-boxes on ${texts} ciphertexts and measure the bias |#(parity 0) − ${texts / 2}| / ${texts}${list.length > 1 ? ' of each approximation, adding the squares (shown × 10⁴)' : ''}: the best are ${best.map((b) => `${h4(b.k)} (${fmt(b.c)})`).join(', ')}.`, { counts, per, best, nibs }),
      step('lin-result', `The top guess ${h4(guess)} ${guess === right ? 'is' : 'is not'} the true value of those key bits.`, { guess, right, ok: guess === right }),
    ];
    return { guess, counts, per, best, right, ok: guess === right, nibs, trace };
  };

  /** every nibble of K5 from a single-box characteristic (or approximation) that reaches it */
  P.recoverK5Steps = function* ({ keys, seed = 1, method = 'differential', pairs, texts } = {}) {
    keys = keys || P.keys(seed);
    const lin = method === 'linear';
    const found = lin ? P.searchLinear({ maxActive: 1 }) : P.searchDifferential({ maxActive: 1 });
    let k5 = 0;
    const nibbles = [], trace = [step('k5-plan', `Recover K5 one nibble at a time with the best ${lin ? 'linear approximation' : 'differential characteristic'} ending in a single active S-box in round 4.`, {})];
    for (let n = 0; n < 4; n++) {
      const ch = found.find((x) => x.active.length === 1 && x.active[0] === n);
      const several = found.filter((x) => x.active.length === 1 && x.active[0] === n).slice(0, 16);
      const res = lin ? P.linearAttack({ keys, approx: several, texts: texts || 12000, seed: seed * 31 + n })
        : P.diffAttack({ keys, char: ch, pairs: pairs || Math.ceil(24 / ch.prob), seed: seed * 31 + n });
      k5 |= res.guess;
      nibbles.push(res);
      yield { done: n + 1, total: 4 };
      trace.push(step('k5-nibble', `Nibble ${n}: ${res.trace[res.trace.length - 1].say}`, { n, guess: res.guess, ok: res.ok }));
    }
    const ok = k5 === keys[4];
    trace.push(step('k5-done', `The recovered K5 is ${h4(k5)}; the true K5 is ${h4(keys[4])}${ok ? ': the last round key is broken' : ''}.`, { k5, ok }));
    return { k5, keys, nibbles, ok, trace };
  };
  P.recoverK5 = (opts) => S.Sym.drain(P.recoverK5Steps(opts));
})(globalThis.Sifer = globalThis.Sifer || {});
