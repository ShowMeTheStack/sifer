// Attacks on hashes, each a generator that yields progress (so a page can run it in slices with S.NT.runChunked, or
// in a Web Worker) and returns its result with a trace; the plain functions run the generator to the end.
//   S.Hash.birthday({hash, bits, seed, count?}) -> {found, a, b, tries, expected, ...}   first collision, or with
//       count: q, the number of colliding pairs among q messages against the expected q(q−1)/2^(bits+1)
//   S.Hash.rho({hash, bits, seed}) -> {a, b, mu, lambda, evals, path?}   Floyd's cycle finding, no table at all
//   S.Hash.secondPreimage({hash, bits, seed, target}) -> {found, m, tries, expected}
//   S.Hash.joux({bits, t, seed}) -> {stages, messages(), digest}        2^t messages with one toy-hash digest
//   S.Hash.*Steps(opt)   the generators;  S.Hash.truncate(digest, bits) -> number;  S.Hash.rng(seed)
(function (S) {
  'use strict';
  const H = (S.Hash = S.Hash || {});
  const { step, hex, utf8 } = H;
  H.rng = (seed = 1) => {
    let s = (typeof seed === 'number' ? seed : [...String(seed)].reduce((h, c) => Math.imul(h ^ c.charCodeAt(0), 16777619), 2166136261)) >>> 0;
    const next = () => { s = (s + 0x6D2B79F5) >>> 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t ^= t + Math.imul(t ^ (t >>> 7), 61 | t); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
    return { next, int: (n) => Math.floor(next() * n), bytes: (n) => Uint8Array.from({ length: n }, () => (next() * 256) | 0) };
  };
  /** the first `bits` bits of a digest as a number (bits ≤ 48) */
  H.truncate = (d, bits) => {
    let v = 0;
    for (let i = 0; i < Math.ceil(bits / 8); i++) v = v * 256 + d[i];
    const extra = Math.ceil(bits / 8) * 8 - bits;
    return Math.floor(v / 2 ** extra);
  };
  H.truncHex = (v, bits) => v.toString(16).padStart(Math.ceil(bits / 4), '0');
  const drain = (g) => { for (;;) { const r = g.next(); if (r.done) return r.value; } };
  const hashOf = (name) => (typeof name === 'object' ? name.hash : H.get(name || 'sha256').hash);
  const SLICE = 4096;

  // ---- the birthday attack on a truncated hash
  // Messages are short notes that differ only in a counter, so every try is a fresh, legible message.
  const note = (seed, i) => utf8(`Payment note ${seed}-${i}: transfer approved`);
  H.birthdaySteps = function* (opt = {}) {
    const bits = opt.bits || 24, seed = opt.seed === undefined ? 1 : opt.seed, f = hashOf(opt.hash), N = 2 ** bits;
    const name = typeof opt.hash === 'string' ? opt.hash : 'sha256';
    const seen = new Map(), trace = [];
    const expected = Math.sqrt((Math.PI / 2) * N);
    trace.push(step('setup', `Hash notes with ${name} cut to ${bits} bits, so there are 2^${bits} = ${N.toLocaleString('en')} possible digests; a collision is expected after about √(πN/2) ≈ ${Math.round(expected).toLocaleString('en')} tries, not ${N.toLocaleString('en')}.`, { bits, N, expected }));
    if (opt.count) { // count all colliding pairs among q messages
      const q = opt.count, counts = new Map();
      let pairs = 0, first = null;
      for (let i = 0; i < q; i++) {
        const m = note(seed, i), v = H.truncate(f(m), bits), c = counts.get(v) || 0;
        if (c && !first) first = { i, v, j: seen.get(v) };
        if (!c) seen.set(v, i);
        pairs += c; counts.set(v, c + 1);
        if (i % SLICE === SLICE - 1) yield { done: i + 1, total: q };
      }
      const exp = (q * (q - 1)) / 2 / N;
      trace.push(step('count', `${q.toLocaleString('en')} messages make ${(q * (q - 1) / 2).toLocaleString('en')} pairs; each pair collides with chance 1/2^${bits}, so about ${exp.toFixed(2)} collisions are expected, and ${pairs} were found.`, { q, expected: exp, measured: pairs }));
      return { bits, q, expected: exp, measured: pairs, first: first && { a: note(seed, first.j), b: note(seed, first.i), value: H.truncHex(first.v, bits) }, trace };
    }
    const max = opt.maxTries || 16 * Math.ceil(expected) + 1000;
    for (let i = 0; i < max; i++) {
      const m = note(seed, i), d = f(m), v = H.truncate(d, bits);
      const j = seen.get(v);
      if (j !== undefined) {
        const a = note(seed, j), b = m;
        trace.push(step('collide', `Try ${i + 1}: “${new TextDecoder().decode(b)}” has the same ${bits}-bit digest ${H.truncHex(v, bits)} as try ${j + 1}, “${new TextDecoder().decode(a)}”.`, { i, j, value: v }));
        trace.push(step('compare', `${i + 1} tries against about ${Math.round(expected)} expected: ${(100 * (i + 1) / expected).toFixed(0)}% of the estimate. Storing ${seen.size} digests was the price.`, { tries: i + 1, expected, stored: seen.size }));
        return { found: true, bits, a, b, digestA: f(a), digestB: d, value: H.truncHex(v, bits), tries: i + 1, expected, stored: seen.size, trace };
      }
      seen.set(v, i);
      if (i % SLICE === SLICE - 1) yield { done: i + 1, total: Math.ceil(expected) };
    }
    trace.push(step('give-up', `No collision in ${max} tries.`, {}));
    return { found: false, bits, tries: max, expected, trace };
  };
  H.birthday = (opt) => drain(H.birthdaySteps(opt));
  /** the chance of at least one collision among q values drawn from N, for the birthday curve */
  H.birthdayProb = (q, N) => 1 - Math.exp((-q * (q - 1)) / (2 * N));

  // ---- Pollard's rho with Floyd's cycle finding: a walk x → f(x) = trunc(H(x)) must loop; where the tail joins
  // the cycle, two different points map to the same value, which is a collision found with no stored digests.
  const enc = (v, seed) => utf8(`rho:${seed}:${v.toString(16)}`);
  H.rhoSteps = function* (opt = {}) {
    const bits = opt.bits || 24, seed = opt.seed === undefined ? 1 : opt.seed, h = hashOf(opt.hash), N = 2 ** bits;
    const F = (v) => H.truncate(h(enc(v, seed)), bits);
    const rnd = H.rng(seed), trace = [];
    let evals = 0;
    for (let attempt = 0; attempt < 8; attempt++) {
      const x0 = rnd.int(N);
      let t = F(x0), r = F(F(x0)); evals += 3;
      while (t !== r) { t = F(t); r = F(F(r)); evals += 3; if (evals % SLICE < 3) yield { done: evals, total: Math.ceil(3 * Math.sqrt(N)) }; }
      trace.push(step('meet', `Start at ${H.truncHex(x0, bits)}; the tortoise (one step) and the hare (two steps) meet at ${H.truncHex(t, bits)} after ${evals} hash calls: the walk has looped.`, { x0, meet: t, evals }));
      // the tail length mu: restart the tortoise; step both once until the next values agree
      let mu = 0, a = x0, b = t;
      if (a === b) { trace.push(step('on-cycle', 'The start was already on the cycle, so there is no tail and no collision; start again elsewhere.', {})); continue; }
      while (F(a) !== F(b)) { a = F(a); b = F(b); mu++; evals += 2; if (evals % SLICE < 2) yield { done: evals, total: evals + 1 }; }
      evals += 2;
      // the cycle length lambda, for the picture
      const entry = F(a);
      let lambda = 1, c = F(entry);
      while (c !== entry) { c = F(c); lambda++; }
      const v = entry;
      trace.push(step('tail', `Restart one walker at the start, keep the other at the meeting point, step both once at a time: after ${mu} steps they are about to land on the same value ${H.truncHex(v, bits)}.`, { mu }));
      trace.push(step('collide', `So ${H.truncHex(a, bits)} and ${H.truncHex(b, bits)} are different inputs with the same ${bits}-bit digest ${H.truncHex(v, bits)}: a collision, with nothing stored. Tail ${mu + 1}, cycle ${lambda}, ${evals} hash calls (about ${Math.round(Math.sqrt(Math.PI * N / 2))} expected for tail plus cycle).`, { a, b, value: v, lambda }));
      let path = null;
      if (opt.path !== false && mu + lambda < 4000) { path = [x0]; for (let i = 0; i < mu + 1 + lambda; i++) path.push(F(path[path.length - 1])); }
      return { found: true, bits, a, b, ma: enc(a, seed), mb: enc(b, seed), value: v, mu: mu + 1, lambda, evals, path, trace };
    }
    return { found: false, bits, evals, trace };
  };
  H.rho = (opt) => drain(H.rhoSteps(opt));
  H.rhoInput = (v, seed) => enc(v, seed === undefined ? 1 : seed);

  // ---- second preimage: a given message, and a search for another with the same truncated digest. There is no
  // birthday shortcut here, because one side is fixed: about 2^bits tries.
  H.secondPreimageSteps = function* (opt = {}) {
    const bits = opt.bits || 16, seed = opt.seed === undefined ? 1 : opt.seed, f = hashOf(opt.hash), N = 2 ** bits;
    const target = utf8(opt.target || 'Pay 100 to the library fund');
    const want = H.truncate(f(target), bits), trace = [];
    trace.push(step('target', `The target message has the ${bits}-bit digest ${H.truncHex(want, bits)}; a different message with that digest needs about 2^${bits} = ${N.toLocaleString('en')} tries.`, { want }));
    const rnd = H.rng(seed), max = opt.maxTries || 30 * N;
    for (let i = 0; i < max; i++) {
      const m = utf8(`Pay 900 to account ${rnd.int(1e9)} ref ${i}`);
      if (H.truncate(f(m), bits) === want) {
        trace.push(step('found', `Try ${i + 1}: “${new TextDecoder().decode(m)}” also hashes to ${H.truncHex(want, bits)}; ${(100 * (i + 1) / N).toFixed(0)}% of the 2^${bits} estimate. A birthday attack at this size needs only about ${Math.round(Math.sqrt(Math.PI * N / 2))}.`, { tries: i + 1 }));
        return { found: true, bits, target, m, value: H.truncHex(want, bits), tries: i + 1, expected: N, trace };
      }
      if (i % SLICE === SLICE - 1) yield { done: i + 1, total: N };
    }
    return { found: false, bits, tries: max, expected: N, trace };
  };
  H.secondPreimage = (opt) => drain(H.secondPreimageSteps(opt));

  // ---- Joux multicollisions: in a Merkle–Damgård hash, t successive block collisions (each a birthday search
  // from the chaining value the last one left) give 2^t messages with the same digest for t times the work of one.
  H.jouxSteps = function* (opt = {}) {
    const bits = opt.bits || 16, t = opt.t || 4, seed = opt.seed === undefined ? 1 : opt.seed;
    const T = opt.toy || H.toy(bits), BL = T.blockLen, rnd = H.rng(seed), trace = [], stages = [];
    let cv = T.iv[0], work = 0;
    trace.push(step('setup', `A toy Merkle–Damgård hash with a ${bits}-bit chaining value and ${BL}-byte blocks. One block collision costs about 2^${bits / 2} compressions; ${t} of them in a row will give 2^${t} = ${2 ** t} colliding messages.`, { bits, t }));
    for (let s = 0; s < t; s++) {
      const seen = new Map();
      for (let k = 0; ; k++) {
        const blk = rnd.bytes(BL), v = T.compress1(cv, blk); work++;
        const prev = seen.get(v);
        if (prev && !H.eq(prev, blk)) {
          stages.push({ s, cvIn: cv, cvOut: v, b0: prev, b1: blk, tries: k + 1 });
          trace.push(step('stage', `Stage ${s + 1}: from chaining value ${H.truncHex(cv, bits)}, blocks ${hex(prev)} and ${hex(blk)} both give ${H.truncHex(v, bits)} (${k + 1} tries).`, { s, cvIn: cv, cvOut: v, b0: prev, b1: blk }));
          cv = v;
          break;
        }
        seen.set(v, blk);
        if (work % SLICE === 0) yield { done: s, total: t };
      }
    }
    const messages = (limit = 2 ** t) => {
      const out = [];
      for (let m = 0; m < Math.min(limit, 2 ** t); m++) out.push(H.concat(...stages.map((st, i) => ((m >> (t - 1 - i)) & 1 ? st.b1 : st.b0))));
      return out;
    };
    const digest = T.hashValue(messages(1)[0]);
    trace.push(step('done', `Choosing either block at each of the ${t} stages gives ${2 ** t} different ${t * BL}-byte messages; all reach ${H.truncHex(cv, bits)}, and with the same length block, all hash to ${H.truncHex(digest, bits)}. Work: ${work} compressions, not the ${Math.round(2 ** (bits * (2 ** t - 1) / 2 ** t))} a ${2 ** t}-way collision would need in an ideal hash.`, { digest, work }));
    return { bits, t, toy: T, stages, messages, digest, work, trace };
  };
  H.joux = (opt) => drain(H.jouxSteps(opt));
})(globalThis.Sifer = globalThis.Sifer || {});
