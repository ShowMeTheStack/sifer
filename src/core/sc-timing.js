// Timing side channels.
// 1. A cache model of T-table AES: four 1 KB tables T0…T3 of 16 cache lines (16 entries of 4 bytes per line).
//    A lookup costs `hit` cycles if its line is cached and `miss` cycles if not. In an evict+time attack the
//    attacker evicts one line, runs one encryption on a known plaintext and times it; in the first round byte i is
//    looked up at index pᵢ ⊕ kᵢ in table T_(i mod 4), so the slow runs reveal the high nibble of every key byte.
// 2. A leaky tag comparison that stops at the first wrong byte, and the byte-at-a-time attack that recovers a tag.
//   S.SC.Cache.encrypt(key, pt, {evict, rounds, hit, miss, sigma, rng}) -> {cycles, lookups, ct}
//   S.SC.Cache.attack({key, samples, seed, rounds}) -> {nibbles, correct, scores, trace}
//   S.SC.Timing.oracle({tag, seed, perByte, sigma, constantTime}) -> {time(guess), check(guess)}
//   S.SC.Timing.recover(oracle, {len, reps}) -> {tag, ok, profiles, trace}
(function (S) {
  'use strict';
  const C = (S.SC = S.SC || {});
  const Ca = (C.Cache = {});
  const xt = (a) => ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 255;
  /** the AES-128 round keys as 11 arrays of 16 bytes, by the standard key schedule */
  Ca.roundKeys = (key) => {
    const SB = C.sbox(), w = [];
    for (let i = 0; i < 4; i++) w.push(Array.from(key.slice(4 * i, 4 * i + 4)));
    let rc = 1;
    for (let i = 4; i < 44; i++) {
      let t = w[i - 1].slice();
      if (i % 4 === 0) { t = [SB[t[1]] ^ rc, SB[t[2]], SB[t[3]], SB[t[0]]]; rc = xt(rc); }
      w.push(t.map((v, j) => v ^ w[i - 4][j]));
    }
    return Array.from({ length: 11 }, (_, r) => [].concat(w[4 * r], w[4 * r + 1], w[4 * r + 2], w[4 * r + 3]));
  };
  /**
   * one encryption, recording the table lookups: in rounds 1–9 byte i of the round input is looked up in table
   * T_(i mod 4) (the row of the byte); the last round uses a separate S-box table, left out of the cache model.
   */
  Ca.encrypt = (key, pt, o = {}) => {
    const SB = C.sbox(), rk = o.rk || Ca.roundKeys(key), hit = o.hit || 1, miss = o.miss || 40, rounds = o.rounds === 'first' ? 1 : 9;
    const cached = new Uint8Array(64).fill(1);
    if (o.evict) cached[o.evict.table * 16 + o.evict.line] = 0;
    let s = Array.from(pt, (v, i) => v ^ rk[0][i]), cycles = o.base || 200;
    const lookups = [];
    for (let r = 1; r <= 10; r++) {
      if (r <= 9) for (let i = 0; i < 16; i++) {
        const table = i % 4, line = s[i] >> 4, slot = table * 16 + line, isHit = !!cached[slot];
        if (r <= rounds) { cycles += isHit ? hit : miss; cached[slot] = 1; if (o.record !== false) lookups.push({ round: r, byte: i, table, index: s[i], line, hit: isHit }); }
      }
      const b = s.map((v) => SB[v]);
      const sh = new Array(16);
      for (let c = 0; c < 4; c++) for (let row = 0; row < 4; row++) sh[row + 4 * c] = b[row + 4 * ((c + row) % 4)];
      let m = sh;
      if (r < 10) {
        m = new Array(16);
        for (let c = 0; c < 4; c++) {
          const [a0, a1, a2, a3] = sh.slice(4 * c, 4 * c + 4);
          m[4 * c] = xt(a0) ^ xt(a1) ^ a1 ^ a2 ^ a3;
          m[4 * c + 1] = a0 ^ xt(a1) ^ xt(a2) ^ a2 ^ a3;
          m[4 * c + 2] = a0 ^ a1 ^ xt(a2) ^ xt(a3) ^ a3;
          m[4 * c + 3] = xt(a0) ^ a0 ^ a1 ^ a2 ^ xt(a3);
        }
      }
      s = m.map((v, i) => v ^ rk[r][i]);
    }
    if (o.rng) cycles += (o.sigma != null ? o.sigma : 4) * o.rng.gauss();
    return { cycles, lookups, ct: Uint8Array.from(s) };
  };
  /** evict+time against the first round: score each high-nibble guess by the mean time when it predicts a miss */
  Ca.attack = (o) => {
    const key = o.key, rk = Ca.roundKeys(key), r = C.rng(o.seed || 21), samples = o.samples || 20000, rounds = o.rounds || 'all';
    const sum = new Float64Array(16 * 16), cnt = new Float64Array(16 * 16), tSum = new Float64Array(4), tCnt = new Float64Array(4);
    for (let s = 0; s < samples; s++) {
      const pt = r.bytes(16), table = r.int(4), line = r.int(16);
      const { cycles } = Ca.encrypt(key, pt, { rk, evict: { table, line }, rounds, rng: r, sigma: o.sigma, record: false });
      tSum[table] += cycles; tCnt[table]++;
      for (let i = table; i < 16; i += 4) { const k = (pt[i] >> 4) ^ line; sum[i * 16 + k] += cycles; cnt[i * 16 + k]++; }
    }
    const scores = [], nibbles = [];
    for (let i = 0; i < 16; i++) {
      const base = tSum[i % 4] / tCnt[i % 4], sc = Array.from({ length: 16 }, (_, k) => (cnt[i * 16 + k] ? sum[i * 16 + k] / cnt[i * 16 + k] - base : 0));
      scores.push(sc);
      nibbles.push(sc.indexOf(Math.max(...sc)));
    }
    const correct = nibbles.map((v, i) => v === key[i] >> 4);
    const n = correct.filter(Boolean).length;
    const trace = [
      C.step('cache-collect', `${samples} timed encryptions, each after evicting one random line of one table (${rounds === 'first' ? 'first-round lookups only' : 'all nine table rounds, so later lookups add noise'}).`, { samples }),
      C.step('cache-score', `For byte i and each guess h of its high nibble, average the time of the runs where (pᵢ ≫ 4) ⊕ h is the evicted line: if h is right, that run had to miss.`, { scores }),
      C.step('cache-result', `${n} of 16 high nibbles recovered: ${nibbles.map((v) => v.toString(16)).join('')} (true ${Array.from(key, (v) => (v >> 4).toString(16)).join('')}). That is ${4 * n} key bits from the first round alone.`, { nibbles, correct }),
    ];
    return { nibbles, correct, scores, trace };
  };

  const Ti = (C.Timing = {});
  /** a server that checks tags; its leaky comparison takes longer the more leading bytes are right */
  Ti.oracle = (o = {}) => {
    const tag = o.tag || C.rng(o.seed || 31).bytes(o.len || 8), r = C.rng((o.seed || 31) + 1);
    const base = o.base || 100, per = o.perByte != null ? o.perByte : 5, sigma = o.sigma != null ? o.sigma : 3;
    let calls = 0;
    const time = (g) => {
      calls++;
      let t = base;
      if (o.constantTime) {
        // every byte is compared and the differences ORed together: the time never depends on where they differ
        let diff = 0;
        for (let i = 0; i < tag.length; i++) { diff |= tag[i] ^ g[i]; t += per; }
        t += per;
      }
      else { let i = 0; while (i < tag.length && tag[i] === g[i]) { t += per; i++; } t += per; }
      return t + sigma * r.gauss();
    };
    const check = (g) => g.length === tag.length && g.every((v, i) => v === tag[i]);
    return { time, check, len: tag.length, get calls() { return calls; }, secret: tag, constantTime: !!o.constantTime };
  };
  /** recover the tag one byte at a time: for each position, the candidate with the longest mean time wins */
  Ti.recover = (oracle, o = {}) => {
    const len = o.len || oracle.len, reps = o.reps || 15, guess = new Uint8Array(len), profiles = [], trace = [];
    for (let pos = 0; pos < len; pos++) {
      const means = new Float64Array(256);
      for (let c = 0; c < 256; c++) { guess[pos] = c; let s = 0; for (let k = 0; k < reps; k++) s += oracle.time(guess); means[c] = s / reps; }
      let best = 0;
      for (let c = 1; c < 256; c++) if (means[c] > means[best]) best = c;
      const sorted = Array.from(means).sort((a, b) => b - a);
      guess[pos] = best;
      profiles.push(Array.from(means));
      trace.push(C.step('timing-byte', `Byte ${pos}: ${C.h2(best)} takes ${means[best].toFixed(1)} cycles on average, ${(sorted[0] - sorted[1]).toFixed(1)} more than the next candidate.`, { pos, best, margin: sorted[0] - sorted[1], means: Array.from(means) }));
    }
    const ok = oracle.check(Array.from(guess));
    trace.push(C.step(ok ? 'timing-done' : 'timing-fail', ok ? `The recovered tag ${Array.from(guess, C.h2).join('')} is accepted, after ${oracle.calls} timed queries instead of 2^${8 * len} guesses.` : `The tag ${Array.from(guess, C.h2).join('')} is rejected: ${oracle.constantTime ? 'a constant-time comparison gives the clock nothing to read' : 'the noise hid the signal; repeat each query more times'}.`, { tag: Array.from(guess), ok }));
    return { tag: guess, ok, profiles, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
