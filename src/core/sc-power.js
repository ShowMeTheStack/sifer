// Simulated power traces. A device runs the first round of AES-128 one byte at a time (load the plaintext byte,
// add the key byte, look it up in the S-box) and each operation draws power in proportion to the Hamming weight of
// the value it handles (or the Hamming distance from the value it overwrites), plus Gaussian noise. All seeded.
// Traces come out in chunks of plain typed arrays, so a Web Worker can make them and hand them over.
//   S.SC.source({key, model: 'hw' | 'hd', sigma, seed, masked}) -> {T, layout, next(count) -> chunk}
//      chunk = {count, T, plaintexts: Uint8Array(count·16), traces: Float32Array(count·T)}
//   S.SC.maskedSbox(mIn, mOut) -> table with table[x ⊕ mIn] = S[x] ⊕ mOut;  S.SC.maskedLookup(x, mIn, mOut)
//   S.SC.spaTrace(exponent, {seed, sigma, always}) -> {samples, ops, segments}
//   S.SC.spaRead(samples) -> {ops, bits, exponent}
(function (S) {
  'use strict';
  const C = (S.SC = S.SC || {});
  C.step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  C.rng = (seed) => S.PQ.rng(seed);
  const HW = new Uint8Array(256);
  for (let i = 0; i < 256; i++) HW[i] = (i & 1) + HW[i >> 1];
  C.HW = HW;
  C.sbox = () => S.gf256.SBOX;
  C.h2 = (v) => (v & 255).toString(16).padStart(2, '0');

  /** the time-sample layout of one trace: two set-up samples, then three per key byte, then two idle samples */
  C.layout = (masked) => {
    const L = [{ t: 0, op: masked ? 'mask-in' : 'idle' }, { t: 1, op: masked ? 'mask-out' : 'idle' }];
    for (let b = 0; b < 16; b++) ['load', 'ark', 'sbox'].forEach((op, j) => L.push({ t: 2 + 3 * b + j, byte: b, op }));
    L.push({ t: 50, op: 'idle' }, { t: 51, op: 'idle' });
    return L;
  };
  C.sampleOf = (byte, op) => 2 + 3 * byte + ['load', 'ark', 'sbox'].indexOf(op);
  C.maskedSbox = (mIn, mOut) => { const SB = C.sbox(), t = new Uint8Array(256); for (let x = 0; x < 256; x++) t[x ^ mIn] = SB[x] ^ mOut; return t; };
  /** a first-order Boolean masked lookup: the device only ever holds x ⊕ mIn and S(x) ⊕ mOut */
  C.maskedLookup = (x, mIn, mOut) => {
    const t = C.maskedSbox(mIn, mOut), xm = x ^ mIn, ym = t[xm], y = ym ^ mOut;
    return { y, xm, ym, trace: [
      C.step('mask-table', `Recompute the table for masks mIn = ${C.h2(mIn)}, mOut = ${C.h2(mOut)}: T[x ⊕ mIn] = S[x] ⊕ mOut.`, { mIn, mOut }),
      C.step('mask-in', `The device holds x ⊕ mIn = ${C.h2(xm)}, never x = ${C.h2(x)} itself.`, { xm }),
      C.step('mask-out', `T[${C.h2(xm)}] = ${C.h2(ym)} = S(x) ⊕ mOut; only the final unmasking gives S(x) = ${C.h2(y)}. Each value the device touches is uniformly random on its own.`, { ym, y }),
    ] };
  };
  C.source = (opts = {}) => {
    const key = opts.key, model = opts.model || 'hw', sigma = opts.sigma != null ? opts.sigma : 3, masked = !!opts.masked;
    if (!key || key.length !== 16) throw new Error('the trace source needs a 16-byte AES key');
    const r = C.rng(opts.seed || 1), SB = C.sbox(), T = 52, layout = C.layout(masked);
    let made = 0;
    return {
      T, layout, model, sigma, masked,
      get made() { return made; },
      next(count) {
        const pts = new Uint8Array(count * 16), tr = new Float32Array(count * T);
        for (let n = 0; n < count; n++) {
          const o = n * T, p = pts.subarray(n * 16, n * 16 + 16);
          for (let b = 0; b < 16; b++) p[b] = r.int(256);
          const mIn = masked ? r.int(256) : 0, mOut = masked ? r.int(256) : 0;
          const leak = (t, v) => { tr[o + t] = v + sigma * r.gauss(); };
          leak(0, masked ? HW[mIn] : 4); leak(1, masked ? HW[mOut] : 4);
          let prev = 0;
          for (let b = 0; b < 16; b++) {
            const x = p[b] ^ key[b], y = SB[x], t = 2 + 3 * b;
            if (model === 'hd') {
              // a register that is overwritten: plaintext over the last S-box output, then x, then S(x)
              leak(t, HW[prev ^ (p[b] ^ mIn)]); leak(t + 1, HW[(p[b] ^ mIn) ^ (x ^ mIn)]); leak(t + 2, HW[(x ^ mIn) ^ (y ^ mOut)]);
              prev = y ^ mOut;
            } else { leak(t, HW[p[b]]); leak(t + 1, HW[x ^ mIn]); leak(t + 2, HW[y ^ mOut]); }
          }
          leak(50, 4); leak(51, 4);
        }
        made += count;
        return { count, T, plaintexts: pts, traces: tr };
      },
    };
  };

  // Simple power analysis: square and multiply draw visibly different shapes, so the trace spells the exponent.
  const SHAPE = { S: [0.9, 1.8, 2.2, 2.3, 2.2, 2.3, 1.8, 0.9], M: [1.1, 2.4, 3.1, 3.2, 2.6, 3.1, 3.3, 2.6, 3.0, 3.2, 2.3, 1.1] };
  C.SHAPE = SHAPE;
  /** left to right over the bits after the leading 1: square every bit, multiply for each 1 (or always, with a dummy) */
  C.spaTrace = (exponent, opts = {}) => {
    const bitsStr = BigInt(exponent).toString(2), r = C.rng(opts.seed || 4), sigma = opts.sigma != null ? opts.sigma : 0.15, gap = 3;
    const ops = [];
    for (const b of bitsStr.slice(1)) { ops.push('S'); if (b === '1' || opts.always) ops.push('M'); }
    const samples = [], segments = [];
    const idle = () => { for (let i = 0; i < gap; i++) samples.push(sigma * r.gauss()); };
    idle();
    for (const op of ops) { const start = samples.length; for (const v of SHAPE[op]) samples.push(v + sigma * r.gauss()); segments.push({ op, start, end: samples.length }); idle(); }
    return { samples: Float32Array.from(samples), ops, segments, bits: bitsStr, trace: [
      C.step('spa-ops', `Exponent ${bitsStr} (binary): after the leading 1 each bit squares (S), and a 1 bit also multiplies (M): ${ops.join('')}.`, { ops }),
      C.step('spa-trace', opts.always ? 'Square-and-multiply-always: every bit does S then M (a dummy M for a 0), so the shape no longer depends on the bits.' : `The trace has ${ops.length} bursts; an M burst is half as long again as an S burst and draws more power.`, { segments }),
    ] };
  };
  /** read a trace back: cut it at the quiet gaps, call long bursts M and short ones S, then rebuild the bits */
  C.spaRead = (samples, opts = {}) => {
    const th = opts.threshold || 0.5, segs = [];
    let start = -1;
    for (let i = 0; i <= samples.length; i++) {
      const on = i < samples.length && samples[i] > th;
      if (on && start < 0) start = i;
      if (!on && start >= 0) { if (i - start >= 4) segs.push({ start, end: i }); start = -1; } // a blip of noise is not a burst
    }
    const ops = segs.map((s) => (s.end - s.start > (SHAPE.S.length + SHAPE.M.length) / 2 ? 'M' : 'S'));
    let bits = '1';
    ops.forEach((op, i) => { if (op === 'S') bits += ops[i + 1] === 'M' ? '1' : '0'; });
    return { ops, segments: segs, bits, exponent: BigInt('0b' + bits), trace: [C.step('spa-read', `Bursts read as ${ops.join('')}; "SM" is a 1 and a lone "S" is a 0, so the exponent is 1${bits.slice(1)}.`, { ops, bits })] };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
