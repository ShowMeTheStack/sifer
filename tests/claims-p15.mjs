// Part 15, side channels: every topic run with its presets and random inputs; every value a frame's narration
// quotes is one of the frame's facts, and the facts are worked out again here: the AES S-box built from GF(2^8)
// inverses, Hamming weights by counting, correlations and differences of means by our own sums over the same
// simulated traces, cache lines from the first-round indices, comparison times from the loop's own rule, and
// the RSA fault attack by BigInt arithmetic. Prints "claims-p15 N passed, M failed".
// Usage: node tests/claims-p15.mjs [topic id prefix ...]
import { runClaims, near, S } from './claims-lib-p14.mjs';

// the AES S-box, built here: multiplicative inverse in GF(2^8), then the affine map
const mul = (a, b) => { let r = 0; while (b) { if (b & 1) r ^= a; a = (a << 1) ^ (a & 0x80 ? 0x11b : 0); b >>= 1; } return r & 255; };
const SBOX = Array.from({ length: 256 }, (_, x) => { let inv = 0; if (x) for (let y = 1; y < 256; y++) if (mul(x, y) === 1) { inv = y; break; } let s = inv; for (let k = 1; k <= 4; k++) s ^= ((inv << k) | (inv >> (8 - k))) & 255; return s ^ 0x63; });
const HW = (v) => { let c = 0; while (v) { c += v & 1; v >>= 1; } return c; };
const h2 = (v) => v.toString(16).padStart(2, '0');
const key = (t) => new TextEncoder().encode(String(t || 'harbour-lights-7').padEnd(16, '.').slice(0, 16));
const pearson = (a, b) => { const n = a.length; let sa = 0, sb = 0, saa = 0, sbb = 0, sab = 0; for (let i = 0; i < n; i++) { sa += a[i]; sb += b[i]; saa += a[i] * a[i]; sbb += b[i] * b[i]; sab += a[i] * b[i]; } const d = Math.sqrt((n * saa - sa * sa) * (n * sbb - sb * sb)); return d ? (n * sab - sa * sb) / d : 0; };
/** max over samples of |ρ| between the predicted weights for guess g and the traces */
const peakCorr = (ch, byte, g, model) => { let best = 0; const h = []; for (let i = 0; i < ch.count; i++) { const x = ch.plaintexts[i * 16 + byte] ^ g, y = SBOX[x]; h.push(model === 'hd' ? HW(x ^ y) : HW(y)); } for (let t = 0; t < ch.T; t++) { const col = []; for (let i = 0; i < ch.count; i++) col.push(ch.traces[i * ch.T + t]); best = Math.max(best, Math.abs(pearson(h, col))); } return best; };

const mods = [
  {
    topic: 'sc-trace', allow: ['3', '4', '5', '16', '52', '256'],
    random: (rnd) => ({ byte: Math.floor(rnd() * 16), sigma: ['0.5', '1', '2', '3'][Math.floor(rnd() * 4)], seed: 1 + Math.floor(rnd() * 900) }),
    check({ input, r, fail }) {
      const k = key(input.key), b = +input.byte, ch = S.SC.source({ key: k, sigma: 0, seed: +input.seed }).next(1), p = ch.plaintexts[b];
      const f = r.frames.find((x) => x.meta.stage === 'clean').facts;
      if (f.p !== h2(p) || f.x !== h2(p ^ k[b]) || f.y !== h2(SBOX[p ^ k[b]]) || f.hy !== HW(SBOX[p ^ k[b]]) || f.hp !== HW(p)) fail('the three values of byte ' + b);
      if (f.tl !== 2 + 3 * b) fail('the sample of byte ' + b);
      const m = r.frames.find((x) => x.meta.stage === 'many').facts, ch2 = S.SC.source({ key: k, sigma: +input.sigma, seed: +input.seed + 1 }).next(400);
      const h = [], col = []; for (let i = 0; i < 400; i++) { h.push(HW(SBOX[ch2.plaintexts[i * 16 + b] ^ k[b]])); col.push(ch2.traces[i * 52 + 4 + 3 * b]); }
      if (!near(m.rho, pearson(h, col), 6)) fail('ρ = ' + m.rho + ' against ' + pearson(h, col));
    },
  },
  {
    topic: 'sc-models', allow: ['3', '4', '5', '6', '7', '8'],
    random: (rnd) => ({ a: h2(Math.floor(rnd() * 256)), b: h2(Math.floor(rnd() * 256)) }), count: 6,
    check({ input, r, fail }) {
      const a = parseInt(input.a, 16), b = parseInt(input.b, 16), f = r.frames[1].facts;
      if (f.hd !== HW(a ^ b) || f.hb !== HW(b) || f.d !== h2(a ^ b)) fail('the weights');
      const t = r.frames[2].facts, k = key(input.key), want = [];
      for (const dev of ['hw', 'hd']) { const ch = S.SC.source({ key: k, model: dev, sigma: +input.sigma, seed: 21 }).next(+input.n); for (const mod of ['hw', 'hd']) want.push(peakCorr(ch, 0, k[0], mod)); }
      want.forEach((v, i) => { if (!near(t.r[i], v, 6)) fail('the correlation of pairing ' + i + ': ' + t.r[i] + ' against ' + v); });
    },
  },
  {
    topic: 'sc-spa', allow: ['3', '4', '5'],
    random: (rnd) => ({ e: String(2 + Math.floor(rnd() * 500000)), sigma: '0.1', always: rnd() < 0.3 ? 'yes' : 'no' }),
    check({ input, r, fail }) {
      const bits = BigInt(input.e).toString(2), always = input.always === 'yes';
      const ops = [...bits.slice(1)].map((c) => 'S' + (c === '1' || always ? 'M' : '')).join('');
      const f = r.frames[0].facts;
      if (f.bits !== bits || f.ops !== ops) fail('the operations');
      // the outcome frame states whether one trace exposes the exponent; checked here by reading it (never shown)
      const rd = r.frames.find((x) => x.meta.stage === 'outcome');
      if (!rd || r.frames.some((x) => x.meta.stage === 'read' || x.meta.stage === 'bursts')) fail('the frames');
      if (always && rd.meta.ok && /0/.test(bits)) fail('multiply-always was said to expose the exponent');
      if (rd.meta.ok !== (rd.facts.read === bits)) fail('the verdict');
      if (!always && input.sigma === '0.1' && !rd.meta.ok) fail('a clean naive trace should expose the exponent');
    },
  },
  {
    topic: 'sc-dpa', allow: ['3', '15', '16', '256'],
    check({ input, r, fail }) {
      const k = key(input.key), b = +input.byte, bit = +input.bit, ch = S.SC.source({ key: k, sigma: +input.sigma, seed: +input.seed }).next(+input.n);
      const peak = (g) => { let best = 0; for (let t = 0; t < 52; t++) { let s1 = 0, n1 = 0, s0 = 0, n0 = 0; for (let i = 0; i < ch.count; i++) { const v = ch.traces[i * 52 + t]; if ((SBOX[ch.plaintexts[i * 16 + b] ^ g] >> bit) & 1) { s1 += v; n1++; } else { s0 += v; n0++; } } best = Math.max(best, Math.abs(s1 / n1 - s0 / n0)); } return best; };
      const f = r.frames[0].facts, kb = k[b];
      if (!near(f.peak, peak(kb), 6)) fail('the true byte\'s peak');
      const peaks = Array.from({ length: 256 }, (_, g) => peak(g)), rank = peaks.filter((v) => v > peaks[kb]).length + 1;
      if (f.rank !== rank) fail('the rank ' + f.rank + ' against ' + rank);
      // the masked device: its first-order spike should be gone
      const m = r.frames.find((x) => x.meta.stage === 'masked');
      if (!m) fail('no masked frame');
      else if (+input.n >= 1000 && m.facts.mrank === 1) fail('masking left the true byte on top');
    },
  },
  {
    topic: 'sc-cpa', allow: ['4', '128', '16', '255', '256'],
    check({ input, r, fail }) {
      const k = key(input.key), b = +input.byte, src = S.SC.source({ key: k, sigma: +input.sigma, seed: +input.seed });
      const all = src.next(+input.n);
      const sub = (n) => ({ count: n, T: 52, plaintexts: all.plaintexts.subarray(0, n * 16), traces: all.traces.subarray(0, n * 52) });
      for (const f of r.frames.filter((x) => x.meta.stage === 'snap')) {
        const n = f.facts.n, ch = sub(n), mine = peakCorr(ch, b, k[b], 'hw');
        if (!near(f.facts.peak, mine, 6)) fail(n + ' traces: the true peak ' + f.facts.peak + ' against ' + mine);
        if (!near(f.facts.noise, 4 / Math.sqrt(n), 9)) fail('the noise level');
        if (n === +input.n) { const others = Array.from({ length: 256 }, (_, g) => (g === k[b] ? 0 : peakCorr(ch, b, g, 'hw'))); const rank = others.filter((v) => v > mine).length + 1; if (rank !== f.facts.rank) fail('the final rank'); }
      }
    },
  },
  {
    topic: 'sc-cpa-traces', allow: ['2', '3', '4', '6', '8', '12', '16'],
    check({ r, fail }) {
      for (const f of r.frames.filter((x) => x.meta.stage === 'run')) {
        const v = f.facts.all.map((x) => (x === null ? Infinity : x)).sort((a, b) => a - b)[1];
        if ((v === Infinity ? null : v) !== f.facts.s) fail('the median at σ = ' + f.facts.sigma);
      }
    },
  },
  {
    topic: 'sc-masking', allow: ['3', '4', '5', '250', '256'],
    check({ input, r, fail }) {
      const k = key(input.key), b = +input.byte, ex = S.SC.maskedLookup(+input.x, 0x5a, 0xc3), f0 = r.frames[0].facts;
      if (f0.xm !== h2(+input.x ^ 0x5a) || f0.ym !== h2(SBOX[+input.x] ^ 0xc3) || f0.y !== h2(SBOX[+input.x])) fail('the masked lookup');
      // the second-order peak, by our own centred products over the same traces, chunk by chunk
      const src = S.SC.source({ key: k, sigma: +input.sigma, seed: +input.seed, masked: true }), h = [], v = [], ts = 4 + 3 * b;
      for (let n = 0; n < +input.n; n += 250) {
        const ch = src.next(250); let mA = 0, mB = 0;
        for (let i = 0; i < 250; i++) { mA += ch.traces[i * 52 + 1]; mB += ch.traces[i * 52 + ts]; }
        mA /= 250; mB /= 250;
        for (let i = 0; i < 250; i++) { v.push((ch.traces[i * 52 + 1] - mA) * (ch.traces[i * 52 + ts] - mB)); h.push(HW(SBOX[ch.plaintexts[i * 16 + b] ^ k[b]])); }
      }
      const second = r.frames.find((x) => x.meta.stage === 'second').facts;
      if (!near(second.peak, Math.abs(pearson(h, v)), 5)) fail('the second-order correlation ' + second.peak + ' against ' + Math.abs(pearson(h, v)));
    },
  },
  {
    topic: 'sc-cache', allow: ['4', '16', '64', '256', '12', '15', '9'],
    check({ input, r, fail }) {
      const k = key(input.key), pt = new TextEncoder().encode(String(input.pt).padEnd(16, '.').slice(0, 16));
      const f = r.frames.find((x) => x.meta.stage === 'evict').facts;
      if (f.idx !== h2(pt[0] ^ k[0]) || f.line !== (pt[0] ^ k[0]) >> 4) fail('byte 0\'s index and line');
      const lines = new Set([0, 4, 8, 12].map((i) => (pt[i] ^ k[i]) >> 4));
      if (lines.has(f.un)) fail('the "unused" line is used');
      if (f.diff !== 39) fail('a miss should cost 40 − 1 = 39 cycles more');
      if (!r.frames.some((x) => x.meta.stage === 'defence') || r.frames.some((x) => x.meta.stage === 'collect')) fail('the frames');
      const res = r.frames.find((x) => x.meta.stage === 'result').facts;
      if (res.want !== Array.from(k, (v) => (v >> 4).toString(16)).join('')) fail('the true nibbles');
      if (res.ok !== [...res.got].filter((c, i) => c === res.want[i]).length || res.bits !== 4 * res.ok) fail('the count recovered');
    },
  },
  {
    topic: 'sc-mac-timing', allow: ['3', '4', '5', '6', '15', '40', '256'],
    check({ input, r, fail }) {
      const len = +input.len, reps = +input.reps, end = r.frames.find((x) => x.meta.stage === 'end');
      if (end.facts.calls !== len * 256 * reps) fail('the query count');
      if (input.ct === 'yes' && end.meta.ok) fail('a constant-time comparison was broken');
      const o = S.SC.Timing.oracle({ len, seed: +input.seed });
      const tag = Array.from(o.secret, h2).join('');
      if (end.meta.ok !== (end.facts.tag === tag)) fail('the verdict');
      if (r.frames.some((x) => x.meta.stage === 'byte')) fail('the byte-by-byte frames are back');
      const lk = r.frames.find((x) => x.meta.stage === 'leak');
      if (!lk || lk.facts.truth !== tag.slice(0, 2)) fail('the true first byte');
      if ((input.ct !== 'yes') !== r.frames.some((x) => x.meta.stage === 'fix')) fail('the fix frame');
    },
  },
  {
    topic: 'sc-consttime', allow: ['3', '4'],
    random: (rnd) => ({ e1: String(2 + Math.floor(rnd() * 1e6)), e2: String(2 + Math.floor(rnd() * 1e6)), seed: 1 + Math.floor(rnd() * 900) }),
    check({ input, r, fail }) {
      const f = r.frames[1].facts;
      // base 100, 5 a byte: the leaky loop runs (matching prefix + 1) times; the safe one always n + 1
      if (f.l1 !== 105 || f.l2 !== 120 || f.s1 !== 125 || f.s2 !== 125) fail('the comparison times');
      const e = r.frames[2].facts, cnt = (v, always) => { const b = BigInt(v).toString(2); return [b.length - 1, always ? b.length - 1 : [...b.slice(1)].filter((c) => c === '1').length]; };
      if (e.a1.join() !== cnt(input.e1).join() || e.a2.join() !== cnt(input.e2).join() || e.b1.join() !== cnt(input.e1, 1).join() || e.b2.join() !== cnt(input.e2, 1).join()) fail('the operation counts');
    },
  },
  {
    topic: 'sc-fault', allow: ['4', '64', '128', '512'],
    random: (rnd) => ({ bits: ['64', '128'][Math.floor(rnd() * 2)], half: rnd() < 0.5 ? 'p' : 'q', bit: Math.floor(rnd() * 30), seed: 1 + Math.floor(rnd() * 900) }), count: 6,
    check({ input, r, fail }) {
      const k = S.SC.Fault.key({ bits: +input.bits, seed: +input.seed, own: true });
      if (k.p * k.q !== k.n) fail('p·q is not N');
      const gcd = (a, b) => { a = a < 0n ? -a : a; while (b) [a, b] = [b, a % b]; return a; };
      if (((k.e * k.d) % ((k.p - 1n) * (k.q - 1n))) !== 1n) fail('e·d is not 1 mod φ(N)');
      const at = r.frames.find((x) => x.meta.stage === 'exposed');
      if (input.check === 'yes') { if (at || r.frames.find((x) => x.meta.stage === 'fault').meta.released) fail('a faulty signature got out despite the check'); return; }
      if (!at || !at.meta.ok) { fail('the outcome frame'); return; }
      if (r.frames.some((x) => x.meta.stage === 'attack' || x.meta.stage === 'key-out')) fail('the step-by-step frames are back');
      // the claim that one faulty signature exposes a factor, worked out here by BigInt arithmetic (never shown)
      const pw = (b, e, m) => { let r2 = 1n; b %= m; while (e) { if (e & 1n) r2 = (r2 * b) % m; b = (b * b) % m; e >>= 1n; } return r2; };
      let m = 0n; for (const c of new TextEncoder().encode(String(input.msg || 'invoice 4417 paid'))) m = (m * 256n + BigInt(c)) % k.n;
      const bad = S.SC.Fault.sign(k, m, { fault: { half: input.half || 'q', bit: +(input.bit ?? 5) } });
      const g = gcd(((pw(bad.s, k.e, k.n) - m) % k.n + k.n) % k.n, k.n), want = (input.half || 'q') === 'q' ? k.p : k.q;
      if (g !== want) fail('one faulty signature does not expose ' + ((input.half || 'q') === 'q' ? 'p' : 'q'));
    },
  },
  {
    topic: 'sc-defences', allow: ['1000', '256', '16', '6', '12345'],
    check({ r, fail }) {
      const spa = r.frames.find((x) => x.meta.stage === 'spa');
      if (spa && (spa.facts.got === spa.facts.want || !/^1+$/.test(spa.facts.got))) fail('multiply-always should read as all ones');
      const cpa = r.frames.find((x) => x.meta.stage === 'cpa');
      if (cpa && cpa.facts.rank === 1) fail('first-order CPA broke the masking');
      const ho = r.frames.find((x) => x.meta.stage === 'ho');
      if (ho && ho.facts.rank !== 1) fail('the second-order attack did not find the byte');
    },
  },
];

const only = process.argv.slice(2);
await runClaims('claims-p15', 'p15-', mods, only);
