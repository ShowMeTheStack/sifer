// Part 12, hash functions: every topic run with its presets and random inputs; every number and hex string a
// frame's narration quotes is one of the frame's facts, and the facts are worked out again here without the topics'
// code path: node:crypto for SHA-1, SHA-256, SHA-3, SHAKE and MD5, and a SHA-256 round function, a message schedule
// and the Keccak steps written out again below. Prints "claims-p12 N passed, M failed".
// Usage: node tests/claims-p12.mjs [topic id prefix ...]
import { createHash, createHmac } from 'node:crypto';
import { runClaims, utf8, hex, fromHex } from './claims-p12-lib.mjs';

const H = (alg, m) => createHash(alg).update(m).digest();
const trunc = (d, bits) => { let v = 0; for (let i = 0; i < Math.ceil(bits / 8); i++) v = v * 256 + d[i]; return Math.floor(v / 2 ** (Math.ceil(bits / 8) * 8 - bits)); };
const th = (v, bits) => v.toString(16).padStart(Math.ceil(bits / 4), '0');
const h8 = (v) => (v >>> 0).toString(16).padStart(8, '0');

// ---- SHA-256, written out again: the padding, the schedule and the rounds
const K256 = [];
{ const primes = []; for (let n = 2; primes.length < 64; n++) if (primes.every((p) => n % p)) primes.push(n); for (const p of primes) K256.push(Math.floor((Math.cbrt(p) % 1) * 2 ** 32) >>> 0); }
// the cube roots in doubles are exact to 32 bits for these primes except where rounding bites: check two published values
const KFIX = { 0: 0x428a2f98, 63: 0xc67178f2 };
const ror = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
const pad256 = (m) => { const n = m.length, L = Math.ceil((n + 9) / 64) * 64, o = new Uint8Array(L); o.set(m); o[n] = 0x80; const b = BigInt(n) * 8n; for (let i = 0; i < 8; i++) o[L - 1 - i] = Number((b >> BigInt(8 * i)) & 255n); return o; };
const sched = (blk) => { const W = []; for (let t = 0; t < 16; t++) W.push(((blk[4 * t] << 24) | (blk[4 * t + 1] << 16) | (blk[4 * t + 2] << 8) | blk[4 * t + 3]) >>> 0); for (let t = 16; t < 64; t++) { const s0 = ror(W[t - 15], 7) ^ ror(W[t - 15], 18) ^ (W[t - 15] >>> 3), s1 = ror(W[t - 2], 17) ^ ror(W[t - 2], 19) ^ (W[t - 2] >>> 10); W.push((s1 + W[t - 7] + s0 + W[t - 16]) >>> 0); } return W; };
const IV256 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const KT = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
const rounds = (cv, blk) => {
  const W = sched(blk); let [a, b, c, d, e, f, g, h] = cv; const out = [];
  for (let t = 0; t < 64; t++) {
    const T1 = (h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + KT[t] + W[t]) >>> 0, T2 = ((ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
    h = g; g = f; f = e; e = (d + T1) >>> 0; d = c; c = b; b = a; a = (T1 + T2) >>> 0;
    out.push({ T1, T2, regs: [a, b, c, d, e, f, g, h] });
  }
  return { out, H: [a, b, c, d, e, f, g, h].map((v, i) => (v + cv[i]) >>> 0) };
};

// ---- Keccak, written out again
const M64 = (1n << 64n) - 1n, rot = (v, n) => (n % 64 ? ((v << BigInt(n % 64)) | (v >> BigInt(64 - (n % 64)))) & M64 : v);
const RHO = [[0, 1, 62, 28, 27], [36, 44, 6, 55, 20], [3, 10, 43, 25, 39], [41, 45, 15, 21, 8], [18, 2, 61, 56, 14]]; // FIPS 202, r[x][y] by rows of y
const RCS = ['0000000000000001', '0000000000008082', '800000000000808a', '8000000080008000', '000000000000808b', '0000000080000001', '8000000080008081', '8000000000008009', '000000000000008a', '0000000000000088', '0000000080008009', '000000008000000a', '000000008000808b', '800000000000008b', '8000000000008089', '8000000000008003', '8000000000008002', '8000000000000080', '000000000000800a', '800000008000000a', '8000000080008081', '8000000000008080', '0000000080000001', '8000000080008008'];
const theta = (A) => { const C = [0, 1, 2, 3, 4].map((x) => A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20]); const D = C.map((_, x) => C[(x + 4) % 5] ^ rot(C[(x + 1) % 5], 1)); return { A: A.map((v, i) => v ^ D[i % 5]), C, D }; };
const kround = (A, r) => {
  const t = theta(A).A, rh = t.map((v, i) => rot(v, RHO[Math.floor(i / 5)][i % 5])), pi = new Array(25);
  for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) pi[y + 5 * ((2 * x + 3 * y) % 5)] = rh[x + 5 * y];
  const chi = pi.map((v, i) => { const x = i % 5, y = Math.floor(i / 5); return v ^ (~pi[((x + 1) % 5) + 5 * y] & M64 & pi[((x + 2) % 5) + 5 * y]); });
  const io = chi.slice(); io[0] ^= BigInt('0x' + RCS[r]);
  return { theta: t, rho: rh, pi, chi, iota: io };
};
const absorbed = (msg) => { const m = utf8(msg), b = new Uint8Array(136); b.set(m); b[m.length] ^= 6; b[135] ^= 0x80; const A = new Array(25).fill(0n); for (let i = 0; i < 136; i++) A[i >> 3] |= BigInt(b[i]) << BigInt(8 * (i & 7)); return A; };
const pop = (A) => A.reduce((n, v) => n + v.toString(2).split('1').length - 1, 0);

const pick = (rnd, xs) => xs[Math.floor(rnd() * xs.length)];
const words = ['tide', 'lantern', 'ash', 'wren', 'harbour', 'ledger', 'gate', 'salt', 'north', 'sixty', 'quiet', 'river'];
const phrase = (rnd, n) => Array.from({ length: n }, () => pick(rnd, words)).join(' ');

const mods = [
  {
    topic: 'p12-games', allow: ['256'],
    random: (rnd) => { const g = pick(rnd, ['pre', 'second', 'coll']); return { game: g, bits: pick(rnd, g === 'coll' ? ['8', '12', '16', '20'] : ['8', '12']), seed: 1 + Math.floor(rnd() * 900) }; },
    check({ input, r, fail }) {
      const bits = +input.bits, g = input.game, seed = +input.seed, end = r.frames.find((f) => f.meta.stage === 'win').facts;
      const msgOf = (i) => (g === 'pre' ? 'guess ' + i : g === 'second' ? 'Pay 900 to Mallory, note ' + i : 'ticket ' + seed + '-' + i);
      const target = r.frames[1].facts.target, [wi, wj, wv] = end.win;
      if (g !== 'coll') {
        const v = trunc(H('sha256', msgOf(wi)), bits);
        if (th(v, bits) !== target || wv !== target) fail('the winning try does not hit the target');
        for (let i = 1; i < wi; i++) if (trunc(H('sha256', msgOf(i)), bits) === parseInt(target, 16)) { fail('an earlier try ' + i + ' already won'); break; }
        if (hex(H('sha256', msgOf(wi))) !== end.fullA) fail('the full digest of the winner');
      } else {
        const seen = new Map(); let hit = null;
        for (let i = 1; !hit; i++) { const v = trunc(H('sha256', msgOf(i)), bits); if (seen.has(v)) hit = [i, seen.get(v), v]; else seen.set(v, i); }
        if (hit[0] !== wi || hit[1] !== wj || th(hit[2], bits) !== wv) fail('the first collision is ' + hit + ', not ' + end.win);
      }
      const cost = r.frames[r.frames.length - 1].facts;
      const exp = g === 'coll' ? Math.sqrt((Math.PI / 2) * 2 ** bits) : 2 ** bits;
      if (Math.abs(cost.expected - exp) > 1e-6 || Math.abs(cost.ratio - wi / exp) > 1e-9) fail('the expected cost');
    },
  },
  {
    topic: 'p12-birthday',
    random: (rnd) => ({ space: pick(rnd, ['365', '256', '1024', '4096']), q: 2 + Math.floor(rnd() * 150), seed: 1 + Math.floor(rnd() * 900) }),
    check({ input, r, fail }) {
      const N = +input.space, P = (k) => 1 - Math.exp((-k * (k - 1)) / (2 * N));
      let half = 2; while (P(half) < 0.5) half++;
      if (r.frames[0].facts.half !== half) fail('the half-way count ' + r.frames[0].facts.half + ' is not ' + half);
      // the pair counts, worked out again from the slots the frames report, in order
      const counts = new Map(); let pairs = 0, k = 0;
      const rnd = S.Hash.rng('bday:' + input.seed), draws = Array.from({ length: +input.q }, () => rnd.int(N));
      for (const f of r.frames) {
        if (f.meta.stage !== 'draw' && f.meta.stage !== 'hit') continue;
        while (k < f.facts.k) { const v = draws[k++]; pairs += counts.get(v) || 0; counts.set(v, (counts.get(v) || 0) + 1); }
        if (f.facts.v !== draws[k - 1] || f.facts.pairs !== pairs) fail('the pairs after ' + k + ' draws');
        if (Math.abs(f.facts.p - P(k)) > 1e-12) fail('the chance after ' + k);
      }
      const end = r.frames[r.frames.length - 1].facts;
      if (Math.abs(end.expPairs - (+input.q * (+input.q - 1)) / 2 / N) > 1e-12) fail('the expected pairs');
    },
  },
  {
    topic: 'p12-md', allow: ['80', '1000', '0000'],
    random: (rnd) => ({ msg: phrase(rnd, Math.floor(rnd() * 25)), hash: pick(rnd, ['sha256', 'sha1', 'md5']) }),
    check({ input, r, fail }) {
      const m = utf8(input.msg), n = m.length, alg = input.hash, B = 64, L = 8;
      const nb = Math.ceil((n + 1 + L) / B), zeros = nb * B - n - 1 - L;
      const f2 = r.frames.find((f) => f.meta.stage === 'zeros').facts, f3 = r.frames.find((f) => f.meta.stage === 'len').facts;
      if (f2.zeros !== zeros || f3.nb !== nb) fail('the padding: ' + zeros + ' zeros and ' + nb + ' blocks');
      const bits = BigInt(n) * 8n, lb = []; for (let i = 0; i < 8; i++) lb.push(Number((bits >> BigInt(8 * i)) & 255n));
      if (f3.lenHex !== hex(alg === 'md5' ? lb : lb.reverse())) fail('the length field');
      if (r.frames[r.frames.length - 1].facts.digest !== hex(H(alg, m))) fail('the digest against node');
      if (alg === 'sha256') { const p = pad256(m); let cv = IV256; r.frames.filter((f) => f.meta.stage === 'f').forEach((f, k) => { const nx = rounds(cv, p.subarray(64 * k, 64 * k + 64)).H; if (f.facts.cvOut !== nx.map(h8).join(' ')) fail('chaining value ' + (k + 1)); cv = nx; }); }
    },
  },
  {
    topic: 'p12-schedule', allow: ['64', '32', '48', '7', '18', '3', '17', '19', '10', '16'],
    random: (rnd) => ({ msg: phrase(rnd, 2 + Math.floor(rnd() * 6)), block: 1, word: 16 + Math.floor(rnd() * 48) }),
    check({ input, r, fail }) {
      const p = pad256(utf8(input.msg)), W = sched(p.subarray(64 * (input.block - 1), 64 * input.block)), t = +input.word;
      const s0 = r.frames.find((f) => f.meta.stage === 's0').facts, s1 = r.frames.find((f) => f.meta.stage === 's1').facts, sm = r.frames.find((f) => f.meta.stage === 'sum').facts;
      const x = W[t - 15], y = W[t - 2];
      if (s0.s0 !== h8(ror(x, 7) ^ ror(x, 18) ^ (x >>> 3)) || s1.s1 !== h8(ror(y, 17) ^ ror(y, 19) ^ (y >>> 10))) fail('σ0 or σ1');
      if (sm.w !== h8(W[t])) fail('W' + t);
      if (r.frames[r.frames.length - 1].facts.w63 !== h8(W[63])) fail('W63');
      for (const k of [0, 63]) if (K256[k] !== KFIX[k] && KT[k] !== KFIX[k]) fail('the round constants');
    },
  },
  {
    topic: 'p12-compress', allow: ['64', '32'],
    random: (rnd) => ({ msg: phrase(rnd, 1 + Math.floor(rnd() * 8)), block: 1, round: Math.floor(rnd() * 62) }),
    check({ input, r, fail }) {
      const m = utf8(input.msg), p = pad256(m), k = input.block - 1;
      let cv = IV256; for (let i = 0; i < k; i++) cv = rounds(cv, p.subarray(64 * i, 64 * i + 64)).H;
      const R = rounds(cv, p.subarray(64 * k, 64 * k + 64));
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage, rr = f.meta.rr;
        if (st === 'T1' && x.T1 !== h8(R.out[rr].T1)) fail('T1 of round ' + rr);
        if (st === 'T2' && x.T2 !== h8(R.out[rr].T2)) fail('T2 of round ' + rr);
        if (st === 'new' && (x.a !== h8(R.out[rr].regs[0]) || x.e !== h8(R.out[rr].regs[4]))) fail('the new a and e of round ' + rr);
        if (st === 'out') { if (x.dg !== R.H.map(h8).join('')) fail('the output chaining value'); if (x.digest !== hex(H('sha256', m))) fail('the digest against node'); }
      }
    },
  },
  {
    topic: 'p12-older', allow: ['5', '30', '80', '64'],
    random: (rnd) => ({ msg: phrase(rnd, 1 + Math.floor(rnd() * 6)) }),
    check({ input, r, fail }) {
      const m = utf8(input.msg), blk = pad256(m), w0 = ((blk[0] << 24) | (blk[1] << 16) | (blk[2] << 8) | blk[3]) >>> 0;
      const [a, b, c, d, e] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0], rol = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
      const T = (rol(a, 5) + (((b & c) | (~b & d)) >>> 0) + e + 0x5a827999 + w0) >>> 0;
      const f1 = r.frames[0].facts;
      if (f1.T !== h8(T) || f1.c !== h8(rol(b, 30))) fail('SHA-1 step 0');
      const x0 = (blk[0] | (blk[1] << 8) | (blk[2] << 16) | (blk[3] << 24)) >>> 0, F = ((b & c) | (~b & d)) >>> 0, Kk = Math.floor(Math.abs(Math.sin(1)) * 2 ** 32) >>> 0;
      const sum = (a + F + Kk + x0) >>> 0, nb = (b + rol(sum, 7)) >>> 0, f2 = r.frames[1].facts;
      if (f2.sum !== h8(sum) || f2.b !== h8(nb)) fail('MD5 step 0');
      if (r.frames[r.frames.length - 1].facts.d256 !== hex(H('sha256', m))) fail('SHA-256 of the message');
    },
  },
  {
    topic: 'p12-sponge', allow: ['06', '80', '1600', '200', '24'],
    random: (rnd) => ({ msg: phrase(rnd, Math.floor(rnd() * 30)), alg: pick(rnd, ['sha3-224', 'sha3-256', 'sha3-384', 'sha3-512']) }),
    check({ input, r, fail }) {
      const out = r.frames[r.frames.length - 1].facts.out;
      if (out !== hex(H(input.alg, utf8(input.msg)))) fail('the digest against node');
      const rate = { 'sha3-224': 144, 'sha3-256': 136, 'sha3-384': 104, 'sha3-512': 72 }[input.alg];
      if (r.frames[0].facts.rate !== rate || r.frames[0].facts.cap !== 200 - rate) fail('the rate and capacity');
      if (r.frames[0].facts.nb !== Math.floor(utf8(input.msg).length / rate) + 1) fail('the number of blocks');
    },
  },
  {
    topic: 'p12-theta', allow: ['1600', '136', '4', '5', '64'],
    random: (rnd) => ({ msg: phrase(rnd, Math.floor(rnd() * 12)), pick: pick(rnd, ['auto', 'given']), x: Math.floor(rnd() * 5), z: Math.floor(rnd() * 64) }),
    check({ input, r, fail }) {
      const A = absorbed(input.msg), t = theta(A), bit = (v, z) => Number((v >> BigInt(z)) & 1n);
      if (r.frames[0].facts.ones !== pop(A)) fail('the bits set before θ');
      const c = r.frames[1].facts, d = r.frames[2].facts;
      if (c.c !== bit(t.C[c.X], c.Z)) fail('the parity C');
      if (d.d !== (bit(t.C[(c.X + 4) % 5], c.Z) ^ bit(t.C[(c.X + 1) % 5], (c.Z + 63) % 64))) fail('the effect D');
      const flips = A.reduce((n, v, i) => n + pop([v ^ t.A[i]]), 0);
      if (r.frames[3].facts.flips !== flips || r.frames[3].facts.ones !== pop(t.A)) fail('the flips of θ');
      const one = new Array(25).fill(0n); one[7] = 1n << 30n;
      if (r.frames[4].facts.n1 !== pop(theta(one).A)) fail('one bit through θ');
    },
  },
  {
    topic: 'p12-keccak', allow: ['3', '5', '64', '62', '24', '2'],
    random: (rnd) => ({ msg: phrase(rnd, Math.floor(rnd() * 12)), round: Math.floor(rnd() * 24) }),
    check({ input, r, fail }) {
      let A = absorbed(input.msg); const rd = +input.round;
      for (let i = 0; i < rd; i++) A = kround(A, i).iota;
      const R = kround(A, rd), diff = (a, b) => a.reduce((n, v, i) => n + pop([v ^ b[i]]), 0);
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'start' && x.ones !== pop(R.theta)) fail('the bits after θ');
        if (st === 'rho') { if (x.n !== diff(R.theta, R.rho)) fail('the bits ρ changes'); for (let i = 0; i < 25; i++) if (x.R[i] !== RHO[Math.floor(i / 5)][i % 5]) { fail('the ρ offset of lane ' + i); break; } }
        if (st === 'chi') { if (x.n !== diff(R.pi, R.chi)) fail('the bits χ flips'); const row = [0, 1, 2, 3, 4].map((xx) => Number((R.chi[xx] >> BigInt(x.zc)) & 1n)); if (row.join() !== x.rowA.join()) fail('the χ row'); }
        if (st === 'iota' && (x.rc !== RCS[rd] || x.lane[1] !== R.iota[0].toString(16).padStart(16, '0'))) fail('ι of round ' + rd);
      }
    },
  },
  {
    topic: 'p12-shake', allow: ['06', '16'],
    random: (rnd) => ({ msg: phrase(rnd, Math.floor(rnd() * 10)), alg: pick(rnd, ['shake128', 'shake256']), len: 1 + Math.floor(rnd() * 336) }),
    check({ input, r, fail }) {
      const L = +input.len, out = createHash(input.alg, { outputLength: L }).update(utf8(input.msg)).digest(), rate = input.alg === 'shake128' ? 168 : 136;
      for (const f of r.frames) {
        const x = f.facts;
        if (f.meta.stage === 'squeeze' && x.z !== hex(out.subarray((x.j - 1) * rate, (x.j - 1) * rate + 8))) fail('squeeze ' + x.j);
        if (f.meta.stage === 'prefix' && x.pre !== hex(createHash(input.alg, { outputLength: 16 }).update(utf8(input.msg)).digest())) fail('the 16-byte output');
        if (f.meta.stage === 'domain' && x.sha !== hex(H(input.alg === 'shake128' ? 'sha3-256' : 'sha3-512', utf8(input.msg)))) fail('the SHA-3 digest');
      }
      if (r.frames[0].facts.chunks !== Math.ceil(L / rate)) fail('the number of squeezes');
    },
  },
  {
    topic: 'p12-bday-attack', allow: ['256', '128', '4096'],
    extra: [{ bits: '20', seed: 5 }],
    check({ r, fail }) {
      const x = r.frames.find((f) => f.meta.stage === 'hit').facts;
      const da = H('sha256', utf8(x.a)), db = H('sha256', utf8(x.b));
      if (hex(da) !== x.dA || hex(db) !== x.dB) fail('the digests against node');
      if (trunc(da, x.bits) !== trunc(db, x.bits) || th(trunc(da, x.bits), x.bits) !== x.value) fail('the two messages do not collide in ' + x.bits + ' bits');
      if (x.a === x.b) fail('the two messages are the same');
    },
  },
  {
    topic: 'p12-rho', allow: [],
    random: (rnd) => ({ bits: pick(rnd, ['12', '16', '20']), seed: 1 + Math.floor(rnd() * 200) }),
    check({ r, fail }) {
      const x = r.frames.find((f) => f.meta.stage === 'join').facts, F = (v) => th(trunc(H('sha256', S.Hash.rhoInput(parseInt(v, 16), x.seed)), x.bits), x.bits);
      if (x.pa === x.pb) fail('the two predecessors are the same');
      if (F(x.pa) !== x.v || F(x.pb) !== x.v) fail('the predecessors do not both map to the join');
    },
  },
  {
    topic: 'p12-joux',
    random: (rnd) => ({ t: 2 + Math.floor(rnd() * 4), bits: pick(rnd, ['12', '16']), seed: 1 + Math.floor(rnd() * 500) }),
    check({ input, r, fail }) {
      const J = S.Hash.joux({ bits: +input.bits, t: +input.t, seed: +input.seed }), T = J.toy, ms = J.messages();
      if (new Set(ms.map((m) => hex(m))).size !== 2 ** +input.t) fail('the messages are not all different');
      if (ms.some((m) => T.hashValue(m) !== J.digest)) fail('not every message has the same digest');
      const x = r.frames[r.frames.length - 1].facts;
      if (x.ideal !== Math.round(2 ** ((+input.bits * (2 ** +input.t - 1)) / 2 ** +input.t))) fail('the ideal cost');
    },
  },
  {
    topic: 'p12-lenext', allow: ['80', '200', '32', '3'],
    random: (rnd) => ({ hash: pick(rnd, ['sha256', 'sha1', 'md5']), secret: phrase(rnd, 1 + Math.floor(rnd() * 3)).slice(0, 32), msg: 'user=' + pick(rnd, words), ext: '&role=' + pick(rnd, words) }),
    check({ S, input, r, fail }) {
      const sec = utf8(input.secret), m = utf8(input.msg), ext = utf8(input.ext), L = sec.length + m.length, le = input.hash === 'md5';
      // the glue, made here: 80, zeros to 56 mod 64, the length in bits in 8 bytes
      const gl = [0x80]; while ((L + gl.length) % 64 !== 56) gl.push(0); const bits = BigInt(L) * 8n, lb = []; for (let i = 0; i < 8; i++) lb.push(Number((bits >> BigInt(8 * i)) & 255n));
      const glue = Uint8Array.from(gl.concat(le ? lb : lb.reverse())), forged = new Uint8Array([...m, ...glue, ...ext]);
      const x = r.frames.find((f) => f.meta.stage === 'outcome').facts;
      if (x.gl !== glue.length || !x.ok) fail('the outcome');
      // the claim that a longer message gets a valid tag, checked here against node:crypto, never shown in the topic
      const res = S.Hash.lengthExtension({ hash: input.hash, secret: input.secret, msg: input.msg, ext: input.ext, secretLen: sec.length });
      if (hex(res.tag) !== hex(H(input.hash, new Uint8Array([...sec, ...forged])))) fail('the extended tag is not ' + input.hash + '(secret ‖ longer message)');
      const rs = r.frames.find((f) => f.meta.stage === 'resist').facts;
      if (rs.s3 !== hex(H('sha3-256', utf8(input.secret + input.msg)))) fail('the SHA3-256 tag');
      if (rs.t1 === rs.t2) fail('the HMAC trick should fail');
    },
  },
];
const S = (await import('./claims-p12-lib.mjs')).S;
runClaims('claims-p12', 'p12', mods, process.argv.slice(2));
