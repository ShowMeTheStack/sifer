// Part 9, computing discrete logarithms (baby-step giant-step, Pollard's rho, Pohlig–Hellman, index calculus and the
// small-subgroup attack): the claim checks, collected by tests/claims-p09.mjs. Each works the facts out again with
// plain BigInt arithmetic of its own: brute force where the group is small, and the defining equations otherwise.
import { pw, gcd, inv, mod } from './claims-lib-pk.mjs';
import { checkPrimeSync } from 'node:crypto';

const isqrtUp = (n) => { n = BigInt(n); let x = BigInt(Math.floor(Math.sqrt(Number(n)))); while (x * x < n) x++; while (x > 0n && (x - 1n) * (x - 1n) >= n) x--; return x; };
const ceilSqrt = (n) => { let r = 0n, b = 1n << BigInt(Math.ceil(n.toString(2).length / 2) + 1); for (; b; b >>= 1n) if ((r + b) * (r + b) <= n) r += b; return r * r === n ? r : r + 1n; };
const smallPrimes = (k) => { const out = []; for (let p = 3; out.length < k; p += 2) if (checkPrimeSync(BigInt(p))) out.push(p); return out; };
const PR = smallPrimes(40000).filter((p) => p > 11 && p < 200003);
const factor = (n) => { const m = new Map(); for (let d = 2n; d * d <= n; d++) while (n % d === 0n) { m.set(d, (m.get(d) || 0) + 1); n /= d; } if (n > 1n) m.set(n, (m.get(n) || 0) + 1); return m; };
/** the order of g modulo p, by the factors of p − 1 */
const order = (g, p) => { let o = p - 1n; for (const [q] of factor(p - 1n)) while (o % q === 0n && pw(g, o / q, p) === 1n) o /= q; return o; };
const smallestGen = (p) => { for (let g = 2n; ; g++) if (order(g, p) === p - 1n) return g; };

export const mods = [
  {
    topic: 'p09-bsgs', allow: ['28'],
    random: (rnd) => { const p = PR[Math.floor(rnd() * PR.length)]; return { size: 'toy', p: String(p), h: String(1 + Math.floor(rnd() * (p - 1))) }; },
    count: 10,
    extra: [{ size: 'lab', seed: 11 }],
    check({ input, r, fail }) {
      let g = null, n = null, m = null, x = null;
      for (const f of r.frames) {
        const k = f.facts, ph = f.meta.phase;
        if (ph === 'start' && !f.meta.real) {
          const p = BigInt(input.p);
          if (input.size === 'toy') { if (k.g !== smallestGen(p) || k.n !== p - 1n) fail('the generator or the order'); }
          g = k.g; n = k.n; m = k.m;
          if (m !== ceilSqrt(n)) fail('m = ⌈√n⌉');
        }
        if (ph === 'start' && f.meta.real && k.m !== ceilSqrt(k.n)) fail('m for the real group');
        if (ph === 'giant' && k.v !== undefined && !f.meta.real) {
          const p = r.frames[0].facts.p, h = r.frames[0].facts.h;
          if (k.v !== mod(h * pw(inv(pw(g, m, p), p), BigInt(k.i), p), p)) fail('giant step ' + k.i);
        }
        if (ph === 'match') {
          const p = r.frames[0].facts.p;
          if (pw(g, k.j, p) !== k.v) fail('the match is not a baby step');
          if (k.j >= m || BigInt(k.i) >= m) fail('i or j out of range');
        }
        if (ph === 'done') {
          const p = r.frames[0].facts.p, h = r.frames[0].facts.h;
          x = k.x;
          if (pw(g, x, p) !== h % p || x !== BigInt(k.i) * m + k.j || k.ops !== m + BigInt(k.i) + 1n) fail('x or the count');
          // brute force for the toy: the smallest exponent
          if (input.size === 'toy') { let v = 1n, e = 0n; while (v !== h) { v = (v * g) % p; e++; } if (e !== x) fail('brute force gives ' + e + ', not ' + x); }
        }
        if (ph === 'cost' && !f.meta.real && k.half !== Math.ceil(k.qb / 2)) fail('the half of the bits');
      }
      if (input.size !== 'modp' && x === null) fail('no result');
    },
  },
];

// Pollard's rho: the walk again, with its own code (x·h, x², x·g as x mod 3 is 0, 1, 2), its tail and cycle, Floyd's
// meeting at the first multiple of the cycle length that reaches the cycle, and the logarithm by brute force
function walkOf(p, q, g, h, att) {
  let a = (1n + BigInt(att)) % q, b = BigInt(att) % q, X = (pw(g, a, p) * pw(h, b, p)) % p;
  const seq = [], seen = new Map();
  while (!seen.has(X)) { seen.set(X, seq.length); seq.push({ X, a, b }); const r = X % 3n; if (r === 0n) { X = X * h % p; b = (b + 1n) % q; } else if (r === 1n) { X = X * X % p; a = 2n * a % q; b = 2n * b % q; } else { X = X * g % p; a = (a + 1n) % q; } }
  return { seq, mu: seen.get(X), lam: seq.length - seen.get(X) };
}
const rhoPrimes = PR.filter((p) => p < 100003 && [...factor(BigInt(p) - 1n).keys()].some((q) => q >= 11n));
mods.push({
  topic: 'p09-rho', allow: ['3', '4', '30', '224', '256'],
  random: (rnd) => { const p = BigInt(rhoPrimes[Math.floor(rnd() * rhoPrimes.length)]); const q = [...factor(p - 1n).keys()].reduce((a, b) => (a > b ? a : b)); return { size: 'toy', p: String(p), x: String(1n + BigInt(Math.floor(rnd() * Number(q - 1n)))) }; },
  count: 12,
  extra: [{ size: 'lab', seed: 9 }],
  check({ input, r, fail }) {
    const f0 = r.frames[0].facts;
    if (input.size === 'modp') return;
    const { p, q, g, h } = f0;
    if (pw(g, q, p) !== 1n || g === 1n) fail('g does not have order q');
    const shape = r.frames.find((f) => f.meta.phase === 'shape').facts;
    let w = null;
    for (let att = 0; att < 41 && !w; att++) { const c = walkOf(p, q, g, h, att); if (c.seq[0].X === f0.x0) w = c; }
    if (!w) { fail('the start of the walk'); return; }
    if (w.mu !== shape.mu || w.lam !== shape.lam) fail('the tail and the cycle: ' + w.mu + ', ' + w.lam);
    let meet = w.lam; while (meet < Math.max(w.mu, 1)) meet += w.lam;
    if (shape.meet !== meet) fail('Floyd meets at ' + meet + ', not ' + shape.meet);
    const at = (k) => (k < w.mu ? k : w.mu + ((k - w.mu) % w.lam));
    for (const f of r.frames) {
      const k = f.facts;
      if (f.meta.phase === 'floyd' && (k.t !== w.seq[at(k.i)].X || k.hv !== w.seq[at(2 * k.i)].X)) fail('the tortoise or the hare at step ' + k.i);
      if (f.meta.phase === 'meet') { if (k.mv !== w.seq[at(meet)].X) fail('the meeting value'); if ((pw(g, k.a1, p) * pw(h, k.b1, p)) % p !== k.mv || (pw(g, k.a2, p) * pw(h, k.b2, p)) % p !== k.mv) fail('the two exponent pairs'); }
      if (f.meta.phase === 'solve') { if (pw(g, k.x, p) !== h || k.x >= q) fail('x'); if (input.size === 'toy' && k.x !== BigInt(input.x)) fail('x is not the secret'); if (mod(k.db * k.x - k.da, q) !== 0n) fail('the linear equation'); }
    }
  },
});

// Pohlig–Hellman: every digit is the logarithm of t to the base γ in the order-q subgroup (by brute force), the
// residues agree with the true x (found by brute force for the toys), and the CRT result solves g^x = h
const smoothPrimes = PR.filter((p) => p < 30000 && [...factor(BigInt(p) - 1n).keys()].every((q) => q <= 40n));
mods.push({
  topic: 'p09-pohlig', allow: ['3', '200'],
  random: (rnd) => { const p = smoothPrimes[Math.floor(rnd() * smoothPrimes.length)]; return { size: 'toy', p: String(p), h: String(1 + Math.floor(rnd() * (p - 1))) }; },
  count: 10,
  extra: [{ size: 'big', seed: 21 }],
  check({ input, r, fail }) {
    if (input.size === 'modp') return;
    const { p, g, h, n } = r.frames[0].facts;
    if (input.size === 'toy' && g !== smallestGen(p)) fail('the generator');
    let truth = null;
    if (input.size === 'toy') { let v = 1n, e = 0n; while (v !== h) { v = v * g % p; e++; } truth = e; }
    for (const f of r.frames) {
      const k = f.facts;
      if (f.meta.phase === 'digit') {
        if (k.gq !== pw(g, n / k.q, p)) fail('γ for ' + k.q);
        if (k.target !== undefined && k.target !== pw(h * inv(pw(g, k.prev, p), p) % p, n / k.q ** BigInt(k.k + 1), p)) fail('t for ' + k.q + ' digit ' + k.k);
        if (pw(k.gq, k.d, p) !== k.target || k.d >= k.q) fail('the digit for ' + k.q);
        if (truth !== null && truth % k.mod !== k.x) fail('x mod ' + k.mod);
      }
      if (f.meta.phase === 'crt') { if (pw(g, k.x, p) !== h || k.x >= n) fail('the CRT result'); for (const [res, m] of k.parts) if (k.x % m !== res) fail('a residue'); if (truth !== null && truth !== k.x) fail('x is not the logarithm'); }
    }
  },
});

// index calculus: every relation really is smooth and right, every logarithm of the factor base checks, and x solves
// g^x = h; for the toys x is also found by brute force
mods.push({
  topic: 'p09-index', allow: ['112', '224', '1', '3'],
  random: (rnd) => { const p = PR[Math.floor(rnd() * PR.length)]; return { size: 'toy', p: String(p > 1009 ? p : 10007), h: String(2 + Math.floor(rnd() * ((p > 1009 ? p : 10007) - 3))), bound: [7, 11, 13, 17, 19][Math.floor(rnd() * 5)], seed: 1 + Math.floor(rnd() * 99) }; },
  count: 10,
  mayRefuse: true,
  check({ input, r, fail }) {
    if (input.size === 'modp') return;
    const { p, g, h, base } = r.frames[0].facts;
    if (input.size === 'toy' && g !== smallestGen(p)) fail('the generator');
    const prod = (exps) => base.reduce((a, q, i) => a * q ** exps[i], 1n);
    for (const f of r.frames) {
      const k = f.facts;
      if (f.meta.phase === 'relation' && (pw(g, k.k, p) !== k.v || prod(k.exps) !== k.v)) fail('relation ' + k.k);
      if (f.meta.phase === 'solve') k.logs.forEach((L, i) => { if (pw(g, L, p) !== base[i]) fail('log of ' + base[i]); });
      if (f.meta.phase === 'final' && (h * pw(g, k.k, p) % p !== k.v)) fail('the last relation');
      if (f.meta.phase === 'done') {
        if (pw(g, k.x, p) !== h % p) fail('x');
        if (mod(k.x + k.k - base.reduce((a, q, i) => a + k.exps[i] * k.logs[i], 0n), p - 1n) !== 0n) fail('the sum');
        if (input.size === 'toy') { let v = 1n, e = 0n; while (v !== h) { v = v * g % p; e++; } if (e !== k.x) fail('brute force gives ' + e); }
      }
    }
  },
});

// small subgroups: p − 1 factors as said, each probe has the stated order, each residue is x mod q (the secret is
// planted, so it is known), and the safe prime is safe
mods.push({
  topic: 'p09-small-subgroup', allow: [],
  random: (rnd) => ({ size: 'toy', k: 3 + Math.floor(rnd() * 4), cap: 20 + Math.floor(rnd() * 81), seed: 1 + Math.floor(rnd() * 5000) }),
  count: 10,
  check({ input, r, fail }) {
    if (input.size === 'modp') { const f = r.frames[0].facts; if (f.qb !== 2047) fail('the MODP order'); return; }
    const { p } = r.frames[0].facts;
    const fac = factor(p - 1n);
    const crt = r.frames.find((f) => f.meta.phase === 'crt');
    if (!crt || !crt.meta.ok || crt.facts.parts !== fac.size) fail('the outcome: one probe per prime factor recovers x');
    for (const f of r.frames) {
      const k = f.facts;
      if (f.meta.phase === 'probe') {
        if (!fac.has(k.q)) fail(k.q + ' does not divide p − 1');
        if (order(k.beta, p) !== k.q) fail('β does not have order ' + k.q);
        // β^x takes only q values, so it depends on x mod q alone
        const vals = new Set(); for (let t = 0n; t < k.q * 2n; t++) vals.add(pw(k.beta, t, p)); if (BigInt(vals.size) !== k.q) fail('β^x takes ' + vals.size + ' values');
      }
      if (f.meta.phase === 'safe') { if (!checkPrimeSync(k.sp) || !checkPrimeSync(k.Q) || k.sp !== 2n * k.Q + 1n) fail('the safe prime'); if (k.sp.toString(2).length !== k.bits) fail('the size of the safe prime'); }
    }
  },
});
