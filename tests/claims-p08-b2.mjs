// Part 8, the second half of the attacks (Fermat, batch GCD, the CRT fault, timing): their claim checks, collected by
// tests/claims-p08.mjs. Every value is worked out again here by plain BigInt arithmetic and node:crypto.
import { checkPrimeSync } from 'node:crypto';
import { pw, gcd, mod } from './claims-lib-pk.mjs';

const isqrt = (n) => { if (n < 2n) return n; let x = n < 2n ** 52n ? BigInt(Math.floor(Math.sqrt(Number(n)))) + 1n : 1n << BigInt(Math.ceil(n.toString(2).length / 2)); for (;;) { const y = (x + n / x) >> 1n; if (y >= x) { while (x * x > n) x--; while ((x + 1n) * (x + 1n) <= n) x++; return x; } x = y; } };
const nextPrime = (n) => { n += 1n; if (!(n & 1n)) n++; while (!checkPrimeSync(n)) n += 2n; return n; };

export const mods = [
  {
    topic: 'p08-fermat', allow: ['8', '186', '100', '40'],
    random: (rnd) => { const s = ['toy', 'rsa1024', 'rsa2048'][Math.floor(rnd() * 3)]; const hi = { toy: 13, rsa1024: 262, rsa2048: 518 }[s]; return { size: s, gap: 2 + Math.floor(rnd() * (hi - 1)) }; },
    count: 10,
    check({ S, input, r, fail }) {
      const lo = input.size === 'toy' ? 10007n : S.PK.prime(input.size === 'rsa1024' ? 512 : 1024, 0);
      const hi = nextPrime(lo + (1n << BigInt(input.gap))), n = lo * hi;
      let root = isqrt(n); if (root * root < n) root++;
      const steps = (lo + hi) / 2n - root + 1n;
      for (const f of r.frames) {
        const x = f.facts, ph = f.meta.phase;
        if (ph === 'start' && (x.n !== n || x.nlen !== n.toString(2).length)) fail('n');
        if (ph === 'pre' && x.expect !== steps) fail('the estimate of the steps');
        // the outcome stated, worked out here: a = ⌈√n⌉ + tries − 1 makes a² − n a square b², and n = (a − b)(a + b)
        if (ph === 'found') { const a = root + BigInt(x.tries) - 1n, b = isqrt(a * a - n); if (BigInt(x.tries) !== steps || b * b !== a * a - n || (a - b) !== lo || (a + b) !== hi) fail('the factors or the number of steps'); }
        if (ph === 'far' && (x.steps !== steps || x.lb !== steps.toString(2).length || steps <= 2000n)) fail('the estimate of the steps');
        if (ph === 'defence' && (x.safe !== Math.floor(x.nlen / 2) - 100 || x.stepsBits !== 2 * x.safe - Math.floor(x.nlen / 2) - 3)) fail('the defence');
      }
      if (steps <= 2000n && !r.frames.some((f) => f.meta.phase === 'found')) fail('the attack should succeed');
    },
  },
  {
    topic: 'p08-batch-gcd', allow: ['28', '10', '5', '503', '512'],
    random: (rnd) => ({ size: rnd() < 0.8 ? 'toy' : 'rsa1024', pairs: Math.floor(rnd() * 4), seed: 1 + Math.floor(rnd() * 9999) }),
    count: 10,
    check({ input, r, fail }) {
      const ns = r.frames[0].facts.ns;
      if (ns.length !== 8 || new Set(ns.map(String)).size !== 8) fail('eight different keys');
      const P = ns.reduce((a, b) => a * b, 1n);
      const shares = ns.map((n, i) => ns.some((m, j) => j !== i && gcd(n, m) !== 1n));
      const want = shares.map((b, i) => (b ? i + 1 : null)).filter(Boolean);
      if (want.length !== 2 * input.pairs) fail('the number of keys sharing a prime');
      let mults = 0;
      for (const f of r.frames) {
        const x = f.facts, ph = f.meta.phase;
        if (ph === 'product' || ph === 'root') { mults += x.count; if (x.count !== 8 >> x.level || x.mults !== mults) fail('the products at level ' + x.level); }
        if (ph === 'root' && x.bits !== P.toString(2).length) fail('the size of P');
        if (ph === 'gcd' && (x.nb !== want.length || x.idx.join() !== want.join() || !x.ok)) fail('the exposed keys ' + x.idx + ' against ' + want);
        if (ph === 'gcd') for (const i of want) { const n = ns[i - 1], g = gcd(n, P / n); if (g === 1n || n % g !== 0n || !checkPrimeSync(g)) fail('n' + i + ' is not factored by its gcd'); }
      }
    },
  },
  {
    topic: 'p08-crt-fault', allow: [],
    random: (rnd) => { const size = ['toy', 'rsa1024', 'rsa2048'][Math.floor(rnd() * 3)]; return { size, msg: size === 'toy' ? String(2 + Math.floor(rnd() * 1050000)) : 'note ' + Math.floor(rnd() * 1e9), half: rnd() < 0.5 ? 'p' : 'q', bit: Math.floor(rnd() * (size === 'toy' ? 9 : 500)) }; },
    count: 10,
    check({ S, input, r, fail }) {
      let p, q, e;
      if (input.size === 'toy') { p = 1031n; q = 1019n; e = 17n; } else { const half = input.size === 'rsa1024' ? 512 : 1024, a = S.PK.prime(half, 0), b = S.PK.prime(half, 1); p = a > b ? a : b; q = a > b ? b : a; e = 65537n; }
      const n = p * q, phi = (p - 1n) * (q - 1n);
      let d = 1n; { let [r0, r1, s0, s1] = [e, phi, 1n, 0n]; while (r1) { const k = r0 / r1; [r0, r1] = [r1, r0 - k * r1]; [s0, s1] = [s1, s0 - k * s1]; } d = mod(s0, phi); }
      const m = (input.size === 'toy' ? BigInt(input.msg) : BigInt('0x' + Buffer.from(input.msg).toString('hex'))) % n;
      const s = pw(m, d, n), sp = s % p, sq = s % q;
      const flip = (x, P0) => mod(x ^ (1n << BigInt(input.bit)), P0);
      const sp2 = input.half === 'p' ? flip(sp, p) : sp, sq2 = input.half === 'q' ? flip(sq, q) : sq;
      // the faulty signature by the textbook CRT formula, not Garner's
      const s2 = mod(sp2 * q * pw(q, p - 2n, p) + sq2 * p * pw(p, q - 2n, q), n);
      for (const f of r.frames) {
        const x = f.facts, ph = f.meta.phase;
        if (ph === 'start' && (x.n !== n || x.m !== m || x.dp !== d % (p - 1n) || x.dq !== d % (q - 1n))) fail('the key or m');
        if (ph === 'good' && (x.sp !== sp || x.sq !== sq || x.s !== s || x.v !== m)) fail('the correct signature');
        if (ph === 'glitch' && (x.right !== (input.half === 'p' ? sp : sq) || x.wrong !== (input.half === 'p' ? sp2 : sq2))) fail('the glitch');
        if (ph === 'release' && x.s !== s2) fail('the faulty signature');
        // the outcome stated: s′ is wrong, and s′ with m factors n (worked out here, never shown)
        if (ph === 'gcd' && (x.v !== pw(s2, e, n) || x.v === m || !x.ok || gcd(mod(pw(s2, e, n) - m, n), n) !== (input.half === 'p' ? q : p))) fail('the outcome');
        if (ph === 'defence') { const b = e.toString(2); if (x.ops !== b.length - 1 + [...b].filter((c) => c === '1').length - 1) fail('the cost of the check'); }
      }
    },
  },
];
