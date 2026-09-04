// Part 10 claims: attacks on the logarithm and validation attacks. Every recovered key is checked against the
// planted one, and every intermediate point is recomputed with the plain arithmetic of claims-p10-lib.mjs.
import { ec, mod, inv, factor } from './claims-p10-lib.mjs';

const B = BigInt;
const same = (A, Bp) => (!A || !Bp ? !A && !Bp : B(A.x) === B(Bp.x) && B(A.y) === B(Bp.y));
const T = {
  gf1009: [1009, 7, 26], dlog65537: [65537, 14, 13], smooth10007: [10007, 4, 9], gf97: [97, 2, 20], gf17x2: [17, 6, 3], anomalous1013: [1013, 2, 126], target10007: [10007, 14, 10],
};
const curve = (id) => ec(...T[id]);
const isqrt = (n) => { let x = B(Math.floor(Math.sqrt(Number(n)))); while (x * x > n) x--; while ((x + 1n) * (x + 1n) <= n) x++; return x; };
const ri = (rnd, lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));

export const mods = [
  {
    topic: 'ec-bsgs', count: 6, allow: ['256'],
    random: (rnd) => (rnd() < 0.5 ? { curve: 'gf1009', k: String(ri(rnd, 1, 1018)) } : { curve: 'dlog65537', k: String(ri(rnd, 1, 65556)) }),
    check({ input, r, fail }) {
      const E = curve(input.curve), G = { gf1009: { x: 2n, y: 413n }, dlog65537: { x: 2n, y: 7n } }[input.curve], n = { gf1009: 1019n, dlog65537: 65557n }[input.curve], k = B(input.k), Q = E.mul(k, G), m = isqrt(n - 1n) + 1n;
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (x.m !== undefined && B(x.m) !== m) fail('m');
        if (st === 'plan' && !same(x.Q, Q)) fail('Q');
        if ((st === 'giant' || st === 'hit') && !same(x.P, E.add(Q, E.neg(E.mul(B(x.i) * m, G))))) fail('giant step ' + x.i);
        if (st === 'hit' && !same(x.P, E.mul(B(x.j), G))) fail('the table entry');
        if (st === 'done' && (B(x.k) !== k || B(x.i) * m + B(x.j) !== k || x.ops !== Number(m) + Number(x.i))) fail('k or the count');
      }
    },
  },
  {
    topic: 'ec-rho', count: 6, allow: ['3'],
    random: (rnd) => (rnd() < 0.6 ? { curve: 'gf1009', k: String(ri(rnd, 1, 1018)), seed: ri(rnd, 1, 999) } : { curve: 'dlog65537', k: String(ri(rnd, 1, 65556)), seed: ri(rnd, 1, 999) }),
    check({ input, r, fail }) {
      const E = curve(input.curve), G = { gf1009: { x: 2n, y: 413n }, dlog65537: { x: 2n, y: 7n } }[input.curve], n = { gf1009: 1019n, dlog65537: 65557n }[input.curve], k = B(input.k), Q = E.mul(k, G);
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if ((st === 'start' || st === 'walk' || st === 'collide') && !same(x.P, E.add(E.mul(B(x.a), G), E.mul(B(x.b), Q)))) fail('X = a·G + b·Q');
        if (st === 'solve') {
          if (B(x.k) !== k) fail('k is ' + x.k + ', not ' + k);
          if (mod(B(x.a1) - B(x.a2) - k * (B(x.b2) - B(x.b1)), n) !== 0n) fail('the equation');
          if (!same(E.add(E.mul(B(x.a1), G), E.mul(B(x.b1), Q)), E.add(E.mul(B(x.a2), G), E.mul(B(x.b2), Q)))) fail('the two names differ');
        }
        if (st === 'floyd' && x.exp !== Math.round(Math.sqrt(Math.PI * Number(n) / 2))) fail('the expected steps');
      }
    },
  },
  {
    topic: 'ec-pohlig', count: 6, allow: ['3', '6'],
    random: (rnd) => { const c = ['smooth10007', 'gf97', 'gf17x2'][Math.floor(rnd() * 3)], n = { smooth10007: 10206, gf97: 27, gf17x2: 8 }[c]; return { curve: c, k: String(ri(rnd, 1, n - 1)) }; },
    check({ input, r, fail }) {
      const E = curve(input.curve), n = { smooth10007: 10206n, gf97: 27n, gf17x2: 8n }[input.curve], k = B(input.k);
      const plan = r.frames.find((f) => f.meta.stage === 'plan').facts;
      const Q = plan.Q;
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'plan') { const fs = factor(n); if (fs.length !== x.parts.length || fs.some(([q, e], i) => B(x.parts[i][0]) !== q || x.parts[i][1] !== e)) fail('the factors of n'); }
        if (st === 'digit') {
          if (E.order(x.G0) !== B(x.q)) fail('G₀ has the wrong order');
          if (!same(x.Qj, E.mul(B(x.digit), x.G0))) fail('the digit point');
          const qe = B(x.mod), kq = k % qe; if (B(x.digit) !== (kq / B(x.q) ** B(x.j)) % B(x.q)) fail('digit ' + x.j + ' mod ' + x.mod);
        }
        if (st === 'crt') { if (B(x.k) !== k) fail('k'); for (const [res, mo] of x.res) if (k % B(mo) !== B(res)) fail('k mod ' + mo); }
      }
      if (!E.on(Q)) fail('Q is off the curve');
    },
  },
  {
    topic: 'ec-smart', count: 5, allow: ['256'],
    random: (rnd) => ({ k: String(ri(rnd, 1, 1012)) }),
    check({ input, r, fail }) {
      const p = 1013n, E = curve('anomalous1013'), G = { x: 2n, y: 420n }, k = B(input.k), Q = E.mul(k, G);
      if (E.count() !== p) fail('the curve is not anomalous');
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'story' && (B(x.N) !== p || B(x.t) !== 1n)) fail('#E or t');
        if (st === 'lift') {
          const M = p * p, on = (P) => mod(P.y * P.y - P.x ** 3n - B(x.a) * P.x - B(x.b), M) === 0n;
          if (!on(x.G) || !on(x.Q)) fail('a lifted point is off the lifted curve');
          if (mod(x.G.x - G.x, p) || mod(x.G.y - G.y, p) || mod(x.Q.x - Q.x, p) || mod(x.Q.y - Q.y, p)) fail('a lift does not reduce to its point');
          if (mod(B(x.a) - 2n, p)) fail('the lifted a');
        }
        if (st === 'solve') { if (B(x.k) !== k) fail('k'); if (mod(B(x.psiQ) - k * B(x.psiG), p)) fail('ψ(Q) = k·ψ(G)'); }
      }
    },
  },
];
const pwm = (b, e, m) => { let r = 1n; b %= m; while (e) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
mods.push(
  {
    topic: 'ec-invalid', count: 4, random: (rnd) => ({ d: String(ri(rnd, 1, 10008)), seed: ri(rnd, 1, 999) }),
    check({ input, r, fail }) {
      const d = B(input.d);
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'query') {
          const E = ec(10007, 14, B(x.b));
          if (!E.on(x.Q)) fail('the point sent is not on the curve with b′ = ' + x.b);
          if (E.count() !== B(x.order)) fail('#points of b′ = ' + x.b);
          if (E.order(x.Q) !== B(x.l) || B(x.order) % B(x.l)) fail('the order of the point sent');
          if (d % B(x.l) !== B(x.residue)) fail('d mod ' + x.l);
        }
        if (st === 'crt' && (B(x.d) !== d || x.ls.reduce((a, b) => a * B(b), 1n) !== B(x.M) || B(x.M) <= 10009n)) fail('the recovered d');
        if (st === 'defence' && ec(10007, 14, 10).on(x.Q)) fail('the rejected point is on the curve');
      }
    },
  },
  {
    topic: 'ec-twist', count: 4, allow: ['4', '8', '32'], random: (rnd) => ({ d: String(ri(rnd, 1, 2548)), seed: ri(rnd, 1, 999) }),
    check({ input, r, fail }) {
      const p = 10037n, A = 55n, d = B(input.d), fu = (u) => mod(u * u * u + A * u * u + u, p);
      let N = 1n; for (let u = 0n; u < p; u++) { const v = fu(u); N += v === 0n ? 1n : pwm(v, (p - 1n) / 2n, p) === 1n ? 2n : 0n; }
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'setup' && (B(x.N) !== N || B(x.T) !== 2n * p + 2n - N || B(x.q) * 4n !== N)) fail('the counts');
        if (st === 'query') {
          if (pwm(fu(B(x.u)), (p - 1n) / 2n, p) !== p - 1n) fail('u = ' + x.u + ' is not on the twist');
          const o = B(x.order), rr = B(x.residue);
          if (mod(d - rr, o) !== 0n && mod(d + rr, o) !== 0n) fail('d is not ±' + rr + ' mod ' + o);
          if ((2n * p + 2n - N) % o) fail('the order does not divide the twist order');
        }
        if (st === 'signs' && !x.cands.some((c) => B(c) === d || B(c) === B(x.q) - d)) fail('the candidates miss d');
      }
    },
  },
);

export { same, curve, T, inv };
