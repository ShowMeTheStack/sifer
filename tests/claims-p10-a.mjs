// Part 10 claims: curves over the reals and over GF(p). Real roots and sums by closed forms; small curves by brute
// force with the plain arithmetic of claims-p10-lib.mjs.
import { at, ec, mod, inv, factor } from './claims-p10-lib.mjs';

const near = (a, b, e) => Math.abs(a - b) <= (e || 1e-6) * Math.max(1, Math.abs(a), Math.abs(b));
const ri = (rnd, lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));
const primes = [5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127];

export const mods = [
  {
    topic: 'ec-real-shape', allow: ['3', '4', '27'],
    random: (rnd) => ({ a: ri(rnd, -6, 4), b: ri(rnd, -6, 6) }),
    check({ input, r, fail }) {
      const { a, b } = input, f = (x) => x ** 3 + a * x + b, D = 4 * a ** 3 + 27 * b ** 2;
      for (const fr of r.frames) {
        const x = fr.facts, st = fr.meta.stage;
        if (st === 'cubic' || st === 'disc') {
          if (x.D !== D) fail('4a³ + 27b² is ' + x.D + ', not ' + D);
          for (const t of x.roots) if (Math.abs(f(t)) > 1e-6) fail('x = ' + t + ' is not a root');
          const want = D < 0 ? 3 : D > 0 ? 1 : a === 0 ? 1 : 2;
          if (x.roots.length !== want) fail(x.roots.length + ' roots, expected ' + want);
          if (x.pieces !== (D < 0 ? 2 : 1)) fail('the number of pieces');
        }
        if (st === 'sweep') {
          const Dv = 4 * x.a ** 3 + 27 * b ** 2;
          if (fr.meta.i === 1 && Math.abs(Dv) > 1e-6) fail('the singular a = ' + x.a + ' gives ' + Dv);
          if (fr.meta.i !== 1 && !near(Dv, x.D)) fail('the sweep discriminant');
          if (fr.meta.i === 0 && Dv <= 0) fail('the first sweep curve should be one piece');
          if (fr.meta.i === 2 && Dv >= 0) fail('the last sweep curve should be two pieces');
          if (fr.meta.i === 1 && b !== 0) { const g = (t) => t ** 3 + x.a * t + b; if (Math.abs(g(x.x0)) > 1e-6 || Math.abs(3 * x.x0 ** 2 + x.a) > 1e-6) fail('the node is not at a double root'); }
        }
        if (st === 'end' && D === 0 && b !== 0 && (Math.abs(f(x.x0)) > 1e-9 || Math.abs(3 * x.x0 ** 2 + a) > 1e-9)) fail('the singular point');
      }
    },
  },
  {
    topic: 'ec-real-add', allow: ['3'], mayRefuse: true, count: 10,
    random: (rnd) => {
      for (;;) {
        const a = ri(rnd, -6, 4), b = ri(rnd, -6, 6), xp = Math.round((rnd() * 7 - 3.5) * 10) / 10, xq = Math.round((rnd() * 7 - 3.5) * 10) / 10;
        if (4 * a ** 3 + 27 * b ** 2 !== 0 && xp ** 3 + a * xp + b > 0.01 && xq ** 3 + a * xq + b > 0.01 && Math.abs(xp - xq) >= 0.3) return { a, b, xp, xq, sp: rnd() < 0.5 ? 'up' : 'down', sq: rnd() < 0.5 ? 'up' : 'down' };
      }
    },
    check({ input, r, fail }) {
      const { a, b } = input, y = (x, s) => Math.sqrt(x ** 3 + a * x + b) * (s === 'down' ? -1 : 1);
      const P = { x: input.xp, y: y(input.xp, input.sp) }, Q = { x: input.xq, y: y(input.xq, input.sq) };
      const sum = (A, Bp, l) => { const x3 = l * l - A.x - Bp.x; return { x: x3, y: l * (A.x - x3) - A.y }; };
      for (const fr of r.frames) {
        const x = fr.facts, st = fr.meta.stage;
        if (st === 'chord' || st === 'third' || st === 'sum') {
          const l = (Q.y - P.y) / (Q.x - P.x), R = sum(P, Q, l);
          if (x.lambda !== undefined && !near(x.lambda, l)) fail('the chord slope');
          if (x.R && (!near(x.R.x, R.x, 1e-9) || !near(x.R.y, R.y, 1e-9))) fail('P + Q');
          if (x.R && !near(x.R.y ** 2, x.R.x ** 3 + a * x.R.x + b, 1e-7)) fail('P + Q is not on the curve');
          if (x.third && !near(x.third.y, P.y + l * (x.third.x - P.x), 1e-7)) fail('the third point is not on the line');
          if (st === 'third' && fr.meta.above !== x.third.y > 0) fail('above or below');
        }
        if (st === 'tangent' || st === 'double') {
          const l = (3 * P.x ** 2 + a) / (2 * P.y), R = sum(P, P, l);
          if (!near(x.lambda, l)) fail('the tangent slope');
          if (x.R && (!near(x.R.x, R.x, 1e-9) || !near(x.R.y, R.y, 1e-9))) fail('2P');
        }
        if (st === 'vertical' && Math.abs(P.x - Q.x) > 1e-12) fail('a vertical line through two x values');
      }
    },
  },
];

const B = BigInt;
/** a random small curve and points on it, as topic inputs */
export function randCurve(rnd, maxP, nPts) {
  for (;;) {
    const p = primes.filter((q) => q <= maxP)[Math.floor(rnd() * primes.filter((q) => q <= maxP).length)], a = ri(rnd, 0, p - 1), b = ri(rnd, 0, p - 1);
    if ((4 * a ** 3 + 27 * b ** 2) % p === 0) continue;
    const pts = ec(p, a, b).points();
    if (pts.length < 4) continue;
    const pick = () => pts[Math.floor(rnd() * pts.length)];
    const out = { p, a, b, P: '' + (() => { const P = pick(); return P.x + ', ' + P.y; })() };
    if (nPts > 1) { const Q = rnd() < 0.15 ? out.P : (() => { const Q = pick(); return Q.x + ', ' + Q.y; })(); out.Q = Q; }
    return out;
  }
}
const pt = (s) => { const m = /(\d+)\D+(\d+)/.exec(s); return { x: B(m[1]), y: B(m[2]) }; };
const same = (A, Bp) => (!A || !Bp ? !A && !Bp : B(A.x) === B(Bp.x) && B(A.y) === B(Bp.y));

mods.push(
  {
    topic: 'ec-gfp-law', count: 10, allow: ['3'], random: (rnd) => randCurve(rnd, 127, 2),
    check({ input, r, fail }) {
      const E = ec(input.p, input.a, input.b), p = B(input.p), P = pt(input.P), Q = pt(input.Q);
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'cloud' && x.N !== E.points().length) fail('the cloud has ' + E.points().length + ' points, not ' + x.N);
        if (st === 'points' && (x.l !== mod(P.y * P.y, p) || x.r !== mod(P.x ** 3n + B(input.a) * P.x + B(input.b), p))) fail('the check that P is on the curve');
        if (st === 'vertical' && E.add(P, Q) !== null) fail('P + Q is not O');
        if (st === 'slope') {
          const l = same(P, Q) ? mod((3n * P.x * P.x + B(input.a)) * inv(2n * P.y, p), p) : mod((Q.y - P.y) * inv(Q.x - P.x, p), p);
          if (x.lambda !== l) fail('λ is ' + l + ', not ' + x.lambda);
          if (mod(x.den * x.di, p) !== 1n || x.prod !== x.den * x.di) fail('the inverse');
        }
        if (st === 'third' && (!same(x.R, E.add(P, Q)) || !same(x.T, E.neg(E.add(P, Q))) || x.sq !== x.lambda * x.lambda)) fail('the third point');
        if (st === 'sum' && (!same(x.R, E.add(P, Q)) || !E.on(x.R) || x.l !== mod(x.R.y * x.R.y, p))) fail('P + Q');
        if (st === 'double' && !same(x.R2, E.add(P, P))) fail('2P');
      }
    },
  },
  {
    topic: 'ec-infinity', count: 8, random: (rnd) => randCurve(rnd, 127, 1),
    check({ input, r, fail }) {
      const E = ec(input.p, input.a, input.b), P = pt(input.P), pts = E.points();
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (x.nP && !same(x.nP, E.neg(P))) fail('−P');
        if (st === 'vertical' && E.add(P, E.neg(P)) !== null) fail('P + (−P)');
        if (st === 'order2') { const z = pts.filter((R) => R.y === 0n); if (x.n2 !== z.length) fail('points of order 2: ' + z.length); for (const R of z) if (E.add(R, R) !== null) fail('2R is not O'); }
        if (st === 'count' && (x.N !== pts.length || B(x.NE) !== E.count())) fail('#E');
      }
    },
  },
  {
    topic: 'ec-order', count: 8, random: (rnd) => randCurve(rnd, 61, 1),
    check({ input, r, fail }) {
      const E = ec(input.p, input.a, input.b), P = pt(input.P), NE = E.count(), ord = E.order(P);
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (B(x.NE) !== NE) fail('#E is ' + NE);
        if (st === 'walk' && !same(x.R, E.mul(x.up, P))) fail(x.up + 'P');
        if (st === 'order' && (B(x.ord) !== ord || (ord > 1n && !same(x.last, E.neg(P))))) fail('the order is ' + ord);
        if (st === 'lagrange') { const d = []; for (let k = 1n; k <= NE; k++) if (NE % k === 0n) d.push(Number(k)); if (d.join() !== x.divs.join()) fail('the divisors'); if (B(x.cof) * ord !== NE) fail('the cofactor'); }
        if (st === 'orders') {
          const want = new Map([[1, 1]]);
          for (const R of E.points()) { const o = Number(E.order(R)); want.set(o, (want.get(o) || 0) + 1); }
          for (const [o, c] of x.counts) if (want.get(o) !== c) fail(c + ' points of order ' + o + ', want ' + want.get(o));
          if (x.n1 !== Math.max(...want.keys())) fail('the largest order');
        }
        if (st === 'structure') {
          if (B(x.n1) * B(x.n2) !== NE) fail('n₁·n₂');
          if (E.order(x.P1) !== B(x.n1)) fail('P₁ has the wrong order');
          if (x.n2 > 1) {
            if (E.order(x.P2) !== B(x.n2)) fail('P₂ has the wrong order');
            for (let k = 1n, R = x.P2; k < B(x.n2); k++, R = E.add(R, x.P2)) for (let j = 0n, T = null; j < B(x.n1); j++, T = E.add(T, x.P1)) if (same(R, T)) fail('P₂ lies in the subgroup of P₁');
            if ((input.p - 1) % x.n2 !== 0 || x.n1 % x.n2 !== 0) fail('n₂ divides p − 1 and n₁');
          }
        }
      }
    },
  },
  {
    topic: 'ec-hasse', count: 6, allow: ['4', '27', '3', '5'],
    random: (rnd) => { for (;;) { const p = primes[Math.floor(rnd() * primes.length)], a = ri(rnd, -20, 50), b = ri(rnd, -20, 50); const A = ((a % p) + p) % p, Bv = ((b % p) + p) % p; if ((4 * A ** 3 + 27 * Bv ** 2) % p) return { p, a, b }; } },
    check({ input, r, fail }) {
      const p = input.p, E = ec(p, input.a, input.b), N = E.count();
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'one') { const rr = mod(B(x.x0) ** 3n + B(input.a) * B(x.x0) + B(input.b), p); if (B(x.r0) !== rr) fail('f(' + x.x0 + ')'); }
        if (st === 'count') { let z = 0, t = 0; for (let v = 0n; v < B(p); v++) { const rr = mod(v ** 3n + B(input.a) * v + B(input.b), p); if (rr === 0n) z++; else for (let y = 1n; y < B(p); y++) if (mod(y * y - rr, p) === 0n) { t++; break; } } if (x.zeros !== z || x.twos !== t || B(x.N) !== N) fail('the count: ' + z + ' zeros, ' + t + ' squares, #E = ' + N); }
        if (st === 'bound') { const s2 = 2 * Math.sqrt(p); if (x.lo !== Math.ceil(p + 1 - s2) || x.hi !== Math.floor(p + 1 + s2) || B(x.N) !== N || x.t !== p + 1 - Number(N)) fail('the bound'); }
        if (st === 'scatter') { if (!f.meta.inside) fail('a curve outside the band'); if (x.t !== p + 1 - Number(N)) fail('t for p'); }
        if (st === 'real') { const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn, n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n; if (x.t !== P + 1n - n) fail('t of P-256'); }
      }
    },
  },
);

export { primes, ri, near, ec, mod, inv, factor, at };
