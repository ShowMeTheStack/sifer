// Elliptic curves y² = x³ + ax + b, over the reals (numbers) and over a small prime field GF(p) (BigInt), with the
// group law traced: the slope of the chord or tangent, the third point where that line meets the curve, and its
// mirror image, which is the sum. The point at infinity is null.
//   S.EC.real(a, b).add(P, Q) -> {R, lambda, third, trace}; .ys(x) -> the y values on the curve at x
//   S.EC.field(p, a, b).add(P, Q) -> {R, lambda, trace}; .points() -> every affine point; .mul(k, P); .order(P)
(function (S) {
  'use strict';
  const { step } = S.bytes;
  const E = (S.EC = {});
  const f2 = (v) => (Math.abs(v) < 5e-10 ? 0 : v).toFixed(2);
  const pt = (P) => (P ? `(${f2(P.x)}, ${f2(P.y)})` : 'O');

  E.real = (a, b) => {
    const C = { a, b };
    C.on = (P) => !P || Math.abs(P.y * P.y - (P.x ** 3 + a * P.x + b)) < 1e-7 * Math.max(1, Math.abs(P.y * P.y));
    C.rhs = (x) => x ** 3 + a * x + b;
    C.ys = (x) => { const r = C.rhs(x); return r < 0 ? [] : r === 0 ? [0] : [Math.sqrt(r), -Math.sqrt(r)]; };
    C.add = (P, Q) => {
      if (!P) return { R: Q, trace: [step('identity', 'O + Q = Q.', {})] };
      if (!Q) return { R: P, trace: [step('identity', 'P + O = P.', {})] };
      const same = Math.abs(P.x - Q.x) < 1e-12 && Math.abs(P.y - Q.y) < 1e-12;
      if (Math.abs(P.x - Q.x) < 1e-12 && (!same || Math.abs(P.y) < 1e-12)) return { R: null, trace: [step('vertical', `The line through ${pt(P)} and ${pt(Q)} is vertical: it meets the curve at no third point, so the sum is O.`, {})] };
      const lambda = same ? (3 * P.x * P.x + a) / (2 * P.y) : (Q.y - P.y) / (Q.x - P.x);
      const x3 = lambda * lambda - P.x - Q.x, y3 = lambda * (P.x - x3) - P.y;
      const third = { x: x3, y: -y3 }, R = { x: x3, y: y3 };
      const trace = [
        same ? step('tangent', `To double P = ${pt(P)}, take the tangent there: slope λ = (3x² + a) / 2y = ${f2(lambda)}.`, { lambda })
          : step('chord', `The chord through P = ${pt(P)} and Q = ${pt(Q)} has slope λ = (y₂ − y₁) / (x₂ − x₁) = ${f2(lambda)}.`, { lambda }),
        step('third', `It meets the curve once more, at ${pt(third)}: x₃ = λ² − x₁ − x₂ = ${f2(x3)}.`, { third }),
        step('reflect', `Reflect in the x-axis: ${same ? '2P' : 'P + Q'} = ${pt(R)}.`, { R }),
      ];
      return { R, lambda, third, same, trace };
    };
    return C;
  };

  const mod = (v, p) => ((v % p) + p) % p;
  /** the inverse of v modulo p, by the extended Euclidean algorithm */
  E.inv = (v, p) => { let [r0, r1] = [mod(v, p), p], [s0, s1] = [1n, 0n]; while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; } if (r0 !== 1n) throw new Error('no inverse'); return mod(s0, p); };
  E.field = (p, a, b) => {
    p = BigInt(p); a = BigInt(a); b = BigInt(b);
    const C = { p, a, b };
    const pp = (P) => (P ? `(${P.x}, ${P.y})` : 'O');
    C.on = (P) => !P || mod(P.y * P.y - (P.x ** 3n + a * P.x + b), p) === 0n;
    C.points = () => { const out = [], sq = new Map(); for (let y = 0n; y < p; y++) { const k = mod(y * y, p); if (!sq.has(k)) sq.set(k, []); sq.get(k).push(y); } for (let x = 0n; x < p; x++) for (const y of sq.get(mod(x ** 3n + a * x + b, p)) || []) out.push({ x, y }); return out; };
    C.neg = (P) => (P ? { x: P.x, y: mod(-P.y, p) } : null);
    C.eq = (P, Q) => (!P || !Q ? P === Q : P.x === Q.x && P.y === Q.y);
    C.add = (P, Q) => {
      if (!P) return { R: Q, trace: [step('identity', 'O + Q = Q.', {})] };
      if (!Q) return { R: P, trace: [step('identity', 'P + O = P.', {})] };
      if (P.x === Q.x && mod(P.y + Q.y, p) === 0n) return { R: null, trace: [step('vertical', `${pp(Q)} is the negative of ${pp(P)}, so the sum is the point at infinity O.`, {})] };
      const same = C.eq(P, Q);
      const num = same ? mod(3n * P.x * P.x + a, p) : mod(Q.y - P.y, p), den = same ? mod(2n * P.y, p) : mod(Q.x - P.x, p);
      const di = E.inv(den, p), lambda = mod(num * di, p);
      const x3 = mod(lambda * lambda - P.x - Q.x, p), y3 = mod(lambda * (P.x - x3) - P.y, p);
      const R = { x: x3, y: y3 };
      const trace = [
        step(same ? 'tangent' : 'chord', `λ = ${same ? '(3x₁² + a) / 2y₁' : '(y₂ − y₁) / (x₂ − x₁)'} = ${num} · ${den}⁻¹ = ${num} · ${di} = ${lambda} (mod ${p}).`, { lambda, num, den, di }),
        step('x3', `x₃ = λ² − x₁ − x₂ = ${x3} (mod ${p}).`, { x3 }),
        step('y3', `y₃ = λ(x₁ − x₃) − y₁ = ${y3} (mod ${p}), so ${same ? '2P' : 'P + Q'} = ${pp(R)}.`, { R }),
      ];
      return { R, lambda, same, trace };
    };
    C.mul = (k, P) => { let R = null, A = P; k = BigInt(k); while (k > 0n) { if (k & 1n) R = C.add(R, A).R; A = C.add(A, A).R; k >>= 1n; } return R; };
    C.order = (P) => { let n = 1, R = P; while (R) { R = C.add(R, P).R; n++; if (n > 4 * Number(p)) throw new Error('no order'); } return n; };
    return C;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
