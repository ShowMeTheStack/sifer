// The three shapes of one curve: Montgomery B·v² = u³ + A·u² + u, twisted Edwards a·x² + y² = 1 + d·x²y² with
// a = (A + 2)/B and d = (A − 2)/B, and short Weierstrass y² = x³ + a′x + b′. The birational maps carry points and
// sums across, which a toy field lets us check on every pair. Curve25519 and Ed25519 are the same curve in two shapes.
//   S.ECC.forms.make(p, A, B) -> {p, A, B, mont, edw, weier, toEdw(P), fromEdw(Q), toWeier(P), fromWeier(R), rows, trace}
//      mont.add / edw.add are traced: {R, trace};  rows lists every point in all three shapes
//   S.ECC.forms.check(F) -> {pairs, ok}  sums agree under both maps for every pair of points
//   S.ECC.forms.TOY = {p: 127, A: 4, B: 3}, 148 = 4 · 37 points;  S.ECC.forms.toy() -> make(TOY)
//   S.ECC.forms.edToMontU(pub32) -> u (the X25519 coordinate of an Ed25519 public key);  montToEdY(u)
(function (S) {
  'use strict';
  const E = (S.ECC = S.ECC || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const B_ = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const fp = (P) => (P ? `(${P.x ?? P.u}, ${P.y ?? P.v})` : 'O');

  const make = (p, A, B) => {
    p = B_(p); A = B_(A); B = B_(B);
    const m = (v) => E.mod(v, p), inv = (v) => E.inv(v, p);
    if (m(B * (A * A - 4n)) === 0n) throw new Error('singular Montgomery curve');
    const F = { p, A, B, trace: [] };
    // Montgomery
    const mont = {
      on: (P) => !P || m(B * P.v * P.v - (P.u * P.u * P.u + A * P.u * P.u + P.u)) === 0n,
      add: (P, Q) => {
        if (!P) return { R: Q, trace: [step('identity', 'O is the identity.', {})] };
        if (!Q) return { R: P, trace: [step('identity', 'O is the identity.', {})] };
        if (P.u === Q.u && m(P.v + Q.v) === 0n) return { R: null, trace: [step('vertical', 'Opposite points: the sum is O.', {})] };
        const same = P.u === Q.u;
        const l = same ? m((3n * P.u * P.u + 2n * A * P.u + 1n) * inv(2n * B * P.v)) : m((Q.v - P.v) * inv(Q.u - P.u));
        const u = m(B * l * l - A - P.u - Q.u), R = { u, v: m(l * (P.u - u) - P.v) };
        return { R, trace: [step(same ? 'tangent' : 'chord', `λ = ${l}; u₃ = Bλ² − A − u₁ − u₂ = ${u}; v₃ = λ(u₁ − u₃) − v₁ = ${R.v}.`, { lambda: l, R })] };
      },
    };
    mont.points = () => { const out = []; const sq = new Map(); for (let v = 0n; v < p; v++) { const k = m(B * v * v); if (!sq.has(k)) sq.set(k, []); sq.get(k).push(v); } for (let u = 0n; u < p; u++) for (const v of sq.get(m(u * u * u + A * u * u + u)) || []) out.push({ u, v }); return out; };
    // twisted Edwards
    const ea = m((A + 2n) * inv(B)), ed = m((A - 2n) * inv(B));
    const isSq = (v) => v === 0n || E.mod(S.NT.pow(v, (p - 1n) / 2n, p), p) === 1n;
    const edw = {
      a: ea, d: ed, complete: isSq(ea) && !isSq(ed),
      on: (P) => m(ea * P.x * P.x + P.y * P.y - 1n - ed * P.x * P.x * P.y * P.y) === 0n,
      add: (P, Q) => {
        const t = m(ed * P.x * Q.x * P.y * Q.y), x = m((P.x * Q.y + P.y * Q.x) * inv(1n + t)), y = m((P.y * Q.y - ea * P.x * Q.x) * inv(1n - t));
        return { R: { x, y }, trace: [step('edwards-add', `One formula for every case: x₃ = (x₁y₂ + y₁x₂)/(1 + d·x₁x₂y₁y₂) = ${x}, y₃ = (y₁y₂ − a·x₁x₂)/(1 − d·x₁x₂y₁y₂) = ${y}. The identity is (0, 1).`, { R: { x, y } })] };
      },
    };
    F.trace.push(step('edwards', `Twisted Edwards: a = (A + 2)/B = ${ea}, d = (A − 2)/B = ${ed}. ${edw.complete ? 'a is a square and d is not, so the addition law is complete: no input makes a denominator zero.' : 'The addition law has exceptional inputs here.'}`, { a: ea, d: ed, complete: edw.complete }));
    // Weierstrass: u = B·x − A/3, v = B·y  (x = u/B + A/(3B), y = v/B)
    const i3 = inv(3n), wa = m((3n - A * A) * inv(3n * B * B)), wb = m((2n * A * A * A - 9n * A) * inv(27n * B * B * B));
    const weier = E.curve({ p, a: wa, b: wb });
    F.trace.push(step('weierstrass', `Short Weierstrass: x = u/B + A/(3B), y = v/B gives y² = x³ + ${wa}x + ${wb}, with a′ = (3 − A²)/(3B²) and b′ = (2A³ − 9A)/(27B³).`, { a: wa, b: wb }));
    F.toWeier = (P) => (P ? { x: m(P.u * inv(B) + A * i3 * inv(B)), y: m(P.v * inv(B)) } : null);
    F.fromWeier = (R) => (R ? { u: m(B * R.x - A * i3), v: m(B * R.y) } : null);
    F.toEdw = (P) => {
      if (!P) return { x: 0n, y: 1n };
      if (P.v === 0n && P.u === 0n) return { x: 0n, y: m(-1n) };
      if (P.v === 0n || m(P.u + 1n) === 0n) return null;
      return { x: m(P.u * inv(P.v)), y: m((P.u - 1n) * inv(P.u + 1n)) };
    };
    F.fromEdw = (Q) => {
      if (Q.x === 0n && Q.y === 1n) return null;
      if (Q.x === 0n && Q.y === m(-1n)) return { u: 0n, v: 0n };
      const u = m((1n + Q.y) * inv(1n - Q.y));
      return { u, v: m(u * inv(Q.x)) };
    };
    F.trace.push(step('maps', 'Montgomery → Edwards: (x, y) = (u/v, (u − 1)/(u + 1)); back: u = (1 + y)/(1 − y), v = u/x. O ↔ (0, 1) and (0, 0) ↔ (0, −1).', {}));
    F.mont = mont; F.edw = edw; F.weier = weier;
    F.rows = () => [null, ...mont.points()].map((P) => ({ mont: P, edw: F.toEdw(P), weier: F.toWeier(P) }));
    return F;
  };
  const check = (F) => {
    const pts = [null, ...F.mont.points()];
    let pairs = 0, ok = true;
    for (const P of pts) for (const Q of pts) {
      const R = F.mont.add(P, Q).R, eP = F.toEdw(P), eQ = F.toEdw(Q);
      const wR = F.weier.add(F.toWeier(P), F.toWeier(Q));
      if (!F.weier.eq(wR, F.toWeier(R))) ok = false;
      if (eP && eQ) { const eR = F.edw.add(eP, eQ).R, want = F.toEdw(R); if (!want || eR.x !== want.x || eR.y !== want.y) ok = false; }
      pairs++;
    }
    return { pairs, ok };
  };
  const TOY = { p: 127, A: 4, B: 3 };
  E.forms = {
    make, check, TOY, toy: () => make(TOY.p, TOY.A, TOY.B),
    edToMontU: (pub) => { const P = E.Ed25519.decode(pub), { y } = E.Ed25519.affine(P), p = E.Ed25519.p; return E.mod((1n + y) * E.inv(1n - y, p), p); },
    montToEdY: (u) => { const p = E.Ed25519.p; return E.mod((B_(u) - 1n) * E.inv(B_(u) + 1n, p), p); },
    fmt: fp,
  };
})(globalThis.Sifer = globalThis.Sifer || {});
