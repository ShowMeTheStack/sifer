// Short Weierstrass curves y² = x³ + ax + b over GF(p) on BigInt, at any size: the group law in affine coordinates
// (traced, with λ) and in Jacobian coordinates (X : Y : Z) ↔ (X/Z², Y/Z³) with every field multiplication counted,
// point validation, SEC 1 point encoding with compression, and, for toy fields, the full point list, point
// counting, the order of a point, the group structure Z_n1 × Z_n2 and Hasse's bound. The point at infinity is null.
//   S.ECC.curve({p, a, b, n?, h?, G?, name?}) -> C
//   C.on(P) / neg / eq / add(P, Q) / dbl(P) / sub / addT(P, Q) -> {R, lambda, trace} / mul(k, P) (fast)
//   C.toJ(P) / fromJ(J) / jdbl(J, cnt?) / jadd(J1, J2, cnt?) / jaddMixed(J, Q, cnt?)   cnt = {M, S, I} is updated
//   C.validate(P) -> {ok, checks: [{name, ok}], trace}
//   C.encode(P, compressed) -> bytes;  C.decode(bytes) -> {P, trace};  C.compress(P) -> {bytes, trace}
//   toy only: C.points() / count() -> {N, trace} / order(P) -> {order, trace} / hasse() / structure()
//   S.ECC.fmt(v) a number short enough for a sentence; S.ECC.fp(P) a point as text
(function (S) {
  'use strict';
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const E = (S.ECC = S.ECC || {});
  E.step = step;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const mod = (a, n) => { const r = a % n; return r < 0n ? r + n : r; };
  E.mod = mod;
  E.inv = (a, n) => {
    let r0 = mod(a, n), r1 = n, s0 = 1n, s1 = 0n;
    while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
    if (r0 !== 1n) throw new Error(`${a} has no inverse modulo ${n}`);
    return mod(s0, n);
  };
  E.fmt = (v) => {
    if (v == null) return 'O';
    v = B(v);
    if (v >= -(1n << 40n) && v < 1n << 40n) return v.toString();
    const h = v.toString(16);
    return '0x' + h.slice(0, 8) + '…' + h.slice(-8);
  };
  E.fp = (P) => (P ? `(${E.fmt(P.x)}, ${E.fmt(P.y)})` : 'O');
  E.hexN = (v, len) => v.toString(16).padStart(2 * len, '0');
  E.bytesToBig = (b) => { let v = 0n; for (const x of b) v = (v << 8n) | BigInt(x); return v; };
  E.bigToBytes = (v, len) => { const out = new Uint8Array(len); for (let i = len - 1; i >= 0; i--) { out[i] = Number(v & 255n); v >>= 8n; } return out; };
  E.bitLength = (v) => (v <= 0n ? 0 : v.toString(2).length);
  E.lcm = (a, b) => { let x = a, y = b; while (y) [x, y] = [y, x % y]; return (a / x) * b; };

  E.curve = (o) => {
    const p = B(o.p), a = mod(B(o.a), p), b = mod(B(o.b), p);
    const C = { p, a, b, name: o.name || `y² = x³ + ${a}x + ${b} over GF(${p})`, n: o.n != null ? B(o.n) : null, h: o.h != null ? B(o.h) : null };
    C.G = o.G ? { x: B(o.G.x), y: B(o.G.y) } : null;
    C.size = Math.ceil(E.bitLength(p) / 8);
    C.toy = p < 1n << 26n;
    const fp = E.fp, f = E.fmt;
    if (mod(4n * a * a * a + 27n * b * b, p) === 0n) throw new Error('singular curve: 4a³ + 27b² = 0');
    C.m = (v) => mod(v, p);
    C.rhs = (x) => mod(x * x * x + a * x + b, p);
    C.on = (P) => !P || (P.x >= 0n && P.x < p && P.y >= 0n && P.y < p && mod(P.y * P.y, p) === C.rhs(P.x));
    C.neg = (P) => (P ? { x: P.x, y: mod(-P.y, p) } : null);
    C.eq = (P, Q) => (!P || !Q ? !P && !Q : P.x === Q.x && P.y === Q.y);
    C.fmt = fp;
    C.sqrt = (v) => S.GF.prime(p).sqrt(v);

    // ---- affine
    C.add = (P, Q) => {
      if (!P) return Q;
      if (!Q) return P;
      let l;
      if (P.x === Q.x) {
        if (mod(P.y + Q.y, p) === 0n) return null;
        l = mod((3n * P.x * P.x + a) * E.inv(2n * P.y, p), p);
      } else l = mod((Q.y - P.y) * E.inv(Q.x - P.x, p), p);
      const x = mod(l * l - P.x - Q.x, p);
      return { x, y: mod(l * (P.x - x) - P.y, p) };
    };
    C.dbl = (P) => C.add(P, P);
    C.sub = (P, Q) => C.add(P, C.neg(Q));
    C.addT = (P, Q) => {
      if (!P) return { R: Q, trace: [step('identity', `O + ${fp(Q)} = ${fp(Q)}: the point at infinity is the identity.`, { R: Q })] };
      if (!Q) return { R: P, trace: [step('identity', `${fp(P)} + O = ${fp(P)}: the point at infinity is the identity.`, { R: P })] };
      if (P.x === Q.x && mod(P.y + Q.y, p) === 0n) return { R: null, trace: [step('vertical', `${fp(Q)} is the mirror image of ${fp(P)}: the line through them is vertical, so the sum is O.`, { R: null })] };
      const same = P.x === Q.x;
      const num = same ? mod(3n * P.x * P.x + a, p) : mod(Q.y - P.y, p), den = same ? mod(2n * P.y, p) : mod(Q.x - P.x, p);
      const di = E.inv(den, p), lambda = mod(num * di, p);
      const x = mod(lambda * lambda - P.x - Q.x, p), y = mod(lambda * (P.x - x) - P.y, p), R = { x, y };
      return {
        R, lambda, same, trace: [
          step(same ? 'tangent' : 'chord', `λ = ${same ? '(3x₁² + a) / 2y₁' : '(y₂ − y₁) / (x₂ − x₁)'} = ${f(num)} · ${f(den)}⁻¹ = ${f(num)} · ${f(di)} = ${f(lambda)} (mod p).`, { lambda, num, den, di }),
          step('x3', `x₃ = λ² − x₁ − x₂ = ${f(x)}.`, { x }),
          step('y3', `y₃ = λ(x₁ − x₃) − y₁ = ${f(y)}, so ${same ? '2P' : 'P + Q'} = ${fp(R)}.`, { R }),
        ],
      };
    };

    // ---- Jacobian: (X : Y : Z) stands for (X/Z², Y/Z³); Z = 0 is O
    const cntM = (c, m, s) => { if (c) { c.M += m; c.S += s; } };
    C.toJ = (P) => (P ? { X: P.x, Y: P.y, Z: 1n } : { X: 1n, Y: 1n, Z: 0n });
    C.fromJ = (J, cnt) => {
      if (J.Z === 0n) return null;
      const zi = E.inv(J.Z, p), z2 = mod(zi * zi, p);
      if (cnt) { cnt.I++; cnt.M += 3; cnt.S += 1; }
      return { x: mod(J.X * z2, p), y: mod(J.Y * z2 * zi, p) };
    };
    C.jdbl = (J, cnt) => {
      if (J.Z === 0n || J.Y === 0n) return { X: 1n, Y: 1n, Z: 0n };
      const XX = mod(J.X * J.X, p), YY = mod(J.Y * J.Y, p), YYYY = mod(YY * YY, p), ZZ = mod(J.Z * J.Z, p);
      const Sv = mod(4n * J.X * YY, p);
      let M;
      if (a === p - 3n) { M = mod(3n * (J.X - ZZ) * (J.X + ZZ), p); cntM(cnt, 3, 5); }
      else { M = mod(3n * XX + a * ZZ * ZZ, p); cntM(cnt, a === 0n ? 2 : 4, a === 0n ? 4 : 5); }
      const X = mod(M * M - 2n * Sv, p);
      return { X, Y: mod(M * (Sv - X) - 8n * YYYY, p), Z: mod(2n * J.Y * J.Z, p) };
    };
    C.jadd = (J1, J2, cnt) => {
      if (J1.Z === 0n) return J2;
      if (J2.Z === 0n) return J1;
      const Z1Z1 = mod(J1.Z * J1.Z, p), Z2Z2 = mod(J2.Z * J2.Z, p);
      const U1 = mod(J1.X * Z2Z2, p), U2 = mod(J2.X * Z1Z1, p);
      const S1 = mod(J1.Y * J2.Z * Z2Z2, p), S2 = mod(J2.Y * J1.Z * Z1Z1, p);
      const H = mod(U2 - U1, p), r = mod(S2 - S1, p);
      cntM(cnt, 8, 2);
      if (H === 0n) return r === 0n ? C.jdbl(J1, cnt) : { X: 1n, Y: 1n, Z: 0n };
      const HH = mod(H * H, p), HHH = mod(HH * H, p), V = mod(U1 * HH, p);
      const X = mod(r * r - HHH - 2n * V, p);
      cntM(cnt, 4, 2);
      return { X, Y: mod(r * (V - X) - S1 * HHH, p), Z: mod(J1.Z * J2.Z * H, p) };
    };
    /** J + Q with Q affine (Z = 1): the cheaper mixed addition */
    C.jaddMixed = (J, Q, cnt) => {
      if (!Q) return J;
      if (J.Z === 0n) return C.toJ(Q);
      const Z1Z1 = mod(J.Z * J.Z, p), U2 = mod(Q.x * Z1Z1, p), S2 = mod(Q.y * J.Z * Z1Z1, p);
      const H = mod(U2 - J.X, p), r = mod(S2 - J.Y, p);
      cntM(cnt, 4, 1);
      if (H === 0n) return r === 0n ? C.jdbl(J, cnt) : { X: 1n, Y: 1n, Z: 0n };
      const HH = mod(H * H, p), HHH = mod(HH * H, p), V = mod(J.X * HH, p);
      const X = mod(r * r - HHH - 2n * V, p);
      cntM(cnt, 4, 2);
      return { X, Y: mod(r * (V - X) - J.Y * HHH, p), Z: mod(J.Z * H, p) };
    };
    const jneg = (J) => ({ X: J.X, Y: mod(-J.Y, p), Z: J.Z });
    C.jneg = jneg;
    /** k·P, fast: Jacobian with a width-4 window of odd multiples (no trace) */
    C.mul = (k, P) => {
      k = B(k);
      if (k < 0n) { k = -k; P = C.neg(P); }
      if (!P || k === 0n) return null;
      const T = [P], P2 = C.dbl(P);
      for (let i = 1; i < 8; i++) T.push(C.add(T[i - 1], P2));
      const digits = E.naf ? E.naf(k, 5) : null;
      let J = { X: 1n, Y: 1n, Z: 0n };
      if (digits) {
        for (let i = digits.length - 1; i >= 0; i--) {
          J = C.jdbl(J);
          const d = digits[i];
          if (d > 0) J = C.jaddMixed(J, T[(d - 1) >> 1]); else if (d < 0) J = C.jaddMixed(J, C.neg(T[(-d - 1) >> 1]));
        }
      } else for (let i = E.bitLength(k) - 1; i >= 0; i--) { J = C.jdbl(J); if ((k >> BigInt(i)) & 1n) J = C.jaddMixed(J, P); }
      return C.fromJ(J);
    };

    // ---- validation and encoding
    C.validate = (P) => {
      const checks = [], trace = [];
      const ck = (name, ok, say) => { checks.push({ name, ok }); trace.push(step(ok ? 'check-ok' : 'check-fail', say, { name, ok })); return ok; };
      if (!ck('not-infinity', !!P, P ? 'The point is not the point at infinity.' : 'The point at infinity is never a valid public key.')) return { ok: false, checks, trace };
      if (!ck('range', P.x >= 0n && P.x < p && P.y >= 0n && P.y < p, `Both coordinates lie in [0, p): x = ${f(P.x)}, y = ${f(P.y)}.`)) return { ok: false, checks, trace };
      const l = mod(P.y * P.y, p), r = C.rhs(P.x);
      if (!ck('on-curve', l === r, `y² = ${f(l)} and x³ + ax + b = ${f(r)}: ${l === r ? 'equal, so the point is on the curve' : 'different, so the point is NOT on the curve'}.`)) return { ok: false, checks, trace };
      if (C.n && C.h !== 1n) {
        const nP = C.mul(C.n, P);
        if (!ck('order', !nP, nP ? `n·P = ${fp(nP)} ≠ O: the point is outside the subgroup of order n.` : `n·P = O: the point lies in the subgroup of prime order n.`)) return { ok: false, checks, trace };
      } else if (C.n) ck('order', true, 'The cofactor is 1, so every point on the curve other than O has order n.');
      return { ok: true, checks, trace };
    };
    C.encode = (P, compressed) => {
      const L = C.size;
      if (compressed) { const out = new Uint8Array(1 + L); out[0] = 2 + Number(P.y & 1n); out.set(E.bigToBytes(P.x, L), 1); return out; }
      const out = new Uint8Array(1 + 2 * L); out[0] = 4; out.set(E.bigToBytes(P.x, L), 1); out.set(E.bigToBytes(P.y, L), 1 + L); return out;
    };
    C.compress = (P) => {
      const bytes = C.encode(P, true);
      return { bytes, trace: [step('compress', `Keep x = ${f(P.x)} and only the parity of y = ${f(P.y)} (${P.y & 1n ? 'odd' : 'even'}): prefix 0${bytes[0]}, ${bytes.length} bytes instead of ${2 * C.size + 1}.`, { prefix: bytes[0], x: P.x, parity: Number(P.y & 1n) })] };
    };
    C.decode = (bytes) => {
      const L = C.size, trace = [];
      if (bytes[0] === 4 && bytes.length === 1 + 2 * L) {
        const P = { x: E.bytesToBig(bytes.subarray(1, 1 + L)), y: E.bytesToBig(bytes.subarray(1 + L)) };
        trace.push(step('uncompressed', `Prefix 04: x = ${f(P.x)} and y = ${f(P.y)} are both given.`, { P }));
        if (!C.on(P)) { trace.push(step('reject', 'The point is not on the curve: rejected.', {})); return { P: null, trace }; }
        return { P, trace };
      }
      if ((bytes[0] === 2 || bytes[0] === 3) && bytes.length === 1 + L) {
        const x = E.bytesToBig(bytes.subarray(1)), r = C.rhs(x);
        trace.push(step('rhs', `Prefix 0${bytes[0]}: x = ${f(x)}, so y² = x³ + ax + b = ${f(r)}.`, { x, rhs: r }));
        if (x >= p) { trace.push(step('reject', 'x is not below p: rejected.', {})); return { P: null, trace }; }
        let y = C.sqrt(r);
        if (y == null) { trace.push(step('reject', `${f(r)} is not a square mod p, so no point has this x: rejected.`, {})); return { P: null, trace }; }
        trace.push(step('sqrt', `A square root of ${f(r)} is ${f(y)}; the other is p − y = ${f(mod(-y, p))}.`, { y }));
        if (Number(y & 1n) !== bytes[0] - 2) y = mod(-y, p);
        trace.push(step('parity', `The prefix asks for an ${bytes[0] === 2 ? 'even' : 'odd'} y: y = ${f(y)}.`, { y }));
        return { P: { x, y }, trace };
      }
      trace.push(step('reject', 'Unknown prefix or wrong length: rejected.', {}));
      return { P: null, trace };
    };

    // ---- toy fields: brute force
    const needToy = () => { if (!C.toy) throw new Error('brute force needs a small field'); };
    let cache = null;
    C.points = () => {
      needToy();
      if (cache) return cache;
      const P = Number(p), sq = new Map(), out = [];
      for (let y = 0; y < P; y++) { const k = (y * y) % P; if (!sq.has(k)) sq.set(k, []); sq.get(k).push(y); }
      for (let x = 0; x < P; x++) for (const y of sq.get(Number(C.rhs(BigInt(x)))) || []) out.push({ x: BigInt(x), y: BigInt(y) });
      return (cache = out);
    };
    let Ncache = null;
    C.count = () => {
      if (Ncache) return Ncache;
      if (C.n && C.h) { const N = C.n * C.h; return (Ncache = { N, trace: [step('known', `The group order is known: #E = h·n = ${f(N)}.`, { N })] }); }
      needToy();
      const P = Number(p), A = Number(a), Bv = Number(b), sq = new Uint8Array(P);
      for (let y = 1; y < P; y++) sq[(y * y) % P] = 1;
      let N = 1, zeros = 0, twos = 0;
      for (let x = 0; x < P; x++) { const r = ((((x * x) % P) * x) % P + ((A * x) % P) + Bv) % P; if (r === 0) { N += 1; zeros++; } else if (sq[r]) { N += 2; twos++; } }
      const trace = [step('count', `For each of the ${P} values of x, x³ + ax + b is 0 (one point) for ${zeros}, a nonzero square (two points) for ${twos}, and a non-square (none) for the rest. With O, #E = 1 + ${zeros} + 2·${twos} = ${N}.`, { N, zeros, twos })];
      return (Ncache = { N: BigInt(N), trace });
    };
    C.order = (P) => {
      if (!P) return { order: 1n, trace: [step('order', 'O has order 1.', {})] };
      const { N } = C.count(), trace = [];
      let ord = N;
      for (const [q] of S.NT.factor(N)) {
        while (ord % q === 0n && !C.mul(ord / q, P)) { trace.push(step('divide', `(${f(ord)}/${q})·P = O, so the order divides ${f(ord / q)}.`, { q, ord: ord / q })); ord /= q; }
      }
      trace.unshift(step('lagrange', `By Lagrange the order of ${fp(P)} divides #E = ${f(N)}.`, { N }));
      trace.push(step('order', `No smaller divisor works: the order of ${fp(P)} is ${f(ord)}.`, { order: ord }));
      return { order: ord, trace };
    };
    C.hasse = () => {
      const { N } = C.count(), t = p + 1n - N, r = S.NT.isqrt(4n * p);
      const lo = p + 1n - r, hi = p + 1n + r;
      return {
        N, t, lo, hi, p,
        trace: [step('hasse', `Hasse: |#E − (p + 1)| ≤ 2√p. Here p + 1 = ${f(p + 1n)}, 2√p ≈ ${(2 * Math.sqrt(Number(p))).toFixed(2)}, so ${f(lo)} ≤ #E ≤ ${f(hi)}; #E = ${f(N)}, trace of Frobenius t = ${f(t)}.`, { N, t, lo, hi })],
      };
    };
    /** E(GF(p)) ≅ Z_n1 × Z_n2 with n2 | n1: n1 is the largest order of a point (the exponent of the group) */
    C.structure = () => {
      needToy();
      const { N } = C.count(), pts = C.points();
      let n1 = 1n, P1 = null;
      for (const P of pts) { const o = C.order(P).order; if (o > n1) { n1 = o; P1 = P; } if (n1 === N) break; }
      const n2 = N / n1;
      let P2 = null;
      if (n2 > 1n) {
        const inSub = new Set(); for (let i = 0n, R = null; i < n1; i++, R = C.add(R, P1)) inSub.add(R ? R.x + ',' + R.y : 'O');
        // E[n2] ≅ Z_n2 × Z_n2 holds a point of order n2 whose multiples meet ⟨P1⟩ only in O; search it directly
        // (scaling an arbitrary point by n1/n2 can land every candidate inside ⟨P1⟩, as in Z_8 × Z_2)
        for (const Q of pts) {
          if (C.mul(n2, Q) || C.order(Q).order !== n2) continue;
          let ok = true;
          for (let j = 1n, R = Q; j < n2; j++, R = C.add(R, Q)) if (inSub.has(R ? R.x + ',' + R.y : 'O')) { ok = false; break; }
          if (ok) { P2 = Q; break; }
        }
      }
      const cyclic = n2 === 1n;
      return {
        N, n1, n2, cyclic, P1, P2,
        trace: [step('structure', cyclic ? `The group is cyclic of order ${f(N)}: ${fp(P1)} generates every point.` : `The group is Z_${n1} × Z_${n2}: no point has order ${f(N)}; ${fp(P1)} has order ${n1} and ${fp(P2)} of order ${n2} completes it.`, { N, n1, n2, P1, P2 })],
      };
    };
    return C;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
