// Finite fields. GF(p) is Z_p with p prime, with inverses, division and square roots (Tonelli–Shanks). GF(2^m) holds
// polynomials over GF(2) as BigInt bit masks (bit i is the coefficient of x^i), multiplied by shift-and-add with
// reduction, divided by long division, and inverted by the extended Euclidean algorithm on polynomials, all traced.
// GF(2^128) of GCM uses the same field with the bits of each byte reflected: the first bit of the block (the top bit
// of byte 0) is the coefficient of x^0, and the reduction constant R = e1 00…00 appears in that order.
//   S.GF.prime(p) -> {p, add, sub, mul, inv, div, pow, neg, sqrt, isSquare, elements, table(op), invTrace(a)}
//   S.GF.poly: str(a) / deg(a) / mul(a, b) / divmod(a, b) -> {q, r, trace} / gcd / isIrreducible(f)
//   S.GF.binary(m[, f]) -> {m, f, add, mul(a, b) -> value, mulTrace(a, b) -> {value, rows, trace}, inv, invTrace, pow, str}
//   S.GF.IRREDUCIBLE[m]      a standard modulus for m = 2…16, 32, 64, 128, 163, 233, 283
//   S.GF.gcm.mul(X, Y[, trace]) -> 16 bytes; .toPoly(bytes) / fromPoly(v); .ghash(H, aad, ct) -> 16 bytes
(function (S) {
  'use strict';
  const N = () => S.NT;
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const G = (S.GF = S.GF || {});

  G.prime = (p) => {
    p = B(p);
    const F = { p };
    const m = (a) => N().mod(a, p), sh = (v) => N().short(v);
    F.add = (a, b) => m(B(a) + B(b));
    F.sub = (a, b) => m(B(a) - B(b));
    F.neg = (a) => m(-B(a));
    F.mul = (a, b) => m(B(a) * B(b));
    F.inv = (a) => N().inv(a, p);
    F.div = (a, b) => F.mul(a, F.inv(b));
    F.pow = (a, e) => N().pow(a, e, p);
    F.invTrace = (a) => N().inverse(a, p);
    /** Euler's criterion */
    F.isSquare = (a) => { a = m(a); return a === 0n || p === 2n || F.pow(a, (p - 1n) / 2n) === 1n; };
    /** a square root by Tonelli–Shanks (null when a is not a square) */
    F.sqrt = (a) => {
      a = m(a);
      if (a === 0n || p === 2n) return a;
      if (!F.isSquare(a)) return null;
      if (p % 4n === 3n) return F.pow(a, (p + 1n) / 4n);
      let q = p - 1n, s = 0n;
      while (!(q & 1n)) { q >>= 1n; s++; }
      let z = 2n;
      while (F.isSquare(z)) z++;
      let M = s, c = F.pow(z, q), t = F.pow(a, q), R = F.pow(a, (q + 1n) / 2n);
      while (t !== 1n) {
        let i = 0n, t2 = t;
        while (t2 !== 1n) { t2 = (t2 * t2) % p; i++; }
        const b = F.pow(c, 1n << (M - i - 1n));
        M = i; c = (b * b) % p; t = (t * c) % p; R = (R * b) % p;
      }
      return R;
    };
    F.elements = () => { const out = []; for (let k = 0n; k < p; k++) out.push(k); return out; };
    F.table = (op) => F.elements().map((a) => F.elements().map((b) => (op === '+' ? F.add(a, b) : op === '-' ? F.sub(a, b) : op === '/' ? (b ? F.div(a, b) : null) : F.mul(a, b))));
    F.describe = (a, b, op) => `${sh(a)} ${op} ${sh(b)} = ${sh(op === '+' ? F.add(a, b) : op === '−' ? F.sub(a, b) : op === '/' ? F.div(a, b) : F.mul(a, b))} in GF(${sh(p)})`;
    return F;
  };

  // ---- polynomials over GF(2) as BigInt bit masks
  const P = (G.poly = {});
  const SUP = '⁰¹²³⁴⁵⁶⁷⁸⁹';
  const sup = (k) => String(k).split('').map((d) => SUP[d]).join('');
  P.deg = (a) => (B(a) === 0n ? -1 : B(a).toString(2).length - 1);
  P.str = (a) => {
    a = B(a);
    if (a === 0n) return '0';
    const t = [];
    for (let i = P.deg(a); i >= 0; i--) if ((a >> BigInt(i)) & 1n) t.push(i === 0 ? '1' : i === 1 ? 'x' : 'x' + sup(i));
    return t.join(' + ');
  };
  P.bits = (a, width) => B(a).toString(2).padStart(width || 1, '0');
  /** the product without reduction (carry-less multiplication) */
  P.mul = (a, b) => { a = B(a); b = B(b); let r = 0n; for (let i = 0n; b >> i; i++) if ((b >> i) & 1n) r ^= a << i; return r; };
  /** long division: a = q·b + r with deg r < deg b */
  P.divmod = (a, b) => {
    a = B(a); b = B(b);
    if (b === 0n) throw new Error('division by the zero polynomial');
    const db = P.deg(b), trace = [];
    let q = 0n, r = a;
    while (P.deg(r) >= db) {
      const k = P.deg(r) - db, sub = b << BigInt(k);
      trace.push(step('divide', `Leading term x${sup(P.deg(r))} ÷ x${sup(db)} = ${k ? (k === 1 ? 'x' : 'x' + sup(k)) : '1'}: subtract ${P.str(sub)} from ${P.str(r)} to get ${P.str(r ^ sub)}.`, { k, r, sub, next: r ^ sub }));
      q |= 1n << BigInt(k); r ^= sub;
    }
    return { q, r, trace };
  };
  P.mod = (a, b) => P.divmod(a, b).r;
  P.gcd = (a, b) => { a = B(a); b = B(b); while (b) [a, b] = [b, P.mod(a, b)]; return a; };
  P.powmod = (a, e, f) => { let r = 1n; a = P.mod(a, f); e = B(e); while (e) { if (e & 1n) r = P.mod(P.mul(r, a), f); a = P.mod(P.mul(a, a), f); e >>= 1n; } return r; };
  /** Rabin's test: f of degree m is irreducible iff x^(2^m) ≡ x mod f and gcd(x^(2^(m/r)) − x, f) = 1 for each prime r | m */
  P.isIrreducible = (f) => {
    f = B(f);
    const m = P.deg(f);
    if (m < 1) return false;
    if (m === 1) return true;
    const x2k = (k) => { let v = 2n; for (let i = 0; i < k; i++) v = P.mod(P.mul(v, v), f); return v; };
    if (x2k(m) !== 2n) return false;
    for (const [r] of S.NT.factor(m)) if (P.gcd(x2k(m / Number(r)) ^ 2n, f) !== 1n) return false;
    return true;
  };
  const T = (exps) => exps.reduce((v, e) => v | (1n << BigInt(e)), 0n);
  G.IRREDUCIBLE = {
    2: T([2, 1, 0]), 3: T([3, 1, 0]), 4: T([4, 1, 0]), 5: T([5, 2, 0]), 6: T([6, 1, 0]), 7: T([7, 1, 0]), 8: T([8, 4, 3, 1, 0]),
    9: T([9, 4, 0]), 10: T([10, 3, 0]), 11: T([11, 2, 0]), 12: T([12, 6, 4, 1, 0]), 13: T([13, 4, 3, 1, 0]), 14: T([14, 10, 6, 1, 0]),
    15: T([15, 1, 0]), 16: T([16, 12, 3, 1, 0]), 32: T([32, 7, 3, 2, 0]), 64: T([64, 4, 3, 1, 0]), 128: T([128, 7, 2, 1, 0]),
    163: T([163, 7, 6, 3, 0]), 233: T([233, 74, 0]), 283: T([283, 12, 7, 5, 0]),
  };

  /** GF(2^m) = GF(2)[x] / f(x) */
  G.binary = (m, f) => {
    m = Number(m); f = B(f != null ? f : G.IRREDUCIBLE[m]);
    if (P.deg(f) !== m) throw new Error(`the modulus must have degree ${m}`);
    const F = { m, f, size: 1n << BigInt(m), str: P.str };
    const top = 1n << BigInt(m), low = f ^ top, hexw = Math.ceil(m / 4);
    F.hex = (a) => B(a).toString(16).padStart(hexw, '0');
    F.add = (a, b) => B(a) ^ B(b);
    F.reduce = (a) => P.mod(a, f);
    /** shift-and-add: walk the bits of b from x^0 up, adding the current multiple of a, then multiply a by x and reduce */
    F.mulTrace = (a, b) => {
      a = F.reduce(a); b = F.reduce(b);
      const rows = [], trace = [];
      let acc = 0n, cur = a;
      for (let i = 0; i < m; i++) {
        const bit = Number((b >> BigInt(i)) & 1n), before = acc;
        if (bit) acc ^= cur;
        const shifted = cur << 1n, reduced = !!(shifted & top), next = reduced ? shifted ^ top ^ low : shifted;
        rows.push({ i, bit, term: cur, acc, shifted, reduced, next });
        if (bit) trace.push(step('add', `Bit ${i} of b is 1: add x${sup(i)}·a = ${F.hex(cur)}, giving ${F.hex(before)} ⊕ ${F.hex(cur)} = ${F.hex(acc)}.`, { i, term: cur, acc }));
        if (i < m - 1 && b >> BigInt(i + 1)) trace.push(step('shift', `Multiply by x: ${F.hex(cur)} becomes ${F.hex(next)}${reduced ? ` (x${sup(m)} appeared, so add f without it, ${F.hex(low)})` : ''}.`, { i, from: cur, to: next, reduced }));
        cur = next;
      }
      trace.push(step('done', `(${P.str(a)})·(${P.str(b)}) = ${P.str(acc)} in GF(2${sup(m)}).`, { value: acc }));
      return { value: acc, rows, trace };
    };
    F.mul = (a, b) => {
      a = F.reduce(a); b = B(b);
      let acc = 0n;
      for (let i = 0n; b >> i; i++) { if ((b >> i) & 1n) acc ^= a; a <<= 1n; if (a & top) a ^= f; }
      return acc;
    };
    F.square = (a) => F.mul(a, a);
    F.pow = (a, e) => { let r = 1n; a = F.reduce(a); e = B(e); while (e) { if (e & 1n) r = F.mul(r, a); a = F.mul(a, a); e >>= 1n; } return r; };
    /** the extended Euclidean algorithm on polynomials: rows r_i = s_i·f + t_i·a, until r = 1 */
    F.invTrace = (a) => {
      a = F.reduce(a);
      const trace = [], rows = [{ r: f, q: null, t: 0n }, { r: a, q: null, t: 1n }];
      if (a === 0n) return { inv: null, rows, trace: [step('zero', '0 has no inverse.')] };
      while (rows[rows.length - 1].r !== 0n && rows[rows.length - 1].r !== 1n) {
        const p = rows[rows.length - 2], c = rows[rows.length - 1];
        const { q, r } = P.divmod(p.r, c.r);
        c.q = q;
        const t = p.t ^ P.mul(q, c.t);
        rows.push({ r, q: null, t });
        trace.push(step('row', `Divide ${P.str(p.r)} by ${P.str(c.r)}: quotient ${P.str(q)}, remainder ${P.str(r)}; t = ${P.str(t)}.`, { q, r, t }));
      }
      const last = rows[rows.length - 1];
      if (last.r !== 1n) return { inv: null, rows, trace };
      const inv = F.reduce(last.t);
      trace.push(step('done', `The remainder reached 1, so (${P.str(a)})⁻¹ = ${P.str(inv)} = ${F.hex(inv)}.`, { inv }));
      return { inv, rows, trace };
    };
    F.inv = (a) => { const r = F.invTrace(a).inv; if (r === null) throw new Error('0 has no inverse'); return r; };
    F.div = (a, b) => F.mul(a, F.inv(b));
    return F;
  };

  // ---- GF(2^128) as GCM uses it (NIST SP 800-38D)
  const C = (G.gcm = {});
  const R = 0xe1n << 120n;
  const toInt = (b) => { let v = 0n; for (const x of b) v = (v << 8n) | BigInt(x); return v; };
  const toBlock = (v) => { const out = new Uint8Array(16); for (let i = 15; i >= 0; i--) { out[i] = Number(v & 255n); v >>= 8n; } return out; };
  const rev128 = (v) => { let r = 0n; for (let i = 0; i < 128; i++) { r = (r << 1n) | (v & 1n); v >>= 1n; } return r; };
  /** a block as a polynomial in the ordinary order (bit i = coefficient of x^i) */
  C.toPoly = (bytes) => rev128(toInt(bytes));
  C.fromPoly = (v) => toBlock(rev128(B(v)));
  C.R = toBlock(R);
  /** X·Y by the right-shift algorithm of the standard: walk the 128 bits of X from the first; V = Y·x each step */
  C.mul = (X, Y, trace) => {
    const x = toInt(X);
    let Z = 0n, V = toInt(Y);
    const hx = (v) => v.toString(16).padStart(32, '0');
    for (let i = 0; i < 128; i++) {
      const bit = (x >> BigInt(127 - i)) & 1n;
      if (bit) Z ^= V;
      const lsb = V & 1n;
      V = lsb ? (V >> 1n) ^ R : V >> 1n;
      if (trace && i < 128) trace.push(step('bit', `Bit ${i} of X is ${bit}${bit ? `: Z ⊕= V, Z = ${hx(Z)}` : ''}; V moves one place right${lsb ? ' and R is folded in' : ''}.`, { i, bit: Number(bit), Z, V, reduced: !!lsb }));
    }
    return toBlock(Z);
  };
  /** GHASH_H(A, C): the blocks of A and C (each zero-padded), then the lengths in bits, chained by Y = (Y ⊕ X)·H */
  C.ghash = (H, aad, ct) => {
    const blocks = [];
    const pushPadded = (d) => { for (let i = 0; i < d.length; i += 16) { const b = new Uint8Array(16); b.set(d.subarray(i, i + 16)); blocks.push(b); } };
    pushPadded(aad); pushPadded(ct);
    const len = new Uint8Array(16);
    len.set(N().toBytes(BigInt(aad.length) * 8n, 8), 0); len.set(N().toBytes(BigInt(ct.length) * 8n, 8), 8);
    blocks.push(len);
    let Y = new Uint8Array(16);
    for (const b of blocks) { const t = Y.map((v, i) => v ^ b[i]); Y = C.mul(t, H); }
    return Y;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
