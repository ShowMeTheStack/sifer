// X25519 (RFC 7748): Curve25519 in Montgomery form v² = u³ + 486662u² + u over GF(2²⁵⁵ − 19), using only u, with
// the scalar clamped and the Montgomery ladder traced bit by bit (the conditional swap included).
//   S.ECC.X25519.clamp(k32) -> {k: BigInt, bytes, trace}     the three bit changes shown
//   S.ECC.X25519.ladder(k, u[, {trace}]) -> {u, steps: [{t, bit, swap, x2, x3}], cost: {M, S}, trace}
//   S.ECC.X25519.x25519(k32, u32[, {trace}]) -> {out: 32 bytes, trace, steps};  .publicKey(k32) -> 32 bytes
//   S.ECC.X25519.p / A / a24 / base (u = 9)
(function (S) {
  'use strict';
  const E = (S.ECC = S.ECC || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const p = (1n << 255n) - 19n, A = 486662n, a24 = 121665n;
  const mod = (v) => { const r = v % p; return r < 0n ? r + p : r; };
  const pow = (b, e) => { let r = 1n; b = mod(b); while (e) { if (e & 1n) r = (r * b) % p; b = (b * b) % p; e >>= 1n; } return r; };
  const le = (b) => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };
  const toLe = (v, n = 32) => { const out = new Uint8Array(n); for (let i = 0; i < n; i++) { out[i] = Number(v & 255n); v >>= 8n; } return out; };
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const f = (v) => E.fmt(v);
  const X = (E.X25519 = { p, A, a24, base: 9n, le, toLe });

  X.clamp = (k32) => {
    const b = Uint8Array.from(k32), before0 = b[0], before31 = b[31];
    b[0] &= 248; b[31] &= 127; b[31] |= 64;
    const k = le(b), trace = [
      step('clamp-low', `Clear the three low bits of byte 0 (${before0.toString(2).padStart(8, '0')} → ${b[0].toString(2).padStart(8, '0')}): k becomes a multiple of the cofactor 8, so small-subgroup parts of a hostile point vanish.`, { before: before0, after: b[0] }),
      step('clamp-high', `Clear bit 255 and set bit 254 of byte 31 (${before31.toString(2).padStart(8, '0')} → ${b[31].toString(2).padStart(8, '0')}): every key has the same length, so the ladder always runs the same number of steps.`, { before: before31, after: b[31] }),
      step('scalar', `The clamped scalar, read little-endian, is k = ${f(k)}.`, { k }),
    ];
    return { k, bytes: b, trace };
  };
  X.decodeU = (u32) => { const b = Uint8Array.from(u32); b[31] &= 127; return mod(le(b)); };

  /** RFC 7748 section 5: the ladder on (x2 : z2) = k'·u and (x3 : z3) = (k' + 1)·u, for bits 254 down to 0 */
  X.ladder = (k, u, o = {}) => {
    const keep = o.trace !== false;
    const x1 = mod(u);
    let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0n;
    const steps = [], trace = [];
    const cost = { M: 0, S: 0 };
    if (keep) trace.push(step('start', `Ladder on u = ${f(x1)}: start with (x₂ : z₂) = (1 : 0), the point at infinity, and (x₃ : z₃) = (u : 1). The two always differ by the input point.`, { u: x1 }));
    for (let t = 254; t >= 0; t--) {
      const kt = (k >> BigInt(t)) & 1n;
      swap ^= kt;
      if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
      const didSwap = swap;
      swap = kt;
      const Aa = mod(x2 + z2), AA = (Aa * Aa) % p, Bb = mod(x2 - z2), BB = (Bb * Bb) % p, Ee = mod(AA - BB);
      const Cc = mod(x3 + z3), Dd = mod(x3 - z3), DA = (Dd * Aa) % p, CB = (Cc * Bb) % p;
      x3 = mod((DA + CB) * (DA + CB)); z3 = mod(x1 * mod((DA - CB) * (DA - CB)));
      x2 = (AA * BB) % p; z2 = mod(Ee * (AA + a24 * Ee));
      cost.M += 5; cost.S += 4;
      if (keep) {
        steps.push({ t, bit: Number(kt), swap: Number(didSwap), x2, z2, x3, z3 });
        trace.push(step('bit', `Bit ${t} = ${kt}: ${didSwap ? 'swap the pair, then ' : ''}add the two to get one and double the ${kt ? 'second' : 'first'} (differential addition with difference u, then x-only doubling).`, { t, bit: Number(kt), swap: Number(didSwap) }));
      }
    }
    if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    const out = (x2 * pow(z2, p - 2n)) % p;
    if (keep) trace.push(step('done', `Undo the last swap and return x₂ / z₂ = x₂·z₂^(p−2) = ${f(out)} (${cost.M}M + ${cost.S}S, plus the inversion: no branch depends on a secret bit).`, { u: out, cost }));
    return { u: out, steps, cost, trace };
  };

  X.x25519 = (k32, u32, o = {}) => {
    const c = X.clamp(k32), u = X.decodeU(u32), L = X.ladder(c.k, u, o);
    const out = toLe(L.u);
    const trace = o.trace === false ? [] : [...c.trace, step('u', `Decode u little-endian with the top bit masked: u = ${f(u)}.`, { u }), ...L.trace, step('out', `Encode the result little-endian: ${hex(out)}.`, { out: hex(out) })];
    return { out, k: c.k, u, steps: L.steps, cost: L.cost, trace };
  };
  X.publicKey = (k32) => X.x25519(k32, toLe(9n), { trace: false }).out;
  X.shared = (k32, peer32) => {
    const r = X.x25519(k32, peer32);
    const zero = r.out.every((v) => v === 0);
    r.trace.push(step(zero ? 'reject' : 'shared', zero ? 'The output is all zero: the peer sent a point of small order. Abort.' : 'Both sides reach the same u: k_A·(k_B·9) = k_B·(k_A·9).', { zero }));
    return { shared: zero ? null : r.out, trace: r.trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
