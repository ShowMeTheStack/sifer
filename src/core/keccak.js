// Keccak-f[1600]: the 5×5 state of 64-bit lanes (BigInt), its five steps θ, ρ, π, χ and ι, the sponge and SHA3-256.
// Lane (x, y) is A[x + 5y]; bit z of a lane is bit z of the BigInt.
//   S.Keccak.theta(A) -> {A, C, D, trace}; rho, pi, chi, iota(A, round) likewise return {A, trace}
//   S.Keccak.round(A, i) -> {A, steps: {theta, rho, pi, chi, iota}}
//   S.Keccak.f(A) -> A after 24 rounds;  S.Keccak.sha3_256(bytes) -> 32 bytes
(function (S) {
  'use strict';
  const { step } = S.bytes;
  const K = (S.Keccak = {});
  const M = (1n << 64n) - 1n;
  const rot = (v, n) => { n = BigInt(n % 64); return n ? ((v << n) | (v >> (64n - n))) & M : v; };
  K.rot = rot;
  K.hex = (v) => v.toString(16).padStart(16, '0');
  // the rotation offsets of ρ, by (x, y): walk (1, 0) → (y, 2x + 3y) and add t(t+1)/2
  K.R = new Array(25).fill(0);
  for (let t = 0, x = 1, y = 0; t < 24; t++) { K.R[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64; [x, y] = [y, (2 * x + 3 * y) % 5]; }
  // the round constants of ι, from the LFSR x^8 + x^6 + x^5 + x^4 + 1
  const rc = (t) => { if (t % 255 === 0) return 1; let R = 1; for (let i = 0; i < t % 255; i++) { R <<= 1; if (R & 0x100) R ^= 0x171; } return R & 1; };
  K.RC = [];
  for (let i = 0; i < 24; i++) { let c = 0n; for (let j = 0; j <= 6; j++) if (rc(j + 7 * i)) c |= 1n << BigInt(2 ** j - 1); K.RC.push(c); }

  K.theta = (A) => {
    const C = [0, 1, 2, 3, 4].map((x) => A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20]);
    const D = [0, 1, 2, 3, 4].map((x) => C[(x + 4) % 5] ^ rot(C[(x + 1) % 5], 1));
    const out = A.map((v, i) => v ^ D[i % 5]);
    const trace = [
      ...C.map((c, x) => step('parity', `Column parity C[${x}] = the XOR of the five lanes with x = ${x}: ${K.hex(c)}.`, { x, C: c })),
      ...D.map((d, x) => step('effect', `D[${x}] = C[${(x + 4) % 5}] ⊕ (C[${(x + 1) % 5}] rotated by 1) = ${K.hex(d)}.`, { x, D: d })),
      step('apply', 'Every lane is XORed with the D of its column, so each bit now depends on itself and on 10 bits of two nearby columns.', {}),
    ];
    return { A: out, C, D, trace };
  };
  K.rho = (A) => ({ A: A.map((v, i) => rot(v, K.R[i])), trace: [step('rho', 'ρ rotates each lane by its own offset, from 0 to 62 bits.', {})] });
  K.pi = (A) => { const o = new Array(25); for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) o[y + 5 * ((2 * x + 3 * y) % 5)] = A[x + 5 * y]; return { A: o, trace: [step('pi', 'π moves lane (x, y) to (y, 2x + 3y).', {})] }; };
  K.chi = (A) => { const o = new Array(25); for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) o[x + 5 * y] = A[x + 5 * y] ^ (~A[((x + 1) % 5) + 5 * y] & M & A[((x + 2) % 5) + 5 * y]); return { A: o, trace: [step('chi', 'χ is the only non-linear step: a ⊕= (¬b) ∧ c along each row.', {})] }; };
  K.iota = (A, i) => { const o = A.slice(); o[0] ^= K.RC[i]; return { A: o, trace: [step('iota', `ι XORs the round constant ${K.hex(K.RC[i])} into lane (0, 0).`, { rc: K.RC[i] })] }; };
  K.round = (A, i) => {
    const th = K.theta(A), rh = K.rho(th.A), p = K.pi(rh.A), c = K.chi(p.A), io = K.iota(c.A, i);
    return { A: io.A, steps: { theta: th, rho: rh, pi: p, chi: c, iota: io } };
  };
  K.f = (A) => { for (let i = 0; i < 24; i++) A = K.round(A, i).A; return A; };
  K.sponge = (msg, rate, pad, outLen) => {
    const n = msg.length, len = Math.floor(n / rate) * rate + rate, m = new Uint8Array(len);
    m.set(msg); m[n] ^= pad; m[len - 1] ^= 0x80;
    let A = new Array(25).fill(0n);
    for (let off = 0; off < len; off += rate) {
      for (let i = 0; i < rate / 8; i++) { let v = 0n; for (let b = 7; b >= 0; b--) v = (v << 8n) | BigInt(m[off + 8 * i + b]); A[i] ^= v; }
      A = K.f(A);
    }
    const out = new Uint8Array(outLen);
    for (let i = 0; i < outLen; i++) out[i] = Number((A[i >> 3] >> BigInt(8 * (i & 7))) & 255n);
    return out;
  };
  K.sha3_256 = (msg) => K.sponge(msg, 136, 0x06, 32);
  /** a state from bytes (little-endian lanes), for pictures */
  K.fromBytes = (bytes) => { const A = new Array(25).fill(0n); for (let i = 0; i < bytes.length && i < 200; i++) A[i >> 3] |= BigInt(bytes[i]) << BigInt(8 * (i & 7)); return A; };
  K.bit = (A, x, y, z) => Number((A[x + 5 * y] >> BigInt(z)) & 1n);
})(globalThis.Sifer = globalThis.Sifer || {});
