// DES: the tables of the standard, the key schedule, the f-function and the 16-round Feistel ladder, with every
// half-block kept. Blocks are 64 bits; inside, bits are arrays of 0 and 1 with bit 1 (the leftmost) first.
//   S.DES.encrypt(block8, key8[, {decrypt}]) -> {out, ip, rounds: [{i, L, R, K, f, newR}], keys, trace}
//   S.DES.f(R32, K48) -> {E, X, boxes: [{i, in6, row, col, out}], S, P, trace}
(function (S) {
  'use strict';
  const { step } = S.bytes;
  const D = (S.DES = {});
  D.IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
  D.FP = new Array(64); D.IP.forEach((p, i) => { D.FP[p - 1] = i + 1; });
  D.E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
  D.P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
  D.PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];
  D.PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];
  D.SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
  D.SBOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
  ];

  const perm = (bits, table) => table.map((p) => bits[p - 1]);
  const xor = (a, b) => a.map((v, i) => v ^ b[i]);
  D.bits = (bytes) => { const out = []; for (const b of bytes) for (let i = 7; i >= 0; i--) out.push((b >> i) & 1); return out; };
  D.bytes = (bits) => { const out = new Uint8Array(bits.length / 8); bits.forEach((v, i) => { out[i >> 3] |= v << (7 - (i & 7)); }); return out; };
  /** bits as hex, four to a digit */
  D.hex = (bits) => { let s = ''; for (let i = 0; i < bits.length; i += 4) s += ((bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3]).toString(16); return s; };
  D.bin = (bits) => bits.join('');
  D.perm = perm;

  /** the 16 round keys of 48 bits, with C and D after each rotation */
  D.keySchedule = (key) => {
    const k = perm(D.bits(key), D.PC1);
    let C = k.slice(0, 28), Dd = k.slice(28);
    const keys = [], trace = [step('pc1', `PC-1 drops the parity bits and splits the key into C0 = ${D.hex(C)} and D0 = ${D.hex(Dd)} (28 bits each).`, { C, D: Dd })];
    for (let i = 0; i < 16; i++) {
      const s = D.SHIFTS[i];
      C = C.slice(s).concat(C.slice(0, s)); Dd = Dd.slice(s).concat(Dd.slice(0, s));
      const K = perm(C.concat(Dd), D.PC2);
      keys.push({ i: i + 1, C, D: Dd, K });
      trace.push(step('subkey', `Round ${i + 1}: rotate both halves left by ${s}; PC-2 picks 48 bits: K${i + 1} = ${D.hex(K)}.`, { i: i + 1, shift: s, K }));
    }
    return { keys, trace };
  };

  D.f = (R, K) => {
    const E = perm(R, D.E), X = xor(E, K);
    const boxes = [], Sout = [];
    for (let i = 0; i < 8; i++) {
      const in6 = X.slice(6 * i, 6 * i + 6);
      const row = (in6[0] << 1) | in6[5], col = (in6[1] << 3) | (in6[2] << 2) | (in6[3] << 1) | in6[4];
      const v = D.SBOX[i][16 * row + col];
      const out = [3, 2, 1, 0].map((b) => (v >> b) & 1);
      boxes.push({ i: i + 1, in6, row, col, v, out });
      Sout.push(...out);
    }
    const P = perm(Sout, D.P);
    const trace = [
      step('expand', `E spreads R = ${D.hex(R)} to 48 bits: ${D.hex(E)}.`, { R, E }),
      step('key-mix', `XOR with the round key ${D.hex(K)} gives ${D.hex(X)}.`, { K, X }),
      ...boxes.map((b) => step('sbox', `S${b.i}: ${D.bin(b.in6)} picks row ${b.row} (outer bits ${b.in6[0]}${b.in6[5]}), column ${b.col} (middle bits ${D.bin(b.in6.slice(1, 5))}): ${b.v} = ${D.bin(b.out)}.`, b)),
      step('permute', `The S-boxes give ${D.hex(Sout)}; P rearranges it to f = ${D.hex(P)}.`, { S: Sout, P }),
    ];
    return { E, X, boxes, S: Sout, P, trace };
  };

  D.encrypt = (block, key, opts) => {
    const dec = !!(opts && opts.decrypt);
    const { keys } = D.keySchedule(key);
    const ip = perm(D.bits(block), D.IP);
    let L = ip.slice(0, 32), R = ip.slice(32);
    const rounds = [], trace = [step('ip', `The initial permutation gives L0 = ${D.hex(L)} and R0 = ${D.hex(R)}.`, { L, R })];
    for (let i = 0; i < 16; i++) {
      const K = keys[dec ? 15 - i : i].K;
      const f = D.f(R, K);
      const newR = xor(L, f.P);
      rounds.push({ i: i + 1, L, R, K, f, newR });
      trace.push(step('round', `Round ${i + 1}: L${i + 1} = R${i} = ${D.hex(R)}, and R${i + 1} = L${i} ⊕ f(R${i}, K${i + 1}) = ${D.hex(L)} ⊕ ${D.hex(f.P)} = ${D.hex(newR)}.`, { i: i + 1, L: R, R: newR }));
      L = R; R = newR;
    }
    // the halves are swapped once more before the final permutation
    const pre = R.concat(L), out = D.bytes(perm(pre, D.FP));
    trace.push(step('fp', `Swap the halves to ${D.hex(pre)}; the final permutation gives ${D.hex(D.bits(out))}.`, { pre }));
    return { out, ip, rounds, keys, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
