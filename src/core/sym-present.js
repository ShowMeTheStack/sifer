// PRESENT-80, a lightweight block cipher for small hardware: a 64-bit block, an 80-bit key, 31 rounds of round-key
// XOR, sixteen copies of one 4-bit S-box, and a bit permutation (bit i moves to 16·i mod 63, bit 63 stays), then a
// final round key. The key register rotates 61 places left, sends its top nibble through the S-box and takes the
// round counter into bits 19…15. Bit 0 is the least significant bit; blocks and keys are written big-endian.
//   S.PRESENT.encrypt(block8, key10) -> {out, rounds: [{round, key, added, sub, perm}], keys, trace}
//   S.PRESENT.decrypt(block8, key10) -> {out, trace}
//   S.PRESENT.keySchedule(key10) -> {keys: [32 BigInt], trace};  S.PRESENT.cipher(key10) -> {name, n: 8, encrypt, decrypt}
(function (S) {
  'use strict';
  const PR = (S.PRESENT = {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  PR.SBOX = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2];
  PR.INV_SBOX = new Array(16); PR.SBOX.forEach((v, i) => { PR.INV_SBOX[v] = i; });
  PR.PERM = Array.from({ length: 64 }, (_, i) => (i === 63 ? 63 : (16 * i) % 63));
  const M64 = (1n << 64n) - 1n, M80 = (1n << 80n) - 1n;
  const toBig = (b) => b.reduce((v, x) => (v << 8n) | BigInt(x), 0n);
  const toBytes = (v, n) => { const o = new Uint8Array(n); for (let i = n - 1; i >= 0; i--) { o[i] = Number(v & 255n); v >>= 8n; } return o; };
  const h16 = (v) => v.toString(16).padStart(16, '0'), h20 = (v) => v.toString(16).padStart(20, '0');
  PR.hex = h16;
  const sLayer = (x, T) => { let y = 0n; for (let i = 0; i < 16; i++) y |= BigInt(T[Number((x >> BigInt(4 * i)) & 15n)]) << BigInt(4 * i); return y; };
  const pLayer = (x) => { let y = 0n; for (let i = 0; i < 64; i++) if ((x >> BigInt(i)) & 1n) y |= 1n << BigInt(PR.PERM[i]); return y; };
  const pInv = (y) => { let x = 0n; for (let i = 0; i < 64; i++) if ((y >> BigInt(PR.PERM[i])) & 1n) x |= 1n << BigInt(i); return x; };
  PR.sLayer = (x) => sLayer(x, PR.SBOX);
  PR.pLayer = pLayer;

  PR.keySchedule = (key) => {
    if (key.length !== 10) throw new Error('PRESENT-80 needs a 10-byte key');
    let K = toBig(Array.from(key));
    const keys = [], trace = [];
    for (let i = 1; i <= 32; i++) {
      keys.push(K >> 16n);
      if (i === 32) break;
      const rot = ((K << 61n) | (K >> 19n)) & M80;
      const top = BigInt(PR.SBOX[Number(rot >> 76n)]);
      let nk = (rot & ((1n << 76n) - 1n)) | (top << 76n);
      nk ^= BigInt(i) << 15n;
      if (i <= 2 || i === 31) trace.push(step('pkey', `Round key ${i} = ${h16(K >> 16n)}; rotate the register ${h20(K)} left by 61 to ${h20(rot)}, pass its top nibble ${(rot >> 76n).toString(16)} through the S-box to ${top.toString(16)}, and XOR the counter ${i} into bits 19…15: ${h20(nk)}.`, { i, K, rot, next: nk }));
      K = nk;
    }
    return { keys, trace };
  };
  PR.encrypt = (block, key) => {
    const { keys } = PR.keySchedule(key);
    let x = toBig(Array.from(block));
    const rounds = [], trace = [];
    for (let r = 1; r <= 31; r++) {
      const added = x ^ keys[r - 1], sub = sLayer(added, PR.SBOX), perm = pLayer(sub);
      rounds.push({ round: r, key: keys[r - 1], added, sub, perm });
      trace.push(step('pround', `Round ${r}: ⊕ K${r} (${h16(keys[r - 1])}) gives ${h16(added)}; the S-boxes give ${h16(sub)}; the permutation gives ${h16(perm)}.`, { round: r, state: perm }));
      x = perm;
    }
    x ^= keys[31];
    trace.push(step('pfinal', `The final round key K32 = ${h16(keys[31])} gives the ciphertext ${h16(x)}.`, { state: x }));
    return { out: toBytes(x, 8), rounds, keys, trace };
  };
  PR.decrypt = (block, key) => {
    const { keys } = PR.keySchedule(key);
    let x = toBig(Array.from(block)) ^ keys[31];
    for (let r = 31; r >= 1; r--) x = sLayer(pInv(x), PR.INV_SBOX) ^ keys[r - 1];
    return { out: toBytes(x, 8), trace: [step('pdec', `Undoing the 31 rounds in reverse gives ${h16(x)}.`, { state: x })] };
  };
  PR.cipher = (key) => {
    const { keys } = PR.keySchedule(key);
    return {
      name: 'PRESENT-80', n: 8,
      encrypt: (b) => { let x = toBig(Array.from(b)); for (let r = 0; r < 31; r++) x = pLayer(sLayer(x ^ keys[r], PR.SBOX)); return toBytes((x ^ keys[31]) & M64, 8); },
      decrypt: (b) => { let x = toBig(Array.from(b)) ^ keys[31]; for (let r = 30; r >= 0; r--) x = sLayer(pInv(x), PR.INV_SBOX) ^ keys[r]; return toBytes(x, 8); },
    };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
