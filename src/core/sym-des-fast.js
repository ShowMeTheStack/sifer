// DES on 32-bit words, for work that needs thousands of encryptions (meet-in-the-middle, the modes, 3DES): the
// S-boxes and P fold into eight SP tables, and the expansion E is a rotation. Same results as S.DES.encrypt.
//   S.DES.fastKeys(key8) -> Int32Array(16 × 8) six-bit chunks of each round key
//   S.DES.fastBlock(block8, keys, decrypt) -> Uint8Array(8)
//   S.DES.cipher(key8) -> {name, n: 8, encrypt, decrypt}
//   S.TDES.encrypt(block8, key16or24) -> {out, steps, trace}; S.TDES.decrypt; S.TDES.cipher(key)   EDE, 2- or 3-key
//   S.DESX.encrypt(block8, k, k1, k2) -> {out, trace}; S.DESX.cipher(k, k1, k2)    c = k2 ⊕ DES_k(p ⊕ k1)
(function (S) {
  'use strict';
  const D = (S.DES = S.DES || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  let SP = null, IPT = null, FPT = null;
  const init = () => {
    if (SP) return;
    SP = [];
    for (let i = 0; i < 8; i++) {
      const t = new Uint32Array(64);
      for (let x = 0; x < 64; x++) {
        const row = ((x >> 4) & 2) | (x & 1), col = (x >> 1) & 15, v = D.SBOX[i][16 * row + col];
        // the four output bits sit at positions 4i+1…4i+4 (1-based, from the left) before P
        let pre = 0; for (let b = 0; b < 4; b++) if ((v >> (3 - b)) & 1) pre |= 1 << (31 - (4 * i + b));
        let out = 0; D.P.forEach((p, j) => { if ((pre >>> (32 - p)) & 1) out |= 1 << (31 - j); });
        t[x] = out >>> 0;
      }
      SP.push(t);
    }
    IPT = D.IP.map((p) => p - 1); FPT = D.FP.map((p) => p - 1);
  };
  const getBit = (b, i) => (b[i >> 3] >> (7 - (i & 7))) & 1;
  D.fastKeys = (key) => {
    init();
    const bits = D.PC1.map((p) => getBit(key, p - 1));
    let C = 0, Dd = 0;
    for (let i = 0; i < 28; i++) { C = (C << 1) | bits[i]; Dd = (Dd << 1) | bits[28 + i]; }
    const ks = new Int32Array(128), rot = (x, s) => ((x << s) | (x >>> (28 - s))) & 0xfffffff;
    for (let r = 0; r < 16; r++) {
      C = rot(C, D.SHIFTS[r]); Dd = rot(Dd, D.SHIFTS[r]);
      for (let j = 0; j < 8; j++) {
        let v = 0;
        for (let b = 0; b < 6; b++) { const p = D.PC2[6 * j + b] - 1; v = (v << 1) | (p < 28 ? (C >> (27 - p)) & 1 : (Dd >> (55 - p)) & 1); }
        ks[8 * r + j] = v;
      }
    }
    return ks;
  };
  const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  const F = (R, ks, r) => {
    let out = 0;
    for (let i = 0; i < 8; i++) {
      const k = 4 * i - 1, chunk = ((k < 0 ? ((R >>> 1) | (R << 31)) >>> 0 : rotl(R, k)) >>> 26) & 63;
      out ^= SP[i][chunk ^ ks[8 * r + i]];
    }
    return out >>> 0;
  };
  D.fastBlock = (block, ks, decrypt) => {
    init();
    let L = 0, R = 0;
    for (let i = 0; i < 32; i++) { L = (L << 1) | getBit(block, IPT[i]); R = (R << 1) | getBit(block, IPT[32 + i]); }
    L >>>= 0; R >>>= 0;
    for (let r = 0; r < 16; r++) { const t = (L ^ F(R, ks, decrypt ? 15 - r : r)) >>> 0; L = R; R = t; }
    const pre = new Uint8Array(8);
    for (let i = 0; i < 4; i++) { pre[i] = (R >>> (24 - 8 * i)) & 255; pre[4 + i] = (L >>> (24 - 8 * i)) & 255; }
    const out = new Uint8Array(8);
    for (let i = 0; i < 64; i++) if (getBit(pre, FPT[i])) out[i >> 3] |= 1 << (7 - (i & 7));
    return out;
  };
  D.cipher = (key) => { const ks = D.fastKeys(key); return { name: 'DES', n: 8, encrypt: (b) => D.fastBlock(b, ks, false), decrypt: (b) => D.fastBlock(b, ks, true) }; };

  const hex = (a) => S.bytes.hex(a);
  const T = (S.TDES = {});
  const split3 = (key) => {
    if (key.length !== 16 && key.length !== 24) throw new Error('triple DES needs 16 (two keys) or 24 (three keys) bytes');
    const k1 = key.slice(0, 8), k2 = key.slice(8, 16), k3 = key.length === 24 ? key.slice(16, 24) : k1;
    return [k1, k2, k3];
  };
  /** EDE: encrypt with k1, decrypt with k2, encrypt with k3 (k3 = k1 for the two-key version) */
  T.encrypt = (block, key) => {
    const [k1, k2, k3] = split3(key);
    const a = D.cipher(k1).encrypt(block), b = D.cipher(k2).decrypt(a), c = D.cipher(k3).encrypt(b);
    const two = key.length === 16;
    return { out: c, steps: [a, b, c], trace: [
      step('tdes-e', `Encrypt ${hex(block)} with K1 = ${hex(k1)}: ${hex(a)}.`, { stage: 1, key: k1, out: a }),
      step('tdes-d', `Decrypt that with K2 = ${hex(k2)}: ${hex(b)}.`, { stage: 2, key: k2, out: b }),
      step('tdes-e', `Encrypt with K3 = ${hex(k3)}${two ? ' (the two-key version reuses K1)' : ''}: the ciphertext is ${hex(c)}.`, { stage: 3, key: k3, out: c }),
    ] };
  };
  T.decrypt = (block, key) => {
    const [k1, k2, k3] = split3(key);
    const a = D.cipher(k3).decrypt(block), b = D.cipher(k2).encrypt(a), c = D.cipher(k1).decrypt(b);
    return { out: c, steps: [a, b, c], trace: [
      step('tdes-d', `Decrypt ${hex(block)} with K3: ${hex(a)}.`, { stage: 1, out: a }),
      step('tdes-e', `Encrypt with K2: ${hex(b)}.`, { stage: 2, out: b }),
      step('tdes-d', `Decrypt with K1: the plaintext is ${hex(c)}.`, { stage: 3, out: c }),
    ] };
  };
  T.cipher = (key) => {
    const [k1, k2, k3] = split3(key).map(D.cipher);
    return { name: key.length === 16 ? '2-key 3DES' : '3-key 3DES', n: 8, encrypt: (b) => k3.encrypt(k2.decrypt(k1.encrypt(b))), decrypt: (b) => k1.decrypt(k2.encrypt(k3.decrypt(b))) };
  };
  /** with K1 = K2 (or K2 = K3) the first two stages cancel, so EDE is single DES: why EDE was chosen */
  T.compatible = (block, key8) => T.encrypt(block, Uint8Array.from([...key8, ...key8, ...key8])).out;

  const X = (S.DESX = {});
  X.encrypt = (block, k, k1, k2) => {
    const xor = S.bytes.xor, a = xor(block, k1), b = D.cipher(k).encrypt(a), c = xor(b, k2);
    return { out: c, trace: [
      step('whiten', `Pre-whitening: ${hex(block)} ⊕ K1 ${hex(k1)} = ${hex(a)}.`, { out: a }),
      step('des', `DES with K = ${hex(k)} gives ${hex(b)}.`, { out: b }),
      step('whiten', `Post-whitening: ${hex(b)} ⊕ K2 ${hex(k2)} = ${hex(c)}.`, { out: c }),
    ] };
  };
  X.cipher = (k, k1, k2) => {
    const d = D.cipher(k), xor = S.bytes.xor;
    return { name: 'DESX', n: 8, encrypt: (b) => xor(d.encrypt(xor(b, k1)), k2), decrypt: (b) => xor(d.decrypt(xor(b, k2)), k1) };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
