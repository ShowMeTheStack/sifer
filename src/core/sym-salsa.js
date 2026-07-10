// Salsa20, the parent of ChaCha: a 4×4 state of 32-bit words, constants on the diagonal, key words around them,
// nonce and a 64-bit block counter in the middle. Its quarter-round adds two words, rotates the sum and XORs it into
// a third (b ^= (a + d) <<< 7, c ^= (b + a) <<< 9, d ^= (c + b) <<< 13, a ^= (d + c) <<< 18); a double round works
// on the columns, then the rows; ten double rounds and the input added back give 64 bytes of keystream.
//   S.Salsa.qr(a, b, c, d) -> {out, trace}
//   S.Salsa.state(key16or32, nonce8, counter) -> 16 words
//   S.Salsa.block(key, nonce8, counter) -> {state, rounds: [16 words after each double round], words, out (64 bytes), trace}
//   S.Salsa.encrypt(key, nonce8, data[, counter]) -> Uint8Array
(function (S) {
  'use strict';
  const Sa = (S.Salsa = {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  const h8 = (v) => (v >>> 0).toString(16).padStart(8, '0');
  Sa.SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]; // "expand 32-byte k"
  Sa.TAU = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574]; // "expand 16-byte k"
  Sa.STEPS = [[1, 0, 3, 7], [2, 1, 0, 9], [3, 2, 1, 13], [0, 3, 2, 18]]; // target ^= (x + y) <<< r
  const N = 'abcd';
  Sa.qr = (a, b, c, d) => {
    const v = [a >>> 0, b >>> 0, c >>> 0, d >>> 0], trace = [];
    for (const [t, x, y, r] of Sa.STEPS) {
      const before = v[t], sum = (v[x] + v[y]) >>> 0, rot = rotl(sum, r);
      v[t] = (v[t] ^ rot) >>> 0;
      trace.push(step('salsa-qr', `${N[t]} ^= (${N[x]} + ${N[y]}) <<< ${r}: ${h8(v[x])} + ${h8(v[y])} = ${h8(sum)}, rotated ${h8(rot)}, so ${N[t]} = ${h8(before)} ⊕ ${h8(rot)} = ${h8(v[t])}.`, { t, x, y, r, sum, rot, before, after: v[t], words: v.slice() }));
    }
    return { out: v, trace };
  };
  const le = (b, i) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
  Sa.state = (key, nonce, counter = 0) => {
    const k32 = key.length === 32, C = k32 ? Sa.SIGMA : Sa.TAU, k2 = k32 ? key.subarray(16) : key;
    const ctr = BigInt(counter);
    return [C[0], le(key, 0), le(key, 4), le(key, 8), le(key, 12), C[1], le(nonce, 0), le(nonce, 4),
      Number(ctr & 0xffffffffn), Number((ctr >> 32n) & 0xffffffffn), C[2], le(k2, 0), le(k2, 4), le(k2, 8), le(k2, 12), C[3]];
  };
  Sa.COLUMNS = [[0, 4, 8, 12], [5, 9, 13, 1], [10, 14, 2, 6], [15, 3, 7, 11]];
  Sa.ROWS = [[0, 1, 2, 3], [5, 6, 7, 4], [10, 11, 8, 9], [15, 12, 13, 14]];
  const QR = (x, q) => {
    const [a, b, c, d] = q;
    x[b] ^= rotl((x[a] + x[d]) >>> 0, 7); x[b] >>>= 0;
    x[c] ^= rotl((x[b] + x[a]) >>> 0, 9); x[c] >>>= 0;
    x[d] ^= rotl((x[c] + x[b]) >>> 0, 13); x[d] >>>= 0;
    x[a] ^= rotl((x[d] + x[c]) >>> 0, 18); x[a] >>>= 0;
  };
  Sa.core = (st, keepRounds) => {
    const x = st.slice(), rounds = [];
    for (let i = 0; i < 10; i++) { for (const q of Sa.COLUMNS) QR(x, q); for (const q of Sa.ROWS) QR(x, q); if (keepRounds) rounds.push(x.slice()); }
    return { x, rounds };
  };
  Sa.block = (key, nonce, counter = 0) => {
    const st = Sa.state(key, nonce, counter), { x, rounds } = Sa.core(st, true);
    const words = x.map((v, i) => (v + st[i]) >>> 0), out = new Uint8Array(64);
    words.forEach((w, i) => { out[4 * i] = w & 255; out[4 * i + 1] = (w >>> 8) & 255; out[4 * i + 2] = (w >>> 16) & 255; out[4 * i + 3] = w >>> 24; });
    const trace = [
      step('salsa-state', `The state: constants ${[0, 5, 10, 15].map((i) => h8(st[i])).join(' ')} on the diagonal, the key around them, the nonce ${h8(st[6])} ${h8(st[7])} and the counter ${h8(st[8])} ${h8(st[9])} in the middle.`, { state: st }),
      ...rounds.map((r, i) => step('salsa-double', `Double round ${i + 1} (columns, then rows): word 0 is now ${h8(r[0])}.`, { round: i + 1, words: r })),
      step('salsa-add', `Adding the input state back word by word gives the keystream block, first word ${h8(words[0])}.`, { words }),
    ];
    return { state: st, rounds, words, out, trace };
  };
  Sa.encrypt = (key, nonce, data, counter = 0) => {
    const out = new Uint8Array(data.length);
    for (let i = 0, blk = 0; i < data.length; i += 64, blk++) {
      const st = Sa.state(key, nonce, BigInt(counter) + BigInt(blk)), { x } = Sa.core(st, false);
      for (let j = 0; j < 64 && i + j < data.length; j++) { const w = (x[j >> 2] + st[j >> 2]) >>> 0; out[i + j] = data[i + j] ^ ((w >>> (8 * (j & 3))) & 255); }
    }
    return out;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
