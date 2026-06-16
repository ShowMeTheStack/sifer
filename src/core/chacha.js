// ChaCha20: the quarter-round as its twelve add, XOR and rotate steps, the 4×4 state of 32-bit words, and the
// block function (ten double rounds, then the input added back).
//   S.ChaCha.qr(a, b, c, d)                -> {out: [a, b, c, d], trace}  every step with all four words after it
//   S.ChaCha.state(key32, counter, nonce12) -> 16 words
//   S.ChaCha.block(key32, counter, nonce12) -> {state, out (64 bytes), words, rounds: [16 words after each double round]}
(function (S) {
  'use strict';
  const { h8, rotl32, step } = S.bytes;
  const C = (S.ChaCha = {});
  C.CONST = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
  // the twelve steps: [op, target, source, amount]
  C.STEPS = [['add', 0, 1], ['xor', 3, 0], ['rot', 3, 16], ['add', 2, 3], ['xor', 1, 2], ['rot', 1, 12], ['add', 0, 1], ['xor', 3, 0], ['rot', 3, 8], ['add', 2, 3], ['xor', 1, 2], ['rot', 1, 7]];
  const N = 'abcd';
  C.qr = (a, b, c, d) => {
    const v = [a >>> 0, b >>> 0, c >>> 0, d >>> 0];
    const trace = [];
    C.STEPS.forEach(([op, t, s], k) => {
      const before = v[t];
      if (op === 'add') v[t] = (v[t] + v[s]) >>> 0;
      else if (op === 'xor') v[t] = (v[t] ^ v[s]) >>> 0;
      else v[t] = rotl32(v[t], s);
      const say = op === 'add' ? `${N[t]} += ${N[s]}: ${h8(before)} + ${h8(v[s])} = ${h8(v[t])} (mod 2³²).`
        : op === 'xor' ? `${N[t]} ^= ${N[s]}: ${h8(before)} ⊕ ${h8(v[s])} = ${h8(v[t])}.`
          : `${N[t]} <<<= ${s}: ${h8(before)} rotated left by ${s} bits is ${h8(v[t])}.`;
      trace.push(step(op, say, { k, t, s: op === 'rot' ? null : s, by: op === 'rot' ? s : null, before, after: v[t], words: v.slice() }));
    });
    return { out: v, trace };
  };
  const le32 = (b, i) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
  C.state = (key, counter, nonce) => {
    const s = C.CONST.slice();
    for (let i = 0; i < 8; i++) s.push(le32(key, 4 * i));
    s.push(counter >>> 0);
    for (let i = 0; i < 3; i++) s.push(le32(nonce, 4 * i));
    return s;
  };
  const QR = (x, a, b, c, d) => { const r = C.qr(x[a], x[b], x[c], x[d]).out; x[a] = r[0]; x[b] = r[1]; x[c] = r[2]; x[d] = r[3]; };
  C.COLUMNS = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]];
  C.DIAGONALS = [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];
  C.block = (key, counter, nonce) => {
    const st = C.state(key, counter, nonce), x = st.slice(), rounds = [];
    for (let i = 0; i < 10; i++) {
      for (const q of C.COLUMNS) QR(x, ...q);
      for (const q of C.DIAGONALS) QR(x, ...q);
      rounds.push(x.slice());
    }
    const words = x.map((v, i) => (v + st[i]) >>> 0);
    const out = new Uint8Array(64);
    words.forEach((w, i) => { out[4 * i] = w & 255; out[4 * i + 1] = (w >>> 8) & 255; out[4 * i + 2] = (w >>> 16) & 255; out[4 * i + 3] = w >>> 24; });
    return { state: st, rounds, words, out, trace: [step('block', `After 20 rounds and adding the input back, the first keystream word is ${h8(words[0])}.`, {})] };
  };
  /** encrypt (or decrypt) with the keystream, block counter starting at counter */
  C.encrypt = (key, counter, nonce, data) => {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 64) {
      const ks = C.block(key, counter + i / 64, nonce).out;
      for (let j = 0; j < 64 && i + j < data.length; j++) out[i + j] = data[i + j] ^ ks[j];
    }
    return out;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
