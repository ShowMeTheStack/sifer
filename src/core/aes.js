// AES-128: the key expansion and encryption, with every intermediate state kept. The state is 16 bytes in column
// order, as the standard lays it out: byte s[r + 4c] is row r, column c.
//   S.AES.expandKey(key)        -> {w: [44 words], trace}   each word a 4-byte array
//   S.AES.encrypt(block, key)   -> {out, rounds: [{round, start, sub, shift, mix, key, end}], trace}
//   (keys of 24 and 32 bytes are handed to S.AES.expand / encryptBlock of sym-aes.js, which also has decryption)
//   S.AES.subBytes / shiftRows / mixColumns / addRoundKey(state[, k]) -> a new state
//   S.AES.mixColumn(col)        -> {out, trace}  one column as the matrix times a vector over GF(2^8)
(function (S) {
  'use strict';
  const { h2, hex, step } = S.bytes;
  const G = S.gf256;
  const A = (S.AES = {});
  const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
  A.RCON = RCON;
  A.MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
  const wh = (w) => hex(w);

  /** the g-function of the key expansion on a word, with its three stages */
  A.g = (w, i) => {
    const rot = [w[1], w[2], w[3], w[0]];
    const sub = rot.map((b) => G.SBOX[b]);
    const rc = RCON[i / 4 - 1];
    const out = [sub[0] ^ rc, sub[1], sub[2], sub[3]];
    return { rot, sub, rc, out };
  };
  A.expandKey = (key) => {
    // 24- and 32-byte keys go to the general key expansion of sym-aes.js
    if (key.length !== 16) { if (A.expand && (key.length === 24 || key.length === 32)) return A.expand(key); throw new Error('AES needs a 16-, 24- or 32-byte key'); }
    const w = [], trace = [];
    for (let i = 0; i < 4; i++) { w.push(Array.from(key.slice(4 * i, 4 * i + 4))); trace.push(step('key-word', `w${i} = ${wh(w[i])}, straight from the key.`, { i, w: w[i] })); }
    for (let i = 4; i < 44; i++) {
      const prev = w[i - 1], back = w[i - 4];
      if (i % 4 === 0) {
        const g = A.g(prev, i);
        const nw = back.map((b, k) => b ^ g.out[k]);
        trace.push(step('g', `g(w${i - 1}): rotate ${wh(prev)} to ${wh(g.rot)}, substitute to ${wh(g.sub)}, XOR the round constant ${h2(g.rc)} to get ${wh(g.out)}.`, { i, prev, rot: g.rot, sub: g.sub, rc: g.rc, gout: g.out }));
        trace.push(step('word', `w${i} = w${i - 4} ⊕ g(w${i - 1}) = ${wh(back)} ⊕ ${wh(g.out)} = ${wh(nw)}.`, { i, a: back, b: g.out, w: nw, viaG: true }));
        w.push(nw);
      } else {
        const nw = back.map((b, k) => b ^ prev[k]);
        trace.push(step('word', `w${i} = w${i - 4} ⊕ w${i - 1} = ${wh(back)} ⊕ ${wh(prev)} = ${wh(nw)}.`, { i, a: back, b: prev, w: nw, viaG: false }));
        w.push(nw);
      }
    }
    return { w, trace };
  };
  A.roundKey = (w, r) => w.slice(4 * r, 4 * r + 4).flat();

  A.subBytes = (s) => s.map((b) => G.SBOX[b]);
  /** row r moves r places to the left */
  A.shiftRows = (s) => { const o = new Array(16); for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) o[r + 4 * c] = s[r + 4 * ((c + r) % 4)]; return o; };
  A.mixColumn = (col) => {
    const trace = [], out = [];
    for (let r = 0; r < 4; r++) {
      const terms = A.MIX[r].map((m, k) => G.fastMul(m, col[k]));
      const v = terms.reduce((x, y) => x ^ y, 0);
      out.push(v);
      trace.push(step('mix-row', `Row ${r}: ${A.MIX[r].map((m, k) => `${h2(m)}·${h2(col[k])}`).join(' ⊕ ')} = ${terms.map(h2).join(' ⊕ ')} = ${h2(v)}.`, { r, coef: A.MIX[r], terms, v }));
    }
    return { out, trace };
  };
  A.mixColumns = (s) => { const o = []; for (let c = 0; c < 4; c++) o.push(...A.mixColumn(s.slice(4 * c, 4 * c + 4)).out); return o; };
  A.addRoundKey = (s, k) => s.map((b, i) => b ^ k[i]);

  A.encrypt = (block, key, opts) => {
    if (key.length !== 16 && A.encryptBlock) return A.encryptBlock(block, key);
    const { w } = A.expandKey(key);
    let s = Array.from(block);
    const rounds = [], trace = [];
    const k0 = A.roundKey(w, 0);
    const first = A.addRoundKey(s, k0);
    rounds.push({ round: 0, start: s, key: k0, end: first });
    trace.push(step('add-key', `Round 0: the plaintext ${hex(s)} is XORed with the key, giving ${hex(first)}.`, { round: 0, state: first }));
    s = first;
    for (let r = 1; r <= 10; r++) {
      const sub = A.subBytes(s), shift = A.shiftRows(sub), mix = r < 10 ? A.mixColumns(shift) : null, k = A.roundKey(w, r);
      const end = A.addRoundKey(mix || shift, k);
      rounds.push({ round: r, start: s, sub, shift, mix, key: k, end });
      trace.push(step('round', `Round ${r}: SubBytes, ShiftRows, ${mix ? 'MixColumns, ' : ''}AddRoundKey give ${hex(end)}.`, { round: r, state: end }));
      s = end;
    }
    return { out: Uint8Array.from(s), rounds, trace, w };
  };
  /** the four rows of a state as text, for narration */
  A.rows = (s) => [0, 1, 2, 3].map((r) => [0, 1, 2, 3].map((c) => h2(s[r + 4 * c])).join(' '));
})(globalThis.Sifer = globalThis.Sifer || {});
