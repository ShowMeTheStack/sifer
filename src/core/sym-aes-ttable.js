// AES on T-tables, as fast software does it: SubBytes, ShiftRows and MixColumns of a round fold into four lookups
// of 32-bit words per column, Te0[a] ⊕ Te1[b] ⊕ Te2[c] ⊕ Te3[d] ⊕ round key. The index of every lookup is a state
// byte, so which cache lines a round touches depends on the key: that is the leak cache-timing attacks use.
//   S.AES.tt.tables()             -> {Te: [4 × Uint32Array(256)], Td: [...], Sb, Si}
//   S.AES.tt.schedule(key)        -> {Nr, ek: Uint32Array, dk: Uint32Array}  dk for the equivalent inverse cipher
//   S.AES.tt.encrypt(block, key)  -> {out, lookups: [{round, col, table, index, line}], trace}
//   S.AES.tt.encryptFast(T, block) / decryptFast(T, block) -> Uint8Array (16)
(function (S) {
  'use strict';
  const A = (S.AES = S.AES || {});
  const tt = (A.tt = {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  let TB = null;
  const rotr8 = (x) => ((x >>> 8) | (x << 24)) >>> 0;
  tt.tables = () => {
    if (TB) return TB;
    const G = S.gf256, m = G.fastMul;
    const Te = [0, 1, 2, 3].map(() => new Uint32Array(256)), Td = [0, 1, 2, 3].map(() => new Uint32Array(256));
    for (let x = 0; x < 256; x++) {
      const s = G.SBOX[x], si = G.INV_SBOX[x];
      let e = ((m(2, s) << 24) | (s << 16) | (s << 8) | m(3, s)) >>> 0;
      let d = ((m(14, si) << 24) | (m(9, si) << 16) | (m(13, si) << 8) | m(11, si)) >>> 0;
      for (let k = 0; k < 4; k++) { Te[k][x] = e; Td[k][x] = d; e = rotr8(e); d = rotr8(d); }
    }
    TB = { Te, Td, Sb: G.SBOX, Si: G.INV_SBOX };
    return TB;
  };
  const word = (b, i) => ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
  tt.schedule = (key) => {
    const { w, Nr } = A.expand(key), { Td } = tt.tables(), Sb = S.gf256.SBOX;
    const ek = new Uint32Array(4 * (Nr + 1));
    w.forEach((x, i) => { ek[i] = word(x, 0); });
    // the equivalent inverse cipher uses the round keys in reverse, with InvMixColumns applied to the inner ones
    const dk = new Uint32Array(ek.length);
    for (let r = 0; r <= Nr; r++) for (let c = 0; c < 4; c++) {
      const v = ek[4 * (Nr - r) + c];
      dk[4 * r + c] = r === 0 || r === Nr ? v : (Td[0][Sb[v >>> 24]] ^ Td[1][Sb[(v >>> 16) & 255]] ^ Td[2][Sb[(v >>> 8) & 255]] ^ Td[3][Sb[v & 255]]) >>> 0;
    }
    return { Nr, ek, dk };
  };
  const out16 = (s) => { const o = new Uint8Array(16); for (let c = 0; c < 4; c++) { o[4 * c] = s[c] >>> 24; o[4 * c + 1] = (s[c] >>> 16) & 255; o[4 * c + 2] = (s[c] >>> 8) & 255; o[4 * c + 3] = s[c] & 255; } return o; };
  const run = (T, block, dec, rec) => {
    const { Te, Td, Sb, Si } = tt.tables(), K = dec ? T.dk : T.ek, Tb = dec ? Td : Te, Lb = dec ? Si : Sb, Nr = T.Nr;
    // column c takes row r from column c + r (encryption) or c - r (decryption)
    const src = dec ? [0, 3, 2, 1] : [0, 1, 2, 3];
    let s = [0, 1, 2, 3].map((c) => (word(block, 4 * c) ^ K[c]) >>> 0);
    for (let r = 1; r <= Nr; r++) {
      const n = [0, 0, 0, 0];
      for (let c = 0; c < 4; c++) {
        let v = K[4 * r + c];
        for (let k = 0; k < 4; k++) {
          const x = (s[(c + src[k]) & 3] >>> (24 - 8 * k)) & 255;
          if (r < Nr) v ^= Tb[k][x];
          else v ^= Lb[x] << (24 - 8 * k);
          if (rec) rec.push({ round: r, col: c, table: r < Nr ? (dec ? 'Td' : 'Te') + k : dec ? 'Si' : 'S', index: x, line: x >> 4 });
        }
        n[c] = v >>> 0;
      }
      s = n;
    }
    return out16(s);
  };
  tt.encryptFast = (T, block) => run(T, block, false, null);
  tt.decryptFast = (T, block) => run(T, block, true, null);
  /** encryption with every table lookup recorded; a cache line holds 16 four-byte entries */
  tt.encrypt = (block, key) => {
    const T = tt.schedule(key), lookups = [], out = run(T, block, false, lookups), h = S.bytes.hex, h2 = S.bytes.h2, trace = [];
    for (let r = 1; r <= T.Nr; r++) {
      const L = lookups.filter((l) => l.round === r);
      const lines = [...new Set(L.map((l) => l.table + ':' + l.line))].length;
      trace.push(step('tt-round', `Round ${r}: ${r < T.Nr ? 'sixteen lookups in Te0…Te3' : 'the last round looks up the plain S-box'} at indices ${L.map((l) => h2(l.index)).join(' ')}, touching ${lines} cache lines.`, { round: r, lookups: L }));
    }
    const firstIdx = lookups.filter((l) => l.round === 1).map((l) => l.index);
    trace.unshift(step('tt-leak', `The first-round indices are plaintext ⊕ key bytes, so the cache lines they touch (upper four bits ${firstIdx.map((x) => (x >> 4).toString(16)).join('')}) reveal the upper half of each key byte to an observer who knows the plaintext.`, { indices: firstIdx }));
    trace.push(step('tt-out', `The ciphertext is ${h(out)}.`, { out }));
    return { out, lookups, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
