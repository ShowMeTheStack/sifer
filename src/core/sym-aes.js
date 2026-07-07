// AES at every key size, both directions, traced. Extends S.AES (FIPS 197): 128-, 192- and 256-bit keys, the
// inverse cipher with InvShiftRows, InvSubBytes and InvMixColumns, and the S-box and its inverse derived per byte.
//   S.AES.expand(key)              -> {w: [4(Nr+1) words], Nk, Nr, trace}   key of 16, 24 or 32 bytes
//   S.AES.encryptBlock(block, key) -> {out, rounds: [{round, start, sub, shift, mix, key, end}], trace}
//   S.AES.decryptBlock(block, key) -> {out, rounds: [{round, start, shift, sub, key, added, mix, end}], trace}
//   S.AES.invSubBytes / invShiftRows / invMixColumns(state) -> a new state; invMixColumn(col) -> {out, trace}
//   S.AES.sboxDerive(a) -> {out, inv, trace}          inverse in GF(2^8), then the affine map, bit by bit
//   S.AES.invSboxDerive(s) -> {out, pre, trace}       the inverse affine map, then the inverse in GF(2^8)
//   S.AES.cipher(key) -> {name, n: 16, encrypt(block), decrypt(block)}   fast (T-tables), for the modes
(function (S) {
  'use strict';
  const A = (S.AES = S.AES || {});
  const by = () => S.bytes, G = () => S.gf256;
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const hex = (a) => by().hex(a), h2 = (v) => by().h2(v);
  A.NR = { 16: 10, 24: 12, 32: 14 };
  A.INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]];
  const RC = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

  A.expand = (key) => {
    const Nk = key.length / 4, Nr = A.NR[key.length];
    if (!Nr) throw new Error('AES needs a key of 16, 24 or 32 bytes');
    const SB = G().SBOX, w = [], trace = [];
    for (let i = 0; i < Nk; i++) { w.push(Array.from(key.slice(4 * i, 4 * i + 4))); trace.push(step('key-word', `w${i} = ${hex(w[i])}, straight from the key.`, { i, w: w[i] })); }
    for (let i = Nk; i < 4 * (Nr + 1); i++) {
      const prev = w[i - 1], back = w[i - Nk];
      let t = prev, how = 'plain';
      if (i % Nk === 0) {
        const rot = [prev[1], prev[2], prev[3], prev[0]], sub = rot.map((b) => SB[b]), rc = RC[i / Nk - 1];
        t = [sub[0] ^ rc, sub[1], sub[2], sub[3]]; how = 'g';
        trace.push(step('g', `g(w${i - 1}): rotate ${hex(prev)} to ${hex(rot)}, substitute to ${hex(sub)}, XOR the round constant ${h2(rc)} to get ${hex(t)}.`, { i, prev, rot, sub, rc, gout: t }));
      } else if (Nk > 6 && i % Nk === 4) {
        t = prev.map((b) => SB[b]); how = 'sub';
        trace.push(step('subword', `AES-256 also substitutes the middle word: SubWord(w${i - 1}) = SubWord(${hex(prev)}) = ${hex(t)}.`, { i, prev, sub: t }));
      }
      const nw = back.map((b, k) => b ^ t[k]);
      const mid = how === 'g' ? `g(w${i - 1})` : how === 'sub' ? `SubWord(w${i - 1})` : `w${i - 1}`;
      trace.push(step('word', `w${i} = w${i - Nk} ⊕ ${mid} = ${hex(back)} ⊕ ${hex(t)} = ${hex(nw)}.`, { i, a: back, b: t, w: nw, how, viaG: how === 'g' }));
      w.push(nw);
    }
    return { w, Nk, Nr, trace };
  };
  const rk = (w, r) => w.slice(4 * r, 4 * r + 4).flat();
  const xs = (s, k) => s.map((b, i) => b ^ k[i]);

  A.invSubBytes = (s) => s.map((b) => G().INV_SBOX[b]);
  /** row r moves r places to the right */
  A.invShiftRows = (s) => { const o = new Array(16); for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) o[r + 4 * ((c + r) % 4)] = s[r + 4 * c]; return o; };
  A.invMixColumn = (col) => {
    const trace = [], out = [], mul = G().fastMul;
    for (let r = 0; r < 4; r++) {
      const terms = A.INV_MIX[r].map((m, k) => mul(m, col[k])), v = terms.reduce((x, y) => x ^ y, 0);
      out.push(v);
      trace.push(step('mix-row', `Row ${r}: ${A.INV_MIX[r].map((m, k) => `${h2(m)}·${h2(col[k])}`).join(' ⊕ ')} = ${terms.map(h2).join(' ⊕ ')} = ${h2(v)}.`, { r, coef: A.INV_MIX[r], terms, v }));
    }
    return { out, trace };
  };
  A.invMixColumns = (s) => { const o = []; for (let c = 0; c < 4; c++) o.push(...A.invMixColumn(s.slice(4 * c, 4 * c + 4)).out); return o; };

  const sizeName = (key) => 'AES-' + key.length * 8;
  A.encryptBlock = (block, key) => {
    const { w, Nr } = A.expand(key);
    let s = Array.from(block);
    const rounds = [], trace = [];
    const k0 = rk(w, 0), first = xs(s, k0);
    rounds.push({ round: 0, start: s, key: k0, end: first });
    trace.push(step('add-key', `${sizeName(key)}, round 0: the plaintext ${hex(s)} XOR the first round key ${hex(k0)} gives ${hex(first)}.`, { round: 0, state: first, key: k0 }));
    s = first;
    for (let r = 1; r <= Nr; r++) {
      const sub = A.subBytes(s), shift = A.shiftRows(sub), mix = r < Nr ? A.mixColumns(shift) : null, k = rk(w, r), end = xs(mix || shift, k);
      rounds.push({ round: r, start: s, sub, shift, mix, key: k, end });
      trace.push(step('round', `Round ${r}: SubBytes gives ${hex(sub)}, ShiftRows ${hex(shift)}, ${mix ? `MixColumns ${hex(mix)}, ` : 'no MixColumns in the last round, '}and the round key ${hex(k)} gives ${hex(end)}.`, { round: r, sub, shift, mix, key: k, state: end }));
      s = end;
    }
    return { out: Uint8Array.from(s), rounds, trace, w, Nr };
  };
  /** the inverse cipher: the rounds in reverse order, each step undone */
  A.decryptBlock = (block, key) => {
    const { w, Nr } = A.expand(key);
    let s = Array.from(block);
    const rounds = [], trace = [];
    const kN = rk(w, Nr), first = xs(s, kN);
    rounds.push({ round: Nr, start: s, key: kN, end: first });
    trace.push(step('add-key', `Decryption starts with the last round key: ${hex(s)} ⊕ ${hex(kN)} = ${hex(first)}.`, { round: Nr, state: first, key: kN }));
    s = first;
    for (let r = Nr - 1; r >= 0; r--) {
      const shift = A.invShiftRows(s), sub = A.invSubBytes(shift), k = rk(w, r), added = xs(sub, k), mix = r > 0 ? A.invMixColumns(added) : null, end = mix || added;
      rounds.push({ round: r, start: s, shift, sub, key: k, added, mix, end });
      trace.push(step('inv-round', `Undo round ${r + 1}: InvShiftRows gives ${hex(shift)}, InvSubBytes ${hex(sub)}, the round key ${hex(k)} gives ${hex(added)}${mix ? `, InvMixColumns ${hex(mix)}` : ', which is the plaintext'}.`, { round: r, shift, sub, key: k, added, mix, state: end }));
      s = end;
    }
    return { out: Uint8Array.from(s), rounds, trace, w, Nr };
  };

  A.sboxDerive = (a) => G().subByteTrace(a);
  /** the inverse affine map: b_i = s_(i+2) ⊕ s_(i+5) ⊕ s_(i+7) ⊕ d_i with d = 05 */
  A.invAffine = (s) => { let r = 0; for (let i = 0; i < 8; i++) r |= (((s >> ((i + 2) % 8)) ^ (s >> ((i + 5) % 8)) ^ (s >> ((i + 7) % 8)) ^ (0x05 >> i)) & 1) << i; return r; };
  A.invSboxDerive = (s) => {
    const pre = A.invAffine(s), out = G().inv(pre), bits = [];
    for (let i = 0; i < 8; i++) {
      const src = [(i + 2) % 8, (i + 5) % 8, (i + 7) % 8].map((k) => (s >> k) & 1), d = (0x05 >> i) & 1;
      bits.push({ i, src, d, bit: src.reduce((x, y) => x ^ y, d) });
    }
    const trace = [
      step('inv-affine', `The inverse affine map turns ${h2(s)} into ${h2(pre)}: each bit is the XOR of three input bits and a bit of 05.`, { s, pre, bits }),
      step('inverse', pre ? `The inverse of ${h2(pre)} in GF(2^8) is ${h2(out)}, since ${h2(pre)} · ${h2(out)} = 01.` : 'The byte 00 maps to 00.', { a: pre, inv: out }),
    ];
    return { out, pre, trace };
  };

  /** a fast block cipher object for the modes, on T-tables */
  A.cipher = (key) => {
    const T = A.tt.schedule(key);
    return { name: sizeName(key), n: 16, encrypt: (b) => A.tt.encryptFast(T, b), decrypt: (b) => A.tt.decryptFast(T, b) };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
