// GF(2^8), the field of AES: bytes as polynomials over GF(2) modulo m(x) = x^8 + x^4 + x^3 + x + 1 (0x11b).
// Addition is XOR; xtime multiplies by x; mul multiplies any two bytes by shift-and-add; inv finds the inverse
// (0 maps to 0, as AES defines it); affine is the bit mixing that follows the inverse in the S-box.
(function (S) {
  'use strict';
  const { h2, step } = S.bytes;
  const G = (S.gf256 = {});
  G.MOD = 0x11b;
  G.xtime = (a) => ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 255;
  /** a times b; with a trace of the shift-and-add when asked */
  G.mul = (a, b, trace) => {
    let r = 0, x = a;
    for (let i = 0; i < 8; i++) {
      if ((b >> i) & 1) { const was = r; r ^= x; if (trace) trace.push(step('add', `Bit ${i} of ${h2(b)} is 1, so add x^${i}·${h2(a)} = ${h2(x)}: ${h2(was)} ⊕ ${h2(x)} = ${h2(r)}.`, { i, term: x, acc: r })); }
      const nx = G.xtime(x);
      if (trace && i < 7 && (b >> (i + 1))) trace.push(step('xtime', `xtime(${h2(x)}) = ${h2(nx)}${x & 0x80 ? ' (the top bit fell off, so 1b was XORed in)' : ''}.`, { i, from: x, to: nx, reduced: !!(x & 0x80) }));
      x = nx;
    }
    return r;
  };
  // log and antilog tables with the generator 03
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x = x ^ G.xtime(x); }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  G.fastMul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
  G.inv = (a) => (a ? EXP[255 - LOG[a]] : 0);
  /** the polynomial of a byte, as text: 0x53 -> x^6 + x^4 + x + 1 */
  G.poly = (a) => { const t = []; for (let i = 7; i >= 0; i--) if ((a >> i) & 1) t.push(i === 0 ? '1' : i === 1 ? 'x' : 'x' + '⁰¹²³⁴⁵⁶⁷'[i]); return t.join(' + ') || '0'; };
  /** the affine map of the S-box: b'_i = b_i ⊕ b_(i+4) ⊕ b_(i+5) ⊕ b_(i+6) ⊕ b_(i+7) ⊕ c_i, with c = 63 */
  G.affine = (b) => {
    let r = 0;
    for (let i = 0; i < 8; i++) {
      const bit = ((b >> i) ^ (b >> ((i + 4) % 8)) ^ (b >> ((i + 5) % 8)) ^ (b >> ((i + 6) % 8)) ^ (b >> ((i + 7) % 8)) ^ (0x63 >> i)) & 1;
      r |= bit << i;
    }
    return r;
  };
  G.SBOX = new Uint8Array(256);
  G.INV_SBOX = new Uint8Array(256);
  for (let a = 0; a < 256; a++) { const s = G.affine(G.inv(a)); G.SBOX[a] = s; G.INV_SBOX[s] = a; }
  /** one byte through the S-box, step by step: the inverse, then each bit of the affine map */
  G.subByteTrace = (a) => {
    const v = G.inv(a), out = G.SBOX[a];
    const trace = [step('inverse', a ? `The inverse of ${h2(a)} in GF(2^8) is ${h2(v)}, since ${h2(a)} · ${h2(v)} = ${h2(G.fastMul(a, v))}.` : 'The byte 00 has no inverse; AES maps it to 00.', { a, inv: v })];
    const bits = [];
    for (let i = 0; i < 8; i++) {
      const src = [i, (i + 4) % 8, (i + 5) % 8, (i + 6) % 8, (i + 7) % 8].map((k) => (v >> k) & 1), c = (0x63 >> i) & 1;
      const bit = src.reduce((x, y) => x ^ y, c);
      bits.push({ i, src, c, bit });
    }
    trace.push(step('affine', `The affine map turns ${h2(v)} into ${h2(out)}: each output bit is the XOR of five input bits and a bit of 63.`, { inv: v, out, bits }));
    return { out, inv: v, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
