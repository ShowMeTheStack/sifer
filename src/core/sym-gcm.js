// GCM (NIST SP 800-38D): CTR encryption with a 32-bit counter, and the tag GHASH_H(A, C) ⊕ E_k(J0), where
// H = E_k(0^128) and GHASH multiplies a running sum by H in GF(2^128), one block at a time. The field is the one in
// S.GF.gcm (src/core/nt-field.js): bits reflected, so the first bit of a block is the coefficient of x^0. The
// multiplication here runs on 32-bit words for speed; S.GF.gcm.mul gives the same products with a bit-level trace.
//   S.GCM.mul(X, Y) -> 16 bytes; S.GCM.mulTrace(X, Y) -> {out, trace} (128 bit steps, via S.GF.gcm.mul);  S.GCM.ghash(H, aad, ct[, {trace}]) -> {out, blocks, ys, trace}
//   S.GCM.encrypt(key | cipher, iv, pt[, aad, {tagLength, trace}]) -> {ct, tag, H, J0, EJ0, ghash, trace}
//   S.GCM.decrypt(key | cipher, iv, ct, tag[, aad]) -> {ok, pt (null when the tag fails), trace}
//   S.GCM.inc32(block) -> the counter block with its last 32 bits incremented
(function (S) {
  'use strict';
  const G = (S.GCM = S.GCM || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const hex = (a) => S.bytes.hex(a);
  const words = (b) => [0, 1, 2, 3].map((i) => ((b[4 * i] << 24) | (b[4 * i + 1] << 16) | (b[4 * i + 2] << 8) | b[4 * i + 3]) >>> 0);
  const bytes = (w) => { const o = new Uint8Array(16); for (let i = 0; i < 4; i++) { o[4 * i] = w[i] >>> 24; o[4 * i + 1] = (w[i] >>> 16) & 255; o[4 * i + 2] = (w[i] >>> 8) & 255; o[4 * i + 3] = w[i] & 255; } return o; };
  /** X·Y: walk the bits of X from the first; V runs through Y·x^i, folding in R = e1 00…00 when a bit falls off */
  G.mul = (X, Y) => {
    const x = words(X), v = words(Y), z = [0, 0, 0, 0];
    for (let i = 0; i < 128; i++) {
      if ((x[i >> 5] >>> (31 - (i & 31))) & 1) { z[0] ^= v[0]; z[1] ^= v[1]; z[2] ^= v[2]; z[3] ^= v[3]; }
      const lsb = v[3] & 1;
      v[3] = ((v[3] >>> 1) | (v[2] << 31)) >>> 0; v[2] = ((v[2] >>> 1) | (v[1] << 31)) >>> 0; v[1] = ((v[1] >>> 1) | (v[0] << 31)) >>> 0; v[0] >>>= 1;
      if (lsb) v[0] = (v[0] ^ 0xe1000000) >>> 0;
    }
    return bytes(z.map((w) => w >>> 0));
  };
  /** one product with every bit step, from the field of S.GF.gcm */
  G.mulTrace = (X, Y) => { const trace = []; const out = S.GF.gcm.mul(X, Y, trace); return { out, trace }; };
  const lenBlock = (a, c) => { const o = new Uint8Array(16), dv = new DataView(o.buffer); const A = a * 8, C = c * 8; dv.setUint32(0, Math.floor(A / 2 ** 32)); dv.setUint32(4, A >>> 0); dv.setUint32(8, Math.floor(C / 2 ** 32)); dv.setUint32(12, C >>> 0); return o; };
  G.lenBlock = lenBlock;
  const padBlocks = (d) => { const out = []; for (let i = 0; i < d.length; i += 16) { const b = new Uint8Array(16); b.set(d.subarray(i, i + 16)); out.push(b); } return out; };
  /** the blocks GHASH reads: A and C each padded with zeros to whole blocks, then len(A) ‖ len(C) in bits */
  G.blocks = (aad, ct) => padBlocks(aad).concat(padBlocks(ct), [lenBlock(aad.length, ct.length)]);
  G.ghash = (H, aad, ct, opts = {}) => {
    const blocks = G.blocks(aad, ct), ys = [], trace = [];
    let Y = new Uint8Array(16);
    blocks.forEach((b, i) => {
      const t = Y.map((v, k) => v ^ b[k]), nY = G.mul(t, H);
      const what = i < Math.ceil(aad.length / 16) ? 'an AAD block' : i < blocks.length - 1 ? 'a ciphertext block' : 'the length block';
      if (opts.trace !== false) trace.push(step('ghash', `Block ${i + 1} (${what}) ${hex(b)}: Y = (Y ⊕ X)·H = (${hex(Y)} ⊕ ${hex(b)})·H = ${hex(nY)}.`, { i, x: b, before: Y, sum: t, y: nY, what }));
      Y = nY; ys.push(Y);
    });
    if (opts.trace !== false) trace.push(step('ghash-poly', `So GHASH = X1·H^${blocks.length} ⊕ … ⊕ X${blocks.length}·H: a polynomial in H whose coefficients are the blocks.`, { n: blocks.length }));
    return { out: Y, blocks, ys, trace };
  };
  G.inc32 = (b) => { const o = Uint8Array.from(b); for (let k = 15; k >= 12; k--) { o[k] = (o[k] + 1) & 255; if (o[k]) break; } return o; };
  const asCipher = (k) => (k && k.encrypt ? k : S.AES.cipher(k));
  const setup = (E, iv, trace) => {
    const H = E.encrypt(new Uint8Array(16));
    let J0;
    if (iv.length === 12) { J0 = new Uint8Array(16); J0.set(iv); J0[15] = 1; }
    else J0 = G.ghash(H, new Uint8Array(0), iv, { trace: false }).out;
    if (trace) {
      trace.push(step('gcm-h', `The hash key H = E_k(0^128) = ${hex(H)}.`, { H }));
      trace.push(step('gcm-j0', iv.length === 12 ? `The 96-bit IV gives J0 = IV ‖ 00000001 = ${hex(J0)}.` : `An IV of ${iv.length} bytes is hashed: J0 = GHASH_H(IV, padded, with its length) = ${hex(J0)}.`, { J0 }));
    }
    return { H, J0 };
  };
  const gctr = (E, J0, data, trace) => {
    const out = new Uint8Array(data.length);
    let ctr = G.inc32(J0);
    for (let i = 0; i < data.length; i += 16) {
      const ks = E.encrypt(ctr), n = Math.min(16, data.length - i);
      for (let j = 0; j < n; j++) out[i + j] = data[i + j] ^ ks[j];
      if (trace) trace.push(step('gcm-ctr', `Counter ${hex(ctr)} gives keystream ${hex(ks.subarray(0, n))}; block ${i / 16 + 1} becomes ${hex(out.subarray(i, i + n))}.`, { ctr, ks: ks.subarray(0, n), i: i / 16 }));
      ctr = G.inc32(ctr);
    }
    return out;
  };
  G.encrypt = (key, iv, pt, aad = new Uint8Array(0), opts = {}) => {
    const E = asCipher(key), tr = opts.trace === false ? null : [];
    const { H, J0 } = setup(E, iv, tr), ct = gctr(E, J0, pt, tr);
    const gh = G.ghash(H, aad, ct, { trace: !!tr }), EJ0 = E.encrypt(J0), full = gh.out.map((v, i) => v ^ EJ0[i]);
    const tag = full.slice(0, opts.tagLength || 16);
    if (tr) {
      tr.push(...gh.trace);
      tr.push(step('gcm-tag', `The tag is GHASH ⊕ E_k(J0) = ${hex(gh.out)} ⊕ ${hex(EJ0)} = ${hex(full)}${tag.length < 16 ? `, cut to ${tag.length} bytes: ${hex(tag)}` : ''}.`, { ghash: gh.out, EJ0, tag }));
    }
    return { ct, tag, H, J0, EJ0, ghash: gh.out, trace: tr || [] };
  };
  G.decrypt = (key, iv, ct, tag, aad = new Uint8Array(0), opts = {}) => {
    const E = asCipher(key), tr = opts.trace === false ? null : [];
    const { H, J0 } = setup(E, iv, tr), gh = G.ghash(H, aad, ct, { trace: false }).out, EJ0 = E.encrypt(J0);
    const want = gh.map((v, i) => v ^ EJ0[i]).slice(0, tag.length);
    let diff = 0; for (let i = 0; i < tag.length; i++) diff |= want[i] ^ tag[i];
    const ok = diff === 0 && tag.length >= 4;
    if (tr) tr.push(step('gcm-verify', ok ? `The recomputed tag ${hex(want)} matches, so the ciphertext is decrypted.` : `The recomputed tag ${hex(want)} differs from ${hex(tag)}: the message is rejected and nothing is decrypted.`, { ok, want }));
    return { ok, pt: ok ? gctr(E, J0, ct, null) : null, trace: tr || [] };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
