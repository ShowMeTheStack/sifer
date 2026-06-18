// Modes of operation over AES (any key size): CBC and CTR, each block traced with the values on every wire.
// The general modes over any block cipher (ECB, CFB, OFB, XTS, GCM, padding, stealing) are in sym-modes.js and beyond.
//   S.Modes.cbc(blocks, key, iv) -> {out: [blocks], steps: [{i, p, prev, x, c}], trace}
//   S.Modes.ctr(blocks, key, nonce16) -> {out: [blocks], steps: [{i, ctr, ks, p, c}], trace}   the last block may be short
//   S.Modes.split(bytes) -> 16-byte blocks; S.Modes.pad(bytes) -> PKCS#7-padded
(function (S) {
  'use strict';
  const { hex, xor, step } = S.bytes;
  const Mo = (S.Modes = {});
  const E = (b, k) => S.AES.encrypt(b, k).out;
  Mo.split = (bytes) => { const out = []; for (let i = 0; i < bytes.length; i += 16) out.push(bytes.slice(i, i + 16)); return out; };
  Mo.pad = (bytes) => { const n = 16 - (bytes.length % 16), out = new Uint8Array(bytes.length + n); out.set(bytes); out.fill(n, bytes.length); return out; };
  Mo.cbc = (blocks, key, iv) => {
    let prev = Uint8Array.from(iv);
    const out = [], steps = [], trace = [];
    blocks.forEach((p, i) => {
      const x = xor(p, prev), c = E(x, key);
      steps.push({ i, p, prev, x, c });
      trace.push(step('cbc', `Block ${i + 1}: ${hex(p)} ⊕ ${i ? 'C' + i : 'IV'} ${hex(prev)} = ${hex(x)}, and E_k of that is C${i + 1} = ${hex(c)}.`, { i, p, prev, x, c }));
      out.push(c); prev = c;
    });
    return { out, steps, trace };
  };
  /** the counter block for block i: the 16-byte initial block plus i, as a big-endian number */
  Mo.counter = (nonce, i) => { const c = Uint8Array.from(nonce); let carry = i; for (let k = 15; k >= 0 && carry; k--) { const v = c[k] + (carry & 255); c[k] = v & 255; carry = (carry >>> 8) + (v >> 8); } return c; };
  Mo.ctr = (blocks, key, nonce) => {
    const out = [], steps = [], trace = [];
    blocks.forEach((p, i) => {
      const ctr = Mo.counter(nonce, i), ks = E(ctr, key).slice(0, p.length), c = xor(p, ks);
      steps.push({ i, ctr, ks, p, c });
      trace.push(step('ctr', `Block ${i + 1}: E_k(${hex(ctr)}) gives the keystream ${hex(ks)}; ${hex(p)} ⊕ that = C${i + 1} = ${hex(c)}.`, { i, ctr, ks, p, c }));
      out.push(c);
    });
    return { out, steps, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
