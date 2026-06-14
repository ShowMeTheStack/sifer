// Bytes and words: hex in and out, XOR of byte arrays, 32-bit arithmetic, and the trace step every engine returns.
// A trace is a list of steps {kind, say, ...data}: kind names the operation, say is one plain sentence with the
// actual values, and the rest is what a picture needs to draw the step.
(function (S) {
  'use strict';
  const B = (S.bytes = {});
  /** one byte as two hex digits */
  B.h2 = (v) => (v & 255).toString(16).padStart(2, '0');
  /** a 32-bit word as eight hex digits */
  B.h8 = (v) => (v >>> 0).toString(16).padStart(8, '0');
  /** a byte array as hex, optionally with a separator between bytes */
  B.hex = (a, sep) => Array.from(a, B.h2).join(sep || '');
  /** hex (spaces allowed) to a byte array */
  B.fromHex = (s) => {
    const t = String(s).replace(/[^0-9a-f]/gi, '');
    if (t.length % 2) throw new Error('odd number of hex digits');
    const out = new Uint8Array(t.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(t.substr(2 * i, 2), 16);
    return out;
  };
  /** text to bytes (UTF-8) */
  B.utf8 = (s) => new TextEncoder().encode(s);
  B.xor = (a, b) => { const out = new Uint8Array(a.length); for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i]; return out; };
  B.eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  /** the number of bits that differ between two byte arrays */
  B.diffBits = (a, b) => { let n = 0; for (let i = 0; i < a.length; i++) { let x = a[i] ^ b[i]; while (x) { n += x & 1; x >>= 1; } } return n; };
  B.popcount = (x) => { let n = 0; x >>>= 0; while (x) { n += x & 1; x >>>= 1; } return n; };
  B.rotl32 = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  B.rotr32 = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
  B.add32 = (...xs) => xs.reduce((a, b) => (a + b) >>> 0, 0);
  /** a step of a trace */
  B.step = (kind, say, data) => Object.assign({ kind, say }, data || {});
})(globalThis.Sifer = globalThis.Sifer || {});
