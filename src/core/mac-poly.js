// Poly1305 and the ChaCha20-Poly1305 AEAD of RFC 8439. Poly1305 evaluates a polynomial in a secret point r modulo
// the prime 2^130 − 5: each 16-byte chunk (with a 1 appended) is added to an accumulator, which is then multiplied
// by r; the secret s is added at the end. r is "clamped" (22 bits cleared) so that the arithmetic stays fast.
//   S.MAC.poly1305(key32, msg[, {trace}]) -> tag | {tag, r, s, steps: [{i, n, acc}], trace}
//   S.MAC.aead.seal(key32, nonce12, plaintext, aad[, {trace}]) -> {ciphertext, tag[, otk, macData, trace]}
//   S.MAC.aead.open(key32, nonce12, ciphertext, tag, aad[, {trace}]) -> {ok, plaintext (null if !ok)[, trace]}
(function (S) {
  'use strict';
  const H = S.Hash, Mc = (S.MAC = S.MAC || {});
  const { step, hex, utf8, concat } = H;
  const P = (1n << 130n) - 5n;
  const le = (b) => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };
  const toLE = (v, n) => { const o = new Uint8Array(n); for (let i = 0; i < n; i++) { o[i] = Number(v & 255n); v >>= 8n; } return o; };
  const h = (v, d = 33) => v.toString(16).padStart(d, '0');
  Mc.POLY_P = P;
  Mc.CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  Mc.poly1305 = (key, msg, opt = {}) => {
    msg = utf8(msg);
    const rRaw = le(key.subarray(0, 16)), r = rRaw & Mc.CLAMP, s = le(key.subarray(16, 32));
    const traced = !!opt.trace, trace = traced ? [] : null, steps = traced ? [] : null;
    if (traced) {
      trace.push(step('clamp', `r is the first 16 key bytes read little-endian, ${h(rRaw, 32)}, with the top 4 bits of bytes 3, 7, 11, 15 and the low 2 bits of bytes 4, 8, 12 cleared: r = ${h(r, 32)}.`, { rRaw, r }));
      trace.push(step('s', `s is the other 16 bytes: ${h(s, 32)}. It is added only at the very end.`, { s }));
    }
    let acc = 0n;
    for (let i = 0; i < msg.length; i += 16) {
      const chunk = msg.subarray(i, i + 16), n = le(chunk) + (1n << BigInt(8 * chunk.length));
      const sum = acc + n;
      acc = (sum * r) % P;
      if (traced) {
        steps.push({ i: i / 16, n, sum, acc });
        trace.push(step('chunk', `Chunk ${i / 16 + 1}: n = ${h(n)} (the ${chunk.length} bytes with 01 appended); acc = (acc + n)·r mod 2¹³⁰−5 = ${h(acc)}.`, { i: i / 16, n, acc }));
      }
    }
    const tag = toLE((acc + s) & ((1n << 128n) - 1n), 16);
    if (!traced) return tag;
    trace.push(step('tag', `tag = (acc + s) mod 2¹²⁸, written little-endian: ${hex(tag)}.`, { tag }));
    return { tag, r, s, steps, trace };
  };

  // ---- ChaCha20-Poly1305 (RFC 8439, section 2.8)
  const A = (Mc.aead = {});
  const keystreamXor = (key, counter, nonce, data) => {
    if (S.ChaCha.encrypt) return S.ChaCha.encrypt(key, counter, nonce, data);
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 64) {
      const ks = S.ChaCha.block(key, counter + i / 64, nonce).out;
      for (let j = 0; j < 64 && i + j < data.length; j++) out[i + j] = data[i + j] ^ ks[j];
    }
    return out;
  };
  const pad16 = (n) => new Uint8Array((16 - (n % 16)) % 16);
  A.macData = (aad, ct) => concat(aad, pad16(aad.length), ct, pad16(ct.length), toLE(BigInt(aad.length), 8), toLE(BigInt(ct.length), 8));
  A.otk = (key, nonce) => S.ChaCha.block(key, 0, nonce).out.slice(0, 32);
  A.seal = (key, nonce, plaintext, aad = new Uint8Array(0), opt = {}) => {
    plaintext = utf8(plaintext); aad = utf8(aad);
    const otk = A.otk(key, nonce), ciphertext = keystreamXor(key, 1, nonce, plaintext);
    const macData = A.macData(aad, ciphertext), p = Mc.poly1305(otk, macData, opt);
    if (!opt.trace) return { ciphertext, tag: p };
    const trace = [
      step('otk', `ChaCha20 block 0 under the key and nonce gives the one-time Poly1305 key ${hex(otk)}: a fresh r and s for every message.`, { otk }),
      step('encrypt', `Blocks 1, 2, … give the keystream; ${plaintext.length} bytes of plaintext XOR it to the ciphertext ${H.short(ciphertext, 24)}.`, { ciphertext }),
      step('macdata', `Poly1305 runs over AAD ‖ zero pad ‖ ciphertext ‖ zero pad ‖ the two lengths as 8-byte little-endian numbers (${macData.length} bytes).`, { macData }),
      ...p.trace,
    ];
    return { ciphertext, tag: p.tag, otk, macData, trace };
  };
  A.open = (key, nonce, ciphertext, tag, aad = new Uint8Array(0), opt = {}) => {
    aad = utf8(aad);
    const otk = A.otk(key, nonce), want = Mc.poly1305(otk, A.macData(aad, ciphertext));
    const ok = Mc.equal(want, tag);
    const plaintext = ok ? keystreamXor(key, 1, nonce, ciphertext) : null;
    if (!opt.trace) return { ok, plaintext };
    return { ok, plaintext, trace: [step(ok ? 'verify' : 'reject', ok ? `The recomputed tag ${hex(want)} matches (compared in constant time), so the ciphertext is decrypted.` : `The recomputed tag ${hex(want)} differs from ${hex(tag)}: the message is rejected before anything is decrypted.`, { ok, want })] };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
