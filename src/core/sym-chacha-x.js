// ChaCha20 as RFC 8439 uses it for encryption, block by block with the counter shown, and XChaCha20, which stretches
// the nonce to 24 bytes: HChaCha20 turns the key and the first 16 nonce bytes into a subkey (20 rounds, no final
// addition, output words 0–3 and 12–15), and the last 8 nonce bytes, after four zero bytes, form the ChaCha20 nonce.
//   S.ChaCha.encryptTrace(key32, counter, nonce12, data) -> {out, blocks: [{i, counter, ks, p, c}], trace}
//   S.ChaCha.hchacha(key32, nonce16) -> {out (32 bytes), trace}
//   S.ChaCha.xencrypt(key32, nonce24, data[, counter = 0]) -> {out, subkey, nonce12, trace}
(function (S) {
  'use strict';
  const C = (S.ChaCha = S.ChaCha || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const hex = (a) => S.bytes.hex(a), h8 = (v) => (v >>> 0).toString(16).padStart(8, '0');
  C.MAX_COUNTER = 0xffffffff;
  C.encryptTrace = (key, counter, nonce, data) => {
    const nBlocks = Math.ceil(data.length / 64);
    if (counter + nBlocks - 1 > C.MAX_COUNTER) throw new Error('the 32-bit block counter would wrap around: at most 2^32 blocks (256 GiB) per nonce');
    const out = new Uint8Array(data.length), blocks = [], trace = [
      step('chacha-setup', `Key ${hex(key)}, nonce ${hex(nonce)}; block j uses the counter ${counter} + j in word 12, so no two blocks share a keystream.`, { counter, nonce }),
    ];
    for (let j = 0; j < nBlocks; j++) {
      const ctr = counter + j, ks = C.block(key, ctr, nonce).out, p = data.subarray(64 * j, 64 * j + 64), c = p.map((v, i) => v ^ ks[i]);
      out.set(c, 64 * j);
      blocks.push({ i: j, counter: ctr, ks: ks.slice(0, p.length), p, c });
      trace.push(step('chacha-block', `Block ${j}: counter ${ctr} (word 12 = ${h8(ctr)}) gives keystream ${hex(ks.slice(0, Math.min(16, p.length)))}…; XOR with ${p.length} plaintext bytes gives ${hex(c.slice(0, Math.min(16, c.length)))}…${p.length < 64 ? ` (the last ${64 - p.length} keystream bytes are thrown away)` : ''}.`, { i: j, counter: ctr }));
    }
    return { out, blocks, trace };
  };
  const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  const QR = (x, a, b, c, d) => {
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 16);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 12);
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 8);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 7);
  };
  const le = (b, i) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
  C.hchacha = (key, nonce16) => {
    const x = C.state(key, le(nonce16, 0), nonce16.subarray(4, 16));
    for (let i = 0; i < 10; i++) { for (const q of C.COLUMNS) QR(x, ...q); for (const q of C.DIAGONALS) QR(x, ...q); }
    const words = [0, 1, 2, 3, 12, 13, 14, 15].map((i) => x[i]), out = new Uint8Array(32);
    words.forEach((w, i) => { out[4 * i] = w & 255; out[4 * i + 1] = (w >>> 8) & 255; out[4 * i + 2] = (w >>> 16) & 255; out[4 * i + 3] = w >>> 24; });
    return { out, trace: [step('hchacha', `HChaCha20 runs the 20 rounds on the key and the 16-byte nonce ${hex(nonce16)} and keeps words 0–3 and 12–15 without adding the input: subkey ${hex(out)}.`, { out })] };
  };
  C.xencrypt = (key, nonce24, data, counter = 0) => {
    if (nonce24.length !== 24) throw new Error('XChaCha20 takes a 24-byte nonce');
    const h = C.hchacha(key, nonce24.subarray(0, 16)), n12 = new Uint8Array(12);
    n12.set(nonce24.subarray(16, 24), 4);
    const r = C.encryptTrace(h.out, counter, n12, data);
    return { out: r.out, subkey: h.out, nonce12: n12, trace: h.trace.concat([step('xchacha', `The ChaCha20 nonce is four zero bytes and the last 8 nonce bytes: ${hex(n12)}.`, { nonce12: n12 })], r.trace) };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
