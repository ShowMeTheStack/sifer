// XTS (IEEE 1619, NIST SP 800-38E), the mode for disk sectors: the key is two AES keys. The tweak (the sector
// number, little-endian in 16 bytes) is encrypted under the second key to give T; block j of the sector is
// C = E_K1(P ⊕ T_j) ⊕ T_j with T_j = T·α^j, where α is x in GF(2^128) with bytes little-endian (shift left by one bit,
// folding 87 into the first byte when a bit falls off the top). A sector that is not a whole number of blocks ends
// with ciphertext stealing, so the ciphertext is as long as the plaintext.
//   S.XTS.encrypt(key32or64, tweak16 | sector number, data) -> {out, tweaks, trace};  S.XTS.decrypt(...)
//   S.XTS.mulAlpha(T) -> T·α;  S.XTS.tweakBlock(n) -> 16 bytes, n little-endian
(function (S) {
  'use strict';
  const X = (S.XTS = {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const hex = (a) => S.bytes.hex(a), xor = (a, b) => a.map((v, i) => v ^ b[i]);
  X.mulAlpha = (T) => {
    const o = new Uint8Array(16);
    let carry = 0;
    for (let i = 0; i < 16; i++) { o[i] = ((T[i] << 1) | carry) & 255; carry = T[i] >> 7; }
    if (carry) o[0] ^= 0x87;
    return o;
  };
  X.tweakBlock = (n) => { const o = new Uint8Array(16); let v = BigInt(n); for (let i = 0; i < 16; i++) { o[i] = Number(v & 255n); v >>= 8n; } return o; };
  const run = (key, tweak, data, dec) => {
    if (key.length !== 32 && key.length !== 64) throw new Error('XTS-AES takes two AES keys: 32 or 64 bytes');
    if (data.length < 16) throw new Error('XTS needs at least one whole block');
    const h = key.length / 2, E1 = S.AES.cipher(key.subarray(0, h)), E2 = S.AES.cipher(key.subarray(h));
    const tw = typeof tweak === 'number' || typeof tweak === 'bigint' ? X.tweakBlock(tweak) : tweak;
    const m = Math.floor(data.length / 16), d = data.length % 16, out = new Uint8Array(data.length), trace = [], tweaks = [];
    let T = E2.encrypt(tw);
    trace.push(step('xts-t', `The tweak ${hex(tw)} encrypted under the second key gives T = ${hex(T)}.`, { T }));
    const Ts = [];
    for (let j = 0; j <= m; j++) { Ts.push(T); T = X.mulAlpha(T); }
    const one = (b, Tj, j) => {
      const pp = xor(b, Tj), cc = dec ? E1.decrypt(pp) : E1.encrypt(pp), c = xor(cc, Tj);
      tweaks.push(Tj);
      trace.push(step('xts-block', `Block ${j + 1}: T·α^${j} = ${hex(Tj)}; ${hex(b)} ⊕ T = ${hex(pp)}; ${dec ? 'D' : 'E'}_K1 gives ${hex(cc)}; ⊕ T = ${hex(c)}.`, { j, T: Tj, in: b, pp, cc, out: c }));
      return c;
    };
    const whole = d ? m - 1 : m;
    for (let j = 0; j < whole; j++) out.set(one(data.subarray(16 * j, 16 * j + 16), Ts[j], j), 16 * j);
    if (d) {
      // the last full block and the partial one: steal the tail of the next-to-last result to fill the last block
      const j = m - 1, a = data.subarray(16 * j, 16 * j + 16), tail = data.subarray(16 * m);
      const first = one(a, dec ? Ts[m] : Ts[j], j);
      const last = new Uint8Array(16); last.set(tail); last.set(first.subarray(d), d);
      const second = one(last, dec ? Ts[j] : Ts[m], m);
      out.set(second, 16 * j); out.set(first.subarray(0, d), 16 * m);
      trace.push(step('xts-steal', `Ciphertext stealing: the last ${d} byte${d === 1 ? '' : 's'} borrow ${16 - d} bytes from the block before, so the output stays ${data.length} bytes long.`, { d }));
    }
    return { out, tweaks, trace };
  };
  X.encrypt = (key, tweak, data) => run(key, tweak, data, false);
  X.decrypt = (key, tweak, data) => run(key, tweak, data, true);
})(globalThis.Sifer = globalThis.Sifer || {});
