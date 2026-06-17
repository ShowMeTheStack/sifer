// SHA-256: padding, the message schedule and the compression function, with the eight registers a..h kept after
// every one of the 64 rounds.
//   S.SHA256.schedule(block64) -> {W: [64 words], trace}  each W[t] for t ≥ 16 with its four sources
//   S.SHA256.compress(H, block64) -> {H: new chaining value, W, rounds: [{t, T1, T2, ch, maj, s0, s1, regs}], trace}
//   S.SHA256.hash(bytes) -> 32 bytes; S.SHA256.pad(bytes) -> the padded message
(function (S) {
  'use strict';
  const { h8, rotr32, add32, step } = S.bytes;
  const H = (S.SHA256 = {});
  H.K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  H.IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const S0 = (x) => rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22), S1 = (x) => rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
  const s0 = (x) => rotr32(x, 7) ^ rotr32(x, 18) ^ (x >>> 3), s1 = (x) => rotr32(x, 17) ^ rotr32(x, 19) ^ (x >>> 10);
  H.Sigma0 = (x) => S0(x) >>> 0; H.Sigma1 = (x) => S1(x) >>> 0; H.sigma0 = (x) => s0(x) >>> 0; H.sigma1 = (x) => s1(x) >>> 0;
  H.ch = (e, f, g) => ((e & f) ^ (~e & g)) >>> 0;
  H.maj = (a, b, c) => ((a & b) ^ (a & c) ^ (b & c)) >>> 0;

  H.pad = (msg) => {
    const n = msg.length, len = Math.ceil((n + 9) / 64) * 64, out = new Uint8Array(len);
    out.set(msg); out[n] = 0x80;
    const bits = n * 8;
    for (let i = 0; i < 8; i++) out[len - 1 - i] = Math.floor(bits / 2 ** (8 * i)) & 255;
    return out;
  };
  H.schedule = (block) => {
    const W = [], trace = [];
    for (let t = 0; t < 16; t++) { W.push(((block[4 * t] << 24) | (block[4 * t + 1] << 16) | (block[4 * t + 2] << 8) | block[4 * t + 3]) >>> 0); trace.push(step('w-copy', `W${t} = ${h8(W[t])}, word ${t} of the block.`, { t, w: W[t] })); }
    for (let t = 16; t < 64; t++) {
      const a = s1(W[t - 2]) >>> 0, b = W[t - 7], c = s0(W[t - 15]) >>> 0, d = W[t - 16];
      W.push(add32(a, b, c, d));
      trace.push(step('w-mix', `W${t} = σ1(W${t - 2}) + W${t - 7} + σ0(W${t - 15}) + W${t - 16} = ${h8(a)} + ${h8(b)} + ${h8(c)} + ${h8(d)} = ${h8(W[t])}.`, { t, terms: [a, b, c, d], src: [t - 2, t - 7, t - 15, t - 16], w: W[t] }));
    }
    return { W, trace };
  };
  H.compress = (Hin, block) => {
    const { W } = H.schedule(block);
    let [a, b, c, d, e, f, g, h] = Hin;
    const rounds = [], trace = [];
    for (let t = 0; t < 64; t++) {
      const sig1 = S1(e) >>> 0, chv = H.ch(e, f, g), T1 = add32(h, sig1, chv, H.K[t], W[t]);
      const sig0 = S0(a) >>> 0, mj = H.maj(a, b, c), T2 = add32(sig0, mj);
      const before = [a, b, c, d, e, f, g, h];
      h = g; g = f; f = e; e = add32(d, T1); d = c; c = b; b = a; a = add32(T1, T2);
      const regs = [a, b, c, d, e, f, g, h];
      rounds.push({ t, before, sig1, ch: chv, T1, sig0, maj: mj, T2, K: H.K[t], W: W[t], regs });
      trace.push(step('round', `Round ${t}: T1 = h + Σ1(e) + Ch(e,f,g) + K${t} + W${t} = ${h8(T1)}, T2 = Σ0(a) + Maj(a,b,c) = ${h8(T2)}; the new a is ${h8(a)} and the new e is ${h8(e)}.`, { t, regs }));
    }
    const out = Hin.map((v, i) => add32(v, [a, b, c, d, e, f, g, h][i]));
    trace.push(step('feed-forward', `Adding the input chaining value word by word gives ${out.map(h8).join(' ')}.`, { H: out }));
    return { H: out, W, rounds, trace };
  };
  H.hash = (msg) => {
    const m = H.pad(msg);
    let st = H.IV.slice();
    for (let i = 0; i < m.length; i += 64) st = H.compress(st, m.subarray(i, i + 64)).H;
    const out = new Uint8Array(32);
    st.forEach((w, i) => { out[4 * i] = w >>> 24; out[4 * i + 1] = (w >>> 16) & 255; out[4 * i + 2] = (w >>> 8) & 255; out[4 * i + 3] = w & 255; });
    return out;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
