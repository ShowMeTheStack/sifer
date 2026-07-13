// SHA-1 and MD5, the two broken hashes, with every round's registers kept, and the story of how they fell.
//   S.Hash.SHA1.compress(state5, block64[, traced]) -> state | {state, W, rounds: [{t, f, K, W, temp, regs}], trace}
//   S.Hash.MD5.compress(state4, block64[, traced])  -> state | {state, X, rounds: [{i, f, g, s, K, regs}], trace}
//   S.Hash.get('sha1') / get('md5') are Merkle–Damgård hashes (see hash-base.js): .hash, .run(msg, {trace, rounds})
//   S.Hash.HISTORY -> [{year, hash, event}]   the timeline of the broken-hash story
(function (S) {
  'use strict';
  const H = (S.Hash = S.Hash || {});
  const { step, h8, rotl, readBE, readLE, wordsBE, wordsLE } = H;

  // ---- SHA-1 (FIPS 180-4, section 6.1)
  const S1 = (H.SHA1 = {});
  S1.IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
  S1.K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
  S1.F_NAMES = ['Ch', 'Parity', 'Maj', 'Parity'];
  const f1 = (t, b, c, d) => (t < 20 ? (b & c) | (~b & d) : t < 40 || t >= 60 ? b ^ c ^ d : (b & c) | (b & d) | (c & d)) >>> 0;
  S1.f = f1;
  S1.compress = (st, block, traced) => {
    const W = new Array(80);
    for (let t = 0; t < 16; t++) W[t] = readBE(block, 4 * t);
    for (let t = 16; t < 80; t++) W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    let [a, b, c, d, e] = st;
    const rounds = traced ? [] : null, trace = traced ? [] : null;
    for (let t = 0; t < 80; t++) {
      const f = f1(t, b, c, d), K = S1.K[(t / 20) | 0];
      const temp = (rotl(a, 5) + f + e + K + W[t]) >>> 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = temp;
      if (traced) {
        rounds.push({ t, f, fname: S1.F_NAMES[(t / 20) | 0], K, W: W[t], temp, regs: [a, b, c, d, e] });
        trace.push(step('round', `Round ${t} (${S1.F_NAMES[(t / 20) | 0]}): T = (a <<< 5) + f(b, c, d) + e + K + W${t} = ${h8(temp)}; it becomes the new a, and the old b turns into c rotated by 30 = ${h8(c)}.`, { t, regs: [a, b, c, d, e] }));
      }
    }
    const out = [a, b, c, d, e].map((v, i) => (v + st[i]) >>> 0);
    if (!traced) return out;
    trace.push(step('feed-forward', `Adding the input chaining value word by word gives ${out.map(h8).join(' ')}.`, { state: out }));
    return { state: out, W, rounds, trace };
  };
  /** the 80-word schedule with the sources of each expanded word */
  S1.schedule = (block) => {
    const W = [], trace = [];
    for (let t = 0; t < 80; t++) {
      if (t < 16) W.push(readBE(block, 4 * t));
      else W.push(rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1));
      trace.push(t < 16 ? step('w-copy', `W${t} = ${h8(W[t])}, word ${t} of the block.`, { t, w: W[t] })
        : step('w-mix', `W${t} = (W${t - 3} ⊕ W${t - 8} ⊕ W${t - 14} ⊕ W${t - 16}) <<< 1 = ${h8(W[t])}.`, { t, src: [t - 3, t - 8, t - 14, t - 16], w: W[t] }));
    }
    return { W, trace };
  };
  H.register(H.md({ name: 'sha1', iv: S1.IV, blockLen: 64, outLen: 20, compress: S1.compress, output: (s) => wordsBE(s), wordHex: (s) => s.map(h8).join(' ') }));

  // ---- MD5 (RFC 1321): little-endian words, four rounds of sixteen steps
  const M5 = (H.MD5 = {});
  M5.IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
  M5.K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);
  M5.S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  M5.F_NAMES = ['F', 'G', 'H', 'I'];
  M5.compress = (st, block, traced) => {
    const X = Array.from({ length: 16 }, (_, i) => readLE(block, 4 * i));
    let [a, b, c, d] = st;
    const rounds = traced ? [] : null, trace = traced ? [] : null;
    for (let i = 0; i < 64; i++) {
      const r = i >> 4;
      let f, g;
      if (r === 0) { f = (b & c) | (~b & d); g = i; }
      else if (r === 1) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
      else if (r === 2) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
      else { f = c ^ (b | ~d); g = (7 * i) & 15; }
      const s = M5.S[4 * r + (i & 3)];
      const sum = (a + (f >>> 0) + M5.K[i] + X[g]) >>> 0;
      const nb = (b + rotl(sum, s)) >>> 0;
      a = d; d = c; c = b; b = nb;
      if (traced) {
        rounds.push({ i, f: f >>> 0, fname: M5.F_NAMES[r], g, s, K: M5.K[i], X: X[g], regs: [a, b, c, d] });
        trace.push(step('round', `Step ${i} (${M5.F_NAMES[r]}): b + ((a + ${M5.F_NAMES[r]}(b, c, d) + K${i} + X[${g}]) <<< ${s}) = ${h8(nb)} is the new b; the registers rotate.`, { i, regs: [a, b, c, d] }));
      }
    }
    const out = [a, b, c, d].map((v, i) => (v + st[i]) >>> 0);
    if (!traced) return out;
    trace.push(step('feed-forward', `Adding the input chaining value gives ${out.map(h8).join(' ')} (stored little-endian).`, { state: out }));
    return { state: out, X, rounds, trace };
  };
  H.register(H.md({ name: 'md5', iv: M5.IV, blockLen: 64, outLen: 16, endian: 'le', compress: M5.compress, output: (s) => wordsLE(s), wordHex: (s) => s.map(h8).join(' ') }));

  H.HISTORY = [
    { year: 1990, hash: 'MD4', event: 'MD4 is published: a fast 128-bit hash built on 32-bit additions, rotations and Boolean functions.' },
    { year: 1992, hash: 'MD5', event: 'MD5 (RFC 1321) adds a fourth round and per-step constants to MD4, and spreads into every protocol of the decade.' },
    { year: 1993, hash: 'SHA-0', event: 'The first Secure Hash Standard: a 160-bit Merkle–Damgård hash with an 80-word message schedule.' },
    { year: 1995, hash: 'SHA-1', event: 'SHA-1 replaces SHA-0, adding a single one-bit rotation to the schedule; the reason was not given at the time.' },
    { year: 1996, hash: 'MD5', event: 'Collisions are found in the MD5 compression function with a chosen chaining value; cautious designers start moving away.' },
    { year: 2004, hash: 'MD5', event: 'The first full MD5 collision is announced: two different 128-byte messages with the same digest, found in hours.' },
    { year: 2005, hash: 'SHA-1', event: 'A differential attack brings SHA-1 collisions down to about 2^69 work, far below the 2^80 birthday bound.' },
    { year: 2008, hash: 'MD5', event: 'A chosen-prefix MD5 collision is used to make a rogue certificate authority certificate that browsers would trust.' },
    { year: 2012, hash: 'MD5', event: 'Malware signed with a forged code-signing certificate, built from an MD5 chosen-prefix collision, is found in the wild.' },
    { year: 2015, hash: 'SHA-3', event: 'FIPS 202 standardises SHA-3, a sponge with no Merkle–Damgård structure at all, as a different design to fall back on.' },
    { year: 2017, hash: 'SHA-1', event: 'The first public SHA-1 collision: two different PDF files with the same digest, after about 2^63 computations.' },
    { year: 2020, hash: 'SHA-1', event: 'A chosen-prefix SHA-1 collision costs about 2^63.4 work, enough to forge identity signatures in old PGP keys.' },
    { year: 2030, hash: 'SHA-1', event: 'The planned end of SHA-1 in US government use; SHA-2 and SHA-3 remain unbroken.' },
  ];
})(globalThis.Sifer = globalThis.Sifer || {});
