// Shared pieces of the post-quantum engines: a fast Keccak-f[1600] on 32-bit halves, the FIPS 202 functions the
// standards need (SHA3-256, SHA3-512, SHAKE128 and SHAKE256 with an incremental squeeze), a seeded random source,
// and small helpers. S.Keccak (the teaching version, one BigInt per lane) gives the same permutation; this one is
// about thirty times faster, which ML-KEM and the hash-based signatures need.
//   S.PQ.sha3_256(bytes) / sha3_512(bytes) -> Uint8Array
//   S.PQ.shake128(bytes, outLen) / shake256(bytes, outLen) -> Uint8Array
//   S.PQ.xof(bytes, 128 | 256) -> {read(n)}   squeezes as much as is asked, block by block
//   S.PQ.rng(seed) -> {next() in [0,1), int(n), bytes(n), gauss(), pick(array)}
(function (S) {
  'use strict';
  const P = (S.PQ = S.PQ || {});
  P.step = (kind, say, data) => Object.assign({ kind, say }, data || {});

  // round constants (from the LFSR x^8 + x^6 + x^5 + x^4 + 1) as low and high 32-bit halves
  const RC = new Uint32Array(48);
  {
    let R = 1;
    const bit = () => { const b = R & 1; R <<= 1; if (R & 0x100) R ^= 0x171; return b; };
    for (let i = 0; i < 24; i++) for (let j = 0; j <= 6; j++) if (bit()) { const p = 2 ** j - 1; RC[2 * i + (p >= 32 ? 1 : 0)] |= (1 << (p % 32)) >>> 0; }
  }
  // ρ offsets, by lane index x + 5y
  const ROT = new Array(25).fill(0);
  for (let t = 0, x = 1, y = 0; t < 24; t++) { ROT[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64; [x, y] = [y, (2 * x + 3 * y) % 5]; }
  const PI = new Array(25);
  for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) PI[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5);
  const C = new Uint32Array(10), Bs = new Uint32Array(50);
  /** Keccak-f[1600] in place on 50 words: lane i is (s[2i] low, s[2i+1] high) */
  P.keccakF = (s) => {
    for (let r = 0; r < 24; r++) {
      for (let x = 0; x < 5; x++) {
        C[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
        C[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
      }
      for (let x = 0; x < 5; x++) {
        const a = (x + 4) % 5, b = (x + 1) % 5;
        const lo = C[2 * a] ^ ((C[2 * b] << 1) | (C[2 * b + 1] >>> 31));
        const hi = C[2 * a + 1] ^ ((C[2 * b + 1] << 1) | (C[2 * b] >>> 31));
        for (let y = 0; y < 25; y += 5) { s[2 * (x + y)] ^= lo; s[2 * (x + y) + 1] ^= hi; }
      }
      for (let i = 0; i < 25; i++) {
        let lo = s[2 * i], hi = s[2 * i + 1], n = ROT[i];
        if (n >= 32) { const t = lo; lo = hi; hi = t; n -= 32; }
        if (n) { const l2 = (lo << n) | (hi >>> (32 - n)), h2 = (hi << n) | (lo >>> (32 - n)); lo = l2; hi = h2; }
        Bs[2 * PI[i]] = lo; Bs[2 * PI[i] + 1] = hi;
      }
      for (let y = 0; y < 25; y += 5) for (let x = 0; x < 5; x++) {
        const i = x + y, b = ((x + 1) % 5) + y, c = ((x + 2) % 5) + y;
        s[2 * i] = Bs[2 * i] ^ (~Bs[2 * b] & Bs[2 * c]);
        s[2 * i + 1] = Bs[2 * i + 1] ^ (~Bs[2 * b + 1] & Bs[2 * c + 1]);
      }
      s[0] ^= RC[2 * r]; s[1] ^= RC[2 * r + 1];
    }
    return s;
  };
  const absorbBlock = (s, m, off, rate) => {
    for (let i = 0; i < rate; i += 4) s[i >> 2] ^= (m[off + i] | (m[off + i + 1] << 8) | (m[off + i + 2] << 16) | (m[off + i + 3] << 24)) >>> 0;
    P.keccakF(s);
  };
  /** a sponge that has absorbed msg; read(n) squeezes the next n bytes */
  P.sponge = (msg, rate, pad) => {
    const s = new Uint32Array(50), n = msg.length, full = Math.floor(n / rate) * rate;
    for (let off = 0; off < full; off += rate) absorbBlock(s, msg, off, rate);
    const last = new Uint8Array(rate);
    last.set(msg.subarray ? msg.subarray(full) : msg.slice(full)); last[n - full] ^= pad; last[rate - 1] ^= 0x80;
    absorbBlock(s, last, 0, rate);
    let pos = 0;
    return {
      read(len) {
        const out = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
          if (pos === rate) { P.keccakF(s); pos = 0; }
          out[i] = (s[pos >> 2] >>> (8 * (pos & 3))) & 255; pos++;
        }
        return out;
      },
    };
  };
  P.sha3_256 = (m) => P.sponge(m, 136, 0x06).read(32);
  P.sha3_512 = (m) => P.sponge(m, 72, 0x06).read(64);
  P.shake128 = (m, len) => P.sponge(m, 168, 0x1f).read(len);
  P.shake256 = (m, len) => P.sponge(m, 136, 0x1f).read(len);
  P.xof = (m, bits) => (bits === 256 ? P.sponge(m, 136, 0x1f) : P.sponge(m, 168, 0x1f));

  P.concat = (...parts) => {
    const len = parts.reduce((n, p) => n + p.length, 0), out = new Uint8Array(len);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };
  P.hex = (a) => Array.from(a, (v) => (v & 255).toString(16).padStart(2, '0')).join('');
  P.eqBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  /** fresh random bytes from the platform, for keys a student does not seed */
  P.randomBytes = (n) => {
    const out = new Uint8Array(n);
    if (globalThis.crypto && globalThis.crypto.getRandomValues) globalThis.crypto.getRandomValues(out);
    else for (let i = 0; i < n; i++) out[i] = (Math.random() * 256) | 0;
    return out;
  };
  /** a seeded random source (mulberry32), so every picture can be redrawn exactly */
  P.rng = (seed = 1) => {
    let s = (typeof seed === 'number' ? seed : hashSeed(String(seed))) >>> 0, spare = null;
    const next = () => { s = (s + 0x6D2B79F5) >>> 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t ^= t + Math.imul(t ^ (t >>> 7), 61 | t); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
    return {
      next,
      int: (n) => Math.floor(next() * n),
      bytes: (n) => { const o = new Uint8Array(n); for (let i = 0; i < n; i++) o[i] = (next() * 256) | 0; return o; },
      gauss() {
        if (spare !== null) { const v = spare; spare = null; return v; }
        let u = 0, v = 0;
        while (u === 0) u = next();
        v = next();
        const r = Math.sqrt(-2 * Math.log(u));
        spare = r * Math.sin(2 * Math.PI * v);
        return r * Math.cos(2 * Math.PI * v);
      },
      pick: (a) => a[Math.floor(next() * a.length)],
    };
  };
  const hashSeed = (str) => { let h = 2166136261; for (let i = 0; i < str.length; i++) h = Math.imul(h ^ str.charCodeAt(i), 16777619); return h >>> 0; };
  P.mod = (a, q) => ((a % q) + q) % q;
  /** a centred representative in (−q/2, q/2] */
  P.centre = (a, q) => { a = P.mod(a, q); return a > q / 2 ? a - q : a; };
})(globalThis.Sifer = globalThis.Sifer || {});
