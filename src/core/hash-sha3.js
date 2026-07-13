// SHA-3 and SHAKE (FIPS 202) as a sponge: the message is cut into rate-sized blocks that are XORed into the top of a
// 1600-bit state, with Keccak-f between blocks; then output is squeezed from the same part of the state. The
// capacity (the rest of the state) is never touched by the input or shown in the output, and is what the security
// rests on. The permutation runs on S.PQ's fast Keccak; S.Keccak's teaching version gives the per-step pictures.
//   S.Hash.SHA3.run(msg, {rate, pad, outLen, trace, steps}) -> {digest, absorbs, squeezes, padded, trace}
//      absorbs: [{i, block, before, xored, after}], squeezes: [{i, out, before}], states as 25 lanes of 16 hex digits
//      steps: true adds, for the first permutation, S.Keccak.round's θ ρ π χ ι for every one of the 24 rounds
//   S.Hash.SHA3.params(name) -> {rate, capacity, pad, outLen};  S.Hash.get('sha3-256') etc.
//   S.Hash.shake128(msg, outLen) / shake256(msg, outLen) -> bytes;  S.Hash.SHA3.lanes(state50) -> 25 hex lanes
(function (S) {
  'use strict';
  const H = (S.Hash = S.Hash || {});
  const { step } = H;
  const S3 = (H.SHA3 = {});
  const PARAMS = {
    'sha3-224': { rate: 144, pad: 0x06, outLen: 28 }, 'sha3-256': { rate: 136, pad: 0x06, outLen: 32 },
    'sha3-384': { rate: 104, pad: 0x06, outLen: 48 }, 'sha3-512': { rate: 72, pad: 0x06, outLen: 64 },
    shake128: { rate: 168, pad: 0x1f, outLen: 32 }, shake256: { rate: 136, pad: 0x1f, outLen: 64 },
  };
  S3.params = (name) => { const p = PARAMS[name]; return Object.assign({ name, capacity: 200 - p.rate }, p); };

  const perm = (s) => {
    if (S.PQ && S.PQ.keccakF) return S.PQ.keccakF(s);
    const A = S3.toBig(s), B = S.Keccak.f(A); S3.fromBig(B, s); return s;
  };
  S3.toBig = (s) => Array.from({ length: 25 }, (_, i) => (BigInt(s[2 * i + 1]) << 32n) | BigInt(s[2 * i]));
  S3.fromBig = (A, s = new Uint32Array(50)) => { A.forEach((v, i) => { s[2 * i] = Number(v & 0xffffffffn); s[2 * i + 1] = Number(v >> 32n); }); return s; };
  S3.lanes = (s) => Array.from({ length: 25 }, (_, i) => s[2 * i + 1].toString(16).padStart(8, '0') + s[2 * i].toString(16).padStart(8, '0'));
  S3.bytes = (s, n = 200) => { const o = new Uint8Array(n); for (let i = 0; i < n; i++) o[i] = (s[i >> 2] >>> (8 * (i & 3))) & 255; return o; };

  /** the padded message: pad10*1 with the domain bits (0x06 for SHA-3, 0x1f for SHAKE) */
  S3.pad = (msg, rate, pad) => {
    const n = msg.length, len = Math.floor(n / rate) * rate + rate, m = new Uint8Array(len);
    m.set(msg); m[n] ^= pad; m[len - 1] ^= 0x80;
    return m;
  };
  S3.run = (msg, opt) => {
    msg = H.utf8(msg);
    const { rate, pad } = opt, outLen = opt.outLen, traced = !!opt.trace;
    const padded = S3.pad(msg, rate, pad), s = new Uint32Array(50);
    const absorbs = [], squeezes = [], trace = [];
    const cap = 200 - rate;
    if (traced) {
      trace.push(step('params', `Rate ${rate} bytes (${rate * 8} bits), capacity ${cap} bytes (${cap * 8} bits): input touches only the first ${rate} bytes of the 200-byte state.`, { rate, capacity: cap }));
      trace.push(step('pad', `The ${msg.length}-byte message gets the domain byte ${pad.toString(16).padStart(2, '0')} (${pad === 6 ? 'SHA-3' : 'SHAKE'}), zeros and a final 0x80, filling ${padded.length / rate} block${padded.length === rate ? '' : 's'} of ${rate} bytes.`, { padded, domain: pad }));
    }
    for (let off = 0, i = 0; off < padded.length; off += rate, i++) {
      const block = padded.subarray(off, off + rate);
      const before = traced ? S3.lanes(s) : null;
      for (let j = 0; j < rate; j += 4) s[j >> 2] ^= (block[j] | (block[j + 1] << 8) | (block[j + 2] << 16) | (block[j + 3] << 24)) >>> 0;
      const xored = traced ? S3.lanes(s) : null;
      let rounds = null;
      if (opt.steps && i === 0 && S.Keccak) {
        let A = S3.toBig(s); rounds = [];
        for (let r = 0; r < 24; r++) { const R = S.Keccak.round(A, r); rounds.push(R.steps); A = R.A; }
      }
      perm(s);
      if (traced) {
        const a = { i, block: block.slice(), before, xored, after: S3.lanes(s), rounds };
        absorbs.push(a);
        trace.push(step('absorb', `Absorb block ${i + 1}: XOR its ${rate} bytes into lanes 0 to ${rate / 8 - 1}, then Keccak-f; lane (0, 0) goes ${xored[0]} → ${a.after[0]}.`, a));
      }
    }
    const out = new Uint8Array(outLen);
    let pos = 0, k = 0;
    for (let i = 0; i < outLen; i++) {
      if (pos === rate) {
        if (traced) squeezes.push({ i: k, before: S3.lanes(s), out: out.slice(i - rate, i) });
        perm(s); pos = 0; k++;
        if (traced) trace.push(step('squeeze-more', `${rate} bytes squeezed; one more Keccak-f gives the next ${rate}.`, { k }));
      }
      out[i] = (s[pos >> 2] >>> (8 * (pos & 3))) & 255; pos++;
    }
    if (traced) {
      squeezes.push({ i: k, before: S3.lanes(s), out: out.slice(k * rate) });
      trace.push(step('squeeze', `Squeeze: the first ${Math.min(outLen, rate)} bytes of the state${outLen > rate ? ', and more after further permutations,' : ''} are the output ${H.short(out, 16)}; the ${cap}-byte capacity is never output.`, { out }));
    }
    return { digest: out, absorbs, squeezes, padded, trace };
  };
  for (const name of ['sha3-224', 'sha3-256', 'sha3-384', 'sha3-512']) {
    const p = S3.params(name);
    H.register({
      name, blockLen: p.rate, outLen: p.outLen, sponge: true,
      run: (msg, opt = {}) => S3.run(msg, Object.assign({}, p, opt)),
      hash: (msg) => S3.run(msg, p).digest,
    });
  }
  H.shake128 = (msg, outLen) => S3.run(msg, { rate: 168, pad: 0x1f, outLen }).digest;
  H.shake256 = (msg, outLen) => S3.run(msg, { rate: 136, pad: 0x1f, outLen }).digest;
  S3.shake = (bits, msg, outLen, opt = {}) => S3.run(msg, Object.assign({ rate: bits === 128 ? 168 : 136, pad: 0x1f, outLen }, opt));
})(globalThis.Sifer = globalThis.Sifer || {});
