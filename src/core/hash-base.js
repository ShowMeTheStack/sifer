// The hash family's shared parts: byte helpers, a registry of every hash by name, and the Merkle–Damgård
// construction made generic, so any compression function can be plugged in and watched.
//   S.Hash.get(name) -> {name, blockLen, outLen, hash(bytes), md?}  names: md5, sha1, sha224, sha256, sha384,
//                     sha512, sha512-256, sha3-224 … sha3-512 (and shake128 / shake256 through S.Hash.shake*)
//   S.Hash.md(spec) -> a Merkle–Damgård hash.  spec = {name, iv, blockLen, lenBytes, endian: 'be' | 'le',
//                     compress(state, block, traced) -> state | {state, rounds, trace}, output(state) -> bytes,
//                     wordHex(state) -> string}
//     .pad(msg[, totalLen]) -> {padded, padLen, bits}   totalLen lets the length field count bytes hashed before
//     .run(msg[, {iv, prefixLen, trace, rounds}]) -> {digest, state, padded, blocks, chain, trace}
//     .hash(msg) -> digest bytes
//   S.Hash.toy(bits) -> a toy Merkle–Damgård hash with a bits-wide chaining value (bits ≤ 32), for attacks
(function (S) {
  'use strict';
  const H = (S.Hash = S.Hash || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  H.step = step;
  const hex = (a) => Array.from(a, (v) => (v & 255).toString(16).padStart(2, '0')).join('');
  H.hex = hex;
  H.short = (a, n = 8) => (a.length > n ? hex(a.subarray ? a.subarray(0, n) : a.slice(0, n)) + '…' : hex(a));
  H.concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };
  H.utf8 = (s) => (typeof s === 'string' ? new TextEncoder().encode(s) : s);
  H.fromHex = (s) => { const t = String(s).replace(/[^0-9a-f]/gi, ''); const o = new Uint8Array(t.length >> 1); for (let i = 0; i < o.length; i++) o[i] = parseInt(t.substr(2 * i, 2), 16); return o; };
  H.eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  H.h8 = (v) => (v >>> 0).toString(16).padStart(8, '0');
  H.readBE = (b, i) => ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
  H.readLE = (b, i) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
  H.wordsBE = (ws) => { const o = new Uint8Array(4 * ws.length); ws.forEach((w, i) => { o[4 * i] = w >>> 24; o[4 * i + 1] = (w >>> 16) & 255; o[4 * i + 2] = (w >>> 8) & 255; o[4 * i + 3] = w & 255; }); return o; };
  H.wordsLE = (ws) => { const o = new Uint8Array(4 * ws.length); ws.forEach((w, i) => { o[4 * i] = w & 255; o[4 * i + 1] = (w >>> 8) & 255; o[4 * i + 2] = (w >>> 16) & 255; o[4 * i + 3] = w >>> 24; }); return o; };
  H.rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  H.rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

  // ---- the registry
  H.algos = H.algos || {};
  H.register = (a) => { H.algos[a.name] = a; return a; };
  H.get = (name) => {
    const a = H.algos[String(name).toLowerCase().replace(/_/g, '-')];
    if (!a) throw new Error('unknown hash ' + name);
    return a;
  };
  H.names = () => Object.keys(H.algos);
  H.digest = (name, msg) => H.get(name).hash(H.utf8(msg));

  // ---- Merkle–Damgård, generic
  H.md = (spec) => {
    const { blockLen, lenBytes = 8, endian = 'be' } = spec;
    const wordHex = spec.wordHex || ((st) => hex(spec.output(st)));
    const M = { name: spec.name, blockLen, outLen: spec.outLen, iv: spec.iv, spec };
    /** pad: a 1 bit (0x80), zeros, then the length in bits in lenBytes bytes; totalLen is the byte count it claims */
    M.pad = (msg, totalLen) => {
      const n = msg.length, total = totalLen === undefined ? n : totalLen;
      let len = n + 1 + lenBytes;
      len = Math.ceil(len / blockLen) * blockLen;
      const out = new Uint8Array(len);
      out.set(msg); out[n] = 0x80;
      let bits = total * 8;
      for (let i = 0; i < lenBytes && bits > 0; i++) {
        const byte = bits % 256;
        bits = Math.floor(bits / 256);
        if (endian === 'be') out[len - 1 - i] = byte; else out[len - lenBytes + i] = byte;
      }
      return { padded: out, padLen: len - n, bits: BigInt(total) * 8n };
    };
    /** the bytes padding appends after a message of totalLen bytes (what a length-extension attacker must reproduce) */
    M.glue = (totalLen) => {
      const p = M.pad(new Uint8Array(totalLen % blockLen), totalLen).padded;
      return p.slice(totalLen % blockLen);
    };
    M.run = (msg, opt = {}) => {
      msg = H.utf8(msg);
      const prefix = opt.prefixLen || 0;
      const { padded, padLen, bits } = M.pad(msg, prefix + msg.length);
      const traced = !!opt.trace, keepRounds = !!opt.rounds;
      let st = (opt.iv || spec.iv).slice();
      const chain = [st.slice()], blocks = [], trace = [];
      if (traced) {
        trace.push(step('pad', `The message is ${msg.length} byte${msg.length === 1 ? '' : 's'}${prefix ? ` (counted as ${prefix + msg.length}, after ${prefix} bytes already hashed)` : ''}; padding adds 0x80, ${padLen - 1 - lenBytes} zero byte${padLen - 1 - lenBytes === 1 ? '' : 's'} and the length ${bits} bits in ${lenBytes} ${endian === 'be' ? 'big' : 'little'}-endian bytes, for ${padded.length / blockLen} block${padded.length === blockLen ? '' : 's'} of ${blockLen}.`, { msgLen: msg.length, padLen, bits, lenBytes, endian, blocks: padded.length / blockLen, padded }));
        trace.push(step('iv', `The chaining value starts at the ${opt.iv ? 'given state' : 'fixed IV'} ${wordHex(st)}.`, { cv: st.slice() }));
      }
      for (let off = 0, i = 0; off < padded.length; off += blockLen, i++) {
        const block = padded.subarray(off, off + blockLen);
        const r = spec.compress(st, block, keepRounds);
        const next = Array.isArray(r) || ArrayBuffer.isView(r) ? r : r.state;
        const info = { i, block: block.slice(), cvIn: st.slice(), cvOut: next.slice(), lengthBlock: off + blockLen > padded.length - lenBytes, hasPad: off + blockLen > msg.length };
        if (keepRounds && r.rounds) info.rounds = r.rounds;
        if (keepRounds && r.trace) info.trace = r.trace;
        blocks.push(info);
        if (traced) trace.push(step('compress', `Block ${i + 1}${info.lengthBlock ? ' (it carries the length)' : ''}: the compression function maps the chaining value ${wordHex(st)} and the block to ${wordHex(next)}.`, info));
        st = next; chain.push(st.slice());
      }
      const digest = spec.output(st);
      if (traced) trace.push(step('output', `The last chaining value${spec.truncate ? ', truncated,' : ''} is the digest: ${hex(digest)}.`, { digest }));
      return { digest, state: st, padded, blocks, chain, trace };
    };
    M.hash = spec.fast || ((msg) => {
      msg = H.utf8(msg);
      const p = M.pad(msg).padded;
      let st = spec.iv;
      for (let off = 0; off < p.length; off += blockLen) st = spec.compress(st, p.subarray(off, off + blockLen), false);
      return spec.output(st);
    });
    return M;
  };

  /** The state words of a digest (to resume hashing from it, as a length-extension attacker does). */
  H.stateFromDigest = (name, digest) => {
    const a = H.get(name), d = H.utf8(digest);
    if (a.name === 'md5') return Array.from({ length: d.length / 4 }, (_, i) => H.readLE(d, 4 * i));
    return Array.from({ length: d.length / 4 }, (_, i) => H.readBE(d, 4 * i));
  };

  // ---- a toy Merkle–Damgård hash with a small chaining value, for multicollisions and second preimages
  // Its compression function is a few rounds of a 32-bit mixer over the block's words, cut to `bits` bits.
  H.toy = (bits = 16, opt = {}) => {
    const mask = bits >= 32 ? 0xffffffff : (1 << bits) - 1, blockLen = opt.blockLen || 8;
    const mix = (h, w) => {
      let x = (h ^ Math.imul(w, 0x9e3779b1)) >>> 0;
      x = Math.imul(x ^ (x >>> 16), 0x85ebca6b) >>> 0;
      x = Math.imul(x ^ (x >>> 13), 0xc2b2ae35) >>> 0;
      return (x ^ (x >>> 16)) >>> 0;
    };
    const compress = (st, block) => {
      let h = (st[0] * 0x01000193) >>> 0;
      for (let i = 0; i < blockLen; i += 4) h = mix(h, H.readLE(block, i));
      return [(h & mask) >>> 0];
    };
    const iv = [(0x2545f491 & mask) >>> 0];
    const digits = Math.ceil(bits / 4);
    const M = H.md({ name: `toy${bits}`, iv, blockLen, lenBytes: 4, endian: 'be', outLen: Math.ceil(bits / 8), compress, output: (st) => H.wordsBE([st[0]]).slice(4 - Math.ceil(bits / 8)), wordHex: (st) => st[0].toString(16).padStart(digits, '0') });
    M.bits = bits; M.compress1 = (cv, block) => compress([cv], block)[0];
    M.hashValue = (msg) => M.run(msg).state[0];
    return M;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
