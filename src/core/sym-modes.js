// Modes of operation over any block cipher object {name, n, encrypt, decrypt} (S.AES.cipher, S.DES.cipher,
// S.TDES.cipher, S.PRESENT.cipher, or S.Sym.cipher(name, key)). Every block is traced with the values on its wires.
//   S.Modes.encrypt(mode, cipher, data, {iv}) / decrypt(...) -> {out, steps: [...], trace}
//       mode: 'ecb' | 'cbc' (whole blocks) | 'cfb' (full-block segments) | 'cfb8' | 'ofb' | 'ctr' (any length)
//       for 'ctr' the iv is the initial counter block, incremented as one big-endian number
//   S.Modes.pkcs7(data, n) / unpkcs7(data, n) (throws on bad padding); iso7816(data, n) / uniso7816(data, n)
//   S.Modes.cts(cipher, data, iv, {variant: 'CS1' | 'CS2' | 'CS3', decrypt}) -> {out, trace}  CBC with ciphertext
//       stealing: no padding, the ciphertext as long as the plaintext (at least one block)
//   S.Modes.ecbImage(cipher, pixels, {bytesPerPixel}) -> {out, distinct, repeats}   pixel bytes encrypted block by block
(function (S) {
  'use strict';
  const Mo = (S.Modes = S.Modes || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const hex = (a) => S.bytes.hex(a), xor = (a, b) => { const o = new Uint8Array(Math.min(a.length, b.length)); for (let i = 0; i < o.length; i++) o[i] = a[i] ^ b[i]; return o; };
  const inc = (ctr) => { const c = Uint8Array.from(ctr); for (let k = c.length - 1; k >= 0; k--) { c[k] = (c[k] + 1) & 255; if (c[k]) break; } return c; };
  Mo.increment = inc;
  const blocksOf = (data, n) => { const out = []; for (let i = 0; i < data.length; i += n) out.push(data.subarray(i, i + n)); return out; };

  const run = (mode, E, data, opts, dec) => {
    const n = E.n, iv = opts.iv ? Uint8Array.from(opts.iv) : null, steps = [], trace = [];
    const name = mode.toUpperCase(), quiet = opts.trace === false;
    const say = (kind, text, d) => { steps.push(d); if (!quiet) trace.push(step(kind, text(), d)); };
    if ((mode === 'ecb' || mode === 'cbc') && data.length % n) throw new Error(`${name} needs whole ${n}-byte blocks: pad the message first`);
    if (mode !== 'ecb' && (!iv || iv.length !== n)) throw new Error(`${name} needs a ${n}-byte IV`);
    const out = new Uint8Array(data.length);
    if (mode === 'ecb') blocksOf(data, n).forEach((b, i) => {
      const c = dec ? E.decrypt(b) : E.encrypt(b); out.set(c, i * n);
      say('ecb', () => `Block ${i + 1}: ${dec ? 'D' : 'E'}_k(${hex(b)}) = ${hex(c)}, on its own: equal blocks give equal results.`, { i, in: b, out: c });
    });
    else if (mode === 'cbc') {
      let prev = iv;
      blocksOf(data, n).forEach((b, i) => {
        if (!dec) { const x = xor(b, prev), c = E.encrypt(x); out.set(c, i * n); say('cbc', () => `Block ${i + 1}: ${hex(b)} ⊕ ${i ? 'C' + i : 'IV'} ${hex(prev)} = ${hex(x)}; E_k gives C${i + 1} = ${hex(c)}.`, { i, p: b, prev, x, c }); prev = c; }
        else { const x = E.decrypt(b), p = xor(x, prev); out.set(p, i * n); say('cbc', () => `Block ${i + 1}: D_k(${hex(b)}) = ${hex(x)}; ⊕ ${i ? 'C' + i : 'IV'} ${hex(prev)} gives P${i + 1} = ${hex(p)}.`, { i, c: b, prev, x, p }); prev = Uint8Array.from(b); }
      });
    } else if (mode === 'cfb') {
      let reg = iv;
      blocksOf(data, n).forEach((b, i) => {
        const ks = E.encrypt(reg), o = xor(b, ks); out.set(o, i * n);
        const c = dec ? b : o;
        say('cfb', () => `Segment ${i + 1}: E_k(${hex(reg)}) = ${hex(ks)}; ${hex(b)} ⊕ that = ${hex(o)}; the ciphertext ${hex(c)} feeds the next segment.`, { i, reg, ks, in: b, out: o });
        reg = c.length === n ? Uint8Array.from(c) : reg;
      });
    } else if (mode === 'cfb8') {
      let reg = iv;
      for (let i = 0; i < data.length; i++) {
        const ks = E.encrypt(reg)[0], o = data[i] ^ ks, c = dec ? data[i] : o;
        out[i] = o;
        if (i < 32) say('cfb8', () => `Byte ${i + 1}: the first byte of E_k(${hex(reg)}) is ${S.bytes.h2(ks)}; ${S.bytes.h2(data[i])} ⊕ ${S.bytes.h2(ks)} = ${S.bytes.h2(o)}; the register shifts one byte left and takes ${S.bytes.h2(c)}.`, { i, reg, ks, in: data[i], out: o });
        const r2 = new Uint8Array(n); r2.set(reg.subarray(1)); r2[n - 1] = c; reg = r2;
      }
    } else if (mode === 'ofb') {
      let reg = iv;
      blocksOf(data, n).forEach((b, i) => {
        reg = E.encrypt(reg); const o = xor(b, reg); out.set(o, i * n);
        say('ofb', () => `Block ${i + 1}: the keystream ${hex(reg)} is E_k of the previous one; ${hex(b)} ⊕ it = ${hex(o)}.`, { i, ks: reg, in: b, out: o });
      });
    } else if (mode === 'ctr') {
      let ctr = iv;
      blocksOf(data, n).forEach((b, i) => {
        const ks = E.encrypt(ctr), o = xor(b, ks); out.set(o, i * n);
        say('ctr', () => `Block ${i + 1}: E_k(counter ${hex(ctr)}) = ${hex(ks.subarray(0, b.length))}; ${hex(b)} ⊕ it = ${hex(o)}.`, { i, ctr, ks, in: b, out: o });
        ctr = inc(ctr);
      });
    } else throw new Error('unknown mode ' + mode);
    return { out, steps, trace };
  };
  Mo.encrypt = (mode, cipher, data, opts = {}) => run(mode, cipher, data, opts, false);
  /** OFB and CTR decrypt exactly as they encrypt; CFB feeds back the incoming ciphertext */
  Mo.decrypt = (mode, cipher, data, opts = {}) => run(mode, cipher, data, opts, true);

  // ---- padding
  Mo.pkcs7 = (data, n = 16) => { const k = n - (data.length % n), o = new Uint8Array(data.length + k); o.set(data); o.fill(k, data.length); return o; };
  Mo.unpkcs7 = (data, n = 16) => {
    const k = data[data.length - 1];
    if (!data.length || data.length % n || k < 1 || k > n) throw new Error('bad padding');
    for (let i = data.length - k; i < data.length; i++) if (data[i] !== k) throw new Error('bad padding');
    return data.slice(0, data.length - k);
  };
  Mo.iso7816 = (data, n = 16) => { const k = n - (data.length % n), o = new Uint8Array(data.length + k); o.set(data); o[data.length] = 0x80; return o; };
  Mo.uniso7816 = (data) => { let i = data.length - 1; while (i >= 0 && data[i] === 0) i--; if (i < 0 || data[i] !== 0x80) throw new Error('bad padding'); return data.slice(0, i); };

  // ---- CBC with ciphertext stealing (the three conventions of the NIST addendum to SP 800-38A)
  Mo.cts = (E, data, iv, { variant = 'CS3', decrypt = false } = {}) => {
    const n = E.n, len = data.length;
    if (len < n) throw new Error('ciphertext stealing needs at least one whole block');
    const d = len % n || n, m = Math.ceil(len / n), trace = [];
    if (!decrypt) {
      const padded = new Uint8Array(m * n); padded.set(data);
      const c = Mo.encrypt('cbc', E, padded, { iv, trace: false }).out;
      if (m === 1) return { out: c, trace: [step('cts', `A single block is plain CBC: ${hex(c)}.`, {})] };
      const head = c.subarray(0, (m - 2) * n), cPrev = c.subarray((m - 2) * n, (m - 2) * n + d), cLast = c.subarray((m - 1) * n);
      const swap = variant === 'CS3' || (variant === 'CS2' && d !== n);
      const out = new Uint8Array(len); out.set(head);
      if (swap) { out.set(cLast, head.length); out.set(cPrev, head.length + n); } else { out.set(cPrev, head.length); out.set(cLast, head.length + d); }
      trace.push(step('cts', `The last block has ${d} byte${d === 1 ? '' : 's'}; it is padded with zeros and CBC runs as usual. The next-to-last ciphertext block is cut to ${d} bytes (${hex(cPrev)}), since its other bytes can be rebuilt by the receiver; ${variant} ${swap ? 'puts the last full block first' : 'keeps the order'}: ${hex(out)}.`, { d, swap }));
      return { out, trace };
    }
    if (m === 1) return { out: Mo.decrypt('cbc', E, data, { iv, trace: false }).out, trace: [] };
    const swap = variant === 'CS3' || (variant === 'CS2' && d !== n), base = (m - 2) * n;
    const cLast = swap ? data.subarray(base, base + n) : data.subarray(base + d, base + d + n);
    const cPrevPart = swap ? data.subarray(base + n) : data.subarray(base, base + d);
    // decrypting the last full block gives (P_m ‖ 0) ⊕ C_(m−1); its tail is the stolen part of C_(m−1)
    const z = E.decrypt(cLast), cPrev = new Uint8Array(n); cPrev.set(cPrevPart); cPrev.set(z.subarray(d), d);
    const pLast = xor(z.subarray(0, d), cPrev.subarray(0, d));
    const front = new Uint8Array(base + n); front.set(data.subarray(0, base)); front.set(cPrev, base);
    const p = Mo.decrypt('cbc', E, front, { iv, trace: false }).out, out = new Uint8Array(len);
    out.set(p); out.set(pLast, base + n);
    trace.push(step('cts', `Decrypting the last full block gives ${hex(z)}; its last ${n - d} bytes restore the stolen part of the block before, and the rest is plain CBC.`, {}));
    return { out, trace };
  };

  /** ECB on an image: every n bytes of pixels form one block, so equal regions give equal (but scrambled) blocks */
  Mo.ecbImage = (E, pixels) => {
    const n = E.n, len = pixels.length - (pixels.length % n), out = Uint8Array.from(pixels), seen = new Map();
    for (let i = 0; i < len; i += n) {
      const c = E.encrypt(pixels.subarray(i, i + n)); out.set(c, i);
      const k = hex(c); seen.set(k, (seen.get(k) || 0) + 1);
    }
    let repeats = 0; for (const v of seen.values()) if (v > 1) repeats += v;
    return { out, distinct: seen.size, blocks: len / n, repeats };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
