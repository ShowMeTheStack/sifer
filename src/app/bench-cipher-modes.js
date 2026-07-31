// The modes of operation over any block cipher of the bench (S.CipherBench.mode), every block with the values on
// every wire: what goes into the cipher, what comes out, what it is XORed with and what is carried to the next block.
// ECB and CBC pad with PKCS#7 (and check and strip it when decrypting); CFB, OFB and CTR are stream modes and need no
// padding: the last block may be short.
//   S.CipherBench.mode(id, cipher, data, iv, decrypt) -> {out, blocks: [{i, p, c, cin, cout, x, chain, ks}], pad, trace}
(function (S) {
  'use strict';
  const CB = (S.CipherBench = S.CipherBench || {});
  const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
  const xor = (a, b) => { const o = new Uint8Array(a.length); for (let i = 0; i < a.length; i++) o[i] = a[i] ^ b[i]; return o; };
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const inc = (ctr) => { const o = ctr.slice(); for (let i = o.length - 1; i >= 0; i--) { o[i] = (o[i] + 1) & 255; if (o[i]) break; } return o; };

  CB.pkcs7 = (data, n) => { const k = n - (data.length % n), o = new Uint8Array(data.length + k); o.set(data); o.fill(k, data.length); return o; };
  CB.unpad = (data, n) => {
    const k = data[data.length - 1];
    if (!data.length || data.length % n) throw new Error('The ciphertext is ' + data.length + ' bytes: in this mode it must be a whole number of ' + n + '-byte blocks.');
    if (!k || k > n || !data.slice(-k).every((v) => v === k)) throw new Error('The padding does not check out (the last byte is ' + k.toString(16).padStart(2, '0') + '): the key or the IV must be wrong, or the ciphertext damaged.');
    return data.slice(0, data.length - k);
  };

  /**
   * The bench runs every mode through the shared engine S.Modes (sym-modes.js), the one the topics use, and only lays
   * its steps out the way the pictures want them. CTS is drawn as the CBC chain it is built on. The layer below
   * (CB.ownMode) is a fallback for a build without S.Modes.
   */
  CB.mode = function (id, E, data, iv, decrypt) {
    const M = S.Modes;
    if (!(M && M.encrypt && M.pkcs7)) { if (id === 'cfb8' || id === 'cts') throw new Error('The ' + id.toUpperCase() + ' engine is not in this build yet.'); return CB.ownMode(id, E, data, iv, decrypt); }
    const n = E.n, trace = [];
    if (id !== 'ecb' && iv.length !== n) throw new Error((id === 'ctr' ? 'The counter block' : 'The IV') + ' must be ' + n + ' bytes, one block; it is ' + iv.length + '.');
    if (id === 'cts') {
      if (data.length < n) throw new Error('CTS must have at least one whole block, ' + n + ' bytes; the input is ' + data.length + '.');
      const r = M.cts(E, data, iv, { variant: 'CS3', decrypt });
      const pt = decrypt ? r.out : data, padded = new Uint8Array(Math.ceil(pt.length / n) * n); padded.set(pt);
      const chain = M.encrypt('cbc', E, padded, { iv });
      const blocks = chain.steps.map((st) => ({ i: st.i, p: st.p, prev: st.prev, x: st.x, cin: st.x, cout: st.c, c: st.c }));
      trace.push(...(chain.trace || []), ...r.trace);
      return { out: r.out, blocks, pad: 0, trace, cts: true };
    }
    let src = data, pad = 0;
    if ((id === 'ecb' || id === 'cbc') && !decrypt) { src = M.pkcs7(data, n); pad = src.length - data.length; trace.push(step('pad', 'PKCS#7 adds ' + pad + ' byte' + (pad === 1 ? '' : 's') + ' of value ' + pad.toString(16).padStart(2, '0') + ', making ' + src.length / n + ' whole blocks of ' + n + ' bytes.', { pad })); }
    if ((id === 'ecb' || id === 'cbc') && decrypt && src.length % n) throw new Error('The ciphertext is ' + src.length + ' bytes: in ' + id.toUpperCase() + ' it must be a whole number of ' + n + '-byte blocks.');
    const r = decrypt ? M.decrypt(id, E, src, { iv }) : M.encrypt(id, E, src, { iv });
    trace.push(...(r.trace || []));
    let prevKs = iv;
    const blocks = r.steps.map((st) => {
      if (id === 'ecb') return { i: st.i, p: st.in, cin: st.in, cout: st.out, c: st.out };
      if (id === 'cbc') return decrypt ? { i: st.i, p: st.c, prev: st.prev, cin: st.c, cout: st.x, x: st.x, c: st.p } : { i: st.i, p: st.p, prev: st.prev, x: st.x, cin: st.x, cout: st.c, c: st.c };
      if (id === 'cfb') return { i: st.i, p: st.in, prev: st.reg, cin: st.reg, cout: st.ks, ks: st.ks.slice(0, st.in.length), c: st.out };
      if (id === 'ofb') { const b = { i: st.i, p: st.in, prev: prevKs, cin: prevKs, cout: st.ks, ks: st.ks.slice(0, st.in.length), c: st.out }; prevKs = st.ks; return b; }
      if (id === 'ctr') return { i: st.i, p: st.in, ctr: st.ctr, cin: st.ctr, cout: st.ks, ks: st.ks.slice(0, st.in.length), c: st.out };
      if (id === 'cfb8') return { i: st.i, p: Uint8Array.of(st.in), cin: st.reg, cout: E.encrypt(st.reg), ks: Uint8Array.of(st.ks), c: Uint8Array.of(st.out), byte: true };
      throw new Error('unknown mode ' + id);
    });
    let out = r.out;
    if ((id === 'ecb' || id === 'cbc') && decrypt) {
      const before = out.length;
      try { out = M.unpkcs7(out, n); } catch (e) { const k = out[out.length - 1] || 0; throw new Error('The padding does not check out (the last byte is ' + k.toString(16).padStart(2, '0') + '): the key or the IV must be wrong, or the ciphertext damaged.'); }
      trace.push(step('unpad', 'The PKCS#7 padding checks out: ' + (before - out.length) + ' byte' + (before - out.length === 1 ? '' : 's') + ' removed.', {}));
    }
    if (id === 'ecb') { const rep = CB.repeats(blocks); if (rep) trace.push(step('ecb-repeat', rep + ' ciphertext block' + (rep === 1 ? ' repeats' : 's repeat') + ' an earlier one: in ECB equal plaintext blocks always give equal ciphertext blocks.', { rep })); }
    return { out, blocks, pad, trace, shared: true, cfb8: id === 'cfb8', total: id === 'cfb8' ? data.length : blocks.length };
  };

  /** the bench's own layer, used only when the shared engine is missing */
  CB.ownMode = function (id, E, data, iv, decrypt) {
    const n = E.n, blocks = [], trace = [];
    let src = data, pad = 0;
    if ((id === 'ecb' || id === 'cbc') && !decrypt) { src = CB.pkcs7(data, n); pad = src.length - data.length; trace.push(step('pad', 'PKCS#7 adds ' + pad + ' byte' + (pad === 1 ? '' : 's') + ' of value ' + pad.toString(16).padStart(2, '0') + ', making ' + src.length / n + ' whole blocks of ' + n + ' bytes.', { pad })); }
    if ((id === 'ecb' || id === 'cbc') && decrypt && src.length % n) throw new Error('The ciphertext is ' + src.length + ' bytes: in ' + id.toUpperCase() + ' it must be a whole number of ' + n + '-byte blocks.');
    if (id !== 'ecb' && iv.length !== n) throw new Error((id === 'ctr' ? 'The counter block' : 'The IV') + ' must be ' + n + ' bytes, one block; it is ' + iv.length + '.');
    let chain = iv.slice(), out = new Uint8Array(src.length);
    for (let i = 0, off = 0; off < src.length; i++, off += n) {
      const p = src.slice(off, off + n), L = p.length;
      let b;
      if (id === 'ecb') {
        const y = decrypt ? E.decrypt(p) : E.encrypt(p);
        b = { i, p, cin: p, cout: y, c: y };
        trace.push(step('ecb', 'Block ' + (i + 1) + ': ' + (decrypt ? 'D' : 'E') + '(' + hex(p) + ') = ' + hex(y) + '.', b));
      } else if (id === 'cbc') {
        if (!decrypt) { const x = xor(p, chain), y = E.encrypt(x); b = { i, p, x, prev: chain, cin: x, cout: y, c: y }; trace.push(step('cbc', 'Block ' + (i + 1) + ': ' + hex(p) + ' ⊕ ' + hex(chain) + ' = ' + hex(x) + ', encrypted to ' + hex(y) + ', which is also carried to the next block.', b)); chain = y; }
        else { const y = E.decrypt(p), x = xor(y, chain); b = { i, p, prev: chain, cin: p, cout: y, x, c: x }; trace.push(step('cbc', 'Block ' + (i + 1) + ': D(' + hex(p) + ') = ' + hex(y) + ', ⊕ ' + hex(chain) + ' = ' + hex(x) + '.', b)); chain = p; }
      } else if (id === 'cfb') {
        const ks = E.encrypt(chain), c = xor(p, ks.slice(0, L));
        b = { i, p, prev: chain, cin: chain, cout: ks, ks: ks.slice(0, L), c };
        trace.push(step('cfb', 'Block ' + (i + 1) + ': E(' + hex(chain) + ') = ' + hex(ks) + '; ' + hex(p) + ' ⊕ it = ' + hex(c) + '.', b));
        chain = decrypt ? p : c;
      } else if (id === 'ofb') {
        const ks = E.encrypt(chain), c = xor(p, ks.slice(0, L));
        b = { i, p, prev: chain, cin: chain, cout: ks, ks: ks.slice(0, L), c };
        trace.push(step('ofb', 'Block ' + (i + 1) + ': E(' + hex(chain) + ') = ' + hex(ks) + ' is the keystream; ' + hex(p) + ' ⊕ it = ' + hex(c) + '.', b));
        chain = ks;
      } else if (id === 'ctr') {
        const ks = E.encrypt(chain), c = xor(p, ks.slice(0, L));
        b = { i, p, ctr: chain, cin: chain, cout: ks, ks: ks.slice(0, L), c };
        trace.push(step('ctr', 'Block ' + (i + 1) + ': the counter ' + hex(chain) + ' encrypts to ' + hex(ks) + '; ' + hex(p) + ' ⊕ it = ' + hex(c) + '.', b));
        chain = inc(chain);
      } else throw new Error('unknown mode ' + id);
      out.set(b.c, off);
      blocks.push(b);
    }
    if ((id === 'ecb' || id === 'cbc') && decrypt) { const before = out.length; out = CB.unpad(out, n); trace.push(step('unpad', 'The PKCS#7 padding checks out: ' + (before - out.length) + ' byte' + (before - out.length === 1 ? '' : 's') + ' removed.', {})); }
    if (id === 'ecb') {
      const seen = new Map(); let rep = 0;
      for (const b of blocks) { const k = hex(b.c); if (seen.has(k)) rep++; else seen.set(k, b.i); }
      if (rep) trace.push(step('ecb-repeat', rep + ' ciphertext block' + (rep === 1 ? ' repeats' : 's repeat') + ' an earlier one: in ECB equal plaintext blocks always give equal ciphertext blocks.', { rep }));
    }
    return { out, blocks, pad, trace };
  };

  /**
   * GCM and XTS, the two AES-only modes, from their engines (S.GCM, S.XTS), laid out block by block like the rest.
   * GCM: iv is the 12-byte nonce, aad the associated data; decrypting takes ciphertext ‖ tag and checks the tag.
   * XTS: the key is two AES keys (32 or 64 bytes), iv is the 16-byte tweak (the sector number).
   */
  CB.aesMode = function (id, key, data, iv, decrypt, aad) {
    const trace = [];
    if (id === 'gcm') {
      need(S.GCM, 'GCM');
      if (iv.length !== 12) throw new Error('The GCM nonce must be 12 bytes; it is ' + iv.length + '.');
      let ct = data, tag = null, r;
      if (decrypt) {
        if (data.length < 16) throw new Error('The input must be the ciphertext followed by its 16-byte tag: it is only ' + data.length + ' bytes.');
        ct = data.slice(0, data.length - 16); tag = data.slice(data.length - 16);
        r = S.GCM.decrypt(key, iv, ct, tag, aad);
        if (!r.ok) throw new Error('The tag does not match: the ciphertext, the associated data, the nonce or the key must be different from the ones it was made with, so GCM releases no plaintext.');
      }
      const e = S.GCM.encrypt(key, iv, decrypt ? r.pt : data, aad, { trace: true });
      const E = S.AES.cipher(key), blocks = [];
      const pt = decrypt ? r.pt : data;
      let ctr = e.J0;
      for (let i = 0, off = 0; off < pt.length; i++, off += 16) {
        ctr = S.GCM.inc32(ctr);
        const ks = E.encrypt(ctr), p = (decrypt ? ct : pt).slice(off, off + 16), c = xor(p, ks.slice(0, p.length));
        blocks.push({ i, p, ctr, cin: ctr, cout: ks, ks: ks.slice(0, p.length), c });
      }
      trace.push(...e.trace);
      if (decrypt) trace.push(step('gcm-ok', 'The tag ' + hex(tag) + ' checks out, so the plaintext is released.', {}));
      const out = decrypt ? r.pt : Uint8Array.from([...e.ct, ...e.tag]);
      return { out, blocks, pad: 0, trace, tag: e.tag, H: e.H, J0: e.J0, gcm: true };
    }
    if (id === 'xts') {
      need(S.XTS, 'XTS');
      if (key.length !== 32 && key.length !== 64) throw new Error('An XTS key must be two AES keys, 32 or 64 bytes; it is ' + key.length + '.');
      if (iv.length !== 16) throw new Error('The tweak must be 16 bytes (the sector number, little-endian); it is ' + iv.length + '.');
      if (data.length < 16) throw new Error('An XTS sector must be at least one block, 16 bytes; it is ' + data.length + '.');
      const r = decrypt ? S.XTS.decrypt(key, iv, data) : S.XTS.encrypt(key, iv, data);
      const k1 = key.slice(0, key.length / 2), E = S.AES.cipher(k1), blocks = [];
      const full = Math.floor(data.length / 16), steal = data.length % 16 ? 2 : 0;
      for (let i = 0; i < full; i++) {
        const T = (r.tweaks || [])[i], p = data.slice(16 * i, 16 * i + 16), c = r.out.slice(16 * i, 16 * i + 16);
        const stolen = steal && i >= full - 1;
        blocks.push({ i, p, T, cin: T ? xor(p, T) : p, cout: T ? (decrypt ? E.decrypt(xor(p, T)) : E.encrypt(xor(p, T))) : c, c, stolen });
      }
      if (steal) blocks.push({ i: full, p: data.slice(16 * full), c: r.out.slice(16 * full), T: (r.tweaks || [])[full] || null, stolen: true, cin: data.slice(16 * full), cout: r.out.slice(16 * full) });
      return { out: r.out, blocks, pad: 0, trace: r.trace || [], cipherKey: k1, xts: true };
    }
    throw new Error('unknown mode ' + id);
  };
  const need = (x, what) => { if (!x) throw new Error('The ' + what + ' engine is not in this build yet.'); };
  /** how many ciphertext blocks repeat an earlier block (ECB's tell) */
  CB.repeats = (blocks) => { const seen = new Set(); let r = 0; for (const b of blocks) { const k = hex(b.c); if (seen.has(k)) r++; seen.add(k); } return r; };
})(globalThis.Sifer = globalThis.Sifer || {});
