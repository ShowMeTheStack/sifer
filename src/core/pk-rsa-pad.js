// RSA padding as PKCS #1 v2.2 (RFC 8017) defines it, with SHA-256 throughout: the mask generator MGF1, OAEP for
// encryption and PSS for signatures. Each returns the encoded block field by field so a picture can lay out
// 00 | maskedSeed | maskedDB and maskedDB | H | bc, and say which bytes the masks changed.
//   S.RSA.mgf1(seed, len) -> bytes                         SHA-256(seed ‖ counter) blocks, cut to len
//   S.RSA.oaepEncode(msg, k[, {label, seed}]) -> {em, lHash, db, seed, dbMask, maskedDB, seedMask, maskedSeed, trace}
//   S.RSA.oaepDecode(em, k[, {label}]) -> {msg, trace}     throws 'decryption error' on a bad block
//   S.RSA.oaepEncrypt(pub, msg[, opts]) -> {c, cBytes, encoding, trace};  oaepDecrypt(key, c[, opts]) -> {msg, trace}
//   S.RSA.pssEncode(msg, emBits[, {salt, saltLength}]) -> {em, mHash, salt, H, db, dbMask, maskedDB, trace}
//   S.RSA.pssVerifyEncoding(msg, em, emBits[, {saltLength}]) -> {ok, salt, reason, trace}
//   S.RSA.pssSign(key, msg[, opts]) -> {s, sBytes, encoding, trace};  pssVerify(pub, msg, sig[, opts]) -> {ok, reason, trace}
(function (S) {
  'use strict';
  const N = () => S.NT;
  const H = (b) => S.SHA256.hash(b);
  const hLen = 32;
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const R = (S.RSA = S.RSA || {});
  const hex = (b, max = 24) => { const s = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(''); return s.length > max * 2 ? s.slice(0, max) + '…' + s.slice(-16) + ` (${b.length} bytes)` : s; };
  const cat = (...parts) => { const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
  const xor = (a, b) => a.map((v, i) => v ^ b[i]);
  const bytes = (m) => (typeof m === 'string' ? new TextEncoder().encode(m) : Uint8Array.from(m));
  R.hexShort = hex;

  R.mgf1 = (seed, len) => {
    const out = new Uint8Array(len);
    for (let c = 0, o = 0; o < len; c++, o += hLen) {
      const h = H(cat(seed, Uint8Array.of(c >>> 24, (c >>> 16) & 255, (c >>> 8) & 255, c & 255)));
      out.set(h.subarray(0, Math.min(hLen, len - o)), o);
    }
    return out;
  };

  R.oaepEncode = (msg, k, opts = {}) => {
    msg = bytes(msg);
    const label = bytes(opts.label || []), trace = [];
    if (msg.length > k - 2 * hLen - 2) throw new Error(`message too long: at most ${k - 2 * hLen - 2} bytes fit a ${k}-byte modulus`);
    const lHash = H(label), ps = new Uint8Array(k - msg.length - 2 * hLen - 2);
    const db = cat(lHash, ps, Uint8Array.of(1), msg);
    trace.push(step('db', `DB = lHash ‖ ${ps.length} zero bytes ‖ 01 ‖ message: ${db.length} bytes, lHash = SHA-256(label) = ${hex(lHash, 8)}.`, { lHash, ps: ps.length, db }));
    const seed = opts.seed ? bytes(opts.seed) : N().randomBytes(hLen);
    trace.push(step('seed', `A fresh random seed of ${hLen} bytes: ${hex(seed, 8)}.`, { seed }));
    const dbMask = R.mgf1(seed, k - hLen - 1), maskedDB = xor(db, dbMask);
    trace.push(step('mask-db', `maskedDB = DB ⊕ MGF1(seed, ${dbMask.length}) = ${hex(maskedDB, 8)}: every byte of DB now looks random.`, { dbMask, maskedDB }));
    const seedMask = R.mgf1(maskedDB, hLen), maskedSeed = xor(seed, seedMask);
    trace.push(step('mask-seed', `maskedSeed = seed ⊕ MGF1(maskedDB, ${hLen}) = ${hex(maskedSeed, 8)}.`, { seedMask, maskedSeed }));
    const em = cat(Uint8Array.of(0), maskedSeed, maskedDB);
    trace.push(step('em', `EM = 00 ‖ maskedSeed ‖ maskedDB, ${em.length} bytes; the leading 00 keeps it below n.`, { em }));
    return { em, lHash, db, seed, dbMask, maskedDB, seedMask, maskedSeed, trace };
  };
  R.oaepDecode = (em, k, opts = {}) => {
    const label = bytes(opts.label || []), trace = [];
    if (em.length !== k || k < 2 * hLen + 2) throw new Error('decryption error');
    const maskedSeed = em.subarray(1, 1 + hLen), maskedDB = em.subarray(1 + hLen);
    const seed = xor(maskedSeed, R.mgf1(maskedDB, hLen)), db = xor(maskedDB, R.mgf1(seed, k - hLen - 1));
    trace.push(step('unmask', `Undo the masks in reverse order: seed = ${hex(seed, 8)}, then DB = ${hex(db, 8)}.`, { seed, db }));
    const lHash = H(label);
    let bad = em[0] !== 0, i = hLen;
    for (let j = 0; j < hLen; j++) bad = bad || db[j] !== lHash[j];
    while (i < db.length && db[i] === 0) i++;
    if (i >= db.length || db[i] !== 1) bad = true;
    if (bad) { trace.push(step('reject', 'The block does not have the form 00 ‖ … ‖ lHash ‖ 00…00 ‖ 01 ‖ M: reject it.')); throw Object.assign(new Error('decryption error'), { trace }); }
    const msg = db.slice(i + 1);
    trace.push(step('message', `lHash matches and the 01 separator is at byte ${i} of DB, so the message is ${hex(msg)}.`, { msg, at: i }));
    return { msg, trace };
  };
  R.oaepEncrypt = (pub, msg, opts = {}) => {
    const k = N().byteLength(pub.n), enc = R.oaepEncode(msg, k, opts);
    const c = N().pow(N().fromBytes(enc.em), pub.e, pub.n);
    const trace = enc.trace.concat([step('encrypt', `c = EM^e mod n = ${N().short(c)}.`, { c })]);
    return { c, cBytes: N().toBytes(c, k), encoding: enc, trace };
  };
  R.oaepDecrypt = (key, c, opts = {}) => {
    const k = N().byteLength(key.n);
    if (c instanceof Uint8Array || Array.isArray(c)) c = N().fromBytes(c);
    if (c >= key.n) throw new Error('decryption error');
    const m = key.p ? R.decryptCRT(c, key).value : N().pow(c, key.d, key.n);
    const em = N().toBytes(m, k), dec = R.oaepDecode(em, k, opts);
    return { msg: dec.msg, em, trace: [step('decrypt', `EM = c^d mod n, written as ${k} bytes: ${hex(em, 8)}.`, { em })].concat(dec.trace) };
  };

  R.pssEncode = (msg, emBits, opts = {}) => {
    msg = bytes(msg);
    const emLen = Math.ceil(emBits / 8), sLen = opts.salt ? opts.salt.length : opts.saltLength == null ? hLen : opts.saltLength, trace = [];
    if (emLen < hLen + sLen + 2) throw new Error('encoding error: the modulus is too short for this salt');
    const mHash = H(msg), salt = opts.salt ? bytes(opts.salt) : N().randomBytes(sLen);
    trace.push(step('hash', `mHash = SHA-256(message) = ${hex(mHash, 8)}; salt = ${sLen ? hex(salt, 8) : 'empty'}.`, { mHash, salt }));
    const mPrime = cat(new Uint8Array(8), mHash, salt), h = H(mPrime);
    trace.push(step('h', `H = SHA-256(00×8 ‖ mHash ‖ salt) = ${hex(h, 8)}.`, { mPrime, H: h }));
    const db = cat(new Uint8Array(emLen - sLen - hLen - 2), Uint8Array.of(1), salt);
    const dbMask = R.mgf1(h, emLen - hLen - 1), maskedDB = xor(db, dbMask);
    const clear = 8 * emLen - emBits;
    maskedDB[0] &= 0xff >> clear;
    trace.push(step('mask', `DB = zeros ‖ 01 ‖ salt (${db.length} bytes), masked with MGF1(H): ${hex(maskedDB, 8)}${clear ? `; the top ${clear} bit${clear > 1 ? 's are' : ' is'} cleared so EM < n` : ''}.`, { db, dbMask, maskedDB, clear }));
    const em = cat(maskedDB, h, Uint8Array.of(0xbc));
    trace.push(step('em', `EM = maskedDB ‖ H ‖ bc, ${em.length} bytes.`, { em }));
    return { em, mHash, salt, H: h, db, dbMask, maskedDB, trace };
  };
  R.pssVerifyEncoding = (msg, em, emBits, opts = {}) => {
    msg = bytes(msg);
    const emLen = Math.ceil(emBits / 8), trace = [], fail = (reason) => { trace.push(step('reject', `Reject: ${reason}.`)); return { ok: false, reason, trace }; };
    if (em.length !== emLen) return fail('the encoded block has the wrong length');
    if (em[emLen - 1] !== 0xbc) return fail('the last byte is not bc');
    const maskedDB = em.subarray(0, emLen - hLen - 1), h = em.subarray(emLen - hLen - 1, emLen - 1), clear = 8 * emLen - emBits;
    if (maskedDB[0] & ~(0xff >> clear) & 0xff) return fail('the top bits are not zero');
    const db = xor(maskedDB, R.mgf1(h, emLen - hLen - 1));
    db[0] &= 0xff >> clear;
    let i = 0;
    while (i < db.length && db[i] === 0) i++;
    if (i >= db.length || db[i] !== 1) return fail('DB has no 01 separator after the zeros');
    const salt = db.slice(i + 1);
    if (opts.saltLength != null && salt.length !== opts.saltLength) return fail(`the salt has ${salt.length} bytes, not ${opts.saltLength}`);
    trace.push(step('salt', `Unmasking DB with MGF1(H) gives the salt ${hex(salt, 8)}.`, { salt }));
    const h2 = H(cat(new Uint8Array(8), H(msg), salt)), ok = h2.every((v, j) => v === h[j]);
    trace.push(step(ok ? 'accept' : 'reject', ok ? `SHA-256(00×8 ‖ mHash ‖ salt) = ${hex(h2, 8)} equals H: the signature is valid.` : `SHA-256(00×8 ‖ mHash ‖ salt) = ${hex(h2, 8)} differs from H = ${hex(h, 8)}: invalid.`, { H: h2 }));
    return { ok, salt, reason: ok ? null : 'the hash does not match', trace };
  };
  R.pssSign = (key, msg, opts = {}) => {
    const modBits = N().bitLength(key.n), k = N().byteLength(key.n), enc = R.pssEncode(msg, modBits - 1, opts);
    const m = N().fromBytes(enc.em), s = key.p ? R.decryptCRT(m, key).value : N().pow(m, key.d, key.n);
    return { s, sBytes: N().toBytes(s, k), encoding: enc, trace: enc.trace.concat([step('sign', `s = EM^d mod n = ${N().short(s)}.`, { s })]) };
  };
  R.pssVerify = (pub, msg, sig, opts = {}) => {
    const modBits = N().bitLength(pub.n), emLen = Math.ceil((modBits - 1) / 8);
    const s = sig instanceof Uint8Array || Array.isArray(sig) ? N().fromBytes(sig) : BigInt(sig);
    if (s >= pub.n) return { ok: false, reason: 'the signature is not below n', trace: [] };
    const m = N().pow(s, pub.e, pub.n);
    if (N().bitLength(m) > modBits - 1) return { ok: false, reason: 'the recovered block is too long', trace: [] };
    const em = N().toBytes(m, emLen), r = R.pssVerifyEncoding(msg, em, modBits - 1, opts);
    r.trace.unshift(step('open', `s^e mod n written as ${emLen} bytes: EM = ${hex(em, 8)}.`, { em }));
    return r;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
