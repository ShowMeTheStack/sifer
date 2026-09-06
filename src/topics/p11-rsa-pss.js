// Part 11, RSA-PSS step by step: the salted hash H, the mask MGF1(H) built from counter blocks, the data block it hides,
// the encoded block EM drawn to scale, the signature EM^d mod n, and the verifier taking it all apart again. A second
// salt gives a second, different signature on the same message; a changed message fails at the final hash.
(function (S) {
  'use strict';
  const W = S.P11, NT = () => S.NT, KP = () => S.Kit.pk;
  const KEYS = [{ value: 'rsa1024', label: 'RSA-1024' }, { value: 'rsa2048', label: 'RSA-2048' }, { value: 'rsa3072', label: 'RSA-3072' }];
  const SUB = (i) => String(i).split('').map((d) => '₀₁₂₃₄₅₆₇₈₉'[d]).join('');

  S.topic({
    id: 'p11-pss', family: 'p11-rsa', order: 20, title: 'RSA-PSS: encode, sign, verify',
    blurb: 'PSS hashes the message, hashes it again with a salt to get H, stretches H into a mask with MGF1 (SHA-256 of H and a counter, block after block), hides the zeros, the 01 and the salt under it, and ends with bc. The block fills the whole modulus, so RSA\'s algebra finds nothing to exploit. The verifier undoes each step and recomputes H.',
    inputs: [
      { id: 'key', kind: 'choice', label: 'Key', def: 'rsa2048', options: KEYS },
      W.textIn('msg', 'Message', 'approve purchase order 5521'),
      { id: 'salt', kind: 'hex', label: 'Salt (hex, up to 32 bytes; empty for none)', def: W.hex(W.sha256('a salt for order 5521')), max: 32 },
    ],
    presets: [
      { label: 'RSA-2048, 32-byte salt', values: { key: 'rsa2048', msg: 'approve purchase order 5521', salt: W.hex(W.sha256('a salt for order 5521')) } },
      { label: 'RSA-1024, 20-byte salt', values: { key: 'rsa1024', msg: 'open the east gate at noon', salt: W.hex(W.sha256('twenty bytes of salt')).slice(0, 40) } },
      { label: 'RSA-2048, no salt', values: { key: 'rsa2048', msg: 'approve purchase order 5521', salt: '' } },
      { label: 'RSA-3072', values: { key: 'rsa3072', msg: 'archive the 2025 ledgers', salt: W.hex(W.sha256('salt for the ledgers')) } },
    ],
    counters: [{ id: 'hash', label: 'SHA-256 calls' }],
    run(inp) { return W.memo('p11-pss', inp, () => pss(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'check', pick: 'option', ask: 'Sign the same message again with a different salt. Is the new signature the same number?', options: ['yes', 'no, but it verifies too'], answer: (fr, i) => (fr[i + 1].facts.same ? 'yes' : 'no, but it verifies too'), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'mask', pick: 'option', ask: (fr, i) => `The mask must cover DB, ${fr[i + 1].facts.dbLen} bytes. How many SHA-256 blocks does MGF1 need?`, options: (fr, i) => { const c = fr[i + 1].facts.blocks; return [String(c - 1), String(c), String(c + 1)]; }, answer: (fr, i) => String(fr[i + 1].facts.blocks), explain: (fr, i) => fr[i + 1].facts.why },
    ],
    quiz: [
      { q: 'What does MGF1(H, L) compute?', options: ['SHA-256(H ‖ 0) ‖ SHA-256(H ‖ 1) ‖ … cut to L bytes', 'H repeated L times', 'an RSA encryption of H', 'HMAC with key H'], answer: 0, why: 'A counter of four bytes is appended to H and hashed, block after block.' },
      { q: 'Where does the verifier find the salt?', options: ['in a separate field', 'at the end of DB, after unmasking it with MGF1(H)', 'in the bc byte', 'it never needs it'], answer: 1, why: 'H travels in the clear inside EM, so the verifier can rebuild the mask and read DB.' },
      { q: 'What is the final test of PSS verification?', options: ['SHA-256(00×8 ‖ mHash ‖ salt) equals the H in EM', 'the salt is random', 'EM is prime', 's < n'], answer: 0, why: 'All the earlier checks are on format; this one ties the block to the message.' },
      { q: 'With an empty salt, PSS signatures are…', options: ['deterministic but still secure', 'insecure', 'longer', 'impossible'], answer: 0, why: 'The salt gives randomness and a tighter proof; without it the same message always gives the same signature.' },
      { q: 'Why is the top bit of EM cleared?', options: ['so EM, read as a number, is below n', 'to mark the salt', 'for speed', 'it is the bc byte'], answer: 0, why: 'emBits = modBits − 1, so the encoded block always lies below the modulus.' },
    ],
  });

  function pss(inp) {
    const key = S.PK.rsaKey(inp.key), modBits = NT().bitLength(key.n), emBits = modBits - 1, emLen = Math.ceil(emBits / 8), k = NT().byteLength(key.n);
    const salt = W.unhex(inp.salt), sl = salt.length, msg = String(inp.msg);
    const enc = S.RSA.pssEncode(msg, emBits, { salt }), sig = S.RSA.pssSign(key, msg, { salt });
    const ver = S.RSA.pssVerify(key, msg, sig.s, { saltLength: sl }), bad = S.RSA.pssVerify(key, msg + '!', sig.s, { saltLength: sl });
    const salt2 = W.sha256(W.cat(salt, W.utf8('again'))).slice(0, sl), sig2 = S.RSA.pssSign(key, msg, { salt: salt2 }), ver2 = S.RSA.pssVerify(key, msg, sig2.s, { saltLength: sl });
    const dbLen = emLen - 33, psLen = dbLen - sl - 1, blocks = Math.ceil(dbLen / 32), lastB = dbLen - 32 * (blocks - 1), clear = 8 * emLen - emBits;
    const emBack = NT().toBytes(NT().pow(sig.s, key.e, key.n), emLen), emSame = W.hex(emBack) === W.hex(enc.em);
    const hx = (b, n) => W.hx(b, n || 4), all = W.hex;
    const F = new S.Frames(['hash']);
    const X0 = 40, WID = 830, sc = WID / emLen;
    // a field of a bar: its text only when it fits
    const seg = (id, bytes, text, cls, title, minW) => { const w = Math.max(minW || 0, bytes * sc); const fit = S.geom.textWidth(text, 13, { mono: true }) + 10 <= w; return { id, w, text: fit ? text : '', cls, title, sub: undefined }; };
    const bar = (prefix, y, segs) => KP().bar({ prefix, x: X0, y, h: 34, segs });
    const lab = (key, y, text) => W.t(key, X0, y - 9, text, 'strong', 'start', 14);
    const YA = 40, YB = 118, YC = 214, YD = 290, YE = 372, YF = 462;
    // row A: message, mHash, salt
    const rowA = (st, tam) => [W.hb('am', 110, YA, 'message', '"' + W.hs(tam ? msg + '!' : msg, 7) + '"', tam ? 'bad' : '', 190, msg), W.box('ah', 285, YA, 92, 40, ['SHA-256'], 'cipher'), W.hb('amh', 470, YA, 'mHash', hx(tam ? W.sha256(msg + '!') : enc.mHash), tam ? 'bad' : 'act', 180, 'mHash = ' + all(enc.mHash)), W.edge('ea1', 'am', 'ah'), W.edge('ea2', 'ah', 'amh')]
      .concat(st >= 1 ? [W.hb('as', 740, YA, sl ? 'salt, ' + sl + ' bytes' : 'salt', sl ? hx(salt) : '(empty)', 'key', 200, 'salt = ' + (all(salt) || 'empty'))] : []);
    const mprime = () => [lab('lb', YB, 'M′ = 00×8 ‖ mHash ‖ salt'), ...KP().bar({ prefix: 'mp', x: X0, y: YB, h: 34, segs: [{ id: 'z', w: 92, text: '00×8', cls: 'zero' }, { id: 'h', w: 160, text: 'mHash', cls: 'hash' }].concat(sl ? [{ id: 's', w: 140, text: 'salt', cls: 'seed' }] : []) }).items];
    const mpEnd = X0 + 92 + 160 + (sl ? 140 : 0);
    const rowB = (cls) => [...mprime(), W.box('bh', mpEnd + 95, YB + 17, 92, 40, ['SHA-256'], 'cipher'), W.wire('wb1', [[mpEnd, YB + 17], [mpEnd + 49, YB + 17]]), W.hb('bH', 760, YB + 17, 'H', hx(enc.H), cls || 'act', 190, 'H = ' + all(enc.H)), W.wire('wb2', [[mpEnd + 141, YB + 17], [665, YB + 17]])];
    const mgf = (cls) => {
      const segs = [];
      for (let i = 0; i < blocks; i++) segs.push({ id: 'T' + i, w: (i === blocks - 1 ? lastB : 32) * sc, text: 'T' + SUB(i), cls: 'mask ' + (cls || ''), title: 'T' + i + ' = SHA-256(H ‖ ' + i.toString(16).padStart(8, '0') + ')' });
      return [lab('lc', YC, `dbMask = MGF1(H, ${dbLen}): Tᵢ = SHA-256(H ‖ i), ${blocks} blocks`), ...bar('mg', YC, segs).items];
    };
    const dbBar = (cls) => [lab('ld', YD, `DB = ${psLen} zero bytes ‖ 01 ‖ salt`), ...bar('db', YD, [seg('ps', psLen - (26 / sc > 1 ? Math.ceil(26 / sc) - 1 : 0), '00 … 00', 'zero ' + (cls || ''), psLen + ' zero bytes'), seg('one', 1, '01', 'sep ' + (cls || ''), 'the 01 separator', 26)].concat(sl ? [seg('s', sl, 'salt', 'seed ' + (cls || ''), 'salt = ' + all(salt))] : [])).items];
    const emBar = (c1, c2, c3) => [lab('le', YE, `EM = maskedDB ‖ H ‖ bc, ${emLen} bytes`), ...bar('em', YE, [seg('m', dbLen - (26 / sc > 1 ? Math.ceil(26 / sc) - 1 : 0), 'maskedDB ' + hx(enc.maskedDB, 3), 'mask ' + (c1 || ''), 'maskedDB = ' + all(enc.maskedDB)), seg('h', 32, 'H', 'hash ' + (c2 || ''), 'H = ' + all(enc.H)), seg('bc', 1, 'bc', 'sep ' + (c3 || ''), 'the trailer bc', 26)]).items, { key: 'xo', kind: 'op', x: 20, y: (YD + 34 + YE) / 2, r: 10, op: 'xor', cls: '' }];
    const sBlk = (cls) => W.vb('fs', 230, YF, 's = EM^d mod n', sig.s, cls || 'key', 300, 18);
    const vBlk = (cls, label) => W.vb('fv', 660, YF, label || 's^e mod n, as ' + emLen + ' bytes', NT().fromBytes(emBack), cls || 'good', 300, 18);
    const add = (items, say, facts, meta) => F.add({ items, say, facts: Object.assign({ msg, sl, emLen }, facts), meta });

    F.count('hash');
    add(rowA(0), `Sign "${msg}" with ${W.rsaName(inp.key)} (n of ${modBits} bits). First mHash = SHA-256(message) = ${hx(enc.mHash, 8)}.`, { modBits, mh: hx(enc.mHash, 8) }, { phase: 'mhash' });
    add(rowA(1), sl ? `A salt of ${sl} bytes, ${hx(salt, 8)}: in use it is fresh and random for every signature (it is given here so the run repeats).` : 'The salt is empty here. PSS still works, but the same message will always give the same signature.', { salt: hx(salt, 8) }, { phase: 'salt' });
    F.count('hash');
    add([...rowA(1), ...rowB()], `M′ = eight zero bytes ‖ mHash ‖ salt, ${8 + 32 + sl} bytes, and H = SHA-256(M′) = ${hx(enc.H, 8)}. H is the heart of the signature: the verifier must arrive at the same ${32} bytes.`, { mp: 8 + 32 + sl, h: hx(enc.H, 8), hl: 32, z: 8 }, { phase: 'h' });
    F.count('hash', blocks);
    const why = `DB has ${emLen} − 32 − 1 = ${dbLen} bytes and each SHA-256 block gives 32, so ⌈${dbLen}/32⌉ = ${blocks} blocks, the last cut to ${lastB} bytes.`;
    add([...rowA(1), ...rowB(), ...mgf('')], `MGF1 stretches H into a mask as long as DB: T₀ = SHA-256(H ‖ 00000000), T₁ = SHA-256(H ‖ 00000001), and so on. ${why}`, { dbLen, blocks, lastB, why, hl: 32 }, { phase: 'mask' });
    add([...rowA(1), ...rowB(), ...mgf(''), ...dbBar('')], `The data block DB = ${psLen} zero bytes, the separator 01, then the salt: ${dbLen} bytes, lined up under the mask.`, { psLen, dbLen }, { phase: 'db' });
    add([...rowA(1), ...rowB(), ...mgf(''), ...dbBar(''), ...emBar('', '', '')], `maskedDB = DB ⊕ dbMask = ${hx(enc.maskedDB, 8)}${clear ? `, with the top ${clear === 1 ? 'bit' : clear + ' bits'} cleared so EM stays below n` : ''}. EM = maskedDB ‖ H ‖ bc: ${emLen} bytes in which nothing but H and bc is visible.`, { mdb: hx(enc.maskedDB, 8), clear }, { phase: 'em' });
    add([...rowA(1), ...rowB(), ...mgf(''), ...dbBar(''), ...emBar('', '', ''), sBlk()], `The signature is s = EM^d mod n = ${W.n(sig.s)}, ${k} bytes. Only the holder of d can make it.`, { s: sig.s, k }, { phase: 'sign' });
    add([...rowA(1), ...rowB(), ...mgf(''), ...dbBar(''), ...emBar('good', 'good', 'good'), sBlk(), vBlk(emSame ? 'good' : 'bad')], `The verifier has the message, s and the public key. s^e mod n, written as ${emLen} bytes, gives back EM${emSame ? ' exactly' : ''}; its last byte is bc and its top bit is 0, so the format is right so far.`, { e: key.e }, { phase: 'open' });
    F.count('hash', blocks);
    add([...rowA(1), ...rowB('good'), ...mgf('good'), ...dbBar('good'), ...emBar('good', 'good', 'good'), sBlk(), vBlk('good')], `It takes H from EM, rebuilds the same ${blocks} MGF1 blocks from it, and unmasks DB: ${psLen} zero bytes, then 01, then the salt ${sl ? hx(salt, 8) : '(empty)'}. A block that does not have this shape is rejected here.`, { blocks, psLen, salt: hx(salt, 8) }, { phase: 'unmask' });
    F.count('hash', 2);
    const hv = ver.trace.find((t) => t.kind === 'accept' || t.kind === 'reject');
    add([...rowA(1), ...rowB('good'), ...mgf('good'), ...dbBar('good'), ...emBar('good', 'good', 'good'), sBlk('good'), vBlk('good'), W.verdict('fok', 450, YF + 52, ver.ok, ver.ok ? 'H′ = H: valid' : 'invalid')], `Finally it recomputes H′ = SHA-256(00×8 ‖ SHA-256(message) ‖ salt) = ${hv && hv.H ? hx(hv.H, 8) : '?'} and compares it with H: ${ver.ok ? 'equal, so the signature is valid' : 'different, so it is rejected'}.`, { hv: hv && hv.H ? hx(hv.H, 8) : '', ok: ver.ok, z: 8 }, { phase: 'check' });
    const same = sig2.s === sig.s;
    add([...rowA(1), ...rowB(), ...mgf(''), ...dbBar(''), ...emBar('', '', ''), W.vb('fs', 230, YF, 's, first salt', sig.s, 'key', 300, 18), W.vb('fv', 660, YF, 's′, second salt', sig2.s, ver2.ok ? 'good' : 'bad', 300, 18)], sl ? `Signing the same message again with another salt, ${hx(salt2, 8)}, changes H, the mask and EM, so s′ = ${W.n(sig2.s)} ${same ? 'equals' : 'differs from'} s. It verifies too (${ver2.ok ? 'valid' : 'invalid'}): two signatures of one message cannot be linked by comparing them.` : `With no salt, signing again gives s′ = ${W.n(sig2.s)}, ${same ? 'the same number as before' : 'a different number'}: PSS without a salt is deterministic. It verifies (${ver2.ok ? 'valid' : 'invalid'}).`, { s2: sig2.s, same, ok2: ver2.ok, salt2: hx(salt2, 8) }, { phase: 'salt2' });
    add([...rowA(1, true), ...rowB('bad'), ...mgf('good'), ...dbBar('good'), ...emBar('good', 'bad', 'good'), sBlk(), vBlk('good'), W.verdict('fok', 450, YF + 52, bad.ok, bad.ok ? 'valid' : 'H′ ≠ H: rejected')], `Change the message to "${msg}!" and check the old s: EM, the mask and the salt all come out as before, but mHash changes, so H′ no longer equals H: ${bad.ok ? 'accepted' : 'rejected'}. ${bad.reason ? 'Reason: ' + bad.reason + '.' : ''}`, { ok: bad.ok }, { phase: 'tamper' });

    const fr = W.fix(F.list, { x: 0, y: 0, w: 900, h: 520 });
    for (const f of fr) f.narrowView = /^(mhash|salt|h)$/.test(f.meta.phase) ? { x: 0, y: 0, w: 900, h: 260 } : { x: 0, y: 180, w: 900, h: 340 };
    return { frames: fr, def: W.def('RSA-PSS (PKCS #1 v2.2, SHA-256)', ['mHash = SHA-256(M)', 'H = SHA-256(00×8 ‖ mHash ‖ salt)', 'DB = 00 … 00 ‖ 01 ‖ salt', 'dbMask = MGF1(H): SHA-256(H ‖ i), i = 0, 1, …', 'EM = (DB ⊕ dbMask) ‖ H ‖ bc', 's = EM^d mod n', 'verify: undo, then SHA-256(00×8 ‖ mHash ‖ salt) = H ?']) };
  }
})(globalThis.Sifer = globalThis.Sifer || {});
