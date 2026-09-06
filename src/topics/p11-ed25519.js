// Part 11, Ed25519 (RFC 8032) step by step: the 32-byte seed hashed with SHA-512 into a scalar half and a prefix half,
// the scalar clamped bit by bit, the public key A = a·B, the nonce r hashed from the prefix and the message, R = r·B,
// the challenge k from R ‖ A ‖ M, S = r + k·a mod L, and the verifier's cofactor check [8][S]B = [8]R + [8][k]A.
(function (S) {
  'use strict';
  const W = S.P11, ED = () => S.ECC.Ed25519;
  const RFC = [
    { seed: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', msg: '' },
    { seed: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', msg: '72' },
    { seed: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7', msg: 'af82' },
  ];
  const OWN = { seed: W.hex(W.sha256('an Ed25519 seed of our own')), msg: W.hex(W.utf8('ship release 4.0')) };

  S.topic({
    id: 'p11-ed25519', family: 'p11-ec', order: 20, title: 'Ed25519, step by step',
    blurb: 'Ed25519 hashes a 32-byte secret with SHA-512: the low half, clamped, is the scalar a, and the high half is a prefix that makes the nonce. r = SHA-512(prefix ‖ M) is fixed by the key and the message, so no random generator is needed. R = r·B, k = SHA-512(R ‖ A ‖ M), S = r + k·a mod L, and the verifier checks [8][S]B = [8]R + [8][k]A.',
    inputs: [W.hexIn('seed', 'Secret seed (32 bytes, hex)', OWN.seed, 32), { id: 'msg', kind: 'hex', label: 'Message (hex, up to 64 bytes)', def: OWN.msg, max: 64 }, { id: 'flip', kind: 'number', label: 'Byte of the message to change (verify step)', def: 0, min: 0, max: 63 }],
    presets: [
      { label: 'Our own: "ship release 4.0"', values: { seed: OWN.seed, msg: OWN.msg } },
      { label: 'RFC 8032 test 1 (empty message)', values: RFC[0] },
      { label: 'RFC 8032 test 2', values: RFC[1] },
      { label: 'RFC 8032 test 3', values: RFC[2] },
    ],
    counters: [{ id: 'sha', label: 'SHA-512 calls' }, { id: 'mul', label: 'scalar multiplications' }],
    run(inp) { return W.memo('p11-ed25519', inp, () => ed(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'public', pick: 'option', ask: 'Sign the same message twice. Will the nonce r be the same both times?', options: ['yes', 'no'], answer: 'yes', explain: (fr, i) => fr[i + 1].say },
      { at: (f) => f.meta.phase === 'check', pick: 'option', ask: 'One byte of the message changes. Will the same signature still verify?', options: ['yes', 'no'], answer: (fr, i) => (fr[i + 1].facts.ok ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Where does the Ed25519 nonce r come from?', options: ['SHA-512 of the secret prefix and the message', 'a random generator', 'the public key', 'the clock'], answer: 0, why: 'r = SHA-512(prefix ‖ M) mod L: fixed by the key and the message, secret because the prefix is.' },
      { q: 'Clamping clears the lowest three bits of the scalar because…', options: ['the curve group has cofactor 8, and a multiple of 8 kills any small-order part', 'it is faster', 'to fit 255 bits', 'to make the scalar odd'], answer: 0, why: 'A scalar divisible by 8 maps any point into the prime-order subgroup.' },
      { q: 'What does the challenge k hash?', options: ['R ‖ A ‖ M', 'M only', 'A only', 'S ‖ M'], answer: 0, why: 'Binding the public key into k stops a signature being moved to another key.' },
      { q: 'Why multiply both sides of the check by 8?', options: ['to ignore small-order components, so every verifier gives the same answer', 'to make S smaller', 'to save time', 'it is optional decoration'], answer: 0, why: 'Cofactored verification is the form RFC 8032 recommends; it agrees for honest signatures and settles edge cases consistently.' },
      { q: 'Why must S be below L?', options: ['otherwise S + L would be a second valid signature (malleability)', 'S is a byte', 'to fit in 32 bytes', 'it need not'], answer: 0, why: 'The check rejects S ≥ L, so each signature has a single encoding.' },
    ],
  });

  function ed(inp) {
    const seed = W.unhex(inp.seed), M = W.unhex(inp.msg), E = ED(), L = E.L;
    const h = S.ECC.sha512(seed), lo = h.slice(0, 32), hi = h.slice(32), K = E.keygen(seed), a = K.a, pub = K.pub;
    const sg = E.sign(seed, M), sig = sg.sig, R = sig.slice(0, 32), Sb = sig.slice(32), ver = E.verify(pub, M, sig);
    const flip = Math.min(Number(inp.flip) || 0, Math.max(0, M.length - 1)), M2 = M.length ? Uint8Array.from(M) : Uint8Array.of(0);
    if (M.length) M2[flip] ^= 1;
    const bad = E.verify(pub, M2, sig), kBad = E.le(S.ECC.sha512(W.cat(R, pub, M2))) % L;
    const B8S = E.encode(E.mul(8n, E.mul(sg.S, E.B))), rhs = E.encode(E.mul(8n, E.add(E.decode(R), E.mul(sg.k, E.decode(pub)))));
    const F = new S.Frames(['sha', 'mul']), hx = W.hex, hs = (b, n) => W.hs(hx(b), n || 6);
    const CW = 25, X0 = 50;
    const strip = (prefix, y, bytes, cls) => W.strip({ prefix, x: X0, y, bytes, cw: CW, cls, size: 13 });
    const lab = (key, y, text) => W.t(key, X0, y - 8, text, 'strong', 'start', 14);
    const seedRow = [lab('ls', 34, 'secret seed, 32 bytes (never leaves the signer)'), ...strip('sd', 40, seed, () => 'key')];
    const hRows = (st) => [lab('lh', 98, 'h = SHA-512(seed): low 32 bytes → the scalar, high 32 bytes → the prefix'), ...strip('hl', 104, lo, (i) => (st >= 2 && (i === 0 || i === 31) ? 'hot' : 'key')), ...strip('hh', 134, hi, () => 'act')];
    const byteBits = (v) => v.toString(2).padStart(8, '0');
    const clampRows = () => {
      const b0 = lo[0], b31 = lo[31], c0 = b0 & 248, c31 = (b31 & 127) | 64;
      const row = (key, x, y, bits, mark) => W.bitrow({ prefix: key, x, y, bits, cw: 24, cls: mark });
      const m0 = (i) => (i >= 5 ? 's11-clear' : ''), m31 = (i) => (i === 0 ? 's11-clear' : i === 1 ? 's11-set' : '');
      return [W.t('cb0', 50, 196, `byte 0: ${byteBits(b0)} → ${byteBits(c0)}`, 'strong', 'start', 14), ...row('b0a', 50, 204, byteBits(b0), () => ''), ...row('b0b', 272, 204, byteBits(c0), m0),
        W.t('cb31', 470, 196, `byte 31: ${byteBits(b31)} → ${byteBits(c31)}`, 'strong', 'start', 14), ...row('b3a', 470, 204, byteBits(b31), () => ''), ...row('b3b', 692, 204, byteBits(c31), m31), W.t('ar0', 256, 222, '→', 'tick', 'middle', 15), W.t('ar1', 676, 222, '→', 'tick', 'middle', 15)];
    };
    const XA = 150, XB = 450, XC = 750, BW = 270, ys = [300, 366, 432, 498];
    const vb = (key, x, y, label, v, cls) => W.vb(key, x, y, label, v, cls, BW, 18);
    const hb = (key, x, y, label, b, cls) => W.hb(key, x, y, label, hs(b), cls, BW, label + ' = ' + hx(b));
    const titles = [W.t('ta', XA, 262, 'the key', 'title', 'middle'), W.t('tb', XB, 262, 'signing', 'title', 'middle'), W.t('tc', XC, 262, 'verifying', 'title', 'middle')];
    const keyCol = [vb('ka', XA, ys[0], 'a = clamped low half', a, 'key'), hb('kA', XA, ys[1], 'public key A = a·B', pub, 'good')];
    const signCol = [vb('sr', XB, ys[0], 'r = SHA-512(prefix ‖ M) mod L', sg.r, 'hot'), hb('sR', XB, ys[1], 'R = r·B, encoded', R, 'act'), vb('sk', XB, ys[2], 'k = SHA-512(R ‖ A ‖ M) mod L', sg.k, 'act'), vb('sS', XB, ys[3], 'S = (r + k·a) mod L', sg.S, 'hot')];
    const mtxt = M.length ? (M.every((c) => c >= 32 && c < 127) ? '"' + new TextDecoder().decode(M) + '"' : 'the ' + W.plural(M.length, 'byte') + ' ' + W.hs(hx(M), 8)) : 'the empty message';
    const add = (items, say, facts, meta) => F.add({ items: seedRow.concat(items), say, facts: Object.assign({ L, seed: hs(seed, 8), mtxt, mlen: M.length }, facts), meta });

    add([], `Ed25519 starts from a 32-byte secret seed, here ${hs(seed, 8)}. Everything else, the scalar, the nonces and the public key, is derived from it.`, { len: 32 }, { phase: 'seed' });
    F.count('sha');
    add(hRows(1), `h = SHA-512(seed) gives 64 bytes. The low 32 bytes, ${hs(lo, 6)}, become the secret scalar; the high 32 bytes, ${hs(hi, 6)}, are the prefix, a second secret used only to make nonces.`, { lo: hs(lo, 6), hi: hs(hi, 6), len: 32, h: 64 }, { phase: 'hash' });
    add([...hRows(2), ...clampRows()], `Clamping, read little-endian: in byte 0 the lowest three bits are cleared, so the scalar is a multiple of 8, the cofactor; in byte 31 the top bit is cleared and the next one set, so the scalar has a fixed length of 255 bits. The result is a = ${W.n(a)}.`, { a, b0: lo[0], b31: lo[31], c: [8, 31, 255, 0] }, { phase: 'clamp' });
    F.count('mul');
    add([...hRows(2), ...titles, ...keyCol], `The public key is A = a·B, with B the base point of order L = ${W.n(L)}; it is encoded as 32 bytes (y little-endian, with the sign of x in the top bit): ${hs(pub, 8)}.`, { pub: hs(pub, 8), len: 32 }, { phase: 'public' });
    F.count('sha');
    add([...hRows(2), ...titles, ...keyCol, signCol[0]], `To sign ${mtxt}: the nonce is r = SHA-512(prefix ‖ M) mod L = ${W.n(sg.r)}. It depends only on the secret prefix and the message, so the same message always gets the same r, a different message an unrelated one, and no random generator can repeat or leak it.`, { r: sg.r, M: hx(M) }, { phase: 'nonce' });
    F.count('mul');
    add([...hRows(2), ...titles, ...keyCol, ...signCol.slice(0, 2)], `R = r·B, encoded in 32 bytes: ${hs(R, 8)}. This is the first half of the signature.`, { R: hs(R, 8), len: 32 }, { phase: 'R' });
    F.count('sha');
    add([...hRows(2), ...titles, ...keyCol, ...signCol.slice(0, 3)], `The challenge hashes the commitment, the public key and the message: k = SHA-512(R ‖ A ‖ M) mod L = ${W.n(sg.k)}.`, { k: sg.k }, { phase: 'k' });
    add([...hRows(2), ...titles, ...keyCol, ...signCol], `S = (r + k·a) mod L = ${W.n(sg.S)}, written as 32 bytes little-endian. The signature is R ‖ S, ${sig.length} bytes: ${hs(sig, 8)}.`, { S: sg.S, sig: hs(sig, 8), len: sig.length }, { phase: 'S' });
    F.count('sha');
    const v0 = [vb('vk', XC, ys[0], 'k = SHA-512(R ‖ A ‖ M) mod L', sg.k, 'act'), W.hb('vS', XC, ys[1], 'S < L ?', sg.S < L ? 'yes' : 'no', sg.S < L ? 'good' : 'bad', BW)];
    add([...hRows(2), ...titles, ...keyCol, ...signCol, ...v0], `The verifier decodes A and R as curve points, checks that S < L (otherwise S + L would be a second signature on the same message), and recomputes k = ${W.n(sg.k)} from R, A and M.`, { k: sg.k }, { phase: 'verify' });
    F.count('mul', 3);
    const v1 = [...v0, W.hb('vl', XC, ys[2], '[8][S]B, encoded', W.hs(hx(B8S), 6), ver.ok ? 'good' : 'bad', BW, hx(B8S)), W.hb('vr', XC, ys[3], '[8]R + [8][k]A, encoded', W.hs(hx(rhs), 6), ver.ok ? 'good' : 'bad', BW, hx(rhs)), W.verdict('vok', XC, 548, ver.ok, ver.ok ? 'equal: valid' : 'differ: invalid')];
    add([...hRows(2), ...titles, ...keyCol, ...signCol, ...v1], `Check [8][S]B = [8]R + [8][k]A: both sides encode to ${W.hs(hx(B8S), 8)}${hx(B8S) === hx(rhs) ? '' : ' and ' + W.hs(hx(rhs), 8)}. It holds because S·B = r·B + k·a·B = R + k·A; the factor 8 clears any small-order part, so every implementation reaches the same verdict: ${ver.ok ? 'valid' : 'invalid'}.`, { l: W.hs(hx(B8S), 8), r: W.hs(hx(rhs), 8), ok: ver.ok, c: 8 }, { phase: 'check' });
    const v2 = [vb('vk', XC, ys[0], 'k′ for the changed message', kBad, 'bad'), v0[1], W.verdict('vok', XC, ys[2], bad.ok, bad.ok ? 'valid' : 'rejected')];
    add([...hRows(2), ...titles, ...keyCol, ...signCol, ...v2], M.length ? `Change one bit of byte ${flip} of the message and check the same signature: k′ = ${W.n(kBad)} instead of k, so S·B no longer equals R + k′·A: ${bad.ok ? 'accepted' : 'rejected'}.` : `Check the same signature against a one-byte message 01 instead of the empty one: k′ = ${W.n(kBad)}, so the equation fails: ${bad.ok ? 'accepted' : 'rejected'}.`, { flip, kBad, ok: bad.ok, one: '01' }, { phase: 'tamper' });

    const raw = { pub: hx(pub), sig: hx(sig), M: hx(M), M2: hx(M2), a, r: sg.r, k: sg.k, S: sg.S, ok: ver.ok, bad: bad.ok, kBad, lo: hx(lo), hi: hx(hi), B8S: hx(B8S), rhs: hx(rhs) };
    for (const f of F.list) f.meta.raw = raw;
    const fr = W.fix(F.list, { x: 0, y: 0, w: 900, h: 570 });
    for (const f of fr) f.narrowView = /^(seed|hash|clamp)$/.test(f.meta.phase) ? { x: 30, y: 0, w: 840, h: 250 } : /^(verify|check|tamper)$/.test(f.meta.phase) ? { x: 300, y: 250, w: 600, h: 320 } : { x: 0, y: 250, w: 600, h: 320 };
    return { frames: fr, def: W.def('Ed25519 (RFC 8032)', ['h = SHA-512(seed); a = clamp(h[0..31]); prefix = h[32..63]', 'A = a·B', 'r = SHA-512(prefix ‖ M) mod L,  R = r·B', 'k = SHA-512(R ‖ A ‖ M) mod L', 'S = (r + k·a) mod L;  signature R ‖ S', 'verify: S < L and [8][S]B = [8]R + [8][k]A']) };
  }
})(globalThis.Sifer = globalThis.Sifer || {});
