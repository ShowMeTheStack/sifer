// Part 6, integrity and correct use: why a confidential mode alone lets a message be changed in transit (CTR, then
// the same bytes under GCM, where the tag catches the change), why a nonce must never repeat (the keystream cancels
// out of C₁ ⊕ C₂, the birthday bound for random nonces, and SIV, which survives a repeat), and the order of
// encryption and MAC (MAC-then-encrypt, encrypt-and-MAC, encrypt-then-MAC), shown with CBC and HMAC-SHA256.
(function (S) {
  'use strict';
  const U = S.P5, K6 = () => S.Kit.p06, Fl = () => S.Kit.flow;
  const sub = (n) => K6().sub(n);
  const utf8 = (v) => S.bytes.utf8(String(v));
  const xor = (a, b) => Uint8Array.from({ length: Math.min(a.length, b.length) }, (_, i) => a[i] ^ b[i]);
  const same = (a, b) => a.length === b.length && Array.from(a).every((v, i) => v === b[i]);
  const nonceOf = (v) => { const t = String(v), h = t.replace(/\s+/g, ''); if (/^[0-9a-fA-F]{24}$/.test(h)) return S.bytes.fromHex(h); const b = utf8(t); return b.length === 12 ? b : null; };
  const nonceInput = (def) => ({ id: 'nonce', kind: 'text', label: 'Nonce N (12 characters or 24 hex digits)', def, check: (v) => (nonceOf(v) ? null : 'Nonce: 12 characters or 24 hex digits (96 bits)') });
  const msgInput = (id, label, def, max) => ({ id, kind: 'text', label: `${label} (1 to ${max} characters)`, def, check: (v) => { const n = utf8(v).length; return n < 1 ? `${label}: at least 1 character` : n > max ? `${label}: at most ${max} bytes, so it fits the picture` : null; } });
  /** the counter block N ‖ c (a 32-bit block counter after a 96-bit nonce) */
  const ctrBlock = (N, c) => { const b = new Uint8Array(16); b.set(N); b[15] = c; return b; };
  /** keystream bytes: CTR run on zeros */
  const keystream = (E, ctr0, n) => S.Modes.encrypt('ctr', E, new Uint8Array(n), { iv: ctr0, trace: false }).out;
  const show = (b) => U.asText(b) || U.hex(b);
  const ch = (v) => (v >= 32 && v < 127 && v !== 34 ? '“' + String.fromCharCode(v) + '”' : '');

  // ---- drawing: lanes of byte strips ------------------------------------------------------------------------------
  const X0 = 156, CW = 32, GP = 3, cx = (i) => X0 + i * (CW + GP) + CW / 2;
  const strip = (pfx, y, label, bytes, cls, lcls) => [U.t(pfx + ':l', 34, y + 21, label, lcls || 'strong', 'start', 14), ...U.cells(pfx + ':', X0, y, bytes, { cw: CW, ch: 30, gap: GP, size: 14, cls })];
  const lane = (key, y, h, title, cls) => U.panel(key, 16, y, 848, h, title, cls);
  const ticks = (pfx, y, n) => Array.from({ length: n }, (_, i) => U.t(pfx + i, cx(i), y, String(i), 'tick', 'middle', 13));
  const verdict = (key, y, text, cls) => U.t(key, 34, y, text, cls, 'start', 15);

  // =================================================================================================================
  // 1. Encryption is not integrity
  // =================================================================================================================
  function notIntegrity(inp) {
    const key = U.key(inp.key), N = nonceOf(inp.nonce), P = utf8(inp.msg), L = P.length, E = S.AES.cipher(key);
    const at = Math.min(+inp.byte, L - 1), bit = +inp.bit, d = 1 << bit;
    const ctr0 = ctrBlock(N, 2), ks = keystream(E, ctr0, L), C = xor(P, ks);
    const D = new Uint8Array(L); D[at] = d;
    const C2 = xor(C, D), P2 = xor(C2, ks);
    const G = S.GCM, A0 = new Uint8Array(0), g = G.encrypt(key, N, P, A0, { trace: false });
    const gv = G.decrypt(key, N, C2, g.tag, A0, { trace: false });
    const t2 = G.ghash(g.H, A0, C2, { trace: false }).out.map((v, i) => v ^ g.EJ0[i]);
    const nDiff = t2.filter((v, i) => v !== g.tag[i]).length, sameC = same(g.ct, C);
    const F = new S.Frames();
    const hot = (i) => (i === at ? 'hot' : '');
    const nv = K6().follow(at <= 12 ? 300 : cx(at), { w: 600, y: 170, h: 470 });
    const sender = (rows) => [...lane('ln:s', 6, 46 + 40 * rows.length, 'sender'), ...rows.flatMap((r, k) => strip('s' + k, 38 + 40 * k, ...r))];
    const wire = (on) => [...lane('ln:w', 176, 122, 'on the wire: an attacker with no key', on ? 'hot' : ''), ...ticks('tk', 217, L), ...strip('w0', 222, 'change Δ', D, (i) => (i === at ? 'hot' : 'soft')), ...strip('w1', 260, 'received C′', C2, hot)];
    const recv = (rows, v) => [...lane('ln:r', 306, 166, 'receiver'), ...rows.flatMap((r, k) => strip('r' + k, 338 + 40 * k, ...r)), ...(v ? [verdict('vd', 448, v[0], v[1])] : [])];
    const txt = (b) => U.asText(b) || '(not printable)';
    const s3 = [['message P', P], ['keystream', ks, () => 'key'], ['ciphertext C', C]];
    F.add({ items: [...sender([['message P', P]]), ...K6().readout([['message', txt(P)], ['key', U.hex(key)], ['nonce N', U.hex(N)]], 'AES-CTR, no tag')], say: `The sender's message, ${show(P)}, is ${L} bytes long. It is encrypted with AES-CTR under nonce N = ${U.hex(N)}. The counter blocks are N ‖ 00000002, N ‖ 00000003 and so on, as in GCM, so the two can be compared later.`, facts: { L, N, ctr: '00000002', c3: '00000003' }, meta: { stage: 'start' } });
    F.add({ items: [...sender(s3), ...K6().readout([['keystream', U.hex(ks), 'key'], ['C = P ⊕ keystream', U.hex(C)]], 'CTR encryption')], hl: { d: [0] }, say: `The keystream is ${U.hex(ks)}, and C = P ⊕ keystream = ${U.hex(C)}. Without the key, C looks like random bytes. The sender sends N and C, and nothing else.`, facts: { ks, C }, meta: { stage: 'enc' } });
    F.add({ items: [...sender(s3), ...wire(true), ...K6().readout([['C, as sent', U.hex(C)], ['Δ', U.hex(D), 'hot'], ['C′ = C ⊕ Δ', U.hex(C2), 'hot']], 'one bit flipped in transit')], narrowView: nv, hl: { d: [1] }, say: `On the way, someone who has no key flips bit ${bit} of byte ${at}: ${U.h2(C[at])} becomes ${U.h2(C2[at])}. The change Δ is ${U.h2(d)} at that byte and 00 everywhere else.`, facts: { bit, at, c: C[at], c2: C2[at], d, z: 0 }, meta: { stage: 'flip' } });
    F.add({ items: [...sender(s3), ...wire(false), ...recv([['keystream', ks, () => 'key'], ['decrypted P′', P2, hot]], ['accepted: CTR has nothing to check, so decryption never fails', 'bad']), ...K6().readout([['sent', txt(P)], ['decrypted', txt(P2), 'hot']], 'what the receiver reads')], narrowView: nv, hl: { d: [1] }, say: `The receiver XORs the same keystream and reads ${show(P2)}. Byte ${at} went from ${U.h2(P[at])}${ch(P[at]) ? ' ' + ch(P[at]) : ''} to ${U.h2(P2[at])}${ch(P2[at]) ? ' ' + ch(P2[at]) : ''}: the very bit that was flipped, since P′ = C′ ⊕ keystream = P ⊕ Δ. CTR decryption cannot fail, so nothing tells the receiver, and anyone who can guess the message can rewrite it at will.`, facts: { at, p: P[at], p2: P2[at], P2 }, meta: { stage: 'recv' } });
    const g3 = [['message P', P], ['ciphertext C', g.ct], ['tag T', g.tag, () => 'act']];
    F.add({ items: [...sender(g3), ...K6().readout([['C', U.hex(g.ct)], ['tag T', U.hex(g.tag), 'act']], 'AES-GCM: the same key and nonce')], hl: { d: [2] }, say: `Now the sender uses AES-GCM with the same key and nonce. GCM encrypts with exactly this keystream, from J0 + 1 = N ‖ 00000002 on, so its ciphertext is ${sameC ? 'the same' : 'different'} ${L} bytes, ${U.hex(g.ct)}. What GCM adds is a 16-byte tag over the ciphertext, T = ${U.hex(g.tag)}.`, facts: { L, ct: g.ct, tag: g.tag, ctr: '00000002' }, meta: { stage: 'gcm', same: sameC } });
    const tagCls = (i) => (t2[i] === g.tag[i] ? 'p1-good' : 'p1-bad');
    F.add({ items: [...sender(g3), ...wire(true), ...recv([['tag T received', g.tag, () => 'act'], ['tag computed', t2, tagCls]], gv.ok ? ['accepted', 'good'] : [`rejected: ${nDiff} of 16 tag bytes differ, so no plaintext is released`, 'bad']), ...K6().readout([['T received', U.hex(g.tag), 'act'], ['T from C′', U.hex(t2), 'hot']], 'the receiver checks the tag first')], narrowView: K6().follow(300, { w: 600, y: 300, h: 340 }), hl: { d: [3] }, say: `The same bit is flipped. The receiver recomputes the tag from C′ and gets ${U.hex(t2)}, not ${U.hex(g.tag)}: ${nDiff} of the 16 bytes differ. GCM ${gv.ok ? 'accepts' : 'rejects the message and releases no plaintext at all'}. To forge a tag that passes, the attacker would have to guess it, once in 2^128 tries.`, facts: { t2, tag: g.tag, nDiff, ok: gv.ok }, meta: { stage: 'gcm-flip', ok: gv.ok } });
    const defence = () => {
      const Nt = Fl().net('df'), y1 = 108, y2 = 318;
      const it = [...U.panel('df:a', 16, 6, 848, 196, 'AEAD: one key, one call (AES-GCM, ChaCha20-Poly1305, AES-CCM)'), ...U.panel('df:b', 16, 214, 848, 230, 'or encrypt-then-MAC, with two independent keys kₑ and kₘ')];
      Nt.box('ap', 90, y1, 120, 50, ['P', K6().short(P, 6)], 'val2');
      Nt.box('ag', 290, y1, 150, 56, ['AES-GCM', 'key k, nonce N'], 'cipher small');
      Nt.box('ac', 490, y1 - 32, 140, 46, ['C', K6().short(g.ct, 6)], 'val2');
      Nt.box('at', 490, y1 + 32, 140, 46, ['T', K6().short(g.tag, 6)], 'val2 act');
      Nt.box('av', 745, y1, 180, 56, ['receiver', 'check T, then decrypt'], 'good small');
      Nt.wire('a1', [Nt.port('ap', 'e'), Nt.port('ag', 'w')], { head: true });
      Nt.wire('a2', [Nt.port('ag', 'e', -0.5), [400, y1 - 14], [400, y1 - 32], Nt.port('ac', 'w')], { head: true });
      Nt.wire('a3', [Nt.port('ag', 'e', 0.5), [400, y1 + 14], [400, y1 + 32], Nt.port('at', 'w')], { head: true, cls: 'act' });
      Nt.wire('a4', [Nt.port('ac', 'e'), [600, y1 - 32], [600, y1 - 14], Nt.port('av', 'w', -0.5)], { head: true });
      Nt.wire('a5', [Nt.port('at', 'e'), [600, y1 + 32], [600, y1 + 14], Nt.port('av', 'w', 0.5)], { head: true, cls: 'act' });
      Nt.box('bp', 90, y2, 120, 50, ['P', K6().short(P, 6)], 'val2');
      Nt.box('bc', 270, y2, 130, 56, ['AES-CTR', 'key kₑ, nonce N'], 'cipher small');
      Nt.box('bC', 450, y2, 120, 50, ['N ‖ C', K6().short(C, 6)], 'val2');
      Nt.box('bm', 640, y2, 150, 56, ['HMAC-SHA256', 'key kₘ'], 'act small');
      Nt.box('bt', 640, y2 + 86, 120, 40, 'T', 'val act');
      Nt.wire('b1', [Nt.port('bp', 'e'), Nt.port('bc', 'w')], { head: true });
      Nt.wire('b2', [Nt.port('bc', 'e'), Nt.port('bC', 'w')], { head: true });
      Nt.wire('b3', [Nt.port('bC', 'e'), Nt.port('bm', 'w')], { head: true, cls: 'act' });
      Nt.wire('b4', [Nt.port('bm', 's'), Nt.port('bt', 'n')], { head: true, cls: 'act' });
      it.push(U.t('df:s', 40, y2 + 92, 'send N, C and T; the receiver checks T over N ‖ C first', 'strong', 'start', 14));
      it.push(verdict('df:v', 470, 'never CTR or CBC alone where anyone can touch the bytes', 'hot'));
      return it.concat(Nt.items);
    };
    F.add({ items: [...defence(), ...K6().readout([['CTR', 'accepted ' + txt(P2), 'hot'], ['GCM', gv.ok ? 'accepted' : 'rejected, nothing released']], 'the same flipped bit')], hl: { d: [3, 4] }, say: `Confidentiality and integrity are separate goals. Use an AEAD mode such as GCM, or encrypt-then-MAC with independent keys; either way the receiver verifies the tag over the ciphertext first and releases plaintext only if it matches.`, facts: {}, meta: { stage: 'defence' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Malleability', ['CTR: C = P ⊕ keystream', 'a change Δ on the wire: P′ = (C ⊕ Δ) ⊕ keystream = P ⊕ Δ', 'GCM: the same C, and T = GHASH_H(A, C) ⊕ Eₖ(J0)', 'receive: recompute T from what arrived, compare in constant time, only then decrypt', 'encrypt-then-MAC: T = HMAC(kₘ, N ‖ C), verified first']) };
  }
  S.topic({
    id: 'integrity-malleable', family: 'p06-labs', order: 50, title: 'Encryption is not integrity',
    blurb: 'A CTR ciphertext with one bit flipped decrypts to a message with that same bit flipped, and the receiver cannot tell. The same bytes under GCM carry a tag, and the change is caught.',
    inputs: [msgInput('msg', 'Message', 'Pay Rowan 100 coins', 20), K6().keyInput(), nonceInput('mill-pond-04'),
      { id: 'byte', kind: 'number', label: 'Byte to change (from 0)', def: 10, min: 0, max: 19, check: (v, inp) => (inp && v >= utf8(inp.msg).length ? 'Byte to change: inside the message (from 0 to its length − 1)' : null) },
      { id: 'bit', kind: 'choice', label: 'Bit to flip', def: '3', options: [0, 1, 2, 3, 4, 5, 6, 7].map((b) => ({ value: String(b), label: 'bit ' + b + ' (' + U.h2(1 << b) + ')' })) }],
    presets: [
      { label: '100 coins becomes 900', values: { msg: 'Pay Rowan 100 coins', byte: 10, bit: '3' } },
      { label: 'A yes becomes a no', values: { msg: 'reply: YES', byte: 7, bit: '1' } },
      { label: 'Upper case to lower case', values: { msg: 'OPEN THE SLUICE', byte: 0, bit: '5' } },
      { label: 'AES-256, the last byte', values: { msg: 'grid ref 4471', key: 'thirty-two bytes of copper wire!', byte: 12, bit: '0' } },
    ],
    run: notIntegrity,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'flip', pick: 'option', options: ['decryption fails', 'it reads the message with that one bit changed, and accepts it', 'the whole message is garbled', 'it reads the original message'], ask: 'The receiver decrypts C′ with CTR. What happens?', answer: 'it reads the message with that one bit changed, and accepts it', explain: 'CTR is a plain XOR with the keystream: a flipped ciphertext bit flips the same plaintext bit, and there is nothing to check.' },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta && fr[i + 1].meta.stage === 'gcm-flip', pick: 'option', options: ['accepted', 'rejected'], ask: 'The same bit of the GCM ciphertext is flipped. Will the receiver accept it?', answer: 'rejected', explain: 'The tag covers every bit of the ciphertext; the recomputed tag no longer matches.' },
    ],
    quiz: [
      { q: 'An attacker flips bit 2 of byte 5 of a CTR ciphertext. What does the receiver get?', options: ['An error', 'The plaintext with bit 2 of byte 5 flipped', 'A fully garbled byte 5', 'Every byte from 5 on garbled'], answer: 1, why: 'P′ = P ⊕ Δ: CTR is perfectly malleable.' },
      { q: 'Why can CTR decryption never report a tampered message?', options: ['It is too fast', 'Every ciphertext decrypts to some plaintext: there is no redundancy to check', 'It uses a nonce', 'It does report it'], answer: 1, why: 'Confidentiality modes map every bit string to a plaintext; only a tag adds a check.' },
      { q: 'What does GCM do when the tag does not match?', options: ['Returns the plaintext with a warning', 'Rejects the message and releases no plaintext', 'Decrypts only the first block', 'Retries'], answer: 1, why: 'Releasing unverified plaintext would undo the point of the tag.' },
      { q: 'Which construction gives integrity safely with a non-AEAD mode?', options: ['MAC-then-encrypt', 'Encrypt-and-MAC', 'Encrypt-then-MAC with independent keys', 'Encrypting twice'], answer: 2, why: 'The tag over the ciphertext is checked before anything is decrypted.' },
      { q: 'Does a CBC ciphertext resist the same trick?', options: ['Yes, CBC gives integrity', 'No: flipping a bit of Cᵢ flips the same bit of Pᵢ₊₁, at the cost of garbling Pᵢ', 'Only with a random IV', 'Only for one block'], answer: 1, why: 'CBC is malleable too; no confidentiality mode gives integrity.' },
    ],
  });

  // =================================================================================================================
  // 2. Never reuse a nonce
  // =================================================================================================================
  // AES-SIV (RFC 5297): S2V, a CMAC chain over the header strings and the message, gives the synthetic IV V; CTR
  // under the second key from V (bits 31 and 63 cleared) encrypts. Exposed for the narration checks.
  const dbl = (b) => { const o = new Uint8Array(16); for (let i = 0; i < 16; i++) o[i] = ((b[i] << 1) | (i < 15 ? b[i + 1] >> 7 : 0)) & 255; if (b[0] & 0x80) o[15] ^= 0x87; return o; };
  const s2v = (k1, parts) => {
    const M = (m) => S.MAC.cmac(k1, m);
    let D = M(new Uint8Array(16));
    for (const s of parts.slice(0, -1)) D = xor(dbl(D), M(s));
    const last = parts[parts.length - 1];
    let T;
    if (last.length >= 16) { T = Uint8Array.from(last); for (let i = 0; i < 16; i++) T[last.length - 16 + i] ^= D[i]; }
    else { const p = new Uint8Array(16); p.set(last); p[last.length] = 0x80; T = xor(dbl(D), p); }
    return M(T);
  };
  const siv = (key, headers, P) => {
    const k1 = key.slice(0, key.length / 2), k2 = key.slice(key.length / 2), V = s2v(k1, [...headers, P]);
    const Q = Uint8Array.from(V); Q[8] &= 0x7f; Q[12] &= 0x7f;
    return { V, Q, C: S.Modes.encrypt('ctr', S.AES.cipher(k2), P, { iv: Q, trace: false }).out };
  };
  S.P6int = { s2v, siv, dbl };

  function reuse(inp) {
    const key = U.key(inp.key, [32]), N = nonceOf(inp.nonce), P1 = utf8(inp.m1), P2 = utf8(inp.m2), E = S.AES.cipher(key);
    const L1 = P1.length, L2 = P2.length, L = Math.min(L1, L2), ctr0 = ctrBlock(N, 1), ks = keystream(E, ctr0, Math.max(L1, L2));
    const C1 = xor(P1, ks), C2 = xor(P2, ks), X = xor(C1, C2), PX = xor(P1, P2), zeros = Array.from(X).filter((v) => !v).length;
    const F = new S.Frames(), cl = (c) => () => c;
    const zc = (i) => (X[i] ? '' : 'hot');
    const one = (k, y, title, P, C, hot) => [...lane('ln' + k, y, 166, title, hot ? 'hot' : ''), ...strip('m' + k + 'p', y + 34, 'message P' + sub(k), P), ...strip('m' + k + 'k', y + 74, 'keystream', ks.slice(0, P.length), cl(hot ? 'keyhot' : 'key')), ...strip('m' + k + 'c', y + 114, 'C' + sub(k) + ' = P' + sub(k) + ' ⊕ ks', C)];
    const head = [['key (AES-256)', U.hex(key)], ['nonce N', U.hex(N)]];
    F.add({ items: [...one(1, 6, 'message 1: key k, nonce N', P1, C1), ...K6().readout([...head, ['message 1', show(P1)]], 'AES-CTR')], say: `Message 1, ${show(P1)}, is encrypted with AES-CTR under key k and nonce N = ${U.hex(N)}, counter blocks N ‖ 00000001 on: C₁ = ${U.hex(C1)}.`, facts: { N, C1, c: '00000001' }, meta: { stage: 'first' } });
    F.add({ items: [...one(1, 6, 'message 1: key k, nonce N', P1, C1), ...one(2, 180, 'message 2: the same key, the same nonce N', P2, C2, true), ...K6().readout([['keystream', U.hex(ks), 'key'], ['C₂', U.hex(C2)]], 'the nonce is used twice')], hl: { d: [0] }, say: `Message 2, ${show(P2)}, is sent later under the same key and the same nonce. The counter blocks are the same, so the keystream is the same bytes, ${U.hex(ks.slice(0, L2))}, and C₂ = ${U.hex(C2)}.`, facts: { ks: ks.slice(0, L2), C2 }, meta: { stage: 'second' } });
    const xr = [...lane('ln:x', 6, 216, 'what an eavesdropper computes, with no key'), ...ticks('tk', 47, L), ...strip('x1', 52, 'C₁', C1.slice(0, L)), ...strip('x2', 92, 'C₂', C2.slice(0, L)), ...strip('x3', 132, 'C₁ ⊕ C₂', X, zc), ...strip('x4', 172, 'P₁ ⊕ P₂', PX, zc)];
    F.add({ items: [...xr, ...K6().readout([['C₁ ⊕ C₂', U.hex(X), 'hot'], ['P₁ ⊕ P₂', U.hex(PX)]], 'the keystream cancels')], hl: { d: [1] }, say: `XOR the two ciphertexts over their common ${L} bytes: C₁ ⊕ C₂ = ${U.hex(X)}, which is exactly P₁ ⊕ P₂, because (P₁ ⊕ ks) ⊕ (P₂ ⊕ ks) = P₁ ⊕ P₂. The key has dropped out. ${zeros ? `The ${zeros} zero byte${zeros > 1 ? 's' : ''} mark${zeros > 1 ? '' : 's'} where the two messages have the same letter.` : 'No byte is zero: the messages differ at every place.'} Part 3's [[st-two-time]] shows how such an XOR is read back into both messages.`, facts: { L, X, zeros }, meta: { stage: 'xor' } });
    const R2 = xor(X, P1), KS = xor(C1, P1);
    F.add({ items: [...lane('ln:k', 6, 166, 'if message 1 is known or guessed'), ...strip('k1', 40, 'C₁ ⊕ C₂', X), ...strip('k2', 80, 'P₁, known', P1.slice(0, L), cl('act')), ...strip('k3', 120, 'P₂ = XOR of both', R2, cl('hot')), ...K6().readout([['P₂ recovered', show(R2), 'hot'], ['keystream = C₁ ⊕ P₁', U.hex(KS), 'key']], 'one known message opens the other')], hl: { d: [2] }, say: `Worse, anyone who knows or guesses message 1, a fixed header say, gets message 2 at once: P₂ = (C₁ ⊕ C₂) ⊕ P₁ = ${show(R2)}. They also get the keystream itself, ${U.hex(KS)}, which opens anything else ever sent under this key and nonce.`, facts: { R2, KS }, meta: { stage: 'known' } });
    // the rule, and the birthday bound for random 96-bit nonces
    const k = +inp.q, lp = (e) => { const x = 2 ** (2 * e - 97); return Math.log2(x < 1e-9 ? x : -Math.expm1(-x)); };
    const pe = (e) => { const v = lp(e); return v > -7 ? { pct: Math.round(100 * 2 ** v), e: null } : { pct: null, e: -Math.round(v) }; };
    const words = (e) => { const p = pe(e); return p.pct !== null ? `about ${p.pct}%` : `about 2^−${p.e}`; };
    const h50 = Math.round(10 * (48 + 0.5 * Math.log2(2 * Math.log(2)))) / 10, mine = pe(k), nist = pe(32);
    const PX0 = 120, PX1 = 820, PY0 = 70, PY1 = 400, gx = (e) => U.r2(PX0 + ((e - 16) / 48) * (PX1 - PX0)), gy = (v) => U.r2(PY0 + (Math.max(-80, v) / -80) * (PY1 - PY0));
    const plot = () => {
      const it = [U.t('bp:t', 40, 34, 'chance that some random 96-bit nonce repeats, by messages under one key', 'title')];
      it.push({ key: 'bp:ax', kind: 'path', d: `M${PX0},${PY0} V${PY1} H${PX1}`, cls: 'axis', audit: 'ignore', layer: 'back', box: { x: PX0, y: PY0, w: PX1 - PX0, h: PY1 - PY0 } });
      for (let e = 16; e <= 64; e += 8) it.push(U.t('bp:x' + e, gx(e), PY1 + 22, '2' + U.sup(e), 'tick', 'middle', 13));
      for (let v = 0; v >= -80; v -= 20) it.push(U.t('bp:y' + v, PX0 - 10, gy(v) + 5, v ? '2' + '⁻' + U.sup(-v) : '1', 'tick', 'end', 13));
      it.push(U.t('bp:xl', PX1, PY1 + 46, 'messages encrypted with random nonces', 'tick', 'end', 13));
      let d = ''; for (let e = 16; e <= 64; e += 0.25) d += (d ? 'L' : 'M') + gx(e) + ',' + gy(lp(e)) + ' ';
      it.push({ key: 'bp:c', kind: 'path', d, cls: 'dline act', pathAudit: 'edge-x' });
      it.push({ key: 'bp:h', kind: 'line', x1: PX0, y1: gy(-1), x2: PX1, y2: gy(-1), cls: 'dash', audit: 'ignore', layer: 'back' });
      it.push(U.t('bp:hl', PX0 + 10, gy(-1) - 8, 'one chance in two', 'tick', 'start', 13));
      it.push({ key: 'bp:n', kind: 'dot', x: gx(32), y: gy(lp(32)), r: 6, cls: 'good', point: true });
      it.push(U.t('bp:nl', gx(32) + 12, gy(lp(32)) + 22, 'SP 800-38D limit: 2³² messages', 'good', 'start', 13));
      if (k !== 32) { it.push({ key: 'bp:k', kind: 'dot', x: gx(k), y: gy(lp(k)), r: 6, cls: 'hot', point: true }); it.push(U.t('bp:kl', gx(k) + (k > 52 ? -12 : 12), gy(lp(k)) + (k > 52 ? 60 : 22), `2${U.sup(k)} messages: ${words(k).replace('2^−', '2⁻').replace(/2⁻(\d+)/, (m, x) => '2⁻' + U.sup(x))}`, 'hot', k > 52 ? 'end' : 'start', 13)); }
      return it;
    };
    F.add({ items: [...plot(), ...K6().readout([['counter nonce', 'never repeats; the counter must survive restarts'], ['random nonce', `2^${k} messages: chance of a repeat ${words(k)}`, 'hot'], ['the limit', 'at most 2^32 random nonces per key (NIST SP 800-38D)', 'strong']], 'the rule: a nonce is used once per key')], hl: { d: [3] }, say: `So a nonce must never repeat under one key. A counter guarantees it, provided its state survives crashes and restarts. Random 96-bit nonces repeat by the birthday bound: q messages collide with chance about q²/2^97. After 2^${k} messages that is ${words(k)}; at 2^32, the limit NIST SP 800-38D sets, it is ${words(32)}, and it reaches one in two near 2^${h50}.`, facts: { k, p: mine.pct, e: mine.e, ne: nist.e, h50, b: 97, lim: 32 }, meta: { stage: 'rule' } });
    // SIV: the IV is made from the message itself
    const s1 = siv(key, [N], P1), s2 = siv(key, [N], P2), SX = xor(s1.C, s2.C), nd = Array.from(SX).filter((v, i) => v !== PX[i]).length, eq = same(P1, P2);
    const sivNet = () => {
      const Nt = Fl().net('sv');
      Nt.box('n', 135, 90, 230, 50, ['nonce N', U.hex(N)], 'val2 key tight');
      Nt.box('p', 135, 190, 230, 50, ['message P₁', K6().short(P1, 12)], 'val2');
      Nt.box('s2v', 380, 140, 130, 60, ['S2V', 'CMAC under K₁'], 'act small');
      K6().box(Nt, 'v', 590, 140, 'V₁: the synthetic IV', s1.V, 'act');
      Nt.box('ctr', 590, 290, 150, 56, ['CTR under K₂', 'from V₁'], 'cipher small');
      K6().box(Nt, 'c', 590, 400, 'C₁', s1.C.slice(0, 16), 'hot');
      Nt.wire('nw', [Nt.port('n', 'e'), [275, 90], [275, 125], Nt.port('s2v', 'w', -0.5)], { head: true });
      Nt.wire('pw', [Nt.port('p', 'e'), [275, 190], [275, 155], Nt.port('s2v', 'w', 0.5)], { head: true });
      Nt.wire('sv', [Nt.port('s2v', 'e'), Nt.port('v', 'w')], { head: true, cls: 'act' });
      Nt.wire('vc', [Nt.port('v', 's'), Nt.port('ctr', 'n')], { head: true, cls: 'act' });
      Nt.wire('pc', [Nt.port('p', 's'), [135, 290], Nt.port('ctr', 'w')], { head: true });
      Nt.wire('cc', [Nt.port('ctr', 's'), Nt.port('c', 'n')], { head: true, cls: 'hot' });
      Nt.wire('vo', [Nt.port('v', 'e'), [760, 140], [760, 400], Nt.port('c', 'e')], { head: true, cls: 'act' });
      Nt.label('vol', 772, 274, 'sent: V and C', 'act', 'start', 13);
      return Nt.items;
    };
    F.add({ items: [...sivNet(), ...K6().readout([['V₁ (message 1)', U.hex(s1.V), 'act'], ['V₂ (message 2)', U.hex(s2.V), 'act']], 'AES-SIV: the IV depends on the message')], hl: { d: [4] }, say: `A nonce-misuse-resistant design survives a repeat. AES-SIV splits the 32 key bytes into K₁ and K₂; S2V, a chain of CMACs under K₁ over the nonce and the whole message, gives a synthetic IV, and CTR under K₂ starts from it. Under the same nonce, message 1 gets V₁ = ${U.hex(s1.V)} and message 2 gets V₂ = ${U.hex(s2.V)}${eq ? ': the same, because the messages are the same' : ''}.`, facts: { V1: s1.V, V2: s2.V, n: 32 }, meta: { stage: 'siv' } });
    const sv = [...lane('ln:sv', 6, 206, 'AES-SIV, both messages under the same nonce'), ...strip('y1', 42, 'C₁ (SIV)', s1.C.slice(0, L)), ...strip('y2', 82, 'C₂ (SIV)', s2.C.slice(0, L)), ...strip('y3', 122, 'C₁ ⊕ C₂', SX, (i) => (SX[i] === PX[i] ? 'hot' : '')), ...strip('y4', 162, 'P₁ ⊕ P₂', PX)];
    F.add({ items: [...sv, ...K6().readout([['C₁ ⊕ C₂', U.hex(SX)], ['P₁ ⊕ P₂', U.hex(PX)]], eq ? 'equal messages: only their equality shows' : 'different IVs, different keystreams')], hl: { d: [4] }, say: eq ? `The two messages are equal, so SIV gives equal ciphertexts. That is all a repeated nonce reveals under SIV: that the same message was sent twice. Nothing about its content leaks.` : `The keystreams now differ, so C₁ ⊕ C₂ = ${U.hex(SX)} has nothing to do with P₁ ⊕ P₂: ${nd} of the ${L} bytes differ from it. A repeated nonce under SIV reveals only whether two messages are equal. The price is two passes over the message; AES-GCM-SIV (RFC 8452) is the fast version of the same idea.`, facts: { SX, nd, L }, meta: { stage: 'siv2', eq } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Nonce reuse', ['Cᵢ = Pᵢ ⊕ ks(k, N): the same (k, N), the same ks', 'C₁ ⊕ C₂ = P₁ ⊕ P₂: the key drops out', 'P₁ known ⇒ P₂ = C₁ ⊕ C₂ ⊕ P₁ and ks = C₁ ⊕ P₁', 'random 96-bit nonces: Pr[repeat] ≈ q² / 2⁹⁷', 'SIV: V = S2V(K₁, N, P), C = CTR(K₂, V, P)']) };
  }
  S.topic({
    id: 'integrity-nonce', family: 'p06-labs', order: 60, title: 'Never reuse a nonce',
    blurb: 'Two CTR messages under the same key and nonce share a keystream, so XORing the ciphertexts gives the XOR of the plaintexts. The rule, the birthday bound for random nonces, and SIV, which survives a repeat.',
    inputs: [msgInput('m1', 'Message 1', 'Meet at the old pier', 20), msgInput('m2', 'Message 2', 'Wait by the old mill', 20),
      { id: 'key', kind: 'text', label: 'Key (32 characters or 64 hex digits)', def: 'one key, two halves: K1 then K2!', check: U.keyCheck('Key', [32]) },
      nonceInput('fixed-nonce!'),
      { id: 'q', kind: 'number', label: 'Messages under one key, 2 to the power', def: 40, min: 16, max: 64 }],
    presets: [
      { label: 'Two orders, one nonce', values: { m1: 'Meet at the old pier', m2: 'Wait by the old mill', q: 40 } },
      { label: 'Messages that share words', values: { m1: 'SHIP 40 CASKS PIER 7', m2: 'SHIP 12 CASKS PIER 3', q: 32 } },
      { label: 'The same message twice', values: { m1: 'status: all well', m2: 'status: all well', q: 48 } },
      { label: '2⁵⁶ random nonces', values: { m1: 'lamp lit', m2: 'lamp out', q: 56 } },
    ],
    run: reuse,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'second', pick: 'option', options: ['P₁ ⊕ P₂', 'the keystream', 'random bytes', 'the key'], ask: 'What does C₁ ⊕ C₂ equal?', answer: 'P₁ ⊕ P₂', explain: 'The keystream appears in both ciphertexts and cancels.' },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta && fr[i + 1].meta.stage === 'siv2' && !fr[i + 1].meta.eq, pick: 'option', options: ['P₁ ⊕ P₂, as with CTR', 'something unrelated to P₁ ⊕ P₂'], ask: 'Under SIV with the same nonce, what will C₁ ⊕ C₂ look like?', answer: 'something unrelated to P₁ ⊕ P₂', explain: 'Different messages give different synthetic IVs, hence different keystreams.' },
    ],
    quiz: [
      { q: 'Two CTR messages share key and nonce. What can an eavesdropper compute with no key?', options: ['Nothing', 'P₁ ⊕ P₂', 'The key', 'Only the lengths'], answer: 1, why: 'C₁ ⊕ C₂ = P₁ ⊕ P₂.' },
      { q: 'With random 96-bit nonces, roughly how many messages give a one-in-two chance of a repeat?', options: ['2³²', '2⁴⁸', '2⁹⁶', '2¹²⁸'], answer: 1, why: 'The birthday bound: about the square root of 2⁹⁶.' },
      { q: 'What does a counter nonce need to stay safe?', options: ['Nothing', 'Its value must never go back, even after a crash or a restore from backup', 'It must be secret', 'It must be random'], answer: 1, why: 'A counter that resets repeats nonces just as surely.' },
      { q: 'Under AES-SIV, what does a repeated nonce reveal?', options: ['The key', 'P₁ ⊕ P₂', 'Only whether the two messages are equal', 'The keystream'], answer: 2, why: 'The IV is derived from the message, so different messages get different keystreams.' },
      { q: 'In GCM, a repeated nonce also breaks the tag. Why?', options: ['It does not', 'Two tags masked by the same Eₖ(J0) give an equation in H, from which H follows and tags can be forged', 'The tag gets shorter', 'The key changes'], answer: 1, why: 'Integrity fails as well as confidentiality.' },
    ],
  });

  // =================================================================================================================
  // 3. Order of operations and error handling
  // =================================================================================================================
  const cat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
  /** the three ways to combine a cipher and a MAC, as data flow side by side */
  const threeWays = () => {
    const Nt = Fl().net('w3'), it = [], X = [150, 440, 730];
    const heads = ['MAC-then-encrypt', 'encrypt-and-MAC', 'encrypt-then-MAC'];
    const notes = [[['the receiver must decrypt and unpad', 'hot'], ['before it can check the tag:', ''], ['padding errors leak (old TLS CBC)', '']],
      [['T is over P: equal messages give', 'hot'], ['equal tags, and the receiver', ''], ['still decrypts first (SSH)', '']],
      [['T is over C, checked first:', 'good'], ['a forged C never reaches Dₖ', ''], ['(IPsec ESP, TLS encrypt_then_mac)', '']]];
    X.forEach((cx, k) => {
      it.push(...U.panel('w3:p' + k, cx - 138, 6, 276, 450, heads[k], k === 2 ? 'act' : ''));
      notes[k].forEach(([t, c], j) => it.push(U.t(`w3:n${k}:${j}`, cx - 124, 392 + j * 20, t, c || '', 'start', 13)));
    });
    // MAC-then-encrypt
    let cx = X[0];
    Nt.box('a:p', cx, 72, 80, 36, 'P', 'val');
    Nt.box('a:m', cx + 70, 140, 100, 44, ['MAC', 'key kₘ'], 'act small');
    Nt.box('a:c', cx, 210, 100, 36, 'P ‖ T', 'val');
    Nt.box('a:e', cx, 280, 110, 44, ['encrypt', 'key kₑ'], 'cipher small');
    Nt.box('a:o', cx, 348, 120, 36, 'send C', 'val');
    Nt.wire('a1', [Nt.port('a:p', 's'), Nt.port('a:c', 'n')], { head: true });
    Nt.wire('a2', [Nt.port('a:p', 'e'), [cx + 70, 72], Nt.port('a:m', 'n')], { head: true, cls: 'act' });
    Nt.wire('a3', [Nt.port('a:m', 's'), [cx + 70, 210], Nt.port('a:c', 'e')], { head: true, cls: 'act' });
    Nt.wire('a4', [Nt.port('a:c', 's'), Nt.port('a:e', 'n')], { head: true });
    Nt.wire('a5', [Nt.port('a:e', 's'), Nt.port('a:o', 'n')], { head: true });
    // encrypt-and-MAC
    cx = X[1];
    Nt.box('b:p', cx, 72, 80, 36, 'P', 'val');
    Nt.box('b:e', cx - 60, 170, 100, 44, ['encrypt', 'key kₑ'], 'cipher small');
    Nt.box('b:m', cx + 60, 170, 100, 44, ['MAC', 'key kₘ'], 'act small');
    Nt.box('b:o', cx, 278, 180, 36, 'send C ‖ T', 'val');
    Nt.dot(cx, 118);
    Nt.wire('b0', [Nt.port('b:p', 's'), [cx, 118]], {});
    Nt.wire('b1', [[cx, 118], [cx - 60, 118], Nt.port('b:e', 'n')], { head: true });
    Nt.wire('b2', [[cx, 118], [cx + 60, 118], Nt.port('b:m', 'n')], { head: true, cls: 'act' });
    Nt.wire('b3', [Nt.port('b:e', 's'), Nt.port('b:o', 'n', -60 / 90)], { head: true });
    Nt.wire('b4', [Nt.port('b:m', 's'), Nt.port('b:o', 'n', 60 / 90)], { head: true, cls: 'act' });
    // encrypt-then-MAC
    cx = X[2];
    Nt.box('c:p', cx, 72, 80, 36, 'P', 'val');
    Nt.box('c:e', cx, 140, 110, 44, ['encrypt', 'key kₑ'], 'cipher small');
    Nt.box('c:c', cx, 208, 80, 36, 'C', 'val');
    Nt.box('c:m', cx + 60, 286, 100, 44, ['MAC', 'key kₘ'], 'act small');
    Nt.box('c:o', cx, 352, 180, 36, 'send C ‖ T', 'val');
    Nt.dot(cx, 244);
    Nt.wire('c1', [Nt.port('c:p', 's'), Nt.port('c:e', 'n')], { head: true });
    Nt.wire('c2', [Nt.port('c:e', 's'), Nt.port('c:c', 'n')], { head: true });
    Nt.wire('c3', [Nt.port('c:c', 's'), [cx, 244]], {});
    Nt.wire('c4', [[cx, 244], [cx - 60, 244], Nt.port('c:o', 'n', -60 / 90)], { head: true });
    Nt.wire('c5', [[cx, 244], [cx + 60, 244], Nt.port('c:m', 'n')], { head: true, cls: 'act' });
    Nt.wire('c6', [Nt.port('c:m', 's'), Nt.port('c:o', 'n', 60 / 90)], { head: true, cls: 'act' });
    it.push(verdict('w3:v', 482, 'only encrypt-then-MAC is secure for any secure cipher and MAC', 'good'));
    return it.concat(Nt.items);
  };

  function order(inp) {
    const ke = U.key(inp.ke, [16]), km = utf8(inp.km), iv = U.block(inp.iv), P = utf8(inp.msg), M = S.Modes, Mc = S.MAC, E = S.AES.cipher(ke);
    const Pp = M.pkcs7(P, 16), n = Pp.length / 16, padN = Pp.length - P.length, C = M.encrypt('cbc', E, Pp, { iv, trace: false }).out;
    const T = Mc.hmac('sha256', km, cat(iv, C));
    const iv2 = Uint8Array.from(iv), C2 = Uint8Array.from(C), T2 = Uint8Array.from(T);
    let what = null, short = null;
    if (inp.tamper === 'c1') { C2[0] ^= 1; what = 'the lowest bit of byte 0 of C₁'; short = 'flips one bit of C₁'; }
    else if (inp.tamper === 'pad') { if (n > 1) { C2[16 * (n - 2) + 15] ^= 1; what = `the lowest bit of the last byte of C${sub(n - 1)}, which lands on the padding`; short = 'flips a bit that lands on the padding'; } else { iv2[15] ^= 1; what = 'the lowest bit of the last byte of the IV, which lands on the padding'; short = 'flips an IV bit that lands on the padding'; } }
    else if (inp.tamper === 'tag') { T2[0] ^= 1; what = 'the lowest bit of the tag'; short = 'flips one bit of the tag'; }
    const T3 = Mc.hmac('sha256', km, cat(iv2, C2)), ok = Mc.equal(T3, T2), nT = T3.filter((v, i) => v !== T2[i]).length;
    const D = M.decrypt('cbc', E, C2, { iv: iv2, trace: false }).out, last = D[D.length - 1];
    let padOk = true, un = null; try { un = M.unpkcs7(D, 16); } catch (e) { padOk = false; }
    const F = new S.Frames([{ id: 'dk', label: 'Dₖ calls at the receiver' }]);
    // the pipeline, lit up to a stage: 0 encrypt, 1 MAC, 2 wire, 3 verify, 4 decrypt
    const pipe = (st) => {
      const Nt = Fl().net('op'), it = [...lane('ol:s', 6, 140, 'sender: encrypt, then MAC'), ...lane('ol:w', 154, 92, 'on the wire', st === 2 && what ? 'hot' : ''), ...lane('ol:r', 254, 222, 'receiver: check the tag, then decrypt')];
      const lit = (k, c) => (st === k ? 'act' : st > k ? c || '' : 'soft');
      Nt.box('p', 92, 78, 140, 52, ['P, padded', K6().short(Pp, 6)], 'val2' + (st === 0 ? ' act' : ''));
      Nt.box('e', 258, 78, 124, 54, ['AES-CBC', 'key kₑ, IV'], 'cipher small');
      Nt.box('c', 430, 78, 148, 52, ['IV ‖ C', K6().short(cat(iv, C), 6)], 'val2' + (st === 0 ? ' hot' : ''));
      Nt.box('m', 610, 78, 140, 54, ['HMAC-SHA256', 'key kₘ, over IV ‖ C'], 'small ' + (st === 1 ? 'act' : st > 1 ? '' : 'soft'));
      Nt.box('t', 790, 78, 112, 52, ['T', st >= 1 ? K6().short(T, 6) : ''], 'val2 ' + (st === 1 ? 'hot' : st > 1 ? 'act' : 'soft'));
      Nt.box('a', 430, 205, 360, 44, ['attacker', short || 'changes nothing'], 'small ' + (st === 2 ? (what ? 'hot' : 'good') : 'soft'));
      Nt.box('r', 100, 370, 150, 52, ['IV′ ‖ C′, T′', st >= 3 ? K6().short(cat(iv2, C2), 6) : ''], 'val2' + (st >= 3 ? '' : ' soft'));
      const vc = st < 3 ? 'soft' : ok ? 'good' : 'bad';
      Nt.box('v', 300, 370, 170, 60, ['check the tag', 'constant-time compare'], 'small ' + vc);
      Nt.box('d', 490, 370, 120, 54, ['AES-CBC⁻¹', 'key kₑ'], 'small ' + (st >= 4 && ok ? 'cipher' : 'soft'));
      Nt.box('u', 640, 370, 110, 54, ['unpad', 'PKCS#7'], 'small ' + (st >= 4 && ok ? 'act' : 'soft'));
      Nt.box('o', 785, 370, 120, 52, ['P', st >= 4 && ok ? K6().short(un || P, 6) : ''], 'val2 ' + (st >= 4 && ok ? 'good' : 'soft'));
      Nt.box('x', 300, 446, 220, 36, 'reject, with the one error', 'small ' + (st >= 3 && !ok ? 'bad' : 'soft'));
      Nt.wire('pe', [Nt.port('p', 'e'), Nt.port('e', 'w')], { head: true, cls: st === 0 ? 'act' : '' });
      Nt.wire('ec', [Nt.port('e', 'e'), Nt.port('c', 'w')], { head: true, cls: st === 0 ? 'act' : '' });
      Nt.wire('cm', [Nt.port('c', 'e'), Nt.port('m', 'w')], { head: true, cls: st === 1 ? 'act' : '' });
      Nt.wire('mt', [Nt.port('m', 'e'), Nt.port('t', 'w')], { head: true, cls: st === 1 ? 'act' : '' });
      Nt.wire('ca', [Nt.port('c', 's'), Nt.port('a', 'n')], { head: true, cls: st === 2 ? 'act' : '' });
      Nt.wire('ta', [Nt.port('t', 's'), [790, 205], Nt.port('a', 'e')], { head: true, cls: st === 2 ? 'act' : '' });
      Nt.wire('ar', [Nt.port('a', 's'), [430, 290], [100, 290], Nt.port('r', 'n')], { head: true, cls: st === 2 ? 'act' : '' });
      Nt.wire('rv', [Nt.port('r', 'e'), Nt.port('v', 'w')], { head: true, cls: st === 3 ? 'act' : '' });
      Nt.wire('vd', [Nt.port('v', 'e'), Nt.port('d', 'w')], { head: true, cls: st >= 4 && ok ? 'act' : '' });
      Nt.wire('du', [Nt.port('d', 'e'), Nt.port('u', 'w')], { head: true, cls: st >= 4 && ok ? 'act' : '' });
      Nt.wire('uo', [Nt.port('u', 'e'), Nt.port('o', 'w')], { head: true, cls: st >= 4 && ok ? 'act' : '' });
      Nt.wire('vx', [Nt.port('v', 's'), Nt.port('x', 'n')], { head: true, cls: st >= 3 && !ok ? 'hot' : '' });
      Nt.label('vdl', 408, 360, 'match', st >= 3 && ok ? 'good' : 'tick', 'middle', 13);
      Nt.label('vxl', 310, 418, 'no match', st >= 3 && !ok ? 'bad' : 'tick', 'start', 13);
      return it.concat(Nt.items);
    };
    F.add({ items: threeWays(), say: 'A cipher and a message authentication code can be combined in three orders. MAC-then-encrypt tags the plaintext and encrypts both; encrypt-and-MAC sends a tag of the plaintext beside the ciphertext; encrypt-then-MAC tags the ciphertext. Only the last lets the receiver check the tag before it touches the ciphertext with the key.', facts: {}, meta: { stage: 'three' } });
    F.add({ items: [...pipe(0), ...K6().readout([['P, padded', U.hex(Pp)], ['IV', U.hex(iv)], ['C', U.hex(C), 'hot']], 'encrypt-then-MAC: AES-CBC and HMAC-SHA256')], hl: { d: [0] }, say: `Encrypt-then-MAC with two independent keys. The ${P.length}-byte message gets ${padN} byte${padN > 1 ? 's' : ''} of PKCS#7 padding, making ${n} block${n > 1 ? 's' : ''}, and AES-CBC under kₑ with IV ${U.hex(iv)} gives C = ${K6().hexb(C)}.`, facts: { L: P.length, padN, n, iv, C, Cb: K6().blocks(C) }, meta: { stage: 'enc' } });
    F.add({ items: [...pipe(1), ...K6().readout([['T', U.hex(T), 'act']], 'T = HMAC(kₘ, IV ‖ C): it covers the IV and every byte of C')], hl: { d: [1] }, say: `The tag is HMAC-SHA256 under kₘ over IV ‖ C: T = ${K6().hexb(T)}, 32 bytes. It covers the IV too, since changing the IV changes the first plaintext block.`, facts: { T, Tb: K6().blocks(T) }, meta: { stage: 'mac' } });
    F.add({ items: [...pipe(2), ...K6().readout(what ? [['sent', U.hex(cat(iv, C)) + ' | T'], ['received', U.hex(cat(iv2, C2)) + ' | T′', 'hot']] : [['received', 'IV, C and T exactly as sent', 'good']], 'in transit')], hl: { d: [2] }, say: what ? `An attacker flips ${what}. The IV, C and T are sent together, and the receiver cannot see which bytes, if any, were touched.` : 'This time nothing is changed on the way: IV, C and T arrive as they were sent.', facts: {}, meta: { stage: 'wire', what: !!what } });
    F.add({ items: [...pipe(3), ...K6().readout([['T′ received', U.hex(T2)], ['HMAC(kₘ, IV′ ‖ C′)', U.hex(T3), ok ? 'good' : 'hot']], ok ? 'the tags match' : `${nT} of 32 bytes differ`)], narrowView: K6().follow(300, { w: 600, y: 250, h: 390 }), hl: { d: [3] }, say: ok ? `The receiver's first step uses kₘ only: HMAC over IV′ ‖ C′ gives ${K6().hexb(T3)}, equal to the T′ received. Only now does it decrypt.` : `The receiver's first step uses kₘ only: HMAC over IV′ ‖ C′ gives ${K6().hexb(T3)}, and ${nT} of the 32 bytes differ from the T′ received. The message is rejected here: the block cipher has run 0 times and the padding was never looked at.`, facts: { T3, T3b: K6().blocks(T3), nT, z: 0 }, counters: { dk: 0 }, meta: { stage: 'verify', ok } });
    if (ok) F.add({ items: [...pipe(4), ...K6().readout([['decrypted', U.hex(D)], ['message', show(un), 'good']], 'verified, then decrypted')], hl: { d: [4] }, counters: { dk: n }, say: `With the tag verified, CBC decryption under kₑ runs ${n} block${n > 1 ? 's' : ''}; the last byte, ${U.h2(last)}, says how much padding to strip, and the message ${show(un)} comes out.`, facts: { n, last, un }, meta: { stage: 'dec' } });
    else F.add({ items: [...pipe(3), ...K6().readout([['decrypt first', U.hex(D)], ['last byte', U.h2(last) + (padOk ? ': padding valid' : ': padding invalid'), padOk ? '' : 'hot'], ['error it would give', padOk ? '“bad MAC”' : '“bad padding”', 'hot']], 'had it decrypted first')], hl: { d: [5] }, say: `Compare a receiver that decrypts first, as MAC-then-encrypt forces. It would run CBC on all ${n} block${n > 1 ? 's' : ''} and find the last byte ${U.h2(last)}: the padding is ${padOk ? 'valid, so it goes on to fail at the MAC' : 'invalid, so it fails before any MAC is checked'}. If those two failures differ in message or in time, the receiver is a padding oracle, and its answers decrypt C byte by byte.`, facts: { n, last }, meta: { stage: 'mte', padOk } });
    const rules = [['verify the tag before decrypting or unpadding anything', 'strong'], ['compare tags in constant time, never byte by byte with an early exit', 'strong'], ['every failure gives the same error, after the same work', 'strong'], ['release no plaintext from a message that fails', 'strong'], ['independent keys kₑ and kₘ, or one AEAD key', 'strong']];
    F.add({ items: [...U.panel('ru', 40, 30, 800, 70 + rules.length * 44, 'the receiver\'s rules'), ...rules.map((r, i) => U.t('ru:' + i, 64, 96 + i * 44, (i + 1) + '.  ' + r[0], r[1], 'start', 15)), ...K6().readout([['this message', ok ? 'accepted: ' + show(un) : 'rejected at the tag; the block cipher never ran', ok ? 'good' : 'hot']], 'one outcome, one error')], hl: { d: [3, 5] }, say: 'So the receiver checks the tag first, compares it in constant time, and answers every failure, bad tag or bad padding or anything else, with one and the same error, after the same amount of work. An attacker who learns only “rejected” learns nothing about which part failed.', facts: {}, meta: { stage: 'rules' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Encrypt-then-MAC', ['send:  C = CBC(kₑ, IV, pad(P)),  T = HMAC(kₘ, IV ‖ C)', 'the tag covers the IV and every byte of C', 'on the wire anything may change', 'receive:  T′ = HMAC(kₘ, IV′ ‖ C′) first, compare in constant time', 'only on a match: decrypt with kₑ, then unpad', 'any failure: one error, the same work, no plaintext']) };
  }
  S.topic({
    id: 'integrity-order', family: 'p06-labs', order: 70, title: 'Encrypt, MAC, and in which order',
    blurb: 'MAC-then-encrypt, encrypt-and-MAC and encrypt-then-MAC as data flow. With CBC and HMAC-SHA256, encrypt-then-MAC rejects a tampered message at the tag check, before any decryption or padding check can leak anything.',
    inputs: [msgInput('msg', 'Message', 'Release crate 7 at dawn', 40), { id: 'ke', kind: 'text', label: 'Encryption key kₑ (16 characters or 32 hex digits)', def: 'kestrel-and-oak!', check: U.keyCheck('Encryption key', [16]) },
      { id: 'km', kind: 'text', label: 'MAC key kₘ (16 to 64 characters)', def: 'a separate mac key', check: (v) => { const n = utf8(v).length; return n < 16 ? 'MAC key: at least 16 characters' : n > 64 ? 'MAC key: at most 64 characters' : null; } },
      K6().ivInput(),
      { id: 'tamper', kind: 'choice', label: 'In transit', def: 'pad', options: [{ value: 'none', label: 'nothing changes' }, { value: 'c1', label: 'flip a bit of C₁' }, { value: 'pad', label: 'flip a bit that lands on the padding' }, { value: 'tag', label: 'flip a bit of the tag' }] }],
    presets: [
      { label: 'A bit aimed at the padding', values: { msg: 'Release crate 7 at dawn', tamper: 'pad' } },
      { label: 'A bit of C₁', values: { msg: 'Release crate 7 at dawn', tamper: 'c1' } },
      { label: 'A bit of the tag', values: { msg: 'Release crate 7 at dawn', tamper: 'tag' } },
      { label: 'Nothing changes', values: { msg: 'Release crate 7 at dawn', tamper: 'none' } },
      { label: 'One block, the IV tampered', values: { msg: 'gate 3 shut', tamper: 'pad' } },
    ],
    run: order, counters: [{ id: 'dk', label: 'block-cipher calls at the receiver' }],
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'wire' && f.meta.what, pick: 'option', options: ['0', '1', 'every block'], ask: 'How many times will the receiver run the block cipher on this tampered message?', answer: '0', explain: 'Encrypt-then-MAC checks the tag with kₘ alone; a bad tag stops everything before decryption.' },
      { at: (f) => f.meta && f.meta.stage === 'three', pick: 'option', options: ['MAC-then-encrypt', 'encrypt-and-MAC', 'encrypt-then-MAC'], ask: 'Which order lets the receiver check integrity without decrypting?', answer: 'encrypt-then-MAC', explain: 'Its tag is over the ciphertext, which the receiver has before it decrypts.' },
    ],
    quiz: [
      { q: 'In encrypt-then-MAC, what does the MAC cover?', options: ['The plaintext', 'The ciphertext (and the IV or nonce)', 'The key', 'The padding only'], answer: 1, why: 'So the receiver can check it before decrypting.' },
      { q: 'Why is MAC-then-encrypt with CBC risky?', options: ['It is slow', 'The receiver must decrypt and unpad before checking, and padding errors can leak as an oracle', 'The tag is too short', 'It needs two IVs'], answer: 1, why: 'Padding-oracle attacks on SSL and TLS CBC suites came from this order.' },
      { q: 'What is the weakness of encrypt-and-MAC?', options: ['None', 'The tag is over the plaintext, so a deterministic MAC shows when two messages are equal, and decryption still comes first', 'It uses one key', 'It cannot use CBC'], answer: 1, why: 'A MAC is not designed to hide its input.' },
      { q: 'Why should every decryption failure give the same error?', options: ['To save code', 'Different errors (or timings) tell the attacker which check failed, which can be turned into a decryption oracle', 'For logging', 'It does not matter'], answer: 1, why: 'Uniform errors and constant-time comparison close the side channel.' },
      { q: 'Should the encryption and MAC keys be the same?', options: ['Yes, it is simpler', 'No: use independent keys (or derive both from one key with a KDF)', 'Only for CTR', 'Only for HMAC-SHA1'], answer: 1, why: 'Reusing a key across two algorithms can let them interfere.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
