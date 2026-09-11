// Part 13, Poly1305 and ChaCha20-Poly1305: the key split into r (clamped) and s, the accumulator stepping through
// the message 16 bytes at a time modulo 2^130 − 5; then the AEAD sealing a message (a one-time Poly1305 key from
// ChaCha20 block 0, the keystream from blocks 1 on, the MAC over AAD and ciphertext with their lengths) and opening
// it again, with a tampered byte rejected before anything is decrypted.
(function (S) {
  'use strict';
  const U = S.P12, Mc = () => S.MAC;
  const { t } = U;
  const h33 = (v) => v.toString(16).padStart(33, '0');
  const leBytes = (v, n) => { const o = []; for (let i = 0; i < n; i++) { o.push(Number(v & 255n)); v >>= 8n; } return o; };

  // ---------------------------------------------------------------------------------------------------------------
  // Poly1305
  // ---------------------------------------------------------------------------------------------------------------
  function poly(inp) {
    const M = Mc(), key = U.fromHex(inp.key), msg = inp.hex ? U.fromHex(inp.msg) : U.utf8(inp.msg);
    const r = M.poly1305(key, msg, { trace: true }), raw = key.slice(0, 16), rb = leBytes(r.r, 16);
    const cleared = (i) => raw[i] !== rb[i];
    const keyRows = (stage) => {
      const items = [t('pk:t', 20, 84, 'the 32-byte one-time key: r (first 16 bytes) and s', 'ptitle')];
      for (let i = 0; i < 16; i++) {
        items.push({ key: 'pk:r' + i, kind: 'cell', x: 96 + i * 34, y: 96, w: 31, h: 26, rx: 3, text: U.h2(raw[i]), size: 13, cls: 'hex ' + (stage >= 1 && cleared(i) ? 'soft' : 'key') });
        if (stage >= 1) items.push({ key: 'pk:c' + i, kind: 'cell', x: 96 + i * 34, y: 130, w: 31, h: 26, rx: 3, text: U.h2(rb[i]), size: 13, cls: 'hex ' + (cleared(i) ? 'hot' : 'key') });
        if (stage >= 2) items.push({ key: 'pk:s' + i, kind: 'cell', x: 96 + i * 34, y: 172, w: 31, h: 26, rx: 3, text: U.h2(key[16 + i]), size: 13, cls: 'hex src' });
      }
      items.push(t('pk:rl', 86, 114, 'r', 'strong', 'end', 14));
      if (stage >= 1) items.push(t('pk:cl', 86, 148, 'clamped', 'hot', 'end', 13));
      if (stage >= 2) items.push(t('pk:sl', 86, 190, 's', 'strong', 'end', 14));
      const rv = (stage >= 1 ? r.r.toString(16).padStart(32, '0') : U.hex([...raw].reverse()));
      items.push(t('pk:note', 664, 106, 'r, read little-endian:', 'ptick', 'start', 13), t('pk:rv', 664, 130, rv.slice(0, 16), 'mono', 'start', 13), t('pk:rv2', 664, 150, rv.slice(16), 'mono', 'start', 13));
      return items;
    };
    const steps = r.steps;
    const table = (upto) => {
      const items = [t('pt:t', 20, 236, 'the accumulator, mod p = 2¹³⁰ − 5', 'ptitle')];
      const cols = [['chunk', 20, 180], ['n = chunk with 01 appended', 204, 330], ['acc = (acc + n) · r mod p', 538, 362]];
      cols.forEach(([n, x], j) => items.push(t('pt:h' + j, x, 256, n, 'ptick', 'start', 13)));
      steps.slice(0, upto).forEach((s, k) => {
        const y = 264 + k * 32, cur = k === upto - 1, chunk = msg.slice(16 * s.i, 16 * s.i + 16);
        items.push({ key: 'pt:m' + k, kind: 'cell', x: 20, y, w: 180, h: 26, rx: 4, text: U.cut(U.show(chunk), 20), size: 13, cls: 'mono ' + (cur ? 'act' : '') });
        items.push({ key: 'pt:n' + k, kind: 'cell', x: 204, y, w: 330, h: 26, rx: 4, text: h33(s.n), size: 13, cls: 'hex' });
        items.push({ key: 'pt:a' + k, kind: 'cell', x: 538, y, w: 362, h: 26, rx: 4, text: h33(s.acc), size: 13, cls: 'hex ' + (cur ? 'hot' : '') });
      });
      if (steps.length > 9 && upto > 9) items.push(t('pt:more', 20, 264 + 9 * 32 + 16, '…', 'ptick', 'start', 14));
      return items;
    };
    const head = U.head('po:h', 'Poly1305: a polynomial evaluated at r, modulo 2¹³⁰ − 5', U.plural(msg.length, 'byte') + ', ' + U.plural(steps.length, 'chunk') + ' of 16 bytes');
    const F = new S.Frames(['chunks']);
    const shownSteps = Math.min(steps.length, 9);
    F.add({ items: [...head, ...keyRows(0)], hl: { d: [0] }, say: `The 32-byte key is used for one message only. Its first 16 bytes, read as a little-endian number, are r: ${U.hex([...raw].reverse())}.`, facts: { raw: U.hex([...raw].reverse()) }, meta: { stage: 'key' } });
    const nClr = raw.reduce((n, v, i) => n + (v !== rb[i] ? 1 : 0), 0);
    F.add({ items: [...head, ...keyRows(1)], hl: { d: [1] }, say: `Clamping clears the top 4 bits of bytes 3, 7, 11 and 15 and the low 2 bits of bytes 4, 8 and 12 (${U.plural(nClr, 'byte')} changed here): r = ${r.r.toString(16)}. A clamped r keeps every product small enough for fast arithmetic and costs a few bits of security.`, facts: { r: r.r.toString(16), nClr, bytes: [3, 7, 11, 15, 4, 8, 12] }, meta: { stage: 'clamp' } });
    F.add({ items: [...head, ...keyRows(2)], hl: { d: [2] }, say: `The other 16 bytes are s = ${r.s.toString(16)}, added only at the end, so the tag hides the polynomial's value.`, facts: { s: r.s.toString(16) }, meta: { stage: 's' } });
    steps.forEach((s, k) => {
      F.count('chunks');
      if (k >= shownSteps && k !== steps.length - 1) return;
      F.add({ items: [...head, ...keyRows(2), ...table(Math.min(k + 1, shownSteps))], hl: { d: [3] }, say: `Chunk ${k + 1}: n = ${h33(s.n)} (the bytes, little-endian, with a 1 byte on top); acc = (acc + n)·r mod 2¹³⁰ − 5 = ${h33(s.acc)}.`, facts: { k: k + 1, n: h33(s.n), acc: h33(s.acc) }, meta: { stage: 'chunk', k } });
    });
    const tag = U.hex(r.tag);
    F.add({ items: [...head, ...keyRows(2), ...table(shownSteps), ...U.readout('po:t', 20, 568 - 16, 880, 'tag = (acc + s) mod 2¹²⁸, written little-endian', [['tag', tag, 'hot']], { dy: 28 })], hl: { d: [4] }, say: `The tag is (acc + s) mod 2¹²⁸ as 16 little-endian bytes: ${tag}. Poly1305 is a one-time MAC: two messages under the same r and s give away r, so the key must be fresh each time, as ChaCha20-Poly1305 makes it.`, facts: { tag }, meta: { stage: 'tag' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Poly1305 (RFC 8439)', ['r = clamp(key[0..15]),  s = key[16..31]  (little-endian)', 'p = 2¹³⁰ − 5', 'for each 16-byte chunk c: n = c + 2^(8·|c|)', 'acc = (acc + n) · r mod p', 'tag = (acc + s) mod 2¹²⁸', 'tag = c₁rᵏ + c₂rᵏ⁻¹ + … + cₖr + s: a polynomial in r']) };
  }
  S.topic({
    id: 'p13-poly1305', family: 'p13-mac', order: 60, title: 'Poly1305: clamping and the accumulator',
    blurb: 'Split a one-time key into r and s, clear a few bits of r, then add each 16-byte chunk to an accumulator and multiply by r modulo the prime 2¹³⁰ − 5. Add s, and that is the tag.',
    inputs: [{ id: 'key', kind: 'text', label: 'One-time key (32 bytes, hex)', def: '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b', check: U.hexCheck('Key', 32, 32) }, { id: 'hex', kind: 'choice', label: 'Message is', def: '', options: [{ value: '', label: 'text' }, { value: 'hex', label: 'hex bytes' }] }, { id: 'msg', kind: 'text', label: 'Message', def: 'Cryptographic Forum Research Group', check: (v, inp) => (inp.hex ? U.hexCheck('Message', 0, 144)(v) : U.utf8(v).length > 144 ? 'Message: at most 144 bytes' : null) }],
    presets: [
      { label: 'RFC 8439, section 2.5.2', values: { key: '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b', hex: '', msg: 'Cryptographic Forum Research Group' } },
      { label: 'Our own note', values: { key: '0f1e2d3c4b5a69788796a5b4c3d2e1f0112233445566778899aabbccddeeff00', hex: '', msg: 'meet at the north gate' } },
      { label: 'r = 0: the tag is just s', values: { key: '0000000000000000000000000000000001010101010101010101010101010101', hex: '', msg: 'a zero r makes every message tag the same' } },
    ],
    counters: [{ id: 'chunks', label: 'chunks' }],
    run: poly,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'key', pick: 'option', options: ['its top 4 bits', 'its low 2 bits', 'both, in different bytes', 'none'], ask: 'Clamping clears which bits of r?', answer: 'both, in different bytes', explain: 'The top 4 bits of bytes 3, 7, 11, 15 and the low 2 bits of bytes 4, 8, 12.' }],
    quiz: [
      { q: 'What is the prime in Poly1305?', options: ['2^128 + 1', '2^130 − 5', '2^255 − 19', '2^127 − 1'], answer: 1, why: 'Hence the name.' },
      { q: 'Why is a 1 byte appended to each chunk?', options: ['padding to 17 bytes', 'so trailing zero bytes still change the value', 'for the length', 'for speed'], answer: 1, why: 'Without it, chunks differing only in trailing zeros would give the same n.' },
      { q: 'Why must a Poly1305 key be used only once?', options: ['it wears out', 'two tags under the same r, s reveal r, and then forgeries', 'it is short', 'it need not'], answer: 1, why: 'The difference of two tags is a polynomial in r with known coefficients.' },
      { q: 'What does s do?', options: ['nothing', 'masks the polynomial\'s value, like a one-time pad', 'sets the length', 'it is the nonce'], answer: 1, why: 'tag = poly(r) + s mod 2¹²⁸.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // ChaCha20-Poly1305
  // ---------------------------------------------------------------------------------------------------------------
  function aead(inp) {
    const A = Mc().aead, key = /^[0-9a-fA-F]{64}$/.test(inp.key) ? U.fromHex(inp.key) : U.utf8(inp.key), nonce = U.fromHex(inp.nonce);
    const pt = U.utf8(inp.pt), aad = inp.aadHex ? U.fromHex(inp.aad) : U.utf8(inp.aad);
    const s = A.seal(key, nonce, pt, aad, { trace: true });
    const ct = s.ciphertext, tag = s.tag;
    // what arrives: perhaps tampered with
    let rc = Uint8Array.from(ct), raad = Uint8Array.from(aad), rtag = Uint8Array.from(tag), rnonce = Uint8Array.from(nonce), where = -1;
    if (inp.tamper === 'ct' && rc.length) { where = Math.min(5, rc.length - 1); rc[where] ^= 0x01; }
    if (inp.tamper === 'aad') { if (raad.length) raad[0] ^= 0x01; else raad = Uint8Array.of(1); }
    if (inp.tamper === 'tag') rtag[15] ^= 0x80;
    if (inp.tamper === 'nonce') rnonce[11] ^= 0x01;
    const o = A.open(key, rnonce, rc, rtag, raad, { trace: true }), want = A.open(key, rnonce, rc, tag, raad).ok ? tag : null;
    const otk = U.hex(s.otk), rr = otk.slice(0, 32), ss = otk.slice(32);
    const ks = Uint8Array.from(ct, (v, i) => v ^ pt[i]);
    const strip = (pre, y, label, bytes, cls, lit) => {
      const n = Math.min(28, bytes.length), items = [t(pre + ':l', 20, y + 17, label, 'strong', 'start', 13)];
      for (let i = 0; i < n; i++) items.push({ key: pre + i, kind: 'cell', x: 120 + i * 27, y, w: 25, h: 24, rx: 3, text: cls === 'txt' ? (bytes[i] >= 33 && bytes[i] < 127 ? String.fromCharCode(bytes[i]) : bytes[i] === 32 ? '␣' : '·') : U.h2(bytes[i]), size: 13, cls: 'hex ' + (lit && lit(i) ? lit(i) : cls === 'txt' ? 'pm' : cls) });
      if (bytes.length > n) items.push(t(pre + ':m', 120 + 28 * 27 + 2, y + 17, '+' + (bytes.length - n), 'ptick', 'start', 13));
      if (!bytes.length) items.push(t(pre + ':e', 120, y + 17, '(empty)', 'ptick', 'start', 13));
      return items;
    };
    const otkRow = () => [...U.readout('ae:o', 20, 72, 880, 'ChaCha20 block 0 under the key and nonce: the one-time Poly1305 key', [['r (clamped later)', rr, 'key'], ['s', ss, 'src']], { dy: 26, vsize: 13 })];
    const enc = () => [t('ae:et', 20, 190, 'ChaCha20 blocks 1, 2, …: the keystream', 'ptitle'), ...strip('ae:p', 200, 'plaintext', pt, 'txt'), ...strip('ae:k', 230, 'keystream', ks, 'soft'), ...strip('ae:c', 260, 'ciphertext', ct, 'act')];
    const macBar = (rx) => {
      const ad = rx ? raad : aad, cc = rx ? rc : ct, segs = [['AAD', ad.length, 'key'], ['pad', (16 - (ad.length % 16)) % 16, 'p00'], ['ciphertext', cc.length, 'act'], ['pad', (16 - (cc.length % 16)) % 16, 'p00'], ['len(AAD)', 8, 'plen'], ['len(ct)', 8, 'plen']];
      const total = segs.reduce((a, s2) => a + s2[1], 0), sc = 760 / total, items = [t('ae:mt', 20, 310, 'Poly1305 runs over ' + total + ' bytes:', 'ptitle')];
      let x = 120;
      segs.forEach(([lab, n, cls], k) => { if (!n) return; const w = n * sc - 2; items.push({ key: 'ae:ms' + k, kind: 'cell', x: U.r2(x), y: 320, w: U.r2(w), h: 26, rx: 3, text: S.geom.textWidth(lab, 12) + 8 < w ? lab : '', size: 13, cls: 'hex ' + cls }); x += n * sc; });
      return items;
    };
    const sealPanel = () => [...U.readout('ae:s', 20, 370, 430, 'sent', [['nonce', U.hex(nonce)], ['AAD', U.cut(U.show(aad), 30) || '(none)'], ['ciphertext', U.short(ct, 9)], ['tag', U.hex(tag), 'hot']], { dy: 26, vsize: 13 })];
    const openPanel = (stage) => {
      const rows = [['nonce', U.hex(rnonce), inp.tamper === 'nonce' ? 'bad' : ''], ['AAD', U.cut(U.show(raad), 30) || '(none)', inp.tamper === 'aad' ? 'bad' : ''], ['ciphertext', U.short(rc, 9), inp.tamper === 'ct' ? 'bad' : ''], ['tag received', U.hex(rtag), inp.tamper === 'tag' ? 'bad' : '']];
      const tagNow = Mc().poly1305(A.otk(key, rnonce), A.macData(raad, rc));
      if (stage >= 1) rows.push(['tag recomputed', U.hex(tagNow), o.ok ? 'good' : 'bad']);
      if (stage >= 2) rows.push([o.ok ? 'decrypted' : 'result', o.ok ? U.cut(U.text(o.plaintext), 30) : 'rejected, nothing decrypted', o.ok ? 'good' : 'bad']);
      return U.readout('ae:r', 470, 370, 430, 'received' + (inp.tamper !== 'none' ? ' (altered on the way)' : ''), rows, { dy: 26, vsize: 13 });
    };
    const head = U.head('ae:h', 'ChaCha20-Poly1305: seal, then open', U.plural(pt.length, 'byte') + ' of plaintext, ' + U.plural(aad.length, 'byte') + ' of associated data');
    const F = new S.Frames(['blocks']);
    F.add({ items: [...head, ...otkRow()], hl: { d: [0] }, say: `ChaCha20 block 0, under the key and the nonce ${U.hex(nonce)}, gives a fresh one-time Poly1305 key: r = ${U.short(rr, 6)}, s = ${U.short(ss, 6)}. A new nonce means a new r and s for every message.`, facts: { otk, nonce: U.hex(nonce) }, meta: { stage: 'otk' } });
    F.set('blocks', 1 + Math.ceil(pt.length / 64));
    F.add({ items: [...head, ...otkRow(), ...enc()], hl: { d: [1] }, say: pt.length ? `Blocks 1, 2, … give the keystream; the ${U.plural(pt.length, 'byte')} of plaintext XOR it to the ciphertext ${U.short(ct, 8)}.` : 'There is no plaintext, so the ciphertext is empty: only the associated data will be authenticated.', facts: { ct: U.hex(ct), n: pt.length }, meta: { stage: 'enc' } });
    F.add({ items: [...head, ...otkRow(), ...enc(), ...macBar(false)], hl: { d: [2] }, say: `Poly1305 authenticates the associated data and the ciphertext, each zero-padded to 16 bytes, then both lengths as 8-byte little-endian numbers (${s.macData.length} bytes). The lengths stop bytes from sliding between AAD and ciphertext.`, facts: { md: s.macData.length }, meta: { stage: 'macdata' } });
    F.add({ items: [...head, ...otkRow(), ...enc(), ...macBar(false), ...sealPanel()], hl: { d: [3] }, say: `The tag: ${U.hex(tag)}. Sent: nonce, AAD, ciphertext and tag. The AAD travels in the clear; it is authenticated, not encrypted.`, facts: { tag: U.hex(tag) }, meta: { stage: 'sealed' } });
    const altered = { none: 'nothing was changed on the way', ct: 'one bit of the ciphertext was flipped on the way', aad: 'one bit of the associated data was flipped on the way', tag: 'one bit of the tag was flipped on the way', nonce: 'the receiver used a different nonce' }[inp.tamper];
    F.add({ items: [...head, ...otkRow(), ...enc(), ...macBar(true), ...sealPanel(), ...openPanel(1)], hl: { d: [4] }, say: `Opening: ${altered}. The receiver derives the one-time key from its nonce and recomputes the tag over what arrived: ${U.hex(Mc().poly1305(A.otk(key, rnonce), A.macData(raad, rc)))}.`, facts: { tag2: U.hex(Mc().poly1305(A.otk(key, rnonce), A.macData(raad, rc))) }, meta: { stage: 'recompute' } });
    F.add({ items: [...head, ...otkRow(), ...enc(), ...macBar(true), ...sealPanel(), ...openPanel(2)], hl: { d: [5] }, say: o.trace[0].say + (o.ok ? ` Plaintext: “${U.cut(U.text(o.plaintext), 60)}”.` : ' The receiver learns nothing about the plaintext, and an attacker learns nothing from the failure.'), facts: { ok: o.ok, step: o.trace[0].say }, meta: { stage: 'open' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('ChaCha20-Poly1305 (RFC 8439)', ['otk = ChaCha20(K, counter 0, N)[0..31]', 'C = P ⊕ ChaCha20 keystream from counter 1', 'mac data = A ‖ pad ‖ C ‖ pad ‖ len(A) ‖ len(C)', 'tag = Poly1305(otk, mac data)', 'open: recompute, compare in constant time, then decrypt', 'encrypt-then-MAC: nothing is decrypted before the tag checks']) };
  }
  S.topic({
    id: 'p13-aead', family: 'p13-aead', order: 10, title: 'ChaCha20-Poly1305: seal and open',
    blurb: 'Authenticated encryption in one call: a one-time MAC key from ChaCha20 block 0, the keystream from the blocks after, and Poly1305 over the associated data and the ciphertext. Change one bit on the way and opening fails before anything is decrypted.',
    inputs: [
      { id: 'key', kind: 'text', label: 'Key (32 characters, or 64 hex digits)', def: 'a lantern keeper guards 32 bytes', check: (v) => (/^[0-9a-fA-F]{64}$/.test(v) || U.utf8(v).length === 32 ? null : 'Key: 32 characters, or 64 hex digits') },
      { id: 'nonce', kind: 'text', label: 'Nonce (12 bytes, hex)', def: '000000000000004a00000000', check: U.hexCheck('Nonce', 12, 12) },
      { id: 'pt', kind: 'text', label: 'Plaintext', def: 'Meet at the north gate at six.', check: (v) => (U.utf8(v).length > 120 ? 'Plaintext: at most 120 bytes' : null) },
      { id: 'aadHex', kind: 'choice', label: 'Associated data is', def: '', options: [{ value: '', label: 'text' }, { value: 'hex', label: 'hex bytes' }] },
      { id: 'aad', kind: 'text', label: 'Associated data', def: 'to: ash, seq 12', check: (v, inp) => (inp.aadHex ? U.hexCheck('Associated data', 0, 32)(v) : U.utf8(v).length > 32 ? 'Associated data: at most 32 bytes' : null) },
      { id: 'tamper', kind: 'choice', label: 'On the way', def: 'none', options: [{ value: 'none', label: 'nothing changes' }, { value: 'ct', label: 'flip a ciphertext bit' }, { value: 'aad', label: 'flip a bit of the AAD' }, { value: 'tag', label: 'flip a tag bit' }, { value: 'nonce', label: 'open with another nonce' }] },
    ],
    presets: [
      { label: 'Seal and open', values: { tamper: 'none' } },
      { label: 'RFC 8439, section 2.8.2', values: { key: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', nonce: '070000004041424344454647', pt: 'Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.', aadHex: 'hex', aad: '50515253c0c1c2c3c4c5c6c7', tamper: 'none' } },
      { label: 'A flipped ciphertext bit', values: { tamper: 'ct' } },
      { label: 'Altered associated data', values: { tamper: 'aad' } },
      { label: 'The wrong nonce', values: { tamper: 'nonce' } },
    ],
    counters: [{ id: 'blocks', label: 'ChaCha20 blocks' }],
    run: aead,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'recompute', pick: 'option', options: ['the plaintext comes out', 'it is rejected'], ask: 'Will the receiver accept the message?', answer: (fr) => (fr[fr.length - 1].facts.ok ? 'the plaintext comes out' : 'it is rejected'), explain: (fr) => fr[fr.length - 1].say }],
    quiz: [
      { q: 'Where does the Poly1305 key come from?', options: ['the user', 'ChaCha20 block 0 under the key and nonce', 'the tag', 'HKDF'], answer: 1, why: 'A fresh one-time key for each nonce.' },
      { q: 'Is the associated data encrypted?', options: ['yes', 'no: it is authenticated only', 'only its length', 'only with GCM'], answer: 1, why: 'It travels in the clear, bound to the ciphertext by the tag.' },
      { q: 'Why check the tag before decrypting?', options: ['speed', 'so altered ciphertexts give no plaintext and no padding or format oracles', 'it does not matter', 'to save memory'], answer: 1, why: 'Encrypt-then-MAC: reject first.' },
      { q: 'What happens if a nonce is ever reused under one key?', options: ['nothing', 'the keystream repeats and the one-time MAC key repeats: plaintext XORs and forgeries leak', 'the tag is longer', 'decryption fails'], answer: 1, why: 'Both halves of the scheme rely on a unique nonce.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
