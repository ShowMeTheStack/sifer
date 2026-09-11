// Part 13, HKDF: extract a uniform pseudorandom key from lumpy input keying material with HMAC keyed by a salt, then
// expand it into as many output bytes as needed, each block an HMAC of the block before, the info and a counter.
(function (S) {
  'use strict';
  const U = S.P12, Mc = () => S.MAC;
  const { t } = U;
  const HN = { sha256: 'SHA-256', sha512: 'SHA-512', sha1: 'SHA-1' };
  const val = (v, hex) => (hex ? U.fromHex(v) : U.utf8(v));

  function hkdf(inp) {
    const M = Mc(), A = S.Hash.get(inp.hash), name = HN[inp.hash], L = +inp.L, hx = !!inp.hex;
    const ikm = val(inp.ikm, hx), salt = val(inp.salt, hx), info = val(inp.info, hx);
    const r = M.hkdf(inp.hash, ikm, salt, info, L, { trace: true }), prk = U.hex(r.prk), okm = U.hex(r.okm), n = r.blocks.length;
    const showV = (b) => (hx ? U.short(b, 10) : '“' + U.cut(U.text(b), 22) + '”');
    const extract = (lit) => {
      const N = S.Kit.flow.net('hx');
      N.box('salt', 150, 112, 250, 34, 'salt: ' + (salt.length ? showV(salt) : '(none: ' + A.outLen + ' zero bytes)'), 'val small key');
      N.box('ikm', 150, 176, 250, 34, 'IKM: ' + showV(ikm), 'val small');
      N.box('h', 430, 144, 170, 50, ['HMAC-' + name, 'key = salt'], 'cipher small' + (lit ? ' act' : ''));
      N.box('prk', 720, 144, 300, 34, 'PRK = ' + prk.slice(0, 24) + '…', 'val small ' + (lit ? 'hot' : 'key'));
      N.wire('s', [N.port('salt', 'e'), [320, 112], [320, 134], N.port('h', 'w', -0.4)], { head: true });
      N.wire('i', [N.port('ikm', 'e'), [320, 176], [320, 154], N.port('h', 'w', 0.4)], { head: true });
      N.wire('p', [N.port('h', 'e'), N.port('prk', 'w')], { head: true, cls: lit ? 'act' : '' });
      return [t('hx:t', 20, 86, 'extract', 'ptitle'), ...N.items];
    };
    const cw = Math.min(210, 820 / n);
    const expand = (upto) => {
      const N = S.Kit.flow.net('he'), items = [t('he:t', 20, 250, 'expand: T(i) = HMAC(PRK, T(i−1) ‖ info ‖ i)', 'ptitle')];
      for (let i = 0; i < upto; i++) {
        const cx = 120 + i * cw, cur = i === upto - 1;
        N.box('in' + i, cx, 290, cw - 24, 34, (i ? 'T(' + i + ') ‖ ' : '') + 'info ‖ ' + U.h2(i + 1), 'val small');
        N.box('h' + i, cx, 352, cw - 24, 40, 'HMAC(PRK, ·)', 'cipher small' + (cur ? ' act' : ''));
        N.box('t' + i, cx, 414, cw - 24, 34, 'T(' + (i + 1) + ') ' + U.hex(r.blocks[i]).slice(0, 8) + '…', 'val small ' + (cur ? 'hot' : ''));
        N.wire('a' + i, [N.port('in' + i, 's'), N.port('h' + i, 'n')], { head: true });
        N.wire('b' + i, [N.port('h' + i, 's'), N.port('t' + i, 'n')], { head: true, cls: cur ? 'act' : '' });
      }
      for (let i = 0; i + 1 < upto; i++) { const cx = 120 + i * cw; N.wire('c' + i, [N.port('t' + i, 'e'), [cx + cw / 2, 414], [cx + cw / 2, 290], N.port('in' + (i + 1), 'w')], { head: true }); }
      return items.concat(N.items);
    };
    const okmBar = () => {
      const items = [t('ho:t', 20, 476, 'OKM: the first ' + L + ' bytes of T(1) ‖ T(2) ‖ …', 'ptitle')];
      const total = n * A.outLen, sc = 860 / total;
      for (let i = 0; i < n; i++) {
        const from = i * A.outLen, to = Math.min(L, from + A.outLen), w = (to - from) * sc - 2;
        if (to > from) items.push({ key: 'ho:b' + i, kind: 'cell', x: U.r2(20 + from * sc), y: 486, w: U.r2(w), h: 28, rx: 3, text: (() => { const lab = 'T(' + (i + 1) + ')' + (to - from < A.outLen ? ', ' + (to - from) + ' of ' + A.outLen + ' bytes' : ''); return S.geom.textWidth(lab, 13) * 1.15 + 16 < w ? lab : S.geom.textWidth('T(' + (i + 1) + ')', 13) + 8 < w ? 'T(' + (i + 1) + ')' : ''; })(), size: 13, cls: 'hex ' + ['act', 'key', 'src'][i % 3] });
        if (to < from + A.outLen) items.push({ key: 'ho:x' + i, kind: 'cell', x: U.r2(20 + to * sc), y: 486, w: U.r2((from + A.outLen - to) * sc - 2), h: 28, rx: 3, text: '', cls: 'hex p00' });
      }
      const lines = okm.match(/.{1,64}/g);
      lines.forEach((l, k) => items.push(t('ho:l' + k, 20, 540 + 22 * k, l.replace(/(.{8})(?!$)/g, '$1 '), 'mono hot', 'start', 14)));
      return items;
    };
    const head = U.head('hk:h', 'HKDF with HMAC-' + name + ': extract, then expand', L + ' bytes of output asked for, ' + U.plural(n, 'HMAC block') + ' of ' + A.outLen);
    const F = new S.Frames(['hmacs']);
    F.add({ items: [...head, ...extract(false)], hl: { d: [0] }, say: `The input keying material is ${U.plural(ikm.length, 'byte')}, perhaps a Diffie–Hellman secret with structure in it; the salt is ${salt.length ? U.plural(salt.length, 'byte') : 'absent, so ' + A.outLen + ' zero bytes stand in'}; the info, ${U.plural(info.length, 'byte')}, says what the keys are for.`, facts: { il: ikm.length, sl: salt.length, nl: info.length, out: A.outLen }, meta: { stage: 'inputs' } });
    F.count('hmacs');
    F.add({ items: [...head, ...extract(true)], hl: { d: [1] }, say: `Extract: PRK = HMAC-${name}(salt, IKM) = ${U.spaced(prk)}. However lumpy the input, the PRK is a uniform ${A.outLen}-byte key.`, facts: { prk, out: A.outLen }, meta: { stage: 'extract' } });
    r.blocks.forEach((b, i) => {
      F.count('hmacs');
      F.add({ items: [...head, ...extract(false), ...expand(i + 1)], hl: { d: [2] }, say: `T(${i + 1}) = HMAC(PRK, ${i ? `T(${i}) ‖ ` : ''}info ‖ ${U.h2(i + 1)}) = ${U.spaced(U.hex(b))}.${i === 0 && n > 1 ? ' Each block feeds the next, so they are chained, not independent.' : ''}`, facts: { i: i + 1, T: U.hex(b), c: U.h2(i + 1) }, meta: { stage: 'expand', i } });
    });
    F.add({ items: [...head, ...extract(false), ...expand(n), ...okmBar()], hl: { d: [3] }, say: `The output keying material is the first ${L} bytes of T(1) ‖ … ‖ T(${n}): ${U.spaced(okm)}. Changing the info gives unrelated keys from the same PRK: that is how one handshake yields separate keys for each direction and purpose.`, facts: { okm, L, n }, meta: { stage: 'okm' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('HKDF (RFC 5869)', ['extract: PRK = HMAC(salt, IKM)  (no salt: HashLen zero bytes)', 'expand: T(0) = empty', 'T(i) = HMAC(PRK, T(i−1) ‖ info ‖ i)  (i as one byte)', 'OKM = first L bytes of T(1) ‖ T(2) ‖ …', 'L ≤ 255 · HashLen']) };
  }
  S.topic({
    id: 'p13-hkdf', family: 'p13-aead', order: 20, title: 'HKDF: extract, then expand',
    blurb: 'A shared secret is not a key: it has structure and the wrong length. HKDF first extracts a uniform key with HMAC, then expands it into as many bytes as a protocol needs, labelled by an info string.',
    inputs: [
      { id: 'hex', kind: 'choice', label: 'Inputs are', def: '', options: [{ value: '', label: 'text' }, { value: 'hex', label: 'hex bytes' }] },
      { id: 'ikm', kind: 'text', label: 'Input keying material', def: 'a shared secret from the handshake', check: (v, inp) => (inp.hex ? U.hexCheck('IKM', 1, 80)(v) : !v.length || U.utf8(v).length > 80 ? 'IKM: 1 to 80 bytes' : null) },
      { id: 'salt', kind: 'text', label: 'Salt', def: 'harbour-salt', check: (v, inp) => (inp.hex ? U.hexCheck('Salt', 0, 80)(v) : U.utf8(v).length > 80 ? 'Salt: at most 80 bytes' : null) },
      { id: 'info', kind: 'text', label: 'Info', def: 'client write key', check: (v, inp) => (inp.hex ? U.hexCheck('Info', 0, 80)(v) : U.utf8(v).length > 80 ? 'Info: at most 80 bytes' : null) },
      { id: 'L', kind: 'number', label: 'Output bytes', def: 42, min: 1, max: 160 },
      { id: 'hash', kind: 'choice', label: 'Hash', def: 'sha256', options: Object.keys(HN).map((k) => ({ value: k, label: HN[k] })) },
    ],
    presets: [
      { label: 'Two keys\' worth from a secret', values: { hex: '', ikm: 'a shared secret from the handshake', salt: 'harbour-salt', info: 'client write key', L: 42, hash: 'sha256' } },
      { label: 'RFC 5869, test case 1', values: { hex: 'hex', ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', salt: '000102030405060708090a0b0c', info: 'f0f1f2f3f4f5f6f7f8f9', L: 42, hash: 'sha256' } },
      { label: 'No salt, short output', values: { hex: '', ikm: 'a shared secret from the handshake', salt: '', info: 'server write key', L: 16, hash: 'sha256' } },
      { label: 'SHA-512, 160 bytes', values: { hex: '', ikm: 'a shared secret from the handshake', salt: 'harbour-salt', info: 'all the keys', L: 160, hash: 'sha512' } },
    ],
    counters: [{ id: 'hmacs', label: 'HMAC calls' }],
    run: hkdf,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'extract', pick: 'option', options: (fr) => { const n = fr.filter((f) => f.meta.stage === 'expand').length; return [...new Set([1, 2, 3, n])].sort((a, b) => a - b).map(String); }, ask: 'How many expand blocks are needed for this output length?', answer: (fr) => String(fr.filter((f) => f.meta.stage === 'expand').length), explain: 'Each block gives one hash length of output; round up.' }],
    quiz: [
      { q: 'Why not use a Diffie–Hellman shared secret directly as an AES key?', options: ['it is too short', 'it is not uniformly random and has the wrong length; extract makes it uniform', 'it is public', 'AES refuses it'], answer: 1, why: 'Group elements have structure; HKDF-Extract concentrates their entropy into a uniform key.' },
      { q: 'What does the info string do?', options: ['adds secrecy', 'separates outputs for different purposes', 'sets the length', 'nothing'], answer: 1, why: 'Different info, unrelated keys from the same PRK.' },
      { q: 'What is the most HKDF-SHA256 can output?', options: ['32 bytes', '255 × 32 = 8160 bytes', 'unlimited', '256 bytes'], answer: 1, why: 'The counter is a single byte.' },
      { q: 'With no salt, HKDF uses…', options: ['a random salt', 'HashLen zero bytes', 'the info', 'the IKM twice'], answer: 1, why: 'RFC 5869 defines that default.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
