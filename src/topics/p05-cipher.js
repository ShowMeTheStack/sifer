// Part 5, the whole cipher: AES encryption step by step (the state before and after each of SubBytes, ShiftRows,
// MixColumns and AddRoundKey, the round key beside it, and one byte followed through), and the inverse cipher, whose
// inverse steps land back on every state the encryption passed through, in reverse.
(function (S) {
  'use strict';
  const U = S.P5;
  const C5 = (S.P5c = S.P5c || {});

  // ---- the picture both topics share -----------------------------------------------------------------------------
  // the step's input grid (left), an arrow with the step's name, its output grid (right), the round key under the
  // input, a panel of the arithmetic for the followed byte, and a strip of the rounds along the bottom
  const AX = 40, BX = 500, GY = 76, CW = 64, CH = 50, GAP = 6, KY = 392;
  const gridW = 4 * CW + 3 * GAP;
  C5.picture = function (o) {
    const items = [];
    const g = (prefix, x, vals, title, cls, tcls) => U.grid(prefix, x, GY, vals, { cw: CW, ch: CH, gap: GAP, size: 19, title, titleCls: tcls, cls }).items;
    items.push(...g('st:a', AX, o.a, o.aTitle, o.aCls));
    if (o.b) items.push(...g('st:b', BX, o.b, o.bTitle, o.bCls, 'act'));
    else if (!o.solo) items.push(...g('st:b', BX, new Array(16).fill(null), o.bTitle || ' ', () => 'soft'));
    const ay = GY + (4 * CH + 3 * GAP) / 2;
    if (!o.solo) items.push(U.arrow('st:arr', [[AX + gridW + 16, ay], [BX - 16, ay]], o.step ? 'act' : ''));
    if (o.step) items.push(U.t('st:arrl', (AX + gridW + BX) / 2, ay - 14, o.step, 'act', 'middle', 15));
    if (o.stepSub) items.push(U.t('st:arrs', (AX + gridW + BX) / 2, ay + 26, o.stepSub, 'tick', 'middle', 13));
    if (o.key) {
      items.push(...U.grid('st:k', AX, KY, o.key, { cw: 44, ch: 32, gap: 4, size: 14, title: o.keyTitle, titleCls: 'key', cls: (i) => 'key' + (i === o.pick ? ' keyhot' : '') }).items);
    }
    const PX = o.key ? 250 : AX, PW = 840 - PX;
    if (o.lines && o.lines.length) {
      items.push(...U.panel('st:p', PX, KY - 26, PW, 44 + o.lines.length * 26, o.panelTitle));
      o.lines.forEach((l, i) => items.push(U.t('st:pl' + i, PX + 16, KY + 32 + i * 26, l.text, l.cls || 'math', 'start', 14)));
    }
    // the rounds strip
    const n = o.Nr + 1, sw = Math.min(52, 800 / n), sx = 440 - (n * sw) / 2;
    items.push(U.t('st:rt', sx, 584, o.stripTitle || 'round', 'title'));
    for (let r = 0; r < n; r++) {
      const cls = o.done && o.done(r) ? 'good' : r === o.round ? 'act' : o.past && o.past(r) ? '' : 'soft';
      items.push({ key: 'st:r' + r, kind: 'cell', x: sx + r * sw, y: 594, w: sw - 4, h: 30, rx: 4, text: String(r), size: 14, cls: 'hex ' + cls });
    }
    return items;
  };
  C5.detailOpts = [{ value: 'ends', label: 'rounds 1, 2 and the last in detail' }, { value: 'all', label: 'every round in detail' }];
  const isDetail = (detail, r, Nr) => detail === 'all' || r <= 2 || r === Nr;
  C5.isDetail = isDetail;
  const cf = (i) => ({ row: i % 4, column: Math.floor(i / 4) });
  const colCls = (i) => 'col' + Math.floor(i / 4);
  /** a byte XOR a key byte, in bits: the state byte, the key byte and the result, each with its hex */
  C5.xorLines = (a, k, b) => [{ text: `   ${U.bin8(a)}   ${U.h2(a)}  state` }, { text: `⊕  ${U.bin8(k)}   ${U.h2(k)}  key`, cls: 'key' }, { text: `=  ${U.bin8(b)}   ${U.h2(b)}`, cls: 'hot' }];

  // ---- encryption --------------------------------------------------------------------------------------------------
  function encrypt(inp) {
    const P = U.block(inp.pt), K = U.key(inp.key), A = S.AES, G = S.gf256;
    const res = A.encrypt(P, K), Nr = res.rounds.length - 1, pick = inp.pick, h = U.h2;
    const F = new S.Frames();
    const base = (o) => C5.picture(Object.assign({ Nr, pick, past: (r) => r < o.round }, o));
    const lit = (cls) => (i) => (i === pick ? 'hot' : cls ? cls(i) : '');
    const R0 = res.rounds[0];
    F.add({ items: base({ a: P, aTitle: 'plaintext', aCls: lit(), key: R0.key, keyTitle: 'round key 0', round: -1 }), say: `The plaintext ${U.asText(P) ? U.asText(P) + ' ' : ''}fills the state column by column. The key gives ${Nr + 1} round keys; round key 0 is ${U.hex(R0.key)}. Byte ${pick} (${U.cell(pick)}) is lit, to follow it through.`, facts: { P, k0: R0.key, n: Nr + 1, pick, at: cf(pick) }, meta: { stage: 'start' }, hl: { d: [0] } });
    const ark = (r, a, b, k) => {
      const lines = C5.xorLines(a[pick], k[pick], b[pick]);
      F.add({ items: base({ a, aTitle: r ? 'after ' + (r === Nr ? 'ShiftRows' : 'MixColumns') : 'plaintext', aCls: lit(), b, bTitle: 'after round ' + r, bCls: lit(() => 'changed'), step: 'AddRoundKey', stepSub: 'XOR, byte by byte', key: k, keyTitle: 'round key ' + r, lines, panelTitle: 'byte ' + pick, round: r }), say: `Round ${r}, AddRoundKey: XOR round key ${r}, ${U.hex(k)}, into the state. Byte ${pick}: ${h(a[pick])} ⊕ ${h(k[pick])} = ${h(b[pick])}. The state after round ${r} is ${U.hex(b)}.`, facts: { r, k, a: a[pick], kb: k[pick], b: b[pick], st: b, pick, at: cf(pick) }, meta: { stage: 'ark', r }, hl: { d: [4] } });
    };
    ark(0, P, R0.end, R0.key);
    for (let r = 1; r <= Nr; r++) {
      const R = res.rounds[r];
      if (!isDetail(inp.detail, r, Nr)) {
        F.add({ items: base({ a: R.start, aTitle: 'after round ' + (r - 1), aCls: lit(), b: R.end, bTitle: 'after round ' + r, bCls: lit(() => 'changed'), step: 'round ' + r, stepSub: 'Sub, Shift, Mix, AddKey', key: R.key, keyTitle: 'round key ' + r, round: r }), say: `Round ${r} runs the same four steps with round key ${U.hex(R.key)}: the state ${U.hex(R.start)} becomes ${U.hex(R.end)}.`, facts: { r, k: R.key, a: R.start, st: R.end }, meta: { stage: 'round', r }, hl: { d: [3] } });
        continue;
      }
      // SubBytes
      const v = R.start[pick], tr = G.subByteTrace(v);
      F.add({ items: base({ a: R.start, aTitle: 'after round ' + (r - 1), aCls: lit(), b: R.sub, bTitle: 'after SubBytes', bCls: lit(() => 'changed'), step: 'SubBytes', stepSub: 'each byte through S', lines: [{ text: `S(${h(v)}) = ${h(R.sub[pick])}` }, { text: `inverse in GF(2⁸): ${h(v)}⁻¹ = ${h(tr.inv)}` }, { text: `affine map: ${h(tr.inv)} → ${h(R.sub[pick])}` }], panelTitle: 'byte ' + pick, round: r }), say: `Round ${r}, SubBytes: each of the 16 bytes goes through the S-box. Byte ${pick} is ${h(v)}; its inverse in GF(2⁸) is ${h(tr.inv)}, and the affine map turns that into ${h(R.sub[pick])}. The state becomes ${U.hex(R.sub)}.`, facts: { r, v, inv: tr.inv, s: R.sub[pick], st: R.sub, pick }, meta: { stage: 'sub', r }, hl: { d: [1] } });
      // ShiftRows: the followed byte moves
      const to = (pick % 4) + 4 * ((Math.floor(pick / 4) - (pick % 4) + 4) % 4);
      F.add({ items: base({ a: R.sub, aTitle: 'after SubBytes', aCls: (i) => colCls(i) + (i === pick ? ' ring' : ''), b: R.shift, bTitle: 'after ShiftRows', bCls: (i) => colCls((i % 4) + 4 * ((Math.floor(i / 4) + (i % 4)) % 4)) + (i === to ? ' ring' : ''), step: 'ShiftRows', stepSub: 'row r turns left r places', lines: A.rows(R.shift).map((t, k) => ({ text: `row ${k}: ${t}`, cls: k === pick % 4 ? 'hot' : 'math' })), panelTitle: 'the rows after the shift', round: r }), say: `ShiftRows turns row k left by k places; the colours show the column each byte came from. Byte ${pick}, in row ${pick % 4}, moves from column ${Math.floor(pick / 4)} to column ${Math.floor(to / 4)}. The state becomes ${U.hex(R.shift)}.`, facts: { r, row: pick % 4, from: Math.floor(pick / 4), to: Math.floor(to / 4), st: R.shift, pick }, meta: { stage: 'shift', r }, hl: { d: [2] } });
      // MixColumns, on the column the followed byte is now in
      if (R.mix) {
        const c = Math.floor(to / 4), col = R.shift.slice(4 * c, 4 * c + 4), mc = A.mixColumn(col), rr = to % 4, t = mc.trace[rr];
        const lines = [{ text: `column ${c}: ${U.hex(col, ' ')} → ${U.hex(mc.out, ' ')}` }, { text: `row ${rr}: ${t.coef.map((m, k) => h(m) + '·' + h(col[k])).join(' ⊕ ')}` }, { text: `= ${t.terms.map(h).join(' ⊕ ')} = ${h(t.v)}`, cls: 'hot' }];
        F.add({ items: base({ a: R.shift, aTitle: 'after ShiftRows', aCls: (i) => (Math.floor(i / 4) === c ? 'act' : ''), b: R.mix, bTitle: 'after MixColumns', bCls: (i) => (i === to ? 'hot' : Math.floor(i / 4) === c ? 'changed' : ''), step: 'MixColumns', stepSub: 'a matrix times each column', lines, panelTitle: 'column ' + c, round: r }), say: `MixColumns multiplies each column by the fixed matrix over GF(2⁸). Column ${c}, ${U.hex(col, ' ')}, becomes ${U.hex(mc.out, ' ')}; its row ${rr} is ${t.terms.map(h).join(' ⊕ ')} = ${h(t.v)}. The state becomes ${U.hex(R.mix)}.`, facts: { r, c, rr, col, out: mc.out, terms: t.terms, v: t.v, st: R.mix }, meta: { stage: 'mix', r }, hl: { d: [3] } });
      }
      const prev = R.mix || R.shift;
      const lines = C5.xorLines(prev[to], R.key[to], R.end[to]);
      F.add({ items: base({ a: prev, aTitle: R.mix ? 'after MixColumns' : 'after ShiftRows', aCls: (i) => (i === to ? 'hot' : ''), b: R.end, bTitle: 'after round ' + r, bCls: (i) => (i === to ? 'hot' : 'changed'), step: 'AddRoundKey', stepSub: R.mix ? 'XOR, byte by byte' : 'last round: no MixColumns', key: R.key, keyTitle: 'round key ' + r, lines, panelTitle: U.cell(to), round: r, pick: to }), say: `${R.mix ? '' : `Round ${r} is the last, so MixColumns was skipped. `}AddRoundKey XORs round key ${r}, ${U.hex(R.key)}: in ${U.cell(to)}, ${h(prev[to])} ⊕ ${h(R.key[to])} = ${h(R.end[to])}. The state after round ${r} is ${U.hex(R.end)}.`, facts: { r, k: R.key, a: prev[to], kb: R.key[to], b: R.end[to], st: R.end, to, at: cf(to) }, meta: { stage: 'ark', r }, hl: { d: [4] } });
    }
    F.add({ items: base({ a: res.rounds[Nr].end, aTitle: 'after round ' + Nr, aCls: () => 'hot', round: Nr + 1, past: () => true, solo: true, lines: [{ text: U.hex(res.out.slice(0, 8), ' '), cls: 'mono hot' }, { text: U.hex(res.out.slice(8), ' '), cls: 'mono hot' }], panelTitle: 'ciphertext, read out column by column' }), say: `After ${Nr} rounds the state, read out column by column, is the ciphertext: ${U.hex(res.out)}.`, facts: { C: res.out, Nr }, meta: { stage: 'out' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('One AES encryption', ['state = plaintext ⊕ round key 0', 'SubBytes: s ← S(s) for every byte', 'ShiftRows: row r turns left r places', 'MixColumns: each column ← M · column over GF(2⁸)', 'AddRoundKey: s ← s ⊕ round key r', 'last round: no MixColumns']) };
  }
  const ptIn = (def) => ({ id: 'pt', kind: 'text', label: 'Plaintext (16 characters or 32 hex digits)', def, check: U.blockCheck('Plaintext') });
  const keyIn = { id: 'key', kind: 'text', label: 'Key (16, 24 or 32 characters, or hex)', def: 'ochre-river-2026', check: U.keyCheck('Key') };
  const pickIn = { id: 'pick', kind: 'number', label: 'Byte to follow', def: 5, min: 0, max: 15 };
  const detailIn = { id: 'detail', kind: 'choice', label: 'Detail', def: 'ends', options: C5.detailOpts };
  S.topic({
    id: 'aes-encrypt', family: 'p05-cipher', order: 10, title: 'One AES encryption, round by round',
    blurb: 'Every step of every round on the 4×4 state: the S-box, the row shifts, the column mixing and the round key, with one byte followed all the way to the ciphertext.',
    inputs: [ptIn('Lanterns at dusk'), keyIn, pickIn, detailIn],
    presets: [
      { label: 'Our own line, AES-128', values: { pt: 'Lanterns at dusk', key: 'ochre-river-2026', pick: 5, detail: 'ends' } },
      { label: 'FIPS 197 C.1 (AES-128)', values: { pt: '00112233445566778899aabbccddeeff', key: '000102030405060708090a0b0c0d0e0f', pick: 0, detail: 'ends' } },
      { label: 'FIPS 197 C.2 (AES-192)', values: { pt: '00112233445566778899aabbccddeeff', key: '000102030405060708090a0b0c0d0e0f1011121314151617', pick: 10, detail: 'ends' } },
      { label: 'FIPS 197 C.3 (AES-256)', values: { pt: '00112233445566778899aabbccddeeff', key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', pick: 15, detail: 'ends' } },
      { label: 'All zeros, every round', values: { pt: '00000000000000000000000000000000', key: '00000000000000000000000000000000', pick: 3, detail: 'all' } },
    ],
    run: encrypt,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'shift' && f.meta.r === 1, pick: 'option', options: ['0', '1', '2', '3'], ask: (fr, i, inp) => `ShiftRows is next. Byte ${inp.pick} sits in row ${inp.pick % 4}, column ${Math.floor(inp.pick / 4)}. In which column will it land?`, answer: (fr, i, inp) => String((Math.floor(inp.pick / 4) - (inp.pick % 4) + 4) % 4), explain: (fr, i, inp) => `Row ${inp.pick % 4} turns left by ${inp.pick % 4}, so column ${Math.floor(inp.pick / 4)} becomes column ${(Math.floor(inp.pick / 4) - (inp.pick % 4) + 4) % 4}.`, once: true },
    ].map((p) => Object.assign(p, { at: ((a) => (f, i, fr) => i + 1 < fr.length && a(fr[i + 1]))(p.at) })),
    quiz: [
      { q: 'Which step mixes bytes from different columns?', options: ['SubBytes', 'ShiftRows', 'MixColumns', 'AddRoundKey'], answer: 1, why: 'ShiftRows moves bytes between columns; MixColumns then mixes within each column.' },
      { q: 'Which step is the only non-linear one?', options: ['SubBytes', 'ShiftRows', 'MixColumns', 'AddRoundKey'], answer: 0, why: 'The S-box (inversion in GF(2⁸)) is the only step that is not linear over GF(2).' },
      { q: 'Without AddRoundKey, what would an attacker need to decrypt?', options: ['Nothing: every other step is public and invertible', 'The S-box', 'The MixColumns matrix', 'The number of rounds'], answer: 0, why: 'All the other steps are fixed and public; the key enters only through AddRoundKey.' },
      { q: 'How many times is AddRoundKey applied in AES-128?', options: ['10', '11', '12', '44'], answer: 1, why: 'Once before the first round and once in each of the 10 rounds.' },
    ],
  });

  // ---- decryption --------------------------------------------------------------------------------------------------
  function decrypt(inp) {
    const C = U.block(inp.ct), K = U.key(inp.key), A = S.AES, h = U.h2;
    const dec = A.decryptBlock(C, K), Nr = dec.Nr, P = dec.out, enc = A.encryptBlock(P, K), pick = inp.pick;
    const E = enc.rounds.map((r) => r.end);
    const F = new S.Frames();
    const matched = new Set();
    const base = (o) => C5.picture(Object.assign({ Nr, pick, stripTitle: 'encryption state matched', done: (r) => matched.has(r) }, o));
    const eqE = (st) => E.findIndex((e) => e.every((v, i) => v === st[i]));
    const R0 = dec.rounds[0];
    F.add({ items: base({ a: C, aTitle: 'ciphertext', aCls: (i) => (i === pick ? 'hot' : ''), key: R0.key, keyTitle: 'round key ' + Nr, round: -1 }), say: `Decryption runs the rounds backwards with the inverse of every step: InvShiftRows, InvSubBytes, AddRoundKey and InvMixColumns, using the round keys from last to first. The ciphertext is ${U.hex(C)}.`, facts: { C, Nr }, meta: { stage: 'start' }, hl: { d: [0] } });
    matched.add(Nr);
    F.add({ items: base({ a: C, aTitle: 'ciphertext', b: R0.end, bTitle: 'after AddRoundKey', bCls: () => 'changed', step: 'AddRoundKey', stepSub: 'XOR is its own inverse', key: R0.key, keyTitle: 'round key ' + Nr, round: Nr }), say: `First XOR the last round key, ${U.hex(R0.key)}: XOR undoes itself, so this strips the key that round ${Nr} added, giving ${U.hex(R0.end)}.`, facts: { k: R0.key, st: R0.end, Nr }, meta: { stage: 'ark0' }, hl: { d: [3] } });
    for (let k = 1; k < dec.rounds.length; k++) {
      const R = dec.rounds[k], r = R.round, detail = isDetail(inp.detail, Nr - r, Nr);
      const m = eqE(R.sub);
      if (!detail) {
        matched.add(m);
        F.add({ items: base({ a: R.start, aTitle: 'state', b: R.end, bTitle: 'undone round ' + (r + 1), bCls: () => 'changed', step: 'undo round ' + (r + 1), stepSub: 'the four inverse steps', key: R.key, keyTitle: 'round key ' + r, round: m }), say: `Undoing round ${r + 1} with round key ${U.hex(R.key)} turns ${U.hex(R.start)} into ${U.hex(R.end)}; on the way it passes ${U.hex(R.sub)}, the state after round ${m} of the encryption.`, facts: { r: r + 1, k: R.key, a: R.start, st: R.end, sub: R.sub, m }, meta: { stage: 'round', r }, hl: { d: [1, 2, 3, 4] } });
        continue;
      }
      const from = pick % 4 + 4 * ((Math.floor(pick / 4) + (pick % 4)) % 4); // InvShiftRows moves row k right by k
      F.add({ items: base({ a: R.start, aTitle: 'state', aCls: (i) => colCls(i) + (i === pick ? ' ring' : ''), b: R.shift, bTitle: 'after InvShiftRows', bCls: (i) => colCls((i % 4) + 4 * ((Math.floor(i / 4) - (i % 4) + 4) % 4)) + (i === from ? ' ring' : ''), step: 'InvShiftRows', stepSub: 'row r turns right r places', lines: A.rows(R.shift).map((t, j) => ({ text: `row ${j}: ${t}`, cls: j === pick % 4 ? 'hot' : 'math' })), panelTitle: 'the rows after the shift', round: -1 }), say: `Undo round ${r + 1}. InvShiftRows turns row k right by k places, putting every byte back in its column: ${U.hex(R.shift)}.`, facts: { r: r + 1, st: R.shift }, meta: { stage: 'ishift', r }, hl: { d: [1] } });
      const sv = R.shift[from], iv = A.invSboxDerive(sv);
      matched.add(m);
      F.add({ items: base({ a: R.shift, aTitle: 'after InvShiftRows', aCls: (i) => (i === from ? 'hot' : ''), b: R.sub, bTitle: 'after InvSubBytes', bCls: (i) => (i === from ? 'hot' : 'changed'), step: 'InvSubBytes', stepSub: 'each byte through S⁻¹', lines: [{ text: `S⁻¹(${h(sv)}) = ${h(R.sub[from])}` }, { text: `inverse affine map: ${h(sv)} → ${h(iv.pre)}` }, { text: `inverse in GF(2⁸): ${h(iv.pre)}⁻¹ = ${h(R.sub[from])}` }, { text: `matches the encryption after round ${m}`, cls: 'good' }], panelTitle: U.cell(from), round: m }), say: `InvSubBytes runs each byte through the inverse S-box: undo the affine map, then invert in GF(2⁸). In ${U.cell(from)}, S⁻¹(${h(sv)}) = ${h(R.sub[from])}. The state ${U.hex(R.sub)} is exactly the state after round ${m} of the encryption.`, facts: { r: r + 1, sv, pre: iv.pre, out: R.sub[from], st: R.sub, m, at: cf(from) }, meta: { stage: 'isub', r }, hl: { d: [2] } });
      F.add({ items: base({ a: R.sub, aTitle: 'after InvSubBytes', b: R.added, bTitle: 'after AddRoundKey', bCls: () => 'changed', step: 'AddRoundKey', stepSub: 'round key ' + r, key: R.key, keyTitle: 'round key ' + r, round: m }), say: `AddRoundKey XORs round key ${r}, ${U.hex(R.key)}, giving ${U.hex(R.added)}.${R.mix ? '' : ` That is the plaintext: round 0 was only a key addition.`}`, facts: { r, k: R.key, st: R.added }, meta: { stage: 'iark', r }, hl: { d: [3] } });
      if (R.mix) {
        const c = Math.floor(from / 4), col = R.added.slice(4 * c, 4 * c + 4), mc = A.invMixColumn(col), rr = from % 4, t = mc.trace[rr];
        F.add({ items: base({ a: R.added, aTitle: 'after AddRoundKey', aCls: (i) => (Math.floor(i / 4) === c ? 'act' : ''), b: R.mix, bTitle: 'after InvMixColumns', bCls: (i) => (i === from ? 'hot' : Math.floor(i / 4) === c ? 'changed' : ''), step: 'InvMixColumns', stepSub: 'rows 0e 0b 0d 09', lines: [{ text: `column ${c}: ${U.hex(col, ' ')} → ${U.hex(mc.out, ' ')}` }, { text: `row ${rr}: ${t.coef.map((x, j) => h(x) + '·' + h(col[j])).join(' ⊕ ')}` }, { text: `= ${t.terms.map(h).join(' ⊕ ')} = ${h(t.v)}`, cls: 'hot' }], panelTitle: 'column ' + c, round: m }), say: `InvMixColumns multiplies each column by the inverse matrix, whose rows are rotations of 0e 0b 0d 09. Column ${c}, ${U.hex(col, ' ')}, becomes ${U.hex(mc.out, ' ')}. The state is ${U.hex(R.mix)}.`, facts: { c, col, out: mc.out, st: R.mix, terms: t.terms, v: t.v }, meta: { stage: 'imix', r }, hl: { d: [4] } });
      }
    }
    F.add({ items: base({ a: P, aTitle: 'plaintext', aCls: () => 'good', round: -1, solo: true, lines: [{ text: U.hex(P.slice(0, 8), ' ') }, { text: U.hex(P.slice(8), ' ') }].concat(U.asText(P) ? [{ text: U.asText(P), cls: 'good' }] : []), panelTitle: 'the plaintext, read out column by column' }), say: U.asText(P) ? `The plaintext is back: ${U.hex(P)}, the text ${U.asText(P)}. Every inverse step met the encryption's states in reverse order.` : `The result is ${U.hex(P)}. With the right key this is the plaintext; with a wrong one it is 16 bytes of noise, and nothing in AES itself says which: that is what message authentication is for.`, facts: { P }, meta: { stage: 'out' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('The inverse cipher', ['state = ciphertext ⊕ round key Nr', 'InvShiftRows: row r turns right r places', 'InvSubBytes: s ← S⁻¹(s): inverse affine map, then inverse in GF(2⁸)', 'AddRoundKey: s ← s ⊕ round key r (Nr−1 down to 0)', 'InvMixColumns: rows 0e 0b 0d 09 (not after round key 0)']) };
  }
  S.topic({
    id: 'aes-decrypt', family: 'p05-cipher', order: 20, title: 'Decryption: the inverse steps',
    blurb: 'The inverse cipher runs the rounds backwards: InvShiftRows, InvSubBytes, AddRoundKey and InvMixColumns, with the round keys from last to first; it lands on every encryption state in reverse.',
    inputs: [{ id: 'ct', kind: 'text', label: 'Ciphertext (32 hex digits)', def: 'dd4d23f3bf51ab4561eae6a9f830b787', check: U.blockCheck('Ciphertext') }, keyIn, pickIn, detailIn],
    presets: [
      { label: 'Back to “Lanterns at dusk”', values: { ct: 'dd4d23f3bf51ab4561eae6a9f830b787', key: 'ochre-river-2026', pick: 5, detail: 'ends' } },
      { label: 'FIPS 197 C.1 (AES-128)', values: { ct: '69c4e0d86a7b0430d8cdb78070b4c55a', key: '000102030405060708090a0b0c0d0e0f', pick: 0, detail: 'ends' } },
      { label: 'AES-192, our own', values: { ct: '47997d94a784d65b9a7258b380ca2ee9', key: 'a quiet orchard of 24 by', pick: 7, detail: 'ends' } },
      { label: 'FIPS 197 C.3 (AES-256)', values: { ct: '8ea2b7ca516745bfeafc49904b496089', key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', pick: 12, detail: 'ends' } },
      { label: 'Wrong key: garbage out', values: { ct: 'dd4d23f3bf51ab4561eae6a9f830b787', key: 'ochre-river-2027', pick: 5, detail: 'ends' } },
    ],
    run: decrypt,
    predict: [{ at: (f, i, fr) => i + 1 < fr.length && fr[i + 1].meta && fr[i + 1].meta.stage === 'isub', once: true, pick: 'option', options: (fr, i, inp) => { const N = U.key(inp.key).length / 4 + 6; return ['after round ' + (N - 2), 'after round ' + (N - 1), 'after round ' + N, 'none of them']; }, ask: 'InvSubBytes is next. Which state of the encryption will the decryption then hold?', answer: (fr, i, inp) => 'after round ' + (U.key(inp.key).length / 4 + 5), explain: 'InvShiftRows and InvSubBytes undo the last round\'s ShiftRows and SubBytes (the key was already removed, and the last round has no MixColumns), so the state is the one after the round before the last.' }],
    quiz: [
      { q: 'Which round key does decryption use first?', options: ['Round key 0', 'Round key 1', 'The last round key', 'The original key'], answer: 2, why: 'The rounds are undone from last to first, so the last key added is removed first.' },
      { q: 'What is the first row of the InvMixColumns matrix?', options: ['02 03 01 01', '0e 0b 0d 09', '01 01 01 01', '09 0d 0b 0e'], answer: 1, why: 'It is the inverse of the MixColumns matrix over GF(2⁸); its rows are rotations of 0e 0b 0d 09.' },
      { q: 'Why is decryption a little slower in byte-oriented software?', options: ['It has more rounds', 'InvMixColumns multiplies by larger constants', 'The inverse S-box is bigger', 'The key schedule runs twice'], answer: 1, why: '02 and 03 are a shift and an XOR; 0e, 0b, 0d and 09 need several.' },
      { q: 'InvSubBytes undoes the affine map and the field inversion in which order?', options: ['Inversion first, then the affine map', 'The affine map first, then the inversion', 'Both at once', 'Only the inversion'], answer: 1, why: 'S = affine ∘ inverse, so S⁻¹ = inverse ∘ affine⁻¹: undo the last step first.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
