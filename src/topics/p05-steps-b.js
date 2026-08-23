// Part 5, the linear steps of a round: ShiftRows turning each row of the state, MixColumns as a matrix times each
// column over GF(2⁸) with xtime written out bit by bit, and AddRoundKey, one XOR of the state with a round key.
(function (S) {
  'use strict';
  const U = S.P5, G = () => S.gf256, A = () => S.AES;
  const blockInputs = (extra) => [
    { id: 'pt', kind: 'text', label: 'Plaintext (16 characters or 32 hex digits)', def: 'Lanterns at dusk', check: U.blockCheck('Plaintext') },
    { id: 'key', kind: 'text', label: 'Key (16, 24 or 32 characters, or hex)', def: 'ochre-river-2026', check: U.keyCheck('Key') },
  ].concat(extra || []);
  const roundsOf = (inp) => A().encrypt(U.block(inp.pt), U.key(inp.key)).rounds;

  // ---- ShiftRows ---------------------------------------------------------------------------------------------
  function shiftRows(inp) {
    const rounds = roundsOf(inp), Nr = rounds.length - 1, rd = Math.min(inp.round, Nr), inv = inp.dir === 'inv';
    const st = inv ? rounds[rd].shift : rounds[rd].sub, out = inv ? A().invShiftRows(st) : A().shiftRows(st);
    const F = new S.Frames();
    const CW = 66, CH = 52, GP = 6, AX = 50, BX = 420, Y = 84, pitch = CW + GP, rowH = CH + GP;
    const colCls = (i) => 'col' + Math.floor(i / 4);
    const before = (ring) => U.grid('sr0', AX, Y, st, { cw: CW, ch: CH, gap: GP, size: 19, title: inv ? `after ShiftRows, round ${rd}` : `after SubBytes, round ${rd}`, cls: (i) => colCls(i) + (ring && ring.includes(i) ? ' ring' : '') }).items;
    // the moving grid: each cell keeps the key of the byte it holds, so a shift glides
    const after = (k, ring) => {
      const items = [U.t('sr1:t', BX, Y - 12, k >= 3 ? (inv ? 'after InvShiftRows' : 'after ShiftRows') : 'turning the rows', 'title')];
      for (let i = 0; i < 16; i++) {
        const r = i % 4, c = Math.floor(i / 4), sh = r <= k ? r : 0, nc = inv ? (c + sh) % 4 : (c - sh + 4) % 4;
        items.push({ key: 'sr1:' + i, kind: 'cell', x: BX + nc * pitch, y: Y + r * rowH, w: CW, h: CH, rx: 5, text: U.h2(st[i]), size: 19, cls: 'hex ' + colCls(i) + (r === k && k > 0 ? ' act' : '') + (ring && ring.includes(r + 4 * nc) ? ' ring' : '') });
      }
      return items;
    };
    const NX = BX + 4 * pitch + 14;
    const notes = (k) => [0, 1, 2, 3].map((r) => U.t('srn' + r, NX, Y + r * rowH + CH / 2 + 5, r ? `${r} ${inv ? '→' : '←'}` : 'stays', r === k ? 'act' : r < k ? 'strong' : 'tick', 'start', 15));
    const rowsTxt = (s) => A().rows(s);
    const bottom = (k) => {
      const items = U.panel('sr:p', 40, 340, 800, 270, inv ? 'InvShiftRows: row r turns r places right' : 'ShiftRows: row r turns r places left');
      for (let r = 0; r < 4; r++) {
        const y = 400 + r * 46, done = r <= k;
        items.push(U.t('sr:pr' + r, 60, y, 'row ' + r, r === k ? 'act' : 'strong', 'start', 15));
        items.push(U.t('sr:pa' + r, 140, y, rowsTxt(st)[r], 'math', 'start', 16));
        items.push(U.t('sr:pb' + r, 360, y, done ? (inv ? '→ ' : '← ') + r : '', 'tick', 'start', 15));
        items.push(U.t('sr:pc' + r, 430, y, done ? rowsTxt(out)[r] : '', 'math ' + (r === k ? 'hot' : ''), 'start', 16));
      }
      return items;
    };
    const R = rowsTxt(st), O = rowsTxt(out);
    F.add({ items: [...before(), ...after(0), ...notes(0), ...bottom(0)], say: `The state ${inv ? 'after ShiftRows' : 'after SubBytes'} in round ${rd}, coloured by the column each byte is in now. Row 0 stays where it is: ${R[0]}.`, facts: { rd, row0: R[0] }, meta: { stage: 'start' } });
    for (let k = 1; k < 4; k++) F.add({ items: [...before(), ...after(k), ...notes(k), ...bottom(k)], hl: { d: [k] }, say: `Row ${k} turns ${k} place${k > 1 ? 's' : ''} to the ${inv ? 'right' : 'left'}${k === 3 ? `, the same as one place to the ${inv ? 'left' : 'right'}` : ''}: ${R[k]} becomes ${O[k]}.`, facts: { k, from: R[k], to: O[k] }, meta: { stage: 'row', k } });
    const diag = inv ? [0, 13, 10, 7] : [0, 5, 10, 15];
    F.add({ items: [...before(diag), ...after(3, [0, 1, 2, 3]), ...notes(4), ...bottom(4)], hl: { d: [4] }, say: `Column 0 now holds ${U.hex(out.slice(0, 4), ' ')}: one byte from each of the four input columns, taken along a ${inv ? 'diagonal running the other way' : 'diagonal'}. Every new column has all four colours, so MixColumns mixes bytes that came from four different columns.`, facts: { col0: out.slice(0, 4) }, meta: { stage: 'diag' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def(inv ? 'InvShiftRows' : 'ShiftRows', [inv ? 's′[r][c] = s[r][(c − r) mod 4]' : 's′[r][c] = s[r][(c + r) mod 4]', 'row 1: one place', 'row 2: two places', 'row 3: three places (one the other way)', 'after it each column holds one byte of every old column']) };
  }
  S.topic({
    id: 'aes-shiftrows', family: 'p05-steps', order: 30, title: 'ShiftRows: row r turns by r places',
    blurb: 'Each row of the state is rotated left by its row number. Colour each byte by the column it came from: afterwards every column holds all four colours.',
    inputs: blockInputs([
      { id: 'round', kind: 'number', label: 'Round', def: 1, min: 1, max: 14 },
      { id: 'dir', kind: 'choice', label: 'Direction', def: 'enc', options: [{ value: 'enc', label: 'ShiftRows (encryption)' }, { value: 'inv', label: 'InvShiftRows (decryption)' }] },
    ]),
    presets: [
      { label: 'Round 1 of the lantern text', values: { pt: 'Lanterns at dusk', key: 'ochre-river-2026', round: 1, dir: 'enc' } },
      { label: 'FIPS 197 example, round 1', values: { pt: '00112233445566778899aabbccddeeff', key: '000102030405060708090a0b0c0d0e0f', round: 1, dir: 'enc' } },
      { label: 'The last round, round 10', values: { pt: 'Kelp beds sway 3', key: 'ochre-river-2026', round: 10, dir: 'enc' } },
      { label: 'InvShiftRows turns the other way', values: { pt: 'Lanterns at dusk', key: 'ochre-river-2026', round: 1, dir: 'inv' } },
    ],
    run: shiftRows,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'row' && f.meta.k === 1, pick: 'option', options: (fr, i) => [...new Set(fr[i + 1].facts.from.split(' '))], ask: (fr, i, inp) => `Row 2 is next. Which byte will be at its left end, in column 0, after ${inp.dir === 'inv' ? 'InvShiftRows' : 'ShiftRows'}?`, answer: (fr, i) => fr[i + 1].facts.to.split(' ')[0], explain: (fr, i, inp) => `Turning row 2 two places either way brings the byte from column 2 to column 0: ${fr[i + 1].facts.to.split(' ')[0]}.` }],
    quiz: [
      { q: 'Which row does ShiftRows leave alone?', options: ['Row 0', 'Row 1', 'Row 3', 'None'], answer: 0, why: 'Row r turns r places, so row 0 does not move.' },
      { q: 'Turning row 3 three places left is the same as…', options: ['three places right', 'one place right', 'no change', 'swapping it with row 1'], answer: 1, why: 'A row has four places, so three left equals one right.' },
      { q: 'Why is ShiftRows needed when MixColumns already mixes?', options: ['It adds key material', 'MixColumns only mixes within a column; ShiftRows moves bytes between columns', 'It makes SubBytes invertible', 'It is not needed'], answer: 1, why: 'Without it the four columns would be four independent 32-bit ciphers.' },
      { q: 'After ShiftRows, the bytes of new column 0 came from…', options: ['old column 0 only', 'one byte of each old column', 'two old columns', 'the key'], answer: 1, why: 'Column 0 is taken along a diagonal: rows 0 to 3 from columns 0 to 3.' },
    ],
  });

  // ---- MixColumns --------------------------------------------------------------------------------------------
  function mixColumns(inp) {
    const col = Array.from(S.bytes.fromHex(inp.col)), inv = inp.dir === 'inv', M = inv ? A().INV_MIX : A().MIX;
    const mc = inv ? A().invMixColumn(col) : A().mixColumn(col), out = mc.out, g = G();
    const F = new S.Frames();
    const MX = 40, MY = 70, CW = 52, CH = 42, GP = 5, pitch = CW + GP, VX = MX + 4 * pitch + 36, RX = VX + CW + 44;
    const mat = (row, filled) => {
      const items = [U.t('mc:mt', MX, MY - 14, inv ? 'inverse matrix' : 'matrix', 'title'), U.t('mc:vt', VX, MY - 14, 'column', 'title'), U.t('mc:rt', RX, MY - 14, 'result', 'title')];
      for (let r = 0; r < 4; r++) for (let k = 0; k < 4; k++) items.push({ key: `mc:m${r}${k}`, kind: 'cell', x: MX + k * pitch, y: MY + r * (CH + GP), w: CW, h: CH, rx: 4, text: U.h2(M[r][k]), size: 17, cls: 'hex ' + (r === row ? 'act' : 'soft') });
      for (let r = 0; r < 4; r++) items.push({ key: 'mc:v' + r, kind: 'cell', x: VX, y: MY + r * (CH + GP), w: CW, h: CH, rx: 4, text: U.h2(col[r]), size: 17, cls: 'hex ' + (row >= 0 ? 'act' : '') });
      for (let r = 0; r < 4; r++) items.push({ key: 'mc:r' + r, kind: 'cell', x: RX, y: MY + r * (CH + GP), w: CW, h: CH, rx: 4, text: r < filled ? U.h2(out[r]) : '', size: 17, cls: 'hex ' + (r === row ? 'hot' : r < filled ? '' : 'soft') });
      const midY = MY + 2 * (CH + GP) - GP / 2;
      items.push(U.t('mc:dot', VX - 18, midY + 7, '·', 'strong', 'middle', 26), U.t('mc:eq', RX - 22, midY + 7, '=', 'strong', 'middle', 22));
      return items;
    };
    // one product as text: how 02, 03 (or 09, 0b, 0d, 0e) times a byte is made from xtime
    const chain = (b) => { const c = [b]; for (let k = 1; k < 4; k++) c.push(g.xtime(c[k - 1])); return c; };
    const prod = (m, b) => {
      const c = chain(b), p = g.fastMul(m, b);
      if (m === 1) return `01·${U.h2(b)} = ${U.h2(b)}`;
      if (m === 2) return `02·${U.h2(b)} = xtime(${U.h2(b)}) = ${U.h2(p)}`;
      if (m === 3) return `03·${U.h2(b)} = ${U.h2(c[1])} ⊕ ${U.h2(b)} = ${U.h2(p)}`;
      const parts = [3, 2, 1, 0].filter((k) => (m >> k) & 1);
      return `${U.h2(m)}·${U.h2(b)} = ${parts.map((k) => U.h2(c[k])).join(' ⊕ ')} = ${U.h2(p)}`;
    };
    const WX = 560;
    const work = (r) => {
      const t = mc.trace[r], items = U.panel('mc:w', WX - 16, 40, 316, 212, 'row ' + r);
      M[r].forEach((m, k) => items.push(U.t('mc:wp' + k, WX, 92 + k * 30, prod(m, col[k]), 'math', 'start', 14)));
      items.push(U.t('mc:ws', WX, 92 + 4 * 30 + 8, `sum: ${t.terms.map(U.h2).join(' ⊕ ')} = ${U.h2(t.v)}`, 'math hot', 'start', 14));
      return items;
    };
    // xtime drawn in bits: b, shifted left (the top bit falls off), ⊕ 1b when it did
    const bitRow = (key, x, y, v, cls, label, lcls) => [U.t(key + ':l', x - 10, y + 19, label, lcls || 'tick', 'end', 14), ...U.cells(key, x, y, U.bin8(v).split('').map(Number), { cw: 26, ch: 28, gap: 2, size: 14, text: (b) => String(b), cls: (i, b) => 'bit ' + (b ? 'one ' : '') + (cls || '') })];
    const xtimeBox = (key, x, b, title, plus) => {
      const items = U.panel(key, x - 110, 286, 410, 330, title), nb = g.xtime(b), top = (b >> 7) & 1;
      let y = 326;
      items.push(...bitRow(key + 'a', x, y, b, '', U.h2(b)));
      y += 40;
      items.push(...bitRow(key + 'b', x, y, (b << 1) & 255, 'act', 'shift ←', 'act'));
      items.push({ key: key + 'of', kind: 'cell', x: x - 30 - 70, y, w: 26, h: 28, rx: 2, text: String(top), size: 14, cls: 'bit ' + (top ? 'one hot' : 'muted') });
      items.push(U.t(key + 'ofl', x - 87, y - 6, 'out', 'tick', 'middle', 13));
      y += 40;
      items.push(...bitRow(key + 'c', x, y, top ? 0x1b : 0, top ? 'key' : 'muted', top ? '⊕ 1b' : '⊕ 00', top ? 'key' : 'tick'));
      y += 40;
      items.push(...bitRow(key + 'd', x, y, nb, 'hot', '= ' + U.h2(nb), 'hot'));
      if (plus) { y += 40; items.push(...bitRow(key + 'e', x, y, b, 'src', '⊕ ' + U.h2(b), 'src')); y += 40; items.push(...bitRow(key + 'f', x, y, nb ^ b, 'hot', '= ' + U.h2(nb ^ b), 'hot')); }
      return items;
    };
    const xBoxes = (r) => {
      if (inv) {
        // the chain b, 2b, 4b, 8b of every byte of the column: each product picks some of them
        const items = U.panel('mc:ch', 40, 286, 800, 330, 'xtime chains: b, 02·b, 04·b, 08·b'), hd = ['b', '02·b', '04·b', '08·b'];
        hd.forEach((h, k) => items.push(U.t('mc:chh' + k, 200 + k * 120 + 40, 336, h, 'strong', 'middle', 14)));
        col.forEach((b, j) => { const c = chain(b); items.push(U.t('mc:chr' + j, 170, 376 + j * 44, 'byte ' + j, 'tick', 'end', 14)); c.forEach((v, k) => items.push({ key: `mc:c${j}${k}`, kind: 'cell', x: 200 + k * 120, y: 356 + j * 44, w: 80, h: 32, rx: 4, text: U.h2(v), size: 15, cls: 'hex ' + (r >= 0 && ((M[r][j] >> k) & 1) ? 'act' : '') })); });
        items.push(U.t('mc:chn', 700, 380, '0e = 08 ⊕ 04 ⊕ 02', 'math', 'end', 13), U.t('mc:chn2', 700, 404, '0b = 08 ⊕ 02 ⊕ 01', 'math', 'end', 13), U.t('mc:chn3', 700, 428, '0d = 08 ⊕ 04 ⊕ 01', 'math', 'end', 13), U.t('mc:chn4', 700, 452, '09 = 08 ⊕ 01', 'math', 'end', 13));
        items.forEach((it) => { if (/^mc:chn/.test(it.key)) it.x = 820; });
        return items;
      }
      const k2 = M[r].indexOf(2), k3 = M[r].indexOf(3);
      return [...xtimeBox('x2', 150, col[k2], `02·${U.h2(col[k2])}: xtime`), ...xtimeBox('x3', 570, col[k3], `03·${U.h2(col[k3])}: xtime, then ⊕ itself`, true)];
    };
    F.add({ items: [...mat(-1, 0)], say: `MixColumns treats a column of four bytes, here ${U.hex(col, ' ')}, as a vector and multiplies it by a fixed ${inv ? 'inverse ' : ''}matrix. Every product is in GF(2⁸), and every sum is an XOR.`, facts: { col }, meta: { stage: 'start' } });
    for (let r = 0; r < 4; r++) {
      const t = mc.trace[r];
      F.add({ items: [...mat(r, r + 1), ...work(r), ...xBoxes(r)], hl: { d: [r + 1] }, say: `Row ${r}: ${M[r].map((m, k) => `${U.h2(m)}·${U.h2(col[k])}`).join(' ⊕ ')} = ${t.terms.map(U.h2).join(' ⊕ ')} = ${U.h2(t.v)}.${inv ? '' : r === 0 ? ` Multiplying by 02 is xtime: shift the bits left, and if a 1 fell off the top, XOR in 1b. 03·b is 02·b ⊕ b.` : ''}`, facts: { r, M: M[r], col, terms: t.terms, v: t.v, poly: 0x1b }, meta: { stage: 'row', r } });
    }
    // diffusion: change one input byte and all four outputs change
    const col2 = col.slice(); col2[0] ^= 1;
    const out2 = (inv ? A().invMixColumn(col2) : A().mixColumn(col2)).out, back = (inv ? A().mixColumn(out) : A().invMixColumn(out)).out;
    const diffN = out.filter((v, i) => v !== out2[i]).length;
    const diffPanel = [...U.panel('mc:d', 40, 286, 800, 330, 'one byte changed'), U.t('mc:d1', 70, 340, 'column', 'tick', 'start', 14), ...U.cells('mc:da', 200, 320, col, { cw: 60, ch: 34, gap: 6, size: 16 }), U.t('mc:d2', 70, 390, 'byte 0 ⊕ 01', 'tick', 'start', 14), ...U.cells('mc:db', 200, 370, col2, { cw: 60, ch: 34, gap: 6, size: 16, cls: (i) => (i === 0 ? 'act' : '') }),
      U.t('mc:d3', 520, 340, 'result', 'tick', 'start', 14), ...U.cells('mc:dc', 600, 320, out, { cw: 52, ch: 34, gap: 4, size: 16 }), U.t('mc:d4', 520, 390, 'result', 'tick', 'start', 14), ...U.cells('mc:dd', 600, 370, out2, { cw: 52, ch: 34, gap: 4, size: 16, cls: (i) => (out2[i] !== out[i] ? 'hot' : '') }),
      U.t('mc:d5', 70, 470, `${diffN} of the 4 output bytes change.`, 'strong', 'start', 15), U.t('mc:d6', 70, 506, `${inv ? 'MixColumns' : 'InvMixColumns'} of the result gives ${U.hex(back, ' ')} back.`, 'math', 'start', 15)];
    F.add({ items: [...mat(-1, 4), ...diffPanel], hl: { d: [5] }, say: `The column becomes ${U.hex(out, ' ')}. Change one input byte (${U.h2(col[0])} to ${U.h2(col2[0])}) and ${diffN} of the four output bytes change: that is the diffusion this step adds. ${inv ? 'MixColumns' : 'InvMixColumns'} of the result gives ${U.hex(back, ' ')}, the column we started from.`, facts: { out, a: col[0], b: col2[0], diffN, back }, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def(inv ? 'InvMixColumns' : 'MixColumns', inv ? ['[0e 0b 0d 09] [b₀]', '[09 0e 0b 0d] [b₁]', '[0d 09 0e 0b] [b₂]', '[0b 0d 09 0e] [b₃]', 'each product a sum of b, 02·b, 04·b, 08·b; sums are XOR', 'it undoes MixColumns: the two matrices multiply to the identity'] : ['[02 03 01 01] [b₀]', '[01 02 03 01] [b₁]', '[01 01 02 03] [b₂]', '[03 01 01 02] [b₃]', 'xtime(b) = (b ≪ 1) ⊕ (1b if b ≥ 80);  03·b = xtime(b) ⊕ b', 'any change of k input bytes changes at least 5 − k outputs']) };
  }
  S.topic({
    id: 'aes-mixcolumns', family: 'p05-steps', order: 40, title: 'MixColumns: a matrix over GF(2⁸)',
    blurb: 'Each column of the state is multiplied by a fixed matrix of small field elements. Multiplying by 02 is a shift and a conditional XOR with 1b; adding is XOR.',
    inputs: [
      { id: 'col', kind: 'hex', label: 'Column (4 bytes, top first)', def: 'c9e2187a', bytes: 4 },
      { id: 'dir', kind: 'choice', label: 'Direction', def: 'mix', options: [{ value: 'mix', label: 'MixColumns' }, { value: 'inv', label: 'InvMixColumns' }] },
    ],
    presets: [
      { label: 'A column with high bits (1b comes in)', values: { col: 'c9e2187a', dir: 'mix' } },
      { label: 'FIPS 197 Appendix B, a column of round 1', values: { col: 'd4bf5d30', dir: 'mix' } },
      { label: 'Column 1 of the lantern text, round 1', values: { col: '63f2836f', dir: 'mix' } },
      { label: '01 01 01 01 stays put', values: { col: '01010101', dir: 'mix' } },
      { label: 'One byte set: 80 00 00 00', values: { col: '80000000', dir: 'mix' } },
      { label: 'InvMixColumns, coefficients 0e 0b 0d 09', values: { col: '046681e5', dir: 'inv' } },
    ],
    run: mixColumns,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'start', pick: 'option', options: (fr, i, inp) => { const b = parseInt(inp.col.slice(0, 2), 16), x = S.gf256.xtime(b); return [...new Set([U.h2(x), U.h2((b << 1) & 255), U.h2(b ^ 0x1b), U.h2(b >> 1)])].sort(); }, ask: (fr, i, inp) => `What is 02·${inp.col.slice(0, 2)} (xtime of ${inp.col.slice(0, 2)})?`, answer: (fr, i, inp) => U.h2(S.gf256.xtime(parseInt(inp.col.slice(0, 2), 16))), explain: (fr, i, inp) => { const b = parseInt(inp.col.slice(0, 2), 16); return `Shift ${inp.col.slice(0, 2)} one place left: ${U.h2((b << 1) & 255)}. ${b & 0x80 ? 'A 1 fell off the top, so XOR in 1b' : 'Nothing fell off the top, so that is the answer'}: ${U.h2(S.gf256.xtime(b))}.`; } }],
    quiz: [
      { q: 'What is xtime(80)?', options: ['00', '1b', '01', '80'], answer: 1, why: 'Shifting 80 left gives 00 with a 1 falling off, so 1b is XORed in.' },
      { q: 'How is 03·b computed?', options: ['b + b + b with carries', 'xtime(b) ⊕ b', 'b ≪ 2', 'b³'], answer: 1, why: '03 = 02 ⊕ 01, and multiplication distributes over XOR.' },
      { q: 'If one byte of a column changes, how many output bytes change?', options: ['1', '2', 'all 4', 'it depends on the key'], answer: 2, why: 'The matrix is MDS: k changed inputs change at least 5 − k outputs, so one changes all four.' },
      { q: 'Which round has no MixColumns?', options: ['Round 0 and the last round', 'Only round 1', 'Every even round', 'None'], answer: 0, why: 'Round 0 is AddRoundKey alone, and the last round leaves MixColumns out.' },
    ],
  });

  // ---- AddRoundKey -------------------------------------------------------------------------------------------
  function addRoundKey(inp) {
    const rounds = roundsOf(inp), Nr = rounds.length - 1, rd = Math.min(inp.round, Nr), R = rounds[rd];
    const st = rd === 0 ? R.start : R.mix || R.shift, k = R.key, out = R.end, pick = inp.pick;
    const F = new S.Frames();
    const CW = 54, CH = 42, GP = 4, Y = 64, X1 = 30, X2 = 316, X3 = 602, W = 4 * (CW + GP) - GP;
    const grid = (pfx, x, vals, title, cls, tcls) => U.grid(pfx, x, Y, vals, { cw: CW, ch: CH, gap: GP, size: 17, title, titleCls: tcls, cls }).items;
    const before = rd === 0 ? 'the plaintext' : rd === Nr ? 'after ShiftRows' : 'after MixColumns';
    const ops = [U.t('ak:x', X1 + W + 27, Y + 2 * (CH + GP) + 4, '⊕', 'strong', 'middle', 26), U.t('ak:e', X2 + W + 27, Y + 2 * (CH + GP) + 4, '=', 'strong', 'middle', 26)];
    const res = (cols, lit) => grid('ak3', X3, out.map((v, i) => (Math.floor(i / 4) < cols ? v : null)), 'after AddRoundKey', (i) => (Math.floor(i / 4) < cols ? (Math.floor(i / 4) === lit ? 'hot' : i === pick && lit === undefined ? 'hot' : '') : 'soft'));
    const colLit = (c) => (i) => (Math.floor(i / 4) === c ? 'act' : '');
    const keyCls = (c) => (i) => 'key' + (Math.floor(i / 4) === c || (c === -2 && i === pick) ? ' keyhot' : '');
    const bitsPanel = (undo) => {
      const items = U.panel('ak:b', 30, 290, 820, 320, `byte ${pick}, ${U.cell(pick)}, bit by bit`);
      const row = (key, y, v, cls, label, lcls) => [U.t(key + ':l', 300, y + 22, label, lcls || 'strong', 'end', 15), ...U.cells(key, 320, y, U.bin8(v).split('').map(Number), { cw: 40, ch: 34, gap: 4, size: 16, text: (b) => String(b), cls: (i, b) => 'bit ' + (b ? 'one ' : '') + cls })];
      items.push(...row('ak:b1', 336, undo ? out[pick] : st[pick], undo ? 'hot' : '', (undo ? 'result ' : 'state ') + U.h2(undo ? out[pick] : st[pick])));
      items.push(...row('ak:b2', 384, k[pick], 'key', '⊕ key ' + U.h2(k[pick]), 'key'));
      items.push({ key: 'ak:rule', kind: 'line', x1: 320, y1: 428, x2: 320 + 8 * 44 - 4, y2: 428, cls: 'rule' });
      items.push(...row('ak:b3', 438, undo ? st[pick] : out[pick], undo ? '' : 'hot', '= ' + U.h2(undo ? st[pick] : out[pick]), undo ? 'strong' : 'hot'));
      const flips = S.bytes.popcount(st[pick] ^ out[pick]);
      items.push(U.t('ak:bn', 320, 512, undo ? 'XOR with the same key again gives the state back.' : `A 1 in the key flips that bit: ${flips} of the 8 bits flip.`, 'tick', 'start', 15));
      return items;
    };
    F.add({ items: [...grid('ak1', X1, st, `state, ${before}`), ...ops, ...grid('ak2', X2, k, `round key ${rd}`, keyCls(-1), 'key'), ...res(0)], say: `Round ${rd}: the state ${before} and round key ${rd}, ${U.hex(k)}, taken from words ${4 * rd} to ${4 * rd + 3} of the key schedule.`, facts: { rd, k, w0: 4 * rd, w3: 4 * rd + 3 }, meta: { stage: 'start' } });
    for (let c = 0; c < 4; c++) F.add({ items: [...grid('ak1', X1, st, `state, ${before}`, colLit(c)), ...ops, ...grid('ak2', X2, k, `round key ${rd}`, keyCls(c), 'key'), ...res(c + 1, c)], hl: { d: [0] }, say: `Column ${c}: ${U.hex(st.slice(4 * c, 4 * c + 4))} ⊕ ${U.hex(k.slice(4 * c, 4 * c + 4))} = ${U.hex(out.slice(4 * c, 4 * c + 4))}, byte by byte.`, facts: { c, s: st.slice(4 * c, 4 * c + 4), k: k.slice(4 * c, 4 * c + 4), o: out.slice(4 * c, 4 * c + 4) }, meta: { stage: 'col', c } });
    F.add({ items: [...grid('ak1', X1, st, `state, ${before}`, (i) => (i === pick ? 'act' : '')), ...ops, ...grid('ak2', X2, k, `round key ${rd}`, keyCls(-2), 'key'), ...res(4), ...bitsPanel(false)], hl: { d: [1] }, say: `Inside one byte, ${U.cell(pick)}: ${U.h2(st[pick])} ⊕ ${U.h2(k[pick])} = ${U.h2(out[pick])}. Each bit of the key flips the matching bit of the state or leaves it alone.`, facts: { a: st[pick], b: k[pick], o: out[pick] }, meta: { stage: 'bits' } });
    F.add({ items: [...grid('ak1', X1, st, `state, ${before}`, (i) => (i === pick ? 'act' : '')), ...ops, ...grid('ak2', X2, k, `round key ${rd}`, keyCls(-2), 'key'), ...res(4), ...bitsPanel(true)], hl: { d: [2] }, say: `XOR is its own inverse: ${U.h2(out[pick])} ⊕ ${U.h2(k[pick])} = ${U.h2(st[pick])}. Decryption undoes AddRoundKey by adding the same round key again. It is the only step that uses the key; without it the other steps would be a fixed, public permutation.`, facts: { a: out[pick], b: k[pick], o: st[pick] }, meta: { stage: 'undo' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('AddRoundKey', ['s′[r][c] = s[r][c] ⊕ k[r][c]  (16 XORs)', 'round key r = words 4r … 4r+3 of the schedule', 'its own inverse: (s ⊕ k) ⊕ k = s']) };
  }
  S.topic({
    id: 'aes-addroundkey', family: 'p05-steps', order: 50, title: 'AddRoundKey: XOR with a round key',
    blurb: 'The only step that touches the key: the state and a 16-byte round key are XORed byte by byte. Doing it again undoes it.',
    inputs: blockInputs([
      { id: 'round', kind: 'number', label: 'Round (0 to the last)', def: 1, min: 0, max: 14 },
      { id: 'pick', kind: 'number', label: 'Byte to look inside (0 to 15)', def: 5, min: 0, max: 15 },
    ]),
    presets: [
      { label: 'Round 1 of the lantern text', values: { pt: 'Lanterns at dusk', key: 'ochre-river-2026', round: 1, pick: 5 } },
      { label: 'Round 0: plaintext ⊕ key', values: { pt: 'Lanterns at dusk', key: 'ochre-river-2026', round: 0, pick: 0 } },
      { label: 'FIPS 197 example, round 10', values: { pt: '00112233445566778899aabbccddeeff', key: '000102030405060708090a0b0c0d0e0f', round: 10, pick: 12 } },
      { label: 'AES-256, round 14', values: { pt: 'Moth on the pane', key: 'thirty-two bytes of copper wire!', round: 14, pick: 9 } },
    ],
    run: addRoundKey,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'col' && f.meta.c === 3, pick: 'option', options: (fr, i) => { const { a, b } = fr[i + 1].facts; return [...new Set([a ^ b, a & b, a | b, (a + b) & 255].map(U.h2))].sort(); }, ask: (fr, i) => `What is ${U.h2(fr[i + 1].facts.a)} ⊕ ${U.h2(fr[i + 1].facts.b)}?`, answer: (fr, i) => U.h2(fr[i + 1].facts.o), explain: (fr, i) => `XOR bit by bit: ${U.bin8(fr[i + 1].facts.a)} ⊕ ${U.bin8(fr[i + 1].facts.b)} = ${U.bin8(fr[i + 1].facts.o)}.` }],
    quiz: [
      { q: 'How does decryption undo AddRoundKey?', options: ['Subtract the key with borrows', 'XOR the same round key again', 'Use the inverse S-box on the key', 'It cannot'], answer: 1, why: 'x ⊕ k ⊕ k = x.' },
      { q: 'How many round keys does AES-256 use?', options: ['11', '13', '15', '16'], answer: 2, why: '14 rounds plus round 0.' },
      { q: 'Which words of the schedule make round key 3?', options: ['w3 … w6', 'w12 … w15', 'w9 … w12', 'w0 … w3'], answer: 1, why: 'Round key r is words 4r to 4r + 3.' },
      { q: 'Why must AddRoundKey come first, before round 1?', options: ['Otherwise the first SubBytes and ShiftRows could be undone by anyone, since they use no key', 'It is faster', 'To pad the block', 'It does not matter'], answer: 0, why: 'Steps without key material can be peeled off by an attacker; whitening the input with the key first prevents that.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
