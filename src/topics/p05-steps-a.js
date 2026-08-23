// Part 5, SubBytes: one byte of the state through the S-box, worked out as its inverse in GF(2⁸) and the affine map
// of its bits; and the whole S-box, all 256 entries derived the same way, with its inverse and its properties.
(function (S) {
  'use strict';
  const U = S.P5, G = () => S.gf256;
  const AFF = [0, 4, 5, 6, 7];

  /** the affine map drawn as a matrix of bits times the inverse's bits, ⊕ 63, = the output; lit: the row being read */
  function affine(x, y, v, o, lit, done) {
    const items = [], s = 28, mx = x + 52;
    items.push(U.t('sb:at', x, y - 34, 'affine map  b′ = M·b ⊕ 63   (bit 0 at the top)', 'title'));
    for (let r = 0; r < 8; r++) {
      items.push(U.t('sb:rl' + r, mx - 10, y + r * s + s * 0.68, 'bit ' + r, r === lit ? 'act' : 'tick', 'end', 13));
      for (let c = 0; c < 8; c++) {
        const one = AFF.includes((c - r + 8) % 8), on = lit === r && one;
        items.push({ key: `sb:m${r},${c}`, kind: 'cell', x: mx + c * s, y: y + r * s, w: s - 2, h: s - 2, rx: 2, text: one ? '1' : '0', size: 13, cls: 'bit ' + (one ? 'one ' : 'muted ') + (on ? 'act' : '') });
      }
    }
    const col = (k, cx, bits, cls, head, hcls) => {
      items.push(U.t('sb:h' + k, cx + (s - 2) / 2, y - 10, head, hcls || 'strong', 'middle', 14));
      for (let r = 0; r < 8; r++) items.push({ key: `sb:${k}${r}`, kind: 'cell', x: cx, y: y + r * s, w: s - 2, h: s - 2, rx: 2, text: String(bits[r]), size: 13, cls: 'bit ' + (bits[r] ? 'one ' : '') + (typeof cls === 'function' ? cls(r) : cls) });
    };
    const bitsOf = (b) => [0, 1, 2, 3, 4, 5, 6, 7].map((k) => (b >> k) & 1);
    const vx = mx + 8 * s + 22;
    const taps = lit === undefined ? [] : AFF.map((d) => (lit + d) % 8);
    col('v', vx, bitsOf(v), (r) => (taps.includes(r) ? 'src' : ''), U.h2(v), 'src');
    items.push(U.t('sb:x', vx + s + 12, y + 4 * s + 2, '⊕', 'strong', 'middle', 18));
    col('c', vx + s + 26, bitsOf(0x63), (r) => (r === lit ? 'key' : ''), '63', 'key');
    items.push(U.t('sb:e', vx + 2 * s + 38, y + 4 * s + 2, '=', 'strong', 'middle', 18));
    const outBits = bitsOf(o).map((b, r) => (done || (lit !== undefined && r <= lit) ? b : ''));
    col('o', vx + 2 * s + 52, outBits.map((b) => (b === '' ? '' : b)), (r) => (r === lit ? 'hot' : done || (lit !== undefined && r < lit) ? '' : 'soft'), done ? U.h2(o) : '?', 'hot');
    return { items, right: vx + 3 * s + 52 };
  }

  function subBytes(inp) {
    const P = U.block(inp.pt), K = U.key(inp.key, [16]), A = S.AES;
    const R1 = A.encrypt(P, K).rounds[1], st = R1.start, out = R1.sub, pick = inp.pick, b = st[pick], tr = G().subByteTrace(b), v = tr.inv, o = tr.out;
    const F = new S.Frames();
    const gA = (cls) => U.grid('sa', 30, 52, st, { cw: 50, ch: 38, size: 15, title: 'state entering round 1', cls }).items;
    const gB = (filled, cls) => U.grid('sb', 318, 52, out.map((x, i) => (filled(i) ? x : null)), { cw: 50, ch: 38, size: 15, title: 'after SubBytes', cls: (i) => (filled(i) ? cls(i) : 'soft') }).items;
    const arrow = [U.arrow('sb:arr', [[254, 132], [306, 132]], 'act'), U.t('sb:arl', 280, 120, 'S', 'act', 'middle', 15)];
    const lit = (i) => (i === pick ? 'act' : '');
    const PX = 560, PW = 300;
    const panel = (k) => {
      const items = U.panel('sb:p', PX, 30, PW, 186, 'one byte: ' + U.cell(pick));
      items.push(U.t('sb:p1', PX + 14, 70, `byte ${U.h2(b)} = ${U.bin8(b)}`, 'math', 'start', 14));
      items.push(U.t('sb:p2', PX + 14, 94, G().poly(b), 'math', 'start', 13));
      if (k >= 1) {
        items.push(U.t('sb:p3', PX + 14, 126, b ? `inverse ${U.h2(b)}⁻¹ = ${U.h2(v)}` : '00 has no inverse: use 00', 'math act', 'start', 14));
        if (b) items.push(U.t('sb:p4', PX + 14, 150, `check  ${U.h2(b)} · ${U.h2(v)} = ${U.h2(G().fastMul(b, v))}`, 'math', 'start', 14));
      }
      if (k >= 2) items.push(U.t('sb:p5', PX + 14, 190, `S(${U.h2(b)}) = ${U.h2(o)}`, 'math hot', 'start', 16));
      return items;
    };
    const AX = 40, AY = 318;
    const affPanel = () => U.panel('sb:ap', 30, 248, 830, 382, '');
    const explain = (r) => {
      if (r === undefined) return [];
      const bt = tr.trace[1].bits[r], ex = 560, items = [];
      items.push(U.t('sb:e0', ex, AY + 14, `bit ${r} of the output:`, 'strong', 'start', 14));
      items.push(U.t('sb:e1', ex, AY + 42, `b${r} ⊕ b${(r + 4) % 8} ⊕ b${(r + 5) % 8} ⊕ b${(r + 6) % 8} ⊕ b${(r + 7) % 8} ⊕ c${r}`, 'math', 'start', 14));
      items.push(U.t('sb:e2', ex, AY + 70, `= ${bt.src.join(' ⊕ ')} ⊕ ${bt.c} = ${bt.bit}`, 'math hot', 'start', 15));
      items.push(U.t('sb:e3', ex, AY + 112, 'Each row of M has five ones,', '', 'start', 14));
      items.push(U.t('sb:e4', ex, AY + 134, 'the same pattern turned one', '', 'start', 14));
      items.push(U.t('sb:e5', ex, AY + 156, 'place for every row.', '', 'start', 14));
      return items;
    };
    const base = (cA, nB, cB) => [...gA(cA), ...gB(nB, cB), ...arrow];
    const none = () => false;
    F.add({ items: [...base(() => '', none, () => '')], say: `The state entering round 1 is the plaintext XORed with the key. SubBytes replaces each of its 16 bytes by looking it up in one fixed table, the S-box.`, facts: { st }, meta: { stage: 'start' } });
    F.add({ items: [...base(lit, none, () => ''), ...panel(0)], hl: { d: [0] }, say: `Take the byte in ${U.cell(pick)}: ${U.h2(b)}, or ${U.bin8(b)} in bits. Read as a polynomial over GF(2), it is ${G().poly(b)}.`, facts: { pick, r: pick % 4, c: Math.floor(pick / 4), b, bits: U.bin8(b), poly: G().poly(b) }, meta: { stage: 'byte' } });
    F.add({ items: [...base(lit, none, () => ''), ...panel(1)], hl: { d: [1] }, say: b ? `First step: its inverse in GF(2⁸), the field of bytes modulo x⁸ + x⁴ + x³ + x + 1. The inverse of ${U.h2(b)} is ${U.h2(v)}, because ${U.h2(b)} · ${U.h2(v)} = 01.` : 'First step: the inverse in GF(2⁸). The byte 00 has none, so AES defines its inverse as 00.', facts: { b, v, prod: G().fastMul(b, v) }, meta: { stage: 'inv' } });
    const af = (lit2, done) => [affPanel(), ...affine(AX, AY, v, o, lit2, done).items, ...explain(lit2)];
    for (const r of [0, 1]) F.add({ items: [...base(lit, none, () => ''), ...panel(1), ...af(r)].flat(), hl: { d: [2] }, say: `Second step: an affine map of the bits of ${U.h2(v)}. Output bit ${r} is the XOR of bits ${U.list(AFF.map((d) => String((r + d) % 8)))} of ${U.h2(v)} and bit ${r} of the constant 63: ${tr.trace[1].bits[r].src.join(' ⊕ ')} ⊕ ${tr.trace[1].bits[r].c} = ${tr.trace[1].bits[r].bit}.`, facts: { v, r, taps: AFF.map((d) => (r + d) % 8), src: tr.trace[1].bits[r].src, c: tr.trace[1].bits[r].c, bit: tr.trace[1].bits[r].bit }, meta: { stage: 'bit', r } });
    F.add({ items: [...base(lit, (i) => i === pick, () => 'hot'), ...panel(2), ...af(undefined, true)].flat(), hl: { d: [2, 3] }, say: `The other six bits follow the same pattern, and the output bits read ${U.bin8(o)} (bit 7 first), so S(${U.h2(b)}) = ${U.h2(o)}. It takes its place in the new state.`, facts: { b, o, bits: U.bin8(o) }, meta: { stage: 'out' } });
    const changed = out.filter((x, i) => x !== st[i]).length;
    F.add({ items: [...base(() => '', () => true, (i) => (i === pick ? 'hot' : 'changed'))], hl: { d: [3] }, say: `Every byte goes through the same S-box, so equal bytes give equal results; ${changed} of the 16 bytes changed value here. The new first column is ${U.hex(out.slice(0, 4))}. SubBytes is the only step of AES that is not linear over GF(2).`, facts: { changed, col0: out.slice(0, 4) }, meta: { stage: 'all' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('SubBytes', ['b as a polynomial: b₇x⁷ + … + b₁x + b₀', 'step 1: b⁻¹ in GF(2⁸), m(x) = x⁸ + x⁴ + x³ + x + 1  (00 ↦ 00)', 'step 2: b′ᵢ = bᵢ ⊕ bᵢ₊₄ ⊕ bᵢ₊₅ ⊕ bᵢ₊₆ ⊕ bᵢ₊₇ ⊕ cᵢ,  c = 63', 'S(b) = affine(b⁻¹), applied to all 16 bytes']) };
  }
  S.topic({
    id: 'aes-subbytes', family: 'p05-steps', order: 10, title: 'SubBytes: one byte through the S-box',
    blurb: 'The S-box is not a random table. A byte is inverted in GF(2⁸), then its bits go through a fixed affine map; every byte of the state takes the same path.',
    inputs: [
      { id: 'pt', kind: 'text', label: 'Plaintext (16 characters or 32 hex digits)', def: 'Lanterns at dusk', check: U.blockCheck('Plaintext') },
      { id: 'key', kind: 'text', label: 'Key (16 characters or 32 hex digits)', def: 'ochre-river-2026', check: U.keyCheck('Key', [16]) },
      { id: 'pick', kind: 'number', label: 'Byte to follow (0 to 15)', def: 6, min: 0, max: 15 },
    ],
    presets: [
      { label: 'A byte of the lantern text', values: { pt: 'Lanterns at dusk', key: 'ochre-river-2026', pick: 6 } },
      { label: 'FIPS 197 example, byte 0', values: { pt: '00112233445566778899aabbccddeeff', key: '000102030405060708090a0b0c0d0e0f', pick: 0 } },
      { label: 'Plaintext equal to the key: the byte 00', values: { pt: 'salt and cedar 9', key: 'salt and cedar 9', pick: 11 } },
      { label: 'A byte with its top bit set', values: { pt: 'Moth on the pane', key: 'ochre-river-2026', pick: 3 } },
    ],
    run: subBytes,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'inv', pick: 'option', options: ['0', '1'], ask: 'Bit 0 of the output is the XOR of bits 0, 4, 5, 6 and 7 of the inverse and bit 0 of 63. Is it 0 or 1?', answer: (fr, i) => String(fr[i + 1].facts.bit), explain: (fr, i) => `The five bits are ${fr[i + 1].facts.src.join(', ')} and the constant's bit is ${fr[i + 1].facts.c}, so the XOR is ${fr[i + 1].facts.bit}.` }],
    quiz: [
      { q: 'What is S(00)?', options: ['00', '01', '63', '7c'], answer: 2, why: '00 is mapped to 00 by the inversion step, and the affine map of 00 is the constant 63.' },
      { q: 'Why does the S-box start with inversion in GF(2⁸)?', options: ['It is fast', 'It is far from linear, which defeats linear and differential cryptanalysis', 'It makes the S-box its own inverse', 'It depends on the key'], answer: 1, why: 'Inversion has the best known resistance to both attacks for an 8-bit map; the affine map then removes its simple algebraic shape and its fixed points.' },
      { q: 'Does the S-box depend on the key?', options: ['Yes, it changes every round', 'Yes, through the first round key', 'No, it is one fixed table', 'Only in AES-256'], answer: 2, why: 'All key material enters through AddRoundKey; the S-box is the same for every key.' },
      { q: 'How many bits of the inverse does each output bit of the affine map read?', options: ['1', '3', '5', '8'], answer: 2, why: 'Each row of the matrix has five ones: bits i, i+4, i+5, i+6 and i+7.' },
    ],
  });

  // ---- the whole S-box -----------------------------------------------------------------------------------------
  function sboxTable(inp) {
    const g = G(), inv = inp.table === 'inv', T = inv ? g.INV_SBOX : g.SBOX, f = parseInt(inp.focus, 16), fr = f >> 4, fc = f & 15;
    const F = new S.Frames();
    const X0 = 64, Y0 = 70, CW = 46, CH = 28;
    const head = [U.t('sx:t', 30, 30, inv ? 'the inverse S-box: S⁻¹(x) for x = row·16 + column' : 'the S-box: S(x) for x = row·16 + column', 'title')];
    for (let c = 0; c < 16; c++) head.push(U.t('sx:ch' + c, X0 + c * CW + CW / 2, Y0 - 9, c.toString(16), c === fc ? 'act' : 'tick', 'middle', 14));
    for (let r = 0; r < 16; r++) head.push(U.t('sx:rh' + r, X0 - 12, Y0 + r * CH + CH / 2 + 5, r.toString(16) + '·', r === fr ? 'act' : 'tick', 'end', 14));
    const table = (rows, focus) => {
      const items = [];
      for (let r = 0; r < 16; r++) for (let c = 0; c < 16; c++) {
        const x = 16 * r + c, on = r < rows;
        items.push({ key: 'sx:c' + x, kind: 'cell', x: X0 + c * CW, y: Y0 + r * CH, w: CW - 2, h: CH - 2, rx: 2, text: on ? U.h2(T[x]) : '', size: 13, cls: 'hex ' + (!on ? 'soft' : focus && x === f ? 'hot' : r === rows - 1 && !focus ? 'act' : '') });
      }
      return items;
    };
    const foot = (lines) => lines.map((l, i) => U.t('sx:f' + i, 30, 568 + i * 26, l[0], l[1] || '', 'start', l[2] || 15));
    F.add({ items: [...head, ...table(0)], say: inv ? 'The inverse S-box undoes SubBytes: S⁻¹(y) is the x with S(x) = y. Decryption needs it for InvSubBytes. It is filled row by row, x from 00 to ff.' : 'The S-box has 256 entries, one for every byte x. Each is worked out the same way: the inverse of x in GF(2⁸), then the affine map. It is filled row by row, x from 00 to ff.', facts: {}, meta: { stage: 'start' } });
    const showRows = [1, 2, 4, 8, 16];
    for (const n of showRows) {
      const r = n - 1, vals = Array.from(T.slice(16 * r, 16 * r + 16));
      F.add({ items: [...head, ...table(n), ...foot([[`row ${r.toString(16)}: x = ${U.h2(16 * r)} … ${U.h2(16 * r + 15)}`, 'strong'], [vals.map(U.h2).join(' '), 'math']])], say: n === 1 ? `Row 0 covers x = 00 to 0f: ${inv ? 'S⁻¹' : 'S'}(00) = ${U.h2(T[0])}, ${inv ? 'S⁻¹' : 'S'}(01) = ${U.h2(T[1])}, and so on to ${inv ? 'S⁻¹' : 'S'}(0f) = ${U.h2(T[15])}.` : `Rows up to ${r.toString(16)} filled: row ${r.toString(16)} holds ${vals.map(U.h2).join(' ')}.`, facts: { r, T0: T[0], T1: T[1], T15: T[15], vals, x0: 16 * r, x1: 16 * r + 15 }, meta: { stage: 'rows', n } });
    }
    // the focus entry, derived
    let lines, say, facts;
    if (!inv) {
      const tr = g.subByteTrace(f);
      lines = [[`S(${U.h2(f)}): inverse ${U.h2(tr.inv)}, then the affine map: ${U.bin8(tr.inv)} → ${U.bin8(tr.out)} = ${U.h2(tr.out)}`, 'hot']];
      say = `Look up ${U.h2(f)} at row ${fr.toString(16)}, column ${fc.toString(16)}: ${U.h2(T[f])}. ${f ? `It comes from the inverse ${U.h2(tr.inv)} (since ${U.h2(f)} · ${U.h2(tr.inv)} = 01)` : 'The byte 00 has no inverse, so the inversion gives 00'}, whose bits ${U.bin8(tr.inv)} the affine map turns into ${U.bin8(tr.out)}.`;
      facts = { f, fr, fc, out: tr.out, inv: tr.inv, ib: U.bin8(tr.inv), ob: U.bin8(tr.out) };
    } else {
      const d = S.AES.invSboxDerive(f);
      lines = [[`S⁻¹(${U.h2(f)}): inverse affine map ${U.bin8(f)} → ${U.bin8(d.pre)} = ${U.h2(d.pre)}, then its inverse ${U.h2(d.out)}`, 'hot']];
      say = `Look up ${U.h2(f)} at row ${fr.toString(16)}, column ${fc.toString(16)}: ${U.h2(T[f])}. The inverse works backwards: the inverse affine map (bits i+2, i+5, i+7 and the constant 05) turns ${U.h2(f)} into ${U.h2(d.pre)}, and the inverse of ${U.h2(d.pre)} in GF(2⁸) is ${U.h2(d.out)}.`;
      facts = { f, fr, fc, pre: d.pre, out: d.out };
    }
    F.add({ items: [...head, ...table(16, true), ...foot(lines)], hl: { d: inv ? [3] : [0, 1] }, say, facts, meta: { stage: 'focus' } });
    // properties, counted from the table
    let fixed = 0, opp = 0;
    for (let x = 0; x < 256; x++) { if (T[x] === x) fixed++; if (T[x] === (x ^ 255)) opp++; }
    const distinct = new Set(T).size;
    const back = inv ? g.SBOX[T[f]] : g.INV_SBOX[T[f]];
    F.add({ items: [...head, ...table(16, true), ...foot([[`${distinct} distinct values · fixed points: ${fixed} · opposite fixed points: ${opp}`, 'strong'], [`${inv ? 'S' : 'S⁻¹'}(${U.h2(T[f])}) = ${U.h2(back)}: the two tables undo each other`, 'math']])], hl: { d: [2] }, say: `All ${distinct} values appear once, so the table is a permutation and can be undone: ${inv ? 'S' : 'S⁻¹'}(${U.h2(T[f])}) = ${U.h2(back)}. No byte maps to itself (${fixed} fixed points) and none to its complement (${opp}): the constant 63 was chosen so.`, facts: { distinct, fixed, opp, y: T[f], back }, meta: { stage: 'props' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('The S-box', ['S(x) = A·x⁻¹ ⊕ 63 over GF(2), with 00⁻¹ = 00', 'row = high nibble of x, column = low nibble', 'a permutation: 256 distinct values, no fixed points', 'S⁻¹(y) = (A⁻¹·(y ⊕ 63))⁻¹: bits i+2, i+5, i+7 ⊕ 05, then invert']) };
  }
  S.topic({
    id: 'aes-sbox', family: 'p05-steps', order: 20, title: 'The S-box, all 256 entries',
    blurb: 'Inversion and the affine map, done for every byte, fill a 16×16 table. It is a permutation with no fixed points, and its inverse is built backwards.',
    inputs: [
      { id: 'focus', kind: 'hex', label: 'A byte to look up (2 hex digits)', def: '6e', bytes: 1 },
      { id: 'table', kind: 'choice', label: 'Table', def: 'sbox', options: [{ value: 'sbox', label: 'S-box' }, { value: 'inv', label: 'inverse S-box' }] },
    ],
    presets: [
      { label: 'S-box, look up 6e', values: { focus: '6e', table: 'sbox' } },
      { label: 'S-box, look up 00', values: { focus: '00', table: 'sbox' } },
      { label: 'S-box, look up ff', values: { focus: 'ff', table: 'sbox' } },
      { label: 'Inverse S-box, look up 9f', values: { focus: '9f', table: 'inv' } },
    ],
    run: sboxTable,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'rows' && f.meta.n === 16, pick: 'option', options: ['none', 'one', 'a few', 'many'], ask: 'How many bytes x does this table map to themselves?', answer: 'none', explain: 'The affine constant 63 was picked so that the S-box has no fixed points, and its inverse has none either.' }],
    quiz: [
      { q: 'Where is S(a7) in the table?', options: ['Row 7, column a', 'Row a, column 7', 'Row a7', 'It depends on the key'], answer: 1, why: 'The high nibble picks the row and the low nibble the column.' },
      { q: 'Why can decryption undo SubBytes?', options: ['The S-box is its own inverse', 'The S-box is a permutation of the 256 bytes', 'The key cancels it', 'It does not need to'], answer: 1, why: 'Every value appears exactly once, so each output comes from one input.' },
      { q: 'How many fixed points does the AES S-box have?', options: ['0', '1', '2', '16'], answer: 0, why: 'None: the constant of the affine map was chosen to avoid them.' },
      { q: 'How is S⁻¹ computed?', options: ['Invert, then the same affine map', 'The inverse affine map, then invert', 'Apply S twice', 'Read the table backwards'], answer: 1, why: 'Undoing S(x) = A·x⁻¹ ⊕ 63 takes the steps in reverse order: undo the affine map, then invert in GF(2⁸).' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
