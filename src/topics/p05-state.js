// Part 5, the AES state: sixteen bytes poured into a 4×4 grid column by column, the key beside them, and the state
// after every round on a ladder of the round steps, until the grid is read out again as the ciphertext.
(function (S) {
  'use strict';
  const U = S.P5;

  function overview(inp) {
    const P = U.block(inp.pt), K = U.key(inp.key), A = S.AES;
    const res = A.encrypt(P, K), Nr = res.rounds.length - 1, Nk = K.length / 4;
    const F = new S.Frames();
    // the block as a row of cells, the key under it, the state grid, the ladder of rounds, the ciphertext row
    const RX = 40, RW = 44, RG = 6, GX = 44, GY = 236, GW = 70, GH = 54, GG = 6;
    const kcw = K.length === 16 ? 44 : K.length === 24 ? 30 : 23, kg = K.length === 16 ? 6 : 2;
    const rowCell = (i) => ({ x: RX + i * (RW + RG), y: 48 });
    const gridCell = (i) => ({ x: GX + Math.floor(i / 4) * (GW + GG), y: GY + (i % 4) * (GH + GG) });
    const byteIt = (key, at, v, cls, w, h, size) => ({ key, kind: 'cell', x: at.x, y: at.y, w, h, rx: 5, text: U.h2(v), size, cls: 'hex ' + (cls || '') });
    const rowItems = (cls) => [U.t('ov:pt', RX, 34, 'plaintext block ' + (U.asText(P) || ''), 'title'), ...Array.from(P, (v, i) => Object.assign(byteIt('ov:p' + i, rowCell(i), v, cls ? cls(i) : '', RW, 38, 15), { sub: String(i) }))];
    const keyItems = (lit) => [U.t('ov:kt', RX, 122, `key: ${K.length} bytes, ${Nk} words`, 'title'), ...U.cells('ov:k', RX, 132, K, { cw: kcw, ch: 30, gap: kg, size: K.length === 32 ? 13 : 14, cls: () => 'key' + (lit ? ' keyhot' : '') })];
    const gridTitle = (text, cls) => U.t('ov:gt', GX, GY - 14, text, 'title' + (cls ? ' ' + cls : ''));
    const empty = () => Array.from({ length: 16 }, (_, i) => ({ key: 'ov:g' + i, kind: 'cell', x: gridCell(i).x, y: gridCell(i).y, w: GW, h: GH, rx: 5, text: '', cls: 'soft', pick: true }));
    const heads = () => [0, 1, 2, 3].map((c) => U.t('ov:ch' + c, gridCell(4 * c).x + GW / 2, GY + 4 * (GH + GG) + 14, 'col ' + c, 'tick', 'middle', 13)).concat([0, 1, 2, 3].map((r) => U.t('ov:rh' + r, GX - 8, gridCell(r).y + GH / 2 + 5, 'r' + r, 'tick', 'end', 13)));
    // the bytes of the state fly in from their places in the row
    const state = (vals, cls) => Array.from(vals, (v, i) => Object.assign(byteIt('ov:b' + i, gridCell(i), v, cls ? cls(i) : '', GW, GH, 19), { enter: 'fly', from: rowCell(i) }));
    // the ladder: round 0 is AddRoundKey alone; the last round has no MixColumns
    const LX = 420, LY = 236, LH = Math.min(26, 360 / (Nr + 1)), STEP = ['Sub', 'Shift', 'MixCol', 'AddKey'];
    const ladder = (now) => {
      const items = [U.t('ov:lt', LX, LY - 14, `${Nr} rounds after round 0`, 'title')];
      STEP.forEach((s, k) => items.push(U.t('ov:lh' + k, LX + 96 + k * 90 + 42, LY + 8, s, 'tick', 'middle', 13)));
      for (let r = 0; r <= Nr; r++) {
        const y = LY + 18 + r * LH, st = r < now ? '' : r === now ? 'act' : 'soft';
        items.push(U.t('ov:lr' + r, LX, y + LH / 2 + 4, 'round ' + r, r === now ? 'act' : r < now ? 'strong' : 'tick', 'start', 13));
        STEP.forEach((s, k) => {
          const has = r === 0 ? k === 3 : r === Nr ? k !== 2 : true;
          if (has) items.push({ key: `ov:l${r}:${k}`, kind: 'cell', x: LX + 96 + k * 90, y, w: 84, h: LH - 4, rx: 3, text: '', cls: (k === 3 ? 'key ' : '') + st });
        });
      }
      return items;
    };
    const cRow = () => [U.t('ov:ct', RX, 122, 'ciphertext', 'title hot'), ...Array.from(res.out, (v, i) => Object.assign(byteIt('ov:b' + i, { x: rowCell(i).x, y: 132 }, v, 'hot', RW, 38, 15), { sub: String(i) }))];
    const pick = inp.pick, lit = (i) => (i === pick ? 'act' : '');
    const row = () => rowItems(() => 'muted');

    F.add({ items: [...rowItems(), ...keyItems(), gridTitle('the state'), ...empty(), ...heads(), ...ladder(-1)], say: `AES works on a block of 16 bytes${U.asText(P) ? ', here the text ' + U.asText(P) : ''}: ${U.hex(P)}. The key is ${K.length} bytes long, so this is AES-${K.length * 8} with ${Nr} rounds.`, facts: { P, K, Nr, bytes: K.length }, meta: { stage: 'block' } });
    F.add({ items: [...rowItems(lit), ...keyItems(), gridTitle('the state'), ...empty(), ...heads(), ...ladder(-1)], say: `Next, the bytes go into the empty 4×4 grid below, the state, one column at a time: bytes 0 to 3 will fill column 0 from the top, bytes 4 to 7 column 1, and so on. Byte ${pick}, lit in the row, is ${U.h2(P[pick])}.`, facts: { pick, b: P[pick] }, meta: { stage: 'row' } });
    F.add({ items: [...rowItems(lit), ...keyItems(), gridTitle('the state'), ...state(P, lit), ...heads(), ...ladder(-1)], say: `Byte i goes to row i mod 4 and column ⌊i/4⌋, so byte ${pick} sits in ${U.cell(pick)}. Each column of four bytes is a 32-bit word; column 0 is ${U.hex(P.slice(0, 4))}.`, facts: { pick, r: pick % 4, c: Math.floor(pick / 4), col0: P.slice(0, 4) }, meta: { stage: 'fill' } });
    const k0 = res.rounds[0].key;
    F.add({ items: [...row(), ...keyItems(true), gridTitle('the state'), ...state(P), ...heads(), ...ladder(-1)], say: `The key is cut into ${Nk} words and expanded into ${Nr + 1} round keys of 16 bytes each, one for round 0 and one for each of the ${Nr} rounds. Round key 0 is ${U.hex(k0)}.`, facts: { Nk, Nr, n: Nr + 1, k0 }, meta: { stage: 'key' } });
    for (let r = 0; r <= Nr; r++) {
      const st = res.rounds[r].end;
      const what = r === 0 ? 'Round 0 is only AddRoundKey: the state is XORed with round key 0' : r === Nr ? `Round ${r}, the last, has no MixColumns: SubBytes, ShiftRows and AddRoundKey` : `Round ${r}: SubBytes, ShiftRows, MixColumns and AddRoundKey`;
      F.add({ items: [...row(), ...keyItems(), gridTitle('after round ' + r, 'act'), ...state(st, () => (r === Nr ? 'hot' : 'changed')), ...heads(), ...ladder(r)], hl: { d: r === 0 ? [2] : r === Nr ? [4] : [3] }, say: `${what}. The state is now ${U.hex(st)}${r === 0 ? '' : `, column 0 ${U.hex(st.slice(0, 4))}`}.`, facts: { r, st, col0: st.slice(0, 4) }, meta: { stage: 'round', r } });
    }
    F.add({ items: [...row(), gridTitle('after round ' + Nr, 'act'), ...state(res.out, () => 'soft').map((x) => Object.assign(x, { key: x.key + 'g', enter: 'none' })), ...heads(), ...ladder(Nr + 1), ...cRow()], say: `The ciphertext is the final state read out column by column, the same way the plaintext went in: ${U.hex(res.out)}.`, facts: { C: res.out }, meta: { stage: 'out' } });
    U.fix(F.list);
    return {
      frames: F.list,
      def: U.def('The AES state and rounds', [
        'state s[r][c] = byte r + 4c of the block (column order)',
        'Nk = key words (4, 6, 8); Nr = Nk + 6 rounds (10, 12, 14)',
        'round 0: AddRoundKey',
        'rounds 1 … Nr−1: SubBytes, ShiftRows, MixColumns, AddRoundKey',
        'round Nr: SubBytes, ShiftRows, AddRoundKey',
      ]),
    };
  }
  S.topic({
    id: 'aes-overview', family: 'p05-state', order: 10, title: 'The AES state and its rounds',
    blurb: 'Sixteen bytes go into a 4×4 grid column by column. Round 0 adds the key, then every round substitutes, shifts, mixes and adds a round key; the last one skips the mixing.',
    inputs: [
      { id: 'pt', kind: 'text', label: 'Plaintext (16 characters or 32 hex digits)', def: 'Lanterns at dusk', check: U.blockCheck('Plaintext') },
      { id: 'key', kind: 'text', label: 'Key (16, 24 or 32 characters, or hex)', def: 'ochre-river-2026', check: U.keyCheck('Key') },
      { id: 'pick', kind: 'number', label: 'Byte to follow', def: 6, min: 0, max: 15 },
    ],
    presets: [
      { label: 'A line of text, AES-128', values: { pt: 'Lanterns at dusk', key: 'ochre-river-2026', pick: 6 } },
      { label: 'FIPS 197 example (AES-128)', values: { pt: '00112233445566778899aabbccddeeff', key: '000102030405060708090a0b0c0d0e0f', pick: 9 } },
      { label: 'AES-192: twelve rounds', values: { pt: 'Kelp beds sway 3', key: 'a quiet orchard of 24 by', pick: 13 } },
      { label: 'AES-256: fourteen rounds', values: { pt: 'Moth on the pane', key: 'thirty-two bytes of copper wire!', pick: 2 } },
    ],
    run: overview,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'row', pick: 'item', ask: (fr, i, inp) => `Click the cell of the state where byte ${inp.pick} will go.`, answer: (fr, i, inp) => 'ov:g' + inp.pick, explain: (fr, i, inp) => `Byte ${inp.pick} goes to row ${inp.pick % 4}, column ${Math.floor(inp.pick / 4)}: the grid fills down each column first.` }],
    quiz: [
      { q: 'In which order are the 16 bytes of a block written into the state?', options: ['Row by row, left to right', 'Column by column, top to bottom', 'Along the diagonals', 'In a key-dependent order'], answer: 1, why: 'Byte i goes to row i mod 4 and column ⌊i/4⌋, so each column is a 4-byte word.' },
      { q: 'How many rounds does AES-256 have?', options: ['10', '12', '14', '16'], answer: 2, why: 'Nr = Nk + 6, and a 256-bit key is 8 words.' },
      { q: 'Which step is left out of the last round?', options: ['SubBytes', 'ShiftRows', 'MixColumns', 'AddRoundKey'], answer: 2, why: 'MixColumns there would add no security, and leaving it out makes decryption line up with encryption.' },
      { q: 'How many round keys does AES-128 use?', options: ['10', '11', '14', '44'], answer: 1, why: 'One for round 0 and one for each of the 10 rounds; together they are the 44 words of the key schedule.' },
      { q: 'Does the block size change with the key size?', options: ['Yes: 192-bit keys use 192-bit blocks', 'No: the block is always 128 bits', 'Only for AES-256', 'Only in decryption'], answer: 1, why: 'AES fixes the block at 16 bytes; only the number of rounds and the key schedule change.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
