// Part 5, Mini-AES by hand: a 16-bit block of four nibbles in a 2×2 state, a 4-bit S-box, a swap of the bottom row,
// MixColumn over GF(2⁴) with x⁴ + x + 1, and two rounds with three 16-bit round keys. Every nibble is shown in
// binary, and every product of MixColumn is worked out, so the whole cipher can be followed with pencil and paper.
(function (S) {
  'use strict';
  const U = S.P5;
  const hx = (v) => v.toString(16);
  const b4 = (v) => v.toString(2).padStart(4, '0');

  function mini(inp) {
    const M = S.MiniAES, dec = inp.dir === 'dec';
    const x = parseInt(inp.p, 16), key = parseInt(inp.k, 16);
    const ks = M.keySchedule(key), w = ks.w, K = ks.keys;
    const F = new S.Frames();
    // the key schedule along the top: twelve nibbles w0 … w11 in three round keys
    const WX = 40, WY = 52, WW = 50, WG = 6, KG = 26;
    const wx = (i) => WX + i * (WW + WG) + Math.floor(i / 4) * KG;
    const sched = (upto, lit, used) => {
      const items = [U.t('mk:t', WX, 26, 'key schedule: w0 … w11', 'title')];
      for (let i = 0; i < 12; i++) {
        const on = i <= upto;
        items.push({ key: 'mk:w' + i, kind: 'cell', x: wx(i), y: WY, w: WW, h: 44, rx: 4, lines: on ? [hx(w[i]), b4(w[i])] : [''], size: 13, cls: 'hex ' + (!on ? 'soft' : lit === i ? 'keyhot' : used && used.includes(i) ? 'act' : 'key') });
        items.push(U.t('mk:l' + i, wx(i) + WW / 2, WY + 62, 'w' + i, lit === i ? 'key' : 'tick', 'middle', 13));
      }
      for (let k = 0; k < 3; k++) items.push({ key: 'mk:b' + k, kind: 'bracket', x1: wx(4 * k), x2: wx(4 * k + 3) + WW, y: WY + 72, side: 'below', text: upto >= 4 * k + 3 ? 'K' + k + ' = ' + M.hex(M.join(K[k])) : 'K' + k, cls: 'key' });
      return items;
    };
    // the state: 2×2, column by column [n0 n2 / n1 n3], each nibble in hex and in binary
    const GY = 196, CW = 84, CH = 64, CG = 8;
    const cellAt = (gx, i) => ({ x: gx + Math.floor(i / 2) * (CW + CG), y: GY + (i % 2) * (CH + CG) });
    const state = (prefix, gx, n, title, cls) => [U.t(prefix + ':t', gx, GY - 14, title, 'title'), ...n.map((v, i) => ({ key: prefix + i, kind: 'cell', ...cellAt(gx, i), w: CW, h: CH, rx: 6, lines: v === null ? [''] : [hx(v), b4(v)], size: 17, cls: 'hex ' + (v === null ? 'soft' : cls ? cls(i) : '') }))];
    const AX = 40, BX = 390, gw = 2 * CW + CG;
    const step = (a, b, name, sub, lines, o) => {
      o = o || {};
      // with no step named, the state stands alone (the block at the start, the result at the end)
      const items = [...state('ms:a', AX, a, o.aTitle || 'state', o.aCls), ...(name ? state('ms:b', BX, b || [null, null, null, null], o.bTitle || ' ', b ? o.bCls || (() => 'changed') : null) : [])];
      const ay = GY + CH + CG / 2;
      if (name) items.push(U.arrow('ms:arr', [[AX + gw + 14, ay], [BX - 14, ay]], 'act'));
      if (name) items.push(U.t('ms:an', (AX + gw + BX) / 2, ay - 12, name, 'act', 'middle', 14));
      if (sub) items.push(U.t('ms:as', (AX + gw + BX) / 2, ay + 24, sub, 'tick', 'middle', 13));
      if (lines && lines.length) {
        items.push(...U.panel('ms:p', 600, GY - 30, 260, 40 + lines.length * 26, o.panel || 'working'));
        lines.forEach((l, i) => items.push(U.t('ms:pl' + i, 616, GY + 22 + i * 26, l.text || l, l.cls || 'math', 'start', 14)));
      }
      return items;
    };
    // the S-box as a table of 16 entries along the bottom, the ones in use lit
    const sbox = (used, inv) => {
      const T = inv ? M.INV_SBOX : M.SBOX, items = [U.t('mx:t', 40, 470, inv ? 'inverse S-box' : 'S-box (NibbleSub)', 'title')];
      items.push(U.t('mx:in', 40, 503, 'in', 'tick', 'start', 13), U.t('mx:out', 40, 545, 'out', 'tick', 'start', 13));
      for (let i = 0; i < 16; i++) {
        const on = used && used.includes(i);
        items.push({ key: 'mx:i' + i, kind: 'cell', x: 76 + i * 48, y: 482, w: 44, h: 32, rx: 3, text: hx(i), size: 15, cls: 'hex ' + (on ? 'act' : 'soft') });
        items.push({ key: 'mx:o' + i, kind: 'cell', x: 76 + i * 48, y: 524, w: 44, h: 32, rx: 3, text: hx(T[i]), size: 15, cls: 'hex ' + (on ? 'hot' : '') });
      }
      return items;
    };
    // the products MixColumn needs: x, 2·x and 3·x in GF(2⁴) for every nibble, the ones in use lit
    const mulTable = (used) => {
      const items = [U.t('mm:t', 40, 450, 'times 2 and times 3 in GF(2⁴)', 'title')];
      [['x', (v) => v], ['2·x', (v) => M.mul(2, v)], ['3·x', (v) => M.mul(3, v)]].forEach(([nm, f], j) => {
        items.push(U.t('mm:n' + j, 40, 481 + j * 40, nm, 'tick', 'start', 13));
        for (let i = 0; i < 16; i++) items.push({ key: `mm:${j}:${i}`, kind: 'cell', x: 76 + i * 48, y: 462 + j * 40, w: 44, h: 32, rx: 3, text: hx(f(i)), size: 15, cls: 'hex ' + (used.includes(i) ? (j ? 'hot' : 'act') : j ? '' : 'soft') });
      });
      return items;
    };
    const st = (n) => `[${hx(n[0])}, ${hx(n[2])} / ${hx(n[1])}, ${hx(n[3])}]`;
    const nf = (n) => ({ n0: n[0], n1: n[1], n2: n[2], n3: n[3] });
    // ---- the key schedule, with the block waiting in the state
    const waiting = () => step(M.nibbles(x), null, '', '', [], { aTitle: dec ? 'ciphertext' : 'plaintext', aCls: () => 'soft' });
    F.add({ items: [...sched(3, -1), ...waiting()], say: `The 16-bit key ${M.hex(key)} is four nibbles: w0 to w3 = ${w.slice(0, 4).map(hx).join(', ')}. They are round key K0.`, facts: { key: M.hex(key), w: w.slice(0, 4) }, meta: { stage: 'k0' } });
    for (const r of [1, 2]) {
      const b = 4 * r, s = M.SBOX[w[b - 1]], rc = M.RCON[r - 1];
      F.add({ items: [...sched(b, b, [b - 4, b - 1]), ...waiting()], hl: { d: [5] }, say: `w${b} = w${b - 4} ⊕ NibbleSub(w${b - 1}) ⊕ rcon(${r}) = ${b4(w[b - 4])} ⊕ ${b4(s)} ⊕ ${b4(rc)} = ${b4(w[b])}, which is ${hx(w[b])}.`, facts: { a: w[b - 4], s, rc, out: w[b], r }, meta: { stage: 'kw', i: b } });
      F.add({ items: [...sched(b + 3, b + 3, [b, b + 1, b + 2]), ...waiting()], hl: { d: [5] }, say: `The other three are plain XORs of the word four back and the word just made: w${b + 1} = ${hx(w[b - 3])} ⊕ ${hx(w[b])} = ${hx(w[b + 1])}, w${b + 2} = ${hx(w[b - 2])} ⊕ ${hx(w[b + 1])} = ${hx(w[b + 2])}, w${b + 3} = ${hx(w[b - 1])} ⊕ ${hx(w[b + 2])} = ${hx(w[b + 3])}. So K${r} = ${M.hex(M.join(K[r]))}.`, facts: { w: w.slice(b - 3, b + 4), K: M.hex(M.join(K[r])), r }, meta: { stage: 'kr', r } });
    }
    // ---- the rounds
    const keyUse = (r) => [4 * r, 4 * r + 1, 4 * r + 2, 4 * r + 3];
    const add = (n, r, title) => {
      const k = K[r], o = n.map((v, i) => v ^ k[i]);
      F.add({ items: [...sched(11, -1, keyUse(r)), ...step(n, o, 'add K' + r, 'XOR with the key', n.map((v, i) => `${b4(v)} ⊕ ${b4(k[i])} = ${b4(o[i])}`), { aTitle: title, bTitle: 'after adding K' + r, panel: 'K' + r + ' = ' + M.hex(M.join(k)) })], hl: { d: [4] }, say: `Add K${r} = ${M.hex(M.join(k))}: XOR it into the state, nibble by nibble. ${st(n)} becomes ${st(o)}.`, facts: { k: M.join(k), n: nf(n), o: nf(o), K: M.hex(M.join(k)), r }, meta: { stage: 'add', r } });
      return o;
    };
    const sub = (n, inv) => {
      const o = n.map((v) => (inv ? M.INV_SBOX : M.SBOX)[v]);
      F.add({ items: [...sched(11, -1), ...step(n, o, inv ? 'inverse NibbleSub' : 'NibbleSub', 'S-box on each nibble', n.map((v, i) => `${hx(v)} → ${hx(o[i])}`), { aTitle: 'state', bTitle: inv ? 'after inverse Sub' : 'after NibbleSub', panel: 'lookups' }), ...sbox(n, inv)], hl: { d: [1] }, say: `${inv ? 'The inverse NibbleSub' : 'NibbleSub'} looks each nibble up in the ${inv ? 'inverse ' : ''}S-box: ${n.map((v, i) => hx(v) + ' → ' + hx(o[i])).join(', ')}.`, facts: { n: nf(n), o: nf(o) }, meta: { stage: inv ? 'isub' : 'sub' } });
      return o;
    };
    const shift = (n) => {
      const o = M.shiftRow(n);
      F.add({ items: [...sched(11, -1), ...step(n, o, 'ShiftRow', 'swap the bottom row', [`top:    ${hx(n[0])} ${hx(n[2])} → ${hx(o[0])} ${hx(o[2])}`, `bottom: ${hx(n[1])} ${hx(n[3])} → ${hx(o[1])} ${hx(o[3])}`, { text: 'its own inverse', cls: 'tick' }], { aTitle: 'state', bTitle: 'after ShiftRow', aCls: (i) => (i % 2 ? 'act' : ''), bCls: (i) => (i % 2 ? 'hot' : '') })], hl: { d: [2] }, say: `ShiftRow swaps the two nibbles of the bottom row, ${hx(n[1])} and ${hx(n[3])}, and leaves the top row alone: ${st(o)}. Doing it twice changes nothing, so it is its own inverse.`, facts: { n: nf(n), o: nf(o) }, meta: { stage: 'shift' } });
      return o;
    };
    const mix = (n, undo) => {
      const o = M.mixColumn(n).out, lines = [];
      for (let c = 0; c < 2; c++) {
        const a = n[2 * c], b = n[2 * c + 1];
        lines.push(`3·${hx(a)} ⊕ 2·${hx(b)} = ${hx(M.mul(3, a))} ⊕ ${hx(M.mul(2, b))} = ${hx(o[2 * c])}`);
        lines.push(`2·${hx(a)} ⊕ 3·${hx(b)} = ${hx(M.mul(2, a))} ⊕ ${hx(M.mul(3, b))} = ${hx(o[2 * c + 1])}`);
      }
      const a = n[0], b = n[1];
      F.add({ items: [...sched(11, -1), ...step(n, o, 'MixColumn', '× [3 2 / 2 3]', lines, { aTitle: 'state', bTitle: 'after MixColumn', panel: 'column by column' }), ...mulTable(n)], hl: { d: [3] }, say: `MixColumn multiplies each column by the matrix [3 2 / 2 3] over GF(2⁴), reducing by x⁴ + x + 1. Column 0: 3·${hx(a)} ⊕ 2·${hx(b)} = ${hx(M.mul(3, a))} ⊕ ${hx(M.mul(2, b))} = ${hx(o[0])}, and 2·${hx(a)} ⊕ 3·${hx(b)} = ${hx(M.mul(2, a))} ⊕ ${hx(M.mul(3, b))} = ${hx(o[1])}. The state is ${st(o)}.${undo ? ' The matrix squared is the identity, so the same step undoes itself.' : ''}`, facts: { n: nf(n), o: nf(o), p: [M.mul(3, a), M.mul(2, b), M.mul(2, a), M.mul(3, b)] }, meta: { stage: 'mix' } });
      return o;
    };
    let s = M.nibbles(x);
    F.add({ items: [...sched(11, -1), ...step(s, null, '', '', [], { aTitle: dec ? 'ciphertext' : 'plaintext', aCls: () => 'act' })], say: `The ${dec ? 'ciphertext' : 'plaintext'} ${M.hex(x)} is four nibbles, written into the 2×2 state column by column: ${st(s)}. In binary they are ${s.map(b4).join(' ')}.`, facts: { x: M.hex(x), n: nf(s), bin: s.map(b4) }, meta: { stage: 'start' } });
    if (!dec) {
      s = add(s, 0, 'plaintext');
      s = sub(s); s = shift(s); s = mix(s); s = add(s, 1, 'after MixColumn');
      s = sub(s); s = shift(s); s = add(s, 2, 'after ShiftRow');
    } else {
      s = add(s, 2, 'ciphertext');
      s = shift(s); s = sub(s, true); s = add(s, 1, 'state');
      s = mix(s, true); s = shift(s); s = sub(s, true); s = add(s, 0, 'state');
    }
    const out = M.join(s), check = dec ? M.encrypt(out, key).out : M.decrypt(out, key).out;
    F.add({ items: [...sched(11, -1), ...step(s, null, '', '', [{ text: M.hex(out), cls: 'hot' }, { text: s.map(b4).join(' ') }], { aTitle: dec ? 'plaintext' : 'ciphertext', aCls: () => 'hot', panel: dec ? 'the plaintext' : 'the ciphertext' })], say: `The ${dec ? 'plaintext' : 'ciphertext'} is ${M.hex(out)}, in binary ${s.map(b4).join(' ')}. ${dec ? 'Encrypting it again' : 'Decrypting it'} gives back ${M.hex(check)}.`, facts: { out: M.hex(out), bin: s.map(b4), back: M.hex(check) }, meta: { stage: 'out' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Mini-AES', ['state [n0 n2 / n1 n3], four 4-bit nibbles', 'NibbleSub: a 4-bit S-box on each nibble', 'ShiftRow: swap n1 and n3', 'MixColumn: each column × [3 2 / 2 3] in GF(2⁴), x⁴ + x + 1', 'add Kr: XOR the 16-bit round key', 'w4r = w4r−4 ⊕ NibbleSub(w4r−1) ⊕ rcon(r); others w(i−4) ⊕ w(i−1)', 'encrypt: add K0; Sub, Shift, Mix, add K1; Sub, Shift, add K2']) };
  }
  const hex4 = (label) => (v) => (/^[0-9a-fA-F]{4}$/.test(String(v).trim()) ? null : label + ': four hex digits (16 bits)');
  S.topic({
    id: 'aes-mini', family: 'p05-mini', order: 10, title: 'Mini-AES, worked by hand',
    blurb: 'AES shrunk to 16 bits: four nibbles in a 2×2 state, a 4-bit S-box, a row swap, a 2×2 mixing matrix over GF(2⁴) and two rounds. Every step fits on a sheet of paper.',
    inputs: [
      { id: 'p', kind: 'text', label: 'Block (4 hex digits)', def: '9c63', check: hex4('Block') },
      { id: 'k', kind: 'text', label: 'Key (4 hex digits)', def: 'c3f0', check: hex4('Key') },
      { id: 'dir', kind: 'choice', label: 'Direction', def: 'enc', options: [{ value: 'enc', label: 'encrypt' }, { value: 'dec', label: 'decrypt' }] },
    ],
    presets: [
      { label: 'Encrypt 9c63 under c3f0', values: { p: '9c63', k: 'c3f0', dir: 'enc' } },
      { label: 'Decrypt 72c6 under c3f0', values: { p: '72c6', k: 'c3f0', dir: 'dec' } },
      { label: 'All zeros', values: { p: '0000', k: '0000', dir: 'enc' } },
      { label: 'Encrypt 5afe under 7e11', values: { p: '5afe', k: '7e11', dir: 'enc' } },
    ],
    run: mini,
    predict: [{
      at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.stage === 'shift', once: true, pick: 'option',
      options: (fr, i) => { const n = fr[i + 1].facts.n, o = fr[i + 1].facts.o, h = (q) => `[${hx(q.n0)}, ${hx(q.n2)} / ${hx(q.n1)}, ${hx(q.n3)}]`; const alt = { n0: n.n2, n1: n.n1, n2: n.n0, n3: n.n3 }, alt2 = { n0: n.n1, n1: n.n0, n2: n.n3, n3: n.n2 }; return [...new Set([h(o), h(n), h(alt), h(alt2)])]; },
      ask: 'ShiftRow is next. What will the state look like?',
      answer: (fr, i) => { const o = fr[i + 1].facts.o; return `[${hx(o.n0)}, ${hx(o.n2)} / ${hx(o.n1)}, ${hx(o.n3)}]`; },
      explain: 'Only the bottom row moves: its two nibbles swap places.',
    }],
    quiz: [
      { q: 'How many bits is a Mini-AES block?', options: ['4', '8', '16', '128'], answer: 2, why: 'Four nibbles of four bits.' },
      { q: 'In GF(2⁴) with x⁴ + x + 1, what is 2·8?', options: ['0', '3', '10', 'f'], answer: 1, why: '8 is x³; times x is x⁴, which reduces to x + 1 = 3.' },
      { q: 'Why can decryption use the same MixColumn as encryption?', options: ['It is linear', 'The matrix [3 2 / 2 3] times itself is the identity over GF(2⁴)', 'It has no effect', 'The S-box undoes it'], answer: 1, why: '3·3 ⊕ 2·2 = 5 ⊕ 4 = 1 and 3·2 ⊕ 2·3 = 0, so the matrix is its own inverse.' },
      { q: 'With a 16-bit key, how many keys must exhaustive search try at most?', options: ['16', '256', '65,536', 'About 3.4 × 10³⁸'], answer: 2, why: '2¹⁶ = 65,536: Mini-AES teaches the structure, not security.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
