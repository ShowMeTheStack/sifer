// Part 4, DES end to end: the whole cipher on a ladder of sixteen rounds that never crosses itself, the initial and
// final permutations as bits flying between two 8×8 grids, and the f-function opened up bit by bit: E, the key mix,
// the eight S-boxes as table lookups, and P. Every value comes from S.DES.
(function (S) {
  'use strict';
  const U = S.SymT, F_ = S.Kit.flow, r2 = U.r2;
  const D4 = (S.P04D = S.P04D || {});
  const DES = () => S.DES;
  const sub = U.sub;
  const hx = (bits) => S.DES.hex(bits);
  const ascii = (b) => (Array.from(b).every((v) => v >= 32 && v < 127) ? '‘' + U.show(b) + '’' : '');

  // ---- shared by the DES topics ------------------------------------------------------------------------------
  D4.plainInp = (def) => ({ id: 'pt', kind: 'hex', label: 'Plaintext (8 bytes, hex)', def: def || U.hex(U.bytesOf('nightjar')), bytes: 8 });
  D4.keyInp = (def) => ({ id: 'key', kind: 'hex', label: 'Key (8 bytes, hex)', def: def || U.hex(U.bytesOf('bramble7')), bytes: 8 });
  const a = (s) => U.hex(U.bytesOf(s));
  /** the presets every DES topic offers: our own words, and two answers from the tables of NIST SP 800-17 */
  D4.presets = (extra) => [
    { label: '‘nightjar’ under ‘bramble7’', values: Object.assign({ pt: a('nightjar'), key: a('bramble7') }, extra || {}) },
    { label: '‘copper42’ under ‘quill&in’', values: Object.assign({ pt: a('copper42'), key: a('quill&in') }, extra || {}) },
    { label: 'SP 800-17: one plaintext bit set', values: Object.assign({ pt: '8000000000000000', key: '0101010101010101' }, extra || {}) },
    { label: 'SP 800-17: one key bit set', values: Object.assign({ pt: '0000000000000000', key: '8001010101010101' }, extra || {}) },
  ];
  D4.bytes = (h) => U.fromHex(h);
  D4.ascii = ascii;
  /** a row of bit cells, keyed by ids(i) when given, so a bit can glide to a new place: {prefix, x, y, bits, cw, ch,
   *  gap, group, groupGap, cls(i, b), text, size, ids(i)} -> {items, xOf(i), w} */
  D4.bits = function (o) {
    const items = [], cw = o.cw || 13, ch = o.ch || 18, gap = o.gap === undefined ? 2 : o.gap, g = o.group || 8, gg = o.groupGap === undefined ? 8 : o.groupGap;
    const xOf = (i) => r2(o.x + i * (cw + gap) + Math.floor(i / g) * gg);
    o.bits.forEach((b, i) => {
      const it = { key: o.prefix + ':' + (o.ids ? o.ids(i) : i), kind: 'cell', x: xOf(i), y: o.y, w: cw, h: ch, rx: 2, text: o.text ? String(b) : '', size: o.size || 13, cls: ['bit dx', b ? 'one' : 'zero', o.cls ? o.cls(i, b) || '' : ''].join(' ') };
      if (o.enter) Object.assign(it, o.enter(i));
      items.push(it);
    });
    return { items, xOf, w: xOf(o.bits.length - 1) + cw - o.x };
  };
  /** a label and its hex on the left of a bit row */
  D4.rowLabel = (key, y, name, hex, cls) => [U.t(key + ':n', 24, y + 6, name, 'strong ' + (cls || ''), 'start', 15), U.t(key + ':x', 24, y + 24, hex, 'mono', 'start', 13)];

  // ---------------------------------------------------------------------------------------------------------------
  // DES end to end
  // ---------------------------------------------------------------------------------------------------------------
  function overview(inp) {
    const P = D4.bytes(inp.pt), K = D4.bytes(inp.key), res = DES().encrypt(P, K), R = res.rounds;
    const out = U.hex(res.out), F = new S.Frames();
    const yA = 226, yB = 366, fy = 296, xIn = 62, xOut = 884, colX = (k) => 112 + (k - 1) * 46;
    const opLane = (k) => (k % 2 ? 'A' : 'B'), yOf = (l) => (l === 'A' ? yA : yB);
    const L0 = hx(R[0].L), R0 = hx(R[0].R);
    const build = (at) => {
      const N = F_.net('do');
      N.box('pt', 170, 88, 260, 50, ['plaintext ' + ascii(P), U.hex(P)], 'val' + (at === 0 ? ' act' : ''));
      N.box('IP', xIn, 296, 56, 190, 'IP', 'cipher' + (at === 1 ? ' act' : ''));
      N.box('FP', xOut, 296, 56, 190, 'FP', 'cipher' + (at === 18 ? ' act' : ''));
      N.box('ct', 760, 500, 290, 50, ['ciphertext', at >= 18 ? out : '…'], 'val' + (at >= 18 ? ' hot' : ' soft'));
      N.wire('in', [N.port('pt', 's', (xIn - 170) / 130), N.port('IP', 'n')], { head: true, cls: at <= 1 ? 'act' : '' });
      N.wire('out', [N.port('FP', 's'), N.port('ct', 'n', (xOut - 760) / 145)], { head: true, cls: at >= 18 ? 'hot' : '' });
      const cuts = { A: [], B: [] };
      for (let k = 1; k <= 16; k++) {
        const x = colX(k), cur = k === at - 1, done = k < at - 1, l = opLane(k), down = l === 'B';
        N.box('f' + k, x, fy, 36, 30, 'f' + sub(k), 'small' + (cur ? ' act' : done ? '' : ' soft'));
        N.op('x' + k, x, yOf(l), 'xor', cur ? 'act' : '');
        cuts[l].push(x);
        const ty = down ? yA : yB;
        N.dot(x, ty, cur ? 'act' : '');
        N.wire('t' + k, [[x, ty], N.port('f' + k, down ? 'n' : 's')], { head: true, cls: cur ? 'act' : '' });
        N.wire('o' + k, [N.port('f' + k, down ? 's' : 'n'), N.port('x' + k, down ? 'n' : 's')], { head: true, cls: cur ? 'act' : '' });
      }
      for (const l of ['A', 'B']) {
        const xs = [90].concat(...cuts[l].map((x) => [x - 11, x + 11]), [856]);
        for (let i = 0; i < xs.length; i += 2) N.wire('l' + l + i, [[xs[i], yOf(l)], [xs[i + 1], yOf(l)]], { head: true, cls: at === 18 ? 'hot' : '' });
      }
      const chip = (id, x, y, text, cls) => N.chip(id, text, [Math.max(150, Math.min(790, x)), y], cls, { onWire: false });
      if (at === 1) { chip('L0', 160, yA - 30, 'L₀ = ' + L0, 'act'); chip('R0', 160, yB + 30, 'R₀ = ' + R0, 'act'); }
      if (at >= 2 && at <= 17) {
        const k = at - 1, r = R[k - 1], l = opLane(k);
        chip('nv', colX(k), l === 'A' ? yA - 30 : yB + 30, 'R' + sub(k) + ' = ' + hx(r.newR), 'hot');
      }
      if (at === 18) { chip('oL', 720, yB + 30, 'left half R₁₆ = ' + hx(R[15].newR), 'hot'); chip('oR', 720, yA - 30, 'right half L₁₆ = ' + hx(R[15].R), 'hot'); }
      return N.items;
    };
    const panel = (rows, title) => U.readout('do:r', 24, 432, 560, title, rows, { dy: 30 });
    F.add({ items: [U.head('do:h', 'DES: IP, sixteen rounds, FP'), ...build(0), ...panel([['plaintext', U.hex(P)], ['key', U.hex(K), 'key'], ['round keys', '16 of 48 bits']], 'the input')],
      say: `DES encrypts one 64-bit block under a 64-bit key (56 bits of it count). Our plaintext is ${U.hex(P)}${ascii(P) ? ', the letters ' + ascii(P) : ''}, under the key ${U.hex(K)}.`, facts: { P: U.hex(P), K: U.hex(K), text: ascii(P) }, meta: { stage: 'start' } });
    F.add({ items: [U.head('do:h', 'DES: IP, sixteen rounds, FP'), ...build(1), ...panel([['L₀', L0, 'act'], ['R₀', R0, 'act']], 'after the initial permutation')],
      say: `The initial permutation shuffles the 64 bits and splits them into two halves of 32: L₀ = ${L0} on the top lane and R₀ = ${R0} on the bottom one.`, facts: { L0, R0 }, meta: { stage: 'ip' } });
    for (let k = 1; k <= 16; k++) {
      const r = R[k - 1], L = hx(r.L), Rr = hx(r.R), Kk = hx(r.K), f = hx(r.f.P), nr = hx(r.newR);
      const say = `Round ${k}: f(R${sub(k - 1)}, K${sub(k)}) = ${f} under the round key ${Kk}; it is XORed into L${sub(k - 1)} = ${L}, giving R${sub(k)} = ${nr}, while R${sub(k - 1)} = ${Rr} passes on as L${sub(k)}.` + (k === 1 ? ' The half just changed feeds f in the next round, so the lanes take turns.' : k === 16 ? ' That is the last round.' : '');
      F.add({ items: [U.head('do:h', 'DES: IP, sixteen rounds, FP'), ...build(k + 1), ...panel([['in: L' + sub(k - 1) + ', R' + sub(k - 1), L + ' ' + Rr], ['K' + sub(k), Kk, 'key'], ['f(R' + sub(k - 1) + ', K' + sub(k) + ')', f], ['R' + sub(k) + ' = L' + sub(k - 1) + ' ⊕ f', nr, 'hot']], 'round ' + k)], hl: { d: [1, 2] },
        say, facts: { k, L, R: Rr, K: Kk, f, newR: nr }, meta: { stage: 'round', k } });
    }
    const pre = hx(R[15].newR) + hx(R[15].R);
    F.add({ items: [U.head('do:h', 'DES: IP, sixteen rounds, FP'), ...build(18), ...panel([['R₁₆ L₁₆ (swapped)', pre, 'hot'], ['FP of that', out, 'hot']], 'swap, then the final permutation')],
      say: `After round 16 the halves leave in swapped order, R₁₆ L₁₆ = ${pre}: the lane changed last goes first. The final permutation, the inverse of IP, gives the ciphertext ${out}.`, facts: { pre, out }, meta: { stage: 'fp' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 610 });
    // on a phone the camera follows the round being worked on
    for (const f of F.list) { const k = f.meta.stage === 'round' ? f.meta.k : f.meta.stage === 'fp' ? 17 : 0, cx = k ? colX(Math.min(k, 16)) + (k > 16 ? 80 : 0) : 170, x = Math.max(0, Math.min(920 - 440, cx - 220)); f.narrowView = { x, y: 50, w: 440, h: 560 }; }
    return { frames: F.list, def: U.def('DES', ['(L₀, R₀) = IP(plaintext)', 'Lᵢ = Rᵢ₋₁', 'Rᵢ = Lᵢ₋₁ ⊕ f(Rᵢ₋₁, Kᵢ),  i = 1 … 16', 'ciphertext = FP(R₁₆ L₁₆),  FP = IP⁻¹', 'block 64 bits, key 56 bits, round keys 48 bits']) };
  }
  S.topic({
    id: 'des-overview', family: 'p04-des', order: 10, title: 'DES end to end',
    blurb: 'The initial permutation splits the block in two; sixteen Feistel rounds each XOR f of one half into the other; the halves leave swapped and the final permutation undoes the first.',
    inputs: [D4.plainInp(), D4.keyInp()], presets: D4.presets(), run: overview,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'round' && f.meta.k === 1, once: true, pick: 'option', options: ['the top lane (L)', 'the bottom lane (R)'], ask: 'Round 1 changed the top lane. Which lane does round 2 change?', answer: 'the bottom lane (R)', explain: 'Each round XORs f of the half just changed into the other half: the lanes take turns.' },
      { at: (f) => f.meta && f.meta.stage === 'round' && f.meta.k === 16, once: true, pick: 'option', options: ['L₁₆', 'R₁₆'], ask: 'Which half becomes the left half of the block that enters FP?', answer: 'R₁₆', explain: 'The output is R₁₆ L₁₆: the final swap is left out, which is what makes decryption the same ladder.' },
    ],
    quiz: [
      { q: 'How many bits of the 64-bit DES key affect the ciphertext?', options: ['64', '56', '48', '32'], answer: 1, why: 'Every eighth bit is a parity bit that the key schedule drops.' },
      { q: 'In round i, what happens to Rᵢ₋₁?', options: ['It is encrypted by f', 'It passes on unchanged as Lᵢ', 'It is XORed with the key', 'It is discarded'], answer: 1, why: 'Only the other half is changed; Rᵢ₋₁ feeds f and moves on untouched.' },
      { q: 'Why does the output take R₁₆ before L₁₆?', options: ['For speed', 'Leaving out the last swap lets decryption run the same ladder with the keys reversed', 'To add security', 'Because FP needs it'], answer: 1, why: 'With the swap undone, decryption is encryption with K₁₆ … K₁.' },
      { q: 'What does the final permutation do?', options: ['Adds the last round key', 'Undoes the initial permutation', 'Mixes the halves', 'Expands the block'], answer: 1, why: 'FP = IP⁻¹; neither adds any security.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // IP and FP
  // ---------------------------------------------------------------------------------------------------------------
  function ipfp(inp) {
    const P = D4.bytes(inp.pt), bits = DES().bits(P), IP = DES().IP, ip = DES().perm(bits, IP), F = new S.Frames();
    const cs = 36, gp = 4, ix = 80, iy = 104, ox = 584, oy = 104;
    const inCell = (p) => ({ x: ix + (p % 8) * (cs + gp), y: iy + Math.floor(p / 8) * (cs + gp) });
    const outCell = (q) => ({ x: ox + (q % 8) * (cs + gp), y: oy + Math.floor(q / 8) * (cs + gp) + (q >= 32 ? 14 : 0) });
    const colOf = (j) => (IP[8 * j] - 1) % 8 + 1;
    const head = U.head('ip:h', 'The initial permutation: columns become bytes');
    const frameIn = (litCol, dim) => {
      const items = [U.t('ip:it', ix, iy - 30, 'input: byte per row', 'title', 'start', 14)];
      for (let c = 0; c < 8; c++) items.push(U.t('ip:ic' + c, ix + c * (cs + gp) + cs / 2, iy - 8, String(c + 1), litCol === c + 1 ? 'act' : 'tick', 'middle', 13));
      for (let r = 0; r < 8; r++) items.push(U.t('ip:ir' + r, ix - 12, iy + r * (cs + gp) + 23, 'byte ' + (r + 1), 'tick', 'end', 13));
      for (let p = 0; p < 64; p++) { const at = inCell(p); items.push({ key: 'ip:i' + p, kind: 'cell', x: at.x, y: at.y, w: cs, h: cs, rx: 3, text: String(bits[p]), size: 15, cls: 'bit ' + (bits[p] ? 'one' : 'zero') + (litCol === p % 8 + 1 ? ' act' : '') + (dim ? ' soft' : '') }); }
      return items;
    };
    const frameOut = (upto, lit) => {
      const items = [U.t('ip:ot', ox, oy - 30, 'IP output: L₀ then R₀', 'title', 'start', 14)];
      for (let j = 0; j < 8; j++) items.push(U.t('ip:or' + j, ox - 12, oy + j * (cs + gp) + (j >= 4 ? 14 : 0) + 23, (j < 4 ? 'L₀ ' : 'R₀ ') + (j % 4 + 1), j === lit ? 'act' : 'tick', 'end', 13));
      for (let q = 0; q < 8 * upto; q++) {
        const p = IP[q] - 1, at = outCell(q), j = Math.floor(q / 8);
        items.push({ key: 'ip:o' + p, kind: 'cell', x: at.x, y: at.y, w: cs, h: cs, rx: 3, text: String(bits[p]), size: 15, cls: 'bit ' + (bits[p] ? 'one' : 'zero') + (j === lit ? ' hot' : ''), enter: 'from', src: 'ip:i' + p });
      }
      return items;
    };
    const mid = (lines) => lines.map(([t, c, s], i) => U.t('ip:m' + i, 466, 210 + i * 30, t, c || '', 'middle', s || 15));
    F.add({ items: [head, ...frameIn(0), ...frameOut(0, -1), ...mid([['IP moves bits;', 'tick'], ['it changes none', 'tick']])],
      say: `The plaintext ${U.hex(P)} written as eight bytes, one per row, most significant bit on the left. IP will read this grid by columns.`, facts: { P: U.hex(P) }, meta: { stage: 'start' } });
    for (let j = 0; j < 8; j++) {
      const c = colOf(j), byte = ip.slice(8 * j, 8 * j + 8);
      F.add({ items: [head, ...frameIn(c), ...frameOut(j + 1, j), ...mid([['column ' + c, 'act', 17], ['read upwards,', 'tick'], ['byte 8 to byte 1', 'tick'], ['→ ' + byte.join(''), 'hot mono', 16]])], hl: { d: [0] },
        say: `Output byte ${j + 1}${j < 4 ? ' (in L₀)' : ' (in R₀)'} is column ${c} of the grid read from byte 8 up to byte 1: ${byte.join('')}.` + (j === 0 ? ` The table starts ${IP.slice(0, 8).join(', ')}: input bits ${IP[0]}, ${IP[1]}, … are bit ${c} of bytes 8, 7, …` : j === 4 ? ' R₀ takes the odd columns, as L₀ took the even ones.' : ''),
        facts: { j: j + 1, c, byte: byte.join(''), t: IP.slice(0, 8) }, meta: { stage: 'row', j, c } });
    }
    const L0 = hx(ip.slice(0, 32)), R0 = hx(ip.slice(32));
    F.add({ items: [head, ...frameIn(0, true), ...frameOut(8, -1), ...mid([['L₀', 'act', 15], [L0, 'act mono', 15], ['R₀', 'act', 15], [R0, 'act mono', 15]])],
      say: `All 64 bits have moved: L₀ = ${L0} is made of the even columns 2, 4, 6, 8 and R₀ = ${R0} of the odd columns 1, 3, 5, 7.`, facts: { L0, R0 }, meta: { stage: 'split' } });
    // FP sends every bit back: the cells fly from their output places to their input places
    const back = DES().perm(ip, DES().FP), same = back.every((b, i) => b === bits[i]);
    const backItems = [U.t('ip:it', ix, iy - 30, 'FP of the output', 'title', 'start', 14)];
    for (let c = 0; c < 8; c++) backItems.push(U.t('ip:ic' + c, ix + c * (cs + gp) + cs / 2, iy - 8, String(c + 1), 'tick', 'middle', 13));
    for (let r = 0; r < 8; r++) backItems.push(U.t('ip:ir' + r, ix - 12, iy + r * (cs + gp) + 23, 'byte ' + (r + 1), 'tick', 'end', 13));
    for (let p = 0; p < 64; p++) { const at = inCell(p); backItems.push({ key: 'ip:o' + p, kind: 'cell', x: at.x, y: at.y, w: cs, h: cs, rx: 3, text: String(back[p]), size: 15, cls: 'bit ' + (back[p] ? 'one' : 'zero') + ' good' }); }
    const ghost = [U.t('ip:ot', ox, oy - 30, 'IP output: L₀ then R₀', 'title', 'start', 14)].concat(Array.from({ length: 64 }, (_, q) => { const at = outCell(q), p = IP[q] - 1; return { key: 'ip:q' + q, kind: 'cell', x: at.x, y: at.y, w: cs, h: cs, rx: 3, text: String(bits[p]), size: 15, cls: 'bit soft ' + (bits[p] ? 'one' : 'zero') }; }));
    for (let j = 0; j < 8; j++) ghost.push(U.t('ip:or' + j, ox - 12, oy + j * (cs + gp) + (j >= 4 ? 14 : 0) + 23, (j < 4 ? 'L₀ ' : 'R₀ ') + (j % 4 + 1), 'tick', 'end', 13));
    F.add({ items: [head, ...backItems, ...ghost, ...mid([['FP = IP⁻¹', 'good', 17], [U.hex(DES().bytes(back)).slice(0, 8), 'mono', 15], [U.hex(DES().bytes(back)).slice(8), 'mono', 15]])], exits: Object.fromEntries(Array.from({ length: 64 }, (_, p) => ['ip:i' + p, { exit: 'fade' }])),
      say: `The final permutation sends every bit back where it came from: FP(IP(x)) = ${U.hex(DES().bytes(back))}, ${same ? 'the plaintext again' : 'not the plaintext'}. Both are public and fixed, so they add no security; they suited the 8-bit hardware buses of the 1970s.`,
      facts: { back: U.hex(DES().bytes(back)), same }, meta: { stage: 'fp' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 470 });
    return { frames: F.list, def: U.def('IP and FP', ['IP: output bit i = input bit IP[i]', 'IP = 58 50 42 34 26 18 10 2 | 60 52 … | 57 49 … | 63 55 … 7', 'output byte j = one input column, read bottom to top', 'L₀ = columns 2, 4, 6, 8;  R₀ = columns 1, 3, 5, 7', 'FP = IP⁻¹']) };
  }
  S.topic({
    id: 'des-ipfp', family: 'p04-des', order: 20, title: 'IP and FP: bits that move',
    blurb: 'The initial permutation reads the block as an 8×8 grid of bits, column by column; the final permutation puts every bit back. Fixed and public, they cost nothing to an attacker.',
    inputs: [D4.plainInp()],
    presets: [
      { label: '‘nightjar’', values: { pt: a('nightjar') } },
      { label: 'One bit set: 80 00 … 00', values: { pt: '8000000000000000' } },
      { label: 'Counting: 01 23 45 … ef', values: { pt: '0123456789abcdef' } },
      { label: 'Alternate bytes: ff 00 ff 00 …', values: { pt: 'ff00ff00ff00ff00' } },
    ],
    run: ipfp,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'row' && f.meta.j === 0, once: true, pick: 'option', options: ['column 1', 'column 3', 'column 4', 'column 8'], ask: 'Output byte 1 was column 2. Which column becomes output byte 2?', answer: (fr, i) => 'column ' + fr[i + 1].facts.c, explain: 'L₀ takes the even columns in order: 2, 4, 6, 8.' },
      { at: (f) => f.meta && f.meta.stage === 'row' && f.meta.j === 3, once: true, pick: 'option', options: ['column 1', 'column 5', 'column 7', 'column 2'], ask: 'L₀ is full. Which column starts R₀?', answer: (fr, i) => 'column ' + fr[i + 1].facts.c, explain: 'R₀ takes the odd columns in order: 1, 3, 5, 7.' },
    ],
    quiz: [
      { q: 'What does IP add to the security of DES?', options: ['A secret shuffle', 'Nothing: it is fixed and public', 'Diffusion between rounds', 'Key whitening'], answer: 1, why: 'An attacker can apply IP and FP herself; they only reorder bits.' },
      { q: 'Output bit 1 of IP is input bit 58. Where is input bit 58?', options: ['Byte 8, bit 2', 'Byte 2, bit 8', 'Byte 7, bit 1', 'Byte 1, bit 58'], answer: 0, why: '58 = 7 × 8 + 2: the eighth byte, its second bit.' },
      { q: 'Which input bits make up L₀?', options: ['The first four bytes', 'The even-numbered bit columns', 'The odd-numbered bit columns', 'Every fourth bit'], answer: 1, why: 'IP reads columns 2, 4, 6 and 8 into L₀.' },
      { q: 'What is FP(IP(x))?', options: ['IP applied twice', 'x', 'The bits reversed', 'L and R swapped'], answer: 1, why: 'FP is the inverse permutation of IP.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The f-function
  // ---------------------------------------------------------------------------------------------------------------
  function ffun(inp) {
    const P = D4.bytes(inp.pt), K = D4.bytes(inp.key), rn = inp.round, res = DES().encrypt(P, K), r = res.rounds[rn - 1], f = r.f;
    const F = new S.Frames(), BX = 128, cw = 13, gap = 2, g6 = 6 * (cw + gap) + 8;
    const yR = 66, yE = 120, yK = 174, yX = 228, yS = 478, yP = 540;
    const head = U.head('ff:h', 'The f-function of round ' + rn, 24, 26);
    // R's group i of four bits sits over E's group i of six
    const xR = (i) => r2(BX + Math.floor(i / 4) * g6 + (cw + gap) + (i % 4) * (cw + gap));
    const rowR = (cls) => r.R.map((b, i) => ({ key: 'ff:r' + i, kind: 'cell', x: xR(i), y: yR, w: cw, h: 18, rx: 2, text: '', cls: 'bit dx ' + (b ? 'one ' : 'zero ') + (cls ? cls(i) : '') }));
    const row48 = (pre, y, bits, cls) => D4.bits({ prefix: pre, x: BX, y, bits, cw, ch: 18, gap, group: 6, groupGap: 8, cls }).items;
    const row32 = (pre, y, bits, cls) => D4.bits({ prefix: pre, x: BX + cw + gap, y, bits, cw, ch: 18, gap, group: 4, groupGap: 8 + 2 * (cw + gap), cls }).items;
    const x32 = (i) => r2(BX + cw + gap + i * (cw + gap) + Math.floor(i / 4) * (8 + 2 * (cw + gap)));
    const dup = new Set(); for (let i = 0; i < 8; i++) { dup.add(6 * i); dup.add(6 * i + 5); }
    const L = (k, y, n, h, c) => D4.rowLabel('ff:' + k, y, n, h, c);
    const top = (stage, box) => {
      const it = [head, ...L('lr', yR, 'R' + sub(rn - 1), hx(r.R)), ...rowR(stage === 1 ? (i) => (i % 4 === 0 || i % 4 === 3 ? 'act' : '') : null)];
      if (stage >= 1) it.push(...L('le', yE, 'E(R)', hx(f.E)), ...row48('ff:e', yE, f.E, (i) => (stage === 1 && dup.has(i) ? 'act' : '')));
      if (stage >= 2) it.push(...L('lk', yK, 'K' + sub(rn), hx(r.K), 'key'), ...row48('ff:k', yK, r.K, () => 'key'));
      if (stage >= 3) it.push(...L('lx', yX, 'E ⊕ K', hx(f.X)), ...row48('ff:x', yX, f.X, (i) => (box !== undefined && Math.floor(i / 6) === box ? 'act' : stage === 3 ? 'hot' : '')));
      for (let i = 0; i < 8 && stage >= 3; i++) it.push(U.t('ff:g' + i, BX + i * g6 + 3 * (cw + gap) - 1, yX + 36, 'S' + (i + 1), box === i ? 'act' : 'tick', 'middle', 13));
      return it;
    };
    const sRow = (upto, lit) => {
      const it = [...L('ls', yS, 'S-boxes', upto >= 8 ? hx(f.S) : '…')];
      it.push(...row32('ff:s', yS, f.S.slice(0, 4 * upto), (i) => (Math.floor(i / 4) === lit ? 'hot' : '')));
      return it;
    };
    const table = (k) => {
      const b = f.boxes[k], tx = 400, ty = 326, tcw = 28, tch = 24, it = [];
      it.push(U.t('ff:tt', tx - 34, ty - 30, 'S' + (k + 1) + ': row by the outer bits, column by the middle four', 'title', 'start', 14));
      for (let c = 0; c < 16; c++) it.push(U.t('ff:tc' + c, tx + c * (tcw + 2) + tcw / 2, ty - 6, String(c), c === b.col ? 'act' : 'tick', 'middle', 13));
      for (let rr = 0; rr < 4; rr++) {
        it.push(U.t('ff:tr' + rr, tx - 10, ty + rr * (tch + 2) + 17, String(rr), rr === b.row ? 'act' : 'tick', 'end', 13));
        for (let c = 0; c < 16; c++) { const v = DES().SBOX[k][16 * rr + c]; it.push({ key: 'ff:t' + rr + '_' + c, kind: 'cell', x: tx + c * (tcw + 2), y: ty + rr * (tch + 2), w: tcw, h: tch, rx: 2, text: String(v), size: 13, cls: 'hex ' + (rr === b.row && c === b.col ? 'hot' : rr === b.row || c === b.col ? 'act' : '') }); }
      }
      const ins = DES().bin(b.in6);
      it.push(U.t('ff:i0', 24, 344, 'in: ' + ins, 'mono', 'start', 17));
      it.push(U.t('ff:i1', 24, 376, 'row ' + ins[0] + ins[5] + ' = ' + b.row, 'act', 'start', 15));
      it.push(U.t('ff:i2', 24, 404, 'col ' + ins.slice(1, 5) + ' = ' + b.col, 'act', 'start', 15));
      it.push(U.t('ff:i3', 24, 438, 'out: ' + b.v + ' = ' + DES().bin(b.out), 'hot', 'start', 17));
      return it;
    };
    const say = [];
    F.add({ items: [...top(0), ...sRow(0)], say: `Round ${rn} of DES on ${U.hex(P)}: f takes the right half R${sub(rn - 1)} = ${hx(r.R)} (32 bits) and the round key K${sub(rn)} = ${hx(r.K)} (48 bits), and gives 32 bits to XOR into the left half.`, facts: { R: hx(r.R), K: hx(r.K), rn }, meta: { stage: 'start' } });
    F.add({ items: [...top(1), ...sRow(0)], hl: { d: [0] }, say: `E expands R to 48 bits: each group of four bits takes its two neighbours' edge bits, so 16 bits appear twice. E(R) = ${hx(f.E)}.`, facts: { E: hx(f.E) }, meta: { stage: 'E' } });
    F.add({ items: [...top(2), ...sRow(0)], hl: { d: [1] }, say: `The round key enters here and only here: K${sub(rn)} = ${hx(r.K)}.`, facts: { K: hx(r.K) }, meta: { stage: 'K' } });
    F.add({ items: [...top(3), ...sRow(0)], hl: { d: [1] }, say: `E(R) ⊕ K${sub(rn)} = ${hx(f.X)}, cut into eight groups of six bits, one for each S-box.`, facts: { X: hx(f.X) }, meta: { stage: 'X' } });
    for (let k = 0; k < 8; k++) {
      const b = f.boxes[k], ins = DES().bin(b.in6);
      F.add({ items: [...top(4, k), ...table(k), ...sRow(k + 1, k)], hl: { d: [2] }, say: `S${k + 1} gets ${ins}: the outer bits ${ins[0]}${ins[5]} pick row ${b.row}, the middle bits ${ins.slice(1, 5)} pick column ${b.col}, and the entry there is ${b.v} = ${DES().bin(b.out)}.` + (k === 0 ? ' Six bits in, four out: the S-boxes are the only part of DES that is not linear.' : ''),
        facts: { k: k + 1, in6: ins, outer: ins[0] + ins[5], mid: ins.slice(1, 5), row: b.row, col: b.col, v: b.v, out: DES().bin(b.out) }, meta: { stage: 'sbox', k } });
    }
    // P: each output bit labelled with the S-box it came from
    const srcBox = DES().P.map((p) => Math.floor((p - 1) / 4) + 1);
    const pRow = [...L('lp', yP, 'f = P(S)', hx(f.P), 'hot'), ...row32('ff:p', yP, f.P, () => 'hot')];
    srcBox.forEach((s, i) => pRow.push(Object.assign(U.t('ff:pb' + i, x32(i) + cw / 2, yP + 34, String(s), 'tick', 'middle', 12), { audit: 'small-ok' })));
    const looks = [U.t('ff:lt', 24, 300, 'the eight lookups', 'title', 'start', 14)].concat(f.boxes.map((bx, k) => ({ key: 'ff:lk' + k, kind: 'cell', x: 24 + (k % 4) * 218, y: 314 + Math.floor(k / 4) * 44, w: 208, h: 34, rx: 4, text: 'S' + (k + 1) + '  ' + DES().bin(bx.in6) + ' → ' + DES().bin(bx.out), size: 14, cls: 'hex' })));
    F.add({ items: [...top(4), ...looks, ...sRow(8), ...pRow, U.t('ff:pn', 24, yP + 64, 'under each bit of f: the S-box it came from', 'tick', 'start', 13)], hl: { d: [3] },
      say: `The eight outputs make ${hx(f.S)}. P scatters them: the four bits of each S-box land in four different groups, so in the next round they reach several S-boxes. f = ${hx(f.P)}.`, facts: { S: hx(f.S), f: hx(f.P) }, meta: { stage: 'P' } });
    F.add({ items: [...top(4), ...looks, ...sRow(8), ...pRow, U.t('ff:pn', 24, yP + 64, 'R' + sub(rn) + ' = L' + sub(rn - 1) + ' ⊕ f = ' + hx(r.L) + ' ⊕ ' + hx(f.P) + ' = ' + hx(r.newR), 'act mono', 'start', 15)], hl: { d: [4] },
      say: `Back in the round, f is XORed into the left half: R${sub(rn)} = ${hx(r.L)} ⊕ ${hx(f.P)} = ${hx(r.newR)}. f never has to be undone: decryption computes the same f again and XORs it out.`, facts: { L: hx(r.L), f: hx(f.P), newR: hx(r.newR) }, meta: { stage: 'xor' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 620 });
    void say;
    return { frames: F.list, def: U.def('f(R, K)', ['E: 32 → 48 bits, 16 of them used twice', 'X = E(R) ⊕ K', 'Sᵢ(b₁…b₆) = table i at row b₁b₆, column b₂b₃b₄b₅', 'P: a fixed shuffle of the 32 S-box bits', 'Rᵢ = Lᵢ₋₁ ⊕ P(S(E(Rᵢ₋₁) ⊕ Kᵢ))']) };
  }
  S.topic({
    id: 'des-f', family: 'p04-des', order: 30, title: 'The f-function: E, the key, eight S-boxes, P',
    blurb: 'f expands the half-block to 48 bits, mixes in the round key, looks each six bits up in an S-box to get four, and scatters the 32 results. The S-boxes are the only non-linear step in DES.',
    inputs: [D4.plainInp(), D4.keyInp(), { id: 'round', kind: 'number', label: 'Round', def: 1, min: 1, max: 16 }],
    presets: D4.presets({ round: 1 }).concat([{ label: '‘nightjar’, round 9', values: { pt: a('nightjar'), key: a('bramble7'), round: 9 } }]),
    run: ffun,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'X', once: true, pick: 'option', options: ['0', '1', '2', '3'], ask: 'Read the first six bits of E ⊕ K. Which row of S1 will they pick?', answer: (fr, i) => String(fr[i + 1].facts.row), explain: 'The row is the first and the sixth bit read as a two-bit number.' },
      { at: (f) => f.meta && f.meta.stage === 'start', once: true, pick: 'option', options: ['8', '16', '24', '32'], ask: 'E makes 48 bits out of 32. How many bits of R will appear twice?', answer: '16', explain: '48 − 32 = 16: the two edge bits of each group of four are copied into the neighbouring groups.' },
    ],
    quiz: [
      { q: 'An S-box input is 110010. Which row and column does it pick?', options: ['row 2, column 9', 'row 3, column 9', 'row 2, column 12', 'row 1, column 9'], answer: 0, why: 'Outer bits 1 and 0 give row 10 = 2; the middle bits 1001 give column 9.' },
      { q: 'Where does the round key enter f?', options: ['Before E', 'Between E and the S-boxes, by XOR', 'After P', 'Into the S-box tables'], answer: 1, why: 'X = E(R) ⊕ K is the only place the key touches the data.' },
      { q: 'Which step of f is not linear over GF(2)?', options: ['E', 'The key XOR', 'The S-boxes', 'P'], answer: 2, why: 'E and P only move bits and the XOR is addition; the S-box lookups are what resist linear and differential attacks.' },
      { q: 'Does f need to be invertible?', options: ['Yes, or decryption fails', 'No: the Feistel structure only ever recomputes f', 'Only its S-boxes', 'Only for weak keys'], answer: 1, why: 'Decryption XORs the same f(R, K) back out; f is never run backwards (it maps 32 bits through 48 and back to 32).' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
