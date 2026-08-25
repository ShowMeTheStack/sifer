// Part 6, ECB: a picture drawn here as pixel art (one byte per pixel, a palette index), encrypted block by block.
// Equal blocks of pixels give equal ciphertext blocks, so the outline of the picture survives in ECB, while CBC or
// CTR turn it into noise.
(function (S) {
  'use strict';
  const U = S.P5, K6 = () => S.Kit.p06, Fl = () => S.Kit.flow;
  const W = 64, H = 48, PAL = 'abcdefgh';

  /** the pictures: a function of (x, y) giving a palette letter */
  const PICTURES = {
    lighthouse(x, y) {
      // the roof, the lamp room and the gallery
      if (y <= 2 && Math.abs(x - 34) <= 1 + y) return 'g';
      if (y >= 3 && y <= 6 && x >= 31 && x <= 37) return x === 31 || x === 37 ? 'g' : 'f';
      if (y === 7 && x >= 29 && x <= 39) return 'g';
      // the tower, wider at the foot, with red bands
      const hw = 3 + (y - 8) * 0.13;
      if (y >= 8 && y <= 33 && Math.abs(x + 0.5 - 34.5) <= hw) return Math.floor((y - 8) / 5) % 2 ? 'e' : 'd';
      // the rocks it stands on
      if (y >= 31 && y >= 30 + ((x - 34) * (x - 34)) / 36) return 'c';
      if (y >= 35) return 'b';
      // the beam, spreading to the left
      if (x < 31 && Math.abs(y - 4.5) <= (31 - x) * 0.11 + 0.6) return 'h';
      return 'a';
    },
    sailboat(x, y) {
      if ((x - 52) * (x - 52) + (y - 9) * (y - 9) <= 25) return 'f';
      if (y >= 34) return y >= 36 && y <= 39 && x >= 14 && x <= 44 && y - 36 <= (x - 14) / 2 && y - 36 <= (44 - x) / 2 ? 'g' : 'b';
      if (y >= 31 && y <= 33 && x >= 12 + (y - 31) && x <= 46 - (y - 31)) return 'g';
      if (x === 29 && y >= 6 && y <= 30) return 'g';
      if (y >= 7 && y <= 29 && x < 29 && x >= 29 - (y - 7) * 0.7) return 'd';
      if (y >= 12 && y <= 29 && x > 29 && x <= 29 + (y - 12) * 0.55) return 'd';
      if (y >= 4 && y <= 6 && x >= 30 && x <= 33) return 'e';
      return 'a';
    },
  };
  const pixelsOf = (name) => { const f = PICTURES[name], px = new Uint8Array(W * H); for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) px[y * W + x] = PAL.indexOf(f(x, y)); return px; };
  const rowsOf = (bytes, look) => { const rows = []; for (let y = 0; y < H; y++) { let s = ''; for (let x = 0; x < W; x++) s += look(bytes[y * W + x]); rows.push(s); } return rows; };
  const plainLook = (v) => PAL[v];
  const hueLook = (v) => String.fromCharCode(65 + (v >> 4));

  function ecb(inp) {
    const key = U.key(inp.key), E = S.AES.cipher(key), M = S.Modes, px = pixelsOf(inp.pic);
    const eb = M.ecbImage(E, px), other = M.encrypt(inp.other, E, px, { iv: U.block(inp.iv), trace: false }).out;
    const nBlocks = px.length / 16, ph = (i) => S.bytes.hex(px.subarray(16 * i, 16 * i + 16));
    const count = new Map(); for (let i = 0; i < nBlocks; i++) count.set(ph(i), (count.get(ph(i)) || 0) + 1);
    const distinctP = count.size, otherDistinct = new Set(Array.from({ length: nBlocks }, (_, i) => S.bytes.hex(other.subarray(16 * i, 16 * i + 16)))).size;
    // the samples: two equal blocks (the most common block, its first two places) and a block that occurs once
    let common = null; for (const [k, v] of count) if (!common || v > count.get(common)) common = k;
    const same = []; for (let i = 0; i < nBlocks && same.length < 2; i++) if (ph(i) === common) same.push(i);
    const lone = Array.from({ length: nBlocks }, (_, i) => i).find((i) => count.get(ph(i)) === 1 && Math.floor(i / 4) > 8);
    const samples = [same[0], same[1], lone];
    const F = new S.Frames(), CS = 4, PY = 76, PX = [20, 312, 604];
    const pic = (k, rows, title, tcls) => [
      U.t('pic:t' + k, PX[k], PY - 14, title, 'title' + (tcls ? ' ' + tcls : '')),
      { key: 'pic:f' + k, kind: 'region', x: PX[k] - 1, y: PY - 1, w: W * CS + 2, h: H * CS + 2, rx: 0, cls: 'p6-pic', audit: 'group' },
      { key: 'pic:b' + k, kind: 'bitmap', x: PX[k], y: PY, cw: CS, ch: CS, gap: 0, rows },
    ];
    const marks = (k) => samples.map((b, j) => ({ key: `pic:m${k}:${j}`, kind: 'region', x: PX[k] + (b % 4) * 16 * CS - 1, y: PY + Math.floor(b / 4) * CS - 2, w: 16 * CS + 2, h: CS + 4, rx: 1, cls: 'p6-mark' + (j === 2 ? ' act' : ''), audit: 'overlap-ok' }));
    const plainRows = rowsOf(px, plainLook), ecbRows = rowsOf(eb.out, hueLook), otherRows = rowsOf(other, hueLook);
    const caption = (k, text, cls) => U.t('pic:c' + k, PX[k], PY + H * CS + 24, text, cls || 'tick', 'start', 14);
    // the sample blocks through Eₖ
    const flow = () => {
      const N = Fl().net('eb'), items = [];
      samples.forEach((b, j) => {
        const y = 348 + j * 92, pb = px.subarray(16 * b, 16 * b + 16), cb = eb.out.subarray(16 * b, 16 * b + 16);
        items.push(U.t('eb:l' + j, 30, y + 6, `block ${b}`, j === 2 ? 'act' : 'hot', 'start', 14));
        items.push({ key: 'eb:pf' + j, kind: 'region', x: 119, y: y - 9, w: 16 * 15 + 1, h: 24, rx: 0, cls: 'p6-pic', audit: 'group' });
        items.push({ key: 'eb:p' + j, kind: 'bitmap', x: 120, y: y - 8, cw: 14, ch: 22, gap: 1, rows: [Array.from(pb, plainLook).join('')] });
        items.push(U.t('eb:ph' + j, 120, y + 34, S.bytes.hex(pb.subarray(0, 8)) + '…', 'mono', 'start', 13));
        N.box('E' + j, 420, y + 3, 80, 40, 'Eₖ', 'cipher');
        N.wire('a' + j, [[350, y + 3], N.port('E' + j, 'w')], { head: true });
        N.wire('b' + j, [N.port('E' + j, 'e'), [526, y + 3]], { head: true });
        items.push({ key: 'eb:c' + j, kind: 'bitmap', x: 530, y: y - 8, cw: 14, ch: 22, gap: 1, rows: [Array.from(cb, hueLook).join('')] });
        items.push(U.t('eb:ch' + j, 530, y + 34, S.bytes.hex(cb.subarray(0, 8)) + '…', 'mono ' + (j < 2 ? 'hot' : ''), 'start', 13));
      });
      items.push(U.t('eb:same', 770, 348 + 46 + 6, '= equal', 'hot', 'start', 15));
      return items.concat(N.items);
    };
    const blank = (k, title) => [U.t('pic:t' + k, PX[k], PY - 14, title, 'title'), { key: 'pic:f' + k, kind: 'region', x: PX[k] - 1, y: PY - 1, w: W * CS + 2, h: H * CS + 2, rx: 0, cls: 'p6-pic', audit: 'group' }];
    const oname = inp.other.toUpperCase();
    F.add({ items: [...pic(0, plainRows, 'plaintext picture'), ...blank(1, 'ECB'), ...blank(2, oname), caption(0, `${W}×${H} pixels, 1 byte each`)], say: `A picture of ${W}×${H} pixels, one byte per pixel: ${px.length} bytes, or ${nBlocks} blocks of 16 pixels each, read row by row. Large areas are one colour, so only ${distinctP} of the ${nBlocks} blocks are different.`, facts: { W, H, bytes: px.length, nBlocks, distinctP }, meta: { stage: 'plain' } });
    const sp = samples.map(ph), sc = samples.map((b) => eb.out.subarray(16 * b, 16 * b + 16));
    F.add({ items: [...pic(0, plainRows, 'plaintext picture'), ...marks(0), ...blank(1, 'ECB'), ...blank(2, oname), ...flow()], say: `ECB encrypts every block on its own. Blocks ${samples[0]} and ${samples[1]} are the same pixels, ${sp[0]}, so they come out the same, ${S.bytes.hex(sc[0])}. Block ${samples[2]} is the only block like it, and gives ${S.bytes.hex(sc[2])}.`, facts: { samples, sp, sc }, meta: { stage: 'flow' } });
    F.add({ items: [...pic(0, plainRows, 'plaintext picture'), ...pic(1, ecbRows, 'ECB', 'hot'), ...marks(1), ...blank(2, oname), caption(1, `${eb.distinct} distinct blocks of ${nBlocks}`, 'hot'), ...flow()], say: `Now the whole picture in ECB, each ciphertext byte drawn as a colour. Every block is scrambled, yet equal blocks stay equal: ${eb.distinct} distinct ciphertext blocks, exactly as many as plaintext blocks, and the shape is still there to see.`, facts: { distinct: eb.distinct, nBlocks }, meta: { stage: 'ecb' } });
    F.add({ items: [...pic(0, plainRows, 'plaintext picture'), ...pic(1, ecbRows, 'ECB', 'hot'), ...pic(2, otherRows, oname, 'act'), caption(1, `${eb.distinct} distinct blocks`, 'hot'), caption(2, `${otherDistinct} distinct blocks`, 'act'), ...flow()], say: `The same pixels in ${oname} with the same key: ${otherDistinct} distinct blocks out of ${nBlocks}. ${inp.other === 'cbc' ? 'Chaining' : 'The counter'} makes every block different, and nothing of the picture survives.`, facts: { otherDistinct, nBlocks }, meta: { stage: 'other' } });
    // distinct blocks as bars: what an observer learns is the pattern of repeats
    const bars = [[`plaintext`, distinctP, ''], ['ECB', eb.distinct, 'hot'], [oname, otherDistinct, 'act']].flatMap(([l, v, c], k) => [
      U.t('eb:bl' + k, 40, 386 + k * 60, l, c || 'strong', 'start', 15),
      { key: 'eb:bb' + k, kind: 'cell', x: 170, y: 368 + k * 60, w: Math.max(2, (v / nBlocks) * 560), h: 28, rx: 3, text: '', cls: 'bar ' + (c || 'soft') },
      U.t('eb:bv' + k, 170 + (v / nBlocks) * 560 + 10, 388 + k * 60, `${v} of ${nBlocks}`, 'tick', 'start', 14)]);
    F.add({ items: [...pic(0, plainRows, 'plaintext picture'), ...pic(1, ecbRows, 'ECB', 'hot'), ...pic(2, otherRows, oname, 'act'), U.t('eb:bt', 40, 346, 'distinct 16-byte blocks', 'title'), ...bars], say: `ECB leaks which blocks are equal, and in a picture, a database column or a protocol message that is a lot. It is never a safe way to encrypt more than one block: use a mode with an IV or a nonce.`, facts: { distinctP, distinct: eb.distinct, otherDistinct }, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('ECB', ['Cᵢ = Eₖ(Pᵢ)', 'Pᵢ = Dₖ(Cᵢ)', 'Pᵢ = Pⱼ  ⇔  Cᵢ = Cⱼ: equality leaks', 'no IV: the same message always gives the same ciphertext']) };
  }
  S.topic({
    id: 'modes-ecb', family: 'p06-modes', order: 10, title: 'ECB: why the picture survives',
    blurb: 'Electronic codebook encrypts each block on its own. A picture drawn in pixels, encrypted block by block, keeps its outline, because equal blocks stay equal.',
    inputs: [
      { id: 'pic', kind: 'choice', label: 'Picture', def: 'lighthouse', options: [{ value: 'lighthouse', label: 'a lighthouse' }, { value: 'sailboat', label: 'a sailboat' }] },
      K6().keyInput(),
      { id: 'other', kind: 'choice', label: 'Compare with', def: 'cbc', options: [{ value: 'cbc', label: 'CBC' }, { value: 'ctr', label: 'CTR' }] },
      K6().ivInput(),
    ],
    presets: [
      { label: 'The lighthouse, against CBC', values: { pic: 'lighthouse', other: 'cbc' } },
      { label: 'The lighthouse with AES-256, against CTR', values: { pic: 'lighthouse', key: 'thirty-two bytes of copper wire!', other: 'ctr' } },
      { label: 'The sailboat', values: { pic: 'sailboat', other: 'cbc' } },
      { label: 'Another key, the same outline', values: { pic: 'lighthouse', key: 'nine-tailed kite', other: 'cbc' } },
    ],
    run: ecb,
    pixels: pixelsOf,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'flow', pick: 'option', options: ['yes, its outline', 'no, pure noise'], ask: 'Will the lighthouse still be visible in the ECB picture?', answer: (fr, i, inp) => 'yes, its outline', explain: 'Equal blocks of sky, sea and rock give equal ciphertext blocks, so the regions keep their shapes.' }],
    quiz: [
      { q: 'What does ECB leak about the plaintext?', options: ['Nothing', 'Which blocks are equal', 'The key', 'Only the length'], answer: 1, why: 'Cᵢ = Cⱼ exactly when Pᵢ = Pⱼ.' },
      { q: 'Does changing the key hide the outline in ECB?', options: ['Yes', 'No: the colours change but equal blocks stay equal', 'Only with AES-256', 'Only for small pictures'], answer: 1, why: 'Any key keeps the pattern of equal blocks.' },
      { q: 'Why does CBC hide the picture?', options: ['Its block cipher is stronger', 'Each block is XORed with the previous ciphertext first, so equal pixels give different inputs', 'It compresses the picture', 'It uses two keys'], answer: 1, why: 'Chaining makes every input to Eₖ different.' },
      { q: 'When is ECB acceptable?', options: ['For long messages', 'For a single block of random data, such as wrapping one key', 'For pictures', 'Never for anything'], answer: 1, why: 'With one unpredictable block there are no repeats to leak; key-wrapping modes still prefer dedicated constructions.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
