// Modes of operation as data flow with the values on the wires: CBC encryption of three blocks (each block
// chained to the ciphertext before it) and CTR (a keystream from counter blocks, nothing chained).
(function (S) {
  'use strict';
  const D = S.Demo, { hex } = S.bytes, F = S.Kit.flow, Mo = S.Modes, box = D.box;
  const sub = (n) => String(n).replace(/\d/g, (d) => '₀₁₂₃₄₅₆₇₈₉'[d]);
  const two = (b) => [hex(b.slice(0, 8)), hex(b.slice(8))];
  const txt = (b) => '“' + String.fromCharCode(...b) + '”';
  const short = (b) => F.short(hex(b), 8);
  const mid = (a, b) => [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2];

  D.add({
    id: 'mode-cbc', order: 30, tag: 'Modes · CBC', short: 'CBC', title: 'CBC encryption of three blocks',
    blurb: 'Each plaintext block is XORed with the ciphertext block before it (the IV for the first), then encrypted. Equal plaintext blocks no longer give equal ciphertext blocks.',
    frames() {
      const P = Mo.split(D.data.modesPlain), key = D.data.modesKey, iv = D.data.modesIv, res = Mo.cbc(P, key, iv);
      const view = box(0, 0, 1160, 470), cx = [250, 600, 950], yP = 50, yX = 150, yE = 232, yT = 296, yC = 372;
      const build = (blk, stage) => {
        const N = F.net('cbc');
        const done = (i) => i < blk || (i === blk && stage >= 2);
        N.box('iv', 86, yX, 160, 64, ['IV', ...two(iv)], 'val3 key');
        for (let i = 0; i < 3; i++) {
          const x = cx[i], cur = i === blk;
          N.box('P' + i, x, yP, 200, 72, ['P' + sub(i + 1) + '  ' + txt(P[i]), ...two(P[i])], 'val3' + (cur && stage === 0 ? ' act' : ''));
          N.op('x' + i, x, yX, 'xor', cur && stage === 0 ? 'act' : '');
          N.box('E' + i, x, yE, 104, 50, 'Eₖ', 'cipher' + (cur && stage === 1 ? ' act' : ''));
          N.box('C' + i, x, yC, 200, 72, ['C' + sub(i + 1), ...(done(i) ? two(res.out[i]) : ['', ''])], 'val3' + (done(i) ? (cur ? ' hot' : '') : ' soft'));
        }
        for (let i = 0; i < 3; i++) {
          const x = cx[i], cur = i === blk;
          const a = (k) => (cur && stage === k ? 'act' : '');
          N.wire('p' + i, [N.port('P' + i, 's'), N.port('x' + i, 'n')], { head: true, cls: a(0) });
          N.wire('xe' + i, [N.port('x' + i, 's'), N.port('E' + i, 'n')], { head: true, cls: a(1) });
          N.wire('ec' + i, [N.port('E' + i, 's'), N.port('C' + i, 'n')], { head: true, cls: a(2) });
          N.wire('k' + i, [[x + 104, yE], N.port('E' + i, 'e')], { head: true, cls: 'key' });
          N.label('kl' + i, x + 110, yE + 5, 'k', 'key', 'start', 15);
          // the chain: from just under E_k round to the next block's ⊕
          if (i < 2) {
            N.dot(x, yT, i + 1 === blk && stage === 0 ? 'act' : '');
            N.wire('ch' + i, [[x, yT], [x + 175, yT], [x + 175, yX], N.port('x' + (i + 1), 'w')], { head: true, cls: i + 1 === blk && stage === 0 ? 'act' : '' });
          }
        }
        N.wire('iv', [N.port('iv', 'e'), N.port('x0', 'w')], { head: true, cls: blk === 0 && stage === 0 ? 'act' : '' });
        // the values riding along, for the block being worked on
        if (blk >= 0 && blk < 3) {
          const i = blk, x = cx[i], st = res.steps[i];
          if (stage === 0) {
            N.chip('p' + i, short(st.p), { path: [N.port('P' + i, 's'), mid(N.port('P' + i, 's'), N.port('x' + i, 'n'))] }, 'act', { ride: true });
            const from = i === 0 ? [N.port('iv', 'e'), mid(N.port('iv', 'e'), N.port('x0', 'w'))] : [[cx[i - 1], yT], [cx[i - 1] + 175, yT], [cx[i - 1] + 175, yX + 52]];
            N.chip('v' + i, short(st.prev), { path: from }, 'key', { ride: true });
          }
          if (stage === 1) N.chip('x' + i, short(st.x), { path: [N.port('x' + i, 's'), mid(N.port('x' + i, 's'), N.port('E' + i, 'n'))] }, 'act', { ride: true });
          if (stage === 2) N.chip('c' + i, short(st.c), { path: [N.port('E' + i, 's'), [x, yT + 18]] }, 'hot', { ride: true });
        }
        return N.items;
      };
      const frames = [{ view, narrowView: D.follow(view, 200, 420), items: build(-1, 0), say: `Three plaintext blocks of 16 bytes, one key k = \`saffron-harbour9\`, and an IV = \`${hex(iv)}\` that must be unpredictable for every message.` }];
      for (let i = 0; i < 3; i++) {
        const st = res.steps[i];
        frames.push({ view, narrowView: D.follow(view, cx[i] - 30, 420), items: build(i, 0), say: `Block ${i + 1}: P${sub(i + 1)} = \`${hex(st.p)}\` meets ${i ? 'C' + sub(i) + ', the ciphertext just made' : 'the IV'}, \`${hex(st.prev)}\`.` });
        frames.push({ view, narrowView: D.follow(view, cx[i], 420), items: build(i, 1), say: `Their XOR, \`${hex(st.x)}\`, is what the block cipher actually encrypts.` });
        frames.push({ view, narrowView: D.follow(view, cx[i] + 40, 420), items: build(i, 2), say: `Eₖ gives C${sub(i + 1)} = \`${hex(st.c)}\`.${i < 2 ? ' It goes out, and it also feeds the next block.' : ''}` });
      }
      frames.push({ view, narrowView: D.follow(view, 600, 420), items: build(3, 0), say: 'Encryption is a chain: block 3 cannot start before block 2 is done. Decryption can run in parallel, since every Cᵢ₋₁ it needs is already known.' });
      return frames;
    },
  });

  D.add({
    id: 'mode-ctr', order: 31, tag: 'Modes · CTR', short: 'CTR', title: 'CTR: a keystream from counter blocks',
    blurb: 'Eₖ never sees the plaintext. It encrypts a nonce and a counter, and the result is XORed into the data, so the blocks are independent.',
    frames() {
      const P = Mo.split(D.data.modesPlain), key = D.data.modesKey, nonce = D.data.modesNonce, res = Mo.ctr(P, key, nonce);
      const view = box(0, 0, 1160, 470), cx = [290, 640, 990], yN = 50, yE = 150, yX = 250, yC = 372;
      const build = (blk, stage) => {
        const N = F.net('ctr');
        for (let i = 0; i < 3; i++) {
          const x = cx[i], cur = i === blk, st = res.steps[i], done = i < blk || (cur && stage >= 1);
          N.box('N' + i, x, yN, 200, 72, ['nonce ‖ ' + i, ...two(st.ctr)], 'val3' + (cur && stage === 0 ? ' act' : ''));
          N.box('E' + i, x, yE, 104, 50, 'Eₖ', 'cipher' + (cur && stage === 0 ? ' act' : ''));
          N.op('x' + i, x, yX, 'xor', cur && stage === 1 ? 'act' : '');
          N.box('P' + i, x - 165, yX, 150, 72, ['P' + sub(i + 1), ...two(P[i])], 'val3' + (cur && stage === 1 ? ' act' : ''));
          N.box('C' + i, x, yC, 200, 72, ['C' + sub(i + 1), ...(done ? two(res.out[i]) : ['', ''])], 'val3' + (done ? (cur ? ' hot' : '') : ' soft'));
          const a = (k) => (cur && stage === k ? 'act' : '');
          N.wire('n' + i, [N.port('N' + i, 's'), N.port('E' + i, 'n')], { head: true, cls: a(0) });
          N.wire('ks' + i, [N.port('E' + i, 's'), N.port('x' + i, 'n')], { head: true, cls: a(0) || a(1) });
          N.wire('p' + i, [N.port('P' + i, 'e'), N.port('x' + i, 'w')], { head: true, cls: a(1) });
          N.wire('c' + i, [N.port('x' + i, 's'), N.port('C' + i, 'n')], { head: true, cls: a(1) });
          N.wire('k' + i, [[x + 104, yE], N.port('E' + i, 'e')], { head: true, cls: 'key' });
          N.label('kl' + i, x + 110, yE + 5, 'k', 'key', 'start', 15);
          if (i <= blk) N.chip('ks' + i, short(st.ks), [x, (yE + 25 + yX - 11) / 2], cur ? 'act' : 'plain');
        }
        if (blk >= 0 && blk < 3) {
          const i = blk, st = res.steps[i];
          if (stage === 1) N.chip('cc' + i, short(st.c), { path: [N.port('x' + i, 's'), [cx[i], yX + 42]] }, 'hot', { ride: true });
        }
        return N.items;
      };
      const frames = [{ view, narrowView: D.follow(view, 220, 420), items: build(-1, 0), say: `The counter blocks are a nonce, \`${hex(nonce.slice(0, 8))}\`, followed by a block number. The same key k = \`saffron-harbour9\` as in the CBC scene.` }];
      for (let i = 0; i < 3; i++) {
        const st = res.steps[i];
        frames.push({ view, narrowView: D.follow(view, cx[i] - 20, 420), items: build(i, 0), say: `Block ${i + 1}: Eₖ(\`${hex(st.ctr)}\`) = \`${hex(st.ks)}\`, the keystream for this block. It could be computed before the message even exists.` });
        frames.push({ view, narrowView: D.follow(view, cx[i] - 60, 420), items: build(i, 1), say: `C${sub(i + 1)} = P${sub(i + 1)} ⊕ keystream = \`${hex(st.p)}\` ⊕ \`${hex(st.ks)}\` = \`${hex(st.c)}\`. Decryption is the very same XOR.` });
      }
      frames.push({ view, narrowView: D.follow(view, 640, 420), items: build(3, 0), say: 'No block waits for another, and a short last block needs no padding. The price: a nonce must never repeat under one key, or two messages share a keystream and their XOR leaks.' });
      return frames;
    },
  });
})(globalThis.Sifer = globalThis.Sifer || {});
