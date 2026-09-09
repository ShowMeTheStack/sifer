// Part 12, Merkle–Damgård: a message padded with 0x80, zeros and its own length, cut into blocks that a chain of
// compression functions takes in one at a time, from a fixed IV to the digest. Drawn with the padded bytes on the
// left (each byte coloured by its role) and the chain of compressions beside the blocks they read.
(function (S) {
  'use strict';
  const U = S.P12, H = () => S.Hash;
  const { t } = U;

  const NAMES = { sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5' };
  function md(inp) {
    const Hs = H(), A = Hs.get(inp.hash), msg = U.utf8(inp.msg), name = NAMES[inp.hash];
    const run = A.run(msg, { trace: true }), padded = run.padded, B = A.blockLen, L = A.spec.lenBytes || 8, n = msg.length;
    const nb = padded.length / B, zeros = padded.length - n - 1 - L, bits = n * 8;
    const wordHex = A.spec.wordHex, cvs = run.chain.map(wordHex), first = (s) => s.split(' ')[0];
    const role = (i) => (i < n ? 'pm' : i === n ? 'p80' : i >= padded.length - L ? 'plen' : 'p00');
    // geometry: 16 bytes a row, four rows a block, blocks one under another
    const cw = 30, ch = 25, per = 16, x0 = 70, y0 = 100, rowH = ch + 3, blockGap = 22;
    const rowY = (r) => y0 + r * rowH + Math.floor(r / 4) * blockGap;
    const blockMid = (k) => rowY(4 * k) + (4 * rowH - 3) / 2;
    const fx = 652, cvx = 800;
    const F = new S.Frames(['blocks', 'compressions']);
    const bytes = (upto, lit) => {
      const items = [];
      for (let i = 0; i < Math.min(upto, padded.length); i++) {
        const r = Math.floor(i / per), c = i % per, rl = role(i), v = padded[i];
        const ch8 = rl === 'pm' && v >= 33 && v < 127 ? String.fromCharCode(v) : rl === 'pm' && v === 32 ? '␣' : U.h2(v);
        items.push({ key: 'md:b' + i, kind: 'cell', x: x0 + c * (cw + 2), y: rowY(r), w: cw, h: ch, rx: 3, text: ch8, size: 13, cls: 'hex ' + rl + (lit && lit(i) ? ' act' : '') });
      }
      return items;
    };
    const blockLabels = (on) => {
      const items = [];
      for (let k = 0; k < nb; k++) items.push(t('md:bl' + k, x0 - 12, blockMid(k) + 5, 'M' + U.sub(k + 1), on === k ? 'act' : 'strong', 'end', 15));
      return items;
    };
    const chain = (done, cur) => {
      // IV at the top, an f box beside each block, chaining values on the wire between them, the digest below
      const items = [], N = S.Kit.flow.net('mdc');
      const ivY = y0 - 36 + 6;
      N.box('iv', fx, ivY, 112, 34, 'IV', 'val key small');
      for (let k = 0; k < nb; k++) {
        const on = k < done, isCur = k === cur;
        N.box('f' + k, fx, blockMid(k), 62, 44, 'f', isCur ? 'cipher act' : on ? 'cipher' : 'soft');
        N.wire('in' + k, [[x0 + per * (cw + 2) + 6, blockMid(k)], N.port('f' + k, 'w')], { head: true, cls: isCur ? 'act' : on ? '' : 'faint' });
        N.wire('cv' + k, [k ? N.port('f' + (k - 1), 's') : N.port('iv', 's'), N.port('f' + k, 'n')], { head: true, cls: isCur ? 'act' : k < done ? '' : 'faint' });
        // the chaining value that comes out, at the side
        if (on) {
          const y = blockMid(k);
          items.push({ key: 'mdc:o' + k, kind: 'wire', pts: [[fx + 31, y], [cvx - 66, y]], head: true, cls: isCur ? 'act' : '' });
          items.push({ key: 'mdc:ov' + k, kind: 'cell', x: cvx - 64, y: y - 15, w: 136, h: 30, rx: 5, text: first(cvs[k + 1]) + '…', size: 13, cls: 'hex ' + (isCur ? 'act' : '') });
          items.push(t('mdc:ol' + k, cvx + 80, y + 5, k === nb - 1 ? 'H' : 'CV' + U.sub(k + 1), isCur ? 'act' : 'ptick', 'start', 13));
        }
      }
      items.push(...N.items);
      items.push(t('mdc:ivv', fx + 66, ivY + 5, first(cvs[0]) + '…', 'mono key', 'start', 13));
      return items;
    };
    const digestPanel = (dg) => {
      const lines = dg.match(/.{1,32}/g), items = U.panel('md:dp', 380, 512, 516, 50 + 22 * lines.length, 'digest, ' + name);
      lines.forEach((l, k) => items.push(t('md:dl' + k, 396, 562 + 22 * k, l.replace(/(.{8})(?!$)/g, '$1 '), 'mono hot', 'start', 15)));
      return items;
    };
    const legend = U.legend('md:lg', 30, 628, [['pm', 'message'], ['p80', '0x80'], ['p00', 'zero bytes'], ['plen', 'length in bits']], 13);
    const head = U.head('md:h', name + ' of ' + U.an(n + '-byte') + ' message', B + '-byte blocks, a ' + (L * 8) + '-bit length field, ' + (A.spec.endian === 'le' ? 'little' : 'big') + '-endian');
    const base = { n, B, L, bits };
    F.add({ items: [...head, ...bytes(n), ...legend], hl: { d: [0] }, say: n ? `The message is ${U.plural(n, 'byte')}: “${U.cut(inp.msg, 60)}”. ${name} eats it in ${B}-byte blocks, so it must first be padded to a whole number of blocks.` : `The message is empty: 0 bytes. Even so, ${name} pads it to one whole ${B}-byte block.`, facts: base, meta: { stage: 'msg' } });
    F.add({ items: [...head, ...bytes(n + 1), ...legend], hl: { d: [1] }, say: `First a single 1 bit, written as the byte 80 (1000 0000), at position ${n}. It marks where the message ends, so a message that itself ends in zero bytes cannot be confused with a shorter one.`, facts: base, meta: { stage: 'one' } });
    F.add({ items: [...head, ...bytes(n + 1 + zeros), ...legend], hl: { d: [2] }, say: `Then ${U.plural(zeros, 'zero byte')}: just enough that, with the ${L}-byte length still to come, the total is a multiple of ${B}. ${Math.ceil((n + 1) / B) < nb ? 'The message left too little room in its last block for the length, so a whole extra block was needed.' : ''}`.trim(), facts: Object.assign({ zeros }, base), meta: { stage: 'zeros' } });
    const lenHex = U.hex(padded.slice(padded.length - L));
    F.add({ items: [...head, ...bytes(padded.length), ...blockLabels(-1), ...legend], hl: { d: [3] }, say: `Last, the length of the message in bits, ${bits}, as ${L} ${A.spec.endian === 'le' ? 'little' : 'big'}-endian bytes: ${lenHex}. This is length strengthening: two messages of different lengths always end in different final blocks. The padded message is ${padded.length} bytes, ${U.plural(nb, 'block')}.`, facts: Object.assign({ lenHex, total: padded.length, nb }, base), meta: { stage: 'len' } });
    F.set('blocks', nb);
    F.add({ items: [...head, ...bytes(padded.length), ...blockLabels(-1), ...chain(0, -1), ...legend], hl: { d: [4] }, say: `The chain starts from a fixed initial value, the IV, which begins ${first(cvs[0])}. ${nb === 1 ? 'One compression' : `${nb} compressions`} will follow, one per block.`, facts: Object.assign({ iv: cvs[0], nb }, base), meta: { stage: 'iv' } });
    for (let k = 0; k < nb; k++) {
      F.count('compressions');
      const blk = run.blocks[k];
      F.add({ items: [...head, ...bytes(padded.length, (i) => Math.floor(i / B) === k), ...blockLabels(k), ...chain(k + 1, k), ...legend], hl: { d: [5] }, say: `Compression ${k + 1}: f takes the chaining value ${first(cvs[k])}… and block M${U.sub(k + 1)}${blk.lengthBlock ? ' (the one that carries the length)' : ''}, and gives ${k === nb - 1 ? 'the last chaining value' : 'CV' + U.sub(k + 1)} = ${first(cvs[k + 1])}…. f never sees the whole message, only the state so far and one block.`, facts: Object.assign({ k: k + 1, cvIn: cvs[k], cvOut: cvs[k + 1] }, base), meta: { stage: 'f', k } });
    }
    const dg = U.hex(run.digest);
    F.add({ items: [...head, ...bytes(padded.length), ...blockLabels(-1), ...chain(nb, -1), ...digestPanel(dg), ...legend], hl: { d: [6] }, say: `The digest is the last chaining value${A.spec.endian === 'le' ? ', written out little-endian' : ''}: ${U.spaced(dg)}. Because the digest is the whole final state, anyone who knows it can carry on hashing from it: the length-extension attack.`, facts: Object.assign({ digest: dg }, base), meta: { stage: 'digest' } });
    U.fix(F.list);
    return {
      frames: F.list, def: U.def('Merkle–Damgård', [
        'message m of ℓ bytes',
        'append the byte 80 (a single 1 bit)',
        'append zero bytes until the length is ' + (B - L) + ' mod ' + B,
        'append ℓ·8 as a ' + (L * 8) + '-bit ' + (A.spec.endian === 'le' ? 'little' : 'big') + '-endian number',
        'CV₀ = IV',
        'CVᵢ = f(CVᵢ₋₁, Mᵢ) for each block Mᵢ',
        'H(m) = the last CV',
      ]),
    };
  }
  S.topic({
    id: 'p12-md', family: 'p12-md', order: 10, title: 'Merkle–Damgård: padding, length and the chain',
    blurb: 'Pad the message with a 1 bit, zeros and its own length, cut it into blocks, and run a compression function down the chain from a fixed IV. A collision-resistant compression function then gives a collision-resistant hash.',
    inputs: [
      { id: 'msg', kind: 'text', label: 'Message', def: 'Sifer hashes this line, one round at a time.', check: (v) => (U.utf8(v).length > 183 ? 'Message: at most 183 bytes, so the picture stays readable' : null) },
      { id: 'hash', kind: 'choice', label: 'Hash', def: 'sha256', options: [{ value: 'sha256', label: 'SHA-256' }, { value: 'sha1', label: 'SHA-1' }, { value: 'md5', label: 'MD5 (little-endian length)' }] },
    ],
    presets: [
      { label: 'One block', values: { msg: 'Sifer hashes this line, one round at a time.', hash: 'sha256' } },
      { label: 'The empty message', values: { msg: '', hash: 'sha256' } },
      { label: '55 bytes: still one block', values: { msg: 'Fifty-five bytes exactly fill one block with the length', hash: 'sha256' } },
      { label: '56 bytes: two blocks', values: { msg: 'Fifty-six bytes leave no room for the length: two blocks', hash: 'sha256' } },
      { label: 'Three blocks', values: { msg: 'A longer note crosses block boundaries: the chaining value carries everything learned so far from one compression to the next, and only the last one is the digest.', hash: 'sha256' } },
      { label: 'MD5 writes its length little-endian', values: { msg: 'Sifer hashes this line, one round at a time.', hash: 'md5' } },
    ],
    counters: [{ id: 'blocks', label: 'blocks' }, { id: 'compressions', label: 'compressions' }],
    run: md,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'one', pick: 'option', options: ['1 block', '2 blocks', '3 blocks', '4 blocks'], ask: 'With the 0x80, the zeros and the length, how many blocks will the padded message fill?', answer: (fr) => { const last = fr.find((f) => f.meta && f.meta.stage === 'len'); const nb = last.facts.nb; return nb + (nb === 1 ? ' block' : ' blocks'); }, explain: 'The message, one byte of 80 and the length field must fit; zeros fill the rest of the last block.' },
      { at: (f) => f.meta && f.meta.stage === 'iv', pick: 'item', ask: 'Click the block that the first compression reads.', answer: () => ['md:b0', 'md:bl0'], explain: 'The chain runs from the IV through block M₁ first.' },
    ],
    quiz: [
      { q: 'A message of 56 bytes is hashed with SHA-256. How many blocks after padding?', options: ['1', '2', '3', '56'], answer: 1, why: '56 + 1 + 8 = 65 bytes is more than 64, so a second block is needed.' },
      { q: 'Why is the length appended?', options: ['to make the digest longer', 'so messages of different lengths end in different blocks, which the security proof needs', 'to speed up hashing', 'for little-endian machines'], answer: 1, why: 'Length strengthening is what lets a collision of the hash be traced back to a collision of the compression function.' },
      { q: 'What does the compression function see?', options: ['the whole message', 'the chaining value and one block', 'only the IV', 'the digest so far and the length'], answer: 1, why: 'f maps (CV, block) to the next CV, one block at a time.' },
      { q: 'Why does the last chaining value being the digest cause trouble?', options: ['it makes collisions easy', 'anyone holding the digest can continue the chain: length extension', 'it leaks the message length', 'it is slower'], answer: 1, why: 'The digest is the full internal state, so hashing can resume from it with more blocks.' },
      { q: 'Which byte marks the end of the message in SHA-256 padding?', options: ['00', '01', '80', 'ff'], answer: 2, why: 'A single 1 bit followed by zeros: the byte 80.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
