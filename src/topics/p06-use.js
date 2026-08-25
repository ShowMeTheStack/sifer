// Part 6, using a block cipher well: padding a message to whole blocks (PKCS#7, ISO 7816-4) or not at all
// (ciphertext stealing), and the two sizes that set a cipher's limits: the key, against exhaustive search, and the
// block, against the birthday bound.
(function (S) {
  'use strict';
  const U = S.P5, K6 = () => S.Kit.p06;

  // ---- padding -----------------------------------------------------------------------------------------------
  function padding(inp) {
    const msg = S.bytes.utf8(String(inp.msg)), M = S.Modes, L = msg.length, d = L % 16, F = new S.Frames();
    const pk = M.pkcs7(msg, 16), iso = M.iso7816(msg, 16), k = pk.length - L;
    const X0 = 64, CW = 44, GP = 3, rowY = (r) => 70 + r * 66;
    const rows = (pfx, bytes, cls, upto, title) => {
      const items = [], n = Math.ceil(Math.max(bytes.length, upto || 0) / 16);
      for (let r = 0; r < n; r++) {
        items.push(U.t(pfx + 't' + r, X0, rowY(r) - 10, title ? title(r) : 'block ' + (r + 1), 'title'));
        for (let c = 0; c < 16; c++) { const i = 16 * r + c, has = i < bytes.length; items.push({ key: pfx + i, kind: 'cell', x: X0 + c * (CW + GP), y: rowY(r), w: CW, h: 34, rx: 3, text: has ? U.h2(bytes[i]) : '', size: 15, cls: 'hex ' + (has ? cls(i) : 'soft') }); }
      }
      return items;
    };
    const msgCls = () => '';
    const padCls = (i) => (i < L ? '' : 'hot');
    const isoCls = (i) => (i < L ? '' : i === L ? 'key' : 'act');
    const panel = (title, lines) => [...U.panel('pd:p', 40, 290, 800, 60 + lines.length * 30, title), ...lines.map((l, i) => U.t('pd:l' + i, 64, 342 + i * 30, l[0], l[1] || '', 'start', l[2] || 15))];
    F.add({ items: [...rows('pd:', msg, msgCls, pk.length)], say: `The message${U.asText(msg) ? ', ' + U.asText(msg) + ',' : ''} is ${L} bytes: ${Math.floor(L / 16)} whole block${Math.floor(L / 16) === 1 ? '' : 's'} ${d ? `and ${d} bytes over` : 'exactly'}. ECB and CBC can only encrypt whole 16-byte blocks, so the end must be filled in a way the receiver can undo.`, facts: { L, whole: Math.floor(L / 16), d }, meta: { stage: 'msg' } });
    F.add({ items: [...rows('pd:', pk, padCls), ...panel('PKCS#7', [[`add k bytes, each equal to k: here k = ${k}, so ${k} × ${U.h2(k)}`, 'math'], [d ? 'k is 16 − (length mod 16)' : 'the length is a multiple of 16, so a whole block of 10s is added', ''], ['k is never 0: there is always at least one padding byte', 'tick']])], hl: { d: [0] }, say: `PKCS#7 adds k bytes of value k, where k = 16 − (${L} mod 16) = ${k}: ${U.plural(k, 'byte')} of ${U.h2(k)}.${d ? '' : ' The message already ends on a block boundary, so a whole extra block is added; otherwise a message ending in 01 could not be told from padding.'}`, facts: { k, kh: U.h2(k), L, n16: L % 16 }, meta: { stage: 'pkcs7' } });
    // checking padding: the good case and a damaged one
    const bad = Uint8Array.from(pk); bad[bad.length - 1 - (k > 1 ? 1 : 0)] ^= k > 1 ? 0x01 : k;
    let badOk = true; try { M.unpkcs7(bad, 16); } catch (e) { badOk = false; }
    const last = pk[pk.length - 1];
    F.add({ items: [...rows('pd:', pk, padCls), ...panel('checking PKCS#7 when decrypting', [[`last byte ${U.h2(last)}: the last ${U.plural(last, 'byte')} must all be ${U.h2(last)}`, 'math'], [`${U.hex(pk.slice(pk.length - last), ' ')}  ✓ strip them`, 'math good'], [`damaged: … ${U.hex(bad.slice(bad.length - Math.max(2, Math.min(last, 4))), ' ')}  ✗ bad padding`, 'math hot'], ['a server that says “bad padding” out loud is a padding oracle', 'tick']])], hl: { d: [1] }, say: `To remove it, read the last byte, ${U.h2(last)}, and check that the last ${U.plural(last, 'byte')} all ${last === 1 ? 'holds' : 'hold'} it. If a byte is wrong, as in ${U.hex(bad.slice(bad.length - Math.max(2, Math.min(last, 4))))}, the padding is ${badOk ? 'still accepted' : 'rejected'}. Telling an attacker which of the two happened is exactly the padding-oracle leak.`, facts: { last, bad: bad.slice(bad.length - Math.max(2, Math.min(last, 4))) }, meta: { stage: 'check', badOk } });
    F.add({ items: [...rows('pd:', iso, isoCls), ...panel('ISO/IEC 7816-4', [['add one byte 80 (a single 1 bit), then 00 bytes to the end of the block', 'math'], [`here: 80 and ${U.plural(iso.length - L - 1, 'byte')} of 00`, 'math'], ['to remove it: drop trailing 00 bytes, then the 80', ''], ['the same as the bit padding 1 0 0 … 0 used by hash functions', 'tick']])], hl: { d: [2] }, say: `ISO/IEC 7816-4 padding marks the end with a single 1 bit: the byte 80, then ${U.plural(iso.length - L - 1, 'byte')} of 00. The receiver strips trailing zeros and then the 80.`, facts: { z: iso.length - L - 1 }, meta: { stage: 'iso' } });
    // ciphertext stealing: no padding at all
    if (d && L > 16) {
      const key = U.key(inp.key), iv = U.block(inp.iv), E = S.AES.cipher(key);
      const zp = new Uint8Array(Math.ceil(L / 16) * 16); zp.set(msg);
      const cb = M.encrypt('cbc', E, zp, { iv, trace: false }).out, out = M.cts(E, msg, iv, { variant: inp.variant }).out, m = zp.length / 16;
      const swap = inp.variant === 'CS3' || inp.variant === 'CS2';
      const cbCls = (i) => (i >= 16 * (m - 2) + d && i < 16 * (m - 1) ? 'soft' : i >= 16 * (m - 2) && i < 16 * (m - 1) ? 'key' : i >= 16 * (m - 1) ? 'act' : '');
      const sb = (i) => K6().sub(i);
      F.add({ items: [...rows('pd:', cb, cbCls, 0, (r) => 'C' + sb(r + 1) + (r === m - 2 ? `: first ${d} bytes kept` : '')), ...panel('ciphertext stealing: CBC on the zero-filled message', [[`C${K6().sub(m - 1)}: only its first ${d} bytes are sent`, 'key'], [`its other ${U.plural(16 - d, 'byte')} ${16 - d === 1 ? 'is' : 'are'} not needed: decrypting C${K6().sub(m)} rebuilds ${16 - d === 1 ? 'it' : 'them'}`, ''], [`C${K6().sub(m)}: sent in full`, 'act']])], hl: { d: [3] }, say: `Ciphertext stealing avoids padding. Fill the last block with zeros and run CBC: C${K6().sub(m - 1)} = ${U.hex(cb.slice(16 * (m - 2), 16 * (m - 1)))}. Only its first ${d} bytes, ${U.hex(cb.slice(16 * (m - 2), 16 * (m - 2) + d))}, are sent; the receiver gets the rest back when it decrypts the last block.`, facts: { d, c: cb.slice(16 * (m - 2), 16 * (m - 1)), head: cb.slice(16 * (m - 2), 16 * (m - 2) + d), m: m - 1, mm: m, rest: 16 - d }, meta: { stage: 'cts1' } });
      const outCls = (i) => { const b = 16 * (m - 2); if (i < b) return ''; return (swap ? i < b + 16 : i >= b + d) ? 'act' : 'key'; };
      const outTitle = (r) => (r < m - 2 ? 'C' + sb(r + 1) : r === m - 2 ? (swap ? `C${sb(m)}, in full` : `C${sb(m - 1)}, first ${d} bytes`) : swap ? `C${sb(m - 1)}, first ${d} bytes` : `C${sb(m)}, in full`);
      F.add({ items: [...rows('pd:', out, outCls, 0, outTitle), ...panel(`${inp.variant}: the ciphertext, ${L} bytes`, [[swap ? 'the full last block goes first, then the stolen short one' : 'the short block keeps its place, the full last block follows', ''], ['CS1: never swap · CS2: swap only when the last block is short · CS3: always swap', 'tick'], [`ciphertext: ${L} bytes, as long as the message`, 'strong']])], hl: { d: [3] }, say: `${inp.variant} ${swap ? 'puts the full last block before the short one' : 'keeps the order'}. The ciphertext is ${K6().hexb(out)}: ${L} bytes, exactly as long as the message.`, facts: { L, C: out, Cb: K6().blocks(out) }, meta: { stage: 'cts2' } });
    } else F.add({ items: [...rows('pd:', msg, msgCls), ...panel('ciphertext stealing', [[L <= 16 ? 'needs more than one block of message' : 'not needed: the message ends on a block boundary', ''], ['otherwise the ciphertext keeps the length of the message', 'tick']])], say: L <= 16 ? 'Ciphertext stealing borrows from the block before the last, so it needs a message longer than one block.' : 'With a message that ends on a block boundary, ciphertext stealing has nothing to do: plain CBC is already the right length.', facts: {}, meta: { stage: 'cts0' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Padding', ['PKCS#7: append k bytes of value k, k = 16 − (len mod 16) ∈ 1 … 16', 'ISO 7816-4: append 80, then 00 bytes to the block boundary', 'CTS: CBC with the last block zero-filled; send only the first d bytes of Cₘ₋₁', 'CS1 keeps the order; CS2 swaps when the last block is short; CS3 always swaps']) };
  }
  S.topic({
    id: 'modes-padding', family: 'p06-use', order: 10, title: 'Padding and ciphertext stealing',
    blurb: 'Block modes like ECB and CBC need whole blocks. PKCS#7 and ISO 7816-4 pad the message in ways that can be undone; ciphertext stealing borrows bytes so the ciphertext keeps the message length.',
    inputs: [K6().msgInput('Three gulls on the harbour rail', 40, 17), K6().keyInput(), K6().ivInput(),
      { id: 'variant', kind: 'choice', label: 'Stealing variant', def: 'CS3', options: ['CS1', 'CS2', 'CS3'].map((v) => ({ value: v, label: v })) }],
    presets: [
      { label: '31 bytes: one byte short', values: { msg: 'Three gulls on the harbour rail', variant: 'CS3' } },
      { label: '32 bytes: a whole block of padding', values: { msg: 'Two whole blocks of text, no gap', variant: 'CS3' } },
      { label: '17 bytes: fifteen bytes of padding', values: { msg: 'Seventeen letters', variant: 'CS1' } },
      { label: 'Stealing with CS2', values: { msg: 'Three gulls on the harbour rail', variant: 'CS2' } },
    ],
    run: padding,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'msg', pick: 'option', options: (fr, i) => [...new Set(['01', '0f', '10', U.h2(16 - fr[i].facts.d || 16)])].sort(), ask: 'Which byte value will PKCS#7 use to pad this message?', answer: (fr, i) => U.h2(16 - (fr[i].facts.d || 0) || 16), explain: (fr, i) => `16 − (${fr[i].facts.L} mod 16) = ${16 - (fr[i].facts.d || 0)}, so every padding byte is ${U.h2(16 - (fr[i].facts.d || 0) || 16)}.` }],
    quiz: [
      { q: 'A message is exactly 32 bytes long. How many PKCS#7 padding bytes are added?', options: ['0', '1', '16', '32'], answer: 2, why: 'A whole block of 10s, so the receiver can always strip the last byte\'s count.' },
      { q: 'Which padding ends with the bytes 80 00 00?', options: ['PKCS#7', 'ISO/IEC 7816-4', 'Ciphertext stealing', 'None'], answer: 1, why: 'A 1 bit then zeros.' },
      { q: 'What does ciphertext stealing achieve?', options: ['Authentication', 'A ciphertext as long as the plaintext, with no padding', 'Faster encryption', 'A shorter key'], answer: 1, why: 'Part of the next-to-last block is left out and recomputed by the receiver.' },
      { q: 'Why is a server that reports padding errors dangerous?', options: ['It leaks the key length', 'It is a padding oracle: its answers let an attacker decrypt CBC byte by byte', 'It wastes time', 'It is not dangerous'], answer: 1, why: 'Each yes/no answer reveals whether a guessed byte made valid padding.' },
    ],
  });

  // ---- key length and block size --------------------------------------------------------------------------------
  const L2 = Math.log10(2), YEAR = 365.25 * 86400;
  /** a time given as log10 of seconds, in words */
  const human = (ls) => {
    if (ls < 0) return 'under a second';
    const s = 10 ** ls;
    if (s < 60) return `${Math.round(s)} seconds`;
    if (s < 3600) return `${Math.round(s / 60)} minutes`;
    if (s < 86400) return `${Math.round(s / 3600)} hours`;
    if (s < YEAR) return `${Math.round(s / 86400)} days`;
    const ly = ls - Math.log10(YEAR);
    if (ly < 6) return `${Math.round(10 ** ly).toLocaleString('en-US')} years`;
    return `10^${Math.floor(ly)} years`;
  };
  const CIPHERS = [['40-bit export key', 40], ['DES', 56], ['64-bit key', 64], ['80-bit key', 80], ['3DES (112 effective)', 112], ['AES-128', 128], ['AES-256', 256]];
  function keysearch(inp) {
    const rate = inp.rate, mach = inp.machines, F = new S.Frames(), lr = rate + mach;
    // expected time: half the key space at 10^rate keys per second on 10^machines machines
    const rows = CIPHERS.map(([name, bits]) => { const ls = (bits - 1) * L2 - lr; return { name, bits, ls: Math.round(ls * 100) / 100, t: human(ls) }; });
    const lo = Math.floor(Math.min(-2, ...rows.map((r) => r.ls)) - 1), hi = Math.ceil(Math.max(20, ...rows.map((r) => r.ls)) + 6), X0 = 250, X1 = 830, X = (v) => U.r2(X0 + ((Math.max(lo, Math.min(hi, v)) - lo) / (hi - lo)) * (X1 - X0));
    const refs = [[0, '1 s'], [Math.log10(YEAR), '1 year'], [Math.log10(YEAR * 1.38e10), 'age of the universe']];
    const chart = (lit) => {
      const items = [U.t('ks:t', 40, 40, `expected time to find a key: 10^${rate} keys a second on 10^${mach} machines`, 'title')];
      const yb = 80 + CIPHERS.length * 52;
      refs.forEach(([v, l], k) => { items.push({ key: 'ks:r' + k, kind: 'line', x1: X(v), y1: 74, x2: X(v), y2: yb + 8 + k * 22, cls: 'dash', audit: 'ignore', layer: 'back' }); items.push(U.t('ks:rl' + k, X(v) + 6, yb + 12 + k * 22, l, 'tick', 'start', 13)); });
      items.push({ key: 'ks:axl', kind: 'line', x1: X0, y1: yb + 80, x2: X1, y2: yb + 80, cls: 'rule', audit: 'ignore', layer: 'back' });
      for (let v = Math.ceil(lo / 10) * 10; v <= hi; v += 10) { items.push({ key: 'ks:tk' + v, kind: 'line', x1: X(v), y1: yb + 76, x2: X(v), y2: yb + 84, cls: 'rule', audit: 'ignore' }); items.push(U.t('ks:t:' + v, X(v), yb + 102, '10^' + v + ' s', 'tick', 'middle', 13)); }
      rows.forEach((r, i) => {
        const y = 86 + i * 52, on = lit.includes(r.bits);
        items.push(U.t('ks:n' + i, 40, y + 20, r.name, on ? 'act' : 'strong', 'start', 15));
        items.push({ key: 'ks:b' + i, kind: 'cell', x: X0, y, w: Math.max(2, X(r.ls) - X0), h: 26, rx: 3, text: '', cls: 'bar ' + (on ? 'act' : r.ls > Math.log10(YEAR * 1.38e10) ? 'good' : r.ls > Math.log10(YEAR) ? 'soft' : 'bad') });
        const lx = X(r.ls) + 8, inside = lx > X1 - 120;
        items.push(U.t('ks:v' + i, inside ? X(r.ls) - 8 : lx, y + 19, r.t, inside ? 'strong' : 'tick', inside ? 'end' : 'start', 14));
      });
      return items;
    };
    const byBits = (b) => rows.find((r) => r.bits === b), num = (t) => +String(t).replace(/\D/g, '');
    F.add({ items: chart([]), say: `Searching half of a key space of 2^n keys takes 2^(n−1) trials. At 10^${rate} keys a second on 10^${mach} machines, the bars show the expected time for each key length, on a scale of powers of ten.`, facts: { rate, mach }, meta: { stage: 'all' } });
    F.add({ items: chart([40, 56]), say: `A 40-bit key falls in ${byBits(40).t}, and DES's 56 bits in ${byBits(56).t}. A dedicated machine found a DES key in a few days as early as 1998, which is why DES was retired.`, facts: { a: byBits(40).t, b: byBits(56).t, an: num(byBits(40).t), bn: num(byBits(56).t), y: 1998 }, meta: { stage: 'des' } });
    F.add({ items: chart([112]), say: `Double DES would give only 57 bits of work against meet-in-the-middle, at the cost of a large table; triple DES with two or three keys keeps about 112 bits: ${byBits(112).t}.`, facts: { t: byBits(112).t, tn: num(byBits(112).t), w: 57, b: 112 }, meta: { stage: '3des' } });
    F.add({ items: chart([128, 256]), say: `AES-128 needs ${byBits(128).t}, AES-256 ${byBits(256).t}. Each extra bit doubles the work, so no improvement in hardware closes that gap; even a quantum computer running Grover's search only halves the exponent, leaving AES-256 at 128 bits.`, facts: { a: byBits(128).t, b: byBits(256).t, an: num(byBits(128).t), bn: num(byBits(256).t), q: 128 }, meta: { stage: 'aes' } });
    // the birthday bound: q blocks under one key repeat a ciphertext block with chance about 1 − e^(−q²/2^(n+1))
    const bs = +inp.block, bb = bs / 8;
    const chance = (n, lgBytes) => { const lq = lgBytes - Math.log2(n / 8); return 1 - Math.exp(-(2 ** (2 * lq - n - 1))); };
    const PX0 = 90, PX1 = 820, PY0 = 120, PY1 = 470, gx = (lg) => U.r2(PX0 + ((lg - 20) / 60) * (PX1 - PX0)), gy = (p) => U.r2(PY1 - p * (PY1 - PY0));
    const half = 0.5 * (bs + 1) + 0.5 * Math.log2(Math.log(2)) + Math.log2(bb);
    const plot = (lit) => {
      const items = [U.t('bd:t', 40, 40, 'chance that two ciphertext blocks repeat, by data encrypted under one key', 'title')];
      items.push({ key: 'bd:ax', kind: 'path', d: `M${PX0},${PY0} V${PY1} H${PX1}`, cls: 'axis', audit: 'ignore', layer: 'back', box: { x: PX0, y: PY0, w: PX1 - PX0, h: PY1 - PY0 } });
      [[30, '1 GiB'], [40, '1 TiB'], [50, '1 PiB'], [60, '1 EiB'], [70, '1 ZiB']].forEach(([lg, l], k) => items.push(U.t('bd:x' + k, gx(lg), PY1 + 22, l, 'tick', 'middle', 13)));
      [[0, '0'], [0.5, '½'], [1, '1']].forEach(([p, l], k) => items.push(U.t('bd:y' + k, PX0 - 10, gy(p) + 5, l, 'tick', 'end', 13)));
      for (const n of [64, 128]) {
        let d = '';
        for (let lg = 20; lg <= 80; lg += 0.25) d += (d ? 'L' : 'M') + gx(lg) + ',' + gy(chance(n, lg)) + ' ';
        items.push({ key: 'bd:c' + n, kind: 'path', d, cls: 'dline ' + (n === bs ? 'hot' : 'act'), pathAudit: 'edge-x' });
        const l50 = 0.5 * (n + 1) + 0.5 * Math.log2(Math.log(2)) + Math.log2(n / 8);
        items.push(U.t('bd:l' + n, n === 128 ? gx(l50) - 14 : gx(l50) + 14, gy(0.5) + 5, `${n}-bit blocks`, n === bs ? 'hot' : 'act', n === 128 ? 'end' : 'start', 14));
      }
      if (lit) items.push({ key: 'bd:pt', kind: 'dot', x: gx(half), y: gy(0.5), r: 6, cls: 'hot', point: true });
      return items;
    };
    const p32 = chance(64, 35), gib = 2 ** (half - 30);
    F.add({ items: plot(false), say: `The block size sets a second limit. Under one key, q ciphertext blocks of n bits repeat a block with chance about 1 − e^(−q²/2^(n+1)): after about 2^(n/2) blocks, a repeat is likely, and in CBC a repeat leaks the XOR of two plaintext blocks.`, facts: {}, meta: { stage: 'bday' } });
    F.add({ items: plot(true), say: `For ${bs}-bit blocks the chance passes one half after ${bs === 64 ? `about ${Math.round(gib)} GiB` : `about 2^${Math.round(half - 60)} EiB`}. ${bs === 64 ? `With 64-bit blocks, as in 3DES, 32 GiB (2^32 blocks) already gives a chance of ${p32.toFixed(2)}: a long session leaks, the Sweet32 attack.` : 'With 128-bit blocks that amount of data is far beyond any real session, though keys are still changed long before it.'}`, facts: { bs, gib: Math.round(gib), e: Math.round(half - 60), p32: +p32.toFixed(2), g: 32 }, meta: { stage: 'half' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Key and block sizes', ['exhaustive search: 2ⁿ⁻¹ trials on average for an n-bit key', 'time = 2ⁿ⁻¹ / (keys per second × machines)', 'Grover: about 2^(n/2) quantum steps', 'birthday bound: P(repeat) ≈ 1 − e^(−q²/2^(b+1)) for q blocks of b bits', 'rekey well before 2^(b/2) blocks']) };
  }
  S.topic({
    id: 'modes-keysearch', family: 'p06-use', order: 20, title: 'Key length, block size and their limits',
    blurb: 'Exhaustive search grows by a factor of two per key bit, so 56-bit DES fell and AES-128 stands. The block size sets a separate limit: after about 2^(n/2) blocks under one key, blocks start to repeat.',
    inputs: [
      { id: 'rate', kind: 'number', label: 'Keys per second per machine (a power of 10)', def: 12, min: 3, max: 18 },
      { id: 'machines', kind: 'number', label: 'Machines (a power of 10)', def: 6, min: 0, max: 12 },
      { id: 'block', kind: 'choice', label: 'Block size for the birthday bound', def: '64', options: [{ value: '64', label: '64 bits (DES, 3DES)' }, { value: '128', label: '128 bits (AES)' }] },
    ],
    presets: [
      { label: 'A million fast chips, 64-bit blocks', values: { rate: 12, machines: 6, block: '64' } },
      { label: 'One ordinary computer', values: { rate: 7, machines: 0, block: '64' } },
      { label: 'Far beyond any real budget', values: { rate: 18, machines: 12, block: '128' } },
      { label: '128-bit blocks', values: { rate: 12, machines: 6, block: '128' } },
    ],
    run: keysearch,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'all', pick: 'option', options: ['twice as long', '10 times as long', 'a million times as long'], ask: 'How much longer does a 57-bit key take to search than a 56-bit key?', answer: 'twice as long', explain: 'One more bit doubles the number of keys.' }],
    quiz: [
      { q: 'How many trials does exhaustive search of a 128-bit key need on average?', options: ['2⁶⁴', '2¹²⁷', '2¹²⁸', '128²'], answer: 1, why: 'Half the key space.' },
      { q: 'Why does 3DES give about 112 bits of security, not 168?', options: ['Its keys are shorter', 'Meet-in-the-middle cuts the work of three keys to about two', 'DES has weak keys', 'It uses 64-bit blocks'], answer: 1, why: 'A table of the middle values trades memory for one layer of search.' },
      { q: 'Roughly how much data under one key makes a repeated 64-bit block likely?', options: ['32 KiB', '32 MiB', '32 GiB', '32 PiB'], answer: 2, why: '2³² blocks of 8 bytes is 32 GiB.' },
      { q: 'What does Grover\'s algorithm do to AES-256?', options: ['Breaks it', 'Leaves about 128 bits of security', 'Nothing', 'Halves the block size'], answer: 1, why: 'It searches 2ⁿ keys in about 2^(n/2) steps.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
