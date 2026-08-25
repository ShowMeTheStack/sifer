// Part 6, XTS, the mode for disk sectors (IEEE 1619, NIST SP 800-38E): two AES keys; the sector number encrypted
// under the second gives T, and block j of the sector uses T·αʲ before and after the first key's cipher. A sector
// that does not end on a block boundary borrows bytes from the block before: ciphertext stealing.
(function (S) {
  'use strict';
  const U = S.P5, K6 = () => S.Kit.p06, Fl = () => S.Kit.flow;
  const sub = (n) => K6().sub(n);
  const dataOf = (v) => { const t = String(v), h = t.replace(/\s+/g, ''); return /^([0-9a-fA-F]{2}){16,}$/.test(h) && h.length >= 32 ? S.bytes.fromHex(h) : S.bytes.utf8(t); };
  const keyOf = (v) => { const t = String(v), h = t.replace(/\s+/g, ''); if (/^[0-9a-fA-F]{64}$/.test(h) || /^[0-9a-fA-F]{128}$/.test(h)) return S.bytes.fromHex(h); const b = S.bytes.utf8(t); return b.length === 32 || b.length === 64 ? b : null; };

  function xts(inp) {
    const key = keyOf(inp.key), data = dataOf(inp.data), sector = inp.sector, h = key.length / 2;
    const res = S.XTS.encrypt(key, sector, data), steps = res.trace.filter((t) => t.kind === 'xts-block'), tw = S.XTS.tweakBlock(sector);
    const T0 = res.trace[0].T, n = steps.length, d = data.length % 16, CX = n >= 3 ? [190, 450, 710] : [250, 560];
    const F = new S.Frames(), box = (...a) => K6().box(...a);
    const yP = 100, yA = 190, yE = 270, yB = 350, yC = 440, yT = 560;
    const build = (blk, stage, o) => {
      o = o || {};
      const N = Fl().net('xts'), later = [];
      box(N, 'tw', 55, 210, 'sector', tw, 'key' + (blk === -1 && stage === 1 ? ' act' : ''), { quad: true, w: 96 });
      N.box('K2', 55, 330, 80, 44, 'AES K₂', 'cipher' + (blk === -1 && stage === 1 ? ' act' : ''));
      N.wire('twE', [N.port('tw', 's'), N.port('K2', 'n')], { head: true, cls: blk === -1 && stage === 1 ? 'act' : '' });
      steps.forEach((st, j) => {
        const x = CX[j], cur = j === blk, done = o.all || j < blk || (cur && stage >= 2), tOn = o.all || j <= blk || (blk === -1 && stage === 1 && j === 0);
        const stolen = d && j === n - 1;
        box(N, 'P' + j, x, yP, stolen ? `P${sub(j + 1)} ‖ ${U.plural(16 - d, 'borrowed byte')}` : 'P' + sub(j + 1), st.in, cur && stage === 0 ? 'act' : stolen ? 'key' : '');
        N.op('a' + j, x, yA, 'xor', cur && stage === 0 ? 'act' : '');
        N.box('E' + j, x, yE, 104, 46, 'AES K₁', 'cipher' + (cur && stage === 1 ? ' act' : ''));
        N.op('b' + j, x, yB, 'xor', cur && stage === 2 ? 'act' : '');
        box(N, 'C' + j, x, yC, 'out ' + (j + 1), done ? st.out : null, done ? (cur ? 'hot' : '') : 'soft');
        box(N, 'T' + j, x + 110, yT, 'T·α' + U.sup(j), tOn ? st.T : null, 'key' + (cur && stage === 0 ? ' act' : '') + (tOn ? '' : ' soft'), { quad: true });
        const a = (k) => (cur && stage === k ? 'act' : '');
        N.wire('pa' + j, [N.port('P' + j, 's'), N.port('a' + j, 'n')], { head: true, cls: a(0) });
        N.wire('ae' + j, [N.port('a' + j, 's'), N.port('E' + j, 'n')], { head: true, cls: a(1) });
        N.wire('eb' + j, [N.port('E' + j, 's'), N.port('b' + j, 'n')], { head: true, cls: a(2) });
        N.wire('bc' + j, [N.port('b' + j, 's'), N.port('C' + j, 'n')], { head: true, cls: a(2) });
        // the tweak of this block goes up its own wire to both XORs
        N.wire('tu' + j, [N.port('T' + j, 'n'), [x + 110, yA], N.port('a' + j, 'e')], { head: true, cls: 'key' });
        N.dot(x + 110, yB, 'key');
        N.wire('tb' + j, [[x + 110, yB], N.port('b' + j, 'e')], { head: true, cls: 'key' });
        if (j < n - 1) later.push(() => { N.wire('al' + j, [N.port('T' + j, 'e'), N.port('T' + (j + 1), 'w')], { head: true, cls: 'key' }); N.label('all' + j, (x + 162 + CX[j + 1] + 58) / 2, yT - 10, '·α', 'key', 'middle', 15); });
      });
      later.forEach((f) => f());
      N.wire('E2T', [N.port('K2', 's'), [55, yT], N.port('T0', 'w')], { head: true, cls: 'key' + (blk === -1 && stage === 1 ? ' act' : '') });
      return N.items;
    };
    F.add({ items: build(-2, 0), say: `A disk sector of ${data.length} bytes, sector number ${sector}. XTS uses two AES keys: K₁ = ${U.hex(key.slice(0, h))} encrypts the data, K₂ = ${U.hex(key.slice(h))} encrypts the sector number. There is no IV to store: the position on the disk is the tweak.`, facts: { len: data.length, sector, k1: key.slice(0, h), k2: key.slice(h) }, meta: { stage: 'start' } });
    F.add({ items: build(-1, 1), hl: { d: [0] }, say: `The sector number as 16 bytes, least significant first, is ${U.hex(tw)}. Encrypted with AES under K₂ it gives T = ${U.hex(T0)}.`, facts: { tw, T: T0 }, meta: { stage: 'tweak' } });
    steps.forEach((st, j) => {
      const nv = K6().follow(CX[j] + 40);
      if (j) F.add({ items: build(j, 0), narrowView: nv, hl: { d: [1] }, say: `Block ${j + 1} uses T·α${j > 1 ? '^' + j : ''}: multiplying by α shifts the 128-bit value one bit up${steps[j - 1].T[15] & 0x80 ? ', and since a bit fell off the top, 87 is XORed into the first byte' : ''}. ${U.hex(steps[j - 1].T)} becomes ${U.hex(st.T)}.`, facts: { j, b: j + 1, prev: steps[j - 1].T, T: st.T }, meta: { stage: 'alpha', j } });
      F.add({ items: build(j, 1), narrowView: nv, hl: { d: [2] }, say: `Block ${j + 1}: ${U.hex(st.in)} ⊕ ${U.hex(st.T)} = ${U.hex(st.pp)}, and AES under K₁ makes that ${U.hex(st.cc)}.`, facts: { j: j + 1, p: st.in, T: st.T, pp: st.pp, cc: st.cc }, meta: { stage: 'enc', j } });
      F.add({ items: build(j, 2), narrowView: nv, hl: { d: [2] }, say: `XOR the same T·α${j > 1 ? '^' + j : ''} again: ${U.hex(st.cc)} ⊕ ${U.hex(st.T)} = ${U.hex(st.out)}.`, facts: { cc: st.cc, T: st.T, c: st.out }, meta: { stage: 'out', j } });
    });
    if (d) {
      const prev = steps[n - 2].out;
      F.add({ items: build(n, 2, { all: true }), hl: { d: [3] }, say: `The sector ends with ${d} bytes, not a whole block. Ciphertext stealing: block ${n - 1}'s result ${U.hex(prev)} gives its first ${d} bytes, ${U.hex(prev.slice(0, d))}, as the short last block of ciphertext; its other ${U.plural(16 - d, 'byte')} ${16 - d === 1 ? 'was' : 'were'} borrowed to fill the last plaintext block, which was encrypted in its place. The ciphertext is ${K6().hexb(res.out)}, exactly ${data.length} bytes.`, facts: { d, prev, head: prev.slice(0, d), borrow: 16 - d, C: res.out, Cb: K6().blocks(res.out), len: data.length, m: n - 1 }, meta: { stage: 'steal' } });
    } else F.add({ items: build(n, 2, { all: true }), hl: { d: [2] }, say: `The sector's ciphertext is ${K6().hexb(res.out)}, the same length as the data. The same plaintext at another sector number gives a different ciphertext, yet each block can be read or rewritten on its own.`, facts: { C: res.out, Cb: K6().blocks(res.out) }, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('XTS-AES', ['T = E_K₂(sector number, 16 bytes little-endian)', 'Tⱼ = T·αʲ in GF(2¹²⁸):  shift left 1 bit, ⊕ 87 if a bit falls off', 'Cⱼ = E_K₁(Pⱼ ⊕ Tⱼ) ⊕ Tⱼ', 'a short last block steals bytes from the one before']) };
  }
  S.topic({
    id: 'modes-xts', family: 'p06-modes', order: 60, title: 'XTS: encrypting a disk sector',
    blurb: 'Disk encryption has no room for an IV, so the sector number becomes a tweak: encrypted under a second key and multiplied by α for each block, it is XORed in before and after the cipher.',
    inputs: [
      { id: 'data', kind: 'text', label: 'Sector data (32 to 48 characters, or hex)', def: 'Shelf 9 holds the tide tables and two old maps.', check: (v) => { const n = dataOf(v).length; return n < 32 ? 'Sector data: at least 32 bytes' : n > 48 ? 'Sector data: at most 48 bytes, so it fits the picture' : null; } },
      { id: 'key', kind: 'text', label: 'Two keys (32 characters, or 64 or 128 hex digits)', def: 'ochre-river-2026saffron-harbour9', check: (v) => (keyOf(v) ? null : 'Keys: 32 characters, or 64 or 128 hex digits (K₁ then K₂)') },
      { id: 'sector', kind: 'number', label: 'Sector number', def: 7, min: 0, max: 1e12 },
    ],
    presets: [
      { label: 'Sector 7, a short last block', values: { data: 'Shelf 9 holds the tide tables and two old maps.', sector: 7 } },
      { label: 'The same data in sector 8', values: { data: 'Shelf 9 holds the tide tables and two old maps.', sector: 8 } },
      { label: 'Two whole blocks', values: { data: 'Shelf 9 holds tide tables, maps.', sector: 3 } },
      { label: 'IEEE 1619 vector 2', values: { data: '4444444444444444444444444444444444444444444444444444444444444444', key: '11111111111111111111111111111111' + '22222222222222222222222222222222', sector: 219902325555 } },
    ],
    run: xts,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'tweak', pick: 'option', options: ['the same', 'different'], ask: 'If the same data were written to the next sector, would its ciphertext be the same or different?', answer: 'different', explain: 'The sector number changes T, and with it every block\'s ciphertext.' }],
    quiz: [
      { q: 'Why does XTS use the sector number instead of a random IV?', options: ['It is faster', 'A disk has no spare room to store an IV per sector, and the position is always known', 'Random IVs are insecure', 'For compression'], answer: 1, why: 'Ciphertext must fit exactly where the plaintext was.' },
      { q: 'What does multiplying by α do to the tweak?', options: ['Adds 1', 'Shifts it one bit, reducing modulo the field polynomial', 'Encrypts it', 'Reverses its bytes'], answer: 1, why: 'Doubling in GF(2¹²⁸) gives each block of the sector its own tweak cheaply.' },
      { q: 'What does XTS not protect against?', options: ['Reading the disk', 'An attacker who puts back an older copy of a sector', 'Seeing which sectors are equal after re-encryption', 'Both of the last two'], answer: 3, why: 'XTS is deterministic per sector and has no authentication tag.' },
      { q: 'How long is the ciphertext of a 40-byte sector?', options: ['40 bytes', '48 bytes', '56 bytes', '64 bytes'], answer: 0, why: 'Ciphertext stealing keeps the length.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
