// Part 4, DES continued: the key schedule (PC-1, rotations whose bits glide round the C and D registers, PC-2),
// decryption as the same ladder with the round keys reversed, and the avalanche of one flipped bit over sixteen
// rounds as a heat map.
(function (S) {
  'use strict';
  const U = S.SymT, D4 = S.P04D, r2 = U.r2, sub = U.sub;
  const DES = () => S.DES;
  const hx = (bits) => S.DES.hex(bits);
  const a = (s) => U.hex(U.bytesOf(s));

  // ---------------------------------------------------------------------------------------------------------------
  // The key schedule
  // ---------------------------------------------------------------------------------------------------------------
  function keys(inp) {
    const K = D4.bytes(inp.key), kb = DES().bits(K), ks = DES().keySchedule(K), PC1 = DES().PC1, PC2 = DES().PC2, SH = DES().SHIFTS;
    const F = new S.Frames(), gx = 30, gy = 92, gc = 20, gg = 2, rx = 290, cw = 20, cgap = 2, yC = 92, yD = 150, yK = 316;
    const unused = new Set(Array.from({ length: 56 }, (_, i) => i).filter((i) => !PC2.includes(i + 1)));
    const head = U.head('ks:h', 'The key schedule: PC-1, rotations, PC-2');
    const grid = (dim) => {
      const it = [U.t('ks:gt', gx, gy - 14, 'key, byte per row', 'title', 'start', 14)];
      for (let p = 0; p < 64; p++) {
        const par = p % 8 === 7;
        it.push({ key: 'ks:g' + p, kind: 'cell', x: gx + (p % 8) * (gc + gg), y: gy + Math.floor(p / 8) * (gc + gg), w: gc, h: gc, rx: 2, text: String(kb[p]), size: 13, cls: 'bit ' + (kb[p] ? 'one' : 'zero') + (par ? ' soft' : dim ? '' : ' key') });
      }
      it.push(U.t('ks:gp', gx, gy + 8 * (gc + gg) + 16, 'last column: parity', 'tick', 'start', 13));
      return it;
    };
    // C and D after `tot` rotations; a cell is keyed by the key bit it holds, so rotations glide
    const regs = (tot, litPick, round) => {
      const it = [];
      [['C', yC, 0], ['D', yD, 28]].forEach(([nm, y, o]) => {
        const vals = Array.from({ length: 28 }, (_, j) => kb[PC1[o + (j + tot) % 28] - 1]);
        it.push(U.t('ks:n' + nm, 222, y + 8, nm + sub(round === undefined ? 0 : round), 'strong', 'start', 16));
        it.push(U.t('ks:x' + nm, 222, y + 30, hx(vals), 'mono', 'start', 13));
        for (let j = 0; j < 28; j++) {
          const src = PC1[o + (j + tot) % 28] - 1, gone = litPick && unused.has(o + j);
          it.push({ key: 'ks:r' + src, kind: 'cell', x: rx + j * (cw + cgap), y, w: cw, h: 24, rx: 2, text: String(vals[j]), size: 13, cls: 'bit ' + (vals[j] ? 'one' : 'zero') + (gone ? ' soft' : litPick ? ' key' : ''), enter: 'from', src: 'ks:g' + src });
        }
      });
      return it;
    };
    const kRow = (K48, n) => [...D4.rowLabel('ks:k', yK, 'K' + sub(n), hx(K48), 'key'), ...D4.bits({ prefix: 'ks:kb', x: 130, y: yK, bits: K48, cw: 13, ch: 20, gap: 2, group: 6, groupGap: 8, cls: () => 'key' }).items];
    const list = (upto, lit) => {
      const it = [U.t('ks:lt', 30, 386, 'round keys so far', 'title', 'start', 14)];
      for (let i = 0; i < upto; i++) {
        const x = i < 8 ? 30 : 476, y = 416 + (i % 8) * 28;
        it.push(U.t('ks:li' + i, x, y, 'K' + sub(i + 1), i === lit ? 'key' : 'strong', 'start', 15));
        it.push(U.t('ks:lv' + i, x + 44, y, hx(ks.keys[i].K), 'mono' + (i === lit ? ' key' : ''), 'start', 15));
        it.push(U.t('ks:ls' + i, x + 186, y, '⟲' + SH[i], 'tick', 'start', 13));
      }
      return it;
    };
    const C0 = hx(ks.keys[0].C.slice(-1).concat(ks.keys[0].C.slice(0, -1))), D0 = hx(ks.keys[0].D.slice(-1).concat(ks.keys[0].D.slice(0, -1)));
    F.add({ items: [head, ...grid(false)], say: `The key ${U.hex(K)} as eight rows of eight bits. The last bit of every byte is a parity bit: it takes no part in encryption, which leaves 56 key bits.`, facts: { K: U.hex(K) }, meta: { stage: 'key' } });
    F.add({ items: [head, ...grid(true), ...regs(0)], hl: { d: [0] }, say: `PC-1 drops the 8 parity bits and sorts the other 56 into two 28-bit registers: C₀ = ${C0} and D₀ = ${D0}. Watch each bit fly from the key to its place.`, facts: { C0, D0 }, meta: { stage: 'pc1' } });
    let tot = 0;
    for (let i = 0; i < 16; i++) {
      tot += SH[i];
      const k = ks.keys[i], Kh = hx(k.K);
      F.add({ items: [head, ...grid(true), ...regs(tot, true, i + 1), U.t('ks:rot', rx, 204, '⟲ both rotate left by ' + SH[i] + ' (' + tot + ' so far); PC-2 skips the faded cells', 'act', 'start', 14), ...kRow(k.K, i + 1), ...list(i + 1, i)], hl: { d: [1, 2] },
        say: `Round ${i + 1}: C and D each rotate left by ${SH[i]} (${tot} places so far), to C${sub(i + 1)} = ${hx(k.C)} and D${sub(i + 1)} = ${hx(k.D)}. PC-2 picks 48 of their 56 bits, leaving out the 8 faded ones: K${sub(i + 1)} = ${Kh}.` + (i === 0 ? ' Rounds 1, 2, 9 and 16 rotate by one, the others by two.' : ''),
        facts: { i: i + 1, s: SH[i], tot, C: hx(k.C), D: hx(k.D), K: Kh }, meta: { stage: 'round', i } });
    }
    const back = hx(ks.keys[15].C) === C0 && hx(ks.keys[15].D) === D0;
    F.add({ items: [head, ...grid(true), ...regs(28, false, 16), U.t('ks:rot', rx, 204, '28 places in all: C₁₆ = C₀ and D₁₆ = D₀', 'good', 'start', 14), ...list(16, -1)], hl: { d: [3] },
      say: `The shifts add up to ${tot}, a whole turn of each 28-bit register, so C₁₆ and D₁₆ ${back ? 'are C₀ and D₀ again' : 'differ from C₀ and D₀'}. Decryption can start from C₀ and D₀ and rotate right, producing K₁₆ … K₁ in order.`, facts: { tot, back }, meta: { stage: 'end' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 640 });
    return { frames: F.list, def: U.def('The key schedule', ['PC-1: 64 key bits → C₀, D₀ (28 bits each), parity dropped', 'Cᵢ = Cᵢ₋₁ ⋘ sᵢ,  Dᵢ = Dᵢ₋₁ ⋘ sᵢ', 's = 1 1 2 2 2 2 2 2 1 2 2 2 2 2 2 1 (sum 28)', 'Kᵢ = PC-2(Cᵢ Dᵢ): 48 of the 56 bits']) };
  }
  S.topic({
    id: 'des-keys', family: 'p04-des', order: 40, title: 'The key schedule: PC-1, rotations, PC-2',
    blurb: 'Fifty-six key bits sit in two 28-bit registers that rotate a place or two each round; PC-2 picks 48 of them as the round key. After sixteen rounds the registers are back where they began.',
    inputs: [D4.keyInp()],
    presets: [
      { label: '‘bramble7’', values: { key: a('bramble7') } },
      { label: '‘quill&in’', values: { key: a('quill&in') } },
      { label: 'SP 800-17: 80 01 01 … 01', values: { key: '8001010101010101' } },
      { label: 'All ones but parity: fe fe …', values: { key: 'fefefefefefefefe' } },
    ],
    run: keys,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'key', once: true, pick: 'option', options: ['4', '8', '16', '0'], ask: 'How many of the 64 key bits will PC-1 drop?', answer: '8', explain: 'One parity bit per byte: 64 − 8 = 56.' },
      { at: (f) => f.meta && f.meta.stage === 'round' && f.meta.i === 7, once: true, pick: 'option', options: ['1', '2', '3'], ask: 'Round 9 is next. By how many places will C and D rotate?', answer: '1', explain: 'Rounds 1, 2, 9 and 16 rotate by one place.' },
    ],
    quiz: [
      { q: 'How many bits does each round key have?', options: ['56', '48', '32', '64'], answer: 1, why: 'PC-2 picks 48 of the 56 bits in C and D.' },
      { q: 'What do the sixteen rotations add up to?', options: ['16', '24', '28', '32'], answer: 2, why: 'Four rotations of one and twelve of two: 28, a full turn of each register.' },
      { q: 'Why does a full turn help decryption?', options: ['It does not matter', 'Decryption can start from C₀ and D₀ and rotate right to get K₁₆ … K₁', 'It hides the parity bits', 'It doubles the key length'], answer: 1, why: 'Since C₁₆ = C₀, rotating right steps backwards through the round keys.' },
      { q: 'Which key bits never affect DES?', options: ['The first byte', 'The last bit of every byte', 'Bits 9, 18, 22 and 25', 'None'], answer: 1, why: 'Those are the parity bits; PC-1 drops them. (Bits 9, 18, 22, 25 of C are only skipped in some rounds.)' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Decryption
  // ---------------------------------------------------------------------------------------------------------------
  function decrypt(inp) {
    const P = D4.bytes(inp.pt), K = D4.bytes(inp.key), enc = DES().encrypt(P, K), C = enc.out, dec = DES().decrypt(C, K);
    const F = new S.Frames(), E = enc.rounds, Dr = dec.rounds;
    // the halves of encryption, by name: L₀, R₀, R₁ … R₁₆
    const names = [['L' + sub(0), hx(E[0].L)], ['R' + sub(0), hx(E[0].R)]].concat(E.map((r, i) => ['R' + sub(i + 1), hx(r.newR)]));
    void names;
    /** decryption round i (from 0) gives back R₁₄₋ᵢ, and L₀ at the end */
    const nameOf = (i) => (i < 15 ? 'R' + sub(14 - i) : 'L' + sub(0));
    const y0 = 128, dy = 27, xe = 40, xd = 470;
    const head = U.head('dd:h', 'Decryption: the same ladder, keys reversed');
    const table = (upto, lit) => {
      const it = [U.t('dd:et', xe, y0 - 40, 'encryption', 'title', 'start', 14), U.t('dd:dt', xd, y0 - 40, 'decryption, K₁₆ first', 'title', 'start', 14)];
      [['round', 0], ['key', 42], ['new half', 196]].forEach(([t, dx], k) => { it.push(U.t('dd:eh' + k, xe + dx, y0 - 14, t, 'tick', 'start', 13)); it.push(U.t('dd:dh' + k, xd + dx, y0 - 14, t, 'tick', 'start', 13)); });
      it.push(U.t('dd:dh3', xd + 300, y0 - 14, 'is', 'tick', 'start', 13));
      const hit = lit >= 0 ? nameOf(lit) : null;
      for (let i = 0; i < 16; i++) {
        const y = y0 + i * dy + 4, nm = 'R' + sub(i + 1), match = hit === nm;
        it.push(U.t('dd:ei' + i, xe + 10, y + 12, String(i + 1), 'tick', 'start', 13));
        it.push(U.t('dd:ek' + i, xe + 42, y + 12, 'K' + sub(i + 1) + ' ' + hx(E[i].K), 'mono key', 'start', 13));
        it.push({ key: 'dd:ev' + i, kind: 'cell', x: xe + 196, y, w: 150, h: 22, rx: 3, text: nm + ' ' + hx(E[i].newR), size: 13, cls: 'hex ' + (match ? 'hot' : '') });
        if (i >= upto) continue;
        const r = Dr[i], nm2 = nameOf(i);
        it.push(U.t('dd:di' + i, xd + 10, y + 12, String(i + 1), i === lit ? 'act' : 'tick', 'start', 13));
        it.push(U.t('dd:dk' + i, xd + 42, y + 12, 'K' + sub(16 - i) + ' ' + hx(r.K), 'mono key', 'start', 13));
        it.push({ key: 'dd:dv' + i, kind: 'cell', x: xd + 196, y, w: 94, h: 22, rx: 3, text: hx(r.newR), size: 13, cls: 'hex ' + (i === lit ? 'act' : '') });
        it.push(U.t('dd:dn' + i, xd + 300, y + 12, '= ' + nm2, i === lit ? 'hot' : 'tick', 'start', 13));
      }
      if (hit === 'L' + sub(0) || hit === 'R' + sub(0)) it.push(U.t('dd:l0', xe + 196, y0 + 16 * dy + 24, 'L₀ ' + hx(E[0].L) + '   R₀ ' + hx(E[0].R), 'hot mono', 'start', 13));
      return it;
    };
    const L0d = hx(Dr[0].L), R0d = hx(Dr[0].R);
    F.add({ items: [head, ...table(0, -1)], say: `Encrypting ${U.hex(P)} under ${U.hex(K)} ran sixteen rounds with K₁ … K₁₆ and gave the ciphertext ${U.hex(C)}. Decryption feeds that ciphertext to the very same ladder.`, facts: { P: U.hex(P), K: U.hex(K), C: U.hex(C) }, meta: { stage: 'start' } });
    F.add({ items: [head, ...table(0, -1), U.t('dd:ip', xd, y0 + 8, 'IP(ciphertext): ' + L0d + ' ' + R0d, 'act mono', 'start', 14), U.t('dd:ip2', xd, y0 + 34, '= R₁₆ L₁₆: IP undoes FP', 'tick', 'start', 13)], hl: { d: [0] },
      say: `IP undoes the final permutation, so the halves come back as the encryption left them: ${L0d} = R₁₆ and ${R0d} = L₁₆, already swapped.`, facts: { L0d, R0d }, meta: { stage: 'ip' } });
    for (let i = 0; i < 16; i++) {
      const r = Dr[i], nv = hx(r.newR), nm = nameOf(i);
      F.add({ items: [head, ...table(i + 1, i)], hl: { d: [1, 2] },
        say: `Decryption round ${i + 1} uses K${sub(16 - i)} = ${hx(r.K)}: ${hx(r.L)} ⊕ f(${hx(r.R)}, K${sub(16 - i)}) = ${nv}, which is ${nm} of the encryption.` + (i === 0 ? ' f(R₁₅, K₁₆) is exactly what encryption XORed in last, so XORing it again removes it.' : ''),
        facts: { i: i + 1, K: hx(r.K), L: hx(r.L), R: hx(r.R), nv, nm }, meta: { stage: 'round', i } });
    }
    const outP = U.hex(dec.out), ok = outP === U.hex(P);
    F.add({ items: [head, ...table(16, -1), U.t('dd:end', xd, y0 + 16 * dy + 24, 'FP → ' + outP + (ok ? '  ✓' : ''), 'good mono', 'start', 15)],
      say: `After sixteen rounds the halves are R₀ and L₀; leaving out the swap and applying FP gives ${outP}, ${ok ? 'the plaintext' : 'not the plaintext'}${D4.ascii(dec.out) ? ' ' + D4.ascii(dec.out) : ''}. Nothing in the ladder was run backwards: only the order of the keys changed.`, facts: { out: outP, ok, text: D4.ascii(dec.out) }, meta: { stage: 'end' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 600 });
    return { frames: F.list, def: U.def('DES decryption', ['(L′₀, R′₀) = IP(c) = (R₁₆, L₁₆)', 'R′ᵢ = L′ᵢ₋₁ ⊕ f(R′ᵢ₋₁, K₁₇₋ᵢ)', 'each round removes one encryption round', 'p = FP(R′₁₆ L′₁₆)']) };
  }
  S.topic({
    id: 'des-decrypt', family: 'p04-des', order: 50, title: 'DES decryption: the same ladder backwards',
    blurb: 'Feed the ciphertext to the same sixteen rounds with the round keys in reverse order: each round XORs out the f that encryption XORed in, and the halves come back one by one.',
    inputs: [D4.plainInp(), D4.keyInp()], presets: D4.presets(), run: decrypt,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'ip', once: true, pick: 'option', options: ['K₁', 'K₈', 'K₁₆'], ask: 'Which round key does decryption round 1 use?', answer: 'K₁₆', explain: 'It must undo the last encryption round first.' },
      { at: (f) => f.meta && f.meta.stage === 'round' && f.meta.i === 0, once: true, pick: 'option', options: (fr, i) => [fr[i + 1].facts.nm, 'R₁', 'R₂', 'R₁₅'].filter((v, k, s) => s.indexOf(v) === k), ask: 'Round 1 gave back R₁₄. Which encryption value will round 2 give back?', answer: (fr, i) => fr[i + 1].facts.nm, explain: 'Each decryption round steps one encryption round back.' },
    ],
    quiz: [
      { q: 'What changes between DES encryption and decryption?', options: ['The S-boxes are inverted', 'The round keys are used in reverse order', 'f is run backwards', 'IP and FP swap places'], answer: 1, why: 'The ladder is identical; only K₁ … K₁₆ becomes K₁₆ … K₁.' },
      { q: 'Why can f stay a one-way mixing function?', options: ['Because XORing the same f(R, K) twice cancels it', 'Because the key is secret', 'Because it is linear', 'It cannot'], answer: 0, why: 'Decryption recomputes f(R, K) from the half it already has and XORs it out.' },
      { q: 'IP of the ciphertext gives…', options: ['L₀ and R₀', 'R₁₆ and L₁₆', 'K₁₆', 'the plaintext'], answer: 1, why: 'IP undoes FP, and the output was R₁₆ L₁₆.' },
      { q: 'Decryption round j produces which encryption value?', options: ['Rⱼ', 'R₁₅₋ⱼ (and L₀ at the end)', 'Lⱼ', 'Kⱼ'], answer: 1, why: 'Round 1 gives L₁₅ = R₁₄, round 2 gives R₁₃, and so on down to R₀ and L₀.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The avalanche
  // ---------------------------------------------------------------------------------------------------------------
  function avalanche(inp) {
    const P = D4.bytes(inp.pt), K = D4.bytes(inp.key), b = inp.bit - 1, onKey = inp.what === 'key';
    const flip = (x) => { const y = Uint8Array.from(x); y[b >> 3] ^= 0x80 >> (b & 7); return y; };
    const P2 = onKey ? P : flip(P), K2 = onKey ? flip(K) : K;
    const e1 = DES().encrypt(P, K), e2 = DES().encrypt(P2, K2);
    const st = (e) => [e.ip].concat(e.rounds.map((r) => r.R.concat(r.newR)));
    const s1 = st(e1), s2 = st(e2), diff = s1.map((v, i) => v.map((x, j) => x ^ s2[i][j])), cnt = diff.map((d) => d.reduce((t, x) => t + x, 0));
    const c1 = U.hex(e1.out), c2 = U.hex(e2.out), cd = DES().bits(e1.out).reduce((t, x, j) => t + (x ^ DES().bits(e2.out)[j]), 0);
    const F = new S.Frames(), x0 = 120, cw = 10, ch = 20, y0 = 104, dy = 25, half = 32 * cw + 14;
    const head = U.head('av:h', 'One flipped ' + (onKey ? 'key' : 'plaintext') + ' bit, sixteen rounds');
    const rows = (upto, lit) => {
      const it = [U.t('av:l', x0, y0 - 16, 'L half', 'tick', 'start', 13), U.t('av:r', x0 + half, y0 - 16, 'R half', 'tick', 'start', 13), U.t('av:c', 800, y0 - 16, 'bits that differ', 'tick', 'start', 13)];
      for (let i = 0; i <= upto; i++) {
        const y = y0 + i * dy, d = diff[i], cur = i === lit;
        it.push(U.t('av:n' + i, 24, y + 15, i ? 'round ' + i : 'after IP', cur ? 'act' : 'tick', 'start', 13));
        it.push({ key: 'av:bl' + i, kind: 'bitmap', x: x0, y, cw, ch, gap: 1.5, rows: [d.slice(0, 32).map((x) => (x ? '2' : '0')).join('')] });
        it.push({ key: 'av:br' + i, kind: 'bitmap', x: x0 + half, y, cw, ch, gap: 1.5, rows: [d.slice(32).map((x) => (x ? '2' : '0')).join('')] });
        it.push({ key: 'av:bar' + i, kind: 'cell', x: 800, y: y + 3, w: Math.max(1, cnt[i] * 1.2), h: ch - 6, rx: 2, text: '', cls: 'avbar' });
        it.push(U.t('av:k' + i, 800 + cnt[i] * 1.2 + 8, y + 15, String(cnt[i]), cur ? 'hot' : 'mono', 'start', 13));
      }
      return it;
    };
    const legend = U.legend('av:lg', x0, y0 + 17 * dy + 22, [['hot', 'differs'], ['', 'same']]);
    const where = onKey ? `bit ${inp.bit} of the key, ${U.hex(K)} → ${U.hex(K2)}` : `bit ${inp.bit} of the plaintext, ${U.hex(P)} → ${U.hex(P2)}`;
    const parity = onKey && b % 8 === 7;
    F.add({ items: [head, ...rows(0, 0), ...legend], say: `Flip ${where}. After IP the two states differ in ${cnt[0]} bit${cnt[0] === 1 ? '' : 's'}` + (onKey ? ': the key has not been used yet.' : ': IP only moved it.') + (parity ? ' This is a parity bit, so the round keys do not change at all.' : ''), facts: { bit: inp.bit, d: cnt[0], P: U.hex(P), P2: U.hex(P2), K: U.hex(K), K2: U.hex(K2) }, meta: { stage: 'start' } });
    for (let i = 1; i <= 16; i++) {
      const say = `Round ${i}: the states now differ in ${cnt[i]} of 64 bits (${cnt[i] - cnt[i - 1] >= 0 ? 'up' : 'down'} from ${cnt[i - 1]}).` + (i === 1 && !onKey ? ' The changed bit reached f through the right half, and the S-boxes turned it into several.' : i === 4 && cnt[4] >= 20 ? ' By now about a third to a half of the state has changed.' : '');
      F.add({ items: [head, ...rows(i, i), ...legend], say, facts: { i, d: cnt[i], prev: cnt[i - 1] }, meta: { stage: 'round', i } });
    }
    let half32 = cnt.findIndex((c) => c >= 24);
    F.add({ items: [head, ...rows(16, -1), ...legend, U.t('av:ct1', 24, y0 + 17 * dy + 54, 'c₁ = ' + c1, 'mono', 'start', 14), U.t('av:ct2', 300, y0 + 17 * dy + 54, 'c₂ = ' + c2, 'mono', 'start', 14), U.t('av:ct3', 580, y0 + 17 * dy + 54, cd + ' ciphertext bits differ', 'hot', 'start', 14)],
      say: `The ciphertexts ${c1} and ${c2} differ in ${cd} of their 64 bits.` + (cd ? ` ${half32 > 0 ? `The difference first reached 24 bits in round ${half32} and then hovered around 32, half the block: each output bit looks like a coin toss.` : ''}` : ' With no change in any round key, nothing changed at all.'),
      facts: { c1, c2, cd, half: half32 }, meta: { stage: 'end' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 600 });
    return { frames: F.list, def: U.def('The avalanche', ['flip one input bit, compare the states round by round', 'S-boxes: one input bit changes about 2 output bits', 'E and P carry those to several S-boxes next round', 'a good cipher: about 32 of 64 output bits change']) };
  }
  S.topic({
    id: 'des-avalanche', family: 'p04-des', order: 60, title: 'The avalanche over sixteen rounds',
    blurb: 'Change one bit of the plaintext or the key and follow the difference round by round: a few rounds in, about half the block differs, and it stays that way.',
    inputs: [D4.plainInp(), D4.keyInp(), U.choice('what', 'Flip a bit of', 'pt', [['pt', 'the plaintext'], ['key', 'the key']]), { id: 'bit', kind: 'number', label: 'Bit (1 is the leftmost)', def: 1, min: 1, max: 64 }],
    presets: [
      { label: '‘nightjar’, plaintext bit 1', values: { pt: a('nightjar'), key: a('bramble7'), what: 'pt', bit: 1 } },
      { label: '‘nightjar’, plaintext bit 40', values: { pt: a('nightjar'), key: a('bramble7'), what: 'pt', bit: 40 } },
      { label: '‘copper42’, key bit 2', values: { pt: a('copper42'), key: a('quill&in'), what: 'key', bit: 2 } },
      { label: 'A parity bit of the key (bit 8)', values: { pt: a('copper42'), key: a('quill&in'), what: 'key', bit: 8 } },
      { label: 'All-zero block, plaintext bit 64', values: { pt: '0000000000000000', key: a('bramble7'), what: 'pt', bit: 64 } },
    ],
    run: avalanche,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'start', once: true, pick: 'option', options: ['none', 'about 8', 'about 32', 'all 64'], ask: 'After all sixteen rounds, how many of the 64 bits will differ?', answer: (fr) => { const c = fr[fr.length - 2].facts.d; return c === 0 ? 'none' : c < 16 ? 'about 8' : c <= 48 ? 'about 32' : 'all 64'; }, explain: 'A good cipher changes each output bit with probability one half (unless the flipped key bit is a parity bit, which changes nothing).' },
    ],
    quiz: [
      { q: 'Which parts of DES spread one changed bit to many?', options: ['IP and FP', 'The S-boxes with E and P', 'The parity bits', 'The final swap'], answer: 1, why: 'An S-box turns one changed input bit into about two changed outputs, and E and P send them to several S-boxes next round.' },
      { q: 'After IP, how many bits differ when one plaintext bit is flipped?', options: ['0', '1', 'about 2', 'about 32'], answer: 1, why: 'IP only moves bits.' },
      { q: 'Flipping a parity bit of the key changes the ciphertext in…', options: ['about 32 bits', 'no bits', 'one bit', '8 bits'], answer: 1, why: 'PC-1 drops the parity bits, so every round key stays the same.' },
      { q: 'Why is "about half the bits change" the goal, not "all of them"?', options: ['All would be the complement, just as predictable', 'Half is faster', 'It saves key bits', 'All is impossible'], answer: 0, why: 'Flipping every bit is a fixed pattern; independent coin tosses are what look random.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
