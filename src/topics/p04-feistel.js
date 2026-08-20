// Part 4, the Feistel principle: a 32-bit block in two 16-bit halves, a few rounds with a round function of your
// choice, and then the same ladder run on the ciphertext with the keys reversed. The ladder is drawn so that F feeds
// the two lanes in turn and nothing crosses; every value decryption brings back lights up where encryption made it.
(function (S) {
  'use strict';
  const U = S.SymT, F_ = S.Kit.flow, sub = U.sub;
  const FE = () => S.Feistel;
  /** a round function that throws information away: many R give the same output */
  const SQUARE = { name: 'F(R, k) = middle bits of (R ⊕ k)² (not invertible)', F: (R, k) => { const x = (R ^ k) & 0xffff; return Math.floor((x * x) / 256) & 0xffff; } };
  const fnOf = (id) => (id === 'square' ? SQUARE : FE().ROUND_FUNCTIONS[id]);
  const h4 = U.h4;

  function feistel(inp) {
    const fn = fnOf(inp.F), keys = inp.keys.map((k) => parseInt(k, 16)), n = keys.length, blk = U.fromHex(inp.pt);
    const L0 = (blk[0] << 8) | blk[1], R0 = (blk[2] << 8) | blk[3];
    const enc = FE().run({ L: L0, R: R0, keys, F: fn.F, bits: 16 });
    const dec = FE().run({ L: enc.L, R: enc.R, keys, F: fn.F, bits: 16, decrypt: true });
    const F = new S.Frames(), yk = (k) => 162 + (k - 1) * 52, yEnd = yk(n) + 34, yOut = yk(n) + 62;
    const G = [{ A: 90, B: 330, f: 210, p: 'fe' }, { A: 540, B: 780, f: 660, p: 'fd' }];
    const laneOf = (k) => (k % 2 ? 'A' : 'B');
    const head = U.head('fs:h', 'A Feistel ladder with ' + fn.name);
    // one ladder: g the geometry, run the rounds, at how many are drawn, cur the round lit, ins the two input values,
    // keyIdx(k) the key used in round k, hot: values to light (matches)
    const ladder = (g, rounds, at, cur, ins, names, keyIdx, hot, outs) => {
      const N = F_.net(g.p);
      N.box('iA', g.A, 104, 112, 44, [names[0], h4(ins[0])], 'val2' + (at === 0 && cur === 0 ? ' act' : ''));
      N.box('iB', g.B, 104, 112, 44, [names[1], h4(ins[1])], 'val2' + (at === 0 && cur === 0 ? ' act' : ''));
      const cuts = { A: [], B: [] };
      for (let k = 1; k <= Math.max(at, 0); k++) {
        const r = rounds[k - 1], y = yk(k), l = laneOf(k), on = k === cur, xo = g[l], xt = g[l === 'A' ? 'B' : 'A'];
        N.box('f' + k, g.f, y, 76, 30, 'F', 'small' + (on ? ' act' : ''));
        N.op('x' + k, xo, y, 'xor', on ? 'act' : '');
        cuts[l].push(y);
        N.dot(xt, y, on ? 'act' : '');
        N.wire('t' + k, [[xt, y], N.port('f' + k, l === 'A' ? 'e' : 'w')], { head: true, cls: on ? 'act' : '' });
        N.wire('o' + k, [N.port('f' + k, l === 'A' ? 'w' : 'e'), N.port('x' + k, l === 'A' ? 'e' : 'w')], { head: true, cls: on ? 'act' : '' });
        N.label('k' + k, g.f, y - 21, 'k' + sub(keyIdx(k)) + ' = ' + h4(keys[keyIdx(k) - 1]), 'key', 'middle', 13);
        N.chip('v' + k, h4(r.newR), [xo, y + 25], hot.has(h4(r.newR)) ? 'hot' : on ? 'act' : 'plain');
      }
      const end = at >= n ? yEnd : at > 0 ? yk(at) + 14 : 150;
      for (const l of ['A', 'B']) {
        const ys = [126].concat(...cuts[l].map((y) => [y - 11, y + 11]), [end]);
        for (let i = 0; i < ys.length; i += 2) if (ys[i + 1] - ys[i] > 2) N.wire('l' + l + i, [[g[l], ys[i]], [g[l], ys[i + 1]]], { head: i + 2 < ys.length || at >= n, cls: '' });
      }
      if (at >= n && outs) {
        const last = laneOf(n), other = last === 'A' ? 'B' : 'A';
        N.box('o' + last, g[last], yOut, 120, 44, [outs[0][0], h4(outs[0][1])], 'val2 ' + outs[2]);
        N.box('o' + other, g[other], yOut, 120, 44, [outs[1][0], h4(outs[1][1])], 'val2 ' + outs[2]);
      }
      return N.items;
    };
    const encNames = ['L₀', 'R₀'], none = new Set();
    const encOuts = [['left = R' + sub(n), enc.L], ['right = L' + sub(n), enc.R], 'hot'];
    const E = (at, cur, hot) => [U.t('fs:et', 40, 70, 'encryption', 'title', 'start', 14), ...ladder(G[0], enc.rounds, at, cur, [L0, R0], encNames, (k) => k, hot || none, encOuts)];
    const Dl = (at, cur) => [U.t('fs:dt', 490, 70, 'decryption: the same ladder, keys reversed', 'title', 'start', 14), ...ladder(G[1], dec.rounds, at, cur, [enc.L, enc.R], ['L′₀ = R' + sub(n), 'R′₀ = L' + sub(n)], (k) => n + 1 - k, none, [['left', dec.L], ['right', dec.R], dec.L === L0 && dec.R === R0 ? 'good' : 'bad'])];
    F.add({ items: [head, ...E(0, 0)], say: `The block ${U.hex(blk)} splits into L₀ = ${h4(L0)} and R₀ = ${h4(R0)}. ${n} round${n === 1 ? '' : 's'} follow, each with its own key, and the round function is ${fn.name}.`, facts: { blk: U.hex(blk), L0: h4(L0), R0: h4(R0), n, fn: fn.name }, meta: { stage: 'start' } });
    enc.rounds.forEach((r, i) => {
      const k = i + 1;
      F.add({ items: [head, ...E(k, k)], hl: { d: [0] }, say: `Round ${k}: F(${h4(r.R)}, k${sub(k)} = ${h4(r.k)}) = ${h4(r.f)}, and ${h4(r.L)} ⊕ ${h4(r.f)} = ${h4(r.newR)} replaces the other half. ${h4(r.R)} itself passes on untouched.`,
        facts: { k, R: h4(r.R), key: h4(r.k), f: h4(r.f), L: h4(r.L), newR: h4(r.newR) }, meta: { stage: 'enc', k } });
    });
    const ct = h4(enc.L) + h4(enc.R);
    F.add({ items: [head, ...E(n, -1)], say: `The ciphertext is ${ct}: the half changed last, R${sub(n)} = ${h4(enc.L)}, goes on the left. Leaving out the last swap is what makes the ladder its own inverse.`, facts: { ct, l: h4(enc.L), r: h4(enc.R) }, meta: { stage: 'out' } });
    F.add({ items: [head, ...E(n, -1), ...Dl(0, 0)], hl: { d: [1] }, say: `Decryption puts the ciphertext into the same ladder: L′₀ = ${h4(enc.L)}, R′₀ = ${h4(enc.R)}, and uses the keys from k${sub(n)} down to k₁.`, facts: { l: h4(enc.L), r: h4(enc.R) }, meta: { stage: 'dec0' } });
    const seen = new Set();
    dec.rounds.forEach((r, i) => {
      const k = i + 1, v = h4(r.newR);
      seen.add(v);
      const where = v === h4(L0) ? 'L₀' : enc.rounds.findIndex((x) => h4(x.newR) === v) >= 0 ? 'the value encryption round ' + (enc.rounds.findIndex((x) => h4(x.newR) === v) + 1) + ' made' : v === h4(R0) ? 'R₀' : 'new';
      F.add({ items: [head, ...E(n, -1, seen), ...Dl(k, k)], hl: { d: [1, 2] }, say: `Decryption round ${k} uses k${sub(n + 1 - k)} = ${h4(r.k)}: F(${h4(r.R)}) = ${h4(r.f)} is the very F that encryption XORed in, so ${h4(r.L)} ⊕ ${h4(r.f)} = ${v} is ${where}.`,
        facts: { k, key: h4(r.k), R: h4(r.R), f: h4(r.f), L: h4(r.L), v, where }, meta: { stage: 'dec', k } });
    });
    const ok = dec.L === L0 && dec.R === R0;
    // a collision of F under k₁, when there is one: F loses information and the cipher does not care
    let col = null;
    const firstSeen = new Map();
    for (let x = 0; x < 65536 && !col; x++) { const v = fn.F(x, keys[0], 0) & 0xffff; if (firstSeen.has(v)) col = [firstSeen.get(v), x, v]; else firstSeen.set(v, x); }
    F.add({ items: [head, ...E(n, -1, seen), ...Dl(n, -1)], hl: { d: [3] }, say: `Out comes ${h4(dec.L)}${h4(dec.R)}, ${ok ? 'the plaintext' : 'not the plaintext'}.` + (col ? ` And F itself cannot be undone: F(${h4(col[0])}, k₁) = F(${h4(col[1])}, k₁) = ${h4(col[2])}. The Feistel ladder never needs F backwards, only F again.` : ' This F happens to be a permutation of R, but the ladder never used that: it only ran F forwards.'),
      facts: { out: h4(dec.L) + h4(dec.R), ok, col: col ? col.map(h4) : null }, meta: { stage: 'end' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: Math.max(440, yOut + 40) });
    // on a phone, the ladder being worked on fills the stage
    const H = Math.max(440, yOut + 40);
    for (const f of F.list) f.narrowView = /^dec/.test(f.meta.stage) || f.meta.stage === 'end' ? { x: 460, y: 50, w: 460, h: H - 50 } : { x: 0, y: 50, w: 460, h: H - 50 };
    return { frames: F.list, def: U.def('The Feistel round', ['Lᵢ = Rᵢ₋₁', 'Rᵢ = Lᵢ₋₁ ⊕ F(Rᵢ₋₁, kᵢ)', 'output (Rₙ, Lₙ): no swap after the last round', 'decrypt: the same rounds with kₙ … k₁', 'F can be any function at all']) };
  }
  const opts = [['sbox', 'S-boxes then a rotation'], ['addRot', 'add the key, rotate'], ['xorKey', 'R ⊕ k (linear)'], ['square', 'squaring (not invertible)'], ['zero', 'F = 0 (just swaps)']];
  S.topic({
    id: 'des-feistel', family: 'p04-feistel', order: 10, title: 'The Feistel principle',
    blurb: 'Split the block in two; each round XORs a function of one half into the other. Whatever the function, running the same rounds with the keys reversed undoes it, because XORing the same value twice cancels.',
    inputs: [
      U.choice('F', 'Round function F', 'sbox', opts),
      { id: 'pt', kind: 'hex', label: 'Block (4 bytes, hex)', def: U.hex(U.bytesOf('wren')), bytes: 4 },
      { id: 'keys', kind: 'list', label: 'Round keys (16-bit hex)', def: ['3a7c', '91e4', '5b20', 'c6d9'], min: 1, max: 8, check: (v) => (v.some((k) => !/^[0-9a-fA-F]{1,4}$/.test(k)) ? 'Round keys: hex numbers of up to four digits' : null) },
    ],
    presets: [
      { label: '‘wren’, S-box F, 4 rounds', values: { F: 'sbox', pt: U.hex(U.bytesOf('wren')), keys: ['3a7c', '91e4', '5b20', 'c6d9'] } },
      { label: 'A lossy F (squaring)', values: { F: 'square', pt: U.hex(U.bytesOf('moth')), keys: ['0f1e', 'a5c3', '7d42'] } },
      { label: 'F = 0: only swaps', values: { F: 'zero', pt: U.hex(U.bytesOf('wren')), keys: ['3a7c', '91e4'] } },
      { label: 'Linear F, 6 rounds', values: { F: 'xorKey', pt: U.hex(U.bytesOf('kelp')), keys: ['1111', '2222', '4444', '8888', 'f00f', '0ff0'] } },
      { label: 'Add and rotate, 8 rounds', values: { F: 'addRot', pt: U.hex(U.bytesOf('fern')), keys: ['0001', '0203', '0405', '0607', '0809', '0a0b', '0c0d', '0e0f'] } },
    ],
    run: feistel,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'out', once: true, pick: 'option', options: (fr) => { const n = fr[0].facts.n; return ['k' + sub(1), 'k' + sub(n)].concat(n > 2 ? ['k' + sub(2)] : []); }, ask: 'Decryption runs the same ladder. Which key must its first round use?', answer: (fr) => 'k' + sub(fr[0].facts.n), explain: 'It must remove the last round first, so the keys go in reverse.' },
      { at: (f) => f.meta && f.meta.stage === 'dec0', once: true, pick: 'option', options: ['yes', 'no'], ask: 'Will decryption need to run F backwards (invert it) anywhere?', answer: 'no', explain: 'Each decryption round recomputes F of a half it already has and XORs it out again.' },
    ],
    quiz: [
      { q: 'What must the round function F be for a Feistel cipher to decrypt?', options: ['A permutation', 'Linear', 'Anything at all', 'Its own inverse'], answer: 2, why: 'Decryption only evaluates F forwards; XORing the same value twice cancels.' },
      { q: 'In round i, what happens to Rᵢ₋₁?', options: ['It is XORed with F', 'It moves on unchanged as Lᵢ', 'It is discarded', 'It becomes the key'], answer: 1, why: 'Rᵢ₋₁ is the input of F; the other half is the one that changes.' },
      { q: 'With F = 0, what does a Feistel round do?', options: ['Nothing', 'Swaps the halves', 'Encrypts with the key', 'Doubles the block'], answer: 1, why: 'Rᵢ = Lᵢ₋₁ ⊕ 0 and Lᵢ = Rᵢ₋₁: a plain swap; the security lives in F.' },
      { q: 'How does a Feistel decryption differ from encryption?', options: ['A new circuit is needed', 'Only the order of the round keys', 'F is replaced by F⁻¹', 'The halves are XORed first'], answer: 1, why: 'That is why DES needs one circuit for both directions.' },
      { q: 'With a linear F such as R ⊕ k, the cipher is…', options: ['secure after enough rounds', 'linear too: easily broken from a few plaintext–ciphertext pairs', 'not invertible', 'a one-time pad'], answer: 1, why: 'XORs and linear F compose to a linear map; the non-linearity must come from F.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
