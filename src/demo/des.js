// DES scenes: one Feistel round with the f-function opened up (E, the key mix, the eight S-boxes, P), and the
// sixteen rounds as a ladder drawn without a single crossing: the f-function feeds the two halves in turn, so the
// swap between rounds is never drawn.
(function (S) {
  'use strict';
  const D = S.Demo, DES = S.DES, F = S.Kit.flow, box = D.box;
  const hx = (bits) => DES.hex(bits);
  const run = () => DES.encrypt(D.data.desPlain, D.data.desKey);
  /** a camera for a phone that follows the action: a window w wide centred on x, as tall as the view */
  D.follow = (view, x, w) => { w = w || 400; const x0 = Math.max(view.x, Math.min(view.x + view.w - w, x - w / 2)); return box(x0, view.y, w, view.h); };

  // ---- one round ---------------------------------------------------------------------------------------------
  D.add({
    id: 'des-round', order: 20, tag: 'DES · Feistel round', short: 'DES round', title: 'One DES round, with the f-function opened',
    blurb: 'The right half goes through f and is XORed into the left half; the right half itself passes on unchanged. That is why any f can be undone.',
    frames({ narrow }) {
      const r = run().rounds[0], f = r.f;
      const view = box(0, 0, 1160, 560);
      const xL = 90, xR = 1060, cx = 575;
      const build = (stage) => {
        const N = F.net('dr');
        const on = (k) => stage >= k;
        N.box('L', xL, 44, 150, 50, ['L₀', hx(r.L)], 'val2' + (stage === 0 ? ' act' : ''));
        N.box('R', xR, 44, 150, 50, ['R₀', hx(r.R)], 'val2' + (stage === 0 || stage === 1 ? ' act' : ''));
        N.box('E', cx, 120, 300, 40, 'E: expand 32 → 48 bits', stage === 1 ? 'act' : '');
        N.op('x1', cx, 200, 'xor', stage === 2 ? 'act' : '');
        N.box('K', 850, 200, 190, 50, ['K₁', hx(r.K)], 'key val2');
        const sx = (k) => cx + (k - 3.5) * 106;
        for (let k = 0; k < 8; k++) {
          const b = f.boxes[k];
          N.box('S' + k, sx(k), 322, 90, 70, on(3) ? [DES.bin(b.in6), 'S' + (k + 1), on(3) ? DES.bin(b.out) : ''] : ['', 'S' + (k + 1), ''], 'sbox' + (stage === 3 && k === 0 ? ' act' : stage === 3 ? ' hot' : ''));
        }
        N.box('P', cx, 424, 220, 38, 'P: permute 32 bits', stage === 4 ? 'act' : '');
        N.op('x2', xL, 424, 'xor', stage === 5 ? 'act' : '');
        N.box('oL', xL, 512, 170, 50, ['R₁ = L₀ ⊕ f', stage >= 5 ? hx(r.newR) : ''], 'val2' + (stage >= 5 ? ' hot' : ' soft'));
        N.box('oR', xR, 512, 170, 50, ['L₁ = R₀', stage >= 5 ? hx(r.R) : ''], 'val2' + (stage >= 5 ? ' hot' : ' soft'));
        // the wires
        const act = (k) => (stage === k ? 'act' : '');
        N.wire('L', [N.port('L', 's'), N.port('x2', 'n')], { head: true, cls: act(5) });
        N.wire('L2', [N.port('x2', 's'), N.port('oL', 'n')], { head: true, cls: act(5) });
        N.wire('R', [N.port('R', 's'), N.port('oR', 'n')], { head: true });
        N.dot(xR, 120, stage === 1 ? 'act' : '');
        N.wire('tap', [[xR, 120], N.port('E', 'e')], { head: true, cls: act(1) });
        N.bus('e', [N.port('E', 's'), N.port('x1', 'n')], 48, { head: true, cls: act(2), at: 0.25 });
        N.wire('k', [N.port('K', 'w'), N.port('x1', 'e')], { head: true, cls: 'key' });
        N.bus('x', [N.port('x1', 's'), [cx, 258]], 48, { cls: act(3), at: 0.3 });
        N.wire('dist', [[sx(0), 258], [sx(7), 258]], { cls: 'bus ' + act(3) });
        N.dot(cx, 258, stage === 3 ? 'act' : '');
        for (let k = 0; k < 8; k++) { N.wire('d' + k, [[sx(k), 258], N.port('S' + k, 'n')], { head: true, cls: act(3) }); if (k > 0 && k < 7) N.dot(sx(k), 258, stage === 3 ? 'act' : ''); }
        for (let k = 0; k < 8; k++) N.wire('u' + k, [N.port('S' + k, 's'), [sx(k), 382]], { cls: act(4) });
        N.wire('merge', [[sx(0), 382], [sx(7), 382]], { cls: 'bus ' + act(4) });
        for (let k = 1; k < 7; k++) N.dot(sx(k), 382, stage === 4 ? 'act' : '');
        N.dot(cx, 382, stage === 4 ? 'act' : '');
        N.bus('m', [[cx, 382], N.port('P', 'n')], 32, { head: true, cls: act(4), at: 0.45 });
        N.wire('f', [N.port('P', 'w'), N.port('x2', 'e')], { head: true, cls: act(5) });
        // values on the wires
        if (on(1)) N.chip('E', hx(f.E), [cx + 120, 166], stage === 1 ? 'act' : 'plain');
        if (on(2)) N.chip('X', hx(f.X), [cx + 120, 236], stage === 2 ? 'act' : 'plain');
        if (on(4)) N.chip('f', 'f = ' + hx(f.P), [270, 424], stage === 4 || stage === 5 ? 'act' : 'plain');
        return N.items;
      };
      // a phone: the lanes at the edges, f down the middle, the eight S-boxes as a table of lookups
      const buildNarrow = (stage) => {
        const N = F.net('dr');
        const xL = 40, xR = 362, cx = 215, act = (k) => (stage === k ? 'act' : '');
        N.box('L', xL, 34, 78, 46, ['L₀', hx(r.L)], 'val2 tight' + (stage === 0 ? ' act' : ''));
        N.box('R', xR, 34, 78, 46, ['R₀', hx(r.R)], 'val2 tight' + (stage <= 1 ? ' act' : ''));
        N.box('E', cx, 106, 190, 34, 'E: 32 → 48 bits', 'small ' + act(1));
        N.op('x1', cx, 186, 'xor', act(2));
        N.box('K', 120, 186, 112, 46, ['K₁', hx(r.K)], 'key val2 tight');
        N.add({ key: 'dr:sreg', kind: 'region', x: 78, y: 236, w: 262, h: 134, rx: 8, text: '', cls: stage === 3 ? 'act' : '' });
        for (let k = 0; k < 8; k++) {
          const b = f.boxes[k], col = k % 2, row = Math.floor(k / 2);
          N.add({ key: 'dr:sb' + k, kind: 'cell', x: 86 + col * 126, y: 244 + row * 30, w: 120, h: 26, rx: 4, text: stage >= 3 ? `S${k + 1} ${DES.bin(b.in6)}→${DES.bin(b.out)}` : `S${k + 1}`, size: 12, cls: 'mono ' + (stage === 3 && k === 0 ? 'act' : stage === 3 ? 'changed' : '') });
        }
        N.box('P', cx, 408, 150, 32, 'P: permute', 'small ' + act(4));
        N.op('x2', xL, 408, 'xor', act(5));
        N.box('oL', 62, 486, 120, 46, ['R₁ = L₀ ⊕ f', stage >= 5 ? hx(r.newR) : ''], 'val2 tight' + (stage >= 5 ? ' hot' : ' soft'));
        N.box('oR', 340, 486, 120, 46, ['L₁ = R₀', stage >= 5 ? hx(r.R) : ''], 'val2 tight' + (stage >= 5 ? ' hot' : ' soft'));
        N.wire('L', [N.port('L', 's'), N.port('x2', 'n')], { head: true, cls: act(5) });
        N.wire('L2', [N.port('x2', 's'), [xL, 463]], { head: true, cls: act(5) });
        N.wire('R', [N.port('R', 's'), [xR, 463]], { head: true });
        N.dot(xR, 106, stage === 1 ? 'act' : '');
        N.wire('tap', [[xR, 106], N.port('E', 'e')], { head: true, cls: act(1) });
        N.bus('e', [N.port('E', 's'), N.port('x1', 'n')], 48, { head: true, cls: act(2), at: 0.22 });
        N.wire('k', [N.port('K', 'e'), N.port('x1', 'w')], { head: true, cls: 'key' });
        N.bus('x', [N.port('x1', 's'), [cx, 236]], 48, { head: true, cls: act(3), at: 0.3 });
        N.bus('s', [[cx, 370], N.port('P', 'n')], 32, { head: true, cls: act(4), at: 0.4 });
        N.wire('f', [N.port('P', 'w'), N.port('x2', 'e')], { head: true, cls: act(5) });
        if (stage >= 1) N.chip('E', hx(f.E), [cx + 92, 150], stage === 1 ? 'act' : 'plain', { onWire: false });
        if (stage >= 2) N.chip('X', hx(f.X), [cx + 92, 216], stage === 2 ? 'act' : 'plain', { onWire: false });
        if (stage >= 4) N.chip('f', hx(f.P), [100, 408], stage >= 4 ? 'act' : 'plain');
        return N.items;
      };
      const b0 = f.boxes[0];
      const says = [
        `Round 1 starts from the two halves after the initial permutation: L₀ = \`${hx(r.L)}\` and R₀ = \`${hx(r.R)}\`. The round key K₁ = \`${hx(r.K)}\` has 48 bits.`,
        `E copies R₀'s 32 bits into 48, using 16 of them twice: \`${hx(f.E)}\`. The doubled bits are what let one bit reach two S-boxes.`,
        `The key enters here, and only here: \`${hx(f.E)}\` ⊕ \`${hx(r.K)}\` = \`${hx(f.X)}\`.`,
        `Each S-box takes 6 bits and gives 4. S1 gets \`${DES.bin(b0.in6)}\`: the outer bits \`${b0.in6[0]}${b0.in6[5]}\` pick row ${b0.row}, the middle four \`${DES.bin(b0.in6.slice(1, 5))}\` pick column ${b0.col}, and the entry there is ${b0.v} = \`${DES.bin(b0.out)}\`. The S-boxes are the only part of DES that is not linear.`,
        `The eight outputs make 32 bits, \`${hx(f.S)}\`, and P scatters them so that the four bits from each S-box reach six other S-boxes in the next round: f = \`${hx(f.P)}\`.`,
        `f is XORed into the left half: R₁ = \`${hx(r.L)}\` ⊕ \`${hx(f.P)}\` = \`${hx(r.newR)}\`. R₀ passes on untouched and becomes L₁. To undo the round, compute the same f(R₀) and XOR it in again.`,
      ];
      if (narrow) return says.map((say, k) => ({ view: box(-4, 0, 408, 520), items: buildNarrow(k), say }));
      return says.map((say, k) => ({ view, items: build(k), say }));
    },
  });

  // ---- the ladder ------------------------------------------------------------------------------------------
  D.add({
    id: 'des-ladder', order: 21, tag: 'DES · sixteen rounds', short: 'DES ladder', title: 'Sixteen rounds on the Feistel ladder',
    blurb: 'Drawn so that f feeds the two halves in turn, the ladder needs no swap and no crossing. After round 16 the halves leave in the order that undoes the last swap.',
    frames({ narrow }) {
      const res = run(), R = res.rounds;
      const view = narrow ? box(0, 0, 1160, 550) : box(0, 0, 1160, 520);
      const yA1 = 66, yB1 = 166, yB2 = 300, yA2 = 400, xIn = 60, xTurnA = 1110, xTurnB = 1060, fy1 = 116, fy2 = 350;
      const colX = (k) => (k <= 8 ? 200 + (k - 1) * 112 : 200 + (16 - k) * 112);
      const build = (at) => {
        const N = F.net('dl');
        N.box('IP', xIn, fy1, 64, 150, ['IP'], 'cipher');
        N.box('FP', xIn, fy2, 64, 150, ['FP'], 'cipher');
        N.label('pin', 28, 22, 'plaintext ' + DES.hex(DES.bits(D.data.desPlain)), 'mono', 'start', 13);
        N.label('pout', 28, 452, 'ciphertext ' + (at >= 17 ? DES.hex(DES.bits(res.out)) : ''), 'mono ' + (at >= 17 ? 'hot' : ''), 'start', 13);
        // which lane a round updates: odd rounds the A lane (top in the first row), even rounds the B lane
        const segs = { A: [], B: [] };
        const opY = (k) => (k <= 8 ? (k % 2 ? yA1 : yB1) : (k % 2 ? yA2 : yB2));
        const tapY = (k) => (k <= 8 ? (k % 2 ? yB1 : yA1) : (k % 2 ? yB2 : yA2));
        for (let k = 1; k <= 16; k++) {
          const x = colX(k), cur = k === at, done = k < at;
          N.box('f' + k, x, k <= 8 ? fy1 : fy2, 44, 34, 'f', 'small' + (cur ? ' act' : done ? '' : ' soft'));
          N.op('x' + k, x, opY(k), 'xor', cur ? 'act' : '');
          N.dot(x, tapY(k), cur ? 'act' : '');
          const down = tapY(k) < opY(k);
          N.wire('t' + k, [[x, tapY(k)], N.port('f' + k, down ? 'n' : 's')], { head: true, cls: cur ? 'act' : '' });
          N.wire('o' + k, [N.port('f' + k, down ? 's' : 'n'), N.port('x' + k, down ? 'n' : 's')], { head: true, cls: cur ? 'act' : '' });
          const kx = k <= 8 ? x - 22 : x + 22;
          N.wire('k' + k, [[k <= 8 ? kx - 26 : kx + 26, k <= 8 ? fy1 : fy2], [kx, k <= 8 ? fy1 : fy2]], { head: true, cls: 'key' });
          N.label('kl' + k, k <= 8 ? kx - 30 : kx + 30, (k <= 8 ? fy1 : fy2) + 5, 'K' + String(k).replace(/\d/g, (d) => '₀₁₂₃₄₅₆₇₈₉'[d]), 'key', k <= 8 ? 'end' : 'start', 13);
        }
        // the lanes, cut at every ⊕ they pass through
        const lane = (name, pts, cuts) => {
          // pts: the lane's corners; cuts: x positions of its ⊕ on each straight run, given as [x, y]
          let cur = [pts[0]], n = 0;
          const flush = (end, head) => { cur.push(end); N.wire(name + n++, cur, { head }); };
          for (let i = 1; i < pts.length; i++) {
            const [a, b] = [pts[i - 1], pts[i]];
            const here = cuts.filter((c) => (a[1] === b[1] && c[1] === a[1] && (c[0] - a[0]) * (c[0] - b[0]) < 0)).sort((p, q) => Math.abs(p[0] - a[0]) - Math.abs(q[0] - a[0]));
            for (const c of here) { const dir = Math.sign(b[0] - a[0]); flush([c[0] - dir * 11, c[1]], true); cur = [[c[0] + dir * 11, c[1]]]; }
            if (i < pts.length - 1) cur.push(b);
          }
          flush(pts[pts.length - 1], true);
        };
        const cuts = []; for (let k = 1; k <= 16; k++) cuts.push([colX(k), opY(k)]);
        lane('A', [[xIn + 32, yA1], [xTurnA, yA1], [xTurnA, yA2], [xIn + 32, yA2]], cuts);
        lane('B', [[xIn + 32, yB1], [xTurnB, yB1], [xTurnB, yB2], [xIn + 32, yB2]], cuts);
        N.label('la', xIn + 40, yA1 - 10, 'L', 'strong', 'start', 13);
        N.label('lb', xIn + 40, yB1 - 10, 'R', 'strong', 'start', 13);
        // the readout of the current round
        if (at >= 1 && at <= 16 && narrow) {
          const r = R[at - 1], x0 = D.follow(view, colX(at), 420).x + 14;
          N.label('r1', x0, 488, `round ${at}:  ${hx(r.L)} ⊕ ${hx(r.f.P)}`, 'math', 'start', 14);
          N.label('r3', x0, 512, `K = ${hx(r.K)}`, 'key', 'start', 14);
          N.label('r5', x0, 536, `= ${hx(r.newR)}`, 'hot', 'start', 14);
        } else if (at >= 1 && at <= 16) {
          const r = R[at - 1], sub = (n) => String(n).replace(/\d/g, (d) => '₀₁₂₃₄₅₆₇₈₉'[d]);
          const y = 494;
          N.label('r1', 160, y, `round ${at}`, 'act', 'start', 15);
          N.label('r2', 280, y, `in: ${hx(r.L)} ${hx(r.R)}`, 'math', 'start', 14);
          N.label('r3', 520, y, `K${sub(at)} = ${hx(r.K)}`, 'key', 'start', 14);
          N.label('r4', 740, y, `f = ${hx(r.f.P)}`, 'math', 'start', 14);
          N.label('r5', 900, y, `new: ${hx(r.newR)}`, 'hot', 'start', 14);
        }
        return N.items;
      };
      const frames = [];
      frames.push({ view, narrowView: D.follow(view, 150, 420), items: build(0), say: `The plaintext \`tidepool\` (\`${DES.hex(DES.bits(D.data.desPlain))}\`) goes through the initial permutation and splits into L₀ = \`${hx(R[0].L)}\` on the top lane and R₀ = \`${hx(R[0].R)}\` below it.` });
      for (let k = 1; k <= 16; k++) {
        const r = R[k - 1];
        frames.push({ view, narrowView: D.follow(view, colX(k), 420), items: build(k), say: `Round ${k}: f of one half, under K${k}, is XORed into the other: \`${hx(r.L)}\` ⊕ \`${hx(r.f.P)}\` = \`${hx(r.newR)}\`.${k === 1 ? ' Then the roles swap: the half just changed feeds f next.' : k === 8 ? ' The lanes turn the corner; they never cross.' : ''}` });
      }
      frames.push({ view, narrowView: D.follow(view, 150, 420), items: build(17), say: `After round 16 the lane changed last leaves first, which is exactly the final swap; FP then gives the ciphertext \`${DES.hex(DES.bits(res.out))}\`. Decryption runs the same ladder with the keys K₁₆ … K₁.` });
      return frames;
    },
  });
})(globalThis.Sifer = globalThis.Sifer || {});
