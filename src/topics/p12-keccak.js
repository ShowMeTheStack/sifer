// Part 12, Keccak-f on the state: θ drawn on the 25 lanes of 64 bits with the column parities C and their effect D
// (and one lone bit spreading to eleven), then ρ, π, χ and ι of any round, each drawn where it acts: the offsets of
// ρ, the lanes of π gliding to their new places, the rows of χ, and the round constant of ι.
(function (S) {
  'use strict';
  const U = S.P12, K = () => S.Keccak;
  const { t } = U;
  const BY = () => S.Kit.bytes;
  const popc = (st) => st.reduce((n, v) => n + v.toString(2).split('1').length - 1, 0);
  const bitOf = (v, z) => Number((v >> BigInt(z)) & 1n);
  /** the state after absorbing a one-block message (padded as SHA3-256 does), before round 0 */
  const absorbed = (msg) => { const m = U.utf8(msg), blk = new Uint8Array(136); blk.set(m); blk[m.length] ^= 0x06; blk[135] ^= 0x80; return K().fromBytes(blk); };
  const msgInput = { id: 'msg', kind: 'text', label: 'Message', def: 'keccak sees all', check: (v) => (U.utf8(v).length > 135 ? 'Message: at most 135 bytes (one block)' : null) };

  // ---------------------------------------------------------------------------------------------------------------
  // θ
  // ---------------------------------------------------------------------------------------------------------------
  function theta(inp) {
    const Kc = K(), A = absorbed(inp.msg), th = Kc.theta(A), A2 = th.A;
    const L = { lx: 64, ly: 74, cw: 13, ch: 9, ygap: 5, cy: 346, cch: 11, dy: 436, iso: [40, 494], isoS: 17, isoD: 130 };
    let X = +inp.x, Z = +inp.z;
    if (inp.pick === 'auto') { outer: for (let k = 0; k < 64; k++) { const z = (k + 26) % 64; for (let x = 1; x < 4; x++) if ((th.C[x] >> BigInt(z)) & 1n) { X = x; Z = z; break outer; } } }
    const xm = (X + 4) % 5, xp = (X + 1) % 5, zm = (Z + 63) % 64;
    const lanes = (st, look) => BY().lanes({ prefix: 'kl', x: L.lx, y: L.ly, A: st, cw: L.cw, ch: L.ch, ygap: L.ygap, look });
    const plane = (key, y, vals, look, title, sb) => {
      const rows = vals.map((v, x) => { let s = ''; for (let z = 0; z < 64; z++) s += look(x, z, bitOf(v, z)); return s; });
      const items = [{ key: key + ':bm', kind: 'bitmap', x: L.lx, y, cw: L.cw, ch: L.cch, gap: 1.5, rows }];
      items.push(t(key + ':t', L.lx, y - 9, title, 'strong', 'start', 14));
      if (sb) items.push(t(key + ':s', L.lx + 64 * L.cw, y - 9, sb, '', 'end', 13));
      for (const x of [0, 2, 4]) items.push({ key: key + ':x' + x, kind: 'text', x: L.lx - 8, y: y + x * L.cch + L.cch - 1.5, text: 'x=' + x, anchor: 'end', size: 13, audit: 'small-ok' });
      return items;
    };
    const frame = () => {
      const items = [], gh = 5 * L.ch + L.ygap;
      for (let y = 0; y < 5; y++) items.push(t('kf:y' + y, L.lx - 10, L.ly + y * gh + 2.5 * L.ch + 4, 'y=' + y, 'strong', 'end', 13));
      items.push(t('kf:z0', L.lx, L.ly - 8, 'z = 0', '', 'start', 13), t('kf:z63', L.lx + 64 * L.cw, L.ly - 8, '63', '', 'end', 13));
      items.push(t('kf:lx', L.lx + 32 * L.cw, L.ly - 8, 'each row is a lane (x = 0…4 inside each group)', '', 'middle', 13));
      items.push(...U.legend('kf:lg', 300, 600, [['p12-b1', 'a 1 bit'], ['p12-b3', 'bits read'], ['p12-b2', 'bits written or flipped']], 13));
      items.push(t('kf:cap', 300, 560, 'The block on the left is the same state: x across, y up, z going back.', 'ptick', 'start', 13));
      return items;
    };
    const zs = (z) => Math.floor(z / 4);
    const iso = (hot, act) => {
      const r = BY().iso({ prefix: 'iso', x: L.iso[0], y: L.iso[1], s: L.isoS, depth: L.isoD, slices: 16, hot, act });
      const items = r.items.slice(), p0 = r.pt(0, 0, 0), p1 = r.pt(5, 0, 0), pz = r.pt(5, 0, 16);
      items.push(t('iso:lx', (p0[0] + p1[0]) / 2, p0[1] + 18, 'x →', '', 'middle', 13), t('iso:ly', p0[0] - 8, (p0[1] + r.pt(0, 5, 0)[1]) / 2 + 4, 'y', '', 'end', 13), t('iso:lz', (p1[0] + pz[0]) / 2 + 12, (p1[1] + pz[1]) / 2 + 14, 'z (64 slices)', '', 'start', 13));
      return items;
    };
    const F = new S.Frames(['flipped']);
    F.add({ items: [...frame(), ...lanes(A).items, ...iso([], [])], hl: { d: [0] }, say: `The 1600-bit state after absorbing “${U.cut(inp.msg, 40)}” with its padding: ${popc(A)} bits are set, all in the lanes the 136-byte block reached.`, facts: { ones: popc(A) }, meta: { stage: 'start' } });
    const colLook = (x, y, z, b) => (x === X && z === Z ? (b ? '3' : '7') : b ? '1' : '0');
    const cxz = bitOf(th.C[X], Z);
    F.add({ items: [...frame(), ...lanes(A, colLook).items, ...iso([], [{ x: X, z: zs(Z) }]), ...plane('kc', L.cy, th.C, (x, z, b) => (x === X && z === Z ? '3' : b ? '1' : '0'), 'C[x] = parity of each column', `C[${X}] at z = ${Z} is ${cxz}`)], hl: { d: [1] }, say: `Column (x = ${X}, z = ${Z}) is the five bits of lanes (${X}, 0) … (${X}, 4) at position ${Z}, lit in blue. Their XOR is C[${X}][${Z}] = ${cxz}. The plane C holds all 5 × 64 = 320 parities.`, facts: { X, Z, c: cxz, n: 320 }, meta: { stage: 'C' } });
    const dxz = bitOf(th.D[X], Z), cm = bitOf(th.C[xm], Z), cp = bitOf(th.C[xp], zm);
    const cSrc = (x, z, b) => ((x === xm && z === Z) || (x === xp && z === zm) ? '3' : b ? '1' : '0');
    F.add({ items: [...frame(), ...lanes(A, (x, y, z, b) => (x === X && z === Z ? '2' : b ? '1' : '0')).items, ...iso([{ x: X, z: zs(Z) }], [{ x: xm, z: zs(Z) }, { x: xp, z: zs(zm) }]), ...plane('kc', L.cy, th.C, cSrc, 'C[x] = parity of each column', ''), ...plane('kd', L.dy, th.D, (x, z, b) => (x === X && z === Z ? '2' : b ? '1' : '0'), 'D[x] = C[x−1] ⊕ (C[x+1] rotated by 1)', `D[${X}][${Z}] = C[${xm}][${Z}] ⊕ C[${xp}][${zm}] = ${dxz}`)], hl: { d: [2] }, say: `D[${X}][${Z}] mixes two columns: the one to the left at the same z, C[${xm}][${Z}] = ${cm}, and the one to the right one slice back, C[${xp}][${zm}] = ${cp}. Their XOR is ${dxz}; that bit is XORed into all five bits of column (${X}, ${Z}).`, facts: { X, Z, xm, xp, zm, cm, cp, d: dxz }, meta: { stage: 'D' } });
    let flips = 0;
    const after = (x, y, z, b) => { const was = bitOf(A[x + 5 * y], z); if (was !== b) { flips++; return '2'; } return b ? '1' : '0'; };
    const it3 = lanes(A2, after).items;
    F.set('flipped', flips);
    F.add({ items: [...frame(), ...it3, ...iso([], []), ...plane('kd', L.dy, th.D, (x, z, b) => (b ? '2' : '0'), 'D[x]: where D is 1, the whole column of the state flips', '')], hl: { d: [3] }, say: `After θ: the ${flips} bits that flipped are lit. Wherever D is 1, all five bits of that column flip, so the flips come in stripes of five, one in each group. The state now has ${popc(A2)} bits set.`, facts: { flips, ones: popc(A2) }, meta: { stage: 'after' } });
    const one = new Array(25).fill(0n); one[2 + 5 * 1] = 1n << 30n;
    const t1 = K().theta(one).A, n1 = popc(t1);
    F.set('flipped', n1 - 1);
    F.add({ items: [...frame(), ...lanes(t1, (x, y, z, b) => (x === 2 && y === 1 && z === 30 ? '3' : b ? '2' : '0')).items, ...iso([{ x: 1, z: zs(30) }, { x: 3, z: zs(31) }], [{ x: 2, z: zs(30) }])], hl: { d: [3] }, say: `Start instead from a single bit, at x = 2, y = 1, z = 30 (blue). It changes the parity of its column, so θ flips the two columns that read that parity: x = 1 at z = 30, and x = 3 at z = 31. One bit becomes ${n1}, and θ runs again at the start of each of the 24 rounds.`, facts: { n1, rounds: 24, pos: [2, 1, 30, 31, 3] }, meta: { stage: 'one' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('θ (theta)', ['C[x][z] = A[x,0][z] ⊕ A[x,1][z] ⊕ … ⊕ A[x,4][z]', 'D[x][z] = C[x−1][z] ⊕ C[x+1][z−1]', 'A[x,y][z] ← A[x,y][z] ⊕ D[x][z]', 'each bit now depends on 11 bits']) };
  }
  S.topic({
    id: 'p12-theta', family: 'p12-sha3', order: 20, title: 'Keccak θ: every bit takes in two nearby columns',
    blurb: 'The state as 25 lanes of 64 bits, grouped by y. θ XORs into every bit the parities of two columns beside it, so one bit spreads to eleven in a single step.',
    inputs: [msgInput, { id: 'pick', kind: 'choice', label: 'Column to follow', def: 'auto', options: [{ value: 'auto', label: 'one with parity 1' }, { value: 'given', label: 'the x and z below' }] }, { id: 'x', kind: 'number', label: 'x', def: 2, min: 0, max: 4 }, { id: 'z', kind: 'number', label: 'z', def: 5, min: 0, max: 63 }],
    presets: [
      { label: 'Our message', values: { msg: 'keccak sees all', pick: 'auto' } },
      { label: 'The empty message', values: { msg: '', pick: 'auto' } },
      { label: 'Column (0, 0)', values: { msg: 'keccak sees all', pick: 'given', x: 0, z: 0 } },
    ],
    counters: [{ id: 'flipped', label: 'bits flipped' }],
    run: theta,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'after', pick: 'option', options: ['3', '5', '11', '64'], ask: 'A state with a single 1 bit goes through θ. How many bits are set afterwards?', answer: '11', explain: 'The bit itself, plus two whole columns of five.' }],
    quiz: [
      { q: 'What is a column in the Keccak state?', options: ['a lane', 'the five bits with the same x and z', 'the 64 bits of a lane', 'a slice'], answer: 1, why: 'Five bits, one from each lane (x, 0) … (x, 4), at the same z.' },
      { q: 'Which columns does θ add into column (x, z)?', options: ['(x−1, z) and (x+1, z−1)', '(x, z−1) and (x, z+1)', 'all columns', 'none'], answer: 0, why: 'D[x][z] = C[x−1][z] ⊕ C[x+1][z−1].' },
      { q: 'Is θ linear?', options: ['yes, it is all XOR', 'no', 'only on the capacity', 'only in round 0'], answer: 0, why: 'θ, ρ, π and ι are linear (or affine); χ is the only non-linear step.' },
      { q: 'A state where every column has even parity goes through θ. What changes?', options: ['everything', 'nothing: C and D are all zero', 'only lane (0, 0)', 'half the bits'], answer: 1, why: 'All parities are 0, so D is 0 and θ does nothing: such states are its kernel.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // ρ, π, χ, ι
  // ---------------------------------------------------------------------------------------------------------------
  function steps(inp) {
    const Kc = K(), rd = +inp.round;
    let A = absorbed(inp.msg);
    for (let i = 0; i < rd; i++) A = Kc.round(A, i).A;
    const R = Kc.round(A, rd).steps, th = R.theta.A, rh = R.rho.A, pi = R.pi.A, ch = R.chi.A, io = R.iota.A;
    const cw = 118, chh = 58, gx = 40, gy = 92;
    const pos = (x, y) => ({ x: gx + x * (cw + 6), y: gy + y * (chh + 6) });
    // the 5 × 5 lanes; key by the lane's origin before π, so π glides
    const grid = (st, o) => {
      o = o || {};
      const items = [];
      for (let i = 0; i < 5; i++) items.push(t('kg:cx' + i, gx + i * (cw + 6) + cw / 2, gy - 10, 'x = ' + i, 'ptick', 'middle', 13), t('kg:ry' + i, gx - 8, gy + i * (chh + 6) + chh / 2 + 4, 'y=' + i, 'ptick', 'end', 13));
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
        const src = o.from ? o.from(x, y) : x + 5 * y, p = pos(x, y), v = st[x + 5 * y];
        const h = Kc.hex(v);
        items.push({ key: 'kg:' + src, kind: 'cell', x: p.x, y: p.y, w: cw, h: chh, rx: 5, lines: [o.label ? o.label(x, y, src) : '(' + (src % 5) + ', ' + Math.floor(src / 5) + ')', h.slice(0, 8), h.slice(8)], size: 13, cls: 'hex ' + (o.cls ? o.cls(x, y, src) || '' : '') });
      }
      return items;
    };
    const lanes = (st, prev, extra) => {
      const look = (x, y, z, b) => { const was = prev ? bitOf(prev[x + 5 * y], z) : b; if (extra) { const e = extra(x, y, z, b); if (e) return e; } return was !== b ? '2' : b ? '1' : '0'; };
      const r = BY().lanes({ prefix: 'kl', x: 40, y: 448, A: st, cw: 13, ch: 6, ygap: 4, look, cellGap: 1 });
      return [...r.items, t('kl:t', 40, 438, 'the 25 lanes, 64 bits each; changed bits lit', 'ptitle')];
    };
    const diff = (a, b) => a.reduce((n, v, i) => n + popc([v ^ b[i]]), 0);
    const side = (title, rows) => {
      const items = U.panel('kp', 680, 84, 230, 330, '');
      items.push(t('kp:t', 694, 106, title, 'strong', 'start', 13));
      rows.forEach(([l, v, c], i) => { items.push(t('kp:l' + i, 694, 128 + i * 26, l, c || '', 'start', 13)); if (v !== undefined) items.push(t('kp:v' + i, 896, 128 + i * 26, v, 'mono ' + (c || ''), 'end', 13)); });
      return items;
    };
    const F = new S.Frames(['changed']);
    const head = U.head('ks:h', 'Round ' + rd + ' of 24: ρ, π, χ and ι');
    F.add({ items: [...head, ...grid(th), ...side('after θ', [['bits set', String(popc(th))], ['lanes shown as', ''], ['16 hex digits,', ''], ['bit 63 first', '']]), ...lanes(th)], hl: { d: [0] }, say: `Round ${rd} begins after θ: ${popc(th)} bits are set. Each cell is one lane (x, y), its 64 bits in hex.`, facts: { rd, ones: popc(th) }, meta: { stage: 'start' } });
    // ρ
    const z0 = (() => { for (let z = 0; z < 64; z++) if (bitOf(th[1], z)) return z; return 0; })(), z1 = (z0 + Kc.R[1]) % 64;
    const nR = diff(th, rh);
    F.set('changed', nR);
    F.add({ items: [...head, ...grid(rh, { label: (x, y, s) => '(' + x + ', ' + y + ')  ⟲ ' + Kc.R[s], cls: (x, y) => (x === 1 && y === 0 ? 'act' : '') }), ...side('ρ: rotate each lane', [['offsets r[x, y], y = 0…4', '', 'strong'], ...[0, 1, 2, 3, 4].map((y) => ['y = ' + y, [0, 1, 2, 3, 4].map((x) => Kc.R[x + 5 * y]).join(' '), y === 0 ? 'act' : '']), ['lane (1, 0): bit ' + z0, '→ ' + z1, 'act']]), ...lanes(rh, th, (x, y, z) => (x === 1 && y === 0 && z === z1 ? '3' : ''))], hl: { d: [1] }, say: `ρ rotates every lane by its own fixed offset, from 0 for lane (0, 0) to 62; lane (1, 0) turns by ${Kc.R[1]}, so its bit ${z0} moves to bit ${z1}. Nothing moves between lanes; ${nR} bit positions now hold a different value.`, facts: { R: Kc.R, z0, z1, n: nR, max: 62 }, meta: { stage: 'rho' } });
    // π: lane (x, y) goes to (y, 2x + 3y); key each cell by where its lane came from
    const fromPi = (X, Y) => { for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) if (y === X && (2 * x + 3 * y) % 5 === Y) return x + 5 * y; return 0; };
    const ex = { x: 1, y: 0 }, dest = { x: ex.y, y: (2 * ex.x + 3 * ex.y) % 5 };
    F.add({ items: [...head, ...grid(rh, { cls: (x, y) => (x === ex.x && y === ex.y ? 'act' : '') }), ...side('π: move the lanes', [['(x, y) → (y, 2x + 3y)', '', 'strong'], ['about to move:', ''], ['(1, 0) → (0, 2)', '', 'act'], ['(0, 0) stays put', ''], ['each lane keeps', ''], ['its 64 bits intact', '']]), ...lanes(rh)], hl: { d: [2] }, say: `π moves whole lanes: lane (x, y) goes to (y, 2x + 3y mod 5). Lane (1, 0), lit, will move to (${dest.x}, ${dest.y}); only lane (0, 0) stays where it is.`, facts: { dest: [dest.x, dest.y] }, meta: { stage: 'pi-before' } });
    F.set('changed', diff(rh, pi));
    F.add({ items: [...head, ...grid(pi, { from: fromPi, cls: (x, y, s) => (s === ex.x + 5 * ex.y ? 'act' : '') }), ...side('π: done', [['(x, y) → (y, 2x + 3y)', '', 'strong'], ['the cells glided to', ''], ['their new places', ''], ['lane (1, 0) is now', ''], ['at (' + dest.x + ', ' + dest.y + ')', '', 'act']]), ...lanes(pi, rh)], hl: { d: [2] }, say: `After π every lane sits in its new place (watch them glide). Neighbours that ρ left side by side are now far apart, so the next step mixes bits that came from distant lanes.`, facts: {}, meta: { stage: 'pi' } });
    // χ on row y = 0 at one z
    const zc = (() => { for (let z = 0; z < 64; z++) { const b = [0, 1, 2, 3, 4].map((x) => bitOf(pi[x], z)); if (b.some((v, x) => v !== bitOf(ch[x], z))) return z; } return 0; })();
    const rowB = [0, 1, 2, 3, 4].map((x) => bitOf(pi[x], zc)), rowA = [0, 1, 2, 3, 4].map((x) => bitOf(ch[x], zc));
    const nC = diff(pi, ch);
    F.set('changed', nC);
    F.add({ items: [...head, ...grid(ch, { from: fromPi, cls: (x, y) => (y === 0 ? 'act' : '') }), ...side('χ on row y = 0, bit z = ' + zc, [['a[x] ⊕= (¬a[x+1]) ∧ a[x+2]', '', 'strong'], ['before', rowB.join(' ')], ['after', rowA.join(' '), 'hot'], ['bits flipped in', ''], ['the whole state', String(nC), 'hot'], ['the only step', ''], ['that is not linear', '']]), ...lanes(ch, pi, (x, y, z) => (y === 0 && z === zc ? '3' : ''))], hl: { d: [3] }, say: `χ works along each row of five bits: a bit flips when its right neighbour is 0 and the next one is 1. On row y = 0 at z = ${zc} the bits ${rowB.join(' ')} become ${rowA.join(' ')}. Over the whole state ${nC} bits flip. The AND makes χ the only non-linear step; without it Keccak would be linear algebra.`, facts: { zc, rowB, rowA, n: nC }, meta: { stage: 'chi' } });
    // ι
    const rc = Kc.RC[rd], ones = popc([rc]);
    F.set('changed', ones);
    F.add({ items: [...head, ...grid(io, { from: fromPi, cls: (x, y) => (x === 0 && y === 0 ? 'hot' : '') }), ...side('ι: the round constant', [['lane (0, 0) before', ''], [Kc.hex(ch[0]), '', 'mono'], ['⊕ RC[' + rd + ']', ''], [Kc.hex(rc), '', 'mono key'], ['=', ''], [Kc.hex(io[0]), '', 'mono hot']]), ...lanes(io, ch)], hl: { d: [4] }, say: `ι XORs the round constant RC[${rd}] = ${Kc.hex(rc)} into lane (0, 0) alone: ${U.plural(ones, 'bit')}. Without it all 24 rounds would be the same, and the state that is all zero would stay all zero.`, facts: { rd, rc: Kc.hex(rc), ones, lane: [Kc.hex(ch[0]), Kc.hex(io[0])], rounds: 24 }, meta: { stage: 'iota' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('One round: θ, then', ['θ: each bit ⊕= two column parities', 'ρ: lane (x, y) rotated by r[x, y]', 'π: lane (x, y) moves to (y, 2x + 3y)', 'χ: a[x] ⊕= (¬a[x+1]) ∧ a[x+2] along rows', 'ι: lane (0, 0) ⊕= RC[round]']) };
  }
  S.topic({
    id: 'p12-keccak', family: 'p12-sha3', order: 30, title: 'Keccak ρ, π, χ and ι, each on the state',
    blurb: 'After θ come a rotation of every lane, a shuffle of the lanes, the one non-linear step along the rows, and a round constant. Watch each act on the 5 × 5 lanes and on their 1600 bits.',
    inputs: [msgInput, { id: 'round', kind: 'number', label: 'Round', def: 0, min: 0, max: 23 }],
    presets: [
      { label: 'Round 0 of our message', values: { msg: 'keccak sees all', round: 0 } },
      { label: 'Round 1', values: { msg: 'keccak sees all', round: 1 } },
      { label: 'Round 23, the last', values: { msg: 'keccak sees all', round: 23 } },
      { label: 'The empty message, round 0', values: { msg: '', round: 0 } },
    ],
    counters: [{ id: 'changed', label: 'bits changed' }],
    run: steps,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'pi-before', pick: 'item', ask: 'Lane (1, 0) is about to move under π. Click the cell where it will land.', answer: () => ['kg:10'], explain: '(1, 0) → (0, 2·1 + 3·0) = (0, 2).' }],
    quiz: [
      { q: 'Which step of Keccak-f is non-linear?', options: ['θ', 'ρ', 'χ', 'ι'], answer: 2, why: 'χ uses an AND; the others are XORs, rotations and moves.' },
      { q: 'What does π do?', options: ['rotates bits within a lane', 'moves whole lanes to new positions', 'adds a constant', 'XORs columns'], answer: 1, why: '(x, y) → (y, 2x + 3y).' },
      { q: 'Why does ι exist?', options: ['for diffusion', 'to break the symmetry between rounds and positions', 'to pad the message', 'to output the digest'], answer: 1, why: 'Without constants every round is identical and the state 0 is fixed.' },
      { q: 'How many rounds does Keccak-f[1600] run?', options: ['12', '16', '24', '64'], answer: 2, why: '12 + 2ℓ with ℓ = 6 for 64-bit lanes.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
