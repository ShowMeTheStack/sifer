// Keccak's θ step on the 5×5×64 state: the state as 25 lanes of 64 bits (with an isometric hint of the block), the
// column parities C, the effect D = C[x−1] ⊕ rot(C[x+1], 1), and the state after θ with every flipped bit lit.
(function (S) {
  'use strict';
  const D = S.Demo, Kc = S.Keccak, BY = S.Kit.bytes, box = D.box;
  D.add({
    id: 'keccak-theta', order: 60, tag: 'SHA-3 · Keccak-f', short: 'Keccak θ', title: 'Keccak θ: every bit takes in two nearby columns',
    blurb: 'Each lane is a row of 64 bits; the 25 lanes are grouped by y. A column is the five bits with the same x and z. θ XORs into every bit the parities of two columns beside it.',
    frames({ narrow }) {
      // the state after absorbing our message: the padded block XORed into the zero state, before round 0
      const msg = D.data.keccakMsg, blk = new Uint8Array(136);
      blk.set(msg); blk[msg.length] ^= 0x06; blk[135] ^= 0x80;
      const A = Kc.fromBytes(blk), th = Kc.theta(A), A2 = th.A;
      const L = narrow
        ? { view: box(-30, -26, 400, 760), lx: 0, ly: 10, cw: 5.5, ch: 5.5, ygap: 4, cy: 220, cch: 7, dy: 300, iso: [40, 420], isoS: 26, isoD: 160, labels: false }
        : { view: box(-70, -40, 1240, 600), lx: 360, ly: 20, cw: 12.5, ch: 10.5, ygap: 6, cy: 360, cch: 12, dy: 460, iso: [-20, 40], isoS: 30, isoD: 210, labels: true };
      // the column to follow: one whose parity is 1
      let X = 0, Z = 0;
      outer: for (let k = 0; k < 64; k++) { const z = (k + 26) % 64; for (let x = 1; x < 4; x++) if ((th.C[x] >> BigInt(z)) & 1n) { X = x; Z = z; break outer; } }
      const xm = (X + 4) % 5, xp = (X + 1) % 5, zm = (Z + 63) % 64;
      const bitOf = (v, z) => Number((v >> BigInt(z)) & 1n);
      const lanes = (st, look) => BY.lanes({ prefix: 'kl', x: L.lx, y: L.ly, A: st, cw: L.cw, ch: L.ch, ygap: L.ygap, look });
      const plane = (key, y, vals, look, title, sub) => {
        const rows = vals.map((v, x) => { let s = ''; for (let z = 0; z < 64; z++) s += look(x, z, bitOf(v, z)); return s; });
        const items = [{ key: key + ':bm', kind: 'bitmap', x: L.lx, y, cw: L.cw, ch: L.cch, gap: narrow ? 1 : 1.5, rows }];
        items.push({ key: key + ':t', kind: 'text', x: L.lx, y: y - 9, text: title, cls: 'strong', size: narrow ? 12 : 14 });
        if (sub && !narrow) items.push({ key: key + ':s', kind: 'text', x: L.lx + 64 * L.cw, y: y - 9, text: sub, anchor: 'end', size: 13 });
        if (L.labels) for (let x = 0; x < 5; x++) items.push({ key: key + ':x' + x, kind: 'text', x: L.lx - 8, y: y + x * L.cch + L.cch - 1.5, text: 'x=' + x, anchor: 'end', size: 11, audit: 'small-ok' });
        return items;
      };
      const frame = (st) => {
        const items = [];
        const gh = 5 * L.ch + L.ygap;
        if (L.labels) {
          for (let y = 0; y < 5; y++) items.push({ key: 'kf:y' + y, kind: 'text', x: L.lx - 10, y: L.ly + y * gh + 2.5 * L.ch + 4, text: 'y=' + y, anchor: 'end', size: 13, cls: 'strong' });
          items.push({ key: 'kf:z0', kind: 'text', x: L.lx, y: L.ly - 8, text: 'z = 0', size: 12 });
          items.push({ key: 'kf:z63', kind: 'text', x: L.lx + 64 * L.cw, y: L.ly - 8, text: '63', size: 12, anchor: 'end' });
          items.push({ key: 'kf:lx', kind: 'text', x: L.lx + 32 * L.cw, y: L.ly - 8, text: 'each row is a lane (x = 0…4 inside each group)', size: 12, anchor: 'middle' });
        } else items.push({ key: 'kf:t', kind: 'text', x: L.lx, y: L.ly - 10, text: '25 lanes × 64 bits, in 5 groups by y', cls: 'strong', size: 12 });
        return items;
      };
      const iso = (hot, act) => {
        const r = BY.iso({ prefix: 'iso', x: L.iso[0], y: L.iso[1], s: L.isoS, depth: L.isoD, slices: 16, hot, act });
        const items = r.items.slice();
        const p0 = r.pt(0, 0, 0), p1 = r.pt(5, 0, 0), pz = r.pt(5, 0, 16);
        items.push({ key: 'iso:lx', kind: 'text', x: (p0[0] + p1[0]) / 2, y: p0[1] + 18, text: 'x →', anchor: 'middle', size: 13 });
        items.push({ key: 'iso:ly', kind: 'text', x: p0[0] - 8, y: (p0[1] + r.pt(0, 5, 0)[1]) / 2 + 4, text: 'y', anchor: 'end', size: 13 });
        items.push({ key: 'iso:lz', kind: 'text', x: (p1[0] + pz[0]) / 2 + 12, y: (p1[1] + pz[1]) / 2 + 14, text: 'z (64 slices)', anchor: 'start', size: 13 });
        return items;
      };
      // the hint shows 16 of the 64 slices: z is folded onto them
      const zs = (z) => Math.floor(z / 4);
      const view = L.view, frames = [];
      const ones = (st) => st.reduce((n, v) => n + v.toString(2).split('1').length - 1, 0);
      frames.push({ view, items: [...frame(), ...lanes(A).items, ...iso([], [])], say: `The 1600-bit state after absorbing “keccak sees all” with its padding: ${ones(A)} bits are set, all in the first lanes and in the last lane of the 136-byte block.` });
      const colLook = (x, y, z, b) => (x === X && z === Z ? (b ? '3' : '7') : b ? '1' : '0');
      frames.push({ view, items: [...frame(), ...lanes(A, colLook).items, ...iso([], [{ x: X, z: zs(Z) }]), ...plane('kc', L.cy, th.C, (x, z, b) => (x === X && z === Z ? '3' : b ? '1' : '0'), 'C[x] = parity of each column', `C[${X}] at z = ${Z} is ${bitOf(th.C[X], Z)}`)],
        say: `Column (x = ${X}, z = ${Z}) is the five bits of lanes (${X}, 0) … (${X}, 4) at position ${Z}, lit in blue. Their XOR is C[${X}][${Z}] = ${bitOf(th.C[X], Z)}. The plane C holds all 5 × 64 = 320 parities.` });
      const dLook = (x, z, b) => (x === X && z === Z ? '2' : b ? '1' : '0');
      const cSrc = (x, z, b) => ((x === xm && z === Z) || (x === xp && z === zm) ? '3' : b ? '1' : '0');
      frames.push({ view, items: [...frame(), ...lanes(A, (x, y, z, b) => (x === X && z === Z ? '2' : b ? '1' : '0')).items, ...iso([{ x: X, z: zs(Z) }], [{ x: xm, z: zs(Z) }, { x: xp, z: zs(zm) }]), ...plane('kc', L.cy, th.C, cSrc, 'C[x] = parity of each column', ''), ...plane('kd', L.dy, th.D, dLook, 'D[x] = C[x−1] ⊕ (C[x+1] rotated by 1)', `D[${X}][${Z}] = C[${xm}][${Z}] ⊕ C[${xp}][${zm}] = ${bitOf(th.D[X], Z)}`)],
        say: `D[${X}][${Z}] mixes two columns: the one to the left at the same z, C[${xm}][${Z}] = ${bitOf(th.C[xm], Z)}, and the one to the right one slice back, C[${xp}][${zm}] = ${bitOf(th.C[xp], zm)}. Their XOR is ${bitOf(th.D[X], Z)}; that bit is XORed into all five bits of column (${X}, ${Z}).` });
      let flips = 0;
      const after = (x, y, z, b) => { const was = Number((A[x + 5 * y] >> BigInt(z)) & 1n); if (was !== b) { flips++; return '2'; } return b ? '1' : '0'; };
      const it3 = lanes(A2, after).items;
      frames.push({ view, items: [...frame(), ...it3, ...iso([], []), ...plane('kd', L.dy, th.D, (x, z, b) => (b ? '2' : '0'), 'D[x]: where D is 1, the whole column of the state flips', '')],
        say: `After θ: the ${flips} bits that flipped are lit. Wherever D is 1, all five bits of that column flip, which is why the flips come in vertical stripes of five, one in each group. The state now has ${ones(A2)} bits set.` });
      // one bit alone: θ spreads it to 11
      const one = new Array(25).fill(0n); one[2 + 5 * 1] = 1n << 30n;
      const t1 = Kc.theta(one).A;
      frames.push({ view, items: [...frame(), ...lanes(t1, (x, y, z, b) => (x === 2 && y === 1 && z === 30 ? '3' : b ? '2' : '0')).items, ...iso([{ x: 1, z: zs(30) }, { x: 3, z: zs(31) }], [{ x: 2, z: zs(30) }])],
        say: 'Start instead from a single bit, at x = 2, y = 1, z = 30 (blue). It changes the parity of its column, so θ flips the two columns that read that parity: x = 1 at z = 30, and x = 3 at z = 31. One bit becomes 11, and θ runs again at the start of each of the 24 rounds.' });
      return frames;
    },
  });
})(globalThis.Sifer = globalThis.Sifer || {});
