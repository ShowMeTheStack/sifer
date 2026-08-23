// Part 5's narration checks (set a: the state, the round steps, the key schedule), used by tests/claims-p05.mjs.
// Every value a frame states is worked out again with the reference AES of tests/claims-ref-aes.mjs.
import { S, hex, same, at } from './claims-lib-p05.mjs';
import * as R from './claims-ref-aes.mjs';

const U = S.P5;
const rb = (rnd, n) => Array.from({ length: n }, () => Math.floor(rnd() * 256));
const hx = (a) => hex(a);
const h = (v) => (v & 255).toString(16).padStart(2, '0');
const randBlock = (rnd) => hx(rb(rnd, 16));
const randKey = (rnd) => hx(rb(rnd, [16, 24, 32][Math.floor(rnd() * 3)]));

export const mods = [
  {
    topic: 'aes-overview', allow: ['3', '4', '7', '16', '32'],
    random: (rnd) => ({ pt: randBlock(rnd), key: randKey(rnd), pick: Math.floor(rnd() * 16) }),
    check({ input, r, fail }) {
      const P = U.block(input.pt), K = U.key(input.key), ref = R.encrypt([...P], [...K]);
      if (!same(ref.out, R.nodeEncrypt([...P], [...K]))) fail('the reference and node:crypto disagree');
      for (const f of at(r, 'block')) if (f.facts.Nr !== ref.Nr) fail('the number of rounds');
      for (const f of at(r, 'fill')) if (f.facts.r !== input.pick % 4 || f.facts.c !== Math.floor(input.pick / 4)) fail('the cell of the byte');
      for (const f of at(r, 'key')) if (!same(f.facts.k0, R.roundKey(ref.w, 0))) fail('round key 0');
      const rounds = at(r, 'round');
      if (rounds.length !== ref.Nr + 1) fail('one frame per round');
      for (const f of rounds) if (!same(f.facts.st, ref.rounds[f.facts.r].end)) fail('the state after round ' + f.facts.r);
      for (const f of at(r, 'out')) if (!same(f.facts.C, R.nodeEncrypt([...P], [...K]))) fail('the ciphertext against node:crypto');
    },
  },
  {
    topic: 'aes-subbytes', allow: ['3', '4', '5', '6', '7', '8', '16', '63'],
    random: (rnd) => ({ pt: randBlock(rnd), key: hx(rb(rnd, 16)), pick: Math.floor(rnd() * 16) }),
    check({ input, r, fail }) {
      const P = U.block(input.pt), K = U.key(input.key, [16]), ref = R.encrypt([...P], [...K]), st = ref.rounds[1].start, b = st[input.pick];
      for (const f of at(r, 'start')) if (!same(f.facts.st, st)) fail('the state entering round 1');
      for (const f of at(r, 'byte')) if (f.facts.b !== b) fail('the picked byte');
      for (const f of at(r, 'inv')) if (f.facts.v !== R.INV[b] || (b && (R.gmul(b, f.facts.v) !== 1 || f.facts.prod !== 1))) fail('the inverse of ' + h(b));
      for (const f of at(r, 'bit')) { const k = f.facts.r, v = R.INV[b]; const bit = [0, 4, 5, 6, 7].reduce((a, d) => a ^ ((v >> ((k + d) % 8)) & 1), (0x63 >> k) & 1); if (f.facts.bit !== bit) fail('affine bit ' + k); }
      for (const f of at(r, 'out')) if (f.facts.o !== R.SBOX[b]) fail('S(' + h(b) + ')');
      for (const f of at(r, 'all')) { const sub = R.subBytes(st); if (f.facts.changed !== sub.filter((x, i) => x !== st[i]).length || !same(f.facts.col0, sub.slice(0, 4))) fail('the substituted state'); }
    },
  },
  {
    topic: 'aes-sbox', allow: ['5', '7', '16', '63', '256', '00', '01', '05', '0f', 'ff'],
    random: (rnd) => ({ focus: h(Math.floor(rnd() * 256)), table: rnd() < 0.5 ? 'sbox' : 'inv' }),
    check({ input, r, fail }) {
      const inv = input.table === 'inv', T = inv ? R.ISBOX : R.SBOX, f = parseInt(input.focus, 16);
      for (const fr of at(r, 'rows')) if (!same(fr.facts.vals, T.slice(16 * fr.facts.r, 16 * fr.facts.r + 16))) fail('row ' + fr.facts.r);
      for (const fr of at(r, 'focus')) { if (fr.facts.out !== T[f]) fail('the looked-up entry'); if (!inv && fr.facts.inv !== R.INV[f]) fail('the inverse'); }
      for (const fr of at(r, 'props')) { if (fr.facts.distinct !== 256 || fr.facts.fixed !== 0 || fr.facts.opp !== 0) fail('the properties'); if (fr.facts.back !== f) fail('the round trip'); }
    },
  },
  {
    topic: 'aes-shiftrows', allow: ['3', '4'],
    random: (rnd) => ({ pt: randBlock(rnd), key: randKey(rnd), round: 1 + Math.floor(rnd() * 14), dir: rnd() < 0.5 ? 'enc' : 'inv' }),
    check({ input, r, fail }) {
      const P = U.block(input.pt), K = U.key(input.key), ref = R.encrypt([...P], [...K]), rd = Math.min(input.round, ref.Nr), inv = input.dir === 'inv';
      const st = inv ? ref.rounds[rd].shift : ref.rounds[rd].sub, out = inv ? R.invShiftRows(st) : R.shiftRows(st);
      const row = (s, k) => [0, 1, 2, 3].map((c) => h(s[k + 4 * c])).join(' ');
      for (const f of at(r, 'row')) if (f.facts.from !== row(st, f.facts.k) || f.facts.to !== row(out, f.facts.k)) fail('row ' + f.facts.k);
      for (const f of at(r, 'diag')) if (!same(f.facts.col0, out.slice(0, 4))) fail('the new column 0');
      if (!inv && !same(R.invShiftRows(out), st)) fail('InvShiftRows does not undo ShiftRows');
    },
  },
  {
    topic: 'aes-mixcolumns', allow: ['3', '4', '5', '01', '02', '03', '1b', '04', '08', '09', '0b', '0d', '0e'],
    random: (rnd) => ({ col: hx(rb(rnd, 4)), dir: rnd() < 0.5 ? 'mix' : 'inv' }),
    check({ input, r, fail }) {
      const col = [...S.bytes.fromHex(input.col)], inv = input.dir === 'inv', out = inv ? R.invMixColumn(col) : R.mixColumn(col);
      const M = inv ? [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]] : [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
      for (const f of at(r, 'row')) { const k = f.facts.r; if (f.facts.v !== out[k]) fail('row ' + k); if (!same(f.facts.terms, M[k].map((m, j) => R.gmul(m, col[j])))) fail('the products of row ' + k); }
      for (const f of at(r, 'end')) {
        if (!same(f.facts.out, out)) fail('the result');
        const c2 = col.slice(); c2[0] ^= 1; const o2 = inv ? R.invMixColumn(c2) : R.mixColumn(c2);
        if (f.facts.diffN !== o2.filter((v, i) => v !== out[i]).length) fail('the count of changed bytes');
        if (!same(f.facts.back, col)) fail('the inverse does not give the column back');
      }
    },
  },
  {
    topic: 'aes-addroundkey', allow: ['3', '8', '16'],
    random: (rnd) => ({ pt: randBlock(rnd), key: randKey(rnd), round: Math.floor(rnd() * 15), pick: Math.floor(rnd() * 16) }),
    check({ input, r, fail }) {
      const P = U.block(input.pt), K = U.key(input.key), ref = R.encrypt([...P], [...K]), rd = Math.min(input.round, ref.Nr), Rr = ref.rounds[rd];
      const st = rd === 0 ? Rr.start : Rr.mix || Rr.shift, k = R.roundKey(ref.w, rd);
      for (const f of at(r, 'start')) if (!same(f.facts.k, k)) fail('the round key');
      for (const f of at(r, 'col')) { const c = f.facts.c; if (!same(f.facts.o, R.xorB(st, k).slice(4 * c, 4 * c + 4))) fail('column ' + c); }
      for (const f of at(r, 'bits')) if (f.facts.o !== (st[input.pick] ^ k[input.pick])) fail('the picked byte');
      if (!same(R.xorB(st, k), Rr.end)) fail('the state after AddRoundKey');
    },
  },
  {
    topic: 'aes-keyexp', allow: ['4', '16', '40', '44', '11'],
    random: (rnd) => ({ key: hx(rb(rnd, 16)) }),
    check({ input, r, fail }) {
      const w = R.expand([...U.key(input.key, [16])]).w;
      for (const f of at(r, 'word')) { const i = f.meta.i; if (!same(f.facts.c || f.facts.w4, w[i])) fail('w' + i); }
      for (const f of at(r, 'rk')) { const k = f.facts.k; if (!same(f.facts.rk, R.roundKey(w, k)) || !same(f.facts.wi, w[4 * k])) fail('round key ' + k); let rc = 1; for (let j = 1; j < k; j++) rc = R.xt(rc); if (f.facts.rc !== rc) fail('Rcon(' + k + ')'); }
      for (const f of at(r, 'end')) if (!same(f.facts.rk, R.roundKey(w, 10))) fail('round key 10');
    },
  },
  {
    topic: 'aes-keysched-wide', allow: ['4', '6', '8'],
    random: (rnd) => ({ key: randKey(rnd), word: 4 + Math.floor(rnd() * 56) }),
    check({ input, r, fail }) {
      const K = [...U.key(input.key)], { w, Nk, Nr } = R.expand(K);
      for (const f of at(r, 'key')) if (f.facts.total !== w.length || f.facts.Nr !== Nr) fail('the word count');
      for (const f of at(r, 'row')) if (!same(f.facts.wb, w[f.facts.b])) fail('w' + f.facts.b);
      for (const f of at(r, 'focus')) if (!same(f.facts.c, w[f.facts.fi]) || !same(f.facts.a, w[f.facts.fi - Nk])) fail('the focused word');
      for (const f of at(r, 'compare')) { const want = [[44, 10, 0], [52, 8, 0], [60, 7, 6]]; f.facts.gs.forEach((g, k) => { if (g.t !== want[k][0] || g.g !== want[k][1] || g.s !== want[k][2]) fail('the comparison for ' + g.n * 8 + ' bits'); }); }
    },
  },
];
