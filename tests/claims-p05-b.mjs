// Part 5's narration checks (set b: the whole cipher, Mini-AES, T-tables and key sizes), used by tests/claims-p05.mjs.
// Every value a frame states is worked out again: AES with the reference of tests/claims-ref-aes.mjs and node:crypto,
// Mini-AES and the search times with arithmetic written here.
import { S, hex, same, near, at } from './claims-lib-p05.mjs';
import * as R from './claims-ref-aes.mjs';

const U = S.P5;
const rb = (rnd, n) => Array.from({ length: n }, () => Math.floor(rnd() * 256));
const randBlock = (rnd) => hex(rb(rnd, 16));
const randKey = (rnd) => hex(rb(rnd, [16, 24, 32][Math.floor(rnd() * 3)]));
const col = (s, c) => s.slice(4 * c, 4 * c + 4);

const cipherMods = [
  {
    topic: 'aes-encrypt', allow: ['16'],
    random: (rnd) => ({ pt: randBlock(rnd), key: randKey(rnd), pick: Math.floor(rnd() * 16), detail: rnd() < 0.3 ? 'all' : 'ends' }),
    check({ input, r, fail }) {
      const P = U.block(input.pt), K = U.key(input.key), ref = R.encrypt([...P], [...K]), Rd = ref.rounds;
      for (const f of at(r, 'start')) if (!same(f.facts.k0, R.roundKey(ref.w, 0)) || f.facts.n !== ref.Nr + 1) fail('round key 0');
      for (const f of at(r, 'sub')) { const x = f.facts; if (!same(x.st, Rd[x.r].sub) || x.inv !== R.INV[x.v] || x.s !== R.SBOX[x.v] || x.v !== Rd[x.r].start[input.pick]) fail('SubBytes in round ' + x.r); }
      for (const f of at(r, 'shift')) { const x = f.facts; if (!same(x.st, Rd[x.r].shift)) fail('ShiftRows in round ' + x.r); const p = input.pick, to = Rd[x.r].shift.findIndex((v, i) => i % 4 === p % 4 && (Math.floor(i / 4) + (p % 4)) % 4 === Math.floor(p / 4)); if (x.to !== Math.floor(to / 4)) fail('where the byte moves'); }
      for (const f of at(r, 'mix')) { const x = f.facts; if (!same(x.st, Rd[x.r].mix) || !same(x.out, R.mixColumn(col(Rd[x.r].shift, x.c))) || x.v !== x.out[x.rr] || x.terms.reduce((a, b) => a ^ b, 0) !== x.v) fail('MixColumns in round ' + x.r); }
      for (const f of at(r, 'ark')) { const x = f.facts; if (!same(x.st, Rd[x.r].end) || !same(x.k, R.roundKey(ref.w, x.r)) || (x.a ^ x.kb) !== x.b) fail('AddRoundKey in round ' + x.r); }
      for (const f of at(r, 'round')) { const x = f.facts; if (!same(x.st, Rd[x.r].end) || !same(x.a, Rd[x.r].start)) fail('round ' + x.r); }
      const out = at(r, 'out')[0];
      if (!out || !same(out.facts.C, R.nodeEncrypt([...P], [...K]))) fail('the ciphertext against node:crypto');
      if (at(r, 'ark').length + at(r, 'round').length !== ref.Nr + 1) fail('one AddRoundKey per round');
    },
  },
  {
    topic: 'aes-decrypt', allow: ['16', '09'], text: ['0e', '0b', '0d'],
    random: (rnd) => ({ ct: randBlock(rnd), key: randKey(rnd), pick: Math.floor(rnd() * 16), detail: rnd() < 0.3 ? 'all' : 'ends' }),
    check({ input, r, fail }) {
      const C = U.block(input.ct), K = U.key(input.key), ref = R.decrypt([...C], [...K]), P = R.nodeDecrypt([...C], [...K]), enc = R.encrypt(P, [...K]);
      if (!same(ref.out, P)) fail('the reference and node:crypto disagree');
      const byR = (rr) => ref.rounds.find((x) => x.round === rr);
      for (const f of at(r, 'ark0')) if (!same(f.facts.st, ref.rounds[0].end)) fail('the first AddRoundKey');
      for (const f of at(r, 'ishift')) if (!same(f.facts.st, byR(f.facts.r - 1).shift)) fail('InvShiftRows');
      for (const f of at(r, 'isub')) { const x = f.facts; if (!same(x.st, enc.rounds[x.m].end) || R.ISBOX[x.sv] !== x.out || R.INV[x.pre] !== x.out) fail('InvSubBytes and the matched state ' + x.m); }
      for (const f of at(r, 'iark')) if (!same(f.facts.st, byR(f.facts.r).added)) fail('AddRoundKey ' + f.facts.r);
      for (const f of at(r, 'imix')) { const x = f.facts; if (!same(x.out, R.invMixColumn(x.col)) || x.terms.reduce((a, b) => a ^ b, 0) !== x.v) fail('InvMixColumns'); }
      for (const f of at(r, 'round')) { const x = f.facts; if (!same(x.sub, enc.rounds[x.m].end)) fail('the matched state of undone round ' + x.r); }
      const out = at(r, 'out')[0];
      if (!out || !same(out.facts.P, P)) fail('the plaintext against node:crypto');
    },
  },
];

const pc = (x) => { let n = 0; while (x) { n += x & 1; x >>= 1; } return n; };
cipherMods.push({
  topic: 'aes-avalanche', allow: ['8', '16', '64', '128'],
  random: (rnd) => { const key = randKey(rnd), where = rnd() < 0.5 ? 'pt' : 'key'; return { pt: randBlock(rnd), key, where, byte: Math.floor(rnd() * (where === 'key' ? key.length / 2 : 16)), bit: Math.floor(rnd() * 8) }; },
  check({ input, r, fail }) {
    const P0 = [...U.block(input.pt)], K0 = [...U.key(input.key)], P1 = P0.slice(), K1 = K0.slice();
    (input.where === 'key' ? K1 : P1)[input.byte] ^= 1 << input.bit;
    const a = R.encrypt(P0, K0), b = R.encrypt(P1, K1);
    const d = a.rounds.map((x, k) => x.end.map((v, i) => v ^ b.rounds[k].end[i]));
    const bits = d.map((x) => x.reduce((n, v) => n + pc(v), 0)), bytes = d.map((x) => x.filter(Boolean).length);
    for (const f of at(r, 'round')) {
      const x = f.facts;
      if (x.bits !== bits[x.r] || x.bytes !== bytes[x.r]) fail('the difference after round ' + x.r);
      if (x.o0 !== undefined && (x.o0 !== R.SBOX[x.s0] || x.o1 !== R.SBOX[x.s1] || x.d !== pc(x.o0 ^ x.o1) || x.s0 !== a.rounds[1].start[input.byte])) fail('the S-box outputs of round 1');
      if (x.mean !== undefined) { const t = bits.slice(2); if (x.mean !== (t.reduce((p, q) => p + q, 0) / t.length).toFixed(1)) fail('the average'); }
    }
    if (at(r, 'round').length !== a.Nr + 1) fail('one frame per round');
    if (!same(R.nodeEncrypt(P0, K0), a.out) || !same(R.nodeEncrypt(P1, K1), b.out)) fail('the reference against node:crypto');
  },
});

// ---- Mini-AES, written again from its definition
const MS = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7];
const MI = []; MS.forEach((v, i) => { MI[v] = i; });
const m4 = (a, b) => { let r = 0; for (let i = 3; i >= 0; i--) { r <<= 1; if (r & 16) r ^= 0b10011; if ((b >> i) & 1) r ^= a; } return r; };
const nib = (x) => [(x >> 12) & 15, (x >> 8) & 15, (x >> 4) & 15, x & 15];
function miniKeys(k) {
  const w = nib(k);
  for (let r = 1; r <= 2; r++) { const b = 4 * r; w[b] = w[b - 4] ^ MS[w[b - 1]] ^ r; for (let j = 1; j < 4; j++) w[b + j] = w[b + j - 4] ^ w[b + j - 1]; }
  return [0, 1, 2].map((r) => w.slice(4 * r, 4 * r + 4));
}
const mMix = (n) => [m4(3, n[0]) ^ m4(2, n[1]), m4(2, n[0]) ^ m4(3, n[1]), m4(3, n[2]) ^ m4(2, n[3]), m4(2, n[2]) ^ m4(3, n[3])];
const mShift = (n) => [n[0], n[3], n[2], n[1]];
const mAdd = (n, k) => n.map((v, i) => v ^ k[i]);
function miniEnc(p, k) {
  const K = miniKeys(k);
  let s = mAdd(nib(p), K[0]);
  s = mAdd(mMix(mShift(s.map((v) => MS[v]))), K[1]);
  s = mAdd(mShift(s.map((v) => MS[v])), K[2]);
  return (s[0] << 12) | (s[1] << 8) | (s[2] << 4) | s[3];
}
const nOf = (q) => [q.n0, q.n1, q.n2, q.n3];
cipherMods.push({
  topic: 'aes-mini', allow: ['3', '16'],
  random: (rnd) => ({ p: Math.floor(rnd() * 65536).toString(16).padStart(4, '0'), k: Math.floor(rnd() * 65536).toString(16).padStart(4, '0'), dir: rnd() < 0.5 ? 'enc' : 'dec' }),
  check({ input, r, fail }) {
    const x = parseInt(input.p, 16), k = parseInt(input.k, 16), K = miniKeys(k), dec = input.dir === 'dec';
    for (const f of at(r, 'kr')) if (f.facts.K !== K[f.facts.r].map((v) => v.toString(16)).join('')) fail('round key ' + f.facts.r);
    for (const f of at(r, 'kw')) { const q = f.facts; if ((q.a ^ q.s ^ q.rc) !== q.out || q.s !== MS[K[q.r - 1][3]] || q.out !== K[q.r][0]) fail('the first word of K' + q.r); }
    for (const f of at(r, 'add')) { const q = f.facts; if (!same(nOf(q.o), mAdd(nOf(q.n), K[q.r]))) fail('adding K' + q.r); }
    for (const f of at(r, 'sub')) if (!same(nOf(f.facts.o), nOf(f.facts.n).map((v) => MS[v]))) fail('NibbleSub');
    for (const f of at(r, 'isub')) if (!same(nOf(f.facts.o), nOf(f.facts.n).map((v) => MI[v]))) fail('the inverse NibbleSub');
    for (const f of at(r, 'shift')) if (!same(nOf(f.facts.o), mShift(nOf(f.facts.n)))) fail('ShiftRow');
    for (const f of at(r, 'mix')) { const n = nOf(f.facts.n); if (!same(nOf(f.facts.o), mMix(n)) || !same(f.facts.p, [m4(3, n[0]), m4(2, n[1]), m4(2, n[0]), m4(3, n[1])])) fail('MixColumn'); }
    const out = at(r, 'out')[0], y = parseInt(out.facts.out, 16);
    if (dec ? miniEnc(y, k) !== x : miniEnc(x, k) !== y) fail('the result');
    if (parseInt(out.facts.back, 16) !== x) fail('the round trip');
  },
});

// ---- T-tables, built again from the S-box of the reference
const rotr = (b, k) => b.map((_, j) => b[(j - k + 4) % 4]);
cipherMods.push({
  topic: 'aes-ttable', allow: ['3', '4', '16', '64', '128', '02', '03'],
  random: (rnd) => ({ pt: randBlock(rnd), key: hex(rb(rnd, 16)), col: Math.floor(rnd() * 4) }),
  check({ input, r, fail }) {
    const P = [...U.block(input.pt)], K = [...U.key(input.key)], ref = R.encrypt(P, K), s0 = ref.rounds[0].end, c = input.col;
    const te = (k, x) => { const s = R.SBOX[x]; return rotr([R.gmul(2, s), s, s, R.gmul(3, s)], k); };
    const idx = [0, 1, 2, 3].map((k) => s0[k + 4 * ((c + k) % 4)]);
    for (const f of at(r, 'start')) if (!same(f.facts.idx, idx)) fail('the diagonal');
    for (const f of at(r, 'te0')) if (f.facts.s !== R.SBOX[idx[0]] || !same(f.facts.te, te(0, idx[0])) || f.facts.w !== hex(te(0, idx[0]))) fail('Te0');
    for (const f of at(r, 'te')) if (f.facts.words.join() !== idx.map((x, k) => hex(te(k, x))).join()) fail('the four lookups');
    for (const f of at(r, 'xor')) { const o = [0, 1, 2, 3].map((j) => idx.reduce((a, x, k) => a ^ te(k, x)[j], 0) ^ ref.rounds[1].key[4 * c + j]); if (f.facts.out !== hex(o) || !same(f.facts.byteCol, ref.rounds[1].end.slice(4 * c, 4 * c + 4)) || hex(o) !== hex(f.facts.byteCol)) fail('the column'); }
    const lines = new Set(); for (let cc = 0; cc < 4; cc++) for (let k = 0; k < 4; k++) lines.add(k + ':' + (s0[k + 4 * ((cc + k) % 4)] >> 4));
    for (const f of at(r, 'cache')) if (f.facts.lines !== lines.size) fail('the number of lines');
    for (const f of at(r, 'cache1')) if (f.facts.lines.join() !== [0, 1, 2, 3].map((k) => s0[k + 4 * (k % 4)] >> 4).join()) fail('the lines of column 0');
    for (const f of at(r, 'leak')) if (f.facts.kn.join() !== K.map((v) => v >> 4).join() || !K.every((v, i) => ((s0[i] >> 4) ^ (P[i] >> 4)) === v >> 4)) fail('the leaked nibbles');
    for (const f of at(r, 'notes')) if (!same(f.facts.C, R.nodeEncrypt(P, K))) fail('the ciphertext against node:crypto');
  },
});

// ---- search times, worked out with BigInt
const YEAR_S = 31557600n;
function spanRef(n, total) {
  // seconds = 2^n / total, as a decimal with 30 digits of scale
  const SC = 10n ** 30n, sec = (2n ** BigInt(n) * SC) / total, secN = Number(sec) / 1e30;
  if (secN < 1e-3) return [];
  const two = (v) => String(+v.toPrecision(2));
  if (secN < 60) return [two(secN)];
  if (secN < 3600) return [two(secN / 60)];
  if (secN < 86400) return [two(secN / 3600)];
  const yrs = sec / YEAR_S;
  if (secN < 31557600) return [two(secN / 86400)];
  const y = Number(yrs) / 1e30;
  if (y < 1e6) return [two(y).replace(/\B(?=(\d{3})+(?!\d))/g, ',')];
  const digits = (yrs / SC).toString(), e = digits.length - 1, m = Number(digits.slice(0, 4)) / 1000;
  let mm = m.toFixed(1), ee = e; if (mm === '10.0') { mm = '1.0'; ee++; }
  return [mm, ee];
}
cipherMods.push({
  topic: 'aes-security', allow: ['3', '10', '64', '128', '256', '25'],
  random: (rnd) => ({ rate: 3 + Math.floor(rnd() * 16), machines: Math.floor(rnd() * 10) }),
  check({ input, r, fail }) {
    const total = 10n ** BigInt(input.rate + input.machines);
    for (const f of at(r, 'size')) { const n = f.facts.n, want = spanRef(n - 1, total); if (f.facts.e !== n - 1 || String(f.facts.t) !== String(want)) fail(n + ' bits: ' + f.facts.t + ' against ' + want); }
    for (const f of at(r, 'grover')) { if (String(f.facts.t1) !== String(spanRef(64, total)) || String(f.facts.t2) !== String(spanRef(128, total))) fail('the Grover times ' + f.facts.t1 + ' / ' + spanRef(64, total)); }
    if (at(r, 'size').length !== 7) fail('seven key sizes');
  },
});

export const mods = [...cipherMods];
