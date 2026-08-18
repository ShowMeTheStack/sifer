// Claim checks for part 3, second half: Geffe, Trivium, Salsa20, ChaCha20 and XChaCha20. Each value a frame quotes
// is worked out again here from the definitions (a plain LFSR, a bit-array Trivium, Salsa20 and ChaCha20 written
// out afresh) and, for ChaCha20 and XChaCha20, by node:crypto's chacha20.
import { createCipheriv } from 'node:crypto';
import { S } from './claims-lib-p03.mjs';

const h8 = (v) => (v >>> 0).toString(16).padStart(8, '0');
const hex = (a) => Buffer.from(a).toString('hex');
const hexs = (a) => Array.from(a, (b) => b.toString(16).padStart(2, '0')).join(' ');
const pop = (x) => { let n = 0; x >>>= 0; while (x) { n += x & 1; x >>>= 1; } return n; };
const diff = (a, b) => a.reduce((n, v, i) => n + pop(v ^ b[i]), 0);
const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
const le = (b, i) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
const utf8 = (s) => new Uint8Array(Buffer.from(s, 'utf8'));
const pick = (rnd, list) => list[Math.floor(rnd() * list.length)];
const word = (rnd, n) => { const a = 'abcdefghijklmnopqrstuvwxyz -.,:!0123456789'; let s = ''; for (let i = 0; i < n; i++) s += a[Math.floor(rnd() * a.length)]; return s; };

// ---- ChaCha20 written out again
const CONST = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
const ccState = (key, ctr, nonce) => [...CONST, ...[0, 4, 8, 12, 16, 20, 24, 28].map((i) => le(key, i)), ctr >>> 0, le(nonce, 0), le(nonce, 4), le(nonce, 8)];
const QRSTEPS = [['add', 0, 1], ['xor', 3, 0], ['rot', 3, 16], ['add', 2, 3], ['xor', 1, 2], ['rot', 1, 12], ['add', 0, 1], ['xor', 3, 0], ['rot', 3, 8], ['add', 2, 3], ['xor', 1, 2], ['rot', 1, 7]];
const qrSteps = (w) => { const v = w.slice(), out = []; for (const [op, t, s] of QRSTEPS) { const before = v[t]; v[t] = op === 'add' ? (v[t] + v[s]) >>> 0 : op === 'xor' ? (v[t] ^ v[s]) >>> 0 : rotl(v[t], s); out.push({ op, before, after: v[t], src: op === 'rot' ? null : v[s] }); } return { out: v, steps: out }; };
const COLS = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]], DIAGS = [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];
const applyQr = (x, groups) => { const y = x.slice(); for (const g of groups) { const o = qrSteps(g.map((i) => y[i])).out; g.forEach((i, j) => { y[i] = o[j]; }); } return y; };
const rounds20 = (st) => { let x = st.slice(); for (let i = 0; i < 10; i++) x = applyQr(applyQr(x, COLS), DIAGS); return x; };
const nodeStream = (key, ctr, nonce, data) => { const iv = Buffer.alloc(16); iv.writeUInt32LE(ctr >>> 0, 0); Buffer.from(nonce).copy(iv, 4); return new Uint8Array(createCipheriv('chacha20', Buffer.from(key), iv).update(Buffer.from(data))); };

// ---- Salsa20 written out again
const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
const saState = (k, n, c) => [SIGMA[0], le(k, 0), le(k, 4), le(k, 8), le(k, 12), SIGMA[1], le(n, 0), le(n, 4), c >>> 0, Math.floor(c / 2 ** 32) >>> 0, SIGMA[2], le(k, 16), le(k, 20), le(k, 24), le(k, 28), SIGMA[3]];
const saQr = (y, [a, b, c, d], log) => {
  for (const [t, p, q, r] of [[b, a, d, 7], [c, b, a, 9], [d, c, b, 13], [a, d, c, 18]]) { const sum = (y[p] + y[q]) >>> 0, rot = rotl(sum, r), before = y[t]; y[t] = (y[t] ^ rot) >>> 0; if (log) log.push({ sum, rot, before, after: y[t], r }); }
};
const SCOLS = [[0, 4, 8, 12], [5, 9, 13, 1], [10, 14, 2, 6], [15, 3, 7, 11]], SROWS = [[0, 1, 2, 3], [5, 6, 7, 4], [10, 11, 8, 9], [15, 12, 13, 14]];

// ---- Trivium written out again: s[1..288]
const trivium = (key, iv) => {
  const s = new Array(289).fill(0), bit = (b, j) => (b[j >> 3] >> (j & 7)) & 1;
  for (let j = 0; j < 80; j++) { s[80 - j] = bit(key, j); s[93 + 80 - j] = bit(iv, j); }
  s[286] = s[287] = s[288] = 1;
  const clock = () => {
    let t1 = s[66] ^ s[93], t2 = s[162] ^ s[177], t3 = s[243] ^ s[288];
    const z = t1 ^ t2 ^ t3;
    t1 ^= (s[91] & s[92]) ^ s[171]; t2 ^= (s[175] & s[176]) ^ s[264]; t3 ^= (s[286] & s[287]) ^ s[69];
    for (let i = 288; i > 178; i--) s[i] = s[i - 1]; s[178] = t2;
    for (let i = 177; i > 94; i--) s[i] = s[i - 1]; s[94] = t1;
    for (let i = 93; i > 1; i--) s[i] = s[i - 1]; s[1] = t3;
    return { z, f: [t3, t1, t2] };
  };
  return { s, clock };
};

// ---- Geffe from the definition
const lfsr = (taps, seed, n) => { const s = seed.slice(); while (s.length < n) { let v = 0; for (const k of taps) v ^= s[s.length - k]; s.push(v); } return s.slice(0, n); };

export const mods = [
  {
    topic: 'st-geffe', allow: ['50', '8', '75'], count: 3,
    random: (rnd) => ({ seed: String(1 + Math.floor(rnd() * 40)), n: 100 + Math.floor(rnd() * 250) }),
    check({ input, r, fail }) {
      const n = input.n, { seeds, taps } = S.Geffe.setup({ seed: +input.seed, n }), x = seeds.map((s, i) => lfsr(taps[i], s, n)), z = x[0].map((a, i) => (a ? x[1][i] : x[2][i]));
      const agree = (s) => s.filter((b, i) => b === z[i]).length, pct = (a) => (100 * a / n).toFixed(1);
      const scan = (r2) => { const L = taps[r2][0], all = []; for (let v = 1; v < 1 << L; v++) all.push(agree(lfsr(taps[r2], Array.from({ length: L }, (_, i) => (v >> i) & 1), n))); return all.sort((a, b) => b - a); };
      for (const f of r.frames) {
        const F = f.facts, st = f.meta.stage;
        if (st === 'clock') { const t = f.meta.t; if (F.a !== x[0][t] || F.b !== x[1][t] || F.c !== x[2][t] || F.z !== z[t]) fail('clock ' + t); }
        if (st === 'stream' && (F.agree2 !== agree(x[1]) || F.agree3 !== agree(x[2]))) fail('the agreement counts');
        if (st === 'table' && (F.same2 !== 6 || F.same3 !== 6)) fail('the truth table counts');
        if (st === 'scan') { const all = scan(F.r - 1); if (F.best !== pct(all[0]) || F.second !== pct(all[1]) || F.count !== all.length) fail('the scan of R' + F.r); if (f.meta.right !== (agree(x[F.r - 1]) === all[0] && all[1] < all[0])) fail('whether the best state of R' + F.r + ' is the true one'); }
        if (st === 'x1' && r.frames.every((g) => g.meta.stage !== 'scan' || g.meta.right) && F.known !== x[1].filter((b, i) => b !== x[2][i]).length) fail('the places where x2 and x3 differ');
        if (st === 'x1' && F.s1 && F.s1 !== seeds[0].join('') && r.frames.find((g) => g.meta.stage === 'done').meta.ok) fail('the start state of R1');
        if (st === 'done' && F.work !== 2 ** 7 + 2 ** 11 + 2 ** 13) fail('the work');
      }
    },
  },
  {
    topic: 'st-trivium', allow: ['4', '288', '1152', '93', '84', '111', '80'], count: 4,
    random: (rnd) => ({ key: hex(Array.from({ length: 10 }, () => Math.floor(rnd() * 256))), iv: hex(Array.from({ length: 10 }, () => Math.floor(rnd() * 256))), clocks: 2 + Math.floor(rnd() * 8) }),
    check({ input, r, fail }) {
      const key = Buffer.from(input.key, 'hex'), iv = Buffer.from(input.iv, 'hex'), T = trivium(key, iv);
      for (let i = 0; i < 1152; i++) T.clock();
      const ones = T.s.slice(1).filter((b) => b).length, zs = [];
      for (const f of r.frames) {
        const F = f.facts, st = f.meta.stage;
        if (st === 'warm' && F.ones !== ones) fail('the bits set after the warm-up: ' + F.ones + ' against ' + ones);
        if (st === 'clock') {
          const s = T.s, t = [s[66] ^ s[93], s[162] ^ s[177], s[243] ^ s[288]], c = T.clock();
          zs.push(c.z);
          if (F.t.join() !== t.join() || F.z !== c.z || F.f.join() !== c.f.join()) fail('clock ' + F.k);
        }
        if (st === 'stream') {
          const T2 = trivium(key, iv); for (let i = 0; i < 1152; i++) T2.clock();
          const ks = new Uint8Array(8); for (let i = 0; i < 64; i++) ks[i >> 3] |= T2.clock().z << (i & 7);
          const msg = utf8('low tide');
          if (F.ks !== hexs(ks) || F.ct !== hexs(msg.map((b, i) => b ^ ks[i]))) fail('the keystream or the ciphertext');
        }
      }
    },
  },
  {
    topic: 'st-salsa', allow: ['4', '64', '512', '256', '32', '8', '20', '7', '9', '13', '18'], count: 4,
    random: (rnd) => ({ key: word(rnd, 32), nonce: word(rnd, 8), counter: Math.floor(rnd() * 100000) }),
    check({ input, r, fail }) {
      const key = utf8(input.key), nonce = utf8(input.nonce), st = saState(key, nonce, input.counter);
      const log = [], c1 = st.slice(); saQr(c1, SCOLS[0], log);
      const col = st.slice(); for (const g of SCOLS) saQr(col, g); const row = col.slice(); for (const g of SROWS) saQr(row, g);
      let x = st.slice(); for (let i = 0; i < 10; i++) { for (const g of SCOLS) saQr(x, g); for (const g of SROWS) saQr(x, g); }
      const words = x.map((v, i) => (v + st[i]) >>> 0), out = words.flatMap((w) => [w & 255, (w >>> 8) & 255, (w >>> 16) & 255, w >>> 24]);
      for (const f of r.frames) {
        const F = f.facts, s2 = f.meta.stage;
        if (s2 === 'state' && (F.c.join() !== [0, 5, 10, 15].map((i) => h8(st[i])).join() || F.n.join() !== [h8(st[6]), h8(st[7])].join() || F.k.join() !== [h8(st[8]), h8(st[9])].join())) fail('the state');
        if (s2 === 'step') { const L = log[f.meta.k]; if (F.sum !== h8(L.sum) || F.rot !== h8(L.rot) || F.before !== h8(L.before) || F.after !== h8(L.after) || F.r !== L.r) fail('step ' + F.k); }
        if (s2 === 'colround' && (F.d !== diff(st, col) || F.x0 !== h8(col[0]))) fail('the column round');
        if (s2 === 'rowround' && (F.d !== diff(st, row) || F.x0 !== h8(row[0]))) fail('the row round');
        if (s2 === 'rounds' && (F.d !== diff(st, x) || F.x0 !== h8(x[0]))) fail('twenty rounds');
        if (s2 === 'add' && (F.w !== h8(words[0]) || F.out !== hex(out.slice(0, 8)))) fail('the keystream block');
      }
    },
  },
  {
    topic: 'st-chacha-qr', allow: ['4', '32', '12', '16', '8', '7', '512', '0', '1', '2', '3'], count: 6,
    random: (rnd) => ({ key: word(rnd, 32), nonce: word(rnd, 12), counter: Math.floor(rnd() * 2 ** 32), group: pick(rnd, ['c0', 'c1', 'c2', 'c3', 'd0', 'd1', 'd2', 'd3']) }),
    check({ input, r, fail }) {
      const st = ccState(utf8(input.key), input.counter, utf8(input.nonce)), col = applyQr(st, COLS), dbl = applyQr(col, DIAGS);
      const diag = input.group[0] === 'd', g = (diag ? DIAGS : COLS)[+input.group[1]], q = qrSteps(g.map((i) => (diag ? col : st)[i]));
      for (const f of r.frames) {
        const F = f.facts, s2 = f.meta.stage;
        if (s2 === 'words' && F.w.join() !== g.map((i) => h8((diag ? col : st)[i])).join()) fail('the four words');
        if (s2 === 'step') { const s = q.steps[f.meta.k]; if (F.before !== h8(s.before) || F.after !== h8(s.after) || (s.op !== 'rot' && (F.src !== h8(s.src) || F.changed !== pop(s.before ^ s.after)))) fail('step ' + F.k); }
        if (s2 === 'colround' && (F.d !== diff(st, col) || F.out.join() !== q.out.map(h8).join())) fail('the column round');
        if (s2 === 'diag' && F.d !== diff(st, dbl)) fail('the double round');
      }
    },
  },
  {
    topic: 'st-chacha-block', allow: ['64', '512', '20', '16', '12', '32'], count: 5,
    random: (rnd) => ({ key: word(rnd, 32), nonce: word(rnd, 12), counter: Math.floor(rnd() * 1000), msg: word(rnd, 1 + Math.floor(rnd() * 170)) }),
    check({ input, r, fail }) {
      const key = utf8(input.key), nonce = utf8(input.nonce), msg = utf8(input.msg), ctr = input.counter;
      const st = ccState(key, ctr, nonce), x = rounds20(st), words = x.map((v, i) => (v + st[i]) >>> 0);
      const nb = Math.ceil(msg.length / 64), ks = nodeStream(key, ctr, nonce, new Uint8Array(64 * nb)), ct = nodeStream(key, ctr, nonce, msg);
      if (hex(ks.slice(0, 4)) !== hex([words[0] & 255, (words[0] >>> 8) & 255, (words[0] >>> 16) & 255, words[0] >>> 24])) fail('the rewritten block disagrees with node:crypto');
      for (const f of r.frames) {
        const F = f.facts, s2 = f.meta.stage;
        if (s2 === 'state' && (F.blocks !== nb || F.n !== msg.length || F.w12 !== h8(ctr))) fail('the state');
        if (s2 === 'rounds' && (F.d !== diff(st, x) || F.x0 !== h8(x[0]))) fail('twenty rounds');
        if (s2 === 'add' && F.w !== h8(words[0])) fail('the addition');
        if (s2 === 'block') { const j = F.j; if (F.counter !== ctr + j || F.ks !== hex(ks.slice(64 * j, 64 * j + Math.min(4, F.n))) || F.c !== hex(ct.slice(64 * j, 64 * j + 4)) || F.n !== Math.min(64, msg.length - 64 * j)) fail('block ' + j); }
        if (s2 === 'end' && (F.c !== hexs(ct.slice(0, 16)) || !F.ok)) fail('the ciphertext');
      }
    },
  },
  {
    topic: 'st-xchacha', allow: ['24', '16', '8', '12', '20', '0', '3', '15', '32', '4', '48', '96'], count: 5,
    random: (rnd) => ({ key: word(rnd, 32), nonce: word(rnd, 24), msg: word(rnd, 1 + Math.floor(rnd() * 110)) }),
    check({ input, r, fail }) {
      const key = utf8(input.key), nonce = utf8(input.nonce), msg = utf8(input.msg);
      const hst = [...CONST, ...[0, 4, 8, 12, 16, 20, 24, 28].map((i) => le(key, i)), ...[0, 4, 8, 12].map((i) => le(nonce, i))], hr = rounds20(hst);
      const sub = new Uint8Array([0, 1, 2, 3, 12, 13, 14, 15].flatMap((i) => [hr[i] & 255, (hr[i] >>> 8) & 255, (hr[i] >>> 16) & 255, hr[i] >>> 24]));
      const n12 = new Uint8Array(12); n12.set(nonce.subarray(16), 4);
      const ct = nodeStream(sub, 0, n12, msg), ks = nodeStream(sub, 0, n12, new Uint8Array(msg.length));
      for (const f of r.frames) {
        const F = f.facts, s2 = f.meta.stage;
        if (s2 === 'nonce' && (F.a !== hex(nonce.subarray(0, 16)) || F.b !== hex(nonce.subarray(16)))) fail('the nonce split');
        if (s2 === 'hstate' && (F.a !== h8(hst[12]) || F.b !== h8(hst[15]))) fail('the HChaCha20 state');
        if (s2 === 'hrounds' && (F.a !== h8(hr[0]) || F.b !== h8(hr[15]))) fail('the HChaCha20 rounds');
        if (s2 === 'subkey' && (F.s !== hex(sub.slice(0, 8)) || F.b !== hexs(sub.slice(0, 4)))) fail('the subkey');
        if (s2 === 'nonce12' && F.n !== hex(n12)) fail('the 12-byte nonce');
        if (s2 === 'encrypt' && (F.ks !== hex(ks.slice(0, 8)) || F.c !== hex(ct.slice(0, 8)) || F.n !== msg.length)) fail('the encryption');
      }
    },
  },
];
