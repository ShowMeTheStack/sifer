// Part 6's narration checks (set a: the modes, GCM, padding and key search), used by tests/claims-p06.mjs. Every
// block a frame states is recomputed with node:crypto (AES in ECB, CBC, CFB, CFB8, OFB, CTR, XTS and GCM) or with
// the reference AES of tests/claims-ref-aes.mjs, and every count with arithmetic written here.
import { createCipheriv } from 'node:crypto';
import { S, hex, same, at } from './claims-lib-p05.mjs';
import * as R from './claims-ref-aes.mjs';

const U = S.P5;
const rb = (rnd, n) => Array.from({ length: n }, () => Math.floor(rnd() * 256));
const words = ['harbour', 'lantern', 'cedar', 'kestrel', 'quay', 'moss', 'ember', 'tide', 'orchard', 'flint', 'meadow', 'copper', 'heron', 'dune'];
const sentence = (rnd, max) => { let s = ''; while (true) { const w = words[Math.floor(rnd() * words.length)]; if ((s + ' ' + w).trim().length > max) break; s = (s + ' ' + w).trim(); if (rnd() < 0.12) break; } return s || 'tide'; };
const randKey = (rnd) => hex(rb(rnd, [16, 24, 32][Math.floor(rnd() * 3)]));
export const nodeRun = (name, key, iv, data, pad) => { const c = createCipheriv('aes-' + key.length * 8 + '-' + name, Buffer.from(key), iv ? Buffer.from(iv) : null); c.setAutoPadding(!!pad); return Uint8Array.from(Buffer.concat([c.update(Buffer.from(data)), c.final()])); };
const blk = (b, i) => b.slice(16 * i, 16 * i + 16);
const ins = (input) => ({ key: U.key(input.key), iv: U.block(input.iv), msg: Buffer.from(String(input.msg), 'utf8') });
/** the keystream of a stream mode: the mode's output on zeros */
const stream = (name, key, iv, n) => nodeRun(name, key, iv, new Uint8Array(n));

export const mods = [
  {
    topic: 'modes-cbc', allow: ['3', '7', '15', '16'],
    random: (rnd) => ({ msg: sentence(rnd, 47), key: randKey(rnd), iv: hex(rb(rnd, 16)), dir: rnd() < 0.5 ? 'enc' : 'dec', flip: ['none', '0', '7', '15'][Math.floor(rnd() * 4)] }),
    check({ input, r, fail }) {
      const { key, iv, msg } = ins(input), C = nodeRun('cbc', key, iv, msg, true);
      const D = (c) => R.decrypt([...c], [...key]).out;
      for (const f of at(r, 'start')) { if (f.facts.n !== C.length / 16) fail('the block count'); if (f.facts.padN !== undefined && f.facts.padN !== C.length - msg.length) fail('the padding'); if (f.facts.C && !same(f.facts.C, C)) fail('the ciphertext'); }
      for (const f of at(r, 'xor')) { const i = f.meta.i, prev = i ? blk(C, i - 1) : iv; if (!same(f.facts.prev, prev)) fail('the chained block ' + i); if (f.facts.x && !same(f.facts.x, D(blk(C, i)))) fail('the XOR of block ' + i); if (f.facts.p && !same(f.facts.p, D(blk(C, i)).map((v, k) => v ^ prev[k]))) fail('P of block ' + i); }
      for (const f of at(r, 'enc')) if (!same(R.encrypt([...f.facts.x], [...key]).out, f.facts.c)) fail('Eₖ of the XOR');
      for (const f of at(r, 'out')) if (!same(f.facts.c, blk(C, f.meta.i))) fail('C of block ' + f.meta.i);
      for (const f of at(r, 'dec')) if (!same(f.facts.x, D(blk(C, f.meta.i)))) fail('Dₖ of block ' + f.meta.i);
      for (const f of at(r, 'end')) if (!same(f.facts.C, C)) fail('the ciphertext');
      for (const f of at(r, 'error')) {
        const Cx = Uint8Array.from(C); Cx[f.facts.flip] ^= 1;
        const p0 = D(blk(Cx, 0)).map((v, k) => v ^ iv[k]);
        if (!same(f.facts.q0, p0)) fail('the garbled first block');
        if (f.facts.at !== undefined && (f.facts.at !== f.facts.flip || (f.facts.a ^ f.facts.b) !== 1)) fail('the flipped bit of P₂');
      }
    },
  },
  {
    topic: 'modes-cfb', allow: ['16'],
    random: (rnd) => ({ msg: sentence(rnd, 48), key: randKey(rnd), iv: hex(rb(rnd, 16)), mode: rnd() < 0.5 ? 'cfb' : 'cfb8' }),
    check({ input, r, fail }) {
      const { key, iv, msg } = ins(input), C = nodeRun(input.mode === 'cfb' ? 'cfb' : 'cfb8', key, iv, msg);
      for (const f of at(r, 'xor')) {
        if (input.mode === 'cfb') { if (!same(f.facts.c, blk(C, f.meta.i))) fail('C of segment ' + f.meta.i); }
        else if (f.facts.c !== C[f.meta.i]) fail('byte ' + f.meta.i);
      }
      for (const f of at(r, 'ks')) if (input.mode === 'cfb' && !same(f.facts.reg, f.meta.i ? blk(C, f.meta.i - 1) : iv)) fail('the register');
      for (const f of at(r, 'end')) if (!same(f.facts.C, C)) fail('the ciphertext');
    },
  },
  {
    topic: 'modes-ofb', allow: ['16'],
    random: (rnd) => ({ msg: sentence(rnd, 48), key: randKey(rnd), iv: hex(rb(rnd, 16)) }),
    check({ input, r, fail }) {
      const { key, iv, msg } = ins(input), C = nodeRun('ofb', key, iv, msg), ks = stream('ofb', key, iv, 48);
      for (const f of at(r, 'ks')) if (!same(f.facts.ks, blk(ks, f.meta.i))) fail('keystream ' + f.meta.i);
      for (const f of at(r, 'xor')) if (!same(f.facts.c, blk(C, f.meta.i))) fail('C ' + f.meta.i);
      for (const f of at(r, 'end')) if (!same(f.facts.C, C)) fail('the ciphertext');
    },
  },
  {
    topic: 'modes-ctr', allow: ['16', '128'],
    random: (rnd) => ({ msg: sentence(rnd, 48), key: randKey(rnd), iv: hex(rb(rnd, 16)), jump: 1 + Math.floor(rnd() * 3), far: 3 + Math.floor(rnd() * 1e9) }),
    check({ input, r, fail }) {
      const { key, iv, msg } = ins(input), C = nodeRun('ctr', key, iv, msg);
      const add = (b, k) => { let v = BigInt('0x' + hex(b)) + BigInt(k); v &= (1n << 128n) - 1n; return Uint8Array.from(Buffer.from(v.toString(16).padStart(32, '0'), 'hex')); };
      for (const f of at(r, 'ks')) { if (!same(f.facts.ctr, add(iv, f.meta.i))) fail('counter ' + f.meta.i); if (!same(f.facts.ks, R.encrypt([...add(iv, f.meta.i)], [...key]).out)) fail('keystream ' + f.meta.i); }
      for (const f of at(r, 'xor')) if (!same(f.facts.c, blk(C, f.meta.i))) fail('C ' + f.meta.i);
      for (const f of at(r, 'jump')) if (!same(f.facts.p, blk(msg, f.facts.jj))) fail('the block read alone');
      for (const f of at(r, 'far')) { if (!same(f.facts.cf, add(iv, input.far))) fail('the far counter'); if (!same(f.facts.kf, R.encrypt([...f.facts.cf], [...key]).out)) fail('the far keystream'); }
    },
  },
  {
    topic: 'modes-ecb', allow: ['16'],
    random: (rnd) => ({ pic: rnd() < 0.5 ? 'lighthouse' : 'sailboat', key: randKey(rnd), other: rnd() < 0.5 ? 'cbc' : 'ctr', iv: hex(rb(rnd, 16)) }),
    check({ tp, input, r, fail }) {
      const key = U.key(input.key), iv = U.block(input.iv), px = tp.pixels(input.pic), n = px.length / 16;
      const ecb = nodeRun('ecb', key, null, px), oth = nodeRun(input.other, key, iv, px);
      const distinct = (b) => new Set(Array.from({ length: n }, (_, i) => hex(blk(b, i)))).size;
      for (const f of at(r, 'plain')) if (f.facts.nBlocks !== n || f.facts.distinctP !== distinct(px)) fail('the plaintext block counts');
      for (const f of at(r, 'flow')) f.facts.samples.forEach((b, j) => { if (!same(f.facts.sc[j], blk(ecb, b))) fail('the ciphertext of block ' + b); });
      for (const f of at(r, 'flow')) if (f.facts.sp[0] !== f.facts.sp[1] || !same(f.facts.sc[0], f.facts.sc[1])) fail('the equal pair');
      for (const f of at(r, 'ecb')) if (f.facts.distinct !== distinct(ecb) || distinct(ecb) !== distinct(px)) fail('the ECB count');
      for (const f of at(r, 'other')) if (f.facts.otherDistinct !== distinct(oth)) fail('the other mode count');
    },
  },
  {
    topic: 'modes-xts', allow: ['16', '87', '128'],
    random: (rnd) => ({ data: sentence(rnd, 48).padEnd(32 + Math.floor(rnd() * 17), '.'), key: hex(rb(rnd, rnd() < 0.5 ? 32 : 64)), sector: Math.floor(rnd() * 1e9) }),
    check({ input, r, fail }) {
      const t = String(input.data).replace(/\s+/g, ''), data = /^([0-9a-fA-F]{2}){16,}$/.test(t) ? Buffer.from(t, 'hex') : Buffer.from(String(input.data), 'utf8');
      const key = /^[0-9a-fA-F]+$/.test(String(input.key)) && String(input.key).length >= 64 ? Buffer.from(String(input.key), 'hex') : Buffer.from(String(input.key), 'utf8');
      const tw = Buffer.alloc(16); let v = BigInt(input.sector); for (let i = 0; i < 16; i++) { tw[i] = Number(v & 255n); v >>= 8n; }
      const C = Uint8Array.from((() => { const c = createCipheriv('aes-' + key.length * 4 + '-xts', key, tw); return Buffer.concat([c.update(data), c.final()]); })());
      const T = R.encrypt([...tw], [...key.subarray(key.length / 2)]).out;
      for (const f of at(r, 'tweak')) if (!same(f.facts.T, T)) fail('T = E_K2(tweak)');
      const dbl = (b) => { const o = new Array(16).fill(0); let c = 0; for (let i = 0; i < 16; i++) { o[i] = ((b[i] << 1) | c) & 255; c = b[i] >> 7; } if (c) o[0] ^= 0x87; return o; };
      for (const f of at(r, 'alpha')) if (!same(f.facts.T, dbl(f.facts.prev))) fail('T·α');
      for (const f of at(r, 'enc')) if (!same(f.facts.cc, R.encrypt([...f.facts.pp], [...key.subarray(0, key.length / 2)]).out)) fail('AES under K1');
      for (const f of [...at(r, 'steal'), ...at(r, 'end')]) if (!same(f.facts.C, C)) fail('the sector ciphertext against node:crypto');
    },
  },
  {
    topic: 'modes-gcm', allow: ['16', '96', '128', '00000001'],
    random: (rnd) => ({ msg: sentence(rnd, 32), aad: rnd() < 0.3 ? '' : sentence(rnd, 16), key: randKey(rnd), iv: hex(rb(rnd, 12)), tamper: ['none', 'ct', 'aad'][Math.floor(rnd() * 3)] }),
    check({ input, r, fail }) {
      const key = U.key(input.key), ivh = String(input.iv).replace(/\s+/g, ''), iv = /^[0-9a-fA-F]{24}$/.test(ivh) ? Buffer.from(ivh, 'hex') : Buffer.from(String(input.iv), 'utf8');
      const mh = String(input.msg).replace(/\s+/g, ''), msg = /^([0-9a-fA-F]{2}){16,}$/.test(mh) ? Buffer.from(mh, 'hex') : Buffer.from(String(input.msg), 'utf8'), aad = Buffer.from(String(input.aad), 'utf8');
      const c = createCipheriv('aes-' + key.length * 8 + '-gcm', Buffer.from(key), iv); c.setAAD(aad); const ct = Buffer.concat([c.update(msg), c.final()]), tag = c.getAuthTag();
      // GF(2^128) multiplication from the definition (bit 0 of the block is the coefficient of x^0)
      const mul = (X, Y) => { let x = BigInt('0x' + hex(X)), v = BigInt('0x' + hex(Y)), z = 0n; for (let i = 127; i >= 0; i--) { if ((x >> BigInt(i)) & 1n) z ^= v; v = v & 1n ? (v >> 1n) ^ (0xe1n << 120n) : v >> 1n; } return Buffer.from(z.toString(16).padStart(32, '0'), 'hex'); };
      const H = R.encrypt(new Array(16).fill(0), [...key]).out;
      for (const f of at(r, 'h')) if (!same(f.facts.H, H)) fail('H');
      for (const f of at(r, 'ctr')) if (!same(f.facts.c, ct.subarray(16 * f.meta.i, 16 * f.meta.i + 16))) fail('C ' + f.meta.i);
      for (const f of at(r, 'ghash')) if (!same(f.facts.y, mul(f.facts.before.map((v, k) => v ^ f.facts.x[k]), H))) fail('GHASH step ' + f.meta.k);
      for (const f of at(r, 'tag')) if (!same(f.facts.tag, tag)) fail('the tag against node:crypto');
      for (const f of at(r, 'tamper')) if (f.meta.ok || same(f.facts.t2, tag)) fail('a tampered message accepted');
    },
  },
  {
    topic: 'modes-padding', allow: ['1', '7816', '4', '16', '10', '00', '01', '80', '3'],
    random: (rnd) => ({ msg: sentence(rnd, 40).padEnd(17 + Math.floor(rnd() * 24), '!'), key: randKey(rnd), iv: hex(rb(rnd, 16)), variant: ['CS1', 'CS2', 'CS3'][Math.floor(rnd() * 3)] }),
    check({ input, r, fail }) {
      const msg = Buffer.from(String(input.msg), 'utf8'), L = msg.length, k = 16 - (L % 16);
      for (const f of at(r, 'msg')) if (f.facts.L !== L || f.facts.d !== L % 16) fail('the length');
      for (const f of at(r, 'pkcs7')) if (f.facts.k !== k) fail('k');
      for (const f of at(r, 'check')) if (f.meta.badOk) fail('a damaged padding accepted');
      for (const f of at(r, 'iso')) if (f.facts.z !== k - 1) fail('the ISO zero count');
      if (L % 16 && L > 16) {
        const key = U.key(input.key), iv = U.block(input.iv), m = Math.ceil(L / 16), zp = Buffer.alloc(16 * m); msg.copy(zp);
        const cb = nodeRun('cbc', key, iv, zp), d = L % 16, head = cb.subarray(0, 16 * (m - 2)), pre = cb.subarray(16 * (m - 2), 16 * (m - 2) + d), last = cb.subarray(16 * (m - 1));
        const swap = input.variant !== 'CS1', want = Buffer.concat(swap ? [head, last, pre] : [head, pre, last]);
        for (const f of at(r, 'cts1')) if (!same(f.facts.head, pre)) fail('the stolen block');
        for (const f of at(r, 'cts2')) if (!same(f.facts.C, want)) fail('the ' + input.variant + ' ciphertext');
      }
    },
  },
  {
    topic: 'modes-keysearch', allow: ['1998', '57', '112', '64', '32', '128', '10', '40', '56', '3'],
    random: (rnd) => ({ rate: 3 + Math.floor(rnd() * 16), machines: Math.floor(rnd() * 13), block: rnd() < 0.5 ? '64' : '128' }),
    check({ input, r, fail }) {
      const YEAR = 365.25 * 86400;
      // the expected time, worked out with BigInt from the definition, then put in words
      const words = (bits) => {
        const keys = 1n << BigInt(bits - 1), per = 10n ** BigInt(input.rate + input.machines);
        if (keys < per) return 'under a second';
        const secs = Number(keys / per) + Number(keys % per) / Number(per);
        const ls = Math.log10(secs);
        if (secs < 60) return Math.round(secs) + ' seconds';
        if (secs < 3600) return Math.round(secs / 60) + ' minutes';
        if (secs < 86400) return Math.round(secs / 3600) + ' hours';
        if (secs < YEAR) return Math.round(secs / 86400) + ' days';
        const ly = ls - Math.log10(YEAR);
        return ly < 6 ? Math.round(10 ** ly).toLocaleString('en-US') + ' years' : '10^' + Math.floor(ly) + ' years';
      };
      for (const f of at(r, 'des')) { if (f.facts.a !== words(40)) fail('40-bit: ' + f.facts.a + ' against ' + words(40)); if (f.facts.b !== words(56)) fail('DES: ' + f.facts.b + ' against ' + words(56)); }
      for (const f of at(r, '3des')) if (f.facts.t !== words(112)) fail('3DES');
      for (const f of at(r, 'aes')) if (f.facts.a !== words(128) || f.facts.b !== words(256)) fail('AES');
      for (const f of at(r, 'half')) {
        const n = +input.block, q50 = Math.sqrt(2 * Math.log(2) * 2 ** n), bytes = q50 * n / 8;
        if (n === 64 && f.facts.gib !== Math.round(bytes / 2 ** 30)) fail('the half-way data for 64-bit blocks');
        if (n === 128 && f.facts.e !== Math.round(Math.log2(bytes) - 60)) fail('the half-way data for 128-bit blocks');
        if (Math.abs(f.facts.p32 - (1 - Math.exp(-0.5))) > 0.006) fail('the chance at 2^32 blocks');
      }
    },
  },
];
