// Claim checks for the part-8 topics on padding (malleability, OAEP, PSS), the first four attacks and the sizes,
// collected by tests/claims-p08.mjs. OAEP ciphertexts are decrypted and PSS signatures verified by node:crypto with
// the same keys; everything else is worked out again with plain BigInt arithmetic here.
import { pw, gcd, inv, mod, S } from './claims-lib-pk.mjs';
import { createPrivateKey, createPublicKey, privateDecrypt, verify, constants, createHash } from 'node:crypto';

const textNum = (s) => BigInt('0x' + (Buffer.from(s, 'utf8').toString('hex') || '0'));
const icbrt = (x) => { if (x < 2n) return x; let lo = 0n, hi = 1n << BigInt(Math.ceil(x.toString(2).length / 3) + 1); while (lo < hi) { const m = (lo + hi + 1n) / 2n; if (m * m * m <= x) lo = m; else hi = m - 1n; } return lo; };
const keyOf = (name, e, pair) => {
  const k = S.P08B.key(name, e, pair);
  if (k.p * k.q !== k.n || mod(BigInt(k.e) * k.d, (k.p - 1n) * (k.q - 1n)) !== 1n) throw new Error('a bad key ' + name);
  return k;
};
const b64 = (v) => { let h = v.toString(16); if (h.length % 2) h = '0' + h; return Buffer.from(h, 'hex').toString('base64url'); };
export const jwkOf = (k) => ({ kty: 'RSA', n: b64(k.n), e: b64(BigInt(k.e)), d: b64(k.d), p: b64(k.p), q: b64(k.q), dp: b64(k.dp), dq: b64(k.dq), qi: b64(k.qinv) });
const msgOf = (input) => (input.key === 'toy' ? BigInt(String(input.msg).trim()) : textNum(input.msg));
const pick = (rnd, xs) => xs[Math.floor(rnd() * xs.length)];
const words = ['the gate opens at dawn', 'ledger 42 is short by 9', 'swap the blue and green crates', 'bring the spare key', 'call me at noon', 'harbour lights off'];

export const mods = [
  {
    topic: 'p08-sizes', allow: [],
    random: (rnd) => { const ps = [11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 251, 499, 997]; const p = pick(rnd, ps); let q = pick(rnd, ps); if (q === p) q = p === 11 ? 13 : 11; return { p: String(p), q: String(q), m: String(2 + Math.floor(rnd() * (p * q - 3))), key: pick(rnd, ['rsa1024', 'rsa2048']), msg: pick(rnd, words) }; },
    check({ input, r, fail }) {
      const p = BigInt(input.p), q = BigInt(input.q), n = p * q, phi = (p - 1n) * (q - 1n), R = keyOf(input.key, 65537), mR = textNum(input.msg), mT = BigInt(input.m);
      const want = (i, x) => [[p > q ? p : q, R.p], [p > q ? q : p, R.q], [n, R.n], [phi, (R.p - 1n) * (R.q - 1n)]][i] || null;
      for (const f of r.frames) {
        if (f.meta.phase !== 'row') continue;
        const x = f.facts, i = f.meta.i, w = want(i);
        if (w && (x.tv !== w[0] || x.rv !== w[1])) fail('row ' + i);
        if (i === 4 && (gcd(x.tv, phi) !== 1n || x.rv !== 65537n)) fail('e');
        if (i === 5 && (mod(x.tv * BigInt(r.frames[5].facts.tv), phi) !== 1n || mod(x.rv * 65537n, (R.p - 1n) * (R.q - 1n)) !== 1n)) fail('d');
        if (i === 7 && (x.tv !== pw(mT, r.frames[5].facts.tv, n) || x.rv !== pw(mR, 65537n, R.n))) fail('c');
        if (i === 8) {
          if (x.tv !== mT || x.rv !== mR) fail('the decryption');
          const dT = r.frames[6].facts.tv, dR = R.d, ones = (v) => v.toString(2).split('').filter((b) => b === '1').length;
          if (x.ops[0] !== dT.toString(2).length - 1 || x.ops[1] !== ones(dT) - 1 || x.ops[2] !== dR.toString(2).length - 1 || x.ops[3] !== ones(dR) - 1) fail('the operation counts');
        }
      }
    },
  },
  {
    topic: 'p08-malleable', allow: [],
    random: (rnd) => { const toy = rnd() < 0.5, lim = toy ? 1050000 : 1e9; const m = 1 + Math.floor(rnd() * lim), s = 2 + Math.floor(rnd() * 50); return { key: toy ? 'toy' : pick(rnd, ['rsa1024', 'rsa2048']), m: String(m), s: String(s), guesses: [String(m + 1), String(m), String(Math.max(0, m - 7))] }; },
    check({ input, r, fail }) {
      const k = keyOf(input.key, 65537), n = k.n, e = BigInt(k.e), m = BigInt(input.m), s = BigInt(input.s), c = pw(m, e, n);
      for (const f of r.frames) {
        const x = f.facts, ph = f.meta.phase;
        if (ph === 'start' && x.c !== c) fail('c');
        if (ph === 'enc-s' && x.t !== pw(s, e, n)) fail('s^e');
        if (ph === 'mul' && x.c2 !== mod(c * pw(s, e, n), n)) fail('c′');
        if (ph === 'dec' && (x.m2 !== mod(m * s, n) || pw(x.c2 ?? 0n, 1n, 2n) === -1n)) fail('the decryption of c′');
        if (ph === 'guess') { const hit = input.guesses.map(BigInt).find((g) => pw(g, e, n) === c); if ((hit ?? null) !== x.hit) fail('the matching guess'); }
      }
    },
  },
  {
    topic: 'p08-oaep', allow: ['66', '33', '32', '00', '01', '0', '1'],
    random: (rnd) => ({ key: pick(rnd, ['rsa1024', 'rsa2048']), msg: pick(rnd, words), label: pick(rnd, ['', 'mail', 'backup 7']), seed: Array.from({ length: 32 }, () => Math.floor(rnd() * 256).toString(16).padStart(2, '0')).join('') }),
    check({ input, r, fail }) {
      const k = keyOf(input.key, 65537), kb = Math.ceil(k.n.toString(2).length / 8);
      const lh = createHash('sha256').update(Buffer.from(input.label, 'utf8')).digest('hex');
      for (const f of r.frames) {
        const x = f.facts, ph = f.meta.phase;
        if (ph === 'lhash' && x.lHash !== lh.slice(0, 16) + '…') fail('lHash');
        if (ph === 'start' && (x.k !== kb || x.ps !== kb - 66 - Buffer.byteLength(input.msg))) fail('the sizes');
        if (ph === 'em') {
          let h = x.c.toString(16); h = h.padStart(2 * kb, '0');
          const pt = privateDecrypt({ key: createPrivateKey({ key: jwkOf(k), format: 'jwk' }), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: Buffer.from(input.label, 'utf8') }, Buffer.from(h, 'hex'));
          if (pt.toString('utf8') !== input.msg) fail('node:crypto does not decrypt the ciphertext to the message');
        }
        if (ph === 'dec' && !f.meta.ok) fail('the round trip');
        if (ph === 'again' && x.diff < kb - 8) fail('a one-bit change of the seed changed only ' + x.diff + ' bytes');
      }
    },
  },
  {
    topic: 'p08-pss', allow: ['8', '00', '01', '32', '33', '1'],
    random: (rnd) => ({ key: pick(rnd, ['rsa1024', 'rsa2048']), msg: pick(rnd, words), salt: rnd() < 0.2 ? '' : Array.from({ length: 32 }, () => Math.floor(rnd() * 256).toString(16).padStart(2, '0')).join('') }),
    check({ input, r, fail }) {
      const k = keyOf(input.key, 65537), sl = input.salt.length / 2;
      const mh = createHash('sha256').update(Buffer.from(input.msg, 'utf8')).digest('hex');
      for (const f of r.frames) {
        const x = f.facts, ph = f.meta.phase;
        if (ph === 'mhash' && x.h !== mh.slice(0, 16) + '…') fail('mHash');
        if (ph === 'sign') {
          let h = x.s.toString(16); h = h.padStart(2 * Math.ceil(k.n.toString(2).length / 8), '0');
          const pub = createPublicKey({ key: jwkOf(k), format: 'jwk' }), opt = { key: pub, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: sl };
          if (!verify('sha256', Buffer.from(input.msg, 'utf8'), opt, Buffer.from(h, 'hex'))) fail('node:crypto rejects the signature');
          if (verify('sha256', Buffer.from(input.msg + '!', 'utf8'), opt, Buffer.from(h, 'hex'))) fail('node:crypto accepts a changed message');
        }
        if (ph === 'verify' && !f.meta.ok) fail('our verification');
        if (ph === 'tamper' && !f.meta.ok) fail('the tampered message verified');
      }
    },
  },
  {
    topic: 'p08-small-e-attack', allow: ['3', '1000'],
    random: (rnd) => (rnd() < 0.5 ? { key: 'toy', msg: String(2 + Math.floor(rnd() * 200)) } : { key: pick(rnd, ['rsa1024', 'rsa2048']), msg: pick(rnd, words) }),
    check({ input, r, fail }) {
      const k = keyOf(input.key, 3), m = msgOf(input), c = pw(m, 3, k.n);
      for (const f of r.frames) {
        const x = f.facts, ph = f.meta.phase;
        if (ph === 'start' && (x.n !== k.n || x.m !== m || x.c !== c)) fail('the setting');
        if (ph === 'size' && (x.b3 !== (m ** 3n).toString(2).length || x.bn !== k.n.toString(2).length)) fail('the sizes');
        // the outcome stated, worked out here: m³ = c + k·n for a small k makes c an exact cube after k wraps
        if (ph === 'done') { const want = m ** 3n < c + 1001n * k.n; if (f.meta.ok !== want) fail('success should be ' + want); if (f.meta.ok) { const kk = (m ** 3n - c) / k.n; if (x.k !== kk || icbrt(c + kk * k.n) !== m) fail('the number of wraps'); } if (!f.meta.ok && x.wraps !== m ** 3n / k.n) fail('the number of wraps'); }
        if (ph === 'defence' && (x.bn !== k.n.toString(2).length || x.bn2 !== 2 * x.bn)) fail('the defence sizes');
      }
    },
  },
  {
    topic: 'p08-common-modulus', allow: [],
    random: (rnd) => { const toy = rnd() < 0.5, e = pick(rnd, [[3, 17], [7, 11], [17, 65537], [11, 65537], [3, 65537], [13, 17]]); return toy ? { key: 'toy', e1: String(e[0] === 3 || e[0] === 13 ? 7 : e[0]), e2: String(e[1]), msg: String(2 + Math.floor(rnd() * 1e6)) } : { key: pick(rnd, ['rsa1024', 'rsa2048']), e1: String(e[0]), e2: String(e[1]), msg: pick(rnd, words) }; },
    mayRefuse: true,
    check({ input, r, fail }) {
      const k = keyOf(input.key, 65537), n = k.n, e1 = BigInt(input.e1), e2 = BigInt(input.e2), m = msgOf(input);
      for (const f of r.frames) {
        const x = f.facts, ph = f.meta.phase;
        if (ph === 'start' && (x.c1 !== pw(m, e1, n) || x.c2 !== pw(m, e2, n))) fail('the ciphertexts');
        if (ph === 'pre' && x.g !== gcd(e1, e2)) fail('gcd(e1, e2)');
        // the outcome stated: coprime exponents let the public values give m (worked out here, never shown)
        if (ph === 'done') {
          let [r0, r1, s0, s1, t0, t1] = [e1, e2, 1n, 0n, 0n, 1n];
          while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; [t0, t1] = [t1, t0 - q * t1]; }
          const c1 = pw(m, e1, n), c2 = pw(m, e2, n), pow = (c, a) => (a < 0n ? pw(inv(c, n), -a, n) : pw(c, a, n));
          const got = r0 === 1n ? mod(pow(c1, s0) * pow(c2, t0), n) : null;
          if (f.meta.ok !== (got === m)) fail('the outcome');
        }
      }
    },
  },
  {
    topic: 'p08-hastad', allow: ['3', '65537'],
    random: (rnd) => (rnd() < 0.5 ? { key: 'toy', msg: String(2 + Math.floor(rnd() * 1e6)) } : { key: pick(rnd, ['rsa1024', 'rsa2048']), msg: pick(rnd, words) }),
    check({ input, r, fail }) {
      const ks = [0, 1, 2].map((i) => keyOf(input.key, 3, i)), m = msgOf(input), N = ks.reduce((a, k) => a * k.n, 1n);
      for (const f of r.frames) {
        const x = f.facts, ph = f.meta.phase;
        if (ph === 'ct' && !ks.some((k) => k.n === x.n && x.c === pw(m, 3, k.n))) fail('a ciphertext');
        if (ph === 'done') {
          if (x.bN !== N.toString(2).length || x.b3 !== (m ** 3n).toString(2).length || m ** 3n >= N) fail('m³ below n1·n2·n3');
          // the outcome stated: the three ciphertexts fix m³ (by the CRT, worked out here) and so m
          let X = 0n; for (const k of ks) { const Mi = N / k.n; X += pw(m, 3, k.n) * Mi * inv(Mi % k.n, k.n); }
          if (mod(X, N) !== m ** 3n || icbrt(mod(X, N)) !== m || !f.meta.ok) fail('the outcome');
        }
      }
    },
  },
  {
    topic: 'p08-wiener', allow: ['4', '3', '65537'],
    random: (rnd) => ({ bits: pick(rnd, ['64', '64', '256']), kind: pick(rnd, ['small', 'small', 'normal']), seed: 1 + Math.floor(rnd() * 9000) }),
    check({ input, r, fail }) {
      let n = null, e = null;
      const d0 = r.frames[0].facts;
      if (input.kind === 'small') { const lab = S.RSA.labs.wiener(input.seed, { bits: +input.bits }); n = lab.public.n; e = lab.public.e; }
      else if (+input.bits >= 1024) { const k = S.PK.rsaKey('rsa' + input.bits); n = k.n; e = k.e; }
      if (n && d0.nb !== n.toString(2).length) fail('the size of n');
      for (const f of r.frames) {
        const x = f.facts, ph = f.meta.phase;
        if (ph === 'pre' && n) { let lo = 0n, hi = n; while (lo < hi) { const md = (lo + hi + 1n) / 2n; if (md ** 4n <= n) lo = md; else hi = md - 1n; } if (x.bb !== (lo / 3n).toString(2).length) fail('the bound'); }
        if (ph === 'done' && f.meta.ok !== (input.kind === 'small')) fail('a small d should be exposed and a full one not');
        if (ph === 'done' && f.meta.ok) { const lab = S.RSA.labs.wiener(input.seed, { bits: +input.bits }), att = S.RSA.attack.wiener({ n, e }); if (att.d !== lab.secret.d || pw(pw(2n, e, n), att.d, n) !== 2n || !x.ok) fail('the outcome'); }
      }
    },
  },
];
