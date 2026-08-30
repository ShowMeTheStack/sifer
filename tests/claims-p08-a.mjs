// Claim checks for part 8's scheme and speed topics (key generation, encryption, Euler, square-and-multiply, the
// ladder, Montgomery multiplication, the CRT, small exponents), collected by tests/claims-p08.mjs. Each works the
// facts out again with its own arithmetic, primality by node:crypto, and RSA without padding by node:crypto.
import { checkPrimeSync, createPrivateKey, createPublicKey, publicEncrypt, privateDecrypt, constants } from 'node:crypto';
import { pw, gcd, inv, mod } from './claims-lib-pk.mjs';

const b64 = (v) => { let h = v.toString(16); if (h.length % 2) h = '0' + h; return Buffer.from(h, 'hex').toString('base64url'); };
const pad = (v, k) => { let h = v.toString(16); h = h.padStart(2 * k, '0'); return Buffer.from(h, 'hex'); };
const bitlen = (v) => (v === 0n ? 0 : v.toString(2).length);
const ones = (v) => [...v.toString(2)].filter((c) => c === '1').length;
/** x^e mod n through node:crypto (RSA without padding) for a real key */
function nodeRSA(key) {
  const jwk = { kty: 'RSA', n: b64(key.n), e: b64(key.e), d: b64(key.d), p: b64(key.p), q: b64(key.q), dp: b64(key.dp), dq: b64(key.dq), qi: b64(key.qinv) };
  const priv = createPrivateKey({ key: jwk, format: 'jwk' }), pub = createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' }), k = Math.ceil(bitlen(key.n) / 8);
  return {
    enc: (m) => BigInt('0x' + publicEncrypt({ key: pub, padding: constants.RSA_NO_PADDING }, pad(m, k)).toString('hex')),
    dec: (c) => BigInt('0x' + privateDecrypt({ key: priv, padding: constants.RSA_NO_PADDING }, pad(c, k)).toString('hex')),
  };
}
const isPrime = (v) => checkPrimeSync(BigInt(v), { checks: 20 });
/** one Miller–Rabin round with base a: true when a is a witness (n composite) */
const witness = (n, a) => { let d = n - 1n, s = 0; while (!(d & 1n)) { d >>= 1n; s++; } let x = pw(a, d, n); if (x === 1n || x === n - 1n) return false; for (let r = 1; r < s; r++) { x = (x * x) % n; if (x === n - 1n) return false; } return true; };
const order = (m, n) => { let k = 1, v = mod(m, n); while (v !== 1n) { v = (v * m) % n; k++; if (k > 1e6) return null; } return k; };
const SMALLP = [5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113];

export const mods = [
  {
    topic: 'p08-keygen', allow: ['3', '4', '8', '17', '65537', '2000', '256'], mayRefuse: true, count: 10,
    random: (rnd) => ({ bits: ['16', '24', '40'][Math.floor(rnd() * 3)], e: ['3', '17', '65537'][Math.floor(rnd() * 3)], seed: 1 + Math.floor(rnd() * 99998) }),
    check({ S, input, r, fail }) {
      const e = BigInt(input.e);
      let key = null;
      for (const f of r.frames) {
        const x = f.facts, ph = f.meta.phase;
        if (ph === 'cand' && x.c !== undefined) {
          if (f.meta.kind === 'small' && x.c % BigInt(x.by) !== 0n) fail(x.c + ' is not divisible by ' + x.by);
          if (f.meta.kind === 'witness' && (!witness(x.c, x.by) || isPrime(x.c))) fail(x.by + ' is not a witness for ' + x.c);
          if ((f.meta.kind === 'prime' || f.meta.kind === 'reject') && !isPrime(x.c)) fail(x.c + ' is not prime');
          if (f.meta.kind === 'reject' && gcd(e, x.c - 1n) === 1n) fail('a rejected prime with gcd(e, p − 1) = 1');
        }
        if (ph === 'witness' && !witness(x.c, x.a)) fail('the composite example has no witness');
        if (ph === 'mr' && x.d * 2n ** BigInt(x.s) !== r.frames.find((g) => g.meta.phase === 'n').facts.p - 1n && x.d * 2n ** BigInt(x.s) !== r.frames.find((g) => g.meta.phase === 'n').facts.q - 1n) fail('p − 1 = 2^s·d');
        if (ph === 'n') { if (x.p * x.q !== x.n || !isPrime(x.p) || !isPrime(x.q) || bitlen(x.n) !== +input.bits) fail('n = p·q with ' + input.bits + ' bits'); key = x; }
        if (ph === 'phi' && x.phi !== (key.p - 1n) * (key.q - 1n)) fail('φ(n)');
        if (ph === 'e' && x.g !== gcd(e, x.phi)) fail('gcd(e, φ)');
        if (ph === 'd') { const phi = (key.p - 1n) * (key.q - 1n); if (x.d !== inv(e, phi) || mod(x.t, phi) !== x.d) fail('d = e⁻¹ mod φ(n)'); }
        if (ph === 'crt' && (x.dp !== mod(r.frames.find((g) => g.meta.phase === 'd').facts.d, key.p - 1n) || x.qinv !== inv(key.q, key.p))) fail('the CRT values');
      }
      if (!key) fail('no key frame');
    },
  },
  {
    topic: 'p08-encdec', allow: ['30'], mayRefuse: true, count: 10,
    random: (rnd) => (rnd() < 0.6 ? { key: 'toy', msg: String(Math.floor(rnd() * 13275499)) } : { key: ['rsa1024', 'rsa2048'][Math.floor(rnd() * 2)], msg: 'note ' + Math.floor(rnd() * 1e9) }),
    check({ S, input, r, fail }) {
      const key = S.P08A.key(input.key), x0 = r.frames[0].facts, m = x0.m;
      const c = pw(m, key.e, key.n);
      for (const f of r.frames) {
        const x = f.facts;
        if (f.meta.phase === 'enc' && (x.sq !== bitlen(key.e) - 1 || x.mul !== ones(key.e) - 1)) fail('the encryption counts');
        if (f.meta.phase === 'c' && x.c !== c) fail('c');
        if (f.meta.phase === 'dec' && (x.sq !== bitlen(key.d) - 1 || x.mul !== ones(key.d) - 1)) fail('the decryption counts');
        if (f.meta.phase === 'back' && (x.back !== m || !f.meta.ok)) fail('decryption gives m back');
      }
      if (input.key !== 'toy') {
        const R = nodeRSA(key);
        if (R.enc(m) !== c) fail('node:crypto encrypts to another c');
        if (R.dec(c) !== m) fail('node:crypto decrypts to another m');
        if (Buffer.from(m.toString(16).padStart(2 * Math.ceil(m.toString(16).length / 2), '0'), 'hex').toString('utf8') !== input.msg) fail('m is not the message bytes');
      }
    },
  },
  {
    topic: 'p08-why', allow: ['12', '24'], mayRefuse: true, count: 14,
    random: (rnd) => { const p = SMALLP[Math.floor(rnd() * 12)], q = SMALLP[Math.floor(rnd() * 12)]; return { size: 'toy', p: String(p), q: String(q), e: String([3, 5, 7, 11, 13][Math.floor(rnd() * 5)]), m: String(2 + Math.floor(rnd() * (p * q - 4))) }; },
    check({ input, r, fail }) {
      let n, phi, e, d;
      for (const f of r.frames) {
        const x = f.facts, ph = f.meta.phase;
        if (ph === 'setup' && x.n !== undefined) { ({ n, phi, e, d } = x); if (x.p * x.q !== n || (x.p - 1n) * (x.q - 1n) !== phi || (e * d) % phi !== 1n || x.ed !== e * d || x.ed !== 1n + x.k * phi) fail('the key'); }
        if (ph === 'setup' && x.nb !== undefined) { ({ phi, e, d } = x); }
        if (ph === 'k' && 1n + x.k * phi !== e * d) fail('k');
        if (ph === 'ring' && order(x.m, n) !== x.L) fail('the cycle length');
        if (ph === 'euler' && x.laps !== undefined && Number(phi) !== x.laps * x.L) fail('φ = laps · L');
        if (ph === 'euler' && x.mphi !== undefined && x.mphi !== 1n) fail('m^φ(n) = 1');
        if (ph === 'enc' && (x.c !== pw(BigInt(input.m), e, n) || x.ePos !== Number(e % BigInt(r.frames[1].facts.L)))) fail('c and its position');
        if (ph === 'dec' && x.back !== BigInt(input.m)) fail('c^d = m');
        if (ph === 'general' && x.pfBack !== x.pf) fail('a message sharing a factor comes back');
        if (ph === 'back' && x.back !== x.m) fail('c^d = m (real)');
      }
    },
  },
  {
    topic: 'p08-sqm', allow: [], mayRefuse: true, count: 12,
    random: (rnd) => { const n = 3 + Math.floor(rnd() * 1e6); return { size: 'toy', x: String(2 + Math.floor(rnd() * (n - 3))), e: String(2 + Math.floor(rnd() * 65530)), n: String(n) }; },
    check({ S, input, r, fail }) {
      const o = r.frames[0].facts, { x, e, n } = o, bits = e.toString(2);
      for (const f of r.frames) {
        const z = f.facts;
        if (f.meta.phase !== 'bit') continue;
        const t = z.t, pre = BigInt('0b' + bits.slice(0, t + 1)), low = e & ((1n << BigInt(t + 1)) - 1n);
        if (z.lr.value !== pw(x, pre, n)) fail('left to right after bit ' + t);
        if (z.rl.power !== pw(x, 2n ** BigInt(t), n)) fail('x^(2^' + t + ')');
        if (z.rl.acc !== pw(x, low, n) && low !== 0n) fail('right to left after bit ' + t);
      }
      const end = r.frames[r.frames.length - 1].facts;
      if (end.v !== pw(x, e, n) || end.ls !== bits.length - 1 || end.lm !== ones(e) - 1 || end.rs !== bits.length - 1 || end.rm !== ones(e) - 1) fail('the result and the counts');
      if (o.ones !== ones(e) || o.L !== bits.length) fail('the bits of e');
    },
  },
  {
    topic: 'p08-ladder', allow: [], mayRefuse: true, count: 10,
    random: (rnd) => { const n = 3 + Math.floor(rnd() * 1e6); return { size: 'toy', x: String(2 + Math.floor(rnd() * (n - 3))), e: String(2 + Math.floor(rnd() * 65530)), n: String(n) }; },
    check({ input, r, fail }) {
      const { x, e, n } = r.frames[0].facts, bits = e.toString(2);
      for (const f of r.frames) {
        if (f.meta.phase !== 'bit') continue;
        const z = f.facts, pre = BigInt('0b' + bits.slice(0, z.t + 1));
        if (z.r0 !== pw(x, pre, n) || z.r1 !== pw(x, pre + 1n, n)) fail('R0 and R1 after bit ' + z.t);
      }
      const end = r.frames[r.frames.length - 1].facts;
      if (end.v !== pw(x, e, n) || end.w !== end.v || end.ls !== bits.length || end.lm !== bits.length || end.ss !== bits.length - 1 || end.sm !== ones(e) - 1) fail('the result and the counts');
    },
  },
  {
    topic: 'p08-montmul', allow: [], mayRefuse: true, count: 12,
    random: (rnd) => { const n = 2 * Math.floor(rnd() * 2046) + 3; return { size: 'toy', n: String(n), a: String(Math.floor(rnd() * n)), b: String(Math.floor(rnd() * n)) }; },
    check({ S, input, r, fail }) {
      const g = (ph) => (r.frames.find((f) => f.meta.phase === ph) || {}).facts || {};
      const { n, k, R, np } = g('setup');
      if (R !== 1n << BigInt(k) || bitlen(n) !== k || mod(np * n, R) !== R - 1n) fail('R and n\'');
      const a = BigInt(input.size === 'toy' ? input.a : input.a), b = BigInt(input.b);
      const { aM, bM } = g('to');
      if (aM !== mod(a * R, n) || bM !== mod(b * R, n)) fail('the Montgomery forms');
      const { t } = g('t'), { m } = g('m'), { mn, s } = g('sum'), { u0 } = g('shift'), { u, extra } = g('extra');
      if (t !== aM * bM || m !== mod(mod(t, R) * np, R) || mn !== m * n || s !== t + mn || s % R !== 0n || u0 !== s / R) fail('t, m and the shift');
      if (u0 >= 2n * n || mod(u0 * R, n) !== mod(aM * bM, n) || (extra === 1) !== (u0 >= n) || u !== (u0 >= n ? u0 - n : u0)) fail('u');
      const { back, direct } = g('back');
      if (back !== (a * b) % n || direct !== back) fail('a·b mod n');
    },
  },
  {
    topic: 'p08-crt', allow: [], mayRefuse: true, count: 10,
    random: (rnd) => ({ key: ['toy', 'toy', 'rsa1024', 'rsa2048'][Math.floor(rnd() * 4)], m: String(Math.floor(rnd() * 13275499)) }),
    check({ S, input, r, fail }) {
      const key = S.P08A.key(input.key), m = BigInt(input.m), c = pw(m, key.e, key.n);
      const g = (ph) => r.frames.find((f) => f.meta.phase === ph).facts;
      if (g('start').c !== c) fail('c');
      const x = g('reduce');
      if (x.cp !== c % key.p || x.cq !== c % key.q || x.dp !== key.d % (key.p - 1n) || x.dq !== key.d % (key.q - 1n)) fail('the halves');
      const h = g('halves');
      if (h.mp !== m % key.p || h.mq !== m % key.q || h.opsP !== bitlen(x.dp) - 1 + ones(x.dp) - 1 || h.opsQ !== bitlen(x.dq) - 1 + ones(x.dq) - 1) fail('mp, mq and their costs');
      if (g('garner').h !== mod(inv(key.q, key.p) * (h.mp - h.mq), key.p)) fail('h');
      if (g('m').v !== m) fail('m');
      const z = g('cost'), opsF = bitlen(key.d) - 1 + ones(key.d) - 1;
      if (z.opsF !== opsF || Math.abs(z.ratio - (opsF * z.kb ** 2) / (z.opsP * z.pb ** 2 + z.opsQ * z.qb ** 2)) > 1e-9) fail('the cost model');
      if (input.key !== 'toy' && nodeRSA(key).dec(c) !== m) fail('node:crypto decrypts to another m');
    },
  },
  {
    topic: 'p08-small-e', allow: ['16', '65537', '3', '17'], count: 4,
    random: (rnd) => ({ key: ['toy2', 'rsa1024', 'rsa2048'][Math.floor(rnd() * 3)], m: String(2 + Math.floor(rnd() * 1e9)) }),
    check({ S, input, r, fail }) {
      const key = S.P08A.key(input.key, 65537), m = BigInt(input.m);
      for (const f of r.frames) {
        if (f.meta.phase !== 'row') continue;
        const x = f.facts, e = x.e;
        if (x.sq !== bitlen(e) - 1 || x.mul !== ones(e) - 1 || x.ops !== x.sq + x.mul || x.bits !== bitlen(e) || x.ones !== ones(e)) fail('the counts for e = ' + e);
        if (f.meta.i < 4 && (gcd(e, key.phi) !== 1n || !isPrime(e))) fail('e = ' + e + ' must be a prime coprime to φ(n)');
        if (f.meta.i === 4 && e !== key.d) fail('the last row is d');
      }
      if (input.key !== 'toy2' && nodeRSA(key).enc(m) !== pw(m, 65537n, key.n)) fail('node:crypto disagrees on m^65537');
    },
  },
];
