// Part 10 claims: scalar multiplication, key exchange, curve shapes and encodings. Multiples are recomputed with the
// plain affine arithmetic of claims-p10-lib.mjs; X25519 and P-256 ECDH against node:crypto.
import { ec, mod, inv, P256, K256, at, crypto, b64u } from './claims-p10-lib.mjs';

const B = BigInt;
/** the curves the topics offer, with parameters typed in here */
export const CURVE = {
  gf101: { p: 101n, a: 6n, b: 14n, n: 103n, G: { x: 1n, y: 18n } },
  gf1009: { p: 1009n, a: 7n, b: 26n, n: 1019n, G: { x: 2n, y: 413n } },
  'P-256': P256, secp256k1: K256,
};
const cache = new Map();
export const curve = (id) => { if (!cache.has(id)) { const c = CURVE[id]; cache.set(id, Object.assign(ec(c.p, c.a, c.b), { n: c.n, G: c.G })); } return cache.get(id); };
const parseK = (v) => B(String(v).trim().toLowerCase());
const same = (A, Bp) => (!A || !Bp ? !A && !Bp : B(A.x) === B(Bp.x) && B(A.y) === B(Bp.y));
const randK = (rnd, bits) => { let k = 0n; for (let i = 0; i < bits; i++) k = (k << 1n) | (rnd() < 0.5 ? 1n : 0n); return k | 1n; };
const randCurveK = (rnd) => { const ids = ['gf101', 'gf1009', 'P-256', 'secp256k1'], id = ids[Math.floor(rnd() * 4)], C = curve(id); let k = id.startsWith('gf') ? 1n + B(Math.floor(rnd() * Number(C.n - 1n))) : randK(rnd, 8 + Math.floor(rnd() * 120)); return { curve: id, k: k.toString() }; };
/** my own width-w NAF */
const naf = (k, w) => { const out = []; const W = 1n << B(w); while (k > 0n) { let d = 0n; if (k & 1n) { d = k % W; if (d >= W / 2n) d -= W; } out.push(d); k = (k - d) / 2n; } return out; };

export const mods = [
  {
    topic: 'ec-double-add', count: 8,
    random: (rnd) => Object.assign(randCurveK(rnd), { dir: rnd() < 0.5 ? 'ltr' : 'rtl' }),
    check({ input, r, fail }) {
      const C = curve(input.curve), k = parseK(input.k), ltr = input.dir === 'ltr', n = k.toString(2).length, ones = k.toString(2).split('1').length - 1;
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'bit') {
          const want = ltr ? k >> B(x.i) : k & ((1n << B(x.i + 1)) - 1n);
          if (B(x.mult) !== want) fail('the multiple at bit ' + x.i);
          if (!same(x.R, C.mul(want, C.G))) fail('the running point at bit ' + x.i);
          if (!ltr && !same(x.Q, C.mul(1n << B(x.i), C.G))) fail('Q at bit ' + x.i);
          if (x.bit !== Number((k >> B(x.i)) & 1n)) fail('bit ' + x.i);
        }
        if (st === 'done') {
          if (!same(x.R, C.mul(k, C.G))) fail('k·P');
          if (x.d !== n - 1 || x.a !== ones - 1 || x.ones !== ones) fail('the counts: ' + x.d + ', ' + x.a);
        }
      }
    },
  },
  {
    topic: 'ec-ladder', count: 6, random: randCurveK,
    check({ input, r, fail }) {
      const C = curve(input.curve), k = parseK(input.k), n = k.toString(2).length;
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'bit') {
          const m = k >> B(x.i);
          if (B(x.m) !== m || B(x.m1) !== m + 1n || B(x.m0) !== k >> B(x.i0 + 1)) fail('the multiples at bit ' + x.i);
          if (!same(x.R0, C.mul(m, C.G)) || !same(x.R1, C.mul(m + 1n, C.G))) fail('R₀ or R₁ at bit ' + x.i);
        }
        if (st === 'done' && (!same(x.R, C.mul(k, C.G)) || x.a !== n || x.d !== n)) fail('the result or the counts');
      }
    },
  },
  {
    topic: 'ec-wnaf', count: 6, allow: ['3'],
    random: (rnd) => Object.assign(randCurveK(rnd), { w: 2 + Math.floor(rnd() * 5) }),
    check({ input, r, fail }) {
      const C = curve(input.curve), k = parseK(input.k), w = input.w, ds = naf(k, w);
      if (ds.reduce((s, d, i) => s + d * (1n << B(i)), 0n) !== k) fail('my NAF does not add up');
      ds.forEach((d, i) => { if (d) { if (!(d & 1n) || (d < 0n ? -d : d) >= 1n << B(w - 1)) fail('a digit out of range'); for (let j = 1; j < w && i + j < ds.length; j++) if (ds[i + j]) fail('two nonzero digits too close'); } });
      const nz = ds.filter((d) => d).length;
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'recode') { if (B(x.d) !== ds[x.i]) fail('digit ' + x.i); if (x.nd !== ds.length || x.nz !== nz) fail('the digit counts'); if (B(x.r) !== B(x.k) % (1n << B(w))) fail('k mod 2^w'); }
        if (st === 'cost') { if (!same(x.R, C.mul(k, C.G))) fail('k·P'); if (x.m !== 1 << (w - 2)) fail('the table size'); if (x.a > nz + x.m) fail('more additions than nonzero digits and the table'); }
      }
    },
  },
  {
    topic: 'ec-jacobian', count: 4,
    random: (rnd) => Object.assign(randCurveK(rnd), { z: String(2 + Math.floor(rnd() * 1e6)) }),
    check({ input, r, fail }) {
      const C = curve(input.curve), k = parseK(input.k), p = C.p, nb = k.toString(2).length, ones = k.toString(2).split('1').length - 1;
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'repr') { const Z = B(x.Z); if (B(x.J.X) !== mod(C.G.x * Z * Z, p) || B(x.J.Y) !== mod(C.G.y * Z * Z * Z, p)) fail('X or Y'); if (!same(x.back, C.G)) fail('back to affine'); }
        if (st === 'count') { if (!same(x.R, C.mul(3n, C.G))) fail('3P'); const e = (p - 2n).toString(2); if (x.pb1 !== e.length - 1 || x.pw1 !== e.split('1').length - 2) fail('the cost of Fermat'); }
        if (st === 'table') {
          const [l, rt, ld] = x.rows;
          if (l[0] !== nb - 1 || l[1] !== ones - 1 || rt[0] !== nb - 1 || rt[1] !== ones - 1) fail('double-and-add counts');
          if (ld[0] !== nb || ld[1] !== nb) fail('ladder counts');
          if (x.inv !== l[0] + l[1]) fail('the inversions');
          if (!f.meta.same) fail('the methods disagree');
        }
      }
    },
  },
];

const p25519 = (1n << 255n) - 19n;
/** RFC 7748's x-only ladder, written out again here (no clamping): the u of k·u */
export function xLadder(k, u) {
  const p = p25519, m = (v) => ((v % p) + p) % p, pw = (b, e) => { let r = 1n; b = m(b); while (e) { if (e & 1n) r = (r * b) % p; b = (b * b) % p; e >>= 1n; } return r; };
  let x2 = 1n, z2 = 0n, x3 = u, z3 = 1n;
  for (let t = 254; t >= 0; t--) {
    if ((k >> BigInt(t)) & 1n) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    const A = m(x2 + z2), AA = m(A * A), Bb = m(x2 - z2), BB = m(Bb * Bb), Ee = m(AA - BB), C = m(x3 + z3), D = m(x3 - z3), DA = m(D * A), CB = m(C * Bb);
    x3 = m((DA + CB) ** 2n); z3 = m(u * (DA - CB) ** 2n); x2 = m(AA * BB); z2 = m(Ee * (AA + 121665n * Ee));
    if ((k >> BigInt(t)) & 1n) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
  }
  return m(x2 * pw(z2, p - 2n));
}
const x25519Key = (hex) => crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(hex, 'hex')]), format: 'der', type: 'pkcs8' });
const ecdhNode = (id, d, Q) => { const e = crypto.createECDH(id === 'P-256' ? 'prime256v1' : 'secp256k1'); e.setPrivateKey(Buffer.from(d.toString(16).padStart(64, '0'), 'hex')); return e.computeSecret(Buffer.concat([Buffer.from([4]), Buffer.from(Q.x.toString(16).padStart(64, '0'), 'hex'), Buffer.from(Q.y.toString(16).padStart(64, '0'), 'hex')])).toString('hex'); };

mods.push(
  {
    topic: 'ec-ecdh', count: 6,
    random: (rnd) => { const id = ['gf101', 'gf1009', 'P-256', 'secp256k1'][Math.floor(rnd() * 4)], C = curve(id), r = () => (id.startsWith('gf') ? 1n + B(Math.floor(rnd() * Number(C.n - 1n))) : randK(rnd, 250)); return { curve: id, dA: r().toString(), dB: r().toString() }; },
    check({ input, r, fail }) {
      const C = curve(input.curve), dA = parseK(input.dA), dB = parseK(input.dB), QA = C.mul(dA, C.G), QB = C.mul(dB, C.G), Sp = C.mul(dA * dB, C.G);
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'alice' && !same(x.QA, QA)) fail('Q_A');
        if (st === 'bob' && !same(x.QB, QB)) fail('Q_B');
        if (st === 'shared' && (!same(x.S, Sp) || !same(x.SB, Sp))) fail('S');
        if (st === 'secret') {
          if (x.shared !== Sp.x.toString(16).padStart(2 * x.len, '0')) fail('the shared bytes');
          if (!input.curve.startsWith('gf') && ecdhNode(input.curve, dA, QB) !== x.shared) fail('node:crypto computes a different shared secret');
        }
      }
    },
  },
  {
    topic: 'ec-x25519', count: 4,
    random: (rnd) => ({ a: Buffer.from(Array.from({ length: 32 }, () => Math.floor(rnd() * 256))).toString('hex'), b: Buffer.from(Array.from({ length: 32 }, () => Math.floor(rnd() * 256))).toString('hex') }),
    check({ input, r, fail }) {
      const a = Buffer.from(input.a, 'hex'), c = Buffer.from(a); c[0] &= 248; c[31] &= 127; c[31] |= 64;
      const k = B('0x' + Buffer.from(c).reverse().toString('hex'));
      const ka = x25519Key(input.a), kb = x25519Key(input.b);
      const pubA = Buffer.from(crypto.createPublicKey(ka).export({ format: 'jwk' }).x, 'base64url').toString('hex'), pubB = Buffer.from(crypto.createPublicKey(kb).export({ format: 'jwk' }).x, 'base64url').toString('hex');
      const sh = crypto.diffieHellman({ privateKey: ka, publicKey: crypto.createPublicKey(kb) }).toString('hex');
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'clamp' && (x.c0 !== c[0].toString(2).padStart(8, '0') || x.c31 !== c[31].toString(2).padStart(8, '0') || x.b0 !== a[0].toString(2).padStart(8, '0'))) fail('the clamped bytes');
        if (st === 'scalar' && (B(x.k) !== k || x.nb !== 255 || B(x.m8) !== 0n)) fail('the clamped scalar');
        if (st === 'ladder') { const m = k >> B(x.t); if (B(x.m) !== m) fail('m at bit ' + x.t); if (x.u !== xLadder(m, 9n).toString(16) || x.u1 !== xLadder(m + 1n, 9n).toString(16)) fail('the u values at bit ' + x.t); if (x.bit !== Number((k >> B(x.t)) & 1n)) fail('bit ' + x.t); }
        if (st === 'public' && x.pub !== pubA) fail('Alice\'s public key differs from node:crypto');
        if (st === 'shared' && f.meta.eq && (x.S !== sh || x.B !== pubB)) fail('the shared secret differs from node:crypto');
      }
    },
  },
);

const legendre = (v, p) => { const r = ((v % p) + p) % p; if (r === 0n) return 0; let e = (p - 1n) / 2n, b = r, out = 1n; while (e) { if (e & 1n) out = (out * b) % p; b = (b * b) % p; e >>= 1n; } return out === 1n ? 1 : -1; };
mods.push(
  {
    topic: 'ec-forms', count: 0,
    check({ input, r, fail }) {
      const p = B(input.p), A = B(input.A), Bm = B(input.B), m = (v) => mod(v, p), iv = (v) => inv(v, p);
      const a = m((A + 2n) * iv(Bm)), d = m((A - 2n) * iv(Bm)), wa = m((3n - A * A) * iv(3n * Bm * Bm)), wb = m((2n * A ** 3n - 9n * A) * iv(27n * Bm ** 3n));
      const onM = (P) => m(Bm * P.v * P.v - P.u ** 3n - A * P.u * P.u - P.u) === 0n, onE = (P) => m(a * P.x * P.x + P.y * P.y - 1n - d * P.x * P.x * P.y * P.y) === 0n, W = ec(p, wa, wb);
      let nM = 0; for (let u = 0n; u < p; u++) for (let v = 0n; v < p; v++) if (onM({ u, v })) nM++;
      const madd = (P, Q) => { if (P.u === Q.u && m(P.v + Q.v) === 0n) return null; const l = P.u === Q.u ? m((3n * P.u * P.u + 2n * A * P.u + 1n) * iv(2n * Bm * P.v)) : m((Q.v - P.v) * iv(Q.u - P.u)); const u = m(Bm * l * l - A - P.u - Q.u); return { u, v: m(l * (P.u - u) - P.v) }; };
      const pt = (t) => { const x = t.split(',').map((z) => B(z.trim())); return { u: x[0], v: x[1] }; };
      const P = pt(input.P), Q = pt(input.Q), R = madd(P, Q);
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'start' && (x.n !== nM || B(x.a) !== a || B(x.d) !== d || B(x.wa) !== wa || B(x.wb) !== wb)) fail('the counts or the constants');
        if (st === 'mont' && R && (B(x.R.u) !== R.u || B(x.R.v) !== R.v)) fail('P + Q on the Montgomery curve');
        if (st === 'edw') { for (const e of x.E) if (e && !onE(e)) fail('an Edwards image off the curve'); if (!f.meta.ok) fail('the Edwards sum'); }
        if (st === 'weier') { for (const w of x.W) if (w && !W.on(w)) fail('a Weierstrass image off the curve'); if (!same(x.wS, W.add(x.W[0], x.W[1]))) fail('the Weierstrass sum'); if (!f.meta.ok) fail('Weierstrass disagrees'); }
        if (st === 'all' && (x.pairs !== (nM + 1) ** 2 || !f.meta.ok)) fail('the pairs');
      }
    },
  },
  {
    topic: 'ec-curve-choice', count: 0, allow: ['3', '4', '5', '6', '8', '128', '256', '255', '224', '192', '96', '977', '19', '32', '33', '7'],
    check({ input, r, fail }) {
      const C = input.left === 'P-256' ? P256 : K256, p2 = (1n << 255n) - 19n, L = (1n << 252n) + 27742317777372353535851937790883648493n;
      for (const f of r.frames) {
        const x = f.facts;
        if (x.s1) { const t1 = 2n * C.p + 2n - C.n, t2 = 2n * p2 + 2n - 8n * L; const q1 = x.s1.reduce((a, b) => a * B(b), 1n), q2 = x.s2.reduce((a, b) => a * B(b), 1n); if (t1 % q1 || t2 % q2) fail('the small factors'); if ((t1 / q1).toString(2).length !== x.b1 || (t2 / q2).toString(2).length !== x.b2) fail('the bit lengths of the twist factors'); }
        if (x.M2 !== undefined && (x.M2 !== 1275 || x.S2 !== 1020)) fail('the ladder cost');
        if (x.lb !== undefined && (x.lb !== 253 || x.nb !== 256)) fail('the subgroup sizes');
      }
    },
  },
  {
    topic: 'ec-compress', count: 0, allow: ['4', '3', '04', '02', '03'],
    check({ input, r, fail }) {
      const C = curve(input.curve), d = B(input.d), Q = C.mul(d, C.G), p = C.p;
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'full' && !same(x.Q, Q)) fail('Q');
        if (st === 'compress' && (x.pre !== 2 + Number(Q.y & 1n))) fail('the prefix');
        if (st === 'decode') { const rhs = mod(Q.x ** 3n + C.a * Q.x + C.b, p); if (B(x.rhs) !== rhs || mod(B(x.r1) ** 2n - rhs, p) !== 0n || B(x.y) !== Q.y) fail('the decoding'); }
        if (st === 'reject') { const rhs = mod(B(x.x) ** 3n + C.a * B(x.x) + C.b, p); if (B(x.rhs) !== rhs || legendre(rhs, p) !== -1) fail('the rejected x has a point'); }
      }
    },
  },
);

export { same, randK };
