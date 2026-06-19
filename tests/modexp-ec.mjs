// Square-and-multiply against node:crypto's raw RSA; the curve engines against node's secp256k1 and the group laws.
import { generateKeyPairSync, publicEncrypt, privateDecrypt, constants, createECDH, randomBytes } from 'node:crypto';
import { load, harness } from './load.mjs';
const S = load(['core']), t = harness('modexp-ec'), M = S.ModExp;
const b64 = (s) => BigInt('0x' + Buffer.from(s, 'base64url').toString('hex'));
const toBuf = (v, n) => Buffer.from(v.toString(16).padStart(2 * n, '0'), 'hex');
t.eq(M.pow(7, 0b1011010011100101, 1000003).value, (() => { let v = 1n; for (let i = 0; i < 0b1011010011100101; i++) v = (v * 7n) % 1000003n; return v; })(), 'a 16-bit exponent against repeated multiplication');
const r16 = M.pow(7, 0b1011010011100101, 1000003);
t.eq(r16.squarings, 15, 'fifteen squarings'); t.eq(r16.multiplications, 8, 'one multiplication for each 1 after the first');
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = privateKey.export({ format: 'jwk' });
const n = b64(jwk.n), e = b64(jwk.e), d = b64(jwk.d);
for (let i = 0; i < 4; i++) {
  const m = BigInt('0x' + randomBytes(200).toString('hex'));
  const c = BigInt('0x' + publicEncrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, toBuf(m, 256)).toString('hex'));
  t.eq(M.pow(m, e, n).value.toString(16), c.toString(16), 'RSA-2048 m^e against node ' + i);
  t.eq(M.pow(c, d, n).value.toString(16), m.toString(16), 'RSA-2048 c^d gives m back ' + i);
  t.eq(BigInt('0x' + privateDecrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, toBuf(c, 256)).toString('hex')).toString(16), M.pow(c, d, n).value.toString(16), 'node agrees on c^d ' + i);
}
// a curve over a small field: the group laws on every point
const F = S.EC.field(97, 2, 3), pts = F.points();
t.ok(pts.every(F.on), 'every listed point is on the curve');
const N = pts.length + 1;
for (const P of pts) { t.ok(F.add(P, F.neg(P)).R === null, 'P + (−P) = O'); t.ok(F.on(F.add(P, P).R), '2P is on the curve'); t.ok(F.mul(N, P) === null, 'N·P = O'); }
for (let i = 0; i < 200; i++) { const [P, Q, R] = [0, 1, 2].map(() => pts[(Math.random() * pts.length) | 0]); t.ok(F.eq(F.add(F.add(P, Q).R, R).R, F.add(P, F.add(Q, R).R).R), 'associativity'); t.ok(F.eq(F.add(P, Q).R, F.add(Q, P).R), 'commutativity'); }
// the real curve: sums lie on the curve
const Rc = S.EC.real(-2, 2);
const P = { x: -1, y: Math.sqrt(Rc.rhs(-1)) }, Q = { x: 0.5, y: -Math.sqrt(Rc.rhs(0.5)) };
t.ok(Rc.on(Rc.add(P, Q).R), 'P + Q on the real curve'); t.ok(Rc.on(Rc.add(P, P).R), '2P on the real curve');
// secp256k1 through the same field code, against node
const p = 2n ** 256n - 2n ** 32n - 977n, K1 = S.EC.field(p, 0, 7);
const Gp = { x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n };
for (let i = 0; i < 3; i++) {
  const k = randomBytes(32), ec = createECDH('secp256k1'); ec.setPrivateKey(k);
  const pub = ec.getPublicKey('hex'), R = K1.mul(BigInt('0x' + k.toString('hex')), Gp);
  t.eq('04' + R.x.toString(16).padStart(64, '0') + R.y.toString(16).padStart(64, '0'), pub, 'secp256k1 k·G against node ' + i);
}
t.done();
