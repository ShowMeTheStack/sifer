// Part 11, the first half: what a signature gives, RSA (raw and hashed), RSA-PSS, Elgamal and DSA. Collected by
// tests/claims-p11.mjs. HMAC, Ed25519, RSA (with no padding and with PSS) and DSA are checked against node:crypto;
// Elgamal by working its formulas out again here.
import crypto from 'node:crypto';
import { pw, inv, mod, gcd } from './claims-lib-pk.mjs';

export const hb = (v, len) => { let h = BigInt(v).toString(16); if (h.length % 2) h = '0' + h; if (len) h = h.padStart(2 * len, '0'); return Buffer.from(h, 'hex'); };
export const big = (b) => BigInt('0x' + (Buffer.from(b).toString('hex') || '0'));
export const sha = (b) => big(crypto.createHash('sha256').update(b).digest());
export const b64u = (v, len) => hb(v, len).toString('base64url');
/** the cut-down hex the pictures and sentences use: first n … last n digits */
export const hs = (h, n) => { n = n || 8; return h.length > 2 * n + 2 ? h.slice(0, n) + '…' + h.slice(-n) : h; };
/** an Ed25519 key pair in node from a 32-byte seed */
export const edKey = (seedHex) => {
  const priv = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv), raw = pub.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { priv, pub, raw: raw.toString('hex') };
};
/** node's RSA key made from the engine's numbers, and m^d mod n computed by node with no padding */
const rsaNode = new Map();
export const rsaKeys = (key) => {
  const id = key.n.toString(16).slice(0, 32);
  if (!rsaNode.has(id)) {
    const k = Number((BigInt(key.n.toString(2).length) + 7n) / 8n);
    const jwk = { kty: 'RSA', n: b64u(key.n), e: b64u(key.e), d: b64u(key.d), p: b64u(key.p), q: b64u(key.q), dp: b64u(key.dp), dq: b64u(key.dq), qi: b64u(key.qinv) };
    const priv = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
    rsaNode.set(id, { priv, pub: crypto.createPublicKey(priv), k });
  }
  return rsaNode.get(id);
};
export const nodeRaw = (key, m) => { const K = rsaKeys(key); return big(crypto.privateEncrypt({ key: K.priv, padding: crypto.constants.RSA_NO_PADDING }, hb(m, K.k))); };
/** DSA verification by node with a key built from p, q, g and y */
const len = (n) => (n < 128 ? Buffer.from([n]) : (() => { const b = []; while (n) { b.unshift(n & 255); n >>= 8; } return Buffer.from([0x80 | b.length, ...b]); })());
const tlv = (t, body) => Buffer.concat([Buffer.from([t]), len(body.length), body]);
const int = (v) => { let b = hb(v); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return tlv(0x02, b); };
const seq = (...x) => tlv(0x30, Buffer.concat(x));
export const dsaOk = (pr, y, msg, r, s) => crypto.verify('sha256', Buffer.from(msg), crypto.createPublicKey({ key: seq(seq(Buffer.from('06072a8648ce380401', 'hex'), seq(int(pr.p), int(pr.q), int(pr.g))), tlv(0x03, Buffer.concat([Buffer.from([0]), int(y)]))), format: 'der', type: 'spki' }), seq(int(r), int(s)));
/** an EC public key in node from its point: P-256 or secp256k1 */
export const ecPub = (curve, Q) => {
  const oid = curve === 'secp256k1' ? '06052b8104000a' : '06082a8648ce3d030107';
  const pt = Buffer.concat([Buffer.from([4]), hb(Q.x, 32), hb(Q.y, 32)]);
  return crypto.createPublicKey({ key: seq(seq(Buffer.from('06072a8648ce3d0201', 'hex'), Buffer.from(oid, 'hex')), tlv(0x03, Buffer.concat([Buffer.from([0]), pt]))), format: 'der', type: 'spki' });
};
export const ecOk = (curve, Q, msg, r, s) => crypto.verify('sha256', Buffer.from(msg), { key: ecPub(curve, Q), dsaEncoding: 'ieee-p1363' }, Buffer.concat([hb(r, 32), hb(s, 32)]));
const MODP = crypto.getDiffieHellman('modp14'), Pm = big(MODP.getPrime());
const F = (r, ph) => (r.frames.find((f) => f.meta.phase === ph) || {}).facts || {};
const textIn = (rnd, words) => words[Math.floor(rnd() * words.length)] + ' ' + Math.floor(rnd() * 1000);
const W = ['pay', 'ship', 'open', 'close', 'sign', 'send'];

export const mods = [
  {
    topic: 'p11-what', allow: ['32', '64'],
    random: (rnd) => ({ msg: textIn(rnd, W), fake: textIn(rnd, W) + '!', mk: crypto.randomBytes(32).toString('hex'), seed: crypto.randomBytes(32).toString('hex') }),
    count: 6,
    check({ input, r, fail }) {
      const tag = crypto.createHmac('sha256', Buffer.from(input.mk, 'hex')).update(input.msg).digest('hex'), tagF = crypto.createHmac('sha256', Buffer.from(input.mk, 'hex')).update(input.fake).digest('hex');
      const K = edKey(input.seed), sig = crypto.sign(null, Buffer.from(input.msg), K.priv).toString('hex');
      if (F(r, 'setup').pub !== K.raw) fail('the Ed25519 public key against node:crypto');
      if (F(r, 'mac').tag !== tag || F(r, 'mac-tamper').tagF !== tagF) fail('the HMAC tags against node:crypto');
      if (F(r, 'sig').sig !== sig) fail('the Ed25519 signature against node:crypto');
      if (F(r, 'sig-tamper').ok !== crypto.verify(null, Buffer.from(input.fake), K.pub, Buffer.from(sig, 'hex'))) fail('the altered message');
      if (F(r, 'table').len !== 32 || F(r, 'table').slen !== 64) fail('the sizes');
    },
  },
  {
    topic: 'p11-rsa-sign', allow: ['256', '2048', '11'],
    random: (rnd) => ({ key: ['toy', 'rsa1024', 'rsa2048'][Math.floor(rnd() * 3)], m1: String(2 + Math.floor(rnd() * 5000)), m2: String(2 + Math.floor(rnd() * 5000)), t1: textIn(rnd, W), t2: textIn(rnd, W) }),
    count: 8,
    check({ S, input, r, fail }) {
      const key = S.P11.rsaKey(input.key), { n, e, d } = key, real = input.key !== 'toy';
      const sg = (m) => (real ? nodeRaw(key, m) : pw(m, d, n));
      if (real && pw(nodeRaw(key, 12345n), e, n) !== 12345n) fail('node and the key disagree');
      if (F(r, 'keys').d !== d || mod(e * d, (key.p - 1n) * (key.q - 1n) / gcd(key.p - 1n, key.q - 1n)) !== 1n) fail('d');
      const m1 = BigInt(input.m1), m2 = BigInt(input.m2), a = F(r, 'raw1'), b = F(r, 'raw2'), c = F(r, 'product');
      if (a.s1 !== sg(m1) || a.c1 !== m1 || b.s2 !== sg(m2) || b.c2 !== m2) fail('the raw signatures');
      if (c.s3 !== (a.s1 * b.s2) % n || c.m3 !== (m1 * m2) % n || c.c3 !== pw(c.s3, e, n) || c.c3 !== c.m3 || c.s3 !== sg(c.m3)) fail('the product');
      const fr = F(r, 'free');
      if (fr.mFree !== pw(fr.sFree, e, n) || sg(fr.mFree) !== fr.sFree) fail('the free forgery');
      const h = F(r, 'hash2'), z1 = sha(Buffer.from(input.t1)) % n, z2 = sha(Buffer.from(input.t2)) % n;
      if (h.z1 !== z1 || h.z2 !== z2 || h.h1 !== sg(z1) || h.h2 !== sg(z2)) fail('hash then sign');
      const hp = F(r, 'hash-product');
      if (hp.z3 !== (z1 * z2) % n || hp.h3 !== (h.h1 * h.h2) % n || hp.g3 !== hp.z3) fail('the hashed product');
      const pd = F(r, 'pad');
      if (pd.zb !== z1.toString(2).length || pd.nb !== n.toString(2).length) fail('the bit lengths');
    },
  },
  {
    topic: 'p11-pss', allow: ['32', '8', '00', '00000000', '00000001', '01', '256', '1'],
    random: (rnd) => ({ key: ['rsa1024', 'rsa2048', 'rsa3072'][Math.floor(rnd() * 3)], msg: textIn(rnd, W), salt: crypto.randomBytes([0, 16, 20, 32][Math.floor(rnd() * 4)]).toString('hex') }),
    count: 6,
    check({ S, input, r, fail }) {
      const key = S.PK.rsaKey(input.key), K = rsaKeys(key), salt = Buffer.from(input.salt, 'hex'), sl = salt.length;
      const emLen = Math.ceil((key.n.toString(2).length - 1) / 8), dbLen = emLen - 33;
      const s = F(r, 'sign').s, s2 = F(r, 'salt2').s2;
      const ok = (sig, msg) => crypto.verify('sha256', Buffer.from(msg), { key: K.pub, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: sl }, hb(sig, K.k));
      if (!ok(s, input.msg)) fail('node:crypto refuses the PSS signature');
      if (!ok(s2, input.msg) || F(r, 'salt2').ok2 !== true) fail('node:crypto refuses the second signature');
      if (F(r, 'salt2').same !== (s === s2) || (sl && s === s2)) fail('the second salt');
      if (ok(s, input.msg + '!') || F(r, 'tamper').ok !== false) fail('the altered message');
      const mHash = crypto.createHash('sha256').update(input.msg).digest(), H = crypto.createHash('sha256').update(Buffer.concat([Buffer.alloc(8), mHash, salt])).digest();
      if (F(r, 'mhash').mh !== mHash.toString('hex').slice(0, 16) + '…') fail('mHash');
      if (F(r, 'h').h !== H.toString('hex').slice(0, 16) + '…' || F(r, 'h').mp !== 40 + sl) fail('H');
      const m = F(r, 'mask');
      if (m.dbLen !== dbLen || m.blocks !== Math.ceil(dbLen / 32) || m.lastB !== dbLen - 32 * (m.blocks - 1)) fail('the MGF1 blocks');
      // EM from node (s^e with no padding) ends with H and bc
      const em = crypto.publicDecrypt({ key: K.pub, padding: crypto.constants.RSA_NO_PADDING }, hb(s, K.k)).subarray(K.k - emLen);
      if (em[emLen - 1] !== 0xbc || !em.subarray(emLen - 33, emLen - 1).equals(H)) fail('EM from node does not end in H ‖ bc');
      // unmask with an MGF1 of our own, from node's SHA-256
      const mask = Buffer.concat(Array.from({ length: m.blocks }, (_, i) => crypto.createHash('sha256').update(Buffer.concat([H, Buffer.from([i >>> 24, (i >>> 16) & 255, (i >>> 8) & 255, i & 255])])).digest())).subarray(0, dbLen);
      const db = Buffer.from(em.subarray(0, dbLen).map((v, i) => v ^ mask[i])); db[0] &= 0xff >> (8 * emLen - (key.n.toString(2).length - 1));
      if (db[dbLen - sl - 1] !== 1 || !db.subarray(dbLen - sl).equals(salt) || db.subarray(0, dbLen - sl - 1).some((v) => v)) fail('DB is not zeros ‖ 01 ‖ salt');
      if (F(r, 'db').psLen !== dbLen - sl - 1) fail('the zero bytes');
    },
  },
  {
    topic: 'p11-elgamal', allow: ['2', '11'],
    random: (rnd) => { if (rnd() < 0.25) return { size: 'real', seed: 1 + Math.floor(rnd() * 999), msg: textIn(rnd, W), fake: textIn(rnd, W) + '?' }; const p = [467, 1019, 2027][Math.floor(rnd() * 3)]; let k; do { k = 2 + Math.floor(rnd() * (p - 3)); } while (gcd(k, p - 1) !== 1n); return { size: 'toy', p: String(p), x: 2 + Math.floor(rnd() * (p - 4)), k, msg: textIn(rnd, W), fake: textIn(rnd, W) + '?' }; },
    count: 10,
    check({ input, r, fail }) {
      const k0 = F(r, 'keys'), p = k0.p, g = k0.g, x = k0.x, y = k0.y, pm = p - 1n, real = input.size === 'real';
      if (real ? p !== Pm || g !== 2n : p !== BigInt(input.p)) fail('the group');
      if (!real) { let o = 1n, v = g; while (v !== 1n) { v = (v * g) % p; o++; } if (o !== pm) fail('g is not a generator'); }
      if (y !== pw(g, x, p)) fail('y');
      const z = mod(sha(Buffer.from(input.msg)), pm), n = F(r, 'nonce'), s = F(r, 'sign');
      if (F(r, 'hash').z !== z || n.r !== pw(g, n.k, p) || n.gcd !== 1n || gcd(n.k, pm) !== 1n) fail('z, k or r');
      if (s.kinv !== inv(n.k, pm) || s.s !== mod(s.kinv * (z - x * n.r), pm)) fail('s');
      const c = F(r, 'check');
      if (c.gz !== pw(g, z, p) || c.yr !== pw(y, n.r, p) || c.rs !== pw(n.r, s.s, p) || c.prod !== (c.yr * c.rs) % p || c.gz !== c.prod || c.ok !== true) fail('the check');
      const w = F(r, 'why');
      if (w.xr !== mod(x * n.r, pm) || w.ks !== mod(n.k * s.s, pm) || w.sum !== mod(w.xr + w.ks, pm) || w.sum !== z) fail('the exponents');
      const t = F(r, 'tamper'), z2 = mod(sha(Buffer.from(input.fake)), pm);
      if (t.z2 !== z2 || t.gz2 !== pw(g, z2, p) || t.ok !== (t.gz2 === c.prod)) fail('the altered message');
      const ru = F(r, 'rules');
      if (ru.bits !== p.toString(2).length || ru.twice !== 2 * ru.bits) fail('the size');
    },
  },
  {
    topic: 'p11-dsa', allow: [],
    random: (rnd) => (rnd() < 0.3 ? { size: 'real', seed: 1 + Math.floor(rnd() * 999), msg: textIn(rnd, W) } : { size: 'toy', q: [11, 101, 1009, 10007, 99991][Math.floor(rnd() * 5)], x: 1 + Math.floor(rnd() * 10), k: 1 + Math.floor(rnd() * 10), msg: textIn(rnd, W) }),
    count: 10,
    check({ input, r, fail }) {
      const pr = F(r, 'params'), keys = F(r, 'keys'), p = pr.p, q = pr.q, g = pr.g, real = input.size === 'real';
      if ((p - 1n) % q !== 0n || pr.cof !== (p - 1n) / q || pr.gq !== 1n || pw(g, q, p) !== 1n || g === 1n) fail('the parameters');
      if (pr.L !== p.toString(2).length || pr.N !== q.toString(2).length) fail('the bit lengths');
      if (real && (pr.L !== 2048 || pr.N !== 224)) fail('the real sizes');
      if (keys.y !== pw(g, keys.x, p)) fail('y');
      const qb = q.toString(2).length, H = sha(Buffer.from(input.msg)), z = qb >= 256 ? H : H >> BigInt(256 - qb);
      const gk = F(r, 'gk'), rr = F(r, 'r').r, s = F(r, 's');
      if (F(r, 'hash').z !== z || gk.gk !== pw(g, gk.k, p) || rr !== gk.gk % q || s.kinv !== inv(gk.k, q) || s.s !== mod(s.kinv * (z + keys.x * rr), q) || s.sb !== 2 * qb) fail('the signature');
      const w = F(r, 'w'), v = F(r, 'v');
      if (w.w !== inv(s.s, q) || w.u1 !== mod(z * w.w, q) || w.u2 !== mod(rr * w.w, q)) fail('w, u1, u2');
      if (v.X !== (pw(g, w.u1, p) * pw(keys.y, w.u2, p)) % p || v.v !== v.X % q || v.v !== rr || v.ok !== true) fail('the check');
      if (real && !dsaOk({ p, q, g }, keys.y, input.msg, rr, s.s)) fail('node:crypto refuses the DSA signature');
      if (F(r, 'sizes').sb !== 2 * qb || F(r, 'sizes').eb !== 2 * pr.L) fail('the sizes');
    },
  },
];
