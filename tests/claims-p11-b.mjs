// Part 11, the second half: Schnorr, ECDSA with RFC 6979, Ed25519, the nonce rules and the comparison. Collected by
// tests/claims-p11.mjs. ECDSA and Ed25519 signatures are checked with node:crypto (Ed25519 byte for byte, since it is
// deterministic), the RFC 6979 chain with node's HMAC, and the presets against the published vectors of RFC 6979
// (appendix A.2.5) and RFC 8032 (section 7.1).
import crypto from 'node:crypto';
import { pw, inv, mod } from './claims-lib-pk.mjs';
import { hb, big, sha, hs, edKey, rsaKeys, ecOk, dsaOk } from './claims-p11-a.mjs';

const F = (r, ph) => (r.frames.find((f) => f.meta.phase === ph) || {}).facts || {};
const RAW = (r) => r.frames[0].meta.raw;
const W = ['pay', 'ship', 'open', 'close', 'sign', 'send'];
const textIn = (rnd) => W[Math.floor(rnd() * W.length)] + ' ' + Math.floor(rnd() * 1000);
const H = (h) => BigInt('0x' + h);

// RFC 6979, appendix A.2.5: P-256 with SHA-256
const RFC6979 = {
  x: H('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721'),
  Ux: H('60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6'), Uy: H('7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299'),
  sample: { k: H('a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60'), r: H('efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716'), s: H('f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8') },
  test: { k: H('d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0'), r: H('f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367'), s: H('019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083') },
};
// RFC 8032, section 7.1: tests 1 to 3
const RFC8032 = {
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60': 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb': '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
  'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7': '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
};

/** RFC 6979 (section 3.2, HMAC-SHA-256) with node's HMAC */
export function rfc6979(q, d, digest) {
  const qlen = q.toString(2).length, rlen = Math.ceil(qlen / 8);
  const mac = (k, ...p) => crypto.createHmac('sha256', k).update(Buffer.concat(p.map((x) => Buffer.from(x)))).digest();
  const b2i = (b) => { const v = big(b), bl = b.length * 8; return bl > qlen ? v >> BigInt(bl - qlen) : v; };
  const x = hb(d, rlen), z = b2i(digest), h1 = hb(z >= q ? z - q : z, rlen);
  let V = Buffer.alloc(32, 1), K = Buffer.alloc(32);
  K = mac(K, V, [0], x, h1); V = mac(K, V); const K1 = K, V1 = V;
  K = mac(K, V, [1], x, h1); V = mac(K, V); const K2 = K, V2 = V;
  for (;;) {
    let T = Buffer.alloc(0);
    while (T.length < rlen) { V = mac(K, V); T = Buffer.concat([T, V]); }
    const k = b2i(T);
    if (k >= 1n && k < q) return { k, K1, V1, K2, V2, T };
    K = mac(K, V, [0]); V = mac(K, V);
  }
}
/** a small curve's arithmetic, affine, written out again here */
const toyCurve = (p, a) => {
  const add = (P, Q) => {
    if (!P) return Q; if (!Q) return P;
    let l;
    if (P.x === Q.x) { if (mod(P.y + Q.y, p) === 0n) return null; l = mod((3n * P.x * P.x + a) * inv(2n * P.y, p), p); } else l = mod((Q.y - P.y) * inv(Q.x - P.x, p), p);
    const x = mod(l * l - P.x - Q.x, p);
    return { x, y: mod(l * (P.x - x) - P.y, p) };
  };
  const mul = (k, P) => { let R = null; for (const b of k.toString(2)) { R = add(R, R); if (b === '1') R = add(R, P); } return R; };
  return { add, mul };
};
const L25519 = (1n << 252n) + 27742317777372353535851937790883648493n;
const le = (b) => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };

export const mods = [
  {
    topic: 'p11-schnorr', allow: [],
    random: (rnd) => (rnd() < 0.3 ? { size: 'real', seed: 1 + Math.floor(rnd() * 999), msg: textIn(rnd), fake: textIn(rnd) + '?' } : { size: 'toy', q: [101, 1009, 10007][Math.floor(rnd() * 3)], x: 1 + Math.floor(rnd() * 99), k: 1 + Math.floor(rnd() * 99), c: 1 + Math.floor(rnd() * 99), msg: textIn(rnd), fake: textIn(rnd) + '?' }),
    count: 10,
    check({ input, r, fail }) {
      const s0 = F(r, 'setup'), { p, q, g, y, x } = s0;
      if (pw(g, q, p) !== 1n || (p - 1n) % q !== 0n || y !== pw(g, x, p)) fail('the group or the key');
      const cm = F(r, 'commit'), c = F(r, 'challenge').c, s = F(r, 'response').s, ck = F(r, 'check');
      if (cm.R !== pw(g, cm.k, p) || s !== mod(cm.k + c * x, q) || ck.gs !== pw(g, s, p) || ck.ryc !== (cm.R * pw(y, c, p)) % p || ck.gs !== ck.ryc) fail('the identification');
      const sm = F(r, 'simulate');
      if (sm.Rs !== (pw(g, sm.sS, p) * pw(y, mod(-c, q), p)) % p || sm.gsS !== pw(g, sm.sS, p) || sm.chkS !== (sm.Rs * pw(y, c, p)) % p || sm.gsS !== sm.chkS) fail('the simulated transcript');
      const fs = F(r, 'fs'), e = mod(sha(Buffer.concat([hb(cm.R), Buffer.from(input.msg)])), q);
      if (fs.R !== cm.R || fs.e !== e || F(r, 'sign').s !== mod(cm.k + e * x, q)) fail('the Fiat–Shamir signature');
      const v = F(r, 'verify'), t = F(r, 'tamper');
      if (v.R2 !== cm.R || v.e2 !== e || v.ok !== true) fail('the verification');
      if (t.R2 !== cm.R || t.e2 !== mod(sha(Buffer.concat([hb(cm.R), Buffer.from(input.fake)])), q) || t.ok !== (t.e2 === e)) fail('the altered message');
    },
  },
  {
    topic: 'p11-ecdsa', allow: ['32', '256', '00', '01', '1'],
    random: (rnd) => (rnd() < 0.3 ? { curve: 'gf1009', d: String(1 + Math.floor(rnd() * 1017)), msg: textIn(rnd) } : { curve: 'P-256', d: '0x' + crypto.randomBytes(31).toString('hex'), msg: textIn(rnd) }),
    count: 8,
    check({ S, input, r, fail }) {
      const raw = RAW(r), C = input.curve === 'P-256' ? S.ECC.P256 : S.ECC.toy(input.curve), n = C.n, msg = Buffer.from(input.msg);
      const digest = crypto.createHash('sha256').update(msg).digest(), ch = rfc6979(n, raw.d, digest);
      if (raw.digest !== digest.toString('hex')) fail('the hash');
      if (raw.k !== ch.k || raw.chain.K1 !== ch.K1.toString('hex') || raw.chain.V1 !== ch.V1.toString('hex') || raw.chain.K2 !== ch.K2.toString('hex') || raw.chain.V2 !== ch.V2.toString('hex') || raw.chain.T !== ch.T.toString('hex')) fail('the RFC 6979 chain against node\'s HMAC');
      const sh6 = (b) => hs(b.toString('hex'), 6);
      if (F(r, 'k1').K1 !== sh6(ch.K1) || F(r, 'k1').V1 !== sh6(ch.V1) || F(r, 'k2').K2 !== sh6(ch.K2) || F(r, 'k2').V2 !== sh6(ch.V2)) fail('the chain as quoted');
      const qlen = n.toString(2).length, e = qlen < 256 ? big(digest) >> BigInt(256 - qlen) : big(digest);
      if (raw.e !== e || mod(raw.s * raw.k, n) !== mod(e + raw.r * raw.d, n) || raw.ki !== inv(raw.k, n)) fail('s');
      if (raw.again.k !== raw.k || raw.again.s !== raw.s) fail('signing again');
      if (input.curve === 'P-256') {
        if (!ecOk('P-256', raw.Q, msg, raw.r, raw.s)) fail('node:crypto refuses the signature');
        if (!ecOk('P-256', raw.Q, Buffer.from(raw.fake.m), raw.fake.r, raw.fake.s)) fail('node:crypto refuses the second signature');
        const ecdh = crypto.createECDH('prime256v1'); ecdh.setPrivateKey(hb(raw.d, 32));
        if (big(ecdh.getPublicKey().subarray(1, 33)) !== raw.Q.x) fail('Q against node:crypto');
        if (raw.d === RFC6979.x) {
          const v = RFC6979[input.msg];
          if (raw.Q.x !== RFC6979.Ux || raw.Q.y !== RFC6979.Uy) fail('the RFC 6979 public key');
          if (v && (raw.k !== v.k || raw.r !== v.r || raw.s !== v.s)) fail('the RFC 6979 vector for "' + input.msg + '"');
        }
      } else {
        const T = toyCurve(C.p, C.a), G = C.G, Q = T.mul(raw.d, G), R = T.mul(raw.k, G);
        if (Q.x !== raw.Q.x || Q.y !== raw.Q.y || R.x !== raw.Rx || mod(R.x, n) !== raw.r) fail('the toy points');
        const w = inv(raw.s, n), X = T.add(T.mul(mod(e * w, n), G), T.mul(mod(raw.r * w, n), Q));
        if (w !== raw.w || X.x !== raw.X.x || mod(X.x, n) !== raw.r || raw.v !== raw.r) fail('the toy verification');
      }
      if (raw.ok !== true || mod(raw.X.x, n) !== raw.v) fail('the verification');
    },
  },
  {
    topic: 'p11-ed25519', allow: ['32', '64', '8', '0', '31', '255', '01'],
    random: (rnd) => ({ seed: crypto.randomBytes(32).toString('hex'), msg: crypto.randomBytes(Math.floor(rnd() * 40)).toString('hex'), flip: Math.floor(rnd() * 8) }),
    count: 8,
    check({ input, r, fail }) {
      const raw = RAW(r), K = edKey(input.seed), M = Buffer.from(input.msg, 'hex'), sig = crypto.sign(null, M, K.priv).toString('hex');
      if (raw.pub !== K.raw) fail('the public key against node:crypto');
      if (raw.sig !== sig) fail('the signature against node:crypto');
      if (RFC8032[input.seed] && (raw.sig !== RFC8032[input.seed])) fail('the RFC 8032 vector');
      const h = crypto.createHash('sha512').update(Buffer.from(input.seed, 'hex')).digest();
      if (raw.lo !== h.subarray(0, 32).toString('hex') || raw.hi !== h.subarray(32).toString('hex')) fail('the halves of h');
      const c = Buffer.from(h.subarray(0, 32)); c[0] &= 248; c[31] &= 127; c[31] |= 64;
      if (raw.a !== le(c) || F(r, 'clamp').a !== le(c)) fail('the clamped scalar');
      const rN = le(crypto.createHash('sha512').update(Buffer.concat([h.subarray(32), M])).digest()) % L25519;
      if (raw.r !== rN) fail('the nonce r');
      const Rb = Buffer.from(sig.slice(0, 64), 'hex'), kN = le(crypto.createHash('sha512').update(Buffer.concat([Rb, Buffer.from(K.raw, 'hex'), M])).digest()) % L25519;
      if (raw.k !== kN || raw.S !== le(Buffer.from(sig.slice(64), 'hex')) || raw.S !== mod(rN + kN * raw.a, L25519)) fail('k or S');
      if (raw.B8S !== raw.rhs || raw.ok !== true) fail('the cofactor check');
      const M2 = Buffer.from(raw.M2, 'hex');
      if (raw.bad !== crypto.verify(null, M2, K.pub, Buffer.from(sig, 'hex')) || raw.kBad !== le(crypto.createHash('sha512').update(Buffer.concat([Rb, Buffer.from(K.raw, 'hex'), M2])).digest()) % L25519) fail('the altered message');
    },
  },
  {
    topic: 'p11-nonce', allow: ['1', '2', '64'],
    random: (rnd) => ({ curve: rnd() < 0.5 ? 'P-256' : 'secp256k1', m1: textIn(rnd), m2: textIn(rnd) + '.', bias: ['4', '8', '16'][Math.floor(rnd() * 3)], seed: 1 + Math.floor(rnd() * 9999) }),
    count: 6,
    check({ S, input, r, fail }) {
      const raw = RAW(r), C = input.curve === 'secp256k1' ? S.ECC.secp256k1 : S.ECC.P256, n = C.n, bias = Number(input.bias);
      const kx = (v) => hs(v.toString(16).padStart(64, '0'), 6);
      for (const row of raw.rows) if (!ecOk(input.curve, raw.Q, Buffer.from(row.m), row.r, row.s) || !row.ok) fail('node:crypto refuses a signature of row ' + row.grp);
      const g = (grp) => raw.rows.filter((x) => x.grp === grp);
      const [s1, s2] = g('stuck');
      if (s1.k !== s2.k || s1.r !== s2.r || F(r, 'stuck').same !== true || F(r, 'stuck').r !== kx(s1.r)) fail('the stuck generator');
      for (const b of g('biased')) if (b.k >= n >> BigInt(bias)) fail('a biased nonce is not short');
      const bz = F(r, 'biased');
      if (bz.z1 !== 256 - g('biased')[0].k.toString(2).length || bz.z1 < bias || bz.z2 < bias) fail('the leading zeros');
      for (const x of g('rfc')) if (x.k !== rfc6979(n, raw.d, crypto.createHash('sha256').update(x.m).digest()).k) fail('an RFC 6979 nonce against node\'s HMAC');
      const rf = g('rfc');
      if (rf[0].k !== rf[1].k || rf[0].s !== rf[1].s || rf[2].k === rf[0].k || F(r, 'rfc').same !== true) fail('the determinism');
      const gd = g('good');
      if (gd[0].k === gd[1].k || F(r, 'good').k1 !== kx(gd[0].k)) fail('the good generator');
      const K = edKey(raw.seedE);
      for (const e of raw.ed) if (crypto.sign(null, Buffer.from(e.m), K.priv).toString('hex') !== e.sig) fail('an Ed25519 signature against node:crypto');
    },
  },
  {
    topic: 'p11-compare', allow: ['256', '2', '65537', '1', '16', '17', '14'],
    random: (rnd) => ({ goal: ['sig', 'pub', 'verify', 'sign', 'level'][Math.floor(rnd() * 5)], seed: 1 + Math.floor(rnd() * 999) }),
    count: 3,
    check({ S, r, fail }) {
      const raw = RAW(r), rows = raw.rows, R = (name) => rows.find((x) => x.name.startsWith(name));
      const bits = (v) => v.toString(2).length, pop = (v) => [...v.toString(2)].filter((c) => c === '1').length, lr = (v) => bits(v) - 1 + pop(v) - 1;
      for (const [name, id] of [['RSA-2048', 'rsa2048'], ['RSA-3072', 'rsa3072']]) {
        const key = S.PK.rsaKey(id), K = rsaKeys(key), row = R(name);
        const sig = crypto.sign('sha256', Buffer.from(raw.msg), { key: K.priv, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
        if (row.pub !== Buffer.from(K.pub.export({ format: 'jwk' }).n, 'base64url').length) fail(name + ': the public key size');
        if (row.sig !== sig.length) fail(name + ': the signature size against node:crypto');
        const half = bits(key.p), unit = (b) => (b / 256) ** 2;
        if (row.verify !== Math.round(lr(key.e) * unit(bits(key.n))) || row.sign !== Math.round((lr(key.dp) + lr(key.dq)) * unit(half))) fail(name + ': the work');
        if (row.level !== { 2048: 112, 3072: 128 }[bits(key.n)]) fail(name + ': the level');
      }
      const D = S.PK.dsaReal(), d = raw.dsa, dsa = R('DSA'), sch = R('Schnorr');
      if (!dsaOk(D, d.y, raw.msg, d.r, d.s)) fail('node:crypto refuses the DSA signature');
      if (dsa.sig !== 56 || dsa.pub !== 256 || dsa.level !== 112 || dsa.sign !== lr(d.k) * 64 || dsa.verify !== (lr(d.u1) + lr(d.u2)) * 64) fail('the DSA row');
      if (sch.sig !== 56 || sch.sign !== lr(d.k2) * 64 || sch.verify !== (lr(d.sch.s) + lr(mod(-d.sch.e, D.q))) * 64) fail('the Schnorr row');
      const C = S.ECC.P256, cnt = { M: 0, S: 0, I: 0 }; C.jdbl(C.toJ(C.G), cnt); const dbl = cnt.M + cnt.S; cnt.M = 0; cnt.S = 0; C.jaddMixed(C.toJ(C.mul(3n, C.G)), C.G, cnt); const addc = cnt.M + cnt.S;
      const ecw = (k) => (bits(k) - 1) * dbl + (pop(k) - 1) * addc, ec = R('ECDSA'), e = raw.ecdsa;
      if (!ecOk('P-256', e.Q, Buffer.from(raw.msg), e.r, e.s)) fail('node:crypto refuses the ECDSA signature');
      const ecdh = crypto.createECDH('prime256v1'); ecdh.setPrivateKey(hb(e.d, 32));
      if (ec.pub !== ecdh.getPublicKey(null, 'compressed').length || ec.sig !== 64 || ec.level !== 128 || ec.sign !== ecw(e.k) || ec.verify !== ecw(e.u1) + ecw(e.u2)) fail('the ECDSA row');
      const ed = R('Ed25519'), K = edKey(raw.ed.seed), sig = crypto.sign(null, Buffer.from(raw.msg), K.priv);
      if (sig.toString('hex') !== raw.ed.sig || ed.sig !== sig.length || ed.pub !== Buffer.from(K.raw, 'hex').length || ed.level !== 128) fail('the Ed25519 row against node:crypto');
      const edw = (k) => 8 * bits(k) + 9 * pop(k);
      if (ed.sign !== edw(raw.ed.r) || ed.verify !== edw(raw.ed.S) + edw(raw.ed.k)) fail('the Ed25519 work');
      for (const key of ['sig', 'pub', 'verify', 'sign']) { const m = Math.min(...rows.map((x) => x[key])); if (raw.best[key].join() !== rows.filter((x) => x[key] === m).map((x) => x.name).join()) fail('the best ' + key); }
    },
  },
];
