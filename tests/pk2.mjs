// Public-key engines against node:crypto, and every attack recovering a planted secret over many seeds.
//   node tests/pk2.mjs
import { generateKeyPairSync, publicEncrypt, privateDecrypt, sign, verify, constants, createDiffieHellman, randomBytes } from 'node:crypto';
import { load, harness, rng } from './load.mjs';
const S = load(['core']), t = harness('pk2'), N = S.NT, R = S.RSA, D = S.DLP, SIG = S.SIG;
const b64 = (s) => BigInt('0x' + Buffer.from(s, 'base64url').toString('hex'));
const toBuf = (v, n) => Buffer.from(v.toString(16).padStart(2 * n, '0'), 'hex');
const rnd = rng(0x51fe3a7);
const randBig = (bits) => { let v = 0n; for (let i = 0; i < bits; i += 30) v = (v << 30n) | BigInt((rnd() * (1 << 30)) >>> 0); return v & ((1n << BigInt(bits)) - 1n); };

// a seeded source so the whole run is reproducible; labs reseed it themselves
N.setRandom(N.seededRandom(20260218));

// ============================================================ RSA against node
{
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = privateKey.export({ format: 'jwk' });
  const n = b64(jwk.n), e = b64(jwk.e), d = b64(jwk.d), p = b64(jwk.p), q = b64(jwk.q);
  const key = { n, e, d, p, q, dp: d % (p - 1n), dq: d % (q - 1n), qinv: N.inv(q, p) }, pub = { n, e };
  const k = N.byteLength(n);
  t.ok(p * q === n, "node's p·q equals n"); t.ok((e * d) % N.lcm(p - 1n, q - 1n) === 1n, 'e·d ≡ 1 mod λ(n)');
  // raw (no padding) both directions, many messages
  for (let i = 0; i < 40; i++) {
    const m = N.fromBytes(randomBytes(200));
    const c = N.fromBytes(publicEncrypt({ key: publicKey, padding: constants.RSA_NO_PADDING }, toBuf(m, k)));
    t.ok(R.encrypt(m, pub).value === c, 'our m^e equals node RSA_NO_PADDING ' + i);
    t.ok(R.decrypt(c, key).value === m, 'our c^d returns m ' + i);
    t.ok(R.decryptCRT(c, key).value === m, 'our CRT decryption returns m ' + i);
    t.ok(N.fromBytes(privateDecrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, toBuf(c, k))) === m, 'node agrees on c^d ' + i);
  }
  // OAEP(sha256): our encode -> node decrypts; node encrypts -> we decode
  for (let i = 0; i < 20; i++) {
    const msg = randomBytes(1 + ((rnd() * 60) | 0));
    const oc = R.oaepEncrypt(pub, msg);
    const back = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(oc.cBytes));
    t.ok(Buffer.from(back).equals(Buffer.from(msg)), 'node decrypts our OAEP ' + i);
    const nc = publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(msg));
    const ours = R.oaepDecrypt(key, Array.from(nc));
    t.ok(Buffer.from(ours.msg).equals(Buffer.from(msg)), 'we decrypt node OAEP ' + i);
  }
  // PSS(sha256, saltLength 32) both directions
  const pssOpt = { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 };
  for (let i = 0; i < 20; i++) {
    const msg = randomBytes(10 + ((rnd() * 50) | 0));
    const ours = R.pssSign(key, msg, { saltLength: 32 });
    t.ok(verify('sha256', Buffer.from(msg), { key: publicKey, ...pssOpt }, Buffer.from(ours.sBytes)), 'node verifies our PSS ' + i);
    const ns = sign('sha256', Buffer.from(msg), { key: privateKey, ...pssOpt });
    t.ok(R.pssVerify(pub, msg, Array.from(ns), { saltLength: 32 }).ok, 'we verify node PSS ' + i);
    // a tampered message must fail both ways
    const bad = Buffer.from(msg); bad[0] ^= 1;
    t.ok(!R.pssVerify(pub, bad, Array.from(ns), { saltLength: 32 }).ok, 'we reject node PSS on a changed message ' + i);
  }
}

// our own keygen round trips (thousands), textbook and CRT, and the three exponentiations agree
{
  const key = R.keygen(1024);
  let ok = 0;
  for (let i = 0; i < 2000; i++) {
    const m = N.randBelow(key.n);
    const c = R.encrypt(m, R.public(key)).value;
    if (R.decrypt(c, key).value === m && R.decryptCRT(c, key).value === m) ok++;
  }
  t.ok(ok === 2000, '2000 RSA round trips, textbook and CRT (' + ok + ')');
  for (let i = 0; i < 200; i++) {
    const m = N.randBelow(key.n), e = N.randBelow(key.n) | 1n;
    const ref = N.pow(m, e, key.n);
    t.ok(R.powLR(m, e, key.n).value === ref && R.powRL(m, e, key.n).value === ref && R.ladder(m, e, key.n).value === ref, 'LR, RL and the ladder agree ' + i);
  }
  // operation counts: one multiply per 1-bit after the leading one; the ladder is regular
  const e = 0b1011010011100101n, lr = R.powLR(3n, e, key.n);
  t.eq(lr.squarings, N.bitLength(e) - 1, 'LR squarings = bits − 1');
  t.eq(lr.multiplications, [...e.toString(2)].filter((b) => b === '1').length - 1, 'LR multiplications = (ones − 1)');
  const lad = R.ladder(3n, e, key.n);
  t.eq(lad.squarings, lad.multiplications, 'the ladder does one of each per bit');
}

// ============================================================ RSA attacks, 20 seeds each
const attackCounts = {};
const runAttack = (name, n, fn) => { let ok = 0; for (let s = 1; s <= n; s++) if (fn(s)) ok++; attackCounts[name] = ok + '/' + n; t.ok(ok === n, name + ' recovers the secret over ' + n + ' seeds (' + ok + ')'); };
runAttack('RSA small-e', 20, (s) => { const l = R.labs.smallE(s); return R.attack.smallE(l.public).m === l.secret.m; });
runAttack('RSA common modulus', 20, (s) => { const l = R.labs.commonModulus(s); return R.attack.commonModulus(l.public).m === l.secret.m; });
runAttack('RSA Hastad', 20, (s) => { const l = R.labs.hastad(s); return R.attack.hastad(l.public).m === l.secret.m; });
runAttack('RSA Wiener', 20, (s) => { const l = R.labs.wiener(s); return R.attack.wiener(l.public).d === l.secret.d; });
runAttack('RSA Fermat', 20, (s) => { const l = R.labs.fermat(s); const r = R.attack.fermat(l.public); return r.p && r.p * r.q === l.public.n && r.q > 1n; });
runAttack('RSA shared primes', 20, (s) => { const l = R.labs.sharedPrimes(s); const r = R.attack.sharedPrimes(l.public.ns); return l.secret.broken.every((b) => { const f = r.factors[b.i]; return f && (f.p === b.p || f.q === b.p); }); });
runAttack('RSA CRT fault', 20, (s) => { const l = R.labs.crtFault(s); const r = R.attack.crtFault(l.public); return r.p === l.secret.p || r.p === l.secret.q; });
runAttack('RSA timing', 20, (s) => { const l = R.labs.timing(s); return R.attack.timing(l.public).d === l.secret.d; });

// ============================================================ Diffie–Hellman against node
{
  for (let i = 0; i < 4; i++) {
    const dh = createDiffieHellman(512);
    const p = BigInt('0x' + dh.getPrime('hex')), g = BigInt('0x' + dh.getGenerator('hex')), plen = N.byteLength(p);
    const group = D.groupZp(p, { gen: g });
    const a = 1n + N.randBelow(p - 2n), b = 1n + N.randBelow(p - 2n);
    void 32; // node is Alice (private a); we are Bob (private b, public B = g^b)
    dh.setPrivateKey(toBuf(a, plen)); dh.generateKeys();
    const A = BigInt('0x' + dh.getPublicKey('hex')), Bp = N.pow(g, b, p);
    t.ok(N.pow(g, a, p) === A, 'our g^a equals node ' + i);
    const nodeShared = BigInt('0x' + dh.computeSecret(toBuf(Bp, plen)).toString('hex'));
    const ours = D.dh(group, a, b);
    t.ok(ours.shared === nodeShared && ours.A === A && ours.B === Bp, 'DH shared secret matches node ' + i);
    // a man in the middle holds a key with each side, neither equal to the true shared secret in general
    const mm = D.dhMITM(group, a, b);
    t.ok(mm.agreeA && mm.agreeB, 'the man-in-the-middle shares a key with each party ' + i);
  }
}
// Elgamal encryption round trips in a proper group
{
  const p = createDiffieHellman(512); const group = D.groupZp(BigInt('0x' + p.getPrime('hex')), { gen: BigInt('0x' + p.getGenerator('hex')) });
  const key = D.elgamalKey(group);
  let ok = 0; for (let i = 0; i < 300; i++) { const m = group.random(); const ct = D.elgamalEncrypt(key.pub, m); if (D.elgamalDecrypt(key, ct).m === m) ok++; }
  t.ok(ok === 300, 'Elgamal round trips (' + ok + '/300)');
}

// ============================================================ DLP attacks, 20 seeds each
runAttack('DLP baby-step giant-step', 20, (s) => { const l = D.labs.dlog(s); return D.attack.bsgs(l.group, l.public.h).x === l.secret.x; });
runAttack('DLP Pollard rho', 20, (s) => { const l = D.labs.dlog(s); const r = D.attack.rho(l.group, l.public.h); return r.x === l.secret.x && r.tortoise.length > 1; });
runAttack('DLP Pohlig–Hellman', 20, (s) => { const l = D.labs.smooth(s); return D.attack.pohligHellman(l.group, l.public.h, { n: l.order }).x === l.secret.x; });
runAttack('DLP index calculus', 20, (s) => { const l = D.labs.indexCalculus(s); return D.attack.indexCalculus(l.public.p, l.public.g, l.public.h).x === l.secret.x; });
runAttack('DLP small subgroup', 20, (s) => { const l = D.labs.smallSubgroup(s); return D.attack.smallSubgroup(l.public).secret === l.secret.x; });
// Pollard's rho returns its walk for drawing the shape
{ const l = D.labs.dlog(1); const r = D.attack.rho(l.group, l.public.h); t.ok(Array.isArray(r.tortoise) && Array.isArray(r.hare) && r.meeting != null, 'rho returns the walk points and the meeting'); }

// ============================================================ signatures
// our DSA and Schnorr over the toy group, thousands of round trips
{
  const params = SIG.toyParams(100003n), key = SIG.dsaKey(params), sk = SIG.schnorrKey(params);
  let d = 0, sc = 0;
  for (let i = 0; i < 1500; i++) {
    const msg = 'message ' + randBig(40).toString();
    const ds = SIG.dsaSign(key, msg); if (SIG.dsaVerify(key.pub, msg, ds).ok && !SIG.dsaVerify(key.pub, msg + 'x', ds).ok) d++;
    const ss = SIG.schnorrSign(sk, msg); if (SIG.schnorrVerify(sk.pub, msg, ss).ok && !SIG.schnorrVerify(sk.pub, msg + 'x', ss).ok) sc++;
  }
  t.ok(d === 1500, 'DSA signs and verifies, rejecting changes (' + d + '/1500)');
  t.ok(sc === 1500, 'Schnorr signs and verifies, rejecting changes (' + sc + '/1500)');
  // Elgamal signatures in Z_p*
  const dp = createDiffieHellman(512), ep = BigInt('0x' + dp.getPrime('hex')), eg = BigInt('0x' + dp.getGenerator('hex'));
  const ex = 2n + N.randBelow(ep - 3n), ey = N.pow(eg, ex, ep);
  let el = 0; for (let i = 0; i < 200; i++) { const m = 'e' + i; const s = SIG.elgamalSign(ep, eg, ex, m); if (SIG.elgamalVerify(ep, eg, ey, m, s).ok && !SIG.elgamalVerify(ep, eg, ey, m + '!', s).ok) el++; }
  t.ok(el === 200, 'Elgamal signatures verify (' + el + '/200)');
}

// our DSA over a real 2048/224 group
{
  const params = SIG.dsaParams({ L: 2048, Nbits: 224 });
  t.ok(N.bitLength(params.p) === 2048 && N.bitLength(params.q) === 224 && (params.p - 1n) % params.q === 0n && N.pow(params.g, params.q, params.p) === 1n, 'real DSA parameters are well formed');
  const key = SIG.dsaKey(params);
  let ok = 0; for (let i = 0; i < 30; i++) { const m = 'real ' + i; const s = SIG.dsaSign(key, m); if (SIG.dsaVerify(key.pub, m, s).ok) ok++; }
  t.ok(ok === 30, 'real DSA signs and verifies (' + ok + '/30)');
}

// DSA against node (if supported): extract the group, key and signature, and cross-verify both ways
{
  const ints = (der) => { const out = []; let i = 0; const walk = (buf, depth) => { let j = 0; while (j < buf.length) { const tag = buf[j++]; let len = buf[j++]; if (len & 0x80) { const k = len & 0x7f; len = 0; for (let b = 0; b < k; b++) len = (len << 8) | buf[j++]; } const body = buf.subarray(j, j + len); j += len; if (tag === 0x02) out.push(BigInt('0x' + Buffer.from(body).toString('hex') || '0')); else if (tag === 0x30 || tag === 0x04) walk(body, depth + 1); else if (tag === 0x03) walk(body.subarray(1), depth + 1); } }; walk(der, 0); return out; };
  let supported = true, pub, priv;
  try { const kp = generateKeyPairSync('dsa', { modulusLength: 2048, divisorLength: 256 }); pub = kp.publicKey; priv = kp.privateKey; } catch { supported = false; }
  if (!supported) t.ok(true, 'node DSA keygen not supported here: skipped');
  else {
    const [p, q, g, y] = ints(pub.export({ type: 'spki', format: 'der' }));
    const xs = ints(priv.export({ type: 'pkcs8', format: 'der' }));
    const x = xs[xs.length - 1];
    t.ok(N.pow(g, x, p) === y, "node's y equals g^x");
    const params = { p, q, g }, key = { params, x, y, pub: { params, y } }, pubO = { params, y };
    let a = 0, b = 0;
    for (let i = 0; i < 20; i++) {
      const msg = Buffer.from('node dsa ' + i);
      // node signs (DER r,s) -> we verify
      const ns = sign('sha256', msg, priv), [r, s] = ints(ns);
      if (SIG.dsaVerify(pubO, msg, { r, s }).ok) a++;
      // we sign -> node verifies (DER-encode r,s)
      const ours = SIG.dsaSign(key, msg);
      const derInt = (v) => { let h = v.toString(16); if (h.length % 2) h = '0' + h; let bb = Buffer.from(h, 'hex'); if (bb[0] & 0x80) bb = Buffer.concat([Buffer.from([0]), bb]); return Buffer.concat([Buffer.from([0x02, bb.length]), bb]); };
      const seq = Buffer.concat([derInt(ours.r), derInt(ours.s)]);
      const sig = Buffer.concat([Buffer.from([0x30, seq.length]), seq]);
      if (verify('sha256', msg, pub, sig)) b++;
    }
    t.ok(a === 20, 'we verify node DSA signatures (' + a + '/20)');
    t.ok(b === 20, 'node verifies our DSA signatures (' + b + '/20)');
  }
}

// nonce-reuse key recovery for DSA and Schnorr, 20 seeds each
runAttack('DSA nonce reuse', 20, (s) => { const l = SIG.labs.dsaNonceReuse(s); const r = SIG.attack.dsaNonceReuse(l.pub, l.m1, l.sig1, l.m2, l.sig2); return r.x === l.secret.x && r.k === l.secret.k; });
runAttack('Schnorr nonce reuse', 20, (s) => { const l = SIG.labs.schnorrNonceReuse(s); const r = SIG.attack.schnorrNonceReuse(l.pub, l.m1, l.sig1, l.m2, l.sig2); return r.x === l.secret.x && r.k === l.secret.k; });

t.done();
console.log('  attacks:', JSON.stringify(attackCounts));
