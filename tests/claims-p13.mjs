// Part 13, MACs, key establishment and protocols: every topic run with its presets and random inputs; every number
// and hex string a frame's narration quotes is one of the frame's facts, and the facts are worked out again here:
// node:crypto for HMAC, AES (CBC-MAC and CMAC built here from AES-ECB), AES-GCM, ChaCha20-Poly1305, HKDF and X25519,
// Poly1305 written out again with BigInt, the published vectors of RFC 4231, 4493, 5869, 8439 and 8448, and for the
// protocols what each party may and may not know. Prints "claims-p13 N passed, M failed".
// Usage: node tests/claims-p13.mjs [topic id prefix ...]
import { createHash, createHmac, createCipheriv, hkdfSync, createPrivateKey, createPublicKey, diffieHellman } from 'node:crypto';
import { runClaims, utf8, hex, fromHex, S } from './claims-p12-lib.mjs';

const pick = (rnd, xs) => xs[Math.floor(rnd() * xs.length)];
const words = ['tide', 'lantern', 'ash', 'wren', 'harbour', 'ledger', 'gate', 'salt', 'north', 'sixty', 'quiet', 'river'];
const phrase = (rnd, n) => Array.from({ length: n }, () => pick(rnd, words)).join(' ');
const hexr = (rnd, n) => Array.from({ length: n }, () => Math.floor(rnd() * 256).toString(16).padStart(2, '0')).join('');
const keyOf = (v) => (/^[0-9a-fA-F]{32}$/.test(v) ? fromHex(v) : utf8(v));
const ecb = (key, b) => { const c = createCipheriv('aes-128-ecb', key, null); c.setAutoPadding(false); return new Uint8Array(c.update(b)); };
const xor = (a, b) => a.map((v, i) => v ^ b[i]);
const cbcmac = (key, m) => { let c = new Uint8Array(16); for (let i = 0; i < m.length; i += 16) c = ecb(key, xor(m.subarray(i, i + 16), c)); return c; };
const dbl = (b) => { const o = new Uint8Array(16); for (let i = 0; i < 16; i++) o[i] = ((b[i] << 1) | (i < 15 ? b[i + 1] >> 7 : 0)) & 255; if (b[0] & 0x80) o[15] ^= 0x87; return o; };
const cmac = (key, m) => {
  const L = ecb(key, new Uint8Array(16)), K1 = dbl(L), K2 = dbl(K1), n = Math.max(1, Math.ceil(m.length / 16)), full = m.length && m.length % 16 === 0;
  const last = new Uint8Array(16); last.set(m.subarray(16 * (n - 1))); if (!full) last[m.length - 16 * (n - 1)] = 0x80;
  const M = new Uint8Array(16 * n); M.set(m.subarray(0, 16 * (n - 1))); M.set(xor(last, full ? K1 : K2), 16 * (n - 1));
  return { tag: cbcmac(key, M), L, K1, K2 };
};
const poly = (key, m) => {
  const le = (b) => b.reduceRight((v, x) => (v << 8n) | BigInt(x), 0n), P = (1n << 130n) - 5n;
  const r = le(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn, s = le(key.subarray(16));
  let acc = 0n; for (let i = 0; i < m.length; i += 16) { const c = m.subarray(i, i + 16); acc = ((acc + le(c) + (1n << BigInt(8 * c.length))) * r) % P; }
  let t = (acc + s) & ((1n << 128n) - 1n); const o = new Uint8Array(16); for (let i = 0; i < 16; i++) { o[i] = Number(t & 255n); t >>= 8n; } return { tag: o, r, s };
};
const x25519 = (priv, pub) => {
  const b64 = (b) => Buffer.from(b).toString('base64url');
  const k = createPrivateKey({ key: { kty: 'OKP', crv: 'X25519', d: b64(priv), x: b64(pub) }, format: 'jwk' });
  return new Uint8Array(diffieHellman({ privateKey: k, publicKey: createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b64(pub) }, format: 'jwk' }) }));
};
const lastFacts = (r) => r.frames[r.frames.length - 1].facts;
const knowsAt = (r, party, atom) => r.frames.some((f) => f.meta.step && (f.meta.step.knows[party] || []).includes(atom));

function dhCheck({ tp, input, r, fail }) {
      const sc = input.scenario, x = lastFacts(r), v = x.resValues;
      if (sc === 'dh') {
        if (!x.keysMatch || knowsAt(r, 'E', 'g^ab')) fail('the plain exchange');
        if (input.group === 'toy64') { const p = 0xfffffffffffffa43n, pw = (b, e) => { let res = 1n; b %= p; while (e) { if (e & 1n) res = (res * b) % p; b = (b * b) % p; e >>= 1n; } return res; }; if (pw(4n, BigInt(v.a)).toString() !== v.A || pw(BigInt(v.B), BigInt(v.a)).toString(16).padStart(16, '0') !== v.kA) fail('the toy group arithmetic'); }
        else if (hex(x25519(fromHex(v.a), fromHex(v.B))) !== v.kA || hex(x25519(fromHex(v.b), fromHex(v.A))) !== v.kB) fail('X25519 against node');
      }
      if (sc === 'mitm' && !(x.attack && x.attack.success && knowsAt(r, 'M', 'g^am′') && knowsAt(r, 'M', 'g^bm'))) fail('Mallory should hold both keys and change the message');
      if (sc === 'auth' && (knowsAt(r, 'E', 'g^ab') || r.frames.some((f) => f.meta.step.type === 'check' && !f.meta.step.ok))) fail('the signed exchange');
      if (sc === 'auth-mitm' && (!x.attack || x.attack.success)) fail('Mallory should be caught');
    }

const mods = [
  {
    topic: 'p13-macgame', allow: ['64'],
    random: (rnd) => ({ mac: pick(rnd, ['hmac', 'trunc', 'keyless', 'prefix', 'leaky']), key: phrase(rnd, 2) }),
    check({ input, r, fail }) {
      const key = utf8(input.key), target = 'amount=9000&to=mallory', x = lastFacts(r), hm = (m) => createHmac('sha256', key).update(m).digest();
      r.frames.filter((f) => f.meta.stage === 'tag').forEach((f, k) => {
        const m = ['amount=20&to=wren', 'amount=35&to=ash', 'amount=50&to=wren'][k];
        const want = input.mac === 'keyless' ? createHash('sha256').update(m).digest() : input.mac === 'prefix' ? createHash('sha256').update(Buffer.concat([key, utf8(m)])).digest() : input.mac === 'trunc' ? hm(m).subarray(0, 1) : hm(m);
        if (f.facts.tag !== hex(want)) fail('tag ' + (k + 1));
      });
      if (input.mac === 'hmac' && x.win) fail('HMAC should not be forged');
      if (input.mac === 'trunc' && (x.win.tag !== hex(hm(target).subarray(0, 1)) || x.queries !== hm(target)[0] + 1)) fail('the 8-bit forgery');
      if (input.mac === 'keyless' && x.win.tag !== hex(createHash('sha256').update(target).digest())) fail('the keyless forgery');
      if (input.mac === 'prefix') { const forged = Buffer.from(x.win.m.replace(/\\x([0-9a-f]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16))), 'latin1'); if (x.win.tag !== hex(createHash('sha256').update(Buffer.concat([key, forged])).digest())) fail('the length-extension outcome'); }
      if (input.mac === 'leaky' && x.win.tag !== hex(hm(target).subarray(0, 4))) fail('the timing attack');
    },
  },
  {
    topic: 'p13-hmac', allow: ['36'],
    random: (rnd) => ({ key: phrase(rnd, 1 + Math.floor(rnd() * 20)).slice(0, 200), keyHex: '', msg: phrase(rnd, Math.floor(rnd() * 8)), hash: pick(rnd, ['sha256', 'sha1', 'md5', 'sha512', 'sha3-256']) }),
    check({ input, r, fail }) {
      const key = input.keyHex ? fromHex(input.key) : utf8(input.key), m = utf8(input.msg);
      if (r.frames.find((f) => f.meta.stage === 'outer').facts.tag !== createHmac(input.hash, key).update(m).digest('hex')) fail('the tag against node');
      const B = { sha256: 64, sha1: 64, md5: 64, sha512: 128, 'sha3-256': 136 }[input.hash], kp = new Uint8Array(B);
      kp.set(key.length > B ? createHash(input.hash).update(key).digest() : key);
      if (r.frames.find((f) => f.meta.stage === 'inner').facts.inner !== createHash(input.hash).update(Buffer.concat([kp.map((v) => v ^ 0x36), m])).digest('hex')) fail('the inner hash');
      if (input.key === 'Jefe' && input.hash === 'sha256' && input.msg === 'what do ya want for nothing?' && lastFacts(r).outLen !== 32) fail('RFC 4231');
      if (input.key === 'Jefe' && input.msg === 'what do ya want for nothing?' && createHmac('sha256', key).update(m).digest('hex') !== '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843') fail('RFC 4231 test case 2');
    },
  },
  {
    topic: 'p13-cbcmac',
    random: (rnd) => ({ key: hexr(rnd, 16), m1: phrase(rnd, 2).slice(0, 32), m2: phrase(rnd, 4).slice(0, 32), mac: pick(rnd, ['cbc', 'cmac']) }),
    check({ input, r, fail }) {
      const key = keyOf(input.key), pad = (s) => { const b = utf8(s), n = Math.max(16, Math.ceil(b.length / 16) * 16), o = new Uint8Array(n).fill(0x20); o.set(b); return o; };
      const m1 = pad(input.m1), m2 = pad(input.m2), mac = (m) => (input.mac === 'cmac' ? cmac(key, m).tag : cbcmac(key, m));
      const t1 = mac(m1), t2 = mac(m2), forged = new Uint8Array([...m1, ...xor(m2.subarray(0, 16), t1), ...m2.subarray(16)]), tf = mac(forged);
      // the outcome the topic states, checked here (the construction is never shown in the topic)
      const st = (k) => (r.frames.find((f) => f.meta.stage === k) || {}).facts || {}, x = st('outcome');
      if (st('m1').t1 !== hex(t1) || st('m2').t2 !== hex(t2) || x.t2 !== hex(t2) || x.tf !== hex(tf)) fail('the tags against AES from node');
      if (x.nb !== forged.length / 16) fail('the length of the longer message');
      if (x.ok !== (hex(tf) === hex(t2)) || x.ok !== (input.mac === 'cbc')) fail('the outcome should be a valid tag on CBC-MAC and a rejection on CMAC');
    },
  },
  {
    topic: 'p13-cmac', allow: ['00', '128', '80', '87'],
    random: (rnd) => ({ key: hexr(rnd, 16), hex: 'hex', msg: hexr(rnd, Math.floor(rnd() * 65)) }),
    check({ input, r, fail }) {
      const key = keyOf(input.key), m = input.hex ? fromHex(input.msg) : utf8(input.msg), c = cmac(key, m), x = lastFacts(r);
      if (x.tag !== hex(c.tag)) fail('the tag');
      if (r.frames[0].facts.L !== hex(c.L) || r.frames[1].facts.K1 !== hex(c.K1) || r.frames[2].facts.K2 !== hex(c.K2)) fail('the subkeys');
      const rfc = { '': 'bb1d6929e95937287fa37d129b756746', '6bc1bee22e409f96e93d7e117393172a': '070a16b46b4d4144f79bdd9dd04a287c', '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411': 'dfa66747de9ae63030ca32611497c827' };
      if (input.key === '2b7e151628aed2a6abf7158809cf4f3c' && input.hex && rfc[input.msg] && rfc[input.msg] !== x.tag) fail('RFC 4493');
    },
  },
  {
    topic: 'p13-gmac', allow: ['128'],
    random: (rnd) => ({ key: hexr(rnd, 16), iv: hexr(rnd, 12), hex: '', aad: phrase(rnd, Math.floor(rnd() * 8)).slice(0, 80) }),
    check({ input, r, fail }) {
      const key = keyOf(input.key), aad = input.hex ? fromHex(input.aad) : utf8(input.aad);
      const c = createCipheriv('aes-128-gcm', key, fromHex(input.iv)); c.setAAD(aad); c.update(new Uint8Array(0)); c.final();
      const x = r.frames.find((f) => f.meta.stage === 'tag').facts;
      if (x.tag !== c.getAuthTag().toString('hex')) fail('the GMAC tag against node');
      if (r.frames[0].facts.Hh !== hex(ecb(key, new Uint8Array(16)))) fail('H');
    },
  },
  {
    topic: 'p13-poly1305', allow: ['128', '130', '16', '32', '5'],
    random: (rnd) => ({ key: hexr(rnd, 32), hex: '', msg: phrase(rnd, Math.floor(rnd() * 20)).slice(0, 144) }),
    check({ input, r, fail }) {
      const key = fromHex(input.key), m = input.hex ? fromHex(input.msg) : utf8(input.msg), p = poly(key, m), x = lastFacts(r);
      if (x.tag !== hex(p.tag)) fail('the tag');
      if (r.frames[1].facts.r !== p.r.toString(16) || r.frames[2].facts.s !== p.s.toString(16)) fail('r or s');
      if (input.msg === 'Cryptographic Forum Research Group' && input.key.startsWith('85d6be78') && x.tag !== 'a8061dc1305136c6c22b8baf0c0127a9') fail('RFC 8439 2.5.2');
    },
  },
  {
    topic: 'p13-aead', allow: ['16', '8'],
    random: (rnd) => ({ key: hexr(rnd, 32), nonce: hexr(rnd, 12), pt: phrase(rnd, Math.floor(rnd() * 18)).slice(0, 120), aadHex: '', aad: phrase(rnd, 2).slice(0, 32), tamper: pick(rnd, ['none', 'ct', 'aad', 'tag', 'nonce']) }),
    check({ input, r, fail }) {
      const key = /^[0-9a-fA-F]{64}$/.test(input.key) ? fromHex(input.key) : utf8(input.key), nonce = fromHex(input.nonce), aad = input.aadHex ? fromHex(input.aad) : utf8(input.aad);
      const c = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 }); c.setAAD(aad, { plaintextLength: utf8(input.pt).length });
      const ct = Buffer.concat([c.update(utf8(input.pt)), c.final()]), tag = c.getAuthTag();
      if (r.frames.find((f) => f.meta.stage === 'enc').facts.ct !== ct.toString('hex')) fail('the ciphertext against node');
      if (r.frames.find((f) => f.meta.stage === 'sealed').facts.tag !== tag.toString('hex')) fail('the tag against node');
      if (lastFacts(r).ok !== (input.tamper === 'none')) fail('opening should succeed only when nothing was changed');
      if (input.nonce === '070000004041424344454647' && tag.toString('hex') !== '1ae10b594f09e26a7e902ecbd0600691') fail('RFC 8439 2.8.2');
    },
  },
  {
    topic: 'p13-hkdf', allow: [],
    random: (rnd) => ({ hex: '', ikm: phrase(rnd, 3), salt: phrase(rnd, Math.floor(rnd() * 3)), info: phrase(rnd, 2), L: 1 + Math.floor(rnd() * 160), hash: pick(rnd, ['sha256', 'sha512', 'sha1']) }),
    check({ input, r, fail }) {
      const v = (s) => (input.hex ? fromHex(s) : utf8(s));
      const okm = Buffer.from(hkdfSync(input.hash, v(input.ikm), v(input.salt), v(input.info), +input.L)).toString('hex');
      if (lastFacts(r).okm !== okm) fail('the OKM against node');
      if (input.hex && input.ikm === '0b'.repeat(22) && okm !== '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865') fail('RFC 5869 test case 1');
    },
  },
  {
    topic: 'p13-ns',
    random: (rnd) => ({ scenario: pick(rnd, ['ns', 'replay', 'fixed', 'fixed-replay']), seed: 1 + Math.floor(rnd() * 900) }),
    check({ input, r, fail }) {
      const sc = input.scenario, checks = r.frames.filter((f) => f.meta.step.type === 'check').map((f) => f.meta.step);
      if (knowsAt(r, 'A', 'Kbs') || knowsAt(r, 'B', 'Kas')) fail('a party learned another\'s long-term key');
      if (sc === 'ns' && (knowsAt(r, 'E', 'Kab') || !checks.every((c) => c.ok))) fail('the plain run');
      if (sc === 'replay' && !(knowsAt(r, 'E', 'K′ab') && checks[checks.length - 1].ok && checks[checks.length - 1].party === 'B')) fail('the replay should fool Bob with a key Eve holds');
      if (sc === 'fixed-replay' && checks[checks.length - 1].ok) fail('the repaired protocol should reject the replay');
      // Alice never opens a ticket sealed under Kbs
      if (r.frames.some((f) => f.meta.step.type === 'message' && f.meta.step.to === 'A' && /Jb\}Kbs/.test(f.meta.step.content) && (f.meta.step.knows.A || []).includes('Jb') && sc !== 'fixed')) fail('Alice read a sealed ticket');
    },
  },
  {
    topic: 'p13-kerberos',
    random: (rnd) => ({ seed: 1 + Math.floor(rnd() * 900) }),
    check({ r, fail }) {
      if (knowsAt(r, 'V', 'password') || knowsAt(r, 'TGS', 'password') || knowsAt(r, 'AS', 'password')) fail('the password left the client');
      if (knowsAt(r, 'C', 'Ktgs') || knowsAt(r, 'C', 'Kv')) fail('the client learned a server key');
      if (!knowsAt(r, 'V', 'Kc,v') || !knowsAt(r, 'C', 'Kc,v')) fail('the service key was not shared');
    },
  },
  { topic: 'p13-dh', random: (rnd) => ({ scenario: pick(rnd, ['dh', 'mitm']), group: pick(rnd, ['toy64', 'x25519']), seed: 1 + Math.floor(rnd() * 900) }), check: dhCheck },
  { topic: 'p13-authdh', random: (rnd) => ({ scenario: pick(rnd, ['auth', 'auth-mitm']), group: pick(rnd, ['toy64', 'x25519']), seed: 1 + Math.floor(rnd() * 20) }), count: 3, check: dhCheck },
  {
    topic: 'p13-certs',
    check({ input, r, fail }) {
      const want = { valid: null, fake: 'signature', 'self-made-root': 'anchor', expired: 'validity', 'revoked-crl': 'crl', 'revoked-ocsp': 'ocsp', 'wrong-host': 'name', 'leaf-as-ca': 'ca' }[input.scenario];
      const failed = r.frames.filter((f) => f.meta.stage === 'fail').map((f) => f.facts.what);
      if (want === null ? failed.length || !lastFacts(r).ok : failed.length !== 1 || failed[0] !== want) fail('the chain should ' + (want ? 'fail at ' + want + ', not ' + failed : 'pass'));
    },
  },
  {
    topic: 'p13-tls',
    check({ input, r, fail }) {
      const x = lastFacts(r), failedCheck = r.frames.find((f) => f.meta.step.type === 'check' && !f.meta.step.ok);
      if (x.ok !== (input.tamper === 'none')) fail('the handshake should succeed only untouched');
      const want = { cert: /certificate rejected/, finished: /Finished does not match/, record: /tag fails/ }[input.tamper];
      if (want && (!failedCheck || !want.test(failedCheck.meta.step.say))) fail('the wrong check failed');
      if (knowsAt(r, 'E', 'handshake keys') || knowsAt(r, 'E', 'application keys')) fail('the eavesdropper learned a key');
    },
  },
  {
    topic: 'p13-tls-keys',
    check({ input, r, fail }) {
      // HKDF-Expand-Label and the schedule, written out with node's HMAC
      const hm = (k, m) => createHmac('sha256', k).update(m).digest();
      const expand = (prk, info, L) => { let T = Buffer.alloc(0), out = Buffer.alloc(0); for (let i = 1; out.length < L; i++) { T = hm(prk, Buffer.concat([T, info, Buffer.from([i])])); out = Buffer.concat([out, T]); } return out.subarray(0, L); };
      const label = (s, l, ctx, L) => { const lb = Buffer.from('tls13 ' + l); return expand(s, Buffer.concat([Buffer.from([L >> 8, L & 255, lb.length]), lb, Buffer.from([ctx.length]), ctx]), L); };
      const at = (id) => r.frames.find((f) => f.meta.stage === id).facts;
      const early = hm(Buffer.alloc(32), Buffer.alloc(32)), empty = createHash('sha256').digest();
      if (at('early').early !== early.toString('hex')) fail('the early secret');
      const d1 = label(early, 'derived', empty, 32);
      if (at('d1').d !== d1.toString('hex')) fail('derived 1');
      const shared = Buffer.from(at('hs').shared, 'hex'), hs = hm(d1, shared);
      if (at('hs').hs !== hs.toString('hex')) fail('the handshake secret');
      const ms = hm(label(hs, 'derived', empty, 32), Buffer.alloc(32));
      if (at('ms').ms !== ms.toString('hex')) fail('the master secret');
      if (input.source === 'rfc' && (hs.toString('hex') !== '1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac' || ms.toString('hex') !== '18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919')) fail('RFC 8448 secrets');
    },
  },
];
runClaims('claims-p13', 'p13', mods, process.argv.slice(2));
