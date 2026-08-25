// Part 6's narration checks (set b: integrity and correct use), used by tests/claims-p06.mjs. Every block a frame
// states is worked out again with node:crypto: aes-ctr for the keystreams, aes-gcm for the ciphertexts and tags
// (and its decipher for the rejection), aes-cbc for encrypt-then-MAC, hmac for the tags, and a CMAC and S2V written
// here over aes-ecb for AES-SIV, itself checked against RFC 5297, appendix A.1, on load.
import { createCipheriv, createDecipheriv, createHmac } from 'node:crypto';
import { S, hex, same, at } from './claims-lib-p05.mjs';

const U = S.P5;
const rb = (rnd, n) => Array.from({ length: n }, () => Math.floor(rnd() * 256));
const words = ['harbour', 'lantern', 'cedar', 'kestrel', 'quay', 'moss', 'ember', 'tide', 'orchard', 'flint', 'meadow', 'copper', 'heron', 'dune', 'PAY', '100', 'gate', 'YES'];
const sentence = (rnd, max) => { let s = ''; while (true) { const w = words[Math.floor(rnd() * words.length)]; if ((s + ' ' + w).trim().length > max) break; s = (s + ' ' + w).trim(); if (rnd() < 0.15) break; } return s || 'tide'; };
const randKey = (rnd, sizes) => hex(rb(rnd, sizes[Math.floor(rnd() * sizes.length)]));
const B = (s) => Buffer.from(String(s), 'utf8');
const xor = (a, b) => Buffer.from(Array.from({ length: Math.min(a.length, b.length) }, (_, i) => a[i] ^ b[i]));
const nonceOf = (v) => { const h = String(v).replace(/\s+/g, ''); return /^[0-9a-fA-F]{24}$/.test(h) ? Buffer.from(h, 'hex') : B(v); };
const ctrBlock = (N, c) => { const b = Buffer.alloc(16); N.copy(b); b[15] = c; return b; };
const ctr = (key, iv, data) => { const c = createCipheriv('aes-' + key.length * 8 + '-ctr', Buffer.from(key), iv); return Buffer.concat([c.update(Buffer.from(data)), c.final()]); };
const gcm = (key, N, data) => { const c = createCipheriv('aes-' + key.length * 8 + '-gcm', Buffer.from(key), N); const ct = Buffer.concat([c.update(Buffer.from(data)), c.final()]); return { ct, tag: c.getAuthTag() }; };
const gcmOpens = (key, N, ct, tag) => { try { const d = createDecipheriv('aes-' + key.length * 8 + '-gcm', Buffer.from(key), N); d.setAuthTag(Buffer.from(tag)); Buffer.concat([d.update(Buffer.from(ct)), d.final()]); return true; } catch (e) { return false; } };

// ---- CMAC (SP 800-38B) and AES-SIV (RFC 5297), over node's AES-128-ECB --------------------------------------------
const ecb = (k, b) => { const c = createCipheriv('aes-128-ecb', Buffer.from(k), null); c.setAutoPadding(false); return Buffer.concat([c.update(Buffer.from(b)), c.final()]); };
const dbl = (b) => { let v = BigInt('0x' + hex(b)) << 1n; if (v >> 128n) v ^= 0x87n; v &= (1n << 128n) - 1n; return Buffer.from(v.toString(16).padStart(32, '0'), 'hex'); };
const cmac = (k, m) => {
  m = Buffer.from(m);
  const L = ecb(k, Buffer.alloc(16)), K1 = dbl(L), K2 = dbl(K1), n = Math.max(1, Math.ceil(m.length / 16)), full = m.length && m.length % 16 === 0;
  const last = Buffer.alloc(16); m.copy(last, 0, 16 * (n - 1)); if (!full) last[m.length - 16 * (n - 1)] = 0x80;
  let x = Buffer.alloc(16);
  for (let i = 0; i < n - 1; i++) x = ecb(k, xor(x, m.subarray(16 * i, 16 * i + 16)));
  return ecb(k, xor(x, xor(last, full ? K1 : K2)));
};
const s2v = (k, parts) => {
  let D = cmac(k, Buffer.alloc(16));
  for (const s of parts.slice(0, -1)) D = xor(dbl(D), cmac(k, s));
  const Sn = Buffer.from(parts[parts.length - 1]);
  if (Sn.length >= 16) return cmac(k, Buffer.concat([Sn.subarray(0, Sn.length - 16), xor(Sn.subarray(Sn.length - 16), D)]));
  const p = Buffer.alloc(16); Sn.copy(p); p[Sn.length] = 0x80;
  return cmac(k, xor(dbl(D), p));
};
const siv = (key, headers, P) => {
  const V = s2v(key.subarray(0, 16), [...headers, P]), Q = Buffer.from(V); Q[8] &= 0x7f; Q[12] &= 0x7f;
  return { V, C: ctr(key.subarray(16), Q, P) };
};
// RFC 5297, A.1 (deterministic AES-SIV): checks this file's SIV, and the topic's own
{
  const key = Buffer.from('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', 'hex'), ad = Buffer.from('101112131415161718191a1b1c1d1e1f2021222324252627', 'hex'), P = Buffer.from('112233445566778899aabbccddee', 'hex');
  const want = '85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c';
  const mine = siv(key, [ad], P), theirs = S.P6int.siv(Uint8Array.from(key), [Uint8Array.from(ad)], Uint8Array.from(P));
  if (hex(mine.V) + hex(mine.C) !== want) throw new Error('claims-p06-b: the reference AES-SIV fails RFC 5297 A.1');
  if (hex(theirs.V) + hex(theirs.C) !== want) throw new Error('claims-p06-b: the topic\'s AES-SIV fails RFC 5297 A.1');
}

export const mods = [
  {
    topic: 'integrity-malleable', allow: ['16', '128'],
    random: (rnd) => { const msg = sentence(rnd, 20); return { msg, key: randKey(rnd, [16, 24, 32]), nonce: hex(rb(rnd, 12)), byte: Math.floor(rnd() * B(msg).length), bit: String(Math.floor(rnd() * 8)) }; },
    check({ input, r, fail }) {
      const key = Buffer.from(U.key(input.key)), N = nonceOf(input.nonce), P = B(input.msg), L = P.length, i = Math.min(+input.byte, L - 1), d = 1 << +input.bit;
      const ks = ctr(key, ctrBlock(N, 2), Buffer.alloc(L)), C = ctr(key, ctrBlock(N, 2), P);
      const C2 = Buffer.from(C); C2[i] ^= d;
      const P2 = Buffer.from(P); P2[i] ^= d;
      const g = gcm(key, N, P), g2 = gcm(key, N, P2);
      for (const f of at(r, 'start')) if (f.facts.L !== L || !same(f.facts.N, N)) fail('the length or the nonce');
      for (const f of at(r, 'enc')) { if (!same(f.facts.ks, ks)) fail('the CTR keystream against node:crypto'); if (!same(f.facts.C, C)) fail('the CTR ciphertext against node:crypto'); }
      for (const f of at(r, 'flip')) if (f.facts.at !== i || f.facts.c !== C[i] || f.facts.c2 !== C2[i] || f.facts.d !== d) fail('the flipped byte');
      for (const f of at(r, 'recv')) { if (f.facts.p !== P[i] || f.facts.p2 !== P2[i]) fail('the changed plaintext byte'); if (!same(ctr(key, ctrBlock(N, 2), C2), P2)) fail('CTR decryption of C′ is not P ⊕ Δ'); }
      for (const f of at(r, 'gcm')) { if (!same(f.facts.ct, g.ct) || !same(f.facts.tag, g.tag)) fail('the GCM ciphertext or tag against node:crypto'); if (!f.meta.same || !same(g.ct, C)) fail('the GCM ciphertext should equal the CTR one'); }
      for (const f of at(r, 'gcm-flip')) {
        // the receiver's tag over C′ is the tag GCM gives P ⊕ Δ, since C′ is its ciphertext
        if (!same(g2.ct, C2)) fail('C′ is not the GCM ciphertext of P ⊕ Δ');
        if (!same(f.facts.t2, g2.tag)) fail('the recomputed tag against node:crypto');
        if (f.facts.nDiff !== Array.from(g2.tag).filter((v, k) => v !== g.tag[k]).length) fail('the count of differing tag bytes');
        if (f.meta.ok || gcmOpens(key, N, C2, g.tag)) fail('a tampered GCM message accepted');
        if (!gcmOpens(key, N, C, g.tag)) fail('the untouched GCM message refused');
      }
    },
  },
  {
    topic: 'integrity-nonce', allow: ['3', '96', '00000001', '97', '32', '8452'],
    random: (rnd) => ({ m1: sentence(rnd, 20), m2: rnd() < 0.15 ? 'tide' : sentence(rnd, 20), key: randKey(rnd, [32]), nonce: hex(rb(rnd, 12)), q: 16 + Math.floor(rnd() * 49) }),
    check({ input, r, fail }) {
      const key = Buffer.from(U.key(input.key, [32])), N = nonceOf(input.nonce), P1 = B(input.m1), P2 = B(input.m2), L = Math.min(P1.length, P2.length);
      const c0 = ctrBlock(N, 1), C1 = ctr(key, c0, P1), C2 = ctr(key, c0, P2), ks = ctr(key, c0, Buffer.alloc(Math.max(P1.length, P2.length)));
      const X = xor(C1, C2), PX = xor(P1, P2);
      for (const f of at(r, 'first')) if (!same(f.facts.C1, C1)) fail('C₁ against node:crypto');
      for (const f of at(r, 'second')) { if (!same(f.facts.C2, C2)) fail('C₂ against node:crypto'); if (!same(f.facts.ks, ks.subarray(0, P2.length))) fail('the keystream'); }
      for (const f of at(r, 'xor')) { if (!same(f.facts.X, PX) || !same(X, PX)) fail('C₁ ⊕ C₂ = P₁ ⊕ P₂'); if (f.facts.L !== L || f.facts.zeros !== Array.from(PX).filter((v) => !v).length) fail('the zero count'); }
      for (const f of at(r, 'known')) { if (!same(f.facts.R2, P2.subarray(0, L))) fail('the recovered P₂'); if (!same(f.facts.KS, ks.subarray(0, P1.length))) fail('the recovered keystream'); }
      for (const f of at(r, 'rule')) {
        // the chance that q random 96-bit values are not all distinct: 1 − Π(1 − i/2^96) ≈ 1 − e^(−q(q−1)/2^97)
        const chance = (k) => { const q = 2 ** k, x = (q * (q - 1)) / 2 ** 97; return x < 1e-9 ? x : -Math.expm1(-x); };
        const say = (k) => { const p = chance(k), l = Math.log2(p); return l > -7 ? { pct: Math.round(100 * p) } : { e: Math.round(-l) }; };
        const m = say(input.q), n = say(32), h = Math.round(10 * Math.log2(Math.sqrt(2 * Math.log(2) * 2 ** 96))) / 10;
        if ((m.pct !== undefined ? f.facts.p !== m.pct : f.facts.e !== m.e)) fail('the chance at 2^' + input.q);
        if (f.facts.ne !== n.e || n.e !== 33) fail('the chance at 2^32');
        if (f.facts.h50 !== h) fail('the half-way point');
      }
      const s1 = siv(key, [N], P1), s2 = siv(key, [N], P2), SX = xor(s1.C, s2.C);
      for (const f of at(r, 'siv')) if (!same(f.facts.V1, s1.V) || !same(f.facts.V2, s2.V)) fail('the synthetic IVs');
      for (const f of at(r, 'siv2')) {
        if (f.meta.eq !== same(P1, P2)) fail('equal messages');
        if (f.meta.eq && !same(s1.C, s2.C)) fail('SIV of equal messages should be equal');
        if (!f.meta.eq) { if (!same(f.facts.SX, SX)) fail('the SIV C₁ ⊕ C₂'); if (f.facts.nd !== Array.from(SX).filter((v, k) => v !== PX[k]).length) fail('the count of differing bytes'); }
      }
    },
  },
  {
    topic: 'integrity-order', allow: ['32', '0'],
    random: (rnd) => ({ msg: sentence(rnd, 40), ke: randKey(rnd, [16]), km: hex(rb(rnd, 8 + Math.floor(rnd() * 24))), iv: hex(rb(rnd, 16)), tamper: ['none', 'c1', 'pad', 'tag'][Math.floor(rnd() * 4)] }),
    check({ input, r, fail }) {
      const ke = Buffer.from(U.key(input.ke, [16])), km = B(input.km), iv = Buffer.from(U.block(input.iv)), P = B(input.msg);
      const ce = createCipheriv('aes-128-cbc', ke, iv), C = Buffer.concat([ce.update(P), ce.final()]), n = C.length / 16;
      const mac = (b) => createHmac('sha256', km).update(b).digest(), T = mac(Buffer.concat([iv, C]));
      const iv2 = Buffer.from(iv), C2 = Buffer.from(C), T2 = Buffer.from(T);
      if (input.tamper === 'c1') C2[0] ^= 1;
      if (input.tamper === 'pad') { if (n > 1) C2[16 * (n - 2) + 15] ^= 1; else iv2[15] ^= 1; }
      if (input.tamper === 'tag') T2[0] ^= 1;
      const T3 = mac(Buffer.concat([iv2, C2])), ok = T3.equals(T2);
      const dd = createDecipheriv('aes-128-cbc', ke, iv2); dd.setAutoPadding(false);
      const D = Buffer.concat([dd.update(C2), dd.final()]), last = D[D.length - 1], padOk = last >= 1 && last <= 16 && D.subarray(D.length - last).every((v) => v === last);
      for (const f of at(r, 'enc')) { if (!same(f.facts.C, C)) fail('the CBC ciphertext against node:crypto'); if (f.facts.n !== n || f.facts.padN !== C.length - P.length || f.facts.L !== P.length) fail('the block and padding counts'); }
      for (const f of at(r, 'mac')) if (!same(f.facts.T, T)) fail('the HMAC tag against node:crypto');
      for (const f of at(r, 'verify')) { if (!same(f.facts.T3, T3)) fail('the receiver\'s HMAC'); if (f.meta.ok !== ok) fail('the verdict'); if (f.facts.nT !== Array.from(T3).filter((v, k) => v !== T2[k]).length) fail('the count of differing tag bytes'); if ((input.tamper === 'none') !== ok) fail('tampering went unnoticed, or an untouched message failed'); }
      for (const f of at(r, 'dec')) { const de = createDecipheriv('aes-128-cbc', ke, iv); const m = Buffer.concat([de.update(C), de.final()]); if (!same(f.facts.un, m) || !m.equals(P)) fail('the decrypted message'); if (f.facts.last !== C.length - P.length) fail('the padding byte'); }
      for (const f of at(r, 'mte')) { if (f.facts.last !== last) fail('the last decrypted byte'); if (f.meta.padOk !== padOk) fail('the padding verdict'); if (input.tamper === 'pad' && padOk) fail('a bit aimed at the padding left it valid'); }
    },
  },
];
