// AES-128 and GF(2^8) against FIPS 197 and node:crypto.
import { createCipheriv, randomBytes } from 'node:crypto';
import { load, harness } from './load.mjs';
const S = load(['core']), t = harness('aes'), { hex, fromHex } = S.bytes, G = S.gf256;
// the field
t.eq(G.mul(0x57, 0x83), 0xc1, 'FIPS 197 4.2: 57 · 83');
t.eq(G.mul(0x57, 0x13), 0xfe, 'FIPS 197 4.2.1: 57 · 13');
t.eq(G.xtime(0x57), 0xae, 'xtime(57)'); t.eq(G.xtime(0xae), 0x47, 'xtime(ae)');
for (let a = 1; a < 256; a++) { t.ok(G.fastMul(a, G.inv(a)) === 1, 'inverse of ' + a); for (const b of [3, 0x1d, 0xc7]) t.ok(G.mul(a, b) === G.fastMul(a, b), 'mul ' + a + '·' + b); }
t.eq([G.SBOX[0x00], G.SBOX[0x53], G.SBOX[0xff], G.SBOX[0x9a]], [0x63, 0xed, 0x16, 0xb8], 'S-box entries');
t.eq(G.subByteTrace(0x53).inv, 0xca, 'inverse of 53 is ca');
t.eq(new Set(G.SBOX).size, 256, 'the S-box is a permutation');
// the key expansion (FIPS 197 A.1)
const key = fromHex('2b7e151628aed2a6abf7158809cf4f3c'), ex = S.AES.expandKey(key);
t.eq(hex(ex.w[4]), 'a0fafe17', 'w4'); t.eq(hex(ex.w[43]), 'b6630ca6', 'w43');
t.eq(ex.trace.filter((s) => s.kind === 'g').length, 10, 'ten g steps');
t.ok(ex.trace.every((s) => typeof s.say === 'string' && s.say.length > 10), 'every step says something');
// encryption (FIPS 197 B and C.1)
const b = S.AES.encrypt(fromHex('3243f6a8885a308d313198a2e0370734'), key);
t.eq(hex(b.out), '3925841d02dc09fbdc118597196a0b32', 'FIPS 197 B');
t.eq(hex(b.rounds[1].sub), 'd42711aee0bf98f1b8b45de51e415230', 'B round 1 after SubBytes');
t.eq(hex(b.rounds[1].shift), 'd4bf5d30e0b452aeb84111f11e2798e5', 'B round 1 after ShiftRows');
t.eq(hex(b.rounds[1].mix), '046681e5e0cb199a48f8d37a2806264c', 'B round 1 after MixColumns');
const c1 = S.AES.encrypt(fromHex('00112233445566778899aabbccddeeff'), fromHex('000102030405060708090a0b0c0d0e0f'));
t.eq(hex(c1.out), '69c4e0d86a7b0430d8cdb78070b4c55a', 'FIPS 197 C.1');
t.eq(S.AES.mixColumn([0xdb, 0x13, 0x53, 0x45]).out, [0x8e, 0x4d, 0xa1, 0xbc], 'a MixColumns column');
// random blocks against node
for (let i = 0; i < 200; i++) {
  const k = randomBytes(16), p = randomBytes(16);
  const c = createCipheriv('aes-128-ecb', k, null).setAutoPadding(false).update(p);
  t.eq(hex(S.AES.encrypt(p, k).out), c.toString('hex'), 'random block ' + i);
}
t.done();
