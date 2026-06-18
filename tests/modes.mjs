// CBC and CTR over AES-128 against NIST SP 800-38A and node:crypto.
import { createCipheriv, randomBytes } from 'node:crypto';
import { load, harness } from './load.mjs';
const S = load(['core']), t = harness('modes'), { hex, fromHex } = S.bytes, Mo = S.Modes;
const key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
const P = ['6bc1bee22e409f96e93d7e117393172a', 'ae2d8a571e03ac9c9eb76fac45af8e51', '30c81c46a35ce411e5fbc1191a0a52ef', 'f69f2445df4f9b17ad2b417be66c3710'].map(fromHex);
t.eq(Mo.cbc(P, key, fromHex('000102030405060708090a0b0c0d0e0f')).out.map((b) => hex(b)), ['7649abac8119b246cee98e9b12e9197d', '5086cb9b507219ee95db113a917678b2', '73bed6b8e3c1743b7116e69e22229516', '3ff1caa1681fac09120eca307586e1a7'], 'SP 800-38A F.2.1 CBC-AES128');
t.eq(Mo.ctr(P, key, fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')).out.map((b) => hex(b)), ['874d6191b620e3261bef6864990db6ce', '9806f66b7970fdff8617187bb9fffdff', '5ae4df3edbd5d35e5b4f09020db03eab', '1e031dda2fbe03d1792170a0f3009cee'], 'SP 800-38A F.5.1 CTR-AES128');
t.eq(hex(Mo.counter(fromHex('000000000000000000000000ffffffff'), 1)), '00000000000000000000000100000000', 'the counter carries');
for (let i = 0; i < 60; i++) {
  const k = randomBytes(16), iv = randomBytes(16), n = 1 + ((Math.random() * 6) | 0), data = randomBytes(16 * n);
  t.eq(Mo.cbc(Mo.split(data), k, iv).out.map((b) => hex(b)).join(''), createCipheriv('aes-128-cbc', k, iv).setAutoPadding(false).update(data).toString('hex'), 'CBC random ' + i);
  const d2 = randomBytes(1 + ((Math.random() * 90) | 0));
  t.eq(Mo.ctr(Mo.split(d2), k, iv).out.map((b) => hex(b)).join(''), createCipheriv('aes-128-ctr', k, iv).update(d2).toString('hex'), 'CTR random ' + i);
}
t.done();
