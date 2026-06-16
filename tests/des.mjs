// DES against FIPS 81, NIST SP 800-20 and node:crypto (three-key triple DES with three equal keys is DES).
import { createCipheriv, randomBytes } from 'node:crypto';
import { load, harness } from './load.mjs';
const S = load(['core']), t = harness('des'), { hex, fromHex } = S.bytes, D = S.DES;
const enc = (k, p, o) => hex(D.encrypt(fromHex(p), fromHex(k), o).out);
t.eq(enc('0123456789abcdef', '4e6f772069732074'), '3fa40e8a984d4815', 'FIPS 81 ECB block 1');
t.eq(enc('0123456789abcdef', '68652074696d6520'), '6a271787ab8883f9', 'FIPS 81 ECB block 2');
t.eq(enc('0101010101010101', '8000000000000000'), '95f8a5e5dd31d900', 'SP 800-20 variable plaintext 1');
t.eq(enc('0101010101010101', '0000000000000001'), '166b40b44aba4bd6', 'SP 800-20 variable plaintext 64');
t.eq(enc('8001010101010101', '0000000000000000'), '95a8d72813daa94d', 'SP 800-20 variable key 1');
t.eq(enc('0123456789abcdef', '3fa40e8a984d4815', { decrypt: true }), '4e6f772069732074', 'decryption reverses the keys');
t.eq(D.FP.length, 64, 'the final permutation'); t.ok(D.IP.every((p, i) => D.FP[p - 1] === i + 1), 'FP inverts IP');
const r = D.encrypt(fromHex('0123456789abcdef'), fromHex('0123456789abcdef'));
t.eq(r.rounds.length, 16, 'sixteen rounds'); t.ok(r.rounds[0].f.trace.length === 11, 'the f-function trace has E, key mix, 8 S-boxes and P');
for (let i = 0; i < 150; i++) {
  const k = randomBytes(8), p = randomBytes(8);
  const c = createCipheriv('des-ede3-ecb', Buffer.concat([k, k, k]), null).setAutoPadding(false).update(p);
  t.eq(hex(D.encrypt(p, k).out), c.toString('hex'), 'random block ' + i);
}
t.done();
