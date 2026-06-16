// ChaCha20 against RFC 8439 and node:crypto.
import { createCipheriv, randomBytes } from 'node:crypto';
import { load, harness } from './load.mjs';
const S = load(['core']), t = harness('chacha'), { hex, h8, fromHex } = S.bytes, C = S.ChaCha;
const q = C.qr(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567);
t.eq(q.out.map(h8), ['ea2a92f4', 'cb1cf8ce', '4581472e', '5881c4bb'], 'RFC 8439 2.1.1 quarter round');
t.eq(q.trace.length, 12, 'twelve steps'); t.eq(h8(q.trace[0].after), '12131415', 'the first step: a += b');
const key = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const blk = C.block(key, 1, fromHex('000000090000004a00000000'));
t.eq(hex(blk.out.slice(0, 16)), '10f1e7e4d13b5915500fdd1fa32071c4', 'RFC 8439 2.3.2 block, first 16 bytes');
t.eq(hex(blk.out.slice(48)), 'b5129cd1de164eb9cbd083e8a2503c4e', 'RFC 8439 2.3.2 block, last 16 bytes');
for (let i = 0; i < 100; i++) {
  const k = randomBytes(32), n = randomBytes(12), ctr = (Math.random() * 1000) | 0, data = randomBytes(1 + ((Math.random() * 200) | 0));
  const iv = Buffer.alloc(16); iv.writeUInt32LE(ctr, 0); n.copy(iv, 4);
  const want = createCipheriv('chacha20', k, iv).update(data).toString('hex');
  t.eq(hex(C.encrypt(k, ctr, n, data)), want, 'random message ' + i);
}
t.done();
