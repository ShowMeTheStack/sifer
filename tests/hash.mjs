// SHA-256 against FIPS 180 and node:crypto; Keccak and SHA3-256 against FIPS 202 and node:crypto.
import { createHash, randomBytes } from 'node:crypto';
import { load, harness } from './load.mjs';
const S = load(['core']), t = harness('hash'), { hex, utf8, h8 } = S.bytes, H = S.SHA256, K = S.Keccak;
t.eq(hex(H.hash(utf8('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'FIPS 180 one block');
t.eq(hex(H.hash(utf8('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))), '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1', 'FIPS 180 two blocks');
const c = H.compress(H.IV, H.pad(utf8('abc')));
t.eq(h8(c.rounds[0].regs[0]), '5d6aebcd', 'abc round 0: a'); t.eq(h8(c.rounds[63].regs[0]), '506e3058', 'abc round 63: a');
t.eq(c.W.length, 64, 'sixty-four schedule words');
for (let i = 0; i < 150; i++) { const m = randomBytes((Math.random() * 300) | 0); t.eq(hex(H.hash(m)), createHash('sha256').update(m).digest('hex'), 'sha256 random ' + i); }
t.eq(K.R[1], 1, 'rho offset (1, 0)'); t.eq(K.R[0 + 5 * 2], 3, 'rho offset (0, 2)'); t.eq(K.R[4 + 5 * 4], 14, 'rho offset (4, 4)');
t.eq(K.hex(K.RC[0]), '0000000000000001', 'RC0'); t.eq(K.hex(K.RC[23]), '8000000080008008', 'RC23'); t.eq(K.hex(K.RC[2]), '800000000000808a', 'RC2');
t.eq(hex(K.sha3_256(new Uint8Array(0))), 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a', 'SHA3-256 of the empty message');
t.eq(hex(K.sha3_256(utf8('abc'))), '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532', 'SHA3-256 of abc');
for (let i = 0; i < 80; i++) { const m = randomBytes((Math.random() * 400) | 0); t.eq(hex(K.sha3_256(m)), createHash('sha3-256').update(m).digest('hex'), 'sha3 random ' + i); }
// theta alone: one bit set touches itself and two columns
const A = new Array(25).fill(0n); A[2 + 5 * 3] = 1n << 10n;
const th = K.theta(A);
t.eq(th.A.reduce((n, v) => n + v.toString(2).split('1').length - 1, 0), 11, 'one bit through theta becomes 11');
t.done();
