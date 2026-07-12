// The symmetric engines: published vectors (FIPS 197, SP 800-38A, the GCM specification test cases, IEEE 1619,
// SP 800-67, RFC 8439, RFC 3962, the PRESENT paper, the eSTREAM Trivium and Salsa20 sets), node:crypto on
// thousands of random cases, and every attack lab recovering its planted secret over several seeds.
import { createCipheriv, createDecipheriv, randomBytes, getCiphers } from 'node:crypto';
import { load, harness, rng } from './load.mjs';
const S = load(['core']), t = harness('sym'), { hex, fromHex, utf8 } = S.bytes;
const R = rng(2026), rb = (n) => Uint8Array.from({ length: n }, () => (R() * 256) | 0), ri = (n) => Math.floor(R() * n);
const has = new Set(getCiphers());
const saysAll = (tr, what) => t.ok(Array.isArray(tr) && tr.length > 0 && tr.every((s) => typeof s.kind === 'string' && typeof s.say === 'string' && s.say.length > 8), what + ': every trace step says something');

// ---- AES at every size (FIPS 197 C.1–C.3, A.1–A.3), decryption, S-box derivation, T-tables
const A = S.AES, pt = fromHex('00112233445566778899aabbccddeeff');
const K = { 128: fromHex('000102030405060708090a0b0c0d0e0f'), 192: fromHex('000102030405060708090a0b0c0d0e0f1011121314151617'), 256: fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f') };
const want = { 128: '69c4e0d86a7b0430d8cdb78070b4c55a', 192: 'dda97ca4864cdfe06eaf70a0ec0d7191', 256: '8ea2b7ca516745bfeafc49904b496089' };
for (const b of [128, 192, 256]) {
  const e = A.encryptBlock(pt, K[b]);
  t.eq(hex(e.out), want[b], `FIPS 197 C AES-${b}`);
  t.eq(e.rounds.length, { 128: 11, 192: 13, 256: 15 }[b], `AES-${b} round count`);
  const d = A.decryptBlock(e.out, K[b]);
  t.eq(hex(d.out), hex(pt), `FIPS 197 C AES-${b} inverse cipher`);
  t.eq(hex(d.rounds[d.rounds.length - 1].end), hex(pt), `AES-${b} the last inverse round ends at the plaintext`);
  t.eq(hex(A.cipher(K[b]).encrypt(pt)), want[b], `T-table AES-${b}`);
  t.eq(hex(A.cipher(K[b]).decrypt(fromHex(want[b]))), hex(pt), `T-table inverse AES-${b}`);
  saysAll(e.trace, `AES-${b} encryption`); saysAll(d.trace, `AES-${b} decryption`);
}
t.eq(hex(A.expand(fromHex('2b7e151628aed2a6abf7158809cf4f3c')).w[43]), 'b6630ca6', 'FIPS 197 A.1 w43');
t.eq([hex(A.encrypt(pt, K[192]).out), hex(A.encrypt(pt, K[256]).out), hex(S.Modes.ctr([pt], K[256], new Uint8Array(16)).out[0])], [want[192], want[256], hex(S.bytes.xor(pt, A.cipher(K[256]).encrypt(new Uint8Array(16))))], 'S.AES.encrypt and S.Modes take every key size');
t.eq(hex(A.expand(fromHex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b')).w[51]), '01002202', 'FIPS 197 A.2 w51');
const x256 = A.expand(fromHex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'));
t.eq(hex(x256.w[59]), '706c631e', 'FIPS 197 A.3 w59'); t.ok(x256.trace.some((s) => s.kind === 'subword'), 'AES-256 key expansion has the extra SubWord');
const c1 = A.encryptBlock(pt, K[128]);
t.eq(hex(A.invMixColumns(c1.rounds[1].mix)), hex(c1.rounds[1].shift), 'InvMixColumns undoes MixColumns');
t.eq(hex(A.invShiftRows(c1.rounds[1].shift)), hex(c1.rounds[1].sub), 'InvShiftRows undoes ShiftRows');
let sb = 0; for (let a = 0; a < 256; a++) { const f = A.sboxDerive(a), g = A.invSboxDerive(S.gf256.SBOX[a]); sb += f.out === S.gf256.SBOX[a] && g.out === a && g.trace.length === 2; }
t.eq(sb, 256, 'the S-box and its inverse derived byte by byte');
const tt = A.tt.encrypt(pt, K[128]);
t.eq(hex(tt.out), want[128], 'traced T-table encryption'); t.eq(tt.lookups.length, 160, '160 table lookups in AES-128');
t.eq(tt.lookups.filter((l) => l.round === 1).map((l) => l.index).sort((a, b) => a - b), Array.from(pt.map((v, i) => v ^ K[128][i])).sort((a, b) => a - b), 'first-round indices are plaintext ⊕ key');
saysAll(tt.trace, 'T-table');
for (let i = 0; i < 600; i++) {
  const ks = [16, 24, 32][i % 3], k = rb(ks), p = rb(16), c = createCipheriv(`aes-${ks * 8}-ecb`, k, null).setAutoPadding(false).update(p);
  t.eq(hex(i < 150 ? A.encryptBlock(p, k).out : A.cipher(k).encrypt(p)), c.toString('hex'), `AES-${ks * 8} block vs node ${i}`);
  t.eq(hex(i < 150 ? A.decryptBlock(c, k).out : A.cipher(k).decrypt(c)), hex(p), `AES-${ks * 8} inverse vs node ${i}`);
}

// ---- Mini-AES
const MA = S.MiniAES, me = MA.encrypt(0x9c63, 0xc3f0);
t.eq(MA.hex(me.out), '72c6', 'Mini-AES specification example'); t.eq(me.keys.map((k) => MA.hex(MA.join(k))), ['c3f0', '30ff', '6696'], 'Mini-AES round keys');
saysAll(me.trace, 'Mini-AES');
let mok = 0; for (let i = 0; i < 2000; i++) { const p = ri(65536), k = ri(65536); mok += MA.decrypt(MA.encrypt(p, k).out, k).out === p; }
t.eq(mok, 2000, 'Mini-AES decrypts');
let inv = 1; for (let a = 0; a < 16; a++) for (let b = 0; b < 16; b++) { const m = MA.mixColumn(MA.mixColumn([a, b, b, a]).out).out; if (m.join() !== [a, b, b, a].join()) inv = 0; }
t.ok(inv, 'Mini-AES MixColumn is its own inverse');

// ---- DES family: fast DES, 3DES (SP 800-67), DESX, weak keys, complementation, Feistel, meet-in-the-middle
const D = S.DES;
t.eq(hex(S.TDES.encrypt(fromHex('5468652071756663'), fromHex('0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123')).out), 'a826fd8ce53b855f', 'SP 800-67 example block 1');
const tdk = fromHex('0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123');
t.eq(hex(S.Modes.encrypt('ecb', S.TDES.cipher(tdk), utf8('The qufck brown fox jump'), { trace: false }).out), 'a826fd8ce53b855fcce21c8112256fe668d5c05dd9b6b900', 'SP 800-67 example, three blocks');
saysAll(S.TDES.encrypt(rb(8), rb(24)).trace, '3DES');
for (let i = 0; i < 1500; i++) {
  const k = rb(8), p = rb(8), c = createCipheriv('des-ede3-ecb', Buffer.concat([k, k, k]), null).setAutoPadding(false).update(p);
  const f = D.cipher(k); t.eq(hex(f.encrypt(p)), c.toString('hex'), 'fast DES vs node ' + i); t.eq(hex(f.decrypt(c)), hex(p), 'fast DES decrypt ' + i);
  if (i < 300) t.eq(hex(D.decrypt(c, k).out), hex(p), 'traced DES decrypt ' + i);
  const k3 = rb(24), k2 = rb(16);
  t.eq(hex(S.TDES.cipher(k3).encrypt(p)), createCipheriv('des-ede3-ecb', k3, null).setAutoPadding(false).update(p).toString('hex'), '3-key 3DES vs node ' + i);
  if (has.has('des-ede-ecb')) t.eq(hex(S.TDES.cipher(k2).encrypt(p)), createCipheriv('des-ede-ecb', k2, null).setAutoPadding(false).update(p).toString('hex'), '2-key 3DES vs node ' + i);
  if (i < 300) { const iv = rb(8), d = rb(8 * (1 + ri(6))); t.eq(hex(S.Modes.encrypt('cbc', S.TDES.cipher(k3), d, { iv, trace: false }).out), createCipheriv('des-ede3-cbc', k3, iv).setAutoPadding(false).update(d).toString('hex'), 'des-ede3-cbc vs node ' + i); }
}
t.eq(hex(S.TDES.compatible(fromHex('4e6f772069732074'), fromHex('0123456789abcdef'))), '3fa40e8a984d4815', 'EDE with equal keys is single DES (FIPS 81 vector)');
for (let i = 0; i < 100; i++) { const k = rb(8), k1 = rb(8), k2 = rb(8), p = rb(8), X = S.DESX.cipher(k, k1, k2), c = X.encrypt(p); t.eq(hex(c), hex(S.DESX.encrypt(p, k, k1, k2).out), 'DESX traced = fast ' + i); t.eq(hex(X.decrypt(c)), hex(p), 'DESX decrypts ' + i); }
for (const w of D.WEAK) { const kc = D.keyClass(fromHex(w)); t.ok(kc.weak && new Set(kc.subkeys).size === 1, 'weak key ' + w); t.ok(D.weakDemo(rb(8), fromHex(w)).back, 'weak key encrypts twice to the plaintext ' + w); }
for (const [a, b] of D.SEMI_WEAK) { t.eq(D.keyClass(fromHex(a)).partner, b, 'semi-weak partner of ' + a); t.ok(D.weakDemo(rb(8), fromHex(a), fromHex(b)).back, 'semi-weak pair undoes itself ' + a); }
t.ok(!D.keyClass(fromHex('133457799bbcdff1')).weak && !D.keyClass(fromHex('133457799bbcdff1')).semiWeak, 'an ordinary key');
let comp = 0; for (let i = 0; i < 300; i++) comp += D.complementation(rb(8), rb(8)).holds; t.eq(comp, 300, 'the complementation property');
const Fe = S.Feistel;
for (const [name, rf] of Object.entries(Fe.ROUND_FUNCTIONS)) for (let i = 0; i < 50; i++) {
  const keys = Array.from({ length: 1 + ri(16) }, () => ri(65536)), x = BigInt(ri(2 ** 32)), o = { keys, F: rf.F, bits: 16 };
  t.eq(Fe.decrypt(Fe.encrypt(x, o).out, o).out, x, `Feistel ${name} decrypts ${i}`);
}
saysAll(Fe.encrypt(0x12345678n, { keys: [1, 2, 3], F: Fe.ROUND_FUNCTIONS.sbox.F, bits: 16 }).trace, 'Feistel');
for (const [seed, bits] of [[1, 16], [2, 16], [3, 12], [4, 12], [5, 14]]) {
  const lab = S.MITM.setup({ seed, bits }), r = S.MITM.attack(lab);
  t.ok(r.found.some((f) => f.k1v === lab.k1v && f.k2v === lab.k2v), `meet-in-the-middle finds the planted keys (seed ${seed}, ${bits} bits)`);
  t.ok(r.found.length <= 2 && r.work.mitm === 2 << bits, `meet-in-the-middle work (seed ${seed})`);
  if (seed === 1) saysAll(r.trace, 'meet-in-the-middle');
}

// ---- toy SPN: tables, searches, both attacks
const P = S.SPN, ddt = P.ddt(), lat = P.lat();
t.ok(ddt.every((row) => row.reduce((a, b) => a + b, 0) === 16) && ddt[0][0] === 16, 'DDT rows sum to 16');
t.ok(lat[0][0] === 8 && lat[0].slice(1).every((v) => v === 0), 'LAT first row');
for (let i = 0; i < 300; i++) { const keys = P.keys(i + 1), p = ri(65536), c = P.encrypt(p, keys).out; t.eq(P.decrypt(c, keys).out, p, 'SPN decrypts ' + i); t.eq(P.fast(keys).enc(p), c, 'SPN tables agree ' + i); t.eq(P.fast(keys).dec(c), p, 'SPN fast decrypt ' + i); }
for (let x = 0; x < 65536; x += 97) t.eq(P.unpermute(P.permute(x)), x, 'SPN permutation inverts ' + x);
const chars = P.searchDifferential(), apps = P.searchLinear();
t.ok(chars.length > 0 && chars[0].prob >= 1 / 128, 'a differential characteristic of probability at least 1/128');
t.ok(apps.length > 0 && apps[0].bias >= 1 / 32, 'a linear approximation of bias at least 1/32');
// the characteristic's probability, measured on the cipher with random keys
{ const c = chars[0], E = P.fast(P.keys(77)).enc; let hit = 0; const N = 40000; for (let i = 0; i < N; i++) { const p = ri(65536); const u = (x) => P.subs(x ^ P.keys(77)[4], true); if ((u(E(p)) ^ u(E(p ^ c.dIn))) === c.dU4) hit++; } t.ok(hit / N > c.prob / 2, `measured differential ${(hit / N).toFixed(4)} vs predicted ${c.prob.toFixed(4)}`); }
for (let s = 1; s <= 6; s++) { const r = P.recoverK5({ seed: s }); t.ok(r.ok, 'differential attack recovers K5, seed ' + s); if (s === 1) { saysAll(r.trace, 'differential attack'); saysAll(r.nibbles[0].trace, 'differential counts'); t.eq(r.nibbles[0].counts.length, 16, 'counts per key guess'); } }
for (let s = 1; s <= 4; s++) { const r = P.recoverK5({ seed: s, method: 'linear' }); t.ok(r.ok, 'linear attack recovers K5, seed ' + s); if (s === 1) saysAll(r.trace, 'linear attack'); }
{ const two = chars.find((c) => c.active.length === 2), keys = P.keys(9), r = P.diffAttack({ keys, char: two, pairs: Math.ceil(30 / two.prob), seed: 3 }); t.ok(r.ok && r.counts.length === 256, 'differential attack on two nibbles (256 guesses)'); }

// ---- PRESENT-80 (the paper's vectors)
const PR = S.PRESENT;
for (const [p, k, c] of [['0000000000000000', '00000000000000000000', '5579c1387b228445'], ['0000000000000000', 'ffffffffffffffffffff', 'e72c46c0f5945049'], ['ffffffffffffffff', '00000000000000000000', 'a112ffc72f68417b'], ['ffffffffffffffff', 'ffffffffffffffffffff', '3333dcd3213210d2']]) {
  const e = PR.encrypt(fromHex(p), fromHex(k)); t.eq(hex(e.out), c, `PRESENT ${p} / ${k}`); t.eq(hex(PR.decrypt(e.out, fromHex(k)).out), p, `PRESENT inverse ${p} / ${k}`); t.eq(hex(PR.cipher(fromHex(k)).encrypt(fromHex(p))), c, 'PRESENT fast ' + k);
}
for (let i = 0; i < 100; i++) { const k = rb(10), p = rb(8), E = PR.cipher(k); t.eq(hex(E.decrypt(E.encrypt(p))), hex(p), 'PRESENT round trip ' + i); }
saysAll(PR.encrypt(rb(8), rb(10)).trace, 'PRESENT');

// ---- LFSRs, Berlekamp–Massey, Geffe
const L = S.LFSR, TAPS = [[4, 3], [5, 2], [7, 1], [11, 2], [13, 4, 3, 1], [16, 15, 13, 4], [9, 4], [10, 3]];
for (const tp of TAPS.slice(0, 7)) t.ok(L.isPrimitive(tp), 'primitive: ' + L.str(L.poly(tp)));
t.eq(L.period([4, 2]), 6, 'a non-primitive register has a short period'); t.eq(L.str(L.poly([4, 3])), '1 + x³ + x⁴', 'polynomial text');
for (let i = 0; i < 200; i++) {
  const tp = TAPS[i % TAPS.length], n = tp[0], seed = Array.from({ length: n }, () => ri(2)); if (!seed.includes(1)) seed[0] = 1;
  const f = L.fibonacci(tp, seed).run(3 * n), g = L.galois(tp, seed).run(3 * n);
  t.eq(g.bits.join(''), f.bits.join(''), 'Galois and Fibonacci forms agree ' + i);
  t.eq(L.sequence(tp, seed, 3 * n).join(''), f.bits.join(''), 'fast sequence agrees ' + i);
  const bm = L.berlekampMassey(f.bits.slice(0, 2 * n));
  t.eq(bm.poly, L.poly(tp), 'Berlekamp–Massey recovers the register from 2L bits ' + i);
}
const bmt = L.berlekampMassey(L.fibonacci([4, 3], [1, 0, 0, 1]).run(8).bits);
t.ok(bmt.steps.length === 8 && bmt.steps.every((s) => s.d === 0 || s.d === 1), 'Berlekamp–Massey records each discrepancy'); saysAll(bmt.trace, 'Berlekamp–Massey');
saysAll(L.fibonacci([5, 2], [1, 0, 1, 1, 0]).run(10).trace, 'LFSR');
for (let s = 1; s <= 4; s++) { const lab = S.Geffe.setup({ seed: s }), r = S.Geffe.attack({ z: lab.z }); t.ok(r.ok && r.seeds.every((x, i) => x.join('') === lab.seeds[i].join('')), 'Geffe correlation attack, seed ' + s); if (s === 1) saysAll(r.trace, 'correlation attack'); }

// ---- stream ciphers: Trivium, Salsa20 (eSTREAM), ChaCha20 (RFC 8439), XChaCha20
const tri = S.Trivium.create(fromHex('80000000000000000000'), fromHex('00000000000000000000')).keystream(512);
t.eq(hex(tri.slice(0, 64)), '38eb86ff730d7a9caf8df13a4420540dbb7b651464c87501552041c249f29a64d2fbf515610921ebe06c8f92cecf7f8098ff20cccc6a62b97be8ef7454fc80f9', 'Trivium eSTREAM set 1, vector 0, bytes 0–63');
t.eq(hex(tri.slice(448, 512)), 'ebf14772061c210843c18cea2d2a275ae02fcb18e5d7942455ff77524e8a4ca51e369a847d1aeefb9002fcd02342983ceafa9d487cc2032b10192cd416310fa4', 'Trivium eSTREAM set 1, vector 0, bytes 448–511');
const tri6 = S.Trivium.create(fromHex('0053A6F94C9FF24598EB'), fromHex('0D74DB42A91077DE45AC')).keystream(131072);
t.eq(hex(tri6.slice(0, 16)), 'f4cd954a717f26a7d6930830c4e7cf08', 'Trivium eSTREAM set 6, vector 0, start');
t.eq(hex(tri6.slice(131008, 131072)), '48107374a9ce3aaf78221ae77789247cf6896a249ed75dce0cf2d30eb9d889a0c61c9f480e5c07381ded9fab2ad54333e82c89ba92e6e47fd828f1a66a8656e0', 'Trivium eSTREAM set 6, vector 0, bytes 131008–131071');
saysAll(S.Trivium.trace(rb(10), rb(10), 8).trace, 'Trivium');
t.eq(hex(S.Salsa.encrypt(fromHex('80000000000000000000000000000000'), new Uint8Array(8), new Uint8Array(64)).slice(0, 16)), '4dfa5e481da23ea09a31022050859936', 'Salsa20 eSTREAM set 1, vector 0');
for (const [k, iv, dig] of [['0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D', '0D74DB42A91077DE', 'C349B6A51A3EC9B712EAED3F90D8BCEE69B7628645F251A996F55260C62EF31FD6C6B0AEA94E136C9D984AD2DF3578F78E457527B03A0450580DD874F63B1AB9'],
  ['0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12', '167DE44BB21980E7', 'C3EAAF32836BACE32D04E1124231EF47E101367D6305413A0EEB07C60698A2876E4D031870A739D6FFDDD208597AFF0A47AC17EDB0167DD67EBA84F1883D4DFD'],
  ['0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417', '1F86ED54BB2289F0', '3CD23C3DC90201ACC0CF49B440B6C417F0DC8D8410A716D5314C059E14B1A8D9A9FB8EA3D9C8DAE12B21402F674AA95C67B1FC514E994C9D3F3A6E41DFF5BBA6'],
  ['0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C', '288FF65DC42B92F9', 'E00EBCCD70D69152725F9987982178A2E2E139C7BCBE04CA8A0E99E318D9AB76F988C8549F75ADD790BA4F81C176DA653C1A043F11A958E169B6D2319F4EEC1A']]) {
  const ks = S.Salsa.encrypt(fromHex(k), fromHex(iv), new Uint8Array(131072)), x = new Uint8Array(64);
  for (let i = 0; i < ks.length; i++) x[i & 63] ^= ks[i];
  t.eq(hex(x), dig.toLowerCase(), 'Salsa20 eSTREAM set 6 xor-digest, key ' + k.slice(0, 8));
}
{ const sk = rb(32), sn = rb(8), blk = S.Salsa.block(sk, sn, 5); t.eq(hex(blk.out), hex(S.Salsa.encrypt(sk, sn, new Uint8Array(64), 5)), 'Salsa20 block = keystream at counter 5'); saysAll(blk.trace, 'Salsa20'); t.eq(S.Salsa.qr(1, 0, 0, 0).trace.length, 4, 'Salsa20 quarter-round has four steps'); }
const C = S.ChaCha, ck = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const sun = utf8("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
const ce = C.encryptTrace(ck, 1, fromHex('000000000000004a00000000'), sun);
t.eq(hex(ce.out), '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d', 'RFC 8439 2.4.2 encryption');
t.eq(ce.blocks.map((b) => b.counter), [1, 2], 'RFC 8439 2.4.2 counters'); saysAll(ce.trace, 'ChaCha20 encryption');
let threw = false; try { C.encryptTrace(ck, 0xffffffff, new Uint8Array(12), new Uint8Array(65)); } catch (e) { threw = true; } t.ok(threw, 'the 32-bit counter may not wrap');
t.eq(hex(C.hchacha(ck, fromHex('000000090000004a0000000031415927')).out), '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc', 'HChaCha20 test vector');
t.eq(hex(C.xencrypt(fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'), fromHex('404142434445464748494a4b4c4d4e4f5051525354555658'), utf8('The dhole (pronounced "dole") is also known as the Asiatic wild dog, red dog, and whistling dog.')).out.slice(0, 32)), '4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e9', 'XChaCha20 test vector');
for (let i = 0; i < 1000; i++) {
  const k = rb(32), n = rb(12), ctr = ri(1 << 20), d = rb(1 + ri(300)), iv = Buffer.alloc(16); iv.writeUInt32LE(ctr, 0); Buffer.from(n).copy(iv, 4);
  t.eq(hex(C.encryptTrace(k, ctr, n, d).out), createCipheriv('chacha20', k, iv).update(d).toString('hex'), 'ChaCha20 vs node ' + i);
  if (i < 500) { const c = createCipheriv('chacha20-poly1305', k, n, { authTagLength: 16 }); const want = c.update(d); t.eq(hex(C.encryptTrace(k, 1, n, d).out), want.toString('hex'), 'chacha20-poly1305 ciphertext (counter 1) vs node ' + i); }
}

// ---- modes over any block cipher (SP 800-38A), padding, CTS (RFC 3962), ECB image
const Mo = S.Modes, k38 = fromHex('2b7e151628aed2a6abf7158809cf4f3c'), k38b = fromHex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
const P38 = fromHex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710');
const iv38 = fromHex('000102030405060708090a0b0c0d0e0f'), ctr38 = fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
const V38 = [
  ['ecb', k38, null, '3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4', 'F.1.1 ECB-AES128'],
  ['cbc', k38, iv38, '7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7', 'F.2.1 CBC-AES128'],
  ['cfb', k38, iv38, '3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6', 'F.3.13 CFB128-AES128'],
  ['ofb', k38, iv38, '3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e', 'F.4.1 OFB-AES128'],
  ['ctr', k38, ctr38, '874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee', 'F.5.1 CTR-AES128'],
  ['ecb', k38b, null, 'f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7', 'F.1.5 ECB-AES256'],
  ['cbc', k38b, iv38, 'f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b', 'F.2.5 CBC-AES256'],
  ['ctr', k38b, ctr38, '601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6', 'F.5.5 CTR-AES256'],
];
for (const [m, k, iv, c, name] of V38) {
  const r = Mo.encrypt(m, A.cipher(k), P38, { iv }); t.eq(hex(r.out), c, 'SP 800-38A ' + name);
  t.eq(hex(Mo.decrypt(m, A.cipher(k), fromHex(c), { iv }).out), hex(P38), 'SP 800-38A ' + name + ' decryption'); saysAll(r.trace, name);
}
t.eq(hex(Mo.encrypt('cfb8', A.cipher(k38), P38.slice(0, 18), { iv: iv38 }).out), '3b79424c9c0dd436bace9e0ed4586a4f32b9', 'SP 800-38A F.3.7 CFB8-AES128');
const sizes = { ecb: 'ecb', cbc: 'cbc', cfb: 'cfb', cfb8: 'cfb8', ofb: 'ofb', ctr: 'ctr' };
for (let i = 0; i < 3600; i++) {
  const ks = [16, 24, 32][i % 3], m = Object.keys(sizes)[Math.floor(i / 3) % 6], k = rb(ks), iv = rb(16), E = A.cipher(k);
  const d = rb(m === 'ecb' || m === 'cbc' ? 16 * (1 + ri(5)) : 1 + ri(90));
  const want = createCipheriv(`aes-${ks * 8}-${sizes[m]}`, k, m === 'ecb' ? null : iv).setAutoPadding(false).update(d);
  const got = Mo.encrypt(m, E, d, { iv, trace: i % 10 === 0 }).out;
  t.eq(hex(got), want.toString('hex'), `aes-${ks * 8}-${m} vs node ${i}`);
  t.eq(hex(Mo.decrypt(m, E, got, { iv, trace: false }).out), hex(d), `aes-${ks * 8}-${m} decrypts ${i}`);
}
for (let i = 0; i < 300; i++) {
  const d = rb(ri(70)), p7 = Mo.pkcs7(d, 16), iso = Mo.iso7816(d, 16);
  t.ok(p7.length % 16 === 0 && p7.length > d.length && hex(Mo.unpkcs7(p7, 16)) === hex(d), 'PKCS#7 round trip ' + i);
  t.ok(iso.length % 16 === 0 && hex(Mo.uniso7816(iso)) === hex(d), 'ISO 7816-4 round trip ' + i);
  const k = rb(16), iv = rb(16);
  const nc = createCipheriv('aes-128-cbc', k, iv); t.eq(hex(Mo.encrypt('cbc', A.cipher(k), p7, { iv, trace: false }).out), Buffer.concat([nc.update(d), nc.final()]).toString('hex'), 'PKCS#7 matches node padding ' + i);
}
let badPad = 0; for (const bad of ['00', '11', '0203', '0102']) { try { Mo.unpkcs7(fromHex('aa'.repeat(16 - bad.length / 2) + bad), 16); } catch (e) { badPad++; } } t.eq(badPad, 4, 'bad PKCS#7 padding is rejected');
const cts = A.cipher(fromHex('636869636b656e207465726979616b69')), cmsg = utf8("I would like the General Gau's Chicken, please, and wonton soup.");
for (const [n, c] of [[17, 'c6353568f2bf8cb4d8a580362da7ff7f97'], [31, 'fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5'], [32, '39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584'], [64, '97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8']])
  t.eq(hex(Mo.cts(cts, cmsg.slice(0, n), new Uint8Array(16), { variant: 'CS3' }).out), c, `RFC 3962 AES ciphertext stealing, ${n} bytes`);
for (let i = 0; i < 300; i++) {
  const v = ['CS1', 'CS2', 'CS3'][i % 3], E = A.cipher(rb(16)), iv = rb(16), d = rb(16 + ri(60)), c = Mo.cts(E, d, iv, { variant: v }).out;
  t.ok(c.length === d.length && hex(Mo.cts(E, c, iv, { variant: v, decrypt: true }).out) === hex(d), `CBC-${v} round trip ${i}`);
  if (v === 'CS1' && d.length % 16 === 0) t.eq(hex(c), hex(Mo.encrypt('cbc', E, d, { iv, trace: false }).out), 'CS1 on whole blocks is CBC ' + i);
}
{ const img = new Uint8Array(64 * 64); for (let y = 0; y < 64; y++) for (let x = 0; x < 64; x++) img[64 * y + x] = (x - 32) ** 2 + (y - 32) ** 2 < 400 ? 200 : 30; const r = Mo.ecbImage(A.cipher(rb(16)), img); t.ok(r.distinct < r.blocks / 4 && r.repeats > r.blocks / 2, `ECB keeps the picture: ${r.distinct} distinct blocks of ${r.blocks}`); }
for (const [name, k] of [['des', rb(8)], ['3des', rb(24)], ['present', rb(10)], ['aes', rb(32)]]) { const E = S.Sym.cipher(name, k), iv = rb(E.n), d = rb(E.n * 4); for (const m of ['cbc', 'cfb', 'ofb', 'ctr', 'ecb', 'cfb8']) t.eq(hex(Mo.decrypt(m, E, Mo.encrypt(m, E, d, { iv }).out, { iv }).out), hex(d), `${m} over ${name}`); }

// ---- XTS (IEEE 1619) and GCM (the GCM specification test cases)
t.eq(hex(S.XTS.encrypt(new Uint8Array(32), 0, new Uint8Array(32)).out), '917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e', 'IEEE 1619 XTS-AES-128 vector 1');
t.eq(hex(S.XTS.encrypt(fromHex('11'.repeat(16) + '22'.repeat(16)), 0x3333333333, fromHex('44'.repeat(32))).out), 'c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0', 'IEEE 1619 XTS-AES-128 vector 2');
saysAll(S.XTS.encrypt(rb(32), 5, rb(40)).trace, 'XTS');
for (let i = 0; i < 1000; i++) {
  const ks = i % 2 ? 64 : 32, k = rb(ks), tw = rb(16), d = rb(16 + ri(100)), want = createCipheriv(ks === 32 ? 'aes-128-xts' : 'aes-256-xts', k, tw).update(d);
  const got = S.XTS.encrypt(k, tw, d).out; t.eq(hex(got), want.toString('hex'), 'XTS vs node ' + i); t.eq(hex(S.XTS.decrypt(k, tw, got).out), hex(d), 'XTS decrypts ' + i);
}
const G = S.GCM, gk = fromHex('feffe9928665731c6d6a8f9467308308'), gp = fromHex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'), gaad = fromHex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
t.eq(hex(G.encrypt(new Uint8Array(16), new Uint8Array(12), new Uint8Array(0)).tag), '58e2fccefa7e3061367f1d57a4e7455a', 'GCM test case 1');
const g2 = G.encrypt(new Uint8Array(16), new Uint8Array(12), new Uint8Array(16)); t.eq([hex(g2.ct), hex(g2.tag)], ['0388dace60b6a392f328c2b971b2fe78', 'ab6e47d42cec13bdf53a67b21257bddf'], 'GCM test case 2'); t.eq(hex(g2.H), '66e94bd4ef8a2c3b884cfa59ca342b2e', 'GCM test case 2 H');
const g3 = G.encrypt(gk, fromHex('cafebabefacedbaddecaf888'), gp); t.eq([hex(g3.ct), hex(g3.tag)], ['42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985', '4d5c2af327cd64a62cf35abd2ba6fab4'], 'GCM test case 3');
const g4 = G.encrypt(gk, fromHex('cafebabefacedbaddecaf888'), gp.slice(0, 60), gaad); t.eq([hex(g4.ct).slice(-8), hex(g4.tag)], ['3d58e091', '5bc94fbc3221a5db94fae95ae7121a47'], 'GCM test case 4 (with AAD)');
const g5 = G.encrypt(gk, fromHex('cafebabefacedbad'), gp.slice(0, 60), gaad); t.eq([hex(g5.ct).slice(0, 32), hex(g5.tag)], ['61353b4c2806934a777ff51fa22a4755', '3612d2e79e3b0785561be14aaca2fccb'], 'GCM test case 5 (64-bit IV)');
saysAll(g4.trace, 'GCM'); t.ok(g4.trace.some((s) => s.kind === 'gcm-tag') && g4.trace.filter((s) => s.kind === 'ghash').length === 7, 'GCM traces each GHASH block and the tag');
t.eq(G.mulTrace(g4.H, g4.H).trace.length, 128, 'a traced GF(2^128) product has 128 bit steps');
t.ok(!G.decrypt(gk, fromHex('cafebabefacedbaddecaf888'), g4.ct, g4.tag.map((v, i) => (i ? v : v ^ 1)), gaad).ok, 'GCM rejects a changed tag');
for (let i = 0; i < 1500; i++) {
  const ks = [16, 24, 32][i % 3], k = rb(ks), iv = rb(i % 5 ? 12 : 1 + ri(40)), p = rb(ri(120)), aad = rb(ri(50));
  const c = createCipheriv(`aes-${ks * 8}-gcm`, k, iv); c.setAAD(aad); const ct = Buffer.concat([c.update(p), c.final()]), tag = c.getAuthTag();
  const r = G.encrypt(k, iv, p, aad, { trace: false });
  t.eq(hex(r.ct) + hex(r.tag), ct.toString('hex') + tag.toString('hex'), `aes-${ks * 8}-gcm vs node ${i}`);
  const dd = G.decrypt(k, iv, r.ct, r.tag, aad, { trace: false }); t.ok(dd.ok && hex(dd.pt) === hex(p), 'GCM decrypts ' + i);
  if (i < 60) { t.eq(hex(G.ghash(r.H, aad, r.ct).out), hex(S.GF.gcm.ghash(r.H, aad, r.ct)), 'GHASH agrees with S.GF.gcm.ghash ' + i); t.eq(hex(G.mul(iv.length === 12 ? r.H : r.J0, p.length >= 16 ? p.slice(0, 16) : r.H)), hex(S.GF.gcm.mul(iv.length === 12 ? r.H : r.J0, p.length >= 16 ? p.slice(0, 16) : r.H)), 'GF(2^128) product agrees ' + i); }
}
{ const F = S.GF128, x = S.GF.gcm.toPoly(rb(16)); t.eq(F.mul(x, F.inv(x)), 1n, 'GF(2^128) inverse'); t.eq(F.sqr(F.sqrt(x)), x, 'GF(2^128) square root'); }

// ---- the attack labs
const T = (a) => String.fromCharCode(...a);
for (let s = 1; s <= 30; s += 6) {
  const lab = S.OTP.setup({ seed: s }), x = S.bytes.xor(lab.c1, lab.c2), r = S.OTP.recover(x);
  const a = S.OTP.agreement(r.m1, r.m2, lab.m1, lab.m2); t.ok(a >= 0.9, `two-time pad, seed ${s}: ${(100 * a).toFixed(1)}% of both messages recovered`);
  const crib = T(lab.m1).split(' ').filter((w) => w.length >= 5)[0], at = T(lab.m1).indexOf(crib), cr = S.OTP.crib(x, crib);
  t.ok(cr.best.slice(0, 3).some((row) => row.pos === at), `crib '${crib}' found at ${at}, seed ${s}`);
  if (s === 1) { saysAll(r.trace, 'two-time pad'); saysAll(cr.trace, 'crib dragging'); }
}
for (let s = 1; s <= 3; s++) {
  const r0 = S.Sym.rng(s), key = S.Sym.bytes(r0, 90), ms = [0, 3, 6, 9].map((i) => utf8(S.OTP.MESSAGES[(i + s) % 12])), n = Math.min(...ms.map((m) => m.length));
  const r = S.OTP.recover(ms.map((m) => S.OTP.encrypt(m.slice(0, n), key).out), { beam: 60 });
  t.ok(r.messages.every((m, i) => T(m) === T(ms[i].slice(0, n))) && hex(r.pad) === hex(key.slice(0, n)), 'many-time pad: four messages and the pad, seed ' + s);
}
{ const m = utf8('attack at dawn'), k = rb(m.length), c = S.OTP.encrypt(m, k).out, other = utf8('retreat at six'); t.eq(T(S.OTP.encrypt(c, S.OTP.keyFor(c, other)).out), 'retreat at six', 'perfect secrecy: a key exists for every message'); }
for (let s = 1; s <= 3; s++) { const lab = S.Attacks.paddingOracle.setup({ seed: s }), r = S.Attacks.paddingOracle.attack(lab); t.ok(hex(r.pt) === hex(lab.secret) && r.queries === lab.queries() && r.queries < 256 * lab.ct.length, `padding oracle recovers the message, seed ${s} (${r.queries} queries)`); if (s === 1) saysAll(r.trace, 'padding oracle'); }
for (let s = 1; s <= 5; s++) { const e = S.Attacks.ecbCutPaste({ seed: s }), b = S.Attacks.cbcBitFlip({ seed: s }), c = S.Attacks.ctrNonceReuse({ seed: s }); t.ok(e.ok, 'ECB cut and paste, seed ' + s); t.ok(b.ok, 'CBC bit flipping, seed ' + s); t.ok(c.ok, 'CTR nonce reuse, seed ' + s); if (s === 1) { saysAll(e.trace, 'ECB cut and paste'); saysAll(b.trace, 'CBC bit flipping'); saysAll(c.trace, 'CTR nonce reuse'); } }
for (let s = 1; s <= 3; s++) { const g = S.Attacks.gcmForbidden({ seed: s }); t.ok(g.ok && g.accepted && g.candidates.some((c) => hex(c.H) === hex(g.trueH)), `GCM nonce reuse: H recovered and a forgery accepted, seed ${s}`); if (s === 1) saysAll(g.trace, 'GCM forbidden attack'); }
{
  // the Trivium topic's eSTREAM preset quotes the published keystream of set 1, vector 0 (38eb86ff730d7a9c…)
  const T = load(['core', 'stage', 'topics']), tp = T.byId('st-trivium'), pr = tp && tp.presets.find((p) => /eSTREAM/.test(p.label));
  t.ok(!!pr, 'the Trivium topic has an eSTREAM preset');
  if (pr) {
    const run = tp.run(T.inputOf(tp, Object.assign(T.inputOf(tp), pr.values))), last = run.frames[run.frames.length - 1].say;
    t.ok(last.includes('38 eb 86 ff 73 0d 7a 9c'), 'the eSTREAM preset shows the published keystream 38 eb 86 ff 73 0d 7a 9c: ' + last.slice(0, 120));
    const bits = run.frames.filter((f) => /^Clock \d+:/.test(f.say)).map((f) => +/output is z = ([01])/.exec(f.say)[1]);
    t.eq(bits, [0, 0, 0, 1, 1, 1, 0, 0].slice(0, bits.length), 'its first output bits are those of 0x38, lowest bit first');
  }
}
t.done();
