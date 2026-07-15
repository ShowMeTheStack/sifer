// Hashes, hash attacks and MACs: published vectors (FIPS 180-4, RFC 1321, FIPS 202, RFC 2202, RFC 4231, RFC 4493,
// RFC 8439, RFC 5869, RFC 6070, SP 800-38D) and node:crypto over many random inputs; every attack across seeds.
import { createHash, createHmac, hkdfSync, pbkdf2Sync, createCipheriv, randomBytes } from 'node:crypto';
import { load, harness } from './load.mjs';
const S = load(['core']), t = harness('hashmac'), H = S.Hash, M = S.MAC;
const hex = H.hex, fh = H.fromHex, u = (s) => new TextEncoder().encode(s);
const quick = process.argv.includes('--quick');
const N = quick ? 60 : 1000;

// ---- FIPS 180-4, RFC 1321 and FIPS 202 example messages
const ABC = 'abc', TWO = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
const T896 = 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu';
const V = [
  ['sha1', ABC, 'a9993e364706816aba3e25717850c26c9cd0d89d'], ['sha1', TWO, '84983e441c3bd26ebaae4aa1f95129e5e54670f1'],
  ['sha224', ABC, '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'], ['sha224', TWO, '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525'],
  ['sha256', ABC, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'], ['sha256', TWO, '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'],
  ['sha384', ABC, 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'],
  ['sha384', T896, '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039'],
  ['sha512', ABC, 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'],
  ['sha512', T896, '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909'],
  ['sha512-256', ABC, '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23'], ['sha512-256', T896, '3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a'],
  ['md5', '', 'd41d8cd98f00b204e9800998ecf8427e'], ['md5', 'a', '0cc175b9c0f1b6a831c399e269772661'], ['md5', ABC, '900150983cd24fb0d6963f7d28e17f72'],
  ['md5', 'message digest', 'f96b697d7cb7938d525a2f31aaf161d0'], ['md5', 'abcdefghijklmnopqrstuvwxyz', 'c3fcd3d76192e4007dfb496cca67e13b'],
  ['md5', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 'd174ab98d277d9f5a5611c2c9f419d9f'], ['md5', '1234567890'.repeat(8), '57edf4a22be3c955ac49da2e2107b67a'],
  ['sha3-224', '', '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7'], ['sha3-256', '', 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'],
  ['sha3-384', '', '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004'],
  ['sha3-512', '', 'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26'],
  ['sha3-224', ABC, 'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf'], ['sha3-256', ABC, '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'],
  ['sha3-384', ABC, 'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25'],
  ['sha3-512', ABC, 'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0'],
];
for (const [h, m, d] of V) t.eq(hex(H.get(h).hash(u(m))), d, `${h}(${m.slice(0, 12)}…) published vector`);
t.eq(hex(H.get('sha1').hash(new Uint8Array(1e6).fill(97))), '34aa973cd4c4daa4f61eeb2bdbad27316534016f', 'SHA-1 of a million a');
t.eq(hex(H.shake128(new Uint8Array(0), 32)), '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26', 'SHAKE128 empty, 256 bits');
t.eq(hex(H.shake256(new Uint8Array(0), 64)), '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be', 'SHAKE256 empty, 512 bits');
// the constants come from the primes, and agree with the table in sha256.js
t.eq(H.SHA2.K256, S.SHA256.K, 'SHA-256 K from cube roots'); t.eq(H.SHA2.IV256, S.SHA256.IV, 'SHA-256 IV from square roots');
t.eq(H.SHA2.h16([H.SHA2.K512[158], H.SHA2.K512[159]]), '6c44198c4a475817', 'SHA-512 K79'); t.eq(H.SHA2.h16([H.SHA2.IV512_256[0], H.SHA2.IV512_256[1]]), '22312194fc2bf72c', 'SHA-512/256 IV H0');
t.eq(H.h8(H.SHA2.IV224[0]), 'c1059ed8', 'SHA-224 IV H0');

// ---- node:crypto, random lengths across block boundaries
const NODE = { md5: 'md5', sha1: 'sha1', sha224: 'sha224', sha256: 'sha256', sha384: 'sha384', sha512: 'sha512', 'sha512-256': 'sha512-256', 'sha3-224': 'sha3-224', 'sha3-256': 'sha3-256', 'sha3-384': 'sha3-384', 'sha3-512': 'sha3-512' };
for (const [k, n] of Object.entries(NODE)) {
  let bad = 0;
  for (let i = 0; i < N; i++) { const m = randomBytes(i < 300 ? i : (Math.random() * 700) | 0); if (hex(H.get(k).hash(m)) !== createHash(n).update(m).digest('hex')) bad++; }
  t.eq(bad, 0, `${k} against node over ${N} random messages`);
}
for (const [bits, rate] of [[128, 168], [256, 136]]) {
  let bad = 0;
  for (let i = 0; i < N / 2; i++) { const m = randomBytes((Math.random() * 400) | 0), L = 1 + ((Math.random() * 2.5 * rate) | 0); if (hex(H['shake' + bits](m, L)) !== createHash('shake' + bits, { outputLength: L }).update(m).digest('hex')) bad++; }
  t.eq(bad, 0, `SHAKE${bits} against node, outputs longer than the rate included`);
}
// traces: the Merkle–Damgård run and the sponge
{
  const r = H.get('sha256').run(u(TWO), { trace: true, rounds: true });
  t.eq(r.blocks.length, 2, 'two-block message has two compressions'); t.ok(r.blocks[1].lengthBlock, 'the last block carries the length');
  t.eq(H.h8(r.chain[1][0]), '85e655d6', 'FIPS 180-4 two-block example: H0 after block 1');
  t.eq(r.chain.length, 3, 'IV and two chaining values'); t.eq(r.trace.map((s) => s.kind), ['pad', 'iv', 'compress', 'compress', 'output'], 'MD trace kinds');
  const s1 = H.get('sha1').run(u(ABC), { rounds: true });
  t.eq(H.h8(s1.blocks[0].rounds[79].regs[0]), '42541b35', 'FIPS 180-4 SHA-1 abc: a after t = 79');
  const m5 = H.get('md5').run(u(ABC), { rounds: true }); t.eq(m5.blocks[0].rounds.length, 64, 'MD5 keeps 64 steps');
  const s5 = H.get('sha512').run(u(ABC), { rounds: true }); t.eq(s5.blocks[0].rounds[79].regs[0], '73a54f399fa4b1b2', 'FIPS 180-4 SHA-512 abc: a after t = 79');
  const sp = H.get('sha3-256').run(u('x'.repeat(300)), { trace: true, steps: true });
  t.eq(sp.absorbs.length, 3, '300 bytes at rate 136: three absorbs'); t.eq(sp.absorbs[0].rounds.length, 24, 'per-step rounds for the first permutation');
  const lastRound = sp.absorbs[0].rounds[23].iota.A;
  t.eq(lastRound.map((v) => v.toString(16).padStart(16, '0')), sp.absorbs[0].after, 'the teaching Keccak and the fast one agree on the first permutation');
  const sh = H.SHA3.shake(128, u('a'), 400, { trace: true }); t.eq(sh.squeezes.length, 3, '400 bytes at rate 168: three squeezes');
  const md = H.get('sha1').pad(new Uint8Array(55)); t.eq(md.padded.length, 64, '55 bytes pad to one block'); t.eq(H.get('sha1').pad(new Uint8Array(56)).padded.length, 128, '56 bytes need two');
}

// ---- HMAC: RFC 2202 and RFC 4231, then node
const k20 = new Uint8Array(20).fill(0x0b), kaa = new Uint8Array(131).fill(0xaa);
const HM = [
  ['sha1', k20, 'Hi There', 'b617318655057264e28bc0b6fb378c8ef146be00'], ['sha1', 'Jefe', 'what do ya want for nothing?', 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79'],
  ['sha1', new Uint8Array(20).fill(0xaa), new Uint8Array(50).fill(0xdd), '125d7342b9ac11cd91a39af48aa17b4f63f175d3'],
  ['md5', new Uint8Array(16).fill(0x0b), 'Hi There', '9294727a3638bb1c13f48ef8158bfc9d'], ['md5', 'Jefe', 'what do ya want for nothing?', '750c783e6ab0b503eaa86e310a5db738'],
  ['sha224', k20, 'Hi There', '896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22'], ['sha256', k20, 'Hi There', 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'],
  ['sha384', k20, 'Hi There', 'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6'],
  ['sha512', k20, 'Hi There', '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854'],
  ['sha256', 'Jefe', 'what do ya want for nothing?', '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'],
  ['sha256', kaa, 'Test Using Larger Than Block-Size Key - Hash Key First', '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54'],
  ['sha512', kaa, 'Test Using Larger Than Block-Size Key - Hash Key First', '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598'],
  ['sha256', kaa, 'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.', '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2'],
];
for (const [h, k, m, d] of HM) t.eq(hex(M.hmac(h, k, m)), d, `HMAC-${h} published vector (${typeof m === 'string' ? m.slice(0, 10) : 'bytes'})`);
for (const h of Object.keys(NODE)) {
  let bad = 0;
  for (let i = 0; i < N / 4; i++) { const k = randomBytes((Math.random() * 200) | 0), m = randomBytes((Math.random() * 300) | 0); if (hex(M.hmac(h, k, m)) !== createHmac(NODE[h], k).update(m).digest('hex')) bad++; }
  t.eq(bad, 0, `HMAC-${h} against node, keys shorter and longer than the block`);
}
{
  const r = M.hmacTrace('sha256', kaa, 'x');
  t.eq(r.trace.map((s) => s.kind), ['key-hash', 'key-pad', 'ipad', 'inner', 'opad', 'outer'], 'HMAC trace with a long key');
  t.eq(hex(r.tag), hex(M.hmac('sha256', kaa, 'x')), 'traced HMAC = HMAC');
}

// ---- HKDF (RFC 5869) and PBKDF2 (RFC 6070)
{
  const salt = fh('000102030405060708090a0b0c'), info = fh('f0f1f2f3f4f5f6f7f8f9');
  const r = M.hkdf('sha256', new Uint8Array(22).fill(0x0b), salt, info, 42, { trace: true });
  t.eq(hex(r.prk), '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5', 'RFC 5869 case 1 PRK');
  t.eq(hex(r.okm), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865', 'RFC 5869 case 1 OKM');
  t.eq(hex(M.hkdfExtract('sha256', null, new Uint8Array(22).fill(0x0b))), '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04', 'RFC 5869 case 3 PRK (no salt)');
  t.eq(hex(M.hkdf('sha256', new Uint8Array(22).fill(0x0b), null, null, 42)), '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8', 'RFC 5869 case 3 OKM');
  t.eq(hex(M.hkdf('sha1', new Uint8Array(11).fill(0x0b), salt, info, 42)), '085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896', 'RFC 5869 case 4 (SHA-1) OKM');
  let bad = 0;
  for (let i = 0; i < N / 4; i++) {
    const h = ['sha256', 'sha512', 'sha1', 'sha384'][i % 4], ikm = randomBytes(1 + ((Math.random() * 80) | 0)), sa = randomBytes((Math.random() * 40) | 0), inf = randomBytes((Math.random() * 30) | 0), L = 1 + ((Math.random() * 200) | 0);
    if (hex(M.hkdf(h, ikm, sa, inf, L)) !== Buffer.from(hkdfSync(h, ikm, sa, inf, L)).toString('hex')) bad++;
  }
  t.eq(bad, 0, 'HKDF against node hkdfSync');
}
{
  const P = [['password', 'salt', 1, 20, '0c60c80f961f0e71f3a9b524af6012062fe037a6'], ['password', 'salt', 2, 20, 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'], ['password', 'salt', 4096, 20, '4b007901b765489abead49d926f721d065a429c1'],
    ['passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25, '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'], ['pass\0word', 'sa\0lt', 4096, 16, '56fa6aa75548099dcc37d7f03425e0c3']];
  for (const [p, s, c, L, d] of P) t.eq(hex(M.pbkdf2('sha1', p, s, c, L)), d, `RFC 6070 PBKDF2-HMAC-SHA1 c = ${c}, ${L} bytes`);
  let bad = 0;
  for (let i = 0; i < N / 10; i++) { const h = ['sha256', 'sha1', 'sha512'][i % 3], p = randomBytes((Math.random() * 90) | 0), s = randomBytes((Math.random() * 20) | 0), c = 1 + ((Math.random() * 20) | 0), L = 1 + ((Math.random() * 100) | 0); if (hex(M.pbkdf2(h, p, s, c, L)) !== pbkdf2Sync(p, s, c, L, h).toString('hex')) bad++; }
  t.eq(bad, 0, 'PBKDF2 against node pbkdf2Sync');
  const tr = M.pbkdf2('sha256', 'hunter', 'pepper', 10, 32, { trace: true }); t.ok(tr.trace.some((s) => s.kind === 'more'), 'PBKDF2 trace elides the middle');
}

// ---- CBC-MAC, CMAC (RFC 4493), GMAC
const K = fh('2b7e151628aed2a6abf7158809cf4f3c');
{
  const sk = M.cmacSubkeys(K);
  t.eq(hex(sk.L), '7df76b0c1ab899b33e42f047b91b546f', 'RFC 4493 L'); t.eq(hex(sk.K1), 'fbeed618357133667c85e08f7236a8de', 'RFC 4493 K1'); t.eq(hex(sk.K2), 'f7ddac306ae266ccf90bc11ee46d513b', 'RFC 4493 K2');
  const msg = fh('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710');
  t.eq(hex(M.cmac(K, msg.slice(0, 0))), 'bb1d6929e95937287fa37d129b756746', 'RFC 4493 example 1 (empty)');
  t.eq(hex(M.cmac(K, msg.slice(0, 16))), '070a16b46b4d4144f79bdd9dd04a287c', 'RFC 4493 example 2 (16 bytes)');
  t.eq(hex(M.cmac(K, msg.slice(0, 40))), 'dfa66747de9ae63030ca32611497c827', 'RFC 4493 example 3 (40 bytes)');
  t.eq(hex(M.cmac(K, msg)), '51f0bebf7e3b9d92fc49741779363cfe', 'RFC 4493 example 4 (64 bytes)');
  t.eq(hex(M.cmac(K, msg.slice(0, 40), { trace: true }).tag), 'dfa66747de9ae63030ca32611497c827', 'traced CMAC');
  let bad = 0;
  for (let i = 0; i < Math.min(N, 200); i++) {
    const k = randomBytes(16), m = randomBytes(16 * (1 + ((Math.random() * 5) | 0)));
    const c = createCipheriv('aes-128-cbc', k, Buffer.alloc(16)); c.setAutoPadding(false);
    const ct = Buffer.concat([c.update(m), c.final()]);
    if (hex(M.cbcMac(k, m)) !== ct.subarray(-16).toString('hex')) bad++;
  }
  t.eq(bad, 0, 'CBC-MAC against node AES-128-CBC with a zero IV');
  for (let seed = 0; seed < 6; seed++) {
    const k = randomBytes(16), m1 = randomBytes(16 * (1 + seed % 3)), m2 = randomBytes(16 * (1 + (seed + 1) % 3));
    const f = M.cbcMacForge({ key: k, m1, m2 });
    t.ok(f.ok && hex(M.cbcMac(k, f.forged)) === hex(f.tag), 'CBC-MAC variable-length forgery ' + seed);
    t.ok(!M.cbcMacForge({ key: k, m1, m2, mac: 'cmac' }).ok, 'the same splice fails under CMAC ' + seed);
  }
  t.ok(M.cbcMacForgeOne(K, u('Pay Mira 50 euro')).ok, 'one-block forgery m ‖ (m ⊕ t)');
}
{
  t.eq(hex(M.gmac(new Uint8Array(16), new Uint8Array(12), new Uint8Array(0))), '58e2fccefa7e3061367f1d57a4e7455a', 'SP 800-38D test case 1 tag (empty data)');
  let bad = 0;
  for (let i = 0; i < Math.min(N, 150); i++) {
    const k = randomBytes(16), iv = randomBytes(12), aad = randomBytes((Math.random() * 90) | 0);
    const c = createCipheriv('aes-128-gcm', k, iv); c.setAAD(aad); c.final();
    if (hex(M.gmac(k, iv, aad)) !== c.getAuthTag().toString('hex')) bad++;
  }
  t.eq(bad, 0, 'GMAC against node AES-128-GCM with no plaintext');
}

// ---- Poly1305 and ChaCha20-Poly1305 (RFC 8439)
{
  const pk = fh('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
  const r = M.poly1305(pk, u('Cryptographic Forum Research Group'), { trace: true });
  t.eq(hex(r.tag), 'a8061dc1305136c6c22b8baf0c0127a9', 'RFC 8439 2.5.2 Poly1305 tag');
  t.eq(r.r.toString(16), '806d5400e52447c036d555408bed685', 'RFC 8439 2.5.2 clamped r'); t.eq(r.steps.length, 3, 'three chunks');
  t.eq(r.steps[0].acc.toString(16), '2c88c77849d64ae9147ddeb88e69c83fc', 'RFC 8439 2.5.2 accumulator after block 1');
  const key = fh('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'), nonce = fh('070000004041424344454647'), aad = fh('50515253c0c1c2c3c4c5c6c7');
  const pt = u("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  const s = M.aead.seal(key, nonce, pt, aad, { trace: true });
  t.eq(hex(s.otk), '7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff', 'RFC 8439 2.8.2 one-time key');
  t.eq(hex(s.ciphertext), 'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116', 'RFC 8439 2.8.2 ciphertext');
  t.eq(hex(s.tag), '1ae10b594f09e26a7e902ecbd0600691', 'RFC 8439 2.8.2 tag');
  const o = M.aead.open(key, nonce, s.ciphertext, s.tag, aad); t.ok(o.ok && H.eq(o.plaintext, pt), 'AEAD opens');
  const bad1 = s.ciphertext.slice(); bad1[5] ^= 1; t.ok(!M.aead.open(key, nonce, bad1, s.tag, aad).ok, 'one flipped bit is rejected');
  t.ok(!M.aead.open(key, nonce, s.ciphertext, s.tag, u('other')).ok, 'different AAD is rejected');
  let bad = 0;
  for (let i = 0; i < Math.min(N, 400); i++) {
    const k = randomBytes(32), n = randomBytes(12), a = randomBytes((Math.random() * 40) | 0), p = randomBytes((Math.random() * 300) | 0);
    const c = createCipheriv('chacha20-poly1305', k, n, { authTagLength: 16 }); c.setAAD(a, { plaintextLength: p.length });
    const ct = Buffer.concat([c.update(p), c.final()]), tg = c.getAuthTag(), mine = M.aead.seal(k, n, p, a);
    if (hex(mine.ciphertext) !== ct.toString('hex') || hex(mine.tag) !== tg.toString('hex')) bad++;
  }
  t.eq(bad, 0, 'ChaCha20-Poly1305 against node');
}

// ---- comparisons
{
  t.ok(M.equal(u('abcd'), u('abcd')) && !M.equal(u('abcd'), u('abce')) && !M.equal(u('ab'), u('abc')), 'constant-time equality');
  for (let seed = 1; seed <= 4; seed++) {
    const secret = randomBytes(8);
    const r = M.timingAttack((g) => M.leakyEqual(secret, g), 8);
    t.eq(hex(r.tag), hex(secret), 'timing attack reads the tag through the leaky compare ' + seed);
    t.ok(r.queries <= 8 * 256, 'at most 256 queries a byte');
  }
}

// ---- attacks, across seeds
for (let seed = 1; seed <= (quick ? 3 : 8); seed++) {
  for (const bits of [16, 20, 24, 28]) {
    const r = H.birthday({ bits, seed, hash: seed % 2 ? 'sha256' : 'sha1' });
    const f = H.get(seed % 2 ? 'sha256' : 'sha1').hash;
    t.ok(r.found && !H.eq(r.a, r.b) && H.truncate(f(r.a), bits) === H.truncate(f(r.b), bits), `birthday collision at ${bits} bits, seed ${seed}`);
    t.ok(r.tries < 8 * r.expected, `birthday tries within reason at ${bits} bits`);
  }
  const rr = H.rho({ bits: 24, seed });
  const f = H.get('sha256').hash;
  t.ok(rr.found && !H.eq(rr.ma, rr.mb) && H.truncate(f(rr.ma), 24) === H.truncate(f(rr.mb), 24), 'rho collision with no table, seed ' + seed);
  t.ok(rr.path === null || rr.path.length === rr.mu + rr.lambda + 1, 'rho path covers tail and cycle');
  const sp = H.secondPreimage({ bits: 12, seed });
  t.ok(sp.found && !H.eq(sp.m, sp.target) && H.truncate(f(sp.m), 12) === H.truncate(f(sp.target), 12), 'second preimage at 12 bits, seed ' + seed);
  const j = H.joux({ bits: 20, t: 4 + (seed % 3), seed }), ms = j.messages();
  t.ok(ms.length === 2 ** j.t && new Set(ms.map(hex)).size === ms.length && new Set(ms.map((m) => j.toy.hashValue(m))).size === 1, `Joux ${2 ** j.t}-way multicollision, seed ${seed}`);
  for (const h of ['sha256', 'sha1', 'md5', 'sha512']) {
    const secret = randomBytes(5 + seed * 3), ext = u('&admin=yes&id=' + seed);
    const r = H.lengthExtension({ hash: h, secret, msg: u('user=asha&quota=10'), ext });
    t.ok(r.ok && r.secretLen === secret.length && hex(H.secretPrefixMac(h, secret, r.forged)) === hex(r.tag), `length extension on ${h}, seed ${seed}`);
    t.ok(hex(r.forged.slice(-ext.length)) === hex(ext), 'the forged message ends with the attacker\'s text');
  }
  // HMAC is not extendable: the same forgery recipe against an HMAC tag fails
  const key = randomBytes(16), tag = M.hmac('sha256', key, 'user=asha');
  const f2 = H.lengthExtend({ hash: 'sha256', tag, msg: 'user=asha', secretLen: 64, ext: '&admin=yes' });
  t.ok(hex(M.hmac('sha256', key, f2.forged)) !== hex(f2.tag), 'length extension fails against HMAC ' + seed);
}
{
  const c = H.birthday({ bits: 16, count: 3000, seed: 9 });
  t.ok(Math.abs(c.measured - c.expected) < 5 * Math.sqrt(c.expected), `measured collision count ${c.measured} near expected ${c.expected.toFixed(1)}`);
  t.ok(!quick ? H.birthday({ bits: 32, seed: 5 }).found : true, '32-bit birthday collision');
  let threw = false; try { H.lengthExtend({ hash: 'sha3-256', tag: new Uint8Array(32), msg: 'a', secretLen: 1, ext: 'b' }); } catch (e) { threw = true; }
  t.ok(threw, 'SHA-3 refuses: a sponge does not output its whole state');
}
t.done();
