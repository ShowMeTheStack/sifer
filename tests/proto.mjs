// Protocols: X25519 against RFC 7748 and node; the TLS 1.3 key schedule against the example handshake of RFC 8448;
// the knowledge states of the key-distribution, Kerberos and Diffie–Hellman runs; certificate validation in every
// scenario; full TLS handshakes whose records node:crypto can open; every attack across seeds.
import { generateKeyPairSync, diffieHellman, createPrivateKey, createPublicKey, createDecipheriv } from 'node:crypto';
import { load, harness } from './load.mjs';
const S = load(['core']), t = harness('proto'), P = S.Proto, H = S.Hash, fh = H.fromHex, hex = H.hex;
const quick = process.argv.includes('--quick');

// ---- X25519
t.eq(hex(P.x25519Base(fh('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'))), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'RFC 7748 6.1 Alice public');
t.eq(hex(P.x25519Base(fh('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'))), 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'RFC 7748 6.1 Bob public');
t.eq(hex(P.x25519(fh('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'), fh('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'))), '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742', 'RFC 7748 6.1 shared secret');
t.eq(hex(P.x25519(fh('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'), fh('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'))), 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552', 'RFC 7748 5.2 first vector');
{
  let bad = 0;
  const raw = (k) => Buffer.from(k.export({ format: 'jwk' })[k.type === 'private' ? 'd' : 'x'], 'base64url');
  for (let i = 0; i < (quick ? 20 : 200); i++) {
    const a = generateKeyPairSync('x25519'), b = generateKeyPairSync('x25519');
    const ad = raw(a.privateKey), bx = raw(b.publicKey);
    if (hex(P.x25519Base(ad)) !== hex(raw(a.publicKey))) bad++;
    const want = diffieHellman({ privateKey: a.privateKey, publicKey: b.publicKey }).toString('hex');
    if (hex(P.x25519(ad, bx)) !== want || hex(P.x25519Own(ad, bx)) !== want) bad++;
  }
  t.eq(bad, 0, 'X25519 public keys and shared secrets against node (the curve engine and the built-in ladder)');
}

// RFC 8448 section 3, the handshake messages as published (ClientHello … client Finished)
const RFC8448 = {
  "ClientHello": '010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001',
  "ServerHello": '020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304',
  "EncryptedExtensions": '080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000',
  "Certificate": '0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000',
  "CertificateVerify": '0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3',
  "Finished": '140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718',
  "Finished2": '14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61',
};
// ---- the TLS 1.3 key schedule, RFC 8448 section 3 (simple 1-RTT handshake)
{
  const T = P.tls;
  const shared = P.x25519(fh('49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005'), fh('c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f'));
  t.eq(hex(shared), '8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d', 'RFC 8448 X25519 shared secret from the client private key and the server share');
  t.eq(hex(P.x25519Base(fh('b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e'))), 'c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f', 'RFC 8448 server key share');
  const ks = T.keySchedule({ shared, helloHash: fh('860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8'), serverFinishedHash: fh('9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13'), clientFinishedHash: fh('209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d') });
  const s = ks.secrets, want = {
    early: '33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a', derivedEarly: '6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba',
    handshake: '1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac', clientHs: 'b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21',
    serverHs: 'b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38', derivedHs: '43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4',
    master: '18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919', clientAp: '9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5',
    serverAp: 'a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643', exporter: 'fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50',
    resumption: '7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c',
  };
  for (const [k, v] of Object.entries(want)) t.eq(hex(s[k]), v, 'RFC 8448 ' + k + ' secret');
  const keys = (sec) => { const k = T.trafficKeys(sec, 16); return hex(k.key) + ' ' + hex(k.iv); };
  t.eq(keys(s.serverHs), '3fce516009c21727d0f2e4e86ee403bc 5d313eb2671276ee13000b30', 'RFC 8448 server handshake write key and IV');
  t.eq(keys(s.clientHs), 'dbfaa693d1762c5b666af5d950258d01 5bd3c71b836e0b76bb73265f', 'RFC 8448 client handshake write key and IV');
  t.eq(keys(s.serverAp), '9f02283b6c9c07efc26bb9f2ac92e356 cf782b88dd83549aadf1e984', 'RFC 8448 server application write key and IV');
  t.eq(keys(s.clientAp), '17422dda596ed5d9acd890e3c63f5051 5b78923dee08579033e523d9', 'RFC 8448 client application write key and IV');
  t.eq(hex(T.expandLabel(s.serverHs, 'finished', new Uint8Array(0), 32)), '008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8', 'RFC 8448 server finished key');
  t.eq(hex(T.hkdfLabel('key', new Uint8Array(0), 16)), '001009746c733133206b657900', 'HkdfLabel for "key", 16 bytes');
  // the transcript hashes from the published messages, and both Finished messages recomputed
  const sha = (...ms) => H.get('sha256').hash(H.concat(...ms.map((k) => fh(RFC8448[k]))));
  t.eq(hex(sha('ClientHello', 'ServerHello')), '860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8', 'RFC 8448 transcript hash through ServerHello');
  const upToCV = ['ClientHello', 'ServerHello', 'EncryptedExtensions', 'Certificate', 'CertificateVerify'];
  t.eq(hex(sha(...upToCV, 'Finished')), '9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13', 'RFC 8448 transcript hash through the server Finished');
  t.eq(hex(sha(...upToCV, 'Finished', 'Finished2')), '209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d', 'RFC 8448 transcript hash through the client Finished');
  t.eq(hex(S.MAC.hmac('sha256', T.expandLabel(s.serverHs, 'finished', new Uint8Array(0), 32), sha(...upToCV))), RFC8448.Finished.slice(8), 'RFC 8448 server Finished verify_data recomputed');
  t.eq(hex(S.MAC.hmac('sha256', T.expandLabel(s.clientHs, 'finished', new Uint8Array(0), 32), sha(...upToCV, 'Finished'))), RFC8448.Finished2.slice(8), 'RFC 8448 client Finished verify_data recomputed');
  t.ok(RFC8448.ClientHello.includes('99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c') && hex(P.x25519Base(fh('49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005'))) === '99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c', 'RFC 8448 client key share is in the ClientHello and matches its private key');
  t.eq(ks.trace.map((x) => x.kind), ['early', 'derived', 'handshake', 'hs-traffic', 'master', 'ap-traffic', 'resumption'], 'key schedule trace');
}

// ---- key distribution and Kerberos: knowledge states
const at = (res, i, who) => res.messages[i - 1].knows[who];
{
  const ns = P.needhamSchroeder({ seed: 3 });
  t.eq(ns.messages.length, 5, 'Needham–Schroeder: five messages'); t.ok(ns.ok, 'it completes');
  t.ok(!at(ns, 1, 'A').includes('Kab') && at(ns, 2, 'A').includes('Kab'), 'Alice learns Kab from message 2');
  t.ok(!at(ns, 2, 'B').includes('Kab') && at(ns, 3, 'B').includes('Kab'), 'Bob learns Kab from the ticket in message 3');
  t.ok(!at(ns, 5, 'A').includes('Kbs'), 'Alice never learns Bob\'s key');
  t.ok(ns.messages[1].wire[0].sealed && /^[0-9a-f]{80,}$/.test(ns.messages[1].wire[0].bytes), 'sealed terms carry real ciphertext');
  t.eq(ns.messages[1].keys.A.sort(), ['Kab', 'Kas'], 'keys known by Alice after message 2');
  for (let seed = 1; seed <= 3; seed++) {
    const rp = P.nsReplay({ seed });
    t.ok(rp.attack.success && rp.final.knows.E.includes('K′ab') && rp.final.knows.B.includes('Nb2−1'), 'replay: Bob accepts a key Eve knows, seed ' + seed);
    t.ok(!rp.final.knows.E.includes('Kab') && !rp.final.knows.E.includes('Kbs'), 'Eve never learns long-term keys');
    const fx = P.nsFixed({ seed }), fr = P.nsFixed({ seed, replay: true });
    t.ok(fx.ok && !fr.ok && fr.attack.success === false, 'the repaired protocol works, and rejects the replay, seed ' + seed);
  }
  const kb = P.kerberos({ seed: 2 });
  t.ok(kb.ok && kb.messages.length === 6, 'Kerberos flow completes in six messages');
  t.ok(kb.messages.every((m) => !/password/.test(m.content)), 'the password never crosses the network');
  t.ok(!kb.final.knows.V.includes('Kc') && !kb.final.knows.V.includes('Ktgs'), 'the service never learns the client or TGS keys');
  t.ok(kb.final.knows.C.includes('Kc,v') && kb.final.knows.V.includes('Kc,v') && kb.final.knows.TGS.includes('Kc,tgs'), 'session keys reach exactly the right parties');
  t.ok(!kb.final.knows.C.includes('Ktgs'), 'the client cannot read its own TGT');
  let threw = false; try { const r = P.run({ parties: [{ id: 'X', knows: [] }, { id: 'Y', knows: [] }] }); r.send('X', 'Y', [P.enc('K', 'secret')]); } catch (e) { threw = true; }
  t.ok(threw, 'a party cannot send what it does not know');
}

// ---- Diffie–Hellman, the man in the middle, authenticated DH
for (let seed = 1; seed <= (quick ? 2 : 5); seed++) {
  for (const group of ['x25519', 'toy64']) {
    const d = P.dh({ seed, group });
    t.ok(d.keysMatch && d.eveKnowsKey === false && d.final.knows.E.includes('g^a'), `DH ${group}: same key, Eve sees the shares only (seed ${seed})`);
    const m = P.dhMitm({ seed, group });
    t.ok(m.attack.success && m.values.kA !== m.values.kB, `MITM ${group}: Mallory reads and rewrites; Alice and Bob hold different keys (seed ${seed})`);
  }
}
for (let seed = 1; seed <= (quick ? 1 : 3); seed++) {
  const au = P.dhAuth({ seed, bits: 768 }), am = P.dhAuth({ seed, bits: 768, mitm: true });
  t.ok(au.ok, 'authenticated DH completes, seed ' + seed);
  t.ok(!am.ok && am.attack.success === false && am.steps.some((s) => s.type === 'check' && !s.ok && s.party === 'A'), 'the substitution is caught by Alice, seed ' + seed);
}

// ---- certificates
for (let seed = 1; seed <= (quick ? 1 : 2); seed++) {
  for (const sc of P.CERT_SCENARIOS) {
    const c = P.certScenario(sc, { seed, bits: 768 });
    t.eq(c.result.ok, sc === 'valid', `certificate scenario ${sc}, seed ${seed}`);
  }
  const v = P.certScenario('valid', { seed, bits: 768 });
  t.ok(v.result.checks.filter((c) => c.what === 'signature').length === 3 && v.result.checks.some((c) => c.what === 'anchor' && c.ok), 'three signatures and an anchor checked');
  const fake = P.certScenario('fake', { seed, bits: 768 });
  t.eq(fake.result.checks.find((c) => !c.ok).what, 'signature', 'the fake fails on its signature');
  t.ok(P.certScenario('valid', { seed, bits: 768, now: '2026-02-01' }).result.ok === false, 'not yet valid is rejected');
  const crlOk = P.validateChain([v.pki.leaf, v.pki.inter, v.pki.root], { trustStore: v.pki.trustStore, crl: v.pki.crl, now: '2026-06-01' });
  t.ok(crlOk.ok && crlOk.checks.some((c) => c.what === 'crl'), 'a CRL without the serial passes');
}

// ---- TLS 1.3 handshakes, with node opening the records
for (let seed = 1; seed <= (quick ? 1 : 4); seed++) {
  const r = P.tls13({ seed, bits: 768 });
  t.ok(r.ok && r.checks.every((c) => c.ok), 'TLS 1.3 handshake completes, seed ' + seed);
  t.eq(r.messages.map((m) => m.label), ['ClientHello', 'ServerHello', 'EncryptedExtensions', 'Certificate', 'CertificateVerify', 'Finished (server)', 'Finished (client)', 'Application data', 'Application data'], 'message order');
  const app = r.records.find((x) => x.label === 'application data' && x.dir === 'C→S'), w = fh(app.wire);
  const d = createDecipheriv('chacha20-poly1305', fh(r.keys.clientAp.key), fh(app.nonce), { authTagLength: 16 });
  d.setAAD(w.subarray(0, 5), { plaintextLength: w.length - 21 }); d.setAuthTag(w.subarray(w.length - 16));
  const pt = Buffer.concat([d.update(w.subarray(5, w.length - 16)), d.final()]);
  t.ok(pt.toString('latin1').startsWith('GET /balance') && pt[pt.length - 1] === 23, 'node opens the application record with the derived key and nonce');
  const fin = r.records.find((x) => x.label === 'Finished (server)');
  t.eq(fin.nonce, hex(P.tls.nonce(fh(r.keys.serverHs.iv), 3)), 'the fourth server record uses iv ⊕ 3');
  t.ok(!r.final.knows.E.includes('handshake keys') && !r.final.knows.E.includes('application keys') && r.final.knows.E.includes('g^c'), 'the eavesdropper has the shares and no keys');
  for (const tp of ['cert', 'finished', 'record']) t.ok(!P.tls13({ seed, bits: 768, tamper: tp }).ok, `tampering with the ${tp} is caught, seed ${seed}`);
}
t.done();
