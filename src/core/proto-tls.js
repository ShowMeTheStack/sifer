// A TLS 1.3 handshake, simplified in its byte encoding but faithful in its logic: ClientHello and ServerHello
// with X25519 key shares, the HKDF key schedule (early, handshake and master secrets, the traffic secrets and the
// keys and IVs drawn from them), the server's EncryptedExtensions, Certificate, CertificateVerify and Finished
// under the handshake keys, the client's Finished, then application data, each record sealed with
// ChaCha20-Poly1305 and a per-record nonce. The key schedule itself is exact (RFC 8446 section 7) and is tested
// against the example handshake of RFC 8448.
//   S.Proto.tls.expandLabel(secret, label, context, length) / deriveSecret(secret, label, transcriptHash)
//   S.Proto.tls.keySchedule({shared, helloHash, serverFinishedHash, clientFinishedHash, psk}) -> {secrets, trace}
//   S.Proto.tls.trafficKeys(secret[, keyLen 32]) -> {key, iv}
//   S.Proto.tls13({seed, host, message, tamper}) -> result: message-sequence data plus {schedule, records, transcript,
//       checks, ok}; tamper: 'cert' | 'finished' | 'record' to see each one caught
(function (S) {
  'use strict';
  const Pr = (S.Proto = S.Proto || {});
  const H = S.Hash, { step, hex, utf8, concat } = H;
  const T = (Pr.tls = {});
  const sha = (m) => H.get('sha256').hash(m);
  const M = () => S.MAC;
  const u16 = (n) => Uint8Array.of(n >> 8, n & 255);

  T.hkdfLabel = (label, context, length) => {
    const l = utf8('tls13 ' + label);
    return concat(u16(length), Uint8Array.of(l.length), l, Uint8Array.of(context.length), context);
  };
  T.expandLabel = (secret, label, context, length) => M().hkdfExpand('sha256', secret, T.hkdfLabel(label, context, length), length);
  T.deriveSecret = (secret, label, hash) => T.expandLabel(secret, label, hash, 32);
  T.trafficKeys = (secret, keyLen = 32) => ({ key: T.expandLabel(secret, 'key', new Uint8Array(0), keyLen), iv: T.expandLabel(secret, 'iv', new Uint8Array(0), 12) });

  T.keySchedule = (o) => {
    const zero = new Uint8Array(32), emptyHash = sha(new Uint8Array(0)), trace = [];
    const s = {};
    s.early = M().hkdfExtract('sha256', zero, o.psk || zero);
    trace.push(step('early', `Early secret = HKDF-Extract(0, ${o.psk ? 'PSK' : '0 (no pre-shared key)'}) = ${hex(s.early)}.`, { secret: s.early }));
    s.derivedEarly = T.deriveSecret(s.early, 'derived', emptyHash);
    trace.push(step('derived', `Derive-Secret(early, "derived", "") = ${hex(s.derivedEarly)}, the salt for the next stage.`, {}));
    s.handshake = M().hkdfExtract('sha256', s.derivedEarly, o.shared);
    trace.push(step('handshake', `Handshake secret = HKDF-Extract(that salt, the X25519 shared secret ${H.short(o.shared, 8)}) = ${hex(s.handshake)}.`, { secret: s.handshake }));
    s.clientHs = T.deriveSecret(s.handshake, 'c hs traffic', o.helloHash);
    s.serverHs = T.deriveSecret(s.handshake, 's hs traffic', o.helloHash);
    trace.push(step('hs-traffic', `With the hash of ClientHello ‖ ServerHello (${H.short(o.helloHash, 8)}): client handshake traffic secret ${hex(s.clientHs)}, server ${hex(s.serverHs)}.`, {}));
    s.derivedHs = T.deriveSecret(s.handshake, 'derived', emptyHash);
    s.master = M().hkdfExtract('sha256', s.derivedHs, zero);
    trace.push(step('master', `Master secret = HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0) = ${hex(s.master)}.`, { secret: s.master }));
    if (o.serverFinishedHash) {
      s.clientAp = T.deriveSecret(s.master, 'c ap traffic', o.serverFinishedHash);
      s.serverAp = T.deriveSecret(s.master, 's ap traffic', o.serverFinishedHash);
      s.exporter = T.deriveSecret(s.master, 'exp master', o.serverFinishedHash);
      trace.push(step('ap-traffic', `With the transcript hash through the server's Finished: client application traffic secret ${hex(s.clientAp)}, server ${hex(s.serverAp)}.`, {}));
    }
    if (o.clientFinishedHash) {
      s.resumption = T.deriveSecret(s.master, 'res master', o.clientFinishedHash);
      trace.push(step('resumption', `Resumption master secret (for a later PSK) = ${hex(s.resumption)}.`, {}));
    }
    return { secrets: s, trace };
  };

  // ---- records: AEAD with nonce = iv ⊕ sequence number, additional data = the record header
  const nonceFor = (iv, seq) => { const n = Uint8Array.from(iv); for (let i = 0; i < 8; i++) n[11 - i] ^= Number((BigInt(seq) >> BigInt(8 * i)) & 255n); return n; };
  T.nonce = nonceFor;
  T.seal = (keys, seq, type, content) => {
    const inner = concat(content, Uint8Array.of(type)), len = inner.length + 16;
    const header = Uint8Array.of(0x17, 0x03, 0x03, len >> 8, len & 255);
    const r = M().aead.seal(keys.key, nonceFor(keys.iv, seq), inner, header);
    return { header, ciphertext: r.ciphertext, tag: r.tag, nonce: nonceFor(keys.iv, seq), wire: concat(header, r.ciphertext, r.tag) };
  };
  T.open = (keys, seq, rec) => {
    const r = M().aead.open(keys.key, nonceFor(keys.iv, seq), rec.ciphertext, rec.tag, rec.header);
    if (!r.ok) return null;
    let end = r.plaintext.length - 1;
    while (end > 0 && r.plaintext[end] === 0) end--;
    return { type: r.plaintext[end], content: r.plaintext.slice(0, end) };
  };
  // handshake messages: type, 3-byte length, body (the bodies here are a readable stand-in for the real structures)
  const HS = { client_hello: 1, server_hello: 2, encrypted_extensions: 8, certificate: 11, certificate_verify: 15, finished: 20 };
  const msg = (type, body) => concat(Uint8Array.of(HS[type], 0, body.length >> 8, body.length & 255), body);

  Pr.tls13 = (o = {}) => {
    const seed = o.seed === undefined ? 1 : o.seed, rng = H.rng('tls' + seed), host = o.host || 'www.harbourbank.example';
    const P = Pr.pki({ seed, bits: o.bits });
    const { atom: a, enc } = Pr;
    const r = Pr.run({
      title: 'TLS 1.3 handshake', seed,
      parties: [
        { id: 'C', label: 'Client', knows: [a('c', 'secret'), a('g^c', 'public'), a('root CA key', 'public'), a('Nc', 'nonce'), a('transcript', 'data'), a('client Finished', 'data'), a('request', 'data')] },
        { id: 'S', label: 'Server', knows: [a('s', 'secret'), a('g^s', 'public'), a('server cert', 'public'), a('server signing key', 'key'), a('Ns', 'nonce'), a('transcript', 'data'), a('extensions', 'data'), a('server Finished', 'data'), a('response', 'data')] },
        { id: 'E', label: 'Eavesdropper', role: 'eavesdropper', knows: [] },
      ],
    });
    const checks = [], records = [];
    const transcript = [];
    const th = () => sha(concat(...transcript));
    // ClientHello
    const cPriv = rng.bytes(32), cPub = Pr.x25519Base(cPriv), cRand = rng.bytes(32);
    const ch = msg('client_hello', concat(cRand, utf8(`|suites=TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_GCM_SHA256|group=x25519|sni=${host}|share=`), cPub));
    transcript.push(ch);
    r.send('C', 'S', [a('Nc'), a('g^c')], { label: 'ClientHello', note: `Client random, cipher suites, the X25519 key share and the server name ${host}; one round trip, because the client guesses the group`, values: { random: hex(cRand), keyShare: hex(cPub) } });
    // ServerHello
    const sPriv = rng.bytes(32), sPub = Pr.x25519Base(sPriv), sRand = rng.bytes(32);
    const sh = msg('server_hello', concat(sRand, utf8('|suite=TLS_CHACHA20_POLY1305_SHA256|group=x25519|share='), sPub));
    transcript.push(sh);
    r.send('S', 'C', [a('Ns'), a('g^s')], { label: 'ServerHello', note: 'Server random, the chosen suite and its key share: everything after this is encrypted', values: { random: hex(sRand), keyShare: hex(sPub) } });
    const sharedS = Pr.x25519(sPriv, cPub), sharedC = Pr.x25519(cPriv, sPub);
    const helloHash = th();
    const ksS = T.keySchedule({ shared: sharedS, helloHash }), ksC = T.keySchedule({ shared: sharedC, helloHash });
    r.learn('C', a('handshake keys', 'key')); r.learn('S', a('handshake keys', 'key'));
    r.check('C', H.eq(ksC.secrets.handshake, ksS.secrets.handshake), `X25519 gives both sides ${H.short(sharedC, 8)}; the handshake secret is ${H.short(ksC.secrets.handshake, 8)}`);
    const sHsKeys = T.trafficKeys(ksS.secrets.serverHs), cHsKeys = T.trafficKeys(ksS.secrets.clientHs);
    // server flight under the server handshake keys
    let sSeq = 0;
    const sendHs = (type, body, label, note, term) => {
      const m = msg(type, body), rec = T.seal(sHsKeys, sSeq, 22, m);
      records.push({ dir: 'S→C', label, seq: sSeq, keys: 'server handshake', wire: hex(rec.wire), nonce: hex(rec.nonce) });
      r.send('S', 'C', [enc(a('handshake keys', 'key'), term)], { label, note, values: { record: H.short(rec.wire, 20), seq: sSeq } });
      sSeq++;
      return { m, rec };
    };
    const ee = sendHs('encrypted_extensions', utf8('|alpn=http/1.1'), 'EncryptedExtensions', 'Extensions not needed to set up keys, now hidden from observers', a('extensions', 'data'));
    transcript.push(ee.m);
    let leafCert = P.leaf;
    if (o.tamper === 'cert') leafCert = Pr.certScenario('fake', { seed, bits: o.bits }).chain[0];
    const certBody = utf8(`|chain=${[leafCert, P.inter].map((c) => `${c.subject}#${c.serial}#${c.fingerprint}`).join(';')}`);
    const ce = sendHs('certificate', certBody, 'Certificate', 'The server\'s certificate chain', a('server cert', 'public'));
    transcript.push(ce.m);
    const cvContent = concat(new Uint8Array(64).fill(0x20), utf8('TLS 1.3, server CertificateVerify'), Uint8Array.of(0), th());
    const cvSig = P.keys.leaf.sign(cvContent);
    const cv = sendHs('certificate_verify', cvSig, 'CertificateVerify', 'A signature by the certificate\'s key over the transcript so far', Pr.sig('S', a('transcript')));
    transcript.push(cv.m);
    const sFinKey = T.expandLabel(ksS.secrets.serverHs, 'finished', new Uint8Array(0), 32);
    let sVerify = M().hmac('sha256', sFinKey, th());
    if (o.tamper === 'finished') sVerify = sVerify.map((v, i) => (i ? v : v ^ 1));
    const fin = sendHs('finished', sVerify, 'Finished (server)', 'An HMAC over the whole transcript under a key from the handshake secret', a('server Finished', 'data'));
    // client side: decrypt and check everything
    const chainOk = Pr.validateChain([leafCert, P.inter, P.root], { trustStore: P.trustStore, hostname: host });
    checks.push({ who: 'C', what: 'certificate chain', ok: chainOk.ok, trace: chainOk.trace });
    r.check('C', chainOk.ok, chainOk.ok ? `the chain ${leafCert.subject} → ${P.inter.subject} → ${P.root.subject} validates, and names ${host}` : `certificate rejected: ${chainOk.reason}`);
    const cvOk = Pr.signer.verifyAny(leafCert.publicKey, cvContent, cvSig);
    checks.push({ who: 'C', what: 'CertificateVerify', ok: cvOk });
    if (chainOk.ok) r.check('C', cvOk, cvOk ? 'CertificateVerify verifies under the certificate\'s key: the server holds the private key, and signed this very handshake' : 'CertificateVerify does not verify');
    const cFinCheckKey = T.expandLabel(ksC.secrets.serverHs, 'finished', new Uint8Array(0), 32);
    const want = M().hmac('sha256', cFinCheckKey, th());
    const finOk = M().equal(want, sVerify);
    checks.push({ who: 'C', what: 'server Finished', ok: finOk });
    if (chainOk.ok && cvOk) r.check('C', finOk, finOk ? 'the server Finished matches her own HMAC of the transcript: nothing was altered in flight' : 'the server Finished does not match: the handshake was tampered with');
    transcript.push(fin.m);
    const handshakeOk = chainOk.ok && cvOk && finOk;
    const result = { schedule: null, records, checks, ok: handshakeOk };
    if (!handshakeOk) {
      r.note('The client aborts with an alert. No application data is sent.');
      Object.assign(result, r.result(), { ok: false, schedule: { ...hexAll(ksC.secrets) }, records, checks });
      result.summary = 'The handshake fails closed: one bad check and no key is ever used.';
      return result;
    }
    const sfHash = th();
    const cFinKey = T.expandLabel(ksC.secrets.clientHs, 'finished', new Uint8Array(0), 32), cVerify = M().hmac('sha256', cFinKey, sfHash);
    const cfin = msg('finished', cVerify), cRec = T.seal(cHsKeys, 0, 22, cfin);
    records.push({ dir: 'C→S', label: 'Finished (client)', seq: 0, keys: 'client handshake', wire: hex(cRec.wire), nonce: hex(cRec.nonce) });
    r.send('C', 'S', [enc(a('handshake keys', 'key'), a('client Finished', 'data'))], { label: 'Finished (client)', note: 'The client\'s HMAC over the transcript', values: { record: H.short(cRec.wire, 20) } });
    const got = T.open(cHsKeys, 0, cRec);
    r.check('S', !!got && M().equal(got.content.slice(4), M().hmac('sha256', T.expandLabel(ksS.secrets.clientHs, 'finished', new Uint8Array(0), 32), sfHash)), 'the client Finished verifies');
    transcript.push(cfin);
    const full = T.keySchedule({ shared: sharedC, helloHash, serverFinishedHash: sfHash, clientFinishedHash: th() });
    r.learn('C', a('application keys', 'key')); r.learn('S', a('application keys', 'key'));
    const cAp = T.trafficKeys(full.secrets.clientAp), sAp = T.trafficKeys(full.secrets.serverAp);
    const request = utf8(o.message || 'GET /balance HTTP/1.1\r\nHost: ' + host + '\r\n\r\n');
    const appRec = T.seal(cAp, 0, 23, request);
    if (o.tamper === 'record') { appRec.ciphertext[3] ^= 0x40; appRec.wire = concat(appRec.header, appRec.ciphertext, appRec.tag); }
    records.push({ dir: 'C→S', label: 'application data', seq: 0, keys: 'client application', wire: hex(appRec.wire), nonce: hex(appRec.nonce) });
    r.send('C', 'S', [enc(a('application keys', 'key'), a('request', 'data'))], { label: 'Application data', note: 'The request, under the client application traffic key', values: { record: H.short(appRec.wire, 20) } });
    const opened = T.open(cAp, 0, appRec);
    r.check('S', !!opened, opened ? `the record opens: “${new TextDecoder().decode(opened.content).split('\r\n')[0]}”` : 'the record\'s tag fails: the server drops it and closes the connection');
    if (opened) {
      const resp = T.seal(sAp, 0, 23, utf8('HTTP/1.1 200 OK\r\n\r\nbalance: 1,204.50'));
      records.push({ dir: 'S→C', label: 'application data', seq: 0, keys: 'server application', wire: hex(resp.wire), nonce: hex(resp.nonce) });
      r.send('S', 'C', [enc(a('application keys', 'key'), a('response', 'data'))], { label: 'Application data', note: 'The response, under the server application traffic key', values: { record: H.short(resp.wire, 20) } });
    }
    r.note('The eavesdropper saw both key shares and every record, and learned none of the keys.');
    Object.assign(result, r.result(), { ok: !!opened, schedule: hexAll(full.secrets), scheduleTrace: full.trace, records, checks, keys: { serverHs: hexKeys(sHsKeys), clientHs: hexKeys(cHsKeys), clientAp: hexKeys(cAp), serverAp: hexKeys(sAp) }, shared: hex(sharedC), host });
    result.summary = 'One round trip: key shares in the hellos, everything after under keys from the schedule, the server proven by its certificate, its signature over the transcript and its Finished.';
    return result;
  };
  const hexAll = (s) => Object.fromEntries(Object.entries(s).map(([k, v]) => [k, hex(v)]));
  const hexKeys = (k) => ({ key: hex(k.key), iv: hex(k.iv) });
})(globalThis.Sifer = globalThis.Sifer || {});
