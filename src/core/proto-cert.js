// A minimal X.509-like public-key infrastructure: certificates (subject, issuer, public key, validity, CA flag,
// names, signature), a root, an intermediate and a server certificate, revocation by list (CRL) and by online
// query (OCSP), and chain validation traced check by check. The attacks: a forged certificate that claims a real
// issuer, a self-made root, an expired, a revoked and a misnamed certificate, and a leaf used as a CA.
//   S.Proto.makeCert({subject, issuer, signer (issuer's), key (subject's signer), notBefore, notAfter, ca, pathLen,
//                     names, serial}) -> cert   (tbs: the signed bytes; signature: bytes)
//   S.Proto.pki({seed, bits}) -> {root, inter, leaf, keys, trustStore, crl, ocsp(serial, now)}
//   S.Proto.validateChain(chain, {trustStore, now, hostname, crl, ocsp}) -> {ok, reason, checks, trace}
//   S.Proto.certScenario(name, {seed, now}) -> {chain, result, story}   names: S.Proto.CERT_SCENARIOS
(function (S) {
  'use strict';
  const Pr = (S.Proto = S.Proto || {});
  const H = S.Hash, { step, hex, utf8 } = H;
  const pubStr = (p) => (p.n !== undefined ? `n=${p.n.toString(16)};e=${p.e}` : `stub=${p.stub}`);
  Pr.tbsBytes = (c) => utf8(['v3', c.serial, c.subject, c.issuer, c.notBefore, c.notAfter, c.ca ? 'CA' : 'EE', c.pathLen === undefined ? '-' : c.pathLen, (c.names || []).join(','), c.sigAlg, pubStr(c.publicKey)].join('|'));
  Pr.makeCert = (o) => {
    const c = {
      version: 3, serial: o.serial || '01', subject: o.subject, issuer: o.issuer, publicKey: o.key.pub, keyKind: o.key.kind,
      keyId: o.key.fingerprint, notBefore: o.notBefore || '2026-01-01', notAfter: o.notAfter || '2027-01-01',
      ca: !!o.ca, pathLen: o.pathLen, names: o.names || [], sigAlg: o.signer.kind.startsWith('RSA') ? 'rsassa-pss with sha256' : 'stand-in',
    };
    c.tbs = Pr.tbsBytes(c);
    c.signature = o.signer.sign(c.tbs);
    c.fingerprint = hex(H.get('sha256').hash(c.tbs)).slice(0, 24);
    return c;
  };
  const verifyWith = (pub, c) => Pr.signer.verifyAny(pub, c.tbs, c.signature);
  Pr.signer.verifyAny = (pub, m, sg) => {
    if (pub.n !== undefined) { try { return S.RSA.pssVerify(pub, m, sg).ok; } catch (e) { return false; } }
    return !!(Pr.stubRegistry && Pr.stubRegistry[pub.stub]) && S.MAC.equal(S.MAC.hmac('sha256', Pr.stubRegistry[pub.stub], m), sg);
  };

  Pr.pki = (o = {}) => {
    const seed = o.seed === undefined ? 1 : o.seed, bits = o.bits || 1024;
    const k = (n) => Pr.signer(n, { seed, bits });
    const keys = { root: k('Lantern Root CA'), inter: k('Lantern Issuing CA 2'), leaf: k('www.harbourbank.example'), ocsp: null };
    const root = Pr.makeCert({ serial: '5a01', subject: 'CN=Lantern Root CA', issuer: 'CN=Lantern Root CA', key: keys.root, signer: keys.root, notBefore: '2020-01-01', notAfter: '2040-01-01', ca: true, pathLen: 1 });
    const inter = Pr.makeCert({ serial: '7c22', subject: 'CN=Lantern Issuing CA 2', issuer: 'CN=Lantern Root CA', key: keys.inter, signer: keys.root, notBefore: '2024-01-01', notAfter: '2030-01-01', ca: true, pathLen: 0 });
    const leaf = Pr.makeCert({ serial: '91e4', subject: 'CN=www.harbourbank.example', issuer: 'CN=Lantern Issuing CA 2', key: keys.leaf, signer: keys.inter, notBefore: '2026-03-01', notAfter: '2026-12-01', names: ['www.harbourbank.example', 'harbourbank.example'] });
    const revoked = new Set(o.revoked || []);
    const crl = Pr.signCrl(keys.inter, 'CN=Lantern Issuing CA 2', [...revoked], '2026-05-30', '2026-06-06');
    const ocsp = (serial, now) => {
      const body = utf8(`ocsp|${serial}|${revoked.has(serial) ? 'revoked' : 'good'}|${now}`);
      return { serial, status: revoked.has(serial) ? 'revoked' : 'good', producedAt: now, responder: 'CN=Lantern Issuing CA 2', body, signature: keys.inter.sign(body) };
    };
    return { root, inter, leaf, keys, trustStore: [root], crl, ocsp, revoked, seed, bits };
  };
  Pr.signCrl = (signer, issuer, serials, thisUpdate, nextUpdate) => {
    const body = utf8(`crl|${issuer}|${serials.join(',')}|${thisUpdate}|${nextUpdate}`);
    return { issuer, serials, thisUpdate, nextUpdate, body, signature: signer.sign(body) };
  };

  const nameMatch = (pattern, host) => pattern === host || (pattern.startsWith('*.') && host.endsWith(pattern.slice(1)) && host.split('.').length === pattern.split('.').length);
  /** chain[0] is the server's certificate, each next one its issuer; the last should be a trusted root */
  Pr.validateChain = (chain, o = {}) => {
    const now = o.now || '2026-06-01', trust = o.trustStore || [], checks = [], trace = [];
    let ok = true, reason = null;
    const check = (i, what, pass, say) => {
      checks.push({ i, cert: chain[i] && chain[i].subject, what, ok: !!pass, say });
      trace.push(step(pass ? 'check-ok' : 'check-fail', say, { i, what, ok: !!pass }));
      if (!pass && ok) { ok = false; reason = say; }
      return pass;
    };
    if (o.hostname) {
      const leaf = chain[0];
      check(0, 'name', leaf.names.some((n) => nameMatch(n, o.hostname)), `The server certificate names ${leaf.names.join(', ') || 'no host'}; the client asked for ${o.hostname}${leaf.names.some((n) => nameMatch(n, o.hostname)) ? ': a match' : ': no match'}.`);
    }
    for (let i = 0; i < chain.length && ok; i++) {
      const c = chain[i], last = i === chain.length - 1;
      check(i, 'validity', c.notBefore <= now && now <= c.notAfter, `${c.subject}: valid from ${c.notBefore} to ${c.notAfter}; today is ${now}${c.notBefore <= now && now <= c.notAfter ? '' : ', outside that window'}.`);
      if (!ok) break;
      if (i > 0) {
        check(i, 'ca', c.ca, `${c.subject} signed the certificate below it, so it must be marked as a CA: ${c.ca ? 'it is' : 'it is not (an end-entity certificate cannot issue others)'}.`);
        if (ok && c.pathLen !== undefined) check(i, 'pathlen', i - 1 <= c.pathLen, `Its path length limit is ${c.pathLen}; there ${i - 1 === 1 ? 'is' : 'are'} ${i - 1} CA certificate${i - 1 === 1 ? '' : 's'} below it.`);
      }
      if (!ok) break;
      const issuerCert = last ? c : chain[i + 1];
      check(i, 'issuer-name', c.issuer === issuerCert.subject, `${c.subject} says it was issued by ${c.issuer}; the next certificate is ${issuerCert.subject}${c.issuer === issuerCert.subject ? '' : ': the names do not chain'}.`);
      if (!ok) break;
      const sigOk = verifyWith(issuerCert.publicKey, c);
      check(i, 'signature', sigOk, sigOk ? `The signature on ${c.subject} verifies under the public key in ${issuerCert.subject} (key ${issuerCert.keyId}).` : `The signature on ${c.subject} does not verify under ${issuerCert.subject}'s key ${issuerCert.keyId}: it was not signed by that CA.`);
      if (!ok) break;
      if (!last && !c.ca && (o.crl || o.ocsp)) {
        if (o.ocsp) {
          const r = o.ocsp(c.serial, now), sOk = Pr.signer.verifyAny(issuerCert.publicKey, r.body, r.signature);
          check(i, 'ocsp-signature', sOk, `The OCSP response for serial ${c.serial} is signed by ${r.responder}${sOk ? '' : ', but the signature fails'}.`);
          if (ok) check(i, 'ocsp', r.status === 'good', `OCSP says serial ${c.serial} is ${r.status}, as of ${r.producedAt}.`);
        } else {
          const crl = o.crl, sOk = Pr.signer.verifyAny(issuerCert.publicKey, crl.body, crl.signature);
          check(i, 'crl-signature', sOk, `The revocation list from ${crl.issuer} (issued ${crl.thisUpdate}, next due ${crl.nextUpdate}) is signed by that CA${sOk ? '' : ', but the signature fails'}.`);
          if (ok) check(i, 'crl', !crl.serials.includes(c.serial), crl.serials.includes(c.serial) ? `Serial ${c.serial} is on the list: the certificate has been revoked.` : `Serial ${c.serial} is not among the ${crl.serials.length} revoked serial${crl.serials.length === 1 ? '' : 's'}.`);
        }
      }
      if (last && ok) {
        const anchored = trust.some((t) => t.subject === c.subject && Pr.samePub(t.publicKey, c.publicKey));
        check(i, 'anchor', anchored, anchored ? `${c.subject} is in the trust store with this very key: the chain ends at a trust anchor.` : `${c.subject} is not in the trust store${trust.some((t) => t.subject === c.subject) ? ' with this key (a root with the same name but a different key)' : ''}: nothing vouches for it.`);
      }
    }
    if (ok) trace.push(step('accept', `Every check passed: the client may use ${chain[0].subject}'s public key.`, {}));
    return { ok, reason, checks, trace };
  };

  Pr.CERT_SCENARIOS = ['valid', 'fake', 'self-made-root', 'expired', 'revoked-crl', 'revoked-ocsp', 'wrong-host', 'leaf-as-ca'];
  Pr.certScenario = (nm = 'valid', o = {}) => {
    const now = o.now || '2026-06-01', host = 'www.harbourbank.example';
    const P = Pr.pki({ seed: o.seed, bits: o.bits, revoked: nm.startsWith('revoked') ? ['91e4'] : [] });
    const atk = Pr.signer('Mallory', { seed: P.seed, bits: P.bits });
    let chain = [P.leaf, P.inter, P.root], opts = { trustStore: P.trustStore, now, hostname: host }, story;
    if (nm === 'valid') story = 'The server sends its certificate and the intermediate; the client holds the root.';
    if (nm === 'fake') {
      const fake = Pr.makeCert({ serial: '91e4', subject: 'CN=www.harbourbank.example', issuer: 'CN=Lantern Issuing CA 2', key: atk, signer: atk, notBefore: '2026-03-01', notAfter: '2026-12-01', names: [host] });
      chain = [fake, P.inter, P.root];
      story = 'Mallory copies every field of the bank\'s certificate but puts in her own key, and signs it herself while naming the real CA as issuer.';
    }
    if (nm === 'self-made-root') {
      const mroot = Pr.makeCert({ serial: '0bad', subject: 'CN=Lantern Root CA', issuer: 'CN=Lantern Root CA', key: atk, signer: atk, notBefore: '2026-01-01', notAfter: '2036-01-01', ca: true });
      const leaf = Pr.makeCert({ serial: '0bae', subject: 'CN=www.harbourbank.example', issuer: 'CN=Lantern Root CA', key: atk, signer: atk, notBefore: '2026-03-01', notAfter: '2026-12-01', names: [host] });
      chain = [leaf, mroot];
      story = 'Mallory makes her own root with the same name as the real one, and issues herself a certificate for the bank.';
    }
    if (nm === 'expired') { opts.now = '2027-02-15'; story = 'The same chain, checked after the server certificate has expired.'; }
    if (nm === 'revoked-crl') { opts.crl = P.crl; story = 'The bank\'s key was stolen and the CA revoked serial 91e4; the client fetches the CA\'s revocation list.'; }
    if (nm === 'revoked-ocsp') { opts.ocsp = P.ocsp; story = 'The same revocation, checked by asking the CA\'s OCSP responder about this one serial.'; }
    if (nm === 'wrong-host') { opts.hostname = 'www.harbour-bank.example'; story = 'A valid certificate for the bank, presented by a look-alike host.'; }
    if (nm === 'leaf-as-ca') {
      const leafKey = P.keys.leaf;
      const evil = Pr.makeCert({ serial: '0c01', subject: 'CN=mail.lanterntrust.example', issuer: 'CN=www.harbourbank.example', key: atk, signer: leafKey, notBefore: '2026-04-01', notAfter: '2026-12-01', names: ['mail.lanterntrust.example'] });
      chain = [evil, P.leaf, P.inter, P.root]; opts.hostname = 'mail.lanterntrust.example';
      story = 'The bank\'s own certificate is used to sign a certificate for some other site. Its signature is genuine, but the bank is not a CA.';
    }
    const result = Pr.validateChain(chain, opts);
    return { name: nm, chain, result, story, pki: P, revocation: { crl: 'a signed list of revoked serials, published by the CA every few days; simple, but can be stale and large', ocsp: 'a signed answer about one serial, fetched when needed (or stapled by the server to its handshake); fresher, but the responder learns which sites you visit' } };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
