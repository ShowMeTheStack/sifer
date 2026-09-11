// Part 13, certificates and chain validation: the chain a server sends drawn as cards (subject, issuer, validity,
// CA flag, names, key, signature), the client's trust store and revocation source, and every check of the
// validation lit on the card field it reads, for a valid chain and for each way a chain can fail.
(function (S) {
  'use strict';
  const U = S.P12, Pr = () => S.Proto;
  const { t } = U;
  const cn = (s) => String(s).replace(/^CN=/, '');
  const STORIES = { valid: 'a valid chain', fake: 'a forged certificate', 'self-made-root': 'a home-made root', expired: 'an expired certificate', 'revoked-crl': 'revoked: the CA\'s list', 'revoked-ocsp': 'revoked: asked online', 'wrong-host': 'the wrong host name', 'leaf-as-ca': 'a server certificate used as a CA' };
  // which card line each check reads
  const FIELD = { name: 'names', validity: 'valid', ca: 'ca', pathlen: 'ca', 'issuer-name': 'issuer', signature: 'sig', 'crl-signature': 'rev', crl: 'rev', 'ocsp-signature': 'rev', ocsp: 'rev', anchor: 'anchor' };
  const SHORT = { name: 'host name matches', validity: 'within its validity', ca: 'issuer is a CA', pathlen: 'path length allowed', 'issuer-name': 'issuer name chains', signature: 'signature verifies', 'crl-signature': 'revocation list signed', crl: 'not on the revocation list', 'ocsp-signature': 'OCSP answer signed', ocsp: 'OCSP says good', anchor: 'root in the trust store' };

  function certs(inp) {
    const P = Pr(), sc = P.certScenario(inp.scenario, { seed: +inp.seed }), ch = sc.chain, res = sc.result, n = ch.length;
    const now = inp.scenario === 'expired' ? '2027-02-15' : '2026-06-01';
    const host = inp.scenario === 'wrong-host' ? 'www.harbour-bank.example' : inp.scenario === 'leaf-as-ca' ? 'mail.lanterntrust.example' : 'www.harbourbank.example';
    const gap = 16, cw = (880 - gap * (n - 1)) / n, x0 = 20, y0 = 96, chH = 196;
    const cardX = (i) => U.r2(x0 + i * (cw + gap));
    const fs = 13;
    const card = (i, lit) => {
      const c = ch[i], x = cardX(i), items = [];
      const title = i === 0 ? 'server certificate' : i === n - 1 ? (c.subject === c.issuer ? 'root (self-signed)' : 'top of the chain') : c.ca ? 'intermediate CA' : 'end-entity certificate';
      items.push(...U.panel('ce:c' + i, x, y0, cw, chH, title, lit && lit.cert === i ? (lit.ok ? 'good' : 'bad') : ''));
      const lines = [
        ['subject', cn(c.subject)], ['issuer', cn(c.issuer), 'issuer'], ['valid', c.notBefore + ' → ' + c.notAfter, 'valid'],
        ['CA', c.ca ? 'yes' + (c.pathLen !== undefined ? ', path ≤ ' + c.pathLen : '') : 'no (end entity)', 'ca'],
        ['names', c.names.length ? c.names.join(', ') : '—', 'names'], ['key', c.keyId, 'key'], ['signed', U.short(U.hex(c.signature), 6), 'sig'], ['serial', c.serial],
      ];
      lines.forEach(([k, v, f], j) => {
        const on = lit && lit.cert === i && lit.field === f, onKey = lit && lit.keyOf === i && f === 'key';
        const cls = on ? (lit.ok ? 'good' : 'bad') : onKey ? 'act' : '';
        items.push(t('ce:k' + i + j, x + 12, y0 + 46 + j * 19, k, 'ptick', 'start', fs), t('ce:v' + i + j, x + 62, y0 + 46 + j * 19, U.cut(v, Math.floor((cw - 74) / (fs * 0.62))), 'mono ' + cls, 'start', fs));
      });
      return items;
    };
    const arrows = () => {
      const items = [];
      for (let i = 0; i < n - 1; i++) {
        const xa = cardX(i) + cw, xb = cardX(i + 1);
        items.push({ key: 'ce:a' + i, kind: 'wire', pts: [[U.r2(xa + 1), y0 + 20], [U.r2(xb - 1), y0 + 20]], head: true, cls: '' });
      }
      items.push(t('ce:al', 20, 82, 'each certificate is signed by the next one\'s key →', 'ptick', 'start', 13));
      return items;
    };
    const client = (lit) => {
      const items = U.panel('ce:cl', 20, 308, 430, 92, 'the client', lit && lit.field === 'names' ? (lit.ok ? 'good' : 'bad') : '');
      items.push(t('ce:cl1', 34, 352, 'connecting to ' + host, 'mono', 'start', 13), t('ce:cl2', 34, 378, 'today ' + now + (inp.scenario.startsWith('revoked') ? (inp.scenario === 'revoked-crl' ? ' · checks the CRL' : ' · asks OCSP') : ''), 'mono', 'start', 13));
      const ts = U.panel('ce:ts', 470, 308, 430, 92, 'trust store', lit && lit.field === 'anchor' ? (lit.ok ? 'good' : 'bad') : '');
      const root = sc.pki.root;
      ts.push(t('ce:ts1', 484, 352, cn(root.subject), 'mono', 'start', 13), t('ce:ts2', 484, 378, 'key ' + root.keyId, 'mono ' + (lit && lit.field === 'anchor' ? 'act' : ''), 'start', 13));
      return items.concat(ts);
    };
    const list = (upto) => {
      const items = [t('ce:lt', 20, 428, 'checks, in order', 'ptitle')];
      const from = Math.max(0, upto - 8);
      res.checks.slice(from, upto).forEach((c, j) => {
        const k = from + j, cur = k === upto - 1;
        items.push({ key: 'ce:ck' + k, kind: 'cell', x: 20, y: 438 + j * 26, w: 880, h: 23, rx: 4, text: (c.ok ? '✓ ' : '✗ ') + 'certificate ' + (c.i + 1) + ': ' + SHORT[c.what], size: 13.5, align: 'start', cls: (c.ok ? (cur ? 'good' : 'soft') : 'bad') });
      });
      return items;
    };
    const F = new S.Frames(['checks', 'failed']);
    const head = U.head('ce:h', 'Chain validation: ' + STORIES[inp.scenario], U.cut(sc.story, 132));
    F.add({ items: [...head, ...arrows(), ...Array.from({ length: n }, (_, i) => card(i)).flat(), ...client(), ...list(0)], hl: { d: [0] }, say: `${sc.story} The client sees ${U.plural(n, 'certificate')}: ${ch.map((c) => cn(c.subject)).join(' → ')}.`, facts: { story: sc.story, n, subjects: ch.map((c) => c.subject) }, meta: { stage: 'start' } });
    res.checks.forEach((c, k) => {
      F.count('checks');
      if (!c.ok) F.count('failed');
      const field = FIELD[c.what], lit = { cert: c.i, field: field === 'rev' ? 'serial' : field, ok: c.ok, keyOf: c.what === 'signature' ? Math.min(c.i + 1, n - 1) : -1 };
      F.add({ items: [...head, ...arrows(), ...Array.from({ length: n }, (_, i) => card(i, lit)).flat(), ...client(lit), ...list(k + 1)], hl: { d: [c.what === 'signature' ? 2 : c.what === 'anchor' ? 4 : /crl|ocsp/.test(c.what) ? 5 : c.what === 'name' ? 1 : 3] }, say: c.say, facts: { say: c.say, what: c.what, ok: c.ok, i: c.i }, meta: { stage: c.ok ? 'pass' : 'fail', what: c.what } });
    });
    F.add({ items: [...head, ...arrows(), ...Array.from({ length: n }, (_, i) => card(i)).flat(), ...client(), ...list(res.checks.length)], hl: { d: [6] }, say: res.ok ? `Every one of the ${res.checks.length} checks passed: the client may trust that ${cn(ch[0].subject)}'s public key, ${ch[0].keyId}, belongs to ${host}.` : `The chain is rejected at the first failure, and the connection is closed: ${res.reason} ${sc.revocation && inp.scenario.startsWith('revoked') ? 'A CRL is ' + sc.revocation.crl + '; OCSP is ' + sc.revocation.ocsp + '.' : ''}`.trim(), facts: { ok: res.ok, reason: res.reason, n: res.checks.length, keyId: ch[0].keyId, rev: sc.revocation }, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Validating a chain', ['1. the server certificate names the host', '2. every certificate is within its validity', '3. each signature verifies under the next certificate\'s key', '4. every issuer is a CA, within its path length', '5. the last certificate is a root in the trust store', '6. no certificate is revoked (CRL or OCSP)', 'any failure: reject the whole chain']) };
  }
  S.topic({
    id: 'p13-certs', family: 'p13-pki', order: 30, title: 'Certificates and chain validation',
    blurb: 'A server proves its key with a chain of certificates up to a root the client already trusts. Watch every check, and the one that fails for a forgery, a home-made root, an expired or revoked certificate, the wrong host, or a server certificate playing CA.',
    inputs: [
      { id: 'scenario', kind: 'choice', label: 'Chain', def: 'valid', options: Object.keys(STORIES).map((k) => ({ value: k, label: STORIES[k] })) },
      { id: 'seed', kind: 'number', label: 'Key seed', def: 1, min: 1, max: 99 },
    ],
    presets: Object.keys(STORIES).map((k) => ({ label: U.cap(STORIES[k]), values: { scenario: k, seed: 1 } })),
    counters: [{ id: 'checks', label: 'checks' }, { id: 'failed', label: 'failed' }],
    run: certs,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'start', pick: 'option', options: ['accept', 'reject'], ask: 'Will the client accept this chain?', answer: (fr) => (fr[fr.length - 1].facts.ok ? 'accept' : 'reject'), explain: (fr) => fr[fr.length - 1].say },
    ],
    quiz: [
      { q: 'What does a certificate\'s signature prove?', options: ['the server is honest', 'the issuing CA vouched for this binding of name and key', 'the key is long', 'the connection is encrypted'], answer: 1, why: 'Only the issuer\'s private key could sign those exact fields.' },
      { q: 'Mallory makes her own root named "Lantern Root CA". Why does it fail?', options: ['the name is wrong', 'the trust store holds the real root\'s key, not hers', 'it is expired', 'roots cannot sign'], answer: 1, why: 'Trust anchors are matched by key, not just by name.' },
      { q: 'Why must an intermediate certificate be marked as a CA?', options: ['for speed', 'otherwise any website could issue certificates for other sites', 'for revocation', 'it need not'], answer: 1, why: 'The basic-constraints flag stops end-entity keys from issuing.' },
      { q: 'What is a drawback of OCSP compared with a CRL?', options: ['it is never signed', 'the responder learns which sites a client visits (unless stapled)', 'it is always stale', 'it cannot revoke'], answer: 1, why: 'Each query names one certificate; stapling lets the server send the answer instead.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
