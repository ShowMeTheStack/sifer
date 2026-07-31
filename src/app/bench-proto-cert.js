// Certificates on the protocol bench: a chain drawn as linked cards (root at the top, the server's certificate at the
// bottom), each with its subject, issuer, key, validity, serial and signature, and between two cards the check of
// the lower card's signature against the upper card's key. The client's checks (S.Proto.validateChain, through
// S.Proto.certScenario) are stepped one at a time: the field each one reads is lit, passed checks keep a tick, and a
// failed one stops the chain. Beside it: the client (host, date, trust store) and the revocation data.
//   S.ProtoCert.FLOWS -> picks for the bench;  S.ProtoCert.run(name, seed) -> data
//   S.ProtoCert.chain(data, i) / side(data, i) / detail(data, i) / summary(data) -> elements
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
  const PC = (S.ProtoCert = {});
  PC.FLOWS = [
    { id: 'cert-valid', scenario: 'valid', title: 'A certificate chain', blurb: 'Server, intermediate, root: every signature checked.' },
    { id: 'cert-fake', scenario: 'fake', title: 'A forged certificate', blurb: 'A man in the middle with his own key, stopped by the chain.' },
    { id: 'cert-self-made-root', scenario: 'self-made-root', title: 'A self-made root', blurb: 'The right names, the wrong key: no trust anchor.' },
    { id: 'cert-expired', scenario: 'expired', title: 'An expired certificate', blurb: 'The same chain, checked too late.' },
    { id: 'cert-revoked-crl', scenario: 'revoked-crl', title: 'Revoked: the list', blurb: 'A stolen key, revoked and found on the CA\'s list.' },
    { id: 'cert-revoked-ocsp', scenario: 'revoked-ocsp', title: 'Revoked: OCSP', blurb: 'The same revocation, asked about online.' },
    { id: 'cert-wrong-host', scenario: 'wrong-host', title: 'A look-alike host', blurb: 'A genuine certificate, for a different name.' },
    { id: 'cert-leaf-as-ca', scenario: 'leaf-as-ca', title: 'A server playing CA', blurb: 'A genuine signature from a key that may not issue.' },
  ].map((f) => Object.assign({ kind: 'cert' }, f));
  PC.available = () => !!(S.Proto && S.Proto.certScenario);
  PC.run = (name, seed) => {
    const d = S.Proto.certScenario(name, { seed });
    d.checks = d.result.checks;
    d.steps = d.checks;
    d.title = PC.FLOWS.find((f) => f.scenario === name).title;
    return d;
  };

  /** which field of a card a check reads */
  const FIELD = { name: 'names', validity: 'validity', ca: 'ca', pathlen: 'ca', 'issuer-name': 'issuer', signature: 'signature', crl: 'serial', 'crl-signature': 'serial', ocsp: 'serial', 'ocsp-signature': 'serial', anchor: 'subject' };
  const cn = (s) => String(s).replace(/^CN=/, '');
  const short = (s, n) => (s.length > n ? s.slice(0, n) + '…' : s);
  const keyText = (c) => (c.publicKey && c.publicKey.n !== undefined ? 'RSA-' + c.publicKey.n.toString(2).length + ', e = ' + c.publicKey.e : c.keyKind || 'key') + ' · id ' + c.keyId;

  /** the state of each field of each card at step i: {'k|field': 'ok' | 'bad' | 'cur'} and of each link */
  function marks(d, i) {
    const m = {};
    for (let k = 0; k <= i && k < d.checks.length; k++) {
      const c = d.checks[k], f = FIELD[c.what] || 'subject', key = c.i + '|' + f;
      m[key] = k === i ? (c.ok ? 'cur' : 'bad') : c.ok ? (m[key] === 'bad' ? 'bad' : 'ok') : 'bad';
      if (c.what === 'signature') m['link|' + c.i] = k === i ? (c.ok ? 'cur' : 'bad') : c.ok ? 'ok' : 'bad';
      if (c.what === 'issuer-name' && c.i + 1 < d.chain.length) m[(c.i + 1) + '|subject'] = m[(c.i + 1) + '|subject'] || (k === i ? 'cur' : c.ok ? 'ok' : 'bad');
    }
    return m;
  }
  const ROLE = (d, k) => (k === 0 ? 'Server certificate' : k === d.chain.length - 1 ? (d.chain[k].subject === d.chain[k].issuer ? 'Root, self-signed' : 'Top of the chain') : 'Intermediate CA');

  PC.chain = function (d, i) {
    const m = marks(d, i);
    const box = h('div.cert-chain', { id: 'certChain', dataset: { scenario: d.name } });
    const row = (k, field, label, value, mono) => {
      const st = m[k + '|' + field] || '';
      return h('div.cr-row' + (st ? '.' + st : ''), { dataset: { field } }, h('span.cr-k', label), h('span.cr-v' + (mono ? '.mono' : ''), value), h('span.cr-mark', st === 'ok' ? icon('check') : st === 'bad' ? icon('x') : st === 'cur' ? icon('target') : null));
    };
    // the root at the top, the server's certificate at the bottom
    for (let k = d.chain.length - 1; k >= 0; k--) {
      const c = d.chain[k], attacker = /Mallory/.test(c.keyKind || '') || (d.pki && c.keyId && ![d.pki.root, d.pki.inter, d.pki.leaf].some((x) => x.keyId === c.keyId));
      const card = h('section.cert-card' + (attacker ? '.cc-forged' : ''), { dataset: { cert: String(k) } },
        h('div.cc-head', h('span.cc-role', ROLE(d, k)), c.ca ? h('span.cc-tag.ca', 'CA') : h('span.cc-tag', 'end entity'), attacker ? h('span.cc-tag.bad', 'not the real key') : null),
        row(k, 'subject', 'Subject', cn(c.subject)),
        row(k, 'issuer', 'Issuer', cn(c.issuer) + (c.issuer === c.subject ? ' (itself)' : '')),
        row(k, 'key', 'Public key', keyText(c), true),
        row(k, 'validity', 'Valid', c.notBefore + ' to ' + c.notAfter),
        row(k, 'serial', 'Serial', c.serial, true),
        row(k, 'ca', 'Constraints', c.ca ? 'CA' + (c.pathLen !== undefined ? ', path length ≤ ' + c.pathLen : '') : 'not a CA'),
        c.names && c.names.length ? row(k, 'names', 'Names', c.names.join(', ')) : null,
        row(k, 'signature', 'Signature', short(hex(c.signature), 24) + ' (' + c.signature.length + ' bytes)', true));
      box.appendChild(card);
      if (k > 0) {
        const st = m['link|' + (k - 1)] || '';
        box.appendChild(h('div.cert-link' + (st ? '.' + st : ''), { dataset: { link: String(k - 1) } }, h('span.cl-line'), h('span.cl-label', icon(st === 'bad' ? 'x' : st ? 'check' : 'key'), h('span', st === 'bad' ? 'this key does not verify the signature below' : st ? 'this key verifies the signature below' : 'signs the certificate below?'))));
      }
    }
    return box;
  };

  PC.side = function (d, i) {
    const P = d.pki, now = d.name === 'expired' ? '2027-02-15' : '2026-06-01', host = d.name === 'wrong-host' ? 'www.harbour-bank.example' : d.name === 'leaf-as-ca' ? 'mail.lanterntrust.example' : 'www.harbourbank.example';
    const cur = i >= 0 ? d.checks[i] : null;
    const lit = (what) => cur && (Array.isArray(what) ? what.includes(cur.what) : cur.what === what) ? (cur.ok ? '.cur' : '.bad') : '';
    const out = h('div.cert-side', { id: 'certSide' });
    out.appendChild(h('section.card.kcard', h('div.kc-head', h('b', 'The client'), h('span.kc-role', 'checking')),
      h('div.kv' + lit('name'), h('span.k', 'Asked for'), h('code.v', host)), h('div.kv' + lit('validity'), h('span.k', 'Today'), h('code.v', now))));
    out.appendChild(h('section.card.kcard' + (lit('anchor') ? '.lit' : ''), h('div.kc-head', h('b', 'Trust store'), h('span.kc-n', P.trustStore.length + ' root')),
      ...P.trustStore.map((t) => h('div.ts-root' + lit('anchor'), icon('lock'), h('div', h('b', cn(t.subject)), h('div.mono.muted', 'key ' + t.keyId))))));
    if (d.name.startsWith('revoked')) {
      const ocsp = d.name === 'revoked-ocsp';
      const crl = P.crl;
      out.appendChild(h('section.card.kcard', h('div.kc-head', h('b', ocsp ? 'OCSP response' : 'Revocation list'), h('span.kc-role', 'from ' + cn(crl.issuer))),
        ocsp ? h('div.kv' + lit(['ocsp', 'ocsp-signature']), h('span.k', 'Serial 91e4'), h('code.v', P.revoked.has('91e4') ? 'revoked' : 'good')) : h('div.kv' + lit(['crl', 'crl-signature']), h('span.k', 'Revoked'), h('code.v', crl.serials.join(', ') || 'none')),
        ocsp ? null : h('div.kv', h('span.k', 'Issued'), h('code.v', crl.thisUpdate + ', next ' + crl.nextUpdate)),
        h('p.muted.small-note', ocsp ? d.revocation.ocsp : d.revocation.crl)));
    }
    return out;
  };

  PC.detail = function (d, i) {
    const box = h('div');
    if (i < 0) { box.append(h('div.pd-k', 'Before the checks'), h('p', d.story), h('p.muted', 'The server has sent its chain. Step forward to watch the client check it, one field at a time.')); return box; }
    const c = d.checks[i];
    const LBL = { name: 'The name', validity: 'The dates', ca: 'May it issue?', pathlen: 'Path length', 'issuer-name': 'The names chain', signature: 'The signature', crl: 'The revocation list', 'crl-signature': 'The list is genuine', ocsp: 'Online status', 'ocsp-signature': 'The answer is genuine', anchor: 'A trust anchor' };
    box.append(h('div.pd-k', 'Check ' + (i + 1) + ' of ' + d.checks.length + ' · ' + cn(c.cert || '')), h('div.pd-label', LBL[c.what] || c.what), h('p.pd-check.' + (c.ok ? 'ok' : 'no'), icon(c.ok ? 'check' : 'x'), h('span', c.say)));
    if (c.what === 'signature') { const sub = d.chain[c.i]; box.appendChild(h('div.kv', h('span.k', 'Signed bytes'), h('code.v', short(new TextDecoder().decode(sub.tbs), 90)))); }
    return box;
  };

  PC.summary = function (d) {
    const ok = d.result.ok;
    return h('div.ls-note.' + (ok ? 'tip' : 'warn'), icon(ok ? 'check' : 'warn'), h('div', h('b', ok ? 'Accepted. ' : 'Rejected. '), ok ? 'Every check passed: the client may use the server\'s public key for the handshake.' : d.result.reason + (d.name === 'fake' ? ' The man in the middle can copy every field, but not the CA\'s signature: the client stops here, before any secret is sent.' : '')));
  };
})(globalThis.Sifer = globalThis.Sifer || {});
