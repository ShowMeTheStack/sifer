// The protocol bench: picking a protocol, stepping its chart, each party's knowledge, the man in the middle, TLS.
import { assert } from '../lib.mjs';

const pick = async (p, flow) => { await p.click(`.proto-pick[data-flow="${flow}"]`); await p.wait("!!document.querySelector('#protoChart svg')"); };
const chips = (p, party) => p.ev(`[...document.querySelectorAll('.kcard[data-party="${party}"] .kchip')].map(c => c.textContent)`);

export default function (t) {
  t.test('Diffie–Hellman: stepping, the chart cursor, and who knows the key', async (p) => {
    await p.route('bench/proto');
    await pick(p, 'dh');
    assert.equal(await p.text('#protoPos'), '0 / ' + (await p.ev('Sifer.app.page.bench.result.steps.length')));
    assert.ok(!(await chips(p, 'A')).includes('g^ab'), 'Alice starts without the key');
    await p.click('#protoNext');
    await p.click('#protoNext');
    assert.ok(await p.exists('.msc-step.cur'), 'the current row is lit');
    await p.ev('Sifer.app.page.bench.go(99)');
    for (const party of ['A', 'B']) assert.ok((await chips(p, party)).includes('g^ab'), party + ' holds g^ab');
    assert.ok(!(await chips(p, 'E')).includes('g^ab'), 'Eve does not');
    assert.ok(await p.exists('.kcard[data-party="A"] .kchip.key'), 'the key is drawn as key material');
    assert.match(await p.text('#protoSummary'), /run completes/);
  });

  t.test('the man in the middle learns both keys, and changes the message', async (p) => {
    await p.route('bench/proto');
    await pick(p, 'mitm');
    await p.key('End');
    const m = await chips(p, 'M');
    assert.ok(m.includes('g^am′') && m.includes('g^bm'), 'Mallory holds both keys: ' + m);
    assert.ok(!(await chips(p, 'A')).includes('g^bm'), 'Alice does not hold Bob\'s key');
    assert.match(await p.text('#protoSummary'), /broken/);
    assert.match(await p.text('#protoSummary'), /Bob read/);
    assert.ok((await p.count('.msc-arrow.bad')) >= 2, 'intercepted and forged messages are marked');
    await p.key('Home');
    assert.equal(await p.ev('Sifer.app.page.bench.step'), -1);
    await p.key('ArrowRight');
    assert.match(await p.text('#protoDetail'), /meant for Bob/i);
  });

  t.test('the group switch, a new run, Kerberos and a tampered TLS handshake', async (p) => {
    await p.route('bench/proto');
    await pick(p, 'dh');
    await p.setValue('#protoGroup', 'x25519', 'change');
    await p.ev('Sifer.app.page.bench.go(1)');
    assert.match(await p.text('#protoDetail'), /[0-9a-f]{40}/, 'X25519 values are 32-byte hex');
    const before = await p.text('#protoDetail');
    await p.click('#protoFresh');
    await p.ev('Sifer.app.page.bench.go(1)');
    assert.notEqual(await p.text('#protoDetail'), before, 'a new run has new values');
    await pick(p, 'kerberos');
    await p.ev('Sifer.app.page.bench.go(99)');
    assert.ok((await chips(p, 'V')).includes('Kc,v'), 'the service ends with the session key');
    await pick(p, 'tls13');
    assert.ok(await p.visible('#protoTamper'), 'TLS can be tampered with');
    await p.setValue('#protoTamper', 'cert', 'change');
    await p.ev('Sifer.app.page.bench.go(99)');
    assert.ok((await p.count('.msc-badge.no')) >= 1, 'a check fails');
  });

  t.test('the choice is kept, shared, and the bench fits a phone', async (p) => {
    await p.route('bench/proto');
    await pick(p, 'kerberos');
    await p.ev('Sifer.app.page.bench.go(3)');
    await p.sleep(400);
    await p.route('');
    await p.route('bench/proto');
    assert.equal(await p.ev("document.querySelector('.proto-pick.on').dataset.flow"), 'kerberos');
    assert.equal(await p.ev('Sifer.app.page.bench.step'), 3);
    await p.viewport(390, 844, { mobile: true, touch: true });
    await p.route('bench/proto');
    assert.ok(await p.noHScroll(), 'no sideways page scroll');
    await p.viewport(1400, 900);
  });

  t.test('certificates: a valid chain is checked field by field up to the trust anchor', async (p) => {
    await p.route('bench/proto');
    await p.click('.proto-pick[data-flow="cert-valid"]');
    await p.wait("!!document.querySelector('#certChain')", 20000);
    assert.equal(await p.count('#certChain .cert-card'), 3, 'root, intermediate, server');
    assert.match(await p.text('#certChain .cert-card:first-child'), /Root, self-signed/);
    assert.equal(await p.count('.cr-row.ok, .cr-row.cur, .cr-row.bad'), 0, 'nothing checked before the start');
    await p.key('ArrowRight');
    assert.ok(await p.exists('.cert-card[data-cert="0"] .cr-row.cur[data-field="names"]'), 'the first check reads the server\'s names');
    await p.key('End');
    assert.equal(await p.count('.cr-row.bad'), 0);
    assert.equal(await p.count('.cert-link.ok, .cert-link.cur'), 2, 'both links verify');
    assert.match(await p.text('#protoSummary'), /Accepted/);
    assert.ok(await p.exists('.ts-root.cur'), 'the trust anchor is lit at the last check');
  }, { timeout: 40000 });

  t.test('certificates: forged, expired, revoked, a look-alike host and a server playing CA are all refused', async (p) => {
    await p.route('bench/proto');
    const cases = { 'cert-fake': [/not signed by that CA/, 'link'], 'cert-self-made-root': [/not in the trust store/, 'subject'], 'cert-expired': [/outside that window/, 'validity'], 'cert-revoked-crl': [/has been revoked/, 'serial'], 'cert-revoked-ocsp': [/is revoked/, 'serial'], 'cert-wrong-host': [/no match/, 'names'], 'cert-leaf-as-ca': [/must be marked as a CA/, 'ca'] };
    for (const [flow, [re, field]] of Object.entries(cases)) {
      await p.click(`.proto-pick[data-flow="${flow}"]`);
      await p.wait(`document.querySelector('#certChain') && document.querySelector('.proto-pick.on').dataset.flow === '${flow}'`, 20000);
      await p.key('End');
      assert.match(await p.text('#protoSummary'), /Rejected/, flow);
      assert.match(await p.text('#protoSummary'), re, flow);
      if (field === 'link') assert.ok(await p.exists('.cert-link.bad'), flow + ': the failed signature link');
      else assert.ok(await p.exists(`.cr-row.bad[data-field="${field}"]`), flow + ': the failed field ' + field);
    }
    assert.ok(await p.exists('.cert-card.cc-forged'), 'the server playing CA signed a card with a foreign key');
    await p.click('.proto-pick[data-flow="cert-fake"]');
    await p.wait("document.querySelector('#certChain[data-scenario=\"fake\"]')", 20000);
    assert.ok(await p.exists('.cert-card.cc-forged'), 'the forged certificate is marked');
    await p.key('End');
    assert.match(await p.text('#protoSummary'), /man in the middle/);
    await p.click('.proto-pick[data-flow="cert-revoked-ocsp"]');
    await p.wait("document.querySelector('#certChain[data-scenario=\"revoked-ocsp\"]')", 20000);
    assert.match(await p.text('#certSide'), /OCSP response/);
    await p.viewport(390, 844, { mobile: true, touch: true });
    assert.ok(await p.noHScroll(), 'the chain fits a phone');
    await p.viewport(1400, 900);
  }, { timeout: 60000 });
}
