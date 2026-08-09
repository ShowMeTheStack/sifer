// The hash bench: published digests (FIPS 180 and 202 examples), the chain and the rounds, HMAC on an RFC 4231 test
// case, the length-extension defence card (no forgery runner), a birthday search on a cut-down digest that finds a
// collision, and the page at phone width.
import { assert } from '../lib.mjs';

const B = 'Sifer.app.page.bench';
async function open(p) { await p.route('bench/hash'); await p.wait("!!document.querySelector('#hbOut')"); }
async function set(p, patch) { await p.ev(`${B}.set(${JSON.stringify(patch)})`); await p.wait("!!document.querySelector('#hbOut')"); await p.sleep(60); }

export default function (t) {
  t.test('SHA-256 and SHA3-256 of "abc", with the chain and every round', async (p) => {
    await open(p);
    await p.setValue('#hbName', 'sha256', 'change');
    await p.setValue('#hbMsg', 'abc');
    await p.wait("document.querySelector('#hbDigestHex').innerText === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'");
    assert.equal(await p.count('#hbRounds tbody tr'), 64);
    assert.equal(await p.count('#hbChain .hc-f'), 1, 'one block');
    assert.match(await p.text('#hbFlip'), /digest bits change/);
    await p.setValue('#hbName', 'sha3-256', 'change');
    await p.setValue('#hbMsg', 'abc');
    await p.wait("document.querySelector('#hbDigestHex').innerText === '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'");
    assert.equal(await p.count('.lanes'), 3);
    await p.setValue('#hbName', 'md5', 'change');
    await p.setValue('#hbMsg', '');
    await p.wait("document.querySelector('#hbDigestHex').innerText === 'd41d8cd98f00b204e9800998ecf8427e'");
  });

  t.test('a long message makes a chain of blocks, each opened', async (p) => {
    await open(p);
    await set(p, { panel: 'hash', name: 'sha1', msg: { mode: 'text', text: 'x'.repeat(150), hex: '' }, block: 2 });
    assert.equal(await p.count('#hbChain .hc-f'), 3);
    assert.equal(await p.count('#hbRounds tbody tr'), 80);
    assert.match(await p.ev("document.getElementById('hbBlock').selectedOptions[0].innerText"), /Block 3/);
  });

  t.test('HMAC-SHA-256 matches RFC 4231 test case 2', async (p) => {
    await open(p);
    await p.click('#hbPanel button[data-v="hmac"]');
    await p.setValue('#hbHmacName', 'sha256', 'change');
    await p.setValue('#hbKey', 'Jefe');
    await p.setValue('#hbHmacMsg', 'what do ya want for nothing?');
    await p.wait("document.querySelector('#hbTag').innerText === '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'");
    assert.match(await p.text('#hbHmac'), /Inner hash[\s\S]*Outer hash/);
  });

  t.test('length extension: a defence card, no forgery runner, with the state table and the links', async (p) => {
    await open(p);
    await set(p, { panel: 'lenext' });
    assert.ok(await p.exists('#hbLenRules .lab-rules'));
    assert.ok(!(await p.exists('#hbForged')) && !(await p.exists('#hbSecret')), 'no forgery runner');
    assert.match(await p.text('#hbLenTable'), /SHA-256\s+32\s+32\s+yes/);
    assert.match(await p.text('#hbLenTable'), /SHA3-256\s+200\s+32\s+no/);
    for (const id of ['p12-lenext', 'p13-hmac']) assert.ok(await p.exists(`#hbLenRules .lab-topics a[data-topic="${id}"]`), 'links to ' + id);
    await p.click('#hbLenRules .lab-topics a[data-topic="p12-lenext"]');
    await p.wait("location.hash === '#topic=p12-lenext'");
  });

  t.test('the birthday attack finds a collision on a 20-bit digest, live', async (p) => {
    await open(p);
    await set(p, { panel: 'bday', bday: { name: 'sha256', bits: 20 } });
    await p.click('#hbBdayRun');
    await p.wait("!!document.getElementById('hbBdayFound')", 20000);
    const a = await p.text('#hbMsgA'), b = await p.text('#hbMsgB');
    assert.notEqual(a, b);
    const same = await p.ev("(() => { const S = Sifer, d = (m) => S.bytes.hex(S.Hash.get('sha256').hash(new TextEncoder().encode(m))); return d(document.getElementById('hbMsgA').innerText).slice(0, 5) === d(document.getElementById('hbMsgB').innerText).slice(0, 5); })()");
    assert.ok(same, 'the first 20 bits agree');
    assert.match(await p.text('#hbBdayFound'), /Collision after [\d,]+ tries/);
  });

  t.test('the hash bench fits a phone', async (p) => {
    await open(p);
    for (const panel of ['hash', 'hmac', 'lenext', 'bday']) { await set(p, { panel }); assert.ok(await p.fitsPhone(), panel); }
  });
}
