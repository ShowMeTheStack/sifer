// The public-key bench: toy RSA round trips (directly and by the CRT), a real 512-bit key searched for in a worker
// while the page stays responsive, OAEP and PSS on it, Diffie–Hellman (toy, group 14 and with a man in the middle),
// Elgamal and DSA, and phone width. Values are checked against the engines.
import { assert } from '../lib.mjs';

const tool = async (p, t) => { await p.click('#pk-tool button[data-v="' + t + '"]'); await p.wait("!!document.querySelector('#pkOut .bcard, #pkOut .berr')"); };
const set = async (p, sel, v) => { await p.setValue(sel, v); await p.sleep(420); };
const out = (p) => p.text('#pkOut');

export default function (t) {
  t.test('toy RSA from primes we pick: the key, encryption, decryption both ways, a signature', async (p) => {
    await p.route('bench/pk');
    await tool(p, 'rsa');
    await p.click('#pkSize button[data-v="toy"]');
    await p.click('#pkPad button[data-v="textbook"]');
    await p.click('#pkKind button[data-v="number"]');
    await p.click('.mb-ex .chip', '127 · 131');
    await set(p, '#pkMsg', '9001');
    const k = JSON.parse(await p.ev("(() => { const k = Sifer.RSA.fromPrimes(127n, 131n, 17n); return JSON.stringify({ n: String(k.n), d: String(k.d), c: String(Sifer.RSA.encrypt(9001n, k).value) }); })()"));
    const txt = await out(p);
    assert.match(txt, new RegExp('\\bn\\s+' + k.n + '\\b'));
    assert.match(txt, new RegExp('\\bd\\s+' + k.d + '\\b'));
    assert.match(txt, new RegExp('result\\s+' + k.c + '\\b'), 'c = m^e mod n');
    assert.match(txt, /by c\^d\s+9001\s+by the CRT\s+9001\s+agree\s+yes/);
    assert.match(txt, /valid\s+yes: it gives back m/);
    await set(p, '#pkQ', '133');
    assert.match(await p.text('#pkOut .berr'), /q = 133 is not prime; the next prime is 137/);
    await set(p, '#pkQ', '131');
    await set(p, '#pkE', '13');
    assert.match(await p.text('#pkOut .berr'), /shares a factor with φ\(n\)/);
    await set(p, '#pkE', '17');
    await p.click('#pkKind button[data-v="text"]');
    await set(p, '#pkText', 'x');
    assert.match(await out(p), /as text\s+"x"/);
    await set(p, '#pkText', 'Hello');
    assert.match(await p.text('#pkOut .berr'), /not below n/);
  });

  t.test('a real 512-bit key is found in the background, then OAEP and PSS work on it', async (p) => {
    await p.route('bench/pk');
    await tool(p, 'rsa');
    await p.click('#pkSize button[data-v="512"]');
    await p.click('#pkGen');
    // the page answers at once while the search runs
    let slowest = 0;
    for (let i = 0; i < 8; i++) { const t0 = Date.now(); await p.ev('1 + 1'); slowest = Math.max(slowest, Date.now() - t0); await p.sleep(60); }
    assert.ok(slowest < 400, 'the page froze for ' + slowest + ' ms');
    await p.wait("/512-bit modulus/.test(document.querySelector('#pkOut').innerText)", 90000);
    const n = await p.ev("document.querySelector('#pkOut').innerText.match(/(\\d+) digits, (\\d+) bits/).slice(1).join(',')");
    assert.equal(n.split(',')[1], '512');
    assert.match(await out(p), /by c\^d\s+(\d+)\s+by the CRT\s+\1\s+agree\s+yes/);
    await p.click('#pkPad button[data-v="oaep"]');
    await p.sleep(150);
    assert.match(await p.text('#pkOut .berr'), /at least 66 bytes/);
    await p.click('#pkSize button[data-v="1024"]');
    await p.click('#pkGen');
    await p.wait("/1024-bit modulus/.test(document.querySelector('#pkOut').innerText)", 90000);
    await set(p, '#pkText', 'Meet at the old mill');
    const txt = await out(p);
    assert.match(txt, /decrypted\s+"Meet at the old mill"/);
    assert.match(txt, /verified\s+yes/);
    await p.click('#pkPad button[data-v="textbook"]');
  }, { timeout: 200000 });

  t.test('Diffie–Hellman agrees in a toy group and in group 14; a man in the middle splits it', async (p) => {
    await p.route('bench/pk');
    await tool(p, 'dh');
    await p.click('#pkGroup button[data-v="toy"]');
    await set(p, '#pkDa', '1234'); await set(p, '#pkDb', '777');
    const want = await p.ev('String(Sifer.NT.pow(Sifer.NT.pow(7n, 777n, 2039n), 1234n, 2039n))');
    const txt = await out(p);
    assert.match(txt, new RegExp('Alice: B\\^a\\s+' + want));
    assert.match(txt, /agree\s+yes/);
    await p.click('#pkMitm');
    await p.sleep(100);
    assert.match(await out(p), /Eve holds both/);
    await p.click('#pkMitm');
    await p.click('#pkGroup button[data-v="modp14"]');
    await p.sleep(200);
    assert.match(await out(p), /agree\s+yes: the same \d+-bit secret/);
    assert.match(await out(p), /RFC 3526 group 14/);
    await p.click('#pkGroup button[data-v="toy"]');
    await set(p, '#pkDg', '4');
    assert.match(await p.text('#pkOut .berr'), /does not generate/);
    await set(p, '#pkDg', '7');
  });

  t.test('Elgamal decrypts what it encrypts, and DSA signs and rejects a changed message', async (p) => {
    await p.route('bench/pk');
    await tool(p, 'elgamal');
    await p.click('#pkGroup button[data-v="toy"]');
    await set(p, '#pkEm', '1066');
    assert.match(await out(p), /\bm\s+1066\s+right\?\s+yes/);
    await tool(p, 'dsa');
    await p.click('#pkDsaSize button[data-v="toy"]');
    await p.sleep(150);
    const txt = await out(p);
    assert.match(txt, /valid\s+yes/);
    assert.match(txt, /rejected: the hash changed/);
  });

  t.test('X25519 reproduces RFC 7748 (6.1), and ECDH agrees on the toy curve and on P-256', async (p) => {
    await p.route('bench/pk');
    await tool(p, 'x25519');
    await p.click('#pkXrfc');
    await p.sleep(500);
    const txt = await out(p);
    assert.match(txt, /8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a/, 'Alice\'s public key');
    assert.match(txt, /de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f/, 'Bob\'s public key');
    assert.match(txt, /Alice gets\s+4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742/);
    assert.match(txt, /agree\s+yes/);
    await tool(p, 'ecdh');
    await p.click('#pkCurve button[data-v="toy"]');
    await set(p, '#pkCa', '7'); await set(p, '#pkCb', '11');
    assert.match(await out(p), /\(41, 20\)/, '7·G on the toy curve');
    assert.match(await out(p), /agree\s+yes/);
    await p.click('#pkCurve button[data-v="p256"]');
    await p.sleep(400);
    assert.match(await out(p), /agree\s+yes/);
  });

  t.test('ECDSA on P-256 signs and verifies; the nonce rules link to their topics', async (p) => {
    await p.route('bench/pk');
    await tool(p, 'ecdsa');
    await p.click('#pkCurve button[data-v="p256"]');
    await p.click('#pkNonce button[data-v="rfc6979"]');
    await p.sleep(500);
    let txt = await out(p);
    assert.match(txt, /valid\s+yes/);
    assert.match(txt, /with one more character\s+rejected/);
    assert.match(txt, /The nonce must never repeat/);
    assert.doesNotMatch(txt, /recovered d|private key is gone/);
    assert.ok(await p.exists('#pkNonceTopics a[data-topic="p09-sigs"]'), 'a link to the signatures topic');
    // the round trip checked again by the engine with the bench's own key and message
    assert.ok(await p.ev("(() => { const st = Sifer.app.page.bench.state().ecdsa, C = Sifer.ECC.P256, k = Sifer.ECC.keygen(C, BigInt(st._dR)); const s = Sifer.ECC.ecdsa.sign(C, k.d, st.msg); return Sifer.ECC.ecdsa.verify(C, k.Q, st.msg, s).ok; })()"));
    await p.click('#pkCurve button[data-v="toy"]');
    await p.click('#pkNonce button[data-v="own"]');
    await set(p, '#pkSd', '45'); await set(p, '#pkSk', '29');
    txt = await out(p);
    assert.match(txt, /valid\s+yes/);
    assert.match(txt, /k\s+29/);
  });

  t.test('Ed25519 reproduces RFC 8032 test 1, and Schnorr signs and verifies', async (p) => {
    await p.route('bench/pk');
    await tool(p, 'ed25519');
    await p.click('#pkErfc');
    await p.sleep(500);
    const txt = await out(p);
    assert.match(txt, /public key\s+d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a/);
    const sig = (await p.ev("[...document.querySelectorAll('#pkEdSig .hx')].map((e) => e.textContent).join('')"));
    assert.equal(sig, 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
    assert.match(txt, /valid\s+yes/);
    await tool(p, 'schnorr');
    await set(p, '#pkZx', '321');
    const t2 = await out(p);
    assert.match(t2, /valid\s+yes/);
    assert.match(t2, /x\s+321/);
    assert.doesNotMatch(t2, /recovered x/);
    assert.match(t2, /The nonce must never repeat/);
  });

  t.test('every tool fits a phone', async (p) => {
    await p.route('bench/pk');
    await p.viewport(390, 844, { mobile: true, touch: true });
    for (const t2 of ['rsa', 'dh', 'elgamal', 'dsa', 'schnorr', 'ecdh', 'x25519', 'ecdsa', 'ed25519']) {
      await tool(p, t2);
      await p.sleep(150);
      assert.ok(await p.noHScroll(), t2 + ' scrolls sideways at 390 px');
    }
    await p.viewport(1400, 900);
  });
}
