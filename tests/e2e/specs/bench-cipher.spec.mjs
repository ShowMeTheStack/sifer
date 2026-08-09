// The cipher bench: AES-128 on the FIPS 197 example vector, ECB's repeated blocks against CBC, a round opened up,
// the avalanche of a flipped bit, a decryption round trip, a classical cipher, a stream cipher, toy beside real, input
// errors in text, hex and file mode, and the page at phone width.
import { assert } from '../lib.mjs';

const B = 'Sifer.app.page.bench';
async function open(p) { await p.route('bench/cipher'); await p.wait("!!document.querySelector('#cbOut')"); }
async function set(p, patch) { await p.ev(`${B}.set(${JSON.stringify(patch)})`); await p.wait("!!document.querySelector('#cbOut')"); await p.sleep(60); }
async function hexInto(p, id, value) {
  await p.click(`#${id}-mode button[data-v="hex"]`);
  await p.setValue('#' + id, value);
}

export default function (t) {
  t.test('AES-128 gives the FIPS 197 example ciphertext, typed in hex', async (p) => {
    await open(p);
    await p.setValue('#cbAlgo', 'aes128', 'change');
    await p.setValue('#cbMode', 'ecb', 'change');
    await hexInto(p, 'cbKey', '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f');
    await hexInto(p, 'cbText', '00112233445566778899aabbccddeeff');
    await p.wait("document.querySelector('#cbOutLine').innerText.startsWith('69c4e0d86a7b0430d8cdb78070b4c55a')");
    assert.match(await p.text('#cbResult'), /2 blocks · 16 padding bytes/);
    // the round ladder of that block: eleven round states after the input, the last equal to the ciphertext
    assert.equal(await p.count('#cbLadder .lrow'), 12);
    assert.match(await p.ev("[...document.querySelectorAll('#cbLadder .lrow')].pop().innerText.replace(/\\s+/g, '')"), /696ad870/, 'row 0 of the last state: bytes 0, 4, 8 and 12 of 69c4e0d8 6a7b0430 d8cdb780 70b4c55a');
    await p.click('#cbLadder .lrow[data-k="3"]');
    assert.match(await p.text('#cbDetail'), /SubBytes[\s\S]*ShiftRows[\s\S]*MixColumns/);
  });

  t.test('ECB repeats equal blocks; CBC hides them; the flow is drawn', async (p) => {
    await open(p);
    await set(p, { algo: 'aes128', mode: 'ecb', dir: 'enc', view: 'mode' });
    await p.click('#cbRepeat');
    assert.match(await p.text('#cbResult'), /2 repeated ciphertext blocks/);
    assert.equal(await p.count('#cbBlocks tbody tr'), 4);
    await p.setValue('#cbMode', 'cbc', 'change');
    assert.doesNotMatch(await p.text('#cbResult'), /repeated/);
    assert.ok(await p.exists('#cbFlow svg.mflow'));
    assert.ok((await p.count('#cbFlow .mf-xor')) >= 3, 'an XOR per block');
    // the bench runs on the shared engine: its output is S.Modes's, for CBC and for CTS
    const same = await p.ev(`(() => { const L = ${B}.last, S = Sifer, E = S.AES.cipher(L.key); return S.bytes.hex(S.Modes.encrypt('cbc', E, S.Modes.pkcs7(L.data, 16), { iv: L.iv }).out) === S.bytes.hex(L.out); })()`);
    assert.ok(same, 'CBC matches S.Modes.encrypt');
    await p.setValue('#cbMode', 'cts', 'change');
    assert.match(await p.text('#cbResult'), /^Ciphertext\s+48 bytes/);
    const cts = await p.ev(`(() => { const L = ${B}.last, S = Sifer; return S.bytes.hex(S.Modes.cts(S.AES.cipher(L.key), L.data, L.iv).out) === S.bytes.hex(L.out) && L.out.length === L.data.length; })()`);
    assert.ok(cts, 'CTS matches S.Modes.cts and adds nothing');
    await p.setValue('#cbMode', 'cfb8', 'change');
    assert.ok((await p.count('#cbBlocks tbody tr')) >= 32, 'a row per byte');
  });

  t.test('decrypting the output gives the message back, in every mode', async (p) => {
    await open(p);
    for (const mode of ['ecb', 'cbc', 'cfb', 'cfb8', 'ofb', 'ctr', 'cts', 'gcm', 'xts']) {
      await set(p, { algo: 'aes128', mode, dir: 'enc', view: 'mode', key: mode === 'xts' ? { mode: 'text', text: 'quiet larch 2026saltmarsh-iv-016', hex: '' } : { mode: 'text', text: 'quiet larch 2026', hex: '' }, text: { mode: 'text', text: 'Bring the lantern to the north gate at nine.', hex: '' } });
      await p.click('#cbSwap');
      await p.wait("!!document.querySelector('#cbOutText')");
      assert.equal(await p.text('#cbResult #cbOutText'), 'Bring the lantern to the north gate at nine.', mode);
    }
    // GCM refuses a ciphertext whose tag does not match
    await set(p, { algo: 'aes128', mode: 'gcm', dir: 'enc', view: 'mode' });
    assert.match(await p.text('#cbResult'), /ciphertext then its 16-byte tag/);
    await p.click('#cbSwap');
    const hx = await p.ev("document.getElementById('cbText').value");
    await p.setValue('#cbText', hx.slice(0, -1) + (hx.endsWith('0') ? '1' : '0'));
    assert.match(await p.text('#cbOut .berr'), /tag does not match/);
    // a wrong key fails the padding check, said plainly
    await set(p, { algo: 'aes128', mode: 'cbc', dir: 'enc', view: 'mode', key: { mode: 'text', text: 'quiet larch 2026', hex: '' } });
    await p.click('#cbSwap');
    await p.setValue('#cbKey', 'quiet larch 2027');
    assert.match(await p.text('.berr'), /padding does not check out/);
  });

  t.test('the avalanche: one flipped bit spreads to about half', async (p) => {
    await open(p);
    await set(p, { algo: 'aes128', mode: 'ecb', dir: 'enc', view: 'aval', aval: { target: 'plaintext', bit: 9 } });
    await p.wait("!!document.querySelector('#cbAvalSum')");
    const s = await p.text('#cbAvalSum');
    const m = /at the end (\d+) of 128/.exec(s);
    assert.ok(m && +m[1] > 40 && +m[1] < 90, s);
    assert.equal(await p.count('#cbAvalRows .aval-row'), 12);
    assert.match(await p.ev("document.querySelector('#cbAvalRows .aval-row .ar-n').innerText"), /^1 \/ 128/);
    await p.click('#cbBits .bit[data-i="100"]');
    await p.wait("/Bit 100 /.test(document.querySelector('#cbAvalSum').innerText)");
    await p.click('#cbAvalTarget button[data-v="key"]');
    await p.wait("/of the key flipped/.test(document.querySelector('#cbAvalSum').innerText)");
    // a stream cipher: one plaintext bit flips exactly one ciphertext bit
    await set(p, { algo: 'chacha20', dir: 'enc', view: 'aval', aval: { target: 'plaintext', bit: 3 } });
    await p.wait("!!document.querySelector('#cbAvalSum')");
    assert.match(await p.text('#cbAvalSum'), /at the end 1 of/);
  });

  t.test('classical ciphers, a stream cipher, and toy beside real', async (p) => {
    await open(p);
    await set(p, { algo: 'aes128', dir: 'enc' });
    await p.setValue('#cbAlgo', 'shift', 'change');
    await p.setValue('#cbText', 'Meet at dawn');
    await p.setValue('#cbKey', '3');
    assert.equal(await p.text('#cbOutText'), 'PHHW DW GDZQ');
    await p.setValue('#cbAlgo', 'playfair', 'change');
    assert.equal(await p.count('.pf-square span'), 25);
    await p.setValue('#cbAlgo', 'affine', 'change');
    await p.setValue('#cbKey', '13, 2');
    assert.match(await p.text('.berr'), /shares a factor with 26/);
    await p.setValue('#cbAlgo', 'trivium', 'change');
    await p.click('#cbViews button[data-v="registers"]');
    assert.equal(await p.count('#cbRegisters i'), 288);
    await p.setValue('#cbAlgo', 'chacha20', 'change');
    assert.equal(await p.count('#cbKeystream tbody tr'), 6);
    await p.click('#cbViews button[data-v="rounds"]');
    assert.equal(await p.count('#cbLadder .lrow'), 12, 'the initial state, ten double rounds and the input added back');
    await set(p, { algo: 'miniaes', mode: 'ecb', dir: 'enc', view: 'rounds', toy: true });
    assert.ok(await p.exists('#cbToyCard'));
    assert.match(await p.text('#cbToyCard'), /Mini-AES[\s\S]*AES-128/);
  });

  t.test('input errors are said plainly, in text, hex and file mode', async (p) => {
    await open(p);
    await set(p, { algo: 'aes128', mode: 'cbc', dir: 'enc', view: 'rounds' });
    await p.setValue('#cbKey', 'too short');
    assert.match(await p.text('#cbOut .berr'), /exactly 16 bytes; it is 9/);
    await p.click('#cbKey-mode button[data-v="hex"]');
    await p.setValue('#cbKey', '00 11 zz');
    assert.match(await p.text('[data-field="cbKey"] .bf-info'), /not a hex digit/);
    await p.click('#cbKey-mode button[data-v="file"]');
    assert.match(await p.text('#cbOut .berr'), /choose a file first/);
    await p.click('#cbKey-mode button[data-v="text"]');
    await p.setValue('#cbKey', 'quiet larch 2026');
    assert.ok(!(await p.exists('#cbOut .berr')));
  });

  t.test('the setup is kept, and the bench fits a phone', async (p) => {
    await open(p);
    await set(p, { algo: 'des', mode: 'ctr', dir: 'enc', view: 'mode' });
    await p.sleep(600);
    await p.reload();
    await p.route('bench/cipher');
    assert.equal(await p.ev("document.getElementById('cbAlgo').value"), 'des');
    assert.ok(await p.fitsPhone(), 'no sideways scroll at 390 px');
  });

  t.test('the labs: defence cards for the real modes, and every toy-cipher lab to its end', async (p) => {
    await open(p);
    await p.ev(`${B}.lab('padding')`);
    // no runner against a real mode: each card explains the defence and links to part 6
    for (const [id, topic] of [['padding', 'integrity-order'], ['ecbcut', 'modes-ecb'], ['bitflip', 'integrity-malleable'], ['ctrreuse', 'integrity-nonce'], ['gcmreuse', 'integrity-nonce']]) {
      await p.click(`.lab-item[data-lab="${id}"]`);
      assert.ok(!(await p.exists('#labBody #labRun')), id + ' has no runner');
      assert.ok(await p.exists(`#labBody .lab-topics a[data-topic="${topic}"]`), id + ' links to ' + topic);
    }
    await p.click('#labBody .lab-topics a[data-topic="integrity-nonce"]');
    await p.wait("location.hash === '#topic=integrity-nonce'");
    await open(p);
    await p.ev(`${B}.lab('geffe')`);
    for (const [id, done] of [['geffe', '#geffeOk.ok-line']]) {
      await p.click(`.lab-item[data-lab="${id}"]`);
      await p.click('#labRun');
      await p.wait(`!!document.querySelector(${JSON.stringify(done)})`, 20000);
    }
    await p.click('.lab-item[data-lab="mitm"]');
    await p.setValue('#mitmBits', '10');
    await p.click('#labRun');
    await p.wait("!!document.querySelector('#mitmOk.ok-line')", 20000);
    await p.click('.lab-item[data-lab="spn"]');
    await p.click('#labRun');
    await p.wait("!!document.querySelector('#spnOk')", 30000);
    assert.equal(await p.count('#spnNibs .spn-nib'), 4);
    await p.click('.lab-item[data-lab="twotime"]');
    assert.ok((await p.count('#otpCribRows tbody tr')) > 0, 'crib dragging shows fits');
    await p.click('#otpRecover');
    await p.wait("!!document.getElementById('otpDone')", 30000);
    await p.click('.lab-item[data-lab="bm"]');
    await p.setValue('#bmBits', '1011001110001111');
    assert.match(await p.text('#bmL'), /^\d+$/);
    assert.ok(await p.fitsPhone(), 'the labs fit a phone');
  }, { timeout: 120000 });
}
