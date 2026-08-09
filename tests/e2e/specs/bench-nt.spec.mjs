// The number-theory bench: Euclid filling row by row, the CRT, square-and-multiply, the ring of powers, Miller–Rabin
// against a Carmichael number, GF(2^8) and GF(p), and every tool at phone width. Values are checked against the engines.
import { assert } from '../lib.mjs';

const tool = async (p, t) => { await p.click('#nt-tool button[data-v="' + t + '"]'); await p.wait("!!document.querySelector('#ntOut .bcard, #ntOut .berr')"); };
const set = async (p, sel, v) => { await p.setValue(sel, v); await p.sleep(420); };
const facts = (p) => p.text('#ntOut');

export default function (t) {
  t.test('extended Euclid fills its table row by row and gives the Bézout identity', async (p) => {
    await p.route('bench/nt');
    await tool(p, 'euclid');
    await set(p, '#ntA', '240');
    await set(p, '#ntB', '46');
    const txt = await facts(p);
    assert.match(txt, /gcd\(a, b\)\s+2/);
    assert.match(txt, /240·\(-9\) \+ 46·\(47\) = 2/);
    assert.equal(await p.count('#ntEuclidTable tbody tr'), 7, 'all rows at first');
    await p.click('#ntEuclidStep button[title="Only the first row"]');
    assert.equal(await p.count('#ntEuclidTable tbody tr'), 2);
    await p.click('#ntEuclidStep button[title="The next row"]');
    assert.equal(await p.count('#ntEuclidTable tbody tr'), 3);
    assert.match(await p.text('#ntEuclidSay'), /q = 240 div 46 = 5/);
    await set(p, '#ntA', '17'); await set(p, '#ntB', '3120');
    assert.match(await facts(p), /a⁻¹ mod b\s+2753/);
    await set(p, '#ntA', 'twelve');
    assert.match(await p.text('#ntOut .berr'), /not a whole number/);
  });

  t.test('the CRT solves a system, builds it term by term, and handles shared factors', async (p) => {
    await p.route('bench/nt');
    await tool(p, 'crt');
    const want = await p.ev("String(Sifer.NT.crt([2n, 3n, 10n], [5n, 7n, 11n]).x)");
    assert.match(await facts(p), new RegExp('\\bx\\s+' + want + '\\b'));
    assert.equal(await p.count('#ntCrtTable tbody tr'), 3);
    await p.click('#ntCrtAdd');
    assert.equal(await p.count('.mb-crt-row'), 4);
    await p.click('.mb-ex .chip', 'no solution');
    await p.sleep(100);
    assert.match(await facts(p), /No solution/);
    await p.click('.mb-ex .chip', 'shared factor');
    await p.sleep(100);
    assert.match(await facts(p), /x\s+\d+\s+modulo\s+36/);
  });

  t.test('square-and-multiply: 7^560 mod 561 = 1, bit by bit', async (p) => {
    await p.route('bench/nt');
    await tool(p, 'power');
    await p.click('.mb-ex .chip', '7^560 mod 561');
    await p.sleep(100);
    assert.match(await facts(p), /x\^e mod n\s+1\b/);
    assert.equal(await p.count('#ntBits .mb-bit'), 10, '560 has ten bits');
    assert.equal(await p.count('#ntBits .mb-bit.one'), 3);
    const sq = await p.ev('Sifer.ModExp.pow(7n, 560n, 561n).squarings');
    assert.match(await facts(p), new RegExp('squarings\\s+' + sq));
  });

  t.test('the order of an element, drawn as its ring of powers', async (p) => {
    await p.route('bench/nt');
    await tool(p, 'order');
    await p.click('.mb-ex .chip', '3 mod 31');
    await p.sleep(100);
    assert.equal(await p.count('.mb-ring .mb-node'), 30);
    assert.match(await facts(p), /generator\?\s+yes/);
    await p.click('.mb-ex .chip', '2 mod 31');
    await p.sleep(100);
    assert.equal(await p.count('.mb-ring .mb-node'), 5);
    assert.match(await facts(p), /ord\(a\)\s+5/);
    assert.match(await facts(p), /generator\?\s+no/);
    assert.ok((await p.count('#ntRoots .mb-chip')) === 8, 'φ(30) = 8 primitive roots of 31');
    await set(p, '#ntOa', '6'); await set(p, '#ntOn', '9');
    assert.match(await p.text('#ntOut .berr'), /not a unit/);
  });

  t.test('Miller–Rabin unmasks a Carmichael number that Fermat\'s test passes', async (p) => {
    await p.route('bench/nt');
    await tool(p, 'prime');
    await p.click('.mb-ex .chip', '561 (Carmichael)');
    await p.sleep(100);
    const txt = await facts(p);
    assert.match(txt, /561 is composite; 2 is a witness/);
    assert.match(txt, /263 → 166 → 67 → 1/);
    const liars = await p.ev('Sifer.NT.fermatLiars(561n).length');
    assert.match(txt, new RegExp('Fermat liars\\s+' + liars));
    await p.click('#ntTest button[data-v="fermat"]');
    await p.sleep(100);
    assert.match(await facts(p), /every base passes/);
    await p.click('#ntTest button[data-v="mr"]');
    await p.click('.mb-ex .chip', 'a 61-bit prime');
    await p.sleep(150);
    assert.match(await facts(p), /probably prime/);
  });

  t.test('GF(2^8): 57 · 83 = c1 and the inverse of 53 is ca; GF(p) inverses and roots', async (p) => {
    await p.route('bench/nt');
    await tool(p, 'field');
    await p.click('.mb-ex .chip', 'AES: 57 · 83');
    await p.sleep(100);
    assert.match(await facts(p), /a · b\s+0xc1/);
    assert.equal(await p.count('#ntGfMulTable tbody tr'), 8);
    await p.click('.mb-ex .chip', 'AES: 53⁻¹');
    await p.sleep(100);
    assert.match(await facts(p), /a⁻¹\s+0xca/);
    await p.click('.mb-ex .chip', 'GF(29): 7⁻¹');
    await p.sleep(100);
    assert.match(await facts(p), /a⁻¹\s+25 \(check: 7 · 25 ≡ 1\)/);
    await p.click('.mb-ex .chip', 'GF(103): √46');
    await p.sleep(100);
    const r = await p.ev('String(Sifer.GF.prime(103n).sqrt(46n))');
    assert.match(await facts(p), new RegExp('±' + r));
    await set(p, '#ntFp', '91');
    assert.match(await p.text('#ntOut .berr'), /not prime/);
  });

  t.test('every tool fits a phone, and the inputs come back after a reload', async (p) => {
    await p.route('bench/nt');
    await tool(p, 'euclid');
    await set(p, '#ntA', '9999');
    await p.reload();
    assert.equal(await p.ev("document.getElementById('ntA').value"), '9999');
    await p.viewport(390, 844, { mobile: true, touch: true });
    for (const t2 of ['euclid', 'crt', 'power', 'order', 'prime', 'field']) {
      await tool(p, t2);
      await p.sleep(150);
      assert.ok(await p.noHScroll(), t2 + ' scrolls sideways at 390 px');
    }
    await p.viewport(1400, 900);
  });
}
