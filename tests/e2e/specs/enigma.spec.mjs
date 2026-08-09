// The Enigma page: typing on the deck against the engine, the double step inside, the signal path, cables dragged
// on the plugboard, rings and thumbwheels, key sheets, a Bombe run that finds the planted key and loads it, the
// sounds (off until asked for), share links, and every view at phone width.
import { assert } from '../lib.mjs';

const CFG = { order: ['III', 'I', 'IV'], reflector: 'B', rings: 'FKD', start: 'RZE', window: 'RZE', plugs: 'AQ BW CP DL' };
const ctx = 'Sifer.app.page.ctx';

export default function (t) {
  t.test('typing on the keyboard lights the lamps the engine says, and the tape keeps both', async (p) => {
    await p.route('enigma');
    await p.ev(`${ctx}.setAll(${JSON.stringify(CFG)})`);
    for (const ch of 'secretmeeting') await p.key(ch);
    const want = await p.ev(`Sifer.Enigma.machine(${JSON.stringify(CFG)}).run('SECRETMEETING')`);
    assert.equal(await p.ev(`${ctx}.st.tapeOut`), want);
    assert.equal(await p.ev(`${ctx}.st.tapeIn`), 'SECRETMEETING');
    assert.equal(await p.text('#tapeOut'), want.slice(0, 5) + ' ' + want.slice(5, 10) + ' ' + want.slice(10));
    // a click on a key of the drawing does the same, and its lamp stays lit while it is held
    const before = await p.ev(`${ctx}.st.window`);
    const [x, y] = await p.center('.dk-key[data-letter="Q"] .dk-key-ring');
    await p.mouse('mouseMoved', x, y);
    await p.mouse('mousePressed', x, y, 'left', 1);
    await p.sleep(60);
    const out = await p.ev(`${ctx}.st.tapeOut.slice(-1)`);
    assert.equal(await p.ev("document.querySelector('.dk-lamp.lit').dataset.letter"), out);
    await p.mouse('mouseReleased', x, y, 'left', 1);
    assert.notEqual(await p.ev(`${ctx}.st.window`), before, 'the rotors stepped');
    assert.equal(await p.ev(`Sifer.Enigma.machine(${JSON.stringify(CFG)}).run('SECRETMEETINGQ').slice(-1)`), out);
  });

  t.test('the inside shows the double step: ADU, ADV, AEW, BFX', async (p) => {
    await p.route('enigma/inside');
    await p.click('#inDemo');
    assert.equal(await p.ev(`${ctx}.st.window`), 'ADU');
    const seen = [];
    for (let k = 0; k < 3; k++) { await p.click('#inPress'); seen.push(await p.ev(`${ctx}.st.window`)); }
    assert.deepEqual(seen, ['ADV', 'AEW', 'BFX']);
    assert.ok(await p.exists('#insideHist li.double'), 'the last press is the double step');
    assert.ok(await p.exists('.in-pawl[data-pawl="0"].engaged'), 'the left pawl dropped in');
    assert.ok(await p.exists('.in-rotor[data-slot="1"].stepped'), 'the middle rotor moved');
    assert.match(await p.text('#insideSay'), /double step/);
  });

  t.test('the signal path is drawn through every part on a key press', async (p) => {
    await p.route('enigma/path');
    await p.ev(`${ctx}.setAll(${JSON.stringify(CFG)})`);
    await p.click('.mk[data-letter="E"]');
    assert.ok(await p.exists('#enigPath .pa-cur.fwd') && await p.exists('#enigPath .pa-cur.back'));
    const out = await p.ev(`${ctx}.st.tapeOut`);
    assert.equal(out, await p.ev(`Sifer.Enigma.machine(${JSON.stringify(CFG)}).run('E')`));
    assert.ok(await p.exists('.pa-key.in[data-letter="E"]') && await p.exists(`.pa-key.out[data-letter="${out}"]`));
    const steps = await p.text('#pathSay');
    assert.match(steps, /reflector UKW-B/);
    assert.match(steps, /cable/);
  });

  t.test('cables are dragged between sockets, and pulled out again', async (p) => {
    await p.route('enigma');
    await p.ev(`${ctx}.setAll({ order: ['I','II','III'], rings: 'AAA', start: 'AAA', window: 'AAA', plugs: '' })`);
    const [x1, y1] = await p.center('.pb-socket[data-letter="Q"] .pb-box');
    const [x2, y2] = await p.center('.pb-socket[data-letter="P"] .pb-box');
    await p.drag(x1, y1, x2, y2);
    assert.equal(await p.ev(`${ctx}.st.plugs`), 'PQ');
    assert.ok(await p.exists('.pb-cable[data-pair="PQ"]'));
    assert.equal(await p.ev("document.getElementById('enPlugs').value"), 'PQ');
    // the cable changes the cipher: with it, the machine agrees with the engine's own plugboard
    await p.key('q');
    assert.equal(await p.ev(`${ctx}.st.tapeOut`), await p.ev("Sifer.Enigma.machine({order:['I','II','III'],rings:'AAA',window:'AAA',plugs:'PQ'}).run('Q')"));
    // pressing a plugged socket picks the cable up; letting go on the board pulls it out
    const [x3, y3] = await p.center('.pb-socket[data-letter="Q"] .pb-box');
    await p.drag(x3, y3, x3 + 2, y3 + 260);
    assert.equal(await p.ev(`${ctx}.st.plugs`), '');
    await p.setValue('#enPlugs', 'AB CD', 'change');
    assert.equal(await p.count('.pb-cable'), 2);
    await p.setValue('#enPlugs', 'AB AC', 'change');
    assert.match(await p.text('.enig-err'), /plugged twice/);
  });

  t.test('rings, rotors and the thumbwheels set the machine', async (p) => {
    await p.route('enigma');
    await p.ev(`${ctx}.setAll({ order: ['I','II','III'], rings: 'AAA', start: 'AAA', window: 'AAA', plugs: '' })`);
    await p.setValue('#enRing0', 'C', 'change');
    assert.equal(await p.ev(`${ctx}.st.rings`), 'CAA');
    await p.setValue('#enRotor2', 'V', 'change');
    assert.deepEqual(await p.ev(`${ctx}.st.order`), ['I', 'II', 'V']);
    await p.setValue('#enRotor0', 'II', 'change');
    assert.deepEqual(await p.ev(`${ctx}.st.order`), ['II', 'I', 'V'], 'a rotor taken from another slot swaps');
    await p.click('[data-turn="2:1"]');
    assert.equal(await p.ev(`${ctx}.st.window`), 'AAB');
    await p.click('[data-turn="0:-1"]');
    assert.equal(await p.ev(`${ctx}.st.window`), 'ZAB');
    assert.equal(await p.ev("document.querySelector('.dk-rotor[data-slot=\"0\"] .dk-win-t').textContent"), 'Z');
    assert.equal(await p.ev(`${ctx}.st.start`), 'ZAB', 'the message starts where the rotors were turned to');
    await p.key('a');
    await p.click('#enRewind');
    assert.equal(await p.ev(`${ctx}.st.window`), 'ZAB');
    assert.equal(await p.ev(`${ctx}.st.tapeIn`), '');
  });

  t.test('a key sheet is made from its seed, and a day is set on the machine', async (p) => {
    await p.route('enigma/sheet');
    await p.setValue('#shSeed', 'lantern-77', 'change');
    await p.setValue('#shMonth', '2', 'change');
    await p.setValue('#shYear', '2027', 'change');
    assert.equal(await p.count('#enigSheet tbody tr'), 28, 'February 2027 has 28 days');
    const day = await p.ev("(() => { const s = Sifer.Enigma.keySheet({ seed: 'lantern-77', year: 2027, month: 2, pairs: 10 }); return s.days.find((d) => d.day === 12); })()");
    await p.click('.sh-set[data-day="12"]');
    await p.wait("location.hash === '#enigma'");
    await p.wait('!!(Sifer.app.page && Sifer.app.page.ctx)');
    assert.deepEqual(await p.ev(`${ctx}.st.order`), day.order);
    assert.equal(await p.ev(`${ctx}.st.window`), day.ground);
    assert.equal(await p.ev(`${ctx}.st.plugs`), day.plugs);
  });

  t.test('the Bombe finds the planted key from a crib and loads it into the machine', async (p) => {
    await p.route('enigma/bombe');
    await p.click('#bmPractice');
    assert.ok(await p.exists('#bombeMenu svg .mn-edge.loop'), 'the menu shows its loops');
    assert.match(await p.text('#bmMenuInfo'), /4 loops/);
    assert.ok((await p.count('#bmOffsets .chip')) > 10, 'the possible places');
    await p.click('#bmRun');
    await p.wait("/surviving the check/.test(document.getElementById('bmStatus').textContent)", 60000);
    assert.ok(await p.exists('#bmStops tr.good'));
    assert.match(await p.text('#bmStops tr.good'), /V II IV/);
    await p.click('#bmStops tr.good button');
    assert.match(await p.text('#bmSolved'), /WEATH ERREP ORTFO/);
    await p.click('#bmLoad');
    await p.wait("location.hash === '#enigma'");
    await p.wait('!!(Sifer.app.page && Sifer.app.page.ctx)');
    assert.match(await p.ev(`${ctx}.st.tapeOut`), /^WEATHERREPORTFORTHEHARBOUR/);
    assert.deepEqual(await p.ev(`${ctx}.st.order`), ['V', 'II', 'IV']);
  }, { timeout: 90000 });

  t.test('sounds are off until asked for, and a share link carries the setting', async (p) => {
    await p.route('enigma');
    assert.equal((await p.settings()).sound, false);
    assert.equal(await p.attr('#enSound', 'aria-pressed'), 'false');
    await p.click('#enSound');
    assert.equal((await p.settings()).sound, true);
    assert.equal(await p.attr('#enSound', 'aria-pressed'), 'true');
    await p.key('a');
    await p.click('#enSound');
    assert.equal((await p.settings()).sound, false);
    await p.ev(`Sifer.Pages.get('enigma').load(${JSON.stringify(CFG)})`);
    await p.route('enigma/path');
    assert.equal(await p.ev(`${ctx}.st.rings`), 'FKD');
    assert.equal(await p.ev(`${ctx}.st.plugs`), 'AQ BW CP DL');
  });

  t.test('keys travel: down on the down-stroke, held, and up on release (pointer, keyboard, a typed message)', async (p) => {
    await p.route('enigma');
    await p.ev(`${ctx}.setAll(${JSON.stringify(CFG)})`);
    const down = (L) => p.ev(`document.querySelector('.dk-key[data-letter="${L}"]').classList.contains('down')`);
    const moved = (L) => p.ev(`getComputedStyle(document.querySelector('.dk-key[data-letter="${L}"] .dk-key-top')).transform`);
    // a pointer press held down: the rotors have already stepped and the lamp is lit
    const [x, y] = await p.center('.dk-key[data-letter="Z"] .dk-key-ring');
    await p.mouse('mouseMoved', x, y);
    await p.mouse('mousePressed', x, y, 'left', 1);
    await p.sleep(200);
    assert.ok(await down('Z'), 'the key is down while held');
    assert.notEqual(await moved('Z'), 'none', 'the key top has moved');
    assert.equal(await p.ev(`${ctx}.st.window`), await p.ev(`(() => { const m = Sifer.Enigma.machine(${JSON.stringify(CFG)}); m.press('Z'); return m.window; })()`), 'stepped on the down-stroke');
    const lamp = await p.ev(`${ctx}.st.tapeOut.slice(-1)`);
    assert.equal(await p.ev("document.querySelector('.dk-lamp.lit').dataset.letter"), lamp, 'the lamp is lit while the key is held');
    await p.mouse('mouseReleased', x, y, 'left', 1);
    await p.sleep(250);
    assert.ok(!(await down('Z')), 'the key comes back up');
    assert.equal(await moved('Z'), 'none');
    assert.ok(!(await p.exists('.dk-lamp.lit')), 'the lamp goes out');
    // a physical key: down, held, up
    await p.b.send('Input.dispatchKeyEvent', { type: 'keyDown', windowsVirtualKeyCode: 87, key: 'w', code: 'KeyW', text: 'w' });
    await p.sleep(150);
    assert.ok(await down('W'), 'the physical key holds the drawn key down');
    assert.ok(await p.exists('.dk-lamp.lit'));
    await p.b.send('Input.dispatchKeyEvent', { type: 'keyUp', windowsVirtualKeyCode: 87, key: 'w', code: 'KeyW' });
    await p.sleep(200);
    assert.ok(!(await down('W')), 'and lets it up');
    // a message typed out at a slow pace: each key goes down and up in turn
    await p.click('#enRewind');
    await p.setValue('#enSpeed', 'slow', 'change');
    await p.setValue('#enMessage', 'abc');
    await p.ev(`(() => { window.__seen = []; window.__spy = setInterval(() => { const d = document.querySelector('.dk-key.down'); const L = d ? d.dataset.letter : '-'; if (window.__seen[window.__seen.length - 1] !== L) window.__seen.push(L); }, 15); })()`);
    await p.click('#enTypeAll');
    assert.match(await p.text('#enTypeAll'), /Stop typing/);
    await p.wait(`${ctx}.st.tapeIn === 'ABC' && !${ctx}.typing`, 6000);
    await p.sleep(100);
    const seen = await p.ev('(() => { clearInterval(window.__spy); return window.__seen.filter((x) => x !== "-"); })()');
    assert.deepEqual(seen, ['A', 'B', 'C'], 'each key went down in turn');
    assert.ok(!(await p.exists('.dk-key.down')), 'no key is left down');
    assert.equal(await p.ev(`${ctx}.st.tapeOut`), await p.ev(`Sifer.Enigma.machine(${JSON.stringify(CFG)}).run('ABC')`));
    assert.match(await p.text('#enTypeAll'), /Type it/);
  });

  t.test('every view fits a phone, and the keys still work there', async (p) => {
    await p.viewport(390, 844, { mobile: true, touch: true });
    for (const v of ['enigma', 'enigma/inside', 'enigma/path', 'enigma/sheet', 'enigma/bombe']) {
      await p.route(v);
      await p.sleep(150);
      assert.ok(await p.noHScroll(), v + ' scrolls sideways at 390 px');
    }
    await p.route('enigma');
    assert.ok(await p.ev("document.querySelector('.deck-svg').classList.contains('narrow')"), 'the phone deck');
    const r = await p.rect('.dk-key[data-letter="Q"] .dk-key-ring');
    assert.ok(r.w >= 28, 'a key is ' + r.w + ' px wide');
    await p.tap('.dk-key[data-letter="Q"] .dk-key-ring');
    assert.equal(await p.ev(`${ctx}.st.tapeIn.slice(-1)`), 'Q');
    await p.viewport(1400, 900);
  });
}
