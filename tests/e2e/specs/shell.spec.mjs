// The frame of the app: the top bar and its routes, the home page and its live avalanche, themes and projector mode,
// settings, the shortcuts sheet, About and the author, a missing page, the demo page, and every page at phone width.
import { assert } from '../lib.mjs';

const PAGES = ['', 'topics', 'learn', 'courses', 'bench', 'enigma', 'ctf', 'sandbox', 'demo'];

export default function (t) {
  t.test('the top bar routes to every section and lights the one open', async (p) => {
    for (const id of ['topics', 'learn', 'courses', 'bench', 'enigma', 'ctf', 'sandbox']) {
      await p.route(id);
      assert.equal(await p.ev("(document.querySelector('#topNav button.on') || {}).dataset?.route || ''"), id, 'nav for ' + id);
    }
    await p.route('lesson=nowhere');
    assert.equal(await p.ev("document.querySelector('#topNav button.on').dataset.route"), 'learn', 'an alias lights its page');
    await p.click('#brand');
    await p.wait("location.hash === '' || location.hash === '#'");
    assert.ok(await p.exists('.hero'));
    await p.click('#topNav button[data-route="ctf"]');
    await p.wait("location.hash === '#ctf'");
  });

  t.test('the home page: the live avalanche, the benches, the machines and the parts', async (p) => {
    await p.route('');
    await p.wait("!!document.querySelector('#heroArt svg.hero-svg')");
    assert.match(await p.text('#heroCap'), /AES-128/);
    assert.equal(await p.count('#heroArt .hg.d .hg-box'), 16, 'sixteen heat cells');
    assert.ok((await p.count('.tool-card')) >= 9);
    await p.click('#toCipher');
    await p.wait("location.hash === '#bench/cipher'");
    await p.route('');
    await p.click('#toEnigma');
    await p.wait("location.hash === '#enigma'");
  });

  t.test('a page that is not there says so', async (p) => {
    await p.route('nowhere-at-all');
    assert.match(await p.text('.notice'), /no page called/);
  });

  t.test('light and dark, projector mode, and settings', async (p) => {
    await p.route('topics');
    const t0 = await p.theme();
    await p.click('#btnTheme');
    assert.notEqual(await p.theme(), t0);
    await p.key('t');
    assert.equal(await p.theme(), t0);
    await p.click('#btnProjector');
    assert.equal(await p.ev('document.documentElement.dataset.projector'), 'on');
    await p.key('P', { shift: true });
    assert.equal(await p.ev('document.documentElement.dataset.projector'), 'off');
    await p.click('#btnAbout');
    await p.click('.menu-pop .menu-item', 'Settings');
    assert.equal(await p.waitModal(), 'Settings');
    assert.ok(await p.exists('#set-sound'), 'machine sounds');
    assert.equal(await p.ev("document.getElementById('set-sound').checked"), false, 'sounds are off by default');
    await p.setValue('#set-theme', 'dark', 'change');
    assert.equal(await p.theme(), 'dark');
    await p.setValue('#set-theme', 'light', 'change');
    assert.match(await p.text('#engineStatus'), /Engines: Classical/);
    await p.closeModals();
    assert.equal((await p.settings()).theme, 'light');
  });

  t.test('the shortcuts sheet and About, with the author and every sister tool', async (p) => {
    await p.route('');
    await p.key('?');
    assert.equal(await p.waitModal(), 'Keyboard shortcuts');
    assert.match(await p.modalText(), /Light or dark/);
    await p.closeModals();
    await p.click('#btnAbout');
    await p.click('.menu-pop .menu-item', 'About Sifer');
    assert.equal(await p.waitModal(), 'About Sifer');
    const about = await p.modalText();
    assert.match(about, /GNU General Public License/);
    for (const name of ['See', 'Strux', 'Baysik', 'Lohgo', 'Kwery', 'Tooring', 'Sirkit']) assert.match(about, new RegExp(name), name);
    await p.closeModals();
    await p.click('#btnAbout');
    await p.click('.menu-pop .menu-item', 'About the author');
    assert.equal(await p.waitModal(), 'About the author');
    const text = await p.modalText();
    assert.match(text, /Jyotiprakash Mishra/);
    for (const name of ['See', 'Strux', 'Baysik', 'Lohgo', 'Kwery', 'Tooring', 'Sirkit']) assert.match(text, new RegExp(name), name);
    assert.ok(await p.ev("!!document.querySelector('.author-photo img').getAttribute('src').startsWith('data:image/png')"), 'the photo');
    await p.closeModals();
  });

  t.test('the demo page shows every sample scene, and its players step', async (p) => {
    await p.route('demo');
    const n = await p.ev('Sifer.Demo.scenes.length');
    assert.ok(n >= 10, 'scenes: ' + n);
    assert.equal(await p.count('section.scene'), n);
    const id = await p.ev('Sifer.Demo.scenes[0].id');
    await p.ev(`Sifer.app.byId[${JSON.stringify(id)}].go(1, true)`);
    assert.match(await p.text('#' + id + ' .say'), /Step 2 of/i);
  });

  t.test('the menu on a phone, and every page fits the phone width', async (p) => {
    await p.viewport(390, 844, { mobile: true, touch: true });
    await p.route('');
    assert.ok(await p.visible('#btnMenu'), 'the menu button');
    assert.ok(!(await p.visible('#topNav button[data-route="ctf"]')), 'the sections are folded away');
    await p.click('#btnMenu');
    assert.ok(await p.visible('#topNav button[data-route="ctf"]'));
    await p.click('#topNav button[data-route="ctf"]');
    await p.wait("location.hash === '#ctf'");
    for (const id of PAGES) {
      await p.route(id);
      await p.sleep(150);
      assert.ok(await p.noHScroll(), 'the page ' + (id || 'home') + ' scrolls sideways at 390 px');
    }
    await p.viewport(1400, 900);
  });
}
