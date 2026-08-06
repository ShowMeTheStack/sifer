// Lesson blocks beyond the basic ones (lessons.js lists them all): bytes as a hex grid, a scene of the demo page,
// and cards that open a bench, a sandbox task, the Enigma set up for the lesson (enigma, enigmaLab at a view) or the
// Bombe loaded with an intercept (bombeLab).
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const LB = (S.LessonBlocks = S.LessonBlocks || {});
  const inline = (t) => S.UI.inline(t);
  const figure = (el, caption, cls) => h('figure.ls-fig' + (cls ? '.' + cls : ''), el, caption ? h('figcaption', inline(caption)) : null);
  const card = (href, ic, kind, title, meta) => h('a.ls-link', { href }, h('span.tc-icon', icon(ic)), h('span', h('span.kind', kind), h('b', title), meta ? h('span.meta', meta) : null), h('span.go', '→'));

  /** {bytes: 'hex' | {hex, cols, hl: [i], key: [i], label}} */
  LB.bytes = function (b) {
    const o = typeof b.bytes === 'string' ? { hex: b.bytes } : b.bytes;
    const hex = String(o.hex).replace(/[^0-9a-f]/gi, '').toLowerCase();
    const n = hex.length >> 1, cols = o.cols || 16, hl = new Set(o.hl || []), key = new Set(o.key || []);
    const grid = h('div.byte-grid', { style: { gridTemplateColumns: 'repeat(' + Math.min(cols, n) + ', minmax(0, 2.4em))' } });
    for (let i = 0; i < n; i++) grid.appendChild(h('span.bg-b' + (hl.has(i) ? '.hl' : '') + (key.has(i) ? '.key' : ''), { title: 'byte ' + i }, hex.slice(2 * i, 2 * i + 2)));
    return figure(h('div.byte-box', o.label ? h('div.bg-label', o.label) : null, grid), b.caption, 'bytes');
  };
  /** {scene: 'demo scene id'}: the scene with its own small player */
  LB.scene = function (b, page) {
    const sc = S.Demo && S.Demo.byId && S.Demo.byId(b.scene);
    if (!sc) return figure(S.UI.empty('watch', 'A figure is missing here', 'It shows the scene "' + b.scene + '", which is not in this build.'), b.caption);
    const p = new S.Player(sc);
    const box = h('div.ls-scene', p.el);
    box._redraw = () => p.resized();
    requestAnimationFrame(() => { try { p.build(); } catch (e) { /* drawn on the next resize */ } });
    if (page) (page.scenes = page.scenes || []).push(p);
    if (S.app) S.app.players.push(p);
    return figure(box, b.caption, 'scene');
  };
  const BENCH = { cipher: 'Cipher bench', nt: 'Number-theory bench', pk: 'Public-key bench', curve: 'Curve explorer', hash: 'Hash bench', proto: 'Protocol bench' };
  /** {bench: 'cipher', state: {...}, text}: a card that opens the bench (with that state) */
  LB.bench = function (b) {
    const id = b.bench;
    const a = card('#bench/' + id, 'cipher', 'Try it on the bench', BENCH[id] || 'The bench', b.text || '');
    if (b.state) a.addEventListener('click', () => { if (S.Bench) S.Bench.preset(id, b.state); });
    return a;
  };
  /** {sandbox: 'task id'} */
  LB.sandbox = function (b) {
    const t = S.Sandbox && S.Sandbox.tasks && S.Sandbox.tasks.find((x) => x.id === b.sandbox);
    return card('#sandbox/' + b.sandbox, 'code', 'Write it yourself', t ? t.title : 'A sandbox task', t ? t.blurb : '');
  };
  /** {enigma: {order, reflector, rings, window, plugs}, text} */
  LB.enigma = function (b) {
    const a = card('#enigma', 'rotor', 'On the machine', 'Enigma I', b.text || '');
    a.addEventListener('click', () => { if (S.EnigmaPage && b.enigma) S.EnigmaPage.preset(b.enigma); });
    return a;
  };
  // labs: the Enigma opened at one of its views, and the Bombe loaded with an intercept
  const labCard = (href, bombe, title, meta) => h('a.ls-link', { href }, h('span.tc-icon', icon(bombe ? 'search' : 'rotor')), h('span', h('span.kind', bombe ? 'Lab: the Bombe' : 'Lab: on the machine'), h('b', title), meta ? h('span.meta', inline(meta)) : null), h('span.go', '→'));
  /** {enigmaLab: {order, rings, window, plugs}, view: '' | 'inside' | 'path', title, text} */
  LB.enigmaLab = function (b) {
    const view = b.view || '';
    const a = labCard('#enigma' + (view ? '/' + view : ''), false, b.title || 'Enigma I', b.text || '');
    a.addEventListener('click', () => { if (S.EnigmaPage) S.EnigmaPage.preset(Object.assign({ reflector: 'B', rings: 'AAA', plugs: '' }, b.enigmaLab)); });
    return a;
  };
  /** {bombeLab: {seed, plain, crib, offset}, title, text}: the intercept is enciphered here, with a key made from the seed */
  LB.bombeLab = function (b) {
    const o = b.bombeLab;
    const a = labCard('#enigma/bombe', true, b.title || 'Open the Bombe', b.text || '');
    a.addEventListener('click', () => {
      const key = S.Enigma.randomKey(S.Enigma.rng(o.seed), { pairs: 10 });
      S.UI.storage.set('enigma.bombe', { cipher: S.Enigma.encrypt(key, o.plain), crib: o.crib, offset: o.offset || 0 });
    });
    return a;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
