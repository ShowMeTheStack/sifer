// The Sifer app: the top bar, routing between the home page, Topics, Learn, Courses, the benches, the Enigma, the
// CTF ladder and the sandbox, the demo page of sample scenes (#demo), settings, About, keyboard shortcuts and share
// links. Pages register themselves with S.Pages (ui.js); this file only frames them.
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const store = S.UI.storage;
  const TITLE = 'Sifer: cryptography you can see inside';
  const NAV = [['topics', 'Topics', 'library'], ['learn', 'Learn', 'learn'], ['courses', 'Courses', 'route'], ['bench', 'Bench', 'cipher'], ['enigma', 'Enigma', 'rotor'], ['ctf', 'CTF', 'flag'], ['sandbox', 'Sandbox', 'code']];
  // other names a link may use for a page
  const ALIAS = { topic: 'topics', part: 'topics', lesson: 'learn', exercise: 'learn', tour: 'learn', course: 'courses', bombe: 'enigma', challenge: 'ctf' };
  /** the frame element that carries menu-open and no-side (the shell's #app, or the body) */
  const frame = () => document.getElementById('app') || document.body;

  class App {
    constructor() {
      S.app = this;
      this.settings = Object.assign({ theme: 'auto', projector: false, animate: true, autosave: true, sound: false }, store.get('settings', {}));
      this.applyTheme();
      try { matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (this.settings.theme === 'auto') this.applyTheme(); }); } catch (e) { /* old browsers */ }
      this.players = [];
      this.byId = {};
      this.buildTop();
      window.addEventListener('hashchange', () => this.route());
      document.addEventListener('keydown', (e) => this.onKey(e));
      let lastW = innerWidth;
      window.addEventListener('resize', () => { if (innerWidth === lastW) return; lastW = innerWidth; for (const p of this.players) p.resized(); });
      this.route();
    }
    saveSettings() { store.set('settings', this.settings); }
    get theme() { return document.documentElement.dataset.theme; }
    applyTheme() {
      let t = this.settings.theme;
      if (t === 'auto') { try { t = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'; } catch (e) { t = 'light'; } }
      document.documentElement.dataset.theme = t;
      document.documentElement.dataset.projector = this.settings.projector ? 'on' : 'off';
      const meta = document.querySelector('meta[name="theme-color"]');
      if (meta) meta.setAttribute('content', t === 'dark' ? '#161a2d' : '#ffffff');
      if (this.btnTheme) { this.btnTheme.innerHTML = ''; this.btnTheme.appendChild(icon(t === 'dark' ? 'sun' : 'moon')); }
      if (this.btnProj) { this.btnProj.classList.toggle('on', !!this.settings.projector); this.btnProj.setAttribute('aria-pressed', String(!!this.settings.projector)); }
    }
    setTheme(t) { this.settings.theme = t; this.saveSettings(); this.applyTheme(); this.redraw(); }
    toggleTheme() { this.setTheme(this.theme === 'dark' ? 'light' : 'dark'); }
    setProjector(on) { this.settings.projector = on; this.saveSettings(); this.applyTheme(); this.redraw(); }
    redraw() {
      if (this.page && this.page.redraw) this.page.redraw();
      for (const p of this.players) p.resized();
    }
    markDone(t) { if (S.Learner) S.Learner.markDone(t); }

    // ---- the frame of the page -------------------------------------------------------------------------
    buildTop() {
      const top = document.getElementById('top');
      // the shell may predate the sections: the menu button and the nav are made here when it has none
      let menu = document.getElementById('btnMenu');
      if (!menu) { menu = h('button.icon-btn', { id: 'btnMenu', type: 'button', 'aria-label': 'Sections', title: 'Sections' }); top.insertBefore(menu, top.firstChild); }
      let nav = document.getElementById('topNav');
      if (!nav) { nav = h('nav.top-nav', { id: 'topNav', 'aria-label': 'Sections' }); document.getElementById('brand').after(nav); }
      if (!document.getElementById('app')) document.body.classList.add('app');
      menu.innerHTML = '';
      menu.appendChild(icon('menu'));
      menu.setAttribute('aria-expanded', 'false');
      menu.addEventListener('click', () => { const on = frame().classList.toggle('menu-open'); menu.setAttribute('aria-expanded', String(on)); });
      document.getElementById('brand').addEventListener('click', (e) => { e.preventDefault(); location.hash = ''; });
      for (const [id, label, ic] of NAV) {
        const b = h('button', { type: 'button', dataset: { route: id }, title: label }, icon(ic), h('span', label));
        b.addEventListener('click', () => { frame().classList.remove('menu-open'); location.hash = id; });
        nav.appendChild(b);
      }
      const tools = document.getElementById('topTools');
      tools.innerHTML = '';
      this.btnProj = h('button.icon-btn', { type: 'button', title: 'Projector mode: large type and strong lines for a classroom (Shift+P)', 'aria-label': 'Projector mode', id: 'btnProjector' }, icon('screen'));
      this.btnProj.addEventListener('click', () => this.setProjector(!this.settings.projector));
      this.btnTheme = h('button.icon-btn', { type: 'button', title: 'Light or dark (T)', 'aria-label': 'Light or dark', id: 'btnTheme' });
      this.btnTheme.addEventListener('click', () => this.toggleTheme());
      const about = h('button.icon-btn', { type: 'button', title: 'Help, settings and About', 'aria-label': 'Help and About', id: 'btnAbout' }, icon('help'));
      about.addEventListener('click', () => this.aboutMenu(about));
      tools.append(this.btnProj, this.btnTheme, about);
      this.applyTheme();
    }
    aboutMenu(anchor) {
      const r = anchor.getBoundingClientRect();
      S.UI.showMenu([
        { label: 'Keyboard shortcuts', sc: '?', action: () => this.shortcuts() },
        { label: 'Settings…', action: () => this.settingsDialog() },
        { label: 'The sample scenes', action: () => { location.hash = 'demo'; } },
        { sep: true },
        { label: 'About Sifer', action: () => this.about() },
        { label: 'About the author', action: () => S.authorDialog && S.authorDialog() },
      ], r.right - 220, r.bottom + 4, { anchor, keyboard: true });
    }

    /** the page a hash names: [page id, the rest] */
    pageOf(hash) {
      const m = /^([a-z]+)(?:[=/?](.*))?$/i.exec(hash);
      if (!m) return [null, ''];
      return [ALIAS[m[1]] || m[1], hash];
    }
    route() {
      let hash = '';
      try { hash = decodeURIComponent(location.hash.replace(/^#\/?/, '')); } catch (e) { hash = location.hash.replace(/^#\/?/, ''); }
      window.__siferReady = false;
      frame().classList.remove('menu-open');
      if (this.page && this.page.dispose) try { this.page.dispose(); } catch (e) { /* gone */ }
      for (const p of this.players) p.stop();
      this.page = null; this.players = []; this.byId = {};
      if (this.hero) { this.hero.stop(); this.hero = null; }
      const main = document.getElementById('main');
      main.innerHTML = '';
      main.className = 'main';
      document.title = TITLE;
      if (hash.startsWith('share=')) { this.openShared(hash.slice(6)); return; }
      const [id, rest] = this.pageOf(hash);
      const pg = id && S.Pages.get(id);
      if (pg) {
        this.setNav(pg.nav || id);
        if (pg.wide) main.classList.add('wide');
        try { this.page = pg.open(this, main, rest) || {}; }
        catch (e) { main.innerHTML = ''; main.appendChild(S.UI.empty('warn', 'This page could not open', String(e.message || e))); if (typeof console !== 'undefined') console.error(e); }
        if (pg.title) document.title = pg.title + ' · Sifer';
        if (!this.page || !this.page.async) requestAnimationFrame(() => { window.__siferReady = true; });
        window.scrollTo(0, 0);
        return;
      }
      this.setNav('');
      this.renderHome(main, hash ? 'There is no page called "' + hash + '". It may have been renamed: start from here.' : null);
      window.scrollTo(0, 0);
      requestAnimationFrame(() => { window.__siferReady = true; });
    }
    setNav(navOf) {
      for (const b of document.querySelectorAll('#topNav button')) { const on = b.dataset.route === navOf; b.classList.toggle('on', on); if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); }
    }

    // ---- home --------------------------------------------------------------------------------------------
    renderHome(main, notice) {
      const box = h('div.home', { id: 'homeView' });
      if (notice) box.appendChild(h('div.notice', icon('info'), h('span', notice)));
      const art = h('div.hero-art', { id: 'heroArt' });
      const start = h('button.btn.primary', { type: 'button', id: 'btnStart' }, icon('cipher'), 'Open the cipher bench');
      start.addEventListener('click', () => { location.hash = 'bench/cipher'; });
      const learn = h('button.btn', { type: 'button', id: 'btnToTopics' }, icon('library'), 'Browse the topics');
      learn.addEventListener('click', () => { location.hash = 'topics'; });
      box.appendChild(h('section.hero',
        h('div.hero-text', h('h1', 'Cryptography you can see inside.'),
          h('p.lead', 'Every cipher, hash and curve opens up: every intermediate value drawn in hex or as bits that light up, data flowing along wires, and diffusion spreading as a heat map. Toy and real sizes sit side by side, and every weakness comes with the rule that prevents it.'),
          h('div.cta', start, learn),
          h('p.hero-stats', 'Every engine reproduces the published test vectors, and the real-size ones agree with a standard library, value for value.')),
        h('div.hero-show', art, h('div.hero-cap', { id: 'heroCap', 'aria-live': 'off' }))));
      const tool = (id, ic, title, text, hash) => { const b = h('button.tool-card', { type: 'button', id }, h('span.tc-icon', icon(ic)), h('span.tc-text', h('b', title), h('span', text))); b.addEventListener('click', () => { location.hash = hash; }); return b; };
      box.appendChild(h('h2.sub-title', 'Benches: run anything, see everything'));
      box.appendChild(h('section.home-tools',
        tool('toCipher', 'cipher', 'Cipher bench', 'Classical ciphers to AES, ChaCha20 and PRESENT, any mode, every round value, and the avalanche of a flipped bit.', 'bench/cipher'),
        tool('toNt', 'numbers', 'Number theory', 'Euclid as a table, the CRT, powers and orders, Miller–Rabin witness by witness, GF(2^8) and GF(p).', 'bench/nt'),
        tool('toPk', 'key', 'Public key', 'RSA at toy or real sizes, Diffie–Hellman, Elgamal and DSA, with every exponentiation shown.', 'bench/pk'),
        tool('toCurve', 'curve', 'Curve explorer', 'Curves over the reals and over GF(p): click two points and watch the chord find their sum.', 'bench/curve'),
        tool('toHash', 'hash', 'Hash bench', 'SHA-1 to SHA-3, HMAC and why it resists length extension, and the birthday bound on a truncated hash.', 'bench/hash'),
        tool('toProto', 'proto', 'Protocols', 'Message-sequence charts, stepped, with what each party knows at every moment.', 'bench/proto')));
      box.appendChild(h('h2.sub-title', 'Machines, challenges and code'));
      box.appendChild(h('section.home-tools',
        tool('toEnigma', 'rotor', 'Enigma I', 'The machine in full: lamps, plugboard cables, the stepping inside, the signal path, key sheets and a working Bombe.', 'enigma'),
        tool('toCtf', 'flag', 'CTF ladder', 'Challenges with a story, a flag and three hints each, from a shift cipher to the Bombe.', 'ctf'),
        tool('toSandbox', 'code', 'Sandbox', 'Write square-and-multiply, xtime or the quarter-round yourself, tested against vectors in a sealed worker.', 'sandbox')));
      const parts = S.parts || [];
      if (parts.length) box.appendChild(h('h2.sub-title', 'The course, in ' + parts.length + ' parts'));
      parts.forEach((p) => {
        const n = (S.topics || []).filter((t) => { const f = S.familyOf(t); return f && f.part === p.id; }).length;
        box.appendChild(h('section.part', { id: 'part-' + p.n }, h('div.part-head', h('span.num', String(p.n)), h('h2', h('a', { href: '#part=' + p.id }, p.title)), n ? h('span.part-n', n + ' topic' + (n === 1 ? '' : 's')) : null), h('p.part-blurb', p.blurb)));
      });
      main.appendChild(box);
      requestAnimationFrame(() => { if (art.isConnected && S.HomeHero) this.hero = S.HomeHero(art, document.getElementById('heroCap')); });
    }

    // ---- share links -------------------------------------------------------------------------------------
    /** copy a link that opens this state: kind is the page that opens it (bench, enigma, sandbox) */
    async share(kind, data) {
      const code = await S.Share.pack({ kind, data });
      const url = location.href.replace(/#.*$/, '') + '#share=' + code;
      S.Share.copy(url, url.length > 6000 ? 'Copied. The link is long (' + Math.round(url.length / 1000) + ' KB): some apps cut long links.' : 'Link copied: whoever opens it gets this exact setup.');
      return url;
    }
    async openShared(code) {
      try {
        const { kind, data } = await S.Share.unpack(code);
        const pg = S.Pages.get(kind);
        if (!pg || !pg.load) throw new Error('This link is for a part of Sifer this version does not have.');
        const where = pg.load(data) || kind;
        history.replaceState(null, '', '#' + where);
        this.route();
        S.UI.toast('Opened the shared ' + ({ bench: 'bench setup', enigma: 'machine setting', sandbox: 'code' }[kind] || 'setup') + '.', 'ok');
      } catch (e) {
        history.replaceState(null, '', '#');
        this.route();
        S.UI.toast(e.message, 'err', 5000);
      }
    }

    // ---- keyboard -----------------------------------------------------------------------------------------
    onKey(e) {
      if (S.UI.anyModalOpen()) return;
      if (e.key === 'Escape' && frame().classList.contains('menu-open')) { frame().classList.remove('menu-open'); return; }
      const tag = (e.target && e.target.tagName) || '';
      const typing = /INPUT|TEXTAREA|SELECT/.test(tag) || (e.target && e.target.isContentEditable);
      if (this.page && this.page.onKey && this.page.onKey(e, typing)) return;
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
      if ((tag === 'BUTTON' || tag === 'A') && (e.key === ' ' || e.key === 'Enter')) return;
      const k = e.key;
      if (k === '?') { e.preventDefault(); this.shortcuts(); }
      else if (k === 'P' && e.shiftKey) { e.preventDefault(); this.setProjector(!this.settings.projector); }
      else if (k === 't' || k === 'T') { e.preventDefault(); this.toggleTheme(); }
    }
    shortcuts() {
      const groups = [['Everywhere', [['T', 'Light or dark'], ['Shift  P', 'Projector mode'], ['Esc', 'Close a dialog or the menu'], ['?', 'This list']]]];
      const pg = this.page && this.page.keys;
      if (pg) groups.unshift(...pg);
      const body = h('div.keys', ...groups.map(([title, rows]) => h('section', h('h4', title), h('table', ...rows.map(([k, v]) => h('tr', h('td', ...k.split('  ').map((x, i) => [i ? ' ' : '', h('kbd', x)])), h('td', v)))))));
      S.UI.modal({ title: 'Keyboard shortcuts', body, wide: true, cls: 'keys-modal', buttons: [{ label: 'OK', value: true, primary: true }], enterValue: true });
    }
    settingsDialog() {
      const s = this.settings;
      const row = (title, sub, ctl) => h('div.settings-row', h('div.what', h('b', title), h('span', sub)), ctl);
      const chk = (key, after) => { const c = h('input', { type: 'checkbox', checked: !!s[key], id: 'set-' + key }); c.addEventListener('change', () => { s[key] = c.checked; this.saveSettings(); this.applyTheme(); if (after) after(); }); return c; };
      const sel = (key, opts, after) => { const c = h('select', { id: 'set-' + key, 'aria-label': key }, ...opts.map(([v, l]) => h('option', { value: v, selected: String(s[key]) === String(v) }, l))); c.addEventListener('change', () => { s[key] = c.value; this.saveSettings(); this.applyTheme(); if (after) after(); }); return c; };
      const L = S.Learner;
      const pr = h('input', { type: 'checkbox', checked: !!(L && L.settings.predict), id: 'set-predict' });
      pr.addEventListener('change', () => { if (L) { L.settings.predict = pr.checked; L.saveSettings(); } });
      S.UI.modal({ title: 'Settings', wide: true, body: h('div',
        row('Theme', 'Light, dark, or whatever the system uses', sel('theme', [['auto', 'Like the system'], ['light', 'Light'], ['dark', 'Dark']], () => this.redraw())),
        row('Animate', 'Values glide between steps; off shows each step at once', chk('animate')),
        row('Predictions', 'The topic player stops to ask what comes next before key moments', pr),
        row('Machine sounds', 'Key clicks and rotor steps on the Enigma (off until you turn them on)', chk('sound')),
        row('Keep my work', 'Save benches, the machine setting and sandbox code in this browser as I go', chk('autosave')),
        row('Projector mode', 'Large type and strong lines for a classroom (Shift+P)', chk('projector', () => this.setProjector(s.projector))),
        h('p.muted.engines', { id: 'engineStatus' }, 'Engines: ' + S.engineStatus().map((x) => x.name + (x.live ? '' : ' (coming)')).join(', ') + '.')),
      buttons: [{ label: 'Close', value: true, primary: true }] });
    }
    about() {
      const more = h('a', { href: '#' }, 'About the author');
      more.addEventListener('click', (e) => { e.preventDefault(); S.UI.closeAllModals(); setTimeout(() => S.authorDialog && S.authorDialog(), 50); });
      const sib = (name, url) => h('a', { href: url, target: '_blank', rel: 'noopener' }, name);
      S.UI.modal({
        title: 'About Sifer',
        body: h('div', h('p', h('b', 'Sifer'), ' @@VERSION@@ is cryptography you can see inside: classical ciphers and the Enigma, number theory, stream and block ciphers, modes, RSA, discrete logarithms, elliptic curves, signatures, hashes, protocols, post-quantum schemes and side channels. Every intermediate value is drawn, every engine reproduces the published test vectors, and every weakness is shown with the defence that stops it. Every example, key, story and exercise in it was made for Sifer.'),
          h('p', 'It runs entirely in your browser from one file: no server, no account, nothing sent anywhere. Your progress and settings stay in this browser.'),
          h('p', 'Its sister tools: ', sib('See', 'https://see.jyotiprakash.org'), ', ', sib('Strux', 'https://strux.jyotiprakash.org'), ', ', sib('Baysik', 'https://baysik.jyotiprakash.org'), ', ', sib('Lohgo', 'https://lohgo.jyotiprakash.org'), ', ', sib('Kwery', 'https://kwery.jyotiprakash.org'), ', ', sib('Tooring', 'https://tooring.jyotiprakash.org'), ' and ', sib('Sirkit', 'https://sirkit.jyotiprakash.org'), '.'),
          h('p', 'Free software under the GNU General Public License, version 3 or later. Every copy and every derived work must keep this attribution: Based on Sifer by Jyotiprakash Mishra (https://sifer.jyotiprakash.org).'),
          h('p', 'Copyright © 2026 Jyotiprakash Mishra. The name Sifer is not licensed for derived works.'), h('p', more)),
        buttons: [{ label: 'OK', value: true, primary: true }],
      });
    }
  }

  /** which engines this build has: the settings dialog lists them, and pages say what is still to come */
  S.engineStatus = function () {
    const has = (p) => p.split('.').reduce((o, k) => (o && o[k] !== undefined ? o[k] : undefined), S) !== undefined;
    return [['Classical', 'Classic'], ['Enigma', 'Enigma.machine'], ['Bombe', 'Enigma.bombe.job'], ['AES', 'AES'], ['DES', 'DES'], ['ChaCha20', 'ChaCha'], ['Modes', 'Modes'], ['Stream and block', 'Sym'], ['LFSR', 'LFSR'], ['SPN', 'SPN'],
      ['Number theory', 'NT'], ['Fields', 'GF'], ['RSA', 'RSA'], ['Discrete logarithm', 'DLP'], ['Signatures', 'SIG'], ['Curves', 'ECC'], ['Hashes', 'Hash.get'], ['MACs', 'MAC'], ['Protocols', 'Proto'], ['Post-quantum', 'PQ'], ['Side channels', 'SC']]
      .map(([name, path]) => ({ name, live: has(path) }));
  };

  S.App = App;
  if (typeof document !== 'undefined' && document.getElementById && document.getElementById('main')) {
    const start = () => { try { new App(); } catch (e) { document.body.innerHTML = '<pre style="padding:20px;white-space:pre-wrap">Sifer could not start: ' + String(e.stack || e.message).replace(/</g, '&lt;') + '</pre>'; throw e; } };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
  }
})(globalThis.Sifer = globalThis.Sifer || {});
