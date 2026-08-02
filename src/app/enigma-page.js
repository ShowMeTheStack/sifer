// The Enigma page (#enigma, #enigma/inside, #enigma/path, #enigma/sheet, #enigma/bombe): one Enigma I shared by
// every view. The machine (S.Enigma.machine) lives here with its settings, the message start and the tape of letters
// typed and lit; the views (enigma-deck.js, enigma-inside.js, enigma-path.js, enigma-sheet.js, enigma-bombe-ui.js)
// register in S.EnigmaViews and are told of every key press. Settings are kept in this browser and can be shared.
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const store = S.UI.storage;
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const VIEWS = (S.EnigmaViews = S.EnigmaViews || {});
  const TABS = [['', 'Machine', 'rotor'], ['inside', 'Inside', 'layers'], ['path', 'Signal path', 'route'], ['sheet', 'Key sheet', 'sheet'], ['bombe', 'Bombe', 'search']];
  const DEFAULT = { order: ['II', 'IV', 'V'], reflector: 'B', rings: 'BUL', start: 'QEM', window: 'QEM', plugs: 'AV BS CG DL FU HZ IN KM OW RX', tapeIn: '', tapeOut: '' };
  let pending = null;

  S.UI.addIcons({
    search: '<circle cx="8.5" cy="8.5" r="5.5"/><path d="M13 13l4.5 4.5"/>',
    sheet: '<rect x="3.5" y="2.5" width="13" height="15" rx="1.5"/><path d="M3.5 6.5h13M7.5 2.5v15M3.5 10h13M3.5 13.5h13"/>',
  });

  /** a configuration as typed by people or links, made safe: unknown parts fall back to the default */
  function clean(c) {
    const st = Object.assign({}, DEFAULT, { tapeIn: '', tapeOut: '' });
    if (!c) return st;
    try {
      const m = S.Enigma.machine({ order: c.order || st.order, reflector: c.reflector || st.reflector, rings: c.rings || st.rings, window: c.window || c.start || st.window, plugs: c.plugs == null ? st.plugs : c.plugs });
      const cf = m.config();
      Object.assign(st, cf, { start: /^[A-Z]{3}$/.test(c.start || '') ? c.start : cf.window, tapeIn: String(c.tapeIn || '').replace(/[^A-Z]/g, ''), tapeOut: String(c.tapeOut || '').replace(/[^A-Z]/g, '') });
    } catch (e) { /* the default */ }
    return st;
  }

  const EP = (S.EnigmaPage = {
    /** set the machine before the page opens (a lesson card, a key sheet day) */
    preset(cfg) { pending = Object.assign({}, cfg, { start: cfg.start || cfg.window, tapeIn: '', tapeOut: '' }); if (EP.ctx) { EP.ctx.setAll(pending); pending = null; } },
    ctx: null,
  });

  /** the shared machine and what the views need of it */
  function makeCtx(app) {
    let st = clean(pending || (app.settings.autosave ? store.get('enigma', null) : null));
    pending = null;
    let m = null;
    const listeners = new Set();
    const build = () => { m = S.Enigma.machine({ order: st.order, reflector: st.reflector, rings: st.rings, window: st.window, plugs: st.plugs }); };
    build();
    const ctx = {
      app,
      get st() { return st; },
      get machine() { return m; },
      save() { if (app.settings.autosave) store.set('enigma', st); },
      on(fn) { listeners.add(fn); return () => listeners.delete(fn); },
      emit(type, data) { for (const f of [...listeners]) { try { f(type, data); } catch (e) { console.error(e); } } },
      /** one key press: the rotors step, the current flows, a lamp lights */
      press(L) {
        const r = m.press(L);
        st.window = m.window;
        st.tapeIn += r.in; st.tapeOut += r.out;
        if (st.tapeIn.length > 2000) { st.tapeIn = st.tapeIn.slice(-2000); st.tapeOut = st.tapeOut.slice(-2000); }
        ctx.save();
        if (S.EnigmaSound) S.EnigmaSound.press(r.stepping.steps.filter(Boolean).length);
        ctx.emit('press', r);
        return r;
      },
      release() { ctx.emit('release'); },
      /**
       * type a message key by key at a readable pace: each key goes down (the rotors step, the lamp lights), is held,
       * and comes back up. speed: 'slow' | 'normal' | 'fast' | 'instant'. Resolves with the letters typed; a new call
       * or ctx.stopTyping() cuts it short.
       */
      typeOut(text, speed) {
        const t = String(text).toUpperCase().replace(/[^A-Z]/g, '');
        const period = { slow: 700, normal: 340, fast: 150 }[speed];
        ctx.stopTyping();
        if (!period || !t) return Promise.resolve(ctx.typeAll(t));
        const token = (ctx.typing = { stop: false });
        ctx.emit('typing', true);
        const wait = (ms) => new Promise((r) => setTimeout(r, ms));
        return (async () => {
          let n = 0;
          for (const c of t) {
            if (token.stop) break;
            ctx.press(c); n++;
            await wait(period * 0.55);
            ctx.release();
            if (token.stop) break;
            await wait(period * 0.45);
          }
          if (ctx.typing === token) { ctx.typing = null; ctx.emit('typing', false); }
          return n;
        })();
      },
      typing: null,
      stopTyping() { if (ctx.typing) { ctx.typing.stop = true; ctx.typing = null; ctx.release(); ctx.emit('typing', false); } },
      /** a whole message at once (the tape box): the last letter's lamp stays lit */
      typeAll(text) {
        const t = String(text).toUpperCase().replace(/[^A-Z]/g, '');
        let r = null;
        for (const c of t) { r = m.press(c); st.tapeIn += r.in; st.tapeOut += r.out; }
        st.window = m.window; ctx.save();
        if (r) ctx.emit('press', r);
        ctx.emit('tape');
        return t.length;
      },
      /** change settings: the machine is rebuilt at the window it shows, and the message starts again there */
      set(part) {
        const next = Object.assign({}, st, part);
        const test = S.Enigma.machine({ order: next.order, reflector: next.reflector, rings: next.rings, window: next.window, plugs: next.plugs });
        st = Object.assign(next, test.config(), { start: test.window, tapeIn: '', tapeOut: '' });
        build(); ctx.save(); ctx.emit('config');
      },
      /** everything at once (a preset, a loaded key): window is the message start */
      setAll(c) { st = clean(c); build(); ctx.save(); ctx.emit('config'); },
      /** back to the start of the message, the tape cleared */
      rewind() { st.window = st.start; st.tapeIn = ''; st.tapeOut = ''; build(); ctx.save(); ctx.emit('config'); },
      /** a rotor turned by hand: +1 or −1 at slot i (0 left) */
      turn(i, d) {
        const w = st.window.split('');
        w[i] = ABC[(ABC.indexOf(w[i]) + d + 26) % 26];
        if (S.EnigmaSound) S.EnigmaSound.click();
        ctx.set({ window: w.join('') });
      },
    };
    return ctx;
  }

  // ---- the settings card and the tape --------------------------------------------------------------------------------
  function settingsCard(ctx) {
    const box = h('section.card.enig-card', { id: 'enigSettings' });
    const err = h('div.enig-err', { role: 'alert' });
    const render = () => {
      const st = ctx.st;
      box.innerHTML = '';
      const sel = (id, label, opts, val, on) => { const s = h('select', { id, 'aria-label': label }, ...opts.map(([v, l]) => h('option', { value: v, selected: v === val }, l))); s.addEventListener('change', () => { err.textContent = ''; try { on(s.value); } catch (e) { err.textContent = e.message; render(); } }); return s; };
      const rot = ['I', 'II', 'III', 'IV', 'V'].map((r) => [r, r]);
      const slot = ['Left', 'Middle', 'Right'];
      const ringOpts = ABC.split('').map((c, i) => [c, String(i + 1).padStart(2, '0') + ' · ' + c]);
      const letOpts = ABC.split('').map((c) => [c, c]);
      const row = (label, ...kids) => h('div.enig-row', h('span.enig-lab', label), h('div.enig-ctl', ...kids));
      box.append(h('h3', 'Settings'),
        row('Rotors', ...[0, 1, 2].map((i) => sel('enRotor' + i, slot[i] + ' rotor', rot, st.order[i], (v) => { const o = st.order.slice(); const j = o.indexOf(v); if (j >= 0 && j !== i) o[j] = o[i]; o[i] = v; ctx.set({ order: o }); }))),
        row('Reflector', sel('enRefl', 'Reflector', [['A', 'UKW-A'], ['B', 'UKW-B'], ['C', 'UKW-C']], st.reflector, (v) => ctx.set({ reflector: v }))),
        row('Rings', ...[0, 1, 2].map((i) => sel('enRing' + i, slot[i] + ' ring setting', ringOpts, st.rings[i], (v) => { const r = st.rings.split(''); r[i] = v; ctx.set({ rings: r.join('') }); }))),
        row('Start', ...[0, 1, 2].map((i) => sel('enPos' + i, slot[i] + ' rotor position', letOpts, st.window[i], (v) => { const w = st.window.split(''); w[i] = v; ctx.set({ window: w.join('') }); }))));
      const plugs = h('input.mono', { type: 'text', id: 'enPlugs', value: st.plugs, spellcheck: 'false', autocomplete: 'off', autocapitalize: 'characters', 'aria-label': 'Plugboard cables', placeholder: 'AV BS CG' });
      const apply = () => { err.textContent = ''; try { ctx.set({ plugs: plugs.value }); } catch (e) { err.textContent = e.message; } };
      plugs.addEventListener('change', apply);
      plugs.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); apply(); } });
      box.append(row('Cables', plugs), err);
      const rnd = h('button.btn.small', { type: 'button', id: 'enRandom' }, icon('shuffle'), 'A random key');
      rnd.addEventListener('click', () => { const k = S.Enigma.randomKey(Math.random, { pairs: 10 }); ctx.setAll(Object.assign(k, { start: k.window })); });
      const back = h('button.btn.small', { type: 'button', id: 'enRewind' }, icon('restart'), 'Back to the start');
      back.addEventListener('click', () => ctx.rewind());
      box.append(h('div.enig-acts', back, rnd));
    };
    render();
    ctx.on((t) => { if (t === 'config') render(); else if (t === 'press' || t === 'tape') { for (let i = 0; i < 3; i++) { const s = box.querySelector('#enPos' + i); if (s) s.value = ctx.st.window[i]; } } });
    return box;
  }
  function tapeCard(ctx) {
    const box = h('section.card.enig-card.enig-tape', { id: 'enigTape' });
    const inEl = h('div.tape-line.mono', { id: 'tapeIn' }), outEl = h('div.tape-line.mono.out', { id: 'tapeOut' });
    const meta = h('div.tape-meta', { id: 'tapeMeta' });
    const msg = h('textarea.mono', { id: 'enMessage', rows: '2', spellcheck: 'false', 'aria-label': 'A message to type', placeholder: 'Paste a message and press Type it' });
    const go = h('button.btn.small.primary', { type: 'button', id: 'enTypeAll' }, icon('keyboard'), 'Type it');
    const speed = h('select', { id: 'enSpeed', 'aria-label': 'Typing speed' }, ...[['slow', 'Slow'], ['normal', 'Normal'], ['fast', 'Fast'], ['instant', 'At once']].map(([v, l]) => h('option', { value: v, selected: v === store.get('enigma.speed', 'normal') }, l)));
    speed.addEventListener('change', () => store.set('enigma.speed', speed.value));
    go.addEventListener('click', () => {
      if (ctx.typing) { ctx.stopTyping(); return; }
      const text = msg.value;
      if (!text.replace(/[^a-z]/gi, '')) return;
      msg.value = '';
      ctx.typeOut(text, speed.value);
    });
    ctx.on((type, on) => { if (type !== 'typing') return; go.innerHTML = ''; go.append(icon(on ? 'stop' : 'keyboard'), on ? 'Stop typing' : 'Type it'); });
    const clear = h('button.btn.small', { type: 'button', id: 'enClear' }, 'Clear the tape');
    clear.addEventListener('click', () => { ctx.stopTyping(); ctx.rewind(); });
    const render = () => {
      const st = ctx.st;
      inEl.textContent = S.Enigma.groups(st.tapeIn) || '—';
      outEl.textContent = S.Enigma.groups(st.tapeOut) || '—';
      meta.textContent = st.tapeIn.length + ' letter' + (st.tapeIn.length === 1 ? '' : 's') + ' from ' + st.start + ', now at ' + st.window;
    };
    box.append(h('h3', 'The message'), h('div.tape-lab', 'Keys pressed'), inEl, h('div.tape-lab', 'Lamps lit'), outEl, meta, msg, h('div.enig-acts', go, speed, clear));
    render();
    ctx.on(() => render());
    return box;
  }

  // ---- the page ------------------------------------------------------------------------------------------------------
  S.Pages.register('enigma', {
    nav: 'enigma',
    wide: true,
    title: 'Enigma I',
    open(app, main, rest) {
      const sub = (rest || '').replace(/^(enigma|bombe)\/?/, (m, a) => (a === 'bombe' ? 'bombe/' : '')).split(/[/?]/)[0];
      const view = TABS.some(([k]) => k === sub) ? sub : '';
      const ctx = makeCtx(app);
      EP.ctx = ctx;
      const page = h('div.enigma-page', { id: 'enigmaView', dataset: { view: view || 'deck' } });
      const sound = h('button.btn.small', { type: 'button', id: 'enSound', 'aria-pressed': String(!!app.settings.sound), title: 'Key and rotor sounds' });
      const showSound = () => { sound.innerHTML = ''; sound.append(icon(app.settings.sound ? 'sound' : 'mute'), app.settings.sound ? 'Sound on' : 'Sound off'); sound.setAttribute('aria-pressed', String(!!app.settings.sound)); };
      sound.addEventListener('click', () => { app.settings.sound = !app.settings.sound; app.saveSettings(); showSound(); if (app.settings.sound && S.EnigmaSound) S.EnigmaSound.click(); });
      showSound();
      const share = h('button.btn.small', { type: 'button', id: 'enShare', title: 'Copy a link to this machine setting' }, icon('link'), 'Share');
      share.addEventListener('click', () => { const s = ctx.st; app.share('enigma', { order: s.order, reflector: s.reflector, rings: s.rings, start: s.start, window: s.start, plugs: s.plugs }); });
      const tabs = h('nav.enig-tabs', { 'aria-label': 'Enigma views' }, ...TABS.map(([k, label, ic]) => h('a.enig-tab' + (k === view ? '.on' : ''), { href: '#enigma' + (k ? '/' + k : ''), id: 'enTab-' + (k || 'deck'), 'aria-current': k === view ? 'page' : null }, icon(ic), h('span', label))));
      page.append(h('div.enig-head', h('div', h('h1', 'Enigma I'), h('p', 'Three rotors from five, a reflector, ring settings and a plugboard: the machine in full, its stepping opened up, the current traced on every key, key sheets for a practice net, and the Bombe that broke it.')), h('div.enig-head-acts', sound, share)), tabs);
      S.UI.scrollRow(tabs);
      const def = VIEWS[view || 'deck'];
      const withSide = !view || view === 'inside' || view === 'path';
      const host = h('div.enig-view');
      const body = h('div.enig-body' + (withSide ? '.with-side' : ''), host);
      if (withSide) body.appendChild(h('div.enig-side', settingsCard(ctx), tapeCard(ctx)));
      page.append(body, h('p.enig-app.muted', icon('rotor'), h('span', 'The full collection of machines (M3, M4, the Abwehr G, the Railway and more) is in the Enigma app for Android.')));
      main.appendChild(page);
      // with animation off (Settings), every view shows its final state at once
      const still = () => page.classList.toggle('still', app.settings.animate === false);
      still();
      ctx.on(still);
      let inst = null;
      try { inst = def ? def.mount(host, ctx) || {} : {}; } catch (e) { host.appendChild(S.UI.empty('warn', 'This view could not open', String(e.message || e))); console.error(e); inst = {}; }
      if (!def) host.appendChild(S.UI.empty('history', 'This view is on its way', ''));
      const typingKey = (e) => !e.metaKey && !e.ctrlKey && !e.altKey && /^[a-z]$/i.test(e.key);
      const keyUp = (e) => { if (typingKey(e) && withSide) ctx.release(); };
      document.addEventListener('keyup', keyUp);
      let down = null;
      return {
        ctx, get view() { return inst; },
        keys: withSide ? [['The machine', [['A … Z', 'Press a key: the rotors step and a lamp lights'], ['Esc', 'Close a dialog']]]] : null,
        onKey(e, typing) {
          if (inst.onKey && inst.onKey(e, typing)) return true;
          if (typing || !withSide || !typingKey(e)) return false;
          e.preventDefault();
          if (e.repeat || down === e.key.toUpperCase()) return true;
          down = e.key.toUpperCase();
          ctx.press(down);
          setTimeout(() => { down = null; }, 60);
          return true;
        },
        redraw() { if (inst.redraw) inst.redraw(); },
        dispose() { ctx.stopTyping(); document.removeEventListener('keyup', keyUp); if (inst.dispose) inst.dispose(); if (EP.ctx === ctx) EP.ctx = null; },
      };
    },
    load(data) { EP.preset(data || {}); return 'enigma'; },
  });

  // ---- what the diagram checker looks at -------------------------------------------------------------------------------
  if (S.Checks) {
    const P = 'Sifer.app.page';
    const ready = (sel) => "document.querySelector('" + sel + "') && window.__siferReady";
    S.Checks.push({ group: 'enigma', name: 'the deck', hash: 'enigma', ready: ready('#enigDeck svg'), setup: P + '.ctx.setAll({}); ' + P + '.ctx.press("H");', sel: '#main' });
    S.Checks.push({ group: 'enigma', name: 'the inside, after a double step', hash: 'enigma/inside', ready: ready('#enigInside svg'), setup: P + '.ctx.setAll({order: ["I","II","III"], rings: "AAA", start: "ADU", window: "ADU", plugs: ""}); ' + P + '.ctx.press("A"); ' + P + '.ctx.press("B"); ' + P + '.ctx.press("C");', sel: '#main' });
    S.Checks.push({ group: 'enigma', name: 'the signal path after a key press', hash: 'enigma/path', ready: ready('#enigPath svg'), setup: P + '.ctx.setAll({}); ' + P + '.ctx.press("E");', sel: '#main' });
    S.Checks.push({ group: 'enigma', name: 'a key sheet', hash: 'enigma/sheet', ready: ready('#enigSheet table'), sel: '#main' });
    S.Checks.push({ group: 'enigma', name: 'the Bombe menu', hash: 'enigma/bombe', ready: ready('#bombeMenu svg'), sel: '#main' });
    S.Checks.push({ group: 'enigma', name: 'the Bombe after a run', hash: 'enigma/bombe', ready: ready('#bombeMenu svg'), setup: 'await ' + P + '.view.runNow(); ', sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
