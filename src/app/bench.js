// The Bench page (#bench, #bench/cipher, /nt, /pk, /curve, /hash, /proto): one tab per bench, each registered by
// its own file with S.Bench.tab(id, def). A bench keeps its inputs in this browser (when "Keep my work" is on) and
// can be shared as a link. def = {title, icon, blurb, order, open(host, state, ctx) -> {state(), dispose(), redraw(),
// onKey(e, typing), keys}}. ctx = {save() (call when the inputs change), share(), app}.
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const store = S.UI.storage;
  // the registry is made in ui.js (bench tab files load before this one); this file adds the page
  const B = S.Bench;
  const tabs = B._tabs, pending = B._pending;
  B.state = (id) => store.get('bench.' + id, null);

  S.Pages.register('bench', {
    nav: 'bench',
    wide: true,
    open(app, main, rest) {
      const want = (rest || '').replace(/^bench\/?/, '').split(/[/?]/)[0];
      const list = B.tabs();
      const id = list.some((t) => t.id === want) ? want : store.get('bench.last', null) && tabs.has(store.get('bench.last')) ? store.get('bench.last') : (list[0] && list[0].id);
      const box = h('div.bench-page', { id: 'benchView', dataset: { bench: id || '' } });
      main.appendChild(box);
      if (!id) { box.appendChild(S.UI.empty('cipher', 'The benches are on their way', 'Each bench runs an algorithm with every intermediate value shown.')); return {}; }
      store.set('bench.last', id);
      const def = tabs.get(id);
      document.title = def.title + ' · Bench · Sifer';
      const bar = h('div.bench-tabs', { role: 'tablist', 'aria-label': 'Benches' }, ...list.map((t) => {
        const b = h('a.bench-tab' + (t.id === id ? '.on' : ''), { href: '#bench/' + t.id, role: 'tab', 'aria-selected': String(t.id === id), id: 'bt-' + t.id, title: t.blurb || t.title }, icon(t.icon || 'cipher'), h('span', t.title));
        return b;
      }));
      box.appendChild(bar);
      S.UI.scrollRow(bar);
      const host = h('div.bench-body', { id: 'benchBody', role: 'tabpanel', 'aria-labelledby': 'bt-' + id });
      box.appendChild(host);
      let inst = null;
      const ctx = {
        app,
        save: S.UI.debounce(() => { if (app.settings.autosave && inst && inst.state) { try { store.set('bench.' + id, inst.state()); } catch (e) { /* not serialisable */ } } }, 300),
        share() { if (inst && inst.state) app.share('bench', { tab: id, state: inst.state() }); },
      };
      const state = pending[id] !== undefined ? pending[id] : app.settings.autosave ? B.state(id) : null;
      delete pending[id];
      try { inst = def.open(host, state, ctx) || {}; }
      catch (e) { host.innerHTML = ''; host.appendChild(S.UI.empty('warn', 'This bench could not open', String(e.message || e))); console.error(e); inst = {}; }
      if (state && pending[id] === undefined) ctx.save();
      return {
        keys: inst.keys || null,
        onKey: (e, typing) => (inst.onKey ? inst.onKey(e, typing) : false),
        redraw() { if (inst.redraw) inst.redraw(); },
        dispose() { if (inst.dispose) inst.dispose(); },
        get bench() { return inst; },
      };
    },
    load(data) { if (data && data.tab) { B.preset(data.tab, data.state); return 'bench/' + data.tab; } return 'bench'; },
  });

  // ---- what the diagram checker looks at: each bench as it opens ---------------------------------------------------
  if (S.Checks) S.Checks.push({ group: 'bench', name: 'bench (first tab)', hash: 'bench', ready: "document.querySelector('#benchView')", sel: '#main' });
})(globalThis.Sifer = globalThis.Sifer || {});
