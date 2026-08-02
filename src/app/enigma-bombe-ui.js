// The Bombe view: an intercept and a crib; where the crib may sit (no letter may face itself); the menu the crib makes,
// with its loops; the drums turning through all 60 rotor orders and 17,576 positions each (in a Web Worker); the stops,
// each checked by deducing the plugboard; and the key recovered and loaded into the machine.
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const store = S.UI.storage;
  // our practice message, enciphered here with a planted key (so the ciphertext always matches the engine)
  const PLAIN = 'WEATHERREPORTFORTHEHARBOURDISTRICTCALMSEASLIGHTMISTCLEARINGBYNOONWINDFROMTHEWESTATTHREEKNOTSTHEFERRYRUNSONTIMEANDTHELIGHTHOUSEKEEPERREPORTSNOTHINGFURTHER';
  const KEY = { order: ['V', 'II', 'IV'], reflector: 'B', rings: 'ARC', window: 'ZBN', plugs: 'NP WZ JK SR QC TY GL BM DA EH' };
  const CRIB = 'WEATHERREPORTFORTHE';
  const clean = (t) => String(t || '').toUpperCase().replace(/[^A-Z]/g, '');
  const fmt = (n) => n.toLocaleString('en-GB');

  (S.EnigmaViews = S.EnigmaViews || {}).bombe = {
    mount(host, ctx) {
      const B = S.Enigma.bombe;
      const saved = store.get('enigma.bombe', null);
      const st = { cipher: (saved && saved.cipher) || S.Enigma.encrypt(KEY, PLAIN), crib: (saved && saved.crib) || CRIB, offset: saved ? saved.offset || 0 : 0 };
      const save = () => store.set('enigma.bombe', st);
      // ---- the intercept and the crib
      const cipherEl = h('textarea.mono', { id: 'bmCipher', rows: '4', spellcheck: 'false', 'aria-label': 'The ciphertext' });
      cipherEl.value = S.Enigma.groups(st.cipher);
      const cribEl = h('input.mono', { type: 'text', id: 'bmCrib', value: st.crib, spellcheck: 'false', autocomplete: 'off', 'aria-label': 'The crib' });
      const fromTape = h('button.btn.small', { type: 'button', id: 'bmFromTape' }, icon('keyboard'), 'Use the machine\'s lamps');
      const practice = h('button.btn.small', { type: 'button', id: 'bmPractice' }, icon('restart'), 'The practice message');
      const intercept = h('section.card.bm-card', h('h3', '1. The intercept and a crib'), h('p.bm-p', 'A weather report goes out every morning and begins the same way. Guess a stretch of plain text, the crib, and say where it sits.'),
        h('label.bm-field', h('span', 'Ciphertext'), cipherEl), h('label.bm-field', h('span', 'Crib'), cribEl), h('div.enig-acts', fromTape, practice));
      // ---- alignment
      const alignBox = h('div.bm-align', { id: 'bmAlign' }), offsBox = h('div.bm-offs', { id: 'bmOffsets' });
      const align = h('section.card.bm-card', h('h3', '2. Where the crib can sit'), h('p.bm-p', 'Enigma never turns a letter into itself, so wherever a crib letter would stand over the same cipher letter, the crib cannot be there.'), offsBox, alignBox);
      // ---- the menu
      const menuBox = h('div.bm-menu', { id: 'bombeMenu' }), menuInfo = h('div.bm-info', { id: 'bmMenuInfo' });
      const menuCard = h('section.card.bm-card', h('h3', '3. The menu'), h('p.bm-p', 'Each crib letter is joined to the cipher letter under it, labelled with its place in the crib: one scrambler of the Bombe per pair. Loops (lit) are what make wrong guesses contradict themselves.'), menuBox, menuInfo);
      // ---- the run
      const runBtn = h('button.btn.primary', { type: 'button', id: 'bmRun' }, icon('run'), 'Run the Bombe');
      const stopBtn = h('button.btn', { type: 'button', id: 'bmStop', disabled: true }, icon('stop'), 'Stop');
      const pace = h('select', { id: 'bmPace', 'aria-label': 'Pace' }, h('option', { value: 'fast' }, 'Full speed, in a worker'), h('option', { value: 'slow' }, 'Slowly, to watch the drums'));
      const bar = h('div.bm-bar', h('i', { id: 'bmBarFill' }));
      const status = h('div.bm-status', { id: 'bmStatus', 'aria-live': 'polite' }, 'Ready: 60 rotor orders × 17,576 positions.');
      const drumBox = h('div.bm-drums', { id: 'bmDrums' });
      const runCard = h('section.card.bm-card', h('h3', '4. The drums'), h('p.bm-p', 'For every rotor order and every position, a stecker is assumed for the register letter and the current spreads through the scramblers and the diagonal board. Where it does not reach every wire, the machine stops.'), h('div.enig-acts', runBtn, stopBtn, pace), bar, status, drumBox);
      // ---- the stops
      const stopsBox = h('div.bm-stops', { id: 'bmStops' });
      const stopsCard = h('section.card.bm-card', h('h3', '5. Stops, checked'), stopsBox);
      host.append(h('div.bm-grid', h('div.bm-col', intercept, align, menuCard), h('div.bm-col', runCard, stopsCard)));

      let menu = null, drums = null, run = null, stops = [], runs = 0, t0 = 0, mode = '';
      const params = () => ({ crib: st.crib, cipher: st.cipher, offset: st.offset, reflector: 'B', stepping: 'fast' });
      const ORDERS = B.orders();
      const redrawAll = () => {
        st.cipher = clean(cipherEl.value); st.crib = clean(cribEl.value); save();
        const al = B.align(st.cipher, st.crib);
        if (!al.possible.includes(st.offset)) st.offset = al.possible.length ? al.possible[0] : 0;
        offsBox.innerHTML = '';
        offsBox.appendChild(h('span.muted', al.possible.length + ' of ' + al.offsets.length + ' places possible: '));
        const chips = h('div.bm-chips');
        for (const o of al.possible.slice(0, 40)) { const c = h('button.chip' + (o === st.offset ? '.on' : ''), { type: 'button', dataset: { offset: String(o) } }, String(o)); c.addEventListener('click', () => { st.offset = o; redrawAll(); }); chips.appendChild(c); }
        offsBox.appendChild(chips);
        S.UI.scrollRow(chips);
        // the crib under the ciphertext at the chosen place
        alignBox.innerHTML = '';
        const k = st.crib.length, seg = st.cipher.slice(st.offset, st.offset + k);
        const cols = h('div.bm-cols');
        for (let i = 0; i < k; i++) cols.appendChild(h('div.bm-colx' + (seg[i] === st.crib[i] ? '.clash' : ''), h('span.n', String(i + 1)), h('span.c', seg[i] || '·'), h('span.p', st.crib[i])));
        alignBox.append(h('div.bm-legend', h('span', 'cipher'), h('span', 'crib')), cols);
        S.UI.scrollRow(cols);
        try { menu = B.menu(st.crib, st.cipher, st.offset); } catch (e) { menu = null; }
        if (menu && menu.edges.length) {
          S.BombeDraw.menu(menuBox, menu);
          S.UI.scrollRow(menuBox);
          menuInfo.innerHTML = '';
          menuInfo.append(h('p', menu.edges.length + ' pairs, ' + menu.letters.length + ' letters; the largest group has ' + menu.main.letters.length + ' letters and ' + menu.main.loops + ' loop' + (menu.main.loops === 1 ? '' : 's') + '. The test register sits on ', h('b', menu.register || '—'), ', the busiest letter.'),
            h('ul.bm-loops', ...menu.loops.slice(0, 6).map((lp) => h('li', h('code', lp.letters.join(' → ')), ' through scramblers ' + lp.edges.map((i) => i + 1).join(', ')))));
          const sub = menu.edges.filter((e) => menu.main.letters.includes(e.a)), subIdx = new Set(sub.map((e) => e.i));
          drums = S.BombeDraw.drums(drumBox, sub);
          S.UI.scrollRow(drumBox);
          try { drums.set(B.drums(params(), ORDERS[0], 'AAA').filter((d) => subIdx.has(d.edge.i))); } catch (e) { /* no menu */ }
        } else { menuBox.innerHTML = ''; menuInfo.textContent = 'This crib gives no menu here.'; drumBox.innerHTML = ''; drums = null; }
        runBtn.disabled = !(menu && menu.register && !menu.clashes.length);
      };
      cipherEl.addEventListener('change', () => { stopRun(); redrawAll(); });
      cribEl.addEventListener('change', () => { stopRun(); redrawAll(); });
      fromTape.addEventListener('click', () => { if (!ctx.st.tapeOut) { S.UI.toast('The machine\'s tape is empty: type a message first.', 'err'); return; } cipherEl.value = S.Enigma.groups(ctx.st.tapeOut); stopRun(); redrawAll(); });
      practice.addEventListener('click', () => { cipherEl.value = S.Enigma.groups(S.Enigma.encrypt(KEY, PLAIN)); cribEl.value = CRIB; st.offset = 0; stopRun(); redrawAll(); });

      const showStops = (done) => {
        stopsBox.innerHTML = '';
        if (!stops.length) { stopsBox.appendChild(h('p.muted', done ? 'No stops: the crib is not at this place, or the key uses a turnover inside the crib. Try another place.' : runs ? 'No stops yet.' : 'Run the Bombe to find stops.')); return; }
        const rows = stops.slice(0, 40).map((s, k) => {
          const v = s.v || (s.v = B.verify(s, menu));
          const solve = h('button.btn.small' + (v.ok ? '.primary' : ''), { type: 'button', dataset: { stop: String(k) } }, v.ok ? 'Solve and load' : 'Try it');
          solve.addEventListener('click', () => solveStop(s));
          return h('tr' + (v.ok ? '.good' : ''), h('td.mono', s.order.join(' ')), h('td.mono', s.pos), h('td.mono', s.register + '↔' + s.hypothesis), h('td.mono', v.plain), h('td', v.ok ? h('b.ok', 'good') : h('span.muted', 'false stop')), h('td', solve));
        });
        stopsBox.appendChild(h('div.fit-table', h('table.b-table.bm-table', h('thead', h('tr', h('th', 'Rotors'), h('th', 'Cores'), h('th', 'Stecker'), h('th', 'Crib reads'), h('th', 'Check'), h('th', ''))), h('tbody', rows))));
        if (stops.length > 40) stopsBox.appendChild(h('p.muted', (stops.length - 40) + ' more stops not shown.'));
        S.UI.fitTables(stopsBox);
      };
      const solveStop = (s) => {
        const sol = B.solve(s, menu);
        const d = sol.verify.deduced;
        const out = h('div.bm-solved', { id: 'bmSolved' },
          h('h4', 'The key'), h('div.kv', h('span.k', 'Rotors'), h('code', sol.key.order.join(' '))), h('div.kv', h('span.k', 'Rings'), h('code', sol.key.rings)), h('div.kv', h('span.k', 'Start'), h('code', sol.key.window)),
          h('div.kv', h('span.k', 'Cables'), h('code', sol.key.plugs || 'none')), h('p.muted', d.pairs.length + ' cables deduced from the stop, the rest found by making the text read as English. The left ring cannot be seen by the Bombe, so it is set to A; the start moves to match.'),
          h('div.bm-plain.mono', S.Enigma.groups(sol.plain)));
        const load = h('button.btn.primary', { type: 'button', id: 'bmLoad' }, icon('rotor'), 'Load into the machine');
        load.addEventListener('click', () => { ctx.setAll(Object.assign({}, sol.key, { start: sol.key.window })); ctx.typeAll(st.cipher); location.hash = 'enigma'; S.UI.toast('The machine is set to the recovered key and has typed the ciphertext: the lamps read the message.', 'ok', 5000); });
        out.appendChild(load);
        const old = stopsBox.querySelector('#bmSolved'); if (old) old.remove();
        stopsBox.appendChild(out);
        return sol;
      };
      function stopRun() { if (run) { run.cancel(); run = null; } runBtn.disabled = false; stopBtn.disabled = true; if (drums) drums.spin(false); }
      const startRun = () => new Promise((resolve) => {
        stopRun();
        stops = []; runs++; t0 = performance.now();
        showStops(false);
        runBtn.disabled = true; stopBtn.disabled = false;
        if (drums) drums.spin(true);
        const subIdx = new Set(menu.edges.filter((e) => menu.main.letters.includes(e.a)).map((e) => e.i));
        let lastDraw = 0;
        run = S.EnigmaRun.start(params(), {
          onProgress(r) {
            if (r.newStops && r.newStops.length) { stops.push(...r.newStops); showStops(false); }
            document.getElementById('bmBarFill').style.width = (100 * r.progress).toFixed(1) + '%';
            const oi = ORDERS.findIndex((o) => o.join() === (r.order || []).join());
            const p = Math.max(0, Math.min(17575, r.tested - oi * 17576));
            const pos = String.fromCharCode(65 + ((p / 676) | 0)) + String.fromCharCode(65 + (((p / 26) | 0) % 26)) + String.fromCharCode(65 + (p % 26));
            status.textContent = 'Rotors ' + (r.order || []).join(' ') + ' at ' + pos + ' · ' + fmt(r.tested) + ' of ' + fmt(ORDERS.length * 17576) + ' positions · ' + stops.length + ' stop' + (stops.length === 1 ? '' : 's');
            const now = performance.now();
            if (drums && now - lastDraw > 90 && r.order) { lastDraw = now; try { drums.set(B.drums(params(), r.order, pos).filter((d) => subIdx.has(d.edge.i))); } catch (e) { /* fine */ } }
          },
          onDone(all) {
            stops = all || stops; run = null;
            runBtn.disabled = false; stopBtn.disabled = true; if (drums) drums.spin(false);
            document.getElementById('bmBarFill').style.width = '100%';
            const good = stops.filter((s) => (s.v || (s.v = B.verify(s, menu))).ok);
            status.textContent = 'Done in ' + ((performance.now() - t0) / 1000).toFixed(1) + ' s ' + (mode === 'worker' ? 'in a worker' : 'on the page') + ': ' + stops.length + ' stop' + (stops.length === 1 ? '' : 's') + ', ' + good.length + ' surviving the check.';
            if (good[0] && drums) { try { drums.set(B.drums(params(), good[0].order, good[0].pos).filter((d) => subIdx.has(d.edge.i))); } catch (e) { /* fine */ } }
            showStops(true);
            resolve(stops);
          },
          onError(msg) { run = null; runBtn.disabled = false; stopBtn.disabled = true; if (drums) drums.spin(false); status.textContent = 'The Bombe cannot run: ' + msg; resolve([]); },
        }, { slow: pace.value === 'slow' });
        mode = run.mode;
        status.textContent = 'Running (' + (run.mode === 'worker' ? 'in a worker' : 'on the page') + ')…';
      });
      runBtn.addEventListener('click', () => { if (menu) startRun(); });
      stopBtn.addEventListener('click', () => { stopRun(); status.textContent = 'Stopped. ' + stops.length + ' stops so far.'; showStops(false); });
      redrawAll();
      showStops(false);
      requestAnimationFrame(() => S.UI.autosize(cipherEl, 260));
      return {
        runNow: () => startRun(),
        solve: (k) => solveStop(stops.filter((s) => (s.v || (s.v = B.verify(s, menu))).ok)[k || 0]),
        get stops() { return stops; },
        get menu() { return menu; },
        dispose() { stopRun(); },
        redraw() { redrawAll(); },
      };
    },
  };
})(globalThis.Sifer = globalThis.Sifer || {});
