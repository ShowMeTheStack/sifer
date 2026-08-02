// The Key sheet view: a month of daily keys for a practice net, made by S.Enigma.keySheet from a seed (the same seed
// gives the same sheet), set out as a sheet of paper that prints on its own. Each day can be set on the machine.
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const store = S.UI.storage;
  const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

  (S.EnigmaViews = S.EnigmaViews || {}).sheet = {
    mount(host, ctx) {
      const now = new Date();
      const o = Object.assign({ seed: 'harbour', year: now.getFullYear(), month: now.getMonth() + 1, pairs: 10 }, store.get('enigma.sheet', {}));
      const seed = h('input.mono', { type: 'text', id: 'shSeed', value: o.seed, spellcheck: 'false', 'aria-label': 'Seed of the sheet' });
      const year = h('input', { type: 'number', id: 'shYear', value: String(o.year), min: '1930', max: '2100', 'aria-label': 'Year' });
      const month = h('select', { id: 'shMonth', 'aria-label': 'Month' }, ...MONTHS.map((m, i) => h('option', { value: String(i + 1), selected: i + 1 === +o.month }, m)));
      const pairs = h('select', { id: 'shPairs', 'aria-label': 'Cables a day' }, ...Array.from({ length: 14 }, (_, n) => h('option', { value: String(n), selected: n === +o.pairs }, String(n))));
      const fresh = h('button.btn.small', { type: 'button', id: 'shNew' }, icon('shuffle'), 'A new sheet');
      const print = h('button.btn.small', { type: 'button', id: 'shPrint' }, icon('download'), 'Print');
      const f = (label, c) => h('label.sh-field', h('span', label), c);
      const paper = h('div.sheet-paper', { id: 'enigSheet' });
      host.append(h('div.sh-controls.card', f('Seed', seed), f('Year', year), f('Month', month), f('Cables a day', pairs), h('div.sh-acts', fresh, print)), paper,
        h('p.muted.sh-note', 'A sheet is made from its seed: give a friend the seed, month and year, and you hold the same keys. Choose Set on a day to put its key on the machine, with the rotors at the day\'s ground setting.'));
      let sheet = null;
      const render = () => {
        o.seed = seed.value.trim() || 'harbour'; o.year = Math.max(1930, Math.min(2100, +year.value || now.getFullYear())); o.month = +month.value; o.pairs = +pairs.value;
        store.set('enigma.sheet', o);
        sheet = S.Enigma.keySheet({ seed: o.seed, year: o.year, month: o.month, pairs: o.pairs });
        paper.innerHTML = '';
        const rows = sheet.days.map((d) => {
          const set = h('button.btn.small.sh-set', { type: 'button', dataset: { day: String(d.day) }, 'aria-label': 'Set the machine to day ' + d.day }, 'Set');
          set.addEventListener('click', () => { const k = S.Enigma.keySheet.dayKey(sheet, d.day); ctx.setAll(Object.assign(k, { start: k.window })); S.UI.toast('The machine is set to day ' + d.day + ' of the ' + sheet.net + ' net.', 'ok'); location.hash = 'enigma'; });
          return h('tr', h('td.day', String(d.day)), h('td', d.order.join(' ')), h('td', d.ringText), h('td.cab', d.plugs || '—'), h('td', d.ground), h('td.grp', d.groups.join(' ')), h('td.noprint', set));
        });
        paper.append(h('div.sp-head', h('div.sp-mark', 'Practice net ' + sheet.net), h('div.sp-title', 'Key sheet · ' + MONTHS[sheet.month - 1] + ' ' + sheet.year), h('div.sp-sub', 'Enigma I · reflector UKW-B · seed "' + sheet.seed + '"')),
          h('div.sp-table', h('table', h('thead', h('tr', h('th', 'Day'), h('th', 'Rotors'), h('th', 'Rings'), h('th', 'Cables'), h('th', 'Ground'), h('th', 'Indicator groups'), h('th.noprint', ''))), h('tbody', rows))),
          h('ul.sp-rules', ...sheet.rules.map((r) => h('li', r[0].toUpperCase() + r.slice(1) + '.'))));
        S.UI.fitTables(paper);
        S.UI.scrollRow(paper.querySelector('.sp-table'));
      };
      for (const c of [seed, year, month, pairs]) c.addEventListener('change', render);
      fresh.addEventListener('click', () => { const w = ['amber', 'birch', 'cedar', 'delta', 'ember', 'fjord', 'grove', 'heath', 'inlet', 'juniper', 'kelp', 'linden', 'marsh', 'nettle', 'osprey', 'pebble']; seed.value = w[Math.floor(Math.random() * w.length)] + '-' + Math.floor(100 + Math.random() * 900); render(); });
      print.addEventListener('click', () => { document.body.classList.add('print-sheet'); setTimeout(() => { window.print(); document.body.classList.remove('print-sheet'); }, 50); });
      render();
      return { sheet: () => sheet, redraw() { S.UI.fitTables(paper); } };
    },
  };
})(globalThis.Sifer = globalThis.Sifer || {});
