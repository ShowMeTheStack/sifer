// Original monthly key sheets for practice nets. A sheet is reproducible from its seed. The rules are the kind a key
// office kept: no rotor order twice in a month, no rotor in the same slot on two days running, no ring setting twice,
// no cable repeated from the day before, no cable joining neighbouring letters, and indicator groups unique on the
// sheet. Days run from the last at the top to the first at the bottom, so used days can be cut off and destroyed.
//   S.Enigma.keySheet({seed, year, month, pairs, net}) -> {title, net, year, month, days: [...], rules, text()}
//     days[k] = {day, order, rings: [n, n, n], ringText, plugs, ground, groups: ['ABC', ...]}
//   S.Enigma.keySheet.dayKey(sheet, day, window)  -> a machine configuration for that day
(function (S) {
  'use strict';
  const E = (S.Enigma = S.Enigma || {});
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const NETS = ['Heron', 'Kestrel', 'Lantern', 'Orchard', 'Ferryman', 'Millstream', 'Weathervane', 'Lamplighter'];
  const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

  E.keySheet = (opts = {}) => {
    const seed = opts.seed == null ? 'practice' : String(opts.seed), year = opts.year || 2026, month = opts.month || 1;
    const pairs = opts.pairs == null ? 10 : opts.pairs, rand = E.rng(seed + '/' + year + '/' + month + '/' + pairs);
    const pick = (n) => Math.floor(rand() * n), letter = () => ABC[pick(26)];
    const net = opts.net || NETS[E.hash(seed) % NETS.length];
    const nDays = new Date(year, month, 0).getDate();
    const usedOrders = new Set(), usedRings = new Set(), usedGroups = new Set(), days = [];
    let prev = null;
    for (let d = 1; d <= nDays; d++) {
      let order, tries = 0;
      do { const ids = E.ROTOR_IDS.slice(); order = []; while (order.length < 3) order.push(ids.splice(pick(ids.length), 1)[0]); tries++; }
      while (tries < 500 && (usedOrders.has(order.join()) || (prev && order.some((r, i) => prev.order[i] === r))));
      usedOrders.add(order.join());
      let rings; do rings = [1 + pick(26), 1 + pick(26), 1 + pick(26)]; while (usedRings.has(rings.join()));
      usedRings.add(rings.join());
      let plugs; tries = 0;
      do {
        const ls = ABC.split(''); for (let i = 25; i > 0; i--) { const j = pick(i + 1); [ls[i], ls[j]] = [ls[j], ls[i]]; }
        plugs = []; for (let i = 0; i < pairs; i++) plugs.push([ls[2 * i], ls[2 * i + 1]].sort().join(''));
        tries++;
      } while (tries < 1000 && plugs.some((p) => Math.abs(p.charCodeAt(0) - p.charCodeAt(1)) === 1 || (prev && prev.plugs.includes(p))));
      plugs.sort();
      const groups = [];
      while (groups.length < 4) { const g = letter() + letter() + letter(); if (!usedGroups.has(g)) { usedGroups.add(g); groups.push(g.toLowerCase()); } }
      const day = { day: d, order, rings, ringText: rings.map((r) => String(r).padStart(2, '0')).join(' '), plugs: plugs.join(' '), ground: letter() + letter() + letter(), groups };
      days.push(day); prev = { order, plugs };
    }
    days.reverse();
    const sheet = {
      title: `Practice net ${net}: key sheet for ${MONTHS[month - 1]} ${year}`, net, year, month, seed, pairs, days,
      rules: ['no rotor order is used twice in the month', 'no rotor stands in the same slot on two days running', 'no ring setting is used twice', 'no cable is repeated from the day before', 'no cable joins two neighbouring letters', 'indicator groups are unique on the sheet', 'the last day is at the top: cut off and destroy each day after use'],
      text() {
        const head = 'Day | Rotors     | Rings    | Cables' + ' '.repeat(Math.max(0, pairs * 3 - 6)) + ' | Ground | Groups';
        const rows = days.map((d) => `${String(d.day).padStart(3)} | ${d.order.map((r) => r.padEnd(3)).join(' ')} | ${d.ringText} | ${d.plugs.padEnd(Math.max(6, pairs * 3 - 1))} | ${d.ground}    | ${d.groups.join(' ')}`);
        return [sheet.title, head, '-'.repeat(head.length), ...rows].join('\n');
      },
    };
    return sheet;
  };
  E.keySheet.dayKey = (sheet, day, window) => {
    const d = sheet.days.find((x) => x.day === day);
    if (!d) throw new Error('no such day on the sheet');
    return { order: d.order.slice(), reflector: 'B', rings: d.rings.slice(), window: window || d.ground, plugs: d.plugs };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
