// Checking a Bombe stop, as the checking machine did: deduce the plugboard from the stop, decrypt the crib with it,
// then recover the ring settings and the message start, and fill in the cables the menu could not see.
//   S.Enigma.bombe.scramblers(stop, menu)            -> per crib index, the scrambler permutation (no plugboard)
//   S.Enigma.bombe.deduce(stop, menu)                -> {partner, pairs, selfs, unknown, conflicts, trace}
//   S.Enigma.bombe.verify(stop, menu)                -> {plain, matches, wrong, open, ok, deduced, trace}
//   S.Enigma.bombe.solve(stop, menu, {complete})     -> {key, plain, score, trace}   the whole daily key and message
//   S.Enigma.bombe.check(stops, menu)                -> the stops that survive verification
(function (S) {
  'use strict';
  const E = (S.Enigma = S.Enigma || {});
  const B = (E.bombe = E.bombe || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const md = (n) => ((n % 26) + 26) % 26;
  const I = (c) => c.charCodeAt(0) - 65;

  B.scramblers = (stop, menu) => {
    const n = menu.length, m = E.machine({ order: stop.order, reflector: stop.reflector, rings: stop.mode === 'full' ? stop.rings : 'AAA' }), out = [];
    const base = Array.from(stop.pos, I);
    if (stop.mode === 'full') m.setWindow(stop.pos);
    for (let i = 0; i < n; i++) {
      if (stop.mode === 'full') m.step(); else m.setWindow(ABC[base[0]] + ABC[base[1]] + ABC[(base[2] + i + 1) % 26]);
      out.push(m.permutation());
    }
    return out;
  };

  B.deduce = (stop, menu) => {
    const perms = B.scramblers(stop, menu), partner = {}, trace = [], conflicts = [];
    const set = (a, b, why) => {
      if (partner[a] === b) return false;
      if (partner[a] != null || (partner[b] != null && partner[b] !== a)) { conflicts.push({ a, b, why, had: partner[a] || partner[b] }); return false; }
      partner[a] = b; partner[b] = a;
      trace.push(step('deduce', `${why}: ${a === b ? a + ' has no cable' : 'cable ' + a + '–' + b}.`, { a, b }));
      return true;
    };
    for (const [a, b] of stop.steckers) set(a, b, `From the stop with ${stop.register}–${stop.hypothesis}`);
    for (let changed = true; changed;) {
      changed = false;
      for (const e of menu.edges) {
        const p = perms[e.i];
        if (partner[e.a] != null && partner[e.b] == null) changed = set(e.b, ABC[p[I(partner[e.a])]], `Scrambler ${e.i + 1} (${e.a}–${e.b}) takes ${partner[e.a]} to ${ABC[p[I(partner[e.a])]]}`) || changed;
        else if (partner[e.b] != null && partner[e.a] == null) changed = set(e.a, ABC[p[I(partner[e.b])]], `Scrambler ${e.i + 1} (${e.a}–${e.b}) takes ${partner[e.b]} to ${ABC[p[I(partner[e.b])]]}`) || changed;
        else if (partner[e.a] != null && partner[e.b] != null && ABC[p[I(partner[e.a])]] !== partner[e.b] && !conflicts.some((c) => c.edge === e.i)) conflicts.push({ edge: e.i, a: e.a, b: e.b, why: 'the scrambler disagrees with both known steckers' });
      }
    }
    const pairs = [], selfs = [], unknown = [];
    for (const c of ABC) { const p = partner[c]; if (p == null) unknown.push(c); else if (p === c) selfs.push(c); else if (c < p) pairs.push(c + p); }
    if (pairs.length > 13) conflicts.push({ why: 'more than 13 cables' });
    trace.push(step('deduce-done', `${pairs.length} cable${pairs.length === 1 ? '' : 's'} (${pairs.join(' ') || 'none'}), ${selfs.length} letter${selfs.length === 1 ? '' : 's'} without a cable, ${unknown.length} not yet known${conflicts.length ? `, and ${conflicts.length} contradiction${conflicts.length === 1 ? '' : 's'}` : ''}.`, { pairs, selfs, unknown, conflicts }));
    return { partner, pairs, selfs, unknown, conflicts, perms, trace };
  };

  /** decrypt the crib's stretch of ciphertext through the deduced plugboard and compare with the crib */
  B.verify = (stop, menu) => {
    const d = B.deduce(stop, menu), P = d.partner, cipher = menu.cipher.slice(menu.offset, menu.offset + menu.length);
    let plain = '', matches = 0, wrong = 0, open = 0;
    for (let i = 0; i < menu.length; i++) {
      const c = cipher[i], sc = P[c];
      if (sc == null) { plain += '?'; open++; continue; }
      const y = ABC[d.perms[i][I(sc)]], p = P[y];
      if (p == null) { plain += '?'; open++; continue; }
      plain += p; if (p === menu.crib[i]) matches++; else wrong++;
    }
    const ok = !d.conflicts.length && wrong === 0 && matches >= Math.min(menu.length, 4);
    const trace = d.trace.concat([step('verify', `Through the deduced cables the ciphertext ${cipher} reads ${plain} against the crib ${menu.crib}: ${matches} right, ${wrong} wrong, ${open} unknown. ${ok ? 'The stop is good.' : 'A false stop.'}`, { plain, matches, wrong, open, ok })]);
    return { plain, matches, wrong, open, ok, deduced: d, trace };
  };
  B.check = (stops, menu) => stops.filter((s) => B.verify(s, menu).ok);

  const english = (t) => S.Classic.score(t, true);

  /** the full key: ring settings of the middle and right rotors, the start window, and the remaining cables */
  B.solve = (stop, menu, opts = {}) => {
    const v = B.verify(stop, menu), trace = v.trace.slice(), known = v.deduced.pairs.slice(), selfs = v.deduced.selfs;
    const cipher = menu.cipher, order = stop.order, W = order.map(E.wheel), core = Array.from(stop.pos, I);
    const tryKey = (rings, plugs) => {
      const win = stop.mode === 'full' ? core : core.map((c, i) => md(c + rings[i]));
      let top = null;
      for (const start of E.walkBack(win, menu.offset, W[1].notch, W[2].notch)) {
        const cfg = { order, reflector: stop.reflector, rings: rings.map((r) => ABC[r]).join(''), window: start.map((x) => ABC[x]).join(''), plugs: plugs.join(' ') };
        const plain = E.machine(cfg).run(cipher), score = english(plain);
        if (!top || score > top.score) top = { cfg, plain, score };
      }
      return top;
    };
    // the cables the menu never touched: add the pair that most improves the English, while any pair helps
    const fill = (first, steps) => {
      let plugs = first.cfg.plugs ? first.cfg.plugs.split(' ') : known.slice(), best = first;
      const rings = Array.from(first.cfg.rings, I);
      const free = () => { const used = new Set(plugs.join('') + selfs.join('')); return ABC.split('').filter((c) => !used.has(c)); };
      while (opts.complete !== false && plugs.length < 13) {
        const f = free(); let top = null;
        for (let a = 0; a < f.length; a++) for (let b = a + 1; b < f.length; b++) { const k = tryKey(rings, plugs.concat([f[a] + f[b]])); if (k && k.score > best.score + 0.01 && (!top || k.score > top.score)) top = Object.assign(k, { pair: f[a] + f[b] }); }
        if (!top) break;
        plugs = plugs.concat([top.pair]); best = top;
        steps.push(step('plug-fill', `Adding the cable ${top.pair} makes the text more English (score ${top.score.toFixed(3).replace("-", "−")} per letter).`, { pair: top.pair, score: top.score }));
      }
      return best;
    };
    let best = null, steps = [];
    if (stop.mode === 'full') best = fill(tryKey(Array.from(stop.rings, I), known), steps);
    else {
      // the Bombe found cores; a ring setting turns window letters against the core, which only shows where the
      // middle and left rotors step. The left ring cannot be seen, so it is set to A. With some cables still
      // unknown the best ring setting can be a near miss, so the leading few are each completed and compared.
      const all = [];
      for (let rm = 0; rm < 26; rm++) for (let rr = 0; rr < 26; rr++) { const k = tryKey([0, rm, rr], known); if (k) all.push(k); }
      all.sort((a, b) => b.score - a.score);
      trace.push(step('rings', `Trying all 676 ring settings of the middle and right rotors, the best English comes from rings ${all[0].cfg.rings} with the message starting at ${all[0].cfg.window}${all.length > 1 ? `; the next are ${all.slice(1, 4).map((k) => k.cfg.rings).join(', ')}` : ''}.`, { rings: all[0].cfg.rings, window: all[0].cfg.window, ranked: all.slice(0, 8).map((k) => ({ rings: k.cfg.rings, score: k.score })) }));
      for (const cand of all.slice(0, opts.ringCandidates || 4)) { const st = []; const k = fill(cand, st); if (!best || k.score > best.score) { best = k; steps = st; } }
      if (best.cfg.rings !== all[0].cfg.rings) trace.push(step('rings-refined', `With the missing cables filled in, rings ${best.cfg.rings} read better than ${all[0].cfg.rings}.`, { rings: best.cfg.rings }));
      // with the whole plugboard in hand, every ring setting is decrypted in full again: a ring one letter off moves
      // a turnover by one key press and spoils a letter or two, which only the complete plugboard makes visible.
      // Rings and cables are refined in turn until neither changes.
      const plugsOf = (k) => (k.cfg.plugs ? k.cfg.plugs.split(' ') : []);
      for (let round = 0; round < 6; round++) {
        let top = best;
        for (let rm = 0; rm < 26; rm++) for (let rr = 0; rr < 26; rr++) { const k = tryKey([0, rm, rr], plugsOf(best)); if (k && k.score > top.score + 1e-9) top = k; }
        if (top === best) break;
        trace.push(step('rings-refined', `Decrypting the whole message with all ${plugsOf(best).length} cables, rings ${top.cfg.rings} (start ${top.cfg.window}) read better than ${best.cfg.rings}.`, { rings: top.cfg.rings, window: top.cfg.window }));
        const st = []; best = fill(top, st); steps = steps.concat(st);
      }
    }
    trace.push(...steps);
    trace.push(step('solved', `Key: rotors ${order.join(' ')}, UKW-${stop.reflector}, rings ${best.cfg.rings}, start ${best.cfg.window}, cables ${best.cfg.plugs || 'none'}. The message reads ${best.plain.slice(0, 40)}…`, { key: best.cfg }));
    return { key: best.cfg, plain: best.plain, score: best.score, verify: v, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
