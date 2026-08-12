// Part 1, the Bombe: a crib's letter pairs drawn as a menu with its loops, one drum position tested by letting the
// current spread through the scramblers and the diagonal board, and the plugboard read off a stop.
(function (S) {
  'use strict';
  const P = S.P1, ABC = P.ABC;
  const E = () => S.Enigma;
  const B = () => S.Enigma.bombe;
  const BOX = { x: 60, y: 150, w: 620, h: 320 };
  const CRIBS = [
    { label: 'WEATHERREPORTFOR at 0', values: { crib: 'WEATHERREPORTFOR', offset: 0 } },
    { label: 'REPORTFORTHENORTH at 7', values: { crib: 'REPORTFORTHENORTH', offset: 7 } },
    { label: 'NORTHVALLEY at 19: no loops', values: { crib: 'NORTHVALLEY', offset: 19 } },
  ];
  const CRIBS2 = [CRIBS[0], { label: 'REPORTFORTHE at 7', values: { crib: 'REPORTFORTHE', offset: 7 } }];
  const cribInputs = [
    { id: 'crib', kind: 'text', label: 'Crib', def: 'WEATHERREPORTFOR', check: (v) => { const n = P.letters(v).length; return n < 6 ? 'Crib: at least 6 letters' : n > 20 ? 'Crib: at most 20 letters' : null; } },
    { id: 'offset', kind: 'number', label: 'Offset in the message', def: 0, min: 0, max: 75 },
  ];
  const loopCheck = (inp) => { const m = B().menu(P.letters(inp.crib), P.enCipher(), inp.offset); return m.main.loops < 2 ? 'This menu has ' + m.main.loops + ' loop' + (m.main.loops === 1 ? '' : 's') + '; with fewer than two the Bombe would stop almost everywhere. Choose a longer crib.' : null; };
  const cribCheck = (inp) => { const ct = P.enCipher(), crib = P.letters(inp.crib); if (inp.offset + crib.length > ct.length) return 'The crib runs past the end of the message'; const m = B().menu(crib, ct, inp.offset); return m.clashes.length ? 'At this offset a crib letter faces itself, so the crib cannot be there' : null; };
  /** the crib written over its stretch of ciphertext, pairs numbered */
  function strips(menu, o) {
    o = o || {};
    const it = [P.title('s:t', 0, -12, 'crib over ciphertext, from position ' + menu.offset)];
    const ct = menu.cipher.slice(menu.offset, menu.offset + menu.length);
    it.push(...P.strip('s:p', 30, 0, menu.crib, { cw: 30, gap: 3, h: 28, size: 15, cls: (i) => (o.hot && o.hot.has(i) ? 'hot' : o.upto !== undefined && i > o.upto ? 'soft' : 'p1-pl') }));
    it.push(...P.strip('s:c', 30, 32, ct, { cw: 30, gap: 3, h: 28, size: 15, cls: (i) => (o.hot && o.hot.has(i) ? 'hot' : o.upto !== undefined && i > o.upto ? 'soft' : 'p1-ct') }));
    for (let i = 0; i < menu.length; i++) it.push(P.text('s:n' + i, 30 + i * 33 + 15, 80, String(i + 1), 'tick', 13, 'middle'));
    it.push(P.text('s:l1', 20, 19, 'crib', 'tick', 13, 'end'));
    it.push(P.text('s:l2', 20, 51, 'cipher', 'tick', 13, 'end'));
    return it;
  }

  // ---- the menu -----------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p01-bombe-menu', family: 'p01-bombe', order: 30, title: 'The Bombe\'s menu and its loops',
    blurb: 'Each crib letter and the cipher letter under it are joined by the machine at one known position. Draw every pair as an edge between two letters: the graph is the menu. Its loops are what make a wrong guess contradict itself.',
    inputs: cribInputs, presets: CRIBS, check: cribCheck,
    run(inp) {
      const ct = P.enCipher(), menu = B().menu(P.letters(inp.crib), ct, inp.offset), pos = P.menuLayout(menu, BOX), F = new S.Frames(['edges']);
      const tr = menu.trace, edges = new Set();
      F.add({ items: strips(menu, {}), say: `The crib ${menu.crib} is believed to sit at position ${menu.offset} of the message. At crib position i the machine, in its state for that letter, joined the crib letter and the cipher letter in a swap. ${menu.length} positions, ${menu.length} known swaps.`, meta: {} });
      const per = Math.ceil(menu.edges.length / 4);
      for (let k = 0; k < menu.edges.length; k += per) {
        const batch = menu.edges.slice(k, k + per); for (const e of batch) edges.add(e.i); F.count('edges', batch.length);
        F.add({ items: strips(menu, { hot: new Set(batch.map((e) => e.i)) }).concat(P.menuItems(menu, { pos, edges: new Set(edges), hotEdges: new Set(batch.map((e) => e.i)) })), say: `Pairs ${batch.map((e) => `${e.a}–${e.b} (${e.i + 1})`).join(', ')}: each becomes an edge, numbered by its place in the crib. ${k === 0 ? 'On the Bombe each edge is a scrambler, three drums set to that place.' : ''}`.trim(), meta: {} });
      }
      const main = menu.main;
      F.add({ items: strips(menu, {}).concat(P.menuItems(menu, { pos, hotLetters: new Set(main.letters) })), say: tr.find((t) => t.kind === 'menu-components').say + (menu.components.length > 1 ? ` Only the largest group is useful; letters outside it cannot feed back on themselves.` : ''), meta: { loops: main.loops } });
      menu.loops.forEach((lp, n) => {
        F.add({ items: strips(menu, { hot: new Set(lp.edges) }).concat(P.menuItems(menu, { pos, hotEdges: new Set(lp.edges), hotLetters: new Set(lp.letters) })), say: tr.filter((t) => t.kind === 'menu-loop')[n].say, meta: { loop: n } });
      });
      F.add({ items: strips(menu, {}).concat(P.menuItems(menu, { pos, register: menu.register })), say: `${tr.find((t) => t.kind === 'menu-register').say} The Bombe will put a guess for ${menu.register}'s stecker partner on that register and let the current flow round the loops.`, meta: { end: true, register: menu.register } });
      return { frames: F.list, def: P.def('The menu', ['edge (a, b, i): crib letter a, cipher letter b,', '  joined by the machine at position i', 'σ(b) = Sᵢ(σ(a))   (Sᵢ: rotors at i, no plugboard)', 'loops = edges − letters + 1 (connected group)', 'each loop: a closed chain of conditions on σ']), counters: [{ id: 'edges', label: 'edges' }] };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.loops !== undefined, pick: 'option', ask: 'How many independent loops does the largest group have?', options: (fr, i) => { const n = fr[i + 1].meta.loops; return [...new Set([0, 1, 2, 3, 4, n])].sort((a, b) => a - b).map(String); }, answer: (fr, i) => String(fr[i + 1].meta.loops), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What does an edge of the menu stand for?', options: ['A plugboard cable', 'A crib letter and its cipher letter, joined by the machine at one position', 'A rotor', 'A loop'], answer: 1, why: 'Each crib position gives one known swap of the machine.' },
      { q: 'A connected group has 9 letters and 11 edges. How many independent loops?', options: ['2', '3', '9', '11'], answer: 1, why: '11 − 9 + 1 = 3.' },
      { q: 'Why are loops valuable?', options: ['They make the menu prettier', 'Going round a loop, a wrong stecker guess leads back to a different value, a contradiction', 'They remove the plugboard', 'They shorten the crib'], answer: 1, why: 'A loop is a consistency check that a wrong hypothesis fails.' },
      { q: 'Which letter makes the best test register?', options: ['A letter with one edge', 'The letter with the most connections', 'Any vowel', 'The first crib letter'], answer: 1, why: 'Current from it reaches the most of the menu fastest.' },
    ],
  });

  // ---- a stop, tested through the diagonal board --------------------------------------------------------------------------
  const GX = 30, GY = 30, GC = 13;
  function grid(live, fresh, reg) {
    const items = [P.title('g:t', GX, 6, 'wires: letter × stecker value')];
    for (let c = 0; c < 26; c++) {
      items.push({ key: 'g:h' + c, kind: 'text', x: GX + c * GC + GC / 2, y: GY - 4, text: ABC[c], anchor: 'middle', size: 11, cls: 'mono', audit: 'small-ok' });
      items.push({ key: 'g:r' + c, kind: 'text', x: GX - 4, y: GY + c * GC + 10, text: ABC[c], anchor: 'end', size: 11, cls: 'mono' + (c === reg ? ' key' : ''), audit: 'small-ok' });
    }
    const rows = [];
    for (let l = 0; l < 26; l++) { let s = ''; for (let v = 0; v < 26; v++) s += fresh.has(l * 26 + v) ? '2' : live.has(l * 26 + v) ? (l === reg ? '4' : '1') : l === reg ? '7' : '0'; rows.push(s); }
    items.push({ key: 'g:b', kind: 'bitmap', x: GX, y: GY, cw: GC, ch: GC, gap: 1.5, rows });
    return items;
  }
  /** the true scenario: menu, rotor order, core position, the true partner of the register letter */
  function truth(inp) {
    const ct = P.enCipher(), menu = B().menu(P.letters(inp.crib), ct, inp.offset), key = P.EN.key;
    const m = E().machine(key); m.run(P.letters(P.EN.plain).slice(0, inp.offset));
    const core = m.window, sig = E().plugMap(E().parsePlugs(key.plugs)), reg = menu.register, partner = ABC[sig[ABC.indexOf(reg)]];
    m.run(menu.crib);
    return { ct, menu, key, core, reg, partner, turnover: m.window[1] !== core[1] };
  }
  S.topic({
    id: 'p01-bombe-stop', family: 'p01-bombe', order: 40, title: 'A Bombe stop, tested through the diagonal board',
    blurb: 'Guess the register letter\'s stecker partner and put current on that one wire. Every scrambler of the menu passes it on, and the diagonal board adds the mirror image (if A is steckered to B, B is steckered to A). At the wrong drum position the current floods every wire; at the right one, a consistent set stays separate, and the drums stop.',
    inputs: cribInputs.concat([{ id: 'case', kind: 'choice', label: 'Test', def: 'right', options: [{ value: 'right', label: 'the right position, the right guess' }, { value: 'wrong', label: 'the right position, a wrong guess' }, { value: 'away', label: 'a wrong drum position' }] }]),
    presets: CRIBS2.map((p) => ({ label: p.label + ': the right guess', values: Object.assign({ case: 'right' }, p.values) })).concat([{ label: 'A wrong guess at the right position', values: { crib: 'WEATHERREPORTFOR', offset: 0, case: 'wrong' } }, { label: 'One drum position off', values: { crib: 'WEATHERREPORTFOR', offset: 0, case: 'away' } }]),
    check: (inp) => cribCheck(inp) || loopCheck(inp) || (truth(inp).turnover ? 'The middle rotor turns over inside this crib; the fast-drum Bombe would miss it. Choose another offset.' : null),
    run(inp) {
      const t = truth(inp), params = { menu: t.menu }, order = t.key.order;
      const pos = inp.case === 'away' ? t.core.slice(0, 2) + ABC[(ABC.indexOf(t.core[2]) + 1) % 26] : t.core;
      const hyp = inp.case === 'wrong' ? ABC[(ABC.indexOf(t.partner) + 1) % 26] : t.partner;
      const res = B().test(params, order, pos, hyp), ev = res.events, reg = ABC.indexOf(t.reg), F = new S.Frames(['wires']);
      const live = new Set(), list = [];
      const evKey = (e) => ABC.indexOf(e.letter) * 26 + ABC.indexOf(e.value);
      const log = (items) => { const it = [P.title('e:t', 420, 6, 'how each wire lit')]; items.slice(-9).forEach((s, k) => it.push(P.text('e:' + k, 420, 30 + k * 22, s, 'tick', 13))); return it; };
      const describe = (e) => (e.why.by === 'hypothesis' ? `${e.letter}${e.value}: the guess` : e.why.by === 'diagonal' ? `${e.letter}${e.value}: diagonal, from ${e.why.from}` : `${e.letter}${e.value}: scrambler ${e.why.edge + 1} from ${e.why.from}`);
      F.add({ items: grid(live, new Set(), reg).concat(log([])), say: `The Bombe stands with rotors ${order.join(' ')} at ${pos}${inp.case === 'away' ? ', one step from the true position' : ''}; each scrambler of the menu sits at its own crib position. The 26 × 26 wires stand for every statement "letter L is steckered to V". The test register is ${t.reg}.`, meta: {} });
      // the spread in a few waves
      const sizes = [1, 1, 2, 4, 8, 16, 32, 64, 128, 256, 676];
      let k = 0;
      for (const sz of sizes) {
        if (k >= ev.length) break;
        const batch = ev.slice(k, k + sz), fresh = new Set(batch.map(evKey));
        for (const e of batch) { live.add(evKey(e)); list.push(describe(e)); }
        k += batch.length; F.set('wires', live.size);
        const regLive = [...live].filter((w) => Math.floor(w / 26) === reg).length;
        F.add({ items: grid(live, fresh, reg).concat(log(list)), say: k === 1 ? res.trace[0].say : batch.length <= 2 ? batch.map((e) => res.trace[ev.indexOf(e)].say).join(' ') : `${batch.length} more wires light: ${live.size} in all, ${regLive} of them on register ${t.reg}.`, meta: { k } });
      }
      const verdict = res.trace[res.trace.length - 1].say;
      F.add({ items: grid(live, new Set(), reg).concat(log(list)), say: `${verdict} ${inp.case === 'right' ? `The lit wires are a whole consistent plugboard for the menu's letters: one value per letter, mirrored by the diagonal board.` : inp.case === 'wrong' ? `The guess ${hyp} was wrong, yet the machine still stops: the dark wire ${t.partner} on ${t.reg} is the true partner. A wrong guess and the right answer are told apart in one go.` : 'At a wrong position the loops contradict every guess, so current reaches everything. The drums turn on to the next position.'}`, meta: { end: true, stop: res.stop } });
      return { frames: F.list, def: P.def('Bombe test', ['wire (L, V): "σ(L) = V"', 'scrambler i (edge a–b): (a, V) → (b, Sᵢ(V))', 'diagonal board: (L, V) → (V, L)', 'all 26 wires of the register live: no stop', 'otherwise: stop; the dark wires are candidates']), counters: [{ id: 'wires', label: 'live wires' }] };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.end, pick: 'option', ask: 'Will the Bombe stop here?', options: ['yes, a stop', 'no, every register wire is live'], answer: (fr, i) => (fr[i + 1].meta.stop ? 'yes, a stop' : 'no, every register wire is live'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What does the diagonal board add?', options: ['A second crib', 'The symmetry of steckering: if A goes to B, then B goes to A', 'Extra rotors', 'The ring settings'], answer: 1, why: 'Steckering is a swap, so wire (A, B) implies wire (B, A).' },
      { q: 'At a wrong drum position, what usually happens?', options: ['Nothing lights', 'All 26 wires of the register light', 'Exactly one wire lights', 'The Bombe breaks'], answer: 1, why: 'Every guess contradicts itself round the loops, and the contradictions spread everywhere.' },
      { q: 'The register shows 25 live wires and one dark. What is the dark one?', options: ['A fault', 'The candidate stecker partner', 'The rotor order', 'The crib letter'], answer: 1, why: 'The only guess not contradicted is the dark wire.' },
      { q: 'Why does one test cover all 26 guesses at once?', options: ['It does not', 'A wrong guess lights the others, and the true partner stays dark either way', 'The rotors move 26 times', 'Because of the plugboard'], answer: 1, why: 'So one current tests every hypothesis for the register letter.' },
    ],
  });

  // ---- plugboard deduction from a stop ----------------------------------------------------------------------------------
  S.topic({
    id: 'p01-bombe-deduce', family: 'p01-bombe', order: 50, title: 'Reading the plugboard off a stop',
    blurb: 'At a stop the guess for the register letter is known. Each menu edge then gives its other end: σ(b) = Sᵢ(σ(a)). Spread along the menu, decrypt the crib through the cables found, then try the ring settings and fill in the cables the menu never touched.',
    inputs: cribInputs, presets: CRIBS2, check: (inp) => cribCheck(inp) || loopCheck(inp) || (truth(inp).turnover ? 'The middle rotor turns over inside this crib; choose another offset.' : null),
    run(inp) {
      const t = truth(inp), menu = t.menu, pos = P.menuLayout(menu, BOX), F = new S.Frames(['cables']);
      const run = B().runAll({ menu, reflector: 'B', orders: [t.key.order] });
      const good = B().check(run.stops, menu), stop = good.find((s) => s.pos === t.core) || good[0];
      F.add({ items: strips(menu, {}).concat(P.menuItems(menu, { pos, register: menu.register })), say: `The Bombe ran through all ${P.big(run.tested)} positions of rotor order ${t.key.order.join(' ')} in ${Math.max(1, Math.round(run.ms))} ms and stopped ${P.plural(run.stops.length, 'time')}; ${good.length} stop${good.length === 1 ? '' : 's'} survive the check below. Take the stop at ${stop.pos}, where the register ${stop.register} goes with ${stop.hypothesis}.`, meta: {} });
      // start from the register's partner alone and let the menu's edges give the rest
      const d = B().deduce(Object.assign({}, stop, { steckers: [[stop.register, stop.hypothesis]] }), menu), subs = {}, known = new Set();
      const dsteps = d.trace.filter((x) => x.kind === 'deduce');
      const first = dsteps.slice(0, 10);
      first.forEach((st, n) => {
        subs[st.a] = '↔ ' + st.b; subs[st.b] = '↔ ' + st.a; known.add(st.a); known.add(st.b);
        const m = /Scrambler (\d+)/.exec(st.say), hotE = m ? new Set([+m[1] - 1]) : new Set();
        if (st.a !== st.b) F.count('cables');
        F.add({ items: strips(menu, { hot: hotE }).concat(P.menuItems(menu, { pos, register: menu.register, subs: Object.assign({}, subs), hotLetters: new Set([st.a, st.b]), hotEdges: hotE })), say: st.say, meta: { a: st.a, b: st.b } });
      });
      if (dsteps.length > first.length) { for (const st of dsteps.slice(first.length)) { subs[st.a] = '↔ ' + st.b; subs[st.b] = '↔ ' + st.a; if (st.a !== st.b) F.count('cables'); } F.add({ items: strips(menu, {}).concat(P.menuItems(menu, { pos, register: menu.register, subs: Object.assign({}, subs) })), say: `The other ${P.plural(dsteps.length - first.length, 'deduction')} follow the same way.`, meta: {} }); }
      const dd = d.trace[d.trace.length - 1].say;
      F.add({ items: strips(menu, {}).concat(P.menuItems(menu, { pos, register: menu.register, subs: Object.assign({}, subs) })), say: dd, meta: {} });
      const v = B().verify(stop, menu), sol = B().solve(stop, menu);
      F.add({ items: strips(menu, {}).concat(P.menuItems(menu, { pos, register: menu.register, subs: Object.assign({}, subs) })), say: v.trace[v.trace.length - 1].say, meta: { ok: v.ok } });
      const ringStep = sol.trace.find((x) => x.kind === 'rings'), fills = sol.trace.filter((x) => x.kind === 'plug-fill'), last = sol.trace[sol.trace.length - 1];
      F.set('cables', E().parsePlugs(sol.key.plugs).length);
      const right = Array.from(sol.plain).filter((c, i) => c === P.letters(P.EN.plain)[i]).length;
      const fin = () => strips(menu, {}).concat(P.menuItems(menu, { pos, register: menu.register, subs: Object.assign({}, subs) }));
      if (ringStep) F.add({ items: fin(), say: ringStep.say + ' The Bombe found the cores; the ring settings turn them into window letters.', meta: {} });
      F.add({ items: fin(), say: `${fills.length ? `Then ${P.plural(fills.length, 'cable')} the menu never touched: ${fills.map((f) => f.pair).join(', ')}, each kept because the text became more English. ` : ''}${last.say.replace(/The message reads ([A-Z]+)…/, (m0, tx) => 'The message reads ' + E().groups(tx) + '…')} ${right} of ${sol.plain.length} letters match the original message.`, meta: { end: true } });
      return { frames: F.list, def: P.def('Deduction from a stop', ['known: σ(register) at the stop', 'edge (a, b, i): σ(b) = Sᵢ(σ(a))', 'repeat until nothing new;', 'a contradiction ⇒ a false stop', 'then: rings, start, the remaining cables']), counters: [{ id: 'cables', label: 'cables known' }] };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.ok !== undefined, pick: 'option', ask: 'Decrypting the crib through the cables found: will it read as the crib?', options: ['yes', 'no'], answer: (fr, i) => (fr[i + 1].meta.ok ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'At a stop, σ(R) = R is known and edge R–T is scrambler 7. What gives σ(T)?', options: ['T itself', 'Scrambler 7 applied to σ(R)', 'The reflector', 'The ring setting'], answer: 1, why: 'σ(T) = S₇(σ(R)).' },
      { q: 'What reveals a false stop during deduction?', options: ['A letter gets two different partners', 'The crib is long', 'The Bombe is slow', 'Nothing'], answer: 0, why: 'A contradiction means the position or guess was wrong.' },
      { q: 'Why are some cables still unknown after the deduction?', options: ['They are always unknown', 'The menu never touched those letters', 'The rings hide them', 'Enigma had only 6 cables'], answer: 1, why: 'Only letters connected to the menu get deduced; the rest come from decrypting the message.' },
      { q: 'The Bombe found core positions. What turns them into the window letters of the key?', options: ['The plugboard', 'The ring settings', 'The reflector', 'The crib length'], answer: 1, why: 'Window letter = core position + ring setting; trying the ring settings recovers the start.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
