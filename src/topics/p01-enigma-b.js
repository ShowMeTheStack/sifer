// Part 1, breaking Enigma begins: Rejewski's characteristic (the cycles of the products of the six indicator
// permutations, untouched by the plugboard because conjugation only renames letters), and a crib laid against the
// ciphertext, where no letter may face itself.
(function (S) {
  'use strict';
  const P = S.P1, ABC = P.ABC;
  const E = () => S.Enigma;

  // ---- cycles drawn as rings ---------------------------------------------------------------------------------------
  function rings(cycles, x0, y0, maxW, o) {
    o = o || {};
    const items = [];
    let x = x0, y = y0, rowH = 0;
    cycles.forEach((cy, n) => {
      // the smallest radius at which neighbouring letters (r 14) keep 30 apart across or down, so even their
      // bounding boxes stay clear on the diagonals
      const L = cy.length;
      let r = L === 1 ? 0 : 26;
      const tight = (rr) => Array.from({ length: L }, (_, k) => { const a = (-90 + (k * 360) / L) * Math.PI / 180, b = (-90 + ((k + 1) * 360) / L) * Math.PI / 180; return Math.max(Math.abs(rr * (Math.cos(a) - Math.cos(b))), Math.abs(rr * (Math.sin(a) - Math.sin(b)))); }).some((d) => d < 30);
      while (L > 1 && tight(r)) r += 1;
      const w = 2 * r + 40;
      if (x + w > x0 + maxW && x > x0) { x = x0; y += rowH + 30; rowH = 0; }
      const cx = x + w / 2, cyy = y + r + 20, pk = (o.prefix || 'cy') + n;
      const pts = Array.from(cy, (c, k) => { const a = (-90 + (k * 360) / L) * Math.PI / 180; return { x: cx + r * Math.cos(a), y: cyy + r * Math.sin(a), c }; });
      pts.forEach((p, k) => items.push({ key: pk + ':' + p.c, kind: 'state', x: p.x, y: p.y, r: 14, text: p.c, size: 14, cls: 'p1-node' + (o.hot && o.hot.has(p.c) ? ' hot' : '') }));
      if (L > 1) pts.forEach((p, k) => { const q = pts[(k + 1) % L]; items.push({ key: pk + ':e' + k, kind: 'edge', from: pk + ':' + p.c, to: pk + ':' + q.c, bend: L === 2 ? 22 : 6, size: 12, cls: o.edgeCls || 'act' }); });
      else items.push({ key: pk + ':e0', kind: 'edge', from: pk + ':' + cy, to: pk + ':' + cy, loop: -90, size: 12, cls: o.edgeCls || 'act' });
      items.push(P.text(pk + ':n', cx, cyy + r + 40, 'length ' + L, 'tick', 13, 'middle'));
      x += w + 16; rowH = Math.max(rowH, 2 * r + 60);
    });
    return { items, h: y + rowH - y0 };
  }

  S.topic({
    id: 'p01-rejewski', family: 'p01-bombe', order: 10, title: 'Rejewski\'s cycles and conjugacy',
    blurb: 'Each message key was typed twice at the day\'s ground setting, so letter 1 and letter 4 of every indicator are the same key letter enciphered three places apart. Following letter 1 → letter 4 round and round gives cycles whose lengths depend only on the rotors, never on the plugboard.',
    inputs: P.enInputs({ order: 'II V I', window: 'KQD', plugs: 'AM BT CY DR FO GW HL JS KV NU' }).concat([{ id: 'n', kind: 'number', label: 'Indicators intercepted', def: 120, min: 10, max: 200 }]),
    presets: [
      { label: 'Ground KQD, 120 indicators', values: { order: 'II V I', rings: 'AAA', window: 'KQD', plugs: 'AM BT CY DR FO GW HL JS KV NU', n: 120 } },
      { label: 'Ground BXC, rotors IV I III', values: { order: 'IV I III', rings: 'AAA', window: 'BXC', plugs: 'IE NZ MU KF OC XS DV PL JT YG', n: 120 } },
      { label: 'Only 20 indicators', values: { order: 'II V I', rings: 'AAA', window: 'KQD', plugs: 'AM BT CY DR FO GW HL JS KV NU', n: 20 } },
      { label: 'Ground MJA, rotors III I II', values: { order: 'III I II', rings: 'AAA', window: 'MJA', plugs: 'AQ BW CE DR FT GY', n: 100 } },
    ],
    run(inp) {
      const cfg = P.enCfg(inp), R = E().rejewski, F = new S.Frames(['known']);
      const list = R.indicators(cfg, inp.n, E().rng('ind:' + cfg.window + inp.n)), fi = R.fromIndicators(list);
      const ch = R.characteristic(cfg), conj = R.conjugacy(cfg);
      const table = (upto, hotRow) => {
        const it = [P.title('i:t', 0, -12, 'indicators')];
        list.slice(0, 6).forEach((x, k) => {
          if (k > upto) return;
          it.push(...P.strip('i:' + k + ':', 0, k * 32, x.indicator, { cw: 24, gap: 2, h: 28, size: 14, cls: (i) => (k === hotRow && (i === 0 || i === 3) ? 'hot' : 'p1-ct') }));
          it.push(P.text('i:k' + k, 166, k * 32 + 19, 'key ' + x.key + x.key, 'tick', 13));
        });
        return it;
      };
      const ad = new Array(26).fill(-1);
      const mapRow = (hot) => {
        const it = [P.title('a:t', 270, -12, 'AD: letter 1 → letter 4')];
        for (let c = 0; c < 26; c++) {
          const col = c % 13, row = Math.floor(c / 13), x = 270 + col * 36, y = row * 76;
          it.push({ key: 'a:p' + c, kind: 'cell', x, y, w: 32, h: 26, rx: 3, text: ABC[c], size: 14, cls: 'mono p1-pl' });
          it.push({ key: 'a:q' + c, kind: 'cell', x, y: y + 30, w: 32, h: 26, rx: 3, text: ad[c] >= 0 ? ABC[ad[c]] : '', size: 14, cls: 'mono ' + (hot && hot.has(c) ? 'hot' : ad[c] >= 0 ? 'p1-ct' : 'p1-ghost') });
        }
        return it;
      };
      F.add({ items: table(5, -1), say: `Before 1938 every operator set his rotors to the day's ground setting, chose a message key of three letters and typed it twice. Six letters come out, the indicator. ${list.length} indicators were intercepted on this day; the analyst does not know the keys, shown here only to explain.`, meta: {} });
      for (let k = 0; k < 4; k++) {
        const x = list[k].indicator, a = ABC.indexOf(x[0]), d = ABC.indexOf(x[3]);
        const fresh = ad[a] < 0; ad[a] = d; if (fresh) F.count('known');
        F.add({ items: table(5, k).concat(mapRow(new Set([a]))), say: `Indicator ${x}: letters 1 and 4 come from the same key letter ${list[k].key[0]}, enciphered at positions 1 and 4. If A1 and A4 are those two permutations, ${x[0]} = A1(${list[k].key[0]}) and ${x[3]} = A4(${list[k].key[0]}), and since A1 is its own inverse, ${x[3]} = A4(A1(${x[0]})). So the product AD takes ${x[0]} to ${x[3]}, whatever the key was.`, meta: { ind: k } });
      }
      for (let c = 0; c < 26; c++) if (fi.maps.AD[c] >= 0) ad[c] = fi.maps.AD[c];
      F.set('known', ad.filter((v) => v >= 0).length);
      F.add({ items: table(5, -1).concat(mapRow()), say: fi.trace[0].say + (fi.complete.AD ? '' : ' More traffic would fill the gaps.'), meta: {} });
      // the cycles of AD, from the indicators where complete, else the closed ones
      const cyc = fi.complete.AD ? fi.cycles.AD.cycles : fi.cycles.AD.cycles;
      const rg = rings(cyc, 0, 180, 760, {});
      if (cyc.length) {
        const first = cyc[0];
        F.add({ items: mapRow().concat(rings([first], 0, 180, 760, {}).items), say: `Follow the map round: ${Array.from(first).join(' → ')} → ${first[0]}. A cycle of length ${first.length}.`, meta: {} });
        F.add({ items: mapRow().concat(rg.items), say: `${fi.complete.AD ? 'All' : 'The closed'} cycles of AD: ${cyc.map((c) => '(' + c + ')').join(' ')}${fi.complete.AD ? `, lengths ${cyc.map((c) => c.length).join(', ')}. They come in pairs of equal length, as they must for a product of two swaps-only permutations.` : '. Some letters are still unknown, so the picture is incomplete.'}`, meta: { lengths: cyc.map((c) => c.length).join(' ') } });
      }
      F.add({ items: mapRow().concat(rg.items), say: `The day's characteristic, AD, BE and CF together: ${ch.text}. It is set by the rotor order and the ground setting alone.`, meta: { char: ch.text } });
      const noP = conj.withoutPlugs.AD.cycles;
      const rgNo = rings(noP, 0, 180, 760, { prefix: 'np', edgeCls: '' });
      F.add({ items: mapRow().concat(rgNo.items), say: `${conj.trace[0].say} Here are the cycles without cables: ${noP.map((c) => '(' + c + ')').join(' ')}. Rename each letter by its cable and you get the cycles with cables. A conjugate keeps the cycle lengths; the plugboard's ${P.big(P.factorial(26) / (P.factorial(26 - 2 * E().parsePlugs(cfg.plugs).length) * P.factorial(E().parsePlugs(cfg.plugs).length) * 2n ** BigInt(E().parsePlugs(cfg.plugs).length)))} settings vanish from the problem.`, meta: { same: conj.same } });
      const job = R.catalogue({ target: ch.key, orders: [cfg.order] }); let res; do res = job.run(1e9); while (!res.done);
      const hit = res.matches.some((m) => m.window === cfg.window);
      F.add({ items: mapRow().concat(rgNo.items), say: `So a catalogue of characteristics for every rotor order and ground setting can be made once, with no cables at all. For order ${cfg.order.join(' ')} alone, ${P.big(17576)} positions give ${P.plural(res.matches.length, 'match', 'matches')} for ${ch.text}${hit ? `, ${cfg.window} among them` : ''}. Look up the day's characteristic, try the handful of candidates, and the plugboard can then be read off the traffic.`, meta: { end: true, matches: res.matches.length } });
      return { frames: F.list, def: P.def('Rejewski\'s characteristic', ['indicator: E(k k), 6 letters, positions 1…6', 'A1 … A6: the machine at positions 1 … 6', 'AD = A4 ∘ A1, BE = A5 ∘ A2, CF = A6 ∘ A3', 'with plugboard σ: Ai = σ Ti σ', '⇒ AD = σ (T4 T1) σ: same cycle lengths']), counters: [{ id: 'known', label: 'letters of AD known' }] };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.lengths !== undefined, pick: 'option', ask: 'The cycles of AD come in pairs of equal length. Do you expect that to hold?', options: ['yes, always', 'only without cables', 'only by chance'], answer: 'yes, always', explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.same !== undefined, pick: 'option', ask: 'Without the cables, will AD\'s cycle lengths change?', options: ['yes', 'no'], answer: (fr, i) => (fr[i + 1].meta.same ? 'no' : 'yes'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why do letters 1 and 4 of an indicator reveal anything?', options: ['They are the same plaintext letter enciphered at two known positions', 'They are always equal', 'They spell the key', 'They are random'], answer: 0, why: 'The message key was typed twice, so letter 1 and letter 4 hide the same key letter.' },
      { q: 'The plugboard σ turns AD into σ·AD·σ. What is kept?', options: ['the letters of each cycle', 'the lengths of the cycles', 'nothing', 'only fixed points'], answer: 1, why: 'Conjugation renames letters but keeps the cycle structure.' },
      { q: 'Why do AD\'s cycles come in pairs of equal length?', options: ['Coincidence', 'AD is a product of two involutions without fixed points', 'The ground setting is symmetric', 'Because of the rings'], answer: 1, why: 'A product of two such involutions always has its cycles in equal-length pairs.' },
      { q: 'What did the characteristic let the codebreakers do?', options: ['Read the plugboard at once', 'Look up the rotor order and ground setting in a catalogue made without cables', 'Avoid the double step', 'Change the indicators'], answer: 1, why: 'The characteristic ignores the plugboard, so a cable-free catalogue suffices.' },
    ],
  });

  // ---- crib alignment ------------------------------------------------------------------------------------------------
  const CW = 18, SHOW = 44;
  S.topic({
    id: 'p01-crib-align', family: 'p01-bombe', order: 20, title: 'Laying a crib against the ciphertext',
    blurb: 'A crib is a phrase the analyst believes is in the message. Enigma never enciphers a letter to itself, so wherever a crib letter would stand over the same cipher letter, the crib cannot be there. Sliding it along rules most places out.',
    inputs: [{ id: 'crib', kind: 'text', label: 'Crib', def: 'NORTHVALLEY', check: (v) => { const n = P.letters(v).length; return n < 4 ? 'Crib: at least 4 letters' : n > 20 ? 'Crib: at most 20 letters' : null; } }],
    presets: [
      { label: 'NORTHVALLEY', values: { crib: 'NORTHVALLEY' } },
      { label: 'WEATHERREPORT', values: { crib: 'WEATHERREPORT' } },
      { label: 'RAINBYEVENING', values: { crib: 'RAINBYEVENING' } },
      { label: 'A long crib: WEATHERREPORTFORTHE', values: { crib: 'WEATHERREPORTFORTHE' } },
    ],
    run(inp) {
      const ct = P.enCipher().slice(0, SHOW), crib = P.letters(inp.crib), al = E().bombe.align(ct, crib), F = new S.Frames(['out']);
      const real = P.letters(P.EN.plain).indexOf(crib);
      const pic = (off, o) => {
        o = o || {};
        const it = [P.title('c:t', 0, -12, 'ciphertext')];
        const clash = new Set(off >= 0 ? al.offsets[off].clashes.map((c) => c.pos) : []);
        it.push(...P.strip('c:', 0, 0, ct, { cw: CW - 1, gap: 1, h: 28, size: 14, cls: (i) => (clash.has(i) ? 'p1-bad' : off >= 0 && i >= off && i < off + crib.length ? 'p1-ct' : 'soft') }));
        if (off >= 0) it.push(...P.strip('k:', off * CW, 34, crib, { cw: CW - 1, gap: 1, h: 28, size: 14, cls: (i) => (clash.has(off + i) ? 'p1-bad' : 'p1-pl') }));
        it.push(P.title('o:t', 0, 106, 'offsets: green may hold the crib, red cannot'));
        al.offsets.forEach((x, k) => { if (k > o.upto) return; it.push({ key: 'o:' + k, kind: 'cell', x: k * CW, y: 116, w: CW - 1, h: 22, rx: 3, text: String(k % 10), size: 12, cls: 'mono ' + (k === off ? 'hot' : x.ok ? 'p1-good' : 'p1-bad'), audit: 'small-ok' }); });
        return it;
      };
      F.add({ items: pic(-1, { upto: -1 }), say: `The first ${SHOW} letters of an intercepted message, and a guess: the report probably contains ${crib}. Where could it be? Slide it along and look for any crib letter standing over the same cipher letter.`, meta: {} });
      al.offsets.forEach((x, k) => {
        if (!x.ok) F.count('out');
        F.add({ items: pic(k, { upto: k }), say: al.trace[k].say, meta: { off: k, ok: x.ok }, slow: k > 2 });
      });
      F.add({ items: pic(-1, { upto: al.offsets.length }), say: `${al.trace[al.trace.length - 1].say.replace('….', '…')} ${real >= 0 && real < al.offsets.length ? `(The crib really is at offset ${real}${al.possible.includes(real) ? ', one of the survivors' : ''}.)` : ''} Each survivor would be tested on the Bombe; a longer crib rules out more places.`.trim(), meta: { end: true } });
      return { frames: F.list, def: P.def('Crib alignment', ['Enigma: E(x) ≠ x at every position', 'crib c₀ … c_(n−1) at offset k:', '  impossible if some cᵢ = cipher[k + i]', 'survivors go to the Bombe']), counters: [{ id: 'out', label: 'offsets ruled out' }] };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.off !== undefined && fr[i + 1].meta.off < 4, pick: 'option', ask: (fr, i) => `Can the crib sit at offset ${fr[i + 1].meta.off}?`, options: ['yes, no letter faces itself', 'no, a letter faces itself'], answer: (fr, i) => (fr[i + 1].meta.ok ? 'yes, no letter faces itself' : 'no, a letter faces itself'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Cipher text …QWERT…, crib KEEP. Can K E E P stand under W E R T?', options: ['yes', 'no, E faces E'], answer: 1, why: 'The second crib letter E would face cipher E, which Enigma cannot produce.' },
      { q: 'Why does a longer crib rule out more offsets?', options: ['It is easier to type', 'Each extra letter is another chance to clash', 'It changes the key', 'It does not'], answer: 1, why: 'At a wrong offset each letter clashes with chance about 1/26; more letters, more clashes.' },
      { q: 'Does surviving the alignment prove the crib is there?', options: ['yes', 'no, it only means it is not ruled out'], answer: 1, why: 'Many wrong offsets survive; the Bombe decides.' },
      { q: 'Where did good cribs come from?', options: ['Random guesses', 'Routine wording such as report headers and weather messages', 'The key sheet', 'The plugboard'], answer: 1, why: 'Stereotyped messages repeated predictable phrases.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
