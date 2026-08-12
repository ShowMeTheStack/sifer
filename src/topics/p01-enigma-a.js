// Part 1, inside Enigma: one key press followed through the machine, the pawls and the double step, the plugboard,
// and why the reflector means no letter can ever encrypt to itself.
(function (S) {
  'use strict';
  const P = S.P1, ABC = P.ABC;
  const E = () => S.Enigma, C = () => S.Classic;
  const keyLetter = (label, def) => ({ id: 'key', kind: 'text', label, def, check: (v) => (/^[A-Za-z]$/.test(String(v).trim()) ? null : label + ': one letter') });

  // ---- the signal path ----------------------------------------------------------------------------------------------
  S.topic({
    id: 'p01-enigma-path', family: 'p01-enigma', order: 10, title: 'One key press through Enigma',
    blurb: 'Press a key: the rotors step first, then the current runs through the plugboard, the entry wheel, three rotors, the reflector, back through the rotors by other wires, the plugboard again, and lights a lamp.',
    inputs: P.enInputs({}).concat([keyLetter('Key pressed', 'W')]),
    presets: [
      { label: 'The practice key, key W', values: { order: 'IV I III', rings: 'AAA', window: 'BXC', plugs: 'IE NZ MU KF OC XS DV PL JT YG', key: 'W' } },
      { label: 'No cables, rings at A', values: { order: 'I II III', rings: 'AAA', window: 'AAA', plugs: '', key: 'A' } },
      { label: 'A press that turns the middle rotor', values: { order: 'I II III', rings: 'AAA', window: 'ADV', plugs: 'AB CD', key: 'K' } },
      { label: 'Ring settings B C D', values: { order: 'II V I', rings: 'BCD', window: 'KQD', plugs: 'AM BT CY DR', key: 'E' } },
    ],
    run(inp) {
      const cfg = P.enCfg(inp), m = E().machine(cfg), before = m.window, k = ABC.indexOf(String(inp.key).trim().toUpperCase());
      const pr = m.press(ABC[k]), st = pr.stepping, path = pr.path, tr = pr.trace, after = pr.window, F = new S.Frames();
      const win = (w) => w.split('');
      const base = (o) => P.machineItems(Object.assign({ cfg, windows: win(after), path, key: k }, o));
      F.add({ items: P.machineItems({ cfg, windows: win(before), key: k }), say: `Enigma I with rotors ${cfg.order.join(', ')} from left to right, reflector B, rings ${cfg.rings} and the window showing ${before}. Every one of the 26 contacts is drawn as a row; the rotors are wired differently inside and turn, so the rows they connect change at every press. Key ${ABC[k]} goes down.`, meta: {} });
      F.add({ items: P.machineItems({ cfg, windows: win(after), key: k, moved: st.steps }), say: tr[0].say + ' ' + tr[1].say + ' Stepping always happens before the current flows.', meta: { step: true, moved: st.steps.filter(Boolean).length } });
      // path parts: plug in, ETW in, R, M, L, UKW, L, M, R, ETW out, plug out
      const sayFor = (pp) => {
        if (pp.part === 'plugboard') return pp.dir === 'in' ? tr.find((t) => t.kind === 'plug').say : tr.filter((t) => t.kind === 'plug')[1].say;
        if (pp.part === 'ETW') return pp.dir === 'in' ? `The entry wheel passes contact ${ABC[pp.from]} straight to the right-hand rotor.` : `Back through the entry wheel at contact ${ABC[pp.from]}.`;
        if (pp.part === 'UKW') return tr.find((t) => t.kind === 'reflector').say + ' The reflector is what sends the current back the way it came, by a different route.';
        const t = tr.find((x) => x.kind === 'rotor' && x.rotor === pp.rotor && x.dir === pp.dir);
        return t.say;
      };
      const marks = new Set();
      for (let n = 1; n <= path.length; n++) {
        const pp = path[n - 1];
        marks.add(pp.to);
        if (pp.part === 'ETW' && pp.dir === 'in') continue;
        F.add({ items: base({ upto: n, marks: new Set(marks) }), say: sayFor(pp), meta: { part: pp.part, dir: pp.dir, to: ABC[pp.to] } });
      }
      F.add({ items: base({ upto: path.length, lamp: ABC.indexOf(pr.out) }), say: `${tr[tr.length - 1].say} The whole journey: ${path.filter((p) => p.part !== 'ETW').map((p) => ABC[p.to]).join(' → ')}. Pressing ${pr.out} at the same position would light ${ABC[k]}: the path simply runs backwards.`, meta: { end: true, out: pr.out } });
      return { frames: F.list, def: P.def('One key press', ['step the rotors (pawls and notches)', 'σ: plugboard', 'R, M, L: each shifted by window − ring', 'U: reflector, pairs of letters', 'L⁻¹, M⁻¹, R⁻¹, then σ again', 'out = σ R⁻¹ M⁻¹ L⁻¹ U L M R σ (in)']) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.step, pick: 'option', ask: 'How many rotors will move on this key press?', options: ['one', 'two', 'three'], answer: (fr, i) => ['one', 'two', 'three'][fr[i + 1].meta.moved - 1], explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.end, pick: 'option', ask: 'Which lamp lights?', options: (fr, i) => P.letterOptions(fr[i + 1].meta.out, [fr[i].meta.to]), answer: (fr, i) => fr[i + 1].meta.out, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What happens first when a key is pressed?', options: ['The lamp lights', 'The rotors step', 'The plugboard swaps', 'The reflector turns'], answer: 1, why: 'The pawls move the rotors as the key goes down; the current flows only once the key closes the circuit.' },
      { q: 'How many times does the current pass through each rotor?', options: ['once', 'twice: in and back out by a different route', 'three times', 'it depends on the plugboard'], answer: 1, why: 'Forward to the reflector, then back again.' },
      { q: 'Why does the right-hand rotor matter most for the substitution changing every letter?', options: ['It has the most wires', 'It steps on every key press', 'It is next to the plugboard', 'It has no notch'], answer: 1, why: 'Every press turns it, so every letter meets a new wiring.' },
      { q: 'If key Q lights lamp T, what does key T light at the same position?', options: ['Q', 'T', 'something else', 'nothing'], answer: 0, why: 'The current path is reversible: Enigma at one position is its own inverse.' },
    ],
  });

  // ---- stepping and the double step ----------------------------------------------------------------------------------
  function wheels(cfg, win, o) {
    const items = [], X = [60, 200, 340], names = ['left', 'middle', 'right'];
    for (let i = 0; i < 3; i++) {
      const w = E().wheel(cfg.order[i]), pos = ABC.indexOf(win[i]);
      items.push(P.text('w:n' + i, X[i], 18, 'rotor ' + cfg.order[i] + ' (' + names[i] + ')', 'strong', 14, 'middle'));
      for (let d = -2; d <= 2; d++) {
        const c = ABC[(pos + d + 26) % 26], notch = i > 0 && (pos + d + 26) % 26 === w.notch;
        items.push({ key: 'w:' + i + ':' + d, kind: 'cell', x: X[i] - 26, y: d === 0 ? 97 : 100 + d * 36, w: 52, h: d === 0 ? 34 : 28, rx: 5, text: c, size: d === 0 ? 20 : 14, cls: 'mono ' + (d === 0 ? (o.moved && o.moved[i] ? 'hot' : 'act') : 'soft') + (notch ? ' p1-notch' : '') });
      }
      if (i > 0) items.push(P.text('w:nt' + i, X[i], 232, 'notch at ' + ABC[w.notch], 'key', 13, 'middle'));
      // the pawl to the right of each rotor: engaged or not
      const engaged = o.pawls && o.pawls[i];
      items.push({ key: 'w:p' + i, kind: 'cell', x: X[i] + 38, y: 102, w: 46, h: 24, rx: 4, text: 'pawl', size: 12, cls: engaged ? 'hot' : 'soft', audit: 'small-ok' });
    }
    return items;
  }
  function log(rows, o) {
    const items = [P.title('l:t', 480, 18, 'key presses')];
    rows.forEach((r, k) => {
      const y = 34 + k * 30;
      items.push(P.text('l:n' + k, 500, y + 19, String(k + 1), 'tick', 13, 'end'));
      for (let i = 0; i < 3; i++) items.push({ key: 'l:' + k + ':' + i, kind: 'cell', x: 512 + i * 30, y, w: 28, h: 26, rx: 3, text: r.after[i], size: 15, cls: 'mono ' + (r.steps[i] ? (r.steps[0] && r.steps[1] ? 'hot' : 'p1-ct') : 'soft') });
      if (r.steps[0] && r.steps[1] && r.double) items.push(P.text('l:d' + k, 612, y + 19, 'double step', 'hot', 13));
      else if (r.steps[1]) items.push(P.text('l:d' + k, 612, y + 19, 'middle steps', 'act', 13));
    });
    return items;
  }
  S.topic({
    id: 'p01-enigma-stepping', family: 'p01-enigma', order: 20, title: 'Stepping and the double step',
    blurb: 'Three pawls push on every key press. The right rotor always moves; when it shows its notch, the middle pawl also drops in; when the middle rotor shows its own notch, the left pawl drops in and pushes both the left rotor and the middle rotor, so the middle rotor steps twice in a row.',
    inputs: [P.enInputs({ order: 'I II III' })[0], { id: 'window', kind: 'text', label: 'Start window', def: 'ADT', check: (v) => (/^[A-Za-z]{3}$/.test(String(v).trim()) ? null : 'Start window: three letters') }, { id: 'presses', kind: 'number', label: 'Key presses', def: 8, min: 2, max: 12 }],
    presets: [
      { label: 'I II III from ADT: the double step', values: { order: 'I II III', window: 'ADT', presses: 8 } },
      { label: 'IV I III from BXC', values: { order: 'IV I III', window: 'BXC', presses: 6 } },
      { label: 'V IV II from QIE', values: { order: 'V IV II', window: 'QIE', presses: 10 } },
    ],
    run(inp) {
      const cfg = { order: String(inp.order).trim().toUpperCase().split(/[\s,]+/), reflector: 'B', window: String(inp.window).trim().toUpperCase() };
      const m = E().machine(cfg), rows = [], F = new S.Frames(['moves']);
      const nm = E().wheel(cfg.order[1]).notch, nr = E().wheel(cfg.order[2]).notch;
      F.add({ items: wheels(cfg, m.window, {}).concat(log(rows)), say: `The window shows ${m.window}. The middle rotor ${cfg.order[1]} carries its neighbour at ${ABC[nm]}, the right rotor ${cfg.order[2]} at ${ABC[nr]}: a pawl can only drop into a rotor's notch when that letter is in the window.`, meta: {} });
      let doubles = 0;
      for (let k = 0; k < inp.presses; k++) {
        const prev = rows.length ? rows[rows.length - 1] : null;
        const s = m.step();
        const dbl = s.steps[0] && s.steps[1] && prev && prev.steps[1];
        if (s.steps[0]) doubles++;
        rows.push({ after: s.after, steps: s.steps, double: dbl || s.steps[0] });
        F.count('moves', s.steps.filter(Boolean).length);
        F.add({ items: wheels(cfg, s.after, { moved: s.steps, pawls: s.pawls }).concat(log(rows)), say: `Press ${k + 1}. ${s.trace[0].say} ${s.trace[1].say}`, meta: { press: k, n: s.steps.filter(Boolean).length, before: s.before } });
      }
      // the period of the stepping, by walking the lever drive until it returns
      let p = cfg.window.split('').map((c) => ABC.indexOf(c)), q = p.slice(), period = 0, seenStart = false;
      const visited = new Set();
      while (!seenStart && period < 20000) { q = E().advance(q, nm, nr); period++; const key = q.join(); if (visited.has(key)) break; visited.add(key); if (q.join() === p.join()) seenStart = true; }
      F.add({ items: wheels(cfg, m.window, {}).concat(log(rows)), say: `${doubles ? `The middle rotor moved on two presses running: once carried by the right rotor, then again by its own notch, taking the left rotor with it. ` : 'No double step in these presses; start the window one or two letters before the middle notch to see it. '}Because of the double step the rotors do not count like an odometer: a full cycle takes ${P.big(seenStart ? period : visited.size)} presses, not 26³ = 17,576.`, meta: { end: true } });
      return { frames: F.list, def: P.def('The lever drive', ['right pawl: always pushes the right rotor', 'middle pawl: drops in at the right notch', '  → pushes the middle rotor', 'left pawl: drops in at the middle notch', '  → pushes the left rotor AND the middle', 'notches: I Q, II E, III V, IV J, V Z']), counters: [{ id: 'moves', label: 'rotor moves' }] };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.press !== undefined && fr[i + 1].meta.press > 0, pick: 'option', ask: (fr, i) => `The window shows ${fr[i + 1].meta.before}. How many rotors move on the next press?`, options: ['one', 'two', 'three'], answer: (fr, i) => ['one', 'two', 'three'][fr[i + 1].meta.n - 1], explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Rotors I II III show ADU. What does the window show after one press?', options: ['ADV', 'AEV', 'ADU', 'BEV'], answer: 0, why: 'Only the right rotor moves: III shows V afterwards, but its notch is acted on at the next press.' },
      { q: 'And after the window shows ADV, the next press gives…', options: ['ADW', 'AEW', 'BEW', 'BDW'], answer: 1, why: 'III shows its notch V, so the middle pawl drops in: D → E, V → W.' },
      { q: 'And after AEW?', options: ['AEX', 'AFX', 'BFX', 'BEX'], answer: 2, why: 'II shows its notch E: the left pawl pushes the left rotor and the middle rotor together, the double step.' },
      { q: 'Why is the period of Enigma\'s stepping 26 × 25 × 26 rather than 26³?', options: ['The left rotor never moves', 'The double step skips one middle position in each cycle', 'The reflector steps', 'The rings change it'], answer: 1, why: 'The middle rotor makes an extra move each time the left rotor turns, so one middle position per cycle is passed through in a single press.' },
    ],
  });

  // ---- the plugboard ------------------------------------------------------------------------------------------------
  const SX = 40, SW = 26;
  function board(pairs, o) {
    const items = [P.title('b:t', SX, 12, 'plugboard: a cable swaps two letters, on the way in and on the way out')];
    for (let c = 0; c < 26; c++) items.push({ key: 'b:' + c, kind: 'cell', x: SX + c * SW, y: 70, w: SW - 3, h: 26, rx: 4, text: ABC[c], size: 14, cls: 'mono ' + (o.hot && o.hot.has(c) ? 'hot' : pairs.some((p) => p.includes(ABC[c])) ? 'p1-key' : 'soft') });
    pairs.forEach((p, k) => {
      const a = ABC.indexOf(p[0]), b = ABC.indexOf(p[1]), x1 = SX + a * SW + 11.5, x2 = SX + b * SW + 11.5, h = 10 + Math.abs(b - a) * 1.6;
      items.push({ key: 'b:c' + p, kind: 'path', d: `M${x1} 68 C${x1} ${68 - h}, ${x2} ${68 - h}, ${x2} 68`, cls: 'p1-cable' + (o.hotPair === p ? ' hot' : ''), pathAudit: 'ignore', box: { x: Math.min(x1, x2), y: 68 - h, w: Math.abs(x2 - x1), h } });
    });
    return items;
  }
  function chain(y, vals, o) {
    // in → σ → scrambler → σ → out, as boxes with letters between
    const items = [], labels = ['key', 'plugboard', 'rotors and reflector', 'plugboard', 'lamp'], xs = [60, 200, 380, 560, 700];
    items.push(P.text('ch:t' + o.id, 0, y - 30, o.title, 'title', 13));
    xs.forEach((x, i) => items.push({ key: 'ch:' + o.id + i, kind: 'state', x, y, w: i === 2 ? 170 : i % 2 ? 110 : 64, h: 40, rx: 6, lines: i % 2 === 0 && i !== 2 ? [labels[i] + ' ' + vals[i === 0 ? 0 : 3]] : [labels[i]], size: 14, cls: 'block ' + (i === 2 ? 'cipher' : i % 2 ? 'key' : 'soft') }));
    for (let i = 0; i < 4; i++) items.push({ key: 'ch:e' + o.id + i, kind: 'edge', from: 'ch:' + o.id + i, to: 'ch:' + o.id + (i + 1), label: vals[i === 0 ? 0 : i === 1 ? 1 : i === 2 ? 2 : 3], size: 15, cls: o.hot ? 'act' : '' });
    return items;
  }
  S.topic({
    id: 'p01-enigma-plugboard', family: 'p01-enigma', order: 30, title: 'The plugboard',
    blurb: 'Cables on the front panel swap pairs of letters before the current reaches the rotors and again after it comes back. Ten cables multiply the keys by about 1.5 × 10^14, yet they never change the rotors\' pattern, only rename its letters.',
    inputs: [{ id: 'plugs', kind: 'text', label: 'Cables', def: 'IE NZ MU KF OC XS DV PL JT YG', check: (v) => { try { const p = E().parsePlugs(v, 13); return p.length < 1 ? 'Cables: at least one' : null; } catch (e) { return 'Cables: ' + e.message; } } }, { id: 'keys', kind: 'text', label: 'Keys to press', def: 'NEW', check: (v) => (P.letters(v).length < 1 || P.letters(v).length > 5 ? 'Keys: 1 to 5 letters' : null) }],
    presets: [
      { label: 'Ten cables, keys NEW', values: { plugs: 'IE NZ MU KF OC XS DV PL JT YG', keys: 'NEW' } },
      { label: 'One cable, keys AB', values: { plugs: 'AB', keys: 'ABC' } },
      { label: 'Thirteen cables', values: { plugs: 'AZ BY CX DW EV FU GT HS IR JQ KP LO MN', keys: 'SIFER' } },
    ],
    run(inp) {
      const pairs = E().parsePlugs(inp.plugs, 13).map((p) => p.join('')), keys = P.letters(inp.keys), cfg = { order: ['IV', 'I', 'III'], reflector: 'B', rings: 'AAA', window: 'BXC' };
      const F = new S.Frames(['cables']);
      const shown = [];
      F.add({ items: board([], {}), say: `Without cables every letter goes straight through the plugboard. Rotors IV, I, III stand at BXC; ${pairs.length} cable${pairs.length === 1 ? '' : 's'} will be plugged in.`, meta: {} });
      const lim = Math.min(pairs.length, 4);
      for (let k = 0; k < lim; k++) { shown.push(pairs[k]); F.count('cables'); F.add({ items: board(shown, { hotPair: pairs[k] }), say: `Cable ${pairs[k][0]}–${pairs[k][1]}: ${pairs[k][0]} becomes ${pairs[k][1]} and ${pairs[k][1]} becomes ${pairs[k][0]}, in both directions.`, meta: {} }); }
      if (pairs.length > lim) { F.count('cables', pairs.length - lim); F.add({ items: board(pairs, {}), say: `And the other ${P.plural(pairs.length - lim, 'cable')}: ${pairs.slice(lim).join(' ')}. ${26 - 2 * pairs.length} letters stay unplugged.`, meta: {} }); }
      const with_ = E().machine(Object.assign({ plugs: pairs.join(' ') }, cfg)), bare = E().machine(Object.assign({ plugs: '' }, cfg));
      for (const ch of keys) {
        const a = with_.press(ch), b = bare.press(ch), p = a.path;
        const sin = ABC[p[0].to], sout = ABC[p[p.length - 1].from];
        const items = board(pairs, { hot: new Set([ABC.indexOf(ch), p[0].to, p[p.length - 1].from, ABC.indexOf(a.out)]) }).concat(chain(200, [ch, sin, sout, a.out], { id: 'w', title: 'with the cables, window ' + a.window, hot: true })).concat(chain(330, [ch, ch, b.out, b.out], { id: 'b', title: 'the same rotors, no cables' }));
        F.add({ items, say: `Key ${ch} at window ${a.window}: the plugboard sends it in as ${sin}; the rotors and reflector turn ${sin} into ${sout}; the plugboard turns ${sout} into ${a.out}. Without cables the rotors alone would give ${ch} → ${b.out}.`, meta: { key: ch, out: a.out } });
      }
      const n10 = P.factorial(26) / (P.factorial(26 - 2 * pairs.length) * P.factorial(pairs.length) * 2n ** BigInt(pairs.length));
      F.add({ items: board(pairs, {}), say: `With ${pairs.length} cable${pairs.length === 1 ? '' : 's'} there are 26! / ((26 − ${2 * pairs.length})! · ${pairs.length}! · 2^${pairs.length}) = ${P.big(n10)} ways to plug them. A huge number, but the plugboard is a fixed swap σ on both sides: the machine is σ·S·σ, a renamed copy of the rotors' substitution S. Rejewski and the Bombe both exploit exactly this.`, meta: { end: true } });
      return { frames: F.list, def: P.def('Plugboard', ['σ: an involution swapping cable pairs', 'machine = σ · S · σ', '  (S: rotors and reflector)', 'ways with n cables:', '  26! / ((26 − 2n)! · n! · 2ⁿ)']), counters: [{ id: 'cables', label: 'cables' }] };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.key !== undefined, pick: 'option', ask: (fr, i) => `Which lamp lights for key ${fr[i + 1].meta.key}?`, options: (fr, i) => P.letterOptions(fr[i + 1].meta.out, []), answer: (fr, i) => fr[i + 1].meta.out, explain: (fr, i) => fr[i + 1].say, once: true },
    ],
    quiz: [
      { q: 'A cable joins K and F. The plugboard turns K into…', options: ['K', 'F', 'a letter chosen by the rotors', 'nothing'], answer: 1, why: 'A cable swaps its two letters.' },
      { q: 'How many times does the current pass the plugboard on one key press?', options: ['once', 'twice', 'three times', 'never'], answer: 1, why: 'On the way in and on the way out.' },
      { q: 'With 10 cables, how many letters are unplugged?', options: ['0', '6', '10', '16'], answer: 1, why: '10 cables use 20 letters.' },
      { q: 'Why does the plugboard not change the cycle lengths Rejewski measured?', options: ['It is removed at night', 'σ·S·σ is a conjugate of S: same cycle structure, letters renamed', 'It has too few cables', 'The rotors cancel it'], answer: 1, why: 'Conjugating a permutation renames its elements but keeps its cycle type.' },
    ],
  });

  // ---- no letter becomes itself ----------------------------------------------------------------------------------------
  const CX = 220, CY = 220, CR = 170;
  const at = (c, r) => { const a = (-90 + (c * 360) / 26) * Math.PI / 180; return { x: CX + (r || CR) * Math.cos(a), y: CY + (r || CR) * Math.sin(a) }; };
  function chords(perm, o) {
    const items = [P.text('cc:t', CX, 14, o.title, 'title', 13, 'middle')];
    for (let c = 0; c < 26; c++) { const p = at(c); items.push({ key: 'cc:' + c, kind: 'state', x: p.x, y: p.y, r: 14, text: ABC[c], size: 14, cls: 'p1-node' + (o.hot && o.hot.has(c) ? ' hot' : '') }); }
    for (let c = 0; c < 26; c++) {
      const d = perm[c]; if (d <= c) continue;
      const a = at(c, CR - 15), b = at(d, CR - 15), hot = o.hot && o.hot.has(c) && o.hot.has(d);
      items.push({ key: 'cc:l' + c, kind: 'path', d: `M${a.x.toFixed(1)} ${a.y.toFixed(1)} Q${CX} ${CY} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`, cls: 'p1-chord' + (hot ? ' hot' : ''), pathAudit: 'ignore', layer: 'back' });
    }
    return items;
  }
  S.topic({
    id: 'p01-enigma-noself', family: 'p01-enigma', order: 40, title: 'Why no letter encrypts to itself',
    blurb: 'The reflector pairs the 26 letters off, none with itself. So at every position the whole machine pairs letters too: pressing one lights its partner, never itself. That made Enigma its own inverse, and it gave the codebreakers a foothold.',
    inputs: P.enInputs({}).concat([keyLetter('Key pressed', 'E')]),
    presets: [
      { label: 'The practice key, key E', values: { order: 'IV I III', rings: 'AAA', window: 'BXC', plugs: 'IE NZ MU KF OC XS DV PL JT YG', key: 'E' } },
      { label: 'No cables', values: { order: 'I II III', rings: 'AAA', window: 'AAA', plugs: '', key: 'T' } },
    ],
    run(inp) {
      const cfg = P.enCfg(inp), k = ABC.indexOf(String(inp.key).trim().toUpperCase()), F = new S.Frames();
      const U = Array.from(E().wheel('B').fwd);
      const m = E().machine(cfg); m.step(); const perm = Array.from(m.permutation()), win = m.window;
      const fixedU = U.filter((v, i) => v === i).length, fixedM = perm.filter((v, i) => v === i).length, invol = perm.every((v, i) => perm[v] === i);
      F.add({ items: chords(U, { title: 'reflector B: 13 pairs' }), say: `The reflector B is wired in 13 pairs: ${Array.from({ length: 26 }, (_, i) => i).filter((i) => U[i] > i).map((i) => ABC[i] + ABC[U[i]]).join(' ')}. ${fixedU ? fixedU + ' letters are wired to themselves' : 'No letter is wired to itself'}: a reflector cannot have such a wire, or the current would come straight back down the same wire.`, meta: {} });
      const pr = E().machine(cfg).press(ABC[k]), y = pr.path.find((p) => p.part === 'UKW');
      F.add({ items: chords(U, { title: 'reflector B: 13 pairs', hot: new Set([y.from, y.to]) }), say: `Press ${ABC[k]} with the window at ${cfg.window}; the rotors step to ${pr.window} and carry it to reflector contact ${ABC[y.from]}, which sends it back as ${ABC[y.to]}, a different letter. The way back uses the inverse wiring from a different contact, so it cannot end at ${ABC[k]}: it lights ${pr.out}.`, meta: {} });
      F.add({ items: chords(perm, { title: 'the whole machine at ' + win + ': 13 pairs', hot: new Set([k, ABC.indexOf(pr.out)]) }), say: `The whole machine at window ${win}, plugboard included, is again ${invol ? 'a set of 13 swaps' : 'a permutation'}: ${perm.map((v, i) => (v > i ? ABC[i] + ABC[v] : '')).filter(Boolean).join(' ')}. ${fixedM ? fixedM + ' letters map to themselves.' : 'No letter maps to itself.'} ${ABC[k]} lights ${pr.out}, and ${pr.out} would light ${ABC[k]}: encrypting and decrypting are the same operation.`, meta: { out: pr.out, key: ABC[k] } });
      // over a long text: matches between plain and cipher letters
      const txt = C().letters(C().corpus.text()).slice(0, 2000), ct = E().encrypt(cfg, txt);
      let same = 0; for (let i = 0; i < txt.length; i++) if (txt[i] === ct[i]) same++;
      const pad = C().otp.pad(txt.length, C().rng(1918)), otp = C().otp.letters(txt, pad, 1).out; let vs = 0; for (let i = 0; i < txt.length; i++) if (txt[i] === otp[i]) vs++;
      F.add({ items: chords(perm, { title: 'the whole machine at ' + win + ': 13 pairs' }), say: `Over ${P.big(txt.length)} letters of text, Enigma never once put a letter in place of itself: ${same} matches. A one-time pad over the same text gives ${vs}, close to the ${Math.round(txt.length / 26)} that one chance in 26 predicts. So if an analyst guesses a phrase in the message, it cannot sit anywhere it would face its own letters, the first step of breaking a message with a crib.`, meta: { end: true } });
      return { frames: F.list, def: P.def('The reflector', ['U: 13 swaps, no fixed letter', 'machine = σ R⁻¹M⁻¹L⁻¹ U L M R σ', '= a conjugate of U', '⇒ 13 swaps, no fixed letter', '⇒ E(E(x)) = x, and E(x) ≠ x']) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.out !== undefined, pick: 'option', ask: (fr, i) => `At this position, could key ${fr[i + 1].meta.key} ever light lamp ${fr[i + 1].meta.key}?`, options: ['yes, with the right plugboard', 'yes, once in 26 presses', 'no, never'], answer: 'no, never', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why can Enigma never encrypt a letter to itself?', options: ['The plugboard forbids it', 'The reflector has no letter wired to itself, and the rest of the path is a renaming', 'The rotors skip it', 'It is a coincidence'], answer: 1, why: 'The machine is a conjugate of the reflector, which has no fixed points.' },
      { q: 'At one position, A lights R. What does R light?', options: ['A', 'R', 'another letter', 'it depends on the rings'], answer: 0, why: 'The machine at a position is a set of swaps.' },
      { q: 'How did the codebreakers use the missing self-encryption?', options: ['To find the rings', 'To rule out crib positions where a crib letter would face itself', 'To read the plugboard directly', 'They did not'], answer: 1, why: 'A guessed phrase can only lie where no letter faces itself.' },
      { q: 'Out of 2,600 letters enciphered with a random one-time pad, about how many equal the plaintext letter?', options: ['0', 'about 100', 'about 1,300', 'all'], answer: 1, why: 'About 1 in 26 by chance; Enigma gives exactly 0.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
