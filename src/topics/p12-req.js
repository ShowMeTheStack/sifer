// Part 12, what a hash must do: the three security properties as games between a challenger and an adversary,
// played for real on SHA-256 cut to a few bits so that a win takes seconds; and the birthday paradox, drawn one
// birthday (or one digest) at a time, with the collision counter and the curve of the chance of a collision.
(function (S) {
  'use strict';
  const U = S.P12, H = () => S.Hash;
  const { t, panel } = U;

  // ---------------------------------------------------------------------------------------------------------------
  // the three games
  // ---------------------------------------------------------------------------------------------------------------
  const GAMES = {
    pre: { name: 'preimage', title: 'The preimage game', gives: 'a digest y', goal: 'find any m with H(m) = y' },
    second: { name: 'second-preimage', title: 'The second-preimage game', gives: 'a message m', goal: 'find m′ ≠ m with H(m′) = H(m)' },
    coll: { name: 'collision', title: 'The collision game', gives: 'nothing', goal: 'find any m ≠ m′ with H(m) = H(m′)' },
  };
  const LOG2 = (v) => Math.log2(v);

  /** play one game: every try, with its truncated digest, from the engine's SHA-256 and truncation */
  function play(game, bits, seed) {
    const Hs = H(), sha = (m) => Hs.get('sha256').hash(U.utf8(m)), cut = (m) => Hs.truncate(sha(m), bits), N = 2 ** bits;
    const rnd = Hs.rng('game:' + seed), tries = [], max = 40 * N;
    let secret = null, target = null, given = null, win = null;
    if (game === 'pre') { secret = 'door code ' + (1000 + rnd.int(9000)); target = cut(secret); }
    if (game === 'second') { given = 'Pay 100 to the library fund, ref ' + (100 + rnd.int(900)); target = cut(given); }
    const seen = new Map();
    for (let i = 1; i <= max && !win; i++) {
      const m = game === 'pre' ? 'guess ' + i : game === 'second' ? 'Pay 900 to Mallory, note ' + i : 'ticket ' + seed + '-' + i;
      const v = cut(m);
      const tr = { i, m, v };
      tries.push(tr);
      if (game === 'coll') { const j = seen.get(v); if (j !== undefined) win = { i, j, m, other: tries[j - 1].m, v }; else seen.set(v, i); }
      else if (v === target) win = { i, m, v };
    }
    const expected = game === 'coll' ? Math.sqrt((Math.PI / 2) * N) : N;
    return { tries, win, target, secret, given, expected, N, stored: game === 'coll' ? seen.size : 0, fullA: win ? U.hex(sha(win.m)) : null, fullB: win && win.other ? U.hex(sha(win.other)) : game === 'second' && win ? U.hex(sha(given)) : null };
  }

  function games(inp) {
    const g = inp.game, bits = +inp.bits, seed = +inp.seed, G = GAMES[g], Hs = H();
    const P = play(g, bits, seed), N = P.N, w = P.win, hx = (v) => Hs.truncHex(v, bits);
    const F = new S.Frames(['tries']);
    const chal = (stage) => {
      const items = [...panel('gm:ch', 24, 84, 300, 196, 'challenger'), ...panel('gm:ad', 596, 84, 300, 196, 'adversary')];
      const lines = g === 'pre' ? ['picks a secret message', stage >= 1 ? '“' + P.secret + '”' : '', stage >= 1 ? 'and hands over y = H(m)' : '']
        : g === 'second' ? ['picks a message m', stage >= 1 ? '“' + U.cut(P.given, 30) + '”' : '', stage >= 1 ? 'and hands it over' : '']
          : ['hands over nothing at all:', 'the adversary chooses both', 'messages'];
      lines.forEach((l, k) => l && items.push(t('gm:cl' + k, 38, 128 + k * 26, l, k === 1 && g !== 'coll' ? 'mono key' : '', 'start', k === 1 && g !== 'coll' ? 13 : 14)));
      items.push(t('gm:cg', 38, 262, 'H = SHA-256, first ' + bits + ' bits', 'ptick', 'start', 13));
      items.push(t('gm:ag', 610, 128, 'goal:', 'strong', 'start', 14));
      items.push(t('gm:ag2', 610, 154, G.goal, 'act', 'start', 14));
      items.push(t('gm:ag3', 610, 186, 'may hash as often as it likes', 'ptick', 'start', 13));
      if (stage >= 4 && w) {
        items.push(t('gm:aw', 610, 226, 'wins after ' + U.commas(w.i) + ' tries', 'good', 'start', 15));
        items.push(t('gm:aw2', 610, 252, 'expected about ' + U.commas(Math.round(P.expected)), 'ptick', 'start', 13));
      }
      // the challenge travels from left to right, the answer back
      items.push({ key: 'gm:w1', kind: 'wire', pts: [[324, 150], [596, 150]], head: true, cls: stage >= 1 ? 'act' : 'faint' });
      if (stage >= 1) items.push({ key: 'gm:c1', kind: 'chip', x: 460, y: 150, text: g === 'pre' ? 'y = ' + hx(P.target) : g === 'second' ? 'm' : '—', cls: 'key', audit: 'on-wire' });
      items.push({ key: 'gm:w2', kind: 'wire', pts: [[596, 230], [324, 230]], head: true, cls: stage >= 4 ? 'hot' : 'faint' });
      if (stage >= 4 && w) items.push({ key: 'gm:c2', kind: 'chip', x: 460, y: 230, text: g === 'coll' ? 'm, m′' : 'm′', cls: 'hot', audit: 'on-wire' });
      return items;
    };
    // the tries: a table of the first few and the winning ones
    const tries = (upto, hit) => {
      const items = [t('gm:tt', 24, 322, 'tries', 'ptitle')];
      const rows = [], first = P.tries.slice(0, Math.min(4, upto));
      for (const r of first) rows.push(r);
      if (hit && w) {
        if (g === 'coll' && w.j > 4) rows.push(null, P.tries[w.j - 1]);
        if (w.i > 4) rows.push(...(rows.length && rows[rows.length - 1] && rows[rows.length - 1].i + 1 < w.i ? [null] : []), P.tries[w.i - 1]);
      }
      rows.forEach((r, k) => {
        const y = 336 + k * 34;
        if (!r) { items.push(t('gm:te' + k, 60, y + 21, '⋮', 'ptick', 'middle', 16)); return; }
        const lit = hit && w && (r.i === w.i || (g === 'coll' && r.i === w.j));
        items.push({ key: 'gm:ti' + k, kind: 'cell', x: 24, y, w: 72, h: 28, rx: 4, text: '#' + U.commas(r.i), size: 13, cls: 'hex ' + (lit ? 'hot' : 'soft') });
        items.push({ key: 'gm:tm' + k, kind: 'cell', x: 100, y, w: 300, h: 28, rx: 4, text: U.cut(r.m, 34), size: 13, cls: 'mono ' + (lit ? 'hot' : '') });
        items.push({ key: 'gm:tv' + k, kind: 'cell', x: 404, y, w: 92, h: 28, rx: 4, text: hx(r.v), size: 14, cls: 'hex ' + (lit ? 'hot' : g !== 'coll' && P.target === r.v ? 'hot' : '') });
      });
      if (g !== 'coll') items.push(t('gm:tw', 404, 322, 'want ' + hx(P.target), 'key', 'start', 13));
      return items;
    };
    // the cost of each game, on a log scale
    const cost = (on) => {
      const top = Math.max(24, Math.ceil(LOG2(Math.max(N, w ? w.i : 1)) / 4) * 4);
      const pl = U.plot({ prefix: 'gc', x: 610, y: 352, w: 270, h: 200, xr: [0, 3], yr: [0, top], yticks: [0, top / 3, (2 * top) / 3, top].map((v) => Math.round(v)), fy: (v) => '2^' + v, ylabel: 'tries, on a log scale', tickSize: 13 });
      const items = pl.items.slice();
      const exp = { pre: N, second: N, coll: Math.sqrt((Math.PI / 2) * N) };
      ['pre', 'second', 'coll'].forEach((k, i) => {
        const v = LOG2(exp[k]), y = pl.Y(v), x = pl.X(i + 0.5);
        items.push({ key: 'gc:b' + k, kind: 'cell', x: U.r2(x - 20), y, w: 40, h: U.r2(pl.Y(0) - y), rx: 2, text: '', cls: 'hex ' + (k === g ? 'act' : 'soft') });
        items.push(t('gc:l' + k, x, pl.Y(0) + 34, k === 'pre' ? 'preimage' : k === 'second' ? '2nd preimage' : 'collision', k === g ? 'act' : 'ptick', 'middle', 13));
      });
      if (on && w) {
        const x = pl.X(['pre', 'second', 'coll'].indexOf(g) + 0.5), y = pl.Y(LOG2(w.i));
        items.push({ key: 'gc:m', kind: 'dot', x, y, r: 6, cls: 'hot', audit: 'overlap-ok', layer: 'top' });
        items.push(t('gc:mt', x + 25, y + 5, U.commas(w.i), 'hot', 'start', 13));
      }
      return items;
    };
    const head = U.head('gm:h', G.title + ' on SHA-256 cut to ' + bits + ' bits', 'N = 2' + U.sup(bits) + ' = ' + U.commas(N) + ' possible digests');
    const base = { bits, N, expected: P.expected };
    F.add({ items: [...head, ...chal(0), ...cost(false)], hl: { d: [0] }, say: `Two players: a challenger who holds SHA-256 cut to its first ${bits} bits, so ${U.commas(N)} digests are possible, and an adversary who wins the ${G.name} game if it can ${G.goal.replace('find', 'find')}.`, facts: base, meta: { stage: 'rules' } });
    const chSay = g === 'pre' ? `The challenger hashes its secret “${P.secret}” and hands over only y = ${hx(P.target)}. Any message with that digest wins, not just the secret.`
      : g === 'second' ? `The challenger hands over “${P.given}”, whose digest is ${hx(P.target)}. The adversary must find a different message with the same digest.`
        : 'The challenger hands over nothing: the adversary may pick both messages, and needs only that they differ and share a digest.';
    F.add({ items: [...head, ...chal(1), ...cost(false)], hl: { d: [g === 'pre' ? 1 : g === 'second' ? 2 : 3] }, say: chSay, facts: Object.assign({ target: P.target === null ? null : hx(P.target) }, base), meta: { stage: 'challenge' } });
    const firstFew = P.tries.slice(0, 4);
    F.set('tries', Math.min(4, P.tries.length));
    const fewSay = firstFew.map((r) => `“${r.m}” → ${hx(r.v)}`).join(', ');
    F.add({ items: [...head, ...chal(2), ...tries(4, false), ...cost(false)], hl: { d: [g === 'pre' ? 1 : g === 'second' ? 2 : 3] }, say: g === 'coll' ? `The adversary hashes message after message and keeps every digest in a table: ${fewSay}. Each new digest is checked against all the ones before it.` : `The adversary can only guess and check: ${fewSay}. None is ${hx(P.target)}; each try wins with chance 1 in ${U.commas(N)}.`, facts: Object.assign({ tries: firstFew.map((r) => [r.i, hx(r.v)]), target: P.target === null ? null : hx(P.target) }, base), meta: { stage: 'tries' } });
    F.set('tries', w ? w.i : P.tries.length);
    const winSay = !w ? `No win in ${U.commas(P.tries.length)} tries.`
      : g === 'coll' ? `Try ${U.commas(w.i)}, “${w.m}”, gives ${hx(w.v)}, already in the table from try ${U.commas(w.j)}, “${w.other}”: a collision. The full digests differ beyond the first ${bits} bits (${U.short(P.fullA, 4)} and ${U.short(P.fullB, 4)}).`
        : `Try ${U.commas(w.i)}, “${w.m}”, hashes to ${hx(w.v)}: the adversary wins. Its full SHA-256 digest, ${U.short(P.fullA, 4)}, ${g === 'second' ? `differs from the given message's ${U.short(P.fullB, 4)}` : 'is unrelated to the secret'}; only the first ${bits} bits had to match.`;
    F.add({ items: [...head, ...chal(3), ...tries(w ? w.i : 4, true), ...cost(false)], hl: { d: [g === 'pre' ? 1 : g === 'second' ? 2 : 3] }, say: winSay, facts: Object.assign({ win: w ? [w.i, w.j, hx(w.v)] : null, fullA: P.fullA, fullB: P.fullB }, base), meta: { stage: 'win' } });
    const ratio = w ? w.i / P.expected : 0;
    F.add({ items: [...head, ...chal(4), ...tries(w ? w.i : 4, true), ...cost(true)], hl: { d: [4] }, say: g === 'coll' ? `${U.commas(w.i)} tries against about √(πN/2) ≈ ${U.commas(Math.round(P.expected))} expected (${U.fx(ratio, 2)} times the estimate), and ${U.commas(P.stored)} digests stored. A collision costs about the square root of N: 2${U.sup(bits / 2)} rather than 2${U.sup(bits)}.` : `${U.commas(w.i)} tries against ${U.commas(N)} expected on average (${U.fx(ratio, 2)} times the estimate). With one side fixed there is no shortcut: about 2${U.sup(bits)} tries, and a real 256-bit digest puts that at 2²⁵⁶.`, facts: Object.assign({ tries: w.i, ratio, stored: P.stored, half: bits / 2 }, base), meta: { stage: 'cost' } });
    U.fix(F.list);
    return {
      frames: F.list, def: U.def('Three games (H with n-bit digests)', [
        'A challenger holds H; an adversary may hash freely.',
        'preimage: given y, find m with H(m) = y          (about 2ⁿ)',
        'second preimage: given m, find m′ ≠ m, H(m′) = H(m)   (about 2ⁿ)',
        'collision: find any m ≠ m′ with H(m) = H(m′)        (about 2ⁿᐟ²)',
        'collision resistance ⇒ second-preimage resistance',
      ]),
    };
  }
  S.topic({
    id: 'p12-games', family: 'p12-req', order: 10, title: 'Preimage, second preimage, collision: three games',
    blurb: 'Each property is a game an adversary should not be able to win. Played for real on SHA-256 cut to a few bits: the two preimage games take about 2ⁿ tries, a collision only about 2ⁿᐟ².',
    inputs: [
      { id: 'game', kind: 'choice', label: 'Game', def: 'pre', options: [{ value: 'pre', label: 'preimage' }, { value: 'second', label: 'second preimage' }, { value: 'coll', label: 'collision' }] },
      { id: 'bits', kind: 'choice', label: 'Digest cut to', def: '12', options: ['8', '12', '16', '20'].map((v) => ({ value: v, label: v + ' bits' })) },
      { id: 'seed', kind: 'number', label: 'Seed', def: 3, min: 1, max: 999 },
    ],
    check: (inp) => (inp.game !== 'coll' && +inp.bits > 16 ? 'The preimage games at 20 bits take about a million tries: choose 16 bits or fewer, or the collision game' : null),
    presets: [
      { label: 'Preimage, 12 bits', values: { game: 'pre', bits: '12', seed: 3 } },
      { label: 'Second preimage, 12 bits', values: { game: 'second', bits: '12', seed: 5 } },
      { label: 'Collision, 12 bits', values: { game: 'coll', bits: '12', seed: 3 } },
      { label: 'Collision, 20 bits', values: { game: 'coll', bits: '20', seed: 8 } },
      { label: 'Preimage, 16 bits', values: { game: 'pre', bits: '16', seed: 11 } },
    ],
    counters: [{ id: 'tries', label: 'tries' }],
    run: games,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'challenge', pick: 'option', options: ['about 2ⁿ', 'about 2ⁿᐟ²', 'about n'], ask: 'About how many tries will the adversary need?', answer: (fr, i, inp) => (inp.game === 'coll' ? 'about 2ⁿᐟ²' : 'about 2ⁿ'), explain: (fr, i, inp) => (inp.game === 'coll' ? 'Every new digest can match any earlier one, so the chances add up quadratically: about √N tries.' : 'One digest is fixed, so each try matches it with chance 1/N: about N tries.') },
    ],
    quiz: [
      { q: 'Which game is the easiest for the adversary on an ideal n-bit hash?', options: ['preimage', 'second preimage', 'collision', 'all cost the same'], answer: 2, why: 'A collision may be any pair, so the birthday bound applies: about 2^(n/2) tries.' },
      { q: 'A password is stored as its SHA-256 digest. Recovering some password from the digest is breaking…', options: ['collision resistance', 'preimage resistance', 'second-preimage resistance', 'none of them'], answer: 1, why: 'Given only y, find any m with H(m) = y: the preimage game (though a guessable password makes the search much smaller than 2²⁵⁶).' },
      { q: 'A forger has a signed contract and wants another document with the same digest. Which property protects the signer?', options: ['preimage resistance', 'second-preimage resistance', 'collision resistance only', 'none'], answer: 1, why: 'The first message is fixed by someone else: that is the second-preimage game.' },
      { q: 'Why does SHA-256 have 256 bits when 128 bits of preimage security might do?', options: ['for speed', 'collisions cost only 2^(n/2), so 256 bits gives 128-bit collision resistance', 'for compatibility with MD5', 'it is required by the length padding'], answer: 1, why: 'The birthday bound halves the exponent for collisions.' },
      { q: 'If you can find collisions, can you always find second preimages?', options: ['yes', 'no: a collision attack chooses both messages', 'only for Merkle–Damgård hashes', 'only for short messages'], answer: 1, why: 'The implication runs the other way: second-preimage attacks give collisions, not the reverse.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // the birthday paradox
  // ---------------------------------------------------------------------------------------------------------------
  const MONTHS = [['Jan', 31], ['Feb', 28], ['Mar', 31], ['Apr', 30], ['May', 31], ['Jun', 30], ['Jul', 31], ['Aug', 31], ['Sep', 30], ['Oct', 31], ['Nov', 30], ['Dec', 31]];
  const dayName = (d) => { for (const [m, n] of MONTHS) { if (d < n) return m + ' ' + (d + 1); d -= n; } return '?'; };
  function birthday(inp) {
    const Hs = H(), N = +inp.space, q = +inp.q, seed = +inp.seed, rnd = Hs.rng('bday:' + seed);
    const days = N === 365;
    const draws = Array.from({ length: q }, () => rnd.int(N));
    const half = (() => { for (let k = 2; k < 10 * Math.sqrt(N) + 10; k++) if (Hs.birthdayProb(k, N) >= 0.5) return k; return null; })();
    // the grid: months by days for 365, else a square
    const side = days ? 0 : Math.round(Math.sqrt(N));
    const cs = days ? 13 : Math.min(26, Math.floor(440 / side) - 1), gap = days ? 2 : side >= 64 ? 1 : 1.5;
    const gx = days ? 76 : 40, gy = days ? 112 : 96;
    const posOf = (v) => { if (!days) return [v % side, Math.floor(v / side)]; let d = v; for (let m = 0; m < 12; m++) { if (d < MONTHS[m][1]) return [d, m]; d -= MONTHS[m][1]; } return [0, 0]; };
    const label = (v) => (days ? dayName(v) : 'slot ' + v);
    const pl = U.plot({ prefix: 'bp', x: 604, y: 96, w: 280, h: 190, xr: [0, Math.max(q, half ? Math.ceil(half * 1.6) : q)], yr: [0, 1], yticks: [0, 0.5, 1], fy: (v) => U.fx(v, 1), xticks: [], xlabel: 'people (or messages) drawn', ylabel: 'chance of a shared slot', tickSize: 13, grid: true });
    const xMax = pl.o.xr[1], step = xMax <= 40 ? 10 : xMax <= 100 ? 20 : xMax <= 200 ? 50 : 100;
    for (let v = 0; v <= xMax; v += step) pl.items.push(t('bp:tx' + v, pl.X(v), 96 + 190 + 17, String(v), 'ptick', 'middle', 13));
    const curveX = [], curveY = [];
    for (let k = 0; k <= 120; k++) { const x = (xMax * k) / 120; curveX.push(x); curveY.push(Hs.birthdayProb(x, N)); }
    const F = new S.Frames(['drawn', 'pairs']);
    const seen = new Map();
    let pairs = 0, first = null;
    // the guest list under the calendar: the last 40 people and their days, shared days lit
    const guests = (k) => {
      const items = [t('bd:gt', gx - 40, 330, 'who came in' + (k > 40 ? ' (the last 40)' : ''), 'ptitle')];
      const from = Math.max(0, k - 40), count = new Map();
      for (let i = 0; i < k; i++) count.set(draws[i], (count.get(draws[i]) || 0) + 1);
      for (let i = from; i < k; i++) {
        const j = i - from, col = Math.floor(j / 10), row = j % 10;
        const shared = count.get(draws[i]) > 1;
        items.push({ key: 'bd:g' + i, kind: 'cell', x: gx - 40 + col * 128, y: 344 + row * 22, w: 122, h: 19, rx: 3, text: (i + 1) + '  ' + dayName(draws[i]), size: 13, cls: 'mono ' + (shared ? 'hot' : i === k - 1 ? 'act' : 'nobox') });
      }
      return items;
    };
    const scene = (k, newest) => {
      const rows = [];
      const nR = days ? 12 : side, nC = days ? 31 : side;
      for (let r = 0; r < nR; r++) rows.push(Array.from({ length: nC }, (_, c) => (days && c >= MONTHS[r][1] ? ' ' : '0')));
      for (const [v, n] of seen) { const [c, r] = posOf(v); rows[r][c] = n > 1 ? '2' : v === newest ? '3' : '1'; }
      const items = [{ key: 'bd:bm', kind: 'bitmap', x: gx, y: gy, cw: cs + gap, ch: cs + gap, gap, rows: rows.map((r) => r.join('')) }];
      if (days) {
        MONTHS.forEach(([m], r) => items.push(t('bd:m' + r, gx - 8, gy + r * (cs + gap) + cs - 2, m, 'ptick', 'end', 13)));
        for (const d of [1, 10, 20, 31]) items.push(t('bd:d' + d, gx + (d - 1) * (cs + gap) + cs / 2, gy - 8, String(d), 'ptick', 'middle', 13));
      }
      items.push(...pl.items, U.line(pl, 'bp:curve', curveX, curveY, 'soft'));
      if (half) items.push({ key: 'bp:half', kind: 'path', d: `M${pl.X(half)},${pl.Y(0)} V${pl.Y(0.5)} H${pl.X(0)}`, cls: 'p12-line dash', audit: 'ignore' }, t('bp:ht', pl.X(half) + 6, pl.Y(0) - 8, String(half), 'act', 'start', 13));
      if (k > 0) items.push({ key: 'bp:now', kind: 'dot', x: pl.X(k), y: pl.Y(Hs.birthdayProb(k, N)), r: 6, cls: 'hot', audit: 'point' });
      const expPairs = (k * (k - 1)) / 2 / N;
      items.push(...U.readout('bd:r', 604, 360, 280, 'after ' + k + ' drawn', [
        ['newest', k ? label(newest) : '—', 'act'],
        ['colliding pairs', String(pairs), pairs ? 'hot' : ''],
        ['expected pairs  k(k−1)/2N', U.fx(expPairs, 2)],
        ['chance of at least one', U.fx(Hs.birthdayProb(k, N), 3)],
      ], { dy: 32 }));
      items.push(...U.legend('bd:lg', 604, 584, [['p12-b0', 'empty'], ['p12-b1', 'taken'], ['p12-b3', 'newest'], ['p12-b2', 'shared']], 13));
      if (days) items.push(...guests(k));
      return items;
    };
    const head = U.head('bd:h', days ? 'Birthdays in a room' : 'Digests in a space of ' + U.commas(N), days ? 'one cell per day of the year: N = 365' : 'one cell per possible digest: N = ' + U.commas(N));
    F.add({ items: [...head, ...scene(0, -1)], hl: { d: [0] }, say: `${days ? 'People walk into a room one at a time, each with a birthday on one of 365 days' : `Messages are hashed one at a time onto ${U.commas(N)} possible digests`}. How many before two share ${days ? 'a day' : 'a digest'}? The chance passes one half at ${half}${days ? ' people' : ''}, far fewer than ${U.commas(N)}.`, facts: { N, half }, meta: { stage: 'start', k: 0 } });
    const show = (k) => k <= 12 || k === q || (first !== null && k <= first + 1) || k % (q > 60 ? 10 : 5) === 0;
    for (let k = 1; k <= q; k++) {
      const v = draws[k - 1], had = seen.get(v) || 0;
      pairs += had; seen.set(v, had + 1);
      F.count('drawn').set('pairs', pairs);
      const isFirst = had > 0 && first === null;
      if (isFirst) first = k;
      if (!show(k) && !had) continue;
      const p = Hs.birthdayProb(k, N);
      const say = had ? `${U.cap(days ? 'person' : 'message')} ${k} lands on ${label(v)}, which ${had === 1 ? 'is already taken' : 'already has ' + had}: ${isFirst ? 'the first shared slot' : 'another collision'}, ${pairs} colliding ${pairs === 1 ? 'pair' : 'pairs'} so far. With ${k} drawn there are ${U.commas((k * (k - 1)) / 2)} pairs, each sharing with chance 1/${N}.`
        : `${U.cap(days ? 'person' : 'message')} ${k}: ${label(v)}. ${k} drawn, chance of a shared slot by now ${U.fx(p, 3)}.`;
      F.add({ items: [...head, ...scene(k, v)], hl: { d: had ? [1, 2] : [1] }, say, facts: { k, v, day: days ? label(v) : null, pairs, p, allPairs: (k * (k - 1)) / 2, N }, meta: { stage: had ? 'hit' : 'draw', k, p } });
    }
    const expPairs = (q * (q - 1)) / 2 / N;
    F.add({ items: [...head, ...scene(q, draws[q - 1])], hl: { d: [2, 3] }, say: `After ${q}: ${pairs} colliding ${pairs === 1 ? 'pair' : 'pairs'} against ${U.fx(expPairs, 2)} expected, since ${q} things make ${U.commas((q * (q - 1)) / 2)} pairs. ${first ? `The first shared slot came at ${first}.` : 'No slot was shared this time.'} For a hash with n-bit digests the same sum says a collision is likely after about 2ⁿᐟ² messages.`, facts: { q, pairs, expPairs, first, allPairs: (q * (q - 1)) / 2 }, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('The birthday bound', ['N slots, k things drawn at random', 'pairs: k(k − 1)/2, each shares a slot with chance 1/N', 'expected colliding pairs: k(k − 1)/2N', 'P(at least one) ≈ 1 − e^(−k(k−1)/2N)', 'P = ½ near k ≈ 1.18·√N;  N = 2ⁿ gives k ≈ 2ⁿᐟ²']) };
  }
  S.topic({
    id: 'p12-birthday', family: 'p12-req', order: 20, title: 'The birthday paradox, one draw at a time',
    blurb: 'In a room of 23 people two probably share a birthday. Draw birthdays, or digests, one by one: every new one can match any earlier one, so collisions arrive after about √N draws.',
    inputs: [
      { id: 'space', kind: 'choice', label: 'Slots', def: '365', options: [{ value: '365', label: '365 days' }, { value: '256', label: '256 digests (8 bits)' }, { value: '1024', label: '1024 digests (10 bits)' }, { value: '4096', label: '4096 digests (12 bits)' }] },
      { id: 'q', kind: 'number', label: 'How many to draw', def: 40, min: 2, max: 200 },
      { id: 'seed', kind: 'number', label: 'Seed', def: 1, min: 1, max: 999 },
    ],
    presets: [
      { label: 'A room of 40', values: { space: '365', q: 40, seed: 1 } },
      { label: 'A room of 23', values: { space: '365', q: 23, seed: 4 } },
      { label: '8-bit digests, 40 messages', values: { space: '256', q: 40, seed: 2 } },
      { label: '12-bit digests, 150 messages', values: { space: '4096', q: 150, seed: 7 } },
    ],
    counters: [{ id: 'drawn', label: 'drawn' }, { id: 'pairs', label: 'colliding pairs' }],
    run: birthday,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'start', pick: 'option', options: (fr, i, inp) => (+inp.space === 365 ? ['about 23', 'about 183', 'about 365'] : ['about √N', 'about N/2', 'about N']), ask: 'How many draws until a shared slot is more likely than not?', answer: (fr, i, inp) => (+inp.space === 365 ? 'about 23' : 'about √N'), explain: 'Each new draw can match any of the earlier ones, so the number of pairs grows like k²/2.' },
    ],
    quiz: [
      { q: 'Why is a shared birthday likely among only 23 people?', options: ['birthdays are not uniform', 'there are 253 pairs, and any pair may match', 'leap years', 'it is not likely'], answer: 1, why: '23 × 22 / 2 = 253 pairs, each matching with chance 1/365.' },
      { q: 'For a 128-bit hash, about how many messages give a collision with good chance?', options: ['2^128', '2^64', '2^32', '128'], answer: 1, why: 'The birthday bound is about √N = 2^64.' },
      { q: 'The expected number of colliding pairs among k draws from N is…', options: ['k/N', 'k²/N', 'k(k − 1)/2N', 'N/k'], answer: 2, why: 'There are k(k − 1)/2 pairs, each colliding with chance 1/N.' },
      { q: 'Doubling the number of draws multiplies the expected number of collisions by about…', options: ['2', '4', '√2', '1'], answer: 1, why: 'It grows with k², so twice the draws give about four times the pairs.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
