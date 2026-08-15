// Part 2, modular arithmetic: the clock you turn, congruence classes from a number line folded into columns, the
// ring Z_n with its addition and multiplication tables, and inverses found by hopping round the clock.
(function (S) {
  'use strict';
  const H = S.P02, NT = () => S.NT, KN = () => S.Kit.nt;
  const n$ = H.n;
  const mod = (a, n) => ((a % n) + n) % n;
  // the number line of the classes runs from −n to hiOf(n): four rows of n for a small n, three for a larger one
  const hiOf = (n) => (n <= 5 ? 3 * n - 1 : 2 * n - 1);

  // ---------------------------------------------------------------------------------------------------------------
  // The modular clock
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'mod-clock', family: 'p02-modular', order: 10, title: 'The modular clock',
    blurb: 'Arithmetic modulo n is arithmetic on a clock with n positions: adding turns the hand forward, subtracting turns it back, and whole laps change nothing. Every integer lands on exactly one of the positions 0 to n − 1, its remainder.',
    inputs: [
      { id: 'n', kind: 'number', label: 'Modulus n', def: 12, min: 2, max: 24 },
      { id: 'a', kind: 'number', label: 'Start a', def: 9, min: -999, max: 999 },
      { id: 't', kind: 'number', label: 'Turn by t', def: 17, min: -999, max: 999 },
    ],
    presets: [
      { label: '9 + 17 on a 12-hour clock', values: { n: 12, a: 9, t: 17 } },
      { label: 'A small clock: 3 + 4 mod 5', values: { n: 5, a: 3, t: 4 } },
      { label: 'Backwards: 2 − 9 mod 7', values: { n: 7, a: 2, t: -9 } },
      { label: 'A negative start: −23 mod 10', values: { n: 10, a: -23, t: 6 } },
      { label: 'Many laps: 100 steps mod 24', values: { n: 24, a: 0, t: 100 } },
      { label: 'Exactly two laps', values: { n: 8, a: 5, t: 16 } },
    ],
    counters: [{ id: 'steps', label: 'steps turned' }, { id: 'laps', label: 'full laps' }],
    run(inp) {
      const n = inp.n, a = inp.a, t = inp.t;
      const F = new S.Frames(['steps', 'laps']);
      const cx = 250, cy = 250, R = 200;
      const r0 = mod(a, n), end = a + t, rEnd = mod(end, n);
      const dir = t >= 0 ? 1 : -1, abs = Math.abs(t), laps = Math.floor(abs / n), rest = abs % n;
      const qa = Math.floor(a / n), qe = Math.floor(end / n);
      const lines = [];
      const panel = (extra, hl) => H.eqs('ce', 520, 70, lines.concat(extra || []).map((l, i) => (hl === i ? [l[0], (l[1] || '') + ' hot'] : l)), 17, 34);
      const clock = (hand, lit, arc) => {
        const c = KN().clock({ prefix: 'ck', cx, cy, R, n, hand, cls: (k) => lit[k] || '' });
        return c.items.concat(arc || []);
      };
      const head = [H.title('h1', 0, -14, 'A clock with ' + n + ' positions'), H.title('h2', 520, 30, 'The arithmetic')];
      const ang = (k) => KN().angle(n, k);
      // the arc from the start, turned through s steps (s ≤ n − 1), inside the ring
      const arcOf = (s, cls) => KN().arc({ key: 'arc', cx, cy, r: R - 60, a0: ang(r0), a1: ang(r0) + dir * (360 * s) / n, cls });

      lines.push(['n = ' + n, 'strong']);
      if (a === r0) {
        lines.push(['start a = ' + n$(a)]);
        F.add({ items: head.concat(clock(r0, { [r0]: 'act' }), panel()), say: 'A clock with positions 0 to ' + (n - 1) + '. Arithmetic modulo ' + n + ' happens here: the hand starts at a = ' + n$(a) + '.', meta: { phase: 'start' } });
      } else {
        lines.push(['a = ' + n$(a) + ' = ' + n$(qa) + '·' + n + ' + ' + r0]);
        lines.push([n$(a) + ' mod ' + n + ' = ' + r0, 'act']);
        F.add({ items: head.concat(clock(null, {}), panel()), say: 'A clock with positions 0 to ' + (n - 1) + '. The start a = ' + n$(a) + ' is not one of them, so first find where it sits.', meta: { phase: 'start' } });
        F.add({ items: head.concat(clock(r0, { [r0]: 'act' }), panel([], lines.length - 1)), say: n$(a) + ' = ' + n$(qa) + '·' + n + ' + ' + r0 + ': take away ' + (qa < 0 ? 'a negative number of' : n$(qa)) + ' whole laps of ' + n + ' and ' + r0 + ' is left, so ' + n$(a) + ' mod ' + n + ' = ' + r0 + '. The remainder is never negative: ' + (a < 0 ? 'a negative a counts back from 0, landing on ' + r0 + '.' : 'it is always one of 0 to ' + (n - 1) + '.'), meta: { phase: 'reduce', r: r0 } });
      }
      // the turn: whole laps first, then the steps that are left
      lines.push(['turn t = ' + (t < 0 ? '−' : '+') + abs + (laps ? ' = ' + (t < 0 ? '−(' : '') + laps + '·' + n + ' + ' + rest + (t < 0 ? ')' : '') : ''), 'act']);
      if (laps) {
        F.set('laps', laps).set('steps', laps * n);
        F.add({ items: head.concat(clock(r0, { [r0]: 'act' }, KN().arc({ key: 'lap', cx, cy, r: R - 52, a0: ang(r0), a1: ang(r0) + dir * 359, cls: 'faint' })), panel([], lines.length - 1)), say: 'Turning by ' + n$(t) + ' means ' + laps + ' whole lap' + (laps > 1 ? 's' : '') + ' of ' + n + ' steps ' + (t < 0 ? 'backwards ' : '') + 'and ' + rest + ' more. A whole lap brings the hand back where it was, so ' + (laps > 1 ? 'the laps change' : 'it changes') + ' nothing: only the ' + rest + ' remaining step' + (rest === 1 ? '' : 's') + ' matter.', meta: { phase: 'laps', laps } });
      }
      // the remaining steps, one frame each (or in a few strides when there are many)
      const stride = rest > 12 ? Math.ceil(rest / 8) : 1;
      for (let s = stride; s <= rest || (s - stride < rest && s > rest); s += stride) {
        const done = Math.min(s, rest), pos = mod(r0 + dir * done, n);
        F.set('steps', laps * n + done);
        const wrapped = dir > 0 ? r0 + done >= n : r0 - done < 0;
        F.add({ items: head.concat(clock(pos, { [r0]: 'soft', [pos]: 'act' }, arcOf(done, '')), panel()), say: (done === stride ? 'Now the remaining ' + rest + ' step' + (rest === 1 ? '' : 's') + (t < 0 ? ' backwards' : '') + '. ' : '') + 'After ' + done + ' step' + (done === 1 ? '' : 's') + ' the hand is at ' + pos + (wrapped && !(dir > 0 ? r0 + done - stride >= n : r0 - done + stride < 0) ? ': it passed ' + (dir > 0 ? (n - 1) + ' and wrapped round to 0' : '0 and wrapped round to ' + (n - 1)) : '') + '.', meta: { phase: 'step', done, pos } });
        if (s >= rest) break;
      }
      // the result
      lines.push([n$(a) + ' + ' + (t < 0 ? '(' + n$(t) + ')' : t) + ' = ' + n$(end) + ' = ' + n$(qe) + '·' + n + ' + ' + rEnd]);
      lines.push([n$(end) + ' ≡ ' + rEnd + ' (mod ' + n + ')', 'good']);
      F.add({ items: head.concat(clock(rEnd, { [r0]: 'act', [rEnd]: 'good' }, rest ? arcOf(rest, 'good') : []), panel([], lines.length - 1)), say: 'The hand stops at ' + rEnd + '. In plain numbers ' + n$(a) + ' + ' + (t < 0 ? '(' + n$(t) + ')' : t) + ' = ' + n$(end) + ', and ' + n$(end) + ' = ' + n$(qe) + '·' + n + ' + ' + rEnd + ', so ' + n$(end) + ' ≡ ' + rEnd + ' (mod ' + n + '): the clock keeps only the remainder.', meta: { phase: 'done', r: rEnd } });
      for (const f of F.list) f.narrowView = { x: 10, y: -36, w: 480, h: 530 };
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'Modular addition', text: ['a mod n: the remainder r with a = q·n + r, 0 ≤ r < n', 'a ≡ b (mod n) when n divides a − b', '(a + t) mod n: start at a mod n, turn t steps', 'whole laps of n steps change nothing'].join('\n') }] } };
    },
    predict: [
      { at: (f, i, fr) => f.meta && (f.meta.phase === 'start' || f.meta.phase === 'reduce' || f.meta.phase === 'laps') && fr[i + 1] && fr[i + 1].meta.phase !== 'reduce' && fr[i + 1].meta.phase !== 'laps', once: true, pick: 'item', ask: 'Where will the hand stop? Click its position on the clock.', answer: (fr) => 'ck:' + fr[fr.length - 1].meta.r, explain: (fr) => fr[fr.length - 1].say },
      { at: (f, i, fr) => f.meta && f.meta.phase === 'start' && fr[i + 1] && fr[i + 1].meta.phase === 'reduce', pick: 'item', ask: 'The start is not on the clock. Which position does it sit at?', answer: (fr, i) => 'ck:' + fr[i + 1].meta.r, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What is 23 mod 7?', options: ['1', '2', '3', '16'], answer: 1, why: '23 = 3·7 + 2.' },
      { q: 'What is −5 mod 12?', options: ['−5', '5', '7', '17'], answer: 2, why: '−5 = −1·12 + 7: five steps back from 0 on a 12-hour clock land on 7.' },
      { q: 'On a clock with 9 positions, turning by 40 steps is the same as turning by…', options: ['4', '5', '31', '0'], answer: 0, why: '40 = 4·9 + 4: four whole laps change nothing, and 4 steps remain.' },
      { q: 'a ≡ b (mod n) means…', options: ['a = b', 'n divides a − b', 'a divides b', 'a·b = n'], answer: 1, why: 'Two integers are congruent when they differ by a multiple of n: they land on the same position.' },
      { q: 'Which is true for every integer a and n ≥ 2?', options: ['0 ≤ a mod n < n', 'a mod n < a', 'a mod n is odd', 'a mod n ≠ 0'], answer: 0, why: 'The remainder is one of the n positions 0 to n − 1.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Congruence classes
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'mod-classes', family: 'p02-modular', order: 20, title: 'Congruence classes',
    blurb: 'Colour every integer by its remainder modulo n and fold the number line into rows of n: each column is one congruence class, the integers that differ by multiples of n. Adding or multiplying any members of two classes always lands in the same class.',
    inputs: [
      { id: 'n', kind: 'number', label: 'Modulus n', def: 5, min: 2, max: 8 },
      { id: 'a', kind: 'number', label: 'An integer a', def: 13, min: -8, max: 19, check: (v, inp) => (v < -inp.n || v > hiOf(inp.n) ? 'a: between ' + -inp.n + ' and ' + hiOf(inp.n) + ', so it is on the line' : null) },
      { id: 'b', kind: 'number', label: 'Another b', def: 7, min: -8, max: 19, check: (v, inp) => (v < -inp.n || v > hiOf(inp.n) ? 'b: between ' + -inp.n + ' and ' + hiOf(inp.n) + ', so it is on the line' : null) },
    ],
    presets: [
      { label: 'Mod 5: 13 and 7', values: { n: 5, a: 13, b: 7 } },
      { label: 'Even and odd: mod 2', values: { n: 2, a: 5, b: -1 } },
      { label: 'Mod 3 with negatives', values: { n: 3, a: -2, b: 7 } },
      { label: 'Mod 8: 13 and −3', values: { n: 8, a: 13, b: -3 } },
      { label: 'Mod 4: the same class twice', values: { n: 4, a: 9, b: 1 } },
    ],
    counters: [{ id: 'classes', label: 'classes drawn' }],
    run(inp) {
      const n = inp.n, a = inp.a, b = inp.b, lo = -n, hi = hiOf(n);
      const F = new S.Frames(['classes']);
      const step = 31, W = 27, CH = 30;
      const ra = mod(a, n), rb = mod(b, n);
      // the line, then the grid: the same cells, moved
      const lineX = (k) => (k - lo) * step, lineY = 34;
      const gw = 52, gh = 36, gx0 = 30, gy0 = 150;
      const gridPos = (k) => ({ x: gx0 + mod(k, n) * (gw + 6), y: gy0 + (Math.floor(k / n) + 1) * (gh + 6) });
      const cell = (k, where, cls) => {
        const p = where === 'line' ? { x: lineX(k), y: lineY } : gridPos(k);
        return { key: (where === 'line' ? 'L' : 'c') + k, enter: where === 'line' ? undefined : 'from', src: 'L' + k, kind: 'cell', x: p.x, y: p.y, w: where === 'line' ? W : gw, h: where === 'line' ? CH : gh, rx: 5, text: String(k).replace('-', '−'), size: where === 'line' ? 13 : 15, cls: 'mono ntc ' + (cls || '') };
      };
      const ks = []; for (let k = lo; k <= hi; k++) ks.push(k);
      const colour = (k) => H.kc(mod(k, n));
      const lineItems = (coloured, lit) => [H.title('lt', 0, 10, 'The integers from ' + n$(lo) + ' to ' + hi), { key: 'axis', kind: 'line', x1: -10, y1: lineY + CH / 2, x2: lineX(hi) + W + 10, y2: lineY + CH / 2, cls: 'nt-axis', audit: 'ignore', layer: 'back' }].concat(ks.map((k) => cell(k, 'line', coloured ? (lit ? lit(k) : '') || colour(k) : '')));
      const heads = () => { const it = [H.title('gt', gx0, gy0 - 34, 'Folded into rows of ' + n + ': one column for each class')]; for (let r = 0; r < n; r++) it.push({ key: 'gh' + r, kind: 'text', x: gx0 + r * (gw + 6) + gw / 2, y: gy0 - 10, text: '[' + r + ']', anchor: 'middle', size: 14, cls: 'ntlab' }); return it; };
      const gridItems = (lit) => heads().concat(ks.map((k) => cell(k, 'grid', (lit ? lit(k) : '') || colour(k))));
      const both = (lit, extra) => base(lit).concat(gridItems(lit), extra || []);
      const px = gx0 + n * (gw + 6) + 40, py = gy0 + 6;
      const memb = (r) => { const out = []; for (let k = r - n; k <= hi; k += n) if (k >= lo) out.push(String(k).replace('-', '−')); return out; };
      F.add({ items: lineItems(false), say: 'The integers from ' + n$(lo) + ' to ' + hi + ' on a line. Modulo ' + n + ' only the remainder matters, so colour each one by its remainder.', meta: { phase: 'line' } });
      F.set('classes', n);
      F.add({ items: lineItems(true), say: 'Coloured by remainder: the colours repeat every ' + n + ' steps, because adding ' + n + ' does not change the remainder.', meta: { phase: 'colour' } });
      F.add({ items: lineItems(true).concat(gridItems()), say: 'Cut the line every ' + n + ' and stack the pieces: the row starting at 0 holds 0 to ' + (n - 1) + ', the next ' + n + ' to ' + (2 * n - 1) + ', and the row above holds ' + n$(lo) + ' to −1. Each column holds one colour: a congruence class.', meta: { phase: 'fold' } });
      const base = (lit) => lineItems(true, lit);
      const eqA = [['[' + ra + '] = {' + memb(ra).join(', ') + ', …}', 'hot'], [n$(a) + ' = ' + n$(Math.floor(a / n)) + '·' + n + ' + ' + ra, 'hot']];
      F.add({ items: both((k) => (k === a ? 'hot' : mod(k, n) === ra ? '' : 'struck'), H.eqs('pe', px, py, eqA, 16)), say: 'a = ' + n$(a) + ' is in column ' + ra + ', since ' + n$(a) + ' = ' + n$(Math.floor(a / n)) + '·' + n + ' + ' + ra + '. Its class [' + ra + '] is every integer ' + ra + ' + k·' + n + ': ' + memb(ra).join(', ') + ' and so on in both directions.', meta: { phase: 'classA', r: ra } });
      const same = ra === rb, diff = a - b;
      const eqB = eqA.concat([['b = ' + n$(b) + ' is in [' + rb + ']', 'key'], [n$(a) + ' − ' + (b < 0 ? '(' + n$(b) + ')' : b) + ' = ' + n$(diff) + (same ? ' = ' + n$(diff / n) + '·' + n : ''), same ? 'good' : 'bad'], [same ? n$(a) + ' ≡ ' + n$(b) + ' (mod ' + n + ')' : n$(a) + ' ≢ ' + n$(b) + ' (mod ' + n + ')', same ? 'good' : 'bad']]);
      F.add({ items: both((k) => (k === a ? 'hot' : k === b ? 'keyhot' : mod(k, n) === ra || mod(k, n) === rb ? '' : 'struck'), H.eqs('pe', px, py, eqB, 16)), say: 'b = ' + n$(b) + ' is in column ' + rb + '. ' + (same ? 'Same column: a − b = ' + n$(diff) + ' is a multiple of ' + n + ', so a ≡ b (mod ' + n + ').' : 'A different column: a − b = ' + n$(diff) + ' is not a multiple of ' + n + ', so a and b are not congruent.'), meta: { phase: 'classB', r: rb, same } });
      // arithmetic on classes: any representatives give the same class
      const other = (r, not) => ks.filter((k) => mod(k, n) === r && k !== not).pop();
      const a2 = other(ra, a), b2 = other(rb, b);
      const s1 = a + b, s2 = a2 + b2, p1 = a * b, p2 = a2 * b2, rs = mod(s1, n), rp = mod(p1, n);
      const eqC = [['[' + ra + '] + [' + rb + '] = [' + rs + ']', 'strong'], [n$(a) + ' + ' + (b < 0 ? '(' + n$(b) + ')' : b) + ' = ' + n$(s1) + ' ≡ ' + rs + ' (mod ' + n + ')', 'hot'], [n$(a2) + ' + ' + (b2 < 0 ? '(' + n$(b2) + ')' : b2) + ' = ' + n$(s2) + ' ≡ ' + rs + ' (mod ' + n + ')', 'key'], ['[' + ra + ']·[' + rb + '] = [' + rp + ']', 'strong'], [n$(a) + '·' + (b < 0 ? '(' + n$(b) + ')' : b) + ' = ' + n$(p1) + ' ≡ ' + rp + ' (mod ' + n + ')', 'hot'], [n$(a2) + '·' + (b2 < 0 ? '(' + n$(b2) + ')' : b2) + ' = ' + n$(p2) + ' ≡ ' + rp + ' (mod ' + n + ')', 'key']];
      F.add({ items: both((k) => (k === a || k === b ? 'hot' : k === a2 || k === b2 ? 'keyhot' : mod(k, n) === ra || mod(k, n) === rb ? '' : 'struck'), H.eqs('pe', px, py, eqC, 16)), say: 'Classes can be added and multiplied: pick any member of each. ' + n$(a) + ' + ' + (b < 0 ? '(' + n$(b) + ')' : b) + ' = ' + n$(s1) + ' and ' + n$(a2) + ' + ' + (b2 < 0 ? '(' + n$(b2) + ')' : b2) + ' = ' + n$(s2) + ' both land in [' + rs + ']; ' + n$(a) + '·' + (b < 0 ? '(' + n$(b) + ')' : b) + ' = ' + n$(p1) + ' and ' + n$(a2) + '·' + (b2 < 0 ? '(' + n$(b2) + ')' : b2) + ' = ' + n$(p2) + ' both land in [' + rp + ']. That is why Z_' + n + ' works with just the ' + n + ' remainders.', meta: { phase: 'arith', rs, rp } });
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'Classes', text: ['a ≡ b (mod n) ⇔ n | (a − b)', '[r] = {r + k·n : k an integer}', 'there are exactly n classes: [0], [1], …, [n − 1]', '[a] + [b] = [a + b],  [a]·[b] = [a·b]'].join('\n') }] } };
    },
    predict: [
      { at: (f, i, fr) => f.meta && f.meta.phase === 'fold', pick: 'option', ask: (fr, i, inp) => 'Which class is a = ' + n$(inp.a) + ' in?', options: (fr, i, inp) => [...Array(inp.n).keys()].map((r) => '[' + r + ']'), answer: (fr, i, inp) => '[' + mod(inp.a, inp.n) + ']', explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta && f.meta.phase === 'classB', pick: 'option', ask: (fr, i, inp) => 'Which class will a + b = ' + n$(inp.a + inp.b) + ' be in?', options: (fr, i, inp) => [...Array(inp.n).keys()].map((r) => '[' + r + ']'), answer: (fr, i, inp) => '[' + mod(inp.a + inp.b, inp.n) + ']', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'How many congruence classes are there modulo 9?', options: ['8', '9', '10', 'infinitely many'], answer: 1, why: 'One for each remainder 0 to 8.' },
      { q: 'Which number is in the same class as 17 modulo 5?', options: ['3', '−3', '12', '−2'], answer: 1, why: '17 − (−3) = 20 = 4·5. (12 is in [2], like 17; −3 is in [2] too: −3 = −1·5 + 2.)' },
      { q: 'Is −1 ≡ 6 (mod 7)?', options: ['yes', 'no'], answer: 0, why: '6 − (−1) = 7, a multiple of 7.' },
      { q: 'If a ≡ 2 and b ≡ 4 (mod 5), then a·b ≡ …', options: ['8', '3', '6', '1'], answer: 1, why: '2·4 = 8 ≡ 3 (mod 5), whichever members of the classes you multiply.' },
      { q: 'Every even number is in the class…', options: ['[0] mod 2', '[1] mod 2', '[2] mod 4', '[0] mod 4'], answer: 0, why: 'Even numbers leave remainder 0 on division by 2; mod 4 they split between [0] and [2].' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The ring Z_n: its two tables, units and zero divisors
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'zn-ring', family: 'p02-modular', order: 30, title: 'The ring Z_n: tables, units and zero divisors',
    blurb: 'Z_n is the set 0 to n − 1 with addition and multiplication modulo n. In the addition table every row holds each value once. In the multiplication table only some rows do: those of the units, the elements with an inverse. Other rows repeat values and hit 0: their elements are zero divisors.',
    inputs: [
      { id: 'n', kind: 'number', label: 'Modulus n', def: 10, min: 2, max: 13 },
      { id: 'a', kind: 'number', label: 'Look at row a', def: 3, min: 0, max: 12, check: (v, inp) => (v >= inp.n ? 'a: one of 0 to ' + (inp.n - 1) : null) },
    ],
    presets: [
      { label: 'Z_10, row 3', values: { n: 10, a: 3 } },
      { label: 'Z_10, row 4 (a zero divisor)', values: { n: 10, a: 4 } },
      { label: 'Z_7: a field', values: { n: 7, a: 3 } },
      { label: 'Z_12: many zero divisors', values: { n: 12, a: 5 } },
      { label: 'Z_9, row 6', values: { n: 9, a: 6 } },
      { label: 'Z_2, the smallest', values: { n: 2, a: 1 } },
    ],
    counters: [{ id: 'units', label: 'units' }, { id: 'zd', label: 'zero divisors' }],
    run(inp) {
      const n = inp.n, a = inp.a, R = NT().ring(n), TB = S.Kit.table;
      const F = new S.Frames(['units', 'zd']);
      const add = R.table('+').map((r) => r.map(Number)), mul = R.table('·').map((r) => r.map(Number));
      const units = R.units().map(Number), zds = R.zeroDivisors().map(Number);
      const isUnit = (x) => units.includes(x);
      const cw = n > 10 ? 32 : 38, ch = n > 10 ? 29 : 34, size = n > 10 ? 13 : 15;
      const heads = [...Array(n).keys()].map(String);
      const tAdd = (cls) => TB.draw({ prefix: 'ta', x: 0, y: 30, rows: add, colHead: heads, rowHead: heads, corner: '+', cw, ch, size, mono: true, cls: (r, c, v) => 'ntc ' + (cls ? cls(r, c, v) || '' : '') });
      const W = TB.draw({ prefix: 'ta', x: 0, y: 30, rows: add, colHead: heads, rowHead: heads, corner: '+', cw, ch, size }).box.w;
      const mx = W + 60;
      const tMul = (cls) => TB.draw({ prefix: 'tm', x: mx, y: 30, rows: mul, colHead: heads, rowHead: heads, corner: '·', cw, ch, size, mono: true, cls: (r, c, v) => 'ntc ' + (cls ? cls(r, c, v) || '' : '') });
      const tBlank = () => TB.draw({ prefix: 'tm', x: mx, y: 30, rows: mul.map((r) => r.map(() => '')), colHead: heads, rowHead: heads, corner: '·', cw, ch, size, mono: true, cls: () => 'ntc empty' });
      const tAddTitle = H.title('tat', 0, 16, 'Addition mod ' + n), tMulTitle = H.title('tmt', mx, 16, 'Multiplication mod ' + n);
      const zeroDim = (v) => (v === 0 ? 'ntzero' : '');
      F.add({ items: [tAddTitle, tMulTitle].concat(tAdd(() => '').items, tBlank().items), say: 'Z_' + n + ' is the set 0 to ' + (n - 1) + '. Its addition table: row r, column c holds (r + c) mod ' + n + '. Each row is the row above moved one place left, so every row holds each element exactly once.', meta: { phase: 'add' } });
      const negA = (n - a) % n;
      F.add({ items: [tAddTitle, tMulTitle].concat(tAdd((r, c, v) => (v === 0 ? 'ntone' : r === a ? 'hot' : '')).items, tBlank().items), say: 'Every row has exactly one 0: the negative of the row\'s element. In row ' + a + ' the 0 is in column ' + negA + ', since ' + a + ' + ' + negA + ' = ' + (a + negA) + ' ≡ 0 (mod ' + n + '). Subtraction is adding the negative.', meta: { phase: 'neg' } });
      // from here the whole multiplication table is on show, so the counters give its units and zero divisors
      F.set('units', units.length).set('zd', zds.length);
      F.add({ items: [tAddTitle, tMulTitle].concat(tAdd(zeroDim).items, tMul(zeroDim).items), say: 'The multiplication table: row r, column c holds (r·c) mod ' + n + '. Row 0 and column 0 are all 0. The other rows are not all alike.', meta: { phase: 'mul' } });
      // the row asked for, then one of the other kind
      const rowSay = (x) => {
        const row = mul[x], one = row.indexOf(1);
        if (x === 0) return 'Row 0 is all 0: 0 times anything is 0, so 0 never has an inverse.';
        if (isUnit(x)) return 'Row ' + x + ' holds every element exactly once, so it reaches 1, in column ' + one + ': ' + x + '·' + one + ' = ' + x * one + ' ≡ 1 (mod ' + n + '). ' + x + ' is a unit, with inverse ' + one + '.';
        const zc = row.findIndex((v, c) => c > 0 && v === 0), seen = [...new Set(row)].sort((p, q) => p - q), g = Number(NT().gcd(x, n));
        return 'Row ' + x + ' repeats itself: it holds only ' + H.list(seen) + ', the multiples of gcd(' + x + ', ' + n + ') = ' + g + ', and never 1. It hits 0 at column ' + zc + ': ' + x + '·' + zc + ' = ' + x * zc + ' ≡ 0 (mod ' + n + ') although neither factor is 0. ' + x + ' is a zero divisor and has no inverse.';
      };
      const rowCls = (x) => (r, c, v) => (r !== x ? zeroDim(v) : isUnit(x) && v === 1 ? 'ntone' : !isUnit(x) && v === 0 && c > 0 ? 'ntzd' : 'hot');
      F.add({ items: [tAddTitle, tMulTitle].concat(tAdd(zeroDim).items, tMul(rowCls(a)).items), say: rowSay(a), meta: { phase: 'row', row: a, unit: isUnit(a) } });
      const other = isUnit(a) || a === 0 ? zds[0] : units.find((u) => u > 1) || 1;
      if (other !== undefined && other !== a) F.add({ items: [tAddTitle, tMulTitle].concat(tAdd(zeroDim).items, tMul(rowCls(other)).items), say: (zds.length || a === 0 ? '' : '') + rowSay(other), meta: { phase: 'row', row: other, unit: isUnit(other) } });
      else if (!zds.length) F.add({ items: [tAddTitle, tMulTitle].concat(tAdd(zeroDim).items, tMul(rowCls(a)).items), say: n + ' is prime, so there is no zero divisor: every row but row 0 holds each element once.', meta: { phase: 'row', row: a, unit: true } });
      // the summary
      const sumCls = (r, c, v) => (r === 0 ? zeroDim(v) : isUnit(r) && v === 1 ? 'ntone' : !isUnit(r) && v === 0 && c > 0 ? 'ntzd' : zeroDim(v));
      const ph = NT().phi(n).phi;
      const lines = [['units: ' + (units.length ? '{' + units.join(', ') + '}' : 'none'), 'good'], ['zero divisors: ' + (zds.length ? '{' + zds.join(', ') + '}' : 'none'), zds.length ? 'bad' : 'muted'], ['φ(' + n + ') = ' + ph + ' units', 'strong']];
      const tm = tMul(sumCls);
      const yL = tm.box.y + tm.box.h + 36;
      F.add({ items: [tAddTitle, tMulTitle].concat(tAdd(zeroDim).items, tm.items, H.eqs('su', mx, yL, lines, 16, 28)), say: 'The units of Z_' + n + ' are ' + (units.length ? H.list(units) : 'none') + ': the elements sharing no factor with ' + n + ', ' + ph + ' of them (that count is Euler\'s φ(' + n + ')). ' + (zds.length ? 'The zero divisors are ' + H.list(zds) + '. Every nonzero element is one or the other.' : 'Every nonzero element is a unit, so Z_' + n + ' is a field: you can divide by anything but 0.'), meta: { phase: 'sum' } });
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'Z_n', text: ['Z_n = {0, 1, …, n − 1}, + and · mod n', 'unit: a·b ≡ 1 for some b  ⇔  gcd(a, n) = 1', 'zero divisor: a ≠ 0 with a·b ≡ 0 for some b ≠ 0', 'Z_n is a field  ⇔  n is prime'].join('\n') }] } };
    },
    predict: [
      { at: (f, i, fr) => f.meta && f.meta.phase === 'mul' && fr[i + 1] && fr[i + 1].meta.row > 0, pick: 'option', ask: (fr, i) => 'Does row ' + fr[i + 1].meta.row + ' of the multiplication table contain a 1?', options: ['yes: it is a unit', 'no: it is a zero divisor'], answer: (fr, i) => (fr[i + 1].meta.unit ? 'yes: it is a unit' : 'no: it is a zero divisor'), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta && f.meta.phase === 'add', pick: 'option', ask: (fr, i, inp) => 'In row ' + inp.a + ' of the addition table, which column holds the 0?', options: (fr, i, inp) => [...new Set([(inp.n - inp.a) % inp.n, inp.a, 0, (inp.n - inp.a + 1) % inp.n])].map(String), answer: (fr, i, inp) => String((inp.n - inp.a) % inp.n), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Which elements of Z_12 are units?', options: ['1, 5, 7, 11', '1, 3, 5, 7, 9, 11', '2, 4, 6, 8, 10', 'all but 0'], answer: 0, why: 'The units are the numbers sharing no factor with 12 = 2²·3.' },
      { q: 'Is 6 a zero divisor in Z_15?', options: ['yes: 6·5 ≡ 0', 'no: 6 is a unit', 'no: 6 > 15/3'], answer: 0, why: '6·5 = 30 ≡ 0 (mod 15) with neither 6 nor 5 equal to 0.' },
      { q: 'Z_n is a field exactly when…', options: ['n is prime', 'n is odd', 'n is a power of 2', 'n > 2'], answer: 0, why: 'Only then is every nonzero element coprime to n, so every nonzero element has an inverse.' },
      { q: 'How often does each element appear in one row of the addition table of Z_n?', options: ['once', 'twice', 'it depends on the row', 'n times'], answer: 0, why: 'Adding r is a turn of the clock: it moves every element to a different place.' },
      { q: 'A row of the multiplication table holds a 1 exactly when its element…', options: ['is coprime to n', 'is odd', 'is prime', 'divides n'], answer: 0, why: 'a·b ≡ 1 has a solution exactly when gcd(a, n) = 1.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Inverses: hopping round the clock by a
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'mod-inverse', family: 'p02-modular', order: 40, title: 'Inverses modulo n',
    blurb: 'The inverse of a modulo n is the number of hops of size a that land on 1. Hop round the clock: if a shares no factor with n the hops visit every position and reach 1; if it does, they visit only the multiples of the common factor and come back to 0 without ever touching 1.',
    inputs: [
      { id: 'a', kind: 'number', label: 'a', def: 5, min: -999, max: 999 },
      { id: 'n', kind: 'number', label: 'Modulus n', def: 17, min: 2, max: 36 },
    ],
    presets: [
      { label: '5 modulo 17', values: { a: 5, n: 17 } },
      { label: '7 modulo 12: its own inverse', values: { a: 7, n: 12 } },
      { label: '3 modulo 11', values: { a: 3, n: 11 } },
      { label: '4 modulo 10: no inverse', values: { a: 4, n: 10 } },
      { label: '9 modulo 26 (an affine key)', values: { a: 9, n: 26 } },
      { label: '−5 modulo 17', values: { a: -5, n: 17 } },
      { label: '6 modulo 9: no inverse', values: { a: 6, n: 9 } },
      { label: '35 modulo 36', values: { a: 35, n: 36 } },
    ],
    counters: [{ id: 'hops', label: 'hops' }],
    run(inp) {
      const n = inp.n, a = inp.a, ar = mod(a, n);
      const F = new S.Frames(['hops']);
      const cx = 240, cy = 240, Rr = 200;
      const res = NT().inverse(a, n), g = Number(NT().gcd(ar, n));
      const clock = (lit) => KN().clock({ prefix: 'ck', cx, cy, R: Rr, n, cls: (k) => lit[k] || '' });
      const pos = (k) => KN().at(n, k, cx, cy, Rr);
      const head = [H.title('h1', 0, -14, 'Hops of ' + ar + ' on a clock of ' + n)];
      const px = 500, rows = [];
      const panel = () => [H.title('h2', px, -14, 'k · ' + ar + ' mod ' + n)].concat(H.eqs('pl', px, 24, rows.slice(-11), 16, 34));
      if (a !== ar) rows.push([n$(a) + ' ≡ ' + ar + ' (mod ' + n + ')', 'muted']);
      F.add({ items: head.concat(clock({ 0: 'act' }).items, panel()), say: 'Look for x with ' + n$(a) + '·x ≡ 1 (mod ' + n + ')' + (a !== ar ? ': ' + n$(a) + ' ≡ ' + ar + ', so hops of ' + ar : ': hop round the clock ' + ar + ' steps at a time') + ', starting from 0. The number of hops that first lands on 1 is the inverse.', meta: { phase: 'start', found: res.inv !== null } });
      if (ar === 0) {
        F.add({ items: head.concat(clock({ 0: 'bad' }).items, panel()), say: n$(a) + ' ≡ 0 (mod ' + n + '): every hop is 0 steps long, so the hand never leaves 0. Zero has no inverse.', meta: { phase: 'none' } });
        return { frames: F.list };
      }
      const visited = [0], hops = [];
      let k = 0, cur = 0;
      const limit = res.inv !== null ? Number(res.inv) : n / g;
      const stride = limit > 14 ? Math.ceil(limit / 10) : 1;
      while (k < limit) {
        const upto = Math.min(limit, k + stride), k0 = k + 1;
        for (; k < upto;) { const nx = (cur + ar) % n; k++; hops.push([cur, nx, k]); rows.push([k + '·' + ar + ' = ' + k * ar + ' ≡ ' + nx, nx === 1 ? 'good' : '']); cur = nx; visited.push(nx); }
        F.set('hops', k);
        const lit = {}; for (const v of visited) lit[v] = 'act'; lit[0] = 'soft';
        if (cur === 1) lit[1] = 'good';
        const items = head.concat(clock(lit).items, panel());
        hops.forEach(([u, v, j]) => items.push(...KN().hop({ key: 'hp' + j, from: pos(u), to: pos(v), cx, cy, bow: 0.18, gap: 21, cls: (j >= k0 ? (cur === 1 && j === k ? 'good' : '') : 'faint') + ' thin', audit: 'edge-x' })));
        const last = hops[hops.length - 1];
        F.add({ items, say: (k > k0 ? 'Hops ' + k0 + ' to ' + k + ': ' : 'Hop ' + k + ': ') + k + '·' + ar + ' = ' + k * ar + ' ≡ ' + last[1] + ' (mod ' + n + ')' + (last[1] === 1 ? '. It lands on 1.' : last[1] === 0 ? ': back at 0, and 1 was never reached.' : '.'), meta: { phase: 'hop', k, at: last[1] } });
      }
      if (res.inv !== null) {
        const x = Number(res.inv), q = (ar * x - 1) / n;
        rows.push([ar + '·' + x + ' = ' + ar * x + ' = ' + q + '·' + n + ' + 1', 'good']);
        F.add({ items: head.concat(clock({ 0: 'soft', 1: 'good' }).items, panel()), say: n$(a) + '⁻¹ ≡ ' + x + ' (mod ' + n + '): ' + ar + '·' + x + ' = ' + ar * x + ' = ' + q + '·' + n + ' + 1. gcd(' + ar + ', ' + n + ') = 1, so the hops can reach every position, 1 among them. For large numbers nobody hops: the extended Euclidean algorithm finds x directly.', meta: { phase: 'done', inv: x } });
      } else {
        const lit = {}; for (let v = 0; v < n; v += g) lit[v] = 'bad';
        rows.push(['gcd(' + ar + ', ' + n + ') = ' + g, 'bad']);
        F.add({ items: head.concat(clock(lit).items, panel()), say: 'The hops visit only ' + H.list([...Array(n / g).keys()].map((j) => j * g)) + ', the multiples of gcd(' + ar + ', ' + n + ') = ' + g + ', and return to 0 after ' + n / g + ' hops. Every k·' + ar + ' is a multiple of ' + g + ' modulo ' + n + ', never 1: ' + n$(a) + ' has no inverse modulo ' + n + '.', meta: { phase: 'done', inv: null } });
      }
      for (const f of F.list) f.narrowView = { x: 0, y: -36, w: 480, h: 500 };
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'The inverse', text: ['a⁻¹ mod n: the x with a·x ≡ 1 (mod n)', 'it exists  ⇔  gcd(a, n) = 1', 'it is unique modulo n', 'found fast by the extended Euclidean algorithm'].join('\n') }] } };
    },
    predict: [
      { at: (f, i) => f.meta && f.meta.phase === 'start', pick: 'option', ask: 'Will the hops ever land on 1?', options: ['yes', 'no'], answer: (fr, i) => (fr[i].meta.found ? 'yes' : 'no'), explain: (fr) => fr[fr.length - 1].say },
      { at: (f, i, fr) => f.meta && f.meta.phase === 'hop' && fr[i + 1] && fr[i + 1].meta.phase === 'hop' && fr[i + 1].meta.k === f.meta.k + 1, once: true, pick: 'item', ask: 'Where does the next hop land? Click the position.', answer: (fr, i) => 'ck:' + fr[i + 1].meta.at, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What is 3⁻¹ modulo 7?', options: ['2', '3', '5', '6'], answer: 2, why: '3·5 = 15 = 2·7 + 1.' },
      { q: 'Why has 6 no inverse modulo 15?', options: ['gcd(6, 15) = 3', '6 is even', '15 is not prime', '6 > 15/3'], answer: 0, why: 'Every multiple of 6 modulo 15 is a multiple of 3, so none is 1.' },
      { q: 'If a⁻¹ ≡ x (mod n), then (−a)⁻¹ ≡ …', options: ['−x', 'x', '1/x', 'n − a'], answer: 0, why: '(−a)·(−x) = a·x ≡ 1.' },
      { q: 'How many elements of Z_26 have an inverse (the multipliers an affine cipher can use)?', options: ['12', '13', '25', '26'], answer: 0, why: 'φ(26) = φ(2)·φ(13) = 1·12 = 12: the odd numbers other than 13.' },
      { q: 'The hops of a round a clock of n visit every position exactly when…', options: ['gcd(a, n) = 1', 'a is prime', 'a < n/2', 'n is even'], answer: 0, why: 'With gcd g they visit only the n/g multiples of g.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
