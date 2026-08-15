// Part 2, testing for primes: Fermat's test with the grid of every base coloured (witness, liar, shares a factor)
// and Korselt's criterion that marks the Carmichael numbers, and Miller–Rabin traced witness by witness, each base
// a row of repeated squarings that must reach −1.
(function (S) {
  'use strict';
  const H = S.P02, NT = () => S.NT;
  const n$ = H.n;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));

  // ---------------------------------------------------------------------------------------------------------------
  // Fermat's test and the Carmichael numbers
  // ---------------------------------------------------------------------------------------------------------------
  const isOdd = (v) => (v % 2 ? null : 'n: an odd number (an even one is plainly composite)');
  S.topic({
    id: 'carmichael', family: 'p02-primality', order: 10, title: 'Fermat\'s test and the Carmichael numbers',
    blurb: 'If n is prime, a^(n−1) ≡ 1 (mod n) for every base a it does not divide. A base where this fails proves n composite: a Fermat witness. A composite n that passes for a base is a liar for that base, and a Carmichael number passes for every base that shares no factor with it.',
    inputs: [{ id: 'n', kind: 'number', label: 'Odd n', def: 561, min: 5, max: 2001, check: isOdd }],
    presets: [
      { label: '561, the smallest Carmichael number', values: { n: 561 } },
      { label: '91 = 7·13, caught at once', values: { n: 91 } },
      { label: '341: fools base 2 alone', values: { n: 341 } },
      { label: '1105, another Carmichael number', values: { n: 1105 } },
      { label: '97, a prime', values: { n: 97 } },
      { label: '1729 = 7·13·19', values: { n: 1729 } },
      { label: '225 = 3²·5², not squarefree', values: { n: 225 } },
    ],
    counters: [{ id: 'tests', label: 'bases tested' }, { id: 'liars', label: 'liars found' }],
    run(inp) {
      const n = B(inp.n), N = Number(n), F = new S.Frames(['tests', 'liars']);
      const prime = NT().isProbablePrime(n);
      const small = N - 1 <= 120;
      // the grid of bases 1 … n − 1
      const cols = small ? 12 : Math.min(50, Math.ceil(Math.sqrt((N - 1) * 1.4))), cw = small ? 40 : Math.min(20, Math.floor(520 / cols)), ch = small ? 30 : cw, gap = small ? 4 : 0;
      const gx = 0, gy = 40;
      const rows = Math.ceil((N - 1) / cols);
      const gw = cols * (cw + gap), gh = rows * (ch + gap);
      const kind = (a) => { const A = B(a); if (NT().gcd(A, n) !== 1n) return 'fac'; return NT().pow(A, n - 1n, n) === 1n ? 'pass' : 'wit'; };
      const kinds = [null]; for (let a = 1; a < N; a++) kinds.push(kind(a));
      const look = { fac: '5', wit: '3', pass: prime ? '7' : '6' };
      const ccls = { fac: 'soft muted', wit: 'act', pass: prime ? 'good' : 'bad' };
      const grid = (shown) => {
        const items = [H.title('gt', gx, gy - 14, 'The bases 1 to ' + (N - 1))];
        if (small) {
          for (let a = 1; a < N; a++) {
            const r = Math.floor((a - 1) / cols), c = (a - 1) % cols, on = shown(a);
            items.push({ key: 'g' + a, kind: 'cell', x: gx + c * (cw + gap), y: gy + r * (ch + gap), w: cw, h: ch, rx: 4, text: String(a), size: 13, cls: 'mono ntc ' + (on ? ccls[kinds[a]] + (on === 'hot' ? ' ring' : '') : 'empty') });
          }
        } else {
          const rs = [];
          for (let r = 0; r < rows; r++) { let s = ''; for (let c = 0; c < cols; c++) { const a = r * cols + c + 1; s += a >= N ? ' ' : shown(a) ? (shown(a) === 'hot' ? '2' : look[kinds[a]]) : '0'; } rs.push(s); }
          items.push({ key: 'bm', kind: 'bitmap', x: gx, y: gy, cw, ch, gap: 1, rows: rs });
        }
        return items;
      };
      const px = gw + 50, lines = [];
      const legend = (counts) => {
        const it = [], ly = gy + gh + 30;
        const ent = [['wit', 'Fermat witness'], ['pass', prime ? 'passes (n is prime)' : 'liar: passes, though n is composite'], ['fac', 'shares a factor with n']];
        let x = gx;
        ent.forEach(([k, label], i) => {
          if (k === 'fac' && prime) return;
          if (small) it.push({ key: 'lg' + i, kind: 'cell', x, y: ly, w: 22, h: 18, rx: 3, text: '', cls: 'ntc ' + ccls[k] });
          else it.push({ key: 'lg' + i, kind: 'bitmap', x, y: ly + 1, cw: 16, ch: 16, gap: 1, rows: [look[k]] });
          const t = label + (counts ? ': ' + counts[k] : '');
          it.push(H.text('lt' + i, x + 30, ly + 14, t, 'ntlab', 13));
          x += 30 + S.geom.textWidth(t, 13) + 26;
        });
        return it;
      };
      const panel = (hl) => [H.text('pt', px, gy - 12, 'n = ' + n + (prime ? ', a prime' : ''), 'strong', 15)].concat(H.eqs('pe', px, gy + 14, lines.slice(-9).map((l, i, all) => (hl && i === all.length - 1 ? [l[0], (l[1] || '') + ' strong'] : l)), 16, 32));
      const tested = new Set();
      const shownT = (hot) => (a) => (tested.has(a) ? (a === hot ? 'hot' : 'on') : null);
      F.add({ items: grid(() => null).concat(legend(null), panel()), say: 'Fermat\'s little theorem: if n is prime, then a^(n−1) ≡ 1 (mod n) for every base a from 1 to n − 1. So test n = ' + n + ' by raising bases to the power ' + n + ' − 1 = ' + (n - 1n) + '.', meta: { phase: 'start' } });
      // a few single tests
      const bases = [2, 3, 5, 7, 11].filter((a) => a < N - 1).slice(0, 4);
      let liars = 0;
      for (const a of bases) {
        const r = NT().fermatTest(n, a);
        tested.add(a);
        if (r.passes && !prime) liars++;
        F.count('tests').set('liars', liars);
        const g = NT().gcd(B(a), n);
        lines.push([a + '^' + (n - 1n) + ' ≡ ' + r.value + ' (mod ' + n + ')', r.passes ? (prime ? 'good' : 'bad') : 'act']);
        F.add({ items: grid(shownT(a)).concat(legend(null), panel(true)), say: a + '^' + (n - 1n) + ' ≡ ' + r.value + ' (mod ' + n + '): ' + (r.passes ? (prime ? n + ' passes for base ' + a + ', as a prime must.' : n + ' passes for base ' + a + ', although it is composite: ' + a + ' is a Fermat liar for ' + n + '.') : a + ' is a Fermat witness, so ' + n + ' is certainly composite' + (g > 1n ? ' (indeed gcd(' + a + ', ' + n + ') = ' + g + ').' : ', though the test names no factor.')), meta: { phase: 'test', a, passes: r.passes } });
      }
      // every base at once
      const liarList = NT().fermatLiars(n).map(Number);
      const counts = { fac: kinds.filter((k) => k === 'fac').length, wit: kinds.filter((k) => k === 'wit').length, pass: kinds.filter((k) => k === 'pass').length };
      const ph = NT().phi(n).phi;
      F.set('tests', N - 1).set('liars', prime ? 0 : liarList.length);
      lines.push(['φ(' + n + ') = ' + ph + ' coprime bases', 'strong']);
      lines.push([(prime ? 'pass: ' : 'liars: ') + liarList.length + ' of ' + ph, prime ? 'good' : 'bad']);
      const carm = !prime && counts.wit === 0;
      F.add({ items: grid(() => 'on').concat(legend(counts), panel()), say: prime
        ? 'All ' + (N - 1) + ' bases pass: ' + n + ' is prime, and Fermat\'s theorem holds for every base.'
        : 'Every base tested: ' + counts.wit + ' Fermat witnesses, ' + liarList.length + ' liars and ' + counts.fac + ' bases sharing a factor with ' + n + '. ' + (carm ? 'Not one base coprime to ' + n + ' is a witness: all φ(' + n + ') = ' + ph + ' of them lie. Only the bases sharing a factor expose it.' : liarList.length > 2 ? 'The liars make up at most half of the coprime bases (here ' + liarList.length + ' of ' + ph + '), so a few random bases catch ' + n + ' quickly.' : 'Only 1 and n − 1, which every odd n passes, lie.'), meta: { phase: 'grid', carm } });
      // Korselt's criterion
      const f = NT().factor(n), ps = [...f.keys()], sqfree = [...f.values()].every((k) => k === 1);
      lines.length = 0;
      lines.push([n + ' = ' + NT().fmtFactors(f), 'strong']);
      if (prime) {
        lines.push([n + ' is prime: no Korselt test needed', 'good']);
        F.add({ items: grid(() => 'on').concat(legend(counts), panel()), say: n + ' has no factor but itself, so it is prime. A Carmichael number must be composite.', meta: { phase: 'korselt', carm: false } });
      } else {
        lines.push(['squarefree: ' + (sqfree ? 'yes' : 'no'), sqfree ? 'good' : 'bad']);
        const parts = ps.map((p) => { const q = (n - 1n) / (p - 1n), r = (n - 1n) % (p - 1n); return { p, q, r }; });
        for (const { p, q, r } of parts) lines.push([(n - 1n) + ' = ' + q + '·' + (p - 1n) + (r ? ' + ' + r : '') + (r ? '  ✗' : '  ✓'), r ? 'bad' : 'good']);
        const kors = sqfree && ps.length >= 2 && parts.every((x) => x.r === 0n);
        const says = parts.map(({ p, q, r }) => p + ' − 1 = ' + (p - 1n) + (r ? ' does not divide ' + (n - 1n) + ' (' + (n - 1n) + ' = ' + q + '·' + (p - 1n) + ' + ' + r + ')' : ' divides ' + (n - 1n) + ' (' + (n - 1n) + ' = ' + q + '·' + (p - 1n) + ')'));
        F.add({ items: grid(() => 'on').concat(legend(counts), panel()), say: 'Korselt\'s criterion: a composite n is a Carmichael number exactly when it is squarefree and p − 1 divides n − 1 for every prime p dividing it. Here ' + n + ' = ' + NT().fmtFactors(f) + (sqfree ? ', squarefree. ' : ', which is not squarefree. ') + says.join('; ') + '. So ' + n + (kors ? ' is a Carmichael number.' : ' is not a Carmichael number.'), meta: { phase: 'korselt', carm: kors } });
        if (kors) {
          lines.push(['all coprime a: a^(n−1) ≡ 1', 'bad']);
          F.add({ items: grid(() => 'on').concat(legend(counts), panel()), say: 'Why it lies: for a coprime to ' + n + ', a^(p−1) ≡ 1 (mod p) for each prime p, and n − 1 is a multiple of every p − 1, so a^(n−1) ≡ 1 modulo each prime factor, hence modulo ' + n + '. Fermat\'s test cannot tell such n from a prime; the Miller–Rabin test can.', meta: { phase: 'why' } });
        }
      }
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'Fermat\'s test', text: ['n prime  ⇒  a^(n−1) ≡ 1 (mod n) for 1 ≤ a < n', 'witness: a^(n−1) ≢ 1, so n is composite', 'liar: n composite, yet a^(n−1) ≡ 1', 'Carmichael: composite, a^(n−1) ≡ 1 for all a coprime to n', 'Korselt: n squarefree and (p − 1) | (n − 1) for each p | n'].join('\n') }] } };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'test' && fr[i + 1].meta.a === 2, pick: 'option', ask: (fr, i, inp) => 'Will ' + inp.n + ' pass Fermat\'s test for base 2?', options: ['yes', 'no'], answer: (fr, i) => (fr[i + 1].meta.passes ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'korselt' && f.meta.phase === 'grid' && !/is prime/.test(fr[i + 1].say.slice(0, 60)), pick: 'option', ask: (fr, i, inp) => 'Is ' + inp.n + ' a Carmichael number?', options: ['yes', 'no'], answer: (fr, i) => (fr[i + 1].meta.carm ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'If 2^(n−1) mod n ≠ 1, then n is…', options: ['certainly composite', 'certainly prime', 'probably prime', 'a Carmichael number'], answer: 0, why: 'A prime n must give 1; any other value is a proof that n is composite.' },
      { q: 'A Carmichael number is…', options: ['a composite n with a^(n−1) ≡ 1 for every a coprime to n', 'a prime that fails Fermat\'s test', 'a product of two primes', 'an even pseudoprime'], answer: 0, why: 'It passes Fermat\'s test for every base that does not share a factor with it.' },
      { q: 'Is 561 = 3·11·17 squarefree, with p − 1 dividing 560 for each p?', options: ['yes', 'no: 16 does not divide 560', 'no: it is not squarefree'], answer: 0, why: '560 = 280·2 = 56·10 = 35·16.' },
      { q: 'Which bases always expose a Carmichael number n?', options: ['those sharing a factor with n', 'the even ones', 'the primes', 'none'], answer: 0, why: 'If gcd(a, n) > 1, a^(n−1) cannot be 1 modulo n; but for a large n such bases are very rare.' },
      { q: 'Why is Fermat\'s test alone not used to choose RSA primes?', options: ['Carmichael numbers pass it for almost every base', 'it is too slow', 'it needs the factors of n', 'it only works for odd n'], answer: 0, why: 'Miller–Rabin has no such blind spot: at most a quarter of the bases lie for any odd composite.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Miller–Rabin, witness by witness
  // ---------------------------------------------------------------------------------------------------------------
  const okN = (v) => { let x; try { x = BigInt(String(v).trim()); } catch (e) { return 'n: a whole number'; } if (x < 5n) return 'n: at least 5'; if (!(x & 1n)) return 'n: an odd number (an even one is plainly composite)'; if (x.toString().length > 80) return 'n: at most 80 digits, so the picture stays readable'; return null; };
  S.topic({
    id: 'miller-rabin', family: 'p02-primality', order: 20, title: 'Miller–Rabin, witness by witness',
    blurb: 'Write n − 1 = 2^s·d with d odd. For a prime n, the chain a^d, a^(2d), a^(4d), … either starts at 1 or reaches −1 before it reaches 1, because the only square roots of 1 modulo a prime are ±1. A base whose chain breaks this rule is a witness that n is composite; for an odd composite at most a quarter of the bases fail to be one.',
    inputs: [
      { id: 'n', kind: 'bigint', label: 'Odd n', def: '2047', check: okN },
      { id: 'bases', kind: 'list', label: 'Bases', def: ['2', '3'], min: 1, max: 6, check: (v, inp) => { if (okN(inp.n)) return null; const n = BigInt(String(inp.n).trim()); for (const a of v) { if (!/^\d+$/.test(a)) return 'Bases: whole numbers'; if (BigInt(a) < 2n || BigInt(a) > n - 2n) return 'Bases: each between 2 and n − 2'; } return null; } },
    ],
    presets: [
      { label: '2047: base 2 lies, base 3 does not', values: { n: '2047', bases: ['2', '3'] } },
      { label: '561 = 3·11·17', values: { n: '561', bases: ['2', '7', '50'] } },
      { label: '65537: a prime with n − 1 = 2^16', values: { n: '65537', bases: ['3', '5'] } },
      { label: '25326001 fools 2, 3 and 5', values: { n: '25326001', bases: ['2', '3', '5', '7'] } },
      { label: '3215031751 fools 2, 3, 5 and 7', values: { n: '3215031751', bases: ['2', '3', '5', '7', '11'] } },
      { label: 'A 128-bit prime, n − 1 = 2^7·d', values: { n: '170141183460469231731687303715884120961', bases: ['2', '3', '5'] } },
      { label: 'A 127-bit product of two primes', values: { n: '85070591740482808040795923499543532697', bases: ['2', '3'] } },
    ],
    counters: [{ id: 'bases', label: 'bases tried' }, { id: 'sq', label: 'squarings' }],
    run(inp) {
      const n = BigInt(String(inp.n).trim()), bases = inp.bases.map((a) => BigInt(a));
      const F = new S.Frames(['bases', 'sq']);
      const big = n >= 10n ** 7n;
      const shortV = (v) => { const s = v.toString(); return s.length > 9 ? s.slice(0, 4) + '…' + s.slice(-4) : s; };
      const cellText = (v) => (v === n - 1n ? '−1' : big ? shortV(v) : v.toString());
      const first = NT().millerRabin(n, [bases[0]]), s = first.s, d = first.d;
      const prime = NT().isProbablePrime(n);
      const cw = big ? 96 : n >= 100000n ? 72 : 62, ch = 38, gap = 6;
      // a long chain wraps: at most 8 cells a line, each line with its own heads
      const per = 8, nl = Math.ceil(s / per), x0 = 96, y0 = 120;
      const lineH = ch + 34, baseH = nl * lineH + 14;
      const colX = (j) => x0 + (j % per) * (cw + gap);
      const cellY = (k, j) => y0 + 24 + k * baseH + Math.floor(j / per) * lineH;
      const headTxt = (j) => (j === 0 ? 'a^d' : 'a^(' + (j === 1 ? '2' : '2' + H.sup(j)) + 'd)');
      const items0 = [];
      items0.push(H.text('nn', 0, 16, 'n = ' + n$(n), 'strong', 17));
      items0.push(H.text('sd', 0, 48, 'n − 1 = ' + n$(n - 1n) + ' = 2' + H.sup(s) + '·' + n$(d), 'eq act', 16));
      // n − 1 in binary when it is short: the s trailing zeros are the 2^s
      if (n < 1n << 24n) {
        const bits = S.Kit.bytes.toBits(Number(n - 1n), NT().bitLength(n - 1n));
        const L = bits.length;
        const br = S.Kit.bytes.bits({ prefix: 'bb', x: 0, y: 66, bits, cw: 18, ch: 24, group: 64, cls: (i) => (i >= L - s ? 'hot' : 'act'), size: 13 });
        items0.push(...br.items);
        items0.push(H.text('bl', L * 19 + 14, 84, 'd = ' + n$(d) + ' in blue, then ' + H.plural(s, 'zero'), 'ntlab', 13));
      }
      const rows = [];
      const draw = () => {
        const it = items0.slice();
        // bases still to come: their label and an empty first cell, so the picture keeps its size
        bases.forEach((a, k) => { if (k < rows.length) return; it.push(H.text('ra' + k, 0, cellY(k, 0) + 25, 'a = ' + n$(a), 'ntlab', 15)); for (let j = 0; j < Math.min(s, per); j++) it.push({ key: 'c' + k + '_' + j, kind: 'cell', x: colX(j), y: cellY(k, j), w: cw, h: ch, rx: 5, text: '', cls: 'ntc empty' }); });
        rows.forEach((r, k) => {
          it.push(H.text('ra' + k, 0, cellY(k, 0) + 25, 'a = ' + n$(r.a), 'strong', 15));
          r.xs.forEach((v, j) => it.push({ key: 'ch' + k + '_' + j, kind: 'text', x: colX(j) + cw / 2, y: cellY(k, j) - 8, text: headTxt(j), anchor: 'middle', size: 13, cls: 'ntlab' }));
          r.xs.forEach((v, j) => {
            const last = j === r.xs.length - 1 && r.done;
            const cls = v === n - 1n ? 'good' : v === 1n ? (j === 0 ? 'good' : 'bad') : '';
            it.push({ key: 'c' + k + '_' + j, kind: 'cell', x: colX(j), y: cellY(k, j), w: cw, h: ch, rx: 5, text: cellText(v), size: 14, cls: 'mono ntc ' + (cls || (r.cur === j ? 'hot' : last && r.verdict === 'fail' ? 'bad' : '')) });
          });
          if (r.done) {
            const lj = Math.max(r.xs.length, 1) - 1, vx = colX(lj) + cw + 14;
            it.push(H.text('rv' + k, vx, cellY(k, lj) + 25, r.verdict === 'pass' ? (prime ? 'passes' : 'strong liar') : 'witness', 'ntlab ' + (r.verdict === 'pass' ? (prime ? 'good' : 'hot') : 'act'), 15));
          }
        });
        return it;
      };
      F.add({ items: draw(), say: 'Test n = ' + n$(n) + '. Split off the powers of 2: ' + n$(n) + ' − 1 = ' + n$(n - 1n) + ' = 2^' + s + '·' + n$(d) + ', with d = ' + n$(d) + ' odd. Each base a gives the chain a^d, then ' + (s > 1 ? s - 1 + ' squaring' + (s > 2 ? 's' : '') : 'no squaring') + ', all modulo n.', meta: { phase: 'split', s } });
      const perStep = bases.length * s <= 24;
      let sq = 0, witness = null;
      bases.forEach((a, k) => {
        const mr = NT().millerRabin(n, [a]), rd = mr.rounds[0];
        const row = { a, xs: [], done: false, verdict: rd.verdict, cur: -1 };
        rows.push(row);
        F.count('bases');
        const xs = rd.x;
        if (perStep) {
          xs.forEach((v, j) => {
            row.xs.push(v); row.cur = j;
            if (j) { sq++; F.set('sq', sq); }
            const isLast = j === xs.length - 1;
            if (isLast) row.done = true;
            const tail = v === n - 1n ? ', which is −1.' : v === 1n ? (j === 0 ? ': the chain starts at 1.' : ', so ' + n$(xs[j - 1]) + ' is a square root of 1 other than ±1.') : '.';
            const sayV = j === 0 ? n$(a) + '^' + n$(d) + ' ≡ ' + n$(v) + ' (mod ' + n$(n) + ')' + tail : 'Square it: ' + n$(xs[j - 1]) + '² ≡ ' + n$(v) + ' (mod ' + n$(n) + ')' + tail;
            F.add({ items: draw(), say: 'Base ' + n$(a) + ': ' + sayV + (isLast ? ' ' + verdictSay(a, rd.verdict, xs, s) : ''), meta: { phase: 'step', k, j, v: v.toString(), last: isLast, verdict: isLast ? rd.verdict : null } });
          });
        } else {
          row.xs = xs.slice(); row.done = true; row.cur = xs.length - 1;
          sq += xs.length - 1; F.set('sq', sq);
          F.add({ items: draw(), say: 'Base ' + n$(a) + ': ' + n$(a) + '^' + n$(d) + ' ≡ ' + n$(xs[0]) + ' (mod ' + n$(n) + ')' + (xs.length > 1 ? ', then ' + (xs.length - 1) + ' squaring' + (xs.length > 2 ? 's' : '') + ' give ' + xs.slice(1).map(n$).join(', ') : '') + '. ' + verdictSay(a, rd.verdict, xs, s), meta: { phase: 'step', k, j: xs.length - 1, v: xs[xs.length - 1].toString(), last: true, verdict: rd.verdict } });
        }
        row.cur = -1;
        if (rd.verdict === 'fail' && witness === null) witness = a;
      });
      function verdictSay(a, v, xs, s) {
        if (v === 'pass') return prime ? n$(a) + ' is not a witness, as for a prime.' : n$(a) + ' is not a witness, yet n is composite: ' + n$(a) + ' is a strong liar for ' + n$(n) + '.';
        const last = xs[xs.length - 1];
        if (last === 1n && xs.length > 1) return 'A square root of 1 other than ±1 cannot exist modulo a prime, so ' + n$(a) + ' is a witness: ' + n$(n) + ' is composite.';
        return 'The chain never reached −1 in ' + H.plural(s, 'step') + ', so ' + n$(a) + ' is a witness: ' + n$(n) + ' is composite.';
      }
      // the verdict
      const passed = rows.filter((r) => r.verdict === 'pass').length;
      let fin;
      if (witness !== null) {
        const fs = n < 10n ** 18n ? NT().factor(n) : null;
        fin = n$(n) + ' is composite: ' + n$(witness) + ' is a witness' + (passed ? ', though ' + H.plural(passed, 'base') + ' lied' : '') + '. Miller–Rabin proves it without finding a factor' + (fs ? ' (the factors are ' + H.list([...fs].map(([p, k]) => (k > 1 ? n$(p) + '^' + k : n$(p)))) + ').' : '.');
      } else fin = n$(n) + ' passed all ' + H.plural(passed, 'base') + (prime ? ': it is prime' : ': it would be taken for a prime, yet it is composite (' + H.list([...NT().factor(n)].map(([p]) => n$(p))) + ' divide it); more bases would catch it') + '. Each random base lets an odd composite through with a chance of at most 1/4, so ' + H.plural(passed, 'round') + ' leave a chance below 4^−' + passed + '.';
      F.add({ items: draw(), say: fin, meta: { phase: 'done', composite: witness !== null } });
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'Miller–Rabin', text: ['n − 1 = 2^s·d, d odd', 'x₀ = a^d mod n, x_(j+1) = x_j² mod n', 'pass: x₀ = 1, or some x_j = n − 1 (j < s)', 'otherwise a is a witness: n is composite', 'composite n: at most 1/4 of bases pass'].join('\n') }] } };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'step' && fr[i + 1].meta.last && fr[i + 1].meta.k === 0, once: true, pick: 'option', ask: 'Will the first base be a witness?', options: ['yes: n is composite', 'no: it passes'], answer: (fr, i) => (fr[i + 1].meta.verdict === 'fail' ? 'yes: n is composite' : 'no: it passes'), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta.phase !== 'done' && fr[i + 1] && fr[i + 1].meta.phase === 'done', pick: 'option', ask: 'Is n prime?', options: ['prime', 'composite'], answer: (fr, i) => (fr[i + 1].meta.composite ? 'composite' : (/yet it is composite/.test(fr[i + 1].say) ? 'composite' : 'prime')), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'For n = 561, what are s and d in n − 1 = 2^s·d?', options: ['s = 4, d = 35', 's = 2, d = 140', 's = 1, d = 280', 's = 5, d = 17'], answer: 0, why: '560 = 16·35, and 35 is odd.' },
      { q: 'Why must the chain reach −1 before 1 when n is prime?', options: ['the only square roots of 1 modulo a prime are 1 and −1', 'a^d is always −1', 'n − 1 is even', 'd is odd'], answer: 0, why: 'x² ≡ 1 means p divides (x − 1)(x + 1), so x ≡ ±1.' },
      { q: 'At most what fraction of bases are strong liars for an odd composite n?', options: ['1/4', '1/2', '1/10', 'all of them for a Carmichael number'], answer: 0, why: 'This bound is why 20 random rounds leave a chance below 4^−20.' },
      { q: 'A base whose chain goes …, 1065, 1 (mod n) with 1065 ≢ ±1 shows that…', options: ['n is composite', 'n is prime', '1065 is prime', 'nothing'], answer: 0, why: '1065 is a square root of 1 other than ±1, impossible modulo a prime.' },
      { q: 'Does Miller–Rabin find a factor of a composite n?', options: ['not in general: it only proves n composite', 'yes, always', 'only for Carmichael numbers'], answer: 0, why: 'It shows a broken rule, not a divisor (though a nontrivial square root of 1 does give one by a gcd).' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
