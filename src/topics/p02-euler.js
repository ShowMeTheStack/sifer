// Part 2, Euler and Fermat: φ(n) counted on a grid struck out prime by prime, the powers of a number hopping round
// the clock until they repeat (a cycle, or a tail and a cycle), and the reshuffled row of units that proves
// a^φ(n) ≡ 1, with Fermat's little theorem as the prime case and its use for cutting down huge exponents.
(function (S) {
  'use strict';
  const H = S.P02, NT = () => S.NT, KN = () => S.Kit.nt;
  const n$ = H.n, sup = H.sup;
  const mod = (a, n) => ((a % n) + n) % n;

  // ---------------------------------------------------------------------------------------------------------------
  // Euler's φ on the coprime grid
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'euler-phi', family: 'p02-euler', order: 10, title: 'Euler\'s φ and the coprime grid',
    blurb: 'φ(n) counts the numbers from 1 to n that share no factor with n. Write them in a grid and strike out the multiples of each prime factor of n: what survives is coprime to n. Counting the survivors gives φ(n) = n·(1 − 1/p)·(1 − 1/q)·…, one factor for each prime.',
    inputs: [{ id: 'n', kind: 'number', label: 'n', def: 60, min: 2, max: 120 }],
    presets: [
      { label: 'n = 60', values: { n: 60 } },
      { label: 'A prime: 31', values: { n: 31 } },
      { label: 'A prime power: 81', values: { n: 81 } },
      { label: 'Two primes: 77 = 7·11', values: { n: 77 } },
      { label: 'Many small primes: 105', values: { n: 105 } },
      { label: 'A power of 2: 64', values: { n: 64 } },
      { label: 'The smallest: 2', values: { n: 2 } },
    ],
    counters: [{ id: 'left', label: 'still standing' }, { id: 'struck', label: 'struck out' }],
    run(inp) {
      const n = inp.n, ph = NT().phi(n), grid = NT().coprimeGrid(n), fs = [...ph.factors];
      const F = new S.Frames(['left', 'struck']);
      const cols = n > 100 ? 12 : 10, cw = 46, chh = 34, gp = 6;
      const pos = (k) => ({ x: ((k - 1) % cols) * (cw + gp), y: 36 + Math.floor((k - 1) / cols) * (chh + gp) });
      const struckBy = new Map(); // k -> the prime that struck it first
      const cells = (newP) => grid.cells.map(({ k }) => {
        const p = pos(k), by = struckBy.get(k);
        const cls = by === undefined ? (newP === 'done' ? 'good' : '') : by === newP ? 'bad' : 'struck';
        return { key: 'g' + k, kind: 'cell', x: p.x, y: p.y, w: cw, h: chh, rx: 5, text: String(k), size: 15, cls: 'mono ntc ' + cls };
      });
      const rows = Math.ceil(n / cols), px = cols * (cw + gp) + 44;
      const head = [H.title('gt', 0, 14, 'The numbers 1 to ' + n)];
      const lines = [[n + ' = ' + NT().fmtFactors(ph.factors).replace(/\^(\d+)/g, (m, d) => sup(d)), 'strong']];
      const panel = (hl) => [H.title('pt', px, 14, 'Striking out')].concat(H.eqs('pl', px, 50, lines.map((l, i) => (i === hl ? [l[0], (l[1] || '') + ' hot'] : l)), 16, 32));
      F.set('left', n);
      F.add({ items: head.concat(cells(null), panel()), say: 'Which of 1 to ' + n + ' share no factor with ' + n + '? ' + ph.trace[0].say.replace(/\.$/, '') + (fs.length === 1 && fs[0][1] === 1 ? ': it is prime, so only ' + n + ' itself shares a factor with it.' : ': a number shares a factor with ' + n + ' exactly when one of ' + H.list(fs.map(([p]) => String(p))) + ' divides it.'), meta: { phase: 'start' } });
      let left = n;
      fs.forEach(([p], idx) => {
        const P = Number(p);
        let fresh = 0;
        for (let k = P; k <= n; k += P) if (!struckBy.has(k)) { struckBy.set(k, P); fresh++; }
        left -= fresh;
        F.set('left', left).set('struck', n - left);
        for (const l of lines) if (l[1] === 'bad') l[1] = 'muted';
        lines.push(['multiples of ' + P + ': ' + n / P + (fresh < n / P ? ', ' + fresh + ' new' : '') + ' → ' + left + ' left', 'bad']);
        F.add({ items: head.concat(cells(P), panel(lines.length - 1)), say: 'Strike out the multiples of ' + P + ': ' + P + ', ' + 2 * P + ', … up to ' + n + ', that is ' + n + '/' + P + ' = ' + n / P + ' numbers' + (fresh < n / P ? ', of which ' + (n / P - fresh) + ' were struck already, so ' + fresh + ' new' : '') + '. ' + left + ' remain.', meta: { phase: 'strike', p: P, fresh, left } });
      });
      // the survivors and the formula
      const parts = ph.trace.filter((t) => t.kind === 'part');
      const prodStr = fs.map(([p, k]) => 'φ(' + p + (k > 1 ? sup(k) : '') + ')').join('·'), valStr = parts.map((t) => String(t.part)).join('·');
      const fracStr = n + fs.map(([p]) => '·(1 − 1/' + p + ')').join('');
      lines.push(['φ(' + n + ') = ' + ph.phi, 'good']);
      lines.push([fracStr + ' = ' + ph.phi, 'good']);
      F.add({ items: head.concat(cells('done'), panel()), say: 'The ' + ph.phi + ' survivors are coprime to ' + n + ', so φ(' + n + ') = ' + ph.phi + '. The factorisation gives it without a grid: ' + (fs.length > 1 ? 'φ(' + n + ') = ' + prodStr + ' = ' + valStr + ' = ' + ph.phi + ', and ' : '') + parts.map((t) => t.say.replace(/\.$/, '')).join('; ') + '. Each prime p keeps the fraction (1 − 1/p) of what is left.', meta: { phase: 'done', phi: Number(ph.phi) } });
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'Euler\'s φ', text: ['φ(n) = #{1 ≤ k ≤ n : gcd(k, n) = 1}', 'φ(p) = p − 1 for a prime p', 'φ(p^k) = p^(k−1)·(p − 1)', 'φ(m·n) = φ(m)·φ(n) when gcd(m, n) = 1', 'φ(n) = n·Π (1 − 1/p) over the primes p | n'].join('\n') }] } };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'done', pick: 'option', ask: 'How many numbers will survive?', options: (fr, i) => { const v = fr[i + 1].meta.phi; return [...new Set([v, v + 1, v - 1 > 0 ? v - 1 : v + 3, v * 2])].map(String); }, answer: (fr, i) => String(fr[i + 1].meta.phi), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta.phase === 'start' && fr[i + 1] && fr[i + 1].meta.phase === 'strike', pick: 'option', ask: (fr, i) => 'How many numbers will striking the multiples of ' + fr[i + 1].meta.p + ' leave?', options: (fr, i, inp) => { const v = fr[i + 1].meta.left, p = fr[i + 1].meta.p; return [...new Set([v, inp.n / p, v + 1, inp.n - 1])].map(String); }, answer: (fr, i) => String(fr[i + 1].meta.left), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What is φ(36)?', options: ['12', '18', '24', '6'], answer: 0, why: '36 = 2²·3²: φ = 36·(1/2)·(2/3) = 12.' },
      { q: 'φ(p) for a prime p is…', options: ['p − 1', 'p', '1', '(p − 1)/2'], answer: 0, why: 'Every number from 1 to p − 1 is coprime to p.' },
      { q: 'If n = p·q with p and q distinct primes, φ(n) = …', options: ['(p − 1)(q − 1)', 'p·q − 1', 'p + q', '(p + 1)(q + 1)'], answer: 0, why: 'φ is multiplicative on coprime factors. This is the φ of an RSA modulus.' },
      { q: 'φ(n) is the number of…', options: ['units of Z_n', 'primes below n', 'divisors of n', 'zero divisors of Z_n'], answer: 0, why: 'A number has an inverse modulo n exactly when it is coprime to n.' },
      { q: 'Why does knowing φ(n) for an RSA modulus n reveal its factors?', options: ['p + q = n − φ(n) + 1, and with p·q = n that is a quadratic', 'φ(n) is one of the factors', 'φ(n) is the private key', 'it does not'], answer: 0, why: 'φ(n) = n − p − q + 1, so p and q are the roots of x² − (n − φ(n) + 1)x + n.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Powers as cycles
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'power-cycles', family: 'p02-euler', order: 20, title: 'Powers modulo n go round in cycles',
    blurb: 'Start at 1 and multiply by a again and again: there are only n positions, so the powers of a must repeat, and from then on they cycle for ever. For a unit the cycle comes back to 1 itself, after ord(a) steps, a divisor of φ(n). A number sharing a factor with n first runs along a tail that never returns: the shape of the letter ρ.',
    inputs: [
      { id: 'a', kind: 'number', label: 'a', def: 3, min: -999, max: 999 },
      { id: 'n', kind: 'number', label: 'Modulus n', def: 17, min: 2, max: 30 },
    ],
    presets: [
      { label: '3 mod 17: every unit', values: { a: 3, n: 17 } },
      { label: '2 mod 7: a shorter cycle', values: { a: 2, n: 7 } },
      { label: '2 mod 12: a tail, then a cycle', values: { a: 2, n: 12 } },
      { label: '10 mod 21', values: { a: 10, n: 21 } },
      { label: '2 mod 20: a ρ', values: { a: 2, n: 20 } },
      { label: '6 mod 20: a cycle of one', values: { a: 6, n: 20 } },
      { label: '−1 mod 11', values: { a: -1, n: 11 } },
      { label: '5 mod 23', values: { a: 5, n: 23 } },
    ],
    counters: [{ id: 'k', label: 'powers' }],
    run(inp) {
      const n = inp.n, a = inp.a, ar = mod(a, n);
      const pw = NT().powers(a, n), seq = pw.seq.map(Number), tail = pw.tail.map(Number), cyc = (pw.cycle || []).map(Number);
      const unit = NT().gcd(ar, n) === 1n, ph = Number(NT().phi(n).phi), rep = pw.trace[pw.trace.length - 1];
      const F = new S.Frames(['k']);
      const cx = 250, cy = 250, R = 200;
      const ck = KN().clock({ prefix: 'ck', cx, cy, R, n });
      const pos = ck.pos, rr = ck.r;
      // the path: a^0 = 1, a^1, a^2, … ; values[k] = a^k mod n
      const values = [1 % n].concat(seq);
      const px = 520, rows = [];
      const panel = () => [H.title('h2', px, -14, 'Powers of ' + ar + ' mod ' + n)].concat(H.eqs('pl', px, 24, rows.slice(-12), 16, 32));
      const labelsAt = (upto) => {
        const by = new Map();
        for (let k = 0; k <= upto; k++) { const v = values[k]; if (!by.has(v)) by.set(v, []); by.get(v).push(k); }
        const it = [];
        for (const [v, ks] of by) {
          const ang = (KN().angle(n, v) - 90) * Math.PI / 180, d = R + rr + 15;
          const c = Math.cos(ang);
          it.push({ key: 'ex' + v, kind: 'text', x: Math.round(cx + d * c), y: Math.round(cy + d * Math.sin(ang) + 5), text: ks.join(', '), anchor: c > 0.3 ? 'start' : c < -0.3 ? 'end' : 'middle', size: 13, cls: 'ntlab act', audit: 'small-ok' });
        }
        return it;
      };
      const head = [H.title('h1', 0, -14, 'Exponents beside the positions they reach')];
      const T = tail.length;
      const draw = (upto, newest, final) => {
        const lit = {};
        for (let k = 1; k <= upto; k++) lit[values[k]] = 'act';
        if (final) { for (const v of tail) lit[v] = 'key'; for (const v of cyc) lit[v] = 'good'; }
        if (!final || !unit) lit[values[0]] = lit[values[0]] === 'act' && !final ? 'act' : final ? 'soft' : upto === 0 ? 'act' : lit[values[0]] || 'soft';
        if (newest !== null && !final) lit[values[upto]] = 'hot';
        const c = KN().clock({ prefix: 'ck', cx, cy, R, n, cls: (k) => lit[k] || '' });
        const it = head.concat(c.items, labelsAt(upto), panel());
        // a short hop bows far enough inwards to pass inside the positions between its ends
        const hop = (key, u, v, cls, more) => {
          if (u === v) return;
          const A = pos(u), Bp = pos(v), L = Math.hypot(Bp.x - A.x, Bp.y - A.y), m0 = Math.hypot((A.x + Bp.x) / 2 - cx, (A.y + Bp.y) / 2 - cy);
          const bow = Math.max(0.12, (2 * (m0 - (R - 1.5 * rr - 8))) / L) + (more || 0);
          it.push(...KN().hop({ key, from: A, to: Bp, cx, cy, bow, gap: rr + 3, cls: cls + ' thin', audit: 'edge-x' }));
        };
        for (let k = 1; k <= upto; k++) hop('hp' + k, values[k - 1], values[k], final ? (!unit && k <= T + 1 ? 'key' : 'good') : k === upto ? 'hot' : '');
        // a cycle that does not pass through 1 closes on its first value
        if (final && !unit) hop('hpc', values[upto], cyc[0], 'good', 0.3);
        return it;
      };
      rows.push([ar + '⁰ ≡ 1', 'muted']);
      F.add({ items: draw(0, null, false), say: 'Powers of ' + n$(a) + (a !== ar ? ' (≡ ' + ar + ')' : '') + ' modulo ' + n + ': start at ' + ar + '⁰ = 1 and multiply by ' + ar + ' each step. Only ' + n + ' positions exist, so a value must come round again.', meta: { phase: 'start', cycle: cyc.length } });
      const total = seq.length + (rep.kind === 'repeat' ? 1 : 0);
      const stride = total > 14 ? Math.ceil(total / 10) : 1;
      for (let k = 1; k <= seq.length; k += 0) {
        const to = Math.min(seq.length, k + stride - 1);
        for (const r of rows) if (r[1] === 'hot') r[1] = '';
        for (let j = k; j <= to; j++) rows.push([ar + sup(j) + ' ≡ ' + values[j - 1] + '·' + ar + ' ≡ ' + values[j], j === to ? 'hot' : '']);
        F.set('k', to);
        const v = values[to];
        F.add({ items: draw(to, to, false), say: (to > k ? 'Powers ' + k + (to - k === 1 ? ' and ' : ' to ') + to + ': ' : '') + n$(ar) + '^' + to + ' ≡ ' + values[to - 1] + '·' + ar + ' ≡ ' + v + ' (mod ' + n + ')' + (v === values[0] && to > 0 && unit ? ': back at 1.' : '.'), meta: { phase: 'power', k: to, at: v } });
        k = to + 1;
      }
      // the repeat
      F.set('k', seq.length);
      const L = cyc.length, ord = unit ? L : null;
      let say;
      if (unit) say = ar + '^' + L + ' ≡ 1 (mod ' + n + '): the powers are back at 1 after ' + L + ' step' + (L === 1 ? '' : 's') + ' and repeat for ever, so ord(' + ar + ') = ' + L + '. φ(' + n + ') = ' + ph + ', and ' + L + ' divides ' + ph + (L === ph ? ': every unit appears, so ' + ar + ' generates them all, a primitive root.' : ': ' + ar + ' reaches only ' + L + ' of the ' + ph + ' units.');
      else say = ar + '^' + rep.k + ' ≡ ' + values[rep.start] + ' again, the value first reached at power ' + rep.start + ': ' + (T ? 'a tail of ' + H.plural(T, 'value') + ' (' + H.list(tail) + '), then ' : '') + 'a cycle of length ' + L + ' (' + H.list(cyc) + '). gcd(' + ar + ', ' + n + ') = ' + NT().gcd(ar, n) + ', so no power of ' + ar + ' is ever 1 again.';
      for (const r of rows) if (r[1] === 'hot') r[1] = '';
      if (!unit) rows.push([ar + sup(rep.k) + ' ≡ ' + values[seq.length] + '·' + ar + ' ≡ ' + values[rep.start] + ', seen before', 'hot']);
      rows.push([unit ? 'ord(' + ar + ') = ' + L : 'tail ' + tail.length + ', cycle ' + L, 'good']);
      F.add({ items: draw(seq.length, null, true), say, meta: { phase: 'done', cycle: L, tail: tail.length, ord } });
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'Powers', text: ['a⁰ = 1, a^(k+1) = a^k·a mod n', 'at most n values, so they repeat', 'unit a: a^ord(a) ≡ 1, ord(a) divides φ(n)', 'ord(a) = φ(n): a is a primitive root', 'non-unit a: a tail, then a cycle (a ρ)'].join('\n') }] } };
    },
    predict: [
      { at: (f) => f.meta.phase === 'start', pick: 'option', ask: 'How long will the cycle be?', options: (fr, i, inp) => { const L = fr[i].meta.cycle, ph = Number(S.NT.phi(inp.n).phi); return [...new Set([L, ph, inp.n, Math.max(1, L - 1)])].map(String); }, answer: (fr, i) => String(fr[i].meta.cycle), explain: (fr) => fr[fr.length - 1].say },
      { at: (f, i, fr) => f.meta.phase === 'power' && fr[i + 1] && fr[i + 1].meta.phase === 'power' && fr[i + 1].meta.k === f.meta.k + 1 && f.meta.k >= 1, once: true, pick: 'item', ask: 'Where will the next power land? Click its position.', answer: (fr, i) => 'ck:' + fr[i + 1].meta.at, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What is the order of 2 modulo 7?', options: ['3', '6', '2', '7'], answer: 0, why: '2, 4, 8 ≡ 1: three steps.' },
      { q: 'The order of a unit modulo n always…', options: ['divides φ(n)', 'equals φ(n)', 'divides n', 'is prime'], answer: 0, why: 'The powers of a form a subgroup of the φ(n) units, and its size divides theirs.' },
      { q: 'Why do the powers of 6 modulo 20 never return to 1?', options: ['6 shares the factor 2 with 20', '6 is even', '20 is not prime', 'they do'], answer: 0, why: 'Every power of 6 is even, and so is every number ≡ it mod 20; 1 is odd.' },
      { q: 'A primitive root modulo a prime p is a number whose powers…', options: ['reach all p − 1 nonzero residues', 'reach 0', 'are all odd', 'repeat after 2 steps'], answer: 0, why: 'Its order is p − 1, the whole group.' },
      { q: 'Why must the powers repeat at all?', options: ['there are only n possible values', 'because of Fermat', 'because a < n', 'they need not'], answer: 0, why: 'n + 1 powers cannot all differ when there are n positions.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Fermat and Euler
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'fermat-euler', family: 'p02-euler', order: 30, title: 'Fermat\'s little theorem and Euler\'s theorem',
    blurb: 'Multiply every unit modulo n by a unit a: the results are the same units in another order. So both rows have the same product, and the second is a^φ(n) times the first. Cancelling gives Euler\'s theorem, a^φ(n) ≡ 1; for a prime p it is Fermat\'s little theorem, a^(p−1) ≡ 1. It cuts any exponent down modulo φ(n), which is what makes RSA decrypt.',
    inputs: [
      { id: 'n', kind: 'number', label: 'Modulus n', def: 13, min: 2, max: 21 },
      { id: 'a', kind: 'number', label: 'a (a unit)', def: 7, min: -999, max: 999, check: (v, inp) => (Number(S.NT.gcd(v, inp.n)) !== 1 ? 'a must share no factor with n (gcd(' + v + ', ' + inp.n + ') = ' + S.NT.gcd(v, inp.n) + ')' : null) },
      { id: 'e', kind: 'bigint', label: 'A big exponent e', def: '1000', check: H.range(0, 10n ** 30n, 'e') },
    ],
    presets: [
      { label: 'Fermat: 7 mod 13', values: { n: 13, a: 7, e: '1000' } },
      { label: 'Euler: 3 mod 10', values: { n: 10, a: 3, e: '2026' } },
      { label: 'Euler: 2 mod 15', values: { n: 15, a: 2, e: '123456789' } },
      { label: 'Fermat: 5 mod 19', values: { n: 19, a: 5, e: '1000000000000000000000' } },
      { label: 'Euler: 5 mod 21', values: { n: 21, a: 5, e: '77' } },
      { label: 'A tiny prime: 2 mod 3', values: { n: 3, a: 2, e: '5' } },
    ],
    counters: [{ id: 'units', label: 'units' }],
    run(inp) {
      const n = inp.n, a = inp.a, ar = Number(NT().mod(a, n)), e = H.big(inp.e);
      const R = NT().ring(n), units = R.units().map(Number), ph = units.length, prime = R.isField();
      const F = new S.Frames(['units']);
      F.set('units', ph);
      const prod = units.map((u) => Number(R.mul(ar, u)));
      const cw = 42, gp = 8, step = cw + gp, x0 = 60, yT = 40, yB = 210;
      const colOf = (v) => units.indexOf(v);
      const top = (cls) => units.map((u, i) => ({ key: 'u' + u, kind: 'cell', x: x0 + i * step, y: yT, w: cw, h: 36, rx: 5, text: String(u), size: 15, cls: 'mono ntc ' + (cls ? cls(u) : '') }));
      const bottom = (sorted, cls) => units.map((u, i) => ({ key: 'p' + u, kind: 'cell', x: x0 + (sorted ? colOf(prod[i]) : i) * step, y: yB, w: cw, h: 36, rx: 5, text: String(prod[i]), size: 15, cls: 'mono ntc ' + (cls ? cls(u) : 'act'), enter: 'from', src: 'u' + u }));
      // a wire from each unit down to its product: straight down out of the cell, across, and straight down in
      const arrows = (cls, sorted) => units.map((u, i) => {
        const x1 = x0 + i * step + cw / 2, x2 = x0 + (sorted ? colOf(prod[i]) : i) * step + cw / 2, y1 = yT + 36, y2 = yB;
        const pts = x1 === x2 ? [[x1, y1], [x2, y2]] : [[x1, y1], [x1, y1 + 16], [x2, y2 - 16], [x2, y2]];
        return { key: 'ar' + u, kind: 'wire', pts, head: true, cls: (cls || 'act') + ' hop' };
      });
      const labels = [H.text('lu', 0, yT + 24, 'u', 'ntlab', 15), H.text('lp', 0, yB + 24, ar + '·u', 'ntlab act', 15), H.title('t1', 0, 14, 'The ' + ph + ' units modulo ' + n)];
      const W = x0 + ph * step;
      const ly = yB + 80, rows = [];
      const panel = () => H.eqs('pl', 0, ly, rows, 16, 30);
      const P = units.reduce((x, u) => x * BigInt(u), 1n), Pm = NT().mod(P, n);
      F.add({ items: labels.concat(top()), say: 'The units modulo ' + n + ' are the ' + ph + ' numbers below ' + n + ' that share no factor with it' + (prime ? ': all of 1 to ' + (n - 1) + ', since ' + n + ' is prime.' : ': ' + H.list(units) + '. φ(' + n + ') = ' + ph + '.'), meta: { phase: 'units' } });
      const ex = units.slice(0, 3).map((u, i) => u + ' to ' + prod[i]);
      F.add({ items: labels.concat(top(), bottom(false), arrows()), say: 'Multiply each by ' + ar + ' modulo ' + n + ': ' + (units.length > 3 ? ex.join(', ') + ', and so on' : H.list(ex)) + '.', meta: { phase: 'times' } });
      F.add({ items: labels.concat(top(), bottom(true, () => 'act'), arrows('act', true)), say: 'Sort the bottom row: it is the top row again. Each product is a unit, and no two are equal, since ' + ar + '·u ≡ ' + ar + '·v forces u ≡ v (multiply by ' + ar + '⁻¹ ≡ ' + R.inv(ar) + '). Multiplying by ' + ar + ' only reshuffles the units.', meta: { phase: 'perm' } });
      // equal products, then cancel
      const prodTxt = ph <= 8 ? units.join('·') : units.slice(0, 3).join('·') + '·…·' + units[ph - 1];
      rows.push(['top: ' + prodTxt + ' ≡ ' + Pm + ' (mod ' + n + ')']);
      rows.push(['bottom: ' + ar + sup(ph) + '·(' + prodTxt + ') ≡ ' + Pm + ' (mod ' + n + ')', 'act']);
      rows.push([ar + sup(ph) + ' ≡ 1 (mod ' + n + ')', 'good']);
      F.add({ items: labels.concat(top(), bottom(true, () => 'act'), arrows('act', true), panel()), say: 'So the two rows have the same product. The top multiplies out to ' + (ph <= 8 ? prodTxt + ' = ' + P + ' ≡ ' + Pm + ' (mod ' + n + ')' : Pm + ' modulo ' + n) + '. The bottom is the same product with one extra factor ' + ar + ' for each of the ' + ph + ' units: ' + ar + '^' + ph + '·' + Pm + ' ≡ ' + Pm + ' (mod ' + n + '). ' + Pm + ' is a unit, so it cancels: ' + ar + '^' + ph + ' ≡ 1 (mod ' + n + ').', meta: { phase: 'cancel' } });
      // the theorem, checked
      const v1 = NT().pow(ar, ph, n), vp = NT().pow(ar, n, n);
      rows.length = 0;
      rows.push([(prime ? 'Fermat: ' : 'Euler: ') + ar + sup(ph) + ' ≡ ' + v1 + ' (mod ' + n + ')', 'good']);
      if (prime) rows.push(['and ' + ar + sup(n) + ' ≡ ' + vp + ' (mod ' + n + ')', 'good']);
      F.add({ items: labels.concat(top(), bottom(true, () => 'good'), arrows('act', true), panel()), say: (prime ? 'This is Fermat\'s little theorem: for the prime ' + n + ', a^' + (n - 1) + ' ≡ 1 for every a it does not divide; here ' + ar + '^' + ph + ' ≡ ' + v1 + ' (mod ' + n + '). Multiply by ' + ar + ' once more: ' + ar + '^' + n + ' ≡ ' + vp + ' (mod ' + n + '), a^p ≡ a, true even for a ≡ 0.' : 'This is Euler\'s theorem: a^φ(n) ≡ 1 for every unit a. Here ' + ar + '^' + ph + ' ≡ ' + v1 + ' (mod ' + n + ').') + ' Nothing about ' + ar + ' was special: the argument works for every unit.', meta: { phase: 'theorem' } });
      // using it: cut the exponent down modulo φ(n)
      const q = e / BigInt(ph), r = e % BigInt(ph), v = NT().pow(ar, r, n), ve = NT().pow(ar, e, n);
      rows.push([n$(e) + ' = ' + n$(q) + '·' + ph + ' + ' + r, 'act']);
      rows.push([ar + '^' + n$(e) + ' ≡ ' + ar + sup(r) + ' ≡ ' + v + ' (mod ' + n + ')', 'hot']);
      F.add({ items: labels.concat(top(), bottom(true, () => 'good'), arrows('act', true), panel()), say: 'A use: ' + ar + '^' + n$(e) + ' modulo ' + n + ' needs no ' + n$(e) + ' multiplications. ' + n$(e) + ' = ' + n$(q) + '·' + ph + ' + ' + r + ', and every ' + ar + '^' + ph + ' is 1, so ' + ar + '^' + n$(e) + ' ≡ ' + ar + '^' + r + ' ≡ ' + v + ' (mod ' + n + ').' , meta: { phase: 'use', value: Number(v), full: Number(ve) } });
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'The theorems', text: ['Euler: gcd(a, n) = 1  ⇒  a^φ(n) ≡ 1 (mod n)', 'Fermat: p prime, p ∤ a  ⇒  a^(p−1) ≡ 1 (mod p)', 'and a^p ≡ a (mod p) for every a', 'so a^e ≡ a^(e mod φ(n)) for a unit a', 'RSA: (m^e)^d = m^(1 + k·φ(n)) ≡ m'].join('\n') }] } };
    },
    predict: [
      { at: (f) => f.meta.phase === 'times', pick: 'option', ask: 'Sorted, will the bottom row be the same as the top row?', options: ['yes', 'no: some values repeat', 'no: some are not units'], answer: 'yes', explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'use', pick: 'option', ask: (fr, i, inp) => 'What is ' + Number(S.NT.mod(inp.a, inp.n)) + '^' + inp.e + ' mod ' + inp.n + '?', options: (fr, i, inp) => { const v = fr[i + 1].meta.value; return [...new Set([v, 1, (v + 1) % inp.n, 0])].map(String); }, answer: (fr, i) => String(fr[i + 1].meta.value), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What is 3^100 mod 7?', options: ['4', '1', '3', '2'], answer: 0, why: '100 = 16·6 + 4, so 3^100 ≡ 3^4 = 81 ≡ 4 (mod 7).' },
      { q: 'Euler\'s theorem needs a to be…', options: ['coprime to n', 'prime', 'smaller than φ(n)', 'odd'], answer: 0, why: 'For 2 modulo 4, 2^φ(4) = 2² = 4 ≡ 0, not 1.' },
      { q: 'Why does multiplying the units by a unit a only reshuffle them?', options: ['a has an inverse, so a·u ≡ a·v gives u ≡ v', 'because n is prime', 'because a < n', 'because the units are odd'], answer: 0, why: 'The map u ↦ a·u can be undone by multiplying by a⁻¹.' },
      { q: 'A number n that passes a^(n−1) ≡ 1 (mod n) for some a is…', options: ['probably prime, but possibly composite', 'certainly prime', 'certainly composite', 'a power of a'], answer: 0, why: 'Fermat\'s theorem only goes one way; composite numbers can pass, and Carmichael numbers pass for every coprime a.' },
      { q: 'RSA decryption works because e·d ≡ 1 (mod φ(n)) and…', options: ['m^(k·φ(n) + 1) ≡ m by Euler\'s theorem', 'Fermat says m^e ≡ m', 'the CRT', 'φ(n) is prime'], answer: 0, why: '(m^e)^d = m^(e·d) = m·(m^φ(n))^k ≡ m.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
