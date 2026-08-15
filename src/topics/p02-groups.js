// Part 2, groups: the table of powers of every unit of Z_n*, where each row runs until it reaches 1 (its length is
// the order) and the full rows are the generators, with the quick test of a generator by the prime factors of the
// group order; and a cyclic subgroup H = ⟨a⟩ with its cosets gathered out of the group one by one, which shows
// Lagrange's theorem: the cosets have the size of H and share nothing, so |H| divides |G|.
(function (S) {
  'use strict';
  const H = S.P02, NT = () => S.NT;

  // ---------------------------------------------------------------------------------------------------------------
  // Orders, generators and primitive roots
  // ---------------------------------------------------------------------------------------------------------------
  const unitOf = (v, inp) => (v >= inp.n || Number(S.NT.gcd(v, inp.n)) !== 1 ? 'g: a number below n that shares no factor with it' : null);
  S.topic({
    id: 'group-order', family: 'p02-groups', order: 10, title: 'Order, generators and primitive roots',
    blurb: 'The units of Z_n form a group under multiplication, Z_n*. Each element\'s powers run round until they reach 1; the number of steps is its order, and it always divides the size of the group. An element whose powers reach every unit is a generator (a primitive root), and a quick test needs only the prime factors of the group\'s size.',
    inputs: [
      { id: 'n', kind: 'number', label: 'Modulus n', def: 13, min: 3, max: 19 },
      { id: 'g', kind: 'number', label: 'Test g', def: 6, min: 1, max: 18, check: unitOf },
    ],
    presets: [
      { label: 'Z_13*: 4 generators', values: { n: 13, g: 6 } },
      { label: 'Z_7*: is 3 a generator?', values: { n: 7, g: 3 } },
      { label: 'Z_11*, testing 3', values: { n: 11, g: 3 } },
      { label: 'Z_19*, testing 2', values: { n: 19, g: 2 } },
      { label: 'Z_18*: cyclic though 18 is not prime', values: { n: 18, g: 5 } },
      { label: 'Z_8*: no generator', values: { n: 8, g: 3 } },
      { label: 'Z_15*: not cyclic', values: { n: 15, g: 2 } },
    ],
    counters: [{ id: 'rows', label: 'rows filled' }, { id: 'gens', label: 'generators' }],
    run(inp) {
      const n = inp.n, g = inp.g, F = new S.Frames(['rows', 'gens']);
      const units = NT().ring(n).units().map(Number), ph = units.length;
      const pows = new Map(units.map((a) => [a, NT().powers(a, n).seq.map(Number)]));
      const ordOf = (a) => pows.get(a).length;
      const cw = 32, ch = 27, gap = 3, x0 = 50, y0 = 50;
      const colX = (e) => x0 + (e - 1) * (cw + gap), rowY = (i) => y0 + i * (ch + gap);
      const ordX = colX(ph + 1) + 8;
      const px = ordX + 60, W = px;
      const lines = [];
      const table = (filled, cls) => {
        const it = [H.text('tt', 0, 14, 'Powers a^e mod ' + n + ', e across', 'ntlab', 14)];
        for (let e = 1; e <= ph; e++) it.push({ key: 'he' + e, kind: 'text', x: colX(e) + cw / 2, y: y0 - 8, text: String(e), anchor: 'middle', size: 12, cls: 'ntlab' });
        it.push({ key: 'ho', kind: 'text', x: ordX + 22, y: y0 - 8, text: 'ord', anchor: 'middle', size: 12, cls: 'ntlab' });
        units.forEach((a, i) => {
          const full = filled(a);
          it.push({ key: 'ra' + a, kind: 'cell', x: 0, y: rowY(i), w: 40, h: ch, rx: 4, text: String(a), size: 14, cls: 'head ' + (cls && cls.head ? cls.head(a) || '' : '') });
          for (let e = 1; e <= ph; e++) {
            const v = e <= ordOf(a) ? pows.get(a)[e - 1] : null;
            const shown = full && v !== null;
            it.push({ key: 'p' + a + '_' + e, kind: 'cell', x: colX(e), y: rowY(i), w: cw, h: ch, rx: 3, text: shown ? String(v) : '', size: 13, cls: 'mono ntc ' + (!shown ? (e <= ordOf(a) || !full ? 'empty' : 'nobox') : (cls && cls.cell ? cls.cell(a, e, v) || '' : v === 1 ? 'ntone' : '')) });
          }
          if (full) it.push({ key: 'o' + a, kind: 'cell', x: ordX, y: rowY(i), w: 44, h: ch, rx: 4, text: String(ordOf(a)), size: 14, cls: 'mono ntc ' + (ordOf(a) === ph ? 'good' : '') });
        });
        return it;
      };
      const panel = () => [H.title('pt', px, 14, 'Z_' + n + '*')].concat(H.eqs('pe', px, 46, lines.slice(-14), 15, 28));
      lines.push(['|Z_' + n + '*| = φ(' + n + ') = ' + ph, 'strong']);
      F.add({ items: table(() => false).concat(panel()), say: 'Z_' + n + '* holds the units modulo ' + n + ', the ' + ph + ' numbers ' + H.list(units) + '. Each row will hold the powers a, a², a³, … of one of them, until the power reaches 1.', meta: { phase: 'start' } });
      // the rows, a few at a time
      const done = new Set(), per = Math.ceil(units.length / 7);
      for (let i = 0; i < units.length; i += per) {
        const chunk = units.slice(i, i + per);
        chunk.forEach((a) => done.add(a));
        F.set('rows', done.size);
        const says = chunk.map((a) => { const o = ordOf(a), sq = pows.get(a); return a + '^' + o + ' ≡ 1 (mod ' + n + ') first at exponent ' + o + (o > 1 ? ' (after ' + sq.slice(0, Math.min(o - 1, 6)).join(', ') + (o - 1 > 6 ? ', …' : '') + ')' : '') + ', so ord(' + a + ') = ' + o; });
        F.add({ items: table((a) => done.has(a), { cell: (a, e, v) => (v === 1 ? 'ntone' : chunk.includes(a) ? 'hot' : '') }).concat(panel()), say: (i === 0 ? 'Row by row: ' : '') + says.join('; ') + '.', meta: { phase: 'rows', rows: chunk.slice(), orders: chunk.map(ordOf) } });
      }
      // generators
      const gens = units.filter((a) => ordOf(a) === ph), roots = NT().primitiveRoots(n).map(Number);
      const ords = [...new Set(units.map(ordOf))].sort((a, b) => a - b);
      F.set('gens', gens.length);
      lines.push(['orders: ' + ords.join(', '), '']);
      lines.push(['all divide ' + ph, 'good']);
      if (gens.length) { lines.push(['generators: ' + gens.join(', '), 'good']); lines.push(['φ(' + ph + ') = ' + NT().phi(ph).phi + ' of them', 'good']); }
      else { lines.push(['no generator: not cyclic', 'bad']); lines.push(['largest order ' + NT().lambda(n), 'bad']); }
      const genCls = { cell: (a, e, v) => (v === 1 ? 'ntone' : gens.includes(a) ? 'good' : ''), head: (a) => (gens.includes(a) ? 'good' : '') };
      F.add({ items: table(() => true, genCls).concat(panel()), say: 'The orders that occur are ' + H.list(ords) + ': every one divides |Z_' + n + '*| = ' + ph + '. ' + (gens.length ? 'The rows of ' + H.list(gens) + ' are full: their powers reach every unit, so they generate the group, and Z_' + n + '* is cyclic. They are the primitive roots modulo ' + n + ', φ(' + ph + ') = ' + NT().phi(ph).phi + ' of them.' : 'No row is full: the largest order is ' + NT().lambda(n) + ', less than ' + ph + ', so Z_' + n + '* has no generator and is not cyclic.'), meta: { phase: 'gens', gens: gens.slice(), roots } });
      // the quick test for g, by the prime factors of the group order
      const fs = [...NT().factor(ph).keys()].map(Number);
      lines.push(['test g = ' + g + ': ' + ph + ' = ' + NT().fmtFactors(NT().factor(ph)), 'act']);
      const lit = [];
      let isGen = true;
      for (const q of fs) {
        const e = ph / q, v = Number(NT().pow(g, e, n));
        lit.push(e);
        lines.push([g + '^' + e + ' ≡ ' + v + (v === 1 ? '  ✗' : '  ✓'), v === 1 ? 'bad' : 'good']);
        const testCls = { cell: (a, ee, vv) => (a === g && lit.includes(ee) ? (vv === 1 ? 'bad' : 'hot') : vv === 1 ? 'ntone' : gens.includes(a) ? 'good' : ''), head: (a) => (a === g ? 'act' : gens.includes(a) ? 'good' : '') };
        F.add({ items: table(() => true, testCls).concat(panel()), say: 'Prime factor ' + q + ' of ' + ph + ': ' + g + '^' + e + ' ≡ ' + v + ' (mod ' + n + '). ' + (v === 1 ? 'It is 1, so the order of ' + g + ' divides ' + e + ' and ' + g + ' is not a generator.' : 'Not 1, so the order of ' + g + ' does not divide ' + ph + '/' + q + '.'), meta: { phase: 'test', q, e, v } });
        if (v === 1) { isGen = false; break; }
      }
      lines.push([isGen ? g + ' is a generator' : g + ' is not a generator (order ' + ordOf(g) + ')', isGen ? 'good' : 'bad']);
      F.add({ items: table(() => true, { cell: (a, ee, vv) => (a === g ? (vv === 1 ? 'ntone' : isGen ? 'good' : 'act') : vv === 1 ? 'ntone' : ''), head: (a) => (a === g ? (isGen ? 'good' : 'act') : '') }).concat(panel()), say: isGen ? 'No test gave 1, so ord(' + g + ') = ' + ph + ' and ' + g + ' generates Z_' + n + '*. This needs only ' + H.plural(fs.length, 'power') + ', one for each prime factor of ' + ph + ', instead of the whole row: that is how generators are checked when the group has 2^2048 elements.' : g + ' has order ' + ordOf(g) + ', less than ' + ph + ', so it is not a generator. The test found that with ' + H.plural(lit.length, 'power') + ', without writing out the row.', meta: { phase: 'verdict', gen: isGen } });
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'Order and generators', text: ['ord(a): the least k ≥ 1 with a^k ≡ 1 (mod n)', 'ord(a) divides |Z_n*| = φ(n)', 'g generates Z_n*  ⇔  ord(g) = φ(n)', 'test: g^(φ(n)/q) ≢ 1 for every prime q | φ(n)', 'a cyclic Z_n* has φ(φ(n)) generators'].join('\n') }] } };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'rows' && fr[i + 1].meta.rows.length === 1 && fr[i + 1].meta.rows[0] > 1, once: true, pick: 'option', ask: (fr, i) => 'What is the order of ' + fr[i + 1].meta.rows[0] + '?', options: (fr, i, inp) => S.NT.divisors(S.NT.phi(inp.n).phi).map(String), answer: (fr, i) => String(fr[i + 1].meta.orders[0]), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'test' && f.meta.phase === 'gens', pick: 'option', ask: (fr, i, inp) => 'Is ' + inp.g + ' a generator of Z_' + inp.n + '*?', options: ['yes', 'no'], answer: (fr) => (fr[fr.length - 1].meta.gen ? 'yes' : 'no'), explain: (fr) => fr[fr.length - 1].say },
    ],
    quiz: [
      { q: 'In Z_13*, which orders can an element have?', options: ['1, 2, 3, 4, 6, 12', 'any from 1 to 12', '1 and 12 only', '1, 2, 4, 8'], answer: 0, why: 'The order divides |Z_13*| = 12.' },
      { q: 'How many primitive roots does 23 have?', options: ['10', '11', '22', '2'], answer: 0, why: 'φ(22) = φ(2)·φ(11) = 10.' },
      { q: 'To test whether g generates Z_p* with p − 1 = 2·3·5·7, compute…', options: ['g^((p−1)/q) for q = 2, 3, 5, 7', 'all p − 1 powers of g', 'g^(p−1) only', 'gcd(g, p − 1)'], answer: 0, why: 'g is a generator exactly when none of these is 1.' },
      { q: 'Is Z_8* = {1, 3, 5, 7} cyclic?', options: ['no: every element has order 1 or 2', 'yes: 3 generates it', 'yes: 5 generates it'], answer: 0, why: '3² = 9 ≡ 1, 5² = 25 ≡ 1, 7² = 49 ≡ 1 (mod 8).' },
      { q: 'If ord(a) = 6 modulo 7, then a is…', options: ['a primitive root modulo 7', 'not a unit', '−1', 'of order dividing 3'], answer: 0, why: '6 = φ(7): its powers reach all six units.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Cyclic subgroups, cosets and Lagrange's theorem
  // ---------------------------------------------------------------------------------------------------------------
  const smallG = (v) => (S.NT.phi(v).phi > 24n ? 'n: φ(n) at most 24, so every element fits the picture' : null);
  S.topic({
    id: 'lagrange', family: 'p02-groups', order: 20, title: 'Cyclic subgroups, cosets and Lagrange',
    blurb: 'The powers of one element a form a subgroup H = ⟨a⟩. Multiplying all of H by some b gives a coset b·H, the same size as H; two cosets are equal or share nothing. So the cosets cut the group into equal pieces, and the size of H divides the size of the group: Lagrange\'s theorem.',
    inputs: [
      { id: 'n', kind: 'number', label: 'Modulus n', def: 21, min: 3, max: 60, check: smallG },
      { id: 'a', kind: 'number', label: 'Generator a of H', def: 4, min: 1, max: 59, check: (v, inp) => (v >= inp.n || Number(S.NT.gcd(v, inp.n)) !== 1 ? 'a: a unit of Z_n, below n and sharing no factor with it' : null) },
    ],
    presets: [
      { label: 'Z_21*, H = ⟨4⟩', values: { n: 21, a: 4 } },
      { label: 'Z_13*, H = ⟨3⟩ of order 3', values: { n: 13, a: 3 } },
      { label: 'Z_17*, H = ⟨2⟩ of order 8', values: { n: 17, a: 2 } },
      { label: 'Z_19*, H = ⟨7⟩', values: { n: 19, a: 7 } },
      { label: 'Z_15*, H = ⟨14⟩ = {1, 14}', values: { n: 15, a: 14 } },
      { label: 'A generator: H is everything', values: { n: 11, a: 2 } },
      { label: 'H = {1}: one coset per element', values: { n: 9, a: 1 } },
    ],
    counters: [{ id: 'cosets', label: 'cosets' }],
    run(inp) {
      const n = inp.n, a = inp.a, F = new S.Frames(['cosets']);
      const units = NT().ring(n).units().map(Number), G = units.length;
      const sub = NT().subgroup(a, n), Hs = sub.elements.map(Number), h = Hs.length;
      const lag = NT().lagrange(n), cos = lag.cosets(sub.elements).map((c) => ({ rep: Number(c.rep), els: c.elements.map(Number) }));
      // the pool: every element of G, in rows of 8
      const cw = 46, ch = 36, gp = 6, perRow = 8;
      const poolPos = (v) => { const i = units.indexOf(v); return { x: (i % perRow) * (cw + gp), y: 34 + Math.floor(i / perRow) * (ch + gp) }; };
      const poolH = 34 + Math.ceil(G / perRow) * (ch + gp);
      const px = perRow * (cw + gp) + 40;
      // the cosets: boxes flowing left to right below the pool
      const boxW = (k) => k * (cw + 4) + 24, boxH = ch + 44, cy0 = poolH + 40, maxW = 680;
      const boxes = [];
      { let x = 0, y = cy0; for (let k = 0; k < cos.length; k++) { const w = boxW(h); if (x + w > maxW && x > 0) { x = 0; y += boxH + 14; } boxes.push({ x, y, w }); x += w + 14; } }
      const elPos = new Map();
      const lines = [];
      const draw = (placed, cls, below) => {
        const it = [H.title('gt', 0, 14, 'G = Z_' + n + '*, ' + G + ' elements')];
        placed.forEach((k) => { const b = boxes[k]; it.push({ key: 'bx' + k, kind: 'region', x: b.x, y: b.y, w: b.w, h: boxH, rx: 10, text: '', cls: k === 0 ? 'act' : '' }); it.push(H.text('bl' + k, b.x + 12, b.y + 20, k === 0 ? 'H' : cos[k].rep + '·H', 'ntlab' + (k === 0 ? ' act' : ''), 14)); });
        for (const v of units) {
          const p = elPos.get(v) || poolPos(v), inBox = elPos.has(v);
          it.push({ key: 'e' + v, kind: 'cell', x: p.x, y: p.y, w: cw, h: ch, rx: 5, text: String(v), size: 15, cls: 'mono ntc ' + ((cls && cls(v)) || (inBox ? H.kc(cos.findIndex((c) => c.els.includes(v))) : '')) });
        }
        const fit = Math.max(2, Math.floor((cy0 - 60) / 28) + 1);
        it.push(H.title('pt', px, 14, 'Lagrange'), ...H.eqs('pe', px, 46, lines.slice(-fit), 15, 28));
        if (below) { const yb = Math.max(...boxes.map((b) => b.y)) + boxH + 44; it.push(H.title('st', 0, yb - 22, 'Every subgroup of Z_' + n + '*'), ...H.eqs('sb', 0, yb + 6, below, 15, 28)); }
        return it;
      };
      lines.push(['|G| = φ(' + n + ') = ' + G, 'strong']);
      F.add({ items: draw([]), say: 'G = Z_' + n + '* has φ(' + n + ') = ' + G + ' elements: ' + H.list(units) + '. Take a = ' + a + ' and collect its powers.', meta: { phase: 'start' } });
      // the powers of a
      const seq = NT().powers(a, n).seq.map(Number);
      const showPow = (k) => { const done = seq.slice(0, k); return (v) => (v === seq[k - 1] ? 'hot' : done.includes(v) ? 'act' : 'soft muted'); };
      const stride = Math.max(1, Math.ceil(seq.length / 6));
      for (let prev = 0; prev < seq.length;) {
        const kk = Math.min(seq.length, prev + stride);
        const said = seq.slice(prev, kk).map((v, j) => a + '^' + (prev + j + 1) + ' ≡ ' + v);
        F.add({ items: draw([], showPow(kk)), say: said.join(', ') + ' (mod ' + n + ')' + (seq[kk - 1] === 1 ? ': back at 1, so the powers of ' + a + ' close up after ' + h + ' step' + (h === 1 ? '' : 's') + '.' : '.'), meta: { phase: 'pow', k: kk } });
        prev = kk;
      }
      // H itself
      Hs.forEach((v, j) => elPos.set(v, { x: boxes[0].x + 12 + j * (cw + 4), y: boxes[0].y + 32 }));
      F.set('cosets', 1);
      lines.push(['H = ⟨' + a + '⟩, |H| = ' + h, 'act']);
      F.add({ items: draw([0]), say: 'H = ⟨' + a + '⟩ = {' + Hs.join(', ') + '} is a subgroup with ' + H.plural(h, 'element') + ': it contains 1, and a product of powers of ' + a + ' is again a power of ' + a + '.', meta: { phase: 'H', h } });
      // the cosets, one or a few at a time
      const rest = cos.slice(1), perF = Math.max(1, Math.ceil(rest.length / 6));
      for (let k = 0; k < rest.length; k += perF) {
        const now = rest.slice(k, k + perF);
        now.forEach((c, j) => { const bi = k + j + 1; c.els.forEach((v, t) => elPos.set(v, { x: boxes[bi].x + 12 + t * (cw + 4), y: boxes[bi].y + 32 })); });
        F.set('cosets', k + now.length + 1);
        const placed = [...Array(k + now.length + 1).keys()];
        const hot = new Set(now.flatMap((c) => c.els));
        F.add({ items: draw(placed, (v) => (hot.has(v) ? 'hot' : null)), say: now.map((c) => c.rep + '·H = {' + Hs.map((x) => c.rep + '·' + x).join(', ') + '} ≡ {' + Hs.map((x) => (c.rep * x) % n).join(', ') + '} (mod ' + n + ')').join('; ') + '. ' + (k === 0 ? 'Take the smallest element not used yet and multiply all of H by it: ' + H.plural(h, 'new element') + ', none of them in a coset before.' : 'Again ' + h + ' new elements each.'), meta: { phase: 'coset', reps: now.map((c) => c.rep) } });
      }
      const c = cos.length;
      lines.push([c + ' cosets of size ' + h, 'good']);
      lines.push([G + ' = ' + c + '·' + h, 'good']);
      F.add({ items: draw([...Array(c).keys()]), say: 'Every element landed in exactly one coset, and every coset has ' + h + ' element' + (h === 1 ? '' : 's') + ': ' + G + ' = ' + c + '·' + h + '. So |H| = ' + h + ' divides |G| = ' + G + ', which is Lagrange\'s theorem. In particular ord(' + a + ') = ' + h + ' divides ' + G + '.', meta: { phase: 'lagrange', c, h } });
      // every subgroup
      const subs = lag.subgroups;
      const ords = [...new Set(subs.map((x) => Number(x.order)))].sort((p, q) => p - q);
      const below = subs.slice(0, 6).map((x) => ['order ' + x.order + ': {' + x.elements.join(', ') + '}', Number(x.order) === h ? 'act' : '']);
      if (subs.length > 6) below.push(['… and ' + (subs.length - 6) + ' more', 'muted']);
      F.add({ items: draw([...Array(c).keys()], null, below), say: 'Z_' + n + '* has ' + H.plural(subs.length, 'subgroup') + ', of orders ' + H.list(ords) + ': each divides ' + G + '. ' + (subs.every((x) => x.cyclic) ? 'Every one of them is cyclic, generated by one element.' : H.plural(subs.filter((x) => !x.cyclic).length, 'of them is', 'of them are') + ' not cyclic: no single element generates ' + (subs.filter((x) => !x.cyclic).length === 1 ? 'it' : 'them') + '.'), meta: { phase: 'all', ords } });
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'Cosets and Lagrange', text: ['⟨a⟩ = {1, a, a², …}: a subgroup of order ord(a)', 'b·H = {b·h : h ∈ H}: a coset of H', 'two cosets are equal or disjoint', '|G| = (number of cosets)·|H|', 'so |H| divides |G|: Lagrange'].join('\n') }] } };
    },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'start', pick: 'option', ask: (fr, i, inp) => 'How many elements will H = ⟨' + inp.a + '⟩ have?', options: (fr, i, inp) => S.NT.divisors(S.NT.phi(inp.n).phi).map(String), answer: (fr) => String(fr.find((x) => x.meta.phase === 'H').meta.h), explain: (fr) => fr.find((x) => x.meta.phase === 'H').say },
      { at: (f, i, fr) => f.meta.phase === 'H' && fr[i + 1].meta.phase === 'coset', pick: 'option', ask: 'How many cosets will H have?', options: (fr, i, inp) => S.NT.divisors(S.NT.phi(inp.n).phi).map(String), answer: (fr) => String(fr.find((x) => x.meta.phase === 'lagrange').meta.c), explain: (fr) => fr.find((x) => x.meta.phase === 'lagrange').say },
    ],
    quiz: [
      { q: 'A group of order 15 can have subgroups of order…', options: ['1, 3, 5, 15', '1, 2, 3, 5, 15', 'any order up to 15', '1 and 15 only'], answer: 0, why: 'By Lagrange the order of a subgroup divides 15.' },
      { q: 'If |G| = 12 and H has order 4, how many cosets does H have?', options: ['3', '4', '8', '12'], answer: 0, why: '12 = 3·4.' },
      { q: 'Two different cosets of the same subgroup…', options: ['share no element', 'share the element 1', 'have different sizes', 'are both subgroups'], answer: 0, why: 'If b·h₁ = c·h₂, then b·H = c·H.' },
      { q: 'Why does a^|G| = 1 for every a in a finite group G?', options: ['ord(a) divides |G|', 'every a is a generator', 'G is cyclic', 'a^2 = 1'], answer: 0, why: 'The order of a is the size of ⟨a⟩, which divides |G| by Lagrange; this gives Fermat and Euler.' },
      { q: 'A group whose order is a prime p is…', options: ['cyclic, generated by any element but 1', 'never cyclic', 'of order p − 1', 'trivial'], answer: 0, why: 'Any element but 1 has order dividing p and greater than 1, so order p.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
