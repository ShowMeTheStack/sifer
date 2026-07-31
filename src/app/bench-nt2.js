// The number-theory bench, continued: square-and-multiply, the order of an element and its ring of powers,
// primality (Fermat's test and Miller–Rabin), and arithmetic in GF(p) and GF(2^m).
(function (S) {
  'use strict';
  const { h } = S.UI;
  const MB = () => S.MathBench, U = () => S.BenchUI;
  const T = S.NtTools;
  const rerun = (fn) => S.UI.debounce(fn, 250);
  const bind = (o, key, id, label, save, run, attrs) => U().field(label, U().input(id, o[key], (v) => { o[key] = v; save(); run(); }, { attrs: Object.assign({ inputmode: 'numeric' }, attrs || {}) }));
  const setAll = (left, o, map) => { for (const [id, k] of Object.entries(map)) { const e = left.querySelector('#' + id); if (e) e.value = o[k]; } };

  // ---- powers by square-and-multiply ----------------------------------------------------------------------------------
  T.power = function (left, right, o, save) {
    const run = () => {
      right.innerHTML = '';
      MB().guard(right, () => {
        const x = MB().big(o.x, 'x', { min: 0 }), e = MB().big(o.e, 'e', { min: 0 }), n = MB().big(o.n, 'n', { min: 2 });
        if (e === 0n) { right.append(MB().result('x⁰', null, MB().facts(['result', '1 (x⁰ = 1 for every x)']))); return; }
        const r = S.ModExp.pow(x, e, n);
        const rows = r.steps.map((s) => [s.i, s.bit, s.sq === null ? '— (start: x)' : MB().n(s.sq), s.bit ? MB().n(s.mul === null ? s.value : s.mul) : '—', MB().n(s.value)]);
        const big = rows.length > 64;
        const shown = big ? rows.slice(0, 24).concat([['…', '…', '… ' + (rows.length - 40) + ' more bits …', '', '']], rows.slice(-16)) : rows;
        right.append(MB().result('Square-and-multiply', 'The exponent read from its top bit: every bit squares the running value, and a 1 bit multiplies by x as well.',
          h('div.mb-bits', { id: 'ntBits' }, ...String(r.bits).split('').map((b, i) => h('span.mb-bit' + (b === '1' ? '.one' : ''), { title: 'bit ' + i }, b))),
          MB().table(['step', 'bit', 'squared', 'times x', 'value'], shown, { id: 'ntPowTable', hl: shown.length - 1 }),
          MB().facts(['x^e mod n', r.value], ['squarings', r.squarings], ['multiplications', r.multiplications], ['bits of e', String(r.bits).length])));
        if (!big) right.append(MB().result('Step by step', null, U().trace(r.trace)));
      });
    };
    const r = rerun(run);
    left.appendChild(MB().result('x^e mod n', 'Any sizes: the work grows with the number of bits of e, not with e itself.',
      bind(o, 'x', 'ntX', 'x (the base)', save, r), bind(o, 'e', 'ntE', 'e (the exponent)', save, r), bind(o, 'n', 'ntN', 'n (the modulus)', save, r),
      MB().examples([['7^560 mod 561', { x: '7', e: '560', n: '561' }], ['Fermat on 101', { x: '3', e: '100', n: '101' }], ['2^(2^64) mod p', { x: '2', e: '18446744073709551616', n: '1000000007' }]], (v) => { Object.assign(o, v); save(); setAll(left, o, { ntX: 'x', ntE: 'e', ntN: 'n' }); run(); })));
    run();
  };

  // ---- the order of an element, and its cycle ---------------------------------------------------------------------------
  T.order = function (left, right, o, save) {
    const run = () => {
      right.innerHTML = '';
      const N = S.NT;
      MB().guard(right, () => {
        const a = MB().big(o.a, 'a', { min: 1 }), n = MB().big(o.n, 'n', { min: 2, max: '1000000000000', why: 'to keep the cycle of powers in reach' });
        if (N.gcd(a, n) !== 1n) throw new Error(a + ' shares the factor ' + N.gcd(a, n) + ' with ' + n + ', so it is not a unit mod ' + n + ': its powers never come back to 1.');
        const ord = N.order(a, n);
        const phi = N.phi(n).phi;
        const k = Number(ord.order);
        const isGen = ord.order === phi;
        const facts = MB().facts(['ord(a)', ord.order], ['φ(n)', phi], ['generator?', isGen ? 'yes: the powers of ' + a + ' reach every unit mod ' + n : 'no: ' + ord.order + ' divides φ(n) = ' + phi + ' but is smaller']);
        if (k <= 40) {
          const pw = N.powers(a, n);
          // start the ring at a⁰ = 1, at the top
          const cyc = ['1'].concat(pw.cycle.slice(0, -1).map(String));
          right.append(MB().result('The powers of ' + a + ' mod ' + n, 'From a⁰ = 1 at the top, each power is the one before times ' + a + '; after ' + k + ' steps they are back at 1 and go round again.',
            MB().ring(cyc, { closed: true, label: (i) => a + toSup(i), hl: (i) => cyc[i] === '1', centre: ['order ' + k, isGen ? 'a generator' : 'a subgroup of ' + k], aria: 'the powers of ' + a + ' mod ' + n }), facts));
        } else right.append(MB().result('The order of ' + a + ' mod ' + n, 'Too many powers to draw (' + k + '); the order is found from the factors of φ(n) instead.', facts));
        right.append(MB().result('How the order was found', 'By Lagrange the order divides φ(n); prime factors are struck out while a smaller power still gives 1.', U().trace(ord.trace)));
        if (n <= 400n) {
          const roots = N.primitiveRoots(n);
          right.append(MB().result('Generators mod ' + n, roots.length ? roots.length + ' of the ' + phi + ' units generate the whole group.' : 'The units mod ' + n + ' form no cyclic group: no element has order φ(n).', roots.length ? h('div.mb-chips', { id: 'ntRoots' }, ...roots.map((g) => h('span.mb-chip' + (g === a ? '.on' : ''), String(g)))) : null));
        }
      });
    };
    const r = rerun(run);
    left.appendChild(MB().result('An element of Z_n*', 'a must share no factor with n.', h('div.brow', bind(o, 'a', 'ntOa', 'a', save, r), bind(o, 'n', 'ntOn', 'n', save, r)),
      MB().examples([['3 mod 31', { a: '3', n: '31' }], ['2 mod 31', { a: '2', n: '31' }], ['10 mod 41', { a: '10', n: '41' }], ['3 mod 20', { a: '3', n: '20' }]], (v) => { Object.assign(o, v); save(); setAll(left, o, { ntOa: 'a', ntOn: 'n' }); run(); })));
    run();
  };
  const SUP = { 0: '⁰', 1: '¹', 2: '²', 3: '³', 4: '⁴', 5: '⁵', 6: '⁶', 7: '⁷', 8: '⁸', 9: '⁹' };
  const toSup = (k) => String(k).split('').map((c) => SUP[c]).join('');

  // ---- primality --------------------------------------------------------------------------------------------------------
  T.prime = function (left, right, o, save) {
    const run = () => {
      right.innerHTML = '';
      const N = S.NT;
      MB().guard(right, () => {
        const n = MB().big(o.n, 'n', { min: 3 });
        if (n % 2n === 0n) throw new Error(n + ' is even: 2 divides it, no test needed.');
        const bases = String(o.bases || '').split(/[\s,;]+/).filter(Boolean).map((t, i) => MB().big(t, 'base ' + (i + 1), { min: 2 }));
        if (!bases.length) throw new Error('Give at least one base, like 2, 3, 5.');
        for (const b of bases) if (b >= n - 1n) throw new Error('A base must lie between 2 and n − 2; ' + b + ' does not.');
        if (o.test === 'fermat') {
          const rows = bases.map((a) => N.fermatTest(n, a));
          const fails = rows.filter((x) => !x.passes).length;
          right.append(MB().result('Fermat\'s test', 'If n is prime, a^(n−1) ≡ 1 for every base a. A base that gives anything else proves n composite.',
            MB().table(['base a', 'a^(n−1) mod n', 'verdict'], rows.map((x, i) => [bases[i], MB().n(x.value), x.passes ? 'passes' : 'n is composite']), { id: 'ntFermatTable', mono: true }),
            MB().facts(['verdict', fails ? n + ' is composite' : 'every base passes: probably prime, unless n is a Carmichael number'])));
        } else {
          const mr = N.millerRabin(n, bases);
          right.append(MB().result('Miller–Rabin', 'Write n − 1 = 2^s·d with d odd. For each base, the chain a^d, a^(2d), … must start at 1 or reach −1; a square root of 1 other than ±1 proves n composite.',
            MB().facts(['n − 1', '2^' + mr.s + ' · ' + mr.d]),
            MB().table(['base', 'a^d, then squared …', 'verdict'], mr.rounds.map((x) => [x.a, x.x.map(String).join(' → '), x.verdict === 'fail' ? 'witness: composite' : 'passes']), { id: 'ntMrTable' }),
            MB().facts(['verdict', mr.probablePrime ? n + ' is probably prime (each passing base cuts the chance of error by at least 4)' : n + ' is composite; ' + mr.witness + ' is a witness'])));
          right.append(MB().result('Witness by witness', null, U().trace(mr.trace)));
        }
        if (n < 100000n && !N.isProbablePrime(n)) {
          const fl = N.fermatLiars(n).length, sl = N.strongLiars(n).length;
          right.append(MB().result('The liars of ' + n, 'Bases that wrongly pass. A Carmichael number fools Fermat\'s test for every base coprime to it; Miller–Rabin is fooled by at most a quarter of the bases.',
            MB().facts(['Fermat liars', fl], ['strong liars', sl], ['factors', [...N.factor(n)].map(([p, e]) => p + (e > 1 ? '^' + e : '')).join(' · ')])));
        }
      });
    };
    const r = rerun(run);
    left.appendChild(MB().result('Is n prime?', 'Odd n of any size; the bases are the witnesses to try.',
      U().seg('ntTest', [['mr', 'Miller–Rabin'], ['fermat', 'Fermat']], o.test, (v) => { o.test = v; save(); run(); }),
      bind(o, 'n', 'ntPn', 'n', save, r), bind(o, 'bases', 'ntPb', 'bases', save, r, { inputmode: 'text' }),
      MB().examples([['561 (Carmichael)', { n: '561', bases: '2, 5' }], ['1729 (Carmichael)', { n: '1729', bases: '2, 3, 5, 7' }], ['a 61-bit prime', { n: '2305843009213693951', bases: '2, 3, 5, 7, 11' }], ['a strong liar', { n: '2047', bases: '2' }]], (v) => { Object.assign(o, v); save(); setAll(left, o, { ntPn: 'n', ntPb: 'bases' }); run(); })));
    run();
  };

  // ---- finite fields -------------------------------------------------------------------------------------------------
  const OPS = { p: [['add', 'a + b'], ['mul', 'a · b'], ['inv', 'a⁻¹'], ['div', 'a / b'], ['sqrt', '√a']], '2m': [['add', 'a + b'], ['mul', 'a · b'], ['inv', 'a⁻¹'], ['div', 'a / b']] };
  T.field = function (left, right, o, save) {
    const opsBox = h('div');
    const run = () => {
      right.innerHTML = '';
      MB().guard(right, () => o.kind === 'p' ? gfp(right, o) : gf2m(right, o));
    };
    const r = rerun(run);
    const paintOps = () => {
      opsBox.innerHTML = '';
      if (!OPS[o.kind].some(([v]) => v === o.op)) o.op = 'mul';
      opsBox.appendChild(U().field('operation', U().select('ntFop', OPS[o.kind].map(([value, label]) => ({ value, label })), o.op, (v) => { o.op = v; save(); run(); })));
    };
    const fieldsP = h('div.brow', bind(o, 'p', 'ntFp', 'p (a prime)', save, r));
    const fields2 = h('div.brow', bind(o, 'm', 'ntFm', 'm', save, r), bind(o, 'f', 'ntFf', 'modulus f(x) (hex, or empty)', save, r, { inputmode: 'text', placeholder: 'standard' }));
    const vis = () => { fieldsP.style.display = o.kind === 'p' ? '' : 'none'; fields2.style.display = o.kind === 'p' ? 'none' : ''; };
    left.appendChild(MB().result('The field', 'GF(p) is arithmetic mod a prime; GF(2^m) is polynomials over GF(2) mod an irreducible f(x), written as bits (hex).',
      U().seg('ntFkind', [['2m', 'GF(2^m)'], ['p', 'GF(p)']], o.kind, (v) => { o.kind = v; save(); vis(); paintOps(); run(); }), fieldsP, fields2, opsBox,
      h('div.brow', bind(o, 'a', 'ntFa', 'a', save, r, { inputmode: 'text' }), bind(o, 'b', 'ntFb', 'b', save, r, { inputmode: 'text' })),
      MB().examples([['AES: 57 · 83', { kind: '2m', m: '8', f: '', a: '0x57', b: '0x83', op: 'mul' }], ['AES: 53⁻¹', { kind: '2m', m: '8', f: '', a: '0x53', b: '0x01', op: 'inv' }], ['GF(29): 7⁻¹', { kind: 'p', p: '29', a: '7', b: '1', op: 'inv' }], ['GF(103): √46', { kind: 'p', p: '103', a: '46', b: '1', op: 'sqrt' }]], (v) => { Object.assign(o, v); save(); setAll(left, o, { ntFp: 'p', ntFm: 'm', ntFf: 'f', ntFa: 'a', ntFb: 'b' }); left.querySelectorAll('#ntFkind button').forEach((b) => { const on = b.dataset.v === o.kind; b.classList.toggle('on', on); b.setAttribute('aria-checked', String(on)); }); vis(); paintOps(); run(); })));
    vis(); paintOps(); run();
  };
  function gfp(right, o) {
    const p = MB().big(o.p, 'p', { min: 2 });
    if (!S.NT.isProbablePrime(p)) throw new Error(p + ' is not prime, so Z_' + p + ' is not a field: try ' + S.NT.nextPrime(p) + '.');
    const F = S.GF.prime(p), a = S.NT.mod(MB().big(o.a, 'a'), p), b = S.NT.mod(MB().big(o.b, 'b'), p);
    const kids = [];
    let val;
    if (o.op === 'add') { val = F.add(a, b); kids.push(MB().facts(['a + b', a + ' + ' + b + ' = ' + (a + b) + ' ≡ ' + val + ' (mod ' + p + ')'])); }
    else if (o.op === 'mul') { val = F.mul(a, b); kids.push(MB().facts(['a · b', a + ' · ' + b + ' = ' + a * b + ' ≡ ' + val + ' (mod ' + p + ')'])); }
    else if (o.op === 'inv' || o.op === 'div') {
      if ((o.op === 'inv' ? a : b) === 0n) throw new Error('0 has no inverse in any field.');
      const it = F.invTrace(o.op === 'inv' ? a : b);
      val = o.op === 'inv' ? it.inv : F.mul(a, it.inv);
      kids.push(MB().table(['i', 'q', 'r', 's'], it.egcd.rows.map((x) => [x.i, x.q === null ? '—' : x.q, x.r, x.s]), { id: 'ntGfpTable' }));
      kids.push(MB().facts([o.op === 'inv' ? 'a⁻¹' : 'b⁻¹', it.inv + ' (check: ' + (o.op === 'inv' ? a : b) + ' · ' + it.inv + ' ≡ ' + F.mul(o.op === 'inv' ? a : b, it.inv) + ')'], o.op === 'div' ? ['a / b', a + ' · ' + it.inv + ' ≡ ' + val] : null));
    } else {
      const sq = F.isSquare(a);
      if (!sq) { kids.push(MB().facts(['√a', a + ' is not a square mod ' + p + ' (its Legendre symbol is −1): half the nonzero elements have no square root'])); }
      else { val = F.sqrt(a); kids.push(MB().facts(['√a', '±' + val + ', that is ' + val + ' and ' + (p - val) + ' (check: ' + val + '² ≡ ' + F.mul(val, val) + ')'])); }
    }
    right.append(MB().result('GF(' + p + ')', 'The integers 0 … ' + (p - 1n) + ' with addition and multiplication mod ' + p + '.', ...kids));
  }
  function gf2m(right, o) {
    const m = Number(MB().big(o.m, 'm', { min: 2, max: 571 }));
    const fTxt = String(o.f || '').trim();
    const f = fTxt ? MB().big(/^0x/i.test(fTxt) ? fTxt : '0x' + fTxt, 'f(x)') : null;
    if (f !== null && S.GF.poly.deg(f) !== m) throw new Error('f(x) must have degree ' + m + '; ' + S.GF.poly.str(f) + ' has degree ' + S.GF.poly.deg(f) + '.');
    if (f !== null && !S.GF.poly.isIrreducible(f)) throw new Error(S.GF.poly.str(f) + ' factors, so the result would not be a field: choose an irreducible f(x).');
    if (f === null && !S.GF.IRREDUCIBLE[m]) throw new Error('There is no standard modulus for m = ' + m + ' here: give f(x) in hex.');
    const F = S.GF.binary(m, f || undefined);
    const lim = (1n << BigInt(m)) - 1n;
    const rd = (t, l) => { const s = String(t).trim(); const v = MB().big(/^0x/i.test(s) || /[a-f]/i.test(s) ? (/^0x/i.test(s) ? s : '0x' + s) : '0x' + s, l, { min: 0 }); if (v > lim) throw new Error(l + ' has more than ' + m + ' bits: it must be below 2^' + m + '.'); return v; };
    const a = rd(o.a, 'a'), b = rd(o.b, 'b');
    const hx = (v) => F.hex ? F.hex(v) : v.toString(16);
    const ps = (v) => S.GF.poly.str(v);
    const head = MB().facts(['f(x)', ps(F.f) + '  (0x' + F.f.toString(16) + ')'], ['a', '0x' + hx(a) + ' = ' + ps(a)], o.op === 'inv' ? null : ['b', '0x' + hx(b) + ' = ' + ps(b)]);
    const kids = [head];
    if (o.op === 'add') kids.push(MB().facts(['a + b', 'XOR, bit by bit: 0x' + hx(F.add(a, b)) + ' = ' + ps(F.add(a, b))]));
    else if (o.op === 'mul') {
      const t = F.mulTrace(a, b);
      kids.push(MB().table(['bit i of b', 'term xⁱ·a', 'running sum', 'times x', 'reduced?'], t.rows.map((x) => [x.i + ': ' + x.bit, x.bit ? '0x' + hx(x.term) : '—', '0x' + hx(x.acc), '0x' + x.shifted.toString(16), x.reduced ? 'yes: XOR f' : 'no']), { id: 'ntGfMulTable' }));
      kids.push(MB().facts(['a · b', '0x' + hx(t.value) + ' = ' + ps(t.value)]));
      kids.push(U().trace(t.trace));
    } else {
      if ((o.op === 'inv' ? a : b) === 0n) throw new Error('0 has no inverse in any field.');
      const t = F.invTrace(o.op === 'inv' ? a : b);
      kids.push(MB().table(['remainder', 'quotient', 't'], t.rows.map((x) => [ps(x.r), x.q === null ? '—' : ps(x.q), ps(x.t)]), { id: 'ntGfInvTable', text: [] }));
      kids.push(MB().facts([o.op === 'inv' ? 'a⁻¹' : 'b⁻¹', '0x' + hx(t.inv) + ' = ' + ps(t.inv)], o.op === 'div' ? ['a / b', '0x' + hx(F.mul(a, t.inv))] : null));
      kids.push(U().trace(t.trace));
    }
    right.append(MB().result('GF(2^' + m + ')', 'Addition is XOR; multiplication is shift-and-add, reducing by f(x) whenever a term reaches degree ' + m + '; the inverse comes from Euclid on polynomials.', ...kids));
  }

  // ---- what the diagram checker looks at ------------------------------------------------------------------------------
  if (S.Checks) for (const [t, name] of [['euclid', 'Euclid'], ['crt', 'CRT'], ['power', 'square-and-multiply'], ['order', 'the ring of powers'], ['prime', 'Miller–Rabin'], ['field', 'GF(2^8) multiplication']]) {
    S.Checks.push({ group: 'bench-nt', name, hash: 'bench/nt', ready: "document.querySelector('#ntOut .bcard')", setup: `document.querySelector('#nt-tool button[data-v=${t}]').click(); await new Promise((r) => setTimeout(r, 150));`, sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
