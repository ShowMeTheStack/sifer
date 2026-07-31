// The number-theory bench (#bench/nt): Euclid and extended Euclid as a table that fills row by row, the Chinese
// remainder theorem with its construction, powers by square-and-multiply bit by bit, the order of an element and its
// cycle of powers, primality by Fermat and Miller–Rabin witness by witness, and arithmetic in GF(p) and GF(2^m).
// Every number may be as large as the engines allow (BigInt); every result comes with the engine's own trace.
(function (S) {
  'use strict';
  const { h } = S.UI;
  const MB = () => S.MathBench, U = () => S.BenchUI;
  const TOOLS = [['euclid', 'Euclid'], ['crt', 'CRT'], ['power', 'Powers'], ['order', 'Order'], ['prime', 'Primality'], ['field', 'Fields']];
  const DEF = {
    tool: 'euclid',
    euclid: { a: '1071', b: '462' },
    crt: { rows: [['2', '5'], ['3', '7'], ['10', '11']] },
    power: { x: '7', e: '560', n: '561' },
    order: { a: '3', n: '31' },
    prime: { n: '1729', bases: '2, 3, 5, 7', test: 'mr' },
    field: { kind: '2m', p: '29', m: '8', f: '', a: '0x57', b: '0x83', op: 'mul' },
  };
  const clone = (o) => JSON.parse(JSON.stringify(o));

  S.Bench.tab('nt', {
    title: 'Number theory', icon: 'numbers', order: 20,
    blurb: 'Euclid, the CRT, powers and orders, primality and finite fields, with every step shown.',
    open(host, saved, ctx) {
      const st = Object.assign(clone(DEF), saved || {});
      for (const k of Object.keys(DEF)) if (typeof DEF[k] === 'object' && !Array.isArray(DEF[k])) st[k] = Object.assign(clone(DEF[k]), (saved || {})[k] || {});
      if (!S.NT) { host.appendChild(U().missing('The number-theory engine')); return { state: () => st }; }
      let fr = null;
      const draw = () => {
        host.innerHTML = '';
        fr = MB().frame(host, { id: 'nt', title: 'Number theory', blurb: 'Euclid as a table, the Chinese remainder theorem, square-and-multiply, orders and generators, Miller–Rabin witness by witness, and the fields GF(p) and GF(2^m).', tools: TOOLS, tool: st.tool, ctx, onTool: (t) => { st.tool = t; ctx.save(); draw(); } });
        TOOL[st.tool](fr.left, fr.right, st[st.tool], () => ctx.save());
      };
      draw();
      return { state: () => st, redraw() {} };
    },
  });

  const rerun = (fn) => S.UI.debounce(fn, 250);
  /** an input bound to a field of the tool's state */
  const bind = (o, key, id, label, save, run, attrs) => U().field(label, U().input(id, o[key], (v) => { o[key] = v; save(); run(); }, { attrs: Object.assign({ inputmode: 'numeric' }, attrs || {}) }));

  const TOOL = {};
  // ---- Euclid --------------------------------------------------------------------------------------------------------
  TOOL.euclid = function (left, right, o, save) {
    const run = () => {
      right.innerHTML = '';
      const N = S.NT;
      MB().guard(right, () => {
        const a = MB().big(o.a, 'a', { min: 0 }), b = MB().big(o.b, 'b', { min: 0 });
        if (a === 0n && b === 0n) throw new Error('a and b cannot both be 0: every number divides 0.');
        const r = N.egcd(a, b);
        const rows = r.rows, steps = r.trace;
        const tbox = h('div');
        const say = h('p.mb-say', { id: 'ntEuclidSay' });
        const show = (k) => {
          tbox.innerHTML = '';
          const vis = rows.slice(0, k + 1);
          tbox.appendChild(MB().table(['i', 'q', 'r', 's', 't', 'r = a·s + b·t'], vis.map((x) => [x.i, x.q === null ? '—' : MB().n(x.q), MB().n(x.r), MB().n(x.s), MB().n(x.t), x.r.toString().length + x.s.toString().length < 40 ? x.r + ' = ' + a + '·' + (x.s < 0n ? '(' + x.s + ')' : x.s) + ' + ' + b + '·' + (x.t < 0n ? '(' + x.t + ')' : x.t) : 'checks']), { hl: vis.length - 1, id: 'ntEuclidTable' }));
          const s = steps[Math.min(steps.length - 1, Math.max(0, k - 1))];
          say.innerHTML = ''; say.append(...U().say(s ? s.say : ''));
        };
        const stepper = MB().stepper(rows.length - 1, show, { label: 'row', id: 'ntEuclidStep' });
        const inv = r.g === 1n && b > 1n ? N.mod(r.x, b) : null;
        right.append(MB().result('Extended Euclid', 'Each row is the one two above minus q times the one above, so r = a·s + b·t holds on every row.', stepper, say, tbox,
          MB().facts(['gcd(a, b)', r.g], ['Bézout', a + '·(' + r.x + ') + ' + b + '·(' + r.y + ') = ' + r.g], inv !== null ? ['a⁻¹ mod b', inv] : ['a⁻¹ mod b', 'none: gcd(a, b) = ' + r.g + ' ≠ 1'])));
        const e = N.euclid(a, b);
        right.append(MB().result('Plain Euclid', 'a = q·b + r, then (a, b) ← (b, r) until the remainder is 0.', MB().table(['a', 'b', 'q', 'r'], e.rows.map((x) => [MB().n(x.a), MB().n(x.b), MB().n(x.q), MB().n(x.r)]), { id: 'ntEuclidPlain' })));
      });
    };
    const r = rerun(run);
    left.appendChild(MB().result('Inputs', 'Two whole numbers, as large as you like.',
      h('div.brow', bind(o, 'a', 'ntA', 'a', save, r), bind(o, 'b', 'ntB', 'b', save, r)),
      MB().examples([['1071, 462', { a: '1071', b: '462' }], ['an inverse mod 3120', { a: '17', b: '3120' }], ['Fibonacci (slowest)', { a: '832040', b: '514229' }], ['big', { a: '2718281828459045235360287471352662497757', b: '3141592653589793238462643383279502884197' }]], (v) => { Object.assign(o, v); save(); left.querySelector('#ntA').value = o.a; left.querySelector('#ntB').value = o.b; run(); })));
    run();
  };

  // ---- the Chinese remainder theorem --------------------------------------------------------------------------------
  TOOL.crt = function (left, right, o, save) {
    const list = h('div.mb-crt-rows');
    const run = () => {
      right.innerHTML = '';
      MB().guard(right, () => {
        if (o.rows.length < 2) throw new Error('Give at least two congruences.');
        const rs = o.rows.map((x, i) => MB().big(x[0], 'r' + (i + 1))), ms = o.rows.map((x, i) => MB().big(x[1], 'm' + (i + 1), { min: 2 }));
        const sys = h('div.mb-sys', ...rs.map((r, i) => h('div.mono', 'x ≡ ' + r + ' (mod ' + ms[i] + ')')));
        let coprime = true;
        for (let i = 0; i < ms.length; i++) for (let j = i + 1; j < ms.length; j++) if (S.NT.gcd(ms[i], ms[j]) !== 1n) coprime = false;
        if (coprime) {
          const c = S.NT.crt(rs, ms);
          right.append(MB().result('The construction', 'With M the product of the moduli and Mᵢ = M / mᵢ, the term rᵢ·Mᵢ·(Mᵢ⁻¹ mod mᵢ) is rᵢ mod mᵢ and 0 mod every other modulus.', sys,
            MB().table(['i', 'rᵢ', 'mᵢ', 'Mᵢ = M / mᵢ', 'yᵢ = Mᵢ⁻¹ mod mᵢ', 'rᵢ·Mᵢ·yᵢ'], c.rows.map((x, i) => [i + 1, MB().n(x.r), MB().n(x.m), MB().n(x.Mi), MB().n(x.yi), MB().n(x.term)]), { id: 'ntCrtTable' }),
            MB().facts(['M', c.M], ['x', c.x], ['check', rs.map((r, i) => c.x + ' mod ' + ms[i] + ' = ' + (c.x % ms[i])).join(';  ')])));
          right.append(MB().result('Step by step', null, U().trace(c.trace)));
        } else {
          const g = S.NT.crtGeneral(rs, ms);
          right.append(MB().result('Moduli that share a factor', 'The moduli are not pairwise coprime, so the system is merged two congruences at a time; it has a solution only if the shared parts agree.', sys,
            g ? MB().facts(['x', g.x], ['modulo', g.M], ['check', rs.map((r, i) => g.x + ' mod ' + ms[i] + ' = ' + (g.x % ms[i])).join(';  ')]) : h('div.berr', 'No solution: two congruences demand different remainders modulo a common factor of their moduli.')));
        }
      });
    };
    const r = rerun(run);
    const paint = () => {
      list.innerHTML = '';
      o.rows.forEach((row, i) => {
        const del = h('button.icon-btn.mb-del', { type: 'button', title: 'Remove this congruence', 'aria-label': 'Remove congruence ' + (i + 1), disabled: o.rows.length <= 2 }, S.UI.icon('x'));
        del.addEventListener('click', () => { o.rows.splice(i, 1); save(); paint(); run(); });
        list.appendChild(h('div.mb-crt-row', h('span.mono', 'x ≡'), U().input('ntCrtR' + i, row[0], (v) => { row[0] = v; save(); r(); }, { label: 'remainder ' + (i + 1), attrs: { inputmode: 'numeric' } }), h('span.mono', '(mod'), U().input('ntCrtM' + i, row[1], (v) => { row[1] = v; save(); r(); }, { label: 'modulus ' + (i + 1), attrs: { inputmode: 'numeric' } }), h('span.mono', ')'), del));
      });
    };
    const add = h('button.btn.small', { type: 'button', id: 'ntCrtAdd' }, S.UI.icon('plus'), 'Another congruence');
    add.addEventListener('click', () => { o.rows.push(['1', '13']); save(); paint(); run(); });
    paint();
    left.appendChild(MB().result('Congruences', 'x leaves remainder r on division by m, for each row.', list, add,
      MB().examples([['three small', { rows: [['2', '5'], ['3', '7'], ['10', '11']] }], ['RSA-CRT style', { rows: [['27', '71'], ['77', '89']] }], ['shared factor', { rows: [['3', '12'], ['9', '18']] }], ['no solution', { rows: [['1', '6'], ['2', '4']] }]], (v) => { o.rows = clone(v.rows); save(); paint(); run(); })));
    run();
  };

  S.NtTools = TOOL;
})(globalThis.Sifer = globalThis.Sifer || {});
