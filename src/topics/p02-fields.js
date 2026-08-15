// Part 2, finite fields: GF(p) drawn as its elements on a ring with each one joined to its inverse (and Z_n for a
// composite n, where some have no partner), and polynomials over GF(2) as rows of coefficient bits: adding is XOR,
// multiplying is shifted copies added without carries, dividing is long division by XOR.
(function (S) {
  'use strict';
  const H = S.P02, NT = () => S.NT, KN = () => S.Kit.nt, GF = () => S.GF;
  const n$ = H.n;
  const mod = (a, n) => ((a % n) + n) % n;

  // ---------------------------------------------------------------------------------------------------------------
  // GF(p): every nonzero element has a partner
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'gf-p', family: 'p02-fields', order: 10, title: 'The prime field GF(p)',
    blurb: 'Modulo a prime p every nonzero element has an inverse, so you can add, subtract, multiply and divide: Z_p is the field GF(p). Draw the elements round a ring and join each to its inverse. Modulo a composite number some elements are left without a partner.',
    inputs: [
      { id: 'p', kind: 'number', label: 'Modulus p', def: 13, min: 2, max: 31 },
      { id: 'a', kind: 'number', label: 'a', def: 5, min: -99, max: 99 },
      { id: 'b', kind: 'number', label: 'b', def: 9, min: -99, max: 99 },
    ],
    presets: [
      { label: 'GF(13): 5 and 9', values: { p: 13, a: 5, b: 9 } },
      { label: 'GF(7)', values: { p: 7, a: 3, b: 5 } },
      { label: 'GF(31): 17 and 22', values: { p: 31, a: 17, b: 22 } },
      { label: 'GF(2): bits', values: { p: 2, a: 1, b: 1 } },
      { label: 'Z_12 is not a field', values: { p: 12, a: 7, b: 5 } },
      { label: 'Z_15: dividing by 6 fails', values: { p: 15, a: 4, b: 6 } },
    ],
    counters: [{ id: 'pairs', label: 'inverse pairs' }],
    run(inp) {
      const p = inp.p, F = new S.Frames(['pairs']);
      const prime = H.isPrime(p), name = prime ? 'GF(' + p + ')' : 'Z_' + p;
      const R = NT().ring(p), Fp = GF().prime(p);
      const m = p - 1, cx = 220, cy = 220, Rr = 190;
      const els = [...Array(m).keys()].map((k) => k + 1);
      const invOf = (x) => R.inv(x);
      // the pairs, each once: {u, v} with u ≤ v
      const pairs = [], lone = [];
      for (const x of els) { const y = invOf(x); if (y === null) lone.push(x); else if (Number(y) >= x) pairs.push([x, Number(y)]); }
      const ring = (lit) => KN().clock({ prefix: 'el', cx, cy, R: Rr, n: Math.max(m, 1), text: (k) => String(k + 1), cls: (k) => lit[k + 1] || '' });
      const pos = (x) => KN().at(Math.max(m, 1), x - 1, cx, cy, Rr);
      const head = [H.title('h1', 0, -10, 'The nonzero elements of ' + name)];
      const px = 450, lines = [];
      const panel = (hl) => { const tight = lines.length > 12; return [H.title('h2', px, -10, prime ? 'In ' + name : 'In ' + name + ', not a field')].concat(H.eqs('pl', px, 30, lines.map((l, i) => (i === hl ? [l[0], (l[1] || '') + ' hot'] : l)), tight ? 15 : 16, tight ? 25 : 31)); };
      const rr = KN().clock({ cx, cy, R: Rr, n: Math.max(m, 1) }).r;
      // a chord between the inner edges of two positions: it stays inside the ring, clear of every other position
      const inner = (x) => KN().at(Math.max(m, 1), x - 1, cx, cy, Rr - rr - 3);
      const chord = (u, v, cls) => { if (u === v) return []; const A = inner(u), B = inner(v); return [{ key: 'pr' + u, kind: 'path', d: 'M' + A.x + ',' + A.y + ' L' + B.x + ',' + B.y, cls: 'nt-arc thin ' + (cls || ''), audit: 'edge-x', layer: 'back' }]; };
      const chords = (upto, cur) => pairs.slice(0, upto).flatMap(([u, v], i) => chord(u, v, i >= cur ? 'key' : 'faint'));
      const litOf = (upto, cur) => { const l = {}; pairs.slice(0, upto).forEach(([u, v], i) => { l[u] = l[v] = i >= cur ? (u === v ? 'good' : 'key') : u === v ? 'good' : 'act'; }); return l; };
      if (p === 2) {
        lines.push(['1·1 = 1', 'good'], ['1 + 1 = 2 ≡ 0 (mod 2)']);
        F.add({ items: head.concat(ring({ 1: 'good' }).items, panel()), say: 'GF(2) has just two elements, 0 and 1: addition is XOR (1 + 1 = 2 ≡ 0 (mod 2)) and multiplication is AND. The only nonzero element, 1, is its own inverse. This field is the bit; GF(2^8) is built on it.', meta: { phase: 'pairs' } });
      } else {
        F.add({ items: head.concat(ring({}).items, panel()), say: 'The ' + m + ' nonzero elements of ' + name + ' round a ring. Join each element x to its inverse, the y with x·y ≡ 1 (mod ' + p + ').', meta: { phase: 'start', lone: lone.length } });
        const stride = pairs.length > 8 ? Math.ceil(pairs.length / 6) : 1;
        for (let k = 0; k < pairs.length; k += stride) {
          const upto = Math.min(pairs.length, k + stride), now = pairs.slice(k, upto);
          F.set('pairs', upto);
          for (const [u, v] of now) lines.push([u + '·' + v + ' = ' + u * v + (u * v === 1 ? '' : ' ≡ 1'), 'key']);
          lines.forEach((l, i) => { if (i < lines.length - now.length) l[1] = ''; });
          const said = now.map(([u, v]) => u === v ? u + '·' + u + ' = ' + u * u + ' ≡ 1 (mod ' + p + '), so ' + u + ' is its own inverse' : u + '·' + v + ' = ' + u * v + ' ≡ 1 (mod ' + p + ')');
          F.add({ items: head.concat(chords(upto, k), ring(litOf(upto, k)).items, panel()), say: (now.length > 1 ? 'Pairs: ' : '') + said.join('; ') + '.', meta: { phase: 'pair', pairs: now } });
        }
        const lit = litOf(pairs.length, pairs.length); for (const x of lone) lit[x] = 'bad';
        const selfs = pairs.filter(([u, v]) => u === v).map(([u]) => u);
        lines.forEach((l) => { l[1] = ''; });
        if (prime) {
          lines.push(['self-inverse: ' + H.list(selfs), 'good']);
          F.add({ items: head.concat(chords(pairs.length, pairs.length), ring(lit).items, panel()), say: 'Every nonzero element has exactly one partner. Only ' + H.list(selfs) + (selfs.length > 1 ? ' are their own inverses' : ' is its own inverse') + ': x² ≡ 1 means p divides (x − 1)(x + 1), and a prime must divide one factor, so x ≡ ±1. ' + name + ' is a field.', meta: { phase: 'pairs' } });
        } else {
          lines.push(['no partner: ' + H.list(lone), 'bad']);
          F.add({ items: head.concat(chords(pairs.length, pairs.length), ring(lit).items, panel()), say: H.list(lone) + (lone.length > 1 ? ' have' : ' has') + ' no partner: each shares a factor with ' + p + ' (for example gcd(' + lone[0] + ', ' + p + ') = ' + NT().gcd(lone[0], p) + '), so no multiple of it is 1 more than a multiple of ' + p + '. ' + name + ' is a ring but not a field.', meta: { phase: 'pairs', lone } });
        }
      }
      // the four operations on a and b
      const a = mod(inp.a, p), b = mod(inp.b, p), sum = Number(Fp.add(a, b)), dif = Number(Fp.sub(a, b)), pro = Number(Fp.mul(a, b));
      const bi = invOf(b);
      lines.length = 0;
      lines.push(['a = ' + a + ', b = ' + b, 'strong'], [a + ' + ' + b + ' = ' + (a + b) + ' ≡ ' + sum + ' (mod ' + p + ')'], [a + ' − ' + b + ' = ' + n$(a - b) + ' ≡ ' + dif + ' (mod ' + p + ')'], [a + '·' + b + ' = ' + a * b + ' ≡ ' + pro + ' (mod ' + p + ')']);
      let say = 'With a = ' + a + ' and b = ' + b + ': ' + a + ' + ' + b + ' = ' + (a + b) + ' ≡ ' + sum + ' (mod ' + p + '); ' + a + ' − ' + b + ' = ' + n$(a - b) + ' ≡ ' + dif + ' (mod ' + p + '); ' + a + '·' + b + ' = ' + a * b + ' ≡ ' + pro + ' (mod ' + p + ').';
      let quo = null;
      if (bi !== null) {
        quo = Number(Fp.mul(a, bi));
        lines.push([b + '⁻¹ ≡ ' + bi + ' (mod ' + p + ')', 'key'], ['a / b = ' + a + '·' + bi + ' = ' + a * Number(bi) + ' ≡ ' + quo + ' (mod ' + p + ')', 'good']);
        say += ' To divide, multiply by the inverse: ' + b + '⁻¹ ≡ ' + bi + ' (mod ' + p + '), so a / b = ' + a + '·' + bi + ' = ' + a * Number(bi) + ' ≡ ' + quo + ' (mod ' + p + ').' + (prime && p > 2 ? ' Fermat gives the same inverse: ' + b + '^' + (p - 2) + ' ≡ ' + Fp.pow(b, p - 2) + ' (mod ' + p + ').' : '');
      } else {
        lines.push(['a / b: ' + b + ' has no inverse', 'bad']);
        say += ' Dividing by b = ' + b + ' is impossible: ' + (b === 0 ? 'nobody divides by 0' : 'gcd(' + b + ', ' + p + ') = ' + NT().gcd(b, p) + ', so ' + b + ' has no inverse modulo ' + p) + '.';
      }
      const lit2 = { [a]: 'act', [b]: 'key' };
      if (bi !== null && b !== 0) lit2[Number(bi)] = lit2[Number(bi)] || 'good';
      for (const x of lone) lit2[x] = lit2[x] || 'soft';
      F.add({ items: head.concat(pairs.flatMap(([u, v]) => chord(u, v, u === b || v === b ? 'key' : 'faint')), ring(lit2).items, panel(lines.length - 1)), say, meta: { phase: 'ops', sum, dif, pro, quo } });
      for (const f of F.list) f.narrowView = { x: -10, y: -32, w: 460, h: 480 };
      return { frames: F.list, def: { sections: [{ id: 'eq', kind: 'math', title: 'GF(p)', text: ['GF(p) = Z_p for a prime p', 'a / b = a·b⁻¹, b⁻¹ ≡ b^(p−2) (mod p)', 'x² ≡ 1 only for x ≡ ±1', 'Z_n is a field  ⇔  n is prime'].join('\n') }] } };
    },
    predict: [
      { at: (f) => f.meta && f.meta.phase === 'start', pick: 'option', ask: 'Will every nonzero element find a partner?', options: ['yes', 'no'], answer: (fr, i) => (fr[i].meta.lone ? 'no' : 'yes'), explain: (fr) => fr[fr.length - 2].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta && fr[i + 1].meta.phase === 'ops' && fr[i + 1].meta.quo !== null, pick: 'option', ask: (fr, i, inp) => 'What is a / b = ' + mod(inp.a, inp.p) + ' / ' + mod(inp.b, inp.p) + ' here?', options: (fr, i, inp) => { const q = fr[i + 1].meta.quo, P = inp.p; return [...new Set([q, (q + 1) % P, (q + P - 1) % P, Math.floor(mod(inp.a, P) / Math.max(1, mod(inp.b, P))) % P])].map(String); }, answer: (fr, i) => String(fr[i + 1].meta.quo), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'In GF(11), what is 3⁻¹?', options: ['4', '7', '8', '9'], answer: 0, why: '3·4 = 12 ≡ 1 (mod 11).' },
      { q: 'In GF(7), 2 / 3 = …', options: ['3', '4', '5', '6'], answer: 0, why: '3⁻¹ = 5 (3·5 = 15 ≡ 1), and 2·5 = 10 ≡ 3.' },
      { q: 'Which elements of GF(p) are their own inverses?', options: ['1 and p − 1', 'only 1', 'all the odd ones', 'none'], answer: 0, why: 'x² ≡ 1 means p divides (x − 1)(x + 1), so x ≡ 1 or x ≡ −1.' },
      { q: 'Why is Z_12 not a field?', options: ['some nonzero elements have no inverse', '12 is even', 'it has no 0', 'addition fails'], answer: 0, why: '2, 3, 4, 6, 8, 9 and 10 share a factor with 12, so none of them has an inverse.' },
      { q: 'By Fermat, b⁻¹ in GF(p) equals…', options: ['b^(p−2)', 'b^(p−1)', 'p − b', 'b^p'], answer: 0, why: 'b^(p−1) ≡ 1, so b·b^(p−2) ≡ 1.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Polynomials over GF(2)
  // ---------------------------------------------------------------------------------------------------------------
  const P = () => GF().poly;
  const bin = (v) => BigInt(v).toString(2);
  S.topic({
    id: 'gf2-poly', family: 'p02-fields', order: 20, title: 'Polynomials over GF(2)',
    blurb: 'A string of bits is a polynomial whose coefficients are 0 or 1: 1011 is x³ + x + 1. Coefficients add modulo 2, so adding polynomials is XOR, multiplying adds shifted copies without any carries, and dividing is long division where each subtraction is again an XOR.',
    inputs: [
      { id: 'a', kind: 'string', label: 'a (bits, highest first)', def: '1011', alphabet: '01', min: 1, max: 12, check: (v) => (!/1/.test(v) ? 'a: at least one 1' : null) },
      { id: 'b', kind: 'string', label: 'b', def: '110', alphabet: '01', min: 1, max: 9, check: (v) => (!/1/.test(v) ? 'b: at least one 1' : null) },
      { id: 'op', kind: 'choice', label: 'Operation', def: 'mul', options: [{ value: 'add', label: 'a + b' }, { value: 'mul', label: 'a · b' }, { value: 'div', label: 'a ÷ b' }] },
    ],
    presets: [
      { label: 'Multiply: (x³ + x + 1)(x² + x)', values: { a: '1011', b: '110', op: 'mul' } },
      { label: 'Add: x + x = 0', values: { a: '10110', b: '11011', op: 'add' } },
      { label: 'Divide by x² + x + 1', values: { a: '110101', b: '111', op: 'div' } },
      { label: 'A square: (x² + 1)² = x⁴ + 1', values: { a: '101', b: '101', op: 'mul' } },
      { label: 'Reduce by the AES modulus', values: { a: '101101110110', b: '100011011', op: 'div' } },
      { label: 'Divide exactly: x³ + 1 by x + 1', values: { a: '1001', b: '11', op: 'div' } },
    ],
    counters: [{ id: 'xors', label: 'XORs of rows' }],
    run(inp) {
      const a = BigInt('0b' + inp.a), b = BigInt('0b' + inp.b), op = inp.op;
      const F = new S.Frames(['xors']);
      const ps = P().str, deg = P().deg;
      const cw = 30, gap = 4, lx = 0, bx = 110;
      const width = op === 'mul' ? deg(a) + deg(b) + 1 : Math.max(deg(a), deg(b)) + 1;
      const X = (k) => bx + (width - 1 - k) * (cw + gap);
      const right = X(0) + cw + 24;
      const heads = () => { const it = [H.title('tt', lx, -32, op === 'add' ? 'Adding: coefficient by coefficient, mod 2' : op === 'mul' ? 'Multiplying: shifted copies, added without carries' : 'Long division: subtract (XOR) shifted copies of b')]; for (let k = 0; k < width; k++) it.push({ key: 'hx' + k, kind: 'text', x: X(k) + cw / 2, y: -8, text: k === 0 ? '1' : k === 1 ? 'x' : 'x' + H.sup(k), anchor: 'middle', size: 13, cls: 'ntlab' }); return it; };
      const row = (key, y, v, label, cls, polyText, opts = {}) => {
        const it = [{ key: key + ':l', kind: 'text', x: lx, y: y + 20, text: label, cls: 'strong', size: 15 }];
        const d = deg(v), lo = opts.lo || 0, hi = opts.hi === undefined ? Math.max(d, 0) : opts.hi;
        for (let k = lo; k <= hi; k++) {
          const bit = Number((v >> BigInt(k)) & 1n);
          it.push({ key: key + ':' + k, kind: 'cell', x: X(k), y, w: cw, h: 30, rx: 4, text: String(bit), size: 15, cls: 'bit ntc ' + (bit ? 'one' : 'zero') + ' ' + (typeof cls === 'function' ? cls(k, bit) || '' : cls || '') });
        }
        if (polyText !== false) it.push({ key: key + ':p', kind: 'text', x: right, y: y + 20, text: polyText || ps(v), cls: 'eq', size: 16 });
        return it;
      };
      const rule = (key, y) => ({ key, kind: 'line', x1: X(width - 1) - 4, y1: y, x2: X(0) + cw + 4, y2: y, cls: 'rule' });
      const def = { sections: [{ id: 'eq', kind: 'math', title: 'GF(2)[x]', text: ['a bit string b_k…b_1b_0 is Σ b_i·x^i', 'a + b = a ⊕ b (1 + 1 = 0)', 'a·b = ⊕ of x^i·a for each 1 bit b_i of b', 'a = q·b + r with deg r < deg b'].join('\n') }] };
      if (op === 'add') {
        const s = a ^ b;
        F.add({ items: heads().concat(row('ra', 0, a, 'a', 'act', null, { hi: width - 1 }), row('rb', 40, b, 'b', 'key', null, { hi: width - 1 })), say: 'a = ' + ps(a) + ' and b = ' + ps(b) + ', their coefficients lined up by power of x.', meta: { phase: 'rows' } });
        F.count('xors');
        F.add({ items: heads().concat(row('ra', 0, a, 'a', 'act', null, { hi: width - 1 }), row('rb', 40, b, 'b', 'key', null, { hi: width - 1 }), [rule('r1', 78)], row('rs', 86, s, 'a + b', (k) => (((a ^ b) >> BigInt(k)) & 1n ? 'good' : ((a & b) >> BigInt(k)) & 1n ? 'hot' : ''), null, { hi: width - 1 })), say: 'Add each column modulo 2: 1 + 1 = 2 ≡ 0 (mod 2), with nothing carried, so a + b is the XOR of the bit strings, ' + inp.a + '₂ ⊕ ' + inp.b + '₂ = ' + bin(s) + '₂, that is ' + ps(s) + '. Where both have a term (the amber columns) the terms cancel: x^k + x^k = 0. Subtraction is the same operation.', meta: { phase: 'sum', value: s.toString() } });
        return { frames: F.list, def };
      }
      if (op === 'mul') {
        const terms = [];
        for (let i = 0; i <= deg(b); i++) if ((b >> BigInt(i)) & 1n) terms.push(i);
        const base = () => row('ra', 0, a, 'a', 'act').concat(row('rb', 40, b, 'b', 'key'), [rule('r1', 78)]);
        F.add({ items: heads().concat(base()), say: 'Multiply a = ' + ps(a) + ' by b = ' + ps(b) + '. b has ' + H.plural(terms.length, 'term') + ', ' + H.list(terms.map((i) => (i === 0 ? '1' : i === 1 ? 'x' : 'x' + H.sup(i)))) + ': each contributes a copy of a, shifted up by its power.', meta: { phase: 'rows' } });
        let acc = 0n;
        const shown = [];
        terms.forEach((i, j) => {
          const sh = a << BigInt(i);
          acc ^= sh;
          shown.push([i, sh]);
          const it = heads().concat(base());
          shown.forEach(([ii, v], jj) => it.push(...row('sh' + ii, 86 + jj * 38, v, ii === 0 ? '1·a' : (ii === 1 ? 'x' : 'x' + H.sup(ii)) + '·a', jj === shown.length - 1 ? 'hot' : '', null, { lo: ii, hi: ii + deg(a) })));
          F.add({ items: it, say: 'The term ' + (i === 0 ? '1' : i === 1 ? 'x' : 'x' + H.sup(i)) + ' of b gives ' + (i === 0 ? 'a itself' : 'a shifted ' + H.plural(i, 'place') + ' left') + ': ' + ps(sh) + '.', meta: { phase: 'copy', i } });
        });
        const prod = P().mul(a, b), yS = 86 + shown.length * 38 + 8;
        F.set('xors', Math.max(0, terms.length - 1));
        const it = heads().concat(base());
        shown.forEach(([ii, v], jj) => it.push(...row('sh' + ii, 86 + jj * 38, v, ii === 0 ? '1·a' : (ii === 1 ? 'x' : 'x' + H.sup(ii)) + '·a', '', null, { lo: ii, hi: ii + deg(a) })));
        const colCount = (k) => shown.filter(([, v]) => (v >> BigInt(k)) & 1n).length;
        it.push(rule('r2', yS - 4), ...row('rp', yS + 4, prod, 'a·b', (k) => (colCount(k) > 1 ? ((prod >> BigInt(k)) & 1n ? 'good' : 'hot') : (prod >> BigInt(k)) & 1n ? 'good' : ''), null, { hi: width - 1 }));
        const cancel = [...Array(width).keys()].filter((k) => colCount(k) > 1 && !((prod >> BigInt(k)) & 1n));
        F.add({ items: it, say: 'XOR the copies column by column: a·b = ' + ps(prod) + ', or ' + bin(prod) + '₂.' + (cancel.length ? ' In the amber column' + (cancel.length > 1 ? 's' : '') + ' an even number of copies have a 1, and they cancel.' : ' No column has two 1s, so nothing cancels.') + ' As whole numbers ' + a + '·' + b + ' = ' + a * b + ' = ' + bin(a * b) + '₂, which differs' + (a * b === prod ? ' nowhere here' : '') + ': ordinary multiplication carries, this does not.', meta: { phase: 'product', value: prod.toString() } });
        return { frames: F.list, def };
      }
      // division
      const db = deg(b);
      const res = P().divmod(a, b);
      const steps = res.trace;
      const qRow = (q, upto) => row('rq', 0, q, 'q', (k) => (k === upto ? 'hot' : 'act'), q ? null : '0', { lo: 0, hi: Math.max(0, deg(a) - db) });
      const dRow = () => row('rb', 40, b, 'b', 'key');
      F.add({ items: heads().concat(qRow(0n), dRow(), row('rr', 96, a, 'r = a', 'act')), say: 'Divide a = ' + ps(a) + ' by b = ' + ps(b) + '. Start with the remainder r = a; while its degree is at least ' + db + ', cancel its leading term with a shifted copy of b.', meta: { phase: 'start' } });
      let q = 0n;
      steps.forEach((st, j) => {
        q |= 1n << BigInt(st.k);
        F.count('xors');
        const it = heads().concat(qRow(q, st.k), dRow(), row('rr', 96, st.r, 'r', 'act'), row('rs', 134, st.sub, (st.k === 0 ? '' : st.k === 1 ? 'x·' : 'x' + H.sup(st.k) + '·') + 'b', 'key', null, { lo: st.k, hi: st.k + db }), [rule('r2', 172)], row('rn', 180, st.next, 'new r', (k) => (k === deg(st.r) ? 'hot' : ''), st.next ? null : '0', { hi: deg(st.r) }));
        F.add({ items: it, say: 'The leading term of r is x' + H.sup(deg(st.r)) + '; x' + H.sup(deg(st.r)) + ' ÷ x' + H.sup(db) + ' = ' + (st.k === 0 ? '1' : st.k === 1 ? 'x' : 'x' + H.sup(st.k)) + ', so add ' + (st.k === 0 ? '1' : st.k === 1 ? 'x' : 'x' + H.sup(st.k)) + ' to the quotient and XOR ' + ps(st.sub) + ' into r: ' + bin(st.r) + '₂ ⊕ ' + bin(st.sub).padStart(bin(st.r).length, '0') + '₂ = ' + bin(st.next).padStart(bin(st.r).length, '0') + '₂.', meta: { phase: 'step', k: st.k, next: st.next.toString() } });
      });
      F.add({ items: heads().concat(qRow(res.q, -1), dRow(), row('rr', 96, res.r, 'r', 'good', res.r ? null : '0', { hi: Math.max(0, db - 1) })), say: 'deg r < deg b = ' + db + ', so the division stops: q = ' + ps(res.q) + ' and r = ' + ps(res.r) + (res.r === 0n ? ': b divides a exactly.' : '.') + ' Check: q·b + r = ' + ps(P().mul(res.q, b) ^ res.r) + ' = a.', meta: { phase: 'done', q: res.q.toString(), r: res.r.toString() } });
      return { frames: F.list, def };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta && fr[i + 1].meta.phase === 'product', pick: 'option', ask: 'What is a·b, as bits?', options: (fr, i) => { const v = BigInt(fr[i + 1].meta.value); return [...new Set([v, v ^ 2n, v ^ 4n, v ^ 1n].map((x) => bin(x)))]; }, answer: (fr, i) => bin(BigInt(fr[i + 1].meta.value)), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta && fr[i + 1].meta.phase === 'sum', pick: 'option', ask: 'What is a + b, as bits?', options: (fr, i, inp) => { const v = BigInt('0b' + inp.a) ^ BigInt('0b' + inp.b), w = BigInt('0b' + inp.a) | BigInt('0b' + inp.b); return [...new Set([v, w, BigInt('0b' + inp.a) + BigInt('0b' + inp.b)].map(bin))]; }, answer: (fr, i) => bin(BigInt(fr[i + 1].meta.value)), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta && f.meta.phase === 'start' && fr[i + 1] && fr[i + 1].meta.phase === 'step', pick: 'option', ask: 'What is the first term of the quotient?', options: (fr, i) => { const k = fr[i + 1].meta.k; return [...new Set([k, k + 1, Math.max(0, k - 1), k + 2])].map((j) => (j === 0 ? '1' : j === 1 ? 'x' : 'x' + H.sup(j))); }, answer: (fr, i) => { const k = fr[i + 1].meta.k; return k === 0 ? '1' : k === 1 ? 'x' : 'x' + H.sup(k); }, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Over GF(2), (x + 1) + (x² + x) = …', options: ['x² + 1', 'x² + 2x + 1', 'x²', 'x² + x + 1'], answer: 0, why: 'x + x = 2x = 0: the x terms cancel.' },
      { q: 'Over GF(2), (x + 1)² = …', options: ['x² + 1', 'x² + 2x + 1', 'x² + x + 1', 'x²'], answer: 0, why: '(x + 1)(x + 1) = x² + x + x + 1, and x + x = 0.' },
      { q: 'Which bit string is x⁴ + x + 1?', options: ['10011', '11001', '10101', '1011'], answer: 0, why: 'Bits from x⁴ down to x⁰: 1, 0, 0, 1, 1.' },
      { q: 'Multiplying by x shifts the bits…', options: ['one place left', 'one place right', 'not at all', 'and XORs them'], answer: 0, why: 'Every power of x goes up by one.' },
      { q: 'Why do polynomials over GF(2) suit computers?', options: ['addition is XOR, with no carries', 'they are faster to type', 'they have no zero', 'they are always prime'], answer: 0, why: 'No carry runs from one column into the next.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
