// Number theory on BigInt: the ring Z_n, Euclid and extended Euclid as tables, inverses, Euler's φ with the coprime
// grid, powers and their cycles, the order of an element, generators and primitive roots, cyclic subgroups and
// Lagrange, the Chinese remainder theorem, integer roots, continued fractions, factoring of small numbers, and the
// random source every public-key engine draws from. Every argument may be a number or a BigInt; results are BigInt.
//   S.NT.mod(a, n) / pow(b, e, n) / gcd(a, b) / inv(a, n) / bitLength(n) / isqrt(n) / iroot(n, k)
//   S.NT.euclid(a, b) -> {g, rows: [{a, b, q, r}], trace}
//   S.NT.egcd(a, b) -> {g, x, y, rows: [{i, r, q, s, t}], trace}          g = a·x + b·y
//   S.NT.inverse(a, n) -> {inv, egcd, trace}                              (inv null when gcd ≠ 1)
//   S.NT.ring(n) -> {n, add, mul, neg, inv, table(op), units}             Z_n with its tables
//   S.NT.phi(n) -> {phi, factors, trace};  S.NT.coprimeGrid(n) -> {cells: [{k, g, unit}], phi}
//   S.NT.powers(a, n) -> {seq, tail, cycle, trace}                        a, a², a³, … until it repeats
//   S.NT.order(a, n[, factorsOfGroupOrder]) -> {order, trace}
//   S.NT.isGenerator(g, p[, factorsOfPm1]) -> {ok, trace};  S.NT.primitiveRoots(n) -> [g…]
//   S.NT.subgroup(a, n) -> {elements, order};  S.NT.lagrange(n) -> {groupOrder, subgroups, cosets(a), trace}
//   S.NT.crt([r…], [m…]) -> {x, M, rows: [{r, m, Mi, yi, term}], trace}  constructive, for pairwise coprime moduli
//   S.NT.crtGeneral([r…], [m…]) -> {x, M} or null                         any moduli, merging pair by pair
//   S.NT.factor(n) -> Map prime → exponent;  S.NT.contfrac(a, b) -> {terms, convergents}
//   S.NT.setRandom(bytesFn) / seededRandom(seed) / randomBytes(k) / randomBits(bits) / randBelow(n) / randRange(lo, hi)
(function (S) {
  'use strict';
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const N = (S.NT = S.NT || {});
  N.step = step;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  N.big = B;
  /** a value short enough for a sentence: long numbers keep their ends and say how many digits they have */
  N.short = (v) => { const s = B(v).toString(); return s.length > 24 ? s.slice(0, 10) + '…' + s.slice(-10) + ' (' + s.length + ' digits)' : s; };
  const sh = N.short;

  N.mod = (a, n) => { a = B(a); n = B(n); const r = a % n; return r < 0n ? r + n : r; };
  N.abs = (a) => (a < 0n ? -a : a);
  N.bitLength = (n) => { n = B(n); if (n < 0n) n = -n; return n === 0n ? 0 : n.toString(2).length; };
  N.pow = (b, e, n) => {
    b = B(b); e = B(e); n = B(n);
    if (n === 1n) return 0n;
    if (e < 0n) { b = N.inv(b, n); e = -e; }
    let r = 1n; b = N.mod(b, n);
    if (e < 0x10000000000000000n) { while (e > 0n) { if (e & 1n) r = (r * b) % n; b = (b * b) % n; e >>= 1n; } return r; }
    // long exponents: a sliding window of up to 5 bits over the odd powers b, b³, …, b³¹ (about a fifth fewer
    // multiplications than bit by bit; the value is the same)
    const bits = e.toString(2), L = bits.length, b2 = (b * b) % n, odd = [b];
    for (let k = 1; k < 16; k++) odd.push((odd[k - 1] * b2) % n);
    for (let i = 0; i < L;) {
      if (bits[i] === '0') { r = (r * r) % n; i++; continue; }
      let end = Math.min(i + 5, L);
      while (bits[end - 1] === '0') end--;
      for (let k = i; k < end; k++) r = (r * r) % n;
      r = (r * odd[(parseInt(bits.slice(i, end), 2) - 1) >> 1]) % n;
      i = end;
    }
    return r;
  };
  N.gcd = (a, b) => { a = N.abs(B(a)); b = N.abs(B(b)); while (b) [a, b] = [b, a % b]; return a; };
  N.lcm = (a, b) => { a = B(a); b = B(b); return a && b ? N.abs(a / N.gcd(a, b) * b) : 0n; };
  N.inv = (a, n) => {
    a = N.mod(a, n); n = B(n);
    let [r0, r1, s0, s1] = [a, n, 1n, 0n];
    while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
    if (r0 !== 1n) throw new Error(`${sh(a)} has no inverse modulo ${sh(n)}: they share the factor ${sh(r0)}`);
    return N.mod(s0, n);
  };

  /** the Euclidean algorithm: each row divides a by b, and the next row moves b and the remainder up */
  N.euclid = (a, b) => {
    a = N.abs(B(a)); b = N.abs(B(b));
    const rows = [], trace = [];
    trace.push(step('start', `Find gcd(${sh(a)}, ${sh(b)}) by dividing again and again.`, { a, b }));
    while (b) {
      const q = a / b, r = a % b;
      rows.push({ a, b, q, r });
      trace.push(step('row', `${sh(a)} = ${sh(q)}·${sh(b)} + ${sh(r)}.`, { a, b, q, r, row: rows.length - 1 }));
      [a, b] = [b, r];
    }
    trace.push(step('done', `The remainder is 0, so the gcd is the last divisor, ${sh(a)}.`, { g: a }));
    return { g: a, rows, trace };
  };

  /** the extended Euclidean algorithm as a table: row i holds r_i = a·s_i + b·t_i and the quotient q_i */
  N.egcd = (a, b) => {
    a = B(a); b = B(b);
    const rows = [{ i: 0, r: a, q: null, s: 1n, t: 0n }, { i: 1, r: b, q: null, s: 0n, t: 1n }], trace = [];
    trace.push(step('start', `Rows 0 and 1: ${sh(a)} = ${sh(a)}·1 + ${sh(b)}·0 and ${sh(b)} = ${sh(a)}·0 + ${sh(b)}·1.`, { a, b, row: 1 }));
    while (rows[rows.length - 1].r !== 0n) {
      const p = rows[rows.length - 2], c = rows[rows.length - 1];
      const q = p.r / c.r;
      c.q = q;
      const nr = { i: rows.length, r: p.r - q * c.r, q: null, s: p.s - q * c.s, t: p.t - q * c.t };
      rows.push(nr);
      trace.push(step('row', `q = ${sh(p.r)} div ${sh(c.r)} = ${sh(q)}; row ${nr.i} = row ${nr.i - 2} − ${sh(q)}·row ${nr.i - 1}: r = ${sh(nr.r)}, s = ${sh(nr.s)}, t = ${sh(nr.t)}.`, { row: nr.i, q, r: nr.r, s: nr.s, t: nr.t }));
    }
    let { r: g, s: x, t: y } = rows[rows.length - 2];
    if (g < 0n) { g = -g; x = -x; y = -y; }
    trace.push(step('done', `The last non-zero remainder is ${sh(g)}, and ${sh(g)} = ${sh(a)}·(${sh(x)}) + ${sh(b)}·(${sh(y)}).`, { g, x, y }));
    return { g, x, y, rows, trace };
  };

  /** the inverse of a modulo n read off the extended Euclidean table */
  N.inverse = (a, n) => {
    a = B(a); n = B(n);
    const e = N.egcd(N.mod(a, n), n), trace = e.trace.slice();
    if (e.g !== 1n) {
      trace.push(step('none', `gcd(${sh(a)}, ${sh(n)}) = ${sh(e.g)} ≠ 1, so ${sh(a)} has no inverse modulo ${sh(n)}.`, { g: e.g }));
      return { inv: null, egcd: e, trace };
    }
    const inv = N.mod(e.x, n);
    trace.push(step('inverse', `${sh(a)}·${sh(e.x)} ≡ 1 (mod ${sh(n)}), so ${sh(a)}⁻¹ = ${sh(inv)}${e.x < 0n ? ` (${sh(e.x)} + ${sh(n)})` : ''}.`, { inv }));
    return { inv, egcd: e, trace };
  };

  /** Z_n: addition and multiplication tables, negatives, inverses and the units */
  N.ring = (n) => {
    n = B(n);
    const R = { n };
    R.add = (a, b) => N.mod(B(a) + B(b), n);
    R.sub = (a, b) => N.mod(B(a) - B(b), n);
    R.mul = (a, b) => N.mod(B(a) * B(b), n);
    R.neg = (a) => N.mod(-B(a), n);
    R.inv = (a) => (N.gcd(a, n) === 1n ? N.inv(a, n) : null);
    R.pow = (a, e) => N.pow(a, e, n);
    R.elements = () => { const out = []; for (let k = 0n; k < n; k++) out.push(k); return out; };
    R.units = () => R.elements().filter((k) => N.gcd(k, n) === 1n);
    R.zeroDivisors = () => R.elements().filter((k) => k && N.gcd(k, n) !== 1n);
    /** the full table of '+' or '·' (small n only) */
    R.table = (op) => R.elements().map((a) => R.elements().map((b) => (op === '+' ? R.add(a, b) : R.mul(a, b))));
    R.isField = () => N.factor(n).size === 1 && [...N.factor(n).values()][0] === 1;
    return R;
  };

  /** the prime factors of n by trial division, then Pollard's rho with Brent's cycle finding for what is left */
  N.factor = (n) => {
    n = N.abs(B(n));
    const out = new Map(), add = (p, k = 1) => out.set(p, (out.get(p) || 0) + k);
    if (n < 2n) return out;
    for (const p of [2n, 3n, 5n]) while (n % p === 0n) { add(p); n /= p; }
    for (let p = 7n, i = 0, inc = [4n, 2n, 4n, 2n, 4n, 6n, 2n, 6n]; p * p <= n && p < 50000n; p += inc[i++ & 7]) while (n % p === 0n) { add(p); n /= p; }
    const split = (m) => {
      if (m === 1n) return;
      if (N.isProbablePrime ? N.isProbablePrime(m) : N.isPrimeSmall(m)) { add(m); return; }
      const r = N.rho(m);
      split(r); split(m / r);
    };
    split(n);
    return new Map([...out.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)));
  };
  N.isPrimeSmall = (n) => { n = B(n); if (n < 2n) return false; for (let p = 2n; p * p <= n; p++) if (n % p === 0n) return false; return true; };
  /** one non-trivial factor of a composite m (Pollard's rho, Brent's variant) */
  N.rho = (m) => {
    m = B(m);
    if (m % 2n === 0n) return 2n;
    for (let c = 1n; ; c++) {
      let y = 2n, r = 1, q = 1n, g = 1n, x = 0n, ys = 0n;
      const f = (v) => (v * v + c) % m;
      while (g === 1n) {
        x = y;
        for (let i = 0; i < r; i++) y = f(y);
        for (let k = 0; k < r && g === 1n; k += 128) {
          ys = y;
          for (let i = 0; i < Math.min(128, r - k); i++) { y = f(y); q = (q * N.abs(x - y)) % m; }
          g = N.gcd(q, m);
        }
        r *= 2;
      }
      if (g === m) { do { ys = f(ys); g = N.gcd(N.abs(x - ys), m); } while (g === 1n); }
      if (g !== m) return g;
    }
  };
  N.divisors = (n) => {
    let ds = [1n];
    for (const [p, k] of N.factor(n)) { const next = []; for (const d of ds) { let pp = 1n; for (let i = 0; i <= k; i++) { next.push(d * pp); pp *= p; } } ds = next; }
    return ds.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  };
  const fmtFactors = (f) => [...f].map(([p, k]) => (k > 1 ? `${sh(p)}^${k}` : sh(p))).join('·') || '1';
  N.fmtFactors = fmtFactors;

  /** Euler's φ from the factorisation: φ(n) = n·Π(1 − 1/p) */
  N.phi = (n, factors) => {
    n = B(n);
    const f = factors || N.factor(n), trace = [];
    trace.push(step('factor', `${sh(n)} = ${fmtFactors(f)}.`, { n, factors: [...f] }));
    let phi = 1n;
    for (const [p, k] of f) {
      const part = (p - 1n) * p ** BigInt(k - 1);
      phi *= part;
      trace.push(step('part', k > 1 ? `φ(${sh(p)}^${k}) = ${sh(p)}^${k - 1}·(${sh(p)} − 1) = ${sh(part)}.` : `φ(${sh(p)}) = ${sh(p)} − 1 = ${sh(part)}.`, { p, k, part }));
    }
    if (n === 1n) phi = 1n;
    trace.push(step('done', `φ(${sh(n)}) = ${sh(phi)}: that many numbers below ${sh(n)} share no factor with it.`, { phi }));
    return { phi, factors: f, trace };
  };
  /** the coprime grid: every k from 1 to n with gcd(k, n), lit when it is 1 */
  N.coprimeGrid = (n) => {
    n = Number(n);
    const cells = [];
    for (let k = 1; k <= n; k++) { const g = Number(N.gcd(k, n)); cells.push({ k, g, unit: g === 1 }); }
    return { n, cells, phi: cells.filter((c) => c.unit).length };
  };
  /** Carmichael's λ(n), the exponent of the group of units */
  N.lambda = (n) => {
    let l = 1n;
    for (const [p, k] of N.factor(n)) { let v = (p - 1n) * p ** BigInt(k - 1); if (p === 2n && k >= 3) v /= 2n; l = N.lcm(l, v); }
    return l;
  };

  /** a, a², a³, … modulo n until a value repeats: the tail before the cycle and the cycle itself */
  N.powers = (a, n, limit = 100000) => {
    a = N.mod(a, n); n = B(n);
    const seen = new Map(), seq = [], trace = [];
    let v = a;
    for (let k = 1; k <= limit; k++) {
      const key = v.toString();
      if (seen.has(key)) {
        const start = seen.get(key);
        const tail = seq.slice(0, start - 1), cycle = seq.slice(start - 1);
        trace.push(step('repeat', `${sh(a)}^${k} ≡ ${sh(v)} again (first seen at power ${start}): the powers cycle with length ${cycle.length}${tail.length ? ` after a tail of ${tail.length}` : ''}.`, { k, start, cycleLength: cycle.length }));
        return { seq, tail, cycle, trace };
      }
      seen.set(key, k); seq.push(v);
      trace.push(step('power', `${sh(a)}^${k} ≡ ${sh(v)} (mod ${sh(n)}).`, { k, value: v }));
      v = (v * a) % n;
    }
    return { seq, tail: [], cycle: null, trace };
  };

  /** the order of a in Z_n*: start from the group order and strip each prime factor while the power stays 1 */
  N.order = (a, n, groupFactors) => {
    a = N.mod(a, n); n = B(n);
    const trace = [];
    if (N.gcd(a, n) !== 1n) { trace.push(step('none', `${sh(a)} is not a unit modulo ${sh(n)}, so it has no order.`)); return { order: null, trace }; }
    let ord, f;
    if (groupFactors) { f = new Map([...groupFactors].map(([p, k]) => [B(p), k])); ord = [...f].reduce((x, [p, k]) => x * p ** BigInt(k), 1n); }
    else { const ph = N.phi(n); ord = ph.phi; f = N.factor(ord); }
    trace.push(step('start', `The group has order ${sh(ord)} = ${fmtFactors(f)}, so ord(${sh(a)}) divides it.`, { groupOrder: ord }));
    for (const [p] of f) {
      while (ord % p === 0n && N.pow(a, ord / p, n) === 1n) {
        trace.push(step('strip', `${sh(a)}^${sh(ord / p)} ≡ 1, so the order divides ${sh(ord / p)}.`, { p, now: ord / p }));
        ord /= p;
      }
      if (ord % p === 0n) trace.push(step('keep', `${sh(a)}^${sh(ord / p)} ≢ 1, so the factor ${sh(p)} stays.`, { p }));
    }
    trace.push(step('done', `ord(${sh(a)}) = ${sh(ord)}.`, { order: ord }));
    return { order: ord, trace };
  };
  /** g generates Z_p* (p prime) exactly when g^((p−1)/q) ≠ 1 for every prime q dividing p − 1 */
  N.isGenerator = (g, p, factorsOfPm1) => {
    g = N.mod(g, p); p = B(p);
    const f = factorsOfPm1 ? new Map([...factorsOfPm1].map(([q, k]) => [B(q), k])) : N.factor(p - 1n), trace = [];
    trace.push(step('start', `p − 1 = ${fmtFactors(f)}; test ${sh(g)}^((p−1)/q) for each prime q.`));
    let ok = g !== 0n;
    for (const [q] of f) {
      const v = N.pow(g, (p - 1n) / q, p);
      trace.push(step('test', `${sh(g)}^(${sh((p - 1n) / q)}) ≡ ${sh(v)}${v === 1n ? ': it is 1, so the order divides (p−1)/' + sh(q) + '.' : '.'}`, { q, value: v, one: v === 1n }));
      if (v === 1n) { ok = false; break; }
    }
    trace.push(step('done', ok ? `${sh(g)} is a generator of Z_${sh(p)}*.` : `${sh(g)} is not a generator.`, { ok }));
    return { ok, trace };
  };
  /** every primitive root modulo a small n (an empty list when Z_n* is not cyclic) */
  N.primitiveRoots = (n) => {
    n = B(n);
    const ph = N.phi(n).phi, f = N.factor(ph), out = [];
    if (n === 2n) return [1n];
    for (let g = 1n; g < n; g++) {
      if (N.gcd(g, n) !== 1n) continue;
      let ok = true;
      for (const [q] of f) if (N.pow(g, ph / q, n) === 1n) { ok = false; break; }
      if (ok) out.push(g);
    }
    return out;
  };
  /** the cyclic subgroup ⟨a⟩ of Z_n* */
  N.subgroup = (a, n) => {
    a = N.mod(a, n); n = B(n);
    const elements = [1n];
    for (let v = a; v !== 1n; v = (v * a) % n) { elements.push(v); if (elements.length > 1e6) throw new Error('subgroup too large'); }
    return { generator: a, elements, order: BigInt(elements.length) };
  };
  /** every subgroup of Z_n* for a small n, grouped by order, with Lagrange's check and the cosets of any one */
  N.lagrange = (n) => {
    n = B(n);
    const units = N.ring(n).units(), G = BigInt(units.length), byKey = new Map(), trace = [];
    trace.push(step('group', `Z_${n}* has ${G} elements.`, { groupOrder: G }));
    // cyclic subgroups, then closures of pairs, cover every subgroup of these small groups
    const close = (gens) => {
      const set = new Set(['1']), q = [1n];
      while (q.length) { const x = q.pop(); for (const g of gens) { const y = (x * g) % n; if (!set.has(y.toString())) { set.add(y.toString()); q.push(y); } } }
      return [...set].map(BigInt).sort((a, b) => (a < b ? -1 : 1));
    };
    const addSub = (els) => { const k = els.join(','); if (!byKey.has(k)) byKey.set(k, els); };
    for (const a of units) addSub(close([a]));
    // joins of subgroups found so far, until nothing new appears
    for (let grew = true; grew;) {
      grew = false;
      const cur = [...byKey.values()];
      for (let i = 0; i < cur.length; i++) for (let j = i + 1; j < cur.length; j++) { const before = byKey.size; addSub(close(cur[i].concat(cur[j]))); if (byKey.size > before) grew = true; }
    }
    const subgroups = [...byKey.values()].sort((a, b) => a.length - b.length).map((els) => ({ elements: els, order: BigInt(els.length), divides: G % BigInt(els.length) === 0n, cyclic: els.some((g) => close([g]).length === els.length) }));
    for (const s of subgroups) trace.push(step('subgroup', `{${s.elements.join(', ')}} has order ${s.order}, which divides ${G}.`, { elements: s.elements, order: s.order }));
    const cosets = (H) => {
      const seen = new Set(), out = [];
      for (const a of units) if (!seen.has(a.toString())) { const c = H.map((h) => (a * h) % n).sort((x, y) => (x < y ? -1 : 1)); c.forEach((v) => seen.add(v.toString())); out.push({ rep: a, elements: c }); }
      return out;
    };
    return { n, units, groupOrder: G, subgroups, cosets, trace };
  };

  /** the Chinese remainder theorem, constructively: x = Σ r_i·M_i·(M_i⁻¹ mod m_i) mod M */
  N.crt = (rs, ms) => {
    rs = rs.map(B); ms = ms.map(B);
    const trace = [];
    for (let i = 0; i < ms.length; i++) for (let j = i + 1; j < ms.length; j++) if (N.gcd(ms[i], ms[j]) !== 1n) throw new Error(`the moduli ${sh(ms[i])} and ${sh(ms[j])} share a factor`);
    const M = ms.reduce((a, b) => a * b, 1n);
    trace.push(step('start', `Solve ${rs.map((r, i) => `x ≡ ${sh(r)} (mod ${sh(ms[i])})`).join(', ')}. M = ${sh(M)}.`, { M }));
    let x = 0n;
    const rows = rs.map((r, i) => {
      const Mi = M / ms[i], yi = N.inv(Mi, ms[i]), term = N.mod(r, ms[i]) * Mi * yi;
      x += term;
      trace.push(step('term', `M${i + 1} = M / ${sh(ms[i])} = ${sh(Mi)}; its inverse mod ${sh(ms[i])} is ${sh(yi)}; the term is ${sh(r)}·${sh(Mi)}·${sh(yi)} = ${sh(term)}.`, { i, r, m: ms[i], Mi, yi, term }));
      return { r, m: ms[i], Mi, yi, term };
    });
    x = N.mod(x, M);
    trace.push(step('done', `x = (sum of the terms) mod ${sh(M)} = ${sh(x)}.`, { x }));
    return { x, M, rows, trace };
  };
  /** CRT for moduli that need not be coprime: null when the congruences disagree */
  N.crtGeneral = (rs, ms) => {
    let x = 0n, M = 1n;
    for (let i = 0; i < rs.length; i++) {
      const r = N.mod(rs[i], ms[i]), m = B(ms[i]), g = N.gcd(M, m);
      if ((r - x) % g !== 0n) return null;
      const k = N.mod(((r - x) / g) * N.inv(M / g, m / g), m / g);
      x += M * k; M = M / g * m; x = N.mod(x, M);
    }
    return { x, M };
  };

  /** ⌊√n⌋ */
  N.isqrt = (n) => {
    n = B(n);
    if (n < 0n) throw new Error('negative');
    if (n < 2n) return n;
    let x = 1n << BigInt(Math.ceil(N.bitLength(n) / 2));
    for (;;) { const y = (x + n / x) >> 1n; if (y >= x) return x; x = y; }
  };
  /** ⌊n^(1/k)⌋ and whether it is exact */
  N.iroot = (n, k) => {
    n = B(n); k = B(k);
    if (n < 2n) return { root: n, exact: true };
    let x = 1n << (BigInt(N.bitLength(n)) / k + 1n);
    for (;;) { const y = ((k - 1n) * x + n / x ** (k - 1n)) / k; if (y >= x) break; x = y; }
    while (x ** k > n) x--;
    while ((x + 1n) ** k <= n) x++;
    return { root: x, exact: x ** k === n };
  };
  N.isSquare = (n) => { const r = N.isqrt(n); return r * r === B(n); };

  /** the continued fraction of a/b and its convergents h/k */
  N.contfrac = (a, b) => {
    a = B(a); b = B(b);
    const terms = [], convergents = [];
    let [h0, h1, k0, k1] = [0n, 1n, 1n, 0n];
    while (b) {
      const q = a / b;
      terms.push(q);
      [h0, h1] = [h1, q * h1 + h0]; [k0, k1] = [k1, q * k1 + k0];
      convergents.push({ h: h1, k: k1 });
      [a, b] = [b, a - q * b];
    }
    return { terms, convergents };
  };

  // ---- randomness: one replaceable source of bytes, so labs can be seeded and tests can use node's generator
  let source = null;
  const defaultBytes = (k) => {
    const out = new Uint8Array(k), c = globalThis.crypto;
    if (c && c.getRandomValues) { for (let i = 0; i < k; i += 65536) c.getRandomValues(out.subarray(i, Math.min(k, i + 65536))); }
    else for (let i = 0; i < k; i++) out[i] = (Math.random() * 256) | 0;
    return out;
  };
  /** replace the random source with fn(k) -> Uint8Array(k); null restores the default; returns the old one */
  N.setRandom = (fn) => { const old = source; source = fn || null; return old; };
  /** a reproducible source for a lab's story (not for real keys) */
  N.seededRandom = (seed) => {
    let s = (Number(seed) >>> 0) || 1;
    return (k) => { const out = new Uint8Array(k); for (let i = 0; i < k; i++) { s = (s + 0x6d2b79f5) >>> 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t ^= t + Math.imul(t ^ (t >>> 7), 61 | t); out[i] = (t ^ (t >>> 14)) >>> 24; } return out; };
  };
  N.randomBytes = (k) => (source || defaultBytes)(k);
  /** a random BigInt of at most `bits` bits */
  N.randomBits = (bits) => {
    bits = Number(bits);
    const k = Math.ceil(bits / 8), b = N.randomBytes(k);
    let v = 0n;
    for (const x of b) v = (v << 8n) | BigInt(x);
    return v >> BigInt(k * 8 - bits);
  };
  /** uniform in [0, n) by rejection */
  N.randBelow = (n) => {
    n = B(n);
    if (n <= 0n) throw new Error('empty range');
    const bits = N.bitLength(n - 1n) || 1;
    for (;;) { const v = N.randomBits(bits); if (v < n) return v; }
  };
  /** uniform in [lo, hi] */
  N.randRange = (lo, hi) => B(lo) + N.randBelow(B(hi) - B(lo) + 1n);

  // ---- bytes and integers (big-endian), as the standards convert them
  N.toBytes = (v, len) => {
    v = B(v);
    let h = v.toString(16);
    if (h.length % 2) h = '0' + h;
    if (len == null) len = h.length / 2;
    if (h.length / 2 > len) throw new Error('integer too large');
    h = h.padStart(len * 2, '0');
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = parseInt(h.substr(2 * i, 2), 16);
    return out;
  };
  N.fromBytes = (b) => { let v = 0n; for (const x of b) v = (v << 8n) | BigInt(x); return v; };
  N.byteLength = (n) => Math.ceil(N.bitLength(n) / 8);
})(globalThis.Sifer = globalThis.Sifer || {});
