// Claim checks for part 2: testing for primes, groups and the Chinese remainder theorem. Each entry: {random(rnd)
// -> input values, extra: [values], check(ctx)}; every value is worked out again here with tests/claims-lib-p02.mjs.
import { md, gcd, pw, inv, phi, factors, isPrime } from './claims-lib-p02.mjs';

const ri = (rnd, lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));
const N = (x) => BigInt(x);
const nums = (s) => (s.match(/−?\d+/g) || []).map((x) => N(x.replace('−', '-')));
const item = (f, key) => f.items.find((x) => x.key === key);
const sayOf = (f) => f.say || '';
const odd = (rnd, lo, hi) => { const v = ri(rnd, lo, hi); return v % 2 ? v : v + 1; };

/** the Miller–Rabin chain of one base, written out here */
const chain = (n, a) => {
  let d = n - 1n, s = 0;
  while (!(d & 1n)) { d >>= 1n; s++; }
  const xs = [pw(a, d, n)];
  let verdict = xs[0] === 1n || xs[0] === n - 1n ? 'pass' : null;
  for (let j = 1; j < s && !verdict; j++) { const x = (xs[j - 1] * xs[j - 1]) % n; xs.push(x); if (x === n - 1n) verdict = 'pass'; else if (x === 1n) verdict = 'fail'; }
  return { xs, verdict: verdict || 'fail', s, d };
};
/** the order of a unit a modulo n, by stepping */
const ord = (a, n) => { let k = 1, v = md(a, n); while (v !== 1n) { v = (v * a) % n; k++; if (k > 100000) return null; } return k; };

export default {
  carmichael: {
    random: (rnd) => ({ n: odd(rnd, 5, 2001) }),
    extra: [{ n: 5 }, { n: 2001 }, { n: 2465 }, { n: 1999 }],
    mayRefuse: true,
    check({ input, frames, ok }) {
      const n = N(input.n), prime = isPrime(n);
      const kind = (a) => (gcd(a, n) !== 1n ? 'fac' : pw(a, n - 1n, n) === 1n ? 'pass' : 'wit');
      let W = 0, L = 0, Fc = 0;
      for (let a = 1n; a < n; a++) { const k = kind(a); if (k === 'wit') W++; else if (k === 'pass') L++; else Fc++; }
      const look = { fac: '5', wit: '3', pass: prime ? '7' : '6' }, cls = { fac: 'soft', wit: 'act', pass: prime ? 'good' : 'bad' };
      const grid = frames.find((f) => f.meta.phase === 'grid');
      ok(!!grid, 'a frame with every base');
      // every base drawn in its colour
      const bm = item(grid, 'bm');
      if (bm) {
        const cols = bm.rows[0].length;
        bm.rows.forEach((row, r) => [...row].forEach((ch, c) => { const a = N(r * cols + c + 1); if (a < n) ok(ch === look[kind(a)], 'base ' + a + ' is drawn as ' + ch); }));
      } else for (let a = 1n; a < n; a++) { const it = item(grid, 'g' + a); ok(it && it.cls.includes(cls[kind(a)]), 'base ' + a + ' cell ' + (it && it.cls)); }
      const s = sayOf(grid);
      if (!prime) {
        const m = /(\d+) Fermat witnesses, (\d+) liars and (\d+) bases sharing/.exec(s);
        ok(m && +m[1] === W && +m[2] === L && +m[3] === Fc, 'the counts ' + W + ', ' + L + ', ' + Fc + ': ' + s);
        ok(grid.counters.liars === L, 'the liars counter');
      } else ok(s.startsWith('All ' + (n - 1n) + ' bases pass'), 'a prime passes every base: ' + s);
      for (const f of frames) if (f.meta.phase === 'test') ok(f.meta.passes === (pw(N(f.meta.a), n - 1n, n) === 1n), 'the test of base ' + f.meta.a);
      // Korselt
      const fs = factors(n), sqfree = [...fs.values()].every((k) => k === 1);
      const kors = !prime && sqfree && fs.size >= 2 && [...fs.keys()].every((p) => (n - 1n) % (p - 1n) === 0n);
      const k = frames.find((f) => f.meta.phase === 'korselt');
      ok(k && k.meta.carm === kors, 'Korselt says ' + kors + ' for ' + n);
      ok(!kors || W === 0, 'a Carmichael number has no Fermat witness');
      if (!prime) ok(sayOf(k).includes(kors ? ' is a Carmichael number.' : ' is not a Carmichael number.'), 'the verdict in words: ' + sayOf(k));
    },
  },

  'miller-rabin': {
    random: (rnd) => { const n = odd(rnd, 5, 3000000); const b = []; for (let k = ri(rnd, 1, 4); k > 0; k--) b.push(String(ri(rnd, 2, Math.max(2, n - 2)))); return { n: String(n), bases: b }; },
    extra: [{ n: '2047', bases: ['2'] }, { n: '1373653', bases: ['2', '3', '5'] }, { n: '7', bases: ['2', '5'] }, { n: '18446744073709551557', bases: ['2', '3'] }, { n: '340282366920938463463374607431768211457', bases: ['3'] }],
    mayRefuse: true,
    check({ input, frames, ok }) {
      const n = N(input.n), bases = input.bases.map(N);
      const c0 = chain(n, bases[0]);
      ok(sayOf(frames[0]).includes(' = 2^' + c0.s + '·'), 'n − 1 = 2^s·d with s = ' + c0.s + ': ' + sayOf(frames[0]));
      const done = frames[frames.length - 1];
      const ch = bases.map((a) => chain(n, a));
      const witness = ch.findIndex((c) => c.verdict === 'fail');
      ok(done.meta.composite === (witness >= 0), 'the verdict: witness ' + witness);
      if (witness < 0) ok(isPrime(n) ? /it is prime/.test(sayOf(done)) : /yet it is composite/.test(sayOf(done)), 'prime or a liar: ' + sayOf(done));
      if (witness >= 0) ok(!isPrime(n), 'a witness for a prime');
      for (const f of frames) {
        if (f.meta.phase !== 'step') continue;
        const c = ch[f.meta.k];
        ok(f.meta.v === c.xs[f.meta.j].toString(), 'base ' + bases[f.meta.k] + ' value ' + f.meta.j);
        if (f.meta.last) { ok(f.meta.verdict === c.verdict && f.meta.j === c.xs.length - 1, 'base ' + bases[f.meta.k] + ' verdict ' + c.verdict); ok(sayOf(f).includes(c.verdict === 'pass' ? 'is not a witness' : 'is a witness'), 'the verdict in words'); }
        // the cells of this base drawn so far
        for (let j = 0; j <= f.meta.j; j++) {
          const it = item(f, 'c' + f.meta.k + '_' + j), v = c.xs[j];
          const want = v === n - 1n ? '−1' : n >= 10n ** 7n && v.toString().length > 9 ? v.toString().slice(0, 4) + '…' + v.toString().slice(-4) : v.toString();
          ok(it && it.text === want, 'cell ' + f.meta.k + ',' + j + ' shows ' + (it && it.text) + ', want ' + want);
        }
      }
    },
  },

  'group-order': {
    random: (rnd) => { const n = ri(rnd, 3, 19); const us = []; for (let a = 1; a < n; a++) if (gcd(N(a), N(n)) === 1n) us.push(a); return { n, g: us[ri(rnd, 0, us.length - 1)] }; },
    check({ input, frames, ok }) {
      const n = N(input.n), g = N(input.g);
      const units = []; for (let a = 1n; a < n; a++) if (gcd(a, n) === 1n) units.push(a);
      const G = units.length, gens = units.filter((a) => ord(a, n) === G);
      for (const f of frames) {
        for (const it of f.items) {
          let m = /^p(\d+)_(\d+)$/.exec(it.key);
          if (m && it.text !== '') { const a = N(m[1]), e = +m[2]; ok(e <= ord(a, n) && it.text === String(pw(a, N(e), n)), 'cell ' + a + '^' + e + ' shows ' + it.text); }
          m = /^o(\d+)$/.exec(it.key);
          if (m) ok(it.text === String(ord(N(m[1]), n)), 'the order of ' + m[1] + ' shows ' + it.text);
        }
        for (const m of sayOf(f).matchAll(/ord\((\d+)\) = (\d+)/g)) ok(ord(N(m[1]), n) === +m[2], 'ord(' + m[1] + ') = ' + m[2]);
        if (f.meta.phase === 'gens') {
          ok(f.meta.gens.join(',') === gens.join(','), 'the generators ' + f.meta.gens + ', want ' + gens);
          ok(f.meta.roots.join(',') === gens.join(','), 'the primitive roots');
          if (gens.length) ok(sayOf(f).includes('φ(' + G + ') = ' + gens.length), 'the count of generators is φ(φ(n)): ' + sayOf(f));
          const os = /The orders that occur are ([\d, and]+):/.exec(sayOf(f));
          ok(os && nums(os[1]).join(',') === [...new Set(units.map((a) => ord(a, n)))].sort((x, y) => x - y).join(','), 'the orders listed');
        }
        if (f.meta.phase === 'test') { ok(f.meta.e * f.meta.q === G && G % f.meta.q === 0 && isPrime(f.meta.q), 'the test exponent'); ok(N(f.meta.v) === pw(g, N(f.meta.e), n), 'g^e'); }
      }
      ok(frames[frames.length - 1].meta.gen === (ord(g, n) === G), 'the verdict on ' + g);
    },
  },

  lagrange: {
    random: (rnd) => { let n; do n = ri(rnd, 3, 60); while (phi(N(n)) > 24n); const us = []; for (let a = 1; a < n; a++) if (gcd(N(a), N(n)) === 1n) us.push(a); return { n, a: us[ri(rnd, 0, us.length - 1)] }; },
    check({ input, frames, ok }) {
      const n = N(input.n), a = N(input.a);
      const units = []; for (let k = 1n; k < n; k++) if (gcd(k, n) === 1n) units.push(k);
      const h = ord(a, n), Hs = []; for (let k = 0, v = 1n; k < h; k++, v = (v * a) % n) Hs.push(v);
      const Hf = frames.find((f) => f.meta.phase === 'H');
      ok(Hf.meta.h === h, '|H| = ' + h);
      const set = (xs) => xs.map(String).sort().join(',');
      for (const f of frames) {
        if (f.meta.phase === 'coset') for (const m of sayOf(f).matchAll(/(\d+)·H = \{[^}]*\} ≡ \{([^}]*)\}/g)) ok(set(nums(m[2])) === set(Hs.map((x) => (N(m[1]) * x) % n)), 'the coset ' + m[1] + '·H');
        if (f.meta.phase === 'lagrange') ok(f.meta.c * f.meta.h === units.length && f.meta.h === h, 'the cosets times |H| make |G|');
        if (f.meta.phase === 'all') ok(f.meta.ords.every((o) => units.length % o === 0), 'every subgroup order divides |G|');
      }
      // in the last frame each element sits in the box of its own coset, and each box holds one coset
      const last = frames[frames.length - 1];
      const boxes = last.items.filter((x) => /^bx\d+$/.test(x.key));
      ok(boxes.length === units.length / h, 'one box per coset');
      for (const b of boxes) {
        const inside = units.filter((v) => { const c = item(last, 'e' + v); return c.x >= b.x && c.x + c.w <= b.x + b.w && c.y >= b.y && c.y + c.h <= b.y + b.h; });
        const rep = inside[0];
        ok(inside.length === h && set(inside) === set(Hs.map((x) => (rep * x) % n)), 'box ' + b.key + ' holds a coset: ' + inside.join(','));
      }
    },
  },

  'crt-clocks': {
    random: (rnd) => { const m1 = ri(rnd, 2, 9), m2 = ri(rnd, 2, 9); return { m1, m2, r1: ri(rnd, 0, m1 - 1), r2: ri(rnd, 0, m2 - 1) }; },
    check({ input, frames, ok }) {
      const { m1, m2, r1, r2 } = input, g = Number(gcd(N(m1), N(m2))), L = (m1 * m2) / g;
      for (const f of frames) {
        let cells = 0;
        for (const it of f.items) { const m = /^g(\d+)_(\d+)$/.exec(it.key); if (m && it.text !== '') { cells++; const x = +it.text; ok(x % m1 === +m[1] && x % m2 === +m[2] && x < L, 'x = ' + x + ' in cell ' + m[1] + ',' + m[2]); } }
        if (f.meta.phase === 'walk') ok(cells === f.meta.x + 1 && f.counters.cells === cells, 'every x so far is in the grid');
        if (f.meta.phase === 'full') ok(f.meta.L === L && cells === L, 'the pairs repeat after lcm ' + L);
      }
      const look = frames[frames.length - 1];
      let want = null; for (let x = 0; x < L; x++) if (x % m1 === r1 && x % m2 === r2) want = x;
      ok(look.meta.x === want, 'the lookup gives ' + look.meta.x + ', want ' + want);
    },
  },

  'crt-solve': {
    random: (rnd) => { const k = ri(rnd, 2, 3), ms = []; while (ms.length < k) { const m = ri(rnd, 2, 3000); if (ms.every((x) => gcd(N(x), N(m)) === 1n)) ms.push(m); } return { r: ms.map(() => String(ri(rnd, 0, 5000))), m: ms.map(String) }; },
    check({ input, frames, ok }) {
      const rs = input.r.map(N), ms = input.m.map(N), M = ms.reduce((a, b) => a * b, 1n);
      const sum = frames.find((f) => f.meta.phase === 'sum');
      const x = N(sum.meta.x);
      ok(x >= 0n && x < M && ms.every((m, i) => md(x - rs[i], m) === 0n), 'x = ' + x + ' solves every congruence');
      const last = frames[frames.length - 1];
      for (const it of last.items) {
        const m = /^tb:(\d+),(\d+)$/.exec(it.key);
        if (!m || it.text === '') continue;
        const i = +m[1], c = +m[2], Mi = M / ms[i], yi = inv(Mi, ms[i]);
        const want = [rs[i], ms[i], Mi, Mi % ms[i], yi, md(rs[i], ms[i]) * Mi * yi][c];
        ok(it.text === String(want), 'table cell ' + i + ',' + c + ' shows ' + it.text + ', want ' + want);
      }
      for (const f of frames) if (f.meta.phase === 'yi') ok(N(f.meta.yi) === inv(M / ms[f.meta.i], ms[f.meta.i]), 'y' + (f.meta.i + 1));
    },
  },

  'crt-speedup': {
    check({ frames, ok }) {
      const st = frames[0].meta, p = N(st.p), q = N(st.q), c = N(st.c), d = N(st.d), n = p * q;
      ok(isPrime(p) && isPrime(q) && p !== q, 'p and q are primes');
      ok(md(d * 65537n, (p - 1n) * (q - 1n)) === 1n, 'd is the inverse of e');
      const m = pw(c, d, n);
      ok(m === N(st.m0) && pw(N(st.m0), 65537n, n) === c, 'decryption gives the message back');
      const dir = frames.find((f) => f.meta.phase === 'direct'), crt = frames.find((f) => f.meta.phase === 'crt');
      ok(N(dir.meta.m) === m && N(crt.meta.m) === m && crt.meta.same, 'both ways give m');
      const bl = (v) => v.toString(2).length, ops = (e) => bl(e) - 1 + e.toString(2).split('').filter((x) => x === '1').length - 1;
      const wd = ops(d) * bl(n) ** 2, wc = ops(d % (p - 1n)) * bl(p) ** 2 + ops(d % (q - 1n)) * bl(q) ** 2;
      const w = frames[frames.length - 1].meta.ratio;
      ok(w === (wd / wc).toFixed(1), 'the work ratio ' + w + ', want ' + (wd / wc).toFixed(1));
      ok(sayOf(dir).includes((bl(d) - 1) + ' squarings and ' + (d.toString(2).split('').filter((x) => x === '1').length - 1) + ' multiplications'), 'the operation counts: ' + sayOf(dir));
    },
  },
};
