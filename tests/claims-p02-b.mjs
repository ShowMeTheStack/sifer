// Claim checks for part 2, Euclid and Euler: every table cell, struck cell, lit position, label and counter the
// frames draw, against arithmetic worked out here (tests/claims-lib-p02.mjs), apart from the engines.
import { md, gcd, inv, pw, phi } from './claims-lib-p02.mjs';

const ri = (rnd, lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));
const rbig = (rnd, digits) => { let s = String(1 + Math.floor(rnd() * 9)); for (let i = 1; i < digits; i++) s += Math.floor(rnd() * 10); return s; };
const N = (x) => BigInt(x);
const item = (f, key) => f.items.find((x) => x.key === key);
const num = (t) => N(String(t).replace('−', '-'));
const nums = (s) => (s.match(/−?\d+/g) || []).map((x) => Number(x.replace('−', '-')));
const abs = (v) => (v < 0n ? -v : v);

/** plain Euclid, written again */
const euclidRows = (a, b) => { a = abs(a); b = abs(b); const rows = []; while (b) { rows.push({ a, b, q: a / b, r: a % b }); [a, b] = [b, a % b]; } return { rows, g: a }; };
/** the extended table, written again */
const egcdRows = (a, b) => {
  const rows = [{ r: a, s: 1n, t: 0n, q: null }, { r: b, s: 0n, t: 1n, q: null }];
  while (rows[rows.length - 1].r !== 0n) { const p = rows[rows.length - 2], c = rows[rows.length - 1], q = p.r / c.r; c.q = q; rows.push({ r: p.r - q * c.r, s: p.s - q * c.s, t: p.t - q * c.t, q: null }); }
  return rows;
};

export default {
  euclid: {
    random: (rnd) => (rnd() < 0.5 ? { a: String(ri(rnd, 1, 5000)), b: String(ri(rnd, 1, 5000)) } : { a: rbig(rnd, ri(rnd, 5, 22)), b: rbig(rnd, ri(rnd, 3, 22)) }),
    extra: [{ a: '1', b: '1' }, { a: '7', b: '7' }, { a: '1', b: '999999999999999999999999' }, { a: '832040', b: '514229' }],
    check({ input, frames, ok }) {
      const a = N(input.a), b = N(input.b), { rows, g } = euclidRows(a, b);
      const last = frames[frames.length - 1];
      ok(last.meta.g === g, 'gcd ' + last.meta.g + ', want ' + g);
      ok(last.say.includes('gcd(' + a + ', ' + b + ') = ' + g), 'the last frame names the gcd: ' + last.say);
      ok(last.say.includes(rows.length + ' division'), 'the number of divisions');
      let sc = null;
      for (const f of frames) {
        if (f.meta.phase === 'row') { const r = rows[f.meta.i]; ok(f.meta.r === r.r && f.meta.q === r.q && f.counters.div === f.meta.i + 1, 'row ' + f.meta.i); }
        for (const it of f.items) {
          let m = /^r(\d+)([aqbr])$/.exec(it.key);
          if (m && it.kind === 'cell') ok(num(it.text) === rows[+m[1]][m[2]], 'cell ' + it.key + ' shows ' + it.text);
          m = /^sq(\d+)_(\d+)$/.exec(it.key);
          if (m) {
            const r = rows[+m[1]];
            ok(N(m[2]) < r.q, 'square ' + it.key + ' is one of the q cut by its row');
            const k = (it.w + 3) / Number(r.b);
            if (sc === null) sc = k; else ok(Math.abs(k - sc) < 1e-6, 'square ' + it.key + ' has side ' + r.b + ' at the common scale');
          }
        }
      }
    },
  },

  egcd: {
    random: (rnd) => (rnd() < 0.6 ? { a: String(ri(rnd, 1, 9999)), b: String(ri(rnd, 1, 9999)) } : { a: rbig(rnd, ri(rnd, 4, 19)), b: rbig(rnd, ri(rnd, 2, 19)) }),
    extra: [{ a: '1', b: '1' }, { a: '5', b: '10' }, { a: '1', b: '9' }],
    check({ input, frames, ok }) {
      const a = N(input.a), b = N(input.b), rows = egcdRows(a, b), gi = rows.length - 2, g = rows[gi].r;
      for (const f of frames) {
        // every drawn cell, and the invariant r = a·s + b·t on every whole row drawn
        const seen = new Map();
        for (const it of f.items) {
          const m = /^e(\d+)([iqrst])$/.exec(it.key);
          if (!m || m[2] === 'i' || it.text === '') continue;
          const want = rows[+m[1]][m[2]];
          ok(want !== null && num(it.text) === want, 'cell ' + it.key + ' shows ' + it.text + ', want ' + want);
          if (!seen.has(m[1])) seen.set(m[1], {}); seen.get(m[1])[m[2]] = num(it.text);
        }
        for (const [i, v] of seen) if (v.r !== undefined && v.s !== undefined && v.t !== undefined) ok(a * v.s + b * v.t === v.r, 'row ' + i + ' keeps r = a·s + b·t');
        if (f.meta.phase === 'row') { const r = rows[f.meta.i]; ok(f.meta.r === r.r && f.meta.s === r.s && f.meta.t === r.t, 'row ' + f.meta.i + ' values'); }
        if (f.meta.phase === 'result') ok(f.meta.x === rows[gi].s && f.meta.y === rows[gi].t && a * f.meta.x + b * f.meta.y === g, 'the result coefficients');
        if (f.meta.phase === 'inverse') ok(f.meta.inv === inv(b, a), 'the inverse of b modulo a: ' + f.meta.inv);
      }
      const backs = frames.filter((f) => f.meta.phase === 'back');
      ok(backs.length > 0, 'back-substitution is shown');
      const lb = backs[backs.length - 1];
      ok(a * lb.meta.u + b * lb.meta.v === g, 'back-substitution ends with g = a·u + b·v: ' + lb.meta.u + ', ' + lb.meta.v);
      ok(g === 1n ? frames.some((f) => f.meta.phase === 'inverse') : !frames.some((f) => f.meta.phase === 'inverse'), 'the inverse frame only when g = 1');
    },
  },

  'euler-phi': {
    random: (rnd) => ({ n: ri(rnd, 2, 120) }),
    extra: [{ n: 3 }, { n: 4 }, { n: 97 }, { n: 120 }, { n: 113 }],
    check({ input, frames, ok }) {
      const n = input.n, P = [];
      for (let p = 2; p <= n; p++) if (n % p === 0 && [...Array(p - 2).keys()].every((k) => p % (k + 2))) P.push(p);
      const last = frames[frames.length - 1];
      ok(N(last.meta.phi) === phi(n), 'φ(' + n + ') = ' + last.meta.phi);
      for (let k = 1; k <= n; k++) {
        const c = item(last, 'g' + k), cop = gcd(N(k), N(n)) === 1n;
        ok(c && /good/.test(c.cls) === cop && /struck|bad/.test(c.cls) === !cop, 'cell ' + k + ' at the end: ' + (c && c.cls));
      }
      const strikes = frames.filter((f) => f.meta.phase === 'strike');
      ok(strikes.map((f) => f.meta.p).join(',') === P.join(','), 'the primes struck: ' + strikes.map((f) => f.meta.p));
      strikes.forEach((f, j) => {
        let left = 0;
        for (let k = 1; k <= n; k++) {
          const c = item(f, 'g' + k), hit = P.slice(0, j + 1).some((p) => k % p === 0), fresh = k % P[j] === 0 && !P.slice(0, j).some((p) => k % p === 0);
          ok(/bad/.test(c.cls) === fresh && /struck|bad/.test(c.cls) === hit, 'cell ' + k + ' after striking ' + P[j]);
          if (!hit) left++;
        }
        ok(f.meta.left === left && f.counters.left === left && f.say.includes(left + ' remain'), 'left after ' + P[j] + ': ' + left);
      });
    },
  },

  'power-cycles': {
    random: (rnd) => ({ a: ri(rnd, -999, 999), n: ri(rnd, 2, 30) }),
    extra: [{ a: 0, n: 5 }, { a: 1, n: 9 }, { a: 4, n: 12 }, { a: 2, n: 2 }, { a: 30, n: 30 }],
    check({ input, frames, ok }) {
      const n = N(input.n), a = md(N(input.a), n);
      // the walk a^1, a^2, … until a value repeats
      const seen = new Map(); let k = 1, v = a;
      while (!seen.has(v)) { seen.set(v, k); v = (v * a) % n; k++; }
      const start = seen.get(v), L = k - start, T = start - 1, unit = gcd(a, n) === 1n;
      const last = frames[frames.length - 1];
      ok(last.meta.cycle === L && last.meta.tail === T, 'cycle ' + last.meta.cycle + ' and tail ' + last.meta.tail + ', want ' + L + ' and ' + T);
      if (unit) { ok(pw(a, N(L), n) === 1n && phi(n) % N(L) === 0n, 'the order divides φ'); ok(last.meta.ord === L, 'the order'); }
      for (const f of frames) {
        if (f.meta.phase === 'power') {
          const want = pw(a, N(f.meta.k), n);
          ok(N(f.meta.at) === want, 'power ' + f.meta.k + ' lands on ' + f.meta.at + ', want ' + want);
          ok(/hot/.test(item(f, 'ck:' + f.meta.at).cls), 'the newest power is lit');
          ok(f.counters.k === f.meta.k, 'the counter');
        }
        for (const it of f.items) {
          const m = /^ex(\d+)$/.exec(it.key);
          if (m) for (const e of nums(it.text)) ok(pw(a, N(e), n) === N(m[1]) || (e === 0 && m[1] === String(1n % n)), 'the exponent ' + e + ' is drawn at ' + m[1]);
        }
      }
    },
  },

  'fermat-euler': {
    random: (rnd) => { const n = ri(rnd, 2, 21); let a; do a = ri(rnd, -999, 999); while (gcd(N(a), N(n)) !== 1n); return { n, a, e: rbig(rnd, ri(rnd, 1, 30)) }; },
    check({ input, frames, ok }) {
      const n = N(input.n), a = md(N(input.a), n), e = N(input.e);
      const units = []; for (let u = 1n; u < n; u++) if (gcd(u, n) === 1n) units.push(u);
      if (n === 2n) units.splice(0, units.length, 1n);
      ok(pw(a, N(units.length), n) === 1n % n, 'Euler holds');
      for (const f of frames) {
        const tops = units.map((u) => item(f, 'u' + u));
        ok(tops.every((c, i) => c && num(c.text) === units[i]), 'the top row holds the units');
        for (const u of units) {
          const c = item(f, 'p' + u);
          if (!c) continue;
          ok(num(c.text) === md(a * u, n), 'the product of ' + u + ' is ' + c.text);
          if (f.meta.phase !== 'times') { const t = item(f, 'u' + md(a * u, n)); ok(t && t.x === c.x, 'sorted: ' + c.text + ' sits under ' + c.text); }
        }
        if (f.meta.phase === 'use') ok(N(f.meta.value) === pw(a, e, n) && f.meta.value === f.meta.full, 'a^e mod n: ' + f.meta.value + ', want ' + pw(a, e, n));
      }
    },
  },
};
