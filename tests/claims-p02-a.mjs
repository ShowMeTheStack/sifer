// Claim checks for part 2, modular arithmetic and Euclid. Each entry: {random(rnd) -> input values, extra: [values],
// check(ctx)} where ctx = {S, tp, input, frames, fail(msg), ok(cond, msg)}.
import { md, gcd, inv, phi } from './claims-lib-p02.mjs';

const ri = (rnd, lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));
const N = (x) => BigInt(x);
const nums = (s) => (s.match(/−?\d+/g) || []).map((x) => Number(x.replace('−', '-')));
const item = (f, key) => f.items.find((x) => x.key === key);
const sayOf = (f) => f.say || '';
/** the position a clock hand points at: from the angle of its line */
const handAt = (f, n) => {
  const h = item(f, 'ck:hand');
  if (!h) return null;
  const ang = (Math.atan2(h.x2 - h.x1, -(h.y2 - h.y1)) * 180) / Math.PI;
  return md(N(Math.round((((ang + 360) % 360) * n) / 360)), N(n));
};

export default {
  'mod-clock': {
    random: (rnd) => ({ n: ri(rnd, 2, 24), a: ri(rnd, -300, 300), t: ri(rnd, -300, 300) }),
    extra: [{ n: 2, a: 0, t: 0 }, { n: 24, a: -999, t: 999 }, { n: 5, a: 5, t: -5 }],
    check({ input, frames, ok }) {
      const { n, a, t } = input;
      const want = md(N(a + t), N(n)), r0 = md(N(a), N(n));
      const last = frames[frames.length - 1];
      ok(last.meta.r === Number(want), 'the hand stops at ' + last.meta.r + ', want ' + want);
      ok(handAt(last, n) === want, 'the last frame draws the hand at ' + handAt(last, n) + ', want ' + want);
      ok(sayOf(last).includes('stops at ' + want + '.'), 'the last frame names the stop: ' + sayOf(last));
      const dir = t >= 0 ? 1 : -1, rest = Math.abs(t) % n, laps = Math.floor(Math.abs(t) / n);
      for (const f of frames) {
        if (f.meta.phase === 'step') {
          const pos = md(r0 + N(dir * f.meta.done), N(n));
          ok(f.meta.pos === Number(pos), 'after ' + f.meta.done + ' steps the hand is at ' + f.meta.pos + ', want ' + pos);
          ok(handAt(f, n) === pos, 'the hand is drawn at ' + handAt(f, n) + ' after ' + f.meta.done + ' steps, want ' + pos);
          ok(sayOf(f).includes('the hand is at ' + pos), 'the step names the position: ' + sayOf(f));
          ok(f.counters.steps === laps * n + f.meta.done, 'the step counter');
        }
        if (f.meta.phase === 'laps') ok(sayOf(f).includes(laps + ' whole lap') && sayOf(f).includes(rest + ' more'), 'the laps: ' + sayOf(f));
        if (f.meta.phase === 'reduce') ok(f.meta.r === Number(r0) && handAt(f, n) === r0, 'the start reduces to ' + r0);
      }
      ok(frames.filter((f) => f.meta.phase === 'step').length <= 13, 'not too many step frames');
    },
  },

  'mod-classes': {
    random: (rnd) => { const n = ri(rnd, 2, 8), hi = n <= 5 ? 3 * n - 1 : 2 * n - 1; return { n, a: ri(rnd, -n, hi), b: ri(rnd, -n, hi) }; },
    check({ input, frames, ok }) {
      const { n, a, b } = input, ra = md(N(a), N(n)), rb = md(N(b), N(n));
      for (const f of frames) {
        // the grid: each integer sits in the column of its class
        for (const it of f.items) {
          const m = /^c(−?-?\d+)$/.exec(it.key);
          if (!m) continue;
          const k = Number(m[1]), col = Math.round((it.x - 30) / 58);
          ok(col === Number(md(N(k), N(n))), 'the integer ' + k + ' is drawn in column ' + col);
        }
        const s = sayOf(f);
        let m = /is in column (\d+)/.exec(s);
        if (f.meta.phase === 'classA') {
          ok(m && N(m[1]) === ra, 'a is in column ' + ra + ': ' + s);
          const lst = /: ([−\d, ]+) and so on/.exec(s);
          ok(lst && nums(lst[1]).every((x) => md(N(x), N(n)) === ra), 'the members listed are in the class: ' + s);
        }
        if (f.meta.phase === 'classB') {
          ok(m && N(m[1]) === rb, 'b is in column ' + rb + ': ' + s);
          ok(s.includes(ra === rb ? 'Same column' : 'A different column'), 'same or different: ' + s);
        }
        if (f.meta.phase === 'arith') {
          const lands = [...s.matchAll(/both land in \[(\d+)\]/g)].map((x) => N(x[1]));
          ok(lands.length === 2 && lands[0] === md(N(a + b), N(n)) && lands[1] === md(N(a * b), N(n)), 'the classes of the sum and product: ' + s);
        }
      }
    },
  },

  'zn-ring': {
    random: (rnd) => { const n = ri(rnd, 2, 13); return { n, a: ri(rnd, 0, n - 1) }; },
    check({ input, frames, ok }) {
      const n = N(input.n);
      const units = [], zds = [];
      for (let k = 1n; k < n; k++) (gcd(k, n) === 1n ? units : zds).push(k);
      for (const f of frames) {
        // every table cell drawn holds the right sum or product
        for (const it of f.items) {
          const m = /^t([am]):(\d+),(\d+)$/.exec(it.key);
          if (!m || it.text === '') continue;
          const r = N(m[2]), c = N(m[3]), want = m[1] === 'a' ? md(r + c, n) : md(r * c, n);
          ok(it.text === String(want), (m[1] === 'a' ? 'sum' : 'product') + ' cell ' + r + ',' + c + ' shows ' + it.text + ', want ' + want);
          if (/ntzd/.test(it.cls)) ok(gcd(r, n) !== 1n && want === 0n && c > 0n, 'a cell marked as a zero product: ' + r + '·' + c);
          if (/ntone/.test(it.cls) && m[1] === 'm') ok(want === 1n, 'a cell marked 1');
        }
        const s = sayOf(f);
        const row = /^Row (\d+) (holds every element exactly once|repeats itself|is all 0)/.exec(s);
        if (row) {
          const x = N(row[1]);
          ok((row[2].startsWith('holds every')) === (gcd(x, n) === 1n && x > 0n) || (x === 0n && row[2] === 'is all 0'), 'row ' + x + ' is a unit row or not: ' + s);
          const only = /it holds only ([\d, and]+), the multiples of gcd\((\d+), (\d+)\) = (\d+)/.exec(s);
          if (only) {
            const seen = [...new Set([...Array(input.n).keys()].map((c) => md(x * N(c), n)))].sort((p, q) => (p < q ? -1 : 1));
            ok(nums(only[1]).join(',') === seen.join(','), 'the values in row ' + x + ': ' + only[1] + ' want ' + seen.join(','));
          }
        }
        const u = /The units of Z_\d+ are ([\d, and]+|none):/.exec(s);
        if (u) ok(nums(u[1]).join(',') === units.join(','), 'the units: ' + u[1] + ', want ' + units.join(', '));
        const z = /The zero divisors are ([\d, and]+)\./.exec(s);
        if (z) ok(nums(z[1]).join(',') === zds.join(','), 'the zero divisors: ' + z[1]);
        if (f.meta.phase === 'sum') { ok(f.counters.units === units.length && f.counters.zd === zds.length, 'the counters'); ok(s.includes(phi(n) + ' of them'), 'φ(n) in the summary'); ok(zds.length > 0 || s.includes('is a field'), 'a field when n is prime'); }
      }
    },
  },

  'mod-inverse': {
    random: (rnd) => ({ a: ri(rnd, -200, 500), n: ri(rnd, 2, 36) }),
    extra: [{ a: 0, n: 7 }, { a: 36, n: 36 }, { a: 1, n: 2 }, { a: 35, n: 36 }],
    check({ input, frames, ok }) {
      const a = N(input.a), n = N(input.n), x = inv(a, n), g = gcd(md(a, n), n);
      const last = frames[frames.length - 1], s = sayOf(last);
      if (x !== null) {
        ok(last.meta.inv === Number(x), 'the inverse is ' + last.meta.inv + ', want ' + x);
        ok(s.startsWith(String(input.a).replace('-', '−') + '⁻¹ ≡ ' + x + ' (mod ' + n + ')'), 'the last frame states the inverse: ' + s);
        const hops = frames.filter((f) => f.meta.phase === 'hop');
        ok(hops.length && hops[hops.length - 1].meta.k === Number(x) && hops[hops.length - 1].meta.at === 1, 'the hops end on 1 after ' + x);
      } else if (md(a, n) === 0n) ok(/never leaves 0/.test(s), 'zero: ' + s);
      else {
        ok(last.meta.inv === null && s.includes('gcd(' + md(a, n) + ', ' + n + ') = ' + g), 'no inverse, gcd ' + g + ': ' + s);
        const vis = /visit only ([\d, and]+), the multiples/.exec(s);
        ok(vis && nums(vis[1]).join(',') === [...Array(Number(n / g)).keys()].map((j) => j * Number(g)).join(','), 'the positions visited: ' + s);
      }
      for (const f of frames) if (f.meta.phase === 'hop') ok(f.meta.at === Number(md(N(f.meta.k) * md(a, n), n)) && f.counters.hops === f.meta.k, 'hop ' + f.meta.k + ' lands on ' + f.meta.at);
    },
  },
};
