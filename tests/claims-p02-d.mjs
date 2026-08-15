// Claim checks for part 2, finite fields: GF(p), polynomials over GF(2), GF(2^m) multiplication, inversion in
// GF(2^8) and the table of the AES field. Field arithmetic here is written apart from the engines: carry-less
// products, reduction by long division, logarithms found by repeated multiplication, and the S-box from the
// rotation form of its affine map.
import { md, inv } from './claims-lib-p02.mjs';

const ri = (rnd, lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));
const N = (x) => BigInt(x);
const SUP = { '⁰': 0, '¹': 1, '²': 2, '³': 3, '⁴': 4, '⁵': 5, '⁶': 6, '⁷': 7, '⁸': 8, '⁹': 9 };
/** "x⁷ + x³ + x + 1" -> 0b10001011n; null when the text is not a polynomial */
export function poly(text) {
  const t = text.trim();
  if (t === '0') return 0n;
  let v = 0n;
  for (const term of t.split(' + ')) {
    if (term === '1') v ^= 1n;
    else if (term === 'x') v ^= 2n;
    else if (/^x[⁰¹²³⁴⁵⁶⁷⁸⁹]+$/.test(term)) v ^= 1n << N([...term.slice(1)].reduce((k, c) => k * 10 + SUP[c], 0));
    else return null;
  }
  return v;
}
const deg = (v) => (v === 0n ? -1 : v.toString(2).length - 1);
const clmul = (a, b) => { let r = 0n; for (let i = 0; b >> N(i); i++) if ((b >> N(i)) & 1n) r ^= a << N(i); return r; };
const pmod = (a, f) => { const d = deg(f); while (deg(a) >= d) a ^= f << N(deg(a) - d); return a; };
const pdiv = (a, f) => { let q = 0n; const d = deg(f); while (deg(a) >= d) { const k = deg(a) - d; q |= 1n << N(k); a ^= f << N(k); } return { q, r: a }; };
const F8 = 0x11bn;
const gmul = (a, b, f = F8) => pmod(clmul(N(a), N(b)), f);
const FIELD = { 3: 0b1011n, 4: 0b10011n, 5: 0b100101n, 8: F8 };
// logarithms to the base {03}, by repeated multiplication
const LOG = new Map(), EXP = [];
for (let k = 0, v = 1n; k < 255; k++) { EXP.push(v); LOG.set(v, k); v = gmul(v, 3n); }
const ginv = (a) => (N(a) === 0n ? 0n : EXP[(255 - LOG.get(N(a))) % 255]);
const rotl = (b, k) => ((b << N(k)) | (b >> N(8 - k))) & 0xffn;
const sbox = (a) => { const b = ginv(a); return b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ 0x63n; };
const hexes = (s, re) => [...s.matchAll(re)];
const sayOf = (f) => f.say || '';
/** every "{aa}·{bb} = {cc}" in a sentence, checked in GF(2^8) */
function byteProducts(s, ok) { for (const m of hexes(s, /\{([0-9a-f]{1,3})\}·\{([0-9a-f]{1,3})\} = \{([0-9a-f]{1,3})\}/g)) ok(gmul(N('0x' + m[1]), N('0x' + m[2])) === N('0x' + m[3]), 'the product ' + m[0]); }

export default {
  'gf-p': {
    random: (rnd) => ({ p: ri(rnd, 2, 31), a: ri(rnd, -99, 99), b: ri(rnd, -99, 99) }),
    check({ input, frames, ok }) {
      const p = N(input.p), a = md(N(input.a), p), b = md(N(input.b), p);
      const isPrime = (() => { for (let k = 2n; k * k <= p; k++) if (p % k === 0n) return false; return p > 1n; })();
      for (const f of frames) {
        if (f.meta.phase === 'pair') for (const [u, v] of f.meta.pairs) ok(md(N(u) * N(v), p) === 1n % p, 'the pair ' + u + ', ' + v);
        if (f.meta.phase === 'pairs' && f.meta.lone) ok(f.meta.lone.every((x) => inv(N(x), p) === null) && f.meta.lone.length === [...Array(input.p - 1).keys()].filter((k) => inv(N(k + 1), p) === null).length, 'the elements without a partner');
        if (f.meta.phase === 'ops') {
          ok(N(f.meta.sum) === md(a + b, p) && N(f.meta.dif) === md(a - b, p) && N(f.meta.pro) === md(a * b, p), 'the sum, difference and product');
          const bi = inv(b, p);
          ok(bi === null ? f.meta.quo === null : N(f.meta.quo) === md(a * bi, p), 'the quotient');
          ok(isPrime || /not a field|no inverse|nobody divides/.test(sayOf(f)) || bi !== null, 'a composite modulus is called out');
        }
        if (f.meta.phase === 'pairs' && !f.meta.lone && input.p > 2) ok(isPrime && /is a field/.test(sayOf(f)), 'a prime modulus gives a field');
      }
      // the lit elements of the ring are the right ones
      const last = frames[frames.length - 1];
      for (const it of last.items) { const m = /^el:(\d+)$/.exec(it.key); if (m && / act/.test(' ' + it.cls)) ok(N(Number(m[1]) + 1) === a, 'a is lit'); }
    },
  },

  'gf2-poly': {
    random: (rnd) => { const bits = (n) => '1' + [...Array(n - 1)].map(() => (rnd() < 0.5 ? '0' : '1')).join(''); return { a: bits(ri(rnd, 1, 12)), b: bits(ri(rnd, 1, 9)), op: ['add', 'mul', 'div'][ri(rnd, 0, 2)] }; },
    check({ input, frames, ok }) {
      const a = N('0b' + input.a), b = N('0b' + input.b);
      for (const f of frames) {
        const s = sayOf(f);
        if (f.meta.phase === 'sum') ok(N(f.meta.value) === (a ^ b) && s.includes('= ' + (a ^ b).toString(2) + '₂'), 'the sum ' + s);
        if (f.meta.phase === 'product') {
          ok(N(f.meta.value) === clmul(a, b), 'the product');
          const m = /a·b = ([x⁰¹²³⁴⁵⁶⁷⁸⁹ +1]+), or ([01]+)₂/.exec(s);
          ok(m && poly(m[1]) === clmul(a, b) && N('0b' + m[2]) === clmul(a, b), 'the product as said: ' + s);
          ok(s.includes(a + '·' + b + ' = ' + a * b + ' = ' + (a * b).toString(2) + '₂'), 'the integer product: ' + s);
        }
        if (f.meta.phase === 'step') {
          const m = /: ([01]+)₂ ⊕ ([01]+)₂ = ([01]+)₂/.exec(s);
          ok(m && (N('0b' + m[1]) ^ N('0b' + m[2])) === N('0b' + m[3]) && N('0b' + m[3]) === N(f.meta.next), 'the XOR of a division step: ' + s);
        }
        if (f.meta.phase === 'done') {
          const { q, r } = pdiv(a, b);
          ok(N(f.meta.q) === q && N(f.meta.r) === r, 'the quotient and remainder');
          const m = /q = ([^ ].*?) and r = ([^:.]+)[:.]/.exec(s);
          ok(m && poly(m[1]) === q && poly(m[2]) === r, 'the quotient and remainder as said: ' + s);
        }
        // every polynomial a row prints is the bits drawn in that row
        for (const it of f.items) {
          const m = /^(\w+):p$/.exec(it.key);
          if (!m || it.text === '0') continue;
          const bits = f.items.filter((x) => x.key.startsWith(m[1] + ':') && /^\d+$/.test(x.key.slice(m[1].length + 1)));
          const v = bits.reduce((acc, x) => acc | (N(x.text) << N(x.key.slice(m[1].length + 1))), 0n);
          ok(poly(it.text) === v, 'row ' + m[1] + ' prints ' + it.text + ' over the bits ' + v.toString(2));
        }
      }
    },
  },

  'gf2m-mul': {
    random: (rnd) => { const m = [3, 4, 5, 8][ri(rnd, 0, 3)]; return { m: String(m), a: ri(rnd, 0, (1 << m) - 1).toString(16), b: ri(rnd, 0, (1 << m) - 1).toString(16) }; },
    runs: 24,
    check({ input, frames, ok }) {
      const m = +input.m, f = FIELD[m], a = N(parseInt(input.a, 16)), b = N(parseInt(input.b, 16));
      const want = pmod(clmul(a, b), f);
      const last = frames[frames.length - 1];
      ok(N(last.meta.value) === want, 'the product is ' + last.meta.value + ', want ' + want);
      const ws = (v) => (m <= 5 ? v.toString(2).padStart(m, '0') + '₂' : '{' + v.toString(16).padStart(2, '0') + '}');
      ok(sayOf(last).startsWith('a·b = ' + ws(want) + ' = ' + (want === 0n ? '0' : '')), 'the product as said: ' + sayOf(last));
      let acc = 0n;
      for (const fr of frames) {
        const s = sayOf(fr);
        if (fr.meta.phase === 'add') {
          const term = pmod(a << N(fr.meta.i), f);
          if ((b >> N(fr.meta.i)) & 1n) acc ^= term;
          ok(N(fr.meta.acc) === acc, 'the running sum after bit ' + fr.meta.i);
          ok(s.includes(ws(term)) && s.includes(ws(acc)), 'the term and sum as said: ' + s);
          ok(fr.meta.bit === Number((b >> N(fr.meta.i)) & 1n), 'the bit of b');
        }
        if (fr.meta.phase === 'shift') {
          const cur = pmod(a << N(fr.meta.i), f), next = pmod(cur << 1n, f);
          ok(N(fr.meta.next) === next && fr.meta.reduced === !!((cur << 1n) >> N(m)), 'the shift after row ' + fr.meta.i);
          const x = /: ([01]+₂|\{[0-9a-f]+\}) ⊕ ([01]+₂|\{[0-9a-f]+\}) gives/.exec(s);
          if (fr.meta.reduced) { const v = (t) => (t.startsWith('{') ? N('0x' + t.slice(1, -1)) : N('0b' + t.slice(0, -1))); ok(x && (v(x[1]) ^ v(x[2])) === next && v(x[2]) === f, 'the reduction as said: ' + s); }
        }
      }
      if (m === 8) for (const fr of frames) byteProducts(sayOf(fr), ok);
    },
  },

  'gf256-inverse': {
    random: (rnd) => ({ a: ri(rnd, 0, 255).toString(16) }),
    runs: 30,
    check({ input, frames, ok }) {
      const a = N(parseInt(input.a, 16));
      const last = frames[frames.length - 1];
      if (a === 0n) { ok(last.meta.phase === 'zero2' && sayOf(last).includes('{' + sbox(0n).toString(16) + '}'), 'zero maps to S(00)'); return; }
      ok(gmul(a, N(last.meta.inv)) === 1n, 'a·a⁻¹ = 1');
      ok(N(last.meta.inv) === ginv(a), 'the inverse agrees with the logarithms');
      ok(sayOf(last).includes('S({' + a.toString(16).padStart(2, '0') + '}) = {' + sbox(a).toString(16).padStart(2, '0') + '}'), 'the S-box value: ' + sayOf(last));
      byteProducts(sayOf(last), ok);
      // every row keeps r ≡ t·a (mod f), and each step is a long division
      for (const f of frames) if (f.meta.phase === 'row') ok(pmod(clmul(N(f.meta.t), a), F8) === pmod(N(f.meta.r), F8), 'row ' + f.meta.i + ': r ≡ t·a');
      for (const f of frames) {
        const m = /Divide r\S+ = (.+?) by r\S+ = (.+?): quotient (.+?), remainder (.+?)\. Then t\S+ = t\S+ \+ q·t\S+ = (.+?) \+ \((.+?)\)\((.+?)\) = (.+?)\.$/.exec(sayOf(f));
        if (f.meta.phase !== 'row') continue;
        ok(!!m, 'the division sentence: ' + sayOf(f));
        if (!m) continue;
        const [x, y, q, r, t0, q2, t1, t2] = m.slice(1).map(poly);
        const d = pdiv(x, y);
        ok(d.q === q && d.r === r && q2 === q && (t0 ^ clmul(q, t1)) === t2, 'the division and the new t: ' + sayOf(f));
      }
    },
  },

  'gf256-table': {
    random: (rnd) => ({ a: ri(rnd, 0, 255).toString(16), b: ri(rnd, 0, 255).toString(16) }),
    check({ input, frames, ok }) {
      const a = N(parseInt(input.a, 16)), b = N(parseInt(input.b, 16));
      for (const f of frames) {
        const s = sayOf(f);
        byteProducts(s, ok);
        for (const m of hexes(s, /log \{([0-9a-f]{2})\} = (\d+)/g)) ok(LOG.get(N('0x' + m[1])) === Number(m[2]), 'the logarithm ' + m[0]);
        for (const m of hexes(s, /\{03\}([⁰¹²³⁴⁵⁶⁷⁸⁹]+) = \{([0-9a-f]{2})\}/g)) ok(EXP[[...m[1]].reduce((k, c) => k * 10 + SUP[c], 0) % 255] === N('0x' + m[2]), 'the power ' + m[0]);
        // the cells: a logarithm table, or the table of inverses
        const inverses = /The inverse of each byte/.test((f.items.find((x) => x.key === 'gt') || {}).text || '');
        for (const it of f.items) {
          const m = /^g(\d+)$/.exec(it.key);
          if (!m || it.text === '' || it.text === '–') continue;
          const v = N(m[1]);
          if (f.meta.phase === 'bytes') ok(it.text === v.toString(16).padStart(2, '0'), 'the byte cell ' + v);
          else if (inverses) ok(N('0x' + it.text) === ginv(v), 'the inverse cell ' + v);
          else ok(LOG.get(v) === Number(it.text), 'the log cell ' + v + ' shows ' + it.text);
        }
        if (f.meta.phase === 'mul') ok(N(f.meta.value) === gmul(a, b), 'the product cell');
        if (f.meta.phase === 'inv') ok(N(f.meta.inv) === ginv(a), 'the inverse of a');
        if (f.meta.phase === 'table') ok(s.includes('S({' + a.toString(16).padStart(2, '0') + '}) = {' + sbox(a).toString(16).padStart(2, '0') + '}'), 'the S-box value: ' + s);
      }
    },
  },
};
