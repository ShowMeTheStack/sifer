// Preset labels that make a mathematical claim ("Coprime: 391 and 105", "Z_8*: no generator", "a point of order 12",
// "1 + x³ + x⁴ (primitive)") are checked against the engines for the preset's values, and against a plain working-out
// where one is short. Every label holding one of the trigger words must match a rule below or be listed in QUIET
// with the reason it makes no checkable claim, so a new label cannot slip past unchecked.
import { load, harness } from './load.mjs';
const S = load(['core', 'stage', 'topics']), t = harness('claims-labels'), N = S.NT;
const B = (v) => BigInt(String(v).replace(/[\s_]/g, ''));
const gcd = (a, b) => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a; };
const isPrime = (n) => { n = B(n); if (n < 2n) return false; if (n < 1n << 40n) { for (let p = 2n; p * p <= n; p++) if (n % p === 0n) return false; return true; } return N.isProbablePrime(n, 24); };
const bitLen = (n) => B(n).toString(2).length;
const ord = (a, n) => { a = B(a) % B(n); n = B(n); if (gcd(a, n) !== 1n) return null; let x = a, k = 1n; while (x !== 1n % n) { x = (x * a) % n; k++; } return k; };
const phi = (n) => { n = B(n); let k = 0n; for (let i = 1n; i <= n; i++) if (gcd(i, n) === 1n) k++; return k; };
const units = (n) => { const out = []; for (let i = 1n; i < B(n); i++) if (gcd(i, B(n)) === 1n) out.push(i); return out; };
const gens = (n) => units(n).filter((g) => ord(g, n) === phi(n));
const WORDS = { one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10 };
const num = (w) => (WORDS[String(w).toLowerCase()] !== undefined ? WORDS[String(w).toLowerCase()] : Number(w));
const SUB = (s) => String(s).replace(/[₀-₉]/g, (c) => '₀₁₂₃₄₅₆₇₈₉'.indexOf(c));
const SUP = (s) => String(s).replace(/[⁰¹²³⁴⁵⁶⁷⁸⁹]/g, (c) => '⁰¹²³⁴⁵⁶⁷⁸⁹'.indexOf(c));

// points of order 2 on y² = x³ + ax + b over GF(p): the roots of the cubic
const order2 = (p, a, b) => { let k = 0; for (let x = 0n; x < p; x++) if ((((x * x * x + a * x + b) % p) + p) % p === 0n) k++; return k; };
const ecPoint = (s) => { const [x, y] = String(s).split(',').map((v) => B(v.trim())); return { x, y }; };
// a tap list as a feedback polynomial 1 + Σ x^t over GF(2): its period and whether it is irreducible
const lfsrPeriod = (taps) => {
  const n = Math.max(...taps), start = 1; let s = start, k = 0;
  do { let fb = 0; for (const tp of taps) fb ^= (s >> (n - tp)) & 1; s = (s >> 1) | (fb << (n - 1)); k++; } while (s !== start && k < 1 << 22);
  return k;
};
const polyOf = (taps) => taps.reduce((m, tp) => m | (1 << tp), 1); // bit i = coefficient of x^i
const pmod = (a, b) => { const db = 31 - Math.clz32(b); while (a && 31 - Math.clz32(a) >= db) a ^= b << (31 - Math.clz32(a) - db); return a; };
const irreducible = (f) => { const d = 31 - Math.clz32(f); for (let g = 2; 31 - Math.clz32(g) <= d / 2; g++) if (31 - Math.clz32(g) >= 1 && pmod(f, g) === 0) return false; return true; };

const RULES = [
  // gcd, coprime, inverses
  [/Coprime: (\d+) and (\d+)/, (m) => [gcd(B(m[1]), B(m[2])) === 1n && N.gcd(B(m[1]), B(m[2])) === 1n, 'gcd = ' + gcd(B(m[1]), B(m[2]))]],
  [/(\d+) and (\d+): gcd (\d+)/, (m) => [gcd(B(m[1]), B(m[2])) === B(m[3]), 'gcd = ' + gcd(B(m[1]), B(m[2]))]],
  [/(\d+) and (\d+): an inverse/, (m) => [gcd(B(m[1]), B(m[2])) === 1n, 'gcd = ' + gcd(B(m[1]), B(m[2]))]],
  [/(\d+) modulo (\d+): its own inverse/, (m) => [(B(m[1]) * B(m[1])) % B(m[2]) === 1n, 'a² mod n = ' + (B(m[1]) * B(m[1])) % B(m[2])]],
  [/(\d+) modulo (\d+): no inverse/, (m) => [gcd(B(m[1]), B(m[2])) > 1n && N.inverse(B(m[1]), B(m[2])).inv == null, 'gcd = ' + gcd(B(m[1]), B(m[2]))]],
  [/^\{([0-9a-f]{2})\}: its own inverse/, (m) => { const G = S.GF.binary(8, 0x11bn), a = BigInt('0x' + m[1]); return [G.mul(a, a) === 1n, '']; }],
  [/^\{00\}: no inverse/, (m, v) => [v.a === '00', '']],
  // primes and their shapes
  [/^A prime: (\d+)$|^(\d+), a prime$/, (m) => [isPrime(m[1] || m[2]), '']],
  [/^A prime power: (\d+)$/, (m) => { const f = N.factor(B(m[1])); return [f.size === 1 && [...f.values()][0] > 1, '']; }],
  [/^Two primes: (\d+) = (\d+)·(\d+)$/, (m) => [B(m[2]) * B(m[3]) === B(m[1]) && isPrime(m[2]) && isPrime(m[3]), '']],
  [/^Many small primes: (\d+)$/, (m) => { const f = N.factor(B(m[1])); return [f.size >= 3 && [...f.values()].every((k) => k === 1) && [...f.keys()].every((p) => p < 20n), [...f.keys()].join('·')]; }],
  [/^(\d+): a prime with n − 1 = 2\^(\d+)$/, (m, v) => { const n = B(m[1]); let s = 0, d = n - 1n; while (!(d & 1n)) { d >>= 1n; s++; } return [isPrime(n) && s === +m[2] && B(v.n) === n, 's = ' + s]; }],
  [/^A (\d+)-bit prime, n − 1 = 2\^(\d+)·d$/, (m, v) => { const n = B(v.n); let s = 0, d = n - 1n; while (!(d & 1n)) { d >>= 1n; s++; } return [isPrime(n) && bitLen(n) === +m[1] && s === +m[2], bitLen(n) + ' bits, s = ' + s]; }],
  [/^A (\d+)-bit product of two primes$/, (m, v) => [!isPrime(v.n) && bitLen(v.n) === +m[1], bitLen(v.n) + ' bits']],
  [/^A tiny prime: (\d+) mod (\d+)$/, (m, v) => [isPrime(m[2]) && B(v.n) === B(m[2]) && B(v.a) === B(m[1]), '']],
  [/^A (\d+)-bit (safe )?prime$|^A larger prime$/, (m, v, tp) => {
    // a lab makes its prime from a seed: read it off the run's first frame
    const p = v.size === 'lab' ? B(tp.run(v).frames[0].facts.p) : v.p !== undefined ? B(v.p) : null;
    if (p === null) return [false, 'no p'];
    return [isPrime(p) && (!m[1] || bitLen(p) === +m[1]) && (!m[2] || isPrime((p - 1n) / 2n)), 'p = ' + p + ', ' + bitLen(p) + ' bits'];
  }],
  [/^p = (\d+), primes up to (\d+)$/, (m, v) => [isPrime(m[1]) && B(v.p) === B(m[1]) && +v.bound === +m[2], '']],
  [/^Z_(\d+): a field$/, (m, v) => [isPrime(m[1]) && +v.n === +m[1], '']],
  [/^Z_(\d+) is not a field$/, (m, v) => [!isPrime(m[1]) && +v.p === +m[1], '']],
  // orders and generators in Z_n*
  [/^Z_(\d+)\*: (?!no )(\w+) generators?$/, (m, v) => { const g = gens(m[1]).length, e = N.primitiveRoots(B(m[1])).length; return [g === num(m[2]) && e === g && +v.n === +m[1], g + ' generators']; }],
  [/^Z_(\d+)\*: no generator$/, (m) => [gens(m[1]).length === 0 && N.primitiveRoots(B(m[1])).length === 0, '']],
  [/^Z_(\d+)\*: cyclic though (\d+) is not prime$/, (m, v) => [gens(m[1]).length > 0 && !isPrime(m[2]) && ord(v.g, v.n) === phi(v.n), 'ord(g) = ' + ord(v.g, v.n)]],
  [/^Z_(\d+)\*: is (\d+) a generator\?$/, (m, v) => [+v.n === +m[1] && +v.g === +m[2], 'a question; the answer is the topic\'s']],
  [/^Z_(\d+)\*, H = ⟨(\d+)⟩ of order (\d+)$/, (m) => [ord(m[2], m[1]) === B(m[3]) && N.order(B(m[2]), B(m[1])).order === B(m[3]), 'ord = ' + ord(m[2], m[1])]],
  [/^A generator: H is everything$/, (m, v) => [ord(v.a, v.n) === phi(v.n), 'ord = ' + ord(v.a, v.n)]],
  [/^(\d+) mod (\d+): every unit$/, (m) => [ord(m[1], m[2]) === phi(m[2]), 'ord = ' + ord(m[1], m[2])]],
  [/^Not a generator: g = (\d+) mod (\d+)$/, (m, v) => [isPrime(m[2]) && ord(m[1], m[2]) !== B(m[2]) - 1n && +v.g === +m[1] && +v.p === +m[2], 'ord = ' + ord(m[1], m[2])]],
  [/\(lucky gcd\)/, (m, v) => [gcd(B(v.a), B(v.N)) > 1n, 'gcd = ' + gcd(B(v.a), B(v.N))]],
  // elliptic curves over small fields
  [/^A point of order 2$|^With the point \(0, 0\) of order 2$/, (m, v) => [ecPoint(v.P).y === 0n, 'P = ' + v.P]],
  [/^GF\((\d+)\): (\w+) points? of order 2$/, (m, v) => { const k = order2(B(v.p), B(v.a), B(v.b)); return [k === (m[2] === 'no' ? 0 : num(m[2])) && +v.p === +m[1], k + ' points']; }],
  [/^GF\((\d+)\): no point of order 2$/, (m, v) => { const k = order2(B(v.p), B(v.a), B(v.b)); return [k === 0, k + ' points']; }],
  [/^GF\((\d+)\)[,:]? (?:a point of order|prime order) (\d+)$/, (m, v) => {
    const C = S.ECC.curve({ p: B(v.p), a: B(v.a), b: B(v.b) }), P = ecPoint(v.P), o = Number(C.order(P).order), want = +m[2];
    let k = 1, Q = P; while (Q !== null) { Q = C.add(Q, P); k++; } // a plain count: add P until the point at infinity
    return [o === want && k === want && (!/prime order/.test(m[0]) || isPrime(want)), 'order ' + o + ' (counted ' + k + ')'];
  }],
  [/^GF\((\d+)\): a generator of Z(\S+)$/, (m, v) => { const C = S.ECC.curve({ p: B(v.p), a: B(v.a), b: B(v.b) }), n = +SUB(m[2]); return [Number(C.order(ecPoint(v.P)).order) === n && Number(C.count().N) === n, 'order ' + C.order(ecPoint(v.P)).order + ', #E = ' + C.count().N]; }],
  // LFSR feedback polynomials
  [/\(primitive\)$/, (m, v) => { const tp = v.taps.map(Number), n = Math.max(...tp), per = lfsrPeriod(tp); return [per === 2 ** n - 1 && irreducible(polyOf(tp)), 'period ' + per]; }],
  [/\(irreducible\)$/, (m, v) => { const tp = v.taps.map(Number); return [irreducible(polyOf(tp)), 'period ' + lfsrPeriod(tp)]; }],
  // counts and sizes the label states about its own inputs
  [/^(?:Toy|RSA-\d+): (\w+) shared primes?$/, (m, v) => [num(m[1]) === +v.pairs, 'pairs ' + v.pairs]],
  [/^Toy: all primes different$/, (m, v) => [+v.pairs === 0, '']],
  [/^RSA-(\d+), primes 2\^(\d+) apart/, (m, v) => [+v.gap === +m[2] && v.size === 'rsa' + m[1], '']],
  [/^(\w+) small primes$/, (m, v) => [num(m[1]) === +v.k, 'k = ' + v.k]],
  [/^(\w+) primes below (\d+)$/, (m, v) => [num(m[1]) === +v.k && +v.cap === +m[2], '']],
  [/^(\d+) bits, e = (\d+) \(some primes rejected\)$/, (m, v) => {
    const r = S.byId('p08-keygen'), out = r.run(S.inputOf(r, Object.assign(S.inputOf(r), v))), says = out.frames.map((f) => f.say).join(' ');
    return [+v.bits === +m[1] && +v.e === +m[2] && /reject|shares a factor|gcd\(e, p − 1\)|not coprime/i.test(says), ''];
  }],
];
// labels with a trigger word that state nothing to check, with the reason
const QUIET = [
  [/^Primer /, 'autokey primer, a word'], [/rotor order|order [IVX]/i, 'rotor order'], [/^Two orders, one nonce$/, 'orders as in purchases'],
  [/^Inverse S-box/, 'a table name'], [/^(Toy|128-bit|512-bit) primes/, 'the size of the CRT example, made by the engine'],
  [/^AES field:/, 'names the field; the product is checked by the topic claims'], [/^Toy key: halved\? multiply by the inverse$/, 'an instruction'],
  [/^A 200-bit smooth group$|^The MODP group: one big prime$|^The 2048-bit MODP (safe )?prime$/, 'made or loaded by the lab; covered by the data and lab tests'],
];
const TRIGGER = /coprime|prime|generator|gcd|\border\b|inverse|field|irreducible|primitive|smooth/i;

let checked = 0, quiet = 0;
for (const tp of S.topics) for (const p of tp.presets || []) {
  if (!TRIGGER.test(p.label)) continue;
  const v = S.inputOf(tp, Object.assign(S.inputOf(tp), p.values));
  const hit = RULES.map(([re, fn]) => [re.exec(p.label), fn]).find(([m]) => m);
  if (!hit) {
    if (QUIET.some(([re]) => re.test(p.label))) { quiet++; continue; }
    t.ok(false, `${tp.id} "${p.label}": no rule checks this label`);
    continue;
  }
  let res;
  try { res = hit[1](hit[0], v, tp); } catch (e) { res = [false, 'threw ' + e.message]; }
  checked++;
  t.ok(res[0], `${tp.id} "${p.label}" ${JSON.stringify(p.values)}: the label does not hold${res[1] ? ' (' + res[1] + ')' : ''}`);
}
t.ok(checked >= 40, 'labels checked: ' + checked);
console.log(`  ${checked} preset labels checked, ${quiet} with a trigger word but no claim`);
t.done();
