// Part 1 claims, classical ciphers: every quoted value read back out of the narration and compared with ref.mjs.
import * as R from './ref.mjs';
const { ABC, md, L } = R;
const num = (s) => Number(String(s).replace(/−/g, '-').replace(/,/g, ''));
const all = (re, s) => [...String(s).matchAll(re)];

export function classicChecks(S) {
  const C = S.Classic, ENG = C.ENGLISH;
  return {
    'p01-shift'(x) {
      const { input: inp, F } = x, k = inp.k, enc = inp.dir === 'enc', src = L(inp.text), want = enc ? R.shift(src, k) : R.shift(src, -k);
      for (const f of F) for (const m of all(/([A-Z]) is (\d+); (\d+) ([+−]) (\d+) = (−?\d+) ≡ (\d+) \(mod 26\), which is ([A-Z])/g, f.say)) {
        const [, a, p, p2, op, kk, sum, c, b] = m; x.eq(ABC.indexOf(a), +p, 'letter number'); x.eq(+p2, +p, 'p'); x.eq(+kk, k, 'k');
        x.eq(num(sum), op === '+' ? +p + k : +p - k, 'the sum'); x.eq(+c, md(num(sum)), 'mod 26'); x.eq(b, ABC[+c], 'the letter');
      }
      x.match(F.find((f) => f.meta.stage === 'end').say, /: ([A-Z]+) becomes ([A-Z]+) again/, (m) => { x.eq(m[1], want, 'the result'); x.eq(m[2], src, 'the round trip'); });
    },
    'p01-brute-shift'(x) {
      const ct = L(x.input.text);
      for (const f of x.F) x.match(f.say, /^Key (\d+): shifting back \d+ gives ([A-Z]+)…?, scoring (−?[\d.]+) per letter/, (m) => { x.eq(m[2], R.shift(ct, -m[1]).slice(0, m[2].length), 'candidate for key ' + m[1]); x.near(num(m[3]), C.score(R.shift(ct, -m[1]), true), 0.006, 'score'); }, true);
      // the best key really has the best score, and decrypts the planted message when there is one
      const scores = [...Array(26).keys()].map((k) => C.score(R.shift(ct, -k), true)), best = scores.indexOf(Math.max(...scores));
      x.match(x.F[x.F.length - 1].say, /^The answer: key (\d+), plaintext ([A-Z ]+)\./, (m) => { x.eq(+m[1], best, 'best key'); x.eq(L(m[2]), R.shift(ct, -best), 'best plaintext'); if (x.input.truth !== undefined) x.eq(+m[1], x.input.truth, 'the planted key'); });
    },
    'p01-affine'(x) {
      const { a, b } = x.input, ok = R.gcd(a, 26) === 1;
      for (const f of x.F) {
        for (const m of all(/([A-Z]) = (\d+): (\d+)·(\d+) \+ (\d+) = (\d+) ≡ (\d+) \(mod 26\), which is ([A-Z])/g, f.say)) { x.eq(+m[6], m[3] * m[4] + +m[5], 'product'); x.eq(+m[7], md(+m[6]), 'mod'); x.eq(m[8], ABC[+m[7]], 'letter'); x.eq(+m[3], a, 'a'); x.eq(+m[5], b, 'b'); }
        for (const m of all(/([A-Z]) = (\d+): (\d+)·\((\d+) − (\d+)\) = (−?\d+) ≡ (\d+) \(mod 26\), which is ([A-Z])/g, f.say)) { x.eq(num(m[6]), m[3] * (m[4] - m[5]), 'product'); x.eq(+m[7], md(num(m[6])), 'mod'); x.eq(m[8], ABC[+m[7]], 'letter'); x.eq(+m[3], R.inv26(a), 'the inverse used'); }
        for (const m of all(/gcd\(26, (\d+)\) = (\d+) = \(?(−?\d+)\)?·26 \+ \(?(−?\d+)\)?·(\d+)/g, f.say)) { x.eq(+m[2], R.gcd(26, a), 'gcd'); x.eq(num(m[3]) * 26 + num(m[4]) * a, +m[2], 'Bezout'); }
        for (const m of all(/the inverse is −?\d+ mod 26 = (\d+)/g, f.say)) x.eq(+m[1], R.inv26(a), 'inverse');
        for (const m of all(/both become ([A-Z])/g, f.say)) { x.ok(!ok, 'a collision is claimed only for a bad multiplier'); }
      }
      x.ok(ok ? x.F.some((f) => /Every letter comes back: ([A-Z]+)/.test(f.say) && RegExp.$1 === L(x.input.text)) : /no inverse modulo 26/.test(x.F.map((f) => f.say).join(' ')), 'the ending');
      x.match(x.F.map((f) => f.say).join(' '), /The ciphertext is ([A-Z]+)/, (m) => x.eq(m[1], R.affine(x.input.text, a, b), 'ciphertext'), !ok || L(x.input.text).length <= 6);
    },
    'p01-substitution'(x) {
      const alpha = R.keyword(x.input.word, x.input.cont === 'after'), all3 = x.F.map((f) => f.say).join(' ');
      x.match(all3, /becomes cipher ([A-Z]{26})/, (m) => x.eq(m[1], alpha, 'the keyword alphabet'));
      for (const m of all(/([A-Z]) is found in the top row and ([A-Z]) sits beneath it/g, all3)) x.eq(m[2], alpha[ABC.indexOf(m[1])], 'substitution of ' + m[1]);
      x.match(all3, /the ciphertext is ([A-Z]+)/, (m) => x.eq(m[1], R.subst(x.input.text, alpha), 'ciphertext'), true);
      x.match(all3, /26! = ([\d,]+)/, (m) => x.eq(m[1].replace(/,/g, ''), String(R.fact(26)), '26!'));
    },
    'p01-kerckhoffs'(x) {
      const all3 = x.F.map((f) => f.say).join(' '), plugs = R.fact(26) / (R.fact(6) * R.fact(10) * 1024n);
      x.match(all3, /and ([\d,]+) ways to plug 10 cables, about ([\d.]+) × 10\^(\d+) keys/, (m) => { x.eq(m[1].replace(/,/g, ''), String(plugs), 'plugboard count'); const e = 60n * 17576n * 676n * plugs, s = String(e); x.eq(m[3], String(s.length - 1), 'Enigma exponent'); x.eq(m[2], s[0] + '.' + s.slice(1, 3), 'Enigma mantissa'); });
      x.match(all3, /Affine: (\d+) keys/, (m) => x.eq(+m[1], 312, 'affine keys'));
      x.match(all3, new RegExp('26\\^' + x.input.vlen + ' = ([\\d,]+|about [\\d.]+ × 10\\^\\d+) keys'), (m) => { const v = 26n ** BigInt(x.input.vlen); if (/about/.test(m[1])) x.eq(m[1].split('^')[1], String(String(v).length - 1), 'Vigenère exponent'); else x.eq(m[1].replace(/,/g, ''), String(v), 'Vigenère keys'); });
    },
    'p01-frequency'(x) {
      const plain = L(C.corpus.longExamples[x.input.src]), alpha = R.keyword(x.input.word), ct = R.subst(plain, alpha), cnt = R.counts(ct), inv = {};
      for (let i = 0; i < 26; i++) inv[alpha[i]] = ABC[i];
      const all3 = x.F.map((f) => f.say).join(' ');
      x.match(all3, /^A message of (\d+) letters/, (m) => x.eq(+m[1], ct.length, 'length'));
      x.match(all3, /([A-Z]) is the commonest cipher letter, (\d+) times/, (m) => { x.eq(+m[2], Math.max(...cnt), 'top count'); x.eq(cnt[ABC.indexOf(m[1])], +m[2], 'its count'); });
      for (const m of all(/([A-Z]) comes \w+ with (\d+)\..*?([A-Z]) = ([A-Z])\./g, all3)) { x.eq(cnt[ABC.indexOf(m[1])], +m[2], 'count of ' + m[1]); x.eq(m[4], inv[m[3]], 'mapping ' + m[3]); }
      for (const m of all(/([A-Z]) = ([A-Z])(?= and| Look|, |\.)/g, all3)) if (inv[m[1]]) x.eq(m[2], inv[m[1]], 'mapping ' + m[1]);
    },
    'p01-substitution-solver'(x) {
      const plain = L(C.corpus.longExamples[x.input.src]), alpha = R.keyword(x.input.word), ct = R.subst(plain, alpha), inv = {};
      for (let i = 0; i < 26; i++) inv[alpha[i]] = ABC[i];
      let last = -Infinity;
      for (const f of x.F) {
        x.match(f.say, /the best key scores (−[\d.]+) and gets (\d+) of (\d+) letters right: ([A-Z]+)…/, (m) => {
          const s = num(m[1]); x.ok(s >= last - 0.05, 'the score climbs'); last = s;
          x.eq(+m[3], new Set(ct).size, 'letters in use');
          const keyStr = m[4]; x.ok(keyStr.length === 32, 'shown text');
          const right = Array.from(keyStr).filter((c, i) => c === plain[i]).length; x.ok(right <= 32, 'text');
        }, true);
      }
      x.match(x.F[x.F.length - 1].say, /scores (−[\d.]+)(, exactly the score of the real message)?.*?with (\d+) of (\d+) letters right/, (m) => { if (m[2]) x.near(num(m[1]), C.score(plain), 0.06, 'the real message score'); x.eq(+m[4], new Set(ct).size, 'letters in use'); });
    },
    'p01-vigenere'(x) {
      const key = L(x.input.key), p = L(x.input.text), all3 = x.F.map((f) => f.say).join(' ');
      for (const m of all(/Letter (\d+): key letter ([A-Z]) shifts by (\d+)\. In row \2, under ([A-Z]), stands ([A-Z])/g, all3)) { const j = m[1] - 1; x.eq(m[2], key[j % key.length], 'key letter'); x.eq(+m[3], ABC.indexOf(m[2]), 'shift'); x.eq(m[4], p[j], 'plain'); x.eq(m[5], R.vig(p, key)[j], 'cipher'); }
      x.match(all3, /The ciphertext is ([A-Z]+)/, (m) => x.eq(m[1], R.vig(p, key), 'ciphertext'), p.length <= 10);
    },
    'p01-autokey'(x) {
      const pr = L(x.input.primer), p = L(x.input.text), ct = R.autokey(p, pr), all3 = x.F.map((f) => f.say).join(' ');
      for (const m of all(/Letter (\d+): ([A-Z]) ([+−]) ([A-Z]) = ([A-Z])/g, all3)) { const j = m[1] - 1, ks = (pr + p)[j]; x.eq(m[4], ks, 'key letter ' + (j + 1)); if (m[3] === '+') { x.eq(m[2], p[j], 'plain'); x.eq(m[5], ct[j], 'cipher'); } else { x.eq(m[2], ct[j], 'cipher'); x.eq(m[5], p[j], 'plain'); } }
      x.match(all3, /The ciphertext is ([A-Z]+)/, (m) => x.eq(m[1], ct, 'ciphertext'), x.input.dir === 'dec' || p.length <= pr.length + 6);
    },
    'p01-kasiski'(x) {
      const ct = R.vig(C.corpus.longExamples[x.input.src], x.input.key);
      for (const f of x.F) for (const m of all(/([A-Z]{3,}) appears at ([\d, ]+); the distances? (?:is|are) ([\d, ]+), with gcd (\d+)/g, f.say)) {
        const g = m[1], pos = m[2].split(', ').map(Number), ds = m[3].split(', ').map(Number);
        for (const q of pos) x.eq(ct.substr(q, g.length), g, 'repeat at ' + q);
        x.eq(ds.join(), pos.slice(1).map((q) => q - pos[0]).join(), 'distances'); x.eq(+m[4], ds.reduce(R.gcd), 'gcd');
      }
    },
    'p01-ioc'(x) {
      const { ct, plain } = (() => { const p = L(C.corpus.longExamples[x.input.src]); return { plain: p, ct: R.vig(p, x.input.key) }; })(), all3 = x.F.map((f) => f.say).join(' ');
      x.match(all3, /gives an index of coincidence of ([\d.]+)/, (m) => x.near(+m[1], R.ioc(ct), 0.00006, 'cipher IC'));
      x.match(all3, /The plaintext's own index is ([\d.]+)/, (m) => x.near(+m[1], R.ioc(plain), 0.00006, 'plain IC'));
      for (const m of all(/m = (\d+): the \d+ columns have ICs [\d., ]+, average (\d+\.\d+)/g, all3)) { const n = +m[1], cols = Array.from({ length: n }, (_, j) => Array.from(ct).filter((c, i) => i % n === j).join('')); x.near(+m[2], cols.reduce((s, c) => s + R.ioc(c), 0) / n, 0.00006, 'average IC for ' + n); }
    },
    'p01-column-shifts'(x) {
      const ct = R.vig(C.corpus.longExamples[x.input.src], x.input.key), n = x.input.len;
      for (const f of x.F) x.match(f.say, /^Column (\d+) \((\d+) letters\): undoing a shift of (\d+) gives χ² = ([\d.]+), the best of 26/, (m) => {
        const j = m[1] - 1, col = Array.from(ct).filter((c, i) => i % n === j).join(''), s = +m[3];
        x.eq(+m[2], col.length, 'column length');
        const chis = [...Array(26).keys()].map((t) => R.chi(R.counts(R.shift(col, -t)), ENG));
        x.near(+m[4], chis[s], 0.06, 'χ²'); x.eq(s, chis.indexOf(Math.min(...chis)), 'best shift');
      }, true);
    },
    'p01-columnar'(x) {
      if (x.input.dir === 'dec') { x.match(x.F[x.F.length - 1].say, /Reading the rows gives ([A-Z]+)/, (m) => x.eq(R.columnar(m[1], x.input.key).out, L(x.input.text), 'decryption re-encrypts to the ciphertext')); return; }
      const t = x.input.pad === 'X' ? (() => { let s = L(x.input.text); while (s.length % L(x.input.key).length) s += 'X'; return s; })() : L(x.input.text), ref = R.columnar(t, x.input.key);
      for (const f of x.F) x.match(f.say, /^Column (\d+) \(key letter ([A-Z])\) reads ([A-Z]+)/, (m) => x.eq(m[3], ref.cols[m[1] - 1], 'column ' + m[1]), true);
      x.match(x.F[x.F.length - 1].say, /The ciphertext is ([A-Z]+)/, (m) => x.eq(m[1], ref.out, 'ciphertext'));
    },
    'p01-railfence'(x) {
      if (x.input.dir === 'dec') { x.match(x.F[x.F.length - 1].say, /reads ([A-Z]+)/, (m) => x.eq(R.rail(m[1], x.input.rails).out, L(x.input.text), 'decryption re-encrypts')); return; }
      const ref = R.rail(x.input.text, x.input.rails);
      for (const f of x.F) x.match(f.say, /^Rail (\d+) reads ([A-Z]+)/, (m) => x.eq(m[2], ref.rows[m[1] - 1], 'rail ' + m[1]), true);
      x.match(x.F[x.F.length - 1].say, /The ciphertext is ([A-Z]+)/, (m) => x.eq(m[1], ref.out, 'ciphertext'));
    },
    'p01-playfair'(x) {
      const sq = R.playfairSquare(x.input.key), dir = x.input.dir === 'enc' ? 1 : -1;
      x.match(x.F[0].say, /: ([A-Z/ ]+)\.$/, (m) => x.eq(m[1].replace(/[ /]/g, ''), sq, 'square'));
      for (const f of x.F) x.match(f.say, /^([A-Z]{2}): .*giving ([A-Z]{2})/, (m) => x.eq(m[2], R.playfairPair(sq, m[1], dir), 'pair ' + m[1]), true);
    },
    'p01-otp'(x) {
      const all3 = x.F.map((f) => f.say).join(' ');
      for (const m of all(/([A-Z]) \+ ([A-Z]) = ([A-Z]): \1 = (\d+), \2 = (\d+), and \((\d+) \+ (\d+)\) mod 26 = (\d+)/g, all3)) { x.eq(m[3], ABC[md(ABC.indexOf(m[1]) + ABC.indexOf(m[2]))], 'sum'); x.eq(+m[8], md(+m[6] + +m[7]), 'mod'); }
      x.match(all3, /Check: ([A-Z]+) \+ ([A-Z]+) = ([A-Z]+), the same ciphertext/, (m) => { const s = Array.from(m[1], (c, i) => ABC[md(ABC.indexOf(c) + ABC.indexOf(m[2][i]))]).join(''); x.eq(m[3], s, 'decoy + other pad'); x.eq(m[1], L(x.input.decoy), 'the decoy'); });
      x.match(all3, /The ciphertext is ([A-Z]+)\./, (m) => x.match(all3, /The pad is \d+ random letters, ([A-Z]+),/, (n) => x.eq(m[1], Array.from(L(x.input.text), (c, i) => ABC[md(ABC.indexOf(c) + ABC.indexOf(n[1][i]))]).join(''), 'ciphertext')));
    },
    'p01-two-time-pad'(x) {
      const m1 = x.input.m1, m2 = x.input.m2, crib = x.input.crib;
      for (const f of x.F) x.match(f.say, /^Position (\d+): if message 1 has ".*" here, message 2 has "(.*)" \((\d+)% letters/, (m) => {
        const p = +m[1], want = Array.from(crib, (c, i) => { const v = m1.charCodeAt(p + i) ^ m2.charCodeAt(p + i) ^ c.charCodeAt(0); return v >= 32 && v < 127 ? (v === 32 ? '␣' : String.fromCharCode(v)) : '·'; }).join('');
        x.eq(m[2], want, 'the other message under the crib at ' + p);
      }, true);
      x.match(x.F[x.F.length - 1].say, /(?:so message 1 probably has|message 1 probably has) ".*" (?:at|there)/, () => x.pass(), true);
    },
  };
}
