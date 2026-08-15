// Part 2, modular arithmetic and number theory: the families, and the small helpers its topics share.
(function (S) {
  'use strict';
  const fam = (id, order, title, blurb) => S.family({ id, part: 'numbers', order, title, blurb });
  fam('p02-modular', 10, 'Modular arithmetic', 'Arithmetic on a clock: residues, congruence classes, the ring Z_n with its tables, and inverses.');
  fam('p02-euclid', 20, 'Euclid', 'The greatest common divisor by repeated division, and the extended algorithm that finds the coefficients and the inverse.');
  fam('p02-euler', 30, 'Euler and Fermat', 'Euler\'s φ, powers that cycle, and the theorems of Fermat and Euler that make RSA work.');
  fam('p02-primality', 40, 'Testing for primes', 'Fermat\'s test and the Carmichael numbers that fool it, and the Miller–Rabin test that does not.');
  fam('p02-groups', 50, 'Groups', 'The order of an element, generators and primitive roots, cyclic subgroups, cosets and Lagrange\'s theorem.');
  fam('p02-crt', 60, 'The Chinese remainder theorem', 'Two clocks that together name every number below their product, the formula that finds it, and the speed-up it gives RSA.');
  fam('p02-fields', 70, 'Finite fields', 'GF(p), polynomials over GF(2), GF(2^m) with shift-and-add and reduction, inversion by Euclid, and the AES field.');

  const H = (S.P02 = {});
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  H.B = B;
  /** a number for a sentence, with a true minus sign; long ones keep their ends */
  H.n = (v) => S.NT.short(v).replace('-', '−');
  /** a whole number from an input (a number or a string of digits) */
  H.big = (v) => B(String(v).trim());
  /** a free text item */
  H.text = (key, x, y, text, cls, size, anchor) => { const it = { key, kind: 'text', x, y, text, cls: cls || 'strong' }; if (size) it.size = size; if (anchor) it.anchor = anchor; return it; };
  H.title = (key, x, y, text, cls) => ({ key, kind: 'text', x, y, text, cls: 'title' + (cls ? ' ' + cls : '') });
  /** lines of equations, each [text, cls] */
  H.eqs = (prefix, x, y, lines, size, gap) => S.Kit.nt.eqs({ prefix, x, y, lines, size, gap });
  /** "1 item" / "2 items" */
  H.plural = (k, word, many) => k + ' ' + (Number(k) === 1 ? word : many || word + 's');
  /** a list in words: "3, 5 and 7" */
  H.list = (xs) => { xs = xs.map(String); return xs.length < 2 ? xs.join('') : xs.slice(0, -1).join(', ') + ' and ' + xs[xs.length - 1]; };
  /** a whole-number input that must lie between lo and hi (BigInt-safe, for kind 'bigint') */
  H.range = (lo, hi, what) => (v) => { let x; try { x = H.big(v); } catch (e) { return (what || 'This') + ': a whole number'; } if (x < B(lo)) return (what || 'This') + ': at least ' + lo; if (hi !== undefined && x > B(hi)) return (what || 'This') + ': at most ' + hi; return null; };
  H.isPrime = (v) => S.NT.isProbablePrime(B(v));
  /** the class of a residue colour: k0 … k7 */
  H.kc = (r) => 'k' + (Number(r) % 8);
  H.sup = (k) => String(k).split('').map((d) => '⁰¹²³⁴⁵⁶⁷⁸⁹'[d] || d).join('');
})(globalThis.Sifer = globalThis.Sifer || {});
