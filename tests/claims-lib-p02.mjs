// The checking machinery of tests/claims-p02.mjs: an arithmetic of its own (BigInt, written apart from the engines),
// a reader that finds every equation and congruence a sentence states and works each one out again, and the
// wording checks (a/an, doubled words, stray spaces).

// ---- arithmetic, independent of src/core -------------------------------------------------------------------------
export const md = (a, n) => ((a % n) + n) % n;
export const gcd = (a, b) => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a; };
export const pw = (b, e, n) => { let r = 1n % n; b = md(b, n); while (e > 0n) { if (e & 1n) r = (r * b) % n; b = (b * b) % n; e >>= 1n; } return r; };
/** the inverse by a plain search for small n, by Fermat-free extended Euclid otherwise (recursive, unlike the engine) */
export const inv = (a, n) => {
  a = md(a, n);
  const eg = (x, y) => (y === 0n ? [x, 1n, 0n] : (([g, s, t]) => [g, t, s - (x / y) * t])(eg(y, x % y)));
  const [g, s] = eg(a, n);
  return g === 1n ? md(s, n) : null;
};
/** prime factors by trial division (small numbers only) */
export const factors = (n) => { n = BigInt(n); const out = new Map(); for (let p = 2n; p * p <= n; p++) while (n % p === 0n) { out.set(p, (out.get(p) || 0) + 1); n /= p; } if (n > 1n) out.set(n, (out.get(n) || 0) + 1); return out; };
export const phi = (n) => { n = BigInt(n); let c = 0n; if (n < 100000n) { for (let k = 1n; k <= n; k++) if (gcd(k, n) === 1n) c++; return c; } let r = n; for (const [p] of factors(n)) r = (r / p) * (p - 1n); return r; };
export const isPrime = (n) => { n = BigInt(n); if (n < 2n) return false; for (let p = 2n; p * p <= n && p < 1000000n; p++) if (n % p === 0n) return false; if (n < 10n ** 12n) return true; for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n]) { let d = n - 1n, s = 0; while (!(d & 1n)) { d >>= 1n; s++; } let x = pw(a, d, n); if (x === 1n || x === n - 1n) continue; let ok = false; for (let i = 1; i < s; i++) { x = (x * x) % n; if (x === n - 1n) { ok = true; break; } } if (!ok) return false; } return true; };

// ---- expressions -------------------------------------------------------------------------------------------------
const SUP = { '⁰': '0', '¹': '1', '²': '2', '³': '3', '⁴': '4', '⁵': '5', '⁶': '6', '⁷': '7', '⁸': '8', '⁹': '9' };
/**
 * Evaluate a whole-number expression: digits, + − · × ^ (or superscript digits), parentheses, a postfix ⁻¹ (needs a
 * modulus), 'mod', gcd(x, y), φ(x), lcm(x, y). Returns a BigInt, or null when the text is not such an expression.
 * With a modulus m, powers and inverses are taken modulo m (the result is then only meaningful modulo m).
 */
export function evaluate(text, m) {
  let s = text.replace(/\s+/g, ' ').trim();
  if (!s) return null;
  // superscript exponents become ^n, ⁻¹ becomes a postfix mark
  s = s.replace(/⁻¹/g, '~').replace(/[⁰¹²³⁴⁵⁶⁷⁸⁹]+/g, (x) => '^' + [...x].map((c) => SUP[c]).join(''));
  const toks = s.match(/\d+|gcd|lcm|φ|mod|[-−+·×^()~,]|\S/g) || [];
  let i = 0;
  const peek = () => toks[i], next = () => toks[i++];
  const fail = () => { throw new Error('no'); };
  const unit = () => {
    const t = next();
    if (t === undefined) fail();
    if (/^\d+$/.test(t)) return BigInt(t);
    if (t === '(') { const v = sum(); if (next() !== ')') fail(); return v; }
    if (t === '−' || t === '-') return -factor();
    if (t === 'gcd' || t === 'lcm' || t === 'φ') {
      if (next() !== '(') fail();
      const a = sum();
      if (t === 'φ') { if (next() !== ')') fail(); return phi(a); }
      if (next() !== ',') fail();
      const b = sum();
      if (next() !== ')') fail();
      return t === 'gcd' ? gcd(a, b) : (a / gcd(a, b)) * b;
    }
    fail();
  };
  const factor = () => {
    let v = unit();
    for (;;) {
      if (peek() === '^') { next(); const e = factorNoPost(); if (m) v = e < 0n ? pw(inv(v, m), -e, m) : pw(v, e, m); else { if (e < 0n || e > 4096n) fail(); v = v ** e; } continue; }
      if (peek() === '~') { next(); if (!m) fail(); const x = inv(v, m); if (x === null) fail(); v = x; continue; }
      return v;
    }
  };
  const factorNoPost = () => { const t = peek(); if (t === '(') return unit(); if (t === '−' || t === '-') { next(); return -unit(); } return unit(); };
  const term = () => { let v = factor(); while (peek() === '·' || peek() === '×') { next(); v *= factor(); } return v; };
  const sum0 = () => { let v = term(); while (peek() === '+' || peek() === '−' || peek() === '-') { const o = next(); v = o === '+' ? v + term() : v - term(); } return v; };
  const sum = () => { let v = sum0(); while (peek() === 'mod') { next(); const n = sum0(); if (n <= 0n) fail(); v = md(v, n); } return v; };
  try { const v = sum(); if (i !== toks.length) return null; return v; } catch (e) { return null; }
}

// ---- claims in a sentence ----------------------------------------------------------------------------------------
const REL = /\s(=|≡|≢)\s/g;
/** the clauses of a sentence: split at colons, semicolons, full stops and at "so", "and", "since", "but" */
function clauses(say) {
  return say.replace(/\b(Z_|GF|[a-z]_)\d+/g, (x) => x.replace(/\d/g, 'N')).split(/(?<=[.;:!?])\s+|,\s(?![^()]*\))|\s(?:so|and|since|but|while|then|giving|gives|because|which|that|or)\s|\s—\s|\s–\s/);
}
/**
 * Every chain "A rel B rel C … (mod n)" in a sentence, worked out again: = between exact values (or values modulo n
 * inside a congruence), ≡ and ≢ modulo n. Calls bad(msg) for each claim that is false; returns the number checked.
 */
export function checkArithmetic(say, bad, opts = {}) {
  let checked = 0;
  for (const cl of clauses(say)) {
    if (!/[=≡≢]/.test(cl)) continue;
    const mm = /\(mod (\d+)\)/.exec(cl);
    const m = mm ? BigInt(mm[1]) : opts.mod ? BigInt(opts.mod) : null;
    const body = mm ? cl.slice(0, mm.index) : cl;
    const rels = [...body.matchAll(REL)];
    if (!rels.length) continue;
    // the operands between the relations
    const parts = [];
    let from = 0;
    for (const r of rels) { parts.push(body.slice(from, r.index)); from = r.index + r[0].length; }
    parts.push(body.slice(from));
    const words = (t) => t.trim().split(' ');
    const lastParse = (t, mod) => { const w = words(t); for (let k = 0; k < w.length; k++) { let t2 = w.slice(k).join(' '); if (k > 0 && /^[−+·×^-]$/.test(w[k])) continue; if (k > 0 && /^[−+·×^-]$/.test(w[k - 1])) continue; while (t2.startsWith('(') && (t2.match(/\(/g) || []).length > (t2.match(/\)/g) || []).length) t2 = t2.slice(1); const v = evaluate(t2, mod); if (v !== null) return v; } return null; };
    const firstParse = (t, mod) => { const w = words(t); for (let k = w.length; k > 0; k--) { let t2 = w.slice(0, k).join(' ').replace(/[.,;:]+$/, ''); while ((t2.match(/\)/g) || []).length > (t2.match(/\(/g) || []).length) t2 = t2.replace(/\)[.,;:]*$/, ''); const v = evaluate(t2, mod); if (v !== null) return v; } return null; };
    const valsOf = (mod) => parts.map((p, k) => (k === 0 ? lastParse(p, mod) : k === parts.length - 1 ? firstParse(p, mod) : evaluate(p, mod)));
    const vals = valsOf(m), exact = m ? valsOf(null) : vals;
    for (let k = 0; k < rels.length; k++) {
      const a = vals[k], b = vals[k + 1], op = rels[k][1];
      if (a === null || b === null) continue;
      checked++;
      // an equals sign means equal numbers, also inside a congruence (when both sides need no modulus to work out)
      if (op === '=' && exact[k] !== null && exact[k + 1] !== null) { if (exact[k] !== exact[k + 1]) bad('"' + parts[k].trim() + ' = ' + parts[k + 1].trim() + '" is false (' + exact[k] + ' ≠ ' + exact[k + 1] + ')'); }
      else if (op === '=' && !m && a !== b) bad('"' + parts[k].trim() + ' = ' + parts[k + 1].trim() + '" is false (' + a + ' ≠ ' + b + ')');
      else if ((op === '≡' || (op === '=' && m)) && m && md(a - b, m) !== 0n) bad('"' + parts[k].trim() + ' ' + op + ' ' + parts[k + 1].trim() + ' (mod ' + m + ')" is false');
      else if (op === '≢' && m && md(a - b, m) === 0n) bad('"' + parts[k].trim() + ' ≢ ' + parts[k + 1].trim() + ' (mod ' + m + ')" is false');
      else if ((op === '≡' || op === '≢') && !m) checked--;
    }
  }
  return checked;
}

// ---- wording -----------------------------------------------------------------------------------------------------
const VOWEL_SOUND = /^(8|11|18|80|8\d|11\d|18\d|[aeiouAEIOU](?!ni|nu|se|sa|su|t\b)|x\b|n\b|n-|m\b|f\b|h\b|l\b|r\b|s\b|x-|S-box|RSA|LFSR|MR|FIPS|NIST|honest|hour|L\d|F\b|H\b|M\b|N\b|R\b|S\b|X\b|ord)/;
const CONSONANT_FORCED = /^(one|once|uni|use|usu|eu|ur)/;
export function wording(say) {
  const s = (say || '').replace(/"[^"]*"/g, '"…"'), out = [];
  if (/\S {2,}\S/.test(s)) out.push('a double space');
  if (/\s[,.;:](\s|$)/.test(s)) out.push('a space before punctuation');
  if (/\.\./.test(s.replace(/\.\.\./g, ''))) out.push('two full stops');
  for (const m of s.matchAll(/\b([A-Za-z]{2,}) \1\b/g)) if (!/^(that|had)$/i.test(m[1])) out.push('the word "' + m[1] + '" twice');
  for (const m of s.matchAll(/(^|[^\w'′])(a|an|A|An) ([\w′'−-]+)/g)) {
    const art = m[2].toLowerCase(), w = m[3];
    // a and b are often names of numbers: "a and b", "a is", "a ≡ b"
    if (/^(and|is|or|b|n|x|mod|to|in|has|was|with|lies|sits|itself|exactly|by|are|has|gives|times)$/.test(w)) continue;
    const vowel = VOWEL_SOUND.test(w) && !CONSONANT_FORCED.test(w.toLowerCase());
    if (art === 'a' && vowel && !/^[A-Z]$/.test(w)) out.push('"a ' + w + '"');
    if (art === 'an' && !vowel && !/^[aeiou]/i.test(w)) out.push('"an ' + w + '"');
  }
  if (/\b(the|a|an|of|to|is) \1\b/i.test(s) || /\b(a|an|the) (a|an|the)\b/.test(s)) out.push('a doubled small word');
  if (/undefined|NaN|null|\[object/.test(s)) out.push('a broken value');
  return out;
}
