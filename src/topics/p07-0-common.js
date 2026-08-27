// Parts 7, 8 and 9 (public keys, RSA, the discrete logarithm): the families, the real-size keys and groups made
// from the numbers in p07-0-data.js, cost models for the security tables, and the small helpers the topics share.
// Every frame these topics add carries `facts`: the values its narration quotes, by name, taken from the engines,
// so tests/claims-p07.mjs, claims-p08.mjs and claims-p09.mjs can check each one against an independent working-out.
(function (S) {
  'use strict';
  const fam = (id, part, order, title, blurb) => S.family({ id, part, order, title, blurb });
  fam('p07-why', 'pubkey', 10, 'Why public keys', 'Too many shared keys for too many people, and functions that are easy one way and hard the other unless you hold a trapdoor.');
  fam('p07-use', 'pubkey', 20, 'Public keys at work', 'What public keys are for, how long they must be, and why they always travel with a symmetric cipher.');
  fam('p08-scheme', 'rsa', 10, 'The RSA scheme', 'Two random primes found with Miller–Rabin, encryption and decryption, and Euler\'s theorem that makes them inverse.');
  fam('p08-speed', 'rsa', 20, 'Making RSA fast', 'Square-and-multiply in both directions, the Montgomery ladder and Montgomery multiplication, the CRT and small public exponents.');
  fam('p08-padding', 'rsa', 30, 'Padding', 'Why raw RSA must never be used: malleable and deterministic. OAEP for encryption and PSS for signatures, field by field.');
  fam('p08-attacks', 'rsa', 40, 'Attacks on RSA', 'Small exponents, a shared modulus, a broadcast, a small d, close primes, shared primes, one fault and a stopwatch.');
  fam('p08-sizes', 'rsa', 50, 'Toy and real', 'The same formulas on two-digit primes and on real keys, side by side.');
  fam('p09-problem', 'dlp', 10, 'The problem', 'Powers of a generator that jump around a cycle, and the logarithm that undoes them.');
  fam('p09-protocols', 'dlp', 20, 'Diffie–Hellman and Elgamal', 'A shared secret from public mixtures, the attacker who sits in the middle, and encryption built on the same idea.');
  fam('p09-attacks', 'dlp', 30, 'Computing logarithms', 'Baby-step giant-step, Pollard\'s rho, Pohlig–Hellman, index calculus, and small subgroups.');
  fam('p09-signatures', 'dlp', 40, 'Signatures from logarithms', 'Elgamal, DSA and Schnorr signatures, and the nonce that must never repeat.');

  const P = (S.PK = S.PK || {});
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  P.B = B;
  const NT = () => S.NT;
  const hexB = (h) => BigInt('0x' + h);

  // ---- numbers in sentences -------------------------------------------------------------------------------------
  /** a number for a sentence: whole up to 24 digits; longer ones keep their first and last 10 digits and say how long */
  P.n = (v) => { const s = B(v).toString().replace('-', '−'); const d = s.replace('−', '').length; return d > 24 ? s.slice(0, s.length - d + 10) + '…' + s.slice(-10) + ' (' + d + ' digits)' : s; };
  /** the digits of a number (for the claims check: an abbreviated number counts as quoted when its ends match) */
  P.digits = (v) => B(v).toString().replace('-', '').length;
  P.bits = (v) => NT().bitLength(v);
  P.plural = (k, word, many) => k + ' ' + (Number(k) === 1 ? word : many || word + 's');
  P.list = (xs) => { xs = xs.map(String); return xs.length < 2 ? xs.join('') : xs.slice(0, -1).join(', ') + ' and ' + xs[xs.length - 1]; };
  P.sup = (k) => String(k).split('').map((d) => '⁰¹²³⁴⁵⁶⁷⁸⁹'[d] || (d === '−' || d === '-' ? '⁻' : d)).join('');
  P.sub = (k) => String(k).split('').map((d) => '₀₁₂₃₄₅₆₇₈₉'[d] || d).join('');
  /** "a" or "an" before a number word as it is read aloud (8, 11, 18, 80… start with a vowel sound) */
  P.an = (v) => { const s = String(v).replace(/[−-]/, ''); return (s[0] === '8' || (/^1[18]/.test(s) && (s.length - 2) % 3 === 0) ? 'an ' : 'a ') + v; };

  // ---- stage helpers ----------------------------------------------------------------------------------------------
  const r2 = (v) => Math.round(v * 100) / 100;
  P.r2 = r2;
  P.t = (key, x, y, text, cls, anchor, size) => { const it = { key, kind: 'text', x: r2(x), y: r2(y), text, cls: cls || '', anchor: anchor || 'start' }; if (size) it.size = size; return it; };
  P.title = (key, x, y, text, anchor) => ({ key, kind: 'text', x, y, text, cls: 'title', anchor: anchor || 'start' });
  P.eqs = (prefix, x, y, lines, size, gap) => S.Kit.nt.eqs({ prefix, x, y, lines, size: size || 16, gap });
  P.panel = (key, x, y, w, h, title, cls) => [{ key, kind: 'region', x, y, w, h, rx: 10, cls: 'panel ' + (cls || '') }].concat(title ? [{ key: key + ':t', kind: 'text', x: x + 14, y: y + 22, text: title, cls: 'title' }] : []);
  /** the definition panel from math lines */
  P.def = (title, lines, more) => ({ sections: [{ id: 'd', kind: 'math', title, text: lines.join('\n') }].concat(more || []) });
  /** the same camera for every frame */
  P.fix = (frames, box) => { for (const f of frames) f.view = Object.assign({}, box); return frames; };

  /** remember a topic's run per input (real-size work is done once, then reused) */
  const memo = new Map();
  P.memo = (id, input, fn) => {
    const k = id + JSON.stringify(input, (a, v) => (typeof v === 'bigint' ? v.toString() : v));
    if (!memo.has(k)) { if (memo.size > 60) memo.delete(memo.keys().next().value); memo.set(k, fn()); }
    return memo.get(k);
  };

  // ---- real-size keys and groups ---------------------------------------------------------------------------------
  /** the RSA primes of the given size: index i of the pool (p512, p1024, p1536 or p2048) */
  P.prime = (bits, i) => hexB(P.DATA['p' + bits][i]);
  const keys = new Map();
  /** a real key: 'rsa1024', 'rsa2048', 'rsa3072' or 'rsa4096' (pair 0 of the pool, or pair `pair`), with exponent e */
  P.rsaKey = (name, e, pair) => {
    const bits = +String(name).replace('rsa', ''), half = bits / 2, k = name + '/' + (e || 65537) + '/' + (pair || 0);
    if (!keys.has(k)) {
      const i = 2 * (pair || 0), p = P.prime(half, i), q = P.prime(half, i + 1);
      // the pool's primes are tested once, in tests/ (the data test), so the key is built without re-testing them
      keys.set(k, S.RSA.fromPrimes(p > q ? p : q, p > q ? q : p, B(e || 65537), { trusted: true }));
    }
    return keys.get(k);
  };
  /** the 2048-bit MODP group of RFC 3526 as the subgroup of order q = (p − 1)/2 generated by 2 */
  P.modp14 = () => { if (!P._modp) { const p = hexB(P.DATA.modp14); P._modp = S.DLP.subgroupZp(p, (p - 1n) / 2n, 2n); P._modp.name = 'the 2048-bit MODP group'; } return P._modp; };
  /** our DSA group: p of 2048 bits, q of 224 bits, g of order q */
  P.dsaReal = () => ({ p: hexB(P.DATA.dsa.p), q: hexB(P.DATA.dsa.q), g: hexB(P.DATA.dsa.g) });

  // ---- cost models ---------------------------------------------------------------------------------------------
  /**
   * The work of the general number field sieve on an n-bit modulus (or a discrete logarithm modulo an n-bit prime),
   * as log2 of L_n[1/3, (64/9)^(1/3)] = exp((64/9)^(1/3)·(ln n)^(1/3)·(ln ln n)^(2/3)), the o(1) term left out.
   */
  P.gnfsBits = (bits) => { const ln = bits * Math.LN2; return (Math.cbrt(64 / 9) * Math.cbrt(ln) * Math.pow(Math.log(ln), 2 / 3)) / Math.LN2; };
  /** the generic attacks (Pollard's rho, baby-step giant-step) on a group of an n-bit prime order: about √(πn/4) steps */
  P.rhoBits = (bits) => bits / 2 + Math.log2(Math.sqrt(Math.PI / 4));
  /**
   * Comparable strengths as the standard tables give them (NIST SP 800-57 Part 1, Table 2): security bits →
   * symmetric key, RSA or finite-field modulus, finite-field subgroup and elliptic-curve order, in bits.
   */
  P.LEVELS = [
    { s: 80, sym: '2TDEA', rsa: 1024, sub: 160, ecc: 160 },
    { s: 112, sym: '3TDEA', rsa: 2048, sub: 224, ecc: 224 },
    { s: 128, sym: 'AES-128', rsa: 3072, sub: 256, ecc: 256 },
    { s: 192, sym: 'AES-192', rsa: 7680, sub: 384, ecc: 384 },
    { s: 256, sym: 'AES-256', rsa: 15360, sub: 512, ecc: 512 },
  ];
})(globalThis.Sifer = globalThis.Sifer || {});
