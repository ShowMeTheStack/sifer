// The discrete logarithm: cyclic groups (Z_p* and small abstract groups), the protocols built on the hardness of the
// logarithm (Diffie–Hellman, a man-in-the-middle against unauthenticated DH, and Elgamal encryption), all traced.
// A group is an object {name, order, id (the neutral element), op(a, b), pow(g, k), eq(a, b), str(a)[, inv(a)]}; the
// attacks in pk-dlp-attacks.js take any such group, so a toy group and Z_p* are broken by the same code.
//   S.DLP.groupZp(p[, {gen}]) -> group over Z_p* (order p − 1), .generator, .randomExponent()
//   S.DLP.subgroupZp(p, q, g) -> the order-q subgroup ⟨g⟩ of Z_p* (g^q = 1): a prime-order group for DH and DSA
//   S.DLP.additive(n) -> the group Z_n under addition (its logarithm is just division: an easy group, for contrast)
//   S.DLP.dh(group, a, b) -> {A, B, shared, trace}                 a and b are the private exponents
//   S.DLP.dhMITM(group, a, b, m) -> {A, B, Am, Bm, kA, kB, trace}  the attacker's exponent m splits the exchange
//   S.DLP.elgamalKey(group[, x]) / elgamalEncrypt(pub, m[, k]) / elgamalDecrypt(key, ct) -> traced results
(function (S) {
  'use strict';
  const N = () => S.NT;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const sh = (v) => N().short(v);
  const D = (S.DLP = S.DLP || {});

  /** Z_p* as a cyclic group of order p − 1, with a generator (given, or the smallest primitive root found) */
  D.groupZp = (p, opts = {}) => {
    p = B(p);
    const order = p - 1n;
    const g = {
      name: `Z_${p}*`, p, order, id: 1n,
      op: (a, b) => N().mod(B(a) * B(b), p),
      inv: (a) => N().inv(a, p),
      pow: (base, k) => N().pow(base, k, p),
      eq: (a, b) => N().mod(B(a), p) === N().mod(B(b), p),
      str: (a) => B(a).toString(),
      random: () => 2n + N().randBelow(p - 2n),
      randomExponent: () => 1n + N().randBelow(order - 1n),
    };
    if (opts.gen != null) g.generator = B(opts.gen);
    else { const pf = N().factor(order); let c = 2n; while (!N().isGenerator(c, p, pf).ok) c++; g.generator = c; }
    g.generatorOrder = order;
    return g;
  };
  /** the prime-order-q subgroup ⟨g⟩ of Z_p*, where q | p − 1 and g has order q: the right setting for DH and DSA */
  D.subgroupZp = (p, q, g) => {
    p = B(p); q = B(q); g = B(g);
    if (N().pow(g, q, p) !== 1n) throw new Error('g does not have order dividing q');
    return {
      name: `⟨${g}⟩ ⊂ Z_${p}*`, p, q, order: q, id: 1n, generator: g, generatorOrder: q,
      op: (a, b) => N().mod(B(a) * B(b), p),
      inv: (a) => N().inv(a, p),
      pow: (base, k) => N().pow(base, k, p),
      eq: (a, b) => N().mod(B(a), p) === N().mod(B(b), p),
      str: (a) => B(a).toString(),
      random: () => N().pow(g, 1n + N().randBelow(q - 1n), p),
      randomExponent: () => 1n + N().randBelow(q - 1n),
    };
  };
  /** Z_n under addition: a cyclic group whose logarithm is trivial (k·g = h means k = h/g mod n), a foil for the hard case */
  D.additive = (n, gen = 1n) => {
    n = B(n); gen = B(gen);
    return {
      name: `Z_${n} (+)`, n, order: n, id: 0n, generator: gen, generatorOrder: n / N().gcd(gen, n),
      op: (a, b) => N().mod(B(a) + B(b), n),
      inv: (a) => N().mod(-B(a), n),
      pow: (base, k) => N().mod(B(base) * B(k), n),
      eq: (a, b) => N().mod(B(a), n) === N().mod(B(b), n),
      str: (a) => B(a).toString(),
      random: () => N().randBelow(n),
      randomExponent: () => 1n + N().randBelow(n - 1n),
    };
  };

  // ---- Diffie–Hellman
  D.dh = (group, a, b) => {
    const g = group.generator;
    a = a == null ? group.randomExponent() : B(a);
    b = b == null ? group.randomExponent() : B(b);
    const A = group.pow(g, a), Bp = group.pow(g, b), trace = [];
    trace.push(step('public', `The group is ${group.name} with generator g = ${group.str(g)} of order ${sh(group.order)}; both sides agree on these.`, { g, order: group.order }));
    trace.push(step('alice', `Alice keeps a = ${sh(a)} secret and sends A = g^a = ${group.str(A)}.`, { a, A }));
    trace.push(step('bob', `Bob keeps b = ${sh(b)} secret and sends B = g^b = ${group.str(Bp)}.`, { b, B: Bp }));
    const sA = group.pow(Bp, a), sB = group.pow(A, b);
    trace.push(step('shared', `Alice computes B^a = ${group.str(sA)} and Bob computes A^b = ${group.str(sB)}: both are g^(ab), the shared secret.`, { shared: sA }));
    return { a, b, A, B: Bp, shared: sA, agree: group.eq(sA, sB), trace };
  };
  /** the attacker sits in the middle with one exponent m, sharing a separate key with each side */
  D.dhMITM = (group, a, b, m) => {
    const g = group.generator;
    a = a == null ? group.randomExponent() : B(a);
    b = b == null ? group.randomExponent() : B(b);
    m = m == null ? group.randomExponent() : B(m);
    const A = group.pow(g, a), Bp = group.pow(g, b), Mpub = group.pow(g, m), trace = [];
    trace.push(step('setup', `Diffie–Hellman with no authentication in ${group.name}: the attacker chooses m = ${sh(m)} and intercepts every message.`, { m }));
    trace.push(step('intercept-a', `Alice sends A = g^a = ${group.str(A)}; the attacker keeps it and passes M = g^m = ${group.str(Mpub)} on to Bob instead.`, { A, M: Mpub }));
    trace.push(step('intercept-b', `Bob sends B = g^b = ${group.str(Bp)}; the attacker keeps it and passes M = ${group.str(Mpub)} on to Alice instead.`, { B: Bp }));
    const kA = group.pow(A, m), kB = group.pow(Bp, m);
    const Am = group.pow(Mpub, a), Bm = group.pow(Mpub, b);
    trace.push(step('keys', `Alice derives M^a = ${group.str(Am)} (= A^m, which the attacker also has); Bob derives M^b = ${group.str(Bm)} (= B^m). The attacker shares one key with each and neither notices.`, { kA, kB, Am, Bm }));
    return { a, b, m, A, B: Bp, M: Mpub, kA, kB, Am, Bm, agreeA: group.eq(kA, Am), agreeB: group.eq(kB, Bm), trace };
  };

  // ---- Elgamal encryption over any such group (messages are group elements)
  D.elgamalKey = (group, x) => {
    x = x == null ? group.randomExponent() : B(x);
    const h = group.pow(group.generator, x), trace = [];
    trace.push(step('key', `Private key x = ${sh(x)}; public key h = g^x = ${group.str(h)} in ${group.name}.`, { x, h }));
    return { group, x, h, pub: { group, h, g: group.generator }, trace };
  };
  D.elgamalEncrypt = (pub, m, k) => {
    const group = pub.group, g = group.generator;
    k = k == null ? group.randomExponent() : B(k);
    const c1 = group.pow(g, k), s = group.pow(pub.h, k), c2 = group.op(m, s), trace = [];
    trace.push(step('nonce', `A fresh random k = ${sh(k)} gives c1 = g^k = ${group.str(c1)}.`, { k, c1 }));
    trace.push(step('mask', `The shared mask is s = h^k = ${group.str(s)}; the ciphertext is c2 = m·s = ${group.str(c2)}.`, { s, c2 }));
    return { c1, c2, k, s, trace };
  };
  D.elgamalDecrypt = (key, ct) => {
    const group = key.group;
    const s = group.pow(ct.c1, key.x), m = group.op(ct.c2, group.inv(s)), trace = [];
    trace.push(step('unmask', `Recover the mask s = c1^x = ${group.str(s)}, then m = c2·s⁻¹ = ${group.str(m)}.`, { s, m }));
    return { m, s, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
