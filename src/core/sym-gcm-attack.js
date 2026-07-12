// What a repeated nonce does to CTR and GCM. In CTR the keystream repeats, so C1 ⊕ C2 = P1 ⊕ P2, and one known
// plaintext gives away the other. In GCM it is worse: each tag is T = GHASH_H(A, C) ⊕ E_k(J0), and with the same
// nonce E_k(J0) is the same, so T1 ⊕ T2 is a polynomial in H with known coefficients. Its roots in GF(2^128) include
// H; with H and E_k(J0) = T1 ⊕ GHASH_H(A1, C1), anyone can compute valid tags for messages of their own.
// Field elements here are BigInt in the ordinary order (bit i = coefficient of x^i, S.GF.gcm.toPoly), modulo
// x^128 + x^7 + x^2 + x + 1; polynomials over the field are arrays of coefficients, constant term first.
//   S.GF128: mul, sqr, pow, inv, sqrt; poly: add, mul, divmod, gcd, monic, powXmod; roots(P) -> distinct roots
//   S.Attacks.ctrNonceReuse({seed}) -> {recovered, ok, trace}
//   S.Attacks.gcmForbidden({seed}) -> {H, candidates, forged: {aad, ct, tag, pt}, accepted, ok, trace}
(function (S) {
  'use strict';
  const F = (S.GF128 = {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const M = (1n << 128n) - 1n;
  F.mul = (a, b) => {
    let r = 0n;
    for (let i = 0n; b; i++, b >>= 1n) if (b & 1n) r ^= a << i;
    for (let k = 0; k < 2; k++) { const hi = r >> 128n; r = (r & M) ^ hi ^ (hi << 1n) ^ (hi << 2n) ^ (hi << 7n); }
    return r;
  };
  F.sqr = (a) => F.mul(a, a);
  F.pow = (a, e) => { let r = 1n; for (let i = BigInt(e.toString(2).length - 1); i >= 0n; i--) { r = F.sqr(r); if ((e >> i) & 1n) r = F.mul(r, a); } return r; };
  F.inv = (a) => { if (!a) throw new Error('0 has no inverse'); return F.pow(a, (1n << 128n) - 2n); };
  /** squaring is a bijection in characteristic 2, so every element has one square root: a^(2^127) */
  F.sqrt = (a) => { for (let i = 0; i < 127; i++) a = F.sqr(a); return a; };

  const P = (F.poly = {});
  P.trim = (p) => { const q = p.slice(); while (q.length && !q[q.length - 1]) q.pop(); return q; };
  P.deg = (p) => P.trim(p).length - 1;
  P.add = (a, b) => { const n = Math.max(a.length, b.length), o = []; for (let i = 0; i < n; i++) o.push((a[i] || 0n) ^ (b[i] || 0n)); return P.trim(o); };
  P.mul = (a, b) => { if (!a.length || !b.length) return []; const o = new Array(a.length + b.length - 1).fill(0n); a.forEach((x, i) => { if (x) b.forEach((y, j) => { if (y) o[i + j] ^= F.mul(x, y); }); }); return P.trim(o); };
  P.divmod = (a, b) => {
    b = P.trim(b); let r = P.trim(a);
    const db = b.length - 1, li = F.inv(b[db]), q = new Array(Math.max(0, r.length - db)).fill(0n);
    while (r.length - 1 >= db && r.length) {
      const k = r.length - 1 - db, c = F.mul(r[r.length - 1], li);
      q[k] = c;
      for (let i = 0; i <= db; i++) if (b[i]) r[i + k] ^= F.mul(c, b[i]);
      r = P.trim(r);
    }
    return { q: P.trim(q), r };
  };
  P.mod = (a, b) => P.divmod(a, b).r;
  P.monic = (a) => { a = P.trim(a); if (!a.length) return a; const li = F.inv(a[a.length - 1]); return a.map((x) => F.mul(x, li)); };
  P.gcd = (a, b) => { a = P.trim(a); b = P.trim(b); while (b.length) [a, b] = [b, P.mod(a, b)]; return P.monic(a); };
  /** X^(2^k) mod f, by k squarings */
  P.powXmod = (f, k, start = [0n, 1n]) => { let r = P.mod(start, f); for (let i = 0; i < k; i++) r = P.mod(P.mul(r, r), f); return r; };
  /** the distinct roots of f in GF(2^128): gcd with X^(2^128) − X keeps the linear factors, the trace map splits them */
  F.roots = (f, rand = S.Sym.rng(7)) => {
    f = P.monic(f);
    if (f.length <= 1) return [];
    const g = P.gcd(f, P.add(P.powXmod(f, 128), [0n, 1n]));
    const out = [], split = (h) => {
      if (h.length - 1 === 0) return;
      if (h.length - 1 === 1) { out.push(h[0]); return; }   // monic X + c has the root c (−c = c here)
      for (;;) {
        let a = 0n; for (let i = 0; i < 4; i++) a = (a << 32n) | BigInt(Math.floor(rand() * 2 ** 32));
        let t = P.mod([0n, a], h), sum = t.slice();
        for (let i = 1; i < 128; i++) { t = P.mod(P.mul(t, t), h); sum = P.add(sum, t); }
        const d = P.gcd(h, sum);
        if (d.length > 1 && d.length < h.length) { split(d); split(P.divmod(h, d).q.length ? P.monic(P.divmod(h, d).q) : []); return; }
      }
    };
    split(g);
    return out;
  };

  const At = (S.Attacks = S.Attacks || {});
  const hex = (a) => S.bytes.hex(a), toP = (b) => S.GF.gcm.toPoly(b), fromP = (v) => S.GF.gcm.fromPoly(v);
  const txt = (a) => Array.from(a, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '·')).join('');

  At.ctrNonceReuse = ({ seed = 1 } = {}) => {
    const r = S.Sym.rng(seed), E = S.AES.cipher(S.Sym.bytes(r, 16)), nonce = S.Sym.bytes(r, 16);
    const p1 = S.bytes.utf8('Shipping notice: crate 12 of dried figs leaves the north quay at dawn.');
    const p2 = S.bytes.utf8('Payroll: transfer 4,250 to the workshop account before Friday noon.');
    const c1 = S.Modes.encrypt('ctr', E, p1, { iv: nonce, trace: false }).out, c2 = S.Modes.encrypt('ctr', E, p2, { iv: nonce, trace: false }).out;
    const n = Math.min(c1.length, c2.length), x = S.bytes.xor(c1.subarray(0, n), c2.subarray(0, n)), rec = S.bytes.xor(x, p1.subarray(0, n));
    const ok = S.bytes.eq(rec, p2.subarray(0, n));
    return { recovered: rec, ok, trace: [
      step('ctr-reuse', `Both messages were encrypted with the counter starting at ${hex(nonce)}, so they used the same keystream.`, {}),
      step('ctr-xor', `C1 ⊕ C2 = P1 ⊕ P2 = ${hex(x.subarray(0, 16))}…: the keystream is gone.`, { x }),
      step('ctr-known', `Knowing P1 (a routine notice) gives P2 = C1 ⊕ C2 ⊕ P1 = '${txt(rec)}'. Without any known plaintext, crib dragging on C1 ⊕ C2 works as on a two-time pad.`, { ok }),
    ] };
  };

  /** the GHASH polynomial of (A, C) as coefficients of H^1 … H^m (array index = power) */
  const ghashPoly = (aad, ct) => { const bl = S.GCM.blocks(aad, ct), m = bl.length, c = new Array(m + 1).fill(0n); bl.forEach((b, j) => { c[m - j] = toP(b); }); return c; };
  const evalPoly = (c, h) => { let r = 0n; for (let i = c.length - 1; i >= 0; i--) r = F.mul(r, h) ^ c[i]; return r; };
  At.gcmForbidden = ({ seed = 1 } = {}) => {
    const r = S.Sym.rng(seed), key = S.Sym.bytes(r, 16), iv = S.Sym.bytes(r, 12), trace = [];
    const msgs = [
      { aad: S.bytes.utf8('order 5521'), pt: S.bytes.utf8('Deliver 40 sacks of flour to the bakery on Mill Street.') },
      { aad: S.bytes.utf8('order 5522'), pt: S.bytes.utf8('Collect the repaired clock from the shop by the bridge.') },
    ];
    const sent = msgs.map((m) => Object.assign({}, m, S.GCM.encrypt(key, iv, m.pt, m.aad, { trace: false })));
    trace.push(step('gcm-reuse', `Two messages were sealed with the same key and the same nonce ${hex(iv)}; their tags are ${hex(sent[0].tag)} and ${hex(sent[1].tag)}.`, {}));
    // T1 ⊕ T2 = GHASH_H(A1, C1) ⊕ GHASH_H(A2, C2): the E_k(J0) terms cancel
    const c1 = ghashPoly(sent[0].aad, sent[0].ct), c2 = ghashPoly(sent[1].aad, sent[1].ct);
    let f = P.add(c1, c2); f = P.add(f, [toP(sent[0].tag) ^ toP(sent[1].tag)]);
    trace.push(step('gcm-poly', `T1 ⊕ T2 = GHASH_H(A1, C1) ⊕ GHASH_H(A2, C2), since E_k(J0) cancels. Every coefficient is a known block, so H is a root of a polynomial of degree ${P.deg(f)} over GF(2^128).`, { degree: P.deg(f) }));
    const roots = F.roots(f, S.Sym.rng(seed + 99));
    trace.push(step('gcm-roots', `gcd(f, X^(2^128) − X) keeps the linear factors, and the trace map splits them: ${roots.length} root${roots.length === 1 ? '' : 's'}, ${roots.map((x) => hex(fromP(x))).join(', ')}.`, { roots: roots.map(fromP) }));
    // each root gives a guess of E_k(J0); a third message, or a forgery tried on the server, settles any tie
    const candidates = roots.map((h) => ({ H: fromP(h), EJ0: fromP(evalPoly(c1, h) ^ toP(sent[0].tag)) }));
    const target = S.bytes.utf8('Deliver 90 sacks of flour to the bakery on Mill Street.'), ks = S.bytes.xor(sent[0].ct, sent[0].pt);
    const fct = S.bytes.xor(target, ks);
    let forged = null, accepted = false, H = null;
    for (const c of candidates) {
      const tag = fromP(evalPoly(ghashPoly(sent[0].aad, fct), toP(c.H)) ^ toP(c.EJ0));
      const res = S.GCM.decrypt(key, iv, fct, tag, sent[0].aad, { trace: false });
      if (res.ok) { forged = { aad: sent[0].aad, ct: fct, tag, pt: res.pt }; accepted = true; H = c.H; break; }
    }
    const trueH = S.AES.cipher(key).encrypt(new Uint8Array(16));
    trace.push(step('gcm-forge', accepted ? `With H = ${hex(H)}, E_k(J0) = T1 ⊕ GHASH_H(A1, C1). Flip the ciphertext with the reused keystream to say '${txt(target)}', compute its tag ${hex(forged.tag)}, and the receiver accepts it as genuine.` : 'No candidate produced an accepted forgery.', { H, ok: accepted }));
    return { H, trueH, candidates, forged, accepted, ok: accepted && S.bytes.eq(H, trueH), trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
