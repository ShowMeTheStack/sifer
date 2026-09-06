// Part 11, RSA signatures: signing is raising to the private exponent d, verifying is raising to e. Raw RSA signing
// multiplies, so two signatures give a third on a message nobody signed; hashing first takes that away, and a full
// padded encoding (PSS, in p11-rsa-pss.js) is what the standards require.
(function (S) {
  'use strict';
  const W = S.P11, NT = () => S.NT;
  const B = W.B;
  const KEYS = [{ value: 'toy', label: 'toy (n of 20 bits)' }, { value: 'rsa1024', label: 'RSA-1024' }, { value: 'rsa2048', label: 'RSA-2048' }];
  const numIn = (id, label, def) => ({ id, kind: 'bigint', label, def, check: (v, inp) => { const x = B(v); const n = W.rsaKey(inp.key).n; return x < 2n || x >= n ? label + ': from 2 to n − 1' : null; } });

  S.topic({
    id: 'p11-rsa-sign', family: 'p11-rsa', order: 10, title: 'RSA signatures: hash, then sign',
    blurb: 'An RSA signature is s = m^d mod n, checked by s^e mod n = m. Signed raw, it multiplies: the product of two signatures is a valid signature on the product of the two messages, which the signer never saw. Hashing the message first, and then padding it to the full width of n, is what makes RSA signing safe.',
    inputs: [
      { id: 'key', kind: 'choice', label: 'Key', def: 'toy', options: KEYS },
      numIn('m1', 'First amount m₁', '30'),
      numIn('m2', 'Second amount m₂', '7'),
      W.textIn('t1', 'First message', 'pay 30 to the printer'),
      W.textIn('t2', 'Second message', 'pay 7 to the courier'),
    ],
    presets: [
      { label: 'Toy key: 30 and 7', values: { key: 'toy', m1: '30', m2: '7' } },
      { label: 'Toy key: 1200 and 3', values: { key: 'toy', m1: '1200', m2: '3', t1: 'refund 1200', t2: 'refund 3' } },
      { label: 'RSA-2048', values: { key: 'rsa2048', m1: '250000', m2: '40', t1: 'wire 250000 to the supplier', t2: 'wire 40 to the cafe' } },
      { label: 'RSA-1024', values: { key: 'rsa1024', m1: '99', m2: '101' } },
    ],
    counters: [{ id: 'sig', label: 'signatures made with d' }],
    run(inp) { return W.memo('p11-rsa-sign', inp, () => rsaSign(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'raw2', pick: 'option', ask: 'Multiply the two signatures modulo n. Is the product a valid signature, and on what?', options: ['no, it is garbage', 'yes, on m₁·m₂ mod n', 'yes, on m₁ + m₂', 'only with d'], answer: 'yes, on m₁·m₂ mod n', explain: (fr, i) => fr[i + 1].say },
      { at: (f) => f.meta.phase === 'hash2', pick: 'option', ask: 'Now the signatures are on SHA-256 hashes. Does multiplying them still give a forgery anyone can use?', options: ['yes, on the product of the two messages', 'no: the product is the hash of no message anyone can find'], answer: 'no: the product is the hash of no message anyone can find', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'With raw RSA, s₁·s₂ mod n is a valid signature on…', options: ['m₁ + m₂', 'm₁·m₂ mod n', 'nothing', 'm₁ only'], answer: 1, why: '(s₁·s₂)^e = s₁^e·s₂^e = m₁·m₂ (mod n).' },
      { q: 'Pick any number s and compute m = s^e mod n. Then…', options: ['s is a valid raw signature on m', 'nothing follows', 'the key is broken', 's = m'], answer: 0, why: 'Raw RSA verification only checks s^e = m, so every s signs some m; an existential forgery, though m is usually meaningless.' },
      { q: 'Why does hashing first stop the multiplication trick?', options: ['the product of two hashes is not the hash of any message the attacker can find', 'hashes are shorter', 'e changes', 'hashing encrypts the message'], answer: 0, why: 'Turning z₁·z₂ mod n back into a message would need a preimage of SHA-256.' },
      { q: 'What do the standards add beyond a bare hash?', options: ['a padded encoding that fills the block, such as PSS', 'a second private key', 'a smaller e', 'nothing'], answer: 0, why: 'A bare hash is a small number with structure; encodings like PSS spread it over the whole width of n with a fixed format.' },
      { q: 'Which key signs?', options: ['the public exponent e', 'the private exponent d', 'the modulus n', 'either'], answer: 1, why: 's = m^d mod n needs d; anyone can check with e.' },
    ],
  });

  function rsaSign(inp) {
    const key = W.rsaKey(inp.key), { n, e, d } = key, toy = inp.key === 'toy', kname = W.rsaName(inp.key);
    const m1 = B(inp.m1), m2 = B(inp.m2), m3 = (m1 * m2) % n;
    const sg = (m) => S.RSA.signRaw(m, key).value, vr = (s) => S.RSA.verifyRaw(s, key).value;
    const s1 = sg(m1), s2 = sg(m2), s3 = (s1 * s2) % n, c1 = vr(s1), c2 = vr(s2), c3 = vr(s3);
    const zOf = (t) => NT().fromBytes(W.sha256(t)) % n, z1 = zOf(inp.t1), z2 = zOf(inp.t2), z3 = (z1 * z2) % n;
    const h1 = sg(z1), h2 = sg(z2), h3 = (h1 * h2) % n, g1 = vr(h1), g2 = vr(h2), g3 = vr(h3);
    const sFree = NT().fromBytes(W.sha256('any number at all')) % n, mFree = vr(sFree);
    const F = new S.Frames(['sig']), n$ = W.n;
    const X = [110, 335, 570, 795], WD = [200, 180, 180, 180], Y = [168, 248, 352];
    const keys = [W.vb('kn', 250, 46, 'public: n, e = ' + e, n, 'good', 300, 18), W.vb('kd', 660, 46, 'private exponent d', d, 'key', 300, 18)];
    const heads = (h0, h1_) => [W.t('h0', X[0], 116, h0, 'strong s11-colhead', 'middle', 14), W.t('h1', X[1], 116, h1_, 'strong s11-colhead', 'middle', 14), W.t('h2', X[2], 116, 'signature s = m^d mod n', 'strong s11-colhead', 'middle', 14), W.t('h3', X[3], 116, 'check: s^e mod n', 'strong s11-colhead', 'middle', 14)];
    const sep = { key: 'sep', kind: 'line', x1: 20, y1: 300, x2: 885, y2: 300, cls: 'faint', audit: 'ignore', layer: 'back' };
    const cell = (r, c, label, v, cls) => W.vb('c' + r + c, X[c], Y[r], label, v, cls, WD[c]);
    const tcell = (r, label, text, cls) => W.hb('c' + r + '0', X[0], Y[r], label, text, cls, WD[0]);
    const link = (r, a, b, txt, cls) => [W.edge('e' + r + a, 'c' + r + a, 'c' + r + b, cls), W.t('l' + r + a, (X[a] + WD[a] / 2 + X[b] - WD[b] / 2) / 2, Y[r] - 12, txt, 'tick ' + (cls || ''), 'middle', 13)];
    const okc = (c, m) => (c === m ? 'good' : 'bad');
    const row = (r, label, text, m, s, c, mLab, cls) => [tcell(r, label, text, cls === 'hot' ? 'hot' : ''), cell(r, 1, mLab, m, cls || 'act'), ...(r === 2 ? [] : link(r, 1, 2, '^d', 'key')), cell(r, 2, r === 2 ? 's₁·s₂ mod n' : 's', s, cls || ''), ...link(r, 2, 3, '^e', ''), cell(r, 3, c === m ? '= m ✓' : '≠ m ✗', c, okc(c, m))];
    const add = (items, say, facts, meta) => F.add({ items: keys.concat(items), say, facts: Object.assign({ n, e, t1: inp.t1, t2: inp.t2 }, facts), meta });
    const quote = (t) => '"' + t + '"';

    add([...heads('message', 'the number m')], `${kname[0].toUpperCase() + kname.slice(1)}: the public key is n = ${n$(n)} with e = ${e}; the private exponent is d = ${n$(d)}. Signing raises a number to d, and verifying raises the signature to e, because (m^d)^e ≡ m (mod n).`, { d }, { phase: 'keys' });
    F.count('sig');
    const r0 = row(0, 'amount', 'raw m₁', m1, s1, c1, 'm₁');
    add([...heads('message', 'the number m'), ...r0], `Raw signing, with no hash and no padding: the amount m₁ = ${n$(m1)} is signed as s₁ = m₁^d mod n = ${n$(s1)}. Anyone checks it with the public key: s₁^e mod n = ${n$(c1)}${c1 === m1 ? ', which is m₁' : ''}.`, { m1, s1, c1 }, { phase: 'raw1' });
    F.count('sig');
    const r1 = row(1, 'amount', 'raw m₂', m2, s2, c2, 'm₂');
    add([...heads('message', 'the number m'), ...r0, ...r1], `The signer also signs m₂ = ${n$(m2)}: s₂ = ${n$(s2)}, and s₂^e mod n = ${n$(c2)}.`, { m2, s2, c2 }, { phase: 'raw2' });
    const r2 = [sep, ...row(2, 'never signed', 'm₁·m₂ mod n', m3, s3, c3, 'm₁·m₂ mod n', 'hot')];
    add([...heads('message', 'the number m'), ...r0, ...r1, ...r2], `Anyone can now multiply the two signatures: s₁·s₂ mod n = ${n$(s3)}. Raised to e it gives ${n$(c3)}, which is m₁·m₂ mod n = ${n$(m3)}: a valid signature on an amount the signer never signed, because (s₁·s₂)^e = s₁^e·s₂^e = m₁·m₂ (mod n). Raw RSA is multiplicative, so its signatures can be combined.`, { s3, c3, m3 }, { phase: 'product' });
    const rf = [W.hb('c00', X[0], Y[0], 'nobody signed', 'any s at all', 'hot', WD[0]), W.vb('c01', X[1], Y[0], 'm = s^e mod n', mFree, 'hot', WD[1]), W.vb('c02', X[2], Y[0], 'chosen s', sFree, 'hot', WD[2]), W.vb('c03', X[3], Y[0], '= m ✓', mFree, 'good', WD[3]), W.edge('ef', 'c02', 'c01', 'hot'), W.t('lf', (X[1] + X[2]) / 2, Y[0] - 12, '^e', 'tick', 'middle', 13)];
    add([...heads('message', 'the number m'), ...rf], `Worse, with raw RSA every number is a signature on something. Take any s, here s = ${n$(sFree)}, and compute m = s^e mod n = ${n$(mFree)} with the public key: the pair (m, s) verifies. The m is usually meaningless, but a signature scheme must not let anyone produce a valid pair at all.`, { sFree, mFree }, { phase: 'free' });
    F.count('sig', 2);
    const zr0 = [tcell(0, 'message', quote(W.hs(inp.t1, 8)), ''), cell(0, 1, 'z₁ = SHA-256(m₁)' + (toy ? ' mod n' : ''), z1, 'act'), ...link(0, 1, 2, '^d', 'key'), cell(0, 2, 's', h1, ''), ...link(0, 2, 3, '^e', ''), cell(0, 3, g1 === z1 ? '= z₁ ✓' : '✗', g1, okc(g1, z1))];
    const zr1 = [tcell(1, 'message', quote(W.hs(inp.t2, 8)), ''), cell(1, 1, 'z₂ = SHA-256(m₂)' + (toy ? ' mod n' : ''), z2, 'act'), ...link(1, 1, 2, '^d', 'key'), cell(1, 2, 's', h2, ''), ...link(1, 2, 3, '^e', ''), cell(1, 3, g2 === z2 ? '= z₂ ✓' : '✗', g2, okc(g2, z2))];
    add([...heads('message', 'z = its hash'), ...zr0, ...zr1], `Hash, then sign: the signer signs z = SHA-256(message) as a number${toy ? ', here reduced modulo the toy n, which a real key never needs' : ''}. "${inp.t1}" gives z₁ = ${n$(z1)} and s = ${n$(h1)}; "${inp.t2}" gives z₂ = ${n$(z2)} and s = ${n$(h2)}. Both check out with e.`, { z1, z2, h1, h2 }, { phase: 'hash2' });
    const zr2 = [sep, W.hb('c20', X[0], Y[2], 'which message?', 'none known', 'bad', WD[0]), cell(2, 1, 'z₁·z₂ mod n', z3, 'hot'), cell(2, 2, 's₁·s₂ mod n', h3, 'hot'), ...link(2, 2, 3, '^e', ''), cell(2, 3, g3 === z3 ? '= z₁·z₂ ✓' : '✗', g3, okc(g3, z3)), W.edge('e2q', 'c21', 'c20', 'bad'), W.t('l2q', (X[0] + WD[0] / 2 + X[1] - WD[1] / 2) / 2, Y[2] - 12, '?', 'bad', 'middle', 15)];
    add([...heads('message', 'z = its hash'), ...zr0, ...zr1, ...zr2], `The product still verifies, but only for the number z₁·z₂ mod n = ${n$(z3)}. To use it, a forger needs a message whose SHA-256 hash is exactly that number: a preimage, about 2^256 work. The forgery is worthless.`, { z3, g3, h3, w: 256 }, { phase: 'hash-product' });
    add([...heads('message', 'z = its hash'), ...zr0, ...zr1, W.t('pad', 450, 330, 'Never sign raw numbers. Sign an encoded hash: RSA-PSS fills all of n.', 'strong', 'middle', 15), W.t('pad2', 450, 362, `z is ${NT().bitLength(z1)} bits; n is ${NT().bitLength(n)} bits`, 'muted', 'middle', 14)], `One more step is required in practice. ${toy ? 'With a real key a bare hash is a 256-bit number inside a 2048-bit modulus' : `A bare hash is a ${NT().bitLength(z1)}-bit number inside a ${NT().bitLength(n)}-bit modulus`}, with a known structure that RSA's algebra still acts on. The standards therefore sign an encoding that fills the whole width of n with a fixed format and, for PSS, a random salt: see [[p11-pss]].`, { zb: NT().bitLength(z1), nb: NT().bitLength(n), real: toy ? [256, 2048] : [] }, { phase: 'pad' });

    const fr = W.fix(F.list, { x: 0, y: 0, w: 900, h: 400 });
    for (const f of fr) f.narrowView = { x: 220, y: 90, w: 670, h: 300 };
    return { frames: fr, def: W.def('RSA signature', ['sign: s = m^d mod n', 'verify: s^e mod n = m ?', 'raw: (s₁·s₂)^e = m₁·m₂: forgeable', 'hash then sign: s = H(m)^d mod n', 'in practice: s = EM^d, EM = PSS(H(m), salt)']) };
  }
})(globalThis.Sifer = globalThis.Sifer || {});
