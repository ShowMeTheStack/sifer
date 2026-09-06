// Part 11, signatures from the discrete logarithm. Elgamal: the verifier's check in the group next to the equation in
// the exponents that makes it hold, and the rules that keep it safe. DSA: two lanes, the big group modulo p and the small
// exponents modulo q, with every value of key generation, signing and verifying placed in the lane it lives in.
(function (S) {
  'use strict';
  const W = S.P11, NT = () => S.NT, SIG = () => S.SIG, KP = () => S.Kit.pk;
  const B = W.B, n$ = W.n;
  const seeded = (seed, fn) => { const old = NT().setRandom(NT().seededRandom(seed)); try { return fn(); } finally { NT().setRandom(old); } };
  const inl = (key, x, y, label, v, cls, w) => KP().value({ key, x, y, w, label, value: B(v), cls: cls || '', max: 14, count: false, inline: true });

  // ---------------------------------------------------------------------------------------------------------------
  // Elgamal signatures
  // ---------------------------------------------------------------------------------------------------------------
  const TOYP = [467, 1019, 2027];
  const elgGroup = (inp) => {
    if (inp.size === 'real') { const G = S.PK.modp14(); return { p: G.p, g: G.generator }; }
    const p = B(inp.p);
    return W.memo('p11-elg-g', String(p), () => ({ p, g: S.DLP.groupZp(p).generator }));
  };
  S.topic({
    id: 'p11-elgamal', family: 'p11-dlp', order: 10, title: 'Elgamal signatures, and why they verify',
    blurb: 'The signer commits to a secret nonce with r = g^k and solves z ≡ x·r + k·s (mod p − 1) for s. The verifier cannot see that equation, but can see its shadow in the group: g^z = y^r·r^s (mod p). The nonce must be invertible modulo p − 1, fresh and secret, and the message must be hashed.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Size', def: 'toy', options: [{ value: 'toy', label: 'toy: a small p' }, { value: 'real', label: 'real: 2048-bit p' }] },
      { id: 'p', kind: 'choice', label: 'Toy prime p', def: '1019', options: TOYP.map((p) => ({ value: String(p), label: String(p) })) },
      { id: 'x', kind: 'number', label: 'Private key x (toy)', def: 123, min: 2, max: 2025, check: (v, inp) => (inp.size !== 'real' && v > Number(inp.p) - 2 ? 'x: at most p − 2 = ' + (Number(inp.p) - 2) : null) },
      { id: 'k', kind: 'number', label: 'Nonce k (toy)', def: 101, min: 2, max: 2025, check: (v, inp) => { if (inp.size === 'real') return null; const pm = BigInt(inp.p) - 1n; return B(v) >= pm || NT().gcd(B(v), pm) !== 1n ? 'k: below p − 1 and with no factor in common with p − 1 = ' + pm : null; } },
      W.textIn('msg', 'Message', 'the vault code changes on friday'),
      W.textIn('fake', 'Altered message', 'the vault code changes on monday'),
      { id: 'seed', kind: 'number', label: 'Seed (real size)', def: 5, min: 1, max: 99999 },
    ],
    presets: [
      { label: 'Toy: p = 1019', values: { size: 'toy', p: '1019', x: 123, k: 101 } },
      { label: 'Toy: p = 467', values: { size: 'toy', p: '467', x: 127, k: 213 } },
      { label: 'Toy: p = 2027', values: { size: 'toy', p: '2027', x: 1500, k: 77, msg: 'lend the ladder to the neighbours', fake: 'lend the ladder to the neighbour' } },
      { label: 'Real: 2048-bit p', values: { size: 'real', seed: 5 } },
    ],
    counters: [{ id: 'exp', label: 'exponentiations mod p' }],
    run(inp) { return W.memo('p11-elgamal', inp, () => elgamal(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'sign', pick: 'option', ask: 'The verifier computes g^z and y^r·r^s modulo p. Will they be equal?', options: ['yes', 'no'], answer: 'yes', explain: (fr, i) => fr[i + 1].say },
      { at: (f) => f.meta.phase === 'why', pick: 'option', ask: 'The same (r, s) is checked against the altered message. Will g^z′ equal y^r·r^s?', options: ['yes', 'no'], answer: (fr, i) => (fr[i + 1].facts.ok ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why must k have no factor in common with p − 1?', options: ['s needs k⁻¹ modulo p − 1', 'so that r is prime', 'so that y is a generator', 'it need not'], answer: 0, why: 's = k⁻¹(z − x·r) mod (p − 1) exists only when k is invertible modulo p − 1.' },
      { q: 'The verification g^z = y^r·r^s holds because…', options: ['z ≡ x·r + k·s (mod p − 1)', 'z = r + s', 'y = r', 'k = x'], answer: 0, why: 'y^r·r^s = g^(x·r)·g^(k·s) = g^(x·r + k·s), and exponents of g count modulo p − 1.' },
      { q: 'Why must the message be hashed?', options: ['without a hash, anyone can produce valid (z, r, s) triples by choosing r and s first', 'to shorten s', 'to make k random', 'it need not be'], answer: 0, why: 'The verification equation can be satisfied for some z chosen by the forger; hashing makes that z the hash of no message the forger can find.' },
      { q: 'How long is an Elgamal signature with a 2048-bit p?', options: ['about 4096 bits', 'about 448 bits', '256 bits', '2048 bits'], answer: 0, why: 'r and s are each about as long as p; DSA shrinks them to the size of a subgroup.' },
      { q: 'Two signatures that share one k…', options: ['give two linear equations in k and x, so the private key can be computed', 'are harmless', 'cannot verify', 'have different r'], answer: 0, why: 'This is why every signature needs a fresh secret nonce: see the nonce rules.' },
    ],
  });

  function elgamal(inp) {
    const real = inp.size === 'real', { p, g } = elgGroup(inp), pm = p - 1n, msg = String(inp.msg), fake = String(inp.fake);
    const [x, k] = real ? seeded(inp.seed, () => { const x0 = 2n + NT().randBelow(p - 4n); let k0; do { k0 = 2n + NT().randBelow(p - 4n); } while (NT().gcd(k0, pm) !== 1n); return [x0, k0]; }) : [B(inp.x), B(inp.k)];
    const y = SIG().elgamalKey(p, g, x).y, sg = SIG().elgamalSign(p, g, x, msg, k), r = sg.r, s = sg.s, z = sg.z, kinv = NT().inv(k, pm);
    const ok = SIG().elgamalVerify(p, g, y, msg, sg), bad = SIG().elgamalVerify(p, g, y, fake, sg);
    const yr = NT().pow(y, r, p), rs = NT().pow(r, s, p), prod = (yr * rs) % p, gz = NT().pow(g, z, p);
    const xr = (x * r) % pm, ks = (k * s) % pm, sum = (xr + ks) % pm;
    const z2 = NT().mod(NT().fromBytes(W.sha256(fake)), pm), gz2 = NT().pow(g, z2, p);
    const F = new S.Frames(['exp']);
    const top = [W.vb('tp', 120, 44, real ? 'prime p, 2048 bits' : 'prime p', p, '', 200), W.vb('tg', 340, 44, 'generator g', g, '', 200), W.vb('ty', 560, 44, 'public key y = g^x', y, 'good', 200), W.vb('tx', 780, 44, 'private key x', x, 'key', 200)];
    const mB = (t, cls) => W.hb('sm', 120, 120, 'message', '"' + W.hs(t, 7) + '"', cls || '', 200, t);
    const zB = W.vb('sz', 340, 120, 'z = H(m) mod (p − 1)', z, 'act', 200);
    const kB = W.vb('sk', 560, 120, 'nonce k', k, 'key', 200), rB = W.vb('sr', 780, 120, 'r = g^k mod p', r, 'act', 200);
    const kiB = W.vb('ski', 560, 196, 'k⁻¹ mod (p − 1)', kinv, '', 200), sB = W.vb('ss', 780, 196, 's = k⁻¹(z − x·r)', s, 'hot', 200);
    const L = (st, z_, gz_, okL) => [...W.panel('pl', 16, 246, 868, 288, 'the verifier: in the group, mod p'), inl('l0', 230, 300, z_ === z ? 'g^z' : 'g^z′', gz_, okL ? 'good' : 'bad', 300), inl('l1', 230, 360, 'y^r', yr, '', 300), inl('l2', 230, 420, 'r^s', rs, '', 300), inl('l3', 230, 480, 'y^r·r^s', prod, okL ? 'good' : 'bad', 300)];
    const R = () => [W.title('pr:t', 520, 268, 'why: in the exponents, mod p − 1'), inl('r0', 670, 300, 'z', z, 'act', 300), inl('r1', 670, 360, 'x·r', xr, 'key', 300), inl('r2', 670, 420, 'k·s', ks, 'key', 300), inl('r3', 670, 480, 'x·r + k·s', sum, sum === z ? 'good' : 'bad', 300), ...[0, 1, 2, 3].map((i) => W.edge('g' + i, 'r' + i, 'l' + i, 'faint')), ...[0, 1, 2, 3].map((i) => W.t('gt' + i, 450, 300 + 60 * i - 10, 'g^( )', 'tick', 'middle', 13))];
    const add = (items, say, facts, meta) => F.add({ items: top.concat(items), say, facts: Object.assign({ msg, fake, p, g }, facts), meta });

    F.count('exp');
    add([], `Elgamal signatures in Z_p* with p = ${n$(p)} and generator g = ${n$(g)}. The private key is x = ${n$(x)}; the public key is y = g^x mod p = ${n$(y)}. Exponents of g repeat every p − 1 = ${n$(pm)} steps, so all exponent arithmetic is modulo p − 1.`, { x, y, pm }, { phase: 'keys' });
    add([mB(msg, 'act'), zB, W.edge('e1', 'sm', 'sz')], `The message "${msg}" is hashed with SHA-256 and reduced: z = H(m) mod (p − 1) = ${n$(z)}.`, { z }, { phase: 'hash' });
    F.count('exp');
    add([mB(msg, 'act'), zB, kB, rB, W.edge('e2', 'sk', 'sr')], `The signer draws a fresh secret nonce k = ${n$(k)} with gcd(k, p − 1) = ${NT().gcd(k, pm)}, so k has an inverse modulo p − 1, and commits to it: r = g^k mod p = ${n$(r)}.`, { k, r, gcd: NT().gcd(k, pm) }, { phase: 'nonce' });
    add([mB(msg, 'act'), zB, kB, rB, kiB, sB, W.edge('e2', 'sk', 'sr')], `Then s = k⁻¹(z − x·r) mod (p − 1), with k⁻¹ = ${n$(kinv)}: s = ${n$(s)}. The signature is (r, s).`, { kinv, s }, { phase: 'sign' });
    F.count('exp', 3);
    add([mB(msg, 'act'), zB, rB, sB, ...L(1, z, gz, ok.ok)], `The verifier knows p, g, y, the message and (r, s). It computes g^z mod p = ${n$(gz)}, y^r mod p = ${n$(yr)} and r^s mod p = ${n$(rs)}; their product y^r·r^s mod p = ${n$(prod)} ${gz === prod ? 'equals' : 'differs from'} g^z: ${ok.ok ? 'valid' : 'invalid'}.`, { gz, yr, rs, prod, ok: ok.ok }, { phase: 'check' });
    add([mB(msg, 'act'), zB, rB, sB, ...L(1, z, gz, ok.ok), ...R()], `Why it works, in the exponents the signer used: x·r mod (p − 1) = ${n$(xr)} and k·s mod (p − 1) = ${n$(ks)} add up to ${n$(sum)}, which is z. Raising g to each side gives y^r·r^s = g^(x·r + k·s) = g^z. The verifier sees only the left panel; the right one needs x and k.`, { xr, ks, sum }, { phase: 'why' });
    add([mB(fake, 'bad'), W.vb('sz', 340, 120, 'z′ = H(m′) mod (p − 1)', z2, 'bad', 200), rB, sB, ...L(1, z2, gz2, bad.ok)], `Against the altered message "${fake}", z′ = ${n$(z2)} and g^z′ mod p = ${n$(gz2)}, while y^r·r^s is still ${n$(prod)}: ${bad.ok ? 'equal by chance' : 'they differ, so the signature is rejected'}.`, { z2, gz2, prod, ok: bad.ok }, { phase: 'tamper' });
    const bits = NT().bitLength(p);
    const rules = W.eqs('ru', 40, 300, [['the rules', 'strong'], ['k must be invertible mod p − 1, else there is no s', ''], ['k fresh and secret: one k reused gives two linear equations in k and x', 'bad'], ['hash the message: unhashed, a forger picks r, s and gets some valid z', 'bad'], [`size: (r, s) is about 2 × ${bits} = ${2 * bits} bits; DSA shrinks it`, '']], 16, 40);
    add([mB(msg, 'act'), zB, rB, sB, ...W.panel('pl', 16, 246, 868, 288, ''), ...rules], `The rules. k must be invertible modulo p − 1. It must be fresh and secret for every signature: two signatures with one k are two linear equations in the unknowns k and x, and give away the key. The message must be hashed, or a forger can pick r and s first and find some z that verifies. And (r, s) is about 2 × ${bits} = ${2 * bits} bits long, which [[p11-dsa]] shrinks by working in a small subgroup.`, { bits, twice: 2 * bits }, { phase: 'rules' });
    const fr = W.fix(F.list, { x: 0, y: 0, w: 900, h: 540 });
    for (const f of fr) f.narrowView = /^(check|why|tamper)$/.test(f.meta.phase) ? { x: 0, y: 240, w: 900, h: 300 } : { x: 0, y: 0, w: 900, h: 240 };
    return { frames: fr, def: W.def('Elgamal signature', ['key: x, y = g^x mod p', 'sign: k with gcd(k, p − 1) = 1, r = g^k mod p', '      s = k⁻¹(H(m) − x·r) mod (p − 1)', 'verify: g^H(m) ≡ y^r·r^s (mod p)', 'because H(m) ≡ x·r + k·s (mod p − 1)']) };
  }

  // ---------------------------------------------------------------------------------------------------------------
  // DSA in two lanes
  // ---------------------------------------------------------------------------------------------------------------
  const toyParams = (q) => W.memo('p11-dsa-toy', String(q), () => SIG().toyParams(B(q)));
  S.topic({
    id: 'p11-dsa', family: 'p11-dlp', order: 20, title: 'DSA step by step: two moduli',
    blurb: 'DSA does its exponentiations modulo a large prime p, but in a subgroup of small prime order q, so every exponent and both halves of the signature live modulo q. Watch each value land in its lane: g^k is computed mod p, reduced mod q to give r, and s is pure arithmetic mod q.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Size', def: 'toy', options: [{ value: 'toy', label: 'toy: a small q' }, { value: 'real', label: 'real: 2048/224 bits' }] },
      { id: 'q', kind: 'number', label: 'Toy q at least', def: 1009, min: 11, max: 1000000 },
      { id: 'x', kind: 'number', label: 'Private key x (toy)', def: 777, min: 1, max: 1000000, check: (v, inp) => (inp.size !== 'real' && B(v) >= toyParams(inp.q).q ? 'x: below q = ' + toyParams(inp.q).q : null) },
      { id: 'k', kind: 'number', label: 'Nonce k (toy)', def: 345, min: 1, max: 1000000, check: (v, inp) => (inp.size !== 'real' && B(v) >= toyParams(inp.q).q ? 'k: below q = ' + toyParams(inp.q).q : null) },
      W.textIn('msg', 'Message', 'meter 42 read 1180 units'),
      { id: 'seed', kind: 'number', label: 'Seed (real size)', def: 3, min: 1, max: 99999 },
    ],
    presets: [
      { label: 'Toy: q = 1009', values: { size: 'toy', q: 1009, x: 777, k: 345 } },
      { label: 'Toy: q = 101', values: { size: 'toy', q: 101, x: 45, k: 77, msg: 'gate 3 opens at six' } },
      { label: 'Real: 2048/224', values: { size: 'real', seed: 3 } },
      { label: 'Real: another key', values: { size: 'real', seed: 8, msg: 'release 9.2 of the firmware' } },
    ],
    counters: [{ id: 'exp', label: 'exponentiations mod p' }],
    run(inp) { return W.memo('p11-dsa', inp, () => dsa(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'gk', pick: 'option', ask: 'r must live with s, modulo q. How is r made from g^k mod p?', options: ['r = (g^k mod p) mod q', 'r = g^k mod q', 'r = k mod q', 'r = g^k'], answer: 'r = (g^k mod p) mod q', explain: (fr, i) => fr[i + 1].say },
      { at: (f) => f.meta.phase === 'w', pick: 'option', ask: 'v = (g^u1·y^u2 mod p) mod q. What should it equal?', options: ['r', 's', 'z', 'x'], answer: 'r', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Which values of DSA live modulo q?', options: ['x, k, z, r, s, w, u1 and u2', 'only s', 'y and g^k', 'p and g'], answer: 0, why: 'g has order q, so every exponent counts modulo q, and r and s are reduced into it.' },
      { q: 'Which values live modulo p?', options: ['y, g^k and g^u1·y^u2', 'r and s', 'x and k', 'z'], answer: 0, why: 'Only the powers of g are elements of the big group.' },
      { q: 'With p of 2048 bits and q of 224 bits, a DSA signature is…', options: ['2 × 224 = 448 bits', '2 × 2048 bits', '224 bits', '2048 bits'], answer: 0, why: 'Both r and s are below q.' },
      { q: 'Why does g = h^((p − 1)/q) mod p have order q (when g ≠ 1)?', options: ['g^q = h^(p − 1) = 1 by Fermat, and q is prime', 'h is a generator', 'p is prime', 'by luck'], answer: 0, why: 'The order of g divides the prime q, and g ≠ 1, so it is q.' },
      { q: 'z takes the leftmost bits of the hash because…', options: ['z must be below q in size, and DSA keeps as many bits as q has', 'the right bits are weak', 'it saves time', 'p is small'], answer: 0, why: 'FIPS 186 keeps the leftmost min(N, outlen) bits of the hash.' },
    ],
  });

  function dsa(inp) {
    const real = inp.size === 'real', params = real ? S.PK.dsaReal() : toyParams(inp.q), { p, q, g } = params, msg = String(inp.msg);
    const [x, k0] = real ? seeded(inp.seed, () => [1n + NT().randBelow(q - 1n), 1n + NT().randBelow(q - 1n)]) : [B(inp.x), B(inp.k)];
    const key = SIG().dsaKey(params, x), y = key.y;
    let sg, k = k0;
    for (;;) { try { sg = SIG().dsaSign(key, msg, k); break; } catch (e) { k = k % (q - 1n) + 1n; } }
    const ver = SIG().dsaVerify(key.pub, msg, sg), c = ver.trace.find((t) => t.kind === 'check');
    const L = NT().bitLength(p), N = NT().bitLength(q), cof = (p - 1n) / q, gq = NT().pow(g, q, p), gk = NT().pow(g, k, p), kinv = NT().inv(k, q);
    const X = (NT().pow(g, c.u1, p) * NT().pow(y, c.u2, p)) % p;
    const F = new S.Frames(['exp']);
    const BW = 184;
    const top = [W.vb('tp', 120, 44, `prime p, ${L} bits`, p, '', BW + 12), W.vb('tq', 340, 44, `prime q, ${N} bits`, q, 'key', BW + 12), W.vb('tg', 560, 44, 'g, of order q', g, '', BW + 12)];
    const lanes = [...W.panel('lp', 12, 96, 876, 170, `mod p: the big group (p of ${L} bits)`, 's11-lane-p'), ...W.panel('lq', 12, 282, 876, 270, '', 's11-lane-q'), W.title('lq:t', 26, 540, `mod q: exponents and the signature (q of ${N} bits)`), { key: 'mid', kind: 'line', x1: 450, y1: 140, x2: 450, y2: 520, cls: 'faint', audit: 'ignore', layer: 'back' }];
    const yB = (cls) => W.vb('py', 780, 44, 'public key y = g^x mod p', y, cls || 'good', BW + 12);
    const v = (key, x_, y_, label, val, cls) => W.vb(key, x_, y_, label, val, cls, BW);
    const QA = 120, QB = 335, QC = 565, QD = 780, Q1 = 340, Q2 = 410, Q3 = 480;
    const items = {
      k: v('qk', QA, Q1, 'secret nonce k', k, 'key'), r: v('qr', QB, Q1, 'r = (g^k mod p) mod q', sg.r, 'act'),
      x: v('qx', QA, Q2, 'private key x', x, 'key'), z: v('qz', QB, Q2, `z = top ${Math.min(N, 256)} bits of H(m)`, sg.z, 'act'),
      ki: v('qki', QA, Q3, 'k⁻¹ mod q', kinv, ''), s: v('qs', QB, Q3, 's = k⁻¹(z + x·r) mod q', sg.s, 'hot'),
      gk: v('pgk', 228, 196, 'g^k mod p', gk, 'act'),
      u1: v('qu1', QC, Q1, 'u1 = z·w mod q', c.u1, ''), w: v('qw', QC, Q2, 'w = s⁻¹ mod q', c.w, ''), u2: v('qu2', QD, Q2, 'u2 = r·w mod q', c.u2, ''),
      X: v('pX', 672, 196, 'g^u1·y^u2 mod p', X, 'act'), vv: v('qv', QD, Q1, 'v = (that) mod q', c.v, ver.ok ? 'good' : 'bad'),
    };
    const E = (key, a, b, cls, label, lx, ly) => [W.edge(key, a, b, cls)].concat(label ? [W.t(key + ':t', lx, ly, label, 'tick ' + (cls || ''), 'middle', 13)] : []);
    const add = (list, say, facts, meta) => F.add({ items: top.concat(lanes, list), say, facts: Object.assign({ p, q, g, L, N, msg }, facts), meta });
    const climb = () => [...E('ek', 'qk', 'pgk', 'key', 'g^k', 132, 262)];
    const drop = () => [...E('er', 'pgk', 'qr', 'act', 'mod q', 330, 262)];

    add([yB('soft')], `The domain parameters: a prime q of ${N} bits, a prime p of ${L} bits with q dividing p − 1 (p − 1 = q·${n$(cof)}), and g = h^((p − 1)/q) mod p ≠ 1. Then g^q mod p = ${n$(gq)}, so g has order exactly q. Everyone shares p, q and g.`, { cof, gq }, { phase: 'params' });
    F.count('exp');
    add([yB(), items.x], `The private key x = ${n$(x)} is a number below q, so it lives in the lower lane. The public key y = g^x mod p = ${n$(y)} is an element of the big group.`, { x, y }, { phase: 'keys' });
    add([yB(), items.x, items.z, W.hb('mm', QC, Q2, 'message', '"' + W.hs(msg, 7) + '"', 'act', BW, msg), W.edge('em', 'mm', 'qz', 'act')], `The message "${msg}" is hashed with SHA-256, and z keeps the leftmost ${Math.min(N, 256)} bits, because q has ${N}: z = ${n$(sg.z)}.`, { z: sg.z, zb: Math.min(N, 256) }, { phase: 'hash' });
    F.count('exp');
    add([yB(), items.x, items.z, items.k, items.gk, ...climb()], `A fresh secret nonce k = ${n$(k)}, below q. The signer climbs to the big group: g^k mod p = ${n$(gk)}, a number of up to ${L} bits.`, { k, gk }, { phase: 'gk' });
    add([yB(), items.x, items.z, items.k, items.gk, items.r, ...climb(), ...drop()], `And comes straight back down: r = (g^k mod p) mod q = ${n$(sg.r)}. Reducing mod q is what makes the signature short; the verifier will rebuild the same number.`, { r: sg.r }, { phase: 'r' });
    add([yB(), items.x, items.z, items.k, items.gk, items.r, items.ki, items.s, ...climb(), ...drop()], `The rest is arithmetic modulo q: k⁻¹ mod q = ${n$(kinv)} and s = k⁻¹(z + x·r) mod q = ${n$(sg.s)}. The signature is (r, s): two numbers below q, ${2 * N} bits in all.`, { kinv, s: sg.s, sb: 2 * N }, { phase: 's' });
    const left = [items.z, items.r, items.s];
    add([yB(), ...left, items.w, items.u1, items.u2], `The verifier has p, q, g, y, the message and (r, s), and checks that 0 < r, s < q. In the lower lane: w = s⁻¹ mod q = ${n$(c.w)}, u1 = z·w mod q = ${n$(c.u1)} and u2 = r·w mod q = ${n$(c.u2)}.`, { w: c.w, u1: c.u1, u2: c.u2 }, { phase: 'w' });
    F.count('exp', 2);
    add([yB(), ...left, items.w, items.u1, items.u2, items.X, items.vv, ...E('eu', 'qu1', 'pX', '', 'g^u1·y^u2', 568, 262), ...E('ev', 'pX', 'qv', ver.ok ? 'good' : 'bad', 'mod q', 785, 262), W.verdict('ok', QD, Q3, ver.ok, ver.ok ? 'v = r: valid' : 'v ≠ r: invalid')], `Up to the big group: g^u1·y^u2 mod p = ${n$(X)}, and down again: v = ${n$(c.v)}. Since g^u1·y^u2 = g^((z + x·r)·w) = g^k, v equals r = ${n$(sg.r)}: the signature is ${ver.ok ? 'valid' : 'invalid'}.`, { X, v: c.v, r: sg.r, ok: ver.ok }, { phase: 'v' });
    add([yB(), ...left, items.vv, ...W.eqs('sz', 480, 430, [['sizes', 'strong'], [`signature (r, s): 2 × ${N} = ${2 * N} bits`, 'good'], [`Elgamal mod the same p: about ${2 * L}`, 'muted']], 15, 30)], `The point of the two lanes: security against the logarithm in the big group needs p of ${L} bits, but the generic attacks only see the subgroup, so q of ${N} bits is enough. The signature (r, s) is ${2 * N} bits, against about ${2 * L} for Elgamal modulo the same p.`, { sb: 2 * N, eb: 2 * L }, { phase: 'sizes' });
    const fr = W.fix(F.list, { x: 0, y: 0, w: 900, h: 560 });
    for (const f of fr) f.narrowView = /^(w|v|sizes)$/.test(f.meta.phase) ? { x: 440, y: 90, w: 460, h: 470 } : { x: 0, y: 90, w: 460, h: 470 };
    return { frames: fr, def: W.def('DSA (FIPS 186)', ['params: q | p − 1, g = h^((p − 1)/q) mod p, g ≠ 1', 'key: x in [1, q − 1], y = g^x mod p', 'sign: fresh k, r = (g^k mod p) mod q', '      s = k⁻¹(z + x·r) mod q', 'verify: w = s⁻¹, u1 = z·w, u2 = r·w (mod q)', '        v = (g^u1·y^u2 mod p) mod q = r ?']) };
  }
})(globalThis.Sifer = globalThis.Sifer || {});
