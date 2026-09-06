// Part 11, choosing a signature scheme: RSA-PSS at two sizes, DSA, Schnorr, ECDSA on P-256 and Ed25519, compared on
// what each rests on, its key and signature sizes, the work of signing and verifying (counted by running the engines on
// real keys), and its security level. The work is put in one unit: multiplications of 256-bit numbers, counting an
// n-bit modular multiplication as (n/256)² of them, as schoolbook multiplication costs.
(function (S) {
  'use strict';
  const W = S.P11, NT = () => S.NT, E = () => S.ECC;
  const seeded = (seed, fn) => { const old = NT().setRandom(NT().seededRandom(seed)); try { return fn(); } finally { NT().setRandom(old); } };
  const GOALS = [
    { value: 'sig', label: 'the smallest signature' },
    { value: 'pub', label: 'the smallest public key' },
    { value: 'verify', label: 'the cheapest verification' },
    { value: 'sign', label: 'the cheapest signing' },
    { value: 'level', label: 'at least 128-bit security' },
  ];

  S.topic({
    id: 'p11-compare', family: 'p11-compare', order: 10, title: 'Comparing signature schemes',
    blurb: 'RSA-PSS, DSA, Schnorr, ECDSA and Ed25519 side by side: the hard problem under each, the sizes of keys and signatures, the work of signing and of verifying (counted on real keys), and the security level each reaches. RSA verifies cheaply but signs slowly and is large; the curve schemes are small and fast at a higher level.',
    inputs: [{ id: 'goal', kind: 'choice', label: 'What matters most', def: 'sig', options: GOALS }, { id: 'seed', kind: 'number', label: 'Seed for the nonces and keys', def: 2, min: 1, max: 99999 }],
    presets: GOALS.map((g) => ({ label: g.label[0].toUpperCase() + g.label.slice(1), values: { goal: g.value } })),
    counters: [{ id: 'cols', label: 'columns filled' }],
    run(inp) { return W.memo('p11-compare', inp, () => compare(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'sign', pick: 'option', ask: 'Which scheme will verify with the least work?', options: ['RSA-2048', 'DSA', 'ECDSA P-256', 'Ed25519'], answer: (fr, i) => fr[i + 1].facts.bestVerify, explain: (fr, i) => fr[i + 1].say },
      { at: (f) => f.meta.phase === 'assume', pick: 'option', ask: 'Which has the smallest signature?', options: ['RSA-2048', 'DSA 2048/224', 'ECDSA P-256', 'Ed25519'], answer: (fr, i) => fr[i + 1].facts.bestSigName, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why does RSA verify so cheaply?', options: ['e = 65537 has 17 bits, so verification is 16 squarings and one multiplication', 'n is small', 'it uses curves', 'it skips the hash'], answer: 0, why: 'Signing uses the full-length d (two half-length exponents with the CRT); verifying uses the tiny e.' },
      { q: 'Which pair reaches 128-bit security?', options: ['RSA-3072 and P-256', 'RSA-2048 and DSA 2048/224', 'RSA-1024 and P-256', 'DSA and RSA-2048'], answer: 0, why: 'NIST SP 800-57: RSA-3072 and 256-bit curves give 128 bits; RSA-2048 and DSA 2048/224 give 112.' },
      { q: 'An Ed25519 signature is…', options: ['64 bytes', '32 bytes', '256 bytes', '56 bytes'], answer: 0, why: 'R and S, 32 bytes each.' },
      { q: 'Which of these would a large quantum computer break?', options: ['all of them', 'only RSA', 'only the curve schemes', 'none'], answer: 0, why: 'Shor\'s algorithm factors and solves discrete logarithms in any of these groups; see the post-quantum part.' },
      { q: 'Why are DSA signatures (56 bytes) so much shorter than RSA-2048 ones (256 bytes)?', options: ['r and s live modulo the 224-bit q, not the 2048-bit p', 'DSA compresses', 'DSA has no s', 'they are not'], answer: 0, why: 'Only the exponents go into the signature.' },
    ],
  });

  /** k·P by left-to-right double-and-add in Jacobian coordinates, counting field multiplications (squarings too) */
  const ecWork = (C, k, P) => { const cnt = { M: 0, S: 0, I: 0 }, bits = k.toString(2); let J = C.toJ(P); for (let i = 1; i < bits.length; i++) { J = C.jdbl(J, cnt); if (bits[i] === '1') J = C.jaddMixed(J, P, cnt); } return { P: C.fromJ(J), mults: cnt.M + cnt.S, cnt }; };
  /** k·B on Ed25519 exactly as the engine does it (right to left), counting its doublings (8 multiplications) and additions (9) */
  const edWork = (k) => { let d = 0, a = 0; for (let x = k; x > 0n; x >>= 1n) { d++; if (x & 1n) a++; } return { dbl: d, add: a, mults: 8 * d + 9 * a }; };
  const unit = (bits) => (bits / 256) ** 2;

  function compare(inp) {
    const goal = inp.goal, msg = 'compare the schemes', r2048 = S.PK.rsaKey('rsa2048'), r3072 = S.PK.rsaKey('rsa3072');
    const rsaRow = (key, name) => {
      const half = NT().bitLength(key.p), m = NT().fromBytes(W.sha256(msg)) % key.n;
      const a = S.RSA.powLR(m % key.p, key.dp, key.p), b = S.RSA.powLR(m % key.q, key.dq, key.q), v = S.RSA.powLR(m, key.e, key.n);
      const sig = S.RSA.pssSign(key, msg, { salt: new Uint8Array(32) });
      const signW = Math.round((a.squarings + a.multiplications + b.squarings + b.multiplications) * unit(half)), verW = Math.round((v.squarings + v.multiplications) * unit(NT().bitLength(key.n)));
      return { name, assume: 'factoring (the RSA problem)', pub: NT().byteLength(key.n), sig: sig.sBytes.length, sign: signW, verify: verW, level: S.PK.LEVELS.find((l) => l.rsa === NT().bitLength(key.n)).s, detail: { sq: v.squarings, mu: v.multiplications } };
    };
    const D = S.PK.dsaReal(), qb = NT().bitLength(D.q), pb = NT().bitLength(D.p);
    const [x, k, k2] = seeded(inp.seed, () => [1n + NT().randBelow(D.q - 1n), 1n + NT().randBelow(D.q - 1n), 1n + NT().randBelow(D.q - 1n)]);
    const dsaKey = S.SIG.dsaKey(D, x), ds = S.SIG.dsaSign(dsaKey, msg, k), dv = S.SIG.dsaVerify(dsaKey.pub, msg, ds), dc = dv.trace.find((t) => t.kind === 'check');
    const ew = (e, mod) => { const t = S.RSA.powLR(D.g, e, mod); return t.squarings + t.multiplications; };
    const dsaSignW = Math.round(ew(k, D.p) * unit(pb)), dsaVerW = Math.round((ew(dc.u1, D.p) + S.RSA.powLR(dsaKey.y, dc.u2, D.p).squarings + S.RSA.powLR(dsaKey.y, dc.u2, D.p).multiplications) * unit(pb));
    const sch = S.SIG.schnorrSign(S.SIG.schnorrKey(D, x), msg, k2), schSignW = Math.round(ew(k2, D.p) * unit(pb));
    const schVerW = Math.round((ew(sch.s, D.p) + (() => { const t = S.RSA.powLR(dsaKey.y, NT().mod(-sch.e, D.q), D.p); return t.squarings + t.multiplications; })()) * unit(pb));
    const C = E().P256, d = W.scalarOf('the P-256 key of the comparison ' + inp.seed, C.n), Q = C.mul(d, C.G), es = E().ecdsa.sign(C, d, W.utf8(msg)), ev = E().ecdsa.verify(C, Q, W.utf8(msg), es), wv = ev.trace.find((t) => t.kind === 'w');
    const eSign = ecWork(C, es.k, C.G), eV1 = ecWork(C, wv.u1, C.G), eV2 = ecWork(C, wv.u2, Q);
    const seedE = W.sha256('the Ed25519 key of the comparison ' + inp.seed), eg = E().Ed25519.sign(seedE, W.utf8(msg));
    const edSign = edWork(eg.r), edV = [edWork(eg.S), edWork(eg.k)];
    const rows = [
      rsaRow(r2048, 'RSA-2048, PSS'), rsaRow(r3072, 'RSA-3072, PSS'),
      { name: `DSA ${pb}/${qb}`, assume: 'discrete log in Z_p*', pub: NT().byteLength(D.p), sig: 2 * Math.ceil(qb / 8), sign: dsaSignW, verify: dsaVerW, level: S.PK.LEVELS.find((l) => l.sub === qb).s },
      { name: `Schnorr ${pb}/${qb}`, assume: 'discrete log in Z_p*', pub: NT().byteLength(D.p), sig: 2 * Math.ceil(qb / 8), sign: schSignW, verify: schVerW, level: S.PK.LEVELS.find((l) => l.sub === qb).s },
      { name: 'ECDSA, P-256', assume: 'elliptic-curve discrete log', pub: C.encode(Q, true).length, sig: E().p1363.encode(C, es).length, sign: eSign.mults, verify: eV1.mults + eV2.mults, level: S.PK.LEVELS.find((l) => l.ecc === 256).s },
      { name: 'Ed25519', assume: 'elliptic-curve discrete log', pub: eg.pub.length, sig: eg.sig.length, sign: edSign.mults, verify: edV[0].mults + edV[1].mults, level: S.PK.LEVELS.find((l) => l.ecc === 256).s },
    ];
    const F = new S.Frames(['cols']);
    const cols = [{ w: 150, head: 'scheme' }, { w: 220, head: 'rests on' }, { w: 96, head: 'public key', mono: true }, { w: 96, head: 'signature', mono: true }, { w: 100, head: 'sign', mono: true }, { w: 100, head: 'verify', mono: true }, { w: 84, head: 'level', mono: true }];
    const pick = (key, dir) => { const v = rows.map((r) => r[key]); const best = dir > 0 ? Math.max(...v) : Math.min(...v); return rows.filter((r) => r[key] === best).map((r) => r.name); };
    const best = { sig: pick('sig', -1), pub: pick('pub', -1), verify: pick('verify', -1), sign: pick('sign', -1), level: rows.filter((r) => r.level >= 128).map((r) => r.name) };
    const colOf = { sig: 3, pub: 2, verify: 5, sign: 4, level: 6 };
    const table = (upto, hl) => W.table({ prefix: 'tb', x: 27, y: 60, rh: 40, size: 13, cols: cols.slice(0, upto + 1), rows: rows.map((r) => [r.name, r.assume, r.pub + ' B', r.sig + ' B', r.sign.toLocaleString('en-US'), r.verify.toLocaleString('en-US'), String(r.level)].slice(0, upto + 1).map((t, j) => ({ text: t, cls: hl && best[hl].includes(r.name) && (j === 0 || j === colOf[hl]) ? 'best' : '' }))) }).items;
    const note = (lines) => W.eqs('nt', 30, 360, lines, 14, 24);
    const head = W.t('hd', 450, 26, 'one message, signed and verified by each scheme on a real key', 'strong', 'middle', 15);
    const add = (items, say, facts, meta) => F.add({ items: [head].concat(items), say, facts: Object.assign({ rows: rows.map((r) => [r.pub, r.sig, r.sign, r.verify, r.level]) }, facts), meta });
    const R = (name) => rows.find((r) => r.name.startsWith(name));
    const fmt = (v) => v.toLocaleString('en-US');

    F.set('cols', 2);
    add([...table(1)], 'Six schemes. RSA rests on the difficulty of factoring (more exactly, of taking e-th roots modulo n); DSA and Schnorr on the discrete logarithm in a subgroup of Z_p*; ECDSA and Ed25519 on the discrete logarithm on an elliptic curve. PSS, Schnorr and EdDSA also have security proofs that treat the hash as a random function.', {}, { phase: 'assume' });
    F.set('cols', 4);
    const bs = rows.filter((r) => r.sig === Math.min(...rows.map((x) => x.sig)));
    add([...table(3), ...note([['sizes in bytes; RSA public keys also carry e, DSA keys share p, q and g', 'muted']])], `Sizes, from the keys and signatures the engines just made: RSA-2048 has a ${R('RSA-2048').pub}-byte modulus and ${R('RSA-2048').sig}-byte signatures, RSA-3072 ${R('RSA-3072').pub} and ${R('RSA-3072').sig}. DSA and Schnorr need a ${R('DSA').pub}-byte public key but sign in ${R('DSA').sig} bytes. ECDSA's public key is ${R('ECDSA').pub} bytes compressed and its signature ${R('ECDSA').sig}; Ed25519's are ${R('Ed25519').pub} and ${R('Ed25519').sig}.`, { bestSigName: bs[0].name.replace(', PSS', '').replace('ECDSA, P-256', 'ECDSA P-256').replace(/^Schnorr.*/, 'DSA 2048/224') }, { phase: 'sizes' });
    F.set('cols', 5);
    const r2 = R('RSA-2048');
    add([...table(4), ...note([['work in multiplications of 256-bit numbers: an n-bit one counts (n/256)²', 'muted']])], `The work of signing, counted while the engines ran, in multiplications of 256-bit numbers: RSA-2048 needs about ${fmt(r2.sign)} (two 1024-bit exponentiations with the CRT), RSA-3072 ${fmt(R('RSA-3072').sign)}. DSA needs ${fmt(R('DSA').sign)} for one ${qb}-bit exponent modulo the ${pb}-bit p. ECDSA needs ${fmt(R('ECDSA').sign)} field multiplications for k·G, Ed25519 ${fmt(R('Ed25519').sign)} for r·B.`, { qb, pb, half: NT().bitLength(r2048.p) }, { phase: 'sign' });
    F.set('cols', 6);
    const bv = rows.reduce((a, b) => (b.verify < a.verify ? b : a));
    add([...table(5), ...note([['DSA and Schnorr verify with two exponentiations, the curves with two scalar multiplications', 'muted']])], `Verifying turns the picture round. RSA-2048 needs only ${r2.detail.sq} squarings and ${r2.detail.mu} multiplication, since e = 65537: about ${fmt(r2.verify)} units, the cheapest of all. DSA needs ${fmt(R('DSA').verify)}, ECDSA ${fmt(R('ECDSA').verify)} and Ed25519 ${fmt(R('Ed25519').verify)}: two scalar multiplications each.`, { bestVerify: bv.name.replace(', PSS', '').replace('ECDSA, P-256', 'ECDSA P-256').replace(/^DSA.*/, 'DSA') }, { phase: 'verify' });
    F.set('cols', 7);
    add([...table(6), ...note([['security level in bits, from NIST SP 800-57 Part 1 (Table 2)', 'muted'], ['all six fall to Shor\'s algorithm on a large quantum computer', 'bad']])], `Security levels, as NIST SP 800-57 rates them: RSA-2048 and DSA with a ${qb}-bit q give ${R('DSA').level} bits; RSA-3072, P-256 and Ed25519 give ${R('ECDSA').level}. Reaching ${R('ECDSA').level} bits costs RSA a ${R('RSA-3072').pub}-byte modulus, against ${R('Ed25519').pub} bytes for Ed25519. None of them survives a large quantum computer, which is why [[pq-lamport]] and the lattice schemes of part 14 exist.`, { L: [112, 128], qb }, { phase: 'level' });
    const g = GOALS.find((x) => x.value === goal), winners = best[goal];
    add([...table(6, goal), ...note([[`wanted: ${g.label}`, 'strong'], [`best here: ${winners.join(', ')}`, 'good']])], `If ${g.label} matters most, the table points to ${winners.join(' and ')}. In practice Ed25519 or ECDSA P-256 are the usual choice for new systems (small, fast, 128-bit); RSA-PSS stays where verification must be cheap or RSA keys are already deployed.`, { winners }, { phase: 'goal' });
    const raw = { rows, dsa: { x, k, k2, u1: dc.u1, u2: dc.u2, y: dsaKey.y, r: ds.r, s: ds.s, sch: { e: sch.e, s: sch.s } }, ecdsa: { d, k: es.k, u1: wv.u1, u2: wv.u2, r: es.r, s: es.s, Q }, ed: { seed: W.hex(seedE), r: eg.r, S: eg.S, k: eg.k, sig: W.hex(eg.sig), pub: W.hex(eg.pub) }, msg, best };
    for (const f of F.list) f.meta.raw = raw;
    const fr = W.fix(F.list, { x: 0, y: 0, w: 900, h: 420 });
    for (const f of fr) f.narrowView = { x: 10, y: 0, w: 880, h: 420 };
    return { frames: fr, def: W.def('Comparing schemes', ['sizes: bytes of the public key and the signature', 'sign / verify: multiplications of 256-bit numbers', '  an n-bit modular multiplication counts (n/256)²', '  curve field multiplications count 1', 'level: bits of security (NIST SP 800-57)']) };
  }
})(globalThis.Sifer = globalThis.Sifer || {});
