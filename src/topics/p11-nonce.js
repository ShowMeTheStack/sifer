// Part 11, the nonce rules. A table of real ECDSA signatures on one key, made with nonces from four sources: a good
// generator, a stuck one that repeats, a biased one whose nonces start with zero bits, and RFC 6979, which derives them;
// then Ed25519's own derived nonce. Each failure is stated with the reason it is fatal; the fix is to derive the nonce.
(function (S) {
  'use strict';
  const W = S.P11, E = () => S.ECC, NT = () => S.NT;
  const seeded = (seed, fn) => { const old = NT().setRandom(NT().seededRandom(seed)); try { return fn(); } finally { NT().setRandom(old); } };
  const CURVES = [{ value: 'P-256', label: 'P-256' }, { value: 'secp256k1', label: 'secp256k1' }];

  S.topic({
    id: 'p11-nonce', family: 'p11-nonce', order: 10, title: 'The nonce rules: fresh, secret, uniform',
    blurb: 'Every ECDSA, DSA or Schnorr signature uses a nonce k, and the private key is safe only if each k is fresh (never repeated), secret (never revealed) and uniform (no bias). A repeated or biased nonce gives the key away. Deriving k from the private key and the message, as RFC 6979 and EdDSA do, removes the random generator from the danger.',
    inputs: [
      { id: 'curve', kind: 'choice', label: 'Curve', def: 'P-256', options: CURVES },
      W.textIn('m1', 'First message', 'pay 120 to the florist', 32),
      W.textIn('m2', 'Second message', 'pay 75 to the baker', 32),
      { id: 'bias', kind: 'choice', label: 'Bias: leading zero bits', def: '8', options: [{ value: '4', label: '4 bits' }, { value: '8', label: '8 bits' }, { value: '16', label: '16 bits' }] },
      { id: 'seed', kind: 'number', label: 'Seed of the generators', def: 7, min: 1, max: 99999 },
    ],
    presets: [
      { label: 'P-256', values: { curve: 'P-256', m1: 'pay 120 to the florist', m2: 'pay 75 to the baker', bias: '8', seed: 7 } },
      { label: 'secp256k1, other messages', values: { curve: 'secp256k1', m1: 'send 2 coins to the shop', m2: 'send 9 coins to a friend', bias: '4', seed: 21 } },
      { label: 'A strong bias', values: { curve: 'P-256', bias: '16', seed: 3 } },
    ],
    check(inp) { return inp.m1 === inp.m2 ? 'The two messages must differ' : null; },
    counters: [{ id: 'sig', label: 'signatures in the table' }],
    run(inp) { return W.memo('p11-nonce', inp, () => nonce(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'good', pick: 'option', ask: 'Next, a broken generator returns the same k for both messages. What can anyone see in the two signatures?', options: ['their r values are equal', 'their s values are equal', 'nothing at all'], answer: 'their r values are equal', explain: (fr, i) => fr[i + 1].say },
      { at: (f) => f.meta.phase === 'biased', pick: 'option', ask: 'RFC 6979 signs the first message, then the same message again. Will the two nonces be equal?', options: ['yes', 'no'], answer: 'yes', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Two ECDSA signatures by one key share the same r. What does that mean?', options: ['the same nonce was used twice, and the private key can be computed', 'the messages were equal', 'nothing', 'the curve is weak'], answer: 0, why: 'r depends only on k. Two equations s·k = e + r·d with the same k leave two unknowns, k and d: solvable.' },
      { q: 'A nonce leaks for a single signature. Then…', options: ['the private key follows from that one signature', 'only that signature is affected', 'nothing, k is public anyway', 'the next signature is unsafe'], answer: 0, why: 'In s = k⁻¹(e + r·d) mod n everything else is public, so d is the only unknown.' },
      { q: 'Nonces whose top few bits are always zero…', options: ['leak the key once enough signatures are collected (a lattice attack)', 'are harmless', 'are faster and safe', 'only affect RSA'], answer: 0, why: 'Each signature then gives an approximate linear relation on d; a lattice reduction combines them.' },
      { q: 'How does RFC 6979 make the nonce safe without a random generator?', options: ['k = HMAC-based function of the private key and the message hash', 'k = 1', 'k = the message', 'k = the public key'], answer: 0, why: 'It is secret (needs d), uniform (HMAC output), and repeats only for the same message, where it is harmless.' },
      { q: 'Ed25519 avoids the problem because…', options: ['r = SHA-512(prefix ‖ M) with a secret prefix', 'it has no nonce', 'its nonce is public', 'it uses RSA'], answer: 0, why: 'The nonce is derived, never drawn from a generator.' },
    ],
  });

  function nonce(inp) {
    const C = inp.curve === 'secp256k1' ? E().secp256k1 : E().P256, n = C.n, bias = Number(inp.bias), m1 = String(inp.m1), m2 = String(inp.m2);
    const d = W.scalarOf('the key in the nonce table ' + inp.curve, n), Q = C.mul(d, C.G);
    const [g1, g2, st, b1, b2] = seeded(inp.seed, () => [1n + NT().randBelow(n - 1n), 1n + NT().randBelow(n - 1n), 1n + NT().randBelow(n - 1n), 1n + NT().randBelow((n >> BigInt(bias)) - 1n), 1n + NT().randBelow((n >> BigInt(bias)) - 1n)]);
    const sign = (m, k) => { const s = E().ecdsa.sign(C, d, W.utf8(m), k === undefined ? {} : { k }); s.ok = E().ecdsa.verify(C, Q, W.utf8(m), s).ok; s.m = m; return s; };
    const rows = {
      good: [sign(m1, g1), sign(m2, g2)], stuck: [sign(m1, st), sign(m2, st)], biased: [sign(m1, b1), sign(m2, b2)],
      rfc: [sign(m1), sign(m1), sign(m2)],
    };
    const seedE = W.sha256('an Ed25519 seed for the nonce table'), ed = [m1, m2].map((m) => S.ECC.Ed25519.sign(seedE, W.utf8(m)));
    const F = new S.Frames(['sig']);
    const kx = (v) => v.toString(16).padStart(64, '0'), hs = (h) => W.hs(h, 6);
    const cols = [{ w: 46, head: '#' }, { w: 200, head: 'message' }, { w: 170, head: 'nonce from' }, { w: 160, head: 'nonce k (hex)', mono: true }, { w: 130, head: 'r (hex)', mono: true }, { w: 150, head: 'note' }];
    const sameR = rows.stuck[0].r === rows.stuck[1].r, rfcSame = rows.rfc[0].k === rows.rfc[1].k;
    const lz = (k) => 256 - E().bitLength(k);
    const all = [
      ['good', rows.good[0], 'a good generator', ''], ['good', rows.good[1], 'a good generator', ''],
      ['stuck', rows.stuck[0], 'a stuck generator', 'bad'], ['stuck', rows.stuck[1], 'a stuck generator', 'bad'],
      ['biased', rows.biased[0], `a biased generator`, 'hot'], ['biased', rows.biased[1], 'a biased generator', 'hot'],
      ['rfc', rows.rfc[0], 'RFC 6979', 'good'], ['rfc', rows.rfc[1], 'RFC 6979', 'good'], ['rfc', rows.rfc[2], 'RFC 6979', 'good'],
    ];
    const ORDER = ['good', 'stuck', 'biased', 'rfc', 'ed'], NROWS = { good: 2, stuck: 4, biased: 6, rfc: 9, ed: 11 };
    const q = (m) => '"' + (m.length > 23 ? m.slice(0, 22) + '…' : m) + '"';
    const table = (upto, hl) => {
      const lim = ORDER.indexOf(upto), list = all.filter((r) => ORDER.indexOf(r[0]) <= lim);
      const body = list.map(([grp, s, src, cls], i) => {
        const on = grp === hl;
        let note = s.ok ? 'verifies' : 'invalid', nc = on ? cls : '';
        if (grp === 'stuck') { note = sameR ? 'same r as its twin' : 'r differs'; nc = 'bad'; }
        if (grp === 'biased') note = lz(s.k) + ' leading zero bits';
        if (grp === 'rfc' && i > 0 && list[i - 1][0] === 'rfc' && list[i - 1][1].m === s.m) note = s.k === list[i - 1][1].k ? 'repeat: same k' : 'k changed';
        const kText = grp === 'biased' && on ? kx(s.k).slice(0, 10) + '…' : hs(kx(s.k));
        return [String(i + 1), { text: q(s.m), title: s.m }, { text: src, cls: on ? cls : '' }, { text: kText, cls: on ? cls : '', title: 'k = ' + kx(s.k) }, { text: hs(kx(s.r)), cls: grp === 'stuck' ? 'bad' : '', title: 'r = ' + kx(s.r) }, { text: note, cls: nc }];
      });
      if (upto === 'ed') ed.forEach((g, j) => body.push([String(body.length + 1), { text: q([m1, m2][j]) }, { text: 'Ed25519: H(prefix ‖ M)', cls: hl === 'ed' ? 'good' : '' }, { text: hs(kx(g.r)), cls: hl === 'ed' ? 'good' : '', title: 'r = ' + kx(g.r) }, { text: hs(W.hex(g.sig.slice(0, 32))), title: 'R = ' + W.hex(g.sig.slice(0, 32)) }, { text: 'R ‖ S, 64 bytes', cls: hl === 'ed' ? 'good' : '' }]));
      return W.table({ prefix: 'tb', x: 22, y: 52, rh: 34, size: 13, cols, rows: body }).items;
    };
    const rule = (upto, lines) => W.eqs('ru', 30, 78 + NROWS[upto] * 34 + 34, lines, 15, 26);
    const head = W.t('hd', 450, 24, `one ${C.name} key, many signatures: where does each nonce come from?`, 'strong', 'middle', 15);
    const add = (items, say, facts, meta) => F.add({ items: [head].concat(items), say, facts: Object.assign({ m1, m2 }, facts), meta });
    const sk = (s) => hs(kx(s.k)), sr = (s) => hs(kx(s.r));

    F.set('sig', 2);
    add([...table('good', 'good'), ...rule('good', [['fresh: never the same k twice', 'good'], ['secret: k never revealed', 'good'], ['uniform: every k in [1, n − 1] equally likely', 'good']])], `Each ECDSA signature s = k⁻¹(e + r·d) mod n hides the private key d behind a nonce k. With a good generator, the two messages get unrelated nonces, ${sk(rows.good[0])} and ${sk(rows.good[1])}, and both signatures verify. The three rules for k: fresh, secret, uniform.`, { k1: sk(rows.good[0]), k2: sk(rows.good[1]) }, { phase: 'good' });
    F.set('sig', 4);
    add([...table('stuck', 'stuck'), ...rule('stuck', [['a repeated k shows: equal r for different messages', 'bad'], ['two equations s·k = e + r·d, two unknowns k and d: solvable', 'bad'], ['so the key is lost, and every past and future signature with it', 'bad']])], `A stuck generator returns the same k = ${sk(rows.stuck[0])} for both messages. Both signatures verify, but their r values are ${sameR ? 'identical' : 'different'} (${sr(rows.stuck[0])}), which anyone can see. The two signing equations then share their only unknowns, k and d, and simple algebra modulo n gives the private key. That is why a nonce must never repeat.`, { k: sk(rows.stuck[0]), r: sr(rows.stuck[0]), same: sameR }, { phase: 'stuck' });
    F.set('sig', 6);
    add([...table('biased', 'biased'), ...rule('biased', [[`these nonces start with ${bias} zero bits: k < n / 2^${bias}`, 'hot'], ['each signature then leaks a little about d', 'hot'], ['enough of them, and a lattice reduction finds d', 'bad']])], `A biased generator makes nonces whose top ${bias} bits are always zero: here ${lz(rows.biased[0].k)} and ${lz(rows.biased[1].k)} leading zero bits. Each such signature is an approximate linear equation in d; collect enough and a lattice reduction (the hidden number problem) recovers the key. The rule: k uniform in [1, n − 1]. And secret: if a single k is ever revealed, the signing equation has d as its only unknown.`, { bias, z1: lz(rows.biased[0].k), z2: lz(rows.biased[1].k) }, { phase: 'biased' });
    F.set('sig', 9);
    add([...table('rfc', 'rfc'), ...rule('rfc', [['RFC 6979: k = HMAC-DRBG(d, H(m))', 'good'], ['same message: same k and same signature, harmless', 'good'], ['new message: new, unpredictable k; no generator to fail', 'good']])], `RFC 6979 derives k from the private key and the message hash with HMAC-SHA-256. Signing "${m1}" twice gives k = ${sk(rows.rfc[0])} both times (${rfcSame ? 'equal' : 'different'}), and an identical signature, which reveals nothing new. "${m2}" gets ${sk(rows.rfc[2])}, unrelated. The nonce is fresh for every new message, secret because it needs d, and uniform because HMAC output is.`, { k1: sk(rows.rfc[0]), k3: sk(rows.rfc[2]), same: rfcSame }, { phase: 'rfc' });
    F.set('sig', 11);
    add([...table('ed', 'ed'), ...rule('ed', [['Ed25519 builds the same idea in: r = SHA-512(prefix ‖ M) mod L', 'good'], ['in practice: use a derived (or hedged) nonce, never a bare generator', 'good'], ['and compute with k in constant time, so it does not leak by timing', '']])], `EdDSA builds the rule into the scheme: Ed25519's nonce is r = SHA-512(prefix ‖ M) mod L with a secret prefix, here ${hs(kx(ed[0].r))} and ${hs(kx(ed[1].r))} for the two messages. The practice is the same everywhere: derive the nonce (or mix fresh randomness into a derived one, a hedged nonce), never trust a bare generator, and handle k in constant time.`, { r1: hs(kx(ed[0].r)), r2: hs(kx(ed[1].r)) }, { phase: 'ed' });
    const raw = { curve: C.name, d, Q, bias, rows: all.map(([grp, s, src]) => ({ grp, src, m: s.m, k: s.k, r: s.r, s: s.s, ok: s.ok })), ed: ed.map((g, j) => ({ m: [m1, m2][j], sig: W.hex(g.sig), r: g.r, pub: W.hex(g.pub) })), seedE: W.hex(seedE) };
    for (const f of F.list) f.meta.raw = raw;
    const fr = W.fix(F.list, { x: 0, y: 0, w: 900, h: 560 });
    for (const f of fr) f.narrowView = { x: 10, y: 0, w: 880, h: 560 };
    return { frames: fr, def: W.def('The nonce rules', ['ECDSA: s = k⁻¹(e + r·d) mod n, r = (k·G).x', 'fresh: k never repeats (equal r would show it)', 'secret: one known k gives d', 'uniform: biased k leaks d over many signatures', 'RFC 6979: k = HMAC-DRBG(d, H(m))', 'Ed25519: r = SHA-512(prefix ‖ M) mod L']) };
  }
})(globalThis.Sifer = globalThis.Sifer || {});
