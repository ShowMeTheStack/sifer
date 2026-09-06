// Part 11, Schnorr: first the identification protocol (commit, challenge, response) as a message chart, then why the
// challenge must come after the commitment (someone who knows it early answers without the key), then the Fiat–Shamir
// step that replaces the verifier's random challenge by a hash of the commitment and the message: a signature.
(function (S) {
  'use strict';
  const W = S.P11, NT = () => S.NT, SIG = () => S.SIG, KP = () => S.Kit.pk;
  const B = W.B, n$ = W.n;
  const seeded = (seed, fn) => { const old = NT().setRandom(NT().seededRandom(seed)); try { return fn(); } finally { NT().setRandom(old); } };
  const toyParams = (q) => W.memo('p11-sch-toy', String(q), () => SIG().toyParams(B(q)));
  const below = (id, label) => ({ id, kind: 'number', label, def: 1, min: 1, max: 1000000, check: (v, inp) => (inp.size !== 'real' && B(v) >= toyParams(inp.q).q ? label.replace(/ \(toy\)$/, '') + ': below q = ' + toyParams(inp.q).q : null) });

  S.topic({
    id: 'p11-schnorr', family: 'p11-dlp', order: 30, title: 'Schnorr signatures and the Fiat–Shamir idea',
    blurb: 'Schnorr identification proves knowledge of x with y = g^x in three moves: commit R = g^k, receive a random challenge c, answer s = k + c·x. The challenge must come after the commitment. Fiat and Shamir replace the verifier by a hash, c = H(R ‖ m), and the transcript becomes a signature anyone can check.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Size', def: 'toy', options: [{ value: 'toy', label: 'toy: a small q' }, { value: 'real', label: 'real: 2048/224 bits' }] },
      { id: 'q', kind: 'number', label: 'Toy q at least', def: 1009, min: 11, max: 1000000 },
      Object.assign(below('x', 'Private key x (toy)'), { def: 618 }),
      Object.assign(below('k', 'Nonce k (toy)'), { def: 250 }),
      Object.assign(below('c', 'Challenge c (toy)'), { def: 77 }),
      W.textIn('msg', 'Message', 'the shipment left at dawn'),
      W.textIn('fake', 'Altered message', 'the shipment left at dusk'),
      { id: 'seed', kind: 'number', label: 'Seed (real size)', def: 4, min: 1, max: 99999 },
    ],
    presets: [
      { label: 'Toy: q = 1009', values: { size: 'toy', q: 1009, x: 618, k: 250, c: 77 } },
      { label: 'Toy: q = 101', values: { size: 'toy', q: 101, x: 33, k: 58, c: 12, msg: 'hello', fake: 'hello!' } },
      { label: 'Real: 2048/224', values: { size: 'real', seed: 4 } },
      { label: 'Real: another key', values: { size: 'real', seed: 9, msg: 'version 2 is ready' } },
    ],
    counters: [{ id: 'exp', label: 'exponentiations mod p' }],
    run(inp) { return W.memo('p11-schnorr', inp, () => schnorr(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'check', pick: 'option', ask: 'Suppose someone who does not know x learns the challenge c before sending R. Can they make a transcript that passes?', options: ['yes', 'no'], answer: 'yes', explain: (fr, i) => fr[i + 1].say },
      { at: (f) => f.meta.phase === 'verify', pick: 'option', ask: 'The same (e, s) is checked against the altered message. Will the recomputed e′ equal e?', options: ['yes', 'no'], answer: (fr, i) => (fr[i + 1].facts.ok ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why does g^s = R·y^c hold for an honest prover?', options: ['g^(k + c·x) = g^k·(g^x)^c', 'because s = c', 'because R = y', 'by chance'], answer: 0, why: 'Exponents add: g^s = g^k·g^(c·x) = R·y^c.' },
      { q: 'Why must the challenge come after the commitment?', options: ['knowing c first, anyone picks s and sets R = g^s·y^(−c), with no need for x', 'to save time', 'so that R is random', 'it need not'], answer: 0, why: 'That simulated transcript passes the check; the order is what makes passing evidence of x.' },
      { q: 'In a Schnorr signature, the challenge is…', options: ['H(R ‖ m) mod q', 'chosen by the verifier', 'k', 'x'], answer: 0, why: 'Fiat–Shamir: a hash of the commitment and the message plays the verifier.' },
      { q: 'What must the hash take as input?', options: ['R and the message (and, in modern schemes, the public key)', 'only the message', 'only R', 's'], answer: 0, why: 'Without R the signer could choose R after the challenge, which is exactly the forgery shown; without m it would not sign anything.' },
      { q: 'Schnorr\'s s = k + e·x needs…', options: ['no modular inverse', 'k⁻¹', 'x⁻¹', 'an RSA key'], answer: 0, why: 'Unlike DSA, signing is one multiplication and one addition modulo q.' },
    ],
  });

  function schnorr(inp) {
    const real = inp.size === 'real', params = real ? S.PK.dsaReal() : toyParams(inp.q), { p, q, g } = params, msg = String(inp.msg), fake = String(inp.fake);
    const [x, k, c, sf] = real ? seeded(inp.seed, () => [0, 0, 0, 0].map(() => 1n + NT().randBelow(q - 1n))) : [B(inp.x), B(inp.k), B(inp.c), (B(inp.k) * 7n + 3n) % toyParams(inp.q).q];
    const key = SIG().schnorrKey(params, x), y = key.y, pw = (b, e) => NT().pow(b, e, p);
    const R = pw(g, k), s = NT().mod(k + c * x, q), gs = pw(g, s), ryc = (R * pw(y, c)) % p;
    // the simulator: s first, then R = g^s·y^(−c)
    const sS = sf === 0n ? 1n : sf, Rs = (pw(g, sS) * pw(y, NT().mod(-c, q))) % p, gsS = pw(g, sS), chkS = (Rs * pw(y, c)) % p;
    const sg = SIG().schnorrSign(key, msg, k), ok = SIG().schnorrVerify(key.pub, msg, sg), bad = SIG().schnorrVerify(key.pub, fake, sg);
    const rc = ok.trace.find((t) => t.kind === 'recompute'), rc2 = bad.trace.find((t) => t.kind === 'recompute');
    const F = new S.Frames(['exp']);
    const XP = 150, XV = 750, BW = 230;
    const lanes = (who) => { const name = who || 'the prover, with x', ini = /^some/.test(name) ? '?' : /signer/.test(name) ? 'S' : 'P', cls = /^some/.test(name) ? 'bad' : 'alice'; return [...KP().party({ key: 'lnp', x: XP, y: 36, name, initial: ini, cls, r: 22 }), ...KP().party({ key: 'lnv', x: XV, y: 36, name: 'the verifier', initial: 'V', cls: 'bob', r: 22 }), { key: 'lnl0', kind: 'line', x1: XP, y1: 88, x2: XP, y2: 530, cls: 'pk-life', audit: 'ignore', layer: 'back' }, { key: 'lnl1', kind: 'line', x1: XV, y1: 88, x2: XV, y2: 530, cls: 'pk-life', audit: 'ignore', layer: 'back' }]; };
    const pub = [W.t('pq', 450, 30, real ? `q of ${NT().bitLength(q)} bits, p of ${NT().bitLength(p)} bits` : `q = ${q}, p = ${p}, g = ${g}`, 'muted', 'middle', 13), W.vb('py', 450, 72, 'public key y = g^x mod p', y, 'good', 250)];
    const pv = (key, y_, label, v, cls) => W.vb(key, XP, y_, label, v, cls, BW), vv = (key, y_, label, v, cls) => W.vb(key, XV, y_, label, v, cls, BW);
    const msgA = (key, y_, dir, text, cls) => (dir > 0 ? W.arrow(key, XP + BW / 2, XV - BW / 2, y_, text, cls) : W.arrow(key, XV - BW / 2, XP + BW / 2, y_, text, cls));
    const Y1 = 160, Y2 = 240, Y3 = 320, Y4 = 410;
    const add = (items, say, facts, meta) => F.add({ items, say, facts: Object.assign({ p, q, g, y, msg, fake }, facts), meta });

    add([...lanes(), ...pub], `The prover knows x = ${n$(x)}; everyone knows the group (q = ${n$(q)}, p = ${n$(p)}, g = ${n$(g)}) and the public key y = g^x mod p = ${n$(y)}. The prover will convince the verifier that it knows x without revealing it.`, { x }, { phase: 'setup' });
    F.count('exp');
    const commit = [pv('pk', Y1, 'secret k, R = g^k mod p', R, 'act'), ...msgA('m1', Y1, 1, 'R', 'act'), vv('vR', Y1, 'received R', R, '')];
    add([...lanes(), ...pub, ...commit], `Commit: the prover picks a fresh secret k = ${n$(k)} and sends R = g^k mod p = ${n$(R)}.`, { k, R }, { phase: 'commit' });
    const chal = [vv('vc', Y2, 'random challenge c < q', c, 'hot'), ...msgA('m2', Y2, -1, 'c', 'hot'), pv('pc', Y2, 'received c', c, '')];
    add([...lanes(), ...pub, ...commit, ...chal], `Challenge: only after R has arrived, the verifier picks a random c = ${n$(c)} below q and sends it.`, { c }, { phase: 'challenge' });
    const resp = [pv('ps', Y3, 's = k + c·x mod q', s, 'hot'), ...msgA('m3', Y3, 1, 's', 'hot'), vv('vs', Y3, 'received s', s, '')];
    add([...lanes(), ...pub, ...commit, ...chal, ...resp], `Response: s = k + c·x mod q = ${n$(s)}. On its own s says nothing about x, because k is a random mask.`, { s }, { phase: 'response' });
    F.count('exp', 2);
    const chk = [vv('vg', Y4, 'g^s mod p', gs, gs === ryc ? 'good' : 'bad'), vv('vr', Y4 + 70, 'R·y^c mod p', ryc, gs === ryc ? 'good' : 'bad'), W.verdict('vok', 450, Y4 + 35, gs === ryc, gs === ryc ? 'equal: accept' : 'differ: reject')];
    add([...lanes(), ...pub, ...commit, ...chal, ...resp, ...chk], `Check: g^s mod p = ${n$(gs)} and R·y^c mod p = ${n$(ryc)}. They are equal because g^(k + c·x) = g^k·(g^x)^c. Someone who could answer two different challenges for the same R would know x, so passing is evidence of x.`, { gs, ryc }, { phase: 'check' });
    F.count('exp', 2);
    const sim = [pv('pk', Y1, 'R = g^s·y^(−c) mod p', Rs, 'bad'), ...msgA('m1', Y1, 1, 'R', 'bad'), vv('vR', Y1, 'received R', Rs, ''), vv('vc', Y2, 'the challenge c', c, 'hot'), ...msgA('m2', Y2, -1, 'c', 'hot'), pv('pc', Y2, 'knew c in advance', c, 'bad'), pv('ps', Y3, 'chose s first', sS, 'bad'), ...msgA('m3', Y3, 1, 's', 'bad'), vv('vs', Y3, 'received s', sS, ''), vv('vg', Y4, 'g^s mod p', gsS, gsS === chkS ? 'good' : 'bad'), vv('vr', Y4 + 70, 'R·y^c mod p', chkS, gsS === chkS ? 'good' : 'bad'), W.verdict('vok', 450, Y4 + 35, gsS === chkS, 'passes, with no x')];
    add([...lanes('someone without x'), ...pub, ...sim], `Now someone without x who knows c = ${n$(c)} in advance: pick s = ${n$(sS)} first, then set R = g^s·y^(−c) mod p = ${n$(Rs)}. The check g^s = R·y^c passes (${n$(gsS)} = ${n$(chkS)}). So the order is everything: the challenge must be fixed only after R is.`, { sS, Rs, gsS, chkS, c }, { phase: 'simulate' });
    const hbox = W.box('hh', 450, Y2, 240, 50, ['e = H(R ‖ m) mod q'], 'cipher');
    const fsItems = [pv('pk', Y1, 'secret k, R = g^k mod p', R, 'act'), W.wire('w1', [[XP + BW / 2, Y1], [400, Y1], [400, Y2 - 25]], 'act'), hbox, W.wire('w2', [[330, Y2], [XP + BW / 2, Y2]], 'hot'), pv('pe', Y2, 'challenge e', sg.e, 'hot'), W.hb('hm', 610, Y1, 'message m', '"' + W.hs(msg, 8) + '"', 'act', 220, msg), W.edge('wm', 'hm', 'hh', 'act')];
    add([...lanes('the signer, with x'), ...pub, ...fsItems], `Fiat–Shamir: drop the live verifier and let a hash play it. The challenge becomes e = H(R ‖ m) mod q for the message "${msg}", here e = ${n$(sg.e)}. The signer cannot choose R after e, because e is computed from R.`, { e: sg.e, R: sg.R }, { phase: 'fs' });
    const sigItems = [...fsItems, pv('ps', Y3, 's = k + e·x mod q', sg.s, 'hot'), W.hb('sig', XV, Y3, 'signature', '(e, s)', 'good', BW), W.wire('w3', [[XP + BW / 2, Y3], [XV - BW / 2, Y3]], 'good')];
    add([...lanes('the signer, with x'), ...pub, ...sigItems], `The response is s = k + e·x mod q = ${n$(sg.s)}, with no inverse needed. The transcript (e, s) is the signature; anyone can check it later, with no conversation at all.`, { s: sg.s }, { phase: 'sign' });
    F.count('exp', 2);
    const ver = (rr, txt, okv) => [vv('vR2', Y4, 'R′ = g^s·y^(−e) mod p', rr.R, ''), vv('ve2', Y4 + 70, 'e′ = H(R′ ‖ ' + txt + ') mod q', rr.e, okv ? 'good' : 'bad'), W.verdict('vok', 450, Y4 + 35, okv, okv ? 'e′ = e: valid' : 'e′ ≠ e: rejected')];
    add([...lanes('the signer, with x'), ...pub, ...sigItems, ...ver(rc, 'm', ok.ok)], `Verifying: rebuild the commitment R′ = g^s·y^(−e) mod p = ${n$(rc.R)}, which is g^(k + e·x − e·x) = R, then hash it with the message: e′ = ${n$(rc.e)}. ${ok.ok ? 'It equals e, so the signature is valid.' : 'It differs from e: invalid.'}`, { R2: rc.R, e2: rc.e, ok: ok.ok }, { phase: 'verify' });
    add([...lanes('the signer, with x'), ...pub, ...sigItems, ...ver(rc2, 'm′', bad.ok), W.t('mm2', 450, Y4 + 72, 'm′ = "' + W.hs(fake, 8) + '"', 'bad', 'middle', 14)], `Against "${fake}" the verifier rebuilds R′ = ${n$(rc2.R)} as before, but hashing it with the altered message gives e′ = ${n$(rc2.e)}${bad.ok ? ', equal to e by chance' : `, not e = ${n$(sg.e)}: rejected`}.`, { R2: rc2.R, e2: rc2.e, e: sg.e, ok: bad.ok }, { phase: 'tamper' });
    const fr = W.fix(F.list, { x: 0, y: 0, w: 900, h: 540 });
    for (const f of fr) f.narrowView = { x: 20, y: 0, w: 860, h: 540 };
    return { frames: fr, def: W.def('Schnorr', ['identification: R = g^k; c random; s = k + c·x mod q', '  accept if g^s = R·y^c (mod p)', 'signature (Fiat–Shamir): e = H(R ‖ m) mod q', '  s = k + e·x mod q; signature (e, s)', 'verify: R′ = g^s·y^(−e), H(R′ ‖ m) mod q = e ?']) };
  }
})(globalThis.Sifer = globalThis.Sifer || {});
