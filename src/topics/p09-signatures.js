// Part 9, signatures from the discrete logarithm: Elgamal, DSA and Schnorr, each signed and verified step by step in a
// toy group and at real size (our DSA group of 2048/224 bits; the MODP group for Elgamal), and why a DSA nonce must
// never repeat: the visible sign of a repeat, the safe ways to choose k, and how an auditor spots a repeated r.
(function (S) {
  'use strict';
  const P = S.PK, NT = () => S.NT, KP = () => S.Kit.pk, SIG = () => S.SIG;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const seeded = (seed, fn) => { const old = NT().setRandom(NT().seededRandom(seed)); try { return fn(); } finally { NT().setRandom(old); } };
  const n$ = P.n;
  const short = (v) => KP().fmt(B(v), { max: 14 }).text;
  const textIn = (id, label, def) => ({ id, kind: 'text', label, def, check: (v) => (!String(v).length ? label + ': at least one character' : String(v).length > 48 ? label + ': at most 48 characters' : null) });
  /** the toy DSA/Schnorr group for a q (memoised) */
  const toyParams = (q) => P.memo('p09-toyparams', String(q), () => SIG().toyParams(B(q)));
  /** the Elgamal setting: p and a generator g of Z_p* (toy), or the MODP prime with g = 2 (real) */
  const elgParams = (inp) => {
    if (inp.size === 'real') { const G = P.modp14(); return { p: G.p, g: G.generator }; }
    const { p } = toyParams(inp.q);
    return P.memo('p09-elg', String(p), () => ({ p, g: S.DLP.groupZp(p).generator }));
  };

  // ---------------------------------------------------------------------------------------------------------------
  // Elgamal, DSA and Schnorr signatures
  // ---------------------------------------------------------------------------------------------------------------
  const SCHEMES = { dsa: 'DSA', elgamal: 'Elgamal', schnorr: 'Schnorr' };
  S.topic({
    id: 'p09-sigs', family: 'p09-signatures', order: 10, title: 'Elgamal, DSA and Schnorr signatures',
    blurb: 'Three signatures built on the discrete logarithm. Each draws a fresh secret nonce k, commits to g^k, and ties the hash of the message to the private key x in a value s that only the holder of x could make. The verifier checks the tie with the public key y = g^x alone.',
    inputs: [
      { id: 'scheme', kind: 'choice', label: 'Scheme', def: 'dsa', options: [{ value: 'dsa', label: 'DSA' }, { value: 'elgamal', label: 'Elgamal' }, { value: 'schnorr', label: 'Schnorr' }] },
      { id: 'size', kind: 'choice', label: 'Size', def: 'toy', options: [{ value: 'toy', label: 'toy: a small q' }, { value: 'real', label: 'real: 2048-bit p' }] },
      { id: 'q', kind: 'number', label: 'Toy q at least', def: 1009, min: 11, max: 1000000 },
      { id: 'x', kind: 'number', label: 'Private key x (toy)', def: 345, min: 1, max: 1000000, check: (v, inp) => { if (inp.size === 'real') return null; const T = toyParams(inp.q); const top = inp.scheme === 'elgamal' ? T.p - 2n : T.q - 1n; return B(v) > top ? 'x: at most ' + top : null; } },
      { id: 'k', kind: 'number', label: 'Nonce k (toy)', def: 211, min: 1, max: 1000000, check: (v, inp) => { if (inp.size === 'real') return null; const T = toyParams(inp.q); if (inp.scheme === 'elgamal') return B(v) < 2n || B(v) > T.p - 2n || NT().gcd(B(v), T.p - 1n) !== 1n ? 'k: from 2 to p − 2 and coprime to p − 1 = ' + (T.p - 1n) : null; return B(v) > T.q - 1n ? 'k: at most q − 1 = ' + (T.q - 1n) : null; } },
      textIn('msg', 'Message', 'ship the crates on tuesday'),
      textIn('fake', 'Altered message', 'ship the crates on thursday'),
      { id: 'seed', kind: 'number', label: 'Seed (real size)', def: 3, min: 1, max: 99999 },
    ],
    presets: [
      { label: 'DSA, toy', values: { scheme: 'dsa', size: 'toy', q: 1009, x: 345, k: 211 } },
      { label: 'Schnorr, toy', values: { scheme: 'schnorr', size: 'toy', q: 1009, x: 345, k: 211 } },
      { label: 'Elgamal, toy', values: { scheme: 'elgamal', size: 'toy', q: 101, x: 400, k: 295 } },
      { label: 'DSA, 2048/224', values: { scheme: 'dsa', size: 'real', seed: 3 } },
      { label: 'Schnorr, 2048/224', values: { scheme: 'schnorr', size: 'real', seed: 4 } },
      { label: 'Elgamal, 2048-bit', values: { scheme: 'elgamal', size: 'real', seed: 5 } },
    ],
    counters: [{ id: 'sign', label: 'exponentiations to sign' }, { id: 'verify', label: 'exponentiations to verify' }],
    run(inp) { return P.memo('p09-sigs', inp, () => sigs(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'sent', pick: 'option', ask: 'Will the signature verify?', options: ['yes', 'no'], answer: 'yes', explain: (fr, i) => fr[i + 2] ? fr[i + 2].say : fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'tamper', pick: 'option', ask: 'Now the same signature is checked against the altered message. Will it verify?', options: ['yes', 'no'], answer: (fr, i) => (fr[i + 1].facts.ok ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'In DSA, r is…', options: ['g^k mod q', '(g^k mod p) mod q', 'H(m)·x', 'k⁻¹ mod p'], answer: 1, why: 'r = (g^k mod p) mod q: the commitment to the nonce, reduced to the size of q.' },
      { q: 'What does the Schnorr challenge e hash?', options: ['the message alone', 'the commitment R together with the message', 'the private key', 's'], answer: 1, why: 'e = H(R ‖ m): the challenge depends on the commitment, so the signer cannot choose R after e.' },
      { q: 'Why does a DSA signature on 2048-bit p stay short?', options: ['r and s live modulo the 224-bit q', 'it is compressed', 'p is short', 'only r is sent'], answer: 0, why: 'All the exponent arithmetic is modulo q, so (r, s) is two 224-bit numbers.' },
      { q: 'Elgamal signatures do their exponent arithmetic modulo…', options: ['p', 'p − 1', 'q', '2'], answer: 1, why: 'Exponents of g live modulo the order of the group, p − 1 for a generator of Z_p*; so k must be invertible modulo p − 1.' },
      { q: 'Verifying needs…', options: ['x', 'k', 'only the public key y and the message', 'the nonce and x'], answer: 2, why: 'Anyone can verify with y = g^x; x and k stay with the signer.' },
    ],
  });

  /** on a phone: the signer's column while signing, the middle as it travels, the verifier's column after */
  const sigView = (frames) => { for (const f of frames) { const c = /^(keys|hash|nonce|sign)$/.test(f.meta.phase) ? 170 : f.meta.phase === 'sent' ? 450 : 730; f.narrowView = { x: c - 150, y: 20, w: 300, h: 500 }; } return frames; };
  function sigs(inp) {
    const real = inp.size === 'real', scheme = inp.scheme, F = new S.Frames(['sign', 'verify']);
    const msg = String(inp.msg), fake = String(inp.fake);
    const L = 170, M = 450, R = 730, ys = [168, 228, 288, 348, 408, 468];
    const V = (key, x, y, label, v, cls) => KP().value({ key, x, y, w: 250, label, value: v, cls, max: 12 });
    const frame = [...P.panel('ps', L - 135, 104, 270, 402, 'the signer'), ...P.panel('pv', R - 135, 104, 270, 402, 'the verifier')];
    const add = (items, say, facts, meta) => F.add({ items: frame.concat(items), say, facts: Object.assign({ msg, fake }, facts), meta });
    const tag = SCHEMES[scheme];
    const mBox = (text, cls) => ({ key: 'mm', kind: 'state', x: M, y: ys[1], w: 220, h: 54, rx: 7, lines: ['message', '"' + (text.length > 22 ? text.slice(0, 21) + '…' : text) + '"'], cls: 'block val2 ' + cls, title: text });
    if (scheme === 'elgamal') {
      const { p, g } = elgParams(inp);
      const [x, k] = real ? seeded(inp.seed, () => { const x0 = 2n + NT().randBelow(p - 4n); let k0; do { k0 = 2n + NT().randBelow(p - 4n); } while (NT().gcd(k0, p - 1n) !== 1n); return [x0, k0]; }) : [B(inp.x), B(inp.k)];
      const key = SIG().elgamalKey(p, g, x), y = key.y;
      const sg = SIG().elgamalSign(p, g, x, msg, k), ok = SIG().elgamalVerify(p, g, y, msg, sg), bad = SIG().elgamalVerify(p, g, y, fake, sg);
      const chk = ok.trace.find((t) => t.kind === 'check'), chk2 = bad.trace.find((t) => t.kind === 'check');
      const z = sg.z, kinv = NT().inv(k, p - 1n), z2 = NT().mod(NT().fromBytes(S.SHA256.hash(new TextEncoder().encode(fake))), p - 1n);
      const top = [V('gp', 300, 52, 'prime p', p, ''), V('gg', 600, 52, 'generator g', g, '')];
      const keys = [V('sx', L, ys[0], 'private key x', x, 'key'), V('vy', R, ys[0], 'public key y = g^x', y, 'good')];
      const sign = [V('sz', L, ys[1], 'z = H(m) mod (p − 1)', z, 'act'), V('sk', L, ys[2], 'nonce k, coprime to p − 1', k, 'key'), V('sr', L, ys[3], 'r = g^k mod p', sg.r, 'act'), V('ski', L, ys[4], 'k⁻¹ mod (p − 1)', kinv, ''), V('ss', L, ys[5], 's = k⁻¹(z − x·r) mod (p − 1)', sg.s, 'hot')];
      const sigBox = [V('mr', M, ys[3], 'r', sg.r, 'act'), V('ms', M, ys[4], 's', sg.s, 'hot'), { key: 'e1', kind: 'edge', from: 'sr', to: 'mr', cls: 'act' }, { key: 'e2', kind: 'edge', from: 'ss', to: 'ms', cls: 'hot' }];
      const ver = (c, ok_) => [V('vl', R, ys[2], 'g^z mod p', c.lhs, ok_ ? 'good' : 'bad'), V('vr', R, ys[3], 'y^r·r^s mod p', c.rhs, ok_ ? 'good' : 'bad')];
      add([...top, ...keys], `${tag} signatures in Z_p* with p = ${n$(p)} and g = ${n$(g)}. The signer's private key is x = ${n$(x)}; the public key is y = g^x mod p = ${n$(y)}. Exponents of g live modulo p − 1.`, { p, g, x, y }, { phase: 'keys' });
      add([...top, ...keys, mBox(msg, 'act'), ...sign.slice(0, 1)], `The message "${msg}" is hashed with SHA-256 and reduced: z = H(m) mod (p − 1) = ${n$(z)}.`, { z }, { phase: 'hash' });
      F.set('sign', 1);
      add([...top, ...keys, mBox(msg, 'act'), ...sign.slice(0, 3)], `A fresh secret nonce k = ${n$(k)}, coprime to p − 1, commits as r = g^k mod p = ${n$(sg.r)}.`, { k, r: sg.r }, { phase: 'nonce' });
      add([...top, ...keys, mBox(msg, 'act'), ...sign], `With k⁻¹ mod (p − 1) = ${n$(kinv)}, s = k⁻¹(z − x·r) mod (p − 1) = ${n$(sg.s)}. The signature is (r, s).`, { kinv, s: sg.s }, { phase: 'sign' });
      add([...top, ...keys, mBox(msg, 'act'), ...sign, ...sigBox], `The message and (r, s) = (${n$(sg.r)}, ${n$(sg.s)}) go to the verifier, who knows only p, g and y.`, { r: sg.r, s: sg.s }, { phase: 'sent' });
      F.set('verify', 3);
      add([...top, ...keys, mBox(msg, 'act'), ...sign, ...sigBox, ...ver(chk, true)], `The verifier computes g^z mod p = ${n$(chk.lhs)} and y^r·r^s mod p = ${n$(chk.rhs)}. Since y^r·r^s = g^(xr + ks) and ks ≡ z − xr (mod p − 1), the two agree.`, { lhs: chk.lhs, rhs: chk.rhs }, { phase: 'check' });
      add([...top, ...keys, mBox(msg, 'act'), ...sign, ...sigBox, ...ver(chk, true), P.t('ok', R, ys[5] - 6, ok.ok ? '✓ valid' : '✗ invalid', ok.ok ? 'good' : 'bad', 'middle', 18)], ok.ok ? 'The two sides match: the signature is valid.' : 'The two sides differ: invalid.', { ok: ok.ok }, { phase: 'accept' });
      add([...top, ...keys, mBox(fake, 'bad'), ...sign, ...sigBox, ...ver(chk2, bad.ok), P.t('ok', R, ys[5] - 6, bad.ok ? '✓ valid' : '✗ invalid', bad.ok ? 'good' : 'bad', 'middle', 18)], `Check the same (r, s) against "${fake}": its hash z′ = ${n$(z2)} gives g^z′ mod p = ${n$(chk2.lhs)}, but y^r·r^s is still ${n$(chk2.rhs)}. ${bad.ok ? 'They happen to match' : 'They differ: rejected'}.`, { z2, lhs: chk2.lhs, rhs: chk2.rhs, ok: bad.ok }, { phase: 'tamper' });
      return { frames: sigView(P.fix(F.list, { x: 10, y: 10, w: 880, h: 510 })), def: P.def('Elgamal signature', ['key: x, y = g^x mod p', 'sign: k coprime to p − 1, r = g^k mod p', '      s = k⁻¹(H(m) − x·r) mod (p − 1)', 'verify: g^H(m) ≡ y^r·r^s (mod p)', 'never reuse k']) };
    }
    const params = real ? P.dsaReal() : toyParams(inp.q), { p, q, g } = params;
    const [x, k] = real ? seeded(inp.seed, () => [1n + NT().randBelow(q - 1n), 1n + NT().randBelow(q - 1n)]) : [B(inp.x), B(inp.k)];
    const top = [V('gp', 160, 52, 'prime p', p, ''), V('gq', 450, 52, 'subgroup order q', q, ''), V('gg', 740, 52, 'g, of order q', g, '')];
    const key = scheme === 'dsa' ? SIG().dsaKey(params, x) : SIG().schnorrKey(params, x), y = key.y;
    const keys = [V('sx', L, ys[0], 'private key x', x, 'key'), V('vy', R, ys[0], 'public key y = g^x', y, 'good')];
    add([...top, ...keys], `${tag} in the subgroup of order q = ${n$(q)} of Z_p*, p = ${n$(p)}, generated by g = ${n$(g)}. The private key is x = ${n$(x)}; the public key is y = g^x mod p = ${n$(y)}.`, { p, q, g, x, y }, { phase: 'keys' });
    if (scheme === 'dsa') {
      let sg; try { sg = SIG().dsaSign(key, msg, k); } catch (e) { sg = SIG().dsaSign(key, msg, k + 1n); }
      const ok = SIG().dsaVerify(key.pub, msg, sg), bad = SIG().dsaVerify(key.pub, fake, sg);
      const c = ok.trace.find((t) => t.kind === 'check'), c2 = bad.trace.find((t) => t.kind === 'check') || {};
      const kinv = NT().inv(sg.k, q), qb = P.bits(q);
      const sign = [V('sz', L, ys[1], `z = the top ${qb} bits of H(m)`, sg.z, 'act'), V('sk', L, ys[2], 'secret nonce k', sg.k, 'key'), V('sr', L, ys[3], 'r = (g^k mod p) mod q', sg.r, 'act'), V('ski', L, ys[4], 'k⁻¹ mod q', kinv, ''), V('ss', L, ys[5], 's = k⁻¹(z + x·r) mod q', sg.s, 'hot')];
      const sigBox = [V('mr', M, ys[3], 'r', sg.r, 'act'), V('ms', M, ys[4], 's', sg.s, 'hot'), { key: 'e1', kind: 'edge', from: 'sr', to: 'mr', cls: 'act' }, { key: 'e2', kind: 'edge', from: 'ss', to: 'ms', cls: 'hot' }];
      const ver = (t, ok_) => [V('vw', R, ys[1], 'w = s⁻¹ mod q', t.w, ''), V('vu1', R, ys[2], 'u1 = z·w mod q', t.u1, ''), V('vu2', R, ys[3], 'u2 = r·w mod q', t.u2, ''), V('vv', R, ys[4], 'v = (g^u1·y^u2 mod p) mod q', t.v, ok_ ? 'good' : 'bad')];
      add([...top, ...keys, mBox(msg, 'act'), sign[0]], `The message "${msg}" is hashed with SHA-256, and z keeps the leftmost ${qb} bits, as many as q has: z = ${n$(sg.z)}.`, { z: sg.z, qb }, { phase: 'hash' });
      F.set('sign', 1);
      add([...top, ...keys, mBox(msg, 'act'), ...sign.slice(0, 3)], `A fresh secret nonce k = ${n$(sg.k)} gives r = (g^k mod p) mod q = ${n$(sg.r)}.`, { k: sg.k, r: sg.r }, { phase: 'nonce' });
      add([...top, ...keys, mBox(msg, 'act'), ...sign], `With k⁻¹ mod q = ${n$(kinv)}, s = k⁻¹(z + x·r) mod q = ${n$(sg.s)}. The signature is (r, s), two numbers below q.`, { kinv, s: sg.s }, { phase: 'sign' });
      add([...top, ...keys, mBox(msg, 'act'), ...sign, ...sigBox], `The message travels with (r, s) = (${n$(sg.r)}, ${n$(sg.s)}). The verifier has p, q, g and y.`, { r: sg.r, s: sg.s }, { phase: 'sent' });
      F.set('verify', 2);
      add([...top, ...keys, mBox(msg, 'act'), ...sign, ...sigBox, ...ver(c, ok.ok)], `The verifier computes w = s⁻¹ mod q = ${n$(c.w)}, u1 = z·w mod q = ${n$(c.u1)}, u2 = r·w mod q = ${n$(c.u2)}, and v = (g^u1·y^u2 mod p) mod q = ${n$(c.v)}. Since g^u1·y^u2 = g^((z + xr)/s) = g^k, v should be r.`, { w: c.w, u1: c.u1, u2: c.u2, v: c.v }, { phase: 'check' });
      add([...top, ...keys, mBox(msg, 'act'), ...sign, ...sigBox, ...ver(c, ok.ok), P.t('ok', R, ys[5] + 6, ok.ok ? '✓ v = r: valid' : '✗ invalid', ok.ok ? 'good' : 'bad', 'middle', 18)], ok.ok ? `v = r = ${n$(sg.r)}: the signature is valid.` : 'v differs from r: invalid.', { v: c.v, r: sg.r, ok: ok.ok }, { phase: 'accept' });
      const zf = NT().fromBytes(S.SHA256.hash(new TextEncoder().encode(fake))) >> BigInt(Math.max(0, 256 - NT().bitLength(q)));
      add([...top, ...keys, mBox(fake, 'bad'), ...sign, ...sigBox, ...(c2.w !== undefined ? ver(c2, bad.ok) : []), P.t('ok', R, ys[5] + 6, bad.ok ? '✓ valid' : '✗ v ≠ r: rejected', bad.ok ? 'good' : 'bad', 'middle', 18)], `Against the altered message "${fake}" the hash changes to z′ = ${n$(zf)}, so u1 changes to ${n$(c2.u1)} and v = ${n$(c2.v)}${bad.ok ? ', which happens to equal r' : `, not r = ${n$(sg.r)}: rejected`}.`, { z2: zf, u1: c2.u1, v: c2.v, r: sg.r, ok: bad.ok }, { phase: 'tamper' });
    } else {
      const sg = SIG().schnorrSign(key, msg, k), ok = SIG().schnorrVerify(key.pub, msg, sg), bad = SIG().schnorrVerify(key.pub, fake, sg);
      const c = ok.trace.find((t) => t.kind === 'recompute'), c2 = bad.trace.find((t) => t.kind === 'recompute');
      const sign = [V('sk', L, ys[1], 'secret nonce k', sg.k, 'key'), V('sR', L, ys[2], 'R = g^k mod p', sg.R, 'act'), V('se', L, ys[3], 'e = H(R ‖ m) mod q', sg.e, 'act'), V('ss', L, ys[4], 's = k + e·x mod q', sg.s, 'hot')];
      const sigBox = [V('me', M, ys[3], 'e', sg.e, 'act'), V('ms', M, ys[4], 's', sg.s, 'hot'), { key: 'e1', kind: 'edge', from: 'se', to: 'me', cls: 'act' }, { key: 'e2', kind: 'edge', from: 'ss', to: 'ms', cls: 'hot' }];
      const ver = (t, ok_) => [V('vR', R, ys[2], 'R′ = g^s·y^(−e) mod p', t.R, ''), V('ve', R, ys[3], 'e′ = H(R′ ‖ m) mod q', t.e, ok_ ? 'good' : 'bad')];
      F.set('sign', 1);
      add([...top, ...keys, mBox(msg, 'act'), ...sign.slice(0, 2)], `A fresh secret nonce k = ${n$(sg.k)} gives the commitment R = g^k mod p = ${n$(sg.R)}.`, { k: sg.k, R: sg.R }, { phase: 'nonce' });
      add([...top, ...keys, mBox(msg, 'act'), ...sign.slice(0, 3)], `The challenge hashes the commitment with the message "${msg}": e = H(R ‖ m) mod q = ${n$(sg.e)}.`, { e: sg.e }, { phase: 'hash' });
      add([...top, ...keys, mBox(msg, 'act'), ...sign], `The response is s = k + e·x mod q = ${n$(sg.s)}: no inverse needed. The signature is (e, s).`, { s: sg.s }, { phase: 'sign' });
      add([...top, ...keys, mBox(msg, 'act'), ...sign, ...sigBox], `The message travels with (e, s) = (${n$(sg.e)}, ${n$(sg.s)}).`, { e: sg.e, s: sg.s }, { phase: 'sent' });
      F.set('verify', 2);
      add([...top, ...keys, mBox(msg, 'act'), ...sign, ...sigBox, ...ver(c, ok.ok)], `The verifier rebuilds the commitment: R′ = g^s·y^(−e) mod p = ${n$(c.R)}, which is g^(k + ex − ex) = R. Then e′ = H(R′ ‖ m) mod q = ${n$(c.e)}.`, { R: c.R, e: c.e }, { phase: 'check' });
      add([...top, ...keys, mBox(msg, 'act'), ...sign, ...sigBox, ...ver(c, ok.ok), P.t('ok', R, ys[4] + 56, ok.ok ? '✓ e′ = e: valid' : '✗ invalid', ok.ok ? 'good' : 'bad', 'middle', 18)], ok.ok ? `e′ = e = ${n$(sg.e)}: the signature is valid.` : 'e′ differs from e: invalid.', { e: sg.e, ok: ok.ok }, { phase: 'accept' });
      add([...top, ...keys, mBox(fake, 'bad'), ...sign, ...sigBox, ...ver(c2, bad.ok), P.t('ok', R, ys[4] + 56, bad.ok ? '✓ valid' : '✗ e′ ≠ e: rejected', bad.ok ? 'good' : 'bad', 'middle', 18)], `Against "${fake}" the verifier still rebuilds R′ = ${n$(c2.R)}, but hashing it with the altered message gives e′ = ${n$(c2.e)}${bad.ok ? ', equal to e by chance' : `, not e = ${n$(sg.e)}: rejected`}.`, { R: c2.R, e2: c2.e, e: sg.e, ok: bad.ok }, { phase: 'tamper' });
    }
    const defs = scheme === 'dsa' ? ['key: x in [1, q − 1], y = g^x mod p', 'sign: fresh k, r = (g^k mod p) mod q', '      s = k⁻¹(z + x·r) mod q', 'verify: w = s⁻¹, u1 = z·w, u2 = r·w (mod q)', '        (g^u1·y^u2 mod p) mod q = r?'] : ['key: x, y = g^x mod p', 'sign: fresh k, R = g^k mod p', '      e = H(R ‖ m) mod q, s = k + e·x mod q', 'verify: R′ = g^s·y^(−e) mod p', '        H(R′ ‖ m) mod q = e?'];
    return { frames: sigView(P.fix(F.list, { x: 10, y: 10, w: 880, h: 510 })), def: P.def(tag + ' signature', defs.concat(['never reuse k'])) };
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Why a DSA nonce must never repeat: the visible sign, the consequence, and the two safe ways to choose k
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p09-dsa-nonce', family: 'p09-signatures', order: 20, title: 'Why a DSA nonce must never repeat',
    blurb: 'Two DSA signatures made with the same nonce k share the same r, and anyone can see it. The shared r and the two s values are enough for anyone to solve for the private key. The cure is a k that never repeats: fresh and uniform, or derived from the key and the message as RFC 6979 does; and an auditor can watch for a repeated r.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Size', def: 'toy', options: [{ value: 'toy', label: 'toy: a small q' }, { value: 'real', label: 'real: 2048/224 bits' }] },
      { id: 'q', kind: 'number', label: 'Toy q at least', def: 10007, min: 101, max: 1000000 },
      { id: 'x', kind: 'number', label: 'Private key x (toy)', def: 4321, min: 1, max: 1000000, check: (v, inp) => (inp.size !== 'real' && B(v) >= toyParams(inp.q).q ? 'x: below q = ' + toyParams(inp.q).q : null) },
      { id: 'k', kind: 'number', label: 'The repeated nonce k (toy)', def: 777, min: 1, max: 1000000, check: (v, inp) => (inp.size !== 'real' && B(v) >= toyParams(inp.q).q ? 'k: below q = ' + toyParams(inp.q).q : null) },
      textIn('m1', 'First message', 'pay 120 to the florist'),
      textIn('m2', 'Second message', 'pay 75 to the baker'),
      { id: 'seed', kind: 'number', label: 'Seed', def: 11, min: 1, max: 99999 },
    ],
    presets: [
      { label: 'Toy: q = 10007', values: { size: 'toy', q: 10007, x: 4321, k: 777 } },
      { label: 'Toy: q = 1000003', values: { size: 'toy', q: 1000000, x: 654321, k: 98765 } },
      { label: 'Real: 2048/224', values: { size: 'real', seed: 11 } },
      { label: 'Real, another key', values: { size: 'real', seed: 12 } },
    ],
    counters: [{ id: 'audited', label: 'signatures audited' }],
    run(inp) { return P.memo('p09-dsa-nonce', inp, () => nonce(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'spot', pick: 'option', ask: 'Both signatures carry the same r. What can someone who sees only these public numbers do?', options: ['nothing: x is still a discrete logarithm', 'solve for the private key x', 'only learn that the two messages are equal'], answer: 'solve for the private key x', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'How does anyone notice that a nonce was repeated?', options: ['the two r values are equal', 'the s values are equal', 'the messages are equal', 'they cannot'], answer: 0, why: 'r = (g^k mod p) mod q depends only on k, so the same k gives the same r, in public.' },
      { q: 'Two signatures under one key share r and have different s. What follows?', options: ['the private key can be computed by anyone who sees them', 'only the nonce leaks, the key is safe', 'nothing, r is public anyway', 'the second signature is invalid'], answer: 0, why: 'Two equations s = k⁻¹(z + x·r) with the same unknowns k and x: anyone can solve them, so the key is exposed.' },
      { q: 'What prevents a repeat in practice?', options: ['a larger q', 'a fresh uniform k for every signature, or k derived from the key and the message hash as RFC 6979 does', 'hashing twice', 'shorter messages'], answer: 1, why: 'Either keeps k from ever repeating for different messages; RFC 6979 also makes a weak random generator at signing time irrelevant.' },
      { q: 'With RFC 6979, the same message is signed twice. What happens?', options: ['the same k, so the same (r, s): nothing new is revealed', 'a different k each time', 'the key leaks', 'signing fails'], answer: 0, why: 'k is a fixed function of x and H(m), so the second signature is a copy of the first. A repeated r is only dangerous with two different hashes.' },
      { q: 'An auditor finds two signatures under one public key with the same r and different messages. The right response is…', options: ['treat the key as compromised: revoke it and issue a new one', 'ignore it, r is public', 'reject only the later signature', 'ask the signer to sign again'], answer: 0, why: 'Anyone with those two signatures can compute the key, so it must be replaced; signatures made after the repeat cannot be trusted.' },
      { q: 'Even a nonce that is merely biased (a few known bits) can leak the key over many signatures. True or false?', options: ['true', 'false'], answer: 0, why: 'Many signatures with partly known nonces still determine x. So k must be uniform, not merely unrepeated.' },
    ],
  });

  const LOG_FILL = ['pay 40 to the tailor', 'pay 12 to the cooper', 'pay 300 to the mason', 'pay 8 to the ferryman'];
  function nonce(inp) {
    const real = inp.size === 'real', params = real ? P.dsaReal() : toyParams(inp.q), { p, q, g } = params;
    const seed = Number(inp.seed) || 11;
    const [x, k] = real ? seeded(seed, () => [1n + NT().randBelow(q - 1n), 1n + NT().randBelow(q - 1n)]) : [B(inp.x), B(inp.k)];
    const key = SIG().dsaKey(params, x), y = key.y, m1 = String(inp.m1), m2 = String(inp.m2);
    let kk = k, s1, s2;
    for (;;) { try { s1 = SIG().dsaSign(key, m1, kk); s2 = SIG().dsaSign(key, m2, kk); break; } catch (e) { kk += 1n; } }
    const exposed = s1.s !== s2.s;
    const F = new S.Frames(['audited']);
    const V = (key_, x_, y_, label, v, cls) => KP().value({ key: key_, x: x_, y: y_, w: 250, label, value: v, cls, max: 12 });
    const top = [V('gq', 160, 40, 'q', q, ''), V('gy', 450, 40, 'public key y', y, 'good'), V('gp', 740, 40, 'p', p, '')];
    const card = (pre, x0, m, sg, cls, rcls) => [...P.panel(pre, x0 - 135, 92, 270, 236), P.t(pre + ':m', x0 - 121, 114, '"' + (m.length > 28 ? m.slice(0, 27) + '…' : m) + '"', 'strong', 'start', 14), V(pre + 'z', x0, 160, 'z = H(m), top bits', sg.z, ''), V(pre + 'r', x0, 222, 'r', sg.r, rcls), V(pre + 's', x0, 284, 's', sg.s, cls)];
    const cards = (a, b, rcls) => [...card('c1', 160, m1, a, 'act', rcls), ...card('c2', 740, m2, b, 'act', rcls)];
    const mid = (text, cls) => P.t('same', 450, 222, text, cls, 'middle', 16);
    const eq = (lines) => P.eqs('eq', 40, 380, lines, 16, 30);
    const add = (items, say, facts, meta) => F.add({ items: top.concat(items), say, facts: Object.assign({ m1, m2 }, facts), meta });

    add(cards(s1, s2, ''), `A signer with public key y = ${n$(y)} signs two messages, "${m1}" and "${m2}". The group has q = ${n$(q)} and p = ${n$(p)}. Everything shown is public: anyone holding the two signatures sees these numbers.`, { y, q, p }, { phase: 'public' });
    add([...cards(s1, s2, 'hot'), mid('the same r', 'hot')], `Both signatures have r = ${n$(s1.r)}. Since r = (g^k mod p) mod q depends only on the nonce, the signer used one k twice.`, { r: s1.r, r1: s1.r, r2: s2.r }, { phase: 'spot' });
    add([...cards(s1, s2, 'hot'), mid('the same r', 'hot'), ...eq(exposed
      ? [['s1 = k⁻¹(z1 + x·r) mod q', ''], ['s2 = k⁻¹(z2 + x·r) mod q', ''], ['two equations, and only k and x unknown: anyone can solve them', 'bad'], ['the private key x is exposed', 'bad']]
      : [['s1 = s2: the two hashes agree modulo q', ''], ['this pair says nothing new, but any two different hashes would', 'bad']])],
    exposed ? `Each s satisfies s = k⁻¹(z + x·r) mod q, with z and r public. Two such equations with the same k leave only two unknowns, k and x, so anyone who holds both signatures can solve for the private key. From then on they can sign anything in the signer's name, and no size of q helps.`
      : `Here s1 = s2, because the two hashes agree in their top bits, so this pair is one signature seen twice. Two messages whose hashes differ would leave two equations in k and x, and expose the key.`,
    { exposed, s1: s1.s, s2: s2.s, z1: s1.z, z2: s2.z }, { phase: 'exposed' });

    // the first safe practice: a fresh uniform k for every signature
    const [ra, rb] = seeded(seed * 7 + 1, () => [SIG().dsaSign(key, m1), SIG().dsaSign(key, m2)]);
    add([...cards(ra, rb, 'good'), mid(ra.r === rb.r ? 'r repeats (by chance)' : 'r differs', ra.r === rb.r ? 'bad' : 'good'), ...eq([['fresh k for every signature, uniform in 1 … q − 1,', 'good'], ['from a well-seeded cryptographic generator', 'good'], [`r1 = ${short(ra.r)}, r2 = ${short(rb.r)}: ${ra.r === rb.r ? 'equal' : 'different'}`, ra.r === rb.r ? 'bad' : '']])],
    `The first safe practice: draw a fresh k uniformly from 1 … q − 1 for every signature, from a well-seeded cryptographic generator. Now r1 = ${n$(ra.r)} and r2 = ${n$(rb.r)}${ra.r === rb.r ? ', equal by a chance of about 1 in q: with a toy q that happens; at 224 bits it does not' : ', unrelated'}. A counter, a timestamp or a weak generator is not enough.`,
    { r1: ra.r, r2: rb.r, k1: ra.k, k2: rb.k }, { phase: 'random' });

    // the second: RFC 6979, k derived from the key and the message hash with HMAC-SHA-256
    const det = (m) => { const d = S.SHA256.hash(new TextEncoder().encode(m)); return S.ECC.ecdsa.rfc6979({ n: q }, x, d).k; };
    const kd1 = det(m1), kd2 = det(m2), da = SIG().dsaSign(key, m1, kd1), db = SIG().dsaSign(key, m2, kd2), dagain = SIG().dsaSign(key, m1, det(m1));
    const same = dagain.r === da.r && dagain.s === da.s;
    add([...cards(da, db, 'good'), mid(da.r === db.r ? 'r repeats' : 'r differs', da.r === db.r ? 'bad' : 'good'), ...eq([['k from HMAC-SHA-256 seeded with x and H(m) (RFC 6979)', 'key'], [`k1 = ${short(kd1)}, k2 = ${short(kd2)}: different messages, different nonces`, 'good'], [`signing m1 again: the same k, the same (r, s)${same ? '' : ' (not here: something is wrong)'}`, same ? 'good' : 'bad']])],
    `The second: derive k deterministically. RFC 6979 seeds an HMAC-SHA-256 generator with the private key and the message hash, so k1 = ${n$(kd1)} and k2 = ${n$(kd2)} differ whenever the messages do, with no random generator needed at signing time. Signing "${m1}" again gives the same k and so the very same (r, s), which reveals nothing new.`,
    { k1: kd1, k2: kd2, r1: da.r, r2: db.r, s1: da.s, s2: db.s, again: same }, { phase: 'rfc6979' });

    // the auditor: every r seen under one public key, and any repeat flagged
    const log = seeded(seed * 7 + 2, () => [[m1, s1], [LOG_FILL[0], SIG().dsaSign(key, LOG_FILL[0])], [LOG_FILL[1], SIG().dsaSign(key, LOG_FILL[1])], [m2, s2], [LOG_FILL[2], SIG().dsaSign(key, LOG_FILL[2])], [LOG_FILL[3], SIG().dsaSign(key, LOG_FILL[3])]]);
    const seen = new Map(), flags = [];
    log.forEach(([m, sg], i) => { const j = seen.get(sg.r); if (j !== undefined && log[j][1].z !== sg.z) flags.push([j, i]); if (j === undefined) seen.set(sg.r, i); });
    const flagged = new Set(flags.flat());
    const cls = (i) => (flagged.has(i) ? 'bad' : '');
    const col = (pre, x0, text) => P.eqs(pre, x0, 146, log.map((e, i) => [text(e, i), cls(i)]), 15, 31);
    const rows = [...col('au', 50, ([m], i) => `#${i + 1}  "${m.length > 26 ? m.slice(0, 25) + '…' : m}"`), ...col('ar', 360, ([, sg]) => `r = ${short(sg.r)}`),
      ...col('af', 640, (e, i) => { const f = flags.find((fl) => fl[1] === i); return f ? `repeats #${f[0] + 1}` : ''; })].filter((it) => it.text);
    F.set('audited', log.length);
    add([...P.panel('log', 30, 92, 820, 248, 'signatures seen under this public key'), ...rows,
      ...eq([[flags.length ? 'an r repeated on a different message: revoke and replace the key' : 'no r repeats: no sign of a reused nonce', flags.length ? 'bad' : 'good'], ['a verifier or auditor keeps every r it has seen per key and checks each new one', '']])],
    flags.length ? `An auditor, or a verifier that keeps a log, records the r of every signature it sees under each public key. Signature #${flags[0][1] + 1} repeats the r of #${flags[0][0] + 1} on a different message: the nonce was reused, so the key must be treated as exposed, revoked and replaced.`
      : `An auditor records the r of every signature it sees under each public key and flags any r that comes back on a different message. None does here.`,
    { rows: log.map(([m, sg]) => ({ m, r: sg.r, z: sg.z })), flags, first: flags.length ? flags[0][0] + 1 : null, second: flags.length ? flags[0][1] + 1 : null }, { phase: 'audit' });
    return { frames: P.fix(F.list, { x: 10, y: 0, w: 880, h: 530 }), def: P.def('The nonce rule', ['s = k⁻¹(z + x·r) mod q: k is as secret as x', 'the same k gives the same r, in public', 'the same r with two different s: the key is exposed', 'safe: a fresh uniform k, or k from RFC 6979(x, H(m))', 'audit: a repeated r under one key means revoke it']) };
  }
})(globalThis.Sifer = globalThis.Sifer || {});
