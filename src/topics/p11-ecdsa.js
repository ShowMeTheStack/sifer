// Part 11, ECDSA on P-256 (or a small curve) with the nonce derived as RFC 6979 prescribes: the HMAC-SHA-256 chain that
// turns the private key and the message hash into k is shown link by link, then R = k·G, r and s, the verification
// u₁·G + u₂·Q, and the determinism: the same message always gives the same k, another message a new one.
(function (S) {
  'use strict';
  const W = S.P11, E = () => S.ECC, KP = () => S.Kit.pk;
  const RFC_D = 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721';
  const CURVES = [{ value: 'P-256', label: 'P-256' }, { value: 'gf1009', label: 'toy: GF(1009), 1019 points' }];
  const curveOf = (id) => (id === 'P-256' ? E().P256 : E().toy(id));

  /** RFC 6979, section 3.2, with HMAC-SHA-256: every K and V on the way to k */
  W.rfc6979Chain = function (C, d, digest) {
    const H = (key, ...parts) => E().hmacSha256(key, W.cat(...parts.map((p) => Uint8Array.from(p))));
    const q = C.n, qlen = E().bitLength(q), rlen = Math.ceil(qlen / 8);
    const bits2int = (b) => { const v = W.big(b), bl = b.length * 8; return bl > qlen ? v >> BigInt(bl - qlen) : v; };
    const int2oct = (v) => E().bigToBytes(v, rlen);
    const bits2oct = (b) => { const z = bits2int(b); return int2oct(z >= q ? z - q : z); };
    const x = int2oct(d), h1 = bits2oct(digest), V0 = new Uint8Array(32).fill(1), K0 = new Uint8Array(32);
    const K1 = H(K0, V0, [0], x, h1), V1 = H(K1, V0), K2 = H(K1, V1, [1], x, h1), V2 = H(K2, V1);
    let K = K2, V = V2, tries = 0, T, k;
    for (;;) {
      tries++;
      T = new Uint8Array(0);
      while (T.length < rlen) { V = H(K, V); T = W.cat(T, V); }
      k = bits2int(T);
      if (k >= 1n && k < q) break;
      K = H(K, V, [0]); V = H(K, V);
    }
    return { x, h1, V0, K0, K1, V1, K2, V2, T, k, tries, qlen, rlen };
  };

  S.topic({
    id: 'p11-ecdsa', family: 'p11-ec', order: 10, title: 'ECDSA on P-256, with an RFC 6979 nonce',
    blurb: 'ECDSA signs with a nonce k: R = k·G gives r, and s = k⁻¹(e + r·d) mod n. RFC 6979 derives k from the private key and the message hash with a chain of HMAC-SHA-256 calls, so it is secret, uniform and never repeats for different messages, with no random generator to fail. Verification rebuilds R as u₁·G + u₂·Q.',
    inputs: [
      { id: 'curve', kind: 'choice', label: 'Curve', def: 'P-256', options: CURVES },
      { id: 'd', kind: 'text', label: 'Private key d (decimal, or 0x and hex)', def: '0x' + RFC_D, check: (v, inp) => { const d = W.parseK(v); if (d === null) return 'Private key d: a whole number, in decimal or as 0x and hex digits'; const n = curveOf(inp.curve).n; return d < 1n || d >= n ? 'Private key d: from 1 to n − 1 = ' + (n - 1n) : null; } },
      W.textIn('msg', 'Message', 'sample'),
    ],
    presets: [
      { label: 'RFC 6979: "sample"', values: { curve: 'P-256', d: '0x' + RFC_D, msg: 'sample' } },
      { label: 'RFC 6979: "test"', values: { curve: 'P-256', d: '0x' + RFC_D, msg: 'test' } },
      { label: 'Our own key', values: { curve: 'P-256', d: '0x' + W.hex(W.sha256('a P-256 key for the lab')), msg: 'unlock door 12 at 0900' } },
      { label: 'Toy curve', values: { curve: 'gf1009', d: '345', msg: 'sample' } },
    ],
    counters: [{ id: 'hmac', label: 'HMAC calls' }, { id: 'mul', label: 'scalar multiplications' }],
    run(inp) { return W.memo('p11-ecdsa', inp, () => ecdsa(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'u', pick: 'option', ask: 'X = u₁·G + u₂·Q. Its x-coordinate mod n should equal…', options: ['r', 's', 'e', 'd'], answer: 'r', explain: (fr, i) => fr[i + 1].say },
      { at: (f) => f.meta.phase === 'X', pick: 'option', ask: 'Sign the same message again with the same key. Will k be the same?', options: ['yes', 'no'], answer: 'yes', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What goes into the RFC 6979 nonce?', options: ['the private key and the message hash', 'the clock', 'a random seed only', 'the public key only'], answer: 0, why: 'K and V are seeded with int2octets(d) and bits2octets(H(m)); nothing else.' },
      { q: 'Signing one message twice with RFC 6979 gives…', options: ['the same k and the same signature', 'two different signatures', 'an error', 'a leaked key'], answer: 0, why: 'k is a function of (d, H(m)); repeating a message repeats everything, which is harmless.' },
      { q: 'Why is a deterministic k safe when a repeated random k is fatal?', options: ['k repeats only when the message repeats, and then s repeats too, revealing nothing new', 'it is longer', 'it is public', 'it is not safe'], answer: 0, why: 'The danger is one k with two different messages; a deterministic k can never do that.' },
      { q: 'Verification computes X = u₁·G + u₂·Q with…', options: ['u₁ = e·s⁻¹, u₂ = r·s⁻¹ (mod n)', 'u₁ = d, u₂ = k', 'u₁ = r, u₂ = s', 'u₁ = s, u₂ = e'], answer: 0, why: 'u₁·G + u₂·Q = s⁻¹(e + r·d)·G = k·G = R.' },
      { q: 'How long is a P-256 signature in the fixed-width form r ‖ s?', options: ['64 bytes', '32 bytes', '128 bytes', '72 bytes'], answer: 0, why: 'r and s are each 32 bytes; DER adds a few bytes of framing.' },
    ],
  });

  function ecdsa(inp) {
    const C = curveOf(inp.curve), toy = C.toy, d = W.parseK(inp.d), msg = String(inp.msg), mb = W.utf8(msg), n = C.n;
    const Q = C.mul(d, C.G), digest = W.sha256(mb), ch = W.rfc6979Chain(C, d, digest);
    const sg = E().ecdsa.sign(C, d, mb), ver = E().ecdsa.verify(C, Q, mb, sg);
    if (sg.k !== ch.k) throw new Error('the RFC 6979 chain disagrees with the engine');
    const wT = ver.trace.find((t) => t.kind === 'w'), xT = ver.trace.find((t) => t.kind === 'X');
    const ki = E().inv(sg.k, n), L = Math.ceil(E().bitLength(n) / 8), der = E().der.encode(sg);
    const fake = msg + '.', sg2 = E().ecdsa.sign(C, d, W.utf8(fake)), again = E().ecdsa.sign(C, d, mb);
    const F = new S.Frames(['hmac', 'mul']);
    const num = (v) => (toy ? String(v) : '0x' + W.hs(v.toString(16).padStart(2 * L, '0'), 8));
    const hs = (b) => W.hs(W.hex(b), 6);
    const XA = 150, XB = 450, XC = 750, BW = 270, ys = [150, 216, 282, 348, 414, 480];
    const val = (key, x, y, label, v, cls) => KP().value({ key, x, y, w: BW, label, value: v, cls: cls || '', max: toy ? 14 : 16, hex: !toy, count: false });
    const hb = (key, x, y, label, b, cls) => W.hb(key, x, y, label, hs(b), cls, BW, label + ' = ' + W.hex(b));
    const head = [W.t('cv', 450, 18, `${C.name}: n = ${toy ? n : 'a ' + E().bitLength(n) + '-bit prime'}, G = ${toy ? W.n(C.G.x) + ', ' + W.n(C.G.y) : 'the standard base point'}`, 'muted', 'middle', 13), val('td', 230, 52, 'private key d', d, 'key'), val('tQ', 670, 52, 'public key Q = d·G (its x)', Q.x, 'good')];
    const titles = [W.t('ta', XA, 106, 'the nonce: RFC 6979', 'title', 'middle'), W.t('tb', XB, 106, 'signing', 'title', 'middle'), W.t('tc', XC, 106, 'verifying', 'title', 'middle')];
    const A = [hb('a0', XA, ys[0], 'V₀ = 01…01, K₀ = 00…00', ch.V0, ''), hb('a1', XA, ys[1], 'K₁ = HMAC_K₀(V₀‖00‖d‖h₁)', ch.K1, 'key'), hb('a2', XA, ys[2], 'V₁ = HMAC_K₁(V₀)', ch.V1, ''), hb('a3', XA, ys[3], 'K₂ = HMAC_K₁(V₁‖01‖d‖h₁)', ch.K2, 'key'), hb('a4', XA, ys[4], 'V₂ = HMAC_K₂(V₁)', ch.V2, ''), val('a5', XA, ys[5], 'k = bits of HMAC_K₂(V₂)', ch.k, 'hot')];
    const Ae = (upto) => A.slice(0, upto + 1).concat(A.slice(1, upto + 1).map((it, i) => W.edge('ae' + i, 'a' + i, 'a' + (i + 1), i % 2 === 0 ? 'key' : '')));
    const Bk = [hb('b0', XB, ys[0], 'e = SHA-256(m), top bits', digest, 'act'), val('b1', XB, ys[1], 'k, from the chain', sg.k, 'hot'), val('b2', XB, ys[2], 'R = k·G, its x', sg.R.x, 'act'), val('b3', XB, ys[3], 'r = R.x mod n', sg.r, 'act'), val('b4', XB, ys[4], 'k⁻¹ mod n', ki, ''), val('b5', XB, ys[5], 's = k⁻¹(e + r·d) mod n', sg.s, 'hot')];
    const Cv = [val('c0', XC, ys[0], 'w = s⁻¹ mod n', wT.w, ''), val('c1', XC, ys[1], 'u₁ = e·w mod n', wT.u1, ''), val('c2', XC, ys[2], 'u₂ = r·w mod n', wT.u2, ''), val('c3', XC, ys[3], 'X = u₁·G + u₂·Q, its x', xT.X.x, 'act'), val('c4', XC, ys[4], 'X.x mod n', xT.v, ver.ok ? 'good' : 'bad')];
    const add = (items, say, facts, meta) => F.add({ items: head.concat(titles, items), say, facts: Object.assign({ msg, n, d: num(d), Q: num(Q.x), curve: toy ? [C.p, C.a, C.b, C.G.x, C.G.y] : [] }, facts), meta });

    F.count('mul');
    add([], `${toy ? 'A toy curve, ' + C.name + ', whose base point G has prime order n = ' + n : 'P-256: the base point G has prime order n, a 256-bit number'}. The private key is d = ${num(d)}; the public key is the point Q = d·G, with x-coordinate ${num(Q.x)}.`, {}, { phase: 'keys' });
    add([Bk[0]], `The message "${msg}" is hashed: SHA-256 = ${W.hs(W.hex(digest), 8)}. As a number cut to the ${ch.qlen} bits of n, e = ${num(sg.e)}.`, { e: num(sg.e), dg: W.hs(W.hex(digest), 8), ql: ch.qlen }, { phase: 'hash' });
    add([Bk[0], ...Ae(0)], `Now the nonce. RFC 6979 runs HMAC-SHA-256 as a deterministic generator with two 32-byte registers: V starts as 01 01 … 01 and the key K as 00 00 … 00. The inputs will be d and h₁ = the hash as a number below n, each written as ${ch.rlen} bytes.`, { rl: ch.rlen, w: 32 }, { phase: 'seed' });
    F.count('hmac', 2);
    add([Bk[0], ...Ae(2)], `K₁ = HMAC with key K₀ of (V₀ ‖ 00 ‖ d ‖ h₁) = ${hs(ch.K1)}, then V₁ = HMAC_K₁(V₀) = ${hs(ch.V1)}. The private key and the message are now mixed into the generator's state.`, { K1: hs(ch.K1), V1: hs(ch.V1) }, { phase: 'k1' });
    F.count('hmac', 2);
    add([Bk[0], ...Ae(4)], `The same again with the byte 01: K₂ = HMAC_K₁(V₁ ‖ 01 ‖ d ‖ h₁) = ${hs(ch.K2)} and V₂ = HMAC_K₂(V₁) = ${hs(ch.V2)}.`, { K2: hs(ch.K2), V2: hs(ch.V2) }, { phase: 'k2' });
    F.count('hmac', ch.tries + 2 * (ch.tries - 1));
    add([Bk[0], ...Ae(5), Bk[1], W.wire('ak', [[XA + BW / 2, ys[5]], [300, ys[5]], [300, ys[1]], [XB - BW / 2, ys[1]]], 'hot')], `Output: T = HMAC_K₂(V₂) = ${W.hs(W.hex(ch.T), 6)}, and k = its top ${ch.qlen} bits = ${num(ch.k)}. ${ch.tries === 1 ? 'It lies in [1, n − 1], so it is used at once' : `It took ${ch.tries} candidates to land in [1, n − 1]`}. Anyone holding d could recompute it; nobody else can predict it.`, { T: W.hs(W.hex(ch.T), 6), k: num(ch.k), ql: ch.qlen, tries: ch.tries }, { phase: 'k' });
    F.count('mul');
    add([...Ae(5), ...Bk.slice(0, 4), W.wire('ak', [[XA + BW / 2, ys[5]], [300, ys[5]], [300, ys[1]], [XB - BW / 2, ys[1]]], 'hot'), W.edge('bk', 'b1', 'b2', 'act'), W.edge('br', 'b2', 'b3', 'act')], `R = k·G, a point whose x-coordinate is ${num(sg.R.x)}; r = R.x mod n = ${num(sg.r)}.`, { Rx: num(sg.R.x), r: num(sg.r) }, { phase: 'R' });
    add([...Ae(5), ...Bk, W.wire('ak', [[XA + BW / 2, ys[5]], [300, ys[5]], [300, ys[1]], [XB - BW / 2, ys[1]]], 'hot'), W.edge('bk', 'b1', 'b2', 'act'), W.edge('br', 'b2', 'b3', 'act')], `With k⁻¹ mod n = ${num(ki)}: s = k⁻¹(e + r·d) mod n = ${num(sg.s)}. The signature is (r, s): as r ‖ s it is ${2 * L} bytes, in DER ${der.length}.`, { ki: num(ki), s: num(sg.s), L2: 2 * L, der: der.length }, { phase: 's' });
    add([...Bk, ...Cv.slice(0, 3)], `The verifier has Q, the message and (r, s), and checks both lie in [1, n − 1]. Then w = s⁻¹ mod n = ${num(wT.w)}, u₁ = e·w mod n = ${num(wT.u1)} and u₂ = r·w mod n = ${num(wT.u2)}.`, { w: num(wT.w), u1: num(wT.u1), u2: num(wT.u2) }, { phase: 'u' });
    F.count('mul', 2);
    add([...Bk, ...Cv, W.verdict('cok', XC, ys[5], ver.ok, ver.ok ? 'equals r: valid' : 'differs from r'), W.edge('cx', 'c3', 'c4', ver.ok ? 'good' : 'bad')], `X = u₁·G + u₂·Q has x-coordinate ${num(xT.X.x)}, and X.x mod n = ${num(xT.v)}, ${ver.ok ? 'which is r: valid' : 'not r: invalid'}. It works because u₁·G + u₂·Q = s⁻¹(e + r·d)·G = k·G = R.`, { Xx: num(xT.X.x), v: num(xT.v), ok: ver.ok }, { phase: 'X' });
    F.count('hmac', 6).count('mul', 2);
    const det = [val('b1', XB, ys[1], 'k, signing again', again.k, again.k === sg.k ? 'good' : 'bad'), val('b5', XB, ys[5], 's, signing again', again.s, again.s === sg.s ? 'good' : 'bad'), val('c1', XC, ys[1], `k for "${W.hs(fake, 6)}"`, sg2.k, 'hot'), val('c5', XC, ys[5], `s for "${W.hs(fake, 6)}"`, sg2.s, 'hot'), W.t('dt1', XB, ys[3], 'same message: same k', 'good', 'middle', 15), W.t('dt2', XC, ys[3], 'one character more: new k', 'hot', 'middle', 15)];
    add([...Ae(5), ...det], `Determinism: signing "${msg}" again gives k = ${num(again.k)}, ${again.k === sg.k ? 'the same' : 'a different'} nonce and ${again.s === sg.s ? 'the same' : 'a different'} signature, which reveals nothing new. Adding one character ("${fake}") gives k = ${num(sg2.k)}, unrelated to the first. A nonce reused across different messages is impossible.`, { k2: num(again.k), k3: num(sg2.k) }, { phase: 'again' });

    const raw = { d, Q, e: sg.e, k: sg.k, r: sg.r, s: sg.s, ki, w: wT.w, u1: wT.u1, u2: wT.u2, X: xT.X, v: xT.v, ok: ver.ok, digest: W.hex(digest), chain: { K1: W.hex(ch.K1), V1: W.hex(ch.V1), K2: W.hex(ch.K2), V2: W.hex(ch.V2), T: W.hex(ch.T), tries: ch.tries }, again: { k: again.k, s: again.s, r: again.r }, fake: { m: fake, k: sg2.k, r: sg2.r, s: sg2.s }, der: W.hex(der), Rx: sg.R.x };
    for (const f of F.list) f.meta.raw = raw;
    const fr = W.fix(F.list, { x: 0, y: 0, w: 900, h: 520 });
    for (const f of fr) f.narrowView = /^(seed|k1|k2|k)$/.test(f.meta.phase) ? { x: 0, y: 80, w: 600, h: 440 } : /^(u|X)$/.test(f.meta.phase) ? { x: 300, y: 80, w: 600, h: 440 } : { x: 150, y: 0, w: 600, h: 520 };
    return { frames: fr, def: W.def('ECDSA with RFC 6979', ['key: d in [1, n − 1], Q = d·G', 'k = HMAC_DRBG(d, H(m))   (RFC 6979)', 'R = k·G, r = R.x mod n', 's = k⁻¹(e + r·d) mod n', 'verify: w = s⁻¹, u₁ = e·w, u₂ = r·w', '  (u₁·G + u₂·Q).x mod n = r ?']) };
  }
})(globalThis.Sifer = globalThis.Sifer || {});
