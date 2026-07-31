// The public-key bench on elliptic curves: ECDH and ECDSA on a toy curve beside P-256 (with the rules that keep its
// nonce fresh), X25519 with its clamping and its ladder, Ed25519 with its expanded secret and derived
// nonce, and Schnorr signatures in a prime-order subgroup of Z_p*. Every intermediate value is shown.
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const MB = () => S.MathBench, U = () => S.BenchUI;
  const PK = S.PkTools;
  const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
  const unhex = (t, label, n) => {
    const s = String(t || '').replace(/[\s:]/g, '').replace(/^0x/i, '').toLowerCase();
    if (!/^[0-9a-f]*$/.test(s)) throw new Error(label + ': hex digits only.');
    if (s.length !== 2 * n) throw new Error(label + ' must be ' + n + ' bytes (' + 2 * n + ' hex digits); it has ' + s.length + ' digits.');
    const out = new Uint8Array(n); for (let i = 0; i < n; i++) out[i] = parseInt(s.substr(2 * i, 2), 16); return out;
  };
  const rand32 = () => { const b = new Uint8Array(32); crypto.getRandomValues(b); return hex(b); };
  const party = (cls, name, ...kids) => h('div.pk-party.' + cls, h('h4', h('span.dot'), name), ...kids);
  const secret = (v) => h('span.pk-secret', typeof v === 'string' ? v : MB().n(v));
  const pt = (P) => (P ? h('span.pk-pt', '(', MB().n(P.x), ', ', MB().n(P.y), ')') : 'O');
  const binder = (o, save, r) => (k, id, label, attrs, mono) => U().field(label, U().input(id, o[k], (v) => { o[k] = v; save(); r(); }, { mono: mono !== false, attrs: attrs || {} }));
  const curveOf = (o) => (o.curve === 'p256' ? S.ECC.P256 : S.ECC.toy('gf101'));
  const curveSeg = (o, save, done) => U().seg('pkCurve', [['toy', 'Toy curve (p = 101)'], ['p256', 'P-256']], o.curve, (v) => { o.curve = v; save(); done(); });
  const scalarOf = (o, key, C, label) => {
    if (o.curve === 'toy' && String(o[key] || '').trim()) return MB().big(o[key], label, { min: 1, max: String(C.n - 1n), why: '(n − 1)' });
    const keep = '_' + key + (o.curve === 'p256' ? 'R' : 'T');
    if (!o[keep]) o[keep] = String(1n + S.NT.randBelow(C.n - 1n));
    return BigInt(o[keep]);
  };

  // ---- ECDH ----------------------------------------------------------------------------------------------------------
  PK.ecdh = function (left, right, o, save) {
    const run = () => {
      right.innerHTML = '';
      MB().guard(right, () => {
        const C = curveOf(o), dA = scalarOf(o, 'a', C, 'Alice\'s d'), dB = scalarOf(o, 'b', C, 'Bob\'s d');
        const A = S.ECC.keygen(C, dA), B = S.ECC.keygen(C, dB);
        const sA = S.ECC.ecdh(C, dA, B.Q), sB = S.ECC.ecdh(C, dB, A.Q);
        right.append(MB().result('Keys', (o.curve === 'p256' ? 'P-256: a 256-bit prime field and a base point G of prime order n.' : 'y² = x³ + 6x + 14 over GF(101), 103 points, G = (1, 18) of prime order 103.') + ' Each private key is a number d; its public key is the point Q = d·G.',
          h('div.pk-parties', party('alice', 'Alice', U().kv('secret d', secret(dA)), U().kv('Q = d·G', pt(A.Q))), party('bob', 'Bob', U().kv('secret d', secret(dB)), U().kv('Q = d·G', pt(B.Q))))));
        right.append(MB().result('The shared point', 'Each multiplies the other\'s point by its own secret: both reach dA·dB·G. The shared secret is its x-coordinate.',
          h('div.pk-parties', party('alice', 'Alice: dA·QB', U().kv('', pt(sA.S))), party('bob', 'Bob: dB·QA', U().kv('', pt(sB.S)))),
          MB().facts(['agree', sA.S.x === sB.S.x ? 'yes' : 'no'], ['shared bytes', hex(sA.shared)]), U().trace(sA.trace)));
      });
    };
    const r = S.UI.debounce(run, 250), bind = binder(o, save, r);
    const toy = h('div.brow', bind('a', 'pkCa', 'Alice\'s d (empty: random)', { inputmode: 'numeric' }), bind('b', 'pkCb', 'Bob\'s d (empty: random)', { inputmode: 'numeric' }));
    const fresh = h('button.btn.small', { type: 'button', id: 'pkCfresh' }, icon('shuffle'), 'New random keys');
    fresh.addEventListener('click', () => { for (const k of ['_aR', '_bR', '_aT', '_bT']) o[k] = null; save(); run(); });
    const vis = () => { toy.style.display = o.curve === 'toy' ? '' : 'none'; };
    left.appendChild(MB().result('ECDH', 'Diffie–Hellman with points instead of powers. The peer\'s point is validated first.', curveSeg(o, save, () => { vis(); run(); }), toy, fresh));
    vis(); run();
  };

  // ---- X25519 -------------------------------------------------------------------------------------------------------
  // RFC 7748, section 6.1: the published example of an X25519 exchange (test data)
  const RFC7748 = { a: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', b: '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb' };
  PK.x25519 = function (left, right, o, save) {
    const X = S.ECC.X25519;
    const run = () => {
      right.innerHTML = '';
      if (!X) { right.appendChild(U().missing('The X25519 engine')); return; }
      MB().guard(right, () => {
        if (!o.a) o.a = rand32(); if (!o.b) o.b = rand32();
        const a = unhex(o.a, 'Alice\'s secret', 32), b = unhex(o.b, 'Bob\'s secret', 32);
        const ca = X.clamp(a), pa = X.publicKey(a), pb = X.publicKey(b);
        const ab = X.x25519(a, pb, { trace: true }), ba = X.x25519(b, pa);
        right.append(MB().result('Clamping Alice\'s secret', '32 random bytes become the scalar k: three bit changes make every key a multiple of the cofactor 8, with its top bit in the same place.', U().hexGrid(a, { label: 'secret', cols: 16 }), U().trace(ca.trace)));
        right.append(MB().result('Public keys', 'k times the base point u = 9, by the Montgomery ladder on u alone.', h('div.pk-parties', party('alice', 'Alice', U().kv('u', h('code.v.pk-hex', hex(pa)))), party('bob', 'Bob', U().kv('u', h('code.v.pk-hex', hex(pb)))))));
        const st = ab.steps || [];
        const sh = (v) => { const t = BigInt(v).toString(16); return t.length > 18 ? '0x' + t.slice(0, 8) + '…' + t.slice(-8) : '0x' + t; };
        const rows = st.map((s) => [s.t, s.bit, s.swap ? 'swap' : '—', sh(s.x2), sh(s.x3)]);
        const shown = rows.length > 12 ? rows.slice(0, 6).concat([['…', '…', '…', (rows.length - 10) + ' more steps', '']], rows.slice(-4)) : rows;
        right.append(MB().result('The shared secret', 'Alice runs the ladder on Bob\'s u with her k, Bob on hers with his: 255 steps each, a conditional swap and the same work for every bit.',
          MB().table(['bit t', 'value', 'swap', 'x2 (projective)', 'x3 (projective)'], shown, { id: 'pkXladder' }),
          MB().facts(['Alice gets', h('code.v.pk-hex', hex(ab.out))], ['Bob gets', h('code.v.pk-hex', hex(ba.out))], ['agree', hex(ab.out) === hex(ba.out) ? 'yes' : 'no'], ab.cost ? ['work', ab.cost.M + ' multiplications and ' + ab.cost.S + ' squarings in the field'] : null)));
      });
    };
    const r = S.UI.debounce(run, 300), bind = binder(o, save, r);
    const fresh = h('button.btn.small', { type: 'button', id: 'pkXfresh' }, icon('shuffle'), 'New random secrets');
    fresh.addEventListener('click', () => { o.a = rand32(); o.b = rand32(); left.querySelector('#pkXa').value = o.a; left.querySelector('#pkXb').value = o.b; save(); run(); });
    const rfc = h('button.btn.small', { type: 'button', id: 'pkXrfc' }, 'The RFC 7748 example');
    rfc.addEventListener('click', () => { Object.assign(o, RFC7748); left.querySelector('#pkXa').value = o.a; left.querySelector('#pkXb').value = o.b; save(); run(); });
    if (!o.a) o.a = rand32(); if (!o.b) o.b = rand32();
    left.appendChild(MB().result('X25519', 'Curve25519 in Montgomery form, with only the u-coordinate: the key exchange of TLS 1.3 and most of the modern web.',
      bind('a', 'pkXa', 'Alice\'s secret (32 bytes, hex)', { spellcheck: 'false' }), bind('b', 'pkXb', 'Bob\'s secret (32 bytes, hex)', { spellcheck: 'false' }), h('div.brow', fresh, rfc)));
    run();
  };

  /**
   * Why a signature nonce must never repeat, and how real signers make sure of it, with links to the topics that show
   * it (part 9's signatures, part 6's nonce rule, and part 11's nonce topics once they are written).
   */
  PK.nonceRules = function (which) {
    const T = (id) => S.byId && S.byId(id);
    const ids = ['p09-sigs', 'integrity-nonce'].concat((S.topics || []).filter((t) => /^p11-/.test(t.family || '') && /nonce/.test(t.id)).map((t) => t.id));
    const links = ids.map(T).filter(Boolean).map((t) => h('a.btn.small', { href: '#topic=' + t.id, dataset: { topic: t.id } }, icon('library'), t.title));
    const lines = which === 'ecdsa'
      ? ['Each signature needs a fresh secret k: two signatures with one k, or a k that is even slightly predictable, are enough to give away d.', 'RFC 6979 derives k from d and the message hash with HMAC (the “k from RFC 6979” setting above), so a weak random source can no longer repeat it.', 'Ed25519 builds the same idea in: its nonce is a hash of a secret prefix and the message.']
      : ['s = k + e·x is linear in the secret: one repeated or predictable k gives away x.', 'Derive k from the private key and the message, as RFC 6979 and Ed25519 do, or mix a hash of both into fresh randomness.'];
    return MB().result('The nonce must never repeat', lines[0], h('ul.lab-rules', ...lines.slice(1).map((l) => h('li', l))), links.length ? h('div.lab-topics', { id: 'pkNonceTopics' }, h('span.k', 'See it worked through'), ...links) : null);
  };

  // ---- ECDSA ------------------------------------------------------------------------------------
  PK.ecdsa = function (left, right, o, save) {
    const run = () => {
      right.innerHTML = '';
      MB().guard(right, () => {
        const C = curveOf(o), d = scalarOf(o, 'd', C, 'd'), key = S.ECC.keygen(C, d);
        const opts = o.nonce === 'own' && o.curve === 'toy' ? { k: MB().big(o.k, 'k', { min: 1, max: String(C.n - 1n) }) } : { nonce: o.nonce === 'random' ? 'random' : 'rfc6979' };
        const sig = S.ECC.ecdsa.sign(C, d, o.msg, opts);
        const ver = S.ECC.ecdsa.verify(C, key.Q, o.msg, sig), bad = S.ECC.ecdsa.verify(C, key.Q, o.msg + '!', sig);
        right.append(MB().result('Keys', 'd is private; Q = d·G is public.', MB().facts(['d', secret(d)], ['Q', pt(key.Q)], ['n (order of G)', MB().n(C.n)])));
        right.append(MB().result('Sign', 'Hash the message to e, pick a nonce k, and give (r, s): r from the point k·G, s = k⁻¹(e + r·d) mod n.', MB().facts(['k', secret(sig.k)], ['R = k·G', pt(sig.R)], ['r', MB().n(sig.r)], ['s', MB().n(sig.s)], ['DER', h('code.v.pk-hex', hex(S.ECC.der.encode(sig)))]), U().trace(sig.trace)));
        right.append(MB().result('Verify', 'With Q only: u₁·G + u₂·Q lands on R exactly when the signature was made with d.', U().trace(ver.trace), MB().facts(['valid', ver.ok ? h('span.pk-ok', 'yes') : h('span.pk-bad', 'no')], ['with one more character', bad.ok ? 'valid?!' : h('span.pk-bad', 'rejected')])));
        right.append(PK.nonceRules('ecdsa'));
      });
    };
    const r = S.UI.debounce(run, 250), bind = binder(o, save, r);
    const toyBox = h('div', bind('d', 'pkSd', 'private d (empty: random)', { inputmode: 'numeric' }));
    const kBox = bind('k', 'pkSk', 'my own k', { inputmode: 'numeric' });
    const vis = () => { toyBox.style.display = o.curve === 'toy' ? '' : 'none'; kBox.style.display = o.curve === 'toy' && o.nonce === 'own' ? '' : 'none'; };
    left.appendChild(MB().result('ECDSA', 'The signature of TLS certificates and most cryptocurrencies.', curveSeg(o, save, () => { vis(); run(); }), toyBox,
      U().seg('pkNonce', [['rfc6979', 'k from RFC 6979'], ['random', 'Random k'], ['own', 'My own k']], o.nonce, (v) => { o.nonce = v; save(); vis(); run(); }), kBox,
      bind('msg', 'pkSm', 'message', {}, false)));
    vis(); run();
  };

  // ---- Ed25519 ------------------------------------------------------------------------------------------------------
  // RFC 8032, section 7.1, test 1: the published secret key (test data)
  const RFC8032 = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
  PK.ed25519 = function (left, right, o, save) {
    const E = S.ECC.Ed25519;
    const run = () => {
      right.innerHTML = '';
      if (!E) { right.appendChild(U().missing('The Ed25519 engine')); return; }
      MB().guard(right, () => {
        if (!o.sk) o.sk = rand32();
        const sk = unhex(o.sk, 'The secret', 32), msg = new TextEncoder().encode(o.msg);
        const k = E.keygen(sk), sig = E.sign(sk, msg), ver = E.verify(k.pub, msg, sig.sig), bad = E.verify(k.pub, new TextEncoder().encode(o.msg + '!'), sig.sig);
        right.append(MB().result('Keys', 'SHA-512 of the 32-byte secret gives the scalar a (clamped) and a prefix used only for nonces; the public key is A = a·B, written as 32 bytes.', MB().facts(['a', secret(k.a)], ['prefix', h('code.v.pk-hex.pk-secret', hex(k.prefix))], ['public key', h('code.v.pk-hex', hex(k.pub))]), U().trace(k.trace)));
        right.append(MB().result('Sign', 'The nonce is a hash of the prefix and the message: never random, so it can never repeat for two messages.', U().hexGrid(sig.sig, { label: 'signature R ‖ S', cols: 16, id: 'pkEdSig' }), U().trace(sig.trace)));
        right.append(MB().result('Verify', 'Check S·B = R + H(R ‖ A ‖ M)·A, with every value taken from the signature and the public key.', U().trace(ver.trace), MB().facts(['valid', ver.ok ? h('span.pk-ok', 'yes') : h('span.pk-bad', 'no')], ['with one more character', bad.ok ? 'valid?!' : h('span.pk-bad', 'rejected')])));
      });
    };
    const r = S.UI.debounce(run, 300), bind = binder(o, save, r);
    const fresh = h('button.btn.small', { type: 'button', id: 'pkEfresh' }, icon('shuffle'), 'A new random secret');
    fresh.addEventListener('click', () => { o.sk = rand32(); left.querySelector('#pkEsk').value = o.sk; save(); run(); });
    const rfc = h('button.btn.small', { type: 'button', id: 'pkErfc' }, 'RFC 8032, test 1');
    rfc.addEventListener('click', () => { o.sk = RFC8032; o.msg = ''; left.querySelector('#pkEsk').value = o.sk; left.querySelector('#pkEm').value = ''; save(); run(); });
    if (!o.sk) o.sk = rand32();
    left.appendChild(MB().result('Ed25519', 'EdDSA on the twisted Edwards form of Curve25519, whose addition law has no special cases.', bind('sk', 'pkEsk', 'secret (32 bytes, hex)', { spellcheck: 'false' }), bind('msg', 'pkEm', 'message', {}, false), h('div.brow', fresh, rfc)));
    run();
  };

  // ---- Schnorr ------------------------------------------------------------------------------------------------------
  PK.schnorr = function (left, right, o, save) {
    const SIG = S.SIG;
    const run = () => {
      right.innerHTML = '';
      if (!SIG) { right.appendChild(U().missing('The signature engine')); return; }
      MB().guard(right, () => {
        const params = SIG.toyParams(MB().big(o.qMin, 'q at least', { min: 11, max: '1000000000000' }));
        const key = SIG.schnorrKey(params, o.x.trim() ? MB().big(o.x, 'x', { min: 1, max: String(params.q - 1n) }) : undefined);
        const k = o.k.trim() ? MB().big(o.k, 'k', { min: 1, max: String(params.q - 1n) }) : undefined;
        const sig = SIG.schnorrSign(key, o.msg, k), ver = SIG.schnorrVerify(key.pub, o.msg, sig), bad = SIG.schnorrVerify(key.pub, o.msg + '!', sig);
        right.append(MB().result('The group and the key', 'q prime, q dividing p − 1, g of order q; x private, y = g^x public.', MB().facts(['p, q, g', params.p + ', ' + params.q + ', ' + params.g], ['x', secret(key.x)], ['y', MB().n(key.y)])));
        right.append(MB().result('Sign: commit, challenge, respond', 'R = g^k commits to a nonce; the challenge e is a hash of R and the message; s = k + e·x. Linear in x: the property multi-signatures build on.', MB().facts(['k', secret(sig.k)], ['R', MB().n(sig.R)], ['e', MB().n(sig.e)], ['s', MB().n(sig.s)]), U().trace(sig.trace)));
        right.append(MB().result('Verify', 'g^s·y^(−e) gives back R, and so the same challenge.', U().trace(ver.trace), MB().facts(['valid', ver.ok ? h('span.pk-ok', 'yes') : h('span.pk-bad', 'no')], ['with one more character', bad.ok ? 'valid?!' : h('span.pk-bad', 'rejected')])));
        right.append(PK.nonceRules('schnorr'));
      });
    };
    const r = S.UI.debounce(run, 250), bind = binder(o, save, r);
    left.appendChild(MB().result('Schnorr', 'The simplest discrete-logarithm signature, here in a toy subgroup of Z_p*.', bind('qMin', 'pkZq', 'q: the first prime at least', { inputmode: 'numeric' }),
      h('div.brow', bind('x', 'pkZx', 'private x (empty: random)', { inputmode: 'numeric' }), bind('k', 'pkZk', 'nonce k (empty: random)', { inputmode: 'numeric' })),
      bind('msg', 'pkZm', 'message', {}, false)));
    run();
  };

  // ---- what the diagram checker looks at ------------------------------------------------------------------------------
  const click = (sel) => `document.querySelector('${sel}').click(); await new Promise((r) => setTimeout(r, 250));`;
  if (S.Checks) for (const [name, setup] of [['ECDH, toy curve', click('#pk-tool button[data-v=ecdh]') + click('#pkCurve button[data-v=toy]')], ['ECDH, P-256', click('#pk-tool button[data-v=ecdh]') + click('#pkCurve button[data-v=p256]')],
    ['X25519, the RFC 7748 example', click('#pk-tool button[data-v=x25519]') + click('#pkXrfc')], ['ECDSA, toy curve', click('#pk-tool button[data-v=ecdsa]') + click('#pkCurve button[data-v=toy]')],
    ['ECDSA, P-256', click('#pk-tool button[data-v=ecdsa]') + click('#pkCurve button[data-v=p256]')], ['Ed25519, RFC 8032 test 1', click('#pk-tool button[data-v=ed25519]') + click('#pkErfc')], ['Schnorr', click('#pk-tool button[data-v=schnorr]')]]) {
    S.Checks.push({ group: 'bench-pk', name, hash: 'bench/pk', ready: "document.querySelector('#pkOut .bcard')", setup, sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
