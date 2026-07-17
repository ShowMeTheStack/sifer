// Diffie–Hellman as message-sequence data with real numbers: the plain exchange (an eavesdropper sees both public
// values and still not the key), the man-in-the-middle who runs one exchange with each side and rewrites traffic,
// and the exchange authenticated with signatures, where the same substitution is caught.
//   S.Proto.dhGroup(name) -> {name, keygen(rng) -> {priv, pub, show}, shared(priv, pub) -> bytes, show(pub)}
//       'x25519' (RFC 7748) or 'toy64' (a 64-bit safe-prime group, numbers small enough to read)
//   S.Proto.dh({seed, group}) -> result with {values: {a, A, b, B, kA, kB}, keysMatch}
//   S.Proto.dhMitm({seed, group, text, altered}) -> result with {values, attack: {success, bobRead}}
//   S.Proto.dhAuth({seed, group, mitm}) -> result with {values, attack}      signatures from S.Proto.signer
(function (S) {
  'use strict';
  const Pr = (S.Proto = S.Proto || {});
  const H = S.Hash, { hex, utf8, concat } = H;
  const { atom: a, enc } = Pr;

  Pr.dhGroup = (nm = 'x25519') => {
    if (nm === 'toy64') {
      const G = Pr.GROUPS.toy64, w = (v) => Uint8Array.from(H.fromHex(v.toString(16).padStart(16, '0')));
      return {
        name: 'toy64', desc: `p = ${G.p} (a 64-bit safe prime), g = ${G.g}`,
        keygen: (rng) => { let x = 0n; for (const b of rng.bytes(8)) x = (x << 8n) | BigInt(b); x = 2n + (x % (G.q - 2n)); const X = Pr.modpow(G.g, x, G.p); return { priv: x, pub: X, show: X.toString() }; },
        shared: (x, Y) => w(Pr.modpow(Y, x, G.p)),
        show: (X) => X.toString(), bytes: w,
      };
    }
    return {
      name: 'x25519', desc: 'X25519: Curve25519 in Montgomery form, 32-byte keys (RFC 7748)',
      keygen: (rng) => { const k = rng.bytes(32); const X = Pr.x25519Base(k); return { priv: k, pub: X, show: hex(X) }; },
      shared: (k, Y) => Pr.x25519(k, Y), show: (X) => hex(X), bytes: (X) => X,
    };
  };
  const kdf = (shared, label) => S.MAC.hkdf('sha256', shared, utf8('dh-demo'), utf8(label), 32);
  const parties = (extra = []) => [
    { id: 'A', label: 'Alice', knows: [a('A', 'id'), a('B', 'id'), a('a', 'secret'), a('g', 'public')] },
    { id: 'B', label: 'Bob', knows: [a('A', 'id'), a('B', 'id'), a('b', 'secret'), a('g', 'public')] },
    ...extra,
  ];
  const seal = (k, text, n) => { const nonce = new Uint8Array(12); nonce[11] = n; return S.MAC.aead.seal(k, nonce, utf8(text)); };
  const open = (k, c, n) => { const nonce = new Uint8Array(12); nonce[11] = n; const r = S.MAC.aead.open(k, nonce, c.ciphertext, c.tag); return r.ok ? new TextDecoder().decode(r.plaintext) : null; };

  Pr.dh = (o = {}) => {
    const G = Pr.dhGroup(o.group), rng = H.rng(o.seed === undefined ? 1 : o.seed);
    const A = G.keygen(rng), B = G.keygen(rng);
    const r = Pr.run({ title: 'Diffie–Hellman', seed: o.seed, parties: parties([{ id: 'E', label: 'Eve', role: 'eavesdropper', knows: [a('g', 'public')] }]) });
    r.note(`The group: ${G.desc}. Alice picks a secret a, Bob a secret b.`);
    r.learn('A', a('g^a', 'public')); r.learn('B', a('g^b', 'public'));
    r.send('A', 'B', [a('g^a', 'public')], { label: 'key share', values: { 'g^a': G.show(A.pub) } });
    r.send('B', 'A', [a('g^b', 'public')], { label: 'key share', values: { 'g^b': G.show(B.pub) } });
    const kA = G.shared(A.priv, B.pub), kB = G.shared(B.priv, A.pub);
    r.learn('A', a('g^ab', 'key')); r.learn('B', a('g^ab', 'key'));
    r.check('A', true, `(g^b)^a = ${hex(kA)}`);
    r.check('B', H.eq(kA, kB), `(g^a)^b = ${hex(kB)}: the same value`);
    r.note('Eve saw g^a and g^b. Getting g^ab from them is the Diffie–Hellman problem, believed as hard as finding a or b.');
    const res = r.result();
    res.values = { group: G.name, a: G.name === 'toy64' ? A.priv.toString() : hex(A.priv), A: G.show(A.pub), b: G.name === 'toy64' ? B.priv.toString() : hex(B.priv), B: G.show(B.pub), kA: hex(kA), kB: hex(kB), key: hex(kdf(kA, 'A-B')) };
    res.keysMatch = H.eq(kA, kB);
    res.eveKnowsKey = r.knows('E', a('g^ab'));
    res.summary = 'Both sides reach the same key from public messages alone; the eavesdropper does not. But nothing says who sent each share.';
    return res;
  };

  Pr.dhMitm = (o = {}) => {
    const G = Pr.dhGroup(o.group), rng = H.rng(o.seed === undefined ? 1 : o.seed);
    const A = G.keygen(rng), B = G.keygen(rng), M1 = G.keygen(rng), M2 = G.keygen(rng);
    const text = o.text || 'Meet at the north gate at six', altered = o.altered || 'Meet at the south gate at nine';
    const r = Pr.run({ title: 'Man in the middle on unauthenticated Diffie–Hellman', seed: o.seed, parties: parties([{ id: 'M', label: 'Mallory', role: 'attacker', knows: [a('g', 'public'), a('m', 'secret'), a('m′', 'secret'), a('g^m', 'public'), a('g^m′', 'public')] }]) });
    r.learn('A', a('g^a', 'public'), a('message', 'data')); r.learn('B', a('g^b', 'public'));
    r.send('A', 'M', [a('g^a', 'public')], { intended: 'B', label: 'key share (intercepted)', values: { 'g^a': G.show(A.pub) } });
    r.send('M', 'B', [a('g^m', 'public')], { as: 'A', label: 'substituted share', values: { 'g^m': G.show(M1.pub) } });
    r.send('B', 'M', [a('g^b', 'public')], { intended: 'A', label: 'key share (intercepted)', values: { 'g^b': G.show(B.pub) } });
    r.send('M', 'A', [a('g^m′', 'public')], { as: 'B', label: 'substituted share', values: { 'g^m′': G.show(M2.pub) } });
    const kA = G.shared(A.priv, M2.pub), kMA = G.shared(M2.priv, A.pub), kB = G.shared(B.priv, M1.pub), kMB = G.shared(M1.priv, B.pub);
    r.learn('A', a('g^am′', 'key')); r.learn('M', a('g^am′', 'key'), a('g^bm', 'key')); r.learn('B', a('g^bm', 'key'));
    r.note(`Alice's key is ${hex(kA).slice(0, 16)}…, shared with Mallory (${hex(kMA).slice(0, 16)}…); Bob's is ${hex(kB).slice(0, 16)}…, also shared with Mallory. Alice and Bob share nothing.`);
    const keyA = kdf(kA, 'A-B'), keyB = kdf(kB, 'A-B');
    const c1 = seal(keyA, text, 1);
    r.send('A', 'M', [enc(a('g^am′', 'key'), a('message', 'data'))], { intended: 'B', label: 'encrypted message', values: { ciphertext: hex(c1.ciphertext), tag: hex(c1.tag) } });
    const read = open(kdf(kMA, 'A-B'), c1, 1);
    r.note(`Mallory decrypts with her key for Alice: “${read}”. She rewrites it.`);
    r.learn('M', a('message′', 'data'));
    const c2 = seal(kdf(kMB, 'A-B'), altered, 1);
    r.send('M', 'B', [enc(a('g^bm', 'key'), a('message′', 'data'))], { as: 'A', label: 'rewritten message', values: { ciphertext: hex(c2.ciphertext), tag: hex(c2.tag) } });
    const bobRead = open(keyB, c2, 1);
    r.check('B', bobRead !== null, `the tag verifies under his key, so he trusts “${bobRead}”`);
    const res = r.result();
    res.ok = false;
    res.values = { group: G.name, A: G.show(A.pub), B: G.show(B.pub), M1: G.show(M1.pub), M2: G.show(M2.pub), kA: hex(kA), kB: hex(kB) };
    res.attack = { success: bobRead === altered && read === text, aliceSent: text, mallorySaw: read, bobRead };
    res.summary = 'Encryption and MACs were perfect, yet Mallory read and changed everything: each side ran a correct exchange with the wrong party.';
    return res;
  };

  /** the signed transcript: both shares and the signer's name */
  const transcript = (G, X, Y, who) => concat(utf8('dh-auth|'), G.bytes(X), G.bytes(Y), utf8('|' + who));
  Pr.dhAuth = (o = {}) => {
    const G = Pr.dhGroup(o.group), rng = H.rng(o.seed === undefined ? 1 : o.seed), seed = o.seed === undefined ? 1 : o.seed;
    const sA = Pr.signer('Alice', { seed, bits: o.bits }), sB = Pr.signer('Bob', { seed, bits: o.bits });
    const A = G.keygen(rng), B = G.keygen(rng), M1 = G.keygen(rng), M2 = G.keygen(rng);
    const extra = o.mitm ? [{ id: 'M', label: 'Mallory', role: 'attacker', knows: [a('g', 'public'), a('m', 'secret'), a('g^m', 'public'), a('g^m′', 'public'), a('pkA', 'public'), a('pkB', 'public')] }] : [];
    const ps = parties(extra);
    ps[0].knows.push(a('skA', 'key'), a('pkA', 'public'), a('pkB', 'public')); ps[1].knows.push(a('skB', 'key'), a('pkA', 'public'), a('pkB', 'public'));
    const r = Pr.run({ title: o.mitm ? 'Mallory against authenticated Diffie–Hellman' : 'Authenticated Diffie–Hellman', seed, parties: ps });
    r.note(`Each side has a long-term signing key (${sA.kind}) whose public half the other already trusts, for example from a certificate.`);
    r.learn('A', a('g^a', 'public')); r.learn('B', a('g^b', 'public'));
    let attack = null;
    if (!o.mitm) {
      r.send('A', 'B', [a('g^a', 'public')], { label: 'key share', values: { 'g^a': G.show(A.pub) } });
      const sigB = sB.sign(transcript(G, A.pub, B.pub, 'Bob'));
      r.send('B', 'A', [a('g^b', 'public'), Pr.sig('B', a('g^a'), a('g^b'), a('B', 'id'))], { label: 'share and signature', values: { 'g^b': G.show(B.pub), sig: hex(sigB).slice(0, 32) + '…' } });
      r.check('A', sB.verify(sB.pub, transcript(G, A.pub, B.pub, 'Bob'), sigB), 'Bob\'s signature covers her own g^a and his g^b: the share really is Bob\'s, and for this session');
      const sigA = sA.sign(transcript(G, B.pub, A.pub, 'Alice'));
      r.send('A', 'B', [Pr.sig('A', a('g^b'), a('g^a'), a('A', 'id'))], { label: 'signature', values: { sig: hex(sigA).slice(0, 32) + '…' } });
      r.check('B', sA.verify(sA.pub, transcript(G, B.pub, A.pub, 'Alice'), sigA), 'Alice\'s signature covers both shares');
      r.learn('A', a('g^ab', 'key')); r.learn('B', a('g^ab', 'key'));
      r.check('A', H.eq(G.shared(A.priv, B.pub), G.shared(B.priv, A.pub)), 'both compute the same g^ab, and each knows who holds it');
    } else {
      r.send('A', 'M', [a('g^a', 'public')], { intended: 'B', label: 'key share (intercepted)', values: { 'g^a': G.show(A.pub) } });
      r.send('M', 'B', [a('g^m', 'public')], { as: 'A', label: 'substituted share', values: { 'g^m': G.show(M1.pub) } });
      const sigB = sB.sign(transcript(G, M1.pub, B.pub, 'Bob'));
      r.send('B', 'M', [a('g^b', 'public'), Pr.sig('B', a('g^m'), a('g^b'), a('B', 'id'))], { intended: 'A', label: 'share and signature (intercepted)', values: { sig: hex(sigB).slice(0, 32) + '…' } });
      r.note('Mallory needs Bob\'s signature over (g^a, g^m′). She cannot make one without Bob\'s private key; the best she has is the one Bob made over (g^m, g^b).');
      r.send('M', 'A', [a('g^m′', 'public'), Pr.sig('B', a('g^m'), a('g^b'), a('B', 'id'))], { as: 'B', label: 'substituted share, Bob\'s old signature', values: { 'g^m′': G.show(M2.pub) } });
      const okA = sB.verify(sB.pub, transcript(G, A.pub, M2.pub, 'Bob'), sigB);
      r.check('A', okA, 'the signature does not cover (g^a, g^m′): she aborts before using any key');
      attack = { success: okA, detectedBy: 'A' };
    }
    const res = r.result();
    res.values = { group: G.name, A: G.show(A.pub), B: G.show(B.pub), signer: sA.kind };
    res.attack = attack;
    res.summary = o.mitm ? 'The substitution is caught: a signature binds each share to its owner and to this exchange.' : 'Signatures over both shares tie the exchange to the long-term identities: this is the core of the TLS 1.3 handshake.';
    return res;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
