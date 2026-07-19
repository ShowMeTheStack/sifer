// ECDH and ECDSA on any short Weierstrass curve with a prime-order base point, traced step by step. Nonces come
// from RFC 6979 (deterministic, HMAC-SHA-256) unless a random or a forced one is asked for; signatures convert to and
// from DER and the fixed-width r ‖ s form (IEEE P1363).
//   S.ECC.keygen(C[, d]) -> {d, Q}
//   S.ECC.ecdh(C, d, Q) -> {S, shared: bytes of S.x, trace}          Q is validated first
//   S.ECC.ecdsa.sign(C, d, msg, {k?, nonce: 'rfc6979'|'random', digest?}) -> {r, s, k, e, R, trace}
//   S.ECC.ecdsa.verify(C, Q, msg, {r, s}, {digest?}) -> {ok, trace}
//   S.ECC.ecdsa.hashToInt(C, digest) / rfc6979(C, d, digest) -> {k, trace}
//   S.ECC.der.encode({r, s}) / decode(bytes);  S.ECC.p1363.encode(C, {r, s}) / decode(C, bytes)
//   S.ECC.hmacSha256(key, msg)
(function (S) {
  'use strict';
  const E = (S.ECC = S.ECC || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const f = (v) => E.fmt(v), fp = (P) => E.fp(P);
  const sha256 = (m) => S.SHA256.hash(m);
  const cat = (...as) => { const out = new Uint8Array(as.reduce((n, a) => n + a.length, 0)); let o = 0; for (const a of as) { out.set(a, o); o += a.length; } return out; };
  E.concat = cat;
  E.hmacSha256 = (key, msg) => {
    if (key.length > 64) key = sha256(key);
    const k = new Uint8Array(64); k.set(key);
    const ip = k.map((v) => v ^ 0x36), op = k.map((v) => v ^ 0x5c);
    return sha256(cat(op, sha256(cat(ip, msg))));
  };
  const big = E.bytesToBig, toB = E.bigToBytes;

  E.keygen = (C, d) => {
    if (d == null) d = 1n + S.NT.randBelow(C.n - 1n);
    d = BigInt(d);
    return { d, Q: C.mul(d, C.G) };
  };

  E.ecdh = (C, d, Q) => {
    const v = C.validate(Q), trace = [step('validate', 'Check the peer\'s public point before using it.', { checks: v.checks }), ...v.trace];
    if (!v.ok) { trace.push(step('reject', 'The peer\'s point fails validation: refuse to compute a shared secret.', {})); return { S: null, shared: null, trace }; }
    const Sp = C.mul(d, Q);
    trace.push(step('multiply', `Multiply the peer's point by our secret d = ${f(d)}: S = d·Q = ${fp(Sp)}.`, { S: Sp }));
    if (!Sp) { trace.push(step('reject', 'The result is O: abort.', {})); return { S: null, shared: null, trace }; }
    const shared = toB(Sp.x, C.size);
    trace.push(step('shared', `The shared secret is the x-coordinate of S as ${C.size} bytes; both sides get the same point because d_A·(d_B·G) = d_B·(d_A·G).`, { shared }));
    return { S: Sp, shared, trace };
  };

  const hashToInt = (C, digest) => {
    const nb = E.bitLength(C.n), e = big(digest), db = digest.length * 8;
    return db > nb ? e >> BigInt(db - nb) : e;
  };
  /** RFC 6979 section 3.2 with HMAC-SHA-256 */
  const rfc6979 = (C, d, digest) => {
    const q = C.n, qlen = E.bitLength(q), rlen = Math.ceil(qlen / 8), trace = [];
    const bits2int = (b) => { const v = big(b), bl = b.length * 8; return bl > qlen ? v >> BigInt(bl - qlen) : v; };
    const int2oct = (v) => toB(v, rlen);
    const bits2oct = (b) => { const z1 = bits2int(b); return int2oct(z1 >= q ? z1 - q : z1); };
    let V = new Uint8Array(32).fill(1), K = new Uint8Array(32);
    const x = int2oct(d), h1 = bits2oct(digest);
    K = E.hmacSha256(K, cat(V, [0], x, h1)); V = E.hmacSha256(K, V);
    K = E.hmacSha256(K, cat(V, [1], x, h1)); V = E.hmacSha256(K, V);
    trace.push(step('rfc6979-seed', `RFC 6979: seed HMAC-SHA-256 with the private key and the message hash, so the nonce is a fixed function of both and never repeats for different messages. V = ${S.bytes.hex(V).slice(0, 16)}…`, { V: S.bytes.hex(V), K: S.bytes.hex(K) }));
    for (let round = 1; round < 1000; round++) {
      let T = new Uint8Array(0);
      while (T.length < rlen) { V = E.hmacSha256(K, V); T = cat(T, V); }
      const k = bits2int(T);
      if (k >= 1n && k < q) { trace.push(step('rfc6979-k', `Candidate ${round}: k = ${f(k)} lies in [1, n − 1]: use it.`, { k, round })); return { k, trace }; }
      trace.push(step('rfc6979-retry', `Candidate ${round} is out of range: stir K and V and try again.`, { round }));
      K = E.hmacSha256(K, cat(V, [0])); V = E.hmacSha256(K, V);
    }
    throw new Error('no nonce');
  };

  const sign = (C, d, msg, o = {}) => {
    d = BigInt(d);
    const n = C.n, trace = [], digest = o.digest || sha256(msg), e = hashToInt(C, digest);
    trace.push(step('hash', `Hash the message: H(m) = ${S.bytes.hex(digest).slice(0, 32)}${digest.length > 16 ? '…' : ''}, so e = ${f(e)}.`, { digest: S.bytes.hex(digest), e }));
    let k;
    if (o.k != null) { k = BigInt(o.k); trace.push(step('nonce', `Use the given nonce k = ${f(k)}.`, { k, source: 'given' })); }
    else if (o.nonce === 'random') { k = 1n + S.NT.randBelow(n - 1n); trace.push(step('nonce', `Draw a fresh random nonce k = ${f(k)} from [1, n − 1].`, { k, source: 'random' })); }
    else { const r6 = rfc6979(C, d, digest); k = r6.k; trace.push(...r6.trace); }
    const R = C.mul(k, C.G), r = E.mod(R.x, n);
    trace.push(step('R', `R = k·G = ${fp(R)}; r = R.x mod n = ${f(r)}.`, { R, r }));
    if (r === 0n) throw new Error('r = 0: choose another k');
    const ki = E.inv(k, n), s = E.mod(ki * (e + r * d), n);
    trace.push(step('s', `k⁻¹ mod n = ${f(ki)}; s = k⁻¹(e + r·d) mod n = ${f(s)}.`, { ki, s }));
    if (s === 0n) throw new Error('s = 0: choose another k');
    let sOut = s;
    if (o.lowS && s > n / 2n) { sOut = n - s; trace.push(step('low-s', `s is in the upper half: replace it by n − s = ${f(sOut)}, which verifies just as well.`, { s: sOut })); }
    trace.push(step('signature', `The signature is (r, s) = (${f(r)}, ${f(sOut)}).`, { r, s: sOut }));
    return { r, s: sOut, k, e, R, trace };
  };

  const verify = (C, Q, msg, sig, o = {}) => {
    const n = C.n, trace = [], r = BigInt(sig.r), s = BigInt(sig.s);
    const no = (say) => { trace.push(step('reject', say, {})); return { ok: false, trace }; };
    if (r < 1n || r >= n || s < 1n || s >= n) return no('r and s must both lie in [1, n − 1]: rejected.');
    const v = C.validate(Q);
    if (!v.ok) { trace.push(...v.trace); return no('The public key is not a valid point: rejected.'); }
    const digest = o.digest || sha256(msg), e = hashToInt(C, digest);
    trace.push(step('hash', `Hash the message: e = ${f(e)}.`, { e }));
    const w = E.inv(s, n), u1 = E.mod(e * w, n), u2 = E.mod(r * w, n);
    trace.push(step('w', `w = s⁻¹ mod n = ${f(w)}; u₁ = e·w = ${f(u1)}; u₂ = r·w = ${f(u2)}.`, { w, u1, u2 }));
    const X = C.add(C.mul(u1, C.G), C.mul(u2, Q));
    if (!X) return no('u₁·G + u₂·Q is O: rejected.');
    const vv = E.mod(X.x, n), ok = vv === r;
    trace.push(step('X', `X = u₁·G + u₂·Q = ${fp(X)}; X.x mod n = ${f(vv)}.`, { X, v: vv }));
    trace.push(step(ok ? 'accept' : 'reject', ok ? `It equals r = ${f(r)}: the signature is valid. (u₁·G + u₂·Q = s⁻¹(e + r·d)·G = k·G = R.)` : `It differs from r = ${f(r)}: the signature is invalid.`, { ok }));
    return { ok, trace };
  };
  E.ecdsa = { sign, verify, hashToInt, rfc6979 };

  // ---- signature encodings
  const derInt = (v) => {
    let b = v === 0n ? new Uint8Array([0]) : toB(v, Math.ceil(E.bitLength(v) / 8));
    if (b[0] & 0x80) b = cat([0], b);
    return cat([2, b.length], b);
  };
  E.der = {
    encode: ({ r, s }) => { const body = cat(derInt(r), derInt(s)); if (body.length > 127) throw new Error('too long'); return cat([0x30, body.length], body); },
    decode: (b) => {
      if (b[0] !== 0x30 || b[1] !== b.length - 2) throw new Error('not a DER sequence');
      let i = 2;
      const int = () => { if (b[i] !== 2) throw new Error('expected an INTEGER'); const L = b[i + 1], v = big(b.subarray(i + 2, i + 2 + L)); i += 2 + L; return v; };
      const r = int(), s = int();
      return { r, s };
    },
  };
  E.p1363 = {
    encode: (C, { r, s }) => { const L = Math.ceil(E.bitLength(C.n) / 8); return cat(toB(r, L), toB(s, L)); },
    decode: (C, b) => { const L = b.length / 2; return { r: big(b.subarray(0, L)), s: big(b.subarray(L)) }; },
  };
})(globalThis.Sifer = globalThis.Sifer || {});
