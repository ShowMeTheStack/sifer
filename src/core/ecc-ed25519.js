// Ed25519 (RFC 8032): the twisted Edwards curve −x² + y² = 1 + d·x²y² over GF(2²⁵⁵ − 19) in extended coordinates
// (X : Y : Z : T) with x = X/Z, y = Y/Z, xy = T/Z, whose addition law is complete (no special cases). EdDSA with
// SHA-512: the secret expanded and clamped, the nonce derived from the hash of the prefix and the message, and the
// challenge from R ‖ A ‖ M, all traced.
//   S.ECC.Ed25519.keygen(secret32) -> {a, prefix, A: point, pub: 32 bytes, trace}
//   S.ECC.Ed25519.sign(secret32, msg) -> {sig: 64 bytes, r, R, k, S, trace}
//   S.ECC.Ed25519.verify(pub32, msg, sig64) -> {ok, trace}
//   .encode(P) / decode(bytes) -> point or null;  .add / dbl / mul(k, P) / eq / affine(P);  .p, .d, .L, .B
(function (S) {
  'use strict';
  const E = (S.ECC = S.ECC || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const p = (1n << 255n) - 19n, L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const mod = (v, m = p) => { const r = v % m; return r < 0n ? r + m : r; };
  const pow = (b, e, m = p) => { let r = 1n; b = mod(b, m); while (e) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
  const inv = (v) => pow(v, p - 2n);
  const d = mod(-121665n * inv(121666n)), d2 = mod(2n * d);
  const SQRTM1 = pow(2n, (p - 1n) / 4n);
  const le = (b) => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };
  const toLe = (v, n = 32) => { const out = new Uint8Array(n); for (let i = 0; i < n; i++) { out[i] = Number(v & 255n); v >>= 8n; } return out; };
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const f = (v) => E.fmt(v), sh = (b) => hex(b).slice(0, 16) + '…';
  const cat = (...as) => { const out = new Uint8Array(as.reduce((n, a) => n + a.length, 0)); let o = 0; for (const a of as) { out.set(a, o); o += a.length; } return out; };

  const ID = { X: 0n, Y: 1n, Z: 1n, T: 0n };
  const add = (P, Q) => {
    const A = mod((P.Y - P.X) * (Q.Y - Q.X)), B = mod((P.Y + P.X) * (Q.Y + Q.X)), C = mod(P.T * d2 * Q.T), D = mod(P.Z * 2n * Q.Z);
    const Ee = B - A, F = D - C, G = D + C, H = B + A;
    return { X: mod(Ee * F), Y: mod(G * H), Z: mod(F * G), T: mod(Ee * H) };
  };
  const dbl = (P) => {
    const A = mod(P.X * P.X), B = mod(P.Y * P.Y), C = mod(2n * P.Z * P.Z), H = A + B, Ee = H - mod((P.X + P.Y) * (P.X + P.Y)), G = A - B, F = C + G;
    return { X: mod(Ee * F), Y: mod(G * H), Z: mod(F * G), T: mod(Ee * H) };
  };
  const mul = (k, P) => { let R = ID, Q = P; k = BigInt(k); while (k > 0n) { if (k & 1n) R = add(R, Q); Q = dbl(Q); k >>= 1n; } return R; };
  const eq = (P, Q) => mod(P.X * Q.Z - Q.X * P.Z) === 0n && mod(P.Y * Q.Z - Q.Y * P.Z) === 0n;
  const affine = (P) => { const zi = inv(P.Z); return { x: mod(P.X * zi), y: mod(P.Y * zi) }; };
  const fromAffine = (x, y) => ({ X: x, Y: y, Z: 1n, T: mod(x * y) });
  const recoverX = (y, sign) => {
    if (y >= p) return null;
    const x2 = mod((y * y - 1n) * inv(d * y * y + 1n));
    if (x2 === 0n) return sign ? null : 0n;
    let x = pow(x2, (p + 3n) / 8n);
    if (mod(x * x - x2) !== 0n) x = mod(x * SQRTM1);
    if (mod(x * x - x2) !== 0n) return null;
    if (Number(x & 1n) !== sign) x = p - x;
    return x;
  };
  const encode = (P) => { const { x, y } = affine(P); const b = toLe(y); b[31] |= Number(x & 1n) << 7; return b; };
  const decode = (b) => { const t = Uint8Array.from(b), sign = t[31] >> 7; t[31] &= 127; const y = le(t), x = recoverX(y, sign); return x == null ? null : fromAffine(x, y); };
  const By = mod(4n * inv(5n)), Bpt = fromAffine(recoverX(By, 0), By);
  const H512 = (...parts) => E.sha512(cat(...parts));

  const keygen = (secret) => {
    const h = H512(secret), s = Uint8Array.from(h.subarray(0, 32)), prefix = h.subarray(32);
    s[0] &= 248; s[31] &= 127; s[31] |= 64;
    const a = le(s), A = mul(a, Bpt), pub = encode(A);
    const trace = [
      step('expand', `Hash the 32-byte secret with SHA-512: h = ${sh(h)} (64 bytes). The low half becomes the scalar, the high half the nonce prefix.`, { h: hex(h) }),
      step('clamp', `Clamp the low half as X25519 does (clear bits 0–2 and 255, set bit 254): a = ${f(a)}.`, { a }),
      step('public', `A = a·B, encoded as y little-endian with the parity of x in the top bit: ${hex(pub)}.`, { pub: hex(pub) }),
    ];
    return { a, prefix, A, pub, trace };
  };
  const sign = (secret, msg) => {
    const K = keygen(secret), trace = [...K.trace];
    const rh = H512(K.prefix, msg), r = mod(le(rh), L), R = mul(r, Bpt), Rb = encode(R);
    trace.push(step('nonce', `Nonce: r = SHA-512(prefix ‖ M) mod L = ${f(r)}. It depends only on the secret and the message, so no random generator can leak or repeat it.`, { r }));
    trace.push(step('R', `R = r·B, encoded: ${hex(Rb)}.`, { R: hex(Rb) }));
    const kh = H512(Rb, K.pub, msg), k = mod(le(kh), L);
    trace.push(step('challenge', `Challenge: k = SHA-512(R ‖ A ‖ M) mod L = ${f(k)}.`, { k }));
    const Sv = mod(r + k * K.a, L), sig = cat(Rb, toLe(Sv));
    trace.push(step('S', `S = (r + k·a) mod L = ${f(Sv)}. The signature is R ‖ S, 64 bytes: ${sh(sig)}`, { S: Sv, sig: hex(sig) }));
    return { sig, r, R, k, S: Sv, pub: K.pub, trace };
  };
  const verify = (pub, msg, sig) => {
    const trace = [], no = (say) => { trace.push(step('reject', say, {})); return { ok: false, trace }; };
    if (sig.length !== 64 || pub.length !== 32) return no('A signature is 64 bytes and a public key 32: rejected.');
    const A = decode(pub), R = decode(sig.subarray(0, 32)), Sv = le(sig.subarray(32));
    if (!A) return no('The public key does not decode to a curve point: rejected.');
    if (!R) return no('R does not decode to a curve point: rejected.');
    if (Sv >= L) return no('S is not below L: rejected (this stops a malleable second signature S + L).');
    const k = mod(le(H512(sig.subarray(0, 32), pub, msg)), L);
    trace.push(step('challenge', `Recompute k = SHA-512(R ‖ A ‖ M) mod L = ${f(k)}.`, { k }));
    const lhs = mul(8n, mul(Sv, Bpt)), rhs = mul(8n, add(R, mul(k, A))), ok = eq(lhs, rhs);
    trace.push(step('check', `Check [8][S]B = [8]R + [8][k]A: ${ok ? 'equal' : 'different'}. (S·B = r·B + k·a·B = R + k·A.)`, { ok }));
    trace.push(step(ok ? 'accept' : 'reject', ok ? 'The signature is valid.' : 'The signature is invalid.', { ok }));
    return { ok, trace };
  };

  E.Ed25519 = { p, d, L, B: Bpt, ID, add, dbl, mul, eq, affine, fromAffine, encode, decode, recoverX, keygen, sign, verify, le, toLe };
})(globalThis.Sifer = globalThis.Sifer || {});
