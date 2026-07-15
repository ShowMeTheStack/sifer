// HMAC over any hash in S.Hash, HKDF (extract, then expand) and PBKDF2, each traced; and tag comparison done
// safely (in time independent of where the tags differ) next to the leaky early-exit comparison and the attack
// that reads a tag from it one byte at a time.
//   S.MAC.hmac(hash, key, msg) -> tag;  S.MAC.hmacTrace(hash, key, msg) -> {tag, k0, ipadKey, opadKey, inner, trace}
//   S.MAC.hkdfExtract(hash, salt, ikm) -> prk;  S.MAC.hkdfExpand(hash, prk, info, L) -> okm
//   S.MAC.hkdf(hash, ikm, salt, info, L[, {trace}]) -> okm | {okm, prk, blocks: [T(i)], trace}
//   S.MAC.pbkdf2(hash, password, salt, iterations, dkLen[, {trace, show}]) -> dk | {dk, blocks, trace}
//   S.MAC.equal(a, b) -> boolean in constant time;  S.MAC.leakyEqual(a, b) -> {equal, steps}
//   S.MAC.timingAttack(check, len) -> {tag, queries, trace}   check(guess) -> {equal, steps} for a hidden tag
(function (S) {
  'use strict';
  const H = S.Hash, Mc = (S.MAC = S.MAC || {});
  const { step, hex, utf8, concat } = H;
  const hashFn = (h) => (typeof h === 'object' ? h : H.get(h));

  Mc.hmacTrace = (hash, key, msg) => {
    const A = hashFn(hash), B = A.blockLen, trace = [];
    key = utf8(key); msg = utf8(msg);
    let k0 = key;
    if (key.length > B) {
      k0 = A.hash(key);
      trace.push(step('key-hash', `The ${key.length}-byte key is longer than the ${B}-byte block, so it is hashed first: K' = ${A.name}(K) = ${hex(k0)}.`, { k0 }));
    }
    const kp = new Uint8Array(B); kp.set(k0);
    trace.push(step('key-pad', `K' is padded with zeros to the block size, ${B} bytes${key.length <= B ? ` (${B - key.length} zero bytes added)` : ''}.`, { k0: kp }));
    const ipadKey = kp.map((v) => v ^ 0x36), opadKey = kp.map((v) => v ^ 0x5c);
    trace.push(step('ipad', `K' ⊕ ipad (0x36 repeated) = ${H.short(ipadKey, 16)}.`, { ipadKey }));
    const inner = A.hash(concat(ipadKey, msg));
    trace.push(step('inner', `Inner hash: ${A.name}((K' ⊕ ipad) ‖ message) = ${hex(inner)}.`, { inner }));
    trace.push(step('opad', `K' ⊕ opad (0x5c repeated) = ${H.short(opadKey, 16)}.`, { opadKey }));
    const tag = A.hash(concat(opadKey, inner));
    trace.push(step('outer', `Outer hash: ${A.name}((K' ⊕ opad) ‖ inner) = ${hex(tag)}. This outer call is what stops length extension: the inner digest is never the final state.`, { tag }));
    return { tag, k0: kp, ipadKey, opadKey, inner, trace };
  };
  Mc.hmac = (hash, key, msg) => {
    const A = hashFn(hash), B = A.blockLen;
    key = utf8(key);
    const kp = new Uint8Array(B); kp.set(key.length > B ? A.hash(key) : key);
    return A.hash(concat(kp.map((v) => v ^ 0x5c), A.hash(concat(kp.map((v) => v ^ 0x36), utf8(msg)))));
  };

  // ---- HKDF (RFC 5869)
  Mc.hkdfExtract = (hash, salt, ikm) => {
    const A = hashFn(hash);
    salt = salt && salt.length ? utf8(salt) : new Uint8Array(A.outLen);
    return Mc.hmac(A, salt, ikm);
  };
  Mc.hkdfExpand = (hash, prk, info, L, blocks) => {
    const A = hashFn(hash), n = Math.ceil(L / A.outLen);
    if (n > 255) throw new Error('HKDF can expand to at most 255 hash lengths');
    info = utf8(info || new Uint8Array(0));
    const okm = new Uint8Array(n * A.outLen);
    let T = new Uint8Array(0);
    for (let i = 1; i <= n; i++) {
      T = Mc.hmac(A, prk, concat(T, info, Uint8Array.of(i)));
      okm.set(T, (i - 1) * A.outLen);
      if (blocks) blocks.push(T);
    }
    return okm.slice(0, L);
  };
  Mc.hkdf = (hash, ikm, salt, info, L, opt = {}) => {
    const A = hashFn(hash), prk = Mc.hkdfExtract(A, salt, ikm);
    if (!opt.trace) return Mc.hkdfExpand(A, prk, info, L);
    const blocks = [], okm = Mc.hkdfExpand(A, prk, info, L, blocks);
    const trace = [
      step('extract', `Extract: PRK = HMAC-${A.name}(salt, IKM) = ${hex(prk)}. However lumpy the input keying material, the PRK is a uniform ${A.outLen}-byte key.`, { prk }),
      ...blocks.map((T, i) => step('expand', `Expand: T(${i + 1}) = HMAC(PRK, ${i ? `T(${i}) ‖ ` : ''}info ‖ ${(i + 1).toString(16).padStart(2, '0')}) = ${hex(T)}.`, { i: i + 1, T })),
      step('okm', `The first ${L} bytes of T(1) ‖ T(2) ‖ … are the output keying material: ${H.short(okm, 24)}.`, { okm }),
    ];
    return { okm, prk, blocks, trace };
  };

  // ---- PBKDF2 (RFC 8018) with HMAC as the PRF: T_i = U_1 ⊕ U_2 ⊕ … ⊕ U_c
  Mc.pbkdf2 = (hash, password, salt, c, dkLen, opt = {}) => {
    const A = hashFn(hash), P = utf8(password), Sa = utf8(salt), n = Math.ceil(dkLen / A.outLen);
    const out = new Uint8Array(n * A.outLen), blocks = [], trace = opt.trace ? [] : null, show = opt.show || 3;
    // precompute the padded key once, as every real implementation does
    const B = A.blockLen, kp = new Uint8Array(B); kp.set(P.length > B ? A.hash(P) : P);
    const ik = kp.map((v) => v ^ 0x36), ok = kp.map((v) => v ^ 0x5c);
    const prf = (m) => A.hash(concat(ok, A.hash(concat(ik, m))));
    for (let i = 1; i <= n; i++) {
      let U = prf(concat(Sa, Uint8Array.of(i >>> 24, (i >>> 16) & 255, (i >>> 8) & 255, i & 255)));
      const T = U.slice(), us = [];
      if (trace) trace.push(step('u1', `Block ${i}: U1 = HMAC(P, salt ‖ ${i}) = ${hex(U)}.`, { i, j: 1, U }));
      for (let j = 2; j <= c; j++) {
        U = prf(U);
        for (let k = 0; k < T.length; k++) T[k] ^= U[k];
        if (trace && j <= show) trace.push(step('uj', `U${j} = HMAC(P, U${j - 1}) = ${hex(U)}; running XOR T = ${hex(T)}.`, { i, j, U, T: T.slice() }));
        if (j <= show) us.push(U);
      }
      if (trace && c > show) trace.push(step('more', `… ${c - show} more HMAC calls, each XORed in: ${c} in all for this block. That cost is the point: each password guess costs an attacker the same.`, { i, c }));
      out.set(T, (i - 1) * A.outLen); blocks.push(T);
    }
    const dk = out.slice(0, dkLen);
    if (!trace) return dk;
    trace.push(step('dk', `The derived key is the first ${dkLen} bytes of T1 ‖ T2 ‖ …: ${hex(dk)}.`, { dk }));
    return { dk, blocks, trace };
  };

  // ---- comparing tags
  /** constant time: every byte is looked at, and the only branch is on the length */
  Mc.equal = (a, b) => {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  };
  /** the naive comparison, stopping at the first difference; steps stands in for the time it takes */
  Mc.leakyEqual = (a, b) => {
    let steps = 0;
    for (let i = 0; i < a.length; i++) { steps++; if (a[i] !== b[i]) return { equal: false, steps }; }
    return { equal: a.length === b.length, steps };
  };
  /** recover a hidden tag through a leaky check, one byte at a time: the right byte makes the check run longer */
  Mc.timingAttack = (check, len) => {
    const guess = new Uint8Array(len), trace = [];
    let queries = 0;
    for (let i = 0; i < len; i++) {
      let best = 0, bestSteps = -1;
      for (let v = 0; v < 256; v++) {
        guess[i] = v; queries++;
        const r = check(guess);
        if (r.equal) { best = v; bestSteps = Infinity; break; }
        if (r.steps > i + 1) { best = v; break; } // the comparison got past byte i
        if (r.steps > bestSteps) { bestSteps = r.steps; best = v; }
      }
      guess[i] = best;
      trace.push(step('byte', `Byte ${i}: of 256 guesses, ${best.toString(16).padStart(2, '0')} makes the comparison run one step longer, so it is the tag's byte. Known so far: ${hex(guess.subarray(0, i + 1))}.`, { i, value: best }));
    }
    trace.push(step('done', `The whole ${len}-byte tag in ${queries} queries, about 128 per byte on average, instead of 2^${8 * len} for a blind search. A constant-time comparison gives every guess the same time and stops this.`, { queries }));
    return { tag: guess, queries, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
