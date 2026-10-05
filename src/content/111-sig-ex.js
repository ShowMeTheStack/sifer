// Part 11, digital signatures: the exercises. The lessons are in 110-sig.js; the tour, the course and the pages the
// diagram checker looks at in 112-sig-tour.js. Messages, keys and nonces are our own, at toy size so they can be done by
// hand; sizes are those of RFC 8017 (PSS), RFC 8032 (Ed25519) and NIST SP 800-57 (security levels). Every answer was
// worked out with the engines (S.RSA, S.SIG, S.ECC, S.ECC.Ed25519), and the code exercises are checked against them.
// The part is defensive: the student signs, verifies and checks, and never recovers a key or forges a signature.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('sg-x-mac-prop')) return;
  const ex = (o) => C.exercise(o);
  const with1 = (o, k, v) => Object.assign({}, o, { [k]: v });

  // =========================================================================================================
  // Chapter 1: what a signature is, and RSA
  // =========================================================================================================
  ex({
    id: 'sg-x-mac-prop', chapter: 'sg-ch-rsa', title: 'What a MAC cannot give', level: 1, kind: 'choice',
    text: ['A message is sent once with an HMAC tag and once with an Ed25519 signature. Which property does the signature give that the MAC does not?'],
    options: ['Integrity: a changed message is detected', 'Confidentiality: the message is hidden', 'Non-repudiation: a third party can check who made it, and only the signer could have', 'Protection against replay of an old message'],
    answer: 2,
    whyNot: { 0: 'Both detect a changed message: integrity is common to the two.', 1: 'Neither hides the message. Encryption does that.', 3: 'Neither stops replay on its own: a replayed message carries a valid tag or signature. A counter or timestamp inside the message does that.' },
    hints: ['Ask who could have produced a valid tag, and who could have produced a valid signature.', 'Both holders of the HMAC key can make tags; only the holder of the private key can sign.', 'Non-repudiation, with public verifiability: anyone with the public key can check the signature, and only the signer could have made it. Integrity they share; neither gives confidentiality or replay protection.'],
    solution: 2, wrong: [0, 1, 3],
  });
  ex({
    id: 'sg-x-dispute', chapter: 'sg-ch-rsa', title: 'Settling a dispute', level: 2, kind: 'choice',
    text: ['A supplier and a shop share an HMAC key K for their orders, and the supplier also has an Ed25519 key pair whose public key the shop knows. The shop shows an arbitrator an order for 900 units, which the supplier denies sending. Which statements are true? Choose every one.'],
    options: ['A valid HMAC tag on the order proves the supplier sent it', 'A valid HMAC tag on the order could have been made by the shop', 'A valid Ed25519 signature on the order, under the supplier\'s public key, could only have been made with the supplier\'s private key', 'The arbitrator needs K to check the Ed25519 signature', 'If the supplier\'s private key has leaked, a valid signature no longer settles the matter'],
    answer: [1, 2, 4],
    whyNot: { 0: 'The shop holds K too, so the tag could be the shop\'s.', 3: 'A signature is checked with the public key alone.' },
    hints: ['Who holds K? Who holds the private signing key?', 'A tag can come from either holder of K. A signature can come only from the private key, which is why a leaked key must be revoked at once.', 'True: a tag could be the shop\'s; a valid signature needs the supplier\'s private key; and a leaked key undoes that. False: a tag proves nothing about which holder made it, and the arbitrator needs only the public key.'],
    solution: [1, 2, 4], wrong: [[0, 2], [1, 2, 3], [2]],
  });
  ex({
    id: 'sg-x-rsa-verify', chapter: 'sg-ch-rsa', title: 'Verify a toy RSA signature', level: 1, kind: 'number',
    text: ['A toy RSA key has n = 391 (= 17 · 23) and e = 3. The message "pay the plumber 80" hashes, reduced modulo n, to z = 138. The signature is s = 161. Compute s^e mod n. Does the signature verify?'],
    answer: 138,
    hints: ['Verifying needs only the public key: raise s to the power 3 modulo 391.', '161² = 25921 = 66·391 + 115, so 161² ≡ 115.', '115 · 161 = 18515 = 47·391 + 138, so s³ mod n = 138. It equals z, so the signature is valid.'],
    solution: '138', wrong: ['161', '115', '235'],
    whyNot: { 161: 'That is s itself. Raise it to e = 3 modulo 391.', 115: 'That is s² mod n. Multiply by s once more.', '*': 'Compute 161³ mod 391 by squaring, reducing, then multiplying.' },
  });
  const CRT = { 'd mod (p − 1)|value': '11', 'd mod (q − 1)|value': '15', 'sₚ = (z mod p)^(d mod (p − 1)) mod p|value': '6', 's_q = (z mod q)^(d mod (q − 1)) mod q|value': '15', 's (from sₚ and s_q)|value': '176' };
  ex({
    id: 'sg-x-rsa-crt', chapter: 'sg-ch-rsa', title: 'Sign by the CRT', level: 3, kind: 'table',
    text: ['The signer of the toy key n = 391 knows p = 17, q = 23 and d = 235 (e = 3). Sign the hash z = 63 of "renew the lease" the fast way: compute s modulo p and modulo q with small exponents, then join the two with the Chinese remainder theorem.', { math: 'sₚ = (z mod p)^(d mod (p − 1)) mod p\ns_q = (z mod q)^(d mod (q − 1)) mod q\ns   = the number below n with s ≡ sₚ (mod p) and s ≡ s_q (mod q)' }],
    rows: ['d mod (p − 1)', 'd mod (q − 1)', 'sₚ = (z mod p)^(d mod (p − 1)) mod p', 's_q = (z mod q)^(d mod (q − 1)) mod q', 's (from sₚ and s_q)'], cols: ['value'], corner: 'Step',
    cells: CRT,
    hints: ['Fermat: exponents modulo p can be reduced modulo p − 1 = 16, and modulo q by q − 1 = 22. 235 = 14·16 + 11 = 10·22 + 15.', 'z mod 17 = 12 and z mod 23 = 17. 12¹¹ mod 17 = 6 and 17¹⁵ mod 23 = 15.', 'd mod 16 = 11, d mod 22 = 15, sₚ = 6, s_q = 15. The number below 391 that is 6 mod 17 and 15 mod 23 is 176 (176 = 10·17 + 6 = 7·23 + 15). Check: 176³ mod 391 = 63 = z.'],
    solution: CRT,
    wrong: [with1(CRT, 's (from sₚ and s_q)|value', '21'), with1(with1(CRT, 'd mod (p − 1)|value', '14'), 'sₚ = (z mod p)^(d mod (p − 1)) mod p|value', '13')],
  });
  ex({
    id: 'sg-x-hash-why', chapter: 'sg-ch-rsa', title: 'Why hash before signing?', level: 2, kind: 'choice',
    text: ['An RSA signer computes s = H(m)^d mod n rather than m^d mod n. Which reasons for the hash are correct? Choose every one.'],
    options: ['Raw signatures multiply into valid signatures on products of messages; with a hash, a product is useless unless some message hashes to it', 'A message of any length is signed as one fixed-size value', 'The hash hides the message from the verifier', 'The hash makes signing cheaper than verifying'],
    answer: [0, 1],
    whyNot: { 2: 'The verifier is given the message and hashes it itself; nothing is hidden.', 3: 'With e = 65537, verifying stays far cheaper than signing; the hash does not change that.' },
    hints: ['Recall (s₁·s₂)^e = m₁·m₂ (mod n) for raw signatures.', 'A useful product would need a message whose hash equals it: a preimage. And a message longer than n would not fit into one RSA block at all.', 'The first two: the hash defeats the multiplicative combination and the "every s signs something" problem, and lets a long message be signed once. It hides nothing and does not change the cost.'],
    solution: [0, 1], wrong: [[0], [0, 1, 2], [1, 3]],
  });
  const PSS = { 'EM (emLen)|RSA-2048, 32-byte salt': '256', 'EM (emLen)|RSA-1024, 20-byte salt': '128', 'DB|RSA-2048, 32-byte salt': '223', 'DB|RSA-1024, 20-byte salt': '95', 'PS (zero bytes)|RSA-2048, 32-byte salt': '190', 'PS (zero bytes)|RSA-1024, 20-byte salt': '74', 'MGF1 blocks|RSA-2048, 32-byte salt': '7', 'MGF1 blocks|RSA-1024, 20-byte salt': '3' };
  ex({
    id: 'sg-x-pss-table', chapter: 'sg-ch-rsa', title: 'The PSS block, field by field', level: 2, kind: 'table',
    text: ['RSA-PSS with SHA-256 (H is 32 bytes) and the trailer byte bc. Fill in the length in bytes of EM, of DB and of PS, the run of zero bytes at the start of DB, and the number of SHA-256 blocks MGF1 needs for the mask, for a 2048-bit modulus with a 32-byte salt and a 1024-bit modulus with a 20-byte salt.', { math: 'emLen = ⌈(modBits − 1) / 8⌉\nEM    = maskedDB ‖ H ‖ bc\nDB    = PS ‖ 01 ‖ salt' }],
    rows: ['EM (emLen)', 'DB', 'PS (zero bytes)', 'MGF1 blocks'], cols: ['RSA-2048, 32-byte salt', 'RSA-1024, 20-byte salt'], corner: 'Bytes',
    cells: PSS,
    hints: ['emLen = ⌈2047/8⌉ = 256 and ⌈1023/8⌉ = 128. DB is what is left of EM after H (32 bytes) and bc (1 byte).', 'DB = 256 − 33 = 223 and 128 − 33 = 95. PS is DB less the 01 byte and the salt.', 'RSA-2048: EM 256, DB 223, PS 223 − 1 − 32 = 190, MGF1 ⌈223/32⌉ = 7 blocks. RSA-1024: EM 128, DB 95, PS 95 − 1 − 20 = 74, MGF1 ⌈95/32⌉ = 3 blocks.'],
    solution: PSS,
    wrong: [with1(with1(PSS, 'DB|RSA-2048, 32-byte salt', '224'), 'PS (zero bytes)|RSA-2048, 32-byte salt', '191'), with1(PSS, 'MGF1 blocks|RSA-2048, 32-byte salt', '8')],
  });
  ex({
    id: 'sg-x-pss-blocks', chapter: 'sg-ch-rsa', title: 'MGF1 for a 3072-bit key', level: 1, kind: 'number',
    text: ['RSA-PSS with SHA-256 and a 3072-bit modulus. How many SHA-256 blocks does MGF1 compute to mask DB?'],
    answer: 11,
    hints: ['emLen = ⌈3071/8⌉ = 384 bytes.', 'DB = 384 − 32 − 1 = 351 bytes, and each block gives 32.', '⌈351/32⌉ = 11 blocks, the last cut to 31 bytes.'],
    solution: '11', wrong: ['12', '10', '351'],
    whyNot: { 12: 'That covers all 384 bytes of EM. The mask covers only DB, which leaves out H and bc.', '*': 'Find DB = emLen − 33, then divide by 32 and round up.' },
  });
  ex({
    id: 'sg-x-pss-topbyte', chapter: 'sg-ch-rsa', title: 'The cleared top bit', level: 1, kind: 'hex',
    text: ['For a 2048-bit modulus, emBits = 2047 and EM has 256 bytes, so 8·256 − 2047 = 1 leftmost bit of EM must be zero, to keep EM below n. DB ⊕ dbMask begins with the byte d7. Give the first byte of maskedDB, in hex.'],
    answer: '57',
    hints: ['Only the leftmost bit is cleared: AND the byte with 0x7f.', 'd7 = 1101 0111 in binary.', '0101 0111 = 57. A verifier rejects any EM whose leftmost bit is set.'],
    solution: '57', wrong: ['d7', '7f', 'a8'],
    whyNot: 'Clear the top bit of d7 and keep the other seven.',
  });
  ex({
    id: 'sg-x-pss-salt', chapter: 'sg-ch-rsa', title: 'What the salt does', level: 2, kind: 'choice',
    text: ['Which statements about the PSS salt are true? Choose every one.'],
    options: ['The verifier recovers the salt from EM, by rebuilding the mask from H and unmasking DB', 'Two PSS signatures of the same message with fresh salts differ', 'The salt must be kept secret, like the private key', 'With an empty salt, PSS still verifies; the signature is then deterministic'],
    answer: [0, 1, 3],
    whyNot: { 2: 'The salt is not secret: anyone with the public key can unmask it from the signature.' },
    hints: ['Where in EM is the salt, and what does the verifier know?', 'H is in EM in the clear, so MGF1(H) can be rebuilt by anyone with s and e.', 'True: the salt is recovered from DB, fresh salts give different signatures, and an empty salt is allowed (the block is then fixed for a given message). False: the salt is not secret.'],
    solution: [0, 1, 3], wrong: [[0, 1], [0, 1, 2, 3], [2]],
  });

  // =========================================================================================================
  // Chapter 2: discrete-log signatures
  // =========================================================================================================
  ex({
    id: 'sg-x-elg-k', chapter: 'sg-ch-dlog', title: 'Which nonces can Elgamal use?', level: 1, kind: 'choice',
    text: ['Elgamal signatures with p = 467, so p − 1 = 466 = 2 · 233. Which of these nonces can be used? Choose every one.'],
    options: ['k = 100', 'k = 213', 'k = 233', 'k = 77', 'k = 466'],
    answer: [1, 3],
    whyNot: { 0: '100 is even and shares the factor 2 with 466.', 2: '233 divides 466.', 4: '466 ≡ 0 (mod 466).' },
    hints: ['s = k⁻¹(z − x·r) mod (p − 1) needs an inverse of k modulo 466.', 'k has an inverse modulo 466 exactly when gcd(k, 466) = 1: k must be odd and not a multiple of 233.', '213 and 77. 100 and 466 are even, and 233 divides 466.'],
    solution: [1, 3], wrong: [[1], [0, 1, 3], [1, 2, 3]],
  });
  const ES = { 'y = g^x mod p|value': '132', 'r = g^k mod p|value': '29', 'k⁻¹ mod (p − 1)|value': '431', 's = k⁻¹(z − x·r) mod (p − 1)|value': '378' };
  ex({
    id: 'sg-x-elg-sign', chapter: 'sg-ch-dlog', title: 'Sign with Elgamal', level: 2, kind: 'table',
    text: ['Elgamal signatures with p = 467 and g = 2. The private key is x = 127. The message "move the meeting to room 4" hashes, modulo p − 1, to z = 317. Sign it with the nonce k = 213.'],
    rows: ['y = g^x mod p', 'r = g^k mod p', 'k⁻¹ mod (p − 1)', 's = k⁻¹(z − x·r) mod (p − 1)'], cols: ['value'], corner: 'Step',
    cells: ES,
    hints: ['Powers of g are taken modulo p = 467; k⁻¹ and s are modulo p − 1 = 466.', 'y = 2¹²⁷ mod 467 = 132 and r = 2²¹³ mod 467 = 29. 213·431 = 91803 = 197·466 + 1, so k⁻¹ = 431.', 'z − x·r = 317 − 127·29 = −3366 ≡ 362 (mod 466), and s = 431·362 mod 466 = 378. The signature is (29, 378).'],
    solution: ES,
    wrong: [with1(ES, 'k⁻¹ mod (p − 1)|value', '57'), with1(ES, 's = k⁻¹(z − x·r) mod (p − 1)|value', '84')],
  });
  const EV = { 'g^z mod p|value': '367', 'y^r mod p|value': '216', 'r^s mod p|value': '406', 'y^r·r^s mod p|value': '367' };
  ex({
    id: 'sg-x-elg-verify', chapter: 'sg-ch-dlog', title: 'Verify the Elgamal signature', level: 2, kind: 'table',
    text: ['Verify the signature (r, s) = (29, 378) on z = 317 with p = 467, g = 2 and the public key y = 132. It is valid when the last two rows agree.'],
    rows: ['g^z mod p', 'y^r mod p', 'r^s mod p', 'y^r·r^s mod p'], cols: ['value'], corner: 'Step',
    cells: EV,
    hints: ['Every computation here is modulo p = 467, and only public values are used.', 'g^z = 2³¹⁷ mod 467 = 367, y^r = 132²⁹ mod 467 = 216 and r^s = 29³⁷⁸ mod 467 = 406.', '216 · 406 = 87696 = 187·467 + 367, so y^r·r^s = 367 = g^z: valid.'],
    solution: EV,
    wrong: [with1(EV, 'y^r·r^s mod p|value', '622'), with1(EV, 'g^z mod p|value', '317')],
  });
  const DS = { 'y = g^x mod p|value': '214', 'g^k mod p|value': '550', 'r = (g^k mod p) mod q|value': '45', 'k⁻¹ mod q|value': '7', 's = k⁻¹(z + x·r) mod q|value': '49' };
  ex({
    id: 'sg-x-dsa-sign', chapter: 'sg-ch-dlog', title: 'Sign with toy DSA', level: 2, kind: 'table',
    text: ['Toy DSA with p = 607, q = 101 and g = 64 (of order q). The private key is x = 58. The message "gate 4 opens at seven" gives z = 124 (the leftmost 7 bits of its SHA-256 hash, as q has 7 bits). Sign it with the nonce k = 29.'],
    rows: ['y = g^x mod p', 'g^k mod p', 'r = (g^k mod p) mod q', 'k⁻¹ mod q', 's = k⁻¹(z + x·r) mod q'], cols: ['value'], corner: 'Step',
    cells: DS,
    hints: ['Powers of g are modulo p = 607; r, k⁻¹ and s are modulo q = 101.', 'y = 64⁵⁸ mod 607 = 214 and g^k = 64²⁹ mod 607 = 550, so r = 550 mod 101 = 45. 29·7 = 203 = 2·101 + 1, so k⁻¹ = 7.', 'z + x·r = 124 + 58·45 = 2734 ≡ 7 (mod 101), and s = 7·7 = 49. The signature is (45, 49).'],
    solution: DS,
    wrong: [with1(DS, 'r = (g^k mod p) mod q|value', '550'), with1(DS, 's = k⁻¹(z + x·r) mod q|value', '23')],
  });
  const DV = { 'w = s⁻¹ mod q|value': '33', 'u1 = z·w mod q|value': '52', 'u2 = r·w mod q|value': '71', 'g^u1·y^u2 mod p|value': '550', 'v = (g^u1·y^u2 mod p) mod q|value': '45' };
  ex({
    id: 'sg-x-dsa-verify', chapter: 'sg-ch-dlog', title: 'Verify the toy DSA signature', level: 2, kind: 'table',
    text: ['Verify the signature (r, s) = (45, 49) on z = 124 with p = 607, q = 101, g = 64 and the public key y = 214. Both r and s lie in [1, q − 1]; the signature is valid when v = r.'],
    rows: ['w = s⁻¹ mod q', 'u1 = z·w mod q', 'u2 = r·w mod q', 'g^u1·y^u2 mod p', 'v = (g^u1·y^u2 mod p) mod q'], cols: ['value'], corner: 'Step',
    cells: DV,
    hints: ['49·w ≡ 1 (mod 101): try 49·33.', '49·33 = 1617 = 16·101 + 1, so w = 33. u1 = 124·33 mod 101 = 52 and u2 = 45·33 mod 101 = 71.', '64⁵²·214⁷¹ mod 607 = 512·122 mod 607 = 550, which is g^k; v = 550 mod 101 = 45 = r: valid.'],
    solution: DV,
    wrong: [with1(DV, 'v = (g^u1·y^u2 mod p) mod q|value', '550'), with1(DV, 'u1 = z·w mod q|value', '23')],
  });

  // modular helpers the code exercises give, read-only, above the editor
  const POW_SRC = 'function modPow(b, e, m) {\n  let r = 1n;\n  b %= m;\n  while (e > 0n) {\n    if (e & 1n) r = r * b % m;\n    b = b * b % m;\n    e >>= 1n;\n  }\n  return r;\n}\n';
  const INV_SRC = 'function modInv(a, m) {\n  let [r0, r1] = [((a % m) + m) % m, m];\n  let [s0, s1] = [1n, 0n];\n  while (r1 !== 0n) {\n    const t = r0 / r1;\n    [r0, r1] = [r1, r0 - t * r1];\n    [s0, s1] = [s1, s0 - t * s1];\n  }\n  if (r0 !== 1n) throw new Error(a + " has no inverse mod " + m);\n  return ((s0 % m) + m) % m;\n}\n';
  const N = () => S.NT, SG = () => S.SIG;
  const enc = (t) => new TextEncoder().encode(t);

  // toy DSA: verify (p, q, g, y, z, r, s) -> true | false
  const dsaRef = (p, q, g, y, z, r, s) => {
    if (!(r > 0n && r < q && s > 0n && s < q)) return false;
    const w = N().inv(s, q), v = (N().pow(g, N().mod(z * w, q), p) * N().pow(y, N().mod(r * w, q), p) % p) % q;
    return v === r;
  };
  const dsaCases = () => {
    const out = [], ms = ['meter 9 read 412', 'open bay 3', 'close the sluice at 6', 'ferry leaves at ten'];
    [[101n, 58n], [1009n, 777n], [30011n, 12345n], [65537n, 40000n]].forEach(([qMin, x], gi) => {
      const P = SG().toyParams(qMin), key = SG().dsaKey(P, x), { p, q, g } = P, y = key.y;
      const m = ms[gi], sig = SG().dsaSign(key, m, 3n + 17n * BigInt(gi + 1)), { r, s, z } = sig;
      out.push([p, q, g, y, z, r, s], [p, q, g, y, z + 1n, r, s], [p, q, g, y, z, r, s + q]);
      if (gi === 1) out.push([p, q, g, y, z, 0n, s], [p, q, g, y, z, r, 0n], [p, q, g, y * g % p, z, r, s]);
      if (gi === 3) out.push([p, q, g, y, z, s, r], [p, q, g, y, z, r + q, s]);
    });
    return out;
  };
  const DSA_SOL = 'function dsaVerify(p, q, g, y, z, r, s) {\n  if (r <= 0n || r >= q || s <= 0n || s >= q) {\n    return false;\n  }\n  const w = modInv(s, q);\n  const u1 = z * w % q;\n  const u2 = r * w % q;\n  const v = modPow(g, u1, p) * modPow(y, u2, p) % p % q;\n  return v === r;\n}\n';
  ex({
    id: 'sg-x-dsa-code', chapter: 'sg-ch-dlog', title: 'Write DSA verification', level: 3, kind: 'code', fn: 'dsaVerify', params: ['p', 'q', 'g', 'y', 'z', 'r', 's'],
    text: ['Write `dsaVerify(p, q, g, y, z, r, s)`: the domain parameters p, q, g, the public key y, the message hash z (already cut to the bits of q) and the signature (r, s), all BigInts. Return `true` if the signature is valid and `false` otherwise. `modPow(b, e, m)` and `modInv(a, m)` are given above the editor (read-only). The tests use four toy groups, with valid signatures, altered hashes and keys, and values out of range.', { math: 'reject unless 0 < r < q and 0 < s < q\nw = s⁻¹ mod q,  u1 = z·w mod q,  u2 = r·w mod q\nv = (g^u1 · y^u2 mod p) mod q\nvalid when v = r' }],
    prelude: POW_SRC + '\n' + INV_SRC,
    start: 'function dsaVerify(p, q, g, y, z, r, s) {\n  \n}\n',
    ref: dsaRef, get cases() { return dsaCases(); },
    hints: ['First the range check: a signature with r or s outside [1, q − 1] is rejected before any arithmetic. Without it, s + q verifies wherever s does.', 'w = modInv(s, q); u1 and u2 are products reduced modulo q; v multiplies two powers modulo p, then reduces modulo q.', DSA_SOL],
    solution: DSA_SOL,
    wrong: [DSA_SOL.replace('  if (r <= 0n || r >= q || s <= 0n || s >= q) {\n    return false;\n  }\n', ''), DSA_SOL.replace('% p % q;', '% p;'), DSA_SOL.replace('const u1 = z * w % q;', 'const u1 = z * s % q;')],
  });
  ex({
    id: 'sg-x-schnorr-sign', chapter: 'sg-ch-dlog', title: 'A Schnorr signature', level: 1, kind: 'number',
    text: ['Schnorr signing in the group p = 607, q = 101, g = 64, with the private key x = 33. For the message "lock the north door" the signer picks k = 19, so R = g^k mod p = 82, and the challenge hash comes out as e = H(R ‖ m) mod q = 95. What is s = k + e·x mod q?'],
    answer: 23,
    hints: ['No inverse is needed: one multiplication and one addition, modulo q = 101.', 'e·x = 95·33 = 3135, and 19 + 3135 = 3154.', '3154 = 31·101 + 23, so s = 23. The signature is (e, s) = (95, 23).'],
    solution: '23', wrong: ['3154', '82', '84'],
    whyNot: { 3154: 'Reduce modulo q = 101.', 82: 'That is R, the commitment.', '*': 'Compute 19 + 95·33 and reduce modulo 101.' },
  });
  ex({
    id: 'sg-x-schnorr-rebuild', chapter: 'sg-ch-dlog', title: 'Rebuild the commitment', level: 2, kind: 'number',
    text: ['Verify the Schnorr signature (e, s) = (95, 23) on "lock the north door" with p = 607, q = 101, g = 64 and the public key y = 480. Compute R′ = g^s·y^(−e) mod p. (y has order q, so y^(−e) = y^(q − e).) The signature is valid when H(R′ ‖ m) mod q gives back e.'],
    answer: 82,
    hints: ['y^(−e) = y^(101 − 95) = y⁶.', 'g^s = 64²³ mod 607 = 204 and y⁶ = 480⁶ mod 607 = 292.', '204 · 292 = 59568 = 98·607 + 82, so R′ = 82, the signer\'s R, and the hash gives back e = 95: valid.'],
    solution: '82', wrong: ['204', '292', '95'],
    whyNot: { 204: 'That is only g^s. Multiply by y^(−e).', 292: 'That is only y^(−e). Multiply by g^s.', '*': 'Compute 64²³ · 480⁶ mod 607.' },
  });

  const SHA_SRC = "function sha256(msg) {\n  const P = [];\n  for (let n = 2; P.length < 64; n++) {\n    if (P.every((p) => n % p)) {\n      P.push(n);\n    }\n  }\n  const fr = (x) =>\n    ((x - Math.floor(x)) * 2 ** 32)\n    >>> 0;\n  const K = P\n    .map((p) => fr(Math.cbrt(p)));\n  const V = P.slice(0, 8)\n    .map((p) => fr(Math.sqrt(p)));\n  const R = (x, n) =>\n    (x >>> n) | (x << (32 - n));\n  const n = msg.length;\n  const len =\n    Math.ceil((n + 9) / 64) * 64;\n  const m = new Uint8Array(len);\n  m.set(msg);\n  m[n] = 0x80;\n  for (let i = 0; i < 4; i++) {\n    m[len - 1 - i] =\n      (n * 8) >>> (8 * i);\n  }\n  const W = [];\n  for (let o = 0; o < len; o += 64) {\n    for (let t = 0; t < 64; t++) {\n      if (t < 16) {\n        const j = o + 4 * t;\n        W[t] = ((m[j] << 24)\n          | (m[j + 1] << 16)\n          | (m[j + 2] << 8)\n          | m[j + 3]) >>> 0;\n        continue;\n      }\n      const x = W[t - 15], y = W[t - 2];\n      const s0 = R(x, 7) ^ R(x, 18)\n        ^ (x >>> 3);\n      const s1 = R(y, 17) ^ R(y, 19)\n        ^ (y >>> 10);\n      W[t] = (W[t - 16] + s0\n        + W[t - 7] + s1) >>> 0;\n    }\n    let [a, b, c, d, e, f, g, h] = V;\n    for (let t = 0; t < 64; t++) {\n      const S1 = R(e, 6) ^ R(e, 11)\n        ^ R(e, 25);\n      const S0 = R(a, 2) ^ R(a, 13)\n        ^ R(a, 22);\n      const ch = (e & f) ^ (~e & g);\n      const mj = (a & b) ^ (a & c)\n        ^ (b & c);\n      const t1 = (h + S1 + ch\n        + K[t] + W[t]) | 0;\n      const t2 = (S0 + mj) | 0;\n      h = g; g = f; f = e;\n      e = (d + t1) | 0;\n      d = c; c = b; b = a;\n      a = (t1 + t2) | 0;\n    }\n    const r = [a, b, c, d, e, f, g, h];\n    for (let i = 0; i < 8; i++) {\n      V[i] = (V[i] + r[i]) >>> 0;\n    }\n  }\n  const out = new Uint8Array(32);\n  for (let i = 0; i < 32; i++) {\n    out[i] =\n      V[i >> 2] >>> (24 - 8 * (i & 3));\n  }\n  return out;\n}\n";
  const CHAL_SRC = 'function challenge(R, msg, q) {\n  let h = R.toString(16);\n  if (h.length % 2) h = "0" + h;\n  const m = new TextEncoder().encode(msg);\n  const b = new Uint8Array(h.length / 2 + m.length);\n  for (let i = 0; i < h.length / 2; i++) {\n    b[i] = parseInt(h.substr(2 * i, 2), 16);\n  }\n  b.set(m, h.length / 2);\n  let v = 0n;\n  for (const x of sha256(b)) {\n    v = (v << 8n) | BigInt(x);\n  }\n  return v % q;\n}\n';
  const schnorrRef = (p, q, g, y, msg, e, s) => {
    if (!(s >= 0n && s < q)) return false;
    return SG().schnorrVerify({ params: { p, q, g }, y }, msg, { e, s }).ok;
  };
  const schnorrCases = () => {
    const out = [], ms = ['lock the north door', 'the kiln is at 900', 'ship crate 31 on monday'];
    [[101n, 33n], [1009n, 618n], [65537n, 4321n]].forEach(([qMin, x], gi) => {
      const P = SG().toyParams(qMin), key = SG().schnorrKey(P, x), { p, q, g } = P, y = key.y, m = ms[gi];
      const sig = SG().schnorrSign(key, m, 19n + 7n * BigInt(gi));
      out.push([p, q, g, y, m, sig.e, sig.s], [p, q, g, y, m + '.', sig.e, sig.s], [p, q, g, y, m, sig.e, sig.s + q]);
      if (gi === 1) out.push([p, q, g, y, m, (sig.e + 1n) % q, sig.s], [p, q, g, y * g % p, m, sig.e, sig.s]);
    });
    return out;
  };
  const SCH_SOL = 'function schnorrVerify(p, q, g, y, msg, e, s) {\n  if (s < 0n || s >= q) {\n    return false;\n  }\n  const yInv = modPow(y, (q - e % q) % q, p);\n  const R = modPow(g, s, p) * yInv % p;\n  return challenge(R, msg, q) === e;\n}\n';
  ex({
    id: 'sg-x-schnorr-code', chapter: 'sg-ch-dlog', title: 'Write Schnorr verification', level: 3, kind: 'code', fn: 'schnorrVerify', params: ['p', 'q', 'g', 'y', 'msg', 'e', 's'],
    text: ['Write `schnorrVerify(p, q, g, y, msg, e, s)`: the group p, q, g and the public key y (BigInts), the message (a string) and the signature (e, s) (BigInts). Return `true` if it is valid. Given above the editor (read-only): `sha256(bytes)`, `modPow(b, e, m)` and `challenge(R, msg, q)`, which computes SHA-256(R ‖ msg) mod q with R written big-endian in as few bytes as it needs, exactly as the signer did. Since y has order q, y^(−e) = y^(q − e) mod p.', { math: 'reject unless 0 ≤ s < q\nR′ = g^s · y^(−e) mod p\nvalid when challenge(R′, msg, q) = e' }],
    prelude: SHA_SRC + '\n' + POW_SRC + '\n' + CHAL_SRC,
    start: 'function schnorrVerify(p, q, g, y, msg, e, s) {\n  \n}\n',
    ref: schnorrRef, get cases() { return schnorrCases(); },
    timeLimit: 4000,
    hints: ['Rebuild the commitment from public values: g^s divided by y^e, which is g^s·y^(q − e) because y^q = 1.', 'Reject an s outside [0, q − 1] first: g^(s + q) = g^s, so without the check s + q would pass as well.', SCH_SOL],
    solution: SCH_SOL,
    wrong: [SCH_SOL.replace('  if (s < 0n || s >= q) {\n    return false;\n  }\n', ''), SCH_SOL.replace('modPow(y, (q - e % q) % q, p)', 'modPow(y, e, p)'), SCH_SOL.replace('return challenge(R, msg, q) === e;', 'return R === modPow(g, s, p);')],
  });
  ex({
    id: 'sg-x-fs-order', chapter: 'sg-ch-dlog', title: 'What the challenge must hash', level: 2, kind: 'choice',
    text: ['A developer proposes to compute the Schnorr challenge as e = H(m) mod q, leaving R out, "since R can be rebuilt by the verifier anyway". Why must this be refused?'],
    options: ['It is harmless: the verifier still rebuilds R′', 'e no longer depends on R, so R can be fitted to e after the fact, and anyone with the public key could produce pairs (e, s) that verify', 'It makes signing slower', 'It makes the signature twice as long'],
    answer: 1,
    whyNot: { 0: 'The rebuilt R′ = g^s·y^(−e) is checked only through the hash; with R left out of the hash nothing ties it to e.', 2: 'It saves a little hashing; the cost is not the issue.', 3: 'The signature is still (e, s).' },
    hints: ['In the interactive protocol, what goes wrong if the challenge is known before the commitment?', 'With e = H(m), e is known before any R exists, and any s gives a matching R = g^s·y^(−e).', 'The second. The hash of R and m is what fixes the challenge after the commitment; that ordering is the whole security of Fiat–Shamir.'],
    solution: 1, wrong: [0, 2, 3],
  });

  // =========================================================================================================
  // Chapter 3: signatures on curves
  // =========================================================================================================
  const MULT = { table: [['j', 'j·G', 'j·Q'], ['1', '(1, 3)', '(15, 12)'], ['2', '(16, 16)', '(2, 11)'], ['3', '(4, 8)', '(16, 1)'], ['4', '(11, 3)', '(5, 14)'], ['5', '(5, 14)', '(12, 1)'], ['6', '(9, 9)', '(11, 14)'], ['7', '(15, 12)', '(4, 8)'], ['8', '(10, 7)', '(6, 16)'], ['9', '(2, 6)', '(9, 8)'], ['10', '(6, 16)', '(1, 3)'], ['11', '(12, 16)', '(10, 7)'], ['12', '(12, 1)', '(10, 10)'], ['13', '(6, 1)', '(1, 14)'], ['14', '(2, 11)', '(9, 9)'], ['15', '(10, 10)', '(6, 1)'], ['16', '(15, 5)', '(4, 9)'], ['17', '(9, 8)', '(11, 3)'], ['18', '(5, 3)', '(12, 16)'], ['19', '(11, 14)', '(5, 3)'], ['20', '(4, 9)', '(16, 16)'], ['21', '(16, 1)', '(2, 6)'], ['22', '(1, 14)', '(15, 5)']], caption: 'Multiples of G = (1, 3) and of the public key Q = (15, 12) on y² = x³ + 3x + 5 over GF(17), which has n = 23 points.' };
  const ECS = { 'R = k·G, x|value': '6', 'R = k·G, y|value': '16', 'r = R.x mod n|value': '6', 'k⁻¹ mod n|value': '7', 's = k⁻¹(e + r·d) mod n|value': '12' };
  ex({
    id: 'sg-x-ecdsa-sign', chapter: 'sg-ch-curve', title: 'Sign with toy ECDSA', level: 2, kind: 'table',
    text: ['The curve y² = x³ + 3x + 5 over GF(17) has 23 points, a prime number, so G = (1, 3) has order n = 23. The signer\'s private key is d = 7. The message "open hatch 2" gives e = 9 (its SHA-256 hash cut to the 5 bits of n). Sign it with the nonce k = 10, reading k·G from the table.', MULT],
    rows: ['R = k·G, x', 'R = k·G, y', 'r = R.x mod n', 'k⁻¹ mod n', 's = k⁻¹(e + r·d) mod n'], cols: ['value'], corner: 'Step',
    cells: ECS,
    hints: ['10·G is in the table. Everything after R is arithmetic modulo n = 23, not modulo 17.', 'R = (6, 16), so r = 6. 10·7 = 70 = 3·23 + 1, so k⁻¹ = 7.', 'e + r·d = 9 + 42 = 51 ≡ 5 (mod 23), and s = 7·5 = 35 ≡ 12. The signature is (r, s) = (6, 12).'],
    solution: ECS,
    wrong: [with1(ECS, 'k⁻¹ mod n|value', '12'), with1(ECS, 's = k⁻¹(e + r·d) mod n|value', '0')],
  });
  const ECV = { 'w = s⁻¹ mod n|value': '2', 'u₁ = e·w mod n|value': '18', 'u₂ = r·w mod n|value': '12', 'X = u₁·G + u₂·Q, x|value': '6', 'X = u₁·G + u₂·Q, y|value': '16', 'v = X.x mod n|value': '6' };
  ex({
    id: 'sg-x-ecdsa-verify', chapter: 'sg-ch-curve', title: 'Verify toy ECDSA by hand', level: 3, kind: 'table',
    text: ['Verify the signature (r, s) = (6, 12) on e = 9 with the public key Q = (15, 12), on the curve y² = x³ + 3x + 5 over GF(17), n = 23. Both r and s lie in [1, n − 1]. Read u₁·G and u₂·Q from the table, then add the two points yourself with the chord rule modulo 17. The signature is valid when v = r.', MULT, { math: 'λ  = (y₂ − y₁) / (x₂ − x₁)   mod 17\nx₃ = λ² − x₁ − x₂           mod 17\ny₃ = λ(x₁ − x₃) − y₁        mod 17' }],
    rows: ['w = s⁻¹ mod n', 'u₁ = e·w mod n', 'u₂ = r·w mod n', 'X = u₁·G + u₂·Q, x', 'X = u₁·G + u₂·Q, y', 'v = X.x mod n'], cols: ['value'], corner: 'Step',
    cells: ECV,
    hints: ['12·2 = 24 ≡ 1 (mod 23), so w = 2; then u₁ = 18 and u₂ = 12.', 'From the table, 18·G = (5, 3) and 12·Q = (10, 10). λ = (10 − 3)/(10 − 5) = 7·5⁻¹ mod 17, and 5⁻¹ = 7 since 35 = 2·17 + 1.', 'λ = 49 mod 17 = 15. x₃ = 225 − 5 − 10 = 210 ≡ 6, y₃ = 15·(5 − 6) − 3 = −18 ≡ 16. X = (6, 16), which is R; v = 6 = r: valid.'],
    solution: ECV,
    wrong: [with1(with1(ECV, 'X = u₁·G + u₂·Q, x|value', '4'), 'v = X.x mod n|value', '4'), with1(ECV, 'w = s⁻¹ mod n|value', '12')],
  });

  const EC_PRE = 'function mod(a, m) {\n  const r = a % m;\n  return r < 0n ? r + m : r;\n}\n' + 'function inv(a, m) {\n  let [r0, r1] = [mod(a, m), m];\n  let [s0, s1] = [1n, 0n];\n  while (r1 !== 0n) {\n    const t = r0 / r1;\n    [r0, r1] = [r1, r0 - t * r1];\n    [s0, s1] = [s1, s0 - t * s1];\n  }\n  if (r0 !== 1n) throw new Error(a + " has no inverse mod " + m);\n  return mod(s0, m);\n}\n' +
    '// points are {x, y}; null is the point at infinity\nfunction add(C, P, Q) {\n  if (!P) return Q;\n  if (!Q) return P;\n  const p = C.p;\n  if (P.x === Q.x && mod(P.y + Q.y, p) === 0n) return null;\n  const l = P.x === Q.x\n    ? mod((3n * P.x * P.x + C.a) * inv(2n * P.y, p), p)\n    : mod((Q.y - P.y) * inv(Q.x - P.x, p), p);\n  const x = mod(l * l - P.x - Q.x, p);\n  return { x, y: mod(l * (P.x - x) - P.y, p) };\n}\n' +
    'function mul(C, k, P) {\n  let R = null;\n  for (const bit of k.toString(2)) {\n    R = add(C, R, R);\n    if (bit === "1") R = add(C, R, P);\n  }\n  return R;\n}\n';
  const ecdsaRef = (Cv, Q, e, r, s) => {
    const n = Cv.n;
    if (r < 1n || r >= n || s < 1n || s >= n) return false;
    const Cc = S.ECC.curve({ p: Cv.p, a: Cv.a, b: Cv.b, n, h: 1n, G: Cv.G }), w = S.ECC.inv(s, n);
    const X = Cc.add(Cc.mul(S.ECC.mod(e * w, n), Cc.G), Cc.mul(S.ECC.mod(r * w, n), Q));
    return !!X && S.ECC.mod(X.x, n) === r;
  };
  const ecdsaCases = () => {
    const out = [], E = S.ECC, ms = ['open hatch 2', 'vent 4 to half', 'pump 7 off at dusk', 'lamp 12 on', 'seal door 8'];
    ['gf17', 'gf101', 'gf1009', 'dlog65537', 'hnp2e20'].forEach((id, i) => {
      const T = E.toy(id), Cv = { p: T.p, a: T.a, b: T.b, n: T.n, G: { x: T.G.x, y: T.G.y } }, d = 7n + 31n * BigInt(i) % (T.n - 1n);
      const Q = T.mul(d, T.G), dig = S.SHA256.hash(enc(ms[i])), sig = E.ecdsa.sign(T, d, enc(ms[i]), { k: 10n + 13n * BigInt(i) }), e = E.ecdsa.hashToInt(T, dig);
      const q = { x: Q.x, y: Q.y };
      out.push([Cv, q, e, sig.r, sig.s], [Cv, q, e + 1n, sig.r, sig.s], [Cv, q, e, sig.r, sig.s + T.n]);
      if (i === 2) { const Q2 = T.add(Q, T.G); out.push([Cv, q, e, 0n, sig.s], [Cv, q, e, sig.r, 0n], [Cv, { x: Q2.x, y: Q2.y }, e, sig.r, sig.s], [Cv, q, e, sig.s, sig.r]); }
    });
    return out;
  };
  const ECDSA_SOL = 'function ecdsaVerify(C, Q, e, r, s) {\n  const n = C.n;\n  if (r < 1n || r >= n || s < 1n || s >= n) {\n    return false;\n  }\n  const w = inv(s, n);\n  const u1 = mod(e * w, n);\n  const u2 = mod(r * w, n);\n  const X = add(C, mul(C, u1, C.G), mul(C, u2, Q));\n  if (!X) return false;\n  return mod(X.x, n) === r;\n}\n';
  ex({
    id: 'sg-x-ecdsa-code', chapter: 'sg-ch-curve', title: 'Write ECDSA verification', level: 3, kind: 'code', fn: 'ecdsaVerify', params: ['C', 'Q', 'e', 'r', 's'],
    text: ['Write `ecdsaVerify(C, Q, e, r, s)`. The curve is `C = {p, a, b, n, G: {x, y}}`, the public key `Q = {x, y}` (a valid point), `e` the message hash as a number (already cut to the bits of n), and (r, s) the signature; all numbers are BigInts. Return `true` if it is valid. The point arithmetic is given above the editor (read-only): `mod(a, m)`, `inv(a, m)`, `add(C, P, Q)` and `mul(C, k, P)`, with `null` for the point at infinity. The tests run on five toy curves, from 23 points to about a million.', { math: 'reject unless 1 ≤ r, s ≤ n − 1\nw = s⁻¹ mod n,  u₁ = e·w mod n,  u₂ = r·w mod n\nX = u₁·G + u₂·Q;  reject if X is the point at infinity\nvalid when X.x mod n = r' }],
    prelude: EC_PRE,
    start: 'function ecdsaVerify(C, Q, e, r, s) {\n  \n}\n',
    ref: ecdsaRef, get cases() { return ecdsaCases(); },
    hints: ['Check the ranges first: s and s + n have the same inverse modulo n, so without the check s + n would verify too.', 'All the scalars are modulo n, the order of G; the coordinates are modulo p, inside add and mul. Compare X.x reduced modulo n with r.', ECDSA_SOL],
    solution: ECDSA_SOL,
    wrong: [ECDSA_SOL.replace('  if (r < 1n || r >= n || s < 1n || s >= n) {\n    return false;\n  }\n', ''), ECDSA_SOL.replace('const w = inv(s, n);', 'const w = inv(s, C.p);'), ECDSA_SOL.replace('mul(C, u2, Q)', 'mul(C, u2, C.G)')],
  });
  const CL = { 'our seed 9d47…: h[0] = a4|after clamping': 'a0', 'our seed 9d47…: h[31] = a9|after clamping': '69', 'RFC 8032 test 1: h[0] = 35|after clamping': '30', 'RFC 8032 test 1: h[31] = 0f|after clamping': '4f' };
  ex({
    id: 'sg-x-ed-clamp', chapter: 'sg-ch-curve', title: 'Clamp the Ed25519 scalar', level: 2, kind: 'table', cellKind: 'hex',
    text: ['Ed25519 hashes the 32-byte seed with SHA-512 and clamps the low 32 bytes h[0..31] into the scalar a. Below are byte 0 and byte 31 for two seeds: the seed of the lesson, and the seed of RFC 8032\'s first test vector. Give each byte after clamping, in hex.', { math: 'h[0]  ← h[0] & 0xf8           clear bits 0, 1, 2: a is a multiple of 8\nh[31] ← (h[31] & 0x7f) | 0x40  clear bit 7, set bit 6: a has exactly 255 bits' }],
    rows: ['our seed 9d47…: h[0] = a4', 'our seed 9d47…: h[31] = a9', 'RFC 8032 test 1: h[0] = 35', 'RFC 8032 test 1: h[31] = 0f'], cols: ['after clamping'], corner: 'Byte',
    cells: CL,
    hints: ['Write each byte in binary. a4 = 1010 0100 and a9 = 1010 1001.', 'Byte 0: keep the top five bits. Byte 31: force the top two bits to 01 and keep the rest.', 'a4 → a0, a9 → 69, 35 → 30, 0f → 4f. In the second seed the top bit of byte 31 was already clear, and bit 6 gets set.'],
    solution: CL,
    wrong: [with1(CL, 'our seed 9d47…: h[31] = a9|after clamping', '29'), with1(CL, 'RFC 8032 test 1: h[31] = 0f|after clamping', '0f')],
  });
  ex({
    id: 'sg-x-ed-s-range', chapter: 'sg-ch-curve', title: 'Why check S < L?', level: 2, kind: 'choice',
    text: ['An Ed25519 verifier rejects a signature R ‖ S when S ≥ L, the order of the base point. What would go wrong without that check?'],
    options: ['Nothing: S·B is the same point for S and S + L, so the check is cosmetic', 'Anyone could turn a valid signature into a second valid one, S + L, on the same message, so signature bytes would no longer identify a signed object', 'Anyone could sign new messages', 'The verifier would reject valid signatures'],
    answer: 1,
    whyNot: { 0: 'S·B is indeed the same point, which is exactly why S + L would verify: a second, different encoding of a valid signature.', 2: 'Adding L gives another signature on the same message only, not on a new one.', 3: 'Signers always output S < L; the check only removes extra encodings.' },
    hints: ['L·B is the point at infinity, so (S + L)·B = S·B.', 'S + L still fits in 32 bytes, so R ‖ (S + L) is a well-formed 64-byte string that passes the equation.', 'The second: malleability. A system that names a transaction or a document by its signature bytes would see two names for one signed object. The check S < L makes every valid signature have one encoding.'],
    solution: 1, wrong: [0, 2, 3],
  });

  // =========================================================================================================
  // Chapter 4: nonces and choosing a scheme
  // =========================================================================================================
  ex({
    id: 'sg-x-nonce-fresh', chapter: 'sg-ch-use', title: 'Nonces on cloned servers', level: 2, kind: 'choice',
    text: ['A service signs with ECDSA on virtual machines that are often started from one snapshot, so two machines may begin with identical generator states. Which ways of choosing the nonce k keep the private key safe? Choose every one.'],
    options: ['RFC 6979: k derived with HMAC-SHA-256 from the private key and the message hash', 'A hedged nonce: k derived from the private key, the message hash and fresh random bytes', 'k from the system generator, seeded once at boot', 'k = a counter kept on disk, increased by one per signature', 'k = SHA-256(message) reduced modulo n'],
    answer: [0, 1],
    whyNot: { 2: 'Two clones with the same state draw the same k for different messages: a repeated nonce.', 3: 'A counter is predictable, and clones restore the same value.', 4: 'Anyone can compute k from the message, and a known k gives d at once.' },
    hints: ['Two clones that sign different messages must still use different nonces, and nobody else may be able to compute k.', 'A derived k depends on the message, so different messages give different nonces whatever the generator does. It also depends on the private key, so nobody else can compute it.', 'The first two. RFC 6979 needs no generator at all; the hedged nonce adds randomness but stays safe if the randomness repeats. A generator seeded once, a counter and a public hash of the message all fail.'],
    solution: [0, 1], wrong: [[0], [0, 1, 2], [0, 4], [2, 3]],
  });
  ex({
    id: 'sg-x-nonce-same-r', chapter: 'sg-ch-use', title: 'The same R twice', level: 1, kind: 'choice',
    text: ['A log holds two Ed25519 signatures from one key, and their first 32 bytes, R, are equal. What does that show?'],
    options: ['The private key is exposed and must be revoked', 'The same message was signed twice, giving the same signature, which is harmless', 'The signer\'s random generator is broken', 'At least one of the signatures is invalid'],
    answer: 1,
    whyNot: { 0: 'That is the conclusion for equal r on different messages in ECDSA with a bad generator. In Ed25519, R depends on the message.', 2: 'Ed25519 uses no random generator to sign.', 3: 'Both can be valid: they are the same signature.' },
    hints: ['How is the Ed25519 nonce made?', 'r = SHA-512(prefix ‖ M) mod L and R = r·B: the same R means the same M, short of a SHA-512 collision.', 'The same message was signed twice, and the two signatures are identical. Nothing new is revealed.'],
    solution: 1, wrong: [0, 2, 3],
  });
  const SZ = { 'RSA-2048, PSS|public key (bytes)': '256', 'RSA-2048, PSS|signature (bytes)': '256', 'RSA-2048, PSS|security (bits)': '112', 'RSA-3072, PSS|public key (bytes)': '384', 'RSA-3072, PSS|signature (bytes)': '384', 'RSA-3072, PSS|security (bits)': '128', 'ECDSA P-256|public key (bytes)': '33', 'ECDSA P-256|signature (bytes)': '64', 'ECDSA P-256|security (bits)': '128', 'Ed25519|public key (bytes)': '32', 'Ed25519|signature (bytes)': '64', 'Ed25519|security (bits)': '128' };
  ex({
    id: 'sg-x-sizes', chapter: 'sg-ch-use', title: 'Sizes and security levels', level: 2, kind: 'table',
    text: ['Fill in the size of the public key and of one signature, in bytes, and the security level in bits as NIST SP 800-57 rates it. Count an RSA public key as its modulus, an ECDSA public key as a compressed point, and an ECDSA signature as r ‖ s at fixed width.'],
    rows: ['RSA-2048, PSS', 'RSA-3072, PSS', 'ECDSA P-256', 'Ed25519'], cols: ['public key (bytes)', 'signature (bytes)', 'security (bits)'], corner: 'Scheme',
    cells: SZ,
    hints: ['An RSA signature is a number below n, written in as many bytes as n has.', 'A compressed P-256 point is one byte for the sign of y plus 32 bytes of x; r and s are 32 bytes each. Ed25519 keys are 32 bytes, signatures R ‖ S 64.', 'RSA-2048: 256, 256, 112. RSA-3072: 384, 384, 128. ECDSA P-256: 33, 64, 128. Ed25519: 32, 64, 128.'],
    solution: SZ,
    wrong: [with1(SZ, 'RSA-2048, PSS|security (bits)', '128'), with1(SZ, 'ECDSA P-256|public key (bytes)', '32')],
  });
  ex({
    id: 'sg-x-level', chapter: 'sg-ch-use', title: 'The level of P-384', level: 1, kind: 'number',
    text: ['The best known attack on the discrete logarithm on a well-chosen curve takes about √n steps for a group of order n. About how many bits of security does ECDSA on P-384, with n of 384 bits, give?'],
    answer: 192,
    hints: ['√(2³⁸⁴) = 2^(384/2).', 'Pollard\'s rho needs about √n group operations.', '192 bits. NIST SP 800-57 rates P-384 at 192 bits, matched by an RSA modulus of 7680 bits.'],
    solution: '192', wrong: ['384', '128', '256'],
    whyNot: { 384: 'The attack is a square-root search, so the bits halve.', '*': 'Halve the size of n in bits.' },
  });
  ex({
    id: 'sg-x-choose', chapter: 'sg-ch-use', title: 'Choose a scheme', level: 2, kind: 'choice',
    text: ['A new messaging app signs every message on phones whose random generators are of unknown quality. It wants the smallest keys and signatures it can get at 128-bit security, with no special hardware or certification needs. Which scheme fits best?'],
    options: ['RSA-2048 with PSS', 'DSA 2048/224 with a random nonce', 'ECDSA P-256 with a random nonce', 'Ed25519'],
    answer: 3,
    whyNot: { 0: '112-bit security, and 256-byte keys and signatures.', 1: 'A 256-byte public key, 112-bit security, and a random nonce on an unreliable generator risks the key.', 2: 'The size fits, but a random nonce on an unreliable generator risks the key; with RFC 6979 nonces it would be a sound second choice.' },
    hints: ['Three requirements: 128 bits, small sizes, and nothing that depends on the phone\'s generator at signing time.', 'Only the curve schemes are small at 128 bits; of those, one derives its nonce by design.', 'Ed25519: 32-byte keys, 64-byte signatures, 128-bit security, and r = SHA-512(prefix ‖ M), so a weak generator cannot leak the key through the nonce.'],
    solution: 3, wrong: [0, 1, 2],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
