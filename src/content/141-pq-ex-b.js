// Part 14, post-quantum cryptography: the exercises of chapter 4 (hash-based signatures and codes). The other
// chapters' exercises are in 141-pq-ex.js. Keys come from S.PQ.Lamport, S.PQ.WOTS and S.PQ.Merkle with seeds of our
// own; the code exercises are checked against S.PQ.Lamport, and the SHAKE256 given to the student against S.PQ.shake256.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('pq-x-lamport-pk')) return;
  const ex = (o) => C.exercise(o);
  const P = () => S.PQ;
  const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');

  // ---- the SHAKE256 helper the Lamport exercises give the student as a prelude (the sandbox has no libraries) -----
  const HELPER = "// SHAKE256 (FIPS 202) and small helpers\nfunction shake256(msg, outLen) {\n  const M = (1n << 64n) - 1n;\n  const rot = (x, n) =>\n    ((x << BigInt(n)) |\n      (x >> BigInt(64 - n))) & M;\n  const R = [0, 1, 62, 28, 27, 36, 44, 6,\n    55, 20, 3, 10, 43, 25, 39, 41, 45,\n    15, 21, 8, 18, 2, 61, 56, 14];\n  const RC = [];\n  let l = 1;\n  for (let i = 0; i < 24; i++) {\n    let c = 0n;\n    for (let j = 0; j < 7; j++) {\n      if (l & 1) {\n        c |= 1n << BigInt((1 << j) - 1);\n      }\n      l = l & 0x80\n        ? ((l << 1) ^ 0x171) & 0xff\n        : l << 1;\n    }\n    RC.push(c);\n  }\n  const f = (A) => {\n    for (let r = 0; r < 24; r++) {\n      const C = [0, 1, 2, 3, 4].map((x) =>\n        A[x] ^ A[x + 5] ^ A[x + 10] ^\n        A[x + 15] ^ A[x + 20]);\n      for (let x = 0; x < 5; x++) {\n        const D = C[(x + 4) % 5] ^\n          rot(C[(x + 1) % 5], 1);\n        for (let y = 0; y < 25; y += 5) {\n          A[x + y] ^= D;\n        }\n      }\n      const B = new Array(25);\n      for (let x = 0; x < 5; x++) {\n        for (let y = 0; y < 5; y++) {\n          const k = x + 5 * y;\n          const t =\n            y + 5 * ((2 * x + 3 * y) % 5);\n          B[t] = R[k]\n            ? rot(A[k], R[k]) : A[k];\n        }\n      }\n      for (let i = 0; i < 25; i += 5) {\n        for (let x = 0; x < 5; x++) {\n          A[i + x] = B[i + x] ^\n            (~B[i + (x + 1) % 5] & M &\n              B[i + (x + 2) % 5]);\n        }\n      }\n      A[0] ^= RC[r];\n    }\n  };\n  const rate = 136;\n  const A = new Array(25).fill(0n);\n  const p = Array.from(msg);\n  p.push(0x1f);\n  while (p.length % rate) p.push(0);\n  p[p.length - 1] |= 0x80;\n  for (let o = 0; o < p.length;\n    o += rate) {\n    for (let i = 0; i < rate; i++) {\n      A[i >> 3] ^= BigInt(p[o + i]) <<\n        BigInt(8 * (i & 7));\n    }\n    f(A);\n  }\n  const out = new Uint8Array(outLen);\n  for (let i = 0; i < outLen; i++) {\n    if (i && i % rate === 0) f(A);\n    const w = A[(i % rate) >> 3];\n    out[i] = Number(\n      (w >> BigInt(8 * (i & 7))) & 255n);\n  }\n  return out;\n}\nconst bytesOf = (text) =>\n  Uint8Array.from(text, (c) =>\n    c.charCodeAt(0));\nconst hex = (b) => Array.from(b,\n  (v) => v.toString(16).padStart(2, \"0\"))\n  .join(\"\");\nconst fromHex = (h) => Uint8Array.from(\n  h.match(/../g), (x) => parseInt(x, 16));\n// the 16 bits of SHAKE256(msg, 2 bytes),\n// high bit of the first byte first\nconst digestBits = (msg) => {\n  const d = shake256(bytesOf(msg), 2);\n  return Array.from({ length: 16 },\n    (_, i) =>\n      (d[i >> 3] >> (7 - (i & 7))) & 1);\n};";

  // one Lamport key over 16-bit digests (n = 2), as hex strings, made from a seed when the tests are first asked for
  let LK = null;
  const lkey = () => {
    if (LK) return LK;
    const kg = P().Lamport.keyGen('tidewater-ledger', { n: 2 });
    LK = { kg, sk: kg.sk.sk.map((pr) => pr.map(hex)), pk: kg.pk.pk.map((pr) => pr.map(hex)) };
    return LK;
  };
  const MSGS = ['ship the tea on Tuesday', 'hold the tea until Friday', 'the barge leaves at nine', 'x', 'pay the bearer 7 crowns'];
  const signHex = (msg) => P().Lamport.sign(Object.assign({}, lkey().kg.sk), msg).sig.map(hex);

  // =========================================================================================================
  // Chapter 4: hash-based signatures and codes
  // =========================================================================================================
  ex({
    id: 'pq-x-lamport-pk', chapter: 'pq-ch-hash', title: 'The size of a Lamport public key', level: 1, kind: 'number',
    text: ['A Lamport key signs 256-bit digests with secret strings of 32 bytes, and its public key holds the 32-byte hash of every secret string. How many bytes is the public key?'],
    answer: 16384,
    hints: ['There is one pair of secret strings per digest bit.', '256 pairs = 512 strings, so 512 hashes.', '512 × 32 = 16 384 bytes, 16 KB for one key that signs once.'],
    solution: '16384', wrong: ['8192', '512', '1024'],
    whyNot: 'Count two hashes for each of the 256 digest bits, 32 bytes each.',
  });
  ex({
    id: 'pq-x-lamport-sig', chapter: 'pq-ch-hash', title: 'The size of a Lamport signature', level: 1, kind: 'number',
    text: ['With the same parameters (256-bit digests, 32-byte secret strings), how many bytes is one signature?'],
    answer: 8192,
    hints: ['A signature reveals one string per digest bit.', '256 strings of 32 bytes.', '256 × 32 = 8192 bytes.'],
    solution: '8192', wrong: ['16384', '256', '32'],
    whyNot: 'One revealed string per digest bit, 32 bytes each.',
  });
  ex({
    id: 'pq-x-lamport-sign', chapter: 'pq-ch-hash', title: 'Write Lamport signing', level: 2, kind: 'code', fn: 'lamportSign', params: ['sk', 'msg'],
    text: ['Write `lamportSign(sk, msg)` for 16-bit digests. `sk` is an array of 16 pairs `[s0, s1]` of secret strings in hex; `msg` is ASCII text. The digest is SHAKE256(msg) cut to 2 bytes, read bit by bit from the high bit of the first byte. For digest bit i, reveal `sk[i][0]` if the bit is 0 and `sk[i][1]` if it is 1. Return the 16 revealed strings, in hex, in order.', 'The given code above the editor holds SHAKE256 and small helpers you may call (`bytesOf`, `hex`, `fromHex`); `digestBits(msg)` already gives the 16 bits.'],
    prelude: HELPER,
    start: 'function lamportSign(sk, msg) {\n  \n}\n',
    tests: () => MSGS.map((m) => ({ args: [lkey().sk, m], want: signHex(m) })),
    hints: ['digestBits(msg) returns an array of 16 numbers, each 0 or 1.', 'For each i, the bit d[i] picks which string of the pair to reveal: sk[i][d[i]].', 'function lamportSign(sk, msg) {\n  const d = digestBits(msg);\n  return d.map((bit, i) => sk[i][bit]);\n}'],
    solution: 'function lamportSign(sk, msg) {\n  const d = digestBits(msg);\n  return d.map((bit, i) => sk[i][bit]);\n}\n',
    wrong: ['function lamportSign(sk, msg) {\n  const d = digestBits(msg);\n  return d.map((bit, i) => sk[i][1 - bit]);\n}\n', 'function lamportSign(sk, msg) {\n  const d = digestBits(msg).reverse();\n  return d.map((bit, i) => sk[i][bit]);\n}\n'],
  });
  ex({
    id: 'pq-x-lamport-verify', chapter: 'pq-ch-hash', title: 'Write Lamport verification', level: 2, kind: 'code', fn: 'lamportVerify', params: ['pk', 'msg', 'sig'],
    text: ['Write `lamportVerify(pk, msg, sig)`. `pk` is an array of 16 pairs `[h0, h1]` in hex, where each value is SHAKE256 of the matching secret string, cut to 2 bytes. `sig` is 16 strings in hex. Return `true` if, for every digest bit i, SHAKE256(sig[i]) cut to 2 bytes equals `pk[i][bit]`, and `false` otherwise.', 'The tests include honest signatures, a signature checked against the wrong message, and signatures with one string changed.'],
    prelude: HELPER,
    start: 'function lamportVerify(pk, msg, sig) {\n  \n}\n',
    tests: () => {
      const k = lkey(), s0 = signHex(MSGS[0]), s1 = signHex(MSGS[1]);
      const bent = s0.slice(); bent[9] = bent[9] === '0000' ? '0001' : '0000';
      const swapped = s0.slice(); [swapped[2], swapped[3]] = [swapped[3], swapped[2]];
      const other = s0.slice(); other[15] = k.sk[15][1 - P().Lamport.digestBits(2, MSGS[0])[15]];
      return [{ args: [k.pk, MSGS[0], s0], want: true }, { args: [k.pk, MSGS[1], s1], want: true }, { args: [k.pk, MSGS[1], s0], want: false }, { args: [k.pk, MSGS[0], bent], want: false }, { args: [k.pk, MSGS[0], other], want: false }, { args: [k.pk, MSGS[0], swapped], want: false }, { args: [k.pk, MSGS[2], signHex(MSGS[2])], want: true }];
    },
    hints: ['Compute the digest bits of msg, then check the 16 positions one by one.', 'hex(shake256(fromHex(sig[i]), 2)) must equal pk[i][d[i]].', 'function lamportVerify(pk, msg, sig) {\n  const d = digestBits(msg);\n  return d.every((bit, i) => hex(shake256(fromHex(sig[i]), 2)) === pk[i][bit]);\n}'],
    solution: 'function lamportVerify(pk, msg, sig) {\n  const d = digestBits(msg);\n  return d.every((bit, i) => hex(shake256(fromHex(sig[i]), 2)) === pk[i][bit]);\n}\n',
    wrong: ['function lamportVerify(pk, msg, sig) {\n  return sig.every((s, i) => pk[i].includes(hex(shake256(fromHex(s), 2))));\n}\n', 'function lamportVerify(pk, msg, sig) {\n  return true;\n}\n'],
  });

  // why a one-time key signs once: how much of the key two signatures expose
  ex({
    id: 'pq-x-lamport-reuse', chapter: 'pq-ch-hash', title: 'What a second signature exposes', level: 2, kind: 'number',
    text: ['A Lamport key over 16-bit digests signed one message with digest bits 1011111011010000. By mistake it then signed a second message, with digest bits 1000001010111111. For how many of the 16 pairs are both secret strings now public? This is the count that makes reuse unsafe: every such pair no longer binds a signature to the message.'],
    answer: 10,
    hints: ['A pair has both strings public exactly where the two digests differ: the first signature revealed one string, the second the other.', 'XOR the digests bit by bit and count the 1s.', 'They differ in 10 of the 16 positions, so 10 pairs are fully public and only 6 bits still bind a signature. The defence is never to sign twice with one key: a Merkle tree gives one fresh leaf per message, and SLH-DSA picks the leaf from the message hash.'],
    solution: '10', wrong: ['6', '16', '8'],
    whyNot: 'Count the positions where the two digests differ.',
  });
  ex({
    id: 'pq-x-reuse-defence', chapter: 'pq-ch-hash', title: 'Keeping one-time keys one-time', level: 1, kind: 'choice',
    text: ['A service signs with XMSS, a Merkle tree of one-time keys, and stores the index of the next unused leaf. Which practice keeps every leaf used at most once?'],
    options: ['Restore the signing module from last week\'s backup after a failure', 'Save the advanced index to durable storage before releasing each signature', 'Run two copies of the signer on cloned virtual machines for availability', 'Pick the leaf at random from the tree for each message'],
    answer: 1,
    whyNot: { 0: 'An old backup holds an old index, so leaves signed since then would be used again.', 2: 'Two clones start from the same index and sign different messages with the same leaves.', 3: 'With a small tree, random choices collide quickly; only a stateless design with a huge tree (SLH-DSA) can afford that.' },
    hints: ['A leaf is spent once a signature with it has left the signer.', 'The danger is any event that makes the signer forget that a leaf is spent.', 'Advance and save the index before the signature goes out; then a crash can waste a leaf but never reuse one.'],
    solution: 1, wrong: [0, 2, 3],
  });

  // Winternitz: n = 2 bytes, w = 16, so 4 message digits and 2 checksum digits
  const WMSG = 'unlock the north hatch';
  const wdig = (() => { const M = P().shake256(new TextEncoder().encode(WMSG), 2); return { hex: hex(M), d: P().WOTS.digits(2, 16, M) }; })();
  const wrows = ['chain 0', 'chain 1', 'chain 2', 'chain 3', 'chain 4 (checksum)', 'chain 5 (checksum)'];
  const wcells = {};
  wdig.d.all.forEach((v, i) => { wcells[wrows[i] + '|digit'] = String(v); wcells[wrows[i] + '|signer walks'] = String(v); wcells[wrows[i] + '|verifier walks'] = String(15 - v); });
  ex({
    id: 'pq-x-wots-table', chapter: 'pq-ch-hash', title: 'Winternitz chains for one message', level: 3, kind: 'table',
    text: ['A Winternitz key with w = 16 signs 16-bit digests: 4 message digits (the hex digits of the digest, first to last) and 2 checksum digits (Σ(15 − dᵢ) written as two base-16 digits, high first). Each chain has 15 hash steps. The digest of “' + WMSG + '” is ' + wdig.hex + '. For each chain, give its digit, the steps the signer walks from the secret start, and the steps the verifier walks to reach the public end.'],
    rows: wrows, cols: ['digit', 'signer walks', 'verifier walks'],
    cells: wcells,
    hints: ['The message digits are the hex digits of ' + wdig.hex + ': ' + wdig.d.msg.join(', ') + '. The signer walks d steps; the verifier walks the remaining 15 − d.', 'Checksum: (15 − ' + wdig.d.msg.join(') + (15 − ') + ') = ' + wdig.d.csum + ', which is ' + wdig.d.check.join(' ') + ' in base 16.', 'Digits ' + wdig.d.all.join(', ') + '; signer ' + wdig.d.all.join(', ') + '; verifier ' + wdig.d.all.map((v) => 15 - v).join(', ') + '. Signer and verifier together walk 15 steps on every chain: 90 hashes in all.'],
    solution: wcells,
    wrong: [Object.assign({}, wcells, { 'chain 4 (checksum)|digit': String(wdig.d.check[1]), 'chain 5 (checksum)|digit': String(wdig.d.check[0]) })],
  });
  ex({
    id: 'pq-x-wots-size', chapter: 'pq-ch-hash', title: 'The size of a Winternitz signature', level: 2, kind: 'number',
    text: ['A Winternitz key with n = 32 bytes and w = 16 signs a 256-bit digest. How many bytes is a signature? Use len₁ = ⌈8n / log₂ w⌉ and len₂ = ⌊log₂(len₁·(w − 1)) / log₂ w⌋ + 1.'],
    answer: 2144,
    hints: ['len₁ = 256 / 4 = 64 message digits.', 'len₁·(w − 1) = 960 and log₂ 960 = 9.91, so len₂ = ⌊9.91 / 4⌋ + 1 = 3.', '67 chain values of 32 bytes: 2144 bytes, about a quarter of a Lamport signature of the same strength.'],
    solution: '2144', wrong: ['2048', '8192', '67'],
    whyNot: 'Add the message and checksum digits, len₁ + len₂, and multiply by n.',
  });
  const mcells = { 'level 0|sibling node': '7', 'level 0|side': 'right', 'level 1|sibling node': '2', 'level 1|side': 'left', 'level 2|sibling node': '0', 'level 2|side': 'left' };
  ex({
    id: 'pq-x-merkle-path', chapter: 'pq-ch-hash', title: 'The authentication path of leaf 6', level: 2, kind: 'table',
    text: ['A Merkle tree of height 3 has 8 leaves, numbered 0 to 7 at level 0; level 1 has nodes 0 to 3, level 2 nodes 0 and 1, and the root is level 3. A signature with one-time key 6 carries the authentication path. For each level, give the index of the sibling node included, and whether the verifier hashes it on the left or the right of the node it has computed.'],
    rows: ['level 0', 'level 1', 'level 2'], cols: ['sibling node', 'side'],
    cells: mcells,
    hints: ['At each level the node on the path has index ⌊6 / 2ᶻ⌋; its sibling is that index with the lowest bit flipped.', 'Level 0: node 6, sibling 7. Level 1: node 3, sibling 2. Level 2: node 1, sibling 0. An even index is a left child, so its sibling goes on the right.', 'Siblings 7 (right), 2 (left), 0 (left). The verifier computes H(leaf 6 ‖ leaf 7) = node 3, H(node 2 ‖ node 3) = node 1, H(node 0 ‖ node 1) = the root.'],
    solution: mcells,
    wrong: [Object.assign({}, mcells, { 'level 1|sibling node': '3', 'level 1|side': 'right' }), Object.assign({}, mcells, { 'level 0|side': 'left' })],
  });
  ex({
    id: 'pq-x-hamming', chapter: 'pq-ch-hash', title: 'Find the flipped bit', level: 2, kind: 'number',
    text: ['The Hamming [7, 4] code has the check matrix H below: column j (j = 1 to 7, left to right) is j written in binary, top row the lowest bit. A codeword was sent and one bit flipped on the way; the receiver got 0110111. Which position (1 to 7, from the left) flipped?', { math: 'H = 1 0 1 0 1 0 1\n    0 1 1 0 0 1 1\n    0 0 0 1 1 1 1' }],
    answer: 5,
    hints: ['The syndrome is H·wᵀ: for each row of H, XOR the bits of the word where the row has a 1.', 'Row 1 (positions 1, 3, 5, 7): 0 ⊕ 1 ⊕ 1 ⊕ 1 = 1. Row 2 (positions 2, 3, 6, 7): 1 ⊕ 1 ⊕ 1 ⊕ 1 = 0. Row 3 (positions 4, 5, 6, 7): 0 ⊕ 1 ⊕ 1 ⊕ 1 = 1.', 'The syndrome, lowest bit on top, is 1, 0, 1: binary 101 = 5. Position 5 flipped; the codeword sent was 0110011, carrying the message 1011.'],
    solution: '5', wrong: ['3', '4', '6'],
    whyNot: 'Read the syndrome as a binary number with the top row as its lowest bit.',
  });
  ex({
    id: 'pq-x-choose', chapter: 'pq-ch-hash', title: 'A scheme for the job', level: 2, kind: 'choice',
    text: ['A maker of medical pumps signs firmware updates. The devices will be in service for twenty years; the signing key sits in one hardware module that is backed up to a second one; and the vendor wants an assumption as conservative as possible. Which signature scheme fits best?'],
    options: ['ML-KEM-768', 'SLH-DSA', 'XMSS with the state kept in the module', 'ECDSA on P-256'],
    answer: 1,
    whyNot: { 0: 'ML-KEM is a key encapsulation, not a signature.', 2: 'A stateful scheme with a backed-up module risks restoring an old state and reusing a one-time key.', 3: 'Shor breaks ECDSA, and twenty years is long enough for that to matter.' },
    hints: ['First rule out what is not a signature, and what Shor breaks.', 'Between the hash-based schemes, consider what a backup of a stateful key can do.', 'SLH-DSA rests on hash functions alone and keeps no state, so a restored backup is harmless. Its large signatures matter little for an occasional firmware update.'],
    solution: 1, wrong: [0, 2, 3],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
