// Part 6, modes of operation: the chapters and the lessons. The exercises, the tour and the course are in
// 061-modes-ex.js. The lessons teach correct use: which mode for which job, the rules for IVs, nonces and padding, and
// why encryption needs a tag. Every value quoted here was worked out by the engines (S.Modes, S.GCM, S.XTS, S.AES) on
// the topics' own inputs.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('mo-ecb')) return;
  const X = (id) => ({ exercise: id });
  const lesson = (o) => C.lesson(Object.assign(o, { blocks: o.blocks.filter(Boolean) }));
  const T = (id, b) => (S.byId && S.byId(id) ? b : null); // a topic block only once that topic exists

  C.chapter({ id: 'mo-block', part: 'modes', n: 1, title: 'ECB and CBC', blurb: 'A block cipher encrypts 16 bytes. ECB applies it to each block alone and shows which blocks are equal; CBC chains the blocks through a fresh, unpredictable IV.' });
  C.chapter({ id: 'mo-stream', part: 'modes', n: 2, title: 'CFB, OFB and CTR', blurb: 'Turning a block cipher into a keystream: feedback from the ciphertext, from the cipher\'s own output, or from a counter that can jump anywhere.' });
  C.chapter({ id: 'mo-ae', part: 'modes', n: 3, title: 'Disks and authenticated encryption', blurb: 'XTS for disk sectors, GCM for messages that must not be changed, and the rules that keep them safe: verify before decrypting, and never repeat a nonce.' });
  C.chapter({ id: 'mo-use', part: 'modes', n: 4, title: 'Padding, limits and choosing a mode', blurb: 'PKCS#7 and ciphertext stealing, how much data one key and one block size can carry, and which mode fits which job.' });

  // =========================================================================================================
  // Chapter 1: ECB and CBC
  // =========================================================================================================
  lesson({
    id: 'mo-ecb', chapter: 'mo-block', title: 'ECB: why the picture survives', minutes: 6,
    summary: 'Electronic codebook mode encrypts every block on its own. Equal plaintext blocks give equal ciphertext blocks, so the structure of the data shows through, however strong the cipher.',
    blocks: [
      'AES encrypts exactly 16 bytes. A file has thousands. The obvious answer is to cut the file into blocks and encrypt each one. What can go wrong with something so simple, when AES itself is unbroken?',
      { topic: 'modes-ecb', frame: 1, caption: 'Blocks 0 and 1 of the picture are the same sixteen pixels, so they encrypt to the same ciphertext, 96d7f5b8b530efb0be9e0ddae618a28d.' },
      { predict: { q: 'The picture has 192 blocks, but only 55 different ones. How many different ciphertext blocks does ECB produce?', options: ['192', '55', 'About 96', 'It depends on the key'], answer: 1, explain: 'ECB is a fixed table from plaintext block to ciphertext block under one key: equal in, equal out. 55 different blocks give 55 different ciphertexts, and the pattern of repeats is the picture.' } },
      { topic: 'modes-ecb', frame: 2, caption: 'Every block is scrambled, yet the outline of the lighthouse is plain to see: 55 distinct ciphertext blocks, exactly as many as plaintext blocks.' },
      { topic: 'modes-ecb', frame: 3, caption: 'The same pixels in CBC: 192 distinct blocks out of 192, and nothing of the picture is left.' },
      { warn: 'It is not only pictures. A database column of encrypted salaries in ECB shows who earns the same; a protocol message shows which fields repeat. ECB is acceptable only for a single block of random data, such as wrapping one key.' },
      { h: 'Recap' },
      { list: ['ECB: Cᵢ = Eₖ(Pᵢ), each block alone.', 'Equal plaintext blocks give equal ciphertext blocks: patterns leak.', 'Use a mode with an IV or nonce for anything longer than one random block.'] },
      X('mo-x-ecb-count'), X('mo-x-ecb-spot'),
    ],
  });

  lesson({
    id: 'mo-cbc', chapter: 'mo-block', title: 'CBC: chaining through an IV', minutes: 8,
    summary: 'Cipher block chaining XORs each plaintext block with the previous ciphertext block before encrypting it, starting from an IV. The IV must be unpredictable and new for every message. Encryption is sequential; decryption can run in parallel.',
    blocks: [
      'ECB fails because the same block always meets the cipher in the same form. If each block were first mixed with something that changes from block to block and from message to message, repeats would vanish. What is cheap and always at hand? The ciphertext block just made.',
      { math: 'C₀ = IV\nCᵢ = Eₖ(Pᵢ ⊕ Cᵢ₋₁)          encryption\nPᵢ = Dₖ(Cᵢ) ⊕ Cᵢ₋₁          decryption' },
      { topic: 'modes-cbc', frame: 1, caption: 'Block 1: P₁ = 4665726e… is XORed with the IV 71756965…, giving 37101b0b…. That XOR, never the plaintext itself, goes into the cipher.' },
      { topic: 'modes-cbc', frame: 4, caption: 'Block 2 is XORed with C₁, the ciphertext just made, 5f936a23…: block 2 cannot start before block 1 is done.' },
      { predict: { q: 'When decrypting, one bit of C₁ was damaged in transit. Which plaintext blocks come out wrong?', options: ['Only P₁', 'P₁ entirely, and one bit of P₂', 'Every block from P₁ on', 'Only P₂'], answer: 1, explain: 'P₁ = Dₖ(C₁) ⊕ IV: the cipher turns the damaged C₁ into garbage. P₂ = Dₖ(C₂) ⊕ C₁: C₂ is intact, so only the one damaged bit of C₁ shows, in the same place of P₂. P₃ does not use C₁ at all.' } },
      { topic: 'modes-cbc', frame: 10, caption: 'Three blocks out: 5f936a23… e25791e2… 2ec18700…. The message was 44 bytes, so PKCS#7 padding added 4 bytes of 04 to fill the last block.' },
      { h: 'The IV' },
      'The IV is sent with the ciphertext; it need not be secret. It must be **unpredictable** and **new for every message**. A fixed IV makes two messages with the same start encrypt to the same first blocks, which is ECB\'s leak again. An IV an attacker can predict in advance, such as a counter or the last ciphertext block of the previous message, lets a chosen-plaintext attacker test guesses about earlier blocks. Generate it with a cryptographic random generator.',
      { warn: 'CBC on its own gives no integrity: a changed ciphertext still decrypts to something, and a receiver that reports bad padding differently from other errors has been broken byte by byte (the padding-oracle attack). Chapter 3 shows what to add.' },
      { h: 'Recap' },
      { list: ['Cᵢ = Eₖ(Pᵢ ⊕ Cᵢ₋₁), starting from C₀ = IV.', 'Equal plaintext blocks give different ciphertext blocks.', 'The IV must be fresh and unpredictable for every message.', 'Encryption is sequential; decryption can run in parallel; a damaged block garbles its own plaintext and one bit of the next.'] },
      X('mo-x-cbc-dec'), X('mo-x-cbc-error'), X('mo-x-cbc-iv'), X('mo-x-code-cbc'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: CFB, OFB and CTR
  // =========================================================================================================
  lesson({
    id: 'mo-cfbofb', chapter: 'mo-stream', title: 'CFB and OFB: keystreams from feedback', minutes: 7,
    summary: 'CFB encrypts the previous ciphertext block and XORs the result with the plaintext; OFB encrypts its own previous output. Both turn the block cipher into a stream cipher, need no padding, and use only the encryption direction of the cipher.',
    blocks: [
      'CBC needs whole blocks and both directions of the cipher. A serial line sends bytes one at a time, and a small device may have room only for encryption. Can a block cipher make a keystream instead?',
      { topic: 'modes-cfb', frame: 2, caption: 'CFB: the register starts as the IV; its encryption, 063bb97d…, is XORed with P₁ to give C₁ = 4d52cd18…, and C₁ becomes the next register.' },
      { topic: 'modes-cfb', frame: 4, caption: 'A short last block uses only part of the keystream: the ciphertext is exactly as long as the message, with no padding.' },
      { topic: 'modes-ofb', frame: 3, caption: 'OFB feeds the cipher its own output: keystream block 2 = Eₖ(keystream block 1) = fe104c88…. The message never enters the chain.' },
      { predict: { q: 'Which of the two can compute its whole keystream before the message is known?', options: ['CFB', 'OFB', 'Both', 'Neither'], answer: 1, explain: 'OFB\'s keystream depends only on the key and the IV. CFB\'s next keystream block is the encryption of the last ciphertext block, which does not exist until that plaintext has arrived.' } },
      { topic: 'modes-ofb', frame: 5, caption: 'In OFB a flipped ciphertext bit flips just that plaintext bit; and reusing an IV repeats the whole keystream, as with a reused one-time pad.' },
      { h: 'Recap' },
      { list: ['CFB: Cᵢ = Pᵢ ⊕ Eₖ(Cᵢ₋₁); it resynchronises after an error.', 'OFB: Oᵢ = Eₖ(Oᵢ₋₁), Cᵢ = Pᵢ ⊕ Oᵢ; the keystream can be made in advance.', 'Neither needs padding or the decryption direction; neither gives integrity; an IV must not repeat under one key.'] },
      X('mo-x-ofb-cfb'),
    ],
  });

  lesson({
    id: 'mo-ctr', chapter: 'mo-stream', title: 'CTR: counter mode', minutes: 8,
    summary: 'Counter mode encrypts successive counter blocks and XORs them with the plaintext. Nothing is chained, so every block can be done in parallel or reached directly. The one rule: a counter value must never be used twice under the same key.',
    blocks: [
      'OFB makes a keystream but one block at a time, each waiting for the last. What if the inputs to the cipher were simply numbered, 1, 2, 3, …?',
      { topic: 'modes-ctr', frame: 1, caption: 'Block 1: the counter 5f1a7c3e9b2d4f600000000000000000 is encrypted to c57fe134…, the first keystream block.' },
      { topic: 'modes-ctr', frame: 3, caption: 'Block 2 uses the counter plus one, …0001. The counter is incremented as one 128-bit number.' },
      { predict: { q: 'To decrypt only block 1000000 of a large file, how many calls of the block cipher are needed?', options: ['1', '1000000', '999999', 'Half a million on average'], answer: 0, explain: 'Its counter is start + 999999, worked out with one addition. One encryption gives its keystream block, and one XOR its plaintext.' } },
      { topic: 'modes-ctr', frame: 9, caption: 'Block 1000000: counter start + 999999 = …000f423f, keystream d11678cb…, in one call of Eₖ.' },
      { topic: 'modes-ctr', frame: 7, caption: 'No block waited for another: all three Eₖ calls could run at once, and the keystream could be made before the message existed.' },
      { h: 'The rule' },
      'The keystream depends only on the key and the counter values. If two messages ever use the same counter value under the same key, their keystream blocks are equal and the XOR of the two ciphertexts is the XOR of the two plaintexts: the key drops out. So a design must make counter ranges disjoint: a fresh nonce in the high bits for every message, and a block counter in the low bits that cannot run into the next message\'s range.',
      T('integrity-nonce', { topic: 'integrity-nonce', frame: 2, caption: 'Two messages under one key and one nonce: C₁ ⊕ C₂ = P₁ ⊕ P₂, and the key has dropped out. The zero bytes mark where the messages agree.' }),
      { h: 'Recap' },
      { list: ['CTR: Cᵢ = Pᵢ ⊕ Eₖ(counterᵢ), with the counter incremented as one big number.', 'Fully parallel, random access, no padding, only the encryption direction.', 'Never repeat a counter value under one key: nonce in the high bits, block counter in the low bits.'] },
      X('mo-x-ctr-inc'), X('mo-x-ctr-xor'), X('mo-x-ctr-far'), X('mo-x-code-ctrinc'), X('mo-x-code-ctr'), X('mo-x-parallel'),
    ],
  });

  // =========================================================================================================
  // Chapter 3: disks and authenticated encryption
  // =========================================================================================================
  lesson({
    id: 'mo-xts', chapter: 'mo-ae', title: 'XTS: encrypting a disk sector', minutes: 7,
    summary: 'A disk has no room for an IV and must encrypt each sector in place, to exactly its own size. XTS uses the sector number as a tweak, encrypted under a second key, and multiplies it by α for each block, so equal data in different places encrypts differently.',
    blocks: [
      'Disk encryption has unusual constraints: a 512-byte sector must stay 512 bytes, any sector must be readable on its own, and there is nowhere to store an IV. ECB would fit, but it shows repeated blocks. What can make each block\'s encryption depend on where it is?',
      { topic: 'modes-xts', frame: 1, caption: 'The sector number 7, as 16 little-endian bytes, is encrypted under K₂: T = c4198772…. The position on the disk is the tweak.' },
      { topic: 'modes-xts', frame: 2, caption: 'Block 1: XOR with T, encrypt under K₁, XOR with T again: C = Eₖ₁(P ⊕ T) ⊕ T.' },
      { topic: 'modes-xts', frame: 4, caption: 'Block 2 uses T·α: shift the 128-bit value left one bit, and since a bit fell off the top, XOR 87 into the first byte.' },
      { predict: { q: 'The same 16 bytes are written at block 1 of sector 7 and at block 1 of sector 8. Do the ciphertexts match?', options: ['Yes, the key is the same', 'No: the sector number changes T', 'Only if the sectors are next to each other', 'Only for the first block'], answer: 1, explain: 'T = Eₖ₂(sector number) differs for every sector, so the same data encrypts differently. What XTS still reveals: rewriting a block at the same place with the same data gives the same ciphertext, since there is no IV.' } },
      { topic: 'modes-xts', frame: 10, caption: 'The sector ends with 15 bytes. Ciphertext stealing borrows from the previous block, so the ciphertext is exactly 47 bytes, like the data.' },
      { warn: 'XTS gives no integrity. Someone with access to the disk can replace a sector with an older copy of itself, or garble a block without being noticed. It is the right mode for a disk, not for a message.' },
      { h: 'Recap' },
      { list: ['XTS: Cⱼ = Eₖ₁(Pⱼ ⊕ T·αʲ) ⊕ T·αʲ, with T = Eₖ₂(sector number).', 'Equal data in different places encrypts differently; no IV is stored; the size is unchanged.', 'No integrity: use it for storage at rest, not for messages.'] },
      X('mo-x-xts-alpha'), X('mo-x-xts-why'),
    ],
  });

  lesson({
    id: 'mo-gcm', chapter: 'mo-ae', title: 'GCM: CTR plus GHASH', minutes: 9,
    summary: 'GCM encrypts with CTR and computes a 16-byte tag over the associated data and the ciphertext with GHASH, multiplication by a hash key H in GF(2¹²⁸). The receiver checks the tag before it releases any plaintext.',
    blocks: [
      'Every mode so far hides the message but lets anyone change it unnoticed. A message to a bank, a firmware update or a cookie needs more: the receiver must know it has not been altered. Can secrecy and integrity come from one key, in one pass?',
      { topic: 'modes-gcm', frame: 1, caption: 'The hash key is H = Eₖ(0¹²⁸) = 96d7f5b8…, the encryption of an all-zero block.' },
      { topic: 'modes-gcm', frame: 2, caption: 'A 96-bit IV becomes J0 by appending 00000001. J0 is kept for the tag; the data uses J0 + 1, J0 + 2, …' },
      { topic: 'modes-gcm', frame: 3, caption: 'Block 1 is plain CTR: Eₖ(…00000002) XOR P₁ gives C₁ = df614e4d….' },
      { topic: 'modes-gcm', frame: 5, caption: 'GHASH starts with the associated data, “dock 4”: Y = (Y ⊕ A₁)·H. Associated data is authenticated but not encrypted, like a packet header.' },
      { topic: 'modes-gcm', frame: 8, caption: 'The last GHASH block holds the lengths in bits, 48 and 208, so data cannot be moved between the associated data and the ciphertext.' },
      { predict: { q: 'GHASH is linear in the data. What stops an attacker from adjusting a tag after changing the ciphertext?', options: ['Nothing; GCM tags can be forged', 'H is secret, and the GHASH result is masked with Eₖ(J0), new for every IV', 'The tag is encrypted with RSA', 'The tag is 128 bits long, so it cannot be computed'], answer: 1, explain: 'Without the key, H and Eₖ(J0) are unknown, and a tag that passes can only be guessed. If an IV is ever reused, though, the two masks cancel and H can be solved for: then forging becomes possible. This is why the nonce rule matters even more in GCM than in CTR.' } },
      { topic: 'modes-gcm', frame: 9, caption: 'The tag is GHASH ⊕ Eₖ(J0) = b014f5f2…. The receiver recomputes it, compares in constant time, and decrypts only if it matches.' },
      { bench: 'cipher', state: { algo: 'aes128', mode: 'gcm', view: 'mode' }, text: 'Encrypt with GCM, then change one byte of the ciphertext or the associated data and watch the tag check fail.' },
      { h: 'Recap' },
      { list: ['GCM = CTR encryption + GHASH tag over the associated data, the ciphertext and their lengths.', 'H = Eₖ(0); tag = GHASH ⊕ Eₖ(J0).', 'Verify the tag first; release nothing if it fails.', 'A nonce must never repeat under one key: a repeat leaks the XOR of the messages and lets tags be forged.'] },
      X('mo-x-gcm-j0'), X('mo-x-gcm-len'), X('mo-x-gcm-nonce'),
    ],
  });

  lesson({
    id: 'mo-integrity', chapter: 'mo-ae', title: 'Encryption is not integrity', minutes: 9,
    summary: 'A ciphertext in CTR or CBC can be changed in transit and still decrypts to something. Integrity needs a tag the receiver checks before using anything: an AEAD mode such as GCM, or encrypt-then-MAC with an independent key. And under one key, a nonce is used once.',
    blocks: [
      'Encrypting a message keeps it secret. Does it also keep it unchanged? It is tempting to think that nobody can make a meaningful change without the key.',
      T('integrity-malleable', { topic: 'integrity-malleable', frame: 3, caption: 'A message in CTR mode, “Pay Rowan 100 coins”, has one ciphertext bit flipped on the way. The receiver reads “Pay Rowan 900 coins”: CTR decryption cannot fail, so nothing tells it.' }),
      T('integrity-malleable', { topic: 'integrity-malleable', frame: 5, caption: 'The same change under GCM: the recomputed tag differs in all 16 bytes, and the message is rejected with no plaintext released.' }),
      { predict: { q: 'A system encrypts with AES-CBC and checks no tag. Its decryption code answers “bad padding” and “bad request” with two different error messages. Why is this a known danger?', options: ['It is not; error messages are harmless', 'It is the setting of the padding-oracle attack: by watching which error comes back, an attacker can decrypt messages without the key', 'It slows the server down', 'It reveals the key length'], answer: 1, explain: 'Distinguishable padding errors have been used to decrypt CBC traffic in real systems. The cure is not to hide the error better, but to check a tag over the ciphertext first, so altered ciphertexts are rejected before padding is ever looked at.' } },
      { h: 'Encrypt-then-MAC' },
      'When a mode without a tag must be used, add a MAC computed **over the ciphertext** (and the IV and any header), with a key independent of the encryption key. The receiver checks the MAC first, in constant time, and decrypts only if it passes. The other orders, MAC-then-encrypt and encrypt-and-MAC, have each led to real attacks: they make the receiver decrypt, or reveal something about the plaintext, before it knows the message is genuine.',
      { table: [['Order', 'What is sent', 'Verdict'], ['Encrypt-then-MAC', 'C, MAC(C)', 'Recommended: check before decrypting'], ['MAC-then-encrypt', 'E(P ‖ MAC(P))', 'Must decrypt before checking: padding and timing leaks'], ['Encrypt-and-MAC', 'E(P), MAC(P)', 'The MAC of P may reveal equal messages']], caption: 'Three ways to combine a cipher and a MAC.' },
      T('integrity-order', { topic: 'integrity-order', frame: 4, caption: 'Encrypt-then-MAC: one ciphertext bit was flipped, and the HMAC over IV ‖ C now differs in all 32 bytes. The message is rejected with the MAC key alone: the block cipher has not run, and the padding was never looked at.' }),
      T('integrity-order', { topic: 'integrity-order', frame: 5, caption: 'A receiver that must decrypt first finds invalid padding and fails before any MAC is checked. If the two failures differ in message or in time, it has become a padding oracle.' }),
      T('integrity-order', { topic: 'integrity-order', frame: 6, caption: 'So: check the tag first, compare in constant time, and answer every failure with one and the same error after the same work.' }),
      T('integrity-nonce', { h: 'Never reuse a nonce' }),
      T('integrity-nonce', { topic: 'integrity-nonce', frame: 4, caption: 'A counter nonce never repeats, as long as its state survives restarts. Random 96-bit nonces collide with chance about q²/2⁹⁷; NIST limits one GCM key to 2³² messages with random nonces.' }),
      T('integrity-nonce', { topic: 'integrity-nonce', frame: 6, caption: 'A misuse-resistant mode such as AES-SIV survives a repeated nonce: it reveals only whether two messages are equal.' }),
      { h: 'Recap' },
      { list: ['Encryption alone is malleable: changed ciphertexts decrypt without complaint.', 'Use an AEAD mode (GCM), or encrypt-then-MAC with an independent key.', 'Check the tag first, in constant time, and release nothing if it fails; give one error for every failure.', 'Never reuse a nonce under one key; prefer counters whose state survives restarts.'] },
      X('mo-x-po-fix'), X('mo-x-etm-order'), X('mo-x-tag-first'), X('mo-x-nonce-rules'), X('mo-x-nonce-birthday'),
    ],
  });

  // =========================================================================================================
  // Chapter 4: padding, limits and choosing a mode
  // =========================================================================================================
  lesson({
    id: 'mo-pad', chapter: 'mo-use', title: 'Padding and ciphertext stealing', minutes: 7,
    summary: 'ECB and CBC need whole blocks. PKCS#7 adds k bytes of value k, always at least one; ISO/IEC 7816-4 adds 80 and zeros. Ciphertext stealing avoids padding by borrowing bytes from the previous block.',
    blocks: [
      'A 31-byte message does not fill two AES blocks. The sender must add something the receiver can recognise and remove, even when the message itself ends in odd-looking bytes. What rule works for every message?',
      { topic: 'modes-padding', frame: 1, caption: '“Three gulls on the harbour rail” is 31 bytes, 15 over a whole block: PKCS#7 adds one byte of 01.' },
      { predict: { q: 'A message is exactly 32 bytes, two whole blocks. How many bytes does PKCS#7 add?', options: ['0', '1', '16', '32'], answer: 2, explain: 'A whole block of 16 bytes of value 10. Padding is always added, so the receiver can always remove it: otherwise a message that happened to end in 01 would be ambiguous.' } },
      { topic: 'modes-padding', frame: 2, caption: 'Removing it: read the last byte k and check that the last k bytes all hold k. A receiver must not tell anyone whether this check failed, apart from failing as a whole.' },
      { topic: 'modes-padding', frame: 3, caption: 'ISO/IEC 7816-4 marks the end with one 1 bit: the byte 80, then zeros.' },
      { topic: 'modes-padding', frame: 5, caption: 'Ciphertext stealing (CS3) needs no padding: the ciphertext is 31 bytes, exactly as long as the message.' },
      { tip: 'Stream-like modes, CTR, CFB, OFB and GCM, need no padding at all: the keystream is simply cut to length.' },
      { h: 'Recap' },
      { list: ['PKCS#7: add k = n − (len mod n) bytes of value k, between 1 and n.', 'ISO/IEC 7816-4: add 80, then zeros.', 'Ciphertext stealing keeps the length; stream-like modes never pad.', 'Check padding only after the tag has been verified.'] },
      X('mo-x-pkcs7'), X('mo-x-iso'), X('mo-x-unpad-valid'), X('mo-x-code-pad'), X('mo-x-code-unpad'),
    ],
  });

  lesson({
    id: 'mo-limits', chapter: 'mo-use', title: 'Key length, block size and their limits', minutes: 8,
    summary: 'Key length sets the cost of exhaustive search; block size sets how much data one key can safely encrypt. After about 2^(n/2) blocks of n bits, equal ciphertext blocks become likely and start to leak. For 64-bit blocks that is tens of gigabytes: the Sweet32 attack.',
    blocks: [
      'AES-128 cannot be searched. But 3DES, with 112-bit keys, was retired in practice by an attack that never touched the key. What did it exploit?',
      { topic: 'modes-keysearch', frame: 1, caption: 'Searching keys: 40-bit and 56-bit keys fall in under a second at 10¹⁸ keys a second. DES was retired for this.' },
      { topic: 'modes-keysearch', frame: 3, caption: 'AES-128 needs 10¹² years, AES-256 10⁵¹. Every extra bit doubles the work.' },
      { topic: 'modes-keysearch', frame: 4, caption: 'The second limit: under one key, q blocks of n bits contain a repeated ciphertext block with chance about 1 − e^(−q²/2^(n+1)). In CBC a repeat leaks the XOR of two plaintext blocks.' },
      { predict: { q: 'With 64-bit blocks, about how many blocks make a repeat likely?', options: ['2⁶⁴', '2³²', '2¹⁶', '64²'], answer: 1, explain: 'The birthday bound: about 2^(n/2) = 2³² blocks, which is 32 GiB of 8-byte blocks. A long HTTPS session can carry that much.' } },
      { topic: 'modes-keysearch', frame: 5, caption: 'With 64-bit blocks, 32 GiB already gives a chance of 0.39. With AES\'s 128-bit blocks the same point is 2⁶⁴ blocks, far beyond any session.' },
      { h: 'Recap' },
      { list: ['Exhaustive search: 2^(n−1) trials on average for an n-bit key.', 'Birthday bound: rekey well before 2^(n/2) blocks under one key.', '64-bit block ciphers (3DES, Blowfish) are unsafe for bulk data; use AES.'] },
      X('mo-x-birthday'), X('mo-x-sweet32'), X('mo-x-aes-limit'),
    ],
  });

  lesson({
    id: 'mo-choose', chapter: 'mo-use', title: 'Choosing a mode', minutes: 6,
    summary: 'Messages and network traffic: an AEAD mode, usually GCM. Disks: XTS. ECB: never for data. CBC, CFB, OFB and CTR alone only inside a construction that adds a MAC. The table below is the whole decision.',
    blocks: [
      'Every mode in this part is correct for something. Faced with a real design, which one should you pick, and what must come with it?',
      { table: [['Job', 'Mode', 'What must come with it'], ['Messages, network traffic, files sent elsewhere', 'GCM (an AEAD mode)', 'A nonce that never repeats under the key; reject on a bad tag'], ['A disk or a partition, sector by sector', 'XTS', 'Two independent keys; no integrity, so not for messages'], ['A legacy system that has only a block cipher and a MAC', 'CTR or CBC, then a MAC over the ciphertext', 'Independent keys; check the MAC first'], ['Wrapping a single random key', 'A key-wrap mode (or ECB on one block)', 'Never ECB for more than one block of data'], ['A cipher with 64-bit blocks', 'Avoid', 'If unavoidable, rekey well before 2³² blocks']], caption: 'Which mode for which job.' },
      { topic: 'modes-ecb', frame: 4, caption: 'The first rule of the table: ECB shows which blocks are equal. Whatever is chosen must use an IV or a nonce, so equal messages and equal blocks never look alike.' },
      { predict: { q: 'A team needs to send sensor readings over a radio link and wants both secrecy and protection against changes. Which is the right choice?', options: ['AES-ECB', 'AES-CBC with a random IV', 'AES-GCM with a counter nonce kept in non-volatile memory', 'AES-XTS with the reading number as the sector'], answer: 2, explain: 'Only GCM here gives integrity. The counter nonce must survive a power cut, or a reboot would repeat it.' } },
      { bench: 'cipher', state: { algo: 'aes128', mode: 'gcm', view: 'mode' }, text: 'Try each mode on the same message and compare what comes out.' },
      { h: 'Recap' },
      { list: ['Default: an AEAD mode such as GCM.', 'Disks: XTS.', 'Never ECB for data, never a mode without a tag where changes matter, never a nonce twice.'] },
      X('mo-x-choose-stream'), X('mo-x-choose-auth'), X('mo-x-misuse-review'),
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
