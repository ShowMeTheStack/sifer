// Part 13, MACs, key establishment and protocols: the chapters and the lessons. The exercises are in 131-mac-ex.js
// and the CTF challenges, the tour and the course in 132-mac-ctf.js. Each lesson opens with a question, runs a topic
// at a frame chosen for the point being made, asks for a prediction, sums up, and leads to its exercises. Every value
// quoted in a caption is what the topic's engine (S.MAC, S.Proto) computes for that input.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('mc-game')) return;
  const X = (id) => ({ exercise: id });

  C.chapter({ id: 'mc-mac', part: 'protocols', n: 1, title: 'Message authentication codes', blurb: 'The forgery game, HMAC’s two nested hashes, CBC-MAC and why it needs one fixed length, CMAC’s subkeys, and the polynomial MACs GMAC and Poly1305.' });
  C.chapter({ id: 'mc-aead', part: 'protocols', n: 2, title: 'Authenticated encryption and key derivation', blurb: 'Encrypt and authenticate in one sealed operation, and turn one shared secret into as many independent keys as a protocol needs.' });
  C.chapter({ id: 'mc-kdc', part: 'protocols', n: 3, title: 'Key distribution with a trusted server', blurb: 'Needham–Schroeder, the replay of an old ticket and its repair, and Kerberos tickets with timestamps.' });
  C.chapter({ id: 'mc-pki', part: 'protocols', n: 4, title: 'Diffie–Hellman, certificates and TLS 1.3', blurb: 'A key from public messages, the man in the middle, signatures and certificate chains that stop him, and the TLS 1.3 handshake that puts it all together.' });

  // =========================================================================================================
  // Chapter 1: message authentication codes
  // =========================================================================================================
  C.lesson({
    id: 'mc-game', chapter: 'mc-mac', title: 'What a MAC must do', minutes: 7,
    summary: 'A MAC gives a short tag computed from a secret key and a message. It is secure if a forger who may ask for tags of any messages it likes still cannot produce a valid tag on a new one. Short tags, keyless hashes, secret-prefix hashes and leaky comparisons all fail that game.',
    blocks: [
      'Encryption hides a message; it does not stop someone from changing it. A bank receiving “amount=50&to=wren” wants to know that this, exactly, is what the account holder sent. What does a tag have to withstand to give that assurance?',
      { def: 'Existential unforgeability under chosen-message attack', text: 'the forger may ask for the tag of any messages it chooses and may ask whether tags are valid; it wins if it outputs a valid tag on any message it never asked about. A secure MAC makes winning infeasible.' },
      { topic: 'p13-macgame', frame: 3, caption: 'The forger has seen three tags of messages it chose. The target is “amount=9000&to=mallory”.' },
      { topic: 'p13-macgame', frame: 4, caption: 'HMAC-SHA256: a random tag and a tag of another message are both rejected. No forgery.' },
      { predict: { q: 'The same game with HMAC-SHA256 cut to its first 8 bits. How does the forger do?', options: ['It cannot win: HMAC is secure', 'It tries tags until one is accepted, at most 256 tries', 'It needs the key', 'It needs about 2¹²⁸ tries'], answer: 1, explain: 'Truncation does not weaken the function, but a t-bit tag can always be guessed in about 2ᵗ tries. Real tags are at least 64 bits, usually 128.' } },
      { topic: 'p13-macgame', input: { mac: 'trunc', key: 'harbour-key-31' }, frame: 4, caption: 'With an 8-bit tag, the tag 0c is accepted after 13 verification queries.' },
      { topic: 'p13-macgame', input: { mac: 'keyless', key: 'harbour-key-31' }, frame: 4, caption: 'With no key, a “MAC” is just a hash: the forger computes SHA-256 of its own message and is accepted at once.' },
      { topic: 'p13-macgame', input: { mac: 'prefix', key: 'harbour-key-31' }, frame: 4, caption: 'SHA-256(key ‖ m): the tag is the hash’s whole state, so the forger carries on from the third tag and is accepted on the first try.' },
      { topic: 'p13-macgame', input: { mac: 'leaky', key: 'harbour-key-31' }, frame: 4, caption: 'HMAC compared byte by byte, stopping at the first difference: timing reveals the tag one byte at a time, in 403 queries instead of about 2³².' },
      { h: 'Recap' },
      { list: ['A MAC must resist forgery even after the forger sees tags of messages it chose.', 'Tags must be long (64 bits at least), keyed, and built from a sound construction such as HMAC.', 'Compare tags in constant time.'] },
      X('mc-x-game'), X('mc-x-tag-guess'), X('mc-x-leaky'),
    ],
  });

  C.lesson({
    id: 'mc-hmac', chapter: 'mc-mac', title: 'HMAC: two nested hashes', minutes: 8,
    summary: 'HMAC pads the key to a block, XORs it with 36 bytes for an inner hash of the message, and with 5c bytes for an outer hash of that digest. It works with any hash, and length extension cannot touch it.',
    blocks: [
      'SHA-256(key ‖ m) falls to length extension; SHA-256(m ‖ key) has its own problems with collisions. How do you build a sound MAC from a hash function, using only the hash as a black box?',
      { math: 'K′ = key padded with zeros to the block size (hashed first if longer than a block)\nHMAC(K, m) = H( (K′ ⊕ opad) ‖ H( (K′ ⊕ ipad) ‖ m ) )\nipad = 36 36 … 36,   opad = 5c 5c … 5c   (one block each)' },
      { topic: 'p13-hmac', frame: 0, caption: 'The 14-byte key is padded with zeros to the block size, 64 bytes: K′.' },
      { topic: 'p13-hmac', frame: 1, caption: 'K′ ⊕ ipad: every byte XORed with 36. The zero bytes become 36 themselves.' },
      { predict: { q: 'A key byte is 68 (“h”). What does it become in K′ ⊕ opad?', options: ['68', '5e', '34', 'a4'], answer: 2, explain: '68 ⊕ 5c = 34. In K′ ⊕ ipad the same byte is 68 ⊕ 36 = 5e: the two key blocks differ in every byte, because 36 ⊕ 5c = 6a.' } },
      { topic: 'p13-hmac', frame: 2, caption: 'Inner hash: SHA-256((K′ ⊕ ipad) ‖ message) = 616efec2…. The key block fills exactly one block, so the message starts on a block boundary.' },
      { topic: 'p13-hmac', frame: 4, caption: 'Outer hash of the 32-byte inner digest under K′ ⊕ opad: the tag 0c993548….' },
      { topic: 'p13-hmac', input: { key: 'Jefe', keyHex: '', msg: 'what do ya want for nothing?', hash: 'sha256' }, frame: 4, caption: 'RFC 4231 test case 2, the published vector: key “Jefe”, tag 5bdcc146….' },
      { tip: 'Why the outer hash defeats length extension: the tag is the state after hashing the opad block and a 32-byte digest. Extending it gives the hash of (K′ ⊕ opad) ‖ inner ‖ glue ‖ x, which is not the HMAC of any longer message.' },
      { bench: 'hash', state: { panel: 'hmac' }, text: 'The hash bench’s HMAC panel computes HMAC with any key and message, in text or hex, and shows both hashes.' },
      { h: 'Recap' },
      { list: ['K′ is the key padded to one block (hashed first if longer).', 'Inner: H((K′ ⊕ 36…) ‖ m); outer: H((K′ ⊕ 5c…) ‖ inner).', 'Secure if the compression function is a pseudorandom function; immune to length extension.'] },
      X('mc-x-ipad'), X('mc-x-code-hmac'),
    ],
  });

  C.lesson({
    id: 'mc-cbcmac', chapter: 'mc-mac', title: 'CBC-MAC and CMAC', minutes: 8,
    summary: 'CBC-MAC encrypts the message in CBC mode from a zero IV and keeps the last block. It is secure for messages of one fixed length, but when lengths vary two tags let anyone make a valid tag on a longer message. CMAC fixes this by masking the last block with a subkey derived from the key.',
    blocks: [
      'A device has AES in hardware and nothing else. Can it make a MAC from AES alone? Chain the blocks as CBC does and keep the last one. What could go wrong?',
      { topic: 'p13-cbcmac', frame: 0, caption: 'The tag of m1, “pay 10 to wren”: t1 = c1fdf8e0…. Each block is XORed with the previous output and encrypted; the tag is the last output.' },
      { topic: 'p13-cbcmac', frame: 1, caption: 'And the tag of m2: t2 = 6440ef5a…. Tags on chosen messages, and a verifier that accepts more than one length: the preconditions.' },
      { predict: { q: 'Each CBC-MAC tag is the chain’s final state, the value a longer message would carry on from. With two tags in hand and lengths allowed to vary, can someone without the key make a valid tag on a message never tagged?', options: ['No: every tag needs the key', 'Yes', 'Only by guessing the tag', 'Only if the messages are equal'], answer: 1, explain: 'A tag that is also a starting point lets a chain be continued without the key, so a longer message gets a valid tag. That is why plain CBC-MAC is only for one fixed length.' } },
      { topic: 'p13-cbcmac', frame: 2, caption: 'The outcome: a valid CBC-MAC tag on a three-block message the key holder never tagged, made without the key.' },
      { topic: 'p13-cbcmac', frame: 3, caption: 'The fixes: CMAC’s subkey on the last block, a length prefix, or encrypting the final value under a second key (EMAC).' },
      { topic: 'p13-cbcmac', input: { key: 'lantern-key-0042', m1: 'pay 10 to wren', m2: 'pay 9000 to mallory, ok', mac: 'cmac' }, frame: 2, caption: 'The same messages under CMAC: t1 came out of a block masked with a subkey, so it is not the chain’s state, and the attempt is rejected.' },
      { h: 'CMAC’s subkeys' },
      { math: 'L = AES_K(0¹²⁸)\nK1 = L·x,  K2 = K1·x   in GF(2¹²⁸): shift left one bit; if a bit fell off, XOR 87 into the last byte\nlast block complete → XOR K1;  last block partial → pad with 80 00 … and XOR K2' },
      { topic: 'p13-cmac', frame: 1, caption: 'RFC 4493: L = 7df76b0c…; its top bit is 0, so K1 = L shifted left: fbeed618….' },
      { topic: 'p13-cmac', frame: 2, caption: 'K2 = K1·x: K1’s top bit is 1, so after the shift 87 is XORed into the last byte: f7ddac30….' },
      { topic: 'p13-cmac', frame: 5, caption: 'The RFC 4493 one-block example: the tag 070a16b4…, the published value.' },
      { h: 'Recap' },
      { list: ['CBC-MAC: CBC from a zero IV, keep the last block. Safe only for messages of one fixed length.', 'Its tag is the chain’s final state, so with lengths free two tags give a valid tag on a longer message.', 'CMAC masks the last block with K1 or K2 (doublings of AES_K(0)), and works for any length.'] },
      X('mc-x-cmac-why'), X('mc-x-cmac-last'), X('mc-x-dbl'), X('mc-x-cmac-subkeys'),
    ],
  });

  C.lesson({
    id: 'mc-poly', chapter: 'mc-mac', title: 'Polynomial MACs: GMAC and Poly1305', minutes: 9,
    summary: 'GMAC and Poly1305 treat the message blocks as coefficients of a polynomial and evaluate it at a secret point: H in GF(2¹²⁸), or r modulo 2¹³⁰ − 5. A one-time mask hides the value. They are very fast, and they collapse if a key or nonce is ever reused.',
    blocks: [
      'HMAC needs two hash calls and CMAC one AES call per block. A server sealing gigabytes per second wants something cheaper: one multiplication per block. Is that enough for a MAC?',
      { topic: 'p13-gmac', frame: 1, caption: 'GMAC: block 1 of the data is XORed into the accumulator and the sum multiplied by H in GF(2¹²⁸).' },
      { topic: 'p13-gmac', frame: 4, caption: 'GHASH is a polynomial in H with the blocks as coefficients; the tag masks it with AES_K(J0) = 3bda2f72….' },
      { topic: 'p13-gmac', frame: 5, caption: 'Never reuse an IV: two tags under one IV share the mask, so their XOR is a known polynomial in H, and its roots give H.' },
      { h: 'Poly1305' },
      { math: 'r = first 16 key bytes (little-endian), clamped;  s = last 16 bytes\nfor each 16-byte chunk:  n = chunk (little-endian) + 2^(8·len)\n                         acc = (acc + n) · r  mod 2¹³⁰ − 5\ntag = (acc + s) mod 2¹²⁸, as 16 little-endian bytes' },
      { topic: 'p13-poly1305', frame: 1, caption: 'RFC 8439, section 2.5.2: clamping clears the top 4 bits of bytes 3, 7, 11 and 15 and the low 2 bits of bytes 4, 8 and 12: r = 806d5400e52447c036d555408bed685.' },
      { topic: 'p13-poly1305', frame: 3, caption: 'Chunk 1, “Cryptographic Fo”, read little-endian with a 01 byte on top: n = 16f4620636968706172676f7470797243. acc = (0 + n)·r mod 2¹³⁰ − 5.' },
      { predict: { q: 'The last chunk of the RFC message is “up”, only 2 bytes. Where does the extra 1 go?', options: ['At byte 16, as for full chunks', 'Just above the 2 bytes, at byte 2: n = 0x017075', 'Nowhere: short chunks get none', 'At the bottom'], answer: 1, explain: 'The 1 goes just above the chunk’s own bytes, so “up” and “up\\0” give different n. Here n = 017075: “u” = 75, “p” = 70, then 01.' } },
      { topic: 'p13-poly1305', frame: 5, caption: 'Chunk 3 is “up”: n = 17075.' },
      { topic: 'p13-poly1305', frame: 6, caption: 'tag = (acc + s) mod 2¹²⁸ = a8061dc1305136c6c22b8baf0c0127a9, the published value.' },
      { warn: 'Poly1305 is a one-time MAC: two messages under the same (r, s) let anyone solve for r. In ChaCha20-Poly1305 every nonce gives a fresh one-time key, so a nonce must never repeat under one key.' },
      { h: 'Recap' },
      { list: ['GMAC: a polynomial in H = AES_K(0) over GF(2¹²⁸), masked by AES_K(J0).', 'Poly1305: a polynomial in clamped r modulo 2¹³⁰ − 5, plus s.', 'Both are one-time per (key, nonce): a repeated nonce gives away the hash key.'] },
      X('mc-x-poly-n'), X('mc-x-clamp'), X('mc-x-code-poly'), X('mc-x-onetime'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: authenticated encryption and key derivation
  // =========================================================================================================
  C.lesson({
    id: 'mc-aead', chapter: 'mc-aead', title: 'Authenticated encryption', minutes: 7,
    summary: 'An AEAD seals a plaintext and some associated data under a key and a nonce: the plaintext is encrypted, both are authenticated, and opening rejects anything changed before decrypting a byte. ChaCha20-Poly1305 derives a fresh Poly1305 key per nonce and MACs the ciphertext.',
    blocks: [
      'With a cipher and a MAC in hand, there are three ways to combine them: MAC the plaintext and encrypt both, encrypt and MAC the plaintext alongside, or encrypt and then MAC the ciphertext. Only one is safe in general. Which, and why do modern protocols use a single combined primitive instead?',
      { table: [['Composition', 'What is sent', 'Verdict'], ['MAC-then-encrypt', 'E(m ‖ MAC(m))', 'Must decrypt before checking: padding and error oracles'], ['Encrypt-and-MAC', 'E(m), MAC(m)', 'The tag of m leaks equality of plaintexts'], ['Encrypt-then-MAC', 'c = E(m), MAC(c)', 'Secure: check the tag first, decrypt only if it passes']], caption: 'Generic composition, with independent keys for the cipher and the MAC.' },
      { topic: 'p13-aead', frame: 0, caption: 'ChaCha20 block 0 under the key and nonce gives a one-time Poly1305 key; a new nonce means a new r and s.' },
      { topic: 'p13-aead', frame: 2, caption: 'Poly1305 covers the associated data and the ciphertext, each padded to 16 bytes, then both lengths.' },
      { topic: 'p13-aead', frame: 3, caption: 'The tag 9a7828c6…. The associated data travels in the clear: authenticated, not encrypted.' },
      { predict: { q: 'One bit of the ciphertext is flipped on the way. What does the receiver do?', options: ['Decrypts, and one bit of the plaintext is wrong', 'Recomputes the tag, finds it differs, and rejects before decrypting', 'Decrypts and then checks the tag', 'Asks for the key again'], answer: 1, explain: 'Opening recomputes Poly1305 over what arrived. The tags differ, and the message is rejected without any plaintext being released.' } },
      { topic: 'p13-aead', input: { tamper: 'ct' }, frame: 5, caption: 'The recomputed tag 2de6dffe… differs from 9a7828c6…: rejected before anything is decrypted.' },
      { topic: 'p13-aead', input: { tamper: 'aad' }, frame: 5, caption: 'Changing the associated data is caught the same way, though it was never encrypted.' },
      { h: 'Recap' },
      { list: ['Encrypt-then-MAC with independent keys is the safe generic composition.', 'An AEAD seals (key, nonce, plaintext, associated data) into ciphertext and tag, and opens only if the tag verifies.', 'Nonces must not repeat under one key.'] },
      X('mc-x-compose'), X('mc-x-aad'), X('mc-x-nonce'),
    ],
  });

  C.lesson({
    id: 'mc-hkdf', chapter: 'mc-aead', title: 'HKDF: one secret, many keys', minutes: 7,
    summary: 'HKDF first extracts a uniform pseudorandom key from a lumpy secret with HMAC under a salt, then expands it into as many bytes as needed: T(i) = HMAC(PRK, T(i−1) ‖ info ‖ i). Different info strings give independent keys.',
    blocks: [
      'A Diffie–Hellman exchange leaves both sides with one shared value. It is not uniformly random (it is a group element), and a protocol needs several keys: one per direction, for encryption and for MACs. How do you get them all from one secret, safely?',
      { topic: 'p13-hkdf', frame: 1, caption: 'Extract: PRK = HMAC-SHA-256(salt, IKM) = 4f85f4bc…. However lumpy the input, the PRK is a uniform 32-byte key.' },
      { math: 'PRK  = HMAC(salt, IKM)\nT(0) = empty\nT(i) = HMAC(PRK, T(i−1) ‖ info ‖ i)      i = 1, 2, … as one byte\nOKM  = first L bytes of T(1) ‖ T(2) ‖ …   (L ≤ 255 · hash length)' },
      { topic: 'p13-hkdf', frame: 2, caption: 'T(1) = HMAC(PRK, info ‖ 01) = c439c575….' },
      { predict: { q: 'For T(2), what goes into HMAC as the message?', options: ['info ‖ 02', 'T(1) ‖ info ‖ 02', 'PRK ‖ info ‖ 02', 'T(1) ⊕ info'], answer: 1, explain: 'Each block feeds the next: T(2) = HMAC(PRK, T(1) ‖ info ‖ 02). The key is always the PRK.' } },
      { topic: 'p13-hkdf', frame: 3, caption: 'T(2) = HMAC(PRK, T(1) ‖ info ‖ 02) = 55164bfa….' },
      { topic: 'p13-hkdf', frame: 4, caption: 'The output is the first 42 bytes of T(1) ‖ T(2). Change the info and the keys are unrelated.' },
      { topic: 'p13-hkdf', input: { hex: 'hex', ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', salt: '000102030405060708090a0b0c', info: 'f0f1f2f3f4f5f6f7f8f9', L: 42, hash: 'sha256' }, frame: 4, caption: 'RFC 5869, test case 1: the output begins 3cb25f25 faacd57a, the published value.' },
      { h: 'Recap' },
      { list: ['Extract: PRK = HMAC(salt, IKM), a uniform key.', 'Expand: T(i) = HMAC(PRK, T(i−1) ‖ info ‖ i), concatenated and cut to L bytes.', 'The info string separates keys for different purposes.'] },
      X('mc-x-hkdf-blocks'), X('mc-x-hkdf-input'), X('mc-x-hkdf-t1'), X('mc-x-code-hkdf'),
    ],
  });

  // =========================================================================================================
  // Chapter 3: key distribution with a trusted server
  // =========================================================================================================
  C.lesson({
    id: 'mc-ns', chapter: 'mc-kdc', title: 'Needham–Schroeder and the replayed ticket', minutes: 9,
    summary: 'A trusted server shares a long-term key with each user and hands out session keys sealed in tickets. In the symmetric Needham–Schroeder protocol, Bob cannot tell a new ticket from an old one: if an old session key leaks, its ticket can be replayed. Putting Bob’s own nonce into the ticket repairs it.',
    blocks: [
      'A thousand users who each want a key with every other need about half a million keys. With a trusted server, each user keeps one key, shared with the server, and asks it for session keys. But a protocol over an open network must also prove that each message is fresh. Who checks what?',
      { topic: 'p13-ns', frame: 1, caption: '2. S → A: {Na, B, Kab, {Kab, A}Kbs}Kas. Only Alice can open this; inside is a ticket only Bob can open.' },
      { topic: 'p13-ns', frame: 2, caption: 'Alice checks her nonce Na: this reply is fresh, for her.' },
      { topic: 'p13-ns', frame: 3, caption: '3. A → B: {Kab, A}Kbs. Alice forwards the ticket she cannot read.' },
      { predict: { q: 'Bob receives the ticket {Kab, A}Kbs. What in it tells him the ticket is new?', options: ['The key Kab', 'Alice’s name', 'Nothing: it holds no value Bob chose or can check for freshness', 'The server’s signature'], answer: 2, explain: 'Alice’s nonce protects Alice. The ticket holds only Kab and A, so a ticket from months ago looks just as good to Bob. The handshake in messages 4 and 5 proves only that the other side knows Kab.' } },
      { topic: 'p13-ns', input: { scenario: 'replay' }, frame: 8, caption: 'Months later the old key K′ab leaks. Old keys are not meant to matter any more.' },
      { topic: 'p13-ns', input: { scenario: 'replay' }, frame: 9, caption: 'Eve replays the old message 3, the ticket {K′ab, A}Kbs.' },
      { topic: 'p13-ns', input: { scenario: 'replay' }, frame: 12, caption: 'Eve holds K′ab, so she answers Bob’s challenge. Bob accepts a key Eve knows, believing he talks to Alice.' },
      { topic: 'p13-ns', input: { scenario: 'fixed' }, frame: 3, caption: 'The repair: Bob first sends Alice a sealed nonce Jb for the server, and the server puts it into the ticket.' },
      { topic: 'p13-ns', input: { scenario: 'fixed-replay' }, frame: 4, caption: 'The replay now fails: the old ticket carries J′b, not the Jb Bob just issued.' },
      { bench: 'proto', state: { flow: 'ns-replay' }, text: 'The protocol bench steps through the replay with what each party knows after every message.' },
      { h: 'Recap' },
      { list: ['A key distribution centre turns n² pairwise keys into n long-term keys.', 'Every party needs its own evidence of freshness: a nonce it chose, or a timestamp it trusts.', 'Symmetric Needham–Schroeder gives Bob none, so a leaked old session key can be replayed.'] },
      X('mc-x-kdc-keys'), X('mc-x-ns-flaw'), X('mc-x-ns-fix'),
    ],
  });

  C.lesson({
    id: 'mc-kerberos', chapter: 'mc-kdc', title: 'Kerberos tickets', minutes: 7,
    summary: 'Kerberos splits the trusted server in two. The authentication server gives a ticket-granting ticket once per login; the ticket-granting server then issues a ticket for each service. Authenticators carry timestamps, so clocks must agree.',
    blocks: [
      'Typing a password for every file server, printer and mail server would be miserable, and keeping the password in memory all day would be risky. How can one login give access to many services, with the password used once?',
      { topic: 'p13-kerberos', frame: 0, caption: 'The client’s long-term key Kc is derived from the password; the password never crosses the network.' },
      { topic: 'p13-kerberos', frame: 2, caption: '2. AS → C: a session key for the TGS sealed under Kc, and the ticket-granting ticket sealed under the TGS’s key.' },
      { topic: 'p13-kerberos', frame: 4, caption: '3. C → TGS: the TGT plus an authenticator {C, T1}Kc,tgs, a fresh timestamp under the session key.' },
      { predict: { q: 'Why does the client send an authenticator with the ticket, rather than the ticket alone?', options: ['To make the message longer', 'The ticket can be copied off the network; only the holder of the session key can make a fresh authenticator', 'To carry the password', 'The TGS cannot open the ticket'], answer: 1, explain: 'A ticket is a sealed blob that anyone can record and resend. The authenticator proves knowledge of the session key and, with its timestamp, that the request is new.' } },
      { topic: 'p13-kerberos', frame: 6, caption: '4. TGS → C: a key for the service and a service ticket under Kv, which the client cannot read.' },
      { topic: 'p13-kerberos', frame: 10, caption: 'The service is genuine: it knew Kv. Timestamps, not nonces, stop replays, so clocks must agree.' },
      { bench: 'proto', state: { flow: 'kerberos' }, text: 'Step through the six messages on the protocol bench.' },
      { h: 'Recap' },
      { list: ['AS: password-derived key → ticket-granting ticket and a TGS session key.', 'TGS: TGT + authenticator → service ticket and a service session key.', 'Authenticators carry timestamps checked against a clock skew window.'] },
      X('mc-x-kerb-who'), X('mc-x-kerb-clock'),
    ],
  });

  // =========================================================================================================
  // Chapter 4: Diffie–Hellman, certificates and TLS 1.3
  // =========================================================================================================
  C.lesson({
    id: 'mc-dh', chapter: 'mc-pki', title: 'Diffie–Hellman and the man in the middle', minutes: 8,
    summary: 'Diffie–Hellman gives two parties a shared secret from public messages, against an eavesdropper. Against someone who can change messages it gives nothing: Mallory runs one exchange with each side. Signing the shares with long-term keys stops her.',
    blocks: [
      'Two strangers can agree on a key over an open line that everyone hears. That sounds like it solves key distribution. What does it leave out?',
      { topic: 'p13-dh', frame: 0, caption: 'The group: a 64-bit safe prime p and g = 4. Alice picks a, Bob picks b.' },
      { topic: 'p13-dh', frame: 4, caption: 'Both compute g^ab = 234f0b46733d8308 from public messages alone.' },
      { predict: { q: 'Mallory sits on the line and can change messages. She replaces g^a with her own g^m on its way to Bob, and g^b with g^m′ on its way to Alice. What does each side end up with?', options: ['The same key as before', 'Alice shares a key with Mallory, Bob shares another key with Mallory', 'No key: the exchange fails', 'Alice and Bob share a key Mallory cannot read'], answer: 1, explain: 'Each side runs a perfectly correct exchange, with the wrong party. Nothing in a share says who sent it.' } },
      { topic: 'p13-dh', input: { scenario: 'mitm', group: 'toy64' }, frame: 4, caption: 'Alice’s key 89b98855… is shared with Mallory; Bob’s 0f44bfe1… too. Alice and Bob share nothing.' },
      { topic: 'p13-dh', input: { scenario: 'mitm', group: 'toy64' }, frame: 8, caption: 'Mallory decrypts, rewrites “north gate at six” to “south gate at nine”, and re-encrypts. Bob’s tag check passes.' },
      { h: 'Signed shares' },
      { topic: 'p13-authdh', frame: 3, caption: 'Bob signs both shares and his name; Alice checks that the signature covers her own g^a.' },
      { topic: 'p13-authdh', input: { scenario: 'auth-mitm', group: 'toy64' }, frame: 6, caption: 'Against Mallory: the only signature she has from Bob covers (g^m, g^b), not (g^a, g^m′). Alice aborts.' },
      { bench: 'proto', state: { flow: 'mitm' }, text: 'Run the man in the middle on the protocol bench, then the signed exchange that catches her.' },
      { h: 'Recap' },
      { list: ['Diffie–Hellman resists eavesdroppers, not active attackers.', 'A man in the middle runs two exchanges and relays, reading and rewriting.', 'Signing both shares with long-term keys binds them to identities, if the public keys themselves are trusted.'] },
      X('mc-x-dh-pub'), X('mc-x-dh-toy'), X('mc-x-mitm'),
    ],
  });

  C.lesson({
    id: 'mc-certs', chapter: 'mc-pki', title: 'Certificates and chain validation', minutes: 9,
    summary: 'A certificate binds a name to a public key under a CA’s signature. A client validates a chain from the server certificate up to a root it already trusts, checking the name, the dates, each issuer, each signature, the CA flags and path lengths, and revocation.',
    blocks: [
      'Signed Diffie–Hellman needs each side to know the other’s public key in advance. A browser cannot know the key of every website. Whose word does it take, and how does it check it?',
      { topic: 'p13-certs', frame: 0, caption: 'The server sends its certificate and an intermediate; the client holds the root: www.harbourbank.example → Lantern Issuing CA 2 → Lantern Root CA.' },
      { topic: 'p13-certs', frame: 1, caption: 'Check 1: the name. The certificate names www.harbourbank.example; the client asked for www.harbourbank.example.' },
      { topic: 'p13-certs', frame: 4, caption: 'The signature on the server certificate verifies under the intermediate’s public key.' },
      { topic: 'p13-certs', frame: 6, caption: 'The intermediate signed a certificate, so it must be marked as a CA: it is.' },
      { topic: 'p13-certs', frame: 15, caption: 'The chain ends at a root in the trust store, with this very key.' },
      { predict: { q: 'Mallory copies every field of the bank’s certificate, puts in her own key, and signs it herself while naming the real CA as issuer. Which check stops her?', options: ['The name', 'The dates', 'The signature on the server certificate, under the issuing CA’s key', 'Nothing'], answer: 2, explain: 'Every field matches, but the signature was made with Mallory’s key, so it does not verify under the CA’s public key.' } },
      { topic: 'p13-certs', input: { scenario: 'fake', seed: 1 }, frame: 4, caption: 'The forged certificate: its signature does not verify under Lantern Issuing CA 2’s key.' },
      { topic: 'p13-certs', input: { scenario: 'leaf-as-ca', seed: 1 }, frame: 6, caption: 'A genuine signature from the bank’s own key on a certificate for another site: the bank’s certificate is not a CA, so the chain is rejected.' },
      { topic: 'p13-certs', input: { scenario: 'revoked-crl', seed: 1 }, frame: 6, caption: 'Serial 91e4 is on the CA’s revocation list: the bank’s key was stolen.' },
      { bench: 'proto', state: { flow: 'cert-self-made-root' }, text: 'The protocol bench lays out each chain certificate by certificate, for all eight scenarios.' },
      { h: 'Recap' },
      { list: ['Name, validity, issuer name, signature, CA flag and path length, for every link.', 'The chain must end at a root in the trust store with the same key, not just the same name.', 'Revocation by a signed list (CRL) or a signed online answer (OCSP).'] },
      X('mc-x-cert-expired'), X('mc-x-cert-root'), X('mc-x-cert-leaf'), X('mc-x-revocation'),
    ],
  });

  C.lesson({
    id: 'mc-tls', chapter: 'mc-pki', title: 'The TLS 1.3 handshake', minutes: 9,
    summary: 'TLS 1.3 puts everything together in one round trip: X25519 key shares in the hellos, a key schedule of HKDF calls, the server’s certificate chain, a signature over the transcript and a Finished MAC, then application data under fresh keys.',
    blocks: [
      'Opening a web page means a key exchange, server authentication and keys for both directions, before the first request. How does TLS 1.3 fit all of it into a single round trip, and what stops a man in the middle?',
      { topic: 'p13-tls', frame: 0, caption: '1. ClientHello: a random, the cipher suites, an X25519 key share and the server name.' },
      { topic: 'p13-tls', frame: 2, caption: 'After ServerHello both sides compute the X25519 secret and the handshake secret; everything after is encrypted.' },
      { topic: 'p13-tls', frame: 5, caption: 'CertificateVerify: a signature by the certificate’s key over the transcript so far.' },
      { topic: 'p13-tls', frame: 6, caption: 'Finished: an HMAC over the whole transcript under a key from the handshake secret.' },
      { predict: { q: 'Mallory swaps the server’s key share for her own. Which message gives her away?', options: ['ClientHello', 'ServerHello', 'CertificateVerify, which signs a transcript containing the real shares', 'None: TLS cannot detect it'], answer: 2, explain: 'The server signs the transcript, including both key shares. Mallory cannot produce that signature for her share without the server’s private key, and the certificate binds that key to the name.' } },
      { topic: 'p13-tls', input: { tamper: 'cert', seed: 1 }, frame: 7, caption: 'A forged certificate: chain validation fails, and the client aborts with an alert.' },
      { h: 'The key schedule' },
      { topic: 'p13-tls-keys', frame: 2, caption: 'Handshake secret = HKDF-Extract(derived, the X25519 secret): here the ephemeral Diffie–Hellman enters.' },
      { topic: 'p13-tls-keys', frame: 3, caption: 'Client handshake traffic secret = Derive-Secret(handshake, "c hs traffic", H(ClientHello ‖ ServerHello)).' },
      { topic: 'p13-tls-keys', frame: 10, caption: 'Application keys and IVs; each record’s nonce is the IV XORed with its sequence number.' },
      { topic: 'p13-tls-keys', input: { source: 'rfc' }, frame: 3, caption: 'The same schedule on the published RFC 8448 trace: the client handshake traffic secret b3eddb12….' },
      { bench: 'proto', state: { flow: 'tls13' }, text: 'Step through the handshake on the protocol bench, and tamper with the certificate, the Finished or a record.' },
      { h: 'Recap' },
      { list: ['Key shares in the hellos give one round trip; everything after ServerHello is encrypted.', 'The certificate binds a key to the name; CertificateVerify proves possession over this transcript; Finished MACs it all.', 'Every key comes from HKDF with its own label and transcript hash.'] },
      X('mc-x-tls-rtt'), X('mc-x-tls-keys'), X('mc-x-tls-label'), X('mc-x-tls-nonce'),
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
