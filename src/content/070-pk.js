// Part 7, introduction to public-key cryptography: the chapters and the lessons. The exercises, the part's tour and
// its course are in 071-pk-ex.js. The lessons start from the problem symmetric keys cannot solve (getting a secret to
// someone first), build up one-way functions and trapdoors, show the three jobs a key pair does, and end with key
// sizes and the question every public key raises: whose is it? Every number quoted was worked out by the engines
// (S.NT, S.RSA, S.DLP) or read off the topics' own narration for the inputs given.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('pk-keys')) return;
  const X = (id) => ({ exercise: id });

  C.chapter({ id: 'pk-why', part: 'pubkey', n: 1, title: 'Why asymmetric', blurb: 'The key-distribution problem, functions that are easy one way and hard the other, and the trapdoor that lets one person come back.' });
  C.chapter({ id: 'pk-use', part: 'pubkey', n: 2, title: 'What a key pair does', blurb: 'Encrypting to a public key, signing with a private one, agreeing a key in public, and hybrid encryption, which is how all three are used in practice.' });
  C.chapter({ id: 'pk-size', part: 'pubkey', n: 3, title: 'Key lengths and trust', blurb: 'Security levels, why a public key is many times longer than a symmetric key of the same strength, and why a public key is worth nothing until you know whose it is.' });

  // =========================================================================================================
  // Chapter 1: why asymmetric
  // =========================================================================================================
  C.lesson({
    id: 'pk-keys', chapter: 'pk-why', title: 'Too many keys: the distribution problem', minutes: 6,
    summary: 'With symmetric ciphers every pair of people needs its own secret key, delivered in secret before the first message: n(n − 1)/2 keys for n people. A key centre cuts the count but sees everything. Public keys need no secret delivery at all.',
    blocks: [
      'AES is fast and, with a 128-bit key, out of reach of any brute force. But it has one demand it cannot meet by itself: before Ana can write to Bo, both must already hold the same secret key, and that key must have reached them by some route nobody else could read. How many such keys does a group need, and who carries them?',
      { topic: 'p07-keydist', frame: 3, caption: 'Each newcomer needs a separate key with everyone already there. After four people, 6 keys, each of which had to be delivered in secret.' },
      { topic: 'p07-keydist', frame: 6, caption: 'Six people need n(n − 1)/2 = 15 keys, and each person keeps 5 of them. One more person would add 6 more.' },
      { predict: { q: 'A firm of 1,000 people wants every pair to be able to talk in private with symmetric keys. Roughly how many keys is that?', options: ['about 1,000', 'about 2,000', 'about 500,000', 'about 1,000,000,000'], answer: 2, explain: 'n(n − 1)/2 = 1000·999/2 = 499,500. The count grows with the square of n: double the firm and the keys roughly quadruple.' } },
      { h: 'A key centre' },
      'The classic remedy is a trusted centre. Each person shares one long-term key with it, and when two people want to talk the centre makes them a fresh session key and sends it to each under their long-term key. Kerberos, in part 13, works this way.',
      { topic: 'p07-keydist', frame: 7, caption: 'With a centre, six people need only six long-term keys. The price: the centre knows every key, must be online for every new conversation, and is the one place an attacker would go first.' },
      { h: 'Key pairs' },
      'Public-key cryptography removes the delivery altogether. Each person makes a pair of keys alone: a **private key** that never leaves them and a **public key** that may be printed in a directory. Anyone can use the public key to lock something only the private key can open.',
      { topic: 'p07-keydist', input: { n: 12, big: 1000000 }, frame: 15, caption: 'For a million people: 499,999,500,000 pairwise secret keys, against one million key pairs, none of which had to travel in secret.' },
      { tip: 'Public keys still have to reach the right people intact: a forged directory entry is as bad as a stolen key. That problem, authenticity, is the last lesson of this part.' },
      { h: 'Recap' },
      { list: ['Symmetric keys: n(n − 1)/2 secret keys for n people, each delivered in secret first.', 'A key centre needs only n keys, but it sees every session key and must always be online.', 'A key pair is made by its owner alone; only the public half is ever sent, and it need not be kept secret.'] },
      X('pk-x-pairs'), X('pk-x-new-member'), X('pk-x-keys-table'), X('pk-x-kdc'),
    ],
  });

  C.lesson({
    id: 'pk-oneway', chapter: 'pk-why', title: 'One-way functions', minutes: 7,
    summary: 'A one-way function is quick to compute and, as far as anyone knows, infeasible to undo. Multiplying two large primes and raising a generator to a power modulo a prime are the two used most; the gap between the forward and the backward work grows with the size of the numbers.',
    blocks: [
      'Multiplying 223 by 227 takes a few seconds with a pencil: 50621. Now go back: which two primes multiply to 50621? There is no column method for that. You try 2, 3, 5, 7, … and the first divisor appears only after 222 tries. Public-key cryptography is built on gaps like this one.',
      { def: 'One-way function', text: 'a function f where computing f(x) is fast, but finding any x with f(x) = y, for a y produced from a random x, is infeasible. No function has been proved one-way; these are believed to be because decades of effort have found no fast way back.' },
      { topic: 'p07-trapdoor', input: { fn: 'factor', size: 'real' }, frame: 1, caption: 'Forwards: one multiplication of two 1024-bit primes gives a 2048-bit n.' },
      { topic: 'p07-trapdoor', input: { fn: 'factor', size: 'real' }, frame: 2, caption: 'Backwards: the best method known, the number field sieve, needs about 2¹¹⁷ operations for a 2048-bit n.' },
      { h: 'Powers modulo a prime' },
      'The second candidate turns an exponent into a power. Fix a prime p and a generator g. Going from x to g^x mod p is square-and-multiply, a few dozen multiplications even for large x. Going back from g^x to x is the **discrete logarithm**, and part 9 is about how hard it is.',
      { topic: 'p07-trapdoor', input: { fn: 'dlog', size: 'toy' }, frame: 1, caption: 'Forwards: 2⁷⁷⁷ mod 1019 = 550 in 12 operations.' },
      { topic: 'p07-trapdoor', input: { fn: 'dlog', size: 'toy' }, frame: 2, caption: 'Backwards: baby-step giant-step needs 57 steps to find 777 again, and its cost grows with √p, while the forward work grows only with the number of bits.' },
      { predict: { q: 'The numbers double in length, from 1024 to 2048 bits. What happens to the work of the forward direction?', options: ['It doubles', 'It grows by about 8', 'It squares', 'It grows by 2¹⁰²⁴'], answer: 1, explain: 'Twice as many bits means twice as many squarings, and each multiplication of numbers twice as long costs about four times as much: 2·4 = 8. The best attacks grow far faster than that.' } },
      'Neither function above has a way back for anyone, not even for the person who chose x. That is enough for some jobs: Diffie–Hellman (part 9) and signatures need only a function nobody can invert. Encryption to a public key needs more, the subject of the next lesson.',
      { h: 'Recap' },
      { list: ['One-way: fast forwards, believed infeasible backwards; none is proved.', 'Multiplying primes (backwards: factoring) and modular powers (backwards: the discrete logarithm) are the two classic examples.', 'The forward work grows slowly with the size; the backward work grows much faster, so size buys security.'] },
      X('pk-x-oneway'), X('pk-x-dlog-small'), X('pk-x-trial'), X('pk-x-code-trial'),
    ],
  });

  C.lesson({
    id: 'pk-trapdoor', chapter: 'pk-why', title: 'Trapdoors: a way back for one person', minutes: 7,
    summary: 'A trapdoor one-way function is one-way for everybody except the holder of a secret, the trapdoor. RSA\'s function x ↦ x^e mod n is the standard example: anyone can compute it from (n, e), and only the holder of d can undo it.',
    blocks: [
      'To encrypt to someone, everyone must be able to go forwards, but one person, the receiver, must be able to come back. Neither multiplication nor modular powers on their own allow that. What is needed is a one-way function with a secret back door.',
      { def: 'Trapdoor one-way function', text: 'a one-way function that becomes easy to invert for whoever knows an extra secret, the trapdoor, which is made at the same time as the function.' },
      { topic: 'p07-trapdoor', frame: 0, caption: 'The RSA function for the toy public key n = 49163, e = 17: it takes x = 4321 to x¹⁷ mod n.' },
      { topic: 'p07-trapdoor', frame: 1, caption: 'Forwards: e = 17 = 10001 in binary, so 4 squarings and 1 multiplication give y = 15446.' },
      { topic: 'p07-trapdoor', frame: 2, caption: 'Without d the way back is to factor n. At this size trial division does it after 105 divisions; at 2048 bits it is the 2¹¹⁷ of the last lesson.' },
      { predict: { q: 'The owner of the key holds d = 25793. How does she undo y = 15446?', options: ['She factors n first', 'She computes y^d mod n', 'She computes the 17th root of y as an ordinary number', 'She cannot: nobody can'], answer: 1, explain: 'e·d ≡ 1 modulo φ(n), so (x^e)^d ≡ x. One more square-and-multiply, this time with the long exponent d, and x comes back. Part 8 shows why.' } },
      { topic: 'p07-trapdoor', frame: 3, caption: 'With the trapdoor: y^d mod n takes 19 operations and returns 4321.' },
      'The trapdoor is not a single number pulled from nowhere. The key owner chose the primes p and q, so she knows φ(n) = (p − 1)(q − 1) and can compute d as the inverse of e modulo φ(n). Everyone else sees only n, and to find φ(n) they would have to factor it.',
      { topic: 'p07-trapdoor', input: { fn: 'rsa', size: 'real' }, frame: 3, caption: 'At real size: with a 2048-bit key, d has 617 digits and coming back takes 3015 operations, still nothing for a computer, while going back without d costs about 2¹¹⁷.' },
      { bench: 'pk', state: { tool: 'rsa', rsa: { size: 'toy', p: '223', q: '227', e: '17', msgKind: 'number', msg: '3001', pad: 'textbook' } }, text: 'Make the toy key from 223 and 227 and send a number through it and back.' },
      { h: 'Recap' },
      { list: ['A trapdoor makes a one-way function easy to undo, but only for its holder.', 'RSA: forwards x ↦ x^e mod n for anyone; backwards y ↦ y^d mod n for the holder of d.', 'd comes from φ(n), and φ(n) from the factors p and q: whoever factors n has the trapdoor.'] },
      X('pk-x-trapdoor-def'), X('pk-x-forward'), X('pk-x-forward-ops'), X('pk-x-trapdoor-back'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: what a key pair does
  // =========================================================================================================
  C.lesson({
    id: 'pk-encrypt', chapter: 'pk-use', title: 'Encrypting to a public key', minutes: 6,
    summary: 'The sender locks the message with the receiver\'s public key; only the receiver\'s private key opens it. A message is turned into a number first, by reading its bytes as one big-endian integer, which must be smaller than the modulus.',
    blocks: [
      'Bob wants anyone at all to be able to send him a secret, including people he has never met, over a line Eve can read. With a trapdoor function that is simple: Bob publishes the forward direction and keeps the way back.',
      { topic: 'p07-uses', frame: 1, caption: 'Bob makes a key pair: n = 114857 and e = 17 are public, d = 13433 stays with him.' },
      { h: 'A message as a number' },
      'RSA works on numbers below n, so the text is read as one number: its bytes, in order, as the digits of a number in base 256. The two letters "pa" are the bytes 70 61, and 0x7061 = 112·256 + 97 = 28769.',
      { topic: 'p07-uses', frame: 3, caption: 'Alice locks m = 28769 with Bob\'s public key: c = m¹⁷ mod n = 69340.' },
      { predict: { q: 'Alice keeps a copy of c = 69340. Can she decrypt it later to check what she sent?', options: ['Yes, with the public key', 'Yes, with her own private key', 'No: only Bob\'s private key opens it'], answer: 2, explain: 'Locking used only Bob\'s public key. Undoing it needs d, which only Bob has; once sent, the ciphertext is closed even to its sender.' } },
      { topic: 'p07-uses', frame: 5, caption: 'Bob opens it: c^d mod n = 28769, "pa" again.' },
      { warn: 'This is textbook RSA, as the picture of the idea. Used as it stands it is not secure: the same message always gives the same ciphertext, and ciphertexts can be multiplied. Part 8 shows the attacks and the padding (OAEP) that stops them.' },
      { topic: 'p07-uses', input: { job: 'encrypt', size: 'real', msg: 'the vault code is 7319' }, frame: 3, caption: 'The same steps with a 2048-bit key: the message is one number, and the arithmetic is the same.' },
      { h: 'Recap' },
      { list: ['Encrypt with the receiver\'s public key; decrypt with the receiver\'s private key.', 'Text becomes a number by reading its bytes in base 256; the number must be below n.', 'Textbook RSA shows the idea; real encryption pads the message first.'] },
      X('pk-x-which-key'), X('pk-x-text-number'), X('pk-x-number-text'), X('pk-x-toy-encrypt'),
    ],
  });

  C.lesson({
    id: 'pk-sign', chapter: 'pk-use', title: 'Signatures: the private key writes', minutes: 7,
    summary: 'A signature is made with the signer\'s private key and checked with her public key. It proves who made it and that the message was not changed, and anyone can check it. Signatures are made on a hash of the message.',
    blocks: [
      'Encryption keeps a message from being read. Often the worry is the opposite: the message is public, but the reader must be sure who wrote it and that nobody changed it on the way. A bank order, a software update, a contract. Can the key pair be turned round?',
      { topic: 'p07-uses', input: { job: 'sign', size: 'toy', msg: 'pay 40 at noon' }, frame: 3, caption: 'Alice hashes "pay 40 at noon" to h = 23663 and signs with her private key: s = h^d mod n = 8842.' },
      { topic: 'p07-uses', input: { job: 'sign', size: 'toy', msg: 'pay 40 at noon' }, frame: 5, caption: 'Bob checks with Alice\'s public key: s^e mod n = 23663, the hash of what he received. Only the holder of d could have made s.' },
      { predict: { q: 'Eve changes the message to "pay 400 at noon" and keeps Alice\'s s = 8842. What does Bob\'s check find?', options: ['s^e still equals the new hash', 's^e equals the old hash 23663, which no longer matches', 'The check cannot be done without d'], answer: 1, explain: 's^e is still 23663, the hash of the original. The new message hashes to 89409, so the two disagree and Bob rejects it. To make a matching s, Eve needs d.' } },
      { topic: 'p07-uses', input: { job: 'sign', size: 'toy', msg: 'pay 40 at noon' }, frame: 6, caption: 'The changed message hashes to 89409, not 23663: rejected.' },
      { h: 'Why sign the hash?' },
      'Signing a hash and not the message itself does two things. A message of any length becomes one short number below n, so one private-key operation signs a whole file. And it removes the algebra an attacker could use: in raw RSA, s₁·s₂ is a valid signature of h₁·h₂, a forgery nobody signed. With a hash, nobody can steer h₁·h₂ to be the hash of a message they want.',
      { tip: 'Encryption: the sender uses the receiver\'s public key. Signing: the signer uses her own private key. Mixing the two up is the most common slip in this part.' },
      { h: 'Recap' },
      { list: ['Sign with your private key; anyone verifies with your public key.', 'A valid signature proves the holder of the private key signed exactly this message.', 'Real schemes sign a hash, padded (PSS) or within a scheme built for signing (DSA, ECDSA, Ed25519).'] },
      X('pk-x-roles'), X('pk-x-toy-sign'), X('pk-x-forged'),
    ],
  });

  C.lesson({
    id: 'pk-agree', chapter: 'pk-use', title: 'Agreeing a key in public', minutes: 6,
    summary: 'Two people who have never met can agree a shared secret over an open line: each sends g raised to a secret exponent, and each raises what arrives to its own secret. Both reach g^(ab), and an eavesdropper would need a discrete logarithm.',
    blocks: [
      'Encryption with a public key moves a secret from Alice to Bob. Often both sides simply want the same fresh key, for a cipher like AES, without either one choosing it alone. Can two people agree on a secret in a conversation that Eve hears in full?',
      { topic: 'p07-uses', input: { job: 'agree', size: 'toy' }, frame: 2, caption: 'In public: p = 2027 and g = 2. In secret: a = 1234 and b = 1717. In public again: A = 2¹²³⁴ mod p = 1646 and B = 2¹⁷¹⁷ mod p = 1676.' },
      { topic: 'p07-uses', input: { job: 'agree', size: 'toy' }, frame: 4, caption: 'Alice computes B^a, Bob computes A^b, and both get g^(ab) mod p = 953, a number that never crossed the line.' },
      { predict: { q: 'Eve has p, g, A and B. What would let her compute the key 953?', options: ['Multiplying A by B', 'Finding a from A, a discrete logarithm', 'Nothing: she already has it', 'Factoring p'], answer: 1, explain: 'A·B = g^(a+b), not g^(ab). With a she could compute B^a just like Alice. Finding a from A = g^a is the discrete logarithm, and p is prime, so there is nothing to factor.' } },
      'This is the Diffie–Hellman key exchange, the subject of part 9. It uses only the one-way power map, with no trapdoor: neither side ever needs to undo anything.',
      { topic: 'p09-dh-paint', frame: 5, caption: 'The same idea as paint: each side mixes its secret colour into the other\'s mixture, and both end with the same colour.' },
      { h: 'Recap' },
      { list: ['Each side sends g^secret; each raises what arrives to its own secret; both get g^(ab).', 'An eavesdropper must solve a discrete logarithm.', 'Without authentication, someone in the middle can run a separate exchange with each side (the last lesson of this part).'] },
      X('pk-x-agree'),
    ],
  });

  C.lesson({
    id: 'pk-hybrid', chapter: 'pk-use', title: 'Hybrid encryption', minutes: 7,
    summary: 'Public-key operations are slow and hold only a short message. So a fresh symmetric session key encrypts the data, and only the session key goes through the public-key scheme. Every practical system works this way.',
    blocks: [
      'RSA-2048 with OAEP holds at most 190 bytes, and decrypting costs about 3000 multiplications of 2048-bit numbers. AES-GCM encrypts gigabytes a second. How should Alice send Bob a 10-megabyte file with only his public key?',
      { topic: 'p07-hybrid', frame: 1, caption: 'Alice draws a fresh 128-bit session key K, used for this message only.' },
      { topic: 'p07-hybrid', frame: 2, caption: 'The data goes through AES-128-GCM under K: fast, and the 16-byte tag will reveal any change.' },
      { topic: 'p07-hybrid', frame: 3, caption: 'Only K goes through RSA-OAEP with Bob\'s public key: one public-key operation, a 256-byte wrapped key.' },
      { predict: { q: 'The file grows from 56 bytes to 10 megabytes. How many RSA operations does Bob need to decrypt it?', options: ['One', 'About 55,000, one per 190 bytes', 'One per AES block', 'None'], answer: 0, explain: 'Only the 16-byte session key was wrapped with RSA, whatever the length of the data. Bob unwraps it once and decrypts the rest with AES.' } },
      { topic: 'p07-hybrid', frame: 4, caption: 'What travels: the wrapped key and the ciphertext with its nonce and tag, 256 + 12 + 56 + 16 = 340 bytes.' },
      { topic: 'p07-hybrid', frame: 6, caption: 'Bob unwraps K with one private-key operation, checks the tag, and decrypts.' },
      { h: 'The same pattern everywhere' },
      'TLS, encrypted e-mail and messaging apps all follow this pattern. Most now get the session key by agreement (Diffie–Hellman on an elliptic curve) instead of by wrapping, and sign the exchange, but the bulk data always goes through a symmetric cipher.',
      { topic: 'p07-hybrid', input: { size: 'toy', msg: 'meet at the pier', seed: 3 }, frame: 3, caption: 'With toy numbers: the 16-bit session key 47113 is the only thing RSA touches, c = 51385. A toy key this small could be factored at once, which is exercise material.' },
      { h: 'Recap' },
      { list: ['A fresh symmetric key encrypts the data; the public key protects only that key.', 'One public-key operation per message, whatever its length.', 'The symmetric part must be authenticated encryption (such as AES-GCM), so changes are detected.'] },
      X('pk-x-hybrid-why'), X('pk-x-hybrid-size'), X('pk-x-oaep-room'), X('pk-x-break-hybrid'),
    ],
  });

  // =========================================================================================================
  // Chapter 3: key lengths and trust
  // =========================================================================================================
  C.lesson({
    id: 'pk-levels', chapter: 'pk-size', title: 'Security levels', minutes: 7,
    summary: 'A security level of s bits means the best known attack costs about 2^s operations. AES-128, a 3072-bit RSA modulus and a 256-bit elliptic curve all sit at 128 bits. Public keys are much longer than symmetric keys of the same strength.',
    blocks: [
      'Which is stronger, a 128-bit AES key or a 2048-bit RSA key? Counting bits suggests RSA by a factor of sixteen. That is wrong, and the reason is that the bits of different schemes are attacked in different ways.',
      { def: 'Security level', text: 's bits of security: the best known attack needs about 2^s basic operations. For a good symmetric cipher this is the key length, since the best attack is to try every key.' },
      { topic: 'p07-levels', frame: 0, caption: 'Five levels and the sizes that reach each one, as the published standard tables give them.' },
      { topic: 'p07-levels', frame: 3, caption: '128 bits: AES-128, a 3072-bit RSA or Diffie–Hellman modulus, a 256-bit curve. The modulus is 12 times the size of the curve.' },
      { predict: { q: 'So where does a 2048-bit RSA modulus sit?', options: ['Above 128 bits', 'At 128 bits', 'At 112 bits', 'Below 80 bits'], answer: 2, explain: 'By the table, 2048 bits reaches 112 bits of security. To reach 128 bits a modulus needs 3072 bits.' } },
      { topic: 'p07-levels', input: { level: '112', rsa: 2048, ecc: 224 }, frame: 7, caption: 'A 2048-bit modulus: the number field sieve\'s running time is about 2¹¹⁷, enough for 112 bits but not for 128.' },
      { topic: 'p07-levels', frame: 5, caption: '256 bits needs a 15,360-bit modulus, and only a 512-bit curve.' },
      'How much is 2¹²⁸? A machine testing 2⁴⁰ keys a second, about a trillion, would need 2⁸⁸ seconds, around 10¹⁹ years. Even 2⁸⁰ operations at that speed take about 35,000 years, which is why 80 bits is now retired: whole data centres do better than one machine.',
      { h: 'Recap' },
      { list: ['s bits of security: about 2^s operations for the best known attack.', 'At 128 bits: AES-128, RSA-3072, a 256-bit curve.', 'RSA-2048 gives 112 bits; 80-bit sizes (RSA-1024, 2TDEA) are retired.'] },
      X('pk-x-level-2048'), X('pk-x-levels-table'), X('pk-x-brute-years'),
    ],
  });

  C.lesson({
    id: 'pk-why-long', chapter: 'pk-size', title: 'Why public keys are so long', minutes: 7,
    summary: 'A symmetric key falls only to brute force. An elliptic curve falls to Pollard\'s rho, at the square root of its size, so it needs twice the bits. An RSA modulus falls to the number field sieve, which is so much faster that a modulus needs thousands of bits, and needs more each time the level goes up.',
    blocks: [
      'At 128 bits of security the symmetric key has 128 bits, the curve 256 and the RSA modulus 3072. All three are meant to cost an attacker the same. So the attacks themselves must be very different. What are they?',
      { topic: 'p07-levels', frame: 6, caption: 'At 128 bits on one scale: brute force costs 2^(key bits); rho costs the square root of the curve\'s size; the number field sieve grows far more slowly with the modulus.' },
      { topic: 'p07-levels', frame: 8, caption: 'A 256-bit curve: Pollard\'s rho needs about √(π·2²⁵⁶/4) = 2^127.8 steps.' },
      { predict: { q: 'From 128 to 256 bits of security, how do the sizes grow?', options: ['All three double', 'Key and curve double; the modulus grows about 5-fold', 'The modulus doubles; the key and the curve stay the same', 'All three grow 5-fold'], answer: 1, explain: 'The key goes from 128 to 256 bits and the curve from 256 to 512, both doubling. The modulus goes from 3072 to 15,360 bits, 5 times as long, because the sieve\'s cost grows much more slowly than exponentially in the length.' } },
      { topic: 'p07-levels', frame: 9, caption: 'RSA\'s size grows fastest. That is one reason elliptic curves replaced RSA in most new protocols.' },
      { topic: 'p07-levels', input: { level: '80', rsa: 512, ecc: 112 }, frame: 7, caption: 'A 512-bit modulus: about 2⁶⁴ for the sieve. Moduli this short have been factored in public.' },
      'There is one more cost behind the table. Public-key work grows with the size: doubling the modulus makes each private-key operation about eight times slower. So a level is chosen to be just high enough for the data\'s lifetime, never much higher.',
      { tip: 'A quantum computer large enough to run Shor\'s algorithm would break RSA, Diffie–Hellman and elliptic curves at every size in the table. That is the subject of part 14; the symmetric keys would survive with their length doubled.' },
      { h: 'Recap' },
      { list: ['Symmetric keys: brute force, 2^k.', 'Curves: Pollard\'s rho, about 2^(bits/2), so twice the bits.', 'RSA and Diffie–Hellman modulo a prime: the number field sieve, which needs moduli of thousands of bits, growing fast with the level.'] },
      X('pk-x-curve-bits'), X('pk-x-grow'),
    ],
  });

  C.lesson({
    id: 'pk-trust', chapter: 'pk-size', title: 'Whose key is it?', minutes: 6,
    summary: 'A public key needs no secrecy, but it needs authenticity: Alice must be sure the key she uses is Bob\'s. An attacker who swaps keys in transit reads everything without breaking any mathematics. Certificates, signed by someone already trusted, bind a key to a name.',
    blocks: [
      'Alice looks up Bob\'s public key and encrypts to it. Mallory, who controls the network between them, had replaced the directory entry with her own public key. Mallory decrypts, reads, re-encrypts to Bob\'s real key and passes it on. Who noticed?',
      { topic: 'p07-keydist', frame: 9, caption: 'Public keys solve the delivery of secrets, but the public halves must still be the right ones: binding a key to a person is the job of certificates.' },
      { topic: 'p09-dh-mitm', frame: 1, caption: 'The same attack on key agreement: Mallory keeps Alice\'s A and hands Bob her own M = 11 instead.' },
      { topic: 'p09-dh-mitm', frame: 3, caption: 'Alice ends up with key 9, Bob with key 10, and Mallory holds both. The key Alice and Bob meant to share, 2, exists nowhere.' },
      { predict: { q: 'What stops this attack?', options: ['A longer modulus', 'Keeping the public keys secret', 'Signing the exchanged values with keys that were certified in advance', 'Using a fresh exponent every time'], answer: 2, explain: 'Mallory solved no hard problem, so bigger numbers do not help, and fresh exponents do not either. What failed is authentication: if A and B are signed with keys whose owners are known, Mallory\'s M carries no valid signature.' } },
      'A **certificate** is a short document that says "this public key belongs to this name", signed by a certificate authority whose own public key you already hold. Your browser and operating system ship with a list of such authorities. Part 13 builds certificate chains and shows how revocation works.',
      { h: 'Recap' },
      { list: ['A public key must be authentic, not secret.', 'A key swapped in transit lets an attacker read and change everything, with no cryptanalysis.', 'Certificates bind keys to names; a signature from a trusted authority vouches for the binding.'] },
      X('pk-x-cert'),
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
