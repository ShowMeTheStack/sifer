// Part 7, introduction to public-key cryptography: the exercises, the part's tour and its course. The lessons are in
// 070-pk.js. Every number below was worked out with the engines (S.NT, S.RSA) in a scratch script before it was
// written down, and the checks that need arithmetic (a factor, a recovered key) call the same engines.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('pk-x-pairs')) return;
  const ex = (o) => C.exercise(o);
  const NT = () => S.NT;
  const big = (t) => { const s = String(t).trim().replace(/[,_\s]/g, '').replace('−', '-'); return /^-?\d+$/.test(s) ? BigInt(s) : null; };
  const fn = (name, params, body) => 'function ' + name + '(' + params.join(', ') + ') {\n' + body + '\n}';

  // ===========================================================================================================
  // Chapter 1: why asymmetric
  // ===========================================================================================================
  ex({
    id: 'pk-x-pairs', chapter: 'pk-why', title: 'Keys for a rowing club', level: 1, kind: 'number', answer: 300,
    text: ['A rowing club of 25 members wants every pair of members to be able to exchange private messages with a symmetric cipher, each pair with its own key. How many keys must be made and delivered?'],
    hints: ['Each key belongs to one pair of members. Count the pairs.', 'The number of pairs among n people is n(n − 1)/2: each of the n people pairs with n − 1 others, and each pair is counted twice.', '25·24/2 = 300 keys, each delivered in secret to both members of its pair.'],
    solution: '300', wrong: ['600', '625', '25'],
    whyNot: 'Count each pair once: Ana–Bo and Bo–Ana share one key.',
  });
  ex({
    id: 'pk-x-new-member', chapter: 'pk-why', title: 'One more member', level: 1, kind: 'number', answer: 100,
    text: ['A network of 100 people uses pairwise symmetric keys. One more person joins. How many new keys must be made and delivered in secret?'],
    hints: ['The newcomer needs a key with each person already there, and nobody else needs a new one.', 'Check with the formula: 101·100/2 − 100·99/2.', '5050 − 4950 = 100 new keys, one with each existing member. With public keys the newcomer makes one key pair and publishes one public key.'],
    solution: '100', wrong: ['101', '1', '5050'],
  });
  ex({
    id: 'pk-x-keys-table', chapter: 'pk-why', title: 'Keys against people', level: 2, kind: 'table',
    text: ['Fill in the table: for a group of n people, how many symmetric keys are needed so that every pair has its own, and how many key pairs are needed if everyone uses public-key cryptography instead? Write plain numbers without commas.'],
    rows: ['n = 4', 'n = 10', 'n = 100', 'n = 1000'], cols: ['pairwise secret keys', 'key pairs'], corner: 'Group',
    cells: { 'n = 4|pairwise secret keys': '6', 'n = 4|key pairs': '4', 'n = 10|pairwise secret keys': '45', 'n = 10|key pairs': '10', 'n = 100|pairwise secret keys': '4950', 'n = 100|key pairs': '100', 'n = 1000|pairwise secret keys': '499500', 'n = 1000|key pairs': '1000' },
    hints: ['Pairwise keys: n(n − 1)/2. Key pairs: one per person.', 'For n = 10: 10·9/2 = 45 keys against 10 key pairs.', 'Rows: 6 and 4; 45 and 10; 4950 and 100; 499500 and 1000. The first column grows with n², the second with n.'],
    solution: { 'n = 4|pairwise secret keys': '6', 'n = 4|key pairs': '4', 'n = 10|pairwise secret keys': '45', 'n = 10|key pairs': '10', 'n = 100|pairwise secret keys': '4950', 'n = 100|key pairs': '100', 'n = 1000|pairwise secret keys': '499500', 'n = 1000|key pairs': '1000' },
    wrong: [
      { 'n = 4|pairwise secret keys': '12', 'n = 4|key pairs': '4', 'n = 10|pairwise secret keys': '90', 'n = 10|key pairs': '10', 'n = 100|pairwise secret keys': '9900', 'n = 100|key pairs': '100', 'n = 1000|pairwise secret keys': '999000', 'n = 1000|key pairs': '1000' },
      { 'n = 4|pairwise secret keys': '6', 'n = 4|key pairs': '8', 'n = 10|pairwise secret keys': '45', 'n = 10|key pairs': '20', 'n = 100|pairwise secret keys': '4950', 'n = 100|key pairs': '200', 'n = 1000|pairwise secret keys': '499500', 'n = 1000|key pairs': '2000' },
    ],
  });
  ex({
    id: 'pk-x-kdc', chapter: 'pk-why', title: 'What a key centre costs', level: 2, kind: 'choice',
    text: ['A company replaces its pairwise keys with a key distribution centre: each employee shares one long-term key with the centre, which hands out session keys on request. Which of these are drawbacks of the centre?'],
    options: ['The centre can read every conversation, since it made every session key', 'Nobody can start a new conversation while the centre is offline', 'The number of long-term keys grows with the square of the number of employees', 'One break-in at the centre exposes every employee\'s long-term key', 'Session keys must be longer than with pairwise keys'],
    answer: [0, 1, 3],
    hints: ['Think about what the centre knows, and when it has to be reachable.', 'The centre needs only one long-term key per employee, so the count grows with n, not n². Session key lengths do not change.', 'The drawbacks are the first, second and fourth: it knows every key, it must be online, and it is a single point to attack.'],
    solution: [0, 1, 3], wrong: [[0, 1], [2], [0, 1, 2, 3]],
  });
  ex({
    id: 'pk-x-oneway', chapter: 'pk-why', title: 'Which are believed one-way?', level: 2, kind: 'choice',
    text: ['Which of these functions are believed to be one-way at the sizes given: easy to compute, but infeasible to invert for a random input?'],
    options: ['x ↦ x + 12345 mod 2²⁵⁶', '(p, q) ↦ p·q for two random 1024-bit primes', 'x ↦ g^x mod p for a 2048-bit prime p and a generator g', 'x ↦ 7·x mod p for a 2048-bit prime p', 'x ↦ x² for 2048-bit x, with no modulus'],
    answer: [1, 2],
    hints: ['For each one, ask how you would go back from the output to the input.', 'Subtraction undoes adding; multiplying by 7⁻¹ mod p undoes the fourth; an ordinary integer square root undoes the last.', 'Only multiplying primes (undone by factoring) and modular powers (undone by the discrete logarithm) have no known fast way back.'],
    solution: [1, 2], wrong: [[1], [1, 2, 3], [2, 4]],
    why: 'Neither is proved one-way; both have resisted every attempt for decades at these sizes.',
  });
  ex({
    id: 'pk-x-dlog-small', chapter: 'pk-why', title: 'A discrete logarithm by hand', level: 2, kind: 'number', answer: 13,
    text: ['5 is a generator of Z₂₃*. Find the x in 0 … 21 with 5^x ≡ 21 (mod 23).'],
    hints: ['There is no formula: list the powers of 5 modulo 23 until 21 appears, multiplying by 5 each time.', '5⁰ … 5⁷ are 1, 5, 2, 10, 4, 20, 8, 17. Keep going: each power is the last one times 5, reduced modulo 23.', '5⁸ … 5¹³ are 16, 11, 9, 22, 18, 21, so x = 13. Check: 5¹³ mod 23 = 21.'],
    solution: '13', wrong: ['12', '21', '4'],
    whyNot: 'Compute 5 to your answer modulo 23: it should give 21.',
  });
  ex({
    id: 'pk-x-trial', chapter: 'pk-why', title: 'Factor a toy modulus', level: 2, kind: 'break', target: 'factor', normalize: 'int',
    text: ['A toy public key has n = 63383, the product of two primes. Find one of them: that is the trapdoor of the whole key. Trial division by hand is long; the [sandbox scratch pad](#sandbox/scratch) or the number-theory bench will do it in a moment.'],
    verify: (v) => { const p = BigInt(v); if (p <= 1n || p >= 63383n) return 'A factor of n lies strictly between 1 and n.'; return 63383n % p === 0n ? true : '63383 = ' + p + '·' + (63383n / p) + ' + ' + (63383n % p) + ': ' + p + ' does not divide n.'; },
    hints: ['Try the primes 2, 3, 5, 7, … in turn. A number with no factor up to its square root is prime, and √63383 ≈ 251.8, so a factor exists below 252.', 'Nothing up to 240 divides 63383. The next prime is 241.', '63383 = 241·263. Either prime breaks the key: with both, φ(n) = 240·262 = 62880 and d follows from e.'],
    solution: '241', wrong: ['251', '1', '63383', '7'],
  });
  ex({
    id: 'pk-x-code-trial', chapter: 'pk-why', title: 'Write trial division', level: 2, kind: 'code', fn: 'smallestFactor', params: ['n'],
    text: ['Write `smallestFactor(n)` for a BigInt n ≥ 2: return its smallest prime factor as a BigInt (n itself when n is prime). Try d = 2, 3, 4, 5, … and stop once d·d > n. One test is the product of two primes near a million, so the loop runs about a million times.'],
    start: 'function smallestFactor(n) {\n  \n}',
    ref: (n) => { for (let d = 2n; d * d <= n; d++) if (n % d === 0n) return d; return n; },
    cases: [[2n], [15n], [49n], [91n], [1000003n], [63383n], [1018081n], [999962000357n], [4096n]],
    timeLimit: 4000,
    hints: ['A loop: `for (let d = 2n; d * d <= n; d++)`, returning d as soon as `n % d === 0n`.', 'If the loop ends, nothing up to √n divided n, so n is prime: return n. The condition must be `<=`, or squares of primes such as 49 slip through.', 'function smallestFactor(n) {\n  for (let d = 2n; d * d <= n; d++) if (n % d === 0n) return d;\n  return n;\n}'],
    solution: fn('smallestFactor', ['n'], '  for (let d = 2n; d * d <= n; d++) if (n % d === 0n) return d;\n  return n;'),
    wrong: [fn('smallestFactor', ['n'], '  for (let d = 2n; d * d < n; d++) if (n % d === 0n) return d;\n  return n;'), fn('smallestFactor', ['n'], '  for (let d = 3n; d * d <= n; d += 2n) if (n % d === 0n) return d;\n  return n;')],
  });
  ex({
    id: 'pk-x-trapdoor-def', chapter: 'pk-why', title: 'What a trapdoor is', level: 1, kind: 'choice',
    text: ['In RSA, which number is the trapdoor: the secret that turns going back from infeasible into easy?'],
    options: ['The modulus n', 'The public exponent e', 'The private exponent d (or the primes p and q it is made from)', 'The ciphertext c'],
    answer: 2,
    whyNot: { 0: 'n is public: everyone has it, and it does not let them go back.', 1: 'e is public, and it only goes forwards.', 3: 'The ciphertext is what has to be undone, not the means of undoing it.' },
    hints: ['A trapdoor is secret, and it is made together with the function.', 'Going back means computing y^d mod n. Which number in that formula is secret?', 'd, the inverse of e modulo φ(n). It comes from p and q, so the primes are the trapdoor too: any one of p, q, φ(n) or d gives the others.'],
    solution: 2, wrong: [0, 1],
  });
  ex({
    id: 'pk-x-forward', chapter: 'pk-why', title: 'Forwards through a toy key', level: 1, kind: 'number', answer: 32723,
    text: ['The toy public key is n = 50621 (= 223·227) and e = 17. Compute y = 3001¹⁷ mod 50621. A calculator that reduces after each step, or the number-theory bench (Powers), will do.'],
    hints: ['17 = 10001 in binary: square four times, then multiply by 3001 once, reducing modulo 50621 at every step.', 'The squarings give 3001², 3001⁴, 3001⁸, 3001¹⁶ ≡ 46084, 32243, 7572, 32212 (mod 50621); one multiplication by 3001 finishes it.', 'y = 32723. That is 4 squarings and 1 multiplication, 5 operations.'],
    solution: '32723', wrong: ['3001', '15446', '50621'],
    whyNot: 'Reduce modulo 50621 after every multiplication; the bench\'s Powers tool shows each step.',
  });
  ex({
    id: 'pk-x-forward-ops', chapter: 'pk-why', title: 'Counting the work', level: 1, kind: 'number', answer: 7,
    text: ['Left-to-right square-and-multiply starts from x for the leading 1 bit, then squares once for every later bit and multiplies by x for every later bit that is 1. How many operations (squarings plus multiplications) does it take to compute x³⁷ mod n?'],
    hints: ['Write 37 in binary.', '37 = 100101: six bits, three of them 1. After the leading 1 there are five more bits, two of them 1.', '5 squarings and 2 multiplications: 7 operations.'],
    solution: '7', wrong: ['36', '6', '8'],
    whyNot: 'The leading 1 costs nothing: it only sets the starting value to x.',
  });
  ex({
    id: 'pk-x-trapdoor-back', chapter: 'pk-why', title: 'Back through the trapdoor', level: 2, kind: 'number', answer: 12345,
    text: ['For the same toy key, n = 50621 and e = 17, the private exponent is d = 29513. Someone sent y = 11617. Undo it: what x had x¹⁷ ≡ 11617 (mod 50621)?'],
    hints: ['With the trapdoor, going back is one more exponentiation: x = y^d mod n.', 'd = 29513 has 15 bits, so this is 14 squarings and a few multiplications: use the bench (Powers) with x = 11617, e = 29513, n = 50621.', 'x = 11617^29513 mod 50621 = 12345. Check forwards: 12345¹⁷ mod 50621 = 11617.'],
    solution: '12345', wrong: ['11617', '29513', '3001'],
    whyNot: 'Raise y to d modulo n, then check by raising your answer to e = 17.',
  });

  // ===========================================================================================================
  // Chapter 2: what a key pair does
  // ===========================================================================================================
  ex({
    id: 'pk-x-which-key', chapter: 'pk-use', title: 'Which key locks it?', level: 1, kind: 'choice',
    text: ['Alice wants to send Bob a message only Bob can read. With which key does she encrypt it?'],
    options: ['Her own public key', 'Her own private key', 'Bob\'s public key', 'Bob\'s private key'],
    answer: 2,
    whyNot: { 0: 'Then only Alice could decrypt it.', 1: 'Anything done with Alice\'s private key can be undone by everyone with her public key: that is a signature, not secrecy.', 3: 'Alice does not have Bob\'s private key, and nobody else should.' },
    hints: ['Only Bob should be able to undo it. Which key does only Bob have?', 'Bob\'s private key undoes what was done with Bob\'s public key.', 'Bob\'s public key: anyone can lock with it, only Bob can open.'],
    solution: 2, wrong: [0, 1, 3],
  });
  ex({
    id: 'pk-x-text-number', chapter: 'pk-use', title: 'Two letters as a number', level: 1, kind: 'number', answer: 26479,
    text: ['Before RSA can encrypt the text "go", it is read as one number: its bytes in order, as the digits of a base-256 number. In ASCII g is 0x67 = 103 and o is 0x6f = 111. What is the number?'],
    hints: ['The first byte is the high digit: m = 103·256 + 111.', 'In hex the number is simply 0x676f.', '103·256 + 111 = 26368 + 111 = 26479.'],
    solution: '26479', wrong: ['214', '28519', '26368'],
    whyNot: 'The first byte is the high one: multiply it by 256 and add the second.',
  });
  ex({
    id: 'pk-x-number-text', chapter: 'pk-use', title: 'A number back to text', level: 2, kind: 'string', answer: 'ok!',
    text: ['Bob decrypted a message and got the number 7301921. Read it as bytes, most significant first, and as ASCII text. What did the message say?'],
    hints: ['Divide by 256 repeatedly; the remainders are the bytes from last to first. Or convert to hex.', '7301921 = 0x6f6b21: the bytes 6f, 6b and 21.', '0x6f is o, 0x6b is k and 0x21 is an exclamation mark: "ok!".'],
    solution: 'ok!', wrong: ['ok', 'ko!', 'OK!'],
    whyNot: 'Write the number in hex and read each pair of digits as one ASCII character, punctuation included.',
  });
  ex({
    id: 'pk-x-toy-encrypt', chapter: 'pk-use', title: 'Encrypt to Bob', level: 1, kind: 'number', answer: 31203,
    text: ['Bob\'s toy public key is n = 60491, e = 7. Encrypt the message "go", which is m = 26479, with textbook RSA: c = m⁷ mod n.'],
    hints: ['7 = 111 in binary: m² · m, squared, times m. Reduce modulo 60491 at every step.', 'm² mod n = 26479² mod 60491 = 46751, and m³ = 46751·26479 mod 60491 = 31905.', 'm⁶ = 31905² mod 60491 = 46968, and m⁷ = 46968·26479 mod 60491 = 31203.'],
    solution: '31203', wrong: ['26479', '60491', '31905'],
    whyNot: 'Raise m to the 7th power and reduce modulo 60491 after each multiplication.',
  });
  ex({
    id: 'pk-x-roles', chapter: 'pk-use', title: 'Who uses which key', level: 2, kind: 'choice',
    text: ['Alice has a key pair and Bob has a key pair. Which of these statements are true?'],
    options: ['To sign a contract, Alice uses her private key', 'To check Alice\'s signature, Bob uses Alice\'s public key', 'To encrypt to Bob, Alice uses her private key', 'To decrypt a message from Alice, Bob uses Alice\'s public key', 'To decrypt a message sent to him, Bob uses his private key'],
    answer: [0, 1, 4],
    hints: ['The private key is used by its owner for the action only the owner may do: sign, or decrypt.', 'The public key is used by everyone else: to encrypt to its owner, or to check its owner\'s signature.', 'True: the first, second and fifth. Encrypting to Bob uses Bob\'s public key, and Bob decrypts with his own private key.'],
    solution: [0, 1, 4], wrong: [[0, 1], [0, 2, 4], [1, 3]],
  });
  ex({
    id: 'pk-x-toy-sign', chapter: 'pk-use', title: 'A toy signature', level: 2, kind: 'number', answer: 40424,
    text: ['Alice\'s toy key is n = 72851, e = 5, with private exponent d = 28925. A message hashes to h = 1234. Sign it with textbook RSA: s = h^d mod n. Then check your s with her public key.'],
    hints: ['Signing is raising to d modulo n; d = 28925 has 15 bits, so use the bench (Powers).', 'To check: s⁵ mod 72851 must give back 1234.', 's = 1234^28925 mod 72851 = 40424, and 40424⁵ mod 72851 = 1234.'],
    solution: '40424', wrong: ['1234', '28925', '7997'],
    whyNot: 'Raise h to d modulo n. Your s is right when s⁵ mod 72851 = 1234.',
  });
  ex({
    id: 'pk-x-forged', chapter: 'pk-use', title: 'Which signatures verify?', level: 3, kind: 'choice',
    text: ['Alice\'s toy public key is n = 72851, e = 5, and she signs hash values with textbook RSA. Eve offers these (hash, signature) pairs. Which of them pass the check s⁵ mod n = h? (One of them Alice never signed.)'],
    options: ['h = 1234, s = 40424', 'h = 2468, s = 7997 (that is 2·40424 mod n)', 'h = 65736, s = 51846 (the squares of 1234 and 40424, mod n)', 'h = 1235, s = 40425'],
    answer: [0, 2],
    hints: ['Check each with s⁵ mod 72851. Or use algebra: (s₁·s₂)⁵ = s₁⁵·s₂⁵.', 'Doubling s multiplies s⁵ by 2⁵ = 32, not by 2, so the second fails. Squaring s squares s⁵, which squares h.', 'The first (Alice\'s own) and the third pass: 51846 = 40424² mod n is a valid signature of 1234² mod n = 65736, which Alice never signed. That is why real schemes sign a padded hash, never a raw number.'],
    solution: [0, 2], wrong: [[0], [0, 1], [0, 1, 2, 3]],
    why: 'Raw RSA signatures multiply: a forger can combine old signatures into new valid ones.',
  });
  ex({
    id: 'pk-x-agree', chapter: 'pk-use', title: 'Agree a key', level: 2, kind: 'number', answer: 434,
    text: ['Alice and Bob agree in public on p = 1019 and g = 2. Alice picks a = 300, Bob picks b = 457. Alice sends A = 2³⁰⁰ mod 1019 = 130, Bob sends B = 2⁴⁵⁷ mod 1019 = 251. What key do they share?'],
    hints: ['Alice computes B^a mod p; Bob computes A^b mod p. Both must agree.', 'Compute 251³⁰⁰ mod 1019 (or 130⁴⁵⁷ mod 1019) on the bench.', 'K = 251³⁰⁰ mod 1019 = 130⁴⁵⁷ mod 1019 = 434. Eve\'s A·B = 2⁷⁵⁷ mod 1019 = 22 is not the key.'],
    solution: '434', wrong: ['22', '381', '757'],
    whyNot: 'Raise the number you received to your own secret, modulo p.',
  });
  ex({
    id: 'pk-x-hybrid-why', chapter: 'pk-use', title: 'Why hybrid?', level: 1, kind: 'choice',
    text: ['Why does practical encryption to a public key wrap a fresh symmetric key and encrypt the data with that, instead of encrypting the data with RSA directly?'],
    options: ['RSA cannot encrypt numbers larger than about 2¹²⁸', 'RSA operations are slow and hold only a short message, while a symmetric cipher is fast on any length', 'A symmetric key is harder to break than an RSA key of any size', 'RSA has no decryption, only signing'],
    answer: 1,
    whyNot: { 0: 'An RSA-2048 block holds up to 190 bytes with OAEP, far more than 128 bits; the problem is long data, not one block.', 2: 'At matching security levels both are equally hard; RSA-3072 and AES-128 both give 128 bits.', 3: 'RSA decrypts: that is the trapdoor.' },
    hints: ['Compare a 10-megabyte file with what one RSA operation holds.', 'RSA-2048 with OAEP holds 190 bytes per operation and decrypting costs about 3000 big multiplications; AES does gigabytes a second.', 'Speed and size: one RSA operation protects the 16-byte key, and AES does the bulk.'],
    solution: 1, wrong: [0, 2],
  });
  ex({
    id: 'pk-x-hybrid-size', chapter: 'pk-use', title: 'How many bytes travel', level: 2, kind: 'number', answer: 1412,
    text: ['Alice sends Bob a 1000-byte file with hybrid encryption: the session key is wrapped with RSA-OAEP under Bob\'s 3072-bit key, and the file is encrypted with AES-GCM with a 12-byte nonce and a 16-byte tag. How many bytes does she send in all?'],
    hints: ['An RSA ciphertext is as long as the modulus, whatever is inside it.', '3072 bits is 384 bytes. GCM ciphertext is as long as the plaintext.', '384 + 12 + 1000 + 16 = 1412 bytes.'],
    solution: '1412', wrong: ['1028', '1016', '1396'],
    whyNot: 'Add the wrapped key (as long as the modulus), the nonce, the ciphertext and the tag.',
  });
  ex({
    id: 'pk-x-oaep-room', chapter: 'pk-use', title: 'How much fits in one RSA block', level: 2, kind: 'number', answer: 318,
    text: ['RSA-OAEP with SHA-256 holds at most k − 2·32 − 2 bytes of message, where k is the length of the modulus in bytes (32 is the hash length). How many bytes fit with a 3072-bit key?'],
    hints: ['k = 3072 / 8.', 'k = 384 bytes; OAEP reserves 66 of them.', '384 − 64 − 2 = 318 bytes. (For RSA-2048 the same formula gives 190.)'],
    solution: '318', wrong: ['384', '190', '320'],
  });
  ex({
    id: 'pk-x-break-hybrid', chapter: 'pk-use', title: 'Unwrap a session key', level: 3, kind: 'break', target: 'session key', normalize: 'int',
    text: [
      'A homemade messenger wraps 16-bit session keys with toy RSA. You captured one exchange:',
      { code: 'Bob\'s public key:  n = 1674427, e = 17\nWrapped key:       c = 489953' },
      'Recover the session key K (a number below 65536). There are at least two ways in.',
      { sandbox: 'scratch' },
    ],
    verify: (v) => { const k = BigInt(v); if (k < 0n || k >= 1674427n) return 'The key is a number below n.'; return NT().pow(k, 17n, 1674427n) === 489953n ? true : k + '¹⁷ mod n = ' + NT().pow(k, 17n, 1674427n) + ', not the wrapped key 489953.'; },
    hints: ['Way one: n has only 7 digits, so factor it, compute d and decrypt. Way two: K has only 16 bits and textbook RSA is deterministic, so encrypt every candidate and compare with c.', 'n = 1291·1297: the primes are so close that n is just above 1293², and Fermat\'s method finds them in one step. Then φ(n) = 1290·1296 = 1671840 and d = 17⁻¹ mod φ(n).', 'd = 1475153 and K = 489953^1475153 mod 1674427 = 47073 (0xb7e1). Brute force agrees: 47073¹⁷ mod n = 489953. Real systems pad the key with randomness (OAEP), which defeats the second way, and use 2048-bit moduli, which defeat the first.'],
    solution: '47073', wrong: ['489953', '1291', '1475153'],
  });

  // ===========================================================================================================
  // Chapter 3: key lengths and trust
  // ===========================================================================================================
  ex({
    id: 'pk-x-level-2048', chapter: 'pk-size', title: 'How strong is RSA-2048?', level: 1, kind: 'choice',
    text: ['By the standard tables, which security level does a 2048-bit RSA modulus give?'],
    options: ['80 bits', '112 bits', '128 bits', '2048 bits'],
    answer: 1,
    whyNot: { 0: '80 bits is a 1024-bit modulus.', 2: '128 bits needs a 3072-bit modulus.', 3: 'The level counts the work of the best attack, not the length of the key: the number field sieve is far faster than trying every number.' },
    hints: ['The level is about 2^s operations for the best known attack.', 'For RSA the best attack is the number field sieve; on 2048 bits it costs about 2¹¹⁷.', '112 bits. 128 bits needs 3072 bits.'],
    solution: 1, wrong: [2, 3],
  });
  const LV = { '80|RSA modulus': '1024', '80|curve': '160', '112|RSA modulus': '2048', '112|curve': '224', '128|RSA modulus': '3072', '128|curve': '256', '192|RSA modulus': '7680', '192|curve': '384', '256|RSA modulus': '15360', '256|curve': '512' };
  ex({
    id: 'pk-x-levels-table', chapter: 'pk-size', title: 'The table of levels', level: 2, kind: 'table',
    text: ['Fill in the sizes, in bits, that reach each security level: the RSA (or prime-field Diffie–Hellman) modulus and the elliptic curve. Write plain numbers without commas. The topic [Key lengths and security levels](#topic=p07-levels) shows the table if you need to look.'],
    rows: ['80', '112', '128', '192', '256'], cols: ['RSA modulus', 'curve'], corner: 'Level (bits)',
    cells: LV,
    hints: ['A curve needs twice the bits of the level, because Pollard\'s rho costs about the square root of its size.', 'The moduli: 1024 for 80 bits and 2048 for 112; 3072 for 128. They grow much faster than the level.', 'Moduli 1024, 2048, 3072, 7680, 15360; curves 160, 224, 256, 384, 512.'],
    solution: LV,
    wrong: [Object.assign({}, LV, { '128|RSA modulus': '2048' }), Object.assign({}, LV, { '256|curve': '256', '192|curve': '192' })],
  });
  ex({
    id: 'pk-x-brute-years', chapter: 'pk-size', title: 'How long is 2⁸⁰?', level: 3, kind: 'number', answer: 34841, tolerance: 600,
    text: ['An attacker\'s machine does 2⁴⁰ operations a second (about a trillion). How many years does it need for 2⁸⁰ operations? Take a year as 365.25 days, and give a whole number of years.'],
    hints: ['2⁸⁰ / 2⁴⁰ = 2⁴⁰ seconds.', '2⁴⁰ = 1,099,511,627,776 seconds, and a year is 31,557,600 seconds.', 'About 34,841 years. A data centre of 100,000 such machines would need a third of a year, which is why 80-bit security is retired.'],
    solution: '34841', wrong: ['2', '1099511627776', '348'],
    higherLower: true,
  });
  ex({
    id: 'pk-x-curve-bits', chapter: 'pk-size', title: 'A 384-bit curve', level: 2, kind: 'number', answer: 192, tolerance: 1,
    text: ['Pollard\'s rho attacks an elliptic curve group of size about 2^b in about √(π·2^b/4) steps. Roughly how many bits of security does a 384-bit curve give? (Answer to the nearest bit.)'],
    hints: ['The square root halves the exponent: √(2^384) = 2^192.', 'The factor √(π/4) ≈ 0.886 is about 2^−0.17, so it changes almost nothing.', 'About 2^191.8 steps: 192 bits, matching the 192-bit level, where AES-192 and a 7680-bit modulus sit.'],
    solution: '192', wrong: ['384', '96', '128'],
  });
  ex({
    id: 'pk-x-grow', chapter: 'pk-size', title: 'The price of a longer modulus', level: 3, kind: 'number', answer: 125,
    text: ['A private-key RSA operation is about one squaring per bit of the exponent, and with schoolbook arithmetic each multiplication of k-bit numbers costs about k². So the cost grows roughly with k³. How many times slower is one private-key operation with a 15,360-bit modulus (256-bit security) than with a 3072-bit one (128-bit security)?'],
    hints: ['15360 / 3072 = 5.', 'Five times as many squarings, each about 5² = 25 times as costly.', '5³ = 125 times slower. A 512-bit curve against a 256-bit one costs about 2³ = 8 times more: another reason curves took over.'],
    solution: '125', wrong: ['5', '25', '625'],
  });
  ex({
    id: 'pk-x-cert', chapter: 'pk-size', title: 'What a certificate fixes', level: 2, kind: 'choice',
    text: ['Mallory sits on the network between Alice and a server and replaces the server\'s public key with her own whenever Alice asks for it. Which measure stops her?'],
    options: ['Doubling the length of the server\'s RSA key', 'Encrypting the public key with AES before sending it', 'Having the server\'s public key signed by an authority whose public key Alice already holds, and checking that signature', 'Keeping the server\'s public key secret'],
    answer: 2,
    whyNot: { 0: 'Mallory breaks nothing: she substitutes a key. A longer key is substituted just as easily.', 1: 'Alice would need a shared AES key first, which is the problem public keys were meant to solve.', 3: 'Anyone must be able to encrypt to the server, so its key cannot be secret; it must be authentic.' },
    hints: ['Mallory solves no hard problem, so making problems harder does not help.', 'Alice needs a way to tell the real key from Mallory\'s, starting from something she already trusts.', 'A certificate: the server\'s key and name, signed by an authority Alice trusts. Mallory cannot make that signature for her own key.'],
    solution: 2, wrong: [0, 1, 3],
  });

  // ===========================================================================================================
  // The part's tour and course
  // ===========================================================================================================
  C.tour({
    id: 'pk-tour', title: 'Tour: public-key cryptography', blurb: 'Why keys come in pairs, and what each half is for, in eight steps.',
    steps: [
      { route: 'part=pubkey', target: '#main', text: 'Part 7 of the catalogue: why symmetric keys alone cannot work for strangers, what a trapdoor is, the three jobs of a key pair, and how long keys must be.' },
      { route: 'topic=p07-keydist', target: '#stageWrap', text: 'The key-distribution problem: every pair of people needs its own secret key, delivered in secret. Step through and watch the count grow with the square of the group.' },
      { target: '#btnPlay', text: 'Play runs the steps; the arrow keys go one at a time. The line under the picture says what happens with the actual numbers.' },
      { route: 'topic=p07-trapdoor', target: '#inputs', text: 'A trapdoor one-way function. Switch between RSA, factoring and the discrete logarithm, and between toy and 2048-bit sizes, to compare the work forwards and backwards.' },
      { route: 'topic=p07-uses', target: '#stageWrap', text: 'One key pair, three jobs: encrypt to its owner, check its owner\'s signature, or agree a key. The examples switch between them.' },
      { route: 'topic=p07-hybrid', target: '#stageWrap', text: 'Hybrid encryption: AES-GCM carries the data and RSA wraps only the 16-byte session key. This is how public keys are really used.' },
      { route: 'topic=p07-levels', target: '#stageWrap', text: 'Security levels: why a 3072-bit RSA modulus, a 256-bit curve and AES-128 all count as 128 bits.' },
      { route: 'learn', target: '[data-chapter="pk-why"]', text: 'The part\'s lessons and exercises start here: count keys, invert a toy trapdoor, sign and forge with textbook RSA, and unwrap a session key from a toy messenger.' },
    ],
  });

  C.course({
    id: 'pk-course', title: 'Public-key cryptography: the ideas', blurb: 'An ordered path through every topic of part 7, from the key-distribution problem to security levels and certificates, with lessons and exercises on the way.',
    steps: [
      { topic: 'p07-keydist', note: 'n(n − 1)/2 secret keys, a key centre, or one key pair each.' },
      { lesson: 'pk-keys', note: 'Why symmetric keys alone do not scale.' },
      { exercise: 'pk-x-keys-table', note: 'Keys against people, from 4 to 1000.' },
      { topic: 'p07-trapdoor', note: 'Easy forwards, hard backwards, easy again with the trapdoor.' },
      { lesson: 'pk-oneway', note: 'Multiplying primes and modular powers.' },
      { exercise: 'pk-x-trial', note: 'Factor a toy modulus.' },
      { lesson: 'pk-trapdoor', note: 'RSA as a trapdoor function.' },
      { exercise: 'pk-x-trapdoor-back', note: 'Undo x¹⁷ with d.' },
      { topic: 'p07-uses', note: 'Encrypt, sign and agree with one key pair.' },
      { lesson: 'pk-sign', note: 'The private key writes, the public key reads.' },
      { exercise: 'pk-x-forged', note: 'A signature nobody made.' },
      { topic: 'p07-hybrid', note: 'One RSA operation, whatever the length of the data.' },
      { exercise: 'pk-x-break-hybrid', note: 'Unwrap a 16-bit session key two ways.' },
      { topic: 'p07-levels', note: 'Brute force, rho and the number field sieve on one scale.' },
      { lesson: 'pk-why-long', note: 'Why the modulus grows fastest.' },
      { exercise: 'pk-x-levels-table', note: 'The sizes for each level.' },
      { lesson: 'pk-trust', note: 'Whose key is it?' },
    ],
  });

  // ---- what the diagram checker looks at on these pages -----------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'pk lesson pk-keys')) {
    const ready = (sel) => "document.querySelector('" + sel + "')";
    for (const ch of C.chapters.filter((c) => c.part === 'pubkey')) for (const id of ch.lessons) S.Checks.push({ group: 'learn', name: 'pk lesson ' + id, hash: 'lesson=' + id, ready: ready('#lessonView'), sel: '#main' });
    for (const id of ['pk-x-keys-table', 'pk-x-code-trial', 'pk-x-break-hybrid']) S.Checks.push({ group: 'learn', name: 'pk exercise ' + id, hash: 'exercise=' + id, ready: ready('#exerciseView'), sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'pk course', hash: 'course=pk-course', ready: ready('#courseView'), sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
