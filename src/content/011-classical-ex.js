// Part 1, classical ciphers and the Enigma wing: the exercises. The lessons are in 010-classical.js. Every text here
// is our own; ciphertexts are made by the engines (S.Classic, S.Enigma) when this file loads, so they always match
// them, and every answer that can be tried is checked by trying it (decrypt and compare), so equivalent keys pass.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.exercises.has('cl-x-shift-key')) return;
  const ex = (o) => C.exercise(o);
  const K = S.Classic, E = S.Enigma;
  const L = (t) => String(t).toUpperCase().replace(/[^A-Z]/g, '');
  const head = (t, n) => { const s = L(t); return s.length > n ? s.slice(0, n) + '…' : s; };
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(' ');
  const enc = (s) => new TextEncoder().encode(s);

  // ===========================================================================================================
  // Chapter 1: shift, affine and substitution
  // ===========================================================================================================
  const SHIFT_P = 'THE NIGHT TRAIN TO THE COAST LEAVES FROM PLATFORM NINE AT TEN PAST ELEVEN.';
  const SHIFT_C = K.shift.encrypt(SHIFT_P, 17).out;
  ex({
    id: 'cl-x-shift-key', chapter: 'cl-mono', title: 'Recover a shift key', level: 1, kind: 'break', target: 'shift', normalize: 'int',
    text: ['A porter found this on a luggage label. It was made with a shift cipher, spaces and punctuation left in place.', { code: SHIFT_C }, 'What is the shift k (the number of places each letter moved forward)?'],
    verify: (v) => { const p = K.shift.decrypt(SHIFT_C, Number(v)).out; return L(p) === L(SHIFT_P) ? true : 'Shifting back by ' + v + ' gives ' + head(p, 18) + ', which is not English.'; },
    hints: ['A three-letter word that appears twice at the start of phrases is a good guess for THE.', 'KYV appears twice. If K stands for T, how far did T move to become K?', 'T = 19 and K = 10, so k ≡ 10 − 19 = −9 ≡ 17 (mod 26). Shifting every letter back 17 reads THE NIGHT TRAIN TO THE COAST LEAVES FROM PLATFORM NINE AT TEN PAST ELEVEN.'],
    solution: '17', wrong: ['9', '-17', '3'],
    why: 'Any number congruent to 17 modulo 26 is the same key.',
  });

  const shiftCases = [['HELLO, WORLD', 3], ['XYZ', 4], ['ATTACK AT DAWN', 0], ['ABC', -1], ['MEET ME AT NINE', 29], ['SHIFT 13 TWICE', 13], ['', 5]];
  ex({
    id: 'cl-x-shift-code', chapter: 'cl-mono', title: 'Write the shift cipher', level: 1, kind: 'code', fn: 'shift', params: ['text', 'k'],
    text: ['Write `shift(text, k)`: move every capital letter A–Z of `text` forward k places round the alphabet and leave every other character where it is. k may be negative or larger than 26.', { code: 'shift("HELLO, WORLD", 3)  →  "KHOOR, ZRUOG"\nshift("ABC", -1)          →  "ZAB"' }],
    start: 'function shift(text, k) {\n  let out = \'\';\n  for (const ch of text) {\n    \n  }\n  return out;\n}',
    tests: shiftCases.map(([t, k]) => ({ args: [t, k], want: K.shift.encrypt(t, k).out })),
    hints: ['A letter\'s number is `ch.charCodeAt(0) - 65`, and `String.fromCharCode(65 + n)` turns a number back into a letter.', 'JavaScript\'s `%` keeps the sign: `-1 % 26` is `-1`. Use `((n % 26) + 26) % 26` to land in 0 … 25.', 'function shift(text, k) {\n  let out = \'\';\n  for (const ch of text) {\n    if (ch >= \'A\' && ch <= \'Z\') out += String.fromCharCode(65 + ((((ch.charCodeAt(0) - 65 + k) % 26) + 26) % 26));\n    else out += ch;\n  }\n  return out;\n}'],
    solution: 'function shift(text, k) {\n  let out = \'\';\n  for (const ch of text) {\n    if (ch >= \'A\' && ch <= \'Z\') out += String.fromCharCode(65 + ((((ch.charCodeAt(0) - 65 + k) % 26) + 26) % 26));\n    else out += ch;\n  }\n  return out;\n}',
    wrong: [
      'function shift(text, k) { let out = \'\'; for (const ch of text) out += String.fromCharCode(65 + (ch.charCodeAt(0) - 65 + k) % 26); return out; }',
      'function shift(text, k) { let out = \'\'; for (const ch of text) { if (ch >= \'A\' && ch <= \'Z\') out += String.fromCharCode(65 + (ch.charCodeAt(0) - 65 + k) % 26); else out += ch; } return out; }',
    ],
  });

  ex({
    id: 'cl-x-affine-inv', chapter: 'cl-mono', title: 'Undo a multiplier', level: 1, kind: 'number', answer: 15,
    text: ['An affine cipher uses the multiplier a = 7. To decrypt, every letter is multiplied by the inverse of 7 modulo 26: the number x between 0 and 25 with 7·x ≡ 1 (mod 26). What is x?'],
    hints: ['Look for a multiple of 26 plus 1 that 7 divides: 27, 53, 79, 105, …', '105 = 4·26 + 1, and 105 = 7·15.', '7·15 = 105 = 4·26 + 1 ≡ 1 (mod 26), so 7⁻¹ ≡ 15. Extended Euclid on 26 and 7 gives the same: 1 = 3·26 − 11·7, and −11 ≡ 15.'],
    solution: '15', wrong: ['11', '19', '-7'],
    whyNot: 'Multiply your answer by 7 and reduce modulo 26: the inverse gives exactly 1.',
  });

  const AFF_P = 'MEET THE PILOT AT THE OLD MILL BEFORE SUNRISE AND BRING THE CHARTS.';
  const AFF_C = K.affine.encrypt(AFF_P, 11, 4).out;
  ex({
    id: 'cl-x-affine-key', chapter: 'cl-mono', title: 'An affine key from a known word', level: 2, kind: 'break', target: 'key', normalize: 'text',
    text: ['A smuggler\'s note was enciphered with an affine cipher, c = a·p + b (mod 26). Every note of his begins with the word MEET.', { code: AFF_C }, 'Find the key. Write it as a, b (for example 5, 8).'],
    verify: (v) => {
      const m = /^\s*\(?\s*a?\s*=?\s*(-?\d+)\s*[,;\s]\s*b?\s*=?\s*(-?\d+)\s*\)?\s*$/i.exec(v);
      if (!m) return 'Write the key as two numbers, a and b, like 5, 8.';
      const a = Number(m[1]), b = Number(m[2]);
      if (!K.affine.valid(a)) return 'a = ' + a + ' shares a factor with 26, so it cannot be undone: no cipher uses it.';
      const p = K.affine.decrypt(AFF_C, a, b).out;
      return L(p) === L(AFF_P) ? true : 'With a = ' + a + ' and b = ' + b + ' the note begins ' + head(p, 12) + '.';
    },
    hints: ['MEET became GWWF. Two letters of known plaintext give two equations: 12·a + b ≡ 6 (M → G) and 19·a + b ≡ 5 (T → F).', 'Subtract the first equation from the second: 7·a ≡ −1 ≡ 25 (mod 26). The inverse of 7 is 15.', 'a ≡ 25·15 = 375 ≡ 11, and b ≡ 6 − 12·11 = −126 ≡ 4. The key is 11, 4, and the note reads MEET THE PILOT AT THE OLD MILL BEFORE SUNRISE AND BRING THE CHARTS.'],
    solution: '11, 4', wrong: ['4, 11', '11, 3', '13, 4'],
  });

  ex({
    id: 'cl-x-keyspace-29', chapter: 'cl-mono', title: 'Affine keys over 29 letters', level: 2, kind: 'number', answer: 812,
    text: ['A Nordic club extends the alphabet with Æ, Ø and Å, so letters are numbers modulo 29. How many affine keys (a, b) give a cipher that can be undone?'],
    hints: ['a must have an inverse modulo 29, and b can be anything from 0 to 28.', '29 is prime, so every a from 1 to 28 has an inverse.', '28 multipliers × 29 shifts = 812 keys. With 26 letters only 12 multipliers work (φ(26) = 12), giving 312.'],
    solution: '812', wrong: ['841', '312', '28'],
    whyNot: 'Count the multipliers that can be undone, then multiply by the number of shifts.',
  });

  ex({
    id: 'cl-x-subst-bits', chapter: 'cl-mono', title: 'A substitution key in bits', level: 2, kind: 'number', answer: 88.38, tolerance: 0.5,
    text: ['A substitution key is one of the 26! orderings of the alphabet. How many bits would it take to number them all, log₂(26!)? Give one decimal place.'],
    hints: ['log₂(26!) = log₂ 2 + log₂ 3 + … + log₂ 26.', '26! ≈ 4.03 × 10²⁶, and log₂ 10 ≈ 3.32.', 'log₂(4.03 × 10²⁶) = log₂ 4.03 + 26·log₂ 10 ≈ 2.01 + 86.37 = 88.4 bits: more than a 56-bit DES key, and still broken by counting letters.'],
    solution: '88.4', wrong: ['26', '130', '4.03'],
    whyNot: 'Add up log₂ of every number from 2 to 26, or take log₂ of 4.03 × 10²⁶.',
  });

  ex({
    id: 'cl-x-kerckhoffs', chapter: 'cl-mono', title: 'Kerckhoffs\' principle', level: 1, kind: 'choice',
    text: ['Which statement follows Kerckhoffs\' principle?'],
    options: ['Keep the algorithm secret, and the key need not be long.', 'Assume the enemy knows the algorithm: all the secrecy must sit in the key.', 'A cipher with more than 2⁸⁰ keys is secure.', 'Change the algorithm every month, the way keys are changed.'],
    answer: 1,
    whyNot: { 0: 'Algorithms leak: machines are captured, programs copied, staff move on. A cipher that relies on a secret method fails the day the method is known.', 2: 'Substitution has 2⁸⁸ keys and falls to letter counts. A large key space is necessary, never enough.', 3: 'An algorithm is far harder to replace than a key, and it still leaks between changes.' },
    hints: ['Ask what is easiest to keep secret and to change when it leaks.', 'A key is short and can be replaced in a minute; a machine or a program cannot.', 'The second statement. Everything except the key is assumed public, and the cipher must survive that.'],
    solution: 1, wrong: [0, 2, 3],
  });

  ex({
    id: 'cl-x-keyword', chapter: 'cl-mono', title: 'A keyword alphabet', level: 1, kind: 'string', caseless: true,
    answer: K.substitution.keywordAlphabet('BLACKSMITH').alphabet,
    text: ['Write the cipher alphabet for the keyword BLACKSMITH: the keyword without repeated letters, then the unused letters in alphabetical order from A. Give all 26 letters, the cipher letter for A first.'],
    hints: ['BLACKSMITH has no repeated letter, so it gives the first 10 cipher letters as it stands.', 'The letters not in BLACKSMITH, in order: D, E, F, G, J, N, O, P, Q, R, U, V, W, X, Y, Z.', 'BLACKSMITHDEFGJNOPQRUVWXYZ. So A → B, B → L, C → A, and from Q onwards the plain and cipher letters agree.'],
    solution: 'BLACKSMITHDEFGJNOPQRUVWXYZ', wrong: [K.substitution.keywordAlphabet('BLACKSMITH', { continueFrom: true }).alphabet, 'BLACKSMITH', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'],
    whyNot: 'After the keyword, continue with the unused letters starting from A.',
  });

  const SUB_P = 'WHEN THE LAST BUS HAD GONE, THE VILLAGE SQUARE WAS EMPTY EXCEPT FOR A BOY WITH A KITE THAT WOULD NOT FLY. HE RAN FROM THE FOUNTAIN TO THE BAKERY AND BACK AGAIN WHILE THE PAPER DIAMOND BUMPED ALONG THE COBBLES BEHIND HIM. AN OLD WOMAN WATCHED FROM HER DOORWAY, THEN WALKED OVER AND TIED A LONG TAIL OF RIBBONS TO THE FRAME. THE NEXT GUST LIFTED IT HIGH OVER THE CHURCH ROOF, AND THE BOY LAUGHED SO LOUD THAT THE PIGEONS SCATTERED FROM THE BELL TOWER.';
  const SUB_C = K.substitution.encrypt(SUB_P, K.substitution.keywordAlphabet('WINDMILL SAILS', { continueFrom: true }).alphabet).out;
  ex({
    id: 'cl-x-freq-table', chapter: 'cl-mono', title: 'The first four letters', level: 1, kind: 'table', rows: ['M', 'R', 'A', 'W'], cols: ['plain letter'], corner: 'cipher', cellKind: 'text',
    cells: { 'M|plain letter': 'E', 'R|plain letter': 'T', 'A|plain letter': 'H', 'W|plain letter': 'A' },
    text: ['A substitution ciphertext of 356 letters, with its word breaks:', { code: SUB_C }, 'Its commonest letters are M (43), R (36), W (31), J (30) and A (29), and its commonest three-letter group is RAM, 13 times. W also stands alone as a word. Which plain letters do M, R, A and W stand for?'],
    hints: ['The commonest letter of English is E.', 'The commonest English three-letter word is THE, and it ends in the letter you just found.', 'M = E (43 times); RAM = THE, so R = T and A = H; W standing alone is A (it could be I, but W is too common for I and the phrase W IJY reads A BOY).'],
    solution: { 'M|plain letter': 'E', 'R|plain letter': 'T', 'A|plain letter': 'H', 'W|plain letter': 'A' },
    wrong: [{ 'M|plain letter': 'E', 'R|plain letter': 'T', 'A|plain letter': 'H', 'W|plain letter': 'I' }, { 'M|plain letter': 'T', 'R|plain letter': 'E', 'A|plain letter': 'H', 'W|plain letter': 'A' }],
  });

  ex({
    id: 'cl-x-subst-solve', chapter: 'cl-mono', title: 'Solve a substitution', level: 3, kind: 'break', target: 'plaintext', normalize: 'letters',
    answer: SUB_P,
    text: ['Now read the whole of it. The same ciphertext as before:', { code: SUB_C }, 'Type the plaintext (spaces and punctuation are ignored).'],
    hints: ['Start from M = E, R = T, A = H and W = A, and write them in. RAM appears 13 times.', 'Short words come next. RJ is a two-letter word beginning with T: TO, so J = O. LJP is then FOR (L = F, P = R), and the first word VAMH, _HE_, reads WHEN (V = W, H = N). Each guess fills letters in other words; keep the ones that make words everywhere.', 'The key alphabet is WINDMLSABCEFGHJKOPQRTUVXYZ (keyword WINDMILL SAILS, continued after S). The text begins WHEN THE LAST BUS HAD GONE, THE VILLAGE SQUARE WAS EMPTY EXCEPT FOR A BOY WITH A KITE THAT WOULD NOT FLY and ends THE PIGEONS SCATTERED FROM THE BELL TOWER.'],
    solution: SUB_P, wrong: [SUB_C, SUB_P.replace(/BELL TOWER/, 'BELL TOWEL')],
    whyNot: 'Type the whole message you read, from the first word to the last.',
  });

  // ===========================================================================================================
  // Chapter 2: Vigenère
  // ===========================================================================================================
  const VT = { P: 'SLACKWATER', K: 'TIDE' };
  const vtCells = {};
  { const c = K.vigenere.encrypt(VT.P, VT.K).out; for (let i = 0; i < VT.P.length; i++) { vtCells[(i + 1) + ' ' + VT.P[i] + '|key letter'] = VT.K[i % 4]; vtCells[(i + 1) + ' ' + VT.P[i] + '|cipher letter'] = c[i]; } }
  ex({
    id: 'cl-x-vig-table', chapter: 'cl-vig', title: 'Encrypt a column at a time', level: 1, kind: 'table', rows: Array.from(VT.P, (ch, i) => (i + 1) + ' ' + ch), cols: ['key letter', 'cipher letter'], corner: 'plain', cellKind: 'text',
    cells: vtCells,
    text: ['Encrypt SLACKWATER with the Vigenère key TIDE. For each plain letter, write the key letter above it and the cipher letter it becomes (A = 0, B = 1, …; add modulo 26).'],
    hints: ['The key repeats: T I D E T I D E T I.', 'S + T: 18 + 19 = 37 ≡ 11, which is L. L + I: 11 + 8 = 19, which is T.', 'Key letters TIDETIDETI; cipher letters L T D G D E D X X Z, so the ciphertext is LTDGDEDXXZ. The two As (letters 3 and 8) met D both times and both became D.'],
    solution: vtCells, wrong: [Object.assign({}, vtCells, { '1 S|cipher letter': 'M' })],
  });

  ex({
    id: 'cl-x-ioc-num', chapter: 'cl-vig', title: 'An index of coincidence by hand', level: 2, kind: 'number', answer: 36 / 210, tolerance: 0.0005,
    text: ['Compute the index of coincidence of SEVEN GREEN TREES (letters only): IC = Σ nᵢ(nᵢ − 1) / (N(N − 1)). Give four decimal places.'],
    hints: ['N = 15 letters. Count each letter: E appears 6 times.', 'The counts are E 6, S 2, N 2, R 2, and V, G, T once each. Letters seen once add nothing.', 'Σ nᵢ(nᵢ − 1) = 6·5 + 2·1 + 2·1 + 2·1 = 36, and N(N − 1) = 15·14 = 210. IC = 36/210 = 0.1714: far above English\'s 0.0655, as a phrase this full of Es should be.'],
    solution: '0.1714', wrong: ['0.16', '0.4', '0.0655'],
    whyNot: 'Check the denominator: N(N − 1), not N².',
  });

  ex({
    id: 'cl-x-ioc-choice', chapter: 'cl-vig', title: 'What the index says', level: 1, kind: 'choice',
    text: ['Three ciphertexts of about 400 English letters each have these indexes of coincidence. Which one was made with several alphabets, as Vigenère makes it?'],
    options: ['0.0662', '0.0413', '0.0671'],
    answer: 1,
    whyNot: { 0: '0.066 is the index of English: one alphabet only (a shift, a substitution or a transposition).', 2: '0.067 is English again, with a little chance on top: one alphabet.' },
    hints: ['A single substitution only renames letters, so it keeps the index of English, about 0.0655.', 'Several alphabets spread each plain letter over several cipher letters, pulling the index towards random letters, 0.0385.', '0.0413: between English and random, as the lighthouse message under the key LANTERN gave.'],
    solution: 1, wrong: [0, 2],
  });

  ex({
    id: 'cl-x-kasiski-len', chapter: 'cl-vig', title: 'Votes for a key length', level: 2, kind: 'number', answer: 6,
    text: ['In a Vigenère ciphertext, repeated sequences turn up at these distances apart: 30, 42, 66, 102 and 37. What is the most likely key length?'],
    hints: ['Factor each distance. One of them stands apart from the rest.', '37 is prime and divides none of the others: a coincidence. The other four are 2·3·5, 2·3·7, 2·3·11 and 2·3·17.', '2, 3 and 6 each divide the same four distances, and a key of 6 explains them all (a key of 2 or 3 would leave plenty of other repeats at distances that are not multiples of 6). The key length is 6.'],
    solution: '6', wrong: ['1', '2', '37'],
    whyNot: 'Leave out the distance that shares no factor with the others, then take the largest factor the rest have in common.',
  });

  const ioc = (text) => { const t = L(text), n = t.length; if (n < 2) return 0; const c = new Array(26).fill(0); for (const ch of t) c[ch.charCodeAt(0) - 65]++; let s = 0; for (const x of c) s += x * (x - 1); return s / (n * (n - 1)); };
  const iocCases = ['SEVEN GREEN TREES', 'A BANANA BANDANA', 'the keeper sleeps', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'Q', '', K.vigenere.encrypt('THE TIDE TURNS AT NINE AND THE BOATS GO OUT AT TEN', 'ROPE').out];
  ex({
    id: 'cl-x-code-ioc', chapter: 'cl-vig', title: 'Write the index of coincidence', level: 2, kind: 'code', fn: 'ioc', params: ['text'],
    text: ['Write `ioc(text)`: the index of coincidence of the letters of `text`, Σ nᵢ(nᵢ − 1) / (N(N − 1)). Count capital and small letters alike and ignore everything else. With fewer than two letters, return 0.', { code: 'ioc("SEVEN GREEN TREES")  →  0.17142857142857143\nioc("Q")                  →  0' }],
    start: 'function ioc(text) {\n  const counts = new Array(26).fill(0);\n  \n}',
    tests: iocCases.map((t) => ({ args: [t], want: ioc(t), check: (got) => (typeof got === 'number' && Math.abs(got - ioc(t)) < 1e-9 ? true : 'it should be ' + ioc(t)) })),
    hints: ['Upper-case the text first, then count only the characters from A to Z.', 'N is the number of letters counted, not the length of the text with its spaces.', 'function ioc(text) {\n  const counts = new Array(26).fill(0);\n  let n = 0;\n  for (const ch of text.toUpperCase()) if (ch >= \'A\' && ch <= \'Z\') { counts[ch.charCodeAt(0) - 65]++; n++; }\n  if (n < 2) return 0;\n  let s = 0;\n  for (const c of counts) s += c * (c - 1);\n  return s / (n * (n - 1));\n}'],
    solution: 'function ioc(text) {\n  const counts = new Array(26).fill(0);\n  let n = 0;\n  for (const ch of text.toUpperCase()) if (ch >= \'A\' && ch <= \'Z\') { counts[ch.charCodeAt(0) - 65]++; n++; }\n  if (n < 2) return 0;\n  let s = 0;\n  for (const c of counts) s += c * (c - 1);\n  return s / (n * (n - 1));\n}',
    wrong: [
      'function ioc(text) { const c = new Array(26).fill(0); const t = text.toUpperCase(); for (const ch of t) if (ch >= \'A\' && ch <= \'Z\') c[ch.charCodeAt(0) - 65]++; let s = 0; for (const x of c) s += x * (x - 1); return s / (t.length * (t.length - 1)); }',
      'function ioc(text) { const c = new Array(26).fill(0); let n = 0; for (const ch of text) if (ch >= \'A\' && ch <= \'Z\') { c[ch.charCodeAt(0) - 65]++; n++; } if (n < 2) return 0; let s = 0; for (const x of c) s += x * x; return s / (n * n); }',
    ],
  });

  const kasiski = (text, n) => { const out = [], first = new Map(); for (let i = 0; i + n <= text.length; i++) { const g = text.slice(i, i + n); if (first.has(g)) out.push(i - first.get(g)); else first.set(g, i); } return out.sort((a, b) => a - b); };
  const kasCases = [['ABCXXABCYYABC', 3], ['THEDOGTHECATTHE', 3], ['ABCDEFG', 3], ['AAAA', 2], [L(K.vigenere.encrypt('THE KEEPER AND THE DOG AND THE CAT WATCHED THE SEA AND THE SKY', 'OAR').out), 3]];
  ex({
    id: 'cl-x-code-kasiski', chapter: 'cl-vig', title: 'Write Kasiski\'s distances', level: 3, kind: 'code', fn: 'kasiski', params: ['text', 'n'],
    text: ['Write `kasiski(text, n)`. `text` is capital letters only. For every run of n letters that occurs more than once, take the distance from its first occurrence to each later one. Return all these distances in one array, sorted from smallest to largest (a distance found twice appears twice).', { code: 'kasiski("ABCXXABCYYABC", 3)  →  [5, 10]     ABC at 0, 5 and 10\nkasiski("AAAA", 2)           →  [1, 2]      AA at 0, 1 and 2' }],
    start: 'function kasiski(text, n) {\n  const first = new Map();\n  const out = [];\n  \n  return out;\n}',
    tests: kasCases.map(([t, n]) => ({ args: [t, n], want: kasiski(t, n) })),
    hints: ['Slide a window of n letters along the text: `text.slice(i, i + n)` for i from 0 to text.length − n.', 'Remember where each run was first seen in a Map; when you meet it again, push i minus that first place.', 'function kasiski(text, n) {\n  const first = new Map();\n  const out = [];\n  for (let i = 0; i + n <= text.length; i++) {\n    const g = text.slice(i, i + n);\n    if (first.has(g)) out.push(i - first.get(g)); else first.set(g, i);\n  }\n  return out.sort((a, b) => a - b);\n}'],
    solution: 'function kasiski(text, n) {\n  const first = new Map();\n  const out = [];\n  for (let i = 0; i + n <= text.length; i++) {\n    const g = text.slice(i, i + n);\n    if (first.has(g)) out.push(i - first.get(g)); else first.set(g, i);\n  }\n  return out.sort((a, b) => a - b);\n}',
    wrong: [
      'function kasiski(text, n) { const last = new Map(), out = []; for (let i = 0; i + n <= text.length; i++) { const g = text.slice(i, i + n); if (last.has(g)) out.push(i - last.get(g)); last.set(g, i); } return out.sort((a, b) => a - b); }',
      'function kasiski(text, n) { const first = new Map(), out = []; for (let i = 0; i + n <= text.length; i++) { const g = text.slice(i, i + n); if (first.has(g)) out.push(i - first.get(g)); else first.set(g, i); } return out.sort(); }',
    ],
  });

  const VA_P = 'THE OBSERVATORY ON THE HILL OPENS ONLY ON CLEAR NIGHTS. VISITORS CLIMB A SPIRAL STAIR OF ONE HUNDRED AND TWELVE STEPS TO REACH THE DOME, WHERE A BRASS TELESCOPE AS LONG AS A ROWING BOAT POINTS AT THE SKY. THE KEEPER LETS EACH CHILD TURN THE BIG WHEEL THAT ROLLS THE ROOF OPEN, AND WHEN THE STARS APPEAR THE WHOLE ROOM GOES QUIET. LAST WINTER A GIRL FROM THE FARM BELOW SPOTTED A COMET THAT NOBODY ELSE HAD SEEN, AND THE KEEPER WROTE HER NAME IN THE LOG IN RED INK.';
  const VA_C = K.groups(K.vigenere.encrypt(VA_P, 'MAPLE').out);
  const vigVerify = (cipher, plain) => (v) => { if (!v.length) return 'Type the key in letters.'; const p = K.vigenere.decrypt(cipher, v).out; return L(p) === L(plain) ? true : 'With the key ' + v + ' the text begins ' + head(p, 20) + '.'; };
  ex({
    id: 'cl-x-vig-short', chapter: 'cl-vig', title: 'Break a Vigenère ciphertext', level: 2, kind: 'break', target: 'key', normalize: 'letters',
    verify: vigVerify(VA_C, VA_P),
    text: ['An astronomy club sent this to its members, in groups of five, enciphered with Vigenère:', { code: VA_C }, 'Find the key.'],
    hints: ['Find the key length first. Kasiski\'s repeats vote most often for 5 (13 votes), and the average IC of the columns jumps for a length of 5.', 'At length 5 the columns have an average IC of 0.0703, like English (length 4 gives 0.0395, length 6 gives 0.0465). Now fit each of the 5 columns with the 26 shifts.', 'The best shifts are 12, 0, 15, 11, 4: the key is MAPLE. The message begins THE OBSERVATORY ON THE HILL OPENS ONLY ON CLEAR NIGHTS.'],
    solution: 'MAPLE', wrong: ['MAPL', 'NBQMF', 'PLEMA'],
  });

  const VB_P = 'THE LOCK KEEPER ON THE OLD CANAL RISES BEFORE DAWN TO CHECK THE GATES. EACH GATE IS A HEAVY BEAM OF OAK THAT SWINGS ON AN IRON PIN, AND THE WATER BEHIND IT PRESSES WITH THE WEIGHT OF A WHOLE VALLEY. WHEN A BARGE ARRIVES HE CLOSES THE LOWER GATES, OPENS THE SLUICES IN THE UPPER ONES, AND WAITS WHILE THE CHAMBER FILLS AND THE BOAT RISES SLOWLY LIKE A LIFT. THE BARGEMEN THROW HIM NEWS FROM THE TOWNS DOWNSTREAM, AND HE THROWS BACK APPLES FROM THE TREE BESIDE HIS COTTAGE. IN THE SPRING FLOODS THE CANAL RUNS FAST AND BROWN, AND HE STAYS UP ALL NIGHT WITH A LANTERN, WATCHING THE MARKS ON THE STONE WALL AND OPENING THE OVERFLOW WHEN THE WATER REACHES THE RED LINE. THE TOWN COUNCIL ONCE OFFERED HIM A MACHINE TO DO THE WORK, BUT HE SAID THAT A MACHINE CANNOT SMELL RAIN COMING.';
  const VB_C = K.groups(K.vigenere.encrypt(VB_P, 'NIGHTJARS').out);
  ex({
    id: 'cl-x-vig-long', chapter: 'cl-vig', title: 'A longer key', level: 3, kind: 'break', target: 'key', normalize: 'letters',
    verify: vigVerify(VB_C, VB_P),
    text: ['A canal company\'s report, enciphered with Vigenère and a longer key:', { code: VB_C }, 'Find the key. Kasiski\'s votes alone may mislead you here: check with the index of coincidence.'],
    hints: ['Kasiski gives 3 (47 votes) and 9 (46 votes) almost the same support. A key of 9 also makes every distance a multiple of 3, so both are worth testing.', 'The column ICs: at length 3 the average is 0.0469 (still mixed), at length 9 it is 0.0705 (English). Friedman\'s single-number estimate is far off here: the text is long but the key is long too.', 'With 9 columns the best χ² shifts spell NIGHTJARS. The text begins THE LOCK KEEPER ON THE OLD CANAL RISES BEFORE DAWN TO CHECK THE GATES.'],
    solution: 'NIGHTJARS', wrong: ['NIG', 'NIGHTJARSNIGHTJAR', 'JARSNIGHT'],
  });

  const AK_C = K.autokey.encrypt('SAIL AT HIGH WATER', 'MOON').out;
  ex({
    id: 'cl-x-autokey', chapter: 'cl-vig', title: 'Decrypt an autokey', level: 2, kind: 'break', target: 'plaintext', normalize: 'letters', answer: 'SAILATHIGHWATER',
    text: ['This was enciphered with the autokey cipher, primer MOON: the key is MOON followed by the plaintext itself.', { code: AK_C }, 'Decrypt it.'],
    hints: ['The first four key letters are M, O, O, N: subtract them from E, O, W, Y.', 'E − M = S, O − O = A, W − O = I, Y − N = L. The fifth key letter is the first plain letter, S.', 'S − S = A, T − A = T, then the key runs I, L, A, T, …: the message is SAIL AT HIGH WATER.'],
    solution: 'SAIL AT HIGH WATER', wrong: ['SAILATHIGHWATRE', 'SAILSTMOOR'],
    whyNot: 'After the primer, each recovered plain letter is the key four letters later.',
  });

  // ===========================================================================================================
  // Chapter 3: transposition, Playfair and the one-time pad
  // ===========================================================================================================
  const TD_P = 'THE CARPENTER MEASURED THE DOORWAY TWICE BEFORE HE CUT THE NEW FRAME FROM A PLANK OF SEASONED ELM';
  const TD = [K.vigenere.encrypt(TD_P, 'OAK').out, K.columnar.encrypt(TD_P, 'MAPLE').out, K.substitution.encrypt(TD_P, K.substitution.keywordAlphabet('MALLET', { continueFrom: true }).alphabet).out].map((t) => K.groups(t));
  ex({
    id: 'cl-x-transpo-detect', chapter: 'cl-trans', title: 'Which one only moved the letters?', level: 2, kind: 'choice',
    text: ['The same 80-letter message was enciphered three ways: with Vigenère, with a substitution, and with a columnar transposition.', { code: 'A  ' + TD[0] + '\n\nB  ' + TD[1] + '\n\nC  ' + TD[2] }, 'Which one is the transposition?'],
    options: ['A', 'B', 'C'], answer: 1,
    whyNot: { 0: 'A has a flat count (E and O 8 each) and an index of 0.045: several alphabets, so Vigenère.', 2: 'C has a peaked count like English, but its commonest letters are T, I and M: letters were replaced, so a substitution.' },
    hints: ['A transposition keeps every letter, so its commonest letters are English\'s commonest.', 'Count the Es in each. A transposition of English text keeps E on top.', 'B: E 16, A 7, R 7, O 6, T 6, exactly the counts of the plaintext. C has the same peaked shape (index 0.0731) but T, I and M on top, and A is flat (index 0.0446).'],
    solution: 1, wrong: [0, 2],
  });

  const RAIL_C = K.railfence.encrypt('THE SIGNAL BOX IS LOCKED AT NIGHT', 4).out;
  ex({
    id: 'cl-x-rail', chapter: 'cl-trans', title: 'Take down a rail fence', level: 2, kind: 'break', target: 'plaintext', normalize: 'letters', answer: 'THESIGNALBOXISLOCKEDATNIGHT',
    text: ['A rail fence with 4 rails gave:', { code: RAIL_C }, 'Decrypt it.'],
    hints: ['On 4 rails the zigzag repeats every 6 letters (down 3, up 3). Count how many of the 27 letters fall on each rail.', 'Rail 1 gets letters 1, 7, 13, 19, 25 (5 letters); rail 2 gets 9; rail 3 gets 9; rail 4 gets 4. Cut the ciphertext into TNIEG | HGAXSKDIH | EILOLCANT | SBOT.', 'Walk the zigzag taking the next letter from each rail in turn: T H E S I G N A L B O X …: THE SIGNAL BOX IS LOCKED AT NIGHT.'],
    solution: 'THE SIGNAL BOX IS LOCKED AT NIGHT', wrong: ['THESIGNALBOXISLOCKEDATNIHGT', 'TNIEGHGAXSKDIHEILOLCANTSBOT'],
    whyNot: 'Count the letters on each rail first: the zigzag on 4 rails repeats every 6 letters.',
  });

  const COL_C = K.columnar.encrypt('DIG UNDER THE THIRD APPLE TREE FROM THE GATE', 'GARDEN').out;
  ex({
    id: 'cl-x-columnar', chapter: 'cl-trans', title: 'Undo a columnar transposition', level: 2, kind: 'break', target: 'plaintext', normalize: 'letters', answer: 'DIGUNDERTHETHIRDAPPLETREEFROMTHEGATE',
    text: ['A treasure note, written in rows under the key GARDEN and read off column by column in the alphabetical order of the key letters:', { code: K.groups(COL_C, 6) }, 'Decrypt it.'],
    hints: ['36 letters under 6 key letters: 6 full rows, so every column has 6 letters.', 'The key letters in order are A (column 2), D (4), E (5), G (1), N (6), R (3). So the first 6 cipher letters are column 2, the next 6 column 4, and so on.', 'Cut the ciphertext into six pieces of 6: IRILFE is column 2, UHDTOA column 4, NEARMT column 5, DEHPEH column 1, DTPETE column 6 and GTRERG column 3. Put the columns back in order and read across the rows: DIGUND ERTHET HIRDAP PLETRE EFROMT HEGATE, that is DIG UNDER THE THIRD APPLE TREE FROM THE GATE.'],
    solution: 'DIG UNDER THE THIRD APPLE TREE FROM THE GATE', wrong: [COL_C, 'DIGUNDERTHETHIRDAPPLETREEFROMTHEGAET'],
    whyNot: 'Work out the column order from GARDEN first, then fill the columns in that order.',
  });

  const PF = K.playfair.square('CANDLEWICK');
  const pfCells = {};
  for (let r = 0; r < 5; r++) for (let c = 0; c < 5; c++) pfCells['row ' + (r + 1) + '|' + (c + 1)] = PF.square[5 * r + c];
  ex({
    id: 'cl-x-playfair-square', chapter: 'cl-trans', title: 'Fill in a Playfair square', level: 1, kind: 'table', rows: ['row 1', 'row 2', 'row 3', 'row 4', 'row 5'], cols: ['1', '2', '3', '4', '5'], cellKind: 'text',
    cells: pfCells,
    text: ['Fill in the Playfair square for the keyword CANDLEWICK: the keyword without repeated letters, row by row, then the rest of the alphabet in order. I and J share a cell: write I.'],
    hints: ['Write CANDLEWICK without its repeats: C, A, N, D, L, E, W, I, then C again (dropped), then K: CANDLEWIK.', 'That is 9 letters: CANDL on row 1, EWIK on row 2, and the alphabet continues with B, F, G, H, M, O, …', 'CANDL / EWIKB / FGHMO / PQRST / UVXYZ.'],
    solution: pfCells, wrong: [Object.assign({}, pfCells, { 'row 2|5': 'J' })],
  });

  ex({
    id: 'cl-x-playfair-pairs', chapter: 'cl-trans', title: 'Encrypt with Playfair', level: 2, kind: 'string', caseless: true,
    answer: K.playfair.encrypt('HIDE THE KEY', 'CANDLEWICK').out,
    text: ['With the CANDLEWICK square (CANDL / EWIKB / FGHMO / PQRST / UVXYZ), encrypt HIDE THE KEY. Write the ten cipher letters.'],
    hints: ['The pairs are HI DE TH EK EY. No pair has a doubled letter and the length is even, so no X is needed.', 'HI: H is row 3, column 3; I is row 2, column 3: the same column, so each moves down one: R and H. DE: a rectangle, the other corners on their own rows: C and K.', 'HI → RH, DE → CK, TH → RO, EK → WB (same row, move right), EY → KU. The ciphertext is RHCKROWBKU.'],
    solution: 'RHCKROWBKU', wrong: ['RHCKROWBUK', 'HIDETHEKEY'],
    whyNot: 'Split into HI DE TH EK EY and apply the row, column or rectangle rule to each pair.',
  });

  const OTP_PAD = K.otp.pad(13, K.rng(77)), OTP_C = K.otp.letters('HOLD THE BRIDGE', OTP_PAD).out;
  ex({
    id: 'cl-x-otp-pad', chapter: 'cl-trans', title: 'Find the pad', level: 1, kind: 'string', caseless: true, answer: OTP_PAD,
    text: ['A one-time pad turned HOLDTHEBRIDGE into ' + OTP_C + ' (c = p + k mod 26, letter by letter). Which pad letters were used?'],
    hints: ['k = c − p (mod 26), letter by letter.', 'S − H = 18 − 7 = 11, which is L. P − O = 15 − 14 = 1, which is B.', 'The pad is ' + OTP_PAD + '. Knowing a plaintext and its ciphertext gives the pad, which is harmless only because the pad is never used again.'],
    solution: OTP_PAD, wrong: [K.otp.letters('HOLDTHEBRIDGE', OTP_C).out, 'HOLDTHEBRIDGE'],
    whyNot: 'Subtract the plain letter from the cipher letter, not the other way round.',
  });

  const P6 = K.otp.bytePad(6, K.rng(606)), XC1 = K.otp.bytes(enc('signal'), P6).out, XC2 = K.otp.bytes(enc('silent'), P6).out;
  const XX = hex(XC1.map((v, i) => v ^ XC2[i]));
  ex({
    id: 'cl-x-xor-hex', chapter: 'cl-trans', title: 'XOR two ciphertexts', level: 1, kind: 'hex', answer: XX,
    text: ['Two six-byte words were XORed with the same pad.', { code: 'c₁ = ' + hex(XC1) + '\nc₂ = ' + hex(XC2) }, 'Compute c₁ ⊕ c₂, byte by byte, in hex.'],
    hints: ['XOR each pair of bytes; equal bytes give 00.', 'The first two bytes are equal in both, so they give 00 00. Then 83 ⊕ 88 = 0b.', 'c₁ ⊕ c₂ = ' + XX + '. That is "signal" ⊕ "silent": the pad is gone, and the two 00s say the words share their first two letters.'],
    solution: XX, wrong: [hex(XC1), XX.replace(/18$/, '81')],
  });

  const TT1 = 'the ferry leaves at noon today', TT2 = 'bring the spare oars and rope';
  const TTP = K.otp.bytePad(30, K.rng(3141)), TC1 = K.otp.bytes(enc(TT1), TTP).out, TC2 = K.otp.bytes(enc(TT2), TTP).out;
  ex({
    id: 'cl-x-two-time', chapter: 'cl-trans', title: 'A pad used twice', level: 3, kind: 'break', target: 'plaintext', normalize: 'caseless', answer: TT2,
    text: ['A harbour office XORed two messages, small letters and spaces, with the same 30-byte pad.', { code: 'c₁ = ' + hex(TC1) + '\nc₂ = ' + hex(TC2) }, 'Message 1 is known to begin with "the ferry ". Recover message 2 in full.', { sandbox: 'scratch' }],
    hints: ['c₁ ⊕ c₂ = m₁ ⊕ m₂. XOR the first 10 bytes with "the ferry " to read the first 10 bytes of message 2.', 'They read "bring the ". Guess how message 1 goes on (what does a ferry do at a time?) and how message 2 goes on (what do you bring?), and test each guess by XOR: a right guess on one side gives readable text on the other.', 'Message 1 is "the ferry leaves at noon today" and message 2 is "bring the spare oars and rope". Each guess at one revealed more of the other.'],
    solution: TT2, wrong: [TT1, 'bring the spare oars and robe'],
    whyNot: 'Message 2 is the one that begins "bring the "; give it in full.',
  });

  // ===========================================================================================================
  // Chapter 4: the Enigma wing
  // ===========================================================================================================
  const LAMP = { order: ['III', 'I', 'V'], reflector: 'B', rings: 'AAA', window: 'LAP', plugs: 'AT GK' };
  ex({
    id: 'cl-x-enigma-lamp', chapter: 'cl-enigma', title: 'Which lamp lights?', level: 2, kind: 'string', caseless: true, answer: E.machine(LAMP).press('K').out,
    text: ['Set Enigma I to rotors III I V, reflector B, rings AAA, window LAP and two cables, A–T and G–K. Press K once. Which lamp lights?', { enigmaLab: LAMP, view: 'path', title: 'Open the signal path set like this', text: 'Rotors III I V at LAP, cables AT GK. Press K and follow the current.' }],
    hints: ['The right rotor steps first: the window becomes LAQ. Then K enters the plugboard and the cable K–G sends it in as G.', 'The current goes G → P → H → V through the three rotors, the reflector sends V back as W, and the way back gives S, S, P.', 'P has no cable, so lamp P lights. Pressing P at LAQ would light K.'],
    solution: 'P', wrong: ['K', 'G', 'Q'],
    whyNot: 'Remember that the rotors step before the current flows, and that the cable acts on the way in and on the way out.',
  });

  ex({
    id: 'cl-x-noself', chapter: 'cl-enigma', title: 'Where a crib cannot sit', level: 1, kind: 'choice',
    text: ['An analyst believes the word KETTLE is in an Enigma message. Under which stretch of ciphertext could it sit?'],
    options: ['XKTRAE', 'MBQZOE', 'PRUNDW', 'KQWAPH'],
    answer: 2,
    whyNot: { 0: 'The third letter: KETTLE\'s T would stand over a T.', 1: 'The last letter: KETTLE\'s E would stand over an E.', 3: 'The first letter: KETTLE\'s K would stand over a K.' },
    hints: ['Enigma never encrypts a letter to itself.', 'Write KETTLE under each stretch and look for a letter standing over the same letter.', 'Only PRUNDW has no letter in common position with KETTLE. The others have T over T, E over E and K over K.'],
    solution: 2, wrong: [0, 1, 3],
  });

  ex({
    id: 'cl-x-plug-count', chapter: 'cl-enigma', title: 'Six cables', level: 2, kind: 'number', answer: '100391791500',
    text: ['Early on, operators plugged 6 cables. In how many ways can 6 cables join 12 of the 26 letters in pairs?'],
    hints: ['Choose the 12 plugged letters, then pair them up; the order of the cables and of the two ends does not matter.', 'The count is 26! / ((26 − 12)!·6!·2⁶).', '26! / (14!·720·64) = 100,391,791,500, about 10¹¹. With 10 cables it is 150,738,274,937,250.'],
    solution: '100391791500', wrong: ['150738274937250', '7905853580625', '1'],
    whyNot: 'Divide 26! by 14! for the letters left unplugged, by 6! for the order of the cables and by 2⁶ for the two ends of each.',
  });

  ex({
    id: 'cl-x-double-step', chapter: 'cl-enigma', title: 'When does the left rotor move?', level: 2, kind: 'number', answer: 5,
    text: ['Rotors V IV III (left to right) start at BIS. Rotor IV carries its neighbour when J is in its window, rotor III when V is. After how many key presses does the left rotor first move?', { enigmaLab: { order: ['V', 'IV', 'III'], rings: 'AAA', window: 'BIS', plugs: '' }, view: 'inside', title: 'Watch it inside', text: 'Rotors V IV III at BIS: press keys and count.' }],
    hints: ['Presses 1 to 3 move only the right rotor: BIT, BIU, BIV.', 'Press 4: the right rotor shows V, so the middle rotor steps: BJW. Now the middle rotor shows its notch J.', 'Press 5: the double step. The middle rotor moves again and takes the left one with it: CKX. The answer is 5.'],
    solution: '5', wrong: ['4', '26', '6'],
    whyNot: 'Step the window one press at a time: the middle rotor moves when the right one shows V, and again on the next press when it shows its own notch J.',
  });

  ex({
    id: 'cl-x-period', chapter: 'cl-enigma', title: 'The period of the rotors', level: 2, kind: 'number', answer: 16900,
    text: ['With the double step, after how many key presses do the three rotors of Enigma I first return to where they started (from a position in the main cycle)?'],
    hints: ['An odometer would need 26³ = 17,576 presses.', 'The double step makes the middle rotor skip one position each time it carries the left rotor: it cycles in 25 steps of the right rotor\'s 26, not 26.', '26 (right) × 25 (middle) × 26 (left) = 16,900.'],
    solution: '16900', wrong: ['17576', '676', '16926'],
    whyNot: 'The double step costs the middle rotor one position in each of its rounds.',
  });

  const RJ = E.rejewski, RJC = { order: ['III', 'V', 'I'], reflector: 'B', rings: 'AAA', window: 'HLD', plugs: 'AQ BW CE DR FT GY' };
  const AD = Array.from(RJ.products(RJ.sixPermutations(RJC).perms).AD, (v) => E.ABC[v]).join('');
  const lens = (t) => (String(t).match(/\d+/g) || []).map(Number).sort((a, b) => b - a).join(' ');
  ex({
    id: 'cl-x-rejewski', chapter: 'cl-enigma', title: 'Cycles of a day', level: 2, kind: 'string',
    accept: (t) => { const g = lens(t); if (!g) return 'List the cycle lengths as numbers, like 13 13.'; const sum = g.split(' ').reduce((a, b) => a + Number(b), 0); if (sum !== 26) return 'The lengths should add up to 26, one for every letter; yours add up to ' + sum + '.'; return g === '11 11 2 2'; },
    text: ['From a day\'s indicators, the product AD takes each letter of the top row to the letter beneath it:', { code: E.ABC + '\n' + AD }, 'Follow the letters round and give the lengths of all the cycles of AD (for example 13 13).'],
    hints: ['Start at A: A → O → C → Q → … and keep going until you are back at A.', 'A → O → C → Q → T → G → Z → Y → S → H → W → A: 11 letters. Then start again from a letter not yet used, such as B.', 'The cycles are (AOCQTGZYSHW) (BMLENUIFVJP) (DR) (KX): lengths 11 11 2 2, in equal pairs, as every AD must be.'],
    solution: '11 11 2 2', wrong: ['11 11 4', '22 2 2', '11 11 1 1'],
    whyNot: 'Check every letter is in exactly one cycle.',
  });

  const AL_KEY = E.randomKey(E.rng('cl-x-align-3'), { pairs: 10 }), AL_C = E.encrypt(AL_KEY, 'TODAYGALEWARNINGINFORCE').slice(0, 20);
  ex({
    id: 'cl-x-crib-align', chapter: 'cl-enigma', title: 'Places a crib cannot take', level: 2, kind: 'set',
    answer: '{' + E.bombe.align(AL_C, 'GALEWARNING').offsets.filter((o) => !o.ok).map((o) => o.offset).join(', ') + '}',
    text: ['An Enigma intercept begins:', { code: AL_C }, 'The analyst expects GALEWARNING somewhere in these 20 letters, at an offset from 0 (under the first letter) to 9. Which offsets are ruled out because a crib letter would stand over the same cipher letter? Answer as a set, like {1, 4}.'],
    hints: ['Write GALEWARNING under the ciphertext at offset 0, then slide it one place at a time, ten placements in all.', 'At offset 2 the L of GALE stands over an L; at offset 3 the E stands over an E.', 'Offsets 2 (L over L), 3 (E over E) and 9 (E over E) are ruled out: {2, 3, 9}. The crib really sits at offset 5, one of the seven left.'],
    solution: '{2, 3, 9}', wrong: ['{2, 3}', '{0, 1, 4, 5, 6, 7, 8}', '{5}'],
  });

  const MN_KEY = E.randomKey(E.rng('cl-x-menu-1'), { pairs: 10 }), MN_C = E.encrypt(MN_KEY, 'RAINSPREADINGEASTWARDLATER').slice(0, 13);
  ex({
    id: 'cl-x-menu-loops', chapter: 'cl-enigma', title: 'Count the loops of a menu', level: 3, kind: 'number', answer: E.bombe.menu('RAINSPREADING', MN_C, 0).main.loops,
    text: ['The crib RAINSPREADING sits under the first 13 letters of an intercept:', { code: 'cipher  ' + MN_C.split('').join(' ') + '\ncrib    ' + 'RAINSPREADING'.split('').join(' ') }, 'Draw the menu: one edge from each crib letter to the cipher letter above it. How many independent loops does its largest connected group have?'],
    hints: ['The edges are R–O, A–V, I–D, N–V, S–Z, P–K, R–G, E–C, A–V, D–C, I–C, N–E, G–I.', 'The largest group joins A, C, D, E, G, I, N, O, R and V: 10 letters, held together by 11 edges.', 'Loops = edges − letters + 1 = 11 − 10 + 1 = 2: I → C → D → I, and A–V taken twice (positions 2 and 9), a loop of two edges.'],
    solution: '2', wrong: ['1', '0', '3'],
    whyNot: 'A connected group of L letters needs L − 1 edges to hang together; every edge beyond those closes a loop.',
  });

  const ST = { seed: 'cl-x-enigma-start-58', crib: 'FERRYTIMETABLEFOR', plain: 'FERRYTIMETABLEFORSATURDAYFIRSTBOATLEAVESATSEVENLASTBOATRETURNSATTENNOSAILINGSIFFOGCLOSESTHEHARBOUR' };
  const ST_KEY = E.randomKey(E.rng(ST.seed), { pairs: 10 }), ST_C = E.encrypt(ST_KEY, ST.plain);
  ex({
    id: 'cl-x-enigma-start', chapter: 'cl-enigma', title: 'Find the message start with the Bombe', level: 3, kind: 'break', target: 'start position', normalize: 'letters',
    verify: (v) => { if (v.length !== 3) return 'The start is three letters, the window of the left, middle and right rotors.'; const p = E.encrypt(Object.assign({}, ST_KEY, { window: v }), ST_C); return p === ST.plain ? true : 'From ' + v + ' with rings ' + ST_KEY.rings + ' the message begins ' + p.slice(0, 12) + '.'; },
    text: ['The ferry company\'s key sheet gives today\'s rotors ' + ST_KEY.order.join(' ') + ', reflector B, rings ' + ST_KEY.rings + ' and cables ' + ST_KEY.plugs + '. Each operator picks his own start for each message. This one begins with FERRYTIMETABLEFOR:', { code: E.groups(ST_C) },
      { bombeLab: { seed: ST.seed, plain: ST.plain, crib: ST.crib, offset: 0 }, title: 'Open the Bombe with the crib FERRYTIMETABLEFOR', text: 'Loads this intercept and its crib at place 0. Run it, solve the stop that checks out, and read off the cores.' },
      'What was the start (the window letters with rings ' + ST_KEY.rings + ')?'],
    hints: ['Run the Bombe with the crib at place 0. Its good stop gives rotors II III IV and a key with rings AAB, start HNO: the Bombe cannot see the left ring and sets it to A.', 'Ring and window together fix the core: core = window − ring, letter by letter (A = 0). With rings AAB and start HNO, the cores are H, N and N.', 'With today\'s rings KSB the window is core + ring: H + K = R, N + S = F, N + B = O. The start is RFO, and the message reads FERRY TIMETABLE FOR SATURDAY, FIRST BOAT LEAVES AT SEVEN…'],
    solution: 'RFO', wrong: ['HNO', 'HNN', 'RFP'],
  });

  // ---- what the diagram checker looks at: a few exercises of this part ---------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'cl exercise cl-x-vig-table')) {
    for (const id of ['cl-x-vig-table', 'cl-x-playfair-square', 'cl-x-code-ioc', 'cl-x-two-time', 'cl-x-enigma-start', 'cl-x-transpo-detect', 'cl-x-rejewski']) S.Checks.push({ group: 'learn', name: 'cl exercise ' + id, hash: 'exercise=' + id, ready: "document.querySelector('#exerciseView') && window.__siferReady", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
