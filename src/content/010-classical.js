// Part 1, classical ciphers, cryptanalysis and the Enigma wing: the chapters and the lessons. The exercises are in
// 011-classical-ex.js; the CTF challenges, the tour and the course in 012-classical-ctf.js. Each lesson opens with a
// question, runs the topic that shows the idea at a frame chosen for the point being made, asks for a prediction,
// sums up and leads to its exercises. The Enigma lessons send the reader to the machine, its inside view and the
// Bombe, set up for the moment. Every number was worked out by the engines (S.Classic, S.Enigma).
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('cl-shift')) return;
  const X = (id) => ({ exercise: id });
  const RJ = { order: 'III I II', window: 'MJA' }; // the day of the Rejewski lesson: its cycles draw clearly at any size

  /** the message the Bombe lab of the last lesson loads (its key comes from the seed, so it never needs storing) */
  S.ClassicLab = { bombe: { seed: 'cl-lab-bombe-6', crib: 'REPORTFROMTHENORTH', offset: 0, plain: 'REPORTFROMTHENORTHLIGHTSEAFOGTHICKENINGVISIBILITYUNDERONEMILESHIPSINTHEROADSSTAYATANCHOR' } };

  C.chapter({ id: 'cl-mono', part: 'classical', n: 1, title: 'Shift, affine and substitution', blurb: 'One fixed alphabet for the whole message: keys you can try one by one, a key space too large to try, and the letter counts that give it away anyway.' });
  C.chapter({ id: 'cl-vig', part: 'classical', n: 2, title: 'Vigenère, broken in three moves', blurb: 'A key of several shifts that flattens the counts, and the three moves that undo it: Kasiski\'s repeats, the index of coincidence and a fit per column.' });
  C.chapter({ id: 'cl-trans', part: 'classical', n: 3, title: 'Transposition, Playfair and the one-time pad', blurb: 'Letters moved instead of replaced, two letters at a time on a square, and the one cipher that cannot be broken until somebody uses its pad twice.' });
  C.chapter({ id: 'cl-enigma', part: 'classical', n: 4, title: 'The Enigma wing', blurb: 'One key press through plugboard, rotors and reflector; the pawls and the double step; Rejewski\'s cycles; and the Bombe that turned a guessed phrase into the day\'s key.' });

  // =========================================================================================================
  // Chapter 1: shift, affine and substitution
  // =========================================================================================================
  C.lesson({
    id: 'cl-shift', chapter: 'cl-mono', title: 'The shift cipher and brute force', minutes: 6,
    summary: 'A shift moves every letter the same number of places round the alphabet. It has 26 keys, so anyone who knows the method tries them all and keeps the one that reads as English.',
    blocks: [
      'A note under a café table reads KYV EZXYK KIRZE KF KYV TFRJK. Nobody would call that hard to read once you suspect each letter has simply been moved along the alphabet. How many guesses would it take, at most, and how would you know which one is right?',
      { def: 'Shift cipher', text: 'number the letters A = 0 … Z = 25 and add a fixed key k to each, modulo 26: c = p + k. Decryption subtracts it: p = c − k. With k = 3 it is the cipher said to have been used by Julius Caesar.' },
      { topic: 'p01-shift', frame: 1, caption: 'Shift 3 as two rings: the outer ring is the plain alphabet, and the inner ring has been turned 3 places, so each plain letter sits over the letter that replaces it. A→D, B→E, and at the end of the alphabet X, Y, Z wrap round to A, B, C.' },
      'With k = 3, MEET ME AT THE OLD BOATHOUSE becomes PHHWPHDWWKHROGERDWKRXVH. Cipher clerks dropped the spaces, so that word lengths would not give the message away.',
      { predict: { q: 'Encrypt a message with shift 13, then encrypt the result with shift 13 again. What comes out?', options: ['A message shifted by 13', 'The original message', 'A message shifted by 26 that reads differently', 'It depends on the message'], answer: 1, explain: '13 + 13 = 26 ≡ 0 (mod 26): two shifts of 13 are no shift at all. Shift 13 is its own inverse, which is why it was used on message boards to hide spoilers, never secrets.' } },
      { h: 'Try every key' },
      'Kerckhoffs\' principle, the subject of the next lesson, says to assume the enemy knows the method. Then a shift has only 26 keys, one of which (k = 0) changes nothing. Decrypting with all of them takes a person a few minutes and a computer a few microseconds. The only real question is how to recognise the right one without reading 26 candidates.',
      { topic: 'p01-brute-shift', frame: 24, caption: 'Key 23 gives THEFREIGHTBOATSWAIT…: every other key gives letter soup. Each candidate gets a score for how English it looks, here a quadgram log-likelihood per letter.' },
      { topic: 'p01-brute-shift', frame: 27, caption: 'Sorted by score: key 23 at −4.48 per letter, the runner-up at −7.09. A gap that wide means only one candidate is English.' },
      { tip: 'A score turns "does this read as English?" into a number a program can compare. A quadgram score adds up how common each run of four letters is in English. On very short texts every score is noisy: try the preset "Very short: four letters" and watch the gap vanish.' },
      { h: 'Recap' },
      { list: ['A shift adds the same key k to every letter, modulo 26.', 'There are 26 keys, so brute force is instant once the method is known.', 'A score of how English a text looks picks the right key without a human reading every candidate.'] },
      X('cl-x-shift-key'), X('cl-x-shift-code'),
    ],
  });

  C.lesson({
    id: 'cl-affine', chapter: 'cl-mono', title: 'Affine, substitution and the size of a key space', minutes: 8,
    summary: 'The affine cipher multiplies before it shifts, and only multipliers coprime to 26 can be undone: 312 keys. A keyword alphabet allows any of 26! orderings. Kerckhoffs\' principle says to count keys, and a large count is necessary but never enough.',
    blocks: [
      'If 26 keys are too few, make more. Multiply each letter by a number before adding: c = a·p + b. Does any multiplier work? Try a = 2 in your head: A = 0 goes to 0 and N = 13 goes to 26 ≡ 0 as well. Two letters land on the same cipher letter, and nobody could tell them apart again.',
      { topic: 'p01-affine', frame: 1, caption: 'With a = 5 and b = 8 the 26 letters land on 26 different letters, INSXCHMRWBGLQVAFKPUZEJOTYD, because gcd(5, 26) = 1.' },
      { topic: 'p01-affine', frame: 13, caption: 'To decrypt, undo the multiplication with the inverse of 5 modulo 26. Extended Euclid finds 5·(−5) ≡ 1, so the inverse is −5 mod 26 = 21. Part 2 shows this algorithm at any size.' },
      { predict: { q: 'Which of these multipliers gives a working affine cipher modulo 26?', options: ['4', '9', '13', '26'], answer: 1, explain: '9 shares no factor with 26 = 2·13, so it has an inverse (3, since 9·3 = 27 ≡ 1). 4 and 26 share the factor 2, and 13 shares 13: each sends two letters to one.' } },
      { topic: 'p01-affine', frame: 17, caption: 'The 12 multipliers coprime to 26 (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25) times 26 shifts make 312 keys. Still few enough to try all of them in a blink.' },
      { h: 'Any alphabet at all' },
      'Stop asking for a formula: let the key be any rearrangement of the alphabet. A keyword makes one easy to remember: write the keyword without repeats, then the unused letters in order.',
      { topic: 'p01-substitution', frame: 3, caption: 'The keyword LIGHTHOUSE KEEPER gives the cipher alphabet LIGHTOUSEKPRABCDFJMNQVWXYZ: write the keyword without its repeats, then the rest of the alphabet.' },
      { topic: 'p01-substitution', frame: 11, caption: '26! orderings, about 4.03 × 10²⁶ keys. Yet every E of the message still becomes the same cipher letter.' },
      { h: 'Kerckhoffs\' principle: count the keys' },
      { def: 'Kerckhoffs\' principle', text: 'a cipher must stay secure when the enemy knows everything about it except the key. Machines are captured and programs are copied; a key is short and can be changed.' },
      { topic: 'p01-kerckhoffs', frame: 5, caption: 'At a billion keys a second, all 26! substitution keys would take about 1.3 × 10¹⁰ years.' },
      { topic: 'p01-kerckhoffs', frame: 7, caption: 'And yet: substitution has more keys than Enigma, and falls to a page of counting. Every cipher in red has a shortcut that ignores most of its keys. Key space is a floor, not a guarantee.' },
      { h: 'Recap' },
      { list: ['Affine: c = a·p + b, with gcd(a, 26) = 1 so that a has an inverse; 12·26 = 312 keys.', 'Substitution: any of the 26! ≈ 4.03 × 10²⁶ orderings of the alphabet.', 'Assume the method is known. Then count the keys, and look for a shortcut that skips most of them.'] },
      X('cl-x-affine-inv'), X('cl-x-affine-key'), X('cl-x-keyspace-29'), X('cl-x-subst-bits'), X('cl-x-kerckhoffs'), X('cl-x-keyword'),
    ],
  });

  C.lesson({
    id: 'cl-frequency', chapter: 'cl-mono', title: 'Frequency analysis', minutes: 9,
    summary: 'A substitution changes the letters but not how often each one occurs. Match the counts with English, use THE and the short words, and the message reads itself; a hill climber does the same by swapping key letters while the text grows more English.',
    blocks: [
      'You hold 401 letters of a substitution cipher. Trying keys is hopeless: there are more of them than grains of sand on every beach. But the cipher writes every E with the same letter, every T with the same letter, and English uses E far more than Q. What would you count first?',
      { topic: 'p01-frequency', frame: 1, caption: 'The cipher letters ranked by count: H 49, P 45, N 35, W 30, I 29, J 25. English\'s most common letters are E, T, A, O, I, N.' },
      { topic: 'p01-frequency', frame: 3, caption: 'H makes up 12.2% of the text, close to E\'s 12.7% in English. The first guess: H = E.' },
      { predict: { q: 'The commonest three-letter group is PNH, 18 times, and H is already taken as E. What is PNH most likely to be?', options: ['AND', 'THE', 'ARE', 'ONE'], answer: 1, explain: 'THE is by far the commonest English trigram, and it ends in E. So P = T and N = H, and three letters of the key fall at once.' } },
      { topic: 'p01-frequency', frame: 4, caption: 'P = T and N = H. Half-words begin to appear, and each one suggests the next letter.' },
      { topic: 'p01-frequency', frame: 13, caption: 'Solved: THE KEEPER CLIMBED THE STAIRS AT MIDNIGHT… Ranks alone were only a first guess (W came fourth but is A, not O); the words did the rest.' },
      { tip: 'Beyond single letters: a one-letter word is A or I; doubled letters are often LL, EE, SS or OO; and the commonest two-letter words are OF, TO, IN, IT and IS. Try the topic with the preset "The keeper, keyword ZEBRA": the counts stay the same, only the labels change.' },
      { h: 'Letting a program do the guessing' },
      'A program cannot read half-words, but it can score. Start from the frequency guess, swap two letters of the key, and keep the swap if the text scores as more English. That is hill climbing; restarts from fresh guesses keep it from sticking on a hilltop that is not the summit.',
      { topic: 'p01-substitution-solver', frame: 0, caption: 'The frequency guess gets 10 of the 24 letters in use right, and scores −2261.6 against −1459.4 for the real message.' },
      { topic: 'p01-substitution-solver', frame: 12, caption: 'After 345 tried swaps, 20 letters are right and the text almost reads: ATTHESCLENCEFALRTWOFRLENDS…' },
      { topic: 'p01-substitution-solver', frame: 14, caption: 'The climber stops at −1459.4, exactly the score of the real message. A key that reads as well as the truth is the truth, for any text of this length.' },
      { warn: 'Frequency analysis needs text. On twenty letters the counts are mostly chance and many keys read as plausibly as the right one. Every monoalphabetic cipher (shift, affine, substitution) falls to it given a paragraph.' },
      { h: 'Recap' },
      { list: ['Substitution keeps letter counts: the commonest cipher letter is probably E.', 'THE, one-letter words and doubled letters fix more letters; the half-words do the rest.', 'Hill climbing on a quadgram score solves a page of substitution in a fraction of a second.'] },
      X('cl-x-freq-table'), X('cl-x-subst-solve'),
      { challenge: 'cl-ctf-desk-letter' },
    ],
  });

  // =========================================================================================================
  // Chapter 2: Vigenère
  // =========================================================================================================
  C.lesson({
    id: 'cl-vigenere', chapter: 'cl-vig', title: 'Vigenère: one letter, many disguises', minutes: 6,
    summary: 'A Vigenère key is a word of shifts, repeated under the message. The same plain letter gets a different cipher letter depending on where it stands, which flattens the counts. Its weakness is that the key repeats.',
    blocks: [
      'Frequency analysis works because every E looks alike. What if each E were disguised differently, depending on where it stood? Use several shifts in turn, written as a key word: that is the Vigenère cipher, called "the indecipherable cipher" for about three hundred years.',
      { topic: 'p01-vigenere', frame: 0, caption: 'The key LANTERN repeats under the message. Each key letter is a shift: L = 11, A = 0, N = 13, T = 19, E = 4, R = 17.' },
      { topic: 'p01-vigenere', frame: 1, caption: 'Letter 1: M under key L. In row L of the table, under M, stands X: M + L = X.' },
      { topic: 'p01-vigenere', frame: 12, caption: 'The two Ms became X and M: one plain letter, two disguises. But plain letters seven places apart share a key letter and so share a disguise.' },
      { predict: { q: 'What is Vigenère with a key of one letter?', options: ['Unbreakable', 'A shift cipher', 'A substitution with a random alphabet', 'A one-time pad'], answer: 1, explain: 'One key letter means the same shift for every letter: a shift cipher with 26 keys. A longer key only means several shift ciphers, interleaved.' } },
      { topic: 'p01-kerckhoffs', input: { vlen: 8 }, frame: 3, caption: 'A key of 8 letters gives 26⁸ = 208,827,064,576 keys, 3 minutes of brute force at a billion a second. Longer keys push it out of reach. The real weakness is elsewhere.' },
      { bench: 'cipher', state: { algo: 'vigenere', key: 'LANTERN', text: { mode: 'text', text: 'MEET AT THE FERRY AFTER THE MARKET', hex: '' }, dir: 'enc' }, text: 'Opens the cipher bench on Vigenère with the key LANTERN: change the message or the key, then use the output as input and decrypt it.' },
      'The weakness is the repetition. Split the ciphertext into as many columns as the key has letters, and each column is a plain shift cipher. So breaking Vigenère comes down to two questions, which the next two lessons answer: how long is the key, and which shift is each column?',
      { h: 'Recap' },
      { list: ['Vigenère: c = p + k(i mod m), the key word of length m repeating.', 'One plain letter gets up to m disguises, so single-letter counts flatten.', 'Letters m apart share a key letter: m interleaved shift ciphers.'] },
      X('cl-x-vig-table'),
    ],
  });

  C.lesson({
    id: 'cl-kasiski', chapter: 'cl-vig', title: 'The key length: Kasiski and the index of coincidence', minutes: 9,
    summary: 'A repeated plain word that meets the key at the same point gives a repeated cipher sequence, a multiple of the key length apart. The index of coincidence measures how English a column looks, and the right length makes every column look English.',
    blocks: [
      'In 401 letters of Vigenère, the word THE appears dozens of times. Whenever two of them happen to sit at the same point of the key, they encrypt alike. So a repeated cipher sequence is a clue: what does the distance between the two copies tell you?',
      { h: 'First move: Kasiski\'s repeats' },
      { topic: 'p01-kasiski', frame: 5, caption: 'EHR appears at 0, 259, 294 and 371. The distances 259, 294 and 371 are all multiples of 7: each of 7\'s factors gets a vote.' },
      { topic: 'p01-kasiski', frame: 9, caption: 'Of 26 distances, 21 are multiples of 7. A few repeats are coincidences, so look for the factor most distances share, not for the gcd of them all.' },
      { predict: { q: 'Repeats sit at distances 30, 42, 66, 102 and 37. Which key length is most likely?', options: ['1, the gcd of all five', '2', '6', '37'], answer: 2, explain: '37 is a coincidence (a prime that divides nothing else). The other four are all multiples of 6, and 6 explains them better than 2 or 3, which divide the same four distances.' } },
      { h: 'Second move: the index of coincidence' },
      { def: 'Index of coincidence', text: 'the chance that two letters drawn at random from a text are the same: IC = Σ nᵢ(nᵢ − 1) / (N(N − 1)), with nᵢ the count of the i-th letter and N the length. English is about 0.0655, uniformly random letters 1/26 ≈ 0.0385.' },
      { topic: 'p01-ioc', frame: 2, caption: 'The whole ciphertext: Σ nᵢ(nᵢ − 1) = 6628 over N(N − 1) = 160400 gives 0.0413, between English and random.' },
      { topic: 'p01-ioc', frame: 4, caption: 'Friedman\'s estimate from that one number: about 9.3. A rough figure that says where to look.' },
      { topic: 'p01-ioc', frame: 11, caption: 'Split into 7 columns, every column scores like English: 0.059 to 0.094, average 0.0662. With 6 or 8 columns each column still mixes several shifts and stays near 0.040.' },
      { tip: 'A substitution leaves the IC exactly where it was, since it only relabels the counts. So an IC near 0.066 says "one alphabet" (shift, affine, substitution or transposition), and an IC near 0.04 says "several alphabets".' },
      { h: 'Recap' },
      { list: ['Kasiski: distances between repeated sequences are mostly multiples of the key length.', 'IC = Σ nᵢ(nᵢ − 1) / (N(N − 1)); English ≈ 0.0655, random ≈ 0.0385.', 'The right key length makes every column\'s IC look English.'] },
      X('cl-x-kasiski-len'), X('cl-x-ioc-num'), X('cl-x-ioc-choice'), X('cl-x-code-ioc'), X('cl-x-code-kasiski'),
    ],
  });

  C.lesson({
    id: 'cl-vig-break', chapter: 'cl-vig', title: 'Each column is a shift', minutes: 8,
    summary: 'With the key length known, each column is a shift cipher: try its 26 shifts and keep the one whose letter counts fit English best (the smallest χ²). The autokey cipher, whose key never repeats, defeats all three moves.',
    blocks: [
      'The key has 7 letters. Column 1 holds letters 1, 8, 15, …, all shifted by the same key letter. That is a shift cipher of about 57 letters: too short to read, but long enough to count. Which of the 26 shifts makes its counts look like English?',
      { def: 'χ² against English', text: 'Σ (seen − expected)² / expected over the 26 letters, where expected is the English share times the column\'s length. The smaller, the better the fit.' },
      { topic: 'p01-column-shifts', frame: 2, caption: 'Column 1: undoing a shift of 11 gives χ² = 9.5, the best of 26 by far (next 190.8). Key letter 1 is L.' },
      { topic: 'p01-column-shifts', frame: 15, caption: 'Seven columns, seven key letters: LANTERN. The text reads THE KEEPER CLIMBED THE STAIRS AT MIDNIGHT…' },
      { predict: { q: 'What happens if you split into 6 columns when the key has 7 letters?', options: ['The key comes out one letter short', 'Every column mixes several shifts, and no shift fits well', 'Nothing: χ² still finds the key', 'The key comes out reversed'], answer: 1, explain: 'With 6 columns, column 1 holds letters 1, 7, 13, …, which met different key letters. No single shift fits, so every best χ² stays large. A bad fit in every column says the length is wrong.' } },
      { topic: 'p01-column-shifts', input: { len: 6 }, frame: 2, caption: 'With the wrong length 6 even the best shift of column 1 fits badly. Compare its χ² with the 9.5 above.' },
      { h: 'A key that never repeats' },
      'Every move so far used the repetition. The autokey cipher removes it: after a short primer, the key is the message itself.',
      { topic: 'p01-autokey', frame: 0, caption: 'Primer KEY, then the plaintext: the key is KEYTHETRAINWAITSATTHEPASSINGPL.' },
      { topic: 'p01-autokey', frame: 11, caption: 'On the 401-letter message, Vigenère with key KEY leaves 43 repeat distances, 98% of them multiples of 3. Autokey leaves 5, about what chance gives. Kasiski is blind; the cipher falls instead to guessing words of the plaintext, since they are also the key.' },
      { h: 'Recap' },
      { list: ['Know the length, split into columns, fit each column\'s 26 shifts against English with χ².', 'The best χ² in each column gives one key letter; uniformly bad fits mean a wrong length.', 'Autokey never repeats its key, so Kasiski and the column split fail; guessed words break it instead.'] },
      X('cl-x-vig-short'), X('cl-x-vig-long'), X('cl-x-autokey'),
      { challenge: 'cl-ctf-ferry-note' },
    ],
  });

  // =========================================================================================================
  // Chapter 3: transposition, Playfair and the one-time pad
  // =========================================================================================================
  C.lesson({
    id: 'cl-transposition', chapter: 'cl-trans', title: 'Transposition: same letters, new places', minutes: 6,
    summary: 'A transposition keeps every letter and moves it. The letter counts stay exactly English, which gives the method away, and the key (a column order or a number of rails) is small enough to search.',
    blocks: [
      'A ciphertext has E as its commonest letter, then T, then A, and an index of coincidence of 0.066, exactly like English, yet it does not read. No substitution would leave E as E. What kind of cipher keeps the letters and only spoils the order?',
      { topic: 'p01-columnar', frame: 2, caption: 'Write the message in rows under the key HARBOUR, seven letters to a row, and number the columns in the alphabetical order of the key letters: A = 1, B = 2, H = 3, O = 4, the two Rs 5 and 6 from the left, U = 7. Column 1, under A, reads HTIG.' },
      { topic: 'p01-columnar', frame: 9, caption: 'Read the columns in that order: HTIGBKTATSSIXREHLEONNSISOANEB. The commonest letters are S 4, E 3, I 3, the counts of the plaintext exactly.' },
      { predict: { q: 'A columnar ciphertext of 29 letters was made with a key of 7 letters. How many columns are 5 letters long?', options: ['None', '1', '4', '7'], answer: 1, explain: '29 = 4·7 + 1: four full rows and one letter left over, so only the first column has a fifth letter. Knowing which columns are long is the first step in decrypting.' } },
      { bench: 'cipher', state: { algo: 'columnar', key: 'HARBOUR', text: { mode: 'text', text: 'THE BRASS TOKEN IS IN THE SIGNAL BOX', hex: '' }, dir: 'enc' }, text: 'Opens the cipher bench on columnar transposition with the key HARBOUR: try a key with a repeated letter, and decrypt the result.' },
      { h: 'The rail fence' },
      { topic: 'p01-railfence', frame: 2, caption: 'Write the message in a zigzag on 3 rails, down and up.' },
      { topic: 'p01-railfence', frame: 6, caption: 'Read rail by rail. The key is only the number of rails: an attacker tries 2, 3, 4, … and keeps the one that reads best, here 3 rails at −3.71 per letter against −6.29 for 4.' },
      { tip: 'Real systems layered a transposition on top of a substitution, so neither the counts nor the order gave much away. Modern block ciphers do the same in miniature: their rounds mix substitution with permutation (part 4).' },
      { h: 'Recap' },
      { list: ['Transposition keeps the letters, so the counts and the IC are exactly those of English.', 'Columnar: rows under a key word, read column by column in key order.', 'Rail fence: a zigzag on n rails, read rail by rail; the key space is tiny.'] },
      X('cl-x-transpo-detect'), X('cl-x-rail'), X('cl-x-columnar'),
    ],
  });

  C.lesson({
    id: 'cl-playfair', chapter: 'cl-trans', title: 'Playfair: two letters at a time', minutes: 7,
    summary: 'Playfair enciphers pairs of letters on a 5×5 square made from a keyword. A pair in a row moves right, a pair in a column moves down, and any other pair swaps to the other corners of its rectangle. Pairs hide single-letter counts, but not pair counts.',
    blocks: [
      'Single-letter counts break substitution. What if the cipher worked on pairs of letters instead? There are 600 possible pairs, and their counts are much flatter than those of single letters. Playfair, used in the field as late as the Second World War, does this with nothing but a square of letters and three rules.',
      { topic: 'p01-playfair', frame: 1, caption: 'The keyword WEATHER STATION without repeats, then the rest of the alphabet, fills the square; J shares I\'s cell, so 25 letters fit. The message is cut into pairs: a doubled pair is split by X, and an odd letter at the end gets an X.' },
      { topic: 'p01-playfair', frame: 3, caption: 'ME: M and E sit in different rows and columns. Take the other two corners of their rectangle, each on its own letter\'s row: LA.' },
      { topic: 'p01-playfair', frame: 5, caption: 'ET: same row, so each letter moves one to the right: AH. In the same column, each would move one down.' },
      { predict: { q: 'ME encrypted to LA. With the same square, what does EM encrypt to?', options: ['LA', 'AL', 'ME', 'It cannot be told'], answer: 1, explain: 'The rectangle rule is symmetric: swapping the pair swaps the result. So a pair and its reverse always encrypt to reverses of each other, one of the clues that breaks Playfair.' } },
      { topic: 'p01-playfair', frame: 19, caption: 'The ciphertext LAAHLAFUHWAWSMQCTHAV. ME appeared twice and became LA twice: pairs repeat, so pair counts can be matched with English pair counts, as single letters were.' },
      { bench: 'cipher', state: { algo: 'playfair', key: 'WEATHER STATION', text: { mode: 'text', text: 'MEET ME BY THE HILL GATE', hex: '' }, dir: 'enc' }, text: 'Opens the cipher bench on Playfair with the WEATHER STATION square: try a message with a doubled letter, such as BALLOON.' },
      { h: 'Recap' },
      { list: ['The square: the keyword without repeats, then the rest of the alphabet, I and J sharing a cell.', 'Pairs: same row → right; same column → down; otherwise → the other corners of the rectangle.', 'No letter pairs with itself, and reversed pairs encrypt to reversed pairs: both are clues for the analyst.'] },
      X('cl-x-playfair-square'), X('cl-x-playfair-pairs'),
    ],
  });

  C.lesson({
    id: 'cl-otp', chapter: 'cl-trans', title: 'The one-time pad, and the pad used twice', minutes: 9,
    summary: 'A pad of truly random letters as long as the message, used once, gives perfect secrecy: every message of that length is equally possible. Used twice, the pad cancels out: the XOR of the two ciphertexts is the XOR of the two messages, and a guessed word dragged along it reveals both.',
    blocks: [
      'Make the Vigenère key as long as the message, choose it at random and never use it again. No repeats for Kasiski, no columns to count. Is anything left to attack?',
      { topic: 'p01-otp', frame: 6, caption: 'ATTACK THE NORTH GATE plus a fresh random pad gives LBKQFPKBLOPHDJKIDB. Every cipher letter is equally likely, whatever the message letter was.' },
      { topic: 'p01-otp', frame: 8, caption: 'A different pad, just as random, turns the same ciphertext into BRING THE BOATS IN NOW. Every message of 18 letters has exactly one pad that fits: the ciphertext says nothing about which was sent.' },
      { def: 'Perfect secrecy', text: 'the ciphertext gives no information about the plaintext: every plaintext is exactly as likely after seeing it as before. The one-time pad has it, and it needs a key at least as long as the message.' },
      { warn: 'The price is the pad: truly random, as long as all the traffic, delivered in secret beforehand, and destroyed after one use. Every practical shortcut (a shorter key, a pad used twice, a pad from a weak generator) gives up the guarantee.' },
      { h: 'The pad used twice' },
      'With bytes, the pad is combined by XOR: c = m ⊕ k. Suppose the same pad encrypted two messages.',
      { math: 'c₁ ⊕ c₂ = (m₁ ⊕ k) ⊕ (m₂ ⊕ k) = m₁ ⊕ m₂' },
      { predict: { q: 'You XOR the two ciphertexts. Where did the pad go?', options: ['It is still mixed in', 'It cancelled: k ⊕ k = 0', 'It doubled', 'It became the first message'], answer: 1, explain: 'XOR with the same value twice undoes itself. The result is the two messages XORed together, with no key at all, and English XOR English has plenty of structure.' } },
      { topic: 'p01-two-time-pad', frame: 1, caption: 'c₁ ⊕ c₂ = m₁ ⊕ m₂: the pad is gone, and these bytes are just the two messages XORed together.' },
      { topic: 'p01-two-time-pad', frame: 12, caption: 'Crib-dragging: guess that one message holds " the " and slide it along. At position 10, the other message shows "urns ": readable text, so the guess fits there.' },
      { topic: 'p01-two-time-pad', frame: 24, caption: 'Each good fragment suggests a longer guess on one side, which reveals more of the other. Both messages unravel without the pad ever being found directly.' },
      { bench: 'cipher', state: { area: 'labs', lab: 'twotime' }, text: 'The two-time pad lab: drag cribs yourself over a fresh pair of messages, then let the solver recover both from the XOR alone.' },
      { tip: 'The same mistake reappears in modern dress: a stream cipher or CTR mode with a repeated nonce produces the same keystream twice, and the attack is exactly this one (part 6).' },
      { h: 'Recap' },
      { list: ['One-time pad: a random pad as long as the message, used once: perfect secrecy.', 'Used twice: c₁ ⊕ c₂ = m₁ ⊕ m₂, and the pad is gone.', 'Crib-dragging: XOR a guessed word at each position; readable text on the other side means the guess fits.'] },
      X('cl-x-otp-pad'), X('cl-x-xor-hex'), X('cl-x-two-time'),
      { challenge: 'cl-ctf-two-pads' },
    ],
  });

  // =========================================================================================================
  // Chapter 4: the Enigma wing
  // =========================================================================================================
  C.lesson({
    id: 'cl-enigma-press', chapter: 'cl-enigma', title: 'One key press through Enigma', minutes: 9,
    summary: 'A key press steps the rotors, then sends current through the plugboard, three rotors, the reflector, back through the rotors and the plugboard to a lamp. The result is a swap of 13 pairs that changes at every press, so encrypting and decrypting are the same, and no letter ever encrypts to itself.',
    blocks: [
      'Enigma is a typewriter that lights a lamp instead of printing. Press W and lamp V lights; press W again and some other lamp lights. Inside, the current runs through a fixed path whose wiring the rotors keep changing. Where does it go, and why does the same machine both encrypt and decrypt?',
      { topic: 'p01-enigma-path', frame: 1, caption: 'Stepping comes first: the key goes down, the right rotor turns from C to D, and only then does the current flow.' },
      { topic: 'p01-enigma-path', frame: 3, caption: 'In through the right rotor III: its core is turned 3 places, so contact W meets core pin Z, wired to O, and leaves at contact L.' },
      { topic: 'p01-enigma-path', frame: 6, caption: 'The reflector UKW-B sends A back as Y, and the current returns through the rotors by a different route.' },
      { topic: 'p01-enigma-path', frame: 12, caption: 'W → L → Y → A → Y → E → Z → D → V: key W lights lamp V. Pressing V at the same position would run the same path backwards and light W.' },
      { enigmaLab: { order: ['IV', 'I', 'III'], rings: 'AAA', window: 'BXC', plugs: 'IE NZ MU KF OC XS DV PL JT YG' }, view: 'path', title: 'Trace a key press yourself', text: 'Opens the signal path set to rotors IV I III at BXC with the ten cables above. Press W: lamp V lights, and the path is drawn wire by wire. Then press keys of your own.' },
      { h: 'The plugboard' },
      { topic: 'p01-enigma-plugboard', frame: 6, caption: 'Key N at BXD: the cable N–Z sends it in as Z, the rotors and reflector give F, and the cable F–K lights K. Without cables the rotors alone would give Q.' },
      { topic: 'p01-enigma-plugboard', frame: 9, caption: '150,738,274,937,250 ways to plug 10 cables. But the plugboard is the same swap σ on the way in and out, so the machine is σ·S·σ: the rotors\' substitution S with its letters renamed.' },
      { h: 'Never itself' },
      { predict: { q: 'Can Enigma ever encrypt a letter to itself?', options: ['Yes, about one letter in 26', 'Never', 'Only when no cables are plugged', 'Only during a double step'], answer: 1, explain: 'The reflector pairs every contact with a different one, so the current always comes back on another wire, and the plugboard only renames both ends. A letter never lights its own lamp.' } },
      { topic: 'p01-enigma-noself', frame: 2, caption: 'At window BXD the whole machine, cables included, is 13 swaps: AH BU CP DS EY FL GI JR KN MT OX QZ VW. E lights Y and Y lights E.' },
      { topic: 'p01-enigma-noself', frame: 3, caption: 'Over 2,000 letters, Enigma never once put a letter in place of itself, where a one-time pad did so 66 times. This one fact tells an analyst where a guessed phrase cannot sit.' },
      { h: 'Recap' },
      { list: ['Each press: step first, then plugboard → rotors → reflector → rotors → plugboard → lamp.', 'At each position the machine is a swap of 13 pairs: the same setting decrypts.', 'No letter encrypts to itself, and the plugboard σ only renames: σ·S·σ.'] },
      X('cl-x-enigma-lamp'), X('cl-x-noself'), X('cl-x-plug-count'),
    ],
  });

  C.lesson({
    id: 'cl-enigma-step', chapter: 'cl-enigma', title: 'Stepping and the double step', minutes: 7,
    summary: 'The right rotor steps at every key press. When it shows its notch letter, a pawl carries the middle rotor too; when the middle rotor shows its notch, it steps again on the next press along with the left rotor. That double step makes the period 26·25·26 = 16,900, not 26³.',
    blocks: [
      'The rotors of Enigma look like the wheels of a mileage counter: the right one turns at every press, and every 26 presses it carries the next one. But the stepping is done by three pawls pushing on notched rings, and one of them pushes two rotors at once. What does that do to the count?',
      { topic: 'p01-enigma-stepping', frame: 0, caption: 'Rotors I II III at ADT. Rotor II carries its neighbour when E is in the window, rotor III when V is.' },
      { topic: 'p01-enigma-stepping', frame: 3, caption: 'Press 3: the right rotor shows its notch V, so the middle pawl drops in. ADV becomes AEW.' },
      { predict: { q: 'The window shows AEW, and E is the middle rotor\'s notch. What does the next press show?', options: ['AEX', 'AFX', 'BFX', 'BEX'], answer: 2, explain: 'The left pawl drops into the middle rotor\'s notch and pushes it, and that pawl also pushes the left rotor: both move. The middle rotor has stepped on two presses running, the double step.' } },
      { topic: 'p01-enigma-stepping', frame: 4, caption: 'Press 4: AEW becomes BFX. The middle rotor moved again, taking the left rotor with it.' },
      { enigmaLab: { order: ['I', 'II', 'III'], rings: 'AAA', window: 'ADU', plugs: '' }, view: 'inside', title: 'Watch the pawls drop', text: 'Opens the inside view at ADU with rotors I II III. Press any key three times and watch the pawls: ADV, then AEW, then the double step to BFX.' },
      { topic: 'p01-enigma-stepping', frame: 9, caption: 'Because of the double step the rotors do not count like an odometer: a full cycle takes 16,900 presses, not 26³ = 17,576.' },
      { tip: 'The ring setting (Ringstellung) turns the wiring against the lettered ring, so it moves the notch relative to the wiring. Two settings with the same core positions encrypt alike until a rotor steps, which is why the Bombe finds core positions and leaves the rings to be worked out afterwards.' },
      { h: 'Recap' },
      { list: ['Right rotor: every press. Middle rotor: when the right shows its notch.', 'When the middle rotor shows its own notch, it steps again with the left rotor: the double step.', 'The period of the three rotors is 26·25·26 = 16,900 presses.'] },
      X('cl-x-double-step'), X('cl-x-period'),
    ],
  });

  C.lesson({
    id: 'cl-rejewski', chapter: 'cl-enigma', title: 'Rejewski\'s cycles', minutes: 8,
    summary: 'Under the early procedure each message key was typed twice. Letters 1 and 4 of every indicator then define a permutation AD of the day, whose cycle lengths come in equal pairs and do not depend on the plugboard. A catalogue of cycle lengths for every rotor position, made once without cables, gave the day\'s rotors.',
    blocks: [
      'Before 1938 an operator set his rotors to the day\'s ground setting, chose three letters as the key for his message, and typed them twice: six letters, the indicator. A day\'s traffic held a hundred indicators. Without knowing a single key, what can be learnt from the fact that letters 1 and 4 came from the same key letter?',
      { topic: 'p01-rejewski', input: RJ, frame: 3, caption: 'JWRIQR: letters 1 and 4 were both made from key letter X, at positions 1 and 4. Since each position is a swap, I = A4(A1(J)): the product AD takes J to I, whatever X was.' },
      { topic: 'p01-rejewski', input: RJ, frame: 5, caption: '120 indicators fix all 26 letters of AD: (AJIMZTDFWB) (ENVPXQYGUH), and six letters that stay where they are, C, K, L, O, R and S.' },
      { predict: { q: 'AD is the product of two swaps-only permutations. What can you say about its cycle lengths?', options: ['They are all 13', 'They come in pairs of equal length', 'They add up to 13', 'There is always a cycle of length 1'], answer: 1, explain: 'A product of two involutions without fixed points always has its cycles in equal pairs. Here 10, 10 and six cycles of length 1; another day gave 13 and 13.' } },
      { topic: 'p01-rejewski', input: RJ, frame: 8, caption: 'The day\'s characteristic, AD, BE and CF together: 10 10 1 1 1 1 1 1 | 5 5 4 4 4 4 | 6 6 5 5 1 1 1 1.' },
      { topic: 'p01-rejewski', input: RJ, frame: 9, caption: 'With the cables the cycles are renamed but keep their lengths: σ·AD·σ is a conjugate of AD. Conjugate permutations have the same cycle type, the same idea as in part 2\'s groups.' },
      { topic: 'p01-rejewski', input: RJ, frame: 10, caption: 'So a catalogue for every rotor order and position can be made once, with no cables. For order III I II, the 17,576 positions give exactly 1 match: the true ground setting MJA.' },
      { h: 'Recap' },
      { list: ['Each position of the machine is a swap; letters 1 and 4 of an indicator give the product AD.', 'Cycles of a product of two fixed-point-free swaps come in equal pairs.', 'The plugboard conjugates AD, so the cycle lengths depend on the rotors alone: catalogue them.'] },
      X('cl-x-rejewski'),
    ],
  });

  C.lesson({
    id: 'cl-bombe', chapter: 'cl-enigma', title: 'Cribs, menus and the Bombe', minutes: 10,
    summary: 'Guess a phrase of the plaintext, the crib, and slide it to places where no letter faces itself. The crib and the ciphertext make a menu: a graph whose loops let a wrong guess at the plugboard contradict itself. The Bombe tests every rotor position against the menu, stops where the guess holds, and the plugboard is read off the stop.',
    blocks: [
      'Weather stations sent a report every morning, and reports began the same way. An analyst holding the morning\'s intercept can guess the first words. With 60 rotor orders, 17,576 positions and 150 trillion plugboards, how can a guessed phrase pin down the key?',
      { h: 'Where the crib can sit' },
      { topic: 'p01-crib-align', frame: 2, caption: 'At offset 1 the crib\'s V would face a V in the ciphertext. Enigma never encrypts a letter to itself, so the crib cannot be there.' },
      { topic: 'p01-crib-align', frame: 35, caption: '24 of 34 places survive. A longer crib rules out more of them.' },
      { h: 'The menu' },
      { topic: 'p01-bombe-menu', frame: 5, caption: 'Each crib letter joined to the cipher letter under it is an edge, numbered by its place. The largest group has 12 letters, 14 edges and 3 loops.' },
      { topic: 'p01-bombe-menu', frame: 6, caption: 'Loop 1: W → R → V → W through scramblers 16, 7 and 1. Around a loop, a wrong guess at a cable contradicts itself.' },
      { predict: { q: 'The main group of a menu has 10 letters and 11 edges. How many independent loops does it have?', options: ['0', '1', '2', '11'], answer: 2, explain: 'A connected graph needs letters − 1 = 9 edges to hang together; every edge beyond that closes one more loop: 11 − 9 = 2.' } },
      { h: 'The stop' },
      { topic: 'p01-bombe-stop', frame: 1, caption: 'Assume R is plugged to itself: current on wire R of register R. Each scrambler carries the assumption to a consequence.' },
      { topic: 'p01-bombe-stop', frame: 7, caption: 'At the right position only one wire of the register is live: the assumption holds together, and the machine stops. At a wrong position the current floods all 26 wires.' },
      { topic: 'p01-bombe-deduce', frame: 12, caption: 'From the stop, 7 cables are read off. Through them the ciphertext reads WE?THERRE?ORTFOR against WEATHERREPORTFOR: 14 right, none wrong.' },
      { topic: 'p01-bombe-deduce', frame: 14, caption: 'The ring settings and the three cables the menu never touched are found by making the text read best as English: 79 of the 81 letters come out right, and a reader fixes the last two at a glance.' },
      { h: 'Lab: break a message yourself' },
      'The harbour station sends a report every morning, and the first words are always REPORT FROM THE NORTH. Open the Bombe with this crib: the intercept is loaded, the crib sits at place 0, and the menu is drawn with its loops.',
      { bombeLab: S.ClassicLab.bombe, title: 'Open the Bombe with the crib REPORTFROMTHENORTH', text: 'Loads the intercept and the crib. Run the Bombe (it searches all 60 rotor orders in a few seconds), press "Solve and load" on the stop that checks out, and read the whole report on the lamps.' },
      { steps: ['Look at step 2 of the Bombe page: is place 0 among the places the crib can sit?', 'Read the menu: which letter is the register, and how many loops does the main group have?', 'Run the Bombe. Note the rotor order and the cores of the good stop.', 'Solve and load: the machine types the intercept and the lamps read the message. What does the harbour say about the fog?'] },
      { warn: 'This Bombe, like the real one, moves only the fast drum over the crib: if the middle rotor stepped inside the crib, it finds nothing at the true place. A short crib, or another place for it, avoids the turnover.' },
      { h: 'Recap' },
      { list: ['A crib can only sit where no letter faces itself.', 'The menu joins crib and cipher letters; its loops (edges − letters + 1) make wrong guesses contradict themselves.', 'A stop gives the rotor order, the core positions and part of the plugboard; English fills in the rest.'] },
      X('cl-x-crib-align'), X('cl-x-menu-loops'), X('cl-x-enigma-start'),
      { challenge: 'cl-ctf-weather' },
    ],
  });

  // ---- what the diagram checker looks at: every lesson of this part ----------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'cl lesson cl-shift')) {
    for (const l of C.lessons.values()) if (/^cl-/.test(l.id)) S.Checks.push({ group: 'learn', name: 'cl lesson ' + l.id, hash: 'lesson=' + l.id, ready: "document.querySelector('#lessonView') && window.__siferReady", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
