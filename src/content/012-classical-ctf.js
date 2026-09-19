// Part 1, classical ciphers and the Enigma wing: the CTF challenges, the tour and the course. Each challenge's data is
// made here by the engines from a fixed seed (the key, the pad, the Enigma setting), so it is the same on every
// visit and never needs storing; each flag is kept only as its SHA-256, with the plain flag in solution for the
// content checker.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.challenges.has('cl-ctf-ferry-note')) return;
  const K = S.Classic, E = S.Enigma;
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const enc = (s) => new TextEncoder().encode(s);
  const once = (f) => { let v = null; return () => v || (v = f()); };
  // lines of at most n characters, broken at spaces, so a long note reads as a note
  const wrap = (t, n = 64) => { const out = []; let line = ''; for (const w of String(t).split(' ')) { if (line && line.length + 1 + w.length > n) { out.push(line); line = w; } else line = line ? line + ' ' + w : w; } if (line) out.push(line); return out.join('\n'); };

  // ---- 1. a Vigenère note ----------------------------------------------------------------------------------------
  const FERRY = 'TO THE NIGHT CLERK. THE MORNING FERRY WILL SAIL TWENTY MINUTES LATE TOMORROW, BECAUSE THE HARBOUR MASTER WANTS THE NEW BUOYS CHECKED BEFORE THE SPRING TIDES. PLEASE TELL THE PASSENGERS WHO ASK, BUT DO NOT POST IT ON THE BOARD, SINCE THE COMPANY DOES NOT LIKE TO ADMIT A DELAY IN WRITING. THE CAR DECK IS FULL FOR THE FIRST CROSSING, SO SEND ANY LATE VANS TO THE SECOND ONE. THE CAPTAIN ASKS THAT SOMEBODY FIXES THE BELL ON THE GANGWAY, WHICH HAS BEEN RINGING BY ITSELF IN THE WIND ALL WEEK. IF ANYONE FROM HEAD OFFICE ASKS FOR THE PASSWORD TO THE TIMETABLE FILE, IT IS SIFER{TIDE_TABLES_NEVER_LIE}. THANK YOU. THE DAY CLERK.';
  const ferry = once(() => { const r = K.rng(2611); let key = ''; for (let i = 0; i < 7; i++) key += ABC[Math.floor(r() * 26)]; return { key, cipher: K.vigenere.encrypt(FERRY, key).out }; });
  C.challenge({
    id: 'cl-ctf-ferry-note', n: 11, level: 2, points: 200,
    title: 'The night clerk\'s note',
    story: 'The ferry office keeps its notes between shifts in a tin box by the ticket window, and the day clerk enciphers hers with a Vigenère key she changes every month. She leaves the spaces and the punctuation alone, because the night clerk complained he could not find where sentences ended. Tonight\'s note mentions a password. Read it: [Kasiski](#topic=p01-kasiski), [the index of coincidence](#topic=p01-ioc) and [a fit per column](#topic=p01-column-shifts) are all you need.',
    data: () => ({ 'The note': wrap(ferry().cipher) }),
    format: 'sifer{...}', caseless: true,
    flagHash: '8df4273c3f3ef0875d9549e02116ac95c1c64e81cf2dd293f249ec7ee05ad698',
    solution: 'sifer{tide_tables_never_lie}',
    wrong: ['sifer{tide_tables}', 'tide_tables_never_lie', 'sifer{TIDE TABLES NEVER LIE}'],
    hints: [
      'A repeating key means letters a key length apart share a shift. Count the letters only (leave out spaces and punctuation), then look for repeated runs of three or four letters and the distances between them.',
      'Kasiski\'s distances and the index of coincidence of the columns both point at a key of 7. Split the letters into 7 columns and fit each column\'s 26 shifts against English with χ².',
      'The column fits give the key VRDSOHX; decrypting with it reads "TO THE NIGHT CLERK. THE MORNING FERRY WILL SAIL TWENTY MINUTES LATE…" and ends "…THE PASSWORD TO THE TIMETABLE FILE, IT IS SIFER{TIDE_TABLES_NEVER_LIE}". The flag in lower case: sifer{tide_tables_never_lie}.',
    ],
    tools: ['sandbox/scratch'],
  });

  // ---- 2. a substitution letter -------------------------------------------------------------------------------------
  const DESK = 'MY DEAR NEPHEW, THE HOUSE IS SOLD AND THE FURNITURE IS SCATTERED AMONG THE COUSINS, BUT I ASKED THAT THIS WRITING DESK SHOULD GO TO YOU, BECAUSE YOU WERE THE ONLY ONE WHO EVER SAT AT IT AND ASKED WHAT THE LITTLE DRAWERS WERE FOR. YOUR GRANDFATHER KEPT HIS STAMPS IN THE LEFT ONES AND HIS LETTERS IN THE RIGHT, AND HE NEVER LOCKED ANY OF THEM, SAYING THAT A LOCK ONLY TELLS A THIEF WHERE TO LOOK. WHAT HE DID KEEP SECRET HE HID IN PLAIN SIGHT. PRESS THE CARVED ACORN UNDER THE MIDDLE SHELF AND SEE WHAT HAPPENS. IF YOU HAVE FOUND THIS LETTER YOU WILL WANT THE WORD THAT OPENS THE REST: SIFER{FALSE_BOTTOM_DRAWER}. LOOK AFTER THE DESK, AND WRITE SOMETHING GOOD AT IT. YOUR LOVING AUNT.';
  const desk = once(() => { const alpha = K.shuffle(ABC.split(''), K.rng(1907)).join(''); return { alpha, cipher: K.substitution.encrypt(DESK, alpha).out }; });
  C.challenge({
    id: 'cl-ctf-desk-letter', n: 12, level: 2, points: 200,
    title: 'The letter in the writing desk',
    story: 'You bought an old writing desk at a house sale. Behind the smallest drawer is a folded letter in capitals that make no sense, though every word keeps its length and every comma is where a comma should be. Your great-aunt liked puzzles, and she replaced each letter of the alphabet with another, the same one every time. [Frequency analysis](#topic=p01-frequency) will open it.',
    data: () => ({ 'The letter': wrap(desk().cipher) }),
    format: 'sifer{...}', caseless: true,
    flagHash: 'f27c74c735e99b56ccc3d9febfd806845816e36fb7f3255e999f95e6bdea210e',
    solution: 'sifer{false_bottom_drawer}',
    wrong: ['sifer{false_bottom}', 'sifer{acorn}', 'false_bottom_drawer'],
    hints: [
      'Every plain letter has one cipher letter, so count them. The commonest cipher letter is probably E, and the commonest three-letter word is probably THE.',
      'The flag keeps its shape: five letters, a brace, words joined by underscores, a brace. Its first five letters are SIFER, which hands you five letters of the key at once. Fill them in everywhere and read the short words.',
      'The letter begins MY DEAR NEPHEW, THE HOUSE IS SOLD… and near the end says THE WORD THAT OPENS THE REST: SIFER{FALSE_BOTTOM_DRAWER}. In lower case, sifer{false_bottom_drawer}.',
    ],
  });

  // ---- 3. a pad used twice -----------------------------------------------------------------------------------------
  const PAD1 = 'the night boat is running late again and the cook says the tea has run out', PAD2 = 'keep the spare key under the anchor: sifer{one_pad_two_messages}';
  const pads = once(() => { const pad = K.otp.bytePad(PAD1.length, K.rng(4404)); return { c1: K.otp.bytes(enc(PAD1), pad).out, c2: K.otp.bytes(enc(PAD2), pad).out }; });
  C.challenge({
    id: 'cl-ctf-two-pads', n: 13, level: 3, points: 300,
    title: 'One pad, two messages',
    story: 'A harbour radio room bought a box of one-time pads and was told, firmly, to use each page once. Paper costs money. Two messages went out on the same evening, both XORed with the same page, small letters, spaces and a little punctuation. You have both ciphertexts, and [crib-dragging](#topic=p01-two-time-pad) is the way in.',
    data: () => ({ 'Message 1, hex': hex(pads().c1), 'Message 2, hex': hex(pads().c2) }),
    format: 'sifer{...}',
    flagHash: 'b4f1536ede994d55152cf1cf4598a2a0ef85759f3809c5487e11f6fd326a2140',
    solution: 'sifer{one_pad_two_messages}',
    wrong: ['sifer{one_pad}', 'SIFER{ONE_PAD_TWO_MESSAGES}', 'sifer{two_pads_one_message}'],
    hints: [
      'XOR the two ciphertexts byte by byte. The pad cancels: what is left is message 1 XOR message 2, as far as the shorter one goes.',
      'Drag a crib along that XOR: try " the " and, since one message must hold the flag, "sifer{". Wherever the other side turns into readable words, the crib fits. Extend each fragment with the words it suggests.',
      '"sifer{" fits at position 37: message 1 shows "and th" there. Message 1 is "the night boat is running late again and the cook says the tea has run out", and message 2 is "keep the spare key under the anchor: sifer{one_pad_two_messages}".',
    ],
    tools: ['sandbox/scratch'],
  });

  // ---- 4. Enigma and a weather crib ----------------------------------------------------------------------------------
  const WX = 'WEATHERFORECASTFORTHEOUTERISLANDSWINDSOUTHWESTFOURVEERINGWESTBYEVENINGSEAMODERATERAININTHEAFTERNOONVISIBILITYGOODFLAGCOPPERXKETTLEXSTORMXGLASSXENDS';
  const wx = once(() => E.encrypt(E.randomKey(E.rng('cl-ctf-enigma-16'), { pairs: 10 }), WX));
  C.challenge({
    id: 'cl-ctf-weather', n: 14, level: 3, points: 400,
    title: 'The weather station',
    story: 'An island weather station sends its forecast every morning on an Enigma I, reflector B, ten cables, a fresh key each day. The operator is careful about everything except habit: every forecast he has ever sent begins with the same words, WEATHER FORECAST FOR THE. This morning\'s report ends with a flag of four words, which he separated with X as operators did. Take [the Bombe](#enigma/bombe) to it. The flag is sifer{} round those four words in lower case, joined by underscores.',
    data: () => ({ 'This morning\'s intercept': (E.groups(wx()).match(/(\S+ ?){1,10}/g) || []).map((l) => l.trim()).join('\n'), 'Every forecast begins': 'WEATHERFORECASTFORTHE' }),
    format: 'sifer{...}', caseless: true,
    flagHash: '0e013471e47e7a92e0fb475598a5c28c4cc55b47bb8a8d158db03756c03c045f',
    solution: 'sifer{copper_kettle_storm_glass}',
    wrong: ['sifer{copperxkettlexstormxglass}', 'sifer{copper_kettle}', 'copper_kettle_storm_glass'],
    hints: [
      'Open the Bombe (Enigma, then the Bombe tab), paste the intercept in place of the practice message and put WEATHERFORECASTFORTHE as the crib. Place 0 is allowed: no crib letter stands over the same cipher letter there.',
      'The menu has loops, so a run over all 60 rotor orders gives very few stops. Check them, press "Solve and load" on the one that checks out, and read the lamps.',
      'The good stop is rotors I IV II; the solved key has rings AEB, start LIJ and cables AR BT CV EF HJ KL MW PY SX DG. The message ends FLAG COPPER X KETTLE X STORM X GLASS X ENDS: the flag is sifer{copper_kettle_storm_glass}.',
    ],
  });

  // ---- the tour --------------------------------------------------------------------------------------------------------
  C.tour({
    id: 'cl-tour', title: 'Tour: classical ciphers and Enigma', blurb: 'From a shift cipher to a Bombe stop, in nine steps.',
    steps: [
      { route: 'part=classical', target: '#main', text: 'Part 1 of the catalogue: classical ciphers and the Enigma wing. Each card is a topic that works one real example, step by step, with every value shown.' },
      { route: 'topic=p01-brute-shift', target: '#stageWrap', text: 'Brute force on a shift cipher: every one of the 26 keys is tried, and each candidate is scored for how English it reads. One stands far above the rest.' },
      { target: '#inputs', text: 'Every topic takes your own input. Paste a ciphertext of your own here, or pick an example.' },
      { route: 'topic=p01-frequency', target: '#stageWrap', text: 'Frequency analysis: the cipher letters ranked by count against English, and the key filled in one letter at a time.' },
      { route: 'topic=p01-ioc', target: '#stageWrap', text: 'The index of coincidence: split a Vigenère ciphertext into columns, and the right key length makes every column look like English.' },
      { route: 'enigma', target: '#enigDeck', text: 'Enigma I: press keys, watch the rotors step and the lamps light. Settings, cables and the message tape are at the side.' },
      { route: 'enigma/inside', target: '#enigInside', text: 'Inside: the pawls and the notches. Set the window to ADU on rotors I II III and press three times to see the double step.' },
      { route: 'enigma/bombe', target: '#bombeMenu', text: 'The Bombe: a crib laid against the intercept makes this menu. Its loops let a wrong guess contradict itself, and the drums test every rotor position.' },
      { route: 'learn', target: '[data-chapter="cl-mono"]', text: 'Thirteen lessons and thirty-six exercises for this part start here, and the CTF ladder has four challenges to break, the last with the Bombe.' },
    ],
  });

  // ---- the course ------------------------------------------------------------------------------------------------------
  C.course({
    id: 'cl-course', title: 'Classical ciphers and Enigma, start to finish', blurb: 'Every topic of part 1 in order, from a shift to a Bombe stop, with lessons to read and ciphers to break on the way.',
    steps: [
      { topic: 'p01-shift', note: 'Every letter moved the same distance.' },
      { topic: 'p01-brute-shift', note: 'Twenty-six keys: try them all and score each.' },
      { exercise: 'cl-x-shift-key', note: 'Your turn: a luggage label.' },
      { topic: 'p01-affine', note: 'Multiply, then shift; only some multipliers can be undone.' },
      { topic: 'p01-substitution', note: 'Any rearranged alphabet: 26! keys.' },
      { topic: 'p01-kerckhoffs', note: 'Assume the method is known, and count the keys.' },
      { lesson: 'cl-affine', note: 'Affine keys, keyword alphabets and key spaces together.' },
      { exercise: 'cl-x-affine-key', note: 'An affine key from one known word.' },
      { topic: 'p01-frequency', note: 'The counts survive a substitution.' },
      { topic: 'p01-substitution-solver', note: 'A hill climber finishes the job.' },
      { exercise: 'cl-x-subst-solve', note: 'Read a whole substitution yourself.' },
      { topic: 'p01-vigenere', note: 'A word of shifts, repeated under the message.' },
      { topic: 'p01-kasiski', note: 'First move: repeats and their distances.' },
      { topic: 'p01-ioc', note: 'Second move: the index of coincidence, column by column.' },
      { topic: 'p01-column-shifts', note: 'Third move: each column is a shift.' },
      { lesson: 'cl-kasiski', note: 'The key length two ways.' },
      { exercise: 'cl-x-vig-short', note: 'Break a Vigenère ciphertext.' },
      { topic: 'p01-autokey', note: 'A key that never repeats.' },
      { topic: 'p01-columnar', note: 'Letters moved, not replaced.' },
      { topic: 'p01-railfence', note: 'A zigzag on a few rails.' },
      { topic: 'p01-playfair', note: 'Two letters at a time on a square.' },
      { exercise: 'cl-x-playfair-square', note: 'Fill in a square.' },
      { topic: 'p01-otp', note: 'Perfect secrecy, and its price.' },
      { topic: 'p01-two-time-pad', note: 'The pad used twice, and crib-dragging.' },
      { exercise: 'cl-x-two-time', note: 'Recover a message from a reused pad.' },
      { topic: 'p01-enigma-plugboard', note: 'Cables swap letters on the way in and out.' },
      { topic: 'p01-enigma-path', note: 'One key press, contact by contact.' },
      { topic: 'p01-enigma-noself', note: 'Why no letter becomes itself.' },
      { topic: 'p01-enigma-stepping', note: 'Pawls, notches and the double step.' },
      { lesson: 'cl-enigma-step', note: 'The double step on the machine itself.' },
      { topic: 'p01-rejewski', note: 'Cycles that the plugboard cannot change.' },
      { topic: 'p01-crib-align', note: 'Where a guessed phrase can sit.' },
      { topic: 'p01-bombe-menu', note: 'The menu and its loops.' },
      { topic: 'p01-bombe-stop', note: 'A stop, tested through the diagonal board.' },
      { topic: 'p01-bombe-deduce', note: 'The plugboard read off a stop.' },
      { lesson: 'cl-bombe', note: 'The whole attack, with a lab on the Bombe.' },
      { exercise: 'cl-x-enigma-start', note: 'Find a message start with the Bombe.' },
    ],
  });

  // ---- what the diagram checker looks at: the challenges of this part ---------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'cl challenge cl-ctf-ferry-note')) {
    for (const id of ['cl-ctf-ferry-note', 'cl-ctf-desk-letter', 'cl-ctf-two-pads', 'cl-ctf-weather']) S.Checks.push({ group: 'learn', name: 'cl challenge ' + id, hash: 'ctf/' + id, ready: "document.querySelector('#ctfChallenge') && window.__siferReady", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
