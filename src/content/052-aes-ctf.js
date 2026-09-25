// Part 5, AES: the CTF challenges, the guided tour and the course, and the pages the diagram checker looks at. Both
// challenges are Mini-AES, small enough to do by hand or with a short program. Their data is made when the page opens,
// from a fixed seed, by S.MiniAES, so it is the same for everyone; only the SHA-256 of each flag is kept, with the plain
// flag in solution for the content checker.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.challenges.has('ae-ctf-mini-note')) return;
  /** a message encrypted with Mini-AES in ECB, two bytes to a block, under a 16-bit key drawn from the seed */
  const miniEcb = (seed, msg) => {
    const M = S.MiniAES, r = S.Sym.rng(seed), key = S.Sym.int(r, 65536), b = new TextEncoder().encode(msg), out = [];
    for (let i = 0; i < b.length; i += 2) out.push(M.hex(M.encrypt((b[i] << 8) | b[i + 1], key).out));
    return { key: M.hex(key), ct: out.join(' ') };
  };

  // ---- Mini-AES with the key on the lid --------------------------------------------------------------------------
  C.challenge({
    id: 'ae-ctf-mini-note', n: 50, level: 1, points: 100,
    title: 'The key under the lid',
    story: 'Two pupils built pagers for the school science fair, with “real AES inside”. It is Mini-AES: every two characters of a message become one 16-bit block, encrypted on its own. To save the judges time they wrote the key on a sticker under the lid. You picked up one of the pagers after the fair, opened the lid, and scrolled to the last message received.',
    data: () => { const d = miniEcb(5001, 'sifer{key_under_the_lid}'); return { 'Key, from the sticker': d.key, 'Last message, one Mini-AES block per two characters': d.ct }; },
    format: 'sifer{...}',
    flagHash: '60b77e74959a2ca9f9af625ed9cf97c45721a1b12a795fc6be5dba2513cd8b55',
    solution: 'sifer{key_under_the_lid}',
    wrong: ['sifer{dc4f}', 'sifer{key_under_the}', 'SIFER{KEY_UNDER_THE_LID}'],
    hints: [
      'Each four-hex-digit block decrypts to two ASCII characters. Make the round keys of the key first: K0 is the key itself, and K1 and K2 come from the schedule.',
      'The key dc4f gives K1 = b73c and K2 = cb84. The first block ee2b: add K2, ShiftRow and the inverse S-box, add K1, MixColumn, ShiftRow and the inverse S-box, add K0: 7369, which is “si”.',
      'Decrypting all twelve blocks (by hand or on the bench, Mini-AES in ECB, decrypting hex) gives 73 69 66 65 72 7b …, the text sifer{key_under_the_lid}.',
    ],
    tools: ['bench/cipher'],
  });

  // ---- Mini-AES with the key unknown, but the greeting known ------------------------------------------------------
  C.challenge({
    id: 'ae-ctf-mini-key', n: 51, level: 2, points: 200,
    title: 'Every message says hello',
    story: 'The pagers won a prize, and next year\'s model hides the key: it is set in a hidden menu and printed nowhere. But the firmware still uses Mini-AES with a 16-bit key, two characters to a block, each block on its own, and the pupils were proud of their manners: every message starts with “Hi, ”. You recorded one message going past.',
    data: () => ({ 'The message, one Mini-AES block per two characters': miniEcb(5002, 'Hi, sifer{sixteen_bits_fall}').ct, 'Every message starts with': '“Hi, ”: H, i, a comma and a space, 48 69 2c 20' }),
    format: 'sifer{...}',
    flagHash: '497d47556fcba165cda17d6dbe528fdb580abe463b2e64bfb281d60761c480ac',
    solution: 'sifer{sixteen_bits_fall}',
    wrong: ['sifer{b3f3}', 'Hi, sifer{sixteen_bits_fall}', 'sifer{sixteen_bits}'],
    hints: [
      '“Hi, ” is two blocks of known plaintext: 4869 and 2c20. A 16-bit key has only 65 536 values: try them all.',
      'Encrypt 4869 under every key and keep those that give the first block, b105: two keys survive. Keep the one that also turns 2c20 into the second block, 9605.',
      'The key is b3f3. Decrypting the whole message gives “Hi, sifer{sixteen_bits_fall}”. A real AES key has 2¹²⁸ values, and the same search is hopeless.',
    ],
    tools: ['sandbox/scratch', 'bench/cipher'],
  });

  // ---- the guided tour ---------------------------------------------------------------------------------------------
  C.tour({
    id: 'ae-tour', title: 'Tour: AES', blurb: 'The state, the four steps, the key schedule and Mini-AES, in eight steps.',
    steps: [
      { route: 'part=aes', target: '#main', text: 'Part 5 of the catalogue: AES. Each card is a topic that works one block through with the actual bytes.' },
      { route: 'topic=aes-overview', target: '#stageWrap', text: 'The state: 16 bytes in a 4×4 grid, filled column by column, and the rounds that change it.' },
      { target: '#btnPlay', text: 'Play steps through the run; the arrow keys go one step at a time, forwards or back.' },
      { route: 'topic=aes-subbytes', target: '#stageWrap', text: 'SubBytes worked out for one byte: the inverse in GF(2⁸), then the affine map, bit by bit.' },
      { route: 'topic=aes-mixcolumns', target: '#inputs', text: 'MixColumns on a column you choose. Type four bytes here and every product in GF(2⁸) is shown.' },
      { route: 'topic=aes-keyexp', target: '#stageWrap', text: 'The key expansion: RotWord, SubWord and the round constant make each fourth word, plain XORs the rest.' },
      { route: 'lesson=ae-mini', target: '#lessonView', text: 'Mini-AES does all of this on 16 bits, small enough for pencil and paper. Lessons run the topics, ask for a prediction, and end with exercises.' },
      { route: 'learn', target: '[data-chapter="ae-state"]', text: 'The lessons and exercises of this part start here: fill in states, compute round keys, write xtime, MixColumns and g, and break Mini-AES.' },
    ],
  });

  // ---- a course through every topic of the part --------------------------------------------------------------------
  C.course({
    id: 'ae-course', title: 'AES', blurb: 'All fourteen topics of part 5, from the state to key length, with the lessons and a few exercises on the way.',
    steps: [
      { topic: 'aes-overview', note: 'The 4×4 state and the ten rounds.' },
      { lesson: 'ae-state', note: 'How the block fills the grid.' },
      { exercise: 'ae-x-state-load', note: 'Load a block by hand.' },
      { topic: 'aes-subbytes', note: 'One byte through inversion and the affine map.' },
      { topic: 'aes-sbox', note: 'The whole S-box, and its inverse.' },
      { lesson: 'ae-sub', note: 'Why the S-box is built this way.' },
      { exercise: 'ae-x-code-xtime', note: 'Write xtime.' },
      { topic: 'aes-shiftrows', note: 'Rows turned by 0, 1, 2 and 3 places.' },
      { topic: 'aes-mixcolumns', note: 'A column times a matrix over GF(2⁸).' },
      { exercise: 'ae-x-mixcol', note: 'MixColumns on one column by hand.' },
      { topic: 'aes-addroundkey', note: 'The only step with the key.' },
      { topic: 'aes-keyexp', note: 'Eleven round keys and the g-function.' },
      { exercise: 'ae-x-g', note: 'g for round key 1.' },
      { topic: 'aes-keysched-wide', note: 'The schedules for 192- and 256-bit keys.' },
      { topic: 'aes-encrypt', note: 'One encryption, round by round.' },
      { exercise: 'ae-x-round1', note: 'A whole round for one column.' },
      { topic: 'aes-decrypt', note: 'The inverse cipher.' },
      { topic: 'aes-avalanche', note: 'One bit becomes half the block in two rounds.' },
      { topic: 'aes-mini', note: 'Mini-AES, worked by hand.' },
      { lesson: 'ae-mini', note: 'Every step in miniature.' },
      { exercise: 'ae-x-mini-dec', note: 'Decrypt a Mini-AES block.' },
      { topic: 'aes-ttable', note: 'T-tables, and the cache lines they leak.' },
      { topic: 'aes-security', note: 'Key length against exhaustive and quantum search.' },
      { lesson: 'ae-sec', note: 'A key is only as strong as its source.' },
    ],
  });

  // ---- what the diagram checker looks at on these pages -------------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'lesson ae-state')) {
    const lessonReady = "document.querySelector('#lessonView')", exReady = "document.querySelector('#exerciseView')";
    for (const id of C.chapters.filter((c) => c.part === 'aes').flatMap((c) => c.lessons)) S.Checks.push({ group: 'learn', name: 'lesson ' + id, hash: 'lesson=' + id, ready: lessonReady, sel: '#main' });
    for (const id of ['ae-x-state-load', 'ae-x-subbytes-state', 'ae-x-affine', 'ae-x-mixcol', 'ae-x-code-g', 'ae-x-round1', 'ae-x-mini-round', 'ae-x-mini-key', 'ae-x-impl-fix'])
      S.Checks.push({ group: 'learn', name: 'exercise ' + id, hash: 'exercise=' + id, ready: exReady, sel: '#main' });
    for (const id of ['ae-ctf-mini-note', 'ae-ctf-mini-key']) S.Checks.push({ group: 'learn', name: 'challenge ' + id, hash: 'ctf/' + id, ready: "document.querySelector('#ctfChallenge')", sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'course ae-course', hash: 'course=ae-course', ready: "document.querySelector('#courseView')", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
