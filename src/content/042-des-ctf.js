// Part 4, DES and the Feistel network: the CTF challenges, the guided tour and the course, and the pages the diagram
// checker looks at. Each challenge's data is made when the page opens, from a fixed seed, by the engines (the toy
// cipher Tern of 041-des-ex.js, S.SPN), so it is the same for everyone; only the SHA-256 of each flag is kept, with the
// plain flag in solution for the content checker.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.challenges.has('des-ctf-relay')) return;
  const h8 = (x) => (x >>> 0).toString(16).padStart(8, '0');
  const h4 = (x) => x.toString(16).padStart(4, '0');

  // ---- double encryption met in the middle ---------------------------------------------------------------------
  const RELAY_FLAG = 'sifer{two_keys_one_bit_more}';
  const relay = () => {
    const tern = S.Tern.encrypt, r = S.Sym.rng(4204), k1 = Math.floor(r() * 65536), k2 = Math.floor(r() * 65536);
    const dbl = (p) => tern(tern(p, k1), k2);
    const b = new TextEncoder().encode(RELAY_FLAG), blocks = [];
    for (let i = 0; i < b.length; i += 4) blocks.push(h8(dbl(((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0)));
    return {
      'Tern, the cipher (JavaScript)': S.Tern.SRC,
      'Known pairs, plaintext → ciphertext': [0x73656e64, 0x6e6f7274, 0x68617262].map((p) => h8(p) + ' → ' + h8(dbl(p))).join('\n'),
      'The flag, encrypted 4 bytes at a time': blocks.join(' '),
    };
  };
  C.challenge({
    id: 'des-ctf-relay', n: 40, level: 3, points: 300,
    title: 'The relay that encrypts twice',
    story: 'A courier network passes messages through two relay stations. Each station encrypts what it receives with Tern, a small cipher of its own, under its own 16-bit key, so the message arrives encrypted twice. The network\'s engineers reckon that two keys make 32 bits, far too many to try. You have the source of Tern, three blocks whose plaintexts you know (the words “send”, “nort” and “harb” from a routine header), and an intercepted message that holds the flag, each 4-byte block encrypted on its own.',
    data: relay,
    format: 'sifer{...}',
    flagHash: '48489ae74821dcd6c6e575da6d224bba61dd93585d79e092cc4f57458477c0b4',
    solution: RELAY_FLAG,
    wrong: ['sifer{two_keys}', 'sifer{18e0_7a2d}', 'sifer{meet_in_the_middle}'],
    hints: [
      'Trying every pair of keys is 2³² double encryptions. But C = tern(tern(P, K₁), K₂) means tern(C, K₂, decrypt) = tern(P, K₁): the two sides meet at the middle value.',
      'Encrypt the first known plaintext under all 65 536 values of K₁ and keep the middle values in a Map. Decrypt its ciphertext under every K₂ and look each one up. Several candidates turn up; the second known pair leaves one.',
      'The keys are K₁ = 18e0 and K₂ = 7a2d. Decrypt each block under K₂, then under K₁, and read the 28 bytes as text: sifer{two_keys_one_bit_more}.',
    ],
    tools: ['sandbox/scratch'],
  });

  // ---- a toy SPN broken differentially ---------------------------------------------------------------------------
  const KEYPAD_FLAG = 'sifer{last_round_key_badb}';
  const keypad = () => {
    const keys = S.SPN.keys(1414), E = S.SPN.fast(keys).enc;
    const set = (dIn, n, seed) => {
      const r = S.Sym.rng(seed), out = [];
      for (let i = 0; i < n; i++) { const p = Math.floor(r() * 65536); out.push(h4(E(p)) + h4(E(p ^ dIn))); }
      return out.map((x, i) => x + ((i + 1) % 8 ? ' ' : '\n')).join('').trim();
    };
    return {
      'The toy SPN': 'A 16-bit block, four rounds. Rounds 1–3: XOR a round key, four 4-bit S-boxes, then the bit transposition (bit j of nibble i goes to bit i of nibble j). Round 4: XOR K₄, the S-boxes, XOR K₅. Nibble 0 is the leftmost.',
      'The S-box, for inputs 0 … f': '6 b 5 4 2 e 7 a 9 d f c 3 1 0 8',
      'Pairs with ΔP = 0300 (C ‖ C′, 400 pairs)': set(0x0300, 400, 14205),
      'Pairs with ΔP = 0400 (C ‖ C′, 1200 pairs)': set(0x0400, 1200, 14206),
      'Pairs with ΔP = 0500 (C ‖ C′, 800 pairs)': set(0x0500, 800, 14208),
    };
  };
  C.challenge({
    id: 'des-ctf-keypad', n: 41, level: 4, points: 400,
    title: 'The door keypad\'s last round key',
    story: 'A door keypad talks to its controller in 16-bit blocks, encrypted with a toy four-round SPN its maker thought too small to bother attacking. You wired a clip to its bus and made it encrypt plaintexts of your choice in pairs. Three batches came out, each with a fixed XOR difference between the two plaintexts of a pair; every pair is written as the two ciphertexts side by side, eight hex digits. The flag is the last round key K₅, as sifer{last_round_key_xxxx} with the four hex digits in lower case.',
    data: keypad,
    format: 'sifer{...}',
    flagHash: '09cb0cf04804b18e10cbcb0f84e13723bef86ed3100d89f9c21d77ba99074c3e',
    solution: KEYPAD_FLAG,
    wrong: ['sifer{last_round_key_0000}', 'sifer{last_round_key_BADB}', 'sifer{last_round_key_db}'],
    hints: [
      'Each batch matches a characteristic. ΔP = 0300 reaches 0044 before the last S-boxes (nibbles 2 and 3, about 1 pair in 64); ΔP = 0400 reaches 0400 (nibble 1, about 1 in 64); ΔP = 0500 reaches 4000 (nibble 0, about 1 in 128).',
      'For each batch, drop the pairs whose ciphertexts differ outside the target nibbles. For each guess of those K₅ nibbles, undo the S-box on the target nibbles of both ciphertexts and count the pairs that show the predicted difference.',
      'The counts peak at db for nibbles 2 and 3, at a for nibble 1 and at b for nibble 0, each well clear of the runner-up. K₅ = badb, and the flag is sifer{last_round_key_badb}.',
    ],
    tools: ['bench/cipher', 'sandbox/scratch'],
  });

  // ---- the guided tour ---------------------------------------------------------------------------------------------
  C.tour({
    id: 'des-tour', title: 'Tour: DES and the Feistel network', blurb: 'From the Feistel ladder to a toy cipher broken differentially, in eight steps.',
    steps: [
      { route: 'part=des', target: '#main', text: 'Part 4 of the catalogue: DES and the Feistel network. Each card is a topic that works one example through, every bit shown.' },
      { route: 'topic=des-feistel', target: '#stageWrap', text: 'The Feistel ladder: each round XORs F of one half into the other. Decryption is the same ladder with the keys reversed, whatever F is.' },
      { target: '#btnPlay', text: 'Play steps through the run; the arrow keys go one step at a time, forwards or back.' },
      { route: 'topic=des-f', target: '#inputs', text: 'DES\'s f-function. Change the plaintext, the key or the round here and watch the eight S-box lookups.' },
      { route: 'topic=des-avalanche', target: '#stageWrap', text: 'One flipped bit spreads to about half of the block within three rounds.' },
      { route: 'topic=des-mitm', target: '#stageWrap', text: 'Double DES met in the middle: a table from one side, lookups from the other, and two keys cost little more than one.' },
      { route: 'lesson=des-diff', target: '#lessonView', text: 'Lessons run the topics inside them, ask for a prediction, and end with exercises. This one recovers the last round key of a toy SPN by counting pairs.' },
      { route: 'learn', target: '[data-chapter="des-ladder"]', text: 'The lessons and exercises of this part start here: fill in Feistel rounds and S-box outputs, write a Feistel network and an S-box lookup, and break a double cipher.' },
    ],
  });

  // ---- a course through every topic of the part --------------------------------------------------------------------
  C.course({
    id: 'des-course', title: 'DES and the Feistel network', blurb: 'All fifteen topics of part 4, from the Feistel principle to PRESENT, with the lessons and a few exercises on the way.',
    steps: [
      { topic: 'des-feistel', note: 'Any round function, an invertible cipher.' },
      { exercise: 'des-x-feistel-table', note: 'Three rounds by hand.' },
      { topic: 'des-overview', note: 'DES from plaintext to ciphertext.' },
      { topic: 'des-ipfp', note: 'The initial and final permutations.' },
      { topic: 'des-f', note: 'Expansion, key, eight S-boxes, P.' },
      { lesson: 'des-f', note: 'Inside the f-function.' },
      { exercise: 'des-x-f-sboxes', note: 'Eight S-box lookups.' },
      { topic: 'des-keys', note: 'Sixteen round keys from 56 bits.' },
      { topic: 'des-decrypt', note: 'The same ladder backwards.' },
      { topic: 'des-avalanche', note: 'One bit becomes thirty-two.' },
      { topic: 'des-weak', note: 'Weak keys and the complement.' },
      { topic: 'des-search', note: 'What a 56-bit key costs to search.' },
      { topic: 'des-mitm', note: 'Double DES met in the middle.' },
      { exercise: 'des-x-mitm-break', note: 'Break a toy double cipher.' },
      { topic: 'des-3des', note: '3DES and DESX.' },
      { topic: 'spn-ddt', note: 'Differences through an S-box and through rounds.' },
      { topic: 'spn-diff', note: 'The last round key, by counting.' },
      { lesson: 'des-diff', note: 'The differential attack step by step.' },
      { exercise: 'des-x-spn-break', note: 'Recover a nibble yourself.' },
      { topic: 'spn-linear', note: 'Linear approximations and known plaintexts.' },
      { topic: 'spn-present', note: 'A real SPN for tiny chips.' },
    ],
  });

  // ---- what the diagram checker looks at on these pages -------------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'lesson des-feistel')) {
    const lessonReady = "document.querySelector('#lessonView')", exReady = "document.querySelector('#exerciseView')";
    for (const id of C.chapters.filter((c) => c.part === 'des').flatMap((c) => c.lessons)) S.Checks.push({ group: 'learn', name: 'lesson ' + id, hash: 'lesson=' + id, ready: lessonReady, sel: '#main' });
    for (const id of ['des-x-feistel-table', 'des-x-code-feistel', 'des-x-ip', 'des-x-s1', 'des-x-f-sboxes', 'des-x-code-sbox', 'des-x-keys', 'des-x-mitm-break', 'des-x-ddt-row', 'des-x-spn-break', 'des-x-present'])
      S.Checks.push({ group: 'learn', name: 'exercise ' + id, hash: 'exercise=' + id, ready: exReady, sel: '#main' });
    for (const id of ['des-ctf-relay', 'des-ctf-keypad']) S.Checks.push({ group: 'learn', name: 'challenge ' + id, hash: 'ctf/' + id, ready: "document.querySelector('#ctfChallenge')", sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'course des-course', hash: 'course=des-course', ready: "document.querySelector('#courseView')", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
