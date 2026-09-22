// Part 3, stream ciphers: the CTF challenges, the guided tour and the course, and the pages the diagram checker
// looks at. Each challenge's data is made at the moment the page opens, from a fixed seed, by the same engines the
// lessons use (S.LFSR, S.ChaCha), so it is the same for everyone; only the SHA-256 of each flag is kept, with the
// plain flag in solution for the content checker.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.challenges.has('st-ctf-chart')) return;
  const enc = (t) => new TextEncoder().encode(t);
  const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');

  // ---- an LFSR keystream given away by a file header ------------------------------------------------------------
  const CHART = '<?xml version="1.0" encoding="UTF-8"?>\n'
    + '<svg xmlns="http://www.w3.org/2000/svg" width="360" height="240" viewBox="0 0 360 240">\n'
    + '  <title>North channel, soundings of the spring survey</title>\n'
    + '  <path d="M20 200 C 90 150, 160 170, 230 110 S 320 60, 340 40" fill="none" stroke="#2a6f97" stroke-width="3"/>\n'
    + '  <circle cx="230" cy="110" r="5" fill="#c1121f"/>\n'
    + '  <text x="20" y="30" font-family="monospace" font-size="12">sifer{xml_header_gives_the_taps}</text>\n'
    + '</svg>\n';
  /** the chart XORed with 48-cell LFSR output, eight bits to a byte, the first bit as the most significant */
  const chartCipher = () => {
    const r = S.Sym.rng(3401), seed = Array.from({ length: 48 }, () => (r() < 0.5 ? 1 : 0));
    const file = enc(CHART), ks = S.LFSR.sequence([48, 47, 21, 20], seed, 8 * file.length);
    return hex(file.map((b, i) => { let k = 0; for (let j = 0; j < 8; j++) k = (k << 1) | ks[8 * i + j]; return b ^ k; }));
  };
  C.challenge({
    id: 'st-ctf-chart', n: 30, level: 3, points: 300,
    title: 'The survey boat\'s chart',
    story: 'A survey boat sends its depth charts to the harbour office over a cheap radio link. The radio\'s maker calls its encryption unbreakable: a shift register of a few dozen cells, with secret taps and a secret start state, whose output bits are XORed onto the file, the first bit of each byte as its most significant. You caught one transmission. The office\'s drawing software only reads SVG, and the maker never thought about what every SVG file starts with.',
    data: () => ({ 'The transmission, in hex': chartCipher() }),
    format: 'sifer{...}',
    flagHash: '1eaa6cee3b474152780b8ecff76b5d3a641529bf02a7c81feddcffe88b014df7',
    solution: 'sifer{xml_header_gives_the_taps}',
    wrong: ['sifer{north_channel}', 'sifer{xml_header}', '<?xml version="1.0" encoding="UTF-8"?>'],
    hints: [
      'An SVG file is XML, and XML files open with a fixed declaration: <?xml version="1.0" encoding="UTF-8"?> followed by a newline. XOR those 39 bytes with the start of the transmission and you hold 312 bits of keystream.',
      'Run Berlekamp–Massey on those 312 bits, most significant bit of each byte first. The shortest register has 48 cells, and 312 bits are far more than the 96 that pin it down.',
      'C(x) = 1 + x²⁰ + x²¹ + x⁴⁷ + x⁴⁸, so sₙ = sₙ₋₂₀ ⊕ sₙ₋₂₁ ⊕ sₙ₋₄₇ ⊕ sₙ₋₄₈. Seed it with the first 48 keystream bits, run it for the whole file, XOR, and read the <text> element: sifer{xml_header_gives_the_taps}.',
    ],
    tools: ['bench/cipher', 'sandbox/scratch'],
  });

  // ---- ChaCha20 with a nonce used twice ---------------------------------------------------------------------------
  const PUBLIC = 'BUOY 17 REPORT 2026-03-04T06:00Z wind SW 14 kn gusting 22, swell 2.1 m at 9 s, water 11.4 C, pressure 1009 hPa falling.';
  const SECRET = 'BUOY 17 MAINT: service code sifer{one_nonce_two_messages}; battery 61%, hull dry.';
  const buoys = () => {
    const r = S.Sym.rng(3402), key = S.Sym.bytes(r, 32), nonce = S.Sym.bytes(r, 12);
    return {
      'Nonce of both messages': hex(nonce),
      'Message 1, encrypted': hex(S.ChaCha.encrypt(key, 1, nonce, enc(PUBLIC))),
      'Message 2, encrypted': hex(S.ChaCha.encrypt(key, 1, nonce, enc(SECRET))),
      'Message 1, as the forecast page published it': PUBLIC,
    };
  };
  C.challenge({
    id: 'st-ctf-buoys', n: 31, level: 2, points: 200,
    title: 'Two reports, one nonce',
    story: 'Weather buoy 17 encrypts everything it sends with ChaCha20. Its firmware keeps the nonce in memory and counts up from a fixed value after every reboot, and a storm rebooted it twice in one morning. Two messages went out under the same key and nonce: an ordinary weather report, which the forecast office published word for word an hour later, and a maintenance message for the technicians, which was never meant to be read on shore.',
    data: buoys,
    format: 'sifer{...}',
    flagHash: '1c6a3f566b6d65f55e04e8b0190aba9b066bf242e9ca57ea73f0fd58dca118bb',
    solution: 'sifer{one_nonce_two_messages}',
    wrong: ['sifer{buoy_17}', 'sifer{one_nonce}', 'SIFER{ONE_NONCE_TWO_MESSAGES}'],
    hints: [
      'Same key, same nonce, same counter: ChaCha20 produces the same keystream for both messages. Nothing about the key needs to be found.',
      'The keystream is c₁ ⊕ m₁, and you know m₁. XOR that keystream into c₂, byte by byte; message 2 is shorter than message 1, so all of it comes out.',
      'c₁ ⊕ c₂ ⊕ m₁ reads “BUOY 17 MAINT: service code sifer{one_nonce_two_messages}; battery 61%, hull dry.”',
    ],
    tools: ['sandbox/scratch'],
  });

  // ---- the guided tour ---------------------------------------------------------------------------------------------
  C.tour({
    id: 'st-tour', title: 'Tour: stream ciphers', blurb: 'From the one-time pad to ChaCha20, in eight steps.',
    steps: [
      { route: 'part=stream', target: '#main', text: 'Part 3 of the catalogue: stream ciphers. Each card is a topic that works one example through, with the actual bits and words.' },
      { route: 'topic=st-two-time', target: '#stageWrap', text: 'A pad used twice. The ciphertexts XOR to the two messages XORed together, and a guessed word dragged along the result reads the other message.' },
      { target: '#btnPlay', text: 'Play steps through the run; the arrow keys go one step at a time, forwards or back.' },
      { route: 'topic=st-lfsr', target: '#inputs', text: 'An LFSR. Change the taps or the seed here, or pick an example, and the register runs again with your values.' },
      { route: 'topic=st-bm', target: '#stageWrap', text: 'Berlekamp–Massey rebuilds an unknown register from 2L of its output bits. This is why a bare LFSR is never a cipher.' },
      { route: 'topic=st-chacha-qr', target: '#stageWrap', text: 'ChaCha20\'s quarter-round: twelve add, XOR and rotate steps on four 32-bit words, each one shown with its values.' },
      { route: 'lesson=st-geffe', target: '#lessonView', text: 'Lessons run the topics inside them, ask for a prediction, and end with exercises. This one splits a three-register generator apart by correlation.' },
      { route: 'learn', target: '[data-chapter="st-pad"]', text: 'The lessons and exercises of this part start here: fill in register states and quarter-rounds, write an LFSR step and Berlekamp–Massey, and break a two-time pad.' },
    ],
  });

  // ---- a course through every topic of the part --------------------------------------------------------------------
  C.course({
    id: 'st-course', title: 'Stream ciphers', blurb: 'All thirteen topics of part 3, from perfect secrecy to XChaCha20, with the lessons and a few exercises on the way.',
    steps: [
      { topic: 'st-otp-secrecy', note: 'Why a random key as long as the message hides everything but the length.' },
      { lesson: 'st-otp', note: 'Perfect secrecy, and its price.' },
      { topic: 'st-two-time', note: 'Use the pad twice and the key cancels.' },
      { exercise: 'st-x-twotime-known', note: 'Read a message from a known one.' },
      { topic: 'st-rng', note: 'True, pseudo-random and cryptographic generators.' },
      { topic: 'st-lfsr', note: 'A shift register with taps, clock by clock.' },
      { exercise: 'st-x-lfsr-table', note: 'Clock a register by hand.' },
      { topic: 'st-period', note: 'Which taps give the longest period.' },
      { topic: 'st-galois', note: 'The same sequence from a differently wired register.' },
      { topic: 'st-bm', note: 'The register rebuilt from 2L output bits.' },
      { lesson: 'st-bm', note: 'Berlekamp–Massey, step by step.' },
      { exercise: 'st-x-lfsr-recover', note: 'Predict a keystream from 40 bits.' },
      { topic: 'st-geffe', note: 'Three registers, and the correlation that splits them.' },
      { exercise: 'st-x-geffe-break', note: 'Find one register by counting agreements.' },
      { topic: 'st-trivium', note: 'Three registers coupled by AND gates.' },
      { topic: 'st-salsa', note: 'Add, rotate and XOR on sixteen words.' },
      { topic: 'st-chacha-qr', note: 'ChaCha\'s quarter-round and double round.' },
      { exercise: 'st-x-qr-table', note: 'A quarter-round by hand.' },
      { topic: 'st-chacha-block', note: 'The block function, the counter and the keystream.' },
      { topic: 'st-xchacha', note: 'A nonce long enough to choose at random.' },
      { lesson: 'st-chacha', note: 'Counter, nonce, and what goes wrong when a nonce repeats.' },
    ],
  });

  // ---- what the diagram checker looks at on these pages -------------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'lesson st-otp')) {
    const lessonReady = "document.querySelector('#lessonView')", exReady = "document.querySelector('#exerciseView')";
    for (const id of C.chapters.filter((c) => c.part === 'stream').flatMap((c) => c.lessons)) S.Checks.push({ group: 'learn', name: 'lesson ' + id, hash: 'lesson=' + id, ready: lessonReady, sel: '#main' });
    for (const id of ['st-x-otp-xor', 'st-x-crib', 'st-x-lfsr-table', 'st-x-primitive', 'st-x-bm-table', 'st-x-code-bm', 'st-x-geffe-break', 'st-x-qr-table', 'st-x-state', 'st-x-xchacha'])
      S.Checks.push({ group: 'learn', name: 'exercise ' + id, hash: 'exercise=' + id, ready: exReady, sel: '#main' });
    for (const id of ['st-ctf-chart', 'st-ctf-buoys']) S.Checks.push({ group: 'learn', name: 'challenge ' + id, hash: 'ctf/' + id, ready: "document.querySelector('#ctfChallenge')", sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'course st-course', hash: 'course=st-course', ready: "document.querySelector('#courseView')", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
