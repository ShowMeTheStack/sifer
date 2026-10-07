// Part 12, hash functions: the CTF challenges, the guided tour and the course, and the pages the diagram checker looks
// at. Both challenges are birthday searches on a deliberately tiny hash (SHA-256 cut to 16 or 24 bits), run in a fixed
// order so that the first collision, and so the flag, is the same for everyone. Their data is made from a fixed seed
// with S.Hash.rng; only the SHA-256 of each flag is kept, with the plain flag in solution for the content checker.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.challenges.has('hs-ctf-cloakroom')) return;
  const cut = (m, bits) => S.Hash.truncate(S.Hash.digest('sha256', m), bits).toString(16).padStart(bits / 4, '0');
  const hall = () => 'hall' + (100 + S.Hash.rng(1201).int(900));
  const fest = () => { const r = S.Hash.rng(1202); return ['Saltmarsh', 'Lanternfall', 'Tidewater', 'Gullsong'][r.int(4)] + ' ' + (2026 + r.int(3)); };

  // ---- a 16-bit cloakroom tag ---------------------------------------------------------------------------------------
  C.challenge({
    id: 'hs-ctf-cloakroom', n: 120, level: 1, points: 100,
    title: 'The cloakroom tags',
    story: 'The concert hall’s new cloakroom prints a short check code on each coat tag so the attendants can match tag and hanger at a glance: the first 16 bits of SHA-256 of the tag’s text, as four hex digits. Tags are numbered from 0 upwards. The head attendant swears two tags will never show the same code on one night. Hand out tags in order, 0, 1, 2, …, and find the first tag whose code was already printed on an earlier one.',
    data: () => ({ 'Tag text': hall() + '-coat-N, with N = 0, 1, 2, … (no leading zeros)', 'Check code': 'the first 4 hex digits of SHA-256 of the tag text', 'Flag': 'sifer{i_j}: j is the first tag whose code equals that of an earlier tag i' }),
    format: 'sifer{...}',
    flagHash: '7deed404da3c9932f1b1b3756b0b2ae5818dae529e3fd865db1909fea064bcfa',
    solution: 'sifer{178_252}',
    wrong: ['sifer{252_178}', 'sifer{0_65536}', 'sifer{178}'],
    hints: [
      'There are only 65,536 codes, and every new tag can clash with any earlier one: a collision is expected after about √(π·65536/2) ≈ 320 tags, not 65,536.',
      'In the sandbox: a Map from code to tag number. For N = 0, 1, 2, …, hash the text, take the first 16 bits, and stop at the first code already in the Map.',
      () => 'Tags ' + hall() + '-coat-178 and ' + hall() + '-coat-252 both print ' + cut(hall() + '-coat-178', 16) + ', and no earlier pair clashes. The flag is sifer{178_252}: the head attendant was wrong after 253 tags.',
    ].map((x) => (typeof x === 'function' ? x() : x)),
    tools: ['sandbox/scratch', 'bench/hash'],
  });

  // ---- two lists, one 24-bit check -----------------------------------------------------------------------------------
  C.challenge({
    id: 'hs-ctf-wristbands', n: 121, level: 2, points: 200,
    title: 'Guest or staff?',
    story: 'At the harbour festival the gate scanners read a 24-bit check from each wristband: the first 24 bits of SHA-256 of the band’s text. Guest bands and staff bands are printed in two numbered series. The organisers want to know whether a guest band could ever carry the same check as a staff band. Print them alternately, guest 0, staff 0, guest 1, staff 1, …, and stop at the first band whose check matches a band of the other series already printed.',
    data: () => ({ 'Guest band text': fest() + ' wristband: guest N', 'Staff band text': fest() + ' wristband: staff N', 'Check': 'the first 6 hex digits of SHA-256 of the band text', 'Flag': 'sifer{guest_i_staff_j}: the matching guest band i and staff band j' }),
    format: 'sifer{...}',
    flagHash: 'f1f6a6ace1f613f8ad16af80b387df14f07080a51d5afeb06d3884782cb8bde9',
    solution: 'sifer{guest_3448_staff_1828}',
    wrong: ['sifer{guest_1828_staff_3448}', 'sifer{staff_1828_guest_3448}', 'sifer{guest_3448}'],
    hints: [
      'A match between two lists is still a birthday search: with g guest and s staff bands there are g·s cross pairs, each matching with chance 2⁻²⁴. Expect a match when g·s is near 2²⁴, so a few thousand bands of each.',
      'Keep two Maps, one per series, from check to band number (keep the first band for each check). Each new guest band is looked up in the staff Map, each new staff band in the guest Map. Matches inside one series do not count.',
      () => 'Guest band 3448 and staff band 1828 both carry ' + cut(fest() + ' wristband: guest 3448', 24) + '; the match appears when guest 3448 is printed. The flag is sifer{guest_3448_staff_1828}.',
    ].map((x) => (typeof x === 'function' ? x() : x)),
    tools: ['sandbox/scratch'],
  });

  // ---- the guided tour ---------------------------------------------------------------------------------------------
  C.tour({
    id: 'hs-tour', title: 'Tour: hash functions', blurb: 'The birthday paradox, Merkle–Damgård, SHA-256 round by round, the sponge and length extension, in eight steps.',
    steps: [
      { route: 'part=hash', target: '#main', text: 'Part 12 of the catalogue: hash functions. Each card is a topic that runs one hash with the actual words and bytes.' },
      { route: 'topic=p12-birthday', target: '#stageWrap', text: 'The birthday paradox, one draw at a time: why collisions cost only the square root of the number of digests.' },
      { target: '#btnPlay', text: 'Play steps through the run; the arrow keys go one step at a time, forwards or back.' },
      { route: 'topic=p12-md', target: '#inputs', text: 'Merkle–Damgård padding and the chain. Type your own message here and watch where the 80 byte and the length go.' },
      { route: 'topic=p12-compress', target: '#stageWrap', text: 'SHA-256’s compression function: T1, T2, the eight registers, and the feed-forward.' },
      { route: 'topic=p12-sponge', target: '#stageWrap', text: 'SHA-3 is a sponge: absorb into the rate, scramble with Keccak-f, squeeze. The capacity is never shown.' },
      { route: 'bench/hash', target: '#main', text: 'The hash bench: any hash round by round, HMAC, the length-extension defence card and a birthday attack on a cut-down digest you can run.' },
      { route: 'learn', target: '[data-chapter="hs-req"]', text: 'The lessons and exercises of this part start here: fill in padding, schedule words and a round, compute θ parities, and write SHA-256 padding and a round.' },
    ],
  });

  // ---- a course through every topic of the part --------------------------------------------------------------------
  C.course({
    id: 'hs-course', title: 'Hash functions', blurb: 'All fourteen topics of part 12, from the three games to length extension, with the lessons and a few exercises on the way.',
    steps: [
      { topic: 'p12-games', note: 'Preimage, second preimage and collision as games.' },
      { topic: 'p12-birthday', note: 'Why collisions come early.' },
      { lesson: 'hs-birthday', note: 'The birthday bound, worked out.' },
      { exercise: 'hs-x-bday-bound', note: 'The bound for a 40-bit digest.' },
      { topic: 'p12-md', note: 'Padding with the length, and the chain.' },
      { exercise: 'hs-x-pad-hex', note: 'Write a padding by hand.' },
      { topic: 'p12-schedule', note: 'Sixteen words become sixty-four.' },
      { topic: 'p12-compress', note: 'The 64 rounds and the feed-forward.' },
      { lesson: 'hs-compress', note: 'One round, register by register.' },
      { exercise: 'hs-x-round-table', note: 'Fill in the registers after round 0.' },
      { topic: 'p12-older', note: 'SHA-1, MD5 and how they fell.' },
      { topic: 'p12-sponge', note: 'Absorb and squeeze.' },
      { topic: 'p12-theta', note: 'θ: column parities.' },
      { topic: 'p12-keccak', note: 'ρ, π, χ and ι.' },
      { exercise: 'hs-x-theta-parity', note: 'Compute five column parities.' },
      { topic: 'p12-shake', note: 'Output of any length.' },
      { topic: 'p12-bday-attack', note: 'A birthday table on a cut-down hash.' },
      { topic: 'p12-rho', note: 'The same with no memory.' },
      { topic: 'p12-joux', note: 'Many-way collisions almost free.' },
      { exercise: 'hs-x-collide', note: 'A collision on 20 bits.' },
      { topic: 'p12-lenext', note: 'Length extension, and why HMAC and SHA-3 resist.' },
      { lesson: 'hs-lenext', note: 'What a digest gives away.' },
      { exercise: 'hs-x-hmac-why', note: 'Why HMAC is immune.' },
    ],
  });

  // ---- what the diagram checker looks at on these pages -------------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'lesson hs-games')) {
    const lessonReady = "document.querySelector('#lessonView')", exReady = "document.querySelector('#exerciseView')";
    for (const id of C.chapters.filter((c) => c.part === 'hash').flatMap((c) => c.lessons)) S.Checks.push({ group: 'learn', name: 'lesson ' + id, hash: 'lesson=' + id, ready: lessonReady, sel: '#main' });
    for (const id of ['hs-x-work-table', 'hs-x-pad-table', 'hs-x-sched-w16', 'hs-x-round-table', 'hs-x-code-round', 'hs-x-code-pad', 'hs-x-theta-parity', 'hs-x-theta-d', 'hs-x-collide', 'hs-x-exposed'])
      S.Checks.push({ group: 'learn', name: 'exercise ' + id, hash: 'exercise=' + id, ready: exReady, sel: '#main' });
    for (const id of ['hs-ctf-cloakroom', 'hs-ctf-wristbands']) S.Checks.push({ group: 'learn', name: 'challenge ' + id, hash: 'ctf/' + id, ready: "document.querySelector('#ctfChallenge')", sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'course hs-course', hash: 'course=hs-course', ready: "document.querySelector('#courseView')", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
