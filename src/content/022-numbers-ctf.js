// Part 2, modular arithmetic, number theory and finite fields: three CTF challenges, the part's guided tour and its
// course. Each challenge's data is made from a fixed seed by the engines (S.NT.seededRandom for the randomness, a
// deterministic Miller–Rabin for primes), so every visitor sees the same numbers; each flag is kept only as its
// SHA-256, with the plain flag in solution for the content checker.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || !C.challenge || C.challenges.has('num-ctf-rowing')) return;
  const NT = S.NT;

  // ---- deterministic helpers ----------------------------------------------------------------------------------
  /** a seeded source of BigInts: below(n) is uniform in [0, n) */
  const source = (seed) => {
    const bytes = NT.seededRandom(seed);
    const bits = (k) => { const b = bytes(Math.ceil(k / 8)); let v = 0n; for (const x of b) v = (v << 8n) | BigInt(x); return v >> BigInt(b.length * 8 - k); };
    return { below(n) { const k = NT.bitLength(n - 1n) || 1; for (;;) { const v = bits(k); if (v < n) return v; } }, range(lo, hi) { return lo + this.below(hi - lo + 1n); } };
  };
  /** Miller–Rabin with the first twelve primes as bases: exact for every n below 3.3·10²⁴ */
  const BASES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
  const isPrime = (n) => { if (n < 2n) return false; for (const p of BASES) if (n % p === 0n) return n === p; return NT.millerRabin(n, BASES).probablePrime; };
  const nextPrime = (n) => { n = n | 1n; while (!isPrime(n)) n += 2n; return n; };
  const toInt = (text) => { let v = 0n; for (const b of new TextEncoder().encode(text)) v = (v << 8n) | BigInt(b); return v; };
  const memo = (f) => { let v; return () => (v === undefined ? (v = f()) : v); };

  // ===========================================================================================================
  // 1. Multiplying by a secret is not encryption
  // ===========================================================================================================
  const ROW_P = (1n << 61n) - 1n;
  const ROW_TEXT = 'ORDERS: Row out at the second bell, hold the line by the red buoy, and tell the cox: sifer{one_known_block_undoes_all}';
  const rowing = memo(() => {
    const k = source(2002).range(2n, ROW_P - 2n);
    const text = ROW_TEXT + ' '.repeat((7 - (ROW_TEXT.length % 7)) % 7);
    const blocks = [];
    for (let i = 0; i < text.length; i += 7) blocks.push((toInt(text.slice(i, i + 7)) * k) % ROW_P);
    return { k, blocks, m0: toInt('ORDERS:') };
  });
  C.challenge({
    id: 'num-ctf-rowing', n: 21, level: 1, points: 100,
    title: 'The rowing club\'s race orders',
    story: 'The harbour rowing club radios its race orders to the coxes out on the water. To keep the rival club guessing, the captain cuts each order into groups of seven characters, reads each group as one number (seven bytes, big-endian), and multiplies it by the club\'s secret number modulo the prime p = 2⁶¹ − 1. "Multiplication cannot be undone without the secret," she says. You have the blocks of tonight\'s order. Every order she has ever sent starts with the same seven characters: ORDERS:',
    data: () => ({
      'The prime p = 2^61 − 1': ROW_P.toString(),
      'The order, one block per line': rowing().blocks.join('\n'),
    }),
    format: 'sifer{...}',
    flagHash: '2f36d9c0f9dfef81a8f6ed7256e2c271e655a955d32dc09afe97eada763dc6e0',
    solution: 'sifer{one_known_block_undoes_all}',
    wrong: ['sifer{one_known_block}', 'ORDERS:', 'sifer{ORDERS}'],
    hints: [
      'Each block is c = k·m mod p with the same k. If you knew one plaintext block m and its ciphertext c, the secret would follow from k = c·m⁻¹ mod p, and every other block from m = c·k⁻¹.',
      'You do know one: the first block is the text "ORDERS:", whose seven bytes 4f 52 44 45 52 53 3a read as the number ' + toInt('ORDERS:') + '. Find its inverse modulo p with extended Euclid, or as m^(p−2) by Fermat.',
      'k⁻¹ = m₀·c₀⁻¹ mod p. Multiply every block by it, write each result as seven bytes, and read the text: "ORDERS: Row out at the second bell, hold the line by the red buoy, and tell the cox: sifer{one_known_block_undoes_all}". One known block is enough because the map m ↦ k·m is linear: no mixing, no rounds, and a single unknown.',
    ],
    tools: ['bench/nt', 'sandbox/scratch'],
  });

  // ===========================================================================================================
  // 2. The clockmaker's three clocks (the Chinese remainder theorem)
  // ===========================================================================================================
  const CLOCK_FLAG = 'sifer{hands_meet_once}';
  const clocks = memo(() => {
    const src = source(2718), lo = 1n << 59n, ms = [];
    while (ms.length < 3) { const m = nextPrime(src.range(lo, (lo << 1n) - 1n)); if (m < lo << 1n && !ms.includes(m)) ms.push(m); }
    const x = toInt(CLOCK_FLAG);
    return { ms, rs: ms.map((m) => x % m), x };
  });
  C.challenge({
    id: 'num-ctf-clocks', n: 22, level: 2, points: 200,
    title: 'The clockmaker\'s three clocks',
    story: 'The old clockmaker of the market square loved primes. For her last puzzle she built three clocks whose faces are divided into enormous prime numbers of ticks. She set all three hands to 0 at the same instant, let every clock run forward by one and the same secret number of ticks, and stopped them. The secret number, written out in bytes, is the flag. Her apprentice wrote down each face and where its hand stopped.',
    data: () => {
      const c = clocks(), out = {};
      ['first', 'second', 'third'].forEach((w, i) => { out['The ' + w + ' clock: ticks on its face'] = c.ms[i].toString(); out['The ' + w + ' clock: where its hand stopped'] = c.rs[i].toString(); });
      return out;
    },
    format: 'sifer{...}',
    flagHash: '552ddcbbb2c0f6b537a727c32a3be06edf4fe8a576af254f287246733d940c12',
    solution: CLOCK_FLAG,
    wrong: ['sifer{hands}', 'sifer{three_clocks}', 'sifer{' + 'x'.repeat(16) + '}'],
    hints: [
      'Each hand shows the secret number x modulo the number of ticks on its face: x ≡ r₁ (mod m₁), x ≡ r₂ (mod m₂), x ≡ r₃ (mod m₃). The faces are distinct primes, so they share no factor.',
      'By the Chinese remainder theorem there is exactly one x below M = m₁·m₂·m₃, a number of 180 bits, and a flag of 22 characters is at most 176 bits. Build x = Σ rᵢ·Mᵢ·yᵢ mod M (the number-theory bench, CRT, takes all three rows).',
      'x comes out as a 22-byte number. In hex it starts 73 69 66 65 72 7b, which is "sifer{"; reading all 22 bytes as text gives the flag, sifer{hands_meet_once}.',
    ],
    tools: ['bench/nt', 'sandbox/scratch'],
  });

  // ===========================================================================================================
  // 3. The impostor in the key list (a Carmichael number)
  // ===========================================================================================================
  const impostor = memo(() => {
    const src = source(561);
    // a Carmichael number (6k + 1)(12k + 1)(18k + 1) with all three factors prime
    let k = src.range(20000n, 60000n);
    while (!(isPrime(6n * k + 1n) && isPrime(12n * k + 1n) && isPrime(18n * k + 1n))) k++;
    const fs = [6n * k + 1n, 12n * k + 1n, 18n * k + 1n], n = fs[0] * fs[1] * fs[2];
    // eleven honest primes of the same size
    const list = [];
    while (list.length < 11) { const p = nextPrime(src.range(n / 3n, n * 3n)); if (!list.includes(p)) list.push(p); }
    const at = Number(src.below(12n));
    list.splice(at, 0, n);
    return { list, n, fs, at, k };
  });
  C.challenge({
    id: 'num-ctf-impostor', n: 23, level: 3, points: 300,
    title: 'The impostor in the key list',
    story: 'A small firm makes door-entry fobs, and every fob needs a prime for its key. To save time on the tiny chip, the firmware tests its random candidates with Fermat\'s test only, to the bases 2, 3, 5, 7, 11 and 13, and keeps a number when all six say 1. An auditor printed the twelve numbers the last batch kept. She is sure that one of them is not prime at all. Find it and factor it: the flag is sifer{p_q_r}, its three prime factors in increasing order, joined by underscores.',
    data: () => ({ 'The twelve numbers the firmware kept': impostor().list.map((v, i) => (i + 1 < 10 ? ' ' : '') + (i + 1) + '. ' + v).join('\n') }),
    format: 'sifer{...}',
    flagHash: 'c5f5a70fb5231818047efe5a13a9f3ebb920540e9680414afaca98a319554344',
    solution: '',
    wrong: ['sifer{2_3_5}', 'sifer{561}'],
    hints: [],
    tools: ['bench/nt', 'sandbox/scratch'],
  });
  // the flag and the last hint come from the generated numbers
  {
    const g = impostor(), x = C.challenges.get('num-ctf-impostor');
    const flag = 'sifer{' + g.fs.join('_') + '}';
    x.solution = flag;
    x.wrong.push('sifer{' + g.n + '}', 'sifer{' + g.fs.slice().reverse().join('_') + '}');
    x.hints = [
      'Fermat\'s test cannot find it: a Carmichael number passes for every base that shares no factor with it, and its factors are far larger than 13. Miller–Rabin is not fooled. Run it on all twelve (the number-theory bench, Primality, does several bases at once).',
      'Exactly one number fails Miller–Rabin. In its failing chain, look for a value x with x² ≡ 1 but x ≢ ±1: then gcd(x − 1, n) is a proper factor. Carmichael numbers this size are often of the form (6k + 1)(12k + 1)(18k + 1) with all three factors prime; that form satisfies Korselt\'s criterion automatically.',
      'Number ' + (g.at + 1) + ', n = ' + g.n + ', is the impostor. It is (6k + 1)(12k + 1)(18k + 1) with k = ' + g.k + ': ' + g.fs.join(' · ') + '. Check Korselt: n − 1 is divisible by ' + g.fs.map((p) => p - 1n).join(', ') + '. The flag is ' + flag + '.',
    ];
  }

  // ===========================================================================================================
  // The part's tour and course
  // ===========================================================================================================
  C.tour({
    id: 'num-tour', title: 'Tour: number theory', blurb: 'From a clock to the field inside AES, in eight steps.',
    steps: [
      { route: 'part=numbers', target: '#main', text: 'Part 2 of the catalogue: modular arithmetic, number theory and finite fields, the mathematics under RSA, Diffie–Hellman, elliptic curves and AES. Each card is a topic that works one example with real values.' },
      { route: 'topic=mod-clock', target: '#stageWrap', text: 'Arithmetic modulo n happens on a clock: whole laps change nothing, so only the remainder is kept.' },
      { target: '#btnPlay', text: 'Play steps through the run; the arrow keys go one step at a time, forwards or back. The line under the picture says what happens with the actual numbers.' },
      { route: 'topic=egcd', target: '#inputs', text: 'The extended Euclidean algorithm as a table. Change the numbers here: 8448 and 17 compute a toy RSA private exponent in three rows.' },
      { route: 'topic=crt-clocks', target: '#stageWrap', text: 'The Chinese remainder theorem as two clocks turned together: each pair of hand positions belongs to exactly one number below the product.' },
      { route: 'topic=gf2m-mul', target: '#stageWrap', text: 'Multiplying two bytes in the AES field: shift, add with XOR, and reduce when a bit falls off the top.' },
      { route: 'lesson=num-primes', target: '#lessonView', text: 'Lessons run the topics inside them, ask for a prediction, and end with exercises. This one shows why 561 fools Fermat\'s test and not Miller–Rabin.' },
      { route: 'learn', target: '[data-chapter="num-mod"]', text: 'The part\'s lessons and exercises start here: tables to fill, inverses and orders to find, functions to write and test, and a liar to catch. Three challenges on the CTF ladder break things with the same ideas.' },
    ],
  });

  C.course({
    id: 'num-course', title: 'Number theory for cryptography, start to finish', blurb: 'An ordered path through every topic of part 2, from the modular clock to the inverse of a byte in GF(2⁸), with lessons and exercises on the way.',
    steps: [
      { topic: 'mod-clock', note: 'Only the remainder survives a lap of the clock.' },
      { topic: 'mod-classes', note: 'Congruence classes, and why any member will do.' },
      { exercise: 'num-x-reduce', note: 'A negative number, reduced the right way.' },
      { topic: 'zn-ring', note: 'Units and zero divisors in the tables of Z_n.' },
      { topic: 'mod-inverse', note: 'An inverse by hopping round the clock.' },
      { lesson: 'num-ring', note: 'Who has an inverse, and why gcd decides.' },
      { topic: 'euclid', note: 'gcd by repeated division, drawn as squares in a rectangle.' },
      { topic: 'egcd', note: 'Carry s and t along, and the inverse falls out.' },
      { exercise: 'num-x-egcd-table', note: 'Fill the table yourself.' },
      { exercise: 'num-x-rsa-d', note: 'A private exponent from e.' },
      { topic: 'euler-phi', note: 'Counting the units with a sieve and with the factorisation.' },
      { topic: 'power-cycles', note: 'Powers return to 1, or run into a cycle that misses it.' },
      { topic: 'fermat-euler', note: 'Why a^φ(n) ≡ 1: multiplying by a unit reshuffles.' },
      { lesson: 'num-powers', note: 'The theorems, and square-and-multiply.' },
      { exercise: 'num-x-last-digits', note: 'The last two digits of 3²⁰²⁶.' },
      { topic: 'carmichael', note: 'Composites that pass Fermat\'s test for every coprime base.' },
      { topic: 'miller-rabin', note: 'A square root of 1 that is not ±1 gives the game away.' },
      { exercise: 'num-x-mr-chain', note: 'The chain for 1729, step by step.' },
      { topic: 'group-order', note: 'Orders divide the group size; generators have the largest.' },
      { topic: 'lagrange', note: 'Cosets cut the group into equal blocks.' },
      { exercise: 'num-x-generators', note: 'Every primitive root modulo 11.' },
      { topic: 'crt-clocks', note: 'Two clocks name every number below their product.' },
      { topic: 'crt-solve', note: 'One term per modulus, added up.' },
      { topic: 'crt-speedup', note: 'RSA decryption in two halves.' },
      { lesson: 'num-crt', note: 'The theorem, the formula and the speed-up together.' },
      { exercise: 'num-x-crt-table', note: 'Build a solution term by term.' },
      { topic: 'gf-p', note: 'GF(p): every nonzero element has a partner.' },
      { topic: 'gf2-poly', note: 'Bits as polynomials: add with XOR, no carries.' },
      { topic: 'gf2m-mul', note: 'Shift, add and reduce in GF(2ᵐ).' },
      { exercise: 'num-x-gmul-table', note: 'A GF(2⁸) product, row by row.' },
      { topic: 'gf256-inverse', note: 'Euclid on polynomials inverts a byte.' },
      { topic: 'gf256-table', note: 'Logarithms turn products into sums of exponents.' },
      { lesson: 'num-gf256', note: 'GF(2⁸) as AES uses it.' },
      { exercise: 'num-x-gf-inv', note: 'An inverse in the AES field.' },
    ],
  });

  // ---- what the diagram checker looks at on these pages -----------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'num lesson num-clock')) {
    const ready = (sel) => "document.querySelector('" + sel + "')";
    for (const ch of C.chapters.filter((c) => c.part === 'numbers')) for (const id of ch.lessons) S.Checks.push({ group: 'learn', name: 'num lesson ' + id, hash: 'lesson=' + id, ready: ready('#lessonView'), sel: '#main' });
    for (const id of ['num-ctf-rowing', 'num-ctf-clocks', 'num-ctf-impostor']) S.Checks.push({ group: 'learn', name: 'num challenge ' + id, hash: 'ctf/' + id, ready: ready('#ctfChallenge'), sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'num course', hash: 'course=num-course', ready: ready('#courseView'), sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
