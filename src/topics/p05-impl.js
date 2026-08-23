// Part 5, implementation and security: AES on T-tables (SubBytes, ShiftRows and MixColumns of a round folded into
// four 32-bit lookups per column), the cache lines those lookups touch and the key nibbles they give away; and what
// key length buys against exhaustive search, classical and with Grover's algorithm.
(function (S) {
  'use strict';
  const U = S.P5;
  const h8 = (v) => (v >>> 0).toString(16).padStart(8, '0');
  const wb = (v) => [v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];

  // ---- T-tables -----------------------------------------------------------------------------------------------------
  function ttable(inp) {
    const P = U.block(inp.pt), K = U.key(inp.key), A = S.AES, G = S.gf256, c = inp.col;
    const T = A.tt.tables(), run = A.tt.encrypt(P, K), ref = A.encrypt(P, K), s0 = ref.rounds[0].end, r1 = ref.rounds[1];
    const look = run.lookups.filter((l) => l.round === 1);
    const mine = look.filter((l) => l.col === c);
    const src = [0, 1, 2, 3].map((k) => k + 4 * ((c + k) % 4)), idx = src.map((i) => s0[i]);
    const words = idx.map((x, k) => T.Te[k][x]), kcol = r1.key.slice(4 * c, 4 * c + 4), kw = ((kcol[0] << 24) | (kcol[1] << 16) | (kcol[2] << 8) | kcol[3]) >>> 0;
    const outW = (words.reduce((a, b) => a ^ b, 0) ^ kw) >>> 0, outB = wb(outW), byteCol = r1.end.slice(4 * c, 4 * c + 4);
    const F = new S.Frames();
    const grid = (lit) => U.grid('tt:s', 40, 82, s0, { cw: 52, ch: 42, gap: 4, size: 16, title: 'after round 0: p ⊕ k', cls: (i) => (lit && src.includes(i) ? 'act' : '') }).items;
    const LX = 330, LY = 70, WC = 44;
    const wordRow = (k, show, cls) => {
      const y = LY + k * 50, items = [U.t('tt:wl' + k, LX, y + 26, `Te${k}[${U.h2(idx[k])}]`, k === 0 && cls === 'hot' ? 'hot' : 'strong', 'start', 14)];
      wb(words[k]).forEach((v, j) => items.push({ key: `tt:w${k}:${j}`, kind: 'cell', x: LX + 100 + j * (WC + 4), y: y + 6, w: WC, h: 32, rx: 3, text: show ? U.h2(v) : '', size: 15, cls: 'hex ' + (show ? cls || '' : 'soft') }));
      return items;
    };
    const keyRow = () => [U.t('tt:kl', LX, LY + 4 * 50 + 26, 'round key', 'key', 'start', 14), ...kcol.map((v, j) => ({ key: 'tt:k' + j, kind: 'cell', x: LX + 100 + j * (WC + 4), y: LY + 4 * 50 + 6, w: WC, h: 32, rx: 3, text: U.h2(v), size: 15, cls: 'hex key' }))];
    const outRow = (ok) => [{ key: 'tt:rule', kind: 'line', x1: LX + 96, y1: LY + 5 * 50 + 1, x2: LX + 100 + 4 * (WC + 4), y2: LY + 5 * 50 + 1, cls: 'rule' }, U.t('tt:xo', LX + 80, LY + 5 * 50 - 14, '⊕', 'strong', 'middle', 16), U.t('tt:ol', LX, LY + 5 * 50 + 30, 'column ' + c, 'hot', 'start', 14), ...outB.map((v, j) => ({ key: 'tt:o' + j, kind: 'cell', x: LX + 100 + j * (WC + 4), y: LY + 5 * 50 + 10, w: WC, h: 32, rx: 3, text: U.h2(v), size: 15, cls: 'hex hot' })), ...(ok ? [U.t('tt:ok', LX + 100 + 4 * (WC + 4) + 14, LY + 5 * 50 + 31, '= the byte-by-byte round 1', 'good', 'start', 14)] : [])];
    const SB = G.SBOX[idx[0]], te = wb(words[0]);
    // the cache: each table is 1 KB, sixteen lines of 64 bytes, each line sixteen entries
    const CX = 96, CY = 412, LW = 46;
    const cache = (upto) => {
      const items = [U.t('tt:ct', 40, CY - 14, 'cache lines of the four tables (64 bytes, 16 entries each)', 'title')];
      for (let k = 0; k < 4; k++) {
        items.push(U.t('tt:cn' + k, 40, CY + k * 36 + 22, 'Te' + k, 'strong', 'start', 13));
        const hit = new Set(look.filter((l, j) => l.table === 'Te' + k && j < upto).map((l) => l.line));
        for (let L = 0; L < 16; L++) items.push({ key: `tt:c${k}:${L}`, kind: 'cell', x: CX + L * LW, y: CY + k * 36, w: LW - 4, h: 30, rx: 3, text: L.toString(16), size: 13, cls: 'hex ' + (hit.has(L) ? 'hot' : 'soft') });
      }
      return items;
    };
    const lines = [...new Set(look.map((l) => l.table + l.line))].length;
    F.add({ items: [...grid(true), ...cache(0)], say: `Fast AES software folds SubBytes, ShiftRows and MixColumns of a round into table lookups. Round 1 starts from the state after round 0, the plaintext XOR the key. ShiftRows means output column ${c} reads the diagonal ${U.hex(idx, ' ')}: row k from column ${c} + k.`, facts: { c, idx }, meta: { stage: 'start' }, hl: { d: [0] } });
    F.add({ items: [...grid(true), ...wordRow(0, true, 'hot'), ...[1, 2, 3].flatMap((k) => wordRow(k, false)), ...cache(0)], say: `Te0 holds, for every byte x, the column MixColumns would make from S(x) in row 0: (02·S(x), S(x), S(x), 03·S(x)). For x = ${U.h2(idx[0])}, S(x) = ${U.h2(SB)}, so Te0[${U.h2(idx[0])}] = ${h8(words[0])}: ${U.h2(te[0])}, ${U.h2(te[1])}, ${U.h2(te[2])}, ${U.h2(te[3])}.`, facts: { x: idx[0], s: SB, w: h8(words[0]), te }, meta: { stage: 'te0' }, hl: { d: [1] } });
    F.add({ items: [...grid(true), ...[0, 1, 2, 3].flatMap((k) => wordRow(k, true)), ...cache(0)], say: `Te1, Te2 and Te3 are Te0 turned one, two and three bytes, for rows 1 to 3. The four lookups for column ${c} give ${words.map(h8).join(', ')}.`, facts: { words: words.map(h8), c }, meta: { stage: 'te' }, hl: { d: [2] } });
    F.add({ items: [...grid(true), ...[0, 1, 2, 3].flatMap((k) => wordRow(k, true)), ...keyRow(), ...outRow(true), ...cache(0)], say: `XOR the four words and the round key's column ${c}, ${U.hex(kcol)}: ${h8(outW)}. That is exactly column ${c} after round 1 the byte-by-byte way, ${U.hex(byteCol)}: four lookups and four XORs replace 16 S-box lookups and the field arithmetic.`, facts: { kcol, out: h8(outW), byteCol, c }, meta: { stage: 'xor' }, hl: { d: [3] } });
    const firstLines = look.slice(0, 4).map((l) => l.line);
    F.add({ items: [...grid(true), ...[0, 1, 2, 3].flatMap((k) => wordRow(k, true)), ...keyRow(), ...outRow(true), ...cache(4)], say: `Memory comes into the cache in lines of 64 bytes, 16 table entries. A lookup at index x touches line x >> 4 of its table: column 0's four lookups touch lines ${firstLines.map((v) => v.toString(16)).join(', ')} of Te0 to Te3.`, facts: { lines: firstLines }, meta: { stage: 'cache1' } });
    F.add({ items: [...grid(false), ...[0, 1, 2, 3].flatMap((k) => wordRow(k, true)), ...keyRow(), ...outRow(true), ...cache(16)], say: `All 16 lookups of round 1 touch ${lines} lines. Which lines were touched can be measured from outside, by another program sharing the cache, timing its own memory.`, facts: { lines }, meta: { stage: 'cache' } });
    // the leak: line = (p ⊕ k) >> 4, so the top nibble of k = line ⊕ top nibble of p
    const LY2 = 412, kn = Array.from(K.slice(0, 16), (v) => v >> 4), pn = Array.from(P, (v) => v >> 4), ln = Array.from(s0, (v) => v >> 4);
    const row = (key, y, label, vals, cls) => [U.t('tl:' + key, 40, y + 22, label, 'strong', 'start', 13), ...vals.map((v, i) => ({ key: `tl:${key}${i}`, kind: 'cell', x: 210 + i * 40, y, w: 36, h: 30, rx: 3, text: v.toString(16), size: 14, cls: 'hex ' + cls }))];
    const leak = [U.t('tl:t', 40, LY2 - 14, 'round 1 of 16 bytes: top nibbles', 'title'), ...row('l', LY2, 'line seen', ln, 'hot'), ...row('p', LY2 + 36, 'plaintext known', pn, ''), ...row('k', LY2 + 72, '⊕ = key top half', kn, 'key'), U.t('tl:n', 40, LY2 + 140, '64 of the 128 key bits, from the first round alone', 'heat', 'start', 14)];
    F.add({ items: [...grid(false), ...[0, 1, 2, 3].flatMap((k) => wordRow(k, true)), ...keyRow(), ...outRow(true), ...leak], say: `The leak: in round 1 every index is a plaintext byte XOR a key byte, so the line seen is the top nibble of p ⊕ k. An attacker who knows the plaintext XORs it out: key byte 0 starts with ${kn[0].toString(16)}, key byte 1 with ${kn[1].toString(16)}, and so on. Half of every key byte leaks; later rounds and more plaintexts give the rest.`, facts: { kn, k0: K[0], k1: K[1] }, meta: { stage: 'leak' }, hl: { d: [4] } });
    F.add({ items: [...grid(false), ...[0, 1, 2, 3].flatMap((k) => wordRow(k, true)), ...keyRow(), ...outRow(true), ...U.readout('tn', 40, 400, 800, 'implementations that do not leak this way', [['bitsliced', 'the S-box as logic gates on bit planes'], ['AES-NI and similar', 'a round is one processor instruction'], ['constant time', 'no table index depends on the key']], { dy: 34, size: 14, vsize: 14 })], say: `The defences: a bitsliced AES computes the S-box with logic operations on many blocks at once and looks nothing up; processors with AES instructions do a whole round in one instruction; either way no memory address depends on the key. The ciphertext here is ${U.hex(run.out)} in every implementation.`, facts: { C: run.out }, meta: { stage: 'notes' }, hl: { d: [5] } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('AES on T-tables', ['x = state after round 0 = p ⊕ k', 'Te0[x] = (02·S(x), S(x), S(x), 03·S(x)); Te1, Te2, Te3 = Te0 turned 1, 2, 3 bytes', 'Te1[x], Te2[x], Te3[x]: the same word rotated', 'column c ← Te0[s(0,c)] ⊕ Te1[s(1,c+1)] ⊕ Te2[s(2,c+2)] ⊕ Te3[s(3,c+3)] ⊕ k_c', 'cache line = index >> 4 = top nibble of p ⊕ k in round 1', 'defences: bitslicing, AES instructions, constant-time code']) };
  }
  S.topic({
    id: 'aes-ttable', family: 'p05-impl', order: 10, title: 'T-tables, and why they leak',
    blurb: 'Fast software folds a round into four 32-bit table lookups per column. The lookups are indexed by p ⊕ k, and the cache lines they touch can be seen from outside: half of every key byte leaks.',
    inputs: [
      { id: 'pt', kind: 'text', label: 'Plaintext (16 characters or 32 hex digits)', def: 'Lanterns at dusk', check: U.blockCheck('Plaintext') },
      { id: 'key', kind: 'text', label: 'Key (16 characters or 32 hex digits)', def: 'ochre-river-2026', check: U.keyCheck('Key', [16]) },
      { id: 'col', kind: 'number', label: 'Column to compute', def: 0, min: 0, max: 3 },
    ],
    presets: [
      { label: 'Column 0 of our own line', values: { pt: 'Lanterns at dusk', key: 'ochre-river-2026', col: 0 } },
      { label: 'Column 2', values: { pt: 'Lanterns at dusk', key: 'ochre-river-2026', col: 2 } },
      { label: 'FIPS 197 C.1, column 3', values: { pt: '00112233445566778899aabbccddeeff', key: '000102030405060708090a0b0c0d0e0f', col: 3 } },
      { label: 'All-zero plaintext: the lines show the key', values: { pt: '00000000000000000000000000000000', key: 'kiln-and-cobalt7', col: 1 } },
    ],
    run: ttable,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'te0', once: true, pick: 'option', options: ['Te0[x] shifted left', 'Te0[x] turned one byte', 'Te0[S(x)]', 'a separate random table'], ask: 'What is Te1[x], the table for row 1?', answer: 'Te0[x] turned one byte', explain: 'Row 1 of MixColumns has the same coefficients rotated: (03, 02, 01, 01), so each Te is Te0 turned.' }],
    quiz: [
      { q: 'How many bytes is each T-table?', options: ['256', '1,024', '4,096', '65,536'], answer: 1, why: '256 entries of 4 bytes.' },
      { q: 'In round 1, the index of a lookup is…', options: ['the key byte', 'the plaintext byte', 'plaintext byte ⊕ key byte', 'the round number'], answer: 2, why: 'The state after round 0 is p ⊕ k.' },
      { q: 'With 64-byte cache lines, which key bits does round 1 reveal?', options: ['None', 'The top 4 bits of each key byte', 'The low 4 bits', 'All of them'], answer: 1, why: 'The line number is index >> 4, the top nibble of p ⊕ k.' },
      { q: 'Which implementation is safe from this attack?', options: ['Bigger tables', 'Encrypting twice', 'A bitsliced or AES-instruction implementation', 'A longer key'], answer: 2, why: 'They make no key-dependent memory accesses at all.' },
    ],
  });

  // ---- key sizes and exhaustive search --------------------------------------------------------------------------------
  const YEAR = 365.25 * 86400, UNIVERSE = 13.8e9 * YEAR;
  /** a time in seconds, in words, with the numbers it states */
  const sci = (v) => { const e = Math.floor(Math.log10(v)), m = v / 10 ** e; let mm = m.toFixed(1); let ee = e; if (mm === '10.0') { mm = '1.0'; ee++; } return { m: mm, e: ee }; };
  const group = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  U.span = function (s) {
    if (s < 1e-3) return { text: 'under a millisecond', nums: [] };
    const two = (v) => +v.toPrecision(2);
    if (s < 60) return { text: two(s) + ' seconds', nums: [String(two(s))] };
    if (s < 3600) return { text: two(s / 60) + ' minutes', nums: [String(two(s / 60))] };
    if (s < 86400) return { text: two(s / 3600) + ' hours', nums: [String(two(s / 3600))] };
    if (s < YEAR) return { text: two(s / 86400) + ' days', nums: [String(two(s / 86400))] };
    const y = s / YEAR;
    if (y < 1e6) return { text: group(two(y)) + ' years', nums: [group(two(y))] };
    const q = sci(y);
    return { text: `${q.m} × 10^${q.e} years`, nums: [q.m, q.e] };
  };
  const SIZES = [[56, 'DES'], [64, '64-bit key'], [80, '80-bit key'], [112, '3DES (2 keys)'], [128, 'AES-128'], [192, 'AES-192'], [256, 'AES-256']];
  const BEST = { 128: 126.1, 192: 189.7, 256: 254.4 };
  function security(inp) {
    const rate = 10 ** inp.rate, mach = 10 ** inp.machines, total = rate * mach;
    const who = inp.machines ? `10^${inp.machines} machines` : 'one machine';
    const rows = SIZES.map(([n, name]) => ({ n, name, sec: 2 ** (n - 1) / total, q: 2 ** (n / 2) / total }));
    const F = new S.Frames();
    // a log scale of seconds from 10^-12 to 10^80
    const lg = rows.map((R) => Math.log10(R.q)).concat(rows.map((R) => Math.log10(R.sec)));
    const X0 = 200, X1 = 680, L0 = Math.min(-2, Math.floor(Math.min(...lg)) - 1), L1 = Math.max(22, Math.ceil(Math.max(...lg)) + 2), X = (s) => U.r2(X0 + ((Math.max(L0, Math.min(L1, Math.log10(s))) - L0) / (L1 - L0)) * (X1 - X0));
    const RY = 124, RH = 50;
    const axis = () => {
      const items = [{ key: 'ks:ax', kind: 'line', x1: X0, y1: RY - 14, x2: X0, y2: RY + SIZES.length * RH, cls: 'rule' }];
      [[1, '1 second', 0], [YEAR, '1 year', 1], [UNIVERSE, 'age of the universe', 0]].forEach(([s, t, row], j) => {
        items.push({ key: 'ks:m' + j, kind: 'line', x1: X(s), y1: RY - 10, x2: X(s), y2: RY + SIZES.length * RH - 6, cls: 'dash', audit: 'ignore', layer: 'back' });
        items.push(U.t('ks:mt' + j, X(s), RY - 40 + row * 18, t, 'tick', 'middle', 13));
      });
      const yb = RY + SIZES.length * RH;
      items.push({ key: 'ks:base', kind: 'line', x1: X0, y1: yb, x2: X1 + 150, y2: yb, cls: 'rule' });
      items.push(U.t('ks:lo', X0, yb + 18, `10^${String(L0).replace("-", "−")} s`, 'tick', 'middle', 13), U.t('ks:hi', X1 + 150, yb + 18, `10^${(L1 - L0) * 150 / (X1 - X0) + L1 | 0} s`, 'tick', 'end', 13));
      items.push(U.t('ks:t', 20, 34, `exhaustive search at 10^${inp.rate} keys a second on ${who}`, 'title'));
      items.push(U.t('ks:lt', 20, 58, 'expected time: half the keys, on a log scale', 'tick', 'start', 13));
      return items;
    };
    const bar = (i, upto, grover) => {
      const R = rows[i], y = RY + i * RH, items = [U.t('ks:n' + i, 20, y + 20, R.name, i <= upto ? 'strong' : 'tick', 'start', 14), U.t('ks:b' + i, 20, y + 37, R.n + ' bits', 'tick', 'start', 13)];
      if (i > upto) return items;
      items.push({ key: 'ks:bar' + i, kind: 'cell', x: X0, y: y + 6, w: Math.max(2, X(R.sec) - X0), h: grover ? 18 : 26, rx: 3, text: '', cls: 'bar ' + (R.sec > UNIVERSE ? 'good' : R.sec > YEAR ? 'act' : 'bad'), enter: 'grow' });
      if (!grover) items.push(U.t('ks:v' + i, X(R.sec) + 8, y + 24, U.span(R.sec).text, 'tick', 'start', 13));
      if (grover) items.push({ key: 'ks:q' + i, kind: 'cell', x: X0, y: y + 27, w: Math.max(2, X(R.q) - X0), h: 12, rx: 2, text: '', cls: 'bar hot', enter: 'grow' });
      return items;
    };
    const bars = (upto, grover) => SIZES.flatMap((_, i) => bar(i, upto, grover));
    const legend = (grover) => U.t('ks:lg', 20, RY + SIZES.length * RH + 46, grover ? 'thick bars: classical search · thin orange bars: Grover, about 2^(n/2) steps' : 'red: within a year · blue: within the age of the universe · green: beyond it', 'tick', 'start', 13);
    F.add({ items: [...axis(), ...bars(-1), legend()], say: `Exhaustive search tries keys until one works: on average half of them, 2^(n−1) for a key of n bits. Here the attacker has ${who}, each trying 10^${inp.rate} keys a second.`, facts: { rate: inp.rate, machines: inp.machines }, meta: { stage: 'start' }, hl: { d: [0] } });
    rows.forEach((R, i) => {
      const t = U.span(R.sec);
      F.add({ items: [...axis(), ...bars(i), legend()], say: `${R.name}, ${R.n} bits: 2^${R.n - 1} guesses on average take ${t.text}${R.sec > UNIVERSE ? ', longer than the universe has existed' : ''}.`, facts: { n: R.n, e: R.n - 1, t: t.nums }, meta: { stage: 'size', n: R.n }, hl: { d: [0, 1] } });
    });
    const g128 = U.span(rows[4].q), g256 = U.span(rows[6].q);
    F.add({ items: [...axis(), ...bars(SIZES.length, true), legend(true)], say: `Grover's quantum search needs only about 2^(n/2) steps, but they must run one after another: AES-128 drops to about 2^64 steps, ${g128.text} at this speed, while AES-256 keeps 2^128, ${g256.text}. That is why long-lived secrets use 256-bit keys.`, facts: { t1: g128.nums, t2: g256.nums, h: [64, 128] }, meta: { stage: 'grover' }, hl: { d: [2] } });
    F.add({ items: [...axis(), ...bars(SIZES.length, true), ...U.readout('ks:best', 470, 512, 370, 'best known attacks on full AES', [128, 192, 256].map((n) => [`AES-${n}`, `2^${BEST[n]} instead of 2^${n}`, 'good']), { dy: 26 })], say: `Twenty-five years of cryptanalysis have not dented AES much: the best known attacks on the full cipher, bicliques, cost about 2^${BEST[128]}, 2^${BEST[192]} and 2^${BEST[256]}, a few bits under exhaustive search. The key length is the security.`, facts: { best: Object.values(BEST) }, meta: { stage: 'best' }, hl: { d: [3] } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Key length against exhaustive search', ['expected work for an n-bit key: 2^(n−1) trials', 'time = 2^(n−1) / (keys per second × machines)', 'Grover: about 2^(n/2) sequential quantum steps', 'best known attacks on AES: a few bits under 2^n']) };
  }
  S.topic({
    id: 'aes-security', family: 'p05-impl', order: 20, title: 'Key length and exhaustive search',
    blurb: 'How long trying every key takes for DES, 3DES and the three AES sizes, at a speed you choose; what a quantum computer running Grover\'s search would change; and how little the best attacks gain.',
    inputs: [
      { id: 'rate', kind: 'number', label: 'Keys a second per machine (power of 10)', def: 12, min: 3, max: 18 },
      { id: 'machines', kind: 'number', label: 'Machines (power of 10)', def: 6, min: 0, max: 9 },
    ],
    presets: [
      { label: 'A large attacker: 10¹² keys/s on a million chips', values: { rate: 12, machines: 6 } },
      { label: 'One laptop: 10⁸ keys/s', values: { rate: 8, machines: 0 } },
      { label: 'A nation: 10¹⁵ keys/s on a billion chips', values: { rate: 15, machines: 9 } },
      { label: 'A thousand cheap boards at 10⁹', values: { rate: 9, machines: 3 } },
    ],
    run: security,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'size' && f.meta.n === 64, once: true, pick: 'option', options: ['about 2 times', 'about 16 times', 'about 65,000 times', 'about 10^19 times'], ask: 'An 80-bit key is next. How much longer than a 64-bit key will it take?', answer: 'about 65,000 times', explain: 'Sixteen more bits double the work sixteen times: 2^16 = 65,536.' }],
    quiz: [
      { q: 'Each extra key bit multiplies the work of exhaustive search by…', options: ['1.5', '2', '10', '256'], answer: 1, why: 'One more bit doubles the number of keys.' },
      { q: 'How many steps does Grover\'s algorithm need against a 128-bit key, roughly?', options: ['2^128', '2^64', '2^32', '128'], answer: 1, why: 'About the square root of the number of keys.' },
      { q: 'Why does a faster computer not threaten AES-256?', options: ['It is not faster', '2^255 trials outlast any speed-up that physics allows', 'AES-256 is slower to test', 'It has more rounds'], answer: 1, why: 'Even 10^30 keys a second leaves around 10^39 years.' },
      { q: 'The best known attacks on full AES-128 cost about…', options: ['2^56', '2^100', '2^126', '2^127.9'], answer: 2, why: 'Biclique attacks reach about 2^126.1: a speed-up of about four over brute force.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
