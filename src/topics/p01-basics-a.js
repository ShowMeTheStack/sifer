// Part 1: the shift cipher on a two-ring wheel, and brute force over all 26 shifts ranked by how English each
// candidate reads.
(function (S) {
  'use strict';
  const P = S.P1, ABC = P.ABC;
  const C = () => S.Classic;
  const textCheck = (min, max) => (v) => { const n = P.letters(v).length; if (n < min) return 'Message: at least ' + min + ' letters'; if (String(v).length > max) return 'Message: at most ' + max + ' characters, so the picture stays readable'; return null; };

  // ---- the wheel ----------------------------------------------------------------------------------------------
  // radii chosen so that neighbouring letters keep clear even of each other's bounding boxes on the diagonals
  const WX = 232, WY = 232, RO = 212, RI = 172;
  const ang = (i) => (-90 + (i * 360) / 26) * (Math.PI / 180);
  /** the outer ring (plain, fixed) and the inner ring (cipher, turned k places): slot i shows plain i over cipher i + k */
  function wheel(k, o) {
    o = o || {};
    const items = [];
    items.push({ key: 'w:hub', kind: 'state', x: WX, y: WY, r: 52, lines: ['shift', 'k = ' + k], cls: 'block key', size: 15 });
    for (let i = 0; i < 26; i++) {
      const a = ang(i), c = (i + k) % 26;
      const hot = o.at === i;
      items.push({ key: 'w:o' + i, kind: 'state', x: WX + RO * Math.cos(a), y: WY + RO * Math.sin(a), r: 15, text: ABC[i], size: 15, cls: 'p1-pl' + (hot ? ' hot' : o.seen && o.seen.has(i) ? ' p1-seen' : '') });
      items.push({ key: 'w:i' + i, kind: 'state', x: WX + RI * Math.cos(a), y: WY + RI * Math.sin(a), r: 14, text: ABC[c], size: 15, cls: 'p1-ct' + (hot ? ' hot' : '') });
    }
    items.push(P.text('w:lo', WX, WY + RO + 44, 'outer ring: plain · inner ring: cipher', 'tick', 13, 'middle'));
    return items;
  }
  /** the message: plain rows with the cipher (or the other way round) beneath, up to the letter shown */
  const MX = 490, PER = 12, CW = 30, CG = 3;
  function message(top, bottom, upto, o) {
    o = o || {};
    const items = [], rows = P.rows(top, PER), tc = o.swap ? 'p1-ct' : 'p1-pl', bc = o.swap ? 'p1-pl' : 'p1-ct';
    items.push(P.title('m:t1', MX, 30, o.topName || 'plaintext'));
    items.push(P.title('m:t2', MX + 200, 30, o.bottomName || 'ciphertext'));
    rows.forEach((row, r) => {
      const y = 50 + r * 86;
      items.push(...P.strip('m:p' + r + ':', MX, y, row, { cw: CW, gap: CG, cls: (i) => tc + (r * PER + i === (o.hot === undefined ? upto : o.hot) ? ' hot' : '') }));
      const shown = Array.from(row, (ch, i) => (r * PER + i <= upto ? bottom[r * PER + i] : ' ')).join('');
      items.push(...P.strip('m:c' + r + ':', MX, y + 36, shown, { cw: CW, gap: CG, cls: (i) => (r * PER + i <= upto ? bc + (r * PER + i === (o.hot === undefined ? upto : o.hot) ? ' hot' : '') : 'soft') }));
    });
    return items;
  }

  S.topic({
    id: 'p01-shift', family: 'p01-basics', order: 10, title: 'The shift cipher',
    blurb: 'Every letter moves the same number of places round the alphabet, wrapping from Z back to A. The key is that one number, so there are only 26 keys.',
    inputs: [
      { id: 'text', kind: 'text', label: 'Message', def: 'MEET ME AT THE OLD BOATHOUSE', check: textCheck(1, 60) },
      { id: 'k', kind: 'number', label: 'Shift k', def: 3, min: 0, max: 25 },
      { id: 'dir', kind: 'choice', label: 'Direction', def: 'enc', options: [{ value: 'enc', label: 'encrypt' }, { value: 'dec', label: 'decrypt' }] },
    ],
    presets: [
      { label: 'Shift 3 on the boathouse note', values: { text: 'MEET ME AT THE OLD BOATHOUSE', k: 3, dir: 'enc' } },
      { label: 'Shift 13 twice is no cipher at all', values: { text: 'BRING THE BLUE LANTERN', k: 13, dir: 'enc' } },
      { label: 'Wrapping past Z: shift 20', values: { text: 'ZEBRA CROSSING AT SUNRISE', k: 20, dir: 'enc' } },
      { label: 'Decrypt with shift 7', values: { text: 'AOL MLYYF DPSS UVA YBU', k: 7, dir: 'dec' } },
    ],
    run(inp) {
      const k = inp.k, enc = inp.dir === 'enc';
      const r = enc ? C().shift.encrypt(inp.text, k) : C().shift.decrypt(inp.text, k);
      const src = P.letters(inp.text), out = P.letters(r.out), n = src.length;
      const steps = r.trace.filter((s) => s.kind === 'letter');
      // the wheel's slot for the letter being worked on: encrypting reads plain on the outside; decrypting finds
      // the cipher letter on the inside and reads the plain letter outside it
      // the letter's slot on the wheel is its plain letter in both directions: slot p shows plain p over cipher p + k
      const F = new S.Frames();
      const names = enc ? {} : { topName: 'ciphertext', bottomName: 'plaintext', swap: true };
      F.add({ items: wheel(0).concat(message(src, out, -1, names)), say: `The shift cipher moves every letter the same number of places along the alphabet. The two rings start lined up, so every letter stands for itself. The ${enc ? 'message' : 'ciphertext'} has ${P.plural(n, 'letter')}.`, meta: { stage: 'start' } });
      F.add({ items: wheel(k).concat(message(src, out, -1, names)), say: r.trace[0].say.replace(/^Every letter moves (\d+) places? (forward|back)/, (m, a, b) => `Turn the inner ring ${a} place${a === '1' ? '' : 's'}: every letter moves ${a} place${a === '1' ? '' : 's'} ${b}`) + (enc ? '' : ' To decrypt, find each letter on the inner ring and read the letter outside it.'), meta: { stage: 'turn' } });
      const shown = Math.min(n, 8), seen = new Set();
      for (let j = 0; j < shown; j++) {
        const st = steps[j], slot = st.p;
        F.add({ items: wheel(k, { at: slot, seen }).concat(message(src, out, j, names)), say: P.minus(st.say), meta: { letter: j, from: enc ? ABC[st.p] : ABC[st.c], to: enc ? ABC[st.c] : ABC[st.p] } });
        seen.add(slot);
      }
      if (n > shown) F.add({ items: wheel(k, { seen }).concat(message(src, out, n - 1, Object.assign({ hot: -1 }, names))), say: `The other ${P.plural(n - shown, 'letter')} go the same way. The ${enc ? 'ciphertext' : 'plaintext'} is ${out}.`, meta: { stage: 'rest' } });
      const back = P.letters((enc ? C().shift.decrypt(r.out, k) : C().shift.encrypt(r.out, k)).out);
      F.add({ items: wheel(k, { seen }).concat(message(src, out, n - 1, Object.assign({ hot: -1 }, names))), say: `Turning the ring ${enc ? 'back' : 'forward'} ${k} place${k === 1 ? '' : 's'} undoes it: ${out} becomes ${back} again. ${k === 13 ? 'With k = 13 both directions are the same, so encrypting twice gives the message back.' : 'There are only 26 keys, so anyone can try them all.'}`, meta: { stage: 'end', back } });
      return { frames: F.list, def: P.def('Shift cipher', ['letters as numbers: A = 0, B = 1, …, Z = 25', 'encrypt: c = (p + k) mod 26', 'decrypt: p = (c − k) mod 26', 'key: k = ' + k + ', one of 26']) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.letter !== undefined && fr[i + 1].meta.letter > 0, pick: 'option', ask: (fr, i) => `Which letter does ${fr[i + 1].meta.from} become?`, options: (fr, i) => P.letterOptions(fr[i + 1].meta.to, [fr[i + 1].meta.from, ABC[(ABC.indexOf(fr[i + 1].meta.to) + 1) % 26], ABC[(ABC.indexOf(fr[i + 1].meta.to) + 25) % 26]]), answer: (fr, i) => fr[i + 1].meta.to, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'With shift k = 5, what does Y encrypt to?', options: ['C', 'D', 'T', 'Z'], answer: 1, why: 'Y = 24; 24 + 5 = 29 ≡ 3 (mod 26), which is D.' },
      { q: 'How many different keys does the shift cipher have?', options: ['25', '26', '52', '26!'], answer: 1, why: 'k = 0 to 25; k = 0 leaves the text unchanged but is still a key.' },
      { q: 'A message was encrypted with k = 9. Which shift decrypts it?', options: ['9', '13', '17', '−17'], answer: 2, why: 'Undoing +9 is −9, and −9 ≡ 17 (mod 26).' },
      { q: 'Why is k = 13 special?', options: ['It is the strongest key', 'Encrypting twice gives the message back', 'It leaves vowels alone', 'It is not allowed'], answer: 1, why: '13 + 13 = 26 ≡ 0, so the same shift both encrypts and decrypts.' },
    ],
  });

  const FREIGHT = C().shift.encrypt('THE FREIGHT BOATS WAIT AT THE QUAY UNTIL THE TIDE TURNS', 23).out;
  // ---- brute force ---------------------------------------------------------------------------------------------
  const RH = 26, TX = 0, TY = 112, COLW = 400;
  /** the 26 candidates in two columns of 13, in the given order (rank → key) */
  function table(rows, shown, order, o) {
    o = o || {};
    const items = [];
    for (const c of [0, 1]) {
      items.push(P.title('t:h1' + c, TX + c * COLW, TY - 14, 'key'));
      items.push(P.title('t:h2' + c, TX + c * COLW + 44, TY - 14, 'candidate'));
      items.push(P.title('t:h3' + c, TX + c * COLW + 214, TY - 14, 'score'));
    }
    const lo = o.lo, hi = o.hi;
    order.forEach((k, pos) => {
      if (!shown.has(k)) return;
      const row = rows[k], x = TX + Math.floor(pos / 13) * COLW, y = TY + (pos % 13) * RH, best = o.best === k, cur = o.cur === k;
      const cls = best ? 'good' : cur ? 'act' : '';
      items.push({ key: 'r:k' + k, kind: 'cell', x, y, w: 34, h: RH - 4, rx: 3, text: String(k), size: 14, cls: 'mono ' + (best ? 'p1-best' : cur ? 'act' : 'soft') });
      items.push(P.text('r:p' + k, x + 44, y + 16, row.plain.slice(0, 18), 'mono ' + cls, 14));
      const frac = Math.max(0.02, (row.score - lo) / Math.max(1e-9, hi - lo));
      items.push({ key: 'r:s' + k, kind: 'cell', x: x + 214, y: y + 4, w: Math.max(3, 100 * frac), h: RH - 12, rx: 2, text: '', cls: 'p1-bar ' + (best ? 'p1-best' : cur ? 'act' : '') });
      items.push(P.text('r:sv' + k, x + 322, y + 16, P.fmt(row.score, 2), 'tick', 13));
    });
    return items;
  }
  S.topic({
    id: 'p01-brute-shift', family: 'p01-basics', order: 20, title: 'Brute force: try every key',
    blurb: 'With only 26 keys an attacker simply tries them all. The hard part is recognising the right answer without reading 26 texts: score each candidate against English and sort.',
    inputs: [
      { id: 'text', kind: 'text', label: 'Ciphertext', def: FREIGHT, check: textCheck(4, 120) },
    ],
    presets: [
      { label: 'A note about the freight boats', values: { text: FREIGHT } },
      { label: 'A weather report', values: { text: C().shift.encrypt('RAIN BY EVENING AND A STRONG WIND FROM THE WEST', 11).out } },
      { label: 'Very short: four letters', values: { text: 'ZLWK' } },
    ],
    run(inp) {
      const b = C().bruteShift(inp.text), rows = b.rows, ct = P.letters(inp.text);
      const lo = Math.min(...rows.map((r) => r.score)), hi = Math.max(...rows.map((r) => r.score));
      const F = new S.Frames(['tried']);
      const raw = String(inp.text).toUpperCase().replace(/\s+/g, ' ').trim();
      const head = () => [P.title('c:t', TX, 24, 'ciphertext'), P.text('c:v', TX, 52, raw.length > 64 ? raw.slice(0, 62) + '…' : raw, 'mono p1-cttext', 15)];
      const natural = [...Array(26).keys()], shown = new Set();
      F.add({ items: head().concat([P.text('c:n', TX, 80, `${ct.length} letters; 26 keys to try`, 'tick', 13)]), say: `The ciphertext has ${ct.length} letters. The method is known to be a shift, so the key is one of 26 numbers: try every one, decrypting with each.`, meta: {} });
      for (let k = 0; k < 26; k++) {
        shown.add(k); F.count('tried');
        const r = rows[k];
        F.add({ items: head().concat(table(rows, shown, natural, { lo, hi, cur: k })), say: `Key ${k}: shifting back ${k} gives ${r.plain.slice(0, 24)}${r.plain.length > 24 ? '…' : ''}, scoring ${P.fmt(r.score, 2)} per letter (χ² ${P.fmt(r.chi, 1)}).`, meta: { k }, slow: k > 2 });
      }
      const ranked = b.ranked.map((r) => r.k), best = b.best, second = b.ranked[1];
      F.add({ items: head().concat(table(rows, shown, ranked, { lo, hi, best: best.k })), say: `Sorted by score, key ${best.k} comes first at ${P.fmt(best.score, 2)} per letter; the runner-up, key ${second.k}, scores ${P.fmt(second.score, 2)}. ${ct.length < 10 ? 'With so few letters the scores are close, and a short text can read as English under more than one key.' : 'The gap is wide: only one candidate looks like English.'}`, meta: { sorted: true, best: best.k } });
      F.add({ items: head().concat(table(rows, shown, ranked, { lo, hi, best: best.k })).concat([P.title('c:at', TX, TY + 13 * RH + 22, 'plaintext'), P.text('c:ans', TX, TY + 13 * RH + 48, best.plain.length > 60 ? best.plain.slice(0, 58) + '…' : best.plain, 'mono good', 15)]), say: `The answer: key ${best.k}, plaintext ${C().shift.decrypt(raw, best.k).out}.`, meta: { end: true } });
      return { frames: F.list, def: P.def('Brute force', ['for k = 0 … 25:', '  candidate = shift back by k', '  score = Σ log P(quadgram) / letters', 'sort by score; the top one is English', 'χ² = Σ (seen − expected)² / expected'], []), counters: [{ id: 'tried', label: 'keys tried' }] };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.sorted, pick: 'option', ask: 'Which key will come out on top?', options: (fr, i) => { const b = fr[i + 1].meta.best; return [...new Set([b, (b + 3) % 26, (b + 13) % 26, (b + 23) % 26])].sort((x, y) => x - y).map(String); }, answer: (fr, i) => String(fr[i + 1].meta.best), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why does a computer score candidates instead of showing all 26 to a person?', options: ['It is faster to print', 'So the right one can be picked out automatically, which matters when there are millions of keys', 'Because some keys are illegal', 'To hide the plaintext'], answer: 1, why: 'Brute force needs a test for "this looks right"; scoring against English is that test.' },
      { q: 'What does the quadgram score measure?', options: ['How many vowels there are', 'How likely the text\'s four-letter groups are in English', 'The length of the text', 'How many keys were tried'], answer: 1, why: 'It adds up the log-probability of every four-letter group, so English-looking text scores high.' },
      { q: 'Why can a very short ciphertext be ambiguous?', options: ['Short texts cannot be shifted', 'Several keys can give something that looks like English', 'The key must be longer than the text', 'χ² is undefined'], answer: 1, why: 'With few letters there is little evidence; for a shift of four letters, more than one key can give a real word.' },
      { q: 'A cipher has 2^40 keys and a test takes a microsecond. Brute force takes about…', options: ['a second', 'a few minutes', 'about 13 days', 'longer than the age of the universe'], answer: 2, why: '2^40 ≈ 1.1 × 10^12 microseconds ≈ 1.1 × 10^6 seconds ≈ 12.7 days.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
