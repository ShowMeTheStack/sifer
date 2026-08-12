// Part 1: the affine cipher with its inverse found by extended Euclid, the keyword substitution alphabet, and
// Kerckhoffs' principle as a race between key spaces and an attacker who knows the method.
(function (S) {
  'use strict';
  const P = S.P1, ABC = P.ABC;
  const C = () => S.Classic;
  const textCheck = (min, max) => (v) => { const n = P.letters(v).length; if (n < min) return 'Message: at least ' + min + ' letters'; if (String(v).length > max) return 'Message: at most ' + max + ' characters, so the picture stays readable'; return null; };

  // ---- shared: the alphabet over its cipher alphabet ------------------------------------------------------------
  const AW = 28, AG = 2;
  /** plain A..Z (with numbers) over the cipher letters; o: {cipher: string or null, hot: plain index, dup: Set of plain indexes, key: Set of plain indexes in key colour} */
  function alphabet(x, y, o) {
    const items = [];
    items.push(P.text('a:l1', x - 10, y + 22, 'plain', 'tick', 13, 'end'));
    items.push(...P.strip('a:p', x, y, ABC, { cw: AW, gap: AG, h: 32, size: 15, cls: (i) => 'p1-pl' + (o.hot === i ? ' hot' : ''), sub: o.numbers ? (i) => i : null }));
    const cy = y + (o.numbers ? 56 : 40);
    items.push(P.text('a:l2', x - 10, cy + 22, 'cipher', 'tick', 13, 'end'));
    if (o.cipher) items.push(...P.strip('a:c', x, cy, o.cipher, { cw: AW, gap: AG, h: 32, size: 15, cls: (i) => (o.dup && o.dup.has(i) ? 'p1-bad' : o.hot === i ? 'hot' : o.key && o.key.has(i) ? 'p1-key' : 'p1-ct') }));
    else items.push(...P.strip('a:c', x, cy, ' '.repeat(26), { cw: AW, gap: AG, h: 32, cls: () => 'p1-ghost' }));
    return items;
  }
  /** message rows: the source letters over the result, filled up to letter upto */
  function message(prefix, x, y, src, out, upto, per, o) {
    o = o || {};
    const items = [], rows = P.rows(src, per);
    items.push(P.title(prefix + 't1', x, y - 12, o.top || 'plaintext'));
    items.push(P.title(prefix + 't2', x + 170, y - 12, o.bottom || 'ciphertext'));
    rows.forEach((row, r) => {
      const yy = y + r * 80;
      items.push(...P.strip(prefix + 'p' + r + ':', x, yy, row, { cw: 28, gap: 2, h: 30, size: 15, cls: (i) => (o.swap ? 'p1-ct' : 'p1-pl') + (r * per + i === (o.hot === undefined ? upto : o.hot) ? ' hot' : '') }));
      const shown = Array.from(row, (ch, i) => (r * per + i <= upto ? out[r * per + i] : ' ')).join('');
      items.push(...P.strip(prefix + 'c' + r + ':', x, yy + 33, shown, { cw: 28, gap: 2, h: 30, size: 15, cls: (i) => (r * per + i <= upto ? (o.swap ? 'p1-pl' : 'p1-ct') + (r * per + i === (o.hot === undefined ? upto : o.hot) ? ' hot' : '') : 'soft') }));
    });
    return items;
  }

  // ---- affine ----------------------------------------------------------------------------------------------------
  /** the extended Euclid table for the inverse: rows filled up to n */
  function euclid(x, y, rows, n, o) {
    o = o || {};
    const items = [P.title('e:t', x, y - 12, o.title || 'extended Euclid')];
    const head = ['q', 'r', 's', 't'], cw = 58;
    head.forEach((hd, c) => items.push({ key: 'e:h' + c, kind: 'cell', x: x + c * cw, y, w: cw - 2, h: 28, rx: 0, text: hd, cls: 'head' }));
    rows.forEach((row, r) => {
      if (r >= n) return;
      const vals = [row.q === null ? '' : row.q, row.r, row.s, row.t];
      vals.forEach((v, c) => items.push({ key: 'e:' + r + ',' + c, kind: 'cell', x: x + c * cw, y: y + 30 + r * 30, w: cw - 2, h: 28, rx: 0, text: String(v).replace('-', '−'), size: 15, cls: 'mono tcell' + (r === n - 1 && o.hotLast ? ' act' : '') + (o.answer && r === o.answer[0] && c === o.answer[1] ? ' p1-good' : '') }));
    });
    return items;
  }
  S.topic({
    id: 'p01-affine', family: 'p01-basics', order: 30, title: 'The affine cipher and its inverse',
    blurb: 'Multiply the letter\'s number by a and add b, modulo 26. The map can be undone only when a has an inverse modulo 26, and the extended Euclidean algorithm finds it.',
    inputs: [
      { id: 'a', kind: 'number', label: 'Multiplier a', def: 5, min: 1, max: 25 },
      { id: 'b', kind: 'number', label: 'Shift b', def: 8, min: 0, max: 25 },
      { id: 'text', kind: 'text', label: 'Message', def: 'BRING THE BLUE LANTERN', check: textCheck(1, 40) },
    ],
    presets: [
      { label: 'a = 5, b = 8', values: { a: 5, b: 8, text: 'BRING THE BLUE LANTERN' } },
      { label: 'a = 7, b = 3', values: { a: 7, b: 3, text: 'THE TIDE TURNS AT NINE' } },
      { label: 'a = 13 cannot be undone', values: { a: 13, b: 4, text: 'AN ORANGE BOAT' } },
      { label: 'a = 25: the alphabet reversed', values: { a: 25, b: 25, text: 'MILL STREET BAKERY' } },
      { label: 'a = 4 shares a factor with 26', values: { a: 4, b: 1, text: 'CANDLE AND QUILL' } },
    ],
    run(inp) {
      const a = inp.a, b = inp.b, enc = C().affine.encrypt(inp.text, a, b), inv = C().inverse(a, 26);
      const src = P.letters(inp.text), F = new S.Frames();
      const AX = 70, AY = 30, EX = 0, EY = 180, MX = 280, MY = 180, PER = 14;
      const table = Array.from(ABC, (c, i) => ABC[C().mod(a * i + b)]).join('');
      F.add({ items: alphabet(AX, AY, { numbers: true }), say: `The affine cipher turns each letter p into c = ${a}·p + ${b} (mod 26). With a = 1 it would be a shift; the multiplier mixes the alphabet more, but only some values of a work.`, meta: {} });
      if (enc.out === null) {
        // a shares a factor with 26: show the collisions, then Euclid's verdict
        const seen = {}, dup = new Set();
        for (let i = 0; i < 26; i++) { const c = table[i]; if (seen[c] !== undefined) { dup.add(i); dup.add(seen[c]); } else seen[c] = i; }
        const first = [...dup].sort((x, y) => x - y), p1 = first[0], p2 = first.find((i) => i !== p1 && table[i] === table[p1]);
        F.add({ items: alphabet(AX, AY, { numbers: true, cipher: table, dup }), say: `Fill in c = ${a}·p + ${b} for every letter: ${ABC[p1]} (${p1}) gives ${a}·${p1} + ${b} ≡ ${C().mod(a * p1 + b)} and ${ABC[p2]} (${p2}) gives ${a}·${p2} + ${b} = ${a * p2 + b} ≡ ${C().mod(a * p2 + b)}: both become ${table[p1]}. Only ${new Set(table).size} different cipher letters appear, so a ciphertext letter cannot tell which plain letter it was.`, meta: { collide: true } });
        const tr = inv.trace;
        for (let k = 0; k < tr.length; k++) {
          const n = tr[k].kind === 'egcd-start' ? 2 : tr[k].kind === 'egcd-row' ? tr[k].index + 1 : inv.rows.length;
          F.add({ items: alphabet(AX, AY, { numbers: true, cipher: table, dup }).concat(euclid(EX, EY, inv.rows, n, { hotLast: tr[k].kind === 'egcd-row', title: 'extended Euclid on 26 and ' + a })), say: P.minus(tr[k].say), meta: { euclid: k } });
        }
        F.add({ items: alphabet(AX, AY, { numbers: true, cipher: table, dup }).concat(euclid(EX, EY, inv.rows, inv.rows.length, { title: 'extended Euclid on 26 and ' + a })), say: enc.trace[enc.trace.length - 1].say + ` Of the 25 multipliers only the 12 coprime to 26 work (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25), which gives 12 × 26 = ${C().affine.keys().length} keys.`, meta: { end: true } });
        return { frames: F.list, def: P.def('Affine cipher', ['encrypt: c = (a·p + b) mod 26', 'decrypt: p = a⁻¹·(c − b) mod 26', 'needs gcd(a, 26) = 1', 'a = ' + a + ': gcd(' + a + ', 26) = ' + inv.g]) };
      }
      const ai = enc.inv, steps = enc.trace.filter((s) => s.kind === 'letter');
      F.add({ items: alphabet(AX, AY, { numbers: true, cipher: table }), say: enc.trace[0].say + ` The whole alphabet: ${table}.`, meta: {} });
      const shown = Math.min(src.length, 6);
      for (let j = 0; j < shown; j++) {
        const st = steps[j];
        F.add({ items: alphabet(AX, AY, { numbers: true, cipher: table, hot: st.p }).concat(message('m:', MX, MY, src, P.letters(enc.out), j, PER)), say: st.say, meta: { letter: j, from: ABC[st.p], to: ABC[st.c] } });
      }
      const ct = P.letters(enc.out);
      if (src.length > shown) F.add({ items: alphabet(AX, AY, { numbers: true, cipher: table }).concat(message('m:', MX, MY, src, ct, src.length - 1, PER, { hot: -1 })), say: `The rest the same way. The ciphertext is ${ct}.`, meta: {} });
      // the inverse, row by row
      const tr = inv.trace, last = inv.rows.length - 2;
      for (let k = 0; k < tr.length; k++) {
        const n = tr[k].kind === 'egcd-start' ? 2 : tr[k].kind === 'egcd-row' ? tr[k].index + 1 : inv.rows.length;
        const done = tr[k].kind === 'inverse';
        F.add({ items: alphabet(AX, AY, { numbers: true, cipher: table }).concat(euclid(EX, EY, inv.rows, n, { hotLast: tr[k].kind === 'egcd-row', answer: done || tr[k].kind === 'egcd-done' ? [last, 3] : null, title: 'Euclid: inverse of ' + a + ' mod 26' })).concat(message('m:', MX, MY, src, ct, src.length - 1, PER, { hot: -1 })), say: (k === 0 ? `To decrypt we must undo the multiplication by ${a}, so we need a number a⁻¹ with ${a}·a⁻¹ ≡ 1 (mod 26). Extended Euclid on 26 and ${a}: ` + P.lower1(P.minus(tr[k].say)) : P.minus(tr[k].say)), meta: done ? { inverse: ai, a } : { euclid: k } });
      }
      // decrypt the first letters with the inverse
      const dec = C().affine.decrypt(enc.out, a, b), ds = dec.trace.filter((s) => s.kind === 'letter');
      const dshown = Math.min(3, ds.length);
      for (let j = 0; j < dshown; j++) F.add({ items: alphabet(AX, AY, { numbers: true, cipher: table, hot: ds[j].p }).concat(euclid(EX, EY, inv.rows, inv.rows.length, { answer: [last, 3], title: 'Euclid: inverse of ' + a + ' mod 26' })).concat(message('d:', MX, MY, ct, P.letters(dec.out), j, PER, { top: 'ciphertext', bottom: 'decrypted', swap: true })), say: (j === 0 ? `Decrypt with p = ${ai}·(c − ${b}). ` : '') + P.minus(ds[j].say), meta: { dec: j } });
      F.add({ items: alphabet(AX, AY, { numbers: true, cipher: table }).concat(euclid(EX, EY, inv.rows, inv.rows.length, { answer: [last, 3], title: 'Euclid: inverse of ' + a + ' mod 26' })).concat(message('d:', MX, MY, ct, P.letters(dec.out), ct.length - 1, PER, { top: 'ciphertext', bottom: 'decrypted', swap: true, hot: -1 })), say: `Every letter comes back: ${P.letters(dec.out)}. The key (${a}, ${b}) is one of ${C().affine.keys().length}: 12 multipliers coprime to 26, times 26 shifts, few enough to try them all.`, meta: { end: true } });
      return { frames: F.list, def: P.def('Affine cipher', ['encrypt: c = (a·p + b) mod 26', 'decrypt: p = a⁻¹·(c − b) mod 26', 'a⁻¹: a·a⁻¹ ≡ 1 (mod 26), by Euclid', 'a = ' + a + ', b = ' + b + ', a⁻¹ = ' + ai]) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.letter !== undefined && fr[i + 1].meta.letter > 0, pick: 'option', ask: (fr, i) => `Which letter does ${fr[i + 1].meta.from} become?`, options: (fr, i) => P.letterOptions(fr[i + 1].meta.to, [fr[i + 1].meta.from]), answer: (fr, i) => fr[i + 1].meta.to, explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.inverse !== undefined, pick: 'option', ask: (fr, i) => `So what is the inverse of ${fr[i + 1].meta.a} modulo 26?`, options: (fr, i) => { const v = fr[i + 1].meta.inverse; return [...new Set([v, (v + 2) % 26, 26 - v, (v + 12) % 26].filter((x) => x > 0))].sort((x, y) => x - y).map(String); }, answer: (fr, i) => String(fr[i + 1].meta.inverse), explain: (fr, i) => fr[i + 1].say, once: true },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.collide, pick: 'option', ask: 'Can this key be used?', options: ['yes', 'no: two letters would encrypt alike'], answer: 'no: two letters would encrypt alike', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Which multiplier is allowed in an affine cipher mod 26?', options: ['2', '13', '15', '26'], answer: 2, why: 'gcd(15, 26) = 1; 2 and 26 share 2 with 26, and 13 shares 13.' },
      { q: 'What is the inverse of 3 modulo 26?', options: ['3', '9', '17', '23'], answer: 1, why: '3 · 9 = 27 ≡ 1 (mod 26).' },
      { q: 'How many affine keys are there modulo 26?', options: ['26', '312', '650', '26!'], answer: 1, why: '12 valid multipliers times 26 shifts.' },
      { q: 'Extended Euclid on 26 and a ends with 1 = s·26 + t·a. The inverse of a is…', options: ['s mod 26', 't mod 26', 's·t', '26 − s'], answer: 1, why: 't·a ≡ 1 − s·26 ≡ 1 (mod 26).' },
    ],
  });

  // ---- keyword substitution ---------------------------------------------------------------------------------------
  S.topic({
    id: 'p01-substitution', family: 'p01-basics', order: 40, title: 'Substitution with a keyword alphabet',
    blurb: 'Any rearrangement of the alphabet can be the key. A keyword makes one easy to remember: write its letters without repeats, then the rest of the alphabet.',
    inputs: [
      { id: 'word', kind: 'text', label: 'Keyword', def: 'LIGHTHOUSE KEEPER', check: (v) => (P.letters(v).length < 1 ? 'Keyword: at least one letter' : P.letters(v).length > 26 ? 'Keyword: at most 26 letters' : null) },
      { id: 'cont', kind: 'choice', label: 'Rest of the alphabet', def: 'a', options: [{ value: 'a', label: 'from A' }, { value: 'after', label: 'after the last keyword letter' }] },
      { id: 'text', kind: 'text', label: 'Message', def: 'THE LAMP TURNS AT DUSK', check: textCheck(1, 40) },
    ],
    presets: [
      { label: 'LIGHTHOUSE KEEPER', values: { word: 'LIGHTHOUSE KEEPER', cont: 'a', text: 'THE LAMP TURNS AT DUSK' } },
      { label: 'Continuing after the keyword', values: { word: 'ORCHARD', cont: 'after', text: 'PICK THE PEARS ON FRIDAY' } },
      { label: 'FERRYMAN', values: { word: 'FERRYMAN', cont: 'a', text: 'NO CROSSING ON SATURDAY' } },
    ],
    run(inp) {
      const kw = C().substitution.keywordAlphabet(inp.word, { continueFrom: inp.cont === 'after' }), alpha = kw.alphabet;
      const word = P.letters(inp.word), uniq = kw.trace[0].unique, src = P.letters(inp.text);
      const enc = C().substitution.encrypt(inp.text, alpha), ct = P.letters(enc.out), F = new S.Frames();
      const KX = 70, KY = 30, AX = 70, AY = 120, MX = 70, MY = 240, PER = 20;
      const keyIdx = new Set([...Array(uniq.length).keys()]);
      const kwRow = (mark) => [P.title('k:t', KX, KY - 10, 'keyword')].concat(P.strip('k:', KX, KY, word.slice(0, 26), { cw: 30, gap: 2, h: 32, size: 15, cls: (i, ch) => (mark && word.indexOf(ch) !== i ? 'p1-ghost' : 'p1-key') }));
      F.add({ items: kwRow(false).concat(alphabet(AX, AY, {})), say: `The key is a whole rearranged alphabet. Start from the keyword ${word}.`, meta: {} });
      F.add({ items: kwRow(true).concat(alphabet(AX, AY, { cipher: uniq.padEnd(26, ' '), key: keyIdx })), say: kw.trace[0].say + ` ${word.length - uniq.length ? `${P.plural(word.length - uniq.length, 'repeat')} dropped.` : 'Nothing repeats.'}`, meta: { stage: 'unique' } });
      F.add({ items: kwRow(true).concat(alphabet(AX, AY, { cipher: alpha, key: keyIdx })), say: kw.trace[1].say, meta: {} });
      F.add({ items: kwRow(true).concat(alphabet(AX, AY, { cipher: alpha, key: keyIdx })), say: kw.trace[2].say, meta: {} });
      const steps = enc.trace.filter((s) => s.kind === 'letter'), shown = Math.min(src.length, 6);
      for (let j = 0; j < shown; j++) F.add({ items: kwRow(true).concat(alphabet(AX, AY, { cipher: alpha, key: keyIdx, hot: steps[j].p })).concat(message('m:', MX, MY, src, ct, j, PER)), say: `${ABC[steps[j].p]} is found in the top row and ${ABC[steps[j].c]} sits beneath it, so ${ABC[steps[j].p]} becomes ${ABC[steps[j].c]}.`, meta: { letter: j, from: ABC[steps[j].p], to: ABC[steps[j].c] } });
      if (src.length > shown) F.add({ items: kwRow(true).concat(alphabet(AX, AY, { cipher: alpha, key: keyIdx })).concat(message('m:', MX, MY, src, ct, src.length - 1, PER, { hot: -1 })), say: `The rest the same way: the ciphertext is ${ct}.`, meta: {} });
      const fixed = [...ABC].filter((c, i) => alpha[i] === c);
      const n = P.factorial(26);
      F.add({ items: kwRow(true).concat(alphabet(AX, AY, { cipher: alpha, key: keyIdx })).concat(message('m:', MX, MY, src, ct, src.length - 1, PER, { hot: -1 })), say: `Any of the 26! = ${P.big(n)} orderings (about ${P.sci(n)}) could be the key, far too many to try one by one. ${fixed.length ? `This one leaves ${P.list(fixed)} unchanged, which is allowed.` : 'This one moves every letter.'} Yet every E of the message still becomes the same cipher letter, and that is its weakness.`, meta: { end: true } });
      return { frames: F.list, def: P.def('Monoalphabetic substitution', ['key: a rearranged alphabet π', 'encrypt: c = π(p)', 'decrypt: p = π⁻¹(c)', 'keys: 26! ≈ 4.03 × 10^26', 'keyword: ' + uniq + ' + the rest']) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.letter !== undefined && fr[i + 1].meta.letter > 0, pick: 'option', ask: (fr, i) => `Which letter does ${fr[i + 1].meta.from} become?`, options: (fr, i) => P.letterOptions(fr[i + 1].meta.to, [fr[i + 1].meta.from]), answer: (fr, i) => fr[i + 1].meta.to, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'With the keyword BANANA (rest from A), what is the cipher alphabet\'s start?', options: ['BANANA…', 'BANCDE…', 'BANACD…', 'ABNCDE…'], answer: 1, why: 'Without repeats BANANA is BAN; then C, D, E… skipping letters already used.' },
      { q: 'How many keys does a monoalphabetic substitution have?', options: ['26', '312', '26²', '26!'], answer: 3, why: 'Any ordering of the 26 letters: 26! ≈ 4 × 10^26.' },
      { q: 'Why is a huge key space not enough here?', options: ['Keys are hard to remember', 'Letter frequencies survive encryption, so the key can be worked out piece by piece', 'The cipher is too slow', 'Some keys leave letters unchanged'], answer: 1, why: 'Each plain letter always becomes the same cipher letter, so English\'s letter counts show through.' },
      { q: 'How do you decrypt with a substitution alphabet?', options: ['Apply it again', 'Find the cipher letter in the bottom row and read the letter above', 'Shift back by the keyword length', 'Reverse the ciphertext'], answer: 1, why: 'Decryption uses the inverse permutation: read the table upwards.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
