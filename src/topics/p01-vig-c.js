// Part 1: breaking Vigenère, move three. With the key length known, every column is a shift cipher of English: try
// all 26 shifts on each column and keep the one whose letter counts fit English best by chi-squared.
(function (S) {
  'use strict';
  const P = S.P1, ABC = P.ABC;
  const C = () => S.Classic;

  function picture(o) {
    const items = [], L = o.len;
    items.push(P.title('k:t', 0, -10, 'the key, one letter per column'));
    for (let i = 0; i < L; i++) {
      const known = i < o.found.length;
      items.push({ key: 'k:' + i, kind: 'cell', x: i * 32, y: 0, w: 30, h: 32, rx: 4, text: known ? o.found[i] : String(i + 1), size: known ? 16 : 13, cls: 'mono ' + (i === o.col ? 'hot' : known ? 'p1-key' : 'p1-ghost') });
    }
    if (o.col >= 0) {
      const col = o.cols[o.col], show = col.text.slice(0, 40);
      items.push(P.title('c:t', 0, 62, `column ${o.col + 1}: letters ${o.col + 1}, ${o.col + 1 + L}, ${o.col + 1 + 2 * L}, … (${col.text.length} letters)`));
      items.push(...P.strip('c:', 0, 72, show, { cw: 16, gap: 1, h: 24, size: 13, cls: () => 'p1-ct' }));
      // chi-squared for each shift
      const chis = col.chis, max = Math.max(...chis);
      items.push(P.title('x:t', 0, 132, 'χ² against English after undoing each shift (lower is a better fit)'));
      items.push(...P.bars('x:', 0, 246, chis, { w: 18, gap: 6, hmax: 96, max, cls: (s) => (s === col.shift ? 'p1-best' : o.showBest ? '' : 'act'), label: (s) => ABC[s], labelCls: (s) => (s === col.shift && o.showBest ? 'good' : '') }));
      if (o.showBest) {
        items.push(P.text('x:best', 0, 286, 'best: ' + ABC[col.shift] + ' (shift ' + col.shift + '), χ² ' + P.fmt(chis[col.shift]), 'good', 13));
        // the column's counts with the best shift undone, beside English's expected counts
        const counts = new Array(26).fill(0); for (const ch of col.text) counts[(ABC.indexOf(ch) - col.shift + 26) % 26]++;
        const n = col.text.length, exp = C().ENGLISH.map((p) => (p * n) / 100), m = Math.max(...counts, ...exp);
        items.push(P.title('h:t', 0, 318, `column ${o.col + 1} shifted back by ${col.shift} (${ABC[col.shift]}), beside English`));
        for (let i = 0; i < 26; i++) {
          const x = i * 24, h = (80 * counts[i]) / m, eh = (80 * exp[i]) / m;
          items.push({ key: 'h:c' + i, kind: 'cell', x, y: 410 - Math.max(1.5, h), w: 11, h: Math.max(1.5, h), rx: 2, text: '', cls: 'p1-bar act' });
          items.push({ key: 'h:e' + i, kind: 'cell', x: x + 12, y: 410 - Math.max(1.5, eh), w: 7, h: Math.max(1.5, eh), rx: 2, text: '', cls: 'p1-bar p1-eng' });
          items.push(P.text('h:l' + i, x + 9, 426, ABC[i].toLowerCase(), 'tick', 13, 'middle'));
        }
      }
    }
    if (o.plain) {
      items.push(P.title('d:t', 0, 62, 'the ciphertext decrypted with ' + o.found.join('')));
      P.rows(o.plain.slice(0, 96), 32).forEach((row, r) => items.push(...P.strip('d:' + r + ':', 0, 72 + r * 32, row, { cw: 19, gap: 1, h: 28, size: 14, cls: (i, ch) => (ch === o.truth[r * 32 + i] ? 'p1-pl' : 'p1-bad') })));
    }
    return items;
  }

  S.topic({
    id: 'p01-column-shifts', family: 'p01-vigenere', order: 40, title: 'Each column is a shift: recover the key letters',
    blurb: 'Once the key length m is known, write the ciphertext in m columns. Each column was enciphered by one key letter, a plain shift; undo each of the 26 shifts and keep the one whose letter counts fit English best.',
    inputs: P.VIG_INPUTS.concat([{ id: 'len', kind: 'number', label: 'Key length to try', def: 7, min: 1, max: 20 }]),
    presets: P.VIG_PRESETS.map((p) => ({ label: p.label, values: Object.assign({ len: P.letters(p.values.key).length }, p.values) })).concat([{ label: 'The keeper, LANTERN, wrong length 6', values: { src: 'keeper', key: 'LANTERN', len: 6 } }]),
    run(inp) {
      const { ct, plain, key } = P.vigCipher(inp), L = inp.len, cs = C().columnShifts(ct, L), F = new S.Frames(['letters']);
      const found = [];
      F.add({ items: picture({ len: L, found, col: -1, cols: cs.columns }), say: `Take the key length to be ${L} and split the ${ct.length} letters into ${L} columns: letter 1 goes to column 1, letter 2 to column 2, …, letter ${L + 1} back to column 1. Each column then holds about ${Math.round(ct.length / L)} letters, all shifted by the same key letter.`, meta: {} });
      cs.columns.forEach((col, i) => {
        F.add({ items: picture({ len: L, found, col: i, cols: cs.columns }), say: `Column ${i + 1}: ${col.text.slice(0, 16)}… For each shift s from 0 (A) to 25 (Z), shift the column back by s and compare its letter counts with English: χ² = Σ (seen − expected)² / expected.`, meta: { col: i, chis: col.chis, best: col.shift } });
        found.push(col.letter); F.count('letters');
        F.add({ items: picture({ len: L, found, col: i, cols: cs.columns, showBest: true }), say: cs.trace[i].say + ` The shifted counts now line up with English's.`, meta: { col: i, done: true, letter: col.letter } });
      });
      const dec = C().letters(C().vigenere.decrypt(ct, cs.key).out), right = Array.from(dec).filter((c, i) => c === plain[i]).length;
      const exact = cs.key === key;
      F.add({ items: picture({ len: L, found, col: -1, cols: cs.columns, plain: dec, truth: plain }), say: exact ? `The key is ${cs.key}, and the ciphertext decrypts to ${C().corpus.longExamples[inp.src].slice(0, 48).replace(/\s+\S*$/, '')}… Vigenère is broken: Kasiski or the IC gave the length, χ² gave each letter.` : L % key.length === 0 && cs.key === key.repeat(L / key.length) ? `The letters found are ${cs.key}, the key ${key} repeated: a multiple of the true length also works, just with more columns.` : `With length ${L} the letters found are ${cs.key}, and only ${right} of ${dec.length} letters come out right${L % key.length && key.length % L ? ': the columns mix several key letters, so no single shift fits and the result is nonsense. The length must come first.' : '. Short columns can fool χ²; scoring the whole text letter by letter fixes the stragglers.'}`, meta: { end: true } });
      return { frames: F.list, def: P.def('Per-column χ²', ['column j: letters j, j + m, j + 2m, …', 'for s = 0 … 25:', '  χ²(s) = Σ (count(x + s) − N·Eₓ)² / (N·Eₓ)', 'key letter j = the s with smallest χ²']), counters: [{ id: 'letters', label: 'key letters found' }] };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.done && fr[i + 1].meta.col > 0, pick: 'option', ask: 'Which shift fits best? Pick the key letter.', options: (fr, i) => { const m = fr[i].meta; const order = m.chis.map((v, s) => [v, s]).sort((a, b) => a[0] - b[0]).slice(0, 4).map((x) => ABC[x[1]]); return order.sort(); }, answer: (fr, i) => fr[i + 1].meta.letter, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What kind of cipher is a single column of a Vigenère ciphertext (for the right key length)?', options: ['a substitution with any alphabet', 'a shift cipher', 'a transposition', 'a one-time pad'], answer: 1, why: 'Every letter of the column was shifted by the same key letter.' },
      { q: 'A column\'s best shift is 4. The key letter is…', options: ['D', 'E', 'F', 'W'], answer: 1, why: 'A = 0, so shift 4 is E.' },
      { q: 'Why can χ² pick the wrong shift?', options: ['χ² is always right', 'A short column has too few letters to match English closely', 'The key has repeated letters', 'English has 26 letters'], answer: 1, why: 'With 20 or 30 letters the counts are noisy; two shifts can fit about equally well.' },
      { q: 'What happens if the key length is wrong (and not a multiple)?', options: ['The same key comes out', 'Each column mixes shifts, so no shift fits well and the text stays garbled', 'The key comes out reversed', 'Only the first letter is wrong'], answer: 1, why: 'The columns are no longer single shift ciphers.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
