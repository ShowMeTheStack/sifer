// Part 1: Playfair. A keyword fills a 5×5 square (I and J share a cell); the message is cut into pairs, and each pair
// becomes another pair by one of three rules: same row, same column, or the other corners of their rectangle.
(function (S) {
  'use strict';
  const P = S.P1;
  const C = () => S.Classic;
  const SQ = 46, PX = 290, PPER = 6, PW = 70;
  function picture(sq, pairs, out, o) {
    o = o || {};
    const items = [P.title('s:t', 0, -12, 'the square')];
    const hot = new Set(), good = new Set();
    if (o.pair !== undefined) {
      const pr = pairs[o.pair], ou = out[o.pair];
      if (pr) for (const ch of pr) hot.add(sq.indexOf(ch));
      if (ou && o.show) for (const ch of ou) good.add(sq.indexOf(ch));
    }
    for (let i = 0; i < 25; i++) {
      const r = Math.floor(i / 5), c = i % 5, ch = sq[i];
      items.push({ key: 's:' + i, kind: 'cell', x: c * SQ, y: r * SQ, w: SQ - 4, h: SQ - 4, rx: 5, text: ch === 'I' ? 'I/J' : ch, size: ch === 'I' ? 14 : 18, cls: 'mono ' + (hot.has(i) ? 'hot' : good.has(i) ? 'p1-good' : o.keyCells && i < o.keyCells ? 'p1-key' : 'p1-pl') });
    }
    if (o.rect) {
      const [a, b] = o.rect, r0 = Math.min(a[0], b[0]), r1 = Math.max(a[0], b[0]), c0 = Math.min(a[1], b[1]), c1 = Math.max(a[1], b[1]);
      items.push({ key: 's:rect', kind: 'region', x: c0 * SQ - 4, y: r0 * SQ - 4, w: (c1 - c0 + 1) * SQ + 4, h: (r1 - r0 + 1) * SQ + 4, rx: 8, cls: 'hot', audit: 'overlap-ok', layer: 'back' });
    }
    if (o.rule) items.push(P.text('s:rule', 0, 5 * SQ + 22, o.rule, 'hot', 14));
    if (pairs) {
      items.push(P.title('p:t', PX, -12, 'pairs, and what they become'));
      pairs.forEach((pr, k) => {
        const x = PX + (k % PPER) * PW, y = Math.floor(k / PPER) * 90;
        const cur = o.pair === k, done = o.upto !== undefined && k <= o.upto;
        items.push(...P.strip('p:a' + k + ':', x, y, pr, { cw: 28, gap: 2, h: 30, size: 15, cls: (i) => (cur ? 'hot' : o.added && o.added.has(k * 2 + i) ? 'p1-key' : 'p1-pl') }));
        items.push(...P.strip('p:b' + k + ':', x, y + 34, done ? out[k] : '  ', { cw: 28, gap: 2, h: 30, size: 15, cls: () => (done ? (cur ? 'p1-good' : 'p1-ct') : 'p1-ghost') }));
      });
    }
    return items;
  }
  S.topic({
    id: 'p01-playfair', family: 'p01-transposition', order: 30, title: 'Playfair: two letters at a time',
    blurb: 'Pairs of letters are enciphered together on a 5×5 keyword square. With about 600 possible pairs instead of 26 letters, single-letter counting no longer works, though pair counting still does.',
    inputs: [
      { id: 'key', kind: 'text', label: 'Keyword', def: 'WEATHER STATION', check: (v) => (P.letters(v).length > 25 ? 'Keyword: at most 25 letters' : null) },
      { id: 'text', kind: 'text', label: 'Message', def: 'MEET ME BY THE HILL GATE', check: (v) => { const n = P.letters(v).length; return n < 2 ? 'Message: at least 2 letters' : n > 30 ? 'Message: at most 30 letters' : null; } },
      { id: 'dir', kind: 'choice', label: 'Direction', def: 'enc', options: [{ value: 'enc', label: 'encrypt' }, { value: 'dec', label: 'decrypt' }] },
    ],
    presets: [
      { label: 'WEATHER STATION', values: { key: 'WEATHER STATION', text: 'MEET ME BY THE HILL GATE', dir: 'enc' } },
      { label: 'A doubled letter and an odd end', values: { key: 'LIBRARY', text: 'THE BOOKS ARE DUE', dir: 'enc' } },
      { label: 'Decrypt with HARBOUR', values: { key: 'HARBOUR', text: C().playfair.encrypt('THE BOAT LEAVES AT DAWN', 'HARBOUR').out, dir: 'dec' } },
    ],
    run(inp) {
      const enc = inp.dir === 'enc', r = enc ? C().playfair.encrypt(inp.text, inp.key) : C().playfair.decrypt(inp.text, inp.key);
      const sq = r.square, pairs = r.pairs, steps = r.trace.filter((t) => t.kind === 'pf-pair'), out = steps.map((t) => t.out), F = new S.Frames();
      const keyCells = new Set(P.letters(inp.key).replace(/J/g, 'I')).size;
      F.add({ items: picture(sq, null, out, { keyCells }), say: r.trace[0].say, meta: {} });
      // the letters Playfair added to the message: an X between doubles, an X at an odd end
      const added = new Set();
      if (enc) { const src = P.letters(inp.text).replace(/J/g, 'I'); let i = 0; pairs.forEach((pr, k) => { for (let j = 0; j < 2; j++) { if (src[i] === pr[j]) i++; else added.add(2 * k + j); } }); }
      const notes = r.trace.filter((t) => t.kind === 'pf-split' || t.kind === 'pf-pad').map((t) => t.say.replace(/\.$/, ''));
      F.add({ items: picture(sq, pairs, out, { keyCells, added }), say: enc ? `Cut the message into pairs, J written as I. ${notes.length ? notes.join('; ') + '. ' : 'No pair is doubled and the length is even, so nothing is added. '}${r.trace.find((t) => t.kind === 'pf-pairs').say}` : `Cut the ciphertext into pairs: ${pairs.join(' ')}. Decryption uses the same square with the row and column moves reversed.`, meta: {} });
      const shown = Math.min(pairs.length, 8);
      for (let k = 0; k < shown; k++) {
        const t = steps[k], a = t.a, b = t.b;
        const rule = t.rule === 'row' ? 'same row' : t.rule === 'column' ? 'same column' : 'rectangle';
        F.add({ items: picture(sq, pairs, out, { keyCells, pair: k, upto: k - 1, rect: t.rule === 'rectangle' ? [a, b] : null, added }), say: `Pair ${k + 1}: ${t.pair}. ${t.pair[0]} is in row ${a[0] + 1}, column ${a[1] + 1}; ${t.pair[1]} in row ${b[0] + 1}, column ${b[1] + 1}.`, meta: { pair: k, rule } });
        F.add({ items: picture(sq, pairs, out, { keyCells, pair: k, upto: k, show: true, rect: t.rule === 'rectangle' ? [a, b] : null, rule: P.cap(rule) + ': ' + t.pair + ' → ' + t.out, added }), say: t.say, meta: { pair: k, done: true, out: t.out } });
      }
      if (pairs.length > shown) F.add({ items: picture(sq, pairs, out, { keyCells, upto: pairs.length - 1, added }), say: `The other ${P.plural(pairs.length - shown, 'pair')} the same way.`, meta: {} });
      F.add({ items: picture(sq, pairs, out, { keyCells, upto: pairs.length - 1, added }), say: enc ? `The ciphertext is ${r.out}. A letter never meets itself in a pair, and a pair and its reverse (say ${pairs[0]} and ${pairs[0][1] + pairs[0][0]}) always encrypt to reverses of each other, clues that pair counts can exploit.` : `The plaintext is ${r.out}; the receiver drops the padding X letters by sense.`, meta: { end: true } });
      return { frames: F.list, def: P.def('Playfair', ['square: keyword, then the rest (I = J)', 'pairs: split doubles with X, pad an odd end', 'same row: take the letters to the right', 'same column: take the letters below', 'rectangle: take the other corners,', '  each staying in its own row', 'decrypt: left and up instead']) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.pair !== undefined && !fr[i + 1].meta.done && fr[i + 1].meta.pair > 0, pick: 'option', ask: 'Which rule will the next pair use?', options: ['same row', 'same column', 'rectangle'], answer: (fr, i) => fr[i + 1].meta.rule, explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.done && fr[i + 1].meta.pair > 0, pick: 'option', ask: 'What does the pair become?', options: (fr, i) => { const o = fr[i + 1].meta.out; return [...new Set([o, o[1] + o[0], o[0] + 'X', 'Q' + o[1]])].sort(); }, answer: (fr, i) => fr[i + 1].meta.out, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why does Playfair insert an X into BALLOON?', options: ['To pad the end', 'To break the doubled LL so no pair has two equal letters', 'X is the key', 'For decoration'], answer: 1, why: 'BA LX LO ON: a pair of equal letters has no rule.' },
      { q: 'Two letters share a row. On encryption each is replaced by…', options: ['the letter below it', 'the letter to its right', 'the opposite corner', 'itself'], answer: 1, why: 'Row rule: move right, wrapping round.' },
      { q: 'Why is Playfair harder to break by letter counting than a substitution?', options: ['It has more letters', 'It works on pairs, so single letters do not map one-to-one', 'It has no key', 'It uses numbers'], answer: 1, why: 'There are about 600 pairs, and their counts are spread more evenly.' },
      { q: 'How many letters does the Playfair square hold?', options: ['26', '25, with I and J sharing', '36', '24'], answer: 1, why: 'A 5×5 square: one letter has to give way.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
