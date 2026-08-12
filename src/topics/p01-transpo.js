// Part 1: transposition, where the letters stay the same and only move (a columnar grid read in key order, a rail
// fence), and Playfair, which enciphers pairs of letters on a 5×5 square.
(function (S) {
  'use strict';
  const P = S.P1, ABC = P.ABC;
  const C = () => S.Classic;
  const textCheck = (min, max) => (v) => { const n = P.letters(v).length; if (n < min) return 'Message: at least ' + min + ' letters'; if (n > max) return 'Message: at most ' + max + ' letters, so the picture stays readable'; return null; };
  const DIR = { id: 'dir', kind: 'choice', label: 'Direction', def: 'enc', options: [{ value: 'enc', label: 'encrypt' }, { value: 'dec', label: 'decrypt' }] };
  const ORD = ['first', 'second', 'third', 'fourth', 'fifth', 'sixth', 'seventh', 'eighth', 'ninth'];

  // ---- columnar ------------------------------------------------------------------------------------------------------
  const GC = 36, OX = 400, OPER = 12;
  function columnar(key, rank, grid, o) {
    o = o || {};
    const items = [], w = key.length;
    items.push(P.title('g:t', 0, -40, 'key'));
    for (let c = 0; c < w; c++) {
      items.push({ key: 'g:k' + c, kind: 'cell', x: c * GC, y: 0, w: GC - 3, h: 32, rx: 4, text: key[c], size: 16, cls: 'mono ' + (o.col === c ? 'hot' : 'p1-key') });
      if (o.ranks) items.push(P.text('g:r' + c, c * GC + (GC - 3) / 2, -10, String(rank[c] + 1), o.col === c ? 'hot' : 'act', 14, 'middle'));
    }
    grid.forEach((row, r) => row.forEach((ch, c) => { if (ch === undefined) return; items.push({ key: 'g:' + r + ',' + c, kind: 'cell', x: c * GC, y: 40 + r * 34, w: GC - 3, h: 31, rx: 4, text: ch || '', size: 15, cls: 'mono ' + (o.col === c && ch ? 'hot' : o.read && o.read.has(c) ? 'soft' : ch ? 'p1-pl' : 'p1-ghost') }); }));
    if (o.out !== undefined) {
      items.push(P.title('o:t', OX, -10, o.outName || 'ciphertext'));
      P.rows(o.out, OPER).forEach((row, r) => items.push(...P.strip('o:' + r + ':', OX, r * 34, row, { cw: 24, gap: 2, h: 30, size: 15, cls: (i) => (o.fresh && r * OPER + i >= o.fresh[0] && r * OPER + i < o.fresh[1] ? 'hot' : o.outCls || 'p1-ct') })));
    }
    return items;
  }
  S.topic({
    id: 'p01-columnar', family: 'p01-transposition', order: 10, title: 'Columnar transposition',
    blurb: 'Write the message in rows under a keyword, then read it off column by column in the alphabetical order of the key letters. Every letter survives; only the order changes, so letter counts look exactly like English.',
    inputs: [
      { id: 'text', kind: 'text', label: 'Message', def: 'THE BRASS TOKEN IS IN THE SIGNAL BOX', check: textCheck(4, 40) },
      { id: 'key', kind: 'text', label: 'Key word', def: 'HARBOUR', check: (v) => (P.letters(v).length < 2 ? 'Key word: at least 2 letters' : P.letters(v).length > 9 ? 'Key word: at most 9 letters' : null) },
      { id: 'pad', kind: 'choice', label: 'Fill the last row', def: 'no', options: [{ value: 'no', label: 'leave it short' }, { value: 'X', label: 'pad with X' }] },
      DIR,
    ],
    presets: [
      { label: 'Key HARBOUR', values: { text: 'THE BRASS TOKEN IS IN THE SIGNAL BOX', key: 'HARBOUR', pad: 'no', dir: 'enc' } },
      { label: 'Key BELL: a repeated letter', values: { text: 'RING THE BELL AT NOON', key: 'BELL', pad: 'X', dir: 'enc' } },
      { label: 'Decrypt with key FERRY', values: { text: C().columnar.encrypt('MEET ON THE WEST BANK AT SIX', 'FERRY').out, key: 'FERRY', pad: 'no', dir: 'dec' } },
    ],
    check: (inp) => (Math.ceil(P.letters(inp.text).length / Math.max(1, P.letters(inp.key).length)) > 9 ? 'At most 9 rows: use a longer key word or a shorter message' : null),
    run(inp) {
      const key = P.letters(inp.key), F = new S.Frames();
      if (inp.dir === 'dec') {
        const d = C().columnar.decrypt(inp.text, key), rank = d.rank, ct = P.letters(inp.text), w = key.length;
        const empty = d.grid.map((row) => row.map(() => ''));
        F.add({ items: columnar(key, rank, empty, { ranks: true, out: ct, outName: 'ciphertext' }), say: `To decrypt, first work out the shape of the grid. ${d.trace[0].say}`, meta: {} });
        const g = empty.map((r) => r.slice());
        let p = 0;
        d.trace.filter((t) => t.kind === 'col-fill').forEach((t, n) => {
          for (let r = 0; r < t.letters.length; r++) g[r][t.col] = t.letters[r];
          F.add({ items: columnar(key, rank, g.map((r) => r.slice()), { ranks: true, col: t.col, out: ct, outName: 'ciphertext', fresh: [p, p + t.letters.length] }), say: t.say, meta: { fill: n } });
          p += t.letters.length;
        });
        const last = d.trace[d.trace.length - 1];
        F.add({ items: columnar(key, rank, g, { ranks: true, out: d.out, outName: 'plaintext', outCls: 'p1-pl' }), say: last.say, meta: { end: true } });
        return { frames: F.list, def: P.def('Columnar transposition', ['write in rows of ' + w + ' under ' + key, 'read columns in key order', 'decrypt: columns 1…' + (ct.length % w || w) + ' in key position are long']) };
      }
      const e = C().columnar.encrypt(inp.text, key, { pad: inp.pad === 'X' ? 'X' : false }), rank = e.rank, w = key.length;
      F.add({ items: columnar(key, rank, e.grid, {}), say: e.trace[0].say, meta: {} });
      F.add({ items: columnar(key, rank, e.grid, { ranks: true }), say: e.trace[1].say + (new Set(key).size < key.length ? ' Equal key letters are numbered left to right.' : ''), meta: {} });
      let out = '';
      const read = new Set();
      e.trace.filter((t) => t.kind === 'col-read').forEach((t, n) => {
        const a = out.length; out += t.letters;
        F.add({ items: columnar(key, rank, e.grid, { ranks: true, col: t.col, read, out, fresh: [a, out.length] }), say: t.say, meta: { read: n, col: t.col, keyLetter: key[t.col] } });
        read.add(t.col);
      });
      const fr = C().freq(e.out), pf = C().freq(P.letters(inp.text));
      F.add({ items: columnar(key, rank, e.grid, { ranks: true, read, out }), say: `The ciphertext is ${e.out}. Its letters are the message's letters, rearranged: the commonest are ${fr.ranked.slice(0, 3).map((r) => r.letter + ' ' + r.count).join(', ')}, exactly as in the plaintext. That is the mark of a transposition: English counts, unreadable order.`, meta: { end: true } });
      return { frames: F.list, def: P.def('Columnar transposition', ['write in rows of ' + w + ' under ' + key, 'number the columns by key letter order', 'read the columns in that order', 'keys: orderings of ' + w + ' columns = ' + w + '! = ' + P.big(P.factorial(w))]) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.read !== undefined, pick: 'option', ask: 'Which key letter\'s column is read next?', options: (fr, i) => { const k = P.letters(fr[i + 1].items.filter((x) => /^g:k\d+$/.test(x.key)).map((x) => x.text).join('')); return [...new Set(k)].sort().slice(0, 6); }, answer: (fr, i) => fr[i + 1].meta.keyLetter, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Which statistic shows at once that a ciphertext is a transposition?', options: ['Its letter counts match English', 'Its letters are all different', 'It has no vowels', 'Its length is a prime'], answer: 0, why: 'A transposition only moves letters, so the counts are the plaintext\'s.' },
      { q: 'With key ZEBRA, which column is read first?', options: ['Z', 'E', 'B', 'A'], answer: 3, why: 'Columns are read in alphabetical order of the key letters: A first.' },
      { q: 'How many column orders does a 7-letter key allow?', options: ['7', '49', '5,040', '26^7'], answer: 2, why: '7! = 5,040, few enough to search, especially with anagramming by hand.' },
      { q: 'Why is a short last row a problem for the receiver?', options: ['It is not a problem at all', 'The receiver must work out which columns are one letter shorter before filling them', 'The message is lost', 'The key must change'], answer: 1, why: 'Decryption needs the grid shape: the first (length mod w) columns in writing order are full.' },
    ],
  });

  // ---- rail fence --------------------------------------------------------------------------------------------------------
  const RW = 24, RH = 40;
  function fence(text, path, rails, o) {
    o = o || {};
    const items = [], n = text.length;
    for (let r = 0; r < rails; r++) items.push(P.text('r:l' + r, -10, r * RH + 19, 'rail ' + (r + 1), o.rail === r ? 'hot' : 'tick', 13, 'end'));
    let d = '';
    for (let i = 0; i < n && i <= (o.upto === undefined ? n : o.upto); i++) d += (i ? ' L' : 'M') + (i * RW + 10.5) + ' ' + (path[i] * RH + 14);
    if (d.includes('L')) items.push({ key: 'r:path', kind: 'path', d, cls: 'p1-chord', box: { x: 0, y: 0, w: n * RW, h: rails * RH }, pathAudit: 'ignore', layer: 'back' });
    for (let i = 0; i < n; i++) {
      const shown = o.upto === undefined || i <= o.upto, filled = o.filled ? o.filled(i) : shown;
      items.push({ key: 'r:' + i, kind: 'cell', x: i * RW, y: path[i] * RH, w: RW - 3, h: 28, rx: 3, text: filled ? text[i] : '', size: 15, cls: 'mono ' + (o.hot && o.hot(i) ? 'hot' : filled ? (o.cellCls || 'p1-pl') : 'p1-ghost') });
    }
    if (o.out !== undefined) {
      const y = rails * RH + 30;
      items.push(P.title('o:t', 0, y - 8, o.outName || 'ciphertext'));
      items.push(...P.strip('o:', 0, y, o.out, { cw: RW - 3, gap: 3, h: 28, size: 15, cls: (i) => (o.fresh && i >= o.fresh[0] && i < o.fresh[1] ? 'hot' : o.outCls || 'p1-ct') }));
    }
    return items;
  }
  S.topic({
    id: 'p01-railfence', family: 'p01-transposition', order: 20, title: 'The rail fence',
    blurb: 'Write the message in a zigzag down and up a few rails, then read the rails one after another. The only key is the number of rails, so it falls to trying every one.',
    inputs: [
      { id: 'text', kind: 'text', label: 'Message', def: 'WAIT AT THE PASSING PLACE FOR THE MAIL', check: textCheck(4, 32) },
      { id: 'rails', kind: 'number', label: 'Rails', def: 3, min: 2, max: 6 },
      DIR,
    ],
    presets: [
      { label: 'Three rails', values: { text: 'WAIT AT THE PASSING PLACE FOR THE MAIL', rails: 3, dir: 'enc' } },
      { label: 'Two rails: alternate letters', values: { text: 'BRING THE BLUE LANTERN', rails: 2, dir: 'enc' } },
      { label: 'Decrypt five rails', values: { text: C().railfence.encrypt('THE ORCHESTRA REHEARSES ON TUESDAY', 5).out, rails: 5, dir: 'dec' } },
    ],
    run(inp) {
      const rails = inp.rails, F = new S.Frames();
      if (inp.dir === 'dec') {
        const d = C().railfence.decrypt(inp.text, rails), ct = P.letters(inp.text), path = d.path, n = ct.length;
        // where each ciphertext letter lands: rail by rail, left to right
        const at = []; for (let r = 0; r < rails; r++) for (let i = 0; i < n; i++) if (path[i] === r) at.push(i);
        const place = new Array(n); at.forEach((pos, k) => { place[pos] = ct[k]; });
        F.add({ items: fence(place.join(''), path, rails, { filled: () => false, out: ct, outName: 'ciphertext' }), say: `To decrypt, draw the empty zigzag first. ${d.trace[0].say}`, meta: {} });
        let k = 0;
        d.trace.filter((t) => t.kind === 'rail-fill').forEach((t) => {
          const a = k; k += t.letters.length;
          F.add({ items: fence(place.join(''), path, rails, { filled: (i) => path[i] < t.rail || path[i] === t.rail, hot: (i) => path[i] === t.rail, out: ct, outName: 'ciphertext', fresh: [a, k] }), say: t.say, meta: { fill: t.rail } });
        });
        F.add({ items: fence(place.join(''), path, rails, { out: d.out, outName: 'plaintext', outCls: 'p1-pl' }), say: d.trace[d.trace.length - 1].say, meta: { end: true } });
        return { frames: F.list, def: P.def('Rail fence', ['write in a zigzag on ' + rails + ' rails', 'read rail 1, then rail 2, …', 'period of the zigzag: 2·(' + rails + ' − 1) = ' + 2 * (rails - 1)]) };
      }
      const e = C().railfence.encrypt(inp.text, rails), t = P.letters(inp.text), path = e.path, n = t.length;
      const half = Math.ceil(n / 2);
      F.add({ items: fence(t, path, rails, { upto: Math.min(n - 1, 2 * (rails - 1)) }), say: `${e.trace[0].say} The pen goes down to rail ${rails}, back up to rail 1, and so on: one full zigzag every ${2 * (rails - 1)} letters.`, meta: {} });
      F.add({ items: fence(t, path, rails, { upto: half - 1 }), say: `Halfway: ${half} of ${n} letters written.`, meta: {} });
      F.add({ items: fence(t, path, rails, {}), say: `All ${n} letters are on the fence.`, meta: {} });
      let out = '';
      e.trace.filter((x) => x.kind === 'rail-read').forEach((x) => {
        const a = out.length; out += x.letters;
        F.add({ items: fence(t, path, rails, { hot: (i) => path[i] === x.rail, rail: x.rail, out, fresh: [a, out.length] }), say: x.say, meta: { read: x.rail, letters: x.letters } });
      });
      const br = C().bruteRailfence(e.out, Math.min(10, Math.max(2, n - 1)));
      F.add({ items: fence(t, path, rails, { out }), say: `The ciphertext is ${e.out}. The key is only the number of rails: an attacker tries 2, 3, 4, … and scores each result; here ${br.best.rails} rails reads best (${P.fmt(br.best.score, 2)} per letter, against ${P.fmt(br.ranked[1].score, 2)} for ${br.ranked[1].rails}).`, meta: { end: true } });
      return { frames: F.list, def: P.def('Rail fence', ['write in a zigzag on ' + rails + ' rails', 'read rail 1, then rail 2, …', 'period of the zigzag: 2·(' + rails + ' − 1) = ' + 2 * (rails - 1), 'key space: the number of rails']) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.read === 0, pick: 'option', ask: 'How many letters are on the top rail?', options: (fr, i) => { const n = fr[i + 1].meta.letters.length; return [...new Set([n - 2, n - 1, n, n + 1, n + 2].filter((x) => x > 0))].map(String); }, answer: (fr, i) => String(fr[i + 1].meta.letters.length), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Encrypt HELLOWORLD on 2 rails.', options: ['HLOOLELWRD', 'HELLOWORLD', 'DLROWOLLEH', 'HOLELWRDLO'], answer: 0, why: 'Rail 1 takes letters 1, 3, 5, …: H L O O L; rail 2 takes E L W R D.' },
      { q: 'On 4 rails the zigzag repeats every…', options: ['4 letters', '6 letters', '8 letters', '3 letters'], answer: 1, why: '2·(4 − 1) = 6.' },
      { q: 'How many keys does a rail fence for a 30-letter message have?', options: ['about 30', '26', '30!', '2^30'], answer: 0, why: 'Only the number of rails, from 2 up to the length.' },
      { q: 'A rail fence ciphertext has the same letter counts as English because…', options: ['it is a substitution', 'it only moves letters', 'it adds X', 'it uses a keyword'], answer: 1, why: 'Transpositions keep every letter.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
