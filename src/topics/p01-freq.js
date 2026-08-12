// Part 1: frequency analysis. A substitution ciphertext keeps English's letter counts in a new order: line the
// counts up against English, guess the commonest letters, let THE confirm two more, and read the words as they
// appear. Then the same job done by a hill climber that swaps letters while the text grows more English.
(function (S) {
  'use strict';
  const P = S.P1, ABC = P.ABC;
  const C = () => S.Classic;
  const SOURCES = [{ value: 'keeper', label: 'the lighthouse keeper' }, { value: 'fair', label: 'the science fair' }];
  const kwCheck = (v) => (P.letters(v).length < 1 ? 'Keyword: at least one letter' : P.letters(v).length > 26 ? 'Keyword: at most 26 letters' : null);
  /** the puzzle: a long original message under a keyword alphabet */
  function puzzle(inp) {
    const plain = C().letters(C().corpus.longExamples[inp.src]), alpha = C().substitution.keywordAlphabet(inp.word).alphabet;
    const ct = C().letters(C().substitution.encrypt(plain, alpha).out), inv = C().substitution.invert(alpha);
    return { plain, alpha, ct, inv };
  }
  P.puzzle = puzzle;
  const ENG_ORDER = C().ENGLISH.map((p, i) => [p, i]).sort((a, b) => b[0] - a[0]).map((e) => ABC[e[1]]);

  // ---- the game -------------------------------------------------------------------------------------------------
  const BX = 20, BASE = 170, PITCH = 28, NSHOW = 96, PERROW = 32, DW = 21;
  function picture(ct, fr, known, o) {
    o = o || {};
    const items = [], N = fr.total, maxc = fr.ranked[0].count;
    items.push(P.title('f:t', BX, 14, 'cipher letters by count, beside English at the same rank'));
    fr.ranked.forEach((r, k) => {
      const x = BX + k * PITCH, h = (130 * r.count) / maxc, eh = (130 * (C().ENGLISH[ABC.indexOf(ENG_ORDER[k])] * N) / 100) / maxc;
      const isNew = o.fresh && o.fresh.has(r.letter), isKnown = known[r.letter] !== undefined;
      if (o.bars !== false) items.push({ key: 'f:b' + r.letter, kind: 'cell', x, y: BASE - Math.max(1.5, h), w: 14, h: Math.max(1.5, h), rx: 2, text: '', cls: 'p1-bar ' + (isNew ? 'hot' : isKnown ? 'p1-best' : 'act') });
      if (o.english) items.push({ key: 'f:e' + k, kind: 'cell', x: x + 15, y: BASE - Math.max(1.5, eh), w: 8, h: Math.max(1.5, eh), rx: 2, text: '', cls: 'p1-bar p1-eng' });
      if (o.bars !== false) items.push(P.text('f:l' + r.letter, x + 11, BASE + 17, r.letter, 'mono' + (isNew ? ' hot' : ''), 14, 'middle'));
      if (o.english) items.push(P.text('f:el' + k, x + 11, BASE + 35, ENG_ORDER[k].toLowerCase(), 'tick', 13, 'middle'));
      if (isKnown) items.push({ key: 'f:g' + r.letter, kind: 'cell', x: x + 1, y: BASE + 44, w: 21, h: 24, rx: 3, text: known[r.letter], size: 14, cls: 'mono ' + (isNew ? 'hot' : 'p1-good') });
    });
    if (o.english) { items.push(P.text('f:k1', BX + 26 * PITCH + 8, BASE + 17, 'cipher', 'tick', 13)); items.push(P.text('f:k2', BX + 26 * PITCH + 8, BASE + 35, 'English', 'tick', 13)); }
    if (Object.keys(known).length) items.push(P.text('f:k3', BX + 26 * PITCH + 8, BASE + 61, 'guess', 'tick', 13));
    // the start of the message, decrypted where the letter is known
    const DY = BASE + 108;
    items.push(P.title('d:t', BX, DY - 12, 'the message so far: guessed letters in lower case'));
    for (let i = 0; i < Math.min(NSHOW, ct.length); i++) {
      const c = ct[i], p = known[c], r = Math.floor(i / PERROW), x = BX + (i % PERROW) * (DW + 2), y = DY + r * 36;
      items.push({ key: 'd:' + i, kind: 'cell', x, y, w: DW, h: 30, rx: 3, text: p !== undefined ? p.toLowerCase() : c, size: 14, cls: 'mono ' + (p !== undefined ? (o.fresh && o.fresh.has(c) ? 'hot' : 'p1-good') : 'p1-ct') });
    }
    return items;
  }

  S.topic({
    id: 'p01-frequency', family: 'p01-frequency', order: 10, title: 'Frequency analysis: solve it yourself',
    blurb: 'A substitution changes the names of the letters but not how often they occur. Count the cipher letters, line them up against English, guess, and let the words that appear confirm or correct each guess.',
    inputs: [
      { id: 'src', kind: 'choice', label: 'Hidden message', def: 'keeper', options: SOURCES },
      { id: 'word', kind: 'text', label: 'Keyword of the key', def: 'WEATHERVANE', check: kwCheck },
    ],
    presets: [
      { label: 'The keeper, keyword WEATHERVANE', values: { src: 'keeper', word: 'WEATHERVANE' } },
      { label: 'The science fair, keyword CARDBOARD WHEELS', values: { src: 'fair', word: 'CARDBOARD WHEELS' } },
      { label: 'The keeper, keyword ZEBRA', values: { src: 'keeper', word: 'ZEBRA' } },
    ],
    run(inp) {
      const pz = puzzle(inp), ct = pz.ct, fr = C().freq(ct), N = fr.total, F = new S.Frames(['solved']);
      const known = {}, plainOf = (c) => pz.inv[ABC.indexOf(c)];
      F.add({ items: picture(ct, fr, known, { bars: false }), say: `A message of ${N} letters, each replaced by another letter throughout. The key is one of 26! alphabets, too many to try, but the cipher leaves one thing alone: how often each letter occurs.`, meta: {} });
      F.add({ items: picture(ct, fr, known, {}), say: fr.trace[0].say, meta: {} });
      const top = fr.ranked.slice(0, 6).map((r) => r.letter);
      F.add({ items: picture(ct, fr, known, { english: true }), say: `Beside each cipher letter stands the English letter of the same rank, scaled to ${N} letters: e for ${top[0]}, t for ${top[1]}, a for ${top[2]}. The two shapes match closely; the labels are what the key changed. Ranks are only a first guess, since a few hundred letters do not follow English exactly.`, meta: {} });
      const assign = (letters, say, meta) => {
        const fresh = new Set();
        for (const c of letters) { known[c] = plainOf(c); fresh.add(c); F.count('solved'); }
        F.add({ items: picture(ct, fr, known, { english: true, fresh }), say, meta: Object.assign({ known: Object.keys(known).length }, meta || {}) });
      };
      const first = fr.ranked[0], p0 = plainOf(first.letter);
      assign([first.letter], `${first.letter} is the commonest cipher letter, ${first.count} times (${P.fmt(first.pct)}%), close to English's E at ${P.fmt(C().ENGLISH[4])}%. ${p0 === 'E' ? `Guess ${first.letter} = E.` : `E is the natural guess, but the words that appear say ${first.letter} = ${p0}.`}`, { assign: first.letter, plain: p0, rank: 0 });
      // THE: the commonest trigram
      const tri = C().ngrams(ct, 3, 10), t0 = tri[0], tdec = Array.from(t0.gram, plainOf).join('');
      if (tdec === 'THE') {
        const add = Array.from(t0.gram).filter((c) => known[c] === undefined);
        assign(add, `The commonest three-letter group is ${t0.gram}, ${t0.count} times. In English THE is by far the commonest, and ${t0.gram} ends in ${known[t0.gram[2]] ? 'the letter already taken as ' + known[t0.gram[2]] : t0.gram[2]}, so ${add.map((c) => c + ' = ' + plainOf(c)).join(' and ')}. Look at the message: words begin to show.`, { tri: t0.gram });
      }
      // then by rank, one letter a frame, while the message is still mostly unknown
      let steps = 0;
      for (const r of fr.ranked) {
        if (known[r.letter] !== undefined || r.count === 0 || steps >= 7) continue;
        steps++;
        const p = plainOf(r.letter), rank = fr.ranked.indexOf(r), eng = ENG_ORDER[rank];
        assign([r.letter], `${r.letter} comes ${['first', 'second', 'third', 'fourth', 'fifth', 'sixth', 'seventh', 'eighth', 'ninth', 'tenth', 'eleventh', 'twelfth', 'thirteenth', 'fourteenth', 'fifteenth'][rank] || rank + 1 + 'th'} with ${r.count}. English at that rank has ${eng}; ${p === eng ? `the words agree: ${r.letter} = ${p}.` : `but the partial words read better with ${p}, so ${r.letter} = ${p}.`}`, { assign: r.letter, plain: p, rank });
      }
      const rest = fr.ranked.filter((r) => known[r.letter] === undefined && r.count > 0).map((r) => r.letter);
      if (rest.length) assign(rest, `With ${Object.keys(known).length} letters placed, the rest follow from the words they complete: ${rest.map((c) => c + ' = ' + plainOf(c)).join(', ')}.`, { rest: true });
      const unseen = fr.ranked.filter((r) => r.count === 0).map((r) => r.letter);
      F.add({ items: picture(ct, fr, known, { english: true }), say: `Solved: ${C().corpus.longExamples[inp.src].slice(0, 64).replace(/\s+\S*$/, '')}… ${unseen.length ? `${P.list(unseen)} never appear${unseen.length === 1 ? 's' : ''} in the ciphertext, so the key's entries for ${unseen.length === 1 ? 'it' : 'them'} stay unknown, which does not matter for reading the message.` : 'Every cipher letter appeared, so the whole key is known.'}`, meta: { end: true } });
      return { frames: F.list, def: P.def('Frequency analysis', ['English letters by frequency:', ENG_ORDER.join(' '), 'commonest pairs: TH HE IN ER AN', 'commonest triple: THE', 'match ranks, then let words decide']), counters: [{ id: 'solved', label: 'letters placed' }] };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.assign !== undefined, pick: 'option', ask: (fr, i) => `Which plain letter does ${fr[i + 1].meta.assign} stand for?`, options: (fr, i) => { const m = fr[i + 1].meta, r = m.rank; return P.letterOptions(m.plain, [ENG_ORDER[r], ENG_ORDER[r + 1], ENG_ORDER[Math.max(0, r - 1)], ENG_ORDER[r + 2]].filter(Boolean)); }, answer: (fr, i) => fr[i + 1].meta.plain, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Which letters are the commonest in English text?', options: ['E, T, A, O', 'A, B, C, D', 'S, R, L, N', 'Q, X, Z, J'], answer: 0, why: 'E is about 12.7%, T about 9%, A about 8%, O about 7.5%.' },
      { q: 'Why does frequency analysis work on a substitution cipher?', options: ['The key is short', 'Each plain letter always becomes the same cipher letter, so counts carry over', 'The cipher is a shift', 'It needs a computer'], answer: 1, why: 'The substitution renames letters but keeps each letter\'s frequency.' },
      { q: 'The commonest cipher trigram is QKR and Q = T. What are K and R likely to be?', options: ['H and E', 'A and N', 'E and R', 'O and F'], answer: 0, why: 'THE is by far the commonest English trigram.' },
      { q: 'Why can a short ciphertext defeat frequency analysis?', options: ['Short texts have no vowels', 'Its counts are too few to follow English closely', 'Substitution keys are longer', 'It cannot be counted'], answer: 1, why: 'Frequencies settle down only over a few hundred letters.' },
    ],
  });

  // ---- the hill climber ---------------------------------------------------------------------------------------------
  const GX = 60, GY = 40, GW = 520, GH = 200;
  function climb(steps, at, pz, best, o) {
    const items = [], lo = Math.min(...steps.map((s) => s.score)), hi = Math.max(...steps.map((s) => s.score), o.target);
    const sx = (k) => GX + (GW * k) / Math.max(1, steps.length - 1), sy = (v) => GY + GH - (GH * (v - lo)) / Math.max(1e-9, hi - lo);
    items.push(P.title('g:t', GX, GY - 16, 'score of the best key so far'));
    items.push({ key: 'g:ax', kind: 'path', d: `M${GX} ${GY} V${GY + GH} H${GX + GW}`, cls: 'axis', box: { x: GX, y: GY, w: GW, h: GH }, pathAudit: 'ignore' });
    items.push(P.text('g:hi', GX - 8, GY + 5, P.fmt(hi, 0), 'tick', 13, 'end'));
    items.push(P.text('g:lo', GX - 8, GY + GH + 4, P.fmt(lo, 0), 'tick', 13, 'end'));
    items.push(P.text('g:x', GX + GW, GY + GH + 20, 'improvements →', 'tick', 13, 'end'));
    items.push({ key: 'g:tg', kind: 'line', x1: GX, y1: sy(o.target), x2: GX + GW, y2: sy(o.target), cls: 'dash' });
    items.push(P.text('g:tgl', GX + GW + 8, sy(o.target) + 4, 'the real text', 'tick', 13));
    let d = '';
    for (let k = 0; k <= at; k++) d += (k ? ' L' : 'M') + P.fmt(sx(k), 1).replace('−', '-') + ' ' + P.fmt(sy(steps[k].score), 1).replace('−', '-');
    items.push({ key: 'g:c', kind: 'path', d, cls: 'p1-curve', box: { x: GX, y: GY, w: GW, h: GH }, pathAudit: 'ignore' });
    items.push({ key: 'g:dot', kind: 'dot', x: sx(at), y: sy(steps[at].score), r: 5, cls: 'act' });
    // the key: cipher letter over the plain letter it is taken to mean, right ones in green
    const KY = GY + GH + 60, key = steps[at].key;
    items.push(P.title('k:t', 0, KY - 12, 'the key so far: cipher letter over the plain letter it is taken for'));
    items.push(...P.strip('k:c', 0, KY, ABC, { cw: 22, gap: 2, h: 26, size: 14, cls: () => 'p1-ct' }));
    items.push(...P.strip('k:p', 0, KY + 28, key, { cw: 22, gap: 2, h: 26, size: 14, cls: (i, ch) => (pz.inv[i] === ch ? 'p1-good' : pz.ct.includes(ABC[i]) ? 'p1-bad' : 'soft') }));
    const DY = KY + 88;
    items.push(P.title('m:t', 0, DY - 12, 'the start of the message under this key'));
    const dec = Array.from(pz.ct.slice(0, 64), (c) => key[ABC.indexOf(c)]).join('');
    P.rows(dec, 32).forEach((row, r) => items.push(...P.strip('m:' + r + ':', 0, DY + r * 32, row, { cw: 22, gap: 2, h: 28, size: 14, cls: (i, ch) => (ch === pz.plain[r * 32 + i] ? 'p1-pl' : 'p1-bad') })));
    return items;
  }
  S.topic({
    id: 'p01-substitution-solver', family: 'p01-frequency', order: 20, title: 'Hill climbing to the substitution key',
    blurb: 'Start from the frequency guess, swap two letters of the key, and keep the swap if the text reads more like English by its four-letter groups. Restart from a shaken copy when stuck. The score climbs to the real text.',
    inputs: [
      { id: 'src', kind: 'choice', label: 'Hidden message', def: 'fair', options: SOURCES },
      { id: 'word', kind: 'text', label: 'Keyword of the key', def: 'CARDBOARD WHEELS', check: kwCheck },
      { id: 'seed', kind: 'number', label: 'Random seed', def: 7, min: 1, max: 9999 },
    ],
    presets: [
      { label: 'The science fair', values: { src: 'fair', word: 'CARDBOARD WHEELS', seed: 7 } },
      { label: 'The keeper, another seed', values: { src: 'keeper', word: 'WEATHERVANE', seed: 42 } },
      { label: 'The keeper, keyword QUIET HARBOUR', values: { src: 'keeper', word: 'QUIET HARBOUR', seed: 3 } },
    ],
    run(inp) {
      const pz = puzzle(inp), res = C().solveSubstitution(pz.ct, { seed: inp.seed, restarts: 6, patience: 1000 });
      const tr = res.trace, steps = tr.map((s) => ({ score: s.score, key: s.key, swaps: s.swaps || 0, restart: s.restart || 0, say: s.say }));
      const target = C().score(pz.plain), F = new S.Frames(['right']);
      const right = (key) => Array.from(ABC).filter((c, i) => pz.ct.includes(c) && pz.inv[i] === key[i]).length, seen = new Set(pz.ct).size;
      // at most about 20 frames: the first improvements, then evenly spread, and the last
      const pick = [];
      for (let k = 0; k < steps.length; k++) if (k < 6 || k === steps.length - 1 || k % Math.max(1, Math.ceil((steps.length - 6) / 14)) === 0) pick.push(k);
      pick.forEach((k, n) => {
        const s = steps[k], ok = right(s.key);
        F.set('right', ok);
        const lead = n === 0 ? `The cipher letters, ranked by count, are matched with English's E T A O I N…: the frequency guess. It scores ${P.fmt(s.score)} against ${P.fmt(target)} for the real message, and gets ${ok} of the ${seen} letters in use right. ` : '';
        const body = n === 0 ? '' : `After ${P.big(s.swaps)} tried swaps${s.restart ? ` (restart ${s.restart})` : ''} the best key scores ${P.fmt(s.score)} and gets ${ok} of ${seen} letters right: ${Array.from(pz.ct.slice(0, 32), (c) => s.key[ABC.indexOf(c)]).join('')}…`;
        F.add({ items: climb(steps, k, pz, res, { target }), say: (lead + body).trim(), meta: { k, ok, score: s.score } });
      });
      const last = steps[steps.length - 1], ok = right(last.key);
      F.add({ items: climb(steps, steps.length - 1, pz, res, { target }), say: `${P.big(res.swaps)} swaps in all. The final key scores ${P.fmt(res.score)}${Math.abs(res.score - target) < 0.05 ? ', exactly the score of the real message' : `, against ${P.fmt(target)} for the real message`}, with ${ok} of ${seen} letters right. ${ok === seen ? 'The message reads: ' + C().corpus.longExamples[inp.src].slice(0, 64).replace(/\s+\S*$/, '') + '…' : 'A few rare letters may still be swapped; reading the text fixes them by eye.'}`, meta: { end: true } });
      return { frames: F.list, def: P.def('Hill climbing', ['key := frequency guess', 'repeat:', '  swap two letters of the key', '  keep it if the score rises', '  after many failures: shake, restart', 'score = Σ log₁₀ P(four-letter group)']), counters: [{ id: 'right', label: 'letters right' }] };
    },
    predict: [
      { at: (f, i, fr) => i === 0 && fr.length > 3, pick: 'option', ask: 'Will the score keep rising until the key is right, or can it get stuck?', options: ['it always reaches the right key', 'it can get stuck on a wrong key, so it restarts', 'it gets worse before better on every swap'], answer: 'it can get stuck on a wrong key, so it restarts', explain: 'A swap is kept only when the score rises, so the climber can reach a key where no single swap helps (a local maximum). Restarting from a shaken copy escapes it.' },
    ],
    quiz: [
      { q: 'What does the climber keep?', options: ['Every swap', 'Only swaps that raise the score', 'Only swaps of vowels', 'A random half of the swaps'], answer: 1, why: 'That is hill climbing: move only uphill.' },
      { q: 'Why are four-letter groups used for the score rather than single letters?', options: ['They are faster to count', 'They judge whole word fragments, so they tell nearly-right text from right text', 'English has no single letters', 'They need less text'], answer: 1, why: 'Single-letter counts are the same for many keys; quadgrams reward real words.' },
      { q: 'What is a local maximum here?', options: ['The real key', 'A wrong key that no single swap improves', 'The highest possible score', 'A key with E in it'], answer: 1, why: 'The climber stops there, which is why it restarts.' },
      { q: 'Roughly how many keys does the climber look at?', options: ['All 26!', 'A few thousand to tens of thousands', 'Exactly 26', 'One'], answer: 1, why: 'It tests swaps one at a time, a vanishing fraction of the 4 × 10^26 keys.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
