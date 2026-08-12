// Part 1: breaking Vigenère, moves one and two. Kasiski: repeated sequences in the ciphertext sit a multiple of the
// key length apart, so the factors of their distances vote for it. The index of coincidence: English letters
// collide more often than random ones, so Friedman's estimate and the columns of the right length give it away.
(function (S) {
  'use strict';
  const P = S.P1, ABC = P.ABC;
  const C = () => S.Classic;
  const SOURCES = [{ value: 'keeper', label: 'the lighthouse keeper' }, { value: 'fair', label: 'the science fair' }];
  const keyCheck = (v) => (P.letters(v).length < 1 ? 'Key: at least one letter' : P.letters(v).length > 16 ? 'Key: at most 16 letters' : null);
  P.VIG_PRESETS = [
    { label: 'The keeper, key LANTERN', values: { src: 'keeper', key: 'LANTERN' } },
    { label: 'The fair, key ORCHARD', values: { src: 'fair', key: 'ORCHARD' } },
    { label: 'The keeper, key BELLS', values: { src: 'keeper', key: 'BELLS' } },
    { label: 'The fair, key WEATHERVANE', values: { src: 'fair', key: 'WEATHERVANE' } },
    { label: 'The keeper, key SALT', values: { src: 'keeper', key: 'SALT' } },
  ];
  P.VIG_INPUTS = [
    { id: 'src', kind: 'choice', label: 'Hidden message', def: 'keeper', options: SOURCES },
    { id: 'key', kind: 'text', label: 'Key (to make the ciphertext)', def: 'LANTERN', check: keyCheck },
  ];
  /** the ciphertext the attacker sees */
  P.vigCipher = (inp) => { const plain = C().letters(C().corpus.longExamples[inp.src]); return { plain, ct: C().letters(C().vigenere.encrypt(plain, inp.key).out), key: P.letters(inp.key) }; };

  // ---- Kasiski ----------------------------------------------------------------------------------------------------
  const GW = 17, PER = 36, GX = 0, GY = 24, MAXF = 20;
  const factorsOf = (d) => { const out = []; for (let f = 2; f <= MAXF; f++) if (d % f === 0) out.push(f); return out; };
  function grid(ct, hot, seen) {
    const items = [P.title('g:t', GX, GY - 10, 'the ciphertext, ' + ct.length + ' letters')];
    for (let i = 0; i < ct.length; i++) items.push({ key: 'g:' + i, kind: 'cell', x: GX + (i % PER) * (GW + 1), y: GY + Math.floor(i / PER) * 21, w: GW, h: 19, rx: 2, text: ct[i], size: 13, cls: 'mono ' + (hot.has(i) ? 'hot' : seen.has(i) ? 'changed' : 'p1-ct') });
    return { items, h: GY + Math.ceil(ct.length / PER) * 21 };
  }
  function votesChart(y, votes, o) {
    o = o || {};
    const vals = []; for (let f = 2; f <= MAXF; f++) vals.push(votes[f] || 0);
    const items = [P.title('v:t', 0, y - 6, 'votes: how many distances each number divides')];
    items.push(...P.bars('v:', 0, y + 122, vals, { w: 24, gap: 9, hmax: 96, max: Math.max(4, ...vals), cls: (i) => (o.best === i + 2 ? 'p1-best' : o.fresh && o.fresh.has(i + 2) ? 'hot' : 'act'), label: (i) => String(i + 2), value: (i) => (vals[i] ? String(vals[i]) : '') }));
    return items;
  }
  S.topic({
    id: 'p01-kasiski', family: 'p01-vigenere', order: 20, title: 'Kasiski: repeats give away the key length',
    blurb: 'When the same plaintext meets the same part of the key, the same ciphertext comes out. So repeated sequences in the ciphertext usually sit a multiple of the key length apart, and the factors of their distances vote for it.',
    inputs: P.VIG_INPUTS,
    presets: P.VIG_PRESETS,
    run(inp) {
      const { ct } = P.vigCipher(inp), kas = C().kasiski(ct, { maxFactor: MAXF }), F = new S.Frames(['repeats']);
      const seen = new Set(), votes = new Array(MAXF + 1).fill(0);
      const g0 = grid(ct, new Set(), seen), VY = g0.h + 40;
      F.add({ items: g0.items.concat(votesChart(VY, votes)), say: `${ct.length} letters of Vigenère ciphertext; the key is unknown, even its length. Look for sequences of three or more letters that appear more than once: ${P.plural(kas.repeats.length, 'repeat')} turn up.`, meta: {} });
      const shown = Math.min(kas.repeats.length, 7);
      kas.repeats.slice(0, shown).forEach((r, n) => {
        const hot = new Set(); for (const p of r.positions) for (let k = 0; k < r.gram.length; k++) hot.add(p + k);
        const fresh = new Set(); for (const d of r.distances) for (const f of factorsOf(d)) { votes[f]++; fresh.add(f); }
        F.count('repeats');
        const tr = kas.trace[n];
        F.add({ items: grid(ct, hot, seen).items.concat(votesChart(VY, votes, { fresh })), say: tr.say + ` ${r.distances.map((d) => `${d} is divisible by ${factorsOf(d).join(', ') || 'none of 2 to ' + MAXF}`).join('; ')}, so ${fresh.size === 1 ? 'that number gets' : 'each of those gets'} a vote.`, meta: { rep: n, gcd: r.gcd } });
        for (const x of hot) seen.add(x);
      });
      const rest = kas.repeats.slice(shown);
      if (rest.length) {
        const fresh = new Set();
        for (const r of rest) { for (const d of r.distances) for (const f of factorsOf(d)) { votes[f]++; fresh.add(f); } for (const p of r.positions) for (let k = 0; k < r.gram.length; k++) seen.add(p + k); F.count('repeats'); }
        F.add({ items: grid(ct, new Set(), seen).items.concat(votesChart(VY, votes, { fresh })), say: `The other ${P.plural(rest.length, 'repeat')} vote the same way. A few repeats are chance coincidences, so not every distance agrees; the count is what matters.`, meta: { rest: true } });
      }
      const last = kas.trace[kas.trace.length - 1];
      F.add({ items: grid(ct, new Set(), seen).items.concat(votesChart(VY, votes, { best: kas.best })), say: last.say + (kas.best && kas.best !== P.letters(inp.key).length ? ` (The key used was ${P.letters(inp.key).length} letters long: Kasiski is evidence, not proof, and the index of coincidence is the second opinion.)` : kas.best ? ' Multiples of it collect votes too, but fewer, since not every distance is a multiple of a multiple.' : ''), meta: { end: true, best: kas.best } });
      return { frames: F.list, def: P.def('Kasiski examination', ['find repeated sequences (3+ letters)', 'distance = gap between occurrences', 'key length m divides most distances', 'vote: each f in 2…' + MAXF + ' dividing a distance', 'm = the largest factor with ~top votes']), counters: [{ id: 'repeats', label: 'repeats used' }] };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.end && fr[i + 1].meta.best, pick: 'option', ask: 'Which key length do the votes point to?', options: (fr, i) => { const b = fr[i + 1].meta.best; return [...new Set([2, 3, b, b * 2 <= MAXF ? b * 2 : b + 1, b + 2])].sort((x, y) => x - y).map(String).slice(0, 5); }, answer: (fr, i) => String(fr[i + 1].meta.best), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'A repeat occurs at positions 10 and 52. Which key lengths does it support?', options: ['any', 'the factors of 42: 2, 3, 6, 7, 14, 21', 'only 42', '52 − 10 − 1 = 41'], answer: 1, why: 'The distance is 42 = 2·3·7.' },
      { q: 'Why does a repeat in the ciphertext suggest the key length?', options: ['Ciphertexts never repeat', 'The same plaintext under the same key letters gives the same ciphertext', 'The key is in the repeat', 'Repeats are always the word THE'], answer: 1, why: 'That can only line up if the gap is a multiple of the key length (or by chance).' },
      { q: 'Why do multiples of the true length (like 14 for 7) get fewer votes?', options: ['They are larger', 'Not every multiple of 7 is a multiple of 14', 'The key is never 14', 'Kasiski ignores them'], answer: 1, why: 'Distances like 21 or 35 support 7 but not 14.' },
      { q: 'What can make a repeat misleading?', options: ['It is too long', 'Two unrelated places can match by chance, especially for 3-letter repeats', 'Long keys', 'Spaces'], answer: 1, why: 'Short coincidental matches add stray votes; that is why the votes are counted, not trusted one by one.' },
    ],
  });

  // ---- the index of coincidence and Friedman ------------------------------------------------------------------------
  const NX = 60, NW = 520, NLO = 0.035, NHI = 0.075;
  const nx = (v) => NX + (NW * (Math.max(NLO, Math.min(NHI, v)) - NLO)) / (NHI - NLO);
  function icPicture(o) {
    const items = [];
    // counts: cipher letters (blue) beside the plaintext's (green)
    items.push(P.title('h:t', 0, 10, 'letter counts: ciphertext, with the plaintext\'s beside them'));
    const maxc = Math.max(...o.cc, ...o.pc);
    for (let i = 0; i < 26; i++) {
      const x = i * 24, h = (90 * o.cc[i]) / maxc, ph = (90 * o.pc[i]) / maxc;
      items.push({ key: 'h:c' + i, kind: 'cell', x, y: 116 - Math.max(1.5, h), w: 12, h: Math.max(1.5, h), rx: 2, text: '', cls: 'p1-bar act' });
      if (o.plain) items.push({ key: 'h:p' + i, kind: 'cell', x: x + 13, y: 116 - Math.max(1.5, ph), w: 7, h: Math.max(1.5, ph), rx: 2, text: '', cls: 'p1-bar p1-eng' });
      items.push(P.text('h:l' + i, x + 9, 133, ABC[i], 'mono', 13, 'middle'));
    }
    // the number line of IC values
    if (o.line) {
      const Y = 190;
      items.push(P.title('n:t', 0, Y - 30, 'index of coincidence'));
      items.push({ key: 'n:ax', kind: 'line', x1: NX, y1: Y, x2: NX + NW, y2: Y, cls: 'rule' });
      for (const v of [0.04, 0.05, 0.06, 0.07]) { items.push({ key: 'n:tk' + v, kind: 'line', x1: nx(v), y1: Y - 4, x2: nx(v), y2: Y + 4, cls: '' }); items.push(P.text('n:tl' + v, nx(v), Y + 20, v.toFixed(2), 'tick', 13, 'middle')); }
      for (const m of o.line) {
        items.push({ key: 'n:d' + m.id, kind: 'dot', x: nx(m.v), y: Y, r: 6, cls: m.cls, point: true });
        items.push(P.text('n:m' + m.id, nx(m.v), m.up ? Y - 12 : Y + 40, m.label, m.cls === 'act' ? 'act' : m.cls === 'key' ? 'key' : 'tick', 13, 'middle'));
      }
    }
    if (o.period) {
      const Y = 290, B0 = 0.03, vals = o.period.map((p) => p.avg - B0), max = 0.045;
      items.push(P.title('p:t', 0, Y - 8, 'average IC of the columns, for each guessed key length (bars start at 0.030)'));
      items.push(...P.bars('p:', 0, Y + 110, vals, { w: 22, gap: 8, hmax: 100, max, cls: (i) => (o.pick === i + 1 ? 'p1-best' : o.cur === i + 1 ? 'hot' : vals[i] + B0 >= 0.055 ? 'act' : ''), label: (i) => String(i + 1), labelSize: 13 }));
      const yk = Y + 110 - (100 * (o.kappa - B0)) / max, yr = Y + 110 - (100 * (1 / 26 - B0)) / max, W = o.maxLen * 30;
      items.push({ key: 'p:k', kind: 'line', x1: 0, y1: yk, x2: W, y2: yk, cls: 'dash', audit: 'ignore' });
      items.push(P.text('p:kl', W + 8, yk + 4, 'English', 'tick', 13));
      items.push({ key: 'p:r', kind: 'line', x1: 0, y1: yr, x2: W, y2: yr, cls: 'dash', audit: 'ignore' });
      items.push(P.text('p:rl', W + 8, yr + 4, 'random', 'tick', 13));
    }
    return items;
  }
  S.topic({
    id: 'p01-ioc', family: 'p01-vigenere', order: 30, title: 'The index of coincidence and Friedman\'s test',
    blurb: 'Pick two letters of a text at random: in English they match about 6.6% of the time, in random letters about 3.8%. Vigenère pulls the ciphertext towards random, by an amount that depends on the key length; and every m-th letter, for the right m, looks like English again.',
    inputs: P.VIG_INPUTS,
    presets: P.VIG_PRESETS,
    run(inp) {
      const { ct, plain } = P.vigCipher(inp), F = new S.Frames(), cc = C().freq(ct).counts, pc = C().freq(plain).counts;
      const ic = C().ioc(ct), pic = C().ioc(plain), fr = C().friedman(ct), kappa = C().model().kappa, maxLen = Math.min(20, Math.floor(ct.length / 4));
      const per = C().periodIoC(ct, maxLen);
      const base = { cc, pc };
      F.add({ items: icPicture(base), say: `The ${ct.length} cipher letters, counted. The bars are much flatter than English: the commonest cipher letter makes up ${P.fmt((100 * Math.max(...cc)) / ct.length)}% of the text, where English's E alone is ${P.fmt(C().ENGLISH[4])}%.`, meta: {} });
      F.add({ items: icPicture(Object.assign({ plain: true }, base)), say: `Beside each bar, in green, the count the plaintext had for that letter. Vigenère spread the plaintext's peaks over several cipher letters each.`, meta: {} });
      const line = [{ id: 'r', v: 1 / 26, label: 'random ' + P.fmt(1 / 26, 4), cls: '', up: false }, { id: 'e', v: kappa, label: 'English ' + P.fmt(kappa, 4), cls: 'key', up: false }, { id: 'c', v: ic.ioc, label: 'cipher ' + P.fmt(ic.ioc, 4), cls: 'act', up: true }];
      F.add({ items: icPicture(Object.assign({ plain: true, line }, base)), say: `The index of coincidence is the chance that two letters drawn from the text are the same. ${ic.trace[0].say}`, meta: { ic: ic.ioc } });
      F.add({ items: icPicture(Object.assign({ plain: true, line: line.concat([{ id: 'p', v: pic.ioc, label: 'plain ' + P.fmt(pic.ioc, 4), cls: 'good', up: true }]) }, base)), say: `The plaintext's own index is ${P.fmt(pic.ioc, 4)}, close to English. The ciphertext sits at ${P.fmt(ic.ioc, 4)}, between English and random: a longer key pulls it nearer to random.`, meta: {} });
      F.add({ items: icPicture(Object.assign({ plain: true, line }, base)), say: `Friedman turned that into an estimate of the key length. ${fr.trace[0].say} An estimate only: it is rough, and a hint of where to look.`, meta: { friedman: fr.estimate } });
      // columns: every m-th letter
      const cand = per.filter((p) => p.avg >= 0.055).map((p) => p.len), pick = cand.length ? cand[0] : per.reduce((m, p) => (p.avg > m.avg ? p : m)).len;
      const upto = Math.min(maxLen, Math.max(pick + 1, 8));
      for (let m = 1; m <= upto; m++) {
        const p = per[m - 1];
        F.add({ items: icPicture(Object.assign({ plain: true, line, period: per.slice(0, m), cur: m, kappa, maxLen }, base)), say: m === 1 ? `Now split the ciphertext into columns: for a guessed length m, column j holds letters j, j + m, j + 2m… If m is the key length, each column was shifted by one key letter only, and its IC looks like English. m = 1 is the whole text: ${P.fmt(p.avg, 4)}.` : `m = ${m}: the ${m} columns have ICs ${p.cols.map((v) => P.fmt(v, 3)).join(', ')}, average ${P.fmt(p.avg, 4)}${p.avg >= 0.055 ? ', like English' : ''}.`, meta: { m, avg: p.avg } });
      }
      F.add({ items: icPicture(Object.assign({ plain: true, line, period: per, pick, kappa, maxLen }, base)), say: `All lengths up to ${maxLen}. The first whose columns look like English is ${pick}${cand.length > 1 ? `; ${cand.slice(1, 4).join(', ')} also do, being multiples of it or near them` : ''}. Friedman said about ${P.fmt(fr.estimate, 1)}. The key length is ${pick}.`, meta: { end: true, pick } });
      return { frames: F.list, def: P.def('Index of coincidence', ['IC = Σ nᵢ(nᵢ − 1) / (N(N − 1))', 'English κp ≈ ' + P.fmt(kappa, 4) + ', random κr = 1/26 ≈ 0.0385', 'Friedman: m ≈ (κp − κr)·N / ((N − 1)·IC − κr·N + κp)', 'columns of the right length: IC ≈ κp']) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.ic !== undefined, pick: 'option', ask: 'Where will the ciphertext\'s index of coincidence fall?', options: ['below random (under 0.038)', 'between random and English', 'above English (over 0.066)'], answer: (fr, i) => { const v = fr[i + 1].meta.ic; return v < 1 / 26 ? 'below random (under 0.038)' : v > 0.066 ? 'above English (over 0.066)' : 'between random and English'; }, explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.end, pick: 'option', ask: 'Which key length do the columns point to?', options: (fr, i) => { const b = fr[i + 1].meta.pick; return [...new Set([Math.max(1, b - 2), b - 1 || b + 3, b, b + 1, b + 2])].sort((x, y) => x - y).map(String); }, answer: (fr, i) => String(fr[i + 1].meta.pick), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'A text has an index of coincidence of 0.066. It is probably…', options: ['random letters', 'English, or a substitution of English', 'a Vigenère with a long key', 'a one-time pad'], answer: 1, why: 'A substitution keeps the counts, so its IC equals the plaintext\'s.' },
      { q: 'Why does the IC of a substitution ciphertext not change?', options: ['It does change', 'It depends only on how often letters repeat, not on their names', 'The key is short', 'Substitutions keep vowels'], answer: 1, why: 'Renaming letters keeps the multiset of counts.' },
      { q: 'For m = the key length, every column of a Vigenère ciphertext is…', options: ['random', 'a shift cipher of English', 'a substitution with 26! keys', 'empty'], answer: 1, why: 'Every letter in the column was shifted by the same key letter.' },
      { q: 'Friedman\'s estimate is most reliable for…', options: ['very short texts', 'long texts with short keys', 'one-letter keys', 'keys longer than the text'], answer: 1, why: 'The IC is a statistic; it needs many letters, and long keys push it towards random where the formula is sensitive.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
