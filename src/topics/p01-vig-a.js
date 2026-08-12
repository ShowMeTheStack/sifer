// Part 1: the Vigenère cipher, drawn as the rows of the tableau that its key picks out, and the autokey cipher,
// whose key runs on into the plaintext so it never repeats.
(function (S) {
  'use strict';
  const P = S.P1, ABC = P.ABC;
  const C = () => S.Classic;
  const textCheck = (min, max) => (v) => { const n = P.letters(v).length; if (n < min) return 'Message: at least ' + min + ' letters'; if (String(v).length > max) return 'Message: at most ' + max + ' characters, so the picture stays readable'; return null; };
  const keyCheck = (max, what) => (v) => (P.letters(v).length < 1 ? what + ': at least one letter' : P.letters(v).length > max ? what + ': at most ' + max + ' letters, so the picture stays readable' : null);

  /** the rows of the tableau for the distinct key letters: plain alphabet on top, each row shifted by its letter */
  const TX = 60, TW = 22;
  function tableau(key, o) {
    const items = [], rows = [...new Set(key)];
    items.push(P.text('tb:pl', TX - 10, 17, 'plain', 'tick', 13, 'end'));
    items.push(...P.strip('tb:h', TX, 0, ABC, { cw: TW, gap: 1, h: 24, size: 13, cls: (i) => 'p1-pl' + (o.col === i ? ' hot' : '') }));
    rows.forEach((k, r) => {
      const y = 30 + r * 26, s = ABC.indexOf(k), on = o.row === k;
      items.push({ key: 'tb:k' + k, kind: 'cell', x: TX - 34, y, w: 26, h: 24, rx: 3, text: k, size: 13, cls: 'mono p1-key' + (on ? ' hot' : '') });
      items.push(...P.strip('tb:r' + k + ':', TX, y, Array.from(ABC, (c, i) => ABC[(i + s) % 26]).join(''), { cw: TW, gap: 1, h: 24, size: 13, cls: (i) => (on && o.col === i ? 'hot' : on ? 'p1-ct' : o.col === i ? 'soft' : 'p1-pl') }));
    });
    return { items, h: 30 + rows.length * 26 };
  }
  /** plain, key and cipher rows of the message, up to letter upto; o.keyCls(j) styles key letters */
  function message(x, y, plain, key, cipher, upto, per, o) {
    o = o || {};
    const items = [], n = plain.length, hot = o.hot === undefined ? upto : o.hot;
    for (const [lab, dy] of [[o.topName || 'plain', 20], ['key', 52], [o.bottomName || 'cipher', 84]]) items.push(P.text('m:l' + lab, x - 10, y + dy, lab, 'tick', 13, 'end'));
    for (let r = 0; r * per < n; r++) {
      const yy = y + r * 116, a = r * per, b = Math.min(n, a + per);
      items.push(...P.strip('m:p' + r + ':', x, yy, plain.slice(a, b), { cw: 26, gap: 2, h: 28, size: 14, cls: (i) => (o.topCls || 'p1-pl') + (a + i === hot ? ' hot' : '') }));
      items.push(...P.strip('m:k' + r + ':', x, yy + 32, Array.from(plain.slice(a, b), (c, i) => (a + i <= (o.keyUpto === undefined ? n : o.keyUpto) ? key[a + i] : ' ')).join(''), { cw: 26, gap: 2, h: 28, size: 14, cls: (i) => (a + i > (o.keyUpto === undefined ? n : o.keyUpto) ? 'soft' : (o.keyCls ? o.keyCls(a + i) : 'p1-key') + (a + i === hot ? ' hot' : '')) }));
      items.push(...P.strip('m:c' + r + ':', x, yy + 64, Array.from(plain.slice(a, b), (c, i) => (a + i <= upto ? cipher[a + i] : ' ')).join(''), { cw: 26, gap: 2, h: 28, size: 14, cls: (i) => (a + i <= upto ? (o.bottomCls || 'p1-ct') + (a + i === hot ? ' hot' : '') : 'soft') }));
    }
    return items;
  }

  S.topic({
    id: 'p01-vigenere', family: 'p01-vigenere', order: 10, title: 'The Vigenère cipher',
    blurb: 'A keyword is written again and again under the message, and each key letter shifts the letter above it by its own amount. One plain letter now has several disguises, so single-letter counts flatten out.',
    inputs: [
      { id: 'text', kind: 'text', label: 'Message', def: 'MEET AT THE FERRY AFTER THE MARKET', check: textCheck(1, 40) },
      { id: 'key', kind: 'text', label: 'Key', def: 'LANTERN', check: keyCheck(8, 'Key') },
    ],
    presets: [
      { label: 'Key LANTERN', values: { text: 'MEET AT THE FERRY AFTER THE MARKET', key: 'LANTERN' } },
      { label: 'Key ORE: three shifts', values: { text: 'SEED THE SEED BEDS SEEDLESS', key: 'ORE' } },
      { label: 'A one-letter key is a shift', values: { text: 'THE BRASS TOKEN', key: 'H' } },
    ],
    run(inp) {
      const r = C().vigenere.encrypt(inp.text, inp.key), key = P.letters(inp.key), plain = P.letters(inp.text), ct = P.letters(r.out), n = plain.length;
      const steps = r.trace.filter((s) => s.kind === 'letter'), ks = Array.from(plain, (c, j) => key[j % key.length]).join('');
      const tb = (o) => tableau(key, o), MY = () => tb({}).h + 50, F = new S.Frames();
      const pic = (o, upto, hot) => { const t = tb(o); return t.items.concat(message(TX, t.h + 34, plain, ks, ct, upto, 20, { hot })); };
      F.add({ items: pic({}, -1), say: r.trace[0].say.replace('repeats under the message;', 'is written again and again under the message;') + ` Its letters pick ${P.plural(new Set(key).size, 'row')} of the 26-row Vigenère table.`, meta: {} });
      const shown = Math.min(n, 10);
      for (let j = 0; j < shown; j++) {
        const st = steps[j];
        F.add({ items: pic({ row: st.keyLetter, col: st.p }, j), say: `Letter ${j + 1}: key letter ${st.keyLetter} shifts by ${st.s}. In row ${st.keyLetter}, under ${ABC[st.p]}, stands ${ABC[st.c]}: ${st.say.replace(/\.$/, '')}.`, meta: { letter: j, from: ABC[st.p], key: st.keyLetter, to: ABC[st.c] } });
      }
      if (n > shown) F.add({ items: pic({}, n - 1, -1), say: `The rest the same way. The ciphertext is ${ct}.`, meta: {} });
      // the same plain letter under different key letters
      let ex = null;
      for (let i = 0; i < n && !ex; i++) for (let j = i + 1; j < n; j++) if (plain[i] === plain[j] && ct[i] !== ct[j]) { ex = [i, j]; break; }
      let rep = null;
      for (let i = 0; i < n && !rep; i++) for (let j = i + key.length; j < n; j += key.length) if (plain[i] === plain[j]) { rep = [i, j]; break; }
      const tail = ex ? `The plain letter ${plain[ex[0]]} at positions ${ex[0] + 1} and ${ex[1] + 1} became ${ct[ex[0]]} and ${ct[ex[1]]}: one letter, several disguises, so the counts of single letters flatten.` : 'With a one-letter key every plain letter keeps one disguise: this is just a shift.';
      const tail2 = rep && key.length > 1 ? ` But the key repeats every ${key.length} letters, so the same plain letter ${key.length}·k places apart gets the same disguise (positions ${rep[0] + 1} and ${rep[1] + 1}: ${plain[rep[0]]} → ${ct[rep[0]]} both times). That repetition is what breaks it.` : '';
      F.add({ items: tableau(key, {}).items.concat(message(TX, MY() - 16, plain, ks, ct, n - 1, 20, { hot: -1, keyCls: (j) => (ex && (j === ex[0] || j === ex[1]) ? 'hot' : 'p1-key') })), say: tail + tail2, meta: { end: true } });
      return { frames: F.list, def: P.def('Vigenère', ['key k₀ k₁ … k_(m−1), repeated', 'encrypt: cᵢ = (pᵢ + k_(i mod m)) mod 26', 'decrypt: pᵢ = (cᵢ − k_(i mod m)) mod 26', 'key ' + key + ' = shifts ' + Array.from(key, (c) => ABC.indexOf(c)).join(', ')]) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.letter !== undefined && fr[i + 1].meta.letter > 0, pick: 'option', ask: (fr, i) => `${fr[i + 1].meta.from} under key letter ${fr[i + 1].meta.key} becomes…`, options: (fr, i) => P.letterOptions(fr[i + 1].meta.to, [fr[i + 1].meta.from, fr[i + 1].meta.key]), answer: (fr, i) => fr[i + 1].meta.to, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What is T encrypted with key letter C?', options: ['R', 'V', 'W', 'C'], answer: 1, why: 'C is a shift of 2: T + 2 = V.' },
      { q: 'A Vigenère key has 5 letters. Which plaintext positions share a shift?', options: ['1, 2, 3, 4, 5', '1, 6, 11, 16…', 'only position 1', 'all of them'], answer: 1, why: 'The key repeats every 5 letters.' },
      { q: 'Why do single-letter counts of a Vigenère ciphertext look flatter than English?', options: ['Vowels are removed', 'Each plain letter is spread over several cipher letters', 'The key is random', 'Spaces are counted'], answer: 1, why: 'Each column has its own shift, so E turns up as several different letters.' },
      { q: 'A Vigenère cipher with a one-letter key is…', options: ['a shift cipher', 'a one-time pad', 'unbreakable', 'a transposition'], answer: 0, why: 'Every letter gets the same shift.' },
    ],
  });

  // ---- autokey ---------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p01-autokey', family: 'p01-vigenere', order: 50, title: 'The autokey cipher',
    blurb: 'A short primer starts the key and the plaintext itself continues it. The key never repeats, so Kasiski\'s repeats vanish; but each recovered letter is the key for a later one, so the receiver can still decrypt.',
    inputs: [
      { id: 'text', kind: 'text', label: 'Message', def: 'THE TRAIN WAITS AT THE PASSING PLACE', check: textCheck(2, 40) },
      { id: 'primer', kind: 'text', label: 'Primer', def: 'KEY', check: keyCheck(8, 'Primer') },
      { id: 'dir', kind: 'choice', label: 'Show', def: 'enc', options: [{ value: 'enc', label: 'encryption' }, { value: 'dec', label: 'decryption' }] },
    ],
    presets: [
      { label: 'Primer KEY', values: { text: 'THE TRAIN WAITS AT THE PASSING PLACE', primer: 'KEY', dir: 'enc' } },
      { label: 'Decryption feeds itself', values: { text: 'THE TRAIN WAITS AT THE PASSING PLACE', primer: 'KEY', dir: 'dec' } },
      { label: 'Primer SIGNAL', values: { text: 'LAMPS LIT ALONG THE NORTH SHORE', primer: 'SIGNAL', dir: 'enc' } },
    ],
    run(inp) {
      const enc = C().autokey.encrypt(inp.text, inp.primer), plain = P.letters(inp.text), ct = P.letters(enc.out), pr = P.letters(inp.primer), L = pr.length, n = plain.length;
      const ks = enc.keystream, F = new S.Frames(), PER = 16, X = 70, Y = 30;
      const keyCls = (j) => (j < L ? 'p1-key' : 'p1-pl');
      const link = (j) => {
        // a curved arrow from plaintext letter j − L to key letter j
        const a = j - L, ra = Math.floor(a / PER), rb = Math.floor(j / PER);
        return { key: 'ln', kind: 'edge', from: 'm:p' + ra + ':' + (a % PER), to: 'm:k' + rb + ':' + (j % PER), bend: ra === rb ? -30 : 0, cls: 'hot', layer: 'top', audit: 'ignore' };
      };
      if (inp.dir === 'dec') {
        const dec = C().autokey.decrypt(ct, pr), st = dec.trace.filter((s) => s.kind === 'letter'), pt = P.letters(dec.out);
        const pic = (upto, hot) => message(X, Y, ct, ks, pt, upto, PER, { hot, topName: 'cipher', bottomName: 'plain', topCls: 'p1-ct', bottomCls: 'p1-pl', keyUpto: Math.min(n - 1, Math.max(L - 1, upto + L)), keyCls });
        F.add({ items: pic(-1), say: dec.trace[0].say + ` The receiver knows only the primer ${pr} and the ciphertext ${ct}.`, meta: {} });
        const shown = Math.min(n, L + 6);
        for (let j = 0; j < shown; j++) F.add({ items: pic(j, j).concat(j + L < n ? [Object.assign(link(j + L), { from: 'm:c' + Math.floor(j / PER) + ':' + (j % PER) })] : []), say: `Letter ${j + 1}: ${st[j].say}${j + L < n ? ` It will be the key for letter ${j + L + 1}.` : ''}`, meta: { dec: j, from: ct[j], key: ABC[st[j].s], to: ABC[st[j].p] } });
        F.add({ items: pic(n - 1, -1), say: `The rest the same way, each new plain letter unlocking a later one: ${pt}. A single mistake would spread, since a wrong letter becomes a wrong key ${L} places on.`, meta: { end: true } });
        return { frames: F.list, def: P.def('Autokey', ['key = primer ‖ plaintext', 'encrypt: cᵢ = pᵢ + kᵢ', 'decrypt: pᵢ = cᵢ − kᵢ, and pᵢ = k_(i+' + L + ')', 'primer: ' + pr]) };
      }
      const st = enc.trace.filter((s) => s.kind === 'letter');
      const pic = (upto, hot) => message(X, Y, plain, ks, ct, upto, PER, { hot, keyCls });
      F.add({ items: pic(-1), say: enc.trace[0].say + ` So the key is ${pr} followed by the message: ${ks}.`, meta: {} });
      const shown = Math.min(n, L + 6);
      for (let j = 0; j < shown; j++) F.add({ items: pic(j, j).concat(j >= L ? [link(j)] : []), say: `Letter ${j + 1}: ${st[j].say}`, meta: { letter: j, from: plain[j], key: ABC[st[j].s], to: ct[j] } });
      F.add({ items: pic(n - 1, -1), say: `The rest the same way. The ciphertext is ${ct}.`, meta: {} });
      // the long message under the same primer: Kasiski's repeats find no period
      const longCt = C().autokey.encrypt(C().corpus.longExamples.keeper, pr).out, kas = C().kasiski(longCt, { maxFactor: 20 }), vig = C().kasiski(C().vigenere.encrypt(C().corpus.longExamples.keeper, pr).out, { maxFactor: 20 });
      const share = (k) => (k.total ? Math.round((100 * k.votes[L]) / k.total) : 0), nLong = P.letters(C().corpus.longExamples.keeper).length;
      F.add({ items: pic(n - 1, -1), say: `The key never repeats, so a repeated word meets a different key each time. ` + (L >= 2 ? `On the ${nLong}-letter lighthouse message, Vigenère with key ${pr} leaves ${vig.total} repeat distances, ${share(vig)}% of them multiples of ${L}; autokey with primer ${pr} leaves ${kas.total}, and only ${share(kas)}% are multiples of ${L}, about what chance gives. ` : '') + 'Kasiski finds no period. Autokey still falls to other attacks, because its key is English text.', meta: { end: true } });
      return { frames: F.list, def: P.def('Autokey', ['key = primer ‖ plaintext', 'encrypt: cᵢ = (pᵢ + kᵢ) mod 26', 'k₀ … k_(' + (L - 1) + ') = ' + pr + ', then kᵢ = p_(i−' + L + ')', 'the key never repeats']) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.letter !== undefined && fr[i + 1].meta.letter > 0, pick: 'option', ask: (fr, i) => `${fr[i + 1].meta.from} with key letter ${fr[i + 1].meta.key} becomes…`, options: (fr, i) => P.letterOptions(fr[i + 1].meta.to, [fr[i + 1].meta.from, fr[i + 1].meta.key]), answer: (fr, i) => fr[i + 1].meta.to, explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.dec !== undefined && fr[i + 1].meta.dec > 0, pick: 'option', ask: (fr, i) => `${fr[i + 1].meta.from} minus key letter ${fr[i + 1].meta.key} gives…`, options: (fr, i) => P.letterOptions(fr[i + 1].meta.to, [fr[i + 1].meta.from, fr[i + 1].meta.key]), answer: (fr, i) => fr[i + 1].meta.to, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'With primer AB and plaintext CAT, the key is…', options: ['ABA', 'ABC', 'ABCAT', 'CAT'], answer: 1, why: 'The primer AB, then the plaintext from its first letter: A B C.' },
      { q: 'Why does Kasiski\'s method fail against autokey?', options: ['The key never repeats with a fixed period', 'The ciphertext is shorter', 'There are no repeated words', 'The primer is secret'], answer: 0, why: 'Repeats in the ciphertext come from a repeating key, which autokey does not have.' },
      { q: 'How does the receiver get the key beyond the primer?', options: ['It is sent separately', 'Each decrypted letter becomes a later key letter', 'From a codebook', 'By guessing'], answer: 1, why: 'The key past the primer is the plaintext, which decryption produces as it goes.' },
      { q: 'One ciphertext letter is garbled in transit. What happens on decryption?', options: ['Only that letter is wrong', 'The error repeats every primer-length letters', 'Nothing', 'The whole message is lost'], answer: 1, why: 'The wrong plain letter becomes a wrong key letter, which makes another wrong letter, and so on.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
