// Part 1, classical ciphers and the Enigma wing: the families, and the drawing helpers the part's topics share
// (rows of letter cells, an alphabet over its cipher alphabet, bar charts of letter counts, a score curve).
// Every value a topic draws or says comes from S.Classic or S.Enigma; these helpers only place it.
(function (S) {
  'use strict';
  const P = (S.P1 = S.P1 || {});
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  P.ABC = ABC;

  S.family({ id: 'p01-basics', part: 'classical', order: 10, title: 'Shift, affine and substitution', blurb: 'Letters moved round the alphabet, multiplied and added, or replaced by a scrambled alphabet; every key tried by brute force; and the rule that only the key is secret.' });
  S.family({ id: 'p01-frequency', part: 'classical', order: 20, title: 'Frequency analysis', blurb: 'A substitution keeps the letter counts of English: match them by hand, then let a hill climber finish the job.' });
  S.family({ id: 'p01-vigenere', part: 'classical', order: 30, title: 'Vigenère, broken in three moves', blurb: 'A repeating key of shifts, broken by Kasiski\'s repeats, the index of coincidence and a chi-squared fit per column; and the autokey that stops repeating.' });
  S.family({ id: 'p01-transposition', part: 'classical', order: 40, title: 'Transposition and Playfair', blurb: 'Letters kept but moved: a columnar grid and a rail fence; and Playfair, which enciphers two letters at a time on a 5×5 square.' });
  S.family({ id: 'p01-pad', part: 'classical', order: 50, title: 'The one-time pad', blurb: 'A fresh random key as long as the message gives perfect secrecy; used twice, it falls to crib-dragging.' });
  S.family({ id: 'p01-enigma', part: 'classical', order: 60, title: 'Inside Enigma', blurb: 'One key press through the plugboard, three rotors and the reflector; the pawls and the double step; and why no letter ever becomes itself.' });
  S.family({ id: 'p01-bombe', part: 'classical', order: 70, title: 'Breaking Enigma', blurb: 'Rejewski\'s cycles, a crib laid against the ciphertext, the Bombe\'s menu and its loops, a stop tested through the diagonal board, and the plugboard read off a stop.' });

  /** letters only, upper case */
  P.letters = (t) => String(t || '').toUpperCase().replace(/[^A-Z]/g, '');
  P.cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  P.plural = (n, w, ws) => n + ' ' + (n === 1 ? w : ws || w + 's');
  /** a / an before a word or a letter name */
  P.an = (w) => (/^([AEFHILMNORSX]$|[AEIO]|8|11|18)/.test(String(w)) && !/^(one|use|uni|eu)/i.test(String(w)) ? 'an ' : 'a ') + w;
  P.list = (xs) => (xs.length < 2 ? xs.join('') : xs.slice(0, -1).join(', ') + ' and ' + xs[xs.length - 1]);

  // ---- items -------------------------------------------------------------------------------------------------
  P.text = (key, x, y, text, cls, size, anchor) => ({ key, kind: 'text', x, y, text: String(text), cls: cls || '', size: size || 14, anchor: anchor || 'start' });
  P.title = (key, x, y, text) => ({ key, kind: 'text', x, y, text, cls: 'title', size: 13 });
  /**
   * A row of letter cells. o: {cw, h, gap, size, cls(i, ch) -> classes, sub(i) -> small text under the cell,
   * text(i, ch) -> what to show (default the letter)}
   */
  P.strip = function (prefix, x, y, letters, o) {
    o = o || {};
    const cw = o.cw || 28, h = o.h || 34, gap = o.gap === undefined ? 2 : o.gap, items = [];
    Array.from(letters).forEach((ch, i) => {
      const it = { key: prefix + i, kind: 'cell', x: x + i * (cw + gap), y, w: cw, h, rx: 4, text: o.text ? o.text(i, ch) : ch, size: o.size || 16, cls: 'mono ' + (o.cls ? o.cls(i, ch) || '' : '') };
      if (o.sub) { const s = o.sub(i, ch); if (s !== undefined && s !== null && s !== '') it.sub = String(s); }
      items.push(it);
    });
    return items;
  };
  /** the x of cell i in a strip */
  P.cx = (x, i, cw, gap) => x + i * ((cw || 28) + (gap === undefined ? 2 : gap));
  /** split a string into rows of n */
  P.rows = (t, n) => { const out = []; for (let i = 0; i < t.length; i += n) out.push(t.slice(i, i + n)); return out.length ? out : ['']; };

  /**
   * Bars standing on a baseline at y. vals: numbers; o: {w, gap, hmax, max, cls(i), label(i) under the bar,
   * value(i) text above the bar, labelSize}
   */
  P.bars = function (prefix, x, y, vals, o) {
    o = o || {};
    const w = o.w || 18, gap = o.gap === undefined ? 4 : o.gap, hmax = o.hmax || 120, max = o.max || Math.max(1e-9, ...vals), items = [];
    vals.forEach((v, i) => {
      const h = Math.max(1.5, (hmax * Math.max(0, v)) / max), bx = x + i * (w + gap);
      items.push({ key: prefix + 'b' + i, kind: 'cell', x: bx, y: y - h, w, h, rx: 2, text: '', cls: 'p1-bar ' + (o.cls ? o.cls(i) || '' : '') });
      if (o.label) items.push({ key: prefix + 'l' + i, kind: 'text', x: bx + w / 2, y: y + 16, text: o.label(i), anchor: 'middle', size: o.labelSize || 13, cls: 'mono ' + (o.labelCls ? o.labelCls(i) || '' : '') });
      if (o.value) { const t = o.value(i); if (t !== '' && t !== null && t !== undefined) items.push({ key: prefix + 'v' + i, kind: 'text', x: bx + w / 2, y: y - h - 6, text: t, anchor: 'middle', size: o.valueSize || 12, cls: 'tick ' + (o.valueCls ? o.valueCls(i) || '' : '') }); }
    });
    return items;
  };
  /** the definition panel: one block of math lines */
  P.def = (title, lines, more) => ({ sections: [{ id: 'def', kind: 'math', title, text: lines.join('\n') }].concat(more || []) });

  /** options for a letter prediction: the answer and three other letters, in alphabetical order */
  P.letterOptions = (answer, near) => {
    const set = new Set([answer]);
    for (const c of near || []) { if (set.size >= 4) break; if (c !== answer && /^[A-Z]$/.test(c)) set.add(c); }
    let k = 1; while (set.size < 4) { set.add(ABC[(ABC.indexOf(answer) + 7 * k) % 26]); k++; }
    return [...set].sort();
  };
  /** an engine sentence with proper minus signs: ·-5 → ·(−5), + -5 → + (−5), -5 → −5 */
  P.minus = (s) => String(s).replace(/·-(\d+)/g, '·(−$1)').replace(/([+−] )-(\d+)/g, '$1(−$2)').replace(/(^|[\s(])-(\d)/g, '$1−$2');
  P.lower1 = (s) => s.charAt(0).toLowerCase() + s.slice(1);
  P.fmt = (x, d) => Number(x).toFixed(d === undefined ? 1 : d).replace(/^-/, '−');
  /** a big number with thin groups of three digits, from a BigInt or a number */
  P.big = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  /** a BigInt as roughly m × 10^e */
  P.sci = (n) => { const s = String(n); if (s.length <= 6) return P.big(s); return s[0] + '.' + s.slice(1, 3) + ' × 10^' + (s.length - 1); };
  P.factorial = (n) => { let f = 1n; for (let i = 2n; i <= BigInt(n); i++) f *= i; return f; };
})(globalThis.Sifer = globalThis.Sifer || {});
