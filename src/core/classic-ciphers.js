// The classical ciphers, each with a trace a picture can be drawn from. Letter ciphers keep spaces and punctuation
// in place (so a student can still see the words) and work on the upper-case letters; transposition ciphers and
// Playfair work on the letters alone.
//   S.Classic.shift.encrypt(text, k) / decrypt(text, k)                    -> {out, trace}
//   S.Classic.affine.encrypt(text, a, b) / decrypt(text, a, b)             -> {out, inv, trace}  (inverse by traced Euclid)
//   S.Classic.substitution.keywordAlphabet(word, {continueFrom})           -> {alphabet, trace}
//   S.Classic.substitution.encrypt(text, alphabet) / decrypt(text, alphabet) -> {out, trace}
//   S.Classic.vigenere.encrypt(text, key) / decrypt(text, key)             -> {out, trace}
//   S.Classic.autokey.encrypt(text, primer) / decrypt(text, primer)        -> {out, keystream, trace}
//   S.Classic.columnar.encrypt(text, key, {pad}) / decrypt(text, key)      -> {out, grid, order, trace}
//   S.Classic.railfence.encrypt(text, rails) / decrypt(text, rails)        -> {out, rows, path, trace}
//   S.Classic.playfair.square(key) / encrypt(text, key) / decrypt(text, key) -> {out, square, pairs, trace}
//   S.Classic.otp.letters(text, pad, dir) / bytes(data, pad) / pad(n, rand) / bytePad(n, rand)
(function (S) {
  'use strict';
  const C = (S.Classic = S.Classic || {});
  const step = (kind, say, data) => S.Classic.step(kind, say, data);
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const md = (n) => ((n % 26) + 26) % 26;
  const I = (ch) => ch.charCodeAt(0) - 65, L = (i) => ABC[md(i)];
  const letters = (t) => String(t).toUpperCase().replace(/[^A-Z]/g, '');

  /** run f(letterIndex, j) over the letters of a text, j counting letters only; other characters stay where they are */
  function letterwise(text, f) {
    const src = String(text).toUpperCase(); let out = '', j = 0;
    for (let i = 0; i < src.length; i++) { const ch = src[i]; if (ch >= 'A' && ch <= 'Z') out += L(f(I(ch), j++)); else out += ch; }
    return out;
  }
  const keyLetters = (key, what) => { const k = letters(key); if (!k.length) throw new Error(what + ' needs at least one letter'); return k; };

  /* ---- shift ---- */
  C.shift = {
    encrypt(text, k, sign = 1) {
      k = md(k); const trace = [step('shift-key', `Every letter moves ${k} place${k === 1 ? '' : 's'} ${sign > 0 ? 'forward' : 'back'} round the alphabet: ${ABC[0]}→${L(sign * k)}, ${ABC[1]}→${L(1 + sign * k)}, ${ABC[25]}→${L(25 + sign * k)}.`, { k, sign, table: Array.from(ABC, (c, i) => L(i + sign * k)).join('') })];
      const out = letterwise(text, (p, j) => { const c = md(p + sign * k); trace.push(step('letter', `${L(p)} is ${p}; ${p} ${sign > 0 ? '+' : '−'} ${k} = ${p + sign * k} ≡ ${c} (mod 26), which is ${L(c)}.`, { j, p, c, k })); return c; });
      return { out, trace };
    },
    decrypt(text, k) { return C.shift.encrypt(text, k, -1); },
  };

  /* ---- affine: c = a·p + b ---- */
  C.affine = {
    valid: (a) => C.gcd(md(a), 26) === 1,
    keys() { const out = []; for (let a = 1; a < 26; a += 2) if (a !== 13) for (let b = 0; b < 26; b++) out.push([a, b]); return out; },
    encrypt(text, a, b) {
      a = md(a); b = md(b);
      const inv = C.inverse(a, 26), trace = [];
      if (inv.inv === null) { trace.push(...inv.trace); trace.push(step('affine-bad', `a = ${a} shares the factor ${inv.g} with 26, so two letters would encrypt alike and the cipher could not be undone.`, { a, b })); return { out: null, inv: null, trace }; }
      trace.push(step('affine-key', `c = ${a}·p + ${b} (mod 26). Since gcd(${a}, 26) = 1 the map is one-to-one.`, { a, b, table: Array.from(ABC, (c, i) => L(a * i + b)).join('') }));
      const out = letterwise(text, (p, j) => { const c = md(a * p + b); trace.push(step('letter', `${L(p)} = ${p}: ${a}·${p} + ${b} = ${a * p + b} ≡ ${c} (mod 26), which is ${L(c)}.`, { j, p, c })); return c; });
      return { out, inv: inv.inv, trace };
    },
    decrypt(text, a, b) {
      a = md(a); b = md(b);
      const inv = C.inverse(a, 26), trace = inv.trace.slice();
      if (inv.inv === null) return { out: null, inv: null, trace };
      const ai = inv.inv;
      trace.push(step('affine-inv', `To undo c = ${a}·p + ${b}, compute p = ${ai}·(c − ${b}) (mod 26), using the inverse ${ai} of ${a}.`, { a, b, ai, table: Array.from(ABC, (c, i) => L(ai * (i - b))).join('') }));
      const out = letterwise(text, (c, j) => { const p = md(ai * (c - b)); trace.push(step('letter', `${L(c)} = ${c}: ${ai}·(${c} − ${b}) = ${ai * (c - b)} ≡ ${p} (mod 26), which is ${L(p)}.`, { j, c, p })); return p; });
      return { out, inv: ai, trace };
    },
  };

  /* ---- monoalphabetic substitution; the alphabet lists the cipher letter for A, B, C ... ---- */
  C.substitution = {
    /** the keyword's letters without repeats, then the rest of the alphabet (from A, or continuing after the last keyword letter) */
    keywordAlphabet(word, opts = {}) {
      const k = [...new Set(letters(word))], trace = [step('kw-dedup', `Write the keyword ${letters(word)} without repeated letters: ${k.join('')}.`, { keyword: letters(word), unique: k.join('') })];
      const rest = [], start = opts.continueFrom && k.length ? I(k[k.length - 1]) + 1 : 0;
      for (let i = 0; i < 26; i++) { const ch = L(start + i); if (!k.includes(ch)) rest.push(ch); }
      trace.push(step('kw-rest', `Then the unused letters in order${start ? ' starting after ' + L(start - 1) : ''}: ${rest.join('')}.`, { rest: rest.join('') }));
      const alphabet = k.join('') + rest.join('');
      trace.push(step('kw-alphabet', `Plain ${ABC} becomes cipher ${alphabet}.`, { alphabet }));
      return { alphabet, trace };
    },
    check(alpha) { const a = letters(alpha); if (a.length !== 26 || new Set(a).size !== 26) throw new Error('a substitution alphabet must use each of the 26 letters once'); return a; },
    invert(alpha) { const a = C.substitution.check(alpha), out = new Array(26); for (let i = 0; i < 26; i++) out[I(a[i])] = ABC[i]; return out.join(''); },
    encrypt(text, alpha) {
      const a = C.substitution.check(alpha), trace = [step('sub-table', `Each plain letter is replaced by the letter beneath it: ${ABC} over ${a}.`, { alphabet: a })];
      const out = letterwise(text, (p, j) => { const c = I(a[p]); trace.push(step('letter', `${L(p)} → ${L(c)}.`, { j, p, c })); return c; });
      return { out, trace };
    },
    decrypt(text, alpha) {
      const inv = C.substitution.invert(alpha), trace = [step('sub-table', `Read the table upwards: cipher ${ABC} came from plain ${inv}.`, { alphabet: inv })];
      const out = letterwise(text, (c, j) => { const p = I(inv[c]); trace.push(step('letter', `${L(c)} → ${L(p)}.`, { j, c, p })); return p; });
      return { out, trace };
    },
  };

  /* ---- Vigenère and autokey ---- */
  C.vigenere = {
    encrypt(text, key, sign = 1) {
      const k = keyLetters(key, 'a Vigenère key'), trace = [step('vig-key', `The key ${k} repeats under the message; each key letter is a shift (A = 0, ${k[0]} = ${I(k[0])}).`, { key: k, shifts: Array.from(k, I) })];
      const out = letterwise(text, (p, j) => { const s = I(k[j % k.length]), c = md(p + sign * s); trace.push(step('letter', `${L(p)} ${sign > 0 ? '+' : '−'} ${k[j % k.length]} (${s}) = ${L(c)}.`, { j, p, c, col: j % k.length, keyLetter: k[j % k.length], s })); return c; });
      return { out, trace };
    },
    decrypt(text, key) { return C.vigenere.encrypt(text, key, -1); },
  };
  C.autokey = {
    encrypt(text, primer) {
      const pr = keyLetters(primer, 'an autokey primer'), ks = Array.from(pr, I), trace = [step('autokey-primer', `The primer ${pr} starts the key; after it the key is the plaintext itself.`, { primer: pr })];
      const out = letterwise(text, (p, j) => { const s = ks[j], c = md(p + s); ks.push(p); trace.push(step('letter', `${L(p)} + ${L(s)} = ${L(c)}${j >= pr.length ? ` (key letter ${L(s)} is plaintext letter ${j - pr.length + 1})` : ''}.`, { j, p, c, s, fromPlain: j >= pr.length })); return c; });
      return { out, keystream: ks.slice(0, letters(text).length).map(L).join(''), trace };
    },
    decrypt(text, primer) {
      const pr = keyLetters(primer, 'an autokey primer'), ks = Array.from(pr, I), trace = [step('autokey-primer', `Start with the primer ${pr}; each recovered plaintext letter becomes a later key letter.`, { primer: pr })];
      const out = letterwise(text, (c, j) => { const s = ks[j], p = md(c - s); ks.push(p); trace.push(step('letter', `${L(c)} − ${L(s)} = ${L(p)}, and ${L(p)} joins the key.`, { j, c, p, s })); return p; });
      return { out, keystream: ks.slice(0, letters(text).length).map(L).join(''), trace };
    },
  };

  /* ---- columnar transposition ---- */
  /** the column order of a key word: alphabetical, ties left to right; order[r] is the column read r-th */
  function columnOrder(key) {
    const k = keyLetters(key, 'a columnar key');
    const cols = Array.from(k, (ch, i) => ({ ch, i })).sort((a, b) => (a.ch < b.ch ? -1 : a.ch > b.ch ? 1 : a.i - b.i));
    const rank = new Array(k.length); cols.forEach((c, r) => { rank[c.i] = r; });
    return { key: k, order: cols.map((c) => c.i), rank };
  }
  C.columnar = {
    order: columnOrder,
    encrypt(text, key, opts = {}) {
      const { key: k, order, rank } = columnOrder(key), w = k.length;
      let t = letters(text);
      if (opts.pad) while (t.length % w) t += typeof opts.pad === 'string' ? opts.pad : 'X';
      const grid = []; for (let i = 0; i < t.length; i += w) grid.push(t.slice(i, i + w).split(''));
      const trace = [step('col-grid', `Write the ${t.length} letters in rows under the key ${k}, ${w} to a row, giving ${grid.length} rows.`, { key: k, grid, rank })];
      trace.push(step('col-order', `Number the columns by the alphabetical order of the key letters: ${Array.from(k, (ch, i) => ch + '=' + (rank[i] + 1)).join(' ')}.`, { order, rank }));
      let out = '';
      for (const c of order) { const col = grid.map((r) => r[c]).filter(Boolean).join(''); out += col; trace.push(step('col-read', `Column ${rank[c] + 1} (key letter ${k[c]}) reads ${col}.`, { col: c, letters: col })); }
      return { out, grid, order, rank, trace };
    },
    decrypt(text, key) {
      const { key: k, order, rank } = columnOrder(key), w = k.length, t = letters(text), rows = Math.ceil(t.length / w), full = t.length % w || w;
      const grid = Array.from({ length: rows }, (_, r) => new Array(r < rows - 1 ? w : full).fill(''));
      const trace = [step('col-shape', `${t.length} letters under a key of ${w}: ${rows} rows, the last with ${full} letter${full === 1 ? '' : 's'}, so columns 1 to ${full} in key position are ${rows} long and the rest ${rows - 1}.`, { rows, full })];
      let p = 0;
      for (const c of order) { const h = c < full ? rows : rows - 1, col = t.slice(p, p + h); for (let r = 0; r < h; r++) grid[r][c] = col[r]; p += h; trace.push(step('col-fill', `Column ${rank[c] + 1} (key letter ${k[c]}) gets the next ${h} letters, ${col}.`, { col: c, letters: col })); }
      const out = grid.map((r) => r.join('')).join('');
      trace.push(step('col-rows', `Reading the rows gives ${out}.`, { out }));
      return { out, grid, order, rank, trace };
    },
  };

  /* ---- rail fence ---- */
  function railPath(n, rails) { const path = []; if (rails < 2) return new Array(n).fill(0); let r = 0, d = 1; for (let i = 0; i < n; i++) { path.push(r); if (r === 0) d = 1; else if (r === rails - 1) d = -1; r += d; } return path; }
  C.railfence = {
    path: railPath,
    encrypt(text, rails) {
      const t = letters(text), path = railPath(t.length, rails), rows = Array.from({ length: rails }, () => '');
      for (let i = 0; i < t.length; i++) rows[path[i]] += t[i];
      const trace = [step('rail-zigzag', `Write ${t} in a zigzag down and up ${rails} rails.`, { text: t, rails, path })];
      rows.forEach((r, k) => trace.push(step('rail-read', `Rail ${k + 1} reads ${r}.`, { rail: k, letters: r })));
      return { out: rows.join(''), rows, path, trace };
    },
    decrypt(text, rails) {
      const t = letters(text), path = railPath(t.length, rails), counts = new Array(rails).fill(0);
      path.forEach((r) => counts[r]++);
      const rows = [], trace = [step('rail-count', `The zigzag over ${t.length} letters puts ${counts.join(', ')} letters on the rails.`, { counts, path })];
      let p = 0; for (let r = 0; r < rails; r++) { rows.push(t.slice(p, p + counts[r])); p += counts[r]; trace.push(step('rail-fill', `Rail ${r + 1} takes ${rows[r]}.`, { rail: r, letters: rows[r] })); }
      const at = new Array(rails).fill(0); let out = '';
      for (const r of path) out += rows[r][at[r]++];
      trace.push(step('rail-walk', `Following the zigzag across the rails reads ${out}.`, { out }));
      return { out, rows, path, trace };
    },
  };

  /* ---- Playfair (I and J share a cell) ---- */
  C.playfair = {
    square(key) {
      const seen = [], k = letters(key).replace(/J/g, 'I');
      for (const ch of k + 'ABCDEFGHIKLMNOPQRSTUVWXYZ') if (!seen.includes(ch)) seen.push(ch);
      const sq = seen.join(''), pos = {}; for (let i = 0; i < 25; i++) pos[sq[i]] = [Math.floor(i / 5), i % 5];
      return { square: sq, rows: [0, 1, 2, 3, 4].map((r) => sq.slice(5 * r, 5 * r + 5)), pos, trace: [step('pf-square', `Fill the 5×5 square with the key ${k || '(none)'} without repeats, then the rest of the alphabet (J shares I's cell): ${sq.match(/.{5}/g).join(' / ')}.`, { square: sq })] };
    },
    /** split the message into pairs: J becomes I, a doubled pair is broken by X (Q after X), an odd end gets X */
    digraphs(text) {
      const t = letters(text).replace(/J/g, 'I'), pairs = [], trace = [];
      let i = 0;
      while (i < t.length) {
        const a = t[i]; let b = t[i + 1];
        if (b === undefined) { b = a === 'X' ? 'Q' : 'X'; trace.push(step('pf-pad', `${a} is left alone at the end, so add ${b}.`, { a, b })); i += 1; }
        else if (a === b) { b = a === 'X' ? 'Q' : 'X'; trace.push(step('pf-split', `${a}${a} would be a doubled pair, so put ${b} between them.`, { a, b })); i += 1; }
        else i += 2;
        pairs.push(a + b);
      }
      return { pairs, trace };
    },
    encrypt(text, key, sign = 1) {
      const sq = C.playfair.square(key), trace = sq.trace.slice();
      let pairs;
      if (sign > 0) { const d = C.playfair.digraphs(text); pairs = d.pairs; trace.push(...d.trace); }
      else { const t = letters(text).replace(/J/g, 'I'); if (t.length % 2) throw new Error('Playfair ciphertext has an even number of letters'); pairs = t.match(/../g) || []; }
      trace.push(step('pf-pairs', `The pairs are ${pairs.join(' ')}.`, { pairs }));
      const out = [];
      for (const pr of pairs) {
        const [ra, ca] = sq.pos[pr[0]], [rb, cb] = sq.pos[pr[1]];
        let x, y, rule;
        if (ra === rb) { x = sq.square[ra * 5 + (ca + sign + 5) % 5]; y = sq.square[rb * 5 + (cb + sign + 5) % 5]; rule = 'row'; }
        else if (ca === cb) { x = sq.square[((ra + sign + 5) % 5) * 5 + ca]; y = sq.square[((rb + sign + 5) % 5) * 5 + cb]; rule = 'column'; }
        else { x = sq.square[ra * 5 + cb]; y = sq.square[rb * 5 + ca]; rule = 'rectangle'; }
        const why = rule === 'row' ? `same row, take the letters to the ${sign > 0 ? 'right' : 'left'}` : rule === 'column' ? `same column, take the letters ${sign > 0 ? 'below' : 'above'}` : 'a rectangle, take the other two corners on the same rows';
        trace.push(step('pf-pair', `${pr}: ${why}, giving ${x}${y}.`, { pair: pr, out: x + y, rule, a: [ra, ca], b: [rb, cb] }));
        out.push(x + y);
      }
      return { out: out.join(''), square: sq.square, pairs, trace };
    },
    decrypt(text, key) { return C.playfair.encrypt(text, key, -1); },
  };

  /* ---- the one-time pad ---- */
  C.otp = {
    pad(n, rand) { let s = ''; for (let i = 0; i < n; i++) s += ABC[Math.floor(rand() * 26)]; return s; },
    bytePad(n, rand) { const b = new Uint8Array(n); for (let i = 0; i < n; i++) b[i] = Math.floor(rand() * 256); return b; },
    /** letters: c = p + k (dir 1) or p = c − k (dir −1); the pad must be at least as long as the message */
    letters(text, pad, dir = 1) {
      const t = letters(text), k = letters(pad);
      if (k.length < t.length) throw new Error(`the pad has ${k.length} letters but the message has ${t.length}`);
      const trace = [step('otp-rule', `Each letter gets its own pad letter, used once and never again: ${dir > 0 ? 'c = p + k' : 'p = c − k'} (mod 26).`, { dir })];
      let out = '';
      for (let i = 0; i < t.length; i++) { const v = md(I(t[i]) + dir * I(k[i])); out += L(v); trace.push(step('letter', `${t[i]} ${dir > 0 ? '+' : '−'} ${k[i]} = ${L(v)}.`, { j: i, a: I(t[i]), k: I(k[i]), v })); }
      return { out, used: k.slice(0, t.length), trace };
    },
    /** bytes: c = p XOR k */
    bytes(data, pad) {
      if (pad.length < data.length) throw new Error(`the pad has ${pad.length} bytes but the message has ${data.length}`);
      const h = (v) => v.toString(16).padStart(2, '0'), out = new Uint8Array(data.length), trace = [];
      for (let i = 0; i < data.length; i++) { out[i] = data[i] ^ pad[i]; trace.push(step('byte', `${h(data[i])} ⊕ ${h(pad[i])} = ${h(out[i])}.`, { j: i, a: data[i], k: pad[i], v: out[i] })); }
      return { out, trace };
    },
    /** two ciphertexts under the same pad: their XOR is the XOR of the plaintexts, and a guessed word slid along it shows the other text */
    cribDrag(c1, c2, crib) {
      const x = new Uint8Array(Math.min(c1.length, c2.length)); for (let i = 0; i < x.length; i++) x[i] = c1[i] ^ c2[i];
      const g = typeof crib === 'string' ? new TextEncoder().encode(crib) : crib, rows = [];
      for (let p = 0; p + g.length <= x.length; p++) {
        let s = '', printable = 0; for (let i = 0; i < g.length; i++) { const v = x[p + i] ^ g[i]; s += String.fromCharCode(v); if ((v >= 97 && v <= 122) || (v >= 65 && v <= 90) || v === 32) printable++; }
        rows.push({ pos: p, text: s, printable: printable / g.length });
      }
      return { xor: x, rows };
    },
  };
})(globalThis.Sifer = globalThis.Sifer || {});
