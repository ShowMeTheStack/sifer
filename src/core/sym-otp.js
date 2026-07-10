// The one-time pad and what goes wrong when its key is used twice. With a truly random key as long as the message,
// used once, every plaintext of that length is equally likely given the ciphertext (perfect secrecy). With the same
// key on two messages, c1 ⊕ c2 = m1 ⊕ m2: the key cancels and two English texts remain, tangled together.
// Crib dragging slides a guessed word along m1 ⊕ m2; where the guess is right, the other message shows through.
// A full recovery runs a beam search over both messages at once, scored by a character model of English.
//   S.OTP.encrypt(msg, key) -> {out, trace};  S.OTP.keyFor(c, m') -> the key that "decrypts" c to any m'
//   S.OTP.MESSAGES: original lab plaintexts;  S.OTP.setup({seed}) -> {m1, m2, key, c1, c2}
//   S.OTP.crib(x, crib) -> {rows: [{pos, other, score, plausible}], best, trace}       x = c1 ⊕ c2
//   S.OTP.run(...) -> generator yielding {done, total}; S.OTP.recover(x | [c1, c2, …][, {beam}]) -> {m1, m2, messages, pad, trace}   from c1 ⊕ c2, or from several ciphertexts
//   S.OTP.agreement(r1, r2, m1, m2) -> fraction right, up to the swaps the XOR allows; S.OTP.matches -> all right
(function (S) {
  'use strict';
  const O = (S.OTP = {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const hex = (a) => S.bytes.hex(a);
  const text = (a) => String.fromCharCode(...a);
  const show = (a) => Array.from(a, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '·')).join('');
  O.encrypt = (msg, key) => {
    if (key.length < msg.length) throw new Error('the pad must be at least as long as the message');
    const out = msg.map((v, i) => v ^ key[i]), trace = [];
    for (let i = 0; i < Math.min(msg.length, 12); i++) trace.push(step('otp', `'${show([msg[i]])}' ${S.bytes.h2(msg[i])} ⊕ key ${S.bytes.h2(key[i])} = ${S.bytes.h2(out[i])}.`, { i, m: msg[i], k: key[i], c: out[i] }));
    trace.push(step('otp-done', `Ciphertext ${hex(out)}.`, { out }));
    return { out, trace };
  };
  O.keyFor = (c, m) => c.map((v, i) => v ^ m[i]);
  // written with words of the original corpus, which stands in for the attacker's dictionary
  O.MESSAGES = [
    'wait for me at the north bridge by the old mill at nine in the evening',
    'the cargo of glass jars leaves the harbour on thursday morning by boat',
    'bring the blue notebook and the brass key to the office on friday',
    'our garden club planted a new apple tree along the wall of the school',
    'the bridge on the west road is closed until the men change the steel cables',
    'send the receipts for the bread and the flour back to the baker this week',
    'grandmother says the recipe needs more salt and a little honey and milk',
    'the late trains from the coast were full of students going home for the summer',
    'keep the lamp in the window turned on until the last boat is safe in the harbour',
    'the library will open on sunday and all the readers may take two more books',
    'when the bell rings twice the class should come to the hall in silence',
    'the small dogs of the farmer hid the boots of the doctor under the bench',
  ];

  O.setup = ({ seed = 1 } = {}) => {
    const r = S.Sym.rng(seed), i = Math.floor(r() * O.MESSAGES.length);
    let j = Math.floor(r() * (O.MESSAGES.length - 1)); if (j >= i) j++;
    const m1 = S.bytes.utf8(O.MESSAGES[i]), m2 = S.bytes.utf8(O.MESSAGES[j]);
    // both are cut to the shorter length, at the end of a word of the first
    let n = Math.min(m1.length, m2.length);
    while (n < m1.length && m1[n] !== 32) n--;
    const key = S.Sym.bytes(r, n), a = m1.slice(0, n), b = m2.slice(0, n);
    return { m1: a, m2: b, key, c1: O.encrypt(a, key).out, c2: O.encrypt(b, key).out };
  };

  // ---- a character model of English from the original corpus: interpolated trigram, bigram and unigram
  const ALPHA = "abcdefghijklmnopqrstuvwxyz .,'";
  const A = ALPHA.length, code = new Int16Array(256).fill(-1);
  for (let i = 0; i < A; i++) code[ALPHA.charCodeAt(i)] = i;
  let LM = null;
  const model = () => {
    if (LM) return LM;
    const src = ((S.Classic && S.Classic.corpus && S.Classic.corpus.passages) || O.MESSAGES).join(' ').toLowerCase().replace(/[^a-z .,']+/g, ' ').replace(/ +/g, ' ');
    const u = new Float64Array(A).fill(1), b = new Float64Array(A * A).fill(0), t = new Float64Array(A * A * A).fill(0);
    const ids = Array.from(src, (ch) => code[ch.charCodeAt(0)]);
    for (let i = 0; i < ids.length; i++) {
      u[ids[i]]++;
      if (i > 0) b[ids[i - 1] * A + ids[i]]++;
      if (i > 1) t[(ids[i - 2] * A + ids[i - 1]) * A + ids[i]]++;
    }
    const us = u.reduce((x, y) => x + y, 0), lp = new Float64Array(A * A * A);
    for (let p = 0; p < A; p++) for (let q = 0; q < A; q++) {
      let bs = 0, ts = 0;
      for (let c = 0; c < A; c++) { bs += b[q * A + c]; ts += t[(p * A + q) * A + c]; }
      for (let c = 0; c < A; c++) {
        const pu = u[c] / us, pb = bs ? b[q * A + c] / bs : pu, pt = ts ? t[(p * A + q) * A + c] / ts : pb;
        lp[(p * A + q) * A + c] = Math.log(0.6 * pt + 0.3 * pb + 0.1 * pu);
      }
    }
    LM = { lp, start: code[32] };
    return LM;
  };
  /** score of byte c after context (p, q); bytes outside the model's alphabet (capitals map to their lower case
   *  with a penalty) are very unlikely */
  const sc = (p, q, c) => {
    let k = code[c], pen = 0;
    if (k < 0 && c >= 65 && c <= 90) { k = code[c + 32]; pen = -3.5; }
    if (k < 0) return -1e9;
    return LM.lp[(p * A + q) * A + k] + pen;
  };
  const low = (c) => (code[c] >= 0 ? code[c] : c >= 65 && c <= 90 ? code[c + 32] : LM.start);
  O.textScore = (bytes) => { model(); let p = LM.start, q = LM.start, s = 0; for (const c of bytes) { s += sc(p, q, c); p = q; q = low(c); } return s / Math.max(1, bytes.length); };

  O.crib = (x, crib) => {
    model();
    const w = typeof crib === 'string' ? S.bytes.utf8(crib) : crib, rows = [];
    for (let pos = 0; pos + w.length <= x.length; pos++) {
      const other = w.map((v, i) => v ^ x[pos + i]), score = O.textScore(other);
      rows.push({ pos, other: show(other), score, plausible: other.every((c) => code[c] >= 0 || (c >= 65 && c <= 90)) && score > -4.2 });
    }
    const best = rows.filter((r) => r.plausible).sort((a, b) => b.score - a.score);
    const trace = rows.slice(0, 64).map((r) => step('crib', `Position ${r.pos}: '${text(w)}' ⊕ (c1 ⊕ c2) gives '${r.other}'${r.plausible ? ' — readable, a likely hit' : ''}.`, r));
    trace.push(step('crib-best', best.length ? `The most readable placements of '${text(w)}': ${best.slice(0, 4).map((r) => `${r.pos} → '${r.other}'`).join(', ')}.` : `No placement of '${text(w)}' gives readable text.`, { best: best.slice(0, 8) }));
    return { rows, best, trace };
  };

  // the attacker's dictionary: the words of the corpus, and every prefix of them
  let DICT = null;
  const dict = () => {
    if (DICT) return DICT;
    const src = ((S.Classic && S.Classic.corpus && S.Classic.corpus.passages) || O.MESSAGES).join(' ').toLowerCase();
    const words = new Set(src.match(/[a-z']+/g)), prefixes = new Set();
    for (const w of words) for (let i = 1; i <= w.length; i++) prefixes.add(w.slice(0, i));
    DICT = { words, prefixes };
    return DICT;
  };
  const isWordChar = (c) => (c >= 97 && c <= 122) || (c >= 65 && c <= 90) || c === 39;
  /** the cost of byte c in a stream whose current word is w: the character model, plus a word check */
  const advance = (ctx, w, c) => {
    let s = sc(ctx[0], ctx[1], c), nw = w;
    // a full stop or comma is followed by a space
    if ((ctx[1] === code[46] || ctx[1] === code[44]) && c !== 32) s -= 5;
    if (isWordChar(c)) { nw = w + String.fromCharCode(c | (c === 39 ? 0 : 32)); if (!DICT.prefixes.has(nw)) s -= 5; }
    else if (w) { s += DICT.words.has(w) ? 1.5 : -5; nw = ''; }
    return { s, w: nw, ctx: [ctx[1], low(c)] };
  };
  /** beam search over the messages together, one byte position at a time. With two ciphertexts, m1[i] is chosen and
   *  m2[i] = m1[i] ⊕ x[i] follows; with more, the pad byte is chosen and every message follows from it. */
  O.run = function* (input, { beam = 100 } = {}) {
    model(); dict();
    const cs = Array.isArray(input) ? input : null, n = cs ? Math.min(...cs.map((c) => c.length)) : input.length;
    const k = cs ? cs.length : 2;
    // with two ciphertexts the pad is unknown: take c1 = x, c2 = 0, and the "pad byte" is m2's byte
    const C = cs || [input, new Uint8Array(n)];
    const ok = (c) => code[c] >= 0 || (c >= 65 && c <= 90);
    let states = [{ ctx: Array.from({ length: k }, () => [LM.start, LM.start]), w: new Array(k).fill(''), s: 0, key: [] }];
    const trace = [];
    for (let i = 0; i < n; i++) {
      const next = new Map();
      for (let kb = 0; kb < 256; kb++) {
        const ms = C.map((c) => c[i] ^ kb);
        if (!ms.every(ok)) continue;
        for (const st of states) {
          let s = st.s;
          const ctx = [], w = [];
          for (let j = 0; j < k; j++) { const r = advance(st.ctx[j], st.w[j], ms[j]); s += r.s; ctx.push(r.ctx); w.push(r.w); }
          const sig = ctx.map((x, j) => x.join(',') + ':' + w[j]);
          const key = (cs ? sig : sig.slice().sort()).join('|'), cur = next.get(key);
          if (!cur || cur.s < s) next.set(key, { ctx, w, s, key: st.key.concat(kb) });
        }
      }
      states = [...next.values()].sort((u, v) => v.s - u.s).slice(0, beam);
      yield { done: i + 1, total: n };
      if (i % 8 === 7 || i === n - 1) trace.push(step('beam', `After ${i + 1} characters the best reading is ${C.map((c) => `'${show(states[0].key.map((kb, t) => c[t] ^ kb))}'`).join(' / ')}.`, { i }));
    }
    // a word still open at the end scores as a word if it is one
    // and a message rarely ends in a space
    for (const st of states) st.s += st.w.reduce((t, w) => t + (w && DICT.words.has(w) ? 1.5 : 0), 0) - 3 * st.w.filter((w, j) => !w && st.ctx[j][1] === code[32]).length;
    states.sort((u, v) => v.s - u.s);
    const best = states[0], msgs = C.map((c) => Uint8Array.from(best.key, (kb, t) => c[t] ^ kb));
    // with two ciphertexts the stand-in pad byte was m2 itself, and m1 = x ⊕ m2
    const [m1, m2] = cs ? msgs : [msgs[0], Uint8Array.from(best.key)];
    trace.push(step('recovered', cs ? `Recovered all ${k} messages, and with them the pad: ${hex(best.key.slice(0, 16))}…`
      : `Recovered m1 = '${show(m1)}' and m2 = '${show(m2)}'. Where both messages have a space at the same place, c1 ⊕ c2 is 00 and the rest of the two texts could be swapped: the XOR alone cannot tell which piece belongs to which message.`, {}));
    return { m1, m2, messages: cs ? msgs : [m1, m2], pad: cs ? Uint8Array.from(best.key) : null, score: best.s, trace };
  };
  O.recover = (input, opts) => S.Sym.drain(O.run(input, opts));
  /** the fraction of positions a two-message recovery gets right, allowing the pieces between places where
   *  c1 ⊕ c2 = 00 to be swapped (the XOR cannot order them) */
  O.agreement = (r1, r2, m1, m2) => {
    let i = 0, good = 0;
    while (i < m1.length) {
      let j = i; while (j < m1.length - 1 && (m1[j] ^ m2[j]) !== 0) j++;
      let same = 0, swap = 0;
      for (let t = i; t <= j; t++) { same += r1[t] === m1[t] && r2[t] === m2[t]; swap += r1[t] === m2[t] && r2[t] === m1[t]; }
      good += Math.max(same, swap);
      i = j + 1;
    }
    return good / m1.length;
  };
  O.matches = (r1, r2, m1, m2) => O.agreement(r1, r2, m1, m2) === 1;
})(globalThis.Sifer = globalThis.Sifer || {});
