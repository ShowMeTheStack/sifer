// Part 1: the one-time pad, whose ciphertext could be any message of its length, and the two-time pad: the same pad
// used twice cancels out when the ciphertexts are XORed, and a guessed word slid along the result reveals the other
// message piece by piece.
(function (S) {
  'use strict';
  const P = S.P1, ABC = P.ABC;
  const C = () => S.Classic;
  const hex = (v) => v.toString(16).padStart(2, '0');
  const show = (v) => (v >= 32 && v < 127 ? (v === 32 ? '␣' : String.fromCharCode(v)) : '·');

  // ---- the one-time pad, with letters ------------------------------------------------------------------------------
  const X0 = 80, CW = 30;
  function rows(list, upto, o) {
    o = o || {};
    const items = [];
    list.forEach((row, k) => {
      const y = row.y;
      items.push(P.text('l:' + row.id, X0 - 10, y + 21, row.label, row.labelCls || 'tick', 13, 'end'));
      items.push(...P.strip(row.id + ':', X0, y, Array.from(row.text, (c, i) => (row.partial && i > upto ? ' ' : c)).join(''), { cw: CW - 3, gap: 3, h: 30, size: 15, cls: (i) => (row.partial && i > upto ? 'soft' : row.cls + (i === o.hot ? ' hot' : '')) }));
    });
    return items;
  }
  S.topic({
    id: 'p01-otp', family: 'p01-pad', order: 10, title: 'The one-time pad and perfect secrecy',
    blurb: 'Add a truly random key letter to every message letter, with a key as long as the message and never used again. Then the ciphertext could be any message of that length: there is nothing for an attacker to find.',
    inputs: [
      { id: 'text', kind: 'text', label: 'Message', def: 'ATTACK THE NORTH GATE', check: (v) => { const n = P.letters(v).length; return n < 2 ? 'Message: at least 2 letters' : n > 22 ? 'Message: at most 22 letters' : null; } },
      { id: 'decoy', kind: 'text', label: 'Another message', def: 'BRING THE BOATS IN NOW', check: (v, inp) => (P.letters(v).length !== P.letters(inp.text).length ? 'Another message: exactly as many letters as the message (' + P.letters(inp.text).length + ')' : null) },
      { id: 'seed', kind: 'number', label: 'Pad seed', def: 2026, min: 1, max: 99999 },
    ],
    presets: [
      { label: 'Attack, or bring the boats?', values: { text: 'ATTACK THE NORTH GATE', decoy: 'BRING THE BOATS IN NOW', seed: 2026 } },
      { label: 'Yes or no', values: { text: 'YES', decoy: 'NOT', seed: 7 } },
      { label: 'A sale price', values: { text: 'SELL AT FIFTY', decoy: 'HOLD FOR JUNE', seed: 314 } },
    ],
    run(inp) {
      const m = P.letters(inp.text), n = m.length, pad = C().otp.pad(n, C().rng(inp.seed)), enc = C().otp.letters(m, pad, 1), ct = enc.out;
      const decoy = P.letters(inp.decoy), alt = C().otp.letters(ct, decoy, -1), pad2 = alt.out, check = C().otp.letters(decoy, pad2, 1).out;
      const F = new S.Frames();
      const base = (upto, o) => rows([{ id: 'm', label: 'message', text: m, cls: 'p1-pl', y: 0 }, { id: 'k', label: 'pad', text: pad, cls: 'p1-key', y: 36, labelCls: 'key' }, { id: 'c', label: 'cipher', text: ct, cls: 'p1-ct', y: 72, partial: true }], upto, o);
      F.add({ items: base(-1), say: `The pad is ${n} random letters, ${pad}, made for this message alone and shared in advance. ${enc.trace[0].say}`, meta: {} });
      const steps = enc.trace.filter((t) => t.kind === 'letter'), shown = Math.min(n, 5);
      for (let j = 0; j < shown; j++) F.add({ items: base(j, { hot: j }), say: `${steps[j].say.replace(/\.$/, '')}: ${m[j]} = ${steps[j].a}, ${pad[j]} = ${steps[j].k}, and (${steps[j].a} + ${steps[j].k}) mod 26 = ${steps[j].v}.`, meta: { letter: j, to: ct[j], from: m[j], key: pad[j] } });
      F.add({ items: base(n - 1), say: `The ciphertext is ${ct}. Every cipher letter is equally likely whatever the message letter was, because the pad letter under it is.`, meta: {} });
      const two = rows([{ id: 'm', label: 'message', text: m, cls: 'p1-pl', y: 0 }, { id: 'k', label: 'pad', text: pad, cls: 'p1-key', y: 36, labelCls: 'key' }, { id: 'c', label: 'cipher', text: ct, cls: 'p1-ct', y: 72 }, { id: 'k2', label: 'other pad', text: pad2, cls: 'p1-key', y: 140, labelCls: 'key' }, { id: 'd', label: 'other message', text: decoy, cls: 'p1-good', y: 176 }], n);
      F.add({ items: two, say: `Now suppose the pad had been ${pad2} instead. That pad is just as random, and with it the same ciphertext ${ct} decrypts to ${decoy}: ${pad2} = ${ct} − ${decoy}, letter by letter.`, meta: { decoy: true } });
      F.add({ items: two, say: `Check: ${decoy} + ${pad2} = ${check}${check === ct ? ', the same ciphertext' : ''}. For every message of ${n} letters there is exactly one pad that gives this ciphertext, and all pads are equally likely, so the ciphertext says nothing about which message was sent. This is perfect secrecy.`, meta: {} });
      F.add({ items: two, say: `The price: a truly random pad as long as all the traffic, delivered in secret beforehand, and destroyed after one use. Reusing a pad, even once, breaks it, as the next topic shows.`, meta: { end: true } });
      return { frames: F.list, def: P.def('One-time pad', ['c = (p + k) mod 26, letter by letter', 'k: uniformly random, |k| = |p|', 'used once, then destroyed', 'for every p′ of the same length', '  there is a k′ = c − p′ that fits']) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.letter !== undefined && fr[i + 1].meta.letter > 0, pick: 'option', ask: (fr, i) => `${fr[i + 1].meta.from} plus pad letter ${fr[i + 1].meta.key} is…`, options: (fr, i) => P.letterOptions(fr[i + 1].meta.to, [fr[i + 1].meta.from, fr[i + 1].meta.key]), answer: (fr, i) => fr[i + 1].meta.to, explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.decoy, pick: 'option', ask: 'Could this same ciphertext have come from a completely different message of the same length?', options: ['no, only from the real message', 'yes, from any message of that length', 'only from messages with the same vowels'], answer: 'yes, from any message of that length', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Which is NOT a requirement of the one-time pad?', options: ['The pad is truly random', 'The pad is as long as the message', 'The pad is never reused', 'The pad is a dictionary word'], answer: 3, why: 'A word is far from random; the other three are exactly the rules.' },
      { q: 'Why can brute force not break a one-time pad?', options: ['It is too slow', 'Every message of the right length appears among the decryptions, with nothing to pick the true one', 'The pad is encrypted', 'The ciphertext is longer'], answer: 1, why: 'Trying every pad produces every possible message.' },
      { q: 'What does perfect secrecy mean?', options: ['Nobody has broken it yet', 'The ciphertext gives no information about the message beyond its length', 'The key is short', 'It uses XOR'], answer: 1, why: 'P(message | ciphertext) = P(message).' },
      { q: 'What is the practical difficulty of the one-time pad?', options: ['It is slow to compute', 'Delivering and protecting a secret key as long as all the messages', 'It only works for letters', 'It needs a computer'], answer: 1, why: 'Key distribution, not computation, is the problem.' },
    ],
  });

  // ---- the two-time pad and crib-dragging ------------------------------------------------------------------------------
  const BW = 27, HX = 100;
  function hexRow(id, label, bytes, y, cls, o) {
    o = o || {};
    const items = [P.text('h:' + id, HX - 10, y + 19, label, o.labelCls || 'tick', 13, 'end')];
    bytes.forEach((v, i) => items.push({ key: id + ':' + i, kind: 'cell', x: HX + i * BW, y, w: BW - 2, h: 26, rx: 3, text: o.text ? o.text(v, i) : hex(v), size: 13, cls: 'mono ' + (o.cls ? o.cls(i) : cls) }));
    return items;
  }
  const enc8 = (s) => Array.from(new TextEncoder().encode(s));
  S.topic({
    id: 'p01-two-time-pad', family: 'p01-pad', order: 20, title: 'The two-time pad and crib-dragging',
    blurb: 'Encrypt two messages with the same pad and XOR the ciphertexts: the pad cancels, leaving the two messages XORed together. Slide a likely word along it; where it fits, the other message shows through.',
    inputs: [
      { id: 'm1', kind: 'text', label: 'Message 1', def: 'meet me at the old boathouse', check: (v) => (v.length < 6 ? 'Message 1: at least 6 characters' : v.length > 28 ? 'Message 1: at most 28 characters' : /[^\x20-\x7e]/.test(v) ? 'Message 1: plain ASCII only' : null) },
      { id: 'm2', kind: 'text', label: 'Message 2', def: 'the tide turns before nine', check: (v) => (v.length < 6 ? 'Message 2: at least 6 characters' : v.length > 28 ? 'Message 2: at most 28 characters' : /[^\x20-\x7e]/.test(v) ? 'Message 2: plain ASCII only' : null) },
      { id: 'crib', kind: 'text', label: 'Crib (a guessed word, with spaces)', def: ' the ', check: (v, inp) => (v.length < 3 ? 'Crib: at least 3 characters' : v.length > Math.min(inp.m1.length, inp.m2.length) ? 'Crib: shorter than both messages' : null) },
      { id: 'seed', kind: 'number', label: 'Pad seed', def: 99, min: 1, max: 99999 },
    ],
    presets: [
      { label: 'Crib " the "', values: { m1: 'meet me at the old boathouse', m2: 'the tide turns before nine', crib: ' the ', seed: 99 } },
      { label: 'Crib " and "', values: { m1: 'bread and honey on friday', m2: 'rain by evening and a gale', crib: ' and ', seed: 5 } },
      { label: 'A crib that never fits', values: { m1: 'the ferry will not run', m2: 'cross by the new bridge', crib: 'zebra', seed: 12 } },
    ],
    run(inp) {
      const p1 = enc8(inp.m1), p2 = enc8(inp.m2), n = Math.min(p1.length, p2.length), pad = C().otp.bytePad(Math.max(p1.length, p2.length), C().rng(inp.seed));
      const c1 = Array.from(C().otp.bytes(Uint8Array.from(p1), pad).out), c2 = Array.from(C().otp.bytes(Uint8Array.from(p2), pad).out);
      const drag = C().otp.cribDrag(Uint8Array.from(c1), Uint8Array.from(c2), inp.crib), x = Array.from(drag.xor), crib = enc8(inp.crib), L = crib.length;
      const F = new S.Frames(['tried']);
      const top = (o) => { o = o || {}; let it = hexRow('c1', 'c₁ = m₁ ⊕ k', c1.slice(0, n), 0, 'p1-ct').concat(hexRow('c2', 'c₂ = m₂ ⊕ k', c2.slice(0, n), 32, 'p1-ct')); if (o.x) it = it.concat(hexRow('x', 'c₁ ⊕ c₂', x, 76, 'hot', { labelCls: 'hot', cls: (i) => (o.win && i >= o.win[0] && i < o.win[1] ? 'hot' : 'p1-key') })); return it; };
      const DY = 130, LY = 236;
      const dragRow = (p, res, good) => [P.text('d:l1', HX - 10, DY + 19, 'crib', 'tick', 13, 'end'), P.text('d:l2', HX - 10, DY + 51, 'x ⊕ crib', 'tick', 13, 'end')]
        .concat(crib.map((v, i) => ({ key: 'd:c' + i, kind: 'cell', x: HX + (p + i) * BW, y: DY, w: BW - 2, h: 26, rx: 3, text: show(v), size: 14, cls: 'mono p1-pl' })))
        .concat(Array.from(res, (ch, i) => ({ key: 'd:r' + i, kind: 'cell', x: HX + (p + i) * BW, y: DY + 32, w: BW - 2, h: 26, rx: 3, text: show(ch.charCodeAt(0)), size: 14, cls: 'mono ' + (good ? 'p1-good' : /[^a-zA-Z ]/.test(ch) ? 'p1-bad' : 'p1-ct') })));
      const list = (upto, best) => {
        const it = [P.title('t:t', 0, LY - 10, 'every position: x ⊕ crib, and the share of letters or spaces')];
        drag.rows.forEach((r, k) => {
          if (k > upto) return;
          const col = Math.floor(k / 8), row = k % 8, X = col * 250, Y = LY + row * 24;
          it.push(P.text('t:p' + k, X + 22, Y + 16, String(r.pos), 'tick', 13, 'end'));
          it.push(P.text('t:r' + k, X + 32, Y + 16, Array.from(r.text, (c) => show(c.charCodeAt(0))).join(''), 'mono' + (best === k ? ' good' : ''), 14));
          it.push({ key: 't:b' + k, kind: 'cell', x: X + 40 + L * 10, y: Y + 5, w: Math.max(2, 60 * r.printable), h: 13, rx: 2, text: '', cls: 'p1-bar ' + (best === k ? 'p1-best' : r.printable === 1 ? 'act' : '') });
        });
        return it;
      };
      F.add({ items: top(), say: `Two messages, ${p1.length} and ${p2.length} bytes, were encrypted with the same random pad: each byte XORed with a pad byte. Each ciphertext alone is a perfect one-time pad.`, meta: {} });
      const same = x.every((v, i) => v === (p1[i] ^ p2[i]));
      F.add({ items: top({ x: true }), say: `XOR the two ciphertexts: (m₁ ⊕ k) ⊕ (m₂ ⊕ k) = m₁ ⊕ m₂, since k ⊕ k = 0. The pad is gone${same ? ', and these bytes are exactly the two messages XORed together' : ''}: ${x.slice(0, 8).map(hex).join(' ')}…`, meta: {} });
      // fully readable positions, the most English-looking first; else the most printable one
      const sc = (t) => (P.letters(t).length >= 4 ? C().score(t, true) : -99);
      const cands = drag.rows.map((r, k) => k).filter((k) => drag.rows[k].printable === 1).sort((u, v) => sc(drag.rows[v].text) - sc(drag.rows[u].text) || u - v);
      const best = cands.length ? cands[0] : drag.rows.reduce((b, r, k) => (r.printable > drag.rows[b].printable ? k : b), 0);
      const shown = Math.min(drag.rows.length, 24);
      for (let k = 0; k < shown; k++) {
        const r = drag.rows[k];
        F.count('tried');
        F.add({ items: top({ x: true, win: [r.pos, r.pos + L] }).concat(dragRow(r.pos, r.text, false)).concat(list(k, -1)), say: `Position ${r.pos}: if message 1 has "${inp.crib}" here, message 2 has "${Array.from(r.text, (c) => show(c.charCodeAt(0))).join('')}" (${Math.round(100 * r.printable)}% letters or spaces).`, meta: { pos: r.pos }, slow: k > 3 });
      }
      const rb = drag.rows[best], realAt = inp.m1.indexOf(inp.crib), fits = rb.printable === 1;
      F.count('tried', drag.rows.length - shown);
      F.add({ items: top({ x: true, win: [rb.pos, rb.pos + L] }).concat(dragRow(rb.pos, rb.text, fits)).concat(list(Math.min(shown, drag.rows.length) - 1, best < shown ? best : -1)), say: fits ? (cands.length > 1 ? `Readable text appears at ${P.plural(cands.length, 'position')}: ${cands.map((k) => drag.rows[k].pos + ' ("' + drag.rows[k].text + '")').join(', ')}. Scored against English, "${rb.text}" reads best, so message 1 probably has "${inp.crib}" at ${rb.pos} and message 2 has "${rb.text}" there.` : `Only position ${rb.pos} gives readable text, "${rb.text}": message 1 probably has "${inp.crib}" there and message 2 has "${rb.text}".`) + ` ${realAt === rb.pos ? 'That is right.' : realAt >= 0 ? `(In fact message 1 has it at ${realAt}: a chance fit won, so every readable candidate needs checking.)` : '(Yet message 1 never contains the crib: the fit was luck, which is why guesses are extended and checked.)'} Each fragment suggests the next guess, and both messages unravel.` : `No position gives clean text: the best, at ${rb.pos}, is only ${Math.round(100 * rb.printable)}% letters or spaces. This crib is in neither message at the same place as readable text; try another likely word.`, meta: { end: true, best: rb.pos } });
      return { frames: F.list, def: P.def('Two-time pad', ['c₁ = m₁ ⊕ k,  c₂ = m₂ ⊕ k', 'c₁ ⊕ c₂ = m₁ ⊕ m₂   (k cancels)', 'guess w in m₁ at position p:', '  m₂[p…] = (c₁ ⊕ c₂)[p…] ⊕ w', 'readable text ⇒ the guess was right']), counters: [{ id: 'tried', label: 'positions tried' }] };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.end, pick: 'option', ask: 'At which position does the crib fit best?', options: (fr, i) => { const b = fr[i + 1].meta.best; return [...new Set([b, Math.max(0, b - 3), b + 2, b + 5])].sort((x, y) => x - y).map(String); }, answer: (fr, i) => String(fr[i + 1].meta.best), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why does XORing two ciphertexts under the same pad remove the pad?', options: ['Because the pad is short', 'Because k ⊕ k = 0', 'Because XOR is slow', 'It does not'], answer: 1, why: '(m₁ ⊕ k) ⊕ (m₂ ⊕ k) = m₁ ⊕ m₂.' },
      { q: 'What is a crib?', options: ['A random key', 'A word guessed to be in one of the messages', 'The pad', 'An error'], answer: 1, why: 'A likely word, like " the ", tried at every position.' },
      { q: 'How do you know a crib position is probably right?', options: ['The XOR is zero', 'The other message comes out as readable text there', 'The bytes are even', 'The position is a multiple of 8'], answer: 1, why: 'Wrong positions give mostly unprintable or odd characters.' },
      { q: 'What does the two-time pad teach about stream ciphers like CTR mode?', options: ['Nothing', 'Never reuse the same keystream (key and nonce) twice', 'Use shorter keys', 'Always use XOR twice'], answer: 1, why: 'Reusing a keystream is exactly a two-time pad.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
