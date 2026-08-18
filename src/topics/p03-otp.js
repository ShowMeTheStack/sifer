// Part 3, the one-time pad: perfect secrecy (one ciphertext, and for every plaintext of the same length exactly one
// key that explains it), and the two-time pad (the same pad used twice cancels out of c1 ⊕ c2, and a guessed word
// dragged along m1 ⊕ m2 makes the other message show through).
(function (S) {
  'use strict';
  const U = S.SymT, O = () => S.OTP;
  const ch = (b) => (b === 32 ? '␣' : b >= 33 && b < 127 ? String.fromCharCode(b) : '·');
  const q = (s) => '“' + s + '”';
  const printable = (label, min, max) => (v) => {
    const s = String(v);
    if (/[^\x20-\x7e]/.test(s)) return label + ': plain ASCII letters, digits, spaces and punctuation';
    if (s.length < min) return label + ': at least ' + min + ' characters';
    if (s.length > max) return label + ': at most ' + max + ' characters, so the picture stays readable';
    return null;
  };

  // ---------------------------------------------------------------------------------------------------------------
  // Perfect secrecy
  // ---------------------------------------------------------------------------------------------------------------
  function secrecy(inp) {
    const m = U.bytesOf(inp.message), n = m.length, key = S.Sym.bytes(S.Sym.rng(inp.seed), n);
    const enc = O().encrypt(m, key), c = enc.out;
    const decoys = inp.decoys.split('/').map((s) => s.trim()).filter(Boolean).map((s) => (s.length >= n ? s.slice(0, n) : s.padEnd(n, '.')));
    const cw = Math.min(110, Math.floor(776 / n) - 4), x0 = 116;
    const F = new S.Frames();
    const head = U.head('os:h', 'One ciphertext, every plaintext');
    const row = (prefix, y, bytes, cls, subs, label, lcls) => [
      U.t(prefix + ':lb', 24, y + 27, label, lcls || 'strong', 'start', 16),
      ...U.cells({ prefix: prefix + ':', x: x0, y, cw, ch: 38, gap: 4, values: Array.from(bytes), text: (v) => U.h2(v), size: cw >= 40 ? 16 : 14, cls: () => cls, sub: subs ? (v) => ch(v) : null }),
    ];
    const top = (stage, dim) => {
      const it = [];
      it.push(...row('om', 64, m, dim ? 'soft' : '', true, 'm', 'strong'));
      if (stage >= 1) it.push(...row('ok', 130, key, dim ? 'soft' : 'key', false, '⊕ k', 'key'));
      if (stage >= 2) it.push(...row('oc', 192, c, 'hot', false, '= c', 'hot'));
      return it;
    };
    const first = `${q(ch(m[0]))} ${U.h2(m[0])} ⊕ ${U.h2(key[0])} = ${U.h2(c[0])}`;
    F.add({ items: [head, ...top(0)], say: `The message ${q(inp.message)} is ${n} bytes, shown in hex with each character under its byte.`, facts: { n, m: U.hex(m) }, meta: { stage: 'msg' } });
    F.add({ items: [head, ...top(1)], hl: { d: [0] }, say: `The key is ${n} bytes from a fair source, ${U.hex(key)}: every one of the 256 values of each byte equally likely, and the key never used again.`, facts: { n, key: U.hex(key) }, meta: { stage: 'key' } });
    F.add({ items: [head, ...top(2)], hl: { d: [1] }, say: `Encryption is a byte-by-byte XOR, c = m ⊕ k: ${first}, and so on, giving the ciphertext ${U.hex(c)}.`, facts: { c: U.hex(c), m0: U.h2(m[0]), k0: U.h2(key[0]), c0: U.h2(c[0]) }, meta: { stage: 'cipher' } });
    const all = [{ text: inp.message, k: key, real: true }];
    decoys.forEach((d, j) => {
      const md = U.bytesOf(d), kd = O().keyFor(c, md);
      all.push({ text: d, k: kd, real: false });
      const items = [head, ...top(2, true),
        U.t('od:hd', 24, 284, 'another reading of the same c', 'title', 'start', 14),
        ...row('od:c', 300, c, 'hot', false, 'c', 'hot'),
        ...row('od:k', 362, kd, 'keyhot', false, '⊕ k′', 'key'),
        ...row('od:m', 424, md, 'act', true, '= m′', 'act'),
      ];
      F.add({ items, hl: { d: [2] }, say: `Could c have come from ${q(d)}? Yes: the key k′ = c ⊕ m′ = ${U.hex(kd)} turns it into exactly that. This key is as likely as the real one, so the ciphertext cannot favour either message.`, facts: { kd: U.hex(kd), d }, meta: { stage: 'decoy', j } });
    });
    // the summary: every candidate with its key
    const bits = 8 * n, rows = all.slice(0, 7);
    const sum = [head, ...top(2, true), ...U.panel('ot', 24, 270, 872, 70 + rows.length * 38, 'one key for each plaintext')];
    rows.forEach((r, i) => {
      const y = 330 + i * 38;
      sum.push(U.t('ot:m' + i, 44, y, q(r.text) + (r.real ? '   (the one sent)' : ''), r.real ? 'strong' : 'act', 'start', 16));
      sum.push(U.t('ot:k' + i, 876, y, 'k = ' + U.hex(r.k).slice(0, 2 * Math.min(n, 14)) + (n > 14 ? '…' : ''), r.real ? 'key' : 'mono', 'end', 15));
    });
    F.add({ items: sum, hl: { d: [3, 4] }, say: `Every ${n}-byte plaintext is reached from this ciphertext by exactly one of the 2^${bits} keys. With every key equally likely, seeing c leaves every message exactly as likely as before: Pr[m | c] = Pr[m]. That is perfect secrecy; the price is a truly random key as long as the message, used once.`, facts: { n, bits }, meta: { stage: 'end' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 610 });
    return { frames: F.list, def: U.def('The one-time pad', ['key k: n uniformly random bytes, used once', 'c = m ⊕ k,  m = c ⊕ k', 'for any m′ of length n: k′ = c ⊕ m′ gives c', 'Pr[m | c] = Pr[m]  (perfect secrecy)', 'needs |k| ≥ |m|: no shorter key can do it']) };
  }
  S.topic({
    id: 'st-otp-secrecy', family: 'p03-otp', order: 10, title: 'Perfect secrecy: the one-time pad',
    blurb: 'XOR the message with a random key as long as itself. Any other message of that length has its own key that produces the same ciphertext, equally likely, so the ciphertext says nothing.',
    inputs: [
      { id: 'message', kind: 'string', spaces: true, label: 'Message', def: 'meet me at dawn!', check: printable('Message', 3, 18) },
      { id: 'decoys', kind: 'text', label: 'Other plaintexts (split by /)', def: 'run away tonight / the fox is safe. / all clear, stay.', check: (v) => (String(v).split('/').map((s) => s.trim()).filter(Boolean).length < 1 ? 'Other plaintexts: at least one' : String(v).split('/').filter((s) => s.trim()).length > 5 ? 'Other plaintexts: at most five' : /[^\x20-\x7e]/.test(v) ? 'Other plaintexts: plain ASCII' : null) },
      { id: 'seed', kind: 'number', label: 'Key seed', def: 31, min: 1, max: 9999 },
    ],
    presets: [
      { label: 'A dawn meeting', values: { message: 'meet me at dawn!', decoys: 'run away tonight / the fox is safe. / all clear, stay.', seed: 31 } },
      { label: 'One word', values: { message: 'attack', decoys: 'retire / parley / ignore', seed: 5 } },
      { label: 'Buy or sell', values: { message: 'sell', decoys: 'hold / buy! / wait', seed: 808 } },
      { label: 'A decoy that is too short', values: { message: 'the vault is open', decoys: 'all quiet / the vault is shut', seed: 77 } },
    ],
    run: secrecy,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'cipher', once: true, pick: 'option', options: ['No: the ciphertext came from the real message', 'Yes, with exactly one key', 'Yes, with many keys', 'Only if the key were longer'], ask: 'Could this same ciphertext have come from a different message of the same length?', answer: 'Yes, with exactly one key', explain: 'k′ = c ⊕ m′ is the one key that does it, and it is as likely as any other key.' }],
    quiz: [
      { q: 'A one-time pad ciphertext is 12 bytes long. What does it tell an attacker with unlimited computing power?', options: ['The first byte', 'Only the length of the message', 'Half the bits', 'Nothing until enough ciphertext is collected'], answer: 1, why: 'Every 12-byte plaintext is explained by exactly one equally likely key.' },
      { q: 'How many keys turn a given n-byte ciphertext into a given n-byte plaintext?', options: ['None', 'Exactly one', '256', '2^(8n)'], answer: 1, why: 'k = c ⊕ m is fixed by c and m.' },
      { q: 'Which of these breaks perfect secrecy?', options: ['A key chosen uniformly at random', 'A key as long as the message', 'Using the same key for two messages', 'Encrypting with XOR'], answer: 2, why: 'A second use lets the key cancel: c₁ ⊕ c₂ = m₁ ⊕ m₂.' },
      { q: 'Why is the one-time pad rarely used?', options: ['It is slow', 'It can be broken by brute force', 'The key must be truly random, as long as all the traffic, and shared in advance', 'XOR is not invertible'], answer: 2, why: 'Distributing and never reusing that much key is the hard part.' },
      { q: 'Perfect secrecy means…', options: ['Pr[m | c] = Pr[m] for every m and c', 'No attacker can find the key in polynomial time', 'The ciphertext looks random', 'The key is longer than the message'], answer: 0, why: 'The ciphertext changes no probability about the message.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The two-time pad and crib dragging
  // ---------------------------------------------------------------------------------------------------------------
  function twoTime(inp) {
    const o = O().setup({ seed: inp.seed }), n = o.m1.length, x = o.c1.map((v, i) => v ^ o.c2[i]);
    const crib = U.bytesOf(inp.crib), cr = O().crib(x, crib), L = crib.length;
    const Wn = 18, cw = 42, gap = 3, x0 = 104;
    const xOf = (i, s) => x0 + (i - s) * (cw + gap);
    const F = new S.Frames(), head = U.head('tt:h', 'One pad, two messages');
    const cellRow = (prefix, y, bytes, s, cls, txt, label, lcls) => {
      const items = [U.t(prefix + ':lb', 24, y + 26, label, lcls || 'strong', 'start', 15)];
      for (let i = s; i < Math.min(n, s + Wn); i++) if (bytes[i] !== undefined) items.push({ key: prefix + ':' + i, kind: 'cell', x: xOf(i, s), y, w: cw, h: 36, rx: 3, text: txt ? txt(bytes[i], i) : U.h2(bytes[i]), size: 16, cls: 'hex ' + (cls ? cls(i, bytes[i]) || '' : '') });
      return items;
    };
    const idx = (s) => { const it = []; for (let i = s; i < Math.min(n, s + Wn); i++) if (i % 5 === 0) it.push(U.t('tt:ix' + i, xOf(i, s) + cw / 2, 60, String(i), 'tick', 'middle', 13)); return it; };
    const upper = (s, xcls) => [...idx(s), ...cellRow('tc1', 70, o.c1, s, null, null, 'c₁'), ...cellRow('tc2', 120, o.c2, s, null, null, 'c₂'), ...cellRow('tx', 184, x, s, xcls || (() => 'hot'), null, 'c₁⊕c₂', 'hot')];
    const winFor = (pos) => Math.max(0, Math.min(n - Wn, pos - Math.floor((Wn - L) / 2)));
    // frame: the two ciphertexts
    F.add({ items: [head, ...upper(0, () => 'soft').filter((it) => !String(it.key).startsWith('tx'))], say: `Two messages of ${n} bytes were encrypted with the same pad. Each ciphertext alone is perfectly hidden: c₁ begins ${U.hexs(o.c1.slice(0, 4))} and c₂ begins ${U.hexs(o.c2.slice(0, 4))}.`, facts: { n, c1: U.hexs(o.c1.slice(0, 4)), c2: U.hexs(o.c2.slice(0, 4)) }, meta: { stage: 'two' } });
    F.add({ items: [head, ...upper(0)], hl: { d: [0] }, say: `XOR them: c₁ ⊕ c₂ = (m₁ ⊕ k) ⊕ (m₂ ⊕ k) = m₁ ⊕ m₂, because k ⊕ k = 0. The pad is gone; at byte 0, ${U.h2(o.c1[0])} ⊕ ${U.h2(o.c2[0])} = ${U.h2(x[0])}, which is m₁[0] ⊕ m₂[0].`, facts: { a: U.h2(o.c1[0]), b: U.h2(o.c2[0]), x0: U.h2(x[0]) }, meta: { stage: 'xor' } });
    const sp = Array.from(x).filter((v) => v >= 0x40).length, spWin = Array.from(x.slice(0, Wn)).filter((v) => v >= 0x40).length;
    F.add({ items: [head, ...upper(0, (i, v) => (v >= 0x40 ? 'act' : '')), U.t('tt:sp', 104, 250, 'lit: 40 or more, so one of the two bytes is probably a space', 'act', 'start', 15)], hl: { d: [1] }, say: `Two letters XOR to a byte below 40 (hex); a letter and a space XOR to 40 or more, the letter with its case flipped. So the ${sp} lit bytes (${spWin} in view) mark places where one message has a space: the structure of English shows through.`, facts: { sp, spWin, h: '40' }, meta: { stage: 'space' } });
    // crib dragging: the first three places, then the most readable ones
    const tried = [];
    const order = [0, 1, 2].filter((p) => p + L <= n).map((p) => cr.rows[p]);
    for (const b of cr.best.slice(0, 3)) if (!order.includes(b)) order.push(b);
    const table = () => {
      const items = [...U.panel('tt:tb', 24, 384, 872, 54 + 6 * 30, 'placements tried')];
      items.push(U.t('tt:th0', 44, 432, 'position', 'tick', 'start', 13), U.t('tt:th1', 160, 432, 'crib ⊕ (c₁ ⊕ c₂)', 'tick', 'start', 13), U.t('tt:th2', 876, 432, 'readable?', 'tick', 'end', 13));
      tried.slice(-5).forEach((r, k) => {
        const y = 466 + k * 30;
        items.push(U.t('tt:tp' + r.pos, 44, y, String(r.pos), 'mono', 'start', 15), U.t('tt:to' + r.pos, 160, y, q(r.other), r.plausible ? 'good' : 'mono', 'start', 15), U.t('tt:tr' + r.pos, 876, y, r.plausible ? 'yes' : 'no', r.plausible ? 'good' : 'tick', 'end', 15));
      });
      return items;
    };
    order.forEach((r, k) => {
      tried.push(r);
      const s = winFor(r.pos), other = crib.map((v, j) => v ^ x[r.pos + j]);
      const items = [head, ...upper(s, (i) => (i >= r.pos && i < r.pos + L ? 'hot' : 'soft')),
        ...cellRow('tcr', 254, Object.fromEntries(Array.from(crib, (v, j) => [r.pos + j, v])), s, () => 'key', (v) => ch(v), 'crib', 'key'),
        ...cellRow('tot', 306, Object.fromEntries(Array.from(other, (v, j) => [r.pos + j, v])), s, () => (r.plausible ? 'good' : 'bad'), (v) => ch(v), '= ?', r.plausible ? 'good' : 'bad'),
        ...table()];
      const say = k === 0 ? `Guess a word one message may contain, the crib ${q(inp.crib)}, and XOR it into c₁ ⊕ c₂ at position ${r.pos}: if the guess is right there, what comes out is the other message. Here it gives ${q(r.other)}: ${r.plausible ? 'it reads like text' : 'not text, so the crib is not here'}.`
        : k < 3 && order.length > 3 ? `Slide the crib to position ${r.pos}: ${q(r.other)}, ${r.plausible ? 'readable' : 'nonsense'}.`
          : `Position ${r.pos}: ${q(r.other)}${r.plausible ? ', which reads like English: a likely hit' : ''}.` + (k === order.length - 1 ? ` Every readable placement is a foothold; extend it a letter at a time from both sides.` : '');
      F.add({ items, hl: { d: [2] }, say, facts: { pos: r.pos, other: r.other, k }, meta: { stage: 'crib', pos: r.pos, plausible: r.plausible } });
    });
    // the reveal
    const best = cr.best[0], t = (a) => String.fromCharCode(...a);
    const pos = best ? best.pos : 0, s = winFor(pos);
    const in1 = !!best && t(o.m1.slice(pos, pos + L)) === inp.crib, in2 = !!best && t(o.m2.slice(pos, pos + L)) === inp.crib;
    const mark = (i) => (best && i >= pos && i < pos + L ? 'good' : '');
    F.add({ items: [head, ...upper(s, () => 'soft'), ...cellRow('tm1', 254, o.m1, s, (i) => mark(i), (v) => ch(v), 'm₁', 'act'), ...cellRow('tm2', 306, o.m2, s, (i) => mark(i), (v) => ch(v), 'm₂', 'act'), ...table()],
      say: best ? `The messages, for checking: at position ${pos} ${in1 ? `m₁ holds the crib and m₂ reads ${q(t(o.m2.slice(pos, pos + L)))}` : in2 ? `m₂ holds the crib and m₁ reads ${q(t(o.m1.slice(pos, pos + L)))}` : `neither message holds the crib; the readable text there was a coincidence`}. Reusing a pad once is enough to expose both messages.`
        : `No placement of ${q(inp.crib)} gave readable text, so neither message contains it; another guess is needed. The messages were ${q(t(o.m1.slice(0, 24)))}… and ${q(t(o.m2.slice(0, 24)))}…`,
      facts: { pos, in1, in2 }, meta: { stage: 'reveal' } });
    U.fix(F.list, { x: 0, y: 0, w: 920, h: 640 });
    return { frames: F.list, def: U.def('The two-time pad', ['c₁ = m₁ ⊕ k,  c₂ = m₂ ⊕ k', 'c₁ ⊕ c₂ = m₁ ⊕ m₂: the pad cancels', 'letter ⊕ space = the letter in the other case', 'crib w at position i: w ⊕ (c₁ ⊕ c₂)[i…] = the other message there', 'with m₁ known, k = c₁ ⊕ m₁ opens every message under k']) };
  }
  S.topic({
    id: 'st-two-time', family: 'p03-otp', order: 20, title: 'The two-time pad and crib dragging',
    blurb: 'Use the pad twice and it cancels: c₁ ⊕ c₂ = m₁ ⊕ m₂. Slide a guessed word along that and, where the guess is right, the other message appears.',
    inputs: [
      { id: 'seed', kind: 'number', label: 'Message pair', def: 7, min: 1, max: 999 },
      { id: 'crib', kind: 'string', spaces: true, label: 'Crib (a guessed word)', def: 'harbour', check: printable('Crib', 2, 10) },
    ],
    presets: [
      { label: 'Guess “harbour”', values: { seed: 7, crib: 'harbour' } },
      { label: 'Guess “ the ”', values: { seed: 3, crib: ' the ' } },
      { label: 'Guess “ the ” (another pair)', values: { seed: 4, crib: ' the ' } },
      { label: 'A word in neither', values: { seed: 1, crib: 'harbour' } },
    ],
    run: twoTime,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'two', once: true, pick: 'option', options: ['m₁ ⊕ m₂', 'the pad k', 'all zeros', 'random-looking bytes with no structure'], ask: 'What is c₁ ⊕ c₂ when both used the same pad?', answer: 'm₁ ⊕ m₂', explain: 'The two copies of k cancel: k ⊕ k = 0.' }],
    quiz: [
      { q: 'Two ciphertexts used the same pad. What does c₁ ⊕ c₂ equal?', options: ['k', 'm₁ ⊕ m₂', 'm₁ ⊕ m₂ ⊕ k', '0'], answer: 1, why: 'The pad appears twice and cancels.' },
      { q: 'In crib dragging, a guessed word w is XORed into c₁ ⊕ c₂ at position i. If w really is in m₁ at i, the result is…', options: ['the key', 'the text of m₂ at i', 'zeros', 'w again'], answer: 1, why: 'w ⊕ m₁ ⊕ m₂ = m₂ where w = m₁.' },
      { q: 'Why does a byte of c₁ ⊕ c₂ of 40 (hex) or more hint at a space?', options: ['Spaces are 40 in ASCII', 'A space (20) XOR a letter (40–7f) lands at 40 or more; two letters XOR below 40', 'Because the pad is biased', 'It does not'], answer: 1, why: 'Letters share their top bits; a space flips bit 5 and clears bit 6.' },
      { q: 'Once one message under a reused pad is fully recovered, what else falls?', options: ['Nothing', 'Only that message', 'The pad bytes it covered, and so every message encrypted under them', 'Only the next message'], answer: 2, why: 'k = c ⊕ m for the recovered message opens the others.' },
      { q: 'Which real failure is a two-time pad?', options: ['Reusing a stream cipher key and nonce', 'Using AES with a 128-bit key', 'Signing twice', 'Hashing a password'], answer: 0, why: 'The same key and nonce give the same keystream.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
