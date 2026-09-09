// Part 12, weaknesses of the Merkle–Damgård structure itself: Joux's multicollisions on a truncated toy hash (t block
// collisions in a row give 2^t messages with one digest), and why a secret-prefix MAC can be length-extended (the tag
// is the hash's whole state), with HMAC and SHA-3 shown resisting.
(function (S) {
  'use strict';
  const U = S.P12, H = () => S.Hash;
  const { t } = U;

  // ---------------------------------------------------------------------------------------------------------------
  // Joux multicollisions
  // ---------------------------------------------------------------------------------------------------------------
  function joux(inp) {
    const Hs = H(), bits = +inp.bits, T = +inp.t, seed = +inp.seed;
    const J = Hs.joux({ bits, t: T, seed }), hx = (v) => Hs.truncHex(v, bits), st = J.stages, toy = J.toy;
    const step = Math.min(200, 760 / T), x0 = 70, cy = 210;
    const nodeX = (s) => U.r2(x0 + s * step);
    const graph = (done, cur) => {
      const items = [];
      for (let s = 0; s <= T; s++) {
        const v = s === 0 ? st[0].cvIn : st[s - 1].cvOut, on = s <= done;
        items.push({ key: 'jx:n' + s, kind: 'state', x: nodeX(s), y: cy, r: 28, text: on ? hx(v) : '?', size: 13, cls: 'mono ' + (s === done && cur ? 'hot' : on ? 'act' : '') });
        items.push(t('jx:nl' + s, nodeX(s), cy + 50, s === 0 ? 'IV' : 'CV' + U.sub(s), 'ptick', 'middle', 13));
      }
      for (let s = 0; s < done; s++) {
        const lit = s === done - 1 && cur;
        for (const [j, bend, blk, ly] of [[0, -46, st[s].b0, cy - 46], [1, 46, st[s].b1, cy + 46]]) {
          items.push({ key: 'jx:e' + s + j, kind: 'edge', from: 'jx:n' + s, to: 'jx:n' + (s + 1), bend, cls: lit ? 'act' : '', audit: 'ignore' });
          items.push(t('jx:el' + s + j, (nodeX(s) + nodeX(s + 1)) / 2, ly + (j ? 24 : -14), U.hex(blk).slice(0, 8) + '…', 'mono ' + (lit ? 'act' : ''), 'middle', 13));
        }
      }
      return items;
    };
    const msgs = J.messages(16), dg = J.digest;
    const list = (upto) => {
      const items = [t('jx:lt', 30, 336, 'messages: one choice of block per stage (0 = upper, 1 = lower)', 'ptitle')];
      msgs.slice(0, upto).forEach((m, k) => {
        const col = Math.floor(k / 8), row = k % 8, code = k.toString(2).padStart(T, '0');
        items.push({ key: 'jx:m' + k, kind: 'cell', x: 30 + col * 440, y: 350 + row * 30, w: 300, h: 25, rx: 4, text: code + '  ' + U.hex(m).slice(0, 24) + '…', size: 13, cls: 'mono' });
        items.push({ key: 'jx:d' + k, kind: 'cell', x: 336 + col * 440, y: 350 + row * 30, w: 70, h: 25, rx: 4, text: hx(toy.hashValue(m)), size: 13, cls: 'hex hot' });
      });
      return items;
    };
    const head = U.head('jx:h', 'Joux multicollisions on a ' + bits + '-bit Merkle–Damgård hash', toy.blockLen + '-byte blocks; each stage is a birthday search from the chaining value the last one left');
    const F = new S.Frames(['stages', 'work']);
    F.add({ items: [...head, ...graph(0, false)], hl: { d: [0] }, say: `A toy hash with a ${bits}-bit chaining value. One block collision costs about 2${U.sup(bits / 2)} compressions. Find one from the IV ${hx(st[0].cvIn)}, then another from wherever that leads, ${T} times in a row.`, facts: { bits, half: bits / 2, iv: hx(st[0].cvIn), T }, meta: { stage: 'start' } });
    let work = 0;
    st.forEach((s, i) => {
      work += s.tries;
      F.count('stages').set('work', work);
      F.add({ items: [...head, ...graph(i + 1, true)], hl: { d: [1] }, say: `Stage ${i + 1}: from ${hx(s.cvIn)}, the blocks ${U.hex(s.b0)} and ${U.hex(s.b1)} both lead to ${hx(s.cvOut)}, found after ${s.tries} tries. Now there are ${2 ** (i + 1)} ways to reach ${hx(s.cvOut)}.`, facts: { i: i + 1, cvIn: hx(s.cvIn), cvOut: hx(s.cvOut), b0: U.hex(s.b0), b1: U.hex(s.b1), tries: s.tries, ways: 2 ** (i + 1) }, meta: { stage: 'stage', i } });
    });
    const shown = Math.min(16, 2 ** T);
    F.add({ items: [...head, ...graph(T, false), ...list(shown)], hl: { d: [2] }, say: `Choosing the upper or lower block at each stage gives ${2 ** T} different ${T * toy.blockLen}-byte messages${2 ** T > shown ? ` (${shown} shown)` : ''}. All end at ${hx(st[T - 1].cvOut)}, and as they have the same length, the same length block follows: every one hashes to ${hx(dg)}.`, facts: { n: 2 ** T, len: T * toy.blockLen, cv: hx(st[T - 1].cvOut), dg: hx(dg), shown }, meta: { stage: 'list' } });
    const ideal = Math.round(2 ** ((bits * (2 ** T - 1)) / 2 ** T));
    F.add({ items: [...head, ...graph(T, false), ...list(shown), t('jx:c1', 30, 628, 'compressions used: ' + U.commas(J.work), 'hot', 'start', 15), t('jx:c2', 340, 628, 'an ideal ' + 2 ** T + '-way collision: about ' + U.commas(ideal), 'strong', 'start', 15)], hl: { d: [3] }, say: `Work: ${U.commas(J.work)} compressions, ${T} times one collision. In an ideal ${bits}-bit hash ${U.an(2 ** T + '-way')} collision should cost about ${U.commas(ideal)}. So iterated hashes give multicollisions almost for free, and concatenating two of them, H₁(m) ‖ H₂(m), is barely stronger than the better one.`, facts: { work: J.work, ideal, bits, n: 2 ** T, T }, meta: { stage: 'cost' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Joux\'s multicollision', ['CV₀ = IV', 'stage i: find blocks Bᵢ ≠ B′ᵢ with f(CVᵢ₋₁, Bᵢ) = f(CVᵢ₋₁, B′ᵢ) = CVᵢ', 'any choice of B or B′ at each stage reaches CVₜ', 't stages: 2ᵗ messages, one digest', 'cost: t · 2ⁿᐟ², not 2^(n(2ᵗ−1)/2ᵗ)']) };
  }
  S.topic({
    id: 'p12-joux', family: 'p12-attacks', order: 30, title: 'Attack lab: Joux multicollisions',
    blurb: 'In a Merkle–Damgård hash, collisions compose: t block collisions in a row give 2ᵗ messages with the same digest for t times the work of one. Built for real on a toy hash with a 16-bit chaining value.',
    inputs: [
      { id: 't', kind: 'number', label: 'Stages', def: 3, min: 2, max: 5 },
      { id: 'bits', kind: 'choice', label: 'Chaining value', def: '16', options: [{ value: '12', label: '12 bits' }, { value: '16', label: '16 bits' }, { value: '20', label: '20 bits' }] },
      { id: 'seed', kind: 'number', label: 'Seed', def: 1, min: 1, max: 999 },
    ],
    presets: [
      { label: '3 stages, 8 messages', values: { t: 3, bits: '16', seed: 1 } },
      { label: '4 stages, 16 messages', values: { t: 4, bits: '16', seed: 2 } },
      { label: '5 stages, 12-bit', values: { t: 5, bits: '12', seed: 3 } },
      { label: '2 stages, 20-bit', values: { t: 2, bits: '20', seed: 4 } },
    ],
    counters: [{ id: 'stages', label: 'stages' }, { id: 'work', label: 'compressions' }],
    run: joux,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'start', pick: 'option', options: (fr, i, inp) => [String(+inp.t), String(2 * +inp.t), String(2 ** +inp.t)], ask: 'With this many stages, how many colliding messages will there be?', answer: (fr, i, inp) => String(2 ** +inp.t), explain: 'Two choices at each stage: 2ᵗ messages.' }],
    quiz: [
      { q: 'Why do the 2ᵗ messages have the same digest?', options: ['they are equal', 'every path reaches the same chaining value, and they have the same length', 'the hash is broken', 'luck'], answer: 1, why: 'The final chaining value and the length block are the same for all.' },
      { q: 'Each stage costs about…', options: ['2ⁿ', '2ⁿᐟ²', 'n', '2ᵗ'], answer: 1, why: 'One birthday search on the chaining value.' },
      { q: 'What does Joux\'s result say about H₁(m) ‖ H₂(m)?', options: ['it has twice the security', 'it is barely stronger than the stronger of the two', 'it is weaker than either', 'it is a MAC'], answer: 1, why: 'Make 2^(n/2) multicollisions of H₁, then among them find a birthday collision of H₂.' },
      { q: 'Does the sponge construction of SHA-3 suffer the same way?', options: ['exactly the same', 'it is also iterated, but with a 1600-bit state the internal collisions cost 2^(c/2)', 'it is immune to all collisions', 'it has no state'], answer: 1, why: 'Internal collisions need the capacity to collide, about 2^(c/2) work.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // length extension
  // ---------------------------------------------------------------------------------------------------------------
  const NAMES = { sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5' };
  function lenext(inp) {
    const Hs = H(), A = Hs.get(inp.hash), name = NAMES[inp.hash], B = A.blockLen;
    const secret = U.utf8(inp.secret), msg = U.utf8(inp.msg), ext = U.utf8(inp.ext);
    const res = Hs.lengthExtension({ hash: inp.hash, secret: inp.secret, msg: inp.msg, ext: inp.ext, secretLen: secret.length });
    const L = secret.length + msg.length, glue = res.glue, tag = U.hex(res.original);
    const newPad = A.glue(L + glue.length + ext.length).length, total = L + glue.length + ext.length + newPad;
    const scale = 840 / total, X0 = 30;
    // a bar of segments [[label, bytes, cls]] starting `off` bytes in; labels that do not fit go underneath
    const bar = (pre, off, y, segs, title) => {
      const items = [t(pre + ':t', X0, y - 10, title, 'ptitle')];
      let at = X0 + off * scale, below = 0;
      segs.forEach(([lab, n, cls], k) => {
        const w = U.r2(n * scale - 2), fits = S.geom.textWidth(lab, 12, { mono: true }) + 12 <= w;
        items.push({ key: pre + ':s' + k, kind: 'cell', x: U.r2(at), y, w, h: 30, rx: 4, text: fits ? lab : '', size: 13, cls: 'hex ' + cls });
        if (!fits && lab) { items.push(t(pre + ':sl' + k, at + w / 2, y + 46 + 16 * below, lab, 'ptick', 'middle', 13)); below++; }
        at += n * scale;
      });
      return items;
    };
    const ticks = () => { const items = []; for (let b = B; b < total; b += B) items.push({ key: 'le:bt' + b, kind: 'path', d: `M${U.r2(X0 + b * scale)},102 V148`, cls: 'p12-line faint', audit: 'ignore' }); return items; };
    const head = U.head('le:h', 'Length extension on ' + name + '(secret ‖ message)', 'the server tags messages with a hash of a secret it keeps, followed by the message');
    const F = new S.Frames(['blocks']);
    const server = (lit) => [...ticks(), ...bar('le:sv', 0, 110, [['secret, ' + secret.length + ' B', secret.length, 'key'], ['“' + U.cut(inp.msg, 22) + '”', msg.length, 'pm'], ['glue ' + glue.length + ' B', glue.length, lit ? 'hot' : 'p00']], 'what the server hashed: ' + (L + glue.length) + ' bytes, ' + U.plural((L + glue.length) / B, 'block')), t('le:tag', 30, 196, 'tag = ' + tag, 'mono key', 'start', 14)];
    // the outcome only: a longer message, carrying the original and the appended text, gets a tag the server accepts
    const outcome = () => [...U.panel('le:oc', 30, 236, 860, 150, 'what anyone holding the tag can do, without the secret'),
      t('le:o1', 46, 288, 'a longer message: “' + U.cut(inp.msg, 22) + '” … “' + U.cut(inp.ext, 22) + '”', 'mono hot', 'start', 14),
      t('le:o2', 46, 318, res.ok ? 'with a tag the server accepts ✓' : 'with a tag the server rejects', res.ok ? 'bad' : 'good', 'start', 14),
      t('le:o3', 46, 348, 'the server never tagged it, and the secret was never needed', 'ptick', 'start', 13)];
    const base = { L, sl: secret.length, ml: msg.length, gl: glue.length, el: ext.length, B };
    F.add({ items: [...head, ...server(false)], hl: { d: [0] }, say: `The server's tag for “${inp.msg}” is ${name}(secret ‖ message) = ${U.short(tag, 8)}. It will accept any message whose tag matches, believing only the secret's holder could make one.`, facts: Object.assign({ tag }, base), meta: { stage: 'server' } });
    F.set('blocks', (L + glue.length) / B);
    F.add({ items: [...head, ...server(true)], hl: { d: [1] }, say: `Before hashing, ${name} padded the ${L} bytes of secret ‖ message with ${glue.length} bytes of glue: 80, zeros and the length ${L * 8} bits. The tag is the chaining value after exactly ${(L + glue.length) / B === 1 ? 'that block' : 'those ' + (L + glue.length) / B + ' blocks'}: the hash's whole internal state, handed out in public.`, facts: Object.assign({ bits: L * 8, nb: (L + glue.length) / B }, base), meta: { stage: 'glue' } });
    F.add({ items: [...head, ...server(true), ...outcome()], hl: { d: [2] }, say: `Because the tag is the complete state, anyone holding it can carry on hashing where the server stopped. The outcome: a valid tag for a longer message that starts with “${inp.msg}” and ends with “${inp.ext}”, a message the server never tagged, made without the secret.${res.ok ? '' : ' (Here it failed: something is wrong.)'}`, facts: Object.assign({ ok: res.ok }, base), meta: { stage: 'outcome' } });
    // HMAC and SHA-3 against the same trick
    const hmacTag = S.MAC.hmac(inp.hash, secret, msg);
    const tried = Hs.lengthExtend({ hash: inp.hash, tag: hmacTag, msg, ext, secretLen: B + secret.length });
    const hmacReal = S.MAC.hmac(inp.hash, secret, tried.forged), hmacOk = U.hex(hmacReal) === U.hex(tried.tag);
    const s3 = Hs.get('sha3-256').hash(U.utf8(inp.secret + inp.msg));
    const resist = [...U.panel('le:rs', 30, 410, 860, 200, 'the same trick against'),
      t('le:r1', 46, 462, 'HMAC-' + name, 'strong', 'start', 15), t('le:r1b', 230, 462, 'forged tag ' + U.short(tried.tag, 8) + ' ≠ real ' + U.short(hmacReal, 8), 'mono ' + (hmacOk ? 'hot' : 'bad'), 'start', 14),
      t('le:r1c', 230, 488, 'the outer hash takes the inner digest as a message: extending it gives nothing valid', 'ptick', 'start', 13),
      t('le:r2', 46, 540, 'SHA3-256', 'strong', 'start', 15), t('le:r2b', 230, 540, 'tag ' + U.short(s3, 8) + ' is 32 of the 200 state bytes', 'mono good', 'start', 14),
      t('le:r2c', 230, 566, 'the 64-byte capacity is never output, so no one can resume the sponge', 'ptick', 'start', 13)];
    F.add({ items: [...head, ...server(true), ...outcome(), ...resist], hl: { d: [3] }, say: `The same trick on HMAC-${name}: extending its tag gives ${U.short(tried.tag, 8)}, but the true HMAC of the longer message is ${U.short(hmacReal, 8)}: ${hmacOk ? 'accepted' : 'rejected'}. And SHA3-256(secret ‖ message) = ${U.short(s3, 8)} reveals only 32 of 200 state bytes, so it cannot be resumed at all.`, facts: { t1: U.hex(tried.tag), t2: U.hex(hmacReal), s3: U.hex(s3) }, meta: { stage: 'resist' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Length extension', ['tag = H(secret ‖ m) is the chaining value after pad(secret ‖ m)', 'so the tag is the hash\'s whole internal state', 'whoever holds it can tag longer messages: never use H(secret ‖ m) as a MAC', 'fix: HMAC, or a hash that hides its state (SHA-3, SHA-512/256, KMAC)']) };
  }
  S.topic({
    id: 'p12-lenext', family: 'p12-attacks', order: 40, title: 'Length extension, and why HMAC and SHA-3 resist',
    blurb: 'A tag made as H(secret ‖ message) with a Merkle–Damgård hash is the hash\'s final state. Anyone holding it can carry on hashing, so a longer message gets a valid tag without the secret. Why that is, and why HMAC\'s outer hash and SHA-3\'s hidden capacity stop it.',
    inputs: [
      { id: 'hash', kind: 'choice', label: 'Hash', def: 'sha256', options: [{ value: 'sha256', label: 'SHA-256' }, { value: 'sha1', label: 'SHA-1' }, { value: 'md5', label: 'MD5' }] },
      { id: 'secret', kind: 'text', label: 'Server\'s secret', def: 'tidewater-7', check: (v) => (!v.length || v.length > 32 ? 'Secret: 1 to 32 characters' : null) },
      { id: 'msg', kind: 'text', label: 'Tagged message', def: 'user=wren&role=reader', check: (v) => (v.length > 60 ? 'Message: at most 60 characters' : null) },
      { id: 'ext', kind: 'text', label: 'Text to append', def: '&role=admin', check: (v) => (!v.length || v.length > 40 ? 'Text to append: 1 to 40 characters' : null) },
    ],
    presets: [
      { label: 'SHA-256, role=admin', values: { hash: 'sha256', secret: 'tidewater-7', msg: 'user=wren&role=reader', ext: '&role=admin' } },
      { label: 'A short secret', values: { hash: 'sha256', secret: 'k3y', msg: 'amount=10&to=wren', ext: '&to=mallory' } },
      { label: 'SHA-1', values: { hash: 'sha1', secret: 'a quiet shared key', msg: 'file=report.pdf', ext: '&file=passwd' } },
      { label: 'MD5', values: { hash: 'md5', secret: 'x9', msg: 'vote=yes', ext: ';vote=no' } },
    ],
    counters: [{ id: 'blocks', label: 'blocks the tag sums up' }],
    run: lenext,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'glue', pick: 'option', options: ['yes', 'no'], ask: 'The tag is the hash\'s whole state after these blocks. Could someone without the secret make a valid tag for a longer message?', answer: 'yes', explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'What makes H(secret ‖ message) extendable?', options: ['a short secret', 'the tag is the Merkle–Damgård hash\'s whole final state, so hashing can resume from it', 'the message is public', 'SHA-256 has collisions'], answer: 1, why: 'Nothing is hidden after the last compression: the tag is everything needed to keep going.' },
      { q: 'Why does HMAC resist length extension?', options: ['it uses a longer key', 'its tag is an outer hash of the inner digest, so the tag is not a resumable state of the message hash', 'it is slower', 'it uses SHA-3'], answer: 1, why: 'Extending the outer hash only appends to the inner digest, which the verifier recomputes from scratch.' },
      { q: 'Which of these is not vulnerable to length extension?', options: ['SHA-256(k ‖ m)', 'SHA-1(k ‖ m)', 'SHA3-256(k ‖ m)', 'MD5(k ‖ m)'], answer: 2, why: 'The sponge never outputs its capacity.' },
      { q: 'A system needs a keyed tag from SHA-256. What should it use?', options: ['SHA-256(key ‖ message)', 'HMAC-SHA-256(key, message)', 'SHA-256(message) with the key kept secret', 'SHA-256(message ‖ key ‖ message)'], answer: 1, why: 'HMAC is built for this and its tag is not a resumable state; or use a hash that hides its state, such as SHA-3 in KMAC.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
