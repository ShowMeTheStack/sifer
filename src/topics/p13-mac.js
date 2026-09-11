// Part 13, MACs: the forgery game a MAC must win (against a good MAC, a short tag, a keyless hash, a secret-prefix
// hash and a leaky tag comparison), and HMAC opened up: the padded key XORed with ipad and opad, and two nested hashes.
(function (S) {
  'use strict';
  const U = S.P12, H = () => S.Hash, Mc = () => S.MAC;
  const { t } = U;

  // ---------------------------------------------------------------------------------------------------------------
  // the forgery game
  // ---------------------------------------------------------------------------------------------------------------
  const GAMES = {
    hmac: 'HMAC-SHA256, full tag', trunc: 'HMAC-SHA256 cut to 8 bits', keyless: 'SHA-256(m), no key', prefix: 'SHA-256(key ‖ m)', leaky: 'HMAC, compared byte by byte',
  };
  function game(inp) {
    const Hs = H(), M = Mc(), g = inp.mac, key = U.utf8(inp.key), sha = (m) => Hs.get('sha256').hash(U.utf8(m));
    const tagOf = (m) => (g === 'keyless' ? sha(m) : g === 'prefix' ? Hs.secretPrefixMac('sha256', key, U.utf8(m)) : g === 'trunc' ? M.hmac('sha256', key, m).slice(0, 1) : M.hmac('sha256', key, m));
    const asked = ['amount=20&to=wren', 'amount=35&to=ash', 'amount=50&to=wren'], target = 'amount=9000&to=mallory';
    const log = [];
    for (const m of asked) log.push({ kind: 'tag?', m, tag: U.hex(tagOf(m)), ok: null });
    let win = null, queries = 0, detail = '';
    if (g === 'hmac') {
      const guess = sha('a guess'); queries = 1;
      log.push({ kind: 'verify?', m: target, tag: U.hex(guess), ok: U.hex(guess) === U.hex(tagOf(target)) });
      const reuse = log[0].tag; queries++;
      log.push({ kind: 'verify?', m: target, tag: reuse, ok: reuse === U.hex(tagOf(target)) });
      detail = 'a guess, then a tag of another message: both rejected';
    } else if (g === 'trunc') {
      const want = tagOf(target)[0];
      for (let v = 0; v < 256; v++) { queries++; if (v === want) { win = { tag: U.h2(v), tries: queries }; break; } }
      log.push({ kind: 'verify?', m: target, tag: '00 … ' + U.h2(want - 1 < 0 ? 0 : want - 1), ok: false, many: queries - 1 });
      log.push({ kind: 'verify?', m: target, tag: win.tag, ok: true });
      detail = 'guessing all 256 tags in turn';
    } else if (g === 'keyless') {
      queries = 1; win = { tag: U.hex(sha(target)), tries: 1 };
      log.push({ kind: 'verify?', m: target, tag: win.tag, ok: U.hex(tagOf(target)) === win.tag });
      detail = 'computing the tag itself';
    } else if (g === 'prefix') {
      const r = Hs.lengthExtension({ hash: 'sha256', secret: key, msg: asked[2], ext: '&to=mallory', secretLen: key.length });
      queries = 1; win = { tag: U.hex(r.tag), tries: 1, m: U.show(r.forged) };
      log.push({ kind: 'verify?', m: 'a longer message, ending “&to=mallory”', tag: win.tag, ok: r.ok });
      detail = 'continuing from the third tag (length extension)';
    } else {
      const secretTag = M.hmac('sha256', key, target).slice(0, 4);
      const r = M.timingAttack((guess) => M.leakyEqual(secretTag, guess), 4);
      queries = r.queries; win = { tag: U.hex(r.tag), tries: r.queries };
      log.push({ kind: 'verify?', m: target, tag: win.tag, ok: U.hex(secretTag) === win.tag });
      detail = 'timing the comparison (a 4-byte tag)';
    }
    const tagCut = (s) => U.cut(s, 30);
    const table = (upto) => {
      const items = [t('mg:lt', 20, 300, 'the forger\'s queries', 'ptitle')];
      log.slice(0, upto).forEach((r, k) => {
        const y = 312 + k * 34, cls = r.ok === null ? '' : r.ok ? 'good' : 'bad';
        items.push({ key: 'mg:q' + k, kind: 'cell', x: 20, y, w: 84, h: 28, rx: 4, text: r.kind, size: 13, cls: 'hex ' + (r.kind === 'tag?' ? 'soft' : 'act') });
        items.push({ key: 'mg:m' + k, kind: 'cell', x: 108, y, w: 330, h: 28, rx: 4, text: U.cut(r.m, 40), size: 13.5, cls: 'mono' });
        items.push({ key: 'mg:t' + k, kind: 'cell', x: 442, y, w: 300, h: 28, rx: 4, text: tagCut(r.tag), size: 13.5, cls: 'hex ' + (r.kind === 'tag?' ? 'key' : '') });
        items.push({ key: 'mg:r' + k, kind: 'cell', x: 746, y, w: 154, h: 28, rx: 4, text: r.ok === null ? 'given' : (r.ok ? '✓ accepted' : '✗ rejected') + (r.many ? ' (×' + r.many + ')' : ''), size: 13.5, cls: 'hex ' + cls });
      });
      return items;
    };
    const top = (stage) => {
      const items = [...U.panel('mg:o', 20, 84, 420, 186, 'key holder'), ...U.panel('mg:f', 480, 84, 420, 186, 'forger')];
      items.push(t('mg:o1', 34, 128, g === 'keyless' ? 'no key at all' : 'key: ' + '•'.repeat(Math.min(16, key.length)) + ' (secret)', 'mono key', 'start', 14));
      items.push(t('mg:o2', 34, 156, 'tag(m) = ' + GAMES[g], '', 'start', 14));
      items.push(t('mg:o3', 34, 184, 'answers “tag?” for any message', 'ptick', 'start', 13), t('mg:o4', 34, 206, 'answers “verify?” with yes or no', 'ptick', 'start', 13));
      items.push(t('mg:f1', 494, 128, 'wins with a valid tag on a message', '', 'start', 14), t('mg:f2', 494, 150, 'it never asked about', '', 'start', 14));
      items.push(t('mg:f3', 494, 178, 'target: ' + target, 'mono act', 'start', 13));
      if (stage >= 2) items.push(t('mg:f4', 494, 214, win ? 'wins after ' + U.plural(queries, 'verification query', 'verification queries') : 'no forgery', win ? 'bad' : 'good', 'start', 15), t('mg:f5', 494, 240, detail, 'ptick', 'start', 13));
      return items;
    };
    const head = U.head('mg:h', 'The forgery game: ' + GAMES[g]);
    const F = new S.Frames(['tags', 'verifies']);
    F.add({ items: [...head, ...top(0), ...table(0)], hl: { d: [0] }, say: `The forger may ask the key holder for the tag of any message it likes, and may ask whether a tag is valid. It wins by producing a valid tag on a new message, here “${target}”. The MAC: ${GAMES[g]}.`, facts: { g: GAMES[g] }, meta: { stage: 'rules' } });
    for (let k = 0; k < 3; k++) {
      F.count('tags');
      F.add({ items: [...head, ...top(1), ...table(k + 1)], hl: { d: [1] }, say: `Tag query ${k + 1}: “${log[k].m}” has tag ${U.short(log[k].tag, 8)}. Seeing tags of chosen messages must not help with any other message.`, facts: { k: k + 1, tag: log[k].tag }, meta: { stage: 'tag' } });
    }
    F.set('verifies', queries);
    const say = g === 'hmac' ? `A random tag for “${target}” is rejected, and so is the tag of another message: a 256-bit tag can only be guessed with chance 2⁻²⁵⁶ per try, and HMAC's tags of other messages say nothing about this one. No forgery.`
      : g === 'trunc' ? `With an 8-bit tag the forger simply tries all of them: the tag ${win.tag} is accepted after ${win.tries} verification queries. A t-bit tag can always be guessed in about 2ᵗ tries, so real tags are at least 64 bits.`
        : g === 'keyless' ? `With no key, a “MAC” is just a hash: the forger computes SHA-256 of its own message, ${U.short(win.tag, 8)}, and it is accepted at once. A MAC needs a secret.`
          : g === 'prefix' ? `SHA-256(key ‖ m) hands out the hash's whole state as its tag, so the forger can carry on from the third tag: a longer message ending in “&to=mallory” gets a tag, ${U.short(win.tag, 8)}, that is accepted on the first try, with no key. It is not a secure MAC: use HMAC.`
            : `The key holder compares tags byte by byte and stops at the first difference, so a correct byte makes the answer a little slower. That lets the forger learn the whole tag of the target, ${win.tries} queries in all instead of about 2³² guesses. Compare tags in constant time.`;
    const bitsT = g === 'trunc' ? 8 : g === 'leaky' ? 32 : 256;
    const sum = U.readout('mg:s', 20, 470, 880, 'the score', [['tag length', bitsT + ' bits'], ['a blind guess succeeds with chance', '2^-' + bitsT], ['verification queries used', String(queries), win ? 'bad' : 'good'], ['forgery', win ? 'yes: the MAC loses the game' : 'no: the MAC wins', win ? 'bad' : 'good']], { dy: 26, vsize: 14 });
    F.add({ items: [...head, ...top(2), ...table(log.length), ...sum], hl: { d: [2, 3] }, say, facts: { win, queries, target, bitsT }, meta: { stage: 'forge' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Existential unforgeability (EUF-CMA)', ['the key K is secret; the forger gets oracles:', '  tag?(m) → MAC_K(m), for messages it chooses', '  verify?(m, τ) → accept or reject', 'it wins with (m*, τ*) valid and m* never asked', 'secure: every efficient forger wins with tiny chance', 'about 2⁻ᵗ per guess for a t-bit tag']) };
  }
  S.topic({
    id: 'p13-macgame', family: 'p13-mac', order: 10, title: 'What a MAC must do: the forgery game',
    blurb: 'A forger may see tags of any messages it chooses; it must still not tag a new one. HMAC wins the game. A short tag, a keyless hash, a secret-prefix hash and a comparison that leaks timing all lose it.',
    inputs: [
      { id: 'mac', kind: 'choice', label: 'MAC', def: 'hmac', options: Object.keys(GAMES).map((k) => ({ value: k, label: GAMES[k] })) },
      { id: 'key', kind: 'text', label: 'Key', def: 'harbour-key-31', check: (v) => (!v.length || v.length > 40 ? 'Key: 1 to 40 characters' : null) },
    ],
    presets: Object.keys(GAMES).map((k) => ({ label: GAMES[k], values: { mac: k, key: 'harbour-key-31' } })),
    counters: [{ id: 'tags', label: 'tag queries' }, { id: 'verifies', label: 'verify queries' }],
    run: game,
    predict: [{ at: (f, i, fr) => f.meta && f.meta.stage === 'tag' && fr[i + 1] && fr[i + 1].meta.stage === 'forge', pick: 'option', options: ['the forger wins', 'no forgery'], ask: 'The forger now tries for a tag on the target message. Who wins?', answer: (fr) => (fr[fr.length - 1].facts.win ? 'the forger wins' : 'no forgery'), explain: (fr) => fr[fr.length - 1].say }],
    quiz: [
      { q: 'In the forgery game, which message must the forger tag?', options: ['any message', 'a message it never asked the key holder about', 'the first message asked', 'the key'], answer: 1, why: 'Replaying a tag it was given is not a forgery.' },
      { q: 'Why is a keyless hash not a MAC?', options: ['it is too slow', 'anyone can compute it for any message', 'it is too short', 'it uses padding'], answer: 1, why: 'A MAC must need the secret key.' },
      { q: 'How many guesses does a 32-bit tag cost a forger at most?', options: ['32', 'about 2^16', 'about 2^32', '2^256'], answer: 2, why: 'Each verification query is one guess; the birthday bound does not help against a fixed target.' },
      { q: 'What stops the timing attack on tag comparison?', options: ['longer keys', 'comparing every byte, in time that does not depend on where the tags differ', 'SHA-3', 'sending the tag twice'], answer: 1, why: 'A constant-time comparison gives a wrong first byte and a wrong last byte the same time.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // HMAC
  // ---------------------------------------------------------------------------------------------------------------
  const HN = { sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5', sha512: 'SHA-512', 'sha3-256': 'SHA3-256' };
  function hmac(inp) {
    const Hs = H(), A = Hs.get(inp.hash), B = A.blockLen, name = HN[inp.hash];
    const key = inp.keyHex ? U.fromHex(inp.key) : U.utf8(inp.key), msg = U.utf8(inp.msg);
    const r = Mc().hmacTrace(inp.hash, key, msg), long = key.length > B;
    const strip = (pre, y, bytes, cls, title, lit) => {
      const items = [t(pre + ':t', 20, y - 8, title, 'ptitle')], L = bytes.length;
      // a block longer than 32 bytes: its first 23 and its last 8, with the middle elided
      const idx = L <= 32 ? [...Array(L).keys()] : [...Array(23).keys(), -1, ...Array.from({ length: 8 }, (_, k) => L - 8 + k)];
      idx.forEach((i, j) => {
        if (i < 0) { items.push(t(pre + ':el', 20 + j * 26 + 12, y + 17, '⋯', 'ptick', 'middle', 14)); return; }
        items.push({ key: pre + i, kind: 'cell', x: 20 + j * 26, y, w: 24, h: 24, rx: 3, text: U.h2(bytes[i]), size: 13, cls: 'hex ' + (lit && lit(i) ? lit(i) : cls) });
      });
      return items;
    };
    const kl = key.length;
    const keyRole = (i) => (i < Math.min(kl, long ? A.outLen : kl) ? 'key' : 'p00');
    const ipadRole = (i) => (i < (long ? A.outLen : kl) ? 'key' : '');
    const flow = (pre, y, left, right, out, stage, lit) => {
      const N = S.Kit.flow.net(pre);
      N.box('a', 140, y, 240, 38, left, lit ? 'val key small' : 'val soft small');
      N.box('b', 400, y, 220, 38, right, lit ? 'val small' : 'val soft small');
      N.box('h', 590, y, 84, 38, name, lit ? 'cipher act' : 'cipher');
      N.box('o', 790, y, 220, 38, out, lit ? 'val hot small' : 'val soft small');
      N.wire('ab', [N.port('a', 'e'), N.port('b', 'w')], {});
      N.wire('bh', [N.port('b', 'e'), N.port('h', 'w')], { head: true, cls: lit ? 'act' : '' });
      N.wire('ho', [N.port('h', 'e'), N.port('o', 'w')], { head: true, cls: lit ? 'act' : '' });
      N.label('cat', 270, y - 26, '‖', 'strong', 'middle', 15);
      return N.items;
    };
    const head = U.head('hm:h', 'HMAC-' + name + ': two hashes, two padded keys', 'block size ' + B + ' bytes; ipad = 36 repeated, opad = 5c repeated');
    const F = new S.Frames(['hashes']);
    const kp = r.k0, inner = U.hex(r.inner), tag = U.hex(r.tag);
    const keyItems = () => strip('hk', 106, kp, 'p00', 'K′: the key' + (long ? ' hashed (it was longer than a block)' : '') + ', padded with zeros to ' + B + ' bytes', keyRole);
    F.add({ items: [...head, ...keyItems()], hl: { d: [0] }, say: long ? `The ${kl}-byte key is longer than the ${B}-byte block, so it is hashed first: K′ = ${name}(K) = ${U.short(U.hex(Hs.get(inp.hash).hash(key)), 8)}, then padded with zeros to ${B} bytes.` : `The ${U.plural(kl, 'byte')} key is padded with zeros to the block size, ${B} bytes: K′.`, facts: { kl, B, k0: U.hex(kp) }, meta: { stage: 'key' } });
    const ip = strip('hi', 180, r.ipadKey, '', 'K′ ⊕ ipad (each byte XOR 36)', ipadRole);
    F.add({ items: [...head, ...keyItems(), ...ip], hl: { d: [1] }, say: `K′ ⊕ ipad: every byte XORed with 36. The zero bytes become 36 themselves: ${U.short(r.ipadKey, 8)}.`, facts: { ipad: U.hex(r.ipadKey) }, meta: { stage: 'ipad' } });
    F.count('hashes');
    const f1 = flow('hf1', 250, 'K′ ⊕ ipad (' + B + ' B)', U.cut('“' + inp.msg + '”', 26), inner.slice(0, 16) + '…', 1, true);
    F.add({ items: [...head, ...keyItems(), ...ip, ...f1], hl: { d: [2] }, say: `Inner hash: ${name}((K′ ⊕ ipad) ‖ message) = ${U.short(inner, 8)}. The padded key fills exactly one block, so the message starts on a block boundary.`, facts: { inner }, meta: { stage: 'inner' } });
    const op = strip('ho', 330, r.opadKey, '', 'K′ ⊕ opad (each byte XOR 5c)', ipadRole);
    F.add({ items: [...head, ...keyItems(), ...ip, ...flow('hf1', 250, 'K′ ⊕ ipad (' + B + ' B)', U.cut('“' + inp.msg + '”', 26), inner.slice(0, 16) + '…', 1, false), ...op], hl: { d: [3] }, say: `K′ ⊕ opad: every byte XORed with 5c, giving a second, unrelated key block: ${U.short(r.opadKey, 8)}.`, facts: { opad: U.hex(r.opadKey) }, meta: { stage: 'opad' } });
    F.count('hashes');
    const f2 = flow('hf2', 400, 'K′ ⊕ opad (' + B + ' B)', 'inner ' + inner.slice(0, 12) + '…', tag.slice(0, 16) + '…', 2, true);
    const tagPanel = () => { const lines = tag.match(/.{1,64}/g), items = U.panel('hm:tp', 20, 460, 880, 46 + 22 * lines.length, 'HMAC-' + name + ' tag'); lines.forEach((l, k) => items.push(t('hm:tl' + k, 34, 504 + 22 * k, l.replace(/(.{8})(?!$)/g, '$1 '), 'mono hot', 'start', 15))); return items; };
    F.add({ items: [...head, ...keyItems(), ...ip, ...flow('hf1', 250, 'K′ ⊕ ipad (' + B + ' B)', U.cut('“' + inp.msg + '”', 26), inner.slice(0, 16) + '…', 1, false), ...op, ...f2, ...tagPanel()], hl: { d: [4] }, say: `Outer hash: ${name}((K′ ⊕ opad) ‖ inner) = ${U.spaced(tag)}. That is the tag.`, facts: { tag }, meta: { stage: 'outer' } });
    F.add({ items: [...head, ...keyItems(), ...ip, ...flow('hf1', 250, 'K′ ⊕ ipad (' + B + ' B)', U.cut('“' + inp.msg + '”', 26), inner.slice(0, 16) + '…', 1, false), ...op, ...flow('hf2', 400, 'K′ ⊕ opad (' + B + ' B)', 'inner ' + inner.slice(0, 12) + '…', tag.slice(0, 16) + '…', 2, false), ...tagPanel()], hl: { d: [5] }, say: `Why two hashes: the tag is the state after hashing only the opad block and a ${A.outLen}-byte digest, so extending it never yields the HMAC of a longer message, and the two keys K′ ⊕ ipad and K′ ⊕ opad differ in half their bits. HMAC is secure if the compression function behaves as a pseudorandom function.`, facts: { outLen: A.outLen }, meta: { stage: 'why' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('HMAC (RFC 2104)', ['K′ = K, or H(K) if K is longer than a block; pad with zeros', 'ipad = 36 36 … 36,  opad = 5c 5c … 5c', 'inner = H((K′ ⊕ ipad) ‖ m)', 'HMAC(K, m) = H((K′ ⊕ opad) ‖ inner)', 'two hash calls more than H(m), whatever the length of m', 'not extendable: the tag is the outer hash']) };
  }
  S.topic({
    id: 'p13-hmac', family: 'p13-mac', order: 20, title: 'HMAC: ipad, opad and two nested hashes',
    blurb: 'Pad the key to a block, XOR it with 36s for the inner hash of the message and with 5cs for the outer hash of that digest. Two extra hash calls buy a MAC that length extension cannot touch.',
    inputs: [
      { id: 'key', kind: 'text', label: 'Key', def: 'harbour-key-31', check: (v, inp) => (inp.keyHex ? U.hexCheck('Key', 1, 200)(v) : !v.length || v.length > 200 ? 'Key: 1 to 200 characters' : null) },
      { id: 'keyHex', kind: 'choice', label: 'Key is', def: '', options: [{ value: '', label: 'text' }, { value: 'hex', label: 'hex bytes' }] },
      { id: 'msg', kind: 'text', label: 'Message', def: 'amount=20&to=wren', check: (v) => (v.length > 200 ? 'Message: at most 200 characters' : null) },
      { id: 'hash', kind: 'choice', label: 'Hash', def: 'sha256', options: Object.keys(HN).map((k) => ({ value: k, label: HN[k] })) },
    ],
    presets: [
      { label: 'HMAC-SHA256', values: { key: 'harbour-key-31', keyHex: '', msg: 'amount=20&to=wren', hash: 'sha256' } },
      { label: 'RFC 4231 test case 2', values: { key: 'Jefe', keyHex: '', msg: 'what do ya want for nothing?', hash: 'sha256' } },
      { label: 'A key longer than a block', values: { key: 'aa'.repeat(131), keyHex: 'hex', msg: 'Test Using Larger Than Block-Size Key - Hash Key First', hash: 'sha256' } },
      { label: 'HMAC-SHA512', values: { key: 'harbour-key-31', keyHex: '', msg: 'amount=20&to=wren', hash: 'sha512' } },
      { label: 'HMAC-MD5', values: { key: 'harbour-key-31', keyHex: '', msg: 'amount=20&to=wren', hash: 'md5' } },
    ],
    counters: [{ id: 'hashes', label: 'hash calls' }],
    run: hmac,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'ipad', pick: 'option', options: ['the message', 'the inner digest', 'the key again'], ask: 'The outer hash will take K′ ⊕ opad followed by what?', answer: 'the inner digest', explain: 'HMAC = H((K′ ⊕ opad) ‖ H((K′ ⊕ ipad) ‖ m)).' }],
    quiz: [
      { q: 'What does HMAC do with a key longer than the hash\'s block?', options: ['truncates it', 'hashes it first', 'rejects it', 'uses two blocks'], answer: 1, why: 'K′ = H(K), then zero-padded.' },
      { q: 'Why are there two different pads, ipad and opad?', options: ['for speed', 'so the inner and outer hashes use different keys', 'for the length', 'they are equal'], answer: 1, why: 'The two derived keys differ in half their bits.' },
      { q: 'Is HMAC-SHA256 vulnerable to length extension?', options: ['yes', 'no', 'only for long messages', 'only with short keys'], answer: 1, why: 'The tag is an outer hash over a fixed-length input.' },
      { q: 'HMAC-MD5 is still considered a reasonable MAC because…', options: ['MD5 is unbroken', 'HMAC\'s security rests on the compression function as a PRF, not on collision resistance', 'it is fast', 'it is not'], answer: 1, why: 'Collision attacks on MD5 do not directly give HMAC forgeries (though better choices exist).' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
