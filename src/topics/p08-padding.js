// Part 8, padding: why textbook RSA must never be used as it is (multiplying ciphertexts multiplies plaintexts, and the
// same message always gives the same ciphertext), then OAEP (two masks in a two-round Feistel shape) and PSS (a salted
// hash, masked, with a fixed trailer), each drawn field by field with the bytes the engine produced.
(function (S) {
  'use strict';
  const P = S.PK, NT = () => S.NT, KP = () => S.Kit.pk, H = () => S.P08B;

  // ---------------------------------------------------------------------------------------------------------------
  // Textbook RSA is malleable and deterministic
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p08-malleable', family: 'p08-padding', order: 10, title: 'Textbook RSA is malleable',
    blurb: 'Raw RSA multiplies: (m^e)·(s^e) = (m·s)^e. Someone on the wire who cannot read a sealed bid can still multiply it, and the receiver decrypts m·s. And the same message always encrypts the same way, so a guess can be checked by encrypting it with the public key.',
    inputs: [
      H_keyPicker(),
      { id: 'm', kind: 'bigint', label: 'Sealed bid m', def: '420' },
      { id: 's', kind: 'bigint', label: 'Attacker\'s factor s', def: '3' },
      { id: 'guesses', kind: 'list', label: 'Guesses to test', def: ['300', '420', '500'], max: 5, min: 1 },
    ],
    presets: [
      { label: 'Toy key: a bid of 420, tripled', values: { key: 'toy', m: '420', s: '3', guesses: ['300', '420', '500'] } },
      { label: 'Toy key: halved? multiply by the inverse', values: { key: 'toy', m: '9000', s: '525295', guesses: ['8000', '9000'] } },
      { label: 'RSA-2048: a salary multiplied by 10', values: { key: 'rsa2048', m: '61500', s: '10', guesses: ['55000', '61500', '70000'] } },
      { label: 'RSA-1024: a vote, yes or no', values: { key: 'rsa1024', m: '1', s: '2', guesses: ['0', '1'] } },
    ],
    check(inp) {
      let m, s; try { m = BigInt(inp.m); s = BigInt(inp.s); } catch (e) { return 'm and s must be whole numbers'; }
      const n = H().key(inp.key).n;
      if (m < 0n || m >= n || s < 1n || s >= n) return 'm and s must lie between 0 and n − 1 (s at least 1)';
      if (inp.guesses.some((g) => !/^\d+$/.test(g) || BigInt(g) >= n)) return 'Guesses: whole numbers below n';
      return null;
    },
    counters: [{ id: 'enc', label: 'encryptions with the public key' }],
    run(inp) {
      return P.memo('p08-malleable', inp, () => {
        const key = H().key(inp.key), n = key.n, e = key.e, m = BigInt(inp.m), s = BigInt(inp.s);
        const c = S.RSA.encrypt(m, key).value, t = S.RSA.encrypt(s, key).value, c2 = (c * t) % n, m2 = S.RSA.decrypt(c2, key).value, ms = (m * s) % n;
        const F = new S.Frames(['enc']);
        const add = (say, facts, items, meta) => F.add({ items, say, facts, meta: meta || {} });
        const Y1 = 80, Y2 = 210, Y3 = 340;
        const pic = (o) => {
          const mb = H().vb('m', 95, Y1, 'bid m', m, o.lit === 'm' ? 'act' : ''), e1 = H().box('E1', 255, Y1, 112, 58, ['encrypt', 'x^e mod n'], 'act'), cb = H().vb('c', 430, Y1, 'c', c, 'act');
          const out = [P.title('t1', 20, Y1 - 46, 'sender'), mb, e1, cb, H().wire('w1', [H().port(mb, 'e'), H().port(e1, 'w')]), H().wire('w2', [H().port(e1, 'e'), H().port(cb, 'w')])];
          if (o.att) {
            const sb = H().vb('s', 95, Y2, 'factor s', s, 'bad'), e2 = H().box('E2', 255, Y2, 112, 58, ['encrypt', 'x^e mod n'], 'act'), tb = H().vb('t', 430, Y2, 's^e mod n', t, 'bad');
            out.push(P.title('t2', 20, Y2 - 46, 'attacker on the wire: public key only'), sb, e2, tb, H().wire('w3', [H().port(sb, 'e'), H().port(e2, 'w')], 'bad'), H().wire('w4', [H().port(e2, 'e'), H().port(tb, 'w')], 'bad'));
            if (o.mul) {
              out.push({ key: 'op', kind: 'state', x: 600, y: Y2, r: 14, text: '×', size: 18, cls: 'pk-party hot' }, P.t('opl', 622, Y2 - 20, 'mod n', 'hot', 'start', 13));
              out.push(H().wire('w5', [H().port(cb, 'e'), [600, Y1], [600, Y2 - 14]], 'act'), H().wire('w6', [H().port(tb, 'e'), [586, Y2]], 'bad'));
              const c2b = H().vb('c2', 760, Y2, 'c′ = c·s^e', c2, 'hot');
              out.push(c2b, H().wire('w7', [[614, Y2], H().port(c2b, 'w')], 'hot'));
              out.push(...P.eqs('why', 20, 330, [['(m^e)·(s^e) = (m·s)^e  (mod n)', 'strong']].concat(o.dec ? [[`decrypts to m·s mod n = ${P.n(ms)}`, 'bad']] : []), 16));
              if (o.dec) {
                const db = H().box('D', 760, Y3, 112, 58, ['decrypt', 'x^d mod n'], 'key'), mb2 = H().vb('m2', 760, Y3 + 110, 'receiver reads', m2, 'bad');
                out.push(P.title('t3', 700, Y3 + 5, 'receiver', 'end'), db, mb2, H().wire('w8', [H().port(c2b, 's'), H().port(db, 'n')], 'hot'), H().wire('w9', [H().port(db, 's'), H().port(mb2, 'n')], 'bad'));
              }
            }
          }
          return out;
        };
        F.set('enc', 1);
        add(`The sender seals the bid m = ${P.n(m)} with ${H().kname(inp.key)}: c = m^e mod n = ${P.n(c)}, with e = ${e}. Nobody without d can read it.`, { m, c, e }, pic({ lit: 'm' }), { phase: 'start' });
        F.set('enc', 2);
        add(`The attacker cannot decrypt c, but anyone can encrypt: with the public key the attacker computes s^e mod n = ${P.n(t)} for s = ${P.n(s)}.`, { s, t }, pic({ att: true }), { phase: 'enc-s' });
        add(`Multiply the two ciphertexts: c′ = c·s^e mod n = ${P.n(c2)}. Since (m^e)·(s^e) = (m·s)^e, this is a valid encryption of m·s, made without knowing m.`, { c2 }, pic({ att: true, mul: true }), { phase: 'mul' });
        add(`The receiver decrypts c′ and reads ${P.n(m2)} = ${P.n(m)}·${P.n(s)} mod n${m2 === m * s ? '' : ' (the product wrapped round n)'}. The bid changed and nothing looked wrong: raw RSA gives no integrity at all.`,
          { m2, ms, m, s, ok: m2 === ms }, pic({ att: true, mul: true, dec: true }), { phase: 'dec' });
        // the guesses
        const gs = inp.guesses.map((g) => BigInt(g)), enc = gs.map((g) => S.RSA.encrypt(g, key).value);
        const rows = gs.map((g, i) => [P.n(g), KP().fmt(enc[i], { max: 14 }).text, enc[i] === c ? 'equals c ✓' : 'differs']);
        const hit = gs.findIndex((g, i) => enc[i] === c);
        F.set('enc', 2 + gs.length);
        const tb = S.Kit.table.draw({ prefix: 'gs', x: 20, y: 200, colHead: ['guess', 'guess^e mod n', 'against c'], rows, mono: true, size: 14, hot: hit >= 0 ? [[hit, 2]] : [], cls: (r) => (r === hit ? 'good' : '') });
        add(`A second weakness: encryption is deterministic. To test guesses for the bid, encrypt each with the public key and compare with c. ${hit >= 0 ? `The guess ${P.n(gs[hit])} gives exactly c, so the bid is ${P.n(gs[hit])}.` : 'None matches, so the bid is none of them.'} With a yes-or-no vote, two encryptions reveal everything.`,
          { guesses: gs, hit: hit >= 0 ? gs[hit] : null, count: gs.length }, [...pic({}), P.title('t4', 20, 180, 'testing guesses with the public key'), ...tb.items], { phase: 'guess' });
        add('Both flaws have one cure: padding that is random and checked. OAEP mixes fresh random bytes into every encryption, so the same message never encrypts twice the same way, and a multiplied ciphertext no longer decrypts to a valid block.',
          {}, [...pic({}), P.title('t4', 20, 180, 'testing guesses with the public key'), ...tb.items, ...P.eqs('fx', 520, 230, [['padding: random + checked', 'good'], ['→ OAEP for encryption', 'good'], ['→ PSS for signatures', 'good']], 16)], { phase: 'end' });
        const fr = P.fix(F.list, { x: 0, y: 20, w: 870, h: 490 });
        for (const f of fr) f.narrowView = /^(guess|end)$/.test(f.meta.phase) ? { x: 0, y: 160, w: 500, h: 290 } : f.meta.phase === 'dec' ? { x: 380, y: 140, w: 480, h: 360 } : { x: 0, y: 20, w: 540, h: 260 };
        return { frames: fr, def: P.def('Raw RSA', ['E(m) = m^e mod n', 'E(m)·E(s) = (m·s)^e = E(m·s mod n)', 'E is deterministic: E(m) is the same every time', 'anyone can compute E(guess) and compare']) };
      });
    },
    predict: [
      { at: (f) => f.meta.phase === 'mul', pick: 'option', ask: 'What will the receiver read when decrypting c′?', options: (fr, i) => { const x = fr[i + 1].facts; return [...new Set([P.n(x.ms), P.n(fr[0].facts.m), '0', 'garbage'])]; }, answer: (fr, i) => P.n(fr[i + 1].facts.ms), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Given c = m^e mod n, what does c·2^e mod n decrypt to?', options: ['m', '2m mod n', 'm + 2', 'm^2'], answer: 1, why: '(m^e)(2^e) = (2m)^e.' },
      { q: 'Why can anyone test a guess against a raw RSA ciphertext?', options: ['The public key encrypts, and encryption is deterministic', 'd is public', 'n is small', 'They cannot'], answer: 0, why: 'Encrypt the guess and compare: equal ciphertexts mean equal messages.' },
      { q: 'Which property does textbook RSA lack?', options: ['Correctness', 'Security against chosen ciphertexts and guessing', 'A public key', 'A modulus'], answer: 1, why: 'It is malleable and deterministic, so it is not secure in any modern sense.' },
      { q: 'What fixes both problems?', options: ['A larger e', 'Randomised, checked padding such as OAEP', 'Encrypting twice', 'Keeping n secret'], answer: 1, why: 'OAEP adds fresh randomness and structure that a multiplied ciphertext destroys.' },
    ],
  });
  function H_keyPicker() { return { id: 'key', kind: 'choice', label: 'Key', def: 'toy', options: [{ value: 'toy', label: 'toy (n of 20 bits)' }, { value: 'rsa1024', label: 'RSA-1024' }, { value: 'rsa2048', label: 'RSA-2048' }] }; }

  // ---------------------------------------------------------------------------------------------------------------
  // OAEP and PSS share the real keys and the byte inputs
  // ---------------------------------------------------------------------------------------------------------------
  const REAL = [{ value: 'rsa1024', label: 'RSA-1024 (128-byte blocks)' }, { value: 'rsa2048', label: 'RSA-2048 (256-byte blocks)' }, { value: 'rsa3072', label: 'RSA-3072 (384-byte blocks)' }];
  const hexCheck = (n, what) => (v) => (!/^([0-9a-fA-F]{2})*$/.test(String(v)) ? what + ': whole bytes in hex' : n !== null && String(v).length !== 2 * n ? what + ': exactly ' + n + ' bytes (' + 2 * n + ' hex digits)' : null);
  const fromHex = (h) => Uint8Array.from((String(h).match(/../g) || []).map((x) => parseInt(x, 16)));
  /** a field of bytes in a bar: its first bytes as hex, the whole of it on a click */
  const fieldOf = (id, w, label, bytes, cls) => ({ id, w, text: label, cls: (cls || '') + ' pk-long', title: label + ' = ' + H().hexAll(bytes) + ' (' + bytes.length + ' bytes)' });

  S.topic({
    id: 'p08-oaep', family: 'p08-padding', order: 20, title: 'OAEP, field by field',
    blurb: 'Optimal asymmetric encryption padding builds a block DB = lHash ‖ zeros ‖ 01 ‖ message, picks a fresh random seed, and runs two Feistel rounds: DB is masked by MGF1(seed), the seed by MGF1(maskedDB). The result 00 ‖ maskedSeed ‖ maskedDB is what gets raised to e. Every encryption looks new, and any change breaks the structure.',
    inputs: [
      { id: 'key', kind: 'choice', label: 'Key', def: 'rsa1024', options: REAL },
      { id: 'msg', kind: 'text', label: 'Message', def: 'ship the samples on tuesday', check: (v) => (String(v).length < 1 || new TextEncoder().encode(String(v)).length > 62 ? 'Message: 1 to 62 bytes (the most RSA-1024 can carry with SHA-256)' : null) },
      { id: 'label', kind: 'text', label: 'Label', def: '' },
      { id: 'seed', kind: 'string', label: 'Seed (32 bytes, hex)', def: '5e1f0a77c3b2d4e6f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f', check: hexCheck(32, 'Seed') },
    ],
    presets: [
      { label: 'RSA-1024, a short note', values: { key: 'rsa1024', msg: 'ship the samples on tuesday', label: '', seed: '5e1f0a77c3b2d4e6f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f' } },
      { label: 'RSA-2048 with a label', values: { key: 'rsa2048', msg: 'release 3 is signed off', label: 'build-server', seed: 'a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f' } },
      { label: 'RSA-3072, one byte', values: { key: 'rsa3072', msg: 'Y', label: '', seed: '0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0' } },
      { label: 'RSA-1024, the longest message', values: { key: 'rsa1024', msg: 'sixty-two bytes exactly fill the room OAEP leaves in a block!!', label: '', seed: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' } },
    ],
    check(inp) { const k = NT().byteLength(P.rsaKey(inp.key).n); return new TextEncoder().encode(inp.msg).length > k - 66 ? 'Message: at most ' + (k - 66) + ' bytes for this key' : null; },
    counters: [{ id: 'mgf', label: 'MGF1 calls' }],
    run(inp) {
      return P.memo('p08-oaep', inp, () => {
        const key = P.rsaKey(inp.key), k = NT().byteLength(key.n), msg = new TextEncoder().encode(inp.msg);
        const seed = fromHex(inp.seed), enc = S.RSA.oaepEncode(msg, k, { label: inp.label, seed });
        const cx = S.RSA.oaepEncrypt(key, msg, { label: inp.label, seed }), dec = S.RSA.oaepDecrypt(key, cx.c, { label: inp.label });
        const ps = k - msg.length - 66, dbLen = k - 33;
        const F = new S.Frames(['mgf']);
        const add = (say, facts, items, meta) => F.add({ items, say, facts, meta: meta || {} });
        const hx = H().hx;
        // geometry: the seed column on the left, the DB column on the right
        const SX = 130, DX = 540, SW = 160, DW = 560, DL = 260;
        const msgW = Math.max(110, Math.min(200, 40 + 7 * msg.length)), sepW = 40, lW = 140, psW = DW - msgW - sepW - lW;
        const dbBar = (cls) => KP().bar({ prefix: 'db', x: DL, y: 40, h: 40, segs: [fieldOf('l', lW, 'lHash (32)', enc.lHash, cls || 'hash', '32 bytes'), fieldOf('ps', psW, ps ? '00 × ' + ps : '(no zeros)', new Uint8Array(ps), cls || 'zero', ps + ' bytes'), fieldOf('sep', sepW, '01', Uint8Array.of(1), cls || 'sep', '1'), fieldOf('m', msgW, 'M (' + msg.length + ')', msg, cls || 'msg', msg.length + ' bytes')] }).items;
        const seedBar = (cls) => KP().bar({ prefix: 'sd', x: SX - SW / 2, y: 40, h: 40, segs: [fieldOf('s', SW, 'seed ' + hx(seed, 3), seed, cls || 'seed', '32 random bytes')] }).items;
        const Y1 = 175, Y2 = 285, YB = 360;
        const mgfG = H().box('mg', 335, Y1, 112, 42, ['MGF1'], 'cipher'), mgfH = H().box('mh', 335, Y2, 112, 42, ['MGF1'], 'cipher');
        const pic = (st) => {
          const out = [P.title('st', SX - SW / 2, 22, 'seed'), P.title('dt', DL, 22, 'DB = lHash ‖ PS ‖ 01 ‖ M  (' + dbLen + ' bytes)')];
          out.push(...(st >= 4 ? seedBar() : []), ...dbBar(st >= 6 ? 'zero' : null));
          if (st >= 5) {
            out.push(mgfG, { key: 'x1', kind: 'op', x: DX, y: Y1, r: 12, op: 'xor', cls: st === 6 ? 'hot' : '' });
            out.push(H().wire('dbv', [[DX, 100], [DX, Y1 - 12]], ''), H().wire('sg', [[SX, 100], [SX, Y1], H().port(mgfG, 'w')], 'key'), { key: 'j1', kind: 'dot', x: SX, y: Y1, r: 3.6, cls: 'key', audit: 'ignore' });
            out.push(H().wire('g1', [H().port(mgfG, 'e'), [DX - 12, Y1]], 'act'), { key: 'gc', kind: 'chip', x: 455, y: Y1, text: hx(enc.dbMask, 3), cls: 'act', title: 'dbMask = ' + H().hexAll(enc.dbMask) });
          }
          if (st >= 6) out.push(H().wire('dbm', [[DX, Y1 + 12], [DX, YB]], 'hot'), ...KP().bar({ prefix: 'mdb', x: DL, y: YB, h: 40, segs: [fieldOf('md', DW, 'maskedDB ' + hx(enc.maskedDB, 6), enc.maskedDB, 'mask', dbLen + ' bytes')] }).items);
          if (st >= 7) {
            out.push(mgfH, { key: 'x2', kind: 'op', x: SX, y: Y2, r: 12, op: 'xor', cls: st === 8 ? 'hot' : '' }, { key: 'j2', kind: 'dot', x: DX, y: Y2, r: 3.6, cls: 'hot', audit: 'ignore' });
            out.push(H().wire('h1', [[DX, Y2], H().port(mgfH, 'e')], 'hot'), H().wire('h2', [H().port(mgfH, 'w'), [SX + 12, Y2]], 'act'), { key: 'hc', kind: 'chip', x: 225, y: Y2, text: hx(enc.seedMask, 3), cls: 'act', title: 'seedMask = ' + H().hexAll(enc.seedMask) });
            out.push(H().wire('sv', [[SX, Y1], [SX, Y2 - 12]], 'key', false));
          }
          if (st >= 8) out.push(H().wire('sm', [[SX, Y2 + 12], [SX, YB]], 'hot'), ...KP().bar({ prefix: 'ms', x: SX - SW / 2, y: YB, h: 40, segs: [fieldOf('mss', SW, 'maskedSeed ' + hx(enc.maskedSeed, 2), enc.maskedSeed, 'mask', '32 bytes')] }).items);
          if (st >= 9) out.push(P.title('et', 20, 450, 'EM = 00 ‖ maskedSeed ‖ maskedDB  (' + k + ' bytes, below n)'), ...KP().bar({ prefix: 'em', x: 20, y: 462, h: 34, segs: [fieldOf('z', 40, '00', Uint8Array.of(0), 'zero'), fieldOf('a', 190, hx(enc.maskedSeed, 4), enc.maskedSeed, 'mask'), fieldOf('b', 600, hx(enc.maskedDB, 10), enc.maskedDB, 'mask')] }).items);
          return out;
        };
        add(`${inp.key.replace('rsa', 'RSA-')} has k = ${k} bytes. OAEP with SHA-256 reserves 66 of them, so the message “${inp.msg}” (${msg.length} bytes) fits, with ${ps} bytes to spare.`, { k, len: msg.length, ps, msg: inp.msg, r: 66 }, pic(0), { phase: 'start' });
        add(`lHash = SHA-256(label) = ${hx(enc.lHash, 8)}, ${inp.label ? 'the hash of the label “' + inp.label + '”' : 'the hash of the empty label'}. It ties the ciphertext to its purpose and is checked on decryption.`, { lHash: hx(enc.lHash, 8), label: inp.label }, pic(1), { phase: 'lhash' });
        add(`PS is ${ps} zero bytes, then the separator 01 marks where the message starts.`, { ps, sep: '01' }, pic(2), { phase: 'ps' });
        add(`DB = lHash ‖ PS ‖ 01 ‖ M is ${dbLen} bytes, k − 33: one byte for the leading 00 and 32 for the seed.`, { dbLen, k, kk: 33 }, pic(3), { phase: 'db' });
        add(`A fresh random seed of 32 bytes: ${hx(seed, 8)}. Here it is fixed by the input so the picture repeats; a real encryption draws a new one every time.`, { seed: hx(seed, 8), sl: 32 }, pic(4), { phase: 'seed' });
        F.set('mgf', 1);
        add(`First round: MGF1 stretches the seed into a mask of ${dbLen} bytes, ${hx(enc.dbMask, 8)}: SHA-256(seed ‖ counter) for counters 0, 1, 2, … cut to length.`, { dbLen, mask: hx(enc.dbMask, 8) }, pic(5), { phase: 'mgf-g' });
        add(`maskedDB = DB ⊕ MGF1(seed) = ${hx(enc.maskedDB, 8)}. The zeros, the 01 and the message all vanish into bytes that look random.`, { mdb: hx(enc.maskedDB, 8) }, pic(6), { phase: 'mask-db' });
        F.set('mgf', 2);
        add(`Second round: MGF1(maskedDB) gives a 32-byte mask ${hx(enc.seedMask, 8)} for the seed.`, { mask: hx(enc.seedMask, 8), sl: 32 }, pic(7), { phase: 'mgf-h' });
        add(`maskedSeed = seed ⊕ MGF1(maskedDB) = ${hx(enc.maskedSeed, 8)}. To find the seed you need all of maskedDB; to unmask DB you need the seed: all or nothing.`, { ms: hx(enc.maskedSeed, 8) }, pic(8), { phase: 'mask-seed' });
        add(`EM = 00 ‖ maskedSeed ‖ maskedDB, ${k} bytes. The leading 00 keeps EM below n. Now c = EM^e mod n = ${P.n(cx.c)}.`, { k, c: cx.c }, pic(9), { phase: 'em' });
        const okDec = new TextDecoder().decode(dec.msg) === inp.msg;
        add(`Decryption runs the rounds backwards: EM = c^d mod n, seed = maskedSeed ⊕ MGF1(maskedDB), DB = maskedDB ⊕ MGF1(seed). lHash matches and the 01 is found after the zeros: the message is “${new TextDecoder().decode(dec.msg)}”${okDec ? '' : ' (MISMATCH)'}. A tampered c would almost surely fail these checks.`,
          { msg: inp.msg, ok: okDec }, pic(9), { phase: 'dec', ok: okDec });
        const seed2 = seed.slice(); seed2[0] ^= 1;
        const enc2 = S.RSA.oaepEncode(msg, k, { label: inp.label, seed: seed2 }), diff = enc.em.reduce((a, v, i) => a + (v !== enc2.em[i] ? 1 : 0), 0);
        add(`Flip one bit of the seed and encrypt the same message again: ${diff} of the ${k} bytes of EM change. The same message never encrypts the same way twice.`, { diff, k }, pic(9), { phase: 'again', diff });
        const fr = P.fix(F.list, { x: 0, y: 0, w: 860, h: 510 });
        for (const f of fr) f.narrowView = f.meta.phase === 'again' || f.meta.phase === 'dec' || f.meta.phase === 'em' ? { x: 0, y: 340, w: 860, h: 170 } : { x: 0, y: 0, w: 860, h: 420 };
        return { frames: fr, def: P.def('OAEP (PKCS #1 v2.2, SHA-256)', ['DB = lHash ‖ PS (zeros) ‖ 01 ‖ M', 'maskedDB = DB ⊕ MGF1(seed, k − 33)', 'maskedSeed = seed ⊕ MGF1(maskedDB, 32)', 'EM = 00 ‖ maskedSeed ‖ maskedDB', 'c = EM^e mod n']) };
      });
    },
    predict: [
      { at: (f) => f.meta.phase === 'em', pick: 'option', ask: 'The same message is encrypted again with a seed that differs in one bit. How much of EM changes?', options: ['one bit', 'one byte', 'about half the block', 'almost every byte'], answer: 'almost every byte', explain: (fr) => fr[fr.length - 1].say },
    ],
    quiz: [
      { q: 'What does maskedDB hide?', options: ['Only the message', 'lHash, the zeros, the 01 and the message', 'The seed', 'n'], answer: 1, why: 'All of DB is XORed with MGF1(seed).' },
      { q: 'Why must the seed be fresh and random?', options: ['To make n larger', 'So that encrypting the same message twice gives different ciphertexts', 'So that decryption is faster', 'It need not be'], answer: 1, why: 'The randomness is what defeats guessing and replaying.' },
      { q: 'How many bytes does OAEP with SHA-256 take from a k-byte block?', options: ['11', '32', '66', 'k/2'], answer: 2, why: 'Two hashes of 32 bytes, the 00 at the front and the 01 separator: 2·32 + 2 = 66.' },
      { q: 'What does the decryptor check?', options: ['Only the 01', 'The leading 00, lHash and the 01 after the zeros', 'That c < n only', 'Nothing'], answer: 1, why: 'Any mismatch means the block was not made by OAEP for this label; it is rejected with one error for all cases.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // PSS
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p08-pss', family: 'p08-padding', order: 30, title: 'PSS signatures, field by field',
    blurb: 'The probabilistic signature scheme hashes the message, hashes again with a random salt, hides the salt under a mask made from that hash, and ends the block with bc. The signer raises the block to d; the verifier raises the signature to e, unmasks the salt and recomputes the hash.',
    inputs: [
      { id: 'key', kind: 'choice', label: 'Key', def: 'rsa1024', options: REAL },
      { id: 'msg', kind: 'text', label: 'Message', def: 'pay invoice 2207 in full' },
      { id: 'salt', kind: 'string', label: 'Salt (hex; empty for none)', def: 'c0ffee00112233445566778899aabbccddeeff00112233445566778899aabbcc', check: hexCheck(null, 'Salt') },
    ],
    presets: [
      { label: 'RSA-1024, a 32-byte salt', values: { key: 'rsa1024', msg: 'pay invoice 2207 in full', salt: 'c0ffee00112233445566778899aabbccddeeff00112233445566778899aabbcc' } },
      { label: 'RSA-2048', values: { key: 'rsa2048', msg: 'firmware 7.4 approved for release', salt: '1032547698badcfe1032547698badcfe1032547698badcfe1032547698badcfe' } },
      { label: 'RSA-1024, no salt (deterministic)', values: { key: 'rsa1024', msg: 'pay invoice 2207 in full', salt: '' } },
      { label: 'RSA-3072', values: { key: 'rsa3072', msg: 'minutes of the march meeting', salt: 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100' } },
    ],
    check(inp) { return String(inp.salt).length / 2 > 64 ? 'Salt: at most 64 bytes' : null; },
    counters: [{ id: 'hash', label: 'hashes' }],
    run(inp) {
      return P.memo('p08-pss', inp, () => {
        const key = P.rsaKey(inp.key), modBits = P.bits(key.n), emBits = modBits - 1, emLen = Math.ceil(emBits / 8), salt = fromHex(inp.salt);
        const enc = S.RSA.pssEncode(inp.msg, emBits, { salt }), sig = S.RSA.pssSign(key, inp.msg, { salt });
        const ver = S.RSA.pssVerify(key, inp.msg, sig.s, { saltLength: salt.length }), bad = S.RSA.pssVerify(key, inp.msg + '!', sig.s, { saltLength: salt.length });
        const hx = H().hx, sl = salt.length, dbLen = emLen - 33, psLen = dbLen - sl - 1;
        const F = new S.Frames(['hash']);
        const add = (say, facts, items, meta) => F.add({ items, say, facts, meta: meta || {} });
        const msgB = new TextEncoder().encode(inp.msg);
        const saltF = (id, w, cls) => fieldOf(id, w, sl ? 'salt ' + hx(salt, 3) : '(no salt)', salt, cls || 'seed', sl + ' bytes');
        const pic = (st) => {
          const out = [];
          const mc = { key: 'msg', kind: 'cell', x: 20, y: 40, w: 230, h: 40, rx: 5, text: inp.msg.length > 22 ? inp.msg.slice(0, 21) + '…' : inp.msg, cls: 'pk-field msg', title: 'message = ' + inp.msg };
          out.push(P.title('mt', 20, 24, 'message M (' + msgB.length + ' bytes)'), mc);
          if (st >= 1) {
            out.push(H().box('h1', 330, 60, 80, 40, ['SHA-256'], 'cipher'), H().wire('w1', [[250, 60], [290, 60]]));
            out.push(...KP().bar({ prefix: 'mh', x: 420, y: 40, h: 40, segs: [fieldOf('v', 150, 'mHash ' + hx(enc.mHash, 3), enc.mHash, 'hash', '32 bytes')] }).items, H().wire('w2', [[370, 60], [420, 60]]));
          }
          if (st >= 2) out.push(...KP().bar({ prefix: 'sa', x: 660, y: 40, h: 40, segs: [saltF('v', 170)] }).items);
          if (st >= 3) {
            out.push(P.title('pt', 405, 165, "M′ = 00×8 ‖ mHash ‖ salt", 'end'), ...KP().bar({ prefix: 'mp', x: 420, y: 140, h: 40, segs: [fieldOf('z', 90, '00 × 8', new Uint8Array(8), 'zero', '8'), fieldOf('h', 150, 'mHash', enc.mHash, 'hash', '32'), saltF('s', 170)] }).items);
            out.push(H().wire('w3', [[495, 80], [495, 140]]), H().wire('w4', [[745, 80], [745, 140]], 'key'));
          }
          if (st >= 4) {
            out.push(H().box('h2', 705, 235, 80, 40, ['SHA-256'], 'cipher'), H().wire('w5', [[705, 180], [705, 215]]));
            out.push(...KP().bar({ prefix: 'hh', x: 630, y: 290, h: 40, segs: [fieldOf('v', 150, 'H ' + hx(enc.H, 3), enc.H, 'hash', '32 bytes')] }).items, H().wire('w6', [[705, 255], [705, 290]]));
          }
          if (st >= 5) out.push(P.title('dt', 20, 222, 'DB = PS ‖ 01 ‖ salt  (' + dbLen + ' bytes)'), ...KP().bar({ prefix: 'db', x: 20, y: 234, h: 40, segs: [fieldOf('ps', 220, psLen ? '00 × ' + psLen : '(none)', new Uint8Array(psLen), 'zero', psLen + ''), fieldOf('sep', 40, '01', Uint8Array.of(1), 'sep', '1'), saltF('s', 170)] }).items);
          if (st >= 6) {
            out.push(H().box('mg', 470, 350, 90, 40, ['MGF1'], 'cipher'), { key: 'x', kind: 'op', x: 235, y: 350, r: 12, op: 'xor', cls: st === 6 ? 'hot' : '' });
            out.push(H().wire('w7', [[675, 330], [675, 350], [515, 350]], 'act'), H().wire('w8', [[425, 350], [247, 350]], 'act'), H().wire('w9', [[235, 274], [235, 338]]));
            out.push({ key: 'mc', kind: 'chip', x: 335, y: 350, text: hx(enc.dbMask, 3), cls: 'act', title: 'dbMask = ' + H().hexAll(enc.dbMask) });
          }
          if (st >= 7) {
            out.push(P.title('et', 662, 456, 'EM = maskedDB ‖ H ‖ bc'), P.title('et2', 662, 476, emLen + ' bytes'), H().wire('w10', [[235, 362], [235, 440]], 'hot'), H().wire('w11', [[740, 330], [740, 400], [505, 400], [505, 440]], 'act', true));
            out.push(...KP().bar({ prefix: 'em', x: 20, y: 440, h: 40, segs: [fieldOf('a', 430, 'maskedDB ' + hx(enc.maskedDB, 6), enc.maskedDB, 'mask', dbLen + ' bytes'), fieldOf('b', 150, 'H', enc.H, 'hash', '32'), fieldOf('c', 46, 'bc', Uint8Array.of(0xbc), 'sep', '1')] }).items);
          }
          if (st >= 8) out.push(H().vb('sig', 100, 165, 'signature s = EM^d mod n', sig.s, st === 9 ? 'good' : st === 10 ? 'bad' : 'key'));
          return out;
        };
        F.set('hash', 1);
        add(`Sign “${inp.msg}” with ${inp.key.replace('rsa', 'RSA-')}. First mHash = SHA-256(M) = ${hx(enc.mHash, 8)}.`, { msg: inp.msg, h: hx(enc.mHash, 8) }, pic(1), { phase: 'mhash' });
        add(sl ? `A fresh random salt of ${sl} bytes, ${hx(salt, 8)}: it makes every signature of the same message different and lets the security proof go through.` : 'No salt: the scheme still works, but every signature of the same message is now the same.', { sl, salt: hx(salt, 8) }, pic(2), { phase: 'salt' });
        add(`M′ = eight zero bytes ‖ mHash ‖ salt, ${8 + 32 + sl} bytes.`, { len: 8 + 32 + sl, z: 8 }, pic(3), { phase: 'mprime' });
        F.set('hash', 2);
        add(`H = SHA-256(M′) = ${hx(enc.H, 8)}. This is the value the verifier will recompute.`, { h: hx(enc.H, 8) }, pic(4), { phase: 'h' });
        add(`DB = ${psLen} zero bytes ‖ 01 ‖ salt, ${dbLen} bytes: the block is ${emLen} bytes, minus 32 for H and 1 for bc.`, { psLen, dbLen, emLen, h: 32 }, pic(5), { phase: 'db' });
        add(`maskedDB = DB ⊕ MGF1(H), and the top ${8 * emLen - emBits} bit of the first byte is cleared so EM, read as a number, stays below n: ${hx(enc.maskedDB, 8)}.`, { clear: 8 * emLen - emBits, mdb: hx(enc.maskedDB, 8) }, pic(6), { phase: 'mask' });
        add(`EM = maskedDB ‖ H ‖ bc, ${emLen} bytes. The signature is s = EM^d mod n = ${P.n(sig.s)}.`, { emLen, s: sig.s }, pic(8), { phase: 'sign' });
        add(`Verifying: s^e mod n gives EM back; the last byte is bc, MGF1(H) unmasks DB, the zeros and 01 lead to the salt, and SHA-256(00×8 ‖ SHA-256(M) ‖ salt) equals H: ${ver.ok ? 'valid' : 'INVALID'}.`, { ok: ver.ok, z: 8 }, pic(9), { phase: 'verify', ok: ver.ok });
        add(`Change the message to “${inp.msg}!” and verify the same signature: ${bad.ok ? 'accepted (wrong!)' : 'rejected, because ' + bad.reason}. Unlike raw RSA, two signatures cannot be multiplied into a third: the product's block has no valid structure.`, { msg: inp.msg, ok: bad.ok }, pic(10), { phase: 'tamper', ok: !bad.ok });
        const fr = P.fix(F.list, { x: 0, y: 0, w: 860, h: 500 });
        for (const f of fr) f.narrowView = /^(sign|verify|tamper|mask)$/.test(f.meta.phase) ? { x: 0, y: 130, w: 860, h: 370 } : { x: 0, y: 0, w: 860, h: 340 };
        return { frames: fr, def: P.def('PSS (PKCS #1 v2.2, SHA-256)', ['mHash = SHA-256(M)', "M′ = 00×8 ‖ mHash ‖ salt,  H = SHA-256(M′)", 'DB = PS ‖ 01 ‖ salt', 'maskedDB = DB ⊕ MGF1(H)', 'EM = maskedDB ‖ H ‖ bc,  s = EM^d mod n']) };
      });
    },
    predict: [
      { at: (f) => f.meta.phase === 'verify', pick: 'option', ask: 'The message gains one character. Will the old signature still verify?', options: ['yes', 'no'], answer: 'no', explain: (fr) => fr[fr.length - 1].say },
    ],
    quiz: [
      { q: 'What does the last byte of a PSS block hold?', options: ['00', '01', 'bc', 'the salt length'], answer: 2, why: 'The trailer bc is fixed; a block without it is rejected at once.' },
      { q: 'How does the verifier learn the salt?', options: ['It is sent separately', 'By unmasking DB with MGF1(H)', 'It is always zero', 'By brute force'], answer: 1, why: 'H sits in the clear in EM; MGF1(H) unmasks DB, which ends with the salt.' },
      { q: 'What does the salt add?', options: ['Secrecy of the message', 'Randomness: a fresh signature each time, and a tight security proof', 'A shorter signature', 'Nothing'], answer: 1, why: 'With the salt, signing is probabilistic; without it PSS is still sound but deterministic.' },
      { q: 'Why can raw RSA signatures be forged by multiplying, and PSS ones cannot?', options: ['PSS uses a bigger e', 'The product of two PSS blocks is not a valid PSS block', 'PSS keeps n secret', 'They both can'], answer: 1, why: 's1·s2 opens to EM1·EM2 mod n, which has no bc trailer and no matching hash.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
