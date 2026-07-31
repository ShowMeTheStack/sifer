// The cipher bench's algorithms: one adapter per cipher over the engines in src/core, so the bench asks every cipher
// the same questions. Engines are looked up only when used, so an algorithm whose engine is not in the build says so
// instead of breaking the page.
//   S.CipherBench.algos: [{id, label, group, kind: 'classic' | 'block' | 'stream', has(), ...}]
//   block:   n (block bytes), keyLens, roundsOf(block, key) -> {out, states: [{label, bytes, key?, detail?}], trace},
//            cipher(key) -> {n, encrypt(b), decrypt(b)}, view: 'aes' | 'des' | 'present' | 'mini' | 'spn'
//   stream:  keyLen, ivLen, ivName, run(key, iv, data) -> {out, keystream, view, trace}, rounds(key, iv) -> states
//   classic: keyHelp, run(text, key, decrypt) -> {out, trace, extra}
(function (S) {
  'use strict';
  const CB = (S.CipherBench = S.CipherBench || {});
  const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
  const u8 = (a) => Uint8Array.from(a);
  /** bits (arrays of 0/1, first bit most significant) to bytes */
  const bitsToBytes = (bits) => { const o = new Uint8Array(Math.ceil(bits.length / 8)); bits.forEach((b, i) => { if (b) o[i >> 3] |= 0x80 >> (i & 7); }); return o; };
  const bigToBytes = (v, n) => { const o = new Uint8Array(n); for (let i = n - 1; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
  const bytesToBig = (b) => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);
  const wordsLE = (w) => { const o = new Uint8Array(w.length * 4); w.forEach((x, i) => { o[4 * i] = x & 255; o[4 * i + 1] = (x >>> 8) & 255; o[4 * i + 2] = (x >>> 16) & 255; o[4 * i + 3] = (x >>> 24) & 255; }); return o; };
  CB.util = { hex, bitsToBytes, bigToBytes, bytesToBig, wordsLE };
  const need = (cond, what) => { if (!cond) throw new Error('The ' + what + ' engine is not in this build yet.'); };

  const aes = (bits) => ({
    id: 'aes' + bits, label: 'AES-' + bits, group: 'Block ciphers', kind: 'block', n: 16, keyLens: [bits / 8], view: 'aes',
    blurb: 'A 4×4 byte state through SubBytes, ShiftRows, MixColumns and AddRoundKey, ' + ({ 128: 10, 192: 12, 256: 14 })[bits] + ' rounds.',
    has: () => !!(S.AES && (bits === 128 ? S.AES.encrypt : S.AES.encryptBlock)),
    roundsOf(block, key, dec) {
      need(this.has(), 'AES');
      const r = dec ? S.AES.decryptBlock(block, key) : S.AES.encryptBlock ? S.AES.encryptBlock(block, key) : S.AES.encrypt(block, key);
      const states = [{ label: dec ? 'Cipher input (C)' : 'Cipher input', bytes: u8(block) }];
      for (const x of r.rounds) states.push({ label: x.round === 0 ? (dec ? 'First key added' : 'Round 0') : 'Round ' + x.round, bytes: u8(x.end), key: u8(x.key), detail: x });
      return { out: u8(r.out), states, trace: r.trace };
    },
    cipher(key) { need(S.AES && S.AES.cipher, 'AES'); return S.AES.cipher(key); },
  });

  const algos = [
    // ---- classical ------------------------------------------------------------------------------------------------
    { id: 'shift', label: 'Shift (Caesar)', group: 'Classical', kind: 'classic', keyLabel: 'Shift', keyDef: '3', keyHelp: 'a number from 0 to 25',
      blurb: 'Every letter moves the same number of places round the alphabet.', has: () => !!(S.Classic && S.Classic.shift),
      run(t, k, dec) { const n = parseInt(k, 10); if (!Number.isFinite(n)) throw new Error('The shift must be a number from 0 to 25.'); return S.Classic.shift[dec ? 'decrypt' : 'encrypt'](t, n); } },
    { id: 'affine', label: 'Affine', group: 'Classical', kind: 'classic', keyLabel: 'a, b', keyDef: '5, 8', keyHelp: 'two numbers a, b with a coprime to 26',
      blurb: 'c = a·p + b (mod 26): a multiplication, then a shift.', has: () => !!(S.Classic && S.Classic.affine),
      run(t, k, dec) { const m = /^\s*(-?\d+)\s*[, ]\s*(-?\d+)\s*$/.exec(k); if (!m) throw new Error('The key must be two numbers a, b, like 5, 8.'); const r = S.Classic.affine[dec ? 'decrypt' : 'encrypt'](t, +m[1], +m[2]); if (r.out === null) throw new Error('a must be coprime to 26: a = ' + m[1] + ' shares a factor with 26, so this key cannot be undone. Pick a from 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25.'); return r; } },
    { id: 'substitution', label: 'Keyword substitution', group: 'Classical', kind: 'classic', keyLabel: 'Keyword', keyDef: 'LANTERN', keyHelp: 'a word: the cipher alphabet starts with its letters',
      blurb: 'A whole alphabet as the key: 26! of them, yet frequency analysis reads it.', has: () => !!(S.Classic && S.Classic.substitution),
      run(t, k, dec) { const a = S.Classic.substitution.keywordAlphabet(k); const r = S.Classic.substitution[dec ? 'decrypt' : 'encrypt'](t, a.alphabet); return { out: r.out, trace: a.trace.concat(r.trace), extra: { alphabet: a.alphabet } }; } },
    { id: 'vigenere', label: 'Vigenère', group: 'Classical', kind: 'classic', keyLabel: 'Key word', keyDef: 'HARBOUR', keyHelp: 'a word; each letter is a shift',
      blurb: 'A shift that changes with every letter, following a key word.', has: () => !!(S.Classic && S.Classic.vigenere),
      run(t, k, dec) { return S.Classic.vigenere[dec ? 'decrypt' : 'encrypt'](t, k); } },
    { id: 'columnar', label: 'Columnar transposition', group: 'Classical', kind: 'classic', keyLabel: 'Key word', keyDef: 'MAPLE', keyHelp: 'a word: its letters in alphabetical order give the column order',
      blurb: 'The letters stay the same; only their order changes.', has: () => !!(S.Classic && S.Classic.columnar),
      run(t, k, dec) { const r = S.Classic.columnar[dec ? 'decrypt' : 'encrypt'](t, k, dec ? undefined : { pad: 'X' }); return Object.assign(r, { extra: { grid: r.grid, order: r.order } }); } },
    { id: 'railfence', label: 'Rail fence', group: 'Classical', kind: 'classic', keyLabel: 'Rails', keyDef: '3', keyHelp: 'the number of rails, 2 or more',
      blurb: 'Write the letters in a zigzag over a few rails, then read the rails one after another.', has: () => !!(S.Classic && S.Classic.railfence),
      run(t, k, dec) { const n = parseInt(k, 10); if (!(n >= 2)) throw new Error('The rail fence must have at least 2 rails.'); return S.Classic.railfence[dec ? 'decrypt' : 'encrypt'](t, n); } },
    { id: 'playfair', label: 'Playfair', group: 'Classical', kind: 'classic', keyLabel: 'Key word', keyDef: 'KESTREL', keyHelp: 'a word that starts the 5×5 square',
      blurb: 'Pairs of letters through a 5×5 square: the first cipher to work on digraphs.', has: () => !!(S.Classic && S.Classic.playfair),
      run(t, k, dec) { const r = S.Classic.playfair[dec ? 'decrypt' : 'encrypt'](t, k); return Object.assign(r, { extra: { square: r.square } }); } },
    // ---- block ------------------------------------------------------------------------------------------------------
    aes(128), aes(192), aes(256),
    { id: 'des', label: 'DES', group: 'Block ciphers', kind: 'block', n: 8, keyLens: [8], view: 'des',
      blurb: 'The 16-round Feistel ladder on two 32-bit halves, with the eight S-boxes inside f.', has: () => !!(S.DES && S.DES.encrypt),
      roundsOf(block, key, dec) {
        need(this.has(), 'DES');
        const r = S.DES.encrypt(block, key, dec ? { decrypt: true } : undefined);
        const states = [{ label: dec ? 'Cipher input (C)' : 'Cipher input', bytes: u8(block) }];
        if (r.ip) states.push({ label: 'After IP', bytes: bitsToBytes(r.ip), half: true });
        for (const x of r.rounds) states.push({ label: 'Round ' + x.i, bytes: bitsToBytes(x.R.concat(x.newR)), key: bitsToBytes(x.K), half: true, detail: x });
        return { out: u8(r.out), states, trace: r.trace };
      },
      cipher(key) { need(S.DES && S.DES.cipher, 'DES'); return S.DES.cipher(key); } },
    { id: '3des', label: '3DES (EDE)', group: 'Block ciphers', kind: 'block', n: 8, keyLens: [16, 24], view: 'tdes',
      blurb: 'DES three times, encrypt–decrypt–encrypt, with two or three keys.', has: () => !!(S.TDES && S.TDES.encrypt),
      roundsOf(block, key, dec) {
        need(this.has(), '3DES');
        const r = dec ? S.TDES.decrypt(block, key) : S.TDES.encrypt(block, key);
        const states = [{ label: dec ? 'Cipher input (C)' : 'Cipher input', bytes: u8(block) }];
        const names = dec ? ['Decrypt with K3', 'Encrypt with K2', 'Decrypt with K1'] : ['Encrypt with K1', 'Decrypt with K2', 'Encrypt with K3'];
        (r.steps || []).forEach((x, i) => states.push({ label: names[i] || 'Stage ' + (i + 1), bytes: u8(x && x.length !== undefined ? x : x.out || []) }));
        return { out: u8(r.out), states: states.filter((s) => s.bytes.length), trace: r.trace };
      },
      cipher(key) { need(S.TDES && S.TDES.cipher, '3DES'); return S.TDES.cipher(key); } },
    { id: 'present', label: 'PRESENT-80', group: 'Block ciphers', kind: 'block', n: 8, keyLens: [10], view: 'present',
      blurb: 'A lightweight SPN: 31 rounds of one 4-bit S-box and a bit permutation.', has: () => !!(S.PRESENT && S.PRESENT.encrypt),
      roundsOf(block, key, dec) {
        need(this.has(), 'PRESENT');
        if (dec) { const r = S.PRESENT.decrypt(block, key); return { out: u8(r.out), states: [{ label: 'Ciphertext', bytes: u8(block) }, { label: 'Plaintext', bytes: u8(r.out) }], trace: r.trace }; }
        const r = S.PRESENT.encrypt(block, key);
        const states = [{ label: 'Cipher input', bytes: u8(block) }];
        for (const x of r.rounds) states.push({ label: 'Round ' + x.round, bytes: bigToBytes(x.perm, 8), key: bigToBytes(x.key, 8), detail: x });
        states.push({ label: 'Final key', bytes: u8(r.out) });
        return { out: u8(r.out), states, trace: r.trace };
      },
      cipher(key) { need(S.PRESENT && S.PRESENT.cipher, 'PRESENT'); return S.PRESENT.cipher(key); } },
    { id: 'miniaes', label: 'Mini-AES (toy)', group: 'Toy ciphers', kind: 'block', n: 2, keyLens: [2], view: 'mini', toy: true,
      blurb: 'AES shrunk to a 16-bit block of four nibbles: the same steps, small enough to do by hand.', has: () => !!(S.MiniAES && S.MiniAES.encrypt),
      roundsOf(block, key, dec) {
        need(this.has(), 'Mini-AES');
        const M = S.MiniAES, p = (block[0] << 8) | block[1], k = (key[0] << 8) | key[1];
        const r = dec ? M.decrypt(p, k) : M.encrypt(p, k);
        const nb = (n) => Uint8Array.from([(n[0] << 4) | n[1], (n[2] << 4) | n[3]]);
        const states = [{ label: dec ? 'Cipher input (C)' : 'Cipher input', bytes: u8(block) }];
        if (!dec && r.keys) states.push({ label: 'Round 0 (add K0)', bytes: nb(r.rounds[0].start), key: nb(r.keys[0]) });
        for (const x of r.rounds || []) states.push({ label: 'Round ' + x.round, bytes: nb(x.end), key: x.key ? nb(x.key) : null, detail: x });
        return { out: Uint8Array.from([(r.out >> 8) & 255, r.out & 255]), states, trace: r.trace };
      },
      cipher(key) { const k = (key[0] << 8) | key[1]; return { n: 2, encrypt: (b) => { const o = S.MiniAES.encrypt((b[0] << 8) | b[1], k).out; return Uint8Array.from([o >> 8, o & 255]); }, decrypt: (b) => { const o = S.MiniAES.decrypt((b[0] << 8) | b[1], k).out; return Uint8Array.from([o >> 8, o & 255]); } }; } },
    { id: 'spn', label: 'Toy SPN (16-bit)', group: 'Toy ciphers', kind: 'block', n: 2, keyLens: [10], view: 'spn', toy: true,
      blurb: 'Four rounds of four 4-bit S-boxes and a bit transposition, with five 16-bit round keys: the network differential and linear attacks break.', has: () => !!(S.SPN && S.SPN.encrypt),
      keysOf: (key) => [0, 1, 2, 3, 4].map((i) => (key[2 * i] << 8) | key[2 * i + 1]),
      roundsOf(block, key, dec) {
        need(this.has(), 'toy SPN');
        const ks = this.keysOf(key), p = (block[0] << 8) | block[1];
        const two = (v) => Uint8Array.from([(v >> 8) & 255, v & 255]);
        if (dec) { const r = S.SPN.decrypt(p, ks); const o = typeof r === 'number' ? r : r.out; return { out: two(o), states: [{ label: 'Ciphertext', bytes: u8(block) }, { label: 'Plaintext', bytes: two(o) }], trace: (r && r.trace) || [] }; }
        const r = S.SPN.encrypt(p, ks);
        const states = [{ label: 'Cipher input', bytes: u8(block) }];
        for (const x of r.rounds) states.push({ label: 'Round ' + x.round, bytes: two(x.w !== undefined && x.w !== null ? x.w : x.v), key: two(ks[x.round - 1]), detail: x });
        states.push({ label: 'Add K5', bytes: two(r.out), key: two(ks[4]) });
        return { out: two(r.out), states, trace: r.trace };
      },
      cipher(key) { const self = this, ks = this.keysOf(key), f = S.SPN.fast ? S.SPN.fast(ks) : null; void self; return { n: 2, encrypt: (b) => { const o = f ? f.enc((b[0] << 8) | b[1]) : S.SPN.encrypt((b[0] << 8) | b[1], ks).out; return Uint8Array.from([o >> 8, o & 255]); }, decrypt: (b) => { const o = f ? f.dec((b[0] << 8) | b[1]) : S.SPN.decrypt((b[0] << 8) | b[1], ks).out; return Uint8Array.from([o >> 8, o & 255]); } }; } },
    // ---- stream -----------------------------------------------------------------------------------------------------
    { id: 'chacha20', label: 'ChaCha20', group: 'Stream ciphers', kind: 'stream', keyLen: 32, ivLen: 12, ivName: 'Nonce', view: 'words',
      blurb: '20 rounds of add, rotate and XOR on a 4×4 state of 32-bit words; the output is a keystream.', has: () => !!(S.ChaCha && S.ChaCha.block),
      run(key, iv, data) {
        need(this.has(), 'ChaCha20');
        if (S.ChaCha.encryptTrace) { const r = S.ChaCha.encryptTrace(key, 1, iv, data); const ks = new Uint8Array(data.length); r.blocks.forEach((b) => ks.set(b.ks.slice(0, Math.min(64, data.length - 64 * b.i)), 64 * b.i)); return { out: u8(r.out), keystream: ks, blocks: r.blocks, trace: r.trace }; }
        const ks = new Uint8Array(data.length);
        for (let i = 0; 64 * i < data.length; i++) ks.set(S.ChaCha.block(key, 1 + i, iv).out.slice(0, Math.min(64, data.length - 64 * i)), 64 * i);
        return { out: data.map((v, i) => v ^ ks[i]), keystream: ks, trace: [] };
      },
      rounds(key, iv) { const r = S.ChaCha.block(key, 1, iv); return [{ label: 'Initial state', bytes: wordsLE(r.state), words: r.state }].concat(r.rounds.map((w, i) => ({ label: 'Double round ' + (i + 1), bytes: wordsLE(w), words: w }))).concat([{ label: 'Input added back', bytes: u8(r.out), words: r.words }]); } },
    { id: 'salsa20', label: 'Salsa20', group: 'Stream ciphers', kind: 'stream', keyLen: 32, ivLen: 8, ivName: 'Nonce', view: 'words',
      blurb: 'ChaCha\'s parent: the same 4×4 words, a different quarter-round and layout.', has: () => !!(S.Salsa && S.Salsa.block),
      run(key, iv, data) {
        need(this.has(), 'Salsa20');
        const ks = new Uint8Array(data.length);
        for (let i = 0; 64 * i < data.length; i++) ks.set(S.Salsa.block(key, iv, i).out.slice(0, Math.min(64, data.length - 64 * i)), 64 * i);
        return { out: data.map((v, i) => v ^ ks[i]), keystream: ks, trace: S.Salsa.block(key, iv, 0).trace || [] };
      },
      rounds(key, iv) { const r = S.Salsa.block(key, iv, 0); return [{ label: 'Initial state', bytes: wordsLE(r.state), words: r.state }].concat(r.rounds.map((w, i) => ({ label: 'Double round ' + (i + 1), bytes: wordsLE(w), words: w }))).concat([{ label: 'Input added back', bytes: u8(r.out), words: r.words }]); } },
    { id: 'trivium', label: 'Trivium', group: 'Stream ciphers', kind: 'stream', keyLen: 10, ivLen: 10, ivName: 'IV', view: 'registers',
      blurb: 'Three shift registers of 93, 84 and 111 bits, each fed by an AND of two cells and a tap from another.', has: () => !!(S.Trivium && S.Trivium.create),
      run(key, iv, data) {
        need(this.has(), 'Trivium');
        const g = S.Trivium.create(key, iv), ks = g.keystream(data.length);
        const t = S.Trivium.trace ? S.Trivium.trace(key, iv, 8).trace : [];
        return { out: data.map((v, i) => v ^ ks[i]), keystream: u8(ks), registers: S.Trivium.create(key, iv).state(), trace: t };
      } },
  ];
  CB.algos = algos;
  CB.byId = (id) => algos.find((a) => a.id === id) || null;
  /** the toy and real ciphers that teach the same thing, side by side */
  CB.pairs = { aes128: 'miniaes', miniaes: 'aes128', present: 'spn', spn: 'present' };
  CB.MODES = [
    { id: 'ecb', label: 'ECB', blurb: 'Each block alone: equal blocks give equal ciphertext.' },
    { id: 'cbc', label: 'CBC', blurb: 'Each plaintext block is XORed with the previous ciphertext block (the IV for the first).' },
    { id: 'cfb', label: 'CFB', blurb: 'The cipher encrypts the previous ciphertext block; the result is XORed with the plaintext.' },
    { id: 'ofb', label: 'OFB', blurb: 'The cipher encrypts its own output again and again: a keystream independent of the message.' },
    { id: 'ctr', label: 'CTR', blurb: 'The cipher encrypts a counter; the keystream is XORed with the plaintext.' },
    { id: 'cfb8', label: 'CFB-8', has: () => !!(S.Modes && S.Modes.encrypt), blurb: 'CFB one byte at a time: the cipher runs once per byte and the register shifts in each ciphertext byte, so a lost byte only garbles the next block.' },
    { id: 'cts', label: 'CBC-CTS', has: () => !!(S.Modes && S.Modes.cts), blurb: 'CBC with ciphertext stealing (CS3): no padding, the ciphertext exactly as long as the message; the last two blocks share bytes.' },
    { id: 'gcm', label: 'GCM', aes: true, has: () => !!S.GCM, blurb: 'CTR encryption plus a tag: GHASH over the ciphertext and the associated data in GF(2^128). Decrypting checks the tag before releasing anything.' },
    { id: 'xts', label: 'XTS', aes: true, has: () => !!S.XTS, blurb: 'For disk sectors: two keys, and a tweak (the sector number) that makes equal blocks in different places encrypt differently.' },
  ];
})(globalThis.Sifer = globalThis.Sifer || {});
