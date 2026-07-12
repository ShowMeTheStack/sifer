// Attack labs on block cipher modes, each against a small "server" holding a secret key.
//   S.Attacks.paddingOracle.setup({seed, message}) -> {iv, ct, oracle(iv, ct) -> bool, queries(), secret}
//   S.Attacks.paddingOracle.run({iv, ct, oracle}) -> generator; yields {block, byte, queries}; returns {pt, queries, trace}
//   S.Attacks.paddingOracle.attack(lab) -> the result at once
//       CBC with PKCS#7: the server only says whether the padding was good. Changing the block before a target block
//       changes the decrypted bytes predictably, so at most 256 guesses reveal each byte.
//   S.Attacks.ecbCutPaste({seed}) -> {forged, profile, ok, trace}    ECB blocks are independent: cut and reassemble
//   S.Attacks.cbcBitFlip({seed}) -> {forged, text, ok, trace}        flipping a ciphertext bit flips the same bit of
//       the next plaintext block (and scrambles the current one)
(function (S) {
  'use strict';
  const At = (S.Attacks = S.Attacks || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const hex = (a) => S.bytes.hex(a), h2 = (v) => S.bytes.h2(v);
  const txt = (a) => Array.from(a, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '·')).join('');
  const Mo = () => S.Modes;

  const PO = (At.paddingOracle = {});
  PO.MESSAGES = ['The spare key to the tool shed hangs behind the calendar in the kitchen.', 'Meeting moved: the choir rehearses in the east hall on Thursday at six.', 'Account 4471 owes three library books, due back before the end of the month.'];
  PO.setup = ({ seed = 1, message } = {}) => {
    const r = S.Sym.rng(seed), key = S.Sym.bytes(r, 16), iv = S.Sym.bytes(r, 16), E = S.AES.cipher(key);
    const secret = S.bytes.utf8(message || PO.MESSAGES[Math.floor(r() * PO.MESSAGES.length)]);
    const ct = Mo().encrypt('cbc', E, Mo().pkcs7(secret, 16), { iv, trace: false }).out;
    let q = 0;
    const oracle = (ivx, c) => { q++; try { Mo().unpkcs7(Mo().decrypt('cbc', E, c, { iv: ivx, trace: false }).out, 16); return true; } catch (e) { return false; } };
    return { iv, ct, oracle, queries: () => q, secret };
  };
  PO.run = function* ({ iv, ct, oracle }) {
    const n = 16, blocks = [iv];
    for (let i = 0; i < ct.length; i += n) blocks.push(ct.subarray(i, i + n));
    const plain = [], trace = [];
    let queries = 0;
    const ask = (prev, c) => { queries++; return oracle(prev, c); };
    trace.push(step('po-start', `The ciphertext has ${blocks.length - 1} blocks. For each block C, send (C', C) with a chosen C'; the server decrypts C to its intermediate value I = D_k(C), XORs C', and reports only whether the padding is valid.`, {}));
    for (let b = 1; b < blocks.length; b++) {
      const C = blocks[b], prev = blocks[b - 1], I = new Uint8Array(n), P = new Uint8Array(n);
      for (let pos = n - 1; pos >= 0; pos--) {
        const pad = n - pos, fake = new Uint8Array(n);
        for (let k = pos + 1; k < n; k++) fake[k] = I[k] ^ pad;
        let found = -1, tries = 0;
        for (let g = 0; g < 256; g++) {
          fake[pos] = g; tries++;
          if (!ask(fake, C)) continue;
          // the last byte can also succeed by making a longer valid padding (… 02 02): change the byte before and ask again
          if (pos === n - 1) { const f2 = Uint8Array.from(fake); f2[pos - 1] ^= 1; tries++; if (!ask(f2, C)) continue; }
          found = g; break;
        }
        if (found < 0) throw new Error('the oracle never accepted a guess');
        I[pos] = found ^ pad; P[pos] = I[pos] ^ prev[pos];
        trace.push(step('po-byte', `Block ${b}, byte ${pos + 1}: aiming for padding ${h2(pad)}, the guess C'[${pos}] = ${h2(found)} is accepted after ${tries} quer${tries === 1 ? 'y' : 'ies'}, so I = ${h2(found)} ⊕ ${h2(pad)} = ${h2(I[pos])} and the plaintext byte is I ⊕ ${h2(prev[pos])} = ${h2(P[pos])} '${txt([P[pos]])}'.`, { block: b, pos, guess: found, pad, I: I[pos], p: P[pos], tries }));
        yield { block: b, byte: pos, queries };
      }
      trace.push(step('po-block', `Block ${b} is ${hex(P)}: '${txt(P)}'.`, { block: b, P, I }));
      plain.push(...P);
    }
    const padded = Uint8Array.from(plain);
    let pt;
    try { pt = Mo().unpkcs7(padded, 16); } catch (e) { pt = padded; }
    trace.push(step('po-done', `Recovered '${txt(pt)}' with ${queries} oracle queries (at most 256 per byte, about 128 on average), without the key.`, { queries }));
    return { pt, queries, trace };
  };
  PO.attack = (lab) => S.Sym.drain(PO.run(lab));

  // ---- ECB cut and paste: a profile token, forged into an administrator's
  At.ecbCutPaste = ({ seed = 1 } = {}) => {
    const r = S.Sym.rng(seed), key = S.Sym.bytes(r, 16), E = S.AES.cipher(key), n = 16, shelf = 1 + Math.floor(r() * 98);
    const server = {
      token: (name) => {
        if (/[&=]/.test(name)) throw new Error('names may not contain & or =');
        return Mo().encrypt('ecb', E, Mo().pkcs7(S.bytes.utf8(`user=${name}&shelf=${shelf}&role=reader`), n), { trace: false }).out;
      },
      read: (tok) => {
        const s = txt(Mo().unpkcs7(Mo().decrypt('ecb', E, tok, { trace: false }).out, n));
        return Object.fromEntries(s.split('&').map((kv) => kv.split('=')));
      },
    };
    const trace = [], prefix = 'user='.length, blk = (t, i) => t.subarray(n * i, n * i + n);
    // 1. a name that puts "admin" plus a full block of PKCS#7 padding at the start of the second block
    const fill = 'x'.repeat(n - prefix), adminBlock = 'admin' + String.fromCharCode(11).repeat(11);
    const t1 = server.token(fill + adminBlock), paste = blk(t1, 1);
    trace.push(step('ecb-1', `Register the name '${fill}admin' followed by eleven 0b bytes: block 2 of its token is E_k('admin' + padding) = ${hex(paste)}.`, { block: paste }));
    // 2. a name long enough that "role=" ends exactly at a block boundary
    const tail = `&shelf=${shelf}&role=`;
    let L = 1; while ((prefix + L + tail.length) % n) L++;
    const name = 'nadia.owen.reads'.slice(0, L) + 'x'.repeat(Math.max(0, L - 16));
    const t2 = server.token(name), keep = (prefix + name.length + tail.length) / n;
    trace.push(step('ecb-2', `Register a name of ${name.length} characters, so that 'user=${name}${tail}' fills exactly ${keep} blocks and the value of role starts a new block.`, { name }));
    // 3. paste
    const forged = new Uint8Array((keep + 1) * n); forged.set(t2.subarray(0, keep * n)); forged.set(paste, keep * n);
    const profile = server.read(forged), ok = profile.role === 'admin';
    trace.push(step('ecb-3', `Keep the first ${keep} blocks of the second token and append the 'admin' block: the server decrypts user=${profile.user}, shelf=${profile.shelf}, role=${profile.role}${ok ? ' — an administrator token, made without the key' : ''}.`, { profile, ok }));
    return { forged, profile, ok, trace };
  };

  // ---- CBC bit flipping: a cookie with a comment field, forged to say admin=true
  At.cbcBitFlip = ({ seed = 1 } = {}) => {
    const r = S.Sym.rng(seed), key = S.Sym.bytes(r, 16), E = S.AES.cipher(key), n = 16;
    const prefix = 'club=garden;member=', suffix = ';notes=bring%20gloves%20on%20saturday';
    const server = {
      make: (input) => {
        const safe = input.replace(/[;=]/g, (c) => '%' + c.charCodeAt(0).toString(16));
        const iv = S.Sym.bytes(r, n);
        return { iv, ct: Mo().encrypt('cbc', E, Mo().pkcs7(S.bytes.utf8(prefix + safe + suffix), n), { iv, trace: false }).out };
      },
      check: ({ iv, ct }) => { const s = txt(Mo().unpkcs7(Mo().decrypt('cbc', E, ct, { iv, trace: false }).out, n)); return { text: s, admin: s.split(';').includes('admin=true') }; },
    };
    const trace = [];
    // fill to the next block boundary, then one whole block of filler (it will be scrambled), then the payload
    const want = ';admin=true;', sent = '?admin?true?', lead = (n - (prefix.length % n)) % n;
    const input = 'A'.repeat(lead + n) + sent;
    const tok = server.make(input), start = (prefix.length + lead) / n; // the filler block index
    trace.push(step('flip-1', `Send '${input}': the server escapes ; and = but leaves ?, and the ciphertext has the filler in block ${start + 1} and '${sent}' in block ${start + 2}.`, { input }));
    const ct = Uint8Array.from(tok.ct);
    for (let i = 0; i < sent.length; i++) ct[start * n + i] ^= sent.charCodeAt(i) ^ want.charCodeAt(i);
    trace.push(step('flip-2', `XOR '?' ⊕ ';' = ${h2(0x3f ^ 0x3b)} and '?' ⊕ '=' = ${h2(0x3f ^ 0x3d)} into the matching bytes of ciphertext block ${start + 1}: block ${start + 2} decrypts with exactly those bits flipped.`, {}));
    const res = server.check({ iv: tok.iv, ct });
    trace.push(step('flip-3', `The server decrypts '${res.text}': block ${start + 1} is garbage, but ';admin=true;' is there${res.admin ? ', and the server grants administrator access' : ''}.`, res));
    return { forged: ct, text: res.text, ok: res.admin, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
