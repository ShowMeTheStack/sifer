// Part 7, public keys at work: the three jobs (encrypting to someone, signing so anyone can check, and agreeing a
// shared secret over an open line), each drawn as a message chart with an eavesdropper who sees every message.
(function (S) {
  'use strict';
  const P = S.PK, NT = () => S.NT;
  const enc = (s) => NT().fromBytes(new TextEncoder().encode(s));
  const H = (s) => NT().fromBytes(S.SHA256.hash(new TextEncoder().encode(s)));

  const toyKey = () => S.RSA.fromPrimes(347n, 331n, 17n);
  const setting = (job, size, msg) => P.memo('p07-uses', { job, size, msg }, () => {
    const real = size === 'real', o = { job, real };
    if (job === 'agree') {
      const group = real ? P.modp14() : S.DLP.groupZp(2027n);
      const a = real ? H('Alice keeps this exponent secret ' + msg) : 1234n, b = real ? H('Bob keeps this exponent secret ' + msg) : 1717n;
      const dh = S.DLP.dh(group, a, b);
      return Object.assign(o, { p: group.p, g: group.generator, a, b, A: dh.A, B: dh.B, K: dh.shared, agree: dh.agree });
    }
    const key = real ? P.rsaKey('rsa2048') : toyKey();
    Object.assign(o, { n: key.n, e: key.e, d: key.d, bits: key.bits });
    if (job === 'encrypt') {
      const text = real ? msg : msg.slice(0, 2);
      o.text = text; o.m = enc(text);
      o.c = S.RSA.encrypt(o.m, key).value; o.back = S.RSA.decrypt(o.c, key).value;
      return o;
    }
    o.text = msg; o.h = H(msg) % key.n; o.s = S.RSA.signRaw(o.h, key).value; o.v = S.RSA.verifyRaw(o.s, key).value;
    o.forged = msg.replace(/\d+/, (d) => String(Number(d) * 10)).replace(/^([^\d]*)$/, '$1!'); o.h2 = H(o.forged) % key.n;
    return o;
  });

  S.topic({
    id: 'p07-uses', family: 'p07-use', order: 10, title: 'What public keys are for',
    blurb: 'Three jobs. Encryption: anyone can lock a message with Bob\'s public key, only Bob\'s private key opens it. Signatures: only Alice\'s private key makes a signature that anyone can check with her public key. Key agreement: two people build a shared secret from public messages. An eavesdropper sees every message in all three.',
    inputs: [
      { id: 'job', kind: 'choice', label: 'Job', def: 'encrypt', options: [{ value: 'encrypt', label: 'encrypt to Bob' }, { value: 'sign', label: 'Alice signs' }, { value: 'agree', label: 'agree a key' }] },
      { id: 'size', kind: 'choice', label: 'Size', def: 'toy', options: [{ value: 'toy', label: 'toy numbers' }, { value: 'real', label: 'real (2048 bits)' }] },
      { id: 'msg', kind: 'text', label: 'Message', def: 'pay 40 at noon', check: (v) => (!v || v.length < 2 ? 'Message: at least two characters' : v.length > 60 ? 'Message: at most 60 characters' : null) },
    ],
    presets: [
      { label: 'Encrypt, toy', values: { job: 'encrypt', size: 'toy', msg: 'hi there' } },
      { label: 'Encrypt, RSA-2048', values: { job: 'encrypt', size: 'real', msg: 'the vault code is 7319' } },
      { label: 'Sign, toy', values: { job: 'sign', size: 'toy', msg: 'pay 40 at noon' } },
      { label: 'Sign, RSA-2048', values: { job: 'sign', size: 'real', msg: 'pay 40 at noon' } },
      { label: 'Agree a key, toy', values: { job: 'agree', size: 'toy' } },
      { label: 'Agree a key, 2048 bits', values: { job: 'agree', size: 'real' } },
    ],
    counters: [{ id: 'public', label: 'values sent in the open' }, { id: 'secret', label: 'values never sent' }],
    run(inp) {
      const o = setting(inp.job, inp.size, inp.msg), K = S.Kit.pk, job = inp.job;
      const F = new S.Frames(['public', 'secret']);
      const xs = [160, 450, 740], Y0 = 50, row = (k) => 150 + k * 68, Y1 = row(6) + 34;
      const lanes = K.lanes({ prefix: 'ln', names: ['Alice', 'Eve', 'Bob'], xs, y0: Y0, y1: Y1, cls: ['alice', 'eve', 'bob'] });
      const got = [];
      const add = (say, facts, phase, extra) => { F.add({ items: lanes.concat(got, extra || []), say, facts: Object.assign({ text: o.text, forged: o.forged, msg: inp.msg }, facts), meta: { phase } }); };
      const put = (...its) => got.push(...its);
      const blk = (key, lane, k, label, v, cls) => K.value({ key, x: xs[lane], y: row(k), label, value: v, max: 16, count: false, cls });
      const msg = (key, from, to, k, text, cls) => K.msg({ key, x1: xs[from], x2: xs[to], y: row(k), text, cls });
      const view = { x: -10, y: 10, w: 910, h: Y1 };

      if (job === 'encrypt') {
        add(`Bob wants to receive secrets from anyone, over a line Eve can read. ${o.real ? '' : 'With toy numbers the message is the two letters "' + o.text + '", as a number m = ' + o.m + '.'}`.trim(), { m: o.m }, 'start');
        F.set('secret', 1);
        put(blk('n', 2, 0, 'n', o.n, 'act'), blk('d', 2, 1, 'd', o.d, 'key'));
        add(`Bob makes a key pair: the public key n = ${P.n(o.n)} with e = ${o.e}, and the private key d = ${P.n(o.d)}, which never leaves him.`, { n: o.n, e: o.e, d: o.d }, 'keys');
        F.count('public');
        put(...msg('pub', 2, 0, 2, 'n, e = ' + o.e, 'act'), blk('eve1', 1, 3, 'e', o.e, 'bad'));
        add(`Bob publishes (n, e). Alice reads it, and so does Eve: a public key is meant to be seen.`, { e: o.e }, 'publish');
        put(blk('c', 0, 4, 'c = m^e mod n', o.c, 'act'));
        add(`Alice locks the message m = ${P.n(o.m)}${o.real ? ' ("' + o.text + '" as a number)' : ''} with Bob's public key: c = m^e mod n = ${P.n(o.c)}.`, { m: o.m, c: o.c }, 'lock');
        F.count('public');
        put(...msg('ct', 0, 2, 5, 'c', 'act'), blk('eve2', 1, 4, 'c', o.c, 'bad'));
        add(`Alice sends c. Eve copies it, but turning c back into m needs d: e-th roots modulo n are out of reach without it. Alice herself could not undo her own c.`, {}, 'send');
        put(blk('m', 2, 6, 'm = c^d mod n', o.back, 'good'));
        add(`Bob opens it with his private key: m = c^d mod n = ${P.n(o.back)}, "${o.text}" again. Anyone can lock a message for Bob; only Bob can open it.${o.real ? ' (Real systems pad m first, with OAEP: part 8.)' : ''}`, { m: o.back }, 'open');
      } else if (job === 'sign') {
        add(`Alice wants to send "${o.text}" so that anyone can check it came from her and was not changed on the way.`, {}, 'start');
        F.set('secret', 1);
        put(blk('n', 0, 0, 'n', o.n, 'act'), blk('d', 0, 1, 'd', o.d, 'key'));
        add(`Alice makes a key pair: public n = ${P.n(o.n)} and e = ${o.e}, private d = ${P.n(o.d)}.`, { n: o.n, e: o.e, d: o.d }, 'keys');
        F.count('public');
        put(...msg('pub', 0, 2, 2, 'n, e = ' + o.e, 'act'));
        add('Alice publishes her public key; Bob, Eve and everyone else can read it.', {}, 'publish');
        put(blk('s', 0, 3, 's = h^d mod n', o.s, 'key'));
        add(`Alice hashes the message, h = SHA-256("${o.text}") mod n = ${P.n(o.h)}, and signs with her private key: s = h^d mod n = ${P.n(o.s)}. Only d can make this s.`, { h: o.h, s: o.s }, 'sign');
        F.count('public', 2);
        put(...msg('sm', 0, 2, 4, 'message, s', 'act'));
        add('She sends the message and s in the open. Nothing here is secret: a signature is about who wrote it, not about hiding it.', {}, 'send');
        put(blk('v', 2, 5, 's^e mod n', o.v, o.v === o.h ? 'good' : 'bad'));
        add(`Bob checks with Alice's public key: s^e mod n = ${P.n(o.v)}, which equals the hash h of the message he received. Valid: it came from the holder of d.`, { v: o.v, h: o.h }, 'verify');
        put(blk('h2', 1, 6, 'h′', o.h2, 'bad'));
        add(`If Eve changes the message to "${o.forged}", its hash becomes h′ = ${P.n(o.h2)}, which is not s^e mod n, and Bob rejects it. To forge a signature for the new hash she would need d.`, { h2: o.h2 }, 'forge');
      } else {
        add(`Alice and Bob want a shared secret key but have only an open line, which Eve reads.`, {}, 'start');
        F.set('public', 2);
        put(blk('p', 1, 0, 'p', o.p, 'act'), blk('g', 1, 1, 'g', o.g, 'act'));
        add(`They agree in public on a prime p = ${P.n(o.p)} and a base g = ${o.g}. Eve knows them too.`, { p: o.p, g: o.g }, 'params');
        F.set('secret', 2);
        put(blk('A', 0, 2, 'A = g^a', o.A, 'act'), blk('B', 2, 2, 'B = g^b', o.B, 'act'));
        add(`Each picks a secret exponent, a = ${P.n(o.a)} and b = ${P.n(o.b)}, and computes A = g^a mod p = ${P.n(o.A)} and B = g^b mod p = ${P.n(o.B)}.`, { a: o.a, b: o.b, A: o.A, B: o.B }, 'secrets');
        F.count('public', 2);
        put(...msg('mA', 0, 2, 3, 'A', 'act'), ...msg('mB', 2, 0, 4, 'B', 'act'));
        add('They swap A and B in the open. Eve now has p, g, A and B.', {}, 'swap');
        put(blk('KA', 0, 5, 'B^a', o.K, 'good'), blk('KB', 2, 5, 'A^b', o.K, 'good'));
        add(`Alice computes B^a and Bob computes A^b: both are g^(ab) mod p = ${P.n(o.K)}. A shared secret, and it never crossed the line.`, { K: o.K }, 'shared');
        put(blk('eve', 1, 6, 'needs a = log_g A', o.A, 'bad'));
        add(`Eve would need a or b, a discrete logarithm: ${o.real ? 'hopeless for ' + P.an(P.bits(o.p)) + '-bit p' : 'easy here with p = ' + o.p + ', hopeless with ' + P.an(P.bits(P.modp14().p)) + '-bit p'}. Unauthenticated, though, the exchange can be hijacked by someone who replaces A and B: part 9.`, { p: o.p, bits: P.bits(o.p), big: P.bits(P.modp14().p) }, 'eve');
      }
      for (const f of F.list) f.narrowView = { x: -10, y: 10, w: 910, h: Y1 };
      return { frames: P.fix(F.list, view), def: P.def('Who uses which key', ['encrypt to Bob:  c = m^e mod n   (Bob\'s public key)', 'Bob decrypts:    m = c^d mod n   (Bob\'s private key)', 'Alice signs:     s = H(m)^d mod n (her private key)', 'anyone verifies: s^e mod n = H(m) (her public key)', 'key agreement:   A = g^a, B = g^b, K = g^(ab)']) };
    },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'publish' && fr[i + 1].meta.phase === 'lock', pick: 'option', ask: 'Which key does Alice use to lock the message for Bob?', options: ['Bob\'s public key', 'Bob\'s private key', 'Alice\'s private key', 'a key they shared earlier'], answer: 'Bob\'s public key', explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta.phase === 'publish' && fr[i + 1].meta.phase === 'sign', pick: 'option', ask: 'Which key does Alice sign with?', options: ['her private key', 'her public key', 'Bob\'s public key'], answer: 'her private key', explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta.phase === 'swap', pick: 'option', ask: 'Will Alice\'s B^a and Bob\'s A^b be equal?', options: ['yes', 'no', 'only by luck'], answer: 'yes', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'To send Bob a secret, Alice encrypts with…', options: ['her private key', 'her public key', 'Bob\'s public key', 'Bob\'s private key'], answer: 2, why: 'Anyone may use Bob\'s public key; only Bob\'s private key undoes it.' },
      { q: 'A signature is checked with…', options: ['the signer\'s public key', 'the signer\'s private key', 'the reader\'s private key', 'a shared secret'], answer: 0, why: 'Only the signer\'s private key makes it; anyone can check it with the public key.' },
      { q: 'In a key agreement, what does Eve see?', options: ['nothing', 'p, g, A and B', 'a and b', 'the shared key'], answer: 1, why: 'Every message is public; the secrets a and b and the key g^(ab) never cross the line.' },
      { q: 'What does a signature give that encryption does not?', options: ['secrecy', 'proof of who wrote the message and that it was not changed', 'speed', 'a shorter message'], answer: 1, why: 'A signature authenticates and protects integrity; it does not hide the message.' },
      { q: 'Why is the message hashed before signing?', options: ['to hide it', 'so a message of any length becomes one number below n', 'to make it longer', 'it is not'], answer: 1, why: 'The hash maps any message to a fixed-size value that fits the key, and a change to the message changes it.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
// Part 7, public keys at work: key lengths and security levels, a table to play with.
(function (S) {
  'use strict';
  const P = S.PK;
  const fmt = (v) => (Number(v) < 10000 ? String(v) : Number(v).toLocaleString('en-US'));
  S.topic({
    id: 'p07-levels', family: 'p07-use', order: 20, title: 'Key lengths and security levels',
    blurb: 'A security level of s bits means the best known attack needs about 2^s operations. Symmetric keys reach it with s bits; elliptic curves need about 2s, because of Pollard\'s rho; RSA and finite-field Diffie–Hellman need thousands of bits, because the number field sieve is far faster than brute force. Pick a level, then rate a key of your own.',
    inputs: [
      { id: 'level', kind: 'choice', label: 'Security level', def: '128', options: P.LEVELS.map((l) => ({ value: String(l.s), label: l.s + ' bits' })) },
      { id: 'rsa', kind: 'number', label: 'Your RSA modulus (bits)', def: 2048, min: 256, max: 16384 },
      { id: 'ecc', kind: 'number', label: 'Your curve (bits)', def: 256, min: 64, max: 571 },
    ],
    presets: [
      { label: '128 bits: today\'s usual choice', values: { level: '128', rsa: 3072, ecc: 256 } },
      { label: 'A 2048-bit key', values: { level: '112', rsa: 2048, ecc: 224 } },
      { label: 'Long-term: 256 bits', values: { level: '256', rsa: 15360, ecc: 521 } },
      { label: 'Old: 1024-bit RSA', values: { level: '80', rsa: 1024, ecc: 160 } },
      { label: 'Broken: 512-bit RSA', values: { level: '80', rsa: 512, ecc: 112 } },
    ],
    counters: [{ id: 'rows', label: 'levels compared' }],
    run(inp) {
      const F = new S.Frames(['rows']);
      const L = P.LEVELS, li = L.findIndex((l) => String(l.s) === String(inp.level)), lv = L[li];
      const view = { x: -10, y: 0, w: 900, h: 560 };
      const rows = L.map((l) => [String(l.s), l.sym, fmt(l.rsa), String(l.sub), String(l.ecc)]);
      const table = (hot, act) => S.Kit.table.draw({ prefix: 'tb', x: 0, y: 40, colHead: ['security', 'symmetric', 'RSA, DH modulus', 'DH subgroup', 'elliptic curve'], rows, mono: true, size: 15, hot: hot || [], act: act || [], title: 'comparable strengths, in bits (NIST SP 800-57)' }).items;
      const x0 = 190, W = 600, by = 350, maxB = Math.max(lv.rsa, inp.rsa) * 1.08;
      const bars = (l, mine) => {
        const its = [P.title('bt', 0, by - 18, `the key sizes for ${l.s}-bit security, on one scale`)];
        const list = [['symmetric key', l.s, 'good'], ['elliptic curve', l.ecc, 'act'], ['RSA modulus', l.rsa, 'hot']].concat(mine || []);
        list.forEach(([label, bits, cls], i) => {
          const y = by + i * 40, w = Math.max(3, P.r2((bits / maxB) * W));
          its.push(P.t('bl' + i, x0 - 12, y + 18, label, 'strong', 'end', 14), { key: 'bar' + i, kind: 'cell', x: x0, y, w, h: 26, rx: 3, text: '', cls }, P.t('bv' + i, x0 + w + 10, y + 18, fmt(bits) + ' bits', 'mono', 'start', 14));
        });
        return its;
      };
      const add = (items, say, facts, phase, nv) => F.add({ items, say, facts, meta: { phase }, narrowView: nv });
      const tview = { x: -10, y: 0, w: 720, h: 300 }, bview = { x: -10, y: by - 50, w: 900, h: 220 };
      add(table(), 'Five security levels and the key sizes that reach each, as the standard tables give them. A level of s bits means about 2^s operations for the best known attack.', {}, 'table', tview);
      L.forEach((l, i) => {
        F.set('rows', i + 1);
        add(table([[i, 0]], [[i, 1], [i, 2], [i, 4]]), `${l.s} bits: ${l.sym} for a symmetric key, ${P.an(fmt(l.rsa))}-bit RSA or Diffie–Hellman modulus, ${P.an(l.ecc)}-bit elliptic curve. The modulus is ${Math.round(l.rsa / l.ecc)} times the size of the curve.`, { s: l.s, rsa: l.rsa, ecc: l.ecc, ratio: Math.round(l.rsa / l.ecc), sym: l.sym }, 'row', tview);
      });
      add(table([[li, 0]]).concat(bars(lv)), `At ${lv.s} bits, on one scale: ${lv.s} bits of symmetric key, ${lv.ecc} bits of curve, ${fmt(lv.rsa)} bits of RSA modulus. Brute force on a key costs 2^${lv.s}; Pollard's rho on a curve costs about the square root of its size, so the curve needs twice the bits; the number field sieve is so much faster than either that a modulus needs thousands.`, { s: lv.s, ecc: lv.ecc, rsa: lv.rsa }, 'bars', bview);
      // your own key
      const g = P.gnfsBits(inp.rsa), r = P.rhoBits(inp.ecc);
      const reach = (bits) => { let k = -1; for (let i = 0; i < L.length; i++) if (bits >= L[i].s) k = i; return k; };
      const rTab = (() => { let k = -1; for (let i = 0; i < L.length; i++) if (inp.rsa >= L[i].rsa) k = i; return k; })();
      const eTab = (() => { let k = -1; for (let i = 0; i < L.length; i++) if (inp.ecc >= L[i].ecc) k = i; return k; })();
      const mine = [['your RSA', inp.rsa, 'key'], ['your curve', inp.ecc, 'key']];
      const verdict = (k) => (k < 0 ? 'below every level in the table' : `enough for ${L[k].s} bits`);
      add(table(rTab >= 0 ? [[rTab, 2]] : []).concat(bars(lv, mine)), `Your ${fmt(inp.rsa)}-bit modulus: the number field sieve's running time, without its o(1) term, is about 2^${Math.round(g)}. By the table it is ${verdict(rTab)}${rTab >= 0 && rTab < L.length - 1 ? `; the next level needs ${fmt(L[rTab + 1].rsa)} bits` : ''}.${inp.rsa < 1024 ? ' Moduli this short have been factored in public.' : ''}`, { rsa: inp.rsa, g: Math.round(g), next: rTab >= 0 && rTab < L.length - 1 ? L[rTab + 1].rsa : 0, level: rTab >= 0 ? L[rTab].s : 0 }, 'mine-rsa', bview);
      add(table(eTab >= 0 ? [[eTab, 4]] : []).concat(bars(lv, mine)), `Your ${inp.ecc}-bit curve: Pollard's rho needs about √(π·2^${inp.ecc}/4) steps, 2^${r.toFixed(1)}: ${reach(r) < 0 ? 'below every level here' : 'at least ' + L[reach(r)].s + ' bits'}. By the table it is ${verdict(eTab)}.`, { ecc: inp.ecc, r: r, rr: r.toFixed(1), level: eTab >= 0 ? L[eTab].s : 0, reach: reach(r) >= 0 ? L[reach(r)].s : 0 }, 'mine-ecc', bview);
      add(table([[li, 0]]).concat(bars(lv, mine)), `So a public key is always much longer than a symmetric key of the same strength, and RSA's grows fastest: from 128 to 256 bits of security the curve doubles but the modulus grows ${(15360 / 3072).toFixed(0)}-fold. That is one reason elliptic curves replaced RSA in most new protocols.`, { a: 128, b: 256, k: 15360 / 3072, rsa1: 3072, rsa2: 15360 }, 'end', bview);
      return { frames: P.fix(F.list, view), def: P.def('Security levels', ['s bits of security: about 2^s operations to break', 'symmetric: brute force, 2^k for a k-bit key', 'curve of n bits: rho, about 2^(n/2)', 'RSA / DH, n-bit modulus: number field sieve,', '  exp(1.923·(ln N)^(1/3)·(ln ln N)^(2/3))']) };
    },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'table', pick: 'option', ask: 'For 256 bits of security, roughly how long must an RSA modulus be?', options: ['512 bits', '2048 bits', '4096 bits', '15360 bits'], answer: '15360 bits', explain: (fr, i) => fr[i + 5].say },
      { at: (f, i, fr) => f.meta.phase === 'bars', pick: 'option', ask: 'Will your RSA modulus reach the level you picked?', options: ['yes', 'no'], answer: (fr, i) => (fr[i + 1].facts.rsa >= fr[i].facts.rsa ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Which gives about 128-bit security?', options: ['RSA-2048', 'RSA-3072', 'a 128-bit curve', 'RSA-1024'], answer: 1, why: 'The tables pair 128 bits with a 3072-bit modulus and a 256-bit curve.' },
      { q: 'Why does a 256-bit curve give only about 128 bits of security?', options: ['Pollard\'s rho needs about the square root of the group size', 'Grover\'s algorithm', 'half the bits are public', 'it does not'], answer: 0, why: 'Generic attacks on a group of order about 2^256 take about 2^128 steps.' },
      { q: 'Why must RSA moduli be so much longer than symmetric keys?', options: ['RSA is slower', 'the number field sieve factors far faster than brute force', 'RSA keys are public', 'to fit the message'], answer: 1, why: 'Factoring has subexponential algorithms; the best attack on a good symmetric cipher is still brute force.' },
      { q: 'Going from 128 to 256 bits of security, the RSA modulus grows…', options: ['2 times', 'about 5 times', '128 times', 'not at all'], answer: 1, why: '3072 to 15360 bits: five times, while the curve only doubles.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
// Part 7, public keys at work: hybrid encryption. A fresh symmetric key encrypts the message (AES-GCM); the public
// key encrypts only that short key (RSA-OAEP). The toy version wraps a 16-bit key with toy RSA.
(function (S) {
  'use strict';
  const P = S.PK, NT = () => S.NT;
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const short = (b, n) => { const h = hex(b); return h.length > 2 * (n || 6) ? h.slice(0, 2 * (n || 6)) + '…' : h; };
  const utf = (s) => new TextEncoder().encode(s);
  /** the toy stream: SHA-256(K ‖ counter) blocks, XORed onto the message */
  const toyStream = (K, data) => { const out = new Uint8Array(data.length); for (let i = 0; i < data.length; i += 32) { const ks = S.SHA256.hash(Uint8Array.from([...K, i >> 5])); for (let j = 0; j < 32 && i + j < data.length; j++) out[i + j] = data[i + j] ^ ks[j]; } return out; };

  const setting = (size, msg, seed) => P.memo('p07-hybrid', { size, msg, seed }, () => S.RSA.seeded(seed, () => {
    const m = utf(msg), o = { size, real: size !== 'toy', len: m.length };
    if (!o.real) {
      const key = S.RSA.fromPrimes(347n, 331n, 17n);
      const K = NT().randomBytes(2), kInt = NT().fromBytes(K);
      const w = S.RSA.encrypt(kInt, key).value, back = S.RSA.decrypt(w, key).value;
      const ct = toyStream(K, m), pt = toyStream(NT().toBytes(back, 2), ct);
      return Object.assign(o, { key, n: key.n, K, kInt, wrapped: w, wrappedBytes: NT().byteLength(w), back, ct, pt: new TextDecoder().decode(pt), ok: true, k: NT().byteLength(key.n) });
    }
    const key = P.rsaKey(size), k = NT().byteLength(key.n);
    const K = NT().randomBytes(16), iv = NT().randomBytes(12);
    const g = S.GCM.encrypt(K, iv, m);
    const wrap = S.RSA.oaepEncrypt(key, K, {});
    const un = S.RSA.oaepDecrypt(key, wrap.c);
    const d = S.GCM.decrypt(un.msg, iv, g.ct, g.tag);
    const per = k - 2 * 32 - 2;
    return Object.assign(o, { key, n: key.n, k, K, iv, ct: g.ct, tag: g.tag, wrapped: wrap.c, wrappedBytes: wrap.cBytes.length, unK: un.msg, pt: new TextDecoder().decode(d.pt), ok: d.ok, per, rsaBlocks: Math.ceil(m.length / per), aesBlocks: Math.ceil(m.length / 16) });
  }));

  S.topic({
    id: 'p07-hybrid', family: 'p07-use', order: 30, title: 'Hybrid encryption',
    blurb: 'Public-key encryption is slow and holds only a short message, so it is never used on the data itself. A fresh symmetric key encrypts the message; the public key encrypts only that key. The receiver opens the key with the private key, then the message with the key.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Keys', def: 'rsa2048', options: [{ value: 'toy', label: 'toy RSA and a 16-bit key' }, { value: 'rsa1024', label: 'RSA-1024 and AES-128' }, { value: 'rsa2048', label: 'RSA-2048 and AES-128' }, { value: 'rsa3072', label: 'RSA-3072 and AES-128' }] },
      { id: 'msg', kind: 'text', label: 'Message', def: 'Bring the blue notebook to the reading room on Thursday.', check: (v) => (!v ? 'Message: write something' : v.length > 600 ? 'Message: at most 600 characters' : null) },
      { id: 'seed', kind: 'number', label: 'Randomness (seed)', def: 7, min: 1, max: 99999 },
    ],
    presets: [
      { label: 'RSA-2048 and AES-128-GCM', values: { size: 'rsa2048', seed: 7 } },
      { label: 'Toy numbers', values: { size: 'toy', msg: 'meet at the pier', seed: 3 } },
      { label: 'A long message', values: { size: 'rsa2048', msg: 'The quarterly figures are attached. '.repeat(12).trim(), seed: 11 } },
      { label: 'RSA-3072', values: { size: 'rsa3072', msg: 'one short line', seed: 5 } },
    ],
    counters: [{ id: 'pk', label: 'public-key operations' }, { id: 'sym', label: 'symmetric blocks' }],
    run(inp) {
      const o = setting(inp.size, inp.msg, inp.seed), K = S.Kit.pk, real = o.real;
      const F = new S.Frames(['pk', 'sym']);
      const view = { x: -10, y: 10, w: 930, h: 540 };
      const symName = real ? 'AES-128-GCM' : 'toy stream', wrapName = real ? 'RSA-OAEP' : 'toy RSA';
      const stage = (k) => {
        const N = S.Kit.flow.net('hy'), items = [];
        items.push(...P.panel('pa', 0, 30, 420, 470, 'Alice, the sender'), ...P.panel('pb', 490, 30, 420, 470, 'Bob, the receiver'));
        // Alice
        N.box('K', 100, 110, 150, 46, ['session key K', short(o.K, 6)], 'key val2' + (k === 1 ? ' hot' : ''));
        N.box('m', 310, 110, 170, 46, ['message', o.len + ' bytes'], 'val2');
        N.box('enc', 310, 230, 150, 40, symName, 'cipher' + (k === 2 ? ' act' : ''));
        N.box('wrap', 100, 230, 150, 40, wrapName + ', pk', 'cipher' + (k === 3 ? ' act' : ''));
        if (k >= 2) N.box('ct', 310, 345, 170, 46, ['ciphertext', real ? o.ct.length + ' bytes + tag' : o.ct.length + ' bytes'], 'val2');
        if (k >= 3) N.box('wk', 100, 345, 150, 46, ['wrapped key', o.wrappedBytes + ' bytes'], 'val2 key');
        N.wire('mw', [N.port('m', 's'), N.port('enc', 'n')], { head: true });
        N.wire('kw', [N.port('K', 's'), N.port('wrap', 'n')], { head: true, cls: 'key' });
        N.wire('kw2', [N.port('K', 'e'), [205, 110], [205, 230], N.port('enc', 'w')], { head: true, cls: 'key' });
        if (k >= 2) N.wire('cw', [N.port('enc', 's'), N.port('ct', 'n')], { head: true });
        if (k >= 3) N.wire('ww', [N.port('wrap', 's'), N.port('wk', 'n')], { head: true });
        // the envelope
        if (k >= 4) {
          N.box('env', 455, 450, 220, 46, ['sent: ' + (o.wrappedBytes + o.ct.length + (real ? 28 : 0)) + ' bytes', real ? 'key, nonce, data, tag' : 'key, data'], 'val2 act');
          N.wire('e1', [N.port('wk', 's'), [100, 450], N.port('env', 'w')], { head: true });
          N.wire('e2', [N.port('ct', 's'), [310, 420], [430, 420], [430, 427]], { head: true });
        }
        if (k >= 5) {
          N.box('unwrap', 590, 345, 160, 40, wrapName + ', sk', 'cipher' + (k === 5 ? ' act' : ''));
          N.box('K2', 590, 230, 150, 46, ['session key K', short(real ? o.unK : NT().toBytes(o.back, 2), 6)], 'key val2' + (k === 5 ? ' hot' : ''));
          N.wire('u1', [N.port('env', 'e', -0.45), [590, 439.65], N.port('unwrap', 's')], { head: true });
          N.wire('u2', [N.port('unwrap', 'n'), N.port('K2', 's')], { head: true, cls: 'key' });
        }
        if (k >= 6) {
          N.box('dec', 800, 230, 150, 40, symName, 'cipher act');
          N.box('m2', 800, 110, 170, 46, ['message', o.ok ? 'tag checked' : 'rejected'], 'val2 ' + (o.ok ? 'good' : 'bad'));
          N.wire('d1', [N.port('env', 'e', 0.45), [800, 460.35], N.port('dec', 's')], { head: true });
          N.wire('d2', [N.port('K2', 'e'), N.port('dec', 'w')], { head: true, cls: 'key' });
          N.wire('d3', [N.port('dec', 'n'), N.port('m2', 's')], { head: true });
        }
        return items.concat(N.items);
      };
      const add = (k, say, facts, phase) => F.add({ items: stage(k), say, facts: Object.assign({ len: o.len, k: o.k, n: o.n, ct: short(o.ct, 6), tag: real ? short(o.tag, 6) : '' }, facts), meta: { phase, o } });
      add(0, `Alice has a message of ${o.len} bytes for Bob and knows his public key, ${real ? P.an(o.key.bits) + '-bit RSA key' : 'a toy RSA key n = ' + o.n}. ${real ? `RSA-OAEP with it holds at most ${o.per} bytes, and each operation is slow.` : 'The toy key holds less than 17 bits at a time.'}`, { bits: real ? o.key.bits : 0, per: o.per }, 'start');
      add(1, `She draws a fresh random session key K = ${hex(o.K)}: ${real ? '16 bytes, 128 bits' : '2 bytes, a toy 16 bits'}, used for this message only.`, { K: hex(o.K) }, 'key');
      F.set('sym', real ? o.aesBlocks : Math.ceil(o.len / 32));
      add(2, real ? `The message goes through AES-128-GCM under K: ${P.plural(o.aesBlocks, 'block')} of 16 bytes, fast, giving ${o.ct.length} bytes of ciphertext beginning ${short(o.ct, 6)} and a 16-byte tag ${short(o.tag, 6)} that detects any change.` : `The message is XORed with a keystream made from K: ${o.ct.length} bytes of ciphertext beginning ${short(o.ct, 6)}.`, { blocks: o.aesBlocks, ct: o.ct.length }, 'data');
      F.set('pk', 1);
      add(3, real ? `Only K goes through RSA-OAEP with Bob's public key: one RSA operation, and the wrapped key c = ${P.n(o.wrapped)} fills ${o.wrappedBytes} bytes.` : `Only K, as the number ${o.kInt}, goes through toy RSA: c = K^e mod n = ${o.wrapped}.`, { c: o.wrapped, bytes: o.wrappedBytes, kInt: o.kInt }, 'wrap');
      add(4, `She sends both: the wrapped key and the ciphertext${real ? ' with its nonce and tag' : ''}, ${o.wrappedBytes + o.ct.length + (real ? 28 : 0)} bytes in all. Eve sees all of it and has neither K nor Bob's private key.`, { total: o.wrappedBytes + o.ct.length + (real ? 28 : 0) }, 'send');
      F.count('pk');
      add(5, `Bob unwraps with his private key: one RSA operation gives K = ${hex(real ? o.unK : NT().toBytes(o.back, 2))} again.`, { K: hex(real ? o.unK : NT().toBytes(o.back, 2)) }, 'unwrap');
      F.count('sym', real ? o.aesBlocks : Math.ceil(o.len / 32));
      add(6, `With K he decrypts the data${real ? ', checking the tag first' : ''}: "${o.pt.length > 60 ? o.pt.slice(0, 57) + '…' : o.pt}"${/[.!?]$/.test(o.pt) && o.pt.length <= 60 ? '' : '.'}`, { pt: o.pt }, 'open');
      const rsaOnly = real ? o.rsaBlocks : o.len;
      add(6, real ? `Why not RSA alone? This message would take ${P.plural(o.rsaBlocks, 'RSA-OAEP block')} of at most ${o.per} bytes, each ${o.wrappedBytes} bytes long and each a slow private-key operation for Bob. Hybrid: one RSA operation for any length, and the bulk work in AES.` : `Why not toy RSA alone? It would need one operation for every byte of the ${o.len}-byte message. Hybrid: one public-key operation whatever the length.`, { rsaOnly, per: o.per, bytes: o.wrappedBytes }, 'why');
      F.list.forEach((f, i) => { f.narrowView = i < 5 ? { x: -10, y: 20, w: 440, h: 500 } : i < 7 ? { x: 480, y: 20, w: 440, h: 500 } : view; });
      return { frames: P.fix(F.list, view), def: P.def('Hybrid encryption', ['K ← random session key', 'C = E_K(message)        (symmetric, fast)', 'W = RSA-OAEP_pk(K)      (one public-key operation)', 'send (W, C)', 'Bob: K = RSA-OAEP⁻¹_sk(W), message = D_K(C)']) };
    },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'data', pick: 'option', ask: 'What does Alice encrypt with Bob\'s public key?', options: ['the whole message', 'only the session key K', 'the ciphertext', 'nothing'], answer: 'only the session key K', explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta.phase === 'send', pick: 'option', ask: 'How many public-key operations does Bob need?', options: ['1', 'one per block', 'none'], answer: '1', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'In hybrid encryption the public key encrypts…', options: ['the message', 'a fresh symmetric key', 'the hash', 'the nonce'], answer: 1, why: 'Only the short session key goes through the slow public-key operation.' },
      { q: 'Why not encrypt a long file with RSA alone?', options: ['RSA is slow and holds only a short block', 'RSA cannot encrypt bytes', 'it is less secure than AES', 'files are public'], answer: 0, why: 'Each RSA-OAEP block holds at most k − 66 bytes and costs a full modular exponentiation.' },
      { q: 'How long is a session key wrapped with RSA-2048?', options: ['16 bytes', '32 bytes', '256 bytes', '2048 bytes'], answer: 2, why: 'An RSA ciphertext is as long as the modulus: 2048 bits = 256 bytes.' },
      { q: 'Why a fresh session key for every message?', options: ['so one leaked key exposes one message only', 'AES needs it', 'to save space', 'RSA requires it'], answer: 0, why: 'Each key protects one message; nothing else depends on it.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
