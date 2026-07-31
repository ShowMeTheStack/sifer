// The public-key bench (#bench/pk): RSA at toy sizes (primes you pick) or real sizes (a key searched for in a Web
// Worker, Miller–Rabin candidate by candidate), textbook and OAEP encryption, decryption directly and by the CRT,
// textbook and PSS signatures; then Diffie–Hellman, Elgamal and DSA (bench-pk2.js), and Schnorr, ECDH, X25519,
// ECDSA and Ed25519 (bench-pk3.js). Every exponentiation is shown
// bit by bit at toy sizes, and counted at real sizes.
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const MB = () => S.MathBench, U = () => S.BenchUI;
  const TOOLS = [['rsa', 'RSA'], ['dh', 'Diffie–Hellman'], ['elgamal', 'Elgamal'], ['dsa', 'DSA'], ['schnorr', 'Schnorr'], ['ecdh', 'ECDH'], ['x25519', 'X25519'], ['ecdsa', 'ECDSA'], ['ed25519', 'Ed25519']];
  const DEF = {
    tool: 'rsa',
    rsa: { size: 'toy', p: '1009', q: '1013', e: '17', real: null, msgKind: 'number', msg: '424242', text: 'Meet at the old mill', pad: 'textbook' },
    dh: { group: 'toy', p: '2039', g: '7', a: '1234', b: '777', mitm: false, m: '99' },
    elgamal: { group: 'toy', p: '2039', g: '7', x: '1500', m: '1066', k: '' },
    dsa: { size: 'toy', qMin: '1009', x: '', k: '', msg: 'Pay the ferryman 3 coins', real: null },
    schnorr: { qMin: '1013', x: '', k: '', msg: 'The lantern is lit' },
    ecdh: { curve: 'toy', a: '', b: '' },
    x25519: { a: '', b: '' },
    ecdsa: { curve: 'toy', d: '', nonce: 'rfc6979', k: '29', msg: 'Ship forty crates to the north quay' },
    ed25519: { sk: '', msg: 'Gate code changes at dawn' },
  };
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const PK = (S.PkTools = {});
  const K = (S.PkKit = {});

  S.Bench.tab('pk', {
    title: 'Public key', icon: 'key', order: 30,
    blurb: 'RSA, Diffie–Hellman, Elgamal, DSA and Schnorr; ECDH, X25519, ECDSA and Ed25519, toy beside real.',
    open(host, saved, ctx) {
      const st = clone(DEF);
      for (const k of Object.keys(DEF)) { if (typeof DEF[k] === 'object') Object.assign(st[k], (saved || {})[k] || {}); else if (saved && saved[k] !== undefined) st[k] = saved[k]; }
      if (!S.NT || !S.RSA) { host.appendChild(U().missing('The public-key engines')); return { state: () => st }; }
      const jobs = [];
      const draw = () => {
        for (const j of jobs.splice(0)) j.stop();
        host.innerHTML = '';
        const fr = MB().frame(host, { id: 'pk', title: 'Public key', blurb: 'RSA from two primes to a 2048-bit key; Diffie–Hellman, Elgamal, DSA and Schnorr; and on elliptic curves ECDH, X25519, ECDSA and Ed25519. Toy sizes show every step; real sizes prove it is the same arithmetic.', tools: TOOLS, tool: st.tool, ctx, onTool: (t) => { st.tool = t; ctx.save(); draw(); } });
        PK[st.tool](fr.left, fr.right, st[st.tool], () => ctx.save(), (j) => jobs.push(j));
      };
      draw();
      return { state: () => st, dispose() { for (const j of jobs.splice(0)) j.stop(); } };
    },
  });

  /** x^e mod n shown: the bit table when e is short, a count with the first and last steps when it is long */
  K.pow = function (title, x, e, n, sub) {
    const r = S.ModExp.pow(x, e, n);
    const rows = r.steps.map((s) => [s.i, s.bit, s.sq === null ? 'start: x' : MB().n(s.sq), s.bit && s.sq !== null ? MB().n(s.mul) : '—', MB().n(s.value)]);
    const long = rows.length > 24;
    const shown = long ? rows.slice(0, 6).concat([['…', '…', (rows.length - 10) + ' more bits', '', '']], rows.slice(-4)) : rows;
    return MB().result(title, sub || null, MB().table(['step', 'bit', 'squared', 'times base', 'running value'], shown, { hl: shown.length - 1 }),
      MB().facts(['result', MB().n(r.value)], ['work', String(r.bits).length + '-bit exponent: ' + r.squarings + ' squarings and ' + r.multiplications + ' multiplications']));
  };
  /** a key's numbers */
  K.keyFacts = (key) => h('div.pk-keys', MB().facts(['n', MB().n(key.n)], ['e', MB().n(key.e)], ['d', h('span.pk-secret', MB().n(key.d))], ['p', h('span.pk-secret', MB().n(key.p))], ['q', h('span.pk-secret', MB().n(key.q))], ['φ(n)', MB().n(key.phi)], ['dp, dq', h('span.pk-secret', MB().n(key.dp) + ', ' + MB().n(key.dq))], ['q⁻¹ mod p', MB().n(key.qinv)]));
  /** a running search: a bar, the phase and the last candidates */
  K.progress = function (label) {
    const bar = h('div.pk-bar', h('i')), msg = h('div.pk-prog-t', label), log = h('pre.pk-log', { 'aria-live': 'off' });
    const lines = [];
    return {
      el: h('div.pk-prog', { id: 'pkProgress' }, msg, bar, log),
      set(text, frac, line) { msg.textContent = text; bar.firstChild.style.width = Math.round(100 * Math.min(1, frac)) + '%'; if (line) { lines.push(line); if (lines.length > 6) lines.shift(); log.textContent = lines.join('\n'); } },
    };
  };
  K.outcome = (v) => (!v || !v.outcome ? '' : v.outcome.kind === 'small' ? 'divisible by ' + v.outcome.by : v.outcome.kind === 'witness' ? 'Miller–Rabin witness ' + String(v.outcome.by).slice(0, 12) + (String(v.outcome.by).length > 12 ? '…' : '') : v.outcome.kind === 'prime' ? 'prime after ' + v.outcome.rounds + ' rounds' : v.outcome.kind);
  const bytesText = (b) => { try { return new TextDecoder('utf-8', { fatal: true }).decode(b); } catch (e) { return null; } };

  // ---- RSA ----------------------------------------------------------------------------------------------------------
  PK.rsa = function (left, right, o, save, track) {
    const N = S.NT, R = S.RSA;
    let key = null;
    const keyOf = () => {
      if (o.size === 'toy') {
        const p = MB().big(o.p, 'p', { min: 3 }), q = MB().big(o.q, 'q', { min: 3 }), e = MB().big(o.e, 'e', { min: 3 });
        for (const [v, nm] of [[p, 'p'], [q, 'q']]) if (!N.isProbablePrime(v)) throw new Error(nm + ' = ' + v + ' is not prime; the next prime is ' + N.nextPrime(v) + '.');
        if (p === q) throw new Error('p and q must differ: with p = q, n = p² and φ(n) is easy to find.');
        if (N.gcd(e, (p - 1n) * (q - 1n)) !== 1n) throw new Error('e = ' + e + ' shares a factor with φ(n) = ' + (p - 1n) * (q - 1n) + ', so it has no inverse d: pick another e.');
        return R.fromPrimes(p, q, e);
      }
      const r = o.real && o.real[o.size];
      return r ? R.fromPrimes(BigInt(r.p), BigInt(r.q), BigInt(r.e)) : null;
    };
    const run = () => {
      right.innerHTML = '';
      key = MB().guard(right, keyOf);
      if (!key) { if (o.size !== 'toy' && !right.firstChild) right.appendChild(MB().result('No ' + o.size + '-bit key yet', 'Press Generate: the search runs in the background, so the page stays responsive.')); return; }
      const toy = o.size === 'toy';
      right.append(MB().result('The key', key.bits + '-bit modulus n = p·q. The public key is (n, e); everything in rose is private.', K.keyFacts(key), toy ? U().trace(key.trace.slice(-4)) : null));
      MB().guard(right, () => {
        const k = N.byteLength(key.n);
        if (o.pad === 'oaep') {
          if (k < 66) throw new Error('OAEP with SHA-256 needs a modulus of at least 66 bytes (528 bits); this one has ' + k + '. Use a real-size key, or textbook RSA.');
          const msg = new TextEncoder().encode(o.text);
          if (msg.length > k - 66) throw new Error('With this key OAEP carries at most ' + (k - 66) + ' bytes; the message has ' + msg.length + '.');
          const enc = R.oaepEncrypt(R.public(key), msg), dec = R.oaepDecrypt(key, enc.c);
          right.append(MB().result('OAEP encryption', 'The message is padded with a random seed and hashed masks before the exponentiation, so the same message never encrypts twice the same way.',
            U().hexGrid(enc.encoding.em, { label: 'EM = 00 ‖ maskedSeed ‖ maskedDB', cols: 16 }), MB().facts(['c', MB().n(enc.c)], ['decrypted', '"' + (bytesText(dec.msg) || '') + '"']), U().trace(enc.trace)));
          const sig = R.pssSign(key, msg), ver = R.pssVerify(R.public(key), msg, sig.s);
          right.append(MB().result('PSS signature', 'The hash of the message, salted and masked, is exponentiated with d; anyone checks it with e.', MB().facts(['s', MB().n(sig.s)], ['verified', ver.ok ? 'yes' : 'no: ' + ver.reason]), U().trace(ver.trace)));
          return;
        }
        let m;
        if (o.msgKind === 'text') { const b = new TextEncoder().encode(o.text); m = N.fromBytes(b); if (m >= key.n) throw new Error('The text read as a number (' + b.length + ' bytes) is not below n; textbook RSA can only encrypt numbers below n. Shorten it, or use a larger key.'); }
        else m = MB().big(o.msg, 'm', { min: 0 });
        if (m >= key.n) throw new Error('m must be below n = ' + key.n + '.');
        const c = R.encrypt(m, R.public(key)).value;
        right.append(K.pow('Encrypt: c = m^e mod n', m, key.e, key.n, 'Anyone can do this with the public key.'));
        const dm = R.decrypt(c, key), dc = R.decryptCRT(c, key);
        right.append(K.pow('Decrypt: m = c^d mod n', c, key.d, key.n, 'Only the holder of d can.'));
        right.append(MB().result('Decrypt faster with the CRT', 'Two half-size exponentiations with the short exponents dp and dq, joined by Garner\'s formula: about four times less work.',
          U().trace(dc.trace), MB().facts(['by c^d', MB().n(dm.value)], ['by the CRT', MB().n(dc.value)], ['agree', dm.value === dc.value ? 'yes' : 'no'], o.msgKind === 'text' ? ['as text', '"' + (bytesText(N.toBytes(dc.value, Math.ceil(N.bitLength(dc.value) / 8))) || '?') + '"'] : null)));
        const s = R.signRaw(m, key).value, v = R.verifyRaw(s, R.public(key)).value;
        right.append(MB().result('Textbook signature', 'Sign with d, check with e. Without padding this is malleable: the product of two signatures signs the product of the messages.', MB().facts(['s = m^d mod n', MB().n(s)], ['s^e mod n', MB().n(v)], ['valid', v === m ? 'yes: it gives back m' : 'no'])));
      });
    };
    const r = S.UI.debounce(run, 250);
    const bind = (k, id, label, attrs) => U().field(label, U().input(id, o[k], (v) => { o[k] = v; save(); r(); }, { attrs: Object.assign({ inputmode: 'numeric' }, attrs || {}) }));
    const toyBox = h('div', h('div.brow', bind('p', 'pkP', 'p'), bind('q', 'pkQ', 'q'), bind('e', 'pkE', 'e')),
      MB().examples([['1009 · 1013', { p: '1009', q: '1013', e: '17' }], ['127 · 131', { p: '127', q: '131', e: '17' }], ['two 32-bit primes', { p: '4294967291', q: '4294967279', e: '65537' }]], (v) => { Object.assign(o, v); save(); for (const [id, k] of [['pkP', 'p'], ['pkQ', 'q'], ['pkE', 'e']]) left.querySelector('#' + id).value = o[k]; run(); }));
    const gen = h('button.btn.primary', { type: 'button', id: 'pkGen' }, icon('key'), 'Generate a key');
    const prog = K.progress('');
    prog.el.style.display = 'none';
    const realBox = h('div', h('p.b-note', 'Two random primes of half the size each, found by drawing odd numbers and testing them; e = 65537.'), gen, prog.el);
    gen.addEventListener('click', () => {
      const bits = Number(o.size), expect = Math.round((bits / 2) * Math.LN2 / 2);
      gen.disabled = true; prog.el.style.display = '';
      let qPhase = false;
      prog.set('Searching for p…', 0);
      const job = S.PkWork.run({ kind: 'rsa', bits, e: 65537 }, (v) => {
        if (v.phase === 'q') qPhase = true;
        prog.set('Searching for ' + v.phase + ': candidate ' + v.tried, (qPhase ? 0.5 : 0) + Math.min(0.49, (0.5 * v.tried) / (2.2 * expect)), v.phase + ' #' + v.tried + ': ' + K.outcome(v));
      });
      track(job);
      job.promise.then((k) => {
        o.real = Object.assign({}, o.real || {}, { [o.size]: { p: String(k.p), q: String(k.q), e: String(k.e) } });
        save(); prog.set('Done: two primes found and checked.', 1, 'key ready: ' + k.bits + '-bit n'); gen.disabled = false; run();
      }, (e) => { gen.disabled = false; if (e.message !== 'stopped') prog.set('The search failed: ' + e.message, 0); });
    });
    const vis = () => { toyBox.style.display = o.size === 'toy' ? '' : 'none'; realBox.style.display = o.size === 'toy' ? 'none' : ''; gen.lastChild.textContent = o.real && o.real[o.size] ? 'Generate another ' + o.size + '-bit key' : 'Generate a ' + o.size + '-bit key'; };
    left.appendChild(MB().result('The key', 'Toy: primes you choose, every step visible. Real: the sizes in use today.',
      U().seg('pkSize', [['toy', 'Toy'], ['512', '512'], ['1024', '1024'], ['2048', '2048'], ['3072', '3072']], o.size, (v) => { o.size = v; save(); vis(); run(); }), toyBox, realBox));
    const numBox = bind('msg', 'pkMsg', 'm (a number below n)');
    const textBox = U().field('message', U().input('pkText', o.text, (v) => { o.text = v; save(); r(); }, { mono: false }));
    const vis2 = () => { numBox.style.display = o.msgKind === 'number' && o.pad === 'textbook' ? '' : 'none'; textBox.style.display = o.msgKind === 'text' || o.pad === 'oaep' ? '' : 'none'; };
    left.appendChild(MB().result('The message', 'Textbook RSA exponentiates the number itself; OAEP pads it first (and PSS signs a salted hash).',
      U().seg('pkPad', [['textbook', 'Textbook'], ['oaep', 'OAEP and PSS']], o.pad, (v) => { o.pad = v; save(); vis2(); run(); }),
      U().seg('pkKind', [['number', 'A number'], ['text', 'Text']], o.msgKind, (v) => { o.msgKind = v; save(); vis2(); run(); }), numBox, textBox));
    vis(); vis2(); run();
  };
})(globalThis.Sifer = globalThis.Sifer || {});
