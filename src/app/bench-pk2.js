// The public-key bench, continued: Diffie–Hellman (with a man in the middle if you like), Elgamal encryption and DSA
// signatures, each in a toy group whose every exponentiation is drawn, or in a real one: the 2048-bit group 14 of
// RFC 3526 for Diffie–Hellman and Elgamal, and freshly generated 2048/224 parameters for DSA.
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const MB = () => S.MathBench, U = () => S.BenchUI, K = () => S.PkKit;
  const PK = S.PkTools;
  // RFC 3526, group 14: a 2048-bit safe prime p = 2q + 1, with g = 2 generating the subgroup of order q
  const MODP14 = BigInt('0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff');
  const party = (cls, name, ...kids) => h('div.pk-party.' + cls, h('h4', h('span.dot'), name), ...kids);
  const secret = (v) => h('span.pk-secret', MB().n(v));
  const binder = (o, save, r) => (k, id, label, attrs) => U().field(label, U().input(id, o[k], (v) => { o[k] = v; save(); r(); }, { attrs: Object.assign({ inputmode: 'numeric' }, attrs || {}) }));

  /** the group a tool works in: toy Z_p* with a generator the student names, or group 14 */
  function groupOf(o) {
    if (o.group === 'modp14') return { G: S.DLP.subgroupZp(MODP14, (MODP14 - 1n) / 2n, 2n), p: MODP14, g: 2n, real: true, order: (MODP14 - 1n) / 2n };
    const p = MB().big(o.p, 'p', { min: 5 });
    if (!S.NT.isProbablePrime(p)) throw new Error('p = ' + p + ' is not prime; the next prime is ' + S.NT.nextPrime(p) + '.');
    if (p > 10n ** 15n) throw new Error('A toy p stays below 10^15 (so p − 1 can be factored to check g); for real sizes choose group 14.');
    const g = MB().big(o.g, 'g', { min: 2 });
    if (g >= p) throw new Error('g must be below p.');
    const ok = S.NT.isGenerator(g, p);
    if (!ok.ok) throw new Error(g + ' does not generate Z_' + p + '*: its order is ' + S.NT.order(g, p).order + ', not p − 1 = ' + (p - 1n) + '.' + (p < 5000n ? ' Try ' + S.NT.primitiveRoots(p).slice(0, 3).join(', ') + '.' : ''));
    return { G: S.DLP.groupZp(p, { gen: g }), p, g, real: false, order: p - 1n };
  }
  const randExp = (gr) => 2n + S.NT.randBelow(gr.order - 3n);
  /** a private exponent: the one typed (toy), or a random one kept (as text, so the state stays JSON) until renewed */
  const expOf = (o, key, gr, label) => {
    if (!gr.real && String(o[key] || '').trim()) return MB().big(o[key], label, { min: 1 });
    const keep = gr.real ? '_' + key + 'R' : '_' + key;
    if (!o[keep]) o[keep] = String(randExp(gr));
    return BigInt(o[keep]);
  };
  const groupSeg = (o, save, onChange) => U().seg('pkGroup', [['toy', 'Toy Z_p*'], ['modp14', '2048-bit group 14']], o.group, (v) => { o.group = v; save(); onChange(); });

  // ---- Diffie–Hellman ----------------------------------------------------------------------------------------------
  PK.dh = function (left, right, o, save) {
    const run = () => {
      right.innerHTML = '';
      MB().guard(right, () => {
        const gr = groupOf(o);
        const a = expOf(o, 'a', gr, 'a'), b = expOf(o, 'b', gr, 'b');
        const N = S.NT, p = gr.p, g = gr.g;
        const A = N.pow(g, a, p), B = N.pow(g, b, p);
        right.append(MB().result('The exchange', (gr.real ? 'RFC 3526 group 14: p is a 2048-bit safe prime and g = 2.' : 'Z_' + p + '* with generator g = ' + g + '.') + ' Each side keeps its exponent and sends only g to that power.',
          h('div.pk-parties', party('alice', 'Alice', U().kv('secret a', secret(a)), U().kv('sends A = g^a', MB().n(A))), party('bob', 'Bob', U().kv('secret b', secret(b)), U().kv('sends B = g^b', MB().n(B))))));
        if (o.mitm) {
          const m = gr.real ? randExp(gr) : MB().big(o.m, 'Eve\'s m', { min: 1 });
          const r = S.DLP.dhMITM(gr.G, a, b, m);
          right.append(MB().result('A man in the middle', 'Eve swaps both public values for g^m. Nothing tells Alice or Bob: each shares a key, but with Eve.',
            h('div.pk-parties', party('alice', 'Alice computes', U().kv('key', MB().n(r.kA))), party('eve', 'Eve holds both', U().kv('with Alice', MB().n(r.kA)), U().kv('with Bob', MB().n(r.kB))), party('bob', 'Bob computes', U().kv('key', MB().n(r.kB)))),
            U().trace(r.trace)));
          return;
        }
        const sA = N.pow(B, a, p), sB = N.pow(A, b, p);
        right.append(MB().result('The shared secret', 'Alice raises B to a, Bob raises A to b: both reach g^(ab), which an eavesdropper who saw only A and B cannot compute.',
          h('div.pk-parties', party('alice', 'Alice: B^a', U().kv('', MB().n(sA))), party('bob', 'Bob: A^b', U().kv('', MB().n(sB)))),
          MB().facts(['agree', sA === sB ? 'yes: the same ' + N.bitLength(sA) + '-bit secret' : 'no'])));
        if (!gr.real) { right.append(K().pow('Alice: A = g^a mod p', g, a, p)); right.append(K().pow('Alice: B^a mod p', B, a, p)); right.append(MB().result('The engine\'s account', null, U().trace(S.DLP.dh(gr.G, a, b).trace))); }
        else right.append(K().pow('Alice: A = g^a mod p', g, a, p, 'At this size the exponent has hundreds of bits: only the first and last steps are listed.'));
      });
    };
    const r = S.UI.debounce(run, 250), bind = binder(o, save, r);
    const toy = h('div', h('div.brow', bind('p', 'pkDp', 'p'), bind('g', 'pkDg', 'g')), h('div.brow', bind('a', 'pkDa', 'Alice\'s a (empty: random)'), bind('b', 'pkDb', 'Bob\'s b (empty: random)')));
    const fresh = h('button.btn.small', { type: 'button', id: 'pkDfresh' }, icon('shuffle'), 'New random exponents');
    fresh.addEventListener('click', () => { o._a = o._b = o._aR = o._bR = null; if (o.group === 'toy') { o.a = ''; o.b = ''; left.querySelector('#pkDa').value = ''; left.querySelector('#pkDb').value = ''; } save(); run(); });
    const mitm = h('input', { type: 'checkbox', id: 'pkMitm', checked: !!o.mitm });
    mitm.addEventListener('change', () => { o.mitm = mitm.checked; save(); run(); });
    const vis = () => { toy.style.display = o.group === 'toy' ? '' : 'none'; };
    left.appendChild(MB().result('Diffie–Hellman', 'Two parties agree on a secret over an open line.', groupSeg(o, save, () => { vis(); run(); }), toy, fresh,
      h('label.bfield.inline', mitm, h('span', 'Put Eve in the middle (no authentication)'))));
    vis(); run();
  };

  // ---- Elgamal -------------------------------------------------------------------------------------------------------
  PK.elgamal = function (left, right, o, save) {
    const run = () => {
      right.innerHTML = '';
      MB().guard(right, () => {
        const gr = groupOf(o), N = S.NT, p = gr.p;
        const x = expOf(o, 'x', gr, 'x');
        const m = MB().big(o.m, 'm', { min: 1 });
        if (m >= p) throw new Error('m must be below p.');
        const k = o.k.trim() && !gr.real ? MB().big(o.k, 'k', { min: 1 }) : randExp(gr);
        const key = S.DLP.elgamalKey(gr.G, x), ct = S.DLP.elgamalEncrypt(key.pub || key, m, k), pt = S.DLP.elgamalDecrypt(key, ct);
        right.append(MB().result('Keys', 'The private key is x; the public key is h = g^x.', MB().facts(['x', secret(x)], ['h = g^x', MB().n(key.h)])));
        right.append(MB().result('Encrypt', 'A fresh k for every message: c1 = g^k carries k hidden, and the mask s = h^k hides m in c2 = m·s.', MB().facts(['k', secret(k)], ['c1 = g^k', MB().n(ct.c1)], ['s = h^k', secret(ct.s)], ['c2 = m·s', MB().n(ct.c2)]), U().trace(ct.trace)));
        right.append(MB().result('Decrypt', 'The key holder rebuilds the mask from c1 alone: s = c1^x, then m = c2·s⁻¹.', MB().facts(['m', MB().n(pt.m)], ['right?', pt.m === m ? 'yes' : 'no']), U().trace(pt.trace)));
        if (!gr.real) right.append(K().pow('The mask: s = h^k mod p', key.h, k, p));
        void N;
      });
    };
    const r = S.UI.debounce(run, 250), bind = binder(o, save, r);
    const toy = h('div', h('div.brow', bind('p', 'pkEp', 'p'), bind('g', 'pkEg', 'g')), h('div.brow', bind('x', 'pkEx', 'private x (empty: random)'), bind('k', 'pkEk', 'nonce k (empty: random)')));
    const vis = () => { toy.style.display = o.group === 'toy' ? '' : 'none'; };
    left.appendChild(MB().result('Elgamal', 'Encryption from the discrete logarithm: a fresh nonce makes every ciphertext different.', groupSeg(o, save, () => { vis(); run(); }), toy, bind('m', 'pkEm', 'message m (a number below p)')));
    vis(); run();
  };

  // ---- DSA ------------------------------------------------------------------------------------------------------------
  PK.dsa = function (left, right, o, save, track) {
    const SIG = S.SIG;
    const run = () => {
      right.innerHTML = '';
      if (!SIG) { right.appendChild(U().missing('The signature engine')); return; }
      MB().guard(right, () => {
        let params;
        if (o.size === 'toy') params = SIG.toyParams(MB().big(o.qMin, 'q at least', { min: 11, max: '1000000000000' }));
        else if (o.real) params = { p: BigInt(o.real.p), q: BigInt(o.real.q), g: BigInt(o.real.g) };
        else { right.appendChild(MB().result('No 2048-bit parameters yet', 'Press Generate: a 224-bit prime q, then a 2048-bit prime p with q dividing p − 1. It runs in the background and takes a while.')); return; }
        const toy = o.size === 'toy';
        const key = SIG.dsaKey(params, toy && o.x.trim() ? MB().big(o.x, 'x', { min: 1, max: String(params.q - 1n) }) : undefined);
        const sig = SIG.dsaSign(key, o.msg, toy && o.k.trim() ? MB().big(o.k, 'k', { min: 1, max: String(params.q - 1n) }) : undefined);
        const ver = SIG.dsaVerify(key.pub, o.msg, sig), bad = SIG.dsaVerify(key.pub, o.msg + '!', sig);
        right.append(MB().result('Domain parameters', 'q is prime, q divides p − 1, and g has order q: all the work happens in that small subgroup.', MB().facts(['p', MB().n(params.p)], ['q', MB().n(params.q)], ['g', MB().n(params.g)], ['sizes', S.NT.bitLength(params.p) + '-bit p, ' + S.NT.bitLength(params.q) + '-bit q'])));
        right.append(MB().result('Sign', 'The private key x and a fresh secret nonce k give the pair (r, s). Reusing k gives the key away.', MB().facts(['x', secret(key.x)], ['y = g^x', MB().n(key.y)], ['k', secret(sig.k)], ['r', MB().n(sig.r)], ['s', MB().n(sig.s)]), U().trace(sig.trace)));
        right.append(MB().result('Verify', 'Anyone with y recomputes v from (r, s) and the message; v = r means valid.', U().trace(ver.trace), MB().facts(['valid', ver.ok ? h('span.pk-ok', 'yes') : h('span.pk-bad', 'no')], ['with one more character', bad.ok ? 'still valid?!' : h('span.pk-bad', 'rejected: the hash changed')])));
        if (toy) right.append(K().pow('r = (g^k mod p) mod q, the exponentiation', params.g, sig.k, params.p));
      });
    };
    const r = S.UI.debounce(run, 250), bind = binder(o, save, r);
    const toyBox = h('div', bind('qMin', 'pkQmin', 'q: the first prime at least'), h('div.brow', bind('x', 'pkDx', 'private x (empty: random)'), bind('k', 'pkDk', 'nonce k (empty: random)')));
    const gen = h('button.btn.primary', { type: 'button', id: 'pkDsaGen' }, icon('key'), 'Generate 2048/224 parameters');
    const prog = K().progress('');
    prog.el.style.display = 'none';
    gen.addEventListener('click', () => {
      gen.disabled = true; prog.el.style.display = '';
      prog.set('Searching for a 224-bit q…', 0.02);
      const job = S.PkWork.run({ kind: 'dsa', L: 2048, N: 224 }, (v) => { if (v.phase === 'q') prog.set('q found; now p = q·k + 1 of 2048 bits…', 0.1); else prog.set('Candidates for p tried: ' + v.tried, Math.min(0.97, 0.1 + v.tried / 1400), 'tried ' + v.tried + ' candidates for p'); });
      track(job);
      job.promise.then((pr) => { o.real = { p: String(pr.p), q: String(pr.q), g: String(pr.g) }; save(); prog.set('Done.', 1); gen.disabled = false; run(); }, (e) => { gen.disabled = false; if (e.message !== 'stopped') prog.set('The search failed: ' + e.message, 0); });
    });
    const realBox = h('div', gen, prog.el);
    const vis = () => { toyBox.style.display = o.size === 'toy' ? '' : 'none'; realBox.style.display = o.size === 'toy' ? 'none' : ''; };
    left.appendChild(MB().result('DSA', 'Signatures in a prime-order subgroup of Z_p*, with SHA-256.',
      U().seg('pkDsaSize', [['toy', 'Toy'], ['real', '2048/224']], o.size, (v) => { o.size = v; save(); vis(); run(); }), toyBox, realBox,
      U().field('message', U().input('pkDmsg', o.msg, (v) => { o.msg = v; save(); r(); }, { mono: false }))));
    vis(); run();
  };

  // ---- what the diagram checker looks at ------------------------------------------------------------------------------
  const pkClick = (sel) => `document.querySelector('${sel}').click(); await new Promise((r) => setTimeout(r, 200));`;
  if (S.Checks) for (const [name, setup] of [['RSA, toy key', pkClick('#pk-tool button[data-v=rsa]') + pkClick('#pkSize button[data-v=toy]') + pkClick('#pkPad button[data-v=textbook]')],
    ['RSA, text message', pkClick('#pkKind button[data-v=text]')], ['Diffie–Hellman, toy', pkClick('#pk-tool button[data-v=dh]')],
    ['Diffie–Hellman, group 14', pkClick('#pkGroup button[data-v=modp14]')], ['Diffie–Hellman, a man in the middle', pkClick('#pkGroup button[data-v=toy]') + pkClick('#pkMitm')],
    ['Elgamal, toy', pkClick('#pk-tool button[data-v=elgamal]')], ['DSA, toy', pkClick('#pk-tool button[data-v=dsa]')]]) {
    S.Checks.push({ group: 'bench-pk', name, hash: 'bench/pk', ready: "document.querySelector('#pkOut .bcard')", setup, sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
