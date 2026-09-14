// Part 14, code-based encryption: a toy McEliece on a binary Goppa code. The secret generator is scrambled into a
// public one that looks random; a message is encoded and hidden under an error vector of weight t; the key holder
// unscrambles, decodes the syndrome with Patterson's algorithm, and reads the message back.
(function (S) {
  'use strict';
  const U = S.P14, P = () => S.PQ;
  const bits = (v) => v.join('');

  /** a bit matrix as a bitmap: 1s dark, and cells picked out by mark(i, j) -> look ('2' hot, '4' key, '3' act) */
  function grid(key, x, y, M, cs, mark) {
    const rows = M.map((r, i) => r.map((v, j) => (mark && mark(i, j, v)) || (v ? '1' : '0')).join(''));
    return { key, kind: 'bitmap', x, y, cw: cs, ch: cs, gap: 1.2, rows };
  }
  const label = (key, x, y, t, cls, size) => U.t(key, x, y, t, cls || 'strong', 'start', size || 15);

  function mce(inp) {
    const m = +inp.m, t = +inp.t, Mc = P().McEliece;
    const kg = Mc.keyGen({ m, t, seed: +inp.seed }), code = kg.sk.code, k = kg.pk.k, n = kg.pk.n;
    const src = String(inp.msg).replace(/[^01]/g, '') || '1';
    const msg = Array.from({ length: k }, (_, i) => +src[i % src.length]);
    let err = null;
    if (inp.errors !== 't') { err = new Array(n).fill(0); const r = P().rng(+inp.eseed); let c = 0; const want = inp.errors === 'more' ? t + 1 : t - 1; while (c < want) { const j = r.int(n); if (!err[j]) { err[j] = 1; c++; } } }
    const enc = Mc.encrypt(kg.pk, msg, err ? { error: err } : { seed: +inp.eseed }), dec = Mc.decrypt(kg.sk, enc.c);
    const e = enc.error, w = e.reduce((a, b) => a + b, 0), cs = n > 16 ? 14 : 24;
    const F = new S.Frames();
    const head = U.t('mc:h', 20, 30, `A toy McEliece: a binary Goppa code of length ${n}, dimension ${k}, correcting ${t} errors`, 'strong', 'start', 16);
    const G = code.G, Sm = kg.sk.S, perm = kg.sk.perm, Gp = kg.pk.Gpub;
    const X2 = 40 + n * (cs + 1.2) + 50;
    const facts0 = { n, k, t, m, w, q: 2 ** m, mt: m * t };
    const tr = kg.trace, dt = dec.trace, T = (kind) => dt.find((s) => s.kind === kind);
    F.add({ items: [head, label('mc:gl', 40, 70, 'G: the secret Goppa code\'s generator, ' + k + ' × ' + n), grid('mc:G', 40, 84, G, cs), label('mc:hl', 40, 110 + k * (cs + 1.2), 'H: its parity checks, ' + m * t + ' × ' + n), grid('mc:H', 40, 124 + k * (cs + 1.2), code.H, cs), U.t('mc:g', 40, 160 + (k + m * t) * (cs + 1.2), tr[0].gText ? 'g(z) = ' + tr[0].gText : '', 'mono', 'start', 15)], hl: { d: [0] }, say: tr[0].say + ' ' + tr[3].say.replace('null space', 'kernel'), facts: Object.assign({ g: tr[0].gText }, facts0), meta: { stage: 'code' } });
    const yS = 84, xS = X2;
    F.add({ items: [head, label('mc:gl', 40, 70, 'G (secret)'), grid('mc:G', 40, 84, G, cs), label('mc:sl', xS, 70, 'S (secret, invertible)'), grid('mc:S', xS, yS, Sm, cs), label('mc:pl', 40, 110 + k * (cs + 1.2), `G′ = S·G·P: the public key, ${k} × ${n}`, 'act'), grid('mc:Gp', 40, 124 + k * (cs + 1.2), Gp, cs), U.t('mc:pp', 40, 160 + 2 * k * (cs + 1.2), 'P sends column j to ' + perm.slice(0, Math.min(n, 16)).join(' ') + (n > 16 ? ' …' : ''), 'mono', 'start', 14)], hl: { d: [1] }, say: tr[4].say + ' Anyone may encrypt with G′; only the holder of S, P and g can decode it fast.', facts: Object.assign({ perm }, facts0), meta: { stage: 'scramble' } });
    const cw = Mc.encrypt(kg.pk, msg, { error: new Array(n).fill(0) }).c;
    const rowY = (r) => (n > 16 ? 360 : 330) + r * 70;
    const vecRow = (key, r, name, v, mark, cls) => [label(key + ':l', 40, rowY(r) - 8, name, cls), grid(key, 40, rowY(r), [v], n > 16 ? 24 : 30, mark && ((i, j, b) => mark(j, b)))];
    const top = [label('mc:pl', 40, 70, 'G′ (public)', 'act'), grid('mc:Gp', 40, 84, Gp, cs)];
    F.add({ items: [head, ...top, ...vecRow('mc:m', 0, `message m, ${k} bits: ${bits(msg)}`, msg), ...vecRow('mc:cw', 1, `m·G′, a codeword of ${n} bits`, cw)], hl: { d: [2] }, say: enc.trace[0].say + ' On its own this would be no secret at all: G′ has an inverse on its codewords.', facts: Object.assign({ msg: bits(msg), cw: bits(cw) }, facts0), meta: { stage: 'encode' } });
    F.add({ items: [head, ...top, ...vecRow('mc:m', 0, `message m: ${bits(msg)}`, msg), ...vecRow('mc:cw', 1, 'm·G′', cw), ...vecRow('mc:e', 2, `error e, weight ${w}`, e, (j, b) => (b ? '2' : '0'), 'hot'), ...vecRow('mc:c', 3, 'ciphertext c = m·G′ + e', enc.c, (j, b) => (e[j] ? (b ? '4' : '7') : b ? '1' : '0'), 'key')], hl: { d: [3] }, say: enc.trace[1].say + ` Without the secret structure, finding which ${w} of ${n} bits were flipped means decoding a random-looking code, a problem with no known fast method, quantum or not.`, facts: Object.assign({ e: bits(e), c: bits(enc.c) }, facts0), meta: { stage: 'error' } });
    const un = T('mce-unpermute');
    const decRows = (upto) => {
      const items = [head, label('mc:dl', 40, 70, 'decryption, by the key holder', 'key')];
      items.push(...vecRow('mc:c', -3, 'c', enc.c, (j, b) => (b ? '1' : '0')));
      if (upto >= 1) items.push(...vecRow('mc:u', -2, 'c·P⁻¹: back in the Goppa code\'s own order', un.word));
      return items;
    };
    const fix = (s) => s.replace(/\s+/g, ' ');
    F.add({ items: [...decRows(1)], hl: { d: [4] }, say: un.say, facts: Object.assign({ word: bits(un.word) }, facts0), meta: { stage: 'unpermute' } });
    const sy = T('syndrome'), T1 = T('T'), ke = T('key-equation'), ro = T('roots'), fin = dt.find((s) => s.kind === 'corrected' || s.kind === 'decode-fail');
    const syn = (more) => [...decRows(1), label('mc:sl', 40, 300, 'syndrome H·wᵀ (' + m * t + ' bits)'), grid('mc:sy', 40, 312, [sy.syndrome], 26, (i, j, b) => (b ? '3' : '0')), ...(more || [])];
    F.add({ items: syn(), hl: { d: [5] }, say: fix(sy.say) + (sy.syndrome.some(Boolean) ? ' A non-zero syndrome says errors are present; it depends only on the error, not on the message.' : ''), facts: Object.assign({ syn: bits(sy.syndrome) }, facts0), meta: { stage: 'syndrome' } });
    if (T1) F.add({ items: syn(fix(T1.say).replace(/\s*\([^)]*\)/g, '').replace(/\.$/, '').split(/;\s*/).map((l, j) => U.t('mc:t' + j, 40, 380 + 28 * j, l, 'mono', 'start', 15))), hl: { d: [6] }, say: T1.say, facts: facts0, meta: { stage: 'T' } });
    if (ke) F.add({ items: syn([U.t('mc:k', 40, 380, 'σ(z) = ' + fix(ke.say).split('σ(z) = a² + z·b² = ')[1], 'mono', 'start', 15)]), hl: { d: [6] }, say: ke.say, facts: facts0, meta: { stage: 'key' } });
    const ok = !!dec.msg && bits(dec.msg) === bits(msg);
    const posMark = (j, b) => (ro.positions.includes(j) ? '2' : b ? '1' : '0');
    F.add({ items: [...syn(), label('mc:rl', 40, 386, `the roots of σ: errors at ${ro.positions.join(', ') || 'no position'}`, 'hot'), grid('mc:ro', 40, 398, [un.word], n > 16 ? 24 : 30, (i, j, b) => posMark(j, b))], hl: { d: [6, 7] }, say: ro.say, facts: Object.assign({ pos: ro.positions }, facts0), meta: { stage: 'roots' } });
    if (ok) {
      const so = T('mce-solve'), er = dt.filter((s) => s.kind === 'mce-error').pop();
      F.add({ items: [...syn(), ...vecRow('mc:fx', 2, 'corrected codeword', fin.codeword), ...vecRow('mc:ms', 3, `m = ${bits(dec.msg)}, the message back`, dec.msg, null, 'good')], hl: { d: [8] }, say: fin.say + ' ' + so.say + ' ' + er.say + ` It is the error that was added: weight ${w}.`, facts: Object.assign({ cw: bits(fin.codeword), mS: bits(so.mS), msg: bits(dec.msg), err: bits(er.error) }, facts0), meta: { stage: 'done', ok } });
    } else F.add({ items: [...syn(), label('mc:bad', 40, 470, `decoding failed: ${w} errors are more than the ${t} this code corrects`, 'bad')], hl: { d: [7] }, say: `${fin.say} With ${w} errors, more than t = ${t}, the error-locator polynomial has the wrong roots and the message is lost. The encrypter must add exactly t errors: fewer would make the attacker's job easier, more make decryption fail.`, facts: facts0, meta: { stage: 'done', ok } });
    F.add({ items: [head, ...top, label('mc:sec', 40, 340, 'What protects it', 'strong'), U.t('mc:s1', 40, 372, `public key: ${k} × ${n} bits (real sets: codes thousands of bits long, keys of hundreds of kilobytes)`, 'tick', 'start', 14), U.t('mc:s2', 40, 400, 'attack: decode a random-looking linear code, or recover g, L, S and P from G′', 'tick', 'start', 14), U.t('mc:s3', 40, 428, 'the oldest public-key scheme still unbroken, by classical and quantum attacks alike', 'tick', 'start', 14)], hl: { d: [9] }, say: `The whole secret is the structure: g, the support, S and P. To an attacker G′ is a random-looking ${k} × ${n} binary matrix, and removing ${t} errors from a word of a random code has resisted every attack, quantum ones included, for over four decades. The price is size: real public keys run to hundreds of kilobytes.`, facts: facts0, meta: { stage: 'why' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('McEliece', ['secret: a Goppa code (g, support L), correcting t errors, generator G', 'public: G′ = S·G·P, S invertible, P a permutation', 'encrypt: c = m·G′ + e, with e of weight t', 'decrypt: c·P⁻¹ = (m·S)·G + e·P⁻¹', 'syndrome H·wᵀ → Patterson: S(z), T = S⁻¹, R = √(T + z)', 'key equation a ≡ b·R; σ = a² + z·b²; roots = error positions', 'solve (m·S)·G = codeword; m = (m·S)·S⁻¹', 'security: decoding a random linear code']) };
  }
  S.topic({
    id: 'pq-mceliece', family: 'p14-other', order: 10, title: 'McEliece: a scrambled code and its errors',
    blurb: 'Encrypt by encoding the message in an error-correcting code and flipping t bits at random. The code\'s structure, which makes the errors easy to remove, is hidden behind a scramble and a shuffle.',
    inputs: [
      { id: 'm', kind: 'choice', label: 'Field', def: '4', options: [{ value: '4', label: 'GF(2⁴): length 16' }, { value: '5', label: 'GF(2⁵): length 32' }] },
      { id: 't', kind: 'choice', label: 'Errors corrected t', def: '2', options: [{ value: '2', label: '2' }, { value: '3', label: '3' }] },
      { id: 'seed', kind: 'number', label: 'Key seed', def: 11, min: 1, max: 999 },
      { id: 'msg', kind: 'string', label: 'Message bits', def: '10110010', alphabet: '01', min: 1, max: 32 },
      { id: 'errors', kind: 'choice', label: 'Error weight', def: 't', options: [{ value: 't', label: 't, as the scheme says' }, { value: 'more', label: 't + 1: too many' }] },
      { id: 'eseed', kind: 'number', label: 'Error seed', def: 3, min: 1, max: 999 },
    ],
    presets: [
      { label: 'Length 16, t = 2', values: { m: '4', t: '2', seed: 11, msg: '10110010' } },
      { label: 'Length 32, t = 3', values: { m: '5', t: '3', seed: 7, msg: '11001010011100101' } },
      { label: 'Too many errors', values: { m: '4', t: '2', seed: 11, errors: 'more' } },
      { label: 'Another key', values: { m: '4', t: '2', seed: 29, msg: '01101100', eseed: 8 } },
    ],
    run: mce,
    predict: [{ at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.stage === 'roots', pick: 'option', options: ['yes', 'no'], ask: 'Will the decoder find exactly the error positions that were added?', answer: (fr, i) => (fr[fr.length - 2].meta.ok ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'In McEliece the public key is…', options: ['the Goppa polynomial', 'a scrambled generator matrix G′ = S·G·P', 'the error vector', 'the syndrome'], answer: 1, why: 'S and P hide the structure of G.' },
      { q: 'Why does the syndrome help decoding?', options: ['It contains the message', 'H·cᵀ = H·eᵀ: it depends only on the error', 'It is random', 'It is the key'], answer: 1, why: 'Codewords have zero syndrome, so only the error remains.' },
      { q: 'What happens with more than t errors?', options: ['Decryption still works', 'Decoding fails or gives a wrong word', 'The key changes', 'Nothing'], answer: 1, why: 'A Goppa code of degree t corrects at most t errors.' },
      { q: 'The main drawback of McEliece is…', options: ['it is broken by Shor', 'very large public keys', 'slow encryption', 'small security'], answer: 1, why: 'Its keys are hundreds of kilobytes, though it has resisted attack for decades.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
