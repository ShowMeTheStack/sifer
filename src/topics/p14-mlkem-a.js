// Part 14, ML-KEM (FIPS 203), first half: the data flow of KeyGen, Encaps and Decaps at the level of polynomial
// vectors, each polynomial drawn as a strip of its 256 coefficients; and the number-theoretic transform as seven
// layers of butterflies, with one coefficient followed through all seven.
(function (S) {
  'use strict';
  const U = S.P14, K = () => S.PQ.MLKEM, P = () => S.PQ;
  const q = 3329;
  const hex = (b, n) => P().hex(b).slice(0, n || 16) + '…';
  const cen = (v) => (v > q / 2 ? v - q : v);
  /** seeds from a word: 32 bytes of SHAKE256 */
  const seed32 = (tag, word) => P().shake256(new TextEncoder().encode(tag + ':' + word), 32);

  /**
   * A polynomial as a strip: 256 coefficients in 8 rows of 32 cells. look: 'small' (shade by size, centred),
   * 'uniform' (shade by value mod q), 'bits' (0 or 1), 'half' (near 0 or near q/2).
   */
  U.polyStrip = function (key, x, y, f, look, cs) {
    const rows = [];
    for (let r = 0; r < 8; r++) {
      let s = '';
      for (let c = 0; c < 32; c++) {
        const v = f[r * 32 + c];
        if (look === 'small') { const a = Math.abs(v > q / 2 ? v - q : v); s += a === 0 ? '0' : a === 1 ? '7' : a === 2 ? '3' : '4'; }
        else if (look === 'bits') s += v ? '1' : '0';
        else if (look === 'half') { const a = Math.abs(cen(v)); s += a < q / 4 ? '0' : '2'; }
        else { const k = Math.floor((v / q) * 4); s += ['0', '5', '7', '3'][Math.min(3, k)]; }
      }
      rows.push(s);
    }
    return { key, kind: 'bitmap', x, y, cw: cs || 7, ch: cs || 7, gap: 1, rows };
  };
  const range = (vs) => { let lo = Infinity, hi = -Infinity; for (const f of vs) for (const v of f) { const c = cen(v); if (c < lo) lo = c; if (c > hi) hi = c; } return [lo, hi]; };

  // ---------------------------------------------------------------------------------------------------------------
  // The data flow
  // ---------------------------------------------------------------------------------------------------------------
  const LANES = [
    { id: 'kg', title: 'KeyGen (Alice)', x: 96, blocks: [['G(d ‖ k)', '→ ρ, σ'], ['Â ← SampleNTT(ρ)'], ['s, e ← CBD(σ)'], ['ŝ = NTT(s)', 'ê = NTT(e)'], ['t̂ = Â∘ŝ + ê'], ['ek = t̂ ‖ ρ', 'dk = ŝ ‖ ek ‖ h ‖ z']] },
    { id: 'en', title: 'Encaps (Bob)', x: 300, blocks: [['(K, r) =', 'G(m ‖ H(ek))'], ['Â from ρ,', 't̂ from ek'], ['y, e₁, e₂ ← CBD(r)'], ['u = NTT⁻¹(Âᵀ∘ŷ)', '+ e₁'], ['v = NTT⁻¹(t̂ᵀ∘ŷ)', '+ e₂ + μ'], ['c = Compress(u)', '‖ Compress(v)']] },
    { id: 'de', title: 'Decaps (Alice)', x: 504, blocks: [['w = v′ −', 'NTT⁻¹(ŝᵀ∘û′)'], ['m′ = round(w)'], ['(K′, r′) =', 'G(m′ ‖ h)'], ['c′ = Encrypt(m′, r′)'], ['c′ = c ?'], ['K′, or J(z ‖ c)', 'if not']] },
  ];
  const BY = (i) => 112 + i * 84, BW = 168, BH = 54;
  function flowItems(lit, done, sizes) {
    const N = S.Kit.flow.net('fl');
    for (const L of LANES) {
      N.label('h' + L.id, L.x, 64, L.title, 'strong', 'middle', 15);
      L.blocks.forEach((t, i) => {
        const id = L.id + i, on = lit === id, past = done.has(id);
        N.box(id, L.x, BY(i), BW, BH, t.length > 1 ? t : t[0], 'small ' + (on ? 'act' : past ? '' : 'soft'));
        if (i) N.wire(L.id + 'w' + i, [N.port(L.id + (i - 1), 's'), N.port(id, 'n')], { head: true, cls: done.has(id) || on ? 'act' : '' });
      });
    }
    // ek to Encaps, c to Decaps, dk to Decaps
    const ek = [N.port('kg5', 'e'), [198, BY(5)], [198, BY(1)], N.port('en1', 'w')];
    N.wire('ek', ek, { head: true, cls: done.has('en1') || lit === 'en1' ? 'key' : '' });
    N.wire('c', [N.port('en5', 'e'), [402, BY(5)], [402, BY(0)], N.port('de0', 'w')], { head: true, cls: done.has('de0') || lit === 'de0' ? 'act' : '' });
    N.wire('dk', [N.port('kg5', 's'), [96, 604], [602, 604], [602, BY(0)], N.port('de0', 'e')], { head: true, cls: done.has('de0') || lit === 'de0' ? 'key' : '' });
    N.chip('ek', 'ek', [198, (BY(2) + BY(3)) / 2], 'key');
    N.chip('c', 'c', [402, (BY(2) + BY(3)) / 2], 'act');
    N.chip('dk', 'dk ' + sizes.dk + ' B', [352, 604], 'key');
    N.label('eks', 198, BY(5) + 46, sizes.ek + ' B', 'key', 'middle', 13);
    N.label('cs', 402, BY(5) + 46, sizes.c + ' B', 'act', 'middle', 13);
    return N.items;
  }
  function flow(inp) {
    const set = inp.set, p = K().params(set), d = seed32('d', inp.seed), z = seed32('z', inp.seed), m = seed32('m', inp.msg);
    const kg = K().keyGen(set, { d, z }), en = K().encaps(set, kg.ek, { m });
    let c = en.c;
    if (inp.tamper === 'yes') { c = Uint8Array.from(c); c[c.length - 1] ^= 0x10; }
    const de = K().decaps(set, kg.dk, c);
    const F = new S.Frames();
    const done = new Set();
    const head = U.t('fl:h', 20, 30, `${p.name}: k = ${p.k}, η₁ = ${p.eta1}, η₂ = ${p.eta2}, d_u = ${p.du}, d_v = ${p.dv}`, 'strong', 'start', 16);
    const insp = (title, parts) => {
      // the inspector: what this step makes, each polynomial vector as strips
      const items = U.panel('fl:i', 618, 48, 290, 586, '').concat([U.t('fl:i:tt', 632, 72, title, 'strong', 'start', 15)]);
      let y = 90;
      for (const pt of parts) {
        if (pt.text) { items.push(U.t('fl:i:t' + y, 632, y + 12, pt.text, pt.cls || 'mono', 'start', 14)); y += 26; continue; }
        items.push(U.t('fl:i:n' + y, 632, y + 12, pt.name, 'strong', 'start', 14));
        y += 22;
        if (pt.grid) {
          // a k × k matrix of polynomials, each a small square
          const n = pt.grid.length, cs = Math.min(3, 240 / (n * 16 + n));
          pt.grid.forEach((row, i) => row.forEach((f, j) => {
            const rows = []; for (let r = 0; r < 16; r++) { let s = ''; for (let c2 = 0; c2 < 16; c2++) s += ['0', '5', '7', '3'][Math.min(3, Math.floor((f[r * 16 + c2] / q) * 4))]; rows.push(s); }
            items.push({ key: 'fl:i:g' + i + '_' + j, kind: 'bitmap', x: U.r2(636 + j * (16 * (cs + 0.5) + 8)), y: U.r2(y + i * (16 * (cs + 0.5) + 8)), cw: cs, ch: cs, gap: 0.5, rows });
          }));
          y += n * (16 * (cs + 0.5) + 8) + 6;
          continue;
        }
        pt.vec.forEach((f, i) => { items.push(U.polyStrip('fl:i:s' + y + '_' + i, 636, y, f, pt.look, 7)); y += 66; });
        y += 4;
      }
      return items;
    };
    const legend = () => U.legend('fl:k', 20, 640, [['surface', 'not yet'], ['actsoft', 'this step'], ['white', 'done']]);
    const add = (lit, title, parts, step, extra) => {
      F.add({ items: [head, ...flowItems(lit, done, p.sizes), ...insp(title, parts), ...legend()], say: step.say + (extra || ''), facts: Object.assign({ k: p.k, eta1: p.eta1, eta2: p.eta2, du: p.du, dv: p.dv, q, ek: p.sizes.ek, dk: p.sizes.dk, c: p.sizes.c, set: p.name }, step.facts || {}), meta: { stage: step.kind, lit } });
      done.add(lit);
    };
    const T = (list, kind) => list.find((s) => s.kind === kind);
    const kt = kg.trace, et = en.trace, dt = de.trace;
    const sm = (v) => v.map((f) => f.map((x) => (x < 0 ? x + q : x)));
    add('kg0', 'seeds', [{ text: 'd = ' + hex(d) }, { text: 'z = ' + hex(z) }, { text: 'ρ = ' + hex(T(kt, 'seeds').rho), cls: 'mono' }, { text: 'σ = ' + hex(T(kt, 'seeds').sigma), cls: 'mono key' }], { kind: 'seeds', say: T(kt, 'kg-start').say + ' ' + T(kt, 'seeds').say, facts: { d: P().hex(d), z: P().hex(z), rho: P().hex(T(kt, 'seeds').rho), sigma: P().hex(T(kt, 'seeds').sigma) } });
    const A = T(kt, 'matrix').A;
    add('kg1', 'Â, public', [{ name: `Â: ${p.k} × ${p.k} polynomials, uniform mod ${q}`, grid: A }], { kind: 'matrix', say: T(kt, 'matrix').say, facts: { rej: T(kt, 'matrix').rejected } });
    const sv = T(kt, 'secret').s, ev = T(kt, 'error').e;
    add('kg2', 's and e, secret', [{ name: `s, coefficients in [${range(sv).join(', ')}]`, vec: sm(sv), look: 'small' }, { name: `e, in [${range(ev).join(', ')}]`, vec: sm(ev), look: 'small' }], { kind: 'secret', say: T(kt, 'secret').say + ' ' + T(kt, 'error').say, facts: { s: range(sv), e: range(ev), k2: 2 * p.k, k1: p.k - 1, k21: 2 * p.k - 1 } });
    add('kg3', 'ŝ = NTT(s)', [{ name: 'ŝ: the same s, transformed', vec: T(kt, 'ntt').sHat, look: 'uniform' }], { kind: 'ntt', say: T(kt, 'ntt').say });
    add('kg4', 't̂, public', [{ name: 't̂ = Â∘ŝ + ê', vec: T(kt, 'public').tHat, look: 'uniform' }], { kind: 'public', say: T(kt, 'public').say });
    add('kg5', 'the keys', [{ text: `ek: ${p.sizes.ek} bytes (t̂ and ρ)` }, { text: `dk: ${p.sizes.dk} bytes` }, { text: 'H(ek) = ' + hex(T(kt, 'kg-dk').h) }], { kind: 'encode', say: T(kt, 'encode').say + ' ' + T(kt, 'kg-dk').say, facts: { ekLen: T(kt, 'encode').ekLen, dkLen: T(kt, 'encode').dkLen, dk2: T(kt, 'kg-dk').dkLen } });
    const es = T(et, 'enc-start');
    add('en0', 'Bob\'s seed and key', [{ text: 'm = ' + hex(m) }, { text: 'K = ' + hex(es.K), cls: 'mono good' }, { text: 'r = ' + hex(es.r), cls: 'mono key' }], { kind: 'enc-start', say: es.say, facts: { m: P().hex(m), K: P().hex(es.K) } });
    add('en1', 'from ek', [{ name: 't̂, read from ek', vec: T(et, 'enc-matrix').tHat, look: 'uniform' }], { kind: 'enc-matrix', say: T(et, 'enc-matrix').say, facts: { rho: P().hex(T(kt, 'seeds').rho) } });
    const nz = T(et, 'enc-noise');
    add('en2', 'y, e₁, e₂', [{ name: 'y (the encrypter\'s secret)', vec: sm(nz.y), look: 'small' }, { name: 'e₂', vec: [sm([nz.e2])[0]], look: 'small' }], { kind: 'enc-noise', say: nz.say, facts: { y: range(nz.y) } });
    add('en3', 'u', [{ name: 'u', vec: T(et, 'enc-u').u, look: 'uniform' }], { kind: 'enc-u', say: T(et, 'enc-u').say });
    const mu = T(et, 'enc-mu');
    add('en4', 'μ, then v', [{ name: 'μ: the 256 bits of m, as 0 or 1665', vec: [mu.mu], look: 'half' }, { name: 'v = NTT⁻¹(t̂ᵀ∘ŷ) + e₂ + μ', vec: [T(et, 'enc-v').v], look: 'uniform' }], { kind: 'enc-v', say: mu.say + ' ' + T(et, 'enc-v').say, facts: { half: K().decompress(1, 1) } });
    const cp = T(et, 'enc-compress');
    add('en5', 'c, compressed', [{ name: `v compressed to ${p.dv} bits a coefficient`, vec: [cp.vCompressed.map((x) => Math.round((x * q) / 2 ** p.dv))], look: 'uniform' }, { text: `c: ${p.sizes.c} bytes` }], { kind: 'enc-compress', say: cp.say + ' ' + T(et, 'enc-done').say + (inp.tamper === 'yes' ? ' On the way, one bit of the last byte of c is flipped.' : ''), facts: { c1: 32 * p.du * p.k, c2: 32 * p.dv, cLen: en.c.length } });
    const dw = T(dt, 'dec-w');
    add('de0', 'w', [{ name: 'w: near 0 or near q/2', vec: [dw.w], look: 'half' }, { name: 'the noise left in w', vec: [dw.noise.map((x) => (x < 0 ? x + q : x))], look: 'small' }], { kind: 'dec-w', say: dw.say, facts: { worst: dw.worst, limit: 832 } });
    const dm = T(dt, 'dec-m');
    add('de1', 'm′', [{ name: 'the bits of m′', vec: [dm.bits], look: 'bits' }], { kind: 'dec-m', say: dm.say + (P().eqBytes(dm.m, m) ? ' It is Bob\'s m, bit for bit.' : ' It is not Bob\'s m.'), facts: { m: P().hex(dm.m) } });
    const re = T(dt, 'dec-reencrypt');
    const [K2, r2] = K().G(P().concat(dm.m, K().H(kg.ek))), c2 = K().pkeEncrypt(p, kg.ek, dm.m, r2, []);
    add('de2', 'G(m′ ‖ h)', [{ text: 'K′ = ' + hex(K2), cls: 'mono good' }, { text: 'r′ = ' + hex(r2), cls: 'mono key' }], { kind: 'dec-g', say: `Alice runs Bob's steps herself: (K′, r′) = G(m′ ‖ H(ek)), with the hash of ek she stored in dk. K′ = ${hex(K2)}.`, facts: { K2: P().hex(K2) } });
    add('de3', 're-encrypt', [{ text: 'c′ = ' + hex(c2, 20) }, { text: 'c  = ' + hex(c, 20) }], { kind: 'dec-reenc', say: 'With r′ she encrypts m′ again, exactly as Bob did: every sample of y, e₁ and e₂ comes out the same if m′ = m.', facts: { c2: P().hex(c2), c: P().hex(c) } });
    add('de4', 'compare', [{ text: re.same ? 'c′ = c' : 'c′ ≠ c', cls: re.same ? 'good' : 'bad' }], { kind: 'dec-reencrypt', say: re.say });
    const fin = dt[dt.length - 1];
    add('de5', de.rejected ? 'rejected' : 'shared key', [{ text: 'Alice: ' + hex(de.K), cls: 'mono ' + (de.rejected ? 'bad' : 'good') }, { text: 'Bob:   ' + hex(en.K), cls: 'mono good' }, { text: P().eqBytes(de.K, en.K) ? 'the same 32 bytes' : 'different keys', cls: P().eqBytes(de.K, en.K) ? 'good' : 'bad' }], { kind: fin.kind, say: fin.say + (P().eqBytes(de.K, en.K) ? ' Alice and Bob now share 32 bytes that no eavesdropper can compute.' : ' Bob and Alice hold different keys, and the next message will fail to decrypt.'), facts: { K: P().hex(de.K), Kb: P().hex(en.K) } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('ML-KEM (FIPS 203)', ['KeyGen: (ρ, σ) = G(d ‖ k); Â from ρ; s, e small', '  t̂ = Â∘NTT(s) + NTT(e); ek = (t̂, ρ)', 'Encaps: (K, r) = G(m ‖ H(ek)); y, e₁, e₂ from r', '  u = Aᵀy + e₁; v = tᵀy + e₂ + ⌈q/2⌋·m; c = Compress(u, v)', 'Decaps: m′ = round(v − sᵀu); re-encrypt; K if c′ = c']) };
  }
  S.topic({
    id: 'pq-mlkem-flow', family: 'p14-mlkem', order: 10, title: 'ML-KEM: the data flow',
    blurb: 'Key generation, encapsulation and decapsulation, step by step at the level of vectors of polynomials. Small secrets look sparse; everything public looks like noise; and the shared key comes out the same on both sides.',
    inputs: [
      { id: 'set', kind: 'choice', label: 'Parameter set', def: '768', options: ['512', '768', '1024'].map((v) => ({ value: v, label: 'ML-KEM-' + v })) },
      { id: 'seed', kind: 'text', label: 'Alice\'s seed word', def: 'heron', check: (v) => (!v || v.length > 30 ? 'Seed word: 1 to 30 characters' : null) },
      { id: 'msg', kind: 'text', label: 'Bob\'s seed word', def: 'kingfisher', check: (v) => (!v || v.length > 30 ? 'Seed word: 1 to 30 characters' : null) },
      { id: 'tamper', kind: 'choice', label: 'Ciphertext', def: 'no', options: [{ value: 'no', label: 'delivered as sent' }, { value: 'yes', label: 'one bit flipped on the way' }] },
    ],
    presets: [
      { label: 'ML-KEM-768', values: { set: '768', seed: 'heron', msg: 'kingfisher', tamper: 'no' } },
      { label: 'ML-KEM-512', values: { set: '512', seed: 'otter', msg: 'willow', tamper: 'no' } },
      { label: 'ML-KEM-1024', values: { set: '1024', seed: 'lynx', msg: 'aspen', tamper: 'no' } },
      { label: 'A bit flipped on the way', values: { set: '768', seed: 'heron', msg: 'kingfisher', tamper: 'yes' } },
    ],
    run: flow,
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.stage === 'secret', pick: 'option', options: ['sparse: mostly small values', 'like noise: any value mod q'], ask: 'The secret s comes next. Will its picture look sparse, or like noise?', answer: 'sparse: mostly small values', explain: 's is drawn from the centred binomial distribution: every coefficient is within ±η of 0.' },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.stage === 'dec-w', pick: 'option', options: ['near 0 or near q/2', 'spread over everything'], ask: 'Alice computes w = v′ − sᵀu. How will its coefficients look?', answer: 'near 0 or near q/2', explain: 'The big terms cancel, leaving μ (0 or 1665) plus small noise.' },
    ],
    quiz: [
      { q: 'Which of these does ML-KEM make public?', options: ['s and e', 't̂ and ρ', 'σ', 'z'], answer: 1, why: 'ek = ByteEncode(t̂) ‖ ρ; the matrix Â is rebuilt from ρ by anyone.' },
      { q: 'Why is Â sampled straight into the NTT domain?', options: ['It is secret', 'It is used only in products, which are fast there, so it never needs converting', 'To compress it', 'For the checksum'], answer: 1, why: 'Products of polynomials are coefficient-wise (in pairs) in the NTT domain.' },
      { q: 'What makes t̂ = Â∘ŝ + ê hard to invert?', options: ['Â is secret', 'The small error ê: without it this would be linear algebra', 'The NTT', 'The hash'], answer: 1, why: 'It is a Module-LWE sample.' },
      { q: 'In decapsulation, why does Alice encrypt m′ again?', options: ['To send it back', 'To check that c is exactly what an honest Bob would have sent (the FO transform)', 'To make a new key', 'To compress it'], answer: 1, why: 'A ciphertext that does not re-encrypt to itself is rejected, which stops chosen-ciphertext attacks.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The NTT as a butterfly network
  // ---------------------------------------------------------------------------------------------------------------
  /** the forward NTT layer by layer, with the engine's ζ table; checked against the engine at the end */
  function nttLayers(f) {
    const KK = K(), layers = [Array.from(f)], flies = [];
    let a = Array.from(f), i = 1;
    for (let len = 128; len >= 2; len >>= 1) {
      const fl = [];
      for (let start = 0; start < 256; start += 2 * len) {
        const zeta = KK.ZETAS[i], zi = i; i++;
        for (let j = start; j < start + len; j++) { const t = (zeta * a[j + len]) % q, x = a[j], y = a[j + len]; a[j + len] = (x - t + q) % q; a[j] = (x + t) % q; fl.push({ j, k: j + len, zeta, zi, x, y, t, out0: a[j], out1: a[j + len] }); }
      }
      layers.push(a.slice()); flies.push({ len, fl });
    }
    return { layers, flies, ok: KK.ntt(f).every((v, k) => v === a[k]) };
  }
  function ntt(inp) {
    const KK = K(), idx = +inp.follow;
    let f;
    if (inp.poly === 'x') { f = new Array(256).fill(0); f[1] = 1; }
    else if (inp.poly === 'small') f = KK.cbd(KK.prf(2, seed32('ntt', inp.seed), 0), 2);
    else f = KK.byteDecode(seed32('msg', inp.seed), 1).map((b) => KK.decompress(b, 1));
    const N = nttLayers(f);
    const F = new S.Frames(['layers', 'mults']);
    const top = 70, pitch = 2.12, X0 = 70, colW = 52;
    const Yw = (j) => U.r2(top + j * pitch);
    const XL = (L) => X0 + 26 + L * colW;
    // the dense mesh: one path a layer, every butterfly an X between its two wires
    const mesh = (lit) => {
      const items = [];
      for (let L = 0; L < 7; L++) {
        let d = '';
        for (const b of N.flies[L].fl) d += `M${XL(L)},${Yw(b.j)} L${XL(L) + colW - 10},${Yw(b.k)} M${XL(L)},${Yw(b.k)} L${XL(L) + colW - 10},${Yw(b.j)} `;
        items.push({ key: 'nt:m' + L, kind: 'path', d, cls: 'dline mesh ' + (L === lit ? 'act' : 'faint'), audit: 'ignore', layer: 'back' });
        items.push(U.t('nt:ml' + L, XL(L) + (colW - 10) / 2, top - 12, String(N.flies[L].len), L === lit ? 'act' : 'tick', 'middle', 14));
      }
      items.push(U.t('nt:mlh', X0 - 6, top - 12, 'len', 'tick', 'end', 14));
      // the followed coefficient's wire, and its partner at each layer
      let d = `M${X0},${Yw(idx)} H${XL(7)}`;
      items.push({ key: 'nt:fw', kind: 'path', d, cls: 'dline hot', audit: 'ignore' });
      for (let L = 0; L <= Math.min(lit === undefined ? 6 : lit, 6); L++) {
        const b = N.flies[L].fl.find((x) => x.j === idx || x.k === idx);
        items.push({ key: 'nt:fx' + L, kind: 'path', d: `M${XL(L)},${Yw(b.j)} L${XL(L) + colW - 10},${Yw(b.k)} M${XL(L)},${Yw(b.k)} L${XL(L) + colW - 10},${Yw(b.j)}`, cls: 'dline hot', audit: 'ignore' });
      }
      if (idx > 12) items.push(U.t('nt:in', X0 - 6, Yw(0) + 5, '0', 'tick', 'end', 13));
      if (idx < 243) items.push(U.t('nt:in2', X0 - 6, Yw(255) + 5, '255', 'tick', 'end', 13));
      items.push(U.t('nt:fi', X0 - 6, Yw(idx) + 5, String(idx), 'hot', 'end', 14));
      return items;
    };
    // one butterfly drawn large with its numbers
    const fly = (b, L) => {
      const x0 = 570, x1 = 800, ya = 150, yb = 280, items = [];
      items.push(U.t('nt:bt', 520, 92, `layer ${L + 1}: pairs ${N.flies[L].len} apart, ζ = 17^${'bitrev₇'}(${b.zi}) = ${b.zeta}`, 'strong', 'start', 14));
      const node = (k, x, y, v, cls, sub) => items.push({ key: 'nt:n' + k, kind: 'cell', x: x - 40, y: y - 18, w: 80, h: 36, rx: 5, text: String(v), size: 16, cls: 'hex ' + cls }, U.t('nt:ns' + k, x, y + 38, sub, 'mono', 'middle', 14));
      node('a', x0, ya, b.x, b.j === idx ? 'hot' : '', 'f[' + b.j + ']');
      node('b', x0, yb, b.y, b.k === idx ? 'hot' : '', 'f[' + b.k + ']');
      node('c', x1, ya, b.out0, b.j === idx ? 'hot' : 'act', 'f[' + b.j + ']');
      node('d', x1, yb, b.out1, b.k === idx ? 'hot' : 'act', 'f[' + b.k + ']');
      items.push({ key: 'nt:w1', kind: 'wire', pts: [[x0 + 40, ya], [x1 - 40, ya]], head: true, cls: '' });
      items.push({ key: 'nt:w2', kind: 'wire', pts: [[x0 + 40, yb], [x1 - 40, yb]], head: true, cls: '' });
      items.push({ key: 'nt:w3', kind: 'wire', pts: [[x0 + 40, yb - 8], [x1 - 40, ya + 8]], head: true, cls: 'act hop' });
      items.push({ key: 'nt:w4', kind: 'wire', pts: [[x0 + 40, ya + 8], [x1 - 40, yb - 8]], head: true, cls: 'act hop' });
      items.push(U.t('nt:eq1', 520, 356, `t = ζ · f[${b.k}] = ${b.zeta} × ${b.y} mod ${q} = ${b.t}`, 'mono', 'start', 15));
      items.push(U.t('nt:eq2', 520, 384, `f[${b.j}] ← ${b.x} + ${b.t} = ${b.out0}`, 'mono', 'start', 15));
      items.push(U.t('nt:eq3', 520, 412, `f[${b.k}] ← ${b.x} − ${b.t} = ${b.out1}  (mod ${q})`, 'mono', 'start', 15));
      return items;
    };
    const head = U.t('nt:h', 20, 30, 'The NTT of ML-KEM: 7 layers of 128 butterflies over Z_3329', 'strong', 'start', 16);
    const counts = (L) => U.readout('nt:r', 520, 450, 386, 'work so far', [['butterflies', String(128 * (L + 1))], ['multiplications by ζ', String(128 * (L + 1))], ['schoolbook product', '65536 multiplications']], { dy: 28 });
    const name = { x: 'f = X (one 1, at index 1)', small: 'a small polynomial from CBD₂', msg: 'a message: 256 bits as 0 or 1665' }[inp.poly];
    const nz = f.filter((v) => v).length;
    F.add({ items: [head, ...mesh(undefined), U.t('nt:p', 520, 92, name, 'strong', 'start', 14), U.t('nt:p2', 520, 120, `${nz} of 256 coefficients are not 0; f[${idx}] = ${f[idx]}`, 'mono', 'start', 14)], hl: { d: [0] }, say: `The input: ${name}. Each of the 256 coefficients runs along a wire from left to right; at each of the 7 layers it meets one partner in a butterfly. We follow coefficient ${idx}, which starts as ${f[idx]}.`, facts: { idx, nz, v: f[idx], layers: 7 }, meta: { stage: 'start' } });
    for (let L = 0; L < 7; L++) {
      const b = N.flies[L].fl.find((x) => x.j === idx || x.k === idx);
      F.count('layers'); F.count('mults', 128);
      F.add({ items: [head, ...mesh(L), ...fly(b, L), ...counts(L)], hl: { d: [1, 2] }, say: `Layer ${L + 1}: every coefficient j is paired with j + ${N.flies[L].len} inside blocks of ${2 * N.flies[L].len}. Coefficient ${idx} meets ${b.j === idx ? b.k : b.j}; with ζ = ${b.zeta}, t = ${b.zeta} × ${b.y} mod ${q} = ${b.t}, and the pair becomes ${b.out0} and ${b.out1}.`, facts: { L: L + 1, len: N.flies[L].len, block: 2 * N.flies[L].len, idx, j: b.j, k: b.k, zeta: b.zeta, zi: b.zi, y: b.y, x: b.x, t: b.t, o0: b.out0, o1: b.out1 }, meta: { stage: 'layer', L, t: b.t, out: b.j === idx ? b.out0 : b.out1 } });
    }
    // what it buys: products in the NTT domain
    const g = KK.cbd(KK.prf(2, seed32('g', inp.seed), 1), 2);
    const prodN = KK.invNtt(KK.multiplyNtts(KK.ntt(f), KK.ntt(g))), prodS = KK.mulSchoolbook(f, g), same = prodN.every((v, k) => v === prodS[k]);
    F.add({ items: [head, ...mesh(7), U.t('nt:e1', 520, 92, 'f̂ = NTT(f), after 7 layers', 'strong', 'start', 14), U.t('nt:e2', 520, 120, `f̂[${idx}] = ${N.layers[7][idx]}`, 'mono', 'start', 15), U.t('nt:e3', 520, 160, 'f · g by NTT: 2 NTTs, 128 pair products, 1 inverse', 'strong', 'start', 14), U.t('nt:e4', 520, 188, `same as the schoolbook product: ${same ? 'all 256 match' : 'no'}`, same ? 'good' : 'bad', 'start', 15), ...counts(6)], hl: { d: [3, 4] }, say: `After 7 layers the coefficient at index ${idx} holds ${N.layers[7][idx]}: f̂ = NTT(f), matching the engine's NTT. Its use: to multiply f by another polynomial g, transform both, multiply 128 pairs of degree-one polynomials, and transform back. Here that gives the same 256 coefficients as the schoolbook product mod X²⁵⁶ + 1, with three transforms of 896 butterflies and 128 small products: a few thousand multiplications instead of 65536.`, facts: { idx, out: N.layers[7][idx], same: same ? 256 : 0, sb: 65536, fly: 896, pairs: 128, deg: 256, ones: 1 }, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('The NTT (FIPS 203, Algorithm 9)', ['for len = 128, 64, …, 2:  (7 layers)', '  each block of 2·len uses the next ζ = 17^bitrev₇(i) mod 3329', '  t = ζ·f[j + len];  f[j + len] = f[j] − t;  f[j] = f[j] + t', 'f·g = NTT⁻¹(NTT(f) ∘ NTT(g)): 128 products mod X² − γᵢ', '17 is a 256th root of unity mod 3329; X²⁵⁶ + 1 splits into 128 quadratics']) };
  }
  S.topic({
    id: 'pq-ntt', family: 'p14-mlkem', order: 20, title: 'The NTT as a butterfly network',
    blurb: 'Seven layers of butterflies turn a polynomial into the form where multiplying is cheap. Follow one coefficient as it meets a partner 128, 64, … 2 places away and is mixed with it by a power of 17 mod 3329.',
    inputs: [
      { id: 'poly', kind: 'choice', label: 'Polynomial f', def: 'small', options: [{ value: 'x', label: 'f = X' }, { value: 'small', label: 'small, from CBD₂' }, { value: 'msg', label: 'a message, 0 or 1665' }] },
      { id: 'seed', kind: 'text', label: 'Seed word', def: 'tern', check: (v) => (!v || v.length > 30 ? 'Seed word: 1 to 30 characters' : null) },
      { id: 'follow', kind: 'number', label: 'Follow coefficient', def: 5, min: 0, max: 255 },
    ],
    presets: [
      { label: 'Small f, follow 5', values: { poly: 'small', seed: 'tern', follow: 5 } },
      { label: 'f = X, follow 1', values: { poly: 'x', follow: 1 } },
      { label: 'Small f, follow 200', values: { poly: 'small', seed: 'tern', follow: 200 } },
      { label: 'A message, follow 37', values: { poly: 'msg', seed: 'gannet', follow: 37 } },
    ],
    counters: [{ id: 'layers', label: 'layers' }, { id: 'mults', label: 'multiplications by ζ' }],
    run: ntt,
    predict: [{ at: (f, i, fr) => f.meta && f.meta.stage === 'layer' && f.meta.L === 0, pick: 'option', options: ['64', '32', '128', '2'], ask: 'Layer 1 paired coefficients 128 apart. How far apart are the partners in layer 2?', answer: '64', explain: 'The distance halves each layer: 128, 64, 32, 16, 8, 4, 2.' }],
    quiz: [
      { q: 'How many layers of butterflies does ML-KEM\'s NTT have?', options: ['8', '7', '256', '128'], answer: 1, why: 'len runs 128, 64, …, 2: seven layers, stopping at pairs of coefficients.' },
      { q: 'One butterfly with twiddle ζ maps (a, b) to…', options: ['(a + b, a − b)', '(a + ζb, a − ζb)', '(ζa, ζb)', '(a·b, a + b)'], answer: 1, why: 't = ζ·b, then a + t and a − t, all mod 3329.' },
      { q: 'Why does ML-KEM stop at degree-one pieces instead of a full NTT to single values?', options: ['To save memory', 'Because 3329 has 256th roots of unity but not the 512th that X²⁵⁶ + 1 would need', 'For security', 'By accident'], answer: 1, why: 'X²⁵⁶ + 1 splits into 128 quadratics X² − γ mod 3329, so products are done on pairs.' },
      { q: 'About how many multiplications does an NTT-based product of two 256-coefficient polynomials take?', options: ['65536', 'a few thousand', '256', '7'], answer: 1, why: 'Two NTTs and one inverse of 896 butterflies each, plus 128 pair products: a few thousand, against 65536 for the schoolbook way.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
