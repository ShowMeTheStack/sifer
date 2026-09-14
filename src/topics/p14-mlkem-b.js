// Part 14, ML-KEM, second half: compression and the noise budget (how far each coefficient of w strays from 0
// or q/2, against the 832 at which a bit would flip), and implicit rejection (a tampered ciphertext gets a key
// that looks as good as any, so the attacker learns nothing from the answer).
(function (S) {
  'use strict';
  const U = S.P14, K = () => S.PQ.MLKEM, P = () => S.PQ;
  const q = 3329;
  const cen = (v) => { v = ((v % q) + q) % q; return v > q / 2 ? v - q : v; };
  const seed32 = (tag, word) => P().shake256(new TextEncoder().encode(tag + ':' + word), 32);
  const hex = (b, n) => P().hex(b).slice(0, n || 16) + '…';
  /** the largest rounding error of Compress_d then Decompress_d over all of Z_q */
  const roundErr = (d) => { let m = 0; for (let x = 0; x < q; x++) m = Math.max(m, Math.abs(cen(K().decompress(K().compress(x, d), d) - x))); return m; };
  /** run encaps and decaps and return the noise left in w (from the decapsulation trace) */
  const noiseOf = (set, kg, word) => {
    const en = K().encaps(set, kg.ek, { m: seed32('m', word) }), de = K().decaps(set, kg.dk, en.c);
    const st = de.trace.find((s) => s.kind === 'dec-w');
    return { noise: st.noise, worst: st.worst, ok: P().eqBytes(de.K, en.K) };
  };

  // ---------------------------------------------------------------------------------------------------------------
  // Compression and the noise budget
  // ---------------------------------------------------------------------------------------------------------------
  function noise(inp) {
    const set = inp.set, p = K().params(set), kg = K().keyGen(set, { d: seed32('d', inp.seed), z: seed32('z', inp.seed) });
    const F = new S.Frames(['runs']);
    const head = U.t('nb:h', 20, 30, `${p.name}: compression and the noise budget`, 'strong', 'start', 16);
    // 1. Compress_dv on a number line of Z_q
    const x = +inp.x, d = p.dv, y = K().compress(x, d), x2 = K().decompress(y, d), err = cen(x2 - x);
    const line = (lit) => {
      const X = (v) => U.r2(40 + (v / q) * 840), items = [{ key: 'nb:l', kind: 'path', d: `M40,140 H880`, cls: 'axis', audit: 'ignore' }];
      for (let k = 0; k < 2 ** d; k++) {
        const c = K().decompress(k, d), lo = k === 0 ? 0 : (K().decompress(k - 1, d) + c) / 2, hi = k === 2 ** d - 1 ? q : (c + K().decompress(k + 1, d)) / 2;
        items.push({ key: 'nb:t' + k, kind: 'path', d: `M${X(lo)},128 V152`, cls: 'axis', audit: 'ignore' });
        items.push({ key: 'nb:c' + k, kind: 'dot', x: X(c), y: 140, r: k === y ? 6 : 3.5, cls: k === y ? 'act' : '', point: true });
        if (k % 2 === 0 || 2 ** d <= 16) items.push(U.t('nb:k' + k, X(c), 176, String(k), k === y ? 'act' : 'tick', 'middle', 13));
        if (k === y && lit) items.push({ key: 'nb:band', kind: 'path', d: `M${X(lo)},120 H${X(hi)} V160 H${X(lo)} Z`, cls: 'band act', audit: 'ignore', layer: 'back' });
      }
      items.push(U.t('nb:lx', 40, 66, `Z_${q} cut into 2^${d} = ${2 ** d} buckets; each bucket's dot is the value Decompress gives back`, 'strong', 'start', 14));
      if (lit) {
        items.push({ key: 'nb:x', kind: 'head', x: X(x), y: 128, text: 'x = ' + x, side: 'above', cls: 'hot' });
        items.push(U.t('nb:r', 40, 214, `Compress_${d}(${x}) = ${y};  Decompress_${d}(${y}) = ${x2};  the error is ${U.int(err)}`, 'mono', 'start', 15));
      }
      return items;
    };
    F.add({ items: [head, ...line(true)], hl: { d: [0, 1] }, say: `Compress_d keeps only the top d bits of a coefficient: Compress_${d}(${x}) = ⌈2^${d}/q · ${x}⌋ mod 2^${d} = ${y}. Decompress_${d}(${y}) = ${x2} is the middle of that bucket, ${Math.abs(err)} away from ${x}. That error is extra noise, added on purpose to make the ciphertext smaller.`, facts: { d, x, y, x2, err, b: 2 ** d, q }, meta: { stage: 'compress' } });
    // 2. how big the rounding errors are for the d's in use
    const ds = [p.dv, p.du].filter((v, i, a) => a.indexOf(v) === i).sort((a, b) => a - b), errs = ds.map(roundErr);
    const tbl = [];
    ds.forEach((dd, i) => {
      const y0 = 280 + i * 50, w = Math.max(3, (errs[i] / 832) * 560);
      tbl.push(U.t('nb:tn' + dd, 150, y0 + 20, `d = ${dd}${dd === p.du ? ' (u)' : dd === p.dv ? ' (v)' : dd === 1 ? ' (m)' : ''}`, 'strong', 'end', 15));
      tbl.push({ key: 'nb:tb' + dd, kind: 'cell', x: 166, y: y0 + 4, w: U.r2(w), h: 22, rx: 3, text: '', cls: 'bar ' + (dd === p.dv ? 'hot' : dd === p.du ? 'act' : 'soft') });
      tbl.push(U.t('nb:tv' + dd, 166 + w + 10, y0 + 20, 'at most ' + errs[i], 'mono', 'start', 14));
    });
    tbl.push(U.t('nb:tt', 20, 264, 'the largest rounding error of Compress_d then Decompress_d, against the budget of 832', 'strong', 'start', 14));
    tbl.push({ key: 'nb:tl', kind: 'path', d: `M726,270 V${280 + ds.length * 50}`, cls: 'needline', audit: 'ignore' });
    tbl.push(U.t('nb:tlt', 730, 268, '832', 'hot', 'start', 14));
    F.add({ items: [head, ...line(true), ...tbl], hl: { d: [1, 2] }, say: `The coarser the compression, the bigger the error: at most ${errs[ds.indexOf(p.du)]} for u (d_u = ${p.du}) but ${errs[ds.indexOf(p.dv)]} for v (d_v = ${p.dv}). A bit of m is lost only when the total noise in a coefficient of w reaches 832, about q/4, so these rounding errors spend part of that budget.`, facts: { du: p.du, dv: p.dv, eu: errs[ds.indexOf(p.du)], ev: errs[ds.indexOf(p.dv)], lim: 832, errs }, meta: { stage: 'table' } });
    // 3. the noise of one decapsulation, coefficient by coefficient
    const first = noiseOf(set, kg, inp.msg + ':0');
    const sp = U.plot({ prefix: 'nb:s', x: 80, y: 250, w: 800, h: 340, xr: [0, 256], yr: [-1000, 1000], xticks: [0, 64, 128, 192, 256], yticks: [-832, -400, 0, 400, 832], zero: true, ylabel: 'noise left in each coefficient of w', xlabel: 'coefficient', tickSize: 13 });
    const band = { key: 'nb:sb', kind: 'path', d: `M${sp.X(0)},${sp.Y(832)} H${sp.X(256)} V${sp.Y(-832)} H${sp.X(0)} Z`, cls: 'band', audit: 'ignore', layer: 'back' };
    const dots = first.noise.map((v, i) => ({ key: 'nb:sd' + i, kind: 'dot', x: sp.X(i + 0.5), y: sp.Y(v), r: 2.4, cls: Math.abs(v) === first.worst ? 'hot' : 'act' }));
    F.count('runs');
    F.add({ items: [head, ...line(false), band, ...sp.items, ...dots], hl: { d: [3, 4] }, say: `One real encapsulation and decapsulation: after w = v′ − sᵀu′, each of the 256 coefficients sits this far from the 0 or 1665 it encodes. The largest is ${first.worst}; the green band is ±832. Every bit decodes correctly${first.ok ? ', and the keys match' : ''}.`, facts: { worst: first.worst, lim: 832, n: 256, half: 1665 }, meta: { stage: 'one' } });
    // 4. many runs: the spread
    const runs = +inp.runs, all = first.noise.slice();
    let worst = first.worst, okAll = first.ok;
    for (let k = 1; k < runs; k++) { const r = noiseOf(set, kg, inp.msg + ':' + k); all.push(...r.noise); worst = Math.max(worst, r.worst); okAll = okAll && r.ok; F.count('runs'); }
    const bin = 40, hist = new Map();
    for (const v of all) { const b = Math.floor(v / bin); hist.set(b, (hist.get(b) || 0) + 1); }
    let topc = 1; for (const c of hist.values()) topc = Math.max(topc, c);
    const hp = U.plot({ prefix: 'nb:h', x: 80, y: 250, w: 800, h: 300, xr: [-1000, 1000], yr: [0, topc * 1.12], xticks: [-832, -400, 0, 400, 832], yticks: [], ylabel: `the noise of all ${all.length} coefficients from ${runs} encapsulations`, tickSize: 13 });
    const hb = [];
    for (const [b, c] of hist) { const x0 = Math.max(-1000, b * bin); hb.push({ key: 'nb:hb' + b, kind: 'cell', x: hp.X(x0), y: hp.Y(c), w: U.r2(hp.X(x0 + bin) - hp.X(x0) - 1), h: U.r2(hp.Y(0) - hp.Y(c)), rx: 1, text: '', cls: 'bar act' }); }
    for (const sg of [-1, 1]) hb.push({ key: 'nb:hl' + sg, kind: 'path', d: `M${hp.X(sg * 832)},${hp.Y(0)} V${hp.Y(topc * 1.12)}`, cls: 'needline', audit: 'ignore' });
    const margin = 832 / worst;
    F.add({ items: [head, ...line(false), ...hp.items, ...hb, U.t('nb:hw', 880, 604, `largest: ${worst}, budget 832`, 'strong', 'end', 15)], hl: { d: [4] }, say: `${runs} encapsulations, ${all.length} coefficients: the noise piles up in a narrow bell around 0, the sum of products of small secrets plus the rounding of u and v. The largest of all is ${worst}, ${U.fx(margin, 1)} times inside the budget. The parameters of ${p.name} are chosen so that a coefficient reaching 832 is astronomically rare, so a wrong key is, in practice, never seen.`, facts: { runs, n: all.length, worst, margin, lim: 832 }, meta: { stage: 'many', ok: okAll } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Compression and noise', ['Compress_d(x) = ⌈(2^d / q)·x⌋ mod 2^d', 'Decompress_d(y) = ⌈(q / 2^d)·y⌋', 'w = v′ − sᵀu′ = ⌈q/2⌋·m + eᵀy − sᵀe₁ + e₂ + (rounding)', 'a bit is right while its noise stays below q/4 ≈ 832', 'more compression: smaller c, more noise']) };
  }
  S.topic({
    id: 'pq-mlkem-noise', family: 'p14-mlkem', order: 30, title: 'Compression and the noise budget',
    blurb: 'ML-KEM throws away the low bits of its ciphertext to save space, which adds noise on purpose. Watch where that noise and the lattice noise leave each coefficient, against the 832 at which a bit would flip.',
    inputs: [
      { id: 'set', kind: 'choice', label: 'Parameter set', def: '768', options: ['512', '768', '1024'].map((v) => ({ value: v, label: 'ML-KEM-' + v })) },
      { id: 'x', kind: 'number', label: 'A value x to compress', def: 1000, min: 0, max: 3328 },
      { id: 'seed', kind: 'text', label: 'Key seed word', def: 'heron', check: (v) => (!v || v.length > 30 ? 'Seed word: 1 to 30 characters' : null) },
      { id: 'msg', kind: 'text', label: 'Message seed word', def: 'kingfisher', check: (v) => (!v || v.length > 30 ? 'Seed word: 1 to 30 characters' : null) },
      { id: 'runs', kind: 'choice', label: 'Encapsulations', def: '8', options: ['4', '8', '16'].map((v) => ({ value: v, label: v })) },
    ],
    presets: [
      { label: 'ML-KEM-768', values: { set: '768', x: 1000 } },
      { label: 'ML-KEM-512', values: { set: '512', x: 2500, seed: 'otter' } },
      { label: 'ML-KEM-1024 (d_v = 5)', values: { set: '1024', x: 1000, seed: 'lynx' } },
      { label: 'Sixteen runs', values: { set: '768', x: 104, runs: '16' } },
    ],
    counters: [{ id: 'runs', label: 'encapsulations' }],
    run: noise,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'table', pick: 'option', options: ['all well inside ±832', 'many near ±832', 'some beyond ±832'], ask: 'One real decapsulation is next. Where will the noise of its 256 coefficients lie?', answer: 'all well inside ±832', explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'What does Compress_d keep of a coefficient?', options: ['Its lowest d bits', 'About its top d bits: which of 2^d buckets of Z_q it falls in', 'Its sign', 'Nothing'], answer: 1, why: 'It rounds (2^d/q)·x; decompressing gives the middle of the bucket.' },
      { q: 'Why is v compressed more than u?', options: ['v is less important', 'v is a single polynomial; u is k of them, so compressing u hard would add noise k times over', 'By accident', 'u is secret'], answer: 1, why: 'The noise from u is multiplied by s and summed over k polynomials.' },
      { q: 'A bit of m decodes wrongly when the noise in its coefficient reaches about…', options: ['q/2', 'q/4 ≈ 832', '1', '3329'], answer: 1, why: 'Then the value is nearer the other of 0 and q/2.' },
      { q: 'Decryption failures matter for security because…', options: ['they do not', 'an attacker who can trigger and observe them learns about s', 'they slow things down', 'they change the key size'], answer: 1, why: 'Which is also why decapsulation re-encrypts and never reveals a failure.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Implicit rejection
  // ---------------------------------------------------------------------------------------------------------------
  function reject(inp) {
    const set = inp.set, p = K().params(set), kg = K().keyGen(set, { d: seed32('d', inp.seed), z: seed32('z', inp.seed) });
    const m = seed32('m', inp.msg), en = K().encaps(set, kg.ek, { m }), c = en.c;
    const c1len = 32 * p.du * p.k, byte = inp.where === 'none' ? -1 : inp.where === 'u' ? +inp.byte % c1len : c1len + (+inp.byte % (32 * p.dv));
    const ct = Uint8Array.from(c);
    if (byte >= 0) ct[byte] ^= 1 << +inp.bit;
    const de = K().decaps(set, kg.dk, ct), dm = de.trace.find((s) => s.kind === 'dec-m'), dw = de.trace.find((s) => s.kind === 'dec-w');
    const mb = K().byteDecode(m, 1), m2b = dm.bits, flipped = mb.reduce((n, b, i) => n + (b !== m2b[i] ? 1 : 0), 0);
    const [, r2] = K().G(P().concat(dm.m, K().H(kg.ek))), c2 = K().pkeEncrypt(p, kg.ek, dm.m, r2, []);
    const diff = c2.reduce((n, v, i) => n + (v !== ct[i] ? 1 : 0), 0);
    const Kbar = K().J(P().concat(kg.z, ct));
    const F = new S.Frames();
    const head = U.t('rj:h', 20, 30, `${p.name}: implicit rejection`, 'strong', 'start', 16);
    // the ciphertext as a carpet of bytes, 64 to a row; the tampered byte lit
    const per = 64, cs = 6.4;
    const carpet = (lit, mark) => {
      const rows = [];
      for (let r = 0; r * per < ct.length; r++) { let s = ''; for (let k = r * per; k < Math.min(ct.length, (r + 1) * per); k++) s += k === mark ? '2' : k < c1len ? (lit === 'u' ? '7' : '5') : lit === 'v' ? '3' : '1'; rows.push(s); }
      const h = rows.length * cs;
      return [{ key: 'rj:c', kind: 'bitmap', x: 20, y: 70, cw: cs, ch: cs, gap: 0.6, rows }, U.t('rj:cl', 20, 70 + h + 22, `c: ${ct.length} bytes, ${c1len} of u then ${32 * p.dv} of v${mark >= 0 ? `; byte ${mark} tampered` : ''}`, 'tick', 'start', 13)];
    };
    const bits = (key, y, label, b, other) => {
      const rows = []; for (let r = 0; r < 4; r++) { let s = ''; for (let k = 0; k < 64; k++) { const i = r * 64 + k; s += other && b[i] !== other[i] ? '2' : b[i] ? '1' : '0'; } rows.push(s); }
      return [U.t(key + ':l', 470, y - 8, label, 'strong', 'start', 14), { key, kind: 'bitmap', x: 470, y, cw: 6.4, ch: 9, gap: 0.6, rows }];
    };
    // Alice's checklist, filled in as she goes
    const steps = (upto) => U.readout('rj:st', 20, 260, 420, 'what decapsulation does', [
      ['1. decrypt m′', upto >= 1 ? (flipped ? flipped + ' bit' + (flipped === 1 ? '' : 's') + ' off' : 'm′ = m') : '…', upto >= 1 ? (flipped ? 'bad' : 'good') : ''],
      ['2. (K′, r′) = G(m′ ‖ h)', upto >= 2 ? 'done' : '…'],
      ['3. re-encrypt: c′', upto >= 2 ? diff + ' bytes differ' : '…', upto >= 2 ? (diff ? 'bad' : 'good') : ''],
      ['4. K̄ = J(z ‖ c)', upto >= 3 ? 'always computed' : '…'],
      ['5. output', upto >= 3 ? (diff ? 'K̄, silently' : 'K′') : '…', upto >= 3 ? (diff ? 'bad' : 'good') : ''],
    ], { dy: 32 });
    const keys = (rows) => U.readout('rj:k', 470, 430, 436, 'keys', rows, { dy: 30 });
    const facts0 = { ct: ct.length, c1: c1len, c2: 32 * p.dv, k: p.k };
    F.add({ items: [head, ...carpet('', -1), ...bits('rj:m', 90, 'Bob\'s m: 256 bits', mb)], say: `Bob encapsulates as usual: m = ${hex(m)} gives the key K = ${hex(en.K)} and a ciphertext c of ${c.length} bytes, which he sends to Alice.`, facts: Object.assign({ m: P().hex(m), K: P().hex(en.K) }, facts0), meta: { stage: 'send' } });
    if (byte >= 0) F.add({ items: [head, ...carpet(inp.where, byte), ...bits('rj:m', 90, 'Bob\'s m: 256 bits', mb)], say: `On the way, an attacker flips bit ${inp.bit} of byte ${byte}, which belongs to the ${inp.where === 'u' ? `u part (the first ${c1len} bytes)` : 'v part (the last ' + 32 * p.dv + ' bytes)'}. Byte ${byte} changes from ${U.hex2(c[byte])} to ${U.hex2(ct[byte])}.`, facts: Object.assign({ byte, bit: +inp.bit, from: U.hex2(c[byte]), to: U.hex2(ct[byte]) }, facts0), meta: { stage: 'tamper' } });
    F.add({ items: [head, ...carpet(inp.where, byte), ...bits('rj:m', 90, 'Bob\'s m', mb), ...bits('rj:m2', 200, 'Alice decrypts m′ (orange: bits that differ)', m2b, mb), ...steps(1)], hl: { d: [0] }, say: `Alice decrypts: the largest noise in w is ${dw.worst}, and m′ differs from m in ${flipped} ${flipped === 1 ? 'bit' : 'bits'}. ${flipped ? 'The tampering moved a coefficient of v across the quarter mark.' : byte >= 0 ? 'The change was small enough to be absorbed as noise: m′ is still m.' : 'm′ = m.'}`, facts: Object.assign({ worst: dw.worst, flipped }, facts0), meta: { stage: 'decrypt', flipped } });
    F.add({ items: [head, ...carpet(inp.where, byte), ...bits('rj:m', 90, 'Bob\'s m', mb), ...bits('rj:m2', 200, 'Alice decrypts m′', m2b, mb), ...steps(2), U.t('rj:re', 470, 330, `re-encrypting m′ gives c′; c′ and the received c differ in ${diff} ${diff === 1 ? 'byte' : 'bytes'}`, diff ? 'bad' : 'good', 'start', 14)], hl: { d: [1, 2] }, say: `She re-encrypts m′ with r′ from G(m′ ‖ H(ek)) and compares: c′ and the received ciphertext differ in ${diff} of ${ct.length} bytes. ${diff ? (flipped ? 'A different m′ means a different r′ and a whole new ciphertext.' : 'm′ was right, so c′ is the ciphertext Bob sent, and it differs from the tampered one exactly at the flipped byte.') : 'They are the same: c is exactly what an honest Bob would send.'}`, facts: Object.assign({ diff }, facts0), meta: { stage: 'compare', diff } });
    const same = P().eqBytes(de.K, en.K);
    F.add({ items: [head, ...carpet(inp.where, byte), ...bits('rj:m', 90, 'Bob\'s m', mb), ...bits('rj:m2', 200, 'Alice decrypts m′', m2b, mb), ...steps(3), ...keys([['Bob\'s K', hex(en.K, 24), 'good'], ['Alice\'s output', hex(de.K, 24), same ? 'good' : 'bad'], ['J(z ‖ c)', hex(Kbar, 24)], ['same as Bob?', same ? 'yes' : 'no', same ? 'good' : 'bad']])], hl: { d: de.rejected ? [3, 4] : [2] }, say: de.rejected ? `So decapsulation rejects, but silently: it returns K̄ = J(z ‖ c) = ${hex(de.K)}, made from the secret z and the received bytes. It looks exactly like a real key; only later, when the keys do not match, does the connection fail. No error message, no different timing: the attacker learns nothing about why.` : `Accepted: Alice's key is ${hex(de.K)}, the same as Bob's.`, facts: Object.assign({ K: P().hex(de.K), Kb: P().hex(en.K), J: P().hex(Kbar) }, facts0), meta: { stage: 'key', rejected: de.rejected } });
    if (de.rejected) F.add({ items: [head, ...carpet(inp.where, byte), ...keys([['explicit rejection', 'returns ⊥: tells the attacker', 'bad'], ['implicit rejection', 'returns J(z ‖ c): tells nothing', 'good'], ['K̄ for this c', hex(Kbar, 24)]])], hl: { d: [4] }, say: `Why not just say "invalid"? An attacker who changes ciphertexts and watches which ones fail can tell where decryption is near its edge, and every answer leaks a little about s. With implicit rejection every ciphertext, honest or not, gets a 32-byte answer that only the holder of z can compute, so tampering gains nothing.`, facts: Object.assign({ J: P().hex(Kbar), len: 32 }, facts0), meta: { stage: 'why' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Decaps with implicit rejection', ['m′ = Decrypt(dk, c)', '(K′, r′) = G(m′ ‖ h)', 'K̄ = J(z ‖ c)', 'c′ = Encrypt(ek, m′, r′)', 'return K′ if c′ = c, else K̄ (always computed)']) };
  }
  S.topic({
    id: 'pq-mlkem-reject', family: 'p14-mlkem', order: 40, title: 'Implicit rejection',
    blurb: 'Decapsulation re-encrypts what it decrypted and compares. A ciphertext that was tampered with gets a key all the same, made from a secret z, so an attacker cannot tell rejection from success.',
    inputs: [
      { id: 'set', kind: 'choice', label: 'Parameter set', def: '768', options: ['512', '768', '1024'].map((v) => ({ value: v, label: 'ML-KEM-' + v })) },
      { id: 'where', kind: 'choice', label: 'Tamper with', def: 'v', options: [{ value: 'none', label: 'nothing' }, { value: 'u', label: 'a byte of u' }, { value: 'v', label: 'a byte of v' }] },
      { id: 'byte', kind: 'number', label: 'Byte (within that part)', def: 9, min: 0, max: 959 },
      { id: 'bit', kind: 'choice', label: 'Bit', def: '3', options: [0, 1, 2, 3, 4, 5, 6, 7].map((v) => ({ value: String(v), label: String(v) })) },
      { id: 'seed', kind: 'text', label: 'Key seed word', def: 'heron', check: (v) => (!v || v.length > 30 ? 'Seed word: 1 to 30 characters' : null) },
      { id: 'msg', kind: 'text', label: 'Message seed word', def: 'kingfisher', check: (v) => (!v || v.length > 30 ? 'Seed word: 1 to 30 characters' : null) },
    ],
    presets: [
      { label: 'Top bit of a v coefficient', values: { set: '768', where: 'v', byte: 9, bit: '3' } },
      { label: 'Low bit of a u coefficient', values: { set: '768', where: 'u', byte: 100, bit: '0' } },
      { label: 'Untouched', values: { set: '768', where: 'none' } },
      { label: 'ML-KEM-512, v', values: { set: '512', where: 'v', byte: 40, bit: '7' } },
    ],
    run: reject,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'decrypt', pick: 'option', options: ['accept', 'reject'], ask: 'Will the re-encryption match what Alice received?', answer: (fr, i) => (fr[i + 1].meta.diff ? 'reject' : 'accept'), explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'What does ML-KEM decapsulation return for a tampered ciphertext?', options: ['An error', 'A pseudorandom key J(z ‖ c)', 'Nothing', 'The real key'], answer: 1, why: 'Implicit rejection: the output looks like any key.' },
      { q: 'Even when m′ = m, a tampered c is rejected because…', options: ['the noise is too large', 're-encryption gives Bob\'s original c, which differs from what arrived', 'z changed', 'it is not'], answer: 1, why: 'Only the exact honest ciphertext re-encrypts to itself.' },
      { q: 'Why is K̄ = J(z ‖ c) computed even when c is accepted?', options: ['To waste time', 'So that the time taken does not reveal which branch was taken', 'It is the key', 'To check z'], answer: 1, why: 'Doing the same work either way keeps the decision invisible.' },
      { q: 'The re-encrypt-and-compare check is part of…', options: ['the NTT', 'the Fujisaki–Okamoto transform', 'compression', 'key generation'], answer: 1, why: 'FO turns a passively secure encryption into a CCA-secure KEM.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
