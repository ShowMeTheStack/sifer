// Hash-based signatures, whose security rests on nothing but the hash function. The hash is SHAKE256 cut to n
// bytes, used as a tweakable hash with an address (as in the SHAKE versions of the standards), so that no two
// calls anywhere in a key ever hash the same input.
//   S.PQ.Lamport.keyGen(seed, {n}) / sign(sk, msg) / verify(pk, msg, sig) / forge(known, msg)
//   S.PQ.WOTS.keyGen(seed, {n, w, checksum}) / sign / verify / forge(pk, msg, sig, msg2)
//   S.PQ.Merkle.keyGen(seed, {h, n, w}) / sign(sk, msg) (stateful: uses sk.next) / verify(pk, msg, sig)
//   S.PQ.SLH.params() / keyGen(seed, params) / sign(sk, msg) / verify(pk, msg, sig)   a toy SLH-DSA (SPHINCS+)
// Messages and seeds may be strings or bytes. Every call returns a trace.
(function (S) {
  'use strict';
  const P = (S.PQ = S.PQ || {});
  const step = (...a) => P.step(...a);
  const enc = (m) => (typeof m === 'string' ? new TextEncoder().encode(m) : m);
  const short = (b) => P.hex(b).slice(0, 12) + (b.length > 6 ? '…' : '');
  const seedBytes = (seed, n, tag) => P.shake256(P.concat(enc(tag), enc(String(seed))), n);
  const bitsOf = (b, count) => Array.from({ length: count }, (_, i) => (b[i >> 3] >> (7 - (i & 7))) & 1);

  // ---------------------------------------------------------------------------------------------------------
  // Lamport: two secret strings per digest bit; a signature reveals one of each pair, so a key signs once.
  const Lm = (P.Lamport = {});
  Lm.keyGen = (seed = 'lamport', opts = {}) => {
    const n = opts.n || 32, bits = 8 * n, root = seedBytes(seed, 32, 'lamport-sk');
    const sk = Array.from({ length: bits }, (_, i) => [0, 1].map((b) => P.shake256(P.concat(root, [i >> 8, i & 255, b]), n)));
    const pk = sk.map((pair) => pair.map((x) => P.shake256(x, n)));
    const trace = [step('lamport-keys', `${bits} pairs of secret ${n}-byte strings; the public key is the hash of each: ${2 * bits} hashes, ${2 * bits * n} bytes.`, { bits, n })];
    return { sk: { n, sk, used: 0 }, pk: { n, pk }, trace };
  };
  Lm.digestBits = (n, msg) => bitsOf(P.shake256(enc(msg), n), 8 * n);
  Lm.sign = (sk, msg) => {
    const d = Lm.digestBits(sk.n, msg);
    sk.used++;
    const sig = d.map((b, i) => sk.sk[i][b]);
    const trace = [
      step('lamport-digest', `The digest of the message has bits ${d.slice(0, 24).join('')}…`, { bits: d }),
      step('lamport-reveal', `For each bit reveal one secret of the pair: the first if the bit is 0, the second if it is 1. ${sk.used > 1 ? `This key has now signed ${sk.used} times: secrets from both halves are public.` : 'The other halves stay secret.'}`, { bits: d, used: sk.used }),
    ];
    return { sig, trace };
  };
  Lm.verify = (pk, msg, sig) => {
    const d = Lm.digestBits(pk.n, msg);
    const bad = d.findIndex((b, i) => !P.eqBytes(P.shake256(sig[i], pk.n), pk.pk[i][b]));
    const trace = [step(bad < 0 ? 'lamport-ok' : 'lamport-bad', bad < 0 ? `Hash each revealed secret: all ${d.length} match the public halves chosen by the digest bits.` : `Bit ${bad}: the hash of the revealed string is not the public value ${short(pk.pk[bad][d[bad]])}. Reject.`, { bad })];
    return { ok: bad < 0, bad, trace };
  };
  /** with signatures known on some messages, can one be assembled for msg? Returns {sig | null, missing} */
  Lm.forge = (known, msg, n = 32) => {
    const revealed = new Map();
    for (const { msg: m, sig } of known) Lm.digestBits(n, m).forEach((b, i) => revealed.set(i + ':' + b, sig[i]));
    const d = Lm.digestBits(n, msg), missing = [];
    const sig = d.map((b, i) => { const v = revealed.get(i + ':' + b); if (!v) missing.push(i); return v; });
    const both = Array.from({ length: 8 * n }, (_, i) => revealed.has(i + ':0') && revealed.has(i + ':1')).filter(Boolean).length;
    return { sig: missing.length ? null : sig, missing, both, trace: [step('lamport-forge', missing.length ? `${missing.length} needed secrets were never revealed (bits ${missing.slice(0, 8).join(', ')}…): no forgery.` : `Every secret this digest needs has been revealed by earlier signatures (${both} pairs are fully known): a valid forgery.`, { missing, both })] };
  };

  // ---------------------------------------------------------------------------------------------------------
  // Addresses and the tweakable hash shared by WOTS, the Merkle tree and SLH-DSA.
  const T_WOTS = 0, T_WOTSPK = 1, T_TREE = 2, T_FORS = 3, T_FORSROOTS = 4, T_WOTSPRF = 5, T_FORSPRF = 6;
  const adrs = (o) => { const b = new Uint8Array(24); [o.layer | 0, o.tree | 0, o.type | 0, o.keypair | 0, o.chain | 0, o.hash | 0].forEach((v, i) => { b[4 * i] = v >>> 24; b[4 * i + 1] = (v >>> 16) & 255; b[4 * i + 2] = (v >>> 8) & 255; b[4 * i + 3] = v & 255; }); return b; };
  const Th = (ctx, a, ...m) => P.shake256(P.concat(ctx.pkSeed, adrs(a), ...m), ctx.n);
  const PRF = (ctx, a) => P.shake256(P.concat(ctx.pkSeed, adrs(a), ctx.skSeed), ctx.n);
  const lg = (w) => Math.log2(w);
  const wotsLens = (n, w) => { const len1 = Math.ceil((8 * n) / lg(w)), len2 = Math.floor(Math.log2(len1 * (w - 1)) / lg(w)) + 1; return { len1, len2, len: len1 + len2 }; };
  /** base-w digits of the n-byte message, then of its checksum Σ(w − 1 − dᵢ) */
  const digits = (n, w, M, withChecksum = true) => {
    const { len1, len2 } = wotsLens(n, w), b = lg(w), bits = bitsOf(M, 8 * n), d = [];
    for (let i = 0; i < len1; i++) { let v = 0; for (let j = 0; j < b; j++) v = 2 * v + (bits[i * b + j] || 0); d.push(v); }
    const csum = d.reduce((s, v) => s + (w - 1 - v), 0), cd = [];
    for (let i = len2 - 1; i >= 0; i--) cd.push(Math.floor(csum / w ** i) % w);
    return { msg: d, csum, check: withChecksum ? cd : [], all: withChecksum ? d.concat(cd) : d };
  };
  const chain = (ctx, x, start, steps, a) => { for (let j = start; j < start + steps; j++) x = Th(ctx, Object.assign({}, a, { type: T_WOTS, hash: j }), x); return x; };
  const wotsPk = (ctx, a, withChecksum = true) => {
    const { len1, len } = wotsLens(ctx.n, ctx.w), L = withChecksum ? len : len1, ends = [];
    for (let i = 0; i < L; i++) ends.push(chain(ctx, PRF(ctx, Object.assign({}, a, { type: T_WOTSPRF, chain: i })), 0, ctx.w - 1, Object.assign({}, a, { chain: i })));
    return { ends, pk: Th(ctx, Object.assign({}, a, { type: T_WOTSPK }), ...ends) };
  };
  const wotsSign = (ctx, M, a, withChecksum = true) => {
    const dg = digits(ctx.n, ctx.w, M, withChecksum);
    return { sig: dg.all.map((d, i) => chain(ctx, PRF(ctx, Object.assign({}, a, { type: T_WOTSPRF, chain: i })), 0, d, Object.assign({}, a, { chain: i }))), digits: dg };
  };
  const wotsPkFromSig = (ctx, sig, M, a, withChecksum = true) => {
    const dg = digits(ctx.n, ctx.w, M, withChecksum);
    const ends = sig.map((s, i) => chain(ctx, s, dg.all[i], ctx.w - 1 - dg.all[i], Object.assign({}, a, { chain: i })));
    return { ends, pk: Th(ctx, Object.assign({}, a, { type: T_WOTSPK }), ...ends), digits: dg };
  };
  const ctxFrom = (seed, n, w) => ({ n, w, skSeed: seedBytes(seed, n, 'sk-seed'), pkSeed: seedBytes(seed, n, 'pk-seed') });

  // Winternitz one-time signatures: a chain of w − 1 hashes per base-w digit; signing walks d steps up the chain.
  const Wo = (P.WOTS = {});
  Wo.lens = wotsLens;
  Wo.digits = digits;
  Wo.keyGen = (seed = 'winternitz', opts = {}) => {
    const n = opts.n || 16, w = opts.w || 16, withChecksum = opts.checksum !== false;
    const ctx = ctxFrom(seed, n, w), a = { layer: 0, tree: 0, keypair: 0 };
    const { ends, pk } = wotsPk(ctx, a, withChecksum), L = wotsLens(n, w);
    const trace = [step('wots-keys', `w = ${w}: ${L.len1} chains for the message digits${withChecksum ? ` and ${L.len2} for the checksum` : ', no checksum'}, each ${w - 1} hashes long. The public key is the hash of the ${ends.length} chain ends.`, { n, w, len1: L.len1, len2: withChecksum ? L.len2 : 0, ends })];
    return { sk: Object.assign({}, ctx, { withChecksum, used: 0 }), pk: { n, w, pkSeed: ctx.pkSeed, pk, ends, withChecksum }, trace };
  };
  Wo.sign = (sk, msg) => {
    const M = P.shake256(enc(msg), sk.n), r = wotsSign(sk, M, { layer: 0, tree: 0, keypair: 0 }, sk.withChecksum);
    sk.used++;
    const trace = [
      step('wots-digits', `The digest in base ${sk.w}: ${r.digits.msg.slice(0, 12).join(' ')}…`, { digits: r.digits.msg }),
      sk.withChecksum ? step('wots-checksum', `Checksum Σ(${sk.w - 1} − dᵢ) = ${r.digits.csum}, written in base ${sk.w} as ${r.digits.check.join(' ')}. Raising any message digit lowers the checksum, so forging means walking some chain backwards.`, { csum: r.digits.csum, check: r.digits.check }) : step('wots-nochecksum', 'Without a checksum, anyone can walk a chain further up and sign a digest with larger digits.', {}),
      step('wots-sign', `Chain i is walked dᵢ steps from its secret start: the signature is ${r.sig.length} values of ${sk.n} bytes.`, { positions: r.digits.all, w: sk.w }),
    ];
    return { sig: r.sig, digits: r.digits.all, trace };
  };
  Wo.verify = (pk, msg, sig) => {
    const M = P.shake256(enc(msg), pk.n), ctx = { n: pk.n, w: pk.w, pkSeed: pk.pkSeed };
    const r = wotsPkFromSig(ctx, sig, M, { layer: 0, tree: 0, keypair: 0 }, pk.withChecksum), ok = P.eqBytes(r.pk, pk.pk);
    const bad = r.ends.findIndex((e, i) => !P.eqBytes(e, pk.ends[i]));
    return { ok, trace: [step(ok ? 'wots-ok' : 'wots-bad', ok ? `Finish every chain (${pk.w - 1} − dᵢ more steps): all ${r.ends.length} ends match the public key.` : `Chain ${bad} ends at ${short(r.ends[bad])}, not at the public ${short(pk.ends[bad])}. Reject.`, { ends: r.ends, bad })] };
  };
  /** forging msg2 from a signature on msg needs every digit of msg2 (checksum included) to be at least msg's */
  Wo.forge = (pk, msg, sig, msg2) => {
    const d1 = digits(pk.n, pk.w, P.shake256(enc(msg), pk.n), pk.withChecksum).all, d2 = digits(pk.n, pk.w, P.shake256(enc(msg2), pk.n), pk.withChecksum).all;
    const blocked = d2.map((d, i) => (d < d1[i] ? i : -1)).filter((i) => i >= 0);
    if (blocked.length) return { sig: null, blocked, trace: [step('wots-forge-fail', `${blocked.length} chains would have to go backwards (first: chain ${blocked[0]}, from ${d1[blocked[0]]} down to ${d2[blocked[0]]}), which means inverting the hash.`, { blocked })] };
    const ctx = { n: pk.n, w: pk.w, pkSeed: pk.pkSeed };
    const forged = sig.map((s, i) => chain(ctx, s, d1[i], d2[i] - d1[i], { layer: 0, tree: 0, keypair: 0, chain: i }));
    return { sig: forged, blocked, trace: [step('wots-forge', 'Every digit of the new digest is at least the old one: walk each chain forward and the forgery verifies.', {})] };
  };

  // ---------------------------------------------------------------------------------------------------------
  // A Merkle tree (as in XMSS) of 2^h WOTS keys: the root is the public key; a signature is one WOTS signature
  // and the h sibling nodes (the authentication path) that lead from its leaf to the root.
  const xmssLevels = (ctx, h, a) => {
    const levels = [Array.from({ length: 2 ** h }, (_, i) => wotsPk(ctx, Object.assign({}, a, { keypair: i })).pk)];
    for (let z = 1; z <= h; z++) {
      const prev = levels[z - 1], cur = [];
      for (let i = 0; i < prev.length / 2; i++) cur.push(Th(ctx, Object.assign({}, a, { type: T_TREE, chain: z, hash: i }), prev[2 * i], prev[2 * i + 1]));
      levels.push(cur);
    }
    return levels;
  };
  const authPath = (levels, idx) => levels.slice(0, -1).map((lv, z) => lv[(idx >> z) ^ 1]);
  const climb = (ctx, leaf, idx, auth, a, record) => {
    let node = leaf;
    auth.forEach((sib, z) => {
      const i = idx >> (z + 1), left = ((idx >> z) & 1) === 0;
      node = Th(ctx, Object.assign({}, a, { type: T_TREE, chain: z + 1, hash: i }), left ? node : sib, left ? sib : node);
      if (record) record.push({ level: z + 1, index: i, node, sibling: sib, side: left ? 'right' : 'left' });
    });
    return node;
  };
  const Mk = (P.Merkle = {});
  Mk.keyGen = (seed = 'merkle', opts = {}) => {
    const h = opts.h || 3, n = opts.n || 16, w = opts.w || 16, ctx = ctxFrom(seed, n, w);
    const levels = xmssLevels(ctx, h, { layer: 0, tree: 0 }), root = levels[h][0];
    const trace = [
      step('merkle-leaves', `${2 ** h} WOTS key pairs; each leaf is the hash of one WOTS public key.`, { leaves: levels[0] }),
      step('merkle-root', `Hash pairs upward through ${h} levels to the root ${short(root)}: the whole public key is ${n} bytes.`, { levels, root }),
    ];
    return { sk: Object.assign({}, ctx, { h, next: 0, levels }), pk: { n, w, h, pkSeed: ctx.pkSeed, root }, levels, trace };
  };
  Mk.sign = (sk, msg) => {
    if (sk.next >= 2 ** sk.h) throw new Error('every one-time key of this tree has been used');
    const idx = sk.next++, M = P.shake256(enc(msg), sk.n), a = { layer: 0, tree: 0, keypair: idx };
    const ws = wotsSign(sk, M, a), auth = authPath(sk.levels, idx);
    const trace = [
      step('merkle-state', `Use one-time key ${idx}, and advance the state to ${sk.next}: a key reused would leak like Lamport.`, { idx }),
      step('merkle-wots', `Sign the digest with WOTS key ${idx}: ${ws.sig.length} chain values.`, { digits: ws.digits.all }),
      step('merkle-auth', `Attach the authentication path: the ${sk.h} siblings ${auth.map(short).join(', ')}.`, { auth, idx }),
    ];
    return { sig: { idx, wots: ws.sig, auth }, trace };
  };
  Mk.verify = (pk, msg, sig) => {
    const ctx = { n: pk.n, w: pk.w, pkSeed: pk.pkSeed }, M = P.shake256(enc(msg), pk.n);
    const leaf = wotsPkFromSig(ctx, sig.wots, M, { layer: 0, tree: 0, keypair: sig.idx }).pk, path = [];
    const root = climb(ctx, leaf, sig.idx, sig.auth, { layer: 0, tree: 0 }, path), ok = P.eqBytes(root, pk.root);
    const trace = [
      step('merkle-leaf', `Finish the WOTS chains and hash their ends: leaf ${sig.idx} = ${short(leaf)}.`, { leaf, idx: sig.idx }),
      ...path.map((p) => step('merkle-climb', `Level ${p.level}: hash with the sibling on the ${p.side} to get node ${p.index} = ${short(p.node)}.`, p)),
      step(ok ? 'merkle-ok' : 'merkle-bad', ok ? `The computed root equals the public key. Accept.` : `The computed root ${short(root)} is not the public ${short(pk.root)}. Reject.`, { root }),
    ];
    return { ok, trace };
  };

  // ---------------------------------------------------------------------------------------------------------
  // A toy SLH-DSA: the message picks one FORS key at the bottom of a hypertree of d layers of Merkle trees of
  // height h/d. FORS signs the digest (a few-time signature); each tree layer signs the root of the one below with
  // WOTS. No state is kept: the leaf is chosen by the message hash, and the tree is big enough that a reuse is rare.
  const Sl = (P.SLH = {});
  Sl.params = (o = {}) => {
    const p = Object.assign({ n: 16, h: 6, d: 2, a: 3, k: 4, w: 16 }, o);
    p.hp = p.h / p.d;
    if (!Number.isInteger(p.hp)) throw new Error('h must be a multiple of d');
    const { len } = wotsLens(p.n, p.w);
    p.sigBytes = p.n + p.k * (1 + p.a) * p.n + p.d * (len + p.hp) * p.n;
    p.mdBits = p.k * p.a;
    return p;
  };
  const forsLeaf = (ctx, a, idx) => Th(ctx, Object.assign({}, a, { type: T_FORS, chain: 0, hash: idx }), PRF(ctx, Object.assign({}, a, { type: T_FORSPRF, hash: idx })));
  const forsTree = (ctx, p, a, t) => {
    const levels = [Array.from({ length: 2 ** p.a }, (_, j) => forsLeaf(ctx, a, t * 2 ** p.a + j))];
    for (let z = 1; z <= p.a; z++) {
      const prev = levels[z - 1], cur = [];
      for (let i = 0; i < prev.length / 2; i++) cur.push(Th(ctx, Object.assign({}, a, { type: T_FORS, chain: z, hash: t * 2 ** (p.a - z) + i }), prev[2 * i], prev[2 * i + 1]));
      levels.push(cur);
    }
    return levels;
  };
  const forsClimb = (ctx, p, a, t, j, leaf, auth) => {
    let node = leaf;
    auth.forEach((sib, z) => {
      const left = ((j >> z) & 1) === 0, i = t * 2 ** (p.a - z - 1) + (j >> (z + 1));
      node = Th(ctx, Object.assign({}, a, { type: T_FORS, chain: z + 1, hash: i }), left ? node : sib, left ? sib : node);
    });
    return node;
  };
  const toInt = (bits) => bits.reduce((v, b) => v * 2 + b, 0);
  const digest = (p, R, pk, msg) => {
    const bits = bitsOf(P.shake256(P.concat(R, pk.pkSeed, pk.root, enc(msg)), Math.ceil((p.mdBits + p.h) / 8) + 1), p.mdBits + p.h);
    const md = Array.from({ length: p.k }, (_, i) => toInt(bits.slice(i * p.a, (i + 1) * p.a)));
    const treeBits = bits.slice(p.mdBits, p.mdBits + p.h - p.hp), leafBits = bits.slice(p.mdBits + p.h - p.hp);
    return { md, tree: toInt(treeBits), leaf: toInt(leafBits) };
  };
  Sl.keyGen = (seed = 'slh', params) => {
    const p = params || Sl.params(), ctx = ctxFrom(seed, p.n, p.w);
    const top = xmssLevels(ctx, p.hp, { layer: p.d - 1, tree: 0 }), root = top[p.hp][0];
    const trace = [step('slh-keys', `Toy SLH-DSA: n = ${p.n}, a hypertree of height ${p.h} in ${p.d} layers of trees of height ${p.hp}, FORS with k = ${p.k} trees of height a = ${p.a}, w = ${p.w}. The public key is the root of the top tree, ${short(root)}, with the public seed.`, { params: p, root })];
    return { sk: Object.assign({}, ctx, { p, prf: seedBytes(seed, p.n, 'sk-prf'), root }), pk: { p, pkSeed: ctx.pkSeed, root }, trace };
  };
  Sl.sign = (sk, msg) => {
    const p = sk.p, trace = [];
    const R = P.shake256(P.concat(sk.prf, sk.pkSeed, enc(msg)), p.n);
    const { md, tree, leaf } = digest(p, R, { pkSeed: sk.pkSeed, root: sk.root }, msg);
    trace.push(step('slh-digest', `R = PRF(sk.prf, msg) = ${short(R)} randomises the hash. The digest gives ${p.k} FORS indices (${md.join(', ')}), bottom tree ${tree} and leaf ${leaf}.`, { R, md, tree, leaf }));
    const fa = { layer: 0, tree, keypair: leaf }, fors = [], roots = [];
    for (let t = 0; t < p.k; t++) {
      const lv = forsTree(sk, p, fa, t), j = md[t];
      fors.push({ sk: PRF(sk, Object.assign({}, fa, { type: T_FORSPRF, hash: t * 2 ** p.a + j })), auth: authPath(lv, j) });
      roots.push(lv[p.a][0]);
    }
    let node = Th(sk, Object.assign({}, fa, { type: T_FORSROOTS }), ...roots);
    trace.push(step('slh-fors', `FORS reveals one secret leaf in each of its ${p.k} trees, with its path of ${p.a} siblings. The FORS public key (hash of the ${p.k} roots) is ${short(node)}.`, { md, roots, forsPk: node }));
    const layers = [];
    let t = tree, l = leaf;
    for (let layer = 0; layer < p.d; layer++) {
      const a = { layer, tree: t }, levels = xmssLevels(sk, p.hp, a);
      const ws = wotsSign(sk, node, Object.assign({}, a, { keypair: l }));
      layers.push({ wots: ws.sig, auth: authPath(levels, l), tree: t, leaf: l });
      const root = levels[p.hp][0];
      trace.push(step('slh-layer', `Layer ${layer}, tree ${t}, leaf ${l}: WOTS signs ${short(node)}; the tree's root ${short(root)} is what the layer above signs${layer === p.d - 1 ? ' — at the top it is the public key' : ''}.`, { layer, tree: t, leaf: l, signed: node, root }));
      node = root; l = t & (2 ** p.hp - 1); t = t >> p.hp;
    }
    trace.push(step('slh-size', `Signature: R, ${p.k}×(1 + ${p.a}) FORS values and ${p.d}×(WOTS + ${p.hp} path) values = ${p.sigBytes} bytes.`, { bytes: p.sigBytes }));
    return { sig: { R, fors, layers }, trace };
  };
  Sl.verify = (pk, msg, sig) => {
    const p = pk.p, ctx = { n: p.n, w: p.w, pkSeed: pk.pkSeed }, trace = [];
    const { md, tree, leaf } = digest(p, sig.R, pk, msg), fa = { layer: 0, tree, keypair: leaf };
    const roots = sig.fors.map((f, t) => forsClimb(ctx, p, fa, t, md[t], Th(ctx, Object.assign({}, fa, { type: T_FORS, chain: 0, hash: t * 2 ** p.a + md[t] }), f.sk), f.auth));
    let node = Th(ctx, Object.assign({}, fa, { type: T_FORSROOTS }), ...roots);
    trace.push(step('slh-v-fors', `Recompute the ${p.k} FORS roots from the revealed leaves: FORS public key ${short(node)}.`, { forsPk: node }));
    let t = tree, l = leaf;
    for (let layer = 0; layer < p.d; layer++) {
      const L = sig.layers[layer], a = { layer, tree: t };
      const lf = wotsPkFromSig(ctx, L.wots, node, Object.assign({}, a, { keypair: l })).pk;
      node = climb(ctx, lf, l, L.auth, a);
      trace.push(step('slh-v-layer', `Layer ${layer}: the WOTS signature gives leaf ${l}, its path gives the root ${short(node)}.`, { layer, root: node }));
      l = t & (2 ** p.hp - 1); t = t >> p.hp;
    }
    const ok = P.eqBytes(node, pk.root);
    trace.push(step(ok ? 'slh-ok' : 'slh-bad', ok ? 'The top root is the public key. Accept.' : 'The top root differs from the public key. Reject.', {}));
    return { ok, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
