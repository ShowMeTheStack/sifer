// Part 14, hash-based signatures, second half: a Merkle tree of one-time keys, with the authentication path that
// lets a verifier climb from one leaf to the root; and the structure of SLH-DSA, a hypertree of such trees with a
// few-time FORS key at the bottom, chosen by the message itself, so no state need be kept.
(function (S) {
  'use strict';
  const U = S.P14, P = () => S.PQ;
  const hx = (b, n) => P().hex(b).slice(0, n || 4);

  // ---------------------------------------------------------------------------------------------------------------
  // Merkle tree
  // ---------------------------------------------------------------------------------------------------------------
  function merkle(inp) {
    const h = +inp.h, N = 2 ** h, idx = Math.min(+inp.leaf, N - 1), Mk = P().Merkle;
    const kg = Mk.keyGen(inp.seed, { h }), levels = kg.levels;
    // the state: earlier one-time keys have been used already
    for (let k = 0; k < idx; k++) Mk.sign(kg.sk, 'an earlier message ' + k);
    const sg = Mk.sign(kg.sk, inp.msg), vr = Mk.verify(kg.pk, inp.msg, sg.sig);
    const cw = Math.min(64, 860 / N - 6), top = 80, levH = Math.min(130, 460 / h);
    const NX = (z, i) => U.r2(30 + ((i + 0.5) * 860) / (N >> z)), NY = (z) => U.r2(top + (h - z) * levH);
    const climb = vr.trace.filter((t) => t.kind === 'merkle-climb');
    const tree = (o) => {
      const items = [];
      for (let z = 0; z <= h; z++) for (let i = 0; i < N >> z; i++) {
        const onPath = (idx >> z) === i, sib = z < h && ((idx >> z) ^ 1) === i;
        const shown = z <= (o.built === undefined ? h : o.built);
        let cls = '';
        if (o.path && onPath) cls = z <= o.climbed ? 'act' : 'soft';
        if (o.auth && sib) cls = 'hot';
        if (z === h && o.rootCls) cls = o.rootCls;
        if (z === 0 && i < idx && o.used) cls = 'muted soft';
        if (z === 0 && i === idx && o.leaf) cls = 'keyhot';
        if (!shown) continue;
        items.push({ key: 'mk:n' + z + '_' + i, kind: 'cell', x: U.r2(NX(z, i) - cw / 2), y: NY(z) - 15, w: U.r2(cw), h: 30, rx: 4, text: hx(levels[z][i], cw > 50 ? 4 : 3), size: 13, cls: 'hex ' + cls });
        if (z > 0) for (const c of [2 * i, 2 * i + 1]) items.push({ key: 'mk:e' + z + '_' + c, kind: 'wire', pts: [[NX(z - 1, c), NY(z - 1) - 15], [NX(z, i), NY(z) + 15]], cls: o.path && (idx >> (z - 1)) === c && z <= o.climbed ? 'act' : '' });
      }
      items.push(U.t('mk:root', NX(h, 0) + cw / 2 + 10, NY(h) + 5, 'root = public key', 'act', 'start', 14));
      items.push(U.t('mk:lv', 30, NY(0) + 36, `${N} leaves: each the hash of one WOTS public key`, 'tick', 'start', 13));
      return items;
    };
    const note = (rows) => rows.map(([t, c], k) => U.t('mk:x' + k, 30, 604 + 26 * k, t, c || 'strong', 'start', 15));
    const F = new S.Frames(['hashes']);
    const head = U.t('mk:h', 20, 30, `A Merkle tree of ${N} one-time keys (height ${h})`, 'strong', 'start', 16);
    const facts0 = { h, N, idx };
    F.add({ items: [head, ...tree({ built: 0 })], hl: { d: [0] }, say: kg.trace[0].say + ' Each can sign once; the tree lets one short public key stand for all of them.', facts: facts0, meta: { stage: 'leaves' } });
    for (let z = 1; z <= h; z++) { F.count('hashes', N >> z); F.add({ items: [head, ...tree({ built: z })], hl: { d: [1] }, say: z < h ? `Level ${z}: hash each pair of nodes below into their parent, ${N >> z} ${N >> z === 1 ? 'node' : 'nodes'}.` : kg.trace[1].say, facts: Object.assign({ z, count: N >> z, n: 16 }, facts0), meta: { stage: 'build', z } }); }
    F.add({ items: [head, ...tree({ used: true, leaf: true }), ...note([[`signing “${inp.msg}” with one-time key ${idx}`, 'key']])], hl: { d: [2] }, say: sg.trace[0].say + (idx ? ` Keys 0 to ${idx - 1} were used for earlier messages.` : '') + ' ' + sg.trace[1].say, facts: Object.assign({ next: idx + 1, prev: idx - 1, chains: sg.sig.wots.length }, facts0), meta: { stage: 'sign' } });
    F.add({ items: [head, ...tree({ used: true, leaf: true, auth: true }), ...note([[`authentication path: ${sg.sig.auth.map((a) => hx(a)).join(', ')}`, 'hot']])], hl: { d: [3] }, say: sg.trace[2].say + ` The signature is the WOTS signature, the index ${idx}, and these ${h} nodes.`, facts: Object.assign({ auth: sg.sig.auth.map((a) => P().hex(a)) }, facts0), meta: { stage: 'auth' } });
    F.add({ items: [head, ...tree({ leaf: true, auth: true, path: true, climbed: 0 }), ...note([[vr.trace[0].say, 'act']])], hl: { d: [4] }, say: `The verifier knows only the root. ${vr.trace[0].say}`, facts: Object.assign({ leaf: P().hex(vr.trace[0].leaf) }, facts0), meta: { stage: 'leaf' } });
    climb.forEach((c, k) => { F.count('hashes'); F.add({ items: [head, ...tree({ leaf: true, auth: true, path: true, climbed: k + 1 })], hl: { d: [4] }, say: c.say, facts: Object.assign({ level: c.level, index: c.index, node: P().hex(c.node) }, facts0), meta: { stage: 'climb', k } }); });
    const okT = vr.trace[vr.trace.length - 1];
    F.add({ items: [head, ...tree({ leaf: true, auth: true, path: true, climbed: h, rootCls: vr.ok ? 'good' : 'bad' }), ...note([[okT.say, vr.ok ? 'good' : 'bad'], [`next free key: ${idx + 1} of ${N}; the signer must remember it`, 'strong']])], hl: { d: [5] }, say: `${okT.say} The tree signs ${N} messages with a public key of 16 bytes, but the signer must keep state: key ${idx} is spent, and using it again would leak like Lamport. After ${N} signatures the tree is used up.`, facts: Object.assign({ next: idx + 1, n: 16 }, facts0), meta: { stage: 'done' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Merkle signatures (as in XMSS)', ['leaves: Lᵢ = H(WOTS public key i)', 'node = H(left child ‖ right child); root = public key', 'sign with key i (then i + 1: the state)', 'signature: WOTS sig, i, the h siblings on the path', 'verify: rebuild leaf i, climb with the siblings, compare with the root', 'the tree is used up after 2^h signatures']) };
  }
  S.topic({
    id: 'pq-merkle', family: 'p14-hashsig', order: 30, title: 'Merkle trees and the authentication path',
    blurb: 'Many one-time keys under one public key: hash them in pairs up to a root. A signature carries the siblings along the path from its leaf, and the verifier climbs from the leaf to the root.',
    inputs: [
      { id: 'h', kind: 'choice', label: 'Height', def: '3', options: ['2', '3', '4'].map((v) => ({ value: v, label: v + ' (' + 2 ** +v + ' keys)' })) },
      { id: 'leaf', kind: 'number', label: 'One-time key to use', def: 5, min: 0, max: 15 },
      { id: 'seed', kind: 'text', label: 'Key seed', def: 'beacon', check: (v) => (!v || v.length > 30 ? 'Key seed: 1 to 30 characters' : null) },
      { id: 'msg', kind: 'text', label: 'Message', def: 'the bridge opens at noon', check: (v) => (!v || v.length > 50 ? 'Message: 1 to 50 characters' : null) },
    ],
    presets: [
      { label: 'Height 3, key 5', values: { h: '3', leaf: 5 } },
      { label: 'Height 3, key 0', values: { h: '3', leaf: 0 } },
      { label: 'Height 2, key 2', values: { h: '2', leaf: 2 } },
      { label: 'Height 4, key 11', values: { h: '4', leaf: 11 } },
    ],
    counters: [{ id: 'hashes', label: 'tree hashes' }],
    run: merkle,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'sign', pick: 'item', ask: 'Click the node that is the first sibling on the authentication path.', answer: (fr, i, inp) => 'mk:n0_' + (Math.min(+inp.leaf, 2 ** +inp.h - 1) ^ 1), explain: 'The first sibling is the leaf next to ours: the one that shares its parent.' }],
    quiz: [
      { q: 'How many nodes does the authentication path of a tree of height h have?', options: ['1', 'h', '2^h', 'h²'], answer: 1, why: 'One sibling per level.' },
      { q: 'Why must a Merkle signer keep state?', options: ['To store the root', 'Each one-time key may sign only once, so it must remember which are used', 'For speed', 'It need not'], answer: 1, why: 'Reusing a leaf would reveal more of a one-time key.' },
      { q: 'The public key of a Merkle signature scheme is…', options: ['all the WOTS keys', 'the root hash', 'the authentication path', 'the leaf index'], answer: 1, why: 'One hash stands for all the leaves.' },
      { q: 'Verifying costs about…', options: ['2^h hashes', 'the WOTS chains plus h hashes', 'one hash', 'a modular exponentiation'], answer: 1, why: 'Rebuild the leaf, then one hash per level.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // SLH-DSA: the hypertree and FORS
  // ---------------------------------------------------------------------------------------------------------------
  /** a small binary tree of height hh drawn as dots and one path of edges; the path from leaf `leaf` lit */
  function miniTree(key, cx, y0, width, hh, leaf, cls, lit) {
    const n = 2 ** hh, items = [], dy = 26;
    const X = (z, i) => U.r2(cx - width / 2 + ((i + 0.5) * width) / (n >> z)), Y = (z) => U.r2(y0 + (hh - z) * dy);
    let d = '';
    for (let z = 1; z <= hh; z++) for (let i = 0; i < n >> z; i++) for (const c of [2 * i, 2 * i + 1]) d += `M${X(z - 1, c)},${Y(z - 1)} L${X(z, i)},${Y(z)} `;
    items.push({ key: key + ':e', kind: 'path', d, cls: 'dline ' + (lit ? 'soft' : 'faint'), audit: 'ignore', layer: 'back' });
    if (lit && leaf !== null) {
      let pd = '';
      for (let z = 1; z <= hh; z++) pd += `M${X(z - 1, leaf >> (z - 1))},${Y(z - 1)} L${X(z, leaf >> z)},${Y(z)} `;
      items.push({ key: key + ':p', kind: 'path', d: pd, cls: 'dline ' + cls, audit: 'ignore' });
    }
    for (let z = 0; z <= hh; z++) for (let i = 0; i < n >> z; i++) {
      const on = lit && leaf !== null && (leaf >> z) === i;
      items.push({ key: key + ':d' + z + '_' + i, kind: 'dot', x: X(z, i), y: Y(z), r: on ? 4.5 : 2.6, cls: on ? cls : 'lat', layer: on ? 'items' : 'back' });
    }
    return { items, root: [X(hh, 0), Y(hh)], leafAt: (i) => [X(0, i), Y(0)] };
  }
  function slh(inp) {
    const p = P().SLH.params(), kg = P().SLH.keyGen(inp.seed, p), sg = P().SLH.sign(kg.sk, inp.msg), vr = P().SLH.verify(kg.pk, inp.msg, sg.sig);
    const dgs = sg.trace[0], md = dgs.md, tree = dgs.tree, leaf = dgs.leaf;
    const nb = 2 ** (p.h - p.hp), topLeaf = tree & (2 ** p.hp - 1);
    const F = new S.Frames();
    const head = U.t('sl:h', 20, 30, `A toy SLH-DSA: hypertree of ${p.d} layers of trees of height ${p.hp}, FORS of ${p.k} trees of height ${p.a}`, 'strong', 'start', 16);
    const scene = (stage) => {
      const items = [head];
      const lit = (s) => ['digest', 'fors', 'layer0', 'layer1', 'size', 'verify'].indexOf(stage) >= ['digest', 'fors', 'layer0', 'layer1', 'size', 'verify'].indexOf(s);
      // top layer: one tree, whose root is the public key
      const top = miniTree('sl:t', 460, 74, 300, p.hp, lit('layer1') ? topLeaf : null, 'act', true);
      items.push(...top.items, U.t('sl:tl', 660, 92, `layer ${p.d - 1}: the root is the public key`, 'act', 'start', 14), U.t('sl:pk', 460, 64, 'PK ' + hx(kg.pk.root, 8), 'mono', 'middle', 14));
      // bottom layer: 2^(h − h′) trees; the message picks one
      const bw = 96, gap = 14, x0 = 460 - (nb * (bw + gap) - gap) / 2;
      let chosenRoot = null, chosenLeaf = null;
      for (let t = 0; t < nb; t++) {
        const cx = x0 + t * (bw + gap) + bw / 2, on = t === tree;
        const mt = miniTree('sl:b' + t, cx, 214, bw, p.hp, on && lit('layer0') ? leaf : null, 'key', on && lit('digest'));
        items.push(...mt.items);
        items.push(U.t('sl:bn' + t, cx, 316, 'tree ' + t, on && lit('digest') ? 'key' : 'tick', 'middle', 13));
        if (on) { chosenRoot = mt.root; chosenLeaf = mt.leafAt(leaf); }
      }
      items.push(U.t('sl:bl', 20, 204, 'layer 0', 'strong', 'start', 14));
      if (lit('layer1')) items.push({ key: 'sl:up', kind: 'path', d: `M${chosenRoot[0]},${chosenRoot[1] - 6} L${top.leafAt(topLeaf)[0]},${top.leafAt(topLeaf)[1] + 6}`, cls: 'dline act', audit: 'ignore' });
      // FORS: k trees of height a, one leaf revealed in each
      const fw = 150, fg = 24, f0 = 460 - (p.k * (fw + fg) - fg) / 2;
      items.push(...U.panel('sl:fp', f0 - 16, 372, p.k * (fw + fg) - fg + 32, 150, ''));
      items.push(U.t('sl:fl', f0, 394, `FORS key under tree ${tree}, leaf ${leaf}: ${p.k} trees of ${2 ** p.a} secret leaves`, lit('digest') ? 'key' : 'strong', 'start', 14));
      for (let t = 0; t < p.k; t++) {
        const cx = f0 + t * (fw + fg) + fw / 2;
        const ft = miniTree('sl:f' + t, cx, 416, fw, p.a, lit('fors') ? md[t] : null, 'hot', lit('digest'));
        items.push(...ft.items, U.t('sl:fi' + t, cx, 512, lit('digest') ? 'index ' + md[t] : '', 'hot', 'middle', 13));
      }
      if (lit('layer0')) items.push({ key: 'sl:fup', kind: 'path', d: `M460,372 L${chosenLeaf[0]},${chosenLeaf[1] + 6}`, cls: 'dline key', audit: 'ignore' });
      return items;
    };
    const note = (rows) => rows.map(([t, c], k) => U.t('sl:x' + k, 20, 566 + 28 * k, t, c || 'strong', 'start', 15));
    const facts0 = { d: p.d, hp: p.hp, k: p.k, a: p.a, n: p.n, w: p.w, h: p.h, trees: nb, leaves: 2 ** p.a };
    F.add({ items: [...scene('keys'), ...note([[`${nb} bottom trees × ${2 ** p.hp} leaves = ${nb * 2 ** p.hp} FORS keys under one public key`, 'strong']])], hl: { d: [0] }, say: kg.trace[0].say + ` Below the top tree hang ${nb} trees of layer 0, and under each of their ${2 ** p.hp} leaves a FORS key: ${nb * 2 ** p.hp} in all, none of them computed until needed.`, facts: Object.assign({ total: nb * 2 ** p.hp, root: P().hex(kg.pk.root) }, facts0), meta: { stage: 'keys' } });
    F.add({ items: [...scene('digest'), ...note([[`digest → FORS indices ${md.join(', ')}; tree ${tree}, leaf ${leaf}`, 'key']])], hl: { d: [1] }, say: dgs.say + ' The message itself chooses where in the hypertree to sign, so the signer keeps no state; with real sizes (h = 63 or more) two messages landing on the same FORS key is rare, and FORS tolerates a few.', facts: Object.assign({ md, tree, leaf, R: P().hex(dgs.R), real: 63 }, facts0), meta: { stage: 'digest' } });
    F.add({ items: [...scene('fors'), ...note([[`FORS public key ${hx(sg.trace[1].forsPk, 12)}`, 'hot']])], hl: { d: [2] }, say: sg.trace[1].say, facts: Object.assign({ fpk: P().hex(sg.trace[1].forsPk) }, facts0), meta: { stage: 'fors' } });
    const L0 = sg.trace[2], L1 = sg.trace[3];
    F.add({ items: [...scene('layer0'), ...note([[`WOTS (tree ${L0.tree}, leaf ${L0.leaf}) signs the FORS key; this tree's root: ${hx(L0.root, 12)}`, 'key']])], hl: { d: [3] }, say: L0.say, facts: Object.assign({ tree: L0.tree, leaf: L0.leaf, signed: P().hex(L0.signed), root: P().hex(L0.root) }, facts0), meta: { stage: 'layer0' } });
    F.add({ items: [...scene('layer1'), ...note([[`WOTS (top tree, leaf ${L1.leaf}) signs that root; up to the public key`, 'act']])], hl: { d: [3, 4] }, say: L1.say, facts: Object.assign({ tree: L1.tree, leaf: L1.leaf, signed: P().hex(L1.signed), root: P().hex(L1.root) }, facts0), meta: { stage: 'layer1' } });
    const sz = sg.trace[4];
    F.add({ items: [...scene('size'), ...note([[`signature: ${sz.bytes} bytes`, 'strong']])], hl: { d: [5] }, say: sz.say + ' The real parameter sets give signatures of about 8 to 50 kilobytes: the price of resting on nothing but a hash function.', facts: Object.assign({ bytes: sz.bytes, lo: 8, hi: 50 }, facts0), meta: { stage: 'size' } });
    F.add({ items: [...scene('verify'), ...note([[vr.ok ? 'verified: the climb ends at the public key' : 'rejected', vr.ok ? 'good' : 'bad']])], hl: { d: [6] }, say: vr.trace.map((t) => t.say).join(' '), facts: Object.assign({ fpk: P().hex(vr.trace[0].forsPk), r0: P().hex(vr.trace[1].root), r1: P().hex(vr.trace[2].root) }, facts0), meta: { stage: 'verify', ok: vr.ok } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('SLH-DSA (toy sizes)', ['public key: the root of the top tree (and a public seed)', 'R = PRF(sk.prf, M); digest = H(R, PK, M)', 'digest → FORS indices, a bottom tree and a leaf', 'FORS reveals one secret leaf per tree, with its path', 'each layer: WOTS signs the root of the layer below', 'verify: rebuild FORS key, climb every layer, compare with PK', 'stateless: the message picks the leaf']) };
  }
  S.topic({
    id: 'pq-slhdsa', family: 'p14-hashsig', order: 40, title: 'SLH-DSA: the hypertree and FORS',
    blurb: 'A tree of trees of one-time keys, with a few-time FORS key at the bottom. The hash of the message picks the path, so the signer keeps no state, and the whole scheme rests on the hash function alone.',
    inputs: [
      { id: 'seed', kind: 'text', label: 'Key seed', def: 'meridian', check: (v) => (!v || v.length > 30 ? 'Key seed: 1 to 30 characters' : null) },
      { id: 'msg', kind: 'text', label: 'Message', def: 'firmware 4.2 for the pump controller', check: (v) => (!v || v.length > 50 ? 'Message: 1 to 50 characters' : null) },
    ],
    presets: [
      { label: 'Firmware', values: { msg: 'firmware 4.2 for the pump controller' } },
      { label: 'Another message', values: { msg: 'firmware 4.3 for the pump controller' } },
      { label: 'Another key', values: { seed: 'zenith', msg: 'firmware 4.2 for the pump controller' } },
    ],
    run: slh,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'keys', pick: 'option', options: ['the signer\'s counter', 'the hash of the message', 'the time of day'], ask: 'What chooses which FORS key signs this message?', answer: 'the hash of the message', explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'Why does SLH-DSA need no state, unlike a Merkle tree scheme?', options: ['It uses no one-time keys', 'The message hash picks a leaf among so many that collisions are rare, and FORS survives a few reuses', 'It stores state in the signature', 'It does need state'], answer: 1, why: 'A huge hypertree plus a few-time scheme at the bottom.' },
      { q: 'What does each layer of the hypertree sign?', options: ['The message', 'The root of the tree below it, with WOTS', 'The public key', 'Nothing'], answer: 1, why: 'Certificates all the way up to the public root.' },
      { q: 'FORS is…', options: ['a one-time signature', 'a few-time signature: k trees, one secret leaf revealed in each', 'a hash function', 'a lattice scheme'], answer: 1, why: 'Its security degrades slowly with reuse.' },
      { q: 'The main cost of SLH-DSA is…', options: ['large keys', 'large signatures and slow signing', 'weak security', 'needing a quantum computer'], answer: 1, why: 'Keys are tiny; signatures run to kilobytes.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
