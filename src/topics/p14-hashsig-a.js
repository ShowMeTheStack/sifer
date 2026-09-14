// Part 14, hash-based signatures, first half: a Lamport one-time signature with its key drawn whole, and the
// forgery that a second signature with the same key makes possible; and Winternitz chains, where a signature is a
// point part-way up each chain and the checksum stops anyone walking a chain on.
(function (S) {
  'use strict';
  const U = S.P14, P = () => S.PQ;
  const hx = (b, n) => P().hex(b).slice(0, n || 4);

  // ---------------------------------------------------------------------------------------------------------------
  // Lamport
  // ---------------------------------------------------------------------------------------------------------------
  function lamport(inp) {
    const n = +inp.n, bits = 8 * n, Lm = P().Lamport, kg = Lm.keyGen(inp.seed, { n });
    const m1 = inp.m1, m2 = inp.m2, d1 = Lm.digestBits(n, m1), d2 = Lm.digestBits(n, m2);
    const s1 = Lm.sign(kg.sk, m1), v1 = Lm.verify(kg.pk, m1, s1.sig);
    // the columns: a digest bit, the two secrets, the two public hashes
    const cw = Math.min(50, 860 / bits - 4), x0 = 56, X = (i) => U.r2(x0 + i * (cw + 4));
    const grid = (o) => {
      const items = [];
      items.push(U.t('lm:lb', x0 - 10, 106, 'bit', 'strong', 'end', 14), U.t('lm:l0', x0 - 10, 170, 'sk₀', 'key', 'end', 14), U.t('lm:l1', x0 - 10, 210, 'sk₁', 'key', 'end', 14), U.t('lm:p0', x0 - 10, 290, 'pk₀', 'act', 'end', 14), U.t('lm:p1', x0 - 10, 330, 'pk₁', 'act', 'end', 14));
      items.push(U.t('lm:sk', x0, 140, 'secret key: two random strings per digest bit', 'tick', 'start', 13), U.t('lm:pk', x0, 260, 'public key: the hash of each', 'tick', 'start', 13));
      for (let i = 0; i < bits; i++) {
        const bit = o.digest ? o.digest[i] : null;
        if (bit !== null) items.push({ key: 'lm:b' + i, kind: 'cell', x: X(i), y: 84, w: cw, h: 30, rx: 3, text: String(bit), size: 15, cls: 'hex ' + (o.diff && o.diff[i] ? 'hot' : '') });
        for (const b of [0, 1]) {
          const rev = o.revealed && o.revealed.has(i + ':' + b), need = o.need && o.need[i] === b;
          items.push({ key: 'lm:s' + b + '_' + i, kind: 'cell', x: X(i), y: 150 + 40 * b, w: cw, h: 32, rx: 3, text: hx(kg.sk.sk[i][b], cw > 44 ? 4 : 2), size: 13, cls: 'hex ' + (need ? (rev ? 'good' : 'bad') : rev ? 'keyhot' : 'soft') });
          items.push({ key: 'lm:p' + b + '_' + i, kind: 'cell', x: X(i), y: 270 + 40 * b, w: cw, h: 32, rx: 3, text: hx(kg.pk.pk[i][b], cw > 44 ? 4 : 2), size: 13, cls: 'hex ' + (o.check && o.digest && o.digest[i] === b ? 'act' : '') });
        }
      }
      return items;
    };
    const msgs = (rows) => rows.map(([t, c], k) => U.t('lm:m' + k, x0, 400 + 30 * k, t, c || 'strong', 'start', 15)).concat(U.legend('lm:k', x0, 540, [['surface', 'still secret'], ['key', 'revealed by a signature'], ['good', 'needed and public'], ['bad', 'needed but secret']]));
    const F = new S.Frames(['signatures', 'revealed']);
    const head = U.t('lm:h', 20, 30, `Lamport with a ${bits}-bit digest (the real thing uses 256)`, 'strong', 'start', 16);
    const facts0 = { bits, n, pairs: bits, real: 256, m1, m2 };
    F.add({ items: [head, ...grid({})], hl: { d: [0] }, say: `The private key: ${bits} pairs of random ${n}-byte strings, one pair per bit of the message digest. The public key is the hash of each of the ${2 * bits} strings. Hashes cannot be undone, so the public key reveals nothing.`, facts: Object.assign({ two: 2 * bits }, facts0), meta: { stage: 'keys' } });
    const rev = new Set();
    d1.forEach((b, i) => rev.add(i + ':' + b));
    F.count('signatures'); F.count('revealed', bits);
    F.add({ items: [head, ...grid({ digest: d1, revealed: rev }), ...msgs([[`signed: “${m1}”`], [`digest bits ${d1.join('')}`, 'mono']])], hl: { d: [1] }, say: `To sign “${m1}”, hash it: its digest bits are ${d1.join('')}. For each bit reveal one secret of the pair, sk₀ for a 0 and sk₁ for a 1. The signature is those ${bits} strings; the other ${bits} stay hidden.`, facts: Object.assign({ d: d1.join('') }, facts0), meta: { stage: 'sign1' } });
    F.add({ items: [head, ...grid({ digest: d1, revealed: rev, check: true }), ...msgs([[`signed: “${m1}”`], [v1.ok ? 'verified: every revealed string hashes to the chosen public value' : 'rejected', v1.ok ? 'good' : 'bad']])], hl: { d: [2] }, say: v1.trace[0].say + ' Anyone can check; only the key holder could have known the strings.', facts: Object.assign({ d: d1.join('') }, facts0), meta: { stage: 'verify' } });
    const s2 = Lm.sign(kg.sk, m2);
    d2.forEach((b, i) => rev.add(i + ':' + b));
    const diff = d1.map((b, i) => (b !== d2[i] ? 1 : 0)), both = diff.reduce((a, b) => a + b, 0);
    F.count('signatures'); F.count('revealed', both);
    F.add({ items: [head, ...grid({ digest: d2, revealed: rev, diff }), ...msgs([[`signed: “${m1}”`], [`signed with the same key: “${m2}”`, 'hot'], [`digest bits ${d2.join('')}; ${both} differ from the first`, 'mono']])], hl: { d: [3] }, say: `Now the same key signs a second message, “${m2}”, with digest ${d2.join('')}. Where its bits differ from the first (${both} places), the other secret of the pair is revealed too: both halves of ${both} pairs are now public.`, facts: Object.assign({ d: d2.join(''), both }, facts0), meta: { stage: 'sign2', both } });
    // a forgery: some message whose every digest bit is covered by what has been revealed
    const known = [{ msg: m1, sig: s1.sig }, { msg: m2, sig: s2.sig }];
    let forged = null, tries = 0;
    for (let k = 1; k <= 200000 && !forged; k++) { tries = k; const cand = inp.forge.replace('#', String(k)); const f = Lm.forge(known, cand, n); if (f.sig) forged = { msg: cand, sig: f.sig, d: Lm.digestBits(n, cand) }; }
    if (forged) {
      const vf = Lm.verify(kg.pk, forged.msg, forged.sig);
      F.add({ items: [head, ...grid({ digest: forged.d, revealed: rev, need: forged.d }), ...msgs([[`forged: “${forged.msg}”`, 'bad'], [`digest bits ${forged.d.join('')}: every needed secret is already public`, 'mono'], [vf.ok ? 'it verifies under the public key' : 'it does not verify', vf.ok ? 'bad' : 'good']])], hl: { d: [3] }, say: `The forger tries messages of the form “${inp.forge}” until one has a digest needing only revealed secrets: the same bit as both signatures wherever they agreed. Try ${tries}, “${forged.msg}”, works: its signature is assembled from the two public signatures, and it ${vf.ok ? 'verifies' : 'fails'}. A Lamport key must sign once only.`, facts: Object.assign({ tries, d: forged.d.join(''), agree: bits - both }, facts0), meta: { stage: 'forge', ok: vf.ok } });
    } else F.add({ items: [head, ...grid({ digest: d2, revealed: rev })], say: 'No forgery found among the tries.', facts: facts0, meta: { stage: 'forge', ok: false } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Lamport one-time signature', ['sk: pairs (x_{i,0}, x_{i,1}) of random strings', 'pk: (H(x_{i,0}), H(x_{i,1}))', 'sign m: reveal x_{i, dᵢ} for each digest bit dᵢ', 'verify: H(revealed) = pk_{i, dᵢ} for every i', 'one key, one signature: a second one leaks the other halves']) };
  }
  S.topic({
    id: 'pq-lamport', family: 'p14-hashsig', order: 10, title: 'Lamport signatures, and the forgery after reuse',
    blurb: 'A signature made of nothing but a hash function: reveal one of two secrets for each digest bit. Safe once; sign twice with the same key and the forger has enough secrets to sign something else.',
    inputs: [
      { id: 'n', kind: 'choice', label: 'Digest', def: '2', options: [{ value: '2', label: '16 bits' }, { value: '3', label: '24 bits' }] },
      { id: 'seed', kind: 'text', label: 'Key seed', def: 'saltmarsh', check: (v) => (!v || v.length > 30 ? 'Key seed: 1 to 30 characters' : null) },
      { id: 'm1', kind: 'text', label: 'First message', def: 'ship the tea on Tuesday', check: (v) => (!v || v.length > 50 ? 'First message: 1 to 50 characters' : null) },
      { id: 'm2', kind: 'text', label: 'Second message, same key', def: 'hold the tea until Friday', check: (v) => (!v || v.length > 50 ? 'Second message: 1 to 50 characters' : null) },
      { id: 'forge', kind: 'text', label: 'Forgery pattern (# is a number)', def: 'pay the bearer # crowns', check: (v) => (!v.includes('#') || v.length > 50 ? 'Forgery pattern: up to 50 characters with a # in it' : null) },
    ],
    presets: [
      { label: '16-bit digest', values: { n: '2', seed: 'saltmarsh' } },
      { label: '24-bit digest', values: { n: '3', seed: 'saltmarsh' } },
      { label: 'Other messages', values: { n: '2', seed: 'quarry', m1: 'the gate code is 4471', m2: 'the gate code is 9022', forge: 'open the gate for visitor #' } },
    ],
    counters: [{ id: 'signatures', label: 'signatures with this key' }, { id: 'revealed', label: 'secrets revealed' }],
    run: lamport,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'verify', pick: 'option', options: ['none', 'some', 'all'], ask: 'The same key will now sign a second message. How many pairs will have both secrets revealed?', answer: (fr, i) => { const b = fr[i + 1].meta.both; return b === 0 ? 'none' : b === fr[i].facts.bits ? 'all' : 'some'; }, explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'A Lamport signature on a 256-bit digest consists of…', options: ['one hash', '256 secret strings, one from each pair', '512 public hashes', 'a number mod p'], answer: 1, why: 'One revealed secret per digest bit.' },
      { q: 'Why must a Lamport key sign only once?', options: ['It wears out', 'A second signature reveals the other secret wherever the digests differ, enough to forge', 'The hash changes', 'It does not matter'], answer: 1, why: 'With both halves of many pairs public, many digests can be signed.' },
      { q: 'What does the security of Lamport signatures rest on?', options: ['Factoring', 'Discrete logarithms', 'Only the one-wayness of the hash function', 'Lattices'], answer: 2, why: 'That is why hash-based signatures are the most conservative post-quantum choice.' },
      { q: 'With 16-bit digests, after two signatures whose digests agree in 8 places, a random message can be forged with chance about…', options: ['1/2', '1/256', '1/65536', '0'], answer: 1, why: 'Its digest must match in the 8 places where only one secret is known.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Winternitz
  // ---------------------------------------------------------------------------------------------------------------
  function wots(inp) {
    const Wo = P().WOTS, w = +inp.w, n = 2, withChecksum = inp.cs === 'yes';
    const kg = Wo.keyGen(inp.seed, { n, w, checksum: withChecksum }), L = Wo.lens(n, w);
    const sg = Wo.sign(kg.sk, inp.m1), vr = Wo.verify(kg.pk, inp.m1, sg.sig);
    const dg = sg.digits, chains = dg.length, lenMsg = L.len1;
    const step = Math.min(52, 680 / (w - 1)), x0 = 150, rowH = Math.min(60, 420 / chains), top = 90;
    const NX = (j) => U.r2(x0 + j * step), NY = (i) => U.r2(top + i * rowH);
    const chainItems = (o) => {
      const items = [];
      for (let i = 0; i < chains; i++) {
        const y = NY(i), isCs = i >= lenMsg;
        items.push(U.t('wo:n' + i, x0 - 26, y + 5, (isCs ? 'checksum ' : 'chain ') + i, isCs ? 'hot' : 'strong', 'end', 14));
        items.push({ key: 'wo:w' + i, kind: 'wire', pts: [[NX(0) + 7, y], [NX(w - 1) - 7, y]], cls: 'faint' });
        for (let j = 0; j < w; j++) {
          const at = o.pos && o.pos[i] === j, walked = o.walk && j > o.pos[i] && j <= o.walk, blocked = o.blocked && o.blocked.includes(i) && j === o.to[i];
          const cls = blocked ? 'bad' : at ? 'hot' : j === 0 ? 'key' : j === w - 1 ? 'act' : walked ? 'act' : '';
          items.push({ key: 'wo:d' + i + '_' + j, kind: 'dot', x: NX(j), y, r: at || blocked ? 7 : j === 0 || j === w - 1 ? 6 : 3.5, cls, point: true });
        }
        if (o.pos && o.pos[i] !== undefined) items.push(U.t('wo:v' + i, NX(w - 1) + 18, y + 5, (isCs ? 'c' : 'd') + ' = ' + o.pos[i], isCs ? 'hot' : 'mono', 'start', 14));
      }
      items.push(U.t('wo:sk', NX(0), top - 26, 'secret start', 'key', 'middle', 13), U.t('wo:pk', w > 4 ? NX(w - 1) + 8 : NX(w - 1) - 8, top - 26, `end: public (${w - 1} hashes up)`, 'act', w > 4 ? 'end' : 'start', 13));
      return items;
    };
    const F = new S.Frames(['hashes']);
    const head = U.t('wo:h', 20, 30, `Winternitz with w = ${w}: ${lenMsg} message chains${withChecksum ? ` and ${L.len2} checksum chains` : ', no checksum'}`, 'strong', 'start', 16);
    const note = (rows) => rows.map(([t, c], k) => U.t('wo:x' + k, 20, 540 + 28 * k, t, c || 'strong', 'start', 15)).concat(U.legend('wo:k', 20, 630, [['key', 'secret start'], ['hot', 'signature value'], ['act', 'public end, or walked'], ['bad', 'below the signature: out of reach']]));
    const facts0 = { m1: inp.m1, w, w1: w - 1, len1: lenMsg, len2: withChecksum ? L.len2 : 0, chains };
    F.add({ items: [head, ...chainItems({})], hl: { d: [0] }, say: kg.trace[0].say + ` Each chain starts at a secret value and hashes it ${w - 1} times; only the ends are published.`, facts: facts0, meta: { stage: 'keys' } });
    const msgD = dg.slice(0, lenMsg), csum = dg.slice(lenMsg);
    F.add({ items: [head, ...chainItems({ pos: dg.slice(0, lenMsg).concat(csum.map(() => 0)).map((v, i) => (i < lenMsg ? v : undefined)) }), ...note([[`“${inp.m1}”: digest digits in base ${w}: ${msgD.join(' ')}`, 'mono']])], hl: { d: [1] }, say: sg.trace[0].say.replace('…', '') + `. Each digit says how far up its chain the signature will be: the digest of “${inp.m1}” gives ${msgD.join(', ')}.`, facts: Object.assign({ digits: msgD }, facts0), meta: { stage: 'digits' } });
    if (withChecksum) {
      const sum = sg.trace[1].csum;
      F.add({ items: [head, ...chainItems({ pos: dg }), ...note([[`checksum Σ(${w - 1} − dᵢ) = ${sum} = ${csum.join(' ')} in base ${w}`, 'hot']])], hl: { d: [2] }, say: sg.trace[1].say, facts: Object.assign({ sum, check: csum }, facts0), meta: { stage: 'checksum' } });
    }
    F.count('hashes', dg.reduce((a, b) => a + b, 0));
    F.add({ items: [head, ...chainItems({ pos: dg }), ...note([[`signature: the value at each orange point, ${chains} values of ${n} bytes`]])], hl: { d: [3] }, say: sg.trace[sg.trace.length - 1].say + ` That took ${dg.reduce((a, b) => a + b, 0)} hashes.`, facts: Object.assign({ n, total: dg.reduce((a, b) => a + b, 0) }, facts0), meta: { stage: 'sign' } });
    F.count('hashes', dg.reduce((a, b) => a + (w - 1 - b), 0));
    F.add({ items: [head, ...chainItems({ pos: dg, walk: w - 1 }), ...note([[vr.ok ? 'verified: every chain ends at its public value' : 'rejected', vr.ok ? 'good' : 'bad']])], hl: { d: [4] }, say: vr.trace[0].say + ` The verifier did the remaining ${dg.reduce((a, b) => a + (w - 1 - b), 0)} hashes.`, facts: Object.assign({ rest: dg.reduce((a, b) => a + (w - 1 - b), 0) }, facts0), meta: { stage: 'verify' } });
    // a forgery: anyone can walk a chain further up, never down
    let forged = null, tries = 0, last = null;
    for (let k = 1; k <= 20000 && !forged; k++) {
      tries = k; const cand = inp.m2.replace('#', String(k)), f = Wo.forge(kg.pk, inp.m1, sg.sig, cand);
      last = { cand, f };
      if (f.sig) forged = { cand, f };
      if (withChecksum && k >= 300) break;
    }
    const tgt = (msg) => Wo.digits(n, w, P().shake256(new TextEncoder().encode(msg), n), withChecksum).all;
    if (forged) {
      const vf = Wo.verify(kg.pk, forged.cand, forged.f.sig), d2 = tgt(forged.cand);
      F.add({ items: [head, ...chainItems({ pos: d2, walk: w - 1 }), ...note([[`forged: “${forged.cand}”, digits ${d2.join(' ')}`, 'bad'], [vf.ok ? 'it verifies: the forger only walked chains forward' : 'rejected', vf.ok ? 'bad' : 'good']])], hl: { d: [5] }, say: `With no checksum the forger looks for a message whose every digit is at least the signed one's. Try ${tries}, “${forged.cand}”, has digits ${d2.join(', ')}: walking each chain further up from the signature gives a valid signature on it, which ${vf.ok ? 'verifies' : 'fails'}. That is what the checksum is for.`, facts: Object.assign({ tries, d2 }, facts0), meta: { stage: 'forge', ok: vf.ok } });
    } else {
      const d2 = tgt(last.cand), bl = last.f.blocked;
      F.add({ items: [head, ...chainItems({ pos: dg, blocked: bl, to: d2 }), ...note([[`“${last.cand}” would need chains ${bl.join(', ')} to go down`, 'good'], [`no forgery in ${tries} tries`, 'good']])], hl: { d: [5] }, say: `The forger needs a message whose digits are all at least the signed ones, checksum digits included. But raising a message digit lowers the checksum, so some chain must always go backwards. For “${last.cand}”: ${last.f.trace[0].say} None of ${tries} tries works.`, facts: Object.assign({ tries, d2, blocked: bl, first: bl[0], a: dg[bl[0]], b: d2[bl[0]] }, facts0), meta: { stage: 'forge', ok: false } });
    }
    U.fix(F.list);
    return { frames: F.list, def: U.def('Winternitz (WOTS)', ['digits dᵢ of the digest in base w', 'checksum C = Σ (w − 1 − dᵢ), also in base w', 'pk: each chain hashed w − 1 times from its secret start', 'sign: chain i hashed dᵢ times', 'verify: hash each value w − 1 − dᵢ more times; compare']) };
  }
  S.topic({
    id: 'pq-winternitz', family: 'p14-hashsig', order: 20, title: 'Winternitz chains and the checksum',
    blurb: 'Instead of a pair of secrets per bit, one chain of hashes per digit: the signature is the point part-way up each chain. Anyone can walk a chain further up, so a checksum makes sure some chain would have to come down.',
    inputs: [
      { id: 'w', kind: 'choice', label: 'w', def: '16', options: [{ value: '4', label: '4' }, { value: '16', label: '16' }] },
      { id: 'cs', kind: 'choice', label: 'Checksum', def: 'yes', options: [{ value: 'yes', label: 'with the checksum' }, { value: 'no', label: 'without it' }] },
      { id: 'seed', kind: 'text', label: 'Key seed', def: 'winterbourne', check: (v) => (!v || v.length > 30 ? 'Key seed: 1 to 30 characters' : null) },
      { id: 'm1', kind: 'text', label: 'Message', def: 'release the second shipment', check: (v) => (!v || v.length > 50 ? 'Message: 1 to 50 characters' : null) },
      { id: 'm2', kind: 'text', label: 'Forgery pattern (# is a number)', def: 'release shipment number #', check: (v) => (!v.includes('#') || v.length > 50 ? 'Forgery pattern: up to 50 characters with a # in it' : null) },
    ],
    presets: [
      { label: 'w = 16, with checksum', values: { w: '16', cs: 'yes' } },
      { label: 'w = 16, no checksum: forged', values: { w: '16', cs: 'no' } },
      { label: 'w = 4, with checksum', values: { w: '4', cs: 'yes' } },
      { label: 'w = 4, no checksum', values: { w: '4', cs: 'no' } },
    ],
    counters: [{ id: 'hashes', label: 'hashes' }],
    run: wots,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'verify', pick: 'option', options: ['yes', 'no'], ask: 'Can a forger use this signature to sign another message?', answer: (fr, i) => (fr[i + 1].meta.ok ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'In WOTS, the signature value for a digit d is…', options: ['the secret start', 'the chain value after d hashes', 'the public end', 'd itself'], answer: 1, why: 'The verifier hashes it w − 1 − d more times to reach the public end.' },
      { q: 'Why is a checksum needed?', options: ['For speed', 'Without it, anyone can walk chains further up and sign digests with larger digits', 'To compress', 'It is not'], answer: 1, why: 'Raising a digit lowers the checksum, so some chain would have to go down, which needs inverting the hash.' },
      { q: 'A larger w gives…', options: ['longer signatures', 'shorter signatures but more hashing', 'no change', 'weaker security'], answer: 1, why: 'Fewer chains (each digit carries more bits), each longer.' },
      { q: 'Is WOTS a one-time signature?', options: ['No, it can sign many times', 'Yes: two signatures together reveal points lower on chains', 'Only with w = 2', 'Only without a checksum'], answer: 1, why: 'Like Lamport, its key must sign only once.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
