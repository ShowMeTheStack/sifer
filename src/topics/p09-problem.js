// Part 9, the problem: the powers of a generator of Z_p* hop around the ring of residues in an order that looks random,
// so the only obvious way back from h to x is to walk the hops one by one. The same ring under addition steps evenly
// and gives its logarithm away by one division. At real size the walk is never drawn: one modular power forwards
// costs a few thousand multiplications, and the best way back costs more than any computer can do.
(function (S) {
  'use strict';
  const P = S.PK, NT = () => S.NT, KN = () => S.Kit.nt;
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const isP = (v) => NT().isProbablePrime(B(v));
  /** run fn with the random source seeded */
  const seeded = (seed, fn) => { const old = NT().setRandom(NT().seededRandom(seed)); try { return fn(); } finally { NT().setRandom(old); } };
  S.P09 = S.P09 || {};
  S.P09.seeded = seeded;

  S.topic({
    id: 'p09-dlp', family: 'p09-problem', order: 10, title: 'The discrete logarithm in Z_p*',
    blurb: 'Raise a generator g to the powers 1, 2, 3, … modulo a prime p and the results hop around every residue in a scrambled order. Going forwards is a few multiplications; going back from h = g^x to x has no shortcut on the ring: you walk the hops until you land on h.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Size', def: 'toy', options: [{ value: 'toy', label: 'toy: a ring you can see' }, { value: 'real', label: 'real: the 2048-bit MODP group' }] },
      { id: 'p', kind: 'number', label: 'Prime p', def: 29, min: 5, max: 43, check: (v) => (isP(v) ? null : 'p: a prime') },
      { id: 'g', kind: 'number', label: 'Base g (0: the smallest generator)', def: 0, min: 0, max: 42, check: (v, inp) => (v !== 0 && (v < 2 || v >= inp.p) ? 'g: 0, or from 2 to p − 1' : null) },
      { id: 'x', kind: 'number', label: 'Secret x', def: 17, min: 1, max: 41, check: (v, inp) => (v > inp.p - 2 ? 'x: from 1 to p − 2' : null) },
      { id: 'seed', kind: 'number', label: 'Seed (real size)', def: 9, min: 1, max: 99999 },
    ],
    presets: [
      { label: 'p = 29, x = 17', values: { size: 'toy', p: 29, g: 0, x: 17 } },
      { label: 'A small ring: p = 11', values: { size: 'toy', p: 11, g: 0, x: 7 } },
      { label: 'p = 43 with g = 3', values: { size: 'toy', p: 43, g: 3, x: 29 } },
      { label: 'Not a generator: g = 4 mod 23', values: { size: 'toy', p: 23, g: 4, x: 6 } },
      { label: 'Real: the 2048-bit group', values: { size: 'real', seed: 9 } },
    ],
    counters: [{ id: 'tries', label: 'powers tried' }, { id: 'mults', label: 'multiplications' }],
    run(inp) { return inp.size === 'real' ? P.memo('p09-dlp', inp.seed, () => real(inp)) : toy(inp); },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'hop' && f.meta.k === 3 && fr[i + 1] && fr[i + 1].meta.phase === 'hop' && fr[i + 1].meta.k === 4, pick: 'item', ask: (fr, i) => `Where does g⁴ land? Click its residue on the ring.`, answer: (fr, i) => 'ck:' + (fr[i + 1].meta.v - 1), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => f.meta.phase === 'forward' && fr[i + 1] && fr[i + 1].meta.phase === 'costs', pick: 'option', ask: 'Which way back from h to x is the fastest known for this group?', options: ['trying every x', 'baby-step giant-step or rho', 'the number field sieve'], answer: 'the number field sieve', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'In Z_11* with g = 2, what is log_g(8)?', options: ['3', '4', '8', '6'], answer: 0, why: '2³ = 8, and 8 < 11, so no reduction is needed: x = 3.' },
      { q: 'Why is the discrete logarithm easy in Z_n under addition?', options: ['n is small', 'x·g ≡ h is solved by one division modulo n', 'addition has no inverse', 'it is not easy'], answer: 1, why: 'The "power" x·g is a multiple; dividing by g (multiplying by its inverse modulo n) gives x at once.' },
      { q: 'A generator g of Z_p* visits how many residues before returning to 1?', options: ['p', 'p − 1', '(p − 1)/2', 'it depends on x'], answer: 1, why: 'A generator has order p − 1: its powers run through every one of 1, …, p − 1.' },
      { q: 'If g has order d < p − 1, which h can be written as g^x?', options: ['every residue', 'only the d residues in the cycle of g', 'only even ones', 'none'], answer: 1, why: 'The powers of g form a subgroup of d elements; any h outside it has no logarithm to base g.' },
      { q: 'Computing g^x mod p for a 2048-bit p takes about…', options: ['x multiplications', 'a few thousand multiplications', '2^1024 multiplications', 'one multiplication'], answer: 1, why: 'Square-and-multiply needs one squaring per bit of x and a multiplication per 1 bit.' },
    ],
  });

  function toy(inp) {
    const p = inp.p, n = p - 1, pB = BigInt(p);
    const gen = S.DLP.groupZp(pB).generator;
    const g = inp.g ? BigInt(inp.g) : gen, ord = Number(NT().order(g, pB).order);
    const x = inp.x, h = NT().pow(g, x, pB), isGen = ord === n;
    const F = new S.Frames(['tries', 'mults']);
    const cx = 240, cy = 260, R = 215, view = { x: -20, y: -10, w: 880, h: 536 };
    const right = 520;
    const seq = [1n]; for (let k = 1; k <= Math.max(ord, x); k++) seq.push((seq[k - 1] * g) % pB);
    const pos = (v) => KN().at(n, Number(v) - 1, cx, cy, R);
    const ring = (lit, labels) => KN().clock({ prefix: 'ck', cx, cy, R, n, text: labels || ((k) => String(k + 1)), cls: (k) => lit(k + 1) }).items;
    const bowOf = (a, b) => { const d = Math.hypot(a.x - b.x, a.y - b.y); return d < R * 0.9 ? 0.6 : 0.18; };
    const hops = (upto, cur) => {
      const out = [];
      for (let k = 1; k <= upto; k++) out.push(...KN().hop({ key: 'hp' + k, from: pos(seq[k - 1]), to: pos(seq[k]), cx, cy, bow: bowOf(pos(seq[k - 1]), pos(seq[k])), gap: 15, cls: k === cur ? 'act' : 'faint', audit: k === cur ? 'edge-x' : 'ignore' }));
      return out;
    };
    const T = (k, x0, y0, t) => Object.assign(P.title(k, x0, y0, t), { size: 14 });
    const head = (t) => [T('h1', -4, 16, `Z_${p}*: the residues 1 to ${n}`), T('h2', right, 40, t)];
    const panel = (lines) => P.eqs('q', right, 84, lines, 17, 31);
    const recent = (k) => { const out = []; for (let j = Math.max(1, k - 5); j <= k; j++) out.push([`g${P.sup(j)} = ${seq[j - 1]}·${g} mod ${p} = ${seq[j]}`, j === k ? (seq[j] === h ? 'good' : 'act') : '']); return out; };
    const base = [[`g = ${g}${isGen ? ', a generator' : `, of order ${ord}`}`, 'strong'], [`find x with g^x = h = ${h}`, 'hot']];
    const lit = (upto) => (v) => { const B_ = BigInt(v); if (B_ === h && upto >= 0 && seq.slice(0, upto + 1).includes(h)) return 'good'; if (B_ === h) return 'hot'; if (seq.slice(1, upto + 1).includes(B_)) return 'act'; return ''; };
    F.add({ items: [...ring(lit(-1)), ...head('The problem'), ...panel(base)], say: `The ring holds the ${n} residues 1 to ${n} of Z_${p}*, in plain order. The base is g = ${g}${isGen ? ', a generator: its powers reach every residue' : `, whose powers return to 1 after only ${ord} steps`}. Someone publishes h = ${h}. Which power x of ${g} is it?`, facts: { p, n, g, h, ord }, meta: { phase: 'start' } });
    // the walk
    const ks = []; for (let k = 1; k <= x; k++) if (k <= 8 || k === x || (x - k) % Math.ceil((x - 8) / 4) === 0) ks.push(k);
    for (const k of ks) {
      F.set('tries', k).set('mults', k - 1);
      const hit = seq[k] === h, skipped = ks.indexOf(k) > 0 && k - ks[ks.indexOf(k) - 1] > 1;
      F.add({ items: [...hops(k, k), ...ring(lit(k)), ...head('Walking the powers'), ...panel(base.concat(recent(k)))],
        say: (skipped ? `Skipping ahead, ` : '') + `g${P.sup(k)} = ${seq[k - 1]}·${g} mod ${p} = ${seq[k]}` + (hit ? `: that is h. So x = ${k}, found after trying ${P.plural(k, 'power')}.` : k === 1 ? `: start at g itself and multiply by g at every hop.` : `. ${skipped ? 'The hops jump about the ring with no pattern a walker could use.' : `Not h; the hop went from ${seq[k - 1]} to ${seq[k]}, ${Math.abs(Number(seq[k]) - Number(seq[k - 1]))} places away on the ring.`}`),
        facts: { k, prev: seq[k - 1], v: seq[k], g, p, dist: Math.abs(Number(seq[k]) - Number(seq[k - 1])) }, meta: { phase: 'hop', k, v: Number(seq[k]) } });
    }
    // the whole cycle
    F.set('tries', ord).set('mults', ord - 1);
    F.add({ items: [...hops(ord, -1), ...ring((v) => (BigInt(v) === h ? 'good' : seq.includes(BigInt(v)) ? 'act' : 'soft')), ...head('The whole cycle'), ...panel(base.concat([[`${ord} hops back to g${P.sup(ord)} = 1`, 'strong'], [isGen ? `every residue visited once` : `${n - ord} residues never reached`, isGen ? 'good' : 'bad']]))],
      say: isGen ? `All ${ord} powers of ${g}: every residue is visited exactly once before g${P.sup(ord)} = 1 closes the cycle, and the order of the visits looks random. That scrambled cycle is why going back from h to x is hard.` : `${g} has order ${ord}: its powers visit only ${ord} of the ${n} residues before g${P.sup(ord)} = 1. Any h off this cycle has no logarithm to base ${g}; a generator, of order ${n}, reaches them all.`,
      facts: { ord, n, g, missing: n - ord }, meta: { phase: 'cycle' } });
    // the additive contrast
    const step = NT().gcd(g, BigInt(n)) === 1n ? Number(g) % n : 1;
    const hAdd = (x * step) % n, addMax = Math.min(n, 9);
    const addPos = (k) => KN().at(n, k, cx, cy, R);
    const addHops = []; for (let k = 1; k <= addMax; k++) addHops.push(...KN().hop({ key: 'ad' + k, from: addPos(((k - 1) * step) % n), to: addPos((k * step) % n), cx, cy, bow: 0.18, gap: 15, cls: 'key', audit: 'edge-x' }));
    const inv = NT().inv(BigInt(step), BigInt(n));
    F.add({ items: [...addHops, ...KN().clock({ prefix: 'ck', cx, cy, R, n, text: (k) => String(k), cls: (k) => (k === hAdd ? 'good' : '') }).items, T('h1', -4, 16, `Z_${n} under addition: 0 to ${n - 1}`), T('h2', right, 40, 'The easy group'), ...panel([[`"g^x" here is x·${step} mod ${n}`, 'strong'], [`steps of ${step}: evenly spaced`, 'key'], [`h = ${hAdd}: x = ${hAdd}·${inv} mod ${n} = ${x}`, 'good']])],
      say: `For contrast, the ring Z_${n} under addition with g = ${step}: the "powers" are the multiples x·${step} mod ${n}, and they step evenly round the ring. Here h = ${hAdd} gives its logarithm away at once: x = ${hAdd}·${step}⁻¹ = ${hAdd}·${inv} mod ${n} = ${x}. A cyclic group is only as hard as the way its elements are written down.`,
      facts: { n, step, hAdd, inv, x }, meta: { phase: 'additive' } });
    for (const f of F.list) f.narrowView = { x: -10, y: 20, w: 500, h: 490 };
    return { frames: P.fix(F.list, view), def: P.def('The discrete logarithm', [`Z_p*: {1, …, p − 1} under multiplication mod p`, 'g generates it when its order is p − 1', 'log_g(h) = the x in 0 ≤ x < p − 1 with g^x ≡ h', 'forwards: square-and-multiply, about log₂ x steps', 'backwards: no known shortcut on a general group'], [{ id: 'g', kind: 'table', title: 'Powers of g', colHead: ['x', 'g^x mod p'], rows: seq.slice(1, Math.min(seq.length, 41)).map((v, k) => [String(k + 1), String(v)]) }]) };
  }

  function real(inp) {
    const G = P.modp14(), p = G.p, q = G.q, g = G.generator;
    const x = seeded(inp.seed, () => 2n + NT().randBelow(q - 2n));
    const pw = S.RSA.powLR(g, x, p), h = pw.value;
    const F = new S.Frames(['tries', 'mults']);
    const view = { x: 0, y: -10, w: 860, h: 530 };
    const V = (key, x0, y0, label, value, cls) => S.Kit.pk.value({ key, x: x0, y: y0, label, value, cls, anchor: 'start', max: 22 });
    const pBits = P.bits(p), qBits = P.bits(q), xBits = P.bits(x);
    const top = [P.title('h1', 20, 26, 'The 2048-bit MODP group'), V('vp', 20, 74, 'p (a safe prime)', p), V('vq', 20, 148, 'q = (p − 1)/2, the order of g', q), V('vg', 470, 74, 'generator g', g)];
    F.add({ items: top, say: `At real size the ring has ${P.n(p - 1n)} positions and is never drawn. The group is the ${pBits}-bit MODP group of RFC 3526: p = ${P.n(p)}, and g = ${g} generates the subgroup of prime order q = (p − 1)/2, a ${qBits}-bit number.`, facts: { p, g, q, pBits, qBits, pm1: p - 1n }, meta: { phase: 'group' } });
    F.set('mults', pw.squarings + pw.multiplications);
    const fwd = [...top, V('vx', 20, 236, 'secret x', x, 'key'), V('vh', 20, 310, 'h = g^x mod p', h, 'hot'), P.t('ops', 470, 236, `${pw.squarings} squarings`, 'strong', 'start', 16), P.t('ops2', 470, 262, `${pw.multiplications} multiplications`, 'strong', 'start', 16)];
    F.add({ items: fwd, say: `Forwards is quick: the secret x = ${P.n(x)}, ${P.an(xBits)}-bit number, gives h = g^x mod p = ${P.n(h)} in ${pw.squarings} squarings and ${pw.multiplications} multiplications. Click a number to read all of its digits.`, facts: { x, h, xBits, sq: pw.squarings, mul: pw.multiplications }, meta: { phase: 'forward' } });
    // the ways back, as log2 of the work
    const opsLog = Math.log2(pw.squarings + pw.multiplications), brute = qBits, rho = P.rhoBits(qBits), nfs = P.gnfsBits(pBits);
    const rows = [['forwards: g^x', opsLog, 'good'], ['try every x', brute, 'bad'], ['baby-step giant-step, rho', rho, 'hot'], ['number field sieve', nfs, 'act']];
    const x0 = 250, sc = 450 / 2048, y0 = 230, items = [P.title('h1', 20, 26, 'The work, as a power of 2 (bars to scale in the exponent)')];
    rows.forEach(([name, v, cls], i) => {
      const y = y0 + i * 76 - 150 + (i ? 30 : 0);
      items.push(P.t('rl' + i, x0 - 14, y + 20, name, 'strong', 'end', 15));
      items.push({ key: 'rb' + i, kind: 'cell', x: x0, y, w: Math.max(4, P.r2(v * sc)), h: 30, rx: 3, text: '', cls: 'pk-bar ' + cls });
      items.push(P.t('rv' + i, x0 + Math.max(4, v * sc) + 12, y + 21, '2^' + v.toFixed(i === 0 ? 1 : 0), 'mono', 'start', 16));
      if (i === 0) items.push(P.t('back', 20, y + 70, 'and back, from h to x:', 'strong', 'start', 15));
    });
    const century = Math.round(40 + Math.log2(100 * 365.25 * 86400));
    items.push(P.t('note', 20, 440, `A computer doing 2^40 steps a second for a century does about 2^${century}.`, 'muted', 'start', 15));
    F.add({ items, say: `Backwards is another matter. Trying every x takes up to 2^${brute} powers; baby-step giant-step or Pollard's rho about 2^${rho.toFixed(0)} steps, the square root of q; the number field sieve, which works in Z_p* itself, about 2^${nfs.toFixed(0)}. Against 2^${opsLog.toFixed(1)} multiplications forwards, the gap is the whole point.`, facts: { brute, rho, nfs, opsLog }, meta: { phase: 'costs' } });
    for (const f of F.list) f.narrowView = { x: 0, y: 0, w: 860, h: 440 };
    return { frames: P.fix(F.list, view), def: P.def('The discrete logarithm at real size', [`p: ${pBits} bits, q = (p − 1)/2: ${qBits} bits`, 'g^x: about 1.5·log₂ x multiplications', 'generic attacks: about √q steps', 'Z_p* also falls to the number field sieve,', 'which is why p must be so much longer than 2·128 bits']) };
  }
})(globalThis.Sifer = globalThis.Sifer || {});
