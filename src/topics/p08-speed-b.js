// Part 8, making RSA fast (2): Montgomery multiplication (reduction by a shift instead of a division), decryption by
// the Chinese remainder theorem with Garner's recombination and what it saves, and the cost of small public exponents.
(function (S) {
  'use strict';
  const P = S.PK, B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const NT = () => S.NT, A = () => S.P08A;
  const n$ = (v) => P.n(v);
  const bin = (v, w) => B(v).toString(2).padStart(w, '0');

  // ---------------------------------------------------------------------------------------------------------------
  // Montgomery multiplication
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p08-montmul', family: 'p08-speed', order: 30, title: 'Montgomery multiplication',
    blurb: 'Reducing modulo n needs a division, the slowest step of all. Montgomery works with R = 2^k instead: add the multiple m·n of n that clears the low k bits of the product, then shift right by k. Numbers are kept as a·R mod n, so the factor R⁻¹ the shift brings in cancels.',
    inputs: [
      { id: 'size', kind: 'choice', label: 'Size', def: 'toy', options: [{ value: 'toy', label: 'toy: choose n, a, b' }, { value: 'rsa1024', label: 'n of RSA-1024' }, { value: 'rsa2048', label: 'n of RSA-2048' }] },
      { id: 'n', kind: 'bigint', label: 'n (odd)', def: '97' },
      { id: 'a', kind: 'bigint', label: 'a', def: '45' },
      { id: 'b', kind: 'bigint', label: 'b', def: '76' },
    ],
    check: (inp) => {
      let n, a, b;
      try { [n, a, b] = [inp.n, inp.a, inp.b].map((v) => B(String(v).trim())); } catch (e) { return 'n, a and b: whole numbers'; }
      if (inp.size === 'toy') { if (n < 3n || !(n & 1n)) return 'n: an odd number, at least 3'; if (n > 4095n) return 'n: at most 4095 for the toy size, so every bit can be drawn'; }
      else n = P.rsaKey(inp.size).n;
      if (a < 0n || b < 0n || a >= n || b >= n) return 'a and b: from 0 to n − 1';
      return null;
    },
    presets: [
      { label: '45·76 mod 97', values: { size: 'toy', n: '97', a: '45', b: '76' } },
      { label: 'An extra subtraction: 400·900 mod 1001', values: { size: 'toy', n: '1001', a: '400', b: '900' } },
      { label: 'n = 4093, a 12-bit modulus', values: { size: 'toy', n: '4093', a: '4000', b: '3999' } },
      { label: 'RSA-1024 modulus', values: { size: 'rsa1024', a: '2026', b: '1999' } },
      { label: 'RSA-2048 modulus', values: { size: 'rsa2048', a: '31337', b: '27182' } },
    ],
    counters: [{ id: 'div', label: 'divisions by n' }, { id: 'shift', label: 'shifts' }],
    run(inp) {
      const toy = inp.size === 'toy', n = toy ? B(inp.n) : P.rsaKey(inp.size).n, a = B(inp.a), b = B(inp.b);
      const M = S.RSA.montgomery(n), k = Number(M.k), R = M.R, mask = R - 1n, np = M.nprime;
      const aM = M.to(a), bM = M.to(b), t = aM * bM, m = ((t & mask) * np) & mask, mn = m * n, s = t + mn, u0 = s >> M.k;
      const res = M.mul(aM, bM), u = res.value, extra = res.extra, back = M.from(u), direct = (a * b) % n;
      const F = new S.Frames(['div', 'shift']);
      const W = toy ? 2 * k + 1 : 24, cw = toy ? Math.min(18, Math.floor(400 / W)) : 16, XR = 860, x0 = XR - W * cw;
      const view = { x: -10, y: -20, w: 880, h: 560 }, Y = (i) => 20 + i * 44;
      const rowsDef = [['n', n], ['R = 2^' + k, R], ["n' = −n⁻¹ mod R", np], ['ā = a·R mod n', aM], ['b̄ = b·R mod n', bM], ['t = ā·b̄', t], ["m = (t mod R)·n' mod R", m], ['m·n', mn], ['t + m·n', s], ['u = (t + m·n) / R', u0], [extra ? 'u − n' : 'result', u]];
      const bitRows = { 5: t, 7: mn, 8: s };
      const draw = (upto, lit, more) => {
        const items = [];
        rowsDef.slice(0, upto + 1).forEach(([l, v], i) => items.push(...A().row('v' + i, -10, Y(i), l, v, i === lit ? 'act' : i === 10 && upto === 10 ? 'good' : '', { lw: 180, w: 230, max: 16 })));
        for (const [i, v] of Object.entries(bitRows)) {
          if (+i > upto) continue;
          const str = bin(v & ((1n << BigInt(W)) - 1n), W);
          for (let j = 0; j < W; j++) {
            const pos = W - 1 - j, low = pos < k;
            items.push({ key: 'b' + i + ':' + j, kind: 'cell', x: x0 + j * cw, y: Y(+i) + 3, w: cw - 1, h: 28, rx: 2, text: str[j], size: 13, cls: 'bit hex ' + (str[j] === '1' ? 'one ' : '') + (+i === 8 && low ? 'good' : +i === 5 && low && lit === 6 ? 'act' : '') });
          }
        }
        if (toy && upto >= 9) { const str = bin(u0, W - k); for (let j = 0; j < W - k; j++) items.push({ key: 'b9:' + j, kind: 'cell', x: x0 + j * cw, y: Y(9) + 3, w: cw - 1, h: 28, rx: 2, text: str[j], size: 13, cls: 'bit hex ' + (str[j] === '1' ? 'one' : '') }); }
        if (upto >= 8) {
          const lowW = toy ? k : W;
          items.push({ key: 'brk', kind: 'bracket', x1: XR - lowW * cw, x2: XR - 1, y: Y(8) + 34, side: 'below', text: toy ? `low k = ${k} bits: all 0` : `lowest ${W} of k = ${k} bits: all 0`, cls: 'good' });
        }
        if (upto < 5) items.push(P.t('hint', x0, Y(5) + 22, toy ? 'the bits of t, m·n and t + m·n appear here' : `the lowest ${W} bits of t, m·n and t + m·n appear here`, 'muted', 'start', 14));
        return items.concat(more || []);
      };
      const add = (upto, lit, say, facts, phase) => F.add({ items: draw(upto, lit), say, facts, meta: { phase } });
      add(2, 2, `n = ${n$(n)} has k = ${k} bits, so take R = 2^${k} = ${n$(R)}, a power of two just above n. n is odd, so it has an inverse modulo R; precompute n' = −n⁻¹ mod R = ${n$(np)}. This is done once per modulus.`, { n, k, R, np }, 'setup');
      add(4, 4, `Work with Montgomery forms ā = a·R mod n = ${n$(aM)} and b̄ = b·R mod n = ${n$(bM)} (for a = ${n$(a)} and b = ${n$(b)}). Converting costs one ordinary reduction each, but a whole exponentiation then stays in this form.`, { aM, bM, a, b }, 'to');
      add(5, 5, `Multiply: t = ā·b̄ = ${n$(t)}, up to ${2 * k} bits. Reducing t modulo n would need a long division; Montgomery avoids it.`, { t, k2: 2 * k }, 't');
      add(6, 6, `Look only at the low k bits of t: m = (t mod R)·n' mod R = ${n$(m)}. Both steps are just multiplications and masks, since R is a power of two.`, { m }, 'm');
      add(8, 8, `Add m·n = ${n$(mn)}: since m·n ≡ −t (mod R), t + m·n = ${n$(s)} ends in ${k} zero bits. Adding a multiple of n changes nothing modulo n.`, { mn, s, k }, 'sum');
      F.set('shift', 1);
      add(9, 9, `So divide by R exactly, by shifting right ${k} bits: u = ${n$(u0)}. Then u ≡ t·R⁻¹ ≡ a·b·R (mod n): the Montgomery form of the product, and u < 2n.`, { u0, k }, 'shift');
      add(10, 10, extra ? `u = ${n$(u0)} is not below n, so one subtraction: u − n = ${n$(u)}. This conditional extra subtraction is the step a timing attack listens for.` : `u = ${n$(u0)} is already below n, so no extra subtraction is needed: the result is ${n$(u)}.`, { u0, u, extra: extra ? 1 : 0 }, 'extra');
      const okBack = back === direct;
      F.add({ items: draw(10, 10, [P.t('chk', x0, Y(10) + 22, `back: u·R⁻¹ mod n = ${S.Kit.pk.fmt(back, { max: 14 }).text}`, okBack ? 'good' : 'bad', 'start', 15)]), say: `Leaving Montgomery form (one more Montgomery multiplication, by 1) gives ${n$(back)}, the same as a·b mod n = ${n$(direct)} computed directly. In all no division by n was needed${extra ? ', only one subtraction' : ''}.`, facts: { back, direct }, meta: { phase: 'back', ok: okBack } });
      for (const f of F.list) f.narrowView = { x: -10, y: -20, w: 430, h: 520 };
      return { frames: P.fix(F.list, view), def: P.def('Montgomery multiplication', ['R = 2^k > n, gcd(R, n) = 1,  n\' = −n⁻¹ mod R', 'MonMul(ā, b̄): t = ā·b̄', '  m = (t mod R)·n\' mod R', '  u = (t + m·n) / R    (exact: a shift)', '  if u ≥ n: u = u − n', 'result ≡ ā·b̄·R⁻¹ (mod n)', 'ā = a·R mod n keeps products in the same form']) };
    },
    predict: [
      { at: (f) => f.meta.phase === 'm', pick: 'option', ask: 'What will the low k bits of t + m·n be?', options: ['all 0', 'all 1', 'the same as t', 'random'], answer: 'all 0', explain: (fr, i) => fr[i + 1].say },
      { at: (f) => f.meta.phase === 'shift', pick: 'option', ask: 'Is u at least n, so that one more subtraction is needed?', options: ['yes', 'no'], answer: (fr, i) => (fr[i + 1].facts.extra ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why choose R as a power of two?', options: ['So that n divides R', 'So that reducing modulo R and dividing by R are a mask and a shift', 'So that R is prime', 'It makes n smaller'], answer: 1, why: 'Computers reduce and divide by powers of two for free.' },
      { q: 'Why must n be odd?', options: ['So that R and n are coprime and n⁻¹ mod R exists', 'So that the shift is exact', 'So that the result is odd', 'It need not be'], answer: 0, why: 'n\' = −n⁻¹ mod R needs gcd(n, 2^k) = 1.' },
      { q: 'What does one Montgomery multiplication of ā and b̄ return?', options: ['a·b mod n', 'ā·b̄·R⁻¹ mod n, the Montgomery form of a·b', 'ā·b̄·R mod n', 'a·b·R²'], answer: 1, why: '(a·R)(b·R)·R⁻¹ = a·b·R: still in Montgomery form.' },
      { q: 'Which step can leak through timing?', options: ['The multiplication t = ā·b̄', 'The mask t mod R', 'The final conditional subtraction', 'Choosing R'], answer: 2, why: 'It runs only for some inputs; constant-time code always subtracts and then selects.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Decryption by the CRT, with Garner
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p08-crt', family: 'p08-speed', order: 40, title: 'Decryption with the CRT and Garner',
    blurb: 'Whoever holds p and q can decrypt modulo each prime separately, with exponents dp and dq half as long, on numbers half as long, then glue the two halves with Garner\'s formula. About four times less work than c^d mod n.',
    inputs: [
      { id: 'key', kind: 'choice', label: 'Key', def: 'toy', options: S.P08A ? S.P08A.KEYS : [] },
      { id: 'm', kind: 'bigint', label: 'Message m', def: '7654321' },
    ],
    check: (inp) => { let m; try { m = B(String(inp.m).trim()); } catch (e) { return 'm: a whole number'; } const k = A().key(inp.key); return m < 0n || m >= k.n ? 'm: from 0 to n − 1 = ' + (k.n - 1n) : null; },
    presets: [
      { label: 'Toy key, m = 7654321', values: { key: 'toy', m: '7654321' } },
      { label: 'm below q: then h = 0', values: { key: 'toy', m: '2026' } },
      { label: 'RSA-1024, m = 3^600', values: { key: 'rsa1024', m: (3n ** 600n).toString() } },
      { label: 'RSA-2048, m = 7^700', values: { key: 'rsa2048', m: (7n ** 700n).toString() } },
      { label: 'RSA-2048, a small m (below q: h = 0)', values: { key: 'rsa2048', m: '9876543210987654321' } },
    ],
    counters: [{ id: 'cost', label: 'work so far (size² units)' }],
    run(inp) {
      const key = A().key(inp.key), { n, e, p, q, dp, dq, qinv, d } = key, m = B(inp.m);
      const c = NT().pow(m, e, n), r = S.RSA.decryptCRT(c, key);
      const cp = c % p, cq = c % q;
      const full = P.memo('p08-crt-full', [inp.key, c.toString()], () => S.RSA.powLR(c, d, n)), hp = S.RSA.powLR(cp, dp, p), hq = S.RSA.powLR(cq, dq, q);
      const kb = P.bits(n), pb = P.bits(p), qb = P.bits(q);
      const opsF = full.squarings + full.multiplications, opsP = hp.squarings + hp.multiplications, opsQ = hq.squarings + hq.multiplications;
      const costF = opsF * kb * kb, costC = opsP * pb * pb + opsQ * qb * qb, ratio = costF / costC;
      const F = new S.Frames(['cost']);
      const view = { x: -10, y: -10, w: 880, h: 620 }, LX = 0, RX = 450, row = (k, x, y, l, v, cls, w) => A().row(k, x, y, l, v, cls, { lw: 110, w: w || 290, max: 16 });
      const lane = (side, upto, lit) => {
        const X = side === 'p' ? LX : RX, items = [...P.panel('pn' + side, X, 80, 420, 190, 'modulo ' + side + ' (' + (side === 'p' ? pb : qb) + ' bits)', side === 'p' ? 'key' : 'key')];
        const rows = side === 'p' ? [['c mod p', cp], ['dp', dp], ['mp', r.mp]] : [['c mod q', cq], ['dq', dq], ['mq', r.mq]];
        rows.slice(0, upto).forEach(([l, v], i) => items.push(...row('l' + side + i, X, 112 + i * 50, l, v, lit && i === upto - 1 ? 'act' : '')));
        return items;
      };
      const wires = [{ key: 'w1', kind: 'wire', pts: [[430, 56], [430, 66], [210, 66], [210, 80]], head: true }, { key: 'w2', kind: 'wire', pts: [[430, 66], [660, 66], [660, 80]], head: true }];
      const top = (cls) => row('c', 120, 18, 'c = m^e mod n', c, cls || 'hot', 330);
      const garner = (upto) => {
        const items = [...P.panel('gp', 110, 300, 650, 140, 'Garner: glue the halves')];
        if (upto >= 1) items.push(...row('h', 110, 332, 'h = qinv·(mp − mq) mod p', r.h, upto === 1 ? 'act' : '', 260).map((it) => (it.kind === 'text' ? Object.assign(it, { x: it.x + 140 }) : Object.assign(it, { x: it.x + 140 }))));
        if (upto >= 2) items.push(...row('mm', 110, 386, 'm = mq + h·q', r.value, 'good', 260).map((it) => Object.assign(it, { x: it.x + 140 })));
        return items;
      };
      const bars = (show) => {
        if (!show) return [];
        const W = 520, wF = W, wC = Math.max(4, Math.round(W / ratio));
        return [P.title('bt', 0, 480, 'work, counted as operations × (bits)²'),
          P.t('bl1', 150, 512, 'c^d mod n', 'strong', 'end', 14), { key: 'bf', kind: 'cell', x: 160, y: 496, w: wF, h: 24, rx: 3, text: '', cls: 'p8bar hot' }, P.t('bv1', 160 + wF + 8, 513, `${opsF} ops × ${kb}²`, 'muted', 'start', 13),
          P.t('bl2', 150, 552, 'CRT halves', 'strong', 'end', 14), { key: 'bc', kind: 'cell', x: 160, y: 536, w: wC, h: 24, rx: 3, text: '', cls: 'p8bar good' }, P.t('bv2', 160 + wC + 8, 553, `(${opsP} × ${pb}²) + (${opsQ} × ${qb}²): ${ratio.toFixed(1)} times less`, 'muted', 'start', 13)];
      };
      const add = (items, say, facts, phase) => F.add({ items, say, facts, meta: { phase } });
      add([...top(), ...wires, ...lane('p', 0), ...lane('q', 0), ...garner(0)], `The ciphertext c = ${n$(c)} (from m = ${n$(m)}, a ${kb}-bit modulus). Plain decryption would compute c^d mod n with d of ${P.bits(d)} bits. The key owner knows p and q, and can work modulo each.`, { c, m, kb, db: P.bits(d) }, 'start');
      add([...top(), ...wires, ...lane('p', 2, true), ...lane('q', 2, true), ...garner(0)], `Reduce: c mod p = ${n$(cp)} and c mod q = ${n$(cq)}, numbers of ${pb} and ${qb} bits. The exponents shrink too: dp = d mod (p − 1) = ${n$(dp)} and dq = d mod (q − 1) = ${n$(dq)}, by Fermat's little theorem.`, { cp, cq, pb, qb, dp, dq }, 'reduce');
      F.set('cost', opsP * pb * pb + opsQ * qb * qb);
      add([...top(), ...wires, ...lane('p', 3, true), ...lane('q', 3, true), ...garner(0)], `Two half-size exponentiations: mp = (c mod p)^dp mod p = ${n$(r.mp)} with ${opsP} operations, and mq = (c mod q)^dq mod q = ${n$(r.mq)} with ${opsQ}. Then m ≡ mp (mod p) and m ≡ mq (mod q).`, { mp: r.mp, mq: r.mq, opsP, opsQ }, 'halves');
      add([...top(), ...wires, ...lane('p', 3), ...lane('q', 3), ...garner(1)], `Garner's formula finds the one m below n with both residues: h = qinv·(mp − mq) mod p = ${n$(r.h)}, where qinv = q⁻¹ mod p = ${n$(qinv)} was stored with the key.`, { h: r.h, qinv }, 'garner');
      const ok = r.value === m;
      add([...top(), ...wires, ...lane('p', 3), ...lane('q', 3), ...garner(2)], `m = mq + h·q = ${n$(r.value)}${ok ? ', the message' : ' (NOT the message)'}. Check: m mod p = ${n$(r.value % p)} = mp and m mod q = ${n$(r.value % q)} = mq.`, { v: r.value, vp: r.value % p, vq: r.value % q }, 'm');
      add([...top(), ...wires, ...lane('p', 3), ...lane('q', 3), ...garner(2), ...bars(true)], `The cost: c^d mod n takes ${opsF} operations on ${kb}-bit numbers; the halves take ${opsP} and ${opsQ} on ${pb === qb ? 'numbers of ' + pb + ' bits' : pb + '- and ' + qb + '-bit numbers'}. With the work of one multiplication growing as the square of the size, the CRT is about ${ratio.toFixed(1)} times faster. The price: p and q must be kept, and a fault in one half gives them away.`, { opsF, opsP, opsQ, kb, pb, qb, ratio }, 'cost');
      for (const f of F.list) f.narrowView = f.meta.phase === 'cost' ? { x: -10, y: 460, w: 880, h: 120 } : { x: -10, y: -10, w: 880, h: 460 };
      return { frames: P.fix(F.list, view), def: P.def('RSA decryption by the CRT', ['dp = d mod (p − 1),  dq = d mod (q − 1),  qinv = q⁻¹ mod p', 'mp = (c mod p)^dp mod p', 'mq = (c mod q)^dq mod q', 'h = qinv·(mp − mq) mod p    (Garner)', 'm = mq + h·q', 'about 4 times faster than c^d mod n']) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'cost', pick: 'option', ask: 'About how much faster is decryption with the CRT?', options: ['no faster', 'about 2 times', 'about 4 times', 'about 8 times'], answer: (fr, i) => { const r = fr[i + 1].facts.ratio; return r < 1.5 ? 'no faster' : r < 3 ? 'about 2 times' : r < 6 ? 'about 4 times' : 'about 8 times'; }, explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why may dp = d mod (p − 1) replace d when working modulo p?', options: ['Because x^(p−1) ≡ 1 (mod p) for x not divisible by p (Fermat)', 'Because d < p', 'Because p is odd', 'It may not'], answer: 0, why: 'Exponents only matter modulo p − 1 when working modulo the prime p.' },
      { q: 'Halving the size of the numbers and of the exponent makes each half about how much cheaper?', options: ['2 times', '4 times', '8 times', 'no cheaper'], answer: 2, why: 'Half as many operations, each a quarter of the cost: 8 times; with two halves the total saving is about 4 times.' },
      { q: 'What does Garner\'s formula need besides mp and mq?', options: ['d', 'qinv = q⁻¹ mod p', 'φ(n)', 'e'], answer: 1, why: 'h = qinv·(mp − mq) mod p, then m = mq + h·q.' },
      { q: 'What is the danger of CRT decryption?', options: ['It is slower', 'A fault in one half lets anyone factor n from the wrong result', 'It needs a larger e', 'It only works for small m'], answer: 1, why: 'The wrong result is right modulo one prime only, so a gcd with n reveals that prime.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Small public exponents
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p08-small-e', family: 'p08-speed', order: 50, title: 'Small public exponents',
    blurb: 'Encryption and signature checking cost one squaring per bit of e and one multiplication per further 1 bit. e = 3 costs two operations, e = 65537 = 2^16 + 1 costs seventeen, a large random e costs as much as decryption. d stays large whatever e is.',
    inputs: [
      { id: 'key', kind: 'choice', label: 'Key', def: 'rsa2048', options: [{ value: 'toy2', label: 'toy: 52067 · 40013' }, { value: 'rsa1024', label: 'RSA-1024' }, { value: 'rsa2048', label: 'RSA-2048' }] },
      { id: 'm', kind: 'bigint', label: 'Message m', def: '424242' },
    ],
    check: (inp) => { let m; try { m = B(String(inp.m).trim()); } catch (e) { return 'm: a whole number'; } const k = A().key(inp.key); return m < 2n || m >= k.n ? 'm: from 2 to n − 1' : null; },
    presets: [
      { label: 'RSA-2048', values: { key: 'rsa2048', m: '424242' } },
      { label: 'RSA-1024', values: { key: 'rsa1024', m: '77777777' } },
      { label: 'Toy key', values: { key: 'toy2', m: '123456' } },
    ],
    counters: [{ id: 'ops', label: 'operations for this exponent' }],
    run(inp) {
      const name = inp.key, m = B(inp.m), base = A().key(name, 65537), { n, phi } = base;
      // a large exponent: the first prime above 2^(bits − 2) of a size we can afford, coprime to φ(n)
      const big = P.memo('p08-bige', [name], () => { let e = NT().nextPrime(NT().fromBytes(S.SHA256.hash(new TextEncoder().encode('a large public exponent'))) >> BigInt(Math.max(0, 258 - P.bits(phi)))); while (NT().gcd(e, phi) !== 1n) e = NT().nextPrime(e); return e; });
      const list = [{ e: 3n, label: 'e = 3' }, { e: 17n, label: 'e = 17' }, { e: 65537n, label: 'e = 65537' }, { e: big, label: 'a large e' }, { e: base.d, label: 'd (decrypting)' }];
      for (const x of list) { x.r = P.memo('p08-se', [name, m.toString(), x.e.toString()], () => S.RSA.powLR(m, x.e, n)); x.ops = x.r.squarings + x.r.multiplications; x.bits = x.r.bits; x.ones = [...x.bits].filter((b) => b === '1').length; }
      const maxOps = list[4].ops;
      const F = new S.Frames(['ops']);
      const view = { x: -10, y: -20, w: 880, h: 470 }, Y = (i) => 30 + i * 84;
      const rowItems = (i, lit) => {
        const x = list[i], y = Y(i), items = [P.t('lab' + i, 0, y + 20, x.label, lit ? 'act' : 'strong', 'start', 16)];
        const shown = x.bits.length <= 17 ? x.bits.split('') : x.bits.slice(0, 13).split('').concat(['…'], x.bits.slice(-3).split(''));
        shown.forEach((b, j) => items.push({ key: 'b' + i + ':' + j, kind: 'cell', x: 130 + j * 20, y: y + 2, w: 18, h: 26, rx: 3, text: b, size: 13, cls: 'bit hex ' + (b === '1' ? 'one' : '') }));
        items.push(P.t('bn' + i, 130, y + 52, `${x.bits.length} bits, ${x.ones} of them 1${x.bits.length > 17 ? ' (the middle elided)' : ''}`, 'muted', 'start', 13));
        const w = Math.max(3, Math.round((x.ops / maxOps) * 250));
        items.push({ key: 'bar' + i, kind: 'cell', x: 500, y: y + 4, w, h: 24, rx: 3, text: '', cls: 'p8bar ' + (i === 4 ? 'hot' : 'good') });
        items.push(P.t('bv' + i, 500 + w + 8, y + 21, `${x.ops} ops`, 'strong', 'start', 14));
        return items;
      };
      const head = [P.title('h1', 130, 10, 'the exponent\'s bits'), P.title('h2', 500, 10, 'squarings + multiplications')];
      for (let i = 0; i < list.length; i++) {
        const x = list[i];
        F.set('ops', x.ops);
        const items = head.concat(...list.slice(0, i + 1).map((_, j) => rowItems(j, j === i)));
        const says = [
          `e = 3 is binary 11: one squaring and one multiplication, ${x.ops} operations to encrypt or verify. The cheapest possible, but with no padding a small message has m³ < n and is read off by an ordinary cube root.`,
          `e = 17 is binary 10001: ${x.r.squarings} squarings and ${P.plural(x.r.multiplications, 'multiplication')}, ${x.ops} operations.`,
          `e = 65537 = 2^16 + 1 is binary 1 followed by fifteen 0s and a 1: ${x.r.squarings} squarings and ${P.plural(x.r.multiplications, 'multiplication')}, ${x.ops} operations. Large enough to make the small-exponent attacks harder, still almost free: the usual choice.`,
          `A large random-looking prime e of ${x.bits.length} bits, ${x.ones} of them 1: ${x.ops} operations. Nothing is gained in security, and encryption becomes as slow as a ${x.bits.length}-bit exponentiation.`,
          `For comparison, decryption with d of ${x.bits.length} bits takes ${x.ops} operations, about ${Math.round(x.ops / list[2].ops)} times the cost of encrypting with 65537. A small e is safe; a small d is not (it can be recovered from e and n).`,
        ];
        F.add({ items, say: says[i], facts: { bin: x.bits, e: x.e, sq: x.r.squarings, mul: x.r.multiplications, ops: x.ops, bits: x.bits.length, ones: x.ones, ratio: Math.round(x.ops / list[2].ops) }, meta: { phase: 'row', i } });
      }
      F.add({ items: head.concat(...list.map((_, j) => rowItems(j, false))), say: `Every one of these exponents gives a working key with the same n (as long as gcd(e, φ(n)) = 1). The choice only changes the public side's cost: ${list[0].ops}, ${list[1].ops}, ${list[2].ops} and ${list[3].ops} operations, against ${list[4].ops} for decrypting.`, facts: { ops: list.map((x) => x.ops) }, meta: { phase: 'end' } });
      return { frames: P.fix(F.list, view), def: P.def('The cost of x^e', ['squarings = (bits of e) − 1', 'multiplications = (1 bits of e) − 1', 'e = 3 = 11₂: 2 operations', 'e = 65537 = 10000000000000001₂: 17', 'd ≈ n in size: about 1.5 × (bits of n)']) };
    },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'row' && f.meta.i === 1, pick: 'option', ask: 'How many operations (squarings and multiplications) does e = 65537 take?', options: ['2', '17', '32', '65536'], answer: (fr, i) => String(fr[i + 1].facts.ops), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Why is e = 65537 so popular?', options: ['It is the largest prime', 'It has only two 1 bits, so encryption is 17 operations, yet it is not tiny', 'It makes d small', 'It is required by RSA'], answer: 1, why: '2^16 + 1: 16 squarings and one multiplication.' },
      { q: 'Does a small e make decryption faster?', options: ['Yes', 'No: d is still about as long as n', 'Only with the CRT', 'Only for e = 3'], answer: 1, why: 'e·d ≡ 1 (mod φ(n)) forces a large d for any ordinary key.' },
      { q: 'Choosing d small instead (for fast decryption) is…', options: ['Fine', 'Dangerous: a small d can be recovered from (n, e)', 'Impossible', 'Required for signatures'], answer: 1, why: 'Continued-fraction attacks find d below about n^0.25.' },
      { q: 'What is the risk with e = 3?', options: ['None at all', 'Without padding, a short message is recovered by an integer cube root, and one message sent to three people leaks', 'Decryption fails', 'n must be even'], answer: 1, why: 'Small e is only safe with proper padding such as OAEP.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
