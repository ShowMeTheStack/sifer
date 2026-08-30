// Part 8, why the rules for RSA keys exist (the first four): a small public exponent without padding, one message
// under one modulus with two exponents, one message broadcast to three people with e = 3, and a small private
// exponent. Each shows the weakness and when it applies, states what it costs, and ends with the defence; none works
// the recovery through. Also the helpers that p08-padding.js and p08-sizes.js share (S.P08B): toy keys, value
// blocks, ports, short hex.
(function (S) {
  'use strict';
  const P = S.PK, NT = () => S.NT, KP = () => S.Kit.pk;
  const H = (S.P08B = S.P08B || {});

  // ---- shared helpers ---------------------------------------------------------------------------------------------
  /** toy primes, all ≡ 2 (mod 3), so e = 3, 17 and 65537 all work */
  H.TOY = [[1031n, 1019n], [1061n, 1049n], [1097n, 1091n]];
  H.KEYS = [
    { value: 'toy', label: 'toy (n of 20 bits)' },
    { value: 'rsa1024', label: 'RSA-1024' },
    { value: 'rsa2048', label: 'RSA-2048' },
  ];
  /** a key by name: 'toy' (pair 0..2 of the toy primes) or a real one; e defaults to 65537 */
  H.key = (name, e, pair) => {
    e = BigInt(e || 65537);
    if (name === 'toy') { const [p, q] = H.TOY[pair || 0]; return S.RSA.fromPrimes(p, q, e); }
    return P.rsaKey(name, e, pair || 0);
  };
  H.kname = (name) => (name === 'toy' ? 'the toy key' : name.replace('rsa', 'RSA-'));
  /** a value block: a long number abbreviated (click for the whole of it) */
  H.vb = (key, x, y, label, value, cls, o) => KP().value(Object.assign({ key, x, y, label, value, cls: cls || '', max: 14, count: false }, o || {}));
  /** the four mid-edge points of a block */
  H.port = (it, side) => (side === 'n' ? [it.x, it.y - it.h / 2] : side === 's' ? [it.x, it.y + it.h / 2] : side === 'w' ? [it.x - it.w / 2, it.y] : [it.x + it.w / 2, it.y]);
  H.wire = (key, pts, cls, head) => ({ key, kind: 'wire', pts: pts.map((p) => [P.r2(p[0]), P.r2(p[1])]), head: head !== false, cls: cls || '' });
  H.box = (key, x, y, w, h, lines, cls) => ({ key, kind: 'state', x, y, w, h, rx: 7, lines, cls: 'block ' + (cls || '') });
  /** bytes as hex, the first n bytes and an ellipsis */
  H.hx = (b, n) => { const s = Array.from(b, (v) => v.toString(16).padStart(2, '0')).join(''); return s.length > 2 * (n || 8) ? s.slice(0, 2 * (n || 8)) + '…' : s; };
  H.hexAll = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
  H.textNum = (s) => NT().fromBytes(new TextEncoder().encode(s));
  /** a number read back as text, when its bytes are printable */
  H.numText = (m) => { try { const t = new TextDecoder('utf-8', { fatal: true }).decode(NT().toBytes(m)); return /^[\x20-\x7e]+$/.test(t) ? t : null; } catch (e) { return null; } };
  H.view = { x: 0, y: 0, w: 860, h: 500 };
  H.keyPicker = (def) => ({ id: 'key', kind: 'choice', label: 'Key', def: def || 'toy', options: H.KEYS });

  // ---------------------------------------------------------------------------------------------------------------
  // A small public exponent and no padding
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p08-small-e-attack', family: 'p08-attacks', order: 10, title: 'A small exponent without padding',
    blurb: 'With e = 3 and no padding, a short message has m³ smaller than n: the reduction modulo n never happens, and the ciphertext is just m³, an ordinary integer that no key protects. The defence is padding that makes every encoded message as long as n.',
    inputs: [
      H.keyPicker('rsa2048'),
      { id: 'msg', kind: 'text', label: 'Message (text; a number for the toy key)', def: 'meet at the old mill at nine', check: (v, inp) => (inp.key === 'toy' ? (/^\d+$/.test(String(v).trim()) && BigInt(v) > 1n && BigInt(v) < 1048000n ? null : 'Message: a whole number from 2 to 1047999 for the toy key') : String(v).length < 1 || String(v).length > 40 ? 'Message: 1 to 40 characters' : null) },
    ],
    presets: [
      { label: 'RSA-2048, a short message', values: { key: 'rsa2048', msg: 'meet at the old mill at nine' } },
      { label: 'RSA-1024, a short message', values: { key: 'rsa1024', msg: 'pin 4417' } },
      { label: 'Toy: m³ < n', values: { key: 'toy', msg: '87' } },
      { label: 'Toy: m³ wraps once', values: { key: 'toy', msg: '113' } },
      { label: 'Toy: wraps too often', values: { key: 'toy', msg: '50001' } },
    ],
    run(inp) {
      return P.memo('p08-small-e-attack', inp, () => {
        const key = H.key(inp.key, 3), n = key.n, toy = inp.key === 'toy';
        const m = toy ? BigInt(String(inp.msg).trim()) : H.textNum(inp.msg);
        if (m >= n) throw new Error('the message must be below n');
        const c = S.RSA.encrypt(m, { n, e: 3n }).value;
        const att = S.RSA.attack.smallE({ n, e: 3n, c }, { maxK: 1000 });
        const F = new S.Frames([]);
        const bm = P.bits(m), b3 = P.bits(m ** 3n), bn = P.bits(n);
        // bars on a scale of bits
        const lg2 = (v) => { const t = v.toString(2); return t.length - 1 + Math.log2(parseInt(t.slice(0, 30), 2) / 2 ** (Math.min(30, t.length) - 1)); };
        const X0 = 150, W = 560, maxL = Math.max(lg2(m ** 3n), lg2(n)), sc = (v) => P.r2((W * lg2(v)) / maxL);
        const bar = (k, y, label, v, cls) => [P.t(k + ':l', X0 - 14, y + 19, label, 'strong', 'end', 15), { key: k, kind: 'cell', x: X0, y, w: Math.max(4, sc(v)), h: 28, rx: 4, text: '', cls: cls }, P.t(k + ':n', X0 + Math.max(4, sc(v)) + 10, y + 19, P.bits(v) + ' bits', 'mono', 'start', 14)];
        const nline = [{ key: 'nl', kind: 'line', x1: X0 + sc(n), y1: 40, x2: X0 + sc(n), y2: 214, cls: 'bad dash', audit: 'ignore' }, P.t('nlt', X0 + sc(n), 30, 'size of n', 'bad', 'middle', 13)];
        const values = (lit) => [H.vb('vm', 140, 290, 'message m', m, lit === 'm' ? 'bad' : ''), H.vb('vc', 430, 290, 'c = m³ mod n', c, lit === 'c' ? 'act' : ''), H.vb('vn', 715, 290, 'modulus n', n)];
        const fits = m ** 3n < n;
        const bars = (stage) => [...nline, ...bar('bm', 60, 'm', m, 'act'), ...(stage >= 1 ? bar('b3', 110, 'm³', m ** 3n, fits ? 'good' : 'bad') : []), ...bar('bn', 160, 'n', n, 'key')];
        const eq = (lines) => P.eqs('tr', 30, 380, lines, 15, 28);
        const add = (say, facts, items, meta) => F.add({ items, say, facts, meta: meta || {} });
        add(`${toy ? `The toy key with e = 3: n = ${P.n(n)}` : `${H.kname(inp.key)} with e = 3 and no padding: n has ${bn} bits`}. The message ${toy ? `m = ${P.n(m)}` : `“${inp.msg}”, read as a number m,`} has ${bm} bits, and c = m³ mod n = ${P.n(c)}.`,
          { n, m, c, bn, bm, digits: [P.digits(n), P.digits(c)], msg: inp.msg }, [...bars(0), ...values('c')], { phase: 'start' });
        add(fits ? `m³ has only ${b3} bits${b3 === bn ? ' and is still below n' : `, fewer than the ${bn} of n`}: m³ is smaller than n, so “mod n” did nothing. The ciphertext is m³ itself, an ordinary integer, and nothing secret stands between it and m.` : `m³ has ${b3} bits and is larger than n (${bn} bits), so m³ wrapped round n. How often it wrapped decides everything: a few times, and the ciphertext is still nearly an ordinary integer; very many times, and the reduction hides m as RSA intends.`,
          { b3, bn }, [...bars(1), ...values('c')], { phase: 'size', fits });
        const wraps = (m ** 3n) / n;
        if (att.m !== null) {
          add(`The outcome: ${att.k === 0n ? 'with no wrap at all' : `with m³ wrapping round n only ${att.k === 1n ? 'once' : P.plural(att.k, 'time')}`}, anyone holding c can undo the encryption by an integer cube root, without d and without factoring n. This recovers the plaintext.`,
            { k: att.k, ok: att.m === m, msg: inp.msg }, [...bars(1), ...values('m'), ...eq([['no padding, e = 3, a short m: c is (nearly) m³ over the integers', ''], ['outcome: the plaintext is recovered, no key needed', 'bad']])], { phase: 'done', ok: att.m === m });
        } else {
          add(`Here m³ wrapped round n about ${P.n(wraps)} times, more than a short search covers. But this message is safe only by luck of its length; a shorter one would not be.`,
            { wraps }, [...bars(1), ...values('c'), ...eq([['m³ wrapped round n too many times', 'good'], ['safe by luck of length, not by design', 'bad']])], { phase: 'done', ok: false });
        }
        add(`The defence is padding. OAEP turns every message into a random-looking block as long as n (${bn} bits), so its cube wraps round n about 2^${2 * bn} times and no root can be taken. With padding, e = 65537 is the usual choice too.`,
          { bn, bn2: 2 * bn, e: 65537 }, [...bars(1), ...values('c'), ...eq([['defence: OAEP fills every message to the size of n', 'good'], ['with fresh random bytes, so the block cubed wraps round n', 'good'], ['an astronomical number of times', 'good']])], { phase: 'defence' });
        return { frames: P.fix(F.list, { x: 0, y: 10, w: 860, h: 520 }), def: P.def('Small e without padding', ['c = m³ mod n, no padding', 'm³ < n: c = m³ over the integers, no secret involved', 'the same if m³ wraps round n only a few times', 'defence: padding (OAEP) fills m to the size of n']) };
      });
    },
    predict: [
      { at: (f) => f.meta.phase === 'start', pick: 'option', ask: 'Will m³ be smaller than n, so that no reduction happens?', options: ['yes', 'no'], answer: (fr, i) => (fr[i + 1].meta.fits ? 'yes' : 'no'), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'With e = 3 and m³ < n, what is c?', options: ['m³, exactly', 'a random number', 'm', 'n − m³'], answer: 0, why: 'The reduction modulo n never happens, so c is the integer m³.' },
      { q: 'Why does the private key not protect a short message here?', options: ['The reduction modulo n, which is what hides m, never happened', 'e = 3 is not prime', 'n is too short', 'The message is not ASCII'], answer: 0, why: 'RSA hides m only by wrapping m^e round n many times; with no wrap, c is just m³.' },
      { q: 'What defeats this weakness?', options: ['A larger e only', 'Random padding such as OAEP', 'A larger n alone', 'Encrypting twice'], answer: 1, why: 'Padding fills the block to the size of n with random bytes, so m³ wraps round n an astronomical number of times.' },
      { q: 'A longer modulus with the same short message and no padding…', options: ['fixes it', 'changes nothing: m³ is still below n', 'makes it worse', 'needs a larger e'], answer: 1, why: 'A larger n only widens the gap between m³ and n.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // The common modulus
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p08-common-modulus', family: 'p08-attacks', order: 20, title: 'A common modulus',
    blurb: 'One modulus n shared by two people with exponents e1 and e2. The same message sent to both gives c1 = m^e1 and c2 = m^e2, and when gcd(e1, e2) = 1 those two public numbers, with e1 and e2, give m to anyone, with no private key. Worse, either person can factor n. Every key pair needs its own modulus.',
    inputs: [
      H.keyPicker('toy'),
      { id: 'e1', kind: 'bigint', label: 'Exponent e1', def: '17' },
      { id: 'e2', kind: 'bigint', label: 'Exponent e2', def: '65537' },
      { id: 'msg', kind: 'text', label: 'Message (text; a number for the toy key)', def: '271828', check: (v, inp) => (inp.key === 'toy' ? (/^\d+$/.test(String(v).trim()) && BigInt(v) > 1n && BigInt(v) < 1050000n ? null : 'Message: a whole number from 2 to 1049999 for the toy key') : String(v).length < 1 || String(v).length > 60 ? 'Message: 1 to 60 characters' : null) },
    ],
    presets: [
      { label: 'Toy: e1 = 17, e2 = 65537', values: { key: 'toy', e1: '17', e2: '65537', msg: '271828' } },
      { label: 'Toy: e1 = 7, e2 = 11', values: { key: 'toy', e1: '7', e2: '11', msg: '424242' } },
      { label: 'RSA-2048: e1 = 3, e2 = 65537', values: { key: 'rsa2048', e1: '3', e2: '65537', msg: 'payroll run approved' } },
      { label: 'RSA-1024: e1 = 17, e2 = 3', values: { key: 'rsa1024', e1: '17', e2: '3', msg: 'the vault code is 0613' } },
    ],
    check(inp) {
      let e1, e2; try { e1 = BigInt(inp.e1); e2 = BigInt(inp.e2); } catch (e) { return 'The exponents must be whole numbers'; }
      if (e1 < 3n || e2 < 3n || e1 === e2) return 'Two different exponents of at least 3';
      const k = H.key(inp.key, 65537);
      for (const e of [e1, e2]) if (NT().gcd(e, k.phi) !== 1n || e >= k.phi) return 'Exponent ' + e + ' is not a valid RSA exponent for this key (it shares a factor with φ(n))';
      return null;
    },
    run(inp) {
      return P.memo('p08-common-modulus', inp, () => {
        const toy = inp.key === 'toy', k = H.key(inp.key, 65537), n = k.n, e1 = BigInt(inp.e1), e2 = BigInt(inp.e2);
        const m = toy ? BigInt(String(inp.msg).trim()) : H.textNum(inp.msg);
        if (m >= n) throw new Error('the message must be below n');
        const c1 = NT().pow(m, e1, n), c2 = NT().pow(m, e2, n);
        const att = S.RSA.attack.commonModulus({ n, e1, e2, c1, c2 });
        const g = NT().gcd(e1, e2), ok = att.m === m;
        const F = new S.Frames([]);
        const add = (say, facts, items, meta) => F.add({ items, say, facts, meta: meta || {} });
        const lanes = (lit) => {
          const mb = H.vb('m', 100, 80, 'message m', m, lit.m || ''), c1b = H.vb('c1', 340, 80, `c1 = m^${e1} mod n`, c1, 'act'), c2b = H.vb('c2', 340, 200, `c2 = m^${e2} mod n`, c2, 'act');
          return [mb, c1b, c2b, H.wire('w1', [H.port(mb, 'e'), H.port(c1b, 'w')], 'act'), H.wire('w2', [[205, 80], [205, 200], H.port(c2b, 'w')], 'act'), { key: 'jd', kind: 'dot', x: 205, y: 80, r: 3.6, cls: 'act', audit: 'ignore' },
            P.t('nn', 20, 290, 'both under one n = ' + KP().fmt(n, { max: 18 }).text, 'mono', 'start', 14)];
        };
        const eq = (lines) => P.eqs('bz', 20, 350, lines, 16, 30);
        add(`One modulus n is shared, and the same message m = ${toy ? P.n(m) : 'the text “' + inp.msg + '”'} goes out twice: c1 = m^${e1} mod n = ${P.n(c1)} and c2 = m^${e2} mod n = ${P.n(c2)}. An eavesdropper sees n, e1, e2, c1 and c2, and never d.`,
          { m, c1, c2, e1, e2, msg: inp.msg }, [...lanes({})], { phase: 'start' });
        add(`The precondition: gcd(e1, e2) = ${g}${g === 1n ? ', as it is for almost any two exponents' : ''}. Both ciphertexts are powers of one m under one modulus, so their exponents can be played off against each other using public numbers alone.`,
          { g, e1, e2 }, [...lanes({}), ...eq([['the same m, the same n, two exponents', 'strong'], [`gcd(e1, e2) = ${g}`, g === 1n ? 'bad' : '']])], { phase: 'pre' });
        add(ok ? `The outcome: from c1, c2, e1 and e2 alone, anyone recovers the message, without d. And there is worse: either person, holding their own e and d for this n, can factor n and compute the other's d.` : `With gcd(e1, e2) = ${g} the public numbers give only a power of m here. But either person, holding their own e and d for this n, can still factor n and compute the other's d.`,
          { ok, g, msg: inp.msg }, [...lanes({ m: ok ? 'bad' : '' }), ...eq([['outcome: the message is recovered without d', ok ? 'bad' : 'muted'], ['and one key pair on n factors n', 'bad']])], { phase: 'done', ok });
        add('The defence: never share a modulus. Each key pair gets its own n, made from its own fresh random primes, and then nothing one person holds says anything about another\'s key.',
          {}, [...lanes({}), ...eq([['defence: one modulus per key pair', 'good'], ['each n from its own fresh random primes', 'good']])], { phase: 'defence' });
        return { frames: P.fix(F.list, { x: 0, y: 0, w: 870, h: 470 }), def: P.def('A shared modulus', ['c1 = m^e1 mod n, c2 = m^e2 mod n (the same n)', 'gcd(e1, e2) = 1: the public values give m', 'one key pair (e, d) on n also factors n', 'defence: every key pair has its own modulus']) };
      });
    },
    predict: [
      { at: (f) => f.meta.phase === 'start', pick: 'option', ask: 'Can the eavesdropper, with n, e1, e2, c1 and c2 only, read m?', options: ['yes', 'no'], answer: (fr) => (fr.find((f) => f.meta.phase === 'done').meta.ok ? 'yes' : 'no'), explain: (fr) => fr.find((f) => f.meta.phase === 'done').say },
    ],
    quiz: [
      { q: 'What does the eavesdropper need besides c1 and c2?', options: ['d', 'p and q', 'only n, e1 and e2', 'φ(n)'], answer: 2, why: 'Public values are enough when the exponents are coprime.' },
      { q: 'What must hold for the two ciphertexts alone to give m?', options: ['gcd(e1, e2) = 1', 'n is prime', 'd is small', 'm is short'], answer: 0, why: 'With coprime exponents the two powers of m can be combined into m itself; otherwise only a power of m comes out.' },
      { q: 'An employee holds (e1, d1) for the shared n. What can they do?', options: ['Nothing beyond their own messages', 'Factor n, and so compute everyone else\'s d', 'Only read messages sent with e1', 'Only sign'], answer: 1, why: 'e1·d1 − 1 is a multiple of φ(n), which is enough to factor n.' },
      { q: 'What is the lesson?', options: ['Use e = 3', 'Never reuse one modulus for different key pairs', 'Use longer messages', 'Encrypt twice'], answer: 1, why: 'Anyone holding one key pair for n can factor n; and the same message under two exponents leaks directly.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Håstad's broadcast
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p08-hastad', family: 'p08-attacks', order: 30, title: 'One message to three people',
    blurb: 'The same unpadded message goes to three people, each with e = 3 and a modulus of their own. Each ciphertext alone is as hard as RSA; together they pin down m³ exactly, because m is below every modulus, and that gives the message away. Random padding makes the three copies different numbers, and the weakness disappears.',
    inputs: [
      H.keyPicker('toy'),
      { id: 'msg', kind: 'text', label: 'Message (text; a number for the toy keys)', def: '777001', check: (v, inp) => (inp.key === 'toy' ? (/^\d+$/.test(String(v).trim()) && BigInt(v) > 1n && BigInt(v) < 1050000n ? null : 'Message: a whole number from 2 to 1049999 for the toy keys') : String(v).length < 1 || String(v).length > 120 ? 'Message: 1 to 120 characters' : null) },
    ],
    presets: [
      { label: 'Toy keys', values: { key: 'toy', msg: '777001' } },
      { label: 'Toy keys, a small message', values: { key: 'toy', msg: '5309' } },
      { label: 'Three RSA-1024 keys', values: { key: 'rsa1024', msg: 'the board meets on friday in the long room upstairs at ten' } },
      { label: 'RSA-1024, a short message', values: { key: 'rsa1024', msg: 'meet at ten' } },
      { label: 'Three RSA-2048 keys', values: { key: 'rsa2048', msg: 'the new door code is 8835; change it after the audit and tell only the night shift, nobody else' } },
    ],
    run(inp) {
      return P.memo('p08-hastad', inp, () => {
        const toy = inp.key === 'toy', keys = [0, 1, 2].map((i) => H.key(inp.key, 3, i));
        const m = toy ? BigInt(String(inp.msg).trim()) : H.textNum(inp.msg);
        if (keys.some((k) => m >= k.n)) throw new Error('the message must be below every modulus');
        const items = keys.map((k) => ({ n: k.n, c: NT().pow(m, 3n, k.n) }));
        const att = S.RSA.attack.hastad({ e: 3n, items });
        const N = items.reduce((a, x) => a * x.n, 1n);
        const F = new S.Frames([]);
        const add = (say, facts, its, meta) => F.add({ items: its, say, facts, meta: meta || {} });
        const ys = [80, 200, 320], names = ['Ana', 'Bo', 'Cai'];
        const pic = (o) => {
          const out = [...KP().party({ key: 'snd', x: 55, y: 186, name: 'sender', cls: 'alice' })];
          ys.forEach((y, i) => {
            const cb = H.vb('c' + i, 300, y, `c${i + 1} = m³ mod n${i + 1} (${names[i]})`, items[i].c, o.lit === i ? 'hot' : o.c > i ? 'act' : 'soft');
            out.push(cb);
            out.push(H.wire('ws' + i, [[80, 200 + (i - 1) * 12], [140, 200 + (i - 1) * 12], [140, y], H.port(cb, 'w')], o.c > i ? 'act' : 'faint'));
          });
          if (o.lines) out.push(...P.eqs('eq', 470, 110, o.lines, 15, 32));
          return out;
        };
        add(`Three people, three moduli of their own, and e = 3 for each. The sender encrypts the same message m ${toy ? '= ' + P.n(m) : '(the text “' + inp.msg + '”)'} three times, with no padding.`, { m, msg: inp.msg }, pic({ c: 0 }), { phase: 'start' });
        items.forEach((it, i) => add(`c${i + 1} = m³ mod n${i + 1} = ${P.n(it.c)}, with n${i + 1} = ${P.n(it.n)}. ${it.c === m ** 3n ? 'Here m³ is even below n' + (i + 1) + ', so c' + (i + 1) + ' is m³ itself: the small-exponent weakness alone would do. A longer message wraps, and needs the three.' : i < 2 ? 'Any one of these alone is as hard as RSA: m³ wrapped round n' + (i + 1) + '.' : 'Each ciphertext says what m³ is modulo one modulus.'}`, { c: it.c, n: it.n }, pic({ c: i + 1, lit: i }), { phase: 'ct' }));
        const bN = P.bits(N), b3 = P.bits(m ** 3n);
        add(`The precondition and the outcome: m is below every modulus, so m³ (${b3} bits) is below their product (${bN} bits). Three remainders of one number, modulo three coprime moduli whose product exceeds it, fix that number exactly, so the three ciphertexts together give m³ and then m. This recovers the message, with no private key.`,
          { b3, bN, ok: att.m === m, msg: inp.msg }, pic({ c: 3, lines: [['the same m, e = 3, three moduli', 'strong'], [`m³: ${b3} bits < n1·n2·n3: ${bN} bits`, ''], ['outcome: the message is recovered', 'bad']] }), { phase: 'done', ok: att.m === m });
        add(`The defence is random padding. OAEP pads each copy with a fresh random seed, so the three recipients receive encryptions of three different numbers and there is no common m³ to rebuild. A larger e alone (65537) only raises the number of copies needed; padding is what removes the weakness.`,
          { e: 65537 }, pic({ c: 3, lines: [['defence: OAEP, a fresh random seed per copy', 'good'], ['three different padded numbers', 'good'], ['no common m³ exists', 'good']] }), { phase: 'defence' });
        return { frames: P.fix(F.list, { x: 0, y: 20, w: 850, h: 440 }), def: P.def('One message, three recipients', ['c_i = m³ mod n_i, i = 1, 2, 3, no padding', 'm < every n_i, so m³ < n1·n2·n3', 'the three c_i fix m³ exactly: m is exposed', 'defence: random padding (OAEP), so the copies differ']) };
      });
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'done', pick: 'option', ask: 'Three unpadded copies of one message under e = 3. Can an eavesdropper read m without any private key?', options: ['yes', 'no'], answer: 'yes', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'How many ciphertexts of the same message does this weakness need with e = 3?', options: ['1', '2', '3', '65537'], answer: 2, why: 'Three congruences modulo three moduli fix m³ modulo a number larger than m³.' },
      { q: 'Why do the three together fix m³ exactly?', options: ['Because m < each n_i, so m³ < n1·n2·n3', 'Because e is odd', 'Because the n_i are prime', 'It is a coincidence'], answer: 0, why: 'm³ is below the product of the three moduli, so knowing it modulo that product is knowing it.' },
      { q: 'Do longer moduli help?', options: ['Yes, a lot', 'No: m is still below each, and m³ below their product', 'Only for e = 3', 'Only with a short message'], answer: 1, why: 'The condition m³ < n1·n2·n3 holds at any size.' },
      { q: 'What removes the weakness?', options: ['Larger moduli', 'Random padding, so each copy encrypts a different number', 'Sending at night', 'e = 3 for everyone'], answer: 1, why: 'With OAEP the three plaintexts differ, so there is no common m³ to reconstruct.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Wiener's attack
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p08-wiener', family: 'p08-attacks', order: 40, title: 'A small private exponent',
    blurb: 'To make decryption fast, someone picks a small d. But e·d − k·φ(n) = 1 with φ(n) close to n, so e/n is an extremely close approximation of k/d, and when d is below about n^¼/3 that closeness is enough for the public key alone to give d away. Keep d full length; get speed from the CRT.',
    inputs: [
      { id: 'bits', kind: 'choice', label: 'Modulus size', def: '64', options: [{ value: '64', label: '64 bits (toy)' }, { value: '256', label: '256 bits' }, { value: '1024', label: '1024 bits' }, { value: '2048', label: '2048 bits' }] },
      { id: 'kind', kind: 'choice', label: 'Private exponent', def: 'small', options: [{ value: 'small', label: 'small: d < n^¼ / 3' }, { value: 'normal', label: 'normal: e = 65537, d as long as n' }] },
      { id: 'seed', kind: 'number', label: 'Seed', def: 7, min: 1, max: 9999 },
    ],
    presets: [
      { label: '64 bits, small d', values: { bits: '64', kind: 'small', seed: 7 } },
      { label: '256 bits, small d', values: { bits: '256', kind: 'small', seed: 21 } },
      { label: '1024 bits, small d', values: { bits: '1024', kind: 'small', seed: 3 } },
      { label: '2048 bits, small d', values: { bits: '2048', kind: 'small', seed: 5 } },
      { label: '64 bits, a normal d', values: { bits: '64', kind: 'normal', seed: 7 } },
      { label: 'RSA-1024, a normal d', values: { bits: '1024', kind: 'normal', seed: 1 } },
    ],
    run(inp) {
      return P.memo('p08-wiener', inp, () => {
        const bits = +inp.bits;
        let n, e, secret;
        if (inp.kind === 'small') { const lab = S.RSA.labs.wiener(inp.seed, { bits }); n = lab.public.n; e = lab.public.e; secret = lab.secret; }
        else { const k = bits >= 1024 ? P.rsaKey('rsa' + bits) : S.RSA.seeded(inp.seed, () => S.RSA.keygen(bits)); n = k.n; e = k.e; secret = { d: k.d, p: k.p, q: k.q }; }
        const att = S.RSA.attack.wiener({ n, e });
        const bound = NT().iroot(n, 4).root / 3n, db = P.bits(secret.d), bb = P.bits(bound), nb = P.bits(n), eb = P.bits(e);
        const F = new S.Frames([]);
        const add = (say, facts, its, meta) => F.add({ items: its, say, facts, meta: meta || {} });
        // a scale of bits: where d sits against n^¼/3 and n
        const X0 = 120, W = 640, sc = (b) => P.r2(X0 + (W * b) / nb);
        const scale = (lit) => [
          { key: 'ax', kind: 'line', x1: X0, y1: 250, x2: X0 + W, y2: 250, cls: 'nt-axis', audit: 'ignore', layer: 'back' },
          { key: 'zone', kind: 'cell', x: X0, y: 212, w: Math.max(4, sc(bb) - X0), h: 30, rx: 4, text: '', cls: 'bad' },
          P.t('zt', X0, 200, 'd below n^¼/3: exposed', 'bad', 'start', 14),
          P.t('bt', sc(bb), 318, 'n^¼/3: ' + bb + ' bits', 'mono', 'middle', 14),
          P.t('nt', X0 + W, 318, 'n: ' + nb + ' bits', 'mono', 'end', 14),
          { key: 'dm', kind: 'head', x: sc(db), y: 250, text: 'd: ' + db + ' bits', side: 'below', cls: lit || (db <= bb ? 'hot' : 'good') },
        ];
        const head = [H.vb('n', 140, 60, 'n (' + nb + ' bits)', n), H.vb('e', 440, 60, 'e (' + eb + ' bits)', e)];
        const eq = (lines) => P.eqs('eq', 40, 370, lines, 16, 30);
        add(`The public key: n of ${nb} bits and e of ${eb} bits. ${inp.kind === 'small' ? 'An e almost as long as n is a warning sign: it is what you get when d was chosen first, and small.' : 'Here e = 65537 and d is about as long as n.'} Only n and e are public.`,
          { nb, eb, e65537: 65537 }, [...head], { phase: 'start' });
        add(`Why size matters: e·d = 1 + k·φ(n) and φ(n) differs from n only in its lower half, so e/n is an extremely good approximation of k/d. When d is below about n^¼/3 (here ${bb} bits), it is so good that k/d can be read off e/n. This d has ${db} bits.`,
          { bb, db }, [...head, ...scale(), ...eq([['e·d = 1 + k·φ(n), and φ(n) ≈ n', ''], ['so e/n ≈ k/d, closely enough when d < n^¼/3', '']])], { phase: 'pre' });
        if (att.d !== null) {
          add(`The outcome: d is in the exposed range, so the public key alone gives it away, and with it the factors of n, in a moment and at any size of n. This recovers the private key.`,
            { ok: att.d === secret.d }, [...head, ...scale('bad'), ...eq([['d below n^¼/3', 'bad'], ['outcome: (n, e) alone reveal d and the factors', 'bad']])], { phase: 'done', ok: true });
        } else {
          add(`The outcome: d has ${db} bits, far above n^¼/3 (${bb} bits), so e/n says nothing useful about it. A full-length d is safe from this weakness.`,
            { db, bb }, [...head, ...scale('good'), ...eq([['d far above n^¼/3', 'good'], ['outcome: nothing is revealed', 'good']])], { phase: 'done', ok: false });
        }
        add('The defence is in key generation: choose e (usually 65537) and compute d from it, so d is as long as n. If private-key work must be faster, use the CRT, which gives about a fourfold speed-up and leaves d full length.',
          { e: 65537 }, [...head, ...scale(), ...eq([['defence: e = 65537, d computed from it, full length', 'good'], ['speed from the CRT, never from a short d', 'good']])], { phase: 'defence' });
        return { frames: P.fix(F.list, { x: 0, y: 0, w: 870, h: 480 }), def: P.def('A small private exponent', ['e·d = 1 + k·φ(n), and φ(n) ≈ n', 'so e/n ≈ k/d', 'd < n^¼/3: (n, e) alone give d away', 'defence: e = 65537, d full length; speed from the CRT']) };
      });
    },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'pre', pick: 'option', ask: 'Will the public key alone give this d away?', options: ['yes', 'no'], answer: (fr) => (fr.find((f) => f.meta.phase === 'done').meta.ok ? 'yes' : 'no'), explain: (fr) => fr.find((f) => f.meta.phase === 'done').say },
    ],
    quiz: [
      { q: 'Why is k/d close to e/n?', options: ['Because e·d = 1 + k·φ(n) and φ(n) is close to n', 'Because e = d', 'Because n is prime', 'Because k is small'], answer: 0, why: 'Divide e·d − k·φ = 1 by d·φ: e/φ − k/d = 1/(d·φ), and φ differs from n only in its lower half.' },
      { q: 'Below roughly what size is d exposed this way?', options: ['n^¼/3', 'n/2', 'e', 'Any size'], answer: 0, why: 'Below about n^¼/3 the approximation is close enough to give d away.' },
      { q: 'Which key generation choice avoids it?', options: ['Pick a small d, then compute e', 'Pick e = 65537, then compute d', 'Pick d = e', 'Pick a short n'], answer: 1, why: 'A d computed from a small e is about as long as n, far above the bound.' },
      { q: 'What is the safe way to make decryption fast?', options: ['A small d', 'The CRT with a full-size d', 'e = 1', 'A shorter n'], answer: 1, why: 'The CRT gives about a fourfold speed-up and leaves d full-size.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
