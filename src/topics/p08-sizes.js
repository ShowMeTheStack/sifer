// Part 8, toy and real keys side by side: the same formulas run on two two-digit primes and on a real key of 1024 to
// 3072 bits, row by row (p, q, n, φ(n), e, d, a message, its ciphertext, the message back, and the work it took),
// with each number's length drawn to scale.
(function (S) {
  'use strict';
  const P = S.PK, NT = () => S.NT, KP = () => S.Kit.pk;

  const isP = (v) => { try { return S.NT.isProbablePrime(BigInt(v)); } catch (e) { return false; } };
  S.topic({
    id: 'p08-sizes', family: 'p08-sizes', order: 10, title: 'Toy and real keys side by side',
    blurb: 'A toy key from two-digit primes fits on a postcard: every number can be checked by hand. A real key runs the very same formulas on numbers hundreds of digits long. Row by row, the toy and the real key side by side, with each number\'s length drawn to scale.',
    inputs: [
      { id: 'p', kind: 'bigint', label: 'Toy prime p', def: '89', check: (v) => (!isP(v) || BigInt(v) < 11n || BigInt(v) > 997n ? 'p: a prime from 11 to 997' : null) },
      { id: 'q', kind: 'bigint', label: 'Toy prime q', def: '97', check: (v, inp) => (!isP(v) || BigInt(v) < 11n || BigInt(v) > 997n ? 'q: a prime from 11 to 997' : BigInt(v) === BigInt(inp.p) ? 'q: a prime different from p' : null) },
      { id: 'm', kind: 'bigint', label: 'Toy message m', def: '4242', check: (v, inp) => { try { return BigInt(v) < 2n || BigInt(v) >= BigInt(inp.p) * BigInt(inp.q) ? 'm: from 2 to p·q − 1' : null; } catch (e) { return 'm: a whole number'; } } },
      { id: 'key', kind: 'choice', label: 'Real key', def: 'rsa2048', options: [{ value: 'rsa1024', label: 'RSA-1024' }, { value: 'rsa2048', label: 'RSA-2048' }, { value: 'rsa3072', label: 'RSA-3072' }] },
      { id: 'msg', kind: 'text', label: 'Real message', def: 'hello from the real key', check: (v) => (String(v).length < 1 || String(v).length > 60 ? 'Real message: 1 to 60 characters' : null) },
    ],
    presets: [
      { label: '89 and 97 next to RSA-2048', values: { p: '89', q: '97', m: '4242', key: 'rsa2048', msg: 'hello from the real key' } },
      { label: '11 and 13 next to RSA-1024', values: { p: '11', q: '13', m: '100', key: 'rsa1024', msg: 'small and large' } },
      { label: '991 and 997 next to RSA-3072', values: { p: '991', q: '997', m: '123456', key: 'rsa3072', msg: 'the same formulas' } },
      { label: '53 and 71 next to RSA-2048', values: { p: '53', q: '71', m: '2020', key: 'rsa2048', msg: 'two thousand bits' } },
    ],
    counters: [{ id: 'rows', label: 'rows compared' }],
    run(inp) {
      return P.memo('p08-sizes', inp, () => {
        const p = BigInt(inp.p), q = BigInt(inp.q), phiT = (p - 1n) * (q - 1n);
        const eT = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n].find((e) => NT().gcd(e, phiT) === 1n);
        const T = S.RSA.fromPrimes(p > q ? p : q, p > q ? q : p, eT), R = P.rsaKey(inp.key);
        const mT = BigInt(inp.m), mR = NT().fromBytes(new TextEncoder().encode(inp.msg));
        const cT = S.RSA.encrypt(mT, T).value, cR = S.RSA.encrypt(mR, R).value;
        const dT = S.RSA.powLR(cT, T.d, T.n);
        // the real decryption by the CRT; the count of squarings and multiplications of c^d depends on d's bits alone,
        // so it is read from the same loop run on a small modulus
        const ops = S.RSA.powLR(cR % 1000003n, R.d, 1000003n), dR = { value: S.RSA.decryptCRT(cR, R).value, squarings: ops.squarings, multiplications: ops.multiplications };
        const name = inp.key.replace('rsa', 'RSA-'), maxBits = P.bits(R.n);
        const rows = [
          ['p', T.p, R.p, 'a prime'], ['q', T.q, R.q, 'a second prime'], ['n = p·q', T.n, R.n, 'the modulus'], ['φ(n)', T.phi, R.phi, '(p − 1)(q − 1)'],
          ['e', T.e, R.e, 'public exponent'], ['d', T.d, R.d, 'e⁻¹ mod φ(n)'], ['m', mT, mR, 'message'], ['c = m^e', cT, cR, 'ciphertext'], ['c^d', dT.value, dR.value, 'decrypted'],
        ];
        const F = new S.Frames(['rows']);
        const X1 = 120, W1 = 150, X2 = 290, BW = 190, X3 = 570, Y0 = 72, RH = 42;
        const pic = (upto, lit) => {
          const out = [P.title('h1', X1, 40, 'toy key'), P.title('h2', X2, 40, name + ': length to scale'), P.title('h3', X3, 40, 'value')];
          rows.slice(0, upto).forEach(([lab, tv, rv], i) => {
            const y = Y0 + i * RH, on = i === lit, ft = KP().fmt(rv, { max: 18 });
            out.push(P.t('l' + i, X1 - 12, y + 24, lab, on ? 'act' : 'strong', 'end', 15));
            out.push({ key: 't' + i, kind: 'cell', x: X1, y, w: W1, h: 34, rx: 5, text: tv.toString(), size: 15, cls: 'mono ' + (on ? 'act' : 'soft') });
            const bw = Math.max(3, P.r2((BW * P.bits(rv)) / maxBits));
            out.push({ key: 'b' + i, kind: 'cell', x: X2, y: y + 7, w: bw, h: 20, rx: 3, text: '', cls: on ? 'act' : 'key' });
            out.push(P.t('bb' + i, X2 + bw + 8, y + 22, P.bits(rv) + ' bits', 'tick', 'start', 13));
            out.push({ key: 'r' + i, kind: 'cell', x: X3, y, w: 270, h: 34, rx: 5, text: ft.text, size: 14, cls: 'mono ' + (on ? 'act' : '') + (ft.long ? ' pk-long' : ''), title: lab + ' = ' + ft.full + (ft.long ? ' (' + ft.digits + ' digits, ' + ft.bits + ' bits)' : '') });
          });
          return out;
        };
        const say = (i) => {
          const [lab, tv, rv, what] = rows[i], dt = P.digits(tv), dr = P.digits(rv);
          const extra = [
            `A toy prime of ${P.bits(tv)} bits against a real one of ${P.bits(rv)} bits: ${dt} digits against ${dr}.`,
            `q is chosen the same way. Real primes are drawn at random and tested with Miller–Rabin; toy ones you can check by trial division.`,
            `n = p·q: ${P.n(tv)} for the toy key, which anyone can factor in a moment, against ${dr} digits, which no one can.`,
            `φ(n) = (p − 1)(q − 1) = ${P.n(tv)} for the toy key. It is secret: from n and φ(n) the factors follow at once.`,
            `e = ${tv} for the toy key (the smallest choice coprime to φ(n)) and ${rv} for the real one, the usual choice: short, so encryption is fast.`,
            `d = e⁻¹ mod φ(n) = ${P.n(tv)} for the toy key; the real d has ${P.bits(rv)} bits, about as long as n.`,
            `The message: the number ${P.n(tv)} for the toy key, the text “${inp.msg}” (${P.bits(rv)} bits) for the real one.`,
            `c = m^e mod n: ${P.n(tv)} for the toy key, ${P.n(rv)} for the real one.`,
            `c^d mod n gives back ${P.n(tv)} and the text “${inp.msg}”: the same formula works at both sizes. The toy decryption took ${dT.squarings} squarings and ${dT.multiplications} multiplications; the real one took ${dR.squarings} squarings and ${dR.multiplications} multiplications on ${maxBits}-bit numbers.`,
          ][i];
          return { text: `${lab}, ${what}. ` + extra, facts: { tv, rv, dt, dr, bits: [P.bits(tv), P.bits(rv), P.bits(R.p), maxBits], msg: inp.msg, ops: [dT.squarings, dT.multiplications, dR.squarings, dR.multiplications] } };
        };
        F.add({ items: pic(0), say: `The same RSA formulas, twice: on the toy primes ${p} and ${q}, and on ${name}. Each row puts the toy number next to the real one, with the real number's length drawn to scale.`, facts: { p, q }, meta: { phase: 'start' } });
        rows.forEach((r, i) => { F.set('rows', i + 1); const s = say(i); F.add({ items: pic(i + 1, i), say: s.text, facts: s.facts, meta: { phase: 'row', i, ok: i === 8 ? dT.value === mT && dR.value === mR : true } }); });
        const fr = P.fix(F.list, { x: 0, y: 10, w: 860, h: 470 });
        for (const f of fr) f.narrowView = { x: 30, y: 20, w: 530, h: 460 };
        return { frames: fr, def: P.def('One scheme, two sizes', ['n = p·q,  φ(n) = (p − 1)(q − 1)', 'd = e⁻¹ mod φ(n)', 'c = m^e mod n,  m = c^d mod n', 'toy: checkable by hand, broken by hand', 'real: the same steps on numbers of 1024 to 3072 bits']) };
      });
    },
    predict: [
      { at: (f) => f.meta.phase === 'row' && f.meta.i === 4, pick: 'option', ask: 'How long will the real private exponent d be?', options: ['17 bits, like e', 'about half as long as n', 'about as long as n', 'longer than n'], answer: 'about as long as n', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'What changes between the toy key and a real key?', options: ['The formulas', 'Only the sizes of the numbers', 'The meaning of e', 'Nothing at all'], answer: 1, why: 'Key generation, encryption and decryption are the same steps; only the numbers grow.' },
      { q: 'Why can the toy key be broken by hand?', options: ['Its e is small', 'Its n can be factored by trial division', 'Its d is public', 'It cannot'], answer: 1, why: 'A four-digit n has a prime factor below 100: trying them takes a minute.' },
      { q: 'How long is d in a real key, typically?', options: ['17 bits', 'About as long as n', 'Twice as long as n', '64 bits'], answer: 1, why: 'd is the inverse of e modulo φ(n), a number about as large as n.' },
      { q: 'Decrypting with a 2048-bit d takes roughly how many modular multiplications?', options: ['17', 'about 3000', '2^2048', 'about 100'], answer: 1, why: 'About 2047 squarings plus a multiplication for each 1 bit, roughly 1000.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
