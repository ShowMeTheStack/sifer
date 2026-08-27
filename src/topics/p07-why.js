// Part 7, why public keys: the key-distribution problem with n people (a secret key for every pair, a key centre that
// must be trusted and online, or one key pair each with the public halves on a board anyone can read), and trapdoor
// one-way functions (easy forwards, hard backwards, easy again for whoever holds the trapdoor).
(function (S) {
  'use strict';
  const P = S.PK;
  const NAMES = ['Ana', 'Bo', 'Cai', 'Dev', 'Eli', 'Fay', 'Gus', 'Hal', 'Ivy', 'Jo', 'Kit', 'Lu'];
  const pairs = (n) => (n * (n - 1)) / 2;
  const big = (n) => { n = BigInt(n); return n * (n - 1n) / 2n; };
  const fmt = (v) => BigInt(v).toLocaleString('en-US');

  // ---------------------------------------------------------------------------------------------------------------
  // The key-distribution problem
  // ---------------------------------------------------------------------------------------------------------------
  S.topic({
    id: 'p07-keydist', family: 'p07-why', order: 10, title: 'The key-distribution problem',
    blurb: 'With symmetric keys alone, every pair of people needs its own secret key, delivered in secret: n(n − 1)/2 keys for n people. A key centre cuts that to n but must be trusted with everything. Public keys need one key pair each, and the public halves need no secrecy at all.',
    inputs: [
      { id: 'n', kind: 'number', label: 'People n', def: 6, min: 2, max: 12 },
      { id: 'big', kind: 'number', label: 'And for a group of', def: 1000, min: 13, max: 1e9 },
    ],
    presets: [
      { label: 'Six people', values: { n: 6, big: 1000 } },
      { label: 'Two people: one key', values: { n: 2, big: 100 } },
      { label: 'Twelve people', values: { n: 12, big: 1000000 } },
      { label: 'A company of 50,000', values: { n: 8, big: 50000 } },
      { label: 'A billion people online', values: { n: 10, big: 1000000000 } },
    ],
    counters: [{ id: 'keys', label: 'secret keys delivered' }, { id: 'stored', label: 'keys each person keeps' }],
    run(inp) {
      const n = inp.n, N = inp.big;
      const F = new S.Frames(['keys', 'stored']);
      const cx = 210, cy = 270, R = 170, view = { x: -50, y: 40, w: 890, h: 470 };
      const ang = (i) => (2 * Math.PI * i) / n - Math.PI / 2;
      const at = (i, r) => ({ x: P.r2(cx + (r || R) * Math.cos(ang(i))), y: P.r2(cy + (r || R) * Math.sin(ang(i))) });
      // a chord between two people must pass clear of the one between them
      const rr = P.r2(Math.min(23, R * (1 - Math.cos((2 * Math.PI) / n)) - 4));
      const people = (cls, sk) => {
        const out = [];
        for (let i = 0; i < n; i++) {
          const p = at(i), l = at(i, R + 44), c = Math.cos(ang(i));
          out.push({ key: 'p' + i, kind: 'state', x: p.x, y: p.y, r: rr, text: NAMES[i][0], cls: 'pk-party ' + (cls ? cls(i) || '' : '') });
          out.push(P.t('n' + i, l.x, l.y + 5, NAMES[i], 'strong', Math.abs(c) < 0.3 ? 'middle' : c > 0 ? 'start' : 'end', 15));
          if (sk) { const q = at(i, R - 56); out.push({ key: 'sk' + i, kind: 'cell', x: P.r2(q.x - 21), y: P.r2(q.y - 13), w: 42, h: 26, rx: 5, text: 'sk' + P.sub(i + 1), size: 13, cls: 'mono key' }); }
        }
        return out;
      };
      const pairEdges = (upto, lit) => {
        const out = [];
        for (let j = 1; j < upto; j++) for (let i = 0; i < j; i++) out.push({ key: 'e' + i + '-' + j, kind: 'edge', from: 'p' + i, to: 'p' + j, head: false, cls: j === lit ? 'key' : 'faint', audit: 'edge-x', layer: 'edges' });
        return out;
      };
      const right = 450;
      const say = (s, facts, items, meta) => F.add({ items, say: s, facts, meta: meta || {} });
      const head = (t) => [P.title('h', right, 60, t)];

      say(`${n} people want to talk in pairs, each conversation kept secret from ${n > 2 ? 'the other ' + (n - 2) : 'everyone else'}. With a symmetric cipher every pair needs its own secret key, and that key must reach both of them by a secret route first.`,
        { n, others: n - 2 }, [...people(), ...head('Symmetric keys only')], { phase: 'start' });
      for (let k = 2; k <= n; k++) {
        const total = pairs(k);
        F.set('keys', total).set('stored', k - 1);
        const items = [...pairEdges(k, k - 1), ...people((i) => (i === k - 1 ? 'hot' : i < k - 1 ? 'key' : 'soft')), ...head('Symmetric keys only'),
          ...P.eqs('q', right, 110, [[`${NAMES[k - 1]} joins: ${P.plural(k - 1, 'new key')}`, 'key'], [`keys so far: ${fmt(total)}`, 'strong']], 17)];
        say(k === 2 ? `${NAMES[0]} and ${NAMES[1]} meet and agree one secret key, carried by hand or by a courier they trust: 1 key.` : `${NAMES[k - 1]} joins and needs a separate key with each of the ${k - 1} people already here, each one delivered in secret: ${k - 1} new keys, ${fmt(total)} in all.`,
          { k, added: k - 1, total }, items, { phase: 'join', k, total });
      }
      const all = pairs(n);
      const eqs = [[`n(n − 1)/2 = ${n}·${n - 1}/2 = ${all}`, 'strong'], [`each person keeps n − 1 = ${n - 1}`], [`a newcomer adds n = ${n} more`]];
      say(`For n = ${n} people that is n(n − 1)/2 = ${all} secret keys, each delivered in secret, and every person keeps ${n - 1} of them. The number grows with the square of n: one more person would add ${n} more keys.`,
        { n, all, keep: n - 1, next: n }, [...pairEdges(n), ...people(() => 'key'), ...head('Symmetric keys only'), ...P.eqs('q', right, 110, eqs, 17)], { phase: 'all', all });
      // the key centre
      F.set('keys', n).set('stored', 1);
      const centre = [{ key: 'kdc', kind: 'state', x: cx, y: cy, w: 76, h: 46, rx: 8, text: 'centre', cls: 'block key' }];
      const spokes = []; for (let i = 0; i < n; i++) spokes.push({ key: 's' + i, kind: 'edge', from: 'kdc', to: 'p' + i, head: false, cls: 'key', layer: 'edges' });
      say(`A key centre helps: each person shares one long-term key with the centre, ${n} keys in all, and the centre hands out a fresh key whenever two people want to talk. But the centre knows every key, must be online for every new conversation, and is one place to attack.`,
        { n }, [...spokes, ...centre, ...people(() => 'key'), ...head('A trusted key centre'), ...P.eqs('q', right, 110, [[`keys delivered in secret: n = ${n}`, 'strong'], ['the centre can read everything', 'bad'], ['and must be online every time', 'bad']], 17)], { phase: 'kdc' });
      // public keys
      F.set('keys', 0).set('stored', 1);
      const board = [{ key: 'board', kind: 'region', x: right, y: 150, w: 370, h: 34 + Math.ceil(n / 2) * 40, rx: 10, cls: 'panel' }, P.t('board:t', right + 14, 172, 'public directory: anyone may read it', 'title')];
      for (let i = 0; i < n; i++) board.push({ key: 'pk' + i, kind: 'cell', x: right + 14 + (i % 2) * 172, y: 186 + Math.floor(i / 2) * 40, w: 160, h: 32, rx: 5, text: NAMES[i] + ': pk' + P.sub(i + 1), cls: 'mono good' });
      say(`Public keys: each person makes one key pair alone. The private half (sk) never leaves its owner; the public half (pk) goes on a directory anyone may read. ${n} key pairs, and not one secret had to be delivered: to write to ${NAMES[n - 1]}, look up ${NAMES[n - 1]}'s public key.`,
        { n }, [...people(() => 'alice', true), ...head('Public keys'), ...P.eqs('q', right, 110, [[`key pairs: n = ${n}, secrets delivered: 0`, 'good']], 17), ...board], { phase: 'public' });
      // the scale
      const lines = [[`${fmt(n)} people`, 'strong'], [`pairwise keys: ${fmt(pairs(n))}`, 'key'], [`key pairs: ${fmt(n)}`, 'good'], ['', ''], [`${fmt(N)} people`, 'strong'], [`pairwise keys: ${fmt(big(N))}`, 'key'], [`key pairs: ${fmt(N)}`, 'good']];
      const digits = big(N).toString().length;
      say(`At scale the difference is everything. For ${fmt(N)} people, pairwise secret keys number ${fmt(big(N))}, ${P.an(digits)}-digit count; key pairs number ${fmt(N)}. The public halves must still be the right ones: binding a public key to a person is the job of certificates.`,
        { n, N, pairsN: big(N), pairsn: pairs(n), digits }, [...people(() => 'alice'), ...head('How it grows'), ...P.eqs('q', right, 110, lines, 17)], { phase: 'scale' });
      const circle = { x: -50, y: 40, w: 500, h: 470 }, panel = { x: right - 20, y: 40, w: 420, h: 400 };
      for (const f of F.list) f.narrowView = /^(public|scale)$/.test(f.meta.phase) ? panel : circle;
      return { frames: P.fix(F.list, view), def: P.def('Keys for n people', ['symmetric, every pair: n(n − 1)/2 keys, all delivered in secret', 'each person keeps n − 1 keys', 'key centre: n keys, but it knows them all', 'public keys: n key pairs, 0 secrets delivered', 'a public key must still be authentic (certificates)']) };
    },
    predict: [
      { at: (f, i, fr) => f.meta.phase === 'join' && fr[i + 1] && fr[i + 1].meta.phase === 'join' && f.meta.k === 3, pick: 'option', ask: (fr, i) => `${NAMES[3]} joins next. How many keys will there be in all?`, options: (fr, i) => { const t = fr[i + 1].meta.total; return [String(t - 2), String(t - 1), String(t), String(t + 3)]; }, answer: (fr, i) => String(fr[i + 1].meta.total), explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.phase === 'all' && f.meta.phase !== 'all', once: true, pick: 'option', ask: (fr, i) => `How many secret keys for all ${fr[i + 1].facts.n} people?`, options: (fr, i) => { const n = fr[i + 1].facts.n; return [...new Set([String(n), String(n * (n - 1) / 2), String(n * (n - 1)), String(n * n)])]; }, answer: (fr, i) => String(fr[i + 1].facts.all), explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'How many pairwise secret keys do 10 people need?', options: ['10', '20', '45', '100'], answer: 2, why: '10·9/2 = 45: one for every pair.' },
      { q: 'With public keys, how many secrets must be delivered before 10 people can write to each other?', options: ['0', '10', '45', '90'], answer: 0, why: 'Each person makes a key pair alone; only public halves are shared, and they need no secrecy.' },
      { q: 'What is the weakness of a key centre?', options: ['It needs n² keys', 'It knows every key and must be online', 'It cannot handle new people', 'It only works for two people'], answer: 1, why: 'The centre hands out every session key, so it can read everything, and nobody can start a conversation without it.' },
      { q: 'What must still be checked about a public key?', options: ['That it is secret', 'That it belongs to the person it claims to', 'That it is shorter than the private key', 'Nothing'], answer: 1, why: 'A public key needs no secrecy but it needs authenticity; otherwise an attacker can substitute their own (certificates solve this).' },
      { q: 'One more person joins a group of n using pairwise keys. How many new keys?', options: ['1', 'n', 'n²', '2n'], answer: 1, why: 'The newcomer needs a key with each of the n people already there.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
