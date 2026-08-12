// Part 1: Kerckhoffs' principle. The attacker knows the method, so only the key is secret: how many keys each
// cipher has, how long trying them all takes, and why a large key space is needed but not enough.
(function (S) {
  'use strict';
  const P = S.P1;
  const C = () => S.Classic, E = () => S.Enigma;

  /** log10 of a positive BigInt */
  const log10 = (n) => { const s = String(n); return s.length - 1 + Math.log10(Number('0.' + s.slice(0, 15)) * 10); };
  const YEAR = 365.25 * 86400;
  /** a time in seconds, given as its log10, in words */
  function duration(lg) {
    const sec = Math.pow(10, lg);
    if (lg < -3) return 'under a millisecond';
    if (sec < 1) return P.fmt(sec * 1000, 0) + ' ms';
    if (sec < 120) return P.fmt(sec, sec < 10 ? 1 : 0) + ' s';
    if (sec < 7200) return P.fmt(sec / 60, 0) + ' minutes';
    if (sec < 2 * 86400) return P.fmt(sec / 3600, 0) + ' hours';
    if (sec < 2 * YEAR) return P.fmt(sec / 86400, 0) + ' days';
    const ly = lg - Math.log10(YEAR);
    if (ly < 6) return P.big(Math.round(Math.pow(10, ly))) + ' years';
    return P.fmt(Math.pow(10, ly - Math.floor(ly)), 1) + ' × 10^' + Math.floor(ly) + ' years';
  }
  /** the ciphers and their key counts, each worked out from the engines' own key lists */
  function ciphers(vlen) {
    const enigmaOrders = E().bombe.orders().length, plugs10 = P.factorial(26) / (P.factorial(6) * P.factorial(10) * 1024n);
    return [
      { id: 'shift', name: 'shift', keys: BigInt(C().bruteShift('A').rows.length), how: 'the 26 keys are tried in a moment', broken: 'brute force', why: '26 values of k' },
      { id: 'affine', name: 'affine', keys: BigInt(C().affine.keys().length), how: 'all of them are tried in a moment', broken: 'brute force', why: '12 multipliers × 26 shifts' },
      { id: 'vig', name: 'Vigenère, key of ' + vlen, keys: 26n ** BigInt(vlen), how: '', broken: 'Kasiski and coincidences', why: '26^' + vlen },
      { id: 'enigma', name: 'Enigma I, 10 cables', keys: BigInt(enigmaOrders) * 17576n * 676n * plugs10, how: '', broken: 'cribs and the Bombe', why: enigmaOrders + ' rotor orders × 26³ starts × 26² rings × ' + P.sci(plugs10) + ' plugboards', plugs: plugs10, orders: enigmaOrders },
      { id: 'sub', name: 'substitution', keys: P.factorial(26), how: '', broken: 'frequency analysis', why: '26!' },
      { id: 'aes', name: 'AES-128', keys: 2n ** 128n, how: '', broken: 'no shortcut known', why: '2^128' },
    ];
  }
  const LX = 0, BX = 230, BW = 300, TOP = 140, RH = 52, MAXLG = 40, TX = BX + BW + 125;
  function chart(list, upto, rateLg, o) {
    o = o || {};
    const items = [];
    items.push({ key: 'k:pub', kind: 'state', x: 170, y: 46, w: 300, h: 64, lines: ['the method', 'public: the enemy knows it'], cls: 'block' , size: 15 });
    items.push({ key: 'k:sec', kind: 'state', x: 560, y: 46, w: 300, h: 64, lines: ['the key', 'secret, short, changeable'], cls: 'block key', size: 15 });
    items.push(P.title('c:h1', LX, TOP - 18, 'cipher'));
    items.push(P.title('c:h2', BX, TOP - 18, 'keys (log scale)'));
    items.push(P.title('c:h3', TX, TOP - 18, 'all keys at 10^' + rateLg + ' per second'));
    for (const d of [0, 10, 20, 30, 40]) items.push(P.text('c:tk' + d, BX + (BW * d) / MAXLG, TOP + list.length * RH + 14, '10^' + d, 'tick', 13, 'middle'));
    items.push({ key: 'c:axis', kind: 'line', x1: BX, y1: TOP + list.length * RH - 4, x2: BX + BW, y2: TOP + list.length * RH - 4, cls: 'faint' });
    list.forEach((c, i) => {
      if (i > upto) return;
      const y = TOP + i * RH, lg = log10(c.keys), cur = i === upto && !o.done;
      const bad = o.done && c.id !== 'aes', good = o.done && c.id === 'aes';
      items.push(P.text('c:n' + i, LX, y + 18, c.name, 'strong', 14));
      items.push(P.text('c:w' + i, LX, y + 36, o.done ? c.broken : c.why.length > 26 ? c.why.slice(0, 25) + '…' : c.why, o.done ? (good ? 'good' : 'bad') : 'tick', 13));
      items.push({ key: 'c:b' + i, kind: 'cell', x: BX, y: y + 6, w: Math.max(4, (BW * lg) / MAXLG), h: 24, rx: 3, text: '', cls: 'p1-bar ' + (good ? 'p1-best' : bad ? 'hot' : cur ? 'act' : 'key') });
      items.push(P.text('c:v' + i, BX + Math.max(4, (BW * lg) / MAXLG) + 8, y + 23, lg < 6 ? P.big(c.keys) : P.sci(c.keys), 'mono', 13));
      items.push(P.text('c:t' + i, TX, y + 23, duration(lg - rateLg), lg - rateLg > Math.log10(YEAR * 100) ? 'good' : 'mono', 14));
    });
    return items;
  }

  S.topic({
    id: 'p01-kerckhoffs', family: 'p01-basics', order: 50, title: 'Kerckhoffs\' principle and key spaces',
    blurb: 'Assume the enemy knows exactly how the cipher works; only the key is secret. Then the number of keys sets the price of brute force, though a big number alone does not make a cipher safe.',
    inputs: [
      { id: 'rate', kind: 'choice', label: 'Attacker\'s speed', def: '9', options: [{ value: '6', label: 'a million keys a second' }, { value: '9', label: 'a billion keys a second' }, { value: '12', label: 'a trillion keys a second' }] },
      { id: 'vlen', kind: 'number', label: 'Vigenère key length', def: 8, min: 1, max: 20 },
    ],
    presets: [
      { label: 'A laptop: 10^9 keys a second', values: { rate: '9', vlen: 8 } },
      { label: 'A large cluster: 10^12 a second', values: { rate: '12', vlen: 8 } },
      { label: 'A short Vigenère key of 3', values: { rate: '6', vlen: 3 } },
      { label: 'A Vigenère key of 20', values: { rate: '9', vlen: 20 } },
    ],
    run(inp) {
      const rate = +inp.rate, list = ciphers(inp.vlen), F = new S.Frames();
      F.add({ items: chart(list, -1, rate), say: 'Kerckhoffs\' principle: a cipher must stay secure even when the enemy knows everything about it except the key. Methods leak, machines are captured and programs are copied; a key is short and can be changed. So assume the method is public and ask how hard the key is to find.', meta: {} });
      list.forEach((c, i) => {
        const lg = log10(c.keys), t = duration(lg - rate);
        const count = lg < 6 ? P.big(c.keys) : 'about ' + P.sci(c.keys);
        let say;
        if (c.id === 'enigma') say = `Enigma I with 10 cables: ${c.orders} rotor orders, 26³ = 17,576 starting positions, 26² = 676 ring settings that matter and ${P.big(c.plugs)} ways to plug 10 cables, ${count} keys in all. Trying them all takes ${t}.`;
        else if (c.id === 'vig') say = `Vigenère with a key of ${inp.vlen} letter${inp.vlen === 1 ? '' : 's'}: 26^${inp.vlen} = ${lg < 15 ? P.big(c.keys) : count} keys, ${t} to try them all.`;
        else say = `${P.cap(c.name)}: ${count} keys (${c.why}). At 10^${rate} keys a second, trying every one takes ${t}.`;
        F.add({ items: chart(list, i, rate), say, meta: { cipher: c.id, lg } });
      });
      const sub = list.find((c) => c.id === 'sub'), en = list.find((c) => c.id === 'enigma');
      F.add({ items: chart(list, list.length - 1, rate, { done: true }), say: `Now the catch. Substitution has more keys (${P.sci(sub.keys)}) than Enigma (${P.sci(en.keys)}), far beyond brute force, yet a page of it falls to frequency analysis in minutes. Every cipher in red has a shortcut that ignores most of the keys. A large key space is necessary, but only a design with no shortcut makes brute force the best attack; for AES none is known.`, meta: { end: true } });
      return { frames: F.list, def: P.def('Kerckhoffs\' principle', ['assume the enemy knows the method;', 'security rests on the key alone', '', 'brute-force time = keys / rate', 'a big key space is needed,', 'but shortcuts must not exist']) };
    },
    predict: [
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.cipher === 'sub', pick: 'option', ask: 'Which has more keys: monoalphabetic substitution or Enigma I with 10 cables?', options: ['substitution', 'Enigma I', 'about the same'], answer: (fr, i) => { const s = fr[i + 1].meta.lg, e = fr.find((x) => x.meta && x.meta.cipher === 'enigma').meta.lg; return Math.abs(s - e) < 1 ? 'about the same' : s > e ? 'substitution' : 'Enigma I'; }, explain: (fr, i) => fr[i + 1].say },
      { at: (f, i, fr) => fr[i + 1] && fr[i + 1].meta.end, pick: 'option', ask: 'Which of these ciphers is safe from every attack we know?', options: ['substitution', 'Vigenère', 'Enigma I', 'AES-128'], answer: 'AES-128', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Kerckhoffs\' principle says a cipher should be secure even if…', options: ['the key is published', 'the enemy knows the method', 'the message is short', 'nobody uses it'], answer: 1, why: 'Only the key should need to stay secret.' },
      { q: 'Why is keeping the method secret a poor plan?', options: ['It is illegal', 'Methods are hard to change and tend to leak; a key can be replaced', 'Secret methods are slower', 'It makes keys longer'], answer: 1, why: 'Captured machines and copied programs reveal the method; a compromised key is simply changed.' },
      { q: 'Monoalphabetic substitution has about 4 × 10^26 keys. Why is it weak?', options: ['Brute force is fast', 'Frequency analysis finds the key without trying keys', 'The key is public', 'It only has 26 keys'], answer: 1, why: 'The shortcut ignores the key space entirely.' },
      { q: 'Doubling the attacker\'s speed changes the brute-force time of a 2^128 key space by…', options: ['nothing', 'a factor of 2', 'a factor of 2^128', 'it makes it feasible'], answer: 1, why: 'Time = keys / rate; each extra key bit doubles it back.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
