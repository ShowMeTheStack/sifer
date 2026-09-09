// Part 12, the older hashes: one step of SHA-1 and one of MD5 on our own message (their registers, the sum each
// step forms and the rotation of the registers), how their sizes compare with SHA-256, and the timeline of the
// attacks that broke them, each event lit in turn with the table of what was broken by then.
(function (S) {
  'use strict';
  const U = S.P12, H = () => S.Hash;
  const { t, h8 } = U;
  const SHORT = { '1990MD4': 'MD4 published', '1992MD5': 'MD5, RFC 1321', '1993SHA-0': 'SHA-0 standard', '1995SHA-1': 'SHA-0 patched', '1996MD5': 'compression flaw', '2004MD5': 'first collision', '2005SHA-1': 'attack below 2^80', '2008MD5': 'rogue CA', '2012MD5': 'forged signing', '2015SHA-3': 'FIPS 202', '2017SHA-1': 'first collision', '2020SHA-1': 'chosen prefix', '2030SHA-1': 'SHA-1 retired' };
  // when collisions of each hash became public (from the timeline itself)
  const brokenIn = (hist, hash) => { const e = hist.find((x) => x.hash === hash && /first|collision is announced|first public|full MD5 collision/i.test(x.event) && !/compression function/.test(x.event)); return e ? e.year : null; };

  function older(inp) {
    const Hs = H(), msg = U.utf8(inp.msg), hist = Hs.HISTORY;
    const s1 = Hs.get('sha1').run(msg, { rounds: true }).blocks[0], m5 = Hs.get('md5').run(msg, { rounds: true }).blocks[0];
    const r1 = s1.rounds[0], iv1 = s1.cvIn, r5 = m5.rounds[0], iv5 = m5.cvIn;
    const d = { md5: U.hex(Hs.get('md5').hash(msg)), sha1: U.hex(Hs.get('sha1').hash(msg)), sha256: U.hex(Hs.get('sha256').hash(msg)) };
    const regRow = (pre, names, vals, y, x0, cls) => names.map((n, i) => U.val(pre + i, x0 + i * 150, y, 136, n, h8(vals[i]), cls ? cls(i) : ''));
    const terms = (pre, x, y, rows, total) => {
      const items = [];
      rows.forEach(([n, v, c], i) => { items.push(t(pre + 'n' + i, x, y + i * 26, n, c || 'ptick', 'start', 14)); items.push(t(pre + 'v' + i, x + 330, y + i * 26, h8(v), 'mono', 'end', 15)); });
      const yy = y + rows.length * 26 - 14;
      items.push({ key: pre + 'rule', kind: 'line', x1: x + 220, y1: yy, x2: x + 334, y2: yy, cls: 'rule' }, t(pre + 'plus', x + 206, y + (rows.length - 1) * 26, '+', 'strong', 'end', 15));
      items.push(t(pre + 'tn', x, yy + 22, total[0], 'hot', 'start', 15), t(pre + 'tv', x + 330, yy + 22, h8(total[1]), 'mono hot', 'end', 15));
      return items;
    };
    const F = new S.Frames(['events']);
    // SHA-1, step 0
    const sha1Items = [...U.head('ol:h', 'One step of SHA-1', 'five 32-bit registers, 80 steps, four Boolean functions'),
      t('ol:b', 30, 90, 'before step 0 (the IV)', 'ptitle'), ...regRow('ol:r', ['a', 'b', 'c', 'd', 'e'], iv1, 126, 90, (i) => (i === 0 || i === 4 ? 'src' : '')),
      ...terms('ol:t', 120, 214, [['a rotated left by 5', ((iv1[0] << 5) | (iv1[0] >>> 27)) >>> 0, 'src'], ['f(b, c, d) = ' + r1.fname, r1.f], ['e', iv1[4], 'src'], ['K₀', r1.K, 'key'], ['W₀', r1.W, 'key']], ['T', r1.temp]),
      t('ol:a', 30, 440, 'after step 0', 'ptitle'), ...regRow('ol:s', ['a = T', 'b = old a', 'c = old b <<< 30', 'd = old c', 'e = old d'], r1.regs, 476, 90, (i) => (i === 0 ? 'hot' : i === 2 ? 'act' : ''))];
    F.add({ items: sha1Items, hl: { d: [0] }, say: `SHA-1 keeps five registers. Step 0 on our message: T = (a <<< 5) + ${r1.fname}(b, c, d) + e + K₀ + W₀ = ${h8(r1.temp)}, which becomes the new a; b is rotated by 30 into c (${h8(r1.regs[2])}); the rest move along. 80 such steps, with a schedule that only XORs and rotates.`, facts: { T: h8(r1.temp), c: h8(r1.regs[2]), f: r1.fname, steps: 80 }, meta: { stage: 'sha1' } });
    // MD5, step 0
    const sum5 = (iv5[0] + r5.f + r5.K + r5.X) >>> 0;
    const md5Items = [...U.head('ol:h', 'One step of MD5', 'four 32-bit registers, 64 steps, little-endian words'),
      t('ol:b', 30, 90, 'before step 0 (the IV)', 'ptitle'), ...regRow('ol:r', ['a', 'b', 'c', 'd'], iv5, 126, 90, (i) => (i === 0 ? 'src' : '')),
      ...terms('ol:t', 120, 214, [['a', iv5[0], 'src'], ['F(b, c, d)', r5.f], ['K₀', r5.K, 'key'], ['X[' + r5.g + ']', r5.X, 'key']], ['sum', sum5]),
      t('ol:x', 480, 278, 'new b = b + (sum <<< ' + r5.s + ')', 'act', 'start', 15), t('ol:x2', 480, 306, '= ' + h8(r5.regs[1]), 'mono hot', 'start', 15),
      t('ol:a', 30, 440, 'after step 0', 'ptitle'), ...regRow('ol:s', ['a = old d', 'b = new', 'c = old b', 'd = old c'], r5.regs, 476, 90, (i) => (i === 1 ? 'hot' : ''))];
    F.add({ items: md5Items, hl: { d: [1] }, say: `MD5 keeps four registers and reads the block as little-endian words. Step 0: a + F(b, c, d) + K₀ + X[${r5.g}] = ${h8(sum5)}, rotated left by ${r5.s} and added to b: the new b is ${h8(r5.regs[1])}, and the registers rotate. 64 steps make one compression.`, facts: { sum: h8(sum5), b: h8(r5.regs[1]), s: r5.s, g: r5.g, steps: 64 }, meta: { stage: 'md5' } });
    // the table and the timeline
    const X = (y) => U.r2(60 + ((y - 1990) / 40) * 800), yAx = 420;
    const order = hist.map((e, i) => i);
    const slots = (side) => order.filter((i) => i % 2 === (side === 'up' ? 0 : 1));
    const slotX = (i) => { const side = i % 2 === 0 ? 'up' : 'down', list = slots(side), j = list.indexOf(i), n = list.length; return U.r2(side === 'up' ? 70 + j * 130 : 135 + j * 130); };
    const timeline = (cur) => {
      const items = [{ key: 'tl:ax', kind: 'path', d: `M40,${yAx} H890`, cls: 'p12-axis', audit: 'ignore' }];
      for (let y = 1990; y <= 2030; y += 10) items.push({ key: 'tl:y' + y, kind: 'path', d: `M${X(y)},${yAx - 5} V${yAx + 5}`, cls: 'p12-stem', audit: 'ignore' });
      hist.forEach((e, i) => {
        const up = i % 2 === 0, sx = slotX(i), ly = up ? yAx - 96 : yAx + 44, on = i === cur, past = i < cur;
        const bad = /collision|forged|rogue|flaw|2\^/.test(e.event) && e.hash !== 'SHA-3';
        items.push({ key: 'tl:s' + i, kind: 'path', d: `M${X(e.year)},${yAx + (up ? -6 : 6)} L${sx},${up ? ly + 42 : ly}`, cls: 'p12-stem' + (on ? ' act' : ''), audit: 'ignore' });
        items.push({ key: 'tl:d' + i, kind: 'dot', x: X(e.year), y: yAx, r: on ? 7 : 5, cls: on ? 'hot' : past && bad ? 'bad' : past ? 'act' : '' });
        items.push({ key: 'tl:l' + i, kind: 'cell', x: U.r2(sx - 62), y: ly, w: 124, h: 42, rx: 6, lines: [String(e.year) + ' · ' + e.hash, SHORT[e.year + e.hash] || e.hash], size: 13, cls: on ? 'hot' : past ? (bad ? 'bad' : 'act') : 'soft' });
      });
      if (cur >= 0) {
        const words = hist[cur].event.split(' '), lines = [''];
        for (const w of words) { if ((lines[lines.length - 1] + ' ' + w).length > 92) lines.push(''); lines[lines.length - 1] += (lines[lines.length - 1] ? ' ' : '') + w; }
        items.push(...U.panel('tl:ev', 20, 548, 880, 40 + 22 * lines.length, hist[cur].year + ', ' + hist[cur].hash, 'hot'));
        lines.forEach((l, k) => items.push(t('tl:et' + k, 34, 596 + 22 * k, l, '', 'start', 14)));
      }
      return items;
    };
    const table = (year) => {
      const rows = [['MD5', 128, 64, 'md5', brokenIn(hist, 'MD5')], ['SHA-1', 160, 80, 'sha1', brokenIn(hist, 'SHA-1')], ['SHA-256', 256, 128, 'sha256', null]];
      const items = [t('tb:t', 30, 84, 'the three hashes as of ' + year, 'ptitle')];
      const cols = [['hash', 30], ['digest', 128], ['birthday bound', 220], ['collisions', 360], ['digest of our message', 480]];
      cols.forEach(([n, x], j) => items.push(t('tb:h' + j, x, 112, n, 'ptick', 'start', 13)));
      rows.forEach(([n, bits, half, k, br], i) => {
        const y = 140 + i * 40, broken = br && br <= year;
        items.push(t('tb:n' + i, 30, y, n, 'strong', 'start', 15), t('tb:b' + i, 128, y, bits + ' bits', 'mono', 'start', 14), t('tb:bb' + i, 220, y, '2^' + half + ' work', 'mono', 'start', 14));
        items.push(t('tb:c' + i, 360, y, broken ? 'found ' + br : 'none known', broken ? 'bad' : 'good', 'start', 14));
        items.push(t('tb:d' + i, 480, y, U.short(d[k], 20), 'mono', 'start', 13));
      });
      return items;
    };
    hist.forEach((e, i) => {
      F.count('events');
      F.add({ items: [...U.head('ol:h', 'How MD5 and SHA-1 fell'), ...table(e.year), ...timeline(i)], hl: { d: [2] }, say: `${e.year}, ${e.hash}: ${e.event}`, facts: { year: e.year, event: e.event }, meta: { stage: 'event', i } });
    });
    F.add({ items: [...U.head('ol:h', 'How MD5 and SHA-1 fell'), ...table(2030), ...timeline(-1)], hl: { d: [2, 3] }, say: `The pattern: a theoretical crack, then a practical collision about ten years later, then a chosen-prefix collision that forges real certificates. SHA-256 of our message, ${U.short(d.sha256, 8)}, still has no known collision; SHA-3 waits as a design with nothing in common.`, facts: { d256: d.sha256 }, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('SHA-1 and MD5', ['SHA-1: 160 bits, 5 registers, 80 steps; T = (a <<< 5) + f(b,c,d) + e + K + Wₜ', 'MD5: 128 bits, 4 registers, 64 steps; b ← b + ((a + F(b,c,d) + Kᵢ + X[g]) <<< s)', 'birthday bound: 2⁸⁰ for SHA-1, 2⁶⁴ for MD5', 'a collision attack is a break when it beats the birthday bound']) };
  }
  S.topic({
    id: 'p12-older', family: 'p12-old', order: 10, title: 'SHA-1, MD5 and the story of broken hashes',
    blurb: 'One step of each of the two hashes the world ran on, then the timeline: compression-function cracks, the first real collisions, and forged certificates built from chosen-prefix collisions.',
    inputs: [{ id: 'msg', kind: 'text', label: 'Message', def: 'Sifer hashes this line, one round at a time.', check: (v) => (U.utf8(v).length > 55 ? 'Message: at most 55 bytes (one block)' : null) }],
    presets: [
      { label: 'Our line', values: { msg: 'Sifer hashes this line, one round at a time.' } },
      { label: 'The empty message', values: { msg: '' } },
      { label: 'A short word', values: { msg: 'ledger' } },
    ],
    counters: [{ id: 'events', label: 'events' }],
    run: older,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'event' && f.meta.i === 4, pick: 'option', options: ['within a year', 'about eight years later', 'never'], ask: 'MD5\'s compression function has just been cracked. When will a full MD5 collision appear?', answer: 'about eight years later', explain: 'The first full MD5 collision was announced in 2004.' },
    ],
    quiz: [
      { q: 'What is the birthday bound for SHA-1 collisions?', options: ['2^160', '2^80', '2^69', '2^63'], answer: 1, why: 'Half of the 160-bit digest.' },
      { q: 'Why did a 2005 attack at about 2^69 count as breaking SHA-1?', options: ['it found a collision that year', 'it beat the 2^80 birthday bound, so SHA-1 fell short of its design strength', 'it recovered keys', 'it found preimages'], answer: 1, why: 'Any attack faster than the generic bound is a break, even before a collision is shown.' },
      { q: 'What made MD5 collisions dangerous for certificates?', options: ['they leak private keys', 'a chosen-prefix collision lets a harmless request and a CA certificate share a digest, so one signature covers both', 'they make RSA slower', 'they break TLS encryption'], answer: 1, why: 'The CA signs the digest of the harmless request; the same signature validates the rogue certificate.' },
      { q: 'How many registers does MD5 keep?', options: ['4', '5', '8', '16'], answer: 0, why: 'a, b, c, d: 128 bits of state.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
