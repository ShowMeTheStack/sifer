// Part 13's shared piece: a protocol run from S.Proto (messages, checks and notes, with what each party knows after
// each one) turned into frames of a message-sequence chart (kit-msc.js) with a knowledge panel under each lifeline.
// The narration of each frame is the engine's own sentence for that step, with the bytes on the wire added.
(function (S) {
  'use strict';
  const U = S.P12, Q = (S.P13 = S.P13 || {});

  /**
   * res: a run's result; o: {order: [party ids], labels: {id: label}, check: [short texts, in order], note: [short
   * texts, in order], head, sub, bad(party, atom) -> true when that knowledge is a loss (the attacker holds a session
   * key), hl(step) -> definition lines, extra(step, i) -> more items, chartY, panelY, facts(step, i)}
   */
  Q.mscFrames = function (res, o) {
    o = o || {};
    const order = o.order || res.parties.map((p) => p.id);
    const parties = order.map((id) => { const p = res.parties.find((x) => x.id === id); return { id, label: (o.labels && o.labels[id]) || p.label, role: p.role === 'honest' ? '' : p.role }; });
    let nc = 0, nn = 0;
    const rows = res.steps.map((s) => {
      if (s.type === 'message') {
        const shown = s.as && s.as !== s.from ? s.from + ' as ' + s.as : '';
        return { type: 'msg', from: s.from, to: s.to, label: s.i + '. ' + (s.label || '') + (shown ? ' (' + shown + ')' : ''), term: o.term ? o.term(s) : s.content, cls: s.as !== s.from || s.intended !== s.to ? 'bad' : '', dashed: s.as !== s.from };
      }
      if (s.type === 'check') return { type: 'check', party: s.party, ok: s.ok, text: (typeof o.check === 'function' ? o.check(s, nc++) : o.check && o.check[nc++]) || (s.ok ? 'checked' : 'rejected') };
      return { type: 'note', text: (o.note && o.note[nn++]) || 'note' };
    });
    const W = 880, X = 20, chartY = o.chartY || 92, panelY = o.panelY || 488, ph = 660 - panelY - 8;
    const lane = W / parties.length;
    // what each party holds sealed (tickets it cannot open), from what it learned
    const sealed = Object.fromEntries(order.map((id) => [id, []]));
    const frames = [];
    let prevKnows = null;
    res.steps.forEach((s, i) => {
      if (s.type === 'message') for (const [id, got] of Object.entries(s.learned || {})) for (const g of got) if (/\(sealed\)$/.test(g) && sealed[id] && !sealed[id].includes(g)) sealed[id].push(g);
      const chart = S.Kit.msc.chart({ prefix: 'mc', x: X, w: W, y: chartY, parties, rows, cur: i, bottom: panelY - 10 });
      const items = [...U.head('mc:hd', o.head || res.title, o.sub)].concat(chart.items);
      for (const p of parties) {
        const known = s.knows[p.id] || [], was = prevKnows ? prevKnows[p.id] || [] : known;
        const chips = known.map((a) => ({ text: a, key: a, cls: [((s.keys && s.keys[p.id]) || []).includes(a) ? 'key' : '', !was.includes(a) ? 'new' : '', o.bad && o.bad(p.id, a) ? 'bad' : ''].filter(Boolean).join(' ') }));
        for (const g of sealed[p.id]) if (!known.includes(g.replace(/ \(sealed\)$/, '').replace(/^.*\}/, ''))) chips.push({ text: g.replace(/ \(sealed\)$/, ''), key: 'sealed:' + g, cls: 'sealed' });
        items.push(...S.Kit.msc.knowledge({ prefix: 'mk:' + p.id, x: chart.xOf(p.id) - lane / 2 + 6, y: panelY, w: lane - 12, h: ph, title: p.label + ' knows', chips }));
      }
      if (o.extra) items.push(...o.extra(s, i));
      const t = res.trace[i];
      let say = (t ? t.say : s.say).replace(/([^.!?…])$/, '$1.').replace(/[0-9a-f]{40,}/g, (h) => U.spaced(h));
      if (s.type === 'message' && s.wire && s.wire.some((w) => w.sealed)) {
        const w = s.wire.find((x) => x.sealed);
        say += ` On the wire it is ${w.bytes.length / 2} bytes of ChaCha20-Poly1305 ciphertext, ${U.short(w.bytes, 8)}: anyone can copy it, only a key holder can open it.`;
      }
      if (s.type === 'message' && s.values) { const vs = Object.entries(s.values).filter(([, v]) => typeof v === 'string' && /^[0-9a-f]{16,}/.test(v)); if (vs.length && !/On the wire/.test(say)) say += ` ${vs[0][0]} = ${U.short(vs[0][1], 8)}.`; }
      frames.push({ items, say, hl: { d: o.hl ? o.hl(s, i) : [] }, facts: Object.assign({ step: t ? t.say : '', wire: s.wire ? s.wire.map((w) => w.bytes) : null, wireLen: s.wire ? s.wire.map((w) => w.bytes.length / 2) : null, values: s.values || null }, o.facts ? o.facts(s, i) : {}), meta: { stage: s.type, i, step: s } });
      prevKnows = s.knows;
    });
    U.fix(frames);
    return frames;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
