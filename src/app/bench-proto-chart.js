// The message-sequence chart of a protocol run: a column per party with its lifeline, a row per step (a message as
// an arrow with its number and name, a check as a badge on the party's line, a note as a band across), the step
// being looked at lit and the steps still to come faded. Drawn as plain SVG so the picture can be audited.
//   S.ProtoChart.draw(result, cursor, {onPick(i)}) -> svg element (its natural width in svg.dataset.w)
//   S.ProtoChart.kindOf(name, step, partyIds) -> 'key' | 'nonce' | 'time' | 'id' | 'secret' | 'data'
(function (S) {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const el = (tag, attrs, text) => { const e = document.createElementNS(NS, tag); for (const k in attrs || {}) if (attrs[k] !== undefined && attrs[k] !== null) e.setAttribute(k, attrs[k]); if (text !== undefined) e.textContent = text; return e; };
  const COL = 216, M = 24, HEAD = 56, TOP = 16, ROW = 62, NOTE = 46;
  const CH = 7.4; // the width of a character of 13px text, near enough to fit labels
  const fit = (s, w, px) => { const n = Math.max(4, Math.floor(w / (px || CH))); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
  const ROLE = { trusted: 'trusted server', attacker: 'attacker', eavesdropper: 'listening', honest: '' };

  const C = (S.ProtoChart = {});
  C.kindOf = (name, step, ids) => {
    if (step && step.keys && Object.values(step.keys).some((ks) => ks.includes(name))) return 'key';
    if (/^K/.test(name)) return 'key';
    if (ids && ids.includes(name)) return 'id';
    if (/^(N|J)[a-z′'0-9]|^N\d|−1$/.test(name)) return 'nonce';
    if (/^T\d|expiry|time/i.test(name)) return 'time';
    if (/password|secret|^[abm]$|^[abm] \(/.test(name)) return 'secret';
    return 'data';
  };

  C.draw = function (res, cursor, o) {
    o = o || {};
    // an attacker stands between the two it deceives, so its arrows are short and never cross another line
    const parties = res.parties.slice();
    const ai = parties.findIndex((p) => p.role === 'attacker');
    if (ai >= 0 && parties.length >= 3) { const [m] = parties.splice(ai, 1); parties.splice(Math.floor(parties.length / 2), 0, m); }
    const ids = parties.map((p) => p.id);
    const xOf = (id) => M + COL * (ids.indexOf(id) + 0.5);
    const W = M * 2 + COL * parties.length;
    let y = TOP + HEAD + 18;
    const rows = res.steps.map((s) => { const r = { y, h: s.type === 'note' ? NOTE : ROW }; y += r.h; return r; });
    const H = y + 18;
    const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, class: 'msc', role: 'img', 'aria-label': 'Message-sequence chart: ' + res.title, width: W, height: H });
    svg.dataset.w = String(W);
    const back = el('g', { 'data-audit': 'ignore' });
    svg.appendChild(back);
    // the step being looked at, behind everything
    if (cursor >= 0 && rows[cursor]) back.appendChild(el('rect', { x: 4, y: rows[cursor].y + 2, width: W - 8, height: rows[cursor].h - 4, rx: 10, class: 'msc-cur' }));
    // lifelines
    for (const p of parties) back.appendChild(el('line', { x1: xOf(p.id), y1: TOP + HEAD, x2: xOf(p.id), y2: H - 8, class: 'msc-life' + (p.role === 'attacker' || p.role === 'eavesdropper' ? ' bad' : '') }));
    // the parties
    for (const p of parties) {
      const g = el('g', { class: 'msc-party ' + (p.role || 'honest'), 'data-party': p.id });
      const x = xOf(p.id);
      g.appendChild(el('rect', { x: x - COL / 2 + 14, y: TOP, width: COL - 28, height: HEAD - 8, rx: 10, class: 'msc-pbox' }));
      const sub = ROLE[p.role] || '';
      g.appendChild(el('text', { x, y: TOP + (sub ? 20 : 29), 'text-anchor': 'middle', class: 'msc-pname' }, fit(p.label + (p.label !== p.id ? ' (' + p.id + ')' : ''), COL - 44, 8)));
      if (sub) g.appendChild(el('text', { x, y: TOP + 37, 'text-anchor': 'middle', class: 'msc-prole' }, sub));
      svg.appendChild(g);
    }
    const defs = el('defs');
    for (const k of ['n', 'cur', 'bad']) { const m = el('marker', { id: 'msc-ah-' + k, viewBox: '0 0 12 12', refX: '11', refY: '6', markerWidth: '11', markerHeight: '11', markerUnits: 'userSpaceOnUse', orient: 'auto' }); m.appendChild(el('path', { d: 'M1,1.5 L11,6 L1,10.5 L3.2,6 z', class: 'msc-head ' + k })); defs.appendChild(m); }
    svg.insertBefore(defs, svg.firstChild);
    let n = 0;
    res.steps.forEach((s, i) => {
      const r = rows[i], state = i === cursor ? 'cur' : i > cursor ? 'later' : 'past';
      const g = el('g', { class: 'msc-step ' + s.type + ' ' + state, 'data-step': String(i), tabindex: '-1' });
      if (o.onPick) g.addEventListener('click', () => o.onPick(i));
      if (s.type === 'message') {
        n++;
        const x1 = xOf(s.from), x2 = xOf(s.to), dir = x2 > x1 ? 1 : -1, ay = r.y + 32;
        const bad = s.as !== s.from || (s.intended && s.intended !== s.to);
        g.appendChild(el('line', { x1: x1 + dir * 4, y1: ay, x2: x2 - dir * 5, y2: ay, class: 'msc-arrow' + (bad ? ' bad' : ''), 'marker-end': `url(#msc-ah-${state === 'cur' ? 'cur' : bad ? 'bad' : 'n'})` }));
        const span = Math.abs(x2 - x1) - 28;
        g.appendChild(el('text', { x: (x1 + x2) / 2, y: ay - 9, 'text-anchor': 'middle', class: 'msc-label' }, fit(s.i + '. ' + (s.label || s.content), span)));
        const why = s.as !== s.from ? 'posing as ' + (parties.find((p) => p.id === s.as) || { label: s.as }).label : s.intended && s.intended !== s.to ? 'meant for ' + (parties.find((p) => p.id === s.intended) || { label: s.intended }).label : '';
        if (why) g.appendChild(el('text', { x: (x1 + x2) / 2, y: ay + 19, 'text-anchor': 'middle', class: 'msc-why' }, fit(why, span, 6.8)));
      } else if (s.type === 'check') {
        const x = xOf(s.party), w = 128;
        g.appendChild(el('rect', { x: x - w / 2, y: r.y + 15, width: w, height: 30, rx: 15, class: 'msc-badge ' + (s.ok ? 'ok' : 'no') }));
        g.appendChild(el('text', { x, y: r.y + 35, 'text-anchor': 'middle', class: 'msc-badge-t' }, (s.ok ? '✓ ' : '✗ ') + (s.ok ? 'accepts' : 'rejects')));
      } else {
        g.appendChild(el('rect', { x: 14, y: r.y + 8, width: W - 28, height: r.h - 16, rx: 8, class: 'msc-note' }));
        g.appendChild(el('text', { x: 26, y: r.y + r.h / 2 + 5, class: 'msc-note-t' }, fit(s.say || '', W - 56, 7)));
      }
      svg.appendChild(g);
    });
    void n;
    return svg;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
