// The plugboard at the front of the deck: 26 sockets in the keyboard's three rows, and cables you drag from socket to
// socket. A cable falls from the bottom of its socket through the gaps between the sockets below and hangs under the
// board in a curve that sags more the wider it spans, with a shadow and its own shade of cloth, so cables that cross
// read as cables lying over one another. Pressing a plugged socket picks its cable up; drop it on a free socket to
// move it, or anywhere else to pull it out.
//   S.EnigmaPlug.draw(g, {y0, pairs, onChange(pairsText)}) -> {set(pairs), height}
(function (S) {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const el = (tag, a, text) => { const e = document.createElementNS(NS, tag); for (const k in a || {}) if (a[k] !== undefined && a[k] !== null) e.setAttribute(k, a[k]); if (text !== undefined) e.textContent = text; return e; };
  const ROWS = ['QWERTZUIO', 'ASDFGHJK', 'PYXCVBNML'];
  const P = 76, X0 = 196, SW = 36, SH = 24;
  const PL = (S.EnigmaPlug = { ROWS, P, X0 });

  /** the centre of a letter's key, lamp or socket in a row layout */
  PL.at = (L) => { for (let r = 0; r < 3; r++) { const i = ROWS[r].indexOf(L); if (i >= 0) return { r, i, x: X0 + (r === 1 ? P / 2 : 0) + i * P }; } return null; };

  PL.draw = function (g, o) {
    const y0 = o.y0, rowY = [y0 + 50, y0 + 122, y0 + 194], tray = y0 + 222;
    const sockets = {};
    const cables = el('g', { class: 'pb-cables' });
    const sockG = el('g', { class: 'pb-sockets' });
    g.append(sockG, cables);
    for (const row of ROWS) for (const L of row) {
      const a = PL.at(L), x = a.x, y = rowY[a.r];
      const s = el('g', { class: 'pb-socket', 'data-letter': L, tabindex: '0', role: 'button', 'aria-label': 'Socket ' + L });
      const box = el('rect', { x: x - SW / 2, y: y - SH / 2, width: SW, height: SH, rx: 5, class: 'pb-box' });
      s.append(el('text', { x, y: y - SH / 2 - 8, class: 'pb-lab', 'text-anchor': 'middle' }, L), box,
        el('circle', { cx: x - 8, cy: y, r: 3.6, class: 'pb-hole' }), el('circle', { cx: x + 8, cy: y, r: 3.6, class: 'pb-hole' }));
      // a larger invisible target for fingers
      s.appendChild(el('rect', { x: x - P / 2 + 4, y: y - SH / 2 - 26, width: P - 8, height: SH + 40, class: 'pb-hit', 'data-audit': 'ignore' }));
      sockG.appendChild(s);
      sockets[L] = { x, y, r: a.r, g: s };
    }
    let pairs = [];
    // Each cable is one smooth path: from the bottom of its socket it falls through the gap between the sockets
    // below (a top-row cable eases sideways, in an S, between the second and third rows, since a third-row socket
    // stands under it), and under the board the two ends are joined by a cubic that sags in proportion to its span.
    const YB = rowY[2] + SH / 2 + 10;
    const f = (v) => v.toFixed(1);
    const drop = (L, toward) => {
      const s = sockets[L], bot = s.y + SH / 2;
      if (s.r !== 0) return { x: s.x, d: [[s.x, bot], [s.x, YB]] };
      const ya = rowY[1] + SH / 2 + 4, yb = rowY[2] - SH / 2 - 32, x2 = s.x + (toward < s.x ? -1 : 1) * (P / 2 + 9), m = (ya + yb) / 2;
      return { x: x2, d: [[s.x, bot], [s.x, ya], [s.x, m, x2, m, x2, yb], [x2, YB]] };
    };
    const seg = (pts) => pts.map((q) => (q.length === 2 ? ' L' + f(q[0]) + ',' + f(q[1]) : ' C' + f(q[0]) + ',' + f(q[1]) + ' ' + f(q[2]) + ',' + f(q[3]) + ' ' + f(q[4]) + ',' + f(q[5]))).join('');
    const SHADES = ['#c8b48a', '#bfa97c', '#d2bf96', '#b9a275', '#cdb68c', '#c3ad82'];
    const draw = () => {
      cables.innerHTML = '';
      for (const s of Object.values(sockets)) s.g.classList.remove('plugged');
      // short cables are drawn last, over the long ones that hang deeper
      const order = pairs.slice().sort((p, q) => Math.abs(sockets[q[0]].x - sockets[q[1]].x) - Math.abs(sockets[p[0]].x - sockets[p[1]].x));
      order.forEach(([a, b], k) => {
        const A = drop(a, sockets[b].x), B = drop(b, sockets[a].x);
        const span = Math.abs(A.x - B.x), sag = Math.min(150, 22 + span * 0.21 + (k % 3) * 4);
        // the path back up the second drop, its curves reversed
        let up = '';
        for (let i = B.d.length - 1; i > 0; i--) {
          const q = B.d[i], prev = B.d[i - 1];
          if (q.length === 2) up += ' L' + f(prev[prev.length - 2]) + ',' + f(prev[prev.length - 1]);
          else up += ' C' + f(q[2]) + ',' + f(q[3]) + ' ' + f(q[0]) + ',' + f(q[1]) + ' ' + f(prev[prev.length - 2]) + ',' + f(prev[prev.length - 1]);
        }
        const d = 'M' + f(A.d[0][0]) + ',' + f(A.d[0][1]) + seg(A.d.slice(1)) + ' C' + f(A.x) + ',' + f(YB + sag) + ' ' + f(B.x) + ',' + f(YB + sag) + ' ' + f(B.x) + ',' + f(YB) + up;
        const c = el('g', { class: 'pb-cable', 'data-pair': a + b });
        c.append(el('path', { d, class: 'pb-shadow', transform: 'translate(2.5 3.5)', 'data-audit': 'ignore' }),
          el('path', { d, class: 'pb-wire', style: 'stroke:' + SHADES[(a.charCodeAt(0) + b.charCodeAt(0)) % SHADES.length], 'data-audit': 'edge-x' }),
          el('path', { d, class: 'pb-shine', 'data-audit': 'ignore' }));
        cables.appendChild(c);
        sockets[a].g.classList.add('plugged'); sockets[b].g.classList.add('plugged');
      });
    };
    const set = (ps) => { pairs = (ps || []).map((p) => [p[0], p[1]]); draw(); };
    set(o.pairs);
    const changed = () => { draw(); if (o.onChange) o.onChange(pairs.map((p) => p.join('')).join(' ')); };

    // dragging a cable: from a free socket, a new one; from a plugged socket, its cable comes out and moves
    const svg = () => g.ownerSVGElement;
    let drag = null;
    const toLocal = (e) => { const p = svg().createSVGPoint(); p.x = e.clientX; p.y = e.clientY; return p.matrixTransform(g.getScreenCTM().inverse()); };
    const socketAt = (e) => { const t = document.elementFromPoint(e.clientX, e.clientY); const s = t && t.closest && t.closest('.pb-socket'); return s ? s.dataset.letter : null; };
    sockG.addEventListener('pointerdown', (e) => {
      const s = e.target.closest('.pb-socket');
      if (!s) return;
      e.preventDefault();
      let from = s.dataset.letter;
      const had = pairs.find((p) => p.includes(from));
      if (had) { pairs = pairs.filter((p) => p !== had); from = had[0] === from ? had[1] : had[0]; draw(); }
      else if (pairs.length >= 13) { if (S.UI.toast) S.UI.toast('Enigma I has at most 13 cables.', 'err'); return; }
      const line = el('line', { x1: sockets[from].x, y1: sockets[from].y, x2: sockets[from].x, y2: sockets[from].y, class: 'pb-drag', 'data-audit': 'ignore' });
      g.appendChild(line);
      sockets[from].g.classList.add('lifted');
      drag = { from, line, moved: false, start: s.dataset.letter, had: !!had };
      try { svg().setPointerCapture(e.pointerId); } catch (x) { /* fine */ }
      const move = (ev) => { if (!drag) return; const p = toLocal(ev); line.setAttribute('x2', p.x); line.setAttribute('y2', p.y); drag.moved = true; const t = socketAt(ev); for (const k in sockets) sockets[k].g.classList.toggle('target', k === t && k !== drag.from && !pairs.some((q) => q.includes(k))); };
      const up = (ev) => {
        svg().removeEventListener('pointermove', move); svg().removeEventListener('pointerup', up); svg().removeEventListener('pointercancel', up);
        if (!drag) return;
        const t = socketAt(ev), d = drag; drag = null;
        line.remove();
        for (const k in sockets) sockets[k].g.classList.remove('target', 'lifted');
        if (t && t !== d.from && !pairs.some((q) => q.includes(t))) { pairs.push([d.from, t].sort()); if (S.EnigmaSound) S.EnigmaSound.click(); }
        changed();
      };
      svg().addEventListener('pointermove', move); svg().addEventListener('pointerup', up); svg().addEventListener('pointercancel', up);
    });
    // the keyboard: Enter on a socket starts a cable, Enter on another finishes it; on a plugged one, pulls it out
    let pick = null;
    sockG.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const s = e.target.closest('.pb-socket'); if (!s) return;
      e.preventDefault(); e.stopPropagation();
      const L = s.dataset.letter, had = pairs.find((p) => p.includes(L));
      if (had) { pairs = pairs.filter((p) => p !== had); pick = null; changed(); return; }
      if (!pick) { pick = L; s.classList.add('lifted'); return; }
      sockets[pick].g.classList.remove('lifted');
      if (pick !== L && pairs.length < 13) pairs.push([pick, L].sort());
      pick = null; changed();
    });
    return { set, height: tray + 13 * 6 + 14 - y0, sockets };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
