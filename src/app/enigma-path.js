// The Signal path view: the machine unrolled from left to right, reflector, left, middle and right rotors, entry wheel,
// plugboard and keys, with the 26 contacts of the housing as rows. Each rotor shows its own wiring at its present
// position, faintly; on every key press the current is drawn over it, forward in orange from the key to the reflector
// and back in blue to the lamp, and the narration names every contact it passes.
(function (S) {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const { h } = S.UI;
  const el = (tag, a, text) => { const e = document.createElementNS(NS, tag); for (const k in a || {}) if (a[k] !== undefined && a[k] !== null) e.setAttribute(k, a[k]); if (text !== undefined) e.textContent = text; return e; };
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const md = (n) => ((n % 26) + 26) % 26;
  const Y0 = 104, RY = 22, BOT = Y0 + 25 * RY;
  const y = (i) => Y0 + i * RY;
  // column boxes: [x1, x2]
  const COL = { UKW: [30, 100], L: [170, 300], M: [360, 490], R: [550, 680], ETW: [740, 780], PB: [830, 880] };
  const KEY_X = 930;

  function wiringPath(x1, x2, a, b) { const m = (x1 + x2) / 2; return `M${x2},${y(a)} C${m},${y(a)} ${m},${y(b)} ${x1},${y(b)}`; }

  function draw(host, st, press) {
    const m = S.Enigma.machine({ order: st.order, reflector: st.reflector, rings: st.rings, window: st.window, plugs: st.plugs });
    const svg = el('svg', { viewBox: '0 0 1000 ' + (BOT + 54), class: 'path-svg', role: 'img', 'aria-label': 'The current through the machine' });
    svg.appendChild(el('rect', { x: 1, y: 1, width: 998, height: BOT + 52, rx: 16, class: 'pa-bg', 'data-audit': 'ignore' }));
    const faint = el('g', { class: 'pa-faint', 'data-audit': 'ignore' });
    const boxes = el('g', { class: 'pa-boxes' });
    const heads = el('g', { class: 'pa-heads' });
    svg.append(boxes, faint);
    const head = (x1, x2, t1, t2) => { heads.appendChild(el('text', { x: (x1 + x2) / 2, y: 46, 'text-anchor': 'middle', class: 'pa-h' }, t1)); if (t2) heads.appendChild(el('text', { x: (x1 + x2) / 2, y: 68, 'text-anchor': 'middle', class: 'pa-h2' }, t2)); };
    const box = (k, cls) => boxes.appendChild(el('rect', { x: COL[k][0], y: Y0 - 14, width: COL[k][1] - COL[k][0], height: 25 * RY + 28, rx: 10, class: 'pa-box ' + (cls || ''), 'data-audit': 'group' }));
    // the rotors as they stand: wire from contact c (right side) to contact out (left side)
    const W = st.order.map((id) => S.Enigma.wheel(id)), pos = m.positions, rings = m.rings;
    ['L', 'M', 'R'].forEach((k, i) => {
      box(k, 'rotor');
      const off = md(pos[i] - rings[i]);
      for (let c = 0; c < 26; c++) { const out = md(W[i].fwd[md(c + off)] - off); faint.appendChild(el('path', { d: wiringPath(COL[k][0], COL[k][1], c, out), class: 'pa-wire' })); }
      head(COL[k][0], COL[k][1], ['Left', 'Middle', 'Right'][i] + ' · ' + st.order[i], 'window ' + st.window[i] + ' · ring ' + String(rings[i] + 1).padStart(2, '0'));
    });
    box('UKW', 'refl');
    const R = S.Enigma.wheel(S.Enigma.reflectorId(st.reflector));
    for (let c = 0; c < 26; c++) { const o = R.fwd[c]; if (o > c) { const xr = COL.UKW[1], xm = COL.UKW[0] + 10 + Math.abs(o - c) * 2; faint.appendChild(el('path', { d: `M${xr},${y(c)} C${xm},${y(c)} ${xm},${y(o)} ${xr},${y(o)}`, class: 'pa-wire' })); } }
    head(COL.UKW[0], COL.UKW[1], 'UKW-' + st.reflector, 'reflector');
    box('ETW'); head(COL.ETW[0] - 10, COL.ETW[1] + 10, 'ETW', 'entry');
    box('PB'); head(COL.PB[0] - 10, COL.PB[1] + 10, 'Plugs', S.Enigma.parsePlugs(st.plugs).length + ' cables');
    for (const [a, b] of S.Enigma.parsePlugs(st.plugs)) { const i = ABC.indexOf(a), j = ABC.indexOf(b), xm = (COL.PB[0] + COL.PB[1]) / 2; const bow = COL.PB[1] - Math.min(44, 12 + Math.abs(j - i) * 1.6); faint.appendChild(el('path', { d: `M${COL.PB[1]},${y(i)} C${bow},${y(i)} ${bow},${y(j)} ${COL.PB[1]},${y(j)}`, class: 'pa-plug' })); void xm; }
    head(KEY_X - 20, KEY_X + 40, 'Keys', 'lamps');
    // straight runs between the boxes for every contact, faint
    for (let c = 0; c < 26; c++) for (const [a, b] of [[COL.UKW[1], COL.L[0]], [COL.L[1], COL.M[0]], [COL.M[1], COL.R[0]], [COL.R[1], COL.ETW[0]], [COL.ETW[0], COL.ETW[1]], [COL.ETW[1], COL.PB[0]], [COL.PB[1], KEY_X - 12]]) faint.appendChild(el('line', { x1: a, x2: b, y1: y(c), y2: y(c), class: 'pa-run' }));
    const letters = el('g', { class: 'pa-letters' });
    for (let c = 0; c < 26; c++) {
      const g = el('g', { class: 'pa-key', 'data-letter': ABC[c] });
      g.append(el('circle', { cx: KEY_X + 10, cy: y(c), r: 10.5, class: 'pa-key-c' }), el('text', { x: KEY_X + 10, y: y(c) + 5, 'text-anchor': 'middle', class: 'pa-key-t' }, ABC[c]));
      letters.appendChild(g);
    }
    svg.append(heads, letters);
    // the current
    if (press && press.path) {
      const fwd = [], back = [];
      let into = fwd;
      const P = press.path;
      const kin = ABC.indexOf(press.in), kout = ABC.indexOf(press.out);
      fwd.push(`M${KEY_X - 1},${y(kin)}`);
      for (const p of P) {
        if (p.part === 'plugboard' && p.dir === 'in') { const xm = (COL.PB[0] + COL.PB[1]) / 2; fwd.push(`L${COL.PB[1]},${y(p.from)} C${xm + 4},${y(p.from)} ${xm - 4},${y(p.to)} ${COL.PB[0]},${y(p.to)}`); }
        else if (p.part === 'ETW' && p.dir === 'in') fwd.push(`L${COL.ETW[1]},${y(p.from)} L${COL.ETW[0]},${y(p.from)}`);
        else if (/^[LMR]$/.test(p.part)) {
          const [x1, x2] = COL[p.part], mm = (x1 + x2) / 2;
          if (p.dir === 'fwd') fwd.push(`L${x2},${y(p.from)} C${mm},${y(p.from)} ${mm},${y(p.to)} ${x1},${y(p.to)}`);
          else back.push(`L${x1},${y(p.from)} C${mm},${y(p.from)} ${mm},${y(p.to)} ${x2},${y(p.to)}`);
        } else if (p.part === 'UKW') {
          const xr = COL.UKW[1], xm = COL.UKW[0] + 10 + Math.abs(p.to - p.from) * 2;
          fwd.push(`L${xr},${y(p.from)} C${xm},${y(p.from)} ${xm},${y(p.to)} ${xr},${y(p.to)}`);
          into = back;
          back.push(`M${xr},${y(p.to)}`);
        } else if (p.part === 'ETW' && p.dir === 'out') back.push(`L${COL.ETW[0]},${y(p.from)} L${COL.ETW[1]},${y(p.from)}`);
        else if (p.part === 'plugboard' && p.dir === 'out') { const xm = (COL.PB[0] + COL.PB[1]) / 2; back.push(`L${COL.PB[0]},${y(p.from)} C${xm - 4},${y(p.from)} ${xm + 4},${y(p.to)} ${COL.PB[1]},${y(p.to)} L${KEY_X - 1},${y(kout)}`); }
      }
      void into;
      const glowF = el('path', { d: fwd.join(' '), class: 'pa-glow fwd', 'data-audit': 'ignore' }), glowB = el('path', { d: back.join(' '), class: 'pa-glow back', 'data-audit': 'ignore' });
      const pf = el('path', { d: fwd.join(' '), class: 'pa-cur fwd', 'data-audit': 'edge-x' }), pb = el('path', { d: back.join(' '), class: 'pa-cur back', 'data-audit': 'edge-x' });
      svg.insertBefore(glowF, heads); svg.insertBefore(glowB, heads); svg.insertBefore(pb, heads); svg.insertBefore(pf, heads);
      letters.querySelector(`[data-letter="${press.in}"]`).classList.add('in');
      letters.querySelector(`[data-letter="${press.out}"]`).classList.add('out');
    }
    svg.appendChild(el('text', { x: 500, y: BOT + 40, 'text-anchor': 'middle', class: 'pa-foot' }, press ? 'Key ' + press.in + ' to lamp ' + press.out + ': orange forward to the reflector, blue back to the lamp.' : 'Press a key: the current is drawn through every contact it touches.'));
    host.innerHTML = '';
    host.appendChild(svg);
    return svg;
  }

  (S.EnigmaViews = S.EnigmaViews || {}).path = {
    mount(host, ctx) {
      const wrap = h('div.enig-path', { id: 'enigPath' });
      const kb = h('div.mini-keys', { role: 'group', 'aria-label': 'Keys' });
      for (const row of ['QWERTZUIO', 'ASDFGHJK', 'PYXCVBNML']) {
        const r = h('div.mk-row');
        for (const L of row) { const b = h('button.mk', { type: 'button', dataset: { letter: L }, 'aria-label': 'Press ' + L }, L); b.addEventListener('click', () => ctx.press(L)); r.appendChild(b); }
        kb.appendChild(r);
      }
      const say = h('ol.path-say', { id: 'pathSay' });
      host.append(wrap, kb, say);
      let last = null;
      const render = () => {
        // the picture shows the rotors as they stood when the current flowed (after the step)
        draw(wrap, ctx.st, last);
        S.UI.scrollRow(wrap);
        // on a narrow screen the keys and lamps (the right end) are where a reader starts
        if (wrap.scrollWidth > wrap.clientWidth + 1) wrap.scrollLeft = wrap.scrollWidth;
        say.innerHTML = '';
        if (last) for (const t of last.trace) say.appendChild(h('li', t.say));
      };
      render();
      const off = ctx.on((type, r) => { if (type === 'press') { last = r; render(); } else if (type === 'config') { last = null; render(); } });
      return { dispose() { off(); }, redraw() { render(); } };
    },
  };
})(globalThis.Sifer = globalThis.Sifer || {});
