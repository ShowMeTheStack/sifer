// The Inside view: the lid open and the three rotors seen from the front, each with its notch ring on the left, its
// alphabet ring in the middle (the window letter framed) and its ratchet on the right. Three pawls stand in the gaps.
// The right pawl always pushes the right rotor. The middle pawl rests on the right rotor's notch ring and drops in
// only when the notch comes round; the left pawl does the same on the middle rotor's notch ring, and when it drops it
// pushes the left rotor's ratchet and the middle rotor's notch at once: the double step, visible as it happens.
(function (S) {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const { h, icon } = S.UI;
  const el = (tag, a, text) => { const e = document.createElementNS(NS, tag); for (const k in a || {}) if (a[k] !== undefined && a[k] !== null) e.setAttribute(k, a[k]); if (text !== undefined) e.textContent = text; return e; };
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const XS = [230, 500, 770], CY = 250, RH = 44, PAWL_X = [365, 635, 900];
  const NAMES = ['Left', 'Middle', 'Right'];

  function draw(host) {
    const svg = el('svg', { viewBox: '0 0 1000 560', class: 'inside-svg', role: 'img', 'aria-label': 'The three rotors, their notches and the three pawls' });
    svg.appendChild(el('rect', { x: 2, y: 2, width: 996, height: 556, rx: 18, class: 'in-bg', 'data-audit': 'ignore' }));
    const rot = [], paw = [];
    for (let k = 0; k < 3; k++) {
      const x = XS[k];
      const g = el('g', { class: 'in-rotor', 'data-slot': String(k) });
      g.appendChild(el('rect', { x: x - 72, y: 72, width: 144, height: 358, rx: 16, class: 'in-drum', 'data-audit': 'group' }));
      const title = el('text', { x, y: 52, 'text-anchor': 'middle', class: 'in-title' }, NAMES[k] + ' rotor');
      const sub = el('text', { x, y: 458, 'text-anchor': 'middle', class: 'in-sub' }, '');
      // the notch ring (left) and the ratchet (right): decoration, with the notch drawn as a gap
      const ring = el('g', { 'data-audit': 'ignore' });
      ring.appendChild(el('rect', { x: x - 64, y: 96, width: 16, height: 310, rx: 5, class: 'in-notchring' }));
      const teeth = el('path', { d: '', class: 'in-teeth' });
      ring.appendChild(teeth);
      const notch = el('rect', { x: x - 66, y: CY - 9, width: 14, height: 18, rx: 3, class: 'in-notch' });
      ring.appendChild(notch);
      const strip = el('g', { class: 'in-strip' });
      const frame = el('rect', { x: x - 30, y: CY - RH / 2, width: 60, height: RH, rx: 7, class: 'in-frame' });
      g.append(ring, frame, strip, title, sub);
      svg.appendChild(g);
      rot.push({ g, strip, notch, teeth, sub, x });
    }
    for (let k = 0; k < 3; k++) {
      const x = PAWL_X[k];
      const g = el('g', { class: 'in-pawl', 'data-pawl': String(k) });
      const body = el('path', { d: `M${x - 9},500 L${x - 9},${CY + 70} L${x},${CY + 50} L${x + 9},${CY + 70} L${x + 9},500 Z`, class: 'in-pawl-b' });
      const lab = el('text', { x, y: 530, 'text-anchor': 'middle', class: 'in-pawl-t' }, NAMES[k].toLowerCase() + ' pawl');
      const push = el('text', { x, y: CY - 70, 'text-anchor': 'middle', class: 'in-push' }, '');
      // when it drops in, the pawl's hook meets the ratchet on its left and (for the left and middle pawls) the notch
      // ring on its right
      const arms = el('g', { class: 'in-arms', 'data-audit': 'ignore' });
      arms.appendChild(el('path', { d: `M${x},${CY + 4} L${XS[k] + 62},${CY + 4}`, class: 'in-arm' }));
      if (k < 2) arms.appendChild(el('path', { d: `M${x},${CY + 4} L${XS[k + 1] - 56},${CY + 4}`, class: 'in-arm' }));
      g.append(arms, body, lab, push);
      svg.appendChild(g);
      paw.push({ g, push });
    }
    host.innerHTML = '';
    host.appendChild(svg);
    return { svg, rot, paw };
  }

  function show(d, st, last) {
    const W = S.Enigma.ROTORS;
    for (let k = 0; k < 3; k++) {
      const r = d.rot[k], id = st.order[k], w = ABC.indexOf(st.window[k]), notch = ABC.indexOf(W[id].notch);
      r.strip.innerHTML = '';
      for (let j = -3; j <= 3; j++) {
        const L = ABC[(w + j + 26) % 26];
        if (Math.abs(j) === 3) continue;
        r.strip.appendChild(el('text', { x: r.x, y: CY + j * RH + 9, 'text-anchor': 'middle', class: 'in-let' + (j === 0 ? ' on' : '') + (L === W[id].notch ? ' notchl' : '') }, L));
      }
      // the notch sits beside its letter when that letter is within sight
      let dj = notch - w; if (dj > 13) dj -= 26; if (dj < -13) dj += 26;
      r.notch.style.display = Math.abs(dj) <= 2 ? '' : 'none';
      r.notch.setAttribute('y', String(CY + dj * RH - 9));
      let tp = '';
      for (let t = 0; t < 14; t++) { const y = 100 + t * 22; tp += `M${r.x + 50},${y} L${r.x + 64},${y + 11} L${r.x + 50},${y + 22} `; }
      r.teeth.setAttribute('d', tp);
      r.sub.textContent = id + ' · notch ' + W[id].notch + ' · ring ' + String(ABC.indexOf(st.rings[k]) + 1).padStart(2, '0');
      r.g.classList.toggle('stepped', !!(last && last.steps[k]));
    }
    for (let k = 0; k < 3; k++) {
      const on = !!(last && last.pawls[k]);
      d.paw[k].g.classList.toggle('engaged', on);
      d.paw[k].push.textContent = !last ? '' : on ? (k === 0 ? 'pushes L and M' : k === 1 ? 'pushes M' : 'pushes R') : 'rests';
    }
  }

  (S.EnigmaViews = S.EnigmaViews || {}).inside = {
    mount(host, ctx) {
      const box = h('div.enig-inside', { id: 'enigInside' });
      const say = h('div.inside-say', { id: 'insideSay', 'aria-live': 'polite' });
      const hist = h('ol.inside-hist', { id: 'insideHist' });
      const pressBtn = h('button.btn.small.primary', { type: 'button', id: 'inPress' }, icon('keyboard'), 'Press a key');
      pressBtn.addEventListener('click', () => ctx.press('X'));
      const demo = h('button.btn.small', { type: 'button', id: 'inDemo' }, icon('rotor'), 'Set up the double step');
      demo.addEventListener('click', () => { ctx.setAll({ order: ['I', 'II', 'III'], reflector: 'B', rings: 'AAA', start: 'ADU', window: 'ADU', plugs: '' }); });
      host.append(box, h('div.inside-tools', pressBtn, demo, h('span.muted', 'Rotors I, II and III at ADU: the next three keys show ADV, AEW, then BFX, the middle rotor moving twice running.')), say, hist);
      const d = draw(box);
      S.UI.scrollRow(box);
      let last = null;
      const log = [];
      const render = () => {
        show(d, ctx.st, last && last.stepping);
        say.innerHTML = '';
        if (!last) say.textContent = 'Press a key (or type) and watch the pawls. A pawl that drops into a notch pushes the rotor on its left; the right pawl never has a notch to wait for.';
        else for (const t of last.stepping.trace) say.appendChild(h('p', t.say));
        hist.innerHTML = '';
        log.slice(-8).forEach((x) => hist.appendChild(h('li' + (x.steps[0] ? '.double' : x.steps[1] ? '.carry' : ''), h('code', x.before + ' → ' + x.after), ' ', x.steps[0] ? 'the double step: left and middle with the right' : x.steps[1] ? 'the right rotor carries the middle' : 'the right rotor alone')));
      };
      render();
      const off = ctx.on((type, r) => {
        if (type === 'press') { last = r; log.push(r.stepping); render(); }
        else if (type === 'config') { last = null; log.length = 0; render(); }
      });
      return { dispose() { off(); }, redraw() { render(); } };
    },
  };
})(globalThis.Sifer = globalThis.Sifer || {});
