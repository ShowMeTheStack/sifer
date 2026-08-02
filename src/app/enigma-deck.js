// The deck of Enigma I, drawn anew in SVG: a wooden case, a brass maker's plate, the three rotor windows with their
// thumbwheels (turn them up or down), the lampboard, the keyboard and the plugboard (enigma-plug.js). Keys answer to
// the pointer and to the keyboard; a key held down keeps its lamp lit. On a phone the case is cropped to the keys so
// they stay large enough to press. This file also registers the Machine view of the Enigma page.
(function (S) {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const el = (tag, a, text) => { const e = document.createElementNS(NS, tag); for (const k in a || {}) if (a[k] !== undefined && a[k] !== null) e.setAttribute(k, a[k]); if (text !== undefined) e.textContent = text; return e; };
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const LAMP_Y = [240, 305, 370], KEY_Y = [458, 534, 610], PLUG_Y0 = 660;
  let seq = 0;

  /** draw a deck into host. o = {narrow, st (the page's settings), onKey(L, down), onTurn(i, d), onPlugs(text)} */
  function deck(host, o) {
    const id = 'dk' + (++seq);
    const plugH = 350;
    const H = PLUG_Y0 + plugH + 24;
    const vx = o.narrow ? 125 : 0, vw = o.narrow ? 750 : 1000, gx = o.narrow ? 158 : 150, gw = o.narrow ? 684 : 700;
    const svg = el('svg', { viewBox: `${vx} 0 ${vw} ${H}`, class: 'deck-svg' + (o.narrow ? ' narrow' : ''), role: 'img', 'aria-label': 'Enigma I: rotor windows, lampboard, keyboard and plugboard' });
    const defs = el('defs');
    defs.innerHTML = `<linearGradient id="${id}w" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#6b3f22"/><stop offset=".45" stop-color="#4a2914"/><stop offset="1" stop-color="#5c3419"/></linearGradient>
      <linearGradient id="${id}b" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#e6c66e"/><stop offset=".5" stop-color="#c9a24a"/><stop offset="1" stop-color="#a57d2c"/></linearGradient>
      <radialGradient id="${id}k" cx=".42" cy=".35" r=".7"><stop offset="0" stop-color="#3a3d44"/><stop offset="1" stop-color="#121418"/></radialGradient>
      <radialGradient id="${id}l" cx=".5" cy=".45" r=".6"><stop offset="0" stop-color="#fff6c8"/><stop offset=".55" stop-color="#ffd25a"/><stop offset="1" stop-color="#e09a1c"/></radialGradient>
      <radialGradient id="${id}g" cx=".5" cy=".5" r=".5"><stop offset="0" stop-color="#ffd66b" stop-opacity=".75"/><stop offset="1" stop-color="#ffb020" stop-opacity="0"/></radialGradient>`;
    svg.appendChild(defs);
    const deco = el('g', { 'data-audit': 'ignore', class: 'dk-deco' });
    deco.append(el('rect', { x: vx + 2, y: 2, width: vw - 4, height: H - 4, rx: 26, fill: `url(#${id}w)`, class: 'dk-wood' }),
      el('rect', { x: vx + 26, y: 26, width: vw - 52, height: H - 52, rx: 12, class: 'dk-metal' }),
      el('rect', { x: vx + 26, y: PLUG_Y0 - 6, width: vw - 52, height: H - PLUG_Y0 - 20, rx: 10, class: 'dk-front' }),
      el('rect', { x: gx, y: 198, width: gw, height: 206, rx: 14, class: 'dk-glass' }),
      el('rect', { x: gx, y: 414, width: gw, height: 236, rx: 14, class: 'dk-keybed' }));
    for (const [sx, sy] of [[vx + 44, 44], [vx + vw - 44, 44], [vx + 44, H - 44], [vx + vw - 44, H - 44], [vx + 44, PLUG_Y0 - 30], [vx + vw - 44, PLUG_Y0 - 30]]) {
      deco.append(el('circle', { cx: sx, cy: sy, r: 6, class: 'dk-screw' }), el('path', { d: `M${sx - 4},${sy - 1.5} L${sx + 4},${sy + 1.5}`, class: 'dk-slot' }));
    }
    svg.appendChild(deco);

    // ---- the top: maker's plate, rotor windows, reflector badge --------------------------------------------------
    const top = el('g', { class: 'dk-top' });
    if (!o.narrow) {
      top.append(el('rect', { x: 60, y: 50, width: 236, height: 104, rx: 8, fill: `url(#${id}b)`, class: 'dk-plate' }),
        el('text', { x: 178, y: 92, 'text-anchor': 'middle', class: 'dk-plate-t' }, 'ENIGMA I'),
        el('text', { x: 178, y: 116, 'text-anchor': 'middle', class: 'dk-plate-s' }, 'Practice machine No. 1926'),
        el('text', { x: 178, y: 138, 'text-anchor': 'middle', class: 'dk-plate-s' }, 'Sifer cipher workshop'));
      for (const [px, py] of [[70, 60], [286, 60], [70, 144], [286, 144]]) top.appendChild(el('circle', { cx: px, cy: py, r: 3, class: 'dk-rivet', 'data-audit': 'ignore' }));
    } else top.appendChild(el('text', { x: 178, y: 106, class: 'dk-name' }, 'ENIGMA I'));
    const wins = [];
    for (let i = 0; i < 3; i++) {
      const cx = 420 + i * 80, cy = 96;
      const g = el('g', { class: 'dk-rotor', 'data-slot': String(i) });
      g.append(el('rect', { x: cx - 26, y: cy - 31, width: 52, height: 62, rx: 7, class: 'dk-win' }));
      const t = el('text', { x: cx, y: cy + 11, 'text-anchor': 'middle', class: 'dk-win-t' }, 'A');
      g.appendChild(t);
      // the thumbwheel: its upper half turns the rotor forward, the lower half back
      const wheel = el('g', { class: 'dk-wheel' });
      wheel.appendChild(el('rect', { x: cx + 32, y: cy - 44, width: 16, height: 88, rx: 6, class: 'dk-wheel-body' }));
      const ridges = el('g', { 'data-audit': 'ignore' });
      for (let k = 0; k < 11; k++) ridges.appendChild(el('line', { x1: cx + 34, x2: cx + 46, y1: cy - 38 + k * 7.6, y2: cy - 38 + k * 7.6, class: 'dk-ridge' }));
      wheel.appendChild(ridges);
      const upB = el('rect', { x: cx + 26, y: cy - 50, width: 28, height: 50, class: 'dk-hit', 'data-audit': 'ignore', role: 'button', tabindex: '0', 'aria-label': ['Left', 'Middle', 'Right'][i] + ' rotor forward', 'data-turn': i + ':1' });
      const dnB = el('rect', { x: cx + 26, y: cy, width: 28, height: 50, class: 'dk-hit', 'data-audit': 'ignore', role: 'button', tabindex: '0', 'aria-label': ['Left', 'Middle', 'Right'][i] + ' rotor back', 'data-turn': i + ':-1' });
      wheel.append(upB, dnB);
      g.appendChild(wheel);
      const name = el('text', { x: cx, y: cy + 56, 'text-anchor': 'middle', class: 'dk-rot-n' }, 'I');
      const ring = el('text', { x: cx, y: cy + 75, 'text-anchor': 'middle', class: 'dk-rot-r' }, 'ring 01');
      g.append(name, ring);
      top.appendChild(g);
      wins.push({ t, name, ring, g });
    }
    const ukwX = o.narrow ? 690 : 740;
    top.append(el('rect', { x: ukwX, y: 62, width: 138, height: 70, rx: 9, class: 'dk-badge' }));
    const ukw = el('text', { x: ukwX + 69, y: 94, 'text-anchor': 'middle', class: 'dk-badge-t' }, 'UKW-B');
    const nCab = el('text', { x: ukwX + 69, y: 118, 'text-anchor': 'middle', class: 'dk-badge-s' }, '10 cables');
    top.append(ukw, nCab);
    svg.appendChild(top);

    // ---- lamps and keys ---------------------------------------------------------------------------------------------
    const lamps = {}, keys = {};
    const lampG = el('g', { class: 'dk-lamps' }), keyG = el('g', { class: 'dk-keys' });
    for (const row of S.EnigmaPlug.ROWS) for (const L of row) {
      const a = S.EnigmaPlug.at(L);
      const ly = LAMP_Y[a.r], ky = KEY_Y[a.r];
      const lg = el('g', { class: 'dk-lamp', 'data-letter': L });
      lg.append(el('circle', { cx: a.x, cy: ly, r: 38, fill: `url(#${id}g)`, class: 'dk-glow', 'data-audit': 'ignore' }), el('circle', { cx: a.x, cy: ly, r: 25, class: 'dk-lamp-c' }), el('text', { x: a.x, y: ly + 7, 'text-anchor': 'middle', class: 'dk-lamp-t' }, L));
      lampG.appendChild(lg);
      lamps[L] = lg;
      const kg = el('g', { class: 'dk-key', 'data-letter': L, role: 'button', tabindex: '-1', 'aria-label': 'Key ' + L });
      // the shadow stays on the key bed; the key top travels down into it (and shrinks a little, as if seen from above)
      const top = el('g', { class: 'dk-key-top' });
      top.style.transformOrigin = a.x + 'px ' + ky + 'px';
      top.append(el('circle', { cx: a.x, cy: ky, r: 30, class: 'dk-key-ring' }), el('circle', { cx: a.x, cy: ky, r: 24, fill: `url(#${id}k)`, class: 'dk-key-cap', 'data-audit': 'ignore' }), el('text', { x: a.x, y: ky + 8.5, 'text-anchor': 'middle', class: 'dk-key-t' }, L));
      const shadow = el('ellipse', { cx: a.x, cy: ky + 5, rx: 31, ry: 31, class: 'dk-key-shadow', 'data-audit': 'ignore' });
      shadow.style.transformOrigin = a.x + 'px ' + (ky + 5) + 'px';
      kg.append(shadow, top);
      keyG.appendChild(kg);
      keys[L] = kg;
    }
    svg.append(lampG, keyG);
    const plugG = el('g', { class: 'dk-plugboard' });
    svg.appendChild(plugG);
    host.innerHTML = '';
    host.appendChild(svg);
    const plug = S.EnigmaPlug.draw(plugG, { y0: PLUG_Y0, pairs: [], onChange: o.onPlugs });

    // ---- input --------------------------------------------------------------------------------------------------------
    let held = null;
    keyG.addEventListener('pointerdown', (e) => {
      const k = e.target.closest('.dk-key'); if (!k) return;
      e.preventDefault();
      held = k.dataset.letter;
      try { svg.setPointerCapture(e.pointerId); } catch (x) { /* fine */ }
      o.onKey(held, true);
    });
    const up = () => { if (held) { const L = held; held = null; o.onKey(L, false); } };
    svg.addEventListener('pointerup', up);
    svg.addEventListener('pointercancel', up);
    top.addEventListener('click', (e) => { const b = e.target.closest('[data-turn]'); if (!b) return; const [i, d] = b.dataset.turn.split(':').map(Number); o.onTurn(i, d); });
    top.addEventListener('keydown', (e) => { const b = e.target.closest('[data-turn]'); if (!b || (e.key !== 'Enter' && e.key !== ' ')) return; e.preventDefault(); e.stopPropagation(); const [i, d] = b.dataset.turn.split(':').map(Number); o.onTurn(i, d); });

    const api = {
      svg,
      show(st) {
        for (let i = 0; i < 3; i++) { wins[i].t.textContent = st.window[i]; wins[i].name.textContent = st.order[i]; wins[i].ring.textContent = (o.narrow ? '' : 'ring ') + String(ABC.indexOf(st.rings[i]) + 1).padStart(2, '0'); }
        ukw.textContent = 'UKW-' + st.reflector;
        const pairs = S.Enigma.parsePlugs(st.plugs || '');
        nCab.textContent = pairs.length + (pairs.length === 1 ? ' cable' : ' cables');
        plug.set(pairs);
      },
      light(L) { for (const k in lamps) lamps[k].classList.toggle('lit', k === L); },
      dark() { for (const k in lamps) lamps[k].classList.remove('lit'); },
      keyDown(L) { for (const k in keys) keys[k].classList.toggle('down', k === L); },
      keyUp() { for (const k in keys) keys[k].classList.remove('down'); },
      stepped(steps) { steps.forEach((s, i) => { if (!s) return; const g = wins[i].g; g.classList.remove('turned'); void g.getBoundingClientRect(); g.classList.add('turned'); }); },
    };
    return api;
  }
  S.EnigmaDeck = deck;

  // ---- the Machine view ----------------------------------------------------------------------------------------------
  (S.EnigmaViews = S.EnigmaViews || {}).deck = {
    mount(host, ctx) {
      const box = document.createElement('div');
      box.className = 'enig-deck';
      box.id = 'enigDeck';
      host.appendChild(box);
      const note = document.createElement('p');
      note.className = 'enig-note muted';
      note.id = 'deckNote';
      host.appendChild(note);
      let d = null, narrow = null, timer = null;
      const say = (r) => {
        if (!r) { note.textContent = 'Type on your keyboard or press the keys. Turn a rotor with its thumbwheel; drag a cable between two sockets of the plugboard.'; return; }
        note.textContent = 'Key ' + r.in + ' lit lamp ' + r.out + '. The window moved from ' + r.stepping.before + ' to ' + r.stepping.after + (r.stepping.steps[0] ? ': the double step, the middle and left rotors turned together.' : r.stepping.steps[1] ? ': the right rotor passed its notch and carried the middle one.' : '.');
      };
      const build = () => {
        narrow = (box.clientWidth || innerWidth) < 600;
        d = deck(box, {
          narrow,
          onKey(L, down) { if (down) ctx.press(L); else ctx.release(); },
          onTurn(i, dir) { ctx.turn(i, dir); },
          onPlugs(text) { try { ctx.set({ plugs: text }); } catch (e) { S.UI.toast(e.message, 'err'); } },
        });
        d.show(ctx.st);
      };
      build();
      say(null);
      const off = ctx.on((type, r) => {
        // the key goes down, the rotors step and the lamp lights together, on the down-stroke; they hold until release
        if (type === 'press') { clearTimeout(timer); d.keyDown(r.in); d.show(ctx.st); d.light(r.out); d.stepped(r.stepping.steps); say(r); }
        else if (type === 'release') { d.keyUp(); clearTimeout(timer); timer = setTimeout(() => d.dark(), 40); }
        else if (type === 'config') { d.show(ctx.st); d.dark(); say(null); }
        else if (type === 'tape') { d.keyUp(); clearTimeout(timer); timer = setTimeout(() => d.dark(), 900); }
      });
      const onResize = S.UI.debounce(() => { if ((box.clientWidth < 600) !== narrow) build(); }, 120);
      window.addEventListener('resize', onResize);
      return { deck: () => d, dispose() { off(); clearTimeout(timer); window.removeEventListener('resize', onResize); }, redraw() { build(); } };
    },
  };
})(globalThis.Sifer = globalThis.Sifer || {});
