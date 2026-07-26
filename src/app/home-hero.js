// The picture on the home page: the avalanche of AES-128, live. Two plaintexts that differ in one bit go through the
// ten rounds side by side; each round the two states are drawn as 4×4 grids of bytes, and between them a heat map
// shows how many bits of each byte now differ. After round 2 every byte has changed; by the end about half of the
// 128 bits differ, as for two unrelated blocks. Then another bit is flipped and it starts again.
(function (S) {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';
  const el = (tag, attrs, text) => { const e = document.createElementNS(NS, tag); for (const k in attrs || {}) e.setAttribute(k, attrs[k]); if (text !== undefined) e.textContent = text; return e; };
  const KEY = 'sifer hero key 1';
  const PLAIN = 'Meet at the mill';

  S.HomeHero = function (host, cap) {
    if (!S.AES || !S.bytes) return { stop() {} };
    const B = S.bytes, key = B.utf8(KEY), p0 = B.utf8(PLAIN).slice(0, 16);
    const W = 640, H = 330, C = 34, G = 4;
    const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, class: 'hero-svg', role: 'img', 'aria-label': 'Two AES states, one bit apart, round by round, with the bits that differ as a heat map' });
    host.innerHTML = '';
    host.appendChild(svg);
    const grid = (x0, y0, label, cls) => {
      const g = el('g', { class: 'hg ' + cls });
      const lab = el('text', { x: x0 + (4 * C + 3 * G) / 2, y: y0 - 12, class: 'hg-label', 'text-anchor': 'middle' }, label);
      g.appendChild(lab);
      const cells = [];
      cells.label = lab;
      for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) {
        const x = x0 + c * (C + G), y = y0 + r * (C + G);
        const box = el('rect', { x, y, width: C, height: C, rx: 6, class: 'hg-box' });
        const t = el('text', { x: x + C / 2, y: y + C / 2 + 5, 'text-anchor': 'middle', class: 'hg-hex' }, '00');
        g.append(box, t);
        cells[r + 4 * c] = { box, t };
      }
      svg.appendChild(g);
      return cells;
    };
    const y0 = 74, gw = 4 * C + 3 * G;
    const xs = [24, (W - gw) / 2, W - 24 - gw];
    const A = grid(xs[0], y0, 'state of P', 'a'), D = grid(xs[1], y0, 'bits that differ', 'd'), Bc = grid(xs[2], y0, 'state of P′', 'b');
    const title = el('text', { x: W / 2, y: 30, 'text-anchor': 'middle', class: 'hg-title' }, '');
    const barY = y0 + 4 * C + 3 * G + 34;
    const track = el('rect', { x: xs[0], y: barY, width: W - 48, height: 12, rx: 6, class: 'hg-track' });
    const bar = el('rect', { x: xs[0], y: barY, width: 0, height: 12, rx: 6, class: 'hg-bar' });
    const half = el('line', { x1: xs[0] + (W - 48) / 2, y1: barY - 5, x2: xs[0] + (W - 48) / 2, y2: barY + 17, class: 'hg-half' });
    const count = el('text', { x: xs[0], y: barY + 38, class: 'hg-count' }, '');
    const halfT = el('text', { x: xs[0] + (W - 48) / 2, y: barY + 38, 'text-anchor': 'middle', class: 'hg-note' }, 'half of 128');
    svg.append(title, track, bar, half, count, halfT);
    let bit = 0, round = 0, ra = null, rb = null, timer = null, stopped = false;
    const still = S.UI && S.UI.reducedMotion && S.UI.reducedMotion();
    const newPair = () => {
      const p1 = p0.slice(); p1[bit >> 3] ^= 0x80 >> (bit & 7);
      ra = S.AES.encrypt(p0, key).rounds; rb = S.AES.encrypt(p1, key).rounds;
    };
    const paint = () => {
      const a = round < 0 ? Array.from(p0) : ra[round].end, b = round < 0 ? (() => { const p = Array.from(p0); p[bit >> 3] ^= 0x80 >> (bit & 7); return p; })() : rb[round].end;
      let total = 0;
      for (let i = 0; i < 16; i++) {
        const d = B.popcount(a[i] ^ b[i]);
        total += d;
        A[i].t.textContent = B.h2(a[i]); Bc[i].t.textContent = B.h2(b[i]);
        A[i].box.setAttribute('class', 'hg-box' + (a[i] !== b[i] ? ' diff' : ''));
        Bc[i].box.setAttribute('class', 'hg-box' + (a[i] !== b[i] ? ' diff' : ''));
        D[i].t.textContent = String(d);
        D[i].box.setAttribute('class', 'hg-box heat h' + d);
        D[i].t.setAttribute('class', 'hg-hex heat-t' + (d >= 5 ? ' on' : ''));
      }
      const last = round === 10;
      title.textContent = round < 0 ? 'The plaintexts: one bit apart' : round === 0 ? 'After the first AddRoundKey' : last ? 'The ciphertexts, after all ten rounds' : 'After round ' + round + ' of 10';
      A.label.textContent = round < 0 ? 'plaintext P' : last ? 'ciphertext C' : 'state of P';
      Bc.label.textContent = round < 0 ? 'plaintext P′' : last ? 'ciphertext C′' : 'state of P′';
      bar.setAttribute('width', String(((W - 48) * total) / 128));
      count.textContent = total + ' of 128 bits differ';
      if (cap) {
        cap.innerHTML = '';
        const b1 = document.createElement('b'); b1.textContent = 'The avalanche, live.';
        cap.append(b1, ' AES-128 on "' + PLAIN + '" and the same block with bit ' + bit + ' flipped. ' + (round < 0 ? 'One bit differs going in.' : round < 3 ? 'After round ' + Math.max(round, 0) + ', ' + total + ' bits differ: S-boxes mix bits within a byte, ShiftRows and MixColumns spread bytes across the state.' : last ? 'Out come C and C′: ' + total + ' of 128 bits differ, about half, as for two unrelated blocks.' : 'After round ' + round + ', ' + total + ' of 128 bits differ: the two blocks already look unrelated.'));
      }
    };
    // it opens on the ciphertexts (the point of the picture), then plays from the plaintexts round by round, on a loop
    const step = () => {
      if (stopped || !host.isConnected) return;
      paint();
      if (still) return;
      const hold = round === 10 ? 4800 : round < 0 ? 2600 : 1150;
      round++;
      if (round > 10) { round = -1; bit = (bit + 37) % 128; newPair(); }
      timer = setTimeout(step, hold);
    };
    round = 10;
    newPair();
    step();
    return { stop() { stopped = true; clearTimeout(timer); } };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
