// What the cipher bench draws: a state as the grid it is (AES's 4×4 bytes in column order, DES's two halves, ChaCha's
// 4×4 words, Mini-AES's 2×2 nibbles), the ladder of round states with what each round changed lit and its round key in
// rose, the details of one round, the data flow of a mode drawn block by block, the registers of Trivium and the
// tables of the classical ciphers.
(function (S) {
  'use strict';
  const { h } = S.UI;
  const CB = (S.CipherBench = S.CipherBench || {});
  const V = (CB.view = CB.view || {});
  const h2 = (v) => v.toString(16).padStart(2, '0');
  const hex = (b) => Array.from(b, h2).join('');
  const NS = 'http://www.w3.org/2000/svg';

  /** a state as a grid of cells; prev lights the bytes (or nibbles, or words) that changed */
  V.state = function (algo, bytes, o) {
    o = o || {};
    const prev = o.prev, cls = o.key ? '.key' : '';
    const cell = (text, changed, title) => h('span.sc' + cls + (changed && !o.key ? '.diff' : ''), title ? { title } : null, text);
    const view = (algo && algo.view) || 'bytes';
    if (view === 'aes' && bytes.length === 16) {
      const g = h('div.sgrid.g4', { role: 'group', 'aria-label': o.label || 'state' });
      for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) { const i = r + 4 * c; g.appendChild(cell(h2(bytes[i]), prev && prev[i] !== bytes[i], 'row ' + r + ', column ' + c)); }
      return g;
    }
    if (view === 'mini' || view === 'spn') {
      const nib = [bytes[0] >> 4, bytes[0] & 15, bytes[1] >> 4, bytes[1] & 15], pn = prev ? [prev[0] >> 4, prev[0] & 15, prev[1] >> 4, prev[1] & 15] : null;
      if (view === 'mini') { const g = h('div.sgrid.g2', { role: 'group', 'aria-label': o.label || 'state' }); for (const i of [0, 2, 1, 3]) g.appendChild(cell(nib[i].toString(16), pn && pn[i] !== nib[i], 'nibble n' + i)); return g; }
      const g = h('div.sgrid.g4n', { role: 'group', 'aria-label': o.label || 'state' }); nib.forEach((v, i) => g.appendChild(cell(v.toString(16), pn && pn[i] !== v, 'nibble ' + i))); return g;
    }
    if (view === 'words' && bytes.length === 64) {
      const g = h('div.sgrid.gw', { role: 'group', 'aria-label': o.label || 'state' });
      for (let i = 0; i < 16; i++) { const w = (bytes[4 * i] | (bytes[4 * i + 1] << 8) | (bytes[4 * i + 2] << 16) | (bytes[4 * i + 3] << 24)) >>> 0; const pw = prev ? (prev[4 * i] | (prev[4 * i + 1] << 8) | (prev[4 * i + 2] << 16) | (prev[4 * i + 3] << 24)) >>> 0 : null; g.appendChild(cell(w.toString(16).padStart(8, '0'), prev && pw !== w, 'word ' + i)); }
      return g;
    }
    if ((view === 'des' || o.half) && bytes.length === 8) {
      const half = (a, b, name) => { const g = h('div.sgrid.g4b'); for (let i = a; i < b; i++) g.appendChild(cell(h2(bytes[i]), prev && prev[i] !== bytes[i])); return h('div.half', h('span.hl-name', name), g); };
      return h('div.halves', { role: 'group', 'aria-label': o.label || 'state' }, half(0, 4, 'L'), half(4, 8, 'R'));
    }
    const g = h('div.sgrid.gb', { role: 'group', 'aria-label': o.label || 'bytes', style: { gridTemplateColumns: 'repeat(' + Math.min(8, Math.max(1, bytes.length)) + ', 2.6em)' } });
    bytes.forEach((v, i) => g.appendChild(cell(h2(v), prev && prev[i] !== v)));
    return g;
  };

  /** the ladder of round states: label, state, round key, and how many bytes the round changed */
  V.ladder = function (algo, res, onPick) {
    const box = h('div.ladder' + (algo && algo.view === 'words' ? '.words' : ''), { id: 'cbLadder' });
    res.states.forEach((st, k) => {
      const prev = k ? res.states[k - 1].bytes : null;
      let changed = 0;
      if (prev && prev.length === st.bytes.length) for (let i = 0; i < st.bytes.length; i++) if (prev[i] !== st.bytes[i]) changed++;
      const row = h('div.lrow' + (st.detail ? '.pick' : ''), { dataset: { k: String(k) }, tabindex: st.detail ? '0' : null, role: st.detail ? 'button' : null, 'aria-label': st.detail ? 'Show the steps of ' + st.label : null },
        h('div.lr-label', h('b', st.label), prev ? h('span.muted', changed + ' of ' + st.bytes.length + ' changed') : h('span.muted', st.bytes.length + ' bytes')),
        V.state(algo, st.bytes, { prev, half: st.half, label: st.label }),
        st.key ? h('div.lr-key', h('span.muted', 'key'), V.state(algo, st.key, { key: true, half: st.half, label: 'round key' })) : h('div.lr-key'));
      if (st.detail && onPick) { const go = () => onPick(k); row.addEventListener('click', go); row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } }); }
      box.appendChild(row);
    });
    return box;
  };

  /** the steps inside one round */
  V.detail = function (algo, st) {
    const d = st.detail, box = h('div.rdetail', { id: 'cbDetail' }, h('h4', st.label + ', step by step'));
    const stage = (name, bytes, o) => h('div.rd-stage', h('span.rd-name', name), V.state(algo, bytes, o));
    if (algo.view === 'aes') {
      box.appendChild(h('div.rd-flow', stage('Start', Uint8Array.from(d.start)), d.sub ? stage('SubBytes', Uint8Array.from(d.sub), { prev: Uint8Array.from(d.start) }) : null,
        d.shift ? stage('ShiftRows', Uint8Array.from(d.shift), { prev: Uint8Array.from(d.sub || d.start) }) : null,
        d.mix ? stage('MixColumns', Uint8Array.from(d.mix), { prev: Uint8Array.from(d.shift) }) : null,
        stage('Round key', Uint8Array.from(d.key), { key: true }), stage('End', Uint8Array.from(d.end))));
    } else if (algo.view === 'des') {
      const U = CB.util, f = d.f || {};
      const row = (k, v) => h('div.kv', h('span.k', k), h('code.v', v));
      const bits = (a) => (a || []).join('').replace(/(.{6})/g, '$1 ').trim();
      box.append(row('R (input to f)', hex(U.bitsToBytes(d.R))), row('E(R), 48 bits', bits(f.E)), row('⊕ round key K' + d.i, bits(d.K)), row('= into the S-boxes', bits(f.X)));
      if (f.boxes) box.appendChild(h('div.sboxes', ...f.boxes.map((b) => h('div.sbox', h('b', 'S' + b.i), h('code', b.in6.join('')), h('span.muted', 'row ' + b.row + ', col ' + b.col), h('code.out', (b.out || []).join(''))))));
      if (f.P) box.appendChild(row('P(S-box outputs) = f', hex(U.bitsToBytes(f.P))));
      box.appendChild(row('new R = L ⊕ f', hex(U.bitsToBytes(d.newR))));
    } else if (algo.view === 'mini' || algo.view === 'spn') {
      const n2 = (a) => Uint8Array.from([(a[0] << 4) | a[1], (a[2] << 4) | a[3]]);
      const two = (v) => Uint8Array.from([(v >> 8) & 255, v & 255]);
      if (algo.view === 'mini') box.appendChild(h('div.rd-flow', stage('Start', n2(d.start)), stage('NibbleSub', n2(d.sub), { prev: n2(d.start) }), stage('ShiftRow', n2(d.shift), { prev: n2(d.sub) }), d.mix ? stage('MixColumn', n2(d.mix), { prev: n2(d.shift) }) : null, stage('Round key', n2(d.key), { key: true }), stage('End', n2(d.end))));
      else box.appendChild(h('div.rd-flow', stage('Key mixed (u)', two(d.u)), stage('S-boxes (v)', two(d.v), { prev: two(d.u) }), d.w !== undefined && d.w !== null ? stage('Permuted (w)', two(d.w), { prev: two(d.v) }) : null));
    } else if (algo.view === 'present') {
      const U = CB.util;
      box.appendChild(h('div.rd-flow', stage('Round key', U.bigToBytes(d.key, 8), { key: true }), stage('Key added', U.bigToBytes(d.added, 8)), stage('S-layer', U.bigToBytes(d.sub, 8), { prev: U.bigToBytes(d.added, 8) }), stage('P-layer', U.bigToBytes(d.perm, 8), { prev: U.bigToBytes(d.sub, 8) })));
    }
    return box;
  };

  // ---- the data flow of a mode -------------------------------------------------------------------------------------------
  const el = (tag, a, text) => { const e = document.createElementNS(NS, tag); for (const k in a) e.setAttribute(k, a[k]); if (text !== undefined) e.textContent = text; return e; };
  /** the first blocks of a mode run, drawn: boxes for every value, the cipher, the XORs, and the carried value */
  V.modeFlow = function (mode, algoLabel, run, decrypt, max) {
    const blocks = run.blocks.slice(0, max || 3), n = run.blocks[0] ? run.blocks[0].p.length : 16;
    const W = 320, LEAD = 20, BW = n > 8 ? 156 : 140, BH = n > 8 ? 46 : 32;
    const H = 362, width = LEAD + blocks.length * W + 10;
    const svg = el('svg', { viewBox: '0 0 ' + width + ' ' + H, width: String(width), height: String(H), class: 'mflow', role: 'img', 'aria-label': mode.toUpperCase() + ' data flow, first ' + blocks.length + ' blocks' });
    const lines = (b) => { const t = hex(b); return t.length > 16 ? [t.slice(0, 16), t.slice(16, 32)] : [t]; };
    const box = (x, y, label, bytes, cls) => {
      const g = el('g', { class: 'mf-box ' + (cls || '') });
      g.appendChild(el('rect', { x: x - BW / 2, y, width: BW, height: BH, rx: 7, class: 'mf-rect', 'data-audit': 'node' }));
      lines(bytes).forEach((t, i, a) => g.appendChild(el('text', { x, y: y + BH / 2 + 5 + (i - (a.length - 1) / 2) * 15, 'text-anchor': 'middle', class: 'mf-hex' }, t)));
      g.appendChild(el('text', { x: x - BW / 2 + 2, y: y - 6, class: 'mf-lab' }, label));
      svg.appendChild(g);
    };
    const wire = (pts, cls) => svg.appendChild(el('path', { d: 'M' + pts.map((p) => p.join(',')).join('L'), class: 'mf-wire ' + (cls || ''), 'marker-end': 'url(#mfArrow)', 'data-audit': 'edge' }));
    const defs = el('defs', {}); const mk = el('marker', { id: 'mfArrow', viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '7', markerHeight: '7', orient: 'auto-start-reverse' }); mk.appendChild(el('path', { d: 'M0,0L10,5L0,10z', class: 'mf-head' })); defs.appendChild(mk); svg.appendChild(defs);
    const cipherBox = (cx, y, i) => { svg.appendChild(el('rect', { x: cx - 56, y, width: 112, height: 34, rx: 8, class: 'mf-cipher', 'data-audit': 'node' })); svg.appendChild(el('text', { x: cx, y: y + 22, 'text-anchor': 'middle', class: 'mf-ctext' }, (decrypt && (mode === 'ecb' || mode === 'cbc') ? 'D' : 'E') + ' · ' + algoLabel)); void i; };
    const xorAt = (cx, cy) => { svg.appendChild(el('circle', { cx, cy, r: 12, class: 'mf-xor', 'data-audit': 'node' })); svg.appendChild(el('path', { d: `M${cx - 7},${cy}H${cx + 7}M${cx},${cy - 7}V${cy + 7}`, class: 'mf-plus', 'data-audit': 'ignore' })); };
    const IN = decrypt ? 'C' : 'P', OUT = decrypt ? 'P' : 'C';
    blocks.forEach((b, k) => {
      const x0 = LEAD + k * W, cx = x0 + 190, j = b.i + 1;
      const yTop = 26, yE = 120, yX = 214, yOut = 300;
      if (mode === 'ecb') {
        box(cx, yTop, IN + j, b.p); cipherBox(cx, yE, k); box(cx, yOut, OUT + j, b.c, 'out');
        wire([[cx, yTop + BH], [cx, yE]]); wire([[cx, yE + 34], [cx, yOut]], 'act');
      } else if (mode === 'cbc' && !decrypt) {
        box(cx, yTop, 'P' + j, b.p); xorAt(cx, 100); cipherBox(cx, 150, k); box(cx, yOut, 'C' + j, b.c, 'out');
        wire([[cx, yTop + BH], [cx, 88]]); wire([[cx, 112], [cx, 150]]); wire([[cx, 184], [cx, yOut]], 'act');
        if (k === 0) { box(x0 + 80, 100 - BH / 2, 'IV', b.prev, 'iv'); wire([[x0 + 80 + BW / 2, 100], [cx - 12, 100]], 'carry'); }
        if (k + 1 < blocks.length) { const nx = x0 + W - 36; svg.appendChild(el('circle', { cx, cy: 242, r: 3.5, class: 'mf-dot', 'data-audit': 'ignore' })); wire([[cx, 242], [nx, 242], [nx, 100], [x0 + W + 190 - 12, 100]], 'carry'); }
      } else if (mode === 'cbc') {
        box(cx, yTop, 'C' + j, b.p); cipherBox(cx, 110, k); xorAt(cx, yX); box(cx, yOut, 'P' + j, b.c, 'out');
        wire([[cx, yTop + BH], [cx, 110]]); wire([[cx, 144], [cx, yX - 12]]); wire([[cx, yX + 12], [cx, yOut]], 'act');
        if (k === 0) { box(x0 + 80, yX - BH / 2, 'IV', b.prev, 'iv'); wire([[x0 + 80 + BW / 2, yX], [cx - 12, yX]], 'carry'); }
        if (k + 1 < blocks.length) { const nx = x0 + W - 36; wire([[cx + BW / 2, yTop + BH / 2], [nx, yTop + BH / 2], [nx, yX], [x0 + W + 190 - 12, yX]], 'carry'); }
      } else {
        // CFB, OFB, CTR: the cipher runs on the top value; its output is XORed with the input
        const topLab = mode === 'ctr' ? 'ctr ' + (j + (run.gcm ? 1 : 0)) : k === 0 ? 'IV' : mode === 'ofb' ? 'O' + (j - 1) : 'C' + (j - 1);
        box(cx, yTop, topLab, b.cin, mode === 'ctr' ? 'ctr' : 'iv'); cipherBox(cx, 100, k); xorAt(cx, yX);
        box(x0 + 64, yX - BH / 2, IN + j, b.p); box(cx, yOut, OUT + j, b.c, 'out');
        wire([[cx, yTop + BH], [cx, 100]]); wire([[cx, 134], [cx, yX - 12]], 'ks'); wire([[x0 + 64 + BW / 2, yX], [cx - 12, yX]]); wire([[cx, yX + 12], [cx, yOut]], 'act');
        if (k + 1 < blocks.length && mode !== 'ctr') {
          const nx = x0 + W - 36, ny = yTop + BH / 2;
          const sy = mode === 'ofb' ? 168 : yOut + BH + 14, sx = cx;
          if (mode === 'cfb') wire([[cx, yOut + BH], [cx, sy], [nx, sy], [nx, ny], [x0 + W + 190 - BW / 2, ny]], 'carry');
          else { svg.appendChild(el('circle', { cx: sx, cy: sy, r: 3.5, class: 'mf-dot', 'data-audit': 'ignore' })); wire([[sx, sy], [sx + 70, sy], [sx + 70, 82], [nx, 82], [nx, ny], [x0 + W + 190 - BW / 2, ny]], 'carry'); }
        }
      }
    });
    if (mode === 'cfb' && blocks.length > 1) svg.setAttribute('viewBox', '0 0 ' + width + ' ' + (H + 26)), svg.setAttribute('height', String(H + 26));
    const wrap = h('div.mflow-wrap', { id: 'cbFlow' }, svg);
    requestAnimationFrame(() => S.UI.scrollRow(wrap));
    return wrap;
  };

  /** every block of a mode run as a table */
  V.modeTable = function (mode, run, decrypt) {
    const IN = decrypt ? 'C' : 'P', OUT = decrypt ? 'P' : 'C';
    if (mode === 'xts') {
      const xc = ['tweak T·α^j', IN + ' ⊕ T', decrypt ? 'D(·)' : 'E(·)', OUT];
      const xr = run.blocks.map((b) => h('tr', h('td', { dataset: { label: 'block' } }, String(b.i + 1)), ...[b.T ? hex(b.T) : '—', b.stolen ? 'stolen' : hex(b.cin), b.stolen ? 'stolen' : hex(b.cout), hex(b.c)].map((v, k) => h('td.mono', { dataset: { label: xc[k] } }, v))));
      return h('div.b-scroll.fit-table', { id: 'cbBlocks' }, h('table.b-table', h('thead', h('tr', h('th', '#'), ...xc.map((c) => h('th', c)))), h('tbody', xr)));
    }
    if (mode === 'gcm') mode = 'ctr';
    if (mode === 'cfb8') {
      const cc = ['register', 'E(register)', 'keystream byte', IN, OUT];
      return h('div.b-scroll.fit-table', { id: 'cbBlocks' }, h('table.b-table', h('thead', h('tr', h('th', 'byte'), ...cc.map((c) => h('th', c)))), h('tbody', run.blocks.map((b) => h('tr', h('td', { dataset: { label: 'byte' } }, String(b.i + 1)), ...[b.cin, b.cout, b.ks, b.p, b.c].map((v, k) => h('td.mono', { dataset: { label: cc[k] } }, hex(v))))))));
    }
    const cols = mode === 'ecb' ? [IN, 'cipher out', OUT] : mode === 'cbc' ? (decrypt ? ['C', 'D(C)', '⊕ previous', 'P'] : ['P', '⊕ previous', 'into E', 'C']) : [mode === 'ctr' ? 'counter' : 'into E', 'keystream', IN, OUT];
    const rows = run.blocks.map((b) => {
      const cells = mode === 'ecb' ? [b.p, b.cout, b.c] : mode === 'cbc' ? (decrypt ? [b.p, b.cout, b.prev, b.c] : [b.p, b.prev, b.x, b.c]) : [b.cin, b.ks, b.p, b.c];
      return h('tr', h('td', { dataset: { label: 'block' } }, String(b.i + 1)), ...cells.map((v, k) => h('td.mono', { dataset: { label: cols[k] } }, hex(v))));
    });
    return h('div.b-scroll.fit-table', { id: 'cbBlocks' }, h('table.b-table', h('thead', h('tr', h('th', '#'), ...cols.map((c) => h('th', c)))), h('tbody', rows)));
  };

  /** Trivium's three registers as rows of bit cells */
  V.registers = function (bits) {
    const reg = (name, a, b) => h('div.treg', h('span.tr-name', name + ' · ' + (b - a) + ' bits'), h('div.tr-bits', ...bits.slice(a, b).map((v) => h('i' + (v ? '.on' : '')))));
    return h('div.tregs', { id: 'cbRegisters', role: 'img', 'aria-label': 'Trivium registers after the warm-up' }, reg('A (s1–s93)', 0, 93), reg('B (s94–s177)', 93, 177), reg('C (s178–s288)', 177, 288));
  };
})(globalThis.Sifer = globalThis.Sifer || {});
