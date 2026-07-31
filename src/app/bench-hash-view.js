// What the hash bench draws: the Merkle–Damgård chain (the IV, each block through the compression function, the
// chaining values, the digest), a compression function's registers round by round, the sponge's 5×5 lanes before and
// after absorbing a block, and HMAC's two nested hashes.
(function (S) {
  'use strict';
  const { h } = S.UI;
  const HB = (S.HashBench = S.HashBench || {});
  const V = (HB.view = HB.view || {});
  const NS = 'http://www.w3.org/2000/svg';
  const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
  const word = (v) => (typeof v === 'number' ? (v >>> 0).toString(16).padStart(8, '0') : typeof v === 'bigint' ? v.toString(16).padStart(16, '0') : String(v));
  const el = (t, a, x) => { const e = document.createElementNS(NS, t); for (const k in a) e.setAttribute(k, a[k]); if (x !== undefined) e.textContent = x; return e; };
  HB.hex = hex; HB.word = word;
  /** a chaining value as text: words joined, cut to n characters */
  const cvText = (cv, n) => { const t = (cv || []).map(word).join(''); return n && t.length > n ? t.slice(0, n) + '…' : t; };
  HB.cvText = cvText;

  /** the chain: IV → f(block 1) → CV1 → … → digest, at most `max` blocks drawn (the rest are said) */
  V.chain = function (run, name, max) {
    const blocks = run.blocks.slice(0, max || 4), more = run.blocks.length - blocks.length;
    const CW = 128, FW = 118, GAP = 34, y = 92, BH = 46;
    const step = CW + GAP + FW + GAP;
    const width = 24 + blocks.length * step + CW + (more ? 90 : 0) + 24, H = 162;
    const svg = el('svg', { width: String(width), height: String(H), viewBox: `0 0 ${width} ${H}`, class: 'hchain', role: 'img', 'aria-label': 'The Merkle–Damgård chain of ' + name });
    const defs = el('defs'), mk = el('marker', { id: 'hcArrow', viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '7', markerHeight: '7', orient: 'auto' });
    mk.appendChild(el('path', { d: 'M0,0L10,5L0,10z', class: 'hc-head' })); defs.appendChild(mk); svg.appendChild(defs);
    const box = (x, label, value, cls) => {
      svg.appendChild(el('rect', { x, y, width: CW, height: BH, rx: 8, class: 'hc-cv ' + (cls || ''), 'data-audit': 'node' }));
      svg.appendChild(el('text', { x: x + CW / 2, y: y + BH / 2 + 5, 'text-anchor': 'middle', class: 'hc-hex' }, value));
      svg.appendChild(el('text', { x: x + 2, y: y - 7, class: 'hc-lab' }, label));
    };
    const wire = (x1, y1, x2, y2, cls) => svg.appendChild(el('path', { d: `M${x1},${y1}L${x2},${y2}`, class: 'hc-wire ' + (cls || ''), 'marker-end': 'url(#hcArrow)', 'data-audit': 'edge' }));
    let x = 24;
    box(x, 'IV', cvText(run.blocks[0] ? run.blocks[0].cvIn : [], 12), 'iv');
    blocks.forEach((b, k) => {
      const fx = x + CW + GAP;
      wire(x + CW, y + BH / 2, fx, y + BH / 2);
      svg.appendChild(el('rect', { x: fx, y: y - 4, width: FW, height: BH + 8, rx: 10, class: 'hc-f', 'data-audit': 'node' }));
      svg.appendChild(el('text', { x: fx + FW / 2, y: y + BH / 2 + 5, 'text-anchor': 'middle', class: 'hc-ftext' }, 'compress'));
      const mx = fx + FW / 2;
      svg.appendChild(el('rect', { x: fx + 4, y: 14, width: FW - 8, height: 30, rx: 6, class: 'hc-m' + (b.hasPad || b.lengthBlock ? ' pad' : ''), 'data-audit': 'node' }));
      svg.appendChild(el('text', { x: mx, y: 34, 'text-anchor': 'middle', class: 'hc-mtext' }, 'block ' + (b.i + 1) + (b.lengthBlock ? ' + len' : b.hasPad ? ' + pad' : '')));
      wire(mx, 44, mx, y - 4, 'msg');
      const nx = fx + FW + GAP;
      wire(fx + FW, y + BH / 2, nx, y + BH / 2, 'act');
      const last = k === run.blocks.length - 1;
      box(nx, last ? 'digest' : 'CV' + (b.i + 1), cvText(b.cvOut, 12), last ? 'out' : '');
      x = nx;
    });
    if (more) svg.appendChild(el('text', { x: x + CW + 14, y: y + BH / 2 + 5, class: 'hc-lab' }, '+ ' + more + ' more'));
    const wrap = h('div.hchain-wrap', { id: 'hbChain' }, svg);
    const note = h('p.b-note', 'Each compression takes the chaining value and one ' + (run.blocks[0] ? run.blocks[0].block.length : 64) + '-byte block; the last chaining value is the digest.');
    requestAnimationFrame(() => S.UI.scrollRow(wrap));
    return h('div.hchain-box', wrap, note);
  };

  const REGS = { md5: ['A', 'B', 'C', 'D'], sha1: ['a', 'b', 'c', 'd', 'e'], sha256: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'], sha224: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'] };
  /** the registers after every round of one block's compression; the registers a round computes are lit */
  V.rounds = function (block, name) {
    const rows = block.rounds || [];
    const names = REGS[name] || ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];
    const extra = name === 'md5' ? ['f', 'g', 's'] : name === 'sha1' ? ['f', 'W'] : rows[0] && rows[0].W !== undefined ? ['W', 'K'] : [];
    const fresh = name === 'md5' ? [1] : name === 'sha1' ? [0] : [0, 4];
    const head = h('tr', h('th', 'round'), ...names.map((n) => h('th.mono', n)), ...extra.map((n) => h('th.mono', n)));
    const body = rows.map((r) => {
      const t = r.t !== undefined ? r.t : r.i;
      const regs = r.regs || [];
      return h('tr', h('td', String(t)), ...names.map((_, k) => h('td.mono' + (fresh.includes(k) ? '.fresh' : ''), word(regs[k]))),
        ...extra.map((n) => h('td.mono', n === 'f' && r.fname ? r.fname : n === 's' || n === 'g' ? String(r[n]) : word(r[n]))));
    });
    return h('div.b-scroll.fit-table.hb-rounds', { id: 'hbRounds' }, h('table.b-table', h('thead', head), h('tbody', body)));
  };
  /** the 25 lanes of the sponge as a 5×5 grid, lanes in the rate lit */
  V.lanes = function (lanes, rateLanes, prev) {
    const g = h('div.lanes', { role: 'group', 'aria-label': 'The 5×5 lanes of the state' });
    for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) { const i = x + 5 * y; g.appendChild(h('span.lane' + (i < rateLanes ? '.rate' : '.cap') + (prev && prev[i] !== lanes[i] ? '.diff' : ''), { title: 'lane (' + x + ', ' + y + ')' + (i < rateLanes ? ', in the rate' : ', in the capacity') }, lanes[i].slice(0, 8) + '…')); }
    return g;
  };
  /** HMAC: the key padded, XORed with ipad and opad, and the two hashes nested */
  V.hmac = function (t, name, msgLen) {
    const row = (label, v, cls) => h('div.hm-row' + (cls ? '.' + cls : ''), h('span.hm-k', label), h('code.hm-v', v));
    const sh = (b, n) => { const x = hex(b); return x.length > (n || 64) ? x.slice(0, n || 64) + '…' : x; };
    return h('div.hmac', { id: 'hbHmac' },
      h('div.hm-step', h('div.hm-n', '1'), h('div', h('b', 'The key, padded to one block'), row('K₀', sh(t.k0), 'key'))),
      h('div.hm-step', h('div.hm-n', '2'), h('div', h('b', 'Inner hash: ' + name + '((K₀ ⊕ ipad) ‖ message)'), row('K₀ ⊕ 36…36', sh(t.ipadKey), 'key'), row('‖ message', msgLen + ' bytes'), row('inner', hex(t.inner), 'act'))),
      h('div.hm-step', h('div.hm-n', '3'), h('div', h('b', 'Outer hash: ' + name + '((K₀ ⊕ opad) ‖ inner)'), row('K₀ ⊕ 5c…5c', sh(t.opadKey), 'key'), row('‖ inner', hex(t.inner)), row('tag', hex(t.tag), 'out'))));
  };
})(globalThis.Sifer = globalThis.Sifer || {});
