// The avalanche: the same cipher on two inputs that differ in one bit. Round by round, a heat map shows how many bits
// of each byte (or word) now differ, and a curve shows the total, against the line at half of all bits, where two
// unrelated blocks sit. A stream cipher shows why it needs a fresh nonce: flip a plaintext bit and exactly one
// ciphertext bit flips; flip a key or nonce bit and the whole keystream changes.
//   S.CipherBench.avalanche(algo, inputs, target, bit) -> {rows: [{label, a, b, diff: [per cell], bits, total}], cell, note}
//   S.CipherBench.view.avalanche(result, o) -> element
(function (S) {
  'use strict';
  const { h } = S.UI;
  const CB = (S.CipherBench = S.CipherBench || {});
  const pop = (x) => { let n = 0; while (x) { n += x & 1; x >>>= 1; } return n; };
  const flip = (b, bit) => { const o = Uint8Array.from(b); o[bit >> 3] ^= 0x80 >> (bit & 7); return o; };
  CB.flip = flip;

  /** inputs = {block, key, iv, text (bytes)}; target 'plaintext' | 'key' | 'iv' */
  CB.avalanche = function (algo, inputs, target, bit) {
    const src = target === 'key' ? inputs.key : target === 'iv' ? inputs.iv : algo.kind === 'block' ? inputs.block : inputs.text;
    if (!src || !src.length) throw new Error('The input must not be empty: there is nothing to flip a bit in.');
    bit = Math.max(0, Math.min(src.length * 8 - 1, bit | 0));
    const A = Object.assign({}, inputs), B = Object.assign({}, inputs);
    const key = target === 'key' ? 'key' : target === 'iv' ? 'iv' : algo.kind === 'block' ? 'block' : 'text';
    B[key] = flip(src, bit);
    let sa, sb, cell = 1, note = '';
    if (algo.kind === 'block') {
      sa = algo.roundsOf(A.block, A.key).states; sb = algo.roundsOf(B.block, B.key).states;
      note = algo.n === 2 ? 'A 16-bit block: half is 8 bits.' : 'Half of the ' + algo.n * 8 + ' bits is ' + algo.n * 4 + '.';
    } else if (algo.rounds && target !== 'plaintext') {
      sa = algo.rounds(A.key, A.iv); sb = algo.rounds(B.key, B.iv); cell = 4;
      note = 'The 64-byte block function, word by word (32 bits each).';
    } else {
      const ra = algo.run(A.key, A.iv, A.text), rb = algo.run(B.key, B.iv, B.text);
      const n = Math.min(32, ra.out.length);
      sa = [{ label: 'Keystream', bytes: ra.keystream.slice(0, n) }, { label: 'Ciphertext', bytes: ra.out.slice(0, n) }];
      sb = [{ label: 'Keystream', bytes: rb.keystream.slice(0, n) }, { label: 'Ciphertext', bytes: rb.out.slice(0, n) }];
      note = target === 'plaintext' ? 'A stream cipher XORs the keystream into the text, so one flipped plaintext bit flips exactly one ciphertext bit: no diffusion at all.' : 'The first ' + n + ' bytes.';
    }
    const rows = sa.map((s, k) => {
      const a = s.bytes, b = sb[k].bytes, diff = [];
      let total = 0;
      for (let i = 0; i < a.length; i += cell) { let d = 0; for (let j = i; j < i + cell && j < a.length; j++) d += pop(a[j] ^ b[j]); diff.push(d); total += d; }
      return { label: s.label, a, b, diff, total, bits: a.length * 8 };
    });
    return { rows, cell, note, bit, target, src, srcBits: src.length * 8, view: cell === 4 ? 'words' : algo.view };
  };

  const V = (CB.view = CB.view || {});
  /** a heat cell's class: h0 … h8 by the share of its bits that differ */
  const heat = (d, of) => 'h' + Math.min(8, Math.round((8 * d) / of));
  V.heatGrid = function (row, res) {
    const of = res.cell * 8, n = row.diff.length;
    const cols = res.view === 'aes' && n === 16 ? 4 : res.view === 'words' ? 4 : Math.min(8, n);
    const order = res.view === 'aes' && n === 16 ? [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15] : row.diff.map((_, i) => i);
    const g = h('div.heat', { style: { gridTemplateColumns: 'repeat(' + cols + ', 1fr)' }, role: 'img', 'aria-label': row.label + ': ' + row.total + ' of ' + row.bits + ' bits differ' });
    for (const i of order) g.appendChild(h('span.hc.' + heat(row.diff[i], of), { title: row.diff[i] + ' of ' + of + ' bits differ' }, String(row.diff[i])));
    return g;
  };
  /** the total per round as a curve, drawn at its own pixel size (never scaled down) */
  V.curve = function (res, width) {
    const NS = 'http://www.w3.org/2000/svg', el = (t, a, x) => { const e = document.createElementNS(NS, t); for (const k in a) e.setAttribute(k, a[k]); if (x !== undefined) e.textContent = x; return e; };
    const W = Math.max(300, Math.min(760, width || 640)), H = 230, L = 46, R = 16, T = 18, B = 40;
    const rows = res.rows, max = rows[0] ? rows[0].bits : 128, n = rows.length;
    const X = (i) => L + (n > 1 ? (i * (W - L - R)) / (n - 1) : 0), Y = (v) => T + (H - T - B) * (1 - v / max);
    const svg = el('svg', { width: String(W), height: String(H), viewBox: `0 0 ${W} ${H}`, class: 'aval-curve', role: 'img', 'aria-label': 'Bits that differ, round by round' });
    svg.appendChild(el('line', { x1: L, y1: Y(0), x2: W - R, y2: Y(0), class: 'ac-axis' }));
    svg.appendChild(el('line', { x1: L, y1: T, x2: L, y2: Y(0), class: 'ac-axis' }));
    svg.appendChild(el('line', { x1: L, y1: Y(max / 2), x2: W - R, y2: Y(max / 2), class: 'ac-half', 'data-audit': 'ignore' }));
    for (const v of [0, max / 2, max]) svg.appendChild(el('text', { x: L - 7, y: Y(v) + 4, 'text-anchor': 'end', class: 'ac-tick' }, String(v)));
    svg.appendChild(el('text', { x: W - R, y: Y(max / 2) - 6, 'text-anchor': 'end', class: 'ac-note' }, 'half'));
    const step = Math.max(1, Math.ceil(n / Math.floor((W - L - R) / 34)));
    rows.forEach((r, i) => { if (i % step === 0 || i === n - 1) svg.appendChild(el('text', { x: X(i), y: H - B + 18, 'text-anchor': 'middle', class: 'ac-tick' }, String(i))); });
    svg.appendChild(el('text', { x: L + (W - L - R) / 2, y: H - 6, 'text-anchor': 'middle', class: 'ac-note' }, 'step (0 is the input)'));
    svg.appendChild(el('path', { d: rows.map((r, i) => (i ? 'L' : 'M') + X(i).toFixed(1) + ',' + Y(r.total).toFixed(1)).join(''), class: 'ac-line', 'data-audit': 'ignore' }));
    rows.forEach((r, i) => svg.appendChild(el('circle', { cx: X(i), cy: Y(r.total), r: 3.5, class: 'ac-dot', 'data-audit': 'point' }, undefined)));
    return svg;
  };
  /** the whole avalanche panel: the bit picker is drawn by the caller; this is the heat maps and the curve */
  V.avalanche = function (res, width) {
    const strip = h('div.aval-rows', { id: 'cbAvalRows' });
    for (const r of res.rows) strip.appendChild(h('div.aval-row', h('div.ar-label', h('b', r.label), h('span.ar-n', r.total + ' / ' + r.bits)), V.heatGrid(r, res)));
    const last = res.rows[res.rows.length - 1];
    const cw = h('div.aval-curve-wrap', V.curve(res, width));
    requestAnimationFrame(() => S.UI.scrollRow(cw));
    return h('div.aval', { id: 'cbAval' },
      h('p.b-note', { id: 'cbAvalSum' }, 'Bit ' + res.bit + ' of the ' + res.target + ' flipped: at the end ' + last.total + ' of ' + last.bits + ' bits differ (' + Math.round((100 * last.total) / last.bits) + '%). ' + res.note),
      cw, strip);
  };
})(globalThis.Sifer = globalThis.Sifer || {});
