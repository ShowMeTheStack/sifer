// Tables to fill in: an AES-style state, a round of a cipher, or any table an exercise spells out.
// S.Check.tableSpec(x) gives the layout and the expected value of every cell, and the checker compares cell by cell. More kinds of table register in S.Check.tables:
//   S.Check.tables.mykind = (x) => ({ rows, cols, corner, cell(r, c) -> key | null, expected: {key: text}, kind })
// kind 'text' compares text (case and spaces ignored), 'hex' a value in hex (0x, spaces and case ignored, leading
// zeros kept), 'bit' a single 0 or 1, 'set' a list like a, b.
(function (S) {
  'use strict';
  const K = (S.Check = S.Check || {});
  K.kinds = K.kinds || {};
  K.tables = K.tables || {};

  /** a custom table: rows, cols and cells {"row|col": expected} given by the exercise */
  K.tables.custom = (x) => {
    const cells = x.cells || {};
    return { rows: x.rows, cols: x.cols, corner: x.corner || '', cell: (r, c) => { const k = x.rows[r] + '|' + x.cols[c]; return k in cells ? k : null; }, expected: Object.fromEntries(Object.entries(cells).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : String(v)])), kind: x.cellKind || 'text' };
  };
  /**
   * a 4×4 byte state (AES; Mini-AES-style nibbles with nibbles: true), or with dim: 2 the 2×2 nibble state of
   * Mini-AES: state is hex in column order (s[r + n·c] is row r, column c, as the standards lay it out); give:
   * [indexes] are shown filled in
   */
  K.tables.state = (x) => {
    const n = x.dim === 2 ? 2 : 4, w = x.nibbles || n === 2 ? 1 : 2, hex = String(x.state).replace(/\s+/g, '').toLowerCase();
    const rows = Array.from({ length: n }, (_, i) => 'r' + i), cols = Array.from({ length: n }, (_, i) => 'c' + i), given = new Set(x.give || []);
    if (hex.length !== n * n * w) throw new Error('a ' + n + '×' + n + ' state needs ' + n * n * w + ' hex digits, not ' + hex.length);
    const expected = {};
    for (let c = 0; c < n; c++) for (let r = 0; r < n; r++) { const i = r + n * c; if (!given.has(i)) expected[rows[r] + '|' + cols[c]] = hex.slice(i * w, i * w + w); }
    return { rows, cols, corner: x.corner || '', cell: (r, c) => { const k = rows[r] + '|' + cols[c]; return k in expected ? k : null; }, expected, kind: 'hex', given: Object.fromEntries([...given].map((i) => [rows[i % n] + '|' + cols[Math.floor(i / n)], hex.slice(i * w, i * w + w)])) };
  };

  K.tableSpec = function (x) {
    const make = K.tables[x.table || 'custom'];
    if (!make) throw new Error('unknown table ' + x.table);
    return make(x);
  };

  // a minus sign typed as U+2212 (or a dash) reads the same as a hyphen-minus
  K.unminus = (t) => String(t === undefined || t === null ? '' : t).replace(/[\u2212\u2012\u2013\uFE63\uFF0D]/g, '-');
  const sameSet = (a, b) => { const A = K.asSet(a), B = K.asSet(b); return A.length === B.length && A.every((v, i) => v === B[i]); };
  const hexOf = (t) => String(t === undefined ? '' : t).trim().toLowerCase().replace(/^0x/, '').replace(/[\s:_]/g, '');
  K.cellRight = function (kind, want, got) {
    want = K.unminus(want); got = K.unminus(got);
    if (kind === 'set') return sameSet(want, got);
    if (kind === 'hex') return hexOf(want) === hexOf(got) || (hexOf(got).length < hexOf(want).length && hexOf(got) !== '' && hexOf(got).padStart(hexOf(want).length, '0') === hexOf(want) && /^[0-9a-f]+$/.test(hexOf(got)));
    if (kind === 'bit') return String(want).trim().toUpperCase() === String(got === undefined ? '' : got).trim().toUpperCase();
    return String(want).trim().replace(/\s+/g, ' ').toLowerCase() === String(got === undefined ? '' : got).trim().replace(/\s+/g, ' ').toLowerCase();
  };

  K.kinds.table = {
    check(x, a) {
      a = a || {};
      const SP = K.tableSpec(x);
      const keys = Object.keys(SP.expected);
      const cells = {};
      let wrong = 0, empty = 0;
      for (const k of keys) {
        const got = a[k] === undefined ? '' : String(a[k]);
        if (!got.trim() && SP.expected[k] !== '') empty++;
        cells[k] = K.cellRight(SP.kind, SP.expected[k], got);
        if (!cells[k]) wrong++;
      }
      if (!wrong) return { ok: true, cells, message: 'Every one of the ' + keys.length + ' cells is right.' };
      const details = [];
      if (empty) details.push(K.plural(empty, 'cell is', 'cells are') + ' still empty.');
      if (SP.kind === 'set') details.push('A set is written like a, b; leave a cell empty for the empty set.');
      if (SP.kind === 'bit') details.push('Each cell holds 0 or 1.');
      if (SP.kind === 'hex') details.push('Each cell holds a value in hex, like 3f.');
      return { ok: false, cells, message: K.plural(wrong, 'cell is', 'cells are') + ' not right yet (marked in red).', details };
    },
  };
})(globalThis.Sifer = globalThis.Sifer || {});
