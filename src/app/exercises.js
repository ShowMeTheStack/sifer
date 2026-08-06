// The answer areas of the cryptographic exercise kinds: hex with a live byte count, a code editor whose tests run in
// the sandbox (the first failing case shown, with the console), a flag box, and "break it" with the ciphertext or
// data at hand. Each is S.ExerciseViews.kind = (x, host, draft, page) -> { get(), mark(result)?, after(result, box)? };
// lessons.js calls it. S.ExWidgets holds the pieces other pages share (the code editor, the cases table).
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const W = (S.ExWidgets = S.ExWidgets || {});
  const V = (S.ExerciseViews = S.ExerciseViews || {});
  const K = () => S.Check;

  /** a text box for code: monospaced, keeps every space and line, Tab indents, Ctrl+Enter runs */
  W.codeArea = function (text, opts) {
    opts = opts || {};
    const ta = h('textarea.mono.code-area', { id: opts.id || 'ansCode', spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off', 'aria-label': opts.label || 'Your code', placeholder: opts.placeholder || '', rows: String(opts.rows || 12), wrap: 'soft' });
    ta.value = text || '';
    ta.addEventListener('keydown', (e) => {
      if (e.key === 'Tab' && !e.shiftKey) { e.preventDefault(); if (!document.execCommand('insertText', false, '  ')) { const a = ta.selectionStart; ta.value = ta.value.slice(0, a) + '  ' + ta.value.slice(ta.selectionEnd); ta.selectionStart = ta.selectionEnd = a + 2; } }
      else if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && opts.onRun) { e.preventDefault(); opts.onRun(); }
    });
    return ta;
  };
  /** the cases of a sandbox run as a table: each test, what it was given, what came back, and a mark */
  W.casesTable = function (x, cases, total) {
    const SB = S.Sandbox;
    const rows = cases.map((c) => h('tr.' + (c.pass ? 'pass' : 'fail'),
      h('td', String(c.i + 1)), h('td.mono', x.fn + '(' + c.args.map((v) => SB.show(v)).join(', ') + ')'),
      h('td.mono', c.error ? 'threw ' + c.error : 'got' in c ? SB.show(c.got) : '—'), h('td.mono', SB.show(c.want)),
      h('td.mark', c.pass ? icon('check') : icon('x'))));
    const more = total > cases.length ? h('tr.rest', h('td', { colspan: '5' }, (total - cases.length) + ' more test' + (total - cases.length === 1 ? '' : 's') + ' not run (the first failure stops the run)')) : null;
    return h('div.fit-table.cases', h('table.cases-table', h('thead', h('tr', h('th', '#'), h('th', 'Call'), h('th', 'Returned'), h('th', 'Wanted'), h('th', ''))), h('tbody', rows, more)));
  };
  W.logBox = (logs) => (logs && logs.length ? h('details.logs', { open: true }, h('summary', 'Console (' + logs.length + ' line' + (logs.length === 1 ? '' : 's') + ')'), h('pre.mono', logs.join('\n'))) : null);

  // ---- hex -----------------------------------------------------------------------------------------------------------
  V.hex = V.bytes = function (x, host, draft) {
    const i = h('input.mono', { type: 'text', id: 'ansText', 'aria-label': 'Your answer in hex', placeholder: x.placeholder || 'hex, like 3a 7f 00 c2', spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off' });
    if (typeof draft === 'string') i.value = draft;
    const count = h('span.hex-count', { 'aria-live': 'polite' });
    const want = [].concat(x.answer)[0];
    const n = want ? K().readHex(want).hex.length / 2 : 0;
    const upd = () => { const r = K().readHex(i.value); count.textContent = !i.value.trim() ? (n && !x.value ? n + ' bytes wanted' : '') : r.error ? r.error : (r.hex.length % 2 ? r.hex.length + ' hex digits' : r.hex.length / 2 + ' byte' + (r.hex.length === 2 ? '' : 's')) + (n && !x.value ? ' of ' + n : ''); count.classList.toggle('bad', !!(i.value.trim() && r.error)); };
    i.addEventListener('input', upd);
    i.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); document.getElementById('btnCheck').click(); } });
    host.appendChild(h('label.ans-line', h('span', 'Your answer'), i));
    host.appendChild(h('p.muted.ans-note', count));
    upd();
    return { get: () => i.value };
  };

  // ---- code ------------------------------------------------------------------------------------------------------------
  /** the helper code a task hands the student (x.prelude): read-only, above the editor, run before their code */
  W.preludeBox = function (x) {
    if (!x.prelude) return null;
    const src = String(x.prelude).replace(/\n+$/, '');
    const lines = src.split('\n').length;
    const names = x.preludeNames || [...new Set([...src.matchAll(/^(?:function\s+([A-Za-z_$][\w$]*)|const\s+([A-Za-z_$][\w$]*)\s*=)/gm)].map((m) => m[1] || m[2]))];
    return h('details.code-prelude', { open: lines <= 12 ? '' : null },
      h('summary', 'Given code, read-only: ' + names.join(', ') + ' (' + lines + ' line' + (lines === 1 ? '' : 's') + ', run before yours)'),
      h('pre.mono', { 'aria-label': 'Given code (read-only)' }, src));
  };
  V.code = function (x, host, draft) {
    const ta = W.codeArea(typeof draft === 'string' ? draft : x.start || 'function ' + x.fn + '(' + (x.params || []).join(', ') + ') {\n  \n}\n', { onRun: () => document.getElementById('btnCheck').click() });
    const pre = W.preludeBox(x);
    if (pre) host.appendChild(pre);
    host.appendChild(h('div.code-wrap', ta));
    host.appendChild(h('p.muted.ans-note', 'Plain JavaScript (BigInt literals like 5n work). It runs in a sealed worker with no page and no network, for at most ' + ((x.timeLimit || 2000) / 1000) + ' s. Ctrl+Enter checks.'));
    requestAnimationFrame(() => S.UI.autosize(ta, 520));
    let extra = null;
    return {
      get: () => ta.value,
      after(r, box) {
        if (extra) extra.remove();
        let tests = [];
        try { tests = K().codeTests(x); } catch (e) { /* none */ }
        extra = h('div.code-res', r.cases && r.cases.length ? W.casesTable(x, r.cases, tests.length) : null, W.logBox(r.logs));
        box.appendChild(extra);
      },
    };
  };

  // ---- a flag ------------------------------------------------------------------------------------------------------------
  V.flag = function (x, host, draft) {
    const i = h('input.mono', { type: 'text', id: 'ansText', 'aria-label': 'The flag', placeholder: K().flagShape(x.format).text, spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off' });
    if (typeof draft === 'string') i.value = draft;
    i.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); document.getElementById('btnCheck').click(); } });
    host.appendChild(h('label.ans-line', h('span', icon('flag'), 'Flag'), i));
    return { get: () => i.value };
  };

  // ---- break it ------------------------------------------------------------------------------------------------------------
  V.break = function (x, host, draft) {
    if (x.data) for (const [label, value] of Object.entries(x.data)) host.appendChild(h('div.break-data', h('span.bd-label', label), h('code.bd-value', String(value))));
    const long = x.normalize === 'letters' || x.normalize === 'text' || x.normalize === 'caseless';
    const i = long ? h('textarea.mono', { id: 'ansText', rows: '3', 'aria-label': 'The ' + (x.target || 'answer') + ' you recovered', spellcheck: 'false', placeholder: x.placeholder || '' }) : h('input.mono', { type: 'text', id: 'ansText', 'aria-label': 'The ' + (x.target || 'answer') + ' you recovered', placeholder: x.placeholder || '', spellcheck: 'false', autocomplete: 'off' });
    if (typeof draft === 'string') i.value = draft;
    if (!long) i.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); document.getElementById('btnCheck').click(); } });
    host.appendChild(h('label.ans-line' + (long ? '.tall' : ''), h('span', 'Recovered ' + (x.target || 'answer')), i));
    if (x.tool) host.appendChild(h('p.muted.ans-note', icon('cipher'), ' ', S.UI.inline(x.tool)));
    return { get: () => i.value };
  };

  // ---- a table with a state: drawn as the 4×4 grid it is -------------------------------------------------------------------
  const tableView = function (x, host, draft) {
    const SP = K().tableSpec(x);
    const inputs = {};
    const grid = h('div.state-fill', { role: 'group', 'aria-label': 'The state, four rows of four bytes' });
    SP.rows.forEach((r, ri) => SP.cols.forEach((c, ci) => {
      const key = r + '|' + c, given = SP.given && SP.given[key];
      if (given !== undefined) { grid.appendChild(h('div.sf-cell.given.mono', given)); return; }
      const i = h('input.mono', { type: 'text', maxlength: x.nibbles ? '1' : '2', 'aria-label': 'Row ' + ri + ', column ' + ci, spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off', dataset: { key } });
      if (draft && draft[key] !== undefined) i.value = draft[key];
      i.addEventListener('input', () => { if (i.value.length === +i.maxLength) { const all = [...grid.querySelectorAll('input')]; const n = all[all.indexOf(i) + 1]; if (n) n.focus(); } });
      inputs[key] = i;
      grid.appendChild(h('div.sf-cell', i));
    }));
    host.appendChild(h('div.state-wrap', h('div.sf-rows', ...SP.rows.map((r, i) => h('span', 'row ' + i))), grid));
    host.appendChild(h('p.muted.ans-note', 'Bytes in hex, two digits each' + (x.nibbles ? ' (here one hex digit: a nibble)' : '') + '. Typing moves on to the next cell.'));
    return { get: () => Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, i.value])), mark(r) { for (const [k, i] of Object.entries(inputs)) { i.classList.toggle('right', !!(r.cells && r.cells[k])); i.classList.toggle('wrong', !!(r.cells && !r.cells[k])); } } };
  };
  V.stateTable = tableView;
})(globalThis.Sifer = globalThis.Sifer || {});
