// Pieces every bench is made of: a field for bytes given as text, hex or a file; labelled controls; bytes drawn as
// a grid of hex cells (changed ones lit); a trace as a numbered list with its values in the monospace face; big
// integers shown with their size; and a polite box for an engine that is still being built.
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const U = (S.BenchUI = {});
  const enc = (s) => new TextEncoder().encode(s);
  const hexOf = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');

  /** a card with a title and an optional line under it */
  U.card = (title, sub, ...kids) => h('section.card.bcard', h('div.bcard-head', h('h3', title), sub ? h('p', sub) : null), h('div.bcard-body', ...kids));
  /** a label over a control */
  U.field = (label, ctl, cls) => h('label.bfield' + (cls ? '.' + cls : ''), h('span', label), ctl);
  U.select = (id, options, value, onChange) => {
    const s = h('select', { id, 'aria-label': id }, ...options.map((o) => (o.group ? h('optgroup', { label: o.group }, ...o.items.map((x) => h('option', { value: x.value, selected: x.value === value }, x.label))) : h('option', { value: o.value, selected: o.value === value }, o.label))));
    if (onChange) s.addEventListener('change', () => onChange(s.value));
    return s;
  };
  U.input = (id, value, onInput, o) => {
    const i = h('input' + (o && o.mono !== false ? '.mono' : ''), Object.assign({ type: 'text', id, value: value === undefined ? '' : String(value), spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off', 'aria-label': (o && o.label) || id }, o && o.attrs));
    if (onInput) i.addEventListener('input', () => onInput(i.value));
    return i;
  };
  /** a segmented switch: [[value, label]] */
  U.seg = (id, items, value, onChange) => {
    const box = h('div.seg', { role: 'radiogroup', id, 'aria-label': id });
    for (const [v, l] of items) {
      const b = h('button' + (v === value ? '.on' : ''), { type: 'button', role: 'radio', 'aria-checked': String(v === value), dataset: { v } }, l);
      b.addEventListener('click', () => { for (const c of box.children) { const on = c === b; c.classList.toggle('on', on); c.setAttribute('aria-checked', String(on)); } onChange(v); });
      box.appendChild(b);
    }
    return box;
  };

  /**
   * Bytes as text, hex or a file. o = {id, label, value: {mode, text, hex}, bytes: exact length (or [min, max]),
   * onChange(state)}. Returns {el, get() -> Uint8Array (throws a sentence), state(), set(state)}.
   */
  U.bytesField = function (o) {
    let st = Object.assign({ mode: 'text', text: '', hex: '' }, o.value || {});
    let file = null;
    const info = h('span.bf-info', { 'aria-live': 'polite' });
    const ta = h('textarea.mono.bf-text', { id: o.id, rows: String(o.rows || 2), spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off', 'aria-label': o.label });
    const pick = h('button.btn.small', { type: 'button', id: o.id + '-file' }, icon('upload2'), 'Choose a file');
    const fileName = h('span.bf-file-name.muted');
    const fileBox = h('div.bf-file', pick, fileName);
    pick.addEventListener('click', async () => {
      const [f] = await S.UI.pickFiles('', false);
      if (!f) return;
      if (f.size > 4 * 1024 * 1024) { S.UI.toast('That file is larger than 4 MB: pick a smaller one.', 'err'); return; }
      file = new Uint8Array(await f.arrayBuffer());
      fileName.textContent = f.name + ' · ' + f.size + ' bytes';
      st.fileName = f.name;
      changed();
    });
    const seg = U.seg(o.id + '-mode', [['text', 'Text'], ['hex', 'Hex'], ['file', 'File']], st.mode, (m) => {
      // carry the value across: text shown as hex, hex shown as text when it is printable
      try { const b = get(); if (m === 'hex') st.hex = hexOf(b); if (m === 'text') { const t = new TextDecoder('utf-8', { fatal: true }).decode(b); st.text = t; } } catch (e) { /* keep what was there */ }
      st.mode = m; show(); changed();
    });
    const show = () => {
      ta.style.display = st.mode === 'file' ? 'none' : '';
      fileBox.style.display = st.mode === 'file' ? '' : 'none';
      ta.value = st.mode === 'hex' ? st.hex : st.text;
      ta.classList.toggle('hexmode', st.mode === 'hex');
      ta.placeholder = st.mode === 'hex' ? 'hex, like 00 11 22 aa' : o.placeholder || 'text';
    };
    ta.addEventListener('input', () => { if (st.mode === 'hex') st.hex = ta.value; else st.text = ta.value; changed(); });
    function get() {
      let b;
      if (st.mode === 'file') { if (!file) throw new Error((o.label || 'The input') + ': choose a file first.'); b = file; }
      else if (st.mode === 'hex') { const r = S.Check.readHex(st.hex); if (r.error && st.hex.trim()) throw new Error((o.label || 'The input') + ': ' + r.error); const t = r.hex || ''; if (t.length % 2) throw new Error((o.label || 'The input') + ': an odd number of hex digits; a byte takes two.'); b = new Uint8Array(t.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(t.substr(2 * i, 2), 16); }
      else b = enc(st.text);
      const n = o.bytes;
      if (typeof n === 'number' && b.length !== n) throw new Error((o.label || 'The input') + ' must be exactly ' + n + ' bytes; it is ' + b.length + '.');
      if (Array.isArray(n) && (b.length < n[0] || b.length > n[1])) throw new Error((o.label || 'The input') + ' must be ' + (n[0] === n[1] ? n[0] : n[0] + ' to ' + n[1]) + ' bytes; it is ' + b.length + '.');
      return b;
    }
    function changed() {
      let msg = '', bad = false;
      try { const b = get(); msg = b.length + ' byte' + (b.length === 1 ? '' : 's'); } catch (e) { msg = e.message; bad = true; }
      info.textContent = msg; info.classList.toggle('bad', bad);
      if (o.onChange) o.onChange(st);
    }
    const el = h('div.bytes-field', { dataset: { field: o.id } }, h('div.bf-head', h('label', { for: o.id }, o.label), seg, info), ta, fileBox);
    show();
    requestAnimationFrame(() => { let msg = ''; try { msg = get().length + ' bytes'; } catch (e) { msg = e.message; info.classList.add('bad'); } info.textContent = msg; });
    return {
      el, get,
      state: () => Object.assign({}, st, { mode: st.mode === 'file' ? 'hex' : st.mode, hex: st.mode === 'file' && file ? hexOf(file) : st.hex }),
      set(s) { st = Object.assign({ mode: 'text', text: '', hex: '' }, s); for (const c of seg.children) { const on = c.dataset.v === st.mode; c.classList.toggle('on', on); c.setAttribute('aria-checked', String(on)); } show(); changed(); },
    };
  };

  /** bytes as a grid of hex cells. o = {cols, changed: Uint8Array to compare with (differing bytes lit), key, label, id} */
  U.hexGrid = function (bytes, o) {
    o = o || {};
    const cols = o.cols || 16, grid = h('div.hexgrid', { style: { gridTemplateColumns: 'repeat(' + Math.max(1, Math.min(cols, bytes.length)) + ', minmax(0, 1fr))' }, id: o.id || null, role: 'group', 'aria-label': o.label || 'bytes' });
    for (let i = 0; i < bytes.length; i++) {
      const diff = o.changed && o.changed[i] !== bytes[i];
      grid.appendChild(h('span.hx' + (diff ? '.diff' : '') + (o.key ? '.key' : ''), { title: 'byte ' + i }, bytes[i].toString(16).padStart(2, '0')));
    }
    if (!bytes.length) grid.appendChild(h('span.muted', '(no bytes)'));
    return h('div.hexgrid-box', o.label ? h('div.hg-cap', o.label, h('span.muted', ' · ' + bytes.length + ' byte' + (bytes.length === 1 ? '' : 's'))) : null, grid);
  };
  /** a trace as a numbered list; `values` and hex runs in the narration are set in the monospace face */
  U.trace = function (trace, o) {
    o = o || {};
    const list = (trace || []).slice(0, o.max || 400);
    const ol = h('ol.trace', { id: o.id || null });
    for (const s of list) ol.appendChild(h('li', { dataset: { kind: s.kind || '' } }, ...U.say(s.say)));
    if ((trace || []).length > list.length) ol.appendChild(h('li.more', '… and ' + (trace.length - list.length) + ' more steps'));
    return ol;
  };
  /** narration with long hex runs and numbers in the monospace face */
  U.say = function (text) {
    const out = [];
    const re = /(`[^`]+`|\b[0-9a-f]{8,}\b|\b\d{6,}\b)/gi;
    let last = 0, m;
    const t = String(text || '');
    while ((m = re.exec(t))) { if (m.index > last) out.push(t.slice(last, m.index)); out.push(h('code.v', m[0].replace(/`/g, ''))); last = m.index + m[0].length; }
    if (last < t.length) out.push(t.slice(last));
    return out;
  };
  /** a big integer with its size: long ones are folded, with a button to show all */
  U.big = function (n, o) {
    const s = typeof n === 'bigint' ? n.toString() : String(n);
    const bits = typeof n === 'bigint' ? (n < 0n ? -n : n).toString(2).length : null;
    const short = s.length > 48 ? s.slice(0, 20) + '…' + s.slice(-20) : s;
    const v = h('code.big', short);
    const box = h('span.bigint', v, bits ? h('span.bits', ' (' + s.length + ' digits, ' + bits + ' bits)') : null);
    if (short !== s) { const b = h('button.linkish', { type: 'button' }, 'show all'); b.addEventListener('click', () => { v.textContent = s; v.classList.add('all'); b.remove(); }); box.appendChild(b); }
    if (o && o.label) return h('div.kv', h('span.k', o.label), box);
    return box;
  };
  /** a row of key-value facts */
  U.kv = (label, value) => h('div.kv', h('span.k', label), value instanceof Node ? value : h('code.v', String(value)));
  /** an engine this bench needs is not in the build yet */
  U.missing = (what, more) => S.UI.empty('history', what + ' is being built', (more || 'This part of the bench switches on as soon as its engine is in place.'));
  /** run fn and show its error as a sentence in box (cleared first); returns fn's value or null */
  U.guard = function (box, fn) {
    try { return fn(); } catch (e) { box.appendChild(h('div.berr', { role: 'alert' }, icon('warn'), h('span', String(e.message || e)))); if (e instanceof TypeError || e instanceof ReferenceError || e instanceof SyntaxError) console.error(e); return null; }
  };
  U.hexOf = hexOf;
})(globalThis.Sifer = globalThis.Sifer || {});
