// The Sandbox page (#sandbox, #sandbox/<task>): a list of coding tasks beside an editor. Run tests sends the code to
// a sealed worker (S.Sandbox.run): no page, no network, a time limit, and results the page judges itself. The first
// failing test is shown with its arguments, what came back and what should have; the console follows. Code, solved
// tasks and hints are kept in this browser.
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const store = S.UI.storage;
  const SB = (S.Sandbox = S.Sandbox || {});
  const inline = (t) => S.UI.inline(t);
  const prog = () => Object.assign({ code: {}, solved: {}, hints: {} }, store.get('sandbox', {}));
  const save = (p) => store.set('sandbox', p);
  let pending = null;

  /** a value as the task speaks of it: bytes and words of the byte tasks in hex */
  const showFor = (t, v) => SB.showAs(t, v);
  const callOf = (t, args) => t.fn + '(' + args.map((v, i) => ((t.decimalArgs || []).includes(i) ? SB.show(v) : showFor(t, v))).join(', ') + ')';
  SB.solved = (id) => !!prog().solved[id];

  function list(cur) {
    const p = prog();
    const ul = h('ul.sb-tasks', { id: 'sbTasks', 'aria-label': 'Tasks' });
    for (const t of SB.tasks) {
      ul.appendChild(h('li' + (t.id === cur ? '.on' : '') + (p.solved[t.id] ? '.done' : ''),
        h('a', { href: '#sandbox/' + t.id, dataset: { task: t.id }, 'aria-current': t.id === cur ? 'page' : null },
          h('span.sbt-title', t.title),
          h('span.sbt-meta', t.level ? h('span.lv', { title: ['', 'easy', 'medium', 'hard'][t.level] }, '●'.repeat(t.level)) : h('span.lv.free', 'free'), p.solved[t.id] ? h('span.ok', { title: 'Solved' }, icon('check')) : null))));
    }
    return ul;
  }

  function open(app, main, rest) {
    const id = (rest || '').replace(/^sandbox\/?/, '').split(/[/?]/)[0];
    const t = SB.task(id) || SB.task(store.get('sandbox.last', 'square-multiply')) || SB.tasks[0];
    store.set('sandbox.last', t.id);
    document.title = t.title + ' · Sandbox · Sifer';
    const p0 = prog();
    let src = pending && pending.task === t.id ? pending.src : p0.code[t.id] !== undefined ? p0.code[t.id] : t.start;
    pending = null;
    const box = h('div.sandbox', { id: 'sandboxView', dataset: { task: t.id } });
    const head = h('div.bench-head', h('div', h('h1', 'Sandbox'), h('p', 'Write the pieces yourself. Your code runs in a sealed worker with no page and no network, for at most a few seconds per test, and is checked against vectors. Nothing leaves this browser.')));
    box.appendChild(head);
    const side = h('aside.sb-side', h('div.sb-side-t', 'Tasks'), list(t.id));
    const solvedTag = h('span.sb-solved', { id: 'sbSolved' }, icon('check'), 'Solved');
    if (!p0.solved[t.id]) solvedTag.hidden = true;
    const sig = h('code.sb-sig', 'function ' + t.fn + '(' + t.params.join(', ') + ')');
    const run = h('button.btn.primary', { type: 'button', id: 'sbRun', title: 'Run the tests (Ctrl+Enter)' }, icon('run'), t.free ? 'Run' : 'Run tests');
    const reset = h('button.btn', { type: 'button', id: 'sbReset' }, icon('restart'), 'Start again');
    const ref = h('button.btn', { type: 'button', id: 'sbRef' }, icon('book'), 'Reference solution');
    const share = h('button.btn', { type: 'button', id: 'sbShare' }, icon('link'), 'Share');
    const hintBtn = h('button.btn', { type: 'button', id: 'sbHint' }, icon('hint'), 'A hint');
    const ta = S.ExWidgets.codeArea(src, { id: 'sbCode', label: 'Your code', rows: 11, onRun: () => go() });
    const result = h('div.sb-result', { id: 'sbResult', 'aria-live': 'polite' });
    const hints = h('div.hints', { id: 'sbHints' });
    const status = h('span.sb-status.muted', { id: 'sbStatus' });
    const keep = S.UI.debounce(() => { const p = prog(); p.code[t.id] = ta.value; save(p); }, 400);
    ta.addEventListener('input', () => { if (!app.settings || app.settings.autosave !== false) keep(); });

    const showHints = () => {
      const n = prog().hints[t.id] || 0;
      hints.innerHTML = '';
      for (let i = 0; i < Math.min(n, t.hints.length); i++) {
        const last = i === t.hints.length - 1;
        hints.appendChild(h('div.ls-note.tip.hint' + (last ? '.worked' : ''), icon(last ? 'book' : 'hint'), h('div', h('b', last ? 'A worked answer. ' : 'Hint ' + (i + 1) + '. '), last ? h('pre.mono.sb-worked', t.hints[i]) : inline(t.hints[i]))));
      }
      hintBtn.disabled = n >= t.hints.length;
      hintBtn.lastChild.textContent = n >= t.hints.length ? 'No more hints' : n === t.hints.length - 1 ? 'Show a worked answer' : n ? 'Another hint' : 'A hint';
    };
    hintBtn.addEventListener('click', async () => {
      const p = prog(), n = p.hints[t.id] || 0;
      if (n === t.hints.length - 1 && !(await S.UI.confirm('Show a worked answer?', 'You learn more by trying first. Show it anyway?', 'Show it', 'Keep trying'))) return;
      p.hints[t.id] = n + 1; save(p); showHints();
    });
    reset.addEventListener('click', async () => {
      if (ta.value !== t.start && !(await S.UI.confirm('Start again?', 'Your code for this task is replaced by the starting code.', 'Start again', 'Keep mine'))) return;
      ta.value = t.start; keep(); result.innerHTML = ''; ta.dispatchEvent(new Event('input'));
    });
    ref.addEventListener('click', async () => {
      if (!(await S.UI.confirm('Show the reference solution?', 'It replaces the code in the editor (your own is kept: Undo brings it back). You learn more by trying first.', 'Show it', 'Keep trying'))) return;
      ta.focus(); ta.select();
      if (!document.execCommand('insertText', false, t.solution)) ta.value = t.solution;
      keep();
    });
    share.addEventListener('click', () => app.share('sandbox', { task: t.id, src: ta.value }));

    let running = false;
    const go = async () => {
      if (running) return;
      running = true; run.disabled = true;
      { const p = prog(); p.code[t.id] = ta.value; save(p); }
      status.textContent = 'Running in the worker…';
      result.innerHTML = '';
      const tests = SB.testsOf(t);
      const t0 = performance.now();
      let rep;
      try { rep = await SB.run({ src: ta.value, fn: t.fn, tests, timeLimit: t.timeLimit }); } finally { running = false; run.disabled = false; }
      const ms = performance.now() - t0;
      status.textContent = 'Ran in ' + Math.round(ms) + ' ms.';
      render(rep, tests);
    };
    run.addEventListener('click', go);

    const render = (rep, tests) => {
      result.innerHTML = '';
      let ok = false, msg;
      if (rep.compileError) msg = rep.missing ? 'There is no function called ' + t.fn + ' in your code: write function ' + t.fn + '(' + t.params.join(', ') + ') { … }.' : 'Your code does not run: ' + rep.compileError + '.';
      else if (rep.ok) { ok = true; msg = t.free ? 'main() returned ' + SB.show(rep.cases[0].got) + '.' : 'All ' + tests.length + ' tests pass.'; }
      else {
        const c = rep.cases[rep.firstFail];
        msg = 'Test ' + (rep.firstFail + 1) + ' of ' + tests.length + ' fails: ' + callOf(t, c.args) + ' ';
        if (rep.timedOut && !('got' in c) && !c.error) msg += 'ran longer than ' + ((t.timeLimit || 2000) / 1000) + ' s and was stopped. Is there a loop that never ends?';
        else if (c.error) msg += 'threw ' + c.error + '.';
        else if (c.want === undefined && typeof c.diff === 'string') msg += 'returned ' + showFor(t, c.got) + ', and ' + c.diff + '.';
        else msg += 'returned ' + showFor(t, c.got) + ', but it should return ' + showFor(t, c.want) + (typeof c.diff === 'string' && c.diff !== 'a different value' ? ' (' + c.diff.replace(/ \(a different value\)$/, '') + ')' : '') + '.';
      }
      result.className = 'sb-result ex-result ' + (ok ? 'ok' : 'bad');
      result.appendChild(h('div.ex-v', icon(ok ? 'check' : 'x'), h('b', ok ? (t.free ? 'Done.' : 'Solved.') : 'Not yet.'), ' ', h('span', { id: 'sbMsg' }, msg)));
      if (rep.cases.length && !t.free) result.appendChild(casesTable(t, rep.cases, tests.length));
      const logs = S.ExWidgets.logBox(rep.logs);
      if (logs) result.appendChild(logs);
      if (ok && !t.free) {
        const p = prog();
        if (!p.solved[t.id]) { p.solved[t.id] = Date.now(); save(p); }
        solvedTag.hidden = false;
        const li = document.querySelector('#sbTasks a[data-task="' + t.id + '"]');
        if (li && !li.querySelector('.ok')) { li.parentElement.classList.add('done'); li.querySelector('.sbt-meta').appendChild(h('span.ok', { title: 'Solved' }, icon('check'))); }
        const k = SB.tasks.indexOf(t);
        if (SB.tasks[k + 1] && !SB.tasks[k + 1].free) result.appendChild(h('a.btn.small.primary', { href: '#sandbox/' + SB.tasks[k + 1].id, id: 'sbNext' }, 'Next task', icon('stepOver')));
      }
    };

    const panel = h('section.card.sb-main',
      h('div.sb-task-head', h('div', h('h2', { id: 'sbTitle' }, t.title), sig), solvedTag),
      h('p.sb-blurb', inline(t.blurb)),
      h('div.code-wrap', ta),
      h('div.ex-tools', run, t.free ? null : hintBtn, reset, t.free ? null : ref, share, status),
      result, hints);
    box.appendChild(h('div.sb-grid', side, panel));
    main.appendChild(box);
    S.UI.scrollRow(side.querySelector('.sb-tasks'));
    showHints();
    requestAnimationFrame(() => S.UI.autosize(ta, 560));
    return {
      keys: [['Sandbox', [['Ctrl  Enter', 'Run the tests'], ['Tab', 'Indent (in the editor)']]]],
      onKey(e) { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); go(); return true; } return false; },
      run: go, editor: ta, task: t,
      dispose() {},
    };
  }
  function casesTable(t, cases, total) {
    const rows = cases.map((c) => h('tr.' + (c.pass ? 'pass' : 'fail'),
      h('td', String(c.i + 1)), h('td.mono', callOf(t, c.args)),
      h('td.mono', c.error ? 'threw ' + c.error : 'got' in c ? showFor(t, c.got) : '—'), h('td.mono', c.want === undefined ? (c.pass ? 'accepted' : String(c.diff || '')) : showFor(t, c.want)),
      h('td.mark', c.pass ? icon('check') : icon('x'))));
    const more = total > cases.length ? h('tr.rest', h('td', { colspan: '5' }, (total - cases.length) + ' more test' + (total - cases.length === 1 ? '' : 's') + ' not run: the first failure stops the run')) : null;
    return h('div.fit-table.cases', h('table.cases-table', h('thead', h('tr', h('th', '#'), h('th', 'Call'), h('th', 'Returned'), h('th', 'Wanted'), h('th', { 'aria-label': 'Pass' }))), h('tbody', rows, more)));
  }

  S.Pages.register('sandbox', {
    nav: 'sandbox',
    wide: true,
    open,
    load(data) { if (data && data.task && SB.task(data.task)) { pending = { task: data.task, src: String(data.src || '') }; return 'sandbox/' + data.task; } return 'sandbox'; },
  });
  if (S.Checks) {
    S.Checks.push({ group: 'sandbox', name: 'sandbox, a task open', hash: 'sandbox/xtime', ready: "document.querySelector('#sandboxView')", sel: '#main' });
    S.Checks.push({ group: 'sandbox', name: 'sandbox, a failing run', hash: 'sandbox/quarter-round', ready: "document.querySelector('#sbResult .cases-table')", setup: "Sifer.app.page.editor.value = 'function quarterRound(a, b, c, d) { return [a, b, c, d]; }'; Sifer.app.page.run();", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
