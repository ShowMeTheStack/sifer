// The CTF page (#ctf, #ctf/<id>): a ladder of break-it challenges, each with a story, its data, a flag format, a box
// to submit the flag, and three hints that cost points. What you solved, when, and with how many hints is kept in
// this browser (every read and write of storage is guarded), and a scoreboard sums it up.
//   S.CTF.solved(id) -> {at, points, hints} | null;  S.CTF.score() -> {points, max, solved, total, hints, solves}
//   S.CTF.submit(id, flag) -> result (as S.Check.answer);  S.CTF.reset()
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const KEY = 'sifer.ctf';
  const inline = (t) => S.UI.inline(t);
  /** points kept after 0, 1, 2 or 3 hints: the worked answer costs the most */
  const KEEP = [1, 0.9, 0.8, 0.5];
  const COST = ['10% of the points', 'another 10%', 'another 30%: it all but solves it'];
  const read = () => { try { const v = JSON.parse(localStorage.getItem(KEY) || 'null'); return Object.assign({ solved: {}, hints: {}, tries: {} }, v || {}); } catch (e) { return { solved: {}, hints: {}, tries: {} }; } };
  const write = (v) => { try { localStorage.setItem(KEY, JSON.stringify(v)); } catch (e) { /* private mode: progress lasts for this visit */ } };
  let memo = null; // when storage is unavailable, the page still remembers this visit
  const state = () => memo || (memo = read());
  const commit = (v) => { memo = v; write(v); };
  const ladder = () => (S.Content && S.Content.ladder ? S.Content.ladder() : []);
  // a rung's number is its place on the whole ladder, so the parts number on from each other; n only orders them
  const rungOf = (x, all) => (all || ladder()).indexOf(x) + 1;
  const byId = (id) => (S.Content && S.Content.challenges ? S.Content.challenges.get(id) : null) || null;

  const CTF = (S.CTF = {
    solved: (id) => state().solved[id] || null,
    hintsUsed: (id) => state().hints[id] || 0,
    score() {
      const st = state(), all = ladder();
      const solves = all.filter((x) => st.solved[x.id]).map((x) => Object.assign({ id: x.id, title: x.title }, st.solved[x.id])).sort((a, b) => a.at - b.at);
      return { points: solves.reduce((n, s) => n + s.points, 0), max: all.reduce((n, x) => n + (x.points || 0), 0), solved: solves.length, total: all.length, hints: all.reduce((n, x) => n + (st.hints[x.id] || 0), 0), solves };
    },
    submit(id, flag) {
      const x = byId(id);
      if (!x) return { ok: false, message: 'There is no such challenge.' };
      const r = S.Check.answer(Object.assign({}, x, { kind: 'flag' }), flag);
      const st = state();
      if (S.Check.flagShape(x.format).re.test(String(flag || '').trim())) st.tries[id] = (st.tries[id] || 0) + 1;
      if (r.ok && !st.solved[id]) st.solved[id] = { at: Date.now(), points: Math.round((x.points || 0) * KEEP[Math.min(3, st.hints[id] || 0)]), hints: st.hints[id] || 0 };
      commit(st);
      return r;
    },
    takeHint(id) { const st = state(); st.hints[id] = Math.min(3, (st.hints[id] || 0) + 1); commit(st); return st.hints[id]; },
    reset() { memo = { solved: {}, hints: {}, tries: {} }; commit(memo); },
  });

  const when = (t) => { try { return new Date(t).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); } catch (e) { return new Date(t).toISOString(); } };
  const levelOf = (n) => ['', 'warm-up', 'steady', 'hard', 'fierce'][n] || '';

  function scoreboard(app) {
    const sc = CTF.score();
    const reset = h('button.btn.small', { type: 'button', id: 'ctfReset' }, icon('restart'), 'Reset my progress');
    reset.addEventListener('click', async () => {
      if (!(await S.UI.confirm('Reset your progress?', 'Every solved challenge and hint in this browser is forgotten. This cannot be undone.', 'Reset', 'Keep it'))) return;
      CTF.reset(); app.route();
    });
    const pct = sc.max ? Math.round((100 * sc.points) / sc.max) : 0;
    return h('section.card.ctf-score', { id: 'ctfScore' },
      h('div.cs-nums',
        h('div.cs-num', h('b', { id: 'ctfPoints' }, String(sc.points)), h('span', 'points of ' + sc.max)),
        h('div.cs-num', h('b', { id: 'ctfSolved' }, sc.solved + ' / ' + sc.total), h('span', 'solved')),
        h('div.cs-num', h('b', { id: 'ctfHints' }, String(sc.hints)), h('span', 'hints taken'))),
      h('div.fc-bar.cs-bar', { 'aria-label': pct + '% of the points' }, h('i', { style: { width: pct + '%' } })),
      sc.solves.length ? h('ol.cs-solves', ...sc.solves.map((s) => h('li', h('a', { href: '#ctf/' + s.id }, s.title), h('span.muted', ' · ' + s.points + ' points' + (s.hints ? ', ' + s.hints + ' hint' + (s.hints === 1 ? '' : 's') : '') + ' · ' + when(s.at))))) : h('p.muted.cs-empty', 'Nothing solved yet. Start at the bottom rung.'),
      h('div.cs-acts', reset));
  }

  function ladderPage(app, main) {
    document.title = 'CTF ladder · Sifer';
    const all = ladder();
    const box = h('div.ctf', { id: 'ctfView' });
    box.appendChild(h('div.bench-head', h('div', h('h1', 'CTF ladder'), h('p', 'Each rung is a small story with something broken in it: a cipher used badly, a key too short, a shortcut that should not have been taken. Break it, find the flag, and climb. Hints help and cost points.'))));
    const rungs = h('ol.ctf-ladder', { id: 'ctfLadder', 'aria-label': 'Challenges' });
    const next = all.find((x) => !CTF.solved(x.id));
    for (const x of all) {
      const solved = CTF.solved(x.id);
      const ahead = !solved && x !== next;
      const a = h('a.ctf-rung' + (solved ? '.solved' : x === next ? '.next' : '.ahead'), { href: '#ctf/' + x.id, dataset: { challenge: x.id } },
        h('span.cr-n', String(rungOf(x, all))),
        h('span.cr-body', h('span.cr-title', x.title), h('span.cr-meta', '●'.repeat(x.level || 1) + ' ' + levelOf(x.level || 1) + ' · ' + (x.points || 0) + ' points' + (CTF.hintsUsed(x.id) ? ' · ' + CTF.hintsUsed(x.id) + ' hint' + (CTF.hintsUsed(x.id) === 1 ? '' : 's') : ''))),
        h('span.cr-state', solved ? [icon('check'), h('span', 'Solved')] : x === next ? [icon('flag'), h('span', 'Next')] : [icon('lock'), h('span', 'Ahead')]));
      if (ahead) a.title = 'Ahead of where you are, but open: every rung can be tried.';
      rungs.appendChild(h('li', a));
    }
    if (!all.length) rungs.appendChild(h('li', S.UI.empty('flag', 'The ladder is being built', 'Challenges are on their way.')));
    box.appendChild(h('div.ctf-grid', h('div.ctf-col', rungs), h('div.ctf-col', scoreboard(app), h('p.muted.ctf-note', 'Flags look like ', h('code', 'sifer{…}'), '. Your progress stays in this browser; nothing is sent anywhere.'))));
    main.appendChild(box);
    return {};
  }

  function copyBtn(text) {
    const b = h('button.icon-btn.copy', { type: 'button', title: 'Copy', 'aria-label': 'Copy' }, icon('copy'));
    b.addEventListener('click', () => S.Share.copy(text, 'Copied.'));
    return b;
  }

  /** a "Useful here" link in words: 'bench/nt', 'sandbox/task', 'topic=id', 'lesson=id', 'enigma/bombe', 'demo' ... */
  const BENCHES = { cipher: 'cipher', nt: 'number-theory', pk: 'public-key', hash: 'hash', curve: 'curve', proto: 'protocol' };
  function toolLabel(t) {
    const [, page, arg] = /^([a-z]+)[/=]?(.*)$/.exec(String(t)) || [null, String(t), ''];
    const id = (arg || '').split(/[?/]/)[0];
    if (page === 'bench') return BENCHES[id] ? 'the ' + BENCHES[id] + ' bench' : 'the benches';
    if (page === 'sandbox') { const tk = id && id !== 'scratch' && S.Sandbox && S.Sandbox.tasks && S.Sandbox.tasks.find((k) => k.id === id); return tk ? 'the sandbox task “' + tk.title + '”' : 'the sandbox'; }
    if (page === 'topic') { const tp = (S.topics || []).find((k) => k.id === id); return tp ? 'the topic “' + tp.title + '”' : 'a topic'; }
    if (page === 'topics' || page === 'part') return 'the topics';
    if (page === 'lesson') { const ls = S.Content && S.Content.lessons.get(id); return ls ? 'the lesson “' + ls.title + '”' : 'a lesson'; }
    if (page === 'exercise') { const ex = S.Content && S.Content.exercises.get(id); return ex ? 'the exercise “' + ex.title + '”' : 'an exercise'; }
    if (page === 'enigma') return id === 'bombe' ? 'the Bombe' : id === 'inside' ? 'the inside of the Enigma' : id === 'path' ? 'the Enigma’s signal path' : 'the Enigma';
    if (page === 'demo') return 'the demo';
    return String(t);
  }
  function challengePage(app, main, id) {
    const x = byId(id);
    if (!x) { main.appendChild(h('div.ctf', S.UI.empty('flag', 'There is no challenge called "' + id + '"', 'It may have been renamed.', [{ label: 'The ladder', icon: 'flag', primary: true, action: () => { location.hash = 'ctf'; } }]))); return {}; }
    document.title = x.title + ' · CTF · Sifer';
    const all = ladder(), k = all.indexOf(x);
    const box = h('article.ctf.ctf-chal', { id: 'ctfChallenge', dataset: { challenge: x.id } });
    const solvedTag = h('span.sb-solved', { id: 'ctfSolvedTag' }, icon('check'), 'Solved');
    const showSolved = () => { const s = CTF.solved(x.id); solvedTag.hidden = !s; if (s) solvedTag.lastChild.textContent = 'Solved for ' + s.points + ' points'; };
    box.append(h('div.crumbs', h('a', { href: '#ctf' }, 'CTF ladder'), ' › Rung ' + rungOf(x, all)),
      h('div.ctf-title', h('h1.page-title', x.title), solvedTag),
      h('div.ls-meta', h('span', '●'.repeat(x.level || 1) + ' ' + levelOf(x.level || 1)), h('span', (x.points || 0) + ' points')),
      h('p.ctf-story', inline(x.story)));
    const data = typeof x.data === 'function' ? x.data() : x.data || {};
    for (const [label, value] of Object.entries(data)) box.appendChild(h('div.ctf-data', h('div.cd-head', h('span.bd-label', label), copyBtn(String(value))), h('code.bd-value', String(value))));
    const input = h('input.mono', { type: 'text', id: 'ctfFlag', 'aria-label': 'The flag', placeholder: S.Check.flagShape(x.format).text, spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off' });
    const submit = h('button.btn.primary', { type: 'button', id: 'ctfSubmit' }, icon('flag'), 'Submit the flag');
    const result = h('div.ex-result', { id: 'ctfResult', 'aria-live': 'polite' });
    const go = () => {
      const r = CTF.submit(x.id, input.value);
      result.className = 'ex-result ' + (r.ok ? 'ok' : 'bad');
      result.innerHTML = '';
      result.appendChild(h('div.ex-v', icon(r.ok ? 'check' : 'x'), h('b', r.ok ? 'Captured.' : 'Not yet.'), ' ', h('span', String(r.message).replace(/^Right\.\s*/, ''))));
      if (r.ok && all[k + 1]) result.appendChild(h('a.btn.small.primary', { href: '#ctf/' + all[k + 1].id, id: 'ctfNext' }, 'Next rung', icon('stepOver')));
      showSolved();
    };
    submit.addEventListener('click', go);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); go(); } });
    box.appendChild(h('section.card.ctf-submit', h('label.ans-line', { for: 'ctfFlag' }, h('span', 'Flag'), input), h('div.ex-tools', submit, h('span.muted', 'The flag looks like ', h('code', S.Check.flagShape(x.format).text), x.caseless ? ' (case does not matter)' : '')), result));
    // hints, one at a time
    const hintBox = h('div.hints', { id: 'ctfHintList' });
    const hintBtn = h('button.btn', { type: 'button', id: 'ctfHint' }, icon('hint'), 'A hint');
    const hints = x.hints || [];
    const showHints = () => {
      const n = CTF.hintsUsed(x.id);
      hintBox.innerHTML = '';
      for (let i = 0; i < Math.min(n, hints.length); i++) hintBox.appendChild(h('div.ls-note.tip.hint' + (i === hints.length - 1 ? '.worked' : ''), icon(i === hints.length - 1 ? 'book' : 'hint'), h('div', h('b', i === hints.length - 1 ? 'The way through. ' : 'Hint ' + (i + 1) + '. '), inline(hints[i]))));
      hintBtn.disabled = n >= hints.length;
      hintBtn.lastChild.textContent = n >= hints.length ? 'No more hints' : 'Hint ' + (n + 1) + ' of ' + hints.length + ' (costs ' + COST[n] + ')';
    };
    hintBtn.addEventListener('click', async () => {
      const n = CTF.hintsUsed(x.id);
      if (n === hints.length - 1 && !(await S.UI.confirm('Take the last hint?', 'It walks you through the whole solution and keeps only half the points.', 'Show it', 'Keep trying'))) return;
      CTF.takeHint(x.id); showHints();
    });
    box.appendChild(h('section.ctf-hints', h('div.ex-tools', hintBtn, CTF.solved(x.id) ? h('span.muted', 'Hints after a solve cost nothing.') : null), hintBox));
    if (x.tools && x.tools.length) box.appendChild(h('p.muted.ctf-tools', 'Useful here: ', ...x.tools.map((t, i) => [i ? ', ' : '', h('a', { href: '#' + t }, toolLabel(t))]), '.'));
    box.appendChild(h('div.ls-nav', k > 0 ? h('a.btn', { href: '#ctf/' + all[k - 1].id }, icon('stepBack'), 'Rung ' + k) : h('a.btn', { href: '#ctf' }, icon('flag'), 'The ladder'), all[k + 1] ? h('a.btn', { href: '#ctf/' + all[k + 1].id }, 'Rung ' + (k + 2), icon('stepOver')) : h('span')));
    main.appendChild(box);
    showHints(); showSolved();
    return { submit: go };
  }

  S.Pages.register('ctf', {
    nav: 'ctf',
    wide: true,
    open(app, main, rest) {
      const id = (rest || '').replace(/^(ctf|challenge)[/=]?/, '').split(/[/?]/)[0];
      return id ? challengePage(app, main, id) : ladderPage(app, main);
    },
  });
  if (S.Checks) {
    S.Checks.push({ group: 'ctf', name: 'ctf ladder', hash: 'ctf', ready: "document.querySelector('#ctfLadder')", sel: '#main' });
    S.Checks.push({ group: 'ctf', name: 'ctf challenge with hints and a wrong flag', hash: 'ctf/cl-ctf-two-pads', ready: "document.querySelector('#ctfChallenge')", setup: "document.getElementById('ctfFlag').value = 'sifer{wrong}'; Sifer.app.page.submit();", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
