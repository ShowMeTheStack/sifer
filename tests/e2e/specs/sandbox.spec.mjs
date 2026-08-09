// The sandbox: tasks, the sealed worker (no network, no page, a time limit, messages it cannot forge), results with
// the first failing case, the console, hints, progress kept, reset, the reference solution and share links.
import { assert } from '../lib.mjs';

const runWith = async (p, src) => {
  await p.ev(`(() => { const e = Sifer.app.page.editor; e.value = ${JSON.stringify(src)}; e.dispatchEvent(new Event('input')); })()`);
  await p.click('#sbRun');
  await p.wait("!document.getElementById('sbRun').disabled && document.getElementById('sbMsg')", 10000);
  return p.text('#sbMsg');
};

export default function (t) {
  t.test('every task\'s reference solution passes its tests in the worker', async (p) => {
    await p.route('sandbox');
    const ids = await p.ev('Sifer.Sandbox.tasks.map(t => t.id)');
    assert.ok(ids.length >= 11, 'tasks: ' + ids.length);
    for (const id of ids) {
      const r = await p.ev(`(async () => { const t = Sifer.Sandbox.task(${JSON.stringify(id)}); const r = await Sifer.Sandbox.run({ src: t.solution, fn: t.fn, tests: Sifer.Sandbox.testsOf(t) }); return { ok: r.ok, err: r.compileError, n: r.cases.length }; })()`);
      assert.ok(r.ok, id + ' fails: ' + JSON.stringify(r));
    }
  }, { timeout: 60000 });

  t.test('a pass marks the task solved; a wrong answer names the first failing case', async (p) => {
    await p.route('sandbox/xtime');
    assert.equal(await p.text('#sbTitle'), 'xtime in GF(2^8)');
    let msg = await runWith(p, 'function xtime(a) { return (a << 1) & 0xff; }');
    assert.match(msg, /Test \d+ of 10 fails: xtime\(0x[0-9a-f]{2}\) returned 0x[0-9a-f]{2}, but it should return 0x[0-9a-f]{2}/);
    assert.ok(await p.exists('#sbResult .cases-table tr.fail'));
    msg = await runWith(p, 'function xtime(a) { return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff; }');
    assert.match(msg, /All 10 tests pass/);
    assert.ok(await p.visible('#sbSolved'));
    assert.ok(await p.exists('#sbTasks li.done a[data-task="xtime"]'));
    await p.reload();
    await p.route('sandbox/xtime');
    assert.ok(await p.visible('#sbSolved'), 'solved is kept');
    assert.match(await p.ev('Sifer.app.page.editor.value'), /0x1b/, 'the code is kept');
  });

  t.test('BigInt tests, a wrong type, and a missing function', async (p) => {
    await p.route('sandbox/square-multiply');
    let msg = await runWith(p, 'function modPow(x, e, n) { return Number(x ** e % n); }');
    assert.match(msg, /modPow\(5n, 0n, 23n\) returned 1, but it should return 1n \(the right value, but as a Number/);
    msg = await runWith(p, 'function power(x, e, n) { return 1n; }');
    assert.match(msg, /no function called modPow/);
    msg = await runWith(p, 'function modPow(x, e, n) { return x **; }');
    assert.match(msg, /does not run: SyntaxError/);
    msg = await runWith(p, 'function modPow(x, e, n) { throw new Error("not yet"); }');
    assert.match(msg, /threw Error: not yet/);
  });

  t.test('an endless loop is stopped at the time limit, and the page stays alive', async (p) => {
    await p.route('sandbox/egcd');
    const t0 = Date.now();
    const msg = await runWith(p, 'function egcd(a, b) { while (true) {} }');
    assert.match(msg, /ran longer than 2 s and was stopped/);
    assert.ok(Date.now() - t0 < 6000, 'stopped promptly');
    assert.equal(await p.ev('1 + 1'), 2);
  });

  t.test('the worker has no network, no page, and cannot forge its results', async (p) => {
    await p.route('sandbox/scratch');
    let msg = await runWith(p, 'function main() { return [typeof fetch, typeof XMLHttpRequest, typeof importScripts, typeof document, typeof window, typeof WebSocket, typeof postMessage, typeof indexedDB].join(","); }');
    assert.match(msg, /"undefined,undefined,undefined,undefined,undefined,undefined,undefined,undefined"/);
    msg = await runWith(p, 'function main() { const g = Function("return this")(); return typeof g.fetch + "," + typeof g.postMessage; }');
    assert.match(msg, /"undefined,function"/, 'the real global has no fetch');
    // a forged message: the worker's own postMessage reached through the global, without the secret
    await p.route('sandbox/xtime');
    msg = await runWith(p, 'function xtime(a) { const g = Function("return this")(); g.postMessage({ type: "done", logs: [] }); g.postMessage({ type: "case", i: 0, got: 174 }); return 0; }');
    assert.match(msg, /fails/, 'the forged pass is ignored: ' + msg);
  });

  t.test('the console, hints, start again and the reference solution', async (p) => {
    await p.route('sandbox/crt');
    await runWith(p, 'function crt(r1, m1, r2, m2) { console.log("trying", r1, m1); return 0n; }');
    assert.match(await p.text('#sbResult details.logs'), /trying 2n 5n|trying 2 5/);
    await p.click('#sbHint');
    assert.equal(await p.count('#sbHints .hint'), 1);
    await p.click('#sbHint');
    await p.click('#sbHint');
    assert.equal(await p.waitModal(), 'Show a worked answer?');
    await p.modalButton('Show it');
    assert.equal(await p.count('#sbHints .hint'), 3);
    await p.click('#sbReset');
    await p.waitModal();
    await p.modalButton('Start again');
    assert.match(await p.ev('Sifer.app.page.editor.value'), /your code here/);
    await p.click('#sbRef');
    await p.waitModal();
    await p.modalButton('Show it');
    const msg = await (async () => { await p.click('#sbRun'); await p.wait("document.getElementById('sbMsg')", 8000); return p.text('#sbMsg'); })();
    assert.match(msg, /All 6 tests pass/);
  });

  t.test('a share link opens the same task with the same code; the page fits a phone', async (p) => {
    await p.route('sandbox/quarter-round');
    await p.ev("Sifer.app.page.editor.value = 'function quarterRound(a, b, c, d) { /* shared */ return [a, b, c, d]; }'");
    const url = await p.ev("Sifer.app.share('sandbox', { task: 'quarter-round', src: Sifer.app.page.editor.value })");
    await p.route('');
    await p.ev(`location.hash = ${JSON.stringify(url.replace(/^[^#]*#/, ''))}`);
    await p.wait("location.hash === '#sandbox/quarter-round' && window.__siferReady", 8000);
    await p.wait('Sifer.app.page && Sifer.app.page.editor');
    assert.match(await p.ev('Sifer.app.page.editor.value'), /shared/);
    await p.viewport(390, 844, { mobile: true, touch: true });
    await p.route('sandbox/sbox');
    assert.ok(await p.noHScroll());
    await p.viewport(1400, 900);
  });
}
