// Slow searches (an RSA key, real DSA parameters, a safe prime) run in a Web Worker made from a blob, so the page
// never freezes. The worker is given the core engines themselves: in the built page they are cut out of the one
// inline script (each file starts with a "// ==== core/…" line); on the development page they are loaded from their
// own files. Where no worker can start, the same generator runs on the page a few milliseconds at a time.
//   S.PkWork.run({kind: 'rsa', bits, e} | {kind: 'dsa', L, N} | {kind: 'safe', bits}, onProgress) -> {promise, stop()}
(function (S) {
  'use strict';
  const W = (S.PkWork = {});
  /** a copy that crosses to and from a worker: no functions */
  const plain = (v, depth) => {
    if (depth > 12 || typeof v === 'function') return undefined;
    if (Array.isArray(v)) return v.map((x) => plain(x, (depth || 0) + 1));
    if (v instanceof Uint8Array || v === null || typeof v !== 'object') return v;
    const o = {};
    for (const k of Object.keys(v)) { const x = plain(v[k], (depth || 0) + 1); if (x !== undefined) o[k] = x; }
    return o;
  };
  W.plain = plain;
  /** the generator for a job, on whichever Sifer it is given */
  const genOf = (S2, job) => {
    if (job.kind === 'rsa') return S2.RSA.keygenSteps(job.bits, { e: BigInt(job.e || 65537) });
    if (job.kind === 'dsa') return S2.SIG.dsaParamsSteps({ L: job.L, Nbits: job.N });
    if (job.kind === 'safe') return S2.NT.safePrimeSteps(job.bits);
    throw new Error('unknown job ' + job.kind);
  };
  W.genOf = genOf;

  let src = null;
  /** the engines' source: {code} from the built page, or {urls} on the development page */
  const engineSource = () => {
    if (src) return src;
    const urls = [], parts = [];
    for (const s of document.scripts) {
      if (s.src && /\/src\/core\/[^/]+\.js$/.test(s.src)) urls.push(s.src);
      else if (!s.src && s.textContent.includes('// ==== core/')) {
        const t = s.textContent;
        const re = /\/\/ ==== (\S+) ====\n/g;
        const marks = [];
        let m;
        while ((m = re.exec(t))) marks.push({ name: m[1], at: m.index, body: m.index + m[0].length });
        marks.forEach((mk, i) => { if (/^core\//.test(mk.name)) parts.push(t.slice(mk.body, i + 1 < marks.length ? marks[i + 1].at : t.length)); });
      }
    }
    src = parts.length ? { code: parts.join('\n') } : urls.length ? { urls } : null;
    return src;
  };
  const WORKER = function () {
    self.onmessage = (e) => {
      const { job, plainSrc, genSrc } = e.data;
      const plainF = (self.plain = new Function('return ' + plainSrc)()), genF = new Function('return ' + genSrc)();
      try {
        const g = genF(self.Sifer, job);
        let r, last = 0;
        for (;;) {
          r = g.next();
          if (r.done) break;
          const now = Date.now();
          if (now - last > 90) { last = now; self.postMessage({ type: 'progress', v: plainF(r.value) }); }
        }
        self.postMessage({ type: 'done', v: plainF(r.value) });
      } catch (err) { self.postMessage({ type: 'error', msg: String(err && err.message || err) }); }
    };
  };

  W.run = function (job, onProgress) {
    let stopped = false, worker = null, stopFn = null;
    const promise = new Promise((resolve, reject) => {
      const fallback = () => {
        const ctl = { aborted: false };
        stopFn = () => { ctl.aborted = true; };
        S.NT.runChunked(genOf(S, job), { budget: 14, onProgress, signal: ctl }).then(resolve, reject);
      };
      const es = typeof Worker !== 'undefined' && typeof document !== 'undefined' ? engineSource() : null;
      if (!es) { fallback(); return; }
      try {
        const head = es.code ? es.code : 'importScripts(' + es.urls.map((u) => JSON.stringify(u)).join(', ') + ');';
        const url = URL.createObjectURL(new Blob([head + '\n;(' + WORKER.toString() + ')();'], { type: 'text/javascript' }));
        worker = new Worker(url);
        URL.revokeObjectURL(url);
      } catch (e) { fallback(); return; }
      worker.onmessage = (e) => {
        const m = e.data;
        if (stopped) return;
        if (m.type === 'progress') { if (onProgress) onProgress(m.v); }
        else if (m.type === 'done') { worker.terminate(); resolve(m.v); }
        else { worker.terminate(); reject(new Error(m.msg)); }
      };
      worker.onerror = (e) => { if (e.preventDefault) e.preventDefault(); worker.terminate(); worker = null; if (!stopped) fallback(); };
      worker.postMessage({ job, plainSrc: plain.toString(), genSrc: genOf.toString() });
      stopFn = () => { if (worker) worker.terminate(); reject(new Error('stopped')); };
    });
    return { promise, stop() { stopped = true; if (stopFn) stopFn(); } };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
