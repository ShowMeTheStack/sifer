// The Bombe's run in a Web Worker, so the page never freezes. The worker is made from a blob holding the engine's own
// source: on the built page it is cut from the one inline script (each file starts with a "// ==== core/x.js ===="
// line); on the development page the worker imports the source files by their addresses. Where no worker can be
// made, the same job runs on the page a slice at a time between frames.
//   S.EnigmaRun.start(params, {onProgress(r), onDone(stops), onError(msg)}, {slow}) -> {cancel(), mode: 'worker' | 'page'}
(function (S) {
  'use strict';
  const FILES = ['core/enigma-machine.js', 'core/enigma-menu.js', 'core/enigma-bombe.js'];
  let url = null;

  function source() {
    const tags = FILES.map((f) => document.querySelector('script[src$="' + f + '"]'));
    if (tags.every(Boolean)) return 'self.Sifer = {};\nimportScripts(' + tags.map((t) => JSON.stringify(new URL(t.getAttribute('src'), location.href).href)).join(', ') + ');\nSifer.Enigma.bombe.serve(self);\n';
    const text = [...document.scripts].map((s) => s.textContent || '').find((t) => t.includes('// ==== core/enigma-bombe.js ===='));
    if (!text) return null;
    const parts = [];
    for (const f of FILES) {
      const mark = '// ==== ' + f + ' ====';
      const a = text.indexOf(mark);
      if (a < 0) return null;
      const b = text.indexOf('\n// ==== ', a + mark.length);
      parts.push(text.slice(a, b < 0 ? text.length : b));
    }
    return 'self.Sifer = {};\n' + parts.join('\n') + '\nSifer.Enigma.bombe.serve(self);\n';
  }

  const R = (S.EnigmaRun = {
    /** can a worker be made here? (false in node, or when the sources cannot be found) */
    workerUrl() {
      if (url) return url;
      if (typeof Worker === 'undefined' || typeof Blob === 'undefined') return null;
      const code = source();
      if (!code) return null;
      url = URL.createObjectURL(new Blob([code], { type: 'text/javascript' }));
      return url;
    },
    /** opts.slow: on the page, 256 positions a frame, so the drums can be watched turning */
    start(params, cb, opts) {
      const slow = !!(opts && opts.slow);
      const u = R.forcePage || slow ? null : R.workerUrl();
      if (u) {
        let w;
        try { w = new Worker(u); } catch (e) { w = null; }
        if (w) {
          let done = false;
          w.onmessage = (e) => {
            const d = e.data || {};
            if (d.type === 'progress') cb.onProgress(d);
            else if (d.type === 'done') { done = true; w.terminate(); cb.onDone(d.stops, d.tested); }
            else if (d.type === 'error') { done = true; w.terminate(); cb.onError(d.message); }
          };
          w.onerror = (e) => { if (done) return; done = true; e.preventDefault(); w.terminate(); R.forcePage = true; R.start(params, cb); };
          w.postMessage({ cmd: 'start', params, slice: 80 });
          return { mode: 'worker', cancel() { if (!done) { done = true; w.postMessage({ cmd: 'cancel' }); w.terminate(); } } };
        }
      }
      // on the page, in slices between frames
      let job;
      try { job = S.Enigma.bombe.job(params); } catch (e) { setTimeout(() => cb.onError(e.message), 0); return { mode: 'page', cancel() {} }; }
      let stop = false;
      const tick = () => {
        if (stop) return;
        const r = job.run(slow ? 0 : 24);
        cb.onProgress({ progress: r.progress, order: r.order, tested: r.tested, rawStops: r.rawStops, newStops: r.newStops });
        if (r.done) { cb.onDone(job.stops, job.tested); return; }
        requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
      return { mode: 'page', cancel() { stop = true; job.cancel(); } };
    },
  });
})(globalThis.Sifer = globalThis.Sifer || {});
