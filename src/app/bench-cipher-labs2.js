// More attack labs, on ciphers rather than modes: the two-time pad by crib dragging and then in full, the
// meet-in-the-middle on double DES (sym-des-mitm.js), the toy SPN's last round key by differential or linear
// cryptanalysis (sym-spn-attack.js), the correlation attack on the Geffe generator (sym-geffe.js) and
// Berlekamp–Massey rebuilding an LFSR from its output (sym-lfsr.js). Slow ones run in slices.
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const CB = (S.CipherBench = S.CipherBench || {});
  const L = (CB.labs = CB.labs || []);
  const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
  const txt = (b) => new TextDecoder().decode(b);
  const h4 = (v) => v.toString(16).padStart(4, '0');
  /** run a generator in slices, calling onProgress with what it yields; returns {stop, done: Promise} */
  const sliced = (gen, onProgress, ms) => {
    const j = { stopped: false };
    const done = new Promise((resolve, reject) => {
      const tick = () => {
        if (j.stopped) return;
        try { const until = performance.now() + (ms || 14); let r; do { r = gen.next(); if (!r.done && r.value && onProgress) onProgress(r.value); } while (!r.done && performance.now() < until); if (r.done) resolve(r.value); else setTimeout(tick, 0); } catch (e) { reject(e); }
      };
      setTimeout(tick, 0);
    });
    return { stop() { j.stopped = true; }, done };
  };
  const meter = (id) => { const bar = h('i'), n = h('span.muted', { id }); return { el: h('div', h('div.hb-meter', bar), n), set(done, total, what) { bar.style.width = Math.min(100, (100 * done) / total) + '%'; n.textContent = (what || '') + done.toLocaleString('en') + ' of ' + total.toLocaleString('en'); } }; };

  // ---- the two-time pad ---------------------------------------------------------------------------------------------
  L.push({
    id: 'twotime', group: 'Stream ciphers', title: 'The two-time pad', has: () => !!(S.OTP && S.OTP.setup),
    blurb: 'A one-time pad used twice. XOR the two ciphertexts and the pad is gone; what is left is two messages tangled together. Drag a likely word along it, and where it fits, the other message shows through.',
    render(box, ctx) {
      let lab = S.OTP.setup({ seed: ctx.seed }), job = null;
      const area = h('div.lab-area');
      const crib = S.BenchUI.input('otpCrib', ctx.crib || ' the ', (v) => { ctx.crib = v; ctx.save(); drag(); }, { label: 'A word to drag', mono: true });
      const rec = h('button.btn.primary', { type: 'button', id: 'otpRecover' }, icon('run'), 'Recover both messages');
      const again = h('button.btn', { type: 'button', id: 'labNew' }, icon('shuffle'), 'New scenario');
      const out = h('div', { id: 'otpCribRows' }), full = h('div', { id: 'otpFull' });
      const x = () => S.bytes.xor(lab.c1, lab.c2);
      const head = () => h('div', h('div.kv', h('span.k', 'C1'), h('code.v', hex(lab.c1))), h('div.kv', h('span.k', 'C2'), h('code.v', hex(lab.c2))), h('div.kv', h('span.k', 'C1 ⊕ C2'), h('code.v.lit-x', hex(x()))));
      const drag = () => {
        const w = String(ctx.crib || ' the ');
        if (!w.length) { out.replaceChildren(); return; }
        const r = S.OTP.crib(x(), w);
        const rows = (r.best || []).slice(0, 8).map((b) => h('tr' + (b.plausible ? '.act' : ''), h('td', String(b.pos)), h('td.mono', JSON.stringify(b.other)), h('td', b.plausible ? 'reads like English' : '')));
        out.replaceChildren(h('p.b-note', 'Where “' + w + '” sits in one message, the other message has these letters (the best fits first):'), h('div.fit-table', h('table.b-table', h('thead', h('tr', h('th', 'position'), h('th', 'the other message there'), h('th', ''))), h('tbody', rows))));
      };
      rec.addEventListener('click', () => {
        if (job) job.stop();
        const m = meter('otpProgress');
        full.replaceChildren(h('p.b-note', 'A search over both messages at once, letter by letter, keeping the 100 most English-looking pairs.'), m.el);
        job = sliced(S.OTP.run(x()), (v) => m.set(v.done, v.total, 'letters: '));
        job.done.then((r) => {
          job = null;
          const ok = S.OTP.agreement ? S.OTP.agreement(r.m1, r.m2, lab.m1, lab.m2) : null;
          full.replaceChildren(h('div.kv', h('span.k', 'message 1'), h('code.v', { id: 'otpM1' }, txt(r.m1))), h('div.kv', h('span.k', 'message 2'), h('code.v', { id: 'otpM2' }, txt(r.m2))),
            h('div.ok-line', { id: 'otpDone' }, icon('check'), 'Both messages back' + (ok !== null ? ', ' + Math.round(100 * ok) + '% of the letters right' : '') + ', with no pad and no key. (Which is message 1 cannot be told: the XOR is symmetric.)'));
        }, (e) => full.replaceChildren(h('div.berr', String(e.message || e))));
      });
      again.addEventListener('click', () => { ctx.seed++; ctx.save(); lab = S.OTP.setup({ seed: ctx.seed }); area.replaceChildren(head(), S.BenchUI.field('Crib', crib), out, h('div.brow', rec), full); full.replaceChildren(); drag(); });
      area.append(head(), S.BenchUI.field('Crib', crib), out, h('div.brow', rec), full);
      box.append(h('div.brow.lab-acts', again), area);
      drag();
      return { stop() { if (job) job.stop(); } };
    },
  });

  // ---- meet in the middle ----------------------------------------------------------------------------------------------
  L.push({
    id: 'mitm', group: 'Block ciphers', title: 'Meet in the middle', has: () => !!(S.MITM && S.MITM.run),
    blurb: 'Double DES uses two keys, but it is not twice as strong: encrypt forward under every first key, decrypt backward under every second key, and look for a value in the middle. Here each key has a few unknown bits, so it runs in a moment.',
    render(box, ctx) {
      let job = null;
      const bits = h('input', { type: 'range', id: 'mitmBits', min: '8', max: '18', value: String(ctx.bits || 14), 'aria-label': 'Unknown bits per key' });
      const bl = h('b', String(ctx.bits || 14));
      bits.addEventListener('input', () => { ctx.bits = +bits.value; bl.textContent = bits.value; ctx.save(); });
      const area = h('div.lab-area');
      const run = (seed) => {
        if (job) job.stop();
        const n = ctx.bits || 14, lab = S.MITM.setup({ seed, bits: n });
        const m = meter('mitmProgress');
        area.replaceChildren(h('div.kv', h('span.k', 'known pair 1'), h('code.v', hex(lab.pairs[0].p) + ' → ' + hex(lab.pairs[0].c))), h('div.kv', h('span.k', 'known pair 2'), h('code.v', hex(lab.pairs[1].p) + ' → ' + hex(lab.pairs[1].c))), m.el);
        job = sliced(S.MITM.run({ base: lab.base, bits: n, pairs: lab.pairs }), (v) => m.set(v.done, v.total, (v.phase === 'forward' ? 'forward, encrypting: ' : 'backward, decrypting: ')));
        job.done.then((r) => {
          job = null;
          const right = r.found.some((f) => f.k1v === lab.k1v && f.k2v === lab.k2v);
          area.append(h('div.lab-work', h('div', h('b', r.work.mitm.toLocaleString('en')), h('span', 'DES operations, meeting in the middle')), h('div', h('b', r.work.brute.toLocaleString('en')), h('span', 'for every pair of keys')), h('div', h('b', r.work.memory.toLocaleString('en')), h('span', 'middle values stored'))),
            h('div.kv', h('span.k', 'candidates'), h('code.v', r.candidates.length + ' (' + r.candidates.filter((c) => !c.ok).length + ' false alarms, rejected by pair 2)')),
            h('div.' + (right ? 'ok-line' : 'berr'), { id: 'mitmOk' }, icon(right ? 'check' : 'warn'), right ? 'Found K1 = ' + lab.k1v + ' and K2 = ' + lab.k2v + ': both keys, in about 2 × 2^' + n + ' operations instead of 2^' + 2 * n + '.' : 'The planted keys were not found.'),
            h('details.lab-trace', h('summary', 'Every step'), h('div.trace-box', S.BenchUI.trace(r.trace, { max: 40 }))));
        }, (e) => area.append(h('div.berr', String(e.message || e))));
      };
      box.append(h('label.bfield', h('span', 'Unknown bits in each key: ', bl), bits), CB.labButtons(ctx, 'Meet in the middle', run), area);
      return { stop() { if (job) job.stop(); } };
    },
  });

  // ---- the toy SPN broken ------------------------------------------------------------------------------------------------
  L.push({
    id: 'spn', group: 'Block ciphers', title: 'Breaking the toy SPN', has: () => !!(S.SPN && S.SPN.recoverK5Steps),
    blurb: 'Differential cryptanalysis sends pairs with a chosen difference; linear cryptanalysis counts a parity over known texts. Either way, peel off the last round under each guess of a key nibble: the right guess stands out.',
    render(box, ctx) {
      let job = null;
      const seg = S.BenchUI.seg('spnMethod', [['differential', 'Differential'], ['linear', 'Linear']], ctx.method || 'differential', (v) => { ctx.method = v; ctx.save(); });
      const area = h('div.lab-area');
      const run = (seed) => {
        if (job) job.stop();
        const keys = S.SPN.keys(seed), m = meter('spnProgress');
        area.replaceChildren(h('div.kv', h('span.k', 'secret round keys'), h('code.v', keys.map(h4).join(' '))), m.el, h('div.spn-nibs', { id: 'spnNibs' }));
        job = sliced(S.SPN.recoverK5Steps({ keys, seed, method: ctx.method || 'differential' }), (v) => m.set(v.done, v.total, 'nibbles of K5: '), 1);
        job.done.then((r) => {
          job = null;
          const nibs = area.querySelector('#spnNibs');
          r.nibbles.forEach((res, n) => {
            const counts = res.counts || [], max = Math.max(1, ...counts);
            const right = res.right !== undefined ? res.right : null;
            nibs.appendChild(h('div.spn-nib', h('b', 'nibble ' + n), h('div.bars', ...counts.map((c, g) => { const val = right !== null && (res.nibs ? (g << (4 * (3 - res.nibs[0]))) : g) === right; return h('span.bar' + (val ? '.right' : ''), { style: { height: Math.max(2, Math.round((48 * Math.abs(c)) / max)) + 'px' }, title: 'guess ' + g.toString(16) + ': ' + c }); })), h('span.muted', 'guesses 0 … f')));
          });
          area.append(h('div.' + (r.ok ? 'ok-line' : 'berr'), { id: 'spnOk' }, icon(r.ok ? 'check' : 'warn'), 'Recovered K5 = ' + h4(r.k5) + '; the true K5 is ' + h4(r.keys[4]) + (r.ok ? '.' : ': not this time.')),
            h('details.lab-trace', h('summary', 'Every step'), h('div.trace-box', S.BenchUI.trace(r.trace))));
        }, (e) => area.append(h('div.berr', String(e.message || e))));
      };
      box.append(S.BenchUI.field('Method', seg), CB.labButtons(ctx, 'Recover the last round key', run), area);
      return { stop() { if (job) job.stop(); } };
    },
  });

  // ---- the Geffe generator and Berlekamp–Massey -------------------------------------------------------------------------
  L.push({
    id: 'geffe', group: 'Stream ciphers', title: 'Correlation attack on Geffe', has: () => !!(S.Geffe && S.Geffe.attack),
    blurb: 'Three LFSRs, and the output is the second or the third, chosen by the first. So the output agrees with each of those two three times in four: try their start states one register at a time, not all together.',
    render(box, ctx) {
      const area = h('div.lab-area');
      const run = (seed) => {
        const lab = S.Geffe.setup({ seed, n: 300 }), r = S.Geffe.attack({ z: lab.z });
        const bits = (a) => a.join('');
        area.replaceChildren(h('div.kv', h('span.k', 'keystream (first 64 of 300 bits)'), h('code.v', bits(lab.z.slice(0, 64)))), CB.labSteps(r.trace),
          h('div.fit-table', h('table.b-table', h('thead', h('tr', h('th', 'register'), h('th', 'recovered start'), h('th', 'true start'))), h('tbody', ...r.seeds.map((s, i) => h('tr' + (bits(s) === bits(lab.seeds[i]) ? '.act' : ''), h('td', 'LFSR ' + (i + 1)), h('td.mono', bits(s)), h('td.mono', bits(lab.seeds[i]))))))),
          h('div.' + (r.ok ? 'ok-line' : 'berr'), { id: 'geffeOk' }, icon(r.ok ? 'check' : 'warn'), r.ok ? 'All three start states, from the keystream alone.' : 'Not recovered.'));
      };
      box.append(CB.labButtons(ctx, 'Split the generator', run), area);
      return { stop() {} };
    },
  });
  L.push({
    id: 'bm', group: 'Stream ciphers', title: 'Berlekamp–Massey', has: () => !!(S.LFSR && S.LFSR.berlekampMassey),
    blurb: 'An LFSR of length L is fixed by 2L of its output bits: Berlekamp–Massey finds the shortest register that produces them, so a plain LFSR is no stream cipher at all.',
    render(box, ctx) {
      const def = S.LFSR.sequence([7, 6, 4, 1], [1, 0, 1, 1, 0, 0, 1], 24).join('');
      const inp = S.BenchUI.input('bmBits', ctx.bits || def, (v) => { ctx.bits = v; ctx.save(); run(); }, { label: 'Output bits' });
      const area = h('div.lab-area');
      const run = () => {
        const b = String(ctx.bits || def).replace(/[^01]/g, '').split('').map(Number);
        if (b.length < 2) { area.replaceChildren(h('div.berr', 'Give at least two bits (0 and 1).')); return; }
        const r = S.LFSR.berlekampMassey(b);
        area.replaceChildren(h('div.kv', h('span.k', 'register length L'), h('code.v', { id: 'bmL' }, String(r.L))), h('div.kv', h('span.k', 'connection polynomial'), h('code.v', S.LFSR.str ? S.LFSR.str(r.poly) : 'taps ' + r.taps.join(', '))),
          h('div.b-scroll.fit-table', h('table.b-table', h('thead', h('tr', h('th', 'n'), h('th', 'bit'), h('th', 'discrepancy'), h('th', 'L'))), h('tbody', ...r.steps.map((s) => h('tr' + (s.d ? '.hl' : ''), h('td', String(s.n)), h('td.mono', String(s.s)), h('td.mono', String(s.d)), h('td', String(s.L))))))),
          h('p.b-note', r.steps.length >= 2 * r.L ? 'With ' + b.length + ' bits, at least 2L = ' + 2 * r.L + ', the register is fixed: it predicts every further bit.' : 'Fewer than 2L bits: another register could still fit them.'));
      };
      box.append(S.BenchUI.field('Output bits (0 and 1)', inp), area);
      run();
      return { stop() {} };
    },
  });
})(globalThis.Sifer = globalThis.Sifer || {});
