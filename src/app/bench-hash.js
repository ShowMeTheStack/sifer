// The hash bench (#bench/hash): any hash on text, hex or a file, with the Merkle–Damgård chain and the registers
// of every round (or the sponge's lanes); HMAC with its inner and outer hash; a defence card on length extension (why
// hash(secret ‖ message) is no MAC, which hashes expose their whole state, and the fix); and the birthday attack on a
// hash cut short, run live with a counter.
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const HB = (S.HashBench = S.HashBench || {});
  const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
  const NAMES = [['md5', 'MD5 (broken)'], ['sha1', 'SHA-1 (broken)'], ['sha224', 'SHA-224'], ['sha256', 'SHA-256'], ['sha384', 'SHA-384'], ['sha512', 'SHA-512'], ['sha512-256', 'SHA-512/256'], ['sha3-224', 'SHA3-224'], ['sha3-256', 'SHA3-256'], ['sha3-384', 'SHA3-384'], ['sha3-512', 'SHA3-512'], ['shake128', 'SHAKE128'], ['shake256', 'SHAKE256']];
  const label = (n) => (NAMES.find((x) => x[0] === n) || [n, n])[1].replace(/ \(broken\)/, '');
  const pop = (x) => { let n = 0; while (x) { n += x & 1; x >>= 1; } return n; };
  const MSG = 'Ferry leaves the east pier at 06:40; bring the blue ledger.';

  /** a hash run with everything kept, whatever its construction */
  HB.run = function (name, msg, outLen) {
    const H = S.Hash;
    if (name === 'shake128' || name === 'shake256') { const p = { rate: name === 'shake128' ? 168 : 136, pad: 0x1f, outLen: outLen || 32, trace: true }; const r = H.SHA3.run(msg, p); return { digest: r.digest, sponge: r, rate: p.rate, trace: r.trace }; }
    const A = H.get(name);
    if (A.run && !/^sha3/.test(name)) { const r = A.run(msg, { trace: true, rounds: true }); return { digest: r.digest, md: r, trace: r.trace }; }
    const p = H.SHA3.params(name), r = H.SHA3.run(msg, Object.assign({}, p, { trace: true }));
    return { digest: r.digest, sponge: r, rate: p.rate, trace: r.trace };
  };
  HB.hash = (name, msg, outLen) => (name === 'shake128' ? S.Hash.shake128(msg, outLen || 32) : name === 'shake256' ? S.Hash.shake256(msg, outLen || 32) : S.Hash.get(name).hash(msg));

  S.Bench.tab('hash', {
    title: 'Hash bench', icon: 'hash', order: 50,
    blurb: 'Hashes round by round, HMAC, why hash(secret ‖ message) is no MAC, and the birthday attack on a cut-down digest.',
    open(host, saved, ctx) {
      const U = S.BenchUI;
      const st = Object.assign({ panel: 'hash', name: 'sha256', msg: { mode: 'text', text: MSG, hex: '' }, outLen: 32, block: 0,
        hmac: { name: 'sha256', key: { mode: 'text', text: 'harbour-master key', hex: '' }, msg: { mode: 'text', text: MSG, hex: '' } },
        bday: { name: 'sha256', bits: 24, seed: 7 } }, saved || {});
      let job = null;
      const has = () => !!(S.Hash && S.Hash.get);
      host.appendChild(h('div.bench-head', h('div', h('h1', 'Hash bench'), h('p', 'A hash compresses any input to a short digest, block by block. See every round, then attack what a hash is used for.')),
        h('div.bench-acts', (() => { const b = h('button.btn', { type: 'button', id: 'hbShare' }, icon('link'), 'Share'); b.addEventListener('click', () => ctx.share()); return b; })())));
      const panels = U.seg('hbPanel', [['hash', 'Hash'], ['hmac', 'HMAC'], ['lenext', 'Length extension'], ['bday', 'Birthday attack']], st.panel, (v) => { st.panel = v; show(); });
      host.appendChild(h('div.hb-panels', panels));
      const body = h('div.hb-body', { id: 'hbBody' });
      host.appendChild(body);
      const stop = () => { if (job) { job.stopped = true; job = null; } };
      const show = () => {
        stop();
        ctx.save();
        body.innerHTML = '';
        if (!has()) { body.appendChild(U.missing('The hash engine')); return; }
        ({ hash: hashPanel, hmac: hmacPanel, lenext: lenPanel, bday: bdayPanel })[st.panel]();
      };
      const twoCol = (setupKids, out) => { const g = h('div.bench-grid'); g.append(h('section.card.bcard', h('div.bcard-head', h('h3', 'Setup')), h('div.bcard-body', ...setupKids)), out); body.appendChild(g); for (const ta of g.querySelectorAll('textarea')) S.UI.autosize(ta, 160); return g; };
      const sel = (id, v, f, only) => U.select(id, NAMES.filter((n) => !only || only.includes(n[0])).map(([value, l]) => ({ value, label: l })), v, f);

      // ---- one hash, opened up -------------------------------------------------------------------------------------
      function hashPanel() {
        const out = h('div.b-out', { id: 'hbOut' });
        const f = U.bytesField({ id: 'hbMsg', label: 'Message', value: st.msg, rows: 3, onChange: (v) => { st.msg = v; draw(); } });
        const kids = [U.field('Hash function', sel('hbName', st.name, (v) => { st.name = v; st.block = 0; hashPanel2(); })), f.el];
        if (/^shake/.test(st.name)) { const n = U.input('hbOutLen', st.outLen, (v) => { st.outLen = Math.max(1, Math.min(256, +v || 32)); draw(); }, { attrs: { type: 'number', min: '1', max: '256' } }); kids.push(U.field('Output length (bytes)', n)); }
        kids.push(h('p.b-note', /^sha3|^shake/.test(st.name) ? 'A sponge: blocks are XORed into the rate part of a 1600-bit state, with the Keccak permutation between; the capacity is never touched by the input.' : st.name === 'md5' || st.name === 'sha1' ? 'Merkle–Damgård with a compression function now known to collide: kept here for history and for attacks.' : 'Merkle–Damgård: the message is padded and cut into blocks; each block is compressed into the running chaining value.'));
        twoCol(kids, out);
        function draw() {
          ctx.save();
          out.innerHTML = '';
          const msg = U.guard(out, () => f.get());
          if (!msg) return;
          const r = U.guard(out, () => HB.run(st.name, msg, st.outLen));
          if (!r) return;
          const flipped = msg.length ? HB.hash(st.name, (() => { const m = msg.slice(); m[0] ^= 1; return m; })(), st.outLen) : null;
          let diff = 0; if (flipped) for (let i = 0; i < flipped.length; i++) diff += pop(flipped[i] ^ r.digest[i]);
          const copy = h('button.btn.small', { type: 'button', id: 'hbCopy' }, icon('copy'), 'Copy');
          copy.addEventListener('click', () => S.Share.copy(hex(r.digest), 'The digest is copied.'));
          out.appendChild(h('section.card.bcard', { id: 'hbDigest' }, h('div.bcard-head', h('h3', label(st.name) + ' digest'), h('p', r.digest.length + ' bytes from ' + msg.length + ' bytes of message')),
            h('div.bcard-body', h('div.brow', h('code.hb-digest', { id: 'hbDigestHex' }, hex(r.digest)), copy),
              flipped ? h('p.b-note', { id: 'hbFlip' }, 'Flip the lowest bit of the first byte and ' + diff + ' of ' + 8 * r.digest.length + ' digest bits change (' + Math.round((100 * diff) / (8 * r.digest.length)) + '%): the digest of a nearly equal message looks unrelated.') : null)));
          const inner = h('div.bcard-body');
          out.appendChild(h('section.card.bcard', h('div.bcard-head', h('h3', r.md ? 'The chain, block by block' : 'The sponge, block by block')), inner));
          if (r.md) {
            inner.appendChild(HB.view.chain(r.md, label(st.name), 4));
            const n = r.md.blocks.length; st.block = Math.min(st.block, n - 1);
            if (n > 1) inner.appendChild(U.field('Block', U.select('hbBlock', r.md.blocks.map((b) => ({ value: String(b.i), label: 'Block ' + (b.i + 1) + (b.lengthBlock ? ' (padding and length)' : b.hasPad ? ' (with padding)' : '') })), String(st.block), (v) => { st.block = +v; draw(); }), 'inline'));
            const b = r.md.blocks[st.block];
            inner.appendChild(U.hexGrid(b.block, { label: 'Block ' + (b.i + 1) + ' as it enters the compression function', cols: 16 }));
            inner.appendChild(h('p.b-note', 'The registers after every round (the ones the round computes are lit). In ' + (st.block + 1 === n ? 'this last block' : 'this block') + ' they start from ' + HB.cvText(b.cvIn, 24) + '.'));
            inner.appendChild(HB.view.rounds(b, st.name));
          } else {
            const sp = r.sponge, rl = r.rate / 8;
            inner.appendChild(h('p.b-note', 'Rate ' + r.rate + ' bytes (' + rl + ' lanes, lit), capacity ' + (200 - r.rate) + ' bytes. ' + sp.absorbs.length + ' block' + (sp.absorbs.length === 1 ? '' : 's') + ' absorbed.'));
            st.block = Math.min(st.block, sp.absorbs.length - 1);
            if (sp.absorbs.length > 1) inner.appendChild(U.field('Block', U.select('hbBlock', sp.absorbs.map((a) => ({ value: String(a.i), label: 'Absorb block ' + (a.i + 1) })), String(st.block), (v) => { st.block = +v; draw(); }), 'inline'));
            const a = sp.absorbs[st.block];
            if (a.before) inner.appendChild(h('div.lanes-row', h('div', h('span.rd-name', 'Before'), HB.view.lanes(a.before, rl)), h('div', h('span.rd-name', 'Block XORed in'), HB.view.lanes(a.xored, rl, a.before)), h('div', h('span.rd-name', 'After Keccak-f'), HB.view.lanes(a.after, rl, a.xored))));
          }
          out.appendChild(h('section.card.bcard', h('div.bcard-head', h('h3', 'Narration')), h('div.bcard-body', h('div.trace-box', U.trace(r.trace, { id: 'hbTrace', max: 60 })))));
          requestAnimationFrame(() => S.UI.fitTables(out));
        }
        draw();
      }
      const hashPanel2 = () => { body.innerHTML = ''; hashPanel(); };

      // ---- HMAC ------------------------------------------------------------------------------------------------------
      function hmacPanel() {
        const s = st.hmac, out = h('div.b-out', { id: 'hbOut' });
        const fk = U.bytesField({ id: 'hbKey', label: 'Key', value: s.key, onChange: (v) => { s.key = v; draw(); } });
        const fm = U.bytesField({ id: 'hbHmacMsg', label: 'Message', value: s.msg, rows: 3, onChange: (v) => { s.msg = v; draw(); } });
        twoCol([U.field('Hash function', sel('hbHmacName', s.name, (v) => { s.name = v; draw(); }, ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-512'])), fk.el, fm.el,
          h('p.b-note', 'HMAC hashes twice, with the key mixed in before each hash, so neither length extension nor a weakness of the inner hash alone gives the tag away.')], out);
        function draw() {
          ctx.save(); out.innerHTML = '';
          if (!(S.MAC && S.MAC.hmacTrace)) { out.appendChild(U.missing('The MAC engine')); return; }
          const r = U.guard(out, () => { const k = fk.get(), m = fm.get(); return { t: S.MAC.hmacTrace(s.name, k, m), m }; });
          if (!r) return;
          out.appendChild(h('section.card.bcard', h('div.bcard-head', h('h3', 'HMAC-' + label(s.name)), h('p', 'tag ' + r.t.tag.length + ' bytes')), h('div.bcard-body', h('code.hb-digest', { id: 'hbTag' }, hex(r.t.tag)), HB.view.hmac(r.t, label(s.name), r.m.length))));
          out.appendChild(h('section.card.bcard', h('div.bcard-head', h('h3', 'Narration')), h('div.bcard-body', h('div.trace-box', U.trace(r.t.trace)))));
        }
        draw();
      }

      // ---- length extension: the defence card, not a runner ----------------------------------------------------------
      const STATE = [['md5', 16], ['sha1', 20], ['sha256', 32], ['sha512', 64], ['sha512-256', 64], ['sha3-256', 200]];
      function lenPanel() {
        const out = h('div.b-out', { id: 'hbOut' });
        const H = S.Hash;
        const rows = STATE.filter(([n]) => H.get(n)).map(([n, sb]) => {
          const db = H.get(n).hash(new Uint8Array(0)).length, open = db >= sb;
          return h('tr' + (open ? '.hl' : ''), h('td', label(n)), h('td.mono', String(sb)), h('td.mono', String(db)), h('td', open ? 'yes: never use it this way' : 'no: ' + (sb - db) + ' bytes stay hidden'));
        });
        const topics = ['p12-lenext', 'p13-hmac', 'p12-sponge'].map((id) => S.byId && S.byId(id)).filter(Boolean);
        body.appendChild(h('section.card.bcard', { id: 'hbLenRes' }, h('div.bcard-head', h('h3', 'Length extension: never tag with hash(secret ‖ message)'),
          h('p', 'A Merkle–Damgård digest is the hash\'s whole final state. If a server tags messages as hash(secret ‖ message), anyone holding a tag can carry on hashing from it, so a longer message gets a valid tag without the secret. The cure is a MAC built for the job.')),
          h('div.bcard-body', h('div.lab-area.lab-defence', { id: 'hbLenRules' },
            h('ul.lab-rules',
              h('li', ...S.UI.inline('Use **HMAC** (or KMAC with SHA-3) for a keyed tag: its outer hash means the tag is not a state anyone can resume.')),
              h('li', ...S.UI.inline('Never build a MAC as hash(secret ‖ message) from MD5, SHA-1, SHA-256 or SHA-512, whatever the secret\'s length.')),
              h('li', ...S.UI.inline('A hash that hides part of its state (SHA3-256, SHA-512/256) is not extendable, but a MAC should still be HMAC or KMAC, not a home-made prefix.')),
              h('li', ...S.UI.inline('Verify tags in constant time, and on the exact bytes that will be acted on.'))),
            h('div.b-scroll.fit-table', h('table.b-table', { id: 'hbLenTable' }, h('thead', h('tr', h('th', 'hash'), h('th', 'state bytes'), h('th', 'digest bytes'), h('th', 'hash(secret ‖ m) extendable?'))), h('tbody', ...rows))),
            topics.length ? h('div.lab-topics', h('span.k', 'See why, and the fix'), ...topics.map((t) => h('a.btn.small', { href: '#topic=' + t.id, dataset: { topic: t.id }, style: { whiteSpace: 'normal', textAlign: 'left' } }, icon('library'), t.title))) : null))));
        body.appendChild(out);
      }

      // ---- the birthday attack ----------------------------------------------------------------------------------------------
      function bdayPanel() {
        const s = st.bday, out = h('div.b-out', { id: 'hbOut' });
        const bits = h('input', { type: 'range', id: 'hbBits', min: '8', max: '40', value: String(s.bits), 'aria-label': 'Digest bits kept' });
        const bl = h('b', { id: 'hbBitsVal' }, String(s.bits));
        const go = h('button.btn.primary', { type: 'button', id: 'hbBdayRun' }, icon('run'), 'Search for a collision');
        const halt = h('button.btn', { type: 'button', id: 'hbBdayStop', disabled: true }, icon('stop'), 'Stop');
        const exp = h('p.b-note', { id: 'hbBdayExp' });
        const upd = () => { const N = 2 ** s.bits; exp.textContent = 'Kept: ' + s.bits + ' bits, so 2^' + s.bits + ' = ' + N.toLocaleString('en') + ' digests. A collision is expected after about √(πN/2) ≈ ' + Math.round(Math.sqrt((Math.PI / 2) * N)).toLocaleString('en') + ' tries, not the ' + N.toLocaleString('en') + ' a single target would take.'; };
        bits.addEventListener('input', () => { s.bits = +bits.value; bl.textContent = String(s.bits); upd(); ctx.save(); });
        go.addEventListener('click', () => start());
        halt.addEventListener('click', () => { stop(); halt.disabled = true; go.disabled = false; });
        twoCol([U.field('Hash function', sel('hbBdayName', s.name, (v) => { s.name = v; ctx.save(); }, ['md5', 'sha1', 'sha256', 'sha512', 'sha3-256'])), h('label.bfield', h('span', 'Digest bits kept: ', bl), bits), exp, h('div.brow', go, halt),
          h('p.b-note', 'Every try hashes a fresh payment note; a table remembers each truncated digest until one comes round again.')], out);
        upd();
        const live = h('section.card.bcard', { id: 'hbBday' }, h('div.bcard-head', h('h3', 'The search')), h('div.bcard-body', h('p.muted', 'Press the button to start.')));
        out.appendChild(live);
        function start() {
          stop();
          if (!S.Hash.birthdaySteps) { live.lastChild.replaceChildren(U.missing('The birthday-attack engine')); return; }
          const j = (job = { stopped: false });
          go.disabled = true; halt.disabled = false;
          const expected = Math.sqrt((Math.PI / 2) * 2 ** s.bits);
          const n = h('b.hb-count', { id: 'hbTries' }, '0'), bar = h('i'), meter = h('div.hb-meter', bar);
          live.lastChild.replaceChildren(h('div.kv', h('span.k', 'tries'), n, h('span.muted', ' of about ' + Math.round(expected).toLocaleString('en') + ' expected')), meter);
          const gen = S.Hash.birthdaySteps({ hash: s.name, bits: s.bits, seed: s.seed });
          const t0 = performance.now();
          const tick = () => {
            if (j.stopped) return;
            const until = performance.now() + 14;
            let r;
            while (!(r = gen.next()).done && performance.now() < until) { if (r.value) { n.textContent = r.value.done.toLocaleString('en'); bar.style.width = Math.min(100, (100 * r.value.done) / expected / 2) + '%'; } }
            if (!r.done) { if (r.value) n.textContent = r.value.done.toLocaleString('en'); requestAnimationFrame(tick); return; }
            done(r.value, performance.now() - t0);
          };
          requestAnimationFrame(tick);
        }
        function done(r, ms) {
          job = null; go.disabled = false; halt.disabled = true;
          s.seed++; ctx.save();
          const dec = (b) => new TextDecoder().decode(b);
          const body = live.lastChild;
          body.innerHTML = '';
          if (!r.found) { body.appendChild(h('p', 'No collision in ' + r.tries.toLocaleString('en') + ' tries.')); return; }
          const pre = Math.ceil(r.bits / 4);
          const dg = (d) => { const x = hex(d); return h('code.hb-dg', h('mark', x.slice(0, pre)), x.slice(pre, 40) + '…'); };
          body.append(h('div.ok-line', { id: 'hbBdayFound' }, icon('check'), 'Collision after ' + r.tries.toLocaleString('en') + ' tries (' + Math.round((100 * r.tries) / r.expected) + '% of the estimate), in ' + Math.max(1, Math.round(ms)) + ' ms.'),
            h('div.hb-pair', h('div', h('span.k', 'message A'), h('code.v', { id: 'hbMsgA' }, dec(r.a)), dg(r.digestA)), h('div', h('span.k', 'message B'), h('code.v', { id: 'hbMsgB' }, dec(r.b)), dg(r.digestB))),
            h('p.b-note', 'The first ' + r.bits + ' bits (' + pre + ' hex digits, lit) agree: ' + r.value + '. The full digests still differ; cut a hash to b bits and collisions cost only about 2^(b/2) tries.'),
            h('div.trace-box', U.trace(r.trace)));
        }
      }

      show();
      return {
        state: () => JSON.parse(JSON.stringify(st)),
        set(patch) { for (const k of Object.keys(patch)) st[k] = patch[k] && typeof patch[k] === 'object' && !Array.isArray(patch[k]) && st[k] && typeof st[k] === 'object' ? Object.assign(st[k], patch[k]) : patch[k]; for (const c of document.querySelectorAll('#hbPanel button')) { const on = c.dataset.v === st.panel; c.classList.toggle('on', on); c.setAttribute('aria-checked', String(on)); } show(); },
        redraw() { if (st.panel !== 'bday') show(); },
        dispose() { stop(); },
      };
    },
  });

  if (S.Checks) {
    const P = 'Sifer.app.page.bench', R = "document.querySelector('#hbOut')";
    const add = (name, js, ready) => S.Checks.push({ group: 'bench-hash', name, hash: 'bench/hash', ready: R, setup: js ? P + '.set(' + js + ');' + (ready ? ' await new Promise((r) => { const t = setInterval(() => { if (' + ready + ') { clearInterval(t); r(); } }, 50); });' : '') : '', sel: '#main' });
    add('SHA-256, two blocks', "{panel: 'hash', name: 'sha256', block: 1}");
    add('MD5 rounds', "{panel: 'hash', name: 'md5', block: 0}");
    add('SHA-512', "{panel: 'hash', name: 'sha512', block: 0}");
    add('SHA3-256 sponge', "{panel: 'hash', name: 'sha3-256', block: 0}");
    add('HMAC-SHA-256', "{panel: 'hmac'}");
    add('length extension, the defence', "{panel: 'lenext'}");
    add('birthday attack, 16 bits, found', "{panel: 'bday', bday: {bits: 16}}); document.getElementById('hbBdayRun').click(", "document.getElementById('hbBdayFound')");
  }
})(globalThis.Sifer = globalThis.Sifer || {});
