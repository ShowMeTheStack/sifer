// The protocol bench (#bench/proto): pick a protocol, step through its run on a message-sequence chart, and see at
// every moment what each party knows (keys in rose, nonces, names and values), what the step put on the wire, and
// for an attacker what the attack has gained. Runs come from the protocol engine (S.Proto); Diffie–Hellman and the
// man in the middle are built here on the same engine with real numbers when it has no flow of its own for them.
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');

  // ---- Diffie–Hellman on the 64-bit toy group, symbolic terms with real values -------------------------------------
  const secretOf = (tag, seed, q) => { const d = S.Hash.get('sha256').hash(new TextEncoder().encode('proto-bench:' + tag + ':' + seed)); return (BigInt('0x' + hex(d).slice(0, 16)) % (q - 2n)) + 2n; };
  const group = () => S.Proto.GROUPS.toy64;
  function dhFlow(o) {
    const P = S.Proto, a = P.atom, G = group(), seed = o.seed || 1;
    const x = secretOf('a', seed, G.q), y = secretOf('b', seed, G.q);
    const A = P.modpow(G.g, x, G.p), B = P.modpow(G.g, y, G.p), K = P.modpow(B, x, G.p);
    const pub = [a('p', 'data'), a('g', 'data')];
    const r = P.run({ title: 'Diffie–Hellman', seed, parties: [
      { id: 'A', label: 'Alice', knows: [a('A', 'id'), a('B', 'id'), ...pub, a('a', 'secret')] },
      { id: 'B', label: 'Bob', knows: [a('A', 'id'), a('B', 'id'), ...pub, a('b', 'secret')] },
      { id: 'E', label: 'Eve', role: 'eavesdropper', knows: [a('A', 'id'), a('B', 'id'), ...pub] },
    ] });
    r.note('The group is public: p = ' + G.p + ', a 64-bit safe prime, and g = ' + G.g + '. Alice picks a secret a, Bob a secret b.', { values: { p: G.p, g: G.g, a: x, b: y } });
    r.learn('A', a('g^a', 'data'));
    r.send('A', 'B', [a('g^a', 'data')], { label: 'g^a', note: 'Alice sends g^a mod p; a stays with her', values: { 'g^a mod p': A } });
    r.learn('B', a('g^b', 'data'));
    r.send('B', 'A', [a('g^b', 'data')], { label: 'g^b', note: 'Bob sends g^b mod p', values: { 'g^b mod p': B } });
    r.learn('A', a('K', 'key'));
    r.note('Alice raises g^b to her a; Bob raises g^a to his b. Both get g^(ab) mod p = ' + K + '.', { values: { 'K = (g^b)^a = (g^a)^b': K } });
    r.learn('B', a('K', 'key'));
    r.check('A', true, 'the key K is shared with whoever sent g^b, and Eve, who saw g^a and g^b, does not hold it');
    const res = r.result();
    res.summary = 'Alice and Bob agree on K = ' + K + ' over an open line. Eve saw p, g, g^a and g^b; to find K she must solve a discrete logarithm. Nothing tells Alice that g^b really came from Bob.';
    res.attack = { success: r.knows('E', a('K', 'key')) };
    return res;
  }
  function mitmFlow(o) {
    const P = S.Proto, a = P.atom, G = group(), seed = o.seed || 1;
    const x = secretOf('a', seed, G.q), y = secretOf('b', seed, G.q), z = secretOf('m', seed, G.q);
    const A = P.modpow(G.g, x, G.p), B = P.modpow(G.g, y, G.p), Mv = P.modpow(G.g, z, G.p);
    const kA = P.modpow(Mv, x, G.p), kB = P.modpow(Mv, y, G.p);
    const pub = [a('p', 'data'), a('g', 'data')];
    const r = P.run({ title: 'A man in the middle of Diffie–Hellman', seed, parties: [
      { id: 'A', label: 'Alice', knows: [a('A', 'id'), a('B', 'id'), ...pub, a('a', 'secret')] },
      { id: 'M', label: 'Mallory', role: 'attacker', knows: [a('A', 'id'), a('B', 'id'), a('M', 'id'), ...pub, a('m', 'secret')] },
      { id: 'B', label: 'Bob', knows: [a('A', 'id'), a('B', 'id'), ...pub, a('b', 'secret')] },
    ] });
    r.note('Mallory sits on the line between Alice and Bob and can change what passes. Nothing in plain Diffie–Hellman says who sent a number.', { values: { a: x, b: y, m: z } });
    r.learn('A', a('g^a', 'data'));
    r.send('A', 'M', [a('g^a', 'data')], { intended: 'B', label: 'g^a', note: 'Alice sends g^a to Bob; Mallory catches it', values: { 'g^a mod p': A } });
    r.learn('M', a('g^m', 'data'));
    r.send('M', 'B', [a('g^m', 'data')], { as: 'A', label: 'g^m', note: 'Mallory sends her own g^m to Bob, as if from Alice', values: { 'g^m mod p': Mv } });
    r.learn('B', a('g^b', 'data'));
    r.send('B', 'M', [a('g^b', 'data')], { intended: 'A', label: 'g^b', note: 'Bob answers Alice; Mallory catches it', values: { 'g^b mod p': B } });
    r.send('M', 'A', [a('g^m', 'data')], { as: 'B', label: 'g^m', note: 'Mallory sends g^m to Alice, as if from Bob', values: { 'g^m mod p': Mv } });
    r.learn('A', a('K_AM', 'key'));
    r.learn('B', a('K_BM', 'key'));
    r.learn('M', a('K_AM', 'key'), a('K_BM', 'key'));
    r.note('Alice computes (g^m)^a = ' + kA + ' and thinks she shares it with Bob; Bob computes (g^m)^b = ' + kB + '. Mallory computes both, from g^a and g^b with her m.', { values: { 'K_AM = g^(am)': kA, 'K_BM = g^(bm)': kB } });
    r.check('A', true, 'a key is agreed, but it is shared with Mallory, not with Bob');
    r.check('B', true, 'a key is agreed, but it is shared with Mallory, not with Alice');
    const res = r.result();
    res.ok = false;
    res.summary = 'Two keys instead of one: Alice–Mallory and Mallory–Bob. Mallory decrypts, reads and re-encrypts every message, and neither side can tell. Signing the exchanged values (authenticated key exchange) stops this.';
    res.attack = { success: r.knows('M', a('K_AM', 'key')) && r.knows('M', a('K_BM', 'key')), knows: ['K_AM', 'K_BM'] };
    return res;
  }

  /** the protocols: the engine's function (any of the names), or a flow built here */
  const FLOWS = [
    { id: 'dh', title: 'Diffie–Hellman', blurb: 'Two strangers agree on a key over an open line.', names: ['dh', 'diffieHellman'], local: dhFlow, group: true },
    { id: 'mitm', title: 'Man in the middle', blurb: 'Unauthenticated Diffie–Hellman, broken by someone on the line.', names: ['dhMitm', 'dhMITM', 'mitm'], local: mitmFlow, group: true },
    { id: 'sts', title: 'Signed Diffie–Hellman', blurb: 'The exchange signed with long-term keys: the man in the middle fails.', names: ['dhAuth', 'sts', 'stationToStation', 'signedDH', 'authDH'], group: true },
    { id: 'sts-mitm', title: 'Signed, with a man in the middle', blurb: 'The same attack against the signed exchange is caught.', names: ['dhAuth'], opts: { mitm: true }, group: true },
    { id: 'ns', title: 'Needham–Schroeder', blurb: 'A trusted server hands out a session key.', names: ['needhamSchroeder'] },
    { id: 'ns-replay', title: 'Replaying an old key', blurb: 'An old session key leaks, and the protocol accepts it again.', names: ['nsReplay'] },
    { id: 'ns-fixed', title: 'Needham–Schroeder, repaired', blurb: 'Bob\'s own nonce in the ticket makes it fresh.', names: ['nsFixed'] },
    { id: 'ns-fixed-replay', title: 'The replay, repaired', blurb: 'The same replay against the repaired protocol fails.', names: ['nsFixed'], opts: { replay: true } },
    { id: 'kerberos', title: 'Kerberos-style tickets', blurb: 'Log in once; tickets for every service after.', names: ['kerberos'] },
    { id: 'tls13', title: 'A TLS 1.3 handshake', blurb: 'Key share, certificate, signature and Finished, in one round trip.', names: ['tls13', 'tlsHandshake'], tamper: true },
  ];
  const engineOf = (f) => { const P = S.Proto; if (!P) return null; for (const n of f.names) if (typeof P[n] === 'function') return P[n]; return null; };
  const available = (f) => (f.kind === 'cert' ? !!(S.ProtoCert && S.ProtoCert.available()) : !!(engineOf(f) || (f.local && S.Proto && S.Proto.run && S.Hash)));
  /** the message flows and, after them, the certificate scenarios (bench-proto-cert.js) */
  const ALL = () => FLOWS.concat(S.ProtoCert ? S.ProtoCert.FLOWS : []);
  const certCache = new Map();
  const runFlow = (f, st) => { const e = engineOf(f); const opts = Object.assign({ seed: st.seed }, f.opts || {}); if (f.group) opts.group = st.group; if (f.tamper && st.tamper) opts.tamper = st.tamper; return e ? e(opts) : f.local(opts); };
  S.ProtoFlows = FLOWS;

  /** what a party held just before step i (i = -1: before anything) */
  function knowsAt(res, i, pid) {
    if (i >= 0) return res.steps[i].knows[pid] || [];
    const s0 = res.steps[0];
    if (!s0) return (res.final && res.final.knows[pid]) || [];
    const got = new Set(s0.type === 'message' ? (s0.learned[pid] || []) : []);
    return (s0.knows[pid] || []).filter((x) => !got.has(x));
  }
  const U2 = () => S.BenchUI;
  const show = (v) => (typeof v === 'bigint' ? v.toString() : v instanceof Uint8Array ? hex(v) : String(v));

  S.Bench.tab('proto', {
    title: 'Protocols', icon: 'proto', order: 60,
    blurb: 'Message-sequence charts, stepped, with what each party knows at every moment.',
    open(host, state, ctx) {
      const U = S.BenchUI;
      const st = Object.assign({ flow: 'dh', step: -1, seed: 1, group: 'toy64', tamper: '' }, state || {});
      host.appendChild(h('div.bench-head', h('div', h('h1', 'Protocol bench'), h('p', 'Pick a protocol and step through it. Each arrow is one message; the cards below show what every party knows after that step, worked out from what it received and the keys it holds, never simply asserted.')), h('div.bench-acts', h('button.btn', { type: 'button', id: 'protoShare', onclick: () => ctx.share() }, icon('link'), 'Share'))));
      if (!S.Proto || !S.Proto.run) { host.appendChild(U.missing('The protocol engine')); return { state: () => st }; }
      const flows = ALL().filter(available);
      if (!flows.some((f) => f.id === st.flow)) st.flow = flows[0].id;
      const picker = h('div.proto-picks', { id: 'protoPicks', role: 'radiogroup', 'aria-label': 'Protocols' });
      for (const f of ALL()) {
        if (f.kind === 'cert' && !picker.querySelector('.proto-pick-head')) picker.appendChild(h('div.proto-pick-head', icon('lock'), h('span', 'Certificates: how a client decides whom to trust')));
        const ok = available(f);
        const b = h('button.proto-pick' + (f.id === st.flow ? '.on' : ''), { type: 'button', role: 'radio', 'aria-checked': String(f.id === st.flow), disabled: !ok, dataset: { flow: f.id }, title: ok ? f.blurb : 'Coming with the protocol engine' }, h('b', f.title), h('span', ok ? f.blurb : 'coming soon'));
        b.addEventListener('click', () => { st.flow = f.id; st.step = -1; for (const c of picker.children) { const on = c === b; c.classList.toggle('on', on); c.setAttribute('aria-checked', String(on)); } load(); ctx.save(); });
        picker.appendChild(b);
      }
      host.appendChild(picker);
      const chartBox = h('div.b-stage.proto-chart', { id: 'protoChart' });
      const ctrl = h('div.proto-ctrl');
      const detail = h('div.proto-detail', { id: 'protoDetail', 'aria-live': 'polite' });
      const knows = h('div.proto-knows', { id: 'protoKnows' });
      const summary = h('div.proto-summary', { id: 'protoSummary' });
      const title = h('h2.proto-title', { id: 'protoTitle' });
      const ib = (id, ic, label, fn) => { const b = h('button.icon-btn', { type: 'button', id, title: label, 'aria-label': label }, icon(ic)); b.addEventListener('click', fn); return b; };
      const bFirst = ib('protoFirst', 'restart', 'Back to the start (Home)', () => go(-1));
      const bPrev = ib('protoPrev', 'prev', 'Step back (←)', () => go(st.step - 1));
      const bPlay = h('button.icon-btn.play', { type: 'button', id: 'protoPlay', title: 'Play (Space)', 'aria-label': 'Play' }, icon('run'));
      const bNext = ib('protoNext', 'next', 'Next step (→)', () => go(st.step + 1));
      const range = h('input', { type: 'range', id: 'protoRange', min: '-1', max: '0', value: '-1', 'aria-label': 'Step' });
      const pos = h('span.pos', { id: 'protoPos' });
      range.addEventListener('input', () => { stop(); go(+range.value); });
      let timer = null;
      const stop = () => { clearTimeout(timer); timer = null; bPlay.replaceChildren(icon('run')); bPlay.setAttribute('aria-label', 'Play'); };
      const play = () => {
        if (timer) { stop(); return; }
        if (st.step >= res.steps.length - 1) go(-1);
        bPlay.replaceChildren(icon('pause')); bPlay.setAttribute('aria-label', 'Pause');
        const tick = () => { if (st.step >= res.steps.length - 1) { stop(); return; } go(st.step + 1); timer = setTimeout(tick, 1500); };
        timer = setTimeout(tick, 500);
      };
      bPlay.addEventListener('click', play);
      ctrl.append(bFirst, bPrev, bPlay, bNext, range, pos);
      // the options of the protocol picked: the group (toy numbers or real X25519), a tampering, a fresh run
      const groupSel = U.select('protoGroup', [{ value: 'toy64', label: 'Toy group (64-bit numbers)' }, { value: 'x25519', label: 'X25519 (real, 32-byte keys)' }], st.group, (v) => { st.group = v; st.step = -1; load(); ctx.save(); });
      const tamperSel = U.select('protoTamper', [{ value: '', label: 'Nobody tampers' }, { value: 'cert', label: 'A forged certificate' }, { value: 'finished', label: 'A changed handshake message' }, { value: 'record', label: 'A changed record' }], st.tamper, (v) => { st.tamper = v; st.step = -1; load(); ctx.save(); });
      const fresh = h('button.btn.small', { type: 'button', id: 'protoFresh', title: 'Run it again with new random values' }, icon('shuffle'), 'New run');
      fresh.addEventListener('click', () => { st.seed = (st.seed % 9999) + 1; load(); ctx.save(); });
      const opts = h('div.proto-opts', U.field('Group', groupSel, 'inline'), U.field('Attack', tamperSel, 'inline'), fresh);
      host.appendChild(h('div.proto-grid', h('section.card.proto-left', h('div.proto-top', title, ctrl), opts, chartBox), h('div.proto-right', h('section.card.bcard', h('div.bcard-body', detail)), knows, summary)));
      let res = null, flow = null;

      function load() {
        stop();
        flow = ALL().find((f) => f.id === st.flow);
        chartBox.innerHTML = ''; detail.innerHTML = ''; knows.innerHTML = ''; summary.innerHTML = '';
        chartBox.classList.toggle('cert-mode', flow.kind === 'cert');
        if (flow.kind === 'cert') {
          groupSel.parentElement.style.display = 'none'; tamperSel.parentElement.style.display = 'none';
          title.textContent = flow.title;
          const key = flow.scenario + '|' + st.seed;
          const done = () => { res = certCache.get(key); range.max = String(res.steps.length - 1); st.step = Math.max(-1, Math.min(res.steps.length - 1, st.step)); go(st.step, true); };
          if (certCache.has(key)) { done(); return; }
          res = null;
          chartBox.appendChild(h('p.muted.cert-wait', { id: 'certWait' }, 'Making the CA keys (1024-bit RSA) and signing the certificates…'));
          const want = st.flow;
          setTimeout(() => {
            try { certCache.set(key, S.ProtoCert.run(flow.scenario, st.seed)); } catch (e) { chartBox.innerHTML = ''; chartBox.appendChild(h('div.berr', icon('warn'), h('span', 'This scenario could not run: ' + (e.message || e)))); console.error(e); return; }
            if (st.flow === want) { chartBox.innerHTML = ''; done(); }
          }, 30);
          return;
        }
        try { res = runFlow(flow, st); } catch (e) { res = null; chartBox.appendChild(h('div.berr', icon('warn'), h('span', 'This protocol could not run: ' + (e.message || e)))); console.error(e); return; }
        title.textContent = res.title || flow.title;
        groupSel.parentElement.style.display = flow.group && engineOf(flow) ? '' : 'none';
        tamperSel.parentElement.style.display = flow.tamper ? '' : 'none';
        range.max = String(res.steps.length - 1);
        st.step = Math.max(-1, Math.min(res.steps.length - 1, st.step));
        go(st.step, true);
      }
      function go(i, quiet) {
        if (!res) return;
        i = Math.max(-1, Math.min(res.steps.length - 1, i));
        st.step = i;
        if (!quiet) ctx.save();
        range.value = String(i);
        pos.textContent = (i + 1) + ' / ' + res.steps.length;
        bPrev.disabled = bFirst.disabled = i < 0;
        bNext.disabled = i >= res.steps.length - 1;
        chartBox.innerHTML = '';
        if (flow.kind === 'cert') {
          const PC = S.ProtoCert;
          chartBox.appendChild(PC.chain(res, i));
          detail.innerHTML = ''; detail.appendChild(PC.detail(res, i));
          knows.innerHTML = ''; knows.appendChild(PC.side(res, i));
          summary.innerHTML = ''; if (i === res.steps.length - 1) summary.appendChild(PC.summary(res));
          const lit = chartBox.querySelector('.cr-row.cur, .cr-row.bad:last-of-type');
          if (lit && !quiet && lit.scrollIntoView) { const r = lit.getBoundingClientRect(); if (r.top < 60 || r.bottom > innerHeight) lit.scrollIntoView({ block: 'nearest' }); }
          return;
        }
        const svg = S.ProtoChart.draw(res, i, { onPick: (k) => { stop(); go(k); } });
        chartBox.appendChild(svg);
        S.UI.scrollRow(chartBox);
        // on a narrow screen the chart scrolls sideways: keep the step being looked at in view
        if (chartBox.scrollWidth > chartBox.clientWidth + 2 && i >= 0) {
          const cur = svg.querySelector('.msc-step.cur');
          try { const b = cur.getBBox(), sc = svg.getBoundingClientRect().width / +svg.dataset.w; chartBox.scrollLeft = Math.max(0, (b.x + b.width / 2) * sc - chartBox.clientWidth / 2); } catch (e) { /* not laid out yet */ }
        }
        renderDetail(i);
        renderKnows(i);
        renderSummary(i);
      }
      function renderDetail(i) {
        detail.innerHTML = '';
        const name = (id) => (res.parties.find((p) => p.id === id) || { label: id }).label;
        if (i < 0) { detail.append(h('div.pd-k', 'Before the run'), h('p', 'Nobody has sent anything yet. The cards show what each party starts with. Step forward with → or the buttons, or click a row of the chart.')); return; }
        const s = res.steps[i];
        if (s.type === 'message') {
          detail.append(h('div.pd-k', 'Message ' + s.i + ' · ' + name(s.from) + ' → ' + name(s.to) + (s.as !== s.from ? ' (posing as ' + name(s.as) + ')' : '') + (s.intended && s.intended !== s.to ? ' (meant for ' + name(s.intended) + ')' : '')),
            h('div.pd-label', s.label || ''), ...(s.note ? [h('p', s.note)] : []), h('div.kv', h('span.k', 'Content'), h('code.v', s.content)));
          for (const w of s.wire || []) if (w.sealed) detail.appendChild(h('div.kv', h('span.k', 'On the wire'), h('code.v.wire', w.bytes.length > 64 ? w.bytes.slice(0, 64) + '…' : w.bytes), h('span.muted.small', ' sealed: ' + w.term)));
          if (s.values) for (const [k, v] of Object.entries(s.values)) detail.appendChild(h('div.kv', h('span.k', k), h('code.v', show(v))));
          for (const [pid, got] of Object.entries(s.learned || {})) detail.appendChild(h('div.kv', h('span.k', name(pid) + ' learns'), got.length ? h('span.v', got.join(', ')) : h('span.muted', 'nothing new')));
        } else if (s.type === 'check') {
          detail.append(h('div.pd-k', 'A check by ' + name(s.party)), h('p.pd-check.' + (s.ok ? 'ok' : 'no'), icon(s.ok ? 'check' : 'x'), h('span', s.say)));
        } else {
          detail.append(h('div.pd-k', 'Meanwhile'), h('p', s.say));
          if (s.values) for (const [k, v] of Object.entries(s.values)) detail.appendChild(h('div.kv', h('span.k', k), h('code.v', show(v))));
        }
      }
      function renderKnows(i) {
        knows.innerHTML = '';
        const ids = res.parties.map((p) => p.id), step = i >= 0 ? res.steps[i] : res.steps[0];
        for (const p of res.parties) {
          const now = knowsAt(res, i, p.id), before = new Set(knowsAt(res, i - 1, p.id));
          const bad = p.role === 'attacker' || p.role === 'eavesdropper';
          const chips = now.map((n) => { const k = S.ProtoChart.kindOf(n, step, ids); return h('span.kchip.' + k + (i >= 0 && !before.has(n) ? '.new' : ''), { title: k + (i >= 0 && !before.has(n) ? ', just learned' : '') }, n); });
          knows.appendChild(h('section.card.kcard' + (bad ? '.bad' : ''), { dataset: { party: p.id } }, h('div.kc-head', h('b', p.label), p.role && p.role !== 'honest' ? h('span.kc-role', { trusted: 'trusted', attacker: 'attacker', eavesdropper: 'listening' }[p.role] || p.role) : null, h('span.kc-n', now.length + ' known')), h('div.kc-chips', ...chips)));
        }
      }
      function renderSummary(i) {
        summary.innerHTML = '';
        if (i < res.steps.length - 1) return;
        const ok = res.ok !== false && !(res.attack && res.attack.success);
        summary.appendChild(h('div.ls-note.' + (ok ? 'tip' : 'warn'), icon(ok ? 'check' : 'warn'), h('div', h('b', ok ? 'The run completes. ' : 'The protocol is broken here. '), res.summary || '')));
        const at = res.attack || {};
        if (at.aliceSent !== undefined) summary.appendChild(h('div.card.bcard', h('div.bcard-body', U2().kv('Alice sent', at.aliceSent), U2().kv('Mallory read', at.mallorySaw), U2().kv('Bob read', at.bobRead))));
      }
      load();
      return {
        state: () => ({ flow: st.flow, step: st.step, seed: st.seed, group: st.group, tamper: st.tamper }),
        dispose: stop,
        keys: [['Protocol bench', [['→  ←', 'Next step, step back'], ['Home  End', 'Start, end'], ['Space', 'Play or pause']]]],
        onKey(e, typing) {
          if (typing || e.metaKey || e.ctrlKey || e.altKey) return false;
          const tag = (e.target && e.target.tagName) || '';
          if (tag === 'BUTTON' && (e.key === ' ' || e.key === 'Enter')) return false;
          const k = e.key;
          if (k === 'ArrowRight') { stop(); go(st.step + 1); } else if (k === 'ArrowLeft') { stop(); go(st.step - 1); } else if (k === 'Home') { stop(); go(-1); } else if (k === 'End') { stop(); go(res ? res.steps.length - 1 : 0); } else if (k === ' ') play(); else return false;
          e.preventDefault(); return true;
        },
        go, get result() { return res; }, get step() { return st.step; },
      };
    },
  });
  if (S.Checks) {
    S.Checks.push({ group: 'bench-proto', name: 'Diffie–Hellman, the start', hash: 'bench/proto', ready: "document.querySelector('#protoChart svg')", setup: "document.querySelector('.proto-pick[data-flow=\"dh\"]').click(); Sifer.app.page.bench.go(-1);", sel: '#main' });
    S.Checks.push({ group: 'bench-proto', name: 'the man in the middle, at the end', hash: 'bench/proto', ready: "document.querySelector('#protoChart svg')", setup: "document.querySelector('.proto-pick[data-flow=\"mitm\"]').click(); Sifer.app.page.bench.go(99);", sel: '#main' });
    S.Checks.push({ group: 'bench-proto', name: 'certificates: a valid chain, all checked', hash: 'bench/proto', ready: "document.querySelector('#certChain') && Sifer.app.page.bench.result && Sifer.app.page.bench.step === Sifer.app.page.bench.result.steps.length - 1", setup: "document.querySelector('.proto-pick[data-flow=\"cert-valid\"]').click(); await new Promise((r) => { const t = setInterval(() => { if (document.querySelector('#certChain')) { clearInterval(t); r(); } }, 50); }); Sifer.app.page.bench.go(99);", sel: '#main' });
    S.Checks.push({ group: 'bench-proto', name: 'certificates: revoked by the list', hash: 'bench/proto', ready: "document.querySelector('#certChain[data-scenario=\"revoked-crl\"]') && Sifer.app.page.bench.step >= 0", setup: "document.querySelector('.proto-pick[data-flow=\"cert-revoked-crl\"]').click(); await new Promise((r) => { const t = setInterval(() => { if (document.querySelector('#certChain')) { clearInterval(t); r(); } }, 50); }); Sifer.app.page.bench.go(99);", sel: '#main' });
    S.Checks.push({ group: 'bench-proto', name: 'certificates: a forged certificate stopped', hash: 'bench/proto', ready: "document.querySelector('#certChain[data-scenario=\"fake\"]') && Sifer.app.page.bench.step >= 0", setup: "document.querySelector('.proto-pick[data-flow=\"cert-fake\"]').click(); await new Promise((r) => { const t = setInterval(() => { if (document.querySelector('#certChain')) { clearInterval(t); r(); } }, 50); }); Sifer.app.page.bench.go(99);", sel: '#main' });
    S.Checks.push({ group: 'bench-proto', name: 'Kerberos, a middle step', hash: 'bench/proto', ready: "document.querySelector('#protoChart svg')", setup: "document.querySelector('.proto-pick[data-flow=\"kerberos\"]').click(); Sifer.app.page.bench.go(4);", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
