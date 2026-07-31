// The cipher bench (#bench/cipher): pick a cipher and a mode, give the key, the IV or nonce and the input as text, hex
// or a file, and see everything: the output, every round's state with what it changed, the steps inside a round, the
// data flow of the mode block by block, the avalanche of one flipped bit, and the engine's own narration. A toy cipher
// can sit beside the real one it teaches (Mini-AES and AES-128, the toy SPN and PRESENT).
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const CB = (S.CipherBench = S.CipherBench || {});
  const enc = (t) => new TextEncoder().encode(t);
  const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
  const PLAIN = 'Bring the lantern to the north gate at nine.';
  const REPEAT = 'HOLD THE BRIDGE.HOLD THE BRIDGE.HOLD THE BRIDGE.';
  // our own keys and IVs, one set per cipher
  const DEF = {
    aes128: { key: 'quiet larch 2026', iv: 'saltmarsh-iv-016' }, aes192: { key: 'quiet larch 2026 / north', iv: 'saltmarsh-iv-016' },
    aes256: { key: 'quiet larch 2026, saltmarsh road', iv: 'saltmarsh-iv-016' }, des: { key: 'heron!42', iv: 'ivy-0008' },
    '3des': { key: 'heron!42 kite#77', iv: 'ivy-0008' }, present: { key: 'willow-80b', iv: 'ivy-0008' },
    miniaes: { keyHex: '3c9a', ivHex: '9e01', textHex: 'b74e' }, spn: { keyHex: '5a3c91e70f42b6d82e19', ivHex: '4d2b', textHex: '7a1f' },
    chacha20: { key: 'lanterns hang over the old quay.', iv: 'fern-nonce12' }, salsa20: { key: 'lanterns hang over the old quay.', iv: 'moss-n08' },
    trivium: { key: 'tide-key10', iv: 'tide-iv-10' },
  };
  const fieldOf = (d, k) => (d[k + 'Hex'] !== undefined ? { mode: 'hex', hex: d[k + 'Hex'], text: '' } : { mode: 'text', text: d[k] || '', hex: '' });
  const defaults = (algo) => {
    const d = DEF[algo.id] || {};
    return { key: algo.kind === 'classic' ? algo.keyDef : fieldOf(d, 'key'), iv: d.iv || d.ivHex ? fieldOf(d, 'iv') : { mode: 'text', text: '', hex: '' }, text: d.textHex ? { mode: 'hex', hex: d.textHex, text: '' } : { mode: 'text', text: PLAIN, hex: '' } };
  };

  S.Bench.tab('cipher', {
    title: 'Cipher bench', icon: 'cipher', order: 10,
    blurb: 'Any cipher, any mode, every intermediate value, toy beside real, and the avalanche of a flipped bit.',
    open(host, saved, ctx) {
      const U = S.BenchUI;
      const first = CB.byId((saved && saved.algo) || 'aes128') || CB.byId('aes128');
      let st = Object.assign({ algo: first.id, mode: 'cbc', dir: 'enc', view: 'rounds', toy: false, round: null, block: 0, aval: { target: 'plaintext', bit: 0 } }, defaults(first), saved || {});
      st.aval = Object.assign({ target: 'plaintext', bit: 0 }, st.aval);
      let last = null;
      const algo = () => CB.byId(st.algo) || CB.byId('aes128');

      // ---- the head and the setup card ---------------------------------------------------------------------------
      const share = h('button.btn', { type: 'button', id: 'cbShare', title: 'Copy a link to this exact setup' }, icon('link'), 'Share');
      share.addEventListener('click', () => ctx.share());
      host.appendChild(h('div.bench-head', h('div', h('h1', 'Cipher bench'), h('p', 'Pick a cipher, give it a key and some input, and watch every value it computes. Flip one bit and watch the change spread.')), h('div.bench-acts', share)));
      const areaSeg = U.seg('cbArea', [['run', 'Encrypt and decrypt'], ['labs', 'Labs and defences']], st.area || 'run', (v) => { st.area = v; ctx.save(); layout(); });
      host.appendChild(h('div.cb-area', areaSeg));
      const grid = h('div.bench-grid');
      const labsBox = h('div.cb-labs', { id: 'cbLabs' });
      host.append(grid, labsBox);
      const setup = h('div.bcard-body');
      const out = h('div.b-out', { id: 'cbOut' });
      grid.append(h('section.card.bcard.cb-setup', h('div.bcard-head', h('h3', 'Setup')), setup), out);

      const groups = []; for (const a of CB.algos) { let g = groups.find((x) => x.group === a.group); if (!g) groups.push(g = { group: a.group, items: [] }); g.items.push({ value: a.id, label: a.label + (a.has() ? '' : ' (coming)') }); }
      let fKey, fIv, fText, keyText;
      const build = () => {
        setup.innerHTML = '';
        const A = algo();
        setup.appendChild(U.field('Cipher', U.select('cbAlgo', groups, A.id, (v) => { const n = CB.byId(v); Object.assign(st, { algo: v, round: null, block: 0 }, defaults(n)); if (CB.MODES.some((m) => m.aes && m.id === st.mode) && !/^aes/.test(v)) st.mode = 'cbc'; if (/^aes/.test(v)) modeDefaults(st.mode); if (n.kind !== 'block') st.view = n.kind === 'classic' ? 'result' : 'keystream'; else if (!['rounds', 'mode', 'aval', 'trace'].includes(st.view)) st.view = 'rounds'; if (!CB.pairs[v]) st.toy = false; build(); run(); })));
        setup.appendChild(h('p.b-note', A.blurb));
        const row = h('div.brow');
        if (A.kind === 'block') row.appendChild(U.field('Mode', U.select('cbMode', CB.MODES.filter((m) => (!m.aes || /^aes/.test(A.id)) && (!m.has || m.has())).map((m) => ({ value: m.id, label: m.label })), st.mode, (v) => { const was = st.mode; st.mode = v; if (v === 'gcm' || v === 'xts' || was === 'gcm' || was === 'xts') { Object.assign(st, defaults(A)); modeDefaults(v); } build(); run(); })));
        const dir = U.seg('cbDir', [['enc', 'Encrypt'], ['dec', 'Decrypt']], st.dir, (v) => { st.dir = v; build(); run(); });
        row.appendChild(U.field('Direction', dir));
        setup.appendChild(row);
        if (A.kind === 'block') { const m = CB.MODES.find((x) => x.id === st.mode); setup.appendChild(h('p.b-note', m.blurb)); }
        if (A.kind === 'classic') {
          keyText = U.input('cbKey', st.key, (v) => { st.key = v; run(); }, { label: A.keyLabel });
          setup.appendChild(U.field(A.keyLabel + ' · ' + A.keyHelp, keyText));
          fText = U.bytesField({ id: 'cbText', label: st.dir === 'dec' ? 'Ciphertext' : 'Plaintext', value: Object.assign({}, st.text, { mode: 'text' }), rows: 3, onChange: (v) => { st.text = v; run(); } });
          setup.appendChild(fText.el);
          fKey = fIv = null;
        } else {
          const kl = A.kind === 'block' ? (st.mode === 'xts' ? [32, 64] : A.keyLens) : [A.keyLen];
          fKey = U.bytesField({ id: 'cbKey', label: st.mode === 'xts' ? 'Key (two AES keys: 32 or 64 bytes)' : 'Key (' + kl.join(' or ') + ' bytes)', value: st.key, bytes: kl.length > 1 ? [Math.min(...kl), Math.max(...kl)] : kl[0], onChange: (v) => { st.key = v; run(); } });
          setup.appendChild(fKey.el);
          const ivn = A.kind === 'block' ? (st.mode === 'ctr' ? 'Initial counter' : st.mode === 'gcm' ? 'Nonce' : st.mode === 'xts' ? 'Tweak, the sector number' : 'IV') : A.ivName;
          const ivLen = A.kind === 'block' ? (st.mode === 'gcm' ? 12 : A.n) : A.ivLen;
          fIv = U.bytesField({ id: 'cbIv', label: ivn + ' (' + ivLen + ' bytes)', value: st.iv, bytes: ivLen, onChange: (v) => { st.iv = v; run(); } });
          if (!(A.kind === 'block' && st.mode === 'ecb')) setup.appendChild(fIv.el);
          if (st.mode === 'gcm' && A.kind === 'block') setup.appendChild(U.field('Associated data (authenticated, not encrypted)', U.input('cbAad', st.aad || '', (v) => { st.aad = v; run(); })));
          fText = U.bytesField({ id: 'cbText', label: st.dir === 'dec' ? (st.mode === 'gcm' ? 'Ciphertext ‖ tag' : 'Ciphertext') : 'Plaintext', value: st.text, rows: 3, onChange: (v) => { st.text = v; run(); } });
          setup.appendChild(fText.el);
          if (A.kind === 'block' && A.n === 16) {
            const rep = h('button.chip', { type: 'button', id: 'cbRepeat', title: 'A message with three equal 16-byte blocks' }, 'Repeated blocks');
            rep.addEventListener('click', () => { st.text = { mode: 'text', text: REPEAT, hex: '' }; st.dir = 'enc'; build(); run(); });
            const own = h('button.chip', { type: 'button', id: 'cbDefault' }, 'The default message');
            own.addEventListener('click', () => { st.text = { mode: 'text', text: PLAIN, hex: '' }; st.dir = 'enc'; build(); run(); });
            setup.appendChild(h('div.presets', rep, own));
          }
          if (A.keyLens && A.keyLens.length > 1 && A.id === '3des') setup.appendChild(h('p.b-note', '16 bytes: two keys, K3 = K1. 24 bytes: three keys.'));
        }
        for (const ta of setup.querySelectorAll('textarea')) S.UI.autosize(ta, 160);
        const swap = h('button.btn.small', { type: 'button', id: 'cbSwap', title: 'Put the output in the input and change direction' }, icon('convert'), 'Use the output as input');
        swap.addEventListener('click', () => { if (!last || !last.out) return; st.text = A.kind === 'classic' ? { mode: 'text', text: last.outText, hex: '' } : { mode: 'hex', hex: hex(last.out), text: '' }; st.dir = st.dir === 'enc' ? 'dec' : 'enc'; build(); run(); });
        const acts = h('div.brow.cb-acts', swap);
        if (CB.pairs[A.id]) {
          const t = h('input', { type: 'checkbox', id: 'cbToy', checked: !!st.toy });
          t.addEventListener('change', () => { st.toy = t.checked; run(); });
          acts.appendChild(h('label.toggle-real', t, h('span', 'Show ' + CB.byId(CB.pairs[A.id]).label + ' beside it')));
        }
        setup.appendChild(acts);
      };

      // ---- running -------------------------------------------------------------------------------------------------
      const ivBytes = (A) => { if (A.kind === 'block' && st.mode === 'ecb') return new Uint8Array(0); return fIv.get(); };
      const run = () => {
        ctx.save();
        out.innerHTML = '';
        last = null;
        const A = algo();
        if (!A.has()) { out.appendChild(U.missing('The ' + A.label + ' engine', 'This cipher switches on as soon as its engine is in place. Every other cipher in the list works now.')); return; }
        const res = U.guard(out, () => {
          if (A.kind === 'classic') { const t = st.text.text || ''; if (!/[a-z]/i.test(t)) throw new Error('The text must have letters in it.'); const r = A.run(t, String(st.key), st.dir === 'dec'); return { kind: 'classic', out: enc(r.out), outText: r.out, r }; }
          const key = fKey.get(), iv = ivBytes(A), data = fText.get();
          if (!data.length) throw new Error('The input is empty: type a message or choose a file.');
          if (data.length > 4096 && A.kind === 'block') throw new Error('The bench draws every block: keep the input to 4096 bytes (it is ' + data.length + ').');
          if (A.kind === 'block') {
            if (st.mode === 'gcm' || st.mode === 'xts') { const m = CB.aesMode(st.mode, key, data, iv, st.dir === 'dec', enc(st.aad || '')); return { kind: 'block', out: m.out, mode: m, key, iv, data, cipherKey: m.cipherKey || key }; }
            const E = A.cipher(key);
            const m = CB.mode(st.mode, E, data, iv, st.dir === 'dec');
            return { kind: 'block', out: m.out, mode: m, key, iv, data, cipherKey: key };
          }
          const r = A.run(key, iv, data);
          return { kind: 'stream', out: r.out, r, key, iv, data };
        });
        if (!res) return;
        last = res;
        out.appendChild(outputCard(A, res));
        if (st.toy && CB.pairs[A.id] && res.kind === 'block') out.appendChild(toyCard(A, res));
        const views = A.kind === 'classic' ? [['result', 'Result'], ['trace', 'Narration']] : A.kind === 'block' ? [['rounds', 'Rounds'], ['mode', 'Mode, block by block'], ['aval', 'Avalanche'], ['trace', 'Narration']] : [['keystream', 'Keystream'], [A.view === 'registers' ? 'registers' : 'rounds', A.view === 'registers' ? 'Registers' : 'Block function'], ['aval', 'Avalanche'], ['trace', 'Narration']];
        if (!views.some((v) => v[0] === st.view)) st.view = views[0][0];
        const body = h('div.cb-view', { id: 'cbView' });
        const seg = U.seg('cbViews', views, st.view, (v) => { st.view = v; ctx.save(); showView(A, res, body); });
        out.appendChild(h('section.card.bcard', h('div.bcard-head.cb-vhead', seg), h('div.bcard-body', body)));
        showView(A, res, body);
      };

      const outputCard = (A, res) => {
        const isDec = st.dir === 'dec';
        let text = '';
        if (res.kind === 'classic') text = res.outText;
        else { try { text = new TextDecoder('utf-8', { fatal: true }).decode(res.out); if (/[\u0000-\u0008\u000e-\u001f]/.test(text)) text = ''; } catch (e) { text = ''; } }
        const copy = h('button.btn.small', { type: 'button', id: 'cbCopy' }, icon('copy'), 'Copy hex');
        copy.addEventListener('click', () => S.Share.copy(hex(res.out), 'The output is copied as hex.'));
        const facts = [];
        if (res.kind === 'block') facts.push(st.mode.toUpperCase() + (res.mode.gcm && st.dir !== 'dec' ? ' · ciphertext then its 16-byte tag' : '') + ' · ' + res.mode.blocks.length + ' block' + (res.mode.blocks.length === 1 ? '' : 's') + (res.mode.pad ? ' · ' + res.mode.pad + ' padding bytes' : ''), st.mode === 'ecb' && CB.repeats(res.mode.blocks) ? CB.repeats(res.mode.blocks) + ' repeated ciphertext block' + (CB.repeats(res.mode.blocks) === 1 ? '' : 's') : '');
        return h('section.card.bcard', { id: 'cbResult' }, h('div.bcard-head', h('h3', isDec ? 'Plaintext' : 'Ciphertext'), h('p', res.out.length + ' bytes' + (facts.filter(Boolean).length ? ' · ' + facts.filter(Boolean).join(' · ') : ''))),
          h('div.bcard-body', res.kind === 'classic' ? h('div.cb-text.mono', { id: 'cbOutText' }, text) : U.hexGrid(res.out, { id: 'cbOutHex', cols: 16, label: 'hex' }),
            res.kind !== 'classic' && text ? h('div.kv', h('span.k', 'as text'), h('code.v', { id: 'cbOutText' }, text)) : null,
            h('div.brow', h('code.cb-hexline', { id: 'cbOutLine' }, hex(res.out).slice(0, 512) + (res.out.length > 256 ? '…' : '')), copy)));
      };

      const decMode = () => st.dir === 'dec' && (st.mode === 'ecb' || st.mode === 'cbc' || st.mode === 'xts');
      const modeDefaults = (m) => { if (m === 'gcm') { st.iv = { mode: 'text', text: 'fern-nonce12', hex: '' }; st.aad = st.aad || 'gate-log 7'; } if (m === 'xts') { st.key = { mode: 'text', text: 'quiet larch 2026saltmarsh-iv-016', hex: '' }; st.iv = { mode: 'hex', hex: '05000000000000000000000000000000', text: '' }; } };
      // ---- the views ------------------------------------------------------------------------------------------------
      const blockPicker = (res, onPick) => {
        const n = res.mode.blocks.length;
        if (n < 2) return null;
        const s = U.select('cbBlock', res.mode.blocks.map((b) => ({ value: String(b.i), label: 'Block ' + (b.i + 1) + ': the cipher on ' + hex(b.cin).slice(0, 12) + '…' })), String(Math.min(st.block, n - 1)), (v) => { st.block = +v; st.round = null; onPick(); });
        return U.field('Which cipher call', s, 'inline');
      };
      const showView = (A, res, body) => {
        body.innerHTML = '';
        if (st.view === 'trace') { const tr = res.kind === 'block' ? res.mode.trace.concat(A.roundsOf(res.mode.blocks[Math.min(st.block, res.mode.blocks.length - 1)].cin, res.cipherKey, decMode()).trace || []) : res.kind === 'classic' ? res.r.trace : res.r.trace; body.appendChild(h('div.trace-box', U.trace(tr, { id: 'cbTrace' }))); return; }
        if (res.kind === 'classic') { body.appendChild(classicView(A, res)); return; }
        if (res.kind === 'block' && st.view === 'rounds') {
          const draw = () => {
            body.innerHTML = '';
            const pick = blockPicker(res, draw); if (pick) body.appendChild(pick);
            const b = res.mode.blocks[Math.min(st.block, res.mode.blocks.length - 1)];
            const dec = decMode();
            const r = A.roundsOf(b.cin, res.cipherKey, dec);
            body.appendChild(h('p.b-note', 'The cipher ' + (dec ? 'decrypts ' : 'encrypts ') + hex(b.cin) + ' to ' + hex(r.out) + '. Bytes that changed in a round are lit; click a round to see its steps.'));
            const det = h('div', { id: 'cbDetailBox' });
            body.appendChild(CB.view.ladder(A, r, (k) => { st.round = k; det.innerHTML = ''; det.appendChild(CB.view.detail(A, r.states[k])); for (const x of body.querySelectorAll('.lrow')) x.classList.toggle('on', +x.dataset.k === k); }));
            body.appendChild(det);
            if (st.round !== null && r.states[st.round] && r.states[st.round].detail) det.appendChild(CB.view.detail(A, r.states[st.round]));
          };
          draw();
          return;
        }
        if (res.kind === 'block' && st.view === 'mode') {
          body.appendChild(h('p.b-note', CB.MODES.find((m) => m.id === st.mode).blurb + ' The first blocks, drawn:'));
          if (st.mode !== 'xts' && st.mode !== 'cfb8') body.appendChild(CB.view.modeFlow(st.mode === 'gcm' ? 'ctr' : st.mode === 'cts' ? 'cbc' : st.mode, A.label.replace(/ \(.*\)/, ''), res.mode, st.dir === 'dec' && st.mode !== 'cts', 3));
          if (res.mode.cts) body.appendChild(h('p.b-note', 'Drawn above: the CBC chain over the message with its last block filled with zeros. Ciphertext stealing then cuts the next-to-last ciphertext block to the length of the last plaintext block and puts the last full block before it, so nothing is added.'));
          if (res.mode.cfb8) body.appendChild(h('p.b-note', 'One cipher call per byte: the first byte of E(register) is XORed with one message byte, and the register shifts left to take in that ciphertext byte.' + (res.mode.total > res.mode.blocks.length ? ' The first ' + res.mode.blocks.length + ' of ' + res.mode.total + ' bytes:' : '')));
          if (res.mode.gcm) body.appendChild(h('div.gcm-facts', U.kv('hash key H = E(0)', hex(res.mode.H)), U.kv('J0 (counter 1)', hex(res.mode.J0)), U.kv('tag', hex(res.mode.tag)), h('p.b-note', 'The data is encrypted from counter 2 on; counter 1, encrypted, masks the GHASH of the associated data and the ciphertext to give the tag.')));
          if (res.mode.xts) body.appendChild(h('p.b-note', 'Each block j is masked before and after the cipher with T·α^j, the encrypted tweak multiplied by x j times in GF(2^128).' + (res.mode.blocks.some((b) => b.stolen) ? ' The last two blocks share bytes by ciphertext stealing, so the output is as long as the input.' : '')));
          body.appendChild(CB.view.modeTable(st.mode === 'cts' ? 'cbc' : st.mode, res.mode, st.dir === 'dec' && st.mode !== 'cts'));
          requestAnimationFrame(() => S.UI.fitTables(body));
          return;
        }
        if (st.view === 'aval') { body.appendChild(avalView(A, res)); return; }
        if (st.view === 'keystream') {
          const n = Math.min(64, res.out.length), rows = [];
          for (let i = 0; i < n; i += 8) rows.push(h('tr', h('td', String(i)), h('td.mono', hex(res.data.slice(i, i + 8))), h('td.mono', '⊕ ' + hex(res.r.keystream.slice(i, i + 8))), h('td.mono', '= ' + hex(res.out.slice(i, i + 8)))));
          body.append(h('p.b-note', 'The cipher makes a keystream from the key and the ' + A.ivName.toLowerCase() + ' alone; the message is only XORed into it. Never reuse a key with the same ' + A.ivName.toLowerCase() + ': two messages XORed under one keystream give away the XOR of the messages.'),
            h('div.b-scroll.fit-table', { id: 'cbKeystream' }, h('table.b-table', h('thead', h('tr', h('th', 'byte'), h('th', st.dir === 'dec' ? 'ciphertext' : 'plaintext'), h('th', 'keystream'), h('th', st.dir === 'dec' ? 'plaintext' : 'ciphertext'))), h('tbody', rows))));
          return;
        }
        if (st.view === 'registers') { body.append(h('p.b-note', 'The 288 bits after the 1152 warm-up clocks: lit cells hold 1. Each clock shifts all three registers by one and outputs t1 ⊕ t2 ⊕ t3.'), CB.view.registers(res.r.registers || [])); return; }
        if (st.view === 'rounds' && A.rounds) {
          const states = A.rounds(res.key, res.iv);
          body.appendChild(h('p.b-note', 'The block function for block 1: the initial state (constants, key, counter, ' + A.ivName.toLowerCase() + '), then each double round, then the input added back. Words that changed are lit.'));
          body.appendChild(CB.view.ladder({ view: 'words' }, { states }));
        }
      };
      const classicView = (A, res) => {
        const box = h('div.cb-classic', { id: 'cbClassic' });
        const x = res.r.extra || {};
        if (x.alphabet) { const al = h('div.alpha', h('div.al-row', h('span.k', 'plain'), ...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('').map((c) => h('span', c))), h('div.al-row.key', h('span.k', 'cipher'), ...x.alphabet.split('').map((c) => h('span', c)))); box.appendChild(al); requestAnimationFrame(() => S.UI.scrollRow(al)); }
        if (x.square) box.appendChild(h('div.pf-square', { role: 'img', 'aria-label': 'The 5×5 Playfair square' }, ...x.square.split('').map((c) => h('span', c))));
        if (x.grid && Array.isArray(x.grid)) box.appendChild(h('div.fit-table', h('table.b-table.cg', h('tbody', ...x.grid.map((r) => h('tr', ...(Array.isArray(r) ? r : String(r).split('')).map((c) => h('td.mono', c))))))));
        box.appendChild(h('div.kv', h('span.k', st.dir === 'dec' ? 'ciphertext' : 'plaintext'), h('code.v', st.text.text || '')));
        box.appendChild(h('div.kv', h('span.k', st.dir === 'dec' ? 'plaintext' : 'ciphertext'), h('code.v', res.outText)));
        return box;
      };
      const avalView = (A, res) => {
        const box = h('div');
        const first = res.kind === 'block' ? res.mode.blocks[0] : null;
        const inputs = res.kind === 'block' ? { block: first.cin, key: res.cipherKey } : { key: res.key, iv: res.iv, text: res.data.slice(0, 64) };
        const targets = res.kind === 'block' ? [['plaintext', 'Input block'], ['key', 'Key']] : [['plaintext', 'Plaintext'], ['key', 'Key'], ['iv', A.ivName]];
        if (!targets.some((t) => t[0] === st.aval.target)) st.aval.target = 'plaintext';
        const holder = h('div');
        const draw = () => {
          holder.innerHTML = '';
          const r = U.guard(holder, () => CB.avalanche(A, inputs, st.aval.target, st.aval.bit));
          if (!r) return;
          st.aval.bit = r.bit; bitIn.max = String(r.srcBits - 1); bitIn.value = String(r.bit);
          holder.appendChild(bitStrip(r));
          holder.appendChild(CB.view.avalanche(r, Math.min(760, (box.clientWidth || 640) - 4)));
          ctx.save();
        };
        const bitIn = h('input', { type: 'number', id: 'cbBit', min: '0', value: String(st.aval.bit), 'aria-label': 'The bit to flip', style: { width: '90px' } });
        bitIn.addEventListener('change', () => { st.aval.bit = +bitIn.value || 0; draw(); });
        const rnd = h('button.btn.small', { type: 'button', id: 'cbBitRandom' }, icon('shuffle'), 'Another bit');
        rnd.addEventListener('click', () => { const n = +bitIn.max + 1 || 128; st.aval.bit = (st.aval.bit + 37 + Math.floor(Math.random() * 50)) % n; draw(); });
        const seg = U.seg('cbAvalTarget', targets, st.aval.target, (v) => { st.aval.target = v; st.aval.bit = 0; draw(); });
        box.appendChild(h('div.brow.cb-aval-ctl', U.field('Flip a bit of', seg), U.field('Bit', bitIn), rnd));
        if (res.kind === 'block') box.appendChild(h('p.b-note', 'The input block is the first cipher call of the ' + st.mode.toUpperCase() + ' run: ' + hex(first.cin) + '.'));
        box.appendChild(holder);
        requestAnimationFrame(draw);
        return box;
      };
      /** the bits of what is flipped, the flipped one lit: click one to flip it instead */
      const bitStrip = (r) => {
        const n = Math.min(r.srcBits, 256), g = h('div.bitstrip', { id: 'cbBits', role: 'group', 'aria-label': 'Click a bit to flip it' });
        for (let i = 0; i < n; i++) {
          const v = (r.src[i >> 3] >> (7 - (i & 7))) & 1;
          const b = h('button.bit' + (v ? '.one' : '') + (i === r.bit ? '.flip' : ''), { type: 'button', title: 'bit ' + i + ' = ' + v, 'aria-label': 'bit ' + i, dataset: { i: String(i) } });
          b.addEventListener('click', () => { st.aval.bit = i; const ctl = document.getElementById('cbBit'); if (ctl) { ctl.value = String(i); ctl.dispatchEvent(new Event('change')); } });
          g.appendChild(b);
        }
        return h('div.bitstrip-box', h('span.muted', r.target === 'plaintext' ? 'The input bits' : 'The ' + r.target + ' bits', r.srcBits > n ? ' (the first ' + n + ')' : ''), g);
      };
      const toyCard = (A, res) => {
        const P = CB.byId(CB.pairs[A.id]);
        const b0 = res.mode.blocks[0].cin, fit = (src, n) => { const o = new Uint8Array(n); for (let i = 0; i < n; i++) o[i] = src.length ? src[i % src.length] : 0; return o; };
        const pk = fit(res.cipherKey, P.keyLens[0]), pb = fit(b0, P.n);
        const ra = A.roundsOf(b0, res.cipherKey), rb = P.roundsOf(pb, pk);
        const side = (X, r, blk, key) => h('div.toy-side', h('h4', X.label + (X.toy ? ' · toy' : ' · real')), h('p.b-note', 'Block ' + hex(blk) + ', key ' + hex(key) + ' → ' + hex(r.out)), CB.view.ladder(X, r));
        return h('section.card.bcard', { id: 'cbToyCard' }, h('div.bcard-head', h('h3', 'Toy beside real'), h('p', A.view === 'mini' || P.view === 'mini' ? 'The same four steps (substitute, shift the rows, mix the columns, add the round key) on 16 bits and on 128 bits.' : 'Both are substitution–permutation networks: 4-bit S-boxes, then a bit permutation, then the round key.')),
          h('div.bcard-body.toy-grid', side(A, ra, b0, res.cipherKey), side(P, rb, pb, pk)));
      };

      // ---- labs and defences -------------------------------------------------------------------------------------------
      let labInst = null;
      const labs = () => {
        if (labInst && labInst.stop) labInst.stop();
        labInst = null;
        labsBox.innerHTML = '';
        const ORDER = ['Modes', 'Block ciphers', 'Stream ciphers'];
        const list = (CB.labs || []).filter((l) => l.has()).map((l, i) => [l, i]).sort((x, y) => (ORDER.indexOf(x[0].group) - ORDER.indexOf(y[0].group)) || x[1] - y[1]).map((x) => x[0]);
        if (!list.length) { labsBox.appendChild(U.missing('The attack engines')); return; }
        const cur = list.find((l) => l.id === st.lab) || list[0];
        st.lab = cur.id;
        const nav = h('nav.lab-list', { 'aria-label': 'Labs and defences' });
        let group = null;
        for (const l of list) {
          if (l.group !== group) { group = l.group; nav.appendChild(h('div.lab-group', group)); }
          const b = h('button.lab-item' + (l.id === cur.id ? '.on' : ''), { type: 'button', dataset: { lab: l.id }, 'aria-current': l.id === cur.id ? 'true' : null }, l.title);
          b.addEventListener('click', () => { st.lab = l.id; ctx.save(); labs(); });
          nav.appendChild(b);
        }
        st.labs = st.labs || {};
        const lctx = st.labs[cur.id] = Object.assign({ seed: 1 }, st.labs[cur.id] || {});
        lctx.save = () => ctx.save();
        const body = h('div.bcard-body', { id: 'labBody', dataset: { lab: cur.id } });
        labsBox.append(nav, h('section.card.bcard.lab-card', h('div.bcard-head', h('h3', cur.title), h('p', cur.blurb)), body));
        try { labInst = cur.render(body, lctx) || null; } catch (e) { body.appendChild(h('div.berr', String(e.message || e))); console.error(e); }
      };
      const layout = () => {
        const isLabs = st.area === 'labs';
        grid.style.display = isLabs ? 'none' : '';
        labsBox.style.display = isLabs ? '' : 'none';
        if (isLabs) labs(); else if (labInst && labInst.stop) { labInst.stop(); labInst = null; }
      };

      build();
      run();
      layout();
      return {
        state: () => JSON.parse(JSON.stringify(st)),
        /** for tests and the diagram checker: change the setup and run again */
        set(patch) { const a = patch.algo && patch.algo !== st.algo ? CB.byId(patch.algo) : null; if (a) Object.assign(st, defaults(a), { round: null, block: 0 }); const was = st.mode; if (patch.mode && patch.mode !== was && [patch.mode, was].some((m) => m === 'gcm' || m === 'xts')) Object.assign(st, defaults(CB.byId(patch.algo || st.algo))); Object.assign(st, patch); if (!patch.area) st.area = 'run'; for (const c of document.querySelectorAll('#cbArea button')) { const on = c.dataset.v === (st.area || 'run'); c.classList.toggle('on', on); c.setAttribute('aria-checked', String(on)); } if (patch.mode === 'gcm' || patch.mode === 'xts') { modeDefaults(patch.mode); for (const k of ['key', 'iv', 'aad']) if (patch[k] !== undefined) st[k] = patch[k]; } if (patch.aval) st.aval = Object.assign({ target: 'plaintext', bit: 0 }, patch.aval); build(); run(); layout(); },
        get last() { return last; },
        redraw() { run(); },
        dispose() { if (labInst && labInst.stop) labInst.stop(); },
        lab(id) { st.area = 'labs'; st.lab = id; for (const c of document.querySelectorAll('#cbArea button')) { const on = c.dataset.v === 'labs'; c.classList.toggle('on', on); c.setAttribute('aria-checked', String(on)); } layout(); },
      };
    },
  });

  // ---- what the diagram checker looks at -------------------------------------------------------------------------------
  if (S.Checks) {
    const P = 'Sifer.app.page.bench', R = "document.querySelector('#cbView')";
    const add = (name, js) => S.Checks.push({ group: 'bench-cipher', name, hash: 'bench/cipher', ready: R, setup: js ? P + '.set(' + js + ');' : '', sel: '#main' });
    add('AES-128 rounds, CBC', "{algo: 'aes128', mode: 'cbc', dir: 'enc', view: 'rounds', toy: false}");
    add('AES-128 round 3 opened', "{algo: 'aes128', mode: 'cbc', dir: 'enc', view: 'rounds', round: 4}");
    add('CBC data flow', "{algo: 'aes128', mode: 'cbc', dir: 'enc', view: 'mode'}");
    add('CBC decryption flow', "{algo: 'aes128', mode: 'cbc', dir: 'enc', view: 'mode'}); " + P + ".set({dir: 'dec', text: {mode: 'hex', hex: Array.from(" + P + ".last.out, (v) => v.toString(16).padStart(2, '0')).join(''), text: ''}}");
    add('ECB, repeated blocks', "{algo: 'aes128', mode: 'ecb', dir: 'enc', view: 'mode', text: {mode: 'text', text: 'HOLD THE BRIDGE.HOLD THE BRIDGE.HOLD THE BRIDGE.', hex: ''}}");
    add('CFB flow', "{algo: 'aes128', mode: 'cfb', dir: 'enc', view: 'mode'}");
    add('OFB flow', "{algo: 'aes128', mode: 'ofb', dir: 'enc', view: 'mode'}");
    add('CTR flow, DES', "{algo: 'des', mode: 'ctr', dir: 'enc', view: 'mode'}");
    add('avalanche, AES-128', "{algo: 'aes128', mode: 'ecb', dir: 'enc', view: 'aval', aval: {target: 'plaintext', bit: 9}}");
    add('DES rounds and the f-function', "{algo: 'des', mode: 'ecb', dir: 'enc', view: 'rounds', round: 3}");
    add('PRESENT rounds', "{algo: 'present', mode: 'ecb', dir: 'enc', view: 'rounds', round: 2}");
    add('Mini-AES beside AES-128', "{algo: 'miniaes', mode: 'ecb', dir: 'enc', view: 'rounds', toy: true, round: 2}");
    add('ChaCha20 block function', "{algo: 'chacha20', dir: 'enc', view: 'rounds'}");
    add('ChaCha20 avalanche of a nonce bit', "{algo: 'chacha20', dir: 'enc', view: 'aval', aval: {target: 'iv', bit: 5}}");
    add('GCM: CTR plus the tag', "{algo: 'aes128', mode: 'gcm', dir: 'enc', view: 'mode'}");
    add('XTS with ciphertext stealing', "{algo: 'aes128', mode: 'xts', dir: 'enc', view: 'mode'}");
    add('CFB-8, byte by byte', "{algo: 'aes128', mode: 'cfb8', dir: 'enc', view: 'mode'}");
    add('CBC with ciphertext stealing', "{algo: 'aes128', mode: 'cts', dir: 'enc', view: 'mode'}");
    const lab = (name, id, run) => S.Checks.push({ group: 'bench-cipher', name: 'lab: ' + name, hash: 'bench/cipher', ready: "document.querySelector('#labBody')", setup: P + ".lab('" + id + "');" + (run ? " document.getElementById('labRun').click(); await new Promise((r) => { const t = setInterval(() => { if (" + run + ") { clearInterval(t); r(); } }, 50); });" : ''), sel: '#main' });
    lab('CBC padding, the defence', 'padding');
    lab('ECB, the defence', 'ecbcut');
    lab('CBC and CTR malleability, the defence', 'bitflip');
    lab('CTR nonces, the defence', 'ctrreuse');
    lab('GCM nonces, the defence', 'gcmreuse');
    lab('two-time pad', 'twotime');
    lab('meet in the middle', 'mitm', "document.getElementById('mitmOk')");
    lab('toy SPN broken', 'spn', "document.getElementById('spnOk')");
    lab('Geffe correlation', 'geffe', "document.getElementById('geffeOk')");
    lab('Berlekamp-Massey', 'bm');
    add('Trivium registers', "{algo: 'trivium', dir: 'enc', view: 'registers'}");
    add('Playfair', "{algo: 'playfair', dir: 'enc', view: 'result'}");
    add('keyword substitution', "{algo: 'substitution', dir: 'enc', view: 'result'}");
  }
})(globalThis.Sifer = globalThis.Sifer || {});
