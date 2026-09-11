// Part 13, TLS 1.3: the handshake as a message-sequence chart (key shares in the hellos, the server's encrypted
// flight, the client's checks of the certificate chain, CertificateVerify and Finished, then application data), with
// a tampered certificate, Finished or record caught; and the key schedule as a tree of HKDF calls.
(function (S) {
  'use strict';
  const U = S.P12, Q = S.P13, Pr = () => S.Proto;
  const { t } = U;

  const shortCheck = (s) => {
    const x = s.say;
    if (/X25519/.test(x)) return 'same handshake secret';
    if (/chain|certificate rejected/.test(x)) return s.ok ? 'chain valid for the host' : 'certificate rejected';
    if (/CertificateVerify/.test(x)) return s.ok ? 'signature over the transcript' : 'bad signature';
    if (/server Finished/.test(x)) return s.ok ? 'server Finished matches' : 'Finished does not match';
    if (/client Finished/.test(x)) return 'client Finished matches';
    if (/record/.test(x)) return s.ok ? 'record opens' : 'record rejected';
    return s.ok ? 'checked' : 'failed';
  };
  function handshake(inp) {
    const res = Pr().tls13({ seed: +inp.seed, tamper: inp.tamper === 'none' ? undefined : inp.tamper });
    const frames = Q.mscFrames(res, {
      order: ['C', 'S', 'E'], labels: { C: 'Client', S: 'Server', E: 'Eavesdropper' }, check: shortCheck, note: ['the eavesdropper learned no key', 'the client aborts with an alert'],
      sub: 'one round trip; everything after ServerHello is encrypted', bad: () => false,
      term: (s) => { const v = s.values || {}; if (v.keyShare) return s.content + ': ' + U.cut(v.keyShare, 12); if (v.record) return s.content.replace(/\{(.*)\}handshake keys/, '{$1}') + ' · ' + U.cut(v.record, 14); return s.content; },
      hl: (s) => (s.type === 'message' ? [/Hello/.test(s.label) ? 0 : /Application/.test(s.label) ? 4 : /Finished/.test(s.label) ? 3 : 2] : [3]),
      chartY: 92, panelY: 470,
    });
    const last = frames[frames.length - 1];
    last.say = last.say.replace(/([^.!?])$/, '$1.') + ' ' + res.summary;
    Object.assign(last.facts, { summary: res.summary, ok: res.ok });
    return { frames, def: U.def('TLS 1.3, one round trip', ['ClientHello: random, suites, X25519 key share g^c', 'ServerHello: random, suite, key share g^s', '— both compute g^cs; the key schedule gives handshake keys —', '{EncryptedExtensions, Certificate, CertificateVerify, Finished}', 'client checks the chain, the signature over the transcript, Finished', 'client Finished; then application data under application keys']) };
  }
  S.topic({
    id: 'p13-tls', family: 'p13-tls', order: 10, title: 'The TLS 1.3 handshake',
    blurb: 'Key shares ride in the two hellos, so keys exist after one round trip. The server proves itself three ways: a certificate chain, a signature over the transcript, and a Finished MAC. Then the request flies under application keys. Tamper with any of it and the client aborts.',
    inputs: [
      { id: 'tamper', kind: 'choice', label: 'On the way', def: 'none', options: [{ value: 'none', label: 'nothing changes' }, { value: 'cert', label: 'a forged certificate' }, { value: 'finished', label: 'a corrupted server Finished' }, { value: 'record', label: 'a flipped bit in the request record' }] },
      { id: 'seed', kind: 'number', label: 'Seed', def: 1, min: 1, max: 99 },
    ],
    presets: [
      { label: 'A full handshake', values: { tamper: 'none', seed: 1 } },
      { label: 'A forged certificate', values: { tamper: 'cert', seed: 1 } },
      { label: 'A corrupted Finished', values: { tamper: 'finished', seed: 1 } },
      { label: 'A tampered record', values: { tamper: 'record', seed: 1 } },
    ],
    run: handshake,
    predict: [
      { at: (f) => f.meta && f.meta.step && f.meta.step.type === 'message' && f.meta.step.label === 'ServerHello', pick: 'option', options: ['after ClientHello', 'after ServerHello', 'after the client Finished'], ask: 'From which point on is everything encrypted?', answer: 'after ServerHello', explain: 'Both sides can compute the handshake keys as soon as they have each other\'s key share.' },
      { at: (f) => f.meta && f.meta.step && f.meta.step.type === 'message' && f.meta.step.label === 'Finished (server)', pick: 'option', options: ['accept', 'abort'], ask: 'The client now checks the chain, CertificateVerify and Finished. Will it go on?', answer: (fr) => (fr.some((f) => f.meta.step.type === 'check' && !f.meta.step.ok && f.meta.step.party === 'C') ? 'abort' : 'accept'), explain: (fr) => fr.find((f) => f.meta.step.type === 'check' && f.meta.step.party === 'C' && f.meta.i > 6) ? fr.find((f) => f.meta.step.type === 'check' && f.meta.step.party === 'C' && f.meta.i > 6).say : '' },
    ],
    quiz: [
      { q: 'How many round trips does a full TLS 1.3 handshake need before the client can send data?', options: ['one', 'two', 'three', 'none'], answer: 0, why: 'The key shares travel in the hellos.' },
      { q: 'What does CertificateVerify prove?', options: ['the certificate is valid', 'the server holds the certificate\'s private key and signed this handshake', 'the client is honest', 'the cipher suite'], answer: 1, why: 'A signature over the transcript hash, which includes both key shares.' },
      { q: 'What does the Finished message protect?', options: ['the application data', 'the whole handshake transcript, with an HMAC under a key from the handshake secret', 'the certificate only', 'nothing'], answer: 1, why: 'Any change to any earlier message changes the transcript hash.' },
      { q: 'An eavesdropper records the whole session and later steals the server\'s signing key. Can it decrypt the recording?', options: ['yes', 'no: the keys came from ephemeral X25519 secrets', 'only the first record', 'only with RSA key exchange'], answer: 1, why: 'Forward secrecy: the signing key only authenticated the exchange.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // the key schedule
  // ---------------------------------------------------------------------------------------------------------------
  const RFC8448 = { shared: '8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d', helloHash: '860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8', serverFinishedHash: '9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13', clientFinishedHash: '209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d' };
  function schedule(inp) {
    const T = Pr().tls, H = S.Hash;
    let sec, keys, shared, kl, src;
    if (inp.source === 'rfc') {
      const fh = U.fromHex, ks = T.keySchedule({ shared: fh(RFC8448.shared), helloHash: fh(RFC8448.helloHash), serverFinishedHash: fh(RFC8448.serverFinishedHash), clientFinishedHash: fh(RFC8448.clientFinishedHash) });
      kl = 16; sec = Object.fromEntries(Object.entries(ks.secrets).map(([k, v]) => [k, U.hex(v)])); shared = RFC8448.shared; src = 'the example handshake of RFC 8448 (AES-128-GCM keys)';
      keys = Object.fromEntries(['serverHs', 'clientHs', 'clientAp', 'serverAp'].map((k) => { const x = T.trafficKeys(ks.secrets[k], kl); return [k, { key: U.hex(x.key), iv: U.hex(x.iv) }]; }));
    } else {
      const r = Pr().tls13({ seed: +inp.seed });
      sec = r.schedule; keys = r.keys; shared = r.shared; kl = 32; src = 'our handshake, seed ' + inp.seed + ' (ChaCha20-Poly1305 keys)';
    }
    // the tree: a spine of extract steps down the left, traffic secrets branching to the right
    const nodes = [
      { id: 'zero', x: 60, y: 104, text: ['0 (no PSK)'], cls: 'soft', w: 104 },
      { id: 'early', x: 250, y: 104, text: ['early secret', sec.early.slice(0, 16) + '…'], cls: 'key', say: `Early secret = HKDF-Extract(0, 0) = ${U.spaced(sec.early)}: with no pre-shared key, a fixed starting point.`, f: { early: sec.early } },
      { id: 'd1', x: 250, y: 178, text: ['derived', sec.derivedEarly.slice(0, 16) + '…'], cls: '', say: `Derive-Secret(early, "derived", hash of nothing) = ${U.spaced(sec.derivedEarly)}: the salt for the next extract.`, f: { d: sec.derivedEarly } },
      { id: 'dh', x: 60, y: 252, text: ['X25519', shared.slice(0, 8) + '…'], cls: 'act', w: 104 },
      { id: 'hs', x: 250, y: 252, text: ['handshake secret', sec.handshake.slice(0, 16) + '…'], cls: 'key', say: `Handshake secret = HKDF-Extract(derived, the X25519 shared secret ${U.short(shared, 4)}) = ${U.spaced(sec.handshake)}. Here the ephemeral Diffie–Hellman enters.`, f: { hs: sec.handshake, shared } },
      { id: 'chs', x: 530, y: 220, text: ['c hs traffic', sec.clientHs.slice(0, 16) + '…'], cls: '', say: `Client handshake traffic secret = Derive-Secret(handshake, "c hs traffic", H(ClientHello ‖ ServerHello)) = ${U.spaced(sec.clientHs)}.`, f: { c: sec.clientHs } },
      { id: 'shs', x: 530, y: 284, text: ['s hs traffic', sec.serverHs.slice(0, 16) + '…'], cls: '', say: `Server handshake traffic secret, with the label "s hs traffic": ${U.spaced(sec.serverHs)}. Different labels, unrelated secrets.`, f: { s: sec.serverHs } },
      { id: 'khs', x: 790, y: 252, text: ['keys and IVs', 'for the handshake'], cls: 'hot', w: 180, say: `Each traffic secret expands into a key and an IV: server ${keys.serverHs.key.slice(0, 16)}… with IV ${keys.serverHs.iv}; client ${keys.clientHs.key.slice(0, 16)}… with IV ${keys.clientHs.iv}. They protect EncryptedExtensions through Finished.`, f: { k1: keys.serverHs, k2: keys.clientHs } },
      { id: 'd2', x: 250, y: 340, text: ['derived', sec.derivedHs.slice(0, 16) + '…'], cls: '', say: `Derive-Secret(handshake, "derived", hash of nothing) = ${U.spaced(sec.derivedHs)}.`, f: { d: sec.derivedHs } },
      { id: 'zero2', x: 60, y: 414, text: ['0'], cls: 'soft', w: 104 },
      { id: 'ms', x: 250, y: 414, text: ['master secret', sec.master.slice(0, 16) + '…'], cls: 'key', say: `Master secret = HKDF-Extract(derived, 0) = ${U.spaced(sec.master)}.`, f: { ms: sec.master } },
      { id: 'cap', x: 530, y: 386, text: ['c ap traffic', sec.clientAp.slice(0, 16) + '…'], cls: '', say: `Client application traffic secret = Derive-Secret(master, "c ap traffic", the transcript hash through the server Finished) = ${U.spaced(sec.clientAp)}.`, f: { c: sec.clientAp } },
      { id: 'sap', x: 530, y: 446, text: ['s ap traffic', sec.serverAp.slice(0, 16) + '…'], cls: '', say: `Server application traffic secret = ${U.spaced(sec.serverAp)}.`, f: { s: sec.serverAp } },
      { id: 'kap', x: 790, y: 416, text: ['keys and IVs', 'for application data'], cls: 'hot', w: 180, say: `Application keys: client ${keys.clientAp.key.slice(0, 16)}… with IV ${keys.clientAp.iv}, server ${keys.serverAp.key.slice(0, 16)}… with IV ${keys.serverAp.iv}. Each record's nonce is the IV XORed with its sequence number.`, f: { k1: keys.clientAp, k2: keys.serverAp } },
      { id: 'exp', x: 530, y: 506, text: ['exporter', sec.exporter.slice(0, 16) + '…'], cls: '', say: `Exporter master secret = ${U.spaced(sec.exporter)}: for protocols that need keys bound to this session.`, f: { e: sec.exporter } },
      { id: 'res', x: 530, y: 566, text: ['resumption', sec.resumption.slice(0, 16) + '…'], cls: '', say: `Resumption master secret = ${U.spaced(sec.resumption)}, computed through the client Finished: the pre-shared key for a later session.`, f: { r: sec.resumption } },
    ];
    for (const n of nodes) { if (n.x === 250) n.x = 270; else if (n.x === 530) n.x = 556; else if (n.x === 790) n.x = 806; else if (n.x === 60) { n.x = 54; n.w = 92; } }
    const order = ['early', 'd1', 'hs', 'chs', 'shs', 'khs', 'd2', 'ms', 'cap', 'sap', 'kap', 'exp', 'res'];
    const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
    const shown = (k) => new Set(['zero', 'dh', 'zero2', ...order.slice(0, k + 1)]);
    const W = (n) => (n.w || 200) / 2;
    const draw = (k) => {
      const on = shown(k), cur = order[k], items = [];
      for (const n of nodes) {
        if (!on.has(n.id)) continue;
        items.push({ key: 'ks:' + n.id, kind: 'state', x: n.x, y: n.y, w: n.w || 200, h: 44, rx: 6, lines: n.text, cls: 'block val2 ' + (n.id === cur ? 'hot' : n.cls) });
      }
      const wire = (key, pts, lit, head) => items.push({ key, kind: 'wire', pts: pts.map((p) => [U.r2(p[0]), U.r2(p[1])]), head: head !== false, cls: lit ? 'act' : '' });
      // the spine, and the inputs from the left
      for (const [a, b] of [['early', 'd1'], ['d1', 'hs'], ['hs', 'd2'], ['d2', 'ms']]) if (on.has(a) && on.has(b)) wire('ke:' + a + b, [[byId[a].x, byId[a].y + 22], [byId[b].x, byId[b].y - 22]], b === cur);
      for (const [a, b] of [['zero', 'early'], ['dh', 'hs'], ['zero2', 'ms']]) if (on.has(b)) { const A = byId[a], B = byId[b]; wire('ke:' + a + b, [[A.x + W(A), A.y], [B.x - W(B), B.y]], b === cur); items.push(t('kl:' + a, (A.x + W(A) + B.x - W(B)) / 2, A.y - 9, 'Extract', 'ptick', 'middle', 13)); }
      // a parent fanning out to its children through one vertical bus
      const fan = (pre, parent, kids) => {
        const vis = kids.filter((c) => on.has(c));
        if (!on.has(parent) || !vis.length) return;
        const P = byId[parent], mx = (P.x + W(P) + byId[kids[0]].x - W(byId[kids[0]])) / 2, ys = vis.map((c) => byId[c].y).concat(P.y);
        const lit = vis.includes(cur);
        wire(pre + ':t', [[P.x + W(P), P.y], [mx, P.y]], lit, false);
        if (Math.max(...ys) > Math.min(...ys)) wire(pre + ':b', [[mx, Math.min(...ys)], [mx, Math.max(...ys)]], lit, false);
        items.push({ key: pre + ':d', kind: 'dot', x: U.r2(mx), y: P.y, r: 3.6, cls: lit ? 'act' : '' });
        for (const c of vis) wire(pre + ':' + c, [[mx, byId[c].y], [byId[c].x - W(byId[c]), byId[c].y]], c === cur);
      };
      // children merging into one box
      const merge = (pre, kids, to) => {
        if (!on.has(to)) return;
        const T = byId[to], mx = (byId[kids[0]].x + W(byId[kids[0]]) + T.x - W(T)) / 2, ys = kids.map((c) => byId[c].y);
        const lit = to === cur;
        for (const c of kids) wire(pre + ':' + c, [[byId[c].x + W(byId[c]), byId[c].y], [mx, byId[c].y]], lit, false);
        wire(pre + ':b', [[mx, Math.min(...ys)], [mx, Math.max(...ys)]], lit, false);
        wire(pre + ':o', [[mx, T.y], [T.x - W(T), T.y]], lit);
      };
      fan('fh', 'hs', ['chs', 'shs']); fan('fm', 'ms', ['cap', 'sap', 'exp', 'res']);
      merge('mh', ['chs', 'shs'], 'khs'); merge('ma', ['cap', 'sap'], 'kap');
      return items;
    };
    const head = U.head('ks:h', 'The TLS 1.3 key schedule', src);
    const F = new S.Frames(['secrets']);
    order.forEach((id, k) => {
      F.count('secrets');
      const n = byId[id];
      F.add({ items: [...head, ...draw(k)], hl: { d: [Math.min(6, Math.floor(k / 2))] }, say: n.say, facts: n.f, meta: { stage: id } });
    });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Key schedule (RFC 8446, section 7.1)', ['HKDF-Expand-Label(secret, label, context, L) with "tls13 " + label', 'Derive-Secret(s, label, msgs) = Expand-Label(s, label, H(msgs), 32)', 'early = Extract(0, PSK or 0)', 'handshake = Extract(Derive-Secret(early, "derived", ""), (EC)DHE)', 'master = Extract(Derive-Secret(handshake, "derived", ""), 0)', 'traffic secrets: Derive-Secret with the transcript so far', 'key = Expand-Label(secret, "key", "", L); iv = Expand-Label(secret, "iv", "", 13)']) };
  }
  S.topic({
    id: 'p13-tls-keys', family: 'p13-tls', order: 20, title: 'The TLS 1.3 key schedule, as a tree',
    blurb: 'Three HKDF-Extract steps down a spine (nothing, the Diffie–Hellman secret, nothing again), and from each stage traffic secrets branching off, bound to the transcript so far, each expanded into a key and an IV.',
    inputs: [{ id: 'source', kind: 'choice', label: 'Inputs', def: 'ours', options: [{ value: 'ours', label: 'our own handshake' }, { value: 'rfc', label: 'the RFC 8448 example' }] }, { id: 'seed', kind: 'number', label: 'Seed', def: 1, min: 1, max: 99 }],
    presets: [{ label: 'Our handshake', values: { source: 'ours', seed: 1 } }, { label: 'RFC 8448, section 3', values: { source: 'rfc' } }],
    counters: [{ id: 'secrets', label: 'secrets derived' }],
    run: schedule,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'd1', pick: 'option', options: ['the PSK', 'the X25519 shared secret', 'the server\'s certificate'], ask: 'What goes into the next HKDF-Extract along with this salt?', answer: 'the X25519 shared secret', explain: 'The handshake secret is where the ephemeral Diffie–Hellman enters.' }],
    quiz: [
      { q: 'Why do client and server traffic secrets differ?', options: ['different keys from the start', 'different labels: "c hs traffic" and "s hs traffic"', 'random choice', 'they do not'], answer: 1, why: 'Same secret, same transcript, different label: unrelated outputs.' },
      { q: 'What binds the application keys to this exact handshake?', options: ['the time', 'the transcript hash through the server Finished, used as context', 'the IP address', 'nothing'], answer: 1, why: 'Derive-Secret hashes the messages so far into the derivation.' },
      { q: 'What is the resumption master secret for?', options: ['logging', 'a pre-shared key for a later, faster handshake', 'the certificate', 'the exporter'], answer: 1, why: 'It seeds the early secret next time.' },
      { q: 'How is a record\'s nonce made?', options: ['random', 'the traffic IV XORed with the record\'s sequence number', 'the key', 'a counter alone'], answer: 1, why: 'Unique per record without sending it.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
