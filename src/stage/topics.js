// Parts, families and topics. A part is one of the fifteen parts of the course; a family is a group of topics on
// one idea (Vigenère, the AES round, Euclid, ECDSA); a topic is one picture with its own inputs and presets, a scene
// for every step with narration that names the actual values, predictions to make on the way and a quiz at the end.
(function (S) {
  'use strict';

  /** The fifteen parts, in teaching order (the home page lists the same) */
  S.parts = [
    { id: 'classical', n: 1, title: 'Classical ciphers and cryptanalysis', blurb: 'Shift, affine and substitution ciphers, frequency analysis, Vigenère broken in three moves, transposition, Playfair and the Enigma wing.' },
    { id: 'numbers', n: 2, title: 'Modular arithmetic and number theory', blurb: 'Clocks and rings, Euclid as a table, Euler and Fermat, the Chinese remainder theorem, groups, and the fields GF(p) and GF(2^8).' },
    { id: 'stream', n: 3, title: 'Stream ciphers', blurb: 'The one-time pad and the two-time pad, LFSRs and Berlekamp–Massey, Trivium, Salsa20 and ChaCha20.' },
    { id: 'des', n: 4, title: 'DES and the Feistel network', blurb: 'The Feistel ladder, DES round by round, the key schedule, meet-in-the-middle, 3DES, a toy SPN broken by differences, PRESENT.' },
    { id: 'aes', n: 5, title: 'AES', blurb: 'The 4×4 state through SubBytes, ShiftRows, MixColumns and AddRoundKey, the key expansion, avalanche, and Mini-AES by hand.' },
    { id: 'modes', n: 6, title: 'Modes of operation', blurb: 'ECB, CBC, CFB, OFB, CTR, XTS and GCM as data flowing on wires, and the rules for using them safely: integrity, unique nonces, checking the tag first.' },
    { id: 'pubkey', n: 7, title: 'Public-key cryptography', blurb: 'Why asymmetric, trapdoor one-way functions, key distribution and security levels compared.' },
    { id: 'rsa', n: 8, title: 'RSA', blurb: 'Key generation with Miller–Rabin, square-and-multiply, the CRT, OAEP, and the classic attacks as labs.' },
    { id: 'dlp', n: 9, title: 'The discrete logarithm problem', blurb: 'Diffie–Hellman, Elgamal, baby-step giant-step, Pollard\'s rho, Pohlig–Hellman and small subgroups.' },
    { id: 'ecc', n: 10, title: 'Elliptic curves', blurb: 'Chord and tangent over the reals, point clouds over GF(p), double-and-add, the Montgomery ladder, ECDH and curve choice.' },
    { id: 'signatures', n: 11, title: 'Digital signatures', blurb: 'RSA, PSS, Elgamal, DSA, ECDSA, Schnorr and Ed25519; forgeries, and nonce reuse that gives away the key.' },
    { id: 'hash', n: 12, title: 'Hash functions', blurb: 'The birthday paradox, Merkle–Damgård, SHA-256 round by round, the Keccak sponge, length extension.' },
    { id: 'protocols', n: 13, title: 'MACs, key establishment and protocols', blurb: 'HMAC, CBC-MAC, CMAC, Poly1305, AEAD, HKDF, Kerberos, certificates, a man in the middle, and TLS 1.3.' },
    { id: 'pq', n: 14, title: 'Post-quantum cryptography', blurb: 'Shor and Grover as intuition, lattices and LWE, ML-KEM and ML-DSA, hash-based signatures and McEliece.' },
    { id: 'side', n: 15, title: 'Side channels and implementation', blurb: 'Power traces, simple and correlation power analysis, timing and caches, faults, and failures of randomness.' },
  ];
  S.partOf = (id) => S.parts.find((p) => p.id === id) || null;
  S.families = [];
  S.topics = [];

  const partRank = (id) => { const i = S.parts.findIndex((p) => p.id === id); return i < 0 ? 99 : i; };
  /** family: {id, part, title, blurb, order} */
  S.family = function (f) {
    if (S.families.some((x) => x.id === f.id)) return S.families.find((x) => x.id === f.id);
    S.families.push(f);
    S.families.sort((a, b) => partRank(a.part) - partRank(b.part) || (a.order || 0) - (b.order || 0));
    return f;
  };
  /**
   * topic: {id, family, title, blurb, order,
   *   inputs: [{id, kind: 'string'|'expr'|'choice'|'number'|'list'|'text'|'program', label, def,
   *             options: [{value, label}] (choice), min, max (number; length for string and list),
   *             alphabet (string: allowed symbols), check(v, input) -> error sentence or null}],
   *   presets: [{label, values}],
   *   run(input) -> [frame] or {frames, def, counters},
   *   counters: [{id, label}], predict: [...], quiz: [{q, options, answer, why}], camera: 'fit-all'|'follow'}
   * A frame is {items: [stage items], say: 'narration', hl: [ids lit in the definition panel],
   *   counters: {id: n}, predict: {ask, options, answer, explain, pick: 'option'|'item'}, mark, slow, view}.
   */
  S.topic = function (t) {
    if (S.topics.some((x) => x.id === t.id)) throw new Error('two topics with id ' + t.id);
    S.topics.push(t);
    const order = (x) => (x.order === undefined ? 500 : x.order);
    const n = S.topics.map((x, k) => [x, k]);
    const fr = (x) => { const f = S.families.find((y) => y.id === x.family); return f ? partRank(f.part) * 1000 + (f.order || 0) : 99999; };
    n.sort((a, b) => fr(a[0]) - fr(b[0]) || order(a[0]) - order(b[0]) || a[1] - b[1]);
    S.topics.length = 0;
    for (const [x] of n) S.topics.push(x);
    return t;
  };
  S.byId = (id) => S.topics.find((t) => t.id === id) || null;
  // A link to another topic inside narration or a definition: [[topic-id]] (shows its title) or [[topic-id|words]].
  S.TOPIC_LINK = /\[\[([a-z0-9][a-z0-9-]*)(?:\|([^\]]+))?\]\]/g;
  /** split text at its topic links: strings and {id, text} pieces; the text is the words given, else the title */
  S.topicLinks = function (text) {
    const out = [], re = new RegExp(S.TOPIC_LINK.source, 'g');
    let last = 0, m;
    text = String(text === undefined || text === null ? '' : text);
    while ((m = re.exec(text))) {
      if (m.index > last) out.push(text.slice(last, m.index));
      const t = S.byId(m[1]);
      out.push({ id: m[1], text: m[2] || (t ? '“' + t.title + '”' : m[1]), missing: !t });
      last = m.index + m[0].length;
    }
    if (last < text.length) out.push(text.slice(last));
    return out;
  };
  /** the same text with each topic link as plain words */
  S.plainLinks = (text) => S.topicLinks(text).map((x) => (typeof x === 'string' ? x : x.text)).join('');
  S.familyOf = (t) => S.families.find((f) => f.id === t.family) || null;
  S.topicPart = (t) => { const f = S.familyOf(t); return f ? S.partOf(f.part) : null; };

  /** The value of each input: the one given, or its default */
  S.inputOf = function (t, given) {
    const o = {};
    for (const i of t.inputs || []) o[i.id] = given && given[i.id] !== undefined ? given[i.id] : (typeof i.def === 'function' ? i.def() : i.def);
    return o;
  };
  /** Read a field's text into a value of the input's kind */
  S.parseInput = function (inp, text) {
    switch (inp.kind) {
      case 'number': return text === '' ? NaN : Number(text);
      case 'hex': return String(text).replace(/\s+/g, '').toLowerCase();
      case 'bigint': return String(text).trim();
      case 'list': return String(text).split(/[\s,]+/).filter(Boolean).map((x) => (x === 'ε' || x === 'eps' ? '' : x));
      case 'string': return String(text).replace(/\s+/g, '') === 'ε' ? '' : String(text).replace(/\s+/g, inp.spaces ? ' ' : '');
      default: return String(text);
    }
  };
  S.showInput = function (inp, v) {
    if (inp.kind === 'list') return (v || []).map((x) => (x === '' ? 'ε' : x)).join(', ');
    return v === undefined || v === null ? '' : String(v);
  };
  /** Check an input against the topic's limits: an error message, or null */
  S.checkInput = function (t, input) {
    for (const i of t.inputs || []) {
      const v = input[i.id];
      const L = i.label || i.id;
      if (i.kind === 'number') {
        if (!Number.isFinite(v) || (i.integer !== false && !Number.isInteger(v))) return L + ': a whole number';
        if (i.min !== undefined && v < i.min) return L + ': at least ' + i.min;
        if (i.max !== undefined && v > i.max) return L + ': at most ' + i.max;
      }
      if (i.kind === 'string') {
        if (typeof v !== 'string') return L + ': a string';
        if (i.alphabet) { const bad = [...v].find((c) => !i.alphabet.includes(c)); if (bad !== undefined) return L + ': "' + bad + '" is not in the alphabet {' + [...i.alphabet].join(', ') + '}'; }
        if (i.max !== undefined && [...v].length > i.max) return L + ': at most ' + i.max + ' symbols, so the picture stays readable';
        if (i.min !== undefined && [...v].length < i.min) return L + ': at least ' + i.min + ' symbols';
      }
      if (i.kind === 'list') {
        if (!Array.isArray(v)) return L + ': a list';
        if (i.max !== undefined && v.length > i.max) return L + ': at most ' + i.max + ' items';
        if (i.min !== undefined && v.length < i.min) return L + ': at least ' + i.min + ' item' + (i.min === 1 ? '' : 's');
      }
      if (i.kind === 'choice' && i.options && !i.options.some((o) => o.value === v)) return L + ': choose one of the options';
      if (i.kind === 'hex') {
        const t = String(v || '').replace(/\s+/g, '');
        if (!/^[0-9a-fA-F]*$/.test(t)) return L + ': hex digits only (0-9, a-f)';
        if (t.length % 2) return L + ': an even number of hex digits (whole bytes)';
        if (i.bytes !== undefined && t.length / 2 !== i.bytes) return L + ': exactly ' + i.bytes + ' bytes (' + 2 * i.bytes + ' hex digits)';
        if (i.max !== undefined && t.length / 2 > i.max) return L + ': at most ' + i.max + ' bytes, so the picture stays readable';
      }
      if (i.kind === 'bigint') { if (!/^\s*-?\d+\s*$/.test(String(v))) return L + ': a whole number'; }
      if (i.check) { let e; try { e = i.check(v, input); } catch (x) { e = x.message; } if (e) return e; }
    }
    if (t.check) return t.check(input);
    return null;
  };

  /** A helper for building a topic's frames: keeps the running counters and stamps them on each frame */
  class Frames {
    constructor(counters) { this.list = []; this.counts = {}; for (const c of counters || []) this.counts[typeof c === 'string' ? c : c.id] = 0; }
    count(id, n) { this.counts[id] = (this.counts[id] || 0) + (n === undefined ? 1 : n); return this; }
    set(id, n) { this.counts[id] = n; return this; }
    add(frame) { frame.counters = Object.assign({}, this.counts, frame.counters || {}); this.list.push(frame); return frame; }
    get length() { return this.list.length; }
    last() { return this.list[this.list.length - 1]; }
  }
  S.Frames = Frames;

  /** Run a topic with an input: frames (each drawable on the stage), the definition panel and the counters */
  S.run = function (t, input) {
    let out;
    try { out = t.run(input); } catch (e) { return { ok: false, error: e.message || String(e), frames: [{ items: [], say: 'This could not be run: ' + (e.message || e) }], stack: e.stack }; }
    if (Array.isArray(out)) out = { frames: out };
    out = out || { frames: [] };
    const frames = (out.frames || []).filter(Boolean);
    for (const f of frames) { if (!f.items) f.items = []; if (f.items.some((x) => !x)) f.items = f.items.filter(Boolean); }
    // one camera for the whole run, so nothing jumps: the box around every frame (a frame may set its own)
    if (t.camera !== 'follow') {
      let box = null;
      for (const f of frames) { const b = S.stageBounds(f.items, t.cameraOpts); if (b) box = box ? S.geom.union([box, b]) : b; }
      if (box) for (const f of frames) if (!f.view) f.view = box;
    }
    // predictions declared on the topic: find the frames they ask at
    // a prediction that cannot be worked out is reported (a topic checker fails on it), not dropped quietly
    const predictErrors = [];
    for (const p of t.predict || []) {
      for (let i = 0; i < frames.length - 1; i++) {
        if (frames[i].predict) continue;
        let hit = false;
        try { hit = p.at(frames[i], i, frames, input); } catch (e) { hit = false; predictErrors.push('prediction ' + (t.predict.indexOf(p) + 1) + ': at() fails at frame ' + i + ': ' + (e.message || e)); }
        if (!hit) continue;
        let q = null;
        try {
          q = { ask: typeof p.ask === 'function' ? p.ask(frames, i, input) : p.ask, answer: typeof p.answer === 'function' ? p.answer(frames, i, input) : p.answer, options: p.options ? (typeof p.options === 'function' ? p.options(frames, i, input) : p.options) : null, explain: p.explain ? (typeof p.explain === 'function' ? p.explain(frames, i, input) : p.explain) : null, pick: p.pick || (p.options ? 'option' : 'item') };
        } catch (e) { q = null; predictErrors.push('prediction ' + (t.predict.indexOf(p) + 1) + ' at frame ' + i + ': ' + (e.message || e)); }
        if (!q || q.answer === null || q.answer === undefined) continue;
        frames[i].predict = q;
        if (p.once) break;
      }
    }
    return { ok: true, frames, def: out.def || (t.def ? t.def(input) : null), counters: out.counters || t.counters || [], result: out.result, predictErrors };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
