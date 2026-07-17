// The protocol engine: messages built from symbolic terms (names, keys, nonces, encryptions, signatures), sent
// between parties who each keep what they know. A party learns the parts of every message it receives, and opens
// an encryption only when it holds the key, so the knowledge state after each step is computed, not asserted. An
// eavesdropper sees every message. Each encryption is also made real (ChaCha20-Poly1305 under a key derived from
// the key's name and the run's seed), so a picture can show the bytes on the wire.
//   S.Proto.atom(name[, kind, {from}]) / enc(key, ...parts) / sig(signer, ...parts) / str(term)
//   S.Proto.run({title, parties: [{id, label, knows: [...], role}], seed}) -> run
//     run.send(from, to, parts, {label, note, as, via, intended, values})   as: the claimed sender; intended: the
//       recipient the sender meant (when an attacker intercepts); via: an attacker who also sees it; values: real bytes
//     run.check(party, ok, say) / run.note(say) / run.learn(party, ...terms) / run.knows(party, term)
//     run.result() -> {title, parties, messages: [{i, from, to, as, label, content, terms, wire, knows, keys, learned}],
//                      steps (messages, checks and notes in order), trace, ok}
//   S.Proto.x25519(k32, u32) -> 32 bytes (RFC 7748; S.ECC.X25519's when loaded, else x25519Own);  S.Proto.x25519Base(k32)
//   S.Proto.GROUPS.toy64 = {p, q, g}   a 64-bit safe-prime group for readable Diffie–Hellman
//   S.Proto.signer(name[, {seed, bits}]) -> {name, pub, sign(bytes) -> bytes, verify(pub, bytes, sig) -> bool, kind}
(function (S) {
  'use strict';
  const Pr = (S.Proto = S.Proto || {});
  const H = S.Hash, { step, hex, utf8, concat } = H;

  // ---- terms
  Pr.atom = (name, kind = 'data', opt = {}) => Object.assign({ t: 'atom', name, kind }, opt);
  Pr.enc = (key, ...body) => ({ t: 'enc', key, body });
  Pr.sig = (signer, ...body) => ({ t: 'sig', signer, body });
  const name = (x) => (typeof x === 'string' ? x : x.name);
  const norm = (x) => (typeof x === 'string' ? Pr.atom(x) : x);
  Pr.str = (x) => {
    x = norm(x);
    if (x.t === 'atom') return x.name;
    if (x.t === 'enc') return `{${x.body.map(Pr.str).join(', ')}}${name(x.key)}`;
    return `sig_${name(x.signer)}(${x.body.map(Pr.str).join(', ')})`;
  };
  const isKey = (a) => a.kind === 'key' || /^K/.test(a.name);

  // ---- a run of a protocol
  Pr.run = (opt) => {
    const seed = opt.seed === undefined ? 1 : opt.seed;
    const parties = opt.parties.map((p) => ({ id: p.id, label: p.label || p.id, role: p.role || 'honest' }));
    const K = {}; // id -> {atoms: Map name -> atom, opaque: [terms it holds but cannot open]}
    const messages = [], steps = [], trace = [];
    let ok = true;
    for (const p of opt.parties) K[p.id] = { atoms: new Map(), opaque: [], held: [] };
    const has = (id, n) => K[id].atoms.has(n);
    const keyMaterial = (n) => H.get('sha256').hash(utf8(`proto-key:${seed}:${n}`));
    const absorb = (id, term, out) => {
      term = norm(term);
      const k = K[id];
      if (term.t === 'atom') { if (!k.atoms.has(term.name)) { k.atoms.set(term.name, term); out.push(term.name); } return; }
      if (term.t === 'sig') { if (!k.held.some((o) => Pr.str(o) === Pr.str(term))) k.held.push(term); term.body.forEach((b) => absorb(id, b, out)); return; }
      if (has(id, name(term.key))) term.body.forEach((b) => absorb(id, b, out));
      else if (!k.opaque.some((o) => Pr.str(o) === Pr.str(term))) { k.opaque.push(term); out.push(Pr.str(term) + ' (sealed)'); }
    };
    const reopen = (id, out) => { // newly learned keys may open sealed terms held from before
      for (let again = true; again;) {
        again = false;
        for (const o of K[id].opaque.slice()) if (has(id, name(o.key))) { K[id].opaque = K[id].opaque.filter((x) => x !== o); o.body.forEach((b) => absorb(id, b, out)); again = true; }
      }
    };
    const learn = (id, ...terms) => { const out = []; terms.forEach((t) => absorb(id, t, out)); reopen(id, out); return out; };
    /** can `id` produce this term: it knows every atom (or it can be derived), or it holds the sealed term itself */
    const canMake = (id, term) => {
      term = norm(term);
      if (term.t === 'atom') return has(id, term.name) || (!!term.from && has(id, term.from));
      if (K[id].opaque.some((o) => Pr.str(o) === Pr.str(term))) return true;
      if (term.t === 'sig') return K[id].held.some((o) => Pr.str(o) === Pr.str(term)) || (name(term.signer) === id && term.body.every((b) => canMake(id, b)));
      return has(id, name(term.key)) && term.body.every((b) => canMake(id, b));
    };
    const seal = (term) => { // real bytes for a sealed term
      const kb = keyMaterial(name(term.key)), pt = utf8(Pr.str(term.body.length === 1 ? term.body[0] : { t: 'atom', name: term.body.map(Pr.str).join(', ') }));
      const nonce = H.get('sha256').hash(utf8(`nonce:${seed}:${messages.length}:${Pr.str(term)}`)).slice(0, 12);
      const r = S.MAC.aead.seal(kb, nonce, pt);
      return hex(concat(nonce, r.ciphertext, r.tag));
    };
    const wire = (terms) => terms.map(norm).map((t) => ({ term: Pr.str(t), sealed: t.t === 'enc', bytes: t.t === 'enc' ? seal(t) : hex(utf8(Pr.str(t))) }));
    const snapshot = () => {
      const knows = {}, keys = {};
      for (const p of parties) { knows[p.id] = [...K[p.id].atoms.keys()]; keys[p.id] = [...K[p.id].atoms.values()].filter(isKey).map((a) => a.name); }
      return { knows, keys };
    };
    for (const p of opt.parties) learn(p.id, ...(p.knows || []));
    const R = {
      parties, seed, knowledge: K,
      learn: (id, ...terms) => { const got = learn(id, ...terms); return got; },
      knows: (id, term) => canMake(id, term),
      send(from, to, parts, o = {}) {
        parts = parts.map(norm);
        const missing = parts.filter((p) => !canMake(from, p)).map(Pr.str);
        if (missing.length) throw new Error(`${from} cannot produce ${missing.join(', ')}`);
        const learned = {};
        learned[to] = learn(to, ...parts);
        // an attacker on the wire, and any passive eavesdropper, see the message too
        for (const p of parties) if (p.id !== to && p.id !== from && (p.role === 'eavesdropper' || p.id === o.via)) learned[p.id] = learn(p.id, ...parts);
        const snap = snapshot();
        const m = { i: messages.length + 1, from, to, as: o.as || from, via: o.via || null, intended: o.intended || to, values: o.values || null, label: o.label || '', note: o.note || '', content: parts.map(Pr.str).join(', '), terms: parts, wire: wire(parts), learned, ...snap };
        messages.push(m); steps.push(Object.assign({ type: 'message' }, m));
        const shown = o.as && o.as !== from ? `${from} (posing as ${o.as})` : from;
        trace.push(step('message', `${m.i}. ${shown} → ${to}: ${m.content}.${m.note ? ' ' + m.note + (/[.!?]$/.test(m.note) ? '' : '.') : ''}${learned[to].length ? ` ${to} learns ${learned[to].join(', ')}.` : ''}`, { i: m.i, from, to, as: m.as }));
        return m;
      },
      check(id, pass, say) {
        const s = { type: 'check', party: id, ok: !!pass, say, ...snapshot() };
        steps.push(s); trace.push(step(pass ? 'check-ok' : 'check-fail', `${id} checks: ${say}`, { party: id, ok: !!pass }));
        if (!pass) ok = false;
        return !!pass;
      },
      note(say, data) { steps.push(Object.assign({ type: 'note', say }, snapshot(), data || {})); trace.push(step('note', say, data || {})); },
      result: () => ({ title: opt.title, parties, messages, steps, trace, ok, final: snapshot() }),
    };
    return R;
  };

  // ---- X25519 (RFC 7748)
  const P25519 = (1n << 255n) - 19n;
  const md = (a) => ((a % P25519) + P25519) % P25519;
  const powm = (b, e) => { let r = 1n; b = md(b); while (e) { if (e & 1n) r = (r * b) % P25519; b = (b * b) % P25519; e >>= 1n; } return r; };
  const leInt = (b) => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };
  const leBytes = (v) => { const o = new Uint8Array(32); for (let i = 0; i < 32; i++) { o[i] = Number(v & 255n); v >>= 8n; } return o; };
  Pr.x25519 = (k, u) => {
    const X = S.ECC && S.ECC.X25519;
    if (X && X.x25519) { const r = X.x25519(k, u); return r.out || r; }
    return Pr.x25519Own(k, u);
  };
  /** the ladder, self-contained, for when the curve engine is not loaded */
  Pr.x25519Own = (k, u) => {
    const kc = Uint8Array.from(k); kc[0] &= 248; kc[31] &= 127; kc[31] |= 64;
    const sc = leInt(kc), ub = Uint8Array.from(u); ub[31] &= 127;
    const x1 = leInt(ub);
    let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0n;
    for (let t = 254; t >= 0; t--) {
      const kt = (sc >> BigInt(t)) & 1n;
      if (swap ^ kt) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
      swap = kt;
      const A = md(x2 + z2), AA = md(A * A), B = md(x2 - z2), BB = md(B * B), E = md(AA - BB);
      const C = md(x3 + z3), D = md(x3 - z3), DA = md(D * A), CB = md(C * B);
      x3 = md((DA + CB) ** 2n); z3 = md(x1 * md((DA - CB) ** 2n)); x2 = md(AA * BB); z2 = md(E * md(AA + 121665n * E));
    }
    if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    return leBytes(md(x2 * powm(z2, P25519 - 2n)));
  };
  Pr.X25519_BASE = (() => { const b = new Uint8Array(32); b[0] = 9; return b; })();
  Pr.x25519Base = (k) => Pr.x25519(k, Pr.X25519_BASE);

  // ---- a small group for Diffie–Hellman with numbers a student can read: p = 2q + 1 safe, g = 4 of order q
  Pr.GROUPS = { toy64: { name: 'toy64', p: 0xfffffffffffffa43n, q: (0xfffffffffffffa43n - 1n) / 2n, g: 4n } };
  Pr.modpow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };

  // ---- long-term signing keys: RSA-PSS when S.RSA is loaded, otherwise a labelled stand-in
  const cache = {};
  Pr.signer = (nm, o = {}) => {
    const seed = o.seed === undefined ? 1 : o.seed, bits = o.bits || 1024, id = `${nm}:${seed}:${bits}`;
    if (cache[id]) return cache[id];
    let s;
    if (S.RSA && S.RSA.keygen && S.RSA.pssSign && S.NT) {
      const old = S.NT.setRandom(S.NT.seededRandom([...id].reduce((h, c) => Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0, 2166136261)));
      let key;
      try { key = S.RSA.keygen(bits); } finally { S.NT.setRandom(old); }
      const pub = S.RSA.public(key);
      s = {
        name: nm, kind: `RSA-${bits} PSS`, pub, fingerprint: hex(H.get('sha256').hash(utf8(pub.n.toString(16)))).slice(0, 16),
        sign: (m) => S.RSA.pssSign(key, utf8(m)).sBytes,
        verify: (p, m, sg) => { try { return S.RSA.pssVerify(p, utf8(m), sg).ok; } catch (e) { return false; } },
      };
    } else {
      const secret = H.get('sha256').hash(utf8('stand-in signing key ' + id)), pub = { stub: hex(secret).slice(0, 16), owner: nm };
      Pr.stubRegistry = Pr.stubRegistry || {};
      Pr.stubRegistry[pub.stub] = secret;
      s = {
        name: nm, kind: 'stand-in (HMAC; load the RSA engine for real signatures)', pub, fingerprint: pub.stub,
        sign: (m) => S.MAC.hmac('sha256', secret, m),
        verify: (p, m, sg) => !!Pr.stubRegistry[p.stub] && S.MAC.equal(S.MAC.hmac('sha256', Pr.stubRegistry[p.stub], m), sg),
      };
    }
    cache[id] = s;
    return s;
  };
  Pr.samePub = (a, b) => (a.n !== undefined ? a.n === b.n && a.e === b.e : a.stub === b.stub);
})(globalThis.Sifer = globalThis.Sifer || {});
