// Enigma I: rotors I–V, reflectors UKW-A, B and C, ring settings, a plugboard of 0–13 cables, and stepping by pawls
// and notches (so the double step falls out of the mechanism rather than being a special rule). Each key press
// returns the full signal path with the contact positions a picture needs.
//   S.Enigma.ROTORS, REFLECTORS, ABC
//   S.Enigma.machine({order, reflector, rings, window, plugs}) -> m
//     order: ['II','IV','V'] left to right; reflector 'B' (or 'UKW-B'); rings 'AAA' or [1..26]; window 'ABC';
//     plugs 'AV BS CG' (0–13 pairs)
//   m.press(ch)        -> {in, out, stepping, path, trace}   one key press: step first, then the current flows
//   m.step()           -> {pawls, steps, before, after, trace}
//   m.stepBack()       -> the window(s) one key press earlier (usually one)
//   m.encrypt(text)    -> {out, presses}          letters only; decrypting is the same operation
//   m.run(text)        -> the output string only (fast)
//   m.window, m.setWindow(w), m.config(), m.clone(), m.permutation() -> the current substitution (no stepping)
//   S.Enigma.parsePlugs(str, max), S.Enigma.groups(text)
(function (S) {
  'use strict';
  const E = (S.Enigma = S.Enigma || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const ABC = (E.ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  const md = (n) => ((n % 26) + 26) % 26;
  const I = (c) => c.charCodeAt(0) - 65;

  // the standard Enigma I wirings (entry contact A..Z to exit letter) and the window letter at which each rotor
  // carries its neighbour on the next key press
  E.ROTORS = {
    I: { wiring: 'EKMFLGDQVZNTOWYHXUSPAIBRCJ', notch: 'Q' },
    II: { wiring: 'AJDKSIRUXBLHWTMCQGZNPYFVOE', notch: 'E' },
    III: { wiring: 'BDFHJLCPRTXVZNYEIWGAKMUSQO', notch: 'V' },
    IV: { wiring: 'ESOVPZJAYQUIRHXLNFTGKDCMWB', notch: 'J' },
    V: { wiring: 'VZBRGITYUPSDNHLXAWMJQOFECK', notch: 'Z' },
  };
  E.REFLECTORS = { A: 'EJMZALYXVBWFCRQUONTSPIKHGD', B: 'YRUHQSLDPXNGOKMIEBFZCWVJAT', C: 'FVPJIAOYEDRZXWGCTKUQSBNMHL' };
  E.ROTOR_IDS = ['I', 'II', 'III', 'IV', 'V'];
  const tables = {};
  E.wheel = (id) => {
    if (tables[id]) return tables[id];
    const w = E.ROTORS[id] ? E.ROTORS[id].wiring : E.REFLECTORS[id];
    if (!w) throw new Error('unknown rotor ' + id);
    const fwd = new Int8Array(26), bwd = new Int8Array(26);
    for (let i = 0; i < 26; i++) { fwd[i] = I(w[i]); bwd[I(w[i])] = i; }
    return (tables[id] = { id, wiring: w, fwd, bwd, notch: E.ROTORS[id] ? I(E.ROTORS[id].notch) : -1 });
  };
  E.reflectorId = (r) => { const k = String(r || 'B').toUpperCase().replace(/^UKW-?/, ''); if (!E.REFLECTORS[k]) throw new Error('unknown reflector ' + r); return k; };

  /** "AB CD" or [['A','B'], ...] to pairs; each letter in at most one cable, at most max cables */
  E.parsePlugs = (input, max = 13) => {
    let pairs;
    if (Array.isArray(input)) pairs = input.map((p) => (typeof p === 'string' ? [p[0], p[1]] : [p[0], p[1]]).map((c) => String(c).toUpperCase()));
    else { const s = String(input || '').toUpperCase().replace(/[^A-Z]/g, ''); if (s.length % 2) throw new Error('the plugboard needs letters in pairs'); pairs = []; for (let i = 0; i < s.length; i += 2) pairs.push([s[i], s[i + 1]]); }
    const used = new Set();
    for (const [a, b] of pairs) {
      if (a === b) throw new Error(`a cable cannot join ${a} to itself`);
      for (const c of [a, b]) { if (!/^[A-Z]$/.test(c)) throw new Error('bad plug ' + c); if (used.has(c)) throw new Error(`${c} is plugged twice`); used.add(c); }
    }
    if (pairs.length > max) throw new Error(`at most ${max} cables`);
    return pairs;
  };
  E.plugMap = (pairs) => { const m = Int8Array.from({ length: 26 }, (_, i) => i); for (const [a, b] of pairs) { m[I(a)] = I(b); m[I(b)] = I(a); } return m; };
  const parseRings = (r) => {
    if (r == null) return [0, 0, 0];
    let a = r;
    if (typeof r === 'string') a = /\d/.test(r) ? r.trim().split(/[^0-9]+/).map(Number) : Array.from(r.toUpperCase().replace(/[^A-Z]/g, ''));
    if (a.length !== 3) throw new Error('three ring settings are needed');
    // letters A–Z, or the numbers 1–26 printed on key sheets
    return a.map((x) => (typeof x === 'number' ? md(x - 1) : I(String(x).toUpperCase())));
  };
  E.groups = (t, n = 5) => (String(t).toUpperCase().replace(/[^A-Z]/g, '').match(new RegExp('.{1,' + n + '}', 'g')) || []).join(' ');

  E.machine = (cfg = {}) => {
    const order = (cfg.order || ['I', 'II', 'III']).map(String);
    if (order.length !== 3) throw new Error('Enigma I takes three rotors');
    if (new Set(order).size !== 3) throw new Error('each rotor can be used only once');
    order.forEach((id) => { if (!E.ROTORS[id]) throw new Error('Enigma I has rotors I to V, not ' + id); });
    const refl = E.reflectorId(cfg.reflector), W = order.map(E.wheel), R = E.wheel(refl);
    const rings = parseRings(cfg.rings), plugs = E.parsePlugs(cfg.plugs || '', 13), pb = E.plugMap(plugs);
    const pos = [0, 0, 0];
    const m = {
      order, reflector: refl, rings, plugs,
      get window() { return pos.map((p) => ABC[p]).join(''); },
      get positions() { return pos.slice(); },
      setWindow(w) { const s = String(w).toUpperCase(); if (!/^[A-Z]{3}$/.test(s)) throw new Error('the window shows three letters'); for (let i = 0; i < 3; i++) pos[i] = I(s[i]); return m; },
      config() { return { order: order.slice(), reflector: refl, rings: rings.map((r) => ABC[r]).join(''), window: m.window, plugs: plugs.map((p) => p.join('')).join(' ') }; },
      clone() { return E.machine(m.config()); },
      /** the pawls: the right pawl always pushes; the middle pawl drops in when the right rotor shows its notch; the
       *  left pawl drops in when the middle rotor shows its notch, and then pushes both the left rotor's ratchet and
       *  the middle rotor's notch, which is the double step */
      step() {
        const before = m.window, atR = pos[2] === W[2].notch, atM = pos[1] === W[1].notch;
        const pawls = [atM, atR, true], steps = [atM, atR || atM, true];
        for (let i = 0; i < 3; i++) if (steps[i]) pos[i] = md(pos[i] + 1);
        const after = m.window, trace = [];
        const name = ['left', 'middle', 'right'];
        trace.push(step('pawls', `Key down: the right pawl pushes the right rotor${atR ? `; the right rotor shows its notch ${ABC[W[2].notch]}, so the middle pawl drops in` : ''}${atM ? `; the middle rotor shows its notch ${ABC[W[1].notch]}, so the left pawl drops in and pushes the left rotor and the middle rotor together (the double step)` : ''}.`, { pawls, steps, before, after }));
        trace.push(step('window', `The window moves from ${before} to ${after}${steps.filter(Boolean).length > 1 ? ` (${steps.map((s, i) => (s ? name[i] : null)).filter(Boolean).join(', ')} rotors moved)` : ''}.`, { before, after }));
        return { pawls, steps, before, after, trace };
      },
      /** the window one key press earlier; more than one only in the rare double-step corner */
      stepBack() {
        const all = E.previous(pos, W[1].notch, W[2].notch), live = all.filter((q) => E.previous(q, W[1].notch, W[2].notch).length);
        const cands = live.concat(all.filter((q) => !live.includes(q))).map((p) => p.map((v) => ABC[v]).join(''));
        if (cands.length) m.setWindow(cands[0]);
        return cands;
      },
      /** the substitution at the current positions, without stepping (index → index) */
      permutation() { const out = new Int8Array(26); for (let c = 0; c < 26; c++) out[c] = through(c).out; return out; },
      press(ch) {
        const c = I(String(ch).toUpperCase());
        if (!(c >= 0 && c < 26)) throw new Error('Enigma has only the letters A to Z');
        const st = m.step(), r = through(c, true);
        const trace = st.trace.concat(r.trace);
        trace.push(step('lamp', `Key ${ABC[c]} lights lamp ${ABC[r.out]}.`, { in: ABC[c], out: ABC[r.out] }));
        return { in: ABC[c], out: ABC[r.out], stepping: st, path: r.path, window: m.window, trace };
      },
      encrypt(text) { const presses = []; let out = ''; for (const ch of String(text).toUpperCase()) if (ch >= 'A' && ch <= 'Z') { const p = m.press(ch); presses.push(p); out += p.out; } return { out, presses }; },
      run(text) {
        let out = '';
        for (const ch of String(text).toUpperCase()) if (ch >= 'A' && ch <= 'Z') {
          const atR = pos[2] === W[2].notch, atM = pos[1] === W[1].notch;
          if (atM) { pos[0] = md(pos[0] + 1); pos[1] = md(pos[1] + 1); } else if (atR) pos[1] = md(pos[1] + 1);
          pos[2] = md(pos[2] + 1);
          out += ABC[through(I(ch)).out];
        }
        return out;
      },
    };
    /** the current through the machine; with full, the path with every contact for drawing */
    function through(c, full) {
      const path = full ? [] : null, trace = full ? [] : null;
      let x = pb[c];
      if (full) { path.push({ part: 'plugboard', dir: 'in', from: c, to: x }); trace.push(step('plug', x === c ? `${ABC[c]} has no cable, so it goes straight to the entry wheel.` : `The cable ${ABC[c]}–${ABC[x]} sends ${ABC[c]} on as ${ABC[x]}.`, { from: ABC[c], to: ABC[x] })); path.push({ part: 'ETW', dir: 'in', from: x, to: x }); }
      const pass = (k, dir) => {
        const off = md(pos[k] - rings[k]), pinIn = md(x + off), pinOut = dir === 'fwd' ? W[k].fwd[pinIn] : W[k].bwd[pinIn], y = md(pinOut - off);
        if (full) {
          const nm = ['left (L)', 'middle (M)', 'right (R)'][k];
          path.push({ part: ['L', 'M', 'R'][k], rotor: order[k], dir, from: x, to: y, pinIn, pinOut, offset: off, window: ABC[pos[k]], ring: ABC[rings[k]] });
          trace.push(step('rotor', `${dir === 'fwd' ? 'In' : 'Back'} through the ${nm} rotor ${order[k]} (window ${ABC[pos[k]]}, ring ${ABC[rings[k]]}, so the core is turned ${off}): contact ${ABC[x]} meets core pin ${ABC[pinIn]}, wired to ${ABC[pinOut]}, which leaves at contact ${ABC[y]}.`, { k, rotor: order[k], dir, from: ABC[x], pinIn: ABC[pinIn], pinOut: ABC[pinOut], to: ABC[y], offset: off }));
        }
        x = y;
      };
      pass(2, 'fwd'); pass(1, 'fwd'); pass(0, 'fwd');
      const y = R.fwd[x];
      if (full) { path.push({ part: 'UKW', reflector: refl, from: x, to: y }); trace.push(step('reflector', `The reflector UKW-${refl} turns ${ABC[x]} back as ${ABC[y]}.`, { from: ABC[x], to: ABC[y] })); }
      x = y;
      pass(0, 'bwd'); pass(1, 'bwd'); pass(2, 'bwd');
      const out = pb[x];
      if (full) { path.push({ part: 'ETW', dir: 'out', from: x, to: x }); path.push({ part: 'plugboard', dir: 'out', from: x, to: out }); trace.push(step('plug', out === x ? `${ABC[x]} has no cable, so lamp ${ABC[x]} lights.` : `The cable ${ABC[x]}–${ABC[out]} sends it to lamp ${ABC[out]}.`, { from: ABC[x], to: ABC[out] })); }
      return { out, path, trace };
    }
    if (cfg.window) m.setWindow(cfg.window);
    return m;
  };
  /** one key press of the lever drive on positions [l, m, r], given the notch positions of the middle and right rotors */
  E.advance = (p, notchM, notchR) => {
    const atM = p[1] === notchM, atR = p[2] === notchR;
    return [atM ? md(p[0] + 1) : p[0], atM || atR ? md(p[1] + 1) : p[1], md(p[2] + 1)];
  };
  /** every position that one key press carries to p */
  E.previous = (p, notchM, notchR) => {
    const out = [];
    for (let dm = 0; dm <= 1; dm++) for (let dl = 0; dl <= 1; dl++) {
      const q = [md(p[0] - dl), md(p[1] - dm), md(p[2] - 1)], n = E.advance(q, notchM, notchR);
      if (n[0] === p[0] && n[1] === p[1] && n[2] === p[2]) out.push(q);
    }
    return out;
  };
  /** the windows k presses before p: candidates whose own history dies out at once (unreachable positions such
   *  as a middle rotor one past its notch without the double step) are dropped unless the walk ends there */
  E.walkBack = (p, k, notchM, notchR, limit = 4) => {
    let front = [p];
    for (let s = 0; s < k; s++) {
      const next = [];
      for (const q of front) for (const r of E.previous(q, notchM, notchR)) {
        const last = s === k - 1;
        if ((last || E.previous(r, notchM, notchR).length) && !next.some((x) => x[0] === r[0] && x[1] === r[1] && x[2] === r[2])) next.push(r);
      }
      front = next.slice(0, limit);
      if (!front.length) break;
    }
    return front;
  };
  /** shorthand: encrypt (= decrypt) a text with a configuration */
  E.encrypt = (cfg, text) => E.machine(cfg).run(text);
  /** a seeded generator and a string hash for reproducible keys and sheets */
  E.rng = (seed = 1) => {
    const { imul } = Math; let s = (typeof seed === 'string' ? E.hash(seed) : seed) >>> 0;
    return () => { s = (s + 0x6D2B79F5) >>> 0; let t = imul(s ^ (s >>> 15), 1 | s); t ^= t + imul(t ^ (t >>> 7), 61 | t); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  };
  E.hash = (str) => { let h = 2166136261 >>> 0; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; } return h; };
  /** a random daily key: order, reflector, rings, window and n plug pairs */
  E.randomKey = (rand, opts = {}) => {
    const ids = E.ROTOR_IDS.slice(), order = [];
    while (order.length < 3) order.push(ids.splice(Math.floor(rand() * ids.length), 1)[0]);
    const letters = ABC.split(''); for (let i = 25; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [letters[i], letters[j]] = [letters[j], letters[i]]; }
    const n = opts.pairs == null ? 10 : opts.pairs, plugs = [];
    for (let i = 0; i < n; i++) plugs.push(letters[2 * i] + letters[2 * i + 1]);
    const rl = () => ABC[Math.floor(rand() * 26)];
    return { order, reflector: opts.reflector || 'B', rings: opts.rings || rl() + rl() + rl(), window: rl() + rl() + rl(), plugs: plugs.join(' ') };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
