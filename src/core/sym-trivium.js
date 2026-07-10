// Trivium: three shift registers of 93, 84 and 111 bits (288 in all), each fed by a nonlinear AND of two cells of its
// own register and a linear tap from another. Key and IV go into the first two registers, the last three cells of
// the third are set to 1, and 4 × 288 = 1152 warm-up clocks pass before any output. Each clock gives one bit.
// Bits of the key, the IV and the keystream are taken least significant bit of each byte first, and s1 holds the
// last key bit (s94 the last IV bit), as the reference code of the eSTREAM submission does, so its published vectors
// apply directly.
//   S.Trivium.create(key10, iv10) -> {clock() -> bit, state() -> 288 bits (s1 first), keystream(nBytes) -> Uint8Array}
//   S.Trivium.trace(key10, iv10, nClocks) -> {trace}  the first output clocks, each with t1, t2, t3 and the AND terms
//   S.Trivium.encrypt(key10, iv10, data) -> Uint8Array
(function (S) {
  'use strict';
  const Tr = (S.Trivium = {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const bitsOf = (bytes, n) => Array.from({ length: n }, (_, i) => (bytes[i >> 3] >> (i & 7)) & 1);
  Tr.create = (key, iv) => {
    if (key.length !== 10 || iv.length !== 10) throw new Error('Trivium takes an 80-bit key and an 80-bit IV');
    // each register is a circular buffer: shifting moves its head back one cell instead of moving every bit
    const A = new Uint8Array(93), B = new Uint8Array(84), C = new Uint8Array(111);
    let a = 0, b = 0, c = 0; // the position of s1, s94, s178 in each register
    // bit j of the key (j = 0 the least significant bit of byte 0) is K(80 − j): s1 is the last key bit
    bitsOf(key, 80).forEach((v, j) => { A[79 - j] = v; });
    bitsOf(iv, 80).forEach((v, j) => { B[79 - j] = v; });
    C[108] = C[109] = C[110] = 1;
    const sa = (i) => A[(a + i - 1) % 93], sb = (i) => B[(b + i - 94) % 84], sc = (i) => C[(c + i - 178) % 111];
    const s = (i) => (i <= 93 ? sa(i) : i <= 177 ? sb(i) : sc(i));
    const self = { last: null };
    self.clock = () => {
      let t1 = sa(66) ^ sa(93), t2 = sb(162) ^ sb(177), t3 = sc(243) ^ sc(288);
      const z = t1 ^ t2 ^ t3;
      const and1 = sa(91) & sa(92), and2 = sb(175) & sb(176), and3 = sc(286) & sc(287);
      self.last = { z, t1, t2, t3, and1, and2, and3, in1: s(171), in2: s(264), in3: s(69) };
      t1 ^= and1 ^ s(171); t2 ^= and2 ^ s(264); t3 ^= and3 ^ s(69);
      // shift each register one place: the new first cell takes the feedback, the last cell falls off
      a = (a + 92) % 93; A[a] = t3;
      b = (b + 83) % 84; B[b] = t1;
      c = (c + 110) % 111; C[c] = t2;
      Object.assign(self.last, { f1: t3, f2: t1, f3: t2 });
      return z;
    };
    self.state = () => Array.from({ length: 288 }, (_, i) => s(i + 1));
    for (let i = 0; i < 1152; i++) self.clock();
    self.keystream = (n) => { const o = new Uint8Array(n); for (let i = 0; i < 8 * n; i++) o[i >> 3] |= self.clock() << (i & 7); return o; };
    return self;
  };
  Tr.encrypt = (key, iv, data) => { const ks = Tr.create(key, iv).keystream(data.length); return data.map((v, i) => v ^ ks[i]); };
  Tr.trace = (key, iv, n = 16) => {
    const g = Tr.create(key, iv), trace = [step('tri-init', `The key fills s1…s80, the IV fills s94…s173, s286…s288 are 1, and 1152 warm-up clocks mix them before any output.`, { state: g.state() })];
    for (let i = 0; i < n; i++) {
      const z = g.clock(), L = g.last;
      trace.push(step('tri-clock', `Clock ${i}: t1 = s66 ⊕ s93 = ${L.t1}, t2 = s162 ⊕ s177 = ${L.t2}, t3 = s243 ⊕ s288 = ${L.t3}; output z = ${z}. Feedback: s1 ← t3 ⊕ s286·s287 ⊕ s69 = ${L.f1}, s94 ← t1 ⊕ s91·s92 ⊕ s171 = ${L.f2}, s178 ← t2 ⊕ s175·s176 ⊕ s264 = ${L.f3}.`, Object.assign({ i, state: g.state() }, L)));
    }
    return { trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
