// The Feistel principle with any round function, and the properties of DES that follow from its structure.
//   S.Feistel.run({L, R, keys, F, bits, decrypt}) -> {L, R, rounds: [{i, L, R, k, f, newR}], trace}
//       halves are integers of `bits` bits (up to 32); F(R, k, i) returns an integer; decrypt runs the keys backwards.
//       The output is (R_n, L_n), swapped after the last round, so decryption is the same ladder with keys reversed.
//   S.Feistel.ROUND_FUNCTIONS: a few round functions to try, from a constant (insecure) to a small S-box network
//   S.Feistel.encrypt(x, opts) / decrypt(x, opts): a 2·bits-bit integer in and out
//   S.DES.decrypt(block, key) -> the traced ladder run with the round keys reversed
//   S.DES.WEAK, S.DES.SEMI_WEAK, S.DES.keyClass(key) -> {weak, semiWeak, partner, subkeys, trace}
//   S.DES.weakDemo(block, key) -> {once, twice, trace}      for a weak key, encrypting twice gives the plaintext back
//   S.DES.complementation(block, key) -> {c, cc, holds, trace}   DES(~p, ~k) = ~DES(p, k)
(function (S) {
  'use strict';
  const F = (S.Feistel = {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const hx = (v, bits) => (v >>> 0).toString(16).padStart(Math.ceil(bits / 4), '0');

  F.run = ({ L, R, keys, F: f, bits = 16, decrypt = false }) => {
    const mask = bits >= 32 ? 0xffffffff : (1 << bits) - 1, n = keys.length;
    L = (L & mask) >>> 0; R = (R & mask) >>> 0;
    const rounds = [], trace = [step('split', `Split the block into L0 = ${hx(L, bits)} and R0 = ${hx(R, bits)}.`, { L, R })];
    for (let i = 0; i < n; i++) {
      const k = keys[decrypt ? n - 1 - i : i], fv = (f(R, k, i) & mask) >>> 0, newR = (L ^ fv) >>> 0;
      rounds.push({ i: i + 1, L, R, k, f: fv, newR });
      trace.push(step('round', `Round ${i + 1}: L${i + 1} = R${i} = ${hx(R, bits)}; R${i + 1} = L${i} ⊕ F(R${i}, k) = ${hx(L, bits)} ⊕ ${hx(fv, bits)} = ${hx(newR, bits)}${decrypt ? ` (key ${n - i} of ${n})` : ''}.`, { i: i + 1, L: R, R: newR, k, f: fv }));
      L = R; R = newR;
    }
    trace.push(step('swap', `Swap the halves at the end: the output is ${hx(R, bits)} ${hx(L, bits)}.`, { L: R, R: L }));
    return { L: R, R: L, rounds, trace };
  };
  const join = (r, bits) => (BigInt(r.L) << BigInt(bits)) | BigInt(r.R);
  F.encrypt = (x, opts) => {
    const b = opts.bits || 16, v = BigInt(x), m = (1n << BigInt(b)) - 1n;
    const r = F.run(Object.assign({}, opts, { L: Number((v >> BigInt(b)) & m), R: Number(v & m) }));
    return Object.assign(r, { out: join(r, b) });
  };
  F.decrypt = (x, opts) => F.encrypt(x, Object.assign({}, opts, { decrypt: !opts.decrypt }));
  const sb4 = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2];
  F.ROUND_FUNCTIONS = {
    zero: { name: 'F = 0 (each round just swaps)', F: () => 0 },
    xorKey: { name: 'F(R, k) = R ⊕ k (linear: easily broken)', F: (R, k) => R ^ k },
    addRot: { name: 'F(R, k) = (R + k) rotated left by 3', F: (R, k) => { const v = (R + k) & 0xffff; return ((v << 3) | (v >>> 13)) & 0xffff; } },
    sbox: {
      name: 'F(R, k) = S-boxes on R ⊕ k, then a rotation',
      F: (R, k) => { let x = (R ^ k) & 0xffff, y = 0; for (let i = 0; i < 4; i++) y |= sb4[(x >> (4 * i)) & 15] << (4 * i); return ((y << 5) | (y >>> 11)) & 0xffff; },
    },
  };

  // ---- DES: decryption, weak keys, complementation
  const D = (S.DES = S.DES || {});
  const bx = (a) => S.bytes.hex(a);
  D.decrypt = (block, key) => D.encrypt(block, key, { decrypt: true });
  D.WEAK = ['0101010101010101', 'fefefefefefefefe', 'e0e0e0e0f1f1f1f1', '1f1f1f1f0e0e0e0e'];
  D.SEMI_WEAK = [['011f011f010e010e', '1f011f010e010e01'], ['01e001e001f101f1', 'e001e001f101f101'], ['01fe01fe01fe01fe', 'fe01fe01fe01fe01'],
    ['1fe01fe00ef10ef1', 'e01fe01ff10ef10e'], ['1ffe1ffe0efe0efe', 'fe1ffe1ffe0efe0e'], ['e0fee0fef1fef1fe', 'fee0fee0fef1fef1']];
  /** parity bits (the last bit of each byte) do not enter the key schedule */
  const norm = (h) => h.replace(/[^0-9a-f]/gi, '').toLowerCase().replace(/../g, (b) => (parseInt(b, 16) & 0xfe).toString(16).padStart(2, '0'));
  D.keyClass = (key) => {
    const k = norm(bx(key)), subkeys = D.keySchedule(key).keys.map((x) => D.hex(x.K));
    const distinct = new Set(subkeys).size;
    const weak = D.WEAK.some((w) => norm(w) === k);
    let partner = null;
    for (const [a, b] of D.SEMI_WEAK) { if (norm(a) === k) partner = b; if (norm(b) === k) partner = a; }
    const trace = [step('subkeys', `The sixteen round keys take ${distinct} distinct value${distinct === 1 ? '' : 's'}: ${[...new Set(subkeys)].join(', ')}.`, { subkeys })];
    if (weak) trace.push(step('weak', `All round keys are equal, so the keys in reverse order are the same keys: decryption equals encryption, and encrypting twice returns the plaintext.`, {}));
    else if (partner) trace.push(step('semi-weak', `The round keys alternate between two values, so the key ${partner} produces them in reverse order: encrypting with one key and then the other returns the plaintext.`, { partner }));
    else trace.push(step('ordinary', `The round keys differ, so this is an ordinary key.`, {}));
    return { weak, semiWeak: !!partner, partner, subkeys, trace };
  };
  D.weakDemo = (block, key, key2) => {
    const k2 = key2 || key, c1 = D.cipher(key).encrypt(block), c2 = D.cipher(k2).encrypt(c1);
    return { once: c1, twice: c2, back: S.bytes.eq(c2, block), trace: [
      step('enc', `Encrypt ${bx(block)} with ${bx(key)}: ${bx(c1)}.`, { out: c1 }),
      step('enc', `Encrypt that again with ${bx(k2)}: ${bx(c2)}${S.bytes.eq(c2, block) ? ', which is the plaintext again' : ''}.`, { out: c2 }),
    ] };
  };
  D.complementation = (block, key) => {
    const not = (a) => a.map((v) => ~v & 255), c = D.cipher(key).encrypt(block), cc = D.cipher(not(key)).encrypt(not(block));
    const holds = S.bytes.eq(cc, not(c));
    return { c, cc, holds, trace: [
      step('enc', `DES(${bx(block)}, ${bx(key)}) = ${bx(c)}.`, { out: c }),
      step('enc', `DES(${bx(not(block))}, ${bx(not(key))}) with both complemented = ${bx(cc)}.`, { out: cc }),
      step('compare', `The complement of the first ciphertext is ${bx(not(c))}: ${holds ? 'the same' : 'different'}. E sees R complemented and the round key complemented, so their XOR is unchanged, and every S-box gets the same input; an exhaustive search needs to try only half the keys.`, { holds }),
    ] };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
