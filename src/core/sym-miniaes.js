// Mini-AES: AES shrunk to a 16-bit block so a student can do it by hand. The state is four nibbles in a 2×2 matrix,
// column by column, [n0 n2 / n1 n3]. NibbleSub uses a 4-bit S-box, ShiftRow swaps the two nibbles of the bottom row,
// MixColumn multiplies each column by [[3, 2], [2, 3]] over GF(2^4) with x^4 + x + 1, and the key schedule makes
// two more 16-bit round keys from the key. Two rounds; the last has no MixColumn.
//   S.MiniAES.encrypt(p16, k16) / decrypt(c16, k16) -> {out, rounds, keys, trace}
//   S.MiniAES.keySchedule(k16) -> {w: [12 nibbles], keys: [K0, K1, K2], trace}
//   S.MiniAES.mul(a, b) GF(2^4); SBOX, INV_SBOX; nibbles(x) / join(n)
(function (S) {
  'use strict';
  const M = (S.MiniAES = {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  M.SBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7];
  M.INV_SBOX = new Array(16); M.SBOX.forEach((v, i) => { M.INV_SBOX[v] = i; });
  M.MIX = [[3, 2], [2, 3]];
  M.RCON = [1, 2];
  const n4 = (v) => v.toString(2).padStart(4, '0');
  const hx = (v) => v.toString(16);
  M.bin = n4;
  /** GF(2^4) product modulo x^4 + x + 1 */
  M.mul = (a, b) => { let r = 0; for (let i = 0; i < 4; i++) { if ((b >> i) & 1) r ^= a; a = (a << 1) & 0x1f; if (a & 0x10) a ^= 0x13; } return r; };
  M.nibbles = (x) => [(x >> 12) & 15, (x >> 8) & 15, (x >> 4) & 15, x & 15];
  M.join = (n) => (n[0] << 12) | (n[1] << 8) | (n[2] << 4) | n[3];
  M.hex = (x) => x.toString(16).padStart(4, '0');
  const st = (n) => `[${hx(n[0])} ${hx(n[2])} / ${hx(n[1])} ${hx(n[3])}]`;

  M.keySchedule = (key) => {
    const w = M.nibbles(key), trace = [step('key', `The key ${M.hex(key)} gives w0…w3 = ${w.map(hx).join(' ')}.`, { w: w.slice() })];
    for (let r = 1; r <= 2; r++) {
      const b = 4 * r, s = M.SBOX[w[b - 1]], rc = M.RCON[r - 1];
      w[b] = w[b - 4] ^ s ^ rc;
      trace.push(step('kword', `w${b} = w${b - 4} ⊕ NibbleSub(w${b - 1}) ⊕ rcon(${r}) = ${n4(w[b - 4])} ⊕ ${n4(s)} ⊕ ${n4(rc)} = ${n4(w[b])}.`, { i: b, w: w[b] }));
      for (let k = 1; k < 4; k++) {
        w[b + k] = w[b + k - 4] ^ w[b + k - 1];
        trace.push(step('kword', `w${b + k} = w${b + k - 4} ⊕ w${b + k - 1} = ${n4(w[b + k - 4])} ⊕ ${n4(w[b + k - 1])} = ${n4(w[b + k])}.`, { i: b + k, w: w[b + k] }));
      }
    }
    const keys = [0, 1, 2].map((r) => w.slice(4 * r, 4 * r + 4));
    trace.push(step('keys', `Round keys: K0 = ${M.hex(M.join(keys[0]))}, K1 = ${M.hex(M.join(keys[1]))}, K2 = ${M.hex(M.join(keys[2]))}.`, { keys }));
    return { w, keys, trace };
  };
  M.nibbleSub = (n, inv) => n.map((v) => (inv ? M.INV_SBOX : M.SBOX)[v]);
  M.shiftRow = (n) => [n[0], n[3], n[2], n[1]];
  M.mixColumn = (n) => {
    const out = [], parts = [];
    for (let c = 0; c < 2; c++) {
      const a = n[2 * c], b = n[2 * c + 1];
      const d0 = M.mul(3, a) ^ M.mul(2, b), d1 = M.mul(2, a) ^ M.mul(3, b);
      out.push(d0, d1);
      parts.push(`column ${c}: 3·${hx(a)} ⊕ 2·${hx(b)} = ${hx(M.mul(3, a))} ⊕ ${hx(M.mul(2, b))} = ${hx(d0)} and 2·${hx(a)} ⊕ 3·${hx(b)} = ${hx(M.mul(2, a))} ⊕ ${hx(M.mul(3, b))} = ${hx(d1)}`);
    }
    return { out, say: parts.join('; ') };
  };
  const add = (n, k) => n.map((v, i) => v ^ k[i]);

  M.encrypt = (p, key) => {
    const { keys } = M.keySchedule(key);
    let s = add(M.nibbles(p), keys[0]);
    const trace = [step('add-key', `Plaintext ${M.hex(p)} = ${st(M.nibbles(p))}; adding K0 = ${M.hex(M.join(keys[0]))} gives ${st(s)}.`, { state: s })], rounds = [];
    for (let r = 1; r <= 2; r++) {
      const sub = M.nibbleSub(s), sh = M.shiftRow(sub), mc = r === 1 ? M.mixColumn(sh) : null, end = add(mc ? mc.out : sh, keys[r]);
      rounds.push({ round: r, start: s, sub, shift: sh, mix: mc && mc.out, key: keys[r], end });
      trace.push(step('sub', `Round ${r}, NibbleSub: ${s.map((v, i) => `${hx(v)}→${hx(sub[i])}`).join(', ')}.`, { round: r, state: sub }));
      trace.push(step('shift', `ShiftRow swaps the bottom row: ${st(sub)} becomes ${st(sh)}.`, { round: r, state: sh }));
      if (mc) trace.push(step('mix', `MixColumn, ${mc.say}.`, { round: r, state: mc.out }));
      trace.push(step('add-key', `Adding K${r} = ${M.hex(M.join(keys[r]))} gives ${st(end)}.`, { round: r, state: end }));
      s = end;
    }
    const out = M.join(s);
    trace.push(step('out', `The ciphertext is ${M.hex(out)} (${M.nibbles(out).map(n4).join(' ')}).`, { out }));
    return { out, rounds, keys, trace };
  };
  /** MixColumn is its own inverse over GF(2^4): [[3,2],[2,3]]² = I */
  M.decrypt = (c, key) => {
    const { keys } = M.keySchedule(key);
    let s = add(M.nibbles(c), keys[2]);
    const trace = [step('add-key', `Ciphertext ${M.hex(c)}; adding K2 gives ${st(s)}.`, { state: s })];
    s = M.nibbleSub(M.shiftRow(s), true);
    trace.push(step('inv', `ShiftRow (its own inverse) and the inverse NibbleSub give ${st(s)}.`, { state: s }));
    s = add(s, keys[1]);
    trace.push(step('add-key', `Adding K1 gives ${st(s)}.`, { state: s }));
    const mc = M.mixColumn(s); s = mc.out;
    trace.push(step('mix', `MixColumn again undoes it, ${mc.say}.`, { state: s }));
    s = M.nibbleSub(M.shiftRow(s), true);
    trace.push(step('inv', `ShiftRow and the inverse NibbleSub give ${st(s)}.`, { state: s }));
    s = add(s, keys[0]);
    const out = M.join(s);
    trace.push(step('out', `Adding K0 recovers the plaintext ${M.hex(out)}.`, { out }));
    return { out, keys, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
