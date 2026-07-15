// MACs from a block cipher (AES-128): CBC-MAC and the forgery that breaks it on messages of varying length, CMAC
// with its two subkeys, and GMAC (GCM with no plaintext, the tag over the associated data alone).
//   S.MAC.cbcMac(key, msg[, {trace}]) -> tag | {tag, chain, trace}       msg a whole number of 16-byte blocks
//   S.MAC.cbcMacForge({key, m1, m2}) -> {forged, tag, ok, trace}           from tags of m1 and m2, a tag for a third
//   S.MAC.cmacSubkeys(key) -> {L, K1, K2, trace};  S.MAC.cmac(key, msg[, {trace}]) -> tag | {tag, chain, trace}
//   S.MAC.gmac(key, iv12, aad[, {trace}]) -> tag | {tag, H, J0, S, trace}
(function (S) {
  'use strict';
  const H = S.Hash, Mc = (S.MAC = S.MAC || {});
  const { step, hex, utf8, concat } = H;
  const E = (b, k) => S.AES.encrypt(b, k).out;
  const xor = (a, b) => a.map((v, i) => v ^ b[i]);
  const blocks = (m) => { const out = []; for (let i = 0; i < m.length; i += 16) out.push(m.slice(i, i + 16)); return out; };

  Mc.cbcMac = (key, msg, opt = {}) => {
    msg = utf8(msg);
    if (msg.length % 16 || !msg.length) throw new Error('CBC-MAC here takes whole 16-byte blocks');
    let c = new Uint8Array(16);
    const chain = [], trace = [];
    blocks(msg).forEach((m, i) => {
      const x = xor(m, c), y = E(x, key);
      chain.push({ i, m, prev: c, x, c: y });
      if (opt.trace) trace.push(step('block', `Block ${i + 1}: ${hex(m)} ⊕ ${i ? 'C' + i : '0'} = ${hex(x)}; E_K gives C${i + 1} = ${hex(y)}.`, { i, m, prev: c, x, c: y }));
      c = y;
    });
    if (!opt.trace) return c;
    trace.push(step('tag', `The tag is the last block, ${hex(c)}: the IV is fixed at zero and only one block is output.`, { tag: c }));
    return { tag: c, chain, trace };
  };
  /** Given tags t1 = MAC(m1) and t2 = MAC(m2), m1 ‖ (m2's first block ⊕ t1) ‖ the rest of m2 has tag t2. */
  // With mac: 'cmac' the same splice is tried against CMAC, where it fails.
  Mc.cbcMacForge = ({ key, m1, m2, mac }) => {
    m1 = utf8(m1); m2 = utf8(m2);
    const tagger = mac === 'cmac' ? Mc.cmac : Mc.cbcMac;
    const t1 = tagger(key, m1), t2 = tagger(key, m2);
    const first = xor(m2.slice(0, 16), t1), forged = concat(m1, first, m2.slice(16));
    const real = tagger(key, forged, { trace: true });
    const ok = H.eq(real.tag, t2);
    const trace = [
      step('query', `The attacker asks for two tags: MAC(m1) = ${hex(t1)} and MAC(m2) = ${hex(t2)}.`, { t1, t2 }),
      step('splice', `Forged message: m1 ‖ (first block of m2 ⊕ ${hex(t1)}) ‖ the rest of m2, ${forged.length / 16} blocks the key holder never tagged.`, { forged, first }),
      step('why', `After m1 the chaining value is t1; XORing the spliced block with it cancels t1, so the chain continues exactly as it did for m2 from zero, and ends at t2.`, {}),
      ...(mac === 'cmac' ? [] : real.trace.slice(m1.length / 16, m1.length / 16 + 1)),
      step(ok ? 'accept' : 'reject', ok ? `The key holder computes MAC(forged) = ${hex(real.tag)} = t2: the forgery is valid.`
        : `The key holder computes MAC(forged) = ${hex(real.tag)}, not t2: under CMAC, t1 is not the chaining value after m1 (its last block was masked with a subkey), so the splice does not cancel and the forgery fails.`, { ok }),
    ];
    return { forged, tag: t2, ok, t1, t2, trace };
  };
  /** the simplest forgery: from one tag t of a one-block message m, m ‖ (m ⊕ t) also has tag t */
  Mc.cbcMacForgeOne = (key, m) => Mc.cbcMacForge({ key, m1: m, m2: m });

  // ---- CMAC (NIST SP 800-38B, RFC 4493)
  const dbl = (b) => { // multiply by x in GF(2^128): shift left one bit, fold in 0x87 if a bit fell off
    const o = new Uint8Array(16);
    for (let i = 0; i < 16; i++) o[i] = ((b[i] << 1) | (i < 15 ? b[i + 1] >>> 7 : 0)) & 255;
    if (b[0] & 0x80) o[15] ^= 0x87;
    return o;
  };
  Mc.dbl = dbl;
  Mc.cmacSubkeys = (key) => {
    const L = E(new Uint8Array(16), key), K1 = dbl(L), K2 = dbl(K1);
    return {
      L, K1, K2, trace: [
        step('L', `L = AES_K(0¹²⁸) = ${hex(L)}.`, { L }),
        step('K1', `K1 = L·x: shift left one bit${L[0] & 0x80 ? ' and, since the top bit was 1, XOR 0x87 into the last byte' : ' (the top bit was 0, so no reduction)'}: ${hex(K1)}.`, { K1 }),
        step('K2', `K2 = K1·x: ${hex(K2)}${K1[0] & 0x80 ? ', with the 0x87 reduction' : ''}.`, { K2 }),
      ],
    };
  };
  Mc.cmac = (key, msg, opt = {}) => {
    msg = utf8(msg);
    const sk = Mc.cmacSubkeys(key), n = Math.max(1, Math.ceil(msg.length / 16));
    const complete = msg.length > 0 && msg.length % 16 === 0;
    const bs = blocks(msg); if (!bs.length) bs.push(new Uint8Array(0));
    let last = bs[n - 1];
    if (!complete) { const p = new Uint8Array(16); p.set(last); p[last.length] = 0x80; last = p; }
    const lastX = xor(last, complete ? sk.K1 : sk.K2);
    const trace = opt.trace ? [...sk.trace] : null;
    if (trace) trace.push(step('last', complete ? `The last block is complete, so it is XORed with K1: ${hex(lastX)}.` : `The last block has ${msg.length % 16} byte${msg.length % 16 === 1 ? '' : 's'}, so it is padded with 80 00 … and XORed with K2: ${hex(lastX)}. Different subkeys keep a padded message from colliding with an unpadded one.`, { last: lastX, complete }));
    let c = new Uint8Array(16);
    const chain = [];
    for (let i = 0; i < n; i++) {
      const m = i === n - 1 ? lastX : bs[i], x = xor(m, c), y = E(x, key);
      chain.push({ i, m, prev: c, x, c: y });
      if (trace) trace.push(step('block', `Block ${i + 1}: ${hex(m)} ⊕ ${hex(c)} → AES → ${hex(y)}.`, { i, x, c: y }));
      c = y;
    }
    if (!trace) return c;
    trace.push(step('tag', `The CMAC tag is ${hex(c)}. The subkey on the last block is what CBC-MAC lacked: a forged extension now has to guess it.`, { tag: c }));
    return { tag: c, subkeys: sk, chain, trace };
  };

  // ---- GMAC (NIST SP 800-38D with an empty plaintext)
  Mc.gmac = (key, iv, aad, opt = {}) => {
    aad = utf8(aad);
    const G = S.GF.gcm || S.GF;
    const Hk = E(new Uint8Array(16), key);
    if (iv.length !== 12) throw new Error('this GMAC takes a 12-byte IV');
    const J0 = concat(iv, Uint8Array.of(0, 0, 0, 1));
    const Sg = G.ghash(Hk, aad, new Uint8Array(0)), EJ = E(J0, key), tag = xor(EJ, Sg);
    if (!opt.trace) return tag;
    const trace = [
      step('H', `The hash key is H = AES_K(0¹²⁸) = ${hex(Hk)}.`, { H: Hk }),
      step('J0', `The 12-byte IV with 00000001 appended is the first counter block J0 = ${hex(J0)}.`, { J0 }),
      step('ghash', `GHASH over the ${aad.length} bytes of data (in ${Math.ceil(aad.length / 16)} blocks, then a length block): each step is Y = (Y ⊕ X)·H in GF(2¹²⁸), ending at ${hex(Sg)}.`, { S: Sg }),
      step('tag', `Tag = AES_K(J0) ⊕ GHASH = ${hex(EJ)} ⊕ ${hex(Sg)} = ${hex(tag)}. Reusing an IV under the same key gives away H, and with it forgeries.`, { tag }),
    ];
    return { tag, H: Hk, J0, S: Sg, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
