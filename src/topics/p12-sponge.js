// Part 12, the sponge: SHA-3 absorbs its padded message block by block into the first `rate` bytes of a 200-byte
// state, with Keccak-f between blocks, then squeezes the digest from the same bytes; the capacity is never touched
// by input or output. And SHAKE, the same sponge squeezed for as long as you like.
(function (S) {
  'use strict';
  const U = S.P12, H = () => S.Hash;
  const { t } = U;
  /** 25 lanes as big-endian hex strings -> the 200 state bytes, in order (lanes are little-endian) */
  const laneBytes = (lanes) => { const o = []; for (const l of lanes) for (let j = 7; j >= 0; j--) o.push(parseInt(l.substr(2 * j, 2), 16)); return o; };
  const NAMES = { 'sha3-224': 'SHA3-224', 'sha3-256': 'SHA3-256', 'sha3-384': 'SHA3-384', 'sha3-512': 'SHA3-512', shake128: 'SHAKE128', shake256: 'SHAKE256' };

  /** the 200-byte state as a grid of 25 × 8 cells: rate bytes tinted, capacity grey, lit bytes on top */
  function stateGrid(prefix, x, y, bytes, rate, lit) {
    const items = [], cw = 33, ch = 21;
    for (let i = 0; i < 200; i++) {
      const c = i % 25, r = Math.floor(i / 25), l = lit ? lit(i) : '';
      items.push({ key: prefix + i, kind: 'cell', x: x + c * (cw + 1), y: y + r * (ch + 2), w: cw, h: ch, rx: 2, text: bytes ? U.h2(bytes[i]) : '', size: 13, cls: 'hex ' + (l || (i < rate ? 'prate' : 'pcap')) });
    }
    return items;
  }

  // ---------------------------------------------------------------------------------------------------------------
  // the sponge
  // ---------------------------------------------------------------------------------------------------------------
  function sponge(inp) {
    const S3 = H().SHA3, p = S3.params(inp.alg), msg = U.utf8(inp.msg), name = NAMES[inp.alg];
    const r = S3.run(msg, Object.assign({}, p, { trace: true })), nb = r.absorbs.length, rate = p.rate, cap = p.capacity, out = U.hex(r.digest);
    const gx = 26, gy = 344;
    // the sponge drawn as data flow: two tracks, rate and capacity, through nb permutations
    const flow = (done, stage) => {
      const N = S.Kit.flow.net('sp'), items = [], yR = 176, yC = 270, fw = 60, step = Math.min(250, 640 / (nb + 1));
      const xs = Array.from({ length: nb }, (_, i) => 130 + i * step);
      items.push(t('sp:lr', 20, yR - 10, 'rate ' + rate + ' B', 'act', 'start', 13), t('sp:lc', 20, yC - 10, 'capacity ' + cap + ' B', 'ptick', 'start', 13));
      let prevR = [86, yR], prevC = [86, yC];
      xs.forEach((x, i) => {
        const on = i < done || (i === done && stage === 'xor');
        N.op('x' + i, x, yR, 'xor', i === done && stage === 'xor' ? 'act' : '');
        N.box('P' + i, x, 108, 54, 36, 'P' + U.sub(i), i === done && stage === 'xor' ? 'act' : on ? '' : 'soft');
        N.wire('p' + i, [N.port('P' + i, 's'), N.port('x' + i, 'n')], { head: true, cls: i === done && stage === 'xor' ? 'act' : '' });
        N.wire('r' + i, [prevR, N.port('x' + i, 'w')], { head: true, cls: '' });
        N.box('f' + i, x + step / 2, (yR + yC) / 2, fw, 136, 'f', i < done || (i === done && stage === 'f') ? 'cipher' + (i === done && stage === 'f' ? ' act' : '') : 'soft');
        N.wire('rx' + i, [N.port('x' + i, 'e'), [x + step / 2 - fw / 2, yR]], { head: true });
        N.wire('c' + i, [prevC, [x + step / 2 - fw / 2, yC]], { head: true, cls: 'faint' });
        prevR = [x + step / 2 + fw / 2, yR]; prevC = [x + step / 2 + fw / 2, yC];
      });
      const zx = 130 + nb * step;
      N.box('Z', zx + 40, 108, 74, 36, 'Z', stage === 'squeeze' ? 'hot' : 'soft');
      N.wire('z', [prevR, [zx, yR], [zx, 108], N.port('Z', 'w')], { head: true, cls: stage === 'squeeze' ? 'hot' : '' });
      N.wire('cend', [prevC, [zx + 20, yC]], { cls: 'faint' });
      items.push(t('sp:ab', 130, 316, 'absorbing', 'ptitle'), t('sp:sq', zx - 6, 316, 'squeezing', 'ptitle'));
      return items.concat(N.items);
    };
    const legend = U.legend('sp:lg', gx, 552 + 26, [['prate', 'rate bytes'], ['pcap', 'capacity bytes'], ['act', 'block XORed in'], ['hot', 'output']], 13);
    const head = U.head('sp:h', name + ': a sponge on a 200-byte state', 'rate ' + rate + ' bytes, capacity ' + cap + ' bytes, Keccak-f[1600] between blocks');
    const F = new S.Frames(['absorbed', 'perms']);
    const base = { rate, cap, rbits: rate * 8, cbits: cap * 8, nb, n: msg.length };
    F.add({ items: [...head, ...flow(-1, ''), ...stateGrid('sg', gx, gy, new Array(200).fill(0), rate), ...legend], hl: { d: [0] }, say: `The state is 1600 bits, 200 bytes, all zero. ${name} splits it into a rate of ${rate} bytes (${rate * 8} bits), the only part input ever touches, and a capacity of ${cap} bytes (${cap * 8} bits), which is never read from or written to directly.`, facts: base, meta: { stage: 'start' } });
    const pad = r.padded, last = pad.length - 1;
    F.add({ items: [...head, ...flow(-1, ''), ...stateGrid('sg', gx, gy, new Array(200).fill(0), rate), ...legend], hl: { d: [1] }, say: `Padding: after the ${U.plural(msg.length, 'byte')} of the message comes the byte 06 (two domain bits that mark SHA-3, then the first 1 of the padding), zeros, and 80 at the end of the block (the final 1). That gives ${U.plural(nb, 'block')} of ${rate} bytes.${pad[msg.length] === 0x86 ? ' Here both fall in the same byte: 06 ⊕ 80 = 86.' : ''}`, facts: Object.assign({ last }, base), meta: { stage: 'pad' } });
    r.absorbs.forEach((a, i) => {
      const xb = laneBytes(a.xored), before = laneBytes(a.before), after = laneBytes(a.after);
      F.count('absorbed');
      F.add({ items: [...head, ...flow(i, 'xor'), ...stateGrid('sg', gx, gy, xb, rate, (j) => (j < rate && xb[j] !== before[j] ? 'act' : '')), ...legend], hl: { d: [2] }, say: `Absorb block ${i + 1}: its ${rate} bytes are XORed into the rate part of the state, bytes 0 to ${rate - 1}; the ${cap} capacity bytes are left alone. The first state bytes are now ${U.hex(xb.slice(0, 6))}…`, facts: Object.assign({ i: i + 1, first: U.hex(xb.slice(0, 6)), lastByte: rate - 1 }, base), meta: { stage: 'xor', i } });
      F.count('perms');
      let changed = 0; for (let j = 0; j < 200; j++) if (after[j] !== xb[j]) changed++;
      F.add({ items: [...head, ...flow(i, 'f'), ...stateGrid('sg', gx, gy, after, rate, (j) => (after[j] !== xb[j] ? 'hot' : '')), ...legend], hl: { d: [3] }, say: `Keccak-f, 24 rounds, scrambles the whole state, capacity included: ${changed} of the 200 bytes changed. Lane (0, 0) went from ${a.xored[0]} to ${a.after[0]}.`, facts: Object.assign({ i: i + 1, changed, lane0: [a.xored[0], a.after[0]] }, base), meta: { stage: 'f', i } });
    });
    const fin = laneBytes(r.absorbs[nb - 1].after), ol = r.digest.length;
    F.add({ items: [...head, ...flow(nb, 'squeeze'), ...stateGrid('sg', gx, gy, fin, rate, (j) => (j < ol ? 'hot' : '')), ...legend], hl: { d: [4] }, say: `Squeeze: the digest is simply the first ${ol} bytes of the rate: ${U.spaced(out)}. ${ol <= rate ? 'One squeeze is enough.' : ''} The capacity was never output, so an attacker who sees the digest still lacks ${cap * 8} bits of the state: no length extension here.`, facts: Object.assign({ ol, out }, base), meta: { stage: 'squeeze' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('The sponge (b = r + c = 1600 bits)', ['state S = 0¹⁶⁰⁰;  r = rate, c = capacity', 'pad: m ‖ 06 ‖ 00 … 00 ‖ 80 to a multiple of r', 'absorb: for each block P, S ← f(S ⊕ (P ‖ 0ᶜ))', 'f = Keccak-f[1600], 24 rounds of θ ρ π χ ι', 'squeeze: output the first r bits, f, the next r bits, …', 'security about c/2 bits: c = 2 × the digest length']) };
  }
  S.topic({
    id: 'p12-sponge', family: 'p12-sha3', order: 10, title: 'The sponge: absorb, then squeeze',
    blurb: 'SHA-3 is not Merkle–Damgård. Message blocks are XORed into the top of a 1600-bit state, a permutation stirs it, and the digest is read off the same top part. The hidden capacity is where the security lives.',
    inputs: [
      { id: 'msg', kind: 'text', label: 'Message', def: 'keccak sees all', check: (v) => (U.utf8(v).length > 200 ? 'Message: at most 200 bytes' : null) },
      { id: 'alg', kind: 'choice', label: 'Hash', def: 'sha3-256', options: ['sha3-224', 'sha3-256', 'sha3-384', 'sha3-512'].map((v) => ({ value: v, label: NAMES[v] })) },
    ],
    presets: [
      { label: 'SHA3-256, one block', values: { msg: 'keccak sees all', alg: 'sha3-256' } },
      { label: 'The empty message', values: { msg: '', alg: 'sha3-256' } },
      { label: 'SHA3-512: a smaller rate', values: { msg: 'A larger capacity buys security with a smaller rate, so this note needs two blocks.', alg: 'sha3-512' } },
      { label: 'SHA3-256, two blocks', values: { msg: 'A note longer than the rate of one hundred and thirty-six bytes cannot fit in a single block, so it is absorbed in two, with a permutation between.', alg: 'sha3-256' } },
    ],
    counters: [{ id: 'absorbed', label: 'blocks absorbed' }, { id: 'perms', label: 'permutations' }],
    run: sponge,
    predict: [
      { at: (f) => f.meta && f.meta.stage === 'xor' && f.meta.i === 0, pick: 'option', options: ['only the rate bytes', 'only the capacity bytes', 'all 200 bytes'], ask: 'Which bytes of the state will Keccak-f change?', answer: 'all 200 bytes', explain: 'Input touches only the rate, but the permutation mixes the whole state.' },
    ],
    quiz: [
      { q: 'Which part of the sponge state is output?', options: ['the capacity', 'the rate', 'all of it', 'a hash of it'], answer: 1, why: 'Only rate bytes are read in squeezing.' },
      { q: 'Why can SHA-3 not be length-extended like SHA-256?', options: ['it is slower', 'its digest omits the capacity, so the full state is unknown', 'it has no padding', 'it uses BigInt'], answer: 1, why: 'Resuming needs the whole state; the capacity is never revealed.' },
      { q: 'SHA3-256 has a capacity of 512 bits. Its generic security is about…', options: ['512 bits', '256 bits', '128 bits', '1600 bits'], answer: 1, why: 'About c/2 = 256 bits against generic attacks on the sponge (and 128 bits for collisions, from the 256-bit output).' },
      { q: 'Why does SHA3-512 have a smaller rate than SHA3-256?', options: ['the state is smaller', 'it needs a larger capacity, and rate + capacity is fixed at 1600 bits', 'it uses fewer rounds', 'it pads differently'], answer: 1, why: 'c = 1024 bits leaves r = 576 bits, 72 bytes.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // SHAKE
  // ---------------------------------------------------------------------------------------------------------------
  function shake(inp) {
    const Hs = H(), S3 = Hs.SHA3, bits = +inp.alg.slice(5), msg = U.utf8(inp.msg), L = +inp.len, name = NAMES[inp.alg];
    const r = S3.shake(bits, msg, L, { trace: true }), rate = bits === 128 ? 168 : 136, out = r.digest;
    const chunks = Math.ceil(L / rate), short = Hs.SHA3.shake(bits, msg, 16).digest;
    const per = 28, cw = 28, ch = 19;
    const ribbon = (upto, lit) => {
      const items = [t('sk:rt', 26, 196, 'the output, ' + U.plural(L, 'byte'), 'ptitle')];
      for (let i = 0; i < Math.min(upto, L); i++) {
        const c = Math.floor(i / rate);
        items.push({ key: 'sk:o' + i, kind: 'cell', x: 26 + (i % per) * (cw + 2), y: 208 + Math.floor(i / per) * (ch + 3), w: cw, h: ch, rx: 2, text: U.h2(out[i]), size: 13, cls: 'hex ' + (lit && lit(i) ? lit(i) : ['act', 'key', 'src'][c % 3]) });
      }
      return items;
    };
    const chain = (k) => {
      const N = S.Kit.flow.net('skc'), y = 118;
      N.box('ab', 90, y, 120, 40, 'absorb m', k >= 0 ? 'cipher' : 'soft');
      let prev = N.port('ab', 'e');
      for (let j = 0; j < chunks; j++) {
        const x = 270 + j * 210;
        N.box('z' + j, x, y, 110, 40, 'Z' + U.sub(j) + ': ' + Math.min(rate, L - j * rate) + ' B', j <= k ? ['act', 'key', 'src'][j % 3] : 'soft');
        N.wire('w' + j, [prev, N.port('z' + j, 'w')], { head: true, cls: j === k ? 'act' : '' });
        if (j < chunks - 1) { N.box('f' + j, x + 105, y, 44, 40, 'f', j < k ? 'cipher' : 'soft'); N.wire('wf' + j, [N.port('z' + j, 'e'), N.port('f' + j, 'w')], { head: true }); prev = N.port('f' + j, 'e'); }
      }
      return N.items;
    };
    const head = U.head('sk:h', name + ': as much output as you ask for', 'rate ' + rate + ' bytes; ' + U.plural(L, 'byte') + ' asked for');
    const F = new S.Frames(['squeezed']);
    const base = { rate, L, chunks, bits };
    F.add({ items: [...head, ...chain(-1)], hl: { d: [0] }, say: `${name} absorbs exactly as SHA-3 does, with a rate of ${rate} bytes, but its padding starts with the byte 1F instead of 06: four domain bits that keep SHAKE's outputs apart from SHA-3's. It has no fixed output length.`, facts: base, meta: { stage: 'start' } });
    for (let j = 0; j < chunks; j++) {
      const upto = Math.min(L, (j + 1) * rate);
      F.set('squeezed', upto);
      F.add({ items: [...head, ...chain(j), ...ribbon(upto, (i) => (i >= j * rate ? '' : 'soft'))], hl: { d: [1, 2] }, say: j === 0 ? `Squeeze ${j + 1}: read the first ${upto} bytes of the rate: ${U.short(out, 8)}${L > rate ? ` (a squeeze gives at most ${rate})` : ''}.` : `The rate is used up, so Keccak-f runs again and the next ${upto - j * rate} bytes are read: ${U.short(out.slice(j * rate), 8)}. Every further block costs one more permutation.`, facts: Object.assign({ j: j + 1, upto, more: upto - j * rate, z: U.hex(out.slice(j * rate, j * rate + 8)) }, base), meta: { stage: 'squeeze', j } });
    }
    const pre = U.hex(short), isPrefix = U.hex(out).startsWith(pre) || L < 16;
    F.add({ items: [...head, ...chain(chunks - 1), ...ribbon(L, (i) => (i < 16 ? 'hot' : 'soft'))], hl: { d: [3] }, say: `Asking for 16 bytes gives ${pre}${L >= 16 ? `, the first 16 of these ${L}` : ''}: ${isPrefix ? 'a shorter output is always a prefix of a longer one' : 'not a prefix'}. So the output length is not mixed into the result; if two lengths must not be related, put the length into the message.`, facts: Object.assign({ pre }, base), meta: { stage: 'prefix' } });
    const sha = Hs.get(bits === 128 ? 'sha3-256' : 'sha3-512').hash(msg), shk = Hs.SHA3.shake(bits, msg, sha.length).digest;
    const cmp = [...U.readout('sk:cmp', 26, 420, 868, 'same message, same sponge, different domain byte', [[bits === 128 ? 'SHA3-256 (06)' : 'SHA3-512 (06)', U.short(sha, 24)], [name + ' (1F), same length', U.short(shk, 24), 'act']], { dy: 34, vsize: 13 })];
    F.add({ items: [...head, ...chain(chunks - 1), ...ribbon(Math.min(L, 196)), ...cmp], hl: { d: [0] }, say: `Domain separation: ${bits === 128 ? 'SHA3-256' : 'SHA3-512'} of the same message begins ${U.short(sha, 6)}, while ${name} cut to the same ${sha.length} bytes begins ${U.short(shk, 6)}: one padding byte makes the two functions unrelated.`, facts: Object.assign({ sha: U.hex(sha), shk: U.hex(shk), n: sha.length }, base), meta: { stage: 'domain' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('SHAKE (an extendable-output function)', ['pad: m ‖ 1F ‖ 00 … 00 ‖ 80  (SHA-3 uses 06)', 'absorb as in SHA-3', 'squeeze: Z₀ = first r bytes, then f, Z₁, …', 'SHAKE128: r = 168 bytes, 128-bit security', 'SHAKE256: r = 136 bytes, 256-bit security']) };
  }
  S.topic({
    id: 'p12-shake', family: 'p12-sha3', order: 40, title: 'SHAKE: output of any length',
    blurb: 'Keep squeezing the sponge and it keeps giving bytes: one permutation per rate-sized block. A shorter output is a prefix of a longer one, and one domain byte keeps SHAKE apart from SHA-3.',
    inputs: [
      { id: 'msg', kind: 'text', label: 'Message', def: 'keccak sees all', check: (v) => (U.utf8(v).length > 120 ? 'Message: at most 120 bytes' : null) },
      { id: 'alg', kind: 'choice', label: 'Function', def: 'shake128', options: [{ value: 'shake128', label: 'SHAKE128' }, { value: 'shake256', label: 'SHAKE256' }] },
      { id: 'len', kind: 'number', label: 'Output bytes', def: 200, min: 1, max: 336 },
    ],
    presets: [
      { label: 'SHAKE128, 200 bytes', values: { msg: 'keccak sees all', alg: 'shake128', len: 200 } },
      { label: 'SHAKE256, 32 bytes', values: { msg: 'keccak sees all', alg: 'shake256', len: 32 } },
      { label: 'SHAKE256, 336 bytes: three squeezes', values: { msg: 'a seed for a long mask', alg: 'shake256', len: 336 } },
      { label: 'The empty message', values: { msg: '', alg: 'shake128', len: 64 } },
    ],
    counters: [{ id: 'squeezed', label: 'bytes squeezed' }],
    run: shake,
    predict: [
      { at: (f, i, fr) => f.meta && f.meta.stage === 'start', pick: 'option', options: (fr) => { const n = fr[fr.length - 1].facts.chunks; return ['1', '2', '3'].concat(n > 3 ? [String(n)] : []); }, ask: 'How many squeeze blocks will this output need?', answer: (fr) => String(fr[0].facts.chunks), explain: (fr) => 'Each squeeze gives at most ' + fr[0].facts.rate + ' bytes.' },
    ],
    quiz: [
      { q: 'How do SHAKE128 and SHA3-256 differ in padding?', options: ['they do not', 'SHAKE starts its padding with 1F, SHA-3 with 06', 'SHAKE pads with zeros only', 'SHA-3 has no padding'], answer: 1, why: 'The domain bits differ, so the functions are independent.' },
      { q: 'SHAKE128(m, 32) and SHAKE128(m, 64): how are they related?', options: ['unrelated', 'the first is a prefix of the second', 'they are equal', 'the second is the hash of the first'], answer: 1, why: 'The output stream does not depend on the length requested.' },
      { q: 'What does each extra block of SHAKE128 output cost?', options: ['nothing', 'one Keccak-f per 168 bytes', 'a new absorb', 'one AES call'], answer: 1, why: 'Squeezing past the rate needs a permutation.' },
      { q: 'Where is an extendable-output function useful?', options: ['only for passwords', 'masks, key derivation, and sampling as in ML-KEM, where any length is needed', 'nowhere', 'only for MD5'], answer: 1, why: 'Lattice schemes expand seeds into matrices with SHAKE.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
