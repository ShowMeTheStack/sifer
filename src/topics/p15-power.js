// Part 15, power analysis: what a power trace of AES's first round shows and why it leaks; the Hamming-weight and
// Hamming-distance models; simple power analysis, where one trace of square-and-multiply follows the exponent's bits,
// and the regular code that stops it; and differential power analysis, a difference of means that shows a key byte
// leaking, and masking, which makes the spike go away.
(function (S) {
  'use strict';
  const U = S.P14, V = S.P15, C = () => S.SC;
  const fx = U.fx, h2 = U.hex2;
  const bin8 = (v) => v.toString(2).padStart(8, '0');
  const sigmaOpt = (vals, def) => ({ id: 'sigma', kind: 'choice', label: 'Noise σ', def, options: vals.map((v) => ({ value: v, label: v })) });

  // ---------------------------------------------------------------------------------------------------------------
  // A power trace
  // ---------------------------------------------------------------------------------------------------------------
  function traceTopic(inp) {
    const key = V.key(inp.key), b = +inp.byte, sigma = +inp.sigma, seed = +inp.seed;
    const clean = C().source({ key, sigma: 0, seed }).next(1), noisy = C().source({ key, sigma, seed }).next(1);
    const p = clean.plaintexts[b], x = p ^ key[b], y = C().sbox()[x], HW = C().HW;
    const tl = C().sampleOf(b, 'load');
    const F = new S.Frames();
    const head = U.t('tr:h', 20, 30, 'A simulated power trace of AES\'s first round, one sample per operation', 'strong', 'start', 16);
    const pl = V.tracePlot({ prefix: 'tr:p', x: 70, y: 70, w: 820, h: 230, yr: [-2, 10], yticks: [0, 4, 8], ylabel: 'power drawn', xlabel: '' });
    const lanes = () => {
      // which byte each stretch of samples belongs to
      const items = [];
      for (let k = 0; k < 16; k++) items.push(U.t('tr:bl' + k, pl.X(3 + 3 * k), 334, 'b' + k, k === b ? 'act' : 'tick', 'middle', 13));
      items.push(U.t('tr:bs', pl.X(0.5), 334, 'set-up', 'tick', 'middle', 13));
      return items;
    };
    const valueCells = (show) => {
      if (!show) return [];
      const items = [U.t('tr:vt', 70, 386, `byte ${b}: the three values the device handles, and the power each draws`, 'strong', 'start', 14)];
      [['load pᵢ', p], ['pᵢ ⊕ kᵢ', x], ['S(pᵢ ⊕ kᵢ)', y]].forEach(([name, v], r) => {
        const yy = 404 + r * 46;
        items.push(U.t('tr:vn' + r, 200, yy + 22, name, r === 1 ? 'key' : 'strong', 'end', 15));
        for (let j = 0; j < 8; j++) { const bit = (v >> (7 - j)) & 1; items.push({ key: 'tr:vb' + r + '_' + j, kind: 'cell', x: 214 + j * 32, y: yy, w: 30, h: 32, rx: 3, text: String(bit), size: 15, cls: 'hex bit ' + (bit ? 'one act' : '') }); }
        items.push(U.t('tr:vh' + r, 480, yy + 22, `= ${h2(v)}, ${HW[v]} bits set → sample ${tl + r} ≈ ${HW[v]}`, 'mono', 'start', 15));
      });
      return items;
    };
    const facts0 = { b, p: h2(p), x: h2(x), y: h2(y), hp: HW[p], hx: HW[x], hy: HW[y], tl, ta: tl + 1, ts: tl + 2, T: 52, sigma };
    F.add({ items: [head, ...pl.items, pl.shade(b), ...lanes(), U.t('tr:n', 70, 400, 'Samples 0 and 1 are set-up; then three for each of the 16 bytes: load pᵢ, add the key byte, look up the S-box.', 'tick', 'start', 14)], hl: { d: [0] }, say: `The device runs AES's first round one byte at a time: for each byte it loads the plaintext byte, adds the key byte and looks the result up in the S-box. One trace has 52 samples: 2 for set-up, 3 for each of the 16 bytes (byte ${b} at samples ${tl} to ${tl + 2}), and 2 idle.`, facts: facts0, meta: { stage: 'layout' } });
    F.add({ items: [head, ...pl.items, pl.shade(b), ...lanes(), pl.steps('tr:clean', clean.traces, 'act'), ...valueCells(true)], hl: { d: [1] }, say: `Without noise, each sample is exactly the Hamming weight of the value handled: for byte ${b}, the plaintext byte ${h2(p)} has ${HW[p]} bits set, p ⊕ k = ${h2(x)} has ${HW[x]}, and S(p ⊕ k) = ${h2(y)} has ${HW[y]}. The middle and last values depend on the key byte.`, facts: facts0, meta: { stage: 'clean' } });
    F.add({ items: [head, ...pl.items, pl.shade(b), ...lanes(), pl.steps('tr:clean', clean.traces, 'soft'), pl.steps('tr:noisy', noisy.traces, 'hot'), ...valueCells(true)], hl: { d: [2] }, say: `A real measurement adds noise: here Gaussian with σ = ${sigma}, so sample ${tl + 2} reads ${fx(noisy.traces[tl + 2], 2)} instead of ${HW[y]}. One trace no longer shows the weights clearly${sigma >= 2 ? ' at all' : ''}; many traces will.`, facts: Object.assign({ read: noisy.traces[tl + 2] }, facts0), meta: { stage: 'noisy' } });
    // many traces: the S-box sample of byte b against the weight of S(p ⊕ k)
    const N = 400, src = C().source({ key, sigma, seed: seed + 1 }), ch = src.next(N), ts = tl + 2;
    const cpa = C().CPA({ byte: b, T: 52 }).add(ch), rho = cpa.corr()[key[b] * 52 + ts];
    const sp = U.plot({ prefix: 'tr:s', x: 600, y: 386, w: 290, h: 200, xr: [-0.5, 8.5], yr: [-4, 12], xticks: [0, 2, 4, 6, 8], yticks: [0, 4, 8], xlabel: 'HW of S(pᵢ ⊕ kᵢ)', ylabel: `sample ${ts}, ${N} traces`, tickSize: 13 });
    const dots = [], means = new Array(9).fill(0), counts = new Array(9).fill(0);
    for (let i = 0; i < N; i++) { const hw = HW[C().sbox()[ch.plaintexts[i * 16 + b] ^ key[b]]], v = ch.traces[i * 52 + ts]; means[hw] += v; counts[hw]++; dots.push({ key: 'tr:sd' + i, kind: 'dot', x: sp.X(hw + ((i * 37) % 11 - 5) * 0.05), y: sp.Y(Math.max(-4, Math.min(12, v))), r: 1.8, cls: 'act', layer: 'back' }); }
    const mx = [], my = [];
    means.forEach((s, k) => { if (counts[k]) { mx.push(k); my.push(s / counts[k]); } });
    F.add({ items: [head, ...pl.items, pl.shade(b, 'sbox', 'hot'), ...lanes(), ...Array.from({ length: 12 }, (_, i) => pl.trace('tr:m' + i, ch.traces.subarray(i * 52, i * 52 + 52), 'faint')), ...sp.items, ...dots, U.line(sp, 'tr:sm', mx, my, 'hot', 'ignore'), U.t('tr:r', 70, 410, `correlation of sample ${ts} with the weight: ρ = ${fx(rho, 3)}`, 'strong', 'start', 15), U.t('tr:r2', 70, 440, 'each column: the traces whose S-box output had that weight', 'tick', 'start', 13), U.t('tr:r3', 70, 466, 'the orange line joins the column means', 'tick', 'start', 13)], hl: { d: [3] }, say: `${N} traces with random plaintexts. Plot sample ${ts} of each against the Hamming weight of its S(pᵢ ⊕ kᵢ): the noise spreads every column, but the means climb in a straight line. The correlation is ρ = ${fx(rho, 3)}. That straight line is the leak: because it holds only for the true key byte, enough traces expose the byte. A defence has to break the line, not hide it under noise.`, facts: Object.assign({ N, rho }, facts0), meta: { stage: 'many' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Power and data', ['P(t) ≈ a · HW(value handled at t) + noise', 'HW(v) = the number of 1 bits in v', 'byte i: load pᵢ, then pᵢ ⊕ kᵢ, then S(pᵢ ⊕ kᵢ)', 'the last two depend on the key byte kᵢ', 'many traces: the mean power at t follows HW']) };
  }
  S.topic({
    id: 'sc-trace', family: 'p15-power', order: 10, title: 'A power trace and what it leaks',
    blurb: 'A chip draws a little more current for every bit that is 1 in the value it handles. A trace of AES\'s first round shows that, sample by sample, under noise that many traces average away.',
    inputs: [
      { id: 'key', kind: 'text', label: 'AES key (16 characters)', def: 'harbour-lights-7', check: V.keyCheck },
      { id: 'byte', kind: 'number', label: 'Byte to look at', def: 0, min: 0, max: 15 },
      sigmaOpt(['0.5', '1', '2', '3'], '1'),
      { id: 'seed', kind: 'number', label: 'Plaintext seed', def: 3, min: 1, max: 999 },
    ],
    presets: [
      { label: 'Byte 0, σ = 1', values: { byte: 0, sigma: '1' } },
      { label: 'Byte 5, little noise', values: { byte: 5, sigma: '0.5', seed: 8 } },
      { label: 'Byte 11, heavy noise', values: { byte: 11, sigma: '3', seed: 4 } },
    ],
    run: traceTopic,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'layout', pick: 'option', options: ['the number of 1 bits in the value', 'the value itself', 'the key only', 'nothing'], ask: 'In this model, what sets the height of each sample?', answer: 'the number of 1 bits in the value', explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'The Hamming weight of 0x3c is…', options: ['2', '4', '6', '60'], answer: 1, why: '0x3c = 00111100: four bits set.' },
      { q: 'Which samples of byte i depend on the key?', options: ['only the load', 'pᵢ ⊕ kᵢ and S(pᵢ ⊕ kᵢ)', 'none', 'only the idle ones'], answer: 1, why: 'The load handles the plaintext alone.' },
      { q: 'Why does an attacker collect many traces?', options: ['Each one is different data', 'Noise averages out, and the data dependence remains', 'To slow the device', 'For the key schedule'], answer: 1, why: 'The signal is the same function of the data in every trace; the noise is independent.' },
      { q: 'Why is the S-box output the most dangerous sample to leak?', options: ['It is the only leak', 'After the non-linear S-box, any other key value gives weights unrelated to the true ones, so the true key stands out clearly', 'It is louder', 'It is not more dangerous'], answer: 1, why: 'Nearby key values give unrelated weights after the S-box, so the leak singles out the true key.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Leakage models
  // ---------------------------------------------------------------------------------------------------------------
  function models(inp) {
    const a = parseInt(inp.a, 16), b = parseInt(inp.b, 16), HW = C().HW, d = a ^ b;
    const key = V.key(inp.key), byte = 0, N = +inp.n;
    const F = new S.Frames();
    const head = U.t('md:h', 20, 30, 'Two leakage models: Hamming weight and Hamming distance', 'strong', 'start', 16);
    const row = (key2, y, name, v, cls, lit) => [U.t(key2 + ':n', 200, y + 22, name, 'strong', 'end', 15), ...Array.from({ length: 8 }, (_, j) => { const bit = (v >> (7 - j)) & 1; return { key: key2 + ':' + j, kind: 'cell', x: 214 + j * 36, y, w: 34, h: 34, rx: 3, text: String(bit), size: 16, cls: 'hex bit ' + (lit && lit(j) ? cls : bit ? 'one' : '') }; }), U.t(key2 + ':h', 520, y + 22, '= ' + h2(v), 'mono', 'start', 16)];
    const facts0 = { a: h2(a), b: h2(b), d: h2(d), ha: HW[a], hb: HW[b], hd: HW[d] };
    F.add({ items: [head, ...row('md:b', 80, 'new value', b, 'act', (j) => (b >> (7 - j)) & 1), U.t('md:w', 214, 150, `Hamming weight: ${HW[b]} bits set`, 'act', 'start', 16)], hl: { d: [0] }, say: `The Hamming-weight model: the power depends on how many bits of the value are 1. The value ${h2(b)} = ${bin8(b)} has weight ${HW[b]}. It fits devices whose buses are cleared to 0 before each value, so every 1 is a bit that rises.`, facts: Object.assign({ bin: bin8(b) }, facts0), meta: { stage: 'hw' } });
    F.add({ items: [head, ...row('md:a', 80, 'old value', a, 'soft', () => false), ...row('md:b', 130, 'new value', b, 'soft', () => false), ...row('md:d', 200, 'bits that flip', d, 'hot', (j) => (d >> (7 - j)) & 1), U.t('md:w', 214, 270, `Hamming distance: ${HW[d]} bits change`, 'hot', 'start', 16)], hl: { d: [1] }, say: `The Hamming-distance model: a register drawing power for every bit that changes when ${h2(a)} is overwritten by ${h2(b)}. The flips are ${h2(a)} ⊕ ${h2(b)} = ${h2(d)}: ${HW[d]} bits, though the new value alone has weight ${HW[b]}. CMOS logic burns power on transitions, so this is often the better model.`, facts: facts0, meta: { stage: 'hd' } });
    // the four pairings of device and model, measured by CPA's correlation for the true key byte
    const res = {};
    for (const dev of ['hw', 'hd']) {
      const ch = C().source({ key, model: dev, sigma: +inp.sigma, seed: 21 }).next(N);
      for (const mod of ['hw', 'hd']) { const r = C().CPA({ byte, T: 52, model: mod }).add(ch).result(key[byte]); res[dev + mod] = { rho: r.peaks[key[byte]], rank: r.rank }; }
    }
    const cell = (k2, x, y, r) => [{ key: 'md:c' + k2, kind: 'cell', x, y, w: 200, h: 64, rx: 6, lines: ['|ρ| = ' + fx(r.rho, 3), 'true key ranks ' + (r.rank + 1)], size: 15, cls: r.rank === 0 ? 'good' : 'bad' }];
    const tbl = [U.t('md:tt', 214, 336, `CPA on ${N} traces, key byte 0, σ = ${inp.sigma}: the correlation of the true key byte`, 'strong', 'start', 14),
      U.t('md:c1', 330, 372, 'model: weight', 'strong', 'middle', 14), U.t('md:c2', 550, 372, 'model: distance', 'strong', 'middle', 14),
      U.t('md:r1', 214, 420, 'device leaks weight', 'strong', 'end', 14), U.t('md:r2', 214, 494, 'device leaks distance', 'strong', 'end', 14),
      ...cell('11', 230, 388, res.hwhw), ...cell('12', 450, 388, res.hwhd), ...cell('21', 230, 462, res.hdhw), ...cell('22', 450, 462, res.hdhd)];
    F.add({ items: [head, ...row('md:a', 80, 'old value', a, 'soft', () => false), ...row('md:b', 130, 'new value', b, 'soft', () => false), ...row('md:d', 200, 'bits that flip', d, 'hot', (j) => (d >> (7 - j)) & 1), ...tbl], hl: { d: [2, 3] }, say: `Does the model matter? Simulate both kinds of device and measure each with both models. On the weight device the weight model gives |ρ| = ${fx(res.hwhw.rho, 3)}, the distance model ${fx(res.hwhd.rho, 3)}; on the distance device, ${fx(res.hdhw.rho, 3)} and ${fx(res.hdhd.rho, 3)}. The model that matches the hardware sees the strongest correlation: an evaluation with the wrong model underestimates the leak.`, facts: Object.assign({ N, sigma: +inp.sigma, r: [res.hwhw.rho, res.hwhd.rho, res.hdhw.rho, res.hdhd.rho], k: [res.hwhw.rank + 1, res.hwhd.rank + 1, res.hdhw.rank + 1, res.hdhd.rank + 1] }, facts0), meta: { stage: 'table', res } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Leakage models', ['HW(v): bits of v that are 1', 'HD(a, b) = HW(a ⊕ b): bits that change', 'P ≈ α·HW(v) + noise, or α·HD(old, new) + noise', 'here the HD device leaks HW(x ⊕ S(x)) at the S-box', 'evaluate with the model that matches the hardware']) };
  }
  S.topic({
    id: 'sc-models', family: 'p15-power', order: 20, title: 'Hamming weight and Hamming distance',
    blurb: 'Two simple stories of where the power goes: one unit for every bit that is 1, or one for every bit that changes. A measurement that tells the hardware\'s own story sees the strongest correlation, so an evaluation must use it.',
    inputs: [
      { id: 'a', kind: 'text', label: 'Old value (hex byte)', def: '5a', check: (v) => (!/^[0-9a-fA-F]{2}$/.test(v) ? 'Old value: two hex digits' : null) },
      { id: 'b', kind: 'text', label: 'New value (hex byte)', def: 'c3', check: (v) => (!/^[0-9a-fA-F]{2}$/.test(v) ? 'New value: two hex digits' : null) },
      { id: 'key', kind: 'text', label: 'AES key (16 characters)', def: 'harbour-lights-7', check: V.keyCheck },
      sigmaOpt(['1', '2', '3'], '2'),
      { id: 'n', kind: 'choice', label: 'Traces', def: '300', options: ['150', '300', '600'].map((v) => ({ value: v, label: v })) },
    ],
    presets: [
      { label: '5a then c3', values: { a: '5a', b: 'c3' } },
      { label: 'Same weight, all bits flip', values: { a: '0f', b: 'f0' } },
      { label: 'Heavier noise', values: { a: '5a', b: 'c3', sigma: '3', n: '600' } },
    ],
    run: models,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'hd', pick: 'option', options: ['weight model on the weight device', 'distance model on the weight device'], ask: 'Which pairing will show the stronger correlation for the weight device?', answer: (fr, i) => (fr[i + 1].meta.res.hwhw.rho >= fr[i + 1].meta.res.hwhd.rho ? 'weight model on the weight device' : 'distance model on the weight device'), explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'The Hamming distance between 0x0f and 0xf0 is…', options: ['0', '4', '8', '15'], answer: 2, why: 'Their XOR is 0xff: every bit changes.' },
      { q: 'Why do CMOS circuits fit the distance model?', options: ['They draw power mostly when bits switch', 'They count ones', 'They are noisy', 'They do not'], answer: 0, why: 'A gate that holds its state draws almost nothing; a switching one charges or discharges a capacitance.' },
      { q: 'If an evaluator measures with the wrong model, the leak…', options: ['vanishes', 'still often shows, but with a weaker correlation, so it is underestimated', 'gets stronger', 'moves to another key'], answer: 1, why: 'The two models usually correlate with each other partly; a matching model sees the leak at full strength.' },
      { q: 'HW(0x80) and HW(0xff) are…', options: ['1 and 8', '8 and 1', '128 and 255', '1 and 1'], answer: 0, why: 'Count the 1 bits.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Simple power analysis
  // ---------------------------------------------------------------------------------------------------------------
  /** long runs of bits or of S and M, cut into groups of eight so a narrow screen can wrap them */
  const grp = (say) => say.replace(/[01SM]{12,}/g, (r) => r.replace(/(.{8})(?=.)/g, '$1 '));
  function spa(inp) {
    const e = BigInt(inp.e), sigma = +inp.sigma, always = inp.always === 'yes';
    const tr = C().spaTrace(e, { seed: +inp.seed, sigma, always }), rd = C().spaRead(tr.samples);
    const T = tr.samples.length, bits = tr.bits;
    const F = new S.Frames();
    const head = U.t('sp:h', 20, 30, `Square-and-multiply on e = ${e} = ${bits}₂${always ? ', with a dummy multiply' : ''}`, 'strong', 'start', 16);
    const pl = V.tracePlot({ prefix: 'sp:p', x: 40, y: 96, w: 850, h: 240, yr: [-1, 4.2], yticks: [0, 2, 4], T, xticks: [0, T - 1], ylabel: '', xlabel: '' });
    const segs = () => tr.segments.map((s, k) => ({ key: 'sp:sg' + k, kind: 'path', d: `M${pl.X(s.start - 0.5)},96 H${pl.X(s.end - 0.5)} V336 H${pl.X(s.start - 0.5)} Z`, cls: 'band ' + (s.op === 'M' ? 'hot' : 'act'), audit: 'ignore', layer: 'back' }));
    const bitRow = () => {
      const items = [U.t('sp:bt', 40, 410, 'the secret exponent, held by the device', 'strong', 'start', 14)];
      const cw = Math.min(40, 840 / bits.length - 3);
      for (let i = 0; i < bits.length; i++) {
        items.push({ key: 'sp:b' + i, kind: 'cell', x: U.r2(40 + i * (cw + 3)), y: 420, w: U.r2(cw), h: 32, rx: 3, text: bits[i], size: 15, cls: 'hex bit ' + (bits[i] === '1' ? 'one' : '') });
      }
      return items;
    };
    const facts0 = { e: String(e), bits, grouped: [grp(bits), grp(tr.ops.join('')), grp(rd.bits)], n: bits.length, ops: tr.ops.join(''), count: tr.ops.length, S: tr.ops.filter((o) => o === 'S').length, M: tr.ops.filter((o) => o === 'M').length, T };
    F.add({ items: [head, ...pl.items, pl.steps('sp:t', tr.samples.map(() => 0), 'faint'), ...bitRow()], hl: { d: [0] }, say: grp(tr.trace[0].say) + ` ${tr.ops.filter((o) => o === 'S').length} squarings and ${tr.ops.filter((o) => o === 'M').length} multiplications.`, facts: facts0, meta: { stage: 'ops' } });
    F.add({ items: [head, ...pl.items, pl.steps('sp:t', tr.samples, 'act'), ...bitRow()], hl: { d: [1] }, say: tr.trace[1].say + ` The trace has ${T} samples.`, facts: facts0, meta: { stage: 'trace' } });
    const okBits = rd.bits === bits;
    const shape = [head, ...pl.items, ...segs(), pl.steps('sp:t', tr.samples, 'act'), ...bitRow()];
    F.add({ items: shape, hl: { d: [2] }, say: always ? `With a multiplication after every squaring, ${tr.ops.length} bursts alternate S, M, S, M whatever the bits are: e = ${e} and any other exponent of the same length give a trace of the same shape. Nothing in it follows the key.`
      : okBits ? `The bursts come in two lengths, a squaring short and a multiplication long, and their order is the order of the operations, which is the order of the bits. So this one trace exposes the whole exponent: no statistics and no second trace are needed. The weakness is in the code, not in the noise.`
        : `The bursts come in two lengths, and their order follows the exponent's bits. Here the noise blurs some of them, so this single trace does not show every bit cleanly; but a few traces of the same exponent averaged together would. Noise is no defence: the code itself must stop depending on the bits.`,
    facts: Object.assign({ read: rd.bits }, facts0), meta: { stage: 'outcome', ok: okBits } });
    F.add({ items: shape, hl: { d: [3] }, say: always ? 'The countermeasure worked: square-and-multiply-always does the same operations for every bit, at the price of about a third more work. Its extra multiplication must feed the result through a mask select, though: a dummy whose result is thrown away can be found with a fault, since disturbing it changes nothing.' : 'A branch on a key bit shows on a power trace. The fixes: always multiply and keep the product with a mask select, or the Montgomery ladder, which does one squaring and one multiplication per bit whatever the bit. Both make the trace the same for every exponent of a given length.', facts: facts0, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Simple power analysis', ['for each bit after the first: square; if 1, multiply', 'S and M take different time and power', 'so the sequence of bursts follows the bits', 'one trace can expose the exponent', 'defence: always S and M with a mask select, or the Montgomery ladder']) };
  }
  S.topic({
    id: 'sc-spa', family: 'p15-power', order: 30, title: 'SPA: an exponent read from one trace',
    blurb: 'Square-and-multiply squares for every bit and multiplies only for the ones. On a power trace a multiplication looks different from a squaring, so the exponent can be read off like Morse code.',
    inputs: [
      { id: 'e', kind: 'text', label: 'Secret exponent (decimal)', def: '46499', check: (v) => (!/^\d+$/.test(v) || BigInt(v) < 2n ? 'Exponent: a whole number of at least 2' : BigInt(v).toString(2).length > 24 ? 'Exponent: at most 24 bits, so the bursts stay readable' : null) },
      sigmaOpt(['0.1', '0.3', '0.6'], '0.1'),
      { id: 'always', kind: 'choice', label: 'Implementation', def: 'no', options: [{ value: 'no', label: 'naive square-and-multiply' }, { value: 'yes', label: 'square-and-multiply-always' }] },
      { id: 'seed', kind: 'number', label: 'Noise seed', def: 4, min: 1, max: 999 },
    ],
    presets: [
      { label: 'A 16-bit exponent', values: { e: '46499', sigma: '0.1', always: 'no' } },
      { label: 'A 22-bit exponent', values: { e: '3141529', sigma: '0.1', always: 'no' } },
      { label: 'Too much noise', values: { e: '46499', sigma: '0.6', always: 'no', seed: 2 } },
      { label: 'Multiply always', values: { e: '46499', sigma: '0.1', always: 'yes' } },
    ],
    run: spa,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'ops', pick: 'option', options: ['yes', 'no'], ask: 'Will the shape of the power trace depend on the exponent\'s bits?', answer: (fr, i, inp) => (inp.always === 'yes' ? 'no' : 'yes'), explain: (fr, i) => fr[i + 2].say }],
    quiz: [
      { q: 'In left-to-right square-and-multiply, a 1 bit costs…', options: ['a squaring', 'a squaring and a multiplication', 'a multiplication only', 'nothing'], answer: 1, why: 'Square for every bit; multiply for the ones.' },
      { q: 'Which exponentiation gives a trace whose shape does not depend on the bits?', options: ['left-to-right square-and-multiply', 'the Montgomery ladder, or multiply-always with a mask select', 'right-to-left square-and-multiply', 'any, if the exponent is long'], answer: 1, why: 'Both do one squaring and one multiplication per bit, whatever the bit.' },
      { q: 'Square-and-multiply-always defeats SPA because…', options: ['it is faster', 'every bit does the same operations', 'it adds noise', 'it hides the modulus'], answer: 1, why: 'The trace no longer depends on the bits, though it costs extra multiplications.' },
      { q: 'Why is SPA called simple?', options: ['It needs only one or a few traces and no statistics', 'It only works on toys', 'It needs no equipment', 'It breaks AES'], answer: 0, why: 'The secret is visible directly in the shape of a single trace.' },
      { q: 'Is more noise a fix for SPA?', options: ['Yes', 'No: averaging a few traces of the same exponent removes it; the code must stop branching on the bits', 'Only for short exponents', 'Only on servers'], answer: 1, why: 'The leak is in the sequence of operations; only regular code removes it.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // Differential power analysis
  // ---------------------------------------------------------------------------------------------------------------
  function dpa(inp) {
    const key = V.key(inp.key), b = +inp.byte, bit = +inp.bit, N = +inp.n, sigma = +inp.sigma;
    const ch = C().source({ key, sigma, seed: +inp.seed }).next(N), D = C().DPA({ byte: b, T: 52, bit }).add(ch);
    const diff = D.diff(), r = D.result(key[b]), kb = key[b], ts = C().sampleOf(b, 'sbox');
    const wrong = r.ranking.find((g) => g !== kb);
    // the same measurement on a masked device, for the defence
    const mch = C().source({ key, sigma, seed: +inp.seed, masked: true }).next(N), MD = C().DPA({ byte: b, T: 52, bit }).add(mch);
    const mdiff = MD.diff(), mr = MD.result(kb);
    const F = new S.Frames();
    const head = U.t('dp:h', 20, 30, `A difference of means on key byte ${b}, bit ${bit} of the S-box output, ${N} traces, σ = ${sigma}`, 'strong', 'start', 16);
    let top = 0; for (const v of diff) top = Math.max(top, Math.abs(v));
    top = Math.max(0.2, Math.ceil(top * 12) / 10);
    const pl = V.tracePlot({ prefix: 'dp:p', x: 70, y: 70, w: 820, h: 250, yr: [-top, top], yticks: [-top / 2, 0, top / 2], fy: (v) => fx(v, 2), zero: true, ylabel: 'mean(bit = 1) − mean(bit = 0)', xlabel: 'time sample' });
    const curve = (d, g, cls, key2) => pl.trace(key2, d.subarray(g * 52, g * 52 + 52), cls);
    const allOthers = (d, k2) => { let p = ''; for (let g = 0; g < 256; g++) { if (g === kb) continue; for (let t = 0; t < 52; t++) p += (t ? 'L' : 'M') + pl.X(t) + ',' + pl.Y(Math.max(-top, Math.min(top, d[g * 52 + t]))) + ' '; } return { key: k2, kind: 'path', d: p, cls: 'dline faint', audit: 'ignore', layer: 'back' }; };
    const note = (k2, y, text, cls) => U.t(k2, 70, y, text, cls || 'strong', 'start', 15);
    const facts0 = { b, bit, N, sigma, kb: h2(kb), ts, others: 255, peak: r.peaks[kb], wrong: h2(wrong), wpeak: r.peaks[wrong], rank: r.rank + 1, mpeak: mr.peaks[kb], mrank: mr.rank + 1 };
    F.add({ items: [head, ...pl.items, pl.shade(b, 'sbox', 'hot'), note('dp:n0', 380, `sample ${ts}: the chip handles S(p${U.sub(b)} ⊕ k${U.sub(b)})`)], hl: { d: [0] }, say: `Sort the traces into two piles by bit ${bit} of the value S(p${U.sub(b)} ⊕ k${U.sub(b)}) the chip really handled, and subtract the mean trace of one pile from the other's. Where the chip handles that value, at sample ${ts}, the two piles drew different power on average; everywhere else the split is random and the difference is only noise.`, facts: facts0, meta: { stage: 'idea' } });
    F.add({ items: [head, ...pl.items, pl.shade(b, 'sbox', 'hot'), curve(diff, kb, 'hot', 'dp:k'), note('dp:n1', 380, `a spike of ${fx(diff[kb * 52 + ts], 3)} at sample ${ts}: the leak`, 'hot')], hl: { d: [1] }, say: `With the true key byte ${h2(kb)}: the difference of means spikes at sample ${ts} with ${fx(diff[kb * 52 + ts], 3)}, about the weight of one bit, standing well above the noise elsewhere. That spike is the device leaking one bit of a value that depends on the key.`, facts: Object.assign({ at: diff[kb * 52 + ts] }, facts0), meta: { stage: 'right' } });
    F.add({ items: [head, ...pl.items, allOthers(diff, 'dp:all'), curve(diff, kb, 'hot', 'dp:k'), note('dp:n2', 380, `true byte: peak ${fx(r.peaks[kb], 3)}; the highest of the other 255: ${fx(r.peaks[wrong], 3)}`, r.rank === 0 ? 'hot' : 'strong')], hl: { d: [2] }, say: `Split by any of the other 255 values of the byte instead and the piles are random with respect to what the chip did: 255 grey curves of noise, the highest reaching ${fx(r.peaks[wrong], 3)} against ${fx(r.peaks[kb], 3)} for the true byte. ${r.rank === 0 ? 'Only the true byte leaves a spike, so with this many traces the measurement exposes the key byte, and the other 15 bytes leak the same way.' : `With this few traces the true byte's spike is not yet the highest (${r.rank} others stand above it); more traces would make it so. The leak is there either way.`}`, facts: Object.assign({ above: r.rank }, facts0), meta: { stage: 'all', rank: r.rank } });
    F.add({ items: [head, ...pl.items, pl.shade(b, 'sbox', 'good'), allOthers(mdiff, 'dp:mall'), curve(mdiff, kb, 'good', 'dp:mk'), note('dp:n3', 380, `masked device: true byte's peak ${fx(mr.peaks[kb], 3)}, ranked ${mr.rank + 1} of 256`, 'good')], hl: { d: [3] }, say: `The defence: the same measurement over ${N} traces of a masked device, which holds S(x) ⊕ m with a fresh random m every run. Bit ${bit} of what it handles is now a coin toss whatever the key, so the spike is gone: the true byte's curve peaks at only ${fx(mr.peaks[kb], 3)} and ranks ${mr.rank + 1} of 256, lost among the others.`, facts: facts0, meta: { stage: 'masked', rank: mr.rank } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Difference of means (DPA)', ['split the traces by bit j of S(pᵢ ⊕ k)', 'Δ(t) = mean of pile 1 − mean of pile 0', 'true k: a spike where S(pᵢ ⊕ k) is handled', 'any other value: noise only, so the key stands out', 'defence: masking makes bit j a coin toss; shuffling moves the spike']) };
  }
  S.topic({
    id: 'sc-dpa', family: 'p15-power', order: 40, title: 'DPA: a difference of means',
    blurb: 'Sort the traces into two piles by one bit of the S-box output and subtract their averages: where the chip handled that bit, a spike appears. Only the true key byte sorts them that way, which is why masking, which makes the bit a coin toss, takes the spike away.',
    inputs: [
      { id: 'key', kind: 'text', label: 'AES key (16 characters)', def: 'harbour-lights-7', check: V.keyCheck },
      { id: 'byte', kind: 'number', label: 'Key byte', def: 0, min: 0, max: 15 },
      { id: 'bit', kind: 'number', label: 'Bit of S(p ⊕ g)', def: 0, min: 0, max: 7 },
      { id: 'n', kind: 'choice', label: 'Traces', def: '1000', options: ['200', '500', '1000', '2000'].map((v) => ({ value: v, label: v })) },
      sigmaOpt(['0.5', '1', '2'], '1'),
      { id: 'seed', kind: 'number', label: 'Seed', def: 5, min: 1, max: 999 },
    ],
    presets: [
      { label: 'Byte 0, 1000 traces', values: { byte: 0, n: '1000', sigma: '1' } },
      { label: 'Byte 7, bit 3', values: { byte: 7, bit: 3, n: '1000', sigma: '1' } },
      { label: 'Too few traces', values: { byte: 0, n: '200', sigma: '2' } },
      { label: 'Little noise', values: { byte: 12, n: '500', sigma: '0.5' } },
    ],
    run: dpa,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'idea', pick: 'option', options: (fr) => { const s = fr[0].facts.ts; return [String(s - 2), String(s - 1), String(s), '50']; }, ask: 'At which sample will the difference of means show its spike?', answer: (fr) => String(fr[0].facts.ts), explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'The difference of means spikes where…', options: ['the trace is loudest', 'the chip handles the value whose bit the traces were sorted by', 'the plaintext is loaded', 'nowhere'], answer: 1, why: 'Only there do the two piles differ in what the chip did.' },
      { q: 'Split by a value other than the true key byte, the difference of means is…', options: ['a spike', 'mostly noise around 0', 'negative everywhere', 'the same'], answer: 1, why: 'The piles are a random split with respect to the real data.' },
      { q: 'What happens to the spike as traces are added?', options: ['It shrinks', 'It stays, while the noise of the difference shrinks like 1/√N', 'It moves', 'It disappears'], answer: 1, why: 'Averaging reduces the noise, not the real difference.' },
      { q: 'Why does masking remove the spike?', options: ['It slows the chip', 'The value handled is XORed with a fresh random mask, so each of its bits is a coin toss whatever the key', 'It hides the plaintext', 'It does not'], answer: 1, why: 'Sorting by a bit of S(p ⊕ k) no longer sorts by anything the chip did.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
