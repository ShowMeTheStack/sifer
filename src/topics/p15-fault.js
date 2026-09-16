// Part 15, faults and defences: one glitch in RSA-CRT signing makes the signature wrong modulo one prime only, which
// is enough to expose a factor of the modulus, and the check before release that stops it; and a map of the side
// channels of this part against the defences that stop them, each defence shown working.
(function (S) {
  'use strict';
  const U = S.P14, V = S.P15, C = () => S.SC;
  const short = (v) => { const s = v.toString(); return s.length > 22 ? s.slice(0, 8) + '…' + s.slice(-8) : s; };

  // ---------------------------------------------------------------------------------------------------------------
  // A fault on RSA-CRT
  // ---------------------------------------------------------------------------------------------------------------
  function fault(inp) {
    const Fa = C().Fault, key = Fa.key({ bits: +inp.bits, seed: +inp.seed, own: true }), n = key.n, e = key.e;
    const bytes = new TextEncoder().encode(inp.msg);
    let m = 0n; for (const b of bytes) m = (m * 256n + BigInt(b)) % n;
    const good = Fa.sign(key, m), bad = Fa.sign(key, m, { fault: { half: inp.half, bit: +inp.bit }, check: inp.check === 'yes' });
    const F = new S.Frames();
    const digits = n.toString().length;
    const head = U.t('fa:h', 20, 30, `RSA-CRT signing with a ${inp.bits}-bit modulus (${digits} digits), and one glitch`, 'strong', 'start', 16);
    const flow = (o) => {
      const N = S.Kit.flow.net('fa');
      N.box('m', 90, 170, 120, 44, 'm', 'val');
      N.box('p', 330, 100, 220, 50, ['s_p = m^dp mod p', short(o.sp)], 'small ' + (o.faulty === 'p' ? 'bad' : 'act'));
      N.box('q', 330, 240, 220, 50, ['s_q = m^dq mod q', short(o.sq)], 'small ' + (o.faulty === 'q' ? 'bad' : 'key'));
      N.box('g', 590, 170, 160, 54, ['Garner: join', 'mod p and mod q'], 'small');
      N.box('s', 806, 170, 196, 44, o.released ? 's = ' + short(o.s) : 'nothing released', 'small ' + (o.released ? (o.faulty ? 'bad' : 'good') : 'good'));
      N.wire('a0', [N.port('m', 'e'), [170, 170]], {});
      N.wire('a', [[170, 170], [170, 100], N.port('p', 'w')], { head: true });
      N.wire('b', [[170, 170], [170, 240], N.port('q', 'w')], { head: true });
      N.dot(170, 170);
      N.wire('c', [N.port('p', 'e'), [480, 100], [480, 155], N.port('g', 'w', -0.55)], { head: true, cls: o.faulty === 'p' ? 'hot' : '' });
      N.wire('d', [N.port('q', 'e'), [480, 240], [480, 185], N.port('g', 'w', 0.55)], { head: true, cls: o.faulty === 'q' ? 'hot' : '' });
      N.wire('e', [N.port('g', 'e'), N.port('s', 'w')], { head: true });
      if (o.faulty) N.label('z', 330, o.faulty === 'p' ? 62 : 290, '⚡ bit ' + inp.bit + ' flipped', 'bad', 'middle', 15);
      return N.items;
    };
    const info = (rows) => U.readout('fa:r', 40, 330, 860, '', rows, { dy: 30 });
    // the engine quotes long numbers by their first and last eight digits and their length: all of those are facts
    const fv = (...vals) => vals.filter((v) => v !== null && v !== undefined).flatMap((v) => { const t = v.toString(); return [t, t.slice(0, 8), t.slice(-8), t.length]; });
    const facts0 = { bits: +inp.bits, digits, e: String(e), bit: +inp.bit, vals: fv(n, key.p, key.q, m, good.s, good.sp, good.sq, bad.s, bad.sp, bad.sq, (bad.trace.find((t) => t.kind === 'garner') || {}).s) };
    F.add({ items: [head, ...flow({ sp: good.sp, sq: good.sq, s: good.s, released: true }), ...info([['N = p · q', short(n)], ['p', short(key.p)], ['q', short(key.q)], ['dp = d mod (p − 1), dq = d mod (q − 1)', short(key.dp) + ', ' + short(key.dq)]])], hl: { d: [0] }, say: `A ${inp.bits}-bit RSA key, N = ${short(n)}. To sign fast, the signer works modulo p and modulo q separately, with the half-size exponents dp and dq, and joins the halves with the Chinese remainder theorem (Garner's formula): about four times faster than one exponentiation mod N.`, facts: Object.assign({ n: short(n), p: short(key.p), q: short(key.q) }, facts0), meta: { stage: 'key' } });
    F.add({ items: [head, ...flow({ sp: good.sp, sq: good.sq, s: good.s, released: true }), ...info([['message m', short(m)], ['signature s', short(good.s)], ['s^e mod N', short(Fa.modpow(good.s, e, n)), 'good'], ['equals m?', Fa.modpow(good.s, e, n) === m ? 'yes' : 'no', 'good']])], hl: { d: [1] }, say: good.trace.map((t) => t.say).join(' ') + ` Raised to e = ${e}, it gives m back.`, facts: Object.assign({ m: short(m), s: short(good.s), sp: short(good.sp), sq: short(good.sq) }, facts0), meta: { stage: 'good' } });
    const faulty = inp.half;
    F.add({ items: [head, ...flow({ sp: bad.sp, sq: bad.sq, s: bad.s, released: bad.released, faulty }), ...info(bad.released ? [['faulty signature s′', short(bad.s), 'bad'], ['s′ mod ' + (faulty === 'q' ? 'p' : 'q'), 'still right'], ['s′ mod ' + faulty, 'wrong', 'bad']] : [['the signer checks s′^e = m', 'it fails', 'good'], ['released', 'nothing', 'good']])], hl: { d: [2] }, say: bad.trace.slice(1).map((t) => t.say).join(' ') + (bad.released ? ` The released signature is right modulo ${faulty === 'q' ? 'p' : 'q'} and wrong modulo ${faulty}.` : ''), facts: Object.assign({ s: bad.released ? short(bad.s) : null, sp: short(bad.sp), sq: short(bad.sq) }, facts0), meta: { stage: 'fault', released: bad.released } });
    if (bad.released) {
      // the outcome is checked by the engine here, but its arithmetic is not drawn
      const at = Fa.attack({ n, e }, m, bad.s), ok = !!(at.ok && at.p * at.q === n);
      F.add({ items: [head, ...flow({ sp: bad.sp, sq: bad.sq, s: bad.s, released: true, faulty }), ...info([['what is public', 'the message m, N, e and the faulty s′'], ['what that gives away', ok ? 'the prime ' + (faulty === 'q' ? 'p' : 'q') + ', so N factors, so d' : 'nothing, this time', ok ? 'bad' : 'good'], ['the fix', 'check s′^e ≡ m before release', 'good']])], hl: { d: [3] }, say: ok ? `Because s′ is right modulo ${faulty === 'q' ? 'p' : 'q'} and wrong modulo ${faulty}, anyone who knows the message and the public key can extract the prime ${faulty === 'q' ? 'p' : 'q'} from this one signature with one cheap computation and no search at all: N is factored and the private key follows. The fix costs one exponentiation with the small public exponent: check s^e ≡ m before releasing s, and release nothing if it fails.` : 'This fault happened to leave the signature useless to an attacker, but most faults in one half do not; the check before release is still needed.', facts: facts0, meta: { stage: 'exposed', ok } });
    } else F.add({ items: [head, ...flow({ sp: bad.sp, sq: bad.sq, s: null, released: false, faulty }), ...info([['released', 'nothing', 'good'], ['for an attacker', 'nothing to work with', 'good']])], hl: { d: [4] }, say: 'With the check in place the faulty signature never leaves the device, so there is nothing to work with. The check costs one exponentiation with the small public exponent: cheap.', facts: facts0, meta: { stage: 'safe' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Faults in RSA-CRT signing', ['s_p = m^dp mod p, s_q = m^dq mod q; join by CRT', 'a fault in s_q only: s′ right mod p, wrong mod q', 'that asymmetry exposes p to anyone with m and the public key', 'defence: verify s^e ≡ m before release, release nothing on failure', 'and protect the check itself (check twice, fold it into the output)']) };
  }
  S.topic({
    id: 'sc-fault', family: 'p15-faults', order: 10, title: 'A fault on RSA-CRT reveals a factor',
    blurb: 'Signing with the Chinese remainder theorem computes the signature modulo p and modulo q separately. A glitch in one half gives a signature that is wrong modulo only one prime, which is enough to expose a factor of the modulus. The defence is cheap: verify the signature before releasing it.',
    inputs: [
      { id: 'bits', kind: 'choice', label: 'Modulus', def: '128', options: ['64', '128', '512'].map((v) => ({ value: v, label: v + ' bits' })) },
      { id: 'half', kind: 'choice', label: 'Glitch in', def: 'q', options: [{ value: 'q', label: 's_q' }, { value: 'p', label: 's_p' }] },
      { id: 'bit', kind: 'number', label: 'Bit flipped', def: 5, min: 0, max: 30 },
      { id: 'check', kind: 'choice', label: 'Signer', def: 'no', options: [{ value: 'no', label: 'releases s at once' }, { value: 'yes', label: 'checks s^e = m first' }] },
      { id: 'msg', kind: 'text', label: 'Message', def: 'invoice 4417 paid', check: (v) => (!v || v.length > 40 ? 'Message: 1 to 40 characters' : null) },
      { id: 'seed', kind: 'number', label: 'Key seed', def: 77, min: 1, max: 999 },
    ],
    presets: [
      { label: '128 bits, glitch in s_q', values: { bits: '128', half: 'q', check: 'no' } },
      { label: '512 bits, glitch in s_p', values: { bits: '512', half: 'p', bit: 17, check: 'no' } },
      { label: 'With the check', values: { bits: '128', half: 'q', check: 'yes' } },
      { label: '64 bits', values: { bits: '64', half: 'q', bit: 0, seed: 12 } },
    ],
    run: fault,
    predict: [{ at: (f) => f.meta && f.meta.stage === 'fault' && f.meta.released, pick: 'option', options: ['no: it is just a wrong signature', 'yes: it exposes a factor of N'], ask: 'Is this one wrong signature of any use to someone who knows m and the public key?', answer: (fr, i) => (fr[i + 1].meta.ok ? 'yes: it exposes a factor of N' : 'no: it is just a wrong signature'), explain: (fr, i) => fr[i + 1].say }],
    quiz: [
      { q: 'Why is one faulty CRT signature so dangerous?', options: ['It reveals d directly', 'It is right modulo one prime and wrong modulo the other, and that asymmetry exposes the prime', 'It is random', 'It is not'], answer: 1, why: 'With the message and the public key, the prime falls out with no search.' },
      { q: 'What does the attacker need besides the faulty signature?', options: ['The private key', 'The message m and the public key', 'A correct signature only', 'Nothing'], answer: 1, why: 'With deterministic padding the message is known; that is all.' },
      { q: 'The simplest defence is to…', options: ['use bigger keys', 'verify s^e ≡ m before releasing s', 'use a smaller e', 'sign twice'], answer: 1, why: 'A faulty signature then never leaves the device.' },
      { q: 'How are faults injected in practice?', options: ['By guessing', 'Voltage or clock glitches, lasers, electromagnetic pulses', 'By the network', 'By the compiler'], answer: 1, why: 'Physical access lets an attacker disturb a computation at a chosen moment.' },
      { q: 'A single glitch could also skip the check itself. What hardened code does about that…', options: ['nothing', 'checks twice, or folds the check into the output so a skipped check spoils the result', 'removes the check', 'signs twice'], answer: 1, why: 'A check that one fault can jump over is only half a defence.' },
    ],
  });

  // ---------------------------------------------------------------------------------------------------------------
  // A map of defences
  // ---------------------------------------------------------------------------------------------------------------
  function defences(inp) {
    const key = V.key(inp.key);
    const ATT = [
      { id: 'spa', name: 'SPA', sub: 'one trace', y: 110 },
      { id: 'cpa', name: 'DPA and CPA', sub: 'many traces', y: 196 },
      { id: 'ho', name: 'higher order', sub: 'combine samples', y: 282 },
      { id: 'cache', name: 'cache timing', sub: 'lines touched', y: 368 },
      { id: 'time', name: 'timing', sub: 'early exits', y: 454 },
      { id: 'fault', name: 'fault injection', sub: 'glitches', y: 540 },
    ];
    const DEF = [
      { id: 'always', name: 'regular code', sub: 'multiply always, ladder', y: 110, against: ['spa'] },
      { id: 'mask', name: 'masking', sub: 'random shares', y: 196, against: ['cpa', 'ho'] },
      { id: 'noise', name: 'noise and shuffling', sub: 'raise the trace count', y: 282, against: ['cpa', 'ho'] },
      { id: 'ct', name: 'constant time', sub: 'no secret branches', y: 368, against: ['time', 'spa'] },
      { id: 'noaddr', name: 'no secret addresses', sub: 'bitsliced, AES-NI', y: 454, against: ['cache'] },
      { id: 'check', name: 'check before release', sub: 'and redundancy', y: 540, against: ['fault'] },
    ];
    // each defence shown working, by the engines
    const ev = {};
    { const tr = C().spaTrace(46499n, { seed: 4, sigma: 0.1, always: true }), rd = C().spaRead(tr.samples); ev.spa = `SPA on multiply-always reads ${rd.bits} for the exponent ${tr.bits}`; ev.spaF = { got: rd.bits, want: tr.bits }; }
    { const src = C().source({ key, sigma: 1, seed: 3, masked: true }), r = C().CPA({ byte: 0, T: 52 }).add(src.next(1000)).result(key[0]); ev.cpa = `first-order CPA on 1000 masked traces ranks the true byte ${r.rank + 1} of 256`; ev.cpaF = { rank: r.rank + 1 }; }
    { const src = C().source({ key, sigma: 1, seed: 3, masked: true }), c2 = C().CPA({ byte: 0, T: 1 }); for (let i = 0; i < 4; i++) c2.add(C().secondOrder(src.next(250), 1, C().sampleOf(0, 'sbox'))); const r = c2.result(key[0]); ev.ho = `but a second-order attack on the same 1000 ranks it ${r.rank + 1}: one mask is not the end`; ev.hoF = { rank: r.rank + 1 }; }
    { const a = C().Cache.attack({ key, samples: 2000, seed: 2, rounds: 'first' }); ev.cache = `evict+time on T-table AES recovers ${a.correct.filter(Boolean).length} of 16 high nibbles; with no secret-dependent addresses there is nothing to time`; ev.cacheF = { n: a.correct.filter(Boolean).length }; }
    { const o = C().Timing.oracle({ len: 4, seed: 31, constantTime: true }), r = C().Timing.recover(o, { reps: 5 }); ev.time = `against a constant-time comparison the byte-at-a-time attack ${r.ok ? 'still succeeds' : 'fails'}, after ${o.calls} queries`; ev.timeF = { calls: o.calls }; }
    { const k = C().Fault.key({ bits: 128, seed: 77, own: true }), s = C().Fault.sign(k, 12345n, { fault: { half: 'q', bit: 5 }, check: true }); ev.fault = `with the check, a glitched RSA-CRT signature is ${s.released ? 'released' : 'never released'}`; ev.faultF = { m: 12345 }; }
    const focus = inp.focus;
    const groups = { power: ['spa', 'cpa', 'ho'], timing: ['cache', 'time'], faults: ['fault'], all: ATT.map((a) => a.id) };
    const order = groups[focus];
    const F = new S.Frames();
    const head = U.t('df:h', 20, 30, 'Side channels and their defences', 'strong', 'start', 16);
    const map = (lit) => {
      const N = S.Kit.flow.net('df');
      N.label('la', 160, 64, 'attacks', 'title', 'middle');
      N.label('ld', 740, 64, 'defences', 'title', 'middle');
      for (const a of ATT) N.box('a' + a.id, 160, a.y, 220, 56, [a.name, a.sub], 'small ' + (lit === a.id ? 'bad' : order.includes(a.id) ? '' : 'soft'));
      for (const d of DEF) N.box('d' + d.id, 740, d.y, 260, 56, [d.name, d.sub], 'small ' + (lit && d.against.includes(lit) ? 'good' : 'soft'));
      DEF.forEach((d, k) => d.against.forEach((a, j) => {
        const on = lit === a;
        N.wire(a + '-' + d.id, [N.port('a' + a, 'e'), N.port('d' + d.id, 'w')], { cls: 'hop ' + (on ? 'act' : 'faint') });
      }));
      return N.items;
    };
    F.add({ items: [head, ...map(null)], hl: { d: [0] }, say: `The attacks of this part on the left, the defences on the right, and a line for each defence that answers an attack. ${focus === 'all' ? 'We go through all six.' : 'We look at the ' + focus + ' attacks.'} Each time, the defence is shown working by running the attack against it.`, facts: { six: 6 }, meta: { stage: 'map' } });
    for (const a of order) {
      const A = ATT.find((x) => x.id === a), ds = DEF.filter((d) => d.against.includes(a)).map((d) => d.name);
      F.add({ items: [head, ...map(a), U.t('df:ev', 20, 610, ev[a], 'strong', 'start', 14)], hl: { d: [1] }, say: `${A.name}: defended by ${ds.join(' and ')}. Run against it: ${ev[a]}.`, facts: ev[a + 'F'], meta: { stage: a } });
    }
    F.add({ items: [head, ...map(null)], hl: { d: [2] }, say: 'No single defence covers every channel, and each has a price: constant time costs speed, masking costs randomness and code size, checks cost an extra operation. Real devices stack them, and are tested by trying the attacks, as this part has done.', facts: {}, meta: { stage: 'end' } });
    U.fix(F.list);
    return { frames: F.list, def: U.def('Defence in depth', ['remove the leak: constant time, no secret addresses', 'randomise what leaks: masking, blinding', 'drown it: noise and shuffling (raises the trace count)', 'detect tampering: checks, redundancy, sensors', 'test by attacking: SPA, CPA, timing, faults']) };
  }
  S.topic({
    id: 'sc-defences', family: 'p15-faults', order: 20, title: 'Defences, drawn as a map',
    blurb: 'Every attack of this part against the defences that answer it: regular code against SPA, masking and noise against DPA, constant time against timing, no secret addresses against caches, checks against faults.',
    inputs: [
      { id: 'focus', kind: 'choice', label: 'Show', def: 'all', options: [{ value: 'all', label: 'every attack' }, { value: 'power', label: 'power attacks' }, { value: 'timing', label: 'timing attacks' }, { value: 'faults', label: 'fault attacks' }] },
      { id: 'key', kind: 'text', label: 'AES key (16 characters)', def: 'harbour-lights-7', check: (v) => S.P15.keyCheck(v) },
    ],
    presets: [{ label: 'Everything', values: { focus: 'all' } }, { label: 'Power', values: { focus: 'power' } }, { label: 'Timing', values: { focus: 'timing' } }, { label: 'Faults', values: { focus: 'faults' } }],
    run: defences,
    predict: [{ at: (f, i, fr) => f.meta && f.meta.stage === 'map' && fr[i + 1].meta.stage === 'spa', pick: 'option', options: ['masking', 'regular code (multiply always)', 'a check before release'], ask: 'Which defence answers simple power analysis?', answer: 'regular code (multiply always)', explain: (fr, i) => fr[i + 1].say }, { at: (f, i, fr) => f.meta && f.meta.stage === 'map' && fr[i + 1].meta.stage !== 'spa', pick: 'option', options: ['yes', 'no'], ask: 'Does any one defence cover every attack on the map?', answer: 'no', explain: 'Each defence answers one or two channels; devices stack them.' }],
    quiz: [
      { q: 'Masking mainly defends against…', options: ['fault attacks', 'DPA and CPA', 'cache timing', 'brute force'], answer: 1, why: 'It makes each value handled independent of the secret.' },
      { q: 'Adding noise to the power trace…', options: ['stops CPA', 'raises the number of traces CPA needs', 'stops SPA only', 'does nothing'], answer: 1, why: 'Averaging still wins, at a higher cost.' },
      { q: 'Which defence answers fault attacks on RSA-CRT?', options: ['Constant time', 'Checking the result before release', 'Masking', 'Longer keys'], answer: 1, why: 'A faulty result is caught before it can be used.' },
      { q: 'Bitsliced AES helps against…', options: ['cache timing, since it has no secret-dependent table addresses', 'faults', 'brute force', 'Shor\'s algorithm'], answer: 0, why: 'It computes the S-box with logic operations instead of lookups.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
