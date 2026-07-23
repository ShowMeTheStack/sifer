// Side-channel engines: the trace source (deterministic, chunk-friendly), CPA and DPA recovering planted key bytes,
// masking defeating first-order CPA (and a second-order attack beating the mask), SPA on square-and-multiply, the
// T-table cache model (its AES checked against node:crypto) and the evict+time attack, the timing oracle on a
// leaky tag comparison, and the RSA-CRT fault attack.
import { createCipheriv, randomBytes, generateKeyPairSync } from 'node:crypto';
import { load, harness } from './load.mjs';
const S = load(['core']), t = harness('sc'), C = S.SC;
const key = S.bytes.utf8('quiet-otter-1987');
const traceOk = (tr, what) => t.ok(Array.isArray(tr) && tr.length && tr.every((s) => s.kind && typeof s.say === 'string' && s.say.length > 10 && !/undefined|NaN|\[object/.test(s.say)), 'trace of ' + what);

// ---- the trace source
{ const a = C.source({ key, seed: 5 }), b = C.source({ key, seed: 5 });
  const one = a.next(300), parts = [b.next(100), b.next(150), b.next(50)];
  t.eq(Array.from(one.traces), parts.flatMap((p) => Array.from(p.traces)), 'chunks join to the same traces as one call');
  t.eq(Array.from(one.plaintexts), parts.flatMap((p) => Array.from(p.plaintexts)), 'and the same plaintexts');
  const cl = structuredClone(one);
  t.ok(cl.traces instanceof Float32Array && cl.traces.length === 300 * 52, 'a chunk is plain data a worker can post');
  const quiet = C.source({ key, seed: 1, sigma: 0 }).next(20);
  let exact = true;
  for (let n = 0; n < 20; n++) for (let bb = 0; bb < 16; bb++) { const p = quiet.plaintexts[n * 16 + bb]; if (quiet.traces[n * 52 + C.sampleOf(bb, 'sbox')] !== C.HW[S.gf256.SBOX[p ^ key[bb]]] || quiet.traces[n * 52 + C.sampleOf(bb, 'ark')] !== C.HW[p ^ key[bb]]) exact = false; }
  t.ok(exact, 'with no noise each sample is exactly the Hamming weight of its value');
  t.eq(C.layout().length, 52, 'the layout names all 52 samples'); }

// ---- CPA recovers planted key bytes; masking defeats it
for (const [byte, model] of [[0, 'hw'], [6, 'hw'], [15, 'hw'], [3, 'hd'], [11, 'hd']]) {
  const r = C.cpaRun({ source: C.source({ key, model, sigma: 3, seed: 10 + byte }), byte, key: key[byte], total: 800, chunk: 50 });
  t.eq(r.result.best, key[byte], `CPA (${model}) recovers key byte ${byte}`);
  t.ok(r.settled != null && r.settled <= 800, `the rank of byte ${byte} settles at 1 (after ${r.settled} traces)`);
  t.eq(r.result.peakSample, C.sampleOf(byte, 'sbox'), `the peak sits at the S-box sample of byte ${byte}`);
  if (!byte) { traceOk(r.trace, 'cpa'); t.ok(r.progress.length === 16 && r.progress.every((p) => p.rank >= 0), 'progress has a rank per chunk'); }
}
{ const noisy = C.cpaRun({ source: C.source({ key, sigma: 8, seed: 3 }), byte: 2, key: key[2], total: 3000, chunk: 100 });
  t.ok(noisy.progress[0].rank > 0 && noisy.result.rank === 0, `with heavy noise the key starts low (rank ${noisy.progress[0].rank + 1}) and climbs to 1 by ${noisy.settled} traces`); }
{ const r = C.cpaRun({ source: C.source({ key, sigma: 3, seed: 4 }), byte: 5, key: key[5], total: 30, chunk: 30 });
  t.ok(r.result.rank > 0, 'thirty noisy traces are not enough'); }
{ const src = C.source({ key, sigma: 1, seed: 6, masked: true }), n = 6000, ch = src.next(n);
  const cpa = C.CPA({ byte: 4 }).add(ch), r = cpa.result(key[4]), corr = cpa.corr();
  t.ok(r.rank !== 0, `masking: first-order CPA misses the key byte (rank ${r.rank + 1}) with ${n} low-noise traces`);
  t.ok(Math.abs(corr[key[4] * 52 + C.sampleOf(4, 'sbox')]) < 5 / Math.sqrt(n), 'masking: no correlation at the S-box sample');
  const plain = C.CPA({ byte: 4 }).add(C.source({ key, sigma: 1, seed: 6 }).next(200)).result(key[4]);
  t.eq(plain.rank, 0, 'the same device without the mask falls to 200 traces');
  const so = C.CPA({ byte: 4, T: 1 }).add(C.secondOrder(ch, 1, C.sampleOf(4, 'sbox'))).result(key[4]);
  t.eq(so.rank, 0, 'a second-order attack (mask sample × masked output) recovers the byte');
  for (const [mi, mo] of [[0x3c, 0xa5], [0, 0], [0xff, 0x01]]) {
    let all = true; for (let x = 0; x < 256; x++) if (C.maskedLookup(x, mi, mo).y !== S.gf256.SBOX[x]) all = false;
    t.ok(all, `the masked S-box unmasks to S(x) for masks ${mi}, ${mo}`);
  }
  traceOk(C.maskedLookup(0x53, 0x3c, 0xa5).trace, 'masked lookup'); }
{ const d = C.DPA({ byte: 9 }).add(C.source({ key, sigma: 2, seed: 12 }).next(2500)).result(key[9]);
  t.eq(d.best, key[9], 'DPA (difference of means) recovers key byte 9'); }

// ---- SPA
for (let i = 1; i <= 40; i++) {
  const e = BigInt('0x' + randomBytes(8).toString('hex')) | 1n, tr = C.spaTrace(e, { seed: i });
  t.eq(C.spaRead(tr.samples).exponent, e, `SPA reads exponent #${i}`);
  if (i === 1) traceOk(tr.trace.concat(C.spaRead(tr.samples).trace), 'spa');
}
{ const e = 0xb5a3n, tr = C.spaTrace(e, { seed: 2, always: true }), r = C.spaRead(tr.samples);
  t.ok(r.exponent !== e && /^1+$/.test(r.bits), 'square-and-multiply-always reads as all ones'); }
{ const tr = C.spaTrace(0xb5a3n, { seed: 3 });
  t.eq([tr.ops.filter((o) => o === 'S').length, tr.ops.filter((o) => o === 'M').length], [15, 8], '0xb5a3: fifteen squarings and eight multiplications'); }

// ---- cache timing
for (let i = 0; i < 40; i++) {
  const k = randomBytes(16), p = randomBytes(16), c = createCipheriv('aes-128-ecb', k, null).update(p);
  t.eq(Buffer.from(C.Cache.encrypt(k, p).ct).toString('hex'), c.toString('hex'), 'the T-table model encrypts as AES-128 #' + i);
}
{ const e = C.Cache.encrypt(key, randomBytes(16), { evict: { table: 2, line: 5 } });
  t.eq(e.lookups.length, 144, 'nine table rounds of sixteen lookups');
  t.eq(e.lookups.filter((l) => !l.hit).length, e.lookups.some((l) => l.table === 2 && l.line === 5) ? 1 : 0, 'the evicted line misses once, then stays');
  t.eq(e.cycles, 200 + 144 + 39 * e.lookups.filter((l) => !l.hit).length, 'cycles = base + hits + misses');
  const first = C.Cache.encrypt(key, new Uint8Array(16), { rounds: 'first' });
  t.eq(first.lookups.map((l) => l.index), Array.from(key), 'first-round indices are p ⊕ k'); }
{ const a = C.Cache.attack({ key, samples: 4000, rounds: 'first', seed: 2 });
  t.eq(a.nibbles, Array.from(key, (v) => v >> 4), 'evict+time on the first round recovers all 16 high nibbles');
  const b = C.Cache.attack({ key, samples: 24000, rounds: 'all', seed: 3 });
  t.ok(b.correct.filter(Boolean).length >= 15, `with all rounds adding noise, ${b.correct.filter(Boolean).length}/16 nibbles from 24000 runs`);
  traceOk(b.trace, 'cache attack'); }

// ---- timing oracle on a tag comparison
for (const seed of [1, 2, 3]) {
  const o = C.Timing.oracle({ seed, len: 8 }), r = C.Timing.recover(o);
  t.ok(r.ok && S.bytes.eq(r.tag, o.secret), `the timing oracle gives up the tag (seed ${seed})`);
  if (seed === 1) traceOk(r.trace, 'timing');
}
{ const o = C.Timing.oracle({ seed: 1, len: 6, constantTime: true }), r = C.Timing.recover(o);
  t.ok(!r.ok, 'a constant-time comparison does not leak the tag');
  const a = o.time(new Uint8Array(6)), b = o.time(o.secret); t.ok(Math.abs(a - b) < 20, 'constant time: a right tag takes as long as a wrong one'); }

// ---- RSA-CRT fault
{ const k = C.Fault.key({ bits: 512, seed: 5, own: true }), m = 0x5eed5eed1234n;
  t.ok(k.p * k.q === k.n && C.Fault.modpow(C.Fault.modpow(m, k.e, k.n), k.d, k.n) === m, 'the small RSA key works');
  const good = C.Fault.sign(k, m);
  t.eq(good.s, C.Fault.modpow(m, k.d, k.n), 'CRT signing equals m^d mod N');
  t.ok(!C.Fault.attack(k, m, good.s).ok, 'a correct signature reveals nothing');
  for (const half of ['p', 'q']) for (const bit of [0, 31, 200]) {
    const bad = C.Fault.sign(k, m, { fault: { half, bit } }), a = C.Fault.attack({ n: k.n, e: k.e }, m, bad.s);
    t.ok(bad.faulty && a.ok && a.p === (half === 'q' ? k.p : k.q), `a fault in s_${half} (bit ${bit}) factors N`);
  }
  const guarded = C.Fault.sign(k, m, { fault: { half: 'q', bit: 9 }, check: true });
  t.ok(guarded.s === null && !guarded.released, 'checking before release withholds the faulty signature');
  traceOk(C.Fault.sign(k, m, { fault: { half: 'q' } }).trace.concat(C.Fault.attack(k, m, good.s).trace), 'fault');
  // a node-made key, imported, falls the same way
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 }), j = privateKey.export({ format: 'jwk' });
  const big = (b64) => BigInt('0x' + Buffer.from(b64, 'base64url').toString('hex'));
  const nk = C.Fault.key({ key: { n: big(j.n), e: big(j.e), d: big(j.d), p: big(j.p), q: big(j.q) } });
  t.eq(nk.dp, big(j.dp), 'dp agrees with node'); t.eq(nk.qinv, big(j.qi), 'q⁻¹ mod p agrees with node');
  const f = C.Fault.sign(nk, 123456789n, { fault: { half: 'q', bit: 77 } });
  t.eq(C.Fault.attack(nk, 123456789n, f.s).p, nk.p, 'a node RSA-1024 key is factored by one fault'); }

t.done();
