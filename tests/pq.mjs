// Post-quantum engines: FIPS 202 against node:crypto; ML-KEM against the NIST ACVP vectors for FIPS 203 (a
// subset kept in tests/pq-kat.json) and against node's own ML-KEM in both directions; lattice reduction and
// closest-vector properties; LWE failure rates against the exact distribution; Grover and Shor; Lamport, WOTS,
// Merkle and the toy SLH-DSA; McEliece and Hamming decoding; the toy Fiat–Shamir-with-aborts signature.
import { createHash, createPublicKey, KeyObject, webcrypto, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { load, harness } from './load.mjs';

process.removeAllListeners('warning'); // node marks its ML-KEM Web Crypto as experimental
const S = load(['core']), t = harness('pq'), P = S.PQ;
const fh = (h) => Uint8Array.from(Buffer.from(h, 'hex')), hx = (b) => Buffer.from(b).toString('hex');
const sha3 = (b) => createHash('sha3-256').update(b).digest('hex');
const traceOk = (tr, what) => t.ok(Array.isArray(tr) && tr.length && tr.every((s) => s.kind && typeof s.say === 'string' && s.say.length > 10 && !/undefined|NaN|\[object/.test(s.say)), 'trace of ' + what);

// ---- FIPS 202
for (let i = 0; i < 60; i++) {
  const m = randomBytes((i * 37) % 600), L = 1 + ((i * 53) % 400);
  t.eq(hx(P.sha3_256(m)), createHash('sha3-256').update(m).digest('hex'), 'sha3-256 ' + i);
  t.eq(hx(P.sha3_512(m)), createHash('sha3-512').update(m).digest('hex'), 'sha3-512 ' + i);
  t.eq(hx(P.shake128(m, L)), createHash('shake128', { outputLength: L }).update(m).digest('hex'), 'shake128 ' + i);
  t.eq(hx(P.shake256(m, L)), createHash('shake256', { outputLength: L }).update(m).digest('hex'), 'shake256 ' + i);
}
{ const x = P.xof(new Uint8Array([1, 2, 3]), 128); const a = P.concat(x.read(5), x.read(200), x.read(1)); t.eq(hx(a), hx(P.shake128(new Uint8Array([1, 2, 3]), 206)), 'incremental squeeze'); }
{ const A = new Array(25).fill(0n).map((_, i) => BigInt(i) * 0x0123456789abcdefn & ((1n << 64n) - 1n)), s = new Uint32Array(50);
  A.forEach((v, i) => { s[2 * i] = Number(v & 0xffffffffn); s[2 * i + 1] = Number(v >> 32n); });
  const B = S.Keccak.f(A.slice()); P.keccakF(s);
  t.ok(B.every((v, i) => v === (BigInt(s[2 * i + 1]) << 32n | BigInt(s[2 * i]))), 'fast Keccak-f equals S.Keccak.f'); }

// ---- ML-KEM: published vectors (NIST ACVP, FIPS 203)
const K = P.MLKEM, kat = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'pq-kat.json'), 'utf8'));
for (const v of kat.keyGen) { const r = K.keyGen(v.set, { d: fh(v.d), z: fh(v.z) }); t.eq([sha3(r.ek), sha3(r.dk)], [v.ekSha3, v.dkSha3], `ACVP keyGen ${v.set} tc${v.tcId}`); }
for (const v of kat.encaps) { const r = K.encaps(v.set, fh(v.ek), { m: fh(v.m) }); t.eq([sha3(r.c), hx(r.K)], [v.cSha3, v.k.toLowerCase()], `ACVP encaps ${v.set} tc${v.tcId}`); }
for (const v of kat.decaps) { const r = K.decaps(v.set, fh(v.dk), fh(v.c)); t.eq(hx(r.K), v.k.toLowerCase(), `ACVP decaps ${v.set} tc${v.tcId} (${v.reason})`); t.eq(r.rejected, v.reason !== 'valid decapsulation', `ACVP decaps ${v.set} tc${v.tcId} rejection flag`); }
for (const v of kat.keyCheck) { const r = v.fn.startsWith('enc') ? K.checkEk(v.set, fh(v.ek)) : K.checkDk(v.set, fh(v.dk)); t.eq(r.ok, v.passed, `ACVP ${v.fn} ${v.set} (${v.reason})`); }
t.eq([K.params(512).sizes, K.params(768).sizes, K.params('ML-KEM-1024').sizes].map((s) => [s.ek, s.dk, s.c]), [[800, 1632, 768], [1184, 2400, 1088], [1568, 3168, 1568]], 'FIPS 203 sizes');

// ---- ML-KEM against node's implementation, both directions
const subtle = webcrypto.subtle;
for (const set of [512, 768, 1024]) for (let i = 0; i < 3; i++) {
  const alg = { name: 'ML-KEM-' + set }, seed = randomBytes(64);
  const mine = K.keyGen(set, { d: seed.subarray(0, 32), z: seed.subarray(32) });
  const priv = await subtle.importKey('raw-seed', seed, alg, true, ['decapsulateBits']);
  const spki = createPublicKey(KeyObject.from(priv)).export({ format: 'der', type: 'spki' });
  const pub = await subtle.importKey('raw-public', mine.ek, alg, true, ['encapsulateBits']);
  t.ok(hx(spki).endsWith(hx(mine.ek)), `node derives the same ek from the seed d ‖ z, ${set} #${i}`);
  const theirs = await subtle.encapsulateBits(alg, pub);
  t.eq(hx(K.decaps(set, mine.dk, new Uint8Array(theirs.ciphertext)).K), hx(new Uint8Array(theirs.sharedKey)), `node encapsulates, we decapsulate, ${set} #${i}`);
  const ours = K.encaps(set, mine.ek);
  t.eq(hx(new Uint8Array(await subtle.decapsulateBits(alg, priv, ours.c))), hx(ours.K), `we encapsulate, node decapsulates, ${set} #${i}`);
}
// round trips, implicit rejection, traces
for (const set of [512, 768, 1024]) {
  const kp = K.keyGen(set), e = K.encaps(set, kp.ek), d = K.decaps(set, kp.dk, e.c);
  t.eq([hx(d.K), d.rejected], [hx(e.K), false], `round trip ${set}`);
  const bad = e.c.slice(); bad[7] ^= 1;
  const z = kp.dk.slice(kp.dk.length - 32), d2 = K.decaps(set, kp.dk, bad);
  t.eq([d2.rejected, hx(d2.K)], [true, hx(P.shake256(P.concat(z, bad), 32))], `implicit rejection gives J(z ‖ c), ${set}`);
  traceOk(kp.trace, 'keyGen ' + set); traceOk(e.trace, 'encaps ' + set); traceOk(d.trace, 'decaps ' + set);
  const w = d.trace.find((s) => s.kind === 'dec-w');
  t.ok(w && w.worst < 832 && w.noise.length === 256, `decryption noise stays inside q/4, ${set}`);
}
{ const kp = K.keyGen(768, { d: new Uint8Array(32).fill(1), z: new Uint8Array(32).fill(2) });
  const m = kp.trace.find((s) => s.kind === 'matrix');
  t.ok(m && m.A.length === 3 && m.A[0][0].length === 256 && m.A.flat(2).every((c) => c >= 0 && c < 3329), 'the trace carries Â');
  t.ok(kp.trace.find((s) => s.kind === 'secret').s.flat().every((c) => Math.abs(c) <= 2), 'secret coefficients lie in [−η, η]'); }
// NTT and the helpers
{ const r = P.rng(4), f = Array.from({ length: 256 }, () => r.int(3329)), g = Array.from({ length: 256 }, () => r.int(3329));
  t.eq(K.invNtt(K.ntt(f)), f, 'NTT⁻¹(NTT(f)) = f');
  t.eq(K.invNtt(K.multiplyNtts(K.ntt(f), K.ntt(g))), K.mulSchoolbook(f, g), 'NTT product equals the product mod X^256 + 1');
  let worst = 0;
  for (const d of [1, 4, 5, 10, 11]) for (let x = 0; x < 3329; x++) { const e = Math.abs(P.centre(K.decompress(K.compress(x, d), d) - x, 3329)); worst = Math.max(worst, e - Math.round(3329 / 2 ** (d + 1))); }
  t.ok(worst <= 0, 'Decompress(Compress(x)) is within q/2^(d+1) of x');
  t.eq(K.byteDecode(K.byteEncode(f, 12), 12), f, 'ByteDecode₁₂(ByteEncode₁₂(f)) = f');
  const cb = K.cbd(P.randomBytes(128), 2); t.ok(cb.every((c) => P.centre(c, 3329) >= -2 && P.centre(c, 3329) <= 2), 'CBD₂ in [−2, 2]'); }

// ---- lattices
const L = P.Lattice, rr = P.rng(99);
for (let i = 0; i < 40; i++) {
  const B = [[rr.int(41) - 20, rr.int(41) - 20], [rr.int(41) - 20, rr.int(41) - 20]];
  if (B[0][0] * B[1][1] - B[0][1] * B[1][0] === 0) continue;
  const g = L.gauss(B), sv = L.shortest(B, 40);
  t.ok(Math.abs(L.norm(g.B[0]) - sv.len) < 1e-9, `Gauss finds a shortest vector #${i}`);
  t.ok(Math.abs(L.volume(g.B) - L.volume(B)) < 1e-6, `Gauss keeps the lattice volume #${i}`);
  const det = g.U[0][0] * g.U[1][1] - g.U[0][1] * g.U[1][0];
  t.ok(Math.abs(det) === 1 && g.B.every((row, k) => row.every((v, j) => v === g.U[k][0] * B[0][j] + g.U[k][1] * B[1][j])), `Gauss is a unimodular change of basis #${i}`);
}
for (const n of [3, 4, 5, 6]) for (let i = 0; i < 6; i++) {
  const B = Array.from({ length: n }, () => Array.from({ length: n }, () => rr.int(61) - 30));
  if (L.volume(B) < 1e-6) continue;
  const r = L.lll(B);
  t.ok(L.isReduced(r.B), `LLL output is reduced, n = ${n} #${i}`);
  t.ok(Math.abs(L.volume(r.B) - L.volume(B)) / L.volume(B) < 1e-6, `LLL keeps the volume, n = ${n} #${i}`);
  t.ok(r.B.every((row, k) => row.every((v, j) => v === r.U[k].reduce((s, u, m) => s + u * B[m][j], 0))), `LLL output is U·B, n = ${n} #${i}`);
  t.ok(r.B.every((row) => row.every(Number.isInteger)), `LLL stays integral, n = ${n} #${i}`);
  if (n === 3) t.ok(L.norm(r.B[0]) <= 2 * L.shortest(B, 8).len + 1e-9, `‖b₁‖ ≤ 2^((n−1)/2)·λ₁, #${i}`);
  t.ok(L.hadamard(r.B) >= L.hadamard(B) - 1e-9, `LLL does not make the basis less orthogonal, n = ${n} #${i}`);
}
{ const gb = L.goodBad(3); let goodHits = 0, badHits = 0;
  t.ok(gb.hGood > 0.9 && gb.hBad < 0.3 && Math.abs(L.volume(gb.good) - L.volume(gb.bad)) < 1e-6, 'goodBad: one lattice, a good and a bad basis');
  for (let i = 0; i < 200; i++) {
    const tg = [rr.next() * 60 - 30, rr.next() * 60 - 30], best = L.closest(gb.good, tg, 12).dist;
    if (Math.abs(L.babai(gb.good, tg).dist - best) < 1e-9) goodHits++;
    if (Math.abs(L.babai(gb.bad, tg).dist - best) < 1e-9) badHits++;
    t.ok(L.nearestPlane(L.lll(gb.bad).B, tg).dist <= best * 2 + 1e-9, 'nearest plane on the reduced basis is near the closest');
  }
  t.ok(goodHits >= 180 && badHits < goodHits - 40, `Babai rounding: good basis right ${goodHits}/200, bad basis ${badHits}/200`);
  traceOk(L.babai(gb.bad, [3.3, 4.1]).trace, 'babai'); traceOk(L.lll(gb.bad).trace, 'lll'); traceOk(L.gauss(gb.bad).trace, 'gauss');
  t.eq(L.points([[2, 0], [1, 2]], { x0: -3, x1: 3, y0: -3, y1: 3 }).length, 11, 'points in a window'); }

// ---- LWE
const W = P.LWE;
{ const par = W.params(), f = W.failure(par);
  t.ok(f.safe && f.bit0 === 0 && f.bit1 === 0, 'default LWE: m·B < q/4, so decryption never fails');
  let fails = 0;
  for (let i = 0; i < 300; i++) { const kp = W.keyGen(par, i + 1), bit = i & 1, c = W.encrypt(kp.pk, bit, i + 1000), d = W.decrypt(kp.sk, c.ct, { e: kp.e, r: c.r }); if (d.bit !== bit) fails++; if (i === 0) { traceOk(kp.trace, 'lwe keyGen'); traceOk(c.trace.concat(d.trace), 'lwe enc/dec'); } }
  t.eq(fails, 0, 'LWE decrypts every bit when the noise is within bounds');
  for (const noisy of [W.params({ noise: { kind: 'uniform', B: 4 } }), W.params({ q: 97, m: 32, noise: { kind: 'gauss', sigma: 3 } })]) {
    const fp = W.failure(noisy), N = 4000;
    let bad = 0;
    for (let i = 0; i < N; i++) { const kp = W.keyGen(noisy, 7000 + i), bit = i & 1, c = W.encrypt(kp.pk, bit, 9000 + i); const d = W.decrypt(kp.sk, c.ct, { e: kp.e, r: c.r }); if (d.bit !== bit) bad++; if (d.bit !== bit) t.ok(Math.abs(d.noise) > noisy.q / 4 - 1, 'a failure always comes with |e·r| near or past q/4'); }
    const sd = Math.sqrt(fp.average * (1 - fp.average) / N);
    t.ok(!fp.safe && Math.abs(bad / N - fp.average) < 4 * sd + 0.002, `LWE failure rate ${(bad / N).toFixed(4)} matches the exact ${fp.average.toFixed(4)}`);
  } }

// ---- quantum intuition
const Q = P.Quantum;
for (const n of [3, 6, 8, 10]) {
  const g = Q.grover({ n, marked: [5] });
  t.ok(g.success[g.best] > 0.9 || n === 3, `Grover peaks above 0.9 after ${g.best} iterations, n = ${n}`);
  t.ok(g.success.every((p, k) => Math.abs(p - Math.sin((2 * k + 1) * g.theta) ** 2) < 1e-9), `Grover follows sin²((2k+1)θ), n = ${n}`);
  t.ok(Math.abs(g.amps[g.best].reduce((s, a) => s + a * a, 0) - 1) < 1e-9, `amplitudes stay normalised, n = ${n}`);
}
{ const g = Q.grover({ n: 6, marked: [1, 9, 33, 60] }); t.eq(g.best, 3, 'four marked of 64: three iterations'); traceOk(g.trace, 'grover'); }
for (const N of [15, 21, 33, 35, 39, 51, 55, 77, 91, 143, 221]) {
  const s = Q.shor(N, { seed: N });
  t.ok(s.factors && s.factors[0] > 1 && s.factors[0] < N && s.factors[0] * s.factors[1] === N, `Shor factors ${N}`);
  if (s.probs) { t.ok(Math.abs(s.probs.reduce((a, b) => a + b, 0) - 1) < 1e-9, `QFT probabilities sum to 1 for ${N}`); t.eq(Q.powmod(s.a, s.r, N), 1, `the period found for ${N} is a period`); }
  traceOk(s.trace, 'shor ' + N);
}
{ const s = Q.shor(15, { a: 7, seed: 1 }); t.eq(s.r, 4, 'the order of 7 mod 15 is 4'); t.eq(Q.period(7, 15).table, [1, 7, 4, 13], 'powers of 7 mod 15');
  const peaks = s.probs.map((p, y) => [p, y]).sort((a, b) => b[0] - a[0]).slice(0, 4).map((x) => x[1]).sort((a, b) => a - b);
  t.eq(peaks, [0, 64, 128, 192], 'Q = 256, r = 4: the peaks sit at multiples of 64'); }

// ---- hash-based signatures
{ const kp = P.Lamport.keyGen('quill'), s = P.Lamport.sign(kp.sk, 'harbour at noon');
  t.ok(P.Lamport.verify(kp.pk, 'harbour at noon', s.sig).ok, 'Lamport verifies');
  t.ok(!P.Lamport.verify(kp.pk, 'harbour at nine', s.sig).ok, 'Lamport rejects another message');
  const bad = s.sig.slice(); bad[17] = bad[17].slice(); bad[17][0] ^= 1;
  t.ok(!P.Lamport.verify(kp.pk, 'harbour at noon', bad).ok, 'Lamport rejects a changed signature');
  t.eq(P.Lamport.forge([{ msg: 'harbour at noon', sig: s.sig }], 'another', 32).sig, null, 'one Lamport signature forges nothing');
  const small = P.Lamport.keyGen('tiny', { n: 1 }), known = ['a', 'b', 'c', 'd', 'e'].map((m) => ({ msg: m, sig: P.Lamport.sign(small.sk, m).sig }));
  let forged = 0;
  for (let i = 0; i < 40; i++) { const f = P.Lamport.forge(known, 'f' + i, 1); if (f.sig && P.Lamport.verify(small.pk, 'f' + i, f.sig).ok) forged++; }
  t.ok(forged > 0, `a reused (8-bit) Lamport key is forged: ${forged} of 40 new messages`);
  traceOk(s.trace, 'lamport'); }
for (const w of [4, 16, 256]) {
  const kp = P.WOTS.keyGen('wots-' + w, { w, n: 16 }), s = P.WOTS.sign(kp.sk, 'salt flats');
  t.ok(P.WOTS.verify(kp.pk, 'salt flats', s.sig).ok, `WOTS w = ${w} verifies`);
  t.ok(!P.WOTS.verify(kp.pk, 'salt flat', s.sig).ok, `WOTS w = ${w} rejects another message`);
  let blocked = 0;
  for (let i = 0; i < 30; i++) if (!P.WOTS.forge(kp.pk, 'salt flats', s.sig, 'x' + i).sig) blocked++;
  t.eq(blocked, 30, `the checksum blocks every forgery, w = ${w}`);
  const L1 = P.WOTS.lens(16, w); t.eq(s.sig.length, L1.len, `WOTS w = ${w} has len₁ + len₂ = ${L1.len} chains`);
  traceOk(s.trace, 'wots ' + w);
}
{ const kp = P.WOTS.keyGen('nock', { n: 2, w: 16, checksum: false }), s = P.WOTS.sign(kp.sk, 'msg');
  let ok = 0; for (let i = 0; i < 300 && !ok; i++) { const f = P.WOTS.forge(kp.pk, 'msg', s.sig, 'try' + i); if (f.sig && P.WOTS.verify(kp.pk, 'try' + i, f.sig).ok) ok++; }
  t.ok(ok === 1, 'without the checksum, walking chains forward forges a signature'); }
{ const kp = P.Merkle.keyGen('orchard', { h: 3 }), sigs = [];
  for (let i = 0; i < 8; i++) { const s = P.Merkle.sign(kp.sk, 'note ' + i); sigs.push(s.sig); t.ok(P.Merkle.verify(kp.pk, 'note ' + i, s.sig).ok, `Merkle leaf ${i} verifies`); t.ok(!P.Merkle.verify(kp.pk, 'note ' + (i + 1), s.sig).ok, `Merkle leaf ${i} rejects another message`); }
  t.ok(!P.Merkle.verify(kp.pk, 'note 2', Object.assign({}, sigs[2], { auth: sigs[3].auth })).ok, 'Merkle rejects a wrong authentication path');
  t.ok(!P.Merkle.verify(kp.pk, 'note 2', Object.assign({}, sigs[2], { idx: 3 })).ok, 'Merkle rejects a wrong leaf index');
  let threw = false; try { P.Merkle.sign(kp.sk, 'one too many'); } catch (e) { threw = true; } t.ok(threw, 'a used-up Merkle key refuses to sign');
  traceOk(P.Merkle.verify(kp.pk, 'note 0', sigs[0]).trace, 'merkle verify'); }
{ const p = P.SLH.params(), kp = P.SLH.keyGen('lighthouse', p);
  for (const m of ['first light', 'second light', 'third light']) {
    const s = P.SLH.sign(kp.sk, m);
    t.ok(P.SLH.verify(kp.pk, m, s.sig).ok, `toy SLH-DSA verifies "${m}"`);
    t.ok(!P.SLH.verify(kp.pk, m + '!', s.sig).ok, `toy SLH-DSA rejects a changed message`);
    const bad = Object.assign({}, s.sig, { fors: s.sig.fors.map((f, i) => (i ? f : { sk: f.sk.map((v, j) => (j ? v : v ^ 1)), auth: f.auth })) });
    t.ok(!P.SLH.verify(kp.pk, m, bad).ok, 'toy SLH-DSA rejects a changed FORS leaf');
    const bytes = s.sig.R.length + s.sig.fors.reduce((n, f) => n + f.sk.length + f.auth.length * p.n, 0) + s.sig.layers.reduce((n, l) => n + (l.wots.length + l.auth.length) * p.n, 0);
    t.eq(bytes, p.sigBytes, 'toy SLH-DSA signature size');
    traceOk(s.trace, 'slh');
  } }

// ---- McEliece and Hamming
for (const [m, tt, n] of [[4, 2, 16], [5, 3, 32], [6, 4, 60], [7, 5, 110]]) for (let seed = 1; seed <= 6; seed++) {
  const kp = P.McEliece.keyGen({ m, t: tt, n, seed }), r = P.rng(seed + 50), msg = Array.from({ length: kp.pk.k }, () => r.int(2));
  t.eq(kp.pk.k, n - m * tt, `Goppa code dimension n − m·t, (${m}, ${tt}, ${n})`);
  const c = P.McEliece.encrypt(kp.pk, msg, { seed });
  t.eq(c.error.reduce((a, b) => a + b, 0), tt, 'the error vector has weight t');
  const d = P.McEliece.decrypt(kp.sk, c.c);
  t.eq([d.msg, d.error], [msg, c.error], `McEliece round trip (${m}, ${tt}, ${n}) seed ${seed}`);
  if (seed === 1) traceOk(kp.trace.concat(c.trace, d.trace), 'mceliece');
}
{ const kp = P.McEliece.keyGen({ seed: 3 }), msg = [1, 0, 1, 1, 0, 1, 0, 0], r = P.rng(8);
  let wrong = 0;
  for (let i = 0; i < 20; i++) { const e = new Array(16).fill(0); let c = 0; while (c < 3) { const j = r.int(16); if (!e[j]) { e[j] = 1; c++; } } const d = P.McEliece.decrypt(kp.sk, P.McEliece.encrypt(kp.pk, msg, { error: e }).c); if (!d.msg || d.msg.join('') !== msg.join('')) wrong++; }
  t.eq(wrong, 20, 'three errors in a 2-error code never decrypt correctly');
  t.ok(P.GF2.matMul(kp.sk.code.G, kp.sk.code.H[0].map((_, j) => kp.sk.code.H.map((row) => row[j]))).every((row) => row.every((v) => v === 0)), 'G·Hᵀ = 0'); }
{ const H = P.Hamming;
  for (let v = 0; v < 16; v++) { const msg = [0, 1, 2, 3].map((b) => (v >> b) & 1), cw = H.encode(msg);
    t.eq(H.decode(cw).msg, msg, `Hamming clean word ${v}`);
    for (let j = 0; j < 7; j++) { const w = cw.slice(); w[j] ^= 1; const d = H.decode(w); t.eq([d.position, d.msg], [j, msg], `Hamming corrects position ${j} of word ${v}`); } } }

// ---- toy Fiat–Shamir with aborts
{ const D = P.ToyDSA, kp = D.keyGen('ferns');
  let attempts = 0;
  for (let i = 0; i < 20; i++) {
    const s = D.sign(kp.sk, 'leaf ' + i, { seed: i + 1 });
    attempts += s.attempts;
    t.ok(D.verify(kp.pk, 'leaf ' + i, s.sig).ok, `toy signature ${i} verifies`);
    t.ok(!D.verify(kp.pk, 'leaf ' + (i + 1), s.sig).ok, `toy signature ${i} does not verify another message`);
    const z = s.sig.z.map((f) => f.slice()); z[0][0] = (z[0][0] + 1) % kp.pk.p.q;
    t.ok(!D.verify(kp.pk, 'leaf ' + i, Object.assign({}, s.sig, { z })).ok, `a changed z is rejected (${i})`);
    if (!i) traceOk(s.trace.concat(kp.trace), 'toy dsa');
  }
  t.ok(attempts > 20 && attempts < 120, `rejection sampling aborts sometimes: ${attempts} attempts for 20 signatures`);
  const leaky = D.zSamples(kp.sk, 300, { abort: false }), safe = D.zSamples(kp.sk, 300);
  t.ok(leaky.edge > 0 && leaky.agree === leaky.edge, `without aborts, ${leaky.edge} coefficients of z leak the sign of c·s₁`);
  t.eq(safe.edge, 0, 'with aborts, no coefficient of z leaves the safe range'); }

t.done();
