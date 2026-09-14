// Part 14 claims: ML-KEM. Node's own ML-KEM (WebCrypto, from the 64-byte seed d ‖ z) decapsulates every
// ciphertext the topics show, tampered or not, and must give the key the topic quotes; the NTT is checked against
// reductions of f modulo X² − γᵢ worked out directly; compression against the formulas of FIPS 203 in rationals.
import { webcrypto, createHash } from 'node:crypto';
import { near } from './claims-lib-p14.mjs';

const { subtle } = webcrypto;
process.removeAllListeners('warning');
const q = 3329;
const hx = (b) => Buffer.from(b).toString('hex');
const shake = (tag, word, n = 32) => createHash('shake256', { outputLength: n }).update(tag + ':' + word).digest();
const pw = (b, e) => { let r = 1n, B = BigInt(b), E = BigInt(e); while (E) { if (E & 1n) r = (r * B) % 3329n; B = (B * B) % 3329n; E >>= 1n; } return Number(r); };
const br7 = (i) => parseInt(i.toString(2).padStart(7, '0').split('').reverse().join(''), 2);
/** Node decapsulates c with the key made from the seed word */
async function nodeDecaps(set, seedWord, c) {
  const alg = { name: 'ML-KEM-' + set };
  const seed = Buffer.concat([shake('d', seedWord), shake('z', seedWord)]);
  const priv = await subtle.importKey('raw-seed', seed, alg, false, ['decapsulateBits']);
  return hx(new Uint8Array(await subtle.decapsulateBits(alg, priv, c)));
}
/** the ciphertext a topic shows: Bob's c from our engine, tampered as the input says */
function cipher(S, input, kind) {
  const K = S.PQ.MLKEM, p = K.params(input.set), kg = K.keyGen(input.set, { d: shake('d', input.seed), z: shake('z', input.seed) });
  const en = K.encaps(input.set, kg.ek, { m: shake('m', input.msg) }), c = Uint8Array.from(en.c);
  if (kind === 'flow' && input.tamper === 'yes') c[c.length - 1] ^= 0x10;
  if (kind === 'reject' && input.where !== 'none') { const c1 = 32 * p.du * p.k, at = input.where === 'u' ? +input.byte % c1 : c1 + (+input.byte % (32 * p.dv)); c[at] ^= 1 << +input.bit; }
  return { c, en, p };
}

export const mods = [
  {
    topic: 'pq-mlkem-flow', allow: ['4', '3', '5', '6', '12', '32', '64', '128', '256', '512', '768', '1024'],
    extra: [{ set: '512', seed: 'pelican', msg: 'reed', tamper: 'yes' }, { set: '1024', seed: 'marten', msg: 'sedge', tamper: 'no' }],
    prepare: async (S, input) => { const { c, en } = cipher(S, input, 'flow'); return { node: await nodeDecaps(input.set, input.seed, c), Kb: hx(en.K) }; },
    check({ input, pre, r, fail }) {
      const k = { 512: 2, 768: 3, 1024: 4 }[input.set];
      const last = r.frames[r.frames.length - 1].facts;
      if (last.K !== pre.node) fail('Alice\'s key ' + last.K.slice(0, 16) + ' is not what Node decapsulates, ' + pre.node.slice(0, 16));
      if (last.Kb !== pre.Kb) fail('Bob\'s key');
      if ((input.tamper === 'yes') === (last.K === last.Kb)) fail('the keys agree when they should not, or the other way round');
      const f0 = r.frames[0].facts;
      if (f0.ek !== 384 * k + 32 || f0.dk !== 768 * k + 96) fail('the key sizes');
    },
  },
  {
    topic: 'pq-ntt', allow: ['3', '4', '5', '6', '7', '17', '65536', '896', '512', '128', '256', '3329', '1665'],
    random: (rnd) => ({ poly: ['x', 'small', 'msg'][Math.floor(rnd() * 3)], seed: 'w' + Math.floor(rnd() * 1000), follow: Math.floor(rnd() * 256) }),
    check({ S, input, r, fail }) {
      const K = S.PQ.MLKEM, idx = +input.follow;
      for (const f of r.frames) {
        const x = f.facts;
        if (f.meta.stage === 'layer') {
          if (x.zeta !== pw(17, br7(x.zi))) fail('ζ at layer ' + x.L);
          if (x.len !== 128 >> (x.L - 1) || (x.j !== idx && x.k !== idx) || x.k - x.j !== x.len) fail('the partner at layer ' + x.L);
          if (x.t !== (x.zeta * x.y) % q || x.o0 !== (x.x + x.t) % q || x.o1 !== (x.x - x.t + q) % q) fail('the butterfly at layer ' + x.L);
        }
        if (f.meta.stage === 'end') {
          // rebuild f, then reduce it modulo X² − γ for the pair that holds idx
          let poly;
          const seed = (t) => createHash('shake256', { outputLength: 32 }).update(t + ':' + input.seed).digest();
          if (input.poly === 'x') { poly = new Array(256).fill(0); poly[1] = 1; } else if (input.poly === 'small') poly = K.cbd(K.prf(2, seed('ntt'), 0), 2); else poly = K.byteDecode(seed('msg'), 1).map((b) => K.decompress(b, 1));
          const i = idx >> 1, g = pw(17, 2 * br7(i) + 1);
          let a0 = 0, a1 = 0;
          for (let j = 0; j < 256; j++) { const c = poly[j] * pw(g, j >> 1); if (j % 2) a1 = (a1 + c) % q; else a0 = (a0 + c) % q; }
          if (x.out !== (idx % 2 ? a1 : a0)) fail('f̂[' + idx + '] = ' + x.out + ', but f mod (X² − ' + g + ') gives ' + (idx % 2 ? a1 : a0));
          if (x.same !== 256) fail('the NTT product does not match the schoolbook one');
        }
      }
    },
  },
  {
    topic: 'pq-mlkem-noise', allow: ['4', '3', '5', '10', '11', '16', '64', '256', '832', '1665', '2048', '4096', '1024', '512', '768'],
    random: (rnd) => ({ set: ['512', '768', '1024'][Math.floor(rnd() * 3)], x: Math.floor(rnd() * 3329), runs: '4' }), count: 4,
    check({ S, input, r, fail }) {
      const p = S.PQ.MLKEM.params(input.set);
      const comp = (x, d) => Math.round((2 ** d * x) / q + 1e-9) % 2 ** d, dec = (y, d) => Math.round((q * y) / 2 ** d + 1e-9);
      const cen = (v) => { v = ((v % q) + q) % q; return v > q / 2 ? v - q : v; };
      const maxErr = (d) => { let m = 0; for (let x = 0; x < q; x++) m = Math.max(m, Math.abs(cen(dec(comp(x, d), d) - x))); return m; };
      for (const f of r.frames) {
        const x = f.facts;
        if (f.meta.stage === 'compress' && (x.y !== comp(x.x, x.d) || x.x2 !== dec(x.y, x.d) || x.err !== cen(x.x2 - x.x) || x.d !== p.dv)) fail('Compress/Decompress of ' + x.x);
        if (f.meta.stage === 'table' && (x.eu !== maxErr(p.du) || x.ev !== maxErr(p.dv))) fail('the rounding errors');
        if (f.meta.stage === 'one' && !(x.worst < 832)) fail('a coefficient beyond 832');
        if (f.meta.stage === 'many' && (!(x.worst < 832) || !near(x.margin, 832 / x.worst, 6) || !f.meta.ok || x.n !== 256 * x.runs)) fail('the many-run summary');
      }
    },
  },
  {
    topic: 'pq-mlkem-reject', allow: ['3', '4', '5', '32', '1024', '512', '768'],
    extra: [{ set: '1024', where: 'u', byte: 7, bit: '6' }, { set: '512', where: 'v', byte: 3, bit: '3', seed: 'badger', msg: 'rush' }],
    prepare: async (S, input) => { const { c } = cipher(S, input, 'reject'); const z = shake('z', input.seed); return { node: await nodeDecaps(input.set, input.seed, c), J: createHash('shake256', { outputLength: 32 }).update(Buffer.concat([z, Buffer.from(c)])).digest('hex') }; },
    check({ input, pre, r, fail }) {
      const kf = r.frames.find((f) => f.meta.stage === 'key');
      if (kf.facts.K !== pre.node) fail('the decapsulated key is not what Node gives for the same ciphertext');
      if (kf.facts.J !== pre.J) fail('J(z ‖ c)');
      if (kf.meta.rejected !== (input.where !== 'none')) fail('rejected an honest ciphertext or accepted a tampered one');
      if (kf.meta.rejected && kf.facts.K !== pre.J) fail('the rejection key is not J(z ‖ c)');
      const cmp = r.frames.find((f) => f.meta.stage === 'compare'), dfr = r.frames.find((f) => f.meta.stage === 'decrypt');
      if (input.where !== 'none' && !dfr.meta.flipped && cmp.meta.diff !== 1) fail('with m′ = m the re-encryption should differ in the one tampered byte');
    },
  },
];
