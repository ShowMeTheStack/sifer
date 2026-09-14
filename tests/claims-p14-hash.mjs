// Part 14 claims: hash-based signatures. Digest bits and base-w digits are worked out again with Node's
// SHAKE256; forgeries are checked against the rule that makes them possible; sizes against the formulas.
import { createHash } from 'node:crypto';

const shake = (data, n) => createHash('shake256', { outputLength: n }).update(data).digest();
const bitsOf = (buf, count) => Array.from({ length: count }, (_, i) => (buf[i >> 3] >> (7 - (i & 7))) & 1);
const wlens = (n, w) => { const lw = Math.log2(w), len1 = Math.ceil((8 * n) / lw), len2 = Math.floor(Math.log2(len1 * (w - 1)) / lw) + 1; return { len1, len2 }; };
const digits = (msg, n, w, cs) => {
  const { len1, len2 } = wlens(n, w), b = Math.log2(w), bits = bitsOf(shake(msg, n), 8 * n), d = [];
  for (let i = 0; i < len1; i++) { let v = 0; for (let j = 0; j < b; j++) v = 2 * v + (bits[i * b + j] || 0); d.push(v); }
  const sum = d.reduce((s, v) => s + (w - 1 - v), 0), c = [];
  for (let i = len2 - 1; i >= 0; i--) c.push(Math.floor(sum / w ** i) % w);
  return { msg: d, sum, all: cs ? d.concat(c) : d, check: c };
};

export const mods = [
  {
    topic: 'pq-lamport', allow: ['16', '24', '256', '4', '3'],
    check({ input, r, fail }) {
      const n = +input.n, d1 = bitsOf(shake(input.m1, n), 8 * n), d2 = bitsOf(shake(input.m2, n), 8 * n);
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'sign1' && x.d !== d1.join('')) fail('the first digest');
        if (st === 'sign2' && (x.d !== d2.join('') || x.both !== d1.filter((b, i) => b !== d2[i]).length)) fail('the second digest or the count of exposed pairs');
        if (st === 'forge' && f.meta.ok) {
          const msg = input.forge.replace('#', String(x.tries)), d = bitsOf(shake(msg, n), 8 * n);
          if (d.join('') !== x.d) fail('the forged digest');
          if (d.some((b, i) => d1[i] === d2[i] && b !== d1[i])) fail('the forgery needs a secret that was never revealed');
          for (let k = 1; k < x.tries; k++) { const e = bitsOf(shake(input.forge.replace('#', String(k)), n), 8 * n); if (e.every((b, i) => d1[i] !== d2[i] || b === d1[i])) { fail('an earlier try ' + k + ' would have worked'); break; } }
        }
      }
    },
  },
  {
    topic: 'pq-winternitz', allow: ['4', '3', '16', '15', '5', '6', '8', '10', '11', '12', '13', '14', '7', '9'],
    check({ input, r, fail }) {
      const w = +input.w, cs = input.cs === 'yes', D = digits(input.m1, 2, w, cs);
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'digits' && x.digits.join() !== D.msg.join()) fail('the digits ' + x.digits + ' against ' + D.msg);
        if (st === 'checksum' && (x.sum !== D.sum || x.check.join() !== D.check.join())) fail('the checksum');
        if (st === 'sign' && x.total !== D.all.reduce((a, b) => a + b, 0)) fail('the hash count');
        if (st === 'forge') {
          if (cs && f.meta.ok) fail('a forgery with the checksum');
          const d2 = digits(input.m2.replace('#', String(x.tries)), 2, w, cs).all;
          if (d2.join() !== x.d2.join()) fail('the forged digits');
          if (f.meta.ok && d2.some((v, i) => v < D.all[i])) fail('the forgery walks a chain down');
          if (!f.meta.ok && x.blocked.join() !== d2.map((v, i) => (v < D.all[i] ? i : -1)).filter((i) => i >= 0).join()) fail('the blocked chains');
        }
      }
    },
  },
  {
    topic: 'pq-merkle', allow: ['4', '3', '16'],
    random: (rnd) => { const h = 2 + Math.floor(rnd() * 3); return { h: String(h), leaf: Math.floor(rnd() * 2 ** h) }; },
    check({ input, r, fail }) {
      const h = +input.h, N = 2 ** h, idx = Math.min(+input.leaf, N - 1);
      const climbs = r.frames.filter((f) => f.meta.stage === 'climb');
      if (climbs.length !== h) fail('the climb has ' + climbs.length + ' levels');
      climbs.forEach((f, k) => { if (f.facts.level !== k + 1 || f.facts.index !== idx >> (k + 1)) fail('the node reached at level ' + (k + 1)); });
      const auth = r.frames.find((f) => f.meta.stage === 'auth').facts.auth;
      if (auth.length !== h) fail('the authentication path length');
      const last = r.frames[r.frames.length - 1];
      if (!/Accept/.test(last.say) || last.facts.next !== idx + 1) fail('the verdict or the state');
    },
  },
  {
    topic: 'pq-slhdsa', allow: ['8', '50', '63', '3', '4', '6', '2', '16', '1', '0'],
    check({ S, input, r, fail }) {
      const p = S.PQ.SLH.params(), kg = S.PQ.SLH.keyGen(input.seed || 'meridian', p), { len1, len2 } = wlens(p.n, p.w);
      const dg = r.frames.find((f) => f.meta.stage === 'digest').facts;
      const nbytes = Math.ceil((p.k * p.a + p.h) / 8) + 1;
      const bits = bitsOf(shake(Buffer.concat([Buffer.from(dg.R, 'hex'), Buffer.from(kg.pk.pkSeed), Buffer.from(kg.pk.root), Buffer.from(input.msg)]), nbytes), p.k * p.a + p.h);
      const toInt = (b) => b.reduce((v, x) => 2 * v + x, 0);
      const md = Array.from({ length: p.k }, (_, i) => toInt(bits.slice(i * p.a, (i + 1) * p.a)));
      if (md.join() !== dg.md.join()) fail('the FORS indices');
      if (toInt(bits.slice(p.k * p.a, p.k * p.a + p.h - p.hp)) !== dg.tree || toInt(bits.slice(p.k * p.a + p.h - p.hp)) !== dg.leaf) fail('the tree and leaf');
      const size = r.frames.find((f) => f.meta.stage === 'size').facts.bytes;
      if (size !== p.n + p.k * (1 + p.a) * p.n + p.d * (len1 + len2 + p.hp) * p.n) fail('the signature size');
      if (!r.frames[r.frames.length - 1].meta.ok) fail('the signature does not verify');
    },
  },
];

// ---- McEliece: the ciphertext, the syndrome and the decoded message, by GF(2) arithmetic done here ----
mods.push({
  topic: 'pq-mceliece', allow: ['4', '3', '5', '16', '32'],
  random: (rnd) => ({ m: rnd() < 0.5 ? '4' : '5', t: rnd() < 0.5 ? '2' : '3', seed: 1 + Math.floor(rnd() * 200), msg: Array.from({ length: 6 + Math.floor(rnd() * 10) }, () => (rnd() < 0.5 ? '0' : '1')).join(''), eseed: 1 + Math.floor(rnd() * 200) }), count: 6,
  check({ S, input, r, fail }) {
    const kg = S.PQ.McEliece.keyGen({ m: +input.m, t: +input.t, seed: +input.seed }), { Gpub, k, n } = kg.pk, code = kg.sk.code;
    const src = String(input.msg).replace(/[^01]/g, '') || '1', msg = Array.from({ length: k }, (_, i) => +src[i % src.length]);
    const cw = Array.from({ length: n }, (_, j) => msg.reduce((s, b, i) => s ^ (b & Gpub[i][j]), 0));
    const fe = r.frames.find((f) => f.meta.stage === 'encode').facts, fr = r.frames.find((f) => f.meta.stage === 'error').facts;
    if (fe.cw !== cw.join('') || fe.msg !== msg.join('')) fail('m·G′');
    const e = fr.e.split('').map(Number), c = cw.map((v, j) => v ^ e[j]);
    if (fr.c !== c.join('')) fail('c = m·G′ + e');
    const w = e.reduce((a, b) => a + b, 0);
    if (w !== (input.errors === 'more' ? +input.t + 1 : +input.t)) fail('the error weight ' + w);
    // undo the permutation and take the syndrome with the secret H
    const un = new Array(n); kg.sk.perm.forEach((p, j) => { un[p] = c[j]; });
    const syn = code.H.map((row) => row.reduce((s, v, j) => s ^ (v & un[j]), 0)).join('');
    if (r.frames.find((f) => f.meta.stage === 'syndrome').facts.syn !== syn) fail('the syndrome');
    const done = r.frames.find((f) => f.meta.stage === 'done');
    if (input.errors !== 'more' && (!done.meta.ok || done.facts.msg !== msg.join('') || done.facts.err !== fr.e)) fail('decryption');
    if (input.errors === 'more' && done.meta.ok) fail('too many errors were corrected');
  },
});
