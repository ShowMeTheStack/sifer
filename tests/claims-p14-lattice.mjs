// Part 14 claims: lattices. Coordinates by Cramer's rule, Gram–Schmidt by hand, Gauss reduction re-run here,
// and shortest and closest vectors by brute-force search over a wide box.
import { near } from './claims-lib-p14.mjs';

const det = (B) => B[0][0] * B[1][1] - B[0][1] * B[1][0];
const dot = (a, b) => a[0] * b[0] + a[1] * b[1];
const len = (a) => Math.hypot(a[0], a[1]);
const combo = (B, c) => [c[0] * B[0][0] + c[1] * B[1][0], c[0] * B[0][1] + c[1] * B[1][1]];
const brute = (B, f) => { let best = null; for (let a = -40; a <= 40; a++) for (let b = -40; b <= 40; b++) { const v = combo(B, [a, b]), k = f(v); if (k !== null && (!best || k < best.k)) best = { v, k }; } return best; };
const shortest = (B) => Math.sqrt(brute(B, (v) => (v[0] || v[1] ? dot(v, v) : null)).k);
const cramer = (B, t) => { const D = det(B); return [(t[0] * B[1][1] - t[1] * B[1][0]) / D, (B[0][0] * t[1] - B[0][1] * t[0]) / D]; };
const randBasis = (rnd) => { for (;;) { const v = Array.from({ length: 4 }, () => Math.floor(rnd() * 41) - 20); const d = v[0] * v[3] - v[1] * v[2]; if (Math.abs(d) >= 6 && Math.abs(d) <= 120) return { basis: v.map(String) }; } };

export const mods = [
  {
    topic: 'pq-lattice-bases', allow: [],
    check({ S, input, r, fail }) {
      const g = S.PQ.Lattice.goodBad(+input.seed), G = g.good, B = g.bad, Um = g.U;
      const UG = [combo(G, Um[0]), combo(G, Um[1])];
      if (JSON.stringify(UG) !== JSON.stringify(B)) fail('the bad basis is not U times the good one');
      if (Math.abs(det(Um)) !== 1) fail('U is not unimodular');
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (x.D !== undefined && x.D !== Math.abs(det(G))) fail('the area ' + x.D);
        if (st === 'good' && !near(x.h, Math.sqrt(Math.abs(det(G)) / (len(G[0]) * len(G[1]))), 3)) fail('the good Hadamard ratio');
        if (st === 'bad' && !near(x.h, Math.sqrt(Math.abs(det(B)) / (len(B[0]) * len(B[1]))), 3)) fail('the bad Hadamard ratio');
        if (st === 'short' && !near(x.l, shortest(G), 6)) fail('the shortest length ' + x.l + ' against ' + shortest(G));
      }
    },
  },
  {
    topic: 'pq-gram-schmidt', allow: [], random: randBasis,
    check({ input, r, fail }) {
      const B = input.basis.map(Number), b1 = [B[0], B[1]], b2 = [B[2], B[3]], mu = dot(b2, b1) / dot(b1, b1), b2s = [b2[0] - mu * b1[0], b2[1] - mu * b1[1]];
      for (const f of r.frames) {
        const x = f.facts;
        if (x.mu !== undefined && (!near(x.mu, mu, 6) || x.dot !== dot(b2, b1) || x.n1 !== dot(b1, b1))) fail('μ');
        if (x.b2s && (!near(x.b2s[0], b2s[0], 6) || !near(x.b2s[1], b2s[1], 6) || !near(x.ip, 0, 6))) fail('b₂*');
        if (x.area !== undefined && (!near(x.area, Math.abs(det([b1, b2])), 6) || x.D !== Math.abs(det([b1, b2])))) fail('the area');
      }
    },
  },
  {
    topic: 'pq-gauss', allow: [], random: randBasis,
    check({ input, r, fail }) {
      const v = input.basis.map(Number), D = Math.abs(v[0] * v[3] - v[1] * v[2]);
      let b1 = [v[0], v[1]], b2 = [v[2], v[3]];
      for (let k = 0; k < 200; k++) { if (dot(b2, b2) < dot(b1, b1)) [b1, b2] = [b2, b1]; const m = Math.round(dot(b1, b2) / dot(b1, b1)); if (!m) break; b2 = [b2[0] - m * b1[0], b2[1] - m * b1[1]]; }
      let prev = null;
      for (const f of r.frames) {
        const x = f.facts;
        if (x.D !== D) fail('the area changed to ' + x.D);
        if (f.meta.stage === 'reduce' && prev) { const want = [prev[1][0] - x.m * prev[0][0], prev[1][1] - x.m * prev[0][1]]; if (want[0] !== x.B[1][0] || want[1] !== x.B[1][1]) fail('b₂ − m·b₁'); if (x.m !== Math.round(dot(prev[0], prev[1]) / dot(prev[0], prev[0]))) fail('m'); }
        prev = x.B;
      }
      const last = r.frames[r.frames.length - 1].facts;
      if (!near(len(last.B[0]), len(b1), 9)) fail('the reduced b₁');
      if (!near(last.short, shortest([[v[0], v[1]], [v[2], v[3]]]), 6) || !near(len(last.B[0]), last.short, 6)) fail('b₁ is not a shortest vector');
    },
  },
  {
    topic: 'pq-babai', allow: [],
    random: (rnd) => ({ seed: ['13', '6', '23', '24', '12'][Math.floor(rnd() * 5)], tx: Math.floor(rnd() * 41) - 20, ty: Math.floor(rnd() * 41) - 20 }),
    check({ S, input, r, fail }) {
      const g = S.PQ.Lattice.goodBad(+input.seed), t = [+input.tx, +input.ty];
      const best = Math.sqrt(brute(g.good, (v) => (v[0] - t[0]) ** 2 + (v[1] - t[1]) ** 2).k);
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st !== 'good' && st !== 'bad') continue;
        const B = st === 'good' ? g.good : g.bad, c = cramer(B, t), rc = c.map(Math.round), v = combo(B, rc);
        if (!near(x.x[0], c[0], 6) || !near(x.x[1], c[1], 6)) fail('the coordinates in the ' + st + ' basis');
        if (x.c.join() !== rc.join() || x.v.join() !== v.join()) fail('the rounded point');
        if (!near(x.d, Math.hypot(v[0] - t[0], v[1] - t[1]), 6)) fail('the distance');
        if (st === 'good' && !near(x.best, best, 6)) fail('the closest distance');
        if (f.meta.hit !== (Math.abs(x.d - best) < 1e-9)) fail('whether it hit');
      }
    },
  },
];

// ---- LWE and the toy signature ----
const md = (a, q) => ((a % q) + q) % q;
const cen = (a, q) => { a = md(a, q); return a > q / 2 ? a - q : a; };
mods.push({
  topic: 'pq-lwe', allow: ['4'],
  random: (rnd) => ({ B: ['1', '2', '4', '6', '8'][Math.floor(rnd() * 5)], m: ['12', '16'][Math.floor(rnd() * 2)], q: ['101', '257'][Math.floor(rnd() * 2)], bit: String(Math.floor(rnd() * 2)), seed: 1 + Math.floor(rnd() * 300), enc: 1 + Math.floor(rnd() * 300) }),
  count: 16,
  check({ S, input, r, fail }) {
    const W = S.PQ.LWE, params = W.params({ n: 8, m: +input.m, q: +input.q, noise: { kind: 'uniform', B: +input.B } }), { q, m } = params, half = Math.floor(q / 2), bit = +input.bit;
    const kg = W.keyGen(params, +input.seed), enc = W.encrypt(kg.pk, bit, +input.enc), A = kg.pk.A, s = kg.sk.s, e = kg.e, sel = enc.r;
    const As = A.map((row) => md(row.reduce((a, v, j) => a + v * s[j], 0), q));
    if (As.some((v, i) => md(v + e[i], q) !== kg.pk.b[i])) fail('b = A·s + e');
    if (e.some((v) => Math.abs(v) > +input.B)) fail('an error out of range');
    const u = s.map((_, j) => md(A.reduce((a, row, i) => a + sel[i] * row[j], 0), q)), v = md(kg.pk.b.reduce((a, x, i) => a + sel[i] * x, 0) + bit * half, q);
    const d = md(v - s.reduce((a, x, j) => a + x * u[j], 0), q), noise = e.reduce((a, x, i) => a + sel[i] * x, 0), got = Math.abs(cen(d, q)) > q / 4 ? 1 : 0;
    // the exact failure chance by a convolution of our own
    let dist = new Map([[0, 1]]);
    for (let i = 0; i < m; i++) { const nd = new Map(); for (const [k, p] of dist) { nd.set(k, (nd.get(k) || 0) + p / 2); for (let x = -params.noise.B; x <= params.noise.B; x++) nd.set(k + x, (nd.get(k + x) || 0) + p / 2 / (2 * params.noise.B + 1)); } dist = nd; }
    let f0 = 0, f1 = 0; for (const [k, p] of dist) { if (Math.abs(cen(k, q)) > q / 4) f0 += p; if (Math.abs(cen(k + half, q)) <= q / 4) f1 += p; }
    for (const f of r.frames) {
      const x = f.facts, st = f.meta.stage;
      if (st === 'As' && x.As.join() !== As.join()) fail('A·s');
      if (st === 'enc' && (x.v !== v || x.count !== sel.filter(Boolean).length)) fail('the ciphertext');
      if (st === 'dec' && (x.d !== d || x.noise !== noise || x.bit !== got || x.c !== cen(d, q) || (got === bit) !== f.meta.ok)) fail('the decryption');
      if (st === 'dec' && md(bit * half + noise, q) !== d) fail('v − s·u is not bit·⌊q/2⌋ + e·r');
      if (st === 'dist' && (!near(x.pct, ((f0 + f1) / 2) * 100, 9) || x.worst !== m * params.noise.B)) fail('the failure chance ' + x.pct + ' against ' + ((f0 + f1) / 2) * 100);
    }
  },
});
mods.push({
  topic: 'pq-toysig', allow: [],
  check({ S, input, r, fail }) {
    const D = S.PQ.ToyDSA, kg = D.keyGen('toy-dsa'), p = kg.sk.p, bound = p.gamma1 - p.beta;
    let accepted = 0;
    for (const f of r.frames) {
      const x = f.facts, st = f.meta.stage;
      if (x.bound !== bound || x.beta !== p.tau * p.eta) fail('the bound');
      if (st === 'dsa-accept' || st === 'dsa-abort') {
        const t = D.sign(kg.sk, input.msg, { seed: +input.seed }).trace[x.attempt - 1];
        const zn = Math.max(...t.z.flat().map(Math.abs));
        if (zn !== x.z || zn !== x.worst) fail('‖z‖∞ of attempt ' + x.attempt);
        const ok = zn < bound && t.lowNorm < p.gamma2 - p.beta;
        if (ok !== (st === 'dsa-accept')) fail('the verdict of attempt ' + x.attempt);
        if (t.z.flat().some((z, i) => Math.abs(z - t.y.flat()[i]) > p.beta)) fail('c·s₁ larger than β');
        if (ok) accepted++;
      }
      if (st === 'verify' && f.say.indexOf('accept') < 0) fail('the signature does not verify');
      if (st === 'leak' && x.agree !== x.beyond) fail('a coefficient beyond γ₁ against the sign of c·s₁');
      if (st === 'flat' && x.beyond !== 0) fail('a coefficient beyond γ₁ after rejection');
    }
    if (accepted !== 1) fail('accepted ' + accepted + ' attempts');
  },
});
