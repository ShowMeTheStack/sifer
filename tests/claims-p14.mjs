// Part 14, post-quantum cryptography: every topic run with its presets and random inputs; every value a frame's
// narration quotes is one of the frame's facts, and the facts are worked out again here without the topic's code
// path (closed forms, brute force, node:crypto where it has the algorithm). Prints "claims-p14 N passed, M failed".
// Usage: node tests/claims-p14.mjs [topic id prefix ...]
import { runClaims, near, S } from './claims-lib-p14.mjs';
import { mods as lat } from './claims-p14-lattice.mjs';
import { mods as kem } from './claims-p14-kem.mjs';
import { mods as hs } from './claims-p14-hash.mjs';

const gcd = (a, b) => { while (b) [a, b] = [b, a % b]; return a; };
const pw = (b, e, m) => { let r = 1n, B = BigInt(b) % BigInt(m), E = BigInt(e); while (E > 0n) { if (E & 1n) r = (r * B) % BigInt(m); B = (B * B) % BigInt(m); E >>= 1n; } return Number(r); };

const quantum = [
  {
    topic: 'pq-grover', allow: ['4', '3', '5', '7', '9', '11', '13', '15', '17', '19', '21', '23', '25', '27', '29', '31'],
    random: (rnd) => { const n = 2 + Math.floor(rnd() * 5), N = 2 ** n, m = 1 + Math.floor(rnd() * Math.max(1, N / 4 - 0.01)); const set = new Set(); while (set.size < Math.min(m, 4)) set.add(Math.floor(rnd() * N)); return { n: String(n), marked: [...set].map(String), iters: ['best', 'over', '1'][Math.floor(rnd() * 3)] }; },
    check({ input, r, fail }) {
      const N = 2 ** +input.n, M = input.marked.length, th = Math.asin(Math.sqrt(M / N));
      const am = (k) => Math.sin((2 * k + 1) * th) / Math.sqrt(M), ao = (k) => Math.cos((2 * k + 1) * th) / Math.sqrt(N - M);
      let best = 0; for (let k = 0; k < 200; k++) if (Math.abs((2 * k + 1) * th - Math.PI / 2) < Math.abs((2 * best + 1) * th - Math.PI / 2)) best = k;
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'start' && !(near(x.amp, 1 / Math.sqrt(N)) && near(x.p, M / N))) fail('the starting amplitude or chance');
        if (st === 'oracle') { const k = x.k; if (!near(x.flipped, -am(k - 1))) fail('the flipped amplitude at ' + k); const mean = (-M * am(k - 1) + (N - M) * ao(k - 1)) / N; if (!near(x.mean, mean)) fail('the mean at ' + k); }
        if (st === 'diffuse') { const k = x.k; if (!near(x.amp, am(k)) || !near(x.other, ao(k)) || !near(x.p, Math.sin((2 * k + 1) * th) ** 2)) fail('the amplitudes after iteration ' + k); const mm = /(grow|shrink)s? to (−?[\d.]+)/.exec(f.say); if (!mm || !near(+mm[2].replace('−', '-'), am(k), 3.5) || (mm[1] === 'grow') !== (Math.abs(am(k)) >= Math.abs(am(k - 1)))) fail('the narration of iteration ' + k); }
        if (st === 'end') { if (x.best !== best) fail('the best number of iterations ' + x.best + ' is not ' + best); if (!near(x.classical, (N + 1) / (M + 1))) fail('the classical average'); if (!near(x.next, Math.sin((2 * x.K + 3) * th) ** 2)) fail('the chance after one more'); }
      }
    },
  },
  {
    topic: 'pq-shor', allow: ['4', '3', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20'],
    random: (rnd) => { const Ns = [15, 21, 33, 35, 39, 51, 55, 57, 65, 77, 85, 91], N = Ns[Math.floor(rnd() * Ns.length)]; return { N: String(N), a: 2 + Math.floor(rnd() * (N - 4)), seed: 1 + Math.floor(rnd() * 900) }; },
    count: 14,
    check({ input, r, fail }) {
      const N = +input.N;
      let a = null;
      for (const f of r.frames) {
        const x = f.facts, st = f.meta.stage;
        if (st === 'choose') a = x.a;
        if (st === 'lucky' && x.g !== undefined && (N % x.g || gcd(a, N) !== x.g)) fail('the lucky gcd');
        if (st === 'modexp') { let p = 1, v = a % N; while (v !== 1) { v = (v * a) % N; p++; } if (x.r !== p) fail('the period of ' + a + ' mod ' + N + ' is ' + p + ', not ' + x.r); }
        if (st === 'qft') { const t = Math.ceil(Math.log2(N * N)); if (x.t !== t || x.Q !== 2 ** t) fail('the register size'); }
        if (st === 'measure') {
          const cf = []; let h0 = 0, h1 = 1, k0 = 1, k1 = 0, p = x.y, q = x.Q;
          while (q) { const tt = Math.floor(p / q); [h0, h1] = [h1, tt * h1 + h0]; [k0, k1] = [k1, tt * k1 + k0]; if (k1 < N) cf.push(h1 + '/' + k1); [p, q] = [q, p - tt * q]; }
          if (cf.join() !== x.convergents.join()) fail('the convergents of ' + x.y + '/' + x.Q + ': ' + cf.join() + ' against ' + x.convergents.join());
        }
        if (st === 'factor') { if (x.f1 * x.f2 !== N && x.f1 * (N / x.f1) !== N) fail('the factors'); if (N % x.f1 || x.f1 === 1 || x.f1 === N) fail('a trivial factor ' + x.f1); }
        if (st === 'end' && x.f && x.f[0] * x.f[1] !== N) fail('the final factors');
      }
    },
  },
  {
    topic: 'pq-levels', allow: ['3', '4'],
    check({ input, r, fail }) {
      const need = +input.need;
      let ok = 0;
      for (const f of r.frames) {
        const x = f.facts;
        if (x.classical === undefined) continue;
        const name = f.say.split(':')[0];
        const want = /RSA|ECC/.test(name) ? 0 : /collision/.test(name) ? Math.round(256 / 3) : /KEM/.test(name) ? x.classical : x.classical / 2;
        if (x.quantum !== want) fail(name + ': ' + x.quantum + ' quantum bits, expected ' + want);
        if (x.quantum >= need) ok++;
      }
      if (r.frames[r.frames.length - 1].facts.count !== ok) fail('the count that meets the target');
    },
  },
];

const only = process.argv.slice(2);
await runClaims('claims-p14', 'p14-', [...quantum, ...lat, ...kem, ...hs], only);
