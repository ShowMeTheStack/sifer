// Part 9, the problem, Diffie–Hellman, Elgamal and the signatures: their claim checks, collected by tests/claims-p09.mjs.
// Real sizes are checked against node:crypto (Diffie–Hellman in the MODP group, DSA verification of our signatures with
// a key built from p, q, g and y); toy sizes by brute force or by working the formulas out again here.
import crypto from 'node:crypto';
import { pw, inv, mod, gcd } from './claims-lib-pk.mjs';

const hb = (v) => { let h = BigInt(v).toString(16); if (h.length % 2) h = '0' + h; return Buffer.from(h, 'hex'); };
const big = (b) => BigInt('0x' + (Buffer.from(b).toString('hex') || '0'));
const sha = (b) => big(crypto.createHash('sha256').update(b).digest());
const PRIMES = [5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43];
const isGen = (g, p) => { let v = 1n; for (let k = 1n; k < p - 1n; k++) { v = (v * g) % p; if (v === 1n) return false; } return true; };
const smallestGen = (p) => { for (let g = 2n; ; g++) if (isGen(g, p)) return g; };
/** node's Diffie–Hellman in the 2048-bit MODP group: public value and shared secret */
const MODP = crypto.getDiffieHellman('modp14'), Pm = big(MODP.getPrime());
const nodePub = (x) => { const d = crypto.createDiffieHellman(MODP.getPrime(), hb(2n)); d.setPrivateKey(hb(x)); d.generateKeys(); return big(d.getPublicKey()); };
const nodeShared = (x, other) => { const d = crypto.createDiffieHellman(MODP.getPrime(), hb(2n)); d.setPrivateKey(hb(x)); d.generateKeys(); return big(d.computeSecret(hb(other))); };
/** a DSA public key and signature in DER, for crypto.verify */
const len = (n) => (n < 128 ? Buffer.from([n]) : (() => { const b = []; while (n) { b.unshift(n & 255); n >>= 8; } return Buffer.from([0x80 | b.length, ...b]); })());
const tlv = (t, body) => Buffer.concat([Buffer.from([t]), len(body.length), body]);
const int = (v) => { let b = hb(v); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return tlv(0x02, b); };
const seq = (...x) => tlv(0x30, Buffer.concat(x));
const dsaOk = (pr, y, msg, r, s) => crypto.verify('sha256', Buffer.from(msg), crypto.createPublicKey({ key: seq(seq(Buffer.from('06072a8648ce380401', 'hex'), seq(int(pr.p), int(pr.q), int(pr.g))), tlv(0x03, Buffer.concat([Buffer.from([0]), int(y)]))), format: 'der', type: 'spki' }), seq(int(r), int(s)));
/** the DSA hash: SHA-256 cut to the bit length of q */
const zOf = (msg, q) => { const H = sha(Buffer.from(msg)), qb = q.toString(2).length; return qb >= 256 ? H : H >> BigInt(256 - qb); };
const toyInput = (rnd, names) => { const p = [23, 101, 467, 1019, 2027, 7919, 65537][Math.floor(rnd() * 7)], o = { size: 'toy', p, g: 0 }; for (const n of names) o[n] = 2 + Math.floor(rnd() * (p - 3)); return o; };

export const mods = [
  {
    topic: 'p09-dlp', allow: ['40'],
    random: (rnd) => (rnd() < 0.15 ? { size: 'real', seed: 1 + Math.floor(rnd() * 999) } : (() => { const p = PRIMES[2 + Math.floor(rnd() * 10)]; return { size: 'toy', p, g: rnd() < 0.3 ? 2 + Math.floor(rnd() * (p - 2)) : 0, x: 1 + Math.floor(rnd() * (p - 2)) }; })()),
    count: 14,
    check({ input, r, fail }) {
      if (input.size === 'real') {
        for (const f of r.frames) {
          const x = f.facts;
          if (f.meta.phase === 'group' && (x.p !== Pm || x.q !== (Pm - 1n) / 2n || x.g !== 2n)) fail('the MODP group');
          if (f.meta.phase === 'forward') {
            if (nodePub(x.x) !== x.h) fail('h = g^x against node:crypto');
            const bits = x.x.toString(2);
            if (x.sq !== bits.length - 1 || x.mul !== [...bits].filter((c) => c === '1').length - 1) fail('the operation counts');
          }
          if (f.meta.phase === 'costs') { const ln = 2048 * Math.LN2; if (Math.abs(x.nfs - Math.cbrt(64 / 9) * Math.cbrt(ln) * Math.log(ln) ** (2 / 3) / Math.LN2) > 1e-9 || x.brute !== 2047) fail('the costs'); }
        }
        return;
      }
      const p = BigInt(input.p), g = input.g ? BigInt(input.g) : smallestGen(p), h = pw(g, input.x, p);
      let ord = 1; for (let v = g; v !== 1n; v = (v * g) % p) ord++;
      for (const f of r.frames) {
        const x = f.facts;
        if (f.meta.phase === 'start' && (x.h !== h || x.g !== g || BigInt(x.ord) !== BigInt(ord))) fail('the start');
        if (f.meta.phase === 'hop') { if (x.v !== pw(g, x.k, p) || x.prev !== pw(g, x.k - 1, p)) fail('the hop ' + x.k); if ((x.v === h) !== (x.k === input.x) && x.k <= input.x) { let first = 1; while (pw(g, first, p) !== h) first++; if (x.k === first && x.v !== h) fail('the hit'); } }
        if (f.meta.phase === 'cycle' && x.ord !== ord) fail('the order of g');
        if (f.meta.phase === 'additive' && (mod(BigInt(x.hAdd) * BigInt(x.inv), BigInt(x.n)) !== BigInt(input.x) % BigInt(x.n) || mod(BigInt(x.step) * BigInt(x.inv), BigInt(x.n)) !== 1n)) fail('the additive logarithm');
      }
    },
  },
  {
    topic: /^p09-dh(-paint)?$/, allow: ['2048'],
    random: (rnd) => (rnd() < 0.2 ? { size: 'real', seed: 1 + Math.floor(rnd() * 999) } : toyInput(rnd, ['a', 'b'])),
    check({ input, r, fail }) {
      const last = (ph) => r.frames.find((f) => f.meta.phase === ph);
      const n = (last('numbers') || last('shared')).facts, pub = last('public');
      const real = input.size === 'real';
      const vals = pub ? Object.assign({}, last('secrets').facts, pub.facts, last('shared').facts) : n;
      const p = real ? Pm : BigInt(input.p), g = real ? 2n : input.g ? BigInt(input.g) : smallestGen(p);
      const a = vals.a, b = vals.b;
      if (!real && (a !== BigInt(input.a) || b !== BigInt(input.b))) fail('the secrets');
      const A = real ? nodePub(a) : pw(g, a, p), B = real ? nodePub(b) : pw(g, b, p), K = real ? nodeShared(a, B) : pw(B, a, p);
      if (vals.A !== A || vals.B !== B || vals.K !== K || K !== pw(A, b, p)) fail('A, B or K');
      if (pub && (pub.facts.sa !== a.toString(2).length - 1 || pub.facts.ma !== [...a.toString(2)].filter((c) => c === '1').length - 1)) fail('the operation counts');
      const ev = r.frames.find((f) => f.meta.phase === 'eve-numbers');
      if (ev && ev.facts.eve !== (A * B) % p) fail('Eve\'s mixture');
    },
  },
  {
    topic: 'p09-dh-mitm',
    random: (rnd) => (rnd() < 0.2 ? { size: 'real', seed: 1 + Math.floor(rnd() * 999) } : toyInput(rnd, ['a', 'b', 'm'])),
    check({ input, r, fail }) {
      const f0 = r.frames[0].facts, k = r.frames.find((f) => f.meta.phase === 'keys').facts, real = input.size === 'real';
      const p = real ? Pm : BigInt(input.p), g = real ? 2n : smallestGen(p);
      const M = pw(g, f0.m, p), A = pw(g, f0.a, p), B = pw(g, f0.b, p);
      if (r.frames[1].facts.A !== A || r.frames[1].facts.M !== M || r.frames[2].facts.B !== B) fail('the public values');
      if (k.kA !== pw(M, f0.a, p) || k.kA !== pw(A, f0.m, p) || k.kB !== pw(M, f0.b, p) || k.kB !== pw(B, f0.m, p) || k.honest !== pw(g, f0.a * f0.b, p)) fail('the keys');
      if (real && k.kA !== nodeShared(f0.a, M)) fail('Alice\'s key against node:crypto');
    },
  },
  {
    topic: 'p09-elgamal',
    random: (rnd) => { if (rnd() < 0.2) return { size: 'real', seed: 1 + Math.floor(rnd() * 999) }; const o = toyInput(rnd, ['x', 'k', 'k2']); o.m = 1 + Math.floor(rnd() * (o.p - 1)); return o; },
    check({ input, r, fail }) {
      const F = (ph) => r.frames.find((f) => f.meta.phase === ph).facts, real = input.size === 'real';
      const key = F('key'), p = key.p, g = key.g, h = pw(g, key.x, p);
      if (!real && (p !== BigInt(input.p) || g !== smallestGen(p))) fail('the group');
      if (real && (p !== Pm || h !== nodePub(key.x))) fail('h against node:crypto');
      if (key.h !== h) fail('h');
      const m = F('message').m;
      if (real && Buffer.from(m.toString(16), 'hex').toString() !== 'the cellar key is under the blue pot') fail('the message encoding');
      const e = F('encrypt'), s = pw(h, e.k, p);
      if (e.c1 !== pw(g, e.k, p) || e.s !== s || e.c2 !== (m * s) % p) fail('the encryption');
      const d = F('decrypt');
      if (d.s !== pw(e.c1, key.x, p) || (d.sInv * d.s) % p !== 1n || d.m !== m) fail('the decryption');
      const a = F('again');
      if (a.c1 !== pw(g, a.k2, p) || a.c2 !== (m * pw(h, a.k2, p)) % p || a.m !== m) fail('the second encryption');
      const ml = F('malleable');
      if (ml.c2x !== (2n * e.c2) % p || ml.m2 !== (2n * m) % p) fail('the malleability');
    },
  },
  {
    topic: 'p09-sigs', allow: [],
    random: (rnd) => { const scheme = ['dsa', 'schnorr', 'elgamal'][Math.floor(rnd() * 3)]; if (rnd() < 0.25) return { scheme, size: 'real', seed: 1 + Math.floor(rnd() * 999) }; const q = [101, 1009, 10007][Math.floor(rnd() * 3)]; return { scheme, size: 'toy', q, x: 1 + Math.floor(rnd() * 90), k: [7, 13, 29, 41, 53][Math.floor(rnd() * 5)], msg: 'note ' + Math.floor(rnd() * 1000), fake: 'note ' + Math.floor(rnd() * 1000) + '!' }; },
    mayRefuse: true, count: 18,
    check({ input, r, fail }) {
      const F = (ph) => (r.frames.find((f) => f.meta.phase === ph) || {}).facts || {}, real = input.size === 'real';
      const keys = F('keys'), p = keys.p, g = keys.g, x = keys.x, y = keys.y, msg = Buffer.from(String(input.msg)), fake = Buffer.from(String(input.fake));
      if (y !== pw(g, x, p)) fail('y = g^x');
      if (input.scheme === 'elgamal') {
        const z = mod(sha(msg), p - 1n), sg = F('sign'), nn = F('nonce');
        if (F('hash').z !== z || nn.r !== pw(g, nn.k, p) || gcd(nn.k, p - 1n) !== 1n || sg.kinv !== inv(nn.k, p - 1n) || sg.s !== mod(sg.kinv * (z - x * nn.r), p - 1n)) fail('the Elgamal signature');
        const c = F('check');
        if (c.lhs !== pw(g, z, p) || c.rhs !== (pw(y, nn.r, p) * pw(nn.r, sg.s, p)) % p || c.lhs !== c.rhs) fail('the Elgamal check');
        const t = F('tamper');
        if (t.lhs !== pw(g, mod(sha(fake), p - 1n), p) || t.ok !== (t.lhs === c.rhs)) fail('the altered message');
        return;
      }
      const q = keys.q;
      if (pw(g, q, p) !== 1n || (p - 1n) % q !== 0n) fail('the group');
      if (input.scheme === 'dsa') {
        const z = zOf(msg, q), nn = F('nonce'), sg = F('sign'), r_ = nn.r;
        if (F('hash').z !== z || r_ !== pw(g, nn.k, p) % q || sg.s !== mod(inv(nn.k, q) * (z + x * r_), q)) fail('the DSA signature');
        const c = F('check'), w = inv(sg.s, q);
        if (c.w !== w || c.u1 !== mod(z * w, q) || c.u2 !== mod(r_ * w, q) || c.v !== ((pw(g, c.u1, p) * pw(y, c.u2, p)) % p) % q || c.v !== r_) fail('the DSA check');
        if (real && !dsaOk(keys, y, msg, r_, sg.s)) fail('node:crypto does not accept the signature');
        const t = F('tamper');
        if (t.z2 !== zOf(fake, q) || (real && t.ok !== dsaOk(keys, y, fake, r_, sg.s))) fail('the altered message');
        return;
      }
      const nn = F('nonce'), R = pw(g, nn.k, p), e = mod(sha(Buffer.concat([hb(R), msg])), q), sg = F('sign');
      if (nn.R !== R || F('hash').e !== e || sg.s !== mod(nn.k + e * x, q)) fail('the Schnorr signature');
      const c = F('check');
      if (c.R !== mod(pw(g, sg.s, p) * pw(y, mod(-e, q), p), p) || c.R !== R || c.e !== e) fail('the Schnorr check');
      const t = F('tamper');
      if (t.e2 !== mod(sha(Buffer.concat([hb(R), fake])), q)) fail('the altered message');
    },
  },
  {
    topic: 'p09-dsa-nonce', allow: ['224'],
    random: (rnd) => (rnd() < 0.25 ? { size: 'real', seed: 1 + Math.floor(rnd() * 999) } : { size: 'toy', q: [101, 1009, 10007, 100003][Math.floor(rnd() * 4)], x: 2 + Math.floor(rnd() * 99), k: 2 + Math.floor(rnd() * 99), m1: 'order ' + Math.floor(rnd() * 999), m2: 'refund ' + Math.floor(rnd() * 999), seed: 1 + Math.floor(rnd() * 999) }),
    count: 14,
    check({ S, input, r, fail }) {
      const F = (ph) => (r.frames.find((f) => f.meta.phase === ph) || {}).facts, real = input.size === 'real';
      const pr = real ? S.PK.dsaReal() : S.SIG.toyParams(BigInt(input.q)), { p, q, g } = pr;
      const y = F('public').y, sp = F('spot'), ex = F('exposed');
      const verifies = (m, rr, ss) => { const z = zOf(Buffer.from(m), q), w = inv(ss, q); return ((pw(g, mod(z * w, q), p) * pw(y, mod(rr * w, q), p)) % p) % q === rr; };
      if (sp.r1 !== sp.r2) fail('the two signatures do not share r');
      if (ex.z1 !== zOf(Buffer.from(String(input.m1)), q) || ex.z2 !== zOf(Buffer.from(String(input.m2)), q)) fail('z1 or z2');
      if (!verifies(String(input.m1), sp.r, ex.s1) || !verifies(String(input.m2), sp.r, ex.s2)) fail('the reused-nonce signatures do not verify');
      if (real && !dsaOk(pr, y, String(input.m1), sp.r, ex.s1)) fail('node:crypto refuses the first signature');
      // the claim that the key is exposed: worked out here, never shown in the topic
      if (ex.exposed !== (ex.s1 !== ex.s2)) fail('exposed');
      if (ex.exposed) {
        const k = mod((ex.z1 - ex.z2) * inv(mod(ex.s1 - ex.s2, q), q), q), x = mod((ex.s1 * k - ex.z1) * inv(sp.r, q), q);
        if (pw(g, x, p) !== y) fail('the shared r and two s values do not determine the key');
      }
      const rd = F('random');
      if (pw(g, rd.k1, p) % q !== rd.r1 || pw(g, rd.k2, p) % q !== rd.r2) fail('the fresh nonces do not give r1, r2');
      // RFC 6979 section 3.2 with HMAC-SHA-256, worked out again with node:crypto
      const hm = (key, ...parts) => crypto.createHmac('sha256', key).update(Buffer.concat(parts)).digest();
      const qlen = q.toString(2).length, rlen = Math.ceil(qlen / 8);
      const b2i = (b) => { const v = big(b), bl = b.length * 8; return bl > qlen ? v >> BigInt(bl - qlen) : v; };
      const i2o = (v) => Buffer.from(v.toString(16).padStart(rlen * 2, '0'), 'hex');
      const rfc = (xv, m) => {
        const h = crypto.createHash('sha256').update(Buffer.from(m)).digest(); let z1 = b2i(h); if (z1 >= q) z1 -= q;
        let V = Buffer.alloc(32, 1), K = Buffer.alloc(32, 0);
        K = hm(K, V, Buffer.from([0]), i2o(xv), i2o(z1)); V = hm(K, V); K = hm(K, V, Buffer.from([1]), i2o(xv), i2o(z1)); V = hm(K, V);
        for (;;) { let T = Buffer.alloc(0); while (T.length < rlen) { V = hm(K, V); T = Buffer.concat([T, V]); } const kk = b2i(T); if (kk >= 1n && kk < q) return kk; K = hm(K, V, Buffer.from([0])); V = hm(K, V); }
      };
      const xs = real ? null : BigInt(input.x), dt = F('rfc6979');
      if (xs !== null && (dt.k1 !== rfc(xs, String(input.m1)) || dt.k2 !== rfc(xs, String(input.m2)))) fail('the RFC 6979 nonces');
      if (pw(g, dt.k1, p) % q !== dt.r1 || pw(g, dt.k2, p) % q !== dt.r2 || !dt.again) fail('the deterministic signatures');
      if (!verifies(String(input.m1), dt.r1, dt.s1) || !verifies(String(input.m2), dt.r2, dt.s2)) fail('the deterministic signatures do not verify');
      const au = F('audit'), seen = new Map(), flags = [];
      au.rows.forEach((row, i) => { const j = seen.get(row.r); if (j !== undefined && au.rows[j].z !== row.z) flags.push([j, i]); if (j === undefined) seen.set(row.r, i); });
      if (JSON.stringify(flags) !== JSON.stringify(au.flags)) fail('the audit flags');
      if (ex.exposed && !flags.some(([a, b]) => a === 0 && b === 3)) fail('the audit misses the repeated r');
    },
  },
];
